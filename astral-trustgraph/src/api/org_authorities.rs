//! 组织行政树与共享单元治理 — HTTP adapter（default-off）。
//!
//! 设计依据：`Docs/架构/Rust架构设计/Rust多租户聚合分区与组织层级设计_V0.1.md` §4/§7。
//! 编排与授权状态机在 `crate::service::org_authorities`；本层只做：
//!
//! 1. **严格输入解析**：mutation DTO 一律 `deny_unknown_fields`（客户端自报
//!    actor/approver/root authority 字段直接解析失败，input claim 不当批准）；
//! 2. **签名 actor 提取**：`Extension<PolicyContext>` 由 permission_check 中间件
//!    在 Gateway 验签 + `PolicyEngine.evaluate()` 之后注入，本层不再读原始身份头；
//! 3. **default-off 路由装配**：[`org_authorities_config_from_env`] 为 `None`
//!    （unset/false）时 main 不 merge 任何 router（fail-closed 404）；非法值由
//!    main 拒绝启动。路由合并由 main 完成（本文件不持有 AppState 构造）。
//!
//! 资源/动作映射（main 登记 registry + `TRUSTGRAPH_PATH_RESOURCE_MAP`）：
//! - `org_authority_edge`：read/create/update/bootstrap（bootstrap 为 ROOT_INIT /
//!   ROOT_GRANT 审批的治理元能力，经 PolicyEngine 放行）
//! - `org_unit_card`：read/create/update
//! - `org_membership`：create/update
//!   动作特例（main 在 `resolve_permission_action` 追加，勿依赖默认 POST→create）：
//! - org_authority_edge + POST + `/move`、`/detach` → `update`
//! - org_unit_card + POST + `/revoke` → `update`
//! - org_membership + POST + `/revoke` → `update`
//! - `permission_request` 的 `/approve`、`/reject` → `approve`、`/cancel` →
//!   `update` 已存在，无需新增。
//!
//! 无 list 端点：DB 统一面当前只提供按 id 读取与 mutation 原语（不虚构不存在
//! 的读取能力）。成员资格调岗 = 旧单元 revoke + 新单元 create 两个明确动作。

use axum::extract::{Extension, Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Deserializer};

use astral_common::contract::ApiResponse;
use astral_common::error::AppError;
use astral_types::org_scope::{OrgGrantRef, OrgSubject};
use astral_types::{AstralError, PolicyContext};

use crate::service::org_authorities::{
    MaskApplyInput, MembershipCreateInput, OrgActorContext, OrgAuthoritiesService,
    OrgScopeSubmitInput, SeedInput,
};
use crate::AppState;

pub use crate::service::org_authorities::org_authorities_config_from_env as org_config_from_env;

/// 构造治理服务（main 集成点：无需新增 AppState 字段；路由合并时按配置门控）。
fn org_service(state: &AppState) -> OrgAuthoritiesService {
    OrgAuthoritiesService::new(
        state.db.clone(),
        state.engine.clone(),
        state.org_scope_enabled,
        state.org_scope_tenant_allowlist.clone(),
    )
}

fn mutation_actor(
    policy_context: &PolicyContext,
    operation_id: &str,
) -> Result<OrgActorContext, AppError> {
    OrgActorContext::from_signed_context(policy_context, Some(operation_id)).map_err(AppError::from)
}

fn read_actor(policy_context: &PolicyContext) -> Result<OrgActorContext, AppError> {
    OrgActorContext::from_signed_context(policy_context, None).map_err(AppError::from)
}

// ===== 请求/响应 DTO（camelCase；mutation 一律 deny_unknown_fields） =====

/// 授权种子 DTO（映射 `OrgGrantSeed`/`OrgScope`）。
/// `resourceTenantId` 与 `domainId` 必须显式出现（数字或 domain 的 `null`）：
/// 缺键即解析失败，绝不静默放宽为无 domain/无 resource tenant 约束；
/// `delegable` 必填布尔。`subject` 仅适用于 GRANT；ROOT_INIT/ROOT_GRANT
/// 携带 subject 时由 service 层拒绝，根种子永远是共享 UNIT contribution。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SeedDto {
    /// 拥有目标资源的租户（显式声明；与接收单元/审批方租户语义分离）。
    pub resource_tenant_id: i64,
    pub resource: String,
    pub action: String,
    #[serde(deserialize_with = "deserialize_required_nullable_domain_id")]
    pub domain_id: Option<i64>,
    pub not_before: Option<i64>,
    pub expires_at: Option<i64>,
    pub delegable: bool,
    pub subject: Option<SubjectDto>,
}

/// PERSONAL contribution 的目标主体。它描述被授予的 user/card 对，不能替代
/// Gateway 签名上下文中的 actor 身份。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubjectDto {
    pub user_id: i64,
    pub card_id: i64,
}

impl SubjectDto {
    fn into_subject(self) -> OrgSubject {
        OrgSubject {
            user_id: self.user_id,
            card_id: self.card_id,
        }
    }
}

fn deserialize_required_nullable_domain_id<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<i64>::deserialize(deserializer)
}

impl SeedDto {
    fn into_input(self) -> Result<SeedInput, AstralError> {
        Ok(SeedInput {
            resource_tenant_id: self.resource_tenant_id,
            resource: self.resource,
            action: self.action,
            domain_id: self.domain_id,
            not_before: self.not_before,
            expires_at: self.expires_at,
            delegable: self.delegable,
            subject: self.subject.map(SubjectDto::into_subject),
        })
    }
}

/// GRANT 请求抽取的父贡献 exact 引用（tenant + grant UUID + revision）。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParentGrantRefDto {
    pub tenant_id: i64,
    pub grant_id: String,
    pub revision: u64,
}

/// POST /permission-requests/org-scopes：六类 org 请求的统一 typed 提交体。
/// kind 与载荷字段必须严格对应（多带/少带字段一律 Validation 拒绝）。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubmitOrgScopeRequestBody {
    pub operation_id: String,
    /// ROOT_INIT | ROOT_GRANT | ATTACH | MOVE | DETACH | GRANT
    pub request_type: String,
    /// ROOT_INIT：初始自源共享贡献种子列表。
    pub seeds: Option<Vec<SeedDto>>,
    /// ROOT_GRANT / GRANT：单个授权种子。
    pub seed: Option<SeedDto>,
    /// GRANT：抽取的父贡献 exact 引用。
    pub parent_grant: Option<ParentGrantRefDto>,
    /// ATTACH：目标父 tenant。
    pub parent_tenant_id: Option<i64>,
    /// MOVE：新父 tenant。
    pub new_parent_tenant_id: Option<i64>,
}

/// POST /org-authority-edges/attach
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttachRequestBody {
    pub operation_id: String,
    pub parent_tenant_id: i64,
}

/// POST /org-authority-edges/move
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MoveRequestBody {
    pub operation_id: String,
    pub new_parent_tenant_id: i64,
}

/// POST /org-authority-edges/detach
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DetachRequestBody {
    pub operation_id: String,
}

/// POST .../revoke（grant）
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevokeGrantRequestBody {
    pub operation_id: String,
    pub expected_revision: u64,
}

/// POST /org-unit-cards/{tenant_id}/masks
/// `targetTenantId` 显式声明被剪裁贡献的祖先租户（must differ from the path
/// tenant；祖先关系由仓储在事务内证明）。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplyMaskRequestBody {
    pub operation_id: String,
    pub target_tenant_id: i64,
    pub target_grant_id: String,
    pub target_grant_revision: u64,
    pub expected_unit_generation: u64,
    pub reason: Option<String>,
}

/// POST .../masks/{mask_id}/revoke
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RemoveMaskRequestBody {
    pub operation_id: String,
    pub expected_revision: u64,
}

/// POST /org-memberships
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MembershipCreateRequestBody {
    pub operation_id: String,
    pub user_id: i64,
    pub identity_card_id: i64,
    pub card_id: i64,
    pub not_before: Option<i64>,
    pub expires_at: Option<i64>,
}

/// POST /org-memberships/{membership_id}/revoke
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MembershipRevokeRequestBody {
    pub operation_id: String,
    pub expected_revision: u64,
}

/// POST .../approve、.../reject
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DecisionRequestBody {
    pub operation_id: String,
    pub expected_revision: u64,
    pub note: Option<String>,
}

/// POST .../cancel
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CancelRequestBody {
    pub operation_id: String,
    pub expected_revision: u64,
}

/// 把统一提交体解析为 kind 化的 service 输入（kind/字段严格对应：
/// 每类 kind 只接受自己的载荷字段，多带/少带一律 Validation 拒绝）。
fn build_submit_input(
    mut body: SubmitOrgScopeRequestBody,
) -> Result<(String, OrgScopeSubmitInput), AppError> {
    let seeds = body.seeds.take();
    let seed = body.seed.take();
    let parent_grant = body.parent_grant.take();
    let parent_tenant_id = body.parent_tenant_id.take();
    let new_parent_tenant_id = body.new_parent_tenant_id.take();
    let forbid = |present: bool, field: &str| -> Result<(), AppError> {
        if present {
            Err(AppError(AstralError::Validation(format!(
                "requestType {} does not allow field {field}",
                body.request_type
            ))))
        } else {
            Ok(())
        }
    };
    let require_seed = |seed: Option<SeedDto>, field: &str| -> Result<SeedInput, AppError> {
        seed.ok_or_else(|| {
            AppError(AstralError::Validation(format!(
                "requestType {} requires field {field}",
                body.request_type
            )))
        })?
        .into_input()
        .map_err(AppError::from)
    };
    let input = match body.request_type.as_str() {
        "ROOT_INIT" => {
            forbid(seed.is_some(), "seed")?;
            forbid(parent_grant.is_some(), "parentGrant")?;
            forbid(parent_tenant_id.is_some(), "parentTenantId")?;
            forbid(new_parent_tenant_id.is_some(), "newParentTenantId")?;
            let seeds = seeds.ok_or_else(|| {
                AppError(AstralError::Validation(
                    "requestType ROOT_INIT requires field seeds".into(),
                ))
            })?;
            OrgScopeSubmitInput::RootInit {
                seeds: seeds
                    .into_iter()
                    .map(SeedDto::into_input)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(AppError::from)?,
            }
        }
        "ROOT_GRANT" => {
            forbid(seeds.is_some(), "seeds")?;
            forbid(parent_grant.is_some(), "parentGrant")?;
            forbid(parent_tenant_id.is_some(), "parentTenantId")?;
            forbid(new_parent_tenant_id.is_some(), "newParentTenantId")?;
            OrgScopeSubmitInput::RootGrant {
                seed: require_seed(seed, "seed")?,
            }
        }
        "ATTACH" => {
            forbid(seeds.is_some(), "seeds")?;
            forbid(seed.is_some(), "seed")?;
            forbid(parent_grant.is_some(), "parentGrant")?;
            forbid(new_parent_tenant_id.is_some(), "newParentTenantId")?;
            let parent_tenant_id = parent_tenant_id.ok_or_else(|| {
                AppError(AstralError::Validation(
                    "requestType ATTACH requires field parentTenantId".into(),
                ))
            })?;
            OrgScopeSubmitInput::Attach { parent_tenant_id }
        }
        "MOVE" => {
            forbid(seeds.is_some(), "seeds")?;
            forbid(seed.is_some(), "seed")?;
            forbid(parent_grant.is_some(), "parentGrant")?;
            forbid(parent_tenant_id.is_some(), "parentTenantId")?;
            let new_parent_tenant_id = new_parent_tenant_id.ok_or_else(|| {
                AppError(AstralError::Validation(
                    "requestType MOVE requires field newParentTenantId".into(),
                ))
            })?;
            OrgScopeSubmitInput::Move {
                new_parent_tenant_id,
            }
        }
        "DETACH" => {
            forbid(seeds.is_some(), "seeds")?;
            forbid(seed.is_some(), "seed")?;
            forbid(parent_grant.is_some(), "parentGrant")?;
            forbid(parent_tenant_id.is_some(), "parentTenantId")?;
            forbid(new_parent_tenant_id.is_some(), "newParentTenantId")?;
            OrgScopeSubmitInput::Detach
        }
        "GRANT" => {
            forbid(seeds.is_some(), "seeds")?;
            forbid(parent_tenant_id.is_some(), "parentTenantId")?;
            forbid(new_parent_tenant_id.is_some(), "newParentTenantId")?;
            let parent_grant = parent_grant.ok_or_else(|| {
                AppError(AstralError::Validation(
                    "requestType GRANT requires field parentGrant".into(),
                ))
            })?;
            OrgScopeSubmitInput::Grant {
                seed: require_seed(seed, "seed")?,
                parent_grant: OrgGrantRef {
                    tenant_id: parent_grant.tenant_id,
                    grant_id: parent_grant.grant_id,
                    revision: parent_grant.revision,
                },
            }
        }
        other => {
            return Err(AppError(AstralError::Validation(format!(
            "unknown requestType {other:?}; expected ROOT_INIT/ROOT_GRANT/ATTACH/MOVE/DETACH/GRANT"
        ))))
        }
    };
    Ok((body.operation_id, input))
}

// ===== 路由注册（default-off：main 仅在配置启用时 merge） =====

/// 行政树治理（resource `org_authority_edge`）。
pub fn org_authority_edge_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/org-authority-edges/roots/{tenant_id}",
            get(get_org_root_gate),
        )
        .route("/org-authority-edges/attach", post(submit_attach))
        .route("/org-authority-edges/move", post(submit_move))
        .route("/org-authority-edges/detach", post(submit_detach))
}

/// 共享单元卡治理（resource `org_unit_card`）。
pub fn org_unit_card_routes() -> Router<AppState> {
    Router::new()
        .route("/org-unit-cards/{tenant_id}", get(get_org_unit_gate))
        .route(
            "/org-unit-cards/{tenant_id}/grants/{grant_id}/revoke",
            post(revoke_org_grant),
        )
        .route("/org-unit-cards/{tenant_id}/masks", post(apply_org_mask))
        .route(
            "/org-unit-cards/{tenant_id}/masks/{mask_id}/revoke",
            post(remove_org_mask),
        )
}

/// 成员资格治理（resource `org_membership`）。
pub fn org_membership_routes() -> Router<AppState> {
    Router::new()
        .route("/org-memberships", post(create_org_membership))
        .route(
            "/org-memberships/{membership_id}/revoke",
            post(revoke_org_membership),
        )
}

/// `/permission-requests/org-scopes` typed 子资源（复用既有 permission-requests
/// 主命名空间，不新增平行 request 主入口；resource `permission_request`）。
pub fn org_scope_request_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/permission-requests/org-scopes",
            post(submit_org_scope_request),
        )
        .route(
            "/permission-requests/org-scopes/{request_id}",
            get(get_org_scope_request),
        )
        .route(
            "/permission-requests/org-scopes/{request_id}/approve",
            post(approve_org_scope_request),
        )
        .route(
            "/permission-requests/org-scopes/{request_id}/reject",
            post(reject_org_scope_request),
        )
        .route(
            "/permission-requests/org-scopes/{request_id}/cancel",
            post(cancel_org_scope_request),
        )
}

// ===== Handlers =====

/// GET /main/api/v1/org-authority-edges/roots/{tenant_id}
async fn get_org_root_gate(
    State(state): State<AppState>,
    Extension(policy_context): Extension<PolicyContext>,
    Path(tenant_id): Path<i64>,
) -> Result<Json<ApiResponse<crate::service::org_authorities::OrgNodeGateView>>, AppError> {
    let actor = read_actor(&policy_context)?;
    let view = org_service(&state)
        .get_node_gate(&actor, tenant_id)
        .await
        .map_err(AppError::from)?;
    Ok(Json(ApiResponse::success(view)))
}

/// GET /main/api/v1/org-unit-cards/{tenant_id}（同一 node 门状态的单元视角）
async fn get_org_unit_gate(
    State(state): State<AppState>,
    Extension(policy_context): Extension<PolicyContext>,
    Path(tenant_id): Path<i64>,
) -> Result<Json<ApiResponse<crate::service::org_authorities::OrgNodeGateView>>, AppError> {
    let actor = read_actor(&policy_context)?;
    let view = org_service(&state)
        .get_node_gate(&actor, tenant_id)
        .await
        .map_err(AppError::from)?;
    Ok(Json(ApiResponse::success(view)))
}

/// POST /main/api/v1/org-authority-edges/attach — 提交 ATTACH 请求（目标父审批）。
async fn submit_attach(
    State(state): State<AppState>,
    Extension(policy_context): Extension<PolicyContext>,
    Json(body): Json<AttachRequestBody>,
) -> Result<Json<ApiResponse<crate::service::org_authorities::OrgScopeSubmitOutcome>>, AppError> {
    let actor = mutation_actor(&policy_context, &body.operation_id)?;
    let outcome = org_service(&state)
        .submit_request(
            &actor,
            OrgScopeSubmitInput::Attach {
                parent_tenant_id: body.parent_tenant_id,
            },
        )
        .await
        .map_err(AppError::from)?;
    Ok(Json(ApiResponse::success(outcome)))
}

/// POST /main/api/v1/org-authority-edges/move — 提交 MOVE 请求（新父审批）。
async fn submit_move(
    State(state): State<AppState>,
    Extension(policy_context): Extension<PolicyContext>,
    Json(body): Json<MoveRequestBody>,
) -> Result<Json<ApiResponse<crate::service::org_authorities::OrgScopeSubmitOutcome>>, AppError> {
    let actor = mutation_actor(&policy_context, &body.operation_id)?;
    let outcome = org_service(&state)
        .submit_request(
            &actor,
            OrgScopeSubmitInput::Move {
                new_parent_tenant_id: body.new_parent_tenant_id,
            },
        )
        .await
        .map_err(AppError::from)?;
    Ok(Json(ApiResponse::success(outcome)))
}

/// POST /main/api/v1/org-authority-edges/detach — 提交 DETACH 请求（现父审批）。
async fn submit_detach(
    State(state): State<AppState>,
    Extension(policy_context): Extension<PolicyContext>,
    Json(body): Json<DetachRequestBody>,
) -> Result<Json<ApiResponse<crate::service::org_authorities::OrgScopeSubmitOutcome>>, AppError> {
    let actor = mutation_actor(&policy_context, &body.operation_id)?;
    let outcome = org_service(&state)
        .submit_request(&actor, OrgScopeSubmitInput::Detach)
        .await
        .map_err(AppError::from)?;
    Ok(Json(ApiResponse::success(outcome)))
}

/// POST /main/api/v1/org-unit-cards/{tenant_id}/grants/{grant_id}/revoke
async fn revoke_org_grant(
    State(state): State<AppState>,
    Extension(policy_context): Extension<PolicyContext>,
    Path((tenant_id, grant_id)): Path<(i64, String)>,
    Json(body): Json<RevokeGrantRequestBody>,
) -> Result<Json<ApiResponse<astral_db::org_scope_repository::OrgMutationOutcome>>, AppError> {
    let actor = mutation_actor(&policy_context, &body.operation_id)?;
    let outcome = org_service(&state)
        .revoke_grant(&actor, tenant_id, &grant_id, body.expected_revision)
        .await
        .map_err(AppError::from)?;
    Ok(Json(ApiResponse::success(outcome)))
}

/// POST /main/api/v1/org-unit-cards/{tenant_id}/masks — 本级精确来源剪裁。
async fn apply_org_mask(
    State(state): State<AppState>,
    Extension(policy_context): Extension<PolicyContext>,
    Path(tenant_id): Path<i64>,
    Json(body): Json<ApplyMaskRequestBody>,
) -> Result<Json<ApiResponse<astral_db::org_scope_repository::OrgMutationOutcome>>, AppError> {
    let actor = mutation_actor(&policy_context, &body.operation_id)?;
    let outcome = org_service(&state)
        .apply_mask(
            &actor,
            tenant_id,
            MaskApplyInput {
                target_tenant_id: body.target_tenant_id,
                target_grant_id: body.target_grant_id,
                target_grant_revision: body.target_grant_revision,
                expected_unit_generation: body.expected_unit_generation,
                reason: body.reason,
            },
        )
        .await
        .map_err(AppError::from)?;
    Ok(Json(ApiResponse::success(outcome)))
}

/// POST /main/api/v1/org-unit-cards/{tenant_id}/masks/{mask_id}/revoke
/// mask 主键是 DB 生成的规范 UUID 文本（service 层 canonical 校验）。
async fn remove_org_mask(
    State(state): State<AppState>,
    Extension(policy_context): Extension<PolicyContext>,
    Path((tenant_id, mask_id)): Path<(i64, String)>,
    Json(body): Json<RemoveMaskRequestBody>,
) -> Result<Json<ApiResponse<astral_db::org_scope_repository::OrgMutationOutcome>>, AppError> {
    let actor = mutation_actor(&policy_context, &body.operation_id)?;
    let outcome = org_service(&state)
        .remove_mask(&actor, tenant_id, &mask_id, body.expected_revision)
        .await
        .map_err(AppError::from)?;
    Ok(Json(ApiResponse::success(outcome)))
}

/// POST /main/api/v1/org-memberships — 登记本单元成员（双卡复核在仓储）。
async fn create_org_membership(
    State(state): State<AppState>,
    Extension(policy_context): Extension<PolicyContext>,
    Json(body): Json<MembershipCreateRequestBody>,
) -> Result<Json<ApiResponse<astral_db::org_scope_repository::OrgMutationOutcome>>, AppError> {
    let actor = mutation_actor(&policy_context, &body.operation_id)?;
    let outcome = org_service(&state)
        .create_membership(
            &actor,
            actor.tenant_id,
            MembershipCreateInput {
                user_id: body.user_id,
                identity_card_id: body.identity_card_id,
                card_id: body.card_id,
                not_before: body.not_before,
                expires_at: body.expires_at,
            },
        )
        .await
        .map_err(AppError::from)?;
    Ok(Json(ApiResponse::success(outcome)))
}

/// POST /main/api/v1/org-memberships/{membership_id}/revoke
/// membership 主键是 DB 生成的规范 UUID 文本（service 层 canonical 校验）。
async fn revoke_org_membership(
    State(state): State<AppState>,
    Extension(policy_context): Extension<PolicyContext>,
    Path(membership_id): Path<String>,
    Json(body): Json<MembershipRevokeRequestBody>,
) -> Result<Json<ApiResponse<astral_db::org_scope_repository::OrgMutationOutcome>>, AppError> {
    let actor = mutation_actor(&policy_context, &body.operation_id)?;
    let outcome = org_service(&state)
        .revoke_membership(
            &actor,
            actor.tenant_id,
            &membership_id,
            body.expected_revision,
        )
        .await
        .map_err(AppError::from)?;
    Ok(Json(ApiResponse::success(outcome)))
}

/// POST /main/api/v1/permission-requests/org-scopes — 六类 org 请求统一提交。
async fn submit_org_scope_request(
    State(state): State<AppState>,
    Extension(policy_context): Extension<PolicyContext>,
    Json(body): Json<SubmitOrgScopeRequestBody>,
) -> Result<Json<ApiResponse<crate::service::org_authorities::OrgScopeSubmitOutcome>>, AppError> {
    let (operation_id, input) = build_submit_input(body)?;
    let actor = mutation_actor(&policy_context, &operation_id)?;
    let outcome = org_service(&state)
        .submit_request(&actor, input)
        .await
        .map_err(AppError::from)?;
    Ok(Json(ApiResponse::success(outcome)))
}

/// GET /main/api/v1/permission-requests/org-scopes/{request_id}
async fn get_org_scope_request(
    State(state): State<AppState>,
    Extension(policy_context): Extension<PolicyContext>,
    Path(request_id): Path<i64>,
) -> Result<Json<ApiResponse<crate::service::org_authorities::OrgScopeRequestSummary>>, AppError> {
    let actor = read_actor(&policy_context)?;
    let summary = org_service(&state)
        .get_request(&actor, request_id)
        .await
        .map_err(AppError::from)?;
    Ok(Json(ApiResponse::success(summary)))
}

/// POST /main/api/v1/permission-requests/org-scopes/{request_id}/approve
/// 批准 actor 只来自签名 ctx；ROOT_INIT/ROOT_GRANT 另要求
/// `org_authority_edge:bootstrap` 元能力 + scope 上限证明（service 层）。
async fn approve_org_scope_request(
    State(state): State<AppState>,
    Extension(policy_context): Extension<PolicyContext>,
    Path(request_id): Path<i64>,
    Json(body): Json<DecisionRequestBody>,
) -> Result<Json<ApiResponse<astral_db::org_scope_repository::OrgApproveOutcome>>, AppError> {
    let actor = mutation_actor(&policy_context, &body.operation_id)?;
    let outcome = org_service(&state)
        .approve_request(
            &actor,
            request_id,
            body.expected_revision,
            body.note.as_deref(),
        )
        .await
        .map_err(AppError::from)?;
    Ok(Json(ApiResponse::success(outcome)))
}

/// POST /main/api/v1/permission-requests/org-scopes/{request_id}/reject
async fn reject_org_scope_request(
    State(state): State<AppState>,
    Extension(policy_context): Extension<PolicyContext>,
    Path(request_id): Path<i64>,
    Json(body): Json<DecisionRequestBody>,
) -> Result<Json<ApiResponse<crate::service::org_authorities::OrgScopeDecisionOutcome>>, AppError> {
    let actor = mutation_actor(&policy_context, &body.operation_id)?;
    let outcome = org_service(&state)
        .reject_request(
            &actor,
            request_id,
            body.expected_revision,
            body.note.as_deref(),
        )
        .await
        .map_err(AppError::from)?;
    Ok(Json(ApiResponse::success(outcome)))
}

/// POST /main/api/v1/permission-requests/org-scopes/{request_id}/cancel
async fn cancel_org_scope_request(
    State(state): State<AppState>,
    Extension(policy_context): Extension<PolicyContext>,
    Path(request_id): Path<i64>,
    Json(body): Json<CancelRequestBody>,
) -> Result<Json<ApiResponse<crate::service::org_authorities::OrgScopeDecisionOutcome>>, AppError> {
    let actor = mutation_actor(&policy_context, &body.operation_id)?;
    let outcome = org_service(&state)
        .cancel_request(&actor, request_id, body.expected_revision)
        .await
        .map_err(AppError::from)?;
    Ok(Json(ApiResponse::success(outcome)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::org_authorities::{org_authorities_config_from_env, OrgAuthoritiesConfig};

    fn production_source() -> &'static str {
        include_str!("org_authorities.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap()
    }

    /// 提交体 kind/字段严格对应（多带字段拒绝；少带字段拒绝）。
    #[test]
    fn submit_input_enforces_kind_field_correspondence() {
        let base = |request_type: &str| SubmitOrgScopeRequestBody {
            operation_id: "op-1".into(),
            request_type: request_type.to_owned(),
            seeds: None,
            seed: None,
            parent_grant: None,
            parent_tenant_id: None,
            new_parent_tenant_id: None,
        };
        let seed_dto = || SeedDto {
            resource_tenant_id: 30,
            resource: "learn_course".into(),
            action: "read".into(),
            domain_id: Some(5),
            not_before: None,
            expires_at: None,
            delegable: false,
            subject: None,
        };

        // DETACH 不允许携带任何载荷字段。
        let mut body = base("DETACH");
        body.parent_tenant_id = Some(30);
        let error = build_submit_input(body).unwrap_err();
        assert!(error.0.to_string().contains("parentTenantId"));

        // ATTACH 必须带 parentTenantId。
        let error = build_submit_input(base("ATTACH")).unwrap_err();
        assert!(error.0.to_string().contains("parentTenantId"));

        // ATTACH 不允许 seed。
        let mut body = base("ATTACH");
        body.parent_tenant_id = Some(30);
        body.seed = Some(seed_dto());
        let error = build_submit_input(body).unwrap_err();
        assert!(error.0.to_string().contains("seed"));

        // MOVE 必须带 newParentTenantId。
        let error = build_submit_input(base("MOVE")).unwrap_err();
        assert!(error.0.to_string().contains("newParentTenantId"));

        // GRANT requires both seed + parentGrant; the parser validates the
        // parent reference first, so this missing-field case must name it.
        let error = build_submit_input(base("GRANT")).unwrap_err();
        assert!(error.0.to_string().contains("parentGrant"));
        let mut body = base("GRANT");
        body.seed = Some(seed_dto());
        let error = build_submit_input(body).unwrap_err();
        assert!(error.0.to_string().contains("parentGrant"));

        // ROOT_INIT 必须带 seeds。
        let error = build_submit_input(base("ROOT_INIT")).unwrap_err();
        assert!(error.0.to_string().contains("seeds"));

        // ROOT_GRANT 不允许 seeds。
        let mut body = base("ROOT_GRANT");
        body.seed = Some(seed_dto());
        body.seeds = Some(vec![seed_dto()]);
        let error = build_submit_input(body).unwrap_err();
        assert!(error.0.to_string().contains("seeds"));

        // 未知 kind 拒绝。
        let error = build_submit_input(base("ROOT_GENESIS")).unwrap_err();
        assert!(error.0.to_string().contains("unknown requestType"));

        // happy paths。
        let mut attach = base("ATTACH");
        attach.parent_tenant_id = Some(30);
        let (operation_id, input) = build_submit_input(attach).unwrap();
        assert_eq!(operation_id, "op-1");
        assert!(matches!(
            input,
            OrgScopeSubmitInput::Attach {
                parent_tenant_id: 30
            }
        ));

        let mut grant = base("GRANT");
        grant.seed = Some(seed_dto());
        grant.parent_grant = Some(ParentGrantRefDto {
            tenant_id: 30,
            grant_id: "0f0e0d0c-0b0a-0908-0706-050403020100".into(),
            revision: 2,
        });
        let (_, input) = build_submit_input(grant).unwrap();
        match input {
            OrgScopeSubmitInput::Grant { parent_grant, .. } => {
                assert_eq!(parent_grant.tenant_id, 30);
                assert_eq!(parent_grant.revision, 2);
            }
            other => panic!("expected GRANT input, got {other:?}"),
        }

        let mut personal = base("GRANT");
        let mut personal_seed = seed_dto();
        personal_seed.subject = Some(SubjectDto {
            user_id: 7,
            card_id: 70,
        });
        personal.seed = Some(personal_seed);
        personal.parent_grant = Some(ParentGrantRefDto {
            tenant_id: 30,
            grant_id: "0f0e0d0c-0b0a-0908-0706-050403020100".into(),
            revision: 2,
        });
        let (_, input) = build_submit_input(personal).unwrap();
        match input {
            OrgScopeSubmitInput::Grant { seed, .. } => {
                assert_eq!(
                    seed.subject,
                    Some(OrgSubject {
                        user_id: 7,
                        card_id: 70
                    })
                );
            }
            other => panic!("expected PERSONAL GRANT input, got {other:?}"),
        }

        let mut detach = base("DETACH");
        detach.operation_id = "op-2".into();
        let (_, input) = build_submit_input(detach).unwrap();
        assert!(matches!(input, OrgScopeSubmitInput::Detach));
    }

    /// camelCase 解析形状保持稳定。
    #[test]
    fn decision_body_parses_camel_case() {
        let body: DecisionRequestBody =
            serde_json::from_str(r#"{"operationId":"op-9","expectedRevision":3,"note":"ok"}"#)
                .expect("camelCase payload must parse");
        assert_eq!(body.operation_id, "op-9");
        assert_eq!(body.expected_revision, 3);
        assert_eq!(body.note.as_deref(), Some("ok"));
    }

    /// mutation DTO 拒绝未知字段（客户端自报 actor/approver 等身份字段即失败）。
    #[test]
    fn mutation_bodies_reject_unknown_fields() {
        let raw = r#"{"operationId":"op-9","expectedRevision":1,"approverUserId":99}"#;
        assert!(serde_json::from_str::<DecisionRequestBody>(raw).is_err());
        let raw = r#"{"operationId":"op-9","expectedRevision":1,"actorTenantId":30}"#;
        assert!(serde_json::from_str::<CancelRequestBody>(raw).is_err());
        let raw = r#"{"operationId":"op-9","parentTenantId":30,"rootTenantId":30}"#;
        assert!(serde_json::from_str::<AttachRequestBody>(raw).is_err());
        let raw = r#"{"operationId":"op-9","userId":7,"identityCardId":1,"cardId":2,"isSuperAdmin":true}"#;
        assert!(serde_json::from_str::<MembershipCreateRequestBody>(raw).is_err());
        let raw = r#"{"operationId":"op-9","targetTenantId":30,"targetGrantId":"g","targetGrantRevision":1,"expectedUnitGeneration":1,"resourceTenantId":9}"#;
        assert!(serde_json::from_str::<ApplyMaskRequestBody>(raw).is_err());
    }

    /// 缺 operationId 的 mutation 体解析失败（幂等键必填）。
    #[test]
    fn mutation_bodies_require_operation_id() {
        let raw = r#"{"expectedRevision":1}"#;
        assert!(serde_json::from_str::<DecisionRequestBody>(raw).is_err());
    }

    /// 种子必须显式携带 resourceTenantId 与 domainId（缺键/未知字段均拒绝）；
    /// domainId 的显式 `null` 保留为无 domain 约束，并逐字段映射到 service
    /// `SeedInput`（GRANT 跨租户种子经此透传，服务端另行约束 root kinds）。
    #[test]
    fn seed_dto_requires_explicit_resource_tenant_and_domain_and_maps_input() {
        let missing_resource_tenant =
            r#"{"resource":"learn_course","action":"read","domainId":null,"delegable":false}"#;
        assert!(serde_json::from_str::<SeedDto>(missing_resource_tenant).is_err());

        let missing_domain = r#"{"resourceTenantId":30,"resource":"learn_course","action":"read","delegable":false}"#;
        assert!(serde_json::from_str::<SeedDto>(missing_domain).is_err());

        let explicit = r#"{"resourceTenantId":30,"resource":"learn_course","action":"read","domainId":null,"delegable":true}"#;
        let dto = serde_json::from_str::<SeedDto>(explicit).expect("explicit seed must parse");
        let input = dto.into_input().expect("seed input must build");
        assert_eq!(input.resource_tenant_id, 30);
        assert_eq!(input.resource, "learn_course");
        assert_eq!(input.action, "read");
        assert_eq!(input.domain_id, None);
        assert!(input.delegable);

        let unknown = r#"{"resourceTenantId":30,"resource":"learn_course","action":"read","domainId":null,"delegable":true,"approverUserId":9}"#;
        assert!(serde_json::from_str::<SeedDto>(unknown).is_err());
    }

    /// mask 请求体必须显式携带 targetTenantId（祖先租户）且拒绝未知字段。
    #[test]
    fn mask_request_parses_target_tenant_id() {
        let body: ApplyMaskRequestBody = serde_json::from_str(
            r#"{"operationId":"op-9","targetTenantId":30,"targetGrantId":"0f0e0d0c-0b0a-0908-0706-050403020100","targetGrantRevision":2,"expectedUnitGeneration":1,"reason":"trim"}"#,
        )
        .expect("mask body with targetTenantId must parse");
        assert_eq!(body.target_tenant_id, 30);
        assert_eq!(body.target_grant_revision, 2);

        let missing = r#"{"operationId":"op-9","targetGrantId":"g","targetGrantRevision":1,"expectedUnitGeneration":1}"#;
        assert!(serde_json::from_str::<ApplyMaskRequestBody>(missing).is_err());
    }

    /// 路由形状守卫：mask/membership 主键走 String 路径段（DB 规范 UUID 文本，
    /// service 层 canonical 校验），mask 提交显式透传 targetTenantId。
    #[test]
    fn mask_and_membership_routes_carry_uuid_text_ids() {
        let source = production_source();
        assert!(source.contains("Path((tenant_id, mask_id)): Path<(i64, String)>"));
        assert!(source.contains("Path(membership_id): Path<String>"));
        assert!(source.contains("body.target_tenant_id,"));
        assert!(
            source.contains(".remove_mask(&actor, tenant_id, &mask_id, body.expected_revision)")
        );
        assert!(source.contains(".revoke_membership(\n            &actor,\n            actor.tenant_id,\n            &membership_id,\n            body.expected_revision,\n        )"));
    }

    /// 路由形状守卫：仅暴露四个 allowlist 前缀内的路由，且全部落在
    /// default-off 的四个 router builder 内。
    #[test]
    fn routes_stay_within_allowlisted_prefixes() {
        let source = production_source();
        let allowed = [
            "/org-authority-edges",
            "/org-unit-cards",
            "/org-memberships",
            "/permission-requests/org-scopes",
        ];
        let mut cursor = 0usize;
        while let Some(marker) = source[cursor..].find(".route(") {
            let after_paren = cursor + marker + ".route(".len();
            let quote = source[after_paren..]
                .find('"')
                .expect("route registration must carry a path string literal")
                + after_paren;
            let end = source[quote + 1..].find('"').expect("path must be quoted") + quote + 1;
            let path = &source[quote + 1..end];
            assert!(
                allowed.iter().any(|prefix| path.starts_with(prefix)),
                "route {path} must stay within org scope allowlist"
            );
            assert!(
                !path.contains(char::is_uppercase),
                "route {path} must be lowercase kebab-case"
            );
            cursor = end;
        }
    }

    /// 关键端点仍路由到对应 handler（main 合并后无需改路径）。
    #[test]
    fn core_endpoints_stay_routed() {
        let source = production_source();
        assert!(source.contains("/org-authority-edges/roots/{tenant_id}"));
        assert!(source.contains("get(get_org_root_gate)"));
        assert!(source.contains("route(\"/org-authority-edges/attach\", post(submit_attach))"));
        assert!(source.contains("route(\"/org-authority-edges/move\", post(submit_move))"));
        assert!(source.contains("route(\"/org-authority-edges/detach\", post(submit_detach))"));
        assert!(source.contains("post(revoke_org_grant)"));
        assert!(source.contains("post(apply_org_mask)"));
        assert!(source.contains("post(remove_org_mask)"));
        assert!(source.contains("post(create_org_membership)"));
        assert!(source.contains("post(revoke_org_membership)"));
        assert!(source.contains("post(submit_org_scope_request)"));
        assert!(source.contains("post(approve_org_scope_request)"));
        assert!(source.contains("post(reject_org_scope_request)"));
        assert!(source.contains("post(cancel_org_scope_request)"));
    }

    /// 配置 re-export 与 service 配置语义一致（default-off）。
    #[test]
    fn config_reexport_is_default_off() {
        std::env::remove_var("ASTRAL_ORG_SCOPE_ENABLED");
        assert!(org_config_from_env().unwrap().is_none());
        assert!(org_authorities_config_from_env().unwrap().is_none());
        std::env::set_var("ASTRAL_ORG_SCOPE_ENABLED", "true");
        assert_eq!(
            org_config_from_env().unwrap(),
            Some(OrgAuthoritiesConfig { enabled: true })
        );
        std::env::remove_var("ASTRAL_ORG_SCOPE_ENABLED");
    }
}
