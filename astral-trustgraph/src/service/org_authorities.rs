//! 组织行政树与共享单元治理服务（org scope authority）。
//!
//! 设计依据：`Docs/架构/Rust架构设计/Rust多租户聚合分区与组织层级设计_V0.1.md` §4/§7
//! 与 MT 运行 `implementation-contract.md`。本模块是 HTTP 与权威存储之间的编排层：
//!
//! - 共享类型**直接使用** `astral_types::org_scope`（types owner 冻结合同；本模块
//!   不新造平行 DTO）；durable 读写**直接使用** DB owner 的统一仓储
//!   `astral_db::org_scope_repository::SqlxOrgScopeRepository`（无自造 store trait、
//!   无 501 占位实现），全部公开端点都落到真实仓储原语。
//! - actor 只来自 Gateway 验签 + permission_check 中间件注入的签名
//!   [`PolicyContext`]；HTTP mutation DTO 一律 `deny_unknown_fields`，任何请求体
//!   身份字段都不是授权来源（input claim 不当批准）。
//! - server-side tenant scope：本地操作（mask/membership/grant revoke）限定签名
//!   actor tenant；请求载荷的 requesting/root tenant 由服务端从 ctx 填充；审批授权
//!   按 kind 从持久行政状态推导（probe node / 载荷对侧），并按 kind 追加
//!   PolicyEngine 治理检查：ROOT_INIT / ROOT_GRANT 要求已注册的
//!   `org_authority_edge:bootstrap` 元能力 + actor 已持有被申请 scope 的
//!   published 证据（上限证明）；不能用 tenant 不等代替授权。
//! - 幂等：mutation 必带显式 `operationId`（1..=64/128 字节、alnum 与 `-_.:/`，
//!   与仓储 `validated_operation_id` 同规则）；审批/撤销带 `expectedRevision`；
//!   operation_id × 输入摘要 dedupe 由仓储负责。
//! - default-off：[`org_authorities_config_from_env`] 经 astral-common 共享
//!   严格解析器解析 `ASTRAL_ORG_SCOPE_ENABLED`（unset/空 = 关闭；非法值 =
//!   Err，main 拒绝启动）。
//!   关闭时 main 不注册任何 org 路由（fail-closed 404，同 `api::test_control`）。
//! - 成员资格调岗：无独立 request kind，按合同由调用方执行两个明确动作——
//!   旧单元管理员 `revoke_membership`，新单元管理员 `create_membership`。

use std::sync::Arc;

use astral_types::org_scope::{OrgGrantRef, OrgRequestKind, OrgRequestPayload, OrgSubject};
use astral_types::{AstralError, PolicyContext, ResourceOwnershipScope};
use policy_engine::PolicyEngine;

use crate::repository::audit_log_repository::validated_request_operation_id;

// DB 统一面（org_scope_repository 子模块文件由 DB owner 落盘；此处只依赖
// mod.rs 已冻结的 re-export 名；命令 struct 仅在下方 db_commands 区块使用）。
use astral_db::org_scope_repository::{
    probe_org_scope_gate, OrgApproveOutcome, OrgGovernanceProof, OrgMutationOutcome,
    OrgRequestView, OrgScopeGateState, OrgScopeRepository, SqlxOrgScopeRepository,
    ORG_MAX_ROOT_INIT_GRANTS,
};
use astral_db::{CachedPublishedEvidenceRuleRepository, SqlxRuleRepository};

/// ROOT_INIT 请求可携带的初始 grant 数上限（取 DB 更严界；types 上限 1000）。
pub const MAX_ROOT_INIT_SEEDS: usize = ORG_MAX_ROOT_INIT_GRANTS;

/// 元能力（治理 meta permission）：ROOT_INIT / ROOT_GRANT 审批要求
/// `org_authority_edge:bootstrap` 经 `PolicyEngine.evaluate()` 放行（main 已登记）。
pub const META_RESOURCE: &str = "org_authority_edge";
pub const META_ACTION_BOOTSTRAP: &str = "bootstrap";

// ===== 配置（default-off） =====

/// 组织治理控制面部署配置。`enabled=false` 时 main 不注册任何 org 路由。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrgAuthoritiesConfig {
    pub enabled: bool,
}

/// 读取 `ASTRAL_ORG_SCOPE_ENABLED`：
/// unset/空白 → `Ok(None)`（关闭）；`true`/`false`（trim 后精确匹配）→ 对应结果；
/// 其他值 → `Err(Config)`，main 必须拒绝启动，绝不静默降级。
///
/// 解析委托给 `astral_common::config` 的共享严格解析器（所有 PolicyEngine 宿主
/// 共用同一契约与 default-off 语义，防止跨宿主 org_scope 准入 split-brain）；
/// 本包装只负责映射为组织治理路由装配的 `Option<OrgAuthoritiesConfig>` 语义
/// （false → None），不改变任何行为。
pub fn org_authorities_config_from_env() -> Result<Option<OrgAuthoritiesConfig>, AstralError> {
    astral_common::config::org_scope_enabled_from_env()
        .map(|enabled| enabled.then_some(OrgAuthoritiesConfig { enabled: true }))
        .map_err(|error| AstralError::Config(error.to_string()))
}

// ===== 签名 actor 上下文 =====

/// 由签名 `PolicyContext` 派生的治理操作主体（PLATFORM_USER 限定，全 id 为正）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgActorContext {
    pub user_id: i64,
    pub identity_card_id: i64,
    pub card_id: i64,
    pub tenant_id: i64,
    pub domain_id: i64,
    operation_id: Option<String>,
}

impl OrgActorContext {
    /// `raw_operation_id` 缺失时 actor 可用于只读；mutation 必须另行通过
    /// [`OrgActorContext::require_operation_id`] 取得稳定幂等键。
    pub fn from_signed_context(
        context: &PolicyContext,
        raw_operation_id: Option<&str>,
    ) -> Result<Self, AstralError> {
        if context.principal_kind.as_deref() != Some("PLATFORM_USER") {
            return Err(AstralError::Auth(
                "org governance requires a signed platform user context".into(),
            ));
        }
        Ok(Self {
            user_id: positive_context_id(context.user_id, "user_id")?,
            identity_card_id: positive_context_id(context.identity_card_id, "identity_card_id")?,
            card_id: positive_context_id(context.card_id, "card_id")?,
            tenant_id: positive_context_id(context.tenant_id, "tenant_id")?,
            domain_id: positive_context_id(context.domain_id, "domain_id")?,
            operation_id: validated_request_operation_id(raw_operation_id)?,
        })
    }

    /// mutation 的稳定 operationId；缺失即拒绝（不静默生成）。
    pub fn require_operation_id(&self) -> Result<&str, AstralError> {
        self.operation_id.as_deref().ok_or_else(|| {
            AstralError::Validation(
                "org governance mutation requires an explicit operationId".into(),
            )
        })
    }
}

fn positive_context_id(value: Option<i64>, field: &str) -> Result<i64, AstralError> {
    value
        .filter(|v| *v > 0)
        .ok_or_else(|| AstralError::Auth(format!("signed context {field} missing or non-positive")))
}

fn positive_body_id(value: i64, field: &str) -> Result<(), AstralError> {
    if value <= 0 {
        return Err(AstralError::Validation(format!(
            "{field} must be a positive id, got {value}"
        )));
    }
    Ok(())
}

fn positive_revision(value: u64, field: &str) -> Result<(), AstralError> {
    if value == 0 {
        return Err(AstralError::Validation(format!(
            "{field} must be a positive revision/generation (>= 1)"
        )));
    }
    Ok(())
}

fn validate_window(not_before: Option<i64>, expires_at: Option<i64>) -> Result<(), AstralError> {
    if let (Some(nb), Some(ex)) = (not_before, expires_at) {
        if nb <= 0 || ex <= 0 {
            return Err(AstralError::Validation(
                "validity bounds must be positive unix seconds".into(),
            ));
        }
        if nb >= ex {
            return Err(AstralError::Validation(
                "validity window requires notBefore < expiresAt".into(),
            ));
        }
    }
    Ok(())
}

/// UUID 标识必须采用 DB 生成的规范小写文本，避免同一 durable subject 用多个
/// 文本表示绕过精确 revision/CAS 约束。
fn validate_stable_uuid(value: &str, field: &str) -> Result<(), AstralError> {
    let parsed = uuid::Uuid::parse_str(value)
        .map_err(|_| AstralError::Validation(format!("{field} must be a canonical UUID")))?;
    if parsed.is_nil() || parsed.to_string() != value {
        return Err(AstralError::Validation(format!(
            "{field} must be a non-nil canonical lowercase UUID"
        )));
    }
    Ok(())
}

fn bounded_note(note: Option<&str>) -> Result<Option<String>, AstralError> {
    match note {
        None => Ok(None),
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Ok(None);
            }
            if trimmed.len() > 512 {
                return Err(AstralError::Validation("note exceeds 512 bytes".into()));
            }
            Ok(Some(trimmed.to_owned()))
        }
    }
}

/// 作用域 resource/action 必须 registry-first 注册（AGENTS §3.3；未注册一律拒绝）。
/// 形态/通配/窗口校验由 `OrgScope::validate` 承担。
fn validate_registered_scope(resource: &str, action: &str) -> Result<(), AstralError> {
    astral_types::registry::ResourceRegistry::global()
        .validate(resource, action)
        .map_err(|error| AstralError::Validation(format!("scope is not registered: {error}")))
}

// ===== 提交输入（service 层 typed 合同；HTTP DTO 在 api 层 deny_unknown_fields） =====

/// 授权种子输入。根种子只允许共享 UNIT contribution；GRANT 可选用
/// `subject` 创建精确绑定 user/card 的 PERSONAL branch。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedInput {
    /// The tenant that owns the target resource. This is deliberately separate
    /// from both the receiving unit and the source/approver tenant.
    pub resource_tenant_id: i64,
    pub resource: String,
    pub action: String,
    pub domain_id: Option<i64>,
    pub not_before: Option<i64>,
    pub expires_at: Option<i64>,
    pub delegable: bool,
    pub subject: Option<OrgSubject>,
}

impl SeedInput {
    fn validate(&self) -> Result<(), AstralError> {
        positive_body_id(self.resource_tenant_id, "resourceTenantId")?;
        validate_registered_scope(&self.resource, &self.action)?;
        validate_window(self.not_before, self.expires_at)?;
        if let Some(domain_id) = self.domain_id {
            positive_body_id(domain_id, "domainId")?;
        }
        if let Some(subject) = self.subject {
            subject.validate().map_err(|error| {
                AstralError::Validation(format!(
                    "subject is invalid: code={} detail={}",
                    error.code.as_str(),
                    error.message
                ))
            })?;
        }
        Ok(())
    }
}

/// `/permission-requests/org-scopes` 六类请求的提交输入（kind 判别由 api 层完成）。
#[derive(Debug, Clone)]
pub enum OrgScopeSubmitInput {
    /// ROOT_INIT：候选根租户管理员提交；seeds 为该根的初始自源共享贡献。
    RootInit { seeds: Vec<SeedInput> },
    /// ROOT_GRANT：为既有治理根追加初始来源授权。
    RootGrant { seed: SeedInput },
    /// ATTACH：子租户申请加入目标父。
    Attach { parent_tenant_id: i64 },
    /// MOVE：子租户申请变更行政父。
    Move { new_parent_tenant_id: i64 },
    /// DETACH：行政独立/摘除申请（先失效旧继承，批准由仓储单事务完成）。
    Detach,
    /// GRANT：下级向上级申请跨租户授权；必须指明抽取的父贡献 exact
    /// `(tenant, grant UUID, revision)`（types 合同；scope/能力由仓储在审批
    /// 事务内复验）。
    Grant {
        seed: SeedInput,
        parent_grant: OrgGrantRef,
    },
}

// ===== 视图/结果（最小稳定 API 面） =====

/// 提交结果（从仓储 outcome 提取的最小稳定面）。
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgScopeSubmitOutcome {
    pub request_id: i64,
    pub operation_id: String,
    pub replayed: bool,
}

/// 决策/撤销类布尔结果。
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgScopeDecisionOutcome {
    pub request_id: i64,
    pub applied: bool,
}

/// GET 请求视图（由仓储 [`OrgRequestView`] 提取的最小稳定面）。
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgScopeRequestSummary {
    pub request_id: i64,
    pub kind: String,
    pub status: String,
    pub requesting_tenant_id: i64,
    pub counterparty_tenant_id: Option<i64>,
    /// DB 请求行当前 revision（乐观并发可见性；决策命令须携带它作为 expectedRevision）。
    pub revision: u64,
}

/// 行政 node 门状态视图（GET /org-authority-edges/roots/{tenant_id}）。
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgNodeGateView {
    pub managed: bool,
    /// SCHEMA_UNMANAGED / TENANT_UNMANAGED / TENANT_MANAGED。
    pub reason: String,
    pub node: Option<OrgNodeDto>,
}

/// node 的 API 投影（u64 代次已由仓储恢复）。
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgNodeDto {
    pub tenant_id: i64,
    pub root_tenant_id: i64,
    pub parent_tenant_id: Option<i64>,
    pub generation: u64,
    pub revoke_fence: u64,
    pub relationship_revision: u64,
    pub active: bool,
}

/// 成员资格登记输入。
#[derive(Debug, Clone)]
pub struct MembershipCreateInput {
    pub user_id: i64,
    pub identity_card_id: i64,
    pub card_id: i64,
    pub not_before: Option<i64>,
    pub expires_at: Option<i64>,
}

/// Exact inherited-source mask input. The caller's unit remains a separate
/// parameter because it is bound to the route and signed actor context.
#[derive(Debug, Clone)]
pub struct MaskApplyInput {
    pub target_tenant_id: i64,
    pub target_grant_id: String,
    pub target_grant_revision: u64,
    pub expected_unit_generation: u64,
    pub reason: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// DB 命令构造（CONVERGENCE 区块）
//
// astral-db org_scope_repository 的 requests.rs / mutations.rs 命令 struct 字段
// 落盘后，仅需核对本区块的字段名/形状；service 与 api 层不感知 DB 命令细节。
// ─────────────────────────────────────────────────────────────────────────────

mod db_commands {
    use super::{OrgActorContext, OrgScopeSubmitInput, OrgScopeSubmitOutcome, SeedInput};
    use astral_db::org_scope_repository::{
        OrgApproveCommand, OrgCancelCommand, OrgCreateRequestCommand, OrgGrantRevokeCommand,
        OrgMaskApplyCommand, OrgMaskRemoveCommand, OrgMembershipCreateCommand,
        OrgMembershipRevokeCommand, OrgRejectCommand, OrgRequestOutcome,
    };
    use astral_types::org_scope::{OrgGrantRef, OrgGrantSeed, OrgRequestPayload, OrgScope};
    use astral_types::{AstralError, ValidityWindow};

    fn scope_from_seed(seed: &SeedInput) -> Result<OrgScope, AstralError> {
        Ok(OrgScope {
            resource_tenant_id: seed.resource_tenant_id,
            domain_id: seed.domain_id,
            resource: seed.resource.clone(),
            action: seed.action.clone(),
            validity: ValidityWindow {
                not_before: seed.not_before,
                expires_at: seed.expires_at,
            },
        })
    }

    fn grant_seed(seed: &SeedInput) -> Result<OrgGrantSeed, AstralError> {
        if seed.subject.is_some() {
            return Err(AstralError::Validation(
                "ROOT_INIT/ROOT_GRANT seeds cannot carry a PERSONAL subject".into(),
            ));
        }
        Ok(OrgGrantSeed {
            scope: scope_from_seed(seed)?,
            delegable: seed.delegable,
        })
    }

    /// Root authority is a self-source contract: the signed root tenant is the
    /// requester, root, and resource tenant for ROOT_INIT/ROOT_GRANT. Cross-tenant
    /// scope delivery is represented only by a parent-bound GRANT.
    pub fn request_payload(
        actor: &OrgActorContext,
        input: &OrgScopeSubmitInput,
    ) -> Result<OrgRequestPayload, AstralError> {
        let payload = match input {
            OrgScopeSubmitInput::RootInit { seeds } => OrgRequestPayload::RootInit {
                root_tenant_id: actor.tenant_id,
                initial_grants: seeds
                    .iter()
                    .map(grant_seed)
                    .collect::<Result<Vec<_>, _>>()?,
            },
            OrgScopeSubmitInput::RootGrant { seed } => OrgRequestPayload::RootGrant {
                root_tenant_id: actor.tenant_id,
                scope: scope_from_seed(seed)?,
                delegable: seed.delegable,
            },
            OrgScopeSubmitInput::Attach { parent_tenant_id } => OrgRequestPayload::Attach {
                child_tenant_id: actor.tenant_id,
                parent_tenant_id: *parent_tenant_id,
            },
            OrgScopeSubmitInput::Move {
                new_parent_tenant_id,
            } => OrgRequestPayload::Move {
                child_tenant_id: actor.tenant_id,
                new_parent_tenant_id: *new_parent_tenant_id,
            },
            OrgScopeSubmitInput::Detach => OrgRequestPayload::Detach {
                child_tenant_id: actor.tenant_id,
            },
            OrgScopeSubmitInput::Grant { seed, parent_grant } => OrgRequestPayload::Grant {
                receiving_tenant_id: actor.tenant_id,
                parent_grant: parent_grant.clone(),
                scope: scope_from_seed(seed)?,
                delegable: seed.delegable,
                subject: seed.subject,
            },
        };
        payload.validate().map_err(|error| {
            AstralError::Validation(format!(
                "org request payload rejected: code={} detail={}",
                error.code.as_str(),
                error.message
            ))
        })?;
        Ok(payload)
    }

    /// 请求载荷的对侧 tenant（审批授权推导与可见性判定的服务端依据）。
    /// ROOT_INIT/ROOT_GRANT 的授权来自元能力（无 tenant 对侧）；DETACH 的对侧
    /// 由 probe node 的 parent 推导；GRANT 的对侧 = 请求方的直接行政父（probe）。
    pub fn counterparty_of(payload: &OrgRequestPayload) -> Option<i64> {
        match payload {
            OrgRequestPayload::RootInit { .. } | OrgRequestPayload::RootGrant { .. } => None,
            OrgRequestPayload::Attach {
                parent_tenant_id, ..
            } => Some(*parent_tenant_id),
            OrgRequestPayload::Move {
                new_parent_tenant_id,
                ..
            } => Some(*new_parent_tenant_id),
            OrgRequestPayload::Detach { .. } => None,
            OrgRequestPayload::Grant { .. } => None,
        }
    }

    /// 请求载荷携带的全部 scope（ROOT_INIT/ROOT_GRANT/GRANT 的元能力上限证明对象）。
    pub fn scopes_of(payload: &OrgRequestPayload) -> Vec<OrgScope> {
        match payload {
            OrgRequestPayload::RootInit { initial_grants, .. } => initial_grants
                .iter()
                .map(|seed| seed.scope.clone())
                .collect(),
            OrgRequestPayload::RootGrant { scope, .. } => vec![scope.clone()],
            OrgRequestPayload::Grant { scope, .. } => vec![scope.clone()],
            _ => Vec::new(),
        }
    }

    pub fn create_request(
        actor: &OrgActorContext,
        payload: OrgRequestPayload,
    ) -> OrgCreateRequestCommand {
        OrgCreateRequestCommand {
            operation_id: actor.require_operation_id().unwrap_or_default().to_owned(),
            actor_user_id: actor.user_id,
            actor_tenant_id: Some(actor.tenant_id),
            payload,
        }
    }

    /// 仓储提交 outcome → API 稳定面（CONVERGENCE：字段名以 requests.rs 为准）。
    pub fn submit_outcome(outcome: OrgRequestOutcome) -> OrgScopeSubmitOutcome {
        OrgScopeSubmitOutcome {
            request_id: outcome.request_id,
            operation_id: outcome.operation_id,
            replayed: outcome.replayed,
        }
    }

    pub fn approve_request(
        approver: &OrgActorContext,
        request_id: i64,
        expected_revision: u64,
        note: Option<String>,
        governance_proof: Option<astral_db::org_scope_repository::OrgGovernanceProof>,
    ) -> OrgApproveCommand {
        OrgApproveCommand {
            request_id,
            expected_revision,
            approver_user_id: approver.user_id,
            approver_tenant_id: Some(approver.tenant_id),
            operation_id: approver
                .require_operation_id()
                .unwrap_or_default()
                .to_owned(),
            note,
            governance_proof,
        }
    }

    pub fn reject_request(
        decider: &OrgActorContext,
        request_id: i64,
        expected_revision: u64,
        note: Option<String>,
        governance_proof: Option<astral_db::org_scope_repository::OrgGovernanceProof>,
    ) -> OrgRejectCommand {
        OrgRejectCommand {
            request_id,
            expected_revision,
            approver_user_id: decider.user_id,
            approver_tenant_id: Some(decider.tenant_id),
            operation_id: decider
                .require_operation_id()
                .unwrap_or_default()
                .to_owned(),
            note,
            governance_proof,
        }
    }

    pub fn cancel_request(
        actor: &OrgActorContext,
        request_id: i64,
        expected_revision: u64,
    ) -> OrgCancelCommand {
        OrgCancelCommand {
            request_id,
            expected_revision,
            actor_user_id: actor.user_id,
            actor_tenant_id: Some(actor.tenant_id),
            operation_id: actor.require_operation_id().unwrap_or_default().to_owned(),
            note: None,
        }
    }

    pub fn revoke_grant(
        actor: &OrgActorContext,
        receiving_tenant_id: i64,
        grant_id: &str,
        expected_revision: u64,
    ) -> OrgGrantRevokeCommand {
        OrgGrantRevokeCommand {
            receiving_tenant_id,
            grant_id: grant_id.to_owned(),
            expected_revision,
            operation_id: actor.require_operation_id().unwrap_or_default().to_owned(),
            actor_user_id: actor.user_id,
            actor_tenant_id: Some(actor.tenant_id),
            reason: None,
        }
    }

    pub fn apply_mask(
        actor: &OrgActorContext,
        tenant_id: i64,
        target: OrgGrantRef,
        expected_unit_generation: u64,
        reason: Option<String>,
    ) -> OrgMaskApplyCommand {
        OrgMaskApplyCommand {
            tenant_id,
            target,
            expected_unit_generation,
            reason,
            operation_id: actor.require_operation_id().unwrap_or_default().to_owned(),
            actor_user_id: actor.user_id,
            actor_tenant_id: Some(actor.tenant_id),
        }
    }

    pub fn remove_mask(
        actor: &OrgActorContext,
        tenant_id: i64,
        mask_id: &str,
        expected_revision: u64,
    ) -> OrgMaskRemoveCommand {
        OrgMaskRemoveCommand {
            tenant_id,
            mask_id: mask_id.to_owned(),
            expected_revision,
            operation_id: actor.require_operation_id().unwrap_or_default().to_owned(),
            actor_user_id: actor.user_id,
            actor_tenant_id: Some(actor.tenant_id),
        }
    }

    pub fn create_membership(
        actor: &OrgActorContext,
        tenant_id: i64,
        input: &super::MembershipCreateInput,
    ) -> OrgMembershipCreateCommand {
        OrgMembershipCreateCommand {
            tenant_id,
            user_id: input.user_id,
            identity_card_id: input.identity_card_id,
            card_id: input.card_id,
            validity: ValidityWindow {
                not_before: input.not_before,
                expires_at: input.expires_at,
            },
            operation_id: actor.require_operation_id().unwrap_or_default().to_owned(),
            actor_user_id: actor.user_id,
            actor_tenant_id: Some(actor.tenant_id),
        }
    }

    pub fn revoke_membership(
        actor: &OrgActorContext,
        tenant_id: i64,
        membership_id: &str,
        expected_revision: u64,
    ) -> OrgMembershipRevokeCommand {
        OrgMembershipRevokeCommand {
            tenant_id,
            membership_id: membership_id.to_owned(),
            expected_revision,
            operation_id: actor.require_operation_id().unwrap_or_default().to_owned(),
            actor_user_id: actor.user_id,
            actor_tenant_id: Some(actor.tenant_id),
        }
    }
}

/// 从仓储 [`OrgRequestView`] 提取授权/可见性所需的最小信息
/// （CONVERGENCE：字段名以 requests.rs 落盘为准——DB 列为 `requester_tenant_id`）。
fn request_info_from_db(view: &OrgRequestView) -> RequestViewInfo {
    RequestViewInfo {
        request_id: view.request_id,
        status: view.status.clone(),
        requesting_tenant_id: view.requester_tenant_id,
        revision: view.revision,
        counterparty_tenant_id: db_commands::counterparty_of(&view.payload),
        kind: view.payload.kind(),
    }
}

/// 授权/可见性判定的纯数据面（可单测，不触 DB）。
#[derive(Debug, Clone)]
pub struct RequestViewInfo {
    pub request_id: i64,
    pub status: String,
    pub requesting_tenant_id: i64,
    pub revision: u64,
    pub counterparty_tenant_id: Option<i64>,
    pub kind: OrgRequestKind,
}

impl RequestViewInfo {
    pub fn is_pending(&self) -> bool {
        self.status.eq_ignore_ascii_case("PENDING")
    }
}

// ===== 服务 =====

/// 组织治理编排服务。内部持有 DB 统一仓储与共享 `PolicyEngine`
/// （评估仍走唯一授权入口；本服务只做 kind 级治理检查，不旁路 evaluate）。
pub struct OrgAuthoritiesService {
    repo: SqlxOrgScopeRepository,
    db: sqlx::MySqlPool,
    engine: Arc<PolicyEngine>,
    org_scope_enabled: bool,
    /// Frozen projector ownership boundary copied from startup configuration.
    /// It is never parsed from a request and is checked before a mutation can
    /// create or restore usable authority for a managed tenant. Safety-reducing
    /// mutations remain available to fail closed even if coverage later drifts.
    org_scope_tenant_allowlist: Vec<i64>,
}

impl OrgAuthoritiesService {
    /// The deployment state and projector tenant boundary are frozen at startup
    /// and reused for every governance mutation, so environment changes cannot
    /// alter an in-flight authorization decision or strand newly managed work.
    pub fn new(
        db: sqlx::MySqlPool,
        engine: Arc<PolicyEngine>,
        org_scope_enabled: bool,
        org_scope_tenant_allowlist: Vec<i64>,
    ) -> Self {
        Self {
            repo: SqlxOrgScopeRepository::new(db.clone()),
            db,
            engine,
            org_scope_enabled,
            org_scope_tenant_allowlist,
        }
    }

    fn require_projector_coverage(&self, tenant_id: i64) -> Result<(), AstralError> {
        require_projector_tenant_coverage(
            self.org_scope_enabled,
            &self.org_scope_tenant_allowlist,
            tenant_id,
        )
    }

    // ---- node 门状态读取 ----

    /// GET /org-authority-edges/roots/{tenant_id}：租户行政 node 的门状态。
    /// `Pending`（DB 故障）映射为 Err（fail-closed 5xx），绝不与 Unmanaged 混淆。
    pub async fn get_node_gate(
        &self,
        actor: &OrgActorContext,
        tenant_id: i64,
    ) -> Result<OrgNodeGateView, AstralError> {
        assert_local_scope(tenant_id, actor)?;
        match probe_org_scope_gate(&self.db, tenant_id).await {
            OrgScopeGateState::SchemaUnmanaged => Ok(OrgNodeGateView {
                managed: false,
                reason: "SCHEMA_UNMANAGED".into(),
                node: None,
            }),
            OrgScopeGateState::TenantUnmanaged => Ok(OrgNodeGateView {
                managed: false,
                reason: "TENANT_UNMANAGED".into(),
                node: None,
            }),
            OrgScopeGateState::TenantManaged { node } => Ok(OrgNodeGateView {
                managed: true,
                reason: "TENANT_MANAGED".into(),
                node: Some(OrgNodeDto {
                    tenant_id: node.tenant_id,
                    root_tenant_id: node.root_tenant_id,
                    parent_tenant_id: node.parent_tenant_id,
                    generation: node.generation,
                    revoke_fence: node.revoke_fence,
                    relationship_revision: node.relationship_revision,
                    active: node.active,
                }),
            }),
            OrgScopeGateState::Pending => Err(AstralError::Database(
                "org scope gate state is pending; failing closed".into(),
            )),
        }
    }

    // ---- 请求提交 ----

    /// 提交 org-scope 请求（六类 kind；requesting/root tenant 一律来自签名 ctx）。
    pub async fn submit_request(
        &self,
        actor: &OrgActorContext,
        input: OrgScopeSubmitInput,
    ) -> Result<OrgScopeSubmitOutcome, AstralError> {
        actor.require_operation_id()?;
        self.require_projector_coverage(actor.tenant_id)?;
        let payload = validate_and_build_payload(actor, &input)?;
        self.require_projector_coverage(request_target_tenant(&payload))?;
        let outcome = self
            .repo
            .create_request(&db_commands::create_request(actor, payload))
            .await?;
        Ok(db_commands::submit_outcome(outcome))
    }

    // ---- 审批 / 驳回 / 撤销 ----

    /// 审批请求。授权按 kind 服务端推导：
    /// - GRANT / DETACH：签名 actor 必须是请求方当前 ACTIVE 行政父（probe node）；
    /// - ATTACH / MOVE：载荷对侧父 tenant；
    /// - ROOT_INIT / ROOT_GRANT：`org_authority_edge:bootstrap` 元能力（PolicyEngine）
    ///   + actor 已持有每个被申请 scope 的 published 证据（上限证明）。
    ///
    /// 治理证明（admission operation id + 精确批准 scope 清单）随命令传入仓储复核。
    /// 结构性资格（边激活、parent grant delegable/revision/包含、环、CAS）由仓储在
    /// 事务内复验；本层结论不得替代仓储复核，仓储复核失败即整体失败。
    pub async fn approve_request(
        &self,
        approver: &OrgActorContext,
        request_id: i64,
        expected_revision: u64,
        note: Option<&str>,
    ) -> Result<OrgApproveOutcome, AstralError> {
        approver.require_operation_id()?;
        positive_revision(expected_revision, "expectedRevision")?;
        let note = bounded_note(note)?;
        let view = self.load_pending_request(request_id).await?;
        self.require_projector_coverage(request_target_tenant(&view.payload))?;
        let info = request_info_from_db(&view);
        self.assert_kind_authority(approver, &info).await?;
        let governance_proof = self
            .authorize_root_meta(approver, info.kind, &view.payload)
            .await?;
        self.repo
            .approve_request(&db_commands::approve_request(
                approver,
                request_id,
                expected_revision,
                note,
                governance_proof,
            ))
            .await
    }

    /// 驳回请求：与审批同一套 kind 授权（不能让无权方驳回）。ROOT_INIT /
    /// ROOT_GRANT 的驳回权与审批权**同界**：同一 `org_authority_edge:bootstrap`
    /// 元能力经 `PolicyEngine.evaluate()` 放行（fail-closed）——否则任何已签名
    /// 平台用户都能驳回根请求（拒绝服务面）。随命令传入仓储的治理证明由 DB
    /// 复核结构并 durable 落审计；驳回不发放 scope，故不做审批那样的逐 scope
    /// 上限评估，但证明能力清单精确绑定请求自身待发 scope。
    pub async fn reject_request(
        &self,
        decider: &OrgActorContext,
        request_id: i64,
        expected_revision: u64,
        note: Option<&str>,
    ) -> Result<OrgScopeDecisionOutcome, AstralError> {
        decider.require_operation_id()?;
        positive_revision(expected_revision, "expectedRevision")?;
        let note = bounded_note(note)?;
        let view = self.load_pending_request(request_id).await?;
        let info = request_info_from_db(&view);
        self.assert_kind_authority(decider, &info).await?;
        let governance_proof = self
            .root_meta_proof_for_reject(decider, info.kind, &view.payload)
            .await?;
        let applied = self
            .repo
            .reject_request(&db_commands::reject_request(
                decider,
                request_id,
                expected_revision,
                note,
                governance_proof,
            ))
            .await?;
        Ok(OrgScopeDecisionOutcome {
            request_id,
            applied,
        })
    }

    /// 请求人撤销自己的 PENDING 请求。
    pub async fn cancel_request(
        &self,
        actor: &OrgActorContext,
        request_id: i64,
        expected_revision: u64,
    ) -> Result<OrgScopeDecisionOutcome, AstralError> {
        actor.require_operation_id()?;
        positive_revision(expected_revision, "expectedRevision")?;
        let view = self.load_pending_request(request_id).await?;
        let info = request_info_from_db(&view);
        if info.requesting_tenant_id != actor.tenant_id {
            return Err(AstralError::Permission(
                "only the requesting tenant may cancel its org scope request".into(),
            ));
        }
        let applied = self
            .repo
            .cancel_request(&db_commands::cancel_request(
                actor,
                request_id,
                expected_revision,
            ))
            .await?;
        Ok(OrgScopeDecisionOutcome {
            request_id,
            applied,
        })
    }

    /// GET /permission-requests/org-scopes/{request_id}：
    /// 请求方或对侧 tenant 可见；DETACH / GRANT 请求额外允许请求方当前行政父
    /// 读取（其审批授权即来自该父）；ROOT_INIT/ROOT_GRANT 仅请求方可读（审批方
    /// 凭元能力按 id 审批，不走本读端点）。
    pub async fn get_request(
        &self,
        actor: &OrgActorContext,
        request_id: i64,
    ) -> Result<OrgScopeRequestSummary, AstralError> {
        positive_body_id(request_id, "request_id")?;
        let view = self.repo.get_request(request_id).await?.ok_or_else(|| {
            AstralError::NotFound(format!("org scope request {request_id} not found"))
        })?;
        let info = request_info_from_db(&view);
        let counterparty = info.counterparty_tenant_id.unwrap_or(0);
        let parent_can_see = matches!(info.kind, OrgRequestKind::Detach | OrgRequestKind::Grant);
        let visible = actor.tenant_id == info.requesting_tenant_id
            || actor.tenant_id == counterparty
            || (parent_can_see
                && self
                    .requesting_parent_tenant(info.requesting_tenant_id)
                    .await?
                    == Some(actor.tenant_id));
        if !visible {
            return Err(AstralError::Permission(
                "org scope request is only visible to its requesting or counterparty tenant".into(),
            ));
        }
        Ok(OrgScopeRequestSummary {
            request_id: info.request_id,
            kind: info.kind.as_str().to_owned(),
            status: info.status,
            requesting_tenant_id: info.requesting_tenant_id,
            counterparty_tenant_id: info.counterparty_tenant_id,
            revision: info.revision,
        })
    }

    // ---- 单元卡：grant 收窄 / mask ----

    /// 撤销本单元 grant（receiving 侧本地收窄；generation 立即推进，旧发布证据
    /// 因源失效不可准入；origin 侧生命周期由仓储治理）。
    pub async fn revoke_grant(
        &self,
        actor: &OrgActorContext,
        tenant_id: i64,
        grant_id: &str,
        expected_revision: u64,
    ) -> Result<OrgMutationOutcome, AstralError> {
        actor.require_operation_id()?;
        assert_local_scope(tenant_id, actor)?;
        positive_revision(expected_revision, "expectedRevision")?;
        // grant 主键是 DB 生成的规范 UUID 文本；非规范表示不得作为同一 durable
        // subject 参与精确 revision CAS。
        let grant_id = grant_id.trim();
        validate_stable_uuid(grant_id, "grantId")?;
        self.repo
            .revoke_grant(&db_commands::revoke_grant(
                actor,
                tenant_id,
                grant_id,
                expected_revision,
            ))
            .await
    }

    /// 本级精确来源剪裁（target 必须指向祖先贡献，exact identity/revision；
    /// 本单元自己的 grant 撤销走 grant ledger，不适用 mask）。
    pub async fn apply_mask(
        &self,
        actor: &OrgActorContext,
        tenant_id: i64,
        input: MaskApplyInput,
    ) -> Result<OrgMutationOutcome, AstralError> {
        actor.require_operation_id()?;
        assert_local_scope(tenant_id, actor)?;
        positive_body_id(input.target_tenant_id, "targetTenantId")?;
        if input.target_tenant_id == tenant_id {
            return Err(AstralError::Validation(
                "targetTenantId must identify an ancestor tenant, not this unit".into(),
            ));
        }
        positive_revision(input.target_grant_revision, "targetGrantRevision")?;
        positive_revision(input.expected_unit_generation, "expectedUnitGeneration")?;
        let grant_id = input.target_grant_id.trim();
        validate_stable_uuid(grant_id, "targetGrantId")?;
        let reason = bounded_note(input.reason.as_deref())?;
        let target = OrgGrantRef {
            tenant_id: input.target_tenant_id,
            grant_id: grant_id.to_owned(),
            revision: input.target_grant_revision,
        };
        self.repo
            .apply_mask(&db_commands::apply_mask(
                actor,
                tenant_id,
                target,
                input.expected_unit_generation,
                reason,
            ))
            .await
    }

    pub async fn remove_mask(
        &self,
        actor: &OrgActorContext,
        tenant_id: i64,
        mask_id: &str,
        expected_revision: u64,
    ) -> Result<OrgMutationOutcome, AstralError> {
        actor.require_operation_id()?;
        assert_local_scope(tenant_id, actor)?;
        self.require_projector_coverage(tenant_id)?;
        validate_stable_uuid(mask_id, "maskId")?;
        positive_revision(expected_revision, "expectedRevision")?;
        self.repo
            .remove_mask(&db_commands::remove_mask(
                actor,
                tenant_id,
                mask_id,
                expected_revision,
            ))
            .await
    }

    // ---- 成员资格 ----

    /// 登记成员（本单元；双卡存在性与 tenant 匹配由仓储复核）。
    pub async fn create_membership(
        &self,
        actor: &OrgActorContext,
        tenant_id: i64,
        input: MembershipCreateInput,
    ) -> Result<OrgMutationOutcome, AstralError> {
        actor.require_operation_id()?;
        assert_local_scope(tenant_id, actor)?;
        self.require_projector_coverage(tenant_id)?;
        positive_body_id(input.user_id, "user_id")?;
        positive_body_id(input.identity_card_id, "identityCardId")?;
        positive_body_id(input.card_id, "cardId")?;
        validate_window(input.not_before, input.expires_at)?;
        self.repo
            .create_membership(&db_commands::create_membership(actor, tenant_id, &input))
            .await
    }

    /// 撤销成员资格（本单元；调岗 = 先 revoke 再由新单元管理员 create）。
    pub async fn revoke_membership(
        &self,
        actor: &OrgActorContext,
        tenant_id: i64,
        membership_id: &str,
        expected_revision: u64,
    ) -> Result<OrgMutationOutcome, AstralError> {
        actor.require_operation_id()?;
        assert_local_scope(tenant_id, actor)?;
        validate_stable_uuid(membership_id, "membershipId")?;
        positive_revision(expected_revision, "expectedRevision")?;
        self.repo
            .revoke_membership(&db_commands::revoke_membership(
                actor,
                tenant_id,
                membership_id,
                expected_revision,
            ))
            .await
    }

    // ---- 内部 ----

    async fn load_pending_request(&self, request_id: i64) -> Result<OrgRequestView, AstralError> {
        positive_body_id(request_id, "request_id")?;
        let view = self.repo.get_request(request_id).await?.ok_or_else(|| {
            AstralError::NotFound(format!("org scope request {request_id} not found"))
        })?;
        if !request_info_from_db(&view).is_pending() {
            return Err(AstralError::Validation(format!(
                "org scope request {request_id} is not pending (status {})",
                request_info_from_db(&view).status
            )));
        }
        Ok(view)
    }

    /// kind 级结构授权（纯推导 + probe；元能力在 [`Self::authorize_root_meta`]）。
    async fn assert_kind_authority(
        &self,
        actor: &OrgActorContext,
        info: &RequestViewInfo,
    ) -> Result<(), AstralError> {
        match kind_authority(info.kind) {
            KindAuthority::Counterparty => {
                if info.counterparty_tenant_id != Some(actor.tenant_id) {
                    return Err(AstralError::Permission(
                        "decision authority belongs to the request's counterparty tenant".into(),
                    ));
                }
                Ok(())
            }
            KindAuthority::RequestingParent => {
                let parent = self
                    .requesting_parent_tenant(info.requesting_tenant_id)
                    .await?;
                if parent != Some(actor.tenant_id) {
                    return Err(AstralError::Permission(
                        "decision authority belongs to the requesting tenant's immediate administrative parent"
                            .into(),
                    ));
                }
                Ok(())
            }
            // ROOT_INIT/ROOT_GRANT 的授权 = 元能力 + scope 上限证明（非 tenant 不等），
            // 审批与驳回同界（驳回不含 scope 上限评估）；结构面在此不做 tenant
            // 归属检查。
            KindAuthority::RootMeta => Ok(()),
        }
    }

    /// 请求方当前行政父（probe node 的 parent_tenant_id）。
    /// Pending（DB 故障）→ Err（fail-closed）；非受治理 → None（无父可授权）。
    async fn requesting_parent_tenant(&self, tenant_id: i64) -> Result<Option<i64>, AstralError> {
        match probe_org_scope_gate(&self.db, tenant_id).await {
            OrgScopeGateState::TenantManaged { node } => Ok(node.parent_tenant_id),
            OrgScopeGateState::Pending => Err(AstralError::Database(
                "org scope gate state is pending; failing closed".into(),
            )),
            _ => Ok(None),
        }
    }

    /// ROOT_INIT / ROOT_GRANT 的治理元检查（审批）：
    /// 1) `org_authority_edge:bootstrap` 经 `PolicyEngine.evaluate()` 放行；
    /// 2) actor 已持有每个被申请 scope 的 published 证据（上限证明）。
    ///
    /// 返回仓储审批所需的治理证明：ROOT_INIT/ROOT_GRANT 为 `Some`，其余 kind 为
    /// `None`。`approved_capabilities` 与实际逐项评估的 scope 清单**完全一致**
    /// （不合并、不放宽），防止把证明伪造得比评估范围更宽。
    async fn authorize_root_meta(
        &self,
        actor: &OrgActorContext,
        kind: OrgRequestKind,
        payload: &OrgRequestPayload,
    ) -> Result<Option<OrgGovernanceProof>, AstralError> {
        if !matches!(kind, OrgRequestKind::RootInit | OrgRequestKind::RootGrant) {
            return Ok(None);
        }
        // ROOT_INIT/ROOT_GRANT 的种子 resource tenant 已在提交边界约束为 actor
        // tenant；元能力评估同样绑定 actor 自身租户（签名 ctx，绝不取自请求头）。
        self.require_root_bootstrap_authority(actor).await?;
        let scopes = db_commands::scopes_of(payload);
        for scope in &scopes {
            self.evaluate_meta(
                actor,
                &scope.resource,
                &scope.action,
                scope.resource_tenant_id,
                scope.domain_id,
            )
            .await?;
        }
        Ok(Some(self.root_governance_proof(actor, scopes)?))
    }

    /// ROOT_INIT / ROOT_GRANT 驳回的元能力边界：与审批**同一**
    /// `org_authority_edge:bootstrap` PolicyEngine 检查（驳回权不得低于审批权；
    /// 评估失败/拒绝一律 Err）。驳回不发放任何 scope，故不做审批的逐 scope
    /// 上限评估；治理证明的能力清单直接绑定请求自身待发 scope，供 DB 精确
    /// 复核与 durable 审计。其余 kind 返回 `None`（非根驳回行为不变）。
    async fn root_meta_proof_for_reject(
        &self,
        actor: &OrgActorContext,
        kind: OrgRequestKind,
        payload: &OrgRequestPayload,
    ) -> Result<Option<OrgGovernanceProof>, AstralError> {
        if !matches!(kind, OrgRequestKind::RootInit | OrgRequestKind::RootGrant) {
            return Ok(None);
        }
        self.require_root_bootstrap_authority(actor).await?;
        let scopes = db_commands::scopes_of(payload);
        Ok(Some(self.root_governance_proof(actor, scopes)?))
    }

    /// 治理元能力（root-init 专用 meta 对）的唯一 PolicyEngine 评估入口；
    /// 拒绝/失败 fail-closed，绝不旁路。
    async fn require_root_bootstrap_authority(
        &self,
        actor: &OrgActorContext,
    ) -> Result<(), AstralError> {
        self.evaluate_meta(
            actor,
            META_RESOURCE,
            META_ACTION_BOOTSTRAP,
            actor.tenant_id,
            Some(actor.domain_id),
        )
        .await
    }

    /// 构造仓储复核用治理证明：meta 对 + 签名 actor 的稳定 admission
    /// operation id + 与实际评估一致的精确能力清单。
    fn root_governance_proof(
        &self,
        actor: &OrgActorContext,
        approved_capabilities: Vec<astral_types::org_scope::OrgScope>,
    ) -> Result<OrgGovernanceProof, AstralError> {
        Ok(OrgGovernanceProof {
            permission_resource: META_RESOURCE.to_owned(),
            permission_action: META_ACTION_BOOTSTRAP.to_owned(),
            admission_operation_id: actor.require_operation_id()?.to_owned(),
            approved_capabilities,
        })
    }

    /// 经 `PolicyEngine.evaluate()`（唯一授权入口）评估 actor 对
    /// resource:action 的持权；评估失败/拒绝一律 Err（fail-closed，不旁路）。
    /// `resource_tenant_id`/`resource_domain_id` 是权威解析的目标资源事实：
    /// root kind 场景下 resource tenant 已约束为签名 actor tenant，domain 来自
    /// 被 eval 的 scope（或 actor 签名 domain），绝不信任任意请求头。
    async fn evaluate_meta(
        &self,
        actor: &OrgActorContext,
        resource: &str,
        action: &str,
        resource_tenant_id: i64,
        resource_domain_id: Option<i64>,
    ) -> Result<(), AstralError> {
        let ctx = PolicyContext::builder()
            .user_id(Some(actor.user_id))
            .principal_kind(Some("PLATFORM_USER".to_owned()))
            .identity_card_id(Some(actor.identity_card_id))
            .card_id(Some(actor.card_id))
            .tenant_id(Some(actor.tenant_id))
            .domain_id(Some(actor.domain_id))
            .resource_tenant_id(Some(resource_tenant_id))
            .resource_domain_id(resource_domain_id)
            .resource_ownership_scope(ResourceOwnershipScope::TenantScoped)
            .resource(Some(resource.to_owned()))
            .action(action.to_owned())
            .build();
        let repo = CachedPublishedEvidenceRuleRepository::new(
            SqlxRuleRepository::new(self.db.clone()).with_org_scope_enabled(self.org_scope_enabled),
            self.db.clone(),
        );
        let decision = self.engine.evaluate(&ctx, &repo).await;
        if decision.allowed {
            Ok(())
        } else {
            Err(AstralError::Permission(format!(
                "org governance meta permission denied for {resource}:{action} (reason {})",
                decision.reason
            )))
        }
    }
}

/// kind → 决策授权方（结构面；ROOT_INIT/ROOT_GRANT 交由元能力检查）。
/// - GRANT / DETACH：请求方的**直接行政父**（probe node 推导）；
/// - ATTACH / MOVE：载荷对侧父 tenant；
/// - ROOT_INIT / ROOT_GRANT：`org_authority_edge:bootstrap` 元能力 + scope 上限
///   证明（审批）/ 同界元能力证明（驳回）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KindAuthority {
    Counterparty,
    RequestingParent,
    RootMeta,
}

fn kind_authority(kind: OrgRequestKind) -> KindAuthority {
    match kind {
        OrgRequestKind::Grant | OrgRequestKind::Detach => KindAuthority::RequestingParent,
        OrgRequestKind::Attach | OrgRequestKind::Move => KindAuthority::Counterparty,
        OrgRequestKind::RootInit | OrgRequestKind::RootGrant => KindAuthority::RootMeta,
    }
}

fn assert_local_scope(tenant_id: i64, actor: &OrgActorContext) -> Result<(), AstralError> {
    if tenant_id != actor.tenant_id {
        return Err(AstralError::Permission(format!(
            "org scope operation on tenant {tenant_id} is restricted to the signed caller tenant {}",
            actor.tenant_id
        )));
    }
    Ok(())
}

/// Enforces the startup-frozen projector ownership boundary before source work is
/// created for a tenant. This is not an authorization decision and never trusts a
/// client-supplied list: `main` parses the allowlist once, proves coverage of all
/// existing managed nodes, and passes the same immutable values through AppState.
fn require_projector_tenant_coverage(
    org_scope_enabled: bool,
    tenant_allowlist: &[i64],
    tenant_id: i64,
) -> Result<(), AstralError> {
    if !org_scope_enabled {
        return Err(AstralError::Config(
            "code=org_scope.projector_disabled_for_mutation".into(),
        ));
    }
    if tenant_allowlist.contains(&tenant_id) {
        return Ok(());
    }
    Err(AstralError::Validation(format!(
        "code=org_scope.projector_tenant_not_configured;tenant_id={tenant_id}"
    )))
}

/// Each typed request mutates exactly this unit's authority aggregate when it is
/// approved. Parent ids only authorize/topologically constrain the change; they
/// do not move the source aggregate away from the request target.
fn request_target_tenant(payload: &OrgRequestPayload) -> i64 {
    match payload {
        OrgRequestPayload::RootInit { root_tenant_id, .. }
        | OrgRequestPayload::RootGrant { root_tenant_id, .. } => *root_tenant_id,
        OrgRequestPayload::Attach {
            child_tenant_id, ..
        }
        | OrgRequestPayload::Move {
            child_tenant_id, ..
        }
        | OrgRequestPayload::Detach {
            child_tenant_id, ..
        } => *child_tenant_id,
        OrgRequestPayload::Grant {
            receiving_tenant_id,
            ..
        } => *receiving_tenant_id,
    }
}

/// ROOT_INIT/ROOT_GRANT 的种子 resource tenant 边界：根请求是行政授权树的
/// 自源 genesis，必须同时满足 root tenant == 签名 actor tenant == scope resource
/// tenant。该约束是原方案的永久合同；目录 parent/path、资金关系或客户端声明
/// 都不能把治理租户变成外部资源租户的隐式代理。跨租户范围只能沿已批准的
/// GRANT parent provenance 下发。
fn assert_root_seed_resource_tenant(
    actor: &OrgActorContext,
    seed: &SeedInput,
) -> Result<(), AstralError> {
    if seed.resource_tenant_id != actor.tenant_id {
        return Err(AstralError::Validation(format!(
            "ROOT_INIT/ROOT_GRANT seed resourceTenantId {} must equal the signed root tenant {} by the self-source root contract",
            seed.resource_tenant_id, actor.tenant_id
        )));
    }
    Ok(())
}

/// 提交输入的完整验证 + payload 构建（registry-first、窗口、上限、kind 语义、
/// `OrgRequestPayload::validate` typed 合同）。
fn validate_and_build_payload(
    actor: &OrgActorContext,
    input: &OrgScopeSubmitInput,
) -> Result<OrgRequestPayload, AstralError> {
    match input {
        OrgScopeSubmitInput::RootInit { seeds } => {
            if seeds.is_empty() || seeds.len() > MAX_ROOT_INIT_SEEDS {
                return Err(AstralError::Validation(format!(
                    "ROOT_INIT requires 1..={MAX_ROOT_INIT_SEEDS} initial grants"
                )));
            }
            for seed in seeds {
                seed.validate()?;
                if seed.subject.is_some() {
                    return Err(AstralError::Validation(
                        "ROOT_INIT seeds must be shared UNIT contributions".into(),
                    ));
                }
                assert_root_seed_resource_tenant(actor, seed)?;
            }
        }
        OrgScopeSubmitInput::RootGrant { seed } => {
            seed.validate()?;
            if seed.subject.is_some() {
                return Err(AstralError::Validation(
                    "ROOT_GRANT seed must be a shared UNIT contribution".into(),
                ));
            }
            assert_root_seed_resource_tenant(actor, seed)?;
        }
        OrgScopeSubmitInput::Attach { parent_tenant_id } => {
            positive_body_id(*parent_tenant_id, "parentTenantId")?;
            if *parent_tenant_id == actor.tenant_id {
                return Err(AstralError::Validation(
                    "attach parent tenant must differ from the child tenant".into(),
                ));
            }
        }
        OrgScopeSubmitInput::Move {
            new_parent_tenant_id,
        } => {
            positive_body_id(*new_parent_tenant_id, "newParentTenantId")?;
            if *new_parent_tenant_id == actor.tenant_id {
                return Err(AstralError::Validation(
                    "move target parent must differ from the child tenant".into(),
                ));
            }
        }
        OrgScopeSubmitInput::Detach => {}
        OrgScopeSubmitInput::Grant { seed, parent_grant } => {
            seed.validate()?;
            positive_body_id(parent_grant.tenant_id, "parentGrant.tenantId")?;
            positive_revision(parent_grant.revision, "parentGrant.revision")?;
            if parent_grant.grant_id.trim().is_empty() || parent_grant.grant_id.len() > 36 {
                return Err(AstralError::Validation(
                    "parentGrant.grantId must be 1..=36 characters".into(),
                ));
            }
        }
    }
    db_commands::request_payload(actor, input)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== 配置 =====

    #[test]
    fn config_flag_is_strict_true_false_and_default_off() {
        std::env::remove_var("ASTRAL_ORG_SCOPE_ENABLED");
        assert!(org_authorities_config_from_env().unwrap().is_none());
        std::env::set_var("ASTRAL_ORG_SCOPE_ENABLED", "true");
        assert_eq!(
            org_authorities_config_from_env().unwrap(),
            Some(OrgAuthoritiesConfig { enabled: true })
        );
        std::env::set_var("ASTRAL_ORG_SCOPE_ENABLED", "false");
        assert!(org_authorities_config_from_env().unwrap().is_none());
        for garbage in ["True", "1", "yes", "on"] {
            std::env::set_var("ASTRAL_ORG_SCOPE_ENABLED", garbage);
            let error = org_authorities_config_from_env()
                .expect_err("invalid value must fail closed via the shared parser");
            assert!(
                error.to_string().contains("ASTRAL_ORG_SCOPE_ENABLED"),
                "invalid value {garbage:?} must name the deployment variable"
            );
        }
        std::env::remove_var("ASTRAL_ORG_SCOPE_ENABLED");
    }

    #[test]
    fn projector_coverage_requires_enabled_and_explicitly_owned_tenant() {
        let disabled = require_projector_tenant_coverage(false, &[20], 20)
            .expect_err("ORG mutations must be denied while the frozen feature is off");
        assert!(matches!(
            disabled,
            AstralError::Config(message)
                if message.contains("org_scope.projector_disabled_for_mutation")
        ));

        assert!(require_projector_tenant_coverage(true, &[20, 30], 30).is_ok());

        let uncovered = require_projector_tenant_coverage(true, &[20], 30)
            .expect_err("a durable authority-producing mutation needs a configured worker owner");
        assert!(matches!(
            uncovered,
            AstralError::Validation(message)
                if message.contains("org_scope.projector_tenant_not_configured;tenant_id=30")
        ));
    }

    #[test]
    fn coverage_gate_blocks_authority_creation_or_restoration_not_safety_reduction() {
        let source = include_str!("org_authorities.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source must precede tests");
        let method = |start: &str, next: &str| {
            let start = source.find(start).expect("method must remain");
            let end = source[start..]
                .find(next)
                .map(|offset| start + offset)
                .expect("next method boundary must remain");
            &source[start..end]
        };

        for (start, next) in [
            (
                "    pub async fn submit_request(",
                "    // ---- 审批 / 驳回 / 撤销 ----",
            ),
            ("    pub async fn approve_request(", "    /// 驳回请求"),
            ("    pub async fn remove_mask(", "    // ---- 成员资格 ----"),
            (
                "    pub async fn create_membership(",
                "    /// 撤销成员资格",
            ),
        ] {
            assert!(
                method(start, next).contains("self.require_projector_coverage("),
                "{start} must not create or restore usable authority without a configured projector owner"
            );
        }

        for (start, next) in [
            ("    pub async fn revoke_grant(", "    /// 本级精确来源剪裁"),
            (
                "    pub async fn apply_mask(",
                "    pub async fn remove_mask(",
            ),
            (
                "    pub async fn revoke_membership(",
                "    // ---- 内部 ----",
            ),
        ] {
            assert!(
                !method(start, next).contains("self.require_projector_coverage("),
                "{start} must remain available to reduce authority after coverage drift"
            );
        }
    }

    // ===== actor（签名上下文派生） =====

    fn policy_context(tenant: i64) -> PolicyContext {
        PolicyContext::builder()
            .user_id(Some(7))
            .principal_kind(Some("PLATFORM_USER".to_owned()))
            .identity_card_id(Some(700))
            .card_id(Some(70))
            .tenant_id(Some(tenant))
            .domain_id(Some(5))
            .resource(Some("permission_request".to_owned()))
            .action("create".to_owned())
            .build()
    }

    #[test]
    fn app_user_context_is_rejected_for_governance() {
        let context = PolicyContext::builder()
            .user_id(Some(7))
            .principal_kind(Some("APP_USER".to_owned()))
            .identity_card_id(Some(700))
            .action("read".to_owned())
            .build();
        let error = OrgActorContext::from_signed_context(&context, None).unwrap_err();
        assert!(matches!(error, AstralError::Auth(_)));
    }

    #[test]
    fn missing_signed_card_or_tenant_is_rejected() {
        let context = PolicyContext::builder()
            .user_id(Some(7))
            .principal_kind(Some("PLATFORM_USER".to_owned()))
            .identity_card_id(Some(700))
            .action("read".to_owned())
            .build();
        let error = OrgActorContext::from_signed_context(&context, None).unwrap_err();
        assert!(matches!(error, AstralError::Auth(_)));
    }

    #[test]
    fn mutation_requires_explicit_operation_id() {
        let actor = OrgActorContext::from_signed_context(&policy_context(20), None).unwrap();
        assert!(actor.require_operation_id().is_err());
        let actor =
            OrgActorContext::from_signed_context(&policy_context(20), Some("op-mt-0001")).unwrap();
        assert_eq!(actor.require_operation_id().unwrap(), "op-mt-0001");
    }

    #[test]
    fn unsafe_operation_id_is_rejected() {
        let error =
            OrgActorContext::from_signed_context(&policy_context(20), Some("bad id with space"))
                .unwrap_err();
        assert!(matches!(error, AstralError::Validation(_)));
    }

    /// grant/mask/membership 主键必须是 DB 生成的规范非 nil 小写 UUID 文本，
    /// 防止同一 durable subject 以多种文本表示绕过精确 revision/CAS 约束。
    #[test]
    fn stable_subject_ids_must_be_canonical_uuid_text() {
        let canonical = "0f0e0d0c-0b0a-0908-0706-050403020100";
        assert!(validate_stable_uuid(canonical, "grantId").is_ok());
        assert!(validate_stable_uuid("0F0E0D0C-0B0A-0908-0706-050403020100", "grantId").is_err());
        assert!(validate_stable_uuid("{0f0e0d0c-0b0a-0908-0706-050403020100}", "grantId").is_err());
        assert!(validate_stable_uuid("00000000-0000-0000-0000-000000000000", "grantId").is_err());
        assert!(validate_stable_uuid("not-a-uuid", "grantId").is_err());
    }

    // ===== 提交输入验证（纯函数，不触 DB） =====

    fn actor(tenant: i64) -> OrgActorContext {
        OrgActorContext::from_signed_context(&policy_context(tenant), Some("op-mt-0001")).unwrap()
    }

    fn seed(resource: &str) -> SeedInput {
        SeedInput {
            // 默认自源种子（actor tenant=20）；GRANT 的跨租户用例显式覆盖该值。
            resource_tenant_id: 20,
            resource: resource.to_owned(),
            action: "read".to_owned(),
            domain_id: Some(5),
            not_before: None,
            expires_at: None,
            delegable: false,
            subject: None,
        }
    }

    fn parent_ref() -> OrgGrantRef {
        OrgGrantRef {
            tenant_id: 30,
            grant_id: "0f0e0d0c-0b0a-0908-0706-050403020100".to_owned(),
            revision: 2,
        }
    }

    #[test]
    fn unregistered_scope_resource_is_rejected() {
        let error = validate_and_build_payload(
            &actor(20),
            &OrgScopeSubmitInput::Grant {
                seed: seed("definitely_not_registered"),
                parent_grant: parent_ref(),
            },
        )
        .unwrap_err();
        assert!(matches!(error, AstralError::Validation(_)));
    }

    #[test]
    fn grant_payload_preserves_seed_resource_tenant_and_parent_ref() {
        let payload = validate_and_build_payload(
            &actor(20),
            &OrgScopeSubmitInput::Grant {
                seed: seed("learn_course"),
                parent_grant: parent_ref(),
            },
        )
        .expect("registered scope must build");
        let OrgRequestPayload::Grant {
            receiving_tenant_id,
            parent_grant,
            scope,
            ..
        } = &payload
        else {
            panic!("expected GRANT payload");
        };
        // receiving tenant 来自签名 actor；scope resource tenant 来自显式种子。
        assert_eq!(*receiving_tenant_id, 20);
        assert_eq!(scope.resource_tenant_id, 20);
        assert_eq!(scope.resource, "learn_course");
        assert_eq!(parent_grant.tenant_id, 30);
        assert_eq!(parent_grant.revision, 2);
    }

    #[test]
    fn grant_payload_preserves_personal_subject() {
        let mut personal_seed = seed("learn_course");
        personal_seed.subject = Some(OrgSubject {
            user_id: 7,
            card_id: 70,
        });
        let payload = validate_and_build_payload(
            &actor(20),
            &OrgScopeSubmitInput::Grant {
                seed: personal_seed,
                parent_grant: parent_ref(),
            },
        )
        .expect("PERSONAL GRANT subject must build");
        let OrgRequestPayload::Grant { subject, .. } = payload else {
            panic!("expected GRANT payload");
        };
        assert_eq!(
            subject,
            Some(OrgSubject {
                user_id: 7,
                card_id: 70
            })
        );
    }

    #[test]
    fn root_payload_rejects_personal_subject() {
        let mut personal_seed = seed("learn_course");
        personal_seed.subject = Some(OrgSubject {
            user_id: 7,
            card_id: 70,
        });
        let error = validate_and_build_payload(
            &actor(20),
            &OrgScopeSubmitInput::RootGrant {
                seed: personal_seed,
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("shared UNIT"));
    }

    /// GRANT 的种子 resource tenant 保持显式值（允许跨租户后代委托），
    /// 绝不被 actor tenant 覆写；DB 在审批事务内用父 grant 包含性证明。
    #[test]
    fn grant_seed_resource_tenant_is_preserved_not_replaced_by_actor_tenant() {
        let mut cross_tenant_seed = seed("learn_course");
        cross_tenant_seed.resource_tenant_id = 30;
        let payload = validate_and_build_payload(
            &actor(20),
            &OrgScopeSubmitInput::Grant {
                seed: cross_tenant_seed,
                parent_grant: parent_ref(),
            },
        )
        .expect("cross-tenant GRANT seed must build");
        let OrgRequestPayload::Grant {
            receiving_tenant_id,
            parent_grant,
            scope,
            ..
        } = &payload
        else {
            panic!("expected GRANT payload");
        };
        assert_eq!(*receiving_tenant_id, 20);
        assert_eq!(parent_grant.tenant_id, 30);
        assert_eq!(scope.resource_tenant_id, 30);
    }

    /// ROOT_INIT/ROOT_GRANT 是永久 self-source 合同：resource tenant 必须等于
    /// 签名 actor tenant；跨租户资源范围只能通过带 parent provenance 的 GRANT
    /// 下发，不能由根请求隐式代理外部资源属主。
    #[test]
    fn root_init_rejects_seed_resource_tenant_outside_actor_tenant() {
        let mut foreign_seed = seed("learn_course");
        foreign_seed.resource_tenant_id = 30;
        let error = validate_and_build_payload(
            &actor(20),
            &OrgScopeSubmitInput::RootInit {
                seeds: vec![foreign_seed],
            },
        )
        .unwrap_err();
        assert!(matches!(error, AstralError::Validation(_)));
        assert!(error.to_string().contains("resourceTenantId"));
    }

    #[test]
    fn root_grant_rejects_seed_resource_tenant_outside_actor_tenant() {
        let mut foreign_seed = seed("learn_course");
        foreign_seed.resource_tenant_id = 30;
        let error = validate_and_build_payload(
            &actor(20),
            &OrgScopeSubmitInput::RootGrant { seed: foreign_seed },
        )
        .unwrap_err();
        assert!(matches!(error, AstralError::Validation(_)));
        assert!(error.to_string().contains("resourceTenantId"));
    }

    /// ROOT_GRANT 接受自源种子（resource tenant == actor tenant）且 payload 保持该值。
    #[test]
    fn root_grant_accepts_actor_tenant_resource_seed() {
        let payload = validate_and_build_payload(
            &actor(20),
            &OrgScopeSubmitInput::RootGrant {
                seed: seed("learn_course"),
            },
        )
        .expect("self-sourced ROOT_GRANT seed must build");
        let OrgRequestPayload::RootGrant {
            root_tenant_id,
            scope,
            ..
        } = &payload
        else {
            panic!("expected ROOT_GRANT payload");
        };
        assert_eq!(*root_tenant_id, 20);
        assert_eq!(scope.resource_tenant_id, 20);
    }

    #[test]
    fn attach_claiming_self_parent_is_rejected() {
        let error = validate_and_build_payload(
            &actor(20),
            &OrgScopeSubmitInput::Attach {
                parent_tenant_id: 20,
            },
        )
        .unwrap_err();
        assert!(matches!(error, AstralError::Validation(_)));
    }

    #[test]
    fn root_init_requires_one_to_max_seeds() {
        let error = validate_and_build_payload(
            &actor(20),
            &OrgScopeSubmitInput::RootInit { seeds: vec![] },
        )
        .unwrap_err();
        assert!(matches!(error, AstralError::Validation(_)));

        let payload = validate_and_build_payload(
            &actor(20),
            &OrgScopeSubmitInput::RootInit {
                seeds: vec![seed("learn_course")],
            },
        )
        .expect("single seed root init must build");
        let OrgRequestPayload::RootInit {
            root_tenant_id,
            initial_grants,
        } = &payload
        else {
            panic!("expected ROOT_INIT payload");
        };
        assert_eq!(*root_tenant_id, 20);
        assert_eq!(initial_grants.len(), 1);
        assert_eq!(initial_grants[0].scope.resource_tenant_id, 20);
    }

    #[test]
    fn inverted_validity_window_is_rejected() {
        let input = SeedInput {
            resource_tenant_id: 20,
            resource: "learn_course".to_owned(),
            action: "read".to_owned(),
            domain_id: Some(5),
            not_before: Some(200),
            expires_at: Some(100),
            delegable: false,
            subject: None,
        };
        let error = validate_and_build_payload(
            &actor(20),
            &OrgScopeSubmitInput::Grant {
                seed: input,
                parent_grant: parent_ref(),
            },
        )
        .unwrap_err();
        assert!(matches!(error, AstralError::Validation(_)));
    }

    #[test]
    fn grant_without_parent_ref_is_rejected() {
        let error = validate_and_build_payload(
            &actor(20),
            &OrgScopeSubmitInput::Grant {
                seed: seed("learn_course"),
                parent_grant: OrgGrantRef {
                    tenant_id: 0,
                    grant_id: parent_ref().grant_id,
                    revision: 0,
                },
            },
        )
        .unwrap_err();
        assert!(matches!(error, AstralError::Validation(_)));
    }

    // ===== kind → 授权方分派（纯函数） =====

    fn view_info(kind: OrgRequestKind) -> RequestViewInfo {
        RequestViewInfo {
            request_id: 1,
            status: "PENDING".into(),
            requesting_tenant_id: 20,
            revision: 3,
            counterparty_tenant_id: Some(30),
            kind,
        }
    }

    #[test]
    fn kind_authority_dispatch_is_structural() {
        assert_eq!(
            kind_authority(OrgRequestKind::Grant),
            KindAuthority::RequestingParent
        );
        assert_eq!(
            kind_authority(OrgRequestKind::Detach),
            KindAuthority::RequestingParent
        );
        assert_eq!(
            kind_authority(OrgRequestKind::Attach),
            KindAuthority::Counterparty
        );
        assert_eq!(
            kind_authority(OrgRequestKind::Move),
            KindAuthority::Counterparty
        );
        assert_eq!(
            kind_authority(OrgRequestKind::RootInit),
            KindAuthority::RootMeta
        );
        assert_eq!(
            kind_authority(OrgRequestKind::RootGrant),
            KindAuthority::RootMeta
        );
        assert!(view_info(OrgRequestKind::Grant).is_pending());
    }

    /// DB 请求视图映射：DB 列 `requester_tenant_id` 映射到服务面
    /// `requesting_tenant_id`，`revision` 透传到 GET 摘要（camelCase `revision`）。
    #[test]
    fn request_view_maps_requester_tenant_revision_and_counterparty() {
        let payload = validate_and_build_payload(
            &actor(20),
            &OrgScopeSubmitInput::Attach {
                parent_tenant_id: 30,
            },
        )
        .expect("attach payload must build");
        let view = OrgRequestView {
            request_id: 11,
            request_kind: "ATTACH".to_owned(),
            requester_tenant_id: 20,
            requester_user_id: 7,
            target_tenant_id: 20,
            parent_tenant_id: Some(30),
            status: "PENDING".to_owned(),
            revision: 4,
            payload,
            decided_by: None,
            decision_note: None,
            created_at_unix: Some(1_000),
            decided_at_unix: None,
        };
        let info = request_info_from_db(&view);
        assert_eq!(info.request_id, 11);
        assert_eq!(info.requesting_tenant_id, 20);
        assert_eq!(info.revision, 4);
        assert_eq!(info.counterparty_tenant_id, Some(30));
        assert!(info.is_pending());

        let summary = OrgScopeRequestSummary {
            request_id: info.request_id,
            kind: info.kind.as_str().to_owned(),
            status: info.status.clone(),
            requesting_tenant_id: info.requesting_tenant_id,
            counterparty_tenant_id: info.counterparty_tenant_id,
            revision: info.revision,
        };
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["revision"], serde_json::json!(4));
        assert_eq!(json["requestingTenantId"], serde_json::json!(20));
        assert_eq!(json["counterpartyTenantId"], serde_json::json!(30));
    }

    /// 驳回命令携带治理证明（ROOT_INIT/ROOT_GRANT 驳回权与审批权同界的 DB
    /// 合同载体）：服务层在 PolicyEngine 元能力放行后随命令传入证明，DB 层
    /// 复核结构并 durable 落审计；非根驳回传 `None`（行为不变）。
    #[test]
    fn reject_command_carries_governance_proof() {
        let decider = actor(20);
        let proof = OrgGovernanceProof {
            permission_resource: META_RESOURCE.to_owned(),
            permission_action: META_ACTION_BOOTSTRAP.to_owned(),
            admission_operation_id: "op-mt-0001".to_owned(),
            approved_capabilities: Vec::new(),
        };
        let cmd = db_commands::reject_request(&decider, 1, 3, None, Some(proof.clone()));
        assert_eq!(cmd.governance_proof.as_ref(), Some(&proof));
        let cmd = db_commands::reject_request(&decider, 1, 3, None, None);
        assert!(cmd.governance_proof.is_none());
    }
}
