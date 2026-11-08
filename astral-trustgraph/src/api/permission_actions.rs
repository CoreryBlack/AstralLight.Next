//! 权限动作管理 API（DomainController 拆分模块 3/7）— HTTP adapter
//!
//! 数据访问在 `repository::permission_action_repository`；
//! scan 的 `ResourceRegistry`/`async_tracker` 编排保留在 handler（in-memory），
//! scan 路径维持 `NotImplemented`（Rust 无运行时注解扫描器），不进入 source
//! 事务。
//!
//! create/update/delete 是动作词汇治理 mutation（与 `ResourceRegistry` 共同
//! 构成授权模型的对象/动作词汇表）：handler 必须先过 `require_platform_admin`
//! 的既有 GlobalAdmin 门禁，再提取 permission 中间件注入的
//! `AuthorizationAdmission` 与已验证 `PolicyContext`，且 Gateway 身份头必须与
//! 该 context 完全一致后才能构造 `PermissionActionMutationContext`（缺失
//! admission 的 Extension 提取直接 fail-closed）。GET/list 为只读路径，不注入
//! admission、不开启 source 事务。事务内的 actor 卡行对牌、目标行锁、insert +
//! 查回原子性与 proven-commit 语义由 repository 承担（create 的 INSERT 与
//! reselect 在同一 source 事务内原子完成）。

use axum::extract::{Extension, Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::{ApiResponse, PageResponse, PaginationParams};
use astral_common::error::AppError;
use astral_types::{AstralError, AuthorizationAdmission, PolicyContext};

use crate::api::async_tracker::AsyncTask;
use crate::api::require_platform_admin;
use crate::repository::permission_action_repository::{
    ActionFilter, ActionPatch, PermissionActionMutationContext, PermissionActionRecord,
};
use crate::AppState;

// ===== Row / DTO =====

/// permission_action 响应 DTO（对齐 Java PermissionAction + 前端 Feature 类型）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionActionRow {
    pub id: i64,                     // action_id as id
    pub domain_id: Option<i64>,      // domain_id
    pub resource_type_id: i64,       // resource_type_id（前端 moduleId）
    pub code: String,                // action_code as code
    pub name: String,                // action_name as name
    pub description: Option<String>, // action_description as description
    pub created_at: Option<String>,
}

impl From<PermissionActionRecord> for PermissionActionRow {
    fn from(r: PermissionActionRecord) -> Self {
        Self {
            id: r.id,
            domain_id: r.domain_id,
            resource_type_id: r.resource_type_id,
            code: r.code,
            name: r.name,
            description: r.description,
            created_at: r.created_at,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateActionRequest {
    pub domain_id: Option<i64>,
    pub resource_type_id: i64,
    pub code: String,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateActionRequest {
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionQuery {
    pub domain_id: Option<i64>,
    pub resource_type_id: Option<i64>,
    pub resource_type_ids: Option<String>, // 逗号分隔的 ID 列表
}

// ===== Routes =====

pub fn permission_action_routes() -> Router<AppState> {
    Router::new()
        .route("/actions", get(list_actions))
        .route("/actions", post(create_action))
        .route("/actions/{id}", put(update_action))
        .route("/actions/{id}", delete(delete_action))
        .route("/actions/scan", post(scan_actions))
        .route("/actions/scan/async", post(scan_actions_async))
}

// ===== Handlers =====

/// Build a permission-action mutation context from the permission middleware's
/// verified extension. The Gateway headers are only accepted when they exactly
/// agree with that extension; the proof-bound admission is required for the
/// source transaction.
fn permission_action_mutation_context(
    headers: &HeaderMap,
    policy_context: &PolicyContext,
    admission: AuthorizationAdmission,
) -> Result<PermissionActionMutationContext, AppError> {
    let parse = |name: &'static str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<i64>().ok())
            .filter(|value| *value > 0)
            .ok_or_else(|| {
                AppError(AstralError::Auth(format!(
                    "Gateway-verified {name} is required"
                )))
            })
    };
    let user_id = parse("x-user-id")?;
    let card_id = parse("x-user-card-id")?;
    let tenant_id = parse("x-user-card-tenant-id")?;
    let domain_id = parse("x-user-card-domain-id")?;
    if policy_context.principal_kind.as_deref() != Some("PLATFORM_USER")
        || policy_context.user_id != Some(user_id)
        || policy_context.card_id != Some(card_id)
        || policy_context.tenant_id != Some(tenant_id)
        || policy_context.domain_id != Some(domain_id)
    {
        return Err(AppError(AstralError::Auth(
            "permission action mutation Gateway headers do not match the verified PolicyContext"
                .into(),
        )));
    }
    let request_id = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok());
    PermissionActionMutationContext::from_policy_context(policy_context, request_id)
        .map(|context| context.with_admission(admission))
        .map_err(AppError::from)
}

/// GET /main/api/v1/actions — 列表（支持 domainId/resourceTypeId 过滤，分页）
async fn list_actions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ActionQuery>,
    Query(page): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<PermissionActionRow>>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    // 解析 resourceTypeId / resourceTypeIds
    let rt_ids: Vec<i64> = if let Some(ref ids_str) = q.resource_type_ids {
        ids_str
            .split(',')
            .filter_map(|s| s.trim().parse::<i64>().ok())
            .collect()
    } else {
        Vec::new()
    };
    let single_rt_id = q.resource_type_id;
    let effective_rt_ids: Vec<i64> = if rt_ids.is_empty() {
        single_rt_id.map(|id| vec![id]).unwrap_or_default()
    } else {
        rt_ids
    };

    let filter = ActionFilter {
        domain_id: q.domain_id,
        resource_type_ids: effective_rt_ids,
    };
    let total = state
        .permission_action_repository
        .count_actions(&filter)
        .await?;
    let rows = state
        .permission_action_repository
        .list_actions(&filter, page.effective_size(), page.offset())
        .await?
        .into_iter()
        .map(PermissionActionRow::from)
        .collect();
    Ok(Json(ApiResponse::success(PageResponse::new(
        rows,
        total,
        page.page,
        page.effective_size(),
    ))))
}

/// POST /main/api/v1/actions — 创建
///
/// 要求已验证 ACTIVE GlobalAdmin；mutation 经 proof-bound admission source
/// transaction 落库（INSERT 与 reselect 同事务原子完成）。
async fn create_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy_context): Extension<PolicyContext>,
    Extension(admission): Extension<AuthorizationAdmission>,
    Json(req): Json<CreateActionRequest>,
) -> Result<Json<ApiResponse<PermissionActionRow>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let context = permission_action_mutation_context(&headers, &policy_context, admission)?;
    if req.code.is_empty() {
        return Err(AppError(AstralError::Validation(
            "action_code must not be empty".into(),
        )));
    }

    let row = state
        .permission_action_repository
        .create_action_with_context(
            req.domain_id,
            req.resource_type_id,
            &req.code,
            &req.name,
            req.description.as_deref(),
            &context,
        )
        .await?;

    tracing::info!(action_code = %req.code, resource_type_id = req.resource_type_id, "permission action created");
    Ok(Json(ApiResponse::success(PermissionActionRow::from(row))))
}

/// PUT /main/api/v1/actions/{id} — 更新
///
/// 要求已验证 ACTIVE GlobalAdmin；mutation 经 proof-bound admission source
/// transaction 落库（目标行锁与 UPDATE 原子）。
async fn update_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy_context): Extension<PolicyContext>,
    Extension(admission): Extension<AuthorizationAdmission>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateActionRequest>,
) -> Result<Json<ApiResponse<PermissionActionRow>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let context = permission_action_mutation_context(&headers, &policy_context, admission)?;
    let patch = ActionPatch {
        name: req.name,
        description: req.description,
    };
    let updated = state
        .permission_action_repository
        .update_action_with_context(id, &patch, &context)
        .await?;
    if !updated {
        return Err(AppError(AstralError::NotFound(format!("action {id}"))));
    }

    let row = state
        .permission_action_repository
        .get_action(id)
        .await?
        .map(PermissionActionRow::from)
        .ok_or_else(|| AppError(AstralError::NotFound(format!("action {id}"))))?;

    tracing::info!(id, "permission action updated");
    Ok(Json(ApiResponse::success(row)))
}

/// DELETE /main/api/v1/actions/{id} — 删除
///
/// 要求已验证 ACTIVE GlobalAdmin；mutation 经 proof-bound admission source
/// transaction 落库（目标行锁与 DELETE 原子）。
async fn delete_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy_context): Extension<PolicyContext>,
    Extension(admission): Extension<AuthorizationAdmission>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let context = permission_action_mutation_context(&headers, &policy_context, admission)?;
    let deleted = state
        .permission_action_repository
        .delete_action_with_context(id, &context)
        .await?;
    if !deleted {
        return Err(AppError(AstralError::NotFound(format!("action {id}"))));
    }

    tracing::warn!(id, "permission action deleted");
    Ok(Json(ApiResponse::success(serde_json::json!({
        "id": id,
        "deleted": true,
    }))))
}

/// GET /main/api/v1/actions/scan — 同步扫描
///
/// 汇总 ResourceRegistry 中所有出现过的动作，同步到 permission_action 表。
/// scan 编排保留在 handler（in-memory，不进入 source 事务）；路径维持
/// `NotImplemented`（Rust 无运行时注解扫描器）。
async fn scan_actions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ApiResponse<Vec<PermissionActionRow>>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    Err(AppError(AstralError::NotImplemented(
        "permission action scan is not implemented: Rust has no runtime annotation scanner".into(),
    )))
}

/// POST /main/api/v1/actions/scan/async — 异步扫描（注册到 tracker）
///
/// scan 编排保留在 handler（in-memory，不进入 source 事务）；路径维持
/// `NotImplemented`（Rust 无运行时注解扫描器）。
async fn scan_actions_async(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ApiResponse<AsyncTask>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    Err(AppError(AstralError::NotImplemented(
        "permission action async scan is not implemented: Rust has no runtime annotation scanner"
            .into(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn platform_policy_context(
        user_id: i64,
        card_id: i64,
        tenant_id: i64,
        domain_id: i64,
    ) -> PolicyContext {
        PolicyContext::builder()
            .user_id(Some(user_id))
            .principal_kind(Some("PLATFORM_USER".into()))
            .card_id(Some(card_id))
            .tenant_id(Some(tenant_id))
            .domain_id(Some(domain_id))
            .action("manage".into())
            .build()
    }

    fn verified_headers(
        user_id: i64,
        card_id: i64,
        tenant_id: i64,
        domain_id: i64,
        request_id: &str,
    ) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("x-user-id", user_id.to_string()),
            ("x-user-card-id", card_id.to_string()),
            ("x-user-card-tenant-id", tenant_id.to_string()),
            ("x-user-card-domain-id", domain_id.to_string()),
            ("x-request-id", request_id.to_string()),
        ] {
            headers.insert(
                name,
                HeaderValue::from_str(&value).expect("valid header value"),
            );
        }
        headers
    }

    /// 权限动作 mutation 与 departments/user-levels mutation 共用同一装配合同：
    /// Gateway 头必须与验证过的 PolicyContext 完全一致，缺头/不一致/非平台身份/
    /// 缺失 request id 一律拒绝。
    #[test]
    fn permission_action_mutation_context_requires_header_policy_agreement() {
        let policy = platform_policy_context(10, 20, 30, 40);
        let admission_fn = || {
            // admission 只作为不透明能力透传；装配合同测试关注 header/context
            // 一致性与 request id，能力本身由 repository 的锁定行对牌复核。
            build_test_admission()
        };
        let agreed = permission_action_mutation_context(
            &verified_headers(10, 20, 30, 40, "req-7"),
            &policy,
            admission_fn(),
        );
        assert!(agreed.is_ok(), "agreed headers must build the context");

        for tampered in [
            verified_headers(11, 20, 30, 40, "req-7"),
            verified_headers(10, 21, 30, 40, "req-7"),
            verified_headers(10, 20, 31, 40, "req-7"),
            verified_headers(10, 20, 30, 41, "req-7"),
        ] {
            assert!(
                permission_action_mutation_context(&tampered, &policy, admission_fn()).is_err(),
                "any header disagreeing with the verified PolicyContext must be rejected"
            );
        }
        assert!(
            permission_action_mutation_context(&HeaderMap::new(), &policy, admission_fn()).is_err(),
            "missing Gateway headers must be rejected"
        );

        let non_platform = PolicyContext::builder()
            .user_id(Some(10))
            .principal_kind(Some("END_USER".into()))
            .card_id(Some(20))
            .tenant_id(Some(30))
            .domain_id(Some(40))
            .action("manage".into())
            .build();
        assert!(
            permission_action_mutation_context(
                &verified_headers(10, 20, 30, 40, "req-7"),
                &non_platform,
                admission_fn()
            )
            .is_err(),
            "non-platform principal must be rejected"
        );

        // 缺失 request id：授权 mutation 无随机 fallback，直接拒绝。
        let mut no_request_id = verified_headers(10, 20, 30, 40, "req-7");
        no_request_id.remove("x-request-id");
        assert!(
            permission_action_mutation_context(&no_request_id, &policy, admission_fn()).is_err(),
            "a missing request id must fail closed"
        );
    }

    /// 结构守卫（include_str!，不连 DB）：create/update/delete 必须提取
    /// `Extension<AuthorizationAdmission>` 与 `Extension<PolicyContext>`、保留
    /// `require_platform_admin` 门禁、并经 `permission_action_mutation_context`
    /// 装配后走 `_with_context` 入口；GET/list 保持只读（不提取 admission、
    /// 不开启 source 事务）；scan 路径保持 NotImplemented 编排。
    #[test]
    fn mutation_handlers_require_admission_and_read_paths_stay_context_free() {
        let source = include_str!("permission_actions.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source must exist");
        let handler_body = |name: &str| -> String {
            let start = production
                .find(&format!("async fn {name}"))
                .unwrap_or_else(|| panic!("{name} handler must exist"));
            let rest = &production[start..];
            let end = rest[1..]
                .find("async fn ")
                .map(|offset| offset + 1)
                .unwrap_or(rest.len());
            rest[..end].to_owned()
        };

        for name in ["create_action", "update_action", "delete_action"] {
            let body = handler_body(name);
            assert!(
                body.contains("Extension(admission): Extension<AuthorizationAdmission>"),
                "{name} must require the proof-bound admission extension"
            );
            assert!(
                body.contains("Extension(policy_context): Extension<PolicyContext>"),
                "{name} must require the verified PolicyContext extension"
            );
            assert!(
                body.contains(concat!(
                    "require_platform_",
                    "admin(&state, &headers).await?"
                )),
                "{name} must keep the platform admin gate"
            );
            assert!(
                body.contains(concat!(
                    "permission_action_mutation_context(&headers, &policy_context, ",
                    "admission)"
                )),
                "{name} must assemble the mutation context through the verified path"
            );
            assert!(
                body.contains("_with_context"),
                "{name} must dispatch through the context-bound repository entry"
            );
        }

        // create 必须走原子 insert+reselect 的 context-bound 入口，且不再依赖
        // 事务外的第二次读取来组装响应行。
        let create_body = handler_body("create_action");
        assert!(
            create_body.contains("create_action_with_context("),
            "create must dispatch through the atomic insert+reselect entry"
        );
        assert!(
            !create_body.contains(".get_action("),
            "create must not re-read the row outside the source transaction"
        );

        let list_body = handler_body("list_actions");
        assert!(
            !list_body.contains("AuthorizationAdmission")
                && !list_body.contains("begin_source_transaction"),
            "GET/list must stay a read-only path without admission or source transactions"
        );
        assert!(
            !production.contains("tx.commit()"),
            "the HTTP adapter must never commit a source transaction directly"
        );
    }

    /// scan 编排保留在 handler 且路径维持 NotImplemented：不实现扫描、不把
    /// ResourceRegistry 编排移入 source 事务。
    #[test]
    fn scan_paths_stay_not_implemented_and_outside_source_transactions() {
        let source = include_str!("permission_actions.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source must exist");
        for name in ["scan_actions", "scan_actions_async"] {
            let body = production
                .find(&format!("async fn {name}"))
                .map(|start| {
                    let rest = &production[start..];
                    let end = rest[1..]
                        .find("async fn ")
                        .map(|offset| offset + 1)
                        .unwrap_or(rest.len());
                    rest[..end].to_owned()
                })
                .unwrap_or_else(|| panic!("{name} handler must exist"));
            assert!(
                body.contains("AstralError::NotImplemented"),
                "{name} must stay NotImplemented (no runtime annotation scanner)"
            );
            assert!(
                !body.contains("_with_context") && !body.contains("source_transaction"),
                "{name} must not open or dispatch source transactions"
            );
        }
    }

    fn build_test_admission() -> AuthorizationAdmission {
        let proof = astral_types::AuthorizationFenceProof {
            authorization_edition: astral_types::AUTHORIZATION_EDITION,
            authority_id: "authority-test".into(),
            authority_term: 1,
            global_fence_sequence: 1,
            scope: astral_types::AuthorizationAuthorityScope {
                tenant_id: 30,
                card_id: 20,
                user_id: Some(10),
                domain: astral_types::AuthorizationDomainScope::Exact(40),
            },
            scope_generation: 1,
            revoke_watermark: 0,
            snapshot_hash: "a".repeat(64),
            parent_hash: None,
            operation_id: "op-action-api-test".into(),
            event_id: "evt-action-api-test".into(),
            key_id: "key-test".into(),
            key_epoch: 1,
            issued_at: 1_700_000_000,
            not_before: 1_700_000_000,
            expires_at: 1_700_000_400,
            request_nonce: "nonce-action-api-test".into(),
            request_binding_digest: None,
            scope_certificate_hash: None,
            proof_id: "proof-action-api-test".into(),
            signature: "ab".repeat(64),
        };
        AuthorizationAdmission::from_verified_proof(proof).expect("structurally valid proof")
    }
}
