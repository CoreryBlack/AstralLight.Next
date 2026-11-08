//! 用户等级定义 API（DomainController 拆分模块 4/7）— HTTP adapter
//!
//! 提供 user_card_level_definition 表的 CRUD。
//! 对齐 Java `DomainControlController` 中用户等级定义部分。
//! 数据访问在 `repository::level_repository`，HTTP 层仅解析参数并包装响应。
//! 路径前缀：`/main/api/v1/user-levels`
//!
//! create/update/delete 是等级定义治理 mutation：handler 必须提取 permission
//! 中间件注入的 `AuthorizationAdmission` 与已验证 `PolicyContext`，且 Gateway
//! 身份头必须与该 context 完全一致后才能构造 `LevelMutationContext`
//! （缺失 admission 的 Extension 提取直接 fail-closed）；`require_platform_admin`
//! 的既有 GlobalAdmin 门禁保持不变。GET/list 为只读路径，不注入 admission、
//! 不开启 source 事务。事务内的 actor 卡行对牌、目标行锁、守卫与
//! proven-commit 语义由 repository 承担。

use axum::extract::{Extension, Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::{ApiResponse, PageResponse, PaginationParams};
use astral_common::error::AppError;
use astral_types::{AstralError, AuthorizationAdmission, PolicyContext};

use crate::api::require_platform_admin;
use crate::repository::level_repository::{
    LevelFilter, LevelMutationContext, LevelPatch, LevelRecord, NewLevel,
};
use crate::AppState;

// ===== DTO =====

/// 用户等级响应 DTO（对齐 Java IdentityUserLevelDefinition + 前端 UserLevelDefinition 的 camelCase）
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserLevelDto {
    pub level_id: i64,
    pub domain_id: i64,
    pub level_no: i32,
    pub level_code: String,
    pub level_name: String,
    pub status: String,
    pub upgrade_strategy_json: Option<String>,
    pub description: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl From<LevelRecord> for UserLevelDto {
    fn from(r: LevelRecord) -> Self {
        Self {
            level_id: r.level_id,
            domain_id: r.domain_id,
            level_no: r.level_no,
            level_code: r.level_code,
            level_name: r.level_name,
            status: r.status,
            upgrade_strategy_json: r.upgrade_strategy_json,
            description: r.description,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateUserLevelRequest {
    pub domain_id: i64,
    pub level_name: String,
    pub level_code: String,
    pub level_no: Option<i32>,
    pub upgrade_strategy_json: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateUserLevelRequest {
    pub level_name: Option<String>,
    pub level_code: Option<String>,
    pub level_no: Option<i32>,
    pub status: Option<String>,
    pub upgrade_strategy_json: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserLevelQuery {
    pub domain_id: Option<i64>,
    pub status: Option<String>,
}

// ===== Routes =====

pub fn user_level_routes() -> Router<AppState> {
    Router::new()
        .route("/user-levels", get(list_user_levels))
        .route("/user-levels", post(create_user_level))
        .route("/user-levels/{id}", put(update_user_level))
        .route("/user-levels/{id}", delete(delete_user_level))
}

// ===== Handlers =====

/// Build a user-level mutation context from the permission middleware's verified
/// extension. The Gateway headers are only accepted when they exactly agree with
/// that extension; the proof-bound admission is required for the source transaction.
fn user_level_mutation_context(
    headers: &HeaderMap,
    policy_context: &PolicyContext,
    admission: AuthorizationAdmission,
) -> Result<LevelMutationContext, AppError> {
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
            "user level mutation Gateway headers do not match the verified PolicyContext".into(),
        )));
    }
    let request_id = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok());
    LevelMutationContext::from_policy_context(policy_context, request_id)
        .map(|context| context.with_admission(admission))
        .map_err(AppError::from)
}

/// GET /main/api/v1/user-levels — 列表（支持 domain_id 过滤，分页）
async fn list_user_levels(
    State(state): State<AppState>,
    Query(q): Query<UserLevelQuery>,
    Query(page): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<UserLevelDto>>>, AppError> {
    let filter = LevelFilter {
        domain_id: q.domain_id,
        status: q.status.as_ref().map(|s| s.to_uppercase()),
    };
    let total = state.level_repository.count_levels(&filter).await?;
    let rows = state
        .level_repository
        .list_levels(&filter, page.effective_size(), page.offset())
        .await?
        .into_iter()
        .map(UserLevelDto::from)
        .collect();
    Ok(Json(ApiResponse::success(PageResponse::new(
        rows,
        total,
        page.page,
        page.effective_size(),
    ))))
}

/// POST /main/api/v1/user-levels — 创建
///
/// 对齐 Java `DomainControlServiceImpl.createUserLevel`：要求已验证 ACTIVE
/// GlobalAdmin；mutation 经 proof-bound admission source transaction 落库。
async fn create_user_level(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy_context): Extension<PolicyContext>,
    Extension(admission): Extension<AuthorizationAdmission>,
    Json(req): Json<CreateUserLevelRequest>,
) -> Result<Json<ApiResponse<UserLevelDto>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let context = user_level_mutation_context(&headers, &policy_context, admission)?;
    if req.level_name.is_empty() || req.level_code.is_empty() {
        return Err(AppError(AstralError::Validation(
            "level_name and level_code must not be empty".into(),
        )));
    }

    let new_id = state
        .level_repository
        .create_level_with_context(
            &NewLevel {
                domain_id: req.domain_id,
                level_name: req.level_name,
                level_code: req.level_code,
                level_no: req.level_no.unwrap_or(0),
                upgrade_strategy_json: req.upgrade_strategy_json,
                description: req.description,
            },
            &context,
        )
        .await?;
    let row = state
        .level_repository
        .get_level(new_id)
        .await?
        .map(UserLevelDto::from)
        .ok_or_else(|| AppError(AstralError::NotFound(format!("user_level {new_id}"))))?;

    tracing::info!(id = new_id, domain_id = req.domain_id, "user level created");
    Ok(Json(ApiResponse::success(row)))
}

/// PUT /main/api/v1/user-levels/{id} — 更新
///
/// 对齐 Java `DomainControlServiceImpl.updateUserLevel`：要求已验证 ACTIVE
/// GlobalAdmin；mutation 经 proof-bound admission source transaction 落库。
async fn update_user_level(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy_context): Extension<PolicyContext>,
    Extension(admission): Extension<AuthorizationAdmission>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateUserLevelRequest>,
) -> Result<Json<ApiResponse<UserLevelDto>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let context = user_level_mutation_context(&headers, &policy_context, admission)?;
    // 状态白名单校验（对齐现有 handler 语义）
    let status = match req.status.as_ref() {
        Some(raw) => {
            let upper = raw.to_uppercase();
            if upper != "ACTIVE" && upper != "INACTIVE" {
                return Err(AppError(AstralError::Validation(
                    "status must be ACTIVE or INACTIVE".into(),
                )));
            }
            Some(upper)
        }
        None => None,
    };

    let patch = LevelPatch {
        level_name: req.level_name,
        level_code: req.level_code,
        level_no: req.level_no,
        status,
        upgrade_strategy_json: req.upgrade_strategy_json,
        description: req.description,
    };
    state
        .level_repository
        .update_level_with_context(id, &patch, &context)
        .await?;

    let row = state
        .level_repository
        .get_level(id)
        .await?
        .map(UserLevelDto::from)
        .ok_or_else(|| AppError(AstralError::NotFound(format!("user_level {id}"))))?;

    tracing::info!(id, "user level updated");
    Ok(Json(ApiResponse::success(row)))
}

/// DELETE /main/api/v1/user-levels/{id} — 删除
///
/// 级联删除引用此等级的 identity_user_grading 记录（FK ON DELETE CASCADE）。
/// 对齐 Java `DomainControlServiceImpl.deleteUserLevel`：要求已验证 ACTIVE
/// GlobalAdmin；mutation 经 proof-bound admission source transaction 落库。
async fn delete_user_level(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy_context): Extension<PolicyContext>,
    Extension(admission): Extension<AuthorizationAdmission>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let context = user_level_mutation_context(&headers, &policy_context, admission)?;
    let deleted = state
        .level_repository
        .delete_level_with_context(id, &context)
        .await?;
    if !deleted {
        return Err(AppError(AstralError::NotFound(format!("user_level {id}"))));
    }

    tracing::warn!(id, "user level deleted (cascade: identity_user_grading)");
    Ok(Json(ApiResponse::success(serde_json::json!({
        "id": id,
        "deleted": true,
    }))))
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

    /// 用户等级 mutation 与 departments mutation 共用同一装配合同：Gateway 头
    /// 必须与验证过的 PolicyContext 完全一致，缺头/不一致/非平台身份/缺失
    /// request id 一律拒绝。
    #[test]
    fn user_level_mutation_context_requires_header_policy_agreement() {
        let policy = platform_policy_context(10, 20, 30, 40);
        let admission_fn = || {
            // admission 只作为不透明能力透传；装配合同测试关注 header/context
            // 一致性与 request id，能力本身由 repository 的锁定行对牌复核。
            build_test_admission()
        };
        let agreed = user_level_mutation_context(
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
                user_level_mutation_context(&tampered, &policy, admission_fn()).is_err(),
                "any header disagreeing with the verified PolicyContext must be rejected"
            );
        }
        assert!(
            user_level_mutation_context(&HeaderMap::new(), &policy, admission_fn()).is_err(),
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
            user_level_mutation_context(
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
            user_level_mutation_context(&no_request_id, &policy, admission_fn()).is_err(),
            "a missing request id must fail closed"
        );
    }

    /// 结构守卫（include_str!，不连 DB）：create/update/delete 必须提取
    /// `Extension<AuthorizationAdmission>` 与 `Extension<PolicyContext>`、
    /// 保留 `require_platform_admin` 门禁、并经 `user_level_mutation_context`
    /// 装配后走 `_with_context` 入口；GET/list 保持只读（不提取 admission、
    /// 不开启 source 事务）。
    #[test]
    fn mutation_handlers_require_admission_and_read_paths_stay_context_free() {
        let source = include_str!("user_levels.rs");
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

        for name in [
            "create_user_level",
            "update_user_level",
            "delete_user_level",
        ] {
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
                body.contains("user_level_mutation_context(&headers, &policy_context, admission)"),
                "{name} must assemble the mutation context through the verified path"
            );
            assert!(
                body.contains("_with_context"),
                "{name} must dispatch through the context-bound repository entry"
            );
        }

        let list_body = handler_body("list_user_levels");
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
            operation_id: "op-level-api-test".into(),
            event_id: "evt-level-api-test".into(),
            key_id: "key-test".into(),
            key_epoch: 1,
            issued_at: 1_700_000_000,
            not_before: 1_700_000_000,
            expires_at: 1_700_000_400,
            request_nonce: "nonce-level-api-test".into(),
            request_binding_digest: None,
            scope_certificate_hash: None,
            proof_id: "proof-level-api-test".into(),
            signature: "ab".repeat(64),
        };
        AuthorizationAdmission::from_verified_proof(proof).expect("structurally valid proof")
    }
}
