//! 权限继承配置 API — HTTP adapter
//!
//! 对齐 Java `PermissionInheritanceConfigService`。
//! 数据访问在 `repository::inheritance_config_repository`，HTTP 层仅校验白名单并包装响应。
//!
//! upsert/delete 是继承配置治理 mutation（影响权限继承聚合语义的 source
//! mutation）：handler 必须先过 `require_platform_admin` 的既有 GlobalAdmin
//! 门禁，再提取 permission 中间件注入的 `AuthorizationAdmission` 与已验证
//! `PolicyContext`，且 Gateway 身份头必须与该 context 完全一致后才能构造
//! `InheritanceMutationContext`（缺失 admission 的 Extension 提取直接
//! fail-closed）。GET/list 为只读路径，不注入 admission、不开启 source 事务。
//! `ResourceRegistry` 注册资源类型校验属于进程内编排，在**开启 source 事务
//! 之前**完成，不进入事务。事务内的 actor 卡行对牌、目标行锁、UPSERT+查回
//! 原子性与 proven-commit 语义由 repository 承担。

use axum::extract::{Extension, Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::{ApiResponse, EmptyResponse, PageResponse, PaginationParams};
use astral_common::error::AppError;
use astral_types::{AstralError, AuthorizationAdmission, PolicyContext, ResourceRegistry};

use crate::api::require_platform_admin;
use crate::repository::inheritance_config_repository::{
    InheritanceConfigRecord, InheritanceMutationContext,
};
use crate::AppState;

// ===== 数据模型 =====

/// 继承配置响应 DTO（对应 permission_inheritance_config 表 camelCase）
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InheritanceConfig {
    pub id: i64,
    pub resource_type: String,
    /// 继承模式（NONE / PARENT_ONLY / CUMULATIVE）
    pub inheritance_mode: String,
    pub updated_at: Option<i64>,
}

impl From<InheritanceConfigRecord> for InheritanceConfig {
    fn from(r: InheritanceConfigRecord) -> Self {
        Self {
            id: r.id,
            resource_type: r.resource_type,
            inheritance_mode: r.inheritance_mode,
            updated_at: r.updated_at,
        }
    }
}

/// 更新继承模式请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInheritanceRequest {
    pub inheritance_mode: String,
}

/// 创建继承配置请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateInheritanceRequest {
    pub resource_type: String,
    pub inheritance_mode: String,
}

// ===== 路由注册 =====

pub fn inheritance_routes() -> Router<AppState> {
    Router::new()
        .route("/inheritance/config", get(list_inheritance_configs))
        .route("/inheritance/config", post(create_inheritance_config))
        .route(
            "/inheritance/config/{resource_type}",
            put(update_inheritance_config),
        )
        .route(
            "/inheritance/config/{resource_type}",
            delete(delete_inheritance_config),
        )
}

const VALID_MODES: [&str; 3] = ["NONE", "PARENT_ONLY", "CUMULATIVE"];

fn validate_registered_resource_type(resource_type: &str) -> Result<(), AppError> {
    let actions = ResourceRegistry::global()
        .list_actions(resource_type)
        .ok_or_else(|| {
            AppError(AstralError::Validation(format!(
                "resource_type '{resource_type}' is not registered"
            )))
        })?;
    if actions.is_empty() {
        return Err(AppError(AstralError::Validation(format!(
            "resource_type '{resource_type}' has no registered actions"
        ))));
    }
    Ok(())
}

fn validate_inheritance_mode(inheritance_mode: &str) -> Result<(), AppError> {
    if !VALID_MODES.contains(&inheritance_mode) {
        return Err(AppError(AstralError::Validation(
            "inheritance_mode must be NONE, PARENT_ONLY, or CUMULATIVE".into(),
        )));
    }
    Ok(())
}

// ===== Handlers =====

/// Build an inheritance mutation context from the permission middleware's
/// verified extension. The Gateway headers are only accepted when they exactly
/// agree with that extension; the proof-bound admission is required for the
/// source transaction.
fn inheritance_mutation_context(
    headers: &HeaderMap,
    policy_context: &PolicyContext,
    admission: AuthorizationAdmission,
) -> Result<InheritanceMutationContext, AppError> {
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
            "inheritance mutation Gateway headers do not match the verified PolicyContext".into(),
        )));
    }
    let request_id = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok());
    InheritanceMutationContext::from_policy_context(policy_context, request_id)
        .map(|context| context.with_admission(admission))
        .map_err(AppError::from)
}

/// GET /main/api/v1/inheritance/config — 列出所有继承配置（分页）
async fn list_inheritance_configs(
    State(state): State<AppState>,
    Query(page): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<InheritanceConfig>>>, AppError> {
    let total = state.inheritance_config_repository.count_configs().await?;
    let rows = state
        .inheritance_config_repository
        .list_configs(page.effective_size(), page.offset())
        .await?
        .into_iter()
        .map(InheritanceConfig::from)
        .collect();
    Ok(Json(ApiResponse::success(PageResponse::new(
        rows,
        total,
        page.page,
        page.effective_size(),
    ))))
}

/// PUT /main/api/v1/inheritance/config/{resource_type} — 更新继承模式
///
/// 对齐既有 upsert 语义：要求已验证 ACTIVE GlobalAdmin；mutation 经
/// proof-bound admission source transaction 落库（UPSERT 与查回同事务原子）。
async fn update_inheritance_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy_context): Extension<PolicyContext>,
    Extension(admission): Extension<AuthorizationAdmission>,
    Path(resource_type): Path<String>,
    Json(req): Json<UpdateInheritanceRequest>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let context = inheritance_mutation_context(&headers, &policy_context, admission)?;
    // ResourceRegistry 编排在事务外（进程内校验，先于 source transaction）。
    validate_registered_resource_type(&resource_type)?;
    validate_inheritance_mode(&req.inheritance_mode)?;

    state
        .inheritance_config_repository
        .upsert_with_context(&resource_type, &req.inheritance_mode, &context)
        .await?;

    tracing::info!(
        resource_type = %resource_type,
        mode = %req.inheritance_mode,
        "inheritance config updated"
    );
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

/// POST /inheritance/config — 创建继承配置
///
/// 对齐既有 upsert 语义（idx_pic_resource_type UNIQUE）：要求已验证 ACTIVE
/// GlobalAdmin；mutation 经 proof-bound admission source transaction 落库，
/// UPSERT 与查回在同一事务内原子完成。
async fn create_inheritance_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy_context): Extension<PolicyContext>,
    Extension(admission): Extension<AuthorizationAdmission>,
    Json(req): Json<CreateInheritanceRequest>,
) -> Result<Json<ApiResponse<InheritanceConfig>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let context = inheritance_mutation_context(&headers, &policy_context, admission)?;
    // ResourceRegistry 编排在事务外（进程内校验，先于 source transaction）。
    validate_registered_resource_type(&req.resource_type)?;
    validate_inheritance_mode(&req.inheritance_mode)?;

    let created = state
        .inheritance_config_repository
        .upsert_with_context(&req.resource_type, &req.inheritance_mode, &context)
        .await?
        .into();

    tracing::info!(resource_type = %req.resource_type, "inheritance config created");
    Ok(Json(ApiResponse::success(created)))
}

/// DELETE /inheritance/config/{resource_type} — 删除继承配置
///
/// 要求已验证 ACTIVE GlobalAdmin；mutation 经 proof-bound admission source
/// transaction 落库（目标行锁与 DELETE 原子）。
async fn delete_inheritance_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy_context): Extension<PolicyContext>,
    Extension(admission): Extension<AuthorizationAdmission>,
    Path(resource_type): Path<String>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let context = inheritance_mutation_context(&headers, &policy_context, admission)?;
    // ResourceRegistry 编排在事务外（进程内校验，先于 source transaction）。
    validate_registered_resource_type(&resource_type)?;
    let deleted = state
        .inheritance_config_repository
        .delete_by_resource_type_with_context(&resource_type, &context)
        .await?;
    if !deleted {
        return Err(AppError(AstralError::NotFound(format!(
            "inheritance config for resource_type '{resource_type}' not found"
        ))));
    }

    tracing::info!(resource_type = %resource_type, "inheritance config deleted");
    Ok(Json(ApiResponse::success(EmptyResponse)))
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

    /// 继承配置 mutation 与 departments/user-levels mutation 共用同一装配合同：
    /// Gateway 头必须与验证过的 PolicyContext 完全一致，缺头/不一致/非平台身份/
    /// 缺失 request id 一律拒绝。
    #[test]
    fn inheritance_mutation_context_requires_header_policy_agreement() {
        let policy = platform_policy_context(10, 20, 30, 40);
        let admission_fn = || {
            // admission 只作为不透明能力透传；装配合同测试关注 header/context
            // 一致性与 request id，能力本身由 repository 的锁定行对牌复核。
            build_test_admission()
        };
        let agreed = inheritance_mutation_context(
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
                inheritance_mutation_context(&tampered, &policy, admission_fn()).is_err(),
                "any header disagreeing with the verified PolicyContext must be rejected"
            );
        }
        assert!(
            inheritance_mutation_context(&HeaderMap::new(), &policy, admission_fn()).is_err(),
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
            inheritance_mutation_context(
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
            inheritance_mutation_context(&no_request_id, &policy, admission_fn()).is_err(),
            "a missing request id must fail closed"
        );
    }

    /// 结构守卫（include_str!，不连 DB）：create/update/delete 必须先过
    /// `require_platform_admin` 门禁，提取 `Extension<AuthorizationAdmission>`
    /// 与 `Extension<PolicyContext>`、经 `inheritance_mutation_context` 装配后
    /// 走 `_with_context` 入口，且 `ResourceRegistry` 校验先于事务入口（进程内
    /// 编排在 source transaction 之外）；GET/list 保持只读（不提取 admission、
    /// 不开启 source 事务）。
    #[test]
    fn mutation_handlers_require_admission_and_read_paths_stay_context_free() {
        let source = include_str!("inheritance.rs");
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
            "create_inheritance_config",
            "update_inheritance_config",
            "delete_inheritance_config",
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
                body.contains("inheritance_mutation_context(&headers, &policy_context, admission)"),
                "{name} must assemble the mutation context through the verified path"
            );
            assert!(
                body.contains("_with_context"),
                "{name} must dispatch through the context-bound repository entry"
            );
            // ResourceRegistry 编排必须在事务入口之前（进程内，不进 source tx）。
            let registry_check = body
                .find("validate_registered_resource_type(")
                .unwrap_or_else(|| panic!("{name} must validate the registered resource type"));
            let tx_entry = body
                .find("_with_context(")
                .unwrap_or_else(|| panic!("{name} must dispatch the context-bound entry"));
            assert!(
                registry_check < tx_entry,
                "{name} must keep the ResourceRegistry check outside/.before the source transaction"
            );
        }

        let list_body = handler_body("list_inheritance_configs");
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

    /// 继承模式白名单：NONE / PARENT_ONLY / CUMULATIVE 之外一律拒绝。
    #[test]
    fn inheritance_mode_whitelist_fails_closed() {
        for mode in VALID_MODES {
            assert!(validate_inheritance_mode(mode).is_ok());
        }
        for bad in ["", "none", "Cascading", "PARENT"] {
            assert!(
                matches!(
                    validate_inheritance_mode(bad),
                    Err(AppError(astral_types::AstralError::Validation(_)))
                ),
                "inheritance_mode '{bad}' must be rejected"
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
            operation_id: "op-inherit-api-test".into(),
            event_id: "evt-inherit-api-test".into(),
            key_id: "key-test".into(),
            key_epoch: 1,
            issued_at: 1_700_000_000,
            not_before: 1_700_000_000,
            expires_at: 1_700_000_400,
            request_nonce: "nonce-inherit-api-test".into(),
            request_binding_digest: None,
            scope_certificate_hash: None,
            proof_id: "proof-inherit-api-test".into(),
            signature: "ab".repeat(64),
        };
        AuthorizationAdmission::from_verified_proof(proof).expect("structurally valid proof")
    }
}
