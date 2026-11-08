//! 资源类型管理 API（DomainController 拆分模块 2/7）— HTTP adapter
//!
//! 数据访问在 `repository::resource_type_repository`；
//! ResourceRegistry 合并与 scan 的 in-memory/async_tracker 编排保留在 handler。
//!
//! register/update 是资源/动作词汇表治理 mutation（与 permission_action 共同
//! 构成授权模型的对象/动作词汇表）：handler 必须先过 `require_platform_admin`
//! 的既有 GlobalAdmin 门禁，再提取 permission 中间件注入的
//! `AuthorizationAdmission` 与已验证 `PolicyContext`，且 Gateway 身份头必须与
//! 该 context 完全一致后才能构造 `ResourceTypeMutationContext`（缺失
//! admission 的 Extension 提取直接 fail-closed）。GET/list 为只读路径，不注入
//! admission、不开启 source 事务。persist-before-runtime 边界保留：durable
//! registry 行由 repository 的 proof-bound admission source transaction 落库
//! （actor 卡行对牌、同事务 audit 关联与 proven commit 由 repository 承担），
//! 运行时 `ResourceRegistry` 安装仍在 proven commit 之后执行；安装失败如实
//! 上报 `RESOURCE_REGISTRY_INSTALL_PENDING`，restart reload 是唯一对账路径。
//! unregister 维持 published-revoke 栅栏 fail-closed；scan 维持
//! `NotImplemented`。无 eligibility fanout。

use axum::extract::{Extension, Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::{ApiResponse, PageResponse, PaginationParams};
use astral_common::error::AppError;
use astral_types::{
    AstralError, AuthorizationAdmission, CustomResourceRegistration, PolicyContext,
    ResourceRegistry, RESOURCE_RETIREMENT_REQUIRES_PUBLISHED_REVOKE,
};

use crate::api::async_tracker::AsyncTask;
use crate::api::require_platform_admin;
use crate::repository::resource_type_repository::{
    DomainResourceTypeRecord, ResourceTypeMutationContext,
};
use crate::AppState;

/// Stable fail-closed code surfaced when a durable resource-registry commit has
/// landed but the post-commit runtime installation failed. The durable row is
/// the source of truth; restart/reload reconciliation (`load_registry_rows` at
/// startup) is the only recovery path, and no retry may bypass it.
const RESOURCE_REGISTRY_INSTALL_PENDING: &str = "RESOURCE_REGISTRY_INSTALL_PENDING";

// ===== Row / DTO =====

/// domain_resource_type 响应 DTO（对齐 Java DomainResourceType + 前端 Module 类型）
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainResourceTypeRow {
    pub id: i64, // resource_type_id as id
    pub domain_id: Option<i64>,
    pub code: Option<String>,        // type_code as code
    pub name: Option<String>,        // type_name as name
    pub description: Option<String>, // type_description as description
    pub sensitivity_level: Option<i32>,
    pub status: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl From<DomainResourceTypeRecord> for DomainResourceTypeRow {
    fn from(r: DomainResourceTypeRecord) -> Self {
        Self {
            id: r.id,
            domain_id: r.domain_id,
            code: Some(r.code),
            name: Some(r.name),
            description: r.description,
            sensitivity_level: None,
            status: r.status,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

/// ResourceRegistry 暴露给前端的资源类型视图（含动作集合）
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceTypeView {
    pub resource_type: String,
    pub actions: Vec<String>,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterResourceTypeRequest {
    pub resource_type: String,
    pub actions: Vec<String>,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateResourceTypeRequest {
    pub actions: Vec<String>,
    pub description: Option<String>,
}

// ===== Routes =====

pub fn resource_type_routes() -> Router<AppState> {
    Router::new()
        .route("/resource-types", get(list_domain_resource_types))
        .route("/resource-types", post(register_resource_type))
        .route("/resource-types/{resource_type}", put(update_resource_type))
        .route(
            "/resource-types/{resource_type}",
            delete(unregister_resource_type),
        )
        .route("/resource-types/scan", post(scan_resource_types))
        .route(
            "/resource-types/scan/async",
            post(scan_resource_types_async),
        )
}

// ===== Handlers =====

/// Build a resource-type mutation context from the permission middleware's
/// verified extension. The Gateway headers are only accepted when they exactly
/// agree with that extension; the proof-bound admission is required for the
/// source transaction.
fn resource_type_mutation_context(
    headers: &HeaderMap,
    policy_context: &PolicyContext,
    admission: AuthorizationAdmission,
) -> Result<ResourceTypeMutationContext, AppError> {
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
            "resource type mutation Gateway headers do not match the verified PolicyContext".into(),
        )));
    }
    let request_id = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok());
    ResourceTypeMutationContext::from_policy_context(policy_context, request_id)
        .map(|context| context.with_admission(admission))
        .map_err(AppError::from)
}

/// GET /main/api/v1/resource-types — 列表（domain_resource_type 表）
async fn list_domain_resource_types(
    State(state): State<AppState>,
    Query(page): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<DomainResourceTypeRow>>>, AppError> {
    let total = state
        .resource_type_repository
        .count_domain_resource_types()
        .await?;
    let rows = state
        .resource_type_repository
        .list_domain_resource_types(page.effective_size(), page.offset())
        .await?
        .into_iter()
        .map(DomainResourceTypeRow::from)
        .collect();
    Ok(Json(ApiResponse::success(PageResponse::new(
        rows,
        total,
        page.page,
        page.effective_size(),
    ))))
}

/// POST /main/api/v1/resource-types — 注册新资源类型（持久化 resource_type_registry）
///
/// 要求已验证 ACTIVE GlobalAdmin；durable registry 行经 proof-bound admission
/// source transaction 落库（actor 卡行对牌 + 同事务 audit 关联 + proven commit），
/// 运行时 `ResourceRegistry` 安装仍在 proven commit 之后执行
/// （persist-before-runtime）。
async fn register_resource_type(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy_context): Extension<PolicyContext>,
    Extension(admission): Extension<AuthorizationAdmission>,
    Json(req): Json<RegisterResourceTypeRequest>,
) -> Result<Json<ApiResponse<ResourceTypeView>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let context = resource_type_mutation_context(&headers, &policy_context, admission)?;
    if req.resource_type.is_empty() {
        return Err(AppError(AstralError::Validation(
            "resource_type must not be empty".into(),
        )));
    }
    if req.actions.is_empty() {
        return Err(AppError(AstralError::Validation(
            "actions must not be empty".into(),
        )));
    }

    let reg = ResourceRegistry::global();
    reg.validate_custom_resources([CustomResourceRegistration {
        resource_type: req.resource_type.clone(),
        actions: req.actions.clone(),
    }])
    .map_err(|error| AppError(AstralError::Validation(error.to_string())))?;
    // 已存在则拒绝覆盖（包括任何 built-in resource）。
    if reg.list_actions(&req.resource_type).is_some() {
        return Err(AppError(AstralError::Validation(format!(
            "resource_type '{}' already registered",
            req.resource_type
        ))));
    }

    // Persist first; only publish the validated action set after durable success.
    let actions_json = serde_json::to_string(&req.actions)
        .map_err(|e| AppError(AstralError::Internal(format!("serialize actions: {e}"))))?;
    state
        .resource_type_repository
        .insert_registry_with_context(
            &req.resource_type,
            &actions_json,
            req.description.as_deref(),
            &context,
        )
        .await?;
    reg.register_custom_resources([CustomResourceRegistration {
        resource_type: req.resource_type.clone(),
        actions: req.actions.clone(),
    }])
    .map_err(|error| {
        tracing::error!(resource_type = %req.resource_type, %error, "durable resource type commit succeeded but post-commit runtime registration failed; restart reconciliation required");
        AppError(AstralError::Pending(format!(
            "{RESOURCE_REGISTRY_INSTALL_PENDING}: durable commit succeeded for resource type '{}'; post-commit runtime registration failed and restart reload must reconcile it",
            req.resource_type
        )))
    })?;

    tracing::info!(resource_type = %req.resource_type, "resource type registered");

    let mut sorted_actions = req.actions.clone();
    sorted_actions.sort();
    Ok(Json(ApiResponse::success(ResourceTypeView {
        resource_type: req.resource_type,
        actions: sorted_actions,
        description: req.description,
    })))
}

/// PUT /main/api/v1/resource-types/{resource_type} — 更新动作集
///
/// 要求已验证 ACTIVE GlobalAdmin；durable registry 行经 proof-bound admission
/// source transaction 落库（actor 卡行对牌 + 同事务 audit 关联 + proven commit），
/// 运行时动作集替换仍在 proven commit 之后执行（persist-before-runtime）。
async fn update_resource_type(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy_context): Extension<PolicyContext>,
    Extension(admission): Extension<AuthorizationAdmission>,
    Path(resource_type): Path<String>,
    Json(req): Json<UpdateResourceTypeRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let context = resource_type_mutation_context(&headers, &policy_context, admission)?;
    let registry = ResourceRegistry::global();
    let registrations = CustomResourceRegistration {
        resource_type: resource_type.clone(),
        actions: req.actions.clone(),
    };
    registry
        .validate_custom_resource_update(registrations)
        .map_err(|error| AppError(AstralError::Validation(error.to_string())))?;
    let actions_json = serde_json::to_string(&req.actions)
        .map_err(|e| AppError(AstralError::Internal(format!("serialize actions: {e}"))))?;

    let updated = state
        .resource_type_repository
        .update_registry_with_context(
            &resource_type,
            &actions_json,
            req.description.as_deref(),
            &context,
        )
        .await?;
    if !updated {
        return Err(AppError(AstralError::NotFound(format!(
            "resource_type '{resource_type}'"
        ))));
    }
    registry
        .replace_custom_resource_actions(astral_types::CustomResourceRegistration {
            resource_type: resource_type.clone(),
            actions: req.actions.clone(),
        })
        .map_err(|error| {
            tracing::error!(resource_type = %resource_type, %error, "durable resource type commit succeeded but post-commit runtime replacement failed; restart reconciliation required");
            AppError(AstralError::Pending(format!(
                "{RESOURCE_REGISTRY_INSTALL_PENDING}: durable commit succeeded for resource type '{resource_type}'; post-commit runtime action replacement failed and restart reload must reconcile it",
            )))
        })?;

    tracing::info!(resource_type = %resource_type, "resource type updated");
    Ok(Json(ApiResponse::success(serde_json::json!({
        "resource_type": resource_type,
        "actions": req.actions,
    }))))
}

/// DELETE /main/api/v1/resource-types/{resource_type} — 注销
async fn unregister_resource_type(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(resource_type): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    Err(resource_retirement_requires_published_revoke(
        &resource_type,
    ))
}

/// Retiring a resource is unavailable until the canonical revoke, generation,
/// and published-evidence barriers are proven. Keeping this guard before any
/// repository or runtime-registry operation makes the endpoint fail closed.
fn resource_retirement_requires_published_revoke(resource_type: &str) -> AppError {
    AppError(AstralError::Validation(format!(
        "{RESOURCE_RETIREMENT_REQUIRES_PUBLISHED_REVOKE}: resource type '{resource_type}' cannot be unregistered until canonical revoke, generation, and published evidence barriers are closed"
    )))
}

/// GET /main/api/v1/resource-types/scan — 同步扫描所有 @RequirePermission 资源
///
/// Stub：返回 ResourceRegistry 当前内容（Rust 端无运行时注解扫描机制）。
async fn scan_resource_types(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ApiResponse<Vec<ResourceTypeView>>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    Err(AppError(AstralError::NotImplemented(
        "resource type scan is not implemented: Rust has no runtime annotation scanner".into(),
    )))
}

/// POST /main/api/v1/resource-types/scan/async — 异步扫描（返回 task_id）
async fn scan_resource_types_async(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ApiResponse<AsyncTask>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    Err(AppError(AstralError::NotImplemented(
        "resource type async scan is not implemented: Rust has no runtime annotation scanner"
            .into(),
    )))
}

#[cfg(test)]
mod tests {
    use super::{
        resource_retirement_requires_published_revoke, resource_type_mutation_context,
        RESOURCE_REGISTRY_INSTALL_PENDING, RESOURCE_RETIREMENT_REQUIRES_PUBLISHED_REVOKE,
    };
    use astral_common::error::AppError;
    use astral_types::{
        AstralError, AuthorizationAdmission, CustomResourceRegistration, PolicyContext,
        ResourceRegistry,
    };
    use axum::http::{HeaderMap, HeaderValue};

    /// Production region only: contract guards must not match test fixtures.
    fn production_source() -> &'static str {
        include_str!("resource_types.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source must precede contract tests")
    }

    /// Slice one handler body (definition marker through the next item's doc).
    fn handler_source<'a>(production: &'a str, start: &str, end: &str) -> &'a str {
        let start_index = production
            .find(start)
            .unwrap_or_else(|| panic!("handler start marker not found: {start}"));
        let rest = &production[start_index..];
        let end_index = rest
            .find(end)
            .unwrap_or_else(|| panic!("handler end marker not found: {end}"));
        &rest[..end_index]
    }

    fn register_handler() -> &'static str {
        handler_source(
            production_source(),
            "async fn register_resource_type",
            "/// PUT /main/api/v1/resource-types",
        )
    }

    fn update_handler() -> &'static str {
        handler_source(
            production_source(),
            "async fn update_resource_type",
            "/// DELETE /main/api/v1/resource-types",
        )
    }

    #[test]
    fn unregister_guard_returns_stable_fail_closed_error_without_runtime_mutation() {
        let resource_type = format!("contract_retirement_{}", std::process::id());
        let registry = ResourceRegistry::global();
        registry
            .register_custom_resources([CustomResourceRegistration {
                resource_type: resource_type.clone(),
                actions: vec!["read".into()],
            }])
            .expect("contract resource must be registered for the test");
        let before = registry.list_actions(&resource_type);

        let error = resource_retirement_requires_published_revoke(&resource_type);
        assert!(matches!(
            error,
            AppError(AstralError::Validation(message))
                if message.starts_with(RESOURCE_RETIREMENT_REQUIRES_PUBLISHED_REVOKE)
        ));
        assert_eq!(
            registry.list_actions(&resource_type),
            before,
            "fail-closed retirement must not mutate the runtime registry"
        );
    }

    #[test]
    fn unregister_handler_has_no_registry_side_effect_before_barriers_close() {
        let production = include_str!("resource_types.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source must precede contract tests");
        let handler = production
            .split("async fn unregister_resource_type")
            .nth(1)
            .expect("resource unregister handler must exist")
            .split("/// GET /main/api/v1/resource-types/scan")
            .next()
            .expect("resource unregister handler must end before scan handler");

        assert!(handler.contains("resource_retirement_requires_published_revoke"));
        assert!(!handler.contains("delete_registry"));
        assert!(!handler.contains("unregister_custom_resource"));
    }

    #[test]
    fn mutations_persist_before_any_runtime_registry_install() {
        for (handler, persist_call, install_call) in [
            (
                register_handler(),
                "insert_registry",
                "register_custom_resources",
            ),
            (
                update_handler(),
                "update_registry",
                "replace_custom_resource_actions",
            ),
        ] {
            let persist_at = handler
                .find(persist_call)
                .unwrap_or_else(|| panic!("durable persist call missing: {persist_call}"));
            let install_at = handler
                .find(install_call)
                .unwrap_or_else(|| panic!("post-commit install call missing: {install_call}"));
            assert!(
                persist_at < install_at,
                "{persist_call} must commit before {install_call} mutates the runtime registry"
            );
        }
    }

    #[test]
    fn post_commit_install_failure_surfaces_pending_restart_reconciliation() {
        assert!(
            !production_source()
                .contains("resource registry changed durably but runtime registration failed"),
            "a generic internal error must not mask the durable-commit-acknowledged state"
        );
        for (handler, persist_call) in [
            (register_handler(), "insert_registry"),
            (update_handler(), "update_registry"),
        ] {
            assert!(handler.contains("AstralError::Pending"));
            assert!(handler.contains(RESOURCE_REGISTRY_INSTALL_PENDING));
            let persist_at = handler
                .find(persist_call)
                .unwrap_or_else(|| panic!("durable persist call missing: {persist_call}"));
            let pending_at = handler
                .find("AstralError::Pending")
                .expect("post-commit install failure must surface Pending, not Internal");
            assert!(
                persist_at < pending_at,
                "Pending reconciliation semantics apply only after the durable commit"
            );
        }
    }

    #[test]
    fn mutation_handlers_keep_transactions_and_cache_out_of_the_request_path() {
        for handler in [
            register_handler(),
            update_handler(),
            handler_source(
                production_source(),
                "async fn unregister_resource_type",
                "/// GET /main/api/v1/resource-types/scan",
            ),
        ] {
            assert!(
                !handler.contains("begin("),
                "resource-type mutation handlers must not open a source transaction"
            );
            assert!(
                !handler.contains("acquire("),
                "resource-type mutation handlers must not acquire pool sessions directly"
            );
            assert!(
                !handler.contains("cache"),
                "resource-type mutation handlers must not perform cache work"
            );
        }
    }

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
            operation_id: "op-resource-type-api-test".into(),
            event_id: "evt-resource-type-api-test".into(),
            key_id: "key-test".into(),
            key_epoch: 1,
            issued_at: 1_700_000_000,
            not_before: 1_700_000_000,
            expires_at: 1_700_000_400,
            request_nonce: "nonce-resource-type-api-test".into(),
            request_binding_digest: None,
            scope_certificate_hash: None,
            proof_id: "proof-resource-type-api-test".into(),
            signature: "ab".repeat(64),
        };
        AuthorizationAdmission::from_verified_proof(proof).expect("structurally valid proof")
    }

    /// 资源类型 mutation 与 domains/permission-actions mutation 共用同一装配合同：
    /// Gateway 头必须与验证过的 PolicyContext 完全一致，缺头/不一致/非平台身份/
    /// 缺失 request id 一律拒绝。
    #[test]
    fn resource_type_mutation_context_requires_header_policy_agreement() {
        let policy = platform_policy_context(10, 20, 30, 40);
        let admission_fn = || {
            // admission 只作为不透明能力透传；装配合同测试关注 header/context
            // 一致性与 request id，能力本身由 repository 的锁定行对牌复核。
            build_test_admission()
        };
        let agreed = resource_type_mutation_context(
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
                resource_type_mutation_context(&tampered, &policy, admission_fn()).is_err(),
                "any header disagreeing with the verified PolicyContext must be rejected"
            );
        }
        assert!(
            resource_type_mutation_context(&HeaderMap::new(), &policy, admission_fn()).is_err(),
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
            resource_type_mutation_context(
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
            resource_type_mutation_context(&no_request_id, &policy, admission_fn()).is_err(),
            "a missing request id must fail closed"
        );
    }

    /// 结构守卫（include_str!，不连 DB）：register/update 必须提取
    /// `Extension<AuthorizationAdmission>` 与 `Extension<PolicyContext>`、保留
    /// `require_platform_admin` 门禁、并经 `resource_type_mutation_context`
    /// 装配后走 `_with_context` 入口（durable source transaction 归 repository，
    /// post-commit 运行时安装与 PENDING 语义保留在 handler）；GET/list、scan 与
    /// unregister 保持无 admission 提取；HTTP adapter 绝不直接提交 source 事务。
    #[test]
    fn mutation_handlers_require_admission_and_read_paths_stay_context_free() {
        for (body, context_entry) in [
            (register_handler(), "insert_registry_with_context("),
            (update_handler(), "update_registry_with_context("),
        ] {
            assert!(
                body.contains("Extension(admission): Extension<AuthorizationAdmission>"),
                "resource-type mutation must require the proof-bound admission extension"
            );
            assert!(
                body.contains("Extension(policy_context): Extension<PolicyContext>"),
                "resource-type mutation must require the verified PolicyContext extension"
            );
            assert!(
                body.contains("require_platform_admin(&state, &headers).await?"),
                "resource-type mutation must keep the platform admin gate"
            );
            assert!(
                body.contains("resource_type_mutation_context(&headers, &policy_context, admission)"),
                "resource-type mutation must assemble the mutation context through the verified path"
            );
            assert!(
                body.contains(context_entry),
                "resource-type mutation must dispatch through the context-bound repository entry"
            );
            assert!(
                body.contains("register_custom_resources")
                    || body.contains("replace_custom_resource_actions"),
                "resource-type mutation must keep the post-commit runtime install in the handler"
            );
            assert!(
                body.contains("AstralError::Pending"),
                "resource-type mutation must keep the PENDING install-failure semantics"
            );
        }

        // GET/list 保持只读路径：不提取 admission、不引用 source 事务。
        let list_body = handler_source(
            production_source(),
            "async fn list_domain_resource_types",
            "/// POST /main/api/v1/resource-types",
        );
        assert!(
            !list_body.contains("AuthorizationAdmission") && !list_body.contains("PolicyContext"),
            "GET/list must stay a read-only path without admission extraction"
        );

        // scan 维持 NotImplemented 编排、unregister 维持 retirement fail-closed
        // 栅栏：两者都不提取 admission。
        for (start, end) in [
            (
                "async fn unregister_resource_type",
                "/// GET /main/api/v1/resource-types/scan",
            ),
            (
                "async fn scan_resource_types",
                "async fn scan_resource_types_async",
            ),
        ] {
            let body = handler_source(production_source(), start, end);
            assert!(
                !body.contains("Extension(admission)"),
                "{start} must not extract the admission extension"
            );
        }

        assert!(
            !production_source().contains("tx.commit()"),
            "the HTTP adapter must never commit a source transaction directly"
        );
    }
}
