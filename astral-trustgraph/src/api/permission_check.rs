//! 路由级权限检查中间件
//!
//! 对齐 Java `PermissionAspect.enforce()` + `@RequirePermission`。
//! 拦截所有 `/main/api/v1/*` 请求，根据 HTTP 方法 + 路径前缀映射到
//! (resource_type, action)，调用 `PolicyEngine.evaluate()` 做权限判定。
//!
//! 方法→动作映射（对齐 Java PermissionAspect 的 action 推断）：
//!   GET / HEAD → "read"
//!   POST → "create"
//!   PUT / PATCH → "update"
//!   DELETE → "delete"

use std::fmt;
use std::time::Instant;

use axum::body::Bytes;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::Value;

use astral_authorization_root::memory_v1_db_rows::BinaryId;
use astral_authorization_root::memory_v1_request::RequestRootExtension;
use astral_authorization_root::memory_v1_root::GovernanceTargetFacts;
use astral_authorization_root::memory_v1_session::RequestSessionExtension;
use astral_common::audit::org_provenance_audit_detail;
use astral_common::error::AppError;
use astral_common::middleware::gateway_signature::VerifiedMemoryV1SessionTransport;
use astral_common::middleware::permission_check_shared::{
    path_matches_prefix, physical_policy_context, request_target_id, resolve_permission_action,
    AuthorizationAuditUnavailableRefusal, AuthorizationPendingRefusal, BoxedResponse,
};
use astral_db::resolve_resource_ownership;
use astral_types::memory_v1::MemoryId;
use astral_types::AstralError;
use policy_engine::memory_v1_batch::{MemoryV1BatchEvaluation, MemoryV1BatchRequest};
use policy_engine::memory_v1_compound::{
    MemoryV1CompoundAction, MemoryV1CompoundEvaluation, MemoryV1CompoundRequest,
    MemoryV1CompoundTargetKind,
};
use policy_engine::memory_v1_formal::{
    MemoryV1Admission, MemoryV1Decision, MemoryV1DenySource, MemoryV1Evaluation,
    MemoryV1PendingSource, MemoryV1Request, MemoryV1RuleSetChangeIntent,
};

use crate::observability::{
    classify_policy_decision, record_authorization_decision, record_authorization_request,
    record_sod_check, AuthorizationAdmissionOutcome, AuthorizationDecisionOutcome, SodCheckOutcome,
};
use crate::service::memory_v1_governance_commit::MemoryV1DenyProofPort;
use crate::AppState;

/// 路径前缀 → 资源类型映射表
///
/// 对应 Java Controller 上的 `@RequirePermission(resource = "xxx", action = "yyy")`
/// 注意：此中间件在 nest("/main/api/v1", ...) 内部运行，路径前缀已被剥离
pub const TRUSTGRAPH_PATH_RESOURCE_MAP: &[(&str, &str)] = &[
    ("/org-authority-edges", "org_authority_edge"),
    ("/org-unit-cards", "org_unit_card"),
    ("/org-memberships", "org_membership"),
    ("/permission-rules", "permission_rule"),
    ("/rule-sets", "permission_rule"),
    ("/audit", "audit"),
    ("/audit-quarantine", "audit_quarantine"),
    ("/simulation", "permission_rule"),
    ("/permission-requests", "permission_request"),
    ("/delegations", "permission_rule"),
    ("/admin-groups", "admin_group"),
    ("/templates", "identity_level_template"),
    ("/sod-policies", "permission_rule"),
    ("/hit-stats", "audit"),
    ("/stats", "monitor"),
    ("/authorization-observations", "monitor"),
    ("/tenants", "platform_tenant"),
    ("/platform-packages", "platform_package"),
    ("/departments", "platform_dept"),
    ("/users", "user"),
    // 内部测试控制面（api::test_control）：复用已注册资源 monitor 的 read 动作，
    // 走正常 PolicyEngine 链路；路由本身默认关闭，启用后另有常量时间 token 校验。
    ("/internal/test-control", "monitor"),
    ("/inheritance", "permission_inheritance"),
    ("/cross-org-grants", "cross_org_grant"),
    ("/operations", "domain"),
    ("/domains", "domain"),
    ("/resource-types", "domain_resource_type"),
    ("/actions", "permission_action"),
    ("/user-levels", "domain"),
    ("/user-gradings", "domain"),
    ("/level-templates", "permission_rule"),
    ("/user-cards", "domain"),
    ("/card-templates", "domain"),
    ("/global-admins", "authorization"),
];

/// 放行路径：TrustGraph 业务端点统一经过 PolicyEngine；健康检查在主路由外单独暴露。
const SKIP_PATHS: &[&str] = &[];

/// 资源映射只按已冻结前缀解析；审批 mutation 的目标另外由精确路由绑定。
fn resource_for_path(path: &str) -> Option<&'static str> {
    TRUSTGRAPH_PATH_RESOURCE_MAP
        .iter()
        .find(|(prefix, _)| path_matches_prefix(path, prefix))
        .map(|(_, resource)| *resource)
}

fn resolve_trustgraph_permission_action(
    resource: &str,
    path: &str,
    method: &str,
) -> Option<&'static str> {
    if resource == "domain" && method == "GET" && path_matches_prefix(path, "/operations") {
        return Some("update");
    }
    if resource == "org_authority_edge"
        && method == "POST"
        && (path.ends_with("/move") || path.ends_with("/detach"))
    {
        return Some("update");
    }
    if resource == "org_unit_card" && method == "POST" && path.contains("/revoke") {
        return Some("update");
    }
    if resource == "org_membership" && method == "POST" && path.ends_with("/revoke") {
        return Some("update");
    }
    if resource == "audit_quarantine" && method == "POST" && path.ends_with("/replay") {
        return Some("replay");
    }
    resolve_permission_action(resource, path, method)
}

fn canonical_positive_id(value: &str) -> Option<i64> {
    value
        .parse::<i64>()
        .ok()
        .filter(|id| *id > 0 && id.to_string() == value)
}

fn permission_request_target<'a>(path: &'a str, method: &str) -> Option<(i64, &'a str)> {
    if method != "POST" {
        return None;
    }
    let (id, action) = path
        .strip_prefix("/permission-requests/")?
        .split_once('/')?;
    if !matches!(action, "cancel" | "reject" | "approve") {
        return None;
    }
    Some((canonical_positive_id(id)?, action))
}

fn trustgraph_request_target_id(
    req: &Request,
    resource: &str,
    path: &str,
    method: &str,
) -> Result<Option<i64>, StatusCode> {
    let path_target = (resource == "permission_request")
        .then(|| permission_request_target(path, method))
        .flatten();
    let Some((path_id, _)) = path_target else {
        return Ok(request_target_id(req));
    };
    if let Some(query) = req.uri().query() {
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            if matches!(
                key,
                "target_id"
                    | "targetId"
                    | "resource_id"
                    | "resourceId"
                    | "id"
                    | "card_id"
                    | "cardId"
            ) && canonical_positive_id(value) != Some(path_id)
            {
                return Err(StatusCode::BAD_REQUEST);
            }
        }
    }
    Ok(Some(path_id))
}

fn request_mutation_kind(
    resource: &str,
    path: &str,
    method: &str,
) -> Option<astral_types::AuthorityMutationKind> {
    if resource == "permission_request" && method == "POST" {
        let exact_route = path == "/permission-requests"
            || permission_request_target(path, method)
                .is_some_and(|(_, action)| matches!(action, "cancel" | "reject"));
        return exact_route.then_some(astral_types::AuthorityMutationKind::ProtectedBusiness);
    }
    if resource == "platform_package" {
        let exact_route = (method == "POST" && path == "/platform-packages")
            || (matches!(method, "PUT" | "DELETE")
                && path.strip_prefix("/platform-packages/").is_some_and(|id| {
                    id.parse::<i64>()
                        .is_ok_and(|value| value > 0 && value.to_string() == id)
                }));
        return exact_route.then_some(astral_types::AuthorityMutationKind::ProtectedBusiness);
    }
    if method != "POST" {
        return None;
    }
    let object_path = match resource {
        "domain" => path
            .strip_prefix("/user-cards/")
            .and_then(|tail| tail.strip_suffix("/bind/async")),
        "platform_tenant" => path
            .strip_prefix("/tenants/")
            .and_then(|tail| tail.strip_suffix("/purchases")),
        _ => None,
    };
    object_path
        .filter(|id| id.parse::<i64>().is_ok_and(|value| value > 0))
        .map(|_| astral_types::AuthorityMutationKind::ProtectedBusiness)
}

fn operation_poll_scope_matches(
    ctx: &astral_types::PolicyContext,
    scope: &crate::api::async_tracker::OperationScope,
) -> bool {
    scope.task_type == crate::api::async_tracker::BATCH_BIND_TASK_TYPE
        && scope.requester_user_id > 0
        && scope.requester_card_id > 0
        && scope.requester_tenant_id > 0
        && scope.requester_domain_id > 0
        && ctx.user_id == Some(scope.requester_user_id)
        && ctx.card_id == Some(scope.requester_card_id)
        && ctx.tenant_id == Some(scope.requester_tenant_id)
        && ctx.domain_id == Some(scope.requester_domain_id)
        && scope.authorization_target_card_id > 0
        && scope.authorization_target_tenant_id > 0
        && scope.authorization_target_domain_id > 0
        && scope.items.iter().any(|item| {
            item.card_id == scope.authorization_target_card_id
                && item.tenant_id == scope.authorization_target_tenant_id
                && item.domain_id == scope.authorization_target_domain_id
        })
}

async fn resolve_operation_poll_ownership(
    pool: &sqlx::MySqlPool,
    path: &str,
    ctx: &astral_types::PolicyContext,
) -> astral_db::ResourceOwnershipResolution {
    use astral_db::ResourceOwnershipResolution;
    let unresolved = ResourceOwnershipResolution::Unresolved {
        code: "resource_ownership.operation_scope_unproven",
    };
    let Some(task_id) = path.strip_prefix("/operations/") else {
        return unresolved;
    };
    if task_id.is_empty()
        || task_id.len() > 64
        || !task_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return unresolved;
    }
    let scope = match tokio::time::timeout(
        std::time::Duration::from_secs(3),
        crate::api::async_tracker::load_operation_scope(pool, task_id),
    )
    .await
    {
        Ok(Ok(Some(scope))) => scope,
        Ok(Ok(None)) => return unresolved,
        Ok(Err(_)) | Err(_) => {
            return ResourceOwnershipResolution::Unavailable {
                code: "resource_ownership.operation_lookup_unavailable",
            };
        }
    };
    if !operation_poll_scope_matches(ctx, &scope) {
        return unresolved;
    }
    let anchor = scope
        .items
        .iter()
        .find(|item| item.card_id == scope.authorization_target_card_id);
    let anchor_path = format!("/user-cards/{}", scope.authorization_target_card_id);
    let resolution = resolve_resource_ownership(
        pool,
        "domain",
        &anchor_path,
        "POST",
        None,
        ctx.card_id,
        ctx.user_id,
    )
    .await;
    match (&resolution, anchor) {
        (
            ResourceOwnershipResolution::TenantScoped {
                tenant_id,
                domain_id,
                ..
            },
            Some(item),
        ) if *tenant_id == item.tenant_id && *domain_id == Some(item.domain_id) => resolution,
        _ => unresolved,
    }
}

fn audit_request_id(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get("x-request-id")?.to_str().ok()?;
    match crate::repository::audit_log_repository::validated_request_operation_id(Some(raw)) {
        Ok(request_id) => request_id,
        Err(_) => {
            tracing::warn!("permission audit request id rejected by canonical safety gate");
            None
        }
    }
}

async fn abort_source_reservation_and_record(
    provider: &astral_db::SqlxAuthorizationFenceProvider,
    abort: &astral_db::SourceReservationAbort,
    phase: &'static str,
) {
    match provider.abort_source_reservation(abort).await {
        Ok(report) => {
            let proven = matches!(
                report.outcome,
                astral_db::SourceAbortOutcome::Aborted
                    | astral_db::SourceAbortOutcome::AlreadyAborted
            );
            if proven {
                tracing::info!(
                    phase,
                    operation_id = %report.operation_id,
                    reservation_id = %report.reservation_id,
                    proof_id = %abort.proof_id,
                    request_digest = %abort.request_digest,
                    reason = %abort.reason,
                    outcome = ?report.outcome,
                    observed_disposition = ?report.observed_disposition,
                    "durable source reservation abort proven"
                );
            } else {
                tracing::warn!(
                    phase,
                    operation_id = %report.operation_id,
                    reservation_id = %report.reservation_id,
                    proof_id = %abort.proof_id,
                    request_digest = %abort.request_digest,
                    reason = %abort.reason,
                    outcome = ?report.outcome,
                    observed_disposition = ?report.observed_disposition,
                    "source reservation abort not proven; stable identity recovery required"
                );
            }
        }
        Err(error) => {
            tracing::warn!(
                phase,
                operation_id = %abort.operation_id,
                reservation_id = %abort.reservation_id,
                proof_id = %abort.proof_id,
                request_digest = %abort.request_digest,
                reason = %abort.reason,
                outcome = "UNKNOWN",
                error = %error,
                "source reservation abort outcome unknown; stable identity recovery required"
            );
        }
    }
}

/// 用法（在 route group 的最外层应用）:
/// ```
/// use axum::{routing::get, Router};
/// use astral_trustgraph::{api::permission_check::permission_check_middleware, AppState};
///
/// fn build_router(state: AppState) -> Router {
///     Router::new()
///         .route("/permission-rules", get(|| async { "ok" }))
///         .layer(axum::middleware::from_fn_with_state(
///             state.clone(),
///             permission_check_middleware,
///         ))
///         .with_state(state)
/// }
/// ```
pub async fn permission_check_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, BoxedResponse> {
    let request_id = audit_request_id(req.headers());
    #[cfg(feature = "e1-observability")]
    {
        policy_engine::e1_observation::scope_request(
            request_id.clone(),
            permission_check_middleware_scoped(state, req, next, request_id),
        )
        .await
    }
    #[cfg(not(feature = "e1-observability"))]
    {
        permission_check_middleware_scoped(state, req, next, request_id).await
    }
}

/// memory—v1 §4.9: TrustGraph route metadata declarations — the single
/// registration point for adapted routes.
///
/// The composition root aggregates these declarations into the root registry at
/// startup, so a route cannot be adapted without also registering its
/// (resource, action) pair. Every other handler still scopes its data or writes
/// by legacy identity context, which a memory—v1 request never carries. T2
/// governance handlers are the only restricted mutation surface.
pub struct MemoryV1RouteDeclaration {
    pub method: &'static str,
    /// Path relative to `/main/api/v1`.
    pub path: &'static str,
    pub resource: &'static str,
    pub action: &'static str,
}

/// Additional same-request actions required by each adapted compound route.
/// The primary declaration remains available through its existing public type.
pub struct MemoryV1RouteRegistration {
    pub method: &'static str,
    pub path: &'static str,
    pub resource: &'static str,
    pub action: &'static str,
    pub additional_actions: &'static [&'static str],
}

pub const MEMORY_V1_ROUTE_DECLARATIONS: &[MemoryV1RouteDeclaration] = &[MemoryV1RouteDeclaration {
    method: "GET",
    path: "/permission-rules/registry",
    resource: "permission_rule",
    action: "read",
}];

pub const MEMORY_V1_ROUTE_REGISTRATIONS: &[MemoryV1RouteRegistration] = &[
    MemoryV1RouteRegistration {
        method: "GET",
        path: "/permission-rules/registry",
        resource: "permission_rule",
        action: "read",
        additional_actions: &[],
    },
    MemoryV1RouteRegistration {
        method: "POST",
        path: "/governance/bindings",
        resource: "binding",
        action: "create",
        additional_actions: &["confirm", "create-overlay-only"],
    },
    MemoryV1RouteRegistration {
        method: "POST",
        path: "/governance/bindings/confirm",
        resource: "binding",
        action: "confirm",
        additional_actions: &[],
    },
    MemoryV1RouteRegistration {
        method: "POST",
        path: "/governance/bindings/confirm/batch",
        resource: "binding",
        action: "confirm",
        additional_actions: &[],
    },
    MemoryV1RouteRegistration {
        method: "DELETE",
        path: "/governance/bindings",
        resource: "binding",
        action: "remove",
        additional_actions: &[],
    },
    MemoryV1RouteRegistration {
        method: "POST",
        path: "/governance/bindings/revoke-confirmation",
        resource: "binding",
        action: "revoke-confirmation",
        additional_actions: &[],
    },
    MemoryV1RouteRegistration {
        method: "POST",
        path: "/governance/rule-sets",
        resource: "rule_set",
        action: "create",
        additional_actions: &["confirm-change"],
    },
    MemoryV1RouteRegistration {
        method: "POST",
        path: "/governance/rule-sets/publish",
        resource: "rule_set",
        action: "version-publish",
        additional_actions: &["confirm-change"],
    },
    MemoryV1RouteRegistration {
        method: "POST",
        path: "/governance/rule-sets/retire",
        resource: "rule_set",
        action: "retire",
        additional_actions: &[],
    },
    MemoryV1RouteRegistration {
        method: "POST",
        path: "/governance/user-cards",
        resource: "user_card",
        action: "create",
        additional_actions: &[],
    },
    MemoryV1RouteRegistration {
        method: "POST",
        path: "/governance/user-cards/enable",
        resource: "user_card",
        action: "enable",
        additional_actions: &[],
    },
    MemoryV1RouteRegistration {
        method: "POST",
        path: "/governance/user-cards/disable",
        resource: "user_card",
        action: "disable",
        additional_actions: &[],
    },
];

// memory—v1: The same exact declaration set drives route lookup and startup
// registry aggregation. Keeping one slice prevents an adapted route from
// evaluating against a resource/action pair that was never registered.
pub fn memory_v1_route_declarations() -> &'static [MemoryV1RouteRegistration] {
    MEMORY_V1_ROUTE_REGISTRATIONS
}

// memory—v1: Exact method/path resolution; HEAD follows its GET route.
pub(super) fn memory_v1_route_declaration(
    method: &axum::http::Method,
    path: &str,
) -> Option<&'static MemoryV1RouteRegistration> {
    let method = if method == axum::http::Method::HEAD {
        "GET"
    } else {
        method.as_str()
    };
    MEMORY_V1_ROUTE_REGISTRATIONS
        .iter()
        .find(|declaration| declaration.method == method && declaration.path == path)
}

/// memory—v1: The exact bounded request bytes and operation binding shared by
/// the authorization middleware and the governance handler. The handler parses
/// these bytes instead of consuming a second, independently read body.
#[derive(Clone)]
pub struct MemoryV1BoundRequest {
    pub operation_id: String,
    pub fingerprint: String,
    pub body: Bytes,
}

impl fmt::Debug for MemoryV1BoundRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryV1BoundRequest")
            .field("operation_id", &self.operation_id)
            .field("fingerprint", &self.fingerprint)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// memory—v1: Admissions for the additional actions of the same request.
#[derive(Clone, Debug)]
pub(crate) struct MemoryV1AdditionalAdmissions(pub(crate) Vec<MemoryV1Admission>);

fn governance_body_id(body: &Value, field: &str) -> Result<BinaryId, StatusCode> {
    let raw = body
        .get(field)
        .and_then(Value::as_str)
        .ok_or(StatusCode::BAD_REQUEST)?;
    let id = raw
        .parse::<MemoryId>()
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .into_bytes();
    if id == [0; 16] {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(id)
}

// memory—v1 §4.15: An OVERLAY with no live BASE requires its own action.
pub(crate) fn is_overlay_only_request(
    root: &RequestRootExtension,
    path: &str,
    body: &Bytes,
) -> Result<bool, StatusCode> {
    if path != "/governance/bindings" {
        return Ok(false);
    }
    let value: Value = serde_json::from_slice(body).map_err(|_| StatusCode::BAD_REQUEST)?;
    match value.get("binding_layer").and_then(Value::as_str) {
        Some("BASE") => Ok(false),
        Some("OVERLAY") => {
            let card_id = governance_body_id(&value, "user_card_id")?;
            root.with_reader(|reader| reader.overlay_only_target(card_id))
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
        }
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

// memory—v1: Resolve governance targets and their tenant from the request root.
fn governance_target_for_request(
    root: &RequestRootExtension,
    method: &axum::http::Method,
    path: &str,
    body: &Bytes,
) -> Result<(BinaryId, GovernanceTargetFacts), StatusCode> {
    let value: Value = serde_json::from_slice(body).map_err(|_| StatusCode::BAD_REQUEST)?;
    root.with_reader(|reader| {
        let (target_id, facts) = match (method.as_str(), path) {
            ("POST", "/governance/bindings") => {
                let target_id = governance_body_id(&value, "binding_id")?;
                let facts = reader
                    .binding_create_target(
                        governance_body_id(&value, "user_card_id")?,
                        governance_body_id(&value, "rule_set_id")?,
                    )
                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                (target_id, facts)
            }
            ("POST", "/governance/bindings/confirm") => {
                let target_id = governance_body_id(&value, "binding_id")?;
                let facts = reader
                    .binding_target(target_id)
                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                if value
                    .get("rule_set_id")
                    .is_some_and(|field| !field.is_null())
                    && governance_body_id(&value, "rule_set_id")? != facts.rule_set_id
                {
                    return Err(StatusCode::BAD_REQUEST);
                }
                (target_id, facts)
            }
            ("DELETE", "/governance/bindings") => {
                let target_id = governance_body_id(&value, "binding_id")?;
                let facts = reader
                    .binding_target(target_id)
                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                (target_id, facts)
            }
            ("POST", "/governance/bindings/revoke-confirmation") => {
                let target_id = governance_body_id(&value, "confirmation_id")?;
                let facts = reader
                    .confirmation_target(target_id)
                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                (target_id, facts)
            }
            ("POST", "/governance/rule-sets") => {
                let target_id = governance_body_id(&value, "rule_set_id")?;
                let facts = reader
                    .rule_set_create_target(
                        target_id,
                        governance_body_id(&value, "owner_tenant_id")?,
                    )
                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                (target_id, facts)
            }
            ("POST", "/governance/rule-sets/publish" | "/governance/rule-sets/retire") => {
                let target_id = governance_body_id(&value, "rule_set_id")?;
                let facts = reader
                    .active_rule_set_target(target_id)
                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                (target_id, facts)
            }
            ("POST", "/governance/user-cards") => {
                let target_id = governance_body_id(&value, "user_card_id")?;
                let facts = reader
                    .user_card_create_target(
                        target_id,
                        governance_body_id(&value, "user_id")?,
                        governance_body_id(&value, "tenant_id")?,
                    )
                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                (target_id, facts)
            }
            ("POST", "/governance/user-cards/disable" | "/governance/user-cards/enable") => {
                let target_id = governance_body_id(&value, "user_card_id")?;
                let facts = reader
                    .user_card_target(target_id)
                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                (target_id, facts)
            }
            _ => return Err(StatusCode::SERVICE_UNAVAILABLE),
        };
        Ok((target_id, facts))
    })
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
}

/// memory—v1: Refuse an invalid or mismatched change-confirmation admission.
fn change_confirmation_impact_pending(path: &str) -> BoxedResponse {
    memory_v1_refusal(
        StatusCode::SERVICE_UNAVAILABLE,
        "Authorization pending",
        "AUTHORIZATION_CONTEXT_INVALID",
        path,
    )
}

// memory—v1: Only the two registered rule-set operations may request change
// confirmation. An unrecognized confirm-change route must never use the generic evaluator.
fn rule_set_change_intent(
    declaration: &MemoryV1RouteRegistration,
    action: &str,
) -> Result<Option<MemoryV1RuleSetChangeIntent>, ()> {
    if action != "confirm-change" {
        return Ok(None);
    }
    match (
        declaration.method,
        declaration.path,
        declaration.resource,
        declaration.action,
    ) {
        ("POST", "/governance/rule-sets", "rule_set", "create") => {
            Ok(Some(MemoryV1RuleSetChangeIntent::Create))
        }
        ("POST", "/governance/rule-sets/publish", "rule_set", "version-publish") => {
            Ok(Some(MemoryV1RuleSetChangeIntent::Publish))
        }
        _ => Err(()),
    }
}

// memory—v1: Every individual evaluation uses the appropriate formal engine
// entry. Multiple admissions do not constitute a compound commit capability.
pub(super) fn evaluate_route_action(
    engine: &policy_engine::PolicyEngine,
    root: &RequestRootExtension,
    session: &RequestSessionExtension,
    declaration: &MemoryV1RouteRegistration,
    request: &MemoryV1Request<'_>,
) -> Result<MemoryV1Evaluation, ()> {
    match rule_set_change_intent(declaration, request.action)? {
        Some(intent) => {
            Ok(engine.evaluate_memory_v1_rule_set_change(root, session, request, intent))
        }
        None => Ok(engine.evaluate_memory_v1(root, session, request)),
    }
}

// memory—v1: Match the exact registered operation to its target interpretation.
fn compound_target_kind(
    declaration: &MemoryV1RouteRegistration,
) -> Option<MemoryV1CompoundTargetKind> {
    match (
        declaration.method,
        declaration.path,
        declaration.resource,
        declaration.action,
    ) {
        ("POST", "/governance/bindings", "binding", "create") => {
            Some(MemoryV1CompoundTargetKind::BindingCreate)
        }
        ("POST", "/governance/rule-sets", "rule_set", "create") => {
            Some(MemoryV1CompoundTargetKind::RuleSetCreate)
        }
        ("POST", "/governance/rule-sets/publish", "rule_set", "version-publish")
        | ("POST", "/governance/rule-sets/retire", "rule_set", "retire")
        | ("POST", "/governance/bindings/confirm", "binding", "confirm")
        | ("DELETE", "/governance/bindings", "binding", "remove")
        | ("POST", "/governance/bindings/revoke-confirmation", "binding", "revoke-confirmation") => {
            Some(MemoryV1CompoundTargetKind::Existing)
        }
        ("POST", "/governance/user-cards", "user_card", "create") => {
            Some(MemoryV1CompoundTargetKind::UserCardCreate)
        }
        ("POST", "/governance/user-cards/enable", "user_card", "enable") => {
            Some(MemoryV1CompoundTargetKind::UserCardEnable)
        }
        ("POST", "/governance/user-cards/disable", "user_card", "disable") => {
            Some(MemoryV1CompoundTargetKind::UserCardDisable)
        }
        _ => None,
    }
}

fn compound_target_kind_for_action(
    declaration: &MemoryV1RouteRegistration,
    action: &str,
) -> Option<MemoryV1CompoundTargetKind> {
    if action == "confirm-change" {
        return match (declaration.path, declaration.action) {
            ("/governance/rule-sets", "create") => Some(MemoryV1CompoundTargetKind::RuleSetCreate),
            ("/governance/rule-sets/publish", "version-publish") => {
                Some(MemoryV1CompoundTargetKind::Existing)
            }
            _ => None,
        };
    }
    compound_target_kind(declaration)
}

fn governance_compound_actions<'a>(
    declaration: &MemoryV1RouteRegistration,
    request: MemoryV1Request<'a>,
    target_facts: GovernanceTargetFacts,
    actual_actions: &[&'a str],
) -> Result<Vec<MemoryV1CompoundAction<'a>>, ()> {
    actual_actions
        .iter()
        .copied()
        .map(|action| {
            Ok(MemoryV1CompoundAction {
                request: MemoryV1Request { action, ..request },
                change_intent: rule_set_change_intent(declaration, action)?,
                target_facts,
                target_kind: compound_target_kind_for_action(declaration, action).ok_or(())?,
            })
        })
        .collect()
}

fn require_memory_v1_compound_admissions(
    evaluation: MemoryV1CompoundEvaluation,
    resource: &str,
    action: &str,
    external_path: &str,
    authorization_started: Instant,
    deny_proof: &dyn MemoryV1DenyProofPort,
) -> Result<Vec<MemoryV1Admission>, BoxedResponse> {
    let MemoryV1CompoundEvaluation {
        decision,
        deny_source,
        pending_source,
        admissions,
        deny_observation,
    } = evaluation;
    let single = match decision {
        MemoryV1Decision::Allow if !admissions.is_empty() => return Ok(admissions),
        MemoryV1Decision::Allow => MemoryV1Evaluation {
            decision: MemoryV1Decision::Pending,
            deny_source: None,
            pending_source: Some(MemoryV1PendingSource::ContextInvalid),
            admission: None,
            deny_observation: None,
        },
        decision => MemoryV1Evaluation {
            decision,
            deny_source,
            pending_source,
            admission: None,
            deny_observation,
        },
    };
    require_memory_v1_admission(
        single,
        resource,
        action,
        external_path,
        authorization_started,
        deny_proof,
    )
    .map(|admission| vec![admission])
}

/// memory—v1: Authorize one in-process request through its request-lifecycle reader.
///
/// The session must be authority-verified, bound to this request's exact root
/// scope and delivered over the proven in-process session transport; identity
/// comes only from those facts, never from headers. Only routes adapted to
/// memory—v1 can be admitted. The operation id and the request fingerprint are
/// frozen before evaluation and bound into the admission. A DENY refuses the
/// handler and returns 503 until both its audit message and the authorization
/// state it read have durable proof. Retryable PENDING remains 503 and a
/// root-level failure is 500 `AUTHORIZATION_ROOT_UNAVAILABLE`. There is no
/// fallback to the legacy path.
async fn memory_v1_permission_check(
    state: &AppState,
    mut req: Request,
    next: Next,
    root: RequestRootExtension,
    declaration: &'static MemoryV1RouteRegistration,
    authorization_started: Instant,
) -> Result<Response, BoxedResponse> {
    let external_path = req
        .extensions()
        .get::<axum::extract::OriginalUri>()
        .map(|uri| uri.0.path().to_owned())
        .unwrap_or_else(|| req.uri().path().to_owned());
    let transport_verified = req
        .extensions()
        .get::<VerifiedMemoryV1SessionTransport>()
        .is_some();
    let session = req
        .extensions()
        .get::<RequestSessionExtension>()
        .filter(|session| transport_verified && session.is_bound_to(&root))
        .cloned();
    let Some(session) = session else {
        record_authorization_request(
            AuthorizationAdmissionOutcome::RejectedContext,
            authorization_started.elapsed(),
        );
        record_authorization_decision(AuthorizationDecisionOutcome::Pending);
        tracing::warn!(
            resource = declaration.resource,
            action = declaration.action,
            path = %external_path,
            "memory-v1 request lacks a bound authenticated session; authorization pending"
        );
        return Err(memory_v1_refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "Authorization pending",
            "AUTHORIZATION_PENDING",
            &external_path,
        ));
    };
    let operation_id = astral_common::middleware::request_binding::request_operation_id(&req)
        .map_err(|status| BoxedResponse::new(status.into_response()))?;
    let (fingerprint, body) =
        astral_common::middleware::request_binding::bind_http_request_with_body(&mut req)
            .await
            .map_err(|status| BoxedResponse::new(status.into_response()))?;

    // memory—v1: Authorize the entire ordered batch, without treating its first
    // item as an anchor for the remaining targets.
    if declaration.method == "POST" && declaration.path == "/governance/bindings/confirm/batch" {
        let items = super::governance_routes::parse_binding_confirmation_batch_items(
            &body,
            state.config.memory_v1_confirmation_batch_limit,
        )
        .map_err(|status| BoxedResponse::new(status.into_response()))?;
        let MemoryV1BatchEvaluation {
            decision,
            deny_source,
            pending_source,
            admission,
            deny_observation,
        } = state.engine.evaluate_memory_v1_confirmation_batch(
            &root,
            &session,
            &MemoryV1BatchRequest {
                operation_id: operation_id.as_bytes(),
                operation_fingerprint: fingerprint.as_bytes(),
                items: &items,
            },
        );
        let admission = match (decision, admission) {
            (MemoryV1Decision::Allow, Some(admission)) => admission,
            (decision, _) => {
                let evaluation = MemoryV1Evaluation {
                    decision,
                    deny_source,
                    pending_source,
                    admission: None,
                    deny_observation,
                };
                let refusal = match require_memory_v1_admission(
                    evaluation,
                    declaration.resource,
                    declaration.action,
                    &external_path,
                    authorization_started,
                    state.memory_v1_deny_proof.as_ref(),
                ) {
                    Err(refusal) => refusal,
                    Ok(_) => change_confirmation_impact_pending(&external_path),
                };
                return Err(refusal);
            }
        };
        if admission.operation_id() != operation_id.as_bytes()
            || admission.operation_fingerprint() != fingerprint.as_bytes()
            || !admission
                .targets()
                .iter()
                .map(|target| target.item)
                .eq(items.iter().copied())
        {
            return Err(change_confirmation_impact_pending(&external_path));
        }
        record_authorization_decision(AuthorizationDecisionOutcome::Allow);
        record_authorization_request(
            AuthorizationAdmissionOutcome::Admitted,
            authorization_started.elapsed(),
        );
        req.extensions_mut().insert(admission);
        req.extensions_mut().insert(MemoryV1BoundRequest {
            operation_id,
            fingerprint,
            body,
        });
        return Ok(next.run(req).await);
    }

    let target_context = if declaration.path.starts_with("/governance/") {
        let target =
            governance_target_for_request(&root, &req.method().clone(), declaration.path, &body)
                .map_err(|status| BoxedResponse::new(status.into_response()))?;
        Some(target)
    } else {
        None
    };
    let (target, target_tenant, target_owner) = target_context
        .map(|(target_id, facts)| {
            (
                Some(target_id),
                Some(facts.tenant_id),
                (!facts.owner_user_id.iter().all(|byte| *byte == 0)).then_some(facts.owner_user_id),
            )
        })
        .unwrap_or((None, None, None));

    // memory—v1 §3.6/§4.10: governance targets are attributed by the same
    // request-root snapshot used by evaluation; the handler receives the exact
    // bounded bytes and operation binding that were admitted here.
    let request = MemoryV1Request {
        resource: declaration.resource,
        action: declaration.action,
        target: target.as_ref().map(|target| target.as_slice()),
        target_tenant: target_tenant
            .as_ref()
            .map(|target_tenant| target_tenant.as_slice()),
        target_owner: target_owner
            .as_ref()
            .map(|target_owner| target_owner.as_slice()),
        operation_id: operation_id.as_bytes(),
        operation_fingerprint: fingerprint.as_bytes(),
    };
    let overlay_only = if declaration.method == "POST" && declaration.path == "/governance/bindings"
    {
        is_overlay_only_request(&root, declaration.path, &body)
            .map_err(|status| BoxedResponse::new(status.into_response()))?
    } else {
        false
    };
    let actual_actions: Vec<&'static str> = std::iter::once(declaration.action)
        .chain(
            declaration
                .additional_actions
                .iter()
                .copied()
                .filter(|action| *action != "create-overlay-only" || overlay_only),
        )
        .collect();
    let action_count = actual_actions.len();
    // Every governance action, including a single-action request, must include
    // the root-derived target fences in the same final check as the actor's
    // dependencies. Non-governance reads keep the ordinary evaluator path.
    let mut admissions = if target_context.is_some() || action_count > 1 {
        let Some((_, target_facts)) = target_context else {
            return Err(change_confirmation_impact_pending(&external_path));
        };
        let compound_actions =
            governance_compound_actions(declaration, request, target_facts, &actual_actions)
                .map_err(|_| change_confirmation_impact_pending(&external_path))?;
        let evaluation = state.engine.evaluate_memory_v1_compound(
            &root,
            &session,
            &MemoryV1CompoundRequest {
                actions: &compound_actions,
            },
        );
        require_memory_v1_compound_admissions(
            evaluation,
            declaration.resource,
            declaration.action,
            &external_path,
            authorization_started,
            state.memory_v1_deny_proof.as_ref(),
        )?
    } else {
        let action = *actual_actions
            .first()
            .expect("primary action exists for a registered route");
        let evaluation_request = MemoryV1Request { action, ..request };
        let expected_intent = rule_set_change_intent(declaration, action)
            .map_err(|_| change_confirmation_impact_pending(&external_path))?;
        let evaluation = evaluate_route_action(
            &state.engine,
            &root,
            &session,
            declaration,
            &evaluation_request,
        )
        .map_err(|_| change_confirmation_impact_pending(&external_path))?;
        let admission = require_memory_v1_admission(
            evaluation,
            declaration.resource,
            action,
            &external_path,
            authorization_started,
            state.memory_v1_deny_proof.as_ref(),
        )?;
        if admission.resource() != declaration.resource
            || admission.action() != action
            || admission.change_intent() != expected_intent
        {
            return Err(change_confirmation_impact_pending(&external_path));
        }
        vec![admission]
    };
    if admissions.len() != actual_actions.len() {
        return Err(change_confirmation_impact_pending(&external_path));
    }
    let first = admissions
        .first()
        .cloned()
        .ok_or_else(|| change_confirmation_impact_pending(&external_path))?;
    for (admission, expected_action) in admissions.iter().zip(actual_actions.iter().copied()) {
        let expected_intent = rule_set_change_intent(declaration, expected_action)
            .map_err(|_| change_confirmation_impact_pending(&external_path))?;
        if admission.resource() != declaration.resource
            || admission.action() != expected_action
            || admission.change_intent() != expected_intent
            || admission.root() != first.root()
            || admission.identity() != first.identity()
            || admission.target() != first.target()
            || admission.target_tenant() != first.target_tenant()
            || admission.target_owner() != first.target_owner()
            || admission.operation_id() != first.operation_id()
            || admission.operation_fingerprint() != first.operation_fingerprint()
            || admission.trusted_time_unix_seconds() != first.trusted_time_unix_seconds()
        {
            return Err(change_confirmation_impact_pending(&external_path));
        }
    }
    let admission = admissions.remove(0);
    record_authorization_decision(AuthorizationDecisionOutcome::Allow);
    record_authorization_request(
        AuthorizationAdmissionOutcome::Admitted,
        authorization_started.elapsed(),
    );
    tracing::debug!(
        resource = declaration.resource,
        action = declaration.action,
        path = %external_path,
        root_version = admission.root().version,
        "memory-v1 request admitted"
    );
    req.extensions_mut().insert(admission);
    req.extensions_mut()
        .insert(MemoryV1AdditionalAdmissions(admissions));
    req.extensions_mut().insert(MemoryV1BoundRequest {
        operation_id,
        fingerprint,
        body,
    });
    Ok(next.run(req).await)
}

/// memory—v1: Convert one evaluator DENY snapshot to the durable observation
/// value the proof owner receives. The conversion is value-preserving; a field
/// that cannot be represented stays an error instead of being dropped.
fn deny_observation_value(
    observation: &policy_engine::memory_v1_formal::MemoryV1DenyObservation,
) -> Result<astral_types::memory_v1_deny_observation::MemoryV1DenyObservation, String> {
    use astral_types::memory_v1_audit::MemoryV1AuditRootStatus;
    use astral_types::memory_v1_deny_observation::MemoryV1DenyAffectedBindingState;
    let root = observation.root();
    let root_observation =
        astral_types::memory_v1_deny_observation::MemoryV1DenyRootObservation::try_from_usize(
            MemoryId::from_bytes(*root.instance_id.as_uuid().as_bytes()),
            root.version,
            root.digest,
            MemoryV1AuditRootStatus::Serving,
            root.budget.max_table_rows,
            root.budget.max_bindings_per_read,
            root.row_count,
        )
        .map_err(|error| format!("deny root observation: {error}"))?;
    let affected_binding = match observation.affected_binding() {
        Some(binding) => MemoryV1DenyAffectedBindingState::Present(
            astral_types::memory_v1_deny_observation::MemoryV1DenyAffectedBinding::new(
                MemoryId::from_bytes(binding.binding_id()),
                MemoryId::from_bytes(binding.user_card_id()),
                MemoryId::from_bytes(binding.owner_user_id()),
                MemoryId::from_bytes(binding.tenant_id()),
            ),
        ),
        None => MemoryV1DenyAffectedBindingState::unknown(),
    };
    // The evaluator snapshot carries the request binding's lowercase hex
    // fingerprint; the durable observation stores the 32 raw bytes.
    let fingerprint = {
        let bytes = observation.operation_fingerprint();
        if bytes.len() == 32 {
            bytes.to_vec()
        } else {
            let hex = std::str::from_utf8(bytes)
                .map_err(|error| format!("deny fingerprint encoding: {error}"))?;
            let decoded = astral_types::memory_v1_audit::memory_v1_audit_fingerprint_from_hex(hex)
                .map_err(|error| format!("deny fingerprint hex: {error}"))?;
            decoded.to_vec()
        }
    };
    astral_types::memory_v1_deny_observation::MemoryV1DenyObservation::from_slices(
        root_observation,
        observation.identity(),
        observation.read_started_at_unix_seconds(),
        observation.resource(),
        observation.action(),
        observation.target(),
        observation.target_tenant(),
        observation.target_owner(),
        affected_binding,
        observation.operation_id(),
        &fingerprint,
        observation.source().audit_source(),
        observation.batch_sequence(),
    )
    .map_err(|error| format!("deny observation value: {error}"))
}

/// memory—v1: The uniform fail-closed 503 body for a DENY whose proofs are not
/// both verified. The decision label stays the evaluator's internal source;
/// the read-phase observation, when present, stays attached for in-process
/// diagnostics only.
fn denial_unavailable_response(
    decision: &str,
    external_path: &str,
    observation: Option<policy_engine::memory_v1_formal::MemoryV1DenyObservation>,
) -> BoxedResponse {
    let body = serde_json::json!({
        "code": StatusCode::SERVICE_UNAVAILABLE.as_u16(),
        "message": "Authorization audit unavailable or evidence durability unconfirmed",
        "requestPath": external_path,
        "decision": decision,
        "reasonCode": "AUTHORIZATION_AUDIT_UNAVAILABLE",
    });
    let mut response = (StatusCode::SERVICE_UNAVAILABLE, axum::Json(body)).into_response();
    response.headers_mut().insert(
        axum::http::header::RETRY_AFTER,
        axum::http::HeaderValue::from_static("3"),
    );
    AuthorizationAuditUnavailableRefusal::attach(&mut response);
    if let Some(observation) = observation {
        response.extensions_mut().insert(observation);
    }
    BoxedResponse::new(response)
}

// memory—v1: Every action in a compound request must independently allow.
fn require_memory_v1_admission(
    evaluation: MemoryV1Evaluation,
    resource: &str,
    action: &str,
    external_path: &str,
    authorization_started: Instant,
    deny_proof: &dyn MemoryV1DenyProofPort,
) -> Result<MemoryV1Admission, BoxedResponse> {
    match (evaluation.decision, evaluation.admission) {
        (MemoryV1Decision::Allow, Some(admission)) => Ok(admission),
        (MemoryV1Decision::Deny, _) => {
            record_authorization_decision(AuthorizationDecisionOutcome::Deny);
            record_authorization_request(
                AuthorizationAdmissionOutcome::RejectedPolicy,
                authorization_started.elapsed(),
            );
            // memory—v1 §7.10: A 403 requires the durable DENY audit proof AND
            // the authorization-state prefix proof, both verified by the
            // injected owner. The fail-closed port keeps every DENY a 503.
            let decision = match evaluation.deny_source {
                Some(MemoryV1DenySource::RuleDenied) => "AUTHORIZATION_RULE_DENIED",
                Some(MemoryV1DenySource::CardUnbound) => "AUTHORIZATION_CARD_UNBOUND",
                _ => "AUTHORIZATION_NO_MATCH",
            };
            if let Some(observation) = evaluation.deny_observation.as_ref() {
                let durable_observation = match deny_observation_value(observation) {
                    Ok(value) => {
                        tracing::warn!(
                            fingerprint_len = value.operation_fingerprint().len(),
                            operation_id = String::from_utf8_lossy(value.operation_id()).as_ref(),
                            "deny observation converted"
                        );
                        value
                    }
                    Err(error) => {
                        tracing::warn!(
                            resource,
                            action,
                            path = %external_path,
                            decision = "DENY",
                            error = %error,
                            "memory-v1 DENY observation conversion failed; staying fail-closed"
                        );
                        // The read-phase value stays attached for diagnostics
                        // even when the durable conversion failed.
                        return Err(denial_unavailable_response(
                            decision,
                            external_path,
                            Some((**observation).clone()),
                        ));
                    }
                };
                match deny_proof.prove_deny(durable_observation) {
                    Ok(crate::service::memory_v1_mutation_coordinator::DenyResponse::Forbidden) => {
                        tracing::warn!(
                            resource,
                            action,
                            path = %external_path,
                            decision = "DENY",
                            deny_source = observation.source().audit_source().as_str(),
                            "memory-v1 request denied; both durable proofs verified"
                        );
                        let body = serde_json::json!({
                            "code": StatusCode::FORBIDDEN.as_u16(),
                            "message": "Authorization denied",
                            "requestPath": external_path,
                            "decision": decision,
                            "reasonCode": decision,
                        });
                        let response = (StatusCode::FORBIDDEN, axum::Json(body)).into_response();
                        return Err(BoxedResponse::new(response));
                    }
                    outcome => {
                        tracing::warn!(
                            resource,
                            action,
                            path = %external_path,
                            decision = "DENY",
                            deny_source = observation.source().audit_source().as_str(),
                            outcome = ?outcome,
                            "memory-v1 request denied; audit or authorization evidence durability unavailable"
                        );
                    }
                }
            } else {
                tracing::warn!(
                    resource,
                    action,
                    path = %external_path,
                    decision = "DENY",
                    deny_source = evaluation
                        .deny_source
                        .map(|source| source.audit_source().as_str())
                        .unwrap_or("unclassified"),
                    "memory-v1 request denied without a complete observation"
                );
            }
            Err(denial_unavailable_response(
                decision,
                external_path,
                evaluation.deny_observation.map(|boxed| *boxed),
            ))
        }
        // `Pending`, or an `Allow` without its admission, never admits the handler.
        _ => {
            record_authorization_decision(AuthorizationDecisionOutcome::Pending);
            record_authorization_request(
                AuthorizationAdmissionOutcome::RejectedPolicy,
                authorization_started.elapsed(),
            );
            // memory—v1 §3.5: retryable pending stays 503; a root-level failure
            // is 500 `AUTHORIZATION_ROOT_UNAVAILABLE` and needs human attention.
            let (status, message, reason) = match evaluation.pending_source {
                Some(MemoryV1PendingSource::ContextInvalid) => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Authorization pending",
                    "AUTHORIZATION_CONTEXT_INVALID",
                ),
                Some(MemoryV1PendingSource::FenceActive) => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Authorization pending",
                    "AUTHORIZATION_PENDING",
                ),
                Some(MemoryV1PendingSource::RootUnavailable) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Authorization unavailable",
                    "AUTHORIZATION_ROOT_UNAVAILABLE",
                ),
                None => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Authorization pending",
                    "AUTHORIZATION_PENDING",
                ),
            };
            let source = evaluation
                .pending_source
                .map(MemoryV1PendingSource::as_str)
                .unwrap_or("unclassified");
            tracing::warn!(
                resource,
                action,
                path = %external_path,
                reason,
                pending_source = source,
                "memory-v1 request pending"
            );
            Err(memory_v1_refusal(status, message, reason, external_path))
        }
    }
}

// memory—v1: Uniform refusal body; it exposes no identity, rule or root detail.
fn memory_v1_refusal(status: StatusCode, message: &str, reason: &str, path: &str) -> BoxedResponse {
    let body = serde_json::json!({
        "code": status.as_u16(),
        "message": message,
        "requestPath": path,
        "decision": reason,
        "reasonCode": reason,
    });
    let mut response = (status, axum::Json(body)).into_response();
    if status == StatusCode::SERVICE_UNAVAILABLE {
        response.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            axum::http::HeaderValue::from_static("3"),
        );
        // memory—v1: A pending guard answer is healthy; the gateway must not count it as an outage.
        if reason == "AUTHORIZATION_PENDING" {
            AuthorizationPendingRefusal::attach(&mut response);
        }
    }
    BoxedResponse::new(response)
}

/// memory—v1: Operation ownership remains unavailable until the shared root supports it.
async fn permission_check_middleware_scoped(
    state: AppState,
    mut req: Request,
    next: Next,
    request_id: Option<String>,
) -> Result<Response, BoxedResponse> {
    let authorization_started = Instant::now();
    let request_path = req.uri().path().to_owned();
    let path = request_path.as_str();
    let method = req.method().clone();

    // 放行路径
    if SKIP_PATHS.iter().any(|p| {
        path == *p
            || path
                .strip_prefix(p)
                .is_some_and(|rest| rest.starts_with('/'))
    }) {
        return Ok(next.run(req).await);
    }

    // memory—v1: A request dispatched with a request root scope is decided only
    // by the memory—v1 engine entry against that scope's reader. It never reaches
    // the legacy fence, header-derived context or retired read surface below.
    // Resolve the exact declaration before the legacy path map: governance routes
    // intentionally have no legacy resource mapping.
    if let Some(root) = req.extensions().get::<RequestRootExtension>().cloned() {
        let Some(declaration) = memory_v1_route_declaration(&method, path) else {
            record_authorization_request(
                AuthorizationAdmissionOutcome::RejectedMethodOrRoute,
                authorization_started.elapsed(),
            );
            record_authorization_decision(AuthorizationDecisionOutcome::Pending);
            tracing::warn!(
                path,
                method = %method,
                "route is not adapted to memory-v1 admission; authorization pending"
            );
            return Err(memory_v1_refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "Authorization pending",
                "AUTHORIZATION_ROUTE_NOT_ADAPTED",
                path,
            ));
        };
        // memory—v1: expose the commit capability only to governance handlers;
        // read-only adapted routes do not receive a mutation capability.
        if declaration.path.starts_with("/governance/") {
            req.extensions_mut()
                .insert(state.memory_v1_governance_commit.clone());
        }
        return memory_v1_permission_check(
            &state,
            req,
            next,
            root,
            declaration,
            authorization_started,
        )
        .await;
    }

    // Legacy requests continue through the existing resource/action and durable
    // ownership path. A request with a root scope can never fall through here.
    let resource = match resource_for_path(path) {
        Some(resource) => resource,
        None => {
            tracing::warn!(path, "no resource mapping for path, denying");
            record_authorization_request(
                AuthorizationAdmissionOutcome::RejectedMethodOrRoute,
                authorization_started.elapsed(),
            );
            return Err(BoxedResponse::new(
                (
                    StatusCode::FORBIDDEN,
                    format!("No permission mapping for path: {}", path),
                )
                    .into_response(),
            ));
        }
    };

    let action = match resolve_trustgraph_permission_action(resource, path, method.as_str()) {
        Some(action) => action,
        None => {
            tracing::warn!(path, method = %method, "no permission action for protected route, denying");
            record_authorization_request(
                AuthorizationAdmissionOutcome::RejectedMethodOrRoute,
                authorization_started.elapsed(),
            );
            return Err(BoxedResponse::new(
                (
                    StatusCode::METHOD_NOT_ALLOWED,
                    format!(
                        "No permission action for method {} on path {}",
                        method, path
                    ),
                )
                    .into_response(),
            ));
        }
    };

    // Capture once before authority reads; installed-but-unavailable is a refusal.
    let admission_fence = match astral_db::memory_projection_hub() {
        None => None,
        Some(hub) => match hub.capture_authority_fence() {
            Some(fence) => Some(fence),
            None => {
                record_authorization_request(
                    AuthorizationAdmissionOutcome::RejectedContext,
                    authorization_started.elapsed(),
                );
                tracing::error!(
                    path = path,
                    "admission fence unavailable: source writer active or outcome unknown; denying"
                );
                return Err(BoxedResponse::new(
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "admission fence unavailable; request denied".to_string(),
                    )
                        .into_response(),
                ));
            }
        },
    };

    let query_target_id = trustgraph_request_target_id(&req, resource, path, method.as_str())
        .map_err(|status| BoxedResponse::new(status.into_response()))?;
    let mut ctx = match physical_policy_context(req.headers(), resource, action, query_target_id) {
        Ok(ctx) => ctx,
        Err(status) => {
            record_authorization_request(
                AuthorizationAdmissionOutcome::RejectedContext,
                authorization_started.elapsed(),
            );
            return Err(BoxedResponse::new(status.into_response()));
        }
    };
    ctx.request_mutation_kind = request_mutation_kind(resource, path, method.as_str());
    ctx.request_operation_id = Some(
        astral_common::middleware::request_binding::request_operation_id(&req)
            .map_err(|status| BoxedResponse::new(status.into_response()))?,
    );
    ctx.request_fingerprint = Some(
        astral_common::middleware::request_binding::bind_http_request(&mut req)
            .await
            .map_err(|status| BoxedResponse::new(status.into_response()))?,
    );
    let read_surface = match astral_db::authorization_read_surface() {
        Some(surface) => surface,
        None => {
            return Err(BoxedResponse::new(
                StatusCode::SERVICE_UNAVAILABLE.into_response(),
            ));
        }
    };
    let read_request = match read_surface.begin_request() {
        Ok(request) => request,
        Err(error) => {
            record_authorization_request(
                AuthorizationAdmissionOutcome::RejectedContext,
                authorization_started.elapsed(),
            );
            tracing::error!(%error, "authorization request token unavailable");
            return Err(BoxedResponse::new(
                StatusCode::SERVICE_UNAVAILABLE.into_response(),
            ));
        }
    };
    // memory—v1: Operation ownership is not yet available from the shared root.
    if path_matches_prefix(path, "/operations") && method == "GET" {
        return Err(BoxedResponse::new(
            StatusCode::SERVICE_UNAVAILABLE.into_response(),
        ));
    }
    // The surface dispatch is the ownership resolver for every profile; this
    // marker keeps the source-layout guard tied to the pre-evaluation boundary.
    // CertifiedMemory never falls back to the durable resolver on this path.
    let resolution = if path_matches_prefix(path, "/operations") && method == "GET" {
        resolve_operation_poll_ownership(&state.db, path, &ctx).await
    } else {
        read_request
            .resolve_ownership(
                resource,
                path,
                method.as_str(),
                query_target_id,
                ctx.card_id,
                ctx.user_id,
            )
            .await
    };
    resolution.apply_to(&mut ctx);
    #[cfg(feature = "e1-observability")]
    {
        let stamp = policy_engine::e1_observation::stamp();
        tracing::info!(
            target: "authz_e1",
            event = "signed_context_bound",
            request_id = stamp.request_id.as_deref().unwrap_or(""),
            process_observation_id = %stamp.process_observation_id,
            event_sequence = stamp.event_sequence,
            wall_unix_ns = %stamp.wall_unix_ns,
            user_id = ?ctx.user_id,
            identity_card_id = ?ctx.identity_card_id,
            card_id = ?ctx.card_id,
            tenant_id = ?ctx.tenant_id,
            domain_id = ?ctx.domain_id,
            resource,
            action,
            "e1 authorization observation"
        );
    }
    let user_id = ctx.user_id;
    let card_id = ctx.card_id;
    let tenant_id = ctx.tenant_id;

    let evaluation = read_request
        .evaluate_with_admission(&state.engine, &ctx)
        .await;
    let (decision, authorization_admission) = evaluation.into_parts();
    record_authorization_decision(classify_policy_decision(&decision));
    #[cfg(feature = "e1-observability")]
    {
        let stamp = policy_engine::e1_observation::stamp();
        tracing::info!(
            target: "authz_e1",
            event = "decision_return",
            request_id = stamp.request_id.as_deref().unwrap_or(""),
            process_observation_id = %stamp.process_observation_id,
            event_sequence = stamp.event_sequence,
            wall_unix_ns = %stamp.wall_unix_ns,
            user_id = ?user_id,
            tenant_id = ?tenant_id,
            card_id = ?card_id,
            resource,
            action,
            allowed = decision.allowed,
            reason = %decision.reason,
            "e1 authorization observation"
        );
    }

    // 权限决策审计（MQ-first，DB fallback；故障不影响权限决策）。
    // ORG_SCOPE 判定携带 provenance 时，detail 升级为有界结构化 JSON
    // （路径 + 校验通过的 orgProvenance）；非 ORG 判定 detail 仍为纯请求路径，
    // 行为不变。provenance 不进入 Prometheus 标签。
    {
        let audit_resource = resource.to_string();
        let audit_action = action.to_string();
        let audit_reason = decision.reason.clone();
        let audit_path = path.to_string();
        let audit_allowed = decision.allowed;
        let audit_domain_id = ctx.domain_id;
        let audit_request_id = request_id.clone();
        let audit_detail = decision
            .org_provenance
            .as_ref()
            .and_then(|provenance| org_provenance_audit_detail(path, provenance));
        let hit_phase =
            policy_engine::PolicyEngine::allow_source_phase(&decision).map(String::from);
        let pool = state.db.clone();
        if let Err(reason) = astral_common::audit::spawn_owned_audit(async move {
            astral_common::audit::record_permission_audit_with_request_detail(
                user_id,
                card_id,
                audit_domain_id,
                tenant_id,
                &audit_resource,
                &audit_action,
                audit_allowed,
                &audit_reason,
                &audit_path,
                audit_request_id,
                audit_detail,
            )
            .await;
            if audit_allowed {
                if let Some(card) = card_id {
                    astral_db::record_permission_hit(
                        &pool,
                        card,
                        &audit_resource,
                        &audit_action,
                        hit_phase.as_deref(),
                    )
                    .await;
                }
            }
        }) {
            tracing::error!(reason, "policy audit task was not admitted");
        }
    }

    if !decision.allowed {
        record_authorization_request(
            AuthorizationAdmissionOutcome::RejectedPolicy,
            authorization_started.elapsed(),
        );
        tracing::warn!(
            user_id = ?user_id,
            card_id = ?card_id,
            resource = resource,
            action = action,
            reason = %decision.reason,
            path = path,
            "permission_denied"
        );
        // 统一消息包络：拒绝体必须对牌 ApiResponse JSON 形状（与 handlers 的
        // AppError 渲染同源——403 / PERMISSION_DENIED / reasonCode 由 reason 中
        // 的 DEFAULT_DENY 等稳定码派生）。纯文本 body 曾使远程断言无法对牌
        // （三节点战役 S12/S13 发现）。
        return Err(BoxedResponse::new(
            AppError(AstralError::Permission(format!(
                "Permission denied: {} for {}:{}",
                decision.reason, resource, action
            )))
            .into_response(),
        ));
    }

    // SoD 冲突检查（对齐 Java PermissionAspect → SodService.checkDynamicSoD）。
    // 对组织 ALLOW，先把 PolicyEngine 返回的 provenance 经 context-aware
    // mirrored 装配入口与组织准入证据对牌（复合进程 warm 命中走辅助镜像的
    // strict read contract，零 DB；镜像 miss/pending 回落既有 fresh DB 严格
    // 读），再进入 deny-only 复核；读取、钉栅或匹配失败统一进入 unavailable
    // 分支，绝不把组织持有权限折算为空集。非 ORG 判定走 context-aware 纯
    // deny-only 入口（warm 态同样零 DB；durable 回退与旧路径同语义）。
    if let Some(so_card_id) = card_id {
        let sod_started = Instant::now();
        let sod_result = read_request.check_sod(&ctx, &decision).await;
        match sod_result {
            Ok(result) if result.has_conflict => {
                record_sod_check(SodCheckOutcome::Conflict, sod_started.elapsed());
                record_authorization_request(
                    AuthorizationAdmissionOutcome::RejectedSod,
                    authorization_started.elapsed(),
                );
                tracing::warn!(
                    card_id = so_card_id,
                    resource = resource,
                    action = action,
                    policy = ?result.conflict_policy,
                    "sod_conflict_denied"
                );
                return Err(BoxedResponse::new(
                    (
                        StatusCode::FORBIDDEN,
                        format!(
                            "SoD conflict: {} holds conflicting permission '{}' per policy '{}'",
                            resource,
                            result.conflict_permission.unwrap_or_default(),
                            result.conflict_policy.unwrap_or_default()
                        ),
                    )
                        .into_response(),
                ));
            }
            Ok(_) => {
                record_sod_check(SodCheckOutcome::Clear, sod_started.elapsed());
            }
            Err(error) => {
                record_sod_check(SodCheckOutcome::Unavailable, sod_started.elapsed());
                record_authorization_request(
                    AuthorizationAdmissionOutcome::RejectedSod,
                    authorization_started.elapsed(),
                );
                tracing::error!(card_id = so_card_id, resource, action, %error, "SoD check unavailable; denying");
                return Err(BoxedResponse::new(
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "SoD check unavailable; request denied".to_string(),
                    )
                        .into_response(),
                ));
            }
        }
    }

    if let Err(error) = read_request.ensure_current() {
        record_authorization_request(
            AuthorizationAdmissionOutcome::RejectedContext,
            authorization_started.elapsed(),
        );
        tracing::error!(%error, "authorization request token changed; denying request");
        return Err(BoxedResponse::new(
            StatusCode::SERVICE_UNAVAILABLE.into_response(),
        ));
    }

    // Compare the original fence after all authority reads. A cold installation
    // can invalidate it; the next request must evaluate from the new baseline.
    if let Some(fence) = admission_fence {
        let fence_holds = astral_db::memory_projection_hub()
            .is_some_and(|hub| hub.authority_fence_matches(fence));
        if !fence_holds {
            record_authorization_request(
                AuthorizationAdmissionOutcome::RejectedContext,
                authorization_started.elapsed(),
            );
            tracing::error!(
                user_id = ?user_id,
                card_id = ?card_id,
                resource = resource,
                action = action,
                path = path,
                "admission fence mismatch: source state changed under an allowed request; denying"
            );
            return Err(BoxedResponse::new(
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "admission fence mismatch; request denied".to_string(),
                )
                    .into_response(),
            ));
        }
    }

    let source_abort = if !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS") {
        read_request
            .ensure_mutation_commit_fence()
            .map_err(|_| BoxedResponse::new(StatusCode::SERVICE_UNAVAILABLE.into_response()))?;
        let provider = state
            .authorization_fence_provider
            .as_ref()
            .ok_or_else(|| BoxedResponse::new(StatusCode::SERVICE_UNAVAILABLE.into_response()))?;
        let admission = authorization_admission
            .as_ref()
            .ok_or_else(|| BoxedResponse::new(StatusCode::SERVICE_UNAVAILABLE.into_response()))?;
        let abort = provider
            .reserve_mutation_with_abort(&ctx, admission)
            .await
            .map_err(|error| {
                BoxedResponse::new(
                    AppError(AstralError::Pending(error.to_string())).into_response(),
                )
            })?;
        Some((provider.clone(), abort))
    } else {
        None
    };

    // The reservation await is a second consistency window. Recheck the
    // original request token and captured fence before exposing the mutation to
    // the handler; never replace them with a newly sampled request.
    if let Some((provider, abort)) = &source_abort {
        let token_error = read_request.ensure_current().err();
        let token_changed = token_error.is_some();
        let fence_holds = admission_fence.is_none_or(|fence| {
            astral_db::memory_projection_hub().is_some_and(|hub| hub.authority_fence_matches(fence))
        });
        if let Some(error) = token_error {
            tracing::error!(%error, "post-reservation request token changed; handler denied");
        }
        if !fence_holds {
            tracing::error!("post-reservation admission fence changed; handler denied");
        }
        if token_changed || !fence_holds {
            record_authorization_request(
                AuthorizationAdmissionOutcome::RejectedContext,
                authorization_started.elapsed(),
            );
            abort_source_reservation_and_record(provider, abort, "trustgraph_post_reservation")
                .await;
            return Err(BoxedResponse::new(
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "authorization state changed after reservation; request denied".to_string(),
                )
                    .into_response(),
            ));
        }
    }

    #[cfg(feature = "e1-observability")]
    {
        let stamp = policy_engine::e1_observation::stamp();
        tracing::info!(
            target: "authz_e1",
            event = "host_admission",
            request_id = stamp.request_id.as_deref().unwrap_or(""),
            process_observation_id = %stamp.process_observation_id,
            event_sequence = stamp.event_sequence,
            wall_unix_ns = %stamp.wall_unix_ns,
            user_id = ?user_id,
            tenant_id = ?tenant_id,
            card_id = ?card_id,
            resource,
            action,
            "e1 authorization observation"
        );
    }

    tracing::debug!(
        user_id = ?user_id,
        resource = resource,
        action = action,
        "permission_allowed"
    );

    record_authorization_request(
        AuthorizationAdmissionOutcome::Admitted,
        authorization_started.elapsed(),
    );

    // 将校验后的上下文注入请求扩展，供下游 handler 使用
    req.extensions_mut().insert(ctx);
    if let Some(authorization_admission) = authorization_admission {
        req.extensions_mut().insert(authorization_admission);
    }
    let response = next.run(req).await;
    if let Some((provider, abort)) = source_abort {
        // HTTP status does not prove source rollback. The DB owner attempts a
        // same-row durable abort and refuses it if admission use/outcome exists.
        abort_source_reservation_and_record(&provider, &abort, "trustgraph_post_handler").await;
    }
    Ok(response)
}

#[cfg(test)]
mod tests {

    use crate::service::memory_v1_governance_commit::FailClosedMemoryV1DenyProofPort;

    // memory—v1: Route and fence fixtures assume an exact policy time; they
    // do not certify this machine's synchronization service. Session issuance
    // still uses the process clock, so keep the fixture in the same epoch.
    fn exact_route_clock() -> Option<(i128, i128)> {
        let elapsed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?;
        Some((i128::try_from(elapsed.as_nanos()).ok()?, 0))
    }

    // memory—v1: Every test path uses the fail-closed port; a 403 needs the
    // durable owner, which these tests do not assemble.
    fn fail_closed_deny_port() -> FailClosedMemoryV1DenyProofPort {
        FailClosedMemoryV1DenyProofPort
    }
    use super::{
        audit_request_id, request_target_id, resolve_trustgraph_permission_action,
        resource_for_path, MemoryV1BoundRequest, TRUSTGRAPH_PATH_RESOURCE_MAP,
    };
    use astral_authorization_root::memory_v1_db_rows::{
        BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, CurrentSelection,
        IdentityCardRow, RuleSetRow, RuleSetVersionRow, TenantRow, UserCardRow, UserCardStatus,
        UserRow,
    };
    use astral_authorization_root::memory_v1_hamt::CandidateBudget;
    use astral_authorization_root::memory_v1_request::{RequestRootExtension, RequestRootScope};
    use astral_authorization_root::memory_v1_root::{install_process_root, RootOwner};
    use astral_authorization_root::memory_v1_rules::{MemoryV1OwnerScope, MemoryV1TenantScope};
    use axum::extract::Request;
    use axum::http::{HeaderMap, HeaderValue};

    fn impact_rows() -> (CandidateRows, Vec<CurrentSelection>) {
        let id = |value| [value; 16];
        let tenant_id = id(0x70);
        let user_id = id(0x71);
        let card_id = id(0x73);
        let rule_set_id = id(0x75);
        (
            CandidateRows {
                users: vec![UserRow { user_id }],
                identity_cards: vec![IdentityCardRow {
                    identity_card_id: id(0x72),
                    user_id,
                }],
                tenants: vec![TenantRow {
                    tenant_id,
                    parent_tenant_id: None,
                }],
                user_cards: vec![UserCardRow {
                    user_card_id: card_id,
                    user_id,
                    tenant_id,
                    status: UserCardStatus::Active,
                }],
                rule_sets: vec![RuleSetRow {
                    status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
                    rule_set_id,
                    owner_tenant_id: tenant_id,
                    current_version_bytes: vec![1],
                }],
                rule_set_versions: vec![RuleSetVersionRow {
                    rule_set_id,
                    version_bytes: vec![1],
                    content_bytes: vec![1],
                    timestamp_bytes: vec![1],
                    hash_input_bytes: vec![1],
                    hash_bytes: vec![1],
                }],
                bindings: vec![BindingRow {
                    binding_id: id(0x76),
                    user_card_id: card_id,
                    rule_set_id,
                    binding_layer: BindingLayer::Base,
                    valid_from: None,
                    valid_until: None,
                    owner_scope: MemoryV1OwnerScope::default(),
                    tenant_scope: MemoryV1TenantScope::default(),
                    removed_at: None,
                    removed_by: None,
                }],
                ..CandidateRows::default()
            },
            vec![CurrentSelection {
                rule_set_id,
                version_bytes: vec![1],
            }],
        )
    }

    fn impact_scope(
        rows: CandidateRows,
        selections: Vec<CurrentSelection>,
        budget: CandidateBudget,
    ) -> (RootOwner, RequestRootScope) {
        let owner = install_process_root(rows, selections, budget)
            .expect("the local impact fixture must build");
        let scope = RequestRootScope::new(owner.handle(), uuid::Uuid::new_v4());
        (owner, scope)
    }

    fn impact_budget() -> CandidateBudget {
        CandidateBudget {
            max_table_rows: 32,
            max_bindings_per_read: 4,
        }
    }

    fn run_isolated_child(test_name: &str, marker: &str) -> bool {
        if std::env::var_os(marker).is_some() {
            return false;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test_name, "--nocapture"])
            .env(marker, "1")
            .output()
            .expect("failed to start isolated test process");
        assert!(
            output.status.success(),
            "stdout: {}\\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        true
    }

    // memory—v1: The candidate adapter remains a compatibility helper for
    // unit-level observations; production request handling requires session facts.
    async fn evaluate_candidate_request(
        engine: &policy_engine::PolicyEngine,
        ctx: &astral_types::PolicyContext,
        root: RequestRootExtension,
    ) -> astral_types::PolicyDecision {
        engine.evaluate_with_request_root(ctx, root).await
    }

    // memory—v1 §4.11/§4.12: Only a complete REMOVE tombstone is excluded;
    // disabled, revoked and future-window relationships remain conservative impact.
    #[test]
    fn change_impact_keeps_recoverable_relationships_and_excludes_removed_rows() {
        if run_isolated_child(
            "api::permission_check::tests::change_impact_keeps_recoverable_relationships_and_excludes_removed_rows",
            "ASTRAL_MEMORY_V1_IMPACT_RELATIONS_CHILD",
        ) {
            return;
        }
        let (mut rows, selections) = impact_rows();
        let id = |value| [value; 16];
        rows.bindings[0].removed_at = Some(10);
        rows.bindings[0].removed_by = Some(id(0x71));
        rows.users
            .extend([UserRow { user_id: id(0x77) }, UserRow { user_id: id(0x78) }]);
        rows.identity_cards.extend([
            IdentityCardRow {
                identity_card_id: id(0x79),
                user_id: id(0x77),
            },
            IdentityCardRow {
                identity_card_id: id(0x7a),
                user_id: id(0x78),
            },
        ]);
        rows.user_cards.extend([
            UserCardRow {
                user_card_id: id(0x7b),
                user_id: id(0x77),
                tenant_id: id(0x70),
                status: UserCardStatus::Disabled,
            },
            UserCardRow {
                user_card_id: id(0x7c),
                user_id: id(0x78),
                tenant_id: id(0x70),
                status: UserCardStatus::Active,
            },
        ]);
        rows.bindings.extend([
            BindingRow {
                binding_id: id(0x7d),
                user_card_id: id(0x7b),
                rule_set_id: id(0x75),
                binding_layer: BindingLayer::Base,
                valid_from: None,
                valid_until: None,
                owner_scope: MemoryV1OwnerScope::default(),
                tenant_scope: MemoryV1TenantScope::default(),
                removed_at: None,
                removed_by: None,
            },
            BindingRow {
                binding_id: id(0x7e),
                user_card_id: id(0x7c),
                rule_set_id: id(0x75),
                binding_layer: BindingLayer::Overlay,
                valid_from: Some(i64::MAX),
                valid_until: None,
                owner_scope: MemoryV1OwnerScope::default(),
                tenant_scope: MemoryV1TenantScope::default(),
                removed_at: None,
                removed_by: None,
            },
        ]);
        rows.binding_confirmations.push(BindingConfirmationRow {
            confirmation_id: id(0x7f),
            binding_id: id(0x7d),
            rule_set_id: id(0x75),
            version_bytes: vec![1],
            confirmer_user_id: id(0x71),
            scope_bytes: vec![1],
            operation_id: vec![1],
            confirmed_at_bytes: vec![1],
            revoked_at: Some(11),
            revoked_by: Some(id(0x71)),
        });
        let (owner, scope) = impact_scope(rows, selections, impact_budget());
        let impact = scope
            .extension()
            .with_reader(|reader| reader.read_change_impact(id(0x75)))
            .unwrap()
            .unwrap();
        assert!(!impact.binding_ids.contains(&id(0x76)));
        assert!(impact.binding_ids.contains(&id(0x7d)));
        assert!(impact.binding_ids.contains(&id(0x7e)));
        assert!(impact.card_ids.contains(&id(0x7b)));
        assert!(impact.user_ids.contains(&id(0x77)));
        assert!(impact.user_ids.contains(&id(0x78)));
        drop(scope);
        drop(owner);
    }

    // memory—v1 §4.11/§4.13: Inconsistent tenant attribution fails impact reading;
    // the dedicated evaluator turns this failure into PENDING.
    #[test]
    fn change_confirmation_impact_returns_pending_for_bad_tenant_and_budget() {
        if run_isolated_child(
            "api::permission_check::tests::change_confirmation_impact_returns_pending_for_bad_tenant_and_budget",
            "ASTRAL_MEMORY_V1_IMPACT_BAD_TENANT_CHILD",
        ) {
            return;
        }
        let (mut rows, selections) = impact_rows();
        rows.tenants.push(TenantRow {
            tenant_id: [0x80; 16],
            parent_tenant_id: None,
        });
        rows.user_cards[0].tenant_id = [0x80; 16];
        let owner = install_process_root(rows, selections, impact_budget())
            .expect("the inconsistent fixture must build as candidate data");
        let scope = RequestRootScope::new(owner.handle(), uuid::Uuid::new_v4());
        assert!(scope
            .extension()
            .with_reader(|reader| reader.read_change_impact([0x75; 16]))
            .unwrap()
            .is_err());
        drop(scope);
        drop(owner);
    }

    #[test]
    fn change_confirmation_impact_returns_pending_for_budget_overflow() {
        if run_isolated_child(
            "api::permission_check::tests::change_confirmation_impact_returns_pending_for_budget_overflow",
            "ASTRAL_MEMORY_V1_IMPACT_BUDGET_CHILD",
        ) {
            return;
        }
        let (rows, selections) = impact_rows();
        let owner = install_process_root(
            rows,
            selections,
            CandidateBudget {
                max_table_rows: 32,
                max_bindings_per_read: 0,
            },
        )
        .expect("the budget fixture must build as candidate data");
        let scope = RequestRootScope::new(owner.handle(), uuid::Uuid::new_v4());
        assert!(scope
            .extension()
            .with_reader(|reader| reader.read_change_impact([0x75; 16]))
            .unwrap()
            .is_err());
        drop(scope);
        drop(owner);
    }

    // Every currently registered single-action governance route must enter the
    // target-aware evaluator; an unknown route cannot gain a target kind.
    #[test]
    fn governance_single_action_target_kinds_are_exact() {
        use policy_engine::memory_v1_compound::MemoryV1CompoundTargetKind;
        let expected = [
            (
                "POST",
                "/governance/bindings/confirm",
                MemoryV1CompoundTargetKind::Existing,
            ),
            (
                "DELETE",
                "/governance/bindings",
                MemoryV1CompoundTargetKind::Existing,
            ),
            (
                "POST",
                "/governance/bindings/revoke-confirmation",
                MemoryV1CompoundTargetKind::Existing,
            ),
            (
                "POST",
                "/governance/rule-sets/retire",
                MemoryV1CompoundTargetKind::Existing,
            ),
            (
                "POST",
                "/governance/user-cards",
                MemoryV1CompoundTargetKind::UserCardCreate,
            ),
            (
                "POST",
                "/governance/user-cards/enable",
                MemoryV1CompoundTargetKind::UserCardEnable,
            ),
            (
                "POST",
                "/governance/user-cards/disable",
                MemoryV1CompoundTargetKind::UserCardDisable,
            ),
        ];
        for (method, path, kind) in expected {
            let route = super::MEMORY_V1_ROUTE_REGISTRATIONS
                .iter()
                .find(|route| route.method == method && route.path == path)
                .unwrap();
            assert!(route.additional_actions.is_empty());
            assert_eq!(super::compound_target_kind(route), Some(kind));
        }
        let unknown = super::MemoryV1RouteRegistration {
            method: "POST",
            path: "/governance/bindings/unknown",
            resource: "binding",
            action: "remove",
            additional_actions: &[],
        };
        assert_eq!(super::compound_target_kind(&unknown), None);
    }

    // memory—v1: A confirm-change cannot fall back to the generic evaluator
    // when any part of its registered route or primary action differs.
    #[test]
    fn change_confirmation_route_resolution_fails_closed() {
        use super::{
            memory_v1_route_declaration, rule_set_change_intent, MemoryV1RouteRegistration,
        };
        use axum::http::Method;
        use policy_engine::memory_v1_formal::MemoryV1RuleSetChangeIntent::{Create, Publish};

        for (path, expected) in [
            ("/governance/rule-sets", Create),
            ("/governance/rule-sets/publish", Publish),
        ] {
            let route = memory_v1_route_declaration(&Method::POST, path).unwrap();
            assert_eq!(
                rule_set_change_intent(route, "confirm-change"),
                Ok(Some(expected))
            );
            assert_eq!(rule_set_change_intent(route, route.action), Ok(None));
            assert!(memory_v1_route_declaration(&Method::GET, path).is_none());
        }
        for (method, path, resource, action) in [
            ("GET", "/governance/rule-sets", "rule_set", "create"),
            (
                "POST",
                "/governance/rule-sets/publish",
                "rule_set",
                "create",
            ),
            ("POST", "/governance/rule-sets", "binding", "create"),
            ("POST", "/governance/rule-sets/other", "rule_set", "create"),
        ] {
            let route = MemoryV1RouteRegistration {
                method,
                path,
                resource,
                action,
                additional_actions: &["confirm-change"],
            };
            assert_eq!(rule_set_change_intent(&route, "confirm-change"), Err(()));
        }
    }

    // memory—v1: Debug diagnostics identify the bounded request without exposing
    // governance body bytes.
    #[test]
    fn bound_request_debug_redacts_body_content() {
        let request = MemoryV1BoundRequest {
            operation_id: "operation-1".into(),
            fingerprint: "fingerprint-1".into(),
            body: axum::body::Bytes::from_static(b"secret-governance-body"),
        };
        let debug = format!("{request:?}");
        assert!(debug.contains("operation-1"));
        assert!(debug.contains("fingerprint-1"));
        assert!(debug.contains("body_len"));
        assert!(!debug.contains("secret-governance-body"));
    }

    #[tokio::test]
    async fn registry_decisions_preserve_pending_and_deny_response_codes() {
        use axum::body::to_bytes;
        use axum::http::StatusCode;
        use axum::response::IntoResponse as _;
        use policy_engine::memory_v1_formal::{
            MemoryV1Decision, MemoryV1DenySource, MemoryV1Evaluation, MemoryV1PendingSource,
        };
        use std::sync::{Arc, Mutex};
        use std::time::Instant;
        use tracing_subscriber::prelude::*;

        #[derive(Clone, Default)]
        struct Events(Arc<Mutex<Vec<String>>>);
        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Events {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _: tracing_subscriber::layer::Context<'_, S>,
            ) {
                struct Visitor(String);
                impl tracing::field::Visit for Visitor {
                    fn record_debug(
                        &mut self,
                        field: &tracing::field::Field,
                        value: &dyn std::fmt::Debug,
                    ) {
                        use std::fmt::Write;
                        write!(self.0, "{}={value:?} ", field.name()).unwrap();
                    }
                }
                let mut visitor = Visitor(String::new());
                event.record(&mut visitor);
                self.0.lock().unwrap().push(visitor.0);
            }
        }

        for (decision, deny_source, pending_source, status, reason) in [
            (
                MemoryV1Decision::Pending,
                None,
                Some(MemoryV1PendingSource::RootUnavailable),
                StatusCode::INTERNAL_SERVER_ERROR,
                "AUTHORIZATION_ROOT_UNAVAILABLE",
            ),
            (
                MemoryV1Decision::Pending,
                None,
                Some(MemoryV1PendingSource::ContextInvalid),
                StatusCode::SERVICE_UNAVAILABLE,
                "AUTHORIZATION_CONTEXT_INVALID",
            ),
            (
                MemoryV1Decision::Pending,
                None,
                Some(MemoryV1PendingSource::FenceActive),
                StatusCode::SERVICE_UNAVAILABLE,
                "AUTHORIZATION_PENDING",
            ),
            (
                MemoryV1Decision::Pending,
                None,
                None,
                StatusCode::SERVICE_UNAVAILABLE,
                "AUTHORIZATION_PENDING",
            ),
            (
                MemoryV1Decision::Deny,
                Some(MemoryV1DenySource::RuleDenied),
                None,
                StatusCode::SERVICE_UNAVAILABLE,
                "AUTHORIZATION_RULE_DENIED",
            ),
            (
                MemoryV1Decision::Deny,
                Some(MemoryV1DenySource::CardUnbound),
                None,
                StatusCode::SERVICE_UNAVAILABLE,
                "AUTHORIZATION_CARD_UNBOUND",
            ),
            (
                MemoryV1Decision::Deny,
                Some(MemoryV1DenySource::NoMatch),
                None,
                StatusCode::SERVICE_UNAVAILABLE,
                "AUTHORIZATION_NO_MATCH",
            ),
            (
                MemoryV1Decision::Deny,
                Some(MemoryV1DenySource::ScopeDenied),
                None,
                StatusCode::SERVICE_UNAVAILABLE,
                "AUTHORIZATION_NO_MATCH",
            ),
            (
                MemoryV1Decision::Deny,
                Some(MemoryV1DenySource::IdentityMismatch),
                None,
                StatusCode::SERVICE_UNAVAILABLE,
                "AUTHORIZATION_NO_MATCH",
            ),
            (
                MemoryV1Decision::Deny,
                Some(MemoryV1DenySource::UnregisteredResource),
                None,
                StatusCode::SERVICE_UNAVAILABLE,
                "AUTHORIZATION_NO_MATCH",
            ),
            (
                MemoryV1Decision::Deny,
                Some(MemoryV1DenySource::SelfConfirmation),
                None,
                StatusCode::SERVICE_UNAVAILABLE,
                "AUTHORIZATION_NO_MATCH",
            ),
            (
                MemoryV1Decision::Deny,
                Some(MemoryV1DenySource::CardDisabled),
                None,
                StatusCode::SERVICE_UNAVAILABLE,
                "AUTHORIZATION_NO_MATCH",
            ),
            (
                MemoryV1Decision::Deny,
                None,
                None,
                StatusCode::SERVICE_UNAVAILABLE,
                "AUTHORIZATION_NO_MATCH",
            ),
        ] {
            let evaluation = MemoryV1Evaluation {
                decision,
                deny_source,
                pending_source,
                admission: None,
                deny_observation: None,
            };
            let events = Events::default();
            let subscriber = tracing_subscriber::registry().with(events.clone());
            let response = match tracing::subscriber::with_default(subscriber, || {
                super::require_memory_v1_admission(
                    evaluation,
                    "document",
                    "read",
                    "/main/api/v1/example",
                    Instant::now(),
                    &fail_closed_deny_port(),
                )
            }) {
                Ok(_) => panic!("a refusal must not admit the request"),
                Err(response) => response.into_response(),
            };
            assert_eq!(response.status(), status);
            assert_eq!(
                astral_common::middleware::permission_check_shared::AuthorizationAuditUnavailableRefusal::is_attached(response.extensions()),
                decision == MemoryV1Decision::Deny
            );
            if decision == MemoryV1Decision::Deny {
                {
                    let events = events.0.lock().unwrap();
                    let expected_source = deny_source
                        .map(|source| source.audit_source().as_str())
                        .unwrap_or("unclassified");
                    assert!(
                        events.iter().any(|event| {
                            event.contains("decision=\"DENY\"")
                                && event.contains(&format!("deny_source=\"{expected_source}\""))
                        }),
                        "missing DENY decision and source {expected_source}: {events:?}"
                    );
                }
                assert!(!astral_common::middleware::permission_check_shared::AuthorizationPendingRefusal::is_attached(
                    response.extensions()
                ));
                let body = to_bytes(response.into_body(), 4096).await.unwrap();
                let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(json["code"], 503);
                assert_eq!(json["decision"], reason);
                assert_eq!(json["reasonCode"], "AUTHORIZATION_AUDIT_UNAVAILABLE");
            } else {
                assert_eq!(response.status(), status);
                let body = to_bytes(response.into_body(), 4096).await.unwrap();
                let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(json["decision"], reason);
                assert_eq!(json["reasonCode"], reason);
            }
        }
    }

    // memory—v1: A refusal must stop the handler for individual/batch and
    // compound evaluations, even though its HTTP status is a 503.
    #[tokio::test]
    async fn deny_gate_stops_oneshot_handler_for_single_and_compound_results() {
        use axum::{
            body::Body,
            http::{Request, StatusCode},
            middleware::{self, Next},
            response::{IntoResponse as _, Response},
            routing::get,
            Extension, Router,
        };
        use policy_engine::memory_v1_compound::MemoryV1CompoundEvaluation;
        use policy_engine::memory_v1_formal::{
            MemoryV1Decision, MemoryV1DenySource, MemoryV1Evaluation,
        };
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        use std::time::Instant;
        use tower::ServiceExt;

        let handler_calls = Arc::new(AtomicUsize::new(0));
        for compound in [false, true] {
            let calls = Arc::clone(&handler_calls);
            let app = Router::new()
                .route(
                    "/",
                    get(move || async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        StatusCode::OK
                    }),
                )
                .layer(middleware::from_fn(
                    |req: Request<Body>, next: Next| async move {
                        let compound = *req.extensions().get::<bool>().unwrap();
                        let result = if compound {
                            super::require_memory_v1_compound_admissions(
                                MemoryV1CompoundEvaluation {
                                    decision: MemoryV1Decision::Deny,
                                    deny_source: Some(MemoryV1DenySource::SelfConfirmation),
                                    pending_source: None,
                                    admissions: vec![],
                                    deny_observation: None,
                                },
                                "binding",
                                "confirm",
                                "/",
                                Instant::now(),
                                &fail_closed_deny_port(),
                            )
                            .map(|_| ())
                        } else {
                            super::require_memory_v1_admission(
                                MemoryV1Evaluation {
                                    decision: MemoryV1Decision::Deny,
                                    deny_source: Some(MemoryV1DenySource::CardUnbound),
                                    pending_source: None,
                                    admission: None,
                                    deny_observation: None,
                                },
                                "binding",
                                "confirm",
                                "/",
                                Instant::now(),
                                &fail_closed_deny_port(),
                            )
                            .map(|_| ())
                        };
                        match result {
                            Ok(()) => next.run(req).await,
                            Err(refusal) => refusal.into_response(),
                        }
                    },
                ))
                .layer(Extension(compound));
            let response: Response = app
                .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(handler_calls.load(Ordering::SeqCst), 0);
        }
    }

    // memory—v1: Only a pending guard refusal carries the mark that the gateway may trust.
    #[test]
    fn only_pending_guard_refusals_carry_the_pending_mark() {
        use astral_common::middleware::permission_check_shared::AuthorizationPendingRefusal;
        use axum::response::IntoResponse as _;
        let pending = super::memory_v1_refusal(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "Authorization pending",
            "AUTHORIZATION_PENDING",
            "/main/api/v1/example",
        )
        .into_response();
        assert!(AuthorizationPendingRefusal::is_attached(
            pending.extensions()
        ));
        let denied = super::memory_v1_refusal(
            axum::http::StatusCode::FORBIDDEN,
            "Permission denied",
            "AUTHORIZATION_DENIED",
            "/main/api/v1/example",
        )
        .into_response();
        assert!(!AuthorizationPendingRefusal::is_attached(
            denied.extensions()
        ));
    }

    // memory—v1: The middleware adapter preserves candidate scope and always receives pending.
    #[tokio::test]
    async fn candidate_adapter_reaches_formal_engine_without_admission() {
        use astral_authorization_root::memory_v1_db_rows::CandidateRows;
        use astral_authorization_root::memory_v1_hamt::CandidateBudget;
        use astral_authorization_root::memory_v1_request::RequestRootScope;
        use astral_authorization_root::memory_v1_root::install_process_root;
        use policy_engine::PolicyEngine;

        let owner = install_process_root(
            CandidateRows::default(),
            vec![],
            CandidateBudget {
                max_table_rows: 16,
                max_bindings_per_read: 4,
            },
        )
        .unwrap();
        let scope = RequestRootScope::new(owner.handle(), uuid::Uuid::new_v4());
        let extension = scope.extension();
        let ctx = astral_types::PolicyContext::builder()
            .action("read".into())
            .build();
        let engine = PolicyEngine::new();
        let decision = evaluate_candidate_request(&engine, &ctx, extension.clone()).await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
        assert!(decision.audit_required);
        assert_eq!(engine.get_stats().evaluation_count, 1);
        drop(owner);
        let decision = evaluate_candidate_request(&engine, &ctx, extension).await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    }

    // memory—v1: Build two distinct governance rule sets for the target-fence tests.
    fn single_governance_rows() -> (CandidateRows, Vec<CurrentSelection>) {
        use astral_authorization_root::memory_v1_db_rows::RuleSetChangeConfirmationRow;
        use astral_authorization_root::memory_v1_rules::{canonical_version_bytes, version_digest};
        let id = |value| [value; 16];
        let content = br#"{"rules":[{"ruleId":"remove","resource":"binding","action":"remove","effect":"ALLOW","ownerScope":"all"},{"ruleId":"confirm","resource":"binding","action":"confirm","effect":"ALLOW","ownerScope":"all"}]}"#;
        let version = |rule_set_id| {
            let hash_input_bytes = canonical_version_bytes(&[1], content, &[2]);
            RuleSetVersionRow {
                rule_set_id: id(rule_set_id),
                version_bytes: vec![1],
                content_bytes: content.to_vec(),
                timestamp_bytes: vec![2],
                hash_bytes: version_digest(&hash_input_bytes),
                hash_input_bytes,
            }
        };
        let binding = |binding_id, user_card_id, rule_set_id| BindingRow {
            binding_id: id(binding_id),
            user_card_id: id(user_card_id),
            rule_set_id: id(rule_set_id),
            binding_layer: BindingLayer::Base,
            valid_from: None,
            valid_until: None,
            owner_scope: MemoryV1OwnerScope::AllUsers,
            tenant_scope: MemoryV1TenantScope::SelfTenant,
            removed_at: None,
            removed_by: None,
        };
        let confirmation =
            |confirmation_id, binding_id, rule_set_id, confirmer| BindingConfirmationRow {
                confirmation_id: id(confirmation_id),
                binding_id: id(binding_id),
                rule_set_id: id(rule_set_id),
                version_bytes: vec![1],
                confirmer_user_id: id(confirmer),
                scope_bytes: vec![1],
                operation_id: vec![confirmation_id],
                confirmed_at_bytes: vec![1],
                revoked_at: None,
                revoked_by: None,
            };
        let rows = CandidateRows {
            users: vec![UserRow { user_id: id(1) }, UserRow { user_id: id(2) }],
            identity_cards: vec![
                IdentityCardRow {
                    identity_card_id: id(3),
                    user_id: id(1),
                },
                IdentityCardRow {
                    identity_card_id: id(4),
                    user_id: id(2),
                },
            ],
            tenants: vec![TenantRow {
                tenant_id: id(10),
                parent_tenant_id: None,
            }],
            user_cards: vec![
                UserCardRow {
                    user_card_id: id(20),
                    user_id: id(1),
                    tenant_id: id(10),
                    status: UserCardStatus::Active,
                },
                UserCardRow {
                    user_card_id: id(21),
                    user_id: id(2),
                    tenant_id: id(10),
                    status: UserCardStatus::Active,
                },
            ],
            rule_sets: [30, 31]
                .into_iter()
                .map(|n| RuleSetRow {
                    status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
                    rule_set_id: id(n),
                    owner_tenant_id: id(10),
                    current_version_bytes: vec![1],
                })
                .collect(),
            rule_set_versions: vec![version(30), version(31)],
            bindings: vec![binding(40, 20, 30), binding(41, 21, 31)],
            binding_confirmations: vec![confirmation(50, 40, 30, 2), confirmation(51, 41, 31, 1)],
            rule_set_change_confirmations: [30, 31]
                .into_iter()
                .map(|n| RuleSetChangeConfirmationRow {
                    confirmation_id: id(n + 30),
                    rule_set_id: id(n),
                    version_bytes: vec![1],
                    confirmer_user_id: id(2),
                    affected_scope_bytes: vec![1],
                    operation_id: vec![n],
                    confirmed_at_bytes: vec![1],
                    revoked_at: None,
                    revoked_by: None,
                })
                .collect(),
        };
        let selections = [30, 31]
            .into_iter()
            .map(|n| CurrentSelection {
                rule_set_id: id(n),
                version_bytes: vec![1],
            })
            .collect();
        (rows, selections)
    }

    // memory—v1: Build separate in-memory roots for the B-5 route and engine tests.
    fn overlay_route_fixture(
        grant_overlay_only: bool,
    ) -> (
        RootOwner,
        astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority,
    ) {
        use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
        use astral_authorization_root::memory_v1_rules::{canonical_version_bytes, version_digest};
        use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority;

        let id = |value| [value; 16];
        let (mut rows, selections) = single_governance_rows();
        for (card, user) in [(22, 1), (23, 2)] {
            rows.user_cards.push(UserCardRow {
                user_card_id: id(card),
                user_id: id(user),
                tenant_id: id(10),
                status: UserCardStatus::Active,
            });
        }
        let mut rules = vec![
            serde_json::json!({"ruleId": "create", "resource": "binding", "action": "create", "effect": "ALLOW", "ownerScope": "all"}),
            serde_json::json!({"ruleId": "confirm", "resource": "binding", "action": "confirm", "effect": "ALLOW", "ownerScope": "all"}),
        ];
        if grant_overlay_only {
            rules.push(serde_json::json!({"ruleId": "overlay", "resource": "binding", "action": "create-overlay-only", "effect": "ALLOW", "ownerScope": "all"}));
        }
        let version = &mut rows.rule_set_versions[0];
        version.content_bytes = serde_json::json!({"rules": rules}).to_string().into_bytes();
        version.hash_input_bytes = canonical_version_bytes(
            &version.version_bytes,
            &version.content_bytes,
            &version.timestamp_bytes,
        );
        version.hash_bytes = version_digest(&version.hash_input_bytes);
        let owner = install_process_root(
            rows,
            selections,
            CandidateBudget {
                max_table_rows: 128,
                max_bindings_per_read: 16,
            },
        )
        .unwrap();
        owner
            .install_registry(&[RegistryDeclaration {
                resource: "binding".into(),
                actions: vec![
                    "create".into(),
                    "confirm".into(),
                    "create-overlay-only".into(),
                    "remove".into(),
                ],
            }])
            .unwrap();
        owner.adopt_serving_for_isolated_tests().unwrap();
        let authority = MemoryV1SessionAuthority::with_clock_for_test(exact_route_clock);
        authority.bind_to_root(&owner).unwrap();
        (owner, authority)
    }

    // memory—v1: Classify real target cards and verify all same-request B-5 admissions.
    #[test]
    fn overlay_route_compound_admissions_require_matching_authority_and_binding() {
        use astral_types::memory_v1::{CandidateIdentity, MemoryId};
        use axum::body::Bytes;
        use axum::http::Method;
        use axum::response::IntoResponse as _;
        use policy_engine::memory_v1_compound::{
            MemoryV1CompoundRequest, MemoryV1CompoundTargetKind,
        };
        use policy_engine::memory_v1_formal::{
            MemoryV1Decision, MemoryV1DenySource, MemoryV1PendingSource, MemoryV1Request,
        };
        use std::time::{SystemTime, UNIX_EPOCH};

        const CHILD: &str = "ASTRAL_OVERLAY_ROUTE_COMPOUND_CHILD";
        let grant_overlay_only = match std::env::var(CHILD).as_deref() {
            Ok("without-grant") => false,
            Ok("with-grant") => true,
            Ok(_) => panic!("unexpected overlay route child scenario"),
            Err(std::env::VarError::NotPresent) => {
                for scenario in ["without-grant", "with-grant"] {
                    let output = std::process::Command::new(std::env::current_exe().unwrap())
                        .args([
                            "--exact",
                            "api::permission_check::tests::overlay_route_compound_admissions_require_matching_authority_and_binding",
                            "--nocapture",
                        ])
                        .env(CHILD, scenario)
                        .output()
                        .expect("failed to start isolated overlay route test");
                    assert!(
                        output.status.success(),
                        "scenario {scenario}: stdout: {}\nstderr: {}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
                }
                return;
            }
            Err(err) => panic!("invalid overlay route child scenario: {err}"),
        };

        let id = |value| [value; 16];
        let value = |n| MemoryId::from_bytes(id(n)).to_string();
        let path = "/governance/bindings";
        let declaration = super::memory_v1_route_declaration(&Method::POST, path).unwrap();
        assert_eq!(
            (declaration.resource, declaration.action),
            ("binding", "create")
        );
        assert_eq!(
            declaration.additional_actions,
            &["confirm", "create-overlay-only"]
        );

        {
            let (owner, authority) = overlay_route_fixture(grant_overlay_only);
            let scope = RequestRootScope::new(owner.handle(), uuid::Uuid::new_v4());
            let root = scope.extension();
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let identity = CandidateIdentity {
                user_id: MemoryId::from_bytes(id(1)),
                identity_card_id: MemoryId::from_bytes(id(3)),
                user_card_id: MemoryId::from_bytes(id(20)),
                tenant_id: MemoryId::from_bytes(id(10)),
            };
            let issued = authority
                .identity_session_adapter()
                .issue_verified_session_in_root(&root, identity, now - 60, 3600)
                .unwrap();
            let session = authority
                .verifier()
                .verify_and_bind(issued.credential(), now, &root)
                .unwrap();
            let engine = policy_engine::PolicyEngine::new();
            let make_body = |card| {
                Bytes::from(
                    serde_json::json!({
                        "binding_id": value(70),
                        "user_card_id": value(card),
                        "rule_set_id": value(31),
                        "binding_layer": "OVERLAY",
                        "target_owner": value(99),
                        "target_tenant": value(98)
                    })
                    .to_string(),
                )
            };

            // Cards 23 and 22 have no bindings; card 21 has an unremoved BASE.
            for (card, expected_overlay_only, expected_owner) in
                [(23, true, 2), (21, false, 2), (22, true, 1)]
            {
                let body = make_body(card);
                assert_eq!(
                    super::is_overlay_only_request(&root, path, &body),
                    Ok(expected_overlay_only)
                );
                let (target, facts) =
                    super::governance_target_for_request(&root, &Method::POST, path, &body)
                        .unwrap();
                assert_eq!(target, id(70));
                assert_eq!(facts.user_card_id, id(card));
                assert_eq!(facts.rule_set_id, id(31));
                assert_eq!(facts.tenant_id, id(10));
                assert_eq!(facts.owner_user_id, id(expected_owner));
                let request = MemoryV1Request {
                    resource: declaration.resource,
                    action: declaration.action,
                    target: Some(&target),
                    target_tenant: Some(&facts.tenant_id),
                    target_owner: Some(&facts.owner_user_id),
                    operation_id: b"overlay-route-operation",
                    operation_fingerprint: b"overlay-route-fingerprint",
                };
                let names: &[&str] = if expected_overlay_only {
                    &["create", "confirm", "create-overlay-only"]
                } else {
                    &["create", "confirm"]
                };
                let actions =
                    super::governance_compound_actions(declaration, request, facts, names).unwrap();
                assert!(actions.iter().all(|action| {
                    action.target_kind == MemoryV1CompoundTargetKind::BindingCreate
                        && action.target_facts == facts
                        && action.change_intent.is_none()
                }));
                let evaluate = |actions: &[_]| {
                    engine.evaluate_memory_v1_compound(
                        &root,
                        &session,
                        &MemoryV1CompoundRequest { actions },
                    )
                };
                let result = evaluate(&actions);
                if card == 22 {
                    assert_eq!(result.decision, MemoryV1Decision::Deny);
                    assert_eq!(
                        result.deny_source,
                        Some(MemoryV1DenySource::SelfConfirmation)
                    );
                    assert!(result.admissions.is_empty());
                    let expected_observation = result.deny_observation.as_deref().unwrap().clone();
                    assert_eq!(expected_observation.action(), "confirm");
                    let refusal = super::require_memory_v1_compound_admissions(
                        result,
                        "binding",
                        "create",
                        path,
                        std::time::Instant::now(),
                        &fail_closed_deny_port(),
                    )
                    .expect_err("DENY must refuse the handler")
                    .into_response();
                    assert_eq!(
                        refusal.status(),
                        axum::http::StatusCode::SERVICE_UNAVAILABLE
                    );
                    assert_eq!(
                        refusal
                            .extensions()
                            .get::<policy_engine::memory_v1_formal::MemoryV1DenyObservation>(),
                        Some(&expected_observation),
                        "extensions: {:?}; status {}",
                        refusal.extensions().len(),
                        refusal.status(),
                    );
                    let ordinary_request = MemoryV1Request {
                        resource: "not-registered",
                        action: "read",
                        ..request
                    };
                    let ordinary = engine.evaluate_memory_v1(&root, &session, &ordinary_request);
                    let expected = ordinary.deny_observation.as_deref().unwrap().clone();
                    let refusal = super::require_memory_v1_admission(
                        ordinary,
                        "not-registered",
                        "read",
                        path,
                        std::time::Instant::now(),
                        &fail_closed_deny_port(),
                    )
                    .expect_err("ordinary DENY must refuse the handler")
                    .into_response();
                    assert_eq!(
                        refusal.status(),
                        axum::http::StatusCode::SERVICE_UNAVAILABLE
                    );
                    assert_eq!(
                        refusal
                            .extensions()
                            .get::<policy_engine::memory_v1_formal::MemoryV1DenyObservation>(),
                        Some(&expected),
                    );
                    let batch_items = [policy_engine::memory_v1_batch::MemoryV1BatchItem {
                        sequence: 0,
                        binding_id: id(40),
                        confirmation_id: id(80),
                    }];
                    let batch = engine.evaluate_memory_v1_confirmation_batch(
                        &root,
                        &session,
                        &policy_engine::memory_v1_batch::MemoryV1BatchRequest {
                            operation_id: b"route-batch-test",
                            operation_fingerprint:
                                b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                            items: &batch_items,
                        },
                    );
                    assert_eq!(batch.decision, MemoryV1Decision::Deny);
                    let expected = batch.deny_observation.as_deref().unwrap().clone();
                    let policy_engine::memory_v1_batch::MemoryV1BatchEvaluation {
                        decision,
                        deny_source,
                        pending_source,
                        deny_observation,
                        ..
                    } = batch;
                    let converted = policy_engine::memory_v1_formal::MemoryV1Evaluation {
                        decision,
                        deny_source,
                        pending_source,
                        admission: None,
                        deny_observation,
                    };
                    let refusal = super::require_memory_v1_admission(
                        converted,
                        "binding",
                        "confirm",
                        path,
                        std::time::Instant::now(),
                        &fail_closed_deny_port(),
                    )
                    .expect_err("batch DENY must refuse the handler")
                    .into_response();
                    assert_eq!(
                        refusal.status(),
                        axum::http::StatusCode::SERVICE_UNAVAILABLE
                    );
                    assert_eq!(
                        refusal
                            .extensions()
                            .get::<policy_engine::memory_v1_formal::MemoryV1DenyObservation>(),
                        Some(&expected),
                    );
                    // Confirm and create-overlay-only must each reject self-authorization.
                    for action in &actions[1..] {
                        let rejected = evaluate(std::slice::from_ref(action));
                        assert_eq!(rejected.decision, MemoryV1Decision::Deny);
                        assert_eq!(
                            rejected.deny_source,
                            Some(MemoryV1DenySource::SelfConfirmation)
                        );
                        assert!(rejected.admissions.is_empty());
                    }
                } else if expected_overlay_only && !grant_overlay_only {
                    let ordinary = evaluate(&actions[..2]);
                    assert_eq!(ordinary.decision, MemoryV1Decision::Allow);
                    assert_eq!(ordinary.admissions.len(), 2);
                    let extra = evaluate(&actions[2..]);
                    assert_eq!(extra.decision, MemoryV1Decision::Deny);
                    assert_eq!(extra.deny_source, Some(MemoryV1DenySource::NoMatch));
                    assert!(extra.admissions.is_empty());
                    assert_eq!(result.decision, MemoryV1Decision::Deny);
                    assert_eq!(result.deny_source, Some(MemoryV1DenySource::NoMatch));
                    assert!(result.admissions.is_empty());
                } else {
                    assert_eq!(result.decision, MemoryV1Decision::Allow);
                    assert_eq!(result.admissions.len(), names.len());
                    for (admission, name) in result.admissions.iter().zip(names.iter()) {
                        assert_eq!(admission.resource(), "binding");
                        assert_eq!(admission.action(), *name);
                        assert_eq!(admission.root(), owner.handle().metadata().unwrap());
                        assert_eq!(admission.identity(), identity);
                        assert_eq!(admission.target(), Some(target.as_slice()));
                        assert_eq!(admission.target_tenant(), Some(facts.tenant_id.as_slice()));
                        assert_eq!(
                            admission.target_owner(),
                            Some(facts.owner_user_id.as_slice())
                        );
                        assert_eq!(admission.operation_id(), request.operation_id);
                        assert_eq!(
                            admission.operation_fingerprint(),
                            request.operation_fingerprint
                        );
                        assert_eq!(
                            admission.trusted_time_unix_seconds(),
                            result.admissions[0].trusted_time_unix_seconds()
                        );
                    }
                    if expected_overlay_only {
                        for mismatch in 0..7 {
                            let mut changed = actions.clone();
                            match mismatch {
                                0 => changed[1].request.target = Some(&[71; 16]),
                                1 => changed[1].request.target_tenant = Some(&[11; 16]),
                                2 => changed[1].request.target_owner = Some(&[3; 16]),
                                3 => changed[1].request.operation_id = b"another-operation",
                                4 => {
                                    changed[1].request.operation_fingerprint =
                                        b"another-fingerprint"
                                }
                                5 => changed[1].target_facts.rule_set_id = id(30),
                                _ => changed[1].target_kind = MemoryV1CompoundTargetKind::Existing,
                            }
                            let rejected = evaluate(&changed);
                            assert_eq!(rejected.decision, MemoryV1Decision::Pending);
                            assert_eq!(
                                rejected.pending_source,
                                Some(MemoryV1PendingSource::ContextInvalid)
                            );
                            assert!(rejected.admissions.is_empty());
                        }
                        let foreign_scope =
                            RequestRootScope::new(owner.handle(), uuid::Uuid::new_v4());
                        let foreign_root = foreign_scope.extension();
                        assert!(!session.is_bound_to(&foreign_root));
                        let rejected = engine.evaluate_memory_v1_compound(
                            &foreign_root,
                            &session,
                            &MemoryV1CompoundRequest { actions: &actions },
                        );
                        assert_eq!(rejected.decision, MemoryV1Decision::Pending);
                        assert!(rejected.admissions.is_empty());
                        assert!(rejected.deny_observation.is_none());
                    }
                }
            }
        }
    }

    // memory—v1: Single-action governance must use the target-aware final check.
    #[test]
    fn governance_single_action_checks_target_fence_and_root() {
        use astral_authorization_root::memory_v1_fence::FenceDeclaration;
        use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
        use astral_authorization_root::memory_v1_root::{
            ManagementMutationV2, MutationPrecondition,
        };
        use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority;
        use astral_types::memory_v1::{CandidateIdentity, MemoryId};
        use policy_engine::memory_v1_compound::MemoryV1CompoundRequest;
        use policy_engine::memory_v1_formal::{MemoryV1Decision, MemoryV1Request};
        use std::time::{SystemTime, UNIX_EPOCH};

        if run_isolated_child(
            "api::permission_check::tests::governance_single_action_checks_target_fence_and_root",
            "ASTRAL_SINGLE_GOVERNANCE_FENCE_CHILD",
        ) {
            return;
        }
        let id = |value| [value; 16];
        let (rows, selections) = single_governance_rows();
        let owner = install_process_root(
            rows,
            selections,
            CandidateBudget {
                max_table_rows: 128,
                max_bindings_per_read: 16,
            },
        )
        .unwrap();
        owner
            .install_registry(&[RegistryDeclaration {
                resource: "binding".into(),
                actions: vec!["remove".into(), "confirm".into()],
            }])
            .unwrap();
        owner.adopt_serving_for_isolated_tests().unwrap();
        let authority = MemoryV1SessionAuthority::with_clock_for_test(exact_route_clock);
        authority.bind_to_root(&owner).unwrap();
        let scope = RequestRootScope::new(owner.handle(), uuid::Uuid::new_v4());
        let root = scope.extension();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let identity = CandidateIdentity {
            user_id: MemoryId::from_bytes(id(1)),
            identity_card_id: MemoryId::from_bytes(id(3)),
            user_card_id: MemoryId::from_bytes(id(20)),
            tenant_id: MemoryId::from_bytes(id(10)),
        };
        let issued = authority
            .identity_session_adapter()
            .issue_verified_session_in_root(&root, identity, now - 60, 3600)
            .unwrap();
        let session = authority
            .verifier()
            .verify_and_bind(issued.credential(), now, &root)
            .unwrap();
        let facts = root
            .with_reader(|reader| reader.binding_target(id(41)))
            .unwrap()
            .unwrap();
        let declaration =
            super::memory_v1_route_declaration(&axum::http::Method::DELETE, "/governance/bindings")
                .unwrap();
        let target = id(41);
        let tenant = id(10);
        let beneficiary = id(2);
        let request = MemoryV1Request {
            resource: "binding",
            action: "remove",
            target: Some(&target),
            target_tenant: Some(&tenant),
            target_owner: Some(&beneficiary),
            operation_id: b"single-governance",
            operation_fingerprint: b"single-governance-fingerprint",
        };
        let actions =
            super::governance_compound_actions(declaration, request, facts, &["remove"]).unwrap();
        let engine = policy_engine::PolicyEngine::new();
        let evaluate = || {
            engine.evaluate_memory_v1_compound(
                &root,
                &session,
                &MemoryV1CompoundRequest { actions: &actions },
            )
        };
        let baseline = evaluate();
        assert_eq!(baseline.decision, MemoryV1Decision::Allow);
        assert_eq!(baseline.admissions.len(), 1);
        assert_eq!(baseline.admissions[0].action(), "remove");
        let metadata = owner.handle().metadata().unwrap();
        owner
            .begin_modification_fence(
                id(31),
                &FenceDeclaration {
                    rule_set_version: vec![1],
                    root_version: metadata.version,
                    digest: metadata.digest,
                },
            )
            .unwrap();
        let fenced = evaluate();
        assert_eq!(fenced.decision, MemoryV1Decision::Pending);
        assert!(fenced.admissions.is_empty());
        owner.abort_modification_fence(id(31)).unwrap();
        let metadata = owner.handle().metadata().unwrap();
        owner
            .execute_mutation_with_precondition_for_isolated_tests(
                &ManagementMutationV2::BindingRemove {
                    binding_id: id(41),
                    removed_at: now,
                    removed_by: id(1),
                },
                &MutationPrecondition {
                    evaluated_root_version: metadata.version,
                },
            )
            .unwrap();
        let stale = evaluate();
        assert_eq!(stale.decision, MemoryV1Decision::Pending);
        assert!(stale.admissions.is_empty());
    }

    // memory—v1: A middleware request must distinguish the target's fence from
    // an unrelated fence, while handing the bound admission only to the handler.
    #[test]
    fn single_governance_middleware_checks_target_fence() {
        use astral_authorization_root::memory_v1_fence::FenceDeclaration;
        use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
        use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority;
        use astral_common::config::AppConfig;
        use astral_common::middleware::gateway_signature::{
            compute_hmac_signature_v3, in_process_gateway_signature_middleware,
            in_process_gateway_source,
        };
        use astral_types::memory_v1::{CandidateIdentity, MemoryId};
        use axum::body::{to_bytes, Body};
        use axum::http::StatusCode;
        use axum::middleware;
        use axum::routing::delete;
        use axum::Router;
        use policy_engine::memory_v1_formal::MemoryV1Admission;
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        use std::time::{SystemTime, UNIX_EPOCH};
        use tower::ServiceExt;

        if run_isolated_child(
            "api::permission_check::tests::single_governance_middleware_checks_target_fence",
            "ASTRAL_SINGLE_GOVERNANCE_MIDDLEWARE_CHILD",
        ) {
            return;
        }
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let id = |n| [n; 16];
                let (mut rows, mut selections) = single_governance_rows();
                let mut unrelated = rows.rule_sets[1].clone();
                unrelated.rule_set_id = id(32);
                rows.rule_sets.push(unrelated);
                let mut version = rows.rule_set_versions[1].clone();
                version.rule_set_id = id(32);
                rows.rule_set_versions.push(version);
                let mut confirmation = rows.rule_set_change_confirmations[1].clone();
                confirmation.confirmation_id = id(62);
                confirmation.rule_set_id = id(32);
                rows.rule_set_change_confirmations.push(confirmation);
                selections.push(CurrentSelection {
                    rule_set_id: id(32),
                    version_bytes: vec![1],
                });
                let owner = install_process_root(
                    rows,
                    selections,
                    CandidateBudget {
                        max_table_rows: 128,
                        max_bindings_per_read: 16,
                    },
                )
                .unwrap();
                owner
                    .install_registry(&[RegistryDeclaration {
                        resource: "binding".into(),
                        actions: vec!["remove".into(), "confirm".into()],
                    }])
                    .unwrap();
                owner.adopt_serving_for_isolated_tests().unwrap();
                let authority = MemoryV1SessionAuthority::with_clock_for_test(exact_route_clock);
                authority.bind_to_root(&owner).unwrap();
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
                let identity = CandidateIdentity {
                    user_id: MemoryId::from_bytes(id(1)),
                    identity_card_id: MemoryId::from_bytes(id(3)),
                    user_card_id: MemoryId::from_bytes(id(20)),
                    tenant_id: MemoryId::from_bytes(id(10)),
                };
                let scope = RequestRootScope::new(owner.handle(), uuid::Uuid::new_v4());
                let root = scope.extension();
                let issued = authority
                    .identity_session_adapter()
                    .issue_verified_session_in_root(
                        &root,
                        identity,
                        now.as_secs() as i64 - 60,
                        3600,
                    )
                    .unwrap();
                let mut config = AppConfig::default();
                config.gateway.hmac_secret = "isolated-test-secret".into();
                let state = crate::memory_v1_state::build_memory_v1_offline_app_state(
                    config.clone(),
                    Arc::new(policy_engine::PolicyEngine::new()),
                );
                let (issuer, verifier) = in_process_gateway_source();
                let calls = Arc::new(AtomicUsize::new(0));
                let handler_calls = Arc::clone(&calls);
                let app = Router::new()
                    .route(
                        "/governance/bindings",
                        delete(move |request: Request| {
                            let calls = Arc::clone(&handler_calls);
                            async move {
                                let admission =
                                    request.extensions().get::<MemoryV1Admission>().unwrap();
                                let bound =
                                    request.extensions().get::<MemoryV1BoundRequest>().unwrap();
                                assert_eq!(
                                    (admission.resource(), admission.action()),
                                    ("binding", "remove")
                                );
                                assert_eq!(admission.target(), Some(id(41).as_slice()));
                                assert_eq!(admission.target_tenant(), Some(id(10).as_slice()));
                                assert_eq!(admission.target_owner(), Some(id(2).as_slice()));
                                assert_eq!(admission.operation_id(), bound.operation_id.as_bytes());
                                assert_eq!(
                                    admission.operation_fingerprint(),
                                    bound.fingerprint.as_bytes()
                                );
                                assert!(request
                                    .extensions()
                                    .get::<super::MemoryV1AdditionalAdmissions>()
                                    .unwrap()
                                    .0
                                    .is_empty());
                                calls.fetch_add(1, Ordering::SeqCst);
                                StatusCode::NO_CONTENT
                            }
                        }),
                    )
                    .layer(middleware::from_fn_with_state(
                        state,
                        super::permission_check_middleware,
                    ))
                    .layer(middleware::from_fn_with_state(
                        (config, verifier),
                        in_process_gateway_signature_middleware,
                    ));
                let path = "/governance/bindings";
                let send = |root: &RequestRootExtension| {
                    let session = authority
                        .verifier()
                        .verify_and_bind(issued.credential(), now.as_secs() as i64, root)
                        .unwrap();
                    let timestamp = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis()
                        .to_string();
                    let signature = compute_hmac_signature_v3(
                        "isolated-test-secret",
                        "DELETE",
                        path,
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        &timestamp,
                    );
                    let body =
                        serde_json::json!({"binding_id": MemoryId::from_bytes(id(41)).to_string()})
                            .to_string();
                    let mut request = axum::http::Request::builder()
                        .method("DELETE")
                        .uri(path)
                        .header("x-gateway-auth", "verified")
                        .header("x-gateway-ts", timestamp)
                        .header("x-gateway-signature", signature)
                        .header("x-original-path", path)
                        .header("x-request-id", "single-governance-middleware-test")
                        .body(Body::from(body))
                        .unwrap();
                    request.extensions_mut().insert(root.clone());
                    request.extensions_mut().insert(session.clone());
                    issuer.mark_memory_v1_session(&mut request);
                    app.clone().oneshot(request)
                };
                let metadata = owner.handle().metadata().unwrap();
                let declaration = FenceDeclaration {
                    rule_set_version: vec![1],
                    root_version: metadata.version,
                    digest: metadata.digest,
                };
                owner
                    .begin_modification_fence(id(32), &declaration)
                    .unwrap();
                assert_eq!(send(&root).await.unwrap().status(), StatusCode::NO_CONTENT);
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                owner.abort_modification_fence(id(32)).unwrap();
                owner
                    .begin_modification_fence(id(31), &declaration)
                    .unwrap();
                let response = send(&root).await.unwrap();
                assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
                let body = to_bytes(response.into_body(), 4096).await.unwrap();
                let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(body["reasonCode"], "AUTHORIZATION_PENDING");
                assert_eq!(body["decision"], "AUTHORIZATION_PENDING");
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                owner.abort_modification_fence(id(31)).unwrap();
                assert_eq!(
                    send(&root).await.unwrap().status(),
                    StatusCode::SERVICE_UNAVAILABLE
                );
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                let fresh = RequestRootScope::new(owner.handle(), uuid::Uuid::new_v4());
                assert_eq!(
                    send(&fresh.extension()).await.unwrap().status(),
                    StatusCode::NO_CONTENT
                );
                assert_eq!(calls.load(Ordering::SeqCst), 2);
            });
    }

    // memory—v1: Middleware and the mounted handler share the configured batch limit.
    #[test]
    fn confirmation_batch_middleware_and_handler_share_operational_limit() {
        use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
        use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority;
        use astral_common::config::{AppConfig, MemoryV1ConfirmationBatchLimit};
        use astral_common::middleware::gateway_signature::{
            compute_hmac_signature_v3, in_process_gateway_signature_middleware,
            in_process_gateway_source,
        };
        use astral_types::memory_v1::{CandidateIdentity, MemoryId};
        use axum::body::Body;
        use axum::http::StatusCode;
        use axum::middleware;
        use policy_engine::memory_v1_batch::MemoryV1BatchAdmission;
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        use std::time::{SystemTime, UNIX_EPOCH};
        use tower::ServiceExt;

        if run_isolated_child(
            "api::permission_check::tests::confirmation_batch_middleware_and_handler_share_operational_limit",
            "ASTRAL_CONFIRMATION_BATCH_LIMIT_MIDDLEWARE_CHILD",
        ) {
            return;
        }
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let id = |n| [n; 16];
                let (mut rows, mut selections) = single_governance_rows();
                rows.binding_confirmations[1].revoked_at = Some(1);
                rows.binding_confirmations[1].revoked_by = Some(id(1));
                let mut second_rule_set = rows.rule_sets[1].clone();
                second_rule_set.rule_set_id = id(32);
                rows.rule_sets.push(second_rule_set);
                let mut second_version = rows.rule_set_versions[1].clone();
                second_version.rule_set_id = id(32);
                rows.rule_set_versions.push(second_version);
                let mut second_change = rows.rule_set_change_confirmations[1].clone();
                second_change.confirmation_id = id(62);
                second_change.rule_set_id = id(32);
                rows.rule_set_change_confirmations.push(second_change);
                selections.push(CurrentSelection {
                    rule_set_id: id(32),
                    version_bytes: vec![1],
                });
                let mut second = rows.bindings[1].clone();
                second.binding_id = id(42);
                second.rule_set_id = id(32);
                second.binding_layer = BindingLayer::Overlay;
                rows.bindings.push(second);
                let mut second_confirmation = rows.binding_confirmations[1].clone();
                second_confirmation.confirmation_id = id(52);
                second_confirmation.binding_id = id(42);
                second_confirmation.rule_set_id = id(32);
                rows.binding_confirmations.push(second_confirmation);
                let owner = install_process_root(
                    rows,
                    selections,
                    CandidateBudget { max_table_rows: 128, max_bindings_per_read: 16 },
                )
                .unwrap();
                owner
                    .install_registry(&[RegistryDeclaration {
                        resource: "binding".into(),
                        actions: vec!["remove".into(), "confirm".into()],
                    }])
                    .unwrap();
                owner.adopt_serving_for_isolated_tests().unwrap();
                let authority = MemoryV1SessionAuthority::with_clock_for_test(exact_route_clock);
                authority.bind_to_root(&owner).unwrap();
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
                let scope = RequestRootScope::new(owner.handle(), uuid::Uuid::new_v4());
                let root = scope.extension();
                let issued = authority
                    .identity_session_adapter()
                    .issue_verified_session_in_root(
                        &root,
                        CandidateIdentity {
                            user_id: MemoryId::from_bytes(id(1)),
                            identity_card_id: MemoryId::from_bytes(id(3)),
                            user_card_id: MemoryId::from_bytes(id(20)),
                            tenant_id: MemoryId::from_bytes(id(10)),
                        },
                        now.as_secs() as i64 - 60,
                        3600,
                    )
                    .unwrap();
                let session = authority
                    .verifier()
                    .verify_and_bind(issued.credential(), now.as_secs() as i64, &root)
                    .unwrap();
                let mut config = AppConfig::default();
                config.gateway.hmac_secret = "isolated-test-secret".into();
                let (issuer, verifier) = in_process_gateway_source();
                let calls = Arc::new(AtomicUsize::new(0));
                let make_app = |limit, handler_limit| {
                    let mut config = config.clone();
                    config.memory_v1_confirmation_batch_limit =
                        MemoryV1ConfirmationBatchLimit::new(limit).unwrap();
                    let state = crate::memory_v1_state::build_memory_v1_offline_app_state(
                        config.clone(),
                        Arc::new(policy_engine::PolicyEngine::new()),
                    );
                    let mut handler_state = state.clone();
                    let mut handler_config = config.clone();
                    handler_config.memory_v1_confirmation_batch_limit =
                        MemoryV1ConfirmationBatchLimit::new(handler_limit).unwrap();
                    handler_state.config = Arc::new(handler_config);
                    let marker_calls = Arc::clone(&calls);
                    axum::Router::new()
                        .merge(crate::api::governance_routes::governance_routes())
                        .layer(middleware::from_fn(move |req: Request, next: axum::middleware::Next| {
                            let calls = Arc::clone(&marker_calls);
                            async move {
                                assert_eq!(req.extensions().get::<MemoryV1BatchAdmission>().unwrap().targets().len(), 2);
                                calls.fetch_add(1, Ordering::SeqCst);
                                next.run(req).await
                            }
                        }))
                        .layer(middleware::from_fn_with_state(state.clone(), super::permission_check_middleware))
                        .layer(middleware::from_fn_with_state((config, verifier.clone()), in_process_gateway_signature_middleware))
                        .with_state(handler_state)
                };
                let path = "/governance/bindings/confirm/batch";
                let send = |app: axum::Router| {
                    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis().to_string();
                    let signature = compute_hmac_signature_v3(
                        "isolated-test-secret", "POST", path, "", "", "", "", "", "", "", "", "", "", "", &timestamp,
                    );
                    let body = serde_json::json!({"items": [
                        {"sequence": 0, "binding_id": MemoryId::from_bytes(id(41)).to_string(), "confirmation_id": MemoryId::from_bytes(id(70)).to_string(), "rule_set_id": MemoryId::from_bytes(id(31)).to_string(), "scope": "scope"},
                        {"sequence": 1, "binding_id": MemoryId::from_bytes(id(42)).to_string(), "confirmation_id": MemoryId::from_bytes(id(71)).to_string(), "rule_set_id": MemoryId::from_bytes(id(32)).to_string(), "scope": "scope"}
                    ]}).to_string();
                    let mut request = axum::http::Request::builder()
                        .method("POST").uri(path)
                        .header("x-gateway-auth", "verified")
                        .header("x-gateway-ts", timestamp)
                        .header("x-gateway-signature", signature)
                        .header("x-original-path", path)
                        .header("x-request-id", "batch-limit-middleware-test")
                        .body(Body::from(body)).unwrap();
                    request.extensions_mut().insert(root.clone());
                    request.extensions_mut().insert(session.clone());
                    issuer.mark_memory_v1_session(&mut request);
                    app.oneshot(request)
                };
                let before = owner.handle().metadata().unwrap();
                assert_eq!(send(make_app(1, 1)).await.unwrap().status(), StatusCode::BAD_REQUEST);
                assert_eq!(calls.load(Ordering::SeqCst), 0);
                assert_eq!(send(make_app(2, 1)).await.unwrap().status(), StatusCode::BAD_REQUEST);
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                assert_eq!(send(make_app(2, 2)).await.unwrap().status(), StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(calls.load(Ordering::SeqCst), 2);
                assert_eq!(owner.handle().metadata().unwrap(), before);
            });
    }

    #[test]
    fn governance_target_comes_from_root_and_ignores_client_attribution() {
        use astral_authorization_root::memory_v1_db_rows::{
            CandidateRows, IdentityCardRow, RuleSetRow, RuleSetVersionRow, TenantRow, UserCardRow,
            UserCardStatus, UserRow,
        };
        use astral_authorization_root::memory_v1_hamt::CandidateBudget;
        use astral_authorization_root::memory_v1_request::RequestRootScope;
        use astral_authorization_root::memory_v1_root::install_process_root;
        use astral_types::memory_v1::MemoryId;
        use axum::body::Bytes;
        use axum::http::{Method, StatusCode};

        const CHILD: &str = "ASTRAL_MEMORY_V1_GOVERNANCE_TARGET_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "api::permission_check::tests::governance_target_comes_from_root_and_ignores_client_attribution",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "stdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
            return;
        }
        let rows = CandidateRows {
            users: vec![UserRow { user_id: [1; 16] }],
            identity_cards: vec![IdentityCardRow {
                identity_card_id: [2; 16],
                user_id: [1; 16],
            }],
            tenants: vec![TenantRow {
                tenant_id: [3; 16],
                parent_tenant_id: None,
            }],
            user_cards: vec![UserCardRow {
                user_card_id: [4; 16],
                user_id: [1; 16],
                tenant_id: [3; 16],
                status: UserCardStatus::Active,
            }],
            rule_sets: vec![RuleSetRow {
                status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
                rule_set_id: [5; 16],
                owner_tenant_id: [3; 16],
                current_version_bytes: vec![1],
            }],
            rule_set_versions: vec![RuleSetVersionRow {
                rule_set_id: [5; 16],
                version_bytes: vec![1],
                content_bytes: vec![1],
                timestamp_bytes: vec![1],
                hash_input_bytes: vec![1],
                hash_bytes: vec![1],
            }],
            ..CandidateRows::default()
        };
        let owner = install_process_root(
            rows,
            vec![
                astral_authorization_root::memory_v1_db_rows::CurrentSelection {
                    rule_set_id: [5; 16],
                    version_bytes: vec![1],
                },
            ],
            CandidateBudget {
                max_table_rows: 16,
                max_bindings_per_read: 4,
            },
        )
        .unwrap();
        let scope = RequestRootScope::new(owner.handle(), uuid::Uuid::new_v4());
        let root = scope.extension();
        let value = |id| MemoryId::from_bytes([id; 16]).to_string();
        let body = Bytes::from(
            serde_json::json!({
                "binding_id": value(6),
                "user_card_id": value(4),
                "rule_set_id": value(5),
                "binding_layer": "OVERLAY",
                "target_owner": value(99),
                "target_tenant": value(98),
                "owner_scope": "all",
                "tenant_scope": "self+descendants"
            })
            .to_string(),
        );
        let (target, facts) = super::governance_target_for_request(
            &root,
            &Method::POST,
            "/governance/bindings",
            &body,
        )
        .unwrap();
        assert_eq!(target, [6; 16]);
        assert_eq!(facts.owner_user_id, [1; 16]);
        assert_eq!(facts.tenant_id, [3; 16]);
        assert_eq!(
            super::is_overlay_only_request(&root, "/governance/bindings", &body),
            Ok(true)
        );
        let base = Bytes::from(serde_json::json!({"binding_layer": "BASE"}).to_string());
        assert_eq!(
            super::is_overlay_only_request(&root, "/governance/bindings", &base),
            Ok(false)
        );
        let missing = Bytes::from(
            serde_json::json!({
                "binding_id": value(6),
                "user_card_id": value(99),
                "rule_set_id": value(5),
                "target_owner": value(1),
                "target_tenant": value(3)
            })
            .to_string(),
        );
        assert_eq!(
            super::governance_target_for_request(
                &root,
                &Method::POST,
                "/governance/bindings",
                &missing,
            )
            .err(),
            Some(StatusCode::SERVICE_UNAVAILABLE)
        );
    }

    #[test]
    fn post_reservation_gate_rechecks_and_aborts_before_handler() {
        let source = include_str!("permission_check.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let gate = production.find(".ensure_mutation_commit_fence()").unwrap();
        let reservation = production
            .find(".reserve_mutation_with_abort(&ctx, admission)")
            .unwrap();
        assert!(gate < reservation);
        let handler = production[reservation..]
            .find("next.run(req).await")
            .unwrap()
            + reservation;
        let window = &production[reservation..handler];
        let token = window.find("read_request.ensure_current()").unwrap();
        let fence = window.find("authority_fence_matches(fence)").unwrap();
        let abort = window
            .find("abort_source_reservation_and_record(provider, abort")
            .unwrap();
        let denial = window[abort..].find("return Err(").unwrap() + abort;
        let admitted = window
            .find("AuthorizationAdmissionOutcome::Admitted")
            .unwrap();
        assert!(token < abort && fence < abort && abort < denial && denial < admitted);
        assert!(!window.contains("begin_request("));
    }

    #[test]
    fn business_mutation_classification_requires_an_exact_trusted_route() {
        use astral_types::AuthorityMutationKind::ProtectedBusiness;
        for (resource, path) in [
            ("platform_tenant", "/tenants/17/purchases"),
            ("domain", "/user-cards/23/bind/async"),
        ] {
            assert_eq!(
                super::request_mutation_kind(resource, path, "POST"),
                Some(ProtectedBusiness)
            );
            assert_eq!(super::request_mutation_kind(resource, path, "PUT"), None);
        }
        for (resource, path) in [
            ("platform_tenant", "/tenants"),
            ("platform_tenant", "/tenants/17"),
            ("platform_tenant", "/tenants/0/purchases"),
            ("platform_tenant", "/tenants/-1/purchases"),
            ("platform_tenant", "/tenants/17/purchases/extra"),
            ("platform_tenant", "/tenants/17/domains"),
            ("domain", "/user-cards/23/bind"),
            ("domain", "/user-cards/23/bind/async/extra"),
            ("permission_rule", "/tenants/17/purchases"),
        ] {
            assert_eq!(super::request_mutation_kind(resource, path, "POST"), None);
        }
    }

    #[test]
    fn approval_workflow_business_kind_and_target_require_exact_routes() {
        use astral_types::AuthorityMutationKind::ProtectedBusiness;
        for path in [
            "/permission-requests",
            "/permission-requests/17/cancel",
            "/permission-requests/17/reject",
        ] {
            assert_eq!(
                super::request_mutation_kind("permission_request", path, "POST"),
                Some(ProtectedBusiness)
            );
        }
        for path in [
            "/permission-requests/17/approve",
            "/permission-requests/017/cancel",
            "/permission-requests/0/reject",
            "/permission-requests/17/reject/extra",
            "/permission-requests/17/",
        ] {
            assert_eq!(
                super::request_mutation_kind("permission_request", path, "POST"),
                None
            );
        }
        let request = |query: &str| {
            Request::builder()
                .uri(format!("/permission-requests/17/reject{query}"))
                .body(axum::body::Body::empty())
                .unwrap()
        };
        for query in ["", "?id=17", "?id=17&target_id=17"] {
            assert_eq!(
                super::trustgraph_request_target_id(
                    &request(query),
                    "permission_request",
                    "/permission-requests/17/reject",
                    "POST"
                ),
                Ok(Some(17))
            );
        }
        for query in ["?id=18", "?id=17&id=18", "?id=017", "?target_id=abc", "?id"] {
            assert_eq!(
                super::trustgraph_request_target_id(
                    &request(query),
                    "permission_request",
                    "/permission-requests/17/reject",
                    "POST"
                ),
                Err(axum::http::StatusCode::BAD_REQUEST)
            );
        }
        assert_eq!(
            super::request_mutation_kind(
                "permission_request",
                "/permission-requests/17/reject",
                "PUT"
            ),
            None
        );
    }

    #[test]
    fn package_business_mutations_require_registered_exact_routes() {
        use astral_types::AuthorityMutationKind::ProtectedBusiness;
        for (path, method) in [
            ("/platform-packages", "POST"),
            ("/platform-packages/17", "PUT"),
            ("/platform-packages/17", "DELETE"),
        ] {
            assert_eq!(
                super::request_mutation_kind("platform_package", path, method),
                Some(ProtectedBusiness)
            );
        }
        for (path, method) in [
            ("/platform-packages", "GET"),
            ("/platform-packages", "PUT"),
            ("/platform-packages/17", "POST"),
            ("/platform-packages/17", "PATCH"),
            ("/platform-packages/0", "PUT"),
            ("/platform-packages/-1", "DELETE"),
            ("/platform-packages/017", "PUT"),
            ("/platform-packages/17/extra", "DELETE"),
            ("/platform-packages/17/", "PUT"),
        ] {
            assert_eq!(
                super::request_mutation_kind("platform_package", path, method),
                None
            );
        }
        assert_eq!(
            super::request_mutation_kind("permission_rule", "/platform-packages", "POST"),
            None
        );
    }

    #[test]
    fn operation_poll_requires_original_requester_and_exact_authorization_anchor() {
        use crate::api::async_tracker::{OperationItemScope, OperationScope, TaskStatus};
        let context = astral_types::PolicyContext::builder()
            .action("update".into())
            .user_id(Some(1))
            .card_id(Some(2))
            .tenant_id(Some(3))
            .domain_id(Some(4))
            .build();
        let scope = OperationScope {
            task_id: "uc_bind:task".into(),
            task_type: "CARD_BIND".into(),
            status: TaskStatus::InDoubt,
            requester_user_id: 1,
            requester_card_id: 2,
            requester_tenant_id: 3,
            requester_domain_id: 4,
            authorization_target_card_id: 5,
            authorization_target_tenant_id: 6,
            authorization_target_domain_id: 7,
            target_user_id: 8,
            items: vec![OperationItemScope {
                card_id: 5,
                tenant_id: 6,
                domain_id: 7,
                status: "IN_DOUBT".into(),
                operation_id: "batch-bind:item".into(),
                error_message: None,
            }],
            total_items: 1,
            completed_items: 0,
            error_message: None,
            created_at: 1,
            updated_at: 2,
        };
        assert!(super::operation_poll_scope_matches(&context, &scope));
        for changed in [
            astral_types::PolicyContext {
                user_id: Some(9),
                ..context.clone()
            },
            astral_types::PolicyContext {
                card_id: Some(9),
                ..context.clone()
            },
            astral_types::PolicyContext {
                tenant_id: Some(9),
                ..context.clone()
            },
            astral_types::PolicyContext {
                domain_id: Some(9),
                ..context.clone()
            },
        ] {
            assert!(!super::operation_poll_scope_matches(&changed, &scope));
        }
        let mut changed = scope.clone();
        changed.items[0].tenant_id += 1;
        assert!(!super::operation_poll_scope_matches(&context, &changed));
        changed = scope.clone();
        changed.items[0].domain_id += 1;
        assert!(!super::operation_poll_scope_matches(&context, &changed));
        changed = scope.clone();
        changed.authorization_target_card_id += 1;
        assert!(!super::operation_poll_scope_matches(&context, &changed));
        changed = scope;
        changed.task_type = "OTHER".into();
        assert!(!super::operation_poll_scope_matches(&context, &changed));
    }

    #[test]
    fn canonical_domain_paths_resolve_resource_and_action() {
        let cases = [
            ("/audit-quarantine", "audit_quarantine", "GET", "read"),
            (
                "/audit-quarantine/7/replay",
                "audit_quarantine",
                "POST",
                "replay",
            ),
            ("/stats", "monitor", "GET", "read"),
            ("/stats/projector", "monitor", "GET", "read"),
            ("/domains", "domain", "GET", "read"),
            (
                "/resource-types/scan",
                "domain_resource_type",
                "POST",
                "scan",
            ),
            ("/actions/scan/async", "permission_action", "POST", "scan"),
            ("/user-levels/7", "domain", "GET", "read"),
            ("/user-gradings", "domain", "POST", "update"),
            (
                "/level-templates/precheck",
                "permission_rule",
                "POST",
                "read",
            ),
            ("/user-cards/7/bind", "domain", "POST", "update"),
            ("/operations/uc_bind_1", "domain", "GET", "update"),
            ("/card-templates/5/rules/batch", "domain", "POST", "create"),
        ];

        for (path, expected_resource, method, expected_action) in cases {
            let resource = resource_for_path(path).expect("canonical path must be mapped");
            assert_eq!(resource, expected_resource, "resource for {path}");
            assert_eq!(
                resolve_trustgraph_permission_action(resource, path, method),
                Some(expected_action),
                "action for {path}"
            );
        }
    }

    fn literal_route_paths(source: &str) -> Vec<&str> {
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        let mut remaining = production;
        let mut paths = Vec::new();
        while let Some(marker) = remaining.find(".route(") {
            let arguments = remaining[marker + ".route(".len()..].trim_start();
            assert!(
                arguments.starts_with('"'),
                "main API route declarations must use a literal path"
            );
            let quoted = &arguments[1..];
            let end = quoted
                .find('"')
                .expect("literal route path must have a closing quote");
            paths.push(&quoted[..end]);
            remaining = &quoted[end + 1..];
        }
        paths
    }

    #[test]
    fn every_registered_main_api_route_has_a_resource_mapping() {
        let route_sources = [
            ("approval", include_str!("approval.rs")),
            ("audit", include_str!("audit.rs")),
            ("audit_replay", include_str!("audit_replay.rs")),
            ("card_templates", include_str!("card_templates.rs")),
            ("cross_org_grants", include_str!("cross_org_grants.rs")),
            ("delegation", include_str!("delegation.rs")),
            ("departments", include_str!("departments.rs")),
            ("domains", include_str!("domains.rs")),
            ("global_admin", include_str!("global_admin.rs")),
            ("inheritance", include_str!("inheritance.rs")),
            ("level_templates", include_str!("level_templates.rs")),
            ("permission_actions", include_str!("permission_actions.rs")),
            (
                "personal_permissions",
                include_str!("personal_permissions.rs"),
            ),
            ("org_authorities", include_str!("org_authorities.rs")),
            ("platform_packages", include_str!("platform_packages.rs")),
            ("resource_types", include_str!("resource_types.rs")),
            ("rule_sets", include_str!("rule_sets.rs")),
            ("rules", include_str!("rules.rs")),
            ("simulation", include_str!("simulation.rs")),
            ("sod", include_str!("sod.rs")),
            ("stats", include_str!("stats.rs")),
            ("templates", include_str!("templates.rs")),
            ("tenants", include_str!("tenants.rs")),
            ("user_cards", include_str!("user_cards.rs")),
            ("user_gradings", include_str!("user_gradings.rs")),
            ("user_levels", include_str!("user_levels.rs")),
        ];
        let mut route_count = 0usize;
        for (module, source) in route_sources {
            for path in literal_route_paths(source) {
                route_count += 1;
                assert!(
                    resource_for_path(path).is_some(),
                    "registered route lacks permission mapping: {module}:{path}"
                );
            }
        }
        assert!(route_count >= 150, "route scan unexpectedly incomplete");

        assert_eq!(
            resource_for_path(crate::api::test_control::TEST_CONTROL_ROUTE),
            Some("monitor")
        );
        let test_control_source = include_str!("test_control.rs");
        let test_control_production = test_control_source
            .split("#[cfg(test)]")
            .next()
            .unwrap_or(test_control_source);
        assert_eq!(test_control_production.matches(".route(").count(), 1);
        assert!(test_control_production.contains(".route(TEST_CONTROL_ROUTE"));
    }

    #[test]
    fn legacy_domain_prefix_is_unknown_and_not_an_alias() {
        assert!(resource_for_path("/domain/domains").is_none());
        assert!(resource_for_path("/domain/user-cards/7/bind").is_none());
        assert!(resource_for_path("/domain/card-templates/5/rules/batch").is_none());
        assert!(TRUSTGRAPH_PATH_RESOURCE_MAP
            .iter()
            .all(|(prefix, _)| !prefix.starts_with("/domain/")));
    }

    #[test]
    fn audit_quarantine_path_mapping_uses_read_and_replay_actions() {
        assert_eq!(
            resource_for_path("/audit-quarantine"),
            Some("audit_quarantine")
        );
        assert_eq!(
            resolve_trustgraph_permission_action("audit_quarantine", "/audit-quarantine", "GET"),
            Some("read")
        );
        assert_eq!(
            resolve_trustgraph_permission_action(
                "audit_quarantine",
                "/audit-quarantine/7/replay",
                "POST",
            ),
            Some("replay")
        );
    }

    #[test]
    fn unknown_methods_never_resolve_to_a_permission_bypass() {
        for method in ["OPTIONS", "TRACE", "CONNECT", "CUSTOM"] {
            assert_eq!(
                resolve_trustgraph_permission_action("monitor", "/stats/projector", method),
                None
            );
        }
    }

    #[test]
    fn audit_request_id_uses_the_durable_canonical_gate() {
        let mut headers = HeaderMap::new();
        assert_eq!(audit_request_id(&headers), None);

        headers.insert(
            "x-request-id",
            HeaderValue::from_static("us27-e1:reader/42"),
        );
        assert_eq!(
            audit_request_id(&headers).as_deref(),
            Some("us27-e1:reader/42")
        );

        headers.insert(
            "x-request-id",
            HeaderValue::from_str(&"x".repeat(65)).expect("ASCII header"),
        );
        assert_eq!(audit_request_id(&headers), None);

        headers.insert("x-request-id", HeaderValue::from_static("unsafe request"));
        assert_eq!(audit_request_id(&headers), None);
    }

    #[test]
    fn object_id_query_uses_the_shared_explicit_key_grammar() {
        use axum::body::Body;
        let request = |query: &str| {
            Request::builder()
                .uri(format!("/permission-rules/check?{query}"))
                .body(Body::empty())
                .unwrap()
        };

        assert_eq!(request_target_id(&request("target_id=11")), Some(11));
        assert_eq!(request_target_id(&request("resource_id=12")), Some(12));
        assert_eq!(request_target_id(&request("id=13")), Some(13));
        assert_eq!(request_target_id(&request("card_id=14")), Some(14));
        assert_eq!(request_target_id(&request("targetId=15")), Some(15));
        assert_eq!(request_target_id(&request("resourceId=16")), Some(16));
        assert_eq!(request_target_id(&request("cardId=17")), Some(17));
    }

    #[test]
    fn object_id_query_rejects_malformed_and_pins_conflict_semantics() {
        use axum::body::Body;
        let request = |query: &str| {
            Request::builder()
                .uri(format!("/permission-rules/check?{query}"))
                .body(Body::empty())
                .unwrap()
        };

        // 非正数、溢出、非数字、空值一律忽略（无对象级目标 → 不做对象级判定）。
        assert_eq!(request_target_id(&request("id=0")), None);
        assert_eq!(request_target_id(&request("id=-3")), None);
        assert_eq!(request_target_id(&request("id=99999999999999999999")), None);
        assert_eq!(request_target_id(&request("id=i64max+1")), None);
        assert_eq!(request_target_id(&request("id=abc")), None);
        assert_eq!(request_target_id(&request("id=")), None);

        // 重复/冲突键：首个匹配键确定性生效，不静默合并、不取最大值。
        assert_eq!(request_target_id(&request("id=5&id=7")), Some(5));
        assert_eq!(
            request_target_id(&request("target_id=5&card_id=7")),
            Some(5)
        );
        assert_eq!(
            request_target_id(&request("card_id=7&target_id=5")),
            Some(7)
        );
        assert_eq!(request_target_id(&request("junk=1&target_id=9")), Some(9));
    }

    #[test]
    fn every_mapped_resource_is_registered_and_grantable() {
        // 路径映射里的每个资源必须在 ResourceRegistry 注册，且至少可被
        // `read` 规则授予（否则该路由的所有 GET 会结构性不可授予）。
        use astral_types::ResourceRegistry;
        let registry = ResourceRegistry::global();
        for (prefix, resource) in TRUSTGRAPH_PATH_RESOURCE_MAP {
            assert!(
                registry.validate(resource, "read").is_ok(),
                "mapped path {prefix} references resource `{resource}` that is not registered with a `read` action"
            );
        }
        // trustgraph 特例动作必须是一等注册动作（registry-first 合同）。
        assert!(registry.validate("audit_quarantine", "replay").is_ok());
        assert!(registry.validate("monitor", "arbitrate").is_ok());
    }

    /// 宿主 SoD 分发与准入栅栏形状守卫（对齐 sod_check 的源文本守卫惯例）：
    /// ORG provenance 判定必须先经 context-aware mirrored 装配
    /// （`load_org_sod_admission_mirrored`），再进入
    /// `check_sod_conflict_with_org` deny-only 复核；无 provenance 时走
    /// context-aware 纯 deny-only 入口（`check_sod_conflict_with_context`）。
    /// 准入栅栏必须在**一切权威读取之前**捕获（先于
    /// `resolve_resource_ownership` 与引擎评估），hub 已安装而栅栏不可得
    /// （capture None）必须立即 503 拒绝（绝不无栅栏放行），并在 SoD 之后、
    /// admit 之前最终复核（`authority_fence_matches`）——覆盖
    /// evaluate/ownership/SoD 全窗口。审计 detail 必须经 shared 有界
    /// provenance helper 并通过显式 detail 审计入口传播。本地不再保留任何
    /// 重复 helper 定义。
    #[test]
    fn sod_dispatch_wires_org_provenance_to_fresh_admission_recheck() {
        let source = include_str!("permission_check.rs");
        let production = source
            .split("async fn permission_check_middleware_scoped(")
            .nth(1)
            .expect("scoped middleware must remain")
            .split("#[cfg(test)]")
            .next()
            .expect("production middleware body");
        let fence_capture = production
            .find("capture_authority_fence")
            .expect("host must capture the opaque admission fence before authorization");
        let ownership = production
            .find("read_request\n            .resolve_ownership(")
            .expect("ownership resolution must use the request-scoped read handle");
        // Durable/mirror profiles retain the shared DB helper; CertifiedMemory
        // uses its one-token read set and never calls this legacy helper.
        let helper = include_str!("../service/admission_checks.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production helper");
        let dispatch = production
            .find("read_request.check_sod(&ctx, &decision)")
            .expect("host must use the request-scoped read handle for SoD");
        let loader = helper
            .find("load_org_sod_admission_mirrored(db, ctx, decision)")
            .expect("shared helper must assemble fresh org admission");
        let with_org = helper
            .find("check_sod_conflict_with_context_and_org(")
            .expect("org admission must use canonical context-aware SoD");
        let plain = helper
            .find("check_sod_conflict_with_context(db, ctx, ctx.resource_owner_id)")
            .expect("plain branch must retain deny-only SoD");
        let fence_recheck = production
            .find("authority_fence_matches")
            .expect("host must recheck the admission fence before admitting");
        assert!(
            fence_capture < ownership && ownership < dispatch,
            "the fence must be captured before ownership and shared admission"
        );
        assert!(
            loader < with_org && with_org < plain,
            "shared helper order must remain loader -> with_org -> plain"
        );
        assert!(
            dispatch < fence_recheck,
            "the fence recheck must run after the shared SoD window"
        );
        // hub 已安装而栅栏不可得（capture None）→ 立即 503 fail-closed。
        assert!(
            production.contains("admission fence unavailable"),
            "a missing fence on an installed hub must be rejected immediately"
        );
        assert!(
            !production.contains("fn org_provenance_audit_detail"),
            "the bounded provenance detail helper must come from astral_common::audit"
        );
        assert!(
            !production.contains("fn org_sod_admission"),
            "the admission loader must come from astral_db"
        );
        assert!(production.contains("org_provenance_audit_detail(path, provenance)"));
        assert!(production.contains("record_permission_audit_with_request_detail("));
        // 不允许把可伪造的 u64 计数器当栅栏：复核必须走 opaque AuthorityReadFence。
        assert!(
            !production.contains("admission_epoch") && !production.contains("fence_counter"),
            "admission fence must stay opaque (AuthorityReadFence), not a raw counter"
        );
        // 栅栏 token 只允许在一切权威读取之前**捕获一次**；末尾复核只比较已
        // 捕获栅栏——不存在"重新采样 token 覆盖旧读"的放行路径。
        assert_eq!(
            production.matches("capture_authority_fence").count(),
            1,
            "the admission fence must be captured exactly once, before authority reads"
        );
        // 漂移分支是安全 Pending（503 可重试），绝不折算成放行（栅栏块内
        // 不出现 Admitted；真正的 Admitted 记录在栅栏复核通过之后）。
        let fence_block_end = production[fence_recheck..]
            .find("host_admission")
            .map_or(production.len(), |index| fence_recheck + index);
        let mismatch_branch = &production[fence_recheck..fence_block_end];
        assert!(
            mismatch_branch.contains("SERVICE_UNAVAILABLE"),
            "a fence mismatch must be a retryable 503 safe-pending, not an admission"
        );
        assert!(
            !mismatch_branch.contains("AuthorizationAdmissionOutcome::Admitted"),
            "no admission may be recorded inside or after a failed fence recheck"
        );
    }
}
