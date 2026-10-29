//! 共享权限解析与上下文构造工具。
//!
//! 各服务必须先解析目标 owner，再自行调用 `PolicyEngine.evaluate()`；本模块
//! 仅提供路径/动作解析、目标 ID 提取和身份上下文构造，不提供通用授权入口。

use std::collections::HashSet;

use crate::token_contract::{PrincipalKind, PRINCIPAL_KIND_HEADER};
use astral_types::ResourceRegistry;
use astral_types::{PolicyContext, ResourceOwnershipScope};
use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Heap-backed middleware response error.
///
/// Axum middleware must return an error that implements `IntoResponse`. Keeping
/// the full response on the heap preserves its status, headers, and body while
/// satisfying `clippy::result_large_err`.
#[derive(Debug)]
pub struct BoxedResponse(Box<Response>);

impl BoxedResponse {
    /// Store an already-built response without changing its HTTP semantics.
    pub fn new(response: Response) -> Self {
        Self(Box::new(response))
    }
}

impl IntoResponse for BoxedResponse {
    fn into_response(self) -> Response {
        *self.0
    }
}

/// 路径前缀 → 资源类型映射表
pub type PathResourceMap = &'static [(&'static str, &'static str)];

/// Match a route prefix without treating a longer resource name as the same path.
pub fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn parse_positive_id(value: &str) -> Option<i64> {
    value.parse::<i64>().ok().filter(|value| *value > 0)
}

/// 从 Gateway 注入的双卡头构建授权上下文。
///
/// PlatformUser 必须同时携带身份卡和用户卡的完整 scope；AppUser 只能返回
/// identity-only 上下文，调用方不得将其送入需要 user_card 的 PolicyEngine 路径。
pub fn physical_policy_context(
    headers: &axum::http::HeaderMap,
    resource: &str,
    action: &str,
    target_id: Option<i64>,
) -> Result<PolicyContext, StatusCode> {
    let user_id = headers
        .get("x-user-id")
        .and_then(|value| value.to_str().ok())
        .and_then(parse_positive_id)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let principal_kind = headers
        .get(PRINCIPAL_KIND_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(PrincipalKind::parse)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let identity_card_id = headers
        .get("x-identity-card-id")
        .and_then(|value| value.to_str().ok())
        .and_then(parse_positive_id)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let (card_id, tenant_id, domain_id) = match principal_kind {
        PrincipalKind::PlatformUser => (
            Some(
                headers
                    .get("x-user-card-id")
                    .and_then(|value| value.to_str().ok())
                    .and_then(parse_positive_id)
                    .ok_or(StatusCode::FORBIDDEN)?,
            ),
            Some(
                headers
                    .get("x-user-card-tenant-id")
                    .and_then(|value| value.to_str().ok())
                    .and_then(parse_positive_id)
                    .ok_or(StatusCode::FORBIDDEN)?,
            ),
            Some(
                headers
                    .get("x-user-card-domain-id")
                    .and_then(|value| value.to_str().ok())
                    .and_then(parse_positive_id)
                    .ok_or(StatusCode::FORBIDDEN)?,
            ),
        ),
        PrincipalKind::AppUser => (None, None, None),
    };

    Ok(PolicyContext::builder()
        .user_id(Some(user_id))
        .principal_kind(Some(principal_kind.as_str().to_string()))
        .identity_card_id(Some(identity_card_id))
        .card_id(card_id)
        .tenant_id(tenant_id)
        .domain_id(domain_id)
        // Gateway identity headers establish actor facts only. A protected HTTP
        // route must call its service-side resource-owner resolver before
        // PolicyEngine.evaluate; actor tenant/domain are never target ownership.
        .resource_ownership_scope(ResourceOwnershipScope::Unresolved)
        .resource(Some(resource.to_string()))
        .action(action.to_string())
        .target_id(target_id)
        .build())
}

/// 从请求 query 提取对象级 target_id（供具体对象规则与 OwnerOnly 条件求值）。
///
/// 对齐 Java `PermissionAspect.resolveResourceId`：对象 ID 只来自 controller 显式参数，
/// 不从未知路径段推断，避免 `/levels/5/play` 之类的路径把非对象数字误当授权资源。
/// query 键：`target_id` / `targetId` / `resource_id` / `resourceId` / `id` / `card_id` / `cardId`。
pub fn request_target_id(req: &Request) -> Option<i64> {
    req.uri().query().and_then(|query| {
        query.split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            match key {
                "target_id" | "targetId" | "resource_id" | "resourceId" | "id" | "card_id"
                | "cardId" => parse_positive_id(value),
                _ => None,
            }
        })
    })
}

/// 根据资源、路径和 HTTP 方法解析 Java canonical permission action。
///
/// 只有明确的业务特例在这里覆盖 HTTP 默认动作；其余操作保持 REST 映射，
/// 未知方法返回 `None`，由调用方放行非业务的 OPTIONS 等预检请求。
pub fn resolve_permission_action(resource: &str, path: &str, method: &str) -> Option<&'static str> {
    if resource == "identity_users"
        && method == "POST"
        && path
            .strip_prefix("/users/")
            .and_then(|rest| rest.strip_suffix("/password"))
            .is_some_and(|user_id| !user_id.is_empty() && !user_id.contains('/'))
    {
        return Some("reset-password");
    }

    if resource == "learn_level_play" && method == "POST" {
        return Some("play");
    }

    if resource == "authorization"
        && ((method == "POST"
            && [
                "/global-admins/grant",
                "/global-admins/enable",
                "/global-admins/disable",
                "/integrations/identity-mappings",
            ]
            .contains(&path))
            || (method == "PUT" && path == "/integrations/identity-mappings/status"))
    {
        return Some("update");
    }

    if resource == "permission_inheritance"
        && ((method == "POST" && path == "/inheritance/config")
            || (method == "DELETE" && path.starts_with("/inheritance/config/")))
    {
        return Some("update");
    }

    if resource == "monitor" {
        if path == "/stats/reset" && method == "POST" {
            return Some("reset");
        }
        if method == "POST" && path.starts_with("/alerts/") && path.ends_with("/toggle") {
            return Some("update");
        }
    }
    if resource == "notification"
        && method == "POST"
        && path.starts_with("/notifications/")
        && path.ends_with("/test")
    {
        return Some("test");
    }

    if resource == "permission_rule"
        && method == "POST"
        && (path == "/sod-policies/detect" || path == "/sod-policies/validate-grant")
    {
        return Some("read");
    }

    if resource == "permission_request" && method == "POST" {
        if path.ends_with("/approve") || path.ends_with("/reject") {
            return Some("approve");
        }
        if path.ends_with("/cancel") {
            return Some("update");
        }
    }

    if matches!(
        resource,
        "domain_resource_type" | "resource_type" | "permission_action"
    ) && method == "POST"
        && path.contains("/scan")
    {
        return Some("scan");
    }

    if resource == "permission_rule"
        && method == "POST"
        && (path.ends_with("/revoke")
            || path.ends_with("/bind")
            || path.ends_with("/unbind")
            || (path.contains("/card/") && path.ends_with("/bind")))
    {
        return Some("update");
    }
    if resource == "permission_rule"
        && method == "DELETE"
        && path.contains("/card/")
        && path.contains("/unbind/")
    {
        return Some("update");
    }

    if resource == "domain"
        && method == "POST"
        && path.contains("/card-templates/")
        && path.contains("/rules/batch")
    {
        return Some("create");
    }

    if resource == "domain" {
        if path.contains("/conflict-detection") && method == "POST" {
            return Some("read");
        }
        if (path.contains("/user-cards/") && path.ends_with("/bind"))
            || (path.contains("/user-cards/") && path.ends_with("/bind/async"))
            || (path.contains("/user-gradings") && method == "POST")
            || (path.contains("/user-levels") && method == "POST")
        {
            return Some("update");
        }
        if (path.contains("/card-templates/")
            && (path.ends_with("/apply")
                || path.ends_with("/apply/async")
                || path.ends_with("/sync")))
            || (path.contains("/card-templates/") && path.contains("/rules/batch"))
        {
            return Some("update");
        }
    }

    if resource == "permission_rule" && method == "POST" && path.contains("/level-templates") {
        return Some(if path.ends_with("/precheck") {
            "read"
        } else {
            "update"
        });
    }

    match method {
        "GET" | "HEAD" => Some("read"),
        "POST" => Some("create"),
        "PUT" | "PATCH" => Some("update"),
        "DELETE" => Some("delete"),
        _ => None,
    }
}

/// 启动期注册校验：验证 PATH_RESOURCE_MAP 中所有资源类型已在 ResourceRegistry 注册
///
/// 对齐 Java `@PostConstruct` 全项目扫描 `@RequirePermission` 的交叉校验。
/// 在每个 crate 的 main.rs 启动后调用。发现未注册的资源类型时输出 ERROR 日志（不阻塞启动）。
pub fn validate_path_map(path_map: PathResourceMap, service_name: &str) {
    let reg = ResourceRegistry::global();
    let mut found_unregistered = false;

    let resources: HashSet<&str> = path_map.iter().map(|(_, r)| *r).collect();
    for resource in &resources {
        if let Err(e) = reg.validate(resource, "read") {
            // 使用 "read" 动作测试注册——只要资源存在即可
            tracing::error!(
                service = service_name,
                resource = %resource,
                error = %e,
                "Route permission mapping references unregistered resource type"
            );
            found_unregistered = true;
        }
    }

    if found_unregistered {
        tracing::warn!(
            service = service_name,
            unregistered = resources.len(),
            "ResourceRegistry validation found unregistered resource types (non-blocking)"
        );
    } else {
        tracing::info!(
            service = service_name,
            registered = resources.len(),
            "All route resource types validated against ResourceRegistry"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{request_target_id, resolve_permission_action};
    use astral_types::ResourceOwnershipScope;

    #[test]
    fn maps_java_special_actions_before_http_defaults() {
        assert_eq!(
            resolve_permission_action(
                "permission_request",
                "/permission-requests/7/approve",
                "POST"
            ),
            Some("approve")
        );
        assert_eq!(
            resolve_permission_action("domain_resource_type", "/resource-types/scan", "POST"),
            Some("scan")
        );
        assert_eq!(
            resolve_permission_action("permission_rule", "/rule-sets/card/7/unbind/3", "DELETE"),
            Some("update")
        );
        assert_eq!(
            resolve_permission_action("domain", "/card-templates/5/rules/batch", "POST"),
            Some("create")
        );
        assert_eq!(
            resolve_permission_action("domain", "/user-cards/7/bind", "POST"),
            Some("update")
        );
        assert_eq!(
            resolve_permission_action("permission_rule", "/level-templates/precheck", "POST"),
            Some("read")
        );
        assert_eq!(
            resolve_permission_action("learn_level_play", "/level-play/start", "POST"),
            Some("play")
        );
    }

    #[test]
    fn maps_special_registered_mutations_and_resource_type_routes() {
        let cases = [
            ("authorization", "/global-admins/grant", "POST", "update"),
            ("authorization", "/global-admins/enable", "POST", "update"),
            ("authorization", "/global-admins/disable", "POST", "update"),
            (
                "authorization",
                "/integrations/identity-mappings",
                "POST",
                "update",
            ),
            (
                "authorization",
                "/integrations/identity-mappings/status",
                "PUT",
                "update",
            ),
            (
                "permission_inheritance",
                "/inheritance/config",
                "POST",
                "update",
            ),
            (
                "permission_inheritance",
                "/inheritance/config/approval",
                "DELETE",
                "update",
            ),
            ("monitor", "/stats/reset", "POST", "reset"),
            ("monitor", "/alerts/3/toggle", "POST", "update"),
            ("notification", "/notifications/3/test", "POST", "test"),
            ("permission_rule", "/sod-policies/detect", "POST", "read"),
            (
                "permission_rule",
                "/sod-policies/validate-grant",
                "POST",
                "read",
            ),
        ];
        let registry = astral_types::ResourceRegistry::global();
        for (resource, path, method, expected) in cases {
            assert_eq!(
                resolve_permission_action(resource, path, method),
                Some(expected),
                "action for {method} {path}"
            );
            assert!(
                registry.validate(resource, expected).is_ok(),
                "route {method} {path} maps to an unregistered permission {resource}:{expected}"
            );
        }
    }

    #[test]
    fn assisted_password_reset_maps_only_the_exact_post_route() {
        let registry = astral_types::ResourceRegistry::global();
        for path in [
            "/users/7/password",
            "/users/{id}/password",
            "/users/0/password",
            "/users/not-an-id/password",
        ] {
            assert_eq!(
                resolve_permission_action("identity_users", path, "POST"),
                Some("reset-password"),
                "action for POST {path}"
            );
        }
        assert!(registry
            .validate("identity_users", "reset-password")
            .is_ok());

        for path in [
            "/users",
            "/cards",
            "/mfa/enable",
            "/mfa/disable",
            "/mfa/verify",
            "/mfa/recovery-codes",
            "/users/7/password-extra",
            "/users/7/password/extra",
            "/users/7/extra/password",
            "/users//password",
            "/password/reset/token",
        ] {
            assert_eq!(
                resolve_permission_action("identity_users", path, "POST"),
                Some("create"),
                "unrelated POST {path} must retain its existing action"
            );
        }
        for (method, expected) in [("GET", "read"), ("PUT", "update"), ("DELETE", "delete")] {
            assert_eq!(
                resolve_permission_action("identity_users", "/users/7/password", method),
                Some(expected)
            );
        }
        assert_eq!(
            resolve_permission_action("identity_users", "/users/7/password", "OPTIONS"),
            None
        );
        assert_eq!(
            resolve_permission_action("permission_rule", "/users/7/password", "POST"),
            Some("create")
        );
    }

    #[test]
    fn maps_ordinary_rest_methods_and_unknown_methods() {
        assert_eq!(
            resolve_permission_action("permission_rule", "/permission-rules", "GET"),
            Some("read")
        );
        assert_eq!(
            resolve_permission_action("permission_rule", "/permission-rules", "POST"),
            Some("create")
        );
        assert_eq!(
            resolve_permission_action("permission_rule", "/permission-rules", "OPTIONS"),
            None
        );
    }

    #[test]
    fn path_prefix_matching_is_segment_bounded() {
        use super::path_matches_prefix;

        assert!(path_matches_prefix("/ws", "/ws"));
        assert!(path_matches_prefix("/ws/42", "/ws"));
        assert!(!path_matches_prefix("/wsfoo", "/ws"));
        assert!(path_matches_prefix("/ws/42/extra", "/ws/42"));
    }

    #[test]
    fn target_id_ignores_path_numbers_and_reads_explicit_query() {
        use axum::body::Body;
        use axum::http::Request;
        let builder = |uri: &str| Request::builder().uri(uri).body(Body::empty()).unwrap();

        assert_eq!(
            request_target_id(&builder("/progress/12/3?target_id=42")),
            Some(42)
        );
        assert_eq!(
            request_target_id(&builder("/progress?resourceId=7")),
            Some(7)
        );

        // 未知路径段不再被推断为对象 ID（对齐 Java 显式 resourceIdExpression）。
        assert_eq!(request_target_id(&builder("/levels/5/play")), None);
        assert_eq!(request_target_id(&builder("/progress/12/3")), None);
        assert_eq!(
            request_target_id(&builder("/permission-requests/7/approve")),
            None
        );

        // 非正数 query 忽略，缺省无目标。
        assert_eq!(request_target_id(&builder("/progress?id=0")), None);
        assert_eq!(request_target_id(&builder("/progress")), None);
    }

    #[test]
    fn target_id_rejects_overflow_and_non_numeric_query_values() {
        use axum::body::Body;
        use axum::http::Request;
        let builder = |uri: &str| Request::builder().uri(uri).body(Body::empty()).unwrap();

        // i64 溢出与非数字一律忽略（fail-closed：无目标 → 不做对象级判定）。
        assert_eq!(
            request_target_id(&builder("/progress?id=99999999999999999999")),
            None
        );
        assert_eq!(request_target_id(&builder("/progress?id=i64min")), None);
        assert_eq!(request_target_id(&builder("/progress?id=-3")), None);
        assert_eq!(request_target_id(&builder("/progress?id=")), None);

        // 重复/冲突 query 键：首个匹配键确定性生效（对齐 Java 显式单参数语义）。
        assert_eq!(request_target_id(&builder("/progress?id=5&id=7")), Some(5));
        assert_eq!(
            request_target_id(&builder("/progress?card_id=7&target_id=5")),
            Some(7)
        );
    }

    // ===== physical_policy_context：Gateway 身份头 → PolicyContext =====

    use super::physical_policy_context;
    use axum::http::{HeaderMap, HeaderValue, StatusCode};

    fn platform_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-user-id", HeaderValue::from_static("7"));
        headers.insert(
            "x-principal-kind",
            HeaderValue::from_static("PLATFORM_USER"),
        );
        headers.insert("x-identity-card-id", HeaderValue::from_static("100"));
        headers.insert("x-user-card-id", HeaderValue::from_static("200"));
        headers.insert("x-user-card-tenant-id", HeaderValue::from_static("30"));
        headers.insert("x-user-card-domain-id", HeaderValue::from_static("40"));
        headers
    }

    fn context_error(headers: &HeaderMap) -> StatusCode {
        physical_policy_context(headers, "example_resource", "read", Some(9)).unwrap_err()
    }

    #[test]
    fn platform_user_context_preserves_full_dual_card_scope() {
        let ctx = physical_policy_context(&platform_headers(), "learn_subject", "read", Some(42))
            .expect("complete platform headers must build a context");
        assert_eq!(ctx.user_id, Some(7));
        assert_eq!(ctx.principal_kind.as_deref(), Some("PLATFORM_USER"));
        assert_eq!(ctx.identity_card_id, Some(100));
        assert_eq!(ctx.card_id, Some(200));
        assert_eq!(ctx.tenant_id, Some(30));
        assert_eq!(ctx.domain_id, Some(40));
        assert_eq!(
            ctx.resource_ownership_scope,
            ResourceOwnershipScope::Unresolved,
            "verified actor headers must not establish target ownership"
        );
        assert_eq!(ctx.resource.as_deref(), Some("learn_subject"));
        assert_eq!(ctx.action, "read");
        assert_eq!(ctx.target_id, Some(42));
    }

    #[test]
    fn app_user_context_keeps_identity_card_but_never_user_card_scope() {
        let mut headers = HeaderMap::new();
        headers.insert("x-user-id", HeaderValue::from_static("7"));
        headers.insert("x-principal-kind", HeaderValue::from_static("APP_USER"));
        headers.insert("x-identity-card-id", HeaderValue::from_static("100"));

        let ctx = physical_policy_context(&headers, "learn_subject", "read", None)
            .expect("app-user headers must build an identity-only context");
        assert_eq!(ctx.user_id, Some(7));
        assert_eq!(ctx.principal_kind.as_deref(), Some("APP_USER"));
        assert_eq!(ctx.identity_card_id, Some(100));
        assert_eq!(ctx.card_id, None, "app user must not gain user-card scope");
        assert_eq!(ctx.tenant_id, None);
        assert_eq!(ctx.domain_id, None);
        assert_eq!(
            ctx.resource_ownership_scope,
            ResourceOwnershipScope::Unresolved
        );

        // 即便客户端伪造 user-card 头，AppUser 也不得获得 user-card scope。
        headers.insert("x-user-card-id", HeaderValue::from_static("200"));
        headers.insert("x-user-card-tenant-id", HeaderValue::from_static("30"));
        headers.insert("x-user-card-domain-id", HeaderValue::from_static("40"));
        let ctx = physical_policy_context(&headers, "learn_subject", "read", None)
            .expect("app-user headers with extra cards must still build a context");
        assert_eq!(ctx.card_id, None);
        assert_eq!(ctx.tenant_id, None);
        assert_eq!(ctx.domain_id, None);
    }

    #[test]
    fn missing_or_invalid_identity_headers_are_unauthorized() {
        // 完全无头。
        let empty = HeaderMap::new();
        assert_eq!(context_error(&empty), StatusCode::UNAUTHORIZED);

        // x-user-id 缺失 / 非数字 / 非正数。
        for user_id in [None, Some("abc"), Some("0"), Some("-7")] {
            let mut headers = platform_headers();
            match user_id {
                Some(value) => headers.insert("x-user-id", HeaderValue::from_str(value).unwrap()),
                None => headers.remove("x-user-id"),
            };
            assert_eq!(
                context_error(&headers),
                StatusCode::UNAUTHORIZED,
                "user id {user_id:?} must be 401"
            );
        }

        // principal kind 缺失 / 非法值。
        for kind in [None, Some("ADMIN"), Some("platform_user"), Some("")] {
            let mut headers = platform_headers();
            match kind {
                Some(value) => {
                    headers.insert("x-principal-kind", HeaderValue::from_str(value).unwrap())
                }
                None => headers.remove("x-principal-kind"),
            };
            assert_eq!(
                context_error(&headers),
                StatusCode::UNAUTHORIZED,
                "principal kind {kind:?} must be 401"
            );
        }

        // identity card 缺失 / 非法值。
        for identity_card in [None, Some("abc"), Some("0")] {
            let mut headers = platform_headers();
            match identity_card {
                Some(value) => {
                    headers.insert("x-identity-card-id", HeaderValue::from_str(value).unwrap())
                }
                None => headers.remove("x-identity-card-id"),
            };
            assert_eq!(
                context_error(&headers),
                StatusCode::UNAUTHORIZED,
                "identity card {identity_card:?} must be 401"
            );
        }
    }

    #[test]
    fn platform_user_with_incomplete_user_card_scope_is_forbidden() {
        // PlatformUser 必须同时携带 user-card/tenant/domain 三项完整 scope；
        // 任一缺失、非法或非正数 → 403（非 401：身份已确认，scope 不完整）。
        let scopes: [(&str, Option<&str>); 9] = [
            ("x-user-card-id", None),
            ("x-user-card-id", Some("abc")),
            ("x-user-card-id", Some("0")),
            ("x-user-card-tenant-id", None),
            ("x-user-card-tenant-id", Some("abc")),
            ("x-user-card-tenant-id", Some("0")),
            ("x-user-card-domain-id", None),
            ("x-user-card-domain-id", Some("abc")),
            ("x-user-card-domain-id", Some("0")),
        ];
        for (header, value) in scopes {
            let mut headers = platform_headers();
            match value {
                Some(value) => headers.insert(header, HeaderValue::from_str(value).unwrap()),
                None => headers.remove(header),
            };
            assert_eq!(
                context_error(&headers),
                StatusCode::FORBIDDEN,
                "platform user with {header}={value:?} must be 403"
            );
        }
    }
}
