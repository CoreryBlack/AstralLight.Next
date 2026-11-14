//! Gateway 签名与进程内来源验证中间件。
//!
//! 来源能力与 v3 签名、时间戳分别验证；有效签名本身不能证明来源。
//! 旧验签入口不验证来源，HTTP 来源验证尚未实现，不应据此开放 listener。

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use hmac::Mac;
use std::sync::Arc;

use crate::config::AppConfig;
use crate::middleware::constant_time_eq;
use crate::token_contract::PrincipalKind;

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

// This identity is intentionally private and cannot be constructed from HTTP data.
struct InProcessSourceIdentity;

#[derive(Clone)]
struct InProcessSourceMark {
    identity: Arc<InProcessSourceIdentity>,
    method: axum::http::Method,
    uri: axum::http::Uri,
    external_path: Option<axum::http::HeaderValue>,
    // Set only by the trusted Gateway after it bound an authority-verified
    // memory—v1 session to this request's root scope.
    memory_v1_session: bool,
}

/// Proof that the paired in-process Gateway source dispatched this request with
/// an authority-verified memory—v1 session bound to the request's root scope.
///
/// Only [`in_process_gateway_signature_middleware`] inserts this value, after
/// validating the source mark; it has no public constructor and HTTP clients
/// cannot set request extensions. It identifies the transport only: identity
/// is carried by the bound session facts, never by legacy identity headers,
/// and this value is not an authorization decision.
///
/// memory—v1
#[derive(Clone, Debug)]
pub struct VerifiedMemoryV1SessionTransport {
    _private: (),
}

/// Capability held only by the trusted Gateway's in-process dispatch code.
///
/// Possession permits marking arbitrary requests. The composition root must not
/// give it to external request handlers or use it before Gateway authentication
/// and header sanitization have succeeded. It is not an authorization decision.
pub struct InProcessGatewayIssuer(Arc<InProcessSourceIdentity>);

/// Verifier for exactly one composition's in-process Gateway source.
///
/// Clones verify the same issuer; a verifier cannot mark requests.
#[derive(Clone)]
pub struct InProcessGatewayVerifier(Arc<InProcessSourceIdentity>);

/// Create an issuer and verifier bound to a fresh, process-local identity.
///
/// The composition root must inject the issuer into the trusted Gateway and the
/// verifier into downstream middleware. Neither capability is an HTTP credential,
/// and this function does not establish a globally unique process owner.
///
/// memory—v1
pub fn in_process_gateway_source() -> (InProcessGatewayIssuer, InProcessGatewayVerifier) {
    let identity = Arc::new(InProcessSourceIdentity);
    (
        InProcessGatewayIssuer(Arc::clone(&identity)),
        InProcessGatewayVerifier(identity),
    )
}

impl InProcessGatewayIssuer {
    /// Mark a fully constructed request for this issuer's paired verifier after
    /// Gateway authentication and sanitization. The snapshot binds the actual
    /// method, URI (including query), and signed external-path header. Replaces
    /// any earlier mark; it is not a signature, replay defense, or authorization.
    ///
    /// memory—v1
    pub fn mark<B>(&self, request: &mut axum::http::Request<B>) {
        self.insert_mark(request, false);
    }

    /// Mark a request whose authority-verified memory—v1 session the trusted
    /// Gateway has already bound to the request's root scope.
    ///
    /// The downstream verifier then accepts the request only with a completely
    /// empty legacy identity context; the v3 signature and timestamp are still
    /// verified. Calling this without a bound session is a composition bug.
    ///
    /// memory—v1
    pub fn mark_memory_v1_session<B>(&self, request: &mut axum::http::Request<B>) {
        self.insert_mark(request, true);
    }

    // memory—v1: Snapshot the exact request shape under this issuer's identity.
    fn insert_mark<B>(&self, request: &mut axum::http::Request<B>, memory_v1_session: bool) {
        let mark = InProcessSourceMark {
            identity: Arc::clone(&self.0),
            method: request.method().clone(),
            uri: request.uri().clone(),
            external_path: request.headers().get("x-original-path").cloned(),
            memory_v1_session,
        };
        request.extensions_mut().insert(mark);
    }
}

/// Require the paired in-process Gateway source before the existing v3 verifier.
///
/// Install with `from_fn_with_state((config, verifier),
/// in_process_gateway_signature_middleware)`. The mark is consumed before any
/// signature checks or handler execution. This middleware does not validate an
/// HTTP peer and must only be installed on the intended in-process dispatch.
///
/// memory—v1
pub async fn in_process_gateway_signature_middleware(
    State((config, verifier)): State<(AppConfig, InProcessGatewayVerifier)>,
    mut req: Request,
    next: Next,
) -> Response {
    let mark = req.extensions_mut().remove::<InProcessSourceMark>();
    let valid_source = mark.as_ref().is_some_and(|mark| {
        let mut paths = req.headers().get_all("x-original-path").iter();
        let path = paths.next();
        Arc::ptr_eq(&mark.identity, &verifier.0)
            && mark.method == *req.method()
            && mark.uri == *req.uri()
            && mark.external_path.as_ref() == path
            && paths.next().is_none()
            && path.and_then(|value| value.to_str().ok()) == Some(req.uri().path())
            && req.uri().scheme().is_none()
            && req.uri().authority().is_none()
            && req.uri().path().starts_with('/')
    });
    if !valid_source {
        return gateway_error(
            &req,
            403,
            "Missing or invalid gateway source",
            "FORBIDDEN",
            "GATEWAY_SOURCE_INVALID",
        );
    }
    // memory—v1: A session transport carries identity only in its bound session
    // facts. Any legacy identity header is a mixed context and is rejected; a
    // marker never survives a dispatch that did not bind a session.
    if mark.is_some_and(|mark| mark.memory_v1_session) {
        if !has_empty_identity_context(req.headers()) {
            return gateway_error(
                &req,
                403,
                "Mixed memory-v1 and legacy identity context",
                "FORBIDDEN",
                "PRINCIPAL_CARD_CONTEXT_INVALID",
            );
        }
        req.extensions_mut()
            .insert(VerifiedMemoryV1SessionTransport { _private: () });
    } else {
        req.extensions_mut()
            .remove::<VerifiedMemoryV1SessionTransport>();
    }

    gateway_signature_middleware(State(config), req, next).await
}

/// 计算 Rust v3 HMAC-SHA256 签名。
///
/// v3 相对 v2 的变化（问题 1 修正）：identity_card 不承担组织归属，
/// canonical payload 移除 identity tenant/domain 字段（与 claims 契约同步）。
/// 保留绑定：method/path、token profile、identity card id、user-card 三字段。
/// 空值用空行表示，保证所有 producer/verifier 字段顺序一致。
#[allow(clippy::too_many_arguments)]
pub fn compute_hmac_signature_v3(
    secret: &str,
    method: &str,
    path: &str,
    user_id: &str,
    principal_kind: &str,
    token_id: &str,
    identity_card_id: &str,
    user_card_id: &str,
    user_card_domain_id: &str,
    user_card_tenant_id: &str,
    token_use: &str,
    claims_version: &str,
    action_codes: &str,
    user_roles: &str,
    timestamp: &str,
) -> String {
    let payload = format!(
        "astral-gateway-v3\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        method.trim(),
        path.trim(),
        user_id.trim(),
        principal_kind.trim(),
        token_id.trim(),
        identity_card_id.trim(),
        user_card_id.trim(),
        user_card_domain_id.trim(),
        user_card_tenant_id.trim(),
        token_use.trim(),
        claims_version.trim(),
        action_codes.trim(),
        user_roles.trim(),
        timestamp.trim(),
    );

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC key");
    mac.update(payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Exact Gateway-signed transports that intentionally carry no business identity.
///
/// This is not an unsigned bypass: callers still need a valid v3 signature,
/// timestamp and `x-gateway-auth` marker. The allowlist only admits the
/// identity-empty wire shape for public credential-bootstrap handlers and
/// Identity session operations that must validate their own refresh token.
fn is_identity_empty_signed_transport(method: &str, path: &str) -> bool {
    if method != "POST" {
        return false;
    }

    matches!(
        path,
        "/api/v1/auth/sessions"
            | "/api/v1/auth/register"
            | "/api/v1/auth/password/forgot"
            | "/api/v1/auth/password/reset/token"
            | "/api/v1/auth/verification/send"
            | "/api/v1/auth/verification/verify"
            | "/api/v1/auth/sessions/refresh"
            | "/api/v1/auth/sessions/switch-card"
            | "/api/v1/auth/sessions/logout"
            | "/api/v1/auth/sessions/revoke"
    ) || path
        .strip_prefix("/api/v1/auth/password/reset/")
        .is_some_and(|token| !token.is_empty() && !token.contains('/'))
}

/// Identity-empty means every signed identity field and every additional
/// gateway-injected identity/permission context field is absent or blank. A
/// partial principal/card context never falls through to the transport exception.
fn has_empty_identity_context(headers: &axum::http::HeaderMap) -> bool {
    const IDENTITY_HEADERS: &[&str] = &[
        "x-user-id",
        "x-principal-kind",
        "x-token-id",
        "x-identity-card-id",
        "x-user-card-id",
        "x-user-card-domain-id",
        "x-user-card-tenant-id",
        "x-token-use",
        "x-claims-version",
        "x-action-codes",
        "x-user-roles",
        "x-template-id",
        "x-tenant-status",
        "x-perms-ref",
        "x-permissions-truncated",
        "x-has-required",
        "x-required-permission",
        "x-resource-owner-id",
    ];

    IDENTITY_HEADERS.iter().all(|name| {
        headers
            .get(*name)
            .is_none_or(|value| value.to_str().is_ok_and(|text| text.trim().is_empty()))
    })
}

fn timestamp_within_tolerance(now_ms: i64, timestamp_ms: i64, tolerance_ms: i64) -> bool {
    tolerance_ms > 0 && now_ms.abs_diff(timestamp_ms) <= tolerance_ms as u64
}

/// Gateway 签名验证中间件
///
/// 验证步骤（对齐 Java `GatewayIdentityHeaders.isVerified()`）：
/// 1. 检查 X-Gateway-Auth == "verified"
/// 2. 检查 X-Gateway-Ts / X-Gateway-Signature 存在
/// 3. 时间戳容差检查（默认 30 秒）
/// 4. 重新计算签名并做常量时间比较
///
/// 注意：Gateway 自身不添加此中间件（它是签名生成方，不是验证方）。
/// 此兼容入口不验证请求来源；不能独立作为可信来源或开放 listener 的依据。
///
/// memory—v1
pub async fn gateway_signature_middleware(
    State(config): State<AppConfig>,
    req: Request,
    next: Next,
) -> Response {
    let headers = req.headers();

    // Step 1: 检查 X-Gateway-Auth
    let gateway_auth = headers
        .get("x-gateway-auth")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .unwrap_or("");

    if !gateway_auth.eq_ignore_ascii_case("verified") {
        return gateway_error(
            &req,
            403,
            "Missing or invalid gateway auth",
            "FORBIDDEN",
            "GATEWAY_AUTH_INVALID",
        );
    }

    // Step 2: 检查必要头存在
    let timestamp = headers
        .get("x-gateway-ts")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .unwrap_or("");

    let signature = headers
        .get("x-gateway-signature")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .unwrap_or("");

    if timestamp.is_empty() || signature.is_empty() {
        return gateway_error(
            &req,
            403,
            "Missing gateway timestamp or signature",
            "FORBIDDEN",
            "GATEWAY_SIGNATURE_MISSING",
        );
    }

    // Step 3: 时间戳容差检查
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    let tolerance_ms = match config.gateway.timestamp_tolerance_secs.checked_mul(1000) {
        Some(value) if value > 0 => value,
        _ => {
            return gateway_error(
                &req,
                500,
                "Gateway timestamp tolerance is invalid",
                "INTERNAL_ERROR",
                "GATEWAY_TIMESTAMP_TOLERANCE_INVALID",
            )
        }
    };
    let ts_ms: i64 = match timestamp.parse() {
        Ok(v) => v,
        Err(_) => {
            return gateway_error(
                &req,
                403,
                "Invalid gateway timestamp",
                "FORBIDDEN",
                "GATEWAY_TIMESTAMP_INVALID",
            )
        }
    };

    // Compare as an unsigned distance so extreme signed timestamps cannot overflow.
    if !timestamp_within_tolerance(now_ms, ts_ms, tolerance_ms) {
        return gateway_error(
            &req,
            403,
            "Gateway timestamp skew too large",
            "FORBIDDEN",
            "GATEWAY_TIMESTAMP_SKEW",
        );
    }

    // Step 4: 重新计算签名并比较
    let method = req.method().as_str();
    let path = headers
        .get("x-original-path")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| req.uri().path());

    let user_id = headers
        .get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let principal_kind = headers
        .get("x-principal-kind")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token_id = headers
        .get("x-token-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let identity_card_id = headers
        .get("x-identity-card-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let user_card_id = headers
        .get("x-user-card-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let user_card_domain_id = headers
        .get("x-user-card-domain-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let user_card_tenant_id = headers
        .get("x-user-card-tenant-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token_use = headers
        .get("x-token-use")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let claims_version = headers
        .get("x-claims-version")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let action_codes = headers
        .get("x-action-codes")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let user_roles = headers
        .get("x-user-roles")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Bootstrap and Refresh transports carry an empty identity payload. The
    // branch stays behind the same v3 verification, and is exact on method/path;
    // any partial or spoofed identity context is rejected rather than ignored.
    // memory—v1: a request the in-process source verifier proved to carry a
    // bound memory—v1 session is also identity-empty at this legacy layer; its
    // identity travels only in the session facts and is checked by the engine.
    let identity_empty_transport = (is_identity_empty_signed_transport(method, path)
        || req
            .extensions()
            .get::<VerifiedMemoryV1SessionTransport>()
            .is_some())
        && has_empty_identity_context(headers);
    let principal_kind = if identity_empty_transport {
        None
    } else {
        match PrincipalKind::parse(principal_kind) {
            Some(kind) => Some(kind),
            None => {
                return gateway_error(
                    &req,
                    403,
                    "Invalid principal kind",
                    "FORBIDDEN",
                    "PRINCIPAL_KIND_INVALID",
                )
            }
        }
    };
    let identity_present = !identity_card_id.trim().is_empty();
    let user_card_fields_present = [user_card_id, user_card_domain_id, user_card_tenant_id]
        .iter()
        .all(|value| !value.trim().is_empty());
    let user_card_fields_absent = [user_card_id, user_card_domain_id, user_card_tenant_id]
        .iter()
        .all(|value| value.trim().is_empty());
    let context_valid = if identity_empty_transport {
        has_empty_identity_context(headers)
    } else {
        identity_present
            && match principal_kind {
                Some(PrincipalKind::PlatformUser) => user_card_fields_present,
                Some(PrincipalKind::AppUser) => user_card_fields_absent,
                None => false,
            }
    };
    if !context_valid {
        return gateway_error(
            &req,
            403,
            "Invalid principal card context",
            "FORBIDDEN",
            "PRINCIPAL_CARD_CONTEXT_INVALID",
        );
    }

    // v3 签名（问题 1 修正后唯一契约：identity_card 不承担组织归属，
    // payload 不含身份侧 tenant/domain 字段）。
    let expected = compute_hmac_signature_v3(
        &config.gateway.hmac_secret,
        method,
        path,
        user_id,
        principal_kind.map(|kind| kind.as_str()).unwrap_or(""),
        token_id,
        identity_card_id,
        user_card_id,
        user_card_domain_id,
        user_card_tenant_id,
        token_use,
        claims_version,
        action_codes,
        user_roles,
        timestamp,
    );

    // 常量时间比较（对齐 Java MessageDigest.isEqual）
    if !constant_time_eq(signature.as_bytes(), expected.as_bytes()) {
        return gateway_error(
            &req,
            403,
            "Gateway signature mismatch",
            "FORBIDDEN",
            "GATEWAY_SIGNATURE_MISMATCH",
        );
    }

    next.run(req).await
}

/// Shared gateway contract error shape. The verifier does not expose internal details.
fn gateway_error(
    req: &Request,
    status: u16,
    message: &str,
    error_type: &str,
    reason: &str,
) -> Response {
    let trace_id = req
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("gateway-signature-error");
    let body = serde_json::json!({
        "code": status,
        "message": message,
        "traceId": trace_id,
        "requestPath": req.uri().path(),
        "requestMethod": req.method().as_str(),
        "errorType": error_type,
        "decision": reason,
        "reasonCode": reason,
    });
    let mut response = (
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        axum::Json(body),
    )
        .into_response();
    if let Ok(value) = trace_id.parse() {
        response.headers_mut().insert("X-Trace-Id", value);
    }
    if status == 503 {
        response
            .headers_mut()
            .insert("Retry-After", axum::http::HeaderValue::from_static("3"));
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-secret-at-least-32-chars-long!!";

    fn baseline_signature() -> String {
        compute_hmac_signature_v3(
            SECRET,
            "GET",
            "/v1/app/learn/progress/12",
            "42",
            "PLATFORM_USER",
            "jti-abc",
            "identity-card",
            "user-card",
            "user-domain",
            "user-tenant",
            "ACCESS",
            "2",
            "read",
            "USER",
            "1700000000000",
        )
    }

    fn empty_signed_request(method: &str, path: &str) -> axum::http::Request<axum::body::Body> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            .to_string();
        let signature = compute_hmac_signature_v3(
            SECRET, method, path, "", // user_id
            "", // principal_kind
            "", // token_id
            "", // identity_card_id
            "", // user_card_id
            "", // user_card_domain_id
            "", // user_card_tenant_id
            "", // token_use
            "", // claims_version
            "", // action_codes
            "", // user_roles
            &timestamp,
        );
        axum::http::Request::builder()
            .method(method)
            .uri(path)
            .header("x-gateway-auth", "verified")
            .header("x-gateway-ts", timestamp)
            .header("x-gateway-signature", signature)
            .header("x-original-path", path)
            .body(axum::body::Body::empty())
            .unwrap()
    }

    fn request_header_value<'a>(headers: &'a axum::http::HeaderMap, name: &str) -> &'a str {
        headers
            .get(name)
            .and_then(|header| header.to_str().ok())
            .unwrap_or("")
    }

    fn resign_request(request: &mut axum::http::Request<axum::body::Body>) {
        let path = request_header_value(request.headers(), "x-original-path");
        let signature = compute_hmac_signature_v3(
            SECRET,
            request.method().as_str(),
            path,
            request_header_value(request.headers(), "x-user-id"),
            request_header_value(request.headers(), "x-principal-kind"),
            request_header_value(request.headers(), "x-token-id"),
            request_header_value(request.headers(), "x-identity-card-id"),
            request_header_value(request.headers(), "x-user-card-id"),
            request_header_value(request.headers(), "x-user-card-domain-id"),
            request_header_value(request.headers(), "x-user-card-tenant-id"),
            request_header_value(request.headers(), "x-token-use"),
            request_header_value(request.headers(), "x-claims-version"),
            request_header_value(request.headers(), "x-action-codes"),
            request_header_value(request.headers(), "x-user-roles"),
            request_header_value(request.headers(), "x-gateway-ts"),
        );
        request
            .headers_mut()
            .insert("x-gateway-signature", signature.parse().unwrap());
    }

    fn config() -> AppConfig {
        AppConfig {
            gateway: crate::config::GatewayCfg {
                hmac_secret: SECRET.to_string(),
                timestamp_tolerance_secs: 30,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn identity_empty_route_app(
        counter: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) -> axum::Router {
        use axum::routing::any;
        use axum::Router;

        let app = Router::new()
            .route(
                "/api/v1/auth/sessions",
                any({
                    let counter = counter.clone();
                    move || {
                        let counter = counter.clone();
                        async move {
                            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            "identity-empty-marker"
                        }
                    }
                }),
            )
            .route(
                "/api/v1/auth/sessions/refresh",
                any({
                    let counter = counter.clone();
                    move || {
                        let counter = counter.clone();
                        async move {
                            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            "identity-empty-marker"
                        }
                    }
                }),
            )
            .route(
                "/api/v1/auth/sessions/refresh-extra",
                any({
                    let counter = counter.clone();
                    move || {
                        let counter = counter.clone();
                        async move {
                            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            "must-not-reach"
                        }
                    }
                }),
            )
            .route(
                "/api/v1/auth/profile",
                any({
                    let counter = counter.clone();
                    move || {
                        let counter = counter.clone();
                        async move {
                            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            "protected-marker"
                        }
                    }
                }),
            )
            .route_layer(axum::middleware::from_fn_with_state(
                config(),
                gateway_signature_middleware,
            ));
        app.with_state(config())
    }

    // memory—v1
    fn in_process_route_app(
        verifier: InProcessGatewayVerifier,
        counter: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) -> axum::Router {
        use axum::{routing::post, Router};

        Router::new()
            .route(
                "/api/v1/auth/sessions",
                post(move |request: Request| {
                    let counter = counter.clone();
                    async move {
                        assert!(request.extensions().get::<InProcessSourceMark>().is_none());
                        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        "verified"
                    }
                }),
            )
            .route_layer(axum::middleware::from_fn_with_state(
                (config(), verifier),
                in_process_gateway_signature_middleware,
            ))
    }

    // memory—v1
    async fn response_reason(response: Response) -> String {
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        json["reasonCode"].as_str().unwrap().to_owned()
    }

    #[tokio::test]
    // memory—v1: A bound-session transport is identity-empty only behind the
    // paired session mark; plain marks, forged markers, mixed identity and bad
    // signatures all fail, and the legacy layer alone never grants the branch.
    async fn memory_v1_session_transport_requires_session_mark_and_empty_identity() {
        use axum::{routing::get, Router};
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        use tower::ServiceExt;

        let (issuer, verifier) = in_process_gateway_source();
        let counter = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&counter);
        let path = "/main/api/v1/permission-rules/registry";
        let app = Router::new()
            .route(
                path,
                get(move |request: Request| {
                    let seen = Arc::clone(&seen);
                    async move {
                        assert!(request
                            .extensions()
                            .get::<VerifiedMemoryV1SessionTransport>()
                            .is_some());
                        seen.fetch_add(1, Ordering::SeqCst);
                        "verified"
                    }
                }),
            )
            .route_layer(axum::middleware::from_fn_with_state(
                (config(), verifier),
                in_process_gateway_signature_middleware,
            ));

        // A plain in-process mark keeps the legacy principal requirement.
        let mut plain = empty_signed_request("GET", path);
        issuer.mark(&mut plain);
        let response = app.clone().oneshot(plain).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response_reason(response).await, "PRINCIPAL_KIND_INVALID");

        // A marker inserted before a non-session dispatch is stripped.
        let mut forged = empty_signed_request("GET", path);
        forged
            .extensions_mut()
            .insert(VerifiedMemoryV1SessionTransport { _private: () });
        issuer.mark(&mut forged);
        let response = app.clone().oneshot(forged).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response_reason(response).await, "PRINCIPAL_KIND_INVALID");

        // Any legacy identity header beside a session mark is a mixed context.
        let mut mixed = empty_signed_request("GET", path);
        mixed
            .headers_mut()
            .insert("x-user-id", "42".parse().unwrap());
        issuer.mark_memory_v1_session(&mut mixed);
        let response = app.clone().oneshot(mixed).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response_reason(response).await,
            "PRINCIPAL_CARD_CONTEXT_INVALID"
        );

        // The v3 signature is still required on the session transport.
        let mut bad_signature = empty_signed_request("GET", path);
        bad_signature
            .headers_mut()
            .insert("x-gateway-signature", "invalid".parse().unwrap());
        issuer.mark_memory_v1_session(&mut bad_signature);
        let response = app.clone().oneshot(bad_signature).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response_reason(response).await,
            "GATEWAY_SIGNATURE_MISMATCH"
        );
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        let mut session = empty_signed_request("GET", path);
        issuer.mark_memory_v1_session(&mut session);
        let response = app.clone().oneshot(session).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        // Without the in-process verifier the legacy layer keeps rejecting.
        let legacy_only = Router::new()
            .route(path, get(|| async { "unreachable" }))
            .route_layer(axum::middleware::from_fn_with_state(
                config(),
                gateway_signature_middleware,
            ));
        let response = legacy_only
            .oneshot(empty_signed_request("GET", path))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response_reason(response).await, "PRINCIPAL_KIND_INVALID");
    }

    #[tokio::test]
    // memory—v1
    async fn in_process_source_must_match_before_signature_validation() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        use tower::ServiceExt;

        let (issuer, verifier) = in_process_gateway_source();
        let (other_issuer, _) = in_process_gateway_source();
        let counter = Arc::new(AtomicUsize::new(0));
        let app = in_process_route_app(verifier, Arc::clone(&counter));
        let path = "/api/v1/auth/sessions";

        // Even a valid signature and plausible source headers cannot create the mark.
        let mut forged = empty_signed_request("POST", path);
        forged
            .headers_mut()
            .insert("x-gateway-source", "in-process".parse().unwrap());
        forged
            .headers_mut()
            .insert("x-forwarded-for", "127.0.0.1".parse().unwrap());
        let response = app.clone().oneshot(forged).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response_reason(response).await, "GATEWAY_SOURCE_INVALID");

        let mut wrong_issuer = empty_signed_request("POST", path);
        other_issuer.mark(&mut wrong_issuer);
        let response = app.clone().oneshot(wrong_issuer).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response_reason(response).await, "GATEWAY_SOURCE_INVALID");

        // Source failure is returned even when the signature fields are missing.
        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(path)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response_reason(response).await, "GATEWAY_SOURCE_INVALID");
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        let mut valid = empty_signed_request("POST", path);
        issuer.mark(&mut valid);
        let response = app.clone().oneshot(valid).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        // A mark from the correct issuer does not bypass the existing verifier.
        let mut invalid_signature = empty_signed_request("POST", path);
        invalid_signature
            .headers_mut()
            .insert("x-gateway-signature", "invalid".parse().unwrap());
        issuer.mark(&mut invalid_signature);
        let response = app.clone().oneshot(invalid_signature).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response_reason(response).await,
            "GATEWAY_SIGNATURE_MISMATCH"
        );

        let mut stale = empty_signed_request("POST", path);
        stale
            .headers_mut()
            .insert("x-gateway-ts", "1".parse().unwrap());
        resign_request(&mut stale);
        issuer.mark(&mut stale);
        let response = app.clone().oneshot(stale).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response_reason(response).await, "GATEWAY_TIMESTAMP_SKEW");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    // memory—v1: The consumed capability binds target identity, method, raw URI and signed path.
    async fn in_process_binding_rejects_retargeting_and_mutation() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        use tower::ServiceExt;

        let (issuer, verifier) = in_process_gateway_source();
        let (_, other_verifier) = in_process_gateway_source();
        let counter = Arc::new(AtomicUsize::new(0));
        let app = axum::Router::new()
            .fallback({
                let counter = Arc::clone(&counter);
                move || {
                    let counter = Arc::clone(&counter);
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        StatusCode::OK
                    }
                }
            })
            .layer(axum::middleware::from_fn_with_state(
                (config(), verifier),
                in_process_gateway_signature_middleware,
            ));
        let other_app = axum::Router::new()
            .fallback(|| async { StatusCode::OK })
            .layer(axum::middleware::from_fn_with_state(
                (config(), other_verifier),
                in_process_gateway_signature_middleware,
            ));
        let path = "/api/v1/auth/sessions";
        let uri = "/api/v1/auth/sessions?next=%2Fhome";
        let make_request = || {
            let mut request = empty_signed_request("POST", path);
            *request.uri_mut() = uri.parse().unwrap();
            issuer.mark(&mut request);
            request
        };

        let response = other_app.oneshot(make_request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response_reason(response).await, "GATEWAY_SOURCE_INVALID");

        for case in ["method", "path", "query", "signed path", "duplicate path"] {
            let mut request = make_request();
            match case {
                "method" => *request.method_mut() = axum::http::Method::GET,
                "path" => {
                    *request.uri_mut() = "/api/v1/auth/register?next=%2Fhome".parse().unwrap()
                }
                "query" => {
                    *request.uri_mut() = "/api/v1/auth/sessions?next=%2Fother".parse().unwrap()
                }
                "signed path" => {
                    request
                        .headers_mut()
                        .insert("x-original-path", "/api/v1/auth/register".parse().unwrap());
                    resign_request(&mut request);
                }
                "duplicate path" => {
                    request
                        .headers_mut()
                        .append("x-original-path", path.parse().unwrap());
                }
                _ => unreachable!(),
            }
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{case}");
            assert_eq!(
                response_reason(response).await,
                "GATEWAY_SOURCE_INVALID",
                "{case}"
            );
        }

        // Even a correctly signed external path cannot be marked for another URI.
        let mut mismatched = empty_signed_request("POST", path);
        *mismatched.uri_mut() = "/api/v1/auth/register".parse().unwrap();
        issuer.mark(&mut mismatched);
        let response = app.clone().oneshot(mismatched).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response_reason(response).await, "GATEWAY_SOURCE_INVALID");

        let response = app.oneshot(make_request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn exact_identity_empty_bootstrap_and_refresh_requests_require_valid_v3_signature() {
        use axum::body::to_bytes;
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        use tower::ServiceExt;

        let counter = Arc::new(AtomicUsize::new(0));
        let app = identity_empty_route_app(Arc::clone(&counter));
        for path in ["/api/v1/auth/sessions", "/api/v1/auth/sessions/refresh"] {
            let response = app
                .clone()
                .oneshot(empty_signed_request("POST", path))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
        }
        assert_eq!(counter.load(Ordering::SeqCst), 2);

        for (label, mut request) in [
            (
                "missing auth marker",
                empty_signed_request("POST", "/api/v1/auth/sessions/refresh"),
            ),
            (
                "missing signature",
                empty_signed_request("POST", "/api/v1/auth/sessions/refresh"),
            ),
            (
                "wrong method",
                empty_signed_request("GET", "/api/v1/auth/sessions/refresh"),
            ),
        ] {
            if label == "missing auth marker" {
                request.headers_mut().remove("x-gateway-auth");
            } else if label == "missing signature" {
                request.headers_mut().remove("x-gateway-signature");
            } else {
                // The signed path is unchanged, so changing this method invalidates v3.
                *request.method_mut() = axum::http::Method::GET;
            }
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{label}");
        }
        let mut wrong_path = empty_signed_request("POST", "/api/v1/auth/sessions/refresh");
        wrong_path.headers_mut().insert(
            "x-original-path",
            "/api/v1/auth/sessions/refresh-extra".parse().unwrap(),
        );
        resign_request(&mut wrong_path);
        *wrong_path.uri_mut() = "/api/v1/auth/sessions/refresh-extra".parse().unwrap();
        let response = app.clone().oneshot(wrong_path).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "wrong path");
        assert_eq!(counter.load(Ordering::SeqCst), 2);

        let mut wrong_original_path = empty_signed_request("POST", "/api/v1/auth/sessions/refresh");
        wrong_original_path.headers_mut().insert(
            "x-original-path",
            "/api/v1/auth/sessions/refresh-extra".parse().unwrap(),
        );
        resign_request(&mut wrong_original_path);
        let response = app.clone().oneshot(wrong_original_path).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "wrong signed path"
        );
        assert_eq!(counter.load(Ordering::SeqCst), 2);

        for extreme_timestamp in [i64::MIN, i64::MAX] {
            let mut extreme = empty_signed_request("POST", "/api/v1/auth/sessions/refresh");
            extreme.headers_mut().insert(
                "x-gateway-ts",
                extreme_timestamp.to_string().parse().unwrap(),
            );
            resign_request(&mut extreme);
            let response = app.clone().oneshot(extreme).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "extreme timestamp {extreme_timestamp}"
            );
        }
        assert_eq!(counter.load(Ordering::SeqCst), 2);

        let mut partial_identity = empty_signed_request("POST", "/api/v1/auth/sessions/refresh");
        partial_identity
            .headers_mut()
            .insert("x-principal-kind", "APP_USER".parse().unwrap());
        resign_request(&mut partial_identity);
        let response = app.clone().oneshot(partial_identity).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(counter.load(Ordering::SeqCst), 2);

        let mut refresh_partial_user =
            empty_signed_request("POST", "/api/v1/auth/sessions/refresh");
        refresh_partial_user
            .headers_mut()
            .insert("x-user-id", "42".parse().unwrap());
        resign_request(&mut refresh_partial_user);
        let response = app.clone().oneshot(refresh_partial_user).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "partial user");
        assert_eq!(counter.load(Ordering::SeqCst), 2);

        let mut protected_route = empty_signed_request("POST", "/api/v1/auth/profile");
        *protected_route.method_mut() = axum::http::Method::GET;
        *protected_route.uri_mut() = "/api/v1/auth/profile".parse().unwrap();
        protected_route
            .headers_mut()
            .insert("x-original-path", "/api/v1/auth/profile".parse().unwrap());
        resign_request(&mut protected_route);
        let response = app.clone().oneshot(protected_route).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let mut valid_platform = empty_signed_request("GET", "/api/v1/auth/profile");
        *valid_platform.uri_mut() = "/api/v1/auth/profile".parse().unwrap();
        *valid_platform.method_mut() = axum::http::Method::GET;
        valid_platform
            .headers_mut()
            .insert("x-original-path", "/api/v1/auth/profile".parse().unwrap());
        for (name, value) in [
            ("x-user-id", "42"),
            ("x-principal-kind", "PLATFORM_USER"),
            ("x-token-id", "access-jti"),
            ("x-identity-card-id", "10"),
            ("x-user-card-id", "40"),
            ("x-user-card-domain-id", "30"),
            ("x-user-card-tenant-id", "20"),
            ("x-token-use", "ACCESS"),
            ("x-claims-version", "2"),
        ] {
            valid_platform
                .headers_mut()
                .insert(name, value.parse().unwrap());
        }
        resign_request(&mut valid_platform);
        let response = app.clone().oneshot(valid_platform).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(counter.load(Ordering::SeqCst), 3);

        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(body.as_ref(), b"protected-marker");
    }

    #[test]
    fn identity_empty_transport_allowlist_is_exact_and_method_bound() {
        for path in [
            "/api/v1/auth/sessions",
            "/api/v1/auth/register",
            "/api/v1/auth/password/forgot",
            "/api/v1/auth/password/reset/token",
            "/api/v1/auth/verification/send",
            "/api/v1/auth/verification/verify",
            "/api/v1/auth/sessions/refresh",
            "/api/v1/auth/sessions/switch-card",
            "/api/v1/auth/sessions/logout",
            "/api/v1/auth/sessions/revoke",
        ] {
            assert!(is_identity_empty_signed_transport("POST", path), "{path}");
            assert!(!is_identity_empty_signed_transport("GET", path), "{path}");
        }
        for path in [
            "/api/v1/auth/register/extra",
            "/api/v1/auth/password/reset",
            "/api/v1/auth/password/reset/token/extra",
            "/api/v1/auth/password/reset/token/extra",
            "/api/v1/auth/sessions/refresh-extra",
            "/api/v1/auth/profile",
            "/api/v1/auth/mfa/verify",
        ] {
            assert!(!is_identity_empty_signed_transport("POST", path), "{path}");
        }
    }

    #[test]
    fn signature_is_deterministic_for_same_payload() {
        let sig1 = baseline_signature();
        let sig2 = baseline_signature();
        assert_eq!(sig1, sig2);
        assert!(constant_time_eq(sig1.as_bytes(), sig2.as_bytes()));
    }

    #[test]
    fn method_change_produces_different_signature() {
        let baseline = baseline_signature();
        let altered = compute_hmac_signature_v3(
            SECRET,
            "POST",
            "/v1/app/learn/progress/12",
            "42",
            "PLATFORM_USER",
            "jti-abc",
            "identity-card",
            "user-card",
            "user-domain",
            "user-tenant",
            "ACCESS",
            "2",
            "read",
            "USER",
            "1700000000000",
        );
        assert_ne!(baseline, altered);
    }

    #[test]
    fn path_change_produces_different_signature() {
        let baseline = baseline_signature();
        let altered = compute_hmac_signature_v3(
            SECRET,
            "GET",
            "/v1/app/learn/progress/13",
            "42",
            "PLATFORM_USER",
            "jti-abc",
            "identity-card",
            "user-card",
            "user-domain",
            "user-tenant",
            "ACCESS",
            "2",
            "read",
            "USER",
            "1700000000000",
        );
        assert_ne!(baseline, altered);
    }

    #[test]
    fn user_id_change_produces_different_signature() {
        // 客户端伪造身份头不能覆盖 JWT 身份：签名包含 user_id，
        // 篡改 x-user-id 会导致签名不匹配 → GATEWAY_SIGNATURE_MISMATCH。
        let baseline = baseline_signature();
        let altered = compute_hmac_signature_v3(
            SECRET,
            "GET",
            "/v1/app/learn/progress/12",
            "43",
            "PLATFORM_USER",
            "jti-abc",
            "identity-card",
            "user-card",
            "user-domain",
            "user-tenant",
            "ACCESS",
            "2",
            "read",
            "USER",
            "1700000000000",
        );
        assert_ne!(baseline, altered);
    }

    #[test]
    fn principal_kind_change_produces_different_signature() {
        // principal_kind 是 v3 canonical payload 的一部分：
        // 篡改 x-principal-kind 会导致签名不匹配 → GATEWAY_SIGNATURE_MISMATCH。
        let baseline = baseline_signature();
        let altered = compute_hmac_signature_v3(
            SECRET,
            "GET",
            "/v1/app/learn/progress/12",
            "42",
            "APP_USER",
            "jti-abc",
            "identity-card",
            "user-card",
            "user-domain",
            "user-tenant",
            "ACCESS",
            "2",
            "read",
            "USER",
            "1700000000000",
        );
        assert_ne!(baseline, altered);
    }

    #[test]
    fn timestamp_change_produces_different_signature() {
        let baseline = baseline_signature();
        let altered = compute_hmac_signature_v3(
            SECRET,
            "GET",
            "/v1/app/learn/progress/12",
            "42",
            "PLATFORM_USER",
            "jti-abc",
            "identity-card",
            "user-card",
            "user-domain",
            "user-tenant",
            "ACCESS",
            "2",
            "read",
            "USER",
            "1700000000001",
        );
        assert_ne!(baseline, altered);
    }

    #[test]
    fn secret_change_produces_different_signature() {
        let baseline = baseline_signature();
        let altered = compute_hmac_signature_v3(
            "another-secret-at-least-32-chars-long!",
            "GET",
            "/v1/app/learn/progress/12",
            "42",
            "PLATFORM_USER",
            "jti-abc",
            "identity-card",
            "user-card",
            "user-domain",
            "user-tenant",
            "ACCESS",
            "2",
            "read",
            "USER",
            "1700000000000",
        );
        assert_ne!(baseline, altered);
    }

    #[test]
    fn timestamp_skew_check_rejects_extreme_values_without_overflow() {
        for timestamp_ms in [i64::MIN, i64::MAX] {
            assert!(!timestamp_within_tolerance(0, timestamp_ms, 30_000));
        }
        assert!(!timestamp_within_tolerance(i64::MIN, i64::MAX, 30_000));
        assert!(!timestamp_within_tolerance(i64::MAX, i64::MIN, 30_000));
        assert!(!timestamp_within_tolerance(100_000, 100_001, 0));
        assert!(timestamp_within_tolerance(100_000, 100_030, 30));
        assert!(!timestamp_within_tolerance(100_000, 100_031, 30));
    }

    #[test]
    fn constant_time_eq_rejects_unequal_lengths() {
        assert!(!constant_time_eq(b"a", b"ab"));
        assert!(!constant_time_eq(b"", b"a"));
    }

    #[test]
    fn constant_time_eq_rejects_equal_length_but_different_bytes() {
        let baseline = baseline_signature();
        let mut tampered = baseline.clone();
        // 翻转最后一个字符以制造差异
        let last = tampered.pop().unwrap();
        let flipped = if last == '0' { '1' } else { '0' };
        tampered.push(flipped);
        assert!(!constant_time_eq(baseline.as_bytes(), tampered.as_bytes()));
    }

    /// 固定 v3 golden vector：锁定 canonical payload 与字段顺序，
    /// 防止后续修改（如字段增删、顺序调整）在未察觉的情况下改变签名语义。
    /// 该值由本实现独立计算，不声称与任何 Java legacy 黄金值相等。
    #[test]
    fn v3_golden_vector_is_stable() {
        let signature = baseline_signature();
        assert_eq!(
            signature,
            "dab71988d282189ecdfe643fb112034d9d0b5c1df3e1906781f73f729bd65b46"
        );
    }
}
