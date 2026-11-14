//! 路由转发处理器
//!
//! 使用 reqwest 将请求代理转发到后端服务，保持原始请求的方法、头、体。
//! 集成了：
//! - 断路器模式：连续失败超过阈值后直接返回 503
//! - HMAC-SHA256 签名注入（X-Gateway-Signature）
//! - X-Original-Path 注入

use std::time::{Duration, SystemTime};

use super::circuit_breaker::{CircuitBreaker, RequestPermit};

use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::{Stream, StreamExt};

use astral_authorization_root::memory_v1_request::RequestRootBudget;
use astral_authorization_root::memory_v1_root::RootHandle;
use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionVerifier;
use astral_common::config::AppConfig;
use astral_common::middleware::gateway_signature::{
    compute_hmac_signature_v3, InProcessGatewayIssuer,
};
use astral_common::middleware::permission_check_shared::AuthorizationPendingRefusal;
use axum::Router;
use tower::ServiceExt;

/// HTTP 客户端（连接池复用）
static CLIENT: once_cell::sync::Lazy<reqwest::Client> = once_cell::sync::Lazy::new(|| {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        // The proxy relays content-encoding and bytes together; decoding only the
        // body would change upstream representations and invalidate length headers.
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .connect_timeout(std::time::Duration::from_secs(3))
        // 对齐 Java Gateway application.yml `response-timeout: 30s`（路由转发响应超时）
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("reqwest Client")
});

/// Bounded collection cap for JSON/HTTP upstream responses. Large media and
/// streaming endpoints need an explicit streaming proxy contract before widening.
const MAX_UPSTREAM_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Client Bearer credentials are needed by Identity's session handlers, but
/// must not become a general-purpose downstream credential forwarding path.
fn is_canonical_session_bearer_route(method: &axum::http::Method, path: &str) -> bool {
    *method == axum::http::Method::POST
        && matches!(
            path,
            "/api/v1/auth/sessions/refresh"
                | "/api/v1/auth/sessions/switch-card"
                | "/api/v1/auth/sessions/logout"
                | "/api/v1/auth/sessions/revoke"
        )
}

fn is_public_identity_empty_bootstrap(method: &axum::http::Method, path: &str) -> bool {
    *method == axum::http::Method::POST
        && (matches!(
            path,
            "/api/v1/auth/sessions"
                | "/api/v1/auth/register"
                | "/api/v1/auth/password/forgot"
                | "/api/v1/auth/password/reset/token"
                | "/api/v1/auth/verification/send"
                | "/api/v1/auth/verification/verify"
        ) || path
            .strip_prefix("/api/v1/auth/password/reset/")
            .is_some_and(|token| !token.is_empty() && !token.contains('/')))
}

fn is_non_empty_bearer(value: &str) -> bool {
    value
        .strip_prefix("Bearer ")
        .is_some_and(|token| !token.trim().is_empty())
}

async fn collect_bounded_response_body<S, E>(
    chunks: S,
    declared_length: Option<u64>,
    limit: usize,
) -> Result<bytes::Bytes, BoundedBodyError>
where
    S: Stream<Item = Result<bytes::Bytes, E>>,
{
    if declared_length.is_some_and(|length| length > limit as u64) {
        return Err(BoundedBodyError::TooLarge);
    }

    let mut body = bytes::BytesMut::new();
    let mut chunks = Box::pin(chunks);
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk.map_err(|_| BoundedBodyError::Read)?;
        if chunk.len() > limit.saturating_sub(body.len()) {
            return Err(BoundedBodyError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body.freeze())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BoundedBodyError {
    TooLarge,
    Read,
}

// memory—v1: Connection nominates additional hop-by-hop fields for this message.
fn connection_header_names(headers: &HeaderMap) -> Result<Vec<HeaderName>, ()> {
    let mut names = Vec::new();
    for value in headers.get_all(axum::http::header::CONNECTION) {
        let value = value.to_str().map_err(|_| ())?;
        for name in value.split(',') {
            let name = name.trim();
            if name.is_empty() {
                return Err(());
            }
            names.push(HeaderName::from_bytes(name.as_bytes()).map_err(|_| ())?);
        }
    }
    Ok(names)
}

// memory—v1: A proxy must not carry hop-by-hop metadata across either leg.
fn is_hop_by_hop_header(name: &HeaderName, nominated: &[HeaderName]) -> bool {
    nominated.contains(name)
        || matches!(
            name.as_str(),
            "connection"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "proxy-connection"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
        )
}

fn should_forward_client_header(
    method: &axum::http::Method,
    path: &str,
    key: &str,
    value: &axum::http::HeaderValue,
) -> bool {
    if key.eq_ignore_ascii_case("authorization") {
        return is_canonical_session_bearer_route(method, path)
            && value.to_str().is_ok_and(is_non_empty_bearer);
    }
    if is_public_identity_empty_bootstrap(method, path)
        && crate::middleware::is_sensitive_auth_header(key)
    {
        return false;
    }
    if is_canonical_session_bearer_route(method, path)
        && matches!(
            key.to_ascii_lowercase().as_str(),
            "x-gateway-auth"
                | "x-gateway-ts"
                | "x-gateway-signature"
                | "x-original-path"
                | "x-user-id"
                | "x-principal-kind"
                | "x-token-id"
                | "x-identity-card-id"
                | "x-user-card-id"
                | "x-user-card-domain-id"
                | "x-user-card-tenant-id"
                | "x-token-use"
                | "x-claims-version"
                | "x-action-codes"
                | "x-user-roles"
                | "x-template-id"
                | "x-tenant-status"
                | "x-perms-ref"
                | "x-permissions-truncated"
        )
    {
        return false;
    }
    !crate::middleware::is_proxy_forbidden_header(key)
}

/// memory—v1: Default bound on concurrently live in-process request scopes.
///
/// Each live scope may pin one immutable root phase. Exhaustion is rejected
/// immediately (503) rather than queued. This candidate default is not a
/// capacity-validated production setting.
pub const DEFAULT_MAX_ACTIVE_REQUEST_SCOPES: usize = 1024;

// memory—v1: Trusted composition supplies separate in-process targets and the root handle.
#[derive(Clone)]
pub(crate) struct InProcessTargets {
    identity: Router,
    trustgraph: Router,
    identity_issuer: std::sync::Arc<InProcessGatewayIssuer>,
    trustgraph_issuer: std::sync::Arc<InProcessGatewayIssuer>,
    root: RootHandle,
    session_verifier: MemoryV1SessionVerifier,
    scope_budget: RequestRootBudget,
}

impl InProcessTargets {
    /// memory—v1: Bind downstream routes to the composition's source and read capabilities.
    pub(crate) fn new(
        identity: Router,
        trustgraph: Router,
        identity_issuer: std::sync::Arc<InProcessGatewayIssuer>,
        trustgraph_issuer: std::sync::Arc<InProcessGatewayIssuer>,
        root: RootHandle,
    ) -> Self {
        Self::with_session_verifier(
            identity,
            trustgraph,
            identity_issuer,
            trustgraph_issuer,
            root,
            MemoryV1SessionVerifier::deny_all(),
        )
    }

    /// memory—v1: Construct targets with the Identity-owned session verifier.
    pub(crate) fn with_session_verifier(
        identity: Router,
        trustgraph: Router,
        identity_issuer: std::sync::Arc<InProcessGatewayIssuer>,
        trustgraph_issuer: std::sync::Arc<InProcessGatewayIssuer>,
        root: RootHandle,
        session_verifier: MemoryV1SessionVerifier,
    ) -> Self {
        Self::with_session_verifier_and_budget(
            identity,
            trustgraph,
            identity_issuer,
            trustgraph_issuer,
            root,
            session_verifier,
            RequestRootBudget::new(DEFAULT_MAX_ACTIVE_REQUEST_SCOPES),
        )
    }

    /// memory—v1: Construct targets that admit request scopes through `scope_budget`.
    pub(crate) fn with_session_verifier_and_budget(
        identity: Router,
        trustgraph: Router,
        identity_issuer: std::sync::Arc<InProcessGatewayIssuer>,
        trustgraph_issuer: std::sync::Arc<InProcessGatewayIssuer>,
        root: RootHandle,
        session_verifier: MemoryV1SessionVerifier,
        scope_budget: RequestRootBudget,
    ) -> Self {
        Self {
            identity,
            trustgraph,
            identity_issuer,
            trustgraph_issuer,
            root,
            session_verifier,
            scope_budget,
        }
    }

    /// memory—v1: The composition's verifier; it can validate but never mint sessions.
    pub(crate) fn session_verifier(&self) -> &MemoryV1SessionVerifier {
        &self.session_verifier
    }
}

static CB_IDENTITY: CircuitBreaker = CircuitBreaker::new();
static CB_TRUSTGRAPH: CircuitBreaker = CircuitBreaker::new();
static CB_MONITOR: CircuitBreaker = CircuitBreaker::new();

/// 转发到 Identity 服务（静态路径由调用方路由保证已注册）。
pub async fn forward_to_identity_static(State(config): State<AppConfig>, req: Request) -> Response {
    let full_path = req.uri().path().to_string();
    forward_identity_path(config, full_path, req).await
}

pub async fn forward_to_identity_password_reset(
    State(config): State<AppConfig>,
    Path(token): Path<String>,
    req: Request,
) -> Response {
    forward_identity_path(config, identity_password_reset_path(&token), req).await
}

fn identity_password_reset_path(token: &str) -> String {
    format!("/api/v1/auth/password/reset/{token}")
}

pub async fn forward_to_identity_sessions_root(
    State(config): State<AppConfig>,
    req: Request,
) -> Response {
    forward_identity_path(config, "/api/v1/auth/sessions".into(), req).await
}

// memory—v1: Hold the upstream permit through dispatch and response classification.
async fn forward_identity_path(config: AppConfig, full_path: String, req: Request) -> Response {
    let Some(permit) = CB_IDENTITY.acquire() else {
        return json_error(
            req.method().as_str(),
            req.uri().path(),
            request_trace_id(&req),
            503,
            "Identity service unavailable (circuit breaker)",
            "SERVICE_UNAVAILABLE",
        );
    };
    let identity_uri = config.identity_service_uri.as_str();
    let response = if let Some(targets) = req.extensions().get::<InProcessTargets>().cloned() {
        forward_in_process(
            &config,
            req,
            &targets,
            targets.identity.clone(),
            &targets.identity_issuer,
            SessionTransport::LegacyOnly,
        )
        .await
    } else {
        forward(&config, identity_uri, &full_path, req).await
    };
    settle(permit, &response);
    response
}

/// memory—v1: Forward through the TrustGraph circuit's request-scoped permit.
pub async fn forward_to_trustgraph(
    State(config): State<AppConfig>,
    Path(path): Path<String>,
    req: Request,
) -> Response {
    let Some(permit) = CB_TRUSTGRAPH.acquire() else {
        tracing::warn!("circuit breaker open for trustgraph service");
        return json_error(
            req.method().as_str(),
            req.uri().path(),
            request_trace_id(&req),
            503,
            "TrustGraph service unavailable (circuit breaker)",
            "SERVICE_UNAVAILABLE",
        );
    };
    let full_path = format!("/main/api/v1/{path}");
    let trustgraph_uri = config.trust_graph_uri.as_str();
    let response = if let Some(targets) = req.extensions().get::<InProcessTargets>().cloned() {
        forward_in_process(
            &config,
            req,
            &targets,
            targets.trustgraph.clone(),
            &targets.trustgraph_issuer,
            SessionTransport::MemoryV1Guarded,
        )
        .await
    } else {
        forward(&config, trustgraph_uri, &full_path, req).await
    };
    settle(permit, &response);
    response
}

/// 转发到 Monitor 服务。
/// memory—v1: Hold the circuit permit until the response is classified.
pub async fn forward_to_monitor(
    State(config): State<AppConfig>,
    Path(path): Path<String>,
    req: Request,
) -> Response {
    let Some(permit) = CB_MONITOR.acquire() else {
        tracing::warn!("circuit breaker open for monitor service");
        return json_error(
            req.method().as_str(),
            req.uri().path(),
            request_trace_id(&req),
            503,
            "Monitor service unavailable (circuit breaker)",
            "SERVICE_UNAVAILABLE",
        );
    };
    let full_path = format!("/api/v1/monitor/{path}");
    let monitor_uri = config.monitor_service_uri.as_str();
    let response = forward(&config, monitor_uri, &full_path, req).await;
    settle(permit, &response);
    response
}

// A transport-independent request prepared only after Gateway authentication.
// Header entries stay ordered and may repeat, matching reqwest's append semantics.
struct PreparedRequest {
    method: axum::http::Method,
    external_path: String,
    upstream_path_and_query: String,
    trace_id: Option<String>,
    headers: Vec<(HeaderName, String)>,
    body: bytes::Bytes,
    session_credential: Option<String>,
}

// memory—v1: Preserve the external path for signing while preparing the downstream request.
// This relies on the existing Gateway sanitization and authentication middleware;
// it is not an authentication entry point for arbitrary in-process callers.
async fn prepare_request(
    config: &AppConfig,
    path: &str,
    req: Request,
) -> Result<PreparedRequest, Box<Response>> {
    let (parts, body) = req.into_parts();
    let external_path = parts.uri.path().to_string();
    let method = parts.method.clone();
    let connection_names = match connection_header_names(&parts.headers) {
        Ok(names) => names,
        Err(()) => {
            return Err(Box::new(json_error(
                method.as_str(),
                &external_path,
                parts
                    .headers
                    .get("x-request-id")
                    .and_then(|v| v.to_str().ok()),
                400,
                "Invalid Connection header",
                "BAD_REQUEST",
            )));
        }
    };
    let identity_empty_bootstrap = is_public_identity_empty_bootstrap(&method, &external_path);
    // 保留原始请求的查询字符串
    let query = parts
        .uri
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let upstream_path_and_query = format!("{path}{query}");

    // 读取请求体
    let body_bytes = match axum::body::to_bytes(body, 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "Failed to read request body");
            return Err(Box::new(json_error(
                method.as_str(),
                &external_path,
                parts
                    .headers
                    .get("x-request-id")
                    .and_then(|v| v.to_str().ok()),
                400,
                &format!("Failed to read body: {e}"),
                "BAD_REQUEST",
            )));
        }
    };

    // Bootstrap endpoints validate credentials in their own handlers. Even a
    // valid optional ACCESS Bearer must not turn the login/body identity into a
    // gateway-authenticated principal or act as proof for another login actor.
    let extract_header = |name: &str| -> String {
        if identity_empty_bootstrap {
            return String::new();
        }
        parts
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .trim()
            .to_string()
    };

    let user_id = extract_header("x-user-id");
    let token_id = extract_header("x-token-id");
    let identity_card_id = extract_header("x-identity-card-id");
    let principal_kind = extract_header("x-principal-kind");
    let user_card_id = extract_header("x-user-card-id");
    let user_card_domain_id = extract_header("x-user-card-domain-id");
    let user_card_tenant_id = extract_header("x-user-card-tenant-id");
    let token_use = extract_header("x-token-use");
    let claims_version = extract_header("x-claims-version");
    let action_codes = extract_header("x-action-codes");
    let user_roles = extract_header("x-user-roles");
    let tenant_status = extract_header("x-tenant-status");
    let perms_ref = extract_header("x-perms-ref");
    let permissions_truncated = extract_header("x-permissions-truncated");

    // 计算 HMAC-SHA256 签名（v3：问题 1 修正后 payload 不含身份侧租户）
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .to_string();

    let signature = compute_hmac_signature_v3(
        &config.gateway.hmac_secret,
        method.as_str(),
        &external_path,
        &user_id,
        &principal_kind,
        &token_id,
        &identity_card_id,
        &user_card_id,
        &user_card_domain_id,
        &user_card_tenant_id,
        &token_use,
        &claims_version,
        &action_codes,
        &user_roles,
        &timestamp,
    );

    // Build an ordered list, preserving duplicate values and reqwest's text-only forwarding.
    let mut headers = Vec::new();
    for (key, value) in parts.headers.iter() {
        let key_str = key.as_str().to_lowercase();
        // Keep a client Bearer only for Identity's exact session operations.
        // All other sensitive, gateway, and hop-by-hop headers remain stripped.
        // Payload framing is regenerated from the buffered body by reqwest.
        if is_hop_by_hop_header(key, &connection_names)
            || key == axum::http::header::CONTENT_LENGTH
            || !should_forward_client_header(&method, &external_path, &key_str, value)
        {
            continue;
        }
        if let Ok(v) = value.to_str() {
            headers.push((key.clone(), v.to_string()));
        }
    }

    // The request headers above are untrusted input. Re-add only the identity
    // values extracted after JWT validation; these values are also bound into
    // the v3 signature sent to the downstream service.
    for (name, value) in [
        ("x-user-id", user_id.as_str()),
        ("x-token-id", token_id.as_str()),
        ("x-identity-card-id", identity_card_id.as_str()),
        ("x-principal-kind", principal_kind.as_str()),
        ("x-user-card-id", user_card_id.as_str()),
        ("x-user-card-domain-id", user_card_domain_id.as_str()),
        ("x-user-card-tenant-id", user_card_tenant_id.as_str()),
        ("x-token-use", token_use.as_str()),
        ("x-claims-version", claims_version.as_str()),
        ("x-action-codes", action_codes.as_str()),
        ("x-user-roles", user_roles.as_str()),
        ("x-tenant-status", tenant_status.as_str()),
        ("x-perms-ref", perms_ref.as_str()),
        ("x-permissions-truncated", permissions_truncated.as_str()),
    ] {
        if !value.is_empty() {
            headers.push((HeaderName::from_static(name), value.to_string()));
        }
    }

    // 注入网关签名头（覆盖任何残留值）
    for (name, value) in [
        ("x-gateway-auth", "verified"),
        ("x-gateway-ts", timestamp.as_str()),
        ("x-gateway-signature", signature.as_str()),
        ("x-original-path", external_path.as_str()),
    ] {
        headers.push((HeaderName::from_static(name), value.to_string()));
    }

    let trace_id = parts
        .headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let session_credential = if is_public_identity_empty_bootstrap(&method, &external_path) {
        None
    } else {
        parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    };
    Ok(PreparedRequest {
        method,
        external_path,
        upstream_path_and_query,
        trace_id,
        headers,
        body: body_bytes,
        session_credential,
    })
}

// memory—v1: Apply the same response limits and hop-by-hop filtering to either transport.
async fn finish_upstream_response<S, E>(
    prepared: &PreparedRequest,
    status: StatusCode,
    resp_headers: HeaderMap,
    declared_length: Option<u64>,
    chunks: S,
) -> Response
where
    S: Stream<Item = Result<bytes::Bytes, E>>,
{
    let method = &prepared.method;
    let external_path = &prepared.external_path;
    let trace_id = prepared.trace_id.as_deref();
    let response_connection_names = match connection_header_names(&resp_headers) {
        Ok(names) => names,
        Err(()) => {
            return json_error(
                method.as_str(),
                external_path,
                trace_id,
                502,
                "Invalid upstream Connection header",
                "BAD_GATEWAY",
            );
        }
    };
    let resp_body =
        match collect_bounded_response_body(chunks, declared_length, MAX_UPSTREAM_RESPONSE_BYTES)
            .await
        {
            Ok(body) => body,
            Err(_) => {
                tracing::warn!(
                    method = %method,
                    path = %external_path,
                    "upstream response read failed or exceeded the configured size limit"
                );
                return json_error(
                    method.as_str(),
                    external_path,
                    trace_id,
                    502,
                    "Upstream response read failed or exceeded the configured size limit",
                    "BAD_GATEWAY",
                );
            }
        };

    let mut response_builder = Response::builder().status(status);
    for (key, value) in resp_headers.iter() {
        if is_hop_by_hop_header(key, &response_connection_names) {
            continue;
        }
        if let Ok(name) = HeaderName::from_bytes(key.as_str().as_bytes()) {
            response_builder = response_builder.header(name, value);
        }
    }
    response_builder
        .body(Body::from(resp_body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// memory—v1: Whether a downstream target may receive the memory—v1 session transport.
///
/// Only a target whose permission guard evaluates memory—v1 sessions (TrustGraph)
/// is `MemoryV1Guarded`. A `LegacyOnly` target keeps the legacy identity
/// requirements even when a verified session is bound, so its handlers never
/// see an identity-empty request on a protected route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionTransport {
    MemoryV1Guarded,
    LegacyOnly,
}

// memory—v1: Dispatch an authenticated Gateway request within the composed process.
async fn forward_in_process(
    config: &AppConfig,
    req: Request,
    targets: &InProcessTargets,
    router: Router,
    issuer: &InProcessGatewayIssuer,
    session_transport: SessionTransport,
) -> Response {
    // Both candidate downstream routers register the external path unchanged.
    // Preserve the raw encoding; Axum's extracted parameters are percent-decoded.
    let path = req.uri().path().to_owned();
    let client_ip = req
        .extensions()
        .get::<super::rate_limit::ResolvedClientIp>()
        .map(|client| client.0);
    let method = req.method().clone();
    let trace_id = request_trace_id(&req).map(str::to_owned);
    // memory—v1: Admit this request's root scope before buffering its body.
    // Exhaustion is rejected at once and never queued; the slot returns when the
    // scope and every reader lease of this request have been released.
    let scope = match targets
        .scope_budget
        .try_begin(targets.root.clone(), uuid::Uuid::new_v4())
    {
        Ok(scope) => scope,
        Err(_) => {
            return json_error(
                method.as_str(),
                &path,
                trace_id.as_deref(),
                503,
                "In-process request capacity exhausted",
                "SERVICE_UNAVAILABLE",
            )
        }
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let prepared =
        match tokio::time::timeout_at(deadline, prepare_request(config, &path, req)).await {
            Ok(Ok(prepared)) => prepared,
            Ok(Err(response)) => return *response,
            Err(_) => {
                return json_error(
                    method.as_str(),
                    &path,
                    trace_id.as_deref(),
                    408,
                    "Request body timed out",
                    "REQUEST_TIMEOUT",
                )
            }
        };
    let mut builder = Request::builder()
        .method(prepared.method.clone())
        .uri(&prepared.upstream_path_and_query);
    for (name, value) in &prepared.headers {
        builder = builder.header(name, value.as_str());
    }
    let mut downstream = match builder.body(Body::from(prepared.body.clone())) {
        Ok(request) => request,
        Err(_) => {
            return json_error(
                prepared.method.as_str(),
                &prepared.external_path,
                prepared.trace_id.as_deref(),
                502,
                "Invalid upstream request",
                "BAD_GATEWAY",
            )
        }
    };
    downstream.headers_mut().remove("x-real-ip");
    if let Some(client_ip) = client_ip {
        downstream
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(std::net::SocketAddr::new(
                client_ip, 0,
            )));
    }
    downstream.extensions_mut().insert(scope.extension());
    let memory_v1_session = if let Some(credential) = prepared.session_credential.as_deref() {
        let root = scope.extension();
        let session = match targets.session_verifier.verify_and_bind(
            credential,
            trusted_request_time(),
            &root,
        ) {
            Ok(session) => session,
            Err(_) => {
                return json_error(
                    prepared.method.as_str(),
                    &prepared.external_path,
                    prepared.trace_id.as_deref(),
                    503,
                    "Authenticated memory-v1 session unavailable",
                    "AUTHORIZATION_PENDING",
                )
            }
        };
        downstream.extensions_mut().insert(session);
        true
    } else {
        false
    };
    // memory—v1: Only a request whose verified session is bound to this exact
    // scope, dispatched to a memory—v1-guarded target, carries the session-
    // transport mark; every other dispatch keeps the legacy identity
    // requirements downstream.
    if memory_v1_session && session_transport == SessionTransport::MemoryV1Guarded {
        issuer.mark_memory_v1_session(&mut downstream);
    } else {
        issuer.mark(&mut downstream);
    }
    let result = tokio::time::timeout_at(deadline, async {
        let _scope = scope;
        let response = router
            .oneshot(downstream)
            .await
            .expect("Router is infallible");
        let (parts, body) = response.into_parts();
        // memory—v1: Read the guard's mark before the rebuild below drops the extensions.
        let guard_refusal = session_transport == SessionTransport::MemoryV1Guarded
            && parts.status == StatusCode::SERVICE_UNAVAILABLE
            && AuthorizationPendingRefusal::is_attached(&parts.extensions);
        let declared_length = parts
            .headers
            .get(axum::http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok());
        let mut response = finish_upstream_response(
            &prepared,
            parts.status,
            parts.headers,
            declared_length,
            body.into_data_stream(),
        )
        .await;
        // memory—v1: Only a guard-attached 503 from a memory-v1 target is exempt, and only
        // after the dispatcher has verified the mark above.
        if guard_refusal && response.status() == StatusCode::SERVICE_UNAVAILABLE {
            response.extensions_mut().insert(VerifiedPendingRefusal);
        }
        response
    })
    .await;
    match result {
        Ok(response) => response,
        Err(_) => json_error(
            prepared.method.as_str(),
            &prepared.external_path,
            prepared.trace_id.as_deref(),
            502,
            "Upstream request failed",
            "BAD_GATEWAY",
        ),
    }
}

// memory—v1: The production HTTP transport consumes the same prepared request.
async fn forward(config: &AppConfig, base_uri: &str, path: &str, req: Request) -> Response {
    let prepared = match prepare_request(config, path, req).await {
        Ok(prepared) => prepared,
        Err(response) => return *response,
    };
    let uri = format!(
        "{}{}",
        base_uri.trim_end_matches('/'),
        prepared.upstream_path_and_query
    );
    let mut forwarded = CLIENT.request(prepared.method.clone(), &uri);
    for (name, value) in &prepared.headers {
        forwarded = forwarded.header(name.as_str(), value.as_str());
    }
    if !prepared.body.is_empty() {
        forwarded = forwarded.body(prepared.body.to_vec());
    }

    let method = &prepared.method;
    let external_path = &prepared.external_path;
    let trace_id = prepared.trace_id.as_deref();
    // 发送请求并接收响应
    match forwarded.send().await {
        Ok(response) => {
            let status = response.status();
            let resp_headers = response.headers().clone();
            let declared_length = response.content_length();
            finish_upstream_response(
                &prepared,
                status,
                resp_headers,
                declared_length,
                response.bytes_stream(),
            )
            .await
        }
        Err(error) => {
            tracing::warn!(
                method = %method,
                path = %external_path,
                error_kind = %error.without_url(),
                "upstream request failed"
            );
            json_error(
                method.as_str(),
                external_path,
                trace_id,
                502,
                "Upstream request failed",
                "BAD_GATEWAY",
            )
        }
    }
}

fn trusted_request_time() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or(i64::MAX)
}

fn dependency_failure(status: reqwest::StatusCode) -> bool {
    matches!(status.as_u16(), 502..=504)
}

/// memory—v1: Attached by the gateway only, after the in-process dispatcher verified the
/// `AuthorizationPendingRefusal` mark on a memory-v1 target's 503. Clients and HTTP
/// upstreams cannot set it, because it is a response extension and never serialized.
#[derive(Clone, Copy)]
struct VerifiedPendingRefusal;

/// memory—v1: Settle one upstream permit from the response it produced. A verified guard
/// refusal is a healthy answer; every other 502-504 remains an upstream failure.
fn settle(permit: RequestPermit<'_>, response: &Response) {
    if circuit_failure(response) {
        permit.record_failure();
    } else {
        permit.record_success();
    }
}

fn circuit_failure(response: &Response) -> bool {
    if response.status() == StatusCode::SERVICE_UNAVAILABLE
        && response
            .extensions()
            .get::<VerifiedPendingRefusal>()
            .is_some()
    {
        return false;
    }
    dependency_failure(response.status())
}

/// 统一 JSON 错误响应（对齐 Java `JwtGlobalFilter.writeErrorResponse`）
///
/// Java 基线响应体：code/message/traceId/requestPath/requestMethod/errorType/decision/
/// reasonCode，并回写 `X-Trace-Id` 响应头。traceId 优先复用 JWT 中间件注入的
/// `x-request-id`，缺失时生成网关自有值；decision/reasonCode 沿用 error_type
/// （网关自有 4xx/5xx 场景与 Java `unavailable()`/`badRequest()` 语义一致）。
fn json_error(
    method: &str,
    path: &str,
    trace_id: Option<&str>,
    status: u16,
    message: &str,
    error_type: &str,
) -> Response {
    let trace_id = trace_id.map(str::to_string).unwrap_or_else(|| {
        format!(
            "req-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        )
    });
    let body = serde_json::json!({
        "code": status,
        "message": message,
        "traceId": trace_id,
        "requestPath": path,
        "requestMethod": method,
        "errorType": error_type,
        "decision": error_type,
        "reasonCode": error_type,
    });
    Response::builder()
        .status(StatusCode::from_u16(status).unwrap())
        .header("X-Trace-Id", &trace_id)
        .header("Content-Type", "application/json;charset=UTF-8")
        .body(Body::from(body.to_string()))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// 从请求上下文提取 traceId（JWT 中间件已注入 x-request-id）。
fn request_trace_id(req: &Request) -> Option<&str> {
    req.headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
}

#[cfg(test)]
mod client_header_policy_tests {
    use super::*;
    use axum::http::HeaderValue;

    // memory—v1: A gateway test response with a status and an optional verified mark.
    fn upstream_response(status: u16, verified: bool) -> Response {
        let mut response = StatusCode::from_u16(status).unwrap().into_response();
        if verified {
            response.extensions_mut().insert(VerifiedPendingRefusal);
        }
        response
    }

    #[test]
    fn circuit_exempts_only_verified_pending_refusals() {
        assert!(!circuit_failure(&upstream_response(503, true)));
        assert!(circuit_failure(&upstream_response(503, false)));
        assert!(circuit_failure(&upstream_response(502, true)));
        assert!(circuit_failure(&upstream_response(504, true)));
        assert!(!circuit_failure(&upstream_response(403, false)));
    }

    #[test]
    fn verified_pending_refusals_never_open_the_circuit() {
        let breaker = CircuitBreaker::new();
        for _ in 0..12 {
            let permit = breaker
                .acquire()
                .expect("verified refusals keep the circuit closed");
            settle(permit, &upstream_response(503, true));
        }
        assert!(breaker.acquire().is_some());
        for _ in 0..5 {
            let permit = breaker
                .acquire()
                .expect("the circuit opens only at the failure threshold");
            settle(permit, &upstream_response(503, false));
        }
        assert!(breaker.acquire().is_none());
    }

    // memory—v1: Body and downstream share a deadline; expiry revokes the reader scope.
    #[tokio::test(start_paused = true)]
    async fn in_process_body_and_downstream_share_one_deadline() {
        use astral_authorization_root::memory_v1_db_rows::CandidateRows;
        use astral_authorization_root::memory_v1_hamt::CandidateBudget;
        use astral_authorization_root::memory_v1_request::{
            RequestRootAccessError, RequestRootExtension,
        };
        use astral_authorization_root::memory_v1_root::install_process_root;
        use axum::extract::Extension;
        use axum::routing::post;
        use std::sync::{Arc, Mutex};

        // The process root is install-once, so run this test in a fresh process.
        const CHILD: &str = "ASTRAL_MEMORY_V1_DEADLINE_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "runtime::proxy::client_header_policy_tests::in_process_body_and_downstream_share_one_deadline",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
            return;
        }

        let owner = install_process_root(
            CandidateRows::default(),
            vec![],
            CandidateBudget {
                max_table_rows: 16,
                max_bindings_per_read: 4,
            },
        )
        .unwrap();
        let captured: Arc<Mutex<Option<RequestRootExtension>>> = Arc::new(Mutex::new(None));
        let downstream_captured = Arc::clone(&captured);
        let downstream = Router::new().route(
            "/api/v1/auth/sessions",
            post(move |Extension(root): Extension<RequestRootExtension>| {
                let captured = Arc::clone(&downstream_captured);
                async move {
                    root.with_reader(|_| ()).unwrap();
                    *captured.lock().unwrap() = Some(root);
                    std::future::pending::<StatusCode>().await
                }
            }),
        );
        let (issuer, _) = astral_common::middleware::gateway_signature::in_process_gateway_source();
        let targets = InProcessTargets::new(
            downstream.clone(),
            Router::new(),
            Arc::new(issuer),
            Arc::new(astral_common::middleware::gateway_signature::in_process_gateway_source().0),
            owner.handle(),
        );
        let config = AppConfig::default();
        let body = Body::from_stream(futures_util::stream::once(async {
            tokio::time::sleep(Duration::from_secs(20)).await;
            Ok::<_, std::convert::Infallible>(bytes::Bytes::from_static(b"body"))
        }));
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/sessions")
            .body(body)
            .unwrap();
        let task = tokio::spawn(async move {
            forward_in_process(
                &config,
                req,
                &targets,
                downstream,
                &targets.identity_issuer,
                SessionTransport::LegacyOnly,
            )
            .await
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(20)).await;
        tokio::task::yield_now().await;
        let root = captured
            .lock()
            .unwrap()
            .clone()
            .expect("downstream received reader");
        assert!(root.with_reader(|_| ()).is_ok());
        tokio::time::advance(Duration::from_secs(11)).await;
        assert_eq!(task.await.unwrap().status(), StatusCode::BAD_GATEWAY);
        assert!(matches!(
            root.with_reader(|_| ()),
            Err(RequestRootAccessError::ScopeEnded)
        ));
    }

    // memory—v1: Check each message's explicit and nominated hop-by-hop fields.
    #[test]
    fn connection_scoped_fields_are_removed_and_invalid_lists_rejected() {
        let mut headers = HeaderMap::new();
        headers.append(
            "connection",
            HeaderValue::from_static("keep-alive, X-Private"),
        );
        headers.append("connection", HeaderValue::from_static("x-second"));
        let names = connection_header_names(&headers).unwrap();
        for name in [
            "x-private",
            "x-second",
            "keep-alive",
            "te",
            "proxy-authorization",
            "trailer",
            "transfer-encoding",
        ] {
            assert!(is_hop_by_hop_header(
                &HeaderName::from_bytes(name.as_bytes()).unwrap(),
                &names
            ));
        }
        assert!(!is_hop_by_hop_header(
            &HeaderName::from_static("content-type"),
            &names
        ));
        headers.append("connection", HeaderValue::from_static("good, bad name"));
        assert!(connection_header_names(&headers).is_err());
    }

    // memory—v1: Sensitive cookies cannot cross the gateway's client boundary.
    #[test]
    fn client_cookie_is_not_forwarded_even_on_session_routes() {
        assert!(!should_forward_client_header(
            &axum::http::Method::POST,
            "/api/v1/auth/sessions/refresh",
            "cookie",
            &HeaderValue::from_static("session=secret"),
        ));
    }

    // memory—v1: Exercise both proxy legs and redirect behavior over an isolated listener.
    #[tokio::test]
    async fn proxy_preserves_body_filters_connection_headers_and_does_not_follow_redirects() {
        use axum::body::to_bytes;
        use axum::routing::{get, post};
        use axum::{Json, Router};
        use serde_json::json;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        struct ServerGuard(tokio::task::JoinHandle<()>);
        impl Drop for ServerGuard {
            fn drop(&mut self) {
                self.0.abort();
            }
        }

        let redirect_hits = Arc::new(AtomicUsize::new(0));
        let sink_hits = redirect_hits.clone();
        let app = Router::new()
            .route(
                "/inspect",
                post(|headers: HeaderMap, body: bytes::Bytes| async move {
                    let report = json!({
                        "body": String::from_utf8_lossy(&body),
                        "private": headers.get("x-private").is_some(),
                        "cookie": headers.get("cookie").is_some(),
                        "template": headers.get("x-template-id").is_some(),
                        "contentLength": headers.get("content-length").and_then(|v| v.to_str().ok()),
                    });
                    (
                        [("connection", "x-upstream-private"), ("x-upstream-private", "secret")],
                        Json(report),
                    )
                }),
            )
            .route(
                "/redirect",
                get(|| async { (StatusCode::TEMPORARY_REDIRECT, [("location", "/sink")]) }),
            )
            .route(
                "/sink",
                get(move || {
                    let hits = sink_hits.clone();
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        StatusCode::OK
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let _server = ServerGuard(tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        }));
        let base_uri = format!("http://{address}");
        let config = AppConfig::default();
        let request = Request::builder()
            .method("POST")
            .uri("/inspect")
            .header("connection", "x-private")
            .header("x-private", "secret")
            .header("cookie", "session=secret")
            .header("x-template-id", "obsolete-template")
            .header("content-length", "7")
            .body(Body::from("payload"))
            .unwrap();
        let response = forward(&config, &base_uri, "/inspect", request).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key("connection"));
        assert!(!response.headers().contains_key("x-upstream-private"));
        let report: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(report["body"], "payload");
        assert_eq!(report["private"], false);
        assert_eq!(report["cookie"], false);
        assert_eq!(report["template"], false);
        assert_eq!(report["contentLength"], "7");

        let request = Request::builder()
            .uri("/redirect")
            .body(Body::empty())
            .unwrap();
        let response = forward(&config, &base_uri, "/redirect", request).await;
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(response.headers().get("location").unwrap(), "/sink");
        assert_eq!(redirect_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn gateway_proxy_and_identity_v3_verifier_share_empty_refresh_contract() {
        use axum::body::to_bytes;
        use axum::routing::post;
        use axum::{middleware, Json, Router};
        use serde_json::json;

        let config = AppConfig {
            gateway: astral_common::config::GatewayCfg {
                hmac_secret: "gateway-proxy-contract-test-secret-0123456789".into(),
                timestamp_tolerance_secs: 30,
                ..Default::default()
            },
            ..Default::default()
        };
        let app = Router::new()
            .route(
                "/api/v1/auth/sessions",
                post(|headers: HeaderMap| async move {
                    Json(json!({
                        "authorization": headers.get("authorization").and_then(|v| v.to_str().ok()),
                        "userId": headers.get("x-user-id").and_then(|v| v.to_str().ok()),
                        "gatewayAuth": headers.get("x-gateway-auth").and_then(|v| v.to_str().ok()),
                    }))
                }),
            )
            .route(
                "/api/v1/auth/sessions/refresh",
                post(|headers: HeaderMap| async move {
                    Json(json!({
                        "authorization": headers.get("authorization").and_then(|v| v.to_str().ok()),
                        "userId": headers.get("x-user-id").and_then(|v| v.to_str().ok()),
                        "principalKind": headers.get("x-principal-kind").and_then(|v| v.to_str().ok()),
                        "gatewayAuth": headers.get("x-gateway-auth").and_then(|v| v.to_str().ok()),
                    }))
                }),
            )
            .layer(middleware::from_fn_with_state(
                config.clone(),
                astral_common::middleware::gateway_signature::gateway_signature_middleware,
            ))
            .with_state(config.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("mock Identity server");
        });
        let base_uri = format!("http://{addr}");

        let bootstrap = Request::builder()
            .method(axum::http::Method::POST)
            .uri("/api/v1/auth/sessions")
            .header("authorization", "Bearer optional-access-token")
            .header("x-user-id", "forged-user")
            .body(Body::from("{}"))
            .unwrap();
        let response = forward(&config, &base_uri, "/api/v1/auth/sessions", bootstrap).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(to_bytes(response.into_body(), 1024).await.unwrap().as_ref())
                .unwrap();
        assert!(body["authorization"].is_null());
        assert!(body["userId"].is_null());
        assert_eq!(body["gatewayAuth"], "verified");

        let refresh = Request::builder()
            .method(axum::http::Method::POST)
            .uri("/api/v1/auth/sessions/refresh")
            .header("authorization", "Bearer refresh-token")
            .body(Body::from("{}"))
            .unwrap();
        let response = forward(&config, &base_uri, "/api/v1/auth/sessions/refresh", refresh).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(to_bytes(response.into_body(), 1024).await.unwrap().as_ref())
                .unwrap();
        assert_eq!(body["authorization"], "Bearer refresh-token");
        assert!(body["userId"].is_null());
        assert!(body["principalKind"].is_null());
        assert_eq!(body["gatewayAuth"], "verified");
        server.abort();
    }

    // memory—v1: Exercise the production preparation and response boundary through a real verifier.
    #[tokio::test]
    async fn prepared_request_supports_in_process_verified_dispatch() {
        use axum::body::to_bytes;
        use axum::routing::post;
        use axum::{middleware, Router};
        use tower::ServiceExt;

        let config = AppConfig {
            gateway: astral_common::config::GatewayCfg {
                hmac_secret: uuid::Uuid::new_v4().to_string(),
                timestamp_tolerance_secs: 30,
                ..Default::default()
            },
            ..Default::default()
        };
        let app = Router::new()
            .route(
                "/internal/session",
                post(|req: Request| async move {
                    assert_eq!(req.uri().query(), Some("next=%2Fhome"));
                    assert_eq!(req.headers()["x-original-path"], "/api/v1/auth/sessions");
                    assert!(!req.headers().contains_key("authorization"));
                    assert!(!req.headers().contains_key("x-user-id"));
                    assert!(!req.headers().contains_key("x-private"));
                    assert!(!req.headers().contains_key("content-length"));
                    assert_eq!(req.headers().get_all("x-example").iter().count(), 2);
                    let body = to_bytes(req.into_body(), 1024).await.unwrap();
                    assert_eq!(body.as_ref(), b"credentials");
                    (
                        [
                            ("connection", "x-private-response"),
                            ("x-private-response", "secret"),
                        ],
                        "upstream body",
                    )
                }),
            )
            .layer(middleware::from_fn_with_state(
                config.clone(),
                astral_common::middleware::gateway_signature::gateway_signature_middleware,
            ))
            .with_state(config.clone());

        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/sessions?next=%2Fhome")
            .header("connection", "x-private")
            .header("x-private", "secret")
            .header("authorization", "Bearer client-token")
            .header("x-user-id", "forged-user")
            .header("x-original-path", "/forged")
            .header("content-length", "11")
            .header("x-example", "one")
            .header("x-example", "two")
            .body(Body::from("credentials"))
            .unwrap();
        let prepared = prepare_request(&config, "/internal/session", request)
            .await
            .unwrap_or_else(|_| panic!("request preparation failed"));
        let mut builder = Request::builder()
            .method(prepared.method.clone())
            .uri(&prepared.upstream_path_and_query);
        for (name, value) in &prepared.headers {
            builder = builder.header(name, value.as_str());
        }
        let downstream = builder.body(Body::from(prepared.body.clone())).unwrap();
        let response = app.oneshot(downstream).await.unwrap();
        let (parts, body) = response.into_parts();
        let response = finish_upstream_response(
            &prepared,
            parts.status,
            parts.headers,
            None,
            body.into_data_stream(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key("connection"));
        assert!(!response.headers().contains_key("x-private-response"));
        assert_eq!(
            to_bytes(response.into_body(), 1024).await.unwrap().as_ref(),
            b"upstream body"
        );
    }

    // memory—v1: Reject malformed connection lists and oversized bodies on both legs.
    #[tokio::test]
    async fn prepared_boundaries_reject_invalid_and_oversized_messages() {
        use futures_util::stream;

        let config = AppConfig::default();
        let invalid = Request::builder()
            .uri("/external")
            .header("connection", "bad name")
            .header("x-request-id", "trace-invalid")
            .body(Body::empty())
            .unwrap();
        let error = match prepare_request(&config, "/internal", invalid).await {
            Ok(_) => panic!("invalid Connection accepted"),
            Err(response) => response,
        };
        assert_eq!(error.status(), StatusCode::BAD_REQUEST);
        assert_eq!(error.headers()["x-trace-id"], "trace-invalid");

        let too_large = Request::builder()
            .uri("/external")
            .body(Body::from(vec![0; 10 * 1024 * 1024 + 1]))
            .unwrap();
        assert!(matches!(
            prepare_request(&config, "/internal", too_large).await,
            Err(response) if response.status() == StatusCode::BAD_REQUEST
        ));

        let prepared = prepare_request(
            &config,
            "/internal",
            Request::builder()
                .uri("/external")
                .header("x-request-id", "trace-upstream")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap_or_else(|_| panic!("request preparation failed"));
        let mut headers = HeaderMap::new();
        headers.insert("connection", HeaderValue::from_static("bad name"));
        let response = finish_upstream_response(
            &prepared,
            StatusCode::OK,
            headers,
            None,
            stream::empty::<Result<bytes::Bytes, ()>>(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(response.headers()["x-trace-id"], "trace-upstream");

        let response = finish_upstream_response(
            &prepared,
            StatusCode::OK,
            HeaderMap::new(),
            Some(MAX_UPSTREAM_RESPONSE_BYTES as u64 + 1),
            stream::empty::<Result<bytes::Bytes, ()>>(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(response.headers()["x-trace-id"], "trace-upstream");
    }

    #[test]
    fn public_bootstrap_transport_drops_client_supplied_identity_and_gateway_headers() {
        let method = axum::http::Method::POST;
        let path = "/api/v1/auth/sessions";
        for name in [
            "x-user-id",
            "x-principal-kind",
            "x-token-id",
            "x-identity-card-id",
            "x-user-card-id",
            "x-gateway-auth",
            "x-gateway-signature",
            "authorization",
        ] {
            let value = if name == "authorization" {
                HeaderValue::from_static("Bearer refresh-token")
            } else {
                HeaderValue::from_static("forged")
            };
            assert!(
                !should_forward_client_header(&method, path, name, &value),
                "bootstrap transport must not forward {name}"
            );
        }
        assert!(should_forward_client_header(
            &method,
            path,
            "content-type",
            &HeaderValue::from_static("application/json"),
        ));
    }

    #[tokio::test]
    async fn bounded_response_collector_rejects_content_length_chunked_and_read_errors() {
        use futures_util::stream;

        let declared_too_large = stream::empty::<Result<bytes::Bytes, &'static str>>();
        assert_eq!(
            collect_bounded_response_body(declared_too_large, Some(5), 4).await,
            Err(BoundedBodyError::TooLarge)
        );

        let chunked = stream::iter([
            Ok::<_, &'static str>(bytes::Bytes::from_static(b"abc")),
            Ok(bytes::Bytes::from_static(b"de")),
        ]);
        assert_eq!(
            collect_bounded_response_body(chunked, None, 4).await,
            Err(BoundedBodyError::TooLarge)
        );

        let malformed = stream::iter([
            Ok::<_, &'static str>(bytes::Bytes::from_static(b"a")),
            Err("truncated upstream body"),
        ]);
        assert_eq!(
            collect_bounded_response_body(malformed, Some(2), 4).await,
            Err(BoundedBodyError::Read)
        );

        let exact_boundary =
            stream::iter([Ok::<_, &'static str>(bytes::Bytes::from_static(b"abcd"))]);
        assert_eq!(
            collect_bounded_response_body(exact_boundary, None, 4)
                .await
                .unwrap(),
            bytes::Bytes::from_static(b"abcd")
        );
    }

    #[test]
    fn canonical_session_routes_retain_bearer_only_for_post() {
        let bearer = HeaderValue::from_static("Bearer refresh-token");
        for path in [
            "/api/v1/auth/sessions/refresh",
            "/api/v1/auth/sessions/switch-card",
            "/api/v1/auth/sessions/logout",
            "/api/v1/auth/sessions/revoke",
        ] {
            assert!(should_forward_client_header(
                &axum::http::Method::POST,
                path,
                "authorization",
                &bearer,
            ));
        }

        assert!(!should_forward_client_header(
            &axum::http::Method::GET,
            "/api/v1/auth/sessions/refresh",
            "authorization",
            &bearer,
        ));
    }

    #[test]
    fn bearer_is_forbidden_on_unrelated_routes_and_malformed_values() {
        let bearer = HeaderValue::from_static("Bearer access-token");
        let malformed = HeaderValue::from_static("Basic credentials");

        assert!(!should_forward_client_header(
            &axum::http::Method::POST,
            "/api/v1/auth/profile",
            "authorization",
            &bearer,
        ));
        assert!(!should_forward_client_header(
            &axum::http::Method::POST,
            "/api/v1/auth/sessions/refresh-extra",
            "authorization",
            &bearer,
        ));
        assert!(!should_forward_client_header(
            &axum::http::Method::POST,
            "/api/v1/auth/sessions/refresh",
            "authorization",
            &malformed,
        ));
        assert!(crate::middleware::is_proxy_forbidden_header(
            "authorization"
        ));
    }

    #[test]
    fn idempotency_key_remains_forwardable() {
        let key = HeaderValue::from_static("request-123");
        assert!(should_forward_client_header(
            &axum::http::Method::POST,
            "/api/v1/auth/sessions/refresh",
            "idempotency-key",
            &key,
        ));
        assert!(!crate::middleware::is_proxy_forbidden_header(
            "idempotency-key"
        ));
    }
}
