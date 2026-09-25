//! 路由转发处理器
//!
//! 使用 reqwest 将请求代理转发到后端服务，保持原始请求的方法、头、体。
//! 集成了：
//! - 断路器模式：连续失败超过阈值后直接返回 503
//! - HMAC-SHA256 签名注入（X-Gateway-Signature）
//! - X-Original-Path 注入

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::SystemTime;

use axum::body::Body;
use axum::extract::{Path, Request, State, WebSocketUpgrade};
use axum::http::{HeaderMap, HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::http::Request as WsRequest;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use crate::middleware::{complete_internal_idempotency, release_internal_idempotency};
use astral_common::config::AppConfig;
use astral_common::middleware::gateway_signature::compute_hmac_signature_v3;
use astral_common::middleware::internal_signature::{
    compute_internal_signature, normalize_query, sha256_hex, InternalSignatureInput,
    INTERNAL_BODY_SHA256_HEADER, INTERNAL_CALLER_GATEWAY, INTERNAL_CALLER_LEARN,
    INTERNAL_IDEMPOTENCY_HEADER, INTERNAL_KEY_ID_HEADER, INTERNAL_NONCE_HEADER,
    INTERNAL_PROTOCOL_HEADER, INTERNAL_PROTOCOL_VERSION, INTERNAL_REQUEST_ID_HEADER,
    INTERNAL_ROUTE_HEADER, INTERNAL_SERVICE_HEADER, INTERNAL_SESSION_PATH,
    INTERNAL_SIGNATURE_HEADER, INTERNAL_TIMESTAMP_HEADER, KEY_ID_GATEWAY_TO_IDENTITY,
    ROUTE_GATEWAY_TO_IDENTITY,
};
use astral_common::token_contract::CHAT_WS_SUBPROTOCOL;

/// HTTP 客户端（连接池复用）
static CLIENT: once_cell::sync::Lazy<reqwest::Client> = once_cell::sync::Lazy::new(|| {
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(3))
        // 对齐 Java Gateway application.yml `response-timeout: 30s`（路由转发响应超时）
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("reqwest Client")
});

const UPSTREAM_WS_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

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

fn is_non_empty_bearer(value: &str) -> bool {
    value
        .strip_prefix("Bearer ")
        .is_some_and(|token| !token.trim().is_empty())
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
    !crate::middleware::is_proxy_forbidden_header(key)
}

/// 断路器失败阈值
const CB_FAILURE_THRESHOLD: u32 = 5;

/// 断路器恢复间隔（秒）：打开后经过此时间允许探测请求
const CB_RECOVERY_SECS: u64 = 30;

/// 断路器状态：每个上游服务独立跟踪
///
/// 状态机：CLOSED → (连续 N 次失败) → OPEN → (等待 CB_RECOVERY_SECS) → HALF_OPEN → (成功) → CLOSED / (失败) → OPEN
struct CircuitBreaker {
    failures: AtomicU32,
    opened_at: AtomicU64,
    probe_in_flight: AtomicBool,
}

impl CircuitBreaker {
    const fn new() -> Self {
        Self {
            failures: AtomicU32::new(0),
            opened_at: AtomicU64::new(0),
            probe_in_flight: AtomicBool::new(false),
        }
    }

    /// Returns true when the request may proceed. At most one request is
    /// allowed through after the recovery window as the half-open probe.
    fn allow_request(&self) -> bool {
        if self.failures.load(Ordering::Acquire) < CB_FAILURE_THRESHOLD {
            return true;
        }
        let opened = self.opened_at.load(Ordering::Acquire);
        if opened == 0 {
            return false;
        }
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now < opened + CB_RECOVERY_SECS {
            return false;
        }
        self.probe_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn is_open(&self) -> bool {
        !self.allow_request()
    }

    fn record_failure(&self) {
        self.probe_in_flight.store(false, Ordering::Release);
        let prev = self.failures.fetch_add(1, Ordering::Release);
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if prev + 1 >= CB_FAILURE_THRESHOLD {
            // 首次达阈值 → OPEN；半开探测失败 → 重置 opened_at 重新进入 OPEN
            // （否则恢复窗口过后每个请求都变探针，持续失败时不再 fail-closed）。
            self.opened_at.store(now, Ordering::Release);
        }
    }

    fn record_success(&self) {
        self.probe_in_flight.store(false, Ordering::Release);
        self.failures.store(0, Ordering::Release);
        self.opened_at.store(0, Ordering::Release);
    }
}

static CB_LEARN: CircuitBreaker = CircuitBreaker::new();
static CB_IDENTITY: CircuitBreaker = CircuitBreaker::new();
static CB_TRUSTGRAPH: CircuitBreaker = CircuitBreaker::new();
static CB_MONITOR: CircuitBreaker = CircuitBreaker::new();
static CB_CHAT: CircuitBreaker = CircuitBreaker::new();

/// 转发到 Learn 管理端
pub async fn forward_to_learn_admin(
    State(config): State<AppConfig>,
    Path(path): Path<String>,
    req: Request,
) -> Response {
    if CB_LEARN.is_open() {
        tracing::warn!("circuit breaker open for learn service");
        return json_error(
            req.method().as_str(),
            req.uri().path(),
            request_trace_id(&req),
            503,
            "Learn service unavailable (circuit breaker)",
            "SERVICE_UNAVAILABLE",
        );
    }
    let full_path = format!("/v1/admin/learn/{path}");
    let response = forward(&config, &config.learn_service_uri, &full_path, req).await;
    if dependency_failure(response.status()) {
        CB_LEARN.record_failure();
    } else {
        CB_LEARN.record_success();
    }
    response
}

/// 转发到 Learn 应用端
pub async fn forward_to_learn_app(
    State(config): State<AppConfig>,
    Path(path): Path<String>,
    req: Request,
) -> Response {
    if CB_LEARN.is_open() {
        tracing::warn!("circuit breaker open for learn service");
        return json_error(
            req.method().as_str(),
            req.uri().path(),
            request_trace_id(&req),
            503,
            "Learn service unavailable (circuit breaker)",
            "SERVICE_UNAVAILABLE",
        );
    }
    let full_path = format!("/v1/app/learn/{path}");
    let response = forward(&config, &config.learn_service_uri, &full_path, req).await;
    if dependency_failure(response.status()) {
        CB_LEARN.record_failure();
    } else {
        CB_LEARN.record_success();
    }
    response
}

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

async fn forward_identity_path(config: AppConfig, full_path: String, req: Request) -> Response {
    if CB_IDENTITY.is_open() {
        return json_error(
            req.method().as_str(),
            req.uri().path(),
            request_trace_id(&req),
            503,
            "Identity service unavailable (circuit breaker)",
            "SERVICE_UNAVAILABLE",
        );
    }
    let response = forward(&config, &config.identity_service_uri, &full_path, req).await;
    if dependency_failure(response.status()) {
        CB_IDENTITY.record_failure();
    } else {
        CB_IDENTITY.record_success();
    }
    response
}

pub async fn forward_internal_session(State(config): State<AppConfig>, req: Request) -> Response {
    if CB_IDENTITY.is_open() {
        return json_error(
            req.method().as_str(),
            req.uri().path(),
            request_trace_id(&req),
            503,
            "Identity service unavailable (circuit breaker)",
            "SERVICE_UNAVAILABLE",
        );
    }
    let (parts, body) = req.into_parts();
    let external_path = parts.uri.path().to_string();
    let request_id = parts
        .headers
        .get("x-internal-request-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_string();
    let idempotency_key = parts
        .headers
        .get(INTERNAL_IDEMPOTENCY_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_string();
    let body = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(body) => body,
        Err(_) => {
            return json_error(
                "POST",
                &external_path,
                Some(&request_id),
                400,
                "Failed to read internal request body",
                "BAD_REQUEST",
            )
        }
    };
    let body_hash = sha256_hex(&body);
    let target_user_id = match serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|value| value.get("userId").and_then(serde_json::Value::as_i64))
        .filter(|value| *value > 0)
    {
        Some(value) => value.to_string(),
        None => {
            return json_error(
                "POST",
                &external_path,
                Some(&request_id),
                400,
                "Invalid internal session body",
                "BAD_REQUEST",
            )
        }
    };
    let timestamp = time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    let timestamp = timestamp.to_string();
    let nonce = format!(
        "nonce-{}-{}",
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        std::process::id()
    );
    if parts.uri.query().is_some() {
        return json_error(
            "POST",
            &external_path,
            Some(&request_id),
            401,
            "Internal session query parameters are forbidden",
            "UNAUTHORIZED",
        );
    }
    let normalized_query = normalize_query(parts.uri.query());
    let input = InternalSignatureInput {
        protocol_version: INTERNAL_PROTOCOL_VERSION,
        key_id: KEY_ID_GATEWAY_TO_IDENTITY,
        caller_service: INTERNAL_CALLER_GATEWAY,
        method: "POST",
        path: INTERNAL_SESSION_PATH,
        normalized_query: &normalized_query,
        body_sha256: &body_hash,
        target_user_id: &target_user_id,
        timestamp: &timestamp,
        nonce: &nonce,
        request_id: &request_id,
        idempotency_key: &idempotency_key,
        route: ROUTE_GATEWAY_TO_IDENTITY,
    };
    let signature = compute_internal_signature(&config.gateway.internal_service_secret, &input);
    let uri = format!(
        "{}{}",
        config.identity_service_uri.trim_end_matches('/'),
        INTERNAL_SESSION_PATH
    );
    if config.identity_service_uri.trim().is_empty()
        || config.gateway.internal_service_secret.len() < 32
    {
        return json_error(
            "POST",
            &external_path,
            Some(&request_id),
            503,
            "Internal identity route is not configured",
            "SERVICE_UNAVAILABLE",
        );
    }
    let response = CLIENT
        .post(uri)
        .header("content-type", "application/json")
        .header(INTERNAL_PROTOCOL_HEADER, INTERNAL_PROTOCOL_VERSION)
        .header(INTERNAL_SERVICE_HEADER, INTERNAL_CALLER_GATEWAY)
        .header("x-internal-caller", INTERNAL_CALLER_GATEWAY)
        .header(INTERNAL_TIMESTAMP_HEADER, &timestamp)
        .header(INTERNAL_NONCE_HEADER, &nonce)
        .header(INTERNAL_REQUEST_ID_HEADER, &request_id)
        .header(INTERNAL_IDEMPOTENCY_HEADER, &idempotency_key)
        .header(INTERNAL_BODY_SHA256_HEADER, &body_hash)
        .header(INTERNAL_SIGNATURE_HEADER, &signature)
        .header(INTERNAL_KEY_ID_HEADER, KEY_ID_GATEWAY_TO_IDENTITY)
        .header(INTERNAL_ROUTE_HEADER, ROUTE_GATEWAY_TO_IDENTITY)
        .body(body.to_vec())
        .send()
        .await;
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            let _ = release_internal_idempotency(
                &config,
                INTERNAL_CALLER_LEARN,
                "learn-to-gateway",
                &idempotency_key,
            )
            .await;
            CB_IDENTITY.record_failure();
            tracing::warn!(%error, "internal Identity request failed");
            return json_error(
                "POST",
                &external_path,
                Some(&request_id),
                502,
                "Identity service request failed",
                "BAD_GATEWAY",
            );
        }
    };
    let status = response.status();
    let headers = response.headers().clone();
    let response_body = match response.bytes().await {
        Ok(body) => body,
        Err(_) => {
            CB_IDENTITY.record_failure();
            return json_error(
                "POST",
                &external_path,
                Some(&request_id),
                502,
                "Identity response read failed",
                "BAD_GATEWAY",
            );
        }
    };
    if status.is_server_error() {
        CB_IDENTITY.record_failure();
        let _ = release_internal_idempotency(
            &config,
            INTERNAL_CALLER_LEARN,
            "learn-to-gateway",
            &idempotency_key,
        )
        .await;
    } else {
        CB_IDENTITY.record_success();
        let _ = complete_internal_idempotency(
            &config,
            INTERNAL_CALLER_LEARN,
            "learn-to-gateway",
            &idempotency_key,
            &body_hash,
        )
        .await;
    }
    let mut builder = Response::builder().status(status);
    for (name, value) in headers {
        if let Some(name) = name {
            if name != "connection" && name != "transfer-encoding" {
                builder = builder.header(name, value);
            }
        }
    }
    builder
        .body(Body::from(response_body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}
pub async fn forward_to_trustgraph(
    State(config): State<AppConfig>,
    Path(path): Path<String>,
    req: Request,
) -> Response {
    if CB_TRUSTGRAPH.is_open() {
        tracing::warn!("circuit breaker open for trustgraph service");
        return json_error(
            req.method().as_str(),
            req.uri().path(),
            request_trace_id(&req),
            503,
            "TrustGraph service unavailable (circuit breaker)",
            "SERVICE_UNAVAILABLE",
        );
    }
    let full_path = format!("/main/api/v1/{path}");
    let response = forward(&config, &config.trust_graph_uri, &full_path, req).await;
    if dependency_failure(response.status()) {
        CB_TRUSTGRAPH.record_failure();
    } else {
        CB_TRUSTGRAPH.record_success();
    }
    response
}

/// 转发到 Monitor 服务
pub async fn forward_to_monitor(
    State(config): State<AppConfig>,
    Path(path): Path<String>,
    req: Request,
) -> Response {
    if CB_MONITOR.is_open() {
        tracing::warn!("circuit breaker open for monitor service");
        return json_error(
            req.method().as_str(),
            req.uri().path(),
            request_trace_id(&req),
            503,
            "Monitor service unavailable (circuit breaker)",
            "SERVICE_UNAVAILABLE",
        );
    }
    let full_path = format!("/api/v1/monitor/{path}");
    let response = forward(&config, &config.monitor_service_uri, &full_path, req).await;
    if dependency_failure(response.status()) {
        CB_MONITOR.record_failure();
    } else {
        CB_MONITOR.record_success();
    }
    response
}

/// 转发到 Chat 服务
pub async fn forward_to_chat(
    State(config): State<AppConfig>,
    Path(path): Path<String>,
    req: Request,
) -> Response {
    if CB_CHAT.is_open() {
        tracing::warn!("circuit breaker open for chat service");
        return json_error(
            req.method().as_str(),
            req.uri().path(),
            request_trace_id(&req),
            503,
            "Chat service unavailable (circuit breaker)",
            "SERVICE_UNAVAILABLE",
        );
    }
    let full_path = format!("/v1/chat/{path}");
    // 与 WS 隧道共用同一解析入口：env 优先、config 兜底，避免 HTTP/WS 打到不同实例。
    let chat_uri = std::env::var("CHAT_SERVICE_URI")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| config.chat_service_uri.clone());
    if chat_uri.trim().is_empty() {
        return json_error(
            req.method().as_str(),
            req.uri().path(),
            request_trace_id(&req),
            503,
            "Chat service URI is not configured",
            "SERVICE_UNAVAILABLE",
        );
    }
    let response = forward(&config, &chat_uri, &full_path, req).await;
    if dependency_failure(response.status()) {
        CB_CHAT.record_failure();
    } else {
        CB_CHAT.record_success();
    }
    response
}

/// 转发到 Learn 服务（/v1/app/users 路径，对齐 Java AppUserController）
pub async fn forward_to_learn_app_users(
    State(config): State<AppConfig>,
    Path(path): Path<String>,
    req: Request,
) -> Response {
    if CB_LEARN.is_open() {
        return json_error(
            req.method().as_str(),
            req.uri().path(),
            request_trace_id(&req),
            503,
            "Learn service unavailable (circuit breaker)",
            "SERVICE_UNAVAILABLE",
        );
    }
    let full_path = format!("/v1/app/users/{path}");
    let response = forward(&config, &config.learn_service_uri, &full_path, req).await;
    if dependency_failure(response.status()) {
        CB_LEARN.record_failure();
    } else {
        CB_LEARN.record_success();
    }
    response
}

/// 转发到 Learn 服务（/v1/app/users 根路径）
pub async fn forward_to_learn_app_users_root(
    State(config): State<AppConfig>,
    req: Request,
) -> Response {
    if CB_LEARN.is_open() {
        return json_error(
            req.method().as_str(),
            req.uri().path(),
            request_trace_id(&req),
            503,
            "Learn service unavailable (circuit breaker)",
            "SERVICE_UNAVAILABLE",
        );
    }
    let response = forward(&config, &config.learn_service_uri, "/v1/app/users", req).await;
    if dependency_failure(response.status()) {
        CB_LEARN.record_failure();
    } else {
        CB_LEARN.record_success();
    }
    response
}

/// 转发 Chat WebSocket（真正的双向 upgrade 隧道）。
pub async fn forward_chat_ws(
    State(config): State<AppConfig>,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    Path(path): Path<String>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if !path.parse::<i64>().is_ok_and(|user_id| user_id > 0) {
        return json_error(
            "GET",
            original_uri.path(),
            None,
            404,
            "Chat WebSocket route not found",
            "NOT_FOUND",
        );
    }
    if CB_CHAT.is_open() {
        return json_error(
            "GET",
            original_uri.path(),
            None,
            503,
            "Chat service unavailable (circuit breaker)",
            "SERVICE_UNAVAILABLE",
        );
    }
    let target_path = format!("/v1/chat/ws/{path}");
    // 外部 canonical path 必须使用客户端请求路径；上游 URL 使用 rewrite 后的内部路径。
    let external_path = original_uri.path().to_string();
    let chat_uri = std::env::var("CHAT_SERVICE_URI")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| config.chat_service_uri.clone());
    let upstream_url = match websocket_upstream_url(&chat_uri, &target_path) {
        Ok(url) => url,
        Err(message) => {
            return json_error(
                "GET",
                original_uri.path(),
                None,
                503,
                message,
                "SERVICE_UNAVAILABLE",
            )
        }
    };

    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .to_string();
    let value = |name: &str| {
        headers
            .get(name)
            .and_then(|header| header.to_str().ok())
            .unwrap_or("")
            .trim()
            .to_string()
    };
    let user_id = value("x-user-id");
    let token_id = value("x-token-id");
    let identity_card_id = value("x-identity-card-id");
    let principal_kind = value("x-principal-kind");
    let user_card_id = value("x-user-card-id");
    let user_card_domain_id = value("x-user-card-domain-id");
    let user_card_tenant_id = value("x-user-card-tenant-id");
    let token_use = value("x-token-use");
    let claims_version = value("x-claims-version");
    let action_codes = value("x-action-codes");
    let user_roles = value("x-user-roles");
    let template_id = value("x-template-id");
    let tenant_status = value("x-tenant-status");
    let perms_ref = value("x-perms-ref");
    let permissions_truncated = value("x-permissions-truncated");
    // v3 签名（问题 1 修正：identity_card 不承担组织归属，payload 移除身份侧租户）
    let signature = compute_hmac_signature_v3(
        &config.gateway.hmac_secret,
        "GET",
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

    let mut builder = WsRequest::builder().uri(upstream_url);
    builder = builder.header("sec-websocket-protocol", CHAT_WS_SUBPROTOCOL);
    for (name, header) in headers.iter() {
        let key = name.as_str().to_ascii_lowercase();
        if crate::middleware::is_proxy_forbidden_header(&key) {
            continue;
        }
        if let Ok(text) = header.to_str() {
            builder = builder.header(name.as_str(), text);
        }
    }
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
        ("x-template-id", template_id.as_str()),
        ("x-tenant-status", tenant_status.as_str()),
        ("x-perms-ref", perms_ref.as_str()),
        ("x-permissions-truncated", permissions_truncated.as_str()),
    ] {
        if !value.is_empty() {
            builder = builder.header(name, value);
        }
    }
    let request = match builder
        .header("x-gateway-auth", "verified")
        .header("x-gateway-ts", &timestamp)
        .header("x-gateway-signature", &signature)
        .header("x-original-path", &external_path)
        .body(())
    {
        Ok(request) => request,
        Err(error) => {
            tracing::error!(error = %error, "failed to build Chat WebSocket request");
            return json_error(
                "GET",
                original_uri.path(),
                None,
                502,
                "Invalid Chat WebSocket request",
                "BAD_GATEWAY",
            );
        }
    };

    let (upstream, _response) =
        match timeout(UPSTREAM_WS_CONNECT_TIMEOUT, connect_async(request)).await {
            Ok(Ok(result)) => {
                CB_CHAT.record_success();
                result
            }
            Ok(Err(error)) => {
                CB_CHAT.record_failure();
                tracing::warn!(error = %error, "Chat WebSocket upstream handshake failed");
                return json_error(
                    "GET",
                    original_uri.path(),
                    None,
                    502,
                    "Chat WebSocket upstream handshake failed",
                    "BAD_GATEWAY",
                );
            }
            Err(_) => {
                CB_CHAT.record_failure();
                tracing::warn!("Chat WebSocket upstream handshake timed out");
                return json_error(
                    "GET",
                    original_uri.path(),
                    None,
                    503,
                    "Chat WebSocket upstream handshake timed out",
                    "SERVICE_UNAVAILABLE",
                );
            }
        };

    let upgrade = ws
        .protocols([CHAT_WS_SUBPROTOCOL])
        .on_upgrade(move |socket| async move {
            bridge_websocket(socket, upstream).await;
        });
    upgrade.into_response()
}

fn websocket_upstream_url(base_uri: &str, target_path: &str) -> Result<String, &'static str> {
    let base_uri = base_uri.trim();
    if base_uri.is_empty() {
        return Err("Chat service URI is not configured");
    }
    let mut url = reqwest::Url::parse(base_uri).map_err(|_| "Chat service URI is invalid")?;
    let websocket_scheme = match url.scheme() {
        "http" => "ws",
        "https" => "wss",
        _ => return Err("Chat service URI must use http or https"),
    };
    url.set_scheme(websocket_scheme)
        .map_err(|_| "Chat service URI scheme is invalid")?;

    let base_path = url.path().trim_end_matches('/');
    let path = format!("{base_path}{target_path}");
    url.set_path(&path);
    url.set_query(None);
    Ok(url.to_string())
}

async fn bridge_websocket<S>(
    socket: axum::extract::ws::WebSocket,
    upstream: tokio_tungstenite::WebSocketStream<S>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut client_sink, mut client_stream) = socket.split();
    let (mut upstream_sink, mut upstream_stream) = upstream.split();
    let client_to_upstream = async {
        while let Some(result) = client_stream.next().await {
            let message = match result {
                Ok(message) => message,
                Err(error) => return Err(error.to_string()),
            };
            let converted = match message {
                axum::extract::ws::Message::Text(text) => WsMessage::Text(text.to_string().into()),
                axum::extract::ws::Message::Binary(bytes) => WsMessage::Binary(bytes),
                axum::extract::ws::Message::Ping(bytes) => WsMessage::Ping(bytes),
                axum::extract::ws::Message::Pong(bytes) => WsMessage::Pong(bytes),
                axum::extract::ws::Message::Close(_) => break,
            };
            upstream_sink
                .send(converted)
                .await
                .map_err(|error| error.to_string())?;
        }
        Ok::<(), String>(())
    };
    let upstream_to_client = async {
        while let Some(result) = upstream_stream.next().await {
            let message = match result {
                Ok(message) => message,
                Err(error) => return Err(error.to_string()),
            };
            let converted = match message {
                WsMessage::Text(text) => axum::extract::ws::Message::Text(text.to_string().into()),
                WsMessage::Binary(bytes) => axum::extract::ws::Message::Binary(bytes),
                WsMessage::Ping(bytes) => axum::extract::ws::Message::Ping(bytes),
                WsMessage::Pong(bytes) => axum::extract::ws::Message::Pong(bytes),
                WsMessage::Close(_) => break,
                WsMessage::Frame(_) => continue,
            };
            client_sink
                .send(converted)
                .await
                .map_err(|error| error.to_string())?;
        }
        Ok::<(), String>(())
    };
    tokio::select! {
        result = client_to_upstream => result,
        result = upstream_to_client => result,
    }
    .unwrap_or_else(|error| tracing::debug!(error = %error, "Chat WebSocket bridge closed"));
}
async fn forward(config: &AppConfig, base_uri: &str, path: &str, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let external_path = parts.uri.path().to_string();
    let method = parts.method.clone();
    // 保留原始请求的查询字符串
    let query = parts
        .uri
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let uri = format!("{}{}{query}", base_uri.trim_end_matches('/'), path);

    // 读取请求体
    let body_bytes = match axum::body::to_bytes(body, 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "Failed to read request body");
            return json_error(
                method.as_str(),
                &external_path,
                parts
                    .headers
                    .get("x-request-id")
                    .and_then(|v| v.to_str().ok()),
                400,
                &format!("Failed to read body: {e}"),
                "BAD_REQUEST",
            );
        }
    };

    // 提取身份头（由 JWT 中间件注入）
    let extract_header = |name: &str| -> String {
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
    let template_id = extract_header("x-template-id");
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

    // 构建转发请求
    let mut forwarded = CLIENT.request(method.clone(), &uri);
    for (key, value) in parts.headers.iter() {
        let key_str = key.as_str().to_lowercase();
        // Keep a client Bearer only for Identity's exact session operations.
        // All other sensitive, gateway, and hop-by-hop headers remain stripped.
        if !should_forward_client_header(&method, &external_path, &key_str, value) {
            continue;
        }
        if let Ok(v) = value.to_str() {
            forwarded = forwarded.header(key.as_str(), v);
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
        ("x-template-id", template_id.as_str()),
        ("x-tenant-status", tenant_status.as_str()),
        ("x-perms-ref", perms_ref.as_str()),
        ("x-permissions-truncated", permissions_truncated.as_str()),
    ] {
        if !value.is_empty() {
            forwarded = forwarded.header(name, value);
        }
    }

    // 注入网关签名头（覆盖任何残留值）
    forwarded = forwarded
        .header("X-Gateway-Auth", "verified")
        .header("X-Gateway-Ts", &timestamp)
        .header("X-Gateway-Signature", &signature)
        .header("X-Original-Path", &external_path);

    if !body_bytes.is_empty() {
        forwarded = forwarded.body(body_bytes.to_vec());
    }

    // 发送请求并接收响应
    match forwarded.send().await {
        Ok(response) => {
            let status = response.status();
            let resp_headers = response.headers().clone();
            let resp_body = match response.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to read upstream response body");
                    return json_error(
                        method.as_str(),
                        &external_path,
                        parts
                            .headers
                            .get("x-request-id")
                            .and_then(|v| v.to_str().ok()),
                        502,
                        &format!("Upstream read failed: {e}"),
                        "BAD_GATEWAY",
                    );
                }
            };

            let mut response_builder = Response::builder().status(status);
            for (key, value) in resp_headers.iter() {
                let key_str = key.as_str().to_lowercase();
                if key_str == "transfer-encoding" || key_str == "connection" {
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
        Err(e) => {
            tracing::error!(
                method = %method,
                uri = %uri,
                error = %e,
                "upstream request failed"
            );
            json_error(
                method.as_str(),
                &external_path,
                parts
                    .headers
                    .get("x-request-id")
                    .and_then(|v| v.to_str().ok()),
                502,
                &format!("Upstream error: {e}"),
                "BAD_GATEWAY",
            )
        }
    }
}

fn dependency_failure(status: reqwest::StatusCode) -> bool {
    matches!(status.as_u16(), 502..=504)
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
mod circuit_breaker_tests {
    use super::*;

    #[test]
    fn half_open_allows_only_one_probe() {
        let breaker = CircuitBreaker::new();
        for _ in 0..CB_FAILURE_THRESHOLD {
            breaker.record_failure();
        }
        breaker.opened_at.store(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .saturating_sub(CB_RECOVERY_SECS + 1),
            Ordering::Release,
        );
        assert!(breaker.allow_request());
        assert!(!breaker.allow_request());
        breaker.record_failure();
        assert!(!breaker.allow_request());
    }
}

#[cfg(test)]
mod client_header_policy_tests {
    use super::*;
    use axum::http::HeaderValue;

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
    fn websocket_upstream_url_drops_query_credentials() {
        let upstream =
            websocket_upstream_url("http://chat.example.test/base", "/v1/chat/ws/42").unwrap();
        assert_eq!(upstream, "ws://chat.example.test/base/v1/chat/ws/42");
    }

    #[test]
    fn websocket_client_headers_forbid_subprotocol_and_authorization_forwarding() {
        let stable = HeaderValue::from_static("astral-chat-v1");
        assert!(!should_forward_client_header(
            &axum::http::Method::GET,
            "/v1/chat/ws/42",
            "sec-websocket-protocol",
            &stable,
        ));
        assert!(!should_forward_client_header(
            &axum::http::Method::GET,
            "/v1/chat/ws/42",
            "authorization",
            &HeaderValue::from_static("Bearer jwt-token"),
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
