//! Gateway 专属认证中间件
//!
//! - `sanitize_internal_auth_headers` — 剥离客户端伪造的身份头
//! - `jwt_auth_middleware` — JWT 验证 + 公共路径放行 + 租户状态拦截 + 身份头注入
//! - `route_credential_policy` / `RouteCredentialPolicy` — 路由凭证策略（Gateway 本地）
//!
//! 本模块只承载 Gateway 运行时的认证职责；`JwtClaims`、`decode_v2_token` 及其
//! claims 校验辅助仍由 `astral-common::middleware` 持有（Identity 仍直接调用）。

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use redis::AsyncCommands;
use serde::Deserialize;

use astral_common::config::AppConfig;
use astral_common::middleware::internal_signature::INTERNAL_SESSION_PATH;
use astral_common::middleware::{decode_v2_token, JwtClaims};
use astral_common::token_contract::{
    PrincipalKind, TokenUse, CHAT_WS_BEARER_SUBPROTOCOL_PREFIX, CHAT_WS_SUBPROTOCOL,
    CLAIMS_VERSION_HEADER, IDENTITY_CARD_ID_HEADER, PRINCIPAL_KIND_HEADER, TOKEN_USE_HEADER,
    USER_CARD_DOMAIN_ID_HEADER, USER_CARD_ID_HEADER, USER_CARD_TENANT_ID_HEADER,
};

/// 内部身份头列表（客户端伪造的可能来源）
const INTERNAL_AUTH_HEADERS: &[&str] = &[
    "x-user-id",
    "x-card-id",
    "x-domain-id",
    "x-tenant-id",
    "x-identity-card-id",
    "x-user-card-id",
    "x-identity-domain-id",
    "x-identity-tenant-id",
    "x-user-card-domain-id",
    "x-user-card-tenant-id",
    "x-token-id",
    "x-claims-version",
    "x-user-roles",
    "x-action-codes",
    "x-token-use",
    "x-principal-kind",
    "x-template-id",
    "x-gateway-auth",
    "x-gateway-ts",
    "x-gateway-signature",
    "x-original-path",
    "x-permissions-truncated",
    "x-perms-ref",
    "x-org-id",
    "x-tenant-status",
    // 对齐 Java GatewayIdentityHeaders.HAS_REQUIRED_HEADER / REQUIRED_PERMISSION_HEADER
    // （JwtGlobalFilter INTERNAL_IDENTITY_HEADERS 共 19 项；此前 Rust 缺这 2 项，
    //  客户端可伪造这两头诱导下游信任权限要求标记）
    "x-has-required",
    "x-required-permission",
    "x-resource-owner-id",
    // Resource ownership is an authorization fact, not a client-controlled identity header.
    // Gateway strips it before forwarding; protected services must derive it authoritatively.
    "x-internal-service",
    "x-internal-service-ts",
    "x-internal-service-signature",
];

/// Return true for client-controlled authentication, identity, or gateway
/// headers. The prefix checks keep newly-added security headers fail-closed.
pub(crate) fn is_sensitive_auth_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name == "authorization"
        || name.starts_with("x-user-")
        || name.starts_with("x-card-")
        || name.starts_with("x-identity-")
        || name.starts_with("x-token-")
        || name.starts_with("x-principal-")
        || name.starts_with("x-action-")
        || name.starts_with("x-permission-")
        || name.starts_with("x-gateway-")
        || name.starts_with("x-internal-service-")
        || matches!(
            name.as_str(),
            "x-claims-version"
                | "x-domain-id"
                | "x-tenant-id"
                | "x-template-id"
                | "x-tenant-status"
                | "x-original-path"
                | "x-perms-ref"
                | "x-permissions-truncated"
                | "x-org-id"
                | "x-has-required"
                | "x-required-permission"
                | "x-resource-owner-id"
                | "x-internal-service"
        )
}

pub(crate) fn is_proxy_forbidden_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    is_sensitive_auth_header(&name)
        || matches!(
            name.as_str(),
            "connection"
                | "host"
                | "upgrade"
                | "sec-websocket-key"
                | "sec-websocket-version"
                | "sec-websocket-protocol"
                | "x-forwarded-for"
                | "x-forwarded-host"
                | "x-forwarded-proto"
        )
}

/// Redis 连接超时（秒）
const REDIS_TIMEOUT_SECS: u64 = 3;

/// Protected-request Redis checks fail closed; tests can exercise the decision helpers without Redis.
type RedisCheckResult<T> = Result<T, ()>;

async fn redis_conn_with_url(redis_url: &str) -> RedisCheckResult<redis::aio::ConnectionManager> {
    let client = redis::Client::open(redis_url).map_err(|_| ())?;
    tokio::time::timeout(
        std::time::Duration::from_secs(REDIS_TIMEOUT_SECS),
        client.get_connection_manager(),
    )
    .await
    .map_err(|_| ())?
    .map_err(|_| ())
}

/// 从 Redis 获取缓存的租户状态。
async fn fetch_cached_tenant_status(
    tenant_id: &str,
    redis_url: &str,
) -> RedisCheckResult<Option<String>> {
    let mut conn = redis_conn_with_url(redis_url).await?;
    tokio::time::timeout(
        std::time::Duration::from_secs(REDIS_TIMEOUT_SECS),
        conn.get::<_, Option<String>>(format!("tenant:status:{}", tenant_id)),
    )
    .await
    .map_err(|_| ())?
    .map_err(|_| ())
}

fn validated_subject(claims: &JwtClaims) -> Result<&str, &'static str> {
    claims
        .sub
        .parse::<i64>()
        .ok()
        .filter(|value| *value > 0)
        .map(|_| claims.sub.as_str())
        .ok_or("invalid subject")
}

fn optional_tenant_id(claims: &JwtClaims) -> Result<Option<i64>, &'static str> {
    // 租户上下文来自 user-card（组织归属唯一承载点，问题 1 修正）。
    match claims.user_card_tenant_id {
        Some(tenant_id) if tenant_id > 0 => Ok(Some(tenant_id)),
        Some(_) => Err("INVALID_TENANT_CONTEXT"),
        None => Ok(None),
    }
}

/// Versioned session grant stored at `access:grant:{jti}`.
///
/// Namespace-specific card fields are authoritative for v2.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SessionGrant {
    pub format_version: i32,
    pub principal_kind: String,
    pub user_id: i64,
    pub session_id: i64,
    pub identity_card_id: Option<i64>,
    pub user_card_id: Option<i64>,
    pub user_card_tenant_id: Option<i64>,
    pub user_card_domain_id: Option<i64>,
    pub session_version: i64,
    pub session_epoch: i64,
    pub token_family_id: i64,
    pub session_state: String,
    pub issued_at_epoch_second: i64,
    pub expires_at_epoch_second: i64,
}

/// Session grant 校验结果（对齐 Java `SessionGrantVerifier.Verification`）。
enum GrantOutcome {
    Match,
    ClaimsMissing,
    Missing,
    Mismatch,
}

/// Verify a v2 session grant without collapsing the identity and user-card namespaces.
fn verify_session_grant(claims: &JwtClaims, grant_json: Option<&str>) -> GrantOutcome {
    let sid = claims.sid;
    let sev = claims.sev;
    let family_id = claims.family_id;
    if sid.is_none() || sev.is_none() || family_id.is_none() {
        return GrantOutcome::ClaimsMissing;
    }
    let grant_json = match grant_json {
        Some(json) if !json.trim().is_empty() => json,
        _ => return GrantOutcome::Missing,
    };
    let grant: SessionGrant = match serde_json::from_str::<SessionGrant>(grant_json) {
        Ok(grant)
            if grant.format_version == 2
                && PrincipalKind::parse(&grant.principal_kind).is_some()
                && grant.user_id > 0
                && grant.session_id > 0
                && grant.session_version >= 1
                && grant.session_epoch >= 1
                && grant.token_family_id > 0
                && grant.issued_at_epoch_second >= 0
                && grant.expires_at_epoch_second > grant.issued_at_epoch_second
                && grant.identity_card_id.is_some_and(|value| value > 0) =>
        {
            grant
        }
        _ => return GrantOutcome::Mismatch,
    };
    let subject = claims.sub.parse::<i64>().ok();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let principal_kind = PrincipalKind::parse(&claims.principal_kind);
    let grant_principal_kind = PrincipalKind::parse(&grant.principal_kind);
    let context_matches = match (principal_kind, grant_principal_kind) {
        (Some(PrincipalKind::PlatformUser), Some(PrincipalKind::PlatformUser)) => {
            claims.identity_card_id == grant.identity_card_id
                && claims.user_card_id == grant.user_card_id
                && claims.user_card_tenant_id == grant.user_card_tenant_id
                && claims.user_card_domain_id == grant.user_card_domain_id
                && grant.user_card_id.is_some_and(|value| value > 0)
                && grant.user_card_tenant_id.is_some_and(|value| value > 0)
                && grant.user_card_domain_id.is_some_and(|value| value > 0)
        }
        (Some(PrincipalKind::AppUser), Some(PrincipalKind::AppUser)) => {
            claims.identity_card_id == grant.identity_card_id
                && claims.user_card_id.is_none()
                && claims.user_card_tenant_id.is_none()
                && claims.user_card_domain_id.is_none()
                && grant.user_card_id.is_none()
                && grant.user_card_tenant_id.is_none()
                && grant.user_card_domain_id.is_none()
        }
        _ => false,
    };
    let matches = subject.is_some()
        && subject == Some(grant.user_id)
        && sid == Some(grant.session_id)
        && claims.session_version == Some(grant.session_version)
        && sev == Some(grant.session_epoch)
        && family_id == Some(grant.token_family_id)
        && context_matches
        && grant.session_state.eq_ignore_ascii_case("ACTIVE")
        && (claims.iat as i64) >= grant.issued_at_epoch_second
        && (claims.exp as i64) <= grant.expires_at_epoch_second
        && grant.expires_at_epoch_second > now;
    if matches {
        GrantOutcome::Match
    } else {
        GrantOutcome::Mismatch
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteCredentialPolicy {
    PublicOnly,
    AccessOnly,
    RefreshOnly,
    AccessOrRefresh,
    InternalOnly,
}

impl RouteCredentialPolicy {
    pub const fn accepts(self, token_use: Option<TokenUse>) -> bool {
        match self {
            // Public routes bypass authentication only when Authorization is
            // absent. A supplied Bearer must still be a validated access token.
            Self::PublicOnly => token_use.is_none() || matches!(token_use, Some(TokenUse::Access)),
            Self::AccessOnly => matches!(token_use, Some(TokenUse::Access)),
            Self::RefreshOnly => matches!(token_use, Some(TokenUse::Refresh)),
            Self::AccessOrRefresh => {
                matches!(token_use, Some(TokenUse::Access | TokenUse::Refresh))
            }
            Self::InternalOnly => false,
        }
    }
}

#[derive(Clone, Copy)]
struct ApprovedPublicRoute {
    method: &'static str,
    pattern: &'static str,
}

/// Gateway-owned registry of routes that may be reached without credentials.
/// Configuration can enable only entries already present here.
const APPROVED_PUBLIC_ROUTES: &[ApprovedPublicRoute] = &[
    ApprovedPublicRoute {
        method: "POST",
        pattern: "/api/v1/auth/sessions",
    },
    ApprovedPublicRoute {
        method: "POST",
        pattern: "/api/v1/auth/register",
    },
    ApprovedPublicRoute {
        method: "POST",
        pattern: "/api/v1/auth/password/forgot",
    },
    ApprovedPublicRoute {
        method: "POST",
        pattern: "/api/v1/auth/password/reset/*",
    },
    ApprovedPublicRoute {
        method: "POST",
        pattern: "/api/v1/auth/verification/send",
    },
    ApprovedPublicRoute {
        method: "POST",
        pattern: "/api/v1/auth/verification/verify",
    },
    ApprovedPublicRoute {
        method: "POST",
        pattern: "/v1/app/users/login",
    },
];

/// Segment-aware glob matching for the Gateway route registry.
/// `*` matches one path segment and `**` matches zero or more segments.
pub(crate) fn segment_glob_matches(pattern: &str, path: &str) -> bool {
    let pattern_segments: Vec<_> = pattern
        .trim_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let path_segments: Vec<_> = path
        .trim_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();

    fn matches(pattern: &[&str], path: &[&str]) -> bool {
        match (pattern.split_first(), path.split_first()) {
            (None, None) => true,
            (Some((segment, rest)), _) if *segment == "**" => {
                matches(rest, path) || (!path.is_empty() && matches(pattern, &path[1..]))
            }
            (Some((segment, rest)), Some((_, path_rest))) if *segment == "*" => {
                matches(rest, path_rest)
            }
            (Some((expected, rest)), Some((actual, path_rest))) if expected == actual => {
                matches(rest, path_rest)
            }
            _ => false,
        }
    }

    matches(&pattern_segments, &path_segments)
}

fn approved_public_route(method: &Method, path: &str) -> bool {
    APPROVED_PUBLIC_ROUTES
        .iter()
        .any(|route| route.method == method.as_str() && segment_glob_matches(route.pattern, path))
}

fn configured_public_route(config: &AppConfig, method: &Method, path: &str) -> bool {
    approved_public_route(method, path)
        && (config.public_paths.is_empty()
            || config
                .public_paths
                .iter()
                .any(|configured| segment_glob_matches(configured, path)))
}

const CHAT_WS_ROUTE_PREFIX: &str = "/v1/chat/ws/";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WsCredentialError {
    MissingProtocol,
    DuplicateProtocol,
    MissingBearerCredential,
    DuplicateBearerCredential,
    QueryCredentialForbidden,
    ConflictingCredentials,
    InvalidBearerCredential,
}

impl WsCredentialError {
    const fn message(self) -> &'static str {
        match self {
            Self::MissingProtocol => "WebSocket subprotocol is required",
            Self::DuplicateProtocol => "Multiple WebSocket subprotocols are not allowed",
            Self::MissingBearerCredential => "WebSocket bearer credential is required",
            Self::DuplicateBearerCredential => {
                "Multiple WebSocket bearer credentials are not allowed"
            }
            Self::QueryCredentialForbidden => "WebSocket query credentials are forbidden",
            Self::ConflictingCredentials => "WebSocket credentials conflict",
            Self::InvalidBearerCredential => "Invalid WebSocket bearer credential",
        }
    }

    const fn reason(self) -> &'static str {
        match self {
            Self::MissingProtocol => "WS_SUBPROTOCOL_REQUIRED",
            Self::DuplicateProtocol => "DUPLICATE_WS_SUBPROTOCOL",
            Self::MissingBearerCredential => "WS_BEARER_REQUIRED",
            Self::DuplicateBearerCredential => "DUPLICATE_WS_BEARER",
            Self::QueryCredentialForbidden => "WS_QUERY_CREDENTIAL_FORBIDDEN",
            Self::ConflictingCredentials => "CONFLICTING_WS_CREDENTIALS",
            Self::InvalidBearerCredential => "INVALID_WS_BEARER",
        }
    }
}

/// Browser WebSocket authentication is limited to the canonical chat route.
/// The client offers the stable wire protocol plus one bearer credential
/// protocol; the credential is converted into the normal HTTP Bearer header.
fn is_canonical_chat_ws_route(method: &Method, path: &str) -> bool {
    *method == Method::GET
        && path
            .strip_prefix(CHAT_WS_ROUTE_PREFIX)
            .is_some_and(|user_id| {
                !user_id.is_empty()
                    && !user_id.contains('/')
                    && user_id.parse::<i64>().is_ok_and(|value| value > 0)
            })
}

fn extract_chat_ws_credential(req: &mut Request) -> Result<(), WsCredentialError> {
    if !is_canonical_chat_ws_route(req.method(), req.uri().path()) {
        return Ok(());
    }
    if req.uri().query().is_some() {
        return Err(WsCredentialError::QueryCredentialForbidden);
    }

    let protocols = req
        .headers()
        .get_all("sec-websocket-protocol")
        .iter()
        .flat_map(|value| value.as_bytes().split(|byte| *byte == b','))
        .map(|value| std::str::from_utf8(value.trim_ascii()).ok())
        .collect::<Option<Vec<_>>>()
        .ok_or(WsCredentialError::InvalidBearerCredential)?;
    if protocols.is_empty() {
        return Err(WsCredentialError::MissingProtocol);
    }

    let unknown_count = protocols
        .iter()
        .filter(|protocol| {
            **protocol != CHAT_WS_SUBPROTOCOL
                && !protocol.starts_with(CHAT_WS_BEARER_SUBPROTOCOL_PREFIX)
        })
        .count();
    if unknown_count > 0 {
        return Err(WsCredentialError::DuplicateProtocol);
    }
    let stable_count = protocols
        .iter()
        .filter(|protocol| **protocol == CHAT_WS_SUBPROTOCOL)
        .count();
    let bearer_tokens = protocols
        .iter()
        .filter_map(|protocol| protocol.strip_prefix(CHAT_WS_BEARER_SUBPROTOCOL_PREFIX))
        .collect::<Vec<_>>();
    if stable_count != 1 {
        return Err(if stable_count == 0 {
            WsCredentialError::MissingProtocol
        } else {
            WsCredentialError::DuplicateProtocol
        });
    }
    if bearer_tokens.is_empty() {
        return Err(WsCredentialError::MissingBearerCredential);
    }
    if bearer_tokens.len() != 1 {
        return Err(WsCredentialError::DuplicateBearerCredential);
    }
    let token = bearer_tokens[0].trim();
    if token.is_empty() {
        return Err(WsCredentialError::InvalidBearerCredential);
    }
    if req.headers().contains_key("authorization") {
        return Err(WsCredentialError::ConflictingCredentials);
    }

    let authorization = HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| WsCredentialError::InvalidBearerCredential)?;
    req.headers_mut().insert("authorization", authorization);
    req.headers_mut().insert(
        "sec-websocket-protocol",
        HeaderValue::from_static(CHAT_WS_SUBPROTOCOL),
    );
    Ok(())
}

fn route_credential_policy_inner(
    method: &Method,
    path: &str,
    configured_public: bool,
) -> RouteCredentialPolicy {
    if configured_public {
        return RouteCredentialPolicy::PublicOnly;
    }

    match (method, path) {
        (&Method::POST, "/api/v1/auth/sessions/refresh")
        | (&Method::POST, "/api/v1/auth/sessions/switch-card") => {
            RouteCredentialPolicy::RefreshOnly
        }
        (&Method::POST, "/api/v1/auth/sessions/logout")
        | (&Method::POST, "/api/v1/auth/sessions/revoke") => RouteCredentialPolicy::AccessOrRefresh,
        (&Method::POST, "/api/v1/auth/internal/sessions") => RouteCredentialPolicy::InternalOnly,
        _ => RouteCredentialPolicy::AccessOnly,
    }
}

fn route_credential_policy_with_config(
    config: &AppConfig,
    method: &Method,
    path: &str,
) -> RouteCredentialPolicy {
    route_credential_policy_inner(method, path, configured_public_route(config, method, path))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InternalSessionRequest {
    pub user_id: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InternalIdempotencyClaim {
    Claimed,
    Duplicate,
}

fn internal_header<'a>(req: &'a Request, name: &str) -> Option<&'a str> {
    req.headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn internal_error(req: &Request, status: u16, message: &str, reason: &str) -> Response {
    json_error(
        req.method().as_str(),
        req.uri().path(),
        internal_header(req, "x-internal-request-id").or_else(|| request_trace_id(req)),
        status,
        message,
        if status == 503 {
            "DEPENDENCY_UNAVAILABLE"
        } else {
            "UNAUTHORIZED"
        },
        reason,
    )
}

async fn claim_internal_replay(
    config: &AppConfig,
    input: &astral_common::middleware::internal_signature::InternalSignatureInput<'_>,
) -> Result<bool, ()> {
    let mut conn = redis_conn_with_url(&config.redis_url).await?;
    let key = astral_common::middleware::internal_signature::replay_key("gateway", input);
    let result: Option<String> = tokio::time::timeout(
        std::time::Duration::from_secs(REDIS_TIMEOUT_SECS),
        redis::cmd("SET")
            .arg(key)
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(config.gateway.timestamp_tolerance_secs.max(60))
            .query_async(&mut conn),
    )
    .await
    .map_err(|_| ())?
    .map_err(|_| ())?;
    Ok(result.is_some())
}

async fn claim_internal_idempotency(
    config: &AppConfig,
    caller: &str,
    route: &str,
    key: &str,
    body_hash: &str,
) -> Result<InternalIdempotencyClaim, ()> {
    let mut conn = redis_conn_with_url(&config.redis_url).await?;
    let redis_key = astral_common::middleware::internal_signature::idempotency_key(
        "gateway", caller, route, key,
    );
    let marker = format!("processing:{body_hash}");
    let result: Option<String> = tokio::time::timeout(
        std::time::Duration::from_secs(REDIS_TIMEOUT_SECS),
        redis::cmd("SET")
            .arg(&redis_key)
            .arg(marker)
            .arg("NX")
            .arg("EX")
            .arg(300)
            .query_async(&mut conn),
    )
    .await
    .map_err(|_| ())?
    .map_err(|_| ())?;
    if result.is_some() {
        return Ok(InternalIdempotencyClaim::Claimed);
    }
    let existing: Option<String> = tokio::time::timeout(
        std::time::Duration::from_secs(REDIS_TIMEOUT_SECS),
        conn.get(&redis_key),
    )
    .await
    .map_err(|_| ())?
    .map_err(|_| ())?;
    match existing.as_deref() {
        Some(value) if value.ends_with(body_hash) => Ok(InternalIdempotencyClaim::Duplicate),
        Some(_) => Err(()),
        None => Err(()),
    }
}

pub(crate) async fn complete_internal_idempotency(
    config: &AppConfig,
    caller: &str,
    route: &str,
    key: &str,
    body_hash: &str,
) -> Result<(), ()> {
    let mut conn = redis_conn_with_url(&config.redis_url).await?;
    let redis_key = astral_common::middleware::internal_signature::idempotency_key(
        "gateway", caller, route, key,
    );
    tokio::time::timeout(
        std::time::Duration::from_secs(REDIS_TIMEOUT_SECS),
        redis::cmd("SET")
            .arg(redis_key)
            .arg(format!("completed:{body_hash}"))
            .arg("EX")
            .arg(300)
            .query_async::<()>(&mut conn),
    )
    .await
    .map_err(|_| ())?
    .map_err(|_| ())
}

pub(crate) async fn release_internal_idempotency(
    config: &AppConfig,
    caller: &str,
    route: &str,
    key: &str,
) -> Result<(), ()> {
    let mut conn = redis_conn_with_url(&config.redis_url).await?;
    let redis_key = astral_common::middleware::internal_signature::idempotency_key(
        "gateway", caller, route, key,
    );
    tokio::time::timeout(
        std::time::Duration::from_secs(REDIS_TIMEOUT_SECS),
        conn.del::<_, ()>(redis_key),
    )
    .await
    .map_err(|_| ())?
    .map_err(|_| ())
}

/// Verify the exact Learn -> Gateway internal session assertion before the
/// global sanitizer/JWT policy can treat the request as an ordinary route.
pub async fn internal_session_auth_middleware_with_config(
    config: AppConfig,
    req: Request,
    next: Next,
) -> Response {
    if req.method() != Method::POST || req.uri().path() != INTERNAL_SESSION_PATH {
        return internal_error(
            &req,
            401,
            "Internal route authentication required",
            "INTERNAL_AUTH_REQUIRED",
        );
    }
    if req.uri().query().is_some() || req.headers().contains_key("authorization") {
        return internal_error(
            &req,
            401,
            "Invalid internal session request",
            "INTERNAL_REQUEST_INVALID",
        );
    }
    let required = [
        "x-internal-protocol",
        "x-internal-service",
        "x-internal-caller",
        "x-internal-timestamp",
        "x-internal-nonce",
        "x-internal-request-id",
        "x-idempotency-key",
        "x-internal-body-sha256",
        "x-internal-signature",
        "x-internal-key-id",
        "x-internal-route",
    ];
    if required
        .iter()
        .any(|name| internal_header(&req, name).is_none())
    {
        return internal_error(
            &req,
            401,
            "Internal assertion is incomplete",
            "INTERNAL_ASSERTION_MISSING",
        );
    }

    let (parts, body_stream) = req.into_parts();
    let body = match axum::body::to_bytes(body_stream, 1024 * 1024).await {
        Ok(body) => body,
        Err(_) => {
            return internal_error_from_parts(
                INTERNAL_SESSION_PATH,
                "",
                401,
                "Internal request body is too large",
                "BODY_TOO_LARGE",
            )
        }
    };
    let body_hash = astral_common::middleware::internal_signature::sha256_hex(&body);
    let parsed: InternalSessionRequest =
        match serde_json::from_slice::<InternalSessionRequest>(&body) {
            Ok(value) if value.user_id > 0 => value,
            _ => {
                return internal_error_from_parts(
                    INTERNAL_SESSION_PATH,
                    "",
                    401,
                    "Invalid internal session body",
                    "BODY_INVALID",
                )
            }
        };
    let req = Request::from_parts(parts, Body::from(body));

    let user_id_string = parsed.user_id.to_string();
    let protocol = internal_header(&req, "x-internal-protocol")
        .unwrap_or("")
        .to_string();
    let service = internal_header(&req, "x-internal-service")
        .unwrap_or("")
        .to_string();
    let caller = internal_header(&req, "x-internal-caller")
        .unwrap_or("")
        .to_string();
    let key_id = internal_header(&req, "x-internal-key-id")
        .unwrap_or("")
        .to_string();
    let route = internal_header(&req, "x-internal-route")
        .unwrap_or("")
        .to_string();
    let timestamp = internal_header(&req, "x-internal-timestamp")
        .unwrap_or("")
        .to_string();
    let nonce = internal_header(&req, "x-internal-nonce")
        .unwrap_or("")
        .to_string();
    let request_id = internal_header(&req, "x-internal-request-id")
        .unwrap_or("")
        .to_string();
    let idempotency_key = internal_header(&req, "x-idempotency-key")
        .unwrap_or("")
        .to_string();
    let signed_body_hash = internal_header(&req, "x-internal-body-sha256")
        .unwrap_or("")
        .to_string();
    let signature = internal_header(&req, "x-internal-signature")
        .unwrap_or("")
        .to_string();
    if protocol != astral_common::middleware::internal_signature::INTERNAL_PROTOCOL_VERSION
        || service != astral_common::middleware::internal_signature::INTERNAL_CALLER_LEARN
        || caller != astral_common::middleware::internal_signature::INTERNAL_CALLER_LEARN
        || key_id != astral_common::middleware::internal_signature::KEY_ID_LEARN_TO_GATEWAY
        || route != astral_common::middleware::internal_signature::ROUTE_LEARN_TO_GATEWAY
        || signed_body_hash != body_hash
        || !astral_common::middleware::internal_signature::valid_sha256_hex(&signed_body_hash)
    {
        return internal_error(
            &req,
            401,
            "Invalid internal assertion",
            "INTERNAL_ASSERTION_INVALID",
        );
    }
    let query = astral_common::middleware::internal_signature::normalize_query(req.uri().query());
    let input = astral_common::middleware::internal_signature::InternalSignatureInput {
        protocol_version: &protocol,
        key_id: &key_id,
        caller_service: &service,
        method: req.method().as_str(),
        path: req.uri().path(),
        normalized_query: &query,
        body_sha256: &signed_body_hash,
        target_user_id: &user_id_string,
        timestamp: &timestamp,
        nonce: &nonce,
        request_id: &request_id,
        idempotency_key: &idempotency_key,
        route: &route,
    };
    if !astral_common::middleware::internal_signature::timestamp_is_within_tolerance(
        input.timestamp,
        config.gateway.timestamp_tolerance_secs,
        time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000,
    ) || !astral_common::middleware::internal_signature::verify_internal_signature(
        &config.internal_service_secret,
        &input,
        &signature,
    ) {
        return internal_error(
            &req,
            401,
            "Invalid internal assertion",
            "INTERNAL_SIGNATURE_INVALID",
        );
    }
    match claim_internal_replay(&config, &input).await {
        Ok(true) => {}
        Ok(false) => {
            return internal_error(
                &req,
                401,
                "Internal assertion replayed",
                "INTERNAL_REPLAY_DETECTED",
            )
        }
        Err(_) => {
            return internal_error(
                &req,
                503,
                "Internal authentication dependency unavailable",
                "AUTH_STATE_UNAVAILABLE",
            )
        }
    }
    match claim_internal_idempotency(
        &config,
        input.caller_service,
        input.route,
        input.idempotency_key,
        input.body_sha256,
    )
    .await
    {
        Ok(InternalIdempotencyClaim::Claimed) => next.run(req).await,
        Ok(InternalIdempotencyClaim::Duplicate) => internal_error(
            &req,
            409,
            "Internal request already completed or in flight",
            "IDEMPOTENCY_REPLAY",
        ),
        Err(_) => internal_error(
            &req,
            409,
            "Idempotency key is bound to another request",
            "IDEMPOTENCY_CONFLICT",
        ),
    }
}

fn internal_error_from_parts(
    path: &str,
    request_id: &str,
    status: u16,
    message: &str,
    reason: &str,
) -> Response {
    json_error(
        "POST",
        path,
        (!request_id.is_empty()).then_some(request_id),
        status,
        message,
        "UNAUTHORIZED",
        reason,
    )
}

pub async fn sanitize_internal_auth_headers(mut req: Request, next: Next) -> Response {
    if req.method() == Method::POST && req.uri().path() == INTERNAL_SESSION_PATH {
        return next.run(req).await;
    }
    let headers = req.headers_mut();
    for name in INTERNAL_AUTH_HEADERS {
        headers.remove(*name);
    }
    let names: Vec<HeaderName> = headers
        .keys()
        .filter(|name| name.as_str() != "authorization" && is_sensitive_auth_header(name.as_str()))
        .cloned()
        .collect();
    for name in names {
        headers.remove(name);
    }
    next.run(req).await
}

/// JWT 认证中间件：公共路径放行 → JWT 校验 → 租户状态拦截 → 身份头注入
///
/// 对齐 Java `JwtGlobalFilter.filter()`
pub async fn jwt_auth_middleware(
    State(config): State<AppConfig>,
    mut req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_owned();

    // Step 0: CORS 预检直通
    if req.method() == "OPTIONS" {
        return next.run(req).await;
    }

    // The exact internal route is authenticated by the dedicated assertion
    // middleware. It must not enter the public/Bearer policy below.
    if req.method() == Method::POST && path == INTERNAL_SESSION_PATH {
        return next.run(req).await;
    }

    // Browser WebSocket clients cannot set Authorization during the native
    // handshake. Translate the credential only for the canonical chat WS route;
    // all subsequent validation remains the normal HTTP Bearer path.
    if let Err(error) = extract_chat_ws_credential(&mut req) {
        return json_error(
            req.method().as_str(),
            &path,
            request_trace_id(&req),
            401,
            error.message(),
            "UNAUTHORIZED",
            error.reason(),
        );
    }

    // Route classification is performed before credential decoding. Unknown
    // routes are never treated as anonymous or refresh endpoints.
    let policy = route_credential_policy_with_config(&config, req.method(), &path);
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok());
    let token = match auth_header {
        Some(header) => match header
            .strip_prefix("Bearer ")
            .filter(|value| !value.trim().is_empty())
        {
            Some(value) => value.trim(),
            None => {
                return json_error(
                    req.method().as_str(),
                    &path,
                    request_trace_id(&req),
                    401,
                    "Invalid Authorization header",
                    "UNAUTHORIZED",
                    "AUTHENTICATION_REQUIRED",
                )
            }
        },
        None if matches!(policy, RouteCredentialPolicy::PublicOnly) => {
            return next.run(req).await;
        }
        None => {
            return json_error(
                req.method().as_str(),
                &path,
                request_trace_id(&req),
                401,
                "missing token",
                "UNAUTHORIZED",
                "AUTHENTICATION_REQUIRED",
            )
        }
    };

    let (claims, token_use) = match decode_v2_token(token, &config) {
        Ok(value) => value,
        Err(reason) => {
            return json_error(
                req.method().as_str(),
                &path,
                request_trace_id(&req),
                401,
                reason,
                "UNAUTHORIZED",
                reason,
            )
        }
    };
    if !policy.accepts(Some(token_use)) {
        return json_error(
            req.method().as_str(),
            &path,
            request_trace_id(&req),
            401,
            "Token type is not accepted on this route",
            "UNAUTHORIZED",
            "TOKEN_ROUTE_MISMATCH",
        );
    }
    if policy == RouteCredentialPolicy::InternalOnly {
        return json_error(
            req.method().as_str(),
            &path,
            request_trace_id(&req),
            401,
            "Internal route requires service authentication",
            "UNAUTHORIZED",
            "INTERNAL_AUTH_REQUIRED",
        );
    }
    if token_use == TokenUse::Refresh {
        // Refresh credentials are session capabilities only. They never carry
        // or produce business identity headers and never consult access grants.
        return next.run(req).await;
    }

    let subject = match validated_subject(&claims) {
        Ok(subject) => subject,
        Err(reason) => {
            return json_error(
                req.method().as_str(),
                &path,
                request_trace_id(&req),
                401,
                reason,
                "UNAUTHORIZED",
                "AUTHENTICATION_REQUIRED",
            )
        }
    };

    let tenant_id = match optional_tenant_id(&claims) {
        Ok(tenant_id) => tenant_id,
        Err(reason) => {
            return json_error(
                req.method().as_str(),
                &path,
                request_trace_id(&req),
                401,
                reason,
                "UNAUTHORIZED",
                reason,
            )
        }
    };

    // Any Bearer credential, including one on a public path, must represent a
    // live access session. Public paths only bypass authentication when no
    // credentials were supplied at all.
    {
        let mut conn = match redis_conn_with_url(&config.redis_url).await {
            Ok(conn) => conn,
            Err(_) => {
                return dependency_unavailable(req.method().as_str(), &path, request_trace_id(&req))
            }
        };
        let revoked: bool = match tokio::time::timeout(
            std::time::Duration::from_secs(REDIS_TIMEOUT_SECS),
            conn.exists::<String, bool>(format!("jwt:revoked:{}", claims.jti)),
        )
        .await
        {
            Ok(Ok(value)) => value,
            _ => {
                return dependency_unavailable(req.method().as_str(), &path, request_trace_id(&req))
            }
        };
        if revoked {
            return json_error(
                req.method().as_str(),
                &path,
                request_trace_id(&req),
                401,
                "Token has been revoked",
                "UNAUTHORIZED",
                "TOKEN_REVOKED",
            );
        }

        // 对齐 Java `JwtGlobalFilter`：
        // 1) `access:jti:{jti}` 必须存在，且其标量值必须等于 JWT subject（OFF 模式同样强制值比对，
        //    防止"投影残留/改写后仅剩 key"绕过撤销语义）；
        // 2) 非 OFF 模式下读取 `access:grant:{jti}` 并校验版本化会话字段；
        //    REQUIRE 模式下校验必须通过（fail-closed），EMIT 模式读取失败 fail-closed 但校验结果不阻塞。
        let scalar: Option<String> = match tokio::time::timeout(
            std::time::Duration::from_secs(REDIS_TIMEOUT_SECS),
            conn.get::<_, Option<String>>(format!("access:jti:{}", claims.jti)),
        )
        .await
        {
            Ok(Ok(value)) => value,
            _ => {
                return dependency_unavailable(req.method().as_str(), &path, request_trace_id(&req))
            }
        };
        let scalar_live = scalar
            .as_deref()
            .is_some_and(|value| value == claims.sub.as_str());
        if !scalar_live {
            return json_error(
                req.method().as_str(),
                &path,
                request_trace_id(&req),
                401,
                "Access session not found",
                "UNAUTHORIZED",
                "SESSION_NOT_FOUND",
            );
        }

        let mode = config.session_grant_claims_mode.to_uppercase();
        if mode == "EMIT" || mode == "REQUIRE" {
            let grant_json: Option<String> = match tokio::time::timeout(
                std::time::Duration::from_secs(REDIS_TIMEOUT_SECS),
                conn.get::<_, Option<String>>(format!("access:grant:{}", claims.jti)),
            )
            .await
            {
                Ok(Ok(value)) => value,
                _ => {
                    return dependency_unavailable(
                        req.method().as_str(),
                        &path,
                        request_trace_id(&req),
                    )
                }
            };
            let outcome = verify_session_grant(&claims, grant_json.as_deref());
            if mode == "REQUIRE" && !matches!(outcome, GrantOutcome::Match) {
                return json_error(
                    req.method().as_str(),
                    &path,
                    request_trace_id(&req),
                    401,
                    "Token has been revoked",
                    "UNAUTHORIZED",
                    "TOKEN_REVOKED",
                );
            }
            // EMIT：grant 读取失败已在上面 fail-closed；校验结果不阻塞（对齐 Java）。
        }
    }

    // Step 4: 注入身份头
    if let Ok(v) = HeaderValue::from_str(subject) {
        req.headers_mut()
            .insert(HeaderName::from_static("x-user-id"), v);
    }
    if let Some(cid) = &claims.identity_card_id {
        if let Ok(v) = HeaderValue::from_str(&cid.to_string()) {
            req.headers_mut()
                .insert(HeaderName::from_static(IDENTITY_CARD_ID_HEADER), v);
        }
    }
    if let Some(cid) = &claims.user_card_id {
        if let Ok(v) = HeaderValue::from_str(&cid.to_string()) {
            req.headers_mut()
                .insert(HeaderName::from_static(USER_CARD_ID_HEADER), v);
        }
    }
    if let Some(tid) = &claims.user_card_tenant_id {
        if let Ok(v) = HeaderValue::from_str(&tid.to_string()) {
            req.headers_mut()
                .insert(HeaderName::from_static(USER_CARD_TENANT_ID_HEADER), v);
        }
    }
    if let Some(did) = &claims.user_card_domain_id {
        if let Ok(v) = HeaderValue::from_str(&did.to_string()) {
            req.headers_mut()
                .insert(HeaderName::from_static(USER_CARD_DOMAIN_ID_HEADER), v);
        }
    }
    if let Some(tid) = &claims.template_id {
        if let Ok(v) = HeaderValue::from_str(&tid.to_string()) {
            req.headers_mut()
                .insert(HeaderName::from_static("x-template-id"), v);
        }
    }
    if let Some(ref status) = claims.tenant_status {
        if let Ok(v) = HeaderValue::from_str(status) {
            req.headers_mut()
                .insert(HeaderName::from_static("x-tenant-status"), v);
        }
    }
    if let Ok(v) = HeaderValue::from_str(&claims.jti) {
        req.headers_mut()
            .insert(HeaderName::from_static("x-token-id"), v);
    }
    if let Ok(v) = HeaderValue::from_str(token_use.as_str()) {
        req.headers_mut()
            .insert(HeaderName::from_static(TOKEN_USE_HEADER), v);
    }
    if let Ok(v) = HeaderValue::from_str(
        PrincipalKind::parse(&claims.principal_kind)
            .unwrap()
            .as_str(),
    ) {
        req.headers_mut()
            .insert(HeaderName::from_static(PRINCIPAL_KIND_HEADER), v);
    }
    if let Ok(v) = HeaderValue::from_str(&claims.claims_version.to_string()) {
        req.headers_mut()
            .insert(HeaderName::from_static(CLAIMS_VERSION_HEADER), v);
    }
    if !claims.roles.is_empty() {
        let roles_str = claims.roles.join(",");
        if let Ok(v) = HeaderValue::from_str(&roles_str) {
            req.headers_mut()
                .insert(HeaderName::from_static("x-user-roles"), v);
        }
    }

    // Step 4.5: 权限动作码头注入（对齐 Java JwtGlobalFilter 权限头逻辑）
    // 从 JWT claims 中的 roles 推导 action codes（对齐 Java shouldForwardPermissions）
    // Java 基线: JwtGlobalFilter.java — 根据 roles 映射为 action codes 注入 X-Action-Codes
    if !claims.roles.is_empty() {
        let action_codes = derive_action_codes(&claims.roles);
        if !action_codes.is_empty() {
            // 权限头截断保护（对齐 Java maxPermissionHeaderLength）
            let max_len = config.max_permission_header_length;
            if action_codes.len() > max_len {
                if let Ok(v) = HeaderValue::from_str(&action_codes[..max_len]) {
                    req.headers_mut()
                        .insert(HeaderName::from_static("x-action-codes"), v);
                }
                if let Ok(v) = HeaderValue::from_bytes(b"true") {
                    req.headers_mut()
                        .insert(HeaderName::from_static("x-permissions-truncated"), v);
                }
            } else if let Ok(v) = HeaderValue::from_str(&action_codes) {
                req.headers_mut()
                    .insert(HeaderName::from_static("x-action-codes"), v);
            }
        }
    }

    // Step 4.6: X-Perms-Ref 注入（对齐 Java permRefEnabled 逻辑）
    // 权限引用头，供下游服务校验权限评估结果引用
    if let Some(card_id) = claims.user_card_id {
        let perms_ref = format!("user-card:{}", card_id);
        if let Ok(v) = HeaderValue::from_str(&perms_ref) {
            req.headers_mut()
                .insert(HeaderName::from_static("x-perms-ref"), v);
        }
    }

    // Step 4.7: X-Request-Id / X-Trace-Id 透传
    if !req.headers().contains_key("x-request-id") {
        if let Ok(v) =
            HeaderValue::from_str(&format!("req-{}", &claims.jti[..8.min(claims.jti.len())]))
        {
            req.headers_mut()
                .insert(HeaderName::from_static("x-request-id"), v);
        }
    }
    if !req.headers().contains_key("x-trace-id") {
        if let Ok(v) = HeaderValue::from_str(&claims.jti) {
            req.headers_mut()
                .insert(HeaderName::from_static("x-trace-id"), v);
        }
    }

    // Step 5: 租户状态检查（SUSPENDED / TERMINATED → 拒绝）
    // 先检查 JWT claims 中的状态
    if let Some(ref status) = claims.tenant_status {
        let upper = status.to_uppercase();
        if upper == "SUSPENDED" || upper == "TERMINATED" {
            tracing::warn!(tenant_status = %status, path = %path, "tenant is {status}");
            return json_error(
                req.method().as_str(),
                &path,
                request_trace_id(&req),
                401,
                &format!("tenant {status}"),
                "UNAUTHORIZED",
                "TENANT_NOT_ACTIVE",
            );
        }
    }

    // Step 6: 受保护请求必须成功获取最新租户状态；Redis 故障时拒绝访问。
    if let Some(tid) = tenant_id {
        let tid_str = tid.to_string();
        let cached_status = match fetch_cached_tenant_status(&tid_str, &config.redis_url).await {
            Ok(Some(status)) => status,
            Ok(None) => {
                tracing::warn!(tenant_id = %tid_str, "tenant status cache missing");
                return dependency_unavailable(
                    req.method().as_str(),
                    &path,
                    request_trace_id(&req),
                );
            }
            Err(_) => {
                return dependency_unavailable(req.method().as_str(), &path, request_trace_id(&req))
            }
        };
        let upper = cached_status.to_uppercase();
        if upper == "SUSPENDED" || upper == "TERMINATED" {
            tracing::warn!(tenant_id = %tid_str, tenant_status = %upper, "tenant status check (redis): rejected");
            return json_error(
                req.method().as_str(),
                &path,
                request_trace_id(&req),
                401,
                &format!("Tenant is {upper}"),
                "UNAUTHORIZED",
                "TENANT_NOT_ACTIVE",
            );
        }
    }

    next.run(req).await
}

/// 推导权限动作码（对齐 Java JwtGlobalFilter 权限映射逻辑）
///
/// JWT roles 已统一为 `["USER"]`（对齐 project_memory 角色统一策略与 §0.12
/// 特权通道禁令：禁止从 cardType 推导 SUPER_ADMIN/ADMIN 等角色）。
/// X-Action-Codes 头仅作为兼容透传注入下游，不作为 Rust 授权放行条件
/// （设计 §4）。因此不再按角色字符串特判动作码，统一返回 "read"。
fn derive_action_codes(_roles: &[String]) -> String {
    "read".to_string()
}

/// 统一 JSON 错误响应（对齐 Java `JwtGlobalFilter.writeErrorResponse`）
///
/// 响应体：code/message/traceId/requestPath/requestMethod/errorType/decision/reasonCode，
/// 并回写 `X-Trace-Id` 响应头。traceId 优先复用入站 `x-request-id`（JWT 中间件
/// Step 4.7 已注入），缺失时生成网关自有值。
fn json_error(
    method: &str,
    path: &str,
    trace_id: Option<&str>,
    status: u16,
    message: &str,
    error_type: &str,
    reason: &str,
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
        "decision": reason,
        "reasonCode": reason,
    });
    Response::builder()
        .status(StatusCode::from_u16(status).unwrap())
        .header("X-Trace-Id", &trace_id)
        .header("Content-Type", "application/json;charset=UTF-8")
        .body(Body::from(body.to_string()))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// 从请求上下文提取 traceId（JWT 中间件 Step 4.7 已注入 x-request-id）。
fn request_trace_id(req: &Request) -> Option<&str> {
    req.headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
}

/// Redis 依赖不可用时的 fail-closed 响应（对齐 Java `JwtGlobalFilter.unavailable()`
/// 返回 503 SERVICE_UNAVAILABLE + Retry-After；前端对 401 会触发会话失效登出，
/// 503 视为可重试的瞬时基础设施故障）。
fn dependency_unavailable(method: &str, path: &str, trace_id: Option<&str>) -> Response {
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
        "code": 503,
        "message": "Authentication dependency unavailable",
        "traceId": trace_id,
        "requestPath": path,
        "requestMethod": method,
        "errorType": "DEPENDENCY_UNAVAILABLE",
        "decision": "AUTH_STATE_UNAVAILABLE",
        "reasonCode": "AUTH_STATE_UNAVAILABLE",
    });
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header("Retry-After", "3")
        .header("X-Trace-Id", &trace_id)
        .header("Content-Type", "application/json;charset=UTF-8")
        .body(Body::from(body.to_string()))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_common::token_contract::CLAIMS_VERSION;

    fn claims(sub: &str) -> JwtClaims {
        JwtClaims {
            claims_version: CLAIMS_VERSION,
            issuer: "identity".into(),
            audience: "astral-api".into(),
            sub: sub.into(),
            jti: "jti".into(),
            roles: vec![],
            token_use: "ACCESS".into(),
            principal_kind: "PLATFORM_USER".into(),
            identity_card_id: Some(10),
            user_card_id: Some(40),
            user_card_tenant_id: Some(20),
            user_card_domain_id: Some(30),
            template_id: None,
            structure_node_id: None,
            tenant_status: None,
            permissions: None,
            sid: Some(1),
            session_version: Some(1),
            sev: Some(1),
            family_id: Some(1),
            exp: usize::MAX,
            iat: 0,
            nbf: 0,
        }
    }

    #[test]
    fn session_grant_requires_exact_session_version() {
        let grant = serde_json::json!({
            "formatVersion": 2,
            "principalKind": "PLATFORM_USER",
            "userId": 42,
            "sessionId": 1,
            "identityCardId": 10,
            "userCardId": 40,
            "userCardTenantId": 20,
            "userCardDomainId": 30,
            "sessionVersion": 2,
            "sessionEpoch": 1,
            "tokenFamilyId": 1,
            "sessionState": "ACTIVE",
            "issuedAtEpochSecond": 0,
            "expiresAtEpochSecond": time::OffsetDateTime::now_utc().unix_timestamp() + 3600,
        })
        .to_string();

        assert!(matches!(
            verify_session_grant(&claims("42"), Some(&grant)),
            GrantOutcome::Mismatch
        ));
    }

    #[test]
    fn app_user_session_grant_is_identity_only() {
        let mut claims = claims("42");
        claims.principal_kind = "APP_USER".into();
        claims.user_card_id = None;
        claims.user_card_tenant_id = None;
        claims.user_card_domain_id = None;
        let grant = serde_json::json!({
            "formatVersion": 2,
            "principalKind": "APP_USER",
            "userId": 42,
            "sessionId": 1,
            "identityCardId": 10,
            "userCardId": null,
            "userCardTenantId": null,
            "userCardDomainId": null,
            "sessionVersion": 1,
            "sessionEpoch": 1,
            "tokenFamilyId": 1,
            "sessionState": "ACTIVE",
            "issuedAtEpochSecond": 0,
            "expiresAtEpochSecond": time::OffsetDateTime::now_utc().unix_timestamp() + 3600,
        })
        .to_string();

        assert!(matches!(
            verify_session_grant(&claims, Some(&grant)),
            GrantOutcome::Match
        ));
    }

    #[test]
    fn session_grant_rejects_legacy_card_id_and_unknown_fields() {
        let grant = serde_json::json!({
            "formatVersion": 2,
            "principalKind": "PLATFORM_USER",
            "userId": 42,
            "sessionId": 1,
            "cardId": 10,
            "identityCardId": 10,
            "userCardId": 40,
            "userCardTenantId": 20,
            "userCardDomainId": 30,
            "sessionVersion": 1,
            "sessionEpoch": 1,
            "tokenFamilyId": 1,
            "sessionState": "ACTIVE",
            "issuedAtEpochSecond": 0,
            "expiresAtEpochSecond": time::OffsetDateTime::now_utc().unix_timestamp() + 3600,
        })
        .to_string();

        assert!(matches!(
            verify_session_grant(&claims("42"), Some(&grant)),
            GrantOutcome::Mismatch
        ));
    }

    #[test]
    fn app_user_grant_with_user_card_scope_is_rejected() {
        let mut claims = claims("42");
        claims.principal_kind = "APP_USER".into();
        claims.user_card_id = None;
        claims.user_card_tenant_id = None;
        claims.user_card_domain_id = None;
        let grant = serde_json::json!({
            "formatVersion": 2,
            "principalKind": "APP_USER",
            "userId": 42,
            "sessionId": 1,
            "identityCardId": 10,
            "userCardId": 40,
            "userCardTenantId": 20,
            "userCardDomainId": 30,
            "sessionVersion": 1,
            "sessionEpoch": 1,
            "tokenFamilyId": 1,
            "sessionState": "ACTIVE",
            "issuedAtEpochSecond": 0,
            "expiresAtEpochSecond": time::OffsetDateTime::now_utc().unix_timestamp() + 3600,
        })
        .to_string();

        assert!(matches!(
            verify_session_grant(&claims, Some(&grant)),
            GrantOutcome::Mismatch
        ));
    }

    #[test]
    fn validated_subject_requires_matching_numeric_user_id() {
        assert_eq!(validated_subject(&claims("42")), Ok("42"));
        assert!(validated_subject(&claims("0")).is_err());
        assert!(validated_subject(&claims("-1")).is_err());
        assert!(validated_subject(&claims("not-a-number")).is_err());
    }

    #[test]
    fn tenant_context_requires_positive_user_card_tenant() {
        let mut claims = claims("42");
        assert_eq!(optional_tenant_id(&claims), Ok(Some(20)));
        claims.user_card_tenant_id = Some(0);
        assert_eq!(optional_tenant_id(&claims), Err("INVALID_TENANT_CONTEXT"));
    }

    #[test]
    fn tenant_context_rejects_non_positive_claim() {
        let mut claims = claims("42");
        claims.user_card_tenant_id = Some(0);
        assert_eq!(optional_tenant_id(&claims), Err("INVALID_TENANT_CONTEXT"));
        claims.user_card_tenant_id = Some(-1);
        assert_eq!(optional_tenant_id(&claims), Err("INVALID_TENANT_CONTEXT"));
    }

    #[test]
    fn tenant_context_accepts_positive_claim() {
        let mut claims = claims("42");
        claims.user_card_tenant_id = Some(42);
        assert_eq!(optional_tenant_id(&claims), Ok(Some(42)));
    }

    #[test]
    fn dependency_unavailable_is_service_unavailable() {
        let response = dependency_unavailable("GET", "/api/v1/auth/profile", Some("trace-1"));
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers().get("Retry-After").unwrap(), "3");
    }

    #[tokio::test]
    async fn redis_failures_are_visible_to_protected_check_seam() {
        assert!(redis_conn_with_url("redis://localhost:1").await.is_err());
        assert!(fetch_cached_tenant_status("42", "redis://localhost:1")
            .await
            .is_err());
    }

    #[test]
    fn derive_action_codes_ignores_role_strings_and_returns_read() {
        // JWT roles 已统一为 ["USER"]，X-Action-Codes 仅兼容透传不作放行条件（设计 §4）。
        // 无论传入何种角色字符串，都不得派生特权动作码，统一返回 "read"。
        assert_eq!(derive_action_codes(&[]), "read");
        assert_eq!(derive_action_codes(&["USER".to_string()]), "read");
        // 即使传入残留的 SUPER_ADMIN/ADMIN 角色字符串，也不得派生特权动作码。
        assert_eq!(derive_action_codes(&["SUPER_ADMIN".to_string()]), "read");
        assert_eq!(derive_action_codes(&["ADMIN".to_string()]), "read");
        assert_eq!(derive_action_codes(&["TEACHER".to_string()]), "read");
        assert_eq!(derive_action_codes(&["STUDENT".to_string()]), "read");
    }

    #[test]
    fn chat_ws_route_is_exact_and_segment_bounded() {
        assert!(is_canonical_chat_ws_route(&Method::GET, "/v1/chat/ws/42"));
        assert!(!is_canonical_chat_ws_route(&Method::POST, "/v1/chat/ws/42"));
        assert!(!is_canonical_chat_ws_route(
            &Method::GET,
            "/v1/chat/ws/42/extra"
        ));
        assert!(!is_canonical_chat_ws_route(
            &Method::GET,
            "/v1/chat/ws/not-a-user"
        ));
    }

    #[test]
    fn chat_ws_subprotocol_promotes_bearer_and_keeps_stable_protocol() {
        let mut request = Request::builder()
            .method(Method::GET)
            .uri("/v1/chat/ws/42")
            .header("sec-websocket-protocol", "astral-chat-v1, bearer.jwt-token")
            .body(Body::empty())
            .unwrap();

        extract_chat_ws_credential(&mut request).unwrap();

        assert_eq!(
            request.headers().get("authorization").unwrap(),
            "Bearer jwt-token"
        );
        assert_eq!(
            request.headers().get("sec-websocket-protocol").unwrap(),
            CHAT_WS_SUBPROTOCOL
        );
    }

    #[test]
    fn chat_ws_rejects_missing_invalid_duplicate_and_conflicting_credentials() {
        let mut missing = Request::builder()
            .method(Method::GET)
            .uri("/v1/chat/ws/42")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            extract_chat_ws_credential(&mut missing),
            Err(WsCredentialError::MissingProtocol)
        );

        let mut missing_bearer = Request::builder()
            .method(Method::GET)
            .uri("/v1/chat/ws/42")
            .header("sec-websocket-protocol", CHAT_WS_SUBPROTOCOL)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            extract_chat_ws_credential(&mut missing_bearer),
            Err(WsCredentialError::MissingBearerCredential)
        );

        let mut duplicate_protocol = Request::builder()
            .method(Method::GET)
            .uri("/v1/chat/ws/42")
            .header(
                "sec-websocket-protocol",
                "astral-chat-v1, astral-chat-v1, bearer.one",
            )
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            extract_chat_ws_credential(&mut duplicate_protocol),
            Err(WsCredentialError::DuplicateProtocol)
        );

        let mut duplicate_bearer = Request::builder()
            .method(Method::GET)
            .uri("/v1/chat/ws/42")
            .header(
                "sec-websocket-protocol",
                "astral-chat-v1, bearer.one, bearer.two",
            )
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            extract_chat_ws_credential(&mut duplicate_bearer),
            Err(WsCredentialError::DuplicateBearerCredential)
        );

        let mut invalid_bearer = Request::builder()
            .method(Method::GET)
            .uri("/v1/chat/ws/42")
            .header("sec-websocket-protocol", "astral-chat-v1, bearer.")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            extract_chat_ws_credential(&mut invalid_bearer),
            Err(WsCredentialError::InvalidBearerCredential)
        );

        let mut unknown_protocol = Request::builder()
            .method(Method::GET)
            .uri("/v1/chat/ws/42")
            .header(
                "sec-websocket-protocol",
                "astral-chat-v1, bearer.one, unknown",
            )
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            extract_chat_ws_credential(&mut unknown_protocol),
            Err(WsCredentialError::DuplicateProtocol)
        );

        let mut query_credential = Request::builder()
            .method(Method::GET)
            .uri("/v1/chat/ws/42?access_token=query-token")
            .header("sec-websocket-protocol", "astral-chat-v1, bearer.one")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            extract_chat_ws_credential(&mut query_credential),
            Err(WsCredentialError::QueryCredentialForbidden)
        );

        let mut conflicting = Request::builder()
            .method(Method::GET)
            .uri("/v1/chat/ws/42")
            .header("authorization", "Bearer header-token")
            .header(
                "sec-websocket-protocol",
                "astral-chat-v1, bearer.query-token",
            )
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            extract_chat_ws_credential(&mut conflicting),
            Err(WsCredentialError::ConflictingCredentials)
        );
    }

    #[test]
    fn non_chat_routes_do_not_interpret_websocket_credentials() {
        let mut request = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/auth/profile?access_token=not-a-credential")
            .header("sec-websocket-protocol", "bearer.not-a-credential")
            .body(Body::empty())
            .unwrap();
        extract_chat_ws_credential(&mut request).unwrap();
        assert!(request.headers().get("authorization").is_none());
        assert_eq!(request.uri().query(), Some("access_token=not-a-credential"));
    }

    #[test]
    fn segment_glob_is_segment_bounded() {
        assert!(segment_glob_matches(
            "/api/v1/auth/password/reset/*",
            "/api/v1/auth/password/reset/token"
        ));
        assert!(!segment_glob_matches(
            "/api/v1/auth/password/reset/*",
            "/api/v1/auth/password/reset/token/extra"
        ));
        assert!(!segment_glob_matches(
            "/api/v1/auth/password/reset/*",
            "/api/v1/auth/password/reset-extra"
        ));
    }

    #[test]
    fn public_policy_does_not_accept_refresh_or_mfa() {
        assert!(!RouteCredentialPolicy::PublicOnly.accepts(Some(TokenUse::Refresh)));
        assert_eq!(
            route_credential_policy_inner(
                &Method::GET,
                "/api/v1/auth/mfa/status",
                approved_public_route(&Method::GET, "/api/v1/auth/mfa/status")
            ),
            RouteCredentialPolicy::AccessOnly
        );
        assert_eq!(
            route_credential_policy_inner(
                &Method::POST,
                "/api/v1/auth/mfa/verify",
                approved_public_route(&Method::POST, "/api/v1/auth/mfa/verify")
            ),
            RouteCredentialPolicy::AccessOnly
        );
    }

    #[test]
    fn configured_public_paths_cannot_register_unknown_routes() {
        let config = AppConfig {
            public_paths: vec!["/api/v1/auth/not-registered".into()],
            ..Default::default()
        };
        assert_eq!(
            route_credential_policy_with_config(
                &config,
                &Method::POST,
                "/api/v1/auth/not-registered"
            ),
            RouteCredentialPolicy::AccessOnly
        );
        assert_eq!(
            route_credential_policy_with_config(
                &config,
                &Method::POST,
                "/api/v1/auth/password/reset/token"
            ),
            RouteCredentialPolicy::AccessOnly
        );
    }
    #[test]
    fn sensitive_header_filter_preserves_business_headers() {
        assert!(is_proxy_forbidden_header("x-claims-version"));
        assert!(is_proxy_forbidden_header("x-user-custom"));
        assert!(is_proxy_forbidden_header("authorization"));
        assert!(!is_proxy_forbidden_header("content-type"));
        assert!(!is_proxy_forbidden_header("accept"));
        assert!(!is_proxy_forbidden_header("idempotency-key"));
        assert!(!is_proxy_forbidden_header("x-request-id"));
    }

    #[test]
    fn route_matrix_is_strict() {
        let cases = [
            (
                Method::POST,
                "/api/v1/auth/sessions",
                RouteCredentialPolicy::PublicOnly,
            ),
            (
                Method::POST,
                "/api/v1/auth/register",
                RouteCredentialPolicy::PublicOnly,
            ),
            (
                Method::POST,
                "/api/v1/auth/password/forgot",
                RouteCredentialPolicy::PublicOnly,
            ),
            (
                Method::POST,
                "/api/v1/auth/password/reset/abc",
                RouteCredentialPolicy::PublicOnly,
            ),
            (
                Method::POST,
                "/api/v1/auth/verification/send",
                RouteCredentialPolicy::PublicOnly,
            ),
            (
                Method::POST,
                "/api/v1/auth/verification/verify",
                RouteCredentialPolicy::PublicOnly,
            ),
            (
                Method::POST,
                "/v1/app/users/login",
                RouteCredentialPolicy::PublicOnly,
            ),
            (
                Method::GET,
                "/api/v1/auth/mfa/status",
                RouteCredentialPolicy::AccessOnly,
            ),
            (
                Method::POST,
                "/api/v1/auth/mfa/verify",
                RouteCredentialPolicy::AccessOnly,
            ),
            (
                Method::POST,
                "/api/v1/auth/sessions/refresh",
                RouteCredentialPolicy::RefreshOnly,
            ),
            (
                Method::POST,
                "/api/v1/auth/sessions/switch-card",
                RouteCredentialPolicy::RefreshOnly,
            ),
            (
                Method::POST,
                "/api/v1/auth/sessions/logout",
                RouteCredentialPolicy::AccessOrRefresh,
            ),
            (
                Method::POST,
                "/api/v1/auth/sessions/revoke",
                RouteCredentialPolicy::AccessOrRefresh,
            ),
            (
                Method::POST,
                "/api/v1/auth/internal/sessions",
                RouteCredentialPolicy::InternalOnly,
            ),
        ];
        for (method, path, expected) in cases {
            assert_eq!(
                route_credential_policy_inner(&method, path, approved_public_route(&method, path)),
                expected,
                "{method} {path}"
            );
        }
        assert_eq!(
            route_credential_policy_inner(
                &Method::POST,
                "/api/v1/auth/sessions/refresh-extra",
                approved_public_route(&Method::POST, "/api/v1/auth/sessions/refresh-extra")
            ),
            RouteCredentialPolicy::AccessOnly
        );
        assert_eq!(
            route_credential_policy_inner(
                &Method::POST,
                "/api/v1/auth/token/refresh",
                approved_public_route(&Method::POST, "/api/v1/auth/token/refresh")
            ),
            RouteCredentialPolicy::AccessOnly
        );
        assert!(!RouteCredentialPolicy::RefreshOnly.accepts(Some(TokenUse::Access)));
        assert!(RouteCredentialPolicy::RefreshOnly.accepts(Some(TokenUse::Refresh)));
        assert!(RouteCredentialPolicy::PublicOnly.accepts(None));
        assert!(RouteCredentialPolicy::PublicOnly.accepts(Some(TokenUse::Access)));
        assert!(!RouteCredentialPolicy::PublicOnly.accepts(Some(TokenUse::Refresh)));
    }
}
