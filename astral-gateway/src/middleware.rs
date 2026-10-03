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
#[cfg(feature = "redis-compat")]
use redis::aio::ConnectionManager;
#[cfg(feature = "redis-compat")]
use redis::AsyncCommands;
use serde::Deserialize;
use std::sync::OnceLock;

use astral_common::config::AppConfig;
use astral_common::middleware::internal_signature::INTERNAL_SESSION_PATH;
use astral_common::middleware::{decode_v2_token, JwtClaims};
use astral_common::session_projection_store::SessionProjectionDecision;
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
#[cfg(feature = "redis-compat")]
const REDIS_TIMEOUT_SECS: u64 = 3;

#[cfg(feature = "redis-compat")]
static GATEWAY_REDIS: OnceLock<ConnectionManager> = OnceLock::new();

/// redis-compat feature 未编译：compat adapter 不存在，判定面恒为 strict
/// MySQL durable facts（与今天 adapter 未装配时的默认路径一致）。
#[cfg(not(feature = "redis-compat"))]
fn gateway_redis_adapter_installed() -> bool {
    false
}

#[cfg(feature = "redis-compat")]
fn gateway_redis_adapter_installed() -> bool {
    GATEWAY_REDIS.get().is_some()
}

/// compat 装配入口（仅 redis-compat feature 编译；feature-off 构建中本 API
/// 不存在——redis 编译层退役的显式 BREAKING 收敛点，登记于架构文档）。
#[cfg(feature = "redis-compat")]
pub async fn init_gateway_redis(redis_url: &str) -> Result<(), String> {
    if GATEWAY_REDIS.get().is_some() {
        return Ok(());
    }
    let client = redis::Client::open(redis_url).map_err(|error| error.to_string())?;
    let config = redis::aio::ConnectionManagerConfig::new()
        .set_connection_timeout(Some(std::time::Duration::from_secs(1)))
        .set_response_timeout(Some(std::time::Duration::from_millis(500)))
        .set_number_of_retries(0);
    let manager = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        ConnectionManager::new_with_config(client, config),
    )
    .await
    .map_err(|_| "Redis connection timed out".to_owned())?
    .map_err(|error| error.to_string())?;
    GATEWAY_REDIS
        .set(manager)
        .map_err(|_| "Gateway Redis manager already initialized".to_owned())
}

#[cfg(feature = "redis-compat")]
fn gateway_redis() -> RedisCheckResult<ConnectionManager> {
    GATEWAY_REDIS.get().cloned().ok_or(())
}

/// Protected-request Redis checks fail closed; tests can exercise the decision helpers without Redis.
#[cfg(feature = "redis-compat")]
type RedisCheckResult<T> = Result<T, ()>;

#[cfg(feature = "redis-compat")]
async fn redis_conn_with_url(_redis_url: &str) -> RedisCheckResult<redis::aio::ConnectionManager> {
    gateway_redis()
}

// ===== Redis-free 会话判定（strict MySQL durable facts + 可选镜像） =====

/// strict 会话判定数据面：MySQL 连接池（启动期由 runtime 装配一次）。
static GATEWAY_SESSION_DB: OnceLock<sqlx::MySqlPool> = OnceLock::new();

/// 安装 strict 会话判定面（Gateway 启动期调用一次）。
///
/// - `pool`：strict MySQL source 的连接池（`auth_session_jti_index` ×
///   `auth_device_session` × `auth_token_family` × `user_card` ×
///   `identity_card` 单条 JOIN）。
/// - `mirror`：可选的有界镜像加速器。**positive allow 只在单写者组合进程
///   且显式配置下启用**（`policy`）；独立多写者 Gateway 必须传
///   [`MirrorPolicy::DenyOnly`]——撤销 marker 仍可加速 deny，ALLOW 每请求
///   strict DB，直到自身拥有完整 channel proof/watermark。
/// - `disable_mirror_positive`：显式配置开关——置 true 时对镜像调用
///   `mark_suspect_permanent()`，positive cache 全部旁路（deny marker 加速
///   保留）。
pub fn install_gateway_session_auth(
    pool: sqlx::MySqlPool,
    mirror: Option<astral_common::session_projection_store::SessionProjectionMirror>,
    policy: astral_common::session_projection_store::MirrorPolicy,
    disable_mirror_positive: bool,
) -> Result<(), String> {
    if astral_common::session_projection_store::global_session_projection_store().is_some() {
        return Err("gateway session auth already initialized".into());
    }
    if disable_mirror_positive {
        if let Some(mirror) = &mirror {
            mirror.mark_suspect_permanent();
            tracing::warn!(
                "session grant mirror positive cache permanently disabled by configuration; allows are strict-DB only"
            );
        }
    }
    if astral_db::install_global_mysql_session_projection_store(pool.clone(), mirror, policy) {
        GATEWAY_SESSION_DB
            .set(pool)
            .map_err(|_| "gateway session db already initialized".to_owned())
    } else {
        Err("gateway session auth already initialized".into())
    }
}

/// strict 判定面的连接池句柄；未安装（无 DB 的测试/组合）返回 `None`。
fn gateway_session_db() -> Option<&'static sqlx::MySqlPool> {
    GATEWAY_SESSION_DB.get()
}

/// 从 Redis 获取缓存的租户状态（仅 redis-compat feature 编译）。
#[cfg(feature = "redis-compat")]
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

/// 把 JWT claims 换算成 strict 会话判定的绑定上下文（与 durable 事实逐项
/// 比对）。principal_kind 无法解析时留空：任何 durable 评估都不会匹配空
/// principal，天然 fail-closed。
fn session_bind_context(
    claims: &JwtClaims,
) -> astral_common::session_projection_store::SessionBindContext {
    astral_common::session_projection_store::SessionBindContext {
        user_id: claims.sub.parse::<i64>().unwrap_or(0),
        session_id: claims.sid.unwrap_or(0),
        session_version: claims.session_version.unwrap_or(0),
        session_epoch: claims.sev.unwrap_or(0),
        token_family_id: claims.family_id.unwrap_or(0),
        principal_kind: PrincipalKind::parse(&claims.principal_kind)
            .map(|kind| kind.as_str())
            .unwrap_or(""),
        identity_card_id: claims.identity_card_id,
        user_card_id: claims.user_card_id,
        user_card_tenant_id: claims.user_card_tenant_id,
        user_card_domain_id: claims.user_card_domain_id,
        expires_at_epoch_second: claims.exp as i64,
    }
}

// ===== 组合进程 positive 判定面强门 + JWT admission 栅栏（gateway-read-final） =====

/// strict 租户状态 DB 读取的硬 deadline：超时按依赖不可用 503 fail-closed，
/// 绝不无限等待（对齐签发侧复核 3s 预算）。
const TENANT_STATUS_DEADLINE_SECS: u64 = 3;

/// 组合进程 positive 判定面强条件（**观测事实，绝非 invented bool**；
/// 安装门与逐请求复验共用同一实现，条件缺一不可）：
///
/// 1. `LocalBus` 已安装且 `owners_ready()`——四个必需队列（含
///    auth.session.revocation / authorization.invalidation）的进程内 owner
///    全部注册且通道存活，撤销/失效 fanout 有真实消费者；
/// 2. **同一进程已安装**的 `memory_projection_hub` 通道健康（非 warming/
///    suspect/健康面失效）。hub 健康**不是**启动自然保证——warm 完成仍可能
///    suspect、本地 supervisor 初始 reconcile 异步；组合 main 的 readiness
///    等待持有租约要求 hub healthy + projection owner alive 后才 spawn
///    gateway，故组合内安装时刻本条件确定成立；
/// 3. aux marker：`auxiliary_authorization_mirror` 已安装——它只是**装配
///    资格**标记（其生产装配方要求启动期租约+warm-up 完成），绝不等于
///    运行期租约存活证明。
///
/// 运行期租约/健康存活不由本函数担保，而由 canonical verifier 的实时门
/// 承担：hub 辅助/strict 读取令牌（含 `runtime_owner_failed` 与健康推进；
/// 租约失联由组合 main 以 `mark_runtime_owner_failed` 关闭全部写/strict 读，
/// 先于 abort，而非普通 suspect）——即 admission 栅栏捕获与 `next.run` 前
/// 同栅栏复验。为假只降级（DenyOnly/strict DB + deadline），绝不 fail
/// startup，也绝不自造"我是组合进程"布尔。
pub(crate) fn composite_positive_ready() -> bool {
    match (
        astral_mq::local_bus::global_local_bus(),
        astral_db::memory_projection_hub(),
    ) {
        (Some(bus), Some(hub)) => {
            bus.owners_ready()
                && hub.channel_is_healthy()
                && astral_db::auxiliary_authorization_mirror().is_some()
        }
        _ => false,
    }
}

/// JWT 全链路 admission 栅栏：token 解码后、任何会话事实 await 之前捕获
/// 一次，`next.run` 之前**同栅栏复验**。栅栏失配一律 503 fail-closed；
/// 绝不重采样 token、绝不按 claims/flag 重新推导放行。
enum AuthorityFence {
    /// 组合进程：hub 权威读栅栏。捕获值是 hub 在"无活跃 source writer、
    /// 源未处于 unknown、健康/纪元未失效"时刻的 opaque 戳；复验通过才允许
    /// 携带捕获期证明的 admission 进入下游。
    Hub(astral_db::memory_projection_hub::AuthorityReadFence),
    /// 独立进程（hub 未安装）：判定面只有全局会话 store（positive 镜像
    /// 策略未安装 → Allow 只能来自 strict DB）。复验确认 hub 未在中途出现。
    Standalone,
}

impl AuthorityFence {
    /// 捕获点：session 判定之前调用恰好一次。hub 在位但栅栏不可用（活跃
    /// writer / unknown 源 / 健康面失效）返回 `None`——此时 canonical
    /// verifier 同样只会 `Unavailable`，语义一致。
    fn capture() -> Option<Self> {
        match astral_db::memory_projection_hub() {
            Some(hub) => hub.capture_authority_fence().map(Self::Hub),
            None => Some(Self::Standalone),
        }
    }

    /// `next.run` 前的同栅栏复验：hub 戳必须仍然匹配（期间任何 source
    /// writer begin/drop、纪元/健康推进都使旧戳失配）；独立进程必须仍是
    /// 无 hub 形态。失配 = 捕获期权威事实不再可信 → 503，绝不续用。
    fn still_valid(&self) -> bool {
        match self {
            Self::Hub(fence) => astral_db::memory_projection_hub()
                .is_some_and(|hub| hub.authority_fence_matches(*fence)),
            Self::Standalone => astral_db::memory_projection_hub().is_none(),
        }
    }
}

/// Step 6 租户状态检查模式（纯函数，fail-closed）。
///
/// `Warmed` = strict 会话判定 canonical verifier **实际返回 Allow**、claims
/// 租户上下文与卡绑定一致、组合 positive 强条件在请求时刻复观测为真、且
/// admission 栅栏为 hub 栅栏——此时 strict 会话 JOIN（tenant ×
/// tenant_domain_map 均 ACTIVE，绑定完整）或其 verified-only 镜像命中已经
/// 覆盖租户状态，跳过逐请求 duplicate tenant SQL。任一条件缺失即
/// `StrictDeadline`（保留 strict DB 读取 + 硬 deadline）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TenantStatusMode {
    Warmed,
    StrictDeadline,
}

fn tenant_status_mode(
    canonical_allow: bool,
    claims_tenant_bound: bool,
    composite_positive_ready: bool,
    fence_is_hub: bool,
) -> TenantStatusMode {
    if canonical_allow && claims_tenant_bound && composite_positive_ready && fence_is_hub {
        TenantStatusMode::Warmed
    } else {
        TenantStatusMode::StrictDeadline
    }
}

/// claims 租户与**本次判定所用的 bind** 的卡/租户绑定一致性（纯函数）。
///
/// 跳过 duplicate tenant SQL 的绑定前提：claims 租户（tid）必须等于 bind
/// 携带的租户，且 bind 真实携带 user_card（平台用户卡绑定）。两者不同——
/// 即使仅在未来 bind 构造与 claims 解耦时才可能出现——一律拒绝快路径回落
/// strict DB。durable 事实侧的 tenant 一致性由 canonical verifier 的
/// 逐项绑定评估（Allow 即证明 fact tenant == bind tenant）承担，本检查
/// 只钉住 claims ↔ bind 这一段。APP_USER（无卡绑定，tid None）不进本检查
/// 所在分支，天然保留 DB 路径。
fn claims_tenant_matches_bind(
    tenant_id: Option<i64>,
    bind: &astral_common::session_projection_store::SessionBindContext,
) -> bool {
    matches!(
        (tenant_id, bind.user_card_id, bind.user_card_tenant_id),
        (Some(tid), Some(card), Some(bound)) if bound == tid && card > 0
    )
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

/// durable replay 声明：`auth_internal_request_guard` 上的 "purge 过期 +
/// UNIQUE INSERT"（多节点安全；UNIQUE 约束即分布式互斥，TTL 由 expires_at
/// 承载）。DB 不可用时返回 `Err` → 调用方 503 fail-closed，绝不本地放行。
async fn claim_internal_replay(
    config: &AppConfig,
    input: &astral_common::middleware::internal_signature::InternalSignatureInput<'_>,
) -> Result<bool, ()> {
    let Some(pool) = gateway_session_db() else {
        return Err(());
    };
    let key = astral_common::middleware::internal_signature::replay_key("gateway", input);
    let ttl = config.gateway.timestamp_tolerance_secs.max(60);
    match astral_db::claim_replay_guard(pool, astral_db::GUARD_SCOPE_GATEWAY_REPLAY, &key, ttl)
        .await
    {
        Ok(astral_db::GuardClaim::Claimed) => Ok(true),
        Ok(astral_db::GuardClaim::Duplicate) => Ok(false),
        Err(_) => Err(()),
    }
}

async fn claim_internal_idempotency(
    _config: &AppConfig,
    caller: &str,
    route: &str,
    key: &str,
    body_hash: &str,
) -> Result<InternalIdempotencyClaim, ()> {
    let Some(pool) = gateway_session_db() else {
        return Err(());
    };
    let guard_key = astral_common::middleware::internal_signature::idempotency_key(
        "gateway", caller, route, key,
    );
    // processing 标记 TTL 与历史 Redis 语义一致（300s in-flight 窗口）。
    match astral_db::claim_idempotency_guard(
        pool,
        astral_db::GUARD_SCOPE_GATEWAY_IDEMPOTENCY,
        &guard_key,
        body_hash,
        300,
    )
    .await
    {
        Ok(astral_db::GuardClaim::Claimed) => Ok(InternalIdempotencyClaim::Claimed),
        Ok(astral_db::GuardClaim::Duplicate) => {
            let marker = astral_db::load_guard_marker(
                pool,
                astral_db::GUARD_SCOPE_GATEWAY_IDEMPOTENCY,
                &guard_key,
            )
            .await
            .map_err(|_| ())?;
            match astral_db::idempotency_marker_decision(marker.as_deref(), body_hash) {
                Ok(astral_db::GuardClaim::Duplicate) => Ok(InternalIdempotencyClaim::Duplicate),
                // 同 key 绑定不同请求体 / 行消失（并发 purge 竞态）→ 冲突拒绝。
                // marker 判定不会产生 Claimed（仅声明路径返回），穷尽匹配兜底拒绝。
                Ok(astral_db::GuardClaim::Claimed) | Err(_) => Err(()),
            }
        }
        Err(_) => Err(()),
    }
}

pub(crate) async fn complete_internal_idempotency(
    _config: &AppConfig,
    caller: &str,
    route: &str,
    key: &str,
    body_hash: &str,
) -> Result<(), ()> {
    let Some(pool) = gateway_session_db() else {
        return Err(());
    };
    let guard_key = astral_common::middleware::internal_signature::idempotency_key(
        "gateway", caller, route, key,
    );
    astral_db::complete_idempotency_guard(
        pool,
        astral_db::GUARD_SCOPE_GATEWAY_IDEMPOTENCY,
        &guard_key,
        body_hash,
        300,
    )
    .await
    .map_err(|_| ())
}

pub(crate) async fn release_internal_idempotency(
    _config: &AppConfig,
    caller: &str,
    route: &str,
    key: &str,
) -> Result<(), ()> {
    let Some(pool) = gateway_session_db() else {
        return Err(());
    };
    let guard_key = astral_common::middleware::internal_signature::idempotency_key(
        "gateway", caller, route, key,
    );
    astral_db::release_idempotency_guard(
        pool,
        astral_db::GUARD_SCOPE_GATEWAY_IDEMPOTENCY,
        &guard_key,
    )
    .await
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

    // JWT 全链路 admission 栅栏捕获点：在任何会话事实 await 之前捕获一次。
    // hub 在位但栅栏不可用（活跃 writer / unknown 源）时 canonical verifier
    // 同样只会 Unavailable，此处提前 503 语义一致（fail-closed）。
    let bind = session_bind_context(&claims);
    let authority_fence = match AuthorityFence::capture() {
        Some(fence) => fence,
        None => {
            return dependency_unavailable(req.method().as_str(), &path, request_trace_id(&req))
        }
    };
    let fence_is_hub = matches!(authority_fence, AuthorityFence::Hub(_));

    // Any Bearer credential, including one on a public path, must represent a
    // live access session. Public paths only bypass authentication when no
    // credentials were supplied at all.
    //
    // canonical store verifier 的 Allow 是全 middleware 唯一可复用的会话/
    // 租户复合证明源（strict JOIN 已含 tenant × tenant_domain_map ACTIVE +
    // 完整绑定；镜像命中 verified-only + hub fanout 失效）；Redis 兼容
    // adapter（显式 opt-in）分支不产生该证明，tenant 检查保持原路径。
    let mut canonical_session_allow = false;
    {
        // 单机组合进程加速器：进程内注册表命中即撤销（写入方是同进程
        // Identity 的已证明撤销事实）。未命中/未安装一律继续下方权威检查，
        // 不以注册表未命中推导 ACTIVE，fail-closed 语义不变。
        if let Some(registry) =
            astral_common::session_revocation_registry::global_session_revocation_registry()
        {
            if registry.is_revoked(&claims.jti) {
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
        }
        if astral_common::session_projection_store::global_session_projection_store().is_some() {
            // Redis-free 默认路径：strict MySQL durable facts（可选已证明镜像
            // 加速）。Allow 仅来自逐项绑定的 durable/已证明事实；Deny/未命中/
            // suspect/DB 错误分别映射 401/503，绝不降级放行。
            match astral_db::verify_access_via_global_store(&claims.jti, &bind).await {
                SessionProjectionDecision::Allow => {
                    canonical_session_allow = true;
                }
                SessionProjectionDecision::Deny(reason) => {
                    let message = match reason {
                        "TOKEN_REVOKED" => "Token has been revoked",
                        "SESSION_NOT_FOUND" => "Access session not found",
                        _ => "Access session state rejected",
                    };
                    return json_error(
                        req.method().as_str(),
                        &path,
                        request_trace_id(&req),
                        401,
                        message,
                        "UNAUTHORIZED",
                        reason,
                    );
                }
                SessionProjectionDecision::Unavailable => {
                    return dependency_unavailable(
                        req.method().as_str(),
                        &path,
                        request_trace_id(&req),
                    )
                }
            }
        } else if gateway_redis_adapter_installed() {
            // Redis 兼容 adapter（default-off，显式配置时才装配；feature-off
            // 构建中本分支整体不存在，`gateway_redis_adapter_installed()` 恒
            // false，与 adapter 未装配时的默认路径一致）。
            // 1) `jwt:revoked:{jti}` 黑名单命中即拒；
            // 2) `access:jti:{jti}` 必须存在，且其标量值必须等于 JWT subject
            //    （强制值比对，防止"投影残留/改写后仅剩 key"绕过撤销语义）；
            // 3) 非 OFF 模式下读取 `access:grant:{jti}` 并校验版本化会话字段；
            //    REQUIRE 模式下校验必须通过（fail-closed），EMIT 模式读取失败
            //    fail-closed 但校验结果不阻塞。
            #[cfg(feature = "redis-compat")]
            {
                let mut conn = match redis_conn_with_url(&config.redis_url).await {
                    Ok(conn) => conn,
                    Err(_) => {
                        return dependency_unavailable(
                            req.method().as_str(),
                            &path,
                            request_trace_id(&req),
                        )
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
                        return dependency_unavailable(
                            req.method().as_str(),
                            &path,
                            request_trace_id(&req),
                        )
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

                let scalar: Option<String> = match tokio::time::timeout(
                    std::time::Duration::from_secs(REDIS_TIMEOUT_SECS),
                    conn.get::<_, Option<String>>(format!("access:jti:{}", claims.jti)),
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
            #[cfg(not(feature = "redis-compat"))]
            {
                tracing::debug!(
                    "redis projection adapter branch requires the redis-compat feature; adapter is never installed without it"
                );
            }
        } else {
            // 未装配任何会话判定面（strict MySQL 与兼容 adapter 均缺）：无
            // 权威事实可用，fail-closed 拒绝（503，对齐依赖不可用语义）。
            return dependency_unavailable(req.method().as_str(), &path, request_trace_id(&req));
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
        if let Ok(v) = HeaderValue::from_str(&format!("req-{}", uuid::Uuid::new_v4())) {
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

    // Step 6: 租户状态检查（SUSPENDED / TERMINATED → 拒绝）。
    // Warmed 快路径：strict 会话判定 canonical verifier **实际 Allow**（strict
    // JOIN 已含 tenant × tenant_domain_map ACTIVE 与完整卡/租户绑定；镜像命中
    // 为 verified-only + hub fanout 失效面）、claims 卡/租户绑定一致、组合
    // positive 强条件逐请求复观测为真——此时租户状态已被会话复合 ALLOW 事实
    // 覆盖，跳过逐请求 duplicate tenant SQL（warmed 会话检查零 DB）。APP_USER
    // 无卡绑定（tenant_id None）天然进不了本快路径。任一条件缺失即保留
    // strict DB 读取并加硬 deadline（超时 503）；仅按 claims/flag 跳过是被
    // 禁止的。兼容 adapter（显式 opt-in）保留历史 Redis 缓存路径。
    if let Some(tid) = tenant_id {
        let claims_tenant_bound = claims_tenant_matches_bind(Some(tid), &bind);
        match tenant_status_mode(
            canonical_session_allow,
            claims_tenant_bound,
            composite_positive_ready(),
            fence_is_hub,
        ) {
            TenantStatusMode::Warmed => {}
            TenantStatusMode::StrictDeadline => {
                let tid_str = tid.to_string();
                let cached_status: Option<String> = if let Some(pool) = gateway_session_db() {
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(TENANT_STATUS_DEADLINE_SECS),
                        astral_db::load_tenant_status_strict(pool, tid),
                    )
                    .await
                    {
                        Ok(Ok(status)) => status,
                        Ok(Err(_)) | Err(_) => {
                            return dependency_unavailable(
                                req.method().as_str(),
                                &path,
                                request_trace_id(&req),
                            )
                        }
                    }
                } else if gateway_redis_adapter_installed() {
                    #[cfg(feature = "redis-compat")]
                    {
                        match fetch_cached_tenant_status(&tid_str, &config.redis_url).await {
                            Ok(status) => status,
                            Err(_) => {
                                return dependency_unavailable(
                                    req.method().as_str(),
                                    &path,
                                    request_trace_id(&req),
                                )
                            }
                        }
                    }
                    #[cfg(not(feature = "redis-compat"))]
                    {
                        unreachable!("redis adapter branch requires the redis-compat feature")
                    }
                } else {
                    return dependency_unavailable(
                        req.method().as_str(),
                        &path,
                        request_trace_id(&req),
                    );
                };
                let Some(status) = cached_status else {
                    tracing::warn!(tenant_id = %tid_str, "tenant status unavailable");
                    return dependency_unavailable(
                        req.method().as_str(),
                        &path,
                        request_trace_id(&req),
                    );
                };
                let upper = status.to_uppercase();
                if upper == "SUSPENDED" || upper == "TERMINATED" {
                    tracing::warn!(tenant_id = %tid_str, tenant_status = %upper, "tenant status check: rejected");
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
        }
    }

    // 同栅栏复验（final）：捕获期的 hub 权威戳必须仍然匹配（期间任何 source
    // writer begin/drop、纪元/健康推进都使旧戳失配）；独立进程必须仍无 hub。
    // 失配 = 捕获期权威事实不再可信 → 503 fail-closed。绝不重采样 token、
    // 绝不按 claims/flag 重新推导放行。
    if !authority_fence.still_valid() {
        return dependency_unavailable(req.method().as_str(), &path, request_trace_id(&req));
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

    /// Redis-free strict 判定的绑定上下文必须与 JWT claims 逐项对应；
    /// principal_kind 不可解析时映射为空串（durable 评估 fail-closed 拒绝）。
    #[test]
    fn session_bind_context_maps_claims_verbatim() {
        let mapped = session_bind_context(&claims("42"));
        assert_eq!(mapped.user_id, 42);
        assert_eq!(mapped.session_id, 1);
        assert_eq!(mapped.session_epoch, 1);
        assert_eq!(mapped.token_family_id, 1);
        assert_eq!(mapped.principal_kind, "PLATFORM_USER");
        assert_eq!(mapped.identity_card_id, Some(10));
        assert_eq!(mapped.user_card_id, Some(40));
        assert_eq!(mapped.user_card_tenant_id, Some(20));
        assert_eq!(mapped.user_card_domain_id, Some(30));

        let mut unknown = claims("42");
        unknown.principal_kind = "SOMETHING_ELSE".into();
        assert_eq!(session_bind_context(&unknown).principal_kind, "");
    }

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

    #[cfg(feature = "redis-compat")]
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

    // ---- gateway-read-final：租户检查模式与 admission 栅栏契约 -------------

    /// 源形状断言只检查生产代码（截去本测试模块，防止锚点命中测试自身）。
    fn source_without_tests() -> &'static str {
        include_str!("middleware.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("test module marker must exist")
    }

    /// 跳过 duplicate tenant SQL 的资格是**全有或全无**的证明束：canonical
    /// Allow、claims 卡/租户绑定、组合强条件复观测、hub 栅栏缺一即回落
    /// strict DB + deadline。仅按 claims/flag 跳过被本钉子拒绝。
    #[test]
    fn tenant_status_mode_requires_the_full_proof_bundle() {
        let warmed = tenant_status_mode(true, true, true, true);
        assert_eq!(warmed, TenantStatusMode::Warmed);
        for (allow, bound, composite, hub) in [
            (false, true, true, true),
            (true, false, true, true),
            (true, true, false, true),
            (true, true, true, false),
            (false, false, false, false),
        ] {
            assert_eq!(
                tenant_status_mode(allow, bound, composite, hub),
                TenantStatusMode::StrictDeadline,
                "any missing proof must keep strict DB tenant checks"
            );
        }
    }

    /// 非组合进程（测试进程未安装 LocalBus/hub）恒为 false：强条件是观测
    /// 事实，绝不是恒真布尔；standalone 因此永远走 strict DB + deadline。
    #[test]
    fn composite_positive_ready_is_false_without_observed_composite_state() {
        assert!(astral_mq::local_bus::global_local_bus().is_none());
        assert!(astral_db::memory_projection_hub().is_none());
        assert!(!composite_positive_ready());
    }

    /// 卡/租户绑定一致性：claims 租户必须等于本次判定 bind 携带的租户，且
    /// bind 真实携带正 user_card。claims 租户与 bind 租户漂移（bind 构造
    /// 与 claims 解耦时的形态）、卡缺失/非正、租户缺失一律拒绝快路径，
    /// 保留 strict DB + deadline。
    #[test]
    fn tenant_skip_binding_requires_claims_tenant_to_match_bind_tenant() {
        let bind = session_bind_context(&claims("42"));
        let tenant_id = optional_tenant_id(&claims("42"))
            .expect("platform claims carry tenant context")
            .expect("platform tenant id present");
        assert!(claims_tenant_matches_bind(Some(tenant_id), &bind));

        let mut drifted = bind.clone();
        drifted.user_card_tenant_id = Some(tenant_id + 10);
        assert!(!claims_tenant_matches_bind(Some(tenant_id), &drifted));

        let mut cardless = bind.clone();
        cardless.user_card_id = None;
        assert!(!claims_tenant_matches_bind(Some(tenant_id), &cardless));

        let mut bad_card = bind.clone();
        bad_card.user_card_id = Some(0);
        assert!(!claims_tenant_matches_bind(Some(tenant_id), &bad_card));

        assert!(!claims_tenant_matches_bind(None, &bind));
    }

    /// 无 hub 进程的栅栏形态：捕获成功（Standalone）且在无 hub 状态下复验
    /// 通过；进程内出现 hub 后同一栅栏立即失配（fail-closed，不续用）。
    #[test]
    fn standalone_fence_captures_and_reverifies_without_hub() {
        assert!(astral_db::memory_projection_hub().is_none());
        let fence = AuthorityFence::capture().expect("standalone capture must succeed");
        assert!(matches!(fence, AuthorityFence::Standalone));
        assert!(fence.still_valid());
    }

    /// JWT admission 栅栏的源形状钉子：捕获点先于 canonical 会话判定，判定
    /// 先于 Step 6 租户模式决策，`next.run` 前必须同栅栏复验；栅栏捕获之后
    /// 不允许再出现 token 重采样（decode 只发生在捕获之前）。strict tenant
    /// 路径必须带硬 deadline。
    #[test]
    fn jwt_admission_fences_order_capture_verify_reverify_before_next_run() {
        let source = source_without_tests();
        let capture = source
            .find("let authority_fence = match AuthorityFence::capture()")
            .expect("admission fence capture must exist before session facts");
        let session_verify = source
            .find("verify_access_via_global_store(")
            .expect("canonical session verifier must remain");
        let tenant_mode = source
            .find("match tenant_status_mode(")
            .expect("tenant status mode decision must remain");
        let reverify = source
            .find("authority_fence.still_valid()")
            .expect("same-fence reverify must exist");
        let final_next = source
            .rfind("next.run(req).await")
            .expect("a final next.run must exist");
        assert!(capture < session_verify);
        assert!(session_verify < tenant_mode);
        assert!(tenant_mode < reverify && reverify < final_next);
        // 栅栏捕获之后绝不再解码 token（无重采样）。
        let last_decode = source
            .rfind("decode_v2_token(")
            .expect("token decode must exist exactly on the admission path");
        assert!(
            last_decode < capture,
            "token must be decoded once, before the fence capture"
        );
        // strict tenant 路径保留且带硬 deadline。
        assert!(source.contains("load_tenant_status_strict("));
        assert!(source.contains("TENANT_STATUS_DEADLINE_SECS"));
    }
}
