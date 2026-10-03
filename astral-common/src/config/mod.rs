//! 配置加载
//!
//! 通过 config-rs 从环境变量 + YAML fallback 加载配置。
//! 优先级：环境变量 > YAML > 默认值。

use axum::http::Uri;
use serde::Deserialize;
use std::fs;
use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigValidationError {
    #[error("JWT_SECRET must be at least 32 characters for HS256")]
    JwtSecretTooShort,
    #[error("JWT_SECRET must not use a known placeholder value")]
    JwtSecretPlaceholder,
    #[error("JWT_RSA_PUBLIC_KEY_PATH is required for RS256")]
    RsaPublicKeyPathMissing,
    #[error("JWT RSA public key is not readable: {0}")]
    RsaPublicKeyUnreadable(String),
    #[error("JWT RSA public key is not a valid PEM key: {0}")]
    RsaPublicKeyInvalid(String),
    #[error("JWT_RSA_PRIVATE_KEY_PATH is required for RS256")]
    RsaPrivateKeyPathMissing,
    #[error("JWT RSA private key is not readable: {0}")]
    RsaPrivateKeyUnreadable(String),
    #[error("JWT RSA private key is not a valid PEM key: {0}")]
    RsaPrivateKeyInvalid(String),
    #[error("unsupported JWT algorithm: {0}")]
    UnsupportedJwtAlgorithm(String),
    #[error("GATEWAY_HMAC_SECRET must be at least 32 characters")]
    GatewayHmacSecretTooShort,
    #[error("GATEWAY_HMAC_SECRET must not use a known placeholder value")]
    GatewayHmacSecretPlaceholder,
    #[error("INTERNAL_SERVICE_SECRET (K_LG) must be at least 32 characters")]
    InternalServiceSecretTooShort,
    #[error("INTERNAL_SERVICE_SECRET (K_LG) must not use a known placeholder value")]
    InternalServiceSecretPlaceholder,
    #[error("GATEWAY_INTERNAL_SERVICE_SECRET (K_GI) must be at least 32 characters")]
    GatewayInternalServiceSecretTooShort,
    #[error("GATEWAY_INTERNAL_SERVICE_SECRET (K_GI) must not use a known placeholder value")]
    GatewayInternalServiceSecretPlaceholder,
    #[error("GATEWAY timestamp tolerance must be positive")]
    GatewayTimestampToleranceInvalid,
    #[error("SESSION_GRANT_CLAIMS_MODE must be one of OFF, EMIT, REQUIRE (got: {0})")]
    InvalidSessionGrantClaimsMode(String),
    #[error("DATABASE_URL is required outside the test profile")]
    DatabaseUrlMissing,
    #[error("REDIS_URL is required outside the test profile")]
    RedisUrlMissing,
    #[error("RABBITMQ_URL is required outside the test profile")]
    RabbitmqUrlMissing,
    #[error("{0} must not point to localhost or a loopback address outside the test profile")]
    LocalhostConnection(String),
    #[error("CORS allowed origins are required outside the test profile")]
    CorsOriginsMissing,
    #[error("CORS wildcard origins are not allowed")]
    CorsWildcard,
    #[error("CORS origin is invalid")]
    CorsOriginInvalid,
    #[error("CORS origin is unsafe outside the test profile")]
    CorsOriginUnsafe,
    #[error("{0} must be a valid connection URL")]
    ConnectionUrlInvalid(String),
    #[error("ASTRAL_MESSAGE_TRANSPORT must be exactly \"local\" or \"rabbit\"")]
    InvalidMessageTransport,
    #[error("RABBITMQ_URL is required when ASTRAL_MESSAGE_TRANSPORT=rabbit")]
    RabbitmqUrlRequiredForTransport,
    #[error("ASTRAL_REGION_ID must be non-empty and at most 64 characters")]
    InvalidRegionId,
    #[error("ASTRAL_NODE_ID must be non-empty and at most 128 characters")]
    InvalidNodeId,
    #[error("ASTRAL_TARGET_REGION must be non-empty and at most 64 characters when present")]
    InvalidTargetRegion,
    #[error("ASTRAL_ORG_SCOPE_ENABLED must be exactly \"true\" or \"false\" (default off)")]
    InvalidOrgScopeEnabled,
    #[error("redis projection compat requires a non-empty REDIS_URL")]
    RedisCompatRequiresUrl,
    #[error(
        "redis projection compat is enabled but this binary was built without the `redis-compat` feature; rebuild with --features redis-compat or disable the compat flag (fail-closed)"
    )]
    RedisCompatRequiresFeatureBuild,
    #[error("ASTRAL_REDIS_PROJECTION_COMPAT must be exactly \"true\" or \"false\" (default off)")]
    InvalidRedisProjectionCompat,
    #[error(
        "redis projection compat freeze conflict: process startup already froze the opposite value; every runtime installer must agree on the same validated flag (fail-closed)"
    )]
    RedisCompatFreezeConflict,
}

impl ConfigValidationError {
    fn into_config_error(self) -> config::ConfigError {
        config::ConfigError::Foreign(Box::new(self))
    }
}

/// Message propagation mode selected once at process startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageTransport {
    Local,
    Rabbit,
}

impl MessageTransport {
    pub fn parse(raw: &str) -> Result<Self, ConfigValidationError> {
        match raw.trim() {
            "local" => Ok(Self::Local),
            "rabbit" => Ok(Self::Rabbit),
            _ => Err(ConfigValidationError::InvalidMessageTransport),
        }
    }
}

// ===== ORG_SCOPE 部署旗标（default-off，跨宿主共享契约） =====
//
// `SqlxRuleRepository::new()` 默认 org_scope 关闭；每个 PolicyEngine 宿主
// （trustgraph / identity / monitor）必须在启动期用本节共享解析器解析
// `ASTRAL_ORG_SCOPE_ENABLED` 并把冻结值传入它构造的每个正式仓储
// （`.with_org_scope_enabled(...)`）。共享同一个解析器与默认关闭语义，防止
// 同一受管租户在一个宿主被准入、另一个宿主被 ORG_AUTHORITY_DISABLED 拒绝
// （split-brain）。解析只发生在进程启动期，授权路径绝不读取 env。

/// ORG_SCOPE 部署旗标的唯一 env 名（严格 bool，default-off）。
pub const ORG_SCOPE_ENABLED_ENV: &str = "ASTRAL_ORG_SCOPE_ENABLED";

/// Redis 会话投影兼容 adapter 的唯一 env 名（严格 bool，default-off）。
pub const REDIS_PROJECTION_COMPAT_ENV: &str = "ASTRAL_REDIS_PROJECTION_COMPAT";

/// 单机组合进程会话镜像加速器的唯一 env 名（严格 bool，default-off）。
pub const SESSION_GRANT_MIRROR_ENV: &str = "ASTRAL_SESSION_GRANT_MIRROR_ENABLED";

/// 镜像 positive cache 永久旁路开关的唯一 env 名（严格 bool，default-off）。
pub const SESSION_GRANT_MIRROR_POSITIVE_DISABLED_ENV: &str =
    "ASTRAL_SESSION_GRANT_MIRROR_POSITIVE_DISABLED";

/// 严格解析 ORG_SCOPE 部署旗标（唯一共享实现，所有 PolicyEngine 宿主共用）。
///
/// 契约：unset/空白/`"false"`（trim 后）→ `Ok(false)`；`"true"`（trim 后精确
/// 匹配，区分大小写）→ `Ok(true)`；其他任何非空值 → `Err`（fail-fast，调用方
/// 必须拒绝启动，绝不静默降级）。错误信息只含变量名与期望格式，不回显值。
pub fn parse_org_scope_enabled(raw: Option<&str>) -> Result<bool, ConfigValidationError> {
    match raw.map(str::trim) {
        None | Some("") | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(_) => Err(ConfigValidationError::InvalidOrgScopeEnabled),
    }
}

/// 启动期一次性读取并解析 `ASTRAL_ORG_SCOPE_ENABLED`。
///
/// 只允许在进程 main / 配置装配路径调用一次并把结果冻结（见
/// [`AppConfig::org_scope_enabled`] 与 [`apply_flat_env_overrides`]）；
/// 授权 / 请求路径禁止调用本函数。
pub fn org_scope_enabled_from_env() -> Result<bool, ConfigValidationError> {
    let raw = std::env::var(ORG_SCOPE_ENABLED_ENV).ok();
    parse_org_scope_enabled(raw.as_deref())
}

// ===== Redis 会话投影兼容旗标（default-off，跨宿主/跨 crate 共享契约） =====
//
// redis-layer-retirement-20261002 收口：compat 是显式 opt-in 的**编译期**能力。
// 零依赖 marker feature 会被 workspace feature 统一放大——任何 crate 打开
// `redis-compat` 都会让 astral-common 的集中 cfg 校验通过，即便某个具体宿主
// 并未编译自己的 compat adapter（历史上只留下 info log 静默 Redis-free 化）。
// 因此本节提供三层共享契约：
// 1. [`AppConfig::validate_redis_adapter_support`]：纯函数能力断言，每个宿主
//    以**自身 crate** 的 `cfg!(feature = "redis-compat")` 在配置校验后、任何
//    DB 连接 / 服务装配之前调用（显式拒绝，不是 log-only）。
// 2. [`install_redis_projection_compat`]：宿主把已校验旗标一次性冻结进进程级
//    **唯一冻结槽**（同值幂等、对槽内任何先到异值冻结冲突拒绝），同进程的
//    组合成员必须一致。
// 3. [`parse_redis_projection_compat`] / [`redis_projection_compat_frozen`] /
//    [`redis_projection_compat_from_env_frozen`]：libs 的中心解析器与单槽冻结
//    读，替代各自重复读 env 的 OnceLock（非法 env 一律 false fail-closed，
//    无网络；env 回落读填充同一槽，保证 getter 答案自首次读取起稳定）。

/// 严格解析 Redis 会话投影兼容旗标（唯一共享实现，宿主与 libs 共用）。
///
/// 契约：unset/空白/`"false"`（trim + ASCII 大小写不敏感）→ `Ok(false)`；
/// `"true"`（trim + ASCII 大小写不敏感）→ `Ok(true)`；其他任何非空值 →
/// `Err`（fail-closed）。大小写不敏感刻意对齐 `apply_flat_env_overrides`
/// 对本 env 名的既有契约（与 ORG_SCOPE 的精确小写契约区分，各自文档已注明）。
/// 与配置加载路径的空白差异：apply 前的 `optional_env` 先把空白 env 过滤为
/// "未配置"（保留 YAML/默认值，同为 default-off），本解析器把空白直接视为
/// `Ok(false)`——两种机制取值一致（false），服务对象不同（libs 直接读 env）。
/// 错误信息只含变量名与期望格式，不回显值。
pub fn parse_redis_projection_compat(raw: Option<&str>) -> Result<bool, ConfigValidationError> {
    match raw
        .map(|value| value.trim().to_ascii_lowercase())
        .as_deref()
    {
        None | Some("") | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(_) => Err(ConfigValidationError::InvalidRedisProjectionCompat),
    }
}

/// 进程级冻结的 Redis 兼容旗标——**唯一冻结槽**（单源真相）。
///
/// 三个写入方共享本槽：宿主安装器 [`install_redis_projection_compat`]（已
/// 校验值）与 legacy/lib 的 env 回落读 [`redis_projection_compat_frozen`]。
/// 先到者冻结（env 回落读也算冻结），后到安装器必须同值幂等、异值冲突拒绝
/// ——否则 legacy 先冻结后安装异值会把 getter 的答案在读方背后改掉
/// （TOCTOU：生产宿主保证 install 先于任何 worker，测试/legacy 无此保证）。
static REDIS_PROJECTION_COMPAT_FROZEN: OnceLock<bool> = OnceLock::new();

/// 把**已通过校验**的 Redis 兼容旗标一次性冻结进进程级唯一槽。
///
/// 每个宿主 runtime 在 [`AppConfig::validate_redis_adapter_support`]（以及配置
/// 加载期集中校验）通过后、任何 DB 连接 / 服务 / worker 装配之前调用恰好一次；
/// 组合进程内多个成员宿主必须装同一份已校验值。冲突语义覆盖**同一槽内的全部
/// 先到冻结**（不限于其他安装器）：槽为空 → 本值生效；槽内同值 → 幂等
/// `Ok`；槽内异值（其他宿主安装器或 legacy env 回落读先到且不同）→ 拒绝启动
/// （fail-closed，绝不静默采纳后来者，也绝不在读方背后改写已发布答案）。
/// 调用前必须先完成宿主能力断言——本函数不做任何编译期能力检查。
pub fn install_redis_projection_compat(value: bool) -> Result<(), ConfigValidationError> {
    match REDIS_PROJECTION_COMPAT_FROZEN.set(value) {
        Ok(()) => Ok(()),
        Err(_) => {
            let frozen = *REDIS_PROJECTION_COMPAT_FROZEN
                .get()
                .expect("OnceLock::set failed but the slot must hold the winner");
            if frozen == value {
                Ok(())
            } else {
                Err(ConfigValidationError::RedisCompatFreezeConflict)
            }
        }
    }
}

/// 读取进程级冻结的 Redis 兼容旗标（default-off，单源真相）。
///
/// 槽已冻结（宿主安装值或先到的 env 回落值）→ 返回冻结值；槽为空（legacy/lib
/// 场景，宿主未走新 API）→ 用 env 视图填充**同一个槽**后返回：此后宿主安装器
/// 必须与该 env 派生值同值（幂等）否则冲突拒绝，保证 getter 的答案自首次读取
/// 起稳定，绝不静默切换。生产路径要求宿主在任何读取方 spawn 之前完成安装，
/// env 回落仅用于无 config 的历史库。
pub fn redis_projection_compat_frozen() -> bool {
    if let Some(value) = REDIS_PROJECTION_COMPAT_FROZEN.get() {
        return *value;
    }
    // legacy env 视图：非法值一律 false（fail-closed 默认关闭，绝不静默开启；
    // 配置加载路径的非法值仍由 apply_flat_env_overrides 严格拒绝启动）。
    let env_value =
        parse_redis_projection_compat(std::env::var(REDIS_PROJECTION_COMPAT_ENV).ok().as_deref())
            .unwrap_or(false);
    match REDIS_PROJECTION_COMPAT_FROZEN.set(env_value) {
        Ok(()) => env_value,
        // 并发竞争：以槽内赢家为准（与 install 的同值幂等/异值冲突同源）。
        Err(_) => *REDIS_PROJECTION_COMPAT_FROZEN
            .get()
            .expect("OnceLock::set failed but the slot must hold the winner"),
    }
}

/// Legacy/lib 兼容别名：读取进程级唯一冻结源（签名与默认 false 语义保持
/// 稳定）。槽为空时经 env 视图填充同一槽（见
/// [`redis_projection_compat_frozen`]），与宿主安装器共享同一冲突语义；
/// 不再是独立的第二 env 槽，杜绝"legacy 先冻结 false、install 后改 true"
/// 的读方背后翻转。无网络。
pub fn redis_projection_compat_from_env_frozen() -> bool {
    redis_projection_compat_frozen()
}

fn is_placeholder_secret(secret: &str) -> bool {
    let normalized = secret.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return true;
    }

    const PLACEHOLDERS: &[&str] = &[
        "change-me",
        "change_me",
        "changeme",
        "change-me-to-a-long-random-secret-key",
        "default-secret",
        "default_secret",
        "replace-me",
        "replace_me",
        "your-secret",
        "your_secret",
        "please-change-me",
        "test-secret",
        "development-secret",
        "password",
        "secret",
    ];
    if PLACEHOLDERS
        .iter()
        .any(|placeholder| normalized == *placeholder)
        || PLACEHOLDERS
            .iter()
            .any(|placeholder| normalized.starts_with(&format!("{placeholder}-")))
        || normalized.starts_with("${")
        || normalized.starts_with("{{")
        || normalized.starts_with("env(")
        || ["placeholder", "example", "todo"]
            .iter()
            .any(|marker| normalized == *marker || normalized.starts_with(&format!("{marker}-")))
    {
        return true;
    }

    normalized.len() >= 8
        && normalized
            .chars()
            .next()
            .is_some_and(|first| normalized.chars().all(|value| value == first))
}

/// 全局应用配置
#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub learn_service_uri: String,
    #[serde(default)]
    pub chat_service_uri: String,
    #[serde(default)]
    pub identity_service_uri: String,
    #[serde(default)]
    pub gateway_service_uri: String,

    #[serde(default)]
    pub trust_graph_uri: String,
    #[serde(default)]
    pub monitor_service_uri: String,

    #[serde(default)]
    pub internal_service_secret: String,

    #[serde(default = "default_public_paths")]
    pub public_paths: Vec<String>,

    /// Session grant claims 发布模式。
    ///
    /// Token v2 always requires a versioned grant. The field remains a
    /// deployment switch for the existing projector rollout, but `REQUIRE`
    /// is the only mode accepted by the new session issuer.
    #[serde(default = "default_session_grant_claims_mode")]
    pub session_grant_claims_mode: String,

    #[serde(default = "default_max_permission_header_length")]
    pub max_permission_header_length: usize,

    #[serde(default)]
    pub cors: CorsConfig,

    #[serde(default)]
    pub jwt: JwtConfig,

    #[serde(default)]
    pub gateway: GatewayCfg,

    #[serde(default)]
    pub rate_limit: RateLimitCfg,

    #[serde(default = "default_database_url")]
    pub database_url: String,

    #[serde(default = "default_redis_url")]
    pub redis_url: String,

    #[serde(default = "default_rabbitmq_url")]
    pub rabbitmq_url: String,

    /// Optional target region for an explicitly remote Rabbit route.
    #[serde(default)]
    pub target_region: Option<String>,

    /// Stable deployment region used by the transport-neutral envelope.
    #[serde(default = "default_region_id")]
    pub region_id: String,

    /// Stable node identity used for distributed transport ownership and tracing.
    #[serde(default = "default_node_id")]
    pub node_id: String,

    /// Message propagation mode. `local` requires the single-node composite
    /// runtime and its bounded in-process bus; `rabbit` uses the remote broker.
    #[serde(default = "default_message_transport")]
    pub message_transport: String,

    /// MySQL 服务连接池最大连接数（读链规模化：trustgraph 读路径扩容用；
    /// 默认 80，部署时须处于 MySQL 服务端 max_connections=151 预算内）。
    /// env `ASTRAL_DB_MAX_CONNECTIONS` 可覆盖，解析规则见
    /// [`AppConfig::resolved_db_max_connections`]。
    #[serde(default = "default_db_max_connections")]
    pub db_max_connections: u32,

    /// MySQL 连接池 acquire 超时（秒；默认 5s 快速失败，替代 sqlx 默认的
    /// 30s 排队等待——池耗尽时请求快速报错而非长时间悬挂）。env
    /// `ASTRAL_DB_ACQUIRE_TIMEOUT_SECS` 可覆盖，见
    /// [`AppConfig::resolved_db_acquire_timeout`]。
    #[serde(default = "default_db_acquire_timeout_seconds")]
    pub db_acquire_timeout_seconds: u64,

    /// ORG_SCOPE 部署旗标（default-off）：启动期由 [`parse_org_scope_enabled`]
    /// 从 `ASTRAL_ORG_SCOPE_ENABLED` 一次性解析并冻结（见
    /// [`apply_flat_env_overrides`]）；此后授权读取只使用本冻结值，绝不逐请求
    /// 读 env。非法值使配置加载失败（启动拒绝，见
    /// [`ConfigValidationError::InvalidOrgScopeEnabled`]）。`serde(skip)`：该
    /// 旗标只认 env 严格契约，YAML 不提供开关（防止绕过共享解析器静默开启）。
    #[serde(skip)]
    pub org_scope_enabled: bool,

    /// Redis 会话投影兼容 adapter（**default-off**）。
    ///
    /// `false`（默认）：登录/refresh/switch 只写 MySQL durable proof
    /// （`auth_session_jti_index`），Gateway 走 strict MySQL 会话判定，
    /// 运行路径 Redis-free。
    /// `true`：在 durable proof 之外**追加**历史 Redis 投影写入
    /// （`access:jti`/`access:grant`/`jwt:revoked`），失败语义与历史一致
    /// （签发失败回滚家族、撤销失败报错）。必须同时配置非空 `redis_url`，
    /// 否则启动失败（[`ConfigValidationError::RedisCompatRequiresUrl`]）。
    #[serde(default)]
    pub redis_projection_compat_enabled: bool,

    /// 单机组合进程镜像加速器（**default-on**，composite 正常会话 zero-DB
    /// 目标的默认闭合；redis-layer-retirement-20261002 同批收口）：安装有界
    /// 进程内会话镜像（TTL/容量/GC/suspect 栅栏）。镜像命中 Allow 仍逐项绑定
    /// durable proof（签发侧经 strict DB 复核登记）；未命中/suspect 一律回退
    /// strict DB。
    ///
    /// 默认 true 只表达"愿意安装"：Gateway 运行期强门仍要求**单写者组合进程**
    /// 的观测事实（LocalBus owners ready + 同进程已安装 hub 通道健康 + aux
    /// 镜像装配资格标记；运行期租约/健康存活由 canonical verifier 的 hub
    /// 读取令牌/栅栏实时承担）才真正安装；独立多写者 Gateway 没有
    /// SessionRevoked fanout 订阅，启动期 warn 并保持
    /// strict DB per request（DenyOnly，无害降级，不影响功能）。多节点部署或
    /// 不愿看到 warn 的部署用 env `ASTRAL_SESSION_GRANT_MIRROR_ENABLED=false`
    /// 或 YAML `false` 显式 opt-out（严格 bool 契约不变：env 存在即覆盖，
    /// 非法值启动失败）。
    #[serde(default = "default_session_grant_mirror_enabled")]
    pub session_grant_mirror_enabled: bool,

    /// 镜像 positive cache 旁路开关（**default-off**，显式配置后生效）：
    /// 置 true 时安装镜像即调用 `mark_suspect_permanent()`——active grant
    /// 永不参与放行（每请求 strict DB），撤销 marker 的 deny 加速保留。
    /// 用于运维在不关闭 deny 加速的前提下永久关闭 positive cache。
    #[serde(default)]
    pub session_grant_mirror_positive_disabled: bool,

    #[serde(default)]
    pub wechat: WeChatConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            learn_service_uri: String::new(),
            chat_service_uri: String::new(),
            identity_service_uri: String::new(),
            gateway_service_uri: String::new(),
            trust_graph_uri: String::new(),
            monitor_service_uri: String::new(),
            internal_service_secret: String::new(),
            public_paths: default_public_paths(),
            session_grant_claims_mode: default_session_grant_claims_mode(),
            max_permission_header_length: default_max_permission_header_length(),
            cors: CorsConfig::default(),
            jwt: JwtConfig::default(),
            gateway: GatewayCfg::default(),
            rate_limit: RateLimitCfg::default(),
            database_url: default_database_url(),
            redis_url: default_redis_url(),
            rabbitmq_url: default_rabbitmq_url(),
            target_region: None,
            region_id: default_region_id(),
            node_id: default_node_id(),
            message_transport: default_message_transport(),
            db_max_connections: default_db_max_connections(),
            db_acquire_timeout_seconds: default_db_acquire_timeout_seconds(),
            org_scope_enabled: false,
            redis_projection_compat_enabled: false,
            session_grant_mirror_enabled: default_session_grant_mirror_enabled(),
            session_grant_mirror_positive_disabled: false,
            wechat: WeChatConfig::default(),
        }
    }
}

fn default_public_paths() -> Vec<String> {
    vec![
        "/api/v1/auth/sessions".into(),
        "/api/v1/auth/register".into(),
        "/api/v1/auth/password/forgot".into(),
        "/api/v1/auth/password/reset/*".into(),
        "/api/v1/auth/verification/send".into(),
        "/api/v1/auth/verification/verify".into(),
        "/v1/app/users/login".into(),
        "/api/health".into(),
        "/api/health/metrics".into(),
        "/api/health/**".into(),
        "/actuator/health".into(),
    ]
}

fn default_session_grant_claims_mode() -> String {
    "REQUIRE".into()
}
/// 组合进程 zero-DB 目标的默认闭合：镜像加速器字段默认 true（运行期仍有
/// composite+hub+lease 强门与 DenyOnly 降级，见字段文档）。显式 env/YAML
/// `false` 必须保持生效——serde 标量 default fn 保证"未配置才默认"。
fn default_session_grant_mirror_enabled() -> bool {
    true
}
fn default_max_permission_header_length() -> usize {
    16000
}
fn default_database_url() -> String {
    String::new()
}
fn default_redis_url() -> String {
    String::new()
}
fn default_rabbitmq_url() -> String {
    String::new()
}
fn default_message_transport() -> String {
    "rabbit".into()
}
fn default_region_id() -> String {
    "local".into()
}
fn default_node_id() -> String {
    "local-node".into()
}
fn default_db_max_connections() -> u32 {
    80
}
fn default_db_acquire_timeout_seconds() -> u64 {
    5
}

/// CORS 配置
#[derive(Debug, Clone, Default, Deserialize)]
pub struct CorsConfig {
    #[serde(default = "default_origins")]
    pub allowed_origins: Vec<String>,
    #[serde(default = "default_allow_credentials")]
    pub allow_credentials: bool,
}

fn default_origins() -> Vec<String> {
    Vec::new()
}
fn default_allow_credentials() -> bool {
    false
}

/// JWT 认证配置
///
/// 支持 HS256（对称）和 RS256（RSA 非对称）两种算法。
/// 对齐 Java JJWT + RSA 非对称签名模式。
///
/// Java 基线: JJWT + RSA 非对称（公钥分发到 Gateway，私钥仅 Identity）
#[derive(Debug, Clone, Default, Deserialize)]
pub struct JwtConfig {
    /// Token v2 access profile. Gateway replicas only need this profile.
    #[serde(default = "default_access_profile")]
    pub access: JwtTokenProfile,
    /// Token v2 refresh profile. Refresh signing material must not be shared
    /// with the access profile in a distributed deployment.
    #[serde(default = "default_refresh_profile")]
    pub refresh: JwtTokenProfile,
}

/// Versioned JWT profile shared by every Rust replica.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct JwtTokenProfile {
    #[serde(default = "default_jwt_algorithm")]
    pub algorithm: String,
    #[serde(default)]
    pub secret: String,
    #[serde(default)]
    pub rsa_private_key_path: Option<String>,
    #[serde(default)]
    pub rsa_public_key_path: Option<String>,
    #[serde(default = "default_jwt_kid")]
    pub kid: String,
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub audience: String,
    #[serde(default = "default_access_expiry")]
    pub expiry_seconds: i64,
}

impl Default for JwtTokenProfile {
    fn default() -> Self {
        Self {
            algorithm: default_jwt_algorithm(),
            secret: String::new(),
            rsa_private_key_path: None,
            rsa_public_key_path: None,
            kid: default_jwt_kid(),
            issuer: String::new(),
            audience: String::new(),
            expiry_seconds: default_access_expiry(),
        }
    }
}

fn default_access_profile() -> JwtTokenProfile {
    JwtTokenProfile {
        audience: "astral-api".into(),
        ..Default::default()
    }
}

fn default_refresh_profile() -> JwtTokenProfile {
    JwtTokenProfile {
        audience: "astral-session".into(),
        expiry_seconds: 7 * 24 * 3600,
        ..Default::default()
    }
}

fn default_jwt_algorithm() -> String {
    "HS256".into()
}

fn default_jwt_kid() -> String {
    "astral-rust-v2".into()
}

fn default_access_expiry() -> i64 {
    900
}

/// Gateway HMAC 签名配置
#[derive(Debug, Clone, Deserialize)]
pub struct GatewayCfg {
    #[serde(default)]
    pub hmac_secret: String,
    /// Gateway -> Identity internal assertion key (K_GI).
    #[serde(default)]
    pub internal_service_secret: String,
    #[serde(default = "default_tolerance")]
    pub timestamp_tolerance_secs: i64,
    /// Exact proxy addresses (or CIDR prefixes) allowed to supply client IP headers.
    #[serde(default)]
    pub trusted_proxy_ips: Vec<String>,
}

impl Default for GatewayCfg {
    fn default() -> Self {
        Self {
            hmac_secret: String::new(),
            internal_service_secret: String::new(),
            timestamp_tolerance_secs: default_tolerance(),
            trusted_proxy_ips: Vec::new(),
        }
    }
}

fn default_tolerance() -> i64 {
    30
}

/// 限流配置
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RateLimitCfg {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_requests_per_second")]
    pub requests_per_second: u32,
    #[serde(default = "default_burst")]
    pub burst_size: u32,
}

fn default_enabled() -> bool {
    true
}
fn default_requests_per_second() -> u32 {
    100
}
fn default_burst() -> u32 {
    200
}

/// 微信小程序配置
#[derive(Debug, Clone, Default, Deserialize)]
pub struct WeChatConfig {
    /// 是否启用微信登录（默认禁用，需显式配置）
    #[serde(default)]
    pub enabled: bool,
    /// 小程序 AppID
    #[serde(default)]
    pub appid: String,
    /// 小程序 AppSecret
    #[serde(default)]
    pub secret: String,
}

/// Identifies which service consumes the shared JWT configuration.
///
/// Gateway replicas only verify tokens and therefore need public RSA keys;
/// Identity issues both access and refresh tokens and must have private keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtValidationRole {
    Gateway,
    Identity,
    Learn,
}

impl JwtValidationRole {
    fn requires_private_key(self) -> bool {
        matches!(self, Self::Identity)
    }
}

fn validate_jwt_profile(
    profile: &JwtTokenProfile,
    requires_private_key: bool,
) -> Result<(), ConfigValidationError> {
    match profile.algorithm.as_str() {
        "HS256" => {
            if profile.secret.len() < 32 {
                return Err(ConfigValidationError::JwtSecretTooShort);
            }
            if is_placeholder_secret(&profile.secret) {
                return Err(ConfigValidationError::JwtSecretPlaceholder);
            }
        }
        "RS256" => {
            let public_path = profile
                .rsa_public_key_path
                .as_deref()
                .ok_or(ConfigValidationError::RsaPublicKeyPathMissing)?;
            let public_pem = fs::read(public_path).map_err(|error| {
                ConfigValidationError::RsaPublicKeyUnreadable(error.to_string())
            })?;
            jsonwebtoken::DecodingKey::from_rsa_pem(&public_pem)
                .map_err(|error| ConfigValidationError::RsaPublicKeyInvalid(error.to_string()))?;
            if requires_private_key {
                let private_path = profile
                    .rsa_private_key_path
                    .as_deref()
                    .ok_or(ConfigValidationError::RsaPrivateKeyPathMissing)?;
                let private_pem = fs::read(private_path).map_err(|error| {
                    ConfigValidationError::RsaPrivateKeyUnreadable(error.to_string())
                })?;
                jsonwebtoken::EncodingKey::from_rsa_pem(&private_pem).map_err(|error| {
                    ConfigValidationError::RsaPrivateKeyInvalid(error.to_string())
                })?;
            }
        }
        algorithm => {
            return Err(ConfigValidationError::UnsupportedJwtAlgorithm(
                algorithm.to_string(),
            ));
        }
    }
    if profile.kid.trim().is_empty()
        || profile.issuer.trim().is_empty()
        || profile.audience.trim().is_empty()
        || profile.expiry_seconds <= 0
    {
        return Err(ConfigValidationError::UnsupportedJwtAlgorithm(
            "invalid token profile metadata".into(),
        ));
    }
    Ok(())
}

/// 部署 flat 环境变量显式覆盖契约（Rust harness / file-less 部署）。
///
/// config-rs 的 `Environment` 源把变量名中的 `_` 当作层级分隔符（同
/// [`AppConfig::resolved_db_max_connections`] 的说明）：`DATABASE_URL` 会被
/// 展开为嵌套键 `database.url`，永远无法命中 serde 扁平字段 `database_url`；
/// `GATEWAY_HMAC_SECRET` 会被展开为 `gateway.hmac.secret`，而真实字段名是
/// `gateway.hmac_secret`；`JWT_SECRET` 会命中不存在的 `jwt.secret`。远程部署
/// 目录没有 `application.yml`，这些部署名因此全部丢失，节点在启动校验
/// （secret/URL/CORS）处退出。
///
/// 本契约逐个显式映射部署 flat 名 → 目标字段，不依赖 config-rs 分隔符推断：
/// - 环境变量存在且非空白即覆盖；缺失或为空时保留 YAML/默认值（空覆盖不会
///   清空文件中已配置的有效值）。
/// - 密钥类覆盖值按字节原样使用（不 trim）；URL/issuer/mode 等非密钥字段
///   trim 后使用。
/// - typed 字段（bool/list）严格解析，非法值一律返回配置错误使启动失败
///   （fail-fast），错误信息只包含变量名与期望格式，绝不回显值。
/// - `LISTEN_ADDR` 与 `ASTRAL_*` 测试控制面变量在 `AppConfig` 之外读取
///   （main.rs / api::test_control），不属于本契约；唯一的 `ASTRAL_*` 例外是
///   部署旗标 `ASTRAL_ORG_SCOPE_ENABLED`（下方 ORG_SCOPE 块，经
///   [`parse_org_scope_enabled`] 严格解析并冻结到 [`AppConfig::org_scope_enabled`]）。
fn apply_flat_env_overrides(cfg: &mut AppConfig) -> Result<(), config::ConfigError> {
    fn optional_env(name: &str) -> Option<String> {
        match std::env::var(name) {
            Ok(value) if !value.trim().is_empty() => Some(value),
            _ => None,
        }
    }

    fn malformed(name: &str, expected: &str) -> config::ConfigError {
        config::ConfigError::Message(format!(
            "environment override {name} is malformed: expected {expected}"
        ))
    }

    fn parse_bool_strict(name: &str, raw: &str) -> Result<bool, config::ConfigError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(malformed(name, "\"true\" or \"false\"")),
        }
    }

    fn parse_origin_list(name: &str, raw: &str) -> Result<Vec<String>, config::ConfigError> {
        let entries: Vec<String> = raw
            .split(',')
            .map(|entry| entry.trim().to_owned())
            .collect();
        if entries.iter().any(String::is_empty) {
            return Err(malformed(name, "comma-separated non-empty origins"));
        }
        Ok(entries)
    }

    // 连接串（trim；scheme/主机策略由 validate_runtime_safety 统一校验）。
    if let Some(value) = optional_env("DATABASE_URL") {
        cfg.database_url = value.trim().to_string();
    }
    if let Some(value) = optional_env("REDIS_URL") {
        cfg.redis_url = value.trim().to_string();
    }
    if let Some(value) = optional_env("RABBITMQ_URL") {
        cfg.rabbitmq_url = value.trim().to_string();
    }
    if let Ok(value) = std::env::var("ASTRAL_MESSAGE_TRANSPORT") {
        cfg.message_transport = value.trim().to_string();
    }
    if let Ok(value) = std::env::var("ASTRAL_REGION_ID") {
        cfg.region_id = value.trim().to_string();
    }
    if let Ok(value) = std::env::var("ASTRAL_NODE_ID") {
        cfg.node_id = value.trim().to_string();
    }
    if let Ok(value) = std::env::var("ASTRAL_TARGET_REGION") {
        cfg.target_region = if value.trim().is_empty() {
            None
        } else {
            Some(value.trim().to_string())
        };
    }
    // JWT 双 profile：access 与 refresh 的签名材料必须相互独立（见 JwtConfig
    // 注释），因此不提供共享的 `JWT_SECRET` 名，避免静默复用。issuer/audience
    // 必须显式提供：只要 env 或 YAML 中存在任一 `jwt.<profile>` 子键，serde
    // 就走字段级默认（audience 字段默认为空串），file-less 部署若不显式映射
    // 这两个元数据字段，Learn 校验会以 "invalid token profile metadata" 拒绝。
    if let Some(value) = optional_env("JWT_ACCESS_SECRET") {
        cfg.jwt.access.secret = value;
    }
    if let Some(value) = optional_env("JWT_REFRESH_SECRET") {
        cfg.jwt.refresh.secret = value;
    }
    if let Some(value) = optional_env("JWT_ACCESS_ISSUER") {
        cfg.jwt.access.issuer = value.trim().to_string();
    }
    if let Some(value) = optional_env("JWT_REFRESH_ISSUER") {
        cfg.jwt.refresh.issuer = value.trim().to_string();
    }
    if let Some(value) = optional_env("JWT_ACCESS_AUDIENCE") {
        cfg.jwt.access.audience = value.trim().to_string();
    }
    if let Some(value) = optional_env("JWT_REFRESH_AUDIENCE") {
        cfg.jwt.refresh.audience = value.trim().to_string();
    }
    // Gateway HMAC（探针/身份头验签）与两把内部服务密钥（K_LG / K_GI）。
    if let Some(value) = optional_env("GATEWAY_HMAC_SECRET") {
        cfg.gateway.hmac_secret = value;
    }
    if let Some(value) = optional_env("INTERNAL_SERVICE_SECRET") {
        cfg.internal_service_secret = value;
    }
    if let Some(value) = optional_env("GATEWAY_INTERNAL_SERVICE_SECRET") {
        cfg.gateway.internal_service_secret = value;
    }
    // 非法取值由 validate_secrets_for 的 InvalidSessionGrantClaimsMode 拒绝。
    if let Some(value) = optional_env("SESSION_GRANT_CLAIMS_MODE") {
        cfg.session_grant_claims_mode = value.trim().to_string();
    }
    // ORG_SCOPE 部署旗标（default-off）：所有 PolicyEngine 宿主（trustgraph /
    // identity / monitor）经共享严格解析器在启动期一次解析并冻结到本字段，
    // 中间件 / 检查端点构造正式 SqlxRuleRepository 时统一传入，防止跨宿主
    // org_scope 准入 split-brain。非法值 fail-fast（配置加载即失败，启动拒绝，
    // 绝不静默降级）；env 缺失/空白保留默认 false。
    if let Some(value) = optional_env(ORG_SCOPE_ENABLED_ENV) {
        cfg.org_scope_enabled = parse_org_scope_enabled(Some(&value))
            .map_err(ConfigValidationError::into_config_error)?;
    }
    // Redis 会话投影兼容 adapter（default-off）：env 存在即覆盖，严格 bool，
    // 非法值启动失败。开启时 validate_runtime_safety 强制 redis_url 非空。
    // 解析走共享中心解析器（parse_redis_projection_compat），与 libs 冻结读
    // 同一契约，绝不复制第二份解析语义。
    if let Some(value) = optional_env(REDIS_PROJECTION_COMPAT_ENV) {
        cfg.redis_projection_compat_enabled = parse_redis_projection_compat(Some(&value))
            .map_err(ConfigValidationError::into_config_error)?;
    }
    // 单机镜像加速器（default-off）：严格 bool；语义边界见字段文档
    // （未命中/suspect 必须回退 strict DB，多节点部署保持关闭）。
    if let Some(value) = optional_env(SESSION_GRANT_MIRROR_ENV) {
        cfg.session_grant_mirror_enabled = parse_bool_strict(SESSION_GRANT_MIRROR_ENV, &value)?;
    }
    // 镜像 positive cache 永久旁路（default-off）：严格 bool，显式配置后
    // Gateway 安装镜像即 mark_suspect_permanent（deny marker 加速保留）。
    if let Some(value) = optional_env(SESSION_GRANT_MIRROR_POSITIVE_DISABLED_ENV) {
        cfg.session_grant_mirror_positive_disabled =
            parse_bool_strict(SESSION_GRANT_MIRROR_POSITIVE_DISABLED_ENV, &value)?;
    }
    // CORS：覆盖值整体替换（不追加）；列表为逗号分隔、条目 trim、空条目拒绝；
    // bool 严格解析。wildcard/localhost/https 策略仍由 validate_runtime_safety
    // 统一执行，本函数只做语法级 fail-fast。
    if let Some(value) = optional_env("CORS_ALLOW_CREDENTIALS") {
        cfg.cors.allow_credentials = parse_bool_strict("CORS_ALLOW_CREDENTIALS", &value)?;
    }
    if let Some(value) = optional_env("CORS_ALLOWED_ORIGINS") {
        cfg.cors.allowed_origins = parse_origin_list("CORS_ALLOWED_ORIGINS", &value)?;
    }
    Ok(())
}

impl AppConfig {
    pub fn from_env() -> Result<Self, config::ConfigError> {
        Self::from_env_for(JwtValidationRole::Identity)
    }

    fn is_test_profile() -> bool {
        ["APP_PROFILE", "RUST_ENV", "ENVIRONMENT"]
            .into_iter()
            .filter_map(|name| std::env::var(name).ok())
            .any(|value| {
                matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "test" | "testing"
                )
            })
    }

    pub fn from_env_for(role: JwtValidationRole) -> Result<Self, config::ConfigError> {
        let mut cfg: Self = config::Config::builder()
            .add_source(
                config::Environment::default()
                    .prefix("")
                    .separator("_")
                    .try_parsing(true),
            )
            .build()?
            .try_deserialize()?;
        // 部署 flat 名显式覆盖（见 apply_flat_env_overrides）：反序列化之后、
        // 校验之前应用，env 存在即覆盖，缺失保留默认值。
        apply_flat_env_overrides(&mut cfg)?;
        ensure_required_public_paths(&mut cfg.public_paths);
        cfg.validate_secrets_for(role)
            .map_err(ConfigValidationError::into_config_error)?;
        cfg.validate_runtime_safety(Self::is_test_profile())
            .map_err(ConfigValidationError::into_config_error)?;
        Ok(cfg)
    }

    pub fn from_files(path: &str) -> Result<Self, config::ConfigError> {
        Self::from_files_for(path, JwtValidationRole::Learn)
    }

    pub fn from_files_for(
        path: &str,
        role: JwtValidationRole,
    ) -> Result<Self, config::ConfigError> {
        let mut cfg: Self = config::Config::builder()
            .add_source(config::File::with_name(path).required(false))
            .add_source(
                config::Environment::default()
                    .prefix("")
                    .separator("_")
                    .try_parsing(true),
            )
            .build()?
            .try_deserialize()?;
        // 部署 flat 环境变量显式覆盖（见 apply_flat_env_overrides）：必须在
        // 反序列化之后、校验之前应用——env 存在即覆盖，缺失保留 YAML 值；
        // 远程部署目录没有 application.yml 时由该契约提供全部启动字段。
        apply_flat_env_overrides(&mut cfg)?;
        // An explicit YAML list must not accidentally remove the mandatory
        // Java-compatible login, refresh, verification, and health routes.
        ensure_required_public_paths(&mut cfg.public_paths);
        cfg.validate_secrets_for(role)
            .map_err(ConfigValidationError::into_config_error)?;
        cfg.validate_runtime_safety(Self::is_test_profile())
            .map_err(ConfigValidationError::into_config_error)?;
        // 将 redis_url 同步到 REDIS_URL 环境变量，供 MQ consumer 等非 AppConfig
        // 场景使用。Redis-free 部署（redis_url 为空）不写 env：下游 Redis 依赖
        // 方（MQ 幂等/兼容 adapter）按各自的可选契约显式处理空值，绝不把空串
        // 误当成可连接地址。
        if !cfg.redis_url.trim().is_empty() && std::env::var("REDIS_URL").is_err() {
            std::env::set_var("REDIS_URL", &cfg.redis_url);
        }
        Ok(cfg)
    }

    pub fn message_transport(&self) -> Result<MessageTransport, ConfigValidationError> {
        MessageTransport::parse(&self.message_transport)
    }

    pub fn validate_identity_session_grant_compatibility(
        &self,
    ) -> Result<(), ConfigValidationError> {
        if !self
            .session_grant_claims_mode
            .eq_ignore_ascii_case("REQUIRE")
        {
            return Err(ConfigValidationError::InvalidSessionGrantClaimsMode(
                "token v2 requires REQUIRE".into(),
            ));
        }
        Ok(())
    }

    /// 解析 MySQL 服务池最大连接数：env `ASTRAL_DB_MAX_CONNECTIONS` >
    /// `db_max_connections` 字段 > 默认 80。
    ///
    /// env 之所以在此显式读取：config-rs 的 Environment 源以 `_` 为层级分隔
    /// 符，`ASTRAL_DB_MAX_CONNECTIONS` 会被展开为嵌套键
    /// `astral.db.max.connections`，无法命中本扁平字段；显式读取保证该部署
    /// 约定的 env 名真实生效。env 存在但非法（非 u32 或为 0）→ `Err`（启动
    /// 失败，fail-fast，对齐 `parse_projector_tenants` 的拒绝语义）。
    pub fn resolved_db_max_connections(&self) -> Result<u32, String> {
        match std::env::var("ASTRAL_DB_MAX_CONNECTIONS") {
            Ok(raw) => {
                let value: u32 = raw
                    .trim()
                    .parse()
                    .map_err(|_| format!("ASTRAL_DB_MAX_CONNECTIONS is not a valid u32: {raw}"))?;
                if value == 0 {
                    return Err("ASTRAL_DB_MAX_CONNECTIONS must be >= 1".into());
                }
                Ok(value)
            }
            // derive(Default) 会把未配置字段填 0：0 视为"未配置"回落默认值。
            Err(_) if self.db_max_connections == 0 => Ok(default_db_max_connections()),
            Err(_) => Ok(self.db_max_connections),
        }
    }

    /// 解析 MySQL 连接池 acquire 超时：env `ASTRAL_DB_ACQUIRE_TIMEOUT_SECS` >
    /// `db_acquire_timeout_seconds` 字段 > 默认 5s（env 展开语义同上；非法
    /// env 同样 fail-fast）。
    pub fn resolved_db_acquire_timeout(&self) -> Result<Duration, String> {
        match std::env::var("ASTRAL_DB_ACQUIRE_TIMEOUT_SECS") {
            Ok(raw) => {
                let seconds: u64 = raw.trim().parse().map_err(|_| {
                    format!("ASTRAL_DB_ACQUIRE_TIMEOUT_SECS is not a valid u64: {raw}")
                })?;
                if seconds == 0 {
                    return Err("ASTRAL_DB_ACQUIRE_TIMEOUT_SECS must be >= 1".into());
                }
                Ok(Duration::from_secs(seconds))
            }
            Err(_) if self.db_acquire_timeout_seconds == 0 => {
                Ok(Duration::from_secs(default_db_acquire_timeout_seconds()))
            }
            Err(_) => Ok(Duration::from_secs(self.db_acquire_timeout_seconds)),
        }
    }

    /// 宿主能力断言（**纯函数**，redis-layer-retirement-20261002 收口）：
    /// `redis_projection_compat_enabled` 开启时，本宿主二进制必须真的编译了
    /// 自己的 `redis-compat` adapter。
    ///
    /// 每个宿主 runtime（gateway / identity / trustgraph / monitor）在配置校验
    /// 之后、任何 DB 连接 / 服务 / worker 装配之前，以**自身 crate** 的
    /// `cfg!(feature = "redis-compat")` 作为 `adapter_compiled` 调用一次。
    /// 纯函数是刻意设计：workspace feature 统一会让 astral-common 的零依赖
    /// marker 在"本宿主没编译 adapter"时也为真，只有宿主自身的 cfg! 才是
    /// 可信的能力事实；旗标开启 + adapter 未编译 → 显式拒绝启动
    /// （[`ConfigValidationError::RedisCompatRequiresFeatureBuild`]，fail-closed，
    /// 绝不 log-only 静默 Redis-free 化）。旗标关闭（Redis-free 默认）恒放行。
    pub fn validate_redis_adapter_support(
        &self,
        adapter_compiled: bool,
    ) -> Result<(), ConfigValidationError> {
        if self.redis_projection_compat_enabled && !adapter_compiled {
            return Err(ConfigValidationError::RedisCompatRequiresFeatureBuild);
        }
        Ok(())
    }

    fn validate_runtime_safety(&self, test_profile: bool) -> Result<(), ConfigValidationError> {
        let transport = MessageTransport::parse(&self.message_transport)?;
        validate_connection_url("DATABASE_URL", &self.database_url, &["mysql"], test_profile)?;
        // Redis-free 默认路径：redis_url 允许为空（会话判定走 strict MySQL，
        // 见 astral-db::session_state_repository）。Redis 退化为显式兼容
        // adapter：开启 redis_projection_compat_enabled 时必须提供非空且
        // scheme 合法的 redis_url（fail-closed，禁止半开配置）。
        if self.redis_url.trim().is_empty() {
            if self.redis_projection_compat_enabled {
                return Err(ConfigValidationError::RedisCompatRequiresUrl);
            }
        } else {
            validate_connection_url("REDIS_URL", &self.redis_url, &["redis"], test_profile)?;
        }
        // Redis 编译层退役收口（redis-layer-retirement-20261002）：compat 是
        // 显式 opt-in 的**编译期**能力——旗标开启但二进制未编译 `redis-compat`
        // feature 时启动必须明确失败，绝不静默 Redis-free 化（fail-closed）。
        // 这里的 cfg 断言只覆盖 astral-common 自身的 marker（feature 由各
        // runtime 的 redis-compat 传播），是对宿主能力门的纵深防御：workspace
        // feature 统一下 marker 可被任意其他 crate 点亮，因此每个宿主还必须
        // 以**自身 crate** 的 `cfg!(feature = "redis-compat")` 调用
        // [`AppConfig::validate_redis_adapter_support`]。
        self.validate_redis_adapter_support(cfg!(feature = "redis-compat"))?;
        validate_transport_identity(
            &self.region_id,
            &self.node_id,
            self.target_region.as_deref(),
            transport,
        )?;
        if matches!(transport, MessageTransport::Rabbit) {
            if self.rabbitmq_url.trim().is_empty() && !test_profile {
                return Err(ConfigValidationError::RabbitmqUrlRequiredForTransport);
            }
            validate_connection_url(
                "RABBITMQ_URL",
                &self.rabbitmq_url,
                &["amqp", "amqps"],
                test_profile,
            )?;
        }

        if self.cors.allowed_origins.is_empty() {
            return Err(ConfigValidationError::CorsOriginsMissing);
        }
        let has_wildcard = self
            .cors
            .allowed_origins
            .iter()
            .any(|origin| origin.trim() == "*");
        if has_wildcard && (!test_profile || self.cors.allow_credentials) {
            return Err(ConfigValidationError::CorsWildcard);
        }
        for origin in &self.cors.allowed_origins {
            validate_cors_origin(origin, test_profile)?;
        }
        Ok(())
    }

    fn validate_secrets_for(&self, role: JwtValidationRole) -> Result<(), ConfigValidationError> {
        let requires_private_key = role.requires_private_key();
        let result: Result<(), ConfigValidationError> =
            validate_jwt_profile(&self.jwt.access, requires_private_key)
                .and_then(|_| validate_jwt_profile(&self.jwt.refresh, requires_private_key));
        result?;
        if matches!(
            role,
            JwtValidationRole::Gateway | JwtValidationRole::Identity
        ) {
            if self.gateway.hmac_secret.len() < 32 {
                return Err(ConfigValidationError::GatewayHmacSecretTooShort);
            }
            if is_placeholder_secret(&self.gateway.hmac_secret) {
                return Err(ConfigValidationError::GatewayHmacSecretPlaceholder);
            }
        }
        if self.gateway.timestamp_tolerance_secs <= 0 {
            return Err(ConfigValidationError::GatewayTimestampToleranceInvalid);
        }
        if matches!(role, JwtValidationRole::Gateway | JwtValidationRole::Learn) {
            if self.internal_service_secret.len() < 32 {
                return Err(ConfigValidationError::InternalServiceSecretTooShort);
            }
            if is_placeholder_secret(&self.internal_service_secret) {
                return Err(ConfigValidationError::InternalServiceSecretPlaceholder);
            }
        }
        if matches!(
            role,
            JwtValidationRole::Gateway | JwtValidationRole::Identity
        ) {
            if self.gateway.internal_service_secret.len() < 32 {
                return Err(ConfigValidationError::GatewayInternalServiceSecretTooShort);
            }
            if is_placeholder_secret(&self.gateway.internal_service_secret) {
                return Err(ConfigValidationError::GatewayInternalServiceSecretPlaceholder);
            }
        }
        // session_grant_claims_mode 取值校验：非法值若静默按 OFF（fail-open）处理
        // 会关闭 SessionGrant 校验，对齐 Java `SessionGrantClaimsMode.parse` 拒绝语义。
        // 空串视为未配置（serde default 为 OFF）；显式配置为非法值则启动失败。
        match self.session_grant_claims_mode.to_uppercase().as_str() {
            "" | "OFF" | "EMIT" | "REQUIRE" => {}
            other => {
                return Err(ConfigValidationError::InvalidSessionGrantClaimsMode(
                    other.to_string(),
                ))
            }
        }
        Ok(())
    }
}

fn ensure_required_public_paths(paths: &mut Vec<String>) {
    for required in default_public_paths() {
        if !paths.iter().any(|path| path == &required) {
            paths.push(required);
        }
    }
}

fn validate_transport_identity(
    region_id: &str,
    node_id: &str,
    target_region: Option<&str>,
    transport: MessageTransport,
) -> Result<(), ConfigValidationError> {
    let region_id = region_id.trim();
    let node_id = node_id.trim();
    if region_id.is_empty() || region_id.len() > 64 {
        return Err(ConfigValidationError::InvalidRegionId);
    }
    if node_id.is_empty() || node_id.len() > 128 {
        return Err(ConfigValidationError::InvalidNodeId);
    }
    if let Some(target_region) = target_region {
        if target_region.trim().is_empty() || target_region.trim().len() > 64 {
            return Err(ConfigValidationError::InvalidTargetRegion);
        }
    }
    if matches!(transport, MessageTransport::Local)
        && target_region.is_some_and(|target| target.trim() != region_id)
    {
        return Err(ConfigValidationError::InvalidTargetRegion);
    }
    Ok(())
}

fn validate_connection_url(
    name: &str,
    value: &str,
    allowed_schemes: &[&str],
    test_profile: bool,
) -> Result<(), ConfigValidationError> {
    let value = value.trim();
    if value.is_empty() {
        if test_profile {
            return Ok(());
        }
        return Err(match name {
            "DATABASE_URL" => ConfigValidationError::DatabaseUrlMissing,
            "REDIS_URL" => ConfigValidationError::RedisUrlMissing,
            "RABBITMQ_URL" => ConfigValidationError::RabbitmqUrlMissing,
            _ => ConfigValidationError::ConnectionUrlInvalid(name.into()),
        });
    }

    if value.chars().any(char::is_whitespace) {
        return Err(ConfigValidationError::ConnectionUrlInvalid(name.into()));
    }
    let uri: Uri = value
        .parse()
        .map_err(|_| ConfigValidationError::ConnectionUrlInvalid(name.into()))?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| ConfigValidationError::ConnectionUrlInvalid(name.into()))?;
    if !allowed_schemes
        .iter()
        .any(|allowed| scheme.eq_ignore_ascii_case(allowed))
    {
        return Err(ConfigValidationError::ConnectionUrlInvalid(name.into()));
    }
    let authority = uri
        .authority()
        .ok_or_else(|| ConfigValidationError::ConnectionUrlInvalid(name.into()))?;
    let host = authority.host();
    if host.is_empty() {
        return Err(ConfigValidationError::ConnectionUrlInvalid(name.into()));
    }

    if !test_profile && is_local_host(host) {
        return Err(ConfigValidationError::LocalhostConnection(name.into()));
    }
    Ok(())
}

fn validate_cors_origin(origin: &str, test_profile: bool) -> Result<(), ConfigValidationError> {
    let origin = origin.trim();
    if origin.is_empty() || origin == "*" {
        return Err(if origin == "*" {
            ConfigValidationError::CorsWildcard
        } else {
            ConfigValidationError::CorsOriginInvalid
        });
    }
    let uri: Uri = origin
        .parse()
        .map_err(|_| ConfigValidationError::CorsOriginInvalid)?;
    let scheme = uri
        .scheme_str()
        .ok_or(ConfigValidationError::CorsOriginInvalid)?;
    if !matches!(scheme, "http" | "https")
        || uri.authority().is_none()
        || uri.query().is_some()
        || (uri.path() != "" && uri.path() != "/")
    {
        return Err(ConfigValidationError::CorsOriginInvalid);
    }
    let authority = uri
        .authority()
        .ok_or(ConfigValidationError::CorsOriginInvalid)?;
    if authority.as_str().contains('@') {
        return Err(ConfigValidationError::CorsOriginInvalid);
    }
    let host = authority.host();
    if host.is_empty() {
        return Err(ConfigValidationError::CorsOriginInvalid);
    }

    if !test_profile && (scheme != "https" || is_local_host(host) || is_private_or_link_local(host))
    {
        return Err(ConfigValidationError::CorsOriginUnsafe);
    }
    Ok(())
}

fn is_local_host(host: &str) -> bool {
    let normalized = host.trim_matches(['[', ']']).to_ascii_lowercase();
    normalized == "localhost"
        || normalized.ends_with(".localhost")
        || normalized == "0.0.0.0"
        || normalized == "::"
        || normalized == "::1"
        || normalized.starts_with("127.")
        || normalized
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback() || address.is_unspecified())
}

fn is_private_or_link_local(host: &str) -> bool {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => address.is_private() || address.is_link_local(),
        Ok(IpAddr::V6(address)) => address.is_unique_local() || address.is_unicast_link_local(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rsa::{
        pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
        RsaPrivateKey,
    };
    use std::path::PathBuf;

    fn valid_jwt_config() -> JwtConfig {
        JwtConfig {
            access: JwtTokenProfile {
                secret: "access-test-secret-0123456789abcdef".into(),
                kid: "access-test".into(),
                issuer: "astral-identity".into(),
                audience: "astral-api".into(),
                ..Default::default()
            },
            refresh: JwtTokenProfile {
                secret: "refresh-test-secret-0123456789abcdef".into(),
                kid: "refresh-test".into(),
                issuer: "astral-identity".into(),
                audience: "astral-session".into(),
                expiry_seconds: 7 * 24 * 3600,
                ..Default::default()
            },
        }
    }

    fn valid_gateway() -> GatewayCfg {
        GatewayCfg {
            hmac_secret: "gateway-test-secret-0123456789abcdef".into(),
            internal_service_secret: "gateway-internal-test-secret-0123456789".into(),
            ..Default::default()
        }
    }

    fn valid_jwt_secret() -> String {
        "jwt-test-secret-0123456789abcdef".into()
    }

    // ---- flat env 覆盖契约测试的进程级 env 隔离 --------------------------
    //
    // env 是进程全局的：lib 测试多线程并行，任何 set/remove 必须串行并恢复
    // 原值。flat env 契约测试与 db_pool 测试共用同一把互斥锁；guard 在
    // acquire 时保存原始值并清空全部契约变量（含 profile 探测名，使
    // is_test_profile() 恒为 false、校验走非 test 分支），drop 时逐项恢复，
    // 既不受外层 shell 环境污染，也不会把临时值泄漏给其他测试。
    const FLAT_ENV_CONTRACT_VARS: &[&str] = &[
        // profile 探测名（is_test_profile）。
        "APP_PROFILE",
        "RUST_ENV",
        "ENVIRONMENT",
        // apply_flat_env_overrides 契约名。
        "DATABASE_URL",
        "REDIS_URL",
        "RABBITMQ_URL",
        "ASTRAL_MESSAGE_TRANSPORT",
        "ASTRAL_REGION_ID",
        "ASTRAL_NODE_ID",
        "ASTRAL_TARGET_REGION",
        "JWT_ACCESS_SECRET",
        "JWT_REFRESH_SECRET",
        "JWT_ACCESS_ISSUER",
        "JWT_REFRESH_ISSUER",
        "JWT_ACCESS_AUDIENCE",
        "JWT_REFRESH_AUDIENCE",
        "GATEWAY_HMAC_SECRET",
        "INTERNAL_SERVICE_SECRET",
        "GATEWAY_INTERNAL_SERVICE_SECRET",
        "SESSION_GRANT_CLAIMS_MODE",
        "CORS_ALLOWED_ORIGINS",
        "CORS_ALLOW_CREDENTIALS",
        // ORG_SCOPE 部署旗标（parse_org_scope_enabled 契约）。
        ORG_SCOPE_ENABLED_ENV,
        // Redis 会话投影兼容旗标（parse_redis_projection_compat 契约）。
        REDIS_PROJECTION_COMPAT_ENV,
        // 单机镜像加速器（default-on）与 positive cache 旁路（default-off）。
        SESSION_GRANT_MIRROR_ENV,
        SESSION_GRANT_MIRROR_POSITIVE_DISABLED_ENV,
    ];

    fn env_contract_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    struct FlatEnvGuard {
        saved: Vec<(&'static str, Option<String>)>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl FlatEnvGuard {
        fn acquire() -> Self {
            let lock = env_contract_test_lock();
            let saved = FLAT_ENV_CONTRACT_VARS
                .iter()
                .map(|name| (*name, std::env::var(name).ok()))
                .collect();
            for name in FLAT_ENV_CONTRACT_VARS {
                std::env::remove_var(name);
            }
            Self { saved, _lock: lock }
        }

        fn set(&self, name: &str, value: &str) {
            std::env::set_var(name, value);
        }
    }

    impl Drop for FlatEnvGuard {
        fn drop(&mut self) {
            for (name, saved) in std::mem::take(&mut self.saved) {
                match saved {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }

    #[test]
    fn hs256_rejects_known_placeholder_secret() {
        let mut jwt = valid_jwt_config();
        jwt.access.secret = "change-me-to-a-long-random-secret-key".into();
        let config = AppConfig {
            jwt,
            gateway: valid_gateway(),
            ..Default::default()
        };
        assert!(matches!(
            config
                .validate_secrets_for(JwtValidationRole::Identity)
                .unwrap_err(),
            ConfigValidationError::JwtSecretPlaceholder
        ));
    }

    #[test]
    fn gateway_rejects_repeated_placeholder_secret() {
        let config = AppConfig {
            jwt: valid_jwt_config(),
            gateway: GatewayCfg {
                hmac_secret: "x".repeat(32),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(matches!(
            config
                .validate_secrets_for(JwtValidationRole::Identity)
                .unwrap_err(),
            ConfigValidationError::GatewayHmacSecretPlaceholder
        ));
    }

    #[test]
    fn trustgraph_gateway_role_requires_real_hmac_while_learn_default_skips_it() {
        // HMAC 审计缺口修复的合同钉子（2026-09-21）：from_files() 的默认角色
        // 是 Learn（跳过 gateway.hmac_secret 强制校验，历史兼容语义保持不变）；
        // 任何验签 Gateway 身份头的服务（trustgraph）必须显式走 Gateway 角色，
        // 占位/过短 hmac 一律启动失败。
        let config = AppConfig {
            jwt: valid_jwt_config(),
            gateway: GatewayCfg {
                hmac_secret: "x".repeat(32),
                ..valid_gateway()
            },
            ..Default::default()
        };
        assert!(matches!(
            config
                .validate_secrets_for(JwtValidationRole::Gateway)
                .unwrap_err(),
            ConfigValidationError::GatewayHmacSecretPlaceholder
        ));
        // Learn 角色保持历史行为：hmac 不在强制清单内（其余密钥要求不变，
        // 该部分配置字段的不满足会以其他错误形态出现，与本合同无关）。
        let learn_error = config.validate_secrets_for(JwtValidationRole::Learn).err();
        assert!(!matches!(
            learn_error,
            Some(ConfigValidationError::GatewayHmacSecretPlaceholder)
                | Some(ConfigValidationError::GatewayHmacSecretTooShort)
        ));
    }

    #[test]
    fn valid_non_placeholder_secrets_are_accepted() {
        let config = AppConfig {
            jwt: valid_jwt_config(),
            gateway: valid_gateway(),
            ..Default::default()
        };
        assert!(config
            .validate_secrets_for(JwtValidationRole::Identity)
            .is_ok());
    }

    #[test]
    fn require_mode_is_the_only_supported_session_grant_mode() {
        let require = AppConfig {
            session_grant_claims_mode: "REQUIRE".into(),
            ..Default::default()
        };
        assert!(require
            .validate_identity_session_grant_compatibility()
            .is_ok());
        for mode in ["OFF", "EMIT"] {
            let config = AppConfig {
                session_grant_claims_mode: mode.into(),
                ..Default::default()
            };
            assert!(config
                .validate_identity_session_grant_compatibility()
                .is_err());
        }
    }

    #[test]
    fn structured_error_identifies_short_jwt_secret() {
        let mut jwt = valid_jwt_config();
        jwt.access.secret = "s".repeat(31);
        let config = AppConfig {
            jwt,
            gateway: valid_gateway(),
            ..Default::default()
        };
        let error = config
            .validate_secrets_for(JwtValidationRole::Identity)
            .unwrap_err();
        assert!(matches!(error, ConfigValidationError::JwtSecretTooShort));
    }

    #[test]
    fn structured_error_identifies_missing_rsa_key_path() {
        let mut jwt = valid_jwt_config();
        jwt.access.algorithm = "RS256".into();
        let config = AppConfig {
            jwt,
            gateway: valid_gateway(),
            ..Default::default()
        };
        assert!(config
            .validate_secrets_for(JwtValidationRole::Identity)
            .unwrap_err()
            .to_string()
            .contains("JWT_RSA_PUBLIC_KEY_PATH"));
    }

    #[test]
    fn structured_error_identifies_unsupported_algorithm() {
        let mut jwt = valid_jwt_config();
        jwt.access.algorithm = "HS512".into();
        let config = AppConfig {
            jwt,
            gateway: valid_gateway(),
            ..Default::default()
        };
        assert!(config
            .validate_secrets_for(JwtValidationRole::Identity)
            .unwrap_err()
            .to_string()
            .contains("unsupported JWT algorithm"));
    }
    #[test]
    fn hs256_rejects_empty_secret() {
        let mut jwt = valid_jwt_config();
        jwt.access.secret.clear();
        let config = AppConfig {
            jwt,
            gateway: valid_gateway(),
            ..Default::default()
        };
        let error = config
            .validate_secrets_for(JwtValidationRole::Identity)
            .unwrap_err();
        assert!(matches!(error, ConfigValidationError::JwtSecretTooShort));
    }
    #[test]
    fn rs256_does_not_require_hs_secret() {
        let mut jwt = valid_jwt_config();
        jwt.access.algorithm = "RS256".into();
        jwt.access.secret.clear();
        jwt.access.rsa_public_key_path = Some("/path/that/does/not/exist".into());
        jwt.access.rsa_private_key_path = Some("/path/that/does/not/exist-private".into());
        let config = AppConfig {
            jwt,
            gateway: valid_gateway(),
            ..Default::default()
        };
        let error = config
            .validate_secrets_for(JwtValidationRole::Identity)
            .unwrap_err()
            .to_string();
        assert!(error.contains("not readable"));
        assert!(!error.contains("JWT_SECRET"));
    }

    #[test]
    fn gateway_hmac_requires_at_least_32_bytes() {
        let mut jwt = valid_jwt_config();
        jwt.access.secret = valid_jwt_secret();
        let config = AppConfig {
            jwt,
            gateway: GatewayCfg {
                hmac_secret: "g".repeat(31),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(config
            .validate_secrets_for(JwtValidationRole::Identity)
            .is_err());
    }

    #[test]
    fn gateway_timestamp_tolerance_must_be_positive() {
        let config = AppConfig {
            jwt: valid_jwt_config(),
            gateway: GatewayCfg {
                hmac_secret: valid_gateway().hmac_secret,
                timestamp_tolerance_secs: 0,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(matches!(
            config
                .validate_secrets_for(JwtValidationRole::Identity)
                .unwrap_err(),
            ConfigValidationError::GatewayTimestampToleranceInvalid
        ));
    }

    #[test]
    fn v2_public_path_contract_contains_sessions_only() {
        assert!(default_public_paths()
            .iter()
            .any(|path| path == "/api/v1/auth/sessions"));
        assert!(!default_public_paths()
            .iter()
            .any(|path| path == "/api/v1/auth/refresh"));
    }

    #[test]
    fn public_defaults_do_not_include_mfa_or_wechat() {
        let paths = default_public_paths();
        assert!(!paths.iter().any(|path| path.contains("/mfa/")));
        assert!(!paths.iter().any(|path| path.contains("wechat")));
        assert!(paths
            .iter()
            .any(|path| path == "/api/v1/auth/password/reset/*"));
    }
    #[test]
    fn loaded_public_paths_keep_v2_login_and_health_routes() {
        let mut paths = vec!["/custom".to_string()];
        ensure_required_public_paths(&mut paths);
        assert!(paths.iter().any(|path| path == "/api/v1/auth/sessions"));
        assert!(paths.iter().any(|path| path == "/api/health/**"));
        assert!(paths.iter().any(|path| path == "/custom"));
    }

    #[test]
    fn rs256_accepts_valid_public_key_without_hs_secret() {
        let (public_pem, private_pem) = generated_rsa_key_pair();
        let path = temp_key_path("valid");
        let private_key_path = temp_key_path("valid-private");
        fs::write(&path, public_pem).unwrap();
        fs::write(&private_key_path, private_pem).unwrap();
        let mut jwt = valid_jwt_config();
        jwt.access.algorithm = "RS256".into();
        jwt.access.secret.clear();
        jwt.access.rsa_public_key_path = Some(path.to_string_lossy().into_owned());
        jwt.access.rsa_private_key_path = Some(private_key_path.to_string_lossy().into_owned());
        let config = AppConfig {
            jwt,
            gateway: valid_gateway(),
            database_url: "mysql://localhost:3306/astral_test".into(),
            ..Default::default()
        };
        assert!(config
            .validate_secrets_for(JwtValidationRole::Identity)
            .is_ok());
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(private_key_path);
    }

    #[test]
    fn gateway_rs256_accepts_public_key_only_profiles() {
        let (public_pem, _) = generated_rsa_key_pair();
        let public_path = temp_key_path("gateway-public-only");
        fs::write(&public_path, public_pem).unwrap();
        let public_path = public_path.to_string_lossy().into_owned();
        let mut jwt = valid_jwt_config();
        for profile in [&mut jwt.access, &mut jwt.refresh] {
            profile.algorithm = "RS256".into();
            profile.secret.clear();
            profile.rsa_public_key_path = Some(public_path.clone());
            profile.rsa_private_key_path = None;
        }
        let config = AppConfig {
            jwt,
            internal_service_secret: "learn-gateway-test-secret-0123456789".into(),
            gateway: valid_gateway(),
            ..Default::default()
        };

        assert!(config
            .validate_secrets_for(JwtValidationRole::Gateway)
            .is_ok());
        assert!(matches!(
            config
                .validate_secrets_for(JwtValidationRole::Identity)
                .unwrap_err(),
            ConfigValidationError::RsaPrivateKeyPathMissing
        ));
        let _ = fs::remove_file(public_path);
    }

    #[test]
    fn rs256_rejects_missing_private_key_path() {
        let (public_pem, _) = generated_rsa_key_pair();
        let public_path = temp_key_path("missing-private-public");
        fs::write(&public_path, public_pem).unwrap();
        let mut jwt = valid_jwt_config();
        jwt.access.algorithm = "RS256".into();
        jwt.access.secret.clear();
        jwt.access.rsa_public_key_path = Some(public_path.to_string_lossy().into_owned());
        let config = AppConfig {
            jwt,
            gateway: valid_gateway(),
            ..Default::default()
        };
        let error = config
            .validate_secrets_for(JwtValidationRole::Identity)
            .unwrap_err();
        let _ = fs::remove_file(public_path);
        assert!(matches!(
            error,
            ConfigValidationError::RsaPrivateKeyPathMissing
        ));
    }

    #[test]
    fn rs256_rejects_unreadable_private_key() {
        let (public_pem, _) = generated_rsa_key_pair();
        let public_path = temp_key_path("unreadable-private-public");
        fs::write(&public_path, public_pem).unwrap();
        let mut jwt = valid_jwt_config();
        jwt.access.algorithm = "RS256".into();
        jwt.access.secret.clear();
        jwt.access.rsa_public_key_path = Some(public_path.to_string_lossy().into_owned());
        jwt.access.rsa_private_key_path = Some("/path/that/does/not/exist-private".into());
        let config = AppConfig {
            jwt,
            gateway: valid_gateway(),
            ..Default::default()
        };
        let error = config
            .validate_secrets_for(JwtValidationRole::Identity)
            .unwrap_err();
        let _ = fs::remove_file(public_path);
        assert!(matches!(
            error,
            ConfigValidationError::RsaPrivateKeyUnreadable(_)
        ));
    }

    #[test]
    fn rs256_rejects_invalid_private_key() {
        let (public_pem, _) = generated_rsa_key_pair();
        let public_path = temp_key_path("invalid-private-public");
        let private_path = temp_key_path("invalid-private");
        fs::write(&public_path, public_pem).unwrap();
        fs::write(&private_path, b"not a key").unwrap();
        let mut jwt = valid_jwt_config();
        jwt.access.algorithm = "RS256".into();
        jwt.access.secret.clear();
        jwt.access.rsa_public_key_path = Some(public_path.to_string_lossy().into_owned());
        jwt.access.rsa_private_key_path = Some(private_path.to_string_lossy().into_owned());
        let config = AppConfig {
            jwt,
            gateway: valid_gateway(),
            ..Default::default()
        };
        let error = config
            .validate_secrets_for(JwtValidationRole::Identity)
            .unwrap_err();
        let _ = fs::remove_file(public_path);
        let _ = fs::remove_file(private_path);
        assert!(matches!(
            error,
            ConfigValidationError::RsaPrivateKeyInvalid(_)
        ));
    }
    #[test]
    fn rs256_rejects_invalid_public_key_without_hs_secret() {
        let path = temp_key_path("invalid");
        fs::write(&path, b"not a key").unwrap();
        let mut jwt = valid_jwt_config();
        jwt.access.algorithm = "RS256".into();
        jwt.access.secret.clear();
        jwt.access.rsa_public_key_path = Some(path.to_string_lossy().into_owned());
        let config = AppConfig {
            jwt,
            gateway: valid_gateway(),
            ..Default::default()
        };
        let error = config
            .validate_secrets_for(JwtValidationRole::Identity)
            .unwrap_err()
            .to_string();
        let _ = fs::remove_file(path);
        assert!(error.contains("not a valid PEM key"));
    }

    fn generated_rsa_key_pair() -> (String, String) {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA test key");
        let public_key = private_key.to_public_key();
        let private_pem = private_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode RSA private test key")
            .to_string();
        let public_pem = public_key
            .to_public_key_pem(LineEnding::LF)
            .expect("encode RSA public test key");
        (public_pem, private_pem)
    }

    fn temp_key_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("astral-common-{label}-{}", std::process::id()))
    }

    #[test]
    fn message_transport_parser_is_strict_and_fail_closed() {
        assert_eq!(
            MessageTransport::parse("local"),
            Ok(MessageTransport::Local)
        );
        assert_eq!(
            MessageTransport::parse("rabbit"),
            Ok(MessageTransport::Rabbit)
        );
        for invalid in ["", " ", "LOCAL", "RABBIT", "amqp", "fallback"] {
            assert!(
                MessageTransport::parse(invalid).is_err(),
                "transport value {invalid:?} must fail closed"
            );
        }
    }

    #[test]
    fn local_runtime_does_not_require_rabbit_url() {
        let mut config = valid_runtime_config();
        config.message_transport = "local".into();
        config.rabbitmq_url.clear();
        assert!(config.validate_runtime_safety(false).is_ok());
    }

    #[test]
    fn rabbit_runtime_requires_rabbit_url() {
        let mut config = valid_runtime_config();
        config.message_transport = "rabbit".into();
        config.rabbitmq_url.clear();
        assert!(matches!(
            config.validate_runtime_safety(false),
            Err(ConfigValidationError::RabbitmqUrlRequiredForTransport)
        ));
    }

    #[test]
    fn transport_identity_rejects_invalid_region_and_local_target() {
        let mut config = valid_runtime_config();
        config.message_transport = "local".into();
        config.region_id.clear();
        assert!(matches!(
            config.validate_runtime_safety(false),
            Err(ConfigValidationError::InvalidRegionId)
        ));
        config.region_id = "region-a".into();
        config.node_id = "node-a".into();
        config.target_region = Some("region-b".into());
        assert!(matches!(
            config.validate_runtime_safety(false),
            Err(ConfigValidationError::InvalidTargetRegion)
        ));
    }

    fn valid_runtime_config() -> AppConfig {
        AppConfig {
            database_url: "mysql://db.example.invalid:3306/astral_test".into(),
            redis_url: "redis://cache.example.invalid:6379/0".into(),
            rabbitmq_url: "amqps://mq.example.invalid:5671/%2f".into(),
            cors: CorsConfig {
                allowed_origins: vec!["https://console.example.invalid".into()],
                allow_credentials: true,
            },
            ..Default::default()
        }
    }

    #[test]
    fn runtime_validation_rejects_missing_service_secret() {
        let config = AppConfig {
            jwt: valid_jwt_config(),
            gateway: valid_gateway(),
            ..valid_runtime_config()
        };
        assert!(matches!(
            config.validate_secrets_for(JwtValidationRole::Gateway),
            Err(ConfigValidationError::InternalServiceSecretTooShort)
        ));
    }

    #[test]
    fn runtime_validation_rejects_localhost_connection_outside_test_profile() {
        let mut config = valid_runtime_config();
        config.redis_url = "redis://localhost:6379/0".into();
        assert!(matches!(
            config.validate_runtime_safety(false),
            Err(ConfigValidationError::LocalhostConnection(name)) if name == "REDIS_URL"
        ));
    }

    #[test]
    fn runtime_validation_rejects_unsafe_cors_origin_and_wildcard() {
        let mut config = valid_runtime_config();
        config.cors.allowed_origins = vec!["*".into()];
        assert!(matches!(
            config.validate_runtime_safety(false),
            Err(ConfigValidationError::CorsWildcard)
        ));

        config.cors.allowed_origins = vec!["http://admin.example.invalid".into()];
        assert!(matches!(
            config.validate_runtime_safety(false),
            Err(ConfigValidationError::CorsOriginUnsafe)
        ));
    }

    #[test]
    fn runtime_validation_accepts_safe_explicit_origin() {
        let config = valid_runtime_config();
        assert!(config.validate_runtime_safety(false).is_ok());
    }

    /// Redis-free 默认路径：redis_url 允许为空（strict MySQL 会话判定），
    /// 兼容 adapter 保持 default-off。
    #[test]
    fn runtime_validation_allows_empty_redis_url_when_compat_disabled() {
        let mut config = valid_runtime_config();
        config.redis_url.clear();
        config.redis_projection_compat_enabled = false;
        assert!(config.validate_runtime_safety(false).is_ok());
    }

    /// Redis 兼容 adapter 是显式 opt-in：开启时 redis_url 为空必须启动失败
    /// （fail-closed，禁止"半开"配置在签发/撤销路径悄悄跳过投影）。
    #[test]
    fn runtime_validation_rejects_compat_enabled_without_redis_url() {
        let mut config = valid_runtime_config();
        config.redis_url.clear();
        config.redis_projection_compat_enabled = true;
        assert!(matches!(
            config.validate_runtime_safety(false),
            Err(ConfigValidationError::RedisCompatRequiresUrl)
        ));
        // 配齐 redis_url 后：仅当二进制编译了 `redis-compat` feature 才合法
        // （feature-off 构建命中集中 refusal，见
        // `runtime_validation_rejects_compat_enabled_without_redis_compat_feature`）。
        config.redis_url = "redis://cache.example.invalid:6379/0".into();
        #[cfg(feature = "redis-compat")]
        assert!(config.validate_runtime_safety(false).is_ok());
        #[cfg(not(feature = "redis-compat"))]
        assert!(matches!(
            config.validate_runtime_safety(false),
            Err(ConfigValidationError::RedisCompatRequiresFeatureBuild)
        ));
    }

    /// redis 编译层退役收口（redis-layer-retirement-20261002）：compat 旗标
    /// 开启 + redis_url 配齐，但二进制未编译 `redis-compat` feature → 启动
    /// 必须明确拒绝，绝不静默 Redis-free 化（fail-closed）。
    #[test]
    fn runtime_validation_rejects_compat_enabled_without_redis_compat_feature() {
        let mut config = valid_runtime_config();
        config.redis_url = "redis://cache.example.invalid:6379/0".into();
        config.redis_projection_compat_enabled = true;
        #[cfg(not(feature = "redis-compat"))]
        assert!(matches!(
            config.validate_runtime_safety(false),
            Err(ConfigValidationError::RedisCompatRequiresFeatureBuild)
        ));
        #[cfg(feature = "redis-compat")]
        assert!(config.validate_runtime_safety(false).is_ok());
    }

    /// 宿主能力门（混合 feature 收口）：`validate_redis_adapter_support` 是
    /// 纯函数，宿主以**自身 crate** 的 `cfg!(feature = "redis-compat")` 断言
    /// adapter 编译能力。workspace feature 统一会让 astral-common 的零依赖
    /// marker 在宿主未编译 adapter 时也为真——本测试二进制本身可能带
    /// redis-compat 编译（marker on），`adapter_compiled=false` 也必须被拒绝；
    /// `adapter_compiled=true`（marker 支持）放行；旗标关闭（Redis-free 默认）
    /// 恒放行。断言不依赖任何 cfg 分支，双模式（marker on/off）语义一致。
    #[test]
    fn redis_adapter_support_is_pure_and_mixed_feature_safe() {
        let mut config = valid_runtime_config();
        config.redis_url = "redis://cache.example.invalid:6379/0".into();
        config.redis_projection_compat_enabled = true;

        // 旗标开启 + 宿主 adapter 未编译 → 显式拒绝（fail-closed，非 log-only）。
        assert!(matches!(
            config.validate_redis_adapter_support(false),
            Err(ConfigValidationError::RedisCompatRequiresFeatureBuild)
        ));
        // 旗标开启 + 宿主 adapter 已编译（marker 支持）→ 放行。
        assert!(config.validate_redis_adapter_support(true).is_ok());

        // 旗标关闭（Redis-free 默认）→ 编译与否都放行。
        config.redis_projection_compat_enabled = false;
        assert!(config.validate_redis_adapter_support(false).is_ok());
        assert!(config.validate_redis_adapter_support(true).is_ok());
    }

    #[test]
    fn runtime_validation_allows_local_test_fixture_only_in_test_profile() {
        let mut config = valid_runtime_config();
        config.database_url = "mysql://localhost:3306/astral_test".into();
        config.redis_url = "redis://localhost:6379/0".into();
        config.rabbitmq_url = "amqp://localhost:5672/%2f".into();
        config.cors.allowed_origins = vec!["http://localhost:5173".into()];
        config.cors.allow_credentials = true;
        assert!(config.validate_runtime_safety(true).is_ok());
    }

    /// 连接池配置解析：env 覆盖 > 字段 > 默认（env 未设置 + 字段 0 =
    /// derive(Default) 的未配置态 → 回落默认）；非法 env 一律 Err（fail-fast）。
    ///
    /// env 变量是进程全局的：本测试与 flat env 契约测试共用
    /// [`env_contract_test_lock`] 串行执行，所有 set/remove 都在锁内完成，
    /// 避免并行互扰。
    #[test]
    fn db_pool_config_resolution_prefers_env_then_field_then_default() {
        let _env_lock = env_contract_test_lock();
        let config = AppConfig::default();
        std::env::remove_var("ASTRAL_DB_MAX_CONNECTIONS");
        std::env::remove_var("ASTRAL_DB_ACQUIRE_TIMEOUT_SECS");

        // env 未设置 + 字段未配置 → 默认 80 / 5s。
        assert_eq!(config.resolved_db_max_connections().unwrap(), 80);
        assert_eq!(
            config.resolved_db_acquire_timeout().unwrap(),
            Duration::from_secs(5)
        );

        // env 未设置 + 字段已配置 → 字段值。
        let configured = AppConfig {
            db_max_connections: 120,
            db_acquire_timeout_seconds: 3,
            ..Default::default()
        };
        assert_eq!(configured.resolved_db_max_connections().unwrap(), 120);
        assert_eq!(
            configured.resolved_db_acquire_timeout().unwrap(),
            Duration::from_secs(3)
        );

        // env 覆盖字段值。
        std::env::set_var("ASTRAL_DB_MAX_CONNECTIONS", "64");
        std::env::set_var("ASTRAL_DB_ACQUIRE_TIMEOUT_SECS", "2");
        assert_eq!(config.resolved_db_max_connections().unwrap(), 64);
        assert_eq!(
            config.resolved_db_acquire_timeout().unwrap(),
            Duration::from_secs(2)
        );

        // 非法 env（非数字 / 0）→ Err，绝不静默回落（fail-open 会掩盖配置错误）。
        std::env::set_var("ASTRAL_DB_MAX_CONNECTIONS", "zero");
        assert!(config.resolved_db_max_connections().is_err());
        std::env::set_var("ASTRAL_DB_MAX_CONNECTIONS", "0");
        assert!(config.resolved_db_max_connections().is_err());
        std::env::set_var("ASTRAL_DB_ACQUIRE_TIMEOUT_SECS", "0");
        assert!(config.resolved_db_acquire_timeout().is_err());

        std::env::remove_var("ASTRAL_DB_MAX_CONNECTIONS");
        std::env::remove_var("ASTRAL_DB_ACQUIRE_TIMEOUT_SECS");
    }

    // ---- ORG_SCOPE 部署旗标共享解析器（default-off parity 契约钉子） -------
    // 所有 PolicyEngine 宿主（trustgraph / identity / monitor）共用本解析器：
    // 同一受管租户在任何宿主的 org_scope 准入判定必须一致，绝不允许一个宿主
    // 准入、另一个宿主以 ORG_AUTHORITY_DISABLED 拒绝（split-brain）。

    #[test]
    fn org_scope_flag_parser_is_strict_and_default_off() {
        // unset / 空白 / "false"（trim 后）→ false（default-off，绝不报错）。
        assert!(!parse_org_scope_enabled(None).unwrap());
        assert!(!parse_org_scope_enabled(Some("")).unwrap());
        assert!(!parse_org_scope_enabled(Some("   ")).unwrap());
        assert!(!parse_org_scope_enabled(Some("false")).unwrap());
        assert!(!parse_org_scope_enabled(Some(" false ")).unwrap());
        // "true"（trim 后精确匹配）→ true。
        assert!(parse_org_scope_enabled(Some("true")).unwrap());
        assert!(parse_org_scope_enabled(Some("  true ")).unwrap());
        // 其他任何非空值一律 Err（区分大小写；绝不静默降级）。
        for garbage in ["True", "TRUE", "1", "0", "yes", "on", "enabled"] {
            assert!(
                parse_org_scope_enabled(Some(garbage)).is_err(),
                "invalid value {garbage:?} must fail closed"
            );
        }
        let error = parse_org_scope_enabled(Some("True")).unwrap_err();
        assert!(matches!(
            error,
            ConfigValidationError::InvalidOrgScopeEnabled
        ));
        // 错误信息只含变量名与期望格式，不回显覆盖值。
        let rendered = error.to_string();
        assert!(rendered.contains("ASTRAL_ORG_SCOPE_ENABLED"));
        assert!(!rendered.contains("True"));
    }

    /// env 读取版与纯解析器同契约；env 是进程全局的，与 flat env 契约测试共用
    /// [`env_contract_test_lock`] 串行执行。
    #[test]
    fn org_scope_flag_from_env_is_strict_and_default_off() {
        let _env_lock = env_contract_test_lock();
        std::env::remove_var(ORG_SCOPE_ENABLED_ENV);
        assert!(!org_scope_enabled_from_env().unwrap());
        std::env::set_var(ORG_SCOPE_ENABLED_ENV, "true");
        assert!(org_scope_enabled_from_env().unwrap());
        std::env::set_var(ORG_SCOPE_ENABLED_ENV, "false");
        assert!(!org_scope_enabled_from_env().unwrap());
        std::env::set_var(ORG_SCOPE_ENABLED_ENV, "maybe");
        assert!(org_scope_enabled_from_env().is_err());
        std::env::remove_var(ORG_SCOPE_ENABLED_ENV);
    }

    // ---- Redis 会话投影兼容旗标共享契约（中心解析器 + 冻结安装） ------------

    /// 中心解析器（libs 与 env 覆盖共用一份语义）：unset/空白/false → false
    /// （default-off）；"true" → true（trim + ASCII 大小写不敏感，对齐
    /// `apply_flat_env_overrides` 的既有契约）；其他任何非空值 fail-closed
    /// Err，错误信息只含变量名与期望格式，不回显值。
    #[test]
    fn redis_projection_compat_flag_parser_is_strict_and_default_off() {
        assert!(!parse_redis_projection_compat(None).unwrap());
        assert!(!parse_redis_projection_compat(Some("")).unwrap());
        assert!(!parse_redis_projection_compat(Some("   ")).unwrap());
        assert!(!parse_redis_projection_compat(Some("false")).unwrap());
        assert!(!parse_redis_projection_compat(Some(" False ")).unwrap());
        assert!(parse_redis_projection_compat(Some("true")).unwrap());
        assert!(parse_redis_projection_compat(Some(" TRUE ")).unwrap());
        for garbage in ["1", "0", "yes", "on", "enabled"] {
            assert!(
                parse_redis_projection_compat(Some(garbage)).is_err(),
                "invalid value {garbage:?} must fail closed"
            );
        }
        let error = parse_redis_projection_compat(Some("maybe")).unwrap_err();
        assert!(matches!(
            error,
            ConfigValidationError::InvalidRedisProjectionCompat
        ));
        let rendered = error.to_string();
        assert!(rendered.contains("ASTRAL_REDIS_PROJECTION_COMPAT"));
        assert!(!rendered.contains("maybe"));
    }

    /// 进程级唯一冻结槽契约：first-wins、同值幂等、对槽内任何先到异值冻结
    /// （其他安装器或 legacy env 回落读）冲突拒绝（fail-closed，组合进程内
    /// 所有宿主安装器必须一致，且不得在读方背后改写已发布答案）。OnceLock
    /// 是进程全局的：本测试是该二进制内唯一安装方，以 false 先冻结（若 env
    /// 回落读测试先运行，冻结值同为 false，断言在两种顺序下均成立），在
    /// 同一序列内覆盖三分支。
    #[test]
    fn redis_projection_compat_install_is_first_wins_identical_idempotent_and_conflict_refusing() {
        // first-wins / 同值幂等：首次冻结 false（Redis-free 默认值）后，
        // 同值重复安装幂等（组合进程成员宿主逐个安装同一份已校验值）。
        assert!(install_redis_projection_compat(false).is_ok());
        assert!(install_redis_projection_compat(false).is_ok());
        // 异值冲突拒绝启动，绝不静默采纳后来者。
        assert!(matches!(
            install_redis_projection_compat(true),
            Err(ConfigValidationError::RedisCompatFreezeConflict)
        ));
        // 冻结读返回首次冻结值（即便 env 声称相反值也不回落）。
        assert!(!redis_projection_compat_frozen());
    }

    /// legacy/lib 的单槽 env 回落读：unset → false（default-off），非法值一律
    /// false（fail-closed，绝不静默开启，无网络），并填充唯一冻结槽（此后
    /// 安装器异值必冲突，见安装契约测试）。OnceLock 进程全局：本测试在锁内
    /// 清空 env 后读取，env 派生值确定为 false；若安装测试先运行，槽内同为
    /// false，断言在两种顺序下均成立。
    #[test]
    fn redis_projection_compat_env_frozen_read_defaults_closed_on_invalid_env() {
        let _env_lock = env_contract_test_lock();
        std::env::remove_var(REDIS_PROJECTION_COMPAT_ENV);
        assert!(!redis_projection_compat_from_env_frozen());
        // 与配置加载路径互补：本冻结读对非法值降级 false（libs 无启动失败
        // 通道），宿主配置校验仍以 fail-fast 拒绝（见 flat env 契约测试）。
    }

    /// 宿主启动期把已校验旗标冻结进配置：env 缺失 → false；env "true" →
    /// true；env 非法 → 配置加载失败（启动拒绝，fail-fast，错误只含变量名，
    /// 不回显值）。这条 env 契约经中心解析器与 libs 冻结读共享同一语义。
    #[test]
    fn app_config_freezes_redis_projection_compat_flag_parsed_once_at_startup() {
        let guard = FlatEnvGuard::acquire();
        guard.set(
            "DATABASE_URL",
            "mysql://db.example.invalid:3306/astral_test",
        );
        guard.set("RABBITMQ_URL", "amqps://mq.example.invalid:5671/%2f");
        guard.set(
            "JWT_ACCESS_SECRET",
            "dist-access-override-secret-0123456789abcdef",
        );
        guard.set(
            "JWT_REFRESH_SECRET",
            "dist-refresh-override-secret-0123456789abcdef",
        );
        guard.set("JWT_ACCESS_ISSUER", "dist-test-access-issuer");
        guard.set("JWT_REFRESH_ISSUER", "dist-test-refresh-issuer");
        guard.set("JWT_ACCESS_AUDIENCE", "dist-test-astral-api");
        guard.set("JWT_REFRESH_AUDIENCE", "dist-test-astral-session");
        guard.set(
            "INTERNAL_SERVICE_SECRET",
            "internal-lg-override-secret-0123456789",
        );
        guard.set("CORS_ALLOWED_ORIGINS", "https://console.example.invalid");

        // env 缺失 → default-off（redis_url 允许为空，Redis-free 默认路径）。
        let config = AppConfig::from_files_for(
            "astral-common-redis-compat-contract-no-such-file",
            JwtValidationRole::Learn,
        )
        .expect("file-less node without the compat flag must pass validation");
        assert!(!config.redis_projection_compat_enabled);

        // env 非法 → fail-fast（启动拒绝），且错误不得回显覆盖值。
        guard.set(REDIS_PROJECTION_COMPAT_ENV, "maybe");
        let error = AppConfig::from_files_for(
            "astral-common-redis-compat-contract-no-such-file",
            JwtValidationRole::Learn,
        )
        .expect_err("invalid compat flag must fail closed");
        let rendered = error.to_string();
        assert!(rendered.contains("ASTRAL_REDIS_PROJECTION_COMPAT"));
        assert!(!rendered.contains("maybe"), "错误信息不得回显覆盖值");
    }

    // ---- 单机镜像加速器默认语义（composite zero-DB 目标闭合） --------------

    /// 字段默认 true（serde 标量 default fn + Default impl 同源）：未配置即
    /// "愿意安装"，组合进程 zero-DB 目标默认闭合；运行期仍有 composite+hub+
    /// lease 强门，独立多写者 warn 后保持 DenyOnly（无害降级）。
    #[test]
    fn session_grant_mirror_defaults_enabled() {
        assert!(AppConfig::default().session_grant_mirror_enabled);
        let config = valid_runtime_config();
        assert!(config.session_grant_mirror_enabled);
        // positive cache 旁路开关保持 default-off（不随默认翻转）。
        assert!(!AppConfig::default().session_grant_mirror_positive_disabled);
    }

    /// 显式 opt-out 契约：env `ASTRAL_SESSION_GRANT_MIRROR_ENABLED=false` 必须
    /// 覆盖默认 true（"未配置才默认"，绝不默默覆盖显式值）；显式 "true" 保持
    /// true；非法值启动失败（严格 bool 契约不变，错误不回显值）。
    #[test]
    fn session_grant_mirror_explicit_env_opt_out_overrides_default() {
        let guard = FlatEnvGuard::acquire();
        guard.set(
            "DATABASE_URL",
            "mysql://db.example.invalid:3306/astral_test",
        );
        guard.set("RABBITMQ_URL", "amqps://mq.example.invalid:5671/%2f");
        guard.set(
            "JWT_ACCESS_SECRET",
            "dist-access-override-secret-0123456789abcdef",
        );
        guard.set(
            "JWT_REFRESH_SECRET",
            "dist-refresh-override-secret-0123456789abcdef",
        );
        guard.set("JWT_ACCESS_ISSUER", "dist-test-access-issuer");
        guard.set("JWT_REFRESH_ISSUER", "dist-test-refresh-issuer");
        guard.set("JWT_ACCESS_AUDIENCE", "dist-test-astral-api");
        guard.set("JWT_REFRESH_AUDIENCE", "dist-test-astral-session");
        guard.set(
            "INTERNAL_SERVICE_SECRET",
            "internal-lg-override-secret-0123456789",
        );
        guard.set("CORS_ALLOWED_ORIGINS", "https://console.example.invalid");

        guard.set(SESSION_GRANT_MIRROR_ENV, "false");
        let config = AppConfig::from_files_for(
            "astral-common-mirror-contract-no-such-file",
            JwtValidationRole::Learn,
        )
        .expect("explicit mirror opt-out must pass validation");
        assert!(!config.session_grant_mirror_enabled);

        guard.set(SESSION_GRANT_MIRROR_ENV, "true");
        let config = AppConfig::from_files_for(
            "astral-common-mirror-contract-no-such-file",
            JwtValidationRole::Learn,
        )
        .expect("explicit mirror opt-in must pass validation");
        assert!(config.session_grant_mirror_enabled);

        guard.set(SESSION_GRANT_MIRROR_ENV, "maybe");
        let error = AppConfig::from_files_for(
            "astral-common-mirror-contract-no-such-file",
            JwtValidationRole::Learn,
        )
        .expect_err("invalid mirror flag must fail closed");
        let rendered = error.to_string();
        assert!(rendered.contains("ASTRAL_SESSION_GRANT_MIRROR_ENABLED"));
        assert!(!rendered.contains("maybe"), "错误信息不得回显覆盖值");
    }

    /// YAML 显式 `false` 同样必须覆盖默认 true（serde 标量 default fn：
    /// "未配置才默认"同时覆盖 env 与文件两条显式路径）。
    #[test]
    fn session_grant_mirror_explicit_yaml_false_overrides_default() {
        let guard = FlatEnvGuard::acquire();
        let yaml_path = std::env::temp_dir().join(format!(
            "astral-common-mirror-yaml-contract-{}.yaml",
            std::process::id()
        ));
        fs::write(
            &yaml_path,
            r#"session_grant_mirror_enabled: false
redis_url: "redis://yaml-fallback.example.invalid:6379/0"
jwt:
  access:
    issuer: "yaml-access-issuer"
    audience: "yaml-access-audience"
  refresh:
    issuer: "yaml-refresh-issuer"
    audience: "yaml-refresh-audience"
cors:
  allowed_origins:
    - "https://yaml-origin.example.invalid"
"#,
        )
        .expect("write temporary config fixture");
        let yaml_stem = yaml_path.with_extension("").to_string_lossy().into_owned();
        guard.set(
            "DATABASE_URL",
            "mysql://db.example.invalid:3306/astral_test",
        );
        guard.set("RABBITMQ_URL", "amqps://mq.example.invalid:5671/%2f");
        guard.set(
            "JWT_ACCESS_SECRET",
            "dist-access-override-secret-0123456789abcdef",
        );
        guard.set(
            "JWT_REFRESH_SECRET",
            "dist-refresh-override-secret-0123456789abcdef",
        );
        guard.set(
            "INTERNAL_SERVICE_SECRET",
            "internal-lg-override-secret-0123456789",
        );

        let config = AppConfig::from_files_for(&yaml_stem, JwtValidationRole::Learn)
            .expect("yaml explicit mirror opt-out must pass Learn validation");
        let _ = fs::remove_file(&yaml_path);
        assert!(
            !config.session_grant_mirror_enabled,
            "explicit YAML false must override the default-on field"
        );
    }

    /// AppConfig 在启动期把 ORG_SCOPE 旗标一次性解析并冻结进配置：
    /// env 缺失 → default false；env "true" → true；env 非法 → 配置加载失败
    /// （启动拒绝，fail-fast；错误只含变量名与期望格式，不回显值）。
    #[test]
    fn app_config_freezes_org_scope_flag_parsed_once_at_startup() {
        let guard = FlatEnvGuard::acquire();
        guard.set(
            "DATABASE_URL",
            "mysql://db.example.invalid:3306/astral_test",
        );
        guard.set("REDIS_URL", "redis://cache.example.invalid:6379/0");
        guard.set("RABBITMQ_URL", "amqps://mq.example.invalid:5671/%2f");
        guard.set(
            "JWT_ACCESS_SECRET",
            "dist-access-override-secret-0123456789abcdef",
        );
        guard.set(
            "JWT_REFRESH_SECRET",
            "dist-refresh-override-secret-0123456789abcdef",
        );
        guard.set("JWT_ACCESS_ISSUER", "dist-test-access-issuer");
        guard.set("JWT_REFRESH_ISSUER", "dist-test-refresh-issuer");
        guard.set("JWT_ACCESS_AUDIENCE", "dist-test-astral-api");
        guard.set("JWT_REFRESH_AUDIENCE", "dist-test-astral-session");
        guard.set(
            "GATEWAY_HMAC_SECRET",
            "gateway-hmac-override-secret-0123456789",
        );
        guard.set(
            "INTERNAL_SERVICE_SECRET",
            "internal-lg-override-secret-0123456789",
        );
        guard.set(
            "GATEWAY_INTERNAL_SERVICE_SECRET",
            "gateway-internal-gi-override-secret-0123456",
        );
        guard.set("CORS_ALLOWED_ORIGINS", "https://console.example.invalid");
        guard.set("CORS_ALLOW_CREDENTIALS", "false");

        // env 缺失 → default-off。
        let config = AppConfig::from_files_for(
            "astral-common-org-scope-contract-no-such-file",
            JwtValidationRole::Learn,
        )
        .expect("file-less node without the org flag must pass validation");
        assert!(!config.org_scope_enabled);

        // env "true" → 冻结 true。
        guard.set(ORG_SCOPE_ENABLED_ENV, "true");
        let config = AppConfig::from_files_for(
            "astral-common-org-scope-contract-no-such-file",
            JwtValidationRole::Learn,
        )
        .expect("explicit org flag must freeze into config");
        assert!(config.org_scope_enabled);

        // env 非法 → fail-fast（启动拒绝），且错误不得回显覆盖值。
        guard.set(ORG_SCOPE_ENABLED_ENV, "maybe");
        let error = AppConfig::from_files_for(
            "astral-common-org-scope-contract-no-such-file",
            JwtValidationRole::Learn,
        )
        .expect_err("invalid org flag must fail closed");
        let rendered = error.to_string();
        assert!(rendered.contains("ASTRAL_ORG_SCOPE_ENABLED"));
        assert!(!rendered.contains("maybe"), "错误信息不得回显覆盖值");
    }

    /// 旗标只认 env 严格契约：YAML 即使写 `org_scope_enabled: true` 也不生效
    /// （`#[serde(skip)]`），防止绕过共享解析器静默开启组织准入。
    #[test]
    fn app_config_org_scope_flag_is_env_only_yaml_cannot_enable() {
        let guard = FlatEnvGuard::acquire();
        let yaml_path = std::env::temp_dir().join(format!(
            "astral-common-org-scope-yaml-contract-{}.yaml",
            std::process::id()
        ));
        fs::write(
            &yaml_path,
            r#"org_scope_enabled: true
redis_url: "redis://yaml-fallback.example.invalid:6379/0"
jwt:
  access:
    issuer: "yaml-access-issuer"
    audience: "yaml-access-audience"
  refresh:
    issuer: "yaml-refresh-issuer"
    audience: "yaml-refresh-audience"
cors:
  allowed_origins:
    - "https://yaml-origin.example.invalid"
"#,
        )
        .expect("write temporary config fixture");
        let yaml_stem = yaml_path.with_extension("").to_string_lossy().into_owned();
        guard.set(
            "DATABASE_URL",
            "mysql://db.example.invalid:3306/astral_test",
        );
        guard.set("RABBITMQ_URL", "amqps://mq.example.invalid:5671/%2f");
        guard.set(
            "JWT_ACCESS_SECRET",
            "dist-access-override-secret-0123456789abcdef",
        );
        guard.set(
            "JWT_REFRESH_SECRET",
            "dist-refresh-override-secret-0123456789abcdef",
        );
        guard.set(
            "INTERNAL_SERVICE_SECRET",
            "internal-lg-override-secret-0123456789",
        );

        let config = AppConfig::from_files_for(&yaml_stem, JwtValidationRole::Learn)
            .expect("yaml fallback must pass Learn validation");
        let _ = fs::remove_file(&yaml_path);
        assert!(
            !config.org_scope_enabled,
            "YAML must not be able to enable the org scope flag; only the strict env contract may"
        );
    }

    /// HIGH-1 缺陷回归：config-rs 以 `_` 为层级分隔符，flat 部署名
    /// （`DATABASE_URL` 等）无法命中 serde 扁平字段，且远程部署目录没有
    /// application.yml，节点因此启动即退出。本用例证明：无任何配置文件时，
    /// 显式 flat env 契约即可提供全部启动字段并通过 Learn 角色的完整启动
    /// 校验（secret 长度/占位符、issuer 元数据、URL scheme/主机、CORS 策略）。
    #[test]
    fn flat_env_config_overrides_reach_fields_and_fileless_learn_validation_passes() {
        let guard = FlatEnvGuard::acquire();
        guard.set(
            "DATABASE_URL",
            "mysql://db.example.invalid:3306/astral_test",
        );
        guard.set("REDIS_URL", "redis://cache.example.invalid:6379/0");
        guard.set("RABBITMQ_URL", "amqps://mq.example.invalid:5671/%2f");
        guard.set(
            "JWT_ACCESS_SECRET",
            "dist-access-override-secret-0123456789abcdef",
        );
        guard.set(
            "JWT_REFRESH_SECRET",
            "dist-refresh-override-secret-0123456789abcdef",
        );
        guard.set("JWT_ACCESS_ISSUER", "dist-test-access-issuer");
        guard.set("JWT_REFRESH_ISSUER", "dist-test-refresh-issuer");
        guard.set("JWT_ACCESS_AUDIENCE", "dist-test-astral-api");
        guard.set("JWT_REFRESH_AUDIENCE", "dist-test-astral-session");
        guard.set(
            "GATEWAY_HMAC_SECRET",
            "gateway-hmac-override-secret-0123456789",
        );
        guard.set(
            "INTERNAL_SERVICE_SECRET",
            "internal-lg-override-secret-0123456789",
        );
        guard.set(
            "GATEWAY_INTERNAL_SERVICE_SECRET",
            "gateway-internal-gi-override-secret-0123456",
        );
        guard.set("SESSION_GRANT_CLAIMS_MODE", "REQUIRE");
        guard.set(
            "CORS_ALLOWED_ORIGINS",
            "https://console.example.invalid, https://admin.example.invalid",
        );
        guard.set("CORS_ALLOW_CREDENTIALS", "true");

        let config = AppConfig::from_files_for(
            "astral-common-flat-env-contract-no-such-file",
            JwtValidationRole::Learn,
        )
        .expect("file-less node with the explicit flat env contract must pass Learn validation");

        assert_eq!(
            config.database_url,
            "mysql://db.example.invalid:3306/astral_test"
        );
        assert_eq!(config.redis_url, "redis://cache.example.invalid:6379/0");
        assert_eq!(config.rabbitmq_url, "amqps://mq.example.invalid:5671/%2f");
        assert_eq!(
            config.jwt.access.secret,
            "dist-access-override-secret-0123456789abcdef"
        );
        assert_eq!(
            config.jwt.refresh.secret,
            "dist-refresh-override-secret-0123456789abcdef"
        );
        assert_ne!(
            config.jwt.access.secret, config.jwt.refresh.secret,
            "access 与 refresh 签名材料必须相互独立"
        );
        assert_eq!(config.jwt.access.issuer, "dist-test-access-issuer");
        assert_eq!(config.jwt.refresh.issuer, "dist-test-refresh-issuer");
        assert_eq!(config.jwt.access.audience, "dist-test-astral-api");
        assert_eq!(config.jwt.refresh.audience, "dist-test-astral-session");
        assert_eq!(
            config.gateway.hmac_secret,
            "gateway-hmac-override-secret-0123456789"
        );
        assert_eq!(
            config.internal_service_secret,
            "internal-lg-override-secret-0123456789"
        );
        assert_eq!(
            config.gateway.internal_service_secret,
            "gateway-internal-gi-override-secret-0123456"
        );
        assert_eq!(config.session_grant_claims_mode, "REQUIRE");
        assert_eq!(
            config.cors.allowed_origins,
            vec![
                "https://console.example.invalid".to_string(),
                "https://admin.example.invalid".to_string()
            ]
        );
        assert!(config.cors.allow_credentials);
    }

    /// typed 覆盖（bool/list）非法值必须 fail-fast 返回配置错误，且错误信息
    /// 只包含变量名与期望格式，绝不回显覆盖值。解析在启动校验之前执行，
    /// 因此 typed 错误优先于任何字段缺失类校验错误出现。
    #[test]
    fn flat_env_config_malformed_bool_and_list_overrides_fail_closed() {
        let guard = FlatEnvGuard::acquire();

        guard.set("CORS_ALLOW_CREDENTIALS", "maybe");
        let error = AppConfig::from_files_for(
            "astral-common-flat-env-contract-no-such-file",
            JwtValidationRole::Learn,
        )
        .expect_err("malformed bool override must fail closed");
        let rendered = error.to_string();
        assert!(rendered.contains("CORS_ALLOW_CREDENTIALS"));
        assert!(!rendered.contains("maybe"), "错误信息不得回显覆盖值");

        guard.set("CORS_ALLOW_CREDENTIALS", "false");
        guard.set(
            "CORS_ALLOWED_ORIGINS",
            "https://a.example.invalid,,https://b.example.invalid",
        );
        let error = AppConfig::from_files_for(
            "astral-common-flat-env-contract-no-such-file",
            JwtValidationRole::Learn,
        )
        .expect_err("empty origin entry must fail closed");
        assert!(error.to_string().contains("CORS_ALLOWED_ORIGINS"));
    }

    /// 覆盖缺失时必须保留 application.yml 中的既有值；只有实际存在的 env
    /// 才覆盖对应字段（partial override 语义）。
    #[test]
    fn flat_env_config_preserves_application_yaml_values_when_overrides_absent() {
        let guard = FlatEnvGuard::acquire();
        let yaml_path = std::env::temp_dir().join(format!(
            "astral-common-config-contract-yaml-{}.yaml",
            std::process::id()
        ));
        fs::write(
            &yaml_path,
            r#"redis_url: "redis://yaml-fallback.example.invalid:6379/0"
jwt:
  access:
    issuer: "yaml-access-issuer"
    audience: "yaml-access-audience"
  refresh:
    issuer: "yaml-refresh-issuer"
    audience: "yaml-refresh-audience"
cors:
  allowed_origins:
    - "https://yaml-origin.example.invalid"
  allow_credentials: true
"#,
        )
        .expect("write temporary config fixture");
        let yaml_stem = yaml_path.with_extension("").to_string_lossy().into_owned();

        guard.set(
            "DATABASE_URL",
            "mysql://db.example.invalid:3306/astral_test",
        );
        guard.set("RABBITMQ_URL", "amqps://mq.example.invalid:5671/%2f");
        guard.set(
            "JWT_ACCESS_SECRET",
            "dist-access-override-secret-0123456789abcdef",
        );
        guard.set(
            "JWT_REFRESH_SECRET",
            "dist-refresh-override-secret-0123456789abcdef",
        );
        guard.set(
            "INTERNAL_SERVICE_SECRET",
            "internal-lg-override-secret-0123456789",
        );

        let config = AppConfig::from_files_for(&yaml_stem, JwtValidationRole::Learn)
            .expect("yaml fallback + partial env overrides must pass Learn validation");
        let _ = fs::remove_file(&yaml_path);

        // env 未覆盖的字段保留 YAML 值。
        assert_eq!(
            config.redis_url,
            "redis://yaml-fallback.example.invalid:6379/0"
        );
        assert_eq!(config.jwt.access.issuer, "yaml-access-issuer");
        assert_eq!(config.jwt.refresh.issuer, "yaml-refresh-issuer");
        assert_eq!(config.jwt.access.audience, "yaml-access-audience");
        assert_eq!(config.jwt.refresh.audience, "yaml-refresh-audience");
        assert_eq!(
            config.cors.allowed_origins,
            vec!["https://yaml-origin.example.invalid".to_string()]
        );
        assert!(config.cors.allow_credentials);
        // env 覆盖的字段优先于 YAML。
        assert_eq!(
            config.database_url,
            "mysql://db.example.invalid:3306/astral_test"
        );
        assert_eq!(config.rabbitmq_url, "amqps://mq.example.invalid:5671/%2f");
        assert_eq!(
            config.jwt.access.secret,
            "dist-access-override-secret-0123456789abcdef"
        );
        assert_eq!(
            config.jwt.refresh.secret,
            "dist-refresh-override-secret-0123456789abcdef"
        );
    }

    /// `from_env_for` 与 `from_files_for` 应用同一份 flat 覆盖契约；Gateway
    /// 角色的三把密钥（Gateway HMAC、K_LG、K_GI）都必须从各自独立 env 名
    /// 落位，绝不允许共用一个变量。
    #[test]
    fn flat_env_config_from_env_for_applies_overrides_for_gateway_role() {
        let guard = FlatEnvGuard::acquire();
        guard.set(
            "DATABASE_URL",
            "mysql://db.example.invalid:3306/astral_test",
        );
        guard.set("REDIS_URL", "redis://cache.example.invalid:6379/0");
        guard.set("RABBITMQ_URL", "amqps://mq.example.invalid:5671/%2f");
        guard.set(
            "JWT_ACCESS_SECRET",
            "dist-access-override-secret-0123456789abcdef",
        );
        guard.set(
            "JWT_REFRESH_SECRET",
            "dist-refresh-override-secret-0123456789abcdef",
        );
        guard.set("JWT_ACCESS_ISSUER", "dist-test-access-issuer");
        guard.set("JWT_REFRESH_ISSUER", "dist-test-refresh-issuer");
        guard.set("JWT_ACCESS_AUDIENCE", "dist-test-astral-api");
        guard.set("JWT_REFRESH_AUDIENCE", "dist-test-astral-session");
        guard.set(
            "GATEWAY_HMAC_SECRET",
            "gateway-hmac-override-secret-0123456789",
        );
        guard.set(
            "INTERNAL_SERVICE_SECRET",
            "internal-lg-override-secret-0123456789",
        );
        guard.set(
            "GATEWAY_INTERNAL_SERVICE_SECRET",
            "gateway-internal-gi-override-secret-0123456",
        );
        guard.set("CORS_ALLOWED_ORIGINS", "https://console.example.invalid");
        guard.set("CORS_ALLOW_CREDENTIALS", "false");

        let config = AppConfig::from_env_for(JwtValidationRole::Gateway)
            .expect("gateway role with the explicit flat env contract must pass validation");

        assert_eq!(
            config.gateway.hmac_secret,
            "gateway-hmac-override-secret-0123456789"
        );
        assert_eq!(
            config.internal_service_secret,
            "internal-lg-override-secret-0123456789"
        );
        assert_eq!(
            config.gateway.internal_service_secret,
            "gateway-internal-gi-override-secret-0123456"
        );
        assert_eq!(
            config.jwt.access.secret,
            "dist-access-override-secret-0123456789abcdef"
        );
        assert_eq!(
            config.jwt.refresh.secret,
            "dist-refresh-override-secret-0123456789abcdef"
        );
        assert_ne!(config.jwt.access.secret, config.jwt.refresh.secret);
        assert_eq!(
            config.cors.allowed_origins,
            vec!["https://console.example.invalid".to_string()]
        );
        assert!(!config.cors.allow_credentials);
    }
}
