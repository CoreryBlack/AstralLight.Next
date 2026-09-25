//! 配置加载
//!
//! 通过 config-rs 从环境变量 + YAML fallback 加载配置。
//! 优先级：环境变量 > YAML > 默认值。

use axum::http::Uri;
use serde::Deserialize;
use std::fs;
use std::net::IpAddr;
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
    #[error("ASTRAL_ORG_SCOPE_ENABLED must be exactly \"true\" or \"false\" (default off)")]
    InvalidOrgScopeEnabled,
}

impl ConfigValidationError {
    fn into_config_error(self) -> config::ConfigError {
        config::ConfigError::Foreign(Box::new(self))
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
#[derive(Debug, Clone, Default, Deserialize)]
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

    #[serde(default)]
    pub wechat: WeChatConfig,
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
        // 将 redis_url 同步到 REDIS_URL 环境变量，供 MQ consumer 等非 AppConfig 场景使用
        if std::env::var("REDIS_URL").is_err() {
            std::env::set_var("REDIS_URL", &cfg.redis_url);
        }
        Ok(cfg)
    }

    /// Token v2 requires all session grants, including app-session grants.
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

    fn validate_runtime_safety(&self, test_profile: bool) -> Result<(), ConfigValidationError> {
        validate_connection_url("DATABASE_URL", &self.database_url, &["mysql"], test_profile)?;
        validate_connection_url("REDIS_URL", &self.redis_url, &["redis"], test_profile)?;
        validate_connection_url(
            "RABBITMQ_URL",
            &self.rabbitmq_url,
            &["amqp", "amqps"],
            test_profile,
        )?;

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
