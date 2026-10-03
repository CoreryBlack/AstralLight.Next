//! 认证核心：密码验证（含 BCrypt/MD5 兼容迁移）+ JWT 签发 + 工具函数
//!
//! 对应 Java `AuthServiceImpl` + `TokenServiceImpl` + `PasswordValidationServiceImpl`。
//!
//! JWT 签名算法：
//! - HS256（对称，默认）— 当前生产可用
//! - RS256（RSA 非对称，可选）— 对齐 Java JJWT + RSA 架构
//!
//! Java 基线: JJWT + RSA（公钥分发到 Gateway，私钥仅在 Identity）

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use md5::Md5;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use astral_common::config::{JwtConfig, JwtTokenProfile};
use astral_common::middleware::JwtClaims;
use astral_common::token_contract::{PrincipalKind, ACCESS_TYP, CLAIMS_VERSION, REFRESH_TYP};
use astral_types::{AstralError, IdentityCard, PolicyError, UserCard};

use crate::srv::source_writer_guard;

/// 密码验证（含自动迁移：Argon2 → BCrypt → MD5）
///
/// 对齐 Java `PasswordValidationServiceImpl.verifyAndMigrate()`。
/// - 如果 hash 是 Argon2 格式，直接验证
/// - 如果是 BCrypt 格式，验证后自动迁移到 Argon2
/// - 如果是 MD5（32 hex），验证后自动迁移到 Argon2
///
/// 返回 `Ok(true)` 表示验证成功且无需迁移。
/// 返回 `Ok((new_hash))` 表示验证成功但已迁移到新 hash（调用方需 UPDATE）。
/// 返回 `Err` 表示验证失败。
pub fn verify_password(
    password: &str,
    hash_str: &str,
) -> Result<PasswordVerifyResult, AstralError> {
    // 检测算法并验证
    if hash_str.starts_with("$argon2") {
        // Argon2 — 当前标准
        verify_argon2(password, hash_str).map(|_| PasswordVerifyResult::Match)
    } else if hash_str.starts_with("$2") {
        // BCrypt — 遗留算法
        let matched = verify_bcrypt(password, hash_str)?;
        if matched {
            let new_hash = hash_password(password)?;
            Ok(PasswordVerifyResult::Migrated(new_hash))
        } else {
            // BCrypt 不匹配时，尝试 Argon2 回退（对齐 Java 容错逻辑）
            verify_argon2(password, hash_str).map(|_| PasswordVerifyResult::Match)
        }
    } else if hash_str.len() == 32 && hash_str.chars().all(|c| c.is_ascii_hexdigit()) {
        // MD5 hex — 遗留算法
        let md5_hash = format!("{:x}", Md5::digest(password.as_bytes()));
        if md5_hash == hash_str.to_lowercase() {
            let new_hash = hash_password(password)?;
            Ok(PasswordVerifyResult::Migrated(new_hash))
        } else {
            Err(AstralError::Auth("Invalid password".into()))
        }
    } else if hash_str.contains("PLACEHOLDER") || hash_str.contains("NEED_RESET") {
        Err(AstralError::Auth("Password reset required".into()))
    } else {
        // 默认为 Argon2 尝试
        verify_argon2(password, hash_str).map(|_| PasswordVerifyResult::Match)
    }
}

/// 密码验证结果
pub enum PasswordVerifyResult {
    /// 验证通过，hash 已是最新
    Match,
    /// 验证通过，但已迁移到新 hash（含 Argon2 hash 字符串）
    Migrated(String),
}

/// Argon2 验证
fn verify_argon2(password: &str, hash_str: &str) -> Result<(), AstralError> {
    use argon2::password_hash::PasswordHash;
    let parsed_hash = PasswordHash::new(hash_str)
        .map_err(|e| AstralError::Auth(format!("Invalid password hash: {e}")))?;
    let argon2 = Argon2::default();
    argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_err(|_| AstralError::Auth("Invalid password".into()))
}

/// BCrypt 验证
fn verify_bcrypt(password: &str, hash_str: &str) -> Result<bool, AstralError> {
    match bcrypt::verify(password, hash_str) {
        Ok(true) => Ok(true),
        Ok(false) => Ok(false),
        Err(_) => Ok(false), // 格式错误当作不匹配，不阻塞认证
    }
}

/// 密码哈希（Argon2id，对齐 Java 参数：m=16MB, t=1, p=4, output=32）
pub fn hash_password(password: &str) -> Result<String, AstralError> {
    let salt = SaltString::generate(&mut OsRng);
    let params = argon2::Params::new(16384, 1, 4, Some(32))
        .map_err(|e| AstralError::Internal(format!("Argon2 params failed: {e}")))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AstralError::Internal(format!("Password hash failed: {e}")))?
        .to_string();
    Ok(hash)
}

/// SHA-256 哈希（用于 refresh_token 的不可逆存储）
pub fn sha256_hash(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// 登录响应（对齐 Java AuthResponse）
///
/// 字段名使用 snake_case，通过 `#[serde(rename_all = "camelCase")]` 输出 camelCase。
/// 前端期望的结构：{accessToken, refreshToken, expiresInMillis, tokenType, user, currentCard, availableCards, permissions, roles, enterprises}
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    /// 短期访问令牌（JWT）
    pub access_token: String,
    /// 长期刷新令牌
    pub refresh_token: String,
    /// Token 类型，固定 "Bearer"
    pub token_type: String,
    /// access token 有效时长（毫秒，对齐 Java expiresInMillis）
    pub expires_in_millis: i64,
    /// refresh token 有效时长（毫秒）
    pub refresh_expires_in_millis: i64,
    /// 别名字段：token = accessToken（对齐 Java getToken()）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// 用户信息（对齐 Java AuthResponse.user）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<serde_json::Value>,
    /// Java serializes this alias alongside currentCard through setCurrentCard().
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_card: Option<serde_json::Value>,
    /// 当前身份卡上下文（对齐 Java AuthResponse.currentCard / identityCard）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_card: Option<serde_json::Value>,
    /// 可用卡片列表（对齐 Java AuthResponse.availableCards）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available_cards: Option<Vec<serde_json::Value>>,
    /// 权限列表（对齐 Java AuthResponse.permissions）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<String>>,
    /// 角色列表（对齐 Java AuthResponse.roles）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
    /// 企业列表（对齐 Java AuthResponse.enterprises）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enterprises: Option<Vec<serde_json::Value>>,
    /// Durable session metadata for clients that need to correlate card switches.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<serde_json::Value>,
}

/// Claims supplements evaluated at issuance time. They are allowed only on
/// ACCESS tokens and are never copied to REFRESH tokens.
pub struct TokenClaimsExtra {
    pub roles: Vec<String>,
    pub permissions: Option<Vec<String>>,
    pub tenant_status: Option<String>,
}

/// refresh issuance never receives authorization facts.
#[derive(Debug, Clone, Copy)]
pub struct SessionContext {
    pub session_id: i64,
    pub session_version: i64,
    pub session_epoch: i64,
    pub family_id: i64,
}

/// 签发侧资格校验错误的业务映射（fail-closed）。
///
/// `astral_db::CardEligibilityService::verify_platform_card_pair` 的失败必须拒绝签发，
/// 不能 panic 或 fail-open：
/// - `NotEligible` → 由调用方决定业务错误码（login/refresh/switch-card 各自保留既有语义）；
/// - `Repository` → `Database`（资格查询失败按 500 暴露，禁止默认放行）；
/// - 其他变体（正常流程不应出现）→ `Internal`。
pub(crate) fn map_eligibility_error(
    error: PolicyError,
    not_eligible: impl FnOnce(String) -> AstralError,
) -> AstralError {
    match error {
        PolicyError::NotEligible(reason) => not_eligible(reason),
        PolicyError::Repository(message) => {
            AstralError::Database(format!("Card eligibility check failed: {message}"))
        }
        other => AstralError::Internal(format!("Card eligibility check failed: {other}")),
    }
}

/// Issue a v2 ACCESS JWT.
pub fn issue_access_token(
    config: &JwtConfig,
    user: &IdentityCard,
    card: &UserCard,
    session: SessionContext,
    extra: Option<&TokenClaimsExtra>,
) -> Result<TokenResult, AstralError> {
    let profile = &config.access;
    let now = OffsetDateTime::now_utc().unix_timestamp() as usize;
    let expiry = now + profile.expiry_seconds as usize;
    let jti = uuid::Uuid::new_v4().to_string();
    let roles: Vec<String> = extra
        .map(|value| value.roles.clone())
        .filter(|value: &Vec<String>| !value.is_empty())
        .unwrap_or_else(|| derive_roles_from_card(Some(card)));
    let claims = JwtClaims {
        claims_version: CLAIMS_VERSION,
        issuer: profile.issuer.clone(),
        audience: profile.audience.clone(),
        sub: user.user_id.to_string(),
        jti: jti.clone(),
        roles,
        token_use: "ACCESS".into(),
        principal_kind: PrincipalKind::PlatformUser.as_str().into(),
        identity_card_id: user.card_id,
        user_card_id: card.card_id,
        user_card_tenant_id: card.tenant_id,
        user_card_domain_id: card.domain_id,
        template_id: card.template_id,
        structure_node_id: None,
        tenant_status: extra.and_then(|value| value.tenant_status.clone()),
        permissions: None,
        sid: Some(session.session_id),
        session_version: Some(session.session_version),
        sev: Some(session.session_epoch),
        family_id: Some(session.family_id),
        exp: expiry,
        iat: now,
        nbf: now,
    };
    let token = encode_profile(profile, ACCESS_TYP, &claims)?;
    Ok(TokenResult {
        token,
        jti,
        expires_in: profile.expiry_seconds,
        issued_at_epoch_second: now as i64,
        expires_at_epoch_second: expiry as i64,
    })
}

pub fn issue_access_token_for_identity_only(
    config: &JwtConfig,
    user: &IdentityCard,
    session: SessionContext,
) -> Result<TokenResult, AstralError> {
    let profile = &config.access;
    let now = OffsetDateTime::now_utc().unix_timestamp() as usize;
    let expiry = now + profile.expiry_seconds as usize;
    let jti = uuid::Uuid::new_v4().to_string();
    let claims = JwtClaims {
        claims_version: CLAIMS_VERSION,
        issuer: profile.issuer.clone(),
        audience: profile.audience.clone(),
        sub: user.user_id.to_string(),
        jti: jti.clone(),
        roles: Vec::new(),
        token_use: "ACCESS".into(),
        principal_kind: PrincipalKind::AppUser.as_str().into(),
        identity_card_id: user.card_id,
        user_card_id: None,
        user_card_tenant_id: None,
        user_card_domain_id: None,
        template_id: None,
        structure_node_id: None,
        tenant_status: None,
        permissions: None,
        sid: Some(session.session_id),
        session_version: Some(session.session_version),
        sev: Some(session.session_epoch),
        family_id: Some(session.family_id),
        exp: expiry,
        iat: now,
        nbf: now,
    };
    let token = encode_profile(profile, ACCESS_TYP, &claims)?;
    Ok(TokenResult {
        token,
        jti,
        expires_in: profile.expiry_seconds,
        issued_at_epoch_second: now as i64,
        expires_at_epoch_second: expiry as i64,
    })
}

pub fn issue_refresh_token(
    config: &JwtConfig,
    user_id: i64,
    principal_kind: PrincipalKind,
    session: SessionContext,
) -> Result<TokenResult, AstralError> {
    let profile = &config.refresh;
    let now = OffsetDateTime::now_utc().unix_timestamp() as usize;
    let expiry = now + profile.expiry_seconds as usize;
    let jti = uuid::Uuid::new_v4().to_string();
    let claims = JwtClaims {
        claims_version: CLAIMS_VERSION,
        issuer: profile.issuer.clone(),
        audience: profile.audience.clone(),
        sub: user_id.to_string(),
        jti: jti.clone(),
        roles: Vec::new(),
        token_use: "REFRESH".into(),
        principal_kind: principal_kind.as_str().into(),
        identity_card_id: None,
        user_card_id: None,
        user_card_tenant_id: None,
        user_card_domain_id: None,
        template_id: None,
        structure_node_id: None,
        tenant_status: None,
        permissions: None,
        sid: Some(session.session_id),
        session_version: Some(session.session_version),
        sev: Some(session.session_epoch),
        family_id: Some(session.family_id),
        exp: expiry,
        iat: now,
        nbf: now,
    };
    let token = encode_profile(profile, REFRESH_TYP, &claims)?;
    Ok(TokenResult {
        token,
        jti,
        expires_in: profile.expiry_seconds,
        issued_at_epoch_second: now as i64,
        expires_at_epoch_second: expiry as i64,
    })
}

fn encode_profile<T: serde::Serialize>(
    profile: &JwtTokenProfile,
    typ: &str,
    claims: &T,
) -> Result<String, AstralError> {
    let algorithm = match profile.algorithm.as_str() {
        "HS256" => Algorithm::HS256,
        "RS256" => Algorithm::RS256,
        value => {
            return Err(AstralError::Config(format!(
                "Unsupported JWT algorithm: {value}"
            )))
        }
    };
    let key = match algorithm {
        Algorithm::HS256 => EncodingKey::from_secret(profile.secret.as_bytes()),
        Algorithm::RS256 => {
            let path = profile.rsa_private_key_path.as_deref().ok_or_else(|| {
                AstralError::Internal("RS256 private key is not configured".into())
            })?;
            let pem = std::fs::read(path)
                .map_err(|error| AstralError::Internal(format!("Read RSA private key: {error}")))?;
            EncodingKey::from_rsa_pem(&pem).map_err(|error| {
                AstralError::Internal(format!("Invalid RSA private key: {error}"))
            })?
        }
        _ => unreachable!(),
    };
    let mut header = Header::new(algorithm);
    header.typ = Some(typ.into());
    header.kid = Some(profile.kid.clone());
    encode(&header, claims, &key)
        .map_err(|error| AstralError::Internal(format!("JWT encode failed: {error}")))
}

/// 根据 user_card 类型推导角色列表
/// 注意：card_type 不是角色的来源，角色应从权限动作码推导
/// 此函数仅用于 issue_token 时快速生成 roles claim（最终权限由 PolicyEngine 评估）
fn derive_roles_from_card(_card: Option<&UserCard>) -> Vec<String> {
    // 不再从 cardType 推导 SUPER_ADMIN/ADMIN 等角色（违反 §0.12 特权通道禁令）
    // 统一默认 USER 角色，实际权限由 PolicyEngine + rule_set 决定
    vec!["USER".into()]
}

/// 根据卡片类型列表推导角色（对齐 Java AuthResponse.roles，用于登录响应）
/// Java 从 actionCodes 推导角色，Rust 当前仅返回基础角色
pub fn derive_roles_from_cards(_card_types: &[String]) -> Vec<String> {
    // 不从 cardType 推导特权角色（违反 §0.12）
    // 实际角色由权限引擎决定
    vec!["USER".to_string()]
}

/// 从当前卡有效 actionCodes 推导 roles claim（对齐 Java `AuthServiceImpl.resolveRolesFromCard`）：
/// 跳过 `global_admin/super_admin/superadmin` 类特权 code（§0.12 特权通道禁令），
/// 其余 actionCode 原样作为角色。空列表回退默认 `USER`（无特权放大）。
pub fn derive_roles_from_action_codes(action_codes: &[String]) -> Vec<String> {
    let roles: Vec<String> = action_codes
        .iter()
        .filter(|code| {
            let lower = code.trim().to_ascii_lowercase();
            lower != "global_admin" && lower != "super_admin" && lower != "superadmin"
        })
        .map(|code| code.trim().to_string())
        .filter(|code| !code.is_empty())
        .collect();
    if roles.is_empty() {
        vec!["USER".to_string()]
    } else {
        roles
    }
}

/// JWT 签发结果
pub struct TokenResult {
    pub token: String,
    pub jti: String,
    pub expires_in: i64,
    pub issued_at_epoch_second: i64,
    pub expires_at_epoch_second: i64,
}

/// Versioned session grant stored at `access:grant:{jti}`.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
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

impl SessionGrant {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn active(
        token: &TokenResult,
        principal_kind: PrincipalKind,
        user_id: i64,
        session_id: i64,
        identity_card_id: Option<i64>,
        user_card_id: Option<i64>,
        user_card_tenant_id: Option<i64>,
        user_card_domain_id: Option<i64>,
        session_version: i64,
        session_epoch: i64,
        family_id: i64,
    ) -> Self {
        Self {
            format_version: 2,
            principal_kind: principal_kind.as_str().to_string(),
            user_id,
            session_id,
            identity_card_id,
            user_card_id,
            user_card_tenant_id,
            user_card_domain_id,
            session_version,
            session_epoch,
            token_family_id: family_id,
            session_state: "ACTIVE".to_string(),
            issued_at_epoch_second: token.issued_at_epoch_second,
            expires_at_epoch_second: token.expires_at_epoch_second,
        }
    }
}

/// JWT `jti` values remain opaque UUIDs inside the v2 token contract.
/// 登录聚合行（JOIN user_local_credential + platform_user + identity_card）
///
/// 对齐 platform_v4 真实表结构。登录流程：
/// - `user_local_credential`：login_name + password_hash（凭证层）
/// - `platform_user`：display_name, email, phone, status（用户基础信息层）
/// - `identity_card`：card_id, user_id, status, token_version, expires_at（身份事实层）
#[derive(Debug, sqlx::FromRow)]
pub struct LoginAggregateRow {
    /// platform_user.user_id
    pub user_id: i64,
    /// platform_user.display_name
    pub display_name: Option<String>,
    /// platform_user.email
    pub email: Option<String>,
    /// platform_user.phone
    pub phone: Option<String>,
    /// platform_user.status
    pub user_status: String,
    /// user_local_credential.login_name
    pub login_name: Option<String>,
    /// user_local_credential.password_hash
    pub password_hash: String,
    /// user_local_credential.password_algo
    pub password_algo: Option<String>,
    /// user_local_credential.must_change_password
    pub must_change_password: Option<bool>,
    /// user_local_credential.credential_id
    pub credential_id: i64,
    /// identity_card.card_id
    pub card_id: Option<i64>,
    /// identity_card.status
    pub card_status: Option<String>,
    /// identity_card.token_version
    pub token_version: Option<i64>,
    /// identity_card.expires_at，供签发链路继续执行时间门禁
    pub identity_expires_at: Option<String>,
}

/// 查询登录聚合数据 by login_name（用户名/手机号/邮箱）
///
/// 对齐 platform_v4 真实表结构：通过 `user_local_credential.login_name` 查询凭证，
/// JOIN `platform_user` 获取用户基础信息，LEFT JOIN `identity_card` 获取身份卡信息。
pub async fn find_login_aggregate(
    db: &sqlx::MySqlPool,
    login: &str,
) -> Result<Option<LoginAggregateRow>, AstralError> {
    // 支持用户名、手机号、邮箱三种登录方式
    let row = sqlx::query_as::<_, LoginAggregateRow>(
        "SELECT u.user_id, u.display_name, u.email, u.phone, u.status AS user_status, \
                c.login_name, c.password_hash, c.password_algo, c.must_change_password, \
                c.credential_id, ic.card_id, ic.status AS card_status, ic.token_version, \
                DATE_FORMAT(ic.expires_at, '%Y-%m-%dT%H:%i:%sZ') AS identity_expires_at \
         FROM user_local_credential c \
         INNER JOIN platform_user u ON u.user_id = c.user_id AND u.deleted_at IS NULL \
         LEFT JOIN identity_card ic ON ic.user_id = u.user_id \
         WHERE (c.login_name = ? OR u.phone = ? OR u.email = ?) AND c.status = 'ACTIVE' \
           AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()) \
         ORDER BY ic.status = 'ACTIVE' DESC, ic.card_id ASC LIMIT 1",
    )
    .bind(login)
    .bind(login)
    .bind(login)
    .fetch_optional(db)
    .await
    .map_err(|e| AstralError::Database(format!("Query login aggregate failed: {e}")))?;
    Ok(row)
}

/// 按 login_name 精确查询登录聚合（`user_local_credential.login_name`）。
async fn find_login_aggregate_by_login_name(
    db: &sqlx::MySqlPool,
    login_name: &str,
) -> Result<Option<LoginAggregateRow>, AstralError> {
    let row = sqlx::query_as::<_, LoginAggregateRow>(
        "SELECT \
                u.user_id, u.display_name, u.email, u.phone, u.status AS user_status, \
                c.login_name, c.password_hash, c.password_algo, c.must_change_password, \
                c.credential_id, ic.card_id, ic.status AS card_status, ic.token_version, \
                DATE_FORMAT(ic.expires_at, '%Y-%m-%dT%H:%i:%sZ') AS identity_expires_at \
             FROM user_local_credential c \
             INNER JOIN platform_user u ON u.user_id = c.user_id AND u.deleted_at IS NULL \
             LEFT JOIN identity_card ic ON ic.user_id = u.user_id \
             WHERE c.login_name = ? AND c.status = 'ACTIVE' \
               AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()) \
             ORDER BY ic.status = 'ACTIVE' DESC, ic.card_id ASC LIMIT 1",
    )
    .bind(login_name)
    .fetch_optional(db)
    .await
    .map_err(|e| AstralError::Database(format!("Query login aggregate failed: {e}")))?;
    Ok(row)
}

/// 按 platform_user.phone 查询登录聚合（由手机号反查用户及其凭证）。
async fn find_login_aggregate_by_user_phone(
    db: &sqlx::MySqlPool,
    phone: &str,
) -> Result<Option<LoginAggregateRow>, AstralError> {
    let row = sqlx::query_as::<_, LoginAggregateRow>(
        "SELECT \
            u.user_id, u.display_name, u.email, u.phone, u.status AS user_status, \
            c.login_name, c.password_hash, c.password_algo, c.must_change_password, \
            c.credential_id, ic.card_id, ic.status AS card_status, \
            ic.token_version, \
            DATE_FORMAT(ic.expires_at, '%Y-%m-%dT%H:%i:%sZ') AS identity_expires_at \
         FROM platform_user u \
         INNER JOIN user_local_credential c ON c.user_id = u.user_id AND c.status = 'ACTIVE' \
         LEFT JOIN identity_card ic ON ic.user_id = u.user_id \
         WHERE u.phone = ? AND u.deleted_at IS NULL \
           AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()) \
         ORDER BY ic.status = 'ACTIVE' DESC, ic.card_id ASC LIMIT 1",
    )
    .bind(phone)
    .fetch_optional(db)
    .await
    .map_err(|e| AstralError::Database(format!("Query login aggregate by phone failed: {e}")))?;
    Ok(row)
}

/// 按 platform_user.email 查询登录聚合（由邮箱反查用户及其凭证）。
async fn find_login_aggregate_by_user_email(
    db: &sqlx::MySqlPool,
    email: &str,
) -> Result<Option<LoginAggregateRow>, AstralError> {
    let row = sqlx::query_as::<_, LoginAggregateRow>(
        "SELECT \
            u.user_id, u.display_name, u.email, u.phone, u.status AS user_status, \
            c.login_name, c.password_hash, c.password_algo, c.must_change_password, \
            c.credential_id, ic.card_id, ic.status AS card_status, \
            ic.token_version, \
            DATE_FORMAT(ic.expires_at, '%Y-%m-%dT%H:%i:%sZ') AS identity_expires_at \
         FROM platform_user u \
         INNER JOIN user_local_credential c ON c.user_id = u.user_id AND c.status = 'ACTIVE' \
         LEFT JOIN identity_card ic ON ic.user_id = u.user_id \
         WHERE u.email = ? AND u.deleted_at IS NULL \
           AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()) \
         ORDER BY ic.status = 'ACTIVE' DESC, ic.card_id ASC LIMIT 1",
    )
    .bind(email)
    .fetch_optional(db)
    .await
    .map_err(|e| AstralError::Database(format!("Query login aggregate by email failed: {e}")))?;
    Ok(row)
}

/// 手机号规范化，对齐 Java `AuthenticationServiceImpl.normalizePhone`：
/// trim、剥离 `+86` 前缀、移除空白与连字符；规范化后为空返回 None。
pub fn normalize_phone(phone: &str) -> Option<String> {
    let trimmed = phone.trim();
    if trimmed.is_empty() {
        return None;
    }
    let stripped = trimmed.strip_prefix("+86").unwrap_or(trimmed);
    let cleaned: String = stripped
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

/// 按 Java `resolveLocalCredential` 优先级解析本地凭证：
/// phone(规范化) → username(login_name) → email(platform_user)。
///
/// - phone：先按规范化 login_name 匹配凭证；未命中再按 platform_user.phone 反查。
/// - username：仅按 user_local_credential.login_name 精确匹配。
/// - email：仅按 platform_user.email 反查用户及其凭证。
pub async fn find_login_aggregate_resolved(
    db: &sqlx::MySqlPool,
    username: Option<&str>,
    phone: Option<&str>,
    email: Option<&str>,
) -> Result<Option<LoginAggregateRow>, AstralError> {
    // 1. phone（优先级最高，需规范化）
    if let Some(phone) = phone {
        if let Some(normalized) = normalize_phone(phone) {
            if let Some(row) = find_login_aggregate_by_login_name(db, &normalized).await? {
                return Ok(Some(row));
            }
            if let Some(row) = find_login_aggregate_by_user_phone(db, &normalized).await? {
                return Ok(Some(row));
            }
        }
    }

    // 2. username（login_name）
    if let Some(username) = username {
        let trimmed = username.trim();
        if !trimmed.is_empty() {
            if let Some(row) = find_login_aggregate_by_login_name(db, trimmed).await? {
                return Ok(Some(row));
            }
        }
    }

    // 3. email（platform_user.email）
    if let Some(email) = email {
        let trimmed = email.trim();
        if !trimmed.is_empty() {
            if let Some(row) = find_login_aggregate_by_user_email(db, trimmed).await? {
                return Ok(Some(row));
            }
        }
    }

    Ok(None)
}

/// 当前有效的本地凭证，供改密等自服务操作使用。
#[derive(Debug, sqlx::FromRow)]
pub struct PasswordCredential {
    pub user_id: i64,
    pub password_hash: String,
    pub status: String,
}

/// 查询用户当前启用的本地凭证。
pub async fn load_password_credential(
    db: &sqlx::MySqlPool,
    user_id: i64,
) -> Result<Option<PasswordCredential>, AstralError> {
    sqlx::query_as::<_, PasswordCredential>(
        "SELECT user_id, password_hash, status \
         FROM user_local_credential \
         WHERE user_id = ? AND status = 'ACTIVE' LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(|e| AstralError::Database(format!("Load password credential failed: {e}")))
}

/// 更新密码 hash（操作 user_local_credential 表）
///
/// 凭证事实 autocommit 写：source writer 栅栏（hub 已装则 fail-closed 取得，
/// 不可得即拒绝写入；await 窗口前武装取消栅栏，Ok → proven；Err/取消 →
/// sticky uncertain）。事务内变体 [`update_password_hash_tx`] 不自围——它是
/// 调用方 source 事务的成员（如 password.rs 重置事务），由事务栅栏统一持有，
/// 绝不双重围栏。
pub async fn update_password_hash(
    db: &sqlx::MySqlPool,
    user_id: i64,
    new_hash: &str,
) -> Result<(), AstralError> {
    let source_guard = source_writer_guard::begin_source_write()?;
    source_writer_guard::fenced_source_write(
        source_guard,
        sqlx::query(
            "UPDATE user_local_credential \
             SET password_hash = ?, password_algo = 'ARGON2ID', password_updated_at = CURRENT_TIMESTAMP, \
                 must_change_password = 0, updated_at = CURRENT_TIMESTAMP \
             WHERE user_id = ? AND status = 'ACTIVE'",
        )
        .bind(new_hash)
        .bind(user_id)
        .execute(db),
    )
    .await
    .map_err(|e| AstralError::Database(format!("Update password hash failed: {e}")))?;
    Ok(())
}

/// 事务内更新密码 hash（与 password reset token 原子消费同一事务，
/// 保证凭据变更与 token 消费要么同时生效要么同时回滚）
pub async fn update_password_hash_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    user_id: i64,
    new_hash: &str,
) -> Result<(), AstralError> {
    sqlx::query(
        "UPDATE user_local_credential \
         SET password_hash = ?, password_algo = 'ARGON2ID', password_updated_at = CURRENT_TIMESTAMP, \
             must_change_password = 0, updated_at = CURRENT_TIMESTAMP \
         WHERE user_id = ? AND status = 'ACTIVE'"
    )
    .bind(new_hash)
    .bind(user_id)
    .execute(&mut **tx)
    .await
    .map_err(|e| AstralError::Database(format!("Update password hash failed: {e}")))?;
    Ok(())
}

/// 更新最后登录时间（操作 user_local_credential 表）
pub async fn update_last_login_at(db: &sqlx::MySqlPool, user_id: i64) -> Result<(), AstralError> {
    sqlx::query(
        "UPDATE user_local_credential SET last_login_at = CURRENT_TIMESTAMP WHERE user_id = ?",
    )
    .bind(user_id)
    .execute(db)
    .await
    .map_err(|e| AstralError::Database(format!("Update last_login_at failed: {e}")))?;
    Ok(())
}

/// 检查登录名是否已存在（查 user_local_credential.login_name）
pub async fn check_login_name_exists(
    db: &sqlx::MySqlPool,
    login_name: &str,
) -> Result<bool, AstralError> {
    let row: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM user_local_credential WHERE login_name = ?")
            .bind(login_name)
            .fetch_one(db)
            .await
            .map_err(|e| AstralError::Database(format!("Check duplicate failed: {e}")))?;
    Ok(row.0 > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hash_and_verify() {
        let password = "test".repeat(8);
        let hash = hash_password(&password).unwrap();
        let result = verify_password(&password, &hash).unwrap();
        assert!(matches!(result, PasswordVerifyResult::Match));
    }

    #[test]
    fn test_password_wrong() {
        let hash = hash_password("correct").unwrap();
        let result = verify_password("wrong", &hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_sha256_hash_consistency() {
        let input = "test-refresh-token";
        let h1 = sha256_hash(input);
        let h2 = sha256_hash(input);
        assert_eq!(h1, h2);
        assert_ne!(h1, sha256_hash("different"));
    }

    #[test]
    fn test_issue_v2_token_pair() {
        let access_profile = JwtTokenProfile {
            algorithm: "HS256".into(),
            secret: "access-test-secret-0123456789abcdef".into(),
            kid: "access-test".into(),
            issuer: "astral-identity".into(),
            audience: "astral-api".into(),
            expiry_seconds: 900,
            ..Default::default()
        };
        let refresh_profile = JwtTokenProfile {
            algorithm: "HS256".into(),
            secret: "refresh-test-secret-0123456789abcdef".into(),
            kid: "refresh-test".into(),
            issuer: "astral-identity".into(),
            audience: "astral-session".into(),
            expiry_seconds: 604800,
            ..Default::default()
        };
        let config = JwtConfig {
            access: access_profile.clone(),
            refresh: refresh_profile.clone(),
        };
        let user = IdentityCard {
            card_id: Some(1),
            user_id: 42,
            status: "ACTIVE".into(),
            token_version: Some(1),
            expires_at: None,
            disabled_reason: None,
            last_used_at: None,
            created_at: None,
            updated_at: None,
        };
        let card = UserCard {
            card_id: Some(3),
            user_id: Some(42),
            domain_id: Some(8),
            card_type: "PLATFORM_CARD".into(),
            card_status: "ACTIVE".into(),
            template_id: None,
            level_id: None,
            priority: Some(100),
            is_primary: Some(true),
            valid_from: None,
            valid_until: None,
            created_at: None,
            updated_at: None,
            tenant_id: Some(10),
        };
        let session = SessionContext {
            session_id: 1,
            session_version: 1,
            session_epoch: 1,
            family_id: 2,
        };
        let access = issue_access_token(&config, &user, &card, session, None).unwrap();
        let refresh =
            issue_refresh_token(&config, user.user_id, PrincipalKind::PlatformUser, session)
                .unwrap();
        let access_header = jsonwebtoken::decode_header(&access.token).unwrap();
        let refresh_header = jsonwebtoken::decode_header(&refresh.token).unwrap();
        assert_eq!(access_header.typ.as_deref(), Some(ACCESS_TYP));
        assert_eq!(access_header.kid.as_deref(), Some("access-test"));
        assert_eq!(refresh_header.typ.as_deref(), Some(REFRESH_TYP));
        assert_eq!(refresh_header.kid.as_deref(), Some("refresh-test"));

        let mut access_validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        access_validation.set_audience(&["astral-api"]);
        let access_claims = jsonwebtoken::decode::<JwtClaims>(
            &access.token,
            &jsonwebtoken::DecodingKey::from_secret(access_profile.secret.as_bytes()),
            &access_validation,
        )
        .unwrap()
        .claims;
        assert_eq!(access_claims.claims_version, CLAIMS_VERSION);
        assert_eq!(access_claims.token_use, "ACCESS");
        assert_eq!(access_claims.identity_card_id, Some(1));
        assert_eq!(access_claims.user_card_id, Some(3));

        let mut refresh_validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        refresh_validation.set_audience(&["astral-session"]);
        let refresh_claims = jsonwebtoken::decode::<JwtClaims>(
            &refresh.token,
            &jsonwebtoken::DecodingKey::from_secret(refresh_profile.secret.as_bytes()),
            &refresh_validation,
        )
        .unwrap()
        .claims;
        assert_eq!(refresh_claims.claims_version, CLAIMS_VERSION);
        assert_eq!(refresh_claims.token_use, "REFRESH");
        assert!(refresh_claims.identity_card_id.is_none());
        assert!(refresh_claims.user_card_id.is_none());
        assert!(refresh_claims.permissions.is_none());
        assert!(refresh_claims.roles.is_empty());
    }

    #[test]
    fn session_grant_uses_java_contract_field_names() {
        let grant = SessionGrant {
            format_version: 2,
            principal_kind: PrincipalKind::PlatformUser.as_str().into(),
            user_id: 10,
            session_id: 20,
            identity_card_id: Some(11),
            user_card_id: Some(30),
            user_card_tenant_id: Some(20),
            user_card_domain_id: Some(40),
            session_version: 4,
            session_epoch: 5,
            token_family_id: 40,
            session_state: "ACTIVE".to_string(),
            issued_at_epoch_second: 100,
            expires_at_epoch_second: 200,
        };

        let value = serde_json::to_value(grant).unwrap();

        assert_eq!(value["formatVersion"], 2);
        assert_eq!(value["principalKind"], "PLATFORM_USER");
        assert_eq!(value["userId"], 10);
        assert_eq!(value["sessionId"], 20);
        assert_eq!(value["identityCardId"], 11);
        assert_eq!(value["userCardId"], 30);
        assert!(value.get("cardId").is_none());
        assert_eq!(value["userCardTenantId"], 20);
        assert_eq!(value["userCardDomainId"], 40);
        assert_eq!(value["sessionVersion"], 4);
        assert_eq!(value["sessionEpoch"], 5);
        assert_eq!(value["tokenFamilyId"], 40);
        assert_eq!(value["sessionState"], "ACTIVE");
        assert_eq!(value["issuedAtEpochSecond"], 100);
        assert_eq!(value["expiresAtEpochSecond"], 200);
    }

    #[test]
    fn roles_from_action_codes_skip_super_admin_and_keep_rest() {
        let codes = vec![
            "learn_subject:read".into(),
            "global_admin".into(),
            "learn_checkin:write".into(),
            "super_admin".into(),
        ];
        let roles = derive_roles_from_action_codes(&codes);
        assert_eq!(roles, vec!["learn_subject:read", "learn_checkin:write"]);
    }

    #[test]
    fn roles_from_action_codes_empty_falls_back_to_user() {
        assert_eq!(
            derive_roles_from_action_codes(&["superadmin".into()]),
            vec!["USER"]
        );
        assert_eq!(derive_roles_from_action_codes(&[]), vec!["USER"]);
    }

    #[test]
    fn issue_token_with_extra_emits_roles_without_permission_facts() {
        // Permission facts never enter the ACCESS JWT; PolicyEngine remains the only authority.
        let config = JwtConfig {
            access: JwtTokenProfile {
                secret: "access-test-secret-0123456789abcdef".into(),
                issuer: "astral-identity".into(),
                audience: "astral-api".into(),
                ..Default::default()
            },
            refresh: JwtTokenProfile {
                secret: "refresh-test-secret-0123456789abcdef".into(),
                issuer: "astral-identity".into(),
                audience: "astral-session".into(),
                expiry_seconds: 604800,
                ..Default::default()
            },
        };
        let user = IdentityCard {
            card_id: Some(3),
            user_id: 7,
            status: "ACTIVE".into(),
            token_version: Some(1),
            expires_at: None,
            disabled_reason: None,
            last_used_at: None,
            created_at: None,
            updated_at: None,
        };
        let card = UserCard {
            card_id: Some(3),
            user_id: Some(7),
            domain_id: Some(8),
            card_type: "PLATFORM_CARD".into(),
            card_status: "ACTIVE".into(),
            template_id: None,
            level_id: None,
            priority: Some(100),
            is_primary: Some(true),
            valid_from: None,
            valid_until: None,
            created_at: None,
            updated_at: None,
            tenant_id: Some(10),
        };
        let extra = TokenClaimsExtra {
            roles: vec!["learn_subject:read".into()],
            permissions: Some(vec!["learn_subject:read".into()]),
            tenant_status: Some("ACTIVE".into()),
        };
        let result = issue_access_token(
            &config,
            &user,
            &card,
            SessionContext {
                session_id: 1,
                session_version: 1,
                session_epoch: 1,
                family_id: 1,
            },
            Some(&extra),
        )
        .unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.set_audience(&["astral-api"]);
        let data = jsonwebtoken::decode::<JwtClaims>(
            &result.token,
            &jsonwebtoken::DecodingKey::from_secret(config.access.secret.as_bytes()),
            &validation,
        )
        .unwrap();
        assert_eq!(data.claims.roles, vec!["learn_subject:read"]);
        assert!(data.claims.permissions.is_none());
        assert_eq!(data.claims.tenant_status.as_deref(), Some("ACTIVE"));
    }

    #[test]
    fn eligibility_error_maps_fail_closed_to_business_error() {
        // NotEligible → 调用方业务错误（登录保留 USER_CARD_SCOPE_REQUIRED 语义）
        let not_eligible =
            map_eligibility_error(PolicyError::NotEligible("tenant inactive".into()), |_| {
                AstralError::Permission("USER_CARD_SCOPE_REQUIRED".into())
            });
        assert!(
            matches!(not_eligible, AstralError::Permission(message) if message == "USER_CARD_SCOPE_REQUIRED")
        );

        // Repository → Database（fail-closed，禁止默认放行）
        let repository =
            map_eligibility_error(PolicyError::Repository("query failed".into()), |_| {
                AstralError::Permission("USER_CARD_SCOPE_REQUIRED".into())
            });
        assert!(matches!(repository, AstralError::Database(_)));

        // 其他变体 → Internal（正常流程不应出现）
        let unexpected = map_eligibility_error(PolicyError::Evaluation("boom".into()), |_| {
            AstralError::Permission("USER_CARD_SCOPE_REQUIRED".into())
        });
        assert!(matches!(unexpected, AstralError::Internal(_)));
    }

    /// 公共凭据写点 source 栅栏形状回归（源形状，无 IO）：published
    /// `update_password_hash`（autocommit）自围；事务内变体
    /// `update_password_hash_tx` 保持裸 SQL——由调用方事务栅栏统一持有，
    /// 绝不双重围栏。
    #[test]
    fn published_password_writer_is_fenced_and_tx_variant_stays_outer_fenced() {
        let source = include_str!("auth.rs");
        let impl_source = &source[..source
            .find("#[cfg(test)]")
            .expect("tests module must stay at the end of auth.rs")];

        let free_body = impl_source
            .split("pub async fn update_password_hash(")
            .nth(1)
            .expect("published update_password_hash must stay in auth.rs")
            .split("pub async fn update_password_hash_tx(")
            .next()
            .expect("tx variant must follow the free fn");
        assert!(
            free_body.contains("source_writer_guard::begin_source_write()")
                && free_body.contains("source_writer_guard::fenced_source_write("),
            "the published autocommit password writer must be self-fenced"
        );

        let tx_body = impl_source
            .split("pub async fn update_password_hash_tx(")
            .nth(1)
            .expect("tx variant must stay in auth.rs")
            .split("pub async fn update_last_login_at(")
            .next()
            .expect("update_last_login_at must follow the tx variant");
        assert!(
            !tx_body.contains("fenced_source_write"),
            "the tx member must stay bare SQL: the caller transaction's fence owns it"
        );
    }
}
