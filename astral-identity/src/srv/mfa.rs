//! 多因素认证（MFA）
//!
//! 支持 TOTP（RFC 6238）和恢复码两种方式。
//! 所有数据持久化到 DB，暴力破解防护通过 mfa_attempt_log 计数实现。

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use base32::Alphabet;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use totp_rs::{Algorithm, TOTP};

use astral_common::contract::{ApiResponse, EmptyResponse};
use astral_common::error::AppError;
use astral_db::{
    count_recent_mfa_failures, find_enabled_mfa_for_user, reserve_mfa_attempt,
    resolve_mfa_attempt_for_actor,
};
use astral_types::AstralError;
use sqlx::{MySql, Transaction};

use crate::AppState;

/// DbError → AppError 辅助转换
fn db_err(e: astral_db::DbError) -> AppError {
    AppError::from(AstralError::Database(format!("{e}")))
}

/// MFA 配置信息
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MfaConfig {
    pub enabled: bool,
    pub method: String,
    pub recovery_codes: Vec<String>,
    pub totp_secret_b32: Option<String>,
    pub created_at: String,
}

/// 启用 MFA 请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnableMfaRequest {
    pub method: String,
    pub password: Option<String>,
    pub factor_method: Option<String>,
    pub factor_code: Option<String>,
}

/// 验证 MFA 请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyMfaRequest {
    pub code: String,
    pub method: Option<String>,
    pub password: Option<String>,
}

const RECOVERY_CODE_COUNT: usize = 10;
const MFA_FAILURE_WINDOW_MINUTES: i32 = 15;
const MFA_FAILURE_MAX_COUNT: i32 = 5;

/// 从请求头提取 user_id
fn extract_user_id(headers: &HeaderMap) -> Result<i64, AppError> {
    headers
        .get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<i64>().ok())
        .ok_or_else(|| AppError::from(AstralError::Auth("Missing x-user-id header".into())))
}

/// 提取客户端 IP 和 User-Agent
fn extract_client_info(headers: &HeaderMap) -> (Option<&str>, Option<&str>) {
    let ip = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
    let ua = headers.get("user-agent").and_then(|v| v.to_str().ok());
    (ip, ua)
}

fn current_user_id(headers: &HeaderMap) -> Result<i64, AppError> {
    extract_user_id(headers)
}

/// 生成恢复码（明文 + JSON 数组 SHA-256 哈希）
fn generate_recovery_codes() -> (Vec<String>, String) {
    let plain_codes: Vec<String> = {
        let mut rng = rand::thread_rng();
        (0..RECOVERY_CODE_COUNT)
            .map(|_| {
                let high: u64 = rng.gen();
                let low: u64 = rng.gen();
                format!("{high:016x}{low:016x}")
            })
            .collect()
    };
    let hashes_json = serde_json::to_string(
        &plain_codes
            .iter()
            .map(|c| format!("{:x}", Sha256::digest(c.as_bytes())))
            .collect::<Vec<_>>(),
    )
    .unwrap_or_default();
    (plain_codes, hashes_json)
}

/// AES-256-GCM 密钥（生产从环境变量注入，对齐 session 响应加密模式）。
///
/// 缺失或长度不对时返回明确错误（fail-closed）：MFA 密文不可用不应静默降级。
fn mfa_aes_gcm_key() -> Result<[u8; 32], AppError> {
    let key_hex = std::env::var("IDENTITY_MFA_AES_GCM_KEY").map_err(|_| {
        AppError::from(AstralError::Internal(
            "IDENTITY_MFA_AES_GCM_KEY is not configured".into(),
        ))
    })?;
    let bytes = hex::decode(key_hex).map_err(|e| {
        AppError::from(AstralError::Internal(format!(
            "IDENTITY_MFA_AES_GCM_KEY hex decode failed: {e}"
        )))
    })?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        AppError::from(AstralError::Internal(
            "IDENTITY_MFA_AES_GCM_KEY must be 64 hex chars (32 bytes)".into(),
        ))
    })
}

/// 加密 TOTP 密钥：`v1.{nonce_b64}.{cipher_b64}`（随机 nonce 防复用）。
fn encrypt_totp_secret(secret: &[u8]) -> Result<Vec<u8>, AppError> {
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use base64::Engine;
    use rand::RngCore;

    let key = mfa_aes_gcm_key()?;
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| AppError::from(AstralError::Internal("AES-GCM key invalid".into())))?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: secret,
                aad: b"mfa-totp",
            },
        )
        .map_err(|e| AstralError::Internal(format!("AES-GCM encrypt failed: {e}")))?;
    Ok(format!(
        "v1.{}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ciphertext)
    )
    .into_bytes())
}

/// 解密 TOTP 密钥：仅接受 `v1.{nonce}.{cipher}`（随机 nonce、AAD 绑定版本格式）。
fn decrypt_totp_secret(enc: &[u8]) -> Result<Vec<u8>, AppError> {
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use base64::Engine;

    let key = mfa_aes_gcm_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| AppError::from(AstralError::Internal("AES-GCM key invalid".into())))?;
    let text = std::str::from_utf8(enc)
        .map_err(|_| AppError::from(AstralError::Auth("MFA ciphertext format invalid".into())))?;
    let rest = text.strip_prefix("v1.").ok_or_else(|| {
        AppError::from(AstralError::Auth(
            "MFA legacy ciphertext is not accepted".into(),
        ))
    })?;
    let mut parts = rest.splitn(2, '.');
    let (Some(nonce_b64), Some(cipher_b64)) = (parts.next(), parts.next()) else {
        return Err(AstralError::Internal(
            "MFA ciphertext format invalid (missing nonce or cipher)".into(),
        )
        .into());
    };
    let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(nonce_b64)
        .map_err(|e| AstralError::Internal(format!("MFA nonce decode failed: {e}")))?;
    let nonce: [u8; 12] = nonce
        .as_slice()
        .try_into()
        .map_err(|_| AstralError::Internal("MFA nonce must be exactly 12 bytes".into()))?;
    let ciphertext = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cipher_b64)
        .map_err(|e| AstralError::Internal(format!("MFA cipher decode failed: {e}")))?;
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: b"mfa-totp",
            },
        )
        .map_err(|e| AstralError::Internal(format!("AES-GCM decrypt failed: {e}")).into())
}

fn prepare_totp_secret() -> Result<(String, Vec<u8>), AppError> {
    let secret_bytes: [u8; 20] = {
        let mut rng = rand::thread_rng();
        std::array::from_fn(|_| rng.gen::<u8>())
    };
    let encoded = base32::encode(Alphabet::Rfc4648 { padding: false }, &secret_bytes);
    Ok((encoded, encrypt_totp_secret(&secret_bytes)?))
}

const CONSUME_TOTP_SQL: &str =
    "UPDATE user_mfa SET last_totp_counter = ?, last_used_at = CURRENT_TIMESTAMP, \
     is_enabled = IF(? = 1, 1, is_enabled), is_primary = IF(? = 1, 1, is_primary), \
     verified_at = IF(? = 1, CURRENT_TIMESTAMP, verified_at), updated_at = CURRENT_TIMESTAMP \
     WHERE user_id = ? AND mfa_type = 'TOTP' AND is_enabled = ? \
       AND (last_totp_counter IS NULL OR last_totp_counter < ?)";
const CONSUME_RECOVERY_SQL: &str = "UPDATE user_mfa SET backup_codes_hash = ?, \
     backup_codes_used = backup_codes_used + 1, last_used_at = CURRENT_TIMESTAMP, \
     is_enabled = IF(? = 1, 1, is_enabled), is_primary = IF(? = 1, 1, is_primary), \
     verified_at = IF(? = 1, CURRENT_TIMESTAMP, verified_at), updated_at = CURRENT_TIMESTAMP \
     WHERE user_id = ? AND mfa_type = 'RECOVERY_CODES' AND is_enabled = ? \
       AND backup_codes_used = ? AND backup_codes_hash = ?";
const STAGE_FACTOR_SQL: &str = "INSERT INTO user_mfa \
     (user_id, mfa_type, secret_enc, backup_codes_hash, is_enabled, is_primary, \
      backup_codes_used, last_totp_counter) VALUES (?, ?, ?, ?, 0, 0, 0, NULL) \
     ON DUPLICATE KEY UPDATE secret_enc = VALUES(secret_enc), \
     backup_codes_hash = VALUES(backup_codes_hash), is_enabled = 0, is_primary = 0, \
     backup_codes_used = 0, verified_at = NULL, last_totp_counter = NULL, \
     updated_at = CURRENT_TIMESTAMP";

async fn verify_factor_in_tx(
    tx: &mut Transaction<'_, MySql>,
    user_id: i64,
    method: &str,
    code: &str,
    allow_pending: bool,
) -> Result<bool, AstralError> {
    if !matches!(method, "TOTP" | "RECOVERY_CODES") {
        return Ok(false);
    }
    let row = sqlx::query_as::<_, astral_db::UserMfaRow>(
        "SELECT id, user_id, mfa_type, secret_enc, phone, email, is_enabled, is_primary, \
         backup_codes_hash, backup_codes_used, verified_at, last_used_at, last_totp_counter \
         FROM user_mfa WHERE user_id = ? AND mfa_type = ? FOR UPDATE",
    )
    .bind(user_id)
    .bind(method)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| {
        AstralError::Database(format!("Lock MFA factor for verification failed: {error}"))
    })?;
    let Some(row) = row else { return Ok(false) };
    if row.is_enabled != 1 && !(allow_pending && row.is_enabled == 0) {
        return Ok(false);
    }
    let activating = row.is_enabled == 0;
    match method {
        "TOTP" => {
            let Some(encrypted) = row.secret_enc.as_deref() else {
                return Ok(false);
            };
            let Some(counter) = encrypted_totp_counter(encrypted, code, row.last_totp_counter)?
            else {
                return Ok(false);
            };
            let result = sqlx::query(CONSUME_TOTP_SQL)
                .bind(counter)
                .bind(activating as i32)
                .bind(activating as i32)
                .bind(activating as i32)
                .bind(user_id)
                .bind(row.is_enabled)
                .bind(counter)
                .execute(&mut **tx)
                .await
                .map_err(|error| {
                    AstralError::Database(format!("Consume MFA TOTP proof failed: {error}"))
                })?;
            Ok(result.rows_affected() == 1)
        }
        "RECOVERY_CODES" => {
            if row.backup_codes_used < 0 || row.backup_codes_used as usize >= RECOVERY_CODE_COUNT {
                return Ok(false);
            }
            let Some(serialized) = row.backup_codes_hash.as_deref() else {
                return Ok(false);
            };
            let code_hash = format!("{:x}", Sha256::digest(code.as_bytes()));
            let mut hashes: Vec<String> = serde_json::from_str(serialized).map_err(|error| {
                AstralError::Database(format!("Invalid recovery hashes: {error}"))
            })?;
            let Some(index) = hashes.iter().position(|hash| hash == &code_hash) else {
                return Ok(false);
            };
            hashes.remove(index);
            let updated_hashes = serde_json::to_string(&hashes).map_err(|error| {
                AstralError::Internal(format!("Serialize recovery hashes failed: {error}"))
            })?;
            let result = sqlx::query(CONSUME_RECOVERY_SQL)
                .bind(updated_hashes)
                .bind(activating as i32)
                .bind(activating as i32)
                .bind(activating as i32)
                .bind(user_id)
                .bind(row.is_enabled)
                .bind(row.backup_codes_used)
                .bind(serialized)
                .execute(&mut **tx)
                .await
                .map_err(|error| {
                    AstralError::Database(format!("Consume MFA recovery proof failed: {error}"))
                })?;
            Ok(result.rows_affected() == 1)
        }
        _ => Ok(false),
    }
}

async fn verify_management_password(
    pool: &sqlx::MySqlPool,
    user_id: i64,
    password: &str,
) -> Result<crate::auth::PasswordCredential, AppError> {
    if password.is_empty() {
        return Err(AstralError::Auth("current password required".into()).into());
    }
    let credential = crate::auth::load_password_credential(pool, user_id)
        .await?
        .ok_or_else(|| AstralError::Auth("local credential not found".into()))?;
    if credential.status != "ACTIVE" || credential.credential_version <= 0 {
        return Err(AstralError::Auth("local credential not active".into()).into());
    }
    crate::auth::verify_password(password, &credential.password_hash)?;
    Ok(credential)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoginFactorOutcome {
    Required,
    Invalid,
    Consumed,
    NotEnabled,
}

fn encrypted_totp_counter(
    enc: &[u8],
    code: &str,
    last_counter: Option<i64>,
) -> Result<Option<i64>, AstralError> {
    let secret =
        decrypt_totp_secret(enc).map_err(|error| AstralError::Internal(error.to_string()))?;
    let totp = TOTP::new(Algorithm::SHA1, 6, 0, 30, secret)
        .map_err(|error| AstralError::Internal(format!("TOTP init failed: {error}")))?;
    let step = time::OffsetDateTime::now_utc()
        .unix_timestamp()
        .div_euclid(30);
    for candidate in (step - 1)..=(step + 1) {
        if candidate < 0 || last_counter.is_some_and(|used| candidate <= used) {
            continue;
        }
        if totp.check(code, (candidate * 30) as u64) {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

pub(crate) async fn consume_login_factor_in_tx(
    tx: &mut Transaction<'_, MySql>,
    user_id: i64,
    method: Option<&str>,
    code: Option<&str>,
    allow_pending: bool,
) -> Result<LoginFactorOutcome, AstralError> {
    if allow_pending {
        return Err(AstralError::Auth(
            "Login cannot activate a pending MFA factor".into(),
        ));
    }
    let rows = sqlx::query_as::<_, astral_db::UserMfaRow>(
        "SELECT id, user_id, mfa_type, secret_enc, phone, email, is_enabled, is_primary, \
         backup_codes_hash, backup_codes_used, verified_at, last_used_at, last_totp_counter \
         FROM user_mfa WHERE user_id = ? AND is_enabled = 1 \
         ORDER BY mfa_type LIMIT 3 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|error| {
        AstralError::Database(format!("Load active MFA login factors failed: {error}"))
    })?;
    if rows.len() > 2
        || rows
            .iter()
            .any(|row| !matches!(row.mfa_type.as_str(), "TOTP" | "RECOVERY_CODES"))
    {
        return Ok(LoginFactorOutcome::Invalid);
    }
    if rows.is_empty() {
        return if code.is_some_and(|value| !value.trim().is_empty()) {
            Ok(LoginFactorOutcome::Invalid)
        } else {
            Ok(LoginFactorOutcome::NotEnabled)
        };
    }
    let (Some(method), Some(code)) = (
        method,
        code.map(str::trim).filter(|value| !value.is_empty()),
    ) else {
        return Ok(LoginFactorOutcome::Required);
    };
    if !rows.iter().any(|row| row.mfa_type == method) {
        return Ok(LoginFactorOutcome::Invalid);
    }
    if verify_factor_in_tx(tx, user_id, method, code, false).await? {
        Ok(LoginFactorOutcome::Consumed)
    } else {
        Ok(LoginFactorOutcome::Invalid)
    }
}

pub(crate) async fn resolve_mfa_attempt_in_tx(
    tx: &mut Transaction<'_, MySql>,
    attempt_code: &str,
    user_id: i64,
    method: &str,
    success: bool,
    failure_reason: Option<&str>,
) -> Result<(), AstralError> {
    let result = sqlx::query(
        "UPDATE mfa_attempt_log SET success = ?, status = ?, failure_reason = ?, \
         attempted_at = CURRENT_TIMESTAMP WHERE attempt_code = ? AND user_id = ? \
           AND mfa_type = ? AND status = 'PENDING' AND success = 0",
    )
    .bind(success as i32)
    .bind(if success { "SUCCEEDED" } else { "FAILED" })
    .bind(failure_reason)
    .bind(attempt_code)
    .bind(user_id)
    .bind(method)
    .execute(&mut **tx)
    .await
    .map_err(|error| AstralError::Database(format!("Resolve MFA login attempt failed: {error}")))?;
    if result.rows_affected() != 1 {
        return Err(AstralError::Database(
            "MFA attempt reservation was not pending".into(),
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct MfaMutationContext {
    user_id: i64,
    identity_card_id: i64,
    card_id: i64,
    tenant_id: i64,
    domain_id: i64,
    operation_id: String,
}

impl MfaMutationContext {
    fn from_headers(headers: &HeaderMap) -> Result<Self, AppError> {
        let positive_id = |name| {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<i64>().ok())
                .filter(|value| *value > 0)
                .ok_or_else(|| {
                    AppError::from(AstralError::Auth(
                        "MFA requires verified platform user-card context".into(),
                    ))
                })
        };
        if headers
            .get("x-principal-kind")
            .and_then(|value| value.to_str().ok())
            != Some("PLATFORM_USER")
        {
            return Err(AstralError::Auth("MFA requires a platform principal".into()).into());
        }
        let request_id = headers
            .get("x-request-id")
            .map(|value| value.to_str())
            .transpose()
            .map_err(|_| AstralError::Validation("Invalid request id".into()))?;
        let operation_id = astral_db::grant_ledger::validated_request_operation_id(request_id)?
            .ok_or_else(|| {
                AstralError::Auth("MFA mutation requires a canonical request id".into())
            })?;
        Ok(Self {
            user_id: positive_id("x-user-id")?,
            identity_card_id: positive_id("x-identity-card-id")?,
            card_id: positive_id("x-user-card-id")?,
            tenant_id: positive_id("x-user-card-tenant-id")?,
            domain_id: positive_id("x-user-card-domain-id")?,
            operation_id,
        })
    }
}

enum MfaMutation<'a> {
    Stage {
        method: &'a str,
        secret: Option<&'a [u8]>,
        hashes: Option<&'a str>,
    },
    Disable {
        method: &'a str,
    },
    Regenerate {
        hashes: &'a str,
    },
    Verify {
        method: &'a str,
        code: &'a str,
    },
}

fn management_credential_matches(
    current: &crate::auth::PasswordCredential,
    expected: Option<&crate::auth::PasswordCredential>,
    user_id: i64,
) -> bool {
    current.user_id == user_id
        && current.status == "ACTIVE"
        && current.credential_version > 0
        && expected.is_none_or(|expected| {
            expected.user_id == user_id
                && expected.status == "ACTIVE"
                && expected.credential_version == current.credential_version
                && expected.password_hash == current.password_hash
        })
}

async fn mutate_mfa(
    pool: &sqlx::MySqlPool,
    context: &MfaMutationContext,
    mutation: MfaMutation<'_>,
    credential: Option<&crate::auth::PasswordCredential>,
    factor: (Option<&str>, Option<&str>),
    client: (Option<&str>, Option<&str>),
) -> Result<bool, AppError> {
    let (method, code) = match &mutation {
        MfaMutation::Verify { method, code } => (Some(*method), Some(*code)),
        _ => factor,
    };
    let attempt = match (method, code.map(str::trim).filter(|code| !code.is_empty())) {
        (None, None) => None,
        (Some(method), Some(code))
            if matches!(method, "TOTP" | "RECOVERY_CODES") && code.len() <= 128 =>
        {
            check_brute_force_protection(pool, context.user_id).await?;
            let attempt_id = uuid::Uuid::new_v4().to_string();
            reserve_mfa_attempt(
                pool,
                context.user_id,
                &attempt_id,
                method,
                client.0,
                client.1,
            )
            .await
            .map_err(db_err)?;
            Some((attempt_id, method, code))
        }
        _ => return Err(AstralError::Auth("MFA factor method and code required".into()).into()),
    };
    let source_guard = crate::srv::source_writer_guard::begin_source_write()?;
    let mut tx = pool.begin().await.map_err(|error| {
        AstralError::Database(format!("Begin MFA management transaction failed: {error}"))
    })?;
    // Credential, pinned cards, then factor rows share the login lock order.
    let current = sqlx::query_as::<_, crate::auth::PasswordCredential>(
        "SELECT user_id, password_hash, status, credential_version FROM user_local_credential \
         WHERE user_id = ? FOR UPDATE",
    )
    .bind(context.user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|error| AstralError::Database(format!("Lock MFA credential failed: {error}")))?;
    let expected_required = !matches!(mutation, MfaMutation::Verify { .. });
    if (expected_required && credential.is_none())
        || current.as_ref().is_none_or(|current| {
            !management_credential_matches(current, credential, context.user_id)
        })
    {
        return Err(
            AstralError::Auth("Credential changed; reauthentication required".into()).into(),
        );
    }
    let pair: Option<(i64,)> = sqlx::query_as(
        "SELECT uc.card_id FROM platform_user pu \
         INNER JOIN identity_card ic ON ic.card_id = ? AND ic.user_id = pu.user_id \
           AND ic.status = 'ACTIVE' AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()) \
         INNER JOIN user_card uc ON uc.card_id = ? AND uc.user_id = pu.user_id \
           AND uc.card_status = 'ACTIVE' AND uc.card_type != 'LEVEL_TEMPLATE_CARD' \
           AND (uc.valid_from IS NULL OR uc.valid_from <= UTC_TIMESTAMP()) \
           AND (uc.valid_until IS NULL OR uc.valid_until >= UTC_TIMESTAMP()) \
         INNER JOIN tenant t ON t.tenant_id = uc.tenant_id AND t.status = 'ACTIVE' \
         INNER JOIN tenant_domain_map tdm ON tdm.tenant_id = uc.tenant_id \
           AND tdm.domain_id = uc.domain_id AND tdm.status = 'ACTIVE' \
         WHERE pu.user_id = ? AND pu.status = 'ACTIVE' AND pu.deleted_at IS NULL \
           AND uc.tenant_id = ? AND uc.domain_id = ? FOR UPDATE",
    ).bind(context.identity_card_id).bind(context.card_id).bind(context.user_id)
        .bind(context.tenant_id).bind(context.domain_id).fetch_optional(&mut *tx).await
        .map_err(|error| AstralError::Database(format!("Lock MFA actor card pair failed: {error}")))?;
    if pair != Some((context.card_id,)) {
        return Err(AstralError::Auth("MFA actor card pair is no longer active".into()).into());
    }
    let rows = sqlx::query_as::<_, astral_db::UserMfaRow>(
        "SELECT id, user_id, mfa_type, secret_enc, phone, email, is_enabled, is_primary, \
         backup_codes_hash, backup_codes_used, verified_at, last_used_at, last_totp_counter \
         FROM user_mfa WHERE user_id = ? ORDER BY mfa_type LIMIT 3 FOR UPDATE",
    )
    .bind(context.user_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|error| {
        AstralError::Database(format!("Lock MFA management factors failed: {error}"))
    })?;
    if rows.len() > 2
        || rows.iter().any(|row| {
            !matches!(row.mfa_type.as_str(), "TOTP" | "RECOVERY_CODES")
                || !matches!(row.is_enabled, 0 | 1)
        })
    {
        return Err(AstralError::Auth("MFA configuration is ambiguous".into()).into());
    }
    let valid = match &mutation {
        MfaMutation::Verify { method, code } => {
            verify_factor_in_tx(&mut tx, context.user_id, method, code, credential.is_some())
                .await?
        }
        _ => match consume_login_factor_in_tx(&mut tx, context.user_id, method, code, false).await?
        {
            LoginFactorOutcome::Consumed | LoginFactorOutcome::NotEnabled => true,
            LoginFactorOutcome::Required | LoginFactorOutcome::Invalid => false,
        },
    };
    if !valid {
        tx.rollback().await.map_err(|error| {
            AstralError::Database(format!("Rollback MFA management failed: {error}"))
        })?;
        if let Some((attempt_id, method, _)) = &attempt {
            resolve_mfa_attempt_for_actor(
                pool,
                attempt_id,
                context.user_id,
                method,
                false,
                Some("invalid MFA factor"),
            )
            .await
            .map_err(db_err)?;
        }
        return Ok(false);
    }
    let action = match mutation {
        MfaMutation::Stage {
            method,
            secret,
            hashes,
        } => {
            if rows
                .iter()
                .any(|row| row.mfa_type == method && row.is_enabled == 1)
            {
                return Err(AstralError::Validation(
                    "Disable the active factor before staging its replacement".into(),
                )
                .into());
            }
            sqlx::query(STAGE_FACTOR_SQL)
                .bind(context.user_id)
                .bind(method)
                .bind(secret)
                .bind(hashes)
                .execute(&mut *tx)
                .await
                .map_err(|error| {
                    AstralError::Database(format!("Stage MFA factor failed: {error}"))
                })?;
            "stage"
        }
        MfaMutation::Disable { method } => {
            sqlx::query(
                "UPDATE user_mfa SET is_enabled = 0, is_primary = 0, secret_enc = NULL, \
                backup_codes_hash = NULL, verified_at = NULL, updated_at = CURRENT_TIMESTAMP \
                WHERE user_id = ? AND (? = 'ALL' OR mfa_type = ?)",
            )
            .bind(context.user_id)
            .bind(method)
            .bind(method)
            .execute(&mut *tx)
            .await
            .map_err(|error| {
                AstralError::Database(format!("Disable MFA factors failed: {error}"))
            })?;
            "disable"
        }
        MfaMutation::Regenerate { hashes } => {
            sqlx::query(
                "INSERT INTO user_mfa (user_id, mfa_type, backup_codes_hash, is_enabled, \
                is_primary, backup_codes_used) VALUES (?, 'RECOVERY_CODES', ?, 1, 1, 0) \
                ON DUPLICATE KEY UPDATE backup_codes_hash = VALUES(backup_codes_hash), \
                is_enabled = 1, backup_codes_used = 0, verified_at = CURRENT_TIMESTAMP, \
                updated_at = CURRENT_TIMESTAMP",
            )
            .bind(context.user_id)
            .bind(hashes)
            .execute(&mut *tx)
            .await
            .map_err(|error| {
                AstralError::Database(format!("Regenerate MFA recovery codes failed: {error}"))
            })?;
            "regenerate"
        }
        MfaMutation::Verify { .. } => "verify",
    };
    if let Some((attempt_id, method, _)) = &attempt {
        resolve_mfa_attempt_in_tx(&mut tx, attempt_id, context.user_id, method, true, None).await?;
    }
    let detail = serde_json::json!({
        "operationId": context.operation_id,
        "credentialVersion": current.as_ref().unwrap().credential_version,
        "attemptId": attempt.as_ref().map(|attempt| &attempt.0),
        "factorMethod": method,
    })
    .to_string();
    sqlx::query(
        "INSERT INTO audit_log (user_id, card_id, action, resource, decision, \
        event_type, source_ip, request_id, domain_id, tenant_id, detail) \
        VALUES (?, ?, ?, 'identity_users', 'SUCCESS', 'IDENTITY_MFA_MUTATION', ?, ?, ?, ?, ?)",
    )
    .bind(context.user_id)
    .bind(context.card_id)
    .bind(action)
    .bind(client.0)
    .bind(&context.operation_id)
    .bind(context.domain_id)
    .bind(context.tenant_id)
    .bind(detail)
    .execute(&mut *tx)
    .await
    .map_err(|error| AstralError::Database(format!("Write MFA mutation audit failed: {error}")))?;
    crate::srv::source_writer_guard::arm_commit_fence(&source_guard);
    tx.commit()
        .await
        .map_err(|error| AstralError::Database(format!("Commit MFA mutation failed: {error}")))?;
    crate::srv::source_writer_guard::settle_commit_fence(&source_guard, true);
    Ok(true)
}

/// 检查暴力破解防护
async fn check_brute_force_protection(
    pool: &sqlx::MySqlPool,
    user_id: i64,
) -> Result<(), AppError> {
    let failures = count_recent_mfa_failures(pool, user_id, MFA_FAILURE_WINDOW_MINUTES)
        .await
        .map_err(db_err)?;
    if failures >= MFA_FAILURE_MAX_COUNT {
        return Err(AppError::from(AstralError::Auth(format!(
            "Too many MFA failures ({}/{} in last {}min). Try again later.",
            failures, MFA_FAILURE_MAX_COUNT, MFA_FAILURE_WINDOW_MINUTES
        ))));
    }
    Ok(())
}

/// MFA 路由
pub fn mfa_routes() -> Router<AppState> {
    Router::new()
        .route("/mfa/status", get(get_mfa_status))
        .route("/mfa/enable", post(enable_mfa))
        .route("/mfa/disable", post(disable_mfa))
        .route("/mfa/verify", post(verify_mfa))
        .route("/mfa/recovery-codes", post(regenerate_recovery_codes))
}

/// GET /api/v1/auth/mfa/status
async fn get_mfa_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ApiResponse<MfaConfig>>, AppError> {
    let user_id = current_user_id(&headers)?;
    let enabled_list = find_enabled_mfa_for_user(&state.db, user_id)
        .await
        .map_err(db_err)?;

    if enabled_list.is_empty() {
        return Ok(Json(ApiResponse::success(MfaConfig {
            enabled: false,
            method: "NONE".into(),
            recovery_codes: vec![],
            totp_secret_b32: None,
            created_at: "".into(),
        })));
    }

    let first = &enabled_list[0];
    let methods: Vec<String> = enabled_list.iter().map(|m| m.mfa_type.clone()).collect();
    Ok(Json(ApiResponse::success(MfaConfig {
        enabled: true,
        method: methods.join(","),
        recovery_codes: vec![],
        totp_secret_b32: None,
        created_at: first.verified_at.map(|t| t.to_string()).unwrap_or_default(),
    })))
}

/// POST /api/v1/auth/mfa/enable
async fn enable_mfa(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<EnableMfaRequest>,
) -> Result<Json<ApiResponse<MfaConfig>>, AppError> {
    let context = MfaMutationContext::from_headers(&headers)?;
    if !matches!(req.method.as_str(), "RECOVERY_CODES" | "TOTP") {
        return Err(AstralError::Validation("method must be TOTP or RECOVERY_CODES".into()).into());
    }
    let credential = verify_management_password(
        &state.db,
        context.user_id,
        req.password.as_deref().unwrap_or(""),
    )
    .await?;
    let now = time::OffsetDateTime::now_utc();
    let (totp_secret_b32, encrypted, plain_codes, hashes) = if req.method == "TOTP" {
        let (encoded, encrypted) = prepare_totp_secret()?;
        (Some(encoded), Some(encrypted), Vec::new(), None)
    } else {
        let (codes, hashes) = generate_recovery_codes();
        (None, None, codes, Some(hashes))
    };
    let accepted = mutate_mfa(
        &state.db,
        &context,
        MfaMutation::Stage {
            method: &req.method,
            secret: encrypted.as_deref(),
            hashes: hashes.as_deref(),
        },
        Some(&credential),
        (req.factor_method.as_deref(), req.factor_code.as_deref()),
        extract_client_info(&headers),
    )
    .await?;
    if !accepted {
        return Err(AstralError::Auth("Invalid MFA code".into()).into());
    }
    Ok(Json(ApiResponse::success(MfaConfig {
        enabled: false,
        method: req.method,
        recovery_codes: plain_codes,
        totp_secret_b32,
        created_at: now.to_string(),
    })))
}

/// POST /api/v1/auth/mfa/disable
async fn disable_mfa(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DisableMfaRequest>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let context = MfaMutationContext::from_headers(&headers)?;
    let method = req.method.as_deref().unwrap_or("ALL");
    if !matches!(method, "ALL" | "TOTP" | "RECOVERY_CODES") {
        return Err(
            AstralError::Validation("method must be ALL, TOTP or RECOVERY_CODES".into()).into(),
        );
    }
    let credential = verify_management_password(
        &state.db,
        context.user_id,
        req.password.as_deref().unwrap_or(""),
    )
    .await?;
    if !mutate_mfa(
        &state.db,
        &context,
        MfaMutation::Disable { method },
        Some(&credential),
        (req.factor_method.as_deref(), req.factor_code.as_deref()),
        extract_client_info(&headers),
    )
    .await?
    {
        return Err(AstralError::Auth("Invalid MFA code".into()).into());
    }
    tracing::warn!(user_id = context.user_id, method, "MFA disabled");
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DisableMfaRequest {
    method: Option<String>,
    password: Option<String>,
    factor_method: Option<String>,
    factor_code: Option<String>,
}

/// POST /api/v1/auth/mfa/verify — 验证 MFA 码
async fn verify_mfa(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<VerifyMfaRequest>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let context = MfaMutationContext::from_headers(&headers)?;
    let method = req.method.as_deref().unwrap_or("TOTP");
    if !matches!(method, "TOTP" | "RECOVERY_CODES") {
        return Err(AstralError::Validation("method must be TOTP or RECOVERY_CODES".into()).into());
    }
    let credential = match req.password.as_deref() {
        Some(password) => {
            Some(verify_management_password(&state.db, context.user_id, password).await?)
        }
        None => None,
    };
    if !mutate_mfa(
        &state.db,
        &context,
        MfaMutation::Verify {
            method,
            code: &req.code,
        },
        credential.as_ref(),
        (None, None),
        extract_client_info(&headers),
    )
    .await?
    {
        return Err(AstralError::Auth("Invalid MFA code".into()).into());
    }
    tracing::info!(
        user_id = context.user_id,
        method,
        "MFA code consumed without issuing a grant"
    );
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

/// POST /api/v1/auth/mfa/recovery-codes — 重新生成恢复码
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegenerateRecoveryCodesRequest {
    password: String,
    factor_method: Option<String>,
    factor_code: Option<String>,
}

async fn regenerate_recovery_codes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegenerateRecoveryCodesRequest>,
) -> Result<Json<ApiResponse<Vec<String>>>, AppError> {
    let context = MfaMutationContext::from_headers(&headers)?;
    let credential = verify_management_password(&state.db, context.user_id, &req.password).await?;
    let (plain_codes, hashes) = generate_recovery_codes();
    if !mutate_mfa(
        &state.db,
        &context,
        MfaMutation::Regenerate { hashes: &hashes },
        Some(&credential),
        (req.factor_method.as_deref(), req.factor_code.as_deref()),
        extract_client_info(&headers),
    )
    .await?
    {
        return Err(AstralError::Auth("Invalid MFA code".into()).into());
    }
    tracing::info!(
        user_id = context.user_id,
        "recovery codes regenerated after reauthentication"
    );
    Ok(Json(ApiResponse::success(plain_codes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factor_sql_has_no_literal_line_continuations() {
        for sql in [CONSUME_TOTP_SQL, CONSUME_RECOVERY_SQL, STAGE_FACTOR_SQL] {
            assert!(!sql.contains('\\'));
        }
        assert_eq!(CONSUME_TOTP_SQL.matches('?').count(), 7);
        assert_eq!(CONSUME_RECOVERY_SQL.matches('?').count(), 8);
        assert!(CONSUME_TOTP_SQL.contains("last_totp_counter < ?"));
        assert!(CONSUME_RECOVERY_SQL.contains("backup_codes_hash = ?"));
    }

    #[test]
    fn management_reauthentication_pins_exact_credential() {
        let credential =
            |user_id, credential_version, hash: &str| crate::auth::PasswordCredential {
                user_id,
                credential_version,
                password_hash: hash.into(),
                status: "ACTIVE".into(),
            };
        let expected = credential(42, 3, "hash-a");
        assert!(management_credential_matches(
            &credential(42, 3, "hash-a"),
            Some(&expected),
            42
        ));
        assert!(!management_credential_matches(
            &credential(42, 4, "hash-a"),
            Some(&expected),
            42
        ));
        assert!(!management_credential_matches(
            &credential(42, 3, "hash-b"),
            Some(&expected),
            42
        ));
        assert!(!management_credential_matches(
            &credential(43, 3, "hash-a"),
            Some(&expected),
            42
        ));
        assert!(!management_credential_matches(
            &credential(42, 0, "hash-a"),
            None,
            42
        ));
    }

    #[test]
    fn management_context_requires_platform_pair_and_request_identity() {
        let mut headers = HeaderMap::new();
        assert!(MfaMutationContext::from_headers(&headers).is_err());
        for (name, value) in [
            ("x-principal-kind", "PLATFORM_USER"),
            ("x-user-id", "42"),
            ("x-identity-card-id", "100"),
            ("x-user-card-id", "101"),
            ("x-user-card-tenant-id", "7"),
            ("x-user-card-domain-id", "8"),
            ("x-request-id", "mfa-request-42"),
        ] {
            headers.insert(name, value.parse().unwrap());
        }
        assert!(MfaMutationContext::from_headers(&headers).is_ok());
        headers.remove("x-request-id");
        assert!(MfaMutationContext::from_headers(&headers).is_err());
        headers.insert("x-request-id", "mfa-request-42".parse().unwrap());
        headers.insert("x-user-card-tenant-id", "0".parse().unwrap());
        assert!(MfaMutationContext::from_headers(&headers).is_err());
        headers.insert("x-user-card-tenant-id", "7".parse().unwrap());
        headers.insert("x-principal-kind", "APP_USER".parse().unwrap());
        assert!(MfaMutationContext::from_headers(&headers).is_err());
    }

    #[test]
    fn management_proof_mutation_and_audit_share_fenced_transaction() {
        let source = include_str!("mfa.rs").split("#[cfg(test)]").next().unwrap();
        let body = source
            .split("async fn mutate_mfa(")
            .nth(1)
            .unwrap()
            .split("async fn check_brute_force_protection(")
            .next()
            .unwrap();
        let guard = body
            .find("source_writer_guard::begin_source_write()?")
            .unwrap();
        let begin = body.find("pool.begin()").unwrap();
        let consume = body.find("consume_login_factor_in_tx(").unwrap();
        let mutate = body.find("sqlx::query(STAGE_FACTOR_SQL)").unwrap();
        let audit = body.find("INSERT INTO audit_log").unwrap();
        let arm = body.find("arm_commit_fence(&source_guard)").unwrap();
        let commit = body.find("tx.commit()").unwrap();
        let settle = body
            .find("settle_commit_fence(&source_guard, true)")
            .unwrap();
        assert!(guard < begin && begin < consume && consume < mutate && mutate < audit);
        assert!(audit < arm && arm < commit && commit < settle);
        let login = source
            .split("pub(crate) async fn consume_login_factor_in_tx(")
            .nth(1)
            .unwrap()
            .split("pub(crate) async fn resolve_mfa_attempt_in_tx(")
            .next()
            .unwrap();
        assert!(login.contains("verify_factor_in_tx("));
        assert!(!login.contains("UPDATE user_mfa"));
    }

    #[test]
    fn legacy_bare_ciphertext_is_rejected() {
        std::env::set_var(
            "IDENTITY_MFA_AES_GCM_KEY",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        );
        let error = decrypt_totp_secret(b"legacy-ciphertext").expect_err("legacy MFA must deny");
        assert!(matches!(
            error.0,
            AstralError::Auth(message) if message == "MFA legacy ciphertext is not accepted"
        ));
    }
}
