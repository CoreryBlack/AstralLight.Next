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
use totp_rs::{Algorithm, Secret, TOTP};

use astral_common::contract::{ApiResponse, EmptyResponse};
use astral_common::error::AppError;
use astral_db::{
    count_recent_mfa_failures, disable_user_mfa, find_enabled_mfa_for_user, find_user_mfa,
    insert_mfa_attempt, mark_mfa_used, upsert_user_mfa,
};
use astral_types::AstralError;

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
}

/// 验证 MFA 请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyMfaRequest {
    pub code: String,
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
            .map(|_| format!("{:08}", rng.gen_range(0..100000000)))
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

/// 生成 TOTP 密钥并加密存储，返回 Base32 明文（仅用于生成 QR 码）
async fn setup_totp(pool: &sqlx::MySqlPool, user_id: i64) -> Result<Option<String>, AppError> {
    // 限定 rng 作用域，确保 ThreadRng（!Send）在 .await 前释放
    let secret_bytes: [u8; 20] = {
        let mut rng = rand::thread_rng();
        std::array::from_fn(|_| rng.gen::<u8>())
    };

    let b32_secret = base32::encode(Alphabet::Rfc4648 { padding: false }, &secret_bytes);

    // 加密密钥从环境变量注入，nonce 每次随机（防 AES-GCM nonce 复用）
    let encrypted = encrypt_totp_secret(&secret_bytes)?;

    upsert_user_mfa(pool, user_id, "TOTP", Some(&encrypted), None)
        .await
        .map_err(db_err)?;
    Ok(Some(b32_secret))
}

/// 验证 TOTP 码（解密后用 totp-rs 校验）
async fn verify_totp_code(
    pool: &sqlx::MySqlPool,
    user_id: i64,
    code: &str,
) -> Result<bool, AppError> {
    let row = match find_user_mfa(pool, user_id, "TOTP").await.map_err(db_err)? {
        Some(r) => r,
        None => return Ok(false),
    };
    if row.is_enabled != 1 {
        return Err(AppError::from(AstralError::Auth(
            "MFA TOTP not enabled".into(),
        )));
    }
    let enc = match row.secret_enc {
        Some(e) => e,
        None => {
            return Err(AppError::from(AstralError::Auth(
                "No TOTP secret stored".into(),
            )))
        }
    };

    let decrypted = decrypt_totp_secret(&enc)?;
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,  // digits
        1,  // skew (允许 ±1 步长)
        30, // step (秒)
        Secret::Raw(decrypted)
            .to_bytes()
            .map_err(|e| AstralError::Internal(format!("TOTP secret error: {e}")))?,
    )
    .map_err(|e| AstralError::Internal(format!("TOTP init failed: {e}")))?;

    Ok(totp.check_current(code).unwrap_or(false))
}

/// 验证恢复码
async fn verify_recovery_code(
    pool: &sqlx::MySqlPool,
    user_id: i64,
    code: &str,
) -> Result<bool, AppError> {
    let row = match find_user_mfa(pool, user_id, "RECOVERY_CODES")
        .await
        .map_err(db_err)?
    {
        Some(r) => r,
        None => return Ok(false),
    };
    if row.is_enabled != 1 || row.backup_codes_used as usize >= RECOVERY_CODE_COUNT {
        return Err(AppError::from(AstralError::Auth(
            "MFA recovery codes not available".into(),
        )));
    }

    let code_hash = format!("{:x}", Sha256::digest(code.as_bytes()));
    let hashes: Vec<String> = row
        .backup_codes_hash
        .as_deref()
        .map(|h| serde_json::from_str(h).unwrap_or_default())
        .unwrap_or_default();

    let valid = hashes.contains(&code_hash);
    if valid {
        mark_mfa_used(pool, user_id, "RECOVERY_CODES")
            .await
            .map_err(db_err)?;
    }
    Ok(valid)
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

/// 记录验证尝试
async fn log_verification_attempt(
    pool: &sqlx::MySqlPool,
    user_id: i64,
    mfa_type: &str,
    success: bool,
    ip: Option<&str>,
    _ua: Option<&str>, // TODO: pass ua when insert_mfa_attempt supports user_agent
) {
    let _ = insert_mfa_attempt(pool, user_id, mfa_type, success, ip, None).await;
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
    let user_id = current_user_id(&headers)?;

    if req.method != "RECOVERY_CODES" && req.method != "TOTP" {
        return Err(AppError::from(AstralError::Validation(format!(
            "Unsupported MFA method: {}",
            req.method
        ))));
    }

    let now = time::OffsetDateTime::now_utc();

    let config = if req.method == "TOTP" {
        let totp_secret_b32 = setup_totp(&state.db, user_id).await?;
        tracing::info!(user_id, method = %req.method, "MFA enabled (TOTP)");
        MfaConfig {
            enabled: true,
            method: req.method.clone(),
            recovery_codes: vec![],
            totp_secret_b32,
            created_at: now.to_string(),
        }
    } else {
        let (plain_codes, hashes_json) = generate_recovery_codes();
        upsert_user_mfa(
            &state.db,
            user_id,
            "RECOVERY_CODES",
            None,
            Some(&hashes_json),
        )
        .await
        .map_err(db_err)?;
        tracing::info!(user_id, method = %req.method, "MFA enabled");
        MfaConfig {
            enabled: true,
            method: req.method.clone(),
            recovery_codes: plain_codes,
            totp_secret_b32: None,
            created_at: now.to_string(),
        }
    };

    Ok(Json(ApiResponse::success(config)))
}

/// POST /api/v1/auth/mfa/disable
async fn disable_mfa(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DisableMfaRequest>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let user_id = current_user_id(&headers)?;
    let mfa_type = req.method.unwrap_or_else(|| "ALL".into());

    if mfa_type == "ALL" {
        for mt in ["TOTP", "RECOVERY_CODES"] {
            disable_user_mfa(&state.db, user_id, mt)
                .await
                .map_err(db_err)?;
        }
    } else {
        disable_user_mfa(&state.db, user_id, &mfa_type)
            .await
            .map_err(db_err)?;
    }

    tracing::warn!(user_id, mfa_type = %mfa_type, "MFA disabled");
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DisableMfaRequest {
    method: Option<String>,
}

/// POST /api/v1/auth/mfa/verify — 验证 MFA 码
async fn verify_mfa(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<VerifyMfaRequest>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let user_id = current_user_id(&headers)?;
    let (ip, ua) = extract_client_info(&headers);

    check_brute_force_protection(&state.db, user_id).await?;

    // 先尝试 TOTP，再尝试恢复码
    let valid = match verify_totp_code(&state.db, user_id, &req.code).await {
        Ok(true) => true,
        Ok(false) => verify_recovery_code(&state.db, user_id, &req.code).await?,
        Err(_) => false,
    };

    log_verification_attempt(&state.db, user_id, "", valid, ip, ua).await;

    if !valid {
        return Err(AppError::from(AstralError::Auth("Invalid MFA code".into())));
    }

    tracing::info!(user_id, "MFA code verified");
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

/// POST /api/v1/auth/mfa/recovery-codes — 重新生成恢复码
async fn regenerate_recovery_codes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ApiResponse<Vec<String>>>, AppError> {
    let user_id = current_user_id(&headers)?;

    let (plain_codes, hashes_json) = generate_recovery_codes();
    upsert_user_mfa(
        &state.db,
        user_id,
        "RECOVERY_CODES",
        None,
        Some(&hashes_json),
    )
    .await
    .map_err(db_err)?;

    log_verification_attempt(&state.db, user_id, "RECOVERY_CODES", true, None, None).await;

    tracing::info!(user_id, "recovery codes regenerated");
    Ok(Json(ApiResponse::success(plain_codes)))
}

#[cfg(test)]
mod tests {
    use super::*;

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
