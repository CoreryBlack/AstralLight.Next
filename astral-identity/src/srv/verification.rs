//! 邮箱/手机验证码服务
//!
//! 对应 Java `VerificationServiceImpl`。
//! 用于注册验证、密码重置、敏感操作确认。
//!
//! 验证码持久化到 verification_code 表（替代原有内存 HashMap）。

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::{ApiResponse, EmptyResponse};
use astral_common::error::AppError;
use astral_db::{
    find_valid_verification_code, insert_verification_code, mark_verification_code_verified,
};
use astral_types::AstralError;

use crate::AppState;

/// 验证码有效期（5 分钟）
const CODE_TTL_MINUTES: i64 = 5;

/// 验证码暴力破解防护：同一 (target, purpose) 在窗口内最多允许的失败次数。
/// 6 位数字验证码空间为 10^6，无限制重试可在有效期内穷举；进程内限速
/// 与验证码 TTL 同窗口，超过阈值后拒绝校验（fail-closed）。
const MAX_VERIFY_ATTEMPTS: usize = 5;
const ATTEMPT_WINDOW: time::Duration = time::Duration::minutes(5);
const MAX_TRACKED_TARGETS: usize = 4096;

/// 进程内失败尝试计数器（key = `{target}|{purpose}` → 失败时间戳队列）。
/// 跨副本不做强一致（与验证码 TTL 相比窗口极短），单副本即可阻断在线穷举；
/// Redis 分发由全局 rate_limit 中间件负责（本服务未接线，属已知差异）。
static VERIFY_FAILURES: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<String, Vec<time::OffsetDateTime>>>,
> = std::sync::OnceLock::new();

fn verify_failures(
) -> &'static std::sync::Mutex<std::collections::HashMap<String, Vec<time::OffsetDateTime>>> {
    VERIFY_FAILURES.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// 校验是否超过失败阈值：超过返回 true（调用方直接拒绝）。
fn verify_attempt_exceeded(key: &str) -> bool {
    let now = time::OffsetDateTime::now_utc();
    let mut map = verify_failures().lock().unwrap();
    // 清理过期窗口内的记录，同时截断超限表（防止未绑定目标被无界写入撑爆内存）
    let cutoff = now - ATTEMPT_WINDOW;
    if map.len() >= MAX_TRACKED_TARGETS {
        map.retain(|_, timestamps| {
            timestamps.retain(|t| *t > cutoff);
            !timestamps.is_empty()
        });
    }
    let failures = map.entry(key.to_string()).or_default();
    failures.retain(|t| *t > cutoff);
    failures.len() >= MAX_VERIFY_ATTEMPTS
}

/// 记录一次失败尝试（窗口内滑动计数）。
fn record_verify_failure(key: &str) {
    let now = time::OffsetDateTime::now_utc();
    let mut map = verify_failures().lock().unwrap();
    let cutoff = now - ATTEMPT_WINDOW;
    let failures = map.entry(key.to_string()).or_default();
    failures.retain(|t| *t > cutoff);
    failures.push(now);
}

/// 验证码请求的尝试键（target + purpose 共同限定，避免不同场景互相计数）
fn attempt_key(target: &str, purpose: &str) -> String {
    format!("{target}|{purpose}")
}

/// 发送验证码请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendCodeRequest {
    pub target: String,
    pub purpose: String,
}

/// 验证验证码请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyCodeRequest {
    pub target: String,
    pub code: String,
    pub purpose: String,
}

/// 验证码响应
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationResult {
    pub verified: bool,
    pub token: Option<String>,
}

/// DbError → AppError 辅助转换
fn db_err(e: astral_db::DbError) -> AppError {
    AppError::from(AstralError::Database(format!("{e}")))
}

/// 验证码路由
pub fn verification_routes() -> Router<AppState> {
    Router::new()
        .route("/verification/send", post(send_code))
        .route("/verification/verify", post(verify_code))
}

/// POST /api/v1/auth/verification/send — 生成验证码并写入 DB
async fn send_code(
    State(state): State<AppState>,
    Json(req): Json<SendCodeRequest>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let code = format!("{:06}", rand::random::<u32>() % 1_000_000);

    let expires_at =
        time::OffsetDateTime::now_utc().saturating_add(time::Duration::minutes(CODE_TTL_MINUTES));
    let expires_prim = time::PrimitiveDateTime::new(expires_at.date(), expires_at.time());

    insert_verification_code(&state.db, &req.target, &req.purpose, &code, &expires_prim)
        .await
        .map_err(db_err)?;

    tracing::info!(
        target = %req.target,
        purpose = %req.purpose,
        // 验证码明文不入日志（防泄露）；仅记录已存储
        "verification code stored in DB"
    );

    Ok(Json(ApiResponse::success(EmptyResponse)))
}

/// POST /api/v1/auth/verification/verify — 验证验证码（DB 比对）
async fn verify_code(
    State(state): State<AppState>,
    Json(req): Json<VerifyCodeRequest>,
) -> Result<Json<ApiResponse<VerificationResult>>, AppError> {
    let key = attempt_key(&req.target, &req.purpose);
    // 暴力破解防护：窗口内失败次数达到阈值直接拒绝（fail-closed），
    // 与验证码 TTL 对齐，避免穷举 6 位验证码。
    if verify_attempt_exceeded(&key) {
        return Err(AppError::from(AstralError::Auth(
            "Too many verification attempts, please request a new code".into(),
        )));
    }

    let row = find_valid_verification_code(&state.db, &req.target, &req.purpose)
        .await
        .map_err(db_err)?
        .ok_or_else(|| {
            AppError::from(AstralError::Auth(
                "No valid verification code found for this target".into(),
            ))
        })?;

    if row.code != req.code {
        record_verify_failure(&key);
        tracing::warn!(
            target = %req.target,
            purpose = %req.purpose,
            "invalid verification code"
        );
        return Err(AppError::from(AstralError::Auth(
            "Invalid verification code".into(),
        )));
    }

    // 验证成功后标记为已验证（一次性消费）
    mark_verification_code_verified(&state.db, row.id)
        .await
        .map_err(db_err)?;

    tracing::info!(
        target = %req.target,
        purpose = %req.purpose,
        "verification code verified"
    );

    let result = VerificationResult {
        verified: true,
        token: Some(uuid::Uuid::new_v4().to_string()),
    };

    Ok(Json(ApiResponse::success(result)))
}
