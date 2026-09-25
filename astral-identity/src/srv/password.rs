//! 密码重置流程 — HTTP adapter
//!
//! 对应 Java `PasswordResetController` + `PasswordResetService`。
//! 流程：请求重置 → 验证令牌 → 设置新密码。
//! 令牌存储于 password_reset_token 表，使用 SHA-256 哈希存储；
//! 数据访问在 `astral-db`（token 表 CRUD）+ `user_repository`（密码哈希更新）。

use axum::extract::{Path, State};
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;

use astral_common::contract::{ApiResponse, EmptyResponse};
use astral_common::error::AppError;
use astral_db::{
    find_valid_password_reset_token, insert_password_reset_token,
    invalidate_user_password_reset_tokens, mark_password_reset_token_used_tx,
};
use astral_types::AstralError;

use crate::auth::{hash_password, sha256_hash, update_password_hash_tx};
use crate::srv::session::revoke_all_sessions_for_user;
use crate::AppState;

/// 请求密码重置
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestResetRequest {
    pub email: Option<String>,
    pub username: Option<String>,
}

/// 验证重置令牌并设置新密码
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetPasswordRequest {
    pub token: String,
    pub new_password: String,
}

/// DbError → AppError 辅助转换
fn db_err(e: astral_db::DbError) -> AppError {
    AppError::from(AstralError::Database(format!("{e}")))
}

/// 密码重置路由
pub fn password_reset_routes() -> Router<AppState> {
    Router::new()
        .route("/password/forgot", post(request_reset))
        .route("/password/reset/{token}", post(reset_password))
}

/// POST /api/v1/auth/password/forgot — 请求密码重置（生成令牌写入 DB）
///
/// 本路由为未认证公开路径。**不得把明文重置令牌返回给调用方**：那等价于把
/// 账户接管凭证直接交给任何能枚举用户名/邮箱的人。令牌仅以 SHA-256 哈希
/// 落库，由带外渠道（邮件/SMS）投递；当前无投递通道时返回成功标记但不
/// 泄露令牌。reset 端点仍按持有令牌方校验消费。
async fn request_reset(
    State(state): State<AppState>,
    Json(req): Json<RequestResetRequest>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    // 解析登录标识（与登录路径一致：phone(规范化) → username → email）
    let username = req
        .username
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let email = req
        .email
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if username.is_none() && email.is_none() {
        return Err(AppError::from(AstralError::Validation(
            "username or email required".into(),
        )));
    }

    // 查找登录聚合数据（复用登录路径的解析顺序与规范化）
    let agg = crate::auth::find_login_aggregate_resolved(&state.db, username, None, email)
        .await
        .map_err(AppError::from)?;

    let (user_id, login_name) = match agg {
        Some(a) => (a.user_id, a.login_name.unwrap_or_default()),
        None => {
            // 不暴露用户是否存在，返回空成功
            tracing::warn!("password reset requested for unknown user");
            return Ok(Json(ApiResponse::success(EmptyResponse)));
        }
    };

    // 作废该用户所有旧令牌
    invalidate_user_password_reset_tokens(&state.db, user_id)
        .await
        .map_err(db_err)?;

    // 生成新令牌（SHA-256 哈希存 DB，明文只应经带外渠道投递）
    let raw_token = uuid::Uuid::new_v4().to_string();
    let token_hash = sha256_hash(&raw_token);

    let expires_at = time::OffsetDateTime::now_utc().saturating_add(time::Duration::minutes(30));
    // time::PrimitiveDateTime from OffsetDateTime
    let expires_prim = time::PrimitiveDateTime::new(expires_at.date(), expires_at.time());

    insert_password_reset_token(&state.db, user_id, &login_name, &token_hash, &expires_prim)
        .await
        .map_err(db_err)?;

    tracing::info!(
        user_id,
        email = ?req.email,
        username = ?req.username,
        "password reset token stored in DB (out-of-band delivery required)"
    );

    Ok(Json(ApiResponse::success(EmptyResponse)))
}

/// POST /api/v1/auth/password/reset/:token — 使用令牌重置密码
async fn reset_password(
    State(state): State<AppState>,
    Path(token): Path<String>,
    Json(req): Json<ResetPasswordRequest>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    // 密码策略：与注册/改密路径一致，至少 8 字符
    if req.new_password.len() < 8 {
        return Err(AppError::from(AstralError::Validation(
            "Password must be at least 8 characters".into(),
        )));
    }

    // 验证 token 一致性
    let path_token = if token.is_empty() { &req.token } else { &token };
    let token_hash = sha256_hash(path_token);

    // 查找有效令牌
    let row = find_valid_password_reset_token(&state.db, &token_hash)
        .await
        .map_err(db_err)?
        .ok_or_else(|| {
            AppError::from(AstralError::Auth(
                "Invalid or expired password reset token".into(),
            ))
        })?;

    // 先哈希新密码，避免事务内执行 Argon2 阻塞连接
    let new_hash = hash_password(&req.new_password).map_err(AppError::from)?;

    // 同一事务原子完成：token 消费（replay 边界）+ 密码哈希更新。
    // 任一步失败整体回滚，避免"token 已消费但密码未改"的锁死窗口。
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| AppError::from(AstralError::Database(format!("{e}"))))?;
    if !mark_password_reset_token_used_tx(&mut tx, row.id)
        .await
        .map_err(db_err)?
    {
        return Err(AppError::from(AstralError::Auth(
            "Invalid or already used password reset token".into(),
        )));
    }
    update_password_hash_tx(&mut tx, row.user_id, &new_hash)
        .await
        .map_err(AppError::from)?;

    // 撤销该用户全部会话/family/JTI/Redis 投影，**在提交之前执行**：
    // 撤销失败则直接返回错误、不提交密码变更（fail-closed），消除
    // "密码已改但旧会话仍存活"的 fail-open 窗口。与 change_password 的
    // 先撤后改顺序一致（Java setPassword 同一事务内撤销失败整体回滚）。
    revoke_all_sessions_for_user(&state, row.user_id, "PASSWORD_RESET")
        .await
        .map_err(AppError::from)?;

    tx.commit()
        .await
        .map_err(|e| AppError::from(AstralError::Database(format!("{e}"))))?;

    tracing::info!(user_id = row.user_id, "password reset completed via token");

    Ok(Json(ApiResponse::success(EmptyResponse)))
}
