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
use crate::srv::source_writer_guard;
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

    // 撤销使用独立 source 写入；凭据事务失败不会恢复已撤销会话。
    // Redis/MQ 投递必须在凭据事务开启之前完成。
    revoke_all_sessions_for_user(&state, row.user_id, "PASSWORD_RESET")
        .await
        .map_err(AppError::from)?;

    // 重置令牌消费和密码更新必须在同一事务内提交。
    // COMMIT await 被取消时，source guard 保留未知结果并关闭读门。
    let source_guard = source_writer_guard::begin_source_write()?;
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

    source_writer_guard::arm_commit_fence(&source_guard);
    tx.commit()
        .await
        .map_err(|e| AppError::from(AstralError::Database(format!("{e}"))))?;
    source_writer_guard::settle_commit_fence(&source_guard, true);
    drop(source_guard);

    tracing::info!(user_id = row.user_id, "password reset completed via token");

    Ok(Json(ApiResponse::success(EmptyResponse)))
}

#[cfg(test)]
mod tests {
    /// 撤销/凭据事务顺序 + source 栅栏形状回归（源形状，无 IO）：
    /// 1. revoke_all 先于凭据事务（撤销网络不再处于事务开启窗口内）；
    /// 2. 事务 begin 前取得 source writer 栅栏；
    /// 3. COMMIT await 前武装取消栅栏。
    #[test]
    fn reset_revokes_before_the_credential_tx_and_arms_the_commit_fence() {
        let source = include_str!("password.rs");
        let body = source
            .split("async fn reset_password(")
            .nth(1)
            .expect("reset_password must stay in password.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("tests module must follow the handler");
        let revoke = body
            .find("revoke_all_sessions_for_user(&state, row.user_id")
            .expect("the reset must revoke all sessions for the user");
        let guard = body
            .find("source_writer_guard::begin_source_write()")
            .expect("the credential tx must acquire the source writer guard");
        let begin = body
            // 多行方法链：state\n .db\n .begin()
            .find(".begin()")
            .expect("the credential tx must stay");
        let arm = body
            .find("arm_commit_fence(&source_guard)")
            .expect("the commit await must be armed");
        let commit = body
            .find("tx.commit()")
            .expect("the credential tx must commit");
        assert!(
            revoke < guard && guard < begin,
            "revocation must run before the guarded credential transaction opens"
        );
        assert!(
            arm < commit,
            "the cancellation fence must arm before awaiting COMMIT"
        );
        // 历史注释不再声称撤销随事务整体回滚（撤销是 autocommit、非事务成员）。
        // needle 由片段拼出，避免本测试源码自匹配。
        let false_atomicity_claim = format!("撤销失败则直接返回错误、不提交密码变{}", "更");
        assert!(
            !body.contains(&false_atomicity_claim),
            "the false-atomicity claim must not return"
        );
    }
}
