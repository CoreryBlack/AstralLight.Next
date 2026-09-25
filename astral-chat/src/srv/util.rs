//! 聊天服务共享工具函数

use astral_common::error::AppError;
use astral_types::AstralError;
use axum::http::HeaderMap;

use crate::scope::ChatScope;

/// 从请求头提取当前用户 ID（由 Gateway JWT 中间件注入 x-user-id 头）
pub fn current_user_id(headers: &HeaderMap) -> Result<i64, AppError> {
    let uid_str = headers
        .get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            tracing::warn!("missing x-user-id header");
            AstralError::Auth("Unauthorized: missing user identity".into())
        })?;

    uid_str
        .parse::<i64>()
        .map_err(|_| {
            tracing::warn!(value = %uid_str, "invalid x-user-id header");
            AstralError::Auth("Unauthorized: invalid user identity".into())
        })
        .map_err(AppError::from)
}

/// 从 Gateway 注入的物理双卡上下文构建 Chat 作用域。
pub fn current_chat_scope(headers: &HeaderMap) -> Result<ChatScope, AppError> {
    ChatScope::from_headers(headers).map_err(|reason| {
        tracing::warn!(reason, "missing or invalid Chat physical scope");
        AppError::from(AstralError::Auth(reason.into()))
    })
}
