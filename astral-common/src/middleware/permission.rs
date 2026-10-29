//! 权限检查中间件与工具函数
//!
//! `extract_user_id()` 从请求头提取用户身份。

use axum::http::HeaderMap;

/// 提取 x-user-id 头
pub fn extract_user_id(headers: &HeaderMap) -> Option<i64> {
    headers
        .get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<i64>().ok())
}
