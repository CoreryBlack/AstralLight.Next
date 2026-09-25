//! 统一错误处理
//!
//! - `AppError` — AstralError 包装 + IntoResponse 实现
//! - `global_exception_handler` — Tower middleware 层全局异常捕获

use std::panic::AssertUnwindSafe;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_util::FutureExt;
use serde_json::json;

use astral_types::AstralError;

/// 应用层错误包装器（满足 orphan rule）
#[derive(Debug)]
pub struct AppError(pub AstralError);

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for AppError {}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, error_type, reason_code) = match &self.0 {
            AstralError::Validation(_msg) => {
                (StatusCode::BAD_REQUEST, 400, "VALIDATION_ERROR", None)
            }
            AstralError::Auth(msg) if msg.contains("OAUTH_DISABLED") => (
                StatusCode::FORBIDDEN,
                403,
                "AUTHENTICATION_ERROR",
                Some("OAUTH_DISABLED"),
            ),
            // 对齐 Java refreshAccessToken/选卡：持久化 user_card 不可用或未绑定
            // → 409 CONFLICT / CARD_SELECTION_REQUIRED，客户端需重新选卡
            AstralError::Auth(msg) if msg.contains("CARD_SELECTION_REQUIRED") => (
                StatusCode::CONFLICT,
                409,
                "CONFLICT",
                Some("CARD_SELECTION_REQUIRED"),
            ),
            // 对齐 Java BaseGlobalExceptionHandler.resolveStatusFromMessage：
            // card_not_found → 404 NOT_FOUND（资源不存在，而非认证失败）
            AstralError::Auth(msg) if msg.contains("CARD_NOT_FOUND") => (
                StatusCode::NOT_FOUND,
                404,
                "NOT_FOUND",
                Some("CARD_NOT_FOUND"),
            ),
            AstralError::Auth(_msg) => {
                (StatusCode::UNAUTHORIZED, 401, "AUTHENTICATION_ERROR", None)
            }
            AstralError::Permission(msg) if msg.contains("DEFAULT_DENY") => (
                StatusCode::FORBIDDEN,
                403,
                "PERMISSION_DENIED",
                Some("DEFAULT_DENY"),
            ),
            AstralError::Permission(msg) if msg.contains("AUTHN_REQUIRED") => (
                StatusCode::FORBIDDEN,
                403,
                "PERMISSION_DENIED",
                Some("AUTHN_REQUIRED"),
            ),
            AstralError::Permission(msg) if msg.contains("CARD_DISABLED") => (
                StatusCode::FORBIDDEN,
                403,
                "PERMISSION_DENIED",
                Some("CARD_DISABLED"),
            ),
            AstralError::Permission(_) => (StatusCode::FORBIDDEN, 403, "PERMISSION_DENIED", None),
            AstralError::Database(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                500,
                "DATABASE_ERROR",
                None,
            ),
            AstralError::NotImplemented(_) => (
                StatusCode::NOT_IMPLEMENTED,
                501,
                "NOT_IMPLEMENTED",
                Some("NOT_IMPLEMENTED"),
            ),
            AstralError::NotFound(_) => (StatusCode::NOT_FOUND, 404, "NOT_FOUND", None),
            AstralError::Cache(_) => (StatusCode::INTERNAL_SERVER_ERROR, 500, "CACHE_ERROR", None),
            AstralError::Config(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, 500, "CONFIG_ERROR", None)
            }
            AstralError::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                500,
                "INTERNAL_ERROR",
                None,
            ),
        };

        let body = json!({
            "code": code,
            "message": self.0.to_string(),
            "success": false,
            "errorType": error_type,
            "timestamp": time::OffsetDateTime::now_utc().unix_timestamp(),
            "decision": reason_code,
            "reasonCode": reason_code,
        });

        tracing::error!(error = %self.0, error_type = %error_type, "request failed");
        (status, Json(body)).into_response()
    }
}

impl From<AstralError> for AppError {
    fn from(err: AstralError) -> Self {
        AppError(err)
    }
}

/// 全局异常处理中间件（对应 Java `@ControllerAdvice` + `BaseGlobalExceptionHandler`）
///
/// 捕获请求处理过程中产生的 panic，统一返回 500 JSON 响应，避免连接挂死。
pub async fn global_exception_handler(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let req_path = req.uri().path().to_string();

    let result = AssertUnwindSafe(next.run(req)).catch_unwind().await;

    match result {
        Ok(response) => {
            // 正常响应：检查状态码，对 5xx 记录日志
            if response.status().is_server_error() {
                tracing::error!(path = %req_path, status = %response.status(), "server error response");
            }
            response
        }
        Err(panic_info) => {
            // 捕获 panic 避免连接挂死
            let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_info.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".into()
            };

            tracing::error!(path = %req_path, error = %msg, "request panicked");

            let body = json!({
                "code": 500,
                "message": "An unexpected error occurred",
                "success": false,
                "errorType": "INTERNAL_ERROR",
                "timestamp": time::OffsetDateTime::now_utc().unix_timestamp(),
            });

            (StatusCode::INTERNAL_SERVER_ERROR, Json(body)).into_response()
        }
    }
}
