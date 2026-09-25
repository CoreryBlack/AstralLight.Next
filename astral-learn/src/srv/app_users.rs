//! App用户端 — 登录/登出/个人信息 — HTTP adapter
//!
//! 对应 Java `AppUsersController`。
//! 登录编排（验证码原子消费 → find-or-create → 外部会话签发 → 补偿）在
//! `service::app_user_service`；数据访问在 `repository::app_user_repository`。
//! 登录必须先消费 Identity 验证码；不能仅凭手机号创建或接管用户。

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::access::authenticated_user_id;
use crate::service::app_user_service::invalid_login as login_error;
use crate::AppState;
use astral_common::contract::ApiResponse;
use astral_common::error::AppError;
use astral_types::AstralError;

// ========== 数据模型 ==========

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct AppUser {
    pub id: i64,
    pub phone: Option<String>,
    pub nickname: Option<String>,
    pub avatar_url: Option<String>,
    pub status: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppLoginReq {
    pub phone: String,
    pub code: String,
}

fn normalize_phone(phone: &str) -> Result<String, AppError> {
    let phone = phone.trim();
    let mut normalized = String::with_capacity(phone.len());
    for (index, ch) in phone.chars().enumerate() {
        if ch.is_ascii_digit() || (ch == '+' && index == 0) {
            normalized.push(ch);
        } else if !matches!(ch, ' ' | '-' | '(' | ')') {
            return Err(AppError(AstralError::Validation(
                "Invalid phone number".into(),
            )));
        }
    }
    let digit_count = normalized.chars().filter(char::is_ascii_digit).count();
    if !(7..=15).contains(&digit_count) || normalized == "+" {
        return Err(AppError(AstralError::Validation(
            "Invalid phone number".into(),
        )));
    }
    Ok(normalized)
}

fn invalid_login() -> AppError {
    // Keep missing, invalid, expired and storage failures indistinguishable to callers.
    AppError(login_error())
}

// ========== 路由注册 ==========

pub fn app_user_routes() -> Router<AppState> {
    Router::new()
        .route("/login", post(app_login))
        .route("/me", get(app_me))
        .route("/logout", post(app_logout))
        .route("/identity", get(app_identity))
        .route("/learning-profile", get(app_learning_profile))
}

async fn app_login(
    State(state): State<AppState>,
    Json(req): Json<AppLoginReq>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    let phone = normalize_phone(&req.phone).map_err(|_| invalid_login())?;
    let code = req.code.trim();
    if code.is_empty() || code.len() > 16 || !code.chars().all(|c| c.is_ascii_digit()) {
        return Err(invalid_login());
    }

    // 编排在 AppUserService：原子消费验证码（fail-closed）→ find-or-create →
    // 外部会话签发（失败补偿删除新建用户）。所有失败映射为非披露性 Auth 错误。
    let outcome = state
        .app_user_service
        .login(
            &state.config.gateway_service_uri,
            &state.config.internal_service_secret,
            phone,
            code,
        )
        .await?;

    let mut body = serde_json::json!({
        "userId": outcome.user_id,
        "isNew": outcome.is_new,
        "accessToken": outcome.session["accessToken"],
        "refreshToken": outcome.session["refreshToken"],
        "tokenType": outcome.session["tokenType"],
        "expiresInMillis": outcome.session["expiresInMillis"],
        "refreshExpiresInMillis": outcome.session["refreshExpiresInMillis"],
    });
    if let Some(p) = outcome.phone {
        body["phone"] = serde_json::Value::String(p);
    }
    if let Some(n) = outcome.nickname {
        body["nickname"] = serde_json::Value::String(n);
    }
    Ok(Json(ApiResponse::success(body)))
}

async fn app_me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    let user_id = authenticated_user_id(&headers)?;
    if user_id == 0 {
        return Err(AppError(AstralError::Validation(
            "Missing X-User-Id header".into(),
        )));
    }

    let user = state
        .app_user_repository
        .find_by_id(user_id)
        .await?
        .ok_or_else(|| AstralError::Validation("User not found".into()))?;

    Ok(Json(ApiResponse::success(serde_json::json!({
        "userId": user.id,
        "phone": user.phone,
        "nickname": user.nickname,
        "avatarUrl": user.avatar_url,
    }))))
}

async fn app_logout() -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    Ok(Json(ApiResponse::success(serde_json::json!({
        "message": "logged out"
    }))))
}

async fn app_identity(
    headers: HeaderMap,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    let user_id = authenticated_user_id(&headers)?;
    if user_id == 0 {
        return Err(AppError(AstralError::Validation(
            "Missing X-User-Id header".into(),
        )));
    }
    Ok(Json(ApiResponse::success(serde_json::json!({
        "userId": user_id,
        "identityCards": [],
    }))))
}

async fn app_learning_profile(
    headers: HeaderMap,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    let user_id = authenticated_user_id(&headers)?;
    if user_id == 0 {
        return Err(AppError(AstralError::Validation(
            "Missing X-User-Id header".into(),
        )));
    }
    Ok(Json(ApiResponse::success(serde_json::json!({
        "userId": user_id,
        "totalStudyTime": 0,
        "completedCourses": 0,
        "streakDays": 0,
    }))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phone_normalization_is_canonical_and_rejects_invalid_values() {
        assert_eq!(
            normalize_phone(" +86 138-0013-8000 ").unwrap(),
            "+8613800138000"
        );
        assert!(normalize_phone("12").is_err());
        assert!(normalize_phone("13800138000x").is_err());
    }

    #[test]
    fn login_failures_use_one_non_disclosing_auth_error() {
        let error = invalid_login();
        assert!(
            matches!(error.0, AstralError::Auth(message) if message == "Invalid login credentials")
        );
    }
}
