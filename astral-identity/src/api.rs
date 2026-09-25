//! 认证 REST API — HTTP adapter
//!
//! 对应 Java `AuthController`。登录、注册、资料、改密编排在 `AuthService`。

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::{get, post, put};
use axum::{Json, Router};

use astral_common::contract::{ApiResponse, EmptyResponse};
use astral_common::error::AppError;
use astral_common::middleware::permission::extract_user_id;
use astral_types::AstralError;

use crate::auth::LoginResponse;
use crate::srv::auth_service::{ChangePasswordRequest, RegisterRequest, UpdateProfileRequest};
use crate::AppState;

pub use crate::srv::auth_service::LoginRequest;

/// 构建认证路由
pub fn auth_routes() -> Router<AppState> {
    Router::new()
        .route("/sessions", post(login))
        .route("/register", post(register))
        .route("/profile", get(get_profile))
        .route("/profile", put(update_profile))
        .route("/change-password", post(change_password))
        .route("/providers", get(list_auth_providers))
}

/// GET /api/v1/auth/providers — 返回支持的登录方式（对齐前端 auth.ts）
async fn list_auth_providers(
    State(_state): State<AppState>,
) -> Json<ApiResponse<Vec<serde_json::Value>>> {
    let providers = vec![serde_json::json!({
        "provider": "local",
        "displayName": "账号密码登录",
        "enabled": true,
        "fields": ["username", "phone", "email", "password"],
    })];
    Json(ApiResponse::success(providers))
}

/// POST /api/v1/auth/login — 用户登录（含密码迁移与 session 签发）。
async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<ApiResponse<LoginResponse>>, AppError> {
    Ok(Json(ApiResponse::success(
        state.auth_service.login(&state, &req).await?,
    )))
}

/// POST /api/v1/auth/register — 用户注册。
async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    state.auth_service.register(&state, &req).await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

/// GET /api/v1/auth/profile — 当前用户资料。
async fn get_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    let user_id = require_user_id(&headers)?;
    Ok(Json(ApiResponse::success(
        state.auth_service.get_profile(&state, user_id).await?,
    )))
}

/// PUT /api/v1/auth/profile — 更新当前用户资料。
async fn update_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<UpdateProfileRequest>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let user_id = require_user_id(&headers)?;
    state
        .auth_service
        .update_profile(&state, user_id, &req)
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

/// POST /api/v1/auth/change-password — 当前用户修改密码。
async fn change_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let user_id = require_user_id(&headers)?;
    state
        .auth_service
        .change_password(&state, user_id, &req)
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

fn require_user_id(headers: &HeaderMap) -> Result<i64, AppError> {
    extract_user_id(headers)
        .ok_or_else(|| AppError::from(AstralError::Auth("X-User-Id header required".into())))
}
