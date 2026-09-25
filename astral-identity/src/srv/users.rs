//! 用户管理 API — HTTP adapter
//!
//! 对应 Java `UsersController`。编排在 `UserService`。

use axum::extract::{Path, Query, State};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};

use astral_common::contract::{ApiResponse, EmptyResponse, PageResponse};
use astral_common::error::AppError;
use astral_types::UserCard;

use crate::srv::user_service::{
    CreateUserRequest, SetPasswordRequest, UpdateStatusRequest, UpdateUserRequest, UserListItem,
    UserQuery,
};
use crate::AppState;

/// 用户管理路由
pub fn user_routes() -> Router<AppState> {
    Router::new()
        .route("/users", get(list_users).post(create_user))
        .route("/users/{id}", get(get_user).put(update_user))
        .route("/users/{id}/status", put(update_user_status))
        .route("/users/{id}", delete(delete_user))
        .route("/users/{id}/cards", get(list_user_cards))
        .route("/users/{id}/password", post(set_password))
}

async fn list_users(
    State(state): State<AppState>,
    Query(query): Query<UserQuery>,
) -> Result<Json<ApiResponse<PageResponse<UserListItem>>>, AppError> {
    Ok(Json(ApiResponse::success(
        state.user_service.list_users(&state, &query).await?,
    )))
}

async fn create_user(
    State(state): State<AppState>,
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    Ok(Json(ApiResponse::success(
        state.user_service.create_user(&state, &req).await?,
    )))
}

async fn get_user(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    Ok(Json(ApiResponse::success(
        state.user_service.get_user(&state, id).await?,
    )))
}

async fn update_user(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    state.user_service.update_user(&state, id, &req).await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn update_user_status(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateStatusRequest>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    state
        .user_service
        .update_user_status(&state, id, &req)
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn delete_user(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    state.user_service.delete_user(&state, id).await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn list_user_cards(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
) -> Result<Json<ApiResponse<Vec<UserCard>>>, AppError> {
    Ok(Json(ApiResponse::success(
        state.user_service.list_user_cards(&state, user_id).await?,
    )))
}

async fn set_password(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<SetPasswordRequest>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    state.user_service.set_password(&state, id, &req).await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}
