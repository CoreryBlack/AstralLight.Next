//! 会话 API
//!
//! 对应 Java `ChatConversationController` + `ChatConversationServiceImpl`。
//! 数据访问在 `repository::conversation_repository` / `repository::member_repository`，
//! 编排在 `service::session_service`。HTTP 层仅解析参数、组装 DTO。

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::{ApiResponse, EmptyResponse, PageResponse, PaginationParams};
use astral_common::error::AppError;

use super::util::current_chat_scope;
use crate::AppState;

/// 会话响应
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct ChatSession {
    pub id: i64,
    pub name: String,
    pub conversation_type: String,
    pub member_count: i64,
    pub created_at: Option<i64>,
}

/// 创建会话请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSessionRequest {
    pub name: String,
    pub conversation_type: Option<String>,
}

/// 会话路由
pub fn session_routes() -> Router<AppState> {
    Router::new()
        .route("/sessions", post(create_session))
        .route("/sessions", get(list_sessions))
        .route("/sessions/{id}", get(get_session))
        .route("/sessions/{id}", put(update_session))
        .route("/sessions/{id}/members", get(list_members))
        .route("/sessions/{id}/members", post(add_member))
}

/// POST /v1/chat/sessions — 创建会话（创建者自动加入）
async fn create_session(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<CreateSessionRequest>,
) -> Result<Json<ApiResponse<ChatSession>>, AppError> {
    let scope = current_chat_scope(&headers)?;
    let conversation_type = req.conversation_type.unwrap_or_else(|| "GROUP".into());
    let session = state
        .session_service
        .create_session(&scope, req.name, conversation_type)
        .await?;
    Ok(Json(ApiResponse::success(session)))
}

/// GET /v1/chat/sessions — 列出当前用户参与的会话（分页）
async fn list_sessions(
    headers: HeaderMap,
    State(state): State<AppState>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<ChatSession>>>, AppError> {
    let scope = current_chat_scope(&headers)?;
    let page = params.page.max(1);
    let size = params.effective_size();
    let result = state
        .session_service
        .list_sessions(&scope, page, size)
        .await?;
    Ok(Json(ApiResponse::success(result)))
}

/// GET /v1/chat/sessions/{id} — 获取会话详情（验证成员资格）
async fn get_session(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<ChatSession>>, AppError> {
    let scope = current_chat_scope(&headers)?;
    let session = state.session_service.get_session(&scope, id).await?;
    Ok(Json(ApiResponse::success(session)))
}

/// PUT /v1/chat/sessions/{id} — 更新会话信息
async fn update_session(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let scope = current_chat_scope(&headers)?;
    let name = req.get("name").and_then(|v| v.as_str());
    state
        .session_service
        .update_session(&scope, id, name)
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

/// GET /v1/chat/sessions/{id}/members — 列出会话成员（分页）
async fn list_members(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<i64>>>, AppError> {
    let scope = current_chat_scope(&headers)?;
    let page = params.page.max(1);
    let size = params.effective_size();
    let result = state
        .session_service
        .list_members(&scope, id, page, size)
        .await?;
    Ok(Json(ApiResponse::success(result)))
}

/// POST /v1/chat/sessions/{id}/members — 添加成员
async fn add_member(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let scope = current_chat_scope(&headers)?;
    let new_member = req.get("user_id").and_then(|v| v.as_i64());
    state
        .session_service
        .add_member(&scope, id, new_member)
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}
