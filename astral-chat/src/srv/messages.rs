//! 消息 API
//!
//! 对应 Java `ChatMessageController` + `ChatMessageServiceImpl`。
//! 数据访问在 `repository::message_repository`，8 步发送链路编排在
//! `service::message_service`（MQ/WS 副作用经注入 trait）。
//! HTTP 层仅解析参数、组装 DTO；成员资格校验在 service。

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::{ApiResponse, EmptyResponse, PageResponse, PaginationParams};
use astral_common::error::AppError;

use super::util::current_chat_scope;
use crate::service::message_service::SendMessageInput;
use crate::AppState;

/// 消息响应
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    pub id: i64,
    pub sender_id: i64,
    pub conversation_id: i64,
    pub content: String,
    pub message_type: String,
    pub created_at: Option<i64>, // Unix timestamp
}

/// 发送消息请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendMessageRequest {
    pub conversation_id: i64,
    pub content: String,
    pub message_type: Option<String>,
}

/// 消息路由
pub fn message_routes() -> Router<AppState> {
    Router::new()
        .route("/messages", post(send_message))
        .route("/messages/{id}", get(get_message))
        .route("/messages/{id}", delete(delete_message))
        .route("/messages/session/{conversation_id}", get(list_session_messages))
}

/// POST /v1/chat/messages — 发送消息（8步链路，编排在 MessageService）
async fn send_message(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<SendMessageRequest>,
) -> Result<Json<ApiResponse<Message>>, AppError> {
    let scope = current_chat_scope(&headers)?;
    let message_type = req.message_type.unwrap_or_else(|| "TEXT".into());
    let message = state
        .message_service
        .send_message(&SendMessageInput {
            scope,
            conversation_id: req.conversation_id,
            content: req.content,
            message_type,
        })
        .await?;
    Ok(Json(ApiResponse::success(message)))
}

/// GET /v1/chat/messages/{id} — 获取单条消息
async fn get_message(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<Message>>, AppError> {
    let scope = current_chat_scope(&headers)?;
    let message = state.message_service.get_message(&scope, id).await?;
    Ok(Json(ApiResponse::success(message)))
}

/// GET /v1/chat/messages/session/{conversation_id} — 获取会话消息列表（验证成员资格，分页）
async fn list_session_messages(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(conversation_id): Path<i64>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<Message>>>, AppError> {
    let scope = current_chat_scope(&headers)?;
    let page = params.page.max(1);
    let size = params.effective_size();
    let result = state
        .message_service
        .list_session_messages(&scope, conversation_id, page, size)
        .await?;
    Ok(Json(ApiResponse::success(result)))
}

/// DELETE /v1/chat/messages/{id} — 删除消息（仅发送者可删）
async fn delete_message(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let scope = current_chat_scope(&headers)?;
    state.message_service.delete_message(&scope, id).await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}
