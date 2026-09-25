//! 已读回执
//!
//! 对应 Java `ReadReceiptController` + `ChatReadWatermarkService`。
//! 数据访问在 `repository::member_repository` / `repository::message_repository`，
//! 编排在 `service::receipt_service`。HTTP 层仅解析参数、组装 DTO。

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::ApiResponse;
use astral_common::error::AppError;

use super::util::current_chat_scope;
use crate::AppState;

/// 已读回执响应
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadReceipt {
    pub user_id: i64,
    pub conversation_id: i64,
    pub last_read_message_id: i64,
    pub unread_count: i64,
}

/// 标记已读请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadReceiptRequest {
    pub conversation_id: i64,
    pub last_read_message_id: i64,
}

/// 回执路由
pub fn receipt_routes() -> Router<AppState> {
    Router::new()
        .route("/receipts", post(mark_read))
        .route("/receipts/{conversation_id}/{user_id}", get(get_receipt))
}

/// POST /v1/chat/receipts — 标记已读
async fn mark_read(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<ReadReceiptRequest>,
) -> Result<Json<ApiResponse<ReadReceipt>>, AppError> {
    let scope = current_chat_scope(&headers)?;
    let receipt = state
        .receipt_service
        .mark_read(&scope, req.conversation_id, req.last_read_message_id)
        .await?;
    Ok(Json(ApiResponse::success(receipt)))
}

/// GET /v1/chat/receipts/{conversation_id}/{user_id} — 获取指定用户的已读回执
async fn get_receipt(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path((conversation_id, target_user_id)): Path<(i64, i64)>,
) -> Result<Json<ApiResponse<ReadReceipt>>, AppError> {
    let scope = current_chat_scope(&headers)?;
    let receipt = state
        .receipt_service
        .get_receipt(&scope, conversation_id, target_user_id)
        .await?;
    Ok(Json(ApiResponse::success(receipt)))
}
