//! Webhook配置 — HTTP adapter
//!
//! 对应 Java `WebhookConfigsController`。数据访问在
//! `repository::webhook_config_repository`。表: `webhook_config`

use axum::extract::{Path, Query, State};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::AppState;
use astral_common::contract::{ApiResponse, EmptyResponse, PageResponse};
use astral_common::error::AppError;

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct WebhookConfig {
    pub id: i64,
    pub url: String,
    pub event_type: String,
    pub secret: Option<String>,
    pub is_active: i32,
    pub created_at: Option<time::PrimitiveDateTime>,
}

impl From<crate::repository::webhook_config_repository::WebhookConfigRecord> for WebhookConfig {
    fn from(r: crate::repository::webhook_config_repository::WebhookConfigRecord) -> Self {
        Self {
            id: r.id,
            url: r.url,
            event_type: r.event_type,
            secret: r.secret,
            is_active: r.is_active,
            created_at: r.created_at,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateWebhookReq {
    pub url: String,
    pub event_type: String,
    pub secret: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListWebhooksQuery {
    pub page: Option<u32>,
    pub size: Option<u32>,
}

pub fn webhook_config_routes() -> Router<AppState> {
    Router::new()
        .route("/webhook-configs", get(list_webhooks))
        .route("/webhook-configs", post(create_webhook))
        .route("/webhook-configs/{id}", delete(delete_webhook))
}

async fn list_webhooks(
    State(state): State<AppState>,
    Query(query): Query<ListWebhooksQuery>,
) -> Result<Json<ApiResponse<PageResponse<WebhookConfig>>>, AppError> {
    let page = query.page.unwrap_or(1).max(1);
    let size = query.size.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * size;

    let total = state.webhook_config_repository.count_all().await?;
    let items = state
        .webhook_config_repository
        .list_all(size as i64, offset as i64)
        .await?
        .into_iter()
        .map(WebhookConfig::from)
        .collect();

    Ok(Json(ApiResponse::success(PageResponse::new(
        items,
        total,
        page as i64,
        size as i64,
    ))))
}

async fn create_webhook(
    State(state): State<AppState>,
    Json(req): Json<CreateWebhookReq>,
) -> Result<Json<ApiResponse<WebhookConfig>>, AppError> {
    let id = state
        .webhook_config_repository
        .create(&req.url, &req.event_type, req.secret.as_deref())
        .await?;
    Ok(Json(ApiResponse::success(WebhookConfig {
        id,
        url: req.url,
        event_type: req.event_type,
        secret: req.secret,
        is_active: 1,
        created_at: None,
    })))
}

async fn delete_webhook(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    state.webhook_config_repository.delete(id).await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}
