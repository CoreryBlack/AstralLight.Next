//! 文档管理 — HTTP adapter
//!
//! 对应 Java `DocumentsController`。数据访问在 `repository::document_repository`。
//! 表: `documents`

use axum::extract::{Path, Query, State};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::AppState;
use astral_common::contract::{ApiResponse, EmptyResponse, PageResponse};
use astral_common::error::AppError;

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    pub id: i64,
    pub title: String,
    pub subject_id: Option<i64>,
    pub file_url: Option<String>,
    pub file_type: Option<String>,
    pub created_at: Option<time::OffsetDateTime>,
}

impl From<crate::repository::document_repository::DocumentRecord> for Document {
    fn from(r: crate::repository::document_repository::DocumentRecord) -> Self {
        Self {
            id: r.id,
            title: r.title,
            subject_id: r.subject_id,
            file_url: r.file_url,
            file_type: r.file_type,
            created_at: r.created_at,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDocumentReq {
    pub title: String,
    pub subject_id: Option<i64>,
    pub file_url: Option<String>,
    pub file_type: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListDocumentsQuery {
    pub subject_id: Option<i64>,
    pub page: Option<i64>,
    pub size: Option<i64>,
}

pub fn document_routes() -> Router<AppState> {
    Router::new()
        .route("/documents", get(list_documents))
        .route("/documents", post(create_document))
        .route("/documents/{id}", delete(delete_document))
}

async fn list_documents(
    State(state): State<AppState>,
    Query(query): Query<ListDocumentsQuery>,
) -> Result<Json<ApiResponse<PageResponse<Document>>>, AppError> {
    let page = query.page.unwrap_or(1).max(1);
    let size = query.size.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * size;

    let total = state.document_repository.count(query.subject_id).await?;
    let items = state
        .document_repository
        .list(query.subject_id, size, offset)
        .await?
        .into_iter()
        .map(Document::from)
        .collect();

    Ok(Json(ApiResponse::success(PageResponse::new(
        items, total, page, size,
    ))))
}

async fn create_document(
    State(state): State<AppState>,
    Json(req): Json<CreateDocumentReq>,
) -> Result<Json<ApiResponse<Document>>, AppError> {
    let id = state
        .document_repository
        .create(
            &req.title,
            req.subject_id,
            req.file_url.as_deref(),
            req.file_type.as_deref(),
        )
        .await?;
    Ok(Json(ApiResponse::success(Document {
        id,
        title: req.title,
        subject_id: req.subject_id,
        file_url: req.file_url,
        file_type: req.file_type,
        created_at: None,
    })))
}

async fn delete_document(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    state.document_repository.delete(id).await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}
