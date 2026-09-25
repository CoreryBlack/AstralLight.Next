//! 学科管理 — HTTP adapter
//!
//! 数据访问在 `repository::subject_repository`，MQ 发布/软删/级联编排在
//! `service::subject_service`。HTTP 层仅解析参数、组装 DTO。
//! 表: `learn_subject`（platform_v4，列名 subject_id/parent_subject_id）

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::{ApiResponse, EmptyResponse, PageResponse};
use astral_common::error::AppError;

use crate::repository::subject_repository::SubjectInput;
use crate::AppState;

#[derive(Debug, Serialize, Clone, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Subject {
    pub id: i64,
    pub name: String,
    pub code: String,
    pub parent_id: Option<i64>,
    pub description: Option<String>,
    pub sort_order: i32,
    pub status: String,
}

impl From<crate::repository::subject_repository::SubjectRecord> for Subject {
    fn from(r: crate::repository::subject_repository::SubjectRecord) -> Self {
        Self {
            id: r.id,
            name: r.name,
            code: r.code,
            parent_id: r.parent_id,
            description: r.description,
            sort_order: r.sort_order,
            status: r.status,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSubjectRequest {
    pub name: String,
    pub code: String,
    pub parent_id: Option<i64>,
    pub description: Option<String>,
    pub sort_order: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListSubjectsQuery {
    pub page: Option<i64>,
    pub size: Option<i64>,
}

pub fn subject_routes() -> Router<AppState> {
    Router::new()
        .route("/subjects", get(list_subjects))
        .route("/subjects", post(create_subject))
        .route("/subjects/all", get(list_all_subjects))
        .route("/subjects/tree", get(get_subject_tree))
        .route("/subjects/{id}", get(get_subject))
        .route("/subjects/{id}", put(update_subject))
        .route("/subjects/{id}", delete(delete_subject))
}

/// GET /v1/admin/learn/subjects/all — 全量学科列表（不分页，前端下拉用）
async fn list_all_subjects(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<Subject>>>, AppError> {
    let subjects = state
        .subject_service
        .list_active()
        .await?
        .into_iter()
        .map(Subject::from)
        .collect();
    Ok(Json(ApiResponse::success(subjects)))
}

async fn list_subjects(
    State(state): State<AppState>,
    Query(query): Query<ListSubjectsQuery>,
) -> Result<Json<ApiResponse<PageResponse<Subject>>>, AppError> {
    let page = query.page.unwrap_or(1).max(1);
    let size = query.size.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * size;

    let total = state.subject_repository.count_all().await?;
    let items = state
        .subject_repository
        .list_all(size, offset)
        .await?
        .into_iter()
        .map(Subject::from)
        .collect();

    Ok(Json(ApiResponse::success(PageResponse::new(
        items, total, page, size,
    ))))
}

async fn create_subject(
    State(state): State<AppState>,
    Json(req): Json<CreateSubjectRequest>,
) -> Result<Json<ApiResponse<Subject>>, AppError> {
    let input = SubjectInput {
        name: req.name,
        code: req.code,
        parent_id: req.parent_id,
        description: req.description,
        sort_order: req.sort_order.unwrap_or(0),
    };
    let id = state.subject_repository.create(&input).await?;
    Ok(Json(ApiResponse::success(Subject {
        id,
        name: input.name,
        code: input.code,
        parent_id: input.parent_id,
        description: input.description,
        sort_order: input.sort_order,
        status: "ACTIVE".into(),
    })))
}

async fn get_subject(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<Subject>>, AppError> {
    let subject = state
        .subject_repository
        .get(id)
        .await?
        .map(Subject::from)
        .ok_or_else(|| astral_types::AstralError::Validation("Subject not found".into()))?;
    Ok(Json(ApiResponse::success(subject)))
}

async fn update_subject(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<CreateSubjectRequest>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let input = SubjectInput {
        name: req.name,
        code: req.code,
        parent_id: req.parent_id,
        description: req.description,
        sort_order: req.sort_order.unwrap_or(0),
    };
    state.subject_repository.update(id, &input).await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn delete_subject(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    // MQ 可用：先发消息再软删（避免软删后 MQ 失败产生僵尸数据）；
    // MQ 不可用：仅软删 + 告警（编排在 SubjectService）
    let operator_id = headers
        .get("X-User-Id")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(0);
    state
        .subject_service
        .delete_subject(id, operator_id)
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn get_subject_tree(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    let tree = state.subject_service.get_subject_tree().await?;
    let value = serde_json::to_value(tree).unwrap_or_default();
    Ok(Json(ApiResponse::success(value)))
}
