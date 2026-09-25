//! 作业提交管理 API — HTTP adapter
//!
//! 数据访问在 `repository::assignment_repository`（SubmissionRow 边界）。
//! 授权（require_same_user）保留在此层。

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::access::{authenticated_user_id, require_same_user};
use crate::AppState;
use astral_common::contract::{ApiResponse, EmptyResponse, PageResponse};
use astral_common::error::AppError;

#[derive(Debug, sqlx::FromRow)]
pub struct SubmissionRow {
    pub id: i64,
    pub assignment_id: i64,
    pub student_id: i64,
    pub content: Option<String>,
    pub file_url: Option<String>,
    pub score: Option<f64>,
    pub feedback: Option<String>,
    pub status: String,
}

impl From<crate::repository::assignment_repository::SubmissionRowRecord> for SubmissionRow {
    fn from(r: crate::repository::assignment_repository::SubmissionRowRecord) -> Self {
        Self {
            id: r.id,
            assignment_id: r.assignment_id,
            student_id: r.student_id,
            content: r.content,
            file_url: r.file_url,
            score: r.score,
            feedback: r.feedback,
            status: r.status,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmissionDto {
    pub id: Option<i64>,
    pub assignment_id: i64,
    pub student_id: i64,
    pub content: Option<String>,
    pub file_url: Option<String>,
    pub score: Option<f64>,
    pub feedback: Option<String>,
    pub status: Option<String>,
}

impl From<SubmissionRow> for SubmissionDto {
    fn from(r: SubmissionRow) -> Self {
        SubmissionDto {
            id: Some(r.id),
            assignment_id: r.assignment_id,
            student_id: r.student_id,
            content: r.content,
            file_url: r.file_url,
            score: r.score,
            feedback: r.feedback,
            status: Some(r.status),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GradeRequest {
    pub score: f64,
    pub feedback: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListSubmissionsQuery {
    pub page: Option<i64>,
    pub size: Option<i64>,
}

pub fn submission_routes() -> Router<AppState> {
    Router::new()
        .route("/submissions", get(list_submissions))
        .route("/submissions", post(create_submission))
        .route("/submissions/{id}", get(get_submission))
        .route("/submissions/{id}", put(update_submission))
        .route("/submissions/{id}", delete(delete_submission))
        .route("/submissions/{id}/grade", post(grade_submission))
}

async fn list_submissions(
    State(state): State<AppState>,
    Query(query): Query<ListSubmissionsQuery>,
) -> Result<Json<ApiResponse<PageResponse<SubmissionDto>>>, AppError> {
    let page = query.page.unwrap_or(1).max(1);
    let size = query.size.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * size;

    let total = state.assignment_repository.count_submissions().await?;
    let items = state
        .assignment_repository
        .list_submissions_page(size, offset)
        .await?
        .into_iter()
        .map(SubmissionRow::from)
        .map(SubmissionDto::from)
        .collect();

    Ok(Json(ApiResponse::success(PageResponse::new(
        items, total, page, size,
    ))))
}

async fn create_submission(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<SubmissionDto>,
) -> Result<Json<ApiResponse<SubmissionDto>>, AppError> {
    require_same_user(authenticated_user_id(&headers)?, req.student_id)?;
    let id = state
        .assignment_repository
        .create_submission(
            req.assignment_id,
            req.student_id,
            req.content.as_deref(),
            req.file_url.as_deref(),
        )
        .await?;
    Ok(Json(ApiResponse::success(SubmissionDto {
        id: Some(id),
        status: Some("SUBMITTED".into()),
        ..req
    })))
}

async fn get_submission(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<SubmissionDto>>, AppError> {
    let row = state
        .assignment_repository
        .get_submission(id)
        .await?
        .map(SubmissionRow::from)
        .ok_or_else(|| {
            AppError(astral_types::AstralError::Internal(
                "Submission not found".into(),
            ))
        })?;
    Ok(Json(ApiResponse::success(SubmissionDto::from(row))))
}

async fn update_submission(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<SubmissionDto>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    require_same_user(authenticated_user_id(&headers)?, req.student_id)?;
    // 修复原 handler 缺失 bind 的潜在运行时错误：SQL 4 个占位符补齐 user_id 绑定
    state
        .assignment_repository
        .update_submission(
            id,
            req.student_id,
            req.content.as_deref(),
            req.file_url.as_deref(),
        )
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn delete_submission(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    state.assignment_repository.delete_submission(id).await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn grade_submission(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<GradeRequest>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    state
        .assignment_repository
        .grade_submission_by_id(id, req.score, req.feedback.as_deref())
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}
