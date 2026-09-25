//! 课程发布与内容管理 — HTTP adapter
//!
//! 课程发布工作流、课时内容审批、课程归档。
//! 数据访问在 `repository::publishing_repository`，状态机编排在
//! `service::publishing_service`。授权（require_same_user）保留在此层。
//! 基于 `learn_course` 表 status + `course_workflow` 表实现（platform_v4）。

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::access::{authenticated_user_id, require_same_user};
use crate::AppState;
use astral_common::contract::ApiResponse;
use astral_common::error::AppError;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishWorkflow {
    pub course_id: i64,
    pub current_status: String,
    pub reviewer_id: Option<i64>,
    pub review_comment: Option<String>,
    pub published_at: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CourseStats {
    pub course_id: i64,
    pub total_students: i64,
    pub avg_progress: f64,
    pub completion_rate: f64,
    pub avg_score: f64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StudentProgress {
    pub user_id: i64,
    pub course_id: i64,
    pub completed_lessons: i32,
    pub total_lessons: i32,
    pub progress_pct: f64,
    pub last_activity: String,
}

pub fn publishing_routes() -> Router<AppState> {
    Router::new()
        .route("/courses/{id}/publish", post(publish_course))
        .route("/courses/{id}/archive", post(archive_course))
        .route("/courses/{id}/review", post(submit_for_review))
        .route("/courses/{id}/approve", post(approve_course))
        .route("/courses/{id}/stats", get(get_course_stats))
        .route(
            "/courses/{id}/students/{uid}/progress",
            get(get_student_progress),
        )
}

async fn publish_course(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<PublishWorkflow>>, AppError> {
    let workflow = state.publishing_service.publish_course(id).await?;
    Ok(Json(ApiResponse::success(workflow)))
}

async fn archive_course(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<PublishWorkflow>>, AppError> {
    let workflow = state.publishing_service.archive_course(id).await?;
    Ok(Json(ApiResponse::success(workflow)))
}

async fn submit_for_review(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<PublishWorkflow>>, AppError> {
    let workflow = state.publishing_service.submit_for_review(id).await?;
    Ok(Json(ApiResponse::success(workflow)))
}

async fn approve_course(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<PublishWorkflow>>, AppError> {
    let workflow = state.publishing_service.approve_course(id).await?;
    Ok(Json(ApiResponse::success(workflow)))
}

async fn get_course_stats(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<CourseStats>>, AppError> {
    let stats = state.publishing_service.course_stats(id).await?;
    Ok(Json(ApiResponse::success(stats)))
}

async fn get_student_progress(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path((course_id, user_id)): Path<(i64, i64)>,
) -> Result<Json<ApiResponse<StudentProgress>>, AppError> {
    require_same_user(authenticated_user_id(&headers)?, user_id)?;
    let progress = state
        .publishing_service
        .student_progress(course_id, user_id)
        .await?;
    Ok(Json(ApiResponse::success(progress)))
}
