//! 作业与提交管理 — HTTP adapter
//!
//! 数据访问在 `repository::assignment_repository`，提交幂等编排在
//! `service::assignment_service`。授权（require_same_user）保留在此层。

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::access::{authenticated_user_id, require_same_user};
use crate::repository::assignment_repository::AssignmentInput;
use crate::AppState;
use astral_common::contract::{ApiResponse, EmptyResponse, PageResponse};
use astral_common::error::AppError;

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Assignment {
    pub id: i64,
    pub course_id: i64,
    pub title: String,
    pub description: Option<String>,
    pub max_score: f64,
    pub status: String,
}

impl From<crate::repository::assignment_repository::AssignmentRecord> for Assignment {
    fn from(r: crate::repository::assignment_repository::AssignmentRecord) -> Self {
        Self {
            id: r.id,
            course_id: r.course_id,
            title: r.title,
            description: r.description,
            max_score: r.max_score,
            status: r.status,
        }
    }
}

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Submission {
    pub id: i64,
    pub assignment_id: i64,
    pub user_id: i64,
    pub content: Option<String>,
    pub score: Option<f64>,
    pub graded: i8,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAssignmentReq {
    pub course_id: i64,
    pub title: String,
    pub description: Option<String>,
    pub max_score: Option<f64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitReq {
    pub user_id: i64,
    pub content: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GradeReq {
    pub score: f64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListAssignmentsQuery {
    pub page: Option<i64>,
    pub size: Option<i64>,
}

pub fn assignment_routes() -> Router<AppState> {
    Router::new()
        .route("/assignments", get(list_assignments))
        .route("/assignments", post(create_assignment))
        .route("/assignments/{id}", get(get_assignment))
        .route("/assignments/{id}", put(update_assignment))
        .route("/assignments/{id}", delete(delete_assignment))
        .route("/assignments/{id}/submissions", get(list_submissions))
        .route("/assignments/{id}/submit", post(submit_assignment))
        .route("/assignments/{id}/grade/{user_id}", post(grade_submission))
        .route(
            "/assignments/stats/{course_id}",
            get(get_course_assignment_stats),
        )
}

async fn list_assignments(
    State(state): State<AppState>,
    Query(query): Query<ListAssignmentsQuery>,
) -> Result<Json<ApiResponse<PageResponse<Assignment>>>, AppError> {
    let page = query.page.unwrap_or(1).max(1);
    let size = query.size.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * size;

    let total = state.assignment_repository.count_assignments().await?;
    let items = state
        .assignment_repository
        .list_assignments(size, offset)
        .await?
        .into_iter()
        .map(Assignment::from)
        .collect();

    Ok(Json(ApiResponse::success(PageResponse::new(
        items, total, page, size,
    ))))
}

fn to_input(req: &CreateAssignmentReq) -> AssignmentInput {
    AssignmentInput {
        course_id: req.course_id,
        title: req.title.clone(),
        description: req.description.clone(),
        max_score: req.max_score.unwrap_or(100.0),
    }
}

async fn create_assignment(
    State(state): State<AppState>,
    Json(req): Json<CreateAssignmentReq>,
) -> Result<Json<ApiResponse<Assignment>>, AppError> {
    let input = to_input(&req);
    let id = state
        .assignment_repository
        .create_assignment(&input)
        .await?;
    Ok(Json(ApiResponse::success(Assignment {
        id,
        course_id: input.course_id,
        title: input.title,
        description: input.description,
        max_score: input.max_score,
        status: "DRAFT".into(),
    })))
}

async fn get_assignment(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<Assignment>>, AppError> {
    let assignment = state
        .assignment_repository
        .get_assignment(id)
        .await?
        .map(Assignment::from)
        .ok_or_else(|| astral_types::AstralError::Validation("Not found".into()))?;
    Ok(Json(ApiResponse::success(assignment)))
}

async fn update_assignment(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<CreateAssignmentReq>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    state
        .assignment_repository
        .update_assignment(id, &to_input(&req))
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn delete_assignment(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    state.assignment_repository.archive_assignment(id).await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn list_submissions(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<Vec<Submission>>>, AppError> {
    let items = state
        .assignment_repository
        .list_submissions_by_assignment(id)
        .await?
        .into_iter()
        .map(|r| Submission {
            id: r.id,
            assignment_id: r.assignment_id,
            user_id: r.user_id,
            content: r.content,
            score: r.score,
            graded: r.graded,
        })
        .collect();
    Ok(Json(ApiResponse::success(items)))
}

async fn submit_assignment(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<SubmitReq>,
) -> Result<Json<ApiResponse<Submission>>, AppError> {
    require_same_user(authenticated_user_id(&headers)?, req.user_id)?;
    let submission = state
        .assignment_service
        .submit_assignment(id, req.user_id, req.content)
        .await?;
    Ok(Json(ApiResponse::success(submission)))
}

async fn grade_submission(
    State(state): State<AppState>,
    Path((id, user_id)): Path<(i64, i64)>,
    Json(req): Json<GradeReq>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    state
        .assignment_service
        .grade_submission(id, user_id, req.score)
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn get_course_assignment_stats(
    State(state): State<AppState>,
    Path(course_id): Path<i64>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    let (total, graded) = state.assignment_repository.course_stats(course_id).await?;
    Ok(Json(ApiResponse::success(serde_json::json!({
        "courseId": course_id,
        "totalAssignments": total,
        "gradedSubmissions": graded,
        "averageScore": 0.0,
    }))))
}
