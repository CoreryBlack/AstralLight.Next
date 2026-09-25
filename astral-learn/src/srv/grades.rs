//! 成绩与评分管理 — HTTP adapter
//!
//! 数据访问在 `repository::assignment_repository`，find-or-create + upsert
//! 编排在 `service::grade_service`。授权（require_same_user）保留在此层。

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::access::{authenticated_user_id, require_same_user};
use crate::AppState;
use astral_common::contract::{ApiResponse, EmptyResponse};
use astral_common::error::AppError;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Grade {
    pub id: i64,
    pub course_id: i64,
    pub user_id: i64,
    pub score: f64,
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateGradeReq {
    pub course_id: i64,
    pub user_id: i64,
    pub score: f64,
    pub comment: Option<String>,
}

pub fn grade_routes() -> Router<AppState> {
    Router::new()
        .route("/grades/course/{course_id}/user/{user_id}", get(get_grade))
        .route("/grades/course/{course_id}", get(list_course_grades))
        .route("/grades", post(submit_grade))
        .route("/grades/{id}", put(update_grade))
        .route("/grades/transcript/{user_id}", get(get_transcript))
}

async fn get_grade(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path((course_id, user_id)): Path<(i64, i64)>,
) -> Result<Json<ApiResponse<Grade>>, AppError> {
    require_same_user(authenticated_user_id(&headers)?, user_id)?;
    let grade = state.grade_service.get_grade(course_id, user_id).await?;
    Ok(Json(ApiResponse::success(grade)))
}

async fn list_course_grades(
    State(state): State<AppState>,
    Path(course_id): Path<i64>,
) -> Result<Json<ApiResponse<Vec<Grade>>>, AppError> {
    let grades = state.grade_service.list_course_grades(course_id).await?;
    Ok(Json(ApiResponse::success(grades)))
}

async fn submit_grade(
    State(state): State<AppState>,
    Json(req): Json<CreateGradeReq>,
) -> Result<Json<ApiResponse<Grade>>, AppError> {
    let grade = state
        .grade_service
        .submit_grade(req.course_id, req.user_id, req.score, req.comment)
        .await?;
    Ok(Json(ApiResponse::success(grade)))
}

async fn update_grade(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let score = req.get("score").and_then(|v| v.as_f64());
    state.grade_service.update_grade(id, score).await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn get_transcript(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    require_same_user(authenticated_user_id(&headers)?, user_id)?;
    let rows = state.assignment_repository.transcript(user_id).await?;
    let grades: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| serde_json::json!({ "courseId": r.course_id, "title": r.title, "score": r.score }))
        .collect();
    Ok(Json(ApiResponse::success(serde_json::json!({
        "userId": user_id,
        "grades": grades,
    }))))
}
