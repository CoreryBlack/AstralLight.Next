//! 考试管理 — HTTP adapter
//!
//! 数据访问在 `repository::exam_repository`，计分逻辑在 `service::exam_service`。

use axum::extract::{Path, Query, State};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::repository::exam_repository::ExamInput;
use crate::AppState;
use astral_common::contract::{ApiResponse, EmptyResponse, PageResponse};
use astral_common::error::AppError;

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Exam {
    pub id: i64,
    pub subject_id: i64,
    pub title: String,
    pub duration_minutes: i32,
    pub total_score: i32,
    pub pass_score: i32,
    pub status: String,
}

impl From<crate::repository::exam_repository::ExamRecord> for Exam {
    fn from(r: crate::repository::exam_repository::ExamRecord) -> Self {
        Self {
            id: r.id,
            subject_id: r.subject_id,
            title: r.title,
            duration_minutes: r.duration_minutes,
            total_score: r.total_score,
            pass_score: r.pass_score,
            status: r.status,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateExamReq {
    pub subject_id: i64,
    pub title: String,
    pub duration_minutes: Option<i32>,
    pub total_score: Option<i32>,
    pub pass_score: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListExamsQuery {
    pub page: Option<i64>,
    pub size: Option<i64>,
}

pub fn exam_routes() -> Router<AppState> {
    Router::new()
        .route("/exams", get(list_exams))
        .route("/exams", post(create_exam))
        .route("/exams/{id}", get(get_exam))
        .route("/exams/{id}", put(update_exam))
        .route("/exams/{id}", delete(delete_exam))
        .route("/exams/{id}/submit", post(submit_exam))
}

async fn list_exams(
    State(state): State<AppState>,
    Query(query): Query<ListExamsQuery>,
) -> Result<Json<ApiResponse<PageResponse<Exam>>>, AppError> {
    let page = query.page.unwrap_or(1).max(1);
    let size = query.size.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * size;

    let total = state.exam_repository.count_all().await?;
    let items = state
        .exam_repository
        .list_all(size, offset)
        .await?
        .into_iter()
        .map(Exam::from)
        .collect();

    Ok(Json(ApiResponse::success(PageResponse::new(
        items, total, page, size,
    ))))
}

fn to_input(req: &CreateExamReq) -> ExamInput {
    ExamInput {
        subject_id: req.subject_id,
        title: req.title.clone(),
        duration_minutes: req.duration_minutes.unwrap_or(60),
        total_score: req.total_score.unwrap_or(100),
        pass_score: req.pass_score.unwrap_or(60),
    }
}

async fn create_exam(
    State(state): State<AppState>,
    Json(req): Json<CreateExamReq>,
) -> Result<Json<ApiResponse<Exam>>, AppError> {
    let input = to_input(&req);
    let id = state.exam_repository.create(&input).await?;
    Ok(Json(ApiResponse::success(Exam {
        id,
        subject_id: input.subject_id,
        title: input.title,
        duration_minutes: input.duration_minutes,
        total_score: input.total_score,
        pass_score: input.pass_score,
        status: "DRAFT".into(),
    })))
}

async fn get_exam(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<Exam>>, AppError> {
    let exam = state
        .exam_repository
        .get(id)
        .await?
        .map(Exam::from)
        .ok_or_else(|| astral_types::AstralError::Validation("Not found".into()))?;
    Ok(Json(ApiResponse::success(exam)))
}

async fn update_exam(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<CreateExamReq>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    state.exam_repository.update(id, &to_input(&req)).await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn delete_exam(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    state.exam_repository.archive(id).await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn submit_exam(
    State(_state): State<AppState>,
    Path(_id): Path<i64>,
    Json(_req): Json<serde_json::Value>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    Err(astral_types::AstralError::NotImplemented(
        "Exam submissions require a durable server-scored result model".into(),
    )
    .into())
}
