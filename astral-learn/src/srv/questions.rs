//! 题目管理 — HTTP adapter
//!
//! 数据访问在 `repository::question_repository`（含批量导入单事务）。

use axum::extract::{Path, Query, State};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::AppState;
use astral_common::contract::{ApiResponse, EmptyResponse, PageResponse};
use astral_common::error::AppError;

use crate::repository::question_repository::QuestionInput;

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Question {
    pub id: i64,
    pub subject_id: i64,
    pub title: String,
    pub content: Option<String>,
    pub question_type: String,
    pub difficulty: i32,
    pub options: Option<String>,
    pub answer: Option<String>,
    pub status: String,
}

impl From<crate::repository::question_repository::QuestionRecord> for Question {
    fn from(r: crate::repository::question_repository::QuestionRecord) -> Self {
        Self {
            id: r.id,
            subject_id: r.subject_id,
            title: r.title,
            content: r.content,
            question_type: r.question_type,
            difficulty: r.difficulty,
            options: r.options,
            answer: r.answer,
            status: r.status,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateQuestionReq {
    pub subject_id: i64,
    pub title: String,
    pub content: Option<String>,
    pub question_type: Option<String>,
    pub difficulty: Option<i32>,
    pub options: Option<serde_json::Value>,
    pub answer: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListQuestionsQuery {
    pub page: Option<i64>,
    pub size: Option<i64>,
}

pub fn question_routes() -> Router<AppState> {
    Router::new()
        .route("/questions", get(list_questions))
        .route("/questions", post(create_question))
        .route("/questions/{id}", get(get_question))
        .route("/questions/{id}", put(update_question))
        .route("/questions/{id}", delete(delete_question))
        .route("/questions/batch-import", post(batch_import_questions))
}

async fn list_questions(
    State(state): State<AppState>,
    Query(query): Query<ListQuestionsQuery>,
) -> Result<Json<ApiResponse<PageResponse<Question>>>, AppError> {
    let page = query.page.unwrap_or(1).max(1);
    let size = query.size.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * size;

    let total = state.question_repository.count_all().await?;
    let items = state
        .question_repository
        .list_all(size, offset)
        .await?
        .into_iter()
        .map(Question::from)
        .collect();

    Ok(Json(ApiResponse::success(PageResponse::new(
        items, total, page, size,
    ))))
}

fn to_input(req: &CreateQuestionReq) -> QuestionInput {
    QuestionInput {
        subject_id: req.subject_id,
        title: req.title.clone(),
        content: req.content.clone(),
        question_type: req
            .question_type
            .clone()
            .unwrap_or_else(|| "SINGLE_CHOICE".into()),
        difficulty: req.difficulty.unwrap_or(1),
        options: req.options.clone().map(|o| o.to_string()),
        answer: req.answer.clone(),
    }
}

async fn create_question(
    State(state): State<AppState>,
    Json(req): Json<CreateQuestionReq>,
) -> Result<Json<ApiResponse<Question>>, AppError> {
    let input = to_input(&req);
    let id = state.question_repository.create(&input).await?;
    Ok(Json(ApiResponse::success(Question {
        id,
        subject_id: input.subject_id,
        title: input.title,
        content: input.content,
        question_type: input.question_type,
        difficulty: input.difficulty,
        options: input.options,
        answer: input.answer,
        status: "ACTIVE".into(),
    })))
}

async fn get_question(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<Question>>, AppError> {
    let question = state
        .question_repository
        .get(id)
        .await?
        .map(Question::from)
        .ok_or_else(|| astral_types::AstralError::Validation("Not found".into()))?;
    Ok(Json(ApiResponse::success(question)))
}

async fn update_question(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<CreateQuestionReq>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    state
        .question_repository
        .update(id, &to_input(&req))
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn delete_question(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    state.question_repository.soft_delete(id).await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn batch_import_questions(
    State(state): State<AppState>,
    Json(req): Json<Vec<CreateQuestionReq>>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    let items: Vec<QuestionInput> = req.iter().map(to_input).collect();
    let count = state.question_repository.batch_import(&items).await?;
    Ok(Json(ApiResponse::success(
        serde_json::json!({"imported": count}),
    )))
}
