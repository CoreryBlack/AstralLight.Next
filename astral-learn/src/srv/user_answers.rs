//! 用户答题记录 — HTTP adapter
//!
//! 对应 Java `UserAnswersController`。
//! 数据访问在 `repository::user_answer_repository`。授权（require_same_user）保留在此层。
//! 表: `user_answer`

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::access::{authenticated_user_id, require_same_user};
use crate::AppState;
use astral_common::contract::{ApiResponse, PageResponse};
use astral_common::error::AppError;

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct UserAnswer {
    pub id: i64,
    pub user_id: i64,
    pub question_id: i64,
    pub answer: Option<String>,
    pub is_correct: i32,
    pub created_at: Option<time::PrimitiveDateTime>,
}

impl From<crate::repository::user_answer_repository::UserAnswerRecord> for UserAnswer {
    fn from(r: crate::repository::user_answer_repository::UserAnswerRecord) -> Self {
        Self {
            id: r.id,
            user_id: r.user_id,
            question_id: r.question_id,
            answer: r.answer,
            is_correct: r.is_correct,
            created_at: r.created_at,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitAnswerReq {
    pub user_id: i64,
    pub question_id: i64,
    pub answer: Option<String>,
    pub is_correct: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListUserAnswersQuery {
    pub user_id: i64,
    pub page: Option<i64>,
    pub size: Option<i64>,
}

pub fn user_answer_routes() -> Router<AppState> {
    Router::new()
        .route("/user-answers", post(submit_answer))
        .route("/user-answers", get(list_user_answers))
}

async fn submit_answer(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<SubmitAnswerReq>,
) -> Result<Json<ApiResponse<UserAnswer>>, AppError> {
    require_same_user(authenticated_user_id(&headers)?, req.user_id)?;
    let id = state
        .user_answer_repository
        .create(
            req.user_id,
            req.question_id,
            req.answer.as_deref(),
            req.is_correct,
        )
        .await?;
    Ok(Json(ApiResponse::success(UserAnswer {
        id,
        user_id: req.user_id,
        question_id: req.question_id,
        answer: req.answer,
        is_correct: req.is_correct as i32,
        created_at: None,
    })))
}

async fn list_user_answers(
    headers: HeaderMap,
    State(state): State<AppState>,
    Query(query): Query<ListUserAnswersQuery>,
) -> Result<Json<ApiResponse<PageResponse<UserAnswer>>>, AppError> {
    require_same_user(authenticated_user_id(&headers)?, query.user_id)?;
    let page = query.page.unwrap_or(1).max(1);
    let size = query.size.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * size;

    let total = state.user_answer_repository.count(query.user_id).await?;
    let items = state
        .user_answer_repository
        .list(query.user_id, size, offset)
        .await?
        .into_iter()
        .map(UserAnswer::from)
        .collect();

    Ok(Json(ApiResponse::success(PageResponse::new(
        items, total, page, size,
    ))))
}
