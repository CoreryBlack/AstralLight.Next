//! 首答记录 — HTTP adapter
//!
//! 对应 Java `QuestionFirstAttemptController`。
//! 数据访问在 `repository::progress_repository`。授权（require_same_user）保留在此层。
//! 表: `learn_question_first_attempt`

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::access::{authenticated_user_id, require_same_user};
use crate::AppState;
use astral_common::contract::{ApiResponse, PageResponse};
use astral_common::error::AppError;

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct FirstAttempt {
    pub id: i64,
    pub user_id: i64,
    pub question_id: i64,
    pub subject_id: Option<i64>,
    pub is_correct: i32,
    pub attempted_at: Option<time::PrimitiveDateTime>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListFirstAttemptsQuery {
    pub user_id: i64,
    pub page: Option<u32>,
    pub size: Option<u32>,
}

pub fn first_attempt_routes() -> Router<AppState> {
    Router::new().route("/question-first-attempts", get(list_first_attempts))
}

async fn list_first_attempts(
    headers: HeaderMap,
    State(state): State<AppState>,
    Query(query): Query<ListFirstAttemptsQuery>,
) -> Result<Json<ApiResponse<PageResponse<FirstAttempt>>>, AppError> {
    require_same_user(authenticated_user_id(&headers)?, query.user_id)?;
    let page = query.page.unwrap_or(1).max(1);
    let size = query.size.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * size;

    let total = state
        .progress_repository
        .count_first_attempts(query.user_id)
        .await?;
    let items = state
        .progress_repository
        .list_first_attempts(query.user_id, size as i64, offset as i64)
        .await?
        .into_iter()
        .map(|r| FirstAttempt {
            id: r.id,
            user_id: r.user_id,
            question_id: r.question_id,
            subject_id: r.subject_id,
            is_correct: r.is_correct,
            attempted_at: r.attempted_at,
        })
        .collect();

    Ok(Json(ApiResponse::success(PageResponse::new(
        items,
        total,
        page as i64,
        size as i64,
    ))))
}
