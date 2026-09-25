//! 错题本 — HTTP adapter
//!
//! 对应 Java `WrongQuestionsController`。
//! 数据访问在 `repository::wrong_question_repository`。授权（require_same_user）
//! 保留在此层；状态流转（UNREVIEWED/REVIEWED/MASTERED）在 repository 的守卫式 UPDATE。
//! 表: `wrong_question`

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::access::{authenticated_user_id, require_same_user};
use crate::AppState;
use astral_common::contract::{ApiResponse, EmptyResponse, PageResponse};
use astral_common::error::AppError;

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct WrongQuestion {
    pub id: i64,
    pub user_id: i64,
    pub question_id: i64,
    pub subject_id: Option<i64>,
    pub status: String,
    pub reviewed_at: Option<time::PrimitiveDateTime>,
    pub mastered_at: Option<time::PrimitiveDateTime>,
    pub created_at: Option<time::PrimitiveDateTime>,
}

impl From<crate::repository::wrong_question_repository::WrongQuestionRecord> for WrongQuestion {
    fn from(r: crate::repository::wrong_question_repository::WrongQuestionRecord) -> Self {
        Self {
            id: r.id,
            user_id: r.user_id,
            question_id: r.question_id,
            subject_id: r.subject_id,
            status: r.status,
            reviewed_at: r.reviewed_at,
            mastered_at: r.mastered_at,
            created_at: r.created_at,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListWrongQuestionsQuery {
    pub user_id: i64,
    pub subject_id: Option<i64>,
    pub page: Option<i64>,
    pub size: Option<i64>,
}

pub fn wrong_question_routes() -> Router<AppState> {
    Router::new()
        .route("/wrong-questions", get(list_wrong_questions))
        .route("/wrong-questions/count", get(count_wrong_questions))
        .route("/wrong-questions/{id}/review", post(mark_reviewed))
        .route("/wrong-questions/{id}/master", post(mark_mastered))
}

async fn list_wrong_questions(
    headers: HeaderMap,
    State(state): State<AppState>,
    Query(query): Query<ListWrongQuestionsQuery>,
) -> Result<Json<ApiResponse<PageResponse<WrongQuestion>>>, AppError> {
    require_same_user(authenticated_user_id(&headers)?, query.user_id)?;
    let page = query.page.unwrap_or(1).max(1);
    let size = query.size.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * size;

    let total = state
        .wrong_question_repository
        .count(query.user_id, query.subject_id)
        .await?;
    let items = state
        .wrong_question_repository
        .list(query.user_id, query.subject_id, size, offset)
        .await?
        .into_iter()
        .map(WrongQuestion::from)
        .collect();

    Ok(Json(ApiResponse::success(PageResponse::new(
        items, total, page, size,
    ))))
}

async fn count_wrong_questions(
    headers: HeaderMap,
    State(state): State<AppState>,
    Query(query): Query<ListWrongQuestionsQuery>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    require_same_user(authenticated_user_id(&headers)?, query.user_id)?;
    let count = state
        .wrong_question_repository
        .count_unreviewed(query.user_id, query.subject_id)
        .await?;
    Ok(Json(ApiResponse::success(
        serde_json::json!({ "count": count }),
    )))
}

async fn mark_reviewed(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let user_id = authenticated_user_id(&headers)?;
    let hit = state
        .wrong_question_repository
        .mark_reviewed(id, user_id)
        .await?;
    if !hit {
        return Err(
            astral_types::AstralError::Validation("Wrong question not found".into()).into(),
        );
    }
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn mark_mastered(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let user_id = authenticated_user_id(&headers)?;
    let hit = state
        .wrong_question_repository
        .mark_mastered(id, user_id)
        .await?;
    if !hit {
        return Err(
            astral_types::AstralError::Validation("Wrong question not found".into()).into(),
        );
    }
    Ok(Json(ApiResponse::success(EmptyResponse)))
}
