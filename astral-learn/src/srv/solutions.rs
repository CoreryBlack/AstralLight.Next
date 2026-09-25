//! 题解系统 — HTTP adapter
//!
//! 对应 Java `QuestionSolutionsController`。
//! 数据访问在 `repository::solution_repository`。授权（require_same_user）保留在此层。
//! 表: `learn_question_solution`（platform_v4）

use axum::extract::{Path, Query, State};
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
pub struct QuestionSolution {
    pub id: i64,
    pub question_id: i64,
    pub user_id: i64,
    pub content: String,
    pub like_count: i32,
    pub created_at: Option<time::PrimitiveDateTime>,
}

impl From<crate::repository::solution_repository::SolutionRecord> for QuestionSolution {
    fn from(r: crate::repository::solution_repository::SolutionRecord) -> Self {
        Self {
            id: r.id,
            question_id: r.question_id,
            user_id: r.user_id,
            content: r.content,
            like_count: r.like_count,
            created_at: r.created_at,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSolutionReq {
    pub question_id: i64,
    pub content: String,
    pub user_id: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListSolutionsQuery {
    pub question_id: Option<i64>,
    pub page: Option<i64>,
    pub size: Option<i64>,
}

pub fn solution_routes() -> Router<AppState> {
    Router::new()
        .route("/solutions", get(list_solutions))
        .route("/solutions", post(create_solution))
        .route("/solutions/{id}/like", post(like_solution))
}

async fn list_solutions(
    State(state): State<AppState>,
    Query(query): Query<ListSolutionsQuery>,
) -> Result<Json<ApiResponse<PageResponse<QuestionSolution>>>, AppError> {
    let page = query.page.unwrap_or(1).max(1);
    let size = query.size.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * size;

    let total = state.solution_repository.count(query.question_id).await?;
    let items = state
        .solution_repository
        .list(query.question_id, size, offset)
        .await?
        .into_iter()
        .map(QuestionSolution::from)
        .collect();

    Ok(Json(ApiResponse::success(PageResponse::new(
        items, total, page, size,
    ))))
}

async fn create_solution(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<CreateSolutionReq>,
) -> Result<Json<ApiResponse<QuestionSolution>>, AppError> {
    require_same_user(authenticated_user_id(&headers)?, req.user_id)?;
    let id = state
        .solution_repository
        .create(req.question_id, req.user_id, &req.content)
        .await?;
    Ok(Json(ApiResponse::success(QuestionSolution {
        id,
        question_id: req.question_id,
        user_id: req.user_id,
        content: req.content,
        like_count: 0,
        created_at: None,
    })))
}

async fn like_solution(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    let hit = state.solution_repository.like(id).await?;
    if !hit {
        return Err(astral_types::AstralError::Validation("Solution not found".into()).into());
    }
    Ok(Json(ApiResponse::success(serde_json::json!({
        "solutionId": id,
        "liked": true,
    }))))
}
