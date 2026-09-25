//! 关卡 API — HTTP adapter
//!
//! 对应 Java `LevelsController` + `LevelController`。
//! 数据访问在 `repository::level_repository`，进度状态机在 `service::level_service`。
//! 授权（require_same_user）保留在此层。
//! 表: `learn_level`, `learn_level_status`, `learn_level_questions`

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::access::{authenticated_user_id, require_same_user};
use crate::repository::level_repository::LevelInput;
use crate::AppState;
use astral_common::contract::{ApiResponse, EmptyResponse, PageResponse};
use astral_common::error::AppError;

// ========== 数据模型 ==========

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Level {
    pub id: i64,
    pub subject_id: i64,
    pub name: String,
    pub sequence: i32,
    pub level_type: String,
    pub config_json: Option<String>,
    pub status: String,
    pub created_at: Option<time::PrimitiveDateTime>,
}

impl From<crate::repository::level_repository::LevelRecord> for Level {
    fn from(r: crate::repository::level_repository::LevelRecord) -> Self {
        Self {
            id: r.id,
            subject_id: r.subject_id,
            name: r.name,
            sequence: r.sequence,
            level_type: r.level_type,
            config_json: r.config_json,
            status: r.status,
            created_at: r.created_at,
        }
    }
}

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct LevelStatus {
    pub id: i64,
    pub level_id: i64,
    pub user_id: i64,
    pub status: String,
    pub score: Option<i32>,
    pub started_at: Option<time::PrimitiveDateTime>,
    pub finished_at: Option<time::PrimitiveDateTime>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct LevelQuestion {
    pub id: i64,
    pub level_id: i64,
    pub question_id: i64,
    pub sequence: i32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateLevelReq {
    pub subject_id: i64,
    pub name: String,
    pub sequence: Option<i32>,
    pub level_type: Option<String>,
    pub config_json: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartLevelReq {
    pub level_id: i64,
    pub user_id: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitAnswerReq {
    pub level_status_id: i64,
    pub answer_json: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinishLevelReq {
    pub level_status_id: i64,
    pub score: i32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListLevelsQuery {
    pub subject_id: Option<i64>,
    pub page: Option<i64>,
    pub size: Option<i64>,
}

// ========== 路由 ==========

pub fn level_routes() -> Router<AppState> {
    Router::new()
        .route("/levels", get(list_levels))
        .route("/levels", post(create_level))
        .route("/levels/{id}", put(update_level))
        .route("/levels/{id}", delete(delete_level))
}

pub fn level_app_routes() -> Router<AppState> {
    Router::new()
        .route("/levels/{id}", get(get_level_app))
        .route("/level-play/start", post(start_level))
        .route("/level-play/submit-answer", post(submit_answer))
        .route("/level-play/finish", post(finish_level))
}

// ========== 处理函数 ==========

async fn list_levels(
    State(state): State<AppState>,
    Query(query): Query<ListLevelsQuery>,
) -> Result<Json<ApiResponse<PageResponse<Level>>>, AppError> {
    let page = query.page.unwrap_or(1).max(1);
    let size = query.size.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * size;

    let total = state.level_repository.count(query.subject_id).await?;
    let items = state
        .level_repository
        .list(query.subject_id, size, offset)
        .await?
        .into_iter()
        .map(Level::from)
        .collect();

    Ok(Json(ApiResponse::success(PageResponse::new(
        items, total, page, size,
    ))))
}

async fn create_level(
    State(state): State<AppState>,
    Json(req): Json<CreateLevelReq>,
) -> Result<Json<ApiResponse<Level>>, AppError> {
    let input = LevelInput {
        subject_id: req.subject_id,
        name: req.name,
        sequence: req.sequence.unwrap_or(0),
        level_type: req.level_type.clone().unwrap_or_else(|| "NORMAL".into()),
    };
    let id = state.level_repository.create(&input).await?;
    Ok(Json(ApiResponse::success(Level {
        id,
        subject_id: input.subject_id,
        name: input.name,
        sequence: input.sequence,
        level_type: input.level_type,
        config_json: req.config_json,
        status: "ACTIVE".into(),
        created_at: None,
    })))
}

async fn update_level(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<CreateLevelReq>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    state
        .level_repository
        .update(
            id,
            &LevelInput {
                subject_id: req.subject_id,
                name: req.name,
                sequence: req.sequence.unwrap_or(0),
                level_type: req.level_type.unwrap_or_else(|| "NORMAL".into()),
            },
        )
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn delete_level(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    state.level_repository.soft_delete(id).await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn get_level_app(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    let level = state
        .level_repository
        .get_active(id)
        .await?
        .map(Level::from)
        .ok_or_else(|| astral_types::AstralError::Validation("Level not found".into()))?;
    let questions: Vec<LevelQuestion> = state
        .level_repository
        .list_questions(id)
        .await?
        .into_iter()
        .map(|r| LevelQuestion {
            id: r.id,
            level_id: r.level_id,
            question_id: r.question_id,
            sequence: r.sequence,
        })
        .collect();
    Ok(Json(ApiResponse::success(serde_json::json!({
        "level": level,
        "questions": questions,
    }))))
}

async fn start_level(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<StartLevelReq>,
) -> Result<Json<ApiResponse<LevelStatus>>, AppError> {
    require_same_user(authenticated_user_id(&headers)?, req.user_id)?;
    let status = state
        .level_service
        .start_level(req.user_id, req.level_id)
        .await?;
    Ok(Json(ApiResponse::success(status)))
}

async fn submit_answer(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<SubmitAnswerReq>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let user_id = authenticated_user_id(&headers)?;
    state
        .level_service
        .submit_answer(user_id, req.level_status_id)
        .await?;
    tracing::info!(level_status_id = req.level_status_id, "answer submitted");
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn finish_level(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<FinishLevelReq>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    let user_id = authenticated_user_id(&headers)?;
    state
        .level_service
        .finish_level(user_id, req.level_status_id, req.score)
        .await?;
    Ok(Json(ApiResponse::success(serde_json::json!({
        "levelStatusId": req.level_status_id,
        "score": req.score,
        "status": "COMPLETED",
    }))))
}
