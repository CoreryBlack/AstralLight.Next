//! 学习进度 — HTTP adapter
//!
//! 对应 Java `LearningProgressController` + `LearningProgressService`。
//! 数据访问与准确率/连续天数计算在 `repository::progress_repository` +
//! `service::progress_service`（platform_v4）。授权（require_same_user）保留在此层。

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::access::{authenticated_user_id, require_same_user};
use crate::ownership::resolve_progress_read_ownership;
use crate::AppState;
use astral_common::contract::ApiResponse;
use astral_common::error::AppError;

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct LearningProgress {
    pub user_id: i64,
    pub subject_id: i64,
    pub total_questions: i32,
    pub completed_questions: i32,
    pub accuracy: f64,
    pub streak_days: i32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressUpdate {
    pub subject_id: i64,
    pub question_id: i64,
    pub correct: bool,
}

pub fn progress_routes() -> Router<AppState> {
    Router::new()
        .route("/progress/{user_id}/{subject_id}", get(get_progress))
        .route("/progress/{user_id}", post(update_progress))
}

async fn get_progress(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path((user_id, subject_id)): Path<(i64, i64)>,
) -> Result<Json<ApiResponse<LearningProgress>>, AppError> {
    let authenticated = authenticated_user_id(&headers)?;
    require_same_user(authenticated, user_id)?;
    let resolution = resolve_progress_read_ownership(&state.db, subject_id, user_id).await;
    if !matches!(
        resolution,
        astral_db::ResourceOwnershipResolution::TenantScoped { .. }
    ) {
        tracing::warn!(
            subject_id,
            user_id,
            ownership = resolution.code(),
            "Learn progress source ownership unresolved; refusing read"
        );
        return Err(astral_types::AstralError::Permission(
            "Progress source ownership is unresolved".into(),
        )
        .into());
    }
    let progress = state
        .progress_service
        .get_progress(user_id, subject_id)
        .await?;
    Ok(Json(ApiResponse::success(progress)))
}

async fn update_progress(
    headers: HeaderMap,
    State(_state): State<AppState>,
    Path(user_id): Path<i64>,
    Json(req): Json<ProgressUpdate>,
) -> Result<Json<ApiResponse<LearningProgress>>, AppError> {
    require_same_user(authenticated_user_id(&headers)?, user_id)?;
    let _ = req;
    Err(astral_types::AstralError::NotImplemented(
        "Progress updates require server-scored persisted answers; client correctness is not accepted".into(),
    )
    .into())
}
