//! App端考试 — 提交与结果
//!
//! 对应 Java `UserExamController`。
//! 复用 exam 表；数据访问在 `repository::exam_repository`，计分在 `service::exam_service`。
//! 授权（require_same_user）保留在此层。

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;

use crate::access::{authenticated_user_id, require_same_user};
use crate::AppState;
use astral_common::contract::ApiResponse;
use astral_common::error::AppError;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitExamReq {
    pub user_id: i64,
    #[serde(default)]
    pub answers: Option<serde_json::Value>,
}

pub fn exam_app_routes() -> Router<AppState> {
    Router::new()
        .route("/exams/{id}/submit", post(submit_exam_app))
        .route("/exams/{id}/result", get(get_exam_result))
}

async fn submit_exam_app(
    headers: HeaderMap,
    State(_state): State<AppState>,
    Path(_id): Path<i64>,
    Json(req): Json<SubmitExamReq>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    require_same_user(authenticated_user_id(&headers)?, req.user_id)?;
    let _answers = req.answers;
    Err(astral_types::AstralError::NotImplemented(
        "Exam submissions require a durable server-scored result model".into(),
    )
    .into())
}

async fn get_exam_result(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    let _user_id = authenticated_user_id(&headers)?;
    let exam = state
        .exam_repository
        .get_info(id)
        .await?
        .ok_or_else(|| astral_types::AstralError::Validation("Exam not found".into()))?;
    Ok(Json(ApiResponse::success(serde_json::json!({
        "examId": id,
        "title": exam.title,
        "totalScore": exam.total_score,
        "passScore": exam.pass_score,
        "status": exam.status,
    }))))
}
