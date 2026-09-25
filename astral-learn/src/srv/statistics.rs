//! 统计概览
//!
//! 对应 Java `StatisticsController`。
//! 从 learn_subject / learn_question / learn_course 等表实时聚合（platform_v4），
//! 数据访问在 `repository::statistics_repository`。

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};

use crate::AppState;
use astral_common::contract::ApiResponse;
use astral_common::error::AppError;

// ========== 路由注册 ==========

pub fn statistics_routes() -> Router<AppState> {
    Router::new()
        .route("/statistics/overview", get(overview))
        .route("/statistics/distribution", get(distribution))
        .route("/statistics/question-types", get(question_types))
}

// ========== 处理函数 ==========

async fn overview(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    let stats = state.statistics_repository.overview().await?;
    Ok(Json(ApiResponse::success(serde_json::json!({
        "subjectCount": stats.subject_count,
        "questionCount": stats.question_count,
        "courseCount": stats.course_count,
        "userCount": stats.user_count,
    }))))
}

async fn distribution(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    let subject_dist = state.statistics_repository.subject_distribution().await?;
    let question_dist = state
        .statistics_repository
        .question_type_distribution()
        .await?;

    Ok(Json(ApiResponse::success(serde_json::json!({
        "subjectsByStatus": subject_dist.iter().map(|r| serde_json::json!({
            "status": r.name, "count": r.cnt
        })).collect::<Vec<_>>(),
        "questionsByType": question_dist.iter().map(|r| serde_json::json!({
            "questionType": r.name, "count": r.cnt
        })).collect::<Vec<_>>(),
    }))))
}

async fn question_types(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    let type_breakdown = state
        .statistics_repository
        .question_type_distribution()
        .await?;
    Ok(Json(ApiResponse::success(serde_json::json!({
        "questionTypes": type_breakdown.iter().map(|r| serde_json::json!({
            "type": r.name, "count": r.cnt
        })).collect::<Vec<_>>(),
    }))))
}
