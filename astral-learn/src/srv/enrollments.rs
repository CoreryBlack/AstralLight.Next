//! 报名管理 — HTTP adapter
//!
//! 数据访问在 `repository::enrollment_repository`。授权（require_same_user）
//! 保留在此层。表: `learn_course_enrollment`（platform_v4，progress_pct 列）
//! 原 `#[allow(dead_code)]` 的 create_class/list_classes/get_class/list_class_students
//! 已删除（无调用方）。

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::access::{authenticated_user_id, require_same_user};
use crate::AppState;
use astral_common::contract::{ApiResponse, EmptyResponse, PageResponse};
use astral_common::error::AppError;

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Enrollment {
    pub id: i64,
    pub user_id: i64,
    pub course_id: i64,
    pub status: String,
    pub progress_pct: f64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollReq {
    pub user_id: i64,
    pub course_id: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListEnrollmentsQuery {
    pub page: Option<i64>,
    pub size: Option<i64>,
}

pub fn enrollment_routes() -> Router<AppState> {
    Router::new()
        .route("/enrollments", post(enroll))
        .route("/enrollments/user/{user_id}", get(list_user_enrollments))
        .route("/enrollments/{id}", delete(withdraw))
}

async fn enroll(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<EnrollReq>,
) -> Result<Json<ApiResponse<Enrollment>>, AppError> {
    require_same_user(authenticated_user_id(&headers)?, req.user_id)?;
    let id = state
        .enrollment_repository
        .enroll(req.user_id, req.course_id)
        .await?;
    Ok(Json(ApiResponse::success(Enrollment {
        id,
        user_id: req.user_id,
        course_id: req.course_id,
        status: "ACTIVE".into(),
        progress_pct: 0.0,
    })))
}

async fn list_user_enrollments(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
    Query(query): Query<ListEnrollmentsQuery>,
) -> Result<Json<ApiResponse<PageResponse<Enrollment>>>, AppError> {
    require_same_user(authenticated_user_id(&headers)?, user_id)?;
    let page = query.page.unwrap_or(1).max(1);
    let size = query.size.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * size;

    let total = state.enrollment_repository.count(user_id).await?;
    let items = state
        .enrollment_repository
        .list(user_id, size, offset)
        .await?
        .into_iter()
        .map(|r| Enrollment {
            id: r.id,
            user_id: r.user_id,
            course_id: r.course_id,
            status: r.status,
            progress_pct: r.progress_pct,
        })
        .collect();

    Ok(Json(ApiResponse::success(PageResponse::new(
        items, total, page, size,
    ))))
}

async fn withdraw(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    state.enrollment_repository.withdraw(id).await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}
