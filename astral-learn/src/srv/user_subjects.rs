//! 用户学科 — HTTP adapter
//!
//! 对应 Java `UserSubjectsController`。数据访问在
//! `repository::user_subject_repository`。授权（require_same_user）保留在此层。
//! 表: `learn_user_subject`

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
pub struct UserSubject {
    pub id: i64,
    pub user_id: i64,
    pub subject_id: i64,
    pub enrolled_at: Option<time::OffsetDateTime>,
}

impl From<crate::repository::user_subject_repository::UserSubjectRecord> for UserSubject {
    fn from(r: crate::repository::user_subject_repository::UserSubjectRecord) -> Self {
        Self {
            id: r.id,
            user_id: r.user_id,
            subject_id: r.subject_id,
            enrolled_at: r.enrolled_at,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollSubjectReq {
    pub user_id: i64,
    pub subject_id: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListUserSubjectsQuery {
    pub user_id: i64,
    pub page: Option<u32>,
    pub size: Option<u32>,
}

pub fn user_subject_routes() -> Router<AppState> {
    Router::new()
        .route("/user-subjects", get(list_user_subjects))
        .route("/user-subjects", post(enroll_subject))
}

async fn list_user_subjects(
    headers: HeaderMap,
    State(state): State<AppState>,
    Query(query): Query<ListUserSubjectsQuery>,
) -> Result<Json<ApiResponse<PageResponse<UserSubject>>>, AppError> {
    require_same_user(authenticated_user_id(&headers)?, query.user_id)?;
    let page = query.page.unwrap_or(1).max(1);
    let size = query.size.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * size;

    let total = state.user_subject_repository.count(query.user_id).await?;
    let items = state
        .user_subject_repository
        .list(query.user_id, size as i64, offset as i64)
        .await?
        .into_iter()
        .map(UserSubject::from)
        .collect();

    Ok(Json(ApiResponse::success(PageResponse::new(
        items,
        total,
        page as i64,
        size as i64,
    ))))
}

async fn enroll_subject(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<EnrollSubjectReq>,
) -> Result<Json<ApiResponse<UserSubject>>, AppError> {
    require_same_user(authenticated_user_id(&headers)?, req.user_id)?;
    let id = state
        .user_subject_repository
        .enroll(req.user_id, req.subject_id)
        .await?;
    Ok(Json(ApiResponse::success(UserSubject {
        id,
        user_id: req.user_id,
        subject_id: req.subject_id,
        enrolled_at: None,
    })))
}
