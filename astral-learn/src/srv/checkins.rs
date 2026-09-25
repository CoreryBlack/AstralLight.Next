//! 签到系统 — HTTP adapter
//!
//! 对应 Java `CheckinsController`。
//! 数据访问在 `repository::checkin_repository`，今日幂等 + 奖励积分在
//! `service::checkin_service`。授权（require_same_user）保留在此层。
//! 表: `learn_checkin`

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
pub struct Checkin {
    pub id: i64,
    pub user_id: i64,
    pub checkin_date: Option<time::Date>,
    pub reward_points: i32,
    pub created_at: Option<time::PrimitiveDateTime>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCheckinReq {
    pub user_id: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListCheckinsQuery {
    pub user_id: Option<i64>,
    pub month: Option<String>, // YYYY-MM
    pub page: Option<i64>,
    pub size: Option<i64>,
}

pub fn checkin_admin_routes() -> Router<AppState> {
    Router::new().route("/checkins", get(admin_checkin_stats))
}

pub fn checkin_app_routes() -> Router<AppState> {
    Router::new()
        .route("/checkins", post(app_checkin))
        .route("/checkins", get(app_list_checkins))
}

async fn app_checkin(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<CreateCheckinReq>,
) -> Result<Json<ApiResponse<Checkin>>, AppError> {
    require_same_user(authenticated_user_id(&headers)?, req.user_id)?;
    let checkin = state.checkin_service.app_checkin(req.user_id).await?;
    Ok(Json(ApiResponse::success(checkin)))
}

async fn app_list_checkins(
    headers: HeaderMap,
    State(state): State<AppState>,
    Query(query): Query<ListCheckinsQuery>,
) -> Result<Json<ApiResponse<PageResponse<Checkin>>>, AppError> {
    let authenticated = authenticated_user_id(&headers)?;
    if let Some(target) = query.user_id {
        require_same_user(authenticated, target)?;
    }
    let user_id = query.user_id.unwrap_or(authenticated);
    let page = query.page.unwrap_or(1).max(1);
    let size = query.size.unwrap_or(20).clamp(1, 100);

    let (rows, total) = state
        .checkin_service
        .list_checkins(user_id, query.month, page, size)
        .await?;
    Ok(Json(ApiResponse::success(PageResponse::new(
        rows, total, page, size,
    ))))
}

async fn admin_checkin_stats(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    let stats = state.checkin_repository.admin_stats().await?;
    Ok(Json(ApiResponse::success(serde_json::json!({
        "totalCheckins": stats.total_checkins,
        "todayCheckins": stats.today_checkins,
        "totalRewardPoints": stats.total_reward_points,
    }))))
}
