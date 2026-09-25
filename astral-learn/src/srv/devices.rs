//! 设备管理 — HTTP adapter
//!
//! 对应 Java `DevicesController`。数据访问在 `repository::device_repository`。
//! 授权（authenticated_user_id）保留在此层。
//! 表: `learn_device`（Rust 后端创建，platform_v4 中无对应表）

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::access::authenticated_user_id;
use crate::AppState;
use astral_common::contract::{ApiResponse, EmptyResponse, PageResponse};
use astral_common::error::AppError;

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub id: i64,
    pub user_id: i64,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
    pub device_id: Option<String>,
    pub last_login_at: Option<time::PrimitiveDateTime>,
    pub created_at: Option<time::PrimitiveDateTime>,
}

impl From<crate::repository::device_repository::DeviceRecord> for Device {
    fn from(r: crate::repository::device_repository::DeviceRecord) -> Self {
        Self {
            id: r.id,
            user_id: r.user_id,
            device_name: r.device_name,
            device_type: r.device_type,
            device_id: r.device_id,
            last_login_at: r.last_login_at,
            created_at: r.created_at,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListDevicesQuery {
    pub page: Option<u32>,
    pub size: Option<u32>,
}

pub fn device_admin_routes() -> Router<AppState> {
    Router::new()
        .route("/devices", get(list_devices))
        .route("/devices/{id}", delete(delete_device))
}

pub fn device_app_routes() -> Router<AppState> {
    Router::new().route("/devices", get(list_my_devices))
}

async fn list_devices(
    State(state): State<AppState>,
    Query(query): Query<ListDevicesQuery>,
) -> Result<Json<ApiResponse<PageResponse<Device>>>, AppError> {
    let page = query.page.unwrap_or(1).max(1);
    let size = query.size.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * size;

    let total = state.device_repository.count_all().await?;
    let items = state
        .device_repository
        .list_all(size as i64, offset as i64)
        .await?
        .into_iter()
        .map(Device::from)
        .collect();

    Ok(Json(ApiResponse::success(PageResponse::new(
        items,
        total,
        page as i64,
        size as i64,
    ))))
}

async fn delete_device(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    state.device_repository.delete(id).await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn list_my_devices(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<Device>>>, AppError> {
    let user_id = authenticated_user_id(&headers)?;
    let devices = state
        .device_repository
        .list_by_user(user_id)
        .await?
        .into_iter()
        .map(Device::from)
        .collect();
    Ok(Json(ApiResponse::success(devices)))
}
