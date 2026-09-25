//! 系统配置 — HTTP adapter
//!
//! 对应 Java `SystemSettingsController`。数据访问在
//! `repository::system_setting_repository`。表: `learn_system_setting`

use axum::extract::{Path, Query, State};
use axum::routing::{get, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::AppState;
use astral_common::contract::{ApiResponse, EmptyResponse, PageResponse};
use astral_common::error::AppError;

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct SystemSetting {
    pub id: i64,
    pub setting_key: String,
    pub setting_value: Option<String>,
    pub description: Option<String>,
    pub updated_at: Option<time::PrimitiveDateTime>,
}

impl From<crate::repository::system_setting_repository::SystemSettingRecord> for SystemSetting {
    fn from(r: crate::repository::system_setting_repository::SystemSettingRecord) -> Self {
        Self {
            id: r.id,
            setting_key: r.setting_key,
            setting_value: r.setting_value,
            description: r.description,
            updated_at: r.updated_at,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateSettingReq {
    pub setting_value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListSettingsQuery {
    pub page: Option<u32>,
    pub size: Option<u32>,
}

pub fn system_setting_routes() -> Router<AppState> {
    Router::new()
        .route("/system-settings", get(list_settings))
        .route("/system-settings/{key}", put(update_setting))
}

async fn list_settings(
    State(state): State<AppState>,
    Query(query): Query<ListSettingsQuery>,
) -> Result<Json<ApiResponse<PageResponse<SystemSetting>>>, AppError> {
    let page = query.page.unwrap_or(1).max(1);
    let size = query.size.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * size;

    let total = state.system_setting_repository.count_all().await?;
    let items = state
        .system_setting_repository
        .list_all(size as i64, offset as i64)
        .await?
        .into_iter()
        .map(SystemSetting::from)
        .collect();

    Ok(Json(ApiResponse::success(PageResponse::new(
        items,
        total,
        page as i64,
        size as i64,
    ))))
}

async fn update_setting(
    State(state): State<AppState>,
    Path(key): Path<String>,
    Json(req): Json<UpdateSettingReq>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let hit = state
        .system_setting_repository
        .update_by_key(&key, &req.setting_value)
        .await?;
    if !hit {
        return Err(AppError(astral_types::AstralError::Validation(
            "Setting not found".into(),
        )));
    }
    Ok(Json(ApiResponse::success(EmptyResponse)))
}
