//! 权限继承配置 API — HTTP adapter
//!
//! 对齐 Java `PermissionInheritanceConfigService`。
//! 数据访问在 `repository::inheritance_config_repository`，HTTP 层仅校验白名单并包装响应。

use axum::extract::{Path, Query, State};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::{ApiResponse, EmptyResponse, PageResponse, PaginationParams};
use astral_common::error::AppError;
use astral_types::AstralError;
use astral_types::ResourceRegistry;

use crate::repository::inheritance_config_repository::InheritanceConfigRecord;
use crate::AppState;

// ===== 数据模型 =====

/// 继承配置响应 DTO（对应 permission_inheritance_config 表 camelCase）
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InheritanceConfig {
    pub id: i64,
    pub resource_type: String,
    /// 继承模式（NONE / PARENT_ONLY / CUMULATIVE）
    pub inheritance_mode: String,
    pub updated_at: Option<i64>,
}

impl From<InheritanceConfigRecord> for InheritanceConfig {
    fn from(r: InheritanceConfigRecord) -> Self {
        Self {
            id: r.id,
            resource_type: r.resource_type,
            inheritance_mode: r.inheritance_mode,
            updated_at: r.updated_at,
        }
    }
}

/// 更新继承模式请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInheritanceRequest {
    pub inheritance_mode: String,
}

/// 创建继承配置请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateInheritanceRequest {
    pub resource_type: String,
    pub inheritance_mode: String,
}

// ===== 路由注册 =====

pub fn inheritance_routes() -> Router<AppState> {
    Router::new()
        .route("/inheritance/config", get(list_inheritance_configs))
        .route("/inheritance/config", post(create_inheritance_config))
        .route(
            "/inheritance/config/{resource_type}",
            put(update_inheritance_config),
        )
        .route(
            "/inheritance/config/{resource_type}",
            delete(delete_inheritance_config),
        )
}

const VALID_MODES: [&str; 3] = ["NONE", "PARENT_ONLY", "CUMULATIVE"];

fn validate_registered_resource_type(resource_type: &str) -> Result<(), AppError> {
    let actions = ResourceRegistry::global()
        .list_actions(resource_type)
        .ok_or_else(|| {
            AppError(AstralError::Validation(format!(
                "resource_type '{resource_type}' is not registered"
            )))
        })?;
    if actions.is_empty() {
        return Err(AppError(AstralError::Validation(format!(
            "resource_type '{resource_type}' has no registered actions"
        ))));
    }
    Ok(())
}

// ===== Handlers =====

/// GET /main/api/v1/inheritance/config — 列出所有继承配置（分页）
async fn list_inheritance_configs(
    State(state): State<AppState>,
    Query(page): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<InheritanceConfig>>>, AppError> {
    let total = state.inheritance_config_repository.count_configs().await?;
    let rows = state
        .inheritance_config_repository
        .list_configs(page.effective_size(), page.offset())
        .await?
        .into_iter()
        .map(InheritanceConfig::from)
        .collect();
    Ok(Json(ApiResponse::success(PageResponse::new(
        rows,
        total,
        page.page,
        page.effective_size(),
    ))))
}

/// PUT /main/api/v1/inheritance/config/{resource_type} — 更新继承模式
async fn update_inheritance_config(
    State(state): State<AppState>,
    Path(resource_type): Path<String>,
    Json(req): Json<UpdateInheritanceRequest>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    validate_registered_resource_type(&resource_type)?;
    // 校验继承模式合法性
    if !VALID_MODES.contains(&req.inheritance_mode.as_str()) {
        return Err(AppError(AstralError::Validation(
            "inheritance_mode must be NONE, PARENT_ONLY, or CUMULATIVE".into(),
        )));
    }

    // 原子 UPSERT：INSERT ON DUPLICATE KEY UPDATE（READ COMMITTED 安全）
    state
        .inheritance_config_repository
        .upsert_by_resource_type(&resource_type, &req.inheritance_mode)
        .await?;

    tracing::info!(
        resource_type = %resource_type,
        mode = %req.inheritance_mode,
        "inheritance config updated"
    );
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

/// POST /inheritance/config — 创建继承配置
async fn create_inheritance_config(
    State(state): State<AppState>,
    Json(req): Json<CreateInheritanceRequest>,
) -> Result<Json<ApiResponse<InheritanceConfig>>, AppError> {
    validate_registered_resource_type(&req.resource_type)?;
    if !VALID_MODES.contains(&req.inheritance_mode.as_str()) {
        return Err(AppError(AstralError::Validation(
            "inheritance_mode must be NONE, PARENT_ONLY, or CUMULATIVE".into(),
        )));
    }

    // 原子 UPSERT：利用 idx_pic_resource_type UNIQUE 约束，无竞态
    state
        .inheritance_config_repository
        .upsert_by_resource_type(&req.resource_type, &req.inheritance_mode)
        .await?;
    let created = state
        .inheritance_config_repository
        .get_by_resource_type(&req.resource_type)
        .await?
        .into();

    tracing::info!(resource_type = %req.resource_type, "inheritance config created");
    Ok(Json(ApiResponse::success(created)))
}

/// DELETE /inheritance/config/{resource_type} — 删除继承配置
async fn delete_inheritance_config(
    State(state): State<AppState>,
    Path(resource_type): Path<String>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    validate_registered_resource_type(&resource_type)?;
    let deleted = state
        .inheritance_config_repository
        .delete_by_resource_type(&resource_type)
        .await?;
    if !deleted {
        return Err(AppError(AstralError::NotFound(format!(
            "inheritance config for resource_type '{resource_type}' not found"
        ))));
    }

    tracing::info!(resource_type = %resource_type, "inheritance config deleted");
    Ok(Json(ApiResponse::success(EmptyResponse)))
}
