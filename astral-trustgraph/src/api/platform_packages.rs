//! 平台套餐 CRUD API — HTTP adapter
//!
//! 对齐 Java `PlatformPackageController` + `PlatformPackageService`。
//! 数据访问在 `repository::platform_package_repository`，HTTP 层仅校验白名单并包装响应。

use axum::extract::{Path, Query, State};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::{ApiResponse, EmptyResponse, PageResponse, PaginationParams};
use astral_common::error::AppError;
use astral_types::AstralError;

use crate::repository::platform_package_repository::{PlatformPackagePatch, PlatformPackageRecord};
use crate::AppState;

// ===== 数据模型 =====

/// 平台套餐响应 DTO（对应 platform_package 表 camelCase）
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformPackage {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    /// 套餐价格（单位：分）
    pub price: Option<i64>,
    /// 计费周期（MONTHLY / YEARLY / ONE_TIME）
    pub billing_cycle: Option<String>,
    /// 状态（ACTIVE / INACTIVE）
    pub status: String,
    /// 创建时间（UNIX 时间戳）
    pub created_at: Option<i64>,
}

impl From<PlatformPackageRecord> for PlatformPackage {
    fn from(r: PlatformPackageRecord) -> Self {
        Self {
            id: r.id,
            name: r.name,
            description: r.description,
            price: r.price,
            billing_cycle: r.billing_cycle,
            status: r.status,
            created_at: r.created_at,
        }
    }
}

/// 创建套餐请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePlatformPackageRequest {
    pub name: String,
    pub description: Option<String>,
    pub price: Option<i64>,
    pub billing_cycle: Option<String>,
}

/// 更新套餐请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePlatformPackageRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub price: Option<i64>,
    pub billing_cycle: Option<String>,
    pub status: Option<String>,
}

// ===== 路由注册 =====

pub fn platform_package_routes() -> Router<AppState> {
    Router::new()
        .route("/platform-packages", get(list_platform_packages))
        .route("/platform-packages", post(create_platform_package))
        .route("/platform-packages/{id}", get(get_platform_package))
        .route("/platform-packages/{id}", put(update_platform_package))
        .route("/platform-packages/{id}", delete(delete_platform_package))
}

const VALID_BILLING_CYCLES: [&str; 3] = ["MONTHLY", "YEARLY", "ONE_TIME"];

// ===== Handlers =====

/// GET /main/api/v1/platform-packages — 列出所有平台套餐（分页）
async fn list_platform_packages(
    State(state): State<AppState>,
    Query(page): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<PlatformPackage>>>, AppError> {
    let total = state.platform_package_repository.count_packages().await?;
    let rows = state
        .platform_package_repository
        .list_packages(page.effective_size(), page.offset())
        .await?
        .into_iter()
        .map(PlatformPackage::from)
        .collect();
    Ok(Json(ApiResponse::success(PageResponse::new(
        rows,
        total,
        page.page,
        page.effective_size(),
    ))))
}

/// POST /main/api/v1/platform-packages — 创建平台套餐
async fn create_platform_package(
    State(state): State<AppState>,
    Json(req): Json<CreatePlatformPackageRequest>,
) -> Result<Json<ApiResponse<PlatformPackage>>, AppError> {
    let billing_cycle = req.billing_cycle.unwrap_or_else(|| "MONTHLY".into());

    // 校验计费周期合法性
    if !VALID_BILLING_CYCLES.contains(&billing_cycle.as_str()) {
        return Err(AppError(AstralError::Validation(
            "billing_cycle must be MONTHLY, YEARLY, or ONE_TIME".into(),
        )));
    }

    let new_id = state
        .platform_package_repository
        .create_package(
            &req.name,
            req.description.as_deref(),
            req.price,
            &billing_cycle,
        )
        .await?;
    let row = state
        .platform_package_repository
        .get_package(new_id)
        .await?
        .map(PlatformPackage::from)
        .ok_or_else(|| {
            AppError(AstralError::Database(format!(
                "package {new_id} not found after insert"
            )))
        })?;

    tracing::info!(id = new_id, name = %req.name, "platform package created");
    Ok(Json(ApiResponse::success(row)))
}

/// GET /main/api/v1/platform-packages/{id} — 获取单个套餐
async fn get_platform_package(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<PlatformPackage>>, AppError> {
    let row = state
        .platform_package_repository
        .get_package(id)
        .await?
        .map(PlatformPackage::from)
        .ok_or_else(|| AppError(AstralError::NotFound(format!("platform package {id}"))))?;
    Ok(Json(ApiResponse::success(row)))
}

/// PUT /main/api/v1/platform-packages/{id} — 更新套餐
async fn update_platform_package(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdatePlatformPackageRequest>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    // 状态与计费周期白名单校验（对齐现有 handler 语义）
    let status = match req.status.as_ref() {
        Some(raw) => {
            let upper = raw.to_uppercase();
            if upper != "ACTIVE" && upper != "INACTIVE" {
                return Err(AppError(AstralError::Validation(
                    "status must be ACTIVE or INACTIVE".into(),
                )));
            }
            Some(upper)
        }
        None => None,
    };
    let billing_cycle = match req.billing_cycle.as_ref() {
        Some(cycle) => {
            if !VALID_BILLING_CYCLES.contains(&cycle.as_str()) {
                return Err(AppError(AstralError::Validation(
                    "billing_cycle must be MONTHLY, YEARLY, or ONE_TIME".into(),
                )));
            }
            Some(cycle.clone())
        }
        None => None,
    };

    let patch = PlatformPackagePatch {
        name: req.name,
        description: req.description,
        price: req.price,
        billing_cycle,
        status,
    };
    state
        .platform_package_repository
        .update_package(id, &patch)
        .await?;

    tracing::info!(id, "platform package updated");
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

/// DELETE /main/api/v1/platform-packages/{id} — 软删除（设置 status=INACTIVE）
async fn delete_platform_package(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let deleted = state
        .platform_package_repository
        .soft_delete_package(id)
        .await?;
    if !deleted {
        return Err(AppError(AstralError::NotFound(format!(
            "platform package {id} not found"
        ))));
    }

    tracing::warn!(id, "platform package soft-deleted (INACTIVE)");
    Ok(Json(ApiResponse::success(EmptyResponse)))
}
