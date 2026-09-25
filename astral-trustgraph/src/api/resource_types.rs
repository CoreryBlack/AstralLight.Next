//! 资源类型管理 API（DomainController 拆分模块 2/7）— HTTP adapter
//!
//! 数据访问在 `repository::resource_type_repository`；
//! ResourceRegistry 合并与 scan 的 in-memory/async_tracker 编排保留在 handler。

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::{ApiResponse, PageResponse, PaginationParams};
use astral_common::error::AppError;
use astral_types::{AstralError, ResourceRegistry};

use crate::api::async_tracker::AsyncTask;
use crate::api::require_platform_admin;
use crate::repository::resource_type_repository::DomainResourceTypeRecord;
use crate::AppState;

// ===== Row / DTO =====

/// domain_resource_type 响应 DTO（对齐 Java DomainResourceType + 前端 Module 类型）
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainResourceTypeRow {
    pub id: i64, // resource_type_id as id
    pub domain_id: Option<i64>,
    pub code: Option<String>,        // type_code as code
    pub name: Option<String>,        // type_name as name
    pub description: Option<String>, // type_description as description
    pub sensitivity_level: Option<i32>,
    pub status: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl From<DomainResourceTypeRecord> for DomainResourceTypeRow {
    fn from(r: DomainResourceTypeRecord) -> Self {
        Self {
            id: r.id,
            domain_id: r.domain_id,
            code: Some(r.code),
            name: Some(r.name),
            description: r.description,
            sensitivity_level: None,
            status: r.status,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

/// ResourceRegistry 暴露给前端的资源类型视图（含动作集合）
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceTypeView {
    pub resource_type: String,
    pub actions: Vec<String>,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterResourceTypeRequest {
    pub resource_type: String,
    pub actions: Vec<String>,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateResourceTypeRequest {
    pub actions: Vec<String>,
    pub description: Option<String>,
}

// ===== Routes =====

pub fn resource_type_routes() -> Router<AppState> {
    Router::new()
        .route("/resource-types", get(list_domain_resource_types))
        .route("/resource-types", post(register_resource_type))
        .route("/resource-types/{resource_type}", put(update_resource_type))
        .route(
            "/resource-types/{resource_type}",
            delete(unregister_resource_type),
        )
        .route("/resource-types/scan", post(scan_resource_types))
        .route(
            "/resource-types/scan/async",
            post(scan_resource_types_async),
        )
}

// ===== Handlers =====

/// GET /main/api/v1/resource-types — 列表（domain_resource_type 表）
async fn list_domain_resource_types(
    State(state): State<AppState>,
    Query(page): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<DomainResourceTypeRow>>>, AppError> {
    let total = state
        .resource_type_repository
        .count_domain_resource_types()
        .await?;
    let rows = state
        .resource_type_repository
        .list_domain_resource_types(page.effective_size(), page.offset())
        .await?
        .into_iter()
        .map(DomainResourceTypeRow::from)
        .collect();
    Ok(Json(ApiResponse::success(PageResponse::new(
        rows,
        total,
        page.page,
        page.effective_size(),
    ))))
}

/// POST /main/api/v1/resource-types — 注册新资源类型（持久化 resource_type_registry）
async fn register_resource_type(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegisterResourceTypeRequest>,
) -> Result<Json<ApiResponse<ResourceTypeView>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    if req.resource_type.is_empty() {
        return Err(AppError(AstralError::Validation(
            "resource_type must not be empty".into(),
        )));
    }
    if req.actions.is_empty() {
        return Err(AppError(AstralError::Validation(
            "actions must not be empty".into(),
        )));
    }

    let reg = ResourceRegistry::global();
    // 已存在则幂等返回
    if reg.list_actions(&req.resource_type).is_some() {
        return Err(AppError(AstralError::Validation(format!(
            "resource_type '{}' already registered",
            req.resource_type
        ))));
    }

    // 持久化（INSERT IGNORE 幂等）
    let actions_json = serde_json::to_string(&req.actions)
        .map_err(|e| AppError(AstralError::Internal(format!("serialize actions: {e}"))))?;
    state
        .resource_type_repository
        .insert_ignore_registry(
            &req.resource_type,
            &actions_json,
            req.description.as_deref(),
        )
        .await?;

    // 注意：ResourceRegistry 当前未暴露运行时 register API，仅启动期注册。
    // 此处记录持久化，重启后由启动期同步逻辑加载（对齐 Java ResourceRegistry.reload）。
    tracing::info!(resource_type = %req.resource_type, "resource type registered (persisted)");

    let mut sorted_actions = req.actions.clone();
    sorted_actions.sort();
    Ok(Json(ApiResponse::success(ResourceTypeView {
        resource_type: req.resource_type,
        actions: sorted_actions,
        description: req.description,
    })))
}

/// PUT /main/api/v1/resource-types/{resource_type} — 更新动作集
async fn update_resource_type(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(resource_type): Path<String>,
    Json(req): Json<UpdateResourceTypeRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let actions_json = serde_json::to_string(&req.actions)
        .map_err(|e| AppError(AstralError::Internal(format!("serialize actions: {e}"))))?;

    let updated = state
        .resource_type_repository
        .update_registry(&resource_type, &actions_json, req.description.as_deref())
        .await?;
    if !updated {
        return Err(AppError(AstralError::NotFound(format!(
            "resource_type '{resource_type}'"
        ))));
    }

    tracing::info!(resource_type = %resource_type, "resource type updated");
    Ok(Json(ApiResponse::success(serde_json::json!({
        "resource_type": resource_type,
        "actions": req.actions,
    }))))
}

/// DELETE /main/api/v1/resource-types/{resource_type} — 注销
async fn unregister_resource_type(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(resource_type): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let deleted = state
        .resource_type_repository
        .delete_registry(&resource_type)
        .await?;
    if !deleted {
        return Err(AppError(AstralError::NotFound(format!(
            "resource_type '{resource_type}'"
        ))));
    }

    tracing::warn!(resource_type = %resource_type, "resource type unregistered");
    Ok(Json(ApiResponse::success(serde_json::json!({
        "resource_type": resource_type,
        "unregistered": true,
    }))))
}

/// GET /main/api/v1/resource-types/scan — 同步扫描所有 @RequirePermission 资源
///
/// Stub：返回 ResourceRegistry 当前内容（Rust 端无运行时注解扫描机制）。
async fn scan_resource_types(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ApiResponse<Vec<ResourceTypeView>>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    Err(AppError(AstralError::NotImplemented(
        "resource type scan is not implemented: Rust has no runtime annotation scanner".into(),
    )))
}

/// POST /main/api/v1/resource-types/scan/async — 异步扫描（返回 task_id）
async fn scan_resource_types_async(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ApiResponse<AsyncTask>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    Err(AppError(AstralError::NotImplemented(
        "resource type async scan is not implemented: Rust has no runtime annotation scanner"
            .into(),
    )))
}
