//! 权限动作管理 API（DomainController 拆分模块 3/7）— HTTP adapter
//!
//! 数据访问在 `repository::permission_action_repository`；
//! scan 的 `ResourceRegistry`/`async_tracker` 编排保留在 handler（in-memory）。

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::{ApiResponse, PageResponse, PaginationParams};
use astral_common::error::AppError;
use astral_types::AstralError;

use crate::api::async_tracker::AsyncTask;
use crate::api::require_platform_admin;
use crate::repository::permission_action_repository::{
    ActionFilter, ActionPatch, PermissionActionRecord,
};
use crate::AppState;

// ===== Row / DTO =====

/// permission_action 响应 DTO（对齐 Java PermissionAction + 前端 Feature 类型）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionActionRow {
    pub id: i64,                     // action_id as id
    pub domain_id: Option<i64>,      // domain_id
    pub resource_type_id: i64,       // resource_type_id（前端 moduleId）
    pub code: String,                // action_code as code
    pub name: String,                // action_name as name
    pub description: Option<String>, // action_description as description
    pub created_at: Option<String>,
}

impl From<PermissionActionRecord> for PermissionActionRow {
    fn from(r: PermissionActionRecord) -> Self {
        Self {
            id: r.id,
            domain_id: r.domain_id,
            resource_type_id: r.resource_type_id,
            code: r.code,
            name: r.name,
            description: r.description,
            created_at: r.created_at,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateActionRequest {
    pub domain_id: Option<i64>,
    pub resource_type_id: i64,
    pub code: String,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateActionRequest {
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionQuery {
    pub domain_id: Option<i64>,
    pub resource_type_id: Option<i64>,
    pub resource_type_ids: Option<String>, // 逗号分隔的 ID 列表
}

// ===== Routes =====

pub fn permission_action_routes() -> Router<AppState> {
    Router::new()
        .route("/actions", get(list_actions))
        .route("/actions", post(create_action))
        .route("/actions/{id}", put(update_action))
        .route("/actions/{id}", delete(delete_action))
        .route("/actions/scan", post(scan_actions))
        .route("/actions/scan/async", post(scan_actions_async))
}

// ===== Handlers =====

/// GET /main/api/v1/actions — 列表（支持 domainId/resourceTypeId 过滤，分页）
async fn list_actions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ActionQuery>,
    Query(page): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<PermissionActionRow>>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    // 解析 resourceTypeId / resourceTypeIds
    let rt_ids: Vec<i64> = if let Some(ref ids_str) = q.resource_type_ids {
        ids_str
            .split(',')
            .filter_map(|s| s.trim().parse::<i64>().ok())
            .collect()
    } else {
        Vec::new()
    };
    let single_rt_id = q.resource_type_id;
    let effective_rt_ids: Vec<i64> = if rt_ids.is_empty() {
        single_rt_id.map(|id| vec![id]).unwrap_or_default()
    } else {
        rt_ids
    };

    let filter = ActionFilter {
        domain_id: q.domain_id,
        resource_type_ids: effective_rt_ids,
    };
    let total = state
        .permission_action_repository
        .count_actions(&filter)
        .await?;
    let rows = state
        .permission_action_repository
        .list_actions(&filter, page.effective_size(), page.offset())
        .await?
        .into_iter()
        .map(PermissionActionRow::from)
        .collect();
    Ok(Json(ApiResponse::success(PageResponse::new(
        rows,
        total,
        page.page,
        page.effective_size(),
    ))))
}

/// POST /main/api/v1/actions — 创建
async fn create_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateActionRequest>,
) -> Result<Json<ApiResponse<PermissionActionRow>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    if req.code.is_empty() {
        return Err(AppError(AstralError::Validation(
            "action_code must not be empty".into(),
        )));
    }

    let row = state
        .permission_action_repository
        .create_action(
            req.domain_id,
            req.resource_type_id,
            &req.code,
            &req.name,
            req.description.as_deref(),
        )
        .await?;

    tracing::info!(action_code = %req.code, resource_type_id = req.resource_type_id, "permission action created");
    Ok(Json(ApiResponse::success(PermissionActionRow::from(row))))
}

/// PUT /main/api/v1/actions/{id} — 更新
async fn update_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(req): Json<UpdateActionRequest>,
) -> Result<Json<ApiResponse<PermissionActionRow>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let patch = ActionPatch {
        name: req.name,
        description: req.description,
    };
    let updated = state
        .permission_action_repository
        .update_action(id, &patch)
        .await?;
    if !updated {
        return Err(AppError(AstralError::NotFound(format!("action {id}"))));
    }

    let row = state
        .permission_action_repository
        .get_action(id)
        .await?
        .map(PermissionActionRow::from)
        .ok_or_else(|| AppError(AstralError::NotFound(format!("action {id}"))))?;

    tracing::info!(id, "permission action updated");
    Ok(Json(ApiResponse::success(row)))
}

/// DELETE /main/api/v1/actions/{id} — 删除
async fn delete_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let deleted = state.permission_action_repository.delete_action(id).await?;
    if !deleted {
        return Err(AppError(AstralError::NotFound(format!("action {id}"))));
    }

    tracing::warn!(id, "permission action deleted");
    Ok(Json(ApiResponse::success(serde_json::json!({
        "id": id,
        "deleted": true,
    }))))
}

/// GET /main/api/v1/actions/scan — 同步扫描
///
/// 汇总 ResourceRegistry 中所有出现过的动作，同步到 permission_action 表。
async fn scan_actions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ApiResponse<Vec<PermissionActionRow>>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    Err(AppError(AstralError::NotImplemented(
        "permission action scan is not implemented: Rust has no runtime annotation scanner".into(),
    )))
}

/// POST /main/api/v1/actions/scan/async — 异步扫描（注册到 tracker）
async fn scan_actions_async(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ApiResponse<AsyncTask>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    Err(AppError(AstralError::NotImplemented(
        "permission action async scan is not implemented: Rust has no runtime annotation scanner"
            .into(),
    )))
}
