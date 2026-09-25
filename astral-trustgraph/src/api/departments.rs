//! 部门 CRUD API — HTTP adapter
//!
//! 对齐 Java `DepartmentController` + `DepartmentService`。
//! 数据访问在 `repository::department_repository`，HTTP 层仅解析参数、校验白名单并包装响应。

use axum::extract::{Path, Query, State};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::{ApiResponse, EmptyResponse, PageResponse, PaginationParams};
use astral_common::error::AppError;
use astral_types::AstralError;

use crate::repository::department_repository::{
    DepartmentFilter, DepartmentPatch, DepartmentRecord,
};
use crate::AppState;

// ===== 数据模型 =====

/// 部门响应 DTO（对齐 platform_v4.departments camelCase）
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Department {
    pub id: i64,
    pub tenant_id: i64,
    pub name: String,
    pub code: Option<String>,
    pub parent_id: Option<i64>,
    pub sort_order: Option<i32>,
    pub status: String,
    pub description: Option<String>,
    pub created_at: Option<i64>,
    pub updated_at: Option<i64>,
}

impl From<DepartmentRecord> for Department {
    fn from(r: DepartmentRecord) -> Self {
        Self {
            id: r.id,
            tenant_id: r.tenant_id,
            name: r.name,
            code: r.code,
            parent_id: r.parent_id,
            sort_order: r.sort_order,
            status: r.status,
            description: r.description,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

/// 创建部门请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDepartmentRequest {
    pub tenant_id: i64,
    pub name: String,
    pub code: Option<String>,
    pub parent_id: Option<i64>,
    pub sort_order: Option<i32>,
    pub description: Option<String>,
}

/// 更新部门请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateDepartmentRequest {
    pub name: Option<String>,
    pub code: Option<String>,
    pub parent_id: Option<i64>,
    pub sort_order: Option<i32>,
    pub description: Option<String>,
}

/// 列表查询参数
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListDepartmentsQuery {
    pub parent_id: Option<i64>,
    pub tenant_id: Option<i64>,
}

// ===== 路由注册 =====

pub fn department_routes() -> Router<AppState> {
    Router::new()
        .route("/departments", get(list_departments))
        .route("/departments", post(create_department))
        .route("/departments/{id}", put(update_department))
        .route("/departments/{id}", delete(delete_department))
}

// ===== Handlers =====

/// GET /main/api/v1/departments — 列出部门（支持 parent_id/tenant_id 过滤，分页）
async fn list_departments(
    State(state): State<AppState>,
    Query(query): Query<ListDepartmentsQuery>,
    Query(page): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<Department>>>, AppError> {
    let filter = DepartmentFilter {
        parent_id: query.parent_id,
        tenant_id: query.tenant_id,
    };
    let total = state
        .department_repository
        .count_departments(&filter)
        .await?;
    let rows = state
        .department_repository
        .list_departments(&filter, page.effective_size(), page.offset())
        .await?
        .into_iter()
        .map(Department::from)
        .collect();
    Ok(Json(ApiResponse::success(PageResponse::new(
        rows,
        total,
        page.page,
        page.effective_size(),
    ))))
}

/// POST /main/api/v1/departments — 创建部门
async fn create_department(
    State(state): State<AppState>,
    Json(req): Json<CreateDepartmentRequest>,
) -> Result<Json<ApiResponse<Department>>, AppError> {
    // 校验父部门存在性
    if let Some(parent_id) = req.parent_id {
        let exists = state
            .department_repository
            .department_exists(parent_id)
            .await?;
        if !exists {
            return Err(AppError(AstralError::Validation(format!(
                "parent department {parent_id} not found"
            ))));
        }
    }

    let new_id = state
        .department_repository
        .create_department(
            req.tenant_id,
            &req.name,
            req.code.as_deref(),
            req.parent_id,
            req.sort_order.unwrap_or(0),
            req.description.as_deref(),
        )
        .await?;
    let row = state
        .department_repository
        .get_department(new_id)
        .await?
        .map(Department::from)
        .ok_or_else(|| {
            AppError(AstralError::Database(format!(
                "department {new_id} not found after insert"
            )))
        })?;

    tracing::info!(id = new_id, name = %req.name, "department created");
    Ok(Json(ApiResponse::success(row)))
}

/// PUT /main/api/v1/departments/{id} — 更新部门
async fn update_department(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateDepartmentRequest>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    // 防止自引用循环
    if let Some(parent_id) = req.parent_id {
        if parent_id == id {
            return Err(AppError(AstralError::Validation(
                "department cannot be its own parent".into(),
            )));
        }
        let exists = state
            .department_repository
            .department_exists(parent_id)
            .await?;
        if !exists {
            return Err(AppError(AstralError::Validation(format!(
                "parent department {parent_id} not found"
            ))));
        }
    }

    let patch = DepartmentPatch {
        name: req.name,
        code: req.code,
        parent_id: req.parent_id,
        sort_order: req.sort_order,
        description: req.description,
    };
    state
        .department_repository
        .update_department(id, &patch)
        .await?;

    tracing::info!(id, "department updated");
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

/// DELETE /main/api/v1/departments/{id} — 删除部门
async fn delete_department(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    // 检查是否有子部门
    let children = state.department_repository.count_children(id).await?;
    if children > 0 {
        return Err(AppError(AstralError::Validation(format!(
            "department {id} has {children} child departments, cannot delete"
        ))));
    }

    let deleted = state.department_repository.delete_department(id).await?;
    if !deleted {
        return Err(AppError(AstralError::NotFound(format!(
            "department {id} not found"
        ))));
    }

    tracing::warn!(id, "department deleted");
    Ok(Json(ApiResponse::success(EmptyResponse)))
}
