//! 域 CRUD API（DomainController 拆分模块 1/7）— HTTP adapter
//!
//! 提供域（domain）的 CRUD 操作与默认域同步。
//! 对齐 Java `DomainControlController` 中域管理部分。
//! 数据访问在 `repository::domain_repository`，HTTP 层仅解析参数并包装响应。
//! 路径前缀：`/main/api/v1/domains`

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::{ApiResponse, PageResponse, PaginationParams};
use astral_common::error::AppError;
use astral_types::AstralError;

use crate::api::require_platform_admin;
use crate::repository::domain_repository::{DomainFilter, DomainPatch, DomainRecord};
use crate::AppState;

// ===== DTO =====

/// 域响应 DTO（对齐 Java Domain 实体 camelCase 序列化，orgId 为前端兼容恒为 None）
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainDto {
    pub id: i64,
    pub name: String,
    pub code: Option<String>,
    pub description: Option<String>,
    pub org_id: Option<i64>,
    pub status: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl From<DomainRecord> for DomainDto {
    fn from(r: DomainRecord) -> Self {
        Self {
            id: r.id,
            name: r.name,
            code: r.code,
            description: r.description,
            org_id: r.org_id,
            status: r.status,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDomainRequest {
    pub name: String,
    pub code: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateDomainRequest {
    pub name: Option<String>,
    pub code: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainQuery {
    pub status: Option<String>,
}

// ===== Routes =====

pub fn domain_routes() -> Router<AppState> {
    Router::new()
        .route("/domains", get(list_domains))
        .route("/domains", post(create_domain))
        .route("/domains/{id}", get(get_domain))
        .route("/domains/{id}", put(update_domain))
        .route("/domains/{id}", delete(delete_domain))
        .route("/domains/defaults/sync", post(sync_default_domains))
}

// ===== Handlers =====

/// GET /main/api/v1/domains — 列表（支持 status 过滤，分页）
async fn list_domains(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<DomainQuery>,
    Query(page): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<DomainDto>>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let filter = DomainFilter {
        status: q.status.as_ref().map(|s| s.to_uppercase()),
    };
    let total = state.domain_repository.count_domains(&filter).await?;
    let rows = state
        .domain_repository
        .list_domains(&filter, page.effective_size(), page.offset())
        .await?
        .into_iter()
        .map(DomainDto::from)
        .collect();
    Ok(Json(ApiResponse::success(PageResponse::new(
        rows,
        total,
        page.page,
        page.effective_size(),
    ))))
}

/// GET /main/api/v1/domains/{id} — 查询
async fn get_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<DomainDto>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let row = state
        .domain_repository
        .get_domain(id)
        .await?
        .map(DomainDto::from)
        .ok_or_else(|| AppError(AstralError::NotFound(format!("domain {id}"))))?;
    Ok(Json(ApiResponse::success(row)))
}

/// POST /main/api/v1/domains — 创建
async fn create_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateDomainRequest>,
) -> Result<Json<ApiResponse<DomainDto>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let status = req
        .status
        .map(|s| s.to_uppercase())
        .unwrap_or_else(|| "ACTIVE".into());
    if status != "ACTIVE" && status != "INACTIVE" {
        return Err(AppError(AstralError::Validation(
            "status must be ACTIVE or INACTIVE".into(),
        )));
    }

    let new_id = state
        .domain_repository
        .create_domain(&req.name, req.code.as_deref(), &status)
        .await?;
    let row = state
        .domain_repository
        .get_domain(new_id)
        .await?
        .map(DomainDto::from)
        .ok_or_else(|| AppError(AstralError::NotFound(format!("domain {new_id}"))))?;

    tracing::info!(id = new_id, name = %req.name, "domain created");
    Ok(Json(ApiResponse::success(row)))
}

/// PUT /main/api/v1/domains/{id} — 更新
async fn update_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(req): Json<UpdateDomainRequest>,
) -> Result<Json<ApiResponse<DomainDto>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    // 状态白名单校验（对齐现有 handler 语义）
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

    let patch = DomainPatch {
        name: req.name,
        code: req.code,
        status,
    };
    state.domain_repository.update_domain(id, &patch).await?;

    let row = state
        .domain_repository
        .get_domain(id)
        .await?
        .map(DomainDto::from)
        .ok_or_else(|| AppError(AstralError::NotFound(format!("domain {id}"))))?;

    tracing::info!(id, "domain updated");
    Ok(Json(ApiResponse::success(row)))
}

/// DELETE /main/api/v1/domains/{id} — 删除域（软删除）
async fn delete_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let deleted = state.domain_repository.soft_delete_domain(id).await?;
    if !deleted {
        return Err(AppError(AstralError::NotFound(format!(
            "domain {id} (not found or already inactive)"
        ))));
    }

    tracing::info!(id, "domain soft-deleted");
    Ok(Json(ApiResponse::success(
        serde_json::json!({ "id": id, "status": "INACTIVE" }),
    )))
}

/// POST /main/api/v1/domains/defaults/sync — 同步默认域
///
/// 幂等：确保系统至少有一个默认域（名为 "默认域"）。
/// platform_v4 中 platform_domain 表无 org_id 列，不再按组织维度同步。
async fn sync_default_domains(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let result = state.domain_repository.sync_default_domain().await?;

    tracing::info!(
        existing_domains = result.existing,
        created = result.created,
        "default domains synced"
    );
    Ok(Json(ApiResponse::success(serde_json::json!({
        "existing_domains": result.existing,
        "domains_created": result.created,
    }))))
}
