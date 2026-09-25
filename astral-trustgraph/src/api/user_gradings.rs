//! 用户分级 API（DomainController 拆分模块 5/7）— HTTP adapter
//!
//! 提供 identity_user_grading 表的 CRUD。
//! 对齐 Java `DomainControlController` 中用户分级部分。
//! 数据访问在 `repository::grading_repository`，HTTP 层仅解析参数并包装响应。
//! 路径前缀：`/main/api/v1/user-gradings`

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::{ApiResponse, PageResponse, PaginationParams};
use astral_common::error::AppError;
use astral_types::AstralError;

use crate::api::require_platform_admin;
use crate::repository::grading_repository::{GradingFilter, GradingRecord};
use crate::AppState;

// ===== DTO =====

/// 用户分级响应 DTO（对齐 Java 实体 camelCase 序列化）
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserGradingDto {
    pub id: i64,
    pub user_id: i64,
    pub level_id: i64,
    pub domain_id: i64,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl From<GradingRecord> for UserGradingDto {
    fn from(r: GradingRecord) -> Self {
        Self {
            id: r.id,
            user_id: r.user_id,
            level_id: r.level_id,
            domain_id: r.domain_id,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateUserGradingRequest {
    pub user_id: i64,
    pub level_id: i64,
    pub domain_id: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserGradingQuery {
    pub user_id: Option<i64>,
    pub domain_id: Option<i64>,
}

// ===== Routes =====

pub fn user_grading_routes() -> Router<AppState> {
    Router::new()
        .route("/user-gradings", get(list_user_gradings))
        .route("/user-gradings", post(create_user_grading))
        .route("/user-gradings/{id}", delete(delete_user_grading))
}

// ===== Handlers =====

/// GET /main/api/v1/user-gradings — 列表（user_id 过滤，分页）
async fn list_user_gradings(
    State(state): State<AppState>,
    Query(q): Query<UserGradingQuery>,
    Query(page): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<UserGradingDto>>>, AppError> {
    let filter = GradingFilter {
        user_id: q.user_id,
        domain_id: q.domain_id,
    };
    let total = state.grading_repository.count_gradings(&filter).await?;
    let rows = state
        .grading_repository
        .list_gradings(&filter, page.effective_size(), page.offset())
        .await?
        .into_iter()
        .map(UserGradingDto::from)
        .collect();
    Ok(Json(ApiResponse::success(PageResponse::new(
        rows,
        total,
        page.page,
        page.effective_size(),
    ))))
}

/// POST /main/api/v1/user-gradings — 创建（单用户单域唯一）
///
/// 对齐 Java `DomainControlServiceImpl.upsertUserGrading`：要求已验证 ACTIVE GlobalAdmin。
async fn create_user_grading(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateUserGradingRequest>,
) -> Result<Json<ApiResponse<UserGradingDto>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    // 校验 level_id 存在且属于该 domain
    let exists = state
        .grading_repository
        .level_exists_in_domain(req.level_id, req.domain_id)
        .await?;
    if !exists {
        return Err(AppError(AstralError::Validation(format!(
            "level_id {} does not exist in domain {} or is inactive",
            req.level_id, req.domain_id
        ))));
    }

    // INSERT ... ON DUPLICATE KEY UPDATE 幂等（uk_iug_user_domain）
    state
        .grading_repository
        .upsert_grading(req.user_id, req.level_id, req.domain_id)
        .await?;
    let row = state
        .grading_repository
        .get_grading(req.user_id, req.domain_id)
        .await?
        .into();

    tracing::info!(
        user_id = req.user_id,
        domain_id = req.domain_id,
        level_id = req.level_id,
        "user grading created/updated"
    );
    Ok(Json(ApiResponse::success(row)))
}

/// DELETE /main/api/v1/user-gradings/{id} — 删除
///
/// 对齐 Java `DomainControlServiceImpl.deleteUserGrading`：要求已验证 ACTIVE GlobalAdmin。
async fn delete_user_grading(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let deleted = state.grading_repository.delete_grading(id).await?;
    if !deleted {
        return Err(AppError(AstralError::NotFound(format!(
            "user_grading {id}"
        ))));
    }

    tracing::warn!(id, "user grading deleted");
    Ok(Json(ApiResponse::success(serde_json::json!({
        "id": id,
        "deleted": true,
    }))))
}
