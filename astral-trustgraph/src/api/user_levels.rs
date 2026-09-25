//! 用户等级定义 API（DomainController 拆分模块 4/7）— HTTP adapter
//!
//! 提供 user_card_level_definition 表的 CRUD。
//! 对齐 Java `DomainControlController` 中用户等级定义部分。
//! 数据访问在 `repository::level_repository`，HTTP 层仅解析参数并包装响应。
//! 路径前缀：`/main/api/v1/user-levels`

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::{ApiResponse, PageResponse, PaginationParams};
use astral_common::error::AppError;
use astral_types::AstralError;

use crate::api::require_platform_admin;
use crate::repository::level_repository::{LevelFilter, LevelPatch, LevelRecord};
use crate::AppState;

// ===== DTO =====

/// 用户等级响应 DTO（对齐 Java IdentityUserLevelDefinition + 前端 UserLevelDefinition 的 camelCase）
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserLevelDto {
    pub level_id: i64,
    pub domain_id: i64,
    pub level_no: i32,
    pub level_code: String,
    pub level_name: String,
    pub status: String,
    pub upgrade_strategy_json: Option<String>,
    pub description: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl From<LevelRecord> for UserLevelDto {
    fn from(r: LevelRecord) -> Self {
        Self {
            level_id: r.level_id,
            domain_id: r.domain_id,
            level_no: r.level_no,
            level_code: r.level_code,
            level_name: r.level_name,
            status: r.status,
            upgrade_strategy_json: r.upgrade_strategy_json,
            description: r.description,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateUserLevelRequest {
    pub domain_id: i64,
    pub level_name: String,
    pub level_code: String,
    pub level_no: Option<i32>,
    pub upgrade_strategy_json: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateUserLevelRequest {
    pub level_name: Option<String>,
    pub level_code: Option<String>,
    pub level_no: Option<i32>,
    pub status: Option<String>,
    pub upgrade_strategy_json: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserLevelQuery {
    pub domain_id: Option<i64>,
    pub status: Option<String>,
}

// ===== Routes =====

pub fn user_level_routes() -> Router<AppState> {
    Router::new()
        .route("/user-levels", get(list_user_levels))
        .route("/user-levels", post(create_user_level))
        .route("/user-levels/{id}", put(update_user_level))
        .route("/user-levels/{id}", delete(delete_user_level))
}

// ===== Handlers =====

/// GET /main/api/v1/user-levels — 列表（支持 domain_id 过滤，分页）
async fn list_user_levels(
    State(state): State<AppState>,
    Query(q): Query<UserLevelQuery>,
    Query(page): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<UserLevelDto>>>, AppError> {
    let filter = LevelFilter {
        domain_id: q.domain_id,
        status: q.status.as_ref().map(|s| s.to_uppercase()),
    };
    let total = state.level_repository.count_levels(&filter).await?;
    let rows = state
        .level_repository
        .list_levels(&filter, page.effective_size(), page.offset())
        .await?
        .into_iter()
        .map(UserLevelDto::from)
        .collect();
    Ok(Json(ApiResponse::success(PageResponse::new(
        rows,
        total,
        page.page,
        page.effective_size(),
    ))))
}

/// POST /main/api/v1/user-levels — 创建
///
/// 对齐 Java `DomainControlServiceImpl.createUserLevel`：要求已验证 ACTIVE GlobalAdmin。
async fn create_user_level(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateUserLevelRequest>,
) -> Result<Json<ApiResponse<UserLevelDto>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    if req.level_name.is_empty() || req.level_code.is_empty() {
        return Err(AppError(AstralError::Validation(
            "level_name and level_code must not be empty".into(),
        )));
    }

    let new_id = state
        .level_repository
        .create_level(
            req.domain_id,
            &req.level_name,
            &req.level_code,
            req.level_no.unwrap_or(0),
            req.upgrade_strategy_json.as_deref(),
            req.description.as_deref(),
        )
        .await?;
    let row = state
        .level_repository
        .get_level(new_id)
        .await?
        .map(UserLevelDto::from)
        .ok_or_else(|| AppError(AstralError::NotFound(format!("user_level {new_id}"))))?;

    tracing::info!(id = new_id, domain_id = req.domain_id, "user level created");
    Ok(Json(ApiResponse::success(row)))
}

/// PUT /main/api/v1/user-levels/{id} — 更新
///
/// 对齐 Java `DomainControlServiceImpl.updateUserLevel`：要求已验证 ACTIVE GlobalAdmin。
async fn update_user_level(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(req): Json<UpdateUserLevelRequest>,
) -> Result<Json<ApiResponse<UserLevelDto>>, AppError> {
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

    let patch = LevelPatch {
        level_name: req.level_name,
        level_code: req.level_code,
        level_no: req.level_no,
        status,
        upgrade_strategy_json: req.upgrade_strategy_json,
        description: req.description,
    };
    state.level_repository.update_level(id, &patch).await?;

    let row = state
        .level_repository
        .get_level(id)
        .await?
        .map(UserLevelDto::from)
        .ok_or_else(|| AppError(AstralError::NotFound(format!("user_level {id}"))))?;

    tracing::info!(id, "user level updated");
    Ok(Json(ApiResponse::success(row)))
}

/// DELETE /main/api/v1/user-levels/{id} — 删除
///
/// 级联删除引用此等级的 identity_user_grading 记录（FK ON DELETE CASCADE）。
/// 对齐 Java `DomainControlServiceImpl.deleteUserLevel`：要求已验证 ACTIVE GlobalAdmin。
async fn delete_user_level(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let deleted = state.level_repository.delete_level(id).await?;
    if !deleted {
        return Err(AppError(AstralError::NotFound(format!("user_level {id}"))));
    }

    tracing::warn!(id, "user level deleted (cascade: identity_user_grading)");
    Ok(Json(ApiResponse::success(serde_json::json!({
        "id": id,
        "deleted": true,
    }))))
}
