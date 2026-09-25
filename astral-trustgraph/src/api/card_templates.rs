//! 卡片模板 CRUD API（DomainControl 拆分补充模块）— HTTP adapter
//!
//! 管理 user_card_template 表的 CRUD，对齐 Java DomainControlController 中卡模板部分。
//! 返回字段对齐 Java UserCardTemplate 实体 + 前端 UserCardTemplateDetail TypeScript 类型。
//! 数据访问在 `repository::card_template_repository`，HTTP 层仅解析参数并包装响应；
//! status 写入在进入 repository 前按 ACTIVE/INACTIVE 白名单校验。
//! 路径前缀：`/main/api/v1/card-templates`

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::{ApiResponse, PageResponse, PaginationParams};
use astral_common::error::AppError;
use astral_types::AstralError;

use crate::api::require_platform_admin;
use crate::repository::card_template_repository::{
    guard_card_template_status, CardTemplatePatch, CardTemplateRecord, NewCardTemplate,
};
use crate::AppState;

// ===== DTO =====

/// 卡片模板响应 DTO（对齐 Java UserCardTemplate + 前端 UserCardTemplateDetail 的 camelCase）
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CardTemplateDto {
    pub template_id: i64,
    pub domain_id: Option<i64>,
    pub template_code: Option<String>,
    pub template_name: String,
    pub card_type: Option<String>,
    pub template_scope: Option<String>,
    pub version_no: Option<i32>,
    pub default_priority: Option<i32>,
    pub default_roles_json: Option<String>,
    pub resource_scope_json: Option<String>,
    pub status: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl From<CardTemplateRecord> for CardTemplateDto {
    fn from(r: CardTemplateRecord) -> Self {
        Self {
            template_id: r.template_id,
            domain_id: r.domain_id,
            template_code: r.template_code,
            template_name: r.template_name,
            card_type: r.card_type,
            template_scope: r.template_scope,
            version_no: r.version_no,
            default_priority: r.default_priority,
            default_roles_json: r.default_roles_json,
            resource_scope_json: r.resource_scope_json,
            status: r.status,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCardTemplateRequest {
    pub template_name: String,
    pub template_code: Option<String>,
    pub card_type: Option<String>,
    pub domain_id: Option<i64>,
    pub template_scope: Option<String>,
    pub default_priority: Option<i32>,
    pub default_roles_json: Option<String>,
    pub resource_scope_json: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateCardTemplateRequest {
    pub template_name: Option<String>,
    pub template_code: Option<String>,
    pub card_type: Option<String>,
    pub template_scope: Option<String>,
    pub default_priority: Option<i32>,
    pub default_roles_json: Option<String>,
    pub resource_scope_json: Option<String>,
    pub status: Option<String>,
}

// ===== Routes =====

pub fn card_template_routes() -> Router<AppState> {
    Router::new()
        .route("/card-templates", get(list_card_templates))
        .route("/card-templates", post(create_card_template))
        .route("/card-templates/{id}", get(get_card_template))
        .route("/card-templates/{id}", put(update_card_template))
        .route("/card-templates/{id}", delete(delete_card_template))
}

// ===== Handlers =====

async fn list_card_templates(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(page): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<CardTemplateDto>>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let total = state.card_template_repository.count_templates().await?;
    let rows = state
        .card_template_repository
        .list_templates(page.effective_size(), page.offset())
        .await?
        .into_iter()
        .map(CardTemplateDto::from)
        .collect();
    Ok(Json(ApiResponse::success(PageResponse::new(
        rows,
        total,
        page.page,
        page.effective_size(),
    ))))
}

async fn create_card_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateCardTemplateRequest>,
) -> Result<Json<ApiResponse<CardTemplateDto>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let card_type = req.card_type.unwrap_or_else(|| "STANDARD".into());
    let template_scope = req.template_scope.unwrap_or_else(|| "TENANT".into());

    let new_id = state
        .card_template_repository
        .create_template(&NewCardTemplate {
            template_name: req.template_name,
            template_code: req.template_code,
            card_type,
            domain_id: req.domain_id,
            template_scope,
            default_priority: req.default_priority,
            default_roles_json: req.default_roles_json,
            resource_scope_json: req.resource_scope_json,
        })
        .await?;

    let row = state
        .card_template_repository
        .get_template(new_id)
        .await?
        .map(CardTemplateDto::from)
        .ok_or_else(|| AppError(AstralError::NotFound(format!("card_template {new_id}"))))?;

    tracing::info!(id = new_id, name = %row.template_name, "card template created");
    Ok(Json(ApiResponse::success(row)))
}

async fn get_card_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<CardTemplateDto>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let row = state
        .card_template_repository
        .get_template(id)
        .await?
        .map(CardTemplateDto::from)
        .ok_or_else(|| AppError(AstralError::NotFound(format!("card_template {id}"))))?;
    Ok(Json(ApiResponse::success(row)))
}

async fn update_card_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(req): Json<UpdateCardTemplateRequest>,
) -> Result<Json<ApiResponse<CardTemplateDto>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    // status 白名单门禁：仅允许 ACTIVE/INACTIVE；非法值在进入 repository /
    // 任何 source 写路径之前 fail-closed 拒绝（400 VALIDATION_ERROR）。
    if let Some(status) = &req.status {
        guard_card_template_status(status)?;
    }
    let patch = CardTemplatePatch {
        template_name: req.template_name,
        template_code: req.template_code,
        card_type: req.card_type,
        template_scope: req.template_scope,
        default_priority: req.default_priority,
        default_roles_json: req.default_roles_json,
        resource_scope_json: req.resource_scope_json,
        status: req.status,
    };
    state
        .card_template_repository
        .update_template(id, &patch)
        .await?;

    let row = state
        .card_template_repository
        .get_template(id)
        .await?
        .map(CardTemplateDto::from)
        .ok_or_else(|| AppError(AstralError::NotFound(format!("card_template {id}"))))?;

    tracing::info!(id, "card template updated");
    Ok(Json(ApiResponse::success(row)))
}

async fn delete_card_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let deleted = state
        .card_template_repository
        .delete_template_if_unreferenced(id)
        .await?;
    if !deleted {
        return Err(AppError(AstralError::NotFound(format!(
            "card_template {id}"
        ))));
    }

    tracing::info!(id, "card template deleted");
    Ok(Json(ApiResponse::success(
        serde_json::json!({ "templateId": id, "deleted": true }),
    )))
}
