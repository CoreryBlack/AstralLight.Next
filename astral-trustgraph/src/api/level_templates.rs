//! 等级模板 API（DomainController 拆分模块 6/7）— HTTP adapter
//!
//! 数据访问在 `repository::level_template_repository`，delete 的级联清理 + 逐卡
//! rebuild 编排在 `service::level_template_service`。HTTP 层仅解析参数并包装响应。

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::{ApiResponse, PageResponse, PaginationParams};
use astral_common::error::AppError;
use astral_types::AstralError;

use crate::api::require_platform_admin;
use crate::repository::level_template_repository::{
    LevelTemplateFilter, LevelTemplateMutationContext, LevelTemplatePatch, LevelTemplateRecord,
    NewLevelTemplate,
};
use crate::AppState;

// ===== Row / DTO =====

/// identity_level_template 响应 DTO（对齐 Java IdentityLevelTemplate + 前端 LevelTemplateDetail）
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LevelTemplateRow {
    pub template_id: i64,
    pub template_code: String,
    pub template_name: String,
    pub domain_id: i64,
    pub principal_type: String,
    pub grant_type: String,
    pub level_no: i32,
    pub user_card_template_id: Option<i64>,
    pub status: String,
    pub version_no: i32,
    pub force_cover: bool,
    pub description: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl From<LevelTemplateRecord> for LevelTemplateRow {
    fn from(r: LevelTemplateRecord) -> Self {
        Self {
            template_id: r.template_id,
            template_code: r.template_code,
            template_name: r.template_name,
            domain_id: r.domain_id,
            principal_type: r.principal_type,
            grant_type: r.grant_type,
            level_no: r.level_no,
            user_card_template_id: r.user_card_template_id,
            status: r.status,
            version_no: r.version_no,
            force_cover: r.force_cover,
            description: r.description,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateLevelTemplateRequest {
    pub template_code: String,
    pub template_name: String,
    pub domain_id: i64,
    pub principal_type: String,
    pub grant_type: String,
    pub level_no: i32,
    pub user_card_template_id: Option<i64>,
    pub version_no: Option<i32>,
    pub force_cover: Option<bool>,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateLevelTemplateRequest {
    pub template_name: Option<String>,
    pub principal_type: Option<String>,
    pub grant_type: Option<String>,
    pub level_no: Option<i32>,
    pub user_card_template_id: Option<i64>,
    pub status: Option<String>,
    pub version_no: Option<i32>,
    pub force_cover: Option<bool>,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LevelTemplateQuery {
    pub domain_id: Option<i64>,
    pub level_no: Option<i32>,
}

// ===== Routes =====

pub fn level_template_routes() -> Router<AppState> {
    Router::new()
        .route("/level-templates", get(list_level_templates))
        .route("/level-templates", post(create_level_template))
        .route("/level-templates/{id}", get(get_level_template))
        .route("/level-templates/{id}", put(update_level_template))
        .route("/level-templates/{id}", delete(delete_level_template))
        .route("/level-templates/sync", post(sync_level_templates))
        .route("/level-templates/precheck", post(precheck_sync))
}

// ===== Handlers =====

fn mutation_context(
    actor_id: i64,
    headers: &HeaderMap,
) -> Result<LevelTemplateMutationContext, AppError> {
    let operation_id = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            AppError(AstralError::Validation(
                "level template mutation requires x-request-id".into(),
            ))
        })?;
    LevelTemplateMutationContext::new(actor_id, operation_id).map_err(AppError::from)
}

/// GET /main/api/v1/level-templates — 列表（支持 domainId/levelNo 过滤，分页）
async fn list_level_templates(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<LevelTemplateQuery>,
    Query(page): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<LevelTemplateRow>>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let filter = LevelTemplateFilter {
        domain_id: q.domain_id,
        level_no: q.level_no,
    };
    let total = state
        .level_template_repository
        .count_templates(&filter)
        .await?;
    let rows = state
        .level_template_repository
        .list_templates(&filter, page.effective_size(), page.offset())
        .await?
        .into_iter()
        .map(LevelTemplateRow::from)
        .collect();
    Ok(Json(ApiResponse::success(PageResponse::new(
        rows,
        total,
        page.page,
        page.effective_size(),
    ))))
}

/// GET /main/api/v1/level-templates/{id} — 查询
async fn get_level_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<LevelTemplateRow>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let row = state
        .level_template_repository
        .get_template(id)
        .await?
        .map(LevelTemplateRow::from)
        .ok_or_else(|| AppError(AstralError::NotFound(format!("level_template {id}"))))?;
    Ok(Json(ApiResponse::success(row)))
}

/// POST /main/api/v1/level-templates — 创建
async fn create_level_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateLevelTemplateRequest>,
) -> Result<Json<ApiResponse<LevelTemplateRow>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    if req.template_name.is_empty() {
        return Err(AppError(AstralError::Validation(
            "template_name must not be empty".into(),
        )));
    }
    if req.template_code.is_empty() {
        return Err(AppError(AstralError::Validation(
            "template_code must not be empty".into(),
        )));
    }

    let new_id = state
        .level_template_repository
        .create_template(&NewLevelTemplate {
            template_code: req.template_code.clone(),
            template_name: req.template_name.clone(),
            domain_id: req.domain_id,
            principal_type: req.principal_type.clone(),
            grant_type: req.grant_type.clone(),
            level_no: req.level_no,
            user_card_template_id: req.user_card_template_id,
            version_no: req.version_no.unwrap_or(1),
            force_cover: req.force_cover.unwrap_or(true),
            description: req.description.clone(),
        })
        .await?;
    let row = state
        .level_template_repository
        .get_template(new_id)
        .await?
        .map(LevelTemplateRow::from)
        .ok_or_else(|| {
            AppError(AstralError::Database(format!(
                "level_template {new_id} not found after insert"
            )))
        })?;

    tracing::info!(id = new_id, template_code = %req.template_code, "level template created");
    Ok(Json(ApiResponse::success(row)))
}

/// PUT /main/api/v1/level-templates/{id} — 更新
async fn update_level_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(req): Json<UpdateLevelTemplateRequest>,
) -> Result<Json<ApiResponse<LevelTemplateRow>>, AppError> {
    let actor_id = require_platform_admin(&state, &headers).await?;
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

    let patch = LevelTemplatePatch {
        template_name: req.template_name,
        principal_type: req.principal_type,
        grant_type: req.grant_type,
        level_no: req.level_no,
        user_card_template_id: req.user_card_template_id,
        status,
        version_no: req.version_no,
        force_cover: req.force_cover,
        description: req.description,
    };
    let context = mutation_context(actor_id, &headers)?;
    state
        .level_template_repository
        .update_template(id, &patch, &context)
        .await?;

    let row = state
        .level_template_repository
        .get_template(id)
        .await?
        .map(LevelTemplateRow::from)
        .ok_or_else(|| AppError(AstralError::NotFound(format!("level_template {id}"))))?;

    tracing::info!(id, "level template updated");
    Ok(Json(ApiResponse::success(row)))
}

/// DELETE /main/api/v1/level-templates/{id} — 删除
async fn delete_level_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    let actor_id = require_platform_admin(&state, &headers).await?;
    let context = mutation_context(actor_id, &headers)?;
    let result = state.level_template_service.delete(id, &context).await?;
    if !result.deleted {
        return Err(AppError(AstralError::NotFound(format!(
            "level_template {id}"
        ))));
    }

    Ok(Json(ApiResponse::success(serde_json::json!({
        "templateId": id,
        "deleted": true,
        "affectedCards": result.affected_card_ids.len(),
    }))))
}

/// POST /main/api/v1/level-templates/sync — 同步模板到所有引用卡
///
/// 当前 schema/API 尚未提供批量同步所需的完整模板来源与范围合同；明确拒绝，
/// 不返回固定成功结果，避免调用方把未执行的授权刷新当成已完成。
async fn sync_level_templates(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(_req): Json<serde_json::Value>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    Err(AppError(AstralError::NotImplemented(
        "level template sync is not implemented".into(),
    )))
}

/// POST /main/api/v1/level-templates/precheck — 预检查同步影响范围
///
/// 预检查必须和实际同步使用同一套受影响卡片查询；当前实现尚未具备该合同，
/// 因此显式拒绝而不是伪造 `ready=true`。
async fn precheck_sync(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(_req): Json<serde_json::Value>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    Err(AppError(AstralError::NotImplemented(
        "level template sync precheck is not implemented".into(),
    )))
}
