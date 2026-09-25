//! 全局管理员 API — HTTP adapter
//!
//! 对齐 Java `GlobalAdminController` + `GlobalAdminService`。
//! 管理 `identity_global_admin` 表（系统级全局管理员）。
//! 数据访问在 `repository::global_admin_repository`（含 disable 的最后活跃
//! 管理员原子保护），HTTP 层仅解析参数并包装响应。
//!
//! 端点（全部挂载在 `/main/api/v1/global-admins` 下）：
//! - `GET /` — 查询全局管理员列表（可选 ?status=ACTIVE/DISABLED）
//! - `GET /summary` — 汇总统计（activeCount + allCount）
//! - `POST /grant` — 授予全局管理员权限
//! - `POST /enable` — 启用全局管理员
//! - `POST /disable` — 禁用全局管理员（保护最后一位活跃管理员）
//!
//! 安全设计：
//! - 路由级权限由 permission_check 中间件统一管理（/global-admins → authorization resource）
//! - granted_by 绑定调用者身份（从 X-User-Id 头提取）
//! - disable 使用派生表绕过 MySQL 1093 限制（并发保护依赖 UNIQUE KEY uk_identity_global_admin_user_id）

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::ApiResponse;
use astral_common::error::AppError;
use astral_types::AstralError;

use crate::repository::global_admin_repository::{DisableOutcome, GlobalAdminRecord};
use crate::AppState;

/// 响应 DTO（对齐 Java IdentityGlobalAdmin 的 camelCase 序列化）
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GlobalAdminDto {
    pub id: i64,
    pub user_id: i64,
    pub status: String,
    pub granted_by: Option<i64>,
    pub granted_reason: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub card_id: Option<i64>,
    pub provisioning_status: Option<String>,
    pub revocation_status: Option<String>,
}

impl From<GlobalAdminRecord> for GlobalAdminDto {
    fn from(r: GlobalAdminRecord) -> Self {
        Self {
            id: r.id,
            user_id: r.user_id,
            status: r.status,
            granted_by: r.granted_by,
            granted_reason: r.granted_reason,
            created_at: r.created_at,
            updated_at: r.updated_at,
            card_id: None,
            provisioning_status: None,
            revocation_status: None,
        }
    }
}

/// 请求体（grant / enable / disable 共用）
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GlobalAdminOperateRequest {
    pub user_id: i64,
    #[serde(default)]
    pub reason: Option<String>,
}

/// 查询参数
#[derive(Debug, Deserialize)]
struct ListParams {
    status: Option<String>,
}

const STATUS_ACTIVE: &str = "ACTIVE";
const STATUS_DISABLED: &str = "DISABLED";

/// 注册路由
pub fn global_admin_routes() -> Router<AppState> {
    Router::new()
        .route("/global-admins", get(list))
        .route("/global-admins/summary", get(summary))
        .route("/global-admins/grant", post(grant))
        .route("/global-admins/enable", post(enable))
        .route("/global-admins/disable", post(disable))
}

// ===== 调用者身份提取（从 Gateway 注入的 X-User-Id 头） =====

/// 提取调用者身份（从 Gateway 注入的 X-User-Id 头）
/// 权限判定由 permission_check 中间件统一处理（/global-admins → authorization resource）
fn extract_caller_id(headers: &HeaderMap) -> Option<i64> {
    headers
        .get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<i64>().ok())
}

// ===== Handlers =====

/// GET /global-admins — 查询列表
async fn list(
    State(state): State<AppState>,
    _headers: HeaderMap,
    Query(params): Query<ListParams>,
) -> Result<Json<ApiResponse<Vec<GlobalAdminDto>>>, AppError> {
    let normalized = params.status.as_deref().map(normalize_status).transpose()?;
    let rows = state
        .global_admin_repository
        .list_admins(normalized.as_deref())
        .await?;
    let dtos: Vec<GlobalAdminDto> = rows.into_iter().map(Into::into).collect();
    Ok(Json(ApiResponse::success(dtos)))
}

/// GET /global-admins/summary — 汇总
async fn summary(
    State(state): State<AppState>,
    _headers: HeaderMap,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    let active_count = state.global_admin_repository.count_active().await?;
    let all_count = state.global_admin_repository.count_all().await?;

    Ok(Json(ApiResponse::success(serde_json::json!({
        "activeCount": active_count,
        "allCount": all_count
    }))))
}

/// 解析 `__SUPERADMIN__` 模板及其 TEMPLATE 来源 BASE 规则集。
async fn resolve_superadmin_prerequisites(db: &sqlx::MySqlPool) -> Result<(i64, i64), AstralError> {
    sqlx::query_as(
        "SELECT t.template_id, rs.rule_set_id \
         FROM user_card_template t \
         INNER JOIN rule_set rs ON rs.source_type = 'TEMPLATE' AND rs.source_id = t.template_id \
         WHERE t.template_code = '__SUPERADMIN__' \
           AND t.status = 'ACTIVE' AND rs.enabled = 1 \
         ORDER BY rs.rule_set_id LIMIT 1",
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AstralError::Database(format!("Resolve superadmin rule set failed: {e}")))?
    .ok_or_else(|| {
        AstralError::NotFound("__SUPERADMIN__ template or rule set not initialized".into())
    })
}

/// POST /global-admins/grant — 授予全局管理员
async fn grant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<GlobalAdminOperateRequest>,
) -> Result<Json<ApiResponse<GlobalAdminDto>>, AppError> {
    grant_or_enable(state, headers, body, false).await
}

async fn grant_or_enable(
    state: AppState,
    headers: HeaderMap,
    body: GlobalAdminOperateRequest,
    enabling: bool,
) -> Result<Json<ApiResponse<GlobalAdminDto>>, AppError> {
    let caller_id = extract_caller_id(&headers)
        .ok_or_else(|| AppError(AstralError::Auth("caller_identity_required".into())))?;
    let user_id = body.user_id;
    let reason = body.reason.filter(|s| !s.trim().is_empty());

    let (template_id, rule_set_id) = resolve_superadmin_prerequisites(&state.db).await?;
    let outcome = state
        .global_admin_repository
        .grant_with_superadmin_privilege(
            user_id,
            caller_id,
            reason.as_deref(),
            template_id,
            rule_set_id,
        )
        .await?;

    let revocation_reason = if enabling {
        "GLOBAL_ADMIN_ENABLED"
    } else {
        "GLOBAL_ADMIN_GRANTED"
    };
    let revocation_status = match crate::api::side_effects::publish_auth_session_revocation(
        &state.db,
        user_id,
        revocation_reason,
    )
    .await
    {
        Ok(()) => "READY",
        Err(AstralError::Internal(message)) if message.contains("pending") => {
            tracing::warn!(
                user_id,
                reason = revocation_reason,
                "global admin session revocation pending"
            );
            "PENDING"
        }
        Err(error) => return Err(AppError(error)),
    };

    let mut dto = state
        .global_admin_repository
        .get_by_id(outcome.admin_id)
        .await?
        .map(GlobalAdminDto::from)
        .ok_or_else(|| AppError(AstralError::Internal("global_admin_load_failed".into())))?;
    dto.card_id = Some(outcome.card_id);
    dto.provisioning_status = Some(if outcome.projection_ready {
        "READY".into()
    } else {
        "PENDING".into()
    });
    dto.revocation_status = Some(revocation_status.into());
    Ok(Json(ApiResponse::success(dto)))
}

/// POST /global-admins/enable — 启用（语义同 grant）
async fn enable(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<GlobalAdminOperateRequest>,
) -> Result<Json<ApiResponse<GlobalAdminDto>>, AppError> {
    grant_or_enable(state, headers, body, true).await
}

/// POST /global-admins/disable — 禁用
async fn disable(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<GlobalAdminOperateRequest>,
) -> Result<Json<ApiResponse<GlobalAdminDto>>, AppError> {
    let caller_id = extract_caller_id(&headers)
        .ok_or_else(|| AppError(AstralError::Auth("caller_identity_required".into())))?;
    let user_id = body.user_id;
    let reason = body.reason.filter(|s| !s.trim().is_empty());

    let existing = state
        .global_admin_repository
        .get_by_user_id(user_id)
        .await?
        .ok_or_else(|| AppError(AstralError::NotFound("global_admin_not_found".into())))?;

    if existing.status.eq_ignore_ascii_case(STATUS_DISABLED) {
        let mut dto = GlobalAdminDto::from(existing);
        dto.revocation_status = Some("NOT_REQUIRED".into());
        return Ok(Json(ApiResponse::success(dto)));
    }

    // 原子保护：repository 内部封装派生表子查询 + 最后活跃回查
    let outcome = state
        .global_admin_repository
        .disable_protected(existing.id, user_id, caller_id, reason.as_deref())
        .await?;
    match outcome {
        DisableOutcome::Disabled => {}
        DisableOutcome::LastAdminProtected => {
            return Err(AppError(AstralError::Validation(
                "LAST_GLOBAL_ADMIN_PROTECTED".into(),
            )));
        }
        DisableOutcome::UpdateFailed => {
            return Err(AppError(AstralError::Internal("update_failed".into())));
        }
    }

    let revocation_status = match crate::api::side_effects::publish_auth_session_revocation(
        &state.db,
        user_id,
        reason.as_deref().unwrap_or("GLOBAL_ADMIN_DISABLED"),
    )
    .await
    {
        Ok(()) => "READY",
        Err(AstralError::Internal(message)) if message.contains("pending") => {
            tracing::warn!(user_id, "global admin disable session revocation pending");
            "PENDING"
        }
        Err(error) => return Err(AppError(error)),
    };

    let mut dto = state
        .global_admin_repository
        .get_by_id(existing.id)
        .await?
        .map(GlobalAdminDto::from)
        .ok_or_else(|| AppError(AstralError::Internal("global_admin_load_failed".into())))?;
    dto.revocation_status = Some(revocation_status.into());
    Ok(Json(ApiResponse::success(dto)))
}

// ===== 辅助函数 =====

fn normalize_status(raw: &str) -> Result<String, AppError> {
    let upper = raw.trim().to_uppercase();
    match upper.as_str() {
        STATUS_ACTIVE | STATUS_DISABLED => Ok(upper),
        _ => Err(AppError(AstralError::Validation(
            "invalid_global_admin_status".into(),
        ))),
    }
}
