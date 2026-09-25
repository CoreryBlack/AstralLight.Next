//! 管理员端点 + 审计日志
//!
//! 对应 Java `AdminController` + `AuditLogService`。

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;

use astral_common::contract::{ApiResponse, PageResponse};
use astral_common::error::AppError;
use astral_db::AuditLogQueryRow;
use astral_types::AstralError;

use crate::AppState;

/// 审计日志条目
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditLogEntry {
    pub id: i64,
    pub user_id: i64,
    pub action: String,
    pub resource: String,
    pub detail: String,
    pub created_at: String,
}

/// 审计日志查询参数
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditQuery {
    pub user_id: Option<i64>,
    pub action: Option<String>,
    pub page: Option<i64>,
    pub size: Option<i64>,
}

/// 系统统计
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemStats {
    pub total_users: i64,
    pub total_cards: i64,
    pub active_sessions: i64,
    pub requests_today: i64,
}

/// DbError → AppError 辅助转换
fn db_err(e: astral_db::DbError) -> AppError {
    AppError::from(AstralError::Database(format!("{e}")))
}

/// 管理员路由
pub fn admin_routes() -> Router<AppState> {
    Router::new()
        .route("/admin/stats", get(get_stats))
        .route("/admin/audit-log", get(list_audit_log))
}

/// GET /api/v1/auth/admin/stats — 系统统计（从 DB 实时查询）
async fn get_stats(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<SystemStats>>, AppError> {
    let db_stats = astral_db::query_system_stats(&state.db)
        .await
        .map_err(db_err)?;

    let stats = SystemStats {
        total_users: db_stats.total_users,
        total_cards: db_stats.total_cards,
        active_sessions: db_stats.active_sessions,
        requests_today: db_stats.requests_today,
    };

    Ok(Json(ApiResponse::success(stats)))
}

/// GET /api/v1/auth/admin/audit-log — 审计日志（从 DB 分页查询）
async fn list_audit_log(
    State(state): State<AppState>,
    Query(query): Query<AuditQuery>,
) -> Result<Json<ApiResponse<PageResponse<AuditLogEntry>>>, AppError> {
    let page = query.page.unwrap_or(1).max(1);
    let size = query.size.unwrap_or(20).clamp(1, 100);
    let action_ref = query.action.as_deref();
    // 空 action 视为无过滤（对齐原 handler：仅非空才加 AND action = ?）
    let action_opt = action_ref.filter(|a| !a.is_empty());

    // 查询总数（astral-db count_audit_logs，与 query_audit_logs 同过滤条件）
    let total = astral_db::count_audit_logs(&state.db, query.user_id, action_opt)
        .await
        .map_err(db_err)?;

    let rows = astral_db::query_audit_logs(&state.db, query.user_id, action_opt, page, size)
        .await
        .map_err(db_err)?;

    let logs: Vec<AuditLogEntry> = rows
        .into_iter()
        .map(|r: AuditLogQueryRow| AuditLogEntry {
            id: r.id,
            user_id: r.user_id,
            action: r.action,
            resource: r.resource,
            detail: r.detail.unwrap_or_default(),
            created_at: r.created_at.map(|t| t.to_string()).unwrap_or_default(),
        })
        .collect();

    Ok(Json(ApiResponse::success(PageResponse::new(
        logs, total, page, size,
    ))))
}
