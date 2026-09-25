//! 审计日志 API — HTTP adapter
//!
//! 对应 Java `AuditController`。数据访问在 `repository::audit_log_repository`。

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::{ApiResponse, PageResponse, PaginationParams};
use astral_common::error::AppError;

use crate::repository::audit_log_repository::AuditLogRecord;
use crate::AppState;

/// 审计日志条目响应 DTO
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntry {
    pub id: i64,
    pub created_at: Option<String>,
    pub user_id: i64,
    pub action: String,
    pub resource: String,
    pub decision: String,
    pub reason: Option<String>,
    pub card_id: Option<i64>,
}

impl From<AuditLogRecord> for AuditEntry {
    fn from(r: AuditLogRecord) -> Self {
        Self {
            id: r.id,
            created_at: r.created_at,
            user_id: r.user_id,
            action: r.action,
            resource: r.resource,
            decision: r.decision,
            reason: r.reason,
            card_id: r.card_id,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditQuery {
    pub user_id: Option<i64>,
    pub action: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub page: Option<i64>,
    pub size: Option<i64>,
}

pub fn audit_routes() -> Router<AppState> {
    Router::new()
        .route("/audit/logs", get(list_audit_logs))
        .route("/audit/stats", get(audit_stats))
}

async fn list_audit_logs(
    State(state): State<AppState>,
    Query(query): Query<AuditQuery>,
    Query(page): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<AuditEntry>>>, AppError> {
    let size = query.size.unwrap_or(page.effective_size()).min(1000);
    let offset = (query.page.unwrap_or(page.page).max(1) - 1) * size;

    let total = state.audit_log_repository.count_logs().await?;
    let rows = state
        .audit_log_repository
        .list_logs(size, offset)
        .await?
        .into_iter()
        .map(AuditEntry::from)
        .collect();
    Ok(Json(ApiResponse::success(PageResponse::new(
        rows, total, page.page, size,
    ))))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditStats {
    pub total_checks: i64,
    pub allowed: i64,
    pub denied: i64,
    pub unique_users: i64,
    pub top_resources: Vec<(String, i64)>,
}

async fn audit_stats(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<AuditStats>>, AppError> {
    let s = state.audit_log_repository.stats().await?;
    Ok(Json(ApiResponse::success(AuditStats {
        total_checks: s.total,
        allowed: s.allowed,
        denied: s.denied,
        unique_users: s.unique_users,
        top_resources: vec![],
    })))
}
