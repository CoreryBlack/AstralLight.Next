//! 统计与监控 API — HTTP adapter
//!
//! 暴露 PolicyEngine 的命中计数（L1/L2/L3）和纳秒级时序分解（纯内存）。
//! DB 级命中统计查询（summary / top-resources / zero-hit / by-card）数据访问
//! 在 `repository::hit_stat_repository`；top-resources 走 `astral_db` 共享读。

use axum::extract::{Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use policy_engine::HitStats;

use astral_common::contract::ApiResponse;
use astral_common::error::AppError;
use astral_db::find_top_permission_hit_stats;

use crate::service::authorization_projector::ProjectorHealthSnapshot;
use crate::AppState;

pub fn stats_routes() -> Router<AppState> {
    Router::new()
        // 内存级统计（PolicyEngine L1/L2/L3 命中 + 时序分解）
        .route("/stats", get(get_stats))
        .route("/stats/reset", post(reset_stats))
        // 投影 worker 监督健康快照（F5 修复 1d）
        .route("/stats/projector", get(projector_health))
        // DB 级命中统计（对齐 Java HitStatController）
        .route("/hit-stats/summary", get(hit_stat_summary))
        .route("/hit-stats/top-resources", get(hit_stat_top_resources))
        .route("/hit-stats/zero-hit", get(hit_stat_zero_hit))
        .route("/hit-stats/by-card", get(hit_stat_by_card))
}

/// GET /main/api/v1/stats — 返回当前命中计数与时序分解（纯内存）
async fn get_stats(State(state): State<AppState>) -> Result<Json<ApiResponse<HitStats>>, AppError> {
    let stats = state.engine.get_stats();
    Ok(Json(ApiResponse::success(stats)))
}

/// POST /main/api/v1/stats/reset — 重置命中计数与时序（仅开发/调试用途）
async fn reset_stats(State(state): State<AppState>) -> Result<Json<ApiResponse<()>>, AppError> {
    state.engine.reset_stats();
    Ok(Json(ApiResponse::success(())))
}

/// GET /main/api/v1/stats/projector — 投影 worker 监督健康快照（F5 修复 1d）。
/// 只含聚合计数、代数/重启数与时间戳——无租户/卡/grant 语义、无 lease token。
/// projector 未启动（配置拒绝启动）时如实返回 `None`。
async fn projector_health(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Option<ProjectorHealthSnapshot>>>, AppError> {
    Ok(Json(ApiResponse::success(
        state.projector_health.get().map(|health| health.snapshot()),
    )))
}

// ===== DB 级命中统计（对齐 Java HitStatController + HitStatServiceImpl）=====

/// 命中统计概览 DTO（对齐 Java HitStatSummaryDto）
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HitStatSummary {
    pub total_hits: i64,
    pub rules_with_hits: i64,
    pub zero_hit_rules: i64,
    pub hit_rate: f64,
}

/// Top 资源命中 DTO（对齐 Java HitStatTopResourceDto）
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HitStatTopResource {
    pub resource_type: String,
    pub action_code: String,
    pub hit_count: i64,
    pub last_hit_at: Option<i64>,
}

/// 零命中权限 DTO（对齐 Java HitStatZeroHitDto）
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HitStatZeroHit {
    pub resource_type: String,
    pub action_code: String,
    pub rule_count: i64,
}

/// 查询参数：limit
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LimitQuery {
    pub limit: Option<i32>,
}

/// 查询参数：cardId + limit（前端 /hit-stats/by-card?cardId=X&limit=Y）
#[derive(Debug, Deserialize)]
pub struct ByCardQuery {
    #[serde(rename = "cardId")]
    pub card_id: i64,
    pub limit: Option<i32>,
}

/// GET /main/api/v1/hit-stats/summary
async fn hit_stat_summary(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<HitStatSummary>>, AppError> {
    let s = state.hit_stat_repository.summary().await?;

    let hit_rate = if s.total_rules > 0 {
        let hit_rules = s.total_rules - s.zero_hit_rules;
        (hit_rules as f64 / s.total_rules as f64) * 100.0
    } else {
        0.0
    };
    // 保留一位小数（对齐 Java Math.round(hitRate * 10.0) / 10.0）
    let hit_rate = (hit_rate * 10.0).round() / 10.0;

    Ok(Json(ApiResponse::success(HitStatSummary {
        total_hits: s.total_hits,
        rules_with_hits: s.rules_with_hits,
        zero_hit_rules: s.zero_hit_rules,
        hit_rate,
    })))
}

/// GET /main/api/v1/hit-stats/top-resources?limit=10
async fn hit_stat_top_resources(
    State(state): State<AppState>,
    Query(q): Query<LimitQuery>,
) -> Result<Json<ApiResponse<Vec<HitStatTopResource>>>, AppError> {
    let limit = q.limit.unwrap_or(10).clamp(1, 100);
    let stats = find_top_permission_hit_stats(&state.db, limit)
        .await
        .map_err(|e| astral_types::AstralError::Database(e.to_string()))?;

    let result = stats
        .into_iter()
        .map(|s| HitStatTopResource {
            resource_type: s.resource_type,
            action_code: s.action_code,
            hit_count: s.hit_count,
            last_hit_at: s.last_hit_at,
        })
        .collect();

    Ok(Json(ApiResponse::success(result)))
}

/// GET /main/api/v1/hit-stats/zero-hit
async fn hit_stat_zero_hit(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<HitStatZeroHit>>>, AppError> {
    let rows = state.hit_stat_repository.zero_hit_permissions().await?;
    Ok(Json(ApiResponse::success(
        rows.into_iter()
            .map(|r| HitStatZeroHit {
                resource_type: r.resource_type,
                action_code: r.action_code,
                rule_count: r.rule_count,
            })
            .collect(),
    )))
}

/// GET /main/api/v1/hit-stats/by-card?cardId=X&limit=10
async fn hit_stat_by_card(
    State(state): State<AppState>,
    Query(q): Query<ByCardQuery>,
) -> Result<Json<ApiResponse<Vec<HitStatTopResource>>>, AppError> {
    let limit = q.limit.unwrap_or(10).clamp(1, 100);
    let rows = state
        .hit_stat_repository
        .by_card(q.card_id, limit as i64)
        .await?;
    Ok(Json(ApiResponse::success(
        rows.into_iter()
            .map(|r| HitStatTopResource {
                resource_type: r.resource_type,
                action_code: r.action_code,
                hit_count: r.hit_count,
                last_hit_at: r.last_hit_at,
            })
            .collect(),
    )))
}
