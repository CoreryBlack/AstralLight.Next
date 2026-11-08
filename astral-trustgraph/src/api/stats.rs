//! 统计与监控 API — HTTP adapter
//!
//! Exposes PolicyEngine evaluation and decision counts with nanosecond timing breakdowns (in-memory).
//! DB 级命中统计查询（summary / top-resources / zero-hit / by-card）数据访问
//! 在 `repository::hit_stat_repository`；top-resources 走 `astral_db` 共享读。

use axum::extract::{Extension, Query, State};
use axum::http::HeaderMap;
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
        // In-memory evaluation/decision counts and timing breakdowns
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

/// POST /main/api/v1/stats/reset — auditable local observation boundary.
async fn reset_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy): Extension<astral_types::PolicyContext>,
    Extension(admission): Extension<astral_types::AuthorizationAdmission>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    let context = astral_db::ProtectedMutationContext::from_policy_context(
        &policy,
        admission,
        headers
            .get("x-request-id")
            .and_then(|value| value.to_str().ok()),
        "monitor",
        "reset",
        None,
    )?;
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|error| astral_types::AstralError::Database(error.to_string()))?;
    match astral_db::begin_protected_mutation_in_tx(&mut tx, &context, &serde_json::json!({}))
        .await?
    {
        astral_db::ProtectedMutationStart::Completed(_) => {
            return Err(AppError(astral_types::AstralError::Pending(
                "stats reset was already admitted; its process-local outcome cannot be replayed or proven after restart".into(),
            )));
        }
        astral_db::ProtectedMutationStart::New => {
            // The reset itself is a POSTCOMMIT in-memory side effect on this
            // process. The durable artifact is the explicit request intent
            // ONLY: the business result and the source evidence both record
            // resetProven=false, and no SQL marker is ever claimed to prove
            // the in-memory reset. The durable before/after of the intent row
            // (result_json absent -> written) is the typed evidence.
            let intent_before: Option<String> = sqlx::query_scalar(
                "SELECT CAST(result_json AS CHAR) FROM protected_mutation_operation \
                 WHERE operation_id = ? AND resource = ?",
            )
            .bind(context.operation_id())
            .bind("monitor")
            .fetch_optional(&mut *tx)
            .await
            .map_err(|error| astral_types::AstralError::Database(error.to_string()))?;
            let result = serde_json::json!({
                "status": "RESET_INTENT_RECORDED",
                "resetProven": false,
                "resetEffect": "postcommit-in-memory",
            });
            let evidence = astral_db::ProtectedSourceEvidence::new()
                .target_row(astral_db::TargetRowEvidence {
                    entity: "protected_mutation_operation",
                    key: serde_json::json!({
                        "operationId": context.operation_id(),
                        "resource": "monitor",
                    }),
                    before: astral_db::RowPresence::from_option(intent_before.map(|result_json| {
                        serde_json::json!({
                            "operationId": context.operation_id(),
                            "resource": "monitor",
                            "resultJson": result_json,
                        })
                    })),
                    after: astral_db::RowPresence::Present(serde_json::json!({
                        "operationId": context.operation_id(),
                        "resource": "monitor",
                        "resultJson": result,
                    })),
                })
                .map_err(|error| astral_types::AstralError::Pending(error.to_string()))?
                .receipt(
                    "protected_mutation_operation",
                    serde_json::json!({
                        "operationId": context.operation_id(),
                        "resource": "monitor",
                    }),
                    astral_db::WriteKind::Probe,
                    1,
                );
            astral_db::finish_protected_mutation_in_tx(&mut tx, &context, &result, &evidence)
                .await?;
        }
    }
    tx.commit().await.map_err(|error| {
        astral_types::AstralError::Pending(format!(
            "stats reset admission COMMIT outcome unknown; reconcile operation {}: {error}",
            context.operation_id(),
        ))
    })?;
    // Postcommit in-memory effect. The HTTP response acknowledges the local
    // reset attempt; the durable record above intentionally never claims an
    // exactly-once reset.
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

/// Parse the card id using the same explicit query-key contract as middleware.
fn query_target_id_for_card_stats(query: &ByCardQuery) -> Option<i64> {
    (query.card_id > 0).then_some(query.card_id)
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

async fn hit_stat_by_card(
    State(state): State<AppState>,
    Query(q): Query<ByCardQuery>,
) -> Result<Json<ApiResponse<Vec<HitStatTopResource>>>, AppError> {
    let limit = q.limit.unwrap_or(10).clamp(1, 100);
    let rows = state
        .hit_stat_repository
        .by_card(
            query_target_id_for_card_stats(&q).ok_or_else(|| {
                AppError(astral_types::AstralError::Validation(
                    "cardId must be a positive integer".into(),
                ))
            })?,
            limit as i64,
        )
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

#[cfg(test)]
mod tests {
    use super::{query_target_id_for_card_stats, ByCardQuery};

    #[test]
    fn by_card_query_uses_a_positive_card_target() {
        for (card_id, expected) in [(42, Some(42)), (0, None), (-1, None)] {
            assert_eq!(
                query_target_id_for_card_stats(&ByCardQuery {
                    card_id,
                    limit: Some(10)
                }),
                expected
            );
        }
    }
}
