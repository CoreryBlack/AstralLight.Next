//! 一致性巡检 API
//!
//! 对齐 Java `ConsistencyCheckMonitorController`。
//! 对采样卡片执行「已发布 evidence 判定 vs 实时 oracle 判定」一致性检查，
//! 返回巡检结果。
//!
//! ## 数据流（新链对照，旧链下线前置改造）
//!
//! - 新链判定：卡级 published evidence（[`crate::api::load_diagnostic_card_evidence`]，
//!   严格 reader 单短事务内锁定当前指针并整链校验 + 卡级 lens）经统一
//!   ALLOW-only 匹配器（[`crate::api::match_published_effective_grant`]，与
//!   PolicyEngine strict gate 同语义）得出 ALLOW/DENY；
//! - oracle 判定：`PolicyEngine::evaluate_realtime`（raw source，oracle 语义
//!   原样保留，强制全量比对不走 1% 采样门）；
//! - 旧链快照胜者/版本号快照表读取已全部移除，也不再进入共享 PolicyEngine
//!   evaluate() 的旧快照路径；
//! - evidence 不可用（NotReady/Corrupt/合同拒绝）→ 输出"新链不可用"结构化
//!   观测（HTTP 200 + observations 字段），不 panic、不 500（诊断端点语义）。

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use sqlx::MySqlPool;

use astral_common::contract::ApiResponse;
use astral_common::error::AppError;
use astral_common::middleware::permission::get_consistency_checker;
use astral_types::{build_resource_key, AstralError, PolicyContext};
use policy_engine::{PermissionRule, RuleRepository, RuleSetSnapshot};

use crate::api::{load_diagnostic_card_evidence, match_published_effective_grant};
use crate::AppState;

// ===== 数据模型 =====

/// 一致性巡检结果项
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsistencyCheckItem {
    pub card_id: i64,
    pub is_consistent: bool,
    /// 新链判定（已发布 evidence + 统一 ALLOW-only 匹配器），格式
    /// `"{allowed}:{reason}"`；evidence 不可用（无法证明一致性）时为 `None`，
    /// 成因见 `observations`。
    pub published_decision: Option<String>,
    /// oracle 判定（`evaluate_realtime` raw source），格式 `"{allowed}:{reason}"`。
    pub realtime_decision: Option<String>,
    /// 结构化观测（"新链不可用"成因、双方判定偏离详情）。
    pub observations: Vec<String>,
}

/// 一致性巡检汇总
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsistencyCheckResult {
    pub total_checked: i64,
    pub violations: i64,
    pub items: Vec<ConsistencyCheckItem>,
}

/// realtime oracle 专用 Repository（仅服务 `PolicyEngine::evaluate_realtime`
/// 的 raw source 读取，不再作为 `evaluate()` 的快照路径仓库使用）。
///
/// 旧链快照胜者委托读取器与读快照表的两个委托实现已随旧链下线前置改造
/// 移除；对后两个必选 trait 成员显式返回空集——`evaluate_realtime` 不
/// 消费它们，若误将本仓库用于正式评估也只会得到 fail-closed 的 DEFAULT_DENY。
struct RealtimeOracleRepo {
    db: MySqlPool,
}

#[async_trait::async_trait]
impl RuleRepository for RealtimeOracleRepo {
    /// 必选 trait 成员：oracle 路径不消费规则集快照读取器，显式空集
    /// （旧链快照表委托实现已删除，见模块文档）。
    async fn load_rule_set_snapshots(
        &self,
        _card_id: i64,
    ) -> Result<Vec<RuleSetSnapshot>, astral_types::PolicyError> {
        Ok(vec![])
    }

    /// 必选 trait 成员：oracle 路径不消费卡规则快照读取器，显式空集
    /// （旧链快照表委托实现已删除，见模块文档）。
    async fn load_permission_rules(
        &self,
        _card_id: i64,
    ) -> Result<Vec<PermissionRule>, astral_types::PolicyError> {
        Ok(vec![])
    }

    /// 一致性检查专用：原始 rule_set_entry（raw source，oracle 语义保留）。
    async fn load_rule_set_entries_raw(
        &self,
        card_id: i64,
    ) -> Result<Vec<RuleSetSnapshot>, astral_types::PolicyError> {
        let repo = astral_db::SqlxRuleRepository::new(self.db.clone());
        repo.load_rule_set_entries_raw(card_id).await
    }

    /// 一致性检查专用：原始 permission_rule（raw source，oracle 语义保留）。
    async fn load_permission_rules_raw(
        &self,
        card_id: i64,
    ) -> Result<Vec<PermissionRule>, astral_types::PolicyError> {
        let repo = astral_db::SqlxRuleRepository::new(self.db.clone());
        repo.load_permission_rules_raw(card_id).await
    }
}

// ===== 路由注册 =====

pub fn consistency_monitor_routes() -> Router<AppState> {
    Router::new()
        .route("/consistency/check", get(run_consistency_check))
        .route("/consistency/check/stats", get(get_stats))
        .route(
            "/consistency/check/violations",
            get(get_violations).delete(clear_violations),
        )
}

// ===== Handlers =====

/// GET /main/api/v1/consistency/check — 触发一致性巡检
///
/// 采样最近活跃的卡片，对每张卡执行「已发布 evidence 判定 vs 实时 oracle
/// 判定」比对（强制全量检查，不走 1% 采样门）。
async fn run_consistency_check(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<ConsistencyCheckResult>>, AppError> {
    let db = &state.db;
    let engine = &state.engine;

    // 获取采样卡片及关联 user_id（最多 50 张活跃卡）
    // 对齐 platform_v4：user_card 表含 user_id 列
    let cards: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT card_id, user_id FROM user_card WHERE card_status = 'ACTIVE' ORDER BY updated_at DESC LIMIT 50"
    )
    .fetch_all(db)
    .await
    .map_err(|e| AppError(AstralError::Database(e.to_string())))?;

    let repo = RealtimeOracleRepo { db: db.clone() };

    let mut items = Vec::new();

    for (card_id, user_id) in &cards {
        // 1. 新链判定：先读卡级已发布 evidence（严格 reader + 卡级 lens）。
        //    evidence 不可用 → "新链不可用"观测，绝不折算成空证据/DENY 判定。
        let mut observations = Vec::new();
        let evidence = match load_diagnostic_card_evidence(db, *card_id).await {
            Ok(evidence) => Some(evidence),
            Err(unavailable) => {
                observations.push(format!("新链不可用：{}", unavailable.observation()));
                None
            }
        };

        // 构造评估上下文（必须含 user_id，否则 realtime 评估直接返回
        // AUTHN_REQUIRED）。tenant 取自已发布证据的权威租户（reader 已复核
        // 租户戳），仅用于匹配器身份边界；realtime oracle 不消费 tenant。
        let ctx = PolicyContext::builder()
            .user_id(Some(*user_id))
            .card_id(Some(*card_id))
            .tenant_id(evidence.as_ref().map(|evidence| evidence.tenant_id))
            .resource(Some("*".into()))
            .action("read".into())
            .build();

        // 2. 新链判定：统一 ALLOW-only 匹配器消费 effective_grants；
        //    resourceKey 构造与 evaluate() 一致（"*" → "*:*" 类型级请求）。
        let published = evidence.map(|evidence| {
            let resource_key =
                build_resource_key(ctx.resource.as_deref().unwrap_or(""), ctx.target_id);
            let (allowed, reason) =
                match match_published_effective_grant(&ctx, &evidence, &resource_key) {
                    Some(grant) => (
                        true,
                        format!(
                            "published:{resource_key}:{}:grantId={}",
                            ctx.action,
                            grant.grant_id.as_str()
                        ),
                    ),
                    None => (
                        false,
                        format!("published:no-matching-grant:{resource_key}:{}", ctx.action),
                    ),
                };
            (allowed, format!("{allowed}:{reason}"))
        });

        // 3. oracle 判定：强制全量比对（不经过 1% 采样门），直接调用
        //    evaluate_realtime（raw source，oracle 语义保留）。
        let realtime = engine.evaluate_realtime(&ctx, &repo).await;
        let realtime_str = format!("{}:{}", realtime.allowed, realtime.reason);

        // 4. 对比结论：只比较 allowed 位（对齐既有语义，原因串仅作观测展示）。
        //    - 一致：对齐既有形状，decision 串不输出；
        //    - 偏离：输出双方 decision + 偏离观测，计入 violations；
        //    - 新链不可用：无法证明一致性，同样计入 violations，成因见
        //      observations（violations 与 !is_consistent 条数一一对应）。
        let (is_consistent, published_str, realtime_field) = match published {
            Some((published_allowed, published_str)) => {
                if published_allowed == realtime.allowed {
                    (true, None, None)
                } else {
                    observations.push(format!(
                        "偏离：新链={published_str} realtime={realtime_str}"
                    ));
                    (false, Some(published_str), Some(realtime_str))
                }
            }
            None => (false, None, Some(realtime_str)),
        };

        items.push(ConsistencyCheckItem {
            card_id: *card_id,
            is_consistent,
            published_decision: published_str,
            realtime_decision: realtime_field,
            observations,
        });
    }

    let total = items.len() as i64;
    // violations 与 !is_consistent 条数一一对应（含"新链不可用"项）。
    let violations = items.iter().filter(|item| !item.is_consistent).count() as i64;

    tracing::info!(total, violations, "consistency check completed");

    Ok(Json(ApiResponse::success(ConsistencyCheckResult {
        total_checked: total,
        violations,
        items,
    })))
}

/// GET /consistency-check/stats — 一致性检查统计
/// 对齐 Java ConsistencyCheckMonitorController.stats()
async fn get_stats() -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    let checker = get_consistency_checker();
    let stats = checker.get_stats();

    let mut data = serde_json::Map::new();
    data.insert(
        "consistencyCheck".to_string(),
        serde_json::Value::Object(stats.into_iter().collect()),
    );

    Ok(Json(ApiResponse::success(serde_json::Value::Object(data))))
}

/// GET /consistency-check/violations — 获取当前违规记录
/// 对齐 Java ConsistencyCheckMonitorController.violations()
async fn get_violations() -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    let checker = get_consistency_checker();
    let violations = checker.get_violations();
    let count = violations.len();

    Ok(Json(ApiResponse::success(serde_json::json!({
        "count": count,
        "violations": violations,
    }))))
}

/// DELETE /consistency-check/violations — 清除违规记录
/// 对齐 Java ConsistencyCheckMonitorController.clearViolations()
async fn clear_violations() -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    let checker = get_consistency_checker();
    checker.clear_violations();
    Ok(Json(ApiResponse::success(serde_json::json!({
        "message": "violations cleared"
    }))))
}

#[cfg(test)]
mod tests {
    /// 全文件守卫（生产代码段）：旧链快照读取已从一致性巡检清除，新链数据
    /// 通路（卡级 evidence 读取 + 统一匹配器）在位，realtime oracle 保留。
    #[test]
    fn legacy_snapshot_reads_are_gone_and_new_chain_path_is_wired() {
        let source = include_str!("consistency_monitor.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("test module must be separable");

        // 旧链读取零残留
        assert!(
            !production.contains("load_snapshot_winners"),
            "legacy snapshot winner read must be gone from consistency monitor"
        );
        assert!(
            !production.contains("MAX(version_no)"),
            "legacy MAX(version_no) snapshot read must be gone"
        );
        assert!(
            !production.contains("FROM rule_set_snapshot"),
            "legacy rule_set_snapshot table must not be read"
        );
        assert!(
            !production.contains("FROM permission_rule_snapshot"),
            "legacy permission_rule_snapshot table must not be read"
        );
        assert!(
            !production.contains("requires_published_card_evidence"),
            "legacy capability-marker annotation must be gone"
        );
        assert!(
            !production.contains("engine.evaluate("),
            "monitor must not run the legacy evaluate() snapshot path any more"
        );

        // 新链数据通路在位
        assert!(
            production.contains("load_diagnostic_card_evidence"),
            "card-level published evidence read must be wired"
        );
        assert!(
            production.contains("match_published_effective_grant"),
            "unified ALLOW-only matcher must be wired"
        );
        // realtime oracle 对照保留
        assert!(production.contains("evaluate_realtime"));
    }

    /// 形状守卫：run_consistency_check 必须先读取已发布 evidence，再调用
    /// realtime oracle；evidence 不可用时输出"新链不可用"结构化观测而不是
    /// panic / 500。
    #[test]
    fn evidence_read_precedes_realtime_oracle_and_marks_unavailable() {
        let source = include_str!("consistency_monitor.rs");
        let body = source
            .split("async fn run_consistency_check")
            .nth(1)
            .expect("run_consistency_check must exist");

        let evidence = body
            .find("load_diagnostic_card_evidence(db, *card_id)")
            .expect("card-level evidence read must exist");
        let oracle = body
            .find("evaluate_realtime")
            .expect("realtime oracle must be retained");
        assert!(
            evidence < oracle,
            "published evidence read must precede the realtime oracle call"
        );
        assert!(
            body.contains("新链不可用"),
            "evidence unavailability must be surfaced as a structured observation"
        );
    }
}
