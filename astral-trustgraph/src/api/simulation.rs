//! 策略模拟 API（V6/V7 旧评估路径已退役）
//!
//! 对应 Java `PolicySimulationController` 的 HTTP 面。历史上本模块基于
//! V6/V7 卡级已发布授权 evidence 读取 + 统一匹配器执行 what-if 评估，并可能
//! 返回 ALLOW；按用户授权的 V6/V7 评估与结构退役（Rust 规范 §15.8 / §15.10
//! BREAKING CHANGE），旧评估路径已整体移除：
//!
//! - 不再读取任何旧 published evidence、旧快照或旧链 head 门禁，也不构造
//!   旧 evaluate / 匹配器评估路径；
//! - 不伪造 memory-v1 / 新版规则语义：proposed 规则不再参与任何判定；
//! - HTTP 路径、admin 门禁与请求契约保留（`/simulation/evaluate`、
//!   `/simulation/what-if`，`SimulationRequest` 反序列化形状不变），两个
//!   端点恒定返回 fail-closed 的 PENDING/不可用结论（稳定前缀
//!   `simulation:unavailable;legacy_evaluation_retired`，`allowed=false`），
//!   绝不返回 ALLOW；
//! - 仿真结论不是授权证据：诊断面不 panic、不 500，也不构成授权读口或
//!   fallback；唯一授权判断入口仍是 `PolicyEngine.evaluate()`。

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::ApiResponse;
use astral_common::error::AppError;
use astral_types::AstralError;

use crate::api::require_platform_admin;
use crate::AppState;

/// What-If 模拟请求（HTTP 请求契约保留）
///
/// 退役后各字段仅维持原 camelCase 反序列化形状，不再参与任何判定。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulationRequest {
    /// 原契约字段：退役后仅保留"缺失即 Validation 拒绝"的原语义，不再用于
    /// 定位任何授权证据。
    pub card_id: Option<i64>,
    /// 原契约字段：请求资源 key；退役后不参与任何判定。
    pub resource: String,
    /// 原契约字段：请求动作；退役后不参与任何判定。
    pub action: String,
    /// 原契约字段：请求用户；退役后不参与任何判定。
    pub user_id: Option<i64>,
    /// 原契约字段：请求 domain；退役后不参与任何判定。
    pub domain_id: Option<i64>,
    /// 原契约字段：请求租户；退役后不参与任何判定。
    pub tenant_id: Option<i64>,
    /// 原契约字段：目标资源属主；退役后不参与任何判定。
    pub resource_owner_id: Option<i64>,
    /// 原契约字段：假设规则；退役后不参与任何判定（不伪造新版规则语义）。
    pub proposed_rules: Vec<ProposedRule>,
}

/// 原假设规则请求契约（保留反序列化形状；退役后不参与任何判定）。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProposedRule {
    pub effect: String,
    pub resource: String,
    pub action: String,
}

/// 模拟结果（HTTP 响应契约保留；退役后恒为 PENDING/不可用结论）。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulationResult {
    pub current_decision: SimulatedDecision,
    pub proposed_decision: SimulatedDecision,
    pub would_change: bool,
}

/// 单条模拟判定（响应契约保留；退役后 `allowed` 恒为 false，`reason` 携带
/// 稳定前缀 `simulation:unavailable;legacy_evaluation_retired`）。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulatedDecision {
    pub allowed: bool,
    pub reason: String,
    pub matched_rule_id: Option<String>,
    pub evaluation_path: Vec<String>,
}

pub fn simulation_routes() -> Router<AppState> {
    Router::new()
        .route("/simulation/evaluate", post(simulate_evaluate))
        .route("/simulation/what-if", post(simulate_what_if))
}

/// POST /main/api/v1/simulation/evaluate — 已退役的 what-if 仿真
///
/// memory—v1：旧 V6/V7 published evidence 评估与匹配已按用户授权退役；本
/// 端点保留 HTTP 路径、admin 门禁与请求契约，不再读取任何授权证据，恒定
/// 返回 PENDING/不可用结论（不返回 ALLOW，也不伪造新版规则语义）。仅允许
/// 已验证的 ACTIVE GlobalAdmin 调用，admin 边界不放宽。
async fn simulate_evaluate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SimulationRequest>,
) -> Result<Json<ApiResponse<SimulationResult>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    // 请求契约保留：card_id 缺失仍按原 Validation 语义拒绝；其余输入不再
    // 参与任何判定。
    if req.card_id.is_none() {
        return Err(AstralError::Validation("card_id required".into()).into());
    }

    Ok(Json(ApiResponse::success(retired_result())))
}

/// POST /main/api/v1/simulation/what-if — 已退役的批量 What-If
///
/// memory—v1：同 evaluate；保留 HTTP 路径、admin 门禁与请求契约，恒定返回
/// PENDING/不可用结论，不返回 ALLOW。
async fn simulate_what_if(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<Vec<SimulationRequest>>,
) -> Result<Json<ApiResponse<Vec<SimulationResult>>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let mut results = Vec::with_capacity(req.len());
    for request in &req {
        // 请求契约保留：逐条维持原 card_id 缺失 Validation 语义。
        if request.card_id.is_none() {
            return Err(AstralError::Validation("card_id required".into()).into());
        }
        results.push(retired_result());
    }

    Ok(Json(ApiResponse::success(results)))
}

// memory—v1：退役后的固定结论；当前/假设判定均为 PENDING/不可用（fail-closed
// DENY 形态，allowed 恒为 false），不产生 would_change，绝不返回 ALLOW。
fn retired_result() -> SimulationResult {
    let pending = SimulatedDecision {
        allowed: false,
        reason: "simulation:unavailable;legacy_evaluation_retired;decision=PENDING".to_string(),
        matched_rule_id: None,
        evaluation_path: vec![
            "SIMULATION:LEGACY_RETIRED".to_string(),
            "DECISION:PENDING".to_string(),
            "DEFAULT:DENY".to_string(),
        ],
    };
    SimulationResult {
        current_decision: pending.clone(),
        proposed_decision: pending,
        would_change: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 全文件守卫（生产代码段）：V6/V7 published evidence 评估与匹配已整体
    /// 退役；仿真不再读取任何证据、不构造任何 ALLOW 判定路径，HTTP 路径、
    /// admin 门禁与 PENDING/不可用结论在位。
    #[test]
    fn legacy_evaluation_is_gone_and_retirement_is_wired() {
        let source = include_str!("simulation.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("test module must be separable");

        // 旧链读取零残留（保留原有安全断言强度）。
        assert!(
            !production.contains("load_snapshot_winners"),
            "legacy snapshot winner read must be gone from simulation"
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
            !production.contains("rule_set_snapshot"),
            "legacy rule_set_snapshot identifier must be gone from simulation"
        );
        assert!(
            !production.contains("permission_rule_snapshot"),
            "legacy permission_rule_snapshot identifier must be gone from simulation"
        );
        assert!(
            !production.contains("authorization_projection_head"),
            "legacy CARD head gate must not be read by simulation any more"
        );
        assert!(
            !production.contains("MAX(version_no)"),
            "legacy MAX(version_no) snapshot read must be gone"
        );
        assert!(
            !production.contains("requires_published_card_evidence"),
            "legacy capability-marker annotation must be gone"
        );
        assert!(
            !production.contains("engine.evaluate("),
            "simulation must not construct the legacy evaluate() path any more"
        );

        // 旧 published evidence 读取与 ALLOW 匹配器零残留（本次退役面）。
        assert!(
            !production.contains("load_diagnostic_card_evidence"),
            "card-level published evidence read must be gone from simulation"
        );
        assert!(
            !production.contains("match_published_effective_grant"),
            "unified ALLOW-only matcher must be gone from simulation"
        );
        assert!(
            !production.contains("PublishedCardAuthorization"),
            "old published evidence type must be gone from simulation"
        );
        assert!(
            !production.contains("PolicyContext"),
            "evaluation context must not be constructed by retired simulation"
        );
        assert!(
            !production.contains("ProposedOverlayRule"),
            "proposed overlay evaluation must be gone (no fabricated new-version semantics)"
        );
        assert!(
            !production.contains("allowed: true"),
            "retired simulation must never produce an ALLOW decision"
        );

        // HTTP 路径、admin 门禁与 PENDING/不可用结论在位（契约与安全守卫不弱化）。
        assert!(
            production.contains(".route(\"/simulation/evaluate\""),
            "HTTP route /simulation/evaluate must be preserved"
        );
        assert!(
            production.contains(".route(\"/simulation/what-if\""),
            "HTTP route /simulation/what-if must be preserved"
        );
        assert!(
            production.contains("require_platform_admin"),
            "platform admin gate must be retained"
        );
        assert!(
            production.contains("simulation:unavailable;legacy_evaluation_retired"),
            "stable retirement prefix must be present"
        );
        assert!(
            production.contains("DECISION:PENDING"),
            "PENDING decision path must be present"
        );
    }

    /// 行为守卫：退役结论必须恒为 fail-closed DENY 形态 + PENDING 标记，
    /// 当前/假设判定一致、不产生 would_change、不含任何 matched_rule。
    #[test]
    fn retired_result_is_fail_closed_pending() {
        let result = retired_result();
        assert!(!result.current_decision.allowed);
        assert!(!result.proposed_decision.allowed);
        assert!(!result.would_change);
        assert_eq!(result.current_decision.matched_rule_id, None);
        assert_eq!(result.proposed_decision.matched_rule_id, None);
        assert!(
            result
                .current_decision
                .reason
                .starts_with("simulation:unavailable;legacy_evaluation_retired;"),
            "retired reason must keep the stable prefix, got: {}",
            result.current_decision.reason
        );
        assert!(
            result.proposed_decision.reason.contains("decision=PENDING"),
            "proposed decision must be marked PENDING, got: {}",
            result.proposed_decision.reason
        );
        assert!(
            result
                .current_decision
                .evaluation_path
                .iter()
                .any(|step| step == "DECISION:PENDING"),
            "evaluation path must carry the PENDING decision step"
        );
        assert!(
            result
                .current_decision
                .evaluation_path
                .iter()
                .any(|step| step == "DEFAULT:DENY"),
            "evaluation path must end fail-closed"
        );
    }

    /// 行为守卫：退役结论确定性恒定（多次构造完全一致，无任何输入派生语义）。
    #[test]
    fn retired_result_is_deterministic() {
        let a = retired_result();
        let b = retired_result();
        assert_eq!(a.current_decision.reason, b.current_decision.reason);
        assert_eq!(
            a.current_decision.evaluation_path,
            b.current_decision.evaluation_path
        );
        assert_eq!(a.would_change, b.would_change);
    }
}
