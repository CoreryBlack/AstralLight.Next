//! 执剑人（Arbiter）控制面 API —— 阶段 B。
//!
//! - `POST /arbiter/arbitrate`：跨节点证据仲裁。证据由测试协调器从各节点
//!   `evaluateWithEvidence` 通道收集后传入（对齐 README S11 的 evidence 行），
//!   本端点执行纯函数内核并返回确定性裁决。调用方负责把 `DEFER` 按
//!   fail-closed 处理（= 现有 `AUTHORIZATION_PENDING` 出口）。
//! - `GET /arbiter/stats`：仲裁统计（信号数 / 仲裁数 / 裁决分布），供监控与
//!   分布式测试断言。
//!
//! 端点挂在 `/main/api/v1` 子路由下，受 Gateway 签名 + `permission_check`
//! 权限中间件保护（资源 `monitor`，与 `/consistency` 同级）。

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::ApiResponse;
use astral_common::error::AppError;
use astral_types::{AstralError, PolicyContext, PolicyDecision};
use policy_engine::{ArbitrationVerdict, DecisionEvidence, ProjectionGate};

use crate::AppState;

/// 证据投影门禁输入（对应 `ProjectionGate` 的三个版本字段；旧
/// `projectedGeneration` 字段已随迁移 20260831000001 退役，反序列化端忽略）。
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArbiterGateInput {
    pub ready: bool,
    pub source_generation: i64,
    pub revoke_fence: i64,
}

/// 单节点决策证据输入（对齐 README S11 `evaluateWithEvidence` 行的最小集合）。
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArbiterEvidenceInput {
    pub node_id: String,
    pub allowed: bool,
    pub reason: String,
    #[serde(default)]
    pub gate: Option<ArbiterGateInput>,
}

/// 仲裁请求：评估上下文 + 跨节点证据。
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArbitrateRequest {
    pub context: PolicyContext,
    pub evidence: Vec<ArbiterEvidenceInput>,
}

/// 仲裁响应。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArbitrateResponse {
    pub verdict: String,
    pub reason_code: String,
    pub reason: String,
}

pub fn arbiter_routes() -> Router<AppState> {
    Router::new()
        .route("/arbiter/arbitrate", post(arbitrate))
        .route("/arbiter/stats", get(arbiter_stats))
}

fn verdict_str(verdict: ArbitrationVerdict) -> &'static str {
    match verdict {
        ArbitrationVerdict::Allow => "ALLOW",
        ArbitrationVerdict::Deny => "DENY",
        ArbitrationVerdict::Defer => "DEFER",
    }
}

/// POST /main/api/v1/arbiter/arbitrate — 跨节点证据仲裁。
async fn arbitrate(
    State(state): State<AppState>,
    Json(req): Json<ArbitrateRequest>,
) -> Result<Json<ApiResponse<ArbitrateResponse>>, AppError> {
    if req.evidence.is_empty() {
        return Err(AppError(AstralError::Validation(
            "arbiter evidence required".into(),
        )));
    }
    if req.context.action.trim().is_empty() {
        return Err(AppError(AstralError::Validation(
            "arbiter context action required".into(),
        )));
    }

    let evidence = req
        .evidence
        .into_iter()
        .map(|input| DecisionEvidence {
            node_id: input.node_id,
            decision: PolicyDecision {
                allowed: input.allowed,
                reason: input.reason,
                matched_rule: None,
                audit_required: true,
                evaluation_path: vec![],
                matched_rule_id: None,
                condition_results: None,
                snapshot_version: None,
                org_provenance: None,
            },
            gate: input.gate.map(|g| ProjectionGate {
                ready: g.ready,
                source_generation: g.source_generation,
                revoke_fence: g.revoke_fence,
            }),
            observed_at_ms: time::OffsetDateTime::now_utc().unix_timestamp() * 1000,
        })
        .collect();

    let outcome = state
        .arbiter_service
        .arbitrate(&req.context, evidence)
        .await;
    Ok(Json(ApiResponse::success(ArbitrateResponse {
        verdict: verdict_str(outcome.verdict).to_string(),
        reason_code: outcome.reason_code,
        reason: outcome.reason,
    })))
}

/// GET /main/api/v1/arbiter/stats — 仲裁统计。
async fn arbiter_stats(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    Ok(Json(ApiResponse::success(
        state.arbiter_service.stats().snapshot(),
    )))
}
