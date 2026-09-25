//! 策略模拟 API
//!
//! 对应 Java `PolicySimulationController`。
//! What-If 场景：基于卡级已发布授权 evidence 评估当前判定，并叠加假设规则
//! （OVERLAY 语义）得到假设判定。
//!
//! ## 数据流（新链，旧链下线前置改造）
//!
//! - 主判定：卡级 published evidence（[`crate::api::load_diagnostic_card_evidence`]，
//!   严格 reader 单短事务内锁定当前指针并整链校验 + 卡级 lens）经统一
//!   ALLOW-only 匹配器（[`crate::api::match_published_effective_grant`]，与
//!   PolicyEngine strict gate 同语义）——展示"若现在发起该请求，按当前已发布
//!   授权将得到 ALLOW/DENY"；
//! - 假设判定：proposed 规则按 OVERLAY 优先（首条命中即胜出），未命中回落到
//!   当前 evidence 基线（对齐旧实现的 OVERLAY→BASE 层序）；
//! - 旧链实现（SimulationRepo 注入旧读取器、直读旧链规则/卡规则快照表 +
//!   旧链 head 门禁）已全部移除；仿真不再经过 `PolicyEngine.evaluate`
//!   （避免为仿真构造完整 RuleRepository）；
//! - evidence 不可用（NotReady/Corrupt/合同拒绝/租户缺失/scope 不符）→
//!   判定 fail-closed DENY 并以稳定前缀呈现"新链不可用"，不 panic、不 500
//!   （诊断端点语义）。

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::MySqlPool;

use astral_common::contract::ApiResponse;
use astral_common::error::AppError;
use astral_types::{AstralError, Effect, PolicyContext, PublishedCardAuthorization};

use crate::api::{
    load_diagnostic_card_evidence, match_published_effective_grant, require_platform_admin,
};
use crate::AppState;

/// What-If 模拟请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulationRequest {
    pub card_id: Option<i64>,
    /// 请求资源 key（`type` / `type:*` / `type:id`，按 `parse_resource_key`
    /// 语义归一）；裸 `type` 等价类型级请求 `type:*`。
    pub resource: String,
    pub action: String,
    /// 请求用户（匹配器身份边界；缺省时一律不命中——与 strict gate 请求恒
    /// 携带 user 的语义一致）。
    pub user_id: Option<i64>,
    /// 请求 domain（携带时 grant 必须属于同一 domain）。
    pub domain_id: Option<i64>,
    /// 仅作 scope 一致性校验（与卡权威租户不符 → scope-mismatch fail-closed）；
    /// 不是授权事实，匹配器租户一律取证据的权威租户。
    pub tenant_id: Option<i64>,
    /// 目标资源属主（请求兼容保留；已发布 evidence 的生效集合为无条件 ALLOW，
    /// 匹配器不消费 owner 条件）。
    pub resource_owner_id: Option<i64>,
    pub proposed_rules: Vec<ProposedRule>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProposedRule {
    pub effect: String,
    pub resource: String,
    pub action: String,
}

/// 模拟结果
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulationResult {
    pub current_decision: SimulatedDecision,
    pub proposed_decision: SimulatedDecision,
    pub would_change: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulatedDecision {
    pub allowed: bool,
    pub reason: String,
    pub matched_rule_id: Option<String>,
    pub evaluation_path: Vec<String>,
}

/// 归一化后的假设规则（OVERLAY 语义：首条命中即胜出，未命中回落 evidence 基线）。
struct ProposedOverlayRule {
    effect: Effect,
    resource: String,
    action: String,
}

impl ProposedOverlayRule {
    fn from_request(rule: &ProposedRule) -> Self {
        Self {
            // 对齐旧实现的宽松映射：非 ALLOW 一律按 DENY 处理（fail-closed）。
            effect: match rule.effect.to_uppercase().as_str() {
                "ALLOW" => Effect::Allow,
                _ => Effect::Deny,
            },
            resource: rule.resource.clone(),
            action: rule.action.clone(),
        }
    }

    /// 假设规则是否命中请求（资源/动作匹配语义与统一匹配器一致）。
    ///
    /// - 资源（`parse_resource_key` 语义）：类型级规则（`type:*`/裸 `type`/`*`）
    ///   可命中同类型的对象请求；对象级规则只命中同一对象；类型级请求绝不
    ///   命中对象级规则；
    /// - 动作：exact → `write` 别名（write→create/update/delete）→ `'*'`。
    fn matches(&self, resource_key: &str, action: &str) -> bool {
        let (rule_type, rule_id) = astral_types::parse_resource_key(&self.resource);
        let (request_type, request_id) = astral_types::parse_resource_key(resource_key);
        let type_level_request = request_id.is_none();
        if rule_type != request_type && rule_type != "*" {
            return false;
        }
        if type_level_request {
            if rule_id.is_some() {
                return false;
            }
        } else if rule_id.is_some() && rule_id != request_id {
            return false;
        }
        self.action == action
            || self.action == "*"
            || astral_types::get_alias_sources(action).contains(&self.action.as_str())
    }
}

pub fn simulation_routes() -> Router<AppState> {
    Router::new()
        .route("/simulation/evaluate", post(simulate_evaluate))
        .route("/simulation/what-if", post(simulate_what_if))
}

/// POST /main/api/v1/simulation/evaluate — 基于已发布授权的 what-if 仿真
///
/// 模拟接口可对任意 `card_id` 评估当前已发布授权并返回 matched_rule 与评估
/// 路径，是对已发布授权面只读的探测面；Java 无对应实现，前端也不使用。仅
/// 允许已验证的 ACTIVE GlobalAdmin 调用，避免普通 operator 枚举其他卡权限。
async fn simulate_evaluate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SimulationRequest>,
) -> Result<Json<ApiResponse<SimulationResult>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let card_id = req
        .card_id
        .ok_or_else(|| AstralError::Validation("card_id required".into()))?;

    let result = simulate_one(&state.db, card_id, &req).await;

    Ok(Json(ApiResponse::success(result)))
}

/// POST /main/api/v1/simulation/what-if — 批量 What-If
///
/// 同 evaluate：对任意卡已发布授权的只读探测面，仅限已验证 ACTIVE GlobalAdmin。
async fn simulate_what_if(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<Vec<SimulationRequest>>,
) -> Result<Json<ApiResponse<Vec<SimulationResult>>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let mut results = Vec::with_capacity(req.len());
    for request in &req {
        let card_id = request
            .card_id
            .ok_or_else(|| AstralError::Validation("card_id required".into()))?;
        results.push(simulate_one(&state.db, card_id, request).await);
    }

    Ok(Json(ApiResponse::success(results)))
}

/// 单条 what-if 仿真：主判定走已发布 evidence 匹配（与一致性巡检共享的
/// 读取路径与统一匹配器，同一严格证据语义）。
async fn simulate_one(
    db: &MySqlPool,
    card_id: i64,
    request: &SimulationRequest,
) -> SimulationResult {
    // === 卡级 published evidence 门禁（fail-closed，先于任何判定） ===
    // evidence 不可用 → fail-closed DENY + 稳定前缀"新链不可用"（诊断端点
    // 不 panic、不 500），绝不折算成空证据伪装成"无授权"基线。
    let evidence = match load_diagnostic_card_evidence(db, card_id).await {
        Ok(evidence) => evidence,
        Err(unavailable) => {
            return unavailable_result(unavailable.code, &unavailable.detail);
        }
    };

    // 请求租户必须与卡的权威租户一致（reader 已复核租户戳）；不一致时对齐
    // PolicyEngine strict gate 的 scope-mismatch 语义 fail-closed。
    if let Some(requested) = request.tenant_id {
        if requested != evidence.tenant_id {
            return unavailable_result(
                "published_card_evidence_scope_mismatch",
                &format!(
                    "request tenant {requested} does not match card tenant {}",
                    evidence.tenant_id
                ),
            );
        }
    }

    // 评估上下文：tenant 取证据权威租户；user/domain 传入匹配器做身份边界。
    let ctx = PolicyContext::builder()
        .user_id(request.user_id)
        .card_id(Some(card_id))
        .tenant_id(Some(evidence.tenant_id))
        .domain_id(request.domain_id)
        .resource(Some(request.resource.clone()))
        .action(request.action.clone())
        .resource_owner_id(request.resource_owner_id)
        .build();

    // 当前判定：已发布 evidence 匹配（无条件生效集合；CanonicalGrant 合同
    // 当前不含 condition 字段，resource_owner_id 仅作请求兼容保留）。
    let current_decision = evidence_decision(&ctx, &evidence, &request.resource);

    // 假设判定：proposed 规则 OVERLAY 优先（首条命中即胜出），未命中回落
    // evidence 基线。
    let proposed_decision = match request
        .proposed_rules
        .iter()
        .map(ProposedOverlayRule::from_request)
        .enumerate()
        .find(|(_, rule)| rule.matches(&request.resource, &request.action))
    {
        Some((index, rule)) => {
            let (allowed, effect_label) = match rule.effect {
                Effect::Allow => (true, "ALLOW"),
                _ => (false, "DENY"),
            };
            SimulatedDecision {
                allowed,
                reason: format!(
                    "simulation:proposed-overlay:{}:{}:effect={effect_label}",
                    request.resource, request.action
                ),
                matched_rule_id: Some(format!("proposed[{index}]")),
                evaluation_path: vec![format!("PROPOSED_OVERLAY:{effect_label}")],
            }
        }
        None => {
            let mut decision = evidence_decision(&ctx, &evidence, &request.resource);
            decision
                .evaluation_path
                .insert(0, "PROPOSED_OVERLAY:NO_MATCH".into());
            decision
        }
    };

    SimulationResult {
        would_change: current_decision.allowed != proposed_decision.allowed,
        current_decision,
        proposed_decision,
    }
}

/// 基于已发布 evidence 的统一匹配器判定（仿真主判定路径）。
fn evidence_decision(
    ctx: &PolicyContext,
    evidence: &PublishedCardAuthorization,
    resource_key: &str,
) -> SimulatedDecision {
    match match_published_effective_grant(ctx, evidence, resource_key) {
        Some(grant) => SimulatedDecision {
            allowed: true,
            reason: format!(
                "published:{resource_key}:{}:cardId={}",
                ctx.action,
                ctx.card_id.unwrap_or(0)
            ),
            matched_rule_id: Some(grant.grant_id.as_str()),
            evaluation_path: vec!["PUBLISHED_EVIDENCE:ALLOW".into()],
        },
        None => SimulatedDecision {
            allowed: false,
            reason: format!("published:no-matching-grant:{resource_key}:{}", ctx.action),
            matched_rule_id: None,
            evaluation_path: vec!["PUBLISHED_EVIDENCE:DENY".into(), "DEFAULT:DENY".into()],
        },
    }
}

/// evidence 不可用（NotReady/Corrupt/合同拒绝/租户缺失/scope 不符）时的
/// fail-closed 仿真结论：当前/假设判定均 DENY + 稳定前缀"新链不可用"。
fn unavailable_result(code: &str, detail: &str) -> SimulationResult {
    let denied = SimulatedDecision {
        allowed: false,
        reason: format!("published:unavailable;{code};detail={detail}"),
        matched_rule_id: None,
        evaluation_path: vec![
            "PUBLISHED_EVIDENCE:UNAVAILABLE".into(),
            "DEFAULT:DENY".into(),
        ],
    };
    SimulationResult {
        current_decision: denied.clone(),
        proposed_decision: denied,
        would_change: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 全文件守卫（生产代码段）：旧链快照读取与旧链 head 门禁已从仿真移除，
    /// 新链 evidence 数据通路在位。
    #[test]
    fn legacy_snapshot_reads_are_gone_from_simulation() {
        let source = include_str!("simulation.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("test module must be separable");

        // 旧链读取零残留
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
        // 旧链快照表名在生产代码段（含文档）零残留（对齐 sod_check.rs 守卫强度）。
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

        // 新链数据通路在位
        assert!(
            production.contains("load_diagnostic_card_evidence"),
            "card-level published evidence read must be wired"
        );
        assert!(
            production.contains("match_published_effective_grant"),
            "unified ALLOW-only matcher must be wired"
        );
    }

    // ===== 假设规则（OVERLAY）匹配语义 =====

    fn overlay(effect: &str, resource: &str, action: &str) -> ProposedOverlayRule {
        ProposedOverlayRule::from_request(&ProposedRule {
            effect: effect.to_string(),
            resource: resource.to_string(),
            action: action.to_string(),
        })
    }

    #[test]
    fn proposed_type_level_rule_matches_object_and_type_requests() {
        let rule = overlay("ALLOW", "learn_subject:*", "read");
        assert!(rule.matches("learn_subject:42", "read"));
        assert!(rule.matches("learn_subject", "read"));
        assert!(rule.matches("learn_subject:*", "read"));
        // 其它类型不命中。
        assert!(!rule.matches("approval:1", "read"));
        // 类型级请求绝不命中对象级规则。
        assert!(!overlay("ALLOW", "learn_subject:42", "read").matches("learn_subject", "read"));
        assert!(!overlay("ALLOW", "learn_subject:42", "read").matches("learn_subject:*", "read"));
        // 对象级规则只命中同一对象。
        assert!(overlay("ALLOW", "learn_subject:42", "read").matches("learn_subject:42", "read"));
        assert!(!overlay("ALLOW", "learn_subject:42", "read").matches("learn_subject:43", "read"));
        // 全局通配。
        assert!(overlay("DENY", "*", "read").matches("anything:1", "read"));
    }

    #[test]
    fn proposed_action_matching_supports_exact_alias_and_wildcard() {
        // write 别名展开：create/update/delete 请求可命中 write 规则。
        let rule = overlay("ALLOW", "learn_subject:*", "write");
        assert!(rule.matches("learn_subject:1", "create"));
        assert!(rule.matches("learn_subject:1", "update"));
        assert!(rule.matches("learn_subject:1", "delete"));
        assert!(!rule.matches("learn_subject:1", "read"));
        // 通配动作命中任意请求动作；exact 照常命中。
        assert!(overlay("ALLOW", "learn_subject:*", "*").matches("learn_subject:1", "read"));
        assert!(overlay("ALLOW", "learn_subject:*", "read").matches("learn_subject:1", "read"));
    }

    #[test]
    fn proposed_effect_normalization_is_deny_biased() {
        // 非 ALLOW 一律按 DENY（对齐旧实现的宽松映射，fail-closed）。
        assert!(matches!(
            overlay("DENY", "a:1", "read").effect,
            Effect::Deny
        ));
        assert!(matches!(
            overlay("allow", "a:1", "read").effect,
            Effect::Allow
        ));
        assert!(matches!(
            overlay("bogus", "a:1", "read").effect,
            Effect::Deny
        ));
    }

    /// 形状守卫：unavailable 结论必须是 fail-closed DENY + 稳定前缀，
    /// 当前/假设判定一致且不产生 would_change。
    #[test]
    fn unavailable_result_is_fail_closed_with_stable_prefix() {
        let result = unavailable_result("published_card_evidence_not_ready", "pointer missing");
        assert!(!result.current_decision.allowed);
        assert!(!result.proposed_decision.allowed);
        assert!(!result.would_change);
        assert!(
            result
                .current_decision
                .reason
                .starts_with("published:unavailable;published_card_evidence_not_ready;"),
            "unavailable reason must keep the stable prefix, got: {}",
            result.current_decision.reason
        );
    }
}
