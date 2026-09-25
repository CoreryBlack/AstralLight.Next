//! 权限评估结果类型

/// 策略评估效果
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Effect {
    Allow,
    Deny,
    NotMatch,
}

/// 单步评估记录
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvaluationStep {
    /// 评估阶段："L1_RULESET", "L2_PERMISSION_RULE", "L3_DEFAULT_DENY"
    pub phase: String,
    pub result: Effect,
    pub detail: String,
    pub matched_rule_id: Option<i64>,
    /// 规则来源："OVERLAY", "BASE", "CARD_ONLY"
    pub source: Option<String>,
}

/// 策略决策结果
///
/// 对齐 Java `PolicyDecision` 全部字段：
/// - `allowed` / `reason` / `matchedRule` / `auditRequired` / `evaluationPath`
/// - `matchedRuleId` — 命中的规则 ID（L2 时填充）
/// - `conditionResults` — 条件评估明细
/// - `snapshotVersion` — 决策依据的快照版本（L1 时填充）
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyDecision {
    pub allowed: bool,
    pub reason: String,
    pub matched_rule: Option<String>,
    pub audit_required: bool,
    pub evaluation_path: Vec<EvaluationStep>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_rule_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition_results: Option<Vec<ConditionResult>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_version: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_provenance: Option<crate::org_scope::OrgBranchProvenance>,
}

/// 条件评估结果明细
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConditionResult {
    pub condition_type: String,
    pub matched: bool,
}
