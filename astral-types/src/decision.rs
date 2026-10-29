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
    /// 当前身份、资格、组织准入及 V6 published evidence 评估阶段。
    pub phase: String,
    pub result: Effect,
    pub detail: String,
    pub matched_rule_id: Option<i64>,
    /// 命中规则的当前来源或 binding layer。
    pub source: Option<String>,
}

/// 策略决策结果
///
/// `evaluationPath` 保存资格、组织准入与当前 published evidence 的评估记录。
/// `matchedRuleId` 和 `conditionResults` 仅在该判定分支提供相应事实时填写；
/// `snapshotVersion` 可记录已验证组织发布的 generation。
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
