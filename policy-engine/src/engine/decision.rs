//! CURRENT V6 decision constructors and ORG authorization outcome classification.

use astral_types::{Effect, EvaluationStep, PolicyDecision};

// ==================== 工具函数 ====================

/// 创建 EvaluationStep
pub(crate) fn step(
    phase: &str,
    result: &str,
    detail: &str,
    source: Option<String>,
) -> EvaluationStep {
    let result_effect = match result {
        "ALLOW" => Effect::Allow,
        "DENY" => Effect::Deny,
        _ => Effect::NotMatch,
    };
    EvaluationStep {
        phase: phase.to_string(),
        result: result_effect,
        detail: detail.to_string(),
        matched_rule_id: None,
        source,
    }
}

/// 创建 ALLOW 决策
pub(crate) fn allow(reason: &str, matched_rule: &str, path: Vec<EvaluationStep>) -> PolicyDecision {
    PolicyDecision {
        allowed: true,
        reason: reason.to_string(),
        matched_rule: Some(matched_rule.to_string()),
        audit_required: false,
        evaluation_path: path,
        matched_rule_id: None,
        condition_results: None,
        snapshot_version: None,
        org_provenance: None,
    }
}

/// 创建 DENY 决策
pub(crate) fn deny(reason: &str, matched_rule: &str, path: Vec<EvaluationStep>) -> PolicyDecision {
    PolicyDecision {
        allowed: false,
        reason: reason.to_string(),
        matched_rule: Some(matched_rule.to_string()),
        audit_required: true,
        evaluation_path: path,
        matched_rule_id: None,
        condition_results: None,
        snapshot_version: None,
        org_provenance: None,
    }
}
