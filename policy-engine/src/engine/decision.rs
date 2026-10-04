//! 决策构造与条件评估纯函数（ALLOW/DENY、EvaluationStep、条件运行时判定）。

use astral_types::{Effect, EvaluationStep, PolicyContext, PolicyDecision};

use crate::condition::evaluator_for;

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

/// 按快照 effect 字符串创建决策（"ALLOW" → 放行，其余 → DENY）
pub(crate) fn decision_from_effect(
    effect: &str,
    matched_rule: &str,
    path: Vec<EvaluationStep>,
) -> PolicyDecision {
    if effect == "ALLOW" {
        allow("RULE_SET_ALLOW", matched_rule, path)
    } else {
        deny("RULE_SET_DENY", matched_rule, path)
    }
}

/// 运行时条件类型名称集合
///
/// 对应 Java `ConditionRegistry.REGISTRY` 中注册的所有条件类型。
/// 在 L1 规则集评估中，带运行时条件的条目被排除（对齐 Java rebuildSnapshot 行为）。
const RUNTIME_CONDITION_TYPES: &[&str] = &[
    "TimeRangeCondition",
    "timeRange",
    "IpRangeCondition",
    "ipRange",
    "RateLimitCondition",
    "rateLimit",
    "DeviceTypeCondition",
    "deviceType",
    "ResourcePropertyCondition",
    "resourceProperty",
    "OwnerOnlyCondition",
    "ownerOnly",
    "BelongsToTenantCondition",
    "belongsToTenant",
    "ScopeCondition",
    "scope",
];

/// 检查 JSON 条件是否包含运行时条件（对齐 Java `RuleSetService.hasRuntimeCondition()`）
///
/// 同时识别 Rust 内部格式（`conditionType`+`params`）与 Java 顶层键格式
/// （`timeRange`/`ownerOnly`/`conditionGroup`），保证 Java 写入的条件规则在 L1
/// 快照编译时同样被正确排除。
pub(crate) fn has_runtime_condition(condition: &Option<serde_json::Value>) -> bool {
    let Some(condition_json) = condition else {
        return false;
    };

    // 唯一的解析入口：严格拒绝未知键、混合格式和不支持的嵌套组。
    let Some(group) = crate::condition::normalize_condition_json(condition_json) else {
        return true;
    };
    condition_group_has_runtime(&group)
}

/// 判断归一化后的条件组是否包含运行时条件
pub(crate) fn condition_group_has_runtime(group: &crate::condition::ConditionGroup) -> bool {
    match group {
        crate::condition::ConditionGroup::AllOf(conds)
        | crate::condition::ConditionGroup::AnyOf(conds) => conds
            .iter()
            .any(|c| RUNTIME_CONDITION_TYPES.contains(&c.condition_type.as_str())),
        crate::condition::ConditionGroup::Not(cond) => {
            RUNTIME_CONDITION_TYPES.contains(&cond.condition_type.as_str())
        }
    }
}

/// 评估原始条件 JSON（异步）
///
/// 先尝试 Rust 内部格式（`conditionType`+`params`），再尝试 Java 顶层键格式
/// （`timeRange`/`ownerOnly`/`conditionGroup` 等）归一化，保证共享库中 Java 写入的
/// 条件规则在 Rust 侧同样求值（此前解析失败恒 DENY，行为对齐性断裂）。
pub(crate) async fn evaluate_entry_condition_raw(
    condition: &Option<serde_json::Value>,
    ctx: &PolicyContext,
) -> bool {
    let condition_json = match condition {
        None => return true,
        Some(v) => v,
    };

    let Some(group) = crate::condition::normalize_condition_json(condition_json) else {
        tracing::warn!(
            "Failed to parse condition JSON (strict normalization): {}",
            condition_json
        );
        return false;
    };
    evaluate_condition_group(&group, ctx).await
}

/// 评估条件组（AllOf / AnyOf / Not）
pub(crate) async fn evaluate_condition_group(
    group: &crate::condition::ConditionGroup,
    ctx: &PolicyContext,
) -> bool {
    match group {
        crate::condition::ConditionGroup::AllOf(conditions) => {
            for cond in conditions {
                match evaluator_for(&cond.condition_type) {
                    Ok(evaluator) => {
                        if !evaluator.evaluate(cond, ctx).await.unwrap_or(false) {
                            return false;
                        }
                    }
                    Err(_) => return false,
                }
            }
            true
        }
        crate::condition::ConditionGroup::AnyOf(conditions) => {
            if conditions.is_empty() {
                return false;
            }
            let mut matched = false;
            let mut had_invalid = false;
            for cond in conditions {
                match evaluator_for(&cond.condition_type) {
                    Ok(evaluator) => match evaluator.evaluate(cond, ctx).await {
                        Ok(true) => matched = true,
                        Ok(false) => {}
                        Err(_) => had_invalid = true,
                    },
                    Err(_) => had_invalid = true,
                }
            }
            matched && !had_invalid
        }
        crate::condition::ConditionGroup::Not(cond) => match evaluator_for(&cond.condition_type) {
            Ok(evaluator) => evaluator.evaluate(cond, ctx).await.unwrap_or(false),
            Err(_) => false,
        },
    }
}
