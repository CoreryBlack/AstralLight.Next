//! 语义等价性测试
//!
//! 读取 `tests/oracle/` 下的 JSON 测试数据，逐场景调用 Rust PolicyEngine
//! 评估，并与预期结果逐字段断言。
//!
//! 这些 oracle JSON 由 Java 版 DecisionDerivationTable 导出（或手工构造
//! 与 Java 版相同的测试数据），确保 Rust 版与 Java 版的权限评估语义一致。

use std::path::PathBuf;

use astral_types::{Effect, PolicyContext, PolicyError};
use policy_engine::{
    PermissionRule, PolicyEngine, RuleRepository, RuleSetEntry, RuleSetSnapshot, SnapshotWinner,
};
use serde::Deserialize;

// ===== Oracle JSON 结构 =====

#[derive(Debug, Deserialize)]
struct OracleCase {
    name: String,
    input: OracleInput,
    snapshots: Vec<OracleSnapshot>,
    rules: Vec<OracleRule>,
    expected: OracleExpected,
}

#[derive(Debug, Deserialize)]
struct OracleInput {
    card_id: Option<i64>,
    user_id: Option<i64>,
    action: String,
    resource: Option<String>,
    #[allow(dead_code)]
    tenant_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct OracleSnapshot {
    rule_set_id: i64,
    ref_type: String,
    entries: Vec<OracleEntry>,
}

#[derive(Debug, Deserialize)]
struct OracleEntry {
    effect: String,
    resource: Option<String>,
    action: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OracleRule {
    id: i64,
    effect: String,
    resource: String,
    action: String,
}

#[derive(Debug, Deserialize)]
struct OracleExpected {
    allowed: bool,
    reason: String,
    #[allow(dead_code)]
    audit_required: Option<bool>,
    evaluation_path: Vec<OracleStep>,
}

#[derive(Debug, Deserialize)]
struct OracleStep {
    phase: String,
    result: String,
    #[allow(dead_code)]
    source: Option<String>,
}

// ===== 模拟仓库实现 =====

struct OracleRepo {
    snapshots: Vec<RuleSetSnapshot>,
    rules: Vec<PermissionRule>,
}

#[async_trait::async_trait]
impl RuleRepository for OracleRepo {
    async fn load_rule_set_snapshots(
        &self,
        _card_id: i64,
    ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
        Ok(self.snapshots.clone())
    }
    async fn load_snapshot_winners(
        &self,
        _card_id: i64,
    ) -> Result<Vec<SnapshotWinner>, PolicyError> {
        // 从源表条目编译胜者（对齐投影器语义）：裸资源名视为类型级 `type:*`，
        // 同 (rule_set_id, resource_key, action) DENY 优先。
        let mut winners: Vec<SnapshotWinner> = Vec::new();
        for snapshot in &self.snapshots {
            for entry in &snapshot.entries {
                let resource = entry.resource.clone().unwrap_or_default();
                let resource_key = if resource.contains(':') {
                    resource
                } else {
                    format!("{resource}:*")
                };
                let action = entry.action.clone().unwrap_or_default();
                if let Some(existing) = winners.iter_mut().find(|w: &&mut SnapshotWinner| {
                    w.rule_set_id == snapshot.rule_set_id
                        && w.resource_key == resource_key
                        && w.action_code == action
                }) {
                    if entry.effect == Effect::Deny {
                        existing.final_effect = "DENY".into();
                    }
                } else {
                    winners.push(SnapshotWinner {
                        ref_type: snapshot.ref_type.clone(),
                        rule_set_id: snapshot.rule_set_id,
                        resource_key,
                        action_code: action,
                        final_effect: if entry.effect == Effect::Allow {
                            "ALLOW".into()
                        } else {
                            "DENY".into()
                        },
                    });
                }
            }
        }
        Ok(winners)
    }
    async fn load_permission_rules(
        &self,
        _card_id: i64,
    ) -> Result<Vec<PermissionRule>, PolicyError> {
        Ok(self.rules.clone())
    }
}

// ===== 辅助转换 =====

fn parse_effect(s: &str) -> Effect {
    match s.to_uppercase().as_str() {
        "ALLOW" => Effect::Allow,
        "DENY" => Effect::Deny,
        _ => Effect::NotMatch,
    }
}

fn build_context(input: &OracleInput) -> PolicyContext {
    PolicyContext::builder()
        .card_id(input.card_id)
        .user_id(input.user_id)
        .action(input.action.clone())
        .resource(input.resource.clone())
        .build()
}

fn build_repo(case: &OracleCase) -> OracleRepo {
    let snapshots = case
        .snapshots
        .iter()
        .map(|s| RuleSetSnapshot {
            rule_set_id: s.rule_set_id,
            ref_type: s.ref_type.clone(),
            entries: s
                .entries
                .iter()
                .map(|e| RuleSetEntry {
                    effect: parse_effect(&e.effect),
                    resource: e.resource.clone(),
                    action: e.action.clone(),
                    condition: None,
                })
                .collect(),
        })
        .collect();

    let rules = case
        .rules
        .iter()
        .map(|r| PermissionRule {
            id: r.id,
            effect: parse_effect(&r.effect),
            resource: r.resource.clone(),
            action: r.action.clone(),
            condition: None,
        })
        .collect();

    OracleRepo { snapshots, rules }
}

/// 加载所有 oracle JSON 文件
fn load_oracle_cases() -> Vec<OracleCase> {
    let mut cases = Vec::new();
    let oracle_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/oracle");

    if !oracle_dir.exists() {
        panic!("oracle directory not found: {:?}", oracle_dir);
    }

    for entry in std::fs::read_dir(&oracle_dir).expect("read oracle dir") {
        let entry = entry.expect("entry");
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json") {
            let content = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read {:?}: {e}", path));
            let case: OracleCase = serde_json::from_str(&content)
                .unwrap_or_else(|e| panic!("failed to parse {:?}: {e}", path));
            cases.push(case);
        }
    }

    cases.sort_by(|a, b| a.name.cmp(&b.name));
    cases
}

// ===== 测试入口 =====

#[tokio::test]
async fn test_oracle_semantic_equivalence() {
    let cases = load_oracle_cases();
    assert!(!cases.is_empty(), "No oracle test cases found");

    let engine = PolicyEngine::new();

    for case in &cases {
        let ctx = build_context(&case.input);
        let repo = build_repo(case);
        let decision = engine.evaluate(&ctx, &repo).await;

        // 核心断言：allowed 和 reason
        assert_eq!(
            decision.allowed, case.expected.allowed,
            "Oracle '{}': allowed mismatch. Expected {}, got {}. Reason: {}",
            case.name, case.expected.allowed, decision.allowed, decision.reason
        );

        assert_eq!(
            decision.reason,
            case.expected.reason,
            "Oracle '{}': reason mismatch. Expected '{}', got '{}'. Path: {:?}",
            case.name,
            case.expected.reason,
            decision.reason,
            decision
                .evaluation_path
                .iter()
                .map(|s| format!("{}:{:?}", s.phase, s.result))
                .collect::<Vec<_>>()
        );

        // The Rust durable projection gate is an infrastructure step that was
        // added after the original Java oracle export. Keep it explicit while
        // comparing the business evaluation path against the frozen oracle.
        assert!(
            decision
                .evaluation_path
                .iter()
                .any(|step| step.phase == "PROJECTION"),
            "Oracle '{}': missing projection gate step",
            case.name
        );
        let business_path: Vec<_> = decision
            .evaluation_path
            .iter()
            .filter(|step| step.phase != "PROJECTION")
            .collect();

        // 断言评估路径长度
        assert_eq!(
            business_path.len(),
            case.expected.evaluation_path.len(),
            "Oracle '{}': evaluation_path length mismatch. Expected {}, got {}",
            case.name,
            case.expected.evaluation_path.len(),
            business_path.len()
        );

        // 断言每一步的 phase 和 result
        for (i, step) in business_path.iter().enumerate() {
            if i >= case.expected.evaluation_path.len() {
                break;
            }
            let expected_step = &case.expected.evaluation_path[i];

            assert_eq!(
                step.phase, expected_step.phase,
                "Oracle '{}': step {i} phase mismatch. Expected '{}', got '{}'",
                case.name, expected_step.phase, step.phase
            );

            let expected_result = parse_effect(&expected_step.result);
            assert_eq!(
                step.result, expected_result,
                "Oracle '{}': step {i} result mismatch. Expected '{:?}', got '{:?}'",
                case.name, expected_result, step.result
            );
        }
    }
}
