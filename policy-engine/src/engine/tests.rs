use astral_types::{
    CanonicalGrant, DomainScopeRequirement, Effect, EvaluationStep, GlobalAccessRequirement,
    PolicyContext, PolicyDecision, PolicyError, PublishedCardAuthorization,
    PublishedCardEvidenceScope, ResourceOwnershipScope,
};

use super::decision::*;
use super::ports::RuleRepository;
use super::published::*;
use super::types::*;
use super::*;
use std::sync::Mutex;

/// 模拟 RuleRepository（空数据，L1/L2 无匹配 → L3 DEFAULT_DENY）
struct EmptyRepo;

#[async_trait::async_trait]
impl RuleRepository for EmptyRepo {
    async fn load_rule_set_snapshots(
        &self,
        _card_id: i64,
    ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
        Ok(vec![])
    }
    async fn load_permission_rules(
        &self,
        _card_id: i64,
    ) -> Result<Vec<PermissionRule>, PolicyError> {
        Ok(vec![])
    }

    async fn load_projected_delegated_rules(
        &self,
        _delegate_id: i64,
        _resource: &str,
        _action: &str,
    ) -> Result<Vec<PermissionRule>, PolicyError> {
        Ok(vec![])
    }
}

// ===== 工具函数 =====

fn allow_entry(resource: &str, action: &str) -> RuleSetEntry {
    RuleSetEntry {
        effect: Effect::Allow,
        resource: Some(resource.to_string()),
        action: Some(action.to_string()),
        condition: None,
    }
}

fn deny_entry(resource: &str, action: &str) -> RuleSetEntry {
    RuleSetEntry {
        effect: Effect::Deny,
        resource: Some(resource.to_string()),
        action: Some(action.to_string()),
        condition: None,
    }
}

fn allow_rule(resource: &str, action: &str) -> PermissionRule {
    PermissionRule {
        id: 0,
        effect: Effect::Allow,
        resource: resource.to_string(),
        action: action.to_string(),
        condition: None,
    }
}

fn deny_rule(resource: &str, action: &str) -> PermissionRule {
    PermissionRule {
        id: 0,
        effect: Effect::Deny,
        resource: resource.to_string(),
        action: action.to_string(),
        condition: None,
    }
}

/// 默认策略上下文（card_id=1, action=read, resource=learn_subject）
fn test_ctx() -> PolicyContext {
    PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .action("read".into())
        .resource(Some("learn_subject".into()))
        .target_id(Some(42))
        .build()
}

/// 模拟仓库（指定 snapshots 和 rules）
struct MockRepo {
    snapshots: Vec<RuleSetSnapshot>,
    rules: Vec<PermissionRule>,
}

#[async_trait::async_trait]
impl RuleRepository for MockRepo {
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
        // 从源表条目编译胜者（对齐投影器语义）：跳过带运行时条件的条目，
        // 裸资源名视为类型级 `type:*`，同 (resource_key, action) DENY 优先。
        let mut winners: Vec<SnapshotWinner> = Vec::new();
        for snapshot in &self.snapshots {
            for entry in &snapshot.entries {
                if entry.condition.is_some() {
                    continue;
                }
                let resource = entry.resource.clone().unwrap_or_default();
                // 已含 `:` 的是完整 key（`type:*` 或 `type:id`）原样保留；
                // 裸类型名视为类型级 `type:*`。
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
                        final_effect: match entry.effect {
                            Effect::Allow => "ALLOW".into(),
                            _ => "DENY".into(),
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

    async fn load_projected_delegated_rules(
        &self,
        _delegate_id: i64,
        _resource: &str,
        _action: &str,
    ) -> Result<Vec<PermissionRule>, PolicyError> {
        Ok(vec![])
    }
}

/// 带投影门禁的模拟仓库：gate 可配置；advance_on_read 在读取规则后推进
/// 版本（模拟 worker 在评估期间完成投影 → 验证 ALLOW 前复检拒绝旧 ALLOW）
struct GateRepo {
    gate: Option<ProjectionGate>,
    advance_on_read: bool,
    reads: std::sync::atomic::AtomicUsize,
    gate_override: Mutex<Option<ProjectionGate>>,
}

impl GateRepo {
    fn ready(gate: ProjectionGate) -> Self {
        Self {
            gate: Some(gate),
            advance_on_read: false,
            reads: std::sync::atomic::AtomicUsize::new(0),
            gate_override: Mutex::new(None),
        }
    }
    fn pending() -> Self {
        Self {
            gate: Some(ProjectionGate {
                ready: false,
                source_generation: 2,
                revoke_fence: 0,
            }),
            advance_on_read: false,
            reads: std::sync::atomic::AtomicUsize::new(0),
            gate_override: Mutex::new(None),
        }
    }
    fn legacy() -> Self {
        Self {
            gate: None,
            advance_on_read: false,
            reads: std::sync::atomic::AtomicUsize::new(0),
            gate_override: Mutex::new(None),
        }
    }
    fn advancing(initial: ProjectionGate) -> Self {
        Self {
            gate: Some(initial),
            advance_on_read: true,
            reads: std::sync::atomic::AtomicUsize::new(0),
            gate_override: Mutex::new(None),
        }
    }
    fn current_gate(&self) -> ProjectionGate {
        self.gate_override
            .lock()
            .unwrap()
            .unwrap_or(self.gate.unwrap_or(ProjectionGate {
                ready: true,
                source_generation: 0,
                revoke_fence: 0,
            }))
    }
}

#[async_trait::async_trait]
impl RuleRepository for GateRepo {
    async fn load_snapshot_winners(
        &self,
        _card_id: i64,
    ) -> Result<Vec<SnapshotWinner>, PolicyError> {
        // 首次读取后推进（模拟 worker 在评估期间完成重建）。
        // 投影托管卡（有 head）走快照胜者快速路径，推进点放在此处与
        // 真实 worker 重建时序一致。
        if self.advance_on_read && self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0
        {
            *self.gate_override.lock().unwrap() = Some(ProjectionGate {
                ready: true,
                source_generation: 2,
                revoke_fence: 0,
            });
        }
        Ok(vec![SnapshotWinner {
            ref_type: "BASE".into(),
            rule_set_id: 1,
            resource_key: "learn_subject:*".into(),
            action_code: "read".into(),
            final_effect: "ALLOW".into(),
        }])
    }
    async fn load_rule_set_snapshots(
        &self,
        _card_id: i64,
    ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
        Ok(vec![RuleSetSnapshot {
            rule_set_id: 1,
            ref_type: "BASE".into(),
            entries: vec![RuleSetEntry {
                effect: Effect::Allow,
                resource: Some("learn_subject".into()),
                action: Some("read".into()),
                condition: None,
            }],
        }])
    }
    async fn load_permission_rules(
        &self,
        _card_id: i64,
    ) -> Result<Vec<PermissionRule>, PolicyError> {
        Ok(vec![])
    }
    async fn get_projection_gate(
        &self,
        _card_id: i64,
    ) -> Result<Option<ProjectionGate>, PolicyError> {
        Ok(Some(self.current_gate()))
    }

    async fn load_projected_delegated_rules(
        &self,
        _delegate_id: i64,
        _resource: &str,
        _action: &str,
    ) -> Result<Vec<PermissionRule>, PolicyError> {
        Ok(vec![])
    }
}

// ===== 投影门禁测试（对齐 Java AuthorizationReadPort gate 语义） =====

#[tokio::test]
async fn test_projection_pending_denies_before_evaluation() {
    // head 存在但未 READY（source=2, projected=1）→ AUTHORIZATION_PENDING，
    // 即使规则集包含 ALLOW 也不放行
    let engine = PolicyEngine::new();
    let repo = GateRepo::pending();
    let ctx = test_ctx();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    let phases: Vec<&str> = decision
        .evaluation_path
        .iter()
        .map(|s| s.phase.as_str())
        .collect();
    assert!(phases.contains(&"PROJECTION"));
}

#[tokio::test]
async fn test_projection_ready_allows_rule_set() {
    // head READY 且 source==projected → 正常评估，BASE ALLOW 生效
    let engine = PolicyEngine::new();
    let repo = GateRepo::ready(ProjectionGate {
        ready: true,
        source_generation: 2,
        revoke_fence: 0,
    });
    let ctx = test_ctx();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(
        decision.allowed,
        "expected ALLOW, got {:?}",
        decision.reason
    );
    assert_eq!(decision.reason, "RULE_SET_ALLOW");
}

#[tokio::test]
async fn test_default_repository_without_projection_gate_allows() {
    // 未接入 durable gate 的 test repository 保持其显式默认行为。
    let engine = PolicyEngine::new();
    let repo = GateRepo::legacy();
    let ctx = test_ctx();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(decision.allowed);
    assert_eq!(decision.reason, "RULE_SET_ALLOW");
}

#[tokio::test]
async fn test_stale_allow_rejected_when_projection_advances() {
    // 规则读取期间投影推进（source 1→2, projected 1→2）→ 旧 ALLOW 转 AUTHORIZATION_PENDING
    let engine = PolicyEngine::new();
    let repo = GateRepo::advancing(ProjectionGate {
        ready: true,
        source_generation: 1,
        revoke_fence: 0,
    });
    let ctx = test_ctx();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    let phases: Vec<&str> = decision
        .evaluation_path
        .iter()
        .map(|s| s.phase.as_str())
        .collect();
    assert!(phases.contains(&"PROJECTION"));
}

#[test]
fn test_ruleset_dependency_readiness_allows_generation_stamped_empty_projection() {
    let base = RuleSetDependencyStatus {
        rule_set_id: 7,
        ref_type: "BASE".into(),
        rule_set_active: true,
        head_ready: true,
        source_generation: 4,
        projected_generation: 4,
        revoke_fence: 0,
        snapshot_generation: Some(4),
        snapshot_row_count: 0,
        stale_snapshot_rows: 0,
    };
    assert!(base.is_ready());

    let mut disabled = base.clone();
    disabled.rule_set_active = false;
    assert!(disabled.is_ready());

    let mut missing = base;
    missing.snapshot_generation = None;
    assert!(!missing.is_ready());

    let mut residual = disabled;
    residual.snapshot_row_count = 1;
    assert!(residual.is_ready());
}

#[tokio::test]
async fn test_default_deny() {
    let engine = PolicyEngine::new();
    let repo = EmptyRepo;
    let ctx = test_ctx();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "DEFAULT_DENY");
}

#[tokio::test]
async fn test_missing_user_id() {
    let engine = PolicyEngine::new();
    let repo = EmptyRepo;
    let ctx = PolicyContext::builder()
        .card_id(Some(1))
        .action("read".into())
        .resource(Some("test".into()))
        .build();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHN_REQUIRED");
}

#[tokio::test]
async fn test_missing_card_id() {
    let engine = PolicyEngine::new();
    let repo = EmptyRepo;
    let ctx = PolicyContext::builder()
        .user_id(Some(1))
        .action("read".into())
        .resource(Some("test".into()))
        .build();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "CARD_REQUIRED");
}

#[tokio::test]
async fn test_missing_resource() {
    let engine = PolicyEngine::new();
    let repo = EmptyRepo;
    let ctx = PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .action("read".into())
        .build();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "RESOURCE_REQUIRED");
}

#[tokio::test]
async fn test_empty_action_rejected() {
    let engine = PolicyEngine::new();
    let repo = EmptyRepo;
    let ctx = PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .resource(Some("test".into()))
        .action("".into())
        .build();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "ACTION_REQUIRED");
}

// ===== L1 BASE 测试 =====

#[tokio::test]
async fn test_l1_base_allow() {
    let engine = PolicyEngine::new();
    let repo = MockRepo {
        snapshots: vec![RuleSetSnapshot {
            rule_set_id: 1,
            ref_type: "BASE".into(),
            entries: vec![allow_entry("learn_subject", "read")],
        }],
        rules: vec![],
    };
    let ctx = test_ctx();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(decision.allowed);
    assert_eq!(decision.reason, "RULE_SET_ALLOW");
}

#[tokio::test]
async fn test_l1_base_deny() {
    let engine = PolicyEngine::new();
    let repo = MockRepo {
        snapshots: vec![RuleSetSnapshot {
            rule_set_id: 1,
            ref_type: "BASE".into(),
            entries: vec![deny_entry("learn_subject:*", "read")],
        }],
        rules: vec![],
    };
    let ctx = test_ctx();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "RULE_SET_DENY");
}

// ===== L1 OVERLAY > BASE 优先级测试 =====

#[tokio::test]
async fn test_overlay_deny_overrides_base_allow() {
    let engine = PolicyEngine::new();
    let repo = MockRepo {
        snapshots: vec![
            RuleSetSnapshot {
                rule_set_id: 1,
                ref_type: "OVERLAY".into(),
                entries: vec![deny_entry("learn_subject:*", "read")],
            },
            RuleSetSnapshot {
                rule_set_id: 2,
                ref_type: "BASE".into(),
                entries: vec![allow_entry("learn_subject", "read")],
            },
        ],
        rules: vec![],
    };
    let ctx = test_ctx();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(!decision.allowed, "OVERLAY DENY must override BASE ALLOW");
    assert_eq!(decision.reason, "RULE_SET_DENY");
}

#[tokio::test]
async fn test_overlay_allow_beats_base_deny() {
    let engine = PolicyEngine::new();
    let repo = MockRepo {
        snapshots: vec![
            RuleSetSnapshot {
                rule_set_id: 1,
                ref_type: "OVERLAY".into(),
                entries: vec![allow_entry("learn_subject", "read")],
            },
            RuleSetSnapshot {
                rule_set_id: 2,
                ref_type: "BASE".into(),
                entries: vec![deny_entry("learn_subject", "read")],
            },
        ],
        rules: vec![],
    };
    let ctx = test_ctx();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(decision.allowed, "OVERLAY ALLOW must beat BASE DENY");
    assert_eq!(decision.reason, "RULE_SET_ALLOW");
}

// ===== 层内 DENY-OVERRIDES 测试（评估正式语义） =====

#[tokio::test]
async fn test_priority_based_within_overlay() {
    let engine = PolicyEngine::new();
    // 同一 overlay snapshot 中同 key 的 ALLOW 与 DENY：快照唯一键约束
    // （rule_set_id, resource_key, action_code）下由投影器编译胜者，
    // 同优先级冲突 DENY 优先（对齐 Java `MergeSemantics.resolveConflict`）。
    let repo = MockRepo {
        snapshots: vec![RuleSetSnapshot {
            rule_set_id: 1,
            ref_type: "OVERLAY".into(),
            entries: vec![
                allow_entry("learn_subject", "read"),
                deny_entry("learn_subject", "read"),
            ],
        }],
        rules: vec![],
    };
    let ctx = test_ctx();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(
        !decision.allowed,
        "same-key conflict must compile to DENY (resolveConflict)"
    );
    assert_eq!(decision.reason, "RULE_SET_DENY");
}

#[tokio::test]
async fn test_priority_based_within_base() {
    let engine = PolicyEngine::new();
    // BASE 中：类型级 ALLOW 与对象级 DENY 并存。
    // 请求 learn_subject:42 → L1 逐 ref 匹配：exact 命中对象级 DENY
    // （快照胜者含 learn_subject:42 DENY），DENY 优先于类型级 ALLOW。
    let repo = MockRepo {
        snapshots: vec![RuleSetSnapshot {
            rule_set_id: 1,
            ref_type: "BASE".into(),
            entries: vec![
                allow_entry("learn_subject:*", "read"),
                deny_entry("learn_subject:42", "read"),
            ],
        }],
        rules: vec![],
    };
    let ctx = test_ctx();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(
        !decision.allowed,
        "exact object DENY must beat type-level ALLOW in L1"
    );
    assert_eq!(decision.reason, "RULE_SET_DENY");
}

#[tokio::test]
async fn test_multi_overlay_first_match_wins() {
    let engine = PolicyEngine::new();
    // 两个 overlay 规则集：第一个有 allow，第二个有 deny
    // Java 行为：第一个匹配的 overlay 生效（first-match-wins per ref type）
    let repo = MockRepo {
        snapshots: vec![
            RuleSetSnapshot {
                rule_set_id: 1,
                ref_type: "OVERLAY".into(),
                entries: vec![allow_entry("learn_subject", "read")],
            },
            RuleSetSnapshot {
                rule_set_id: 2,
                ref_type: "OVERLAY".into(),
                entries: vec![deny_entry("learn_subject", "read")],
            },
        ],
        rules: vec![],
    };
    let ctx = test_ctx();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(
        decision.allowed,
        "Java behavior: first OVERLAY ref with ALLOW wins"
    );
}

#[tokio::test]
async fn test_l1_low_order_ref_wildcard_deny_beats_high_order_ref_exact_allow() {
    // A4 回归：跨 ref 匹配必须按 Java 逐 ref first-match-wins，
    // 而不是跨 ref 的 exact-first（exact 优先会让高序 ref 的精确 ALLOW
    // 遮蔽低序 ref 的通配 DENY，造成越权方向不一致）。
    // 低序 ref(id=1) 类型级 DENY 命中 → 层效果 DENY，高序 ref(id=2) 不再评估。
    let engine = PolicyEngine::new();
    let repo = MockRepo {
        snapshots: vec![
            RuleSetSnapshot {
                rule_set_id: 1,
                ref_type: "OVERLAY".into(),
                entries: vec![deny_entry("learn_subject:*", "read")],
            },
            RuleSetSnapshot {
                rule_set_id: 2,
                ref_type: "OVERLAY".into(),
                entries: vec![allow_entry("learn_subject", "read")],
            },
        ],
        rules: vec![],
    };
    let ctx = test_ctx();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(
        !decision.allowed,
        "per-ref first-match: low-order ref DENY must win over high-order ref ALLOW"
    );
    assert_eq!(decision.reason, "RULE_SET_DENY");
}

#[tokio::test]
async fn test_l1_snapshot_load_failure_denies_without_l2_fallback() {
    // A1 回归：快照加载失败必须立即 DENY（RULE_SET_UNAVAILABLE），
    // 不得继续 L2 评估——即使 L2 存在旧 ALLOW 规则（快照不可用可能掩盖已撤销权限）。
    struct ErrorWinnersRepo {
        rules: Vec<PermissionRule>,
    }

    #[async_trait::async_trait]
    impl RuleRepository for ErrorWinnersRepo {
        async fn load_snapshot_winners(
            &self,
            _card_id: i64,
        ) -> Result<Vec<SnapshotWinner>, PolicyError> {
            Err(PolicyError::Repository("simulated snapshot failure".into()))
        }
        async fn load_permission_rules(
            &self,
            _card_id: i64,
        ) -> Result<Vec<PermissionRule>, PolicyError> {
            Ok(self.rules.clone())
        }
        async fn load_rule_set_snapshots(
            &self,
            _card_id: i64,
        ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
            Ok(vec![])
        }
    }

    let engine = PolicyEngine::new();
    let repo = ErrorWinnersRepo {
        rules: vec![allow_rule("learn_subject:*", "read")],
    };
    let ctx = test_ctx();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(
        !decision.allowed,
        "snapshot load failure must deny without falling back to L2"
    );
    assert_eq!(decision.reason, "RULE_SET_UNAVAILABLE");
}

// ===== Forward/Reverse Wildcard 测试 =====

#[tokio::test]
async fn test_forward_wildcard_type_matches_instance() {
    let engine = PolicyEngine::new();
    // entry 是类型级通配 "learn_subject:*", request 是 "learn_subject:42"
    let repo = MockRepo {
        snapshots: vec![RuleSetSnapshot {
            rule_set_id: 1,
            ref_type: "BASE".into(),
            entries: vec![allow_entry("learn_subject:*", "read")],
        }],
        rules: vec![],
    };
    let ctx = test_ctx();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(
        decision.allowed,
        "Forward wildcard: type:* must match type:42"
    );
}

#[tokio::test]
async fn test_forward_wildcard_type_name_matches() {
    let engine = PolicyEngine::new();
    // entry 用裸类型名 "learn_subject"（不含 :），request 是 "learn_subject:42"
    let repo = MockRepo {
        snapshots: vec![RuleSetSnapshot {
            rule_set_id: 1,
            ref_type: "BASE".into(),
            entries: vec![allow_entry("learn_subject", "read")],
        }],
        rules: vec![],
    };
    let ctx = test_ctx();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(
        decision.allowed,
        "Forward wildcard: bare type name must match type:id"
    );
}

#[tokio::test]
async fn test_object_rule_does_not_match_type_request() {
    let engine = PolicyEngine::new();
    // 类型级请求（无 target_id，key=`learn_subject:*`）+ 对象级快照条目。
    // Java `checkRuleSetEffect` Step3 reverse wildcard：请求为 `type:*` 时扫描
    // 对象级条目，DENY 优先；此处只有对象级 ALLOW → 返回 ALLOW。
    let repo = MockRepo {
        snapshots: vec![RuleSetSnapshot {
            rule_set_id: 1,
            ref_type: "BASE".into(),
            entries: vec![allow_entry("learn_subject:42", "read")],
        }],
        rules: vec![],
    };
    let ctx = PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .action("read".into())
        .resource(Some("learn_subject".into()))
        .build();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(
        decision.allowed,
        "reverse wildcard: type request matches object ALLOW (Java scanSnapshotEffect)"
    );
}

#[tokio::test]
async fn test_reverse_wildcard_object_deny_beats_type_request() {
    let engine = PolicyEngine::new();
    // 类型级请求 + 对象级 DENY → L1 reverse wildcard 返回 DENY（DENY 优先，
    // 对齐 Java `scanSnapshotEffect` orderByDesc(final_effect)）。
    let repo = MockRepo {
        snapshots: vec![RuleSetSnapshot {
            rule_set_id: 1,
            ref_type: "BASE".into(),
            entries: vec![deny_entry("learn_subject:42", "read")],
        }],
        rules: vec![],
    };
    let ctx = PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .action("read".into())
        .resource(Some("learn_subject".into()))
        .build();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(
        !decision.allowed,
        "reverse wildcard: object DENY must block type request"
    );
    assert_eq!(decision.reason, "RULE_SET_DENY");
}

// ===== 动作别名测试 =====

#[tokio::test]
async fn test_action_alias_write_matches_create() {
    let engine = PolicyEngine::new();
    // entry 定义 write，request 要 create
    let repo = MockRepo {
        snapshots: vec![RuleSetSnapshot {
            rule_set_id: 1,
            ref_type: "BASE".into(),
            entries: vec![allow_entry("learn_subject:*", "write")],
        }],
        rules: vec![],
    };
    let ctx = PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .action("create".into())
        .resource(Some("learn_subject".into()))
        .target_id(Some(42))
        .build();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(decision.allowed, "Alias 'write' must match 'create'");
}

#[tokio::test]
async fn test_action_alias_write_matches_delete() {
    let engine = PolicyEngine::new();
    let repo = MockRepo {
        snapshots: vec![RuleSetSnapshot {
            rule_set_id: 1,
            ref_type: "BASE".into(),
            entries: vec![allow_entry("learn_subject:*", "write")],
        }],
        rules: vec![],
    };
    let ctx = PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .action("delete".into())
        .resource(Some("learn_subject".into()))
        .target_id(Some(42))
        .build();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(decision.allowed, "Alias 'write' must match 'delete'");
}

#[tokio::test]
async fn test_alias_forward_wildcard_combined() {
    let engine = PolicyEngine::new();
    // entry 是类型级 write, request 是具体 ID 的 delete
    let repo = MockRepo {
        snapshots: vec![RuleSetSnapshot {
            rule_set_id: 1,
            ref_type: "BASE".into(),
            entries: vec![allow_entry("learn_subject", "write")],
        }],
        rules: vec![],
    };
    let ctx = PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .action("delete".into())
        .resource(Some("learn_subject".into()))
        .target_id(Some(42))
        .build();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(
        decision.allowed,
        "Alias + forward wildcard: write + type matches delete + instance"
    );
}

// ===== L2 PermissionRule 回退测试 =====

#[tokio::test]
async fn test_l2_fallback() {
    let engine = PolicyEngine::new();
    let repo = MockRepo {
        snapshots: vec![],
        rules: vec![allow_rule("learn_subject:*", "read")],
    };
    let ctx = test_ctx();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(decision.allowed);
    assert_eq!(decision.reason, "RULE_ALLOW");
}

#[tokio::test]
async fn test_l2_fallback_alias() {
    let engine = PolicyEngine::new();
    let repo = MockRepo {
        snapshots: vec![],
        rules: vec![allow_rule("learn_subject:*", "write")],
    };
    let ctx = PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .action("update".into())
        .resource(Some("learn_subject".into()))
        .target_id(Some(42))
        .build();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(decision.allowed, "L2 alias: 'write' must match 'update'");
}

#[tokio::test]
async fn test_l2_exact_object_deny_beats_type_allow() {
    // 对齐 Java `findSnapshot` 精确 selectOne：具体对象 DENY 必须先于类型级 ALLOW 判定，
    // 否则 learn_subject:42 的 DENY 会被 learn_subject:* ALLOW 按行序遮蔽（越权）。
    let engine = PolicyEngine::new();
    let repo = MockRepo {
        snapshots: vec![],
        rules: vec![
            allow_rule("learn_subject:*", "read"),
            deny_rule("learn_subject:42", "read"),
        ],
    };
    let ctx = PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .action("read".into())
        .resource(Some("learn_subject".into()))
        .target_id(Some(42))
        .build();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(
        !decision.allowed,
        "exact object DENY must beat type-level ALLOW"
    );
    assert_eq!(decision.reason, "RULE_DENY");
}

#[tokio::test]
async fn test_l2_exact_object_allow_beats_type_deny() {
    // 具体对象 ALLOW 优先于类型级 DENY（精确优先两段式的正向用例）
    let engine = PolicyEngine::new();
    let repo = MockRepo {
        snapshots: vec![],
        rules: vec![
            deny_rule("learn_subject:*", "read"),
            allow_rule("learn_subject:42", "read"),
        ],
    };
    let ctx = PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .action("read".into())
        .resource(Some("learn_subject".into()))
        .target_id(Some(42))
        .build();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(
        decision.allowed,
        "exact object ALLOW must beat type-level DENY"
    );
    assert_eq!(decision.reason, "RULE_ALLOW");
}

#[tokio::test]
async fn test_l2_type_request_ignores_object_rule() {
    // 类型级请求（无 target_id）不能命中具体对象规则：
    // 仅有 learn_subject:42 DENY 时，learn_subject:* 请求不得被对象规则拒绝。
    let engine = PolicyEngine::new();
    let repo = MockRepo {
        snapshots: vec![],
        rules: vec![deny_rule("learn_subject:42", "read")],
    };
    let ctx = PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .action("read".into())
        .resource(Some("learn_subject".into()))
        .build();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(!decision.allowed, "no type-level rule should match");
    assert_eq!(decision.reason, "DEFAULT_DENY");
}

// ===== 条件评估测试 =====
//
// 对齐 Java：运行时条件仅在 L2（permission_rule）级别评估，
// L1（rule_set）中带运行时条件的条目被跳过（如同 Java snapshot 编译时排除）。

#[tokio::test]
async fn test_condition_time_range_passes_at_l2() {
    let engine = PolicyEngine::new();
    let condition = serde_json::json!({
        "condition_type": "TimeRangeCondition",
        "params": { "start": "00:00", "end": "23:59" }
    });
    let repo = MockRepo {
        snapshots: vec![],
        rules: vec![PermissionRule {
            id: 1,
            effect: Effect::Allow,
            resource: "learn_subject:*".into(),
            action: "read".into(),
            condition: Some(condition),
        }],
    };
    let ctx = test_ctx();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(
        decision.allowed,
        "TimeRange 00:00-23:59 should pass at any time (L2)"
    );
}

#[tokio::test]
async fn test_condition_owner_only_pass_at_l2() {
    let engine = PolicyEngine::new();
    let condition = serde_json::json!({
        "condition_type": "OwnerOnlyCondition",
        "params": {}
    });
    let repo = MockRepo {
        snapshots: vec![],
        rules: vec![PermissionRule {
            id: 1,
            effect: Effect::Allow,
            resource: "learn_subject:*".into(),
            action: "read".into(),
            condition: Some(condition),
        }],
    };
    // 对齐 Java ConditionEvaluator.ownerOnly：resourceOwnerId == currentUserId → allow
    let ctx = PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .action("read".into())
        .resource(Some("learn_subject".into()))
        .target_id(Some(100))
        .resource_owner_id(Some(1))
        .build();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(
        decision.allowed,
        "OwnerOnly with matching resource owner should pass at L2"
    );
}

#[tokio::test]
async fn test_condition_owner_only_blocks_at_l2() {
    let engine = PolicyEngine::new();
    let condition = serde_json::json!({
        "condition_type": "OwnerOnlyCondition",
        "params": {}
    });
    let repo = MockRepo {
        snapshots: vec![],
        rules: vec![PermissionRule {
            id: 1,
            effect: Effect::Allow,
            resource: "learn_subject:*".into(),
            action: "read".into(),
            condition: Some(condition),
        }],
    };
    let ctx = PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .action("read".into())
        .resource(Some("learn_subject".into()))
        .build();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(
        !decision.allowed,
        "OwnerOnly without target_id should block at L2"
    );
}

#[tokio::test]
async fn test_l1_skips_condition_entry_falls_to_unconditional() {
    let engine = PolicyEngine::new();
    // 第一个 entry 有时间范围条件（L1 中跳过），第二个无条件（L1 匹配）
    let past_condition = serde_json::json!({
        "condition_type": "TimeRangeCondition",
        "params": { "start": "00:00", "end": "01:00" }
    });
    let repo = MockRepo {
        snapshots: vec![RuleSetSnapshot {
            rule_set_id: 1,
            ref_type: "BASE".into(),
            entries: vec![
                RuleSetEntry {
                    effect: Effect::Allow,
                    resource: Some("learn_subject:*".into()),
                    action: Some("read".into()),
                    condition: Some(past_condition),
                },
                allow_entry("learn_subject:*", "read"), // 无条件，兜底
            ],
        }],
        rules: vec![],
    };
    let ctx = test_ctx();
    let decision = engine.evaluate(&ctx, &repo).await;
    // 第一个 entry 带运行时条件被 L1 跳过，第二个无条件 entry 应匹配
    assert!(
        decision.allowed,
        "L1 should skip condition entry and match unconditional fallback"
    );
}

#[tokio::test]
async fn test_l1_condition_entry_skipped_falls_to_l2() {
    let engine = PolicyEngine::new();
    let condition = serde_json::json!({
        "condition_type": "TimeRangeCondition",
        "params": { "start": "00:00", "end": "23:59" }
    });
    let repo = MockRepo {
        snapshots: vec![RuleSetSnapshot {
            rule_set_id: 1,
            ref_type: "BASE".into(),
            entries: vec![RuleSetEntry {
                effect: Effect::Allow,
                resource: Some("learn_subject:*".into()),
                action: Some("read".into()),
                condition: Some(condition),
            }],
        }],
        // 带条件的 entry 被 L1 跳过，L2 无条件 fallback 匹配
        rules: vec![allow_rule("learn_subject:*", "read")],
    };
    let ctx = test_ctx();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(
        decision.allowed,
        "L1 condition entry skipped, L2 fallback should match"
    );
}

#[tokio::test]
async fn test_l2_repository_error_terminates_before_l2_5() {
    struct ErrorL2DelegationRepo {
        projected_delegation_reads: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl RuleRepository for ErrorL2DelegationRepo {
        async fn load_rule_set_snapshots(
            &self,
            _card_id: i64,
        ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
            Ok(vec![])
        }

        async fn load_permission_rules(
            &self,
            _card_id: i64,
        ) -> Result<Vec<PermissionRule>, PolicyError> {
            Err(PolicyError::Repository("L2 unavailable".into()))
        }

        async fn load_delegated_rules(
            &self,
            _delegate_id: i64,
            _resource: &str,
            _action: &str,
        ) -> Result<Vec<PermissionRule>, PolicyError> {
            Ok(vec![allow_rule("learn_subject:*", "read")])
        }

        async fn load_projected_delegated_rules(
            &self,
            _delegate_id: i64,
            _resource: &str,
            _action: &str,
        ) -> Result<Vec<PermissionRule>, PolicyError> {
            self.projected_delegation_reads
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(vec![allow_rule("learn_subject:*", "read")])
        }
    }

    let engine = PolicyEngine::new();
    let repo = ErrorL2DelegationRepo {
        projected_delegation_reads: std::sync::atomic::AtomicUsize::new(0),
    };
    let ctx = test_ctx();

    for _ in 0..10 {
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "DEPENDENCY_UNAVAILABLE");
        assert!(decision
            .evaluation_path
            .iter()
            .all(|step| step.phase != "DELEGATION"));
    }
    assert_eq!(
        repo.projected_delegation_reads
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "L2 errors must terminate before projected delegation fallback"
    );
    assert_eq!(engine.circuit_breaker_state(), CircuitBreakerState::Open);

    let decision = engine.evaluate(&ctx, &repo).await;
    assert_eq!(decision.reason, "CIRCUIT_BREAKER_OPEN");
}

#[tokio::test]
async fn test_projected_delegation_is_evaluated_only_at_l2_5() {
    struct ProjectedDelegationRepo;

    #[async_trait::async_trait]
    impl RuleRepository for ProjectedDelegationRepo {
        async fn load_rule_set_snapshots(
            &self,
            _card_id: i64,
        ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
            Ok(vec![])
        }

        async fn load_permission_rules(
            &self,
            _card_id: i64,
        ) -> Result<Vec<PermissionRule>, PolicyError> {
            Ok(vec![])
        }

        async fn load_delegated_rules(
            &self,
            _delegate_id: i64,
            _resource: &str,
            _action: &str,
        ) -> Result<Vec<PermissionRule>, PolicyError> {
            Ok(vec![])
        }

        async fn load_projected_delegated_rules(
            &self,
            _delegate_id: i64,
            _resource: &str,
            _action: &str,
        ) -> Result<Vec<PermissionRule>, PolicyError> {
            Ok(vec![allow_rule("learn_subject:*", "read")])
        }
    }

    let engine = PolicyEngine::new();
    let decision = engine.evaluate(&test_ctx(), &ProjectedDelegationRepo).await;

    assert!(decision.allowed);
    assert_eq!(decision.reason, "DELEGATION_ALLOW");
    assert!(decision
        .evaluation_path
        .iter()
        .any(|step| step.phase == "DELEGATION" && step.result == Effect::Allow));
    assert!(!decision
        .evaluation_path
        .iter()
        .any(|step| step.phase == "PERMISSION_RULE" && step.result == Effect::Allow));
    assert_eq!(engine.get_stats().l2_hits, 0);
}

#[tokio::test]
async fn test_l2_5_repository_error_counts_as_failure() {
    struct ErrorDelegationRepo;

    #[async_trait::async_trait]
    impl RuleRepository for ErrorDelegationRepo {
        async fn load_rule_set_snapshots(
            &self,
            _card_id: i64,
        ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
            Ok(vec![])
        }

        async fn load_permission_rules(
            &self,
            _card_id: i64,
        ) -> Result<Vec<PermissionRule>, PolicyError> {
            Ok(vec![])
        }

        async fn load_projected_delegated_rules(
            &self,
            _delegate_id: i64,
            _resource: &str,
            _action: &str,
        ) -> Result<Vec<PermissionRule>, PolicyError> {
            Err(PolicyError::Repository("delegation unavailable".into()))
        }
    }

    let engine = PolicyEngine::new();
    let repo = ErrorDelegationRepo;
    let ctx = test_ctx();

    for _ in 0..10 {
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "DEFAULT_DENY");
    }
    assert_eq!(engine.circuit_breaker_state(), CircuitBreakerState::Open);
}

#[tokio::test]
async fn test_alias_plus_wildcard_at_l1() {
    let engine = PolicyEngine::new();
    // 别名 write + 类型级通配（无条件 → L1 正常匹配）
    let repo = MockRepo {
        snapshots: vec![RuleSetSnapshot {
            rule_set_id: 1,
            ref_type: "BASE".into(),
            entries: vec![RuleSetEntry {
                effect: Effect::Allow,
                resource: Some("learn_subject".into()), // 类型级
                action: Some("write".into()),           // 别名
                condition: None,                        // 无条件
            }],
        }],
        rules: vec![],
    };
    let ctx = PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .action("delete".into())
        .resource(Some("learn_subject".into()))
        .target_id(Some(42))
        .build();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(
        decision.allowed,
        "L1: alias+wildcard without condition should pass"
    );
}

#[tokio::test]
async fn test_alias_plus_condition_at_l2() {
    let engine = PolicyEngine::new();
    // 别名 write + 时间范围条件 → L2 匹配（L1 无条件则 fall through）
    let condition = serde_json::json!({
        "condition_type": "TimeRangeCondition",
        "params": { "start": "00:00", "end": "23:59" }
    });
    let repo = MockRepo {
        snapshots: vec![],
        rules: vec![PermissionRule {
            id: 1,
            effect: Effect::Allow,
            resource: "learn_subject:*".into(),
            action: "write".into(),
            condition: Some(condition),
        }],
    };
    let ctx = PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .action("delete".into())
        .resource(Some("learn_subject".into()))
        .target_id(Some(42))
        .build();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(decision.allowed, "L2: alias+condition+wildcard should pass");
}

#[tokio::test]
async fn test_wildcard_action_match() {
    let engine = PolicyEngine::new();
    // 快照胜者 action 为 read，请求 read → 精确匹配。
    // （Java 快照/引擎均不支持 `*` 动作通配，此处验证类型级资源匹配。）
    let repo = MockRepo {
        snapshots: vec![RuleSetSnapshot {
            rule_set_id: 1,
            ref_type: "BASE".into(),
            entries: vec![allow_entry("learn_subject:*", "read")],
        }],
        rules: vec![],
    };
    let ctx = test_ctx();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(decision.allowed);
}

// ===== 断路器 + 并发测试 =====

#[tokio::test]
async fn test_circuit_breaker_fall_closed() {
    let engine = PolicyEngine::new();
    engine.force_open_circuit_breaker();

    let repo = MockRepo {
        snapshots: vec![RuleSetSnapshot {
            rule_set_id: 1,
            ref_type: "BASE".into(),
            entries: vec![allow_entry("anything", "read")],
        }],
        rules: vec![],
    };
    let ctx = test_ctx();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(!decision.allowed, "circuit breaker open must deny");
    assert_eq!(decision.reason, "CIRCUIT_BREAKER_OPEN");
}

#[tokio::test]
async fn test_inactive_card_rejected() {
    struct InactiveRepo;
    #[async_trait::async_trait]
    impl RuleRepository for InactiveRepo {
        async fn load_rule_set_snapshots(
            &self,
            _card_id: i64,
        ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
            Ok(vec![])
        }
        async fn load_permission_rules(
            &self,
            _card_id: i64,
        ) -> Result<Vec<PermissionRule>, PolicyError> {
            Ok(vec![])
        }
        async fn check_card_active(&self, _ctx: &PolicyContext) -> Result<bool, PolicyError> {
            Ok(false)
        }
    }

    let engine = PolicyEngine::new();
    let repo = InactiveRepo;
    let ctx = test_ctx();
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "CARD_DISABLED");
}

#[tokio::test]
async fn test_concurrent_evaluations() {
    let engine = std::sync::Arc::new(PolicyEngine::new());
    let repo = std::sync::Arc::new(MockRepo {
        snapshots: vec![RuleSetSnapshot {
            rule_set_id: 1,
            ref_type: "BASE".into(),
            entries: vec![allow_entry("test:*", "read")],
        }],
        rules: vec![],
    });

    let mut handles = vec![];
    for i in 0..10 {
        let engine = engine.clone();
        let repo = repo.clone();
        handles.push(tokio::spawn(async move {
            let ctx = PolicyContext::builder()
                .user_id(Some(i))
                .card_id(Some(i))
                .action("read".into())
                .resource(Some("test".into()))
                .target_id(Some(i))
                .build();
            engine.evaluate(&ctx, repo.as_ref()).await
        }));
    }

    for handle in handles {
        let decision = handle.await.unwrap();
        assert!(decision.allowed);
    }
}

// ===== Published-card shadow read port（非正式 evaluate 端口） =====

/// Minimal Ready-gate evidence fixture for classifier tests ONLY.
///
/// The real strict reader is the sole legitimate constructor of
/// [`astral_types::PublishedCardAuthorization`] with non-empty collections;
/// this hand-made empty collection fixture must never leak outside tests.
fn ready_shadow_evidence(scope: &PublishedCardEvidenceScope) -> PublishedCardAuthorization {
    PublishedCardAuthorization {
        tenant_id: scope.tenant_id,
        card_id: scope.card_id,
        read_unix_seconds: 1_700_000_000,
        gate: astral_types::PublishedCardAuthorizationGate {
            status: astral_types::PublishedEvidenceGateStatus::Ready,
            aggregate_manifest_count: 0,
            verified_record_count: 0,
            effective_grant_count: 0,
            not_in_effective_count: 0,
            equivalent_duplicate_collapsed_count: 0,
        },
        manifests: vec![],
        records: vec![],
        effective_grants: vec![],
    }
}

#[test]
fn formal_evaluate_switches_to_published_evidence_only_behind_capability_marker() {
    // 拆分后正式评估主链位于 formal.rs，RuleRepository port 位于 ports.rs；
    // 本测试分别扫描两个模块文件，断言语义与拆分前一致。
    let formal_source = include_str!("../engine/formal.rs");
    let ports_source = include_str!("../engine/ports.rs");

    // evaluate() gates the strict published-evidence path on the capability
    // marker and delegates to the dedicated strict-gate helper.
    let evaluate_region = formal_source
        .split("pub async fn evaluate<R: RuleRepository>")
        .nth(1)
        .and_then(|body| {
            body.split("async fn evaluate_rule_sets<R: RuleRepository>")
                .next()
        })
        .expect("formal evaluate entry must exist");
    assert!(
        evaluate_region.contains("requires_published_card_evidence"),
        "formal evaluate must gate the strict path on the capability marker"
    );
    assert!(
        evaluate_region.contains("evaluate_published_card_evidence"),
        "formal evaluate must delegate the strict path to the published-evidence helper"
    );

    // The L1/L2 union helpers themselves stay free of the published-evidence
    // port: only the strict gate consumes it, never the rule readers.
    let rule_set_union_region = formal_source
        .split("async fn evaluate_rule_sets<R: RuleRepository>")
        .nth(1)
        .and_then(|body| {
            body.split("async fn evaluate_permission_rules<R: RuleRepository>")
                .next()
        })
        .expect("rule set union region must exist");
    let permission_rules_region = formal_source
        .split("async fn evaluate_permission_rules<R: RuleRepository>")
        .nth(1)
        .and_then(|body| body.split("pub fn evaluate_fallback").next())
        .expect("permission rules L2 region must exist");
    for body in [rule_set_union_region, permission_rules_region] {
        assert!(
            !body.contains("load_published_card_authorization"),
            "L1/L2 union paths must never consult the published-evidence port"
        );
        assert!(
            !body.contains("published_card_shadow_evidence_is_usable"),
            "L1/L2 union paths must never consult the shadow classifier"
        );
    }

    // The trait default stays an explicit unavailable marker (`Ok(None)`),
    // never a synthetic Ready payload.
    let default_impl = ports_source
        .split("async fn load_published_card_authorization")
        .nth(1)
        .expect("published evidence port declaration must exist");
    let default_impl_body = default_impl.split('}').next().unwrap_or(default_impl);
    assert!(
        default_impl_body.contains("Ok(None)"),
        "trait default must remain the explicit legacy/test unavailable marker"
    );
    assert!(
        !default_impl_body.contains("PublishedEvidenceGateStatus::Ready"),
        "trait default must never fabricate a Ready gate"
    );

    // The capability marker defaults to false for test/default repositories.
    let marker_default = ports_source
        .split("fn requires_published_card_evidence")
        .nth(1)
        .and_then(|body| body.split('}').next())
        .expect("capability marker declaration must exist");
    assert!(
        marker_default.contains("false"),
        "capability marker must default to false for test/default repositories"
    );
}

#[tokio::test]
async fn shadow_port_default_is_unavailable_and_never_authorizes() {
    let repo = EmptyRepo;
    let scope = PublishedCardEvidenceScope {
        tenant_id: 7,
        card_id: 17,
        user_filter: Some(42),
        domain: astral_types::DomainScopeRequirement::ExactlySome(11),
    };
    let outcome = repo
        .load_published_card_authorization(&scope)
        .await
        .unwrap();
    assert_eq!(outcome, None);
    // Ok(None) is an unavailable marker, NOT an empty-but-valid ALLOW.
    assert!(!published_card_shadow_evidence_is_usable(&Ok(None)));
    // Repository failures classify as unusable too (pending/deny upstream).
    assert!(!published_card_shadow_evidence_is_usable(&Err(PolicyError::Repository(
            "published_card_evidence_not_ready;code=published_card_evidence.current_pointer_missing"
                .into(),
        ))));
    assert!(!published_card_shadow_evidence_is_usable(&Err(
        PolicyError::InvalidContext("published_card_evidence_invalid_request;code=x".into(),)
    )));
}

/// A repository overriding the port must receive the exact caller scope
/// (tenant/card/user/domain lens unchanged) and a Ready gate result is the
/// only outcome classified usable.
#[tokio::test]
async fn shadow_scope_passthrough_keeps_tenant_card_user_domain() {
    struct ScopeCaptureRepo {
        captured: Mutex<Vec<PublishedCardEvidenceScope>>,
    }

    #[async_trait::async_trait]
    impl RuleRepository for ScopeCaptureRepo {
        async fn load_rule_set_snapshots(
            &self,
            _card_id: i64,
        ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
            Ok(vec![])
        }
        async fn load_permission_rules(
            &self,
            _card_id: i64,
        ) -> Result<Vec<PermissionRule>, PolicyError> {
            Ok(vec![])
        }
        async fn load_published_card_authorization(
            &self,
            scope: &PublishedCardEvidenceScope,
        ) -> Result<Option<PublishedCardAuthorization>, PolicyError> {
            self.captured.lock().unwrap().push(scope.clone());
            Ok(Some(ready_shadow_evidence(scope)))
        }
    }

    let repo = ScopeCaptureRepo {
        captured: Mutex::new(vec![]),
    };
    let scope = PublishedCardEvidenceScope {
        tenant_id: 9,
        card_id: 33,
        user_filter: None,
        domain: astral_types::DomainScopeRequirement::ExactlyNone,
    };
    let outcome = repo
        .load_published_card_authorization(&scope)
        .await
        .unwrap();
    assert!(outcome.is_some());
    assert!(published_card_shadow_evidence_is_usable(&Ok(outcome)));
    let captured = repo.captured.lock().unwrap();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0], scope);
    assert_eq!(captured[0].tenant_id, 9);
    assert_eq!(captured[0].card_id, 33);
    assert_eq!(captured[0].user_filter, None);
    assert_eq!(
        captured[0].domain,
        astral_types::DomainScopeRequirement::ExactlyNone
    );
}

#[test]
fn shadow_classifier_only_accepts_ready_gated_some() {
    let usable = ready_shadow_evidence(&PublishedCardEvidenceScope {
        tenant_id: 1,
        card_id: 1,
        user_filter: None,
        domain: astral_types::DomainScopeRequirement::Unconstrained,
    });
    assert!(published_card_shadow_evidence_is_usable(&Ok(Some(usable))));

    let mut corrupt = ready_shadow_evidence(&PublishedCardEvidenceScope {
        tenant_id: 1,
        card_id: 1,
        user_filter: None,
        domain: astral_types::DomainScopeRequirement::Unconstrained,
    });
    corrupt.gate.status = astral_types::PublishedEvidenceGateStatus::Corrupt;
    assert!(!published_card_shadow_evidence_is_usable(&Ok(Some(
        corrupt
    ))));
}

// ===== Published-evidence strict gate（正式路径，capability marker = true） =====

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};

/// strict gate 上下文：PLATFORM 域完整身份（tenant/domain 与 fixture 对齐）。
fn strict_ctx() -> PolicyContext {
    PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .tenant_id(Some(7))
        .domain_id(Some(11))
        .action("read".into())
        .resource(Some("learn_subject".into()))
        .target_id(Some(42))
        .build()
}

/// 类型级请求上下文（无 target_id → resource_key = `learn_subject:*`）。
fn strict_ctx_type_level() -> PolicyContext {
    PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .tenant_id(Some(7))
        .domain_id(Some(11))
        .action("read".into())
        .resource(Some("learn_subject".into()))
        .build()
}

/// Resolver-classified target context for strict published-evidence domain
/// boundary tests. The actor card stays in domain 11; callers choose the
/// authoritative target domain independently.
fn strict_tenant_scoped_ctx(resource_domain_id: Option<i64>) -> PolicyContext {
    PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .tenant_id(Some(7))
        .domain_id(Some(11))
        .resource_tenant_id(Some(7))
        .resource_domain_id(resource_domain_id)
        .resource_ownership_scope(ResourceOwnershipScope::TenantScoped)
        .action("read".into())
        .resource(Some("learn_subject".into()))
        .target_id(Some(42))
        .build()
}

fn strict_global_ctx(access_requirement: GlobalAccessRequirement) -> PolicyContext {
    let mut context = strict_ctx();
    context.resource_ownership_scope = ResourceOwnershipScope::Global;
    context.global_access_requirement = access_requirement;
    context
}

/// 构造一条合同有效的 CanonicalGrant（tenant 7/domain 11/card 1/user 1）。
fn strict_published_grant(
    grant_id: &str,
    source_kind: astral_types::GrantSourceKind,
    binding_layer: astral_types::BindingLayer,
    resource: &str,
    action: &str,
) -> CanonicalGrant {
    CanonicalGrant {
        grant_id: astral_types::GrantId::parse(grant_id).unwrap(),
        revision: astral_types::GrantRevision::new(1).unwrap(),
        state: astral_types::GrantState::Active,
        source_kind,
        binding_layer,
        tenant: astral_types::TenantScope::new(7, Some(11)).unwrap(),
        card_id: 1,
        user_id: 1,
        resource: resource.to_string(),
        action: action.to_string(),
        effect: astral_types::GrantEffect::Allow,
        validity: astral_types::ValidityWindow::perpetual(),
        provenance: astral_types::GrantProvenance {
            source_id: "source-1".to_string(),
            source_entry: Some("entry-1".to_string()),
            binding_id: if source_kind == astral_types::GrantSourceKind::RuleSet {
                Some("binding-1".to_string())
            } else {
                None
            },
            delegation_id: if source_kind == astral_types::GrantSourceKind::Delegation {
                Some("delegation-1".to_string())
            } else {
                None
            },
            operation_id: "op-1".to_string(),
            event_id: Some("event-1".to_string()),
            actor_user_id: None,
        },
    }
}

/// 手工 Ready 证据 fixture（仅测试用；真实构造者是严格 DB reader）。
fn strict_ready_evidence(grants: Vec<CanonicalGrant>) -> PublishedCardAuthorization {
    let record_count = grants.len();
    let manifest = astral_types::PublishedAggregateManifestSummary {
        tenant_id: 7,
        card_id: 1,
        aggregate_type: "CARD".to_string(),
        aggregate_id: 1,
        manifest_id: 1,
        generation: 1,
        source_generation: 1,
        projected_generation: 1,
        revoke_fence: 0,
        cas_version: 1,
        semantic_hash_hex: "a".repeat(64),
        dependency_hash_hex: "b".repeat(64),
        manifest_digest_hex: "c".repeat(64),
        compiler_version: "test".to_string(),
        event_id: "event-1".to_string(),
        operation_id: "op-1".to_string(),
        parent_manifest_id: None,
        segment_count: 1,
        declared_grant_row_count: record_count as u64,
    };
    let records = grants
        .iter()
        .map(|grant| astral_types::VerifiedPublishedGrantRecord {
            aggregate_type: "CARD".to_string(),
            aggregate_id: 1,
            publication_generation: 1,
            revoke_fence: 0,
            manifest_id: 1,
            event_id: "event-1".to_string(),
            operation_id: "op-1".to_string(),
            semantic_hash_hex: "a".repeat(64),
            dependency_hash_hex: "b".repeat(64),
            compiler_version: "test".to_string(),
            segment_ordinal: 0,
            position_in_segment: 0,
            grant: grant.clone(),
            accepted_into_effective_set: true,
            unaccepted_reason: None,
        })
        .collect();
    PublishedCardAuthorization {
        tenant_id: 7,
        card_id: 1,
        read_unix_seconds: 1_700_000_000,
        gate: astral_types::PublishedCardAuthorizationGate {
            status: astral_types::PublishedEvidenceGateStatus::Ready,
            aggregate_manifest_count: 1,
            verified_record_count: record_count,
            effective_grant_count: record_count,
            not_in_effective_count: 0,
            equivalent_duplicate_collapsed_count: 0,
        },
        manifests: vec![manifest],
        records,
        effective_grants: grants,
    }
}

/// strict gate 测试仓库：capability marker = true，按序返回预置读取结果，
/// 预置耗尽后复用 fallback 证据；L1/L2/L2.5 读取器一旦被调用即计数。
/// 一致性采样/realtime oracle 专用读取器（projection gate、raw rule_set、
/// raw permission_rule、legacy delegation）同样计数：strict 路径唯一合法
/// 的仓库读取是 `load_published_card_authorization`，任何其余读取计数
/// 非零都意味着 evaluate() 泄漏到了 legacy consistency/realtime 路径。
struct StrictPublishedRepo {
    outcomes: Mutex<VecDeque<Result<Option<PublishedCardAuthorization>, PolicyError>>>,
    fallback: Option<PublishedCardAuthorization>,
    global_admin_outcomes: Mutex<VecDeque<Result<bool, PolicyError>>>,
    global_admin_fallback: bool,
    global_admin_reads: AtomicUsize,
    legacy_reader_calls: AtomicUsize,
    published_reads: AtomicUsize,
    published_scopes: Mutex<Vec<PublishedCardEvidenceScope>>,
}

impl StrictPublishedRepo {
    fn with_evidence(evidence: PublishedCardAuthorization) -> Self {
        Self {
            outcomes: Mutex::new(VecDeque::new()),
            fallback: Some(evidence),
            global_admin_outcomes: Mutex::new(VecDeque::new()),
            global_admin_fallback: false,
            global_admin_reads: AtomicUsize::new(0),
            legacy_reader_calls: AtomicUsize::new(0),
            published_reads: AtomicUsize::new(0),
            published_scopes: Mutex::new(vec![]),
        }
    }

    fn with_evidence_and_global_admin_outcomes(
        evidence: PublishedCardAuthorization,
        global_admin_outcomes: Vec<Result<bool, PolicyError>>,
    ) -> Self {
        Self {
            outcomes: Mutex::new(VecDeque::new()),
            fallback: Some(evidence),
            global_admin_outcomes: Mutex::new(global_admin_outcomes.into()),
            global_admin_fallback: false,
            global_admin_reads: AtomicUsize::new(0),
            legacy_reader_calls: AtomicUsize::new(0),
            published_reads: AtomicUsize::new(0),
            published_scopes: Mutex::new(vec![]),
        }
    }

    fn with_outcomes(
        outcomes: Vec<Result<Option<PublishedCardAuthorization>, PolicyError>>,
    ) -> Self {
        Self {
            outcomes: Mutex::new(outcomes.into()),
            fallback: None,
            global_admin_outcomes: Mutex::new(VecDeque::new()),
            global_admin_fallback: false,
            global_admin_reads: AtomicUsize::new(0),
            legacy_reader_calls: AtomicUsize::new(0),
            published_reads: AtomicUsize::new(0),
            published_scopes: Mutex::new(vec![]),
        }
    }

    fn legacy_calls(&self) -> usize {
        self.legacy_reader_calls.load(Ordering::SeqCst)
    }

    fn published_reads(&self) -> usize {
        self.published_reads.load(Ordering::SeqCst)
    }

    fn global_admin_reads(&self) -> usize {
        self.global_admin_reads.load(Ordering::SeqCst)
    }

    fn published_scopes(&self) -> Vec<PublishedCardEvidenceScope> {
        self.published_scopes.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl RuleRepository for StrictPublishedRepo {
    fn requires_published_card_evidence(&self) -> bool {
        true
    }

    async fn load_published_card_authorization(
        &self,
        scope: &PublishedCardEvidenceScope,
    ) -> Result<Option<PublishedCardAuthorization>, PolicyError> {
        self.published_scopes.lock().unwrap().push(scope.clone());
        self.published_reads.fetch_add(1, Ordering::SeqCst);
        if let Some(outcome) = self.outcomes.lock().unwrap().pop_front() {
            return outcome;
        }
        match &self.fallback {
            Some(evidence) => Ok(Some(evidence.clone())),
            None => panic!("unexpected extra published evidence read"),
        }
    }

    async fn is_active_global_admin(&self, _user_id: i64) -> Result<bool, PolicyError> {
        self.global_admin_reads.fetch_add(1, Ordering::SeqCst);
        if let Some(outcome) = self.global_admin_outcomes.lock().unwrap().pop_front() {
            return outcome;
        }
        Ok(self.global_admin_fallback)
    }

    // 一致性采样/realtime oracle 专用读取器：strict 路径绝不调用；
    // 计数非零即说明 evaluate() 触碰了 legacy consistency/realtime 路径。
    async fn get_projection_gate(
        &self,
        _card_id: i64,
    ) -> Result<Option<ProjectionGate>, PolicyError> {
        self.legacy_reader_calls.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }
    async fn load_rule_set_entries_raw(
        &self,
        _card_id: i64,
    ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
        self.legacy_reader_calls.fetch_add(1, Ordering::SeqCst);
        Ok(vec![])
    }
    async fn load_permission_rules_raw(
        &self,
        _card_id: i64,
    ) -> Result<Vec<PermissionRule>, PolicyError> {
        self.legacy_reader_calls.fetch_add(1, Ordering::SeqCst);
        Ok(vec![])
    }
    async fn load_delegated_rules(
        &self,
        _delegate_id: i64,
        _resource: &str,
        _action: &str,
    ) -> Result<Vec<PermissionRule>, PolicyError> {
        self.legacy_reader_calls.fetch_add(1, Ordering::SeqCst);
        Ok(vec![])
    }

    // strict 路径绝不触碰 L1/L2/L2.5 读取器；调用即被计数并在断言中失败。
    async fn load_rule_set_snapshots(
        &self,
        _card_id: i64,
    ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
        self.legacy_reader_calls.fetch_add(1, Ordering::SeqCst);
        Ok(vec![])
    }
    async fn load_snapshot_winners(
        &self,
        _card_id: i64,
    ) -> Result<Vec<SnapshotWinner>, PolicyError> {
        self.legacy_reader_calls.fetch_add(1, Ordering::SeqCst);
        Ok(vec![])
    }
    async fn load_permission_rules(
        &self,
        _card_id: i64,
    ) -> Result<Vec<PermissionRule>, PolicyError> {
        self.legacy_reader_calls.fetch_add(1, Ordering::SeqCst);
        Ok(vec![])
    }
    async fn load_projected_delegated_rules(
        &self,
        _delegate_id: i64,
        _resource: &str,
        _action: &str,
    ) -> Result<Vec<PermissionRule>, PolicyError> {
        self.legacy_reader_calls.fetch_add(1, Ordering::SeqCst);
        Ok(vec![])
    }
}

const STRICT_RULESET_BASE_GRANT_ID: &str = "550e8400-e29b-41d4-a716-446655440001";

#[test]
fn published_not_ready_is_business_pending_but_query_is_failure() {
    assert!(published_evidence_error_is_business_pending(
        &PolicyError::Repository("published_card_evidence_not_ready;code=x".into(),)
    ));
    assert!(!published_evidence_error_is_business_pending(
        &PolicyError::Repository("published_card_evidence_query_failed;timeout".into(),)
    ));
    assert!(!published_evidence_error_is_business_pending(
        &PolicyError::Repository("published_card_evidence_corrupt;digest".into(),)
    ));
}

#[tokio::test]
async fn strict_not_ready_does_not_open_breaker_after_repeated_pending() {
    let repo = StrictPublishedRepo::with_outcomes(
            (0..(crate::circuit_breaker::CB_THRESHOLD + 1))
                .map(|_| {
                    Err(PolicyError::Repository(
                        "published_card_evidence_not_ready;code=published_card_evidence.source_freshness_pending"
                            .into(),
                    ))
                })
                .collect(),
        );
    let engine = PolicyEngine::new();
    for _ in 0..crate::circuit_breaker::CB_THRESHOLD {
        let decision = engine.evaluate(&strict_ctx(), &repo).await;
        assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    }
    assert_eq!(engine.circuit_breaker_state(), CircuitBreakerState::Closed);
}
#[tokio::test]
async fn test_strict_published_evidence_allows_matching_grant() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let engine = PolicyEngine::new();
    let ctx = strict_ctx();

    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(
        decision.allowed,
        "expected ALLOW, got {:?}",
        decision.reason
    );
    assert_eq!(decision.reason, "PUBLISHED_EVIDENCE_ALLOW");
    let timing = engine.get_stats().timing_ns;
    assert!(timing.initial_evidence_load_ns > 0);
    assert!(timing.final_evidence_reload_ns > 0);
    assert_eq!(
        timing.refs_load_ns,
        timing.initial_evidence_load_ns + timing.final_evidence_reload_ns,
        "legacy aggregate must equal the separately observed strict reads"
    );
    assert_eq!(
        repo.published_reads(),
        2,
        "ALLOW requires initial + final strict read"
    );
    // ALLOW 复读发生在返回前：initial + recheck 两次读取，无第三次。
    assert_eq!(
        repo.legacy_calls(),
        0,
        "strict path must not read L1/L2/L2.5"
    );
    let allow_step = decision
        .evaluation_path
        .iter()
        .rev()
        .find(|s| s.result == Effect::Allow)
        .expect("ALLOW step must exist");
    assert_eq!(allow_step.phase, "PUBLISHED_EVIDENCE");
    assert_eq!(allow_step.source.as_deref(), Some("RULE_SET_BASE"));
    assert_eq!(
        PolicyEngine::allow_source_phase(&decision),
        Some("RULE_SET")
    );
}

#[tokio::test]
async fn global_control_plane_requires_strict_evidence_before_legacy_reads() {
    struct LegacyGlobalRepo {
        global_admin_reads: AtomicUsize,
        legacy_reads: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl RuleRepository for LegacyGlobalRepo {
        async fn load_rule_set_snapshots(
            &self,
            _card_id: i64,
        ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
            self.legacy_reads.fetch_add(1, Ordering::SeqCst);
            Ok(vec![RuleSetSnapshot {
                rule_set_id: 1,
                ref_type: "BASE".into(),
                entries: vec![allow_entry("learn_subject", "read")],
            }])
        }

        async fn load_permission_rules(
            &self,
            _card_id: i64,
        ) -> Result<Vec<PermissionRule>, PolicyError> {
            self.legacy_reads.fetch_add(1, Ordering::SeqCst);
            Ok(vec![allow_rule("learn_subject", "read")])
        }

        async fn is_active_global_admin(&self, _user_id: i64) -> Result<bool, PolicyError> {
            self.global_admin_reads.fetch_add(1, Ordering::SeqCst);
            Ok(true)
        }
    }

    let repo = LegacyGlobalRepo {
        global_admin_reads: AtomicUsize::new(0),
        legacy_reads: AtomicUsize::new(0),
    };
    let mut ctx = test_ctx();
    ctx.resource_ownership_scope = ResourceOwnershipScope::Global;
    ctx.global_access_requirement = GlobalAccessRequirement::ActiveGlobalAdmin;

    let decision = PolicyEngine::new().evaluate(&ctx, &repo).await;

    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    assert_eq!(
        decision
            .evaluation_path
            .last()
            .map(|step| step.detail.as_str()),
        Some("global control-plane requests require strict published evidence")
    );
    assert_eq!(repo.global_admin_reads.load(Ordering::SeqCst), 0);
    assert_eq!(repo.legacy_reads.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn global_control_plane_requires_active_admin_before_evidence() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let decision = PolicyEngine::new()
        .evaluate(
            &strict_global_ctx(GlobalAccessRequirement::ActiveGlobalAdmin),
            &repo,
        )
        .await;

    assert!(!decision.allowed);
    assert_eq!(decision.reason, "GLOBAL_ADMIN_REQUIRED");
    assert_eq!(repo.global_admin_reads(), 1);
    assert_eq!(repo.published_reads(), 0);
    assert_eq!(repo.legacy_calls(), 0);
    assert_eq!(
        decision
            .evaluation_path
            .last()
            .map(|step| step.phase.as_str()),
        Some("GLOBAL_ADMIN")
    );
}

#[tokio::test]
async fn global_utility_keeps_rule_evidence_without_global_admin_lookup() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let decision = PolicyEngine::new()
        .evaluate(
            &strict_global_ctx(GlobalAccessRequirement::PolicyEvidence),
            &repo,
        )
        .await;

    assert!(
        decision.allowed,
        "self-service global utility remains rule-gated"
    );
    assert_eq!(decision.reason, "PUBLISHED_EVIDENCE_ALLOW");
    assert_eq!(repo.global_admin_reads(), 0);
    assert_eq!(repo.published_reads(), 2);
    assert_eq!(repo.legacy_calls(), 0);
}

#[tokio::test]
async fn global_control_plane_rechecks_active_admin_before_allow() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence_and_global_admin_outcomes(
        evidence,
        vec![Ok(true), Ok(false)],
    );
    let decision = PolicyEngine::new()
        .evaluate(
            &strict_global_ctx(GlobalAccessRequirement::ActiveGlobalAdmin),
            &repo,
        )
        .await;

    assert!(
        !decision.allowed,
        "a disable during evaluation rejects stale ALLOW"
    );
    assert_eq!(decision.reason, "GLOBAL_ADMIN_REQUIRED");
    assert_eq!(repo.global_admin_reads(), 2);
    assert_eq!(repo.published_reads(), 2);
    assert_eq!(repo.legacy_calls(), 0);
    assert_eq!(
        decision
            .evaluation_path
            .last()
            .map(|step| step.detail.as_str()),
        Some("global administrator changed during evaluation")
    );
}

#[tokio::test]
async fn global_control_plane_active_admin_still_requires_matching_evidence() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_course:42",
        "read",
    )]);
    let repo =
        StrictPublishedRepo::with_evidence_and_global_admin_outcomes(evidence, vec![Ok(true)]);
    let decision = PolicyEngine::new()
        .evaluate(
            &strict_global_ctx(GlobalAccessRequirement::ActiveGlobalAdmin),
            &repo,
        )
        .await;

    assert!(!decision.allowed);
    assert_eq!(decision.reason, "DEFAULT_DENY");
    assert_eq!(repo.global_admin_reads(), 1);
    assert_eq!(repo.published_reads(), 1);
    assert_eq!(repo.legacy_calls(), 0);
}

#[tokio::test]
async fn global_control_plane_unavailable_gate_opens_breaker_without_evidence_reads() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence_and_global_admin_outcomes(
        evidence,
        (0..crate::circuit_breaker::CB_THRESHOLD)
            .map(|_| {
                Err(PolicyError::Repository(
                    "global_admin_gate_query_failed;timeout".into(),
                ))
            })
            .collect(),
    );
    let engine = PolicyEngine::new();
    let ctx = strict_global_ctx(GlobalAccessRequirement::ActiveGlobalAdmin);

    for _ in 0..crate::circuit_breaker::CB_THRESHOLD {
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    }
    assert_eq!(engine.circuit_breaker_state(), CircuitBreakerState::Open);
    assert_eq!(
        repo.global_admin_reads(),
        crate::circuit_breaker::CB_THRESHOLD as usize
    );
    assert_eq!(repo.published_reads(), 0);
    assert_eq!(repo.legacy_calls(), 0);
}

#[tokio::test]
async fn global_target_without_resolver_contract_fails_before_evidence() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let decision = PolicyEngine::new()
        .evaluate(
            &strict_global_ctx(GlobalAccessRequirement::Unspecified),
            &repo,
        )
        .await;

    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    assert_eq!(repo.global_admin_reads(), 0);
    assert_eq!(repo.published_reads(), 0);
    assert_eq!(repo.legacy_calls(), 0);
}

#[tokio::test]
async fn strict_tenant_scoped_target_domain_denies_actor_domain_evidence() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let decision = PolicyEngine::new()
        .evaluate(&strict_tenant_scoped_ctx(Some(12)), &repo)
        .await;

    assert!(!decision.allowed);
    assert_eq!(decision.reason, "DEFAULT_DENY");
    assert_eq!(
        repo.published_reads(),
        1,
        "a target-domain mismatch must not begin an ALLOW recheck"
    );
    assert_eq!(repo.legacy_calls(), 0);
}

#[tokio::test]
async fn strict_tenant_scoped_target_domain_allows_matching_evidence() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let decision = PolicyEngine::new()
        .evaluate(&strict_tenant_scoped_ctx(Some(11)), &repo)
        .await;

    assert!(
        decision.allowed,
        "matching target domain must remain authorizable"
    );
    assert_eq!(decision.reason, "PUBLISHED_EVIDENCE_ALLOW");
    assert_eq!(repo.published_reads(), 2);
    assert_eq!(
            repo.published_scopes(),
            vec![
                PublishedCardEvidenceScope {
                    tenant_id: 7,
                    card_id: 1,
                    user_filter: Some(1),
                    domain: DomainScopeRequirement::ExactlySome(11),
                },
                PublishedCardEvidenceScope {
                    tenant_id: 7,
                    card_id: 1,
                    user_filter: Some(1),
                    domain: DomainScopeRequirement::ExactlySome(11),
                },
            ],
            "both strict reads retain the actor-card provenance lens; target-domain enforcement belongs in the matcher"
        );
    assert_eq!(repo.legacy_calls(), 0);
}

#[tokio::test]
async fn strict_tenant_scoped_domainless_target_keeps_tenant_level_evidence() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let decision = PolicyEngine::new()
        .evaluate(&strict_tenant_scoped_ctx(None), &repo)
        .await;

    assert!(
        decision.allowed,
        "a domainless tenant target must not require a domainless card grant"
    );
    assert_eq!(decision.reason, "PUBLISHED_EVIDENCE_ALLOW");
    assert_eq!(repo.published_reads(), 2);
    assert_eq!(repo.legacy_calls(), 0);
}

#[tokio::test]
async fn test_strict_published_evidence_default_denies_without_match() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        "550e8400-e29b-41d4-a716-446655440002",
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_course:9",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let engine = PolicyEngine::new();

    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "DEFAULT_DENY");
    assert_eq!(repo.legacy_calls(), 0);
}

#[tokio::test]
async fn test_strict_missing_evidence_is_fail_closed_pending() {
    let repo = StrictPublishedRepo::with_outcomes(vec![Ok(None)]);
    let engine = PolicyEngine::new();

    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    assert_eq!(repo.legacy_calls(), 0);
}

#[tokio::test]
async fn test_strict_evidence_error_is_fail_closed_pending() {
    let repo = StrictPublishedRepo::with_outcomes(vec![Err(PolicyError::Repository(
        "published_card_evidence_not_ready;code=published_card_evidence.current_pointer_missing"
            .into(),
    ))]);
    let engine = PolicyEngine::new();

    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    assert_eq!(repo.legacy_calls(), 0);
}

#[tokio::test]
async fn test_strict_non_ready_gate_is_fail_closed_pending() {
    // 合同只允许 Ready 证据进入正式授权；非 Ready 即合同违规 → fail-closed。
    let mut evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    evidence.gate.status = astral_types::PublishedEvidenceGateStatus::Pending;
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let engine = PolicyEngine::new();

    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    assert_eq!(repo.legacy_calls(), 0);
}

#[tokio::test]
async fn test_strict_evidence_scope_mismatch_is_fail_closed_pending() {
    let mut evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    evidence.tenant_id = 8; // 与请求 tenant 7 不符
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let engine = PolicyEngine::new();

    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    assert_eq!(repo.legacy_calls(), 0);
}

#[tokio::test]
async fn test_strict_missing_tenant_scope_is_fail_closed_pending() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let engine = PolicyEngine::new();
    let ctx = PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .action("read".into())
        .resource(Some("learn_subject".into()))
        .target_id(Some(42))
        .build();

    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    assert_eq!(repo.legacy_calls(), 0);
}

#[tokio::test]
async fn test_strict_type_wildcard_grant_matches_object_request() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Overlay,
        "learn_subject:*",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let engine = PolicyEngine::new();

    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert!(
        decision.allowed,
        "expected ALLOW, got {:?}",
        decision.reason
    );
    let allow_step = decision
        .evaluation_path
        .iter()
        .rev()
        .find(|s| s.result == Effect::Allow)
        .expect("ALLOW step must exist");
    assert_eq!(allow_step.source.as_deref(), Some("RULE_SET_OVERLAY"));
    assert_eq!(
        PolicyEngine::allow_source_phase(&decision),
        Some("RULE_SET")
    );
}

#[tokio::test]
async fn test_strict_object_grant_never_authorizes_type_request() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let engine = PolicyEngine::new();

    let decision = engine.evaluate(&strict_ctx_type_level(), &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "DEFAULT_DENY");
    assert_eq!(repo.legacy_calls(), 0);
}

#[tokio::test]
async fn test_strict_object_grant_does_not_match_other_object() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let engine = PolicyEngine::new();
    let ctx = PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .tenant_id(Some(7))
        .domain_id(Some(11))
        .action("read".into())
        .resource(Some("learn_subject".into()))
        .target_id(Some(43))
        .build();

    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "DEFAULT_DENY");
}

#[tokio::test]
async fn test_strict_star_grant_matches_object_and_type_requests() {
    let star_object = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::Direct,
        astral_types::BindingLayer::None,
        "*",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence(star_object);
    let engine = PolicyEngine::new();
    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert!(decision.allowed, "object request must match '*' grant");
    assert_eq!(PolicyEngine::allow_source_phase(&decision), Some("DIRECT"));

    let star_type = strict_ready_evidence(vec![strict_published_grant(
        "550e8400-e29b-41d4-a716-446655440003",
        astral_types::GrantSourceKind::Direct,
        astral_types::BindingLayer::None,
        "*",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence(star_type);
    let decision = engine.evaluate(&strict_ctx_type_level(), &repo).await;
    assert!(decision.allowed, "type request must match '*' grant");
    assert_eq!(PolicyEngine::allow_source_phase(&decision), Some("DIRECT"));
}

#[tokio::test]
async fn test_strict_write_alias_matches_create_and_delete() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::Approval,
        astral_types::BindingLayer::None,
        "learn_subject:42",
        "write",
    )]);

    // create / delete 请求命中 write 别名；read 无别名关联 → 默认拒绝。
    let engine = PolicyEngine::new();
    for action in ["create", "delete"] {
        let repo = StrictPublishedRepo::with_evidence(evidence.clone());
        let ctx = PolicyContext::builder()
            .user_id(Some(1))
            .card_id(Some(1))
            .tenant_id(Some(7))
            .domain_id(Some(11))
            .action(action.into())
            .resource(Some("learn_subject".into()))
            .target_id(Some(42))
            .build();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(decision.allowed, "{action} must match write alias");
        assert_eq!(
            PolicyEngine::allow_source_phase(&decision),
            Some("APPROVAL")
        );
    }

    let repo = StrictPublishedRepo::with_evidence(evidence);
    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert!(!decision.allowed, "read must not match write alias");
    assert_eq!(decision.reason, "DEFAULT_DENY");
}

#[tokio::test]
async fn test_strict_star_action_grant_matches_any_action() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::Delegation,
        astral_types::BindingLayer::None,
        "learn_subject:*",
        "*",
    )]);
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let engine = PolicyEngine::new();
    let ctx = PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .tenant_id(Some(7))
        .domain_id(Some(11))
        .action("archive".into())
        .resource(Some("learn_subject".into()))
        .target_id(Some(42))
        .build();

    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(decision.allowed);
    assert_eq!(
        PolicyEngine::allow_source_phase(&decision),
        Some("DELEGATION")
    );
}

#[tokio::test]
async fn test_strict_expired_grant_does_not_authorize() {
    let mut grant = strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    );
    grant.validity = astral_types::ValidityWindow::between(100, 200);
    let evidence = strict_ready_evidence(vec![grant]);
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let engine = PolicyEngine::new();

    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert!(!decision.allowed, "expired grant must not authorize");
    assert_eq!(decision.reason, "DEFAULT_DENY");
}

#[tokio::test]
async fn test_strict_stale_allow_rejected_when_evidence_changes() {
    let first = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let mut second = first.clone();
    // 投影在评估期间推进：manifest 代数变化 → 复读身份不等 → 旧 ALLOW 拒绝。
    second.manifests[0].generation = 2;
    second.manifests[0].source_generation = 2;
    second.manifests[0].projected_generation = 2;
    second.manifests[0].cas_version = 2;
    let repo = StrictPublishedRepo::with_outcomes(vec![Ok(Some(first)), Ok(Some(second))]);
    let engine = PolicyEngine::new();

    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    assert_eq!(repo.legacy_calls(), 0);
}

fn unsafe_allow_omitting_final_reload(
    ctx: &PolicyContext,
    evidence: &PublishedCardAuthorization,
) -> bool {
    match_published_effective_grant(ctx, evidence, "learn_subject:42").is_some()
}

#[tokio::test]
async fn e2_final_reload_omission_accepts_removed_candidate_while_full_contract_reloads() {
    let first = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let mut narrowed = strict_ready_evidence(vec![]);
    narrowed.manifests[0].generation = 2;
    narrowed.manifests[0].source_generation = 2;
    narrowed.manifests[0].projected_generation = 2;
    narrowed.manifests[0].cas_version = 2;
    assert!(first.validate().is_ok());
    assert!(narrowed.validate().is_ok());
    assert!(
        unsafe_allow_omitting_final_reload(&strict_ctx(), &first),
        "omitting the final reload admits the initial stale candidate"
    );

    let repo = StrictPublishedRepo::with_outcomes(vec![Ok(Some(first)), Ok(Some(narrowed))]);
    let decision = PolicyEngine::new().evaluate(&strict_ctx(), &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    assert_eq!(repo.published_reads(), 2);
    assert_eq!(repo.legacy_calls(), 0);
}

fn unsafe_recheck_by_resource_action_only(
    next: &PublishedCardAuthorization,
    matched: &CanonicalGrant,
) -> bool {
    next.effective_grants
        .iter()
        .any(|grant| grant.resource == matched.resource && grant.action == matched.action)
}

#[tokio::test]
async fn test_strict_successor_revision_cannot_replace_original_candidate() {
    let first = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let mut successor = first.clone();
    let successor_revision = astral_types::GrantRevision::new(2).unwrap();

    // Synthetic omission schedule: keep the publication identity fixed and
    // replace only the matched grant revision. This isolates the exact-candidate
    // check; a real publisher must also advance its manifest identity.
    successor.records[0].grant.revision = successor_revision;
    successor.effective_grants[0].revision = successor_revision;
    assert!(successor.validate().is_ok());
    assert_eq!(
        first.effective_grants[0].grant_id,
        successor.effective_grants[0].grant_id
    );
    assert_eq!(
        first.effective_grants[0].resource,
        successor.effective_grants[0].resource
    );
    assert_eq!(
        first.effective_grants[0].action,
        successor.effective_grants[0].action
    );
    assert_ne!(
        first.effective_grants[0].revision,
        successor.effective_grants[0].revision
    );
    let matched = first.effective_grants[0].clone();
    assert!(
        unsafe_recheck_by_resource_action_only(&successor, &matched),
        "resource/action-only omission accepts a successor revision"
    );
    assert!(
        !published_recheck_identity_stable(&first, &successor, 7, 1, &matched),
        "full contract must reject the successor revision"
    );

    let repo = StrictPublishedRepo::with_outcomes(vec![Ok(Some(first)), Ok(Some(successor))]);
    let engine = PolicyEngine::new();

    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    assert_eq!(repo.published_reads(), 2);
    assert_eq!(repo.legacy_calls(), 0);
}

#[tokio::test]
async fn test_strict_recheck_error_is_fail_closed() {
    let first = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_outcomes(vec![
        Ok(Some(first)),
        Err(PolicyError::Repository(
            "published_card_evidence_not_ready".into(),
        )),
    ]);
    let engine = PolicyEngine::new();

    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    assert_eq!(repo.legacy_calls(), 0);
}

#[tokio::test]
async fn test_strict_final_reload_missing_evidence_is_fail_closed_without_breaker_failure() {
    // 复读返回 Ok(None)（证据暂不可用）是业务 pending，不是 repository
    // 硬错误：拒绝放行，且不得计入断路器失败。
    let first = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_outcomes(vec![Ok(Some(first)), Ok(None)]);
    let engine = PolicyEngine::new();

    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    assert_eq!(repo.published_reads(), 2);
    assert_eq!(repo.legacy_calls(), 0);
    assert_eq!(engine.circuit_breaker_state(), CircuitBreakerState::Closed);
}

#[tokio::test]
async fn test_strict_final_reload_business_pending_repeats_keep_breaker_closed() {
    // 复读阶段的 business-pending 错误无论重复多少次都只是
    // AUTHORIZATION_PENDING，不得累积为断路器失败。
    let first = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let mut outcomes = Vec::new();
    for _ in 0..(crate::circuit_breaker::CB_THRESHOLD + 1) {
        outcomes.push(Ok(Some(first.clone())));
        outcomes.push(Err(PolicyError::Repository(
                "published_card_evidence_not_ready;code=published_card_evidence.source_freshness_pending"
                    .into(),
            )));
    }
    let repo = StrictPublishedRepo::with_outcomes(outcomes);
    let engine = PolicyEngine::new();

    for _ in 0..(crate::circuit_breaker::CB_THRESHOLD + 1) {
        let decision = engine.evaluate(&strict_ctx(), &repo).await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    }
    assert_eq!(
        repo.published_reads(),
        2 * (crate::circuit_breaker::CB_THRESHOLD as usize + 1)
    );
    assert_eq!(repo.legacy_calls(), 0);
    assert_eq!(engine.circuit_breaker_state(), CircuitBreakerState::Closed);
}

#[tokio::test]
async fn test_strict_final_reload_hard_errors_open_breaker() {
    // 复读阶段的 repository 硬错误连续达到阈值后，入口断路器直接拒绝，
    // 且不再触碰 repository（复读读取次数停在阈值×2）。
    let first = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let mut outcomes = Vec::new();
    for _ in 0..crate::circuit_breaker::CB_THRESHOLD {
        outcomes.push(Ok(Some(first.clone())));
        outcomes.push(Err(PolicyError::Repository(
            "published_card_evidence_query_failed;timeout".into(),
        )));
    }
    let repo = StrictPublishedRepo::with_outcomes(outcomes);
    let engine = PolicyEngine::new();

    for _ in 0..crate::circuit_breaker::CB_THRESHOLD {
        let decision = engine.evaluate(&strict_ctx(), &repo).await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    }
    assert_eq!(
        repo.published_reads(),
        2 * crate::circuit_breaker::CB_THRESHOLD as usize
    );

    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "CIRCUIT_BREAKER_OPEN");
    assert_eq!(
        repo.published_reads(),
        2 * crate::circuit_breaker::CB_THRESHOLD as usize
    );
    assert_eq!(repo.legacy_calls(), 0);
}

#[tokio::test]
async fn test_strict_initial_load_hard_errors_open_breaker() {
    // 初次证据读取的硬错误同样计入断路器失败；达到阈值后入口直接拒绝。
    let repo = StrictPublishedRepo::with_outcomes(
        (0..crate::circuit_breaker::CB_THRESHOLD)
            .map(|_| {
                Err(PolicyError::Repository(
                    "published_card_evidence_query_failed;timeout".into(),
                ))
            })
            .collect(),
    );
    let engine = PolicyEngine::new();

    for _ in 0..crate::circuit_breaker::CB_THRESHOLD {
        let decision = engine.evaluate(&strict_ctx(), &repo).await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    }
    assert_eq!(
        repo.published_reads(),
        crate::circuit_breaker::CB_THRESHOLD as usize
    );

    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert_eq!(decision.reason, "CIRCUIT_BREAKER_OPEN");
    assert_eq!(repo.legacy_calls(), 0);
}

#[tokio::test]
async fn test_strict_success_resets_hard_error_streak_before_threshold() {
    // 成功评估清零失败连击：两段各 (阈值-1) 次硬错误之间夹一次完整
    // 成功，断路器全程不得打开。
    let first = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let hard_error = || {
        Err::<Option<PublishedCardAuthorization>, PolicyError>(PolicyError::Repository(
            "published_card_evidence_query_failed;timeout".into(),
        ))
    };
    let mut outcomes = Vec::new();
    for _ in 0..(crate::circuit_breaker::CB_THRESHOLD - 1) {
        outcomes.push(Ok(Some(first.clone())));
        outcomes.push(hard_error());
    }
    // 成功评估：initial load 与 final reload 返回同一证据。
    outcomes.push(Ok(Some(first.clone())));
    outcomes.push(Ok(Some(first.clone())));
    for _ in 0..(crate::circuit_breaker::CB_THRESHOLD - 1) {
        outcomes.push(Ok(Some(first.clone())));
        outcomes.push(hard_error());
    }
    let repo = StrictPublishedRepo::with_outcomes(outcomes);
    let engine = PolicyEngine::new();

    for _ in 0..(2 * (crate::circuit_breaker::CB_THRESHOLD as usize - 1) + 1) {
        let decision = engine.evaluate(&strict_ctx(), &repo).await;
        assert_ne!(
            decision.reason, "CIRCUIT_BREAKER_OPEN",
            "success must reset the failure streak"
        );
    }
    assert_eq!(repo.legacy_calls(), 0);
}

// ===== strict gate 与 legacy 一致性采样隔离 =====

/// 一致性采样窗口：`SnapshotConsistencyChecker` 按 1% 采样（间隔 100），
/// 连续 1000 次 evaluate() 在未跳过采样的实现下期望触发约 10 次采样，
/// 每次采样都会调用 projection gate / evaluate_realtime 的 raw 读取器并在
/// StrictPublishedRepo 留下 legacy 计数。整个窗口内计数保持 0 才能证明
/// strict 评估与 legacy consistency/realtime 路径完全隔离。
const CONSISTENCY_SAMPLE_WINDOW: usize = 1000;

#[tokio::test]
async fn test_strict_allow_loop_never_invokes_legacy_consistency_or_realtime() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let engine = PolicyEngine::new();
    let ctx = strict_ctx();

    for _ in 0..CONSISTENCY_SAMPLE_WINDOW {
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(
            decision.allowed,
            "published ALLOW must remain correct, got {:?}",
            decision.reason
        );
        assert_eq!(decision.reason, "PUBLISHED_EVIDENCE_ALLOW");
        assert_eq!(
            repo.legacy_calls(),
            0,
            "strict evaluation must not invoke legacy consistency/realtime/raw readers"
        );
    }

    // 每次 strict ALLOW 恰好两次 published 读取（initial + ALLOW 前复读）；
    // 一致性/realtime 路径不消费 published evidence，计数不得超出。
    assert_eq!(repo.published_reads(), CONSISTENCY_SAMPLE_WINDOW * 2);
}

#[tokio::test]
async fn test_strict_fail_closed_loop_never_invokes_legacy_consistency_or_realtime() {
    // 证据不包含本次请求的 grant → DEFAULT_DENY（fail-closed，无复读）。
    // fail-closed 决策同样不得触碰 legacy consistency/realtime/raw 读取器。
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        "550e8400-e29b-41d4-a716-446655440002",
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_course:9",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let engine = PolicyEngine::new();

    for _ in 0..CONSISTENCY_SAMPLE_WINDOW {
        let decision = engine.evaluate(&strict_ctx(), &repo).await;
        assert!(
            !decision.allowed,
            "no-match must stay fail-closed, got {:?}",
            decision.reason
        );
        assert_eq!(decision.reason, "DEFAULT_DENY");
        assert_eq!(
            repo.legacy_calls(),
            0,
            "strict fail-closed path must not invoke legacy consistency/realtime/raw readers"
        );
    }

    // 无命中 → 仅 initial 读取，无复读，也无一额外读取。
    assert_eq!(repo.published_reads(), CONSISTENCY_SAMPLE_WINDOW);
}

#[test]
fn published_recheck_identity_rejects_tenant_card_drift() {
    let baseline = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let matched = baseline.effective_grants[0].clone();

    // next == baseline 且与请求身份一致 → 复读稳定。
    assert!(published_recheck_identity_stable(
        &baseline, &baseline, 7, 1, &matched
    ));

    // 请求身份漂移（即使 next == baseline）→ 复读不稳定。
    assert!(!published_recheck_identity_stable(
        &baseline, &baseline, 8, 1, &matched
    ));
    assert!(!published_recheck_identity_stable(
        &baseline, &baseline, 7, 2, &matched
    ));

    // next 证据自身携带漂移的 tenant/card → 与 baseline 身份不等，拒绝。
    let mut tenant_drifted = baseline.clone();
    tenant_drifted.tenant_id = 9;
    assert!(!published_recheck_identity_stable(
        &baseline,
        &tenant_drifted,
        9,
        1,
        &matched
    ));
    let mut card_drifted = baseline.clone();
    card_drifted.card_id = 2;
    assert!(!published_recheck_identity_stable(
        &baseline,
        &card_drifted,
        7,
        2,
        &matched
    ));
}

// ===== allow_source_phase 命中来源归因（hit-stat source）=====

#[test]
fn test_allow_source_phase_org_allow_reports_org_authority() {
    // ORG_SCOPE 准入的 ALLOW 步（org_admission 产生的 ORG_AUTHORITY 步，
    // source=ORG_PERSONAL/ORG_SHARED）必须精确上报为 ORG_AUTHORITY，
    // 不得落入 PERMISSION_RULE 兜底。
    for org_source in ["ORG_PERSONAL", "ORG_SHARED"] {
        let decision = allow(
            "ORG_PUBLISHED_EVIDENCE_ALLOW",
            "org-grant-1",
            vec![
                step("AUTHN", "ALLOW", "card active", None),
                step(
                    "ORG_AUTHORITY",
                    "ALLOW",
                    "org_scope contribution matched",
                    Some(org_source.to_string()),
                ),
            ],
        );
        assert_eq!(
            PolicyEngine::allow_source_phase(&decision),
            Some("ORG_AUTHORITY"),
            "ORG_ALLOW (source={org_source}) must be attributed to ORG_AUTHORITY"
        );
    }

    // 命中来源取“最近一个 ALLOW”步：更早的 PERMISSION_RULE ALLOW 不遮蔽
    // 其后的 ORG_AUTHORITY ALLOW。
    let decision = allow(
        "ORG_PUBLISHED_EVIDENCE_ALLOW",
        "org-grant-1",
        vec![
            step("PERMISSION_RULE", "ALLOW", "earlier allow", None),
            step("ORG_AUTHORITY", "DENY", "recheck pending", None),
            step(
                "ORG_AUTHORITY",
                "ALLOW",
                "org_scope contribution matched",
                Some("ORG_SHARED".to_string()),
            ),
        ],
    );
    assert_eq!(
        PolicyEngine::allow_source_phase(&decision),
        Some("ORG_AUTHORITY")
    );
}

#[test]
fn test_allow_source_phase_legacy_mappings_unchanged() {
    // ORG 之外的 phase → source 映射（含 PERMISSION_RULE 兜底）保持不变。
    let phase_cases: &[(&str, &str)] = &[
        ("RULESET", "RULE_SET"),
        ("RULE_SET", "RULE_SET"),
        ("SNAPSHOT", "RULE_SET"),
        ("PERMISSION_RULE", "PERMISSION_RULE"),
        ("DELEGATION", "DELEGATION"),
        ("TEMPLATE", "TEMPLATE"),
        ("SOME_FUTURE_PHASE", "PERMISSION_RULE"),
    ];
    for (phase, expected) in phase_cases {
        let decision = allow("ALLOW", "rule-1", vec![step(phase, "ALLOW", "hit", None)]);
        assert_eq!(
            PolicyEngine::allow_source_phase(&decision),
            Some(*expected),
            "phase {phase} mapping must stay intact"
        );
    }

    // PUBLISHED_EVIDENCE 分支按 grant source 归因，未知 source 兜底
    // PERMISSION_RULE；ORG_PERSONAL/ORG_SHARED 只属于 ORG_AUTHORITY 步，
    // 不影响本分支。
    let published_cases: &[(&str, &str)] = &[
        ("RULE_SET_BASE", "RULE_SET"),
        ("RULE_SET_OVERLAY", "RULE_SET"),
        ("RULE_SET", "RULE_SET"),
        ("DIRECT", "DIRECT"),
        ("APPROVAL", "APPROVAL"),
        ("DELEGATION", "DELEGATION"),
        ("SYSTEM", "PERMISSION_RULE"),
    ];
    for (source, expected) in published_cases {
        let decision = allow(
            "PUBLISHED_EVIDENCE_ALLOW",
            "grant-1",
            vec![step(
                "PUBLISHED_EVIDENCE",
                "ALLOW",
                "hit",
                Some(source.to_string()),
            )],
        );
        assert_eq!(
            PolicyEngine::allow_source_phase(&decision),
            Some(*expected),
            "published source {source} mapping must stay intact"
        );
    }

    // DENY 决策无命中来源（含 ORG_AUTHORITY DENY 步）。
    let denied = deny(
        "DEFAULT_DENY",
        "denied",
        vec![step(
            "ORG_AUTHORITY",
            "DENY",
            "org_scope.no_matching_contribution",
            None,
        )],
    );
    assert_eq!(PolicyEngine::allow_source_phase(&denied), None);
}

// ===== ORG_SCOPE 准入门禁（load_org_authorization 五态切换回归） =====
//
// 覆盖 `PolicyEngine.evaluate()` 在 AUTHN/CARD_CONTEXT/resource/action 校验
// 之后对 `RuleRepository::load_org_authorization` 五态的调度：
// - Disabled → ORG_AUTHORITY_DISABLED（先于 legacy L1/L2 与 strict published
//   evidence 两条证据路径，绝不放行）；
// - Pending → AUTHORIZATION_PENDING（已确认业务态，fail-closed，无 legacy 回落）；
// - Unavailable → AUTHORIZATION_PENDING（依赖不可用，fail-closed 且累计断路器失败）；
// - Unmanaged → 保持既有 legacy 评估路由行为（既有兼容 ALLOW 夹具）；
// - Ready → 经公共入口走 org_admission 正式准入（初始读取 + ALLOW 前复读）。
// 全部为进程内 stub 仓库，不触碰数据库/网络/运行时配置。
use crate::org_admission::OrgAuthorityRead;
use astral_types::org_scope::{
    org_build_segment, org_manifest_digest_hex, OrgAdmissionEvidence, OrgContribution, OrgGrant,
    OrgGrantRef, OrgManifestDigestMaterial, OrgMembership, OrgNode, OrgProvenance, OrgPublication,
    OrgRootActivation, OrgScope, OrgScopeKey, OrgSegmentContent,
};
use astral_types::ValidityWindow;

/// 行政单元（签名 actor）租户与身份四元组（org_admission 夹具同源）。
const ORG_GATE_TENANT: i64 = 100;
const ORG_GATE_USER_ID: i64 = 11;
const ORG_GATE_IDENTITY_CARD_ID: i64 = 111;
const ORG_GATE_CARD_ID: i64 = 222;
/// 统一读取时钟：落在 grant validity (1000..2000) 与 membership 窗口内。
const ORG_GATE_READ_CLOCK: i64 = 1_500;

/// ORG_SCOPE 门禁测试仓库：`load_org_authorization` 恒返回预置三态；
/// strict published-evidence 读取器与 legacy L1/L2 读取器全部计数，用于证明
/// Disabled/Pending 在两条证据路径之前短路、Ready 短路整个旧链、Unmanaged
/// 继续消费既有 legacy 评估路由。
struct OrgGateSwitchRepo {
    org_read: OrgAuthorityRead,
    strict_published_evidence: bool,
    /// published evidence 读取器被（错误）触达时的返回：true = 与请求身份
    /// 逐项匹配的 would-allow Ready 夹具（门禁一旦失效即放行，测试立即
    /// 失败），false = 显式 unavailable（Ok(None)）。
    published_would_allow: bool,
    snapshot_winners: Vec<SnapshotWinner>,
    permission_rules: Vec<PermissionRule>,
    org_reads: AtomicUsize,
    published_reads: AtomicUsize,
    legacy_reader_calls: AtomicUsize,
}

impl OrgGateSwitchRepo {
    fn new(org_read: OrgAuthorityRead, strict_published_evidence: bool) -> Self {
        Self {
            org_read,
            strict_published_evidence,
            published_would_allow: strict_published_evidence,
            snapshot_winners: vec![org_gate_legacy_allow_winner()],
            permission_rules: vec![allow_rule("learn_subject:42", "read")],
            org_reads: AtomicUsize::new(0),
            published_reads: AtomicUsize::new(0),
            legacy_reader_calls: AtomicUsize::new(0),
        }
    }

    fn org_reads(&self) -> usize {
        self.org_reads.load(Ordering::SeqCst)
    }

    fn published_reads(&self) -> usize {
        self.published_reads.load(Ordering::SeqCst)
    }

    fn legacy_reader_calls(&self) -> usize {
        self.legacy_reader_calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl RuleRepository for OrgGateSwitchRepo {
    fn requires_published_card_evidence(&self) -> bool {
        self.strict_published_evidence
    }

    async fn load_published_card_authorization(
        &self,
        _scope: &PublishedCardEvidenceScope,
    ) -> Result<Option<PublishedCardAuthorization>, PolicyError> {
        self.published_reads.fetch_add(1, Ordering::SeqCst);
        if self.published_would_allow {
            Ok(Some(org_gate_strict_allow_evidence()))
        } else {
            Ok(None)
        }
    }

    async fn load_org_authorization(
        &self,
        _ctx: &PolicyContext,
    ) -> Result<OrgAuthorityRead, PolicyError> {
        self.org_reads.fetch_add(1, Ordering::SeqCst);
        Ok(self.org_read.clone())
    }

    // 以下均为 legacy 一致性/评估读取器：Disabled/Pending/Ready 分支必须
    // 保持零调用，否则对应断言失败。
    async fn get_projection_gate(
        &self,
        _card_id: i64,
    ) -> Result<Option<ProjectionGate>, PolicyError> {
        self.legacy_reader_calls.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }

    async fn load_snapshot_winners(
        &self,
        _card_id: i64,
    ) -> Result<Vec<SnapshotWinner>, PolicyError> {
        self.legacy_reader_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.snapshot_winners.clone())
    }

    async fn load_permission_rules(
        &self,
        _card_id: i64,
    ) -> Result<Vec<PermissionRule>, PolicyError> {
        self.legacy_reader_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.permission_rules.clone())
    }
}

/// 与既有 GateRepo 一致的 BASE 类型级 ALLOW 胜者（learn_subject:* / read）。
fn org_gate_legacy_allow_winner() -> SnapshotWinner {
    SnapshotWinner {
        ref_type: "BASE".into(),
        rule_set_id: 1,
        resource_key: "learn_subject:*".into(),
        action_code: "read".into(),
        final_effect: "ALLOW".into(),
    }
}

/// 与 `strict_ctx` 身份逐项匹配的 would-allow published evidence 夹具。
fn org_gate_strict_allow_evidence() -> PublishedCardAuthorization {
    strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )])
}

/// Public-entry fixture aligned with admission evidence membership. It uses
/// resolver-equivalent tenant-scoped target facts rather than the internal
/// compatibility fallback.
fn org_gate_ctx() -> PolicyContext {
    PolicyContext::builder()
        .user_id(Some(ORG_GATE_USER_ID))
        .identity_card_id(Some(ORG_GATE_IDENTITY_CARD_ID))
        .card_id(Some(ORG_GATE_CARD_ID))
        .tenant_id(Some(ORG_GATE_TENANT))
        .resource_tenant_id(Some(ORG_GATE_TENANT))
        .resource_ownership_scope(ResourceOwnershipScope::TenantScoped)
        .resource(Some("doc".into()))
        .target_id(Some(42))
        .action("read".into())
        .build()
}

/// 密封的单贡献 admission 证据（根单元自源共享 grant，org_admission 夹具同源）。
fn org_gate_admission_evidence() -> OrgAdmissionEvidence {
    let grant_value = OrgGrant {
        grant_id: "00000000-0000-0000-0000-000000000001".to_owned(),
        revision: 1,
        receiving_tenant_id: ORG_GATE_TENANT,
        origin_tenant_id: ORG_GATE_TENANT,
        root_tenant_id: ORG_GATE_TENANT,
        scope: OrgScope {
            resource_tenant_id: ORG_GATE_TENANT,
            domain_id: None,
            resource: "doc:42".to_owned(),
            action: "read".to_owned(),
            validity: ValidityWindow::between(1_000, 2_000),
        },
        delegable: true,
        parent: None,
        subject: None,
        active: true,
        operation_id: "op-grant-1".to_owned(),
    };
    let contribution = OrgContribution {
        grant_ref: OrgGrantRef {
            tenant_id: grant_value.receiving_tenant_id,
            grant_id: grant_value.grant_id.clone(),
            revision: grant_value.revision,
        },
        scope: grant_value.scope.clone(),
        delegable: grant_value.delegable,
        subject: grant_value.subject,
        provenance: OrgProvenance {
            origin_tenant_id: grant_value.origin_tenant_id,
            parent_chain: Vec::new(),
            operation_id: grant_value.operation_id.clone(),
        },
    };
    let segment = org_build_segment(
        0,
        OrgSegmentContent {
            key: OrgScopeKey {
                resource: "doc:42".to_owned(),
                action: "read".to_owned(),
            },
            contributions: vec![contribution],
        },
    )
    .expect("segment must build");
    let publication = OrgPublication {
        tenant_id: ORG_GATE_TENANT,
        root_tenant_id: ORG_GATE_TENANT,
        generation: 3,
        relationship_revision: 2,
        revoke_fence: 1,
        dependencies: Vec::new(),
        manifest_digest_hex: String::new(),
        compiler_version: "org-compiler-v1".to_owned(),
        segments: vec![segment],
        operation_id: "op-publish-1".to_owned(),
    };
    let manifest_digest_hex = org_manifest_digest_hex(&OrgManifestDigestMaterial {
        tenant_id: publication.tenant_id,
        root_tenant_id: publication.root_tenant_id,
        generation: publication.generation,
        relationship_revision: publication.relationship_revision,
        revoke_fence: publication.revoke_fence,
        dependencies: &publication.dependencies,
        segments: &publication.segments,
        compiler_version: &publication.compiler_version,
        operation_id: &publication.operation_id,
    })
    .expect("manifest digest must compute");
    OrgAdmissionEvidence {
        publication: OrgPublication {
            manifest_digest_hex,
            ..publication
        },
        node: OrgNode {
            tenant_id: ORG_GATE_TENANT,
            root_tenant_id: ORG_GATE_TENANT,
            parent_tenant_id: None,
            generation: 3,
            revoke_fence: 1,
            relationship_revision: 2,
            active: true,
            operation_id: "op-node-1".to_owned(),
            root_activation: Some(OrgRootActivation {
                operator_user_id: 7,
                approval_operation_id: "op-approve-root".to_owned(),
            }),
        },
        membership: OrgMembership {
            membership_id: "00000000-0000-0000-0000-000000000009".to_owned(),
            tenant_id: ORG_GATE_TENANT,
            root_tenant_id: ORG_GATE_TENANT,
            user_id: ORG_GATE_USER_ID,
            identity_card_id: ORG_GATE_IDENTITY_CARD_ID,
            card_id: ORG_GATE_CARD_ID,
            revision: 1,
            active: true,
            validity: ValidityWindow::between(0, 9_999),
            operation_id: "op-member-1".to_owned(),
        },
        checked_at_unix: ORG_GATE_READ_CLOCK,
    }
}

fn org_gate_last_step(decision: &PolicyDecision) -> &EvaluationStep {
    decision
        .evaluation_path
        .last()
        .expect("decision must carry at least one evaluation step")
}

#[tokio::test]
async fn test_org_gate_disabled_denies_before_legacy_and_strict_evidence() {
    // Disabled：仓库同时声明 strict published-evidence 能力（且预置
    // would-allow 证据）与 legacy L2 ALLOW 规则——若门禁失效，任一路径都会
    // 放行。断言 ORG_AUTHORITY_DISABLED 先于两者短路。
    let engine = PolicyEngine::new();
    let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Disabled, true);
    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert!(!decision.allowed, "Disabled 必须拒绝: {decision:?}");
    assert_eq!(decision.reason, "ORG_AUTHORITY_DISABLED");
    assert!(decision.matched_rule.is_none());
    assert!(decision.org_provenance.is_none());
    assert!(decision.audit_required);
    let last = org_gate_last_step(&decision);
    assert_eq!(last.phase, "ORG_AUTHORITY");
    assert_eq!(last.result, Effect::Deny);
    assert_eq!(last.source, None);
    assert_eq!(
        last.detail,
        "managed authority cannot fall back to legacy evidence"
    );
    let phases: Vec<&str> = decision
        .evaluation_path
        .iter()
        .map(|s| s.phase.as_str())
        .collect();
    assert_eq!(
        phases,
        vec!["AUTHN", "CARD_CONTEXT", "ORG_AUTHORITY"],
        "Disabled 必须先于 legacy/strict 证据路径短路"
    );
    assert_eq!(repo.org_reads(), 1);
    assert_eq!(
        repo.published_reads(),
        0,
        "Disabled 不得触碰 strict published evidence 读取器"
    );
    assert_eq!(
        repo.legacy_reader_calls(),
        0,
        "Disabled 不得回落 legacy L1/L2 读取器"
    );
}

#[tokio::test]
async fn test_org_gate_pending_fail_closed_without_legacy_fallback() {
    // Pending：稳定 code 原样透传为 ORG_AUTHORITY 步 detail；fail-closed
    // AUTHORIZATION_PENDING，绝不回落 legacy（would-allow 夹具确保回归即失败）。
    let engine = PolicyEngine::new();
    let repo = OrgGateSwitchRepo::new(
        OrgAuthorityRead::Pending {
            code: "org_gate.membership_pending".to_owned(),
        },
        true,
    );
    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert!(!decision.allowed, "Pending 必须 fail-closed: {decision:?}");
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    assert!(decision.matched_rule.is_none());
    assert!(decision.org_provenance.is_none());
    assert!(decision.audit_required);
    let last = org_gate_last_step(&decision);
    assert_eq!(last.phase, "ORG_AUTHORITY");
    assert_eq!(last.result, Effect::Deny);
    assert_eq!(last.detail, "org_gate.membership_pending");
    let phases: Vec<&str> = decision
        .evaluation_path
        .iter()
        .map(|s| s.phase.as_str())
        .collect();
    assert_eq!(
        phases,
        vec!["AUTHN", "CARD_CONTEXT", "ORG_AUTHORITY"],
        "Pending 必须先于 legacy/strict 证据路径短路"
    );
    assert_eq!(repo.org_reads(), 1);
    assert_eq!(repo.published_reads(), 0);
    assert_eq!(repo.legacy_reader_calls(), 0);
}

#[tokio::test]
async fn test_org_gate_unmanaged_retains_legacy_route() {
    // Unmanaged：保持既有 legacy 路由行为——既有兼容 ALLOW 夹具
    // （legacy-compatible 无 head + BASE 类型级快照胜者）照常放行，
    // 不因门禁接入而改变既有严格证据假设。
    let engine = PolicyEngine::new();
    let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Unmanaged, false);
    let decision = engine.evaluate(&test_ctx(), &repo).await;
    assert!(
        decision.allowed,
        "Unmanaged 必须保留 legacy 路由: {:?}",
        decision.reason
    );
    assert_eq!(decision.reason, "RULE_SET_ALLOW");
    assert_eq!(repo.org_reads(), 1);
    assert!(
        repo.legacy_reader_calls() >= 1,
        "Unmanaged 必须继续走 legacy 评估链"
    );
    assert_eq!(repo.published_reads(), 0);
}

#[tokio::test]
async fn test_resource_ownership_unresolved_short_circuits_before_org_or_evidence() {
    let engine = PolicyEngine::new();
    let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Unmanaged, true);
    let mut ctx = strict_ctx();
    ctx.resource_ownership_scope = ResourceOwnershipScope::Unresolved;

    let decision = engine.evaluate(&ctx, &repo).await;

    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    let last = org_gate_last_step(&decision);
    assert_eq!(last.phase, "RESOURCE_OWNERSHIP");
    assert_eq!(last.detail, "target resource ownership was not resolved");
    assert_eq!(repo.org_reads(), 0);
    assert_eq!(repo.published_reads(), 0);
    assert_eq!(repo.legacy_reader_calls(), 0);
}

#[tokio::test]
async fn test_resource_ownership_invalid_tenant_scope_short_circuits_before_org_or_evidence() {
    let engine = PolicyEngine::new();
    let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Unmanaged, true);
    let mut ctx = strict_ctx();
    ctx.resource_ownership_scope = ResourceOwnershipScope::TenantScoped;
    ctx.resource_tenant_id = None;

    let decision = engine.evaluate(&ctx, &repo).await;

    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    let last = org_gate_last_step(&decision);
    assert_eq!(last.phase, "RESOURCE_OWNERSHIP");
    assert_eq!(
        last.detail,
        "tenant-scoped target carried invalid authoritative facts"
    );
    assert_eq!(repo.org_reads(), 0);
    assert_eq!(repo.published_reads(), 0);
    assert_eq!(repo.legacy_reader_calls(), 0);
}

#[tokio::test]
async fn test_resource_ownership_non_positive_tenant_scoped_domain_or_owner_short_circuits() {
    for (resource_domain_id, resource_owner_id) in [(Some(0), None), (None, Some(-1))] {
        let engine = PolicyEngine::new();
        let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Unmanaged, true);
        let mut ctx = strict_ctx();
        ctx.resource_ownership_scope = ResourceOwnershipScope::TenantScoped;
        ctx.resource_tenant_id = Some(7);
        ctx.resource_domain_id = resource_domain_id;
        ctx.resource_owner_id = resource_owner_id;

        let decision = engine.evaluate(&ctx, &repo).await;

        assert!(!decision.allowed);
        assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
        assert_eq!(
            org_gate_last_step(&decision).detail,
            "tenant-scoped target carried invalid authoritative facts"
        );
        assert_eq!(repo.org_reads(), 0);
        assert_eq!(repo.published_reads(), 0);
        assert_eq!(repo.legacy_reader_calls(), 0);
    }
}

#[tokio::test]
async fn test_resource_ownership_invalid_global_scope_short_circuits_before_evidence() {
    let engine = PolicyEngine::new();
    let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Unmanaged, true);
    let mut ctx = strict_ctx();
    ctx.resource_ownership_scope = ResourceOwnershipScope::Global;
    ctx.resource_owner_id = Some(99);

    let decision = engine.evaluate(&ctx, &repo).await;

    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    let last = org_gate_last_step(&decision);
    assert_eq!(last.phase, "RESOURCE_OWNERSHIP");
    assert_eq!(last.detail, "global target carried tenant or owner facts");
    assert_eq!(repo.org_reads(), 0);
    assert_eq!(repo.published_reads(), 0);
    assert_eq!(repo.legacy_reader_calls(), 0);
}

#[tokio::test]
async fn test_global_target_skips_org_admission_but_keeps_strict_evidence() {
    let engine = PolicyEngine::new();
    let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Disabled, true);
    let mut ctx = strict_ctx();
    ctx.resource_ownership_scope = ResourceOwnershipScope::Global;
    ctx.global_access_requirement = GlobalAccessRequirement::PolicyEvidence;

    let decision = engine.evaluate(&ctx, &repo).await;

    assert!(
        decision.allowed,
        "global target must remain authorizable: {decision:?}"
    );
    assert_eq!(decision.reason, "PUBLISHED_EVIDENCE_ALLOW");
    assert_eq!(repo.org_reads(), 0, "global target must skip ORG admission");
    assert_eq!(repo.published_reads(), 2);
    assert_eq!(repo.legacy_reader_calls(), 0);
}

#[tokio::test]
async fn test_resource_ownership_unavailable_accrues_breaker_failures() {
    let engine = PolicyEngine::new();
    let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Unmanaged, true);
    let mut ctx = strict_ctx();
    ctx.resource_ownership_scope = ResourceOwnershipScope::Unavailable;

    for _ in 0..crate::circuit_breaker::CB_THRESHOLD {
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
        assert_eq!(
            org_gate_last_step(&decision).detail,
            "target resource ownership resolver unavailable"
        );
    }
    assert_eq!(engine.circuit_breaker_state(), CircuitBreakerState::Open);
    assert_eq!(repo.org_reads(), 0);
    assert_eq!(repo.published_reads(), 0);
    assert_eq!(repo.legacy_reader_calls(), 0);
}

#[tokio::test]
async fn test_org_gate_unmanaged_foreign_tenant_without_actor_tenant_short_circuits() {
    let engine = PolicyEngine::new();
    let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Unmanaged, true);
    let mut ctx = strict_ctx();
    ctx.tenant_id = None;
    ctx.resource_ownership_scope = ResourceOwnershipScope::TenantScoped;
    ctx.resource_tenant_id = Some(900);

    let decision = engine.evaluate(&ctx, &repo).await;

    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    assert_eq!(
        org_gate_last_step(&decision).detail,
        "foreign tenant target cannot use actor-card evidence"
    );
    assert_eq!(repo.org_reads(), 1);
    assert_eq!(repo.published_reads(), 0);
    assert_eq!(repo.legacy_reader_calls(), 0);
}

#[tokio::test]
async fn test_org_gate_unmanaged_foreign_tenant_target_short_circuits_strict_evidence() {
    let engine = PolicyEngine::new();
    let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Unmanaged, true);
    let mut ctx = strict_ctx();
    ctx.resource_ownership_scope = ResourceOwnershipScope::TenantScoped;
    ctx.resource_tenant_id = Some(900);

    let decision = engine.evaluate(&ctx, &repo).await;

    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    let last = org_gate_last_step(&decision);
    assert_eq!(last.phase, "RESOURCE_OWNERSHIP");
    assert_eq!(last.result, Effect::Deny);
    assert_eq!(
        last.detail,
        "foreign tenant target cannot use actor-card evidence"
    );
    assert_eq!(repo.org_reads(), 1);
    assert_eq!(repo.published_reads(), 0);
    assert_eq!(repo.legacy_reader_calls(), 0);
}

#[tokio::test]
async fn test_org_gate_unmanaged_foreign_tenant_target_short_circuits_legacy_evidence() {
    let engine = PolicyEngine::new();
    let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Unmanaged, false);
    let mut ctx = strict_ctx();
    ctx.resource_ownership_scope = ResourceOwnershipScope::TenantScoped;
    ctx.resource_tenant_id = Some(900);

    let decision = engine.evaluate(&ctx, &repo).await;

    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    assert_eq!(org_gate_last_step(&decision).phase, "RESOURCE_OWNERSHIP");
    assert_eq!(repo.org_reads(), 1);
    assert_eq!(repo.published_reads(), 0);
    assert_eq!(repo.legacy_reader_calls(), 0);
}

#[tokio::test]
async fn test_org_gate_unmanaged_same_tenant_target_keeps_strict_evidence_path() {
    let engine = PolicyEngine::new();
    let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Unmanaged, true);
    let mut ctx = strict_ctx();
    ctx.resource_ownership_scope = ResourceOwnershipScope::TenantScoped;
    ctx.resource_tenant_id = ctx.tenant_id;

    let decision = engine.evaluate(&ctx, &repo).await;

    assert!(
        decision.allowed,
        "same-tenant target must retain strict authorization"
    );
    assert_eq!(decision.reason, "PUBLISHED_EVIDENCE_ALLOW");
    assert_eq!(repo.org_reads(), 1);
    assert_eq!(repo.published_reads(), 2);
    assert_eq!(repo.legacy_reader_calls(), 0);
}

#[tokio::test]
async fn test_org_gate_ready_evidence_allows_via_public_entry() {
    // Ready：公共入口端到端走 org_admission 正式准入——初始读取 +
    // ALLOW 前复读共 2 次 org 读取；legacy L1/L2 与 strict published
    // evidence 都绝不被触碰（Ready 短路整个旧链，不被 legacy 夹具遮蔽）。
    let engine = PolicyEngine::new();
    let grant_id = "00000000-0000-0000-0000-000000000001";
    let repo = OrgGateSwitchRepo::new(
        OrgAuthorityRead::Ready(Box::new(org_gate_admission_evidence())),
        false,
    );
    let decision = engine.evaluate(&org_gate_ctx(), &repo).await;
    assert!(
        decision.allowed,
        "Ready ORG 证据应经公共入口放行: {:?}",
        decision.reason
    );
    assert_eq!(decision.reason, "ORG_PUBLISHED_EVIDENCE_ALLOW");
    assert_eq!(decision.matched_rule.as_deref(), Some(grant_id));
    assert!(decision.org_provenance.is_some());
    let last = org_gate_last_step(&decision);
    assert_eq!(last.phase, "ORG_AUTHORITY");
    assert_eq!(last.result, Effect::Allow);
    assert_eq!(last.source.as_deref(), Some("ORG_SHARED"));
    let phases: Vec<&str> = decision
        .evaluation_path
        .iter()
        .map(|s| s.phase.as_str())
        .collect();
    assert_eq!(phases, vec!["AUTHN", "CARD_CONTEXT", "ORG_AUTHORITY"]);
    assert_eq!(repo.org_reads(), 2, "Ready 需要初始读取 + ALLOW 前复读");
    assert_eq!(repo.legacy_reader_calls(), 0);
    assert_eq!(repo.published_reads(), 0);
}

// ===== ORG_SCOPE 门禁记账（stats/断路器，进程内 stub，不触碰数据库） =====
//
// 修复回归：门禁 Disabled/Pending/Err/Ready 分支此前不做任何
// record_evaluation / 断路器记账，导致 ORG 决策从统计中消失、org 读取
// 失败永不累计断路器失败。以下测试经公共 seam（get_stats /
// circuit_breaker_state）证明每个门禁结局都恰好记账一次，且成败归类正确。

/// ORG 权威读取恒失败的仓库：断路器失败累计/成功清零的对照。
struct OrgGateErrRepo {
    org_reads: AtomicUsize,
}

impl OrgGateErrRepo {
    fn new() -> Self {
        Self {
            org_reads: AtomicUsize::new(0),
        }
    }
}

#[async_trait::async_trait]
impl RuleRepository for OrgGateErrRepo {
    async fn load_permission_rules(
        &self,
        _card_id: i64,
    ) -> Result<Vec<PermissionRule>, PolicyError> {
        Ok(vec![])
    }

    async fn load_org_authorization(
        &self,
        _ctx: &PolicyContext,
    ) -> Result<OrgAuthorityRead, PolicyError> {
        self.org_reads.fetch_add(1, Ordering::SeqCst);
        Err(PolicyError::Repository("org_authority_read_failed".into()))
    }
}

/// Ready 分支内部读取行为可控的仓库：首次 org 读取恒 Ready（预置证据），
/// 之后的读取返回预设结果（ALLOW 前复读触发），首次之后的卡片上下文校验
/// 可设为 Err。每次评估需使用全新实例（读取/校验计数区分初次与终局）。
struct OrgGateReadyProbeRepo {
    evidence: OrgAdmissionEvidence,
    /// 首次之后的 org 读取：`Some(read)` → `Ok(read)`；`None` → Err
    /// （复读不可用；PolicyError 未实现 Clone，错误侧按同义错误重建）。
    reread: Option<OrgAuthorityRead>,
    /// 首次之后的卡片上下文校验是否失败（admission 内终局校验 Err）。
    card_active_err: bool,
    org_reads: AtomicUsize,
    card_checks: AtomicUsize,
}

impl OrgGateReadyProbeRepo {
    fn new(reread: Option<OrgAuthorityRead>, card_active_err: bool) -> Self {
        Self {
            evidence: org_gate_admission_evidence(),
            reread,
            card_active_err,
            org_reads: AtomicUsize::new(0),
            card_checks: AtomicUsize::new(0),
        }
    }
}

#[async_trait::async_trait]
impl RuleRepository for OrgGateReadyProbeRepo {
    async fn load_permission_rules(
        &self,
        _card_id: i64,
    ) -> Result<Vec<PermissionRule>, PolicyError> {
        Ok(vec![])
    }

    async fn load_org_authorization(
        &self,
        _ctx: &PolicyContext,
    ) -> Result<OrgAuthorityRead, PolicyError> {
        // 以读取计数区分初始读取与复读（单线程单评估断言，无并发竞争）。
        let read_index = self.org_reads.fetch_add(1, Ordering::SeqCst);
        if read_index == 0 {
            Ok(OrgAuthorityRead::Ready(Box::new(self.evidence.clone())))
        } else {
            match &self.reread {
                Some(read) => Ok(read.clone()),
                None => Err(PolicyError::Repository("org_reread_failed".into())),
            }
        }
    }

    async fn check_card_active(&self, _ctx: &PolicyContext) -> Result<bool, PolicyError> {
        // 首次校验是门禁前的 CARD_CONTEXT，必须成功；仅 admission 内的
        // 终局校验按预设失败，保证评估命中 Ready 分支内部失败点。
        let check_index = self.card_checks.fetch_add(1, Ordering::SeqCst);
        if self.card_active_err && check_index > 0 {
            Err(PolicyError::Repository("card_context_read_failed".into()))
        } else {
            Ok(true)
        }
    }
}

/// 断路器失败计数预热：阈值-1 次门禁 Err 失败（仍闭合，计数=阈值-1）。
async fn seed_breaker_failures_below_threshold(engine: &PolicyEngine) {
    let repo = OrgGateErrRepo::new();
    let ctx = strict_ctx();
    for _ in 0..(crate::circuit_breaker::CB_THRESHOLD - 1) {
        engine.evaluate(&ctx, &repo).await;
    }
    assert_eq!(
        engine.circuit_breaker_state(),
        CircuitBreakerState::Closed,
        "阈值之下的失败不得打开断路器"
    );
}

#[tokio::test]
async fn test_org_gate_read_error_accrues_breaker_failures_and_opens() {
    // Err：org 权威读取不可用必须累计断路器失败并打开断路器（修复核心）。
    let engine = PolicyEngine::new();
    let repo = OrgGateErrRepo::new();
    let ctx = strict_ctx();

    for _ in 0..crate::circuit_breaker::CB_THRESHOLD {
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
        assert_eq!(
            org_gate_last_step(&decision).detail,
            "org_scope.read_unavailable"
        );
    }
    assert_eq!(engine.circuit_breaker_state(), CircuitBreakerState::Open);

    // 打开后短路降级：不再触达 org 读取器，返回降级 DENY。
    let fallback = engine.evaluate(&ctx, &repo).await;
    assert_eq!(fallback.reason, "CIRCUIT_BREAKER_OPEN");
    assert_eq!(
        repo.org_reads.load(Ordering::SeqCst),
        crate::circuit_breaker::CB_THRESHOLD as usize,
    );

    // 每次失败评估都恰好记账一次（layer=ORG_AUTHORITY → 保守 l3 桶）。
    let stats = engine.get_stats();
    assert_eq!(stats.l3_hits, crate::circuit_breaker::CB_THRESHOLD as u64);
    assert_eq!(stats.l1_hits, 0);
    assert_eq!(stats.l2_hits, 0);
    assert!(stats.timing_ns.total_ns > 0);
}

#[tokio::test]
async fn test_org_gate_unavailable_accrues_breaker_failures_and_opens() {
    // Unavailable is an explicit fail-closed infrastructure outcome, distinct
    // from a completed business Pending read. It must therefore affect the
    // breaker exactly like an Err rather than being laundered into success.
    let engine = PolicyEngine::new();
    let repo = OrgGateSwitchRepo::new(
        OrgAuthorityRead::Unavailable {
            code: "org_scope.pending.reader_unavailable".into(),
        },
        true,
    );
    let ctx = strict_ctx();

    for _ in 0..crate::circuit_breaker::CB_THRESHOLD {
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
        assert_eq!(
            org_gate_last_step(&decision).detail,
            "org_scope.pending.reader_unavailable"
        );
    }
    assert_eq!(engine.circuit_breaker_state(), CircuitBreakerState::Open);

    let fallback = engine.evaluate(&ctx, &repo).await;
    assert_eq!(fallback.reason, "CIRCUIT_BREAKER_OPEN");
    assert_eq!(
        repo.org_reads(),
        crate::circuit_breaker::CB_THRESHOLD as usize,
        "the open breaker must short-circuit before another ORG read"
    );
    assert_eq!(repo.published_reads(), 0);
    assert_eq!(repo.legacy_reader_calls(), 0);

    let stats = engine.get_stats();
    assert_eq!(stats.l3_hits, crate::circuit_breaker::CB_THRESHOLD as u64);
    assert_eq!(stats.l1_hits, 0);
    assert_eq!(stats.l2_hits, 0);
}

#[tokio::test]
async fn test_org_gate_disabled_records_success_not_failure() {
    // Disabled：确定性管理态关闭 → 记成功 + 记账恰好一次。
    // 模式：阈值-1 次 Err 失败 → 被测评估（记成功则清零计数）→ 1 次 Err
    // 失败；若被测评估未记成功，最后一次失败会到阈值并打开断路器。
    let engine = PolicyEngine::new();
    seed_breaker_failures_below_threshold(&engine).await;
    let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Disabled, true);
    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert_eq!(decision.reason, "ORG_AUTHORITY_DISABLED");
    let tail = OrgGateErrRepo::new();
    engine.evaluate(&strict_ctx(), &tail).await;
    assert_eq!(
        engine.circuit_breaker_state(),
        CircuitBreakerState::Closed,
        "Disabled 必须记成功（清零失败计数），不得记依赖失败"
    );
    // 记账恰好一次：阈值-1（Err 预热）+ 1（Disabled）+ 1（Err 收尾）。
    let stats = engine.get_stats();
    assert_eq!(
        stats.l3_hits,
        crate::circuit_breaker::CB_THRESHOLD as u64 + 1
    );
    assert_eq!(stats.l1_hits, 0);
    assert_eq!(stats.l2_hits, 0);
    assert!(stats.timing_ns.total_ns > 0);
}

#[tokio::test]
async fn test_org_gate_pending_records_success_not_failure() {
    // Pending：读取已成功（Ok），业务 pending 是确定性授权结果 → 记成功。
    let engine = PolicyEngine::new();
    seed_breaker_failures_below_threshold(&engine).await;
    let repo = OrgGateSwitchRepo::new(
        OrgAuthorityRead::Pending {
            code: "org_gate.membership_pending".into(),
        },
        true,
    );
    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    assert_eq!(
        org_gate_last_step(&decision).detail,
        "org_gate.membership_pending"
    );
    let tail = OrgGateErrRepo::new();
    engine.evaluate(&strict_ctx(), &tail).await;
    assert_eq!(
        engine.circuit_breaker_state(),
        CircuitBreakerState::Closed,
        "Pending 必须记成功（清零失败计数），不得记依赖失败"
    );
    let stats = engine.get_stats();
    assert_eq!(
        stats.l3_hits,
        crate::circuit_breaker::CB_THRESHOLD as u64 + 1
    );
    assert_eq!(stats.l1_hits, 0);
    assert_eq!(stats.l2_hits, 0);
}

#[tokio::test]
async fn test_org_gate_ready_allow_records_success_and_evaluation() {
    // Ready ALLOW：确定性授权结果 → 记成功，且记账恰好一次。
    let engine = PolicyEngine::new();
    seed_breaker_failures_below_threshold(&engine).await;
    let repo = OrgGateSwitchRepo::new(
        OrgAuthorityRead::Ready(Box::new(org_gate_admission_evidence())),
        false,
    );
    let decision = engine.evaluate(&org_gate_ctx(), &repo).await;
    assert!(decision.allowed);
    assert_eq!(decision.reason, "ORG_PUBLISHED_EVIDENCE_ALLOW");
    assert!(decision.org_provenance.is_some());
    let tail = OrgGateErrRepo::new();
    engine.evaluate(&strict_ctx(), &tail).await;
    assert_eq!(
        engine.circuit_breaker_state(),
        CircuitBreakerState::Closed,
        "Ready ALLOW 必须记成功（清零失败计数），不得记依赖失败"
    );
    let stats = engine.get_stats();
    assert_eq!(
        stats.l3_hits,
        crate::circuit_breaker::CB_THRESHOLD as u64 + 1
    );
    assert_eq!(stats.l1_hits, 0);
    assert_eq!(stats.l2_hits, 0);
    assert!(stats.timing_ns.total_ns > 0);
}

#[tokio::test]
async fn test_org_gate_ready_default_deny_records_success_not_failure() {
    // Ready 分支的正常 DEFAULT_DENY（无匹配贡献）是确定性授权结果，
    // 绝不能记为依赖失败。
    let engine = PolicyEngine::new();
    seed_breaker_failures_below_threshold(&engine).await;
    let repo = OrgGateSwitchRepo::new(
        OrgAuthorityRead::Ready(Box::new(org_gate_admission_evidence())),
        false,
    );
    // 请求 doc:43 → 段键 doc:42 无匹配贡献 → DEFAULT_DENY。
    let mut ctx = org_gate_ctx();
    ctx.target_id = Some(43);
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "DEFAULT_DENY");
    assert_eq!(
        org_gate_last_step(&decision).detail,
        "org_scope.no_matching_contribution"
    );
    let tail = OrgGateErrRepo::new();
    engine.evaluate(&strict_ctx(), &tail).await;
    assert_eq!(
        engine.circuit_breaker_state(),
        CircuitBreakerState::Closed,
        "正常 DEFAULT_DENY 必须记成功，不得记依赖失败"
    );
    let stats = engine.get_stats();
    assert_eq!(
        stats.l3_hits,
        crate::circuit_breaker::CB_THRESHOLD as u64 + 1
    );
    assert_eq!(stats.l1_hits, 0);
    assert_eq!(stats.l2_hits, 0);
}

#[tokio::test]
async fn test_org_gate_ready_identity_drift_records_success_not_failure() {
    // 复读身份漂移（final_identity_changed）是确定性复检拒绝 → 记成功。
    let engine = PolicyEngine::new();
    seed_breaker_failures_below_threshold(&engine).await;
    let mut drifted = org_gate_admission_evidence();
    drifted.membership.revision += 1;
    let repo = OrgGateReadyProbeRepo::new(Some(OrgAuthorityRead::Ready(Box::new(drifted))), false);
    let decision = engine.evaluate(&org_gate_ctx(), &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    assert_eq!(
        org_gate_last_step(&decision).detail,
        "org_scope.final_identity_changed"
    );
    let tail = OrgGateErrRepo::new();
    engine.evaluate(&strict_ctx(), &tail).await;
    assert_eq!(
        engine.circuit_breaker_state(),
        CircuitBreakerState::Closed,
        "确定性复检拒绝必须记成功，不得记依赖失败"
    );
    let stats = engine.get_stats();
    assert_eq!(
        stats.l3_hits,
        crate::circuit_breaker::CB_THRESHOLD as u64 + 1
    );
    assert_eq!(stats.l1_hits, 0);
    assert_eq!(stats.l2_hits, 0);
}

#[tokio::test]
async fn test_org_gate_ready_internal_read_unavailable_accrues_breaker_failures() {
    // Ready 分支内两类终局读取不可用（ALLOW 前权威复读 Err / 终局卡片
    // 上下文 Err）都是基础设施路径 → 累计断路器失败并最终打开断路器。
    for (label, expected_detail, reread, card_active_err) in [
        (
            "final reread Err",
            "org_scope.final_read_unavailable",
            None,
            false,
        ),
        (
            "final card context Err",
            "org_scope.final_card_context_unavailable",
            Some(OrgAuthorityRead::Ready(Box::new(
                org_gate_admission_evidence(),
            ))),
            true,
        ),
    ] {
        let engine = PolicyEngine::new();
        let ctx = org_gate_ctx();
        for _ in 0..crate::circuit_breaker::CB_THRESHOLD {
            // 每次评估使用全新 probe 仓库：首次读取恒 Ready，复读/卡片
            // 上下文按场景预设——保证每次评估都命中 Ready 分支内部的
            // 同一失败点（读取计数在实例内区分初始读取与复读）。
            let repo = OrgGateReadyProbeRepo::new(reread.clone(), card_active_err);
            let decision = engine.evaluate(&ctx, &repo).await;
            assert!(!decision.allowed, "{label}");
            assert_eq!(decision.reason, "AUTHORIZATION_PENDING", "{label}");
            assert_eq!(
                org_gate_last_step(&decision).detail,
                expected_detail,
                "{label}"
            );
        }
        assert_eq!(
            engine.circuit_breaker_state(),
            CircuitBreakerState::Open,
            "{label} 必须累计断路器失败"
        );
        // 每次失败评估都恰好记账一次（layer=ORG_AUTHORITY → 保守 l3 桶）。
        let stats = engine.get_stats();
        assert_eq!(
            stats.l3_hits,
            crate::circuit_breaker::CB_THRESHOLD as u64,
            "{label}"
        );
        assert_eq!(stats.l1_hits, 0, "{label}");
        assert_eq!(stats.l2_hits, 0, "{label}");
    }
}
