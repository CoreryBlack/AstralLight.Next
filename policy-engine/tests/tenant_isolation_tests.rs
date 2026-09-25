//! PolicyEngine 租户隔离评估测试
//!
//! 验证 PolicyEngine.evaluate() 在多租户场景下的行为:
//! - 不同租户的相同 resource/action 使用不同 card_id 产生独立决策
//! - tenant_id 在 PolicyContext 中正确传递
//! - DataScopeRuleProvider 为不同租户生成隔离的 DataScopeFilter
//! - 跨租户访问场景验证（租户 A 的 card 不应匹配租户 B 的规则）

use astral_types::{Effect, PolicyContext, PolicyError};
use policy_engine::{
    DataScopeFilter, DataScopeFilterResolver, PermissionRule, PolicyEngine, RuleRepository,
    RuleSetEntry, RuleSetSnapshot, SnapshotWinner,
};

// ===== 模拟仓库 =====

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

// ===== 多租户评估隔离测试 =====

#[tokio::test]
async fn test_multi_tenant_same_resource_different_cards() {
    // 场景: 两个租户都有 learn_subject:read 权限，但通过不同 card_id
    // PolicyEngine 不直接按 tenant_id 过滤规则 — 它按 card_id 加载规则
    // tenant_id 仅用于 DataScopeFilter（数据层隔离）
    let engine = PolicyEngine::new();

    // 租户 A: card_id=1, BASE ALLOW
    let repo_a = MockRepo {
        snapshots: vec![RuleSetSnapshot {
            rule_set_id: 1,
            ref_type: "BASE".into(),
            entries: vec![allow_entry("learn_subject", "read")],
        }],
        rules: vec![],
    };

    // 租户 B: card_id=2, BASE DENY
    let repo_b = MockRepo {
        snapshots: vec![RuleSetSnapshot {
            rule_set_id: 2,
            ref_type: "BASE".into(),
            entries: vec![deny_entry("learn_subject", "read")],
        }],
        rules: vec![],
    };

    let ctx_a = PolicyContext::builder()
        .user_id(Some(10))
        .card_id(Some(1))
        .action("read".into())
        .resource(Some("learn_subject".into()))
        .target_id(Some(42))
        .tenant_id(Some(100))
        .build();

    let ctx_b = PolicyContext::builder()
        .user_id(Some(20))
        .card_id(Some(2))
        .action("read".into())
        .resource(Some("learn_subject".into()))
        .target_id(Some(42))
        .tenant_id(Some(200))
        .build();

    let decision_a = engine.evaluate(&ctx_a, &repo_a).await;
    let decision_b = engine.evaluate(&ctx_b, &repo_b).await;

    assert!(decision_a.allowed, "租户 A 应被允许");
    assert!(!decision_b.allowed, "租户 B 应被拒绝");
}

#[tokio::test]
async fn test_tenant_id_in_context_preserved() {
    // 验证 tenant_id 在评估过程中保留在上下文中
    let engine = PolicyEngine::new();
    let repo = MockRepo {
        snapshots: vec![RuleSetSnapshot {
            rule_set_id: 1,
            ref_type: "BASE".into(),
            entries: vec![allow_entry("test:*", "read")],
        }],
        rules: vec![],
    };

    let ctx = PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .action("read".into())
        .resource(Some("test".into()))
        .tenant_id(Some(42))
        .domain_id(Some(10))
        .build();

    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(decision.allowed);
    // tenant_id 和 domain_id 应保留在上下文中供 DataScope 使用
    assert_eq!(ctx.tenant_id, Some(42));
    assert_eq!(ctx.domain_id, Some(10));
}

// ===== DataScopeRuleProvider 租户隔离测试 =====

#[tokio::test]
async fn test_data_scope_tenant_isolation() {
    // 不同租户的上下文应产生不同的 DataScopeFilter
    let resolver = DataScopeFilterResolver::new();

    let ctx_a = PolicyContext::builder()
        .action("read".into())
        .tenant_id(Some(100))
        .domain_id(Some(10))
        .build();

    let ctx_b = PolicyContext::builder()
        .action("read".into())
        .tenant_id(Some(200))
        .domain_id(Some(20))
        .build();

    let filter_a = resolver.resolve(&ctx_a).await;
    let filter_b = resolver.resolve(&ctx_b).await;

    assert_eq!(filter_a.tenant_id, Some(100));
    assert_eq!(filter_a.domain_id, Some(10));
    assert_eq!(filter_b.tenant_id, Some(200));
    assert_eq!(filter_b.domain_id, Some(20));
    assert_ne!(filter_a.tenant_id, filter_b.tenant_id);
}

#[tokio::test]
async fn test_data_scope_no_tenant_no_filter() {
    // 没有 tenant_id 时不产生租户过滤
    let resolver = DataScopeFilterResolver::new();
    let ctx = PolicyContext::builder().action("read".into()).build();
    let filter: DataScopeFilter = resolver.resolve(&ctx).await;
    assert!(filter.is_empty());
    assert!(filter.tenant_id.is_none());
}

#[tokio::test]
async fn test_data_scope_personal_scope_user_isolation() {
    // personal: 前缀的 action 应产生 user_id 过滤
    let resolver = DataScopeFilterResolver::new();
    let ctx = PolicyContext::builder()
        .action("personal:read".into())
        .tenant_id(Some(1))
        .user_id(Some(999))
        .build();
    let filter = resolver.resolve(&ctx).await;
    assert_eq!(filter.tenant_id, Some(1));
    assert_eq!(filter.user_id, Some(999));
}

#[tokio::test]
async fn test_data_scope_non_personal_no_user_filter() {
    // 非 personal: 前缀的 action 不应产生 user_id 过滤
    let resolver = DataScopeFilterResolver::new();
    let ctx = PolicyContext::builder()
        .action("read".into())
        .tenant_id(Some(1))
        .user_id(Some(999))
        .build();
    let filter = resolver.resolve(&ctx).await;
    assert_eq!(filter.tenant_id, Some(1));
    assert!(filter.user_id.is_none());
}

#[tokio::test]
async fn test_data_scope_custom_filters() {
    let resolver = DataScopeFilterResolver::new();
    let ctx = PolicyContext::builder()
        .action("read".into())
        .tenant_id(Some(1))
        .request(Some(serde_json::json!({
            "org_id": 77,
            "filters": {
                "department_id": 3,
                "project_id": 99
            }
        })))
        .build();
    let filter = resolver.resolve(&ctx).await;
    assert_eq!(filter.org_id, Some(77));
    assert!(filter.custom.iter().any(|(k, _)| k == "department_id"));
    assert!(filter.custom.iter().any(|(k, _)| k == "project_id"));
}

// ===== DataScopeFilter 合并测试 =====

#[test]
fn test_data_scope_filter_merge() {
    let mut base = DataScopeFilter {
        tenant_id: Some(1),
        domain_id: Some(10),
        ..Default::default()
    };
    let overlay = DataScopeFilter {
        tenant_id: Some(2), // 覆盖
        user_id: Some(100), // 新增
        ..Default::default()
    };
    base.merge(&overlay);
    assert_eq!(base.tenant_id, Some(2), "merge 后 tenant_id 应被覆盖");
    assert_eq!(base.domain_id, Some(10), "domain_id 应保留");
    assert_eq!(base.user_id, Some(100), "user_id 应新增");
}

#[test]
fn test_data_scope_filter_is_empty() {
    assert!(DataScopeFilter::default().is_empty());
    assert!(!DataScopeFilter {
        tenant_id: Some(1),
        ..Default::default()
    }
    .is_empty());
}

// ===== 跨租户规则不串扰测试 =====

#[tokio::test]
async fn test_cross_tenant_rule_no_cross_talk() {
    // 租户 A 的 ALLOW 规则不应影响租户 B 的评估
    // PolicyEngine 按 card_id 加载规则，不同 card_id 的规则完全隔离
    let engine = PolicyEngine::new();

    // card_id=1 有 ALLOW 规则
    let repo_a = MockRepo {
        snapshots: vec![RuleSetSnapshot {
            rule_set_id: 1,
            ref_type: "BASE".into(),
            entries: vec![allow_entry("sensitive_data", "read")],
        }],
        rules: vec![],
    };

    // card_id=2 没有任何规则
    let repo_b = MockRepo {
        snapshots: vec![],
        rules: vec![],
    };

    // 用 card_id=1 评估 → ALLOW
    let ctx_a = PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .action("read".into())
        .resource(Some("sensitive_data".into()))
        .tenant_id(Some(100))
        .build();
    let decision_a = engine.evaluate(&ctx_a, &repo_a).await;
    assert!(decision_a.allowed);

    // 用 card_id=2 评估相同 resource → DEFAULT_DENY
    let ctx_b = PolicyContext::builder()
        .user_id(Some(2))
        .card_id(Some(2))
        .action("read".into())
        .resource(Some("sensitive_data".into()))
        .tenant_id(Some(200))
        .build();
    let decision_b = engine.evaluate(&ctx_b, &repo_b).await;
    assert!(!decision_b.allowed);
    assert_eq!(decision_b.reason, "DEFAULT_DENY");
}

// ===== 多租户并发评估测试 =====

#[tokio::test]
async fn test_concurrent_multi_tenant_evaluations() {
    let engine = std::sync::Arc::new(PolicyEngine::new());

    // 10 个租户，每个有独立的 card_id 和 ALLOW 规则
    let repos: Vec<std::sync::Arc<MockRepo>> = (0..10)
        .map(|i| {
            std::sync::Arc::new(MockRepo {
                snapshots: vec![RuleSetSnapshot {
                    rule_set_id: i + 1,
                    ref_type: "BASE".into(),
                    entries: vec![allow_entry("resource", "read")],
                }],
                rules: vec![],
            })
        })
        .collect();

    let mut handles = vec![];
    for (i, repo) in repos.iter().enumerate() {
        let engine = engine.clone();
        let repo = repo.clone();
        handles.push(tokio::spawn(async move {
            let ctx = PolicyContext::builder()
                .user_id(Some(i as i64))
                .card_id(Some(i as i64))
                .action("read".into())
                .resource(Some("resource".into()))
                .target_id(Some(i as i64))
                .tenant_id(Some((i as i64) * 100))
                .build();
            engine.evaluate(&ctx, repo.as_ref()).await
        }));
    }

    for (i, handle) in handles.into_iter().enumerate() {
        let decision = handle.await.unwrap();
        assert!(decision.allowed, "租户 {} 应被允许", i);
    }
}

// ===== 租户状态阻断测试 =====

#[tokio::test]
async fn test_inactive_card_rejected_multi_tenant() {
    // 非活跃卡片在所有租户中都应被拒绝
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

    for tenant_id in [1i64, 2, 3, 100, 999] {
        let ctx = PolicyContext::builder()
            .user_id(Some(1))
            .card_id(Some(1))
            .action("read".into())
            .resource(Some("test".into()))
            .tenant_id(Some(tenant_id))
            .build();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(!decision.allowed, "租户 {} 的非活跃卡片应被拒绝", tenant_id);
        assert_eq!(decision.reason, "CARD_DISABLED");
    }
}
