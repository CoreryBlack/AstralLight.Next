//! PolicyEngine 基准测试
//!
//! 建立性能基线（Phase 4 作为 Rust vs Java 性能对比依据）。
//! 覆盖条件评估器 + 三层评估全链路 + 快照增量编译。
//!
//! 通过 `cargo bench` 运行，不进入普通 PR CI。

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use astral_types::{Effect, PolicyContext, PolicyError};
use policy_engine::{
    Condition, ConditionEvaluator, IpRangeCondition, PermissionRule, PolicyEngine, RuleRepository,
    RuleSetEntry, RuleSetSnapshot, TimeRangeCondition,
};

// ===== 模拟仓库 =====

struct EvalRepo {
    snapshots: Vec<RuleSetSnapshot>,
    rules: Vec<PermissionRule>,
    #[allow(dead_code)]
    label: String,
}

impl EvalRepo {
    /// L1 ALLOW：单条 BASE 规则命中
    fn l1_allow() -> Self {
        Self {
            snapshots: vec![RuleSetSnapshot {
                rule_set_id: 1,
                ref_type: "BASE".into(),
                entries: vec![RuleSetEntry {
                    effect: Effect::Allow,
                    resource: Some("learn_subject".into()),
                    action: Some("read".into()),
                    condition: None,
                }],
            }],
            rules: vec![],
            label: "l1_allow".to_string(),
        }
    }

    /// L1 → L3 DEFAULT_DENY：规则集空
    fn l3_default_deny() -> Self {
        Self {
            snapshots: vec![],
            rules: vec![],
            label: "l3_default_deny".to_string(),
        }
    }

    /// 50 条交替 DENY/ALLOW 规则
    fn many_rules(count: usize) -> Self {
        let entries: Vec<RuleSetEntry> = (0..count)
            .map(|i| RuleSetEntry {
                effect: if i % 2 == 0 {
                    Effect::Allow
                } else {
                    Effect::Deny
                },
                resource: Some(format!("resource_{}", i)),
                action: Some("*".into()),
                condition: None,
            })
            .collect();

        Self {
            snapshots: vec![RuleSetSnapshot {
                rule_set_id: 1,
                ref_type: "BASE".into(),
                entries,
            }],
            rules: vec![],
            label: format!("many_rules_{count}"),
        }
    }

    /// L2 回退路径
    fn l2_fallback() -> Self {
        Self {
            snapshots: vec![],
            rules: vec![PermissionRule {
                id: 1,
                effect: Effect::Allow,
                resource: "learn_subject".into(),
                action: "read".into(),
                condition: None,
            }],
            label: "l2_fallback".to_string(),
        }
    }
}

#[async_trait::async_trait]
impl RuleRepository for EvalRepo {
    async fn load_rule_set_snapshots(
        &self,
        _card_id: i64,
    ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
        Ok(self.snapshots.clone())
    }
    async fn load_permission_rules(
        &self,
        _card_id: i64,
    ) -> Result<Vec<PermissionRule>, PolicyError> {
        Ok(self.rules.clone())
    }
}

// ===== 引擎评估基准 =====

fn bench_engine(c: &mut Criterion) {
    let engine = PolicyEngine::new();
    let rt = tokio::runtime::Runtime::new().unwrap();

    // L1 ALLOW
    {
        let repo = EvalRepo::l1_allow();
        let ctx = PolicyContext::builder()
            .card_id(Some(1))
            .action("read".into())
            .resource(Some("learn_subject".into()))
            .build();
        c.bench_function("engine/l1_allow", |b| {
            b.iter(|| {
                rt.block_on(async {
                    let _ = black_box(engine.evaluate(&ctx, &repo).await);
                });
            })
        });
    }

    // L3 DEFAULT_DENY
    {
        let repo = EvalRepo::l3_default_deny();
        let ctx = PolicyContext::builder()
            .card_id(Some(1))
            .action("read".into())
            .resource(Some("learn_subject".into()))
            .build();
        c.bench_function("engine/l3_default_deny", |b| {
            b.iter(|| {
                rt.block_on(async {
                    let _ = black_box(engine.evaluate(&ctx, &repo).await);
                });
            })
        });
    }

    // 50 条规则
    {
        let repo = EvalRepo::many_rules(50);
        let ctx = PolicyContext::builder()
            .card_id(Some(1))
            .action("read".into())
            .resource(Some("resource_25".into()))
            .build();
        c.bench_function("engine/50_rules", |b| {
            b.iter(|| {
                rt.block_on(async {
                    let _ = black_box(engine.evaluate(&ctx, &repo).await);
                });
            })
        });
    }

    // 500 条规则
    {
        let repo = EvalRepo::many_rules(500);
        let ctx = PolicyContext::builder()
            .card_id(Some(1))
            .action("read".into())
            .resource(Some("resource_250".into()))
            .build();
        c.bench_function("engine/500_rules", |b| {
            b.iter(|| {
                rt.block_on(async {
                    let _ = black_box(engine.evaluate(&ctx, &repo).await);
                });
            })
        });
    }

    // L2 回退
    {
        let repo = EvalRepo::l2_fallback();
        let ctx = PolicyContext::builder()
            .card_id(Some(1))
            .action("read".into())
            .resource(Some("learn_subject".into()))
            .build();
        c.bench_function("engine/l2_fallback", |b| {
            b.iter(|| {
                rt.block_on(async {
                    let _ = black_box(engine.evaluate(&ctx, &repo).await);
                });
            })
        });
    }
}

// ===== 条件评估器基准 =====

fn bench_conditions(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let time_cond = Condition {
        condition_type: "TimeRangeCondition".into(),
        params: serde_json::json!({ "start": "00:00", "end": "23:59" }),
    };
    let ip_cond = Condition {
        condition_type: "IpRangeCondition".into(),
        params: serde_json::json!({ "ranges": ["10.0.0.1", "192.168.1.1"] }),
    };
    let scope_cond = Condition {
        condition_type: "ScopeCondition".into(),
        params: serde_json::json!({ "required_scopes": ["learn:read", "learn:write"] }),
    };

    let ctx = PolicyContext::builder()
        .action("read".into())
        .ip(Some("10.0.0.1".into()))
        .action_codes(vec!["learn:read".into(), "learn:write".into()])
        .build();

    c.bench_function("condition/time_range", |b| {
        let evaluator = TimeRangeCondition;
        b.iter(|| {
            rt.block_on(async {
                let _ = black_box(evaluator.evaluate(&time_cond, &ctx).await);
            })
        });
    });

    c.bench_function("condition/ip_range", |b| {
        let evaluator = IpRangeCondition;
        b.iter(|| {
            rt.block_on(async {
                let _ = black_box(evaluator.evaluate(&ip_cond, &ctx).await);
            })
        });
    });

    c.bench_function("condition/scope", |b| {
        let evaluator = policy_engine::ScopeCondition;
        b.iter(|| {
            rt.block_on(async {
                let _ = black_box(evaluator.evaluate(&scope_cond, &ctx).await);
            })
        });
    });
}

criterion_group! {
    name = engine_benches;
    config = Criterion::default()
        .sample_size(1000)
        .confidence_level(0.95);
    targets = bench_engine
}

criterion_group! {
    name = condition_benches;
    config = Criterion::default()
        .sample_size(1000)
        .confidence_level(0.95);
    targets = bench_conditions
}

criterion_main!(engine_benches, condition_benches);
