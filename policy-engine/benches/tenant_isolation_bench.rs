//! 多租户隔离基准测试
//!
//! 测量 PolicyEngine 在多租户高并发场景下的性能:
//! - 单租户评估基线
//! - 多租户并发评估（10/50/100 租户）
//! - DataScopeRuleProvider 解析性能
//! - 跨租户规则隔离开销

use astral_types::{Effect, PolicyContext, PolicyError};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use policy_engine::{
    DataScopeFilterResolver, PermissionRule, PolicyEngine, RuleRepository, RuleSetEntry,
    RuleSetSnapshot,
};

struct TenantRepo {
    snapshots: Vec<RuleSetSnapshot>,
    rules: Vec<PermissionRule>,
}

#[async_trait::async_trait]
impl RuleRepository for TenantRepo {
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

fn make_tenant_repo(tenant_id: i64, rule_count: usize) -> TenantRepo {
    let entries: Vec<RuleSetEntry> = (0..rule_count)
        .map(|i| RuleSetEntry {
            effect: if i % 3 == 0 {
                Effect::Deny
            } else {
                Effect::Allow
            },
            resource: Some(format!("tenant_{tenant_id}_resource_{i}")),
            action: Some("read".into()),
            condition: None,
        })
        .collect();

    TenantRepo {
        snapshots: vec![RuleSetSnapshot {
            rule_set_id: tenant_id,
            ref_type: "BASE".into(),
            entries,
        }],
        rules: vec![],
    }
}

fn bench_single_tenant(c: &mut Criterion) {
    let engine = PolicyEngine::new();
    let rt = tokio::runtime::Runtime::new().unwrap();

    let repo = make_tenant_repo(1, 10);
    let ctx = PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .action("read".into())
        .resource(Some("tenant_1_resource_5".into()))
        .tenant_id(Some(1))
        .build();

    c.bench_function("tenant_isolation/single_tenant_10_rules", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = black_box(engine.evaluate(&ctx, &repo).await);
            });
        });
    });
}

fn bench_multi_tenant_concurrent(c: &mut Criterion) {
    let engine = std::sync::Arc::new(PolicyEngine::new());
    let rt = tokio::runtime::Runtime::new().unwrap();

    for tenant_count in [10, 50, 100] {
        let repos: Vec<std::sync::Arc<TenantRepo>> = (0..tenant_count)
            .map(|i| std::sync::Arc::new(make_tenant_repo(i as i64, 10)))
            .collect();

        let label = format!("tenant_isolation/concurrent_{tenant_count}_tenants");

        c.bench_function(&label, |b| {
            b.iter(|| {
                rt.block_on(async {
                    let mut handles = vec![];
                    for (i, repo) in repos.iter().enumerate() {
                        let engine = engine.clone();
                        let repo = repo.clone();
                        handles.push(tokio::spawn(async move {
                            let ctx = PolicyContext::builder()
                                .user_id(Some(i as i64))
                                .card_id(Some(i as i64))
                                .action("read".into())
                                .resource(Some(format!("tenant_{}_resource_5", i)))
                                .tenant_id(Some(i as i64))
                                .build();
                            black_box(engine.evaluate(&ctx, repo.as_ref()).await)
                        }));
                    }
                    for h in handles {
                        let _ = h.await;
                    }
                });
            });
        });
    }
}

fn bench_data_scope_resolve(c: &mut Criterion) {
    let resolver = DataScopeFilterResolver::new();
    let rt = tokio::runtime::Runtime::new().unwrap();

    let ctx = PolicyContext::builder()
        .action("read".into())
        .tenant_id(Some(42))
        .domain_id(Some(10))
        .user_id(Some(100))
        .build();

    c.bench_function("tenant_isolation/data_scope_resolve", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = black_box(resolver.resolve(&ctx).await);
            });
        });
    });

    // personal scope 解析（包含 user_id 过滤）
    let ctx_personal = PolicyContext::builder()
        .action("personal:read".into())
        .tenant_id(Some(42))
        .user_id(Some(100))
        .build();

    c.bench_function("tenant_isolation/data_scope_resolve_personal", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = black_box(resolver.resolve(&ctx_personal).await);
            });
        });
    });
}

fn bench_cross_tenant_rule_lookup(c: &mut Criterion) {
    let engine = PolicyEngine::new();
    let rt = tokio::runtime::Runtime::new().unwrap();

    // 100 个租户，每个 50 条规则
    let repos: Vec<TenantRepo> = (0..100).map(|i| make_tenant_repo(i as i64, 50)).collect();

    c.bench_function("tenant_isolation/cross_tenant_100x50_rules", |b| {
        let mut i = 0usize;
        b.iter(|| {
            rt.block_on(async {
                let idx = i % 100;
                let ctx = PolicyContext::builder()
                    .user_id(Some(idx as i64))
                    .card_id(Some(idx as i64))
                    .action("read".into())
                    .resource(Some(format!("tenant_{}_resource_25", idx)))
                    .tenant_id(Some(idx as i64))
                    .build();
                let _ = black_box(engine.evaluate(&ctx, &repos[idx]).await);
                i += 1;
            });
        });
    });
}

criterion_group! {
    name = tenant_isolation_benches;
    config = Criterion::default()
        .sample_size(500)
        .confidence_level(0.95);
    targets = bench_single_tenant,
              bench_multi_tenant_concurrent,
              bench_data_scope_resolve,
              bench_cross_tenant_rule_lookup,
}

criterion_main!(tenant_isolation_benches);
