//! Multi-tenant benchmarks for strict published-evidence authorization.

#[path = "../tests/support/published.rs"]
mod published;

use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use policy_engine::{DataScopeFilterResolver, PolicyEngine};
use published::{assert_allow, assert_deny, canonical_grant, strict_context, PublishedRepo};

fn tenant_grants(
    tenant_count: usize,
    rules_per_tenant: usize,
) -> Vec<astral_types::CanonicalGrant> {
    let mut grants = Vec::with_capacity(tenant_count * rules_per_tenant);
    for tenant_index in 0..tenant_count {
        let tenant_id = 1000 + tenant_index as i64;
        let card_id = 2000 + tenant_index as i64;
        let user_id = 3000 + tenant_index as i64;
        let domain_id = 4000 + tenant_index as i64;
        for rule_index in 0..rules_per_tenant {
            grants.push(canonical_grant(
                (tenant_index * rules_per_tenant + rule_index + 1) as u64,
                tenant_id,
                Some(domain_id),
                card_id,
                user_id,
                &format!("tenant_{tenant_index}_resource_{rule_index}"),
                "read",
            ));
        }
    }
    grants
}

fn tenant_context(tenant_index: i64, rule_index: i64) -> astral_types::PolicyContext {
    strict_context(
        3000 + tenant_index,
        2000 + tenant_index,
        1000 + tenant_index,
        Some(4000 + tenant_index),
        &format!("tenant_{tenant_index}_resource_{rule_index}"),
        "read",
    )
}

fn bench_single_tenant(c: &mut Criterion) {
    let engine = PolicyEngine::new();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let repo = PublishedRepo::from_grants(tenant_grants(1, 10));
    let ctx = tenant_context(0, 5);

    let decision = rt.block_on(engine.evaluate(&ctx, &repo));
    assert_allow(&decision);
    assert_eq!(repo.published_reads(), 2);
    repo.assert_no_legacy_reads();
    repo.reset_counters();

    c.bench_function("tenant_isolation/published_single_tenant_10_rules", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(engine.evaluate(&ctx, &repo).await);
            });
        });
    });
    assert!(repo.published_reads() > 0);
    assert_eq!(repo.published_reads() % 2, 0);
    repo.assert_no_legacy_reads();
}

fn bench_multi_tenant_concurrent(c: &mut Criterion) {
    let engine = Arc::new(PolicyEngine::new());
    let rt = tokio::runtime::Runtime::new().unwrap();

    for tenant_count in [10usize, 50, 100] {
        let repo = Arc::new(PublishedRepo::from_grants(tenant_grants(tenant_count, 10)));
        for tenant_index in [0i64, tenant_count as i64 - 1] {
            let ctx = tenant_context(tenant_index, 5);
            let decision = rt.block_on(engine.evaluate(&ctx, repo.as_ref()));
            assert_allow(&decision);
        }
        repo.assert_no_legacy_reads();
        repo.reset_counters();

        let label = format!("tenant_isolation/published_concurrent_{tenant_count}_tenants");
        c.bench_function(&label, |b| {
            b.iter(|| {
                rt.block_on(async {
                    let mut handles = Vec::with_capacity(tenant_count);
                    for tenant_index in 0..tenant_count as i64 {
                        let engine = Arc::clone(&engine);
                        let repo = Arc::clone(&repo);
                        handles.push(tokio::spawn(async move {
                            let ctx = tenant_context(tenant_index, 5);
                            let decision = engine.evaluate(&ctx, repo.as_ref()).await;
                            black_box(decision)
                        }));
                    }
                    for handle in handles {
                        let decision = handle.await.unwrap();
                        assert_allow(&decision);
                    }
                });
            });
        });
        assert_eq!(repo.published_reads() % 2, 0);
        assert!(repo.published_reads() > 0);
        repo.assert_no_legacy_reads();
    }
}

fn bench_data_scope_resolve(c: &mut Criterion) {
    let resolver = DataScopeFilterResolver::new();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let ctx = astral_types::PolicyContext::builder()
        .action("read".into())
        .tenant_id(Some(42))
        .domain_id(Some(10))
        .user_id(Some(100))
        .build();

    c.bench_function("tenant_isolation/data_scope_resolve", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(resolver.resolve(&ctx).await);
            });
        });
    });

    let ctx_personal = astral_types::PolicyContext::builder()
        .action("personal:read".into())
        .tenant_id(Some(42))
        .user_id(Some(100))
        .build();
    c.bench_function("tenant_isolation/data_scope_resolve_personal", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(resolver.resolve(&ctx_personal).await);
            });
        });
    });
}

fn bench_cross_tenant_published_lookup(c: &mut Criterion) {
    let engine = PolicyEngine::new();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let repo = PublishedRepo::from_grants(tenant_grants(100, 50));
    let matching_ctx = tenant_context(25, 25);
    let matching_decision = rt.block_on(engine.evaluate(&matching_ctx, &repo));
    assert_allow(&matching_decision);
    repo.assert_no_legacy_reads();
    repo.reset_counters();

    let mut nonmatching_ctx = tenant_context(25, 25);
    nonmatching_ctx.resource = Some("tenant_26_resource_25".to_owned());
    let nonmatching_decision = rt.block_on(engine.evaluate(&nonmatching_ctx, &repo));
    assert_deny(&nonmatching_decision, "DEFAULT_DENY");
    repo.assert_no_legacy_reads();
    repo.reset_counters();

    c.bench_function("tenant_isolation/published_cross_tenant_100x50", |b| {
        let mut index = 0i64;
        b.iter(|| {
            let tenant_index = index % 100;
            let rule_index = (index / 100) % 50;
            index += 1;
            let ctx = tenant_context(tenant_index, rule_index);
            rt.block_on(async {
                black_box(engine.evaluate(&ctx, &repo).await);
            });
        });
    });
    assert!(repo.published_reads() > 0);
    assert_eq!(repo.published_reads() % 2, 0);
    repo.assert_no_legacy_reads();
}

fn bench_ready_empty_and_unavailable(c: &mut Criterion) {
    let engine = PolicyEngine::new();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let ctx = tenant_context(0, 5);

    let empty_repo = PublishedRepo::ready_empty_without_scope_recording(1000, 2000);
    let empty_decision = rt.block_on(engine.evaluate(&ctx, &empty_repo));
    assert_deny(&empty_decision, "DEFAULT_DENY");
    empty_repo.assert_no_legacy_reads();
    empty_repo.reset_counters();
    c.bench_function("tenant_isolation/published_empty_deny", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(engine.evaluate(&ctx, &empty_repo).await);
            });
        });
    });
    assert!(empty_repo.published_reads() > 0);
    empty_repo.assert_no_legacy_reads();

    let unavailable_repo = PublishedRepo::unavailable_without_scope_recording();
    let unavailable_decision = rt.block_on(engine.evaluate(&ctx, &unavailable_repo));
    assert_deny(&unavailable_decision, "AUTHORIZATION_PENDING");
    unavailable_repo.assert_no_legacy_reads();
    unavailable_repo.reset_counters();
    c.bench_function("tenant_isolation/published_unavailable_pending", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(engine.evaluate(&ctx, &unavailable_repo).await);
            });
        });
    });
    assert!(unavailable_repo.published_reads() > 0);
    unavailable_repo.assert_no_legacy_reads();
}

criterion_group! {
    name = tenant_isolation_benches;
    config = Criterion::default()
        .sample_size(500)
        .confidence_level(0.95);
    targets = bench_single_tenant,
              bench_multi_tenant_concurrent,
              bench_data_scope_resolve,
              bench_cross_tenant_published_lookup,
              bench_ready_empty_and_unavailable,
}

criterion_main!(tenant_isolation_benches);
