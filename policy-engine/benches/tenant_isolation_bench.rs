//! memory—v1: Retained data-scope resolution benchmarks.
//!
//! The published-evidence tenant-isolation benchmarks
//! (`tenant_isolation/published_*`) were removed together with the retired
//! V6/V7 published-evidence evaluation chain (Rust 规范 §15.10). The data-scope
//! resolver below runs standalone; no PENDING benchmark is added as a stand-in
//! for future memory-v1 authorization performance.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use policy_engine::DataScopeFilterResolver;

/// memory—v1: Benchmark data-scope filter resolution in isolation.
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

criterion_group! {
    name = tenant_isolation_benches;
    config = Criterion::default()
        .sample_size(500)
        .confidence_level(0.95);
    targets = bench_data_scope_resolve,
}

criterion_main!(tenant_isolation_benches);
