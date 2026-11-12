//! memory—v1: Retained condition-component benchmarks.
//!
//! The published-evidence ALLOW/DENY engine benchmarks (`engine/published_*`)
//! were removed together with the retired V6/V7 published-evidence evaluation
//! chain (Rust 规范 §15.10). The condition components below are independent
//! helpers that still run standalone; no PENDING benchmark is added as a
//! stand-in for future memory-v1 authorization performance.

use std::net::Ipv4Addr;

use astral_types::PolicyContext;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use policy_engine::{
    Condition, ConditionEvaluator, IpRangeCondition, ScopeCondition, TimeRangeCondition,
};

/// memory—v1: Benchmark the retained condition components in isolation.
fn bench_condition_components(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let ip = Ipv4Addr::new(10, 0, 0, 1).to_string();
    let second_ip = Ipv4Addr::new(192, 168, 1, 1).to_string();
    let time_cond = Condition {
        condition_type: "TimeRangeCondition".into(),
        params: serde_json::json!({ "start": "00:00", "end": "23:59" }),
    };
    let ip_cond = Condition {
        condition_type: "IpRangeCondition".into(),
        params: serde_json::json!({ "ranges": [ip.clone(), second_ip] }),
    };
    let scope_cond = Condition {
        condition_type: "ScopeCondition".into(),
        params: serde_json::json!({ "required_scopes": ["learn:read", "learn:write"] }),
    };
    let ctx = PolicyContext::builder()
        .action("read".into())
        .ip(Some(ip))
        .action_codes(vec!["learn:read".into(), "learn:write".into()])
        .build();

    c.bench_function("condition/component_time_range", |b| {
        let evaluator = TimeRangeCondition;
        b.iter(|| {
            rt.block_on(async {
                let result = evaluator.evaluate(&time_cond, &ctx).await;
                assert!(black_box(result).is_ok());
            });
        });
    });

    c.bench_function("condition/component_ipv4_range", |b| {
        let evaluator = IpRangeCondition;
        b.iter(|| {
            rt.block_on(async {
                let result = evaluator.evaluate(&ip_cond, &ctx).await;
                assert!(black_box(result).is_ok());
            });
        });
    });

    c.bench_function("condition/component_scope", |b| {
        let evaluator = ScopeCondition;
        b.iter(|| {
            rt.block_on(async {
                let result = evaluator.evaluate(&scope_cond, &ctx).await;
                assert!(black_box(result).is_ok());
            });
        });
    });
}

criterion_group! {
    name = condition_benches;
    config = Criterion::default()
        .sample_size(1000)
        .confidence_level(0.95);
    targets = bench_condition_components
}

criterion_main!(condition_benches);
