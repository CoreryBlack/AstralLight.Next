//! PolicyEngine benchmarks for the strict published-evidence authorization path.
//!
//! The repository fixture models typed published evidence only. It does not prove
//! durable publication and it aborts if evaluation touches legacy/raw ports.

#[path = "../tests/support/published.rs"]
mod published;

use std::net::Ipv4Addr;
use std::sync::Arc;

use astral_types::PolicyContext;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use policy_engine::{
    Condition, ConditionEvaluator, IpRangeCondition, PolicyEngine, ScopeCondition,
    TimeRangeCondition,
};
use published::{assert_allow, assert_deny, canonical_grant, strict_context, PublishedRepo};

fn bench_strict_published_engine(c: &mut Criterion) {
    let engine = PolicyEngine::new();
    let rt = tokio::runtime::Runtime::new().unwrap();

    let allow_repo = PublishedRepo::from_grants_without_scope_recording(vec![canonical_grant(
        1,
        10,
        Some(11),
        20,
        30,
        "learn_subject:42",
        "read",
    )]);
    let allow_ctx = strict_context(30, 20, 10, Some(11), "learn_subject:42", "read");
    let allow_decision = rt.block_on(engine.evaluate(&allow_ctx, &allow_repo));
    assert_allow(&allow_decision);
    assert_eq!(allow_repo.published_reads(), 2);
    allow_repo.assert_no_legacy_reads();
    allow_repo.reset_counters();

    c.bench_function("engine/published_ready_allow", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(engine.evaluate(&allow_ctx, &allow_repo).await);
            });
        });
    });
    assert!(allow_repo.published_reads() > 0);
    assert_eq!(allow_repo.published_reads() % 2, 0);
    allow_repo.assert_no_legacy_reads();

    let empty_repo =
        PublishedRepo::from_evidence_without_scope_recording(vec![published::ready_evidence(
            10,
            20,
            vec![],
        )]);
    let empty_decision = rt.block_on(engine.evaluate(&allow_ctx, &empty_repo));
    assert_deny(&empty_decision, "DEFAULT_DENY");
    assert_eq!(empty_repo.published_reads(), 1);
    empty_repo.assert_no_legacy_reads();
    empty_repo.reset_counters();

    c.bench_function("engine/published_ready_empty_deny", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(engine.evaluate(&allow_ctx, &empty_repo).await);
            });
        });
    });
    assert!(empty_repo.published_reads() > 0);
    empty_repo.assert_no_legacy_reads();

    let unavailable_repo = PublishedRepo::unavailable_without_scope_recording();
    let unavailable_decision = rt.block_on(engine.evaluate(&allow_ctx, &unavailable_repo));
    assert_deny(&unavailable_decision, "AUTHORIZATION_PENDING");
    assert_eq!(unavailable_repo.published_reads(), 1);
    unavailable_repo.assert_no_legacy_reads();
    unavailable_repo.reset_counters();

    c.bench_function("engine/published_unavailable_pending", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(engine.evaluate(&allow_ctx, &unavailable_repo).await);
            });
        });
    });
    assert!(unavailable_repo.published_reads() > 0);
    unavailable_repo.assert_no_legacy_reads();

    let nonmatching_repo = PublishedRepo::from_grants_without_scope_recording(
        (0..500u64)
            .map(|index| {
                canonical_grant(
                    10 + index,
                    10,
                    Some(11),
                    20,
                    30,
                    &format!("nonmatching_resource_{index}:42"),
                    "read",
                )
            })
            .collect(),
    );
    let nonmatching_decision = rt.block_on(engine.evaluate(&allow_ctx, &nonmatching_repo));
    assert_deny(&nonmatching_decision, "DEFAULT_DENY");
    assert_eq!(nonmatching_repo.published_reads(), 1);
    nonmatching_repo.assert_no_legacy_reads();
    nonmatching_repo.reset_counters();

    c.bench_function("engine/published_ready_nonmatching_set", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(engine.evaluate(&allow_ctx, &nonmatching_repo).await);
            });
        });
    });
    assert!(nonmatching_repo.published_reads() > 0);
    nonmatching_repo.assert_no_legacy_reads();

    let gradient_repo = Arc::new(PublishedRepo::from_grants(
        (0..32u64)
            .map(|index| {
                canonical_grant(
                    100 + index,
                    1000 + index as i64,
                    Some(2000 + index as i64),
                    3000 + index as i64,
                    4000 + index as i64,
                    &format!("gradient_resource:{}", index + 1),
                    "read",
                )
            })
            .collect(),
    ));
    for index in [0i64, 31] {
        let resource_index = index + 1;
        let ctx = strict_context(
            4000 + index,
            3000 + index,
            1000 + index,
            Some(2000 + index),
            &format!("gradient_resource:{resource_index}"),
            "read",
        );
        let decision = rt.block_on(engine.evaluate(&ctx, gradient_repo.as_ref()));
        assert_allow(&decision);
    }
    gradient_repo.assert_no_legacy_reads();
    gradient_repo.reset_counters();

    c.bench_function("engine/published_tenant_gradient_32", |b| {
        let mut index = 0i64;
        b.iter(|| {
            let current = index % 32;
            index += 1;
            let resource_index = current + 1;
            let ctx = strict_context(
                4000 + current,
                3000 + current,
                1000 + current,
                Some(2000 + current),
                &format!("gradient_resource:{resource_index}"),
                "read",
            );
            rt.block_on(async {
                black_box(engine.evaluate(&ctx, gradient_repo.as_ref()).await);
            });
        });
    });
    assert!(gradient_repo.published_reads() > 0);
    assert_eq!(gradient_repo.published_reads() % 2, 0);
    gradient_repo.assert_no_legacy_reads();
}

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
    name = engine_benches;
    config = Criterion::default()
        .sample_size(1000)
        .confidence_level(0.95);
    targets = bench_strict_published_engine
}

criterion_group! {
    name = condition_benches;
    config = Criterion::default()
        .sample_size(1000)
        .confidence_level(0.95);
    targets = bench_condition_components
}

criterion_main!(engine_benches, condition_benches);
