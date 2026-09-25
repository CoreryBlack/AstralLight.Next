//! Authorization hot-state compiler 基准测试
//!
//! 量化触发面收窄（commit 1f857e85：窗口不再强制全量、base 形态不再污染增量资格、
//! 精确/窗口 delta 走组合级增量）后 [`AuthorizationCompiler::compile_incremental`]
//! 与全量 oracle（[`FullCompilerOracle`]）的实际收益差，验证增量重建、常态开销和全量降级语义：
//!
//! 1. 单卡规模梯度 N ∈ {100, 1000, 4050}：
//!    - 增量：精确 Add / 精确 Remove / 带窗口精确 Add（收窄后走增量）；
//!    - 全量：同 delta 走 [`FullCompilerOracle::compile`]，对照增量加速比；
//!    - 通配 Add：增量侧快速降级判定（`FullRebuildRequired(WildcardImpact)`）
//!      vs 全量侧真实重建成本。
//! 2. 批量：50 条精确 delta 批次（`MAX_INCREMENTAL_DELTAS` = 100 之内）增量 vs 全量。
//! 3. 段复用率观测：增量候选与 base 的 Arc 指针 / 内容 hash 对比，在 setup 阶段
//!    打印并断言（不影响计时）。
//!
//! 授权生成全部确定性：固定 UUID 文本 + index 化资源名；精确 key（无通配、无窗口）
//! 与通配/窗口变体分开构造。`action = "read"` 不在 [`astral_types::ACTION_ALIASES`]
//! 别名集中，保证精确 delta 不触发 `ActionAliasImpact`。
//!
//! 通过 `cargo bench` 运行，不进入普通 PR CI。

use std::sync::Arc;

use astral_types::{
    BindingLayer, CanonicalGrant, DependencyVector, DependencyVersion, GrantDelta, GrantEffect,
    GrantId, GrantProvenance, GrantRevision, GrantSourceKind, GrantState, ProjectionCompileMode,
    TenantScope, ValidityWindow,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use policy_engine::{
    AuthorizationCompiler, CompileOutcome, CompileRequest, CompiledProjection, FullCompilerOracle,
    FullRebuildReason, FullRebuildRequired, HotState, MAX_INCREMENTAL_DELTAS,
};

/// 单卡授权规模梯度（4050 为现网单卡授权观测上限档）。
const SCALE_STEPS: [usize; 3] = [100, 1000, 4050];
/// 批量场景的精确 delta 条数（须在 `MAX_INCREMENTAL_DELTAS` = 100 之内）。
const BATCH_DELTAS: usize = 50;
const CARD_ID: i64 = 17;
const USER_ID: i64 = 42;
const TENANT_ID: i64 = 7;
const DOMAIN_ID: i64 = 11;
const BASE_VERSION: u64 = 1;
/// 窗口 delta 的固定 UTC Unix 秒窗口（确定性构造，不取当前时钟）。
const WINDOWED_NOT_BEFORE: i64 = 1_700_000_000;
const WINDOWED_EXPIRES_AT: i64 = 1_800_000_000;

fn tenant() -> TenantScope {
    TenantScope::new(TENANT_ID, Some(DOMAIN_ID)).unwrap()
}

fn dependencies() -> DependencyVector {
    DependencyVector::new(vec![
        DependencyVersion::new("card", 4, 0).unwrap(),
        DependencyVersion::new("rule-set", 3, 1).unwrap(),
    ])
    .unwrap()
}

/// 由稳定 index 推导的确定性 UUID 文本（无 RNG，跨运行可复现）。
fn deterministic_grant_id(index: u64) -> GrantId {
    GrantId::parse(&format!("00000000-0000-4000-8000-{index:012x}")).unwrap()
}

/// 单卡精确 ALLOW 授权：`resource = learn_subject:{index}`、`action = "read"`、
/// 永久窗口、RULE_SET/BASE 形态（与 authorization_compiler 测试 helper 同构）。
fn exact_grant(index: u64) -> CanonicalGrant {
    CanonicalGrant {
        grant_id: deterministic_grant_id(index),
        revision: GrantRevision::initial(),
        state: GrantState::Active,
        source_kind: GrantSourceKind::RuleSet,
        binding_layer: BindingLayer::Base,
        tenant: tenant(),
        card_id: CARD_ID,
        user_id: USER_ID,
        resource: format!("learn_subject:{index}"),
        action: "read".to_owned(),
        effect: GrantEffect::Allow,
        validity: ValidityWindow::perpetual(),
        provenance: GrantProvenance {
            source_id: format!("rule-set-{index}"),
            source_entry: Some(format!("entry-{index}")),
            binding_id: Some(format!("binding-{index}")),
            delegation_id: None,
            operation_id: format!("operation-{index}"),
            event_id: Some(format!("event-{index}")),
            actor_user_id: Some(USER_ID),
        },
    }
}

/// 通配变体：resource 含 `*`，delta 自身触发 `WildcardImpact` 全量降级。
fn wildcard_grant(index: u64) -> CanonicalGrant {
    let mut grant = exact_grant(index);
    grant.resource = "learn_subject:*".to_owned();
    grant
}

/// 窗口变体：精确 key + 固定有效期窗口（触发面收窄后仍走组合级增量）。
fn windowed_grant(index: u64) -> CanonicalGrant {
    let mut grant = exact_grant(index);
    grant.validity = ValidityWindow::between(WINDOWED_NOT_BEFORE, WINDOWED_EXPIRES_AT);
    grant
}

fn applied(outcome: CompileOutcome) -> CompiledProjection {
    match outcome {
        CompileOutcome::Applied(candidate) => candidate,
        other => panic!("expected applied candidate, got {other:?}"),
    }
}

/// 段复用统计：用 pub API（`HotState.segments` 迭代）分别按 Arc 指针同一性与
/// 内容 hash 一致性两种口径计数，不修改 src。
struct SegmentReuse {
    base_segments: usize,
    candidate_segments: usize,
    arc_reused: usize,
    hash_unchanged: usize,
}

fn measure_segment_reuse(base: &HotState, candidate: &HotState) -> SegmentReuse {
    let mut arc_reused = 0;
    let mut hash_unchanged = 0;
    for (key, base_segment) in &base.segments {
        if let Some(candidate_segment) = candidate.segments.get(key) {
            if Arc::ptr_eq(base_segment, candidate_segment) {
                arc_reused += 1;
            }
            if base_segment.content_hash == candidate_segment.content_hash {
                hash_unchanged += 1;
            }
        }
    }
    SegmentReuse {
        base_segments: base.segments.len(),
        candidate_segments: candidate.segments.len(),
        arc_reused,
        hash_unchanged,
    }
}

fn print_segment_reuse(
    scenario: &str,
    scale: usize,
    reuse: &SegmentReuse,
    plan_affected_keys: usize,
) {
    let ratio = if reuse.base_segments == 0 {
        100.0
    } else {
        reuse.arc_reused as f64 * 100.0 / reuse.base_segments as f64
    };
    println!(
        "[segment-reuse] scenario={scenario} n={scale} base_segments={} candidate_segments={} \
         arc_reused={} hash_unchanged={} reuse_ratio={ratio:.2}% plan_affected_keys={plan_affected_keys}",
        reuse.base_segments, reuse.candidate_segments, reuse.arc_reused, reuse.hash_unchanged
    );
}

fn bench_compiler(c: &mut Criterion) {
    let compiler = AuthorizationCompiler::new();
    let oracle = FullCompilerOracle::new();
    let deps = dependencies();

    for scale in SCALE_STEPS {
        let max_index = scale as u64;
        let base = HotState::from_grants(
            tenant(),
            BASE_VERSION,
            (1..=max_index).map(exact_grant),
            deps.clone(),
        )
        .unwrap();
        let target = base.version + 1;

        // ===== a. 增量：精确 Add 一条（期待不随 N 增长） =====
        {
            let added = exact_grant(max_index + 1);
            let incremental = applied(
                compiler
                    .compile_incremental(
                        &base,
                        target,
                        deps.clone(),
                        vec![GrantDelta::add(added.clone())],
                    )
                    .unwrap(),
            );
            assert_eq!(
                incremental.mode,
                ProjectionCompileMode::Incremental,
                "精确 Add 必须走组合级增量（触发面收窄）"
            );
            assert_eq!(incremental.plan.affected_keys.len(), 1);
            let reuse = measure_segment_reuse(&base, &incremental.state);
            print_segment_reuse("incremental_exact_add", scale, &reuse, 1);
            assert_eq!(reuse.candidate_segments, scale + 1);
            assert_eq!(
                reuse.arc_reused, scale,
                "未受影响的段必须整体复用 base 的 Arc"
            );
            assert_eq!(reuse.hash_unchanged, scale);

            let full = applied(
                oracle
                    .compile(
                        &base,
                        &CompileRequest::for_base(
                            &base,
                            target,
                            deps.clone(),
                            vec![GrantDelta::add(added.clone())],
                        ),
                    )
                    .unwrap(),
            );
            assert_eq!(full.mode, ProjectionCompileMode::FullRebuild);
            assert_eq!(
                full.state, incremental.state,
                "增量与全量 oracle 必须 parity"
            );

            c.bench_function(&format!("compiler/incremental_exact_add/n={scale}"), |b| {
                b.iter(|| {
                    black_box(compiler.compile_incremental(
                        black_box(&base),
                        target,
                        deps.clone(),
                        vec![GrantDelta::add(black_box(added.clone()))],
                    ))
                })
            });
            c.bench_function(&format!("compiler/full_exact_add/n={scale}"), |b| {
                b.iter(|| {
                    black_box(oracle.compile(
                        black_box(&base),
                        &CompileRequest::for_base(
                            black_box(&base),
                            target,
                            deps.clone(),
                            vec![GrantDelta::add(black_box(added.clone()))],
                        ),
                    ))
                })
            });
        }

        // ===== b. 增量：精确 Remove 一条 =====
        {
            let removed_id = deterministic_grant_id(1);
            let incremental = applied(
                compiler
                    .compile_incremental(
                        &base,
                        target,
                        deps.clone(),
                        vec![GrantDelta::remove(removed_id, GrantRevision::initial())],
                    )
                    .unwrap(),
            );
            assert_eq!(incremental.mode, ProjectionCompileMode::Incremental);
            assert_eq!(incremental.plan.affected_keys.len(), 1);
            let reuse = measure_segment_reuse(&base, &incremental.state);
            print_segment_reuse("incremental_exact_remove", scale, &reuse, 1);
            assert_eq!(
                reuse.candidate_segments,
                scale - 1,
                "Remove 后该 key 段整体消失"
            );
            assert_eq!(reuse.arc_reused, scale - 1);

            let full = applied(
                oracle
                    .compile(
                        &base,
                        &CompileRequest::for_base(
                            &base,
                            target,
                            deps.clone(),
                            vec![GrantDelta::remove(removed_id, GrantRevision::initial())],
                        ),
                    )
                    .unwrap(),
            );
            assert_eq!(full.state, incremental.state);

            c.bench_function(
                &format!("compiler/incremental_exact_remove/n={scale}"),
                |b| {
                    b.iter(|| {
                        black_box(compiler.compile_incremental(
                            black_box(&base),
                            target,
                            deps.clone(),
                            vec![GrantDelta::remove(
                                black_box(removed_id),
                                GrantRevision::initial(),
                            )],
                        ))
                    })
                },
            );
            c.bench_function(&format!("compiler/full_exact_remove/n={scale}"), |b| {
                b.iter(|| {
                    black_box(oracle.compile(
                        black_box(&base),
                        &CompileRequest::for_base(
                            black_box(&base),
                            target,
                            deps.clone(),
                            vec![GrantDelta::remove(
                                black_box(removed_id),
                                GrantRevision::initial(),
                            )],
                        ),
                    ))
                })
            });
        }

        // ===== c. 增量：带窗口精确 Add（触发面收窄后必须走增量） =====
        {
            let windowed = windowed_grant(max_index + 1);
            let incremental = applied(
                compiler
                    .compile_incremental(
                        &base,
                        target,
                        deps.clone(),
                        vec![GrantDelta::add(windowed.clone())],
                    )
                    .unwrap(),
            );
            assert_eq!(
                incremental.mode,
                ProjectionCompileMode::Incremental,
                "窗口精确 delta 必须走组合级增量（触发面收窄核心收益）"
            );
            assert_eq!(incremental.plan.affected_keys.len(), 1);
            let reuse = measure_segment_reuse(&base, &incremental.state);
            print_segment_reuse("incremental_windowed_add", scale, &reuse, 1);
            assert_eq!(reuse.candidate_segments, scale + 1);
            assert_eq!(reuse.arc_reused, scale);

            let full = applied(
                oracle
                    .compile(
                        &base,
                        &CompileRequest::for_base(
                            &base,
                            target,
                            deps.clone(),
                            vec![GrantDelta::add(windowed.clone())],
                        ),
                    )
                    .unwrap(),
            );
            assert_eq!(full.state, incremental.state);

            c.bench_function(
                &format!("compiler/incremental_windowed_add/n={scale}"),
                |b| {
                    b.iter(|| {
                        black_box(compiler.compile_incremental(
                            black_box(&base),
                            target,
                            deps.clone(),
                            vec![GrantDelta::add(black_box(windowed.clone()))],
                        ))
                    })
                },
            );
            c.bench_function(&format!("compiler/full_windowed_add/n={scale}"), |b| {
                b.iter(|| {
                    black_box(oracle.compile(
                        black_box(&base),
                        &CompileRequest::for_base(
                            black_box(&base),
                            target,
                            deps.clone(),
                            vec![GrantDelta::add(black_box(windowed.clone()))],
                        ),
                    ))
                })
            });
        }

        // ===== e. 通配 Add：增量侧降级判定 vs 全量侧真实重建（语义保留的退化路径） =====
        {
            let wildcard = wildcard_grant(max_index + 1);
            let outcome = compiler
                .compile_incremental(
                    &base,
                    target,
                    deps.clone(),
                    vec![GrantDelta::add(wildcard.clone())],
                )
                .unwrap();
            assert!(
                matches!(
                    outcome,
                    CompileOutcome::FullRebuildRequired(FullRebuildRequired {
                        reason: FullRebuildReason::WildcardImpact,
                        ..
                    })
                ),
                "通配 Add 必须显式降级全量（WildcardImpact）"
            );

            let full = applied(
                oracle
                    .compile(
                        &base,
                        &CompileRequest::for_base(
                            &base,
                            target,
                            deps.clone(),
                            vec![GrantDelta::add(wildcard.clone())],
                        ),
                    )
                    .unwrap(),
            );
            assert_eq!(full.mode, ProjectionCompileMode::FullRebuild);

            c.bench_function(
                &format!("compiler/incremental_wildcard_add/n={scale}"),
                |b| {
                    b.iter(|| {
                        black_box(compiler.compile_incremental(
                            black_box(&base),
                            target,
                            deps.clone(),
                            vec![GrantDelta::add(black_box(wildcard.clone()))],
                        ))
                    })
                },
            );
            c.bench_function(&format!("compiler/full_wildcard_add/n={scale}"), |b| {
                b.iter(|| {
                    black_box(oracle.compile(
                        black_box(&base),
                        &CompileRequest::for_base(
                            black_box(&base),
                            target,
                            deps.clone(),
                            vec![GrantDelta::add(black_box(wildcard.clone()))],
                        ),
                    ))
                })
            });
        }

        // ===== 2. 批量：50 条精确 delta（MAX_INCREMENTAL_DELTAS = 100 之内） =====
        {
            let batch: Vec<GrantDelta> = ((max_index + 1)..=(max_index + BATCH_DELTAS as u64))
                .map(|index| GrantDelta::add(exact_grant(index)))
                .collect();
            assert!(batch.len() <= MAX_INCREMENTAL_DELTAS);

            let incremental = applied(
                compiler
                    .compile_incremental(&base, target, deps.clone(), batch.clone())
                    .unwrap(),
            );
            assert_eq!(incremental.mode, ProjectionCompileMode::Incremental);
            assert_eq!(incremental.plan.affected_keys.len(), BATCH_DELTAS);
            let reuse = measure_segment_reuse(&base, &incremental.state);
            print_segment_reuse("batch50_exact_add", scale, &reuse, BATCH_DELTAS);
            assert_eq!(reuse.candidate_segments, scale + BATCH_DELTAS);
            assert_eq!(reuse.arc_reused, scale);

            let full = applied(
                oracle
                    .compile(
                        &base,
                        &CompileRequest::for_base(&base, target, deps.clone(), batch.clone()),
                    )
                    .unwrap(),
            );
            assert_eq!(full.state, incremental.state);

            c.bench_function(&format!("compiler/batch50_incremental/n={scale}"), |b| {
                b.iter(|| {
                    black_box(compiler.compile_incremental(
                        black_box(&base),
                        target,
                        deps.clone(),
                        black_box(batch.clone()),
                    ))
                })
            });
            c.bench_function(&format!("compiler/batch50_full/n={scale}"), |b| {
                b.iter(|| {
                    black_box(oracle.compile(
                        black_box(&base),
                        &CompileRequest::for_base(
                            black_box(&base),
                            target,
                            deps.clone(),
                            black_box(batch.clone()),
                        ),
                    ))
                })
            });
        }
    }
}

criterion_group! {
    name = compiler_benches;
    config = Criterion::default()
        .sample_size(100)
        .confidence_level(0.95);
    targets = bench_compiler
}

criterion_main!(compiler_benches);
