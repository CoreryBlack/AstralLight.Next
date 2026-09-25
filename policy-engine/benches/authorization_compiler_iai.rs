//! Authorization compiler 确定性指令数基准（iai-callgrind）
//!
//! 补齐授权编译器基准的确定性指令数维度：criterion/divan 都存在机器噪声，
//! iai-callgrind 用 callgrind 统计指令数（iai-callgrind 0.14 默认未启用
//! branch miss 指标），同一输入跨运行结果逐指令一致，适合 CI 回归门禁
//! 与独立复核。
//!
//! 实际执行仅限 Linux + valgrind（实验节点/CI），例如：
//!
//! ```text
//! cargo bench -p policy-engine --features iai \
//!   --bench authorization_compiler_iai
//! ```
//!
//! 本地 Windows 无 valgrind 不运行，仅做编译检查（bench 目标经
//! `required-features = ["iai"]` 门控）：
//!
//! ```text
//! cargo bench -p policy-engine --features iai --no-run --bench authorization_compiler_iai
//! ```
//!
//! 测量边界：iai-callgrind 默认 `--toggle-collect=*::__iai_callgrind_wrapper_mod::*`，
//! 仅收集 wrapper mod 内被测函数的指令；`BASE` 构造经 setup 注入，
//! 发生在收集区之外。`compile_incremental_single_add` 同样经 setup 注入
//! `BASE`，测量区只含 1 条 delta、编译器 O(1) 常量构造与增量编译本体，
//! 不含 4050-grant base 的复制/重建；返回的候选经 black_box 由 harness
//! 持有，其析构发生在收集区之外。

use std::sync::LazyLock;

use astral_types::{
    BindingLayer, CanonicalGrant, DependencyVector, DependencyVersion, GrantDelta, GrantEffect,
    GrantId, GrantProvenance, GrantRevision, GrantSourceKind, GrantState, ProjectionCompileMode,
    TenantScope, ValidityWindow,
};
use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use policy_engine::{AuthorizationCompiler, CompileOutcome, HotState, ProjectionKey};

const TENANT_ID: i64 = 7;
const DOMAIN_ID: i64 = 11;
/// Add 目标卡：`BASE` 只含 1..=50 卡，card 51 的 exact key 必然是新增 key
/// （不与 base 段冲突，也不触发通配/别名/全量重建路径）。
const ADDED_CARD: i64 = 51;

fn tenant() -> TenantScope {
    TenantScope::new(TENANT_ID, Some(DOMAIN_ID)).unwrap()
}

fn dependencies() -> DependencyVector {
    DependencyVector::new(vec![DependencyVersion::new("rule-set", 3, 1).unwrap()]).unwrap()
}

fn grant_id(card: i64, index: usize) -> GrantId {
    GrantId::parse(&format!("00000000-0000-4000-8000-{card:04x}{index:08x}")).unwrap()
}

fn shared_grant(card: i64, index: usize) -> CanonicalGrant {
    CanonicalGrant {
        grant_id: grant_id(card, index),
        revision: GrantRevision::initial(),
        state: GrantState::Active,
        source_kind: GrantSourceKind::RuleSet,
        binding_layer: BindingLayer::Base,
        tenant: tenant(),
        card_id: card,
        user_id: 42,
        resource: format!("learn_subject:{index}"),
        action: "read".to_owned(),
        effect: GrantEffect::Allow,
        validity: ValidityWindow::perpetual(),
        provenance: GrantProvenance {
            source_id: "rule-set-shared".to_owned(),
            source_entry: Some(format!("entry-{index}")),
            binding_id: Some(format!("binding-{card}")),
            delegation_id: None,
            operation_id: format!("operation-{card}-{index}"),
            event_id: Some(format!("event-{card}-{index}")),
            actor_user_id: Some(42),
        },
    }
}

/// 50 卡 × 81 条目 factored HotState（跨卡共享 81 条共享条目）。
static BASE: LazyLock<HotState> = LazyLock::new(|| {
    HotState::from_grants(
        tenant(),
        1,
        (1..=50i64).flat_map(|card| (0..81).map(move |index| shared_grant(card, index))),
        dependencies(),
    )
    .unwrap()
});

/// iai-callgrind 只收集 `*::__iai_callgrind_wrapper_mod::*` 内的函数
/// （默认 `--toggle-collect`）。把 `BASE` 的 LazyLock 首次初始化放进
/// setup（生成代码在 wrapper mod 之外展开），构造成本不计入基准
/// 指令数，测量区只含被测操作本身。
fn base_state() -> &'static HotState {
    &BASE
}

// im 持久化结构整体派生：确定性证明 O(1) 结构共享（指令数不随规模增长）。
#[library_benchmark]
#[bench::base(setup = base_state)]
fn clone_hot_state(state: &HotState) -> HotState {
    state.clone()
}

// 共享层条目数读取：恒定 81（跨卡去重事实的确定性断言载体）。
#[library_benchmark]
#[bench::base(setup = base_state)]
fn lookup_shared_entry_count(state: &HotState) -> usize {
    let count = state.shared_entry_count();
    assert_eq!(count, 81);
    count
}

// 单条 Add 的增量编译（`AuthorizationCompiler::compile_incremental`）：4050-grant
// base 经 setup 注入（收集区之外），测量区只含 1 条 delta 与编译器的 O(1) 常量
// 构造，不含 base 的复制/重建。新增 grant 复用共享条目 entry-0 的内容，其
// exact key（card=51, user=42, learn_subject:0, read）在 base 中不存在，命中
// 增量路径。断言只覆盖确定性语义形态（Applied、Incremental、受影响面恰为
// 新增 key/段、版本栅栏 1→2、差量计数 1、新段单贡献），返回完整 outcome 经
// 宏自动 `black_box` 防止优化擦除；候选 state 的析构随返回值发生在收集区
// 之外。无墙钟阈值、分配器总量或指针断言。
#[library_benchmark]
#[bench::base(setup = base_state)]
fn compile_incremental_single_add(state: &HotState) -> CompileOutcome {
    assert_eq!(
        state.version, 1,
        "fixture base must be the version-1 snapshot"
    );
    let added = shared_grant(ADDED_CARD, 0);
    let added_key = ProjectionKey::from_grant(&added).unwrap();
    assert!(
        state.segment_content(&added_key).is_none(),
        "add target must be a genuinely new exact key in the base"
    );
    let outcome = AuthorizationCompiler::new()
        .compile_incremental(state, 2, dependencies(), vec![GrantDelta::add(added)])
        .unwrap();
    let CompileOutcome::Applied(projection) = &outcome else {
        panic!("expected applied candidate, got {outcome:?}");
    };
    assert!(
        !projection.plan.full_rebuild,
        "single Add must stay incremental"
    );
    assert_eq!(projection.mode, ProjectionCompileMode::Incremental);
    assert_eq!(projection.base_version, 1);
    assert_eq!(projection.target_version, 2);
    assert_eq!(projection.applied_delta_count, 1);
    assert_eq!(projection.plan.affected_keys.len(), 1);
    assert_eq!(projection.plan.affected_keys[0], added_key);
    assert_eq!(projection.plan.affected_segments.len(), 1);
    assert_eq!(projection.plan.affected_segments[0].key, added_key);
    let added_segment = projection
        .state
        .segment_content(&added_key)
        .expect("added key must materialize its own segment");
    assert_eq!(added_segment.grant_count(), 1);
    outcome
}

library_benchmark_group!(
    name = compiler_deterministic;
    benchmarks = clone_hot_state, lookup_shared_entry_count, compile_incremental_single_add
);

main!(library_benchmark_groups = compiler_deterministic);
