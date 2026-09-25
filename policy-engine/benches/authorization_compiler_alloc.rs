//! Authorization compiler 分配 norms 基准（divan）
//!
//! 为 factored 共享层（b1107423）补齐内存分配观测维度：
//! criterion benches 只有时间数据，跨卡规则集去重的核心卖点是
//! "同一 (rule_set, entry) 内容在 HotState 中只存在一份"，需要分配
//! 字节数/分配次数的直接对照。
//!
//! 场景（总量恒定 4050 grants = 50 卡 × 81 条目）：
//! 1. `shared_build` / `private_build`：同一决策语义的两种物理布局——
//!    - SHARED：50 卡绑定同一 `source_id` 的同一批条目（factored 路径，
//!      共享层应只有 81 个 shared entry，setup 阶段断言）；
//!    - PRIVATE：等价授权以 DIRECT 形态逐卡私有（私有层 4050 条记录）。
//! 2. `shared_clone`：HotState 整体派生（im 结构共享，O(1)——分配应接近零）。
//! 3. `shared_add_grant` / `private_add_grant`：增量 delta 单条 Add。
//!
//! 静态基线经 `LazyLock` 构造：一次性初始化摊入首次迭代，统计聚合不受影响；
//! build 类基准是主要分配证据（全量在测区域内构造）。
//!
//! 分配字节数/次数由 `AllocProfiler` 全局分配器采集（见下方 `ALLOC` 声明）；
//! 缺少该声明时 divan 只输出 wall-clock 时间，不产生 alloc 列。
//!
//! 通过 `cargo bench -p policy-engine --bench authorization_compiler_alloc` 运行。

use std::sync::LazyLock;

use astral_types::{
    BindingLayer, CanonicalGrant, DependencyVector, DependencyVersion, GrantDelta, GrantEffect,
    GrantId, GrantProvenance, GrantRevision, GrantSourceKind, GrantState, TenantScope,
    ValidityWindow,
};
use policy_engine::HotState;

/// 用 divan 的 `AllocProfiler` 包裹 `System` 分配器，使各基准输出真实的
/// 分配字节数（alloc bytes）与分配次数（alloc count）；包装只做线程本地
/// 计数，不改变分配行为，对 wall-clock 语义无影响。
#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

/// 卡数 × 每卡条目数 = 4050 grants（与 criterion bench 的规模档一致）。
const CARDS: i64 = 50;
const ENTRIES: usize = 81;
const TENANT_ID: i64 = 7;
const DOMAIN_ID: i64 = 11;
const BASE_VERSION: u64 = 1;

fn tenant() -> TenantScope {
    TenantScope::new(TENANT_ID, Some(DOMAIN_ID)).unwrap()
}

fn dependencies() -> DependencyVector {
    DependencyVector::new(vec![DependencyVersion::new("rule-set", 3, 1).unwrap()]).unwrap()
}

fn grant_id(card: i64, index: usize) -> GrantId {
    GrantId::parse(&format!("00000000-0000-4000-8000-{card:04x}{index:08x}")).unwrap()
}

/// SHARED 布局授权：50 卡绑定同一 `rule-set-shared`，条目内容跨卡相同。
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

/// PRIVATE 布局授权：同一决策语义，但每卡私有（DIRECT/NONE 形态契约）。
fn private_grant(card: i64, index: usize) -> CanonicalGrant {
    let mut grant = shared_grant(card, index);
    grant.source_kind = GrantSourceKind::Direct;
    grant.binding_layer = BindingLayer::None;
    grant.provenance.source_id = format!("direct-{card}-{index}");
    grant.provenance.source_entry = None;
    grant
}

fn shared_grants() -> impl Iterator<Item = CanonicalGrant> {
    (1..=CARDS).flat_map(|card| (0..ENTRIES).map(move |index| shared_grant(card, index)))
}

fn private_grants() -> impl Iterator<Item = CanonicalGrant> {
    (1..=CARDS).flat_map(|card| (0..ENTRIES).map(move |index| private_grant(card, index)))
}

static SHARED_BASE: LazyLock<HotState> = LazyLock::new(|| {
    HotState::from_grants(tenant(), BASE_VERSION, shared_grants(), dependencies()).unwrap()
});

static PRIVATE_BASE: LazyLock<HotState> = LazyLock::new(|| {
    HotState::from_grants(tenant(), BASE_VERSION, private_grants(), dependencies()).unwrap()
});

/// SHARED 布局必须命中 factored 共享层：81 条共享条目（非 4050）。
#[divan::bench]
fn shared_entry_count_proof() -> usize {
    let count = SHARED_BASE.shared_entry_count();
    assert_eq!(count, ENTRIES, "factored 共享层必须跨卡去重为 81 条");
    count
}

#[divan::bench]
fn shared_build() -> HotState {
    HotState::from_grants(tenant(), BASE_VERSION, shared_grants(), dependencies()).unwrap()
}

#[divan::bench]
fn private_build() -> HotState {
    HotState::from_grants(tenant(), BASE_VERSION, private_grants(), dependencies()).unwrap()
}

/// im 持久化结构的整体派生：期望 O(1) 结构共享（分配接近零）。
#[divan::bench]
fn shared_clone() -> HotState {
    SHARED_BASE.clone()
}

/// SHARED 布局增量 Add：新卡命中既有共享条目（无新 shared entry 分配）。
#[divan::bench]
fn shared_add_grant() -> HotState {
    let delta = GrantDelta::add(shared_grant(CARDS + 1, 0));
    match policy_engine::AuthorizationCompiler::new()
        .compile_incremental(&SHARED_BASE, BASE_VERSION + 1, dependencies(), vec![delta])
        .unwrap()
    {
        policy_engine::CompileOutcome::Applied(candidate) => candidate.state,
        other => panic!("expected applied candidate, got {other:?}"),
    }
}

/// PRIVATE 布局增量 Add：整条私有记录全新分配。
#[divan::bench]
fn private_add_grant() -> HotState {
    let delta = GrantDelta::add(private_grant(CARDS + 1, 0));
    match policy_engine::AuthorizationCompiler::new()
        .compile_incremental(&PRIVATE_BASE, BASE_VERSION + 1, dependencies(), vec![delta])
        .unwrap()
    {
        policy_engine::CompileOutcome::Applied(candidate) => candidate.state,
        other => panic!("expected applied candidate, got {other:?}"),
    }
}

fn main() {
    divan::main();
}
