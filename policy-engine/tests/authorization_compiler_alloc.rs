//! Authorization compiler 分配 norms 对照测试（factored 共享层内存证据）
//!
//! 为共享层实现补齐内存分配维度：同一决策语义（50 卡 × 81 条目 = 4050
//! grants）在两种物理布局下的精确分配字节数/分配次数对照——
//! - SHARED：50 卡绑定同一 rule-set（factored 路径，共享层 81 条）；
//! - PRIVATE：等价授权逐卡私有（DIRECT/NONE，4050 条记录）。
//!
//! 用进程级计数分配器对测量区间做 delta 快照，仅作为观察项打印：进程全局
//! 计数受分配器预热、复用与测试线程交错影响，并行 harness 下跨运行非确定，
//! 不是可靠的确定性门槛；`--test-threads=1` 下数字量级跨平台可复现
//! （Windows 本地与 Linux 实验节点）。确定性结论由结构断言证明：共享层
//! 去重（81 条）、clone 的等价性与 `Arc` 物理共享、增量 Add 的受影响面与
//! 段复用不变式。
//!
//! 运行：`cargo test -p policy-engine --test authorization_compiler_alloc`
//! （默认并行 harness 即可稳定运行；`--test-threads=1` 只影响观察项数字
//! 的可读性，不影响断言）。

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
static ALLOC_COUNT: AtomicU64 = AtomicU64::new(0);

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = System.realloc(ptr, layout, new_size);
        if !new_ptr.is_null() {
            if new_size > layout.size() {
                ALLOC_BYTES.fetch_add((new_size - layout.size()) as u64, Ordering::Relaxed);
            }
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        new_ptr
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

use astral_types::{
    BindingLayer, CanonicalGrant, DependencyVector, DependencyVersion, GrantDelta, GrantEffect,
    GrantId, GrantProvenance, GrantRevision, GrantSourceKind, GrantState, ProjectionCompileMode,
    TenantScope, ValidityWindow,
};
use policy_engine::{
    AuthorizationCompiler, CompileOutcome, CompiledProjection, HotState, ProjectionKey,
};

const CARDS: i64 = 50;
const ENTRIES: usize = 81;
const TENANT_ID: i64 = 7;
const DOMAIN_ID: i64 = 11;

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

fn private_grant(card: i64, index: usize) -> CanonicalGrant {
    let mut grant = shared_grant(card, index);
    grant.source_kind = GrantSourceKind::Direct;
    grant.binding_layer = BindingLayer::None;
    grant.provenance.source_id = format!("direct-{card}-{index}");
    grant.provenance.source_entry = None;
    grant
}

fn snapshot() -> (u64, u64) {
    (
        ALLOC_BYTES.load(Ordering::SeqCst),
        ALLOC_COUNT.load(Ordering::SeqCst),
    )
}

fn measure<T>(f: impl FnOnce() -> T) -> (T, u64, u64) {
    let (b0, c0) = snapshot();
    let value = f();
    let (b1, c1) = snapshot();
    (value, b1 - b0, c1 - c0)
}

fn build_shared() -> HotState {
    HotState::from_grants(
        tenant(),
        1,
        (1..=CARDS).flat_map(|card| (0..ENTRIES).map(move |index| shared_grant(card, index))),
        dependencies(),
    )
    .unwrap()
}

fn build_private() -> HotState {
    HotState::from_grants(
        tenant(),
        1,
        (1..=CARDS).flat_map(|card| (0..ENTRIES).map(move |index| private_grant(card, index))),
        dependencies(),
    )
    .unwrap()
}

fn applied_projection(outcome: CompileOutcome) -> CompiledProjection {
    match outcome {
        CompileOutcome::Applied(candidate) => candidate,
        other => panic!("expected applied candidate, got {other:?}"),
    }
}

/// SHARED 布局必须命中 factored 共享层：81 条共享条目（非 4050）。
#[test]
fn shared_layer_dedup_proof() {
    let state = build_shared();
    assert_eq!(
        state.shared_entry_count(),
        ENTRIES,
        "factored 共享层必须跨卡去重为 81 条"
    );
}

/// 对照 1：构建分配报告——两种布局的精确分配数字（观察项，非断言）。
///
/// 语义说明：SHARED 的卖点是**内容去重**（81 条共享条目 vs 4050 条记录），
/// 而非任意场景下分配都更少——私有 DIRECT 基线不携带规则集条目内容，
/// 其记录层更扁平。旧"每卡全量复制条目内容"的布局已随 factored 改造
/// 删除，代码中不存在可对照的合法构造路径；此处仅报告两种现存布局的
/// 精确数字供基准分析使用。
#[test]
fn build_allocation_report() {
    let (_, shared_bytes, shared_count) = measure(build_shared);
    let (_, private_bytes, private_count) = measure(build_private);

    println!(
        "alloc: shared_build  = {shared_bytes} bytes / {shared_count} allocs（4050 grants → 81 共享条目）"
    );
    println!(
        "alloc: private_build = {private_bytes} bytes / {private_count} allocs（4050 私有记录）"
    );
    println!("note: shared_entry_count = 81（内容寻址去重），active_grants = 4050");
}

/// 对照 2：整体派生——clone 等价性与持久化结构共享（确定性结构证明）。
///
/// clone 的分配器 delta 字节数/次数只作为观察项打印：进程全局计数受分配器
/// 预热、复用与并行测试线程交错影响，跨运行非确定，不是可靠的确定性门槛，
/// 也不用于证明 O(1)。结构共享的证据由结构断言给出：clone 与 base 逐字段
/// 相等（版本、语义/依赖哈希、编译器身份、ledger 与段内容），且全部段、
/// 共享层条目与记录层 `entry` 句柄按 `Arc` 物理共享——与分配器噪声和测试
/// 顺序无关。clone 丢数据、改变身份/哈希或停止共享即失败。
#[test]
fn clone_is_near_zero_allocation() {
    let base = build_shared();
    let (clone, bytes, count) = measure(|| base.clone());
    println!("alloc: shared_clone = {bytes} bytes / {count} allocs（观察项，非断言）");

    // Equivalent persistent hot state: derived field-for-field equality covers
    // version, hashes, compiler identity, ledger and segment contents; the
    // explicit checks below anchor the same invariants on the public surface.
    assert_eq!(clone, base, "clone must be an equivalent hot state");
    assert_eq!(clone.version, base.version);
    assert_eq!(clone.dependency_hash, base.dependency_hash);
    assert_eq!(clone.compiler_version, base.compiler_version);
    assert_eq!(clone.semantic_hash, base.semantic_hash);
    assert_eq!(
        clone.all_grants(),
        base.all_grants(),
        "full ledger must survive the clone"
    );
    assert_eq!(
        clone.active_grants().len(),
        base.active_grants().len(),
        "active contributions must survive the clone"
    );
    assert_eq!(clone.shared_entry_count(), ENTRIES);
    assert_eq!(
        clone.segment_keys().len(),
        base.segment_keys().len(),
        "segment cardinality must survive the clone"
    );

    // Physical sharing: every immutable segment handle is the same Arc.
    assert!(
        !base.segment_keys().is_empty(),
        "fixture must materialize segments"
    );
    for key in base.segment_keys() {
        let base_segment = base
            .segment_content(key)
            .expect("base must retain its segment");
        let clone_segment = clone
            .segment_content(key)
            .expect("clone must retain the segment");
        assert!(
            Arc::ptr_eq(&base_segment, &clone_segment),
            "clone must physically share segment {key:?}"
        );
    }

    // Shared layer: content-addressed entries are Arc-shared whole.
    assert!(
        !base.shared_entries.is_empty(),
        "shared layout must populate the factored shared layer"
    );
    for (content_hash, base_entry) in base.shared_entries.iter() {
        let clone_entry = clone
            .shared_entries
            .get(content_hash)
            .expect("clone must retain the shared entry");
        assert!(
            Arc::ptr_eq(base_entry, clone_entry),
            "clone must physically share shared-layer entry {content_hash}"
        );
    }

    // Record layer: each RULE_SET record references the same shared entry Arc.
    assert!(
        !base.ruleset_records.is_empty(),
        "shared layout must populate the ruleset record layer"
    );
    for (grant_id, base_record) in base.ruleset_records.iter() {
        let clone_record = clone
            .ruleset_records
            .get(grant_id)
            .expect("clone must retain the ruleset record");
        assert!(
            Arc::ptr_eq(&base_record.entry, &clone_record.entry),
            "clone must physically share the record's shared-entry handle"
        );
    }
}

/// 对照 3：增量 Add 的受影响面与物理复用——确定性结构证明。
///
/// 在 810-grant 与 4050-grant 两个基线上各 Add 一条 grant。单条 Add 的正确性
/// 由结构不变式证明，而非进程级分配器字节数：受影响面恰为一个 key/一个段
/// （且都是新增 key）、版本栅栏与差量计数确定、授权基数恰好 +1、共享层条目
/// 数不变、依赖/编译器身份一致，且未触碰段按 `Arc` 物理复用（`ptr_eq`）。
/// 分配器 delta 字节数/次数只作为观察项打印：进程全局计数受分配器预热与
/// 复用影响，跨运行非单调，不是可靠的确定性门槛，也不用于证明 O(1)——
/// O(受影响面) 的证据由上述结构断言给出。
#[test]
fn incremental_add_allocation_is_constant() {
    let small_base = HotState::from_grants(
        tenant(),
        1,
        (1..=10i64).flat_map(|card| (0..ENTRIES).map(move |index| shared_grant(card, index))),
        dependencies(),
    )
    .unwrap();
    let large_base = build_shared();

    let (small_candidate, small_bytes, small_count) = measure(|| {
        let delta = GrantDelta::add(shared_grant(CARDS + 1, 0));
        applied_projection(
            AuthorizationCompiler::new()
                .compile_incremental(&small_base, 2, dependencies(), vec![delta])
                .unwrap(),
        )
    });
    let (large_candidate, large_bytes, large_count) = measure(|| {
        let delta = GrantDelta::add(shared_grant(CARDS + 1, 0));
        applied_projection(
            AuthorizationCompiler::new()
                .compile_incremental(&large_base, 2, dependencies(), vec![delta])
                .unwrap(),
        )
    });

    println!("alloc: add on 810-grant base  = {small_bytes} bytes / {small_count} allocs");
    println!("alloc: add on 4050-grant base = {large_bytes} bytes / {large_count} allocs");

    assert_incremental_add_invariants(&small_base, &small_candidate);
    assert_incremental_add_invariants(&large_base, &large_candidate);
}

/// Deterministic structural proof of one Add on a base: the affected set is
/// exactly the added key/segment, version fence and delta accounting hold,
/// cardinalities grow by exactly one, and one untouched segment is physically
/// reused (`Arc::ptr_eq`) — independent of process-global allocator totals.
fn assert_incremental_add_invariants(base: &HotState, candidate: &CompiledProjection) {
    let added = shared_grant(CARDS + 1, 0);
    let added_key = ProjectionKey::from_grant(&added).unwrap();
    let untouched_key = ProjectionKey::from_grant(&shared_grant(1, 1)).unwrap();
    assert_ne!(
        added_key, untouched_key,
        "add target must be a genuinely new key, not the untouched probe"
    );

    // Affected set: exactly one key and one segment, both the added one.
    assert!(
        !candidate.plan.full_rebuild,
        "single Add must not require full rebuild"
    );
    assert_eq!(
        candidate.mode,
        ProjectionCompileMode::Incremental,
        "single Add must compile on the local incremental path"
    );
    assert_eq!(candidate.plan.affected_keys, vec![added_key.clone()]);
    assert_eq!(candidate.plan.affected_segments.len(), 1);
    assert_eq!(candidate.plan.affected_segments[0].key, added_key);

    // Version fence and delta accounting.
    assert_eq!(candidate.base_version, base.version);
    assert_eq!(candidate.target_version, 2);
    assert_eq!(candidate.applied_delta_count, 1);

    // Cardinality: exactly one new grant and one new active grant.
    assert_eq!(
        candidate.state.all_grants().len(),
        base.all_grants().len() + 1
    );
    assert_eq!(
        candidate.state.active_grants().len(),
        base.active_grants().len() + 1
    );

    // Factored shared layer keeps its entry count (per-card Add reuses content).
    assert_eq!(
        candidate.state.shared_entry_count(),
        base.shared_entry_count()
    );
    assert_eq!(candidate.state.shared_entry_count(), ENTRIES);

    // Identity coherence: dependency and compiler identity unchanged; semantic
    // hash moves because the candidate version differs from the base version.
    assert_eq!(candidate.state.dependency_hash, base.dependency_hash);
    assert_eq!(candidate.state.compiler_version, base.compiler_version);
    assert_ne!(candidate.state.semantic_hash, base.semantic_hash);

    // Physical reuse independent of allocator totals: the untouched segment is
    // Arc-shared between base and candidate with an unchanged content hash.
    let untouched_in_base = base
        .segment_content(&untouched_key)
        .expect("untouched key must exist in base");
    let untouched_in_candidate = candidate
        .state
        .segment_content(&untouched_key)
        .expect("untouched key must survive the Add");
    assert!(
        Arc::ptr_eq(&untouched_in_base, &untouched_in_candidate),
        "untouched segment must be physically reused"
    );
    assert_eq!(
        untouched_in_base.content_hash,
        untouched_in_candidate.content_hash
    );

    // The added key is genuinely new and materializes its own single-grant segment.
    assert!(
        base.segment_content(&added_key).is_none(),
        "add target must not collide with base keys"
    );
    let added_segment = candidate
        .state
        .segment_content(&added_key)
        .expect("added key must materialize a segment");
    assert_eq!(added_segment.grant_count(), 1);
    assert_eq!(added_segment.grants[0].grant_id, added.grant_id);

    // The base remains an unmodified version-1 snapshot.
    assert_eq!(base.version, 1);
}
