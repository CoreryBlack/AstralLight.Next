//! 授权热路径上限探针（release + --ignored 运行）。
//!
//! 测量三个声明的真实上限与硬件利用率：
//! - 内存权威零 I/O：strict published-evidence 内存仓库（每次读取克隆整份
//!   证据，即生产 reader 的物化语义）；
//! - 编译期 O(1) 策略匹配：published 证据含 4050 条授权但仅 1 条精确命中，
//!   对比 1 条授权的每操作成本验证匹配不随规模线性增长；
//! - 无锁并发：共享 engine+仓库，1/2/4/10 线程聚合吞吐与扩展效率。
//!
//! cfg(test) 下一致性采样按生产代码路径整体跳过（formal.rs 的既定行为），
//! 故本探针不含 1% 二次评估税；生产平均成本 = 本探针 × ~1.01。

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Barrier;
use std::time::{Duration, Instant};

use super::ports::RuleRepository;
use super::types::*;
use super::PolicyEngine;
use astral_types::{
    BindingLayer, CanonicalGrant, GrantEffect, GrantId, GrantProvenance, GrantRevision,
    GrantSourceKind, GrantState, PublishedAggregateManifestSummary, PublishedCardAuthorization,
    PublishedCardAuthorizationGate, PublishedEvidenceGateStatus, TenantScope, ValidityWindow,
    VerifiedPublishedGrantRecord,
};
use astral_types::{PolicyContext, PolicyError, PublishedCardEvidenceScope};

/// 内存权威仓库：整份证据常驻，读取 = 克隆（物化）+ 原子计数。
struct MemoryAuthorityRepo {
    evidence: std::sync::Arc<PublishedCardAuthorization>,
    reads: AtomicUsize,
}

#[async_trait::async_trait]
impl RuleRepository for MemoryAuthorityRepo {
    fn requires_published_card_evidence(&self) -> bool {
        true
    }
    async fn load_published_card_authorization(
        &self,
        _scope: &PublishedCardEvidenceScope,
    ) -> Result<Option<std::sync::Arc<PublishedCardAuthorization>>, PolicyError> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        // 生产读面语义：命中 = 引用计数克隆，零深拷贝。
        Ok(Some(std::sync::Arc::clone(&self.evidence)))
    }
    async fn is_active_global_admin(&self, _user_id: i64) -> Result<bool, PolicyError> {
        Ok(false)
    }
    async fn get_projection_gate(
        &self,
        _card_id: i64,
    ) -> Result<Option<ProjectionGate>, PolicyError> {
        Ok(None)
    }
    async fn load_rule_set_entries_raw(
        &self,
        _card_id: i64,
    ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
        Ok(vec![])
    }
    async fn load_permission_rules_raw(
        &self,
        _card_id: i64,
    ) -> Result<Vec<PermissionRule>, PolicyError> {
        Ok(vec![])
    }
    async fn load_permission_rules(
        &self,
        _card_id: i64,
    ) -> Result<Vec<PermissionRule>, PolicyError> {
        Ok(vec![])
    }
    async fn load_projected_delegated_rules(
        &self,
        _delegate_id: i64,
        _resource: &str,
        _action: &str,
    ) -> Result<Vec<PermissionRule>, PolicyError> {
        Ok(vec![])
    }
}

/// 确定性 canonical UUID（seed 编码进末 12 位 hex），满足 GrantId 契约。
fn deterministic_grant_id(seed: u64) -> GrantId {
    GrantId::parse(&format!(
        "00000000-0000-0000-0000-{:012x}",
        seed & 0xffff_ffff_ffff
    ))
    .unwrap()
}

fn noise_grant(index: usize) -> CanonicalGrant {
    CanonicalGrant {
        grant_id: deterministic_grant_id(index as u64),
        revision: GrantRevision::new(1).unwrap(),
        state: GrantState::Active,
        source_kind: GrantSourceKind::RuleSet,
        binding_layer: BindingLayer::Base,
        tenant: TenantScope::new(7, Some(11)).unwrap(),
        card_id: 1,
        user_id: 1,
        resource: format!("noise_resource_{index}"),
        action: "read".to_string(),
        effect: GrantEffect::Allow,
        validity: ValidityWindow::perpetual(),
        provenance: GrantProvenance {
            source_id: "source-1".to_string(),
            source_entry: Some("entry-1".to_string()),
            binding_id: Some("binding-1".to_string()),
            delegation_id: None,
            operation_id: "op-1".to_string(),
            event_id: Some("event-1".to_string()),
            actor_user_id: None,
        },
    }
}

fn matching_grant() -> CanonicalGrant {
    CanonicalGrant {
        resource: "learn_subject".to_string(),
        grant_id: deterministic_grant_id(u64::MAX),
        ..noise_grant(9_999)
    }
}

fn evidence(grants: Vec<CanonicalGrant>) -> PublishedCardAuthorization {
    let record_count = grants.len();
    let manifest = PublishedAggregateManifestSummary {
        tenant_id: 7,
        card_id: 1,
        aggregate_type: "CARD".to_string(),
        aggregate_id: 1,
        manifest_id: 1,
        generation: 1,
        source_generation: 1,
        projected_generation: 1,
        revoke_fence: 0,
        cas_version: 1,
        semantic_hash_hex: "a".repeat(64),
        dependency_hash_hex: "b".repeat(64),
        manifest_digest_hex: "c".repeat(64),
        compiler_version: "test".to_string(),
        event_id: "event-1".to_string(),
        operation_id: "op-1".to_string(),
        parent_manifest_id: None,
        segment_count: 1,
        declared_grant_row_count: record_count as u64,
    };
    let records = grants
        .iter()
        .map(|grant| VerifiedPublishedGrantRecord {
            aggregate_type: "CARD".to_string(),
            aggregate_id: 1,
            publication_generation: 1,
            revoke_fence: 0,
            manifest_id: 1,
            event_id: "event-1".to_string(),
            operation_id: "op-1".to_string(),
            semantic_hash_hex: "a".repeat(64),
            dependency_hash_hex: "b".repeat(64),
            compiler_version: "test".to_string(),
            segment_ordinal: 0,
            position_in_segment: 0,
            grant: grant.clone(),
            accepted_into_effective_set: true,
            unaccepted_reason: None,
        })
        .collect();
    PublishedCardAuthorization {
        tenant_id: 7,
        card_id: 1,
        read_unix_seconds: 1_700_000_000,
        gate: PublishedCardAuthorizationGate {
            status: PublishedEvidenceGateStatus::Ready,
            aggregate_manifest_count: 1,
            verified_record_count: record_count,
            effective_grant_count: record_count,
            not_in_effective_count: 0,
            equivalent_duplicate_collapsed_count: 0,
        },
        manifests: vec![manifest],
        records,
        effective_grants: grants,
    }
}

fn probe_ctx() -> PolicyContext {
    PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .tenant_id(Some(7))
        .domain_id(Some(11))
        .action("read".into())
        .resource(Some("learn_subject".into()))
        .target_id(Some(42))
        .build()
}

fn percentile(sorted: &[u64], fraction: f64) -> u64 {
    let index = ((sorted.len() as f64) * fraction) as usize;
    sorted[index.min(sorted.len() - 1)]
}

const PHASE_BUDGET: Duration = Duration::from_secs(4);
const SAMPLE_CAP: usize = 150_000;

fn probe_loop(
    engine: &PolicyEngine,
    repo: &MemoryAuthorityRepo,
    ctx: &PolicyContext,
    rt: &tokio::runtime::Runtime,
) -> (usize, Vec<u64>) {
    let mut samples = Vec::new();
    let mut ops = 0usize;
    let start = Instant::now();
    loop {
        let op_start = Instant::now();
        let decision = rt.block_on(engine.evaluate(ctx, repo));
        if samples.len() < SAMPLE_CAP {
            samples.push(op_start.elapsed().as_nanos() as u64);
        }
        assert!(decision.allowed, "probe ctx must evaluate ALLOW");
        ops += 1;
        if start.elapsed() >= PHASE_BUDGET || samples.len() >= SAMPLE_CAP {
            return (ops, samples);
        }
    }
}

fn run_single(
    engine: &PolicyEngine,
    repo: &MemoryAuthorityRepo,
    ctx: &PolicyContext,
) -> (f64, Vec<u64>) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    for _ in 0..2_000 {
        let _ = rt.block_on(engine.evaluate(ctx, repo));
    }
    let start = Instant::now();
    let (ops, samples) = probe_loop(engine, repo, ctx, &rt);
    (ops as f64 / start.elapsed().as_secs_f64(), samples)
}

/// 每线程独立 current_thread runtime + scope 线程；返回（最长墙钟, 0 号线程样本, 总操作数）。
fn run_threads(
    engine: &PolicyEngine,
    repo: &MemoryAuthorityRepo,
    ctx: &PolicyContext,
    threads: usize,
) -> (Duration, Vec<u64>, usize) {
    let barrier = Barrier::new(threads);
    let first_samples = std::sync::Mutex::new(Vec::new());
    let mut total_ops = 0usize;
    let mut last = Duration::ZERO;
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for worker in 0..threads {
            let barrier = &barrier;
            let samples_slot = &first_samples;
            handles.push(scope.spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .build()
                    .expect("runtime");
                for _ in 0..500 {
                    let _ = rt.block_on(engine.evaluate(ctx, repo));
                }
                barrier.wait();
                let start = Instant::now();
                let (ops, samples) = probe_loop(engine, repo, ctx, &rt);
                let elapsed = start.elapsed();
                if worker == 0 {
                    *samples_slot.lock().unwrap() = samples;
                }
                (elapsed, ops)
            }));
        }
        for handle in handles {
            let (elapsed, ops) = handle.join().expect("worker");
            last = last.max(elapsed);
            total_ops += ops;
        }
    });
    (last, first_samples.into_inner().unwrap(), total_ops)
}

static ALLOCS: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
/// 计数开关：仅分配计量阶段置位。关闭时计数路径只做一次无争用 Relaxed 读
/// （缓存行保持共享读态），吞吐/多线程阶段不再被计数器 fetch_add 串行化——
/// 否则观测本身会制造负扩展假象。
static COUNTING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

struct CountingAlloc;

#[inline]
unsafe fn count_alloc(bytes: u64) {
    if COUNTING.load(Ordering::Relaxed) {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(bytes, Ordering::Relaxed);
    }
}

unsafe impl std::alloc::GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        count_alloc(layout.size() as u64);
        std::alloc::System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        std::alloc::System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, new_size: usize) -> *mut u8 {
        count_alloc(new_size as u64);
        std::alloc::System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

#[ignore = "release-only ceiling probe; run with --release -- --ignored"]
#[test]
fn authorization_ceiling_probe() {
    let ctx = probe_ctx();
    eprintln!("machine: 4P+6E cores (10 logical), phase budget {PHASE_BUDGET:?}");
    for size in [1usize, 4050] {
        let mut grants: Vec<CanonicalGrant> = Vec::with_capacity(size);
        grants.push(matching_grant());
        for index in 1..size {
            grants.push(noise_grant(index));
        }
        let repo = MemoryAuthorityRepo {
            evidence: std::sync::Arc::new(evidence(grants)),
            reads: AtomicUsize::new(0),
        };
        let engine = PolicyEngine::new();

        let (single_ops, mut samples) = run_single(&engine, &repo, &ctx);
        samples.sort_unstable();
        eprintln!(
            "[{size:>4} grants] single: {single_ops:>12.0} ops/s | p50={}ns p90={}ns p99={}ns p999={}ns",
            percentile(&samples, 0.50),
            percentile(&samples, 0.90),
            percentile(&samples, 0.99),
            percentile(&samples, 0.999),
        );

        for threads in [2usize, 4, 10] {
            let (wall, mut tail, done) = run_threads(&engine, &repo, &ctx, threads);
            tail.sort_unstable();
            let aggregate = done as f64 / wall.as_secs_f64();
            let efficiency = aggregate / (single_ops * threads as f64) * 100.0;
            let busy_cores = threads as f64 * efficiency / 100.0;
            eprintln!(
                "[{size:>4} grants] x{threads:>2}: {aggregate:>12.0} ops/s | scaling {efficiency:>5.1}% (~{busy_cores:.1} cores busy) | p99={}ns",
                percentile(&tail, 0.99),
            );
        }

        // 每操作分配归因（单线程、计数仅在本阶段开启）：读取面 vs 完整判定。
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let alloc_ops = 20_000usize;
        let scope = PublishedCardEvidenceScope {
            tenant_id: 7,
            card_id: 1,
            user_filter: None,
            domain: astral_types::DomainScopeRequirement::Unconstrained,
        };
        COUNTING.store(true, Ordering::Relaxed);
        ALLOCS.store(0, Ordering::Relaxed);
        ALLOC_BYTES.store(0, Ordering::Relaxed);
        for _ in 0..alloc_ops {
            let _ = rt.block_on(repo.load_published_card_authorization(&scope));
        }
        let load_allocs = ALLOCS.load(Ordering::Relaxed) as f64 / alloc_ops as f64;
        ALLOCS.store(0, Ordering::Relaxed);
        ALLOC_BYTES.store(0, Ordering::Relaxed);
        for _ in 0..alloc_ops {
            let _ = rt.block_on(engine.evaluate(&ctx, &repo));
        }
        let eval_allocs = ALLOCS.load(Ordering::Relaxed) as f64 / alloc_ops as f64;
        let eval_bytes = ALLOC_BYTES.load(Ordering::Relaxed) as f64 / alloc_ops as f64;
        COUNTING.store(false, Ordering::Relaxed);
        // 归因二分：合同校验（validate）单独的耗时与分配。
        let va = Instant::now();
        COUNTING.store(true, Ordering::Relaxed);
        ALLOCS.store(0, Ordering::Relaxed);
        for _ in 0..alloc_ops {
            let _ = repo.evidence.validate();
        }
        let validate_allocs = ALLOCS.load(Ordering::Relaxed) as f64 / alloc_ops as f64;
        COUNTING.store(false, Ordering::Relaxed);
        let validate_ns = va.elapsed().as_nanos() as f64 / alloc_ops as f64;
        eprintln!(
            "[{size:>4} grants] validate alone: {validate_ns:.0} ns, {validate_allocs:.1} allocs"
        );
        eprintln!(
            "[{size:>4} grants] per-op: read-face {load_allocs:.1} | evaluate {eval_allocs:.1} allocs / {eval_bytes:.0} bytes (engine-side ~{:.1})",
            eval_allocs - load_allocs
        );
    }
}
