use super::*;
use astral_types::{PolicyContext, PolicyDecision};
#[cfg(feature = "performance-attribution")]
use policy_engine::AttributionBreakdown;
use policy_engine::PolicyEngine;
use std::hint::black_box;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Barrier;

pub(crate) mod controls;
pub(crate) mod fixture;

use fixture::*;

const SAMPLES: usize = 18;
const SIZES: [u16; 5] = [1, 8, 128, 512, 2_048];
const THREADS: [usize; 3] = [1, 4, 8];
const OUTCOMES: [&str; 3] = ["allow-first", "allow-last", "deny"];
const ARMS: [&str; 3] = ["cached-fixed-second", "forced-assembly", "production-clock"];
const ORDERS: [[usize; 3]; 6] = [
    [0, 1, 2],
    [1, 2, 0],
    [2, 0, 1],
    [0, 2, 1],
    [2, 1, 0],
    [1, 0, 2],
];

#[cfg(feature = "performance-attribution")]
mod allocation_attribution {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    static COUNTING: AtomicBool = AtomicBool::new(false);
    static ALLOCS: AtomicU64 = AtomicU64::new(0);
    static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);

    pub struct CountingAllocator;

    unsafe impl GlobalAlloc for CountingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            if COUNTING.load(Ordering::Relaxed) {
                ALLOCS.fetch_add(1, Ordering::Relaxed);
                ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
            }
            System.alloc(layout)
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            System.dealloc(pointer, layout);
        }

        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            if COUNTING.load(Ordering::Relaxed) {
                ALLOCS.fetch_add(1, Ordering::Relaxed);
                ALLOC_BYTES.fetch_add(size as u64, Ordering::Relaxed);
            }
            System.realloc(pointer, layout, size)
        }
    }

    #[global_allocator]
    static GLOBAL: CountingAllocator = CountingAllocator;

    pub fn begin() {
        COUNTING.store(false, Ordering::Relaxed);
        ALLOCS.store(0, Ordering::Relaxed);
        ALLOC_BYTES.store(0, Ordering::Relaxed);
        COUNTING.store(true, Ordering::Relaxed);
    }

    pub fn end() -> (u64, u64) {
        COUNTING.store(false, Ordering::Relaxed);
        (
            ALLOCS.load(Ordering::Relaxed),
            ALLOC_BYTES.load(Ordering::Relaxed),
        )
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct Measurement {
    decisions: usize,
    wall_ns: u64,
    latency_ns: Vec<u64>,
    #[serde(flatten)]
    reads: ReadCounts,
    cache_hits: usize,
    allowed: usize,
    denied: usize,
    pending: usize,
    mismatches: usize,
    legacy_reads: usize,
    #[cfg(feature = "performance-attribution")]
    #[serde(skip_serializing_if = "Option::is_none")]
    attribution: Option<AttributionMeasurement>,
}

#[cfg(feature = "performance-attribution")]
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct AttributionMeasurement {
    engine_timing_ns: AttributionBreakdown,
    assembly_cache: AssemblyCacheMeasurement,
    allocation: AllocationMeasurement,
}

#[cfg(feature = "performance-attribution")]
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct AllocationMeasurement {
    allocation_count: u64,
    allocation_bytes: u64,
    scope: &'static str,
}

#[cfg(feature = "performance-attribution")]
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct AssemblyCacheMeasurement {
    hits: usize,
    misses: usize,
    arc_clones: usize,
    get_lock_wait_ns: u64,
    insert_lock_wait_ns: u64,
}

#[cfg(feature = "performance-attribution")]
type AttributionAccumulator = Option<AttributionBreakdown>;
#[cfg(not(feature = "performance-attribution"))]
type AttributionAccumulator = Option<()>;

fn new_attribution_accumulator(enabled: bool) -> AttributionAccumulator {
    #[cfg(feature = "performance-attribution")]
    {
        enabled.then(AttributionBreakdown::default)
    }
    #[cfg(not(feature = "performance-attribution"))]
    {
        let _ = enabled;
        None
    }
}

fn begin_attribution_if_enabled(enabled: bool) {
    #[cfg(feature = "performance-attribution")]
    if enabled {
        policy_engine::begin_evaluation_attribution();
    }
    #[cfg(not(feature = "performance-attribution"))]
    let _ = enabled;
}

fn finish_attribution_if_enabled(accumulator: &mut AttributionAccumulator, enabled: bool) {
    #[cfg(feature = "performance-attribution")]
    if enabled {
        accumulator
            .as_mut()
            .expect("enabled attribution accumulator")
            .add_assign(&policy_engine::take_evaluation_attribution());
    }
    #[cfg(not(feature = "performance-attribution"))]
    {
        let _ = (accumulator, enabled);
    }
}

#[cfg(feature = "performance-attribution")]
fn begin_allocation_attribution(enabled: bool) {
    if enabled {
        allocation_attribution::begin();
    }
}

#[cfg(not(feature = "performance-attribution"))]
fn begin_allocation_attribution(_enabled: bool) {}

#[cfg(feature = "performance-attribution")]
fn finish_allocation_attribution(enabled: bool) -> (u64, u64) {
    if enabled {
        allocation_attribution::end()
    } else {
        (0, 0)
    }
}

#[cfg(not(feature = "performance-attribution"))]
fn finish_allocation_attribution(_enabled: bool) -> (u64, u64) {
    (0, 0)
}

fn merge_attribution(
    total: &mut AttributionAccumulator,
    worker: AttributionAccumulator,
    enabled: bool,
) {
    #[cfg(feature = "performance-attribution")]
    if enabled {
        total
            .as_mut()
            .expect("enabled attribution accumulator")
            .add_assign(&worker.expect("worker attribution accumulator"));
    }
    #[cfg(not(feature = "performance-attribution"))]
    {
        let _ = (total, worker, enabled);
    }
}

fn decisions_per_thread(size: u16) -> usize {
    match size {
        1 | 8 => 256,
        128 => 96,
        512 => 32,
        2_048 => 16,
        _ => unreachable!(),
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn measure(
    engine: &PolicyEngine,
    base: &MemoryProjectionHub,
    clock: EvidenceClock,
    ctx: &PolicyContext,
    expected: &PolicyDecision,
    threads: usize,
    per_thread: usize,
    capture_attribution: bool,
) -> Measurement {
    let hub = MemoryProjectionHub {
        assemblies: Arc::new(AssemblyCache::default()),
        ..base.clone()
    };
    let warm_runtime = runtime();
    let warm_clock = match clock {
        EvidenceClock::Forced => EvidenceClock::Cached,
        other => other,
    };
    for _ in 0..4 {
        let (decision, _) = warm_runtime.block_on(checked_decision(
            engine,
            &hub,
            warm_clock,
            ctx.target_id.unwrap(),
        ));
        assert!(decisions_match(&decision, expected));
    }
    let hits_before = hub.assemblies.hits();
    #[cfg(feature = "performance-attribution")]
    let assembly_before = capture_attribution.then(|| hub.assemblies.attribution());
    let ticks = AtomicI64::new(FIXED_SECOND + 100);
    let ready_barrier = Barrier::new(threads + 1);
    let start_barrier = Barrier::new(threads + 1);
    let done_barrier = Barrier::new(threads + 1);
    let expected_reads = if expected.allowed { 2 } else { 1 };
    let runtimes: Vec<_> = (0..threads).map(|_| runtime()).collect();
    let mut latencies = Vec::with_capacity(threads * per_thread);
    let mut counts = ReadCounts::default();
    let mut allowed = 0;
    let mut denied = 0;
    let mut pending = 0;
    let mut mismatches = 0;
    let mut attribution = new_attribution_accumulator(capture_attribution);
    let (wall_ns, allocation) = std::thread::scope(|workers| {
        let mut handles = Vec::with_capacity(threads);
        for runtime in runtimes {
            let hub = &hub;
            let ticks = &ticks;
            let ready_barrier = &ready_barrier;
            let start_barrier = &start_barrier;
            let done_barrier = &done_barrier;
            handles.push(workers.spawn(move || {
                let repo = EvaluationProbe::new(hub, clock, ticks);
                let mut latencies = Vec::with_capacity(per_thread);
                let mut allowed = 0;
                let mut denied = 0;
                let mut pending = 0;
                let mut mismatches = 0;
                ready_barrier.wait();
                start_barrier.wait();
                let worker_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let worker_attribution = runtime.block_on(async {
                        let mut worker_attribution =
                            new_attribution_accumulator(capture_attribution);
                        for _ in 0..per_thread {
                            repo.begin_decision();
                            begin_attribution_if_enabled(capture_attribution);
                            let started = Instant::now();
                            let decision = black_box(engine)
                                .evaluate(black_box(ctx), black_box(&repo))
                                .await;
                            finish_attribution_if_enabled(
                                &mut worker_attribution,
                                capture_attribution,
                            );
                            let nanos = u64::try_from(started.elapsed().as_nanos()).unwrap();
                            latencies.push(nanos);
                            assert_eq!(repo.decision_reads(), expected_reads);
                            allowed += usize::from(decision.allowed);
                            denied += usize::from(decision.reason == "DEFAULT_DENY");
                            pending += usize::from(decision.reason == "AUTHORIZATION_PENDING");
                            mismatches += usize::from(!decisions_match(&decision, expected));
                            black_box(decision);
                        }
                        worker_attribution
                    });
                    let counts = repo.counts();
                    assert_eq!(counts.card_checks, per_thread);
                    assert_eq!(counts.org_reads, per_thread);
                    assert_eq!(counts.evidence_reads, per_thread * expected_reads);
                    assert_eq!(counts.scoped_reads, counts.evidence_reads);
                    assert_eq!(allowed, usize::from(expected.allowed) * per_thread);
                    assert_eq!(denied, usize::from(!expected.allowed) * per_thread);
                    assert_eq!(pending, 0);
                    assert_eq!(mismatches, 0);
                    (
                        latencies,
                        counts,
                        allowed,
                        denied,
                        pending,
                        mismatches,
                        worker_attribution,
                    )
                }));
                done_barrier.wait();
                match worker_result {
                    Ok(result) => result,
                    Err(payload) => std::panic::resume_unwind(payload),
                }
            }));
        }
        let started = Instant::now();
        ready_barrier.wait();
        begin_allocation_attribution(capture_attribution);
        start_barrier.wait();
        done_barrier.wait();
        let allocation = finish_allocation_attribution(capture_attribution);
        for handle in handles {
            let (worker_latencies, worker_counts, a, d, p, m, worker_attribution) =
                handle.join().unwrap();
            latencies.extend(worker_latencies);
            counts.add(worker_counts);
            allowed += a;
            denied += d;
            pending += p;
            mismatches += m;
            merge_attribution(&mut attribution, worker_attribution, capture_attribution);
        }
        (
            u64::try_from(started.elapsed().as_nanos()).unwrap(),
            allocation,
        )
    });
    #[cfg(not(feature = "performance-attribution"))]
    let _ = allocation;
    let hits = hub.assemblies.hits() - hits_before;
    #[cfg(feature = "performance-attribution")]
    let assembly_after = capture_attribution.then(|| hub.assemblies.attribution());
    #[cfg(feature = "performance-attribution")]
    let cache_delta = assembly_before.zip(assembly_after).map(|(before, after)| {
        (
            after.0.saturating_sub(before.0),
            after.1.saturating_sub(before.1),
            after.2.saturating_sub(before.2),
            after.3.saturating_sub(before.3),
            after.4.saturating_sub(before.4),
        )
    });
    match clock {
        EvidenceClock::Cached => assert_eq!(
            hits, counts.evidence_reads,
            "warm TTL expired during measurement"
        ),
        EvidenceClock::Forced => assert_eq!(hits, 0, "forced assembly unexpectedly hit the cache"),
        EvidenceClock::Production => assert!(hits <= counts.evidence_reads),
        _ => unreachable!(),
    }
    assert!(ticks.load(Ordering::Relaxed) > FIXED_SECOND + 100);
    assert!(counts.initial_evidence_ns > 0);
    assert_eq!(counts.final_evidence_ns > 0, expected.allowed);
    assert!(counts.initial_evidence_ns + counts.final_evidence_ns <= latencies.iter().sum());
    assert!(wall_ns >= *latencies.iter().max().unwrap());
    Measurement {
        decisions: threads * per_thread,
        wall_ns,
        latency_ns: latencies,
        reads: counts,
        cache_hits: hits,
        allowed,
        denied,
        pending,
        mismatches,
        legacy_reads: 0,
        #[cfg(feature = "performance-attribution")]
        attribution: capture_attribution.then(|| {
            let cache_delta = cache_delta.expect("enabled cache attribution");
            AttributionMeasurement {
                engine_timing_ns: attribution.expect("enabled engine attribution").clone(),
                assembly_cache: AssemblyCacheMeasurement {
                    hits: cache_delta.0,
                    misses: cache_delta.1,
                    arc_clones: cache_delta.2,
                    get_lock_wait_ns: cache_delta.3,
                    insert_lock_wait_ns: cache_delta.4,
                },
                allocation: AllocationMeasurement {
                    allocation_count: allocation.0,
                    allocation_bytes: allocation.1,
                    scope: "process-global measured loop; not evidence-copy or Arc-drop count",
                },
            }
        }),
    }
}

#[cfg(feature = "performance-attribution")]
#[test]
#[ignore = "instrumented CPU-only evaluate attribution matrix; requires --release and performance-attribution"]
fn policy_evaluate_attribution_matrix() {
    if cfg!(debug_assertions) {
        panic!("evaluate attribution measurements require --release");
    }
    let runtime = runtime();
    runtime.block_on(controls::verify_controls());
    println!(
        "\nEVALUATE_ATTRIBUTION_META {}",
        serde_json::json!({
            "schema": "policy-evaluate-attribution-v1",
            "scope": "policy-engine-evaluate-cpu",
            "samplesPerCase": SAMPLES,
            "grantSizes": SIZES,
            "threads": THREADS,
            "outcomes": OUTCOMES,
            "arms": ARMS,
            "timing": "evaluate-call-return-with-attribution",
            "debugAssertions": cfg!(debug_assertions),
            "controls": {
                "ownedEvidenceParity": true,
                "decisionParity": true,
                "allowTwoReads": true,
                "denyOneRead": true,
                "pendingOneRead": true,
                "crossSecondExpiry": true,
                "finalRevokeRefusal": true,
                "noLegacyReads": true,
                "phaseAttribution": true,
                "assemblyCacheAttribution": true,
                "allocatorObservation": true,
            },
            "premises": {
                "entry": "PolicyEngine.evaluate",
                "evidencePort": "Arc<PublishedCardAuthorization>; assembly/mirror cache hits reuse immutable evidence, forced assembly creates a fresh Arc",
                "fixture": "synthetic verified publication; perpetual scoped grants; one card",
                "cardPort": "checked fixture PLATFORM_USER identity18/user42/card17/tenant7/domain11",
                "resourceOwnership": "server-classified fixture TenantScoped tenant7/domain11",
                "orgPort": "fixture Unmanaged; managed ORG_SCOPE not measured",
                "engine": "same shared engine across all arms of a case; real stats and breaker overhead retained",
                "matcher": "large evidence uses a thread-local four-slot Arc-identity index; each worker must warm first-seen/build/hit independently",
                "cached": "fixed validity second; actual one-second cache TTL retained; both ALLOW reads hit",
                "forced": "warm mirror; unique second per read forces assembly miss, produces fresh Arc evidence, refill and token recheck",
                "production": "actual UTC seconds and actual cache TTL; misses counted",
                "readCounter": "equal shared tick cost in all arms; phase counts are per-worker, not ArcSwap statistics",
                "latency": "Instant around evaluate call to awaited PolicyDecision return; result checks and drop excluded",
                "throughput": "instrumented wall includes barrier wake, result checks/storage/drop and joins; it is not the formal throughput measurement",
                "order": "all six arm permutations repeated three times; no outlier trimming",
                "scopeExclusions": "no socket, MySQL identity/eligibility/ORG reads, signature, audit delivery, SDK, downstream handler, or cold mirror invalidation; allocator data is process-global measured-loop observation, not evidence-copy or Arc-drop count",
            },
        })
    );
    let clocks = [
        EvidenceClock::Cached,
        EvidenceClock::Forced,
        EvidenceClock::Production,
    ];
    let mut cases = 0;
    for size in SIZES {
        let (hub, targets) = fixture(size);
        for threads in THREADS {
            for outcome in OUTCOMES {
                let engine = PolicyEngine::new();
                let target = match outcome {
                    "allow-first" => targets[0],
                    "allow-last" => targets[1],
                    "deny" => 999_999,
                    _ => unreachable!(),
                };
                let ctx = context(target);
                let (expected, _) = runtime.block_on(checked_decision(
                    &engine,
                    &hub,
                    EvidenceClock::Cached,
                    target,
                ));
                assert_eq!(expected.allowed, outcome != "deny");
                assert_eq!(
                    expected.reason,
                    if expected.allowed {
                        "PUBLISHED_EVIDENCE_ALLOW"
                    } else {
                        "DEFAULT_DENY"
                    }
                );
                let per_thread = decisions_per_thread(size);
                let mut samples = Vec::with_capacity(SAMPLES);
                for index in 0..SAMPLES {
                    let order = ORDERS[index % ORDERS.len()];
                    let mut measurements = serde_json::Map::new();
                    for arm in order {
                        let measurement = measure(
                            &engine,
                            &hub,
                            clocks[arm],
                            &ctx,
                            &expected,
                            threads,
                            per_thread,
                            true,
                        );
                        assert_eq!(
                            measurement.reads.evidence_grants,
                            measurement.reads.evidence_reads * usize::from(size)
                        );
                        assert!(measurement.attribution.is_some());
                        measurements.insert(
                            ARMS[arm].to_owned(),
                            serde_json::to_value(measurement).unwrap(),
                        );
                    }
                    samples.push(serde_json::json!({
                        "index": index,
                        "order": order.map(|arm| ARMS[arm]),
                        "measurements": measurements,
                    }));
                }
                cases += 1;
                println!(
                    "\nEVALUATE_ATTRIBUTION_CASE {}",
                    serde_json::json!({
                        "case": format!("evaluate/{size}/threads-{threads}/{outcome}"),
                        "grants": size,
                        "threads": threads,
                        "outcome": outcome,
                        "decisionsPerThread": per_thread,
                        "samples": samples,
                    })
                );
            }
        }
    }
    assert_eq!(cases, 45);
    println!(
        "\nEVALUATE_ATTRIBUTION_END {}",
        serde_json::json!({
            "schema": "policy-evaluate-attribution-v1",
            "status": "PASS",
            "cases": cases,
            "samples": cases * SAMPLES,
            "measurements": cases * SAMPLES * ARMS.len(),
            "postconditions": {
                "workersJoined": true,
                "allDecisionsChecked": true,
                "allReadCountsChecked": true,
                "allAttributionCaptured": true,
            },
        })
    );
}

#[test]
#[ignore = "optimized CPU-only complete evaluate comparison; requires --release"]
fn policy_evaluate_complete_benefit_matrix() {
    if cfg!(debug_assertions) {
        panic!("whole-evaluate measurements require --release");
    }
    let runtime = runtime();
    runtime.block_on(controls::verify_controls());
    println!(
        "\nEVALUATE_PERF_META {}",
        serde_json::json!({
            "schema": "policy-evaluate-benefit-v1",
            "scope": "policy-engine-evaluate-cpu",
            "samplesPerCase": SAMPLES,
            "grantSizes": SIZES,
            "threads": THREADS,
            "outcomes": OUTCOMES,
            "arms": ARMS,
            "timing": "evaluate-call-return",
            "debugAssertions": cfg!(debug_assertions),
            "controls": {
                "ownedEvidenceParity": true,
                "decisionParity": true,
                "allowTwoReads": true,
                "denyOneRead": true,
                "pendingOneRead": true,
                "crossSecondExpiry": true,
                "finalRevokeRefusal": true,
                "noLegacyReads": true,
            },
            "premises": {
                "entry": "PolicyEngine.evaluate",
                "evidencePort": "Arc<PublishedCardAuthorization>; assembly/mirror cache hits reuse immutable evidence, forced assembly creates a fresh Arc",
                "fixture": "synthetic verified publication; perpetual scoped grants; one card",
                "cardPort": "checked fixture PLATFORM_USER identity18/user42/card17/tenant7/domain11",
                "resourceOwnership": "server-classified fixture TenantScoped tenant7/domain11",
                "orgPort": "fixture Unmanaged; managed ORG_SCOPE not measured",
                "engine": "same shared engine across all arms of a case; real stats and breaker overhead retained",
                "matcher": "large evidence uses a thread-local four-slot Arc-identity index; each worker must warm first-seen/build/hit independently",
                "cached": "fixed validity second; actual one-second cache TTL retained; both ALLOW reads hit",
                "forced": "warm mirror; unique second per read forces assembly miss, produces fresh Arc evidence, refill and token recheck",
                "production": "actual UTC seconds and actual cache TTL; misses counted",
                "readCounter": "equal shared tick cost in all arms; phase counts are per-worker, not ArcSwap statistics",
                "latency": "Instant around evaluate call to awaited PolicyDecision return; result checks and drop excluded",
                "throughput": "wall includes barrier wake, result checks/storage/drop and joins; thread/runtime construction and cache prewarm excluded",
                "order": "all six arm permutations repeated three times; no outlier trimming",
                "scopeExclusions": "no socket, MySQL identity/eligibility/ORG reads, signature, audit delivery, SDK, downstream handler, or allocation measurement; cold mirror invalidation is not measured",
            },
        })
    );
    let clocks = [
        EvidenceClock::Cached,
        EvidenceClock::Forced,
        EvidenceClock::Production,
    ];
    let mut cases = 0;
    for size in SIZES {
        let (hub, targets) = fixture(size);
        for threads in THREADS {
            for outcome in OUTCOMES {
                let engine = PolicyEngine::new();
                let target = match outcome {
                    "allow-first" => targets[0],
                    "allow-last" => targets[1],
                    "deny" => 999_999,
                    _ => unreachable!(),
                };
                let ctx = context(target);
                let (expected, _) = runtime.block_on(checked_decision(
                    &engine,
                    &hub,
                    EvidenceClock::Cached,
                    target,
                ));
                assert_eq!(expected.allowed, outcome != "deny");
                assert_eq!(
                    expected.reason,
                    if expected.allowed {
                        "PUBLISHED_EVIDENCE_ALLOW"
                    } else {
                        "DEFAULT_DENY"
                    }
                );
                let per_thread = decisions_per_thread(size);
                let mut samples = Vec::with_capacity(SAMPLES);
                for index in 0..SAMPLES {
                    let order = ORDERS[index % ORDERS.len()];
                    let mut measurements = serde_json::Map::new();
                    for arm in order {
                        let measurement = measure(
                            &engine,
                            &hub,
                            clocks[arm],
                            &ctx,
                            &expected,
                            threads,
                            per_thread,
                            false,
                        );
                        assert_eq!(
                            measurement.reads.evidence_grants,
                            measurement.reads.evidence_reads * usize::from(size)
                        );
                        measurements.insert(
                            ARMS[arm].to_owned(),
                            serde_json::to_value(measurement).unwrap(),
                        );
                    }
                    samples.push(serde_json::json!({
                        "index": index,
                        "order": order.map(|arm| ARMS[arm]),
                        "measurements": measurements,
                    }));
                }
                cases += 1;
                println!(
                    "\nEVALUATE_PERF_CASE {}",
                    serde_json::json!({
                        "case": format!("evaluate/{size}/threads-{threads}/{outcome}"),
                        "grants": size,
                        "threads": threads,
                        "outcome": outcome,
                        "decisionsPerThread": per_thread,
                        "samples": samples,
                    })
                );
            }
        }
    }
    assert_eq!(cases, 45);
    println!(
        "\nEVALUATE_PERF_END {}",
        serde_json::json!({
            "schema": "policy-evaluate-benefit-v1",
            "status": "PASS",
            "cases": cases,
            "samples": cases * SAMPLES,
            "measurements": cases * SAMPLES * ARMS.len(),
            "postconditions": {
                "workersJoined": true,
                "allDecisionsChecked": true,
                "allReadCountsChecked": true,
            },
        })
    );
}
