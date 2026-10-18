use super::*;
use astral_types::{PolicyContext, PolicyDecision};
use policy_engine::PolicyEngine;
use std::hint::black_box;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Barrier;

mod controls;
mod fixture;

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

fn measure(
    engine: &PolicyEngine,
    base: &MemoryProjectionHub,
    clock: EvidenceClock,
    ctx: &PolicyContext,
    expected: &PolicyDecision,
    threads: usize,
    per_thread: usize,
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
    let ticks = AtomicI64::new(FIXED_SECOND + 100);
    let barrier = Barrier::new(threads + 1);
    let expected_reads = if expected.allowed { 2 } else { 1 };
    let runtimes: Vec<_> = (0..threads).map(|_| runtime()).collect();
    let mut latencies = Vec::with_capacity(threads * per_thread);
    let mut counts = ReadCounts::default();
    let mut allowed = 0;
    let mut denied = 0;
    let mut pending = 0;
    let mut mismatches = 0;
    let wall_ns = std::thread::scope(|workers| {
        let mut handles = Vec::with_capacity(threads);
        for runtime in runtimes {
            let hub = &hub;
            let ticks = &ticks;
            let barrier = &barrier;
            handles.push(workers.spawn(move || {
                let repo = EvaluationProbe::new(hub, clock, ticks);
                let mut latencies = Vec::with_capacity(per_thread);
                let mut allowed = 0;
                let mut denied = 0;
                let mut pending = 0;
                let mut mismatches = 0;
                barrier.wait();
                runtime.block_on(async {
                    for _ in 0..per_thread {
                        repo.begin_decision();
                        let started = Instant::now();
                        let decision = black_box(engine)
                            .evaluate(black_box(ctx), black_box(&repo))
                            .await;
                        let nanos = u64::try_from(started.elapsed().as_nanos()).unwrap();
                        latencies.push(nanos);
                        assert_eq!(repo.decision_reads(), expected_reads);
                        allowed += usize::from(decision.allowed);
                        denied += usize::from(decision.reason == "DEFAULT_DENY");
                        pending += usize::from(decision.reason == "AUTHORIZATION_PENDING");
                        mismatches += usize::from(!decisions_match(&decision, expected));
                        black_box(decision);
                    }
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
                (latencies, counts, allowed, denied, pending, mismatches)
            }));
        }
        let started = Instant::now();
        barrier.wait();
        for handle in handles {
            let (worker_latencies, worker_counts, a, d, p, m) = handle.join().unwrap();
            latencies.extend(worker_latencies);
            counts.add(worker_counts);
            allowed += a;
            denied += d;
            pending += p;
            mismatches += m;
        }
        u64::try_from(started.elapsed().as_nanos()).unwrap()
    });
    let hits = hub.assemblies.hits() - hits_before;
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
    }
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
                "evidencePort": "owned PublishedCardAuthorization; Arc is internal to assembly cache",
                "fixture": "synthetic verified publication; perpetual scoped grants; one card",
                "cardPort": "checked fixture PLATFORM_USER identity18/user42/card17/tenant7/domain11",
                "resourceOwnership": "server-classified fixture TenantScoped tenant7/domain11",
                "orgPort": "fixture Unmanaged; managed ORG_SCOPE not measured",
                "engine": "same shared engine across all arms of a case; real stats and breaker overhead retained",
                "cached": "fixed validity second; actual one-second cache TTL retained; both ALLOW reads hit",
                "forced": "unique second per read; same production miss assembly, refill and token recheck",
                "production": "actual UTC seconds and actual cache TTL; misses counted",
                "readCounter": "equal shared tick cost in all arms; phase counts are per-worker, not ArcSwap statistics",
                "latency": "Instant around evaluate call to awaited PolicyDecision return; result checks and drop excluded",
                "throughput": "wall includes barrier wake, result checks/storage/drop and joins; thread/runtime construction and cache prewarm excluded",
                "order": "all six arm permutations repeated three times; no outlier trimming",
                "scopeExclusions": "no socket, MySQL identity/eligibility/ORG reads, signature, audit delivery, SDK, downstream handler or allocation measurement",
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
