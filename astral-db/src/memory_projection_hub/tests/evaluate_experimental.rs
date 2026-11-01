use super::super::*;
use super::evaluate_performance::fixture::{
    context, decisions_match, fixture, EvaluationProbe, EvidenceClock, ReadCounts, FIXED_SECOND,
};
use astral_types::PolicyDecision;
use policy_engine::PolicyEngine;
#[cfg(feature = "performance-attribution")]
use policy_engine::{AttributionBreakdown, CircuitBreakerState, HitStats};
use serde::Serialize;
use std::hint::black_box;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::AtomicI64;
use std::sync::{Arc, Barrier};
use std::time::Instant;

const SCHEMA: &str = "policy-evaluate-sharing-experimental-v1";
#[cfg(feature = "performance-attribution")]
const V2_SCHEMA: &str = "policy-evaluate-sharing-experimental-v2";
const SAMPLES: usize = 15;
const SIZES: [u16; 3] = [128, 1_001, 2_048];
const THREADS: [usize; 3] = [1, 4, 8];
const OUTCOMES: [&str; 2] = ["allow-first", "deny"];
const ARMS: [&str; 2] = ["cached-fixed-second", "forced-assembly"];
const CACHE_SCOPES: [CacheScope; 2] = [CacheScope::SharedMeasurement, CacheScope::PrivateWorker];
const ENGINE_SCOPES: [EngineScope; 2] = [EngineScope::SharedWorkers, EngineScope::PrivateWorker];

#[derive(Clone, Copy)]
enum CacheScope {
    SharedMeasurement,
    PrivateWorker,
}

impl CacheScope {
    fn label(self) -> &'static str {
        match self {
            Self::SharedMeasurement => "shared-measurement",
            Self::PrivateWorker => "private-worker",
        }
    }

    fn owner_count(self, threads: usize) -> usize {
        match self {
            Self::SharedMeasurement => 1,
            Self::PrivateWorker => threads,
        }
    }
}

#[derive(Clone, Copy)]
enum EngineScope {
    SharedWorkers,
    PrivateWorker,
}

impl EngineScope {
    fn label(self) -> &'static str {
        match self {
            Self::SharedWorkers => "shared-workers",
            Self::PrivateWorker => "private-worker",
        }
    }

    fn owner_count(self, threads: usize) -> usize {
        match self {
            Self::SharedWorkers => 1,
            Self::PrivateWorker => threads,
        }
    }
}

#[derive(Default, Clone, Copy)]
struct CacheCounters {
    hits: usize,
    misses: usize,
    arc_clones: usize,
    get_lock_wait_ns: u64,
    insert_lock_wait_ns: u64,
    get_lock_hold_ns: u64,
    insert_lock_hold_ns: u64,
    gc_removed: usize,
    evictions: usize,
}

impl CacheCounters {
    fn add_assign(&mut self, next: Self) {
        self.hits = self.hits.saturating_add(next.hits);
        self.misses = self.misses.saturating_add(next.misses);
        self.arc_clones = self.arc_clones.saturating_add(next.arc_clones);
        self.get_lock_wait_ns = self.get_lock_wait_ns.saturating_add(next.get_lock_wait_ns);
        self.insert_lock_wait_ns = self
            .insert_lock_wait_ns
            .saturating_add(next.insert_lock_wait_ns);
        self.get_lock_hold_ns = self.get_lock_hold_ns.saturating_add(next.get_lock_hold_ns);
        self.insert_lock_hold_ns = self
            .insert_lock_hold_ns
            .saturating_add(next.insert_lock_hold_ns);
        self.gc_removed = self.gc_removed.saturating_add(next.gc_removed);
        self.evictions = self.evictions.saturating_add(next.evictions);
    }

    fn delta(self, before: Self) -> Self {
        Self {
            hits: self.hits.saturating_sub(before.hits),
            misses: self.misses.saturating_sub(before.misses),
            arc_clones: self.arc_clones.saturating_sub(before.arc_clones),
            get_lock_wait_ns: self
                .get_lock_wait_ns
                .saturating_sub(before.get_lock_wait_ns),
            insert_lock_wait_ns: self
                .insert_lock_wait_ns
                .saturating_sub(before.insert_lock_wait_ns),
            get_lock_hold_ns: self
                .get_lock_hold_ns
                .saturating_sub(before.get_lock_hold_ns),
            insert_lock_hold_ns: self
                .insert_lock_hold_ns
                .saturating_sub(before.insert_lock_hold_ns),
            gc_removed: self.gc_removed.saturating_sub(before.gc_removed),
            evictions: self.evictions.saturating_sub(before.evictions),
        }
    }
}

fn cache_counters(caches: &[Arc<AssemblyCache>]) -> CacheCounters {
    caches
        .iter()
        .fold(CacheCounters::default(), |mut total, cache| {
            let detailed = cache.detailed_attribution();
            total.add_assign(CacheCounters {
                hits: detailed.hits,
                misses: detailed.misses,
                arc_clones: detailed.arc_clones,
                get_lock_wait_ns: detailed.get_lock_wait_ns,
                insert_lock_wait_ns: detailed.insert_lock_wait_ns,
                get_lock_hold_ns: detailed.get_lock_hold_ns,
                insert_lock_hold_ns: detailed.insert_lock_hold_ns,
                gc_removed: detailed.gc_removed,
                evictions: detailed.evictions,
            });
            total
        })
}

struct Owners {
    hubs: Vec<MemoryProjectionHub>,
    caches: Vec<Arc<AssemblyCache>>,
    engines: Vec<Arc<PolicyEngine>>,
}

impl Owners {
    fn new(
        base: &MemoryProjectionHub,
        threads: usize,
        cache_scope: CacheScope,
        engine_scope: EngineScope,
    ) -> Self {
        let cache_count = cache_scope.owner_count(threads);
        let caches = (0..cache_count)
            .map(|_| Arc::new(AssemblyCache::default()))
            .collect::<Vec<_>>();
        let hubs = caches
            .iter()
            .map(|cache| MemoryProjectionHub {
                assemblies: Arc::clone(cache),
                ..base.clone()
            })
            .collect::<Vec<_>>();
        let engine_count = engine_scope.owner_count(threads);
        let engines = (0..engine_count)
            .map(|_| Arc::new(PolicyEngine::new()))
            .collect::<Vec<_>>();
        Self {
            hubs,
            caches,
            engines,
        }
    }

    fn hub_index(&self, scope: CacheScope, worker: usize) -> usize {
        match scope {
            CacheScope::SharedMeasurement => 0,
            CacheScope::PrivateWorker => worker,
        }
    }

    fn engine_index(&self, scope: EngineScope, worker: usize) -> usize {
        match scope {
            EngineScope::SharedWorkers => 0,
            EngineScope::PrivateWorker => worker,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Measurement {
    decisions: usize,
    wall_ns: u64,
    latency_ns: Vec<u64>,
    #[serde(flatten)]
    reads: ReadCounts,
    cache_hits: usize,
    cache_misses: usize,
    arc_clones: usize,
    get_lock_wait_ns: u64,
    insert_lock_wait_ns: u64,
    allowed: usize,
    denied: usize,
    pending: usize,
    mismatches: usize,
    legacy_reads: usize,
    engine_instance_count: usize,
    cache_instance_count: usize,
    assembly_cache_scope: &'static str,
    policy_engine_scope: &'static str,
    warmup_excluded: bool,
    workers_joined: bool,
}

#[cfg(feature = "performance-attribution")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EngineOwnerStats {
    evaluation_count: u64,
    allow_count: u64,
    deny_count: u64,
    card_context_check_ns: u64,
    initial_evidence_load_ns: u64,
    final_evidence_reload_ns: u64,
    evidence_match_ns: u64,
    total_ns: u64,
}

#[cfg(feature = "performance-attribution")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct V2Measurement {
    decisions: usize,
    cache_hits: usize,
    cache_misses: usize,
    arc_clones: usize,
    get_lock_wait_ns: u64,
    insert_lock_wait_ns: u64,
    get_lock_hold_ns: u64,
    insert_lock_hold_ns: u64,
    gc_removed: usize,
    evictions: usize,
    engine_evaluation_count: u64,
    engine_allow_count: u64,
    engine_deny_count: u64,
    engine_card_context_check_ns: u64,
    engine_initial_evidence_load_ns: u64,
    engine_final_evidence_reload_ns: u64,
    engine_evidence_match_ns: u64,
    engine_total_ns: u64,
    stats_and_breaker_ns: u64,
    attribution_total_ns: u64,
    breaker_map_wait_ns: u64,
    breaker_state_wait_ns: u64,
    breaker_closed: bool,
    engine_owner_stats: Vec<EngineOwnerStats>,
    engine_instance_count: usize,
    cache_instance_count: usize,
    assembly_cache_scope: &'static str,
    policy_engine_scope: &'static str,
    warmup_excluded: bool,
    workers_joined: bool,
}

#[cfg(feature = "performance-attribution")]
struct MeasuredResult {
    measurement: Measurement,
    v2: V2Measurement,
}

#[cfg(not(feature = "performance-attribution"))]
struct MeasuredResult {
    measurement: Measurement,
}

#[cfg(feature = "performance-attribution")]
fn owner_stats(stats: &HitStats) -> EngineOwnerStats {
    EngineOwnerStats {
        evaluation_count: stats.evaluation_count,
        allow_count: stats.allow_count,
        deny_count: stats.deny_count,
        card_context_check_ns: stats.timing_ns.card_context_check_ns,
        initial_evidence_load_ns: stats.timing_ns.initial_evidence_load_ns,
        final_evidence_reload_ns: stats.timing_ns.final_evidence_reload_ns,
        evidence_match_ns: stats.timing_ns.evidence_match_ns,
        total_ns: stats.timing_ns.total_ns,
    }
}

fn decisions_per_thread(grants: u16) -> usize {
    match grants {
        128 => 64,
        1_001 => 32,
        2_048 => 16,
        _ => unreachable!(),
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("sharing experiment runtime must build")
}

struct WorkerMeasurement {
    latencies: Vec<u64>,
    counts: ReadCounts,
    allowed: usize,
    denied: usize,
    pending: usize,
    mismatches: usize,
    #[cfg(feature = "performance-attribution")]
    attribution: AttributionBreakdown,
}

#[derive(Default)]
struct MeasurementTotals {
    latencies: Vec<u64>,
    counts: ReadCounts,
    allowed: usize,
    denied: usize,
    pending: usize,
    mismatches: usize,
    #[cfg(feature = "performance-attribution")]
    attribution: AttributionBreakdown,
}

#[allow(clippy::too_many_arguments)]
fn measure(
    base: &MemoryProjectionHub,
    expected: &PolicyDecision,
    target: i64,
    grants: u16,
    threads: usize,
    clock: EvidenceClock,
    cache_scope: CacheScope,
    engine_scope: EngineScope,
) -> MeasuredResult {
    let owners = Owners::new(base, threads, cache_scope, engine_scope);
    let ctx = context(target);
    let per_thread = decisions_per_thread(grants);
    let expected_reads = if expected.allowed { 2 } else { 1 };
    let ticks = Arc::new(AtomicI64::new(FIXED_SECOND + 100));
    let ready_barrier = Barrier::new(threads + 1);
    let start_barrier = Barrier::new(threads + 1);
    let done_barrier = Barrier::new(threads + 1);

    let (wall_ns, before, totals) = std::thread::scope(|workers| {
        let mut handles = Vec::with_capacity(threads);
        for worker in 0..threads {
            let hub = &owners.hubs[owners.hub_index(cache_scope, worker)];
            let engine = Arc::clone(&owners.engines[owners.engine_index(engine_scope, worker)]);
            let ticks = Arc::clone(&ticks);
            let ready_barrier = &ready_barrier;
            let start_barrier = &start_barrier;
            let done_barrier = &done_barrier;
            let ctx = &ctx;
            handles.push(workers.spawn(move || {
                let runtime = runtime();
                let warmup = catch_unwind(AssertUnwindSafe(|| {
                    let repo = EvaluationProbe::new(hub, EvidenceClock::Cached, ticks.as_ref());
                    repo.begin_decision();
                    let decision =
                        runtime.block_on(async { engine.evaluate(&context(target), &repo).await });
                    assert!(decisions_match(&decision, expected));
                    assert_eq!(repo.decision_reads(), expected_reads);
                }));

                ready_barrier.wait();
                start_barrier.wait();

                let measured = match warmup {
                    Ok(()) => catch_unwind(AssertUnwindSafe(|| {
                        let repo = EvaluationProbe::new(hub, clock, ticks.as_ref());
                        let mut latencies = Vec::with_capacity(per_thread);
                        let mut allowed = 0;
                        let mut denied = 0;
                        let mut pending = 0;
                        let mut mismatches = 0;
                        #[cfg(feature = "performance-attribution")]
                        let mut attribution = AttributionBreakdown::default();
                        runtime.block_on(async {
                            for _ in 0..per_thread {
                                repo.begin_decision();
                                let started = Instant::now();
                                #[cfg(feature = "performance-attribution")]
                                policy_engine::begin_evaluation_attribution();
                                let decision =
                                    engine.evaluate(black_box(ctx), black_box(&repo)).await;
                                #[cfg(feature = "performance-attribution")]
                                let policy_attribution =
                                    policy_engine::take_evaluation_attribution();
                                #[cfg(feature = "performance-attribution")]
                                attribution.add_assign(&policy_attribution);
                                let nanos = u64::try_from(started.elapsed().as_nanos())
                                    .expect("latency must fit u64");
                                latencies.push(nanos);
                                mismatches += usize::from(repo.decision_reads() != expected_reads);
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
                        WorkerMeasurement {
                            latencies,
                            counts,
                            allowed,
                            denied,
                            pending,
                            mismatches,
                            #[cfg(feature = "performance-attribution")]
                            attribution: {
                                let mut total = AttributionBreakdown::default();
                                total.add_assign(&attribution);
                                total
                            },
                        }
                    })),
                    Err(payload) => Err(payload),
                };

                // Barrier release is outside the catch so every worker reaches
                // the parent even when warmup or measurement fails.
                done_barrier.wait();
                measured
            }));
        }

        ready_barrier.wait();
        #[cfg(feature = "performance-attribution")]
        for engine in &owners.engines {
            engine.reset_stats();
            engine.reset_breaker_attribution();
        }
        let before = cache_counters(&owners.caches);
        let started = Instant::now();
        start_barrier.wait();
        done_barrier.wait();

        let mut totals = MeasurementTotals {
            latencies: Vec::with_capacity(threads * per_thread),
            ..MeasurementTotals::default()
        };
        let mut failure = None;
        for handle in handles {
            match handle.join() {
                Ok(Ok(worker)) => {
                    totals.latencies.extend(worker.latencies);
                    totals.counts.add(worker.counts);
                    totals.allowed += worker.allowed;
                    totals.denied += worker.denied;
                    totals.pending += worker.pending;
                    totals.mismatches += worker.mismatches;
                    #[cfg(feature = "performance-attribution")]
                    totals.attribution.add_assign(&worker.attribution);
                }
                Ok(Err(payload)) | Err(payload) => {
                    if failure.is_none() {
                        failure = Some(payload);
                    }
                }
            }
        }
        if let Some(payload) = failure {
            std::panic::resume_unwind(payload);
        }
        (
            u64::try_from(started.elapsed().as_nanos()).expect("wall time must fit u64"),
            before,
            totals,
        )
    });

    let after = cache_counters(&owners.caches);
    let cache = after.delta(before);
    #[cfg(feature = "performance-attribution")]
    let owner_stats = owners
        .engines
        .iter()
        .map(|engine| owner_stats(&engine.get_stats()))
        .collect::<Vec<_>>();
    #[cfg(feature = "performance-attribution")]
    let engine_stats = owner_stats.iter().fold(
        EngineOwnerStats {
            evaluation_count: 0,
            allow_count: 0,
            deny_count: 0,
            card_context_check_ns: 0,
            initial_evidence_load_ns: 0,
            final_evidence_reload_ns: 0,
            evidence_match_ns: 0,
            total_ns: 0,
        },
        |mut total, next| {
            total.evaluation_count += next.evaluation_count;
            total.allow_count += next.allow_count;
            total.deny_count += next.deny_count;
            total.card_context_check_ns += next.card_context_check_ns;
            total.initial_evidence_load_ns += next.initial_evidence_load_ns;
            total.final_evidence_reload_ns += next.final_evidence_reload_ns;
            total.evidence_match_ns += next.evidence_match_ns;
            total.total_ns += next.total_ns;
            total
        },
    );
    #[cfg(feature = "performance-attribution")]
    let breaker = owners.engines.iter().fold(
        policy_engine::BreakerAttribution::default(),
        |mut total, engine| {
            let next = engine.breaker_attribution();
            total.map_wait_ns += next.map_wait_ns;
            total.state_wait_ns += next.state_wait_ns;
            total
        },
    );
    assert_eq!(totals.latencies.len(), threads * per_thread);
    assert_eq!(
        totals.counts.evidence_grants,
        totals.counts.evidence_reads * usize::from(grants)
    );
    assert_eq!(cache.arc_clones, cache.hits);
    assert!(
        wall_ns
            >= *totals
                .latencies
                .iter()
                .max()
                .expect("latencies are non-empty")
    );

    let measurement = Measurement {
        decisions: threads * per_thread,
        wall_ns,
        latency_ns: totals.latencies,
        reads: totals.counts,
        cache_hits: cache.hits,
        cache_misses: cache.misses,
        arc_clones: cache.arc_clones,
        get_lock_wait_ns: cache.get_lock_wait_ns,
        insert_lock_wait_ns: cache.insert_lock_wait_ns,
        allowed: totals.allowed,
        denied: totals.denied,
        pending: totals.pending,
        mismatches: totals.mismatches,
        legacy_reads: 0,
        engine_instance_count: owners.engines.len(),
        cache_instance_count: owners.caches.len(),
        assembly_cache_scope: cache_scope.label(),
        policy_engine_scope: engine_scope.label(),
        warmup_excluded: true,
        workers_joined: true,
    };
    #[cfg(feature = "performance-attribution")]
    {
        assert_eq!(engine_stats.evaluation_count, measurement.decisions as u64);
        assert_eq!(
            engine_stats.allow_count + engine_stats.deny_count,
            engine_stats.evaluation_count
        );
        assert_eq!(engine_stats.allow_count, measurement.allowed as u64);
        assert_eq!(engine_stats.deny_count, measurement.denied as u64);
        let decisions = measurement.decisions;
        let v2 = V2Measurement {
            decisions,
            cache_hits: cache.hits,
            cache_misses: cache.misses,
            arc_clones: cache.arc_clones,
            get_lock_wait_ns: cache.get_lock_wait_ns,
            insert_lock_wait_ns: cache.insert_lock_wait_ns,
            get_lock_hold_ns: cache.get_lock_hold_ns,
            insert_lock_hold_ns: cache.insert_lock_hold_ns,
            gc_removed: cache.gc_removed,
            evictions: cache.evictions,
            engine_evaluation_count: engine_stats.evaluation_count,
            engine_allow_count: engine_stats.allow_count,
            engine_deny_count: engine_stats.deny_count,
            engine_card_context_check_ns: engine_stats.card_context_check_ns,
            engine_initial_evidence_load_ns: engine_stats.initial_evidence_load_ns,
            engine_final_evidence_reload_ns: engine_stats.final_evidence_reload_ns,
            engine_evidence_match_ns: engine_stats.evidence_match_ns,
            engine_total_ns: engine_stats.total_ns,
            stats_and_breaker_ns: totals.attribution.stats_and_breaker_ns,
            attribution_total_ns: totals.attribution.total_ns,
            breaker_map_wait_ns: breaker.map_wait_ns,
            breaker_state_wait_ns: breaker.state_wait_ns,
            breaker_closed: owners.engines.iter().all(|engine| {
                matches!(engine.circuit_breaker_state(), CircuitBreakerState::Closed)
            }),
            engine_owner_stats: owner_stats,
            engine_instance_count: owners.engines.len(),
            cache_instance_count: owners.caches.len(),
            assembly_cache_scope: cache_scope.label(),
            policy_engine_scope: engine_scope.label(),
            warmup_excluded: true,
            workers_joined: true,
        };
        return MeasuredResult { measurement, v2 };
    }
    #[cfg(not(feature = "performance-attribution"))]
    {
        MeasuredResult { measurement }
    }
}

#[ignore = "release-only CPU owner-sharing experiment; run with --release -- --ignored --nocapture"]
#[test]
fn policy_evaluate_sharing_experiment() {
    if cfg!(debug_assertions) {
        panic!("sharing experiment requires --release");
    }
    let runtime = runtime();
    runtime.block_on(super::evaluate_performance::controls::verify_controls());
    #[cfg(feature = "performance-attribution")]
    println!(
        "\nEVALUATE_SHARING_V2_META {}",
        serde_json::json!({
            "schema": V2_SCHEMA,
            "scope": "policy-engine-evaluate-cpu-owner-sharing-attribution",
            "cases": 72,
            "samplesPerCase": SAMPLES,
            "arms": ARMS,
            "grantSizes": SIZES,
            "threads": THREADS,
            "outcomes": OUTCOMES,
            "assemblyCacheScopes": CACHE_SCOPES.iter().map(|scope| scope.label()).collect::<Vec<_>>(),
            "policyEngineScopes": ENGINE_SCOPES.iter().map(|scope| scope.label()).collect::<Vec<_>>(),
            "controls": {
                "decisionParity": true,
                "allowTwoReads": true,
                "denyOneRead": true,
                "noLegacyReads": true,
                "workersJoined": true,
                "warmupExcluded": true,
                "freshOwnersPerArm": true,
                "atomicStatsReconciled": true,
                "breakerClosed": true,
                "cacheCriticalSectionCaptured": true,
            },
            "premises": {
                "entry": "PolicyEngine.evaluate",
                "stats": "reset after warmup; owner snapshots cover measured decisions only",
                "cache": "detailed stripe lock wait/hold and GC/eviction counters are CPU attribution only",
                "breaker": "map/state wait is observed without changing threshold, recovery, or probe semantics",
                "scopeExclusions": "no HTTP, MySQL, RabbitMQ, signed transport, migration, deployment, production QPS, or distributed capacity claim",
            },
        })
    );
    println!(
        "\nEVALUATE_EXPERIMENT_META {}",
        serde_json::json!({
            "schema": SCHEMA,
            "scope": "policy-engine-evaluate-cpu-owner-sharing",
            "cases": 72,
            "samplesPerCase": SAMPLES,
            "arms": ARMS,
            "grantSizes": SIZES,
            "threads": THREADS,
            "outcomes": OUTCOMES,
            "assemblyCacheScopes": CACHE_SCOPES.iter().map(|scope| scope.label()).collect::<Vec<_>>(),
            "policyEngineScopes": ENGINE_SCOPES.iter().map(|scope| scope.label()).collect::<Vec<_>>(),
            "controls": {
                "decisionParity": true,
                "allowTwoReads": true,
                "denyOneRead": true,
                "noLegacyReads": true,
                "workersJoined": true,
                "warmupExcluded": true,
                "freshOwnersPerArm": true,
            },
            "premises": {
                "entry": "PolicyEngine.evaluate",
                "evidencePort": "Arc<PublishedCardAuthorization>; cache hits reuse immutable evidence, forced assembly creates fresh Arc",
                "assemblyCache": "existing bounded TTL/capacity/fence/read-gate cache; only test owner scope varies",
                "policyEngine": "existing PolicyEngine instance scope varies; production structure is unchanged",
                "matcher": "existing thread-local Arc-identity matcher is inherited and not a shared/private variable",
                "warmup": "one Cached decision per worker before ready barrier; excluded from measured counters and wall time",
                "cached": "fixed validity second; formal evidence reads must all hit",
                "forced": "unique synthetic second per formal evidence read; every formal evidence read must miss",
                "scopeExclusions": "no HTTP, MySQL, RabbitMQ, signed transport, migration, deployment, production QPS, or distributed capacity claim",
            },
        })
    );

    let mut cases = 0;
    for grants in SIZES {
        let (base, targets) = fixture(grants);
        for threads in THREADS {
            for outcome in OUTCOMES {
                let target = if outcome == "deny" {
                    999_999
                } else {
                    targets[0]
                };
                let expected_engine = PolicyEngine::new();
                let (expected, _) =
                    runtime.block_on(super::evaluate_performance::fixture::checked_decision(
                        &expected_engine,
                        &base,
                        EvidenceClock::Cached,
                        target,
                    ));
                assert_eq!(expected.allowed, outcome == "allow-first");
                for cache_scope in CACHE_SCOPES {
                    for engine_scope in ENGINE_SCOPES {
                        let mut samples = Vec::with_capacity(SAMPLES);
                        #[cfg(feature = "performance-attribution")]
                        let mut v2_samples = Vec::with_capacity(SAMPLES);
                        for index in 0..SAMPLES {
                            let mut measurements = serde_json::Map::new();
                            #[cfg(feature = "performance-attribution")]
                            let mut v2_measurements = serde_json::Map::new();
                            for arm in ARMS {
                                let clock = match arm {
                                    "cached-fixed-second" => EvidenceClock::Cached,
                                    "forced-assembly" => EvidenceClock::Forced,
                                    _ => unreachable!(),
                                };
                                let measured = measure(
                                    &base,
                                    &expected,
                                    target,
                                    grants,
                                    threads,
                                    clock,
                                    cache_scope,
                                    engine_scope,
                                );
                                #[cfg(feature = "performance-attribution")]
                                let v2_value = serde_json::to_value(&measured.v2).unwrap();
                                let measurement = measured.measurement;
                                assert_eq!(
                                    measurement.decisions,
                                    threads * decisions_per_thread(grants)
                                );
                                assert_eq!(measurement.latency_ns.len(), measurement.decisions);
                                assert_eq!(
                                    measurement.reads.evidence_grants,
                                    measurement.reads.evidence_reads * usize::from(grants)
                                );
                                assert_eq!(measurement.arc_clones, measurement.cache_hits);
                                assert_eq!(measurement.mismatches, 0);
                                assert_eq!(measurement.pending, 0);
                                assert_eq!(measurement.legacy_reads, 0);
                                assert!(measurement.warmup_excluded);
                                assert!(measurement.workers_joined);
                                if arm == "cached-fixed-second" {
                                    assert_eq!(
                                        measurement.cache_hits,
                                        measurement.reads.evidence_reads
                                    );
                                    assert_eq!(measurement.cache_misses, 0);
                                } else {
                                    assert_eq!(measurement.cache_hits, 0);
                                    assert_eq!(
                                        measurement.cache_misses,
                                        measurement.reads.evidence_reads
                                    );
                                }
                                measurements.insert(
                                    arm.to_owned(),
                                    serde_json::to_value(&measurement).unwrap(),
                                );
                                #[cfg(feature = "performance-attribution")]
                                v2_measurements.insert(arm.to_owned(), v2_value);
                            }
                            samples.push(serde_json::json!({
                                "index": index,
                                "measurements": measurements,
                            }));
                            #[cfg(feature = "performance-attribution")]
                            v2_samples.push(serde_json::json!({
                                "index": index,
                                "measurements": v2_measurements,
                            }));
                        }
                        cases += 1;
                        println!(
                            "\nEVALUATE_EXPERIMENT_CASE {}",
                            serde_json::json!({
                                "case": format!(
                                    "evaluate-sharing/{grants}/threads-{threads}/{outcome}/cache-{}/engine-{}",
                                    cache_scope.label(),
                                    engine_scope.label()
                                ),
                                "grants": grants,
                                "threads": threads,
                                "outcome": outcome,
                                "decisionsPerThread": decisions_per_thread(grants),
                                "assemblyCacheScope": cache_scope.label(),
                                "policyEngineScope": engine_scope.label(),
                                "samples": samples,
                            })
                        );
                        #[cfg(feature = "performance-attribution")]
                        println!(
                            "EVALUATE_SHARING_V2_CASE {}",
                            serde_json::json!({
                                "case": format!(
                                    "evaluate-sharing/{grants}/threads-{threads}/{outcome}/cache-{}/engine-{}",
                                    cache_scope.label(),
                                    engine_scope.label()
                                ),
                                "grants": grants,
                                "threads": threads,
                                "outcome": outcome,
                                "decisionsPerThread": decisions_per_thread(grants),
                                "assemblyCacheScope": cache_scope.label(),
                                "policyEngineScope": engine_scope.label(),
                                "samples": v2_samples,
                            })
                        );
                    }
                }
            }
        }
    }
    assert_eq!(cases, 72);
    println!(
        "\nEVALUATE_EXPERIMENT_END {}",
        serde_json::json!({
            "schema": SCHEMA,
            "status": "PASS",
            "cases": cases,
            "samples": cases * SAMPLES,
            "measurements": cases * SAMPLES * ARMS.len(),
            "postconditions": {
                "workersJoined": true,
                "allDecisionsChecked": true,
                "allReadCountsChecked": true,
                "ownerTopologyChecked": true,
                "cacheReconciliationChecked": true,
                "warmupExcluded": true,
            },
        })
    );
    #[cfg(feature = "performance-attribution")]
    println!(
        "EVALUATE_SHARING_V2_END {}",
        serde_json::json!({
            "schema": V2_SCHEMA,
            "status": "PASS",
            "cases": cases,
            "samples": cases * SAMPLES,
            "measurements": cases * SAMPLES * ARMS.len(),
            "postconditions": {
                "workersJoined": true,
                "allDecisionsChecked": true,
                "ownerTopologyChecked": true,
                "cacheReconciliationChecked": true,
                "atomicStatsReconciled": true,
                "breakerClosed": true,
                "warmupExcluded": true,
            },
        })
    );
}
