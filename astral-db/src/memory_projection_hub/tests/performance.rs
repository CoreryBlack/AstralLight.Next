use super::*;
use std::hint::black_box;
use std::sync::Barrier;

const SAMPLES: usize = 15;

fn read_at(
    hub: &MemoryProjectionHub,
    scope: &PublishedCardEvidenceScope,
    second: i64,
) -> PublishedCardAuthorization {
    serve(hub.try_memory_evidence_with_clock(scope, || second, || {}))
}

fn single_card(grants: u16) -> MemoryProjectionHub {
    let hub = MemoryProjectionHub::default();
    let values: Vec<_> = (0..grants).map(grant).collect();
    let hot =
        policy_engine::HotState::from_grants(tenant(), 1, values, dependency_vector()).unwrap();
    hub.install_published_state(seal_state(&card_identity(), 17, 1, hot, None, 0));
    hub
}

fn reset_cache(hub: &mut MemoryProjectionHub) {
    hub.assemblies = Arc::new(AssemblyCache::default());
}

fn sample_count() -> usize {
    std::env::var("ASTRAL_PERF_SAMPLES")
        .map(|value| value.parse::<usize>().unwrap())
        .unwrap_or(SAMPLES)
        .clamp(SAMPLES, 30)
}

fn selected(case: &str) -> bool {
    std::env::var("ASTRAL_PERF_CASE")
        .map(|filter| case.contains(&filter))
        .unwrap_or(true)
}

fn sequential_sample(
    hub: &mut MemoryProjectionHub,
    mode: &str,
    validate: bool,
    reads: usize,
) -> u128 {
    let scope = scope();
    let mut nanos = 0;
    for read in 0..reads {
        if mode == "cold" {
            reset_cache(hub);
        }
        if mode == "token-change" {
            hub.maps.write().unwrap().source_revision += 1;
        }
        let second = if mode == "cross-second" {
            100 + read as i64
        } else {
            100
        };
        let started = Instant::now();
        let evidence = if mode == "real-clock" {
            serve(hub.try_memory_evidence(&scope))
        } else {
            read_at(hub, &scope, second)
        };
        if validate {
            evidence.validate().unwrap();
        }
        black_box(evidence);
        nanos += started.elapsed().as_nanos();
    }
    nanos / reads as u128
}

fn print_sequential(size: u16, mode: &str, validate: bool) {
    let case = format!("evidence/{size}/{mode}/validate-{validate}");
    if !selected(&case) {
        return;
    }
    let reads = if size <= 128 { 128 } else { 24 };
    let mut hub = single_card(size);
    read_at(&hub, &scope(), 100).validate().unwrap();
    black_box(sequential_sample(&mut hub, mode, validate, reads));
    let samples: Vec<_> = (0..sample_count())
        .map(|_| sequential_sample(&mut hub, mode, validate, reads))
        .collect();
    println!(
        "PERF_MATRIX {}",
        serde_json::json!({
            "case": case, "metric": "ns-per-read", "reads_per_sample": reads,
            "samples": samples,
        })
    );
}

fn concurrent_sample(
    hub: &MemoryProjectionHub,
    scopes: &[PublishedCardEvidenceScope],
    threads: usize,
    reads: usize,
    staggered: bool,
    real_clock: bool,
) -> (f64, u128, u128, u128) {
    let barrier = Barrier::new(threads + 1);
    let mut samples = Vec::with_capacity(threads * reads);
    let mut wall = Duration::ZERO;
    std::thread::scope(|workers| {
        let mut handles = Vec::with_capacity(threads);
        for worker in 0..threads {
            let barrier = &barrier;
            handles.push(workers.spawn(move || {
                let mut nanos = Vec::with_capacity(reads);
                barrier.wait();
                for read in 0..reads {
                    let offset = if staggered { worker * 127 } else { 0 };
                    let scope = &scopes[(read + offset) % scopes.len()];
                    let started = Instant::now();
                    let evidence = if real_clock {
                        serve(hub.try_memory_evidence(scope))
                    } else {
                        read_at(hub, scope, 100)
                    };
                    assert_eq!(evidence.gate.effective_grant_count, 8);
                    black_box(evidence);
                    nanos.push(started.elapsed().as_nanos());
                }
                nanos
            }));
        }
        let started = Instant::now();
        barrier.wait();
        for handle in handles {
            samples.extend(handle.join().unwrap());
        }
        wall = started.elapsed();
    });
    samples.sort_unstable();
    (
        (threads * reads) as f64 / wall.as_secs_f64(),
        percentile(&samples, 0.50),
        percentile(&samples, 0.99),
        percentile(&samples, 0.999),
    )
}

fn print_concurrent(cards: usize, threads: usize, staggered: bool, real_clock: bool) {
    let case =
        format!("concurrent/{cards}/threads-{threads}/staggered-{staggered}/real-{real_clock}");
    if !selected(&case) {
        return;
    }
    let (hub, scopes) = build_warm_mirror(cards, 4);
    for scope in &scopes {
        read_at(&hub, scope, 100).validate().unwrap();
    }
    black_box(concurrent_sample(
        &hub, &scopes, threads, 5_000, staggered, real_clock,
    ));
    let samples: Vec<_> = (0..sample_count())
        .map(|_| concurrent_sample(&hub, &scopes, threads, 5_000, staggered, real_clock))
        .collect();
    println!(
        "PERF_MATRIX {}",
        serde_json::json!({
            "case": case, "metrics": ["reads-per-second", "p50-ns", "p99-ns", "p999-ns"],
            "reads_per_thread": 5000, "samples": samples,
        })
    );
}

fn print_pressure(cards: usize, hot_cold: bool) {
    let case = format!("pressure/{cards}/hot-cold-{hot_cold}");
    if !selected(&case) {
        return;
    }
    let (hub, scopes) = build_warm_mirror(cards, 4);
    let reads = 8_192;
    let sample = || {
        let mut nanos = Vec::with_capacity(reads);
        let started = Instant::now();
        for read in 0..reads {
            let index = if hot_cold && read % 10 != 0 {
                read % 64.min(cards)
            } else {
                read % cards
            };
            let before = Instant::now();
            let evidence = read_at(&hub, &scopes[index], 100);
            assert_eq!(evidence.gate.effective_grant_count, 8);
            black_box(evidence);
            nanos.push(before.elapsed().as_nanos());
        }
        let wall = started.elapsed();
        nanos.sort_unstable();
        (
            reads as f64 / wall.as_secs_f64(),
            percentile(&nanos, 0.50),
            percentile(&nanos, 0.99),
        )
    };
    black_box(sample());
    let samples: Vec<_> = (0..sample_count()).map(|_| sample()).collect();
    println!(
        "PERF_MATRIX {}",
        serde_json::json!({
            "case": case, "metrics": ["reads-per-second", "p50-ns", "p99-ns"],
            "reads_per_sample": reads, "samples": samples,
        })
    );
}

#[test]
#[ignore = "local CPU-only full evidence no-regression matrix"]
fn memory_evidence_no_regression_matrix() {
    for size in [1, 8, 128, 512, 2_048] {
        for mode in [
            "cold",
            "hot-fixed",
            "cross-second",
            "token-change",
            "real-clock",
        ] {
            for validate in [false, true] {
                print_sequential(size, mode, validate);
            }
        }
    }
    for cards in [1, 512] {
        for threads in [1, 4, 8] {
            for staggered in [false, true] {
                for real_clock in [false, true] {
                    print_concurrent(cards, threads, staggered, real_clock);
                }
            }
        }
    }
    for cards in [64, 512, 1_000, 1_100] {
        for hot_cold in [false, true] {
            print_pressure(cards, hot_cold);
        }
    }
}
