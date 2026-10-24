//! 核分配调度曲线探针（release + --ignored）：前台 encode/hash 负载 +
//! 后台同形风暴，在混池（前台+后台共享全部核）与分池（前台 P 核预算、
//! 后台其余）两种部署下测前台 p99——校准 task_scheduling 的预算阈值。
//!
//! 负载形状与授权供给链一致：64-grant 批次的 canonical JSON 编码 + SHA256
//! （staging/发布的真实构成）。前台操作 = 单批次 encode+hash（每次判定的
//! 构造税形状）；后台 = 持续批次风暴（staging 风暴形状）。

use std::hint::black_box;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Barrier;
use std::time::{Duration, Instant};

fn load_batch(seed: usize) -> Vec<astral_types::CanonicalGrant> {
    (0..64)
        .map(|index| astral_types::CanonicalGrant {
            grant_id: astral_types::GrantId::parse(&format!(
                "00000000-0000-0000-5000-{:012x}",
                ((seed * 64 + index) as u64 + 1) & 0xffff_ffff_ffff
            ))
            .unwrap(),
            revision: astral_types::GrantRevision::initial(),
            state: astral_types::GrantState::Active,
            source_kind: astral_types::GrantSourceKind::RuleSet,
            binding_layer: astral_types::BindingLayer::Base,
            tenant: astral_types::TenantScope::new(7, Some(11)).unwrap(),
            card_id: 17,
            user_id: 42,
            resource: format!("load:{seed}:{index}"),
            action: "read".to_owned(),
            effect: astral_types::GrantEffect::Allow,
            validity: astral_types::ValidityWindow::perpetual(),
            provenance: astral_types::GrantProvenance {
                source_id: format!("source-{seed}"),
                source_entry: Some(format!("entry-{index}")),
                binding_id: Some("binding-1".to_owned()),
                delegation_id: None,
                operation_id: format!("op-{seed}"),
                event_id: Some(format!("event-{seed}")),
                actor_user_id: None,
            },
        })
        .collect()
}

fn foreground_op(batch: &[astral_types::CanonicalGrant], sink: &mut u64) {
    let payload = serde_json::to_vec(batch).unwrap();
    let mut digest = [0u8; 32];
    for (index, byte) in payload.iter().take(32).enumerate() {
        digest[index] = byte.swap_bytes();
    }
    *sink = sink
        .wrapping_add(payload.len() as u64)
        .wrapping_add(u64::from_le_bytes(digest[..8].try_into().unwrap()));
}

fn background_encode_storm(stop: &AtomicBool) -> u64 {
    let batches: Vec<_> = (0..512).map(load_batch).collect();
    let mut rounds = 0u64;
    let mut sink = 0u64;
    while !stop.load(Ordering::Relaxed) {
        for batch in &batches {
            foreground_op(batch, &mut sink);
        }
        rounds += 1;
    }
    sink.wrapping_add(rounds)
}

fn percentile(sorted: &[u128], fraction: f64) -> u128 {
    let index = ((sorted.len() as f64) * fraction) as usize;
    sorted[index.min(sorted.len() - 1)]
}

struct ForegroundResult {
    ops_per_second: u128,
    p50: u128,
    p99: u128,
}

fn measure(fg_threads: usize, bg_threads: usize) -> ForegroundResult {
    let stop = AtomicBool::new(false);
    let barrier = Barrier::new(fg_threads);
    let merged = std::sync::Mutex::new(Vec::new());
    let total = std::sync::Mutex::new(0usize);
    std::thread::scope(|scope| {
        let mut background = Vec::new();
        for _ in 0..bg_threads {
            let stop = &stop;
            background.push(scope.spawn(move || background_encode_storm(&stop)));
        }
        let mut handles = Vec::new();
        for _ in 0..fg_threads {
            let barrier = &barrier;
            handles.push(scope.spawn(move || {
                let batches: Vec<_> = (0..512).map(load_batch).collect();
                for _ in 0..500 {
                    let mut sink = 0u64;
                    for batch in &batches {
                        foreground_op(batch, &mut sink);
                    }
                }
                barrier.wait();
                let mut samples = Vec::with_capacity(30_000);
                let start = Instant::now();
                let mut ops = 0usize;
                loop {
                    let op_start = Instant::now();
                    let mut sink = 0u64;
                    for batch in batches.iter().take(8) {
                        foreground_op(batch, &mut sink);
                    }
                    black_box(sink);
                    if samples.len() < 30_000 {
                        samples.push(op_start.elapsed().as_nanos());
                    }
                    ops += 1;
                    if start.elapsed() >= Duration::from_secs(4) || samples.len() >= 30_000 {
                        break;
                    }
                }
                (start.elapsed(), samples, ops)
            }));
        }
        for handle in handles {
            let (elapsed, samples, ops) = handle.join().unwrap();
            let _ = elapsed;
            *total.lock().unwrap() += ops;
            merged.lock().unwrap().extend(samples);
        }
        stop.store(true, Ordering::Relaxed);
        for handle in background {
            let _ = handle.join().unwrap();
        }
    });
    let merged = merged.into_inner().unwrap();
    let mut sorted = merged;
    sorted.sort_unstable();
    let total = *total.lock().unwrap();
    ForegroundResult {
        ops_per_second: (total as f64 / 4.0) as u128,
        p50: percentile(&sorted, 0.50),
        p99: percentile(&sorted, 0.99),
    }
}

#[ignore = "release-only scheduling-curve probe; run with --release -- --ignored"]
#[test]
fn foreground_background_scheduling_curve() {
    let fg = crate::task_scheduling::foreground_budget();
    let bg = crate::task_scheduling::background_budget();
    eprintln!("[sched] foreground budget {fg}, background budget {bg}");

    for (fg_threads, bg_threads) in [(fg, 0), (fg, bg), (fg + bg, 0)] {
        let result = measure(fg_threads, bg_threads);
        eprintln!(
            "[sched] foreground {fg_threads:>2} threads + background {bg_threads:>2} threads: {:>10} ops/s | p50={}ns p99={}ns",
            result.ops_per_second, result.p50, result.p99,
        );
    }
}
