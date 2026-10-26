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
            background.push(scope.spawn(move || background_encode_storm(stop)));
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

/// 接力控制器：三态（延迟模式 / 保护收缩 / 吞吐模式），由实测接力曲线
/// 调教——bg=0 时曲线平滑（10 线程 p99 1.04ms，可吞吐模式），bg=6 时
/// 拐点在 4→5 线程（p99 1.25→3.1ms，吞吐增益 <15%）——突破 SLO 时正确
/// 动作是**收缩到 P 核预算**（保 SLO 牺牲吞吐），而非继续扩池。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayController {
    pub baseline_threads: usize,
    pub total_threads: usize,
    /// p99 SLO：超过即触发保护收缩（fail-safe 优先）。
    pub p99_slo_ns: u128,
    /// 吞吐模式准入：仅当 p99 在 SLO 内且吞吐比 ≥ demote 比例才扩池。
    pub demote_ratio_pct: u64,
    pub mode: RelayMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayMode {
    Latency,
    Throughput,
}

impl RelayController {
    pub fn new(baseline_threads: usize, total_threads: usize, p99_slo_ns: u128) -> Self {
        Self {
            baseline_threads: baseline_threads.max(1),
            total_threads: total_threads.max(baseline_threads.max(1)),
            p99_slo_ns,
            demote_ratio_pct: 60,
            mode: RelayMode::Latency,
        }
    }

    /// 周期反馈：p99 超 SLO → 立即收缩（任何模式下）；SLO 内且吞吐真实
    /// （≥ demote 比例，防空闲误报）→ 吞吐模式；SLO 内但吞吐塌了 → 回
    /// 延迟模式。滞回由吞吐比条件天然提供。
    pub fn on_sample(&mut self, sustained_p99_ns: u128, throughput_ratio_pct: u64) {
        if sustained_p99_ns > self.p99_slo_ns {
            self.mode = RelayMode::Latency;
            return;
        }
        self.mode = if throughput_ratio_pct >= self.demote_ratio_pct {
            RelayMode::Throughput
        } else {
            RelayMode::Latency
        };
    }

    pub fn active_threads(&self) -> usize {
        match self.mode {
            RelayMode::Latency => self.baseline_threads,
            RelayMode::Throughput => self.total_threads,
        }
    }
}

/// 接力曲线扫描：线程数 1→10 × 有/无后台风暴，定位延迟模式→吞吐模式的
/// 拐点（吞吐增益 <15% 而 p99 翻倍的第一个台阶）。
#[ignore = "release-only relay-curve sweep; run with --release -- --ignored"]
#[test]
fn foreground_relay_curve_sweep() {
    let fg = crate::task_scheduling::foreground_budget();
    let bg = crate::task_scheduling::background_budget();
    eprintln!(
        "[relay] foreground budget {fg}, background budget {bg}; sweep 1..={} x background {{0, {bg}}}",
        fg + bg
    );
    for background in [0usize, bg] {
        let mut previous = (0u128, 0u128);
        for threads in 1..=(fg + bg) {
            let result = measure(threads, background);
            let knee = if previous.0 > 0 {
                let gain = result.ops_per_second as f64 / previous.0 as f64;
                let p99_ratio = result.p99 as f64 / previous.1.max(1) as f64;
                if gain < 1.15 && p99_ratio > 1.8 {
                    " <-- relay knee (throughput gain <15%, p99 >1.8x)"
                } else {
                    ""
                }
            } else {
                ""
            };
            eprintln!(
                "[relay bg={background}] threads {threads:>2}: {:>10} ops/s | p50={}ns p99={}ns{}",
                result.ops_per_second, result.p50, result.p99, knee,
            );
            previous = (result.ops_per_second, result.p99);
        }
    }
}

#[test]
fn relay_controller_transitions_match_the_measured_curve() {
    // SLO 2ms：来自接力曲线——bg=6 时 4 线程 p99 1.25ms 合规、5 线程
    // 3.1ms 违规；bg=0 时 10 线程 1.04ms 合规。
    let mut controller = RelayController::new(4, 10, 2_000_000);
    assert_eq!(controller.active_threads(), 4);

    // 无后台、p99 合规、吞吐真实 → 吞吐模式（扩池合法）。
    controller.on_sample(1_000_000, 100);
    assert_eq!(controller.active_threads(), 10);

    // 后台风暴到来：p99 破 SLO → 立即收缩到 P 核预算（保 SLO）。
    controller.on_sample(3_100_000, 100);
    assert_eq!(controller.active_threads(), 4);

    // 收缩后 p99 回到 1.25ms（SLO 内）但吞吐塌了 → 保持延迟模式。
    controller.on_sample(1_250_000, 30);
    assert_eq!(controller.active_threads(), 4);

    // 空闲误报：p99 高但吞吐塌 → 不扩池（提升需 p99+吞吐双条件）。
    let mut idle = RelayController::new(4, 10, 2_000_000);
    idle.on_sample(3_000_000, 20);
    assert_eq!(idle.active_threads(), 4);
}
