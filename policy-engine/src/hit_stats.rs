//! 评估命中计数器及时延统计

use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

/// Outcome counters for the formal authorization evaluator. memory—v1: the
/// retired V6/V7 chain no longer reports per-phase timings; every evaluation
/// is counted as a non-allowing attempt with total wall time only.
#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HitStats {
    pub evaluation_count: u64,
    pub allow_count: u64,
    pub deny_count: u64,
    pub timing_ns: TimingBreakdown,
}

/// Lock-free counters used by the hot evaluation path.
///
/// The public snapshot remains `HitStats`; keeping the mutable representation
/// private prevents observation state from becoming part of the authorization
/// contract.
#[derive(Debug, Default)]
pub(crate) struct AtomicHitStats {
    evaluation_count: AtomicU64,
    allow_count: AtomicU64,
    deny_count: AtomicU64,
    card_context_check_ns: AtomicU64,
    initial_evidence_load_ns: AtomicU64,
    final_evidence_reload_ns: AtomicU64,
    evidence_match_ns: AtomicU64,
    total_ns: AtomicU64,
}

impl AtomicHitStats {
    pub(crate) fn record(&self, allowed: bool, timing: &TimingBreakdown) {
        self.evaluation_count.fetch_add(1, Ordering::Relaxed);
        if allowed {
            self.allow_count.fetch_add(1, Ordering::Relaxed);
        } else {
            self.deny_count.fetch_add(1, Ordering::Relaxed);
        }
        self.card_context_check_ns
            .fetch_add(timing.card_context_check_ns, Ordering::Relaxed);
        self.initial_evidence_load_ns
            .fetch_add(timing.initial_evidence_load_ns, Ordering::Relaxed);
        self.final_evidence_reload_ns
            .fetch_add(timing.final_evidence_reload_ns, Ordering::Relaxed);
        self.evidence_match_ns
            .fetch_add(timing.evidence_match_ns, Ordering::Relaxed);
        self.total_ns.fetch_add(timing.total_ns, Ordering::Relaxed);
    }

    pub(crate) fn snapshot(&self) -> HitStats {
        let timing_ns = TimingBreakdown {
            card_context_check_ns: self.card_context_check_ns.load(Ordering::Relaxed),
            initial_evidence_load_ns: self.initial_evidence_load_ns.load(Ordering::Relaxed),
            final_evidence_reload_ns: self.final_evidence_reload_ns.load(Ordering::Relaxed),
            evidence_match_ns: self.evidence_match_ns.load(Ordering::Relaxed),
            total_ns: self.total_ns.load(Ordering::Relaxed),
        };
        HitStats {
            evaluation_count: self.evaluation_count.load(Ordering::Relaxed),
            allow_count: self.allow_count.load(Ordering::Relaxed),
            deny_count: self.deny_count.load(Ordering::Relaxed),
            timing_ns,
        }
    }

    pub(crate) fn reset(&self) {
        for counter in [
            &self.evaluation_count,
            &self.allow_count,
            &self.deny_count,
            &self.card_context_check_ns,
            &self.initial_evidence_load_ns,
            &self.final_evidence_reload_ns,
            &self.evidence_match_ns,
            &self.total_ns,
        ] {
            counter.store(0, Ordering::Relaxed);
        }
    }
}

#[cfg(feature = "performance-attribution")]
#[derive(Debug, Default, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BreakerAttribution {
    pub map_wait_ns: u64,
    pub state_wait_ns: u64,
}

#[cfg(feature = "performance-attribution")]
#[derive(Debug, Default)]
pub(crate) struct AtomicBreakerAttribution {
    map_wait_ns: AtomicU64,
    state_wait_ns: AtomicU64,
}

#[cfg(feature = "performance-attribution")]
impl AtomicBreakerAttribution {
    pub(crate) fn snapshot(&self) -> BreakerAttribution {
        BreakerAttribution {
            map_wait_ns: self.map_wait_ns.load(Ordering::Relaxed),
            state_wait_ns: self.state_wait_ns.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn reset(&self) {
        self.map_wait_ns.store(0, Ordering::Relaxed);
        self.state_wait_ns.store(0, Ordering::Relaxed);
    }
}

#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimingBreakdown {
    pub card_context_check_ns: u64,
    pub initial_evidence_load_ns: u64,
    pub final_evidence_reload_ns: u64,
    pub evidence_match_ns: u64,
    pub total_ns: u64,
}

#[cfg(feature = "performance-attribution")]
#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionBreakdown {
    pub card_context_check_ns: u64,
    pub initial_evidence_load_ns: u64,
    pub initial_validation_ns: u64,
    pub evidence_match_ns: u64,
    pub final_evidence_reload_ns: u64,
    pub final_recheck_validation_ns: u64,
    pub final_recheck_scan_ns: u64,
    pub stats_and_breaker_ns: u64,
    pub total_ns: u64,
}

#[cfg(feature = "performance-attribution")]
impl AttributionBreakdown {
    pub fn add_assign(&mut self, other: &Self) {
        self.card_context_check_ns = self
            .card_context_check_ns
            .saturating_add(other.card_context_check_ns);
        self.initial_evidence_load_ns = self
            .initial_evidence_load_ns
            .saturating_add(other.initial_evidence_load_ns);
        self.initial_validation_ns = self
            .initial_validation_ns
            .saturating_add(other.initial_validation_ns);
        self.evidence_match_ns = self
            .evidence_match_ns
            .saturating_add(other.evidence_match_ns);
        self.final_evidence_reload_ns = self
            .final_evidence_reload_ns
            .saturating_add(other.final_evidence_reload_ns);
        self.final_recheck_validation_ns = self
            .final_recheck_validation_ns
            .saturating_add(other.final_recheck_validation_ns);
        self.final_recheck_scan_ns = self
            .final_recheck_scan_ns
            .saturating_add(other.final_recheck_scan_ns);
        self.stats_and_breaker_ns = self
            .stats_and_breaker_ns
            .saturating_add(other.stats_and_breaker_ns);
        self.total_ns = self.total_ns.saturating_add(other.total_ns);
    }
}

#[cfg(feature = "performance-attribution")]
thread_local! {
    static EVALUATION_ATTRIBUTION: std::cell::RefCell<Option<AttributionBreakdown>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(feature = "performance-attribution")]
pub fn begin_evaluation_attribution() {
    EVALUATION_ATTRIBUTION.with(|slot| {
        *slot.borrow_mut() = Some(AttributionBreakdown::default());
    });
}

#[cfg(feature = "performance-attribution")]
pub fn take_evaluation_attribution() -> AttributionBreakdown {
    EVALUATION_ATTRIBUTION
        .with(|slot| slot.borrow_mut().take())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{AtomicHitStats, TimingBreakdown};
    use std::sync::Arc;

    #[test]
    fn atomic_stats_accumulate_concurrent_records_without_lost_updates() {
        let stats = Arc::new(AtomicHitStats::default());
        let timing = TimingBreakdown {
            card_context_check_ns: 2,
            initial_evidence_load_ns: 3,
            final_evidence_reload_ns: 5,
            evidence_match_ns: 7,
            total_ns: 11,
        };
        let workers = 8;
        let records_per_worker = 1_000;

        std::thread::scope(|threads| {
            for worker in 0..workers {
                let stats = Arc::clone(&stats);
                let timing = timing.clone();
                threads.spawn(move || {
                    for _ in 0..records_per_worker {
                        stats.record(worker % 2 == 0, &timing);
                    }
                });
            }
        });

        let snapshot = stats.snapshot();
        let expected = (workers * records_per_worker) as u64;
        assert_eq!(snapshot.evaluation_count, expected);
        assert_eq!(snapshot.allow_count, expected / 2);
        assert_eq!(snapshot.deny_count, expected / 2);
        assert_eq!(snapshot.timing_ns.card_context_check_ns, expected * 2);
        assert_eq!(snapshot.timing_ns.initial_evidence_load_ns, expected * 3);
        assert_eq!(snapshot.timing_ns.final_evidence_reload_ns, expected * 5);
        assert_eq!(snapshot.timing_ns.evidence_match_ns, expected * 7);
        assert_eq!(snapshot.timing_ns.total_ns, expected * 11);
    }

    #[test]
    fn reset_establishes_a_new_observation_boundary() {
        let stats = AtomicHitStats::default();
        let timing = TimingBreakdown::default();
        stats.record(false, &timing);
        stats.reset();
        stats.record(true, &timing);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.evaluation_count, 1);
        assert_eq!(snapshot.allow_count, 1);
        assert_eq!(snapshot.deny_count, 0);
    }
}
