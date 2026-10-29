//! 评估命中计数器及时延统计

use serde::Serialize;

/// Outcome counters for the CURRENT V6 evidence evaluator.
#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HitStats {
    pub evaluation_count: u64,
    pub allow_count: u64,
    pub deny_count: u64,
    pub timing_ns: TimingBreakdown,
}

/// CURRENT V6 authorization phase timings.
#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimingBreakdown {
    pub card_context_check_ns: u64,
    pub initial_evidence_load_ns: u64,
    pub final_evidence_reload_ns: u64,
    pub evidence_match_ns: u64,
    pub total_ns: u64,
}
