//! 评估命中计数器及时延统计

use serde::Serialize;

/// L1/L2/L3 三层命中计数器
#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HitStats {
    pub l1_hits: u64,
    pub l2_hits: u64,
    pub l3_hits: u64,
    pub timing_ns: TimingBreakdown,
}

/// 各阶段耗时分布
#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimingBreakdown {
    pub card_active_check_ns: u64,
    /// Backward-compatible aggregate of initial evidence load and final reload.
    pub refs_load_ns: u64,
    /// First strict published-evidence read before candidate matching.
    pub initial_evidence_load_ns: u64,
    /// Final strict published-evidence read before an ALLOW is returned.
    pub final_evidence_reload_ns: u64,
    pub overlay_eval_ns: u64,
    pub base_eval_ns: u64,
    pub perm_rule_eval_ns: u64,
    pub total_ns: u64,
}
