//! PolicyEngine 评估引擎
//!
//! memory—v1 单机权威 profile 的 fail-closed 正式评估入口。
//!
//! The legacy CURRENT V6/V7 published-evidence execution chain has been
//! physically retired (`memory-v1-retire-legacy-read-20261112`). Every formal
//! evaluation now fails closed to `AUTHORIZATION_PENDING`; no published CARD
//! evidence, ORG_SCOPE admission proof, GlobalAdmin lookup, or authorization
//! fence is read, and no evaluation path can return ALLOW. Positive
//! authorization stays reserved for the memory-v1 shared root via
//! `PolicyEngine.evaluate()` once that contract completes adoption (§15.10).

use std::collections::HashMap;
use std::sync::Arc;

use crate::circuit_breaker::{AutoCircuitBreaker, CircuitBreakerState};
#[cfg(feature = "performance-attribution")]
use crate::hit_stats::AtomicBreakerAttribution;
use crate::hit_stats::{AtomicHitStats, HitStats, TimingBreakdown};
use astral_types::{AuthorizationAdmission, PolicyDecision};

mod formal;
mod ports;

pub use ports::{
    AuthorizationFenceProvider, OrgAuthorityFenceRead, PublishedEvidenceReadMode, RuleRepository,
};

/// Result of a formal authorization evaluation plus an optional proof-bound
/// capability. The capability is reserved for a certified positive ALLOW of the
/// memory-v1 shared root and is intentionally excluded from `PolicyDecision`
/// serialization. The retired legacy evaluator never produces one.
#[derive(Debug)]
pub struct PolicyEvaluation {
    pub decision: PolicyDecision,
    admission: Option<AuthorizationAdmission>,
}

impl PolicyEvaluation {
    /// memory—v1: Wrap a decision without a certified admission capability.
    pub fn without_admission(decision: PolicyDecision) -> Self {
        Self {
            decision,
            admission: None,
        }
    }

    pub fn admission(&self) -> Option<&AuthorizationAdmission> {
        self.admission.as_ref()
    }

    pub fn into_parts(self) -> (PolicyDecision, Option<AuthorizationAdmission>) {
        (self.decision, self.admission)
    }
}

pub struct PolicyEngine {
    stats: AtomicHitStats,
    #[cfg(feature = "performance-attribution")]
    breaker_attribution: AtomicBreakerAttribution,
    /// per-resource 断路器（对齐 Java Resilience4j per-endpoint 隔离），
    /// key = resource_type 字符串，"__global__" 为默认兜底。
    ///
    /// memory—v1：旧 V6/V7 评估链退役后，评估路径不再读取任何依赖，因此
    /// 不再产生依赖失败信号，也不再以断路器 fallback 影响正式评估；断路器
    /// 仅作为可观测/演练组件保留（`circuit_breaker_state` /
    /// `force_open_circuit_breaker`）。
    circuit_breakers: std::sync::RwLock<HashMap<String, Arc<AutoCircuitBreaker>>>,
}

impl PolicyEngine {
    /// 创建 PolicyEngine 实例
    pub fn new() -> Self {
        let mut breakers = HashMap::new();
        breakers.insert(
            "__global__".to_string(),
            Arc::new(AutoCircuitBreaker::new()),
        );
        Self {
            stats: AtomicHitStats::default(),
            #[cfg(feature = "performance-attribution")]
            breaker_attribution: AtomicBreakerAttribution::default(),
            circuit_breakers: std::sync::RwLock::new(breakers),
        }
    }

    /// 返回全局断路器状态
    pub fn circuit_breaker_state(&self) -> CircuitBreakerState {
        let guard = self
            .circuit_breakers
            .read()
            .unwrap_or_else(|e| e.into_inner());
        guard
            .get("__global__")
            .map(Arc::as_ref)
            .map(AutoCircuitBreaker::state)
            .unwrap_or(CircuitBreakerState::Closed)
    }

    /// 强制打开所有断路器（仅测试用途）。memory—v1：评估结果不受断路器
    /// 状态影响，fail-closed PENDING 与断路器状态无关。
    pub fn force_open_circuit_breaker(&self) {
        let guard = self
            .circuit_breakers
            .read()
            .unwrap_or_else(|e| e.into_inner());
        for breaker in guard.values() {
            for _ in 0..crate::circuit_breaker::CB_THRESHOLD {
                breaker.record_failure();
            }
        }
    }

    /// memory—v1：旧 V6/V7 评估入口退役后的统一 fail-closed 决策。
    ///
    /// 正式评估在任何上下文下都返回 `AUTHORIZATION_PENDING`；缺失、退役或
    /// 不一致的评估能力一律不得放行（AGENTS §3.4 默认 PENDING/DENY）。
    pub fn authorization_pending(reason: &str) -> PolicyDecision {
        PolicyDecision {
            allowed: false,
            reason: "AUTHORIZATION_PENDING".to_owned(),
            matched_rule: Some(reason.to_owned()),
            audit_required: true,
            evaluation_path: Vec::new(),
            matched_rule_id: None,
            condition_results: None,
            snapshot_version: None,
            org_provenance: None,
        }
    }

    // ==================== 统计 ====================

    /// memory—v1：记录一次 fail-closed 正式评估的结果计数与总耗时。
    ///
    /// 旧评估链的阶段耗时（card context / evidence load / reload / match）
    /// 随链路退役，不再产生；快照中这些字段恒为 0。
    fn record_evaluation(&self, allowed: bool, timing: &TimingBreakdown) {
        self.stats.record(allowed, timing);
    }

    /// 获取当前统计数据的快照（对齐 Java `getCacheHitStats()` + `getBreakdownStats()`）
    pub fn get_stats(&self) -> HitStats {
        self.stats.snapshot()
    }

    #[cfg(feature = "performance-attribution")]
    pub fn breaker_attribution(&self) -> crate::hit_stats::BreakerAttribution {
        self.breaker_attribution.snapshot()
    }

    #[cfg(feature = "performance-attribution")]
    pub fn reset_breaker_attribution(&self) {
        self.breaker_attribution.reset();
    }

    ///
    /// Reset is an observation boundary. Evaluations racing with reset may be
    /// counted before or after the boundary, but each evaluation is atomically
    /// added and is never lost between two completed snapshots.
    pub fn reset_stats(&self) {
        self.stats.reset();
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(test)]
mod tests;
