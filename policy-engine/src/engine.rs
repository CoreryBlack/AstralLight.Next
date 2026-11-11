//! PolicyEngine 评估引擎
//!
//! CURRENT V6 published-evidence authorization evaluator.
//!
//! Evaluation is fail-closed and consumes only strict published evidence after
//! AUTHN, CARD_CONTEXT, target ownership, ORG_SCOPE, and GlobalAdmin gates.

use std::collections::HashMap;
use std::sync::Arc;

use crate::circuit_breaker::{AutoCircuitBreaker, CircuitBreakerState};
#[cfg(feature = "performance-attribution")]
use crate::hit_stats::AtomicBreakerAttribution;
use crate::hit_stats::{AtomicHitStats, HitStats, TimingBreakdown};
use astral_types::{AuthorizationAdmission, PolicyContext, PolicyDecision};

mod decision;
mod formal;
mod ports;
mod published;

pub use ports::{
    AuthorizationFenceProvider, OrgAuthorityFenceRead, PublishedEvidenceReadMode, RuleRepository,
};

/// Result of a formal authorization evaluation plus an optional proof-bound
/// capability. The capability is present only for a certified F1 ALLOW and is
/// intentionally excluded from `PolicyDecision` serialization.
#[derive(Debug)]
pub struct PolicyEvaluation {
    pub decision: PolicyDecision,
    admission: Option<AuthorizationAdmission>,
}

impl PolicyEvaluation {
    pub fn without_admission(decision: PolicyDecision) -> Self {
        Self {
            decision,
            admission: None,
        }
    }

    pub(crate) fn from_parts(
        decision: PolicyDecision,
        admission: Option<AuthorizationAdmission>,
    ) -> Self {
        let admission = if decision.allowed { admission } else { None };
        Self {
            decision,
            admission,
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
    /// key = resource_type 字符串，"__global__" 为默认兜底
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

    #[cfg(not(feature = "performance-attribution"))]
    fn breaker_for(&self, key: &str) -> Arc<AutoCircuitBreaker> {
        if let Ok(guard) = self.circuit_breakers.read() {
            if let Some(breaker) = guard.get(key) {
                return Arc::clone(breaker);
            }
        }
        let mut guard = self
            .circuit_breakers
            .write()
            .unwrap_or_else(|e| e.into_inner());
        Arc::clone(
            guard
                .entry(key.to_owned())
                .or_insert_with(|| Arc::new(AutoCircuitBreaker::new())),
        )
    }

    #[cfg(feature = "performance-attribution")]
    fn breaker_for_attributed(&self, key: &str) -> Arc<AutoCircuitBreaker> {
        let started = std::time::Instant::now();
        if let Ok(guard) = self.circuit_breakers.read() {
            if let Some(breaker) = guard.get(key) {
                self.breaker_attribution.record_map_wait(started.elapsed());
                return Arc::clone(breaker);
            }
        }
        let mut guard = self
            .circuit_breakers
            .write()
            .unwrap_or_else(|e| e.into_inner());
        self.breaker_attribution.record_map_wait(started.elapsed());
        Arc::clone(
            guard
                .entry(key.to_owned())
                .or_insert_with(|| Arc::new(AutoCircuitBreaker::new())),
        )
    }

    #[cfg(feature = "performance-attribution")]
    fn check_circuit_breaker_attributed(&self, ctx: &PolicyContext) -> Option<PolicyDecision> {
        let key = Self::breaker_key(ctx.resource.as_deref());
        let resource_breaker = self.breaker_for_attributed(key);
        let state_started = std::time::Instant::now();
        let resource_open = resource_breaker.is_open();
        self.breaker_attribution
            .record_state_wait(state_started.elapsed());
        let global_open = if key != "__global__" {
            let global = self.breaker_for_attributed("__global__");
            let state_started = std::time::Instant::now();
            let open = global.is_open();
            self.breaker_attribution
                .record_state_wait(state_started.elapsed());
            open
        } else {
            false
        };
        (resource_open || global_open).then(|| self.evaluate_fallback(ctx))
    }
    fn breaker_key(resource: Option<&str>) -> &str {
        resource
            .filter(|resource| !resource.is_empty())
            .unwrap_or("__global__")
    }

    ///
    /// 自动从 Open → HalfOpen 超时恢复（30 秒），
    /// 从 HalfOpen → Closed（成功探测时由 record_success_on_evaluate 触发）。
    #[cfg(not(feature = "performance-attribution"))]
    fn check_circuit_breaker(&self, ctx: &PolicyContext) -> Option<PolicyDecision> {
        let key = Self::breaker_key(ctx.resource.as_deref());
        let resource_breaker = self.breaker_for(key);
        let resource_open = resource_breaker.is_open();
        let global_open = key != "__global__" && self.breaker_for("__global__").is_open();
        if resource_open || global_open {
            Some(self.evaluate_fallback(ctx))
        } else {
            None
        }
    }

    #[cfg(not(feature = "performance-attribution"))]
    fn record_success_on_evaluate(&self, resource: Option<&str>) {
        let key = Self::breaker_key(resource);
        let breaker = self.breaker_for(key);
        breaker.record_success();
        if key != "__global__" {
            self.breaker_for("__global__").record_success();
        }
    }

    #[cfg(feature = "performance-attribution")]
    fn record_success_on_evaluate(&self, resource: Option<&str>) {
        let key = Self::breaker_key(resource);
        let breaker = self.breaker_for_attributed(key);
        let state_started = std::time::Instant::now();
        breaker.record_success();
        self.breaker_attribution
            .record_state_wait(state_started.elapsed());
        if key != "__global__" {
            let global = self.breaker_for_attributed("__global__");
            let state_started = std::time::Instant::now();
            global.record_success();
            self.breaker_attribution
                .record_state_wait(state_started.elapsed());
        }
    }

    #[cfg(not(feature = "performance-attribution"))]
    fn record_failure_on_evaluate(&self, resource: Option<&str>) {
        let key = Self::breaker_key(resource);
        let breaker = self.breaker_for(key);
        breaker.record_failure();
        if key != "__global__" {
            self.breaker_for("__global__").record_failure();
        }
    }

    #[cfg(feature = "performance-attribution")]
    fn record_failure_on_evaluate(&self, resource: Option<&str>) {
        let key = Self::breaker_key(resource);
        let breaker = self.breaker_for_attributed(key);
        let state_started = std::time::Instant::now();
        breaker.record_failure();
        self.breaker_attribution
            .record_state_wait(state_started.elapsed());
        if key != "__global__" {
            let global = self.breaker_for_attributed("__global__");
            let state_started = std::time::Instant::now();
            global.record_failure();
            self.breaker_attribution
                .record_state_wait(state_started.elapsed());
        }
    }

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

    /// 强制打开所有断路器（仅测试用途）
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

    // ==================== 统计 ====================

    /// 累加 CURRENT V6 evidence evaluation 的结果计数与阶段耗时。
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
mod ceiling_probe;
#[cfg(test)]
mod tests;
