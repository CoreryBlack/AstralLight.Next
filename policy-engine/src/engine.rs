//! PolicyEngine 评估引擎
//!
//! CURRENT V6 published-evidence authorization evaluator.
//!
//! Evaluation is fail-closed and consumes only strict published evidence after
//! AUTHN, CARD_CONTEXT, target ownership, ORG_SCOPE, and GlobalAdmin gates.

use std::collections::HashMap;
use std::sync::Arc;

use crate::circuit_breaker::{AutoCircuitBreaker, CircuitBreakerState};
use crate::hit_stats::{HitStats, TimingBreakdown};
use arc_swap::ArcSwap;
use astral_types::{PolicyContext, PolicyDecision};

mod decision;
mod formal;
mod ports;
mod published;

pub use ports::RuleRepository;

/// PolicyEngine（线程安全，ArcSwap 实现运行时配置热更新）
pub struct PolicyEngine {
    stats: ArcSwap<HitStats>,
    /// per-resource 断路器（对齐 Java Resilience4j per-endpoint 隔离），
    /// key = resource_type 字符串，"__global__" 为默认兜底
    circuit_breakers: std::sync::RwLock<HashMap<String, AutoCircuitBreaker>>,
}

impl PolicyEngine {
    /// 创建 PolicyEngine 实例
    pub fn new() -> Self {
        let mut breakers = HashMap::new();
        breakers.insert("__global__".to_string(), AutoCircuitBreaker::new());
        Self {
            stats: ArcSwap::new(Arc::new(HitStats::default())),
            circuit_breakers: std::sync::RwLock::new(breakers),
        }
    }

    ///
    /// 自动从 Open → HalfOpen 超时恢复（30 秒），
    /// 从 HalfOpen → Closed（成功探测时由 record_success_on_evaluate 触发）。
    fn check_circuit_breaker(&self, ctx: &PolicyContext) -> Option<PolicyDecision> {
        let resource = ctx.resource.as_deref();
        let key = resource.filter(|r| !r.is_empty()).unwrap_or("__global__");
        // 惰性创建 per-resource 断路器
        {
            let mut map = self
                .circuit_breakers
                .write()
                .unwrap_or_else(|e| e.into_inner());
            map.entry(key.to_string()).or_default();
        }
        let guard = self
            .circuit_breakers
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let resource_open = guard
            .get(key)
            .map(AutoCircuitBreaker::is_open)
            .unwrap_or(false);
        let global_open = key != "__global__"
            && guard
                .get("__global__")
                .map(AutoCircuitBreaker::is_open)
                .unwrap_or(false);
        if resource_open || global_open {
            Some(self.evaluate_fallback(ctx))
        } else {
            None
        }
    }

    /// 记录一次成功的评估（重置断路器失败计数器 / 关闭 HalfOpen 状态）
    fn record_success_on_evaluate(&self, resource: Option<&str>) {
        let key = resource.unwrap_or("__global__");
        // 惰性创建 per-resource 断路器
        {
            let mut map = self
                .circuit_breakers
                .write()
                .unwrap_or_else(|e| e.into_inner());
            map.entry(key.to_string()).or_default();
        }
        let guard = self
            .circuit_breakers
            .read()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(breaker) = guard.get(key) {
            breaker.record_success();
        }
        // Also reset global breaker
        if key != "__global__" {
            if let Some(breaker) = guard.get("__global__") {
                breaker.record_success();
            }
        }
    }

    /// 记录一次失败的评估（递增失败计数器，达到阈值自动打开断路器）
    fn record_failure_on_evaluate(&self, resource: Option<&str>) {
        let key = resource.unwrap_or("__global__");
        // 惰性创建 per-resource 断路器
        {
            let mut map = self
                .circuit_breakers
                .write()
                .unwrap_or_else(|e| e.into_inner());
            map.entry(key.to_string()).or_default();
        }
        let guard = self
            .circuit_breakers
            .read()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(breaker) = guard.get(key) {
            breaker.record_failure();
        }
        // Also increment global breaker
        if key != "__global__" {
            if let Some(breaker) = guard.get("__global__") {
                breaker.record_failure();
            }
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
            .map(|b| b.state())
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
        let mut stats = HitStats::clone(self.stats.load().as_ref());
        stats.evaluation_count += 1;
        if allowed {
            stats.allow_count += 1;
        } else {
            stats.deny_count += 1;
        }
        stats.timing_ns.card_context_check_ns += timing.card_context_check_ns;
        stats.timing_ns.initial_evidence_load_ns += timing.initial_evidence_load_ns;
        stats.timing_ns.final_evidence_reload_ns += timing.final_evidence_reload_ns;
        stats.timing_ns.evidence_match_ns += timing.evidence_match_ns;
        stats.timing_ns.total_ns += timing.total_ns;
        self.stats.store(Arc::new(stats));
    }

    /// 获取当前统计数据的快照（对齐 Java `getCacheHitStats()` + `getBreakdownStats()`）
    pub fn get_stats(&self) -> HitStats {
        HitStats::clone(self.stats.load().as_ref())
    }

    /// 重置所有统计数据（对齐 Java `resetCacheHitStats()` + `resetBreakdownStats()`）
    pub fn reset_stats(&self) {
        self.stats.store(Arc::new(HitStats::default()));
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
