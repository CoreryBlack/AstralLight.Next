//! PolicyEngine 评估引擎
//!
//! 三层评估主入口，对齐 Java MergeSemantics.evaluateFormal 正式规范：
//! L1: RuleSet（OVERLAY > BASE，每层内 DENY-OVERRIDES）
//! L2: PermissionRule 回退
//! L3: DEFAULT_DENY（fail-closed）
//!
//! 评估链（对齐 Java PolicyEngine.evaluate()）：
//! AUTHN → CARD_CONTEXT → RULESET(OVERLAY>BASE) → PERMISSION_RULE → DEFAULT_DENY

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
mod types;

pub use ports::{published_card_shadow_evidence_is_usable, RuleRepository};
pub use types::{
    PermissionRule, ProjectionGate, RuleSetDependencyStatus, RuleSetEntry, RuleSetSnapshot,
    SnapshotWinner,
};

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

    /// 返回全局断路器状态（兼容旧 API）
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

    /// 累加单次评估的命中计数与时序数据到全局统计（对齐 Java PolicyEngine 的 AtomicLong 计数器 + 时序字段）
    ///
    /// `layer` 表示本次评估命中的层次："L1" / "L2" / "L3"，或 ORG_SCOPE 准入
    /// 决策的稳定类别 "ORG_AUTHORITY"（见 [`ORG_AUTHORITY_EVAL_LAYER`]，不冒领
    /// legacy 层命中；`HitStats` 公共 schema 无专属 ORG 桶，保守计入 l3_hits）。
    fn record_evaluation(&self, layer: &str, timing: &TimingBreakdown) {
        let mut stats = HitStats::clone(self.stats.load().as_ref());
        match layer {
            "L1" => stats.l1_hits += 1,
            "L2" => stats.l2_hits += 1,
            // ORG_SCOPE 准入决策：稳定类别 ORG_AUTHORITY；公共 schema 无专属
            // ORG 桶 → 保守映射进终局 fail-closed 层 l3_hits（同未知 layer 兜底）。
            "ORG_AUTHORITY" => stats.l3_hits += 1,
            _ => stats.l3_hits += 1,
        }
        stats.timing_ns.card_active_check_ns += timing.card_active_check_ns;
        stats.timing_ns.refs_load_ns += timing.refs_load_ns;
        stats.timing_ns.initial_evidence_load_ns += timing.initial_evidence_load_ns;
        stats.timing_ns.final_evidence_reload_ns += timing.final_evidence_reload_ns;
        stats.timing_ns.overlay_eval_ns += timing.overlay_eval_ns;
        stats.timing_ns.base_eval_ns += timing.base_eval_ns;
        stats.timing_ns.perm_rule_eval_ns += timing.perm_rule_eval_ns;
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
mod tests;
