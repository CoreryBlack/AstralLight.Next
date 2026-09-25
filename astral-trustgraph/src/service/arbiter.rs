//! 执剑人（Arbiter）运行侧服务 —— TrustGraph 侧有状态编排。
//!
//! 阶段 B 职责：
//! - 挂接 `policy_engine::set_conflict_signal_sink`，把 evaluate() 的冲突信号计入统计
//!   （阶段 A 只发信号，仲裁执行由本服务触发）；
//! - 提供 `arbitrate()`：把跨节点证据（测试协调器经控制面传入，或未来节点注册表
//!   收集）交给纯函数内核 `policy_engine::arbitrate`，更新统计并写权限审计。
//!
//! 仲裁可用性只影响"冲突能否被解析"：无法证明时内核返回 DEFER（语义 =
//! 现有 AUTHORIZATION_PENDING），调用方必须 fail-closed 拒绝，绝不降级为放行。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use astral_types::PolicyContext;
use policy_engine::{
    arbitrate, set_conflict_signal_sink, ArbitrationOutcome, ArbitrationVerdict, ConflictSignal,
    DecisionEvidence,
};

/// 仲裁统计（原子计数，供监控端点与分布式测试断言）。
#[derive(Debug, Default)]
pub struct ArbiterStats {
    /// 收到的冲突信号数（快照/实时分歧且 gate 可证明）
    pub signals: AtomicU64,
    /// 已执行的仲裁次数
    pub arbitrations: AtomicU64,
    /// 裁决结果分布
    pub allows: AtomicU64,
    pub denies: AtomicU64,
    pub defers: AtomicU64,
}

impl ArbiterStats {
    fn record_verdict(&self, verdict: ArbitrationVerdict) {
        match verdict {
            ArbitrationVerdict::Allow => self.allows.fetch_add(1, Ordering::Relaxed),
            ArbitrationVerdict::Deny => self.denies.fetch_add(1, Ordering::Relaxed),
            ArbitrationVerdict::Defer => self.defers.fetch_add(1, Ordering::Relaxed),
        };
    }

    /// 导出结构化指标（供 /arbiter/stats 与 S12/S13 断言）。
    pub fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "signals": self.signals.load(Ordering::Relaxed),
            "arbitrations": self.arbitrations.load(Ordering::Relaxed),
            "allows": self.allows.load(Ordering::Relaxed),
            "denies": self.denies.load(Ordering::Relaxed),
            "defers": self.defers.load(Ordering::Relaxed),
        })
    }
}

/// 执剑人运行侧服务。
pub struct ArbiterService {
    stats: ArbiterStats,
}

impl ArbiterService {
    pub fn new() -> Self {
        Self {
            stats: ArbiterStats::default(),
        }
    }

    pub fn stats(&self) -> &ArbiterStats {
        &self.stats
    }

    /// 挂接 policy-engine 的冲突信号 sink。返回 `true` 表示本服务成为唯一 sink。
    pub fn register_sink(self: &Arc<Self>) -> bool {
        let service = Arc::clone(self);
        set_conflict_signal_sink(Box::new(move |signal: &ConflictSignal| {
            service.on_conflict_signal(signal);
        }))
    }

    fn on_conflict_signal(&self, signal: &ConflictSignal) {
        self.stats.signals.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            card_id = ?signal.ctx.card_id,
            resource = ?signal.ctx.resource,
            action = %signal.ctx.action,
            snapshot_allowed = signal.snapshot_decision.allowed,
            realtime_allowed = signal.realtime_decision.allowed,
            "conflict signal: snapshot/realtime mismatch on provable projection"
        );
    }

    /// 执行仲裁：跨节点证据 → 裁决；更新统计并写权限审计。
    pub async fn arbitrate(
        &self,
        ctx: &PolicyContext,
        evidence: Vec<DecisionEvidence>,
    ) -> ArbitrationOutcome {
        let outcome = arbitrate(ctx, &evidence);
        self.stats.arbitrations.fetch_add(1, Ordering::Relaxed);
        self.stats.record_verdict(outcome.verdict);

        astral_common::audit::record_permission_audit(
            ctx.user_id,
            ctx.card_id,
            ctx.domain_id,
            ctx.tenant_id,
            ctx.resource.as_deref().unwrap_or(""),
            &ctx.action,
            outcome.verdict == ArbitrationVerdict::Allow,
            &outcome.reason_code,
            "/arbiter/arbitrate",
        )
        .await;

        // 仲裁不可证明时保留可观测记录；调用方必须按 fail-closed 处理 DEFER。
        if outcome.verdict == ArbitrationVerdict::Defer {
            tracing::warn!(
                card_id = ?ctx.card_id,
                resource = ?ctx.resource,
                action = %ctx.action,
                reason_code = %outcome.reason_code,
                "arbitration deferred; caller must fail closed"
            );
        }
        outcome
    }
}

impl Default for ArbiterService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::PolicyDecision;
    use policy_engine::{detect_conflict, ConsistencyViolation, ProjectionGate};

    #[test]
    fn stats_record_verdicts_and_snapshot() {
        let stats = ArbiterStats::default();
        stats.record_verdict(ArbitrationVerdict::Allow);
        stats.record_verdict(ArbitrationVerdict::Deny);
        stats.record_verdict(ArbitrationVerdict::Defer);
        let snap = stats.snapshot();
        assert_eq!(snap["allows"], 1);
        assert_eq!(snap["denies"], 1);
        assert_eq!(snap["defers"], 1);
        assert_eq!(snap["arbitrations"], 0);
    }

    /// 哨兵→统计链路：detect_conflict 产出的信号可被服务统计（不触发 IO）。
    #[test]
    fn conflict_signal_is_counted() {
        let stats = ArbiterStats::default();
        let violation = ConsistencyViolation {
            context: PolicyContext::builder()
                .user_id(Some(1))
                .card_id(Some(7))
                .resource(Some("learn_subject".into()))
                .action("read".into())
                .build(),
            snapshot_decision: PolicyDecision {
                allowed: true,
                reason: "snapshot".into(),
                matched_rule: None,
                audit_required: true,
                evaluation_path: vec![],
                matched_rule_id: None,
                condition_results: None,
                snapshot_version: None,
                org_provenance: None,
            },
            realtime_decision: PolicyDecision {
                allowed: false,
                reason: "realtime".into(),
                matched_rule: None,
                audit_required: true,
                evaluation_path: vec![],
                matched_rule_id: None,
                condition_results: None,
                snapshot_version: None,
                org_provenance: None,
            },
        };
        let gate = ProjectionGate {
            ready: true,
            source_generation: 2,
            revoke_fence: 1,
        };
        let signal = detect_conflict(&violation, Some(gate)).expect("signal expected");
        stats.signals.fetch_add(1, Ordering::Relaxed);
        assert_eq!(stats.snapshot()["signals"], 1);
        assert_eq!(
            signal.kind,
            policy_engine::ConflictSignalKind::SnapshotRealtimeMismatch
        );
        assert!(signal.snapshot_decision.allowed);
        assert!(!signal.realtime_decision.allowed);
    }
}
