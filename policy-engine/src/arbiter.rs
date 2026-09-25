//! 执剑人（Arbiter）—— 冲突仲裁纯函数内核。
//!
//! 定位：多集群授权层的冲突解析器，不是第四投票者。仅在"快照决策可证明
//! （ProjectionGate.ready）且出现版本可区分的分歧"时被激活：
//!
//! - 收敛窗口内（gate 未 ready 或版本落后）属于合法旧状态 / AUTHORIZATION_PENDING，
//!   不进入仲裁；
//! - fence / generation 前进后仍产出旧 ALLOW 才是冲突，才进入仲裁。
//!
//! 裁决依据是 `(source_generation, revoke_fence)` 的**版本序**，不是票数：
//! revoke fence 推进后的 DENY 优先（fail-closed），无法证明时 DEFER
//! （DEFER 语义 = 现有 `AUTHORIZATION_PENDING`，不是新的第三种授权结果）。
//!
//! 本模块是无 IO 的纯函数：不依赖 MySQL/Redis/Rabbit，跨节点证据由调用方
//! （TrustGraph 控制面）组装后传入。仲裁可用性只影响"冲突能否被解析"，
//! 不影响"无法解析时拒绝"这一安全底线。

use std::sync::OnceLock;

use astral_types::{PolicyContext, PolicyDecision};

use crate::consistency::ConsistencyViolation;
use crate::engine::ProjectionGate;

/// 一份节点的决策证据（与 README S11 `evaluateWithEvidence` 的 evidence 行对齐）。
#[derive(Debug, Clone)]
pub struct DecisionEvidence {
    pub node_id: String,
    pub decision: PolicyDecision,
    /// 决策依据的投影门禁。`None` 表示该证据无法证明基于哪个版本。
    pub gate: Option<ProjectionGate>,
    /// 观测时间（epoch ms，仅用于审计排序，不参与裁决）
    pub observed_at_ms: i64,
}

/// 冲突信号类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictSignalKind {
    /// 快照决策与实时（源表）重评估不一致。
    SnapshotRealtimeMismatch,
}

/// 哨兵输出的冲突信号（阶段 A 只生成信号，不执行仲裁）。
#[derive(Debug, Clone)]
pub struct ConflictSignal {
    pub kind: ConflictSignalKind,
    pub ctx: PolicyContext,
    pub snapshot_gate: Option<ProjectionGate>,
    pub snapshot_decision: PolicyDecision,
    pub realtime_decision: PolicyDecision,
}

/// 仲裁裁决（三态）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArbitrationVerdict {
    Allow,
    Deny,
    /// 无法证明 → 与现有 `AUTHORIZATION_PENDING` 同语义（fail-closed 出口）。
    Defer,
}

/// 仲裁结果（含稳定 reason_code 供审计/指标引用）。
#[derive(Debug, Clone)]
pub struct ArbitrationOutcome {
    pub verdict: ArbitrationVerdict,
    pub reason: String,
    pub reason_code: String,
    /// 裁决依据的证据（供审计链引用）。
    pub resolved_evidence: Vec<DecisionEvidence>,
}

fn outcome(
    verdict: ArbitrationVerdict,
    reason_code: &str,
    reason: String,
    resolved: Vec<&DecisionEvidence>,
) -> ArbitrationOutcome {
    ArbitrationOutcome {
        verdict,
        reason_code: reason_code.to_string(),
        reason,
        resolved_evidence: resolved.into_iter().cloned().collect(),
    }
}

fn defer(code: &str, resolved: Vec<&DecisionEvidence>) -> ArbitrationOutcome {
    outcome(
        ArbitrationVerdict::Defer,
        code,
        format!("arbitration deferred: {code}"),
        resolved,
    )
}

fn deny(code: &str, resolved: Vec<&DecisionEvidence>) -> ArbitrationOutcome {
    outcome(
        ArbitrationVerdict::Deny,
        code,
        format!("arbitration denied: {code}"),
        resolved,
    )
}

fn allow(code: &str, resolved: Vec<&DecisionEvidence>) -> ArbitrationOutcome {
    outcome(
        ArbitrationVerdict::Allow,
        code,
        format!("arbitration allowed: {code}"),
        resolved,
    )
}

/// 哨兵：从一致性巡检违规生成冲突信号。
///
/// 只有当快照决策所基于的投影门禁可证明（`ready`）时，快照/实时分歧才构成
/// 冲突；否则只是投影追赶中的合法收敛窗口，不得进入仲裁。
pub fn detect_conflict(
    violation: &ConsistencyViolation,
    snapshot_gate: Option<ProjectionGate>,
) -> Option<ConflictSignal> {
    let gate = snapshot_gate?;
    if !gate.ready {
        return None;
    }
    if violation.snapshot_decision.allowed == violation.realtime_decision.allowed {
        return None;
    }
    Some(ConflictSignal {
        kind: ConflictSignalKind::SnapshotRealtimeMismatch,
        ctx: violation.context.clone(),
        snapshot_gate: Some(gate),
        snapshot_decision: violation.snapshot_decision.clone(),
        realtime_decision: violation.realtime_decision.clone(),
    })
}

/// 冲突信号 sink（阶段 B 注册跨节点证据收集器；默认 no-op 只记 debug 日志）。
type ConflictSignalSink = Box<dyn Fn(&ConflictSignal) + Send + Sync>;
static SIGNAL_SINK: OnceLock<ConflictSignalSink> = OnceLock::new();

/// 注册冲突信号 sink。返回 `true` 表示注册成功；已有 sink 时保持首个注册者并返回 `false`。
pub fn set_conflict_signal_sink(sink: ConflictSignalSink) -> bool {
    SIGNAL_SINK.set(sink).is_ok()
}

pub fn emit_conflict_signal(signal: &ConflictSignal) {
    if let Some(sink) = SIGNAL_SINK.get() {
        sink(signal);
        return;
    }
    tracing::debug!(
        card_id = ?signal.ctx.card_id,
        resource = ?signal.ctx.resource,
        action = %signal.ctx.action,
        snapshot_allowed = signal.snapshot_decision.allowed,
        realtime_allowed = signal.realtime_decision.allowed,
        "conflict signal emitted (no sink registered)"
    );
}

/// 仲裁入口：跨节点证据 → 确定性裁决。
///
/// 版本序为 `(source_generation, revoke_fence)` 字典序（每次 source mutation 递增
/// generation，REVOKE 同时递增 fence，两者在同一事务内单调）。裁决规则（fail-closed）：
/// - R1：最新 READY DENY 版本**严格新于**最新 READY ALLOW 版本 → DENY
///   （fence/generation 前进后的 DENY 覆盖旧 ALLOW，deny-biased）。
/// - R3：最新 DENY 与最新 ALLOW 版本相同（同版本分歧）→ 多数一致采纳，
///   平局/非多数 → DENY。
/// - R2：无任何 DENY，但存在 gate 不可证明（缺失/未 READY）的 ALLOW → DEFER
///   （无法排除旧授权复活）。
/// - R2'：最新版本全 ALLOW（旧 READY ALLOW 属于合法收敛窗口）→ ALLOW。
/// - R4：证据缺失 / 无任何 READY 证据 → DEFER。
pub fn arbitrate(ctx: &PolicyContext, evidence: &[DecisionEvidence]) -> ArbitrationOutcome {
    let _ = ctx;
    if evidence.is_empty() {
        return defer("EVIDENCE_MISSING", vec![]);
    }

    let ready: Vec<&DecisionEvidence> = evidence
        .iter()
        .filter(|e| e.gate.as_ref().is_some_and(|g| g.ready))
        .collect();
    if ready.is_empty() {
        return defer("R4_UNPROVABLE", evidence.iter().collect());
    }

    let version = |e: &DecisionEvidence| -> (i64, i64) {
        e.gate
            .map(|g| (g.source_generation, g.revoke_fence))
            .unwrap_or((0, 0))
    };
    let allow_max = ready
        .iter()
        .copied()
        .filter(|e| e.decision.allowed)
        .map(version)
        .max();
    let deny_max = ready
        .iter()
        .copied()
        .filter(|e| !e.decision.allowed)
        .map(version)
        .max();

    // R1: 最新 DENY 版本严格新于最新 ALLOW 版本 → DENY
    if let (Some(deny_v), Some(allow_v)) = (deny_max, allow_max) {
        if deny_v > allow_v {
            return deny("R1_FENCE_DENY", ready);
        }
        // R3: 同版本分歧 → 多数一致采纳，平局/非多数 DENY
        if deny_v == allow_v {
            let allows = ready.iter().filter(|e| e.decision.allowed).count();
            if allows * 2 > ready.len() {
                return allow("R3_MAJORITY_ALLOW", ready);
            }
            return deny("R3_VERSION_AGREED_DIVERGED", ready);
        }
    }

    // 无 READY DENY（deny_max == None）：全 ALLOW。
    // R2: 存在 gate 不可证明的 ALLOW → 无法排除旧授权复活 → DEFER
    let unprovable_allow = evidence
        .iter()
        .any(|e| e.decision.allowed && !e.gate.as_ref().is_some_and(|g| g.ready));
    if unprovable_allow {
        return defer("R2_STALE_ALLOW_UNPROVABLE", ready);
    }
    // R2': 最新版本全 ALLOW（旧 READY ALLOW 属于合法收敛窗口）→ ALLOW
    allow("R2_NEWEST_ALLOW", ready)
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::{Effect, EvaluationStep, PolicyContext};

    fn ctx() -> PolicyContext {
        PolicyContext::builder()
            .user_id(Some(42))
            .card_id(Some(7))
            .resource(Some("learn_subject".into()))
            .action("read".into())
            .build()
    }

    fn decision(allowed: bool, reason: &str) -> PolicyDecision {
        PolicyDecision {
            allowed,
            reason: reason.to_string(),
            matched_rule: None,
            audit_required: true,
            evaluation_path: vec![EvaluationStep {
                phase: "RULESET".into(),
                result: if allowed { Effect::Allow } else { Effect::Deny },
                detail: reason.to_string(),
                matched_rule_id: None,
                source: None,
            }],
            matched_rule_id: None,
            condition_results: None,
            snapshot_version: None,
            org_provenance: None,
        }
    }

    fn gate(ready: bool, source: i64, fence: i64) -> ProjectionGate {
        ProjectionGate {
            ready,
            source_generation: source,
            revoke_fence: fence,
        }
    }

    fn evidence(node: &str, allowed: bool, gate: Option<ProjectionGate>) -> DecisionEvidence {
        DecisionEvidence {
            node_id: node.to_string(),
            decision: decision(allowed, node),
            gate,
            observed_at_ms: 0,
        }
    }

    // ===== detect_conflict =====

    #[test]
    fn convergence_window_does_not_emit_signal() {
        // 收敛窗口：gate 未 ready → 不构成冲突
        let violation = ConsistencyViolation {
            context: ctx(),
            snapshot_decision: decision(true, "snapshot"),
            realtime_decision: decision(false, "realtime"),
        };
        assert!(detect_conflict(&violation, Some(gate(false, 2, 0))).is_none());
        assert!(detect_conflict(&violation, None).is_none());
    }

    #[test]
    fn consistent_decisions_do_not_emit_signal() {
        let violation = ConsistencyViolation {
            context: ctx(),
            snapshot_decision: decision(true, "snapshot"),
            realtime_decision: decision(true, "realtime"),
        };
        assert!(detect_conflict(&violation, Some(gate(true, 2, 1))).is_none());
    }

    #[test]
    fn ready_mismatch_emits_signal() {
        let violation = ConsistencyViolation {
            context: ctx(),
            snapshot_decision: decision(true, "snapshot"),
            realtime_decision: decision(false, "realtime"),
        };
        let signal = detect_conflict(&violation, Some(gate(true, 2, 1)));
        let signal = signal.expect("ready mismatch must emit signal");
        assert_eq!(signal.kind, ConflictSignalKind::SnapshotRealtimeMismatch);
        assert_eq!(signal.snapshot_gate.unwrap().revoke_fence, 1);
        assert!(signal.snapshot_decision.allowed);
        assert!(!signal.realtime_decision.allowed);
    }

    // ===== arbitrate =====

    #[test]
    fn missing_evidence_defers() {
        let outcome = arbitrate(&ctx(), &[]);
        assert_eq!(outcome.verdict, ArbitrationVerdict::Defer);
        assert_eq!(outcome.reason_code, "EVIDENCE_MISSING");
    }

    #[test]
    fn no_provable_evidence_defers() {
        // 全部证据 gate 缺失或未 READY → 无法证明 → DEFER
        let evidence = vec![
            evidence("A", true, None),
            evidence("B", false, Some(gate(false, 1, 0))),
        ];
        let outcome = arbitrate(&ctx(), &evidence);
        assert_eq!(outcome.verdict, ArbitrationVerdict::Defer);
        assert_eq!(outcome.reason_code, "R4_UNPROVABLE");
    }

    #[test]
    fn newest_fence_deny_wins() {
        // A: gen105 ALLOW（旧版本，READY）；C: gen106 fence 推进后 DENY（最新 READY）
        let evidence = vec![
            evidence("A", true, Some(gate(true, 105, 0))),
            evidence("C", false, Some(gate(true, 106, 1))),
        ];
        let outcome = arbitrate(&ctx(), &evidence);
        assert_eq!(outcome.verdict, ArbitrationVerdict::Deny);
        assert_eq!(outcome.reason_code, "R1_FENCE_DENY");
    }

    #[test]
    fn unprovable_stale_allow_defers() {
        // 最新版本全 ALLOW，但存在 gate 缺失的旧 ALLOW → 无法排除复活 → DEFER
        let evidence = vec![
            evidence("A", true, None),
            evidence("B", true, Some(gate(true, 106, 1))),
            evidence("C", true, Some(gate(true, 106, 1))),
        ];
        let outcome = arbitrate(&ctx(), &evidence);
        assert_eq!(outcome.verdict, ArbitrationVerdict::Defer);
        assert_eq!(outcome.reason_code, "R2_STALE_ALLOW_UNPROVABLE");
    }

    #[test]
    fn majority_allow_when_version_agreed() {
        // 全部 READY 同版本：2 ALLOW 1 DENY → 多数 ALLOW
        let evidence = vec![
            evidence("A", true, Some(gate(true, 106, 1))),
            evidence("B", true, Some(gate(true, 106, 1))),
            evidence("C", false, Some(gate(true, 106, 1))),
        ];
        let outcome = arbitrate(&ctx(), &evidence);
        assert_eq!(outcome.verdict, ArbitrationVerdict::Allow);
        assert_eq!(outcome.reason_code, "R3_MAJORITY_ALLOW");
    }

    #[test]
    fn version_agreed_tie_fails_closed() {
        // 全部 READY 同版本：1 ALLOW 1 DENY → 非多数 → DENY（fail-closed）
        let evidence = vec![
            evidence("A", true, Some(gate(true, 106, 1))),
            evidence("C", false, Some(gate(true, 106, 1))),
        ];
        let outcome = arbitrate(&ctx(), &evidence);
        assert_eq!(outcome.verdict, ArbitrationVerdict::Deny);
        assert_eq!(outcome.reason_code, "R3_VERSION_AGREED_DIVERGED");
    }

    #[test]
    fn newest_allow_with_older_ready_allow_is_allowed() {
        // 旧 READY ALLOW（gen105）属于合法收敛窗口；最新版本全 ALLOW → ALLOW
        let evidence = vec![
            evidence("A", true, Some(gate(true, 105, 0))),
            evidence("B", true, Some(gate(true, 106, 0))),
            evidence("C", true, Some(gate(true, 106, 0))),
        ];
        let outcome = arbitrate(&ctx(), &evidence);
        assert_eq!(outcome.verdict, ArbitrationVerdict::Allow);
        assert_eq!(outcome.reason_code, "R2_NEWEST_ALLOW");
    }

    // ===== S12 / S13 分布式场景（Rust 纯函数侧） =====
    //
    // 场景卡见 Docs/实验/分布式测试/README.md：
    // - S12 conflictingDecisionArbitration：fence 已前进但旧节点仍产出 ALLOW →
    //   仲裁必须 DENY（I10：arbiter_fence_deny）。
    // - S13 arbiterUnavailableFailsClosed：证据不可收集/无法证明 → DEFER →
    //   调用方按 fail-closed 拒绝（I11：arbiter_unavailable_defers）。

    #[test]
    fn s12_conflicting_decision_arbitration_denies() {
        // S12：node-a 在 fence 前进后仍 ALLOW（stale，gen105 fence0），
        // node-c 已在 gen106 fence1 READY 上 DENY → 仲裁 DENY。
        let evidence = vec![
            evidence("A", true, Some(gate(true, 105, 0))),
            evidence("B", false, Some(gate(true, 106, 1))),
            evidence("C", false, Some(gate(true, 106, 1))),
        ];
        let outcome = arbitrate(&ctx(), &evidence);
        assert_eq!(outcome.verdict, ArbitrationVerdict::Deny);
        assert_eq!(outcome.reason_code, "R1_FENCE_DENY");
    }

    #[test]
    fn s13_arbiter_unavailable_fails_closed() {
        // S13：证据收集失败（空证据 / 全部 gate 不可读）→ DEFER；
        // 调用方必须把 DEFER 映射为拒绝（现有 AUTHORIZATION_PENDING 语义）。
        let missing = arbitrate(&ctx(), &[]);
        assert_eq!(missing.verdict, ArbitrationVerdict::Defer);
        assert_eq!(missing.reason_code, "EVIDENCE_MISSING");

        let unreadable = arbitrate(
            &ctx(),
            &[evidence("A", true, None), evidence("B", false, None)],
        );
        assert_eq!(unreadable.verdict, ArbitrationVerdict::Defer);
        assert_eq!(unreadable.reason_code, "R4_UNPROVABLE");
    }
}
