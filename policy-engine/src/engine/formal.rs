//! memory—v1 fail-closed formal authorization entry points.
//!
//! The legacy CURRENT V6/V7 execution chain (AUTHN → CARD_CONTEXT → ownership
//! → GlobalAdmin → ORG_SCOPE admission → published CARD evidence, with its
//! authorization-fence proofs and ALLOW-time rechecks) has been physically
//! retired per `memory-v1-retire-legacy-read-20261112` (Rust 规范 §15.10)。
//! Positive authorization is reserved for the memory-v1 shared root; until that
//! contract completes adoption, every formal evaluation fails closed and no
//! repository method is consulted.

use astral_types::{Effect, EvaluationStep, PolicyContext, PolicyDecision};

use super::ports::RuleRepository;
use super::PolicyEngine;
use crate::hit_stats::TimingBreakdown;

impl PolicyEngine {
    /// memory—v1: Evaluate one request through the fail-closed formal entry.
    ///
    /// The legacy V6/V7 gate-and-evidence chain is retired; the engine reads no
    /// repository state and always returns `AUTHORIZATION_PENDING`. Missing,
    /// stale, or retired evaluation capability never expands authority.
    pub async fn evaluate<R: RuleRepository>(
        &self,
        ctx: &PolicyContext,
        repo: &R,
    ) -> PolicyDecision {
        self.evaluate_with_admission(ctx, repo).await.decision
    }

    /// memory—v1: Evaluate a request and retain the admission slot for the
    /// future memory-v1 positive path. The retired evaluator never certifies an
    /// admission, so `admission()` is always `None` for now. Existing callers
    /// keep receiving the serializable decision via `evaluate`.
    pub async fn evaluate_with_admission<R: RuleRepository>(
        &self,
        ctx: &PolicyContext,
        _repo: &R,
    ) -> crate::engine::PolicyEvaluation {
        let start = std::time::Instant::now();
        // Fail-closed: no gate walk, no evidence read, no fence proof, and no
        // dependency failure accounting — the retired engine has no dependency
        // reads to fail. The request is still counted as a completed
        // non-allowing evaluation for observability.
        let decision = Self::retired_evaluation_pending(ctx);
        let timing = TimingBreakdown {
            total_ns: start.elapsed().as_nanos() as u64,
            ..TimingBreakdown::default()
        };
        self.record_evaluation(false, &timing);
        crate::engine::PolicyEvaluation::without_admission(decision)
    }

    /// memory—v1: Build the auditable retirement decision for one request.
    fn retired_evaluation_pending(ctx: &PolicyContext) -> PolicyDecision {
        PolicyDecision {
            allowed: false,
            reason: "AUTHORIZATION_PENDING".to_owned(),
            matched_rule: Some("policy_engine:legacy_formal_evaluation_retired".to_owned()),
            audit_required: true,
            evaluation_path: vec![EvaluationStep {
                phase: "FORMAL_EVALUATION".to_owned(),
                result: Effect::Deny,
                detail: format!(
                    "legacy V6/V7 formal evaluation chain retired (memory—v1); fail-closed pending, resource={}",
                    ctx.resource.as_deref().unwrap_or("")
                ),
                matched_rule_id: None,
                source: None,
            }],
            matched_rule_id: None,
            condition_results: None,
            snapshot_version: None,
            org_provenance: None,
        }
    }

    /// Return the stable source category for an ALLOW decision.
    ///
    /// memory—v1: the retired evaluator never returns ALLOW, so this currently
    /// yields `None` for every decision the engine can produce; the classifier
    /// is kept for the memory-v1 positive path and existing callers.
    pub fn allow_source_phase(decision: &PolicyDecision) -> Option<&'static str> {
        if !decision.allowed {
            return None;
        }
        decision
            .evaluation_path
            .iter()
            .rev()
            .find(|step| step.result == astral_types::Effect::Allow)
            .and_then(|step| {
                if step.phase == "PUBLISHED_EVIDENCE" {
                    return match step.source.as_deref() {
                        Some("RULE_SET_BASE") | Some("RULE_SET_OVERLAY") | Some("RULE_SET") => {
                            Some("RULE_SET")
                        }
                        Some("DIRECT") => Some("DIRECT"),
                        Some("APPROVAL") => Some("APPROVAL"),
                        Some("DELEGATION") => Some("DELEGATION"),
                        _ => None,
                    };
                }
                match step.phase.as_str() {
                    "ORG_AUTHORITY" => Some("ORG_AUTHORITY"),
                    _ => None,
                }
            })
    }

    /// memory—v1: Simulated permission evaluation follows the same fail-closed
    /// formal entry; simulation can never mint an ALLOW the formal path would
    /// not mint.
    pub async fn simulate<R: RuleRepository>(
        &self,
        ctx: &PolicyContext,
        repo: &R,
    ) -> PolicyDecision {
        self.evaluate(ctx, repo).await
    }
}
