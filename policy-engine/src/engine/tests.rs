//! memory—v1 fail-closed engine tests.
//!
//! The legacy CURRENT V6/V7 chain tests (gate walking, published-evidence
//! matching, ORG_SCOPE admission, authorization-fence proofs, breaker
//! accounting) were retired together with the chain they asserted. These tests
//! pin the replacement contract: every formal evaluation fails closed without
//! consulting the repository, regardless of how permissive the repository
//! would be.

use std::sync::atomic::{AtomicUsize, Ordering};

use super::ports::{PublishedEvidenceReadMode, RuleRepository};
use super::*;
use crate::engine::PolicyEvaluation;
use astral_types::org_scope::OrgAdmissionEvidence;
use astral_types::{
    AuthorizationFenceProof, CertifiedAuthorizationState, PolicyContext, PolicyDecision,
    PolicyError, PublishedCardAuthorization, PublishedCardEvidenceScope,
};
use std::sync::Arc;

/// The most permissive repository configuration the old chain could consume:
/// active card, active global admin, certified-memory read mode, ready
/// reconciliation, and fall-through ORG unmanaged state. Every method counts
/// its calls so the tests can prove the retired engine reads none of them.
struct PermissiveCountingRepo {
    card_active_calls: AtomicUsize,
    global_admin_calls: AtomicUsize,
    fence_calls: AtomicUsize,
    request_fence_calls: AtomicUsize,
    org_fence_calls: AtomicUsize,
    org_fence_certificate_calls: AtomicUsize,
    certify_calls: AtomicUsize,
    published_evidence_calls: AtomicUsize,
    org_authorization_calls: AtomicUsize,
}

impl PermissiveCountingRepo {
    fn new() -> Self {
        Self {
            card_active_calls: AtomicUsize::new(0),
            global_admin_calls: AtomicUsize::new(0),
            fence_calls: AtomicUsize::new(0),
            request_fence_calls: AtomicUsize::new(0),
            org_fence_calls: AtomicUsize::new(0),
            org_fence_certificate_calls: AtomicUsize::new(0),
            certify_calls: AtomicUsize::new(0),
            published_evidence_calls: AtomicUsize::new(0),
            org_authorization_calls: AtomicUsize::new(0),
        }
    }

    fn assert_never_consulted(&self) {
        assert_eq!(
            self.card_active_calls.load(Ordering::SeqCst),
            0,
            "card context read"
        );
        assert_eq!(
            self.global_admin_calls.load(Ordering::SeqCst),
            0,
            "global admin read"
        );
        assert_eq!(
            self.fence_calls.load(Ordering::SeqCst),
            0,
            "scope fence read"
        );
        assert_eq!(
            self.request_fence_calls.load(Ordering::SeqCst),
            0,
            "request fence read"
        );
        assert_eq!(
            self.org_fence_calls.load(Ordering::SeqCst),
            0,
            "org fence read"
        );
        assert_eq!(
            self.org_fence_certificate_calls.load(Ordering::SeqCst),
            0,
            "org fence certificate read"
        );
        assert_eq!(
            self.certify_calls.load(Ordering::SeqCst),
            0,
            "evidence certification"
        );
        assert_eq!(
            self.published_evidence_calls.load(Ordering::SeqCst),
            0,
            "published evidence read"
        );
        assert_eq!(
            self.org_authorization_calls.load(Ordering::SeqCst),
            0,
            "org authorization read"
        );
    }
}

#[async_trait::async_trait]
impl RuleRepository for PermissiveCountingRepo {
    async fn check_card_active(&self, _ctx: &PolicyContext) -> Result<bool, PolicyError> {
        self.card_active_calls.fetch_add(1, Ordering::SeqCst);
        Ok(true)
    }

    async fn is_active_global_admin(&self, _user_id: i64) -> Result<bool, PolicyError> {
        self.global_admin_calls.fetch_add(1, Ordering::SeqCst);
        Ok(true)
    }

    fn published_evidence_read_mode(&self) -> PublishedEvidenceReadMode {
        PublishedEvidenceReadMode::CertifiedMemory
    }

    fn positive_authorization_ready(&self) -> bool {
        true
    }

    async fn read_authorization_fence(
        &self,
        _scope: &PublishedCardEvidenceScope,
        _request_nonce: &str,
    ) -> Result<AuthorizationFenceProof, PolicyError> {
        self.fence_calls.fetch_add(1, Ordering::SeqCst);
        Err(PolicyError::Repository("fence unavailable".to_owned()))
    }

    async fn read_request_authorization_fence(
        &self,
        _context: &PolicyContext,
        _scope: &PublishedCardEvidenceScope,
        _request_nonce: &str,
    ) -> Result<AuthorizationFenceProof, PolicyError> {
        self.request_fence_calls.fetch_add(1, Ordering::SeqCst);
        Err(PolicyError::Repository("fence unavailable".to_owned()))
    }

    async fn read_org_authorization_fence(
        &self,
        _context: &PolicyContext,
        _evidence: &OrgAdmissionEvidence,
        _request_nonce: &str,
    ) -> Result<AuthorizationFenceProof, PolicyError> {
        self.org_fence_calls.fetch_add(1, Ordering::SeqCst);
        Err(PolicyError::Repository("fence unavailable".to_owned()))
    }

    async fn read_org_authorization_fence_with_certificate(
        &self,
        _context: &PolicyContext,
        _evidence: &OrgAdmissionEvidence,
        _request_nonce: &str,
    ) -> Result<super::ports::OrgAuthorityFenceRead, PolicyError> {
        self.org_fence_certificate_calls
            .fetch_add(1, Ordering::SeqCst);
        Err(PolicyError::Repository(
            "certificate unavailable".to_owned(),
        ))
    }

    fn certify_authorization_evidence(
        &self,
        _proof: AuthorizationFenceProof,
        _evidence: Arc<PublishedCardAuthorization>,
        _scope: &PublishedCardEvidenceScope,
        _now_seconds: i64,
    ) -> Result<CertifiedAuthorizationState, PolicyError> {
        self.certify_calls.fetch_add(1, Ordering::SeqCst);
        Err(PolicyError::Repository("certifier unavailable".to_owned()))
    }

    async fn load_published_card_authorization(
        &self,
        _scope: &PublishedCardEvidenceScope,
    ) -> Result<Option<Arc<PublishedCardAuthorization>>, PolicyError> {
        self.published_evidence_calls.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }

    async fn load_org_authorization(
        &self,
        _ctx: &PolicyContext,
    ) -> Result<crate::org_admission::OrgAuthorityRead, PolicyError> {
        self.org_authorization_calls.fetch_add(1, Ordering::SeqCst);
        Ok(crate::org_admission::OrgAuthorityRead::Unmanaged)
    }
}

/// Complete PLATFORM context: the strongest identity the old chain accepted.
fn full_ctx() -> PolicyContext {
    PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .tenant_id(Some(7))
        .domain_id(Some(11))
        .action("read".into())
        .resource(Some("learn_subject".into()))
        .target_id(Some(42))
        .build()
}

fn assert_retired_pending(decision: &PolicyDecision) {
    assert!(
        !decision.allowed,
        "retired engine must never allow: {decision:?}"
    );
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    assert!(
        decision.audit_required,
        "fail-closed pending stays auditable"
    );
    assert!(
        decision
            .matched_rule
            .as_deref()
            .is_some_and(|rule| rule.contains("legacy_formal_evaluation_retired")),
        "decision must carry the retirement marker: {decision:?}"
    );
    let last = decision
        .evaluation_path
        .last()
        .expect("retirement decision must carry an audit step");
    assert_eq!(last.phase, "FORMAL_EVALUATION");
    assert_eq!(last.result, astral_types::Effect::Deny);
    assert!(decision.org_provenance.is_none());
    assert!(decision.snapshot_version.is_none());
}

#[tokio::test]
async fn evaluate_fails_closed_without_consulting_a_permissive_repository() {
    let repo = PermissiveCountingRepo::new();
    let decision = PolicyEngine::new().evaluate(&full_ctx(), &repo).await;

    assert_retired_pending(&decision);
    repo.assert_never_consulted();
}

#[tokio::test]
async fn evaluate_with_admission_is_pending_and_never_certifies_a_capability() {
    let repo = PermissiveCountingRepo::new();
    let evaluation: PolicyEvaluation = PolicyEngine::new()
        .evaluate_with_admission(&full_ctx(), &repo)
        .await;

    assert_retired_pending(&evaluation.decision);
    assert!(
        evaluation.admission().is_none(),
        "retired evaluator must not mint an admission capability"
    );
    let (decision, admission) = evaluation.into_parts();
    assert_retired_pending(&decision);
    assert!(admission.is_none());
    repo.assert_never_consulted();
}

#[tokio::test]
async fn incomplete_context_receives_the_same_fail_closed_pending() {
    // The old AUTHN/CARD_CONTEXT/RESOURCE gate walk is retired; every context
    // shape lands on the identical retirement outcome.
    let repo = PermissiveCountingRepo::new();
    let engine = PolicyEngine::new();

    let empty = PolicyContext::builder().action(String::new()).build();
    assert_retired_pending(&engine.evaluate(&empty, &repo).await);

    let no_card = PolicyContext::builder()
        .user_id(Some(1))
        .action("read".into())
        .build();
    assert_retired_pending(&engine.evaluate(&no_card, &repo).await);

    let blank_action = PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .tenant_id(Some(7))
        .action(String::new())
        .build();
    assert_retired_pending(&engine.evaluate(&blank_action, &repo).await);

    repo.assert_never_consulted();
}

#[tokio::test]
async fn simulate_follows_the_same_fail_closed_entry() {
    let repo = PermissiveCountingRepo::new();
    let engine = PolicyEngine::new();
    let simulated = engine.simulate(&full_ctx(), &repo).await;
    let formal = engine.evaluate(&full_ctx(), &repo).await;

    assert_retired_pending(&simulated);
    assert_eq!(simulated.reason, formal.reason);
    assert_eq!(simulated.matched_rule, formal.matched_rule);
    repo.assert_never_consulted();
}

#[tokio::test]
async fn retired_evaluations_are_counted_as_denials_with_total_time_only() {
    let repo = PermissiveCountingRepo::new();
    let engine = PolicyEngine::new();

    for _ in 0..3 {
        engine.evaluate(&full_ctx(), &repo).await;
    }

    let stats = engine.get_stats();
    assert_eq!(stats.evaluation_count, 3);
    assert_eq!(stats.deny_count, 3);
    assert_eq!(
        stats.allow_count, 0,
        "retired engine must never record an allow"
    );
    assert_eq!(
        stats.timing_ns.card_context_check_ns
            + stats.timing_ns.initial_evidence_load_ns
            + stats.timing_ns.final_evidence_reload_ns
            + stats.timing_ns.evidence_match_ns,
        0,
        "retired chain phases must not report timings"
    );
    assert!(
        stats.timing_ns.total_ns > 0,
        "total wall time stays observable"
    );
    repo.assert_never_consulted();

    engine.reset_stats();
    let stats = engine.get_stats();
    assert_eq!(stats.evaluation_count, 0);
    assert_eq!(stats.deny_count, 0);
}

#[tokio::test]
async fn allow_source_phase_is_none_for_retired_pending_decisions() {
    let repo = PermissiveCountingRepo::new();
    let decision = PolicyEngine::new().evaluate(&full_ctx(), &repo).await;

    assert!(PolicyEngine::allow_source_phase(&decision).is_none());
    assert!(PolicyEngine::allow_source_phase(&PolicyEngine::authorization_pending("x")).is_none());
    repo.assert_never_consulted();
}

#[tokio::test]
async fn circuit_breaker_no_longer_gates_formal_evaluation() {
    let repo = PermissiveCountingRepo::new();
    let engine = PolicyEngine::new();

    for _ in 0..10 {
        assert_retired_pending(&engine.evaluate(&full_ctx(), &repo).await);
    }
    assert_eq!(
        engine.circuit_breaker_state(),
        crate::CircuitBreakerState::Closed,
        "fail-closed pending without dependency reads must not fabricate failures"
    );

    engine.force_open_circuit_breaker();
    assert_eq!(
        engine.circuit_breaker_state(),
        crate::CircuitBreakerState::Open
    );
    assert_retired_pending(&engine.evaluate(&full_ctx(), &repo).await);
    repo.assert_never_consulted();
}

#[test]
fn authorization_pending_is_the_stable_fail_closed_constructor() {
    let decision = PolicyEngine::authorization_pending("dependency-unavailable");
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    assert_eq!(
        decision.matched_rule.as_deref(),
        Some("dependency-unavailable")
    );
    assert!(decision.audit_required);
    assert!(decision.evaluation_path.is_empty());
}
