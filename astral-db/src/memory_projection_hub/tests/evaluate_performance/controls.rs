use super::super::*;
use super::fixture::*;
use policy_engine::{PolicyEngine, RuleRepository};
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

pub(super) async fn verify_controls() {
    let engine = PolicyEngine::new();
    let (mut hub, targets) = fixture(8);
    hub.assemblies = Arc::new(AssemblyCache::default());
    let scope = evidence_scope();
    let cold = serve(hub.try_memory_evidence_with_clock(&scope, || FIXED_SECOND, || {}));
    assert_eq!(hub.assemblies.hits(), 0);
    let warm = serve(hub.try_memory_evidence_with_clock(&scope, || FIXED_SECOND, || {}));
    assert_eq!(hub.assemblies.hits(), 1);
    assert_eq!(cold, warm);
    cold.validate().unwrap();
    let later = serve(hub.try_memory_evidence_with_clock(&scope, || FIXED_SECOND + 100, || {}));
    assert_eq!(hub.assemblies.hits(), 1);
    assert_ne!(cold.read_unix_seconds, later.read_unix_seconds);
    assert_eq!(cold.gate, later.gate);
    assert_eq!(cold.manifests, later.manifests);
    assert_eq!(cold.records, later.records);
    assert_eq!(cold.effective_grants, later.effective_grants);

    for target in [targets[0], targets[1], 999_999] {
        let mut baseline = None;
        for clock in [
            EvidenceClock::Cached,
            EvidenceClock::Forced,
            EvidenceClock::Production,
        ] {
            let (decision, counts) = checked_decision(&engine, &hub, clock, target).await;
            let allow = target != 999_999;
            assert_eq!(decision.allowed, allow);
            assert_eq!(
                decision.reason,
                if allow {
                    "PUBLISHED_EVIDENCE_ALLOW"
                } else {
                    "DEFAULT_DENY"
                }
            );
            assert_eq!(counts.card_checks, 1);
            assert_eq!(counts.org_reads, 1);
            assert_eq!(counts.evidence_reads, if allow { 2 } else { 1 });
            assert_eq!(counts.scoped_reads, counts.evidence_reads);
            assert_eq!(counts.evidence_grants, counts.evidence_reads * 8);
            assert!(counts.initial_evidence_ns > 0);
            assert_eq!(counts.final_evidence_ns > 0, allow);
            if let Some(expected) = &baseline {
                assert!(decisions_match(&decision, expected));
            } else {
                baseline = Some(decision);
            }
        }
    }

    let pending_hub = fixture(8).0;
    pending_hub.record_pending_delta(&pending_request(
        Some(17),
        DeltaEventType::Remove,
        2,
        2,
        true,
    ));
    for clock in [
        EvidenceClock::Cached,
        EvidenceClock::Forced,
        EvidenceClock::Production,
    ] {
        let (decision, counts) = checked_decision(&engine, &pending_hub, clock, targets[0]).await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
        assert_eq!(counts.evidence_reads, 1);
        assert_eq!(counts.evidence_grants, 0);
        assert_eq!(counts.final_evidence_ns, 0);
    }

    let expiry_hub = hub_from_grants(vec![CanonicalGrant {
        validity: ValidityWindow::between(FIXED_SECOND, FIXED_SECOND + 1),
        ..grant(1)
    }]);
    let (before, counts) =
        checked_decision(&engine, &expiry_hub, EvidenceClock::Fixed(FIXED_SECOND), 1).await;
    assert!(before.allowed);
    assert_eq!(counts.evidence_reads, 2);
    let (after, counts) = checked_decision(
        &engine,
        &expiry_hub,
        EvidenceClock::Fixed(FIXED_SECOND + 1),
        1,
    )
    .await;
    assert!(!after.allowed);
    assert_eq!(after.reason, "DEFAULT_DENY");
    assert_eq!(counts.evidence_reads, 1);
    let (crossing, counts) = checked_decision(
        &engine,
        &expiry_hub,
        EvidenceClock::FinalSecond(FIXED_SECOND, FIXED_SECOND + 1),
        1,
    )
    .await;
    assert!(!crossing.allowed);
    assert_eq!(crossing.reason, "AUTHORIZATION_PENDING");
    assert_eq!(counts.evidence_reads, 2);

    for clock in [
        EvidenceClock::Cached,
        EvidenceClock::Forced,
        EvidenceClock::Production,
    ] {
        let revoke_hub = fixture(8).0;
        let ticks = AtomicI64::new(FIXED_SECOND + 100);
        let repo = RevokeBeforeFinal {
            inner: EvaluationProbe::new(&revoke_hub, clock, &ticks),
            hub: &revoke_hub,
            reads: AtomicUsize::new(0),
        };
        repo.inner.begin_decision();
        let decision = engine.evaluate(&context(targets[0]), &repo).await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
        assert_eq!(repo.reads.load(Ordering::Relaxed), 2);
        assert_eq!(repo.inner.counts().evidence_reads, 2);
    }
}

struct RevokeBeforeFinal<'a> {
    inner: EvaluationProbe<'a>,
    hub: &'a MemoryProjectionHub,
    reads: AtomicUsize,
}

#[async_trait::async_trait]
impl RuleRepository for RevokeBeforeFinal<'_> {
    async fn check_card_active(
        &self,
        ctx: &astral_types::PolicyContext,
    ) -> Result<bool, astral_types::PolicyError> {
        self.inner.check_card_active(ctx).await
    }

    async fn load_org_authorization(
        &self,
        ctx: &astral_types::PolicyContext,
    ) -> Result<policy_engine::org_admission::OrgAuthorityRead, astral_types::PolicyError> {
        self.inner.load_org_authorization(ctx).await
    }

    async fn load_permission_rules(
        &self,
        _card_id: i64,
    ) -> Result<Vec<policy_engine::PermissionRule>, astral_types::PolicyError> {
        panic!("revoke control must not read legacy rules")
    }

    fn requires_published_card_evidence(&self) -> bool {
        true
    }

    async fn load_published_card_authorization(
        &self,
        scope: &PublishedCardEvidenceScope,
    ) -> Result<Option<PublishedCardAuthorization>, astral_types::PolicyError> {
        if self.reads.fetch_add(1, Ordering::Relaxed) == 1 {
            publish_revoke(self.hub);
        }
        self.inner.load_published_card_authorization(scope).await
    }
}

#[tokio::test]
async fn policy_evaluate_benefit_controls_preserve_decisions_and_fences() {
    verify_controls().await;
}
