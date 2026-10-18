use super::super::*;
use astral_types::{PolicyContext, PolicyDecision, PolicyError, ResourceOwnershipScope};
use policy_engine::{org_admission::OrgAuthorityRead, PolicyEngine, RuleRepository};
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};

pub(super) const FIXED_SECOND: i64 = 1_000_000_000;

#[derive(Clone, Copy)]
pub(super) enum EvidenceClock {
    Cached,
    Forced,
    Production,
    Fixed(i64),
    FinalSecond(i64, i64),
}

#[derive(Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ReadCounts {
    pub card_checks: usize,
    pub org_reads: usize,
    pub evidence_reads: usize,
    pub scoped_reads: usize,
    pub evidence_grants: usize,
    pub initial_evidence_ns: u64,
    pub final_evidence_ns: u64,
}

impl ReadCounts {
    pub fn add(&mut self, next: Self) {
        self.card_checks += next.card_checks;
        self.org_reads += next.org_reads;
        self.evidence_reads += next.evidence_reads;
        self.scoped_reads += next.scoped_reads;
        self.evidence_grants += next.evidence_grants;
        self.initial_evidence_ns += next.initial_evidence_ns;
        self.final_evidence_ns += next.final_evidence_ns;
    }
}

pub(super) struct EvaluationProbe<'a> {
    hub: &'a MemoryProjectionHub,
    clock: EvidenceClock,
    ticks: &'a AtomicI64,
    phase: AtomicUsize,
    card_checks: AtomicUsize,
    org_reads: AtomicUsize,
    evidence_reads: AtomicUsize,
    scoped_reads: AtomicUsize,
    evidence_grants: AtomicUsize,
    initial_ns: AtomicU64,
    final_ns: AtomicU64,
}

impl<'a> EvaluationProbe<'a> {
    pub fn new(hub: &'a MemoryProjectionHub, clock: EvidenceClock, ticks: &'a AtomicI64) -> Self {
        Self {
            hub,
            clock,
            ticks,
            phase: AtomicUsize::new(0),
            card_checks: AtomicUsize::new(0),
            org_reads: AtomicUsize::new(0),
            evidence_reads: AtomicUsize::new(0),
            scoped_reads: AtomicUsize::new(0),
            evidence_grants: AtomicUsize::new(0),
            initial_ns: AtomicU64::new(0),
            final_ns: AtomicU64::new(0),
        }
    }

    pub fn begin_decision(&self) {
        self.phase.store(0, Ordering::Relaxed);
    }

    pub fn decision_reads(&self) -> usize {
        self.phase.load(Ordering::Relaxed)
    }

    pub fn counts(&self) -> ReadCounts {
        ReadCounts {
            card_checks: self.card_checks.load(Ordering::Relaxed),
            org_reads: self.org_reads.load(Ordering::Relaxed),
            evidence_reads: self.evidence_reads.load(Ordering::Relaxed),
            scoped_reads: self.scoped_reads.load(Ordering::Relaxed),
            evidence_grants: self.evidence_grants.load(Ordering::Relaxed),
            initial_evidence_ns: self.initial_ns.load(Ordering::Relaxed),
            final_evidence_ns: self.final_ns.load(Ordering::Relaxed),
        }
    }
}

#[async_trait::async_trait]
impl RuleRepository for EvaluationProbe<'_> {
    async fn check_card_active(&self, ctx: &PolicyContext) -> Result<bool, PolicyError> {
        self.card_checks.fetch_add(1, Ordering::Relaxed);
        Ok(ctx.user_id == Some(42)
            && ctx.principal_kind.as_deref() == Some("PLATFORM_USER")
            && ctx.identity_card_id == Some(18)
            && ctx.card_id == Some(17)
            && ctx.tenant_id == Some(7)
            && ctx.domain_id == Some(11))
    }

    async fn load_org_authorization(
        &self,
        _ctx: &PolicyContext,
    ) -> Result<OrgAuthorityRead, PolicyError> {
        self.org_reads.fetch_add(1, Ordering::Relaxed);
        Ok(OrgAuthorityRead::Unmanaged)
    }

    async fn load_permission_rules(
        &self,
        _card_id: i64,
    ) -> Result<Vec<policy_engine::PermissionRule>, PolicyError> {
        panic!("strict evaluation benchmark must not read legacy permission rules")
    }

    async fn load_rule_set_snapshots(
        &self,
        _card_id: i64,
    ) -> Result<Vec<policy_engine::RuleSetSnapshot>, PolicyError> {
        panic!("strict evaluation benchmark must not read legacy snapshots")
    }

    async fn load_snapshot_winners(
        &self,
        _card_id: i64,
    ) -> Result<Vec<policy_engine::SnapshotWinner>, PolicyError> {
        panic!("strict evaluation benchmark must not read legacy winners")
    }

    async fn load_rule_set_dependency_statuses(
        &self,
        _card_id: i64,
    ) -> Result<Option<Vec<policy_engine::RuleSetDependencyStatus>>, PolicyError> {
        panic!("strict evaluation benchmark must not read legacy dependencies")
    }

    async fn get_projection_gate(
        &self,
        _card_id: i64,
    ) -> Result<Option<policy_engine::ProjectionGate>, PolicyError> {
        panic!("strict evaluation benchmark must not read legacy projection gates")
    }

    async fn load_rule_set_entries_raw(
        &self,
        _card_id: i64,
    ) -> Result<Vec<policy_engine::RuleSetSnapshot>, PolicyError> {
        panic!("strict evaluation benchmark must not read raw rulesets")
    }

    async fn load_permission_rules_raw(
        &self,
        _card_id: i64,
    ) -> Result<Vec<policy_engine::PermissionRule>, PolicyError> {
        panic!("strict evaluation benchmark must not read raw permission rules")
    }

    async fn load_projected_delegated_rules(
        &self,
        _delegate_id: i64,
        _resource: &str,
        _action: &str,
    ) -> Result<Vec<policy_engine::PermissionRule>, PolicyError> {
        panic!("strict evaluation benchmark must not read legacy delegations")
    }

    async fn load_delegated_rules(
        &self,
        _delegate_id: i64,
        _resource: &str,
        _action: &str,
    ) -> Result<Vec<policy_engine::PermissionRule>, PolicyError> {
        panic!("strict evaluation benchmark must not read raw delegations")
    }

    fn requires_published_card_evidence(&self) -> bool {
        true
    }

    async fn load_published_card_authorization(
        &self,
        request: &PublishedCardEvidenceScope,
    ) -> Result<Option<PublishedCardAuthorization>, PolicyError> {
        let phase = self.phase.fetch_add(1, Ordering::Relaxed);
        assert!(phase < 2, "unexpected third evidence read");
        self.evidence_reads.fetch_add(1, Ordering::Relaxed);
        assert_eq!(request, &evidence_scope());
        self.scoped_reads.fetch_add(1, Ordering::Relaxed);
        let started = Instant::now();
        // Every arm pays the same shared counter cost; only Forced uses its value.
        let tick = self.ticks.fetch_add(1, Ordering::Relaxed);
        let outcome = match self.clock {
            EvidenceClock::Production => self.hub.try_memory_evidence(request),
            clock => {
                let second = match clock {
                    EvidenceClock::Cached => FIXED_SECOND,
                    EvidenceClock::Forced => tick,
                    EvidenceClock::Fixed(second) => second,
                    EvidenceClock::FinalSecond(initial, final_second) => {
                        if phase == 0 {
                            initial
                        } else {
                            final_second
                        }
                    }
                    EvidenceClock::Production => unreachable!(),
                };
                self.hub
                    .try_memory_evidence_with_clock(request, || second, || {})
            }
        };
        let nanos = u64::try_from(started.elapsed().as_nanos()).unwrap();
        if phase == 0 {
            self.initial_ns.fetch_add(nanos, Ordering::Relaxed);
        } else {
            self.final_ns.fetch_add(nanos, Ordering::Relaxed);
        }
        match outcome {
            MemoryEvidenceOutcome::Serve(evidence) => {
                self.evidence_grants
                    .fetch_add(evidence.effective_grants.len(), Ordering::Relaxed);
                Ok(Some(evidence))
            }
            MemoryEvidenceOutcome::DeferToDurable => Err(PolicyError::Repository(
                "published_card_evidence_not_ready;code=evaluate_benchmark_deferred".into(),
            )),
        }
    }
}

pub(super) fn evidence_scope() -> PublishedCardEvidenceScope {
    PublishedCardEvidenceScope {
        domain: DomainScopeRequirement::ExactlySome(11),
        ..scope()
    }
}

pub(super) fn context(target_id: i64) -> PolicyContext {
    PolicyContext::builder()
        .user_id(Some(42))
        .principal_kind(Some("PLATFORM_USER".into()))
        .identity_card_id(Some(18))
        .card_id(Some(17))
        .tenant_id(Some(7))
        .domain_id(Some(11))
        .resource_ownership_scope(ResourceOwnershipScope::TenantScoped)
        .resource_tenant_id(Some(7))
        .resource_domain_id(Some(11))
        .action("read".into())
        .resource(Some("learn_subject".into()))
        .target_id(Some(target_id))
        .build()
}

pub(super) fn fixture(grants: u16) -> (MemoryProjectionHub, [i64; 2]) {
    let values = (0..grants)
        .map(|index| CanonicalGrant {
            resource: format!("learn_subject:{}", 10_000 + i64::from(index)),
            ..grant(index)
        })
        .collect();
    let hub = hub_from_grants(values);
    let evidence =
        serve(hub.try_memory_evidence_with_clock(&evidence_scope(), || FIXED_SECOND, || {}));
    assert_eq!(evidence.effective_grants.len(), usize::from(grants));
    let target =
        |grant: &CanonicalGrant| grant.resource.split_once(':').unwrap().1.parse().unwrap();
    let targets = [
        target(&evidence.effective_grants[0]),
        target(evidence.effective_grants.last().unwrap()),
    ];
    (hub, targets)
}

pub(super) fn hub_from_grants(values: Vec<CanonicalGrant>) -> MemoryProjectionHub {
    let hub = MemoryProjectionHub::default();
    let hot =
        policy_engine::HotState::from_grants(tenant(), 1, values, dependency_vector()).unwrap();
    hub.install_published_state(seal_state(&card_identity(), 17, 1, hot, None, 0));
    hub
}

pub(super) fn publish_revoke(hub: &MemoryProjectionHub) {
    let hot =
        policy_engine::HotState::from_grants(tenant(), 2, vec![], dependency_vector()).unwrap();
    install_committed(hub, seal_state(&card_identity(), 17, 2, hot, Some(1), 2));
}

pub(super) async fn checked_decision(
    engine: &PolicyEngine,
    hub: &MemoryProjectionHub,
    clock: EvidenceClock,
    target: i64,
) -> (PolicyDecision, ReadCounts) {
    let ticks = AtomicI64::new(FIXED_SECOND + 100);
    let repo = EvaluationProbe::new(hub, clock, &ticks);
    repo.begin_decision();
    let decision = engine.evaluate(&context(target), &repo).await;
    (decision, repo.counts())
}

pub(super) fn decisions_match(actual: &PolicyDecision, expected: &PolicyDecision) -> bool {
    actual.allowed == expected.allowed
        && actual.reason == expected.reason
        && actual.matched_rule == expected.matched_rule
        && actual.audit_required == expected.audit_required
        && actual.matched_rule_id == expected.matched_rule_id
        && actual.snapshot_version == expected.snapshot_version
        && actual.org_provenance.is_none()
        && expected.org_provenance.is_none()
        && actual.condition_results.is_none()
        && expected.condition_results.is_none()
        && actual.evaluation_path.len() == expected.evaluation_path.len()
        && actual
            .evaluation_path
            .iter()
            .zip(&expected.evaluation_path)
            .all(|(a, b)| {
                a.phase == b.phase
                    && a.result == b.result
                    && a.detail == b.detail
                    && a.matched_rule_id == b.matched_rule_id
                    && a.source == b.source
            })
}
