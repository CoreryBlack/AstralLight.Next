use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use astral_types::{
    BindingLayer, CanonicalGrant, DomainScopeRequirement, Effect, GrantEffect, GrantId,
    GrantProvenance, GrantRevision, GrantSourceKind, GrantState, PolicyContext, PolicyDecision,
    PolicyError, PublishedAggregateManifestSummary, PublishedCardAuthorization,
    PublishedCardAuthorizationGate, PublishedCardEvidenceScope, PublishedEvidenceGateStatus,
    TenantScope, ValidityWindow, VerifiedPublishedGrantRecord,
};
use policy_engine::{
    PermissionRule, ProjectionGate, RuleRepository, RuleSetSnapshot, SnapshotWinner,
};

#[derive(Clone, Copy)]
enum ReadMode {
    Ready,
    Unavailable,
    Unpublished,
}

struct RepoState {
    evidence: HashMap<(i64, i64), PublishedCardAuthorization>,
    mode: ReadMode,
    card_active: AtomicBool,
    published_reads: AtomicUsize,
    legacy_reads: AtomicUsize,
    scope_samples: Mutex<Vec<PublishedCardEvidenceScope>>,
    scope_record_limit: usize,
}

/// Test-only repository for the current published-evidence authorization path.
///
/// Evidence is indexed by the authoritative tenant/card pair. The fixture models
/// published evidence; it is not a durable publication proof and never performs I/O.
#[derive(Clone)]
pub struct PublishedRepo {
    state: Arc<RepoState>,
}

impl PublishedRepo {
    pub fn from_grants(grants: Vec<CanonicalGrant>) -> Self {
        Self::from_grants_with_scope_limit(grants, 64)
    }

    pub fn from_evidence(evidence: Vec<PublishedCardAuthorization>) -> Self {
        let evidence = evidence
            .into_iter()
            .map(|value| {
                assert!(
                    value.validate().is_ok(),
                    "fixture evidence must satisfy its contract"
                );
                ((value.tenant_id, value.card_id), value)
            })
            .collect();
        Self::from_evidence_map_with_scope_limit(evidence, ReadMode::Ready, true, 64)
    }

    pub fn from_grants_without_scope_recording(grants: Vec<CanonicalGrant>) -> Self {
        Self::from_grants_with_scope_limit(grants, 0)
    }

    pub fn from_evidence_without_scope_recording(
        evidence: Vec<PublishedCardAuthorization>,
    ) -> Self {
        let evidence = evidence
            .into_iter()
            .map(|value| {
                assert!(
                    value.validate().is_ok(),
                    "fixture evidence must satisfy its contract"
                );
                ((value.tenant_id, value.card_id), value)
            })
            .collect();
        Self::from_evidence_map_with_scope_limit(evidence, ReadMode::Ready, true, 0)
    }

    pub fn ready_empty_without_scope_recording(tenant_id: i64, card_id: i64) -> Self {
        let mut evidence = HashMap::new();
        evidence.insert(
            (tenant_id, card_id),
            ready_evidence(tenant_id, card_id, vec![]),
        );
        Self::from_evidence_map_with_scope_limit(evidence, ReadMode::Ready, true, 0)
    }

    pub fn missing() -> Self {
        Self::from_evidence_map(HashMap::new(), ReadMode::Unavailable, true)
    }

    pub fn unavailable_without_scope_recording() -> Self {
        Self::from_evidence_map_with_scope_limit(HashMap::new(), ReadMode::Unavailable, true, 0)
    }

    pub fn unpublished(tenant_id: i64, card_id: i64) -> Self {
        let mut evidence = HashMap::new();
        evidence.insert(
            (tenant_id, card_id),
            ready_evidence(tenant_id, card_id, vec![]),
        );
        Self::from_evidence_map(evidence, ReadMode::Unpublished, true)
    }

    pub fn inactive_with_evidence(grants: Vec<CanonicalGrant>) -> Self {
        let repo = Self::from_grants(grants);
        repo.state.card_active.store(false, Ordering::SeqCst);
        repo
    }

    fn from_grants_with_scope_limit(
        grants: Vec<CanonicalGrant>,
        scope_record_limit: usize,
    ) -> Self {
        let mut grouped: HashMap<(i64, i64), Vec<CanonicalGrant>> = HashMap::new();
        for grant in grants {
            assert!(
                grant.validate().is_ok(),
                "fixture grant must satisfy its contract"
            );
            grouped
                .entry((grant.tenant.tenant_id, grant.card_id))
                .or_default()
                .push(grant);
        }
        let evidence = grouped
            .into_iter()
            .map(|((tenant_id, card_id), grants)| {
                (
                    (tenant_id, card_id),
                    ready_evidence(tenant_id, card_id, grants),
                )
            })
            .collect();
        Self::from_evidence_map_with_scope_limit(
            evidence,
            ReadMode::Ready,
            true,
            scope_record_limit,
        )
    }

    fn from_evidence_map_with_scope_limit(
        evidence: HashMap<(i64, i64), PublishedCardAuthorization>,
        mode: ReadMode,
        card_active: bool,
        scope_record_limit: usize,
    ) -> Self {
        Self {
            state: Arc::new(RepoState {
                evidence,
                mode,
                card_active: AtomicBool::new(card_active),
                published_reads: AtomicUsize::new(0),
                legacy_reads: AtomicUsize::new(0),
                scope_samples: Mutex::new(Vec::new()),
                scope_record_limit,
            }),
        }
    }

    fn from_evidence_map(
        evidence: HashMap<(i64, i64), PublishedCardAuthorization>,
        mode: ReadMode,
        card_active: bool,
    ) -> Self {
        Self::from_evidence_map_with_scope_limit(evidence, mode, card_active, 64)
    }

    pub fn published_reads(&self) -> usize {
        self.state.published_reads.load(Ordering::SeqCst)
    }

    pub fn legacy_reads(&self) -> usize {
        self.state.legacy_reads.load(Ordering::SeqCst)
    }

    pub fn scopes(&self) -> Vec<PublishedCardEvidenceScope> {
        self.state.scope_samples.lock().unwrap().clone()
    }

    pub fn assert_no_legacy_reads(&self) {
        assert_eq!(
            self.legacy_reads(),
            0,
            "strict published-evidence evaluation must not read legacy/raw ports"
        );
    }

    pub fn reset_counters(&self) {
        self.state.published_reads.store(0, Ordering::SeqCst);
        self.state.legacy_reads.store(0, Ordering::SeqCst);
        self.state.scope_samples.lock().unwrap().clear();
    }

    fn abort_legacy_read(&self, port: &str) -> ! {
        self.state.legacy_reads.fetch_add(1, Ordering::SeqCst);
        panic!("strict published-evidence path called legacy/raw port: {port}");
    }
}

#[async_trait::async_trait]
impl RuleRepository for PublishedRepo {
    fn requires_published_card_evidence(&self) -> bool {
        true
    }

    async fn load_published_card_authorization(
        &self,
        scope: &PublishedCardEvidenceScope,
    ) -> Result<Option<PublishedCardAuthorization>, PolicyError> {
        assert!(
            scope.validate().is_ok(),
            "engine supplied an invalid evidence scope"
        );
        self.state.published_reads.fetch_add(1, Ordering::SeqCst);
        if self.state.scope_record_limit > 0 {
            let mut samples = self.state.scope_samples.lock().unwrap();
            if samples.len() < self.state.scope_record_limit {
                samples.push(scope.clone());
            }
        }
        match self.state.mode {
            ReadMode::Unavailable => Ok(None),
            ReadMode::Unpublished => Err(PolicyError::Repository(
                "published_card_evidence_not_ready;code=published_card_evidence.source_freshness_pending"
                    .to_owned(),
            )),
            ReadMode::Ready => Ok(self
                .state
                .evidence
                .get(&(scope.tenant_id, scope.card_id))
                .cloned()),
        }
    }

    async fn check_card_active(&self, _ctx: &PolicyContext) -> Result<bool, PolicyError> {
        Ok(self.state.card_active.load(Ordering::SeqCst))
    }

    async fn load_rule_set_snapshots(
        &self,
        _card_id: i64,
    ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
        self.abort_legacy_read("load_rule_set_snapshots")
    }

    async fn load_snapshot_winners(
        &self,
        _card_id: i64,
    ) -> Result<Vec<SnapshotWinner>, PolicyError> {
        self.abort_legacy_read("load_snapshot_winners")
    }

    async fn load_permission_rules(
        &self,
        _card_id: i64,
    ) -> Result<Vec<PermissionRule>, PolicyError> {
        self.abort_legacy_read("load_permission_rules")
    }

    async fn load_rule_set_entries_raw(
        &self,
        _card_id: i64,
    ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
        self.abort_legacy_read("load_rule_set_entries_raw")
    }

    async fn load_permission_rules_raw(
        &self,
        _card_id: i64,
    ) -> Result<Vec<PermissionRule>, PolicyError> {
        self.abort_legacy_read("load_permission_rules_raw")
    }

    async fn load_delegated_rules(
        &self,
        _delegate_id: i64,
        _resource: &str,
        _action: &str,
    ) -> Result<Vec<PermissionRule>, PolicyError> {
        self.abort_legacy_read("load_delegated_rules")
    }

    async fn load_projected_delegated_rules(
        &self,
        _delegate_id: i64,
        _resource: &str,
        _action: &str,
    ) -> Result<Vec<PermissionRule>, PolicyError> {
        self.abort_legacy_read("load_projected_delegated_rules")
    }

    async fn get_projection_gate(
        &self,
        _card_id: i64,
    ) -> Result<Option<ProjectionGate>, PolicyError> {
        self.abort_legacy_read("get_projection_gate")
    }
}

pub fn canonical_grant(
    grant_number: u64,
    tenant_id: i64,
    domain_id: Option<i64>,
    card_id: i64,
    user_id: i64,
    resource: &str,
    action: &str,
) -> CanonicalGrant {
    assert!(grant_number > 0, "grant identity must be positive");
    let grant_id_text = format!("550e8400-e29b-41d4-a716-{:012x}", grant_number);
    let grant = CanonicalGrant {
        grant_id: GrantId::parse(&grant_id_text).unwrap(),
        revision: GrantRevision::initial(),
        state: GrantState::Active,
        source_kind: GrantSourceKind::RuleSet,
        binding_layer: BindingLayer::Base,
        tenant: TenantScope::new(tenant_id, domain_id).unwrap(),
        card_id,
        user_id,
        resource: resource.to_owned(),
        action: action.to_owned(),
        effect: GrantEffect::Allow,
        validity: ValidityWindow::perpetual(),
        provenance: GrantProvenance {
            source_id: format!("rule-set-{grant_number}"),
            source_entry: Some(format!("entry-{grant_number}")),
            binding_id: Some(format!("binding-{card_id}")),
            delegation_id: None,
            operation_id: format!("operation-{grant_number}"),
            event_id: Some(format!("event-{grant_number}")),
            actor_user_id: Some(user_id),
        },
    };
    assert!(grant.validate().is_ok(), "fixture grant must be canonical");
    grant
}

pub fn ready_evidence(
    tenant_id: i64,
    card_id: i64,
    grants: Vec<CanonicalGrant>,
) -> PublishedCardAuthorization {
    let record_count = grants.len();
    let manifest = PublishedAggregateManifestSummary {
        tenant_id,
        card_id,
        aggregate_type: "CARD".to_owned(),
        aggregate_id: card_id,
        manifest_id: card_id,
        generation: 1,
        source_generation: 1,
        projected_generation: 1,
        revoke_fence: 0,
        cas_version: 1,
        semantic_hash_hex: "a".repeat(64),
        dependency_hash_hex: "b".repeat(64),
        manifest_digest_hex: "c".repeat(64),
        compiler_version: "test".to_owned(),
        event_id: format!("manifest-event-{card_id}"),
        operation_id: format!("manifest-operation-{card_id}"),
        parent_manifest_id: None,
        segment_count: 1,
        declared_grant_row_count: record_count as u64,
    };
    let records = grants
        .iter()
        .enumerate()
        .map(|(position, grant)| VerifiedPublishedGrantRecord {
            aggregate_type: "CARD".to_owned(),
            aggregate_id: card_id,
            publication_generation: 1,
            revoke_fence: 0,
            manifest_id: card_id,
            event_id: format!("manifest-event-{card_id}"),
            operation_id: format!("manifest-operation-{card_id}"),
            semantic_hash_hex: "a".repeat(64),
            dependency_hash_hex: "b".repeat(64),
            compiler_version: "test".to_owned(),
            segment_ordinal: 0,
            position_in_segment: position as u64,
            grant: grant.clone(),
            accepted_into_effective_set: true,
            unaccepted_reason: None,
        })
        .collect();
    let evidence = PublishedCardAuthorization {
        tenant_id,
        card_id,
        read_unix_seconds: 1_700_000_000,
        gate: PublishedCardAuthorizationGate {
            status: PublishedEvidenceGateStatus::Ready,
            aggregate_manifest_count: 1,
            verified_record_count: record_count,
            effective_grant_count: record_count,
            not_in_effective_count: 0,
            equivalent_duplicate_collapsed_count: 0,
        },
        manifests: vec![manifest],
        records,
        effective_grants: grants,
    };
    assert!(
        evidence.validate().is_ok(),
        "fixture must model a valid Ready published evidence value"
    );
    evidence
}

pub fn assert_allow(decision: &PolicyDecision) {
    assert!(decision.allowed, "expected ALLOW, got {}", decision.reason);
    assert_eq!(decision.reason, "PUBLISHED_EVIDENCE_ALLOW");
    let step = decision
        .evaluation_path
        .iter()
        .rev()
        .find(|step| step.phase == "PUBLISHED_EVIDENCE" && step.result == Effect::Allow)
        .expect("published ALLOW step must exist");
    assert_eq!(step.source.as_deref(), Some("RULE_SET_BASE"));
}

pub fn assert_deny(decision: &PolicyDecision, reason: &str) {
    assert!(!decision.allowed, "expected DENY, got {}", decision.reason);
    assert_eq!(decision.reason, reason);
}

pub fn strict_context(
    user_id: i64,
    card_id: i64,
    tenant_id: i64,
    domain_id: Option<i64>,
    resource: &str,
    action: &str,
) -> PolicyContext {
    let (resource_type, target_id) = resource
        .rsplit_once(':')
        .and_then(|(resource_type, id)| id.parse::<i64>().ok().map(|id| (resource_type, Some(id))))
        .unwrap_or((resource, None));
    PolicyContext::builder()
        .user_id(Some(user_id))
        .card_id(Some(card_id))
        .tenant_id(Some(tenant_id))
        .domain_id(domain_id)
        .resource(Some(resource_type.to_owned()))
        .target_id(target_id)
        .action(action.to_owned())
        .build()
}

pub fn strict_scope(
    tenant_id: i64,
    card_id: i64,
    user_id: i64,
    domain_id: Option<i64>,
) -> PublishedCardEvidenceScope {
    PublishedCardEvidenceScope {
        tenant_id,
        card_id,
        user_filter: Some(user_id),
        domain: domain_id
            .map(DomainScopeRequirement::ExactlySome)
            .unwrap_or(DomainScopeRequirement::Unconstrained),
    }
}
