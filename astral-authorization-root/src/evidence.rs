//! Candidate root evidence and coverage inspection, not a production proof.
//!
//! All inputs are ordinary, publicly constructible DTOs. Structural validation
//! here does not authenticate their source, prove a consistent snapshot, prove
//! publication or establish complete coverage. No value in this module opens a
//! serving or authorization gate. Missing entries, including empty collections,
//! are uncovered; a source-backed absence proof is deliberately unavailable.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use astral_types::org_scope::OrgAdmissionEvidence;
use astral_types::{
    CardEligibility, CertifiedSodPolicy, DomainScopeRequirement, GrantState,
    PlatformCardPairRequest, PublishedCardAuthorization, PublishedCardEvidenceScope,
    PublishedEvidenceAggregate, UnacceptedGrantReason,
};
use thiserror::Error;

const MAX_ENTRIES: usize = 16_384;
const MAX_CONTENT_BYTES: usize = 32 * 1024 * 1024;

/// A candidate for one exact physical card pair. The DTO does not contain the
/// user ID, so the pair request supplies it; neither is proof of the JOIN.
#[derive(Debug, Clone)]
pub struct CardContextCandidate {
    pub pair: PlatformCardPairRequest,
    pub eligibility: CardEligibility,
}

/// The database key is retained separately because the shared policy DTO does
/// not contain it. This is a global candidate row, not a tenant-scoped proof.
#[derive(Debug, Clone)]
pub struct SodPolicyCandidate {
    pub policy_id: i64,
    pub policy: CertifiedSodPolicy,
}

/// Inputs from a prospective loader. They have no trusted-source status.
#[derive(Debug, Clone, Default)]
pub struct RootEvidenceInput {
    pub cards: Vec<(PublishedCardEvidenceScope, PublishedCardAuthorization)>,
    pub org: Vec<OrgAdmissionEvidence>,
    pub eligibility: Vec<CardContextCandidate>,
    pub sod: Vec<SodPolicyCandidate>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum DomainKey {
    Any,
    None,
    Exact(i64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct CardKey {
    tenant: i64,
    card: i64,
    user: Option<i64>,
    domain: DomainKey,
}

impl From<&PublishedCardEvidenceScope> for CardKey {
    fn from(scope: &PublishedCardEvidenceScope) -> Self {
        Self {
            tenant: scope.tenant_id,
            card: scope.card_id,
            user: scope.user_filter,
            domain: match scope.domain {
                DomainScopeRequirement::Unconstrained => DomainKey::Any,
                DomainScopeRequirement::ExactlyNone => DomainKey::None,
                DomainScopeRequirement::ExactlySome(id) => DomainKey::Exact(id),
            },
        }
    }
}

/// Exact tenant and physical pair for candidate eligibility and ORG lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PairScope {
    pub tenant_id: i64,
    pub user_id: i64,
    pub identity_card_id: i64,
    pub user_card_id: i64,
}

impl PairScope {
    fn validate(self) -> Result<(), EvidenceError> {
        if self.tenant_id <= 0
            || self.user_id <= 0
            || self.identity_card_id <= 0
            || self.user_card_id <= 0
        {
            return Err(EvidenceError::InvalidScope);
        }
        Ok(())
    }
}

/// No constructor exists because this slice has no source-backed absence
/// verifier. In particular, an empty DTO, a digest or a coverage declaration
/// cannot create this value. A future proof implementation needs its own review.
#[derive(Debug)]
pub enum AbsenceProofUnavailable {}

/// Result of looking at a candidate, not a coverage or authorization verdict.
#[derive(Debug)]
pub enum CandidateLookup<'a, T> {
    CandidatePresent(&'a T),
    ProvenAbsent(AbsenceProofUnavailable),
    Uncovered,
}

/// This module cannot establish the missing durable/authority guarantees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceReadiness {
    Pending,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EvidenceError {
    #[error("invalid or mismatched evidence scope")]
    InvalidScope,
    #[error("candidate evidence is structurally invalid: {0}")]
    Invalid(&'static str),
    #[error("candidate evidence contains a duplicate key: {0}")]
    Duplicate(&'static str),
    #[error("candidate evidence exceeds the inspection budget")]
    Capacity,
}

/// Bounded immutable candidate content. It never represents verified coverage.
#[derive(Debug)]
pub struct RootEvidenceCandidate {
    read_unix_seconds: i64,
    cards: BTreeMap<CardKey, PublishedCardAuthorization>,
    org: BTreeMap<PairScope, OrgAdmissionEvidence>,
    eligibility: BTreeMap<PairScope, CardContextCandidate>,
    sod: BTreeMap<i64, CertifiedSodPolicy>,
}

impl RootEvidenceCandidate {
    /// Validate candidate structure at one supplied UTC clock. The caller must
    /// separately bound data before loading; the budget below applies only to
    /// inspection and is not a process-wide memory limit.
    pub fn inspect(
        input: RootEvidenceInput,
        read_unix_seconds: i64,
    ) -> Result<Self, EvidenceError> {
        let mut count = 0usize;
        for len in [
            input.cards.len(),
            input.org.len(),
            input.eligibility.len(),
            input.sod.len(),
        ] {
            add_count(&mut count, len)?;
        }
        let mut bytes = ByteBudget::default();
        let mut cards = BTreeMap::new();
        let mut org = BTreeMap::new();
        let mut eligibility = BTreeMap::new();
        let mut sod = BTreeMap::new();

        for (scope, evidence) in input.cards {
            add_count(&mut count, evidence.manifests.len())?;
            add_count(&mut count, evidence.records.len())?;
            add_count(&mut count, evidence.effective_grants.len())?;
            bytes.measure(&evidence)?;
            validate_card(&scope, &evidence, read_unix_seconds)?;
            if cards.insert(CardKey::from(&scope), evidence).is_some() {
                return Err(EvidenceError::Duplicate("card scope"));
            }
        }
        for evidence in input.org {
            bytes.measure(&evidence)?;
            if evidence.checked_at_unix != read_unix_seconds || evidence.validate().is_err() {
                return Err(EvidenceError::Invalid("org evidence or read clock"));
            }
            let member = &evidence.membership;
            let key = PairScope {
                tenant_id: member.tenant_id,
                user_id: member.user_id,
                identity_card_id: member.identity_card_id,
                user_card_id: member.card_id,
            };
            key.validate()?;
            if org.insert(key, evidence).is_some() {
                return Err(EvidenceError::Duplicate("org pair scope"));
            }
        }
        for candidate in input.eligibility {
            bytes.measure(&candidate.pair)?;
            bytes.measure(&candidate.eligibility)?;
            let pair = candidate.pair;
            let fact = candidate.eligibility;
            let key = PairScope {
                tenant_id: fact.user_card_tenant_id,
                user_id: pair.user_id,
                identity_card_id: pair.identity_card_id,
                user_card_id: pair.user_card_id,
            };
            key.validate()?;
            if !pair.is_positive()
                || fact.identity_card_id != pair.identity_card_id
                || fact.user_card_id != pair.user_card_id
                || fact.user_card_domain_id <= 0
                || fact
                    .effective_expiry
                    .is_some_and(|expiry| expiry <= read_unix_seconds)
            {
                return Err(EvidenceError::Invalid("eligibility identity or expiry"));
            }
            if eligibility.insert(key, candidate).is_some() {
                return Err(EvidenceError::Duplicate("eligibility pair scope"));
            }
        }
        for candidate in input.sod {
            bytes.measure(&candidate.policy)?;
            if candidate.policy_id <= 0 || candidate.policy.validate().is_err() {
                return Err(EvidenceError::Invalid("SoD policy"));
            }
            if sod.insert(candidate.policy_id, candidate.policy).is_some() {
                return Err(EvidenceError::Duplicate("SoD policy id"));
            }
        }
        // If both families are supplied for the same physical card, inconsistent
        // tenant/user/identity bindings are a conflict, not separate facts.
        let mut identities = BTreeMap::new();
        let mut identity_by_user = BTreeMap::new();
        let domain_by_card: BTreeMap<_, _> = eligibility
            .iter()
            .map(|(key, candidate)| (key.user_card_id, candidate.eligibility.user_card_domain_id))
            .collect();
        for key in org.keys().chain(eligibility.keys()) {
            let identity = (key.tenant_id, key.user_id, key.identity_card_id);
            if let Some(previous) = identities.insert(key.user_card_id, identity) {
                if previous != identity {
                    return Err(EvidenceError::InvalidScope);
                }
            }
            if let Some(previous) = identity_by_user.insert(key.user_id, key.identity_card_id) {
                if previous != key.identity_card_id {
                    return Err(EvidenceError::InvalidScope);
                }
            }
        }
        for key in cards.keys() {
            if let Some((tenant, user, _)) = identities.get(&key.card) {
                if *tenant != key.tenant || key.user.is_some_and(|id| id != *user) {
                    return Err(EvidenceError::InvalidScope);
                }
            }
            if let Some(&domain) = domain_by_card.get(&key.card) {
                if matches!(key.domain, DomainKey::None)
                    || matches!(key.domain, DomainKey::Exact(id) if id != domain)
                {
                    return Err(EvidenceError::InvalidScope);
                }
            }
        }
        Ok(Self {
            read_unix_seconds,
            cards,
            org,
            eligibility,
            sod,
        })
    }

    pub const fn readiness(&self) -> EvidenceReadiness {
        EvidenceReadiness::Pending
    }

    pub const fn read_unix_seconds(&self) -> i64 {
        self.read_unix_seconds
    }

    /// An exact lens is required; a candidate at another lens is not coverage.
    pub fn card(
        &self,
        scope: &PublishedCardEvidenceScope,
    ) -> Result<CandidateLookup<'_, PublishedCardAuthorization>, EvidenceError> {
        scope.validate().map_err(|_| EvidenceError::InvalidScope)?;
        Ok(match self.cards.get(&CardKey::from(scope)) {
            Some(value) if !value.manifests.is_empty() => CandidateLookup::CandidatePresent(value),
            Some(_) | None => CandidateLookup::Uncovered,
        })
    }

    pub fn org(
        &self,
        scope: PairScope,
    ) -> Result<CandidateLookup<'_, OrgAdmissionEvidence>, EvidenceError> {
        scope.validate()?;
        Ok(match self.org.get(&scope) {
            Some(value) => CandidateLookup::CandidatePresent(value),
            None => CandidateLookup::Uncovered,
        })
    }

    pub fn eligibility(
        &self,
        scope: PairScope,
    ) -> Result<CandidateLookup<'_, CardContextCandidate>, EvidenceError> {
        scope.validate()?;
        Ok(match self.eligibility.get(&scope) {
            Some(value) => CandidateLookup::CandidatePresent(value),
            None => CandidateLookup::Uncovered,
        })
    }

    pub fn sod(
        &self,
        policy_id: i64,
    ) -> Result<CandidateLookup<'_, CertifiedSodPolicy>, EvidenceError> {
        if policy_id <= 0 {
            return Err(EvidenceError::InvalidScope);
        }
        Ok(match self.sod.get(&policy_id) {
            Some(value) => CandidateLookup::CandidatePresent(value),
            None => CandidateLookup::Uncovered,
        })
    }
}

fn validate_card(
    scope: &PublishedCardEvidenceScope,
    evidence: &PublishedCardAuthorization,
    now: i64,
) -> Result<(), EvidenceError> {
    scope.validate().map_err(|_| EvidenceError::InvalidScope)?;
    if evidence.tenant_id != scope.tenant_id || evidence.card_id != scope.card_id {
        return Err(EvidenceError::InvalidScope);
    }
    if evidence.read_unix_seconds != now || evidence.validate().is_err() {
        return Err(EvidenceError::Invalid("card DTO or read clock"));
    }
    // A collapsed record loses its segment position; this inspector cannot
    // reconstruct or validate it from the aggregate count alone.
    if evidence.gate.equivalent_duplicate_collapsed_count != 0 {
        return Err(EvidenceError::Invalid("collapsed card records"));
    }
    let mut manifests = BTreeMap::new();
    let mut manifest_ids = BTreeSet::new();
    for manifest in &evidence.manifests {
        if manifest.tenant_id != scope.tenant_id || manifest.card_id != scope.card_id {
            return Err(EvidenceError::InvalidScope);
        }
        if ![
            PublishedEvidenceAggregate::USER_CARD,
            PublishedEvidenceAggregate::RULE_SET,
            PublishedEvidenceAggregate::APPROVAL,
            PublishedEvidenceAggregate::DELEGATION,
        ]
        .contains(&manifest.aggregate_type.as_str())
            || manifest.aggregate_id <= 0
            || manifest.manifest_id <= 0
            || manifest.generation == 0
            || manifest.source_generation == 0
            || manifest.projected_generation == 0
            || manifest.revoke_fence > manifest.generation
            || manifest.cas_version <= 0
            || manifest.event_id.trim().is_empty()
            || manifest.operation_id.trim().is_empty()
            || !digest(&manifest.semantic_hash_hex)
            || !digest(&manifest.dependency_hash_hex)
        {
            return Err(EvidenceError::Invalid("card manifest fields"));
        }
        if !manifest_ids.insert(manifest.manifest_id)
            || manifests
                .insert(
                    (manifest.aggregate_type.as_str(), manifest.aggregate_id),
                    (manifest, 0u64),
                )
                .is_some()
        {
            return Err(EvidenceError::Duplicate("card manifest"));
        }
    }
    let mut positions = BTreeSet::new();
    let mut grants = BTreeSet::new();
    for record in &evidence.records {
        let Some((manifest, count)) =
            manifests.get_mut(&(record.aggregate_type.as_str(), record.aggregate_id))
        else {
            return Err(EvidenceError::Invalid("record manifest missing"));
        };
        if record.grant.tenant.tenant_id != scope.tenant_id || record.grant.card_id != scope.card_id
        {
            return Err(EvidenceError::InvalidScope);
        }
        if record.manifest_id != manifest.manifest_id
            || record.publication_generation != manifest.generation
            || record.revoke_fence != manifest.revoke_fence
            || record.event_id != manifest.event_id
            || record.operation_id != manifest.operation_id
            || record.semantic_hash_hex != manifest.semantic_hash_hex
            || record.dependency_hash_hex != manifest.dependency_hash_hex
            || record.compiler_version != manifest.compiler_version
            || record.segment_ordinal >= manifest.segment_count
        {
            return Err(EvidenceError::Invalid("record manifest binding"));
        }
        if !positions.insert((
            record.manifest_id,
            record.segment_ordinal,
            record.position_in_segment,
        )) || !grants.insert((record.grant.grant_id, record.grant.revision.value()))
        {
            return Err(EvidenceError::Duplicate("card grant or position"));
        }
        *count = count.checked_add(1).ok_or(EvidenceError::Capacity)?;
        let reason = if record.grant.state != GrantState::Active {
            Some(UnacceptedGrantReason::InactiveState)
        } else if record
            .grant
            .validity
            .expires_at
            .is_some_and(|end| now >= end)
        {
            Some(UnacceptedGrantReason::Expired)
        } else if record
            .grant
            .validity
            .not_before
            .is_some_and(|start| now < start)
        {
            Some(UnacceptedGrantReason::NotYetValid)
        } else if scope
            .user_filter
            .is_some_and(|id| id != record.grant.user_id)
        {
            Some(UnacceptedGrantReason::OutOfUserFilter)
        } else if !scope.domain.matches(record.grant.tenant.domain_id) {
            Some(UnacceptedGrantReason::OutOfDomainFilter)
        } else {
            None
        };
        if record.unaccepted_reason != reason
            || record.accepted_into_effective_set != reason.is_none()
        {
            return Err(EvidenceError::Invalid("record derived classification"));
        }
    }
    if manifests
        .values()
        .any(|(manifest, count)| *count != manifest.declared_grant_row_count)
    {
        return Err(EvidenceError::Invalid("manifest row count"));
    }
    Ok(())
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn add_count(count: &mut usize, amount: usize) -> Result<(), EvidenceError> {
    *count = count.checked_add(amount).ok_or(EvidenceError::Capacity)?;
    if *count > MAX_ENTRIES {
        return Err(EvidenceError::Capacity);
    }
    Ok(())
}

#[derive(Default)]
struct ByteBudget {
    used: usize,
    exceeded: bool,
}
impl ByteBudget {
    fn measure<T: serde::Serialize>(&mut self, value: &T) -> Result<(), EvidenceError> {
        serde_json::to_writer(&mut *self, value).map_err(|_| {
            if self.exceeded {
                EvidenceError::Capacity
            } else {
                EvidenceError::Invalid("candidate encoding")
            }
        })
    }
}
impl Write for ByteBudget {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() > MAX_CONTENT_BYTES.saturating_sub(self.used) {
            self.exceeded = true;
            return Err(io::Error::other("candidate byte limit"));
        }
        self.used += buf.len();
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::{
        BindingLayer, CanonicalGrant, CertifiedSodConflictType, GrantEffect, GrantId,
        GrantProvenance, GrantRevision, GrantSourceKind, PublicationSeal,
        PublishedAggregateManifestSummary, PublishedCardAuthorizationGate,
        PublishedEvidenceGateStatus, TenantScope, ValidityWindow, VerifiedPublishedGrantRecord,
        AUTHORIZATION_COMPILER_VERSION,
    };

    fn scope() -> PublishedCardEvidenceScope {
        PublishedCardEvidenceScope {
            tenant_id: 7,
            card_id: 17,
            user_filter: Some(42),
            domain: DomainScopeRequirement::ExactlySome(11),
        }
    }

    fn card() -> PublishedCardAuthorization {
        let grant = CanonicalGrant {
            grant_id: GrantId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            revision: GrantRevision::new(2).unwrap(),
            state: GrantState::Active,
            source_kind: GrantSourceKind::RuleSet,
            binding_layer: BindingLayer::Overlay,
            tenant: TenantScope::new(7, Some(11)).unwrap(),
            card_id: 17,
            user_id: 42,
            resource: "document".into(),
            action: "read".into(),
            effect: GrantEffect::Allow,
            validity: ValidityWindow::between(100, 200),
            provenance: GrantProvenance {
                source_id: "rule-set-1".into(),
                source_entry: Some("entry-1".into()),
                binding_id: Some("binding-1".into()),
                delegation_id: None,
                operation_id: "grant-op".into(),
                event_id: Some("grant-event".into()),
                actor_user_id: Some(42),
            },
        };
        let manifest = PublishedAggregateManifestSummary {
            seal: PublicationSeal::from_unix_seconds(1_700_000_000).unwrap(),
            tenant_id: 7,
            card_id: 17,
            aggregate_type: "USER_CARD".into(),
            aggregate_id: 17,
            manifest_id: 9,
            generation: 4,
            source_generation: 4,
            projected_generation: 4,
            revoke_fence: 1,
            cas_version: 1,
            semantic_hash_hex: "a".repeat(64),
            dependency_hash_hex: "b".repeat(64),
            manifest_digest_hex: "c".repeat(64),
            compiler_version: AUTHORIZATION_COMPILER_VERSION.into(),
            event_id: "publish-event".into(),
            operation_id: "publish-op".into(),
            parent_manifest_id: None,
            segment_count: 1,
            declared_grant_row_count: 1,
        };
        let record = VerifiedPublishedGrantRecord {
            aggregate_type: manifest.aggregate_type.clone(),
            aggregate_id: manifest.aggregate_id,
            publication_generation: manifest.generation,
            revoke_fence: manifest.revoke_fence,
            manifest_id: manifest.manifest_id,
            event_id: manifest.event_id.clone(),
            operation_id: manifest.operation_id.clone(),
            semantic_hash_hex: manifest.semantic_hash_hex.clone(),
            dependency_hash_hex: manifest.dependency_hash_hex.clone(),
            compiler_version: manifest.compiler_version.clone(),
            segment_ordinal: 0,
            position_in_segment: 0,
            grant: grant.clone(),
            accepted_into_effective_set: true,
            unaccepted_reason: None,
        };
        PublishedCardAuthorization {
            tenant_id: 7,
            card_id: 17,
            read_unix_seconds: 100,
            gate: PublishedCardAuthorizationGate {
                status: PublishedEvidenceGateStatus::Ready,
                aggregate_manifest_count: 1,
                verified_record_count: 1,
                effective_grant_count: 1,
                not_in_effective_count: 0,
                equivalent_duplicate_collapsed_count: 0,
            },
            manifests: vec![manifest],
            records: vec![record],
            effective_grants: vec![grant],
        }
    }

    fn card_input(value: PublishedCardAuthorization) -> RootEvidenceInput {
        RootEvidenceInput {
            cards: vec![(scope(), value)],
            ..Default::default()
        }
    }

    fn pair() -> PairScope {
        PairScope {
            tenant_id: 7,
            user_id: 42,
            identity_card_id: 8,
            user_card_id: 17,
        }
    }

    fn eligibility() -> CardContextCandidate {
        CardContextCandidate {
            pair: PlatformCardPairRequest {
                user_id: 42,
                identity_card_id: 8,
                user_card_id: 17,
            },
            eligibility: CardEligibility {
                identity_card_id: 8,
                user_card_id: 17,
                user_card_tenant_id: 7,
                user_card_domain_id: 11,
                effective_expiry: Some(200),
            },
        }
    }

    #[test]
    fn candidate_and_empty_results_never_establish_coverage() {
        let root = RootEvidenceCandidate::inspect(card_input(card()), 100).unwrap();
        assert_eq!(root.readiness(), EvidenceReadiness::Pending);
        assert!(matches!(
            root.card(&scope()).unwrap(),
            CandidateLookup::CandidatePresent(_)
        ));
        let mut other = scope();
        other.domain = DomainScopeRequirement::Unconstrained;
        assert!(matches!(
            root.card(&other).unwrap(),
            CandidateLookup::Uncovered
        ));
        assert!(matches!(
            root.eligibility(pair()).unwrap(),
            CandidateLookup::Uncovered
        ));
        assert!(matches!(root.sod(1).unwrap(), CandidateLookup::Uncovered));
        let mut forged = card();
        forged.manifests.clear();
        forged.records.clear();
        forged.effective_grants.clear();
        forged.gate.aggregate_manifest_count = 0;
        forged.gate.verified_record_count = 0;
        forged.gate.effective_grant_count = 0;
        let empty = RootEvidenceCandidate::inspect(card_input(forged), 100).unwrap();
        assert_eq!(empty.readiness(), EvidenceReadiness::Pending);
        assert!(matches!(
            empty.card(&scope()).unwrap(),
            CandidateLookup::Uncovered
        ));
    }

    #[test]
    fn card_scope_source_duplicates_and_windows_are_checked() {
        assert!(RootEvidenceCandidate::inspect(card_input(card()), 100).is_ok());
        let mut bad = card();
        bad.records[0].grant.tenant.tenant_id = 8;
        bad.effective_grants[0] = bad.records[0].grant.clone();
        assert!(matches!(
            RootEvidenceCandidate::inspect(card_input(bad), 100),
            Err(EvidenceError::InvalidScope)
        ));
        let mut bad = card();
        bad.records[0].operation_id = "other".into();
        assert!(matches!(
            RootEvidenceCandidate::inspect(card_input(bad), 100),
            Err(EvidenceError::Invalid("record manifest binding"))
        ));
        let mut bad = card();
        bad.manifests.push(bad.manifests[0].clone());
        bad.gate.aggregate_manifest_count += 1;
        assert!(matches!(
            RootEvidenceCandidate::inspect(card_input(bad), 100),
            Err(EvidenceError::Duplicate("card manifest"))
        ));
        let mut bad = card();
        bad.records.push(bad.records[0].clone());
        bad.effective_grants.push(bad.effective_grants[0].clone());
        bad.gate.verified_record_count += 1;
        bad.gate.effective_grant_count += 1;
        bad.manifests[0].declared_grant_row_count += 1;
        assert!(matches!(
            RootEvidenceCandidate::inspect(card_input(bad), 100),
            Err(EvidenceError::Duplicate("card grant or position"))
        ));
        let mut bad = card();
        bad.read_unix_seconds = 200;
        assert!(matches!(
            RootEvidenceCandidate::inspect(card_input(bad), 200),
            Err(EvidenceError::Invalid("record derived classification"))
        ));
        let mut expired = card();
        expired.read_unix_seconds = 200;
        expired.records[0].accepted_into_effective_set = false;
        expired.records[0].unaccepted_reason = Some(UnacceptedGrantReason::Expired);
        expired.effective_grants.clear();
        expired.gate.effective_grant_count = 0;
        expired.gate.not_in_effective_count = 1;
        assert!(RootEvidenceCandidate::inspect(card_input(expired), 200).is_ok());
    }

    #[test]
    fn org_candidate_checks_scope_window_and_pair_binding() {
        use astral_types::org_scope::{
            org_manifest_digest_hex, OrgManifestDigestMaterial, OrgMembership, OrgNode,
            OrgPublication, OrgRootActivation,
        };
        let mut publication = OrgPublication {
            tenant_id: 7,
            root_tenant_id: 7,
            generation: 3,
            relationship_revision: 2,
            revoke_fence: 1,
            dependencies: vec![],
            manifest_digest_hex: String::new(),
            compiler_version: astral_types::AUTHORIZATION_ORG_COMPILER_VERSION.into(),
            segments: vec![],
            operation_id: "org-publish".into(),
        };
        publication.manifest_digest_hex = org_manifest_digest_hex(&OrgManifestDigestMaterial {
            tenant_id: publication.tenant_id,
            root_tenant_id: publication.root_tenant_id,
            generation: publication.generation,
            relationship_revision: publication.relationship_revision,
            revoke_fence: publication.revoke_fence,
            dependencies: &publication.dependencies,
            segments: &publication.segments,
            compiler_version: &publication.compiler_version,
            operation_id: &publication.operation_id,
        })
        .unwrap();
        let evidence = OrgAdmissionEvidence {
            publication,
            node: OrgNode {
                tenant_id: 7,
                root_tenant_id: 7,
                parent_tenant_id: None,
                generation: 3,
                revoke_fence: 1,
                relationship_revision: 2,
                active: true,
                operation_id: "org-node".into(),
                root_activation: Some(OrgRootActivation {
                    operator_user_id: 42,
                    approval_operation_id: "org-approval".into(),
                }),
            },
            membership: OrgMembership {
                membership_id: "550e8400-e29b-41d4-a716-446655440001".into(),
                tenant_id: 7,
                root_tenant_id: 7,
                user_id: 42,
                identity_card_id: 8,
                card_id: 17,
                revision: 1,
                active: true,
                validity: ValidityWindow::between(100, 200),
                operation_id: "org-member".into(),
            },
            checked_at_unix: 100,
        };
        let input = RootEvidenceInput {
            org: vec![evidence],
            eligibility: vec![eligibility()],
            ..Default::default()
        };
        let root = RootEvidenceCandidate::inspect(input.clone(), 100).unwrap();
        assert!(matches!(
            root.org(pair()).unwrap(),
            CandidateLookup::CandidatePresent(_)
        ));
        assert_eq!(root.readiness(), EvidenceReadiness::Pending);
        let mut wrong = input.clone();
        wrong.org[0].membership.tenant_id = 8;
        assert!(RootEvidenceCandidate::inspect(wrong, 100).is_err());
        let mut expired = input.clone();
        expired.org[0].checked_at_unix = 200;
        assert!(RootEvidenceCandidate::inspect(expired, 200).is_err());
        let mut split = input;
        split.eligibility[0].pair.user_id = 99;
        assert!(matches!(
            RootEvidenceCandidate::inspect(split, 100),
            Err(EvidenceError::InvalidScope)
        ));
    }

    #[test]
    fn eligibility_and_sod_are_bounded_candidates() {
        let policy = CertifiedSodPolicy {
            policy_name: "payments".into(),
            conflict_type: CertifiedSodConflictType::Static,
            permission_a: Some("create".into()),
            permission_b: Some("approve".into()),
            condition_script: None,
            resource_type: None,
            action_code: None,
        };
        let input = RootEvidenceInput {
            eligibility: vec![eligibility()],
            sod: vec![SodPolicyCandidate {
                policy_id: 3,
                policy,
            }],
            ..Default::default()
        };
        let root = RootEvidenceCandidate::inspect(input.clone(), 100).unwrap();
        assert_eq!(root.readiness(), EvidenceReadiness::Pending);
        assert!(matches!(
            root.eligibility(pair()).unwrap(),
            CandidateLookup::CandidatePresent(_)
        ));
        assert!(matches!(
            root.sod(3).unwrap(),
            CandidateLookup::CandidatePresent(_)
        ));
        assert!(RootEvidenceCandidate::inspect(input.clone(), 200).is_err());
        let mut duplicate = input.clone();
        duplicate.sod.push(duplicate.sod[0].clone());
        assert!(matches!(
            RootEvidenceCandidate::inspect(duplicate, 100),
            Err(EvidenceError::Duplicate("SoD policy id"))
        ));
        let mut wrong = input;
        wrong.eligibility[0].eligibility.identity_card_id = 9;
        assert!(RootEvidenceCandidate::inspect(wrong, 100).is_err());
        let many = RootEvidenceInput {
            eligibility: vec![eligibility(); MAX_ENTRIES + 1],
            ..Default::default()
        };
        assert!(matches!(
            RootEvidenceCandidate::inspect(many, 100),
            Err(EvidenceError::Capacity)
        ));
    }
}
