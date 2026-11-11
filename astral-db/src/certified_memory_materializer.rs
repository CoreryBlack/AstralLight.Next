//! Durable fact-family materialization boundary for CertifiedMemory.
//!
//! This module deliberately contains no SQL queries and no authority transport.
//! Each family owner must return an authority-bound completion produced by its
//! durable source owner. The orchestrator validates the six-family shape and
//! refuses to construct an installable snapshot when any family is pending,
//! unknown, quarantined, duplicated, or bound to another scope/frontier.

use std::sync::Arc;

use astral_types::authority_protocol::{
    AuthorityCertifiedMemoryFamily, AuthorityFamilyCompletion, AuthorityFamilyInventoryItem,
    AuthorityFamilyScope,
};
use astral_types::{PublishedCardAuthorization, PublishedCardEvidenceScope};
use policy_engine::OrgAuthorityRead;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::certified_memory_authority::{
    CardContextKey, CertifiedCardContext, CertifiedMemoryAttestation, CertifiedMemoryCoverage,
    CertifiedMemoryCoverageContract, CertifiedSodPolicy, GlobalAdminStatus, OrgReadKey,
    OwnershipReadKey,
};
use crate::certified_memory_coordinator::{
    CertifiedMemoryCoordinatorError, CertifiedMemoryFamilyBundle,
};
use crate::certified_memory_snapshot_builder::CertifiedMemorySnapshotInput;
use crate::resource_ownership::ResourceOwnershipResolution;

/// Upper bound for one explicit owner registry.
pub const CERTIFIED_MEMORY_FAMILY_COUNT: usize = 6;

/// Exact input for one durable family owner.
///
/// The caller must provide a bounded, already-selected scope. An empty scope
/// selector is not interpreted as "all rows" and cannot become a wildcard scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertifiedMemoryFamilyOwnerRequest {
    pub scope: AuthorityFamilyScope,
    pub generation: u64,
    pub revoke_watermark: u64,
    pub now_unix: i64,
}

impl CertifiedMemoryFamilyOwnerRequest {
    pub fn validate(&self) -> Result<(), CertifiedMemoryMaterializerError> {
        self.scope
            .validate()
            .map_err(|error| invalid(format!("family scope: {error}")))?;
        if self.generation == 0 || self.now_unix <= 0 {
            return Err(invalid("family owner request has invalid generation/time"));
        }
        if self.revoke_watermark > self.generation {
            return Err(invalid("family owner request revoke watermark is ahead"));
        }
        Ok(())
    }
}

/// The concrete value set owned by one family.
#[derive(Debug, Clone)]
pub enum CertifiedMemoryFamilyPayload {
    CardContext(Vec<(CardContextKey, CertifiedCardContext)>),
    GlobalAdmin(Vec<(i64, GlobalAdminStatus)>),
    PublishedEvidence(Vec<(PublishedCardEvidenceScope, Arc<PublishedCardAuthorization>)>),
    OrgAuthorization(Vec<(OrgReadKey, OrgAuthorityRead)>),
    Ownership(Vec<(OwnershipReadKey, ResourceOwnershipResolution)>),
    SodPolicy(Vec<CertifiedSodPolicy>),
    SodPolicyWithProvenance(crate::certified_memory_source_owner_producer::SodPolicySourcePayload),
}

impl CertifiedMemoryFamilyPayload {
    pub(crate) fn is_empty(&self) -> bool {
        match self {
            Self::CardContext(values) => values.is_empty(),
            Self::GlobalAdmin(values) => values.is_empty(),
            Self::PublishedEvidence(values) => values.is_empty(),
            Self::OrgAuthorization(values) => values.is_empty(),
            Self::Ownership(values) => values.is_empty(),
            Self::SodPolicy(values) => values.is_empty(),
            Self::SodPolicyWithProvenance(value) => value.facts.is_empty(),
        }
    }

    pub(crate) fn validate_inventory(
        &self,
        completion: &AuthorityFamilyCompletion,
    ) -> Result<(), CertifiedMemoryMaterializerError> {
        let tenant_id = completion.scope.tenant_id;
        let mut actual = Vec::new();
        match self {
            Self::CardContext(values) => {
                for (key, value) in values {
                    value.validate_for(key).map_err(invalid)?;
                    if tenant_id
                        .is_some_and(|tenant| tenant != value.eligibility.user_card_tenant_id)
                    {
                        return Err(invalid("card context tenant does not match family scope"));
                    }
                    actual.push(inventory_item(
                        format!(
                            "user:{}:identity-card:{}:user-card:{}",
                            key.user_id, key.identity_card_id, key.user_card_id
                        ),
                        tenant_id,
                        value,
                    )?);
                }
            }
            Self::GlobalAdmin(values) => {
                for (user_id, status) in values {
                    if *user_id <= 0 {
                        return Err(invalid("global admin user identity must be positive"));
                    }
                    actual.push(inventory_item(
                        format!("user:{user_id}"),
                        tenant_id,
                        status,
                    )?);
                }
            }
            Self::PublishedEvidence(values) => {
                for (scope, evidence) in values {
                    scope
                        .validate()
                        .map_err(|error| invalid(error.to_string()))?;
                    evidence
                        .validate()
                        .map_err(|error| invalid(error.to_string()))?;
                    if evidence.tenant_id != scope.tenant_id
                        || evidence.card_id != scope.card_id
                        || tenant_id.is_some_and(|tenant| tenant != scope.tenant_id)
                    {
                        return Err(invalid("published evidence does not match family scope"));
                    }
                    for manifest in &evidence.manifests {
                        if manifest.tenant_id != scope.tenant_id
                            || manifest.card_id != scope.card_id
                        {
                            return Err(invalid(
                                "published manifest does not match evidence scope",
                            ));
                        }
                        actual.push(AuthorityFamilyInventoryItem {
                            key: format!(
                                "card:{}:{}:{}",
                                manifest.tenant_id, manifest.card_id, manifest.aggregate_id
                            ),
                            tenant_id: Some(manifest.tenant_id),
                            content_digest: manifest.manifest_digest_hex.clone(),
                        });
                    }
                }
            }
            Self::OrgAuthorization(values) => {
                for (key, read) in values {
                    let OrgAuthorityRead::Ready(evidence) = read else {
                        return Err(invalid("org inventory requires ready evidence"));
                    };
                    let member = &evidence.membership;
                    if key.tenant_id != member.tenant_id
                        || key.user_id != member.user_id
                        || key.identity_card_id != member.identity_card_id
                        || key.card_id != member.card_id
                        || tenant_id != Some(member.tenant_id)
                    {
                        return Err(invalid("org evidence does not match its key and tenant"));
                    }
                    let digest = if evidence.node.active && member.active {
                        evidence
                            .validate()
                            .map_err(|error| invalid(error.to_string()))?;
                        astral_types::org_authority_evidence_hash(evidence)
                    } else {
                        astral_types::org_authority_revocation_evidence_hash(evidence)
                    }
                    .map_err(|error| invalid(error.to_string()))?;
                    actual.push(AuthorityFamilyInventoryItem {
                        key: format!(
                            "org:{}:{}:{}:{}",
                            key.tenant_id, key.user_id, key.identity_card_id, key.card_id
                        ),
                        tenant_id: Some(key.tenant_id),
                        content_digest: digest,
                    });
                }
            }
            Self::Ownership(values) => {
                for (key, resolution) in values {
                    actual.push(
                        crate::certified_memory_source_owner_producer::ownership_inventory_item(
                            key,
                            resolution,
                            &completion.scope,
                        )
                        .map_err(|error| invalid(error.to_string()))?,
                    );
                }
            }
            Self::SodPolicy(values) if !values.is_empty() => {
                return Err(CertifiedMemoryMaterializerError::Pending {
                    family: AuthorityCertifiedMemoryFamily::SodPolicy,
                    code: "certified_memory.sod_inventory_provenance_missing",
                });
            }
            Self::SodPolicy(_) => {
                return Err(CertifiedMemoryMaterializerError::Pending {
                    family: AuthorityCertifiedMemoryFamily::SodPolicy,
                    code: "certified_memory.sod_empty_completeness_unverified",
                });
            }
            Self::SodPolicyWithProvenance(value) => {
                for fact in &value.facts {
                    actual.push(
                        crate::certified_memory_source_owner_producer::sod_policy_inventory_item(
                            fact,
                            &value.provenance,
                            tenant_id,
                        )
                        .map_err(|error| invalid(error.to_string()))?,
                    );
                }
                actual.sort_by(|left, right| left.key.cmp(&right.key));
                if actual != completion.inventory {
                    return Err(invalid(
                        "family payload does not match completion inventory",
                    ));
                }
                return Err(CertifiedMemoryMaterializerError::Pending {
                    family: AuthorityCertifiedMemoryFamily::SodPolicy,
                    code: if value.facts.is_empty() {
                        "certified_memory.sod_empty_completeness_unverified"
                    } else {
                        "certified_memory.sod_source_provenance_unverified"
                    },
                });
            }
        }
        actual.sort_by(|left, right| left.key.cmp(&right.key));
        if actual != completion.inventory {
            return Err(invalid(
                "family payload does not match completion inventory",
            ));
        }
        Ok(())
    }

    pub const fn family(&self) -> AuthorityCertifiedMemoryFamily {
        match self {
            Self::CardContext(_) => AuthorityCertifiedMemoryFamily::CardContext,
            Self::GlobalAdmin(_) => AuthorityCertifiedMemoryFamily::GlobalAdmin,
            Self::PublishedEvidence(_) => AuthorityCertifiedMemoryFamily::PublishedEvidence,
            Self::OrgAuthorization(_) => AuthorityCertifiedMemoryFamily::OrgAuthorization,
            Self::Ownership(_) => AuthorityCertifiedMemoryFamily::Ownership,
            Self::SodPolicy(_) | Self::SodPolicyWithProvenance(_) => {
                AuthorityCertifiedMemoryFamily::SodPolicy
            }
        }
    }
}

/// One owner result. A terminal result must carry the complete-content digest
/// supplied by the durable owner; missing digest is rejected before aggregation.
#[derive(Debug, Clone)]
pub struct CertifiedMemoryFamilyMaterialization {
    pub family: AuthorityCertifiedMemoryFamily,
    pub completion: AuthorityFamilyCompletion,
    pub payload: CertifiedMemoryFamilyPayload,
}

impl CertifiedMemoryFamilyMaterialization {
    fn validate(
        &self,
        request: &CertifiedMemoryFamilyOwnerRequest,
    ) -> Result<(), CertifiedMemoryMaterializerError> {
        self.completion
            .validate()
            .map_err(|error| invalid(format!("family completion: {error}")))?;
        if self.family != self.completion.family || self.family != self.payload.family() {
            return Err(invalid("family completion and payload kinds differ"));
        }
        if self.completion.scope != request.scope
            || self.completion.scope_generation != request.generation
            || self.completion.revoke_watermark != request.revoke_watermark
        {
            return Err(CertifiedMemoryMaterializerError::FrontierMismatch {
                family: self.family,
            });
        }
        if self.completion.state.is_terminal_complete()
            && self.completion.complete_content_digest.is_none()
        {
            return Err(invalid("terminal family completion lacks content digest"));
        }
        Ok(())
    }
}

/// Durable owner contract. Implementations must derive the result from their
/// own source transaction/receipt ledger and must never synthesize completion
/// identities from a request or from a process-local cache.
#[async_trait::async_trait]
pub trait CertifiedMemoryFamilyOwner: Send + Sync {
    fn family(&self) -> AuthorityCertifiedMemoryFamily;

    async fn materialize(
        &self,
        request: &CertifiedMemoryFamilyOwnerRequest,
    ) -> Result<CertifiedMemoryFamilyMaterialization, CertifiedMemoryMaterializerError>;
}

/// Safe owner used by startup wiring until a real durable owner is registered.
/// It makes the missing production owner explicit and keeps the profile pending.
#[derive(Debug, Clone, Copy)]
pub struct UnavailableCertifiedMemoryFamilyOwner {
    family: AuthorityCertifiedMemoryFamily,
}

impl UnavailableCertifiedMemoryFamilyOwner {
    pub const fn new(family: AuthorityCertifiedMemoryFamily) -> Self {
        Self { family }
    }
}

#[async_trait::async_trait]
impl CertifiedMemoryFamilyOwner for UnavailableCertifiedMemoryFamilyOwner {
    fn family(&self) -> AuthorityCertifiedMemoryFamily {
        self.family
    }

    async fn materialize(
        &self,
        _request: &CertifiedMemoryFamilyOwnerRequest,
    ) -> Result<CertifiedMemoryFamilyMaterialization, CertifiedMemoryMaterializerError> {
        Err(CertifiedMemoryMaterializerError::Pending {
            family: self.family,
            code: "certified_memory.family_owner_unavailable",
        })
    }
}

/// The six-family orchestration boundary.
#[derive(Clone)]
pub struct CertifiedMemoryMaterializer {
    owners: Vec<Arc<dyn CertifiedMemoryFamilyOwner>>,
}

impl std::fmt::Debug for CertifiedMemoryMaterializer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CertifiedMemoryMaterializer")
            .field("owner_count", &self.owners.len())
            .finish()
    }
}

impl CertifiedMemoryMaterializer {
    pub fn new(
        owners: Vec<Arc<dyn CertifiedMemoryFamilyOwner>>,
    ) -> Result<Self, CertifiedMemoryMaterializerError> {
        if owners.len() != CERTIFIED_MEMORY_FAMILY_COUNT {
            return Err(CertifiedMemoryMaterializerError::OwnerRegistryIncomplete);
        }
        for required in AuthorityCertifiedMemoryFamily::required() {
            let count = owners
                .iter()
                .filter(|owner| owner.family() == required)
                .count();
            if count != 1 {
                return Err(CertifiedMemoryMaterializerError::OwnerRegistryInvalid {
                    family: required,
                });
            }
        }
        Ok(Self { owners })
    }

    pub fn pending() -> Self {
        let owners = AuthorityCertifiedMemoryFamily::required()
            .into_iter()
            .map(|family| {
                Arc::new(UnavailableCertifiedMemoryFamilyOwner::new(family))
                    as Arc<dyn CertifiedMemoryFamilyOwner>
            })
            .collect();
        Self { owners }
    }

    pub async fn materialize(
        &self,
        request: &CertifiedMemoryFamilyOwnerRequest,
    ) -> Result<CertifiedMemoryMaterialization, CertifiedMemoryMaterializerError> {
        request.validate()?;
        let mut results = Vec::with_capacity(CERTIFIED_MEMORY_FAMILY_COUNT);
        for required in AuthorityCertifiedMemoryFamily::required() {
            let owner = self
                .owners
                .iter()
                .find(|owner| owner.family() == required)
                .ok_or(CertifiedMemoryMaterializerError::OwnerRegistryInvalid {
                    family: required,
                })?;
            let result = owner.materialize(request).await?;
            result.validate(request)?;
            if result.family != required {
                return Err(CertifiedMemoryMaterializerError::FamilyOrderMismatch {
                    expected: required,
                    actual: result.family,
                });
            }
            results.push(result);
        }

        let completions = results
            .iter()
            .map(|result| result.completion.clone())
            .collect();
        let bundle = CertifiedMemoryFamilyBundle::build(request.scope.clone(), completions)
            .map_err(CertifiedMemoryMaterializerError::Bundle)?;
        let mut payloads = Vec::with_capacity(results.len());
        for result in results {
            payloads.push(result.payload);
        }
        Ok(CertifiedMemoryMaterialization {
            scope: request.scope.clone(),
            generation: request.generation,
            revoke_watermark: request.revoke_watermark,
            bundle,
            payloads,
        })
    }
}

/// Complete six-family payload plus the already validated authority-bound bundle.
#[derive(Debug, Clone)]
pub struct CertifiedMemoryMaterialization {
    pub scope: AuthorityFamilyScope,
    pub generation: u64,
    pub revoke_watermark: u64,
    pub bundle: CertifiedMemoryFamilyBundle,
    pub payloads: Vec<CertifiedMemoryFamilyPayload>,
}

impl CertifiedMemoryMaterialization {
    pub fn into_snapshot_input(
        self,
        attestation: CertifiedMemoryAttestation,
        installed_at_unix: i64,
        expires_at_unix: i64,
    ) -> Result<CertifiedMemorySnapshotInput, CertifiedMemoryMaterializerError> {
        let verified_bundle = CertifiedMemoryFamilyBundle::build(
            self.scope.clone(),
            self.bundle.completions.clone(),
        )?;
        if self.payloads.len() != CERTIFIED_MEMORY_FAMILY_COUNT
            || self.bundle != verified_bundle
            || verified_bundle.generation() != self.generation
            || verified_bundle.revoke_watermark() != self.revoke_watermark
        {
            return Err(CertifiedMemoryMaterializerError::Bundle(
                CertifiedMemoryCoordinatorError::FamilyCoverageIncomplete,
            ));
        }
        let mut seen = Vec::with_capacity(CERTIFIED_MEMORY_FAMILY_COUNT);
        for payload in &self.payloads {
            let family = payload.family();
            if seen.contains(&family) {
                return Err(CertifiedMemoryMaterializerError::Bundle(
                    CertifiedMemoryCoordinatorError::DuplicateFamily { family },
                ));
            }
            seen.push(family);
            let completion = verified_bundle
                .completions
                .iter()
                .find(|completion| completion.family == family)
                .ok_or(CertifiedMemoryMaterializerError::Bundle(
                    CertifiedMemoryCoordinatorError::FamilyCoverageIncomplete,
                ))?;
            payload.validate_inventory(completion)?;
            match completion.state {
                astral_types::authority_protocol::AuthorityFamilyCompletionState::CompleteEmpty
                    if !payload.is_empty() =>
                {
                    return Err(invalid("family payload and completion state disagree"));
                }
                astral_types::authority_protocol::AuthorityFamilyCompletionState::Complete
                    if payload.is_empty() =>
                {
                    return Err(invalid("family payload and completion state disagree"));
                }
                _ => {}
            }
        }
        let mut input = CertifiedMemorySnapshotInput {
            generation: self.generation,
            installed_at_unix,
            expires_at_unix,
            attestation,
            coverage: CertifiedMemoryCoverage::Complete,
            coverage_contract: CertifiedMemoryCoverageContract::complete(),
            card_contexts: Vec::new(),
            global_admins: Vec::new(),
            org_reads: Vec::new(),
            ownership: Vec::new(),
            published_cards: Vec::new(),
            sod_policies: Vec::new(),
        };
        for payload in self.payloads {
            match payload {
                CertifiedMemoryFamilyPayload::CardContext(values) => input.card_contexts = values,
                CertifiedMemoryFamilyPayload::GlobalAdmin(values) => input.global_admins = values,
                CertifiedMemoryFamilyPayload::PublishedEvidence(values) => {
                    input.published_cards = values
                }
                CertifiedMemoryFamilyPayload::OrgAuthorization(values) => input.org_reads = values,
                CertifiedMemoryFamilyPayload::Ownership(values) => input.ownership = values,
                CertifiedMemoryFamilyPayload::SodPolicy(values) => input.sod_policies = values,
                CertifiedMemoryFamilyPayload::SodPolicyWithProvenance(value) => {
                    input.sod_policies = value.facts.into_iter().map(|fact| fact.policy).collect()
                }
            }
        }
        Ok(input)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CertifiedMemoryMaterializerError {
    #[error("certified-memory family owner registry is incomplete")]
    OwnerRegistryIncomplete,
    #[error("certified-memory family owner registry has invalid family {family:?}")]
    OwnerRegistryInvalid {
        family: AuthorityCertifiedMemoryFamily,
    },
    #[error("certified-memory family {family:?} is pending: {code}")]
    Pending {
        family: AuthorityCertifiedMemoryFamily,
        code: &'static str,
    },
    #[error("certified-memory family {family:?} is unknown: {code}")]
    Unknown {
        family: AuthorityCertifiedMemoryFamily,
        code: &'static str,
    },
    #[error("certified-memory family {family:?} is quarantined: {code}")]
    Quarantined {
        family: AuthorityCertifiedMemoryFamily,
        code: &'static str,
    },
    #[error("certified-memory family owner returned an invalid result: {0}")]
    Invalid(String),
    #[error("certified-memory family frontier mismatch for {family:?}")]
    FrontierMismatch {
        family: AuthorityCertifiedMemoryFamily,
    },
    #[error("certified-memory family order mismatch: expected {expected:?}, got {actual:?}")]
    FamilyOrderMismatch {
        expected: AuthorityCertifiedMemoryFamily,
        actual: AuthorityCertifiedMemoryFamily,
    },
    #[error("certified-memory family bundle rejected: {0}")]
    Bundle(#[from] CertifiedMemoryCoordinatorError),
}

fn inventory_item(
    key: String,
    tenant_id: Option<i64>,
    value: &impl serde::Serialize,
) -> Result<AuthorityFamilyInventoryItem, CertifiedMemoryMaterializerError> {
    let value = serde_json::to_value(value)
        .map_err(|error| invalid(format!("inventory content serialization failed: {error}")))?;
    let canonical = serde_json::to_vec(&value)
        .map_err(|error| invalid(format!("inventory content serialization failed: {error}")))?;
    Ok(AuthorityFamilyInventoryItem {
        key,
        tenant_id,
        content_digest: hex::encode(Sha256::digest(canonical)),
    })
}

fn invalid(message: impl Into<String>) -> CertifiedMemoryMaterializerError {
    CertifiedMemoryMaterializerError::Invalid(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::authority_protocol::{
        AuthorityFamilyCompletionState, AuthorityFamilyDependencyFrontier,
    };

    fn request() -> CertifiedMemoryFamilyOwnerRequest {
        CertifiedMemoryFamilyOwnerRequest {
            scope: AuthorityFamilyScope {
                tenant_id: Some(7),
                scope: "tenant:7".to_owned(),
            },
            generation: 3,
            revoke_watermark: 1,
            now_unix: 10_000,
        }
    }

    fn owner(family: AuthorityCertifiedMemoryFamily) -> Arc<dyn CertifiedMemoryFamilyOwner> {
        Arc::new(UnavailableCertifiedMemoryFamilyOwner::new(family))
    }

    #[test]
    fn registry_requires_exactly_one_owner_per_family() {
        let mut owners: Vec<_> = AuthorityCertifiedMemoryFamily::required()
            .into_iter()
            .map(owner)
            .collect();
        assert!(CertifiedMemoryMaterializer::new(owners.clone()).is_ok());
        owners.pop();
        assert!(matches!(
            CertifiedMemoryMaterializer::new(owners),
            Err(CertifiedMemoryMaterializerError::OwnerRegistryIncomplete)
        ));
    }

    #[tokio::test]
    async fn unavailable_owner_preserves_pending_without_snapshot() {
        let materializer = CertifiedMemoryMaterializer::pending();
        let result = materializer.materialize(&request()).await;
        assert!(matches!(
            result,
            Err(CertifiedMemoryMaterializerError::Pending {
                family: AuthorityCertifiedMemoryFamily::CardContext,
                code: "certified_memory.family_owner_unavailable",
            })
        ));
    }

    fn empty_materialization() -> CertifiedMemoryMaterialization {
        let request = request();
        let completions = AuthorityCertifiedMemoryFamily::required()
            .into_iter()
            .map(|family| AuthorityFamilyCompletion {
                family,
                state: AuthorityFamilyCompletionState::CompleteEmpty,
                scope: request.scope.clone(),
                reservation_id: "reservation".into(),
                operation_id: "operation".into(),
                event_id: "event".into(),
                message_id: None,
                source_commit_digest: "11".repeat(32),
                source_outcome_digest: "22".repeat(32),
                before_content_digest: None,
                after_content_digest: None,
                complete_content_digest: Some("33".repeat(32)),
                audit_correlation_id: "audit".into(),
                inventory: Vec::new(),
                scope_generation: request.generation,
                revoke_watermark: request.revoke_watermark,
                dependency_frontier: AuthorityFamilyDependencyFrontier {
                    authority_term: 1,
                    global_fence_sequence: 1,
                    dependency_generation: 3,
                },
                authority_completion_receipt_id: "receipt".into(),
            })
            .collect();
        CertifiedMemoryMaterialization {
            scope: request.scope.clone(),
            generation: request.generation,
            revoke_watermark: request.revoke_watermark,
            bundle: CertifiedMemoryFamilyBundle::build(request.scope, completions).unwrap(),
            payloads: vec![
                CertifiedMemoryFamilyPayload::CardContext(Vec::new()),
                CertifiedMemoryFamilyPayload::GlobalAdmin(Vec::new()),
                CertifiedMemoryFamilyPayload::PublishedEvidence(Vec::new()),
                CertifiedMemoryFamilyPayload::OrgAuthorization(Vec::new()),
                CertifiedMemoryFamilyPayload::Ownership(Vec::new()),
                CertifiedMemoryFamilyPayload::SodPolicy(Vec::new()),
            ],
        }
    }

    fn attestation() -> CertifiedMemoryAttestation {
        CertifiedMemoryAttestation {
            authority_term: 1,
            global_fence_sequence: 1,
            key_epoch: 1,
            scope_generation: 3,
            revoke_watermark: 1,
            snapshot_hash: "44".repeat(32),
            issued_at_unix: 9_999,
            expires_at_unix: 10_100,
        }
    }

    #[test]
    fn snapshot_conversion_rejects_forged_bundle_and_duplicate_families() {
        let valid = empty_materialization();
        assert!(matches!(
            valid
                .clone()
                .into_snapshot_input(attestation(), 10_000, 10_100),
            Err(CertifiedMemoryMaterializerError::Pending {
                code: "certified_memory.sod_empty_completeness_unverified",
                ..
            })
        ));

        let mut duplicate = valid.clone();
        duplicate.payloads[1] = CertifiedMemoryFamilyPayload::CardContext(Vec::new());
        assert!(matches!(
            duplicate.into_snapshot_input(attestation(), 10_000, 10_100),
            Err(CertifiedMemoryMaterializerError::Bundle(
                CertifiedMemoryCoordinatorError::DuplicateFamily { .. }
            ))
        ));

        let mut forged = valid.clone();
        forged.bundle.bundle_digest = "55".repeat(32);
        assert!(forged
            .into_snapshot_input(attestation(), 10_000, 10_100)
            .is_err());

        let mut empty_bundle = valid;
        empty_bundle.bundle.completions.clear();
        assert!(empty_bundle
            .into_snapshot_input(attestation(), 10_000, 10_100)
            .is_err());
    }

    #[test]
    fn snapshot_conversion_rejects_nonempty_payload_for_complete_empty() {
        let mut materialization = empty_materialization();
        materialization.payloads[1] =
            CertifiedMemoryFamilyPayload::GlobalAdmin(vec![(1, GlobalAdminStatus::Active)]);
        assert!(matches!(
            materialization.into_snapshot_input(attestation(), 10_000, 10_100),
            Err(CertifiedMemoryMaterializerError::Invalid(_))
        ));
    }

    #[test]
    fn snapshot_conversion_rejects_empty_payload_for_complete() {
        let mut materialization = empty_materialization();
        let completion = &mut materialization.bundle.completions[1];
        completion.state = AuthorityFamilyCompletionState::Complete;
        completion
            .inventory
            .push(astral_types::AuthorityFamilyInventoryItem {
                key: "global-admin:1".into(),
                tenant_id: Some(7),
                content_digest: "44".repeat(32),
            });
        materialization.bundle = CertifiedMemoryFamilyBundle::build(
            materialization.scope.clone(),
            materialization.bundle.completions.clone(),
        )
        .unwrap();
        assert!(matches!(
            materialization.into_snapshot_input(attestation(), 10_000, 10_100),
            Err(CertifiedMemoryMaterializerError::Invalid(_))
        ));
    }

    #[test]
    fn sod_empty_array_and_object_remain_pending_without_durable_empty_proof() {
        use crate::certified_memory_source_owner_producer::{
            SodPolicySourcePayload, SodPolicySourceProvenance,
        };
        let completion = &empty_materialization().bundle.completions[5];
        for payload in [
            CertifiedMemoryFamilyPayload::SodPolicy(Vec::new()),
            CertifiedMemoryFamilyPayload::SodPolicyWithProvenance(SodPolicySourcePayload {
                provenance: SodPolicySourceProvenance {
                    org_contribution_digest: "33".repeat(32),
                },
                facts: Vec::new(),
            }),
        ] {
            assert!(matches!(
                payload.validate_inventory(completion),
                Err(CertifiedMemoryMaterializerError::Pending {
                    code: "certified_memory.sod_empty_completeness_unverified",
                    ..
                })
            ));
        }
    }

    #[test]
    fn nonempty_sod_inventory_stays_pending_without_provenance() {
        let mut value = empty_materialization();
        let completion = &mut value.bundle.completions[5];
        completion.state = AuthorityFamilyCompletionState::Complete;
        completion.inventory = vec![AuthorityFamilyInventoryItem {
            key: "sod-policy:conflict".into(),
            tenant_id: Some(7),
            content_digest: "cc".repeat(32),
        }];
        value.bundle = CertifiedMemoryFamilyBundle::build(
            value.scope.clone(),
            value.bundle.completions.clone(),
        )
        .unwrap();
        value.payloads[5] = CertifiedMemoryFamilyPayload::SodPolicy(vec![CertifiedSodPolicy {
            policy_name: "conflict".into(),
            conflict_type: crate::certified_memory_authority::CertifiedSodConflictType::Static,
            permission_a: Some("rules:read".into()),
            permission_b: Some("rules:write".into()),
            condition_script: None,
            resource_type: None,
            action_code: None,
        }]);
        assert!(matches!(
            value.into_snapshot_input(attestation(), 10_000, 10_100),
            Err(CertifiedMemoryMaterializerError::Pending {
                family: AuthorityCertifiedMemoryFamily::SodPolicy,
                code: "certified_memory.sod_inventory_provenance_missing"
            })
        ));
    }

    #[test]
    fn sod_provenance_binds_inventory_but_does_not_prove_source() {
        use crate::certified_memory_source_owner_producer::{
            sod_policy_inventory_item, SodPolicySourceFact, SodPolicySourcePayload,
            SodPolicySourceProvenance,
        };
        let provenance = SodPolicySourceProvenance {
            org_contribution_digest: "33".repeat(32),
        };
        let fact = SodPolicySourceFact {
            policy: CertifiedSodPolicy {
                policy_name: "conflict".into(),
                conflict_type: crate::certified_memory_authority::CertifiedSodConflictType::Dynamic,
                permission_a: None,
                permission_b: None,
                condition_script: Some("resourceOwnerId == currentUserId".into()),
                resource_type: Some("rules".into()),
                action_code: Some("read".into()),
            },
            dynamic_owner_digest: Some("44".repeat(32)),
        };
        let mut value = empty_materialization();
        let completion = &mut value.bundle.completions[5];
        completion.state = AuthorityFamilyCompletionState::Complete;
        completion.inventory =
            vec![sod_policy_inventory_item(&fact, &provenance, Some(7)).unwrap()];
        value.bundle = CertifiedMemoryFamilyBundle::build(
            value.scope.clone(),
            value.bundle.completions.clone(),
        )
        .unwrap();
        value.payloads[5] =
            CertifiedMemoryFamilyPayload::SodPolicyWithProvenance(SodPolicySourcePayload {
                provenance,
                facts: vec![fact],
            });
        assert!(matches!(
            value
                .clone()
                .into_snapshot_input(attestation(), 10_000, 10_100),
            Err(CertifiedMemoryMaterializerError::Pending {
                code: "certified_memory.sod_source_provenance_unverified",
                ..
            })
        ));
        if let CertifiedMemoryFamilyPayload::SodPolicyWithProvenance(payload) =
            &mut value.payloads[5]
        {
            payload.facts[0].dynamic_owner_digest = Some("55".repeat(32));
        }
        assert!(matches!(
            value.into_snapshot_input(attestation(), 10_000, 10_100),
            Err(CertifiedMemoryMaterializerError::Invalid(_))
        ));
    }

    #[test]
    fn snapshot_conversion_binds_admin_inventory_to_payload() {
        let mut value = empty_materialization();
        let completion = &mut value.bundle.completions[1];
        completion.state = AuthorityFamilyCompletionState::Complete;
        completion.inventory =
            vec![inventory_item("user:5".into(), Some(7), &GlobalAdminStatus::Active).unwrap()];
        value.bundle = CertifiedMemoryFamilyBundle::build(
            value.scope.clone(),
            value.bundle.completions.clone(),
        )
        .unwrap();
        value.payloads[1] =
            CertifiedMemoryFamilyPayload::GlobalAdmin(vec![(5, GlobalAdminStatus::Active)]);
        assert!(value.payloads[1]
            .validate_inventory(&value.bundle.completions[1])
            .is_ok());

        let mut changed = value.clone();
        changed.payloads[1] =
            CertifiedMemoryFamilyPayload::GlobalAdmin(vec![(5, GlobalAdminStatus::Inactive)]);
        assert!(changed.payloads[1]
            .validate_inventory(&changed.bundle.completions[1])
            .is_err());
        value.payloads[1] = CertifiedMemoryFamilyPayload::GlobalAdmin(vec![
            (5, GlobalAdminStatus::Active),
            (6, GlobalAdminStatus::Active),
        ]);
        assert!(value.payloads[1]
            .validate_inventory(&value.bundle.completions[1])
            .is_err());
    }

    #[test]
    fn snapshot_conversion_rejects_non_ready_org_inventory() {
        let mut value = empty_materialization();
        let completion = &mut value.bundle.completions[3];
        completion.state = AuthorityFamilyCompletionState::Complete;
        completion.inventory = vec![AuthorityFamilyInventoryItem {
            key: "org:7:5:8:9".into(),
            tenant_id: Some(7),
            content_digest: "cc".repeat(32),
        }];
        value.bundle = CertifiedMemoryFamilyBundle::build(
            value.scope.clone(),
            value.bundle.completions.clone(),
        )
        .unwrap();
        value.payloads[3] = CertifiedMemoryFamilyPayload::OrgAuthorization(vec![(
            OrgReadKey {
                tenant_id: 7,
                user_id: 5,
                identity_card_id: 8,
                card_id: 9,
            },
            OrgAuthorityRead::Pending {
                code: "org.pending".into(),
            },
        )]);
        assert!(value
            .into_snapshot_input(attestation(), 10_000, 10_100)
            .is_err());
    }

    #[test]
    fn snapshot_conversion_binds_org_evidence_and_revocation() {
        use astral_types::org_scope::{
            OrgAdmissionEvidence, OrgMembership, OrgNode, OrgPublication, OrgRootActivation,
        };
        let mut value = empty_materialization();
        let key = OrgReadKey {
            tenant_id: 7,
            user_id: 23,
            identity_card_id: 31,
            card_id: 17,
        };
        let mut evidence = OrgAdmissionEvidence {
            publication: OrgPublication {
                tenant_id: 7,
                root_tenant_id: 7,
                generation: 1,
                relationship_revision: 1,
                revoke_fence: 0,
                dependencies: Vec::new(),
                manifest_digest_hex: "aa".repeat(32),
                compiler_version: astral_types::AUTHORIZATION_ORG_COMPILER_VERSION.into(),
                segments: Vec::new(),
                operation_id: "op-1".into(),
            },
            node: OrgNode {
                tenant_id: 7,
                root_tenant_id: 7,
                parent_tenant_id: None,
                generation: 1,
                revoke_fence: 0,
                relationship_revision: 1,
                active: true,
                operation_id: "op-1".into(),
                root_activation: Some(OrgRootActivation {
                    operator_user_id: 1,
                    approval_operation_id: "op-0".into(),
                }),
            },
            membership: OrgMembership {
                membership_id: "22222222-2222-4222-8222-222222222222".into(),
                tenant_id: 7,
                root_tenant_id: 7,
                user_id: 23,
                identity_card_id: 31,
                card_id: 17,
                revision: 1,
                active: true,
                validity: astral_types::ValidityWindow::perpetual(),
                operation_id: "op-1".into(),
            },
            checked_at_unix: 100,
        };
        let publication = &evidence.publication;
        evidence.publication.manifest_digest_hex =
            astral_types::org_scope::org_manifest_digest_hex(
                &astral_types::org_scope::OrgManifestDigestMaterial {
                    tenant_id: publication.tenant_id,
                    root_tenant_id: publication.root_tenant_id,
                    generation: publication.generation,
                    relationship_revision: publication.relationship_revision,
                    revoke_fence: publication.revoke_fence,
                    dependencies: &publication.dependencies,
                    segments: &publication.segments,
                    compiler_version: &publication.compiler_version,
                    operation_id: &publication.operation_id,
                },
            )
            .unwrap();
        evidence
            .validate()
            .expect("org evidence fixture must be valid");
        let completion = &mut value.bundle.completions[3];
        completion.state = AuthorityFamilyCompletionState::Complete;
        completion.inventory = vec![AuthorityFamilyInventoryItem {
            key: "org:7:23:31:17".into(),
            tenant_id: Some(7),
            content_digest: astral_types::org_authority_evidence_hash(&evidence).unwrap(),
        }];
        value.bundle = CertifiedMemoryFamilyBundle::build(
            value.scope.clone(),
            value.bundle.completions.clone(),
        )
        .unwrap();
        value.payloads[3] = CertifiedMemoryFamilyPayload::OrgAuthorization(vec![(
            key,
            OrgAuthorityRead::Ready(Box::new(evidence.clone())),
        )]);
        assert!(value.payloads[3]
            .validate_inventory(&value.bundle.completions[3])
            .is_ok());
        let mut revoked = evidence;
        revoked.membership.active = false;
        value.payloads[3] = CertifiedMemoryFamilyPayload::OrgAuthorization(vec![(
            key,
            OrgAuthorityRead::Ready(Box::new(revoked.clone())),
        )]);
        assert!(value.payloads[3]
            .validate_inventory(&value.bundle.completions[3])
            .is_err());
        value.bundle.completions[3].inventory[0].content_digest =
            astral_types::org_authority_revocation_evidence_hash(&revoked).unwrap();
        value.bundle = CertifiedMemoryFamilyBundle::build(
            value.scope.clone(),
            value.bundle.completions.clone(),
        )
        .unwrap();
        assert!(value.payloads[3]
            .validate_inventory(&value.bundle.completions[3])
            .is_ok());
    }

    #[test]
    fn snapshot_conversion_binds_published_manifest_inventory() {
        use astral_types::{
            DomainScopeRequirement, PublishedAggregateManifestSummary,
            PublishedCardAuthorizationGate, PublishedEvidenceGateStatus,
        };
        let mut value = empty_materialization();
        let scope = PublishedCardEvidenceScope {
            tenant_id: 7,
            card_id: 9,
            user_filter: None,
            domain: DomainScopeRequirement::Unconstrained,
        };
        let evidence = PublishedCardAuthorization {
            tenant_id: 7,
            card_id: 9,
            read_unix_seconds: 10_000,
            gate: PublishedCardAuthorizationGate {
                status: PublishedEvidenceGateStatus::Ready,
                aggregate_manifest_count: 1,
                verified_record_count: 0,
                effective_grant_count: 0,
                not_in_effective_count: 0,
                equivalent_duplicate_collapsed_count: 0,
            },
            manifests: vec![PublishedAggregateManifestSummary {
                seal: astral_types::PublicationSeal::from_unix_seconds(10_000).unwrap(),
                tenant_id: 7,
                card_id: 9,
                aggregate_type: "USER_CARD".into(),
                aggregate_id: 9,
                manifest_id: 1,
                generation: 3,
                source_generation: 3,
                projected_generation: 3,
                revoke_fence: 1,
                cas_version: 1,
                semantic_hash_hex: "aa".repeat(32),
                dependency_hash_hex: "bb".repeat(32),
                manifest_digest_hex: "cc".repeat(32),
                compiler_version: astral_types::AUTHORIZATION_COMPILER_VERSION.into(),
                event_id: "event".into(),
                operation_id: "operation".into(),
                parent_manifest_id: None,
                segment_count: 1,
                declared_grant_row_count: 0,
            }],
            records: Vec::new(),
            effective_grants: Vec::new(),
        };
        let completion = &mut value.bundle.completions[2];
        completion.state = AuthorityFamilyCompletionState::Complete;
        completion.inventory = vec![AuthorityFamilyInventoryItem {
            key: "card:7:9:9".into(),
            tenant_id: Some(7),
            content_digest: "cc".repeat(32),
        }];
        value.bundle = CertifiedMemoryFamilyBundle::build(
            value.scope.clone(),
            value.bundle.completions.clone(),
        )
        .unwrap();
        value.payloads[2] = CertifiedMemoryFamilyPayload::PublishedEvidence(vec![(
            scope.clone(),
            Arc::new(evidence.clone()),
        )]);
        assert!(value.payloads[2]
            .validate_inventory(&value.bundle.completions[2])
            .is_ok());
        let mut changed = evidence;
        changed.manifests[0].manifest_digest_hex = "dd".repeat(32);
        value.payloads[2] =
            CertifiedMemoryFamilyPayload::PublishedEvidence(vec![(scope, Arc::new(changed))]);
        assert!(value.payloads[2]
            .validate_inventory(&value.bundle.completions[2])
            .is_err());
    }

    #[test]
    fn snapshot_conversion_binds_ownership_inventory_to_route_and_resolution() {
        let mut value = empty_materialization();
        let key = OwnershipReadKey::new(
            "rules".into(),
            "/rules/42".into(),
            "GET".into(),
            Some(42),
            Some(9),
            Some(5),
        )
        .unwrap();
        let resolution = ResourceOwnershipResolution::TenantScoped {
            target_id: Some(42),
            tenant_id: 7,
            domain_id: Some(4),
            owner_id: Some(5),
        };
        let completion = &mut value.bundle.completions[4];
        completion.state = AuthorityFamilyCompletionState::Complete;
        completion.inventory = vec![
            crate::certified_memory_source_owner_producer::ownership_inventory_item(
                &key,
                &resolution,
                &value.scope,
            )
            .unwrap(),
        ];
        value.bundle = CertifiedMemoryFamilyBundle::build(
            value.scope.clone(),
            value.bundle.completions.clone(),
        )
        .unwrap();
        value.payloads[4] =
            CertifiedMemoryFamilyPayload::Ownership(vec![(key.clone(), resolution)]);
        assert!(value.payloads[4]
            .validate_inventory(&value.bundle.completions[4])
            .is_ok());
        value.payloads[4] = CertifiedMemoryFamilyPayload::Ownership(vec![(
            key,
            ResourceOwnershipResolution::TenantScoped {
                target_id: Some(42),
                tenant_id: 8,
                domain_id: Some(4),
                owner_id: Some(5),
            },
        )]);
        assert!(value.payloads[4]
            .validate_inventory(&value.bundle.completions[4])
            .is_err());
    }

    #[test]
    fn snapshot_conversion_rejects_card_inventory_drift_and_cross_tenant() {
        let mut value = empty_materialization();
        let key = CardContextKey {
            user_id: 5,
            identity_card_id: 8,
            user_card_id: 9,
        };
        let card = CertifiedCardContext {
            user_id: 5,
            eligibility: astral_types::CardEligibility {
                identity_card_id: 8,
                user_card_id: 9,
                user_card_tenant_id: 7,
                user_card_domain_id: 4,
                effective_expiry: None,
            },
        };
        let completion = &mut value.bundle.completions[0];
        completion.state = AuthorityFamilyCompletionState::Complete;
        completion.inventory =
            vec![
                inventory_item("user:5:identity-card:8:user-card:9".into(), Some(7), &card)
                    .unwrap(),
            ];
        value.bundle = CertifiedMemoryFamilyBundle::build(
            value.scope.clone(),
            value.bundle.completions.clone(),
        )
        .unwrap();
        value.payloads[0] = CertifiedMemoryFamilyPayload::CardContext(vec![(key, card.clone())]);
        assert!(value.payloads[0]
            .validate_inventory(&value.bundle.completions[0])
            .is_ok());
        let mut other = card;
        other.eligibility.user_card_tenant_id = 8;
        value.payloads[0] = CertifiedMemoryFamilyPayload::CardContext(vec![(key, other)]);
        assert!(value.payloads[0]
            .validate_inventory(&value.bundle.completions[0])
            .is_err());
    }

    #[test]
    fn terminal_materialization_requires_completion_digest() {
        let scope = request().scope;
        let completion = AuthorityFamilyCompletion {
            family: AuthorityCertifiedMemoryFamily::CardContext,
            state: AuthorityFamilyCompletionState::CompleteEmpty,
            scope,
            reservation_id: "reservation".to_owned(),
            operation_id: "operation".to_owned(),
            event_id: "event".to_owned(),
            message_id: None,
            source_commit_digest: "11".repeat(32),
            source_outcome_digest: "22".repeat(32),
            before_content_digest: None,
            after_content_digest: None,
            complete_content_digest: None,
            audit_correlation_id: "audit".to_owned(),
            inventory: Vec::new(),
            scope_generation: 3,
            revoke_watermark: 1,
            dependency_frontier: AuthorityFamilyDependencyFrontier {
                authority_term: 1,
                global_fence_sequence: 1,
                dependency_generation: 3,
            },
            authority_completion_receipt_id: "receipt".to_owned(),
        };
        let value = CertifiedMemoryFamilyMaterialization {
            family: AuthorityCertifiedMemoryFamily::CardContext,
            completion,
            payload: CertifiedMemoryFamilyPayload::CardContext(Vec::new()),
        };
        assert!(matches!(
            value.validate(&request()),
            Err(CertifiedMemoryMaterializerError::Invalid(_))
        ));
    }
}
