//! Fail-closed CARD_CONTEXT and GLOBAL_ADMIN source-owner completion producer
//! seams.
//!
//! These functions build the complete typed [`AuthorityFamilyCompletion`]
//! evidence for two closed fact families from the caller's already-locked,
//! already-committed source facts. They never query source tables themselves,
//! never infer `CompleteEmpty` from an empty query result, a cache hit, an ACK,
//! a current pointer, or an HTTP status, and never mint a `PROVEN` completion.
//!
//! The authority client exposes family completion and reconciliation, but these
//! seams do not call it or establish receipt provenance. Consequently every
//! produced value stays non-terminal (`Pending`/`Unknown`); handing back a
//! terminal completion is structurally impossible. The completion writer
//! [`record_proven_certified_memory_completion_in_tx`] does not independently
//! prove that a receipt came from authority. Production integration must prove
//! source commit, complete inventory, projection, audit, and authority receipt
//! provenance before recording a completion.

use astral_types::authority_protocol::{
    AuthorityCertifiedMemoryFamily, AuthorityFamilyCompletion, AuthorityFamilyCompletionCandidate,
    AuthorityFamilyCompletionState, AuthorityFamilyDependencyFrontier,
    AuthorityFamilyInventoryItem, AuthorityFamilyScope,
};
use astral_types::org_authority_evidence_hash;
use astral_types::org_scope::OrgAdmissionEvidence;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::certified_memory_authority::{CardContextKey, CertifiedCardContext, GlobalAdminStatus};
use crate::certified_memory_completion_writer::{
    record_proven_certified_memory_completion_in_tx, CertifiedMemoryCompletionWriteError,
    CertifiedMemoryCompletionWriteRequest,
};

/// One exact, caller-captured CARD_CONTEXT source fact.
///
/// Every field comes from the caller's already-locked source row (or the
/// explicit, committed result of a bounded empty-scope decision made by the
/// caller — never from an empty SQL result alone). Zero-value or non-positive
/// identities are rejected before any payload is built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardContextSourceFact {
    pub key: CardContextKey,
    pub value: CertifiedCardContext,
}

/// One exact, caller-captured GLOBAL_ADMIN source fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlobalAdminSourceFact {
    pub user_id: i64,
    pub status: GlobalAdminStatus,
}

/// One exact, caller-captured OWNERSHIP source fact.
///
/// The resolution must already have been produced by the closed server-side
/// route contract. Unresolved/unavailable outcomes are deliberately rejected:
/// a partial route inventory cannot certify the ownership family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipSourceFact {
    pub key: crate::certified_memory_authority::OwnershipReadKey,
    pub resolution: crate::resource_ownership::ResourceOwnershipResolution,
}

/// One exact ORG admission fact captured by the source owner. The evidence is
/// already read through the formal exact admission reader; this type only
/// preserves that exact identity for the bounded family payload.
#[derive(Debug, Clone, PartialEq)]
pub struct OrgAuthorizationSourceFact {
    pub tenant_id: i64,
    pub user_id: i64,
    pub identity_card_id: i64,
    pub card_id: i64,
    pub evidence: OrgAdmissionEvidence,
}

/// Explicit proof that a bounded ORG selector was complete and empty. The
/// selector digest must be committed by the source owner; an empty SQL result
/// alone can never construct this value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgAuthorizationEmptyProof {
    pub tenant_id: i64,
    pub selector_digest: String,
}

/// One exact, caller-captured SOD_POLICY source fact and its dependent proof
/// identities. The dependent digests are part of the inventory and payload.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SodPolicySourceFact {
    pub policy: crate::certified_memory_authority::CertifiedSodPolicy,
    /// Required for every DYNAMIC policy. This identifies the durable dynamic
    /// owner/provenance snapshot used by the policy evaluator.
    pub dynamic_owner_digest: Option<String>,
}

/// Durable provenance identity required before a SOD_POLICY family can be
/// considered completely enumerated. The certified SoD read path still needs
/// the matching ORG contribution implementation before it can serve positive
/// decisions.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SodPolicySourceProvenance {
    pub org_contribution_digest: String,
}

/// Carries source identities through the durable payload; it does not itself
/// establish that the referenced source snapshots exist or are complete.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SodPolicySourcePayload {
    pub provenance: SodPolicySourceProvenance,
    pub facts: Vec<SodPolicySourceFact>,
}
///
/// These are the exact reservation/operation/event/message and digest
/// identities of the source mutation the caller has already proven. This seam
/// never derives them from queries or environment metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceOwnerCompletionIdentity {
    pub scope: AuthorityFamilyScope,
    pub scope_generation: u64,
    pub revoke_watermark: u64,
    pub dependency_frontier: AuthorityFamilyDependencyFrontier,
    pub reservation_id: String,
    pub operation_id: String,
    pub event_id: String,
    pub message_id: Option<String>,
    pub source_commit_digest: String,
    pub source_outcome_digest: String,
    pub before_content_digest: Option<String>,
    pub after_content_digest: Option<String>,
    pub audit_correlation_id: String,
}

impl SourceOwnerCompletionIdentity {
    fn validate(&self) -> Result<(), SourceOwnerCompletionError> {
        self.scope
            .validate()
            .map_err(|error| SourceOwnerCompletionError::Invalid(error.to_string()))?;
        if self.scope_generation == 0 {
            return Err(SourceOwnerCompletionError::Invalid(
                "source owner completion requires a positive scope_generation".into(),
            ));
        }
        if self.revoke_watermark > self.scope_generation {
            return Err(SourceOwnerCompletionError::Invalid(
                "source owner completion revoke watermark is ahead of scope_generation".into(),
            ));
        }
        self.dependency_frontier
            .validate()
            .map_err(|error| SourceOwnerCompletionError::Invalid(error.to_string()))?;
        if self.dependency_frontier.dependency_generation > self.scope_generation {
            return Err(SourceOwnerCompletionError::Invalid(
                "source owner completion dependency frontier diverged from scope_generation".into(),
            ));
        }
        for (value, field) in [
            (&self.reservation_id, "reservation_id"),
            (&self.operation_id, "operation_id"),
            (&self.event_id, "event_id"),
            (&self.source_commit_digest, "source_commit_digest"),
            (&self.source_outcome_digest, "source_outcome_digest"),
            (&self.audit_correlation_id, "audit_correlation_id"),
        ] {
            validate_source_text(value, field)?;
        }
        if let Some(message_id) = &self.message_id {
            validate_source_text(message_id, "message_id")?;
        }
        for (value, field) in [
            (&self.source_commit_digest, "source_commit_digest"),
            (&self.source_outcome_digest, "source_outcome_digest"),
        ] {
            validate_source_digest(value, field)?;
        }
        for (value, field) in [
            (&self.before_content_digest, "before_content_digest"),
            (&self.after_content_digest, "after_content_digest"),
        ] {
            if let Some(value) = value {
                validate_source_digest(value, field)?;
            }
        }
        Ok(())
    }
}

const MAX_FAMILY_FACTS: usize = 4_096;
const MAX_INVENTORY_KEY_BYTES: usize = 512;

/// Why a source-owner completion draft cannot be produced.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SourceOwnerCompletionError {
    /// A captured fact or identity is invalid; the caller must fail closed and
    /// quarantine or re-derive from its own proven evidence.
    #[error("source-owner completion draft is invalid: {0}")]
    Invalid(String),
    /// The producer cannot prove the authority completion receipt for this
    /// family today; the completion stays PENDING and the reconciliation owner
    /// must finish it. This is the only outcome the current seam can produce
    /// for valid input.
    #[error("authority completion receipt is not yet producible; completion stays PENDING")]
    AuthorityReceiptUnavailable,
}

fn validate_source_text(
    value: &str,
    field: &'static str,
) -> Result<(), SourceOwnerCompletionError> {
    if value.is_empty()
        || value.len() > 128
        || value.trim() != value
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(SourceOwnerCompletionError::Invalid(format!(
            "source owner completion {field} is not canonical bounded text"
        )));
    }
    Ok(())
}

fn validate_source_digest(
    value: &str,
    field: &'static str,
) -> Result<(), SourceOwnerCompletionError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SourceOwnerCompletionError::Invalid(format!(
            "source owner completion {field} must be a lowercase sha-256 digest"
        )));
    }
    Ok(())
}

fn validate_inventory_key(key: &str) -> Result<(), SourceOwnerCompletionError> {
    if key.is_empty()
        || key.len() > MAX_INVENTORY_KEY_BYTES
        || key.trim() != key
        || key.chars().any(|character| character.is_control())
    {
        return Err(SourceOwnerCompletionError::Invalid(
            "source-owner inventory key is not canonical bounded text".into(),
        ));
    }
    Ok(())
}

fn validate_optional_digest(
    value: Option<&str>,
    field: &'static str,
) -> Result<(), SourceOwnerCompletionError> {
    let Some(value) = value else {
        return Err(SourceOwnerCompletionError::Invalid(format!(
            "{field} is required for a complete source-owner inventory"
        )));
    };
    validate_source_digest(value, field)
}

/// Build an ORG_AUTHORIZATION completion from the source owner's exact,
/// bounded admission inventory. Every fact is validated against its key and the
/// complete family is kept lexically sorted. An empty inventory is rejected;
/// callers must use [`build_org_authorization_empty_completion`] with a durable
/// selector proof instead.
pub fn build_org_authorization_family_completion(
    identity: &SourceOwnerCompletionIdentity,
    facts: &[OrgAuthorizationSourceFact],
) -> Result<(AuthorityFamilyCompletion, String), SourceOwnerCompletionError> {
    identity.validate()?;
    if facts.is_empty() {
        return Err(SourceOwnerCompletionError::Invalid(
            "ORG authorization inventory cannot infer complete-empty from zero facts".into(),
        ));
    }
    if facts.len() > MAX_FAMILY_FACTS {
        return Err(SourceOwnerCompletionError::Invalid(
            "ORG authorization source facts exceed the bounded inventory capacity".into(),
        ));
    }
    let mut sorted: Vec<&OrgAuthorizationSourceFact> = facts.iter().collect();
    sorted.sort_by_key(|fact| (fact.user_id, fact.identity_card_id, fact.card_id));
    let mut previous_key: Option<String> = None;
    let mut inventory = Vec::with_capacity(sorted.len());
    let mut payload_entries = Vec::with_capacity(sorted.len());
    for fact in sorted {
        if fact.tenant_id <= 0
            || fact.user_id <= 0
            || fact.identity_card_id <= 0
            || fact.card_id <= 0
            || fact.evidence.membership.tenant_id != fact.tenant_id
            || fact.evidence.membership.user_id != fact.user_id
            || fact.evidence.membership.identity_card_id != fact.identity_card_id
            || fact.evidence.membership.card_id != fact.card_id
        {
            return Err(SourceOwnerCompletionError::Invalid(
                "ORG authorization source fact does not bind its exact key".into(),
            ));
        }
        fact.evidence
            .validate()
            .map_err(|error| SourceOwnerCompletionError::Invalid(error.message))?;
        let key = format!(
            "org:{}:{}:{}:{}",
            fact.tenant_id, fact.user_id, fact.identity_card_id, fact.card_id
        );
        validate_inventory_key(&key)?;
        if previous_key
            .as_deref()
            .is_some_and(|previous| previous >= key.as_str())
        {
            return Err(SourceOwnerCompletionError::Invalid(
                "ORG authorization source facts contain a duplicate key".into(),
            ));
        }
        previous_key = Some(key.clone());
        let content_digest = org_authority_evidence_hash(&fact.evidence)
            .map_err(|error| SourceOwnerCompletionError::Invalid(error.to_string()))?;
        inventory.push(AuthorityFamilyInventoryItem {
            key,
            tenant_id: Some(fact.tenant_id),
            content_digest,
        });
        payload_entries.push(serde_json::json!({
            "key": {
                "tenantId": fact.tenant_id,
                "userId": fact.user_id,
                "identityCardId": fact.identity_card_id,
                "cardId": fact.card_id,
            },
            "value": {
                "kind": "READY",
                "evidence": fact.evidence,
            },
        }));
    }
    let payload_json = serde_json::to_string(&payload_entries).map_err(|error| {
        SourceOwnerCompletionError::Invalid(format!(
            "ORG authorization payload cannot be canonicalized: {error}"
        ))
    })?;
    let completion = completion_from_parts(
        identity,
        AuthorityCertifiedMemoryFamily::OrgAuthorization,
        inventory,
        &payload_json,
    )?;
    Ok((completion, payload_json))
}

/// Build an explicit ORG complete-empty draft from a source-owner selector
/// proof. The selector digest is the source outcome identity, not a digest
/// guessed from an empty payload.
pub fn build_org_authorization_empty_completion(
    identity: &SourceOwnerCompletionIdentity,
    proof: &OrgAuthorizationEmptyProof,
) -> Result<(AuthorityFamilyCompletion, String), SourceOwnerCompletionError> {
    identity.validate()?;
    if proof.tenant_id <= 0 || identity.scope.tenant_id != Some(proof.tenant_id) {
        return Err(SourceOwnerCompletionError::Invalid(
            "ORG empty proof tenant does not match completion scope".into(),
        ));
    }
    validate_source_digest(&proof.selector_digest, "selector_digest")?;
    if identity.source_outcome_digest != proof.selector_digest {
        return Err(SourceOwnerCompletionError::Invalid(
            "ORG empty proof must bind the committed source outcome digest".into(),
        ));
    }
    let payload_json = "[]".to_owned();
    let completion = completion_from_parts(
        identity,
        AuthorityCertifiedMemoryFamily::OrgAuthorization,
        Vec::new(),
        &payload_json,
    )?;
    Ok((completion, payload_json))
}

/// inventory. The caller must have enumerated every route in the fixed registry;
/// this function only validates and canonicalizes the captured result.
pub fn build_ownership_family_completion(
    identity: &SourceOwnerCompletionIdentity,
    facts: &[OwnershipSourceFact],
) -> Result<(AuthorityFamilyCompletion, String), SourceOwnerCompletionError> {
    identity.validate()?;
    if facts.len() > MAX_FAMILY_FACTS {
        return Err(SourceOwnerCompletionError::Invalid(
            "ownership source facts exceed the bounded inventory capacity".into(),
        ));
    }
    let mut sorted: Vec<&OwnershipSourceFact> = facts.iter().collect();
    sorted.sort_by_key(|fact| ownership_sort_key(&fact.key));
    let mut inventory = Vec::with_capacity(sorted.len());
    let mut payload_entries = Vec::with_capacity(sorted.len());
    let mut previous_key: Option<String> = None;
    for fact in sorted {
        let key_json = serde_json::to_string(&fact.key).map_err(|error| {
            SourceOwnerCompletionError::Invalid(format!(
                "ownership key cannot be canonicalized: {error}"
            ))
        })?;
        let key_text = format!("ownership:{key_json}");
        validate_inventory_key(&key_text)?;
        if previous_key
            .as_deref()
            .is_some_and(|previous| previous >= key_text.as_str())
        {
            return Err(SourceOwnerCompletionError::Invalid(
                "ownership source facts contain a duplicate or unsorted key".into(),
            ));
        }
        previous_key = Some(key_text.clone());
        let resolution = ownership_wire_resolution(&fact.resolution, &identity.scope)?;
        let resolution_json = serde_json::to_value(&resolution).map_err(|error| {
            SourceOwnerCompletionError::Invalid(format!(
                "ownership resolution cannot be serialized: {error}"
            ))
        })?;
        inventory.push(ownership_inventory_item(
            &fact.key,
            &fact.resolution,
            &identity.scope,
        )?);
        payload_entries.push(serde_json::json!({
            "key": fact.key,
            "resolution": resolution_json,
        }));
    }
    let payload_json =
        serde_json::to_string(&serde_json::Value::Array(payload_entries)).map_err(|error| {
            SourceOwnerCompletionError::Invalid(format!(
                "ownership payload cannot be canonicalized: {error}"
            ))
        })?;
    let completion = completion_from_parts(
        identity,
        AuthorityCertifiedMemoryFamily::Ownership,
        inventory,
        &payload_json,
    )?;
    Ok((completion, payload_json))
}

/// Build an SOD_POLICY completion from a complete policy snapshot and explicit
/// ORG/dynamic provenance. Missing provenance is an UNKNOWN boundary, never an
/// empty policy proof.
pub fn build_sod_policy_family_completion(
    identity: &SourceOwnerCompletionIdentity,
    facts: &[SodPolicySourceFact],
    provenance: &SodPolicySourceProvenance,
) -> Result<(AuthorityFamilyCompletion, String), SourceOwnerCompletionError> {
    identity.validate()?;
    validate_source_digest(
        &provenance.org_contribution_digest,
        "org_contribution_digest",
    )?;
    if facts.len() > MAX_FAMILY_FACTS {
        return Err(SourceOwnerCompletionError::Invalid(
            "SoD policy source facts exceed the bounded inventory capacity".into(),
        ));
    }
    let mut sorted: Vec<&SodPolicySourceFact> = facts.iter().collect();
    sorted.sort_by_key(|fact| sod_policy_sort_key(&fact.policy));
    let mut inventory = Vec::with_capacity(sorted.len());
    let mut payload_facts = Vec::with_capacity(sorted.len());
    let mut previous_name: Option<&str> = None;
    for fact in sorted {
        if previous_name.is_some_and(|previous| previous >= fact.policy.policy_name.as_str()) {
            return Err(SourceOwnerCompletionError::Invalid(
                "SoD policy source facts contain a duplicate or unsorted policy name".into(),
            ));
        }
        previous_name = Some(&fact.policy.policy_name);
        inventory.push(sod_policy_inventory_item(
            fact,
            provenance,
            identity.scope.tenant_id,
        )?);
        payload_facts.push(fact.clone());
    }
    let payload_json = serde_json::to_string(&SodPolicySourcePayload {
        provenance: provenance.clone(),
        facts: payload_facts,
    })
    .map_err(|error| {
        SourceOwnerCompletionError::Invalid(format!(
            "SoD policy payload cannot be canonicalized: {error}"
        ))
    })?;
    let completion = completion_from_parts(
        identity,
        AuthorityCertifiedMemoryFamily::SodPolicy,
        inventory,
        &payload_json,
    )?;
    Ok((completion, payload_json))
}

pub(crate) fn sod_policy_inventory_item(
    fact: &SodPolicySourceFact,
    provenance: &SodPolicySourceProvenance,
    tenant_id: Option<i64>,
) -> Result<AuthorityFamilyInventoryItem, SourceOwnerCompletionError> {
    validate_source_digest(
        &provenance.org_contribution_digest,
        "org_contribution_digest",
    )?;
    fact.policy
        .validate()
        .map_err(SourceOwnerCompletionError::Invalid)?;
    if matches!(
        fact.policy.conflict_type,
        crate::certified_memory_authority::CertifiedSodConflictType::Dynamic
    ) {
        validate_optional_digest(fact.dynamic_owner_digest.as_deref(), "dynamic_owner_digest")?;
    } else if fact.dynamic_owner_digest.is_some() {
        return Err(SourceOwnerCompletionError::Invalid(
            "STATIC SoD policy cannot carry a dynamic owner digest".into(),
        ));
    }
    let inventory_key = format!("sod-policy:{}", fact.policy.policy_name);
    validate_inventory_key(&inventory_key)?;
    let content_identity = serde_json::json!({
        "policy": &fact.policy,
        "dynamicOwnerDigest": &fact.dynamic_owner_digest,
        "orgContributionDigest": &provenance.org_contribution_digest,
    });
    Ok(AuthorityFamilyInventoryItem {
        key: inventory_key,
        tenant_id,
        content_digest: content_digest_hex(&content_identity)?,
    })
}

/// Produce a fail-closed OWNERSHIP draft. No authority receipt or durable row is
/// created by this function.
pub fn produce_ownership_family_completion(
    identity: &SourceOwnerCompletionIdentity,
    facts: &[OwnershipSourceFact],
) -> SourceOwnerCompletionOutcome {
    match build_ownership_family_completion(identity, facts) {
        Ok((completion, payload_json)) => SourceOwnerCompletionOutcome::Pending {
            completion: Box::new(completion),
            payload_json,
        },
        Err(SourceOwnerCompletionError::Invalid(message)) => {
            SourceOwnerCompletionOutcome::Unknown {
                code: invalid_code(&message),
            }
        }
        Err(SourceOwnerCompletionError::AuthorityReceiptUnavailable) => unreachable!(),
    }
}

/// Produce a fail-closed SOD_POLICY draft. Missing ORG or dynamic-owner
/// provenance is returned as UNKNOWN by the builder.
pub fn produce_sod_policy_family_completion(
    identity: &SourceOwnerCompletionIdentity,
    facts: &[SodPolicySourceFact],
    provenance: &SodPolicySourceProvenance,
) -> SourceOwnerCompletionOutcome {
    match build_sod_policy_family_completion(identity, facts, provenance) {
        Ok((completion, payload_json)) => SourceOwnerCompletionOutcome::Pending {
            completion: Box::new(completion),
            payload_json,
        },
        Err(SourceOwnerCompletionError::Invalid(message)) => {
            SourceOwnerCompletionOutcome::Unknown {
                code: invalid_code(&message),
            }
        }
        Err(SourceOwnerCompletionError::AuthorityReceiptUnavailable) => unreachable!(),
    }
}

#[derive(Debug, serde::Serialize)]
#[serde(
    tag = "kind",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase"
)]
enum OwnershipWireResolution {
    TenantScoped {
        target_id: Option<i64>,
        tenant_id: i64,
        domain_id: Option<i64>,
        owner_id: Option<i64>,
    },
    Global {
        target_id: Option<i64>,
        access_requirement: astral_types::GlobalAccessRequirement,
    },
}

pub(crate) fn ownership_inventory_item(
    key: &crate::certified_memory_authority::OwnershipReadKey,
    resolution: &crate::resource_ownership::ResourceOwnershipResolution,
    scope: &AuthorityFamilyScope,
) -> Result<AuthorityFamilyInventoryItem, SourceOwnerCompletionError> {
    let key_text = format!(
        "ownership:{}",
        serde_json::to_string(key).map_err(|error| {
            SourceOwnerCompletionError::Invalid(format!(
                "ownership key cannot be canonicalized: {error}"
            ))
        })?
    );
    validate_inventory_key(&key_text)?;
    let value =
        serde_json::to_value(ownership_wire_resolution(resolution, scope)?).map_err(|error| {
            SourceOwnerCompletionError::Invalid(format!(
                "ownership resolution cannot be serialized: {error}"
            ))
        })?;
    Ok(AuthorityFamilyInventoryItem {
        key: key_text,
        tenant_id: scope.tenant_id,
        content_digest: content_digest_hex(&value)?,
    })
}

fn ownership_wire_resolution(
    resolution: &crate::resource_ownership::ResourceOwnershipResolution,
    scope: &AuthorityFamilyScope,
) -> Result<OwnershipWireResolution, SourceOwnerCompletionError> {
    match resolution {
        crate::resource_ownership::ResourceOwnershipResolution::TenantScoped {
            target_id,
            tenant_id,
            domain_id,
            owner_id,
        } => {
            if scope.tenant_id != Some(*tenant_id) || *tenant_id <= 0 {
                return Err(SourceOwnerCompletionError::Invalid(
                    "ownership resolution tenant does not bind family scope".into(),
                ));
            }
            if domain_id.is_some_and(|id| id <= 0)
                || owner_id.is_some_and(|id| id <= 0)
                || target_id.is_some_and(|id| id <= 0)
            {
                return Err(SourceOwnerCompletionError::Invalid(
                    "ownership resolution contains a non-positive identifier".into(),
                ));
            }
            Ok(OwnershipWireResolution::TenantScoped {
                target_id: *target_id,
                tenant_id: *tenant_id,
                domain_id: *domain_id,
                owner_id: *owner_id,
            })
        }
        crate::resource_ownership::ResourceOwnershipResolution::Global {
            target_id,
            access_requirement,
        } => {
            if *access_requirement == astral_types::GlobalAccessRequirement::Unspecified
                || target_id.is_some_and(|id| id <= 0)
            {
                return Err(SourceOwnerCompletionError::Invalid(
                    "global ownership resolution lacks a declared access requirement".into(),
                ));
            }
            Ok(OwnershipWireResolution::Global {
                target_id: *target_id,
                access_requirement: *access_requirement,
            })
        }
        crate::resource_ownership::ResourceOwnershipResolution::Unresolved { .. }
        | crate::resource_ownership::ResourceOwnershipResolution::Unavailable { .. } => {
            Err(SourceOwnerCompletionError::Invalid(
                "unresolved ownership cannot certify a complete family".into(),
            ))
        }
    }
}

fn ownership_sort_key(key: &crate::certified_memory_authority::OwnershipReadKey) -> String {
    serde_json::to_string(key).unwrap_or_default()
}

fn sod_policy_sort_key(policy: &crate::certified_memory_authority::CertifiedSodPolicy) -> String {
    policy.policy_name.clone()
}

/// facts.
///
/// The payload is the exact family-owner wire contract consumed by
/// `CertifiedMemoryFamilyOwner` decoding (`[{"key":..,"value":..}]`, camelCase),
/// sorted by key so the inventory is canonical. `CompleteEmpty` is never
/// inferred here: for a genuinely empty family the caller must pass the
/// explicit empty fact list together with
/// [`SourceOwnerCompletionIdentity`] values that its own durable owner already
/// proved — the returned completion still stays PENDING until the source and
/// authority receipt are independently proven and reconciled.
pub fn build_card_context_family_completion(
    identity: &SourceOwnerCompletionIdentity,
    facts: &[CardContextSourceFact],
) -> Result<(AuthorityFamilyCompletion, String), SourceOwnerCompletionError> {
    identity.validate()?;
    if facts.len() > MAX_FAMILY_FACTS {
        return Err(SourceOwnerCompletionError::Invalid(
            "card context source facts exceed the bounded inventory capacity".into(),
        ));
    }
    let mut sorted: Vec<&CardContextSourceFact> = facts.iter().collect();
    sorted.sort_by_key(|fact| fact.key);
    let mut inventory = Vec::with_capacity(sorted.len());
    let mut payload_entries = Vec::with_capacity(sorted.len());
    let mut previous_key: Option<CardContextKey> = None;
    for fact in sorted {
        if fact.key.user_id <= 0
            || fact.key.identity_card_id <= 0
            || fact.key.user_card_id <= 0
            || fact.value.user_id <= 0
        {
            return Err(SourceOwnerCompletionError::Invalid(
                "card context source fact has a non-positive identity".into(),
            ));
        }
        if fact.value.validate_for(&fact.key).is_err()
            || identity
                .scope
                .tenant_id
                .is_some_and(|tenant_id| tenant_id != fact.value.eligibility.user_card_tenant_id)
        {
            return Err(SourceOwnerCompletionError::Invalid(
                "card context source fact does not bind its exact key and tenant scope".into(),
            ));
        }
        if let Some(previous) = previous_key {
            if previous >= fact.key {
                return Err(SourceOwnerCompletionError::Invalid(
                    "card context source facts contain a duplicate key".into(),
                ));
            }
        }
        previous_key = Some(fact.key);
        let key_text = format!(
            "user:{}:identity-card:{}:user-card:{}",
            fact.key.user_id, fact.key.identity_card_id, fact.key.user_card_id
        );
        validate_inventory_key(&key_text)?;
        let value_json = serde_json::to_value(&fact.value).map_err(|error| {
            SourceOwnerCompletionError::Invalid(format!(
                "card context source fact cannot be serialized: {error}"
            ))
        })?;
        inventory.push(AuthorityFamilyInventoryItem {
            key: key_text,
            tenant_id: identity.scope.tenant_id,
            content_digest: content_digest_hex(&value_json)?,
        });
        // The family-owner wire contract is one object per entry:
        // `{"key": CardContextKey, "value": CertifiedCardContext}`.
        payload_entries.push(serde_json::json!({ "key": &fact.key, "value": value_json }));
    }
    let payload = serde_json::Value::Array(payload_entries);
    let payload_json = serde_json::to_string(&payload).map_err(|error| {
        SourceOwnerCompletionError::Invalid(format!(
            "card context payload cannot be canonicalized: {error}"
        ))
    })?;
    let completion = completion_from_parts(
        identity,
        AuthorityCertifiedMemoryFamily::CardContext,
        inventory,
        &payload_json,
    )?;
    Ok((completion, payload_json))
}

/// Build the typed GLOBAL_ADMIN family completion from caller-captured source
/// facts.
///
/// The payload is the exact family-owner wire contract consumed by
/// `CertifiedMemoryFamilyOwner` decoding (`[{"userId":..,"status":..}]`),
/// sorted by `user_id`. An empty caller-supplied fact list is the only way
/// `CompleteEmpty` is ever expressed, and even then the returned completion
/// stays non-terminal until the authority receipt is proven and reconciled.
pub fn build_global_admin_family_completion(
    identity: &SourceOwnerCompletionIdentity,
    facts: &[GlobalAdminSourceFact],
) -> Result<(AuthorityFamilyCompletion, String), SourceOwnerCompletionError> {
    identity.validate()?;
    if facts.len() > MAX_FAMILY_FACTS {
        return Err(SourceOwnerCompletionError::Invalid(
            "global admin source facts exceed the bounded inventory capacity".into(),
        ));
    }
    let mut sorted: Vec<&GlobalAdminSourceFact> = facts.iter().collect();
    sorted.sort_by_key(|fact| fact.user_id);
    let mut inventory = Vec::with_capacity(sorted.len());
    let mut payload_entries = Vec::with_capacity(sorted.len());
    let mut previous_user_id: Option<i64> = None;
    for fact in sorted {
        if fact.user_id <= 0 {
            return Err(SourceOwnerCompletionError::Invalid(
                "global admin source fact has a non-positive user identity".into(),
            ));
        }
        if previous_user_id.is_some_and(|previous| previous >= fact.user_id) {
            return Err(SourceOwnerCompletionError::Invalid(
                "global admin source facts contain a duplicate user identity".into(),
            ));
        }
        previous_user_id = Some(fact.user_id);
        let key_text = format!("user:{}", fact.user_id);
        let status_json = serde_json::to_value(fact.status).map_err(|error| {
            SourceOwnerCompletionError::Invalid(format!(
                "global admin source fact cannot be serialized: {error}"
            ))
        })?;
        inventory.push(AuthorityFamilyInventoryItem {
            key: key_text,
            tenant_id: identity.scope.tenant_id,
            content_digest: content_digest_hex(&status_json)?,
        });
        payload_entries.push(serde_json::json!({
            "userId": fact.user_id,
            "status": status_json,
        }));
    }
    let payload = serde_json::Value::Array(payload_entries);
    let payload_json = serde_json::to_string(&payload).map_err(|error| {
        SourceOwnerCompletionError::Invalid(format!(
            "global admin payload cannot be canonicalized: {error}"
        ))
    })?;
    let completion = completion_from_parts(
        identity,
        AuthorityCertifiedMemoryFamily::GlobalAdmin,
        inventory,
        &payload_json,
    )?;
    Ok((completion, payload_json))
}

/// The fail-closed outcome of the producer seam.
///
/// `Pending` and `Unknown` carry the full evidence draft so the reconciliation
/// owner can reconcile them against independently proven source and authority
/// evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceOwnerCompletionOutcome {
    /// The evidence draft is complete and internally consistent, but the
    /// authority completion receipt cannot be proven yet, so the completion is
    /// not terminal and must not be persisted as PROVEN.
    Pending {
        completion: Box<AuthorityFamilyCompletion>,
        payload_json: String,
    },
    /// The producer cannot even guarantee the draft is current (for example
    /// because the caller's evidence is contradictory). Nothing is produced.
    Unknown { code: &'static str },
}

/// Produce the CARD_CONTEXT source-owner completion outcome.
///
/// This never returns a terminal completion and never writes durable state.
/// It does not query source tables; the caller owns the source transaction and
/// must prove commit, projection, audit, and authority evidence independently
/// before any future durable producer step.
pub fn produce_card_context_family_completion(
    identity: &SourceOwnerCompletionIdentity,
    facts: &[CardContextSourceFact],
) -> SourceOwnerCompletionOutcome {
    match build_card_context_family_completion(identity, facts) {
        Ok((completion, payload_json)) => SourceOwnerCompletionOutcome::Pending {
            completion: Box::new(completion),
            payload_json,
        },
        Err(SourceOwnerCompletionError::Invalid(message)) => {
            SourceOwnerCompletionOutcome::Unknown {
                code: invalid_code(&message),
            }
        }
        Err(SourceOwnerCompletionError::AuthorityReceiptUnavailable) => {
            unreachable!("draft builders never construct AuthorityReceiptUnavailable directly")
        }
    }
}

/// Produce the GLOBAL_ADMIN source-owner completion outcome.
///
/// Same contract as [`produce_card_context_family_completion`]: typed,
/// digest-bound, non-terminal, and never durable.
pub fn produce_global_admin_family_completion(
    identity: &SourceOwnerCompletionIdentity,
    facts: &[GlobalAdminSourceFact],
) -> SourceOwnerCompletionOutcome {
    match build_global_admin_family_completion(identity, facts) {
        Ok((completion, payload_json)) => SourceOwnerCompletionOutcome::Pending {
            completion: Box::new(completion),
            payload_json,
        },
        Err(SourceOwnerCompletionError::Invalid(message)) => {
            SourceOwnerCompletionOutcome::Unknown {
                code: invalid_code(&message),
            }
        }
        Err(SourceOwnerCompletionError::AuthorityReceiptUnavailable) => {
            unreachable!("draft builders never construct AuthorityReceiptUnavailable directly")
        }
    }
}

/// Request persistence through the completion writer.
///
/// The caller must prove the source commit, projection, audit, and authority
/// evidence independently. The legacy writer has no verified receipt input and
/// currently returns UNKNOWN before ledger access.
pub async fn record_independently_proven_family_completion_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    completion: AuthorityFamilyCompletion,
    payload_json: impl Into<String>,
) -> Result<
    crate::certified_memory_completion_writer::CertifiedMemoryCompletionWriteResult,
    CertifiedMemoryCompletionWriteError,
> {
    let request = CertifiedMemoryCompletionWriteRequest::new(completion, payload_json)?;
    record_proven_certified_memory_completion_in_tx(tx, request).await
}

/// Promote a source-owner draft into an authority submission candidate.
///
/// The terminal state is supplied explicitly by the source owner. An empty
/// inventory therefore becomes `CompleteEmpty` only when the caller has
/// deliberately selected that terminal state; this function never derives
/// completeness from a query result. Authority still assigns the receipt and
/// the post-commit reconciler still verifies the committed source outcome.
pub fn finalize_source_owner_completion(
    draft: AuthorityFamilyCompletion,
    payload_json: impl Into<String>,
    state: AuthorityFamilyCompletionState,
) -> Result<(AuthorityFamilyCompletionCandidate, String), SourceOwnerCompletionError> {
    if !matches!(
        state,
        AuthorityFamilyCompletionState::Complete | AuthorityFamilyCompletionState::CompleteEmpty
    ) {
        return Err(SourceOwnerCompletionError::Invalid(
            "source-owner completion must use an explicit terminal state".into(),
        ));
    }
    if !draft.authority_completion_receipt_id.is_empty()
        || !matches!(draft.state, AuthorityFamilyCompletionState::Pending)
    {
        return Err(SourceOwnerCompletionError::Invalid(
            "source-owner draft is not an unreceipted pending completion".into(),
        ));
    }
    let payload_json = payload_json.into();
    let parsed: serde_json::Value = serde_json::from_str(&payload_json).map_err(|error| {
        SourceOwnerCompletionError::Invalid(format!(
            "source-owner payload is invalid JSON: {error}"
        ))
    })?;
    if !parsed.is_array() {
        return Err(SourceOwnerCompletionError::Invalid(
            "source-owner payload must be a top-level inventory array".into(),
        ));
    }
    let canonical = serde_json::to_string(&parsed).map_err(|error| {
        SourceOwnerCompletionError::Invalid(format!(
            "source-owner payload cannot be canonicalized: {error}"
        ))
    })?;
    if canonical != payload_json {
        return Err(SourceOwnerCompletionError::Invalid(
            "source-owner payload must already be canonical JSON".into(),
        ));
    }
    let complete_content_digest = hex::encode(Sha256::digest(canonical.as_bytes()));
    let candidate = AuthorityFamilyCompletionCandidate {
        family: draft.family,
        state,
        scope: draft.scope,
        reservation_id: draft.reservation_id,
        operation_id: draft.operation_id,
        event_id: draft.event_id,
        message_id: draft.message_id,
        source_commit_digest: draft.source_commit_digest,
        source_outcome_digest: draft.source_outcome_digest,
        before_content_digest: draft.before_content_digest,
        after_content_digest: draft.after_content_digest,
        complete_content_digest: Some(complete_content_digest),
        audit_correlation_id: draft.audit_correlation_id,
        inventory: draft.inventory,
        scope_generation: draft.scope_generation,
        revoke_watermark: draft.revoke_watermark,
        dependency_frontier: draft.dependency_frontier,
    };
    if matches!(state, AuthorityFamilyCompletionState::CompleteEmpty)
        && !candidate.inventory.is_empty()
        || matches!(state, AuthorityFamilyCompletionState::Complete)
            && candidate.inventory.is_empty()
    {
        return Err(SourceOwnerCompletionError::Invalid(
            "terminal state does not match the explicitly captured inventory".into(),
        ));
    }
    candidate.validate().map_err(|error| {
        SourceOwnerCompletionError::Invalid(format!("source-owner candidate is invalid: {error}"))
    })?;
    let preflight = candidate
        .clone()
        .into_receipted_completion("source-owner-preflight".into())
        .map_err(|error| SourceOwnerCompletionError::Invalid(error.to_string()))?;
    let payload = crate::certified_memory_family_owner::decode_certified_memory_payload(
        candidate.family,
        &canonical,
    )
    .map_err(|error| SourceOwnerCompletionError::Invalid(error.to_string()))?;
    payload
        .validate_inventory(&preflight)
        .map_err(|error| SourceOwnerCompletionError::Invalid(error.to_string()))?;
    Ok((candidate, canonical))
}

/// Construct a complete source-owner candidate from one of the typed family
/// builders. This is the only local promotion boundary before authority.
pub fn finalize_source_owner_draft(
    draft: AuthorityFamilyCompletion,
    payload_json: impl Into<String>,
    complete_empty: bool,
) -> Result<(AuthorityFamilyCompletionCandidate, String), SourceOwnerCompletionError> {
    finalize_source_owner_completion(
        draft,
        payload_json,
        if complete_empty {
            AuthorityFamilyCompletionState::CompleteEmpty
        } else {
            AuthorityFamilyCompletionState::Complete
        },
    )
}

fn completion_from_parts(
    identity: &SourceOwnerCompletionIdentity,
    family: AuthorityCertifiedMemoryFamily,
    inventory: Vec<AuthorityFamilyInventoryItem>,
    payload_json: &str,
) -> Result<AuthorityFamilyCompletion, SourceOwnerCompletionError> {
    if inventory.is_empty() && identity.after_content_digest.is_none() {
        // An explicitly empty family still needs a stable content identity:
        // the canonical empty-array payload digest is the only acceptable
        // complete_content_digest, and the caller must bind it itself via the
        // after/complete digest fields it proved. Nothing is inferred here.
    }
    // The protocol orders inventory keys lexically, independently of the
    // numeric ordering used by the typed payload.
    let mut inventory = inventory;
    inventory.sort_by(|left, right| left.key.cmp(&right.key));
    let completion = AuthorityFamilyCompletion {
        family,
        // This draft has no authority receipt provenance and therefore never
        // becomes terminal here.
        state: AuthorityFamilyCompletionState::Pending,
        scope: identity.scope.clone(),
        reservation_id: identity.reservation_id.clone(),
        operation_id: identity.operation_id.clone(),
        event_id: identity.event_id.clone(),
        message_id: identity.message_id.clone(),
        source_commit_digest: identity.source_commit_digest.clone(),
        source_outcome_digest: identity.source_outcome_digest.clone(),
        before_content_digest: identity.before_content_digest.clone(),
        after_content_digest: identity.after_content_digest.clone(),
        // The draft does not claim terminal completeness. A producer must
        // prove the complete inventory and authority receipt independently.
        complete_content_digest: None,
        audit_correlation_id: identity.audit_correlation_id.clone(),
        inventory,
        scope_generation: identity.scope_generation,
        revoke_watermark: identity.revoke_watermark,
        dependency_frontier: identity.dependency_frontier,
        // The draft carries no receipt. A receipt ID alone would not prove
        // authority provenance or make this a terminal completion.
        authority_completion_receipt_id: String::new(),
    };
    // No AuthorityFamilyCompletion::validate() here: validation would reject
    // the deliberately empty authority_completion_receipt_id. The draft is
    // intentionally protocol-invalid so it can never reach the proof-only
    // writer as a terminal completion.
    let _ = payload_json;
    Ok(completion)
}

fn content_digest_hex(value: &serde_json::Value) -> Result<String, SourceOwnerCompletionError> {
    let canonical = serde_json::to_string(value).map_err(|error| {
        SourceOwnerCompletionError::Invalid(format!(
            "inventory item content cannot be canonicalized: {error}"
        ))
    })?;
    Ok(hex::encode(Sha256::digest(canonical.as_bytes())))
}

fn invalid_code(message: &str) -> &'static str {
    // The outcome carries a stable, bounded code; detailed reason text stays in
    // the typed error the caller received from the build step. Keep this
    // fail-closed and non-positive.
    let _ = message;
    "certified_memory.source_owner_completion_invalid"
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::authority_protocol::AuthorityProtocolError;
    use astral_types::CardEligibility;

    fn identity() -> SourceOwnerCompletionIdentity {
        SourceOwnerCompletionIdentity {
            scope: AuthorityFamilyScope {
                tenant_id: Some(7),
                scope: "tenant:7".into(),
            },
            scope_generation: 3,
            revoke_watermark: 1,
            dependency_frontier: AuthorityFamilyDependencyFrontier {
                authority_term: 1,
                global_fence_sequence: 2,
                dependency_generation: 3,
            },
            reservation_id: "reservation-1".into(),
            operation_id: "operation-1".into(),
            event_id: "event-1".into(),
            message_id: Some("message-1".into()),
            source_commit_digest: "11".repeat(32),
            source_outcome_digest: "22".repeat(32),
            before_content_digest: None,
            after_content_digest: None,
            audit_correlation_id: "audit-1".into(),
        }
    }

    fn card_fact(user_id: i64, user_card_id: i64) -> CardContextSourceFact {
        CardContextSourceFact {
            key: CardContextKey {
                user_id,
                identity_card_id: 8,
                user_card_id,
            },
            value: CertifiedCardContext {
                user_id,
                eligibility: CardEligibility {
                    identity_card_id: 8,
                    user_card_id,
                    user_card_tenant_id: 7,
                    user_card_domain_id: 4,
                    effective_expiry: None,
                },
            },
        }
    }

    fn org_evidence(user_id: i64, identity_card_id: i64, card_id: i64) -> OrgAdmissionEvidence {
        use astral_types::org_scope::{
            org_build_segment, org_manifest_digest_hex, OrgContribution, OrgGrantRef,
            OrgManifestDigestMaterial, OrgProvenance, OrgPublication, OrgScope, OrgScopeKey,
            OrgSegmentContent,
        };

        let grant_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned();
        let contribution = OrgContribution {
            grant_ref: OrgGrantRef {
                tenant_id: 7,
                grant_id,
                revision: 1,
            },
            scope: OrgScope {
                resource_tenant_id: 7,
                domain_id: None,
                resource: "doc:42".into(),
                action: "read".into(),
                validity: astral_types::ValidityWindow::perpetual(),
            },
            delegable: true,
            subject: None,
            provenance: OrgProvenance {
                origin_tenant_id: 7,
                parent_chain: Vec::new(),
                operation_id: "op-1".into(),
            },
        };
        let segment = org_build_segment(
            0,
            OrgSegmentContent {
                key: OrgScopeKey {
                    resource: "doc:42".into(),
                    action: "read".into(),
                },
                contributions: vec![contribution],
            },
        )
        .expect("valid ORG segment");
        let publication = OrgPublication {
            tenant_id: 7,
            root_tenant_id: 7,
            generation: 1,
            relationship_revision: 1,
            revoke_fence: 0,
            dependencies: Vec::new(),
            manifest_digest_hex: String::new(),
            compiler_version: astral_types::AUTHORIZATION_ORG_COMPILER_VERSION.into(),
            segments: vec![segment],
            operation_id: "op-1".into(),
        };
        let manifest_digest_hex = org_manifest_digest_hex(&OrgManifestDigestMaterial {
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
        .expect("valid ORG manifest");
        OrgAdmissionEvidence {
            publication: OrgPublication {
                manifest_digest_hex,
                ..publication
            },
            node: astral_types::org_scope::OrgNode {
                tenant_id: 7,
                root_tenant_id: 7,
                parent_tenant_id: None,
                generation: 1,
                revoke_fence: 0,
                relationship_revision: 1,
                active: true,
                operation_id: "op-1".into(),
                root_activation: Some(astral_types::org_scope::OrgRootActivation {
                    operator_user_id: 1,
                    approval_operation_id: "op-0".into(),
                }),
            },
            membership: astral_types::org_scope::OrgMembership {
                membership_id: format!("22222222-2222-4222-8222-{:012}", user_id * 1000 + card_id),
                tenant_id: 7,
                root_tenant_id: 7,
                user_id,
                identity_card_id,
                card_id,
                revision: 1,
                active: true,
                validity: astral_types::ValidityWindow::perpetual(),
                operation_id: "op-1".into(),
            },
            checked_at_unix: 100,
        }
    }

    #[test]
    fn org_authorization_capture_requires_non_empty_exact_inventory() {
        assert!(matches!(
            build_org_authorization_family_completion(&identity(), &[]),
            Err(SourceOwnerCompletionError::Invalid(message))
                if message.contains("cannot infer complete-empty")
        ));

        let evidence = org_evidence(23, 31, 17);
        let fact = OrgAuthorizationSourceFact {
            tenant_id: 7,
            user_id: 23,
            identity_card_id: 31,
            card_id: 17,
            evidence,
        };
        let (completion, payload) =
            build_org_authorization_family_completion(&identity(), &[fact]).expect("ORG draft");
        assert_eq!(
            completion.family,
            AuthorityCertifiedMemoryFamily::OrgAuthorization
        );
        assert_eq!(completion.state, AuthorityFamilyCompletionState::Pending);
        assert_eq!(completion.inventory[0].key, "org:7:23:31:17");
        assert!(completion.authority_completion_receipt_id.is_empty());
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&payload).unwrap()[0]["value"]["kind"],
            "READY"
        );
    }

    #[test]
    fn org_authorization_capture_rejects_key_drift_and_duplicates() {
        let evidence = org_evidence(23, 31, 17);
        let mismatched = OrgAuthorizationSourceFact {
            tenant_id: 7,
            user_id: 24,
            identity_card_id: 31,
            card_id: 17,
            evidence: evidence.clone(),
        };
        assert!(matches!(
            build_org_authorization_family_completion(&identity(), &[mismatched]),
            Err(SourceOwnerCompletionError::Invalid(message))
                if message.contains("does not bind")
        ));

        let first = OrgAuthorizationSourceFact {
            tenant_id: 7,
            user_id: 23,
            identity_card_id: 31,
            card_id: 17,
            evidence: evidence.clone(),
        };
        let second = first.clone();
        assert!(matches!(
            build_org_authorization_family_completion(&identity(), &[first, second]),
            Err(SourceOwnerCompletionError::Invalid(message))
                if message.contains("duplicate key")
        ));
    }

    #[test]
    fn org_authorization_empty_requires_committed_selector_digest() {
        let mut proof_identity = identity();
        let proof = OrgAuthorizationEmptyProof {
            tenant_id: 7,
            selector_digest: proof_identity.source_outcome_digest.clone(),
        };
        let (completion, payload) =
            build_org_authorization_empty_completion(&proof_identity, &proof)
                .expect("explicit empty proof");
        assert_eq!(completion.state, AuthorityFamilyCompletionState::Pending);
        assert!(completion.inventory.is_empty());
        assert_eq!(payload, "[]");
        assert!(completion.authority_completion_receipt_id.is_empty());

        proof_identity.source_outcome_digest = "33".repeat(32);
        assert!(matches!(
            build_org_authorization_empty_completion(&proof_identity, &proof),
            Err(SourceOwnerCompletionError::Invalid(message))
                if message.contains("source outcome digest")
        ));
    }

    #[test]
    fn card_context_producer_stays_pending_and_never_mints_terminal_state() {
        let facts = vec![card_fact(9, 100)];
        let outcome = produce_card_context_family_completion(&identity(), &facts);
        let SourceOwnerCompletionOutcome::Pending {
            completion,
            payload_json,
        } = outcome
        else {
            panic!("valid facts must produce a Pending draft");
        };
        assert_eq!(completion.state, AuthorityFamilyCompletionState::Pending);
        assert!(!completion.state.is_terminal_complete());
        assert!(completion.complete_content_digest.is_none());
        assert_eq!(completion.authority_completion_receipt_id, "");
        assert_eq!(completion.inventory.len(), 1);
        assert_eq!(
            completion.inventory[0].key,
            "user:9:identity-card:8:user-card:100"
        );
        let payload: serde_json::Value = serde_json::from_str(&payload_json).expect("payload");
        assert_eq!(payload[0]["key"]["userId"], 9);
        assert_eq!(payload[0]["key"]["userCardId"], 100);
    }

    #[test]
    fn global_admin_producer_stays_pending_and_payload_matches_family_owner_wire() {
        let facts = vec![
            GlobalAdminSourceFact {
                user_id: 12,
                status: GlobalAdminStatus::Active,
            },
            GlobalAdminSourceFact {
                user_id: 5,
                status: GlobalAdminStatus::Inactive,
            },
        ];
        let outcome = produce_global_admin_family_completion(&identity(), &facts);
        let SourceOwnerCompletionOutcome::Pending {
            completion,
            payload_json,
        } = outcome
        else {
            panic!("valid facts must produce a Pending draft");
        };
        assert_eq!(
            completion.family,
            AuthorityCertifiedMemoryFamily::GlobalAdmin
        );
        assert_eq!(completion.state, AuthorityFamilyCompletionState::Pending);
        assert_eq!(completion.inventory.len(), 2);
        // Inventory uses protocol lexical order; payload uses numeric order.
        assert_eq!(completion.inventory[0].key, "user:12");
        assert_eq!(completion.inventory[1].key, "user:5");
        let payload: serde_json::Value = serde_json::from_str(&payload_json).expect("payload");
        assert_eq!(payload[0]["userId"], 5);
        assert_eq!(payload[0]["status"], "Inactive");
        assert_eq!(payload[1]["status"], "Active");
    }

    #[test]
    fn non_positive_or_duplicate_facts_fail_closed_to_unknown() {
        let outcome = produce_card_context_family_completion(
            &identity(),
            &[CardContextSourceFact {
                key: CardContextKey {
                    user_id: 0,
                    identity_card_id: 8,
                    user_card_id: 9,
                },
                value: CertifiedCardContext {
                    user_id: 0,
                    eligibility: CardEligibility {
                        identity_card_id: 8,
                        user_card_id: 9,
                        user_card_tenant_id: 7,
                        user_card_domain_id: 4,
                        effective_expiry: None,
                    },
                },
            }],
        );
        assert!(matches!(
            outcome,
            SourceOwnerCompletionOutcome::Unknown { .. }
        ));

        let outcome = produce_global_admin_family_completion(
            &identity(),
            &[
                GlobalAdminSourceFact {
                    user_id: 5,
                    status: GlobalAdminStatus::Active,
                },
                GlobalAdminSourceFact {
                    user_id: 5,
                    status: GlobalAdminStatus::Inactive,
                },
            ],
        );
        assert!(matches!(
            outcome,
            SourceOwnerCompletionOutcome::Unknown { .. }
        ));
    }

    #[test]
    fn draft_inventory_uses_authority_lexical_order() {
        let (mut completion, _) = build_card_context_family_completion(
            &identity(),
            &[card_fact(5, 100), card_fact(12, 101)],
        )
        .unwrap();
        assert_eq!(
            completion.inventory[0].key,
            "user:12:identity-card:8:user-card:101"
        );
        assert_eq!(
            completion.inventory[1].key,
            "user:5:identity-card:8:user-card:100"
        );
        completion.authority_completion_receipt_id = "receipt".into();
        assert!(completion.validate().is_ok());

        let (mut completion, _) = build_global_admin_family_completion(
            &identity(),
            &[
                GlobalAdminSourceFact {
                    user_id: 5,
                    status: GlobalAdminStatus::Active,
                },
                GlobalAdminSourceFact {
                    user_id: 12,
                    status: GlobalAdminStatus::Inactive,
                },
            ],
        )
        .unwrap();
        completion.authority_completion_receipt_id = "receipt".into();
        assert!(completion.validate().is_ok());
    }

    #[test]
    fn card_context_rejects_fact_from_another_tenant() {
        let mut fact = card_fact(9, 100);
        fact.value.eligibility.user_card_tenant_id = 8;
        assert!(matches!(
            produce_card_context_family_completion(&identity(), &[fact]),
            SourceOwnerCompletionOutcome::Unknown { .. }
        ));
    }

    #[test]
    fn identity_validation_rejects_watermark_frontier_and_digest_drift() {
        let mut diverged = identity();
        diverged.revoke_watermark = 4;
        assert!(matches!(
            build_global_admin_family_completion(&diverged, &[]),
            Err(SourceOwnerCompletionError::Invalid(_))
        ));
        let mut bad_digest = identity();
        bad_digest.source_commit_digest = "zz".repeat(32);
        assert!(matches!(
            build_card_context_family_completion(&bad_digest, &[]),
            Err(SourceOwnerCompletionError::Invalid(_))
        ));
        let mut bad_frontier = identity();
        bad_frontier.dependency_frontier = AuthorityFamilyDependencyFrontier {
            authority_term: 1,
            global_fence_sequence: 2,
            dependency_generation: 9,
        };
        assert_eq!(
            build_global_admin_family_completion(&bad_frontier, &[]),
            Err(SourceOwnerCompletionError::Invalid(
                "source owner completion dependency frontier diverged from scope_generation".into()
            ))
        );
    }

    #[test]
    fn card_context_value_must_bind_its_key_exactly() {
        let mut mismatched = card_fact(9, 100);
        mismatched.value.user_id = 10;
        let outcome = produce_card_context_family_completion(&identity(), &[mismatched]);
        assert!(matches!(
            outcome,
            SourceOwnerCompletionOutcome::Unknown { .. }
        ));
    }

    #[test]
    fn empty_fact_list_is_explicit_caller_input_and_stays_pending() {
        // An empty fact list is only ever a caller-supplied explicit input; the
        // producer still does not mark it terminal CompleteEmpty.
        let outcome = produce_global_admin_family_completion(&identity(), &[]);
        let SourceOwnerCompletionOutcome::Pending {
            completion,
            payload_json,
        } = outcome
        else {
            panic!("explicit empty input produces a draft");
        };
        assert!(completion.inventory.is_empty());
        assert_eq!(completion.state, AuthorityFamilyCompletionState::Pending);
        assert_eq!(payload_json, "[]");
    }

    #[test]
    fn ownership_producer_rejects_unresolved_and_keeps_valid_rows_pending() {
        let key = crate::certified_memory_authority::OwnershipReadKey::new(
            "rules".into(),
            "/rules".into(),
            "GET".into(),
            Some(41),
            Some(8),
            Some(9),
        )
        .expect("ownership key");
        let valid = OwnershipSourceFact {
            key: key.clone(),
            resolution: crate::resource_ownership::ResourceOwnershipResolution::TenantScoped {
                target_id: Some(41),
                tenant_id: 7,
                domain_id: Some(4),
                owner_id: Some(9),
            },
        };
        let SourceOwnerCompletionOutcome::Pending {
            completion,
            payload_json,
        } = produce_ownership_family_completion(&identity(), &[valid])
        else {
            panic!("valid ownership facts must stay pending without authority receipt");
        };
        assert_eq!(completion.family, AuthorityCertifiedMemoryFamily::Ownership);
        assert_eq!(completion.state, AuthorityFamilyCompletionState::Pending);
        assert!(completion.complete_content_digest.is_none());
        let decoded: serde_json::Value = serde_json::from_str(&payload_json).expect("payload");
        assert_eq!(decoded[0]["key"]["resource"], "rules");
        assert_eq!(decoded[0]["resolution"]["kind"], "TENANT_SCOPED");

        let unresolved = OwnershipSourceFact {
            key,
            resolution: crate::resource_ownership::ResourceOwnershipResolution::Unavailable {
                code: "ownership.unavailable",
            },
        };
        assert!(matches!(
            produce_ownership_family_completion(&identity(), &[unresolved]),
            SourceOwnerCompletionOutcome::Unknown { .. }
        ));
    }

    #[test]
    fn sod_policy_producer_requires_dynamic_owner_and_org_provenance() {
        let dynamic = SodPolicySourceFact {
            policy: crate::certified_memory_authority::CertifiedSodPolicy {
                policy_name: "owner-conflict".into(),
                conflict_type: crate::certified_memory_authority::CertifiedSodConflictType::Dynamic,
                permission_a: None,
                permission_b: None,
                condition_script: Some("resourceOwnerId == currentUserId".into()),
                resource_type: Some("rules".into()),
                action_code: Some("read".into()),
            },
            dynamic_owner_digest: None,
        };
        let provenance = SodPolicySourceProvenance {
            org_contribution_digest: "33".repeat(32),
        };
        assert!(matches!(
            produce_sod_policy_family_completion(
                &identity(),
                std::slice::from_ref(&dynamic),
                &provenance
            ),
            SourceOwnerCompletionOutcome::Unknown { .. }
        ));

        let mut complete = dynamic;
        complete.dynamic_owner_digest = Some("44".repeat(32));
        let SourceOwnerCompletionOutcome::Pending {
            completion,
            payload_json,
        } = produce_sod_policy_family_completion(&identity(), &[complete], &provenance)
        else {
            panic!("fully bound SoD facts must stay pending without authority receipt");
        };
        assert_eq!(completion.family, AuthorityCertifiedMemoryFamily::SodPolicy);
        assert_eq!(completion.state, AuthorityFamilyCompletionState::Pending);
        let decoded: serde_json::Value = serde_json::from_str(&payload_json).expect("payload");
        assert_eq!(
            decoded["facts"][0]["policy"]["policy_name"],
            "owner-conflict"
        );
        assert_eq!(decoded["facts"][0]["dynamicOwnerDigest"], "44".repeat(32));
        assert_eq!(
            decoded["provenance"]["orgContributionDigest"],
            "33".repeat(32)
        );
    }

    #[test]
    fn protocol_error_conversion_keeps_codes_stable() {
        // The stable invalid code is bounded and non-positive.
        assert_eq!(
            invalid_code("anything"),
            "certified_memory.source_owner_completion_invalid"
        );
        // AuthorityProtocolError is what completion.validate() surfaces.
        let error = AuthorityProtocolError::InvalidCoverage;
        assert!(error.to_string().contains("coverage"));
    }
}
