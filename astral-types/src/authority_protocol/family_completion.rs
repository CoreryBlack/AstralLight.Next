//! Authority-bound completion evidence for one certified-memory fact family.
//!
//! This value contract is intentionally independent of SQL, projection workers,
//! and authority transport. A family owner must first produce a durable,
//! reconciled completion record; only then may a coordinator use this contract
//! as input to a certified-memory root. Empty inventory is never interpreted as
//! complete by inference: `CompleteEmpty` is an explicit terminal state.

use serde::{Deserialize, Serialize};

use super::{
    authority_counter, authority_digest, authority_field, authority_text,
    AuthorityCertifiedMemoryFamily, AuthorityCertifiedMemoryRootProposal, AuthorityCommitBinding,
    AuthorityProtocolError, AuthorityProtocolScope, AuthorityScopePublicationCertificate,
    AuthorityScopeReservation, AuthorityStagedScopeCoverage,
};

const MAX_INVENTORY_ITEMS: usize = 4_096;
const MAX_INVENTORY_KEY_BYTES: usize = 512;
const MAX_SCOPE_BYTES: usize = 256;
const MAX_PUBLICATION_CERTIFICATES: usize = 256;

/// Terminal or non-terminal state of one family completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityFamilyCompletionState {
    Complete,
    CompleteEmpty,
    Pending,
    Unknown,
    Quarantined,
}

impl AuthorityFamilyCompletionState {
    pub const fn is_terminal_complete(self) -> bool {
        matches!(self, Self::Complete | Self::CompleteEmpty)
    }

    pub const fn is_non_positive(self) -> bool {
        matches!(self, Self::Pending | Self::Unknown | Self::Quarantined)
    }

    pub const fn as_text(self) -> &'static str {
        match self {
            Self::Complete => "COMPLETE",
            Self::CompleteEmpty => "COMPLETE_EMPTY",
            Self::Pending => "PENDING",
            Self::Unknown => "UNKNOWN",
            Self::Quarantined => "QUARANTINED",
        }
    }
}

/// Tenant/scope binding for one family inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityFamilyScope {
    /// `None` is reserved for a deliberately global family scope.
    pub tenant_id: Option<i64>,
    pub scope: String,
}

impl AuthorityFamilyScope {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        if self.tenant_id.is_some_and(|tenant_id| tenant_id <= 0) {
            return Err(AuthorityProtocolError::InvalidIdentifier { field: "tenant_id" });
        }
        if self.scope.is_empty()
            || self.scope.len() > MAX_SCOPE_BYTES
            || self.scope.trim() != self.scope
            || self.scope.chars().any(|character| character.is_control())
        {
            return Err(AuthorityProtocolError::InvalidText { field: "scope" });
        }
        Ok(())
    }
}

/// Exact immutable publication evidence required before a GLOBAL certified-memory
/// root can be considered for installation.
///
/// This is deliberately a value contract. It does not claim that a source-side
/// snapshot is durable or that the authority has verified the certificate
/// signatures; the service must perform those checks against its own trust root.
/// Missing, duplicated, or drifted scope evidence is rejected here so callers
/// cannot accidentally turn a partial fanout into a complete proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityCertifiedMemoryPublicationProof {
    pub reservation_id: String,
    pub operation_id: String,
    pub event_id: String,
    pub source_commit_digest: String,
    pub source_outcome_digest: String,
    pub declared_coverage: AuthorityStagedScopeCoverage,
    pub certificates: Vec<AuthorityScopePublicationCertificate>,
    pub certificate_set_digest: String,
    /// Per-scope generation/revoke vector. A certified-memory snapshot has a
    /// single root frontier, but its member scopes may legitimately be at
    /// different publication generations; this digest preserves that vector
    /// without collapsing it into one value.
    pub certificate_frontier_digest: String,
    pub family_bundle_digest: String,
    pub snapshot_hash: String,
    pub scope_generation: u64,
    pub revoke_watermark: u64,
}

impl AuthorityCertifiedMemoryPublicationProof {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        authority_text(&self.reservation_id, "reservation_id")?;
        authority_text(&self.operation_id, "operation_id")?;
        authority_text(&self.event_id, "event_id")?;
        authority_digest(&self.source_commit_digest, "source_commit_digest")?;
        authority_digest(&self.source_outcome_digest, "source_outcome_digest")?;
        authority_digest(&self.certificate_set_digest, "certificate_set_digest")?;
        authority_digest(&self.family_bundle_digest, "family_bundle_digest")?;
        authority_digest(&self.snapshot_hash, "snapshot_hash")?;
        authority_counter(self.scope_generation, "scope_generation")?;
        if self.revoke_watermark > self.scope_generation {
            return Err(AuthorityProtocolError::RevokeWatermarkAhead);
        }
        self.declared_coverage.validate()?;
        if self.certificates.len() != self.declared_coverage.scopes.len()
            || self.certificates.len() > MAX_PUBLICATION_CERTIFICATES
        {
            return Err(AuthorityProtocolError::InvalidCoverage);
        }

        let declared: std::collections::BTreeSet<String> = self
            .declared_coverage
            .scopes
            .iter()
            .map(AuthorityProtocolScope::store_key_text)
            .collect::<Result<_, _>>()?;
        let mut seen = std::collections::BTreeSet::new();
        let mut previous_key: Option<String> = None;
        for certificate in &self.certificates {
            certificate.validate()?;
            let scope_key = certificate.scope.store_key_text()?;
            if previous_key
                .as_deref()
                .is_some_and(|previous| previous >= scope_key.as_str())
                || !seen.insert(scope_key.clone())
                || !declared.contains(&scope_key)
            {
                return Err(AuthorityProtocolError::InvalidCoverage);
            }
            previous_key = Some(scope_key);
            let (generation, revoke_watermark) = certificate_frontier(certificate)?;
            if generation > self.scope_generation || revoke_watermark > self.revoke_watermark {
                return Err(AuthorityProtocolError::FrontierDiverged);
            }
            if certificate.reservation_id != self.reservation_id
                || certificate.operation_id != self.operation_id
                || certificate.event_id != self.event_id
                || certificate.source_commit_digest != self.source_commit_digest
                || certificate.source_outcome_digest != self.source_outcome_digest
            {
                return Err(AuthorityProtocolError::ScopeMismatch);
            }
        }
        if seen != declared {
            return Err(AuthorityProtocolError::InvalidCoverage);
        }
        if self.certificate_set_digest()? != self.certificate_set_digest {
            return Err(AuthorityProtocolError::DigestMismatch {
                field: "certificate_set_digest",
            });
        }
        if self.certificate_frontier_digest()? != self.certificate_frontier_digest {
            return Err(AuthorityProtocolError::DigestMismatch {
                field: "certificate_frontier_digest",
            });
        }
        Ok(())
    }

    /// Validate the proof against the authority's immutable reservation and
    /// source commit binding. This is the exact binding used by root install;
    /// it never consults a current scope pointer.
    pub fn validate_for_root(
        &self,
        proposal: &AuthorityCertifiedMemoryRootProposal,
        reservation: &AuthorityScopeReservation,
        binding: &AuthorityCommitBinding,
    ) -> Result<(), AuthorityProtocolError> {
        self.validate()?;
        proposal.validate()?;
        reservation.validate()?;
        binding.validate()?;
        if !reservation.intent.coverage.is_global()
            || reservation.state != super::AuthorityReservationState::Certified
            || self.reservation_id != reservation.reservation_id
            || self.operation_id != reservation.intent.operation_id
            || self.event_id != reservation.intent.event_id
            || self.source_commit_digest != binding.source_commit_digest
            || self.source_outcome_digest != binding.source_outcome_digest
            || binding.reservation_id != reservation.reservation_id
            || binding.operation_id != self.operation_id
            || binding.event_id != self.event_id
            || binding.mutation_kind != super::AuthorityMutationKind::AuthorizationSource
            || reservation.source_commit_digest.as_deref()
                != Some(self.source_commit_digest.as_str())
            || reservation.source_outcome_digest.as_deref()
                != Some(self.source_outcome_digest.as_str())
        {
            return Err(AuthorityProtocolError::ScopeMismatch);
        }
        if proposal.reservation_id != self.reservation_id
            || proposal.operation_id != self.operation_id
            || proposal.event_id != self.event_id
            || proposal.source_commit_digest != self.source_commit_digest
            || proposal.source_outcome_digest != self.source_outcome_digest
            || proposal.family_bundle_digest != self.family_bundle_digest
            || proposal.snapshot_hash != self.snapshot_hash
            || proposal.scope_generation != self.scope_generation
            || proposal.revoke_watermark != self.revoke_watermark
            || proposal.coverage.families != AuthorityCertifiedMemoryFamily::required()
        {
            return Err(AuthorityProtocolError::ScopeMismatch);
        }
        Ok(())
    }

    /// Canonical digest of this complete proof. The certificate-set digest is
    /// included separately so an operation idempotency record can bind the
    /// exact certificate history without trusting JSON ordering.
    pub fn proof_digest(&self) -> Result<String, AuthorityProtocolError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(2048);
        bytes.extend_from_slice(b"ASTRAL_AUTHORITY_CERTIFIED_MEMORY_PUBLICATION_PROOF_V1\0");
        for value in [
            self.reservation_id.as_str(),
            self.operation_id.as_str(),
            self.event_id.as_str(),
            self.source_commit_digest.as_str(),
            self.source_outcome_digest.as_str(),
            self.declared_coverage.coverage_digest()?.as_str(),
            self.certificate_set_digest.as_str(),
            self.certificate_frontier_digest.as_str(),
            self.family_bundle_digest.as_str(),
            self.snapshot_hash.as_str(),
            self.scope_generation.to_string().as_str(),
            self.revoke_watermark.to_string().as_str(),
        ] {
            authority_field(&mut bytes, value);
        }
        Ok(super::authority_sha256_hex(&bytes))
    }

    /// Canonical digest of the ordered per-scope frontier vector.
    pub fn certificate_frontier_digest(&self) -> Result<String, AuthorityProtocolError> {
        self.validate_without_certificate_digest()?;
        let mut bytes = Vec::with_capacity(512 + self.certificates.len() * 96);
        bytes.extend_from_slice(b"ASTRAL_AUTHORITY_CERTIFIED_MEMORY_CERTIFICATE_FRONTIER_V1\0");
        authority_field(&mut bytes, &self.declared_coverage.coverage_digest()?);
        authority_field(&mut bytes, &self.certificates.len().to_string());
        for certificate in &self.certificates {
            let scope_key = certificate.scope.store_key_text()?;
            let (generation, revoke_watermark) = certificate_frontier(certificate)?;
            authority_field(&mut bytes, &scope_key);
            authority_field(&mut bytes, &generation.to_string());
            authority_field(&mut bytes, &revoke_watermark.to_string());
            authority_field(&mut bytes, &certificate.snapshot_hash);
            authority_field(&mut bytes, &certificate.completion_digest);
        }
        Ok(super::authority_sha256_hex(&bytes))
    }

    /// Canonical digest of the ordered immutable certificate records.
    pub fn certificate_set_digest(&self) -> Result<String, AuthorityProtocolError> {
        self.validate_without_certificate_digest()?;
        let mut bytes = Vec::with_capacity(1024 + self.certificates.len() * 128);
        bytes.extend_from_slice(b"ASTRAL_AUTHORITY_CERTIFIED_MEMORY_CERTIFICATE_SET_V1\0");
        authority_field(&mut bytes, &self.declared_coverage.coverage_digest()?);
        authority_field(&mut bytes, &self.certificates.len().to_string());
        for certificate in &self.certificates {
            authority_field(&mut bytes, &certificate.scope.store_key_text()?);
            authority_field(&mut bytes, &certificate.record_digest()?);
        }
        Ok(super::authority_sha256_hex(&bytes))
    }

    fn validate_without_certificate_digest(&self) -> Result<(), AuthorityProtocolError> {
        authority_text(&self.reservation_id, "reservation_id")?;
        authority_text(&self.operation_id, "operation_id")?;
        authority_text(&self.event_id, "event_id")?;
        authority_digest(&self.source_commit_digest, "source_commit_digest")?;
        authority_digest(&self.source_outcome_digest, "source_outcome_digest")?;
        authority_digest(&self.certificate_set_digest, "certificate_set_digest")?;
        authority_digest(&self.family_bundle_digest, "family_bundle_digest")?;
        authority_digest(&self.snapshot_hash, "snapshot_hash")?;
        authority_counter(self.scope_generation, "scope_generation")?;
        if self.revoke_watermark > self.scope_generation {
            return Err(AuthorityProtocolError::RevokeWatermarkAhead);
        }
        self.declared_coverage.validate()?;
        if self.certificates.len() != self.declared_coverage.scopes.len()
            || self.certificates.len() > MAX_PUBLICATION_CERTIFICATES
        {
            return Err(AuthorityProtocolError::InvalidCoverage);
        }
        Ok(())
    }
}

fn certificate_frontier(
    certificate: &AuthorityScopePublicationCertificate,
) -> Result<(u64, u64), AuthorityProtocolError> {
    let mut generation = 0;
    let mut revoke_watermark = 0;
    for manifest in &certificate.manifests {
        manifest.validate()?;
        generation = generation.max(manifest.generation);
        revoke_watermark = revoke_watermark.max(manifest.revoke_fence);
    }
    Ok((generation, revoke_watermark))
}

/// One bounded, exact inventory item. The key is canonical and sorted by the
/// family owner before submission; the digest identifies the complete item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityFamilyInventoryItem {
    pub key: String,
    pub tenant_id: Option<i64>,
    pub content_digest: String,
}

impl AuthorityFamilyInventoryItem {
    pub fn validate_against(
        &self,
        scope: &AuthorityFamilyScope,
    ) -> Result<(), AuthorityProtocolError> {
        if self.key.is_empty()
            || self.key.len() > MAX_INVENTORY_KEY_BYTES
            || self.key.trim() != self.key
            || self.key.chars().any(|character| character.is_control())
        {
            return Err(AuthorityProtocolError::InvalidText {
                field: "inventory_key",
            });
        }
        if self.tenant_id != scope.tenant_id {
            return Err(AuthorityProtocolError::ScopeMismatch);
        }
        if self.tenant_id.is_some_and(|tenant_id| tenant_id <= 0) {
            return Err(AuthorityProtocolError::InvalidIdentifier {
                field: "inventory_tenant_id",
            });
        }
        authority_digest(&self.content_digest, "inventory_content_digest")
    }
}

/// Dependency frontier observed by the family owner at completion time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityFamilyDependencyFrontier {
    pub authority_term: u64,
    pub global_fence_sequence: u64,
    pub dependency_generation: u64,
}

impl AuthorityFamilyDependencyFrontier {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        authority_counter(self.authority_term, "authority_term")?;
        authority_counter(self.global_fence_sequence, "global_fence_sequence")?;
        authority_counter(self.dependency_generation, "dependency_generation")
    }
}

/// Complete family evidence before the authority assigns its receipt identity.
///
/// This is the only completion shape accepted by the authority submission
/// endpoint. The receipt identity is intentionally absent so a caller cannot
/// self-certify or accidentally bind a local receipt to an authority ledger
/// record. The authority returns the receipt-bearing [`AuthorityFamilyCompletion`]
/// after it has fenced and persisted the completion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityFamilyCompletionCandidate {
    pub family: AuthorityCertifiedMemoryFamily,
    pub state: AuthorityFamilyCompletionState,
    pub scope: AuthorityFamilyScope,
    pub reservation_id: String,
    pub operation_id: String,
    pub event_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    pub source_commit_digest: String,
    pub source_outcome_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_content_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_content_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub complete_content_digest: Option<String>,
    pub audit_correlation_id: String,
    pub inventory: Vec<AuthorityFamilyInventoryItem>,
    pub scope_generation: u64,
    pub revoke_watermark: u64,
    pub dependency_frontier: AuthorityFamilyDependencyFrontier,
}

impl AuthorityFamilyCompletionCandidate {
    /// Validate a complete source-owner candidate without accepting an
    /// authority-assigned identity from the caller.
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.scope.validate()?;
        for (value, field) in [
            (&self.reservation_id, "reservation_id"),
            (&self.operation_id, "operation_id"),
            (&self.event_id, "event_id"),
            (&self.source_commit_digest, "source_commit_digest"),
            (&self.source_outcome_digest, "source_outcome_digest"),
            (&self.audit_correlation_id, "audit_correlation_id"),
        ] {
            authority_text(value, field)?;
        }
        if let Some(message_id) = &self.message_id {
            authority_text(message_id, "message_id")?;
        }
        authority_digest(&self.source_commit_digest, "source_commit_digest")?;
        authority_digest(&self.source_outcome_digest, "source_outcome_digest")?;
        for (value, field) in [
            (&self.before_content_digest, "before_content_digest"),
            (&self.after_content_digest, "after_content_digest"),
            (&self.complete_content_digest, "complete_content_digest"),
        ] {
            if let Some(value) = value {
                authority_digest(value, field)?;
            }
        }
        authority_counter(self.scope_generation, "scope_generation")?;
        if self.revoke_watermark > self.scope_generation {
            return Err(AuthorityProtocolError::RevokeWatermarkAhead);
        }
        self.dependency_frontier.validate()?;
        if self.dependency_frontier.dependency_generation > self.scope_generation {
            return Err(AuthorityProtocolError::FrontierDiverged);
        }
        if self.inventory.len() > MAX_INVENTORY_ITEMS {
            return Err(AuthorityProtocolError::InvalidCoverage);
        }

        let mut previous: Option<&str> = None;
        for item in &self.inventory {
            item.validate_against(&self.scope)?;
            if previous.is_some_and(|key| key >= item.key.as_str()) {
                return Err(AuthorityProtocolError::InvalidCoverage);
            }
            previous = Some(item.key.as_str());
        }

        match self.state {
            AuthorityFamilyCompletionState::Complete => {
                if self.inventory.is_empty() || self.complete_content_digest.is_none() {
                    return Err(AuthorityProtocolError::InvalidCoverage);
                }
            }
            AuthorityFamilyCompletionState::CompleteEmpty => {
                if !self.inventory.is_empty() || self.complete_content_digest.is_none() {
                    return Err(AuthorityProtocolError::InvalidCoverage);
                }
            }
            AuthorityFamilyCompletionState::Pending
            | AuthorityFamilyCompletionState::Unknown
            | AuthorityFamilyCompletionState::Quarantined => {
                return Err(AuthorityProtocolError::InvalidCoverage);
            }
        }
        Ok(())
    }

    /// Bind the authority-assigned receipt identity after the authority has
    /// accepted and fenced this candidate.
    pub fn into_receipted_completion(
        self,
        authority_completion_receipt_id: String,
    ) -> Result<AuthorityFamilyCompletion, AuthorityProtocolError> {
        authority_text(
            &authority_completion_receipt_id,
            "authority_completion_receipt_id",
        )?;
        let completion = AuthorityFamilyCompletion {
            family: self.family,
            state: self.state,
            scope: self.scope,
            reservation_id: self.reservation_id,
            operation_id: self.operation_id,
            event_id: self.event_id,
            message_id: self.message_id,
            source_commit_digest: self.source_commit_digest,
            source_outcome_digest: self.source_outcome_digest,
            before_content_digest: self.before_content_digest,
            after_content_digest: self.after_content_digest,
            complete_content_digest: self.complete_content_digest,
            audit_correlation_id: self.audit_correlation_id,
            inventory: self.inventory,
            scope_generation: self.scope_generation,
            revoke_watermark: self.revoke_watermark,
            dependency_frontier: self.dependency_frontier,
            authority_completion_receipt_id,
        };
        completion.validate()?;
        Ok(completion)
    }
}

/// Complete durable identity and bounded inventory for one fact family after
/// the authority has assigned and persisted its receipt identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityFamilyCompletion {
    pub family: AuthorityCertifiedMemoryFamily,
    pub state: AuthorityFamilyCompletionState,
    pub scope: AuthorityFamilyScope,
    pub reservation_id: String,
    pub operation_id: String,
    pub event_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    pub source_commit_digest: String,
    pub source_outcome_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_content_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_content_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub complete_content_digest: Option<String>,
    pub audit_correlation_id: String,
    pub inventory: Vec<AuthorityFamilyInventoryItem>,
    pub scope_generation: u64,
    pub revoke_watermark: u64,
    pub dependency_frontier: AuthorityFamilyDependencyFrontier,
    pub authority_completion_receipt_id: String,
}

impl AuthorityFamilyCompletion {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.scope.validate()?;
        for (value, field) in [
            (&self.reservation_id, "reservation_id"),
            (&self.operation_id, "operation_id"),
            (&self.event_id, "event_id"),
            (&self.source_commit_digest, "source_commit_digest"),
            (&self.source_outcome_digest, "source_outcome_digest"),
            (&self.audit_correlation_id, "audit_correlation_id"),
            (
                &self.authority_completion_receipt_id,
                "authority_completion_receipt_id",
            ),
        ] {
            authority_text(value, field)?;
        }
        if let Some(message_id) = &self.message_id {
            authority_text(message_id, "message_id")?;
        }
        authority_digest(&self.source_commit_digest, "source_commit_digest")?;
        authority_digest(&self.source_outcome_digest, "source_outcome_digest")?;
        for (value, field) in [
            (&self.before_content_digest, "before_content_digest"),
            (&self.after_content_digest, "after_content_digest"),
            (&self.complete_content_digest, "complete_content_digest"),
        ] {
            if let Some(value) = value {
                authority_digest(value, field)?;
            }
        }
        authority_counter(self.scope_generation, "scope_generation")?;
        if self.revoke_watermark > self.scope_generation {
            return Err(AuthorityProtocolError::RevokeWatermarkAhead);
        }
        self.dependency_frontier.validate()?;
        if self.dependency_frontier.dependency_generation > self.scope_generation {
            return Err(AuthorityProtocolError::FrontierDiverged);
        }
        if self.inventory.len() > MAX_INVENTORY_ITEMS {
            return Err(AuthorityProtocolError::InvalidCoverage);
        }

        let mut previous: Option<&str> = None;
        for item in &self.inventory {
            item.validate_against(&self.scope)?;
            if previous.is_some_and(|key| key >= item.key.as_str()) {
                return Err(AuthorityProtocolError::InvalidCoverage);
            }
            previous = Some(item.key.as_str());
        }

        match self.state {
            AuthorityFamilyCompletionState::Complete => {
                if self.inventory.is_empty() || self.complete_content_digest.is_none() {
                    return Err(AuthorityProtocolError::InvalidCoverage);
                }
            }
            AuthorityFamilyCompletionState::CompleteEmpty => {
                if !self.inventory.is_empty() || self.complete_content_digest.is_none() {
                    return Err(AuthorityProtocolError::InvalidCoverage);
                }
            }
            AuthorityFamilyCompletionState::Pending
            | AuthorityFamilyCompletionState::Unknown
            | AuthorityFamilyCompletionState::Quarantined => {
                // Non-terminal states retain stable identities and may retain
                // partial inventory for reconciliation, but they never certify
                // the inventory as complete.
            }
        }
        Ok(())
    }

    /// Canonical bytes for the complete evidence identity. The encoding is
    /// domain-separated and independent of serde/map iteration order.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthorityProtocolError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(2_048);
        bytes.extend_from_slice(b"ASTRAL_AUTHORITY_FAMILY_COMPLETION_V1\0");
        authority_field(&mut bytes, self.family.as_text());
        authority_field(&mut bytes, self.state.as_text());
        authority_field(
            &mut bytes,
            self.scope
                .tenant_id
                .map_or_else(|| "-".to_owned(), |id| id.to_string())
                .as_str(),
        );
        authority_field(&mut bytes, &self.scope.scope);
        for value in [
            &self.reservation_id,
            &self.operation_id,
            &self.event_id,
            self.message_id.as_deref().unwrap_or("-"),
            &self.source_commit_digest,
            &self.source_outcome_digest,
            self.before_content_digest.as_deref().unwrap_or("-"),
            self.after_content_digest.as_deref().unwrap_or("-"),
            self.complete_content_digest.as_deref().unwrap_or("-"),
            &self.audit_correlation_id,
        ] {
            authority_field(&mut bytes, value);
        }
        authority_field(&mut bytes, &self.scope_generation.to_string());
        authority_field(&mut bytes, &self.revoke_watermark.to_string());
        authority_field(
            &mut bytes,
            &self.dependency_frontier.authority_term.to_string(),
        );
        authority_field(
            &mut bytes,
            &self.dependency_frontier.global_fence_sequence.to_string(),
        );
        authority_field(
            &mut bytes,
            &self.dependency_frontier.dependency_generation.to_string(),
        );
        authority_field(&mut bytes, &self.authority_completion_receipt_id);
        authority_field(&mut bytes, &self.inventory.len().to_string());
        for item in &self.inventory {
            authority_field(&mut bytes, &item.key);
            authority_field(
                &mut bytes,
                &item
                    .tenant_id
                    .map_or_else(|| "-".to_owned(), |id| id.to_string()),
            );
            authority_field(&mut bytes, &item.content_digest);
        }
        Ok(bytes)
    }

    pub fn completion_digest(&self) -> Result<String, AuthorityProtocolError> {
        Ok(super::authority_sha256_hex(&self.canonical_bytes()?))
    }

    pub fn inventory_digest(&self) -> Result<String, AuthorityProtocolError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(self.inventory.len() * 128 + 64);
        bytes.extend_from_slice(b"ASTRAL_AUTHORITY_FAMILY_INVENTORY_V1\0");
        authority_field(&mut bytes, self.family.as_text());
        authority_field(&mut bytes, &self.scope.scope);
        for item in &self.inventory {
            authority_field(&mut bytes, &item.key);
            authority_field(
                &mut bytes,
                &item
                    .tenant_id
                    .map_or_else(|| "-".to_owned(), |id| id.to_string()),
            );
            authority_field(&mut bytes, &item.content_digest);
        }
        Ok(super::authority_sha256_hex(&bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn completion(state: AuthorityFamilyCompletionState) -> AuthorityFamilyCompletion {
        AuthorityFamilyCompletion {
            family: AuthorityCertifiedMemoryFamily::CardContext,
            state,
            scope: AuthorityFamilyScope {
                tenant_id: Some(7),
                scope: "tenant:7".to_owned(),
            },
            reservation_id: "reservation-1".to_owned(),
            operation_id: "operation-1".to_owned(),
            event_id: "event-1".to_owned(),
            message_id: Some("message-1".to_owned()),
            source_commit_digest: "11".repeat(32),
            source_outcome_digest: "22".repeat(32),
            before_content_digest: None,
            after_content_digest: None,
            complete_content_digest: Some("33".repeat(32)),
            audit_correlation_id: "audit-1".to_owned(),
            inventory: vec![AuthorityFamilyInventoryItem {
                key: "card:9".to_owned(),
                tenant_id: Some(7),
                content_digest: "44".repeat(32),
            }],
            scope_generation: 3,
            revoke_watermark: 1,
            dependency_frontier: AuthorityFamilyDependencyFrontier {
                authority_term: 2,
                global_fence_sequence: 5,
                dependency_generation: 3,
            },
            authority_completion_receipt_id: "receipt-1".to_owned(),
        }
    }

    #[test]
    fn complete_empty_is_explicit_and_not_inferred() {
        let mut empty = completion(AuthorityFamilyCompletionState::CompleteEmpty);
        empty.inventory.clear();
        assert!(empty.validate().is_ok());

        let mut bare = completion(AuthorityFamilyCompletionState::Complete);
        bare.inventory.clear();
        assert_eq!(
            bare.validate(),
            Err(AuthorityProtocolError::InvalidCoverage)
        );
    }

    #[test]
    fn inventory_is_strictly_sorted_and_tenant_bound() {
        let mut value = completion(AuthorityFamilyCompletionState::Complete);
        value.inventory.push(AuthorityFamilyInventoryItem {
            key: "card:8".to_owned(),
            tenant_id: Some(7),
            content_digest: "55".repeat(32),
        });
        assert_eq!(
            value.validate(),
            Err(AuthorityProtocolError::InvalidCoverage)
        );

        value.inventory[1].key = "card:10".to_owned();
        value.inventory[1].tenant_id = Some(8);
        assert_eq!(value.validate(), Err(AuthorityProtocolError::ScopeMismatch));
    }

    #[test]
    fn non_terminal_states_never_certify_partial_inventory() {
        let mut value = completion(AuthorityFamilyCompletionState::Pending);
        value.inventory.clear();
        value.complete_content_digest = None;
        assert!(value.validate().is_ok());
        assert!(value.state.is_non_positive());
        assert!(!value.state.is_terminal_complete());
    }

    #[test]
    fn digest_is_stable_for_equivalent_inventory() {
        let first = completion(AuthorityFamilyCompletionState::Complete);
        let mut second = first.clone();
        second.inventory = vec![first.inventory[0].clone()];
        assert_eq!(
            first.completion_digest().expect("first digest"),
            second.completion_digest().expect("second digest")
        );
        assert_eq!(
            first.inventory_digest().expect("first inventory digest"),
            second.inventory_digest().expect("second inventory digest")
        );
    }
}
