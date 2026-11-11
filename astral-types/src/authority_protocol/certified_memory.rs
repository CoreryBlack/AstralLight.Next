//! V7 certified-memory root contract.
//!
//! The authority signs only this metadata root. It never signs arbitrary memory
//! contents or accepts caller-provided keys. The root binds the immutable source
//! operation, the authority frontier, the complete closed family set, and the
//! content identity that a certified-memory installer must materialize.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::{
    authority_counter, authority_digest, authority_field, authority_signature_encoding,
    authority_text, authority_time_window, authority_timestamp, authority_verify_strict,
    AuthorityCallerIdentity, AuthorityProtocolError, AuthorityReadGate, GlobalAuthorityFrontier,
    AUTHORITY_PROTOCOL_VERSION,
};
use crate::AUTHORIZATION_EDITION;

const ROOT_CONTENT_DOMAIN: &[u8] = b"ASTRAL_CERTIFIED_MEMORY_ROOT_CONTENT_V7\0";
const ROOT_SIGNATURE_DOMAIN: &[u8] = b"ASTRAL_CERTIFIED_MEMORY_ROOT_SIGNATURE_V7\0";
const ROOT_RECORD_DOMAIN: &[u8] = b"ASTRAL_CERTIFIED_MEMORY_ROOT_RECORD_V7\0";
const MAX_FAMILY_COUNT: usize = 6;
const MAX_ROOT_TTL_SECONDS: i64 = 3_600;

/// Authenticated internal routes for the authority-owned certified-memory root.
pub const AUTHORITY_PATH_CERTIFIED_MEMORY_ROOT_INSTALL: &str =
    "/main/api/v1/authority-certified-memory-roots";
pub const AUTHORITY_PATH_CERTIFIED_MEMORY_ROOT_CURRENT: &str =
    "/main/api/v1/authority-certified-memory-roots/current";
/// Compatibility aliases for callers that name the resource plural/current.
pub const AUTHORITY_PATH_CERTIFIED_MEMORY_ROOTS: &str =
    AUTHORITY_PATH_CERTIFIED_MEMORY_ROOT_INSTALL;
pub const AUTHORITY_PATH_CERTIFIED_MEMORY_ROOT_READ: &str =
    AUTHORITY_PATH_CERTIFIED_MEMORY_ROOT_CURRENT;

/// The closed set of fact families a certified-memory root may cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityCertifiedMemoryFamily {
    CardContext,
    GlobalAdmin,
    PublishedEvidence,
    OrgAuthorization,
    Ownership,
    SodPolicy,
}

impl AuthorityCertifiedMemoryFamily {
    pub const fn as_text(self) -> &'static str {
        match self {
            Self::CardContext => "CARD_CONTEXT",
            Self::GlobalAdmin => "GLOBAL_ADMIN",
            Self::PublishedEvidence => "PUBLISHED_EVIDENCE",
            Self::OrgAuthorization => "ORG_AUTHORIZATION",
            Self::Ownership => "OWNERSHIP",
            Self::SodPolicy => "SOD_POLICY",
        }
    }

    pub const fn required() -> [Self; MAX_FAMILY_COUNT] {
        [
            Self::CardContext,
            Self::GlobalAdmin,
            Self::PublishedEvidence,
            Self::OrgAuthorization,
            Self::Ownership,
            Self::SodPolicy,
        ]
    }
}

/// Explicit coverage declaration. The ordered complete list is canonical.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityCertifiedMemoryCoverage {
    pub families: Vec<AuthorityCertifiedMemoryFamily>,
}

impl AuthorityCertifiedMemoryCoverage {
    pub fn complete() -> Self {
        Self {
            families: AuthorityCertifiedMemoryFamily::required().to_vec(),
        }
    }

    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        if self.families.len() != MAX_FAMILY_COUNT
            || self.families.as_slice() != AuthorityCertifiedMemoryFamily::required()
        {
            return Err(AuthorityProtocolError::InvalidCoverage);
        }
        Ok(())
    }

    pub fn canonical_text(&self) -> String {
        self.families
            .iter()
            .map(|family| family.as_text())
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Operation kind is closed intentionally: callers cannot make the authority
/// execute an unregistered certified-memory operation by sending a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityCertifiedMemoryRootOperation {
    Install,
    Read,
}

impl AuthorityCertifiedMemoryRootOperation {
    pub const fn as_text(self) -> &'static str {
        match self {
            Self::Install => "INSTALL",
            Self::Read => "READ",
        }
    }
}

/// Unsigned source-side proposal. The authority supplies the current frontier,
/// issue time, signing key identity, root digest, and signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityCertifiedMemoryRootProposal {
    pub protocol_version: u16,
    pub authorization_edition: u16,
    pub authority_id: String,
    pub reservation_id: String,
    pub operation_id: String,
    pub event_id: String,
    pub source_commit_digest: String,
    pub source_outcome_digest: String,
    pub family_bundle_digest: String,
    /// Optional until source owners adopt the exact immutable publication
    /// proof. Authority installation requires this field to be present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publication_proof: Option<super::AuthorityCertifiedMemoryPublicationProof>,
    pub snapshot_hash: String,
    pub scope_generation: u64,
    pub revoke_watermark: u64,
    pub parent_root_digest: Option<String>,
    pub coverage: AuthorityCertifiedMemoryCoverage,
    pub not_before: i64,
    pub expires_at: i64,
}

impl AuthorityCertifiedMemoryRootProposal {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        if self.protocol_version != AUTHORITY_PROTOCOL_VERSION
            || self.authorization_edition != AUTHORIZATION_EDITION
        {
            return Err(AuthorityProtocolError::WrongEdition);
        }
        authority_text(&self.authority_id, "authority_id")?;
        authority_text(&self.reservation_id, "reservation_id")?;
        authority_text(&self.operation_id, "operation_id")?;
        authority_text(&self.event_id, "event_id")?;
        authority_digest(&self.source_commit_digest, "source_commit_digest")?;
        authority_digest(&self.source_outcome_digest, "source_outcome_digest")?;
        authority_digest(&self.family_bundle_digest, "family_bundle_digest")?;
        authority_digest(&self.snapshot_hash, "snapshot_hash")?;
        authority_counter(self.scope_generation, "scope_generation")?;
        if self.revoke_watermark > self.scope_generation {
            return Err(AuthorityProtocolError::RevokeWatermarkAhead);
        }
        if let Some(parent) = &self.parent_root_digest {
            authority_digest(parent, "parent_root_digest")?;
        }
        self.coverage.validate()?;
        if let Some(proof) = &self.publication_proof {
            proof.validate()?;
            if proof.reservation_id != self.reservation_id
                || proof.operation_id != self.operation_id
                || proof.event_id != self.event_id
                || proof.source_commit_digest != self.source_commit_digest
                || proof.source_outcome_digest != self.source_outcome_digest
                || proof.family_bundle_digest != self.family_bundle_digest
                || proof.snapshot_hash != self.snapshot_hash
                || proof.scope_generation != self.scope_generation
                || proof.revoke_watermark != self.revoke_watermark
            {
                return Err(AuthorityProtocolError::ScopeMismatch);
            }
        }
        authority_timestamp(self.not_before, "not_before")?;
        authority_time_window(self.not_before, self.not_before, self.expires_at)?;
        if self.expires_at - self.not_before > MAX_ROOT_TTL_SECONDS {
            return Err(AuthorityProtocolError::InvalidTimeWindow);
        }
        Ok(())
    }

    /// Canonical digest of the exact proposal identity used by the operation
    /// idempotency record. It excludes issue-time and signer-generated fields.
    pub fn proposal_digest(&self) -> Result<String, AuthorityProtocolError> {
        self.validate()?;
        Ok(authority_sha256_hex(&self.canonical_content_bytes()?))
    }

    fn canonical_content_bytes(&self) -> Result<Vec<u8>, AuthorityProtocolError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(768);
        bytes.extend_from_slice(ROOT_CONTENT_DOMAIN);
        authority_field(&mut bytes, &self.protocol_version.to_string());
        authority_field(&mut bytes, &self.authorization_edition.to_string());
        authority_field(&mut bytes, &self.authority_id);
        authority_field(&mut bytes, &self.reservation_id);
        authority_field(&mut bytes, &self.operation_id);
        authority_field(&mut bytes, &self.event_id);
        authority_field(&mut bytes, &self.source_commit_digest);
        authority_field(&mut bytes, &self.source_outcome_digest);
        authority_field(&mut bytes, &self.family_bundle_digest);
        if let Some(proof) = &self.publication_proof {
            authority_field(&mut bytes, &proof.proof_digest()?);
        }
        authority_field(&mut bytes, &self.snapshot_hash);
        authority_field(&mut bytes, &self.scope_generation.to_string());
        authority_field(&mut bytes, &self.revoke_watermark.to_string());
        authority_field(
            &mut bytes,
            self.parent_root_digest.as_deref().unwrap_or("-"),
        );
        authority_field(&mut bytes, &self.coverage.canonical_text());
        authority_field(&mut bytes, &self.not_before.to_string());
        authority_field(&mut bytes, &self.expires_at.to_string());
        Ok(bytes)
    }
}

/// Authority-owned, signed immutable certified-memory root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityCertifiedMemoryRoot {
    pub protocol_version: u16,
    pub authorization_edition: u16,
    pub authority_id: String,
    pub authority_term: u64,
    pub global_fence_sequence: u64,
    pub root_id: String,
    pub reservation_id: String,
    pub operation_id: String,
    pub event_id: String,
    pub source_commit_digest: String,
    pub source_outcome_digest: String,
    pub family_bundle_digest: String,
    pub snapshot_hash: String,
    pub scope_generation: u64,
    pub revoke_watermark: u64,
    pub parent_root_digest: Option<String>,
    pub coverage: AuthorityCertifiedMemoryCoverage,
    pub key_id: String,
    pub key_epoch: u64,
    pub issued_at: i64,
    pub not_before: i64,
    pub expires_at: i64,
    /// Digest of the complete unsigned root content.
    pub root_digest: String,
    /// Lowercase hexadecimal Ed25519 signature owned by the authority.
    pub signature: String,
}

impl AuthorityCertifiedMemoryRoot {
    pub fn validate_unsigned(&self) -> Result<(), AuthorityProtocolError> {
        if self.protocol_version != AUTHORITY_PROTOCOL_VERSION
            || self.authorization_edition != AUTHORIZATION_EDITION
        {
            return Err(AuthorityProtocolError::WrongEdition);
        }
        authority_text(&self.authority_id, "authority_id")?;
        authority_counter(self.authority_term, "authority_term")?;
        authority_counter(self.global_fence_sequence, "global_fence_sequence")?;
        authority_text(&self.root_id, "root_id")?;
        authority_text(&self.reservation_id, "reservation_id")?;
        authority_text(&self.operation_id, "operation_id")?;
        authority_text(&self.event_id, "event_id")?;
        authority_digest(&self.source_commit_digest, "source_commit_digest")?;
        authority_digest(&self.source_outcome_digest, "source_outcome_digest")?;
        authority_digest(&self.family_bundle_digest, "family_bundle_digest")?;
        authority_digest(&self.snapshot_hash, "snapshot_hash")?;
        authority_counter(self.scope_generation, "scope_generation")?;
        if self.revoke_watermark > self.scope_generation {
            return Err(AuthorityProtocolError::RevokeWatermarkAhead);
        }
        if let Some(parent) = &self.parent_root_digest {
            authority_digest(parent, "parent_root_digest")?;
        }
        self.coverage.validate()?;
        authority_text(&self.key_id, "key_id")?;
        authority_counter(self.key_epoch, "key_epoch")?;
        authority_timestamp(self.issued_at, "issued_at")?;
        authority_time_window(self.not_before, self.issued_at, self.expires_at)?;
        if self.expires_at - self.not_before > MAX_ROOT_TTL_SECONDS {
            return Err(AuthorityProtocolError::InvalidTimeWindow);
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.validate_unsigned()?;
        authority_digest(&self.root_digest, "root_digest")?;
        if self.recompute_root_digest()? != self.root_digest {
            return Err(AuthorityProtocolError::DigestMismatch {
                field: "root_digest",
            });
        }
        authority_signature_encoding(&self.signature)
    }

    /// Canonical bytes covered by the authority signature.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, AuthorityProtocolError> {
        self.validate_unsigned()?;
        let mut bytes = Vec::with_capacity(896);
        bytes.extend_from_slice(ROOT_SIGNATURE_DOMAIN);
        authority_field(&mut bytes, &self.protocol_version.to_string());
        authority_field(&mut bytes, &self.authorization_edition.to_string());
        authority_field(&mut bytes, &self.authority_id);
        authority_field(&mut bytes, &self.authority_term.to_string());
        authority_field(&mut bytes, &self.global_fence_sequence.to_string());
        authority_field(&mut bytes, &self.root_id);
        authority_field(&mut bytes, &self.reservation_id);
        authority_field(&mut bytes, &self.operation_id);
        authority_field(&mut bytes, &self.event_id);
        authority_field(&mut bytes, &self.source_commit_digest);
        authority_field(&mut bytes, &self.source_outcome_digest);
        authority_field(&mut bytes, &self.family_bundle_digest);
        authority_field(&mut bytes, &self.snapshot_hash);
        authority_field(&mut bytes, &self.scope_generation.to_string());
        authority_field(&mut bytes, &self.revoke_watermark.to_string());
        authority_field(
            &mut bytes,
            self.parent_root_digest.as_deref().unwrap_or("-"),
        );
        authority_field(&mut bytes, &self.coverage.canonical_text());
        authority_field(&mut bytes, &self.key_id);
        authority_field(&mut bytes, &self.key_epoch.to_string());
        authority_field(&mut bytes, &self.issued_at.to_string());
        authority_field(&mut bytes, &self.not_before.to_string());
        authority_field(&mut bytes, &self.expires_at.to_string());
        authority_field(&mut bytes, &self.root_digest);
        Ok(bytes)
    }

    pub fn recompute_root_digest(&self) -> Result<String, AuthorityProtocolError> {
        self.validate_unsigned()?;
        let mut bytes = Vec::with_capacity(896);
        bytes.extend_from_slice(ROOT_CONTENT_DOMAIN);
        authority_field(&mut bytes, &self.protocol_version.to_string());
        authority_field(&mut bytes, &self.authorization_edition.to_string());
        authority_field(&mut bytes, &self.authority_id);
        authority_field(&mut bytes, &self.authority_term.to_string());
        authority_field(&mut bytes, &self.global_fence_sequence.to_string());
        authority_field(&mut bytes, &self.root_id);
        authority_field(&mut bytes, &self.reservation_id);
        authority_field(&mut bytes, &self.operation_id);
        authority_field(&mut bytes, &self.event_id);
        authority_field(&mut bytes, &self.source_commit_digest);
        authority_field(&mut bytes, &self.source_outcome_digest);
        authority_field(&mut bytes, &self.family_bundle_digest);
        authority_field(&mut bytes, &self.snapshot_hash);
        authority_field(&mut bytes, &self.scope_generation.to_string());
        authority_field(&mut bytes, &self.revoke_watermark.to_string());
        authority_field(
            &mut bytes,
            self.parent_root_digest.as_deref().unwrap_or("-"),
        );
        authority_field(&mut bytes, &self.coverage.canonical_text());
        authority_field(&mut bytes, &self.key_id);
        authority_field(&mut bytes, &self.key_epoch.to_string());
        authority_field(&mut bytes, &self.issued_at.to_string());
        authority_field(&mut bytes, &self.not_before.to_string());
        authority_field(&mut bytes, &self.expires_at.to_string());
        Ok(authority_sha256_hex(&bytes))
    }

    pub fn record_digest(&self) -> Result<String, AuthorityProtocolError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(1_024);
        bytes.extend_from_slice(ROOT_RECORD_DOMAIN);
        bytes.extend_from_slice(&self.signing_bytes()?);
        authority_field(&mut bytes, &self.signature);
        Ok(authority_sha256_hex(&bytes))
    }

    pub fn sign_with(&mut self, signing_key: &SigningKey) -> Result<(), AuthorityProtocolError> {
        self.signature.clear();
        self.root_digest = self.recompute_root_digest()?;
        self.signature = hex::encode(signing_key.sign(&self.signing_bytes()?).to_bytes());
        Ok(())
    }

    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), AuthorityProtocolError> {
        self.validate()?;
        authority_verify_strict(verifying_key, &self.signing_bytes()?, &self.signature)
    }

    pub fn verify_at(
        &self,
        verifying_key: &VerifyingKey,
        now_seconds: i64,
    ) -> Result<(), AuthorityProtocolError> {
        self.verify(verifying_key)?;
        if now_seconds < self.not_before || now_seconds >= self.expires_at {
            return Err(AuthorityProtocolError::NotCurrentlyValid);
        }
        Ok(())
    }
}

/// Authenticated install request. The operation enum is deliberately closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityCertifiedMemoryRootInstallRequest {
    pub caller: AuthorityCallerIdentity,
    pub operation: AuthorityCertifiedMemoryRootOperation,
    pub proposal: AuthorityCertifiedMemoryRootProposal,
}

impl AuthorityCertifiedMemoryRootInstallRequest {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.caller.validate()?;
        if self.operation != AuthorityCertifiedMemoryRootOperation::Install {
            return Err(AuthorityProtocolError::StateConflict {
                record: "certified_memory_root",
                state: self.operation.as_text().to_owned(),
            });
        }
        self.proposal.validate()
    }
}

/// Authenticated read request for the authority-owned current root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityCertifiedMemoryRootReadRequest {
    pub caller: AuthorityCallerIdentity,
    pub operation: AuthorityCertifiedMemoryRootOperation,
    pub expected_root_digest: Option<String>,
}

impl AuthorityCertifiedMemoryRootReadRequest {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.caller.validate()?;
        if self.operation != AuthorityCertifiedMemoryRootOperation::Read {
            return Err(AuthorityProtocolError::StateConflict {
                record: "certified_memory_root",
                state: self.operation.as_text().to_owned(),
            });
        }
        if let Some(digest) = &self.expected_root_digest {
            authority_digest(digest, "expected_root_digest")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityCertifiedMemoryRootResponse {
    pub root: AuthorityCertifiedMemoryRoot,
    pub global_frontier: GlobalAuthorityFrontier,
    pub read_gate: AuthorityReadGate,
}

impl AuthorityCertifiedMemoryRootResponse {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.root.validate()?;
        self.global_frontier.validate()?;
        self.read_gate.validate()
    }
}

fn authority_sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn proposal() -> AuthorityCertifiedMemoryRootProposal {
        AuthorityCertifiedMemoryRootProposal {
            protocol_version: AUTHORITY_PROTOCOL_VERSION,
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: "authority-1".to_owned(),
            reservation_id: "reservation-1".to_owned(),
            operation_id: "operation-1".to_owned(),
            event_id: "event-1".to_owned(),
            source_commit_digest: "11".repeat(32),
            source_outcome_digest: "22".repeat(32),
            family_bundle_digest: "44".repeat(32),
            publication_proof: None,
            snapshot_hash: "33".repeat(32),
            scope_generation: 1,
            revoke_watermark: 0,
            parent_root_digest: None,
            coverage: AuthorityCertifiedMemoryCoverage::complete(),
            not_before: 100,
            expires_at: 200,
        }
    }

    fn publication_proof(
        p: &AuthorityCertifiedMemoryRootProposal,
    ) -> super::super::AuthorityCertifiedMemoryPublicationProof {
        use super::super::{
            AuthorityManifestIdentity, AuthorityProtocolScope,
            AuthorityScopePublicationCertificate, AuthorityStagedScopeCoverage,
        };
        let scope = AuthorityProtocolScope::Card(crate::AuthorizationAuthorityScope {
            tenant_id: 7,
            card_id: 17,
            user_id: None,
            domain: crate::AuthorizationDomainScope::Any,
        });
        let mut certificate = AuthorityScopePublicationCertificate {
            protocol_version: AUTHORITY_PROTOCOL_VERSION,
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: p.authority_id.clone(),
            authority_term: 1,
            global_fence_sequence: 1,
            certificate_id: "certificate-1".into(),
            intent_digest: "11".repeat(32),
            reservation_id: p.reservation_id.clone(),
            operation_id: p.operation_id.clone(),
            event_id: p.event_id.clone(),
            scope: scope.clone(),
            approved_request_digest: "22".repeat(32),
            before_image_digest: None,
            after_image_digest: "33".repeat(32),
            source_commit_digest: p.source_commit_digest.clone(),
            completion_digest: "00".repeat(32),
            snapshot_hash: "55".repeat(32),
            source_outcome_digest: p.source_outcome_digest.clone(),
            parent_certificate_hash: None,
            manifests: vec![AuthorityManifestIdentity {
                aggregate_type: "USER_CARD".into(),
                aggregate_id: 17,
                manifest_digest_hex: "aa".repeat(32),
                dependency_hash_hex: "bb".repeat(32),
                semantic_hash_hex: "cc".repeat(32),
                generation: 1,
                revoke_fence: 0,
                event_id: p.event_id.clone(),
                operation_id: p.operation_id.clone(),
            }],
            key_id: "signer-1".into(),
            key_epoch: 1,
            issued_at: 100,
            not_before: 100,
            expires_at: None,
            certificate_nonce: "nonce-1".into(),
            signature: String::new(),
        };
        certificate.completion_digest = certificate.recompute_completion_digest().unwrap();
        certificate.sign(&SigningKey::from_bytes(&[7; 32])).unwrap();
        let mut proof = super::super::AuthorityCertifiedMemoryPublicationProof {
            reservation_id: p.reservation_id.clone(),
            operation_id: p.operation_id.clone(),
            event_id: p.event_id.clone(),
            source_commit_digest: p.source_commit_digest.clone(),
            source_outcome_digest: p.source_outcome_digest.clone(),
            declared_coverage: AuthorityStagedScopeCoverage {
                scopes: vec![scope],
            },
            certificates: vec![certificate],
            certificate_set_digest: "00".repeat(32),
            certificate_frontier_digest: "00".repeat(32),
            family_bundle_digest: p.family_bundle_digest.clone(),
            snapshot_hash: p.snapshot_hash.clone(),
            scope_generation: p.scope_generation,
            revoke_watermark: p.revoke_watermark,
        };
        proof.certificate_set_digest = proof.certificate_set_digest().unwrap();
        proof.certificate_frontier_digest = proof.certificate_frontier_digest().unwrap();
        proof
    }

    #[test]
    fn proposal_digest_binds_exact_publication_proof() {
        let mut value = proposal();
        let without_proof = value.proposal_digest().unwrap();
        let proof = publication_proof(&value);
        value.publication_proof = Some(proof);
        let original = value.proposal_digest().unwrap();
        assert_ne!(original, without_proof);
        let proof = value.publication_proof.as_mut().unwrap();
        proof.certificates[0].certificate_nonce = "nonce-2".into();
        proof.certificates[0]
            .sign(&SigningKey::from_bytes(&[7; 32]))
            .unwrap();
        proof.certificate_set_digest = proof.certificate_set_digest().unwrap();
        assert_ne!(original, value.proposal_digest().unwrap());
        value.publication_proof.as_mut().unwrap().snapshot_hash = "99".repeat(32);
        assert_eq!(
            value.proposal_digest(),
            Err(AuthorityProtocolError::ScopeMismatch)
        );
    }

    #[test]
    fn coverage_is_closed_and_canonical() {
        assert!(AuthorityCertifiedMemoryCoverage::complete()
            .validate()
            .is_ok());
        let mut missing = AuthorityCertifiedMemoryCoverage::complete();
        missing.families.pop();
        assert_eq!(
            missing.validate(),
            Err(AuthorityProtocolError::InvalidCoverage)
        );
        let mut reordered = AuthorityCertifiedMemoryCoverage::complete();
        reordered.families.swap(0, 1);
        assert_eq!(
            reordered.validate(),
            Err(AuthorityProtocolError::InvalidCoverage)
        );
    }

    #[test]
    fn root_digest_and_signature_reject_tampering() {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let p = proposal();
        let mut root = AuthorityCertifiedMemoryRoot {
            protocol_version: p.protocol_version,
            authorization_edition: p.authorization_edition,
            authority_id: p.authority_id.clone(),
            authority_term: 1,
            global_fence_sequence: 1,
            root_id: "memory-root-1".to_owned(),
            reservation_id: p.reservation_id.clone(),
            operation_id: p.operation_id.clone(),
            event_id: p.event_id.clone(),
            source_commit_digest: p.source_commit_digest.clone(),
            source_outcome_digest: p.source_outcome_digest.clone(),
            family_bundle_digest: p.family_bundle_digest.clone(),
            snapshot_hash: p.snapshot_hash.clone(),
            scope_generation: p.scope_generation,
            revoke_watermark: p.revoke_watermark,
            parent_root_digest: p.parent_root_digest.clone(),
            coverage: p.coverage.clone(),
            key_id: "signer-1".to_owned(),
            key_epoch: 1,
            issued_at: 100,
            not_before: p.not_before,
            expires_at: p.expires_at,
            root_digest: "0".repeat(32),
            signature: String::new(),
        };
        root.sign_with(&signing).unwrap();
        root.verify_at(&signing.verifying_key(), 150).unwrap();
        root.snapshot_hash.replace_range(..1, "4");
        assert!(matches!(
            root.validate(),
            Err(AuthorityProtocolError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn unknown_wire_operation_is_rejected_by_serde() {
        let json = r#"{"caller":{"serviceId":"s","requestNonce":"n","issuedAt":1},"operation":"PURGE","expectedRootDigest":null}"#;
        assert!(serde_json::from_str::<AuthorityCertifiedMemoryRootReadRequest>(json).is_err());
    }
}
