//! Authenticated authorization-fence and in-memory authority contracts.
//!
//! A digest proves content identity, but it does not prove who published that
//! content or whether the publisher is still in the current authority term.
//! This module keeps those concerns explicit. The signed proof is a pure value
//! contract: it performs no I/O, does not reserve a nonce, and does not make an
//! authorization decision by itself.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    DomainScopeRequirement, PublishedCardAuthorization, PublishedCardEvidenceScope,
    AUTHORIZATION_EDITION,
};

const AUTHORITY_PROOF_DOMAIN: &[u8] = b"ASTRAL_AUTHORIZATION_FENCE_PROOF_V1\0";
const AUTHORITY_LEASE_DOMAIN: &[u8] = b"ASTRAL_AUTHORIZATION_ISSUANCE_LEASE_V1\0";
const AUTHORITY_PUBLICATION_COMPLETION_DOMAIN: &[u8] =
    b"ASTRAL_AUTHORIZATION_PUBLICATION_COMPLETION_V1\0";
/// Domain-separated canonical content identity of one published card evidence
/// (V7). Deliberately a NEW domain: every digest produced under the previous
/// lens-sensitive content view is invalid under this contract and must be
/// republished (adoption/cutover requirement, see the V7 authority spec).
const AUTHORIZATION_EVIDENCE_CONTENT_V7_DOMAIN: &[u8] =
    b"ASTRAL_AUTHORIZATION_EVIDENCE_CONTENT_V7\0";
const MAX_IDENTIFIER_BYTES: usize = 128;
const SHA256_HEX_LEN: usize = 64;
const ED25519_SIGNATURE_HEX_LEN: usize = 128;

/// Domain binding in a proof is explicit: unconstrained, no domain, or one exact domain.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorizationDomainScope {
    Any,
    NoDomain,
    Exact(i64),
}

/// Scope bound to one authorization fence proof.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizationAuthorityScope {
    pub tenant_id: i64,
    pub card_id: i64,
    pub user_id: Option<i64>,
    pub domain: AuthorizationDomainScope,
}

impl AuthorizationAuthorityScope {
    /// Build the proof scope without losing the explicit domain requirement.
    pub fn from_evidence_scope(scope: &PublishedCardEvidenceScope) -> Self {
        let domain = match scope.domain {
            DomainScopeRequirement::Unconstrained => AuthorizationDomainScope::Any,
            DomainScopeRequirement::ExactlyNone => AuthorizationDomainScope::NoDomain,
            DomainScopeRequirement::ExactlySome(domain_id) => {
                AuthorizationDomainScope::Exact(domain_id)
            }
        };
        Self {
            tenant_id: scope.tenant_id,
            card_id: scope.card_id,
            user_id: scope.user_filter,
            domain,
        }
    }

    /// Validate the positive identifiers and explicit optional scope values.
    pub fn validate(&self) -> Result<(), AuthorizationAuthorityError> {
        positive_id(self.tenant_id, "tenant_id")?;
        positive_id(self.card_id, "card_id")?;
        if let Some(user_id) = self.user_id {
            positive_id(user_id, "user_id")?;
        }
        if let AuthorizationDomainScope::Exact(domain_id) = self.domain {
            positive_id(domain_id, "domain_id")?;
        }
        Ok(())
    }

    /// Require byte-for-byte equality with the request evidence scope.
    pub fn matches_evidence_scope(
        &self,
        scope: &PublishedCardEvidenceScope,
    ) -> Result<(), AuthorizationAuthorityError> {
        scope
            .validate()
            .map_err(|_| AuthorizationAuthorityError::ScopeMismatch)?;
        if self != &Self::from_evidence_scope(scope) {
            return Err(AuthorizationAuthorityError::ScopeMismatch);
        }
        Ok(())
    }
}

/// A signed, request-bound proof that a scope belongs to the current authority
/// frontier. The signature covers every field returned by
/// [`Self::signing_bytes`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizationFenceProof {
    pub authorization_edition: u16,
    pub authority_id: String,
    pub authority_term: u64,
    pub global_fence_sequence: u64,
    pub scope: AuthorizationAuthorityScope,
    pub scope_generation: u64,
    pub revoke_watermark: u64,
    pub snapshot_hash: String,
    pub parent_hash: Option<String>,
    pub operation_id: String,
    pub event_id: String,
    pub key_id: String,
    pub key_epoch: u64,
    pub issued_at: i64,
    pub not_before: i64,
    pub expires_at: i64,
    pub request_nonce: String,
    /// Digest of the immutable verified policy request authorized by this proof.
    /// Legacy offline fixtures may omit it; production request proofs must carry it.
    #[serde(default)]
    pub request_binding_digest: Option<String>,
    /// Exact signed publication certificate record identity for production reads.
    #[serde(default)]
    pub scope_certificate_hash: Option<String>,
    pub proof_id: String,
    /// Lowercase hex encoding of the 64-byte Ed25519 signature.
    pub signature: String,
}

/// Shared authority provenance carried by authorization invalidation messages.
///
/// This is a projection of a verified [`AuthorizationFenceProof`], not a new
/// authority decision. Consumers use it to reject term/fence/key/generation
/// divergence and to correlate the message with the durable proof; they must
/// still read published evidence through the strict authorization gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizationMessageMetadata {
    pub authorization_edition: u16,
    pub authority_id: String,
    pub authority_term: u64,
    pub global_fence_sequence: u64,
    pub key_id: String,
    pub key_epoch: u64,
    pub proof_id: String,
    pub scope_generation: u64,
    pub revoke_watermark: u64,
    pub snapshot_hash: String,
}

impl AuthorizationMessageMetadata {
    /// Project message provenance from a proof that has already passed the
    /// proof contract. No external or local state is consulted here.
    pub fn from_verified_proof(
        proof: &AuthorizationFenceProof,
    ) -> Result<Self, AuthorizationAuthorityError> {
        proof.validate()?;
        let metadata = Self {
            authorization_edition: proof.authorization_edition,
            authority_id: proof.authority_id.clone(),
            authority_term: proof.authority_term,
            global_fence_sequence: proof.global_fence_sequence,
            key_id: proof.key_id.clone(),
            key_epoch: proof.key_epoch,
            proof_id: proof.proof_id.clone(),
            scope_generation: proof.scope_generation,
            revoke_watermark: proof.revoke_watermark,
            snapshot_hash: proof.snapshot_hash.clone(),
        };
        metadata.validate()?;
        Ok(metadata)
    }

    pub fn validate(&self) -> Result<(), AuthorizationAuthorityError> {
        if self.authorization_edition != AUTHORIZATION_EDITION {
            return Err(AuthorizationAuthorityError::WrongEdition);
        }
        text(&self.authority_id, "authority_id")?;
        counter(self.authority_term, "authority_term")?;
        counter(self.global_fence_sequence, "global_fence_sequence")?;
        text(&self.key_id, "key_id")?;
        counter(self.key_epoch, "key_epoch")?;
        text(&self.proof_id, "proof_id")?;
        counter(self.scope_generation, "scope_generation")?;
        if self.revoke_watermark > self.scope_generation {
            return Err(AuthorizationAuthorityError::RevokeWatermarkAhead);
        }
        digest(&self.snapshot_hash, "snapshot_hash")
    }
}

/// A proof-bound capability carried from the formal policy decision to a
/// sensitive mutation commit. It contains no mutable memory state; the commit
/// owner must still compare it with the durable proof row and current authority
/// frontier inside its own transaction.
#[derive(Debug, Clone)]
pub struct AuthorizationAdmission {
    proof: AuthorizationFenceProof,
    consumption: Arc<AtomicBool>,
}

impl PartialEq for AuthorizationAdmission {
    fn eq(&self, other: &Self) -> bool {
        self.proof == other.proof
    }
}

impl Eq for AuthorizationAdmission {}

impl AuthorizationAdmission {
    /// Construct the capability from a proof that the policy repository has
    /// already authenticated and bound to the request's certified evidence.
    /// Durable commit validation remains mandatory; this constructor only
    /// rejects malformed proof values and does not establish trust by itself.
    pub fn from_verified_proof(
        proof: AuthorizationFenceProof,
    ) -> Result<Self, AuthorizationAuthorityError> {
        proof.validate()?;
        Ok(Self {
            proof,
            consumption: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Reserve this request-bound admission exactly once after the durable
    /// authority rows have been revalidated. A failed reservation is a replay
    /// or concurrent reuse and must remain fail-closed.
    pub fn consume_once(&self) -> Result<(), AuthorizationAuthorityError> {
        self.consumption
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| AuthorizationAuthorityError::AdmissionConsumed)
    }

    pub fn proof(&self) -> &AuthorizationFenceProof {
        &self.proof
    }

    pub fn proof_id(&self) -> &str {
        &self.proof.proof_id
    }

    pub fn operation_id(&self) -> &str {
        &self.proof.operation_id
    }

    pub fn event_id(&self) -> &str {
        &self.proof.event_id
    }
}

/// A one-time, externally authorized capability for the authority signer.
///
/// The arbiter signature authorizes the exact authority frontier and evidence
/// scope. It is deliberately separate from [`AuthorizationFenceProof`]'s
/// publisher signature: a database-backed signer may consume this capability,
/// but cannot create a new global term or fence without the external arbiter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizationIssuanceLease {
    pub authorization_edition: u16,
    pub authority_id: String,
    pub authority_term: u64,
    pub global_fence_sequence: u64,
    pub previous_authority_term: u64,
    pub previous_global_fence_sequence: u64,
    pub previous_key_id: String,
    pub previous_key_epoch: u64,
    pub scope: AuthorizationAuthorityScope,
    pub scope_generation: u64,
    pub revoke_watermark: u64,
    pub snapshot_hash: String,
    pub parent_hash: Option<String>,
    pub operation_id: String,
    pub event_id: String,
    pub key_id: String,
    pub key_epoch: u64,
    pub issued_at: i64,
    pub not_before: i64,
    pub expires_at: i64,
    pub request_nonce: String,
    pub lease_id: String,
    pub arbiter_id: String,
    pub arbiter_key_id: String,
    pub arbiter_key_epoch: u64,
    /// Lowercase hex encoding of the 64-byte arbiter signature.
    pub arbiter_signature: String,
}

impl AuthorizationIssuanceLease {
    /// Canonical identity of the durable publication that this lease authorizes.
    ///
    /// The completion digest is deliberately separate from both the authority
    /// proof signature and the evidence snapshot hash. It binds the exact
    /// operation/event, scope frontier, manifest/segment publication digest and
    /// authority parent into one value that the DB completion gate can recompute.
    pub fn publication_completion_digest(
        &self,
        evidence: &PublishedCardAuthorization,
    ) -> Result<String, AuthorizationAuthorityError> {
        self.scope
            .matches_evidence_scope(&PublishedCardEvidenceScope {
                tenant_id: evidence.tenant_id,
                card_id: evidence.card_id,
                user_filter: self.scope.user_id,
                domain: match self.scope.domain {
                    AuthorizationDomainScope::Any => DomainScopeRequirement::Unconstrained,
                    AuthorizationDomainScope::NoDomain => DomainScopeRequirement::ExactlyNone,
                    AuthorizationDomainScope::Exact(domain_id) => {
                        DomainScopeRequirement::ExactlySome(domain_id)
                    }
                },
            })?;
        let (generation, revoke_watermark) = AuthorizationFenceProof::evidence_frontier(evidence)?;
        if generation != self.scope_generation || revoke_watermark != self.revoke_watermark {
            return Err(AuthorizationAuthorityError::EvidenceFrontierMismatch);
        }
        let snapshot_hash = AuthorizationFenceProof::evidence_content_hash(evidence)?;
        if snapshot_hash != self.snapshot_hash {
            return Err(AuthorizationAuthorityError::EvidenceContentHashMismatch);
        }
        let mut bytes = Vec::with_capacity(768);
        bytes.extend_from_slice(AUTHORITY_PUBLICATION_COMPLETION_DOMAIN);
        field(&mut bytes, &self.authorization_edition.to_string());
        field(&mut bytes, &self.authority_id);
        field(&mut bytes, &self.authority_term.to_string());
        field(&mut bytes, &self.global_fence_sequence.to_string());
        field(&mut bytes, &self.previous_authority_term.to_string());
        field(&mut bytes, &self.previous_global_fence_sequence.to_string());
        field(&mut bytes, &self.previous_key_id);
        field(&mut bytes, &self.previous_key_epoch.to_string());
        field(&mut bytes, &self.scope.tenant_id.to_string());
        field(&mut bytes, &self.scope.card_id.to_string());
        field(&mut bytes, &optional_i64(self.scope.user_id));
        field(&mut bytes, &domain_scope_text(&self.scope.domain));
        field(&mut bytes, &self.scope_generation.to_string());
        field(&mut bytes, &self.revoke_watermark.to_string());
        field(&mut bytes, &self.snapshot_hash);
        field(&mut bytes, self.parent_hash.as_deref().unwrap_or("-"));
        field(&mut bytes, &self.operation_id);
        field(&mut bytes, &self.event_id);
        field(&mut bytes, &self.key_id);
        field(&mut bytes, &self.key_epoch.to_string());
        field(&mut bytes, &self.request_nonce);
        field(&mut bytes, &self.lease_id);
        field(&mut bytes, &evidence.tenant_id.to_string());
        field(&mut bytes, &evidence.card_id.to_string());
        field(&mut bytes, &snapshot_hash);
        for manifest in &evidence.manifests {
            field(&mut bytes, &manifest.aggregate_type);
            field(&mut bytes, &manifest.aggregate_id.to_string());
            field(&mut bytes, &manifest.manifest_id.to_string());
            field(&mut bytes, &manifest.generation.to_string());
            field(&mut bytes, &manifest.revoke_fence.to_string());
            field(&mut bytes, &manifest.manifest_digest_hex);
            field(&mut bytes, &manifest.event_id);
            field(&mut bytes, &manifest.operation_id);
        }
        Ok(hex::encode(Sha256::digest(bytes)))
    }

    fn validate_unsigned_fields(&self) -> Result<(), AuthorizationAuthorityError> {
        if self.authorization_edition != AUTHORIZATION_EDITION {
            return Err(AuthorizationAuthorityError::WrongEdition);
        }
        text(&self.authority_id, "authority_id")?;
        counter(self.authority_term, "authority_term")?;
        counter(self.global_fence_sequence, "global_fence_sequence")?;
        if self.previous_authority_term == 0 && self.previous_global_fence_sequence == 0 {
            if self.previous_key_id != "-" || self.previous_key_epoch != 0 {
                return Err(AuthorizationAuthorityError::InvalidText {
                    field: "previous_frontier",
                });
            }
        } else {
            counter(self.previous_authority_term, "previous_authority_term")?;
            counter(
                self.previous_global_fence_sequence,
                "previous_global_fence_sequence",
            )?;
            text(&self.previous_key_id, "previous_key_id")?;
            counter(self.previous_key_epoch, "previous_key_epoch")?;
        }
        self.scope.validate()?;
        counter(self.scope_generation, "scope_generation")?;
        if self.revoke_watermark > self.scope_generation {
            return Err(AuthorizationAuthorityError::RevokeWatermarkAhead);
        }
        digest(&self.snapshot_hash, "snapshot_hash")?;
        if let Some(parent_hash) = &self.parent_hash {
            digest(parent_hash, "parent_hash")?;
        }
        text(&self.operation_id, "operation_id")?;
        text(&self.event_id, "event_id")?;
        text(&self.key_id, "key_id")?;
        counter(self.key_epoch, "key_epoch")?;
        text(&self.request_nonce, "request_nonce")?;
        text(&self.lease_id, "lease_id")?;
        text(&self.arbiter_id, "arbiter_id")?;
        text(&self.arbiter_key_id, "arbiter_key_id")?;
        counter(self.arbiter_key_epoch, "arbiter_key_epoch")?;
        if self.not_before > self.issued_at || self.issued_at >= self.expires_at {
            return Err(AuthorizationAuthorityError::InvalidTimeWindow);
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), AuthorizationAuthorityError> {
        self.validate_unsigned_fields()?;
        if self.arbiter_signature.len() != ED25519_SIGNATURE_HEX_LEN
            || !self
                .arbiter_signature
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(AuthorizationAuthorityError::InvalidSignatureEncoding);
        }
        Ok(())
    }

    pub fn validate_at(&self, now_seconds: i64) -> Result<(), AuthorizationAuthorityError> {
        self.validate()?;
        if now_seconds < self.not_before || now_seconds >= self.expires_at {
            return Err(AuthorizationAuthorityError::NotCurrentlyValid);
        }
        Ok(())
    }

    /// Canonical bytes covered by the arbiter's lease signature.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, AuthorizationAuthorityError> {
        self.validate_unsigned_fields()?;
        let mut bytes = Vec::with_capacity(640);
        bytes.extend_from_slice(AUTHORITY_LEASE_DOMAIN);
        field(&mut bytes, &self.authorization_edition.to_string());
        field(&mut bytes, &self.authority_id);
        field(&mut bytes, &self.authority_term.to_string());
        field(&mut bytes, &self.global_fence_sequence.to_string());
        field(&mut bytes, &self.previous_authority_term.to_string());
        field(&mut bytes, &self.previous_global_fence_sequence.to_string());
        field(&mut bytes, &self.previous_key_id);
        field(&mut bytes, &self.previous_key_epoch.to_string());
        field(&mut bytes, &self.scope.tenant_id.to_string());
        field(&mut bytes, &self.scope.card_id.to_string());
        field(&mut bytes, &optional_i64(self.scope.user_id));
        field(&mut bytes, &domain_scope_text(&self.scope.domain));
        field(&mut bytes, &self.scope_generation.to_string());
        field(&mut bytes, &self.revoke_watermark.to_string());
        field(&mut bytes, &self.snapshot_hash);
        field(&mut bytes, self.parent_hash.as_deref().unwrap_or("-"));
        field(&mut bytes, &self.operation_id);
        field(&mut bytes, &self.event_id);
        field(&mut bytes, &self.key_id);
        field(&mut bytes, &self.key_epoch.to_string());
        field(&mut bytes, &self.issued_at.to_string());
        field(&mut bytes, &self.not_before.to_string());
        field(&mut bytes, &self.expires_at.to_string());
        field(&mut bytes, &self.request_nonce);
        field(&mut bytes, &self.lease_id);
        field(&mut bytes, &self.arbiter_id);
        field(&mut bytes, &self.arbiter_key_id);
        field(&mut bytes, &self.arbiter_key_epoch.to_string());
        Ok(bytes)
    }

    pub fn verify_at(
        &self,
        verifying_key: &VerifyingKey,
        now_seconds: i64,
    ) -> Result<(), AuthorizationAuthorityError> {
        self.validate_at(now_seconds)?;
        let signature_bytes = decode_hex::<64>(&self.arbiter_signature)
            .ok_or(AuthorizationAuthorityError::InvalidSignatureEncoding)?;
        let signature = Signature::from_bytes(&signature_bytes);
        verifying_key
            .verify_strict(&self.signing_bytes()?, &signature)
            .map_err(|_| AuthorizationAuthorityError::InvalidSignature)
    }

    pub fn matches_evidence_scope(
        &self,
        scope: &PublishedCardEvidenceScope,
    ) -> Result<(), AuthorizationAuthorityError> {
        self.scope.matches_evidence_scope(scope)
    }

    /// Mint the publisher proof only after the caller has verified and consumed
    /// this lease. The caller must persist the resulting proof atomically with
    /// the lease consumption and frontier CAS.
    pub fn sign_proof(
        &self,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<AuthorizationFenceProof, AuthorizationAuthorityError> {
        self.validate()?;
        let mut proof = AuthorizationFenceProof {
            authorization_edition: self.authorization_edition,
            authority_id: self.authority_id.clone(),
            authority_term: self.authority_term,
            global_fence_sequence: self.global_fence_sequence,
            scope: self.scope.clone(),
            scope_generation: self.scope_generation,
            revoke_watermark: self.revoke_watermark,
            snapshot_hash: self.snapshot_hash.clone(),
            parent_hash: self.parent_hash.clone(),
            operation_id: self.operation_id.clone(),
            event_id: self.event_id.clone(),
            key_id: self.key_id.clone(),
            key_epoch: self.key_epoch,
            issued_at: self.issued_at,
            not_before: self.not_before,
            expires_at: self.expires_at,
            request_nonce: self.request_nonce.clone(),
            request_binding_digest: None,
            scope_certificate_hash: None,
            proof_id: self.lease_id.clone(),
            signature: String::new(),
        };
        let signature = signing_key.sign(&proof.signing_bytes()?);
        proof.signature = hex::encode(signature.to_bytes());
        Ok(proof)
    }
}
/// authorization state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AuthorizationAuthorityError {
    #[error("authorization edition is not current")]
    WrongEdition,
    #[error("{field} must be a positive identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("{field} is empty, too long, or non-canonical")]
    InvalidText { field: &'static str },
    #[error("{field} must be a lowercase SHA-256 hex digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} must be a positive monotonic value")]
    InvalidCounter { field: &'static str },
    #[error("revoke watermark cannot exceed scope generation")]
    RevokeWatermarkAhead,
    #[error("proof time window is invalid")]
    InvalidTimeWindow,
    #[error("proof is not valid at the supplied time")]
    NotCurrentlyValid,
    #[error("signature must be exactly 128 lowercase hex characters")]
    InvalidSignatureEncoding,
    #[error("authority proof signature is invalid")]
    InvalidSignature,
    #[error("authority proof identity is not monotonic")]
    NonMonotonicIdentity,
    #[error("authority proof scope does not match the requested scope")]
    ScopeMismatch,
    #[error("authorization admission has already been consumed")]
    AdmissionConsumed,
    #[error("authorization evidence content hash does not match the authority proof")]
    EvidenceContentHashMismatch,
    #[error("authorization evidence does not match the authority proof scope")]
    EvidenceScopeMismatch,
    #[error("authorization evidence frontier does not match the authority proof")]
    EvidenceFrontierMismatch,
    #[error("authorization evidence could not be canonically encoded")]
    CanonicalSerialization,
    #[error("authorization evidence failed its canonical validation")]
    EvidenceInvalid,
    #[error("authorization evidence is not currently usable at the supplied time")]
    EvidenceNotCurrentlyUsable,
    #[error("authorization proof nonce has already been used")]
    NonceReplay,
}

impl AuthorizationFenceProof {
    fn validate_unsigned_fields(&self) -> Result<(), AuthorizationAuthorityError> {
        if self.authorization_edition != AUTHORIZATION_EDITION {
            return Err(AuthorizationAuthorityError::WrongEdition);
        }
        text(&self.authority_id, "authority_id")?;
        counter(self.authority_term, "authority_term")?;
        counter(self.global_fence_sequence, "global_fence_sequence")?;
        self.scope.validate()?;
        counter(self.scope_generation, "scope_generation")?;
        if self.revoke_watermark > self.scope_generation {
            return Err(AuthorizationAuthorityError::RevokeWatermarkAhead);
        }
        digest(&self.snapshot_hash, "snapshot_hash")?;
        if let Some(parent_hash) = &self.parent_hash {
            digest(parent_hash, "parent_hash")?;
        }
        text(&self.operation_id, "operation_id")?;
        text(&self.event_id, "event_id")?;
        text(&self.key_id, "key_id")?;
        counter(self.key_epoch, "key_epoch")?;
        text(&self.request_nonce, "request_nonce")?;
        if let Some(binding) = &self.request_binding_digest {
            digest(binding, "request_binding_digest")?;
        }
        if let Some(certificate) = &self.scope_certificate_hash {
            digest(certificate, "scope_certificate_hash")?;
        }
        text(&self.proof_id, "proof_id")?;
        if self.not_before > self.issued_at || self.issued_at >= self.expires_at {
            return Err(AuthorizationAuthorityError::InvalidTimeWindow);
        }
        Ok(())
    }

    /// Validate fields without checking the wall clock or cryptographic key.
    pub fn validate(&self) -> Result<(), AuthorizationAuthorityError> {
        self.validate_unsigned_fields()?;
        if self.signature.len() != ED25519_SIGNATURE_HEX_LEN
            || !self
                .signature
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(AuthorizationAuthorityError::InvalidSignatureEncoding);
        }
        Ok(())
    }

    /// Validate the proof against an NTP-derived UTC Unix timestamp.
    pub fn validate_at(&self, now_seconds: i64) -> Result<(), AuthorizationAuthorityError> {
        self.validate()?;
        if now_seconds < self.not_before || now_seconds >= self.expires_at {
            return Err(AuthorizationAuthorityError::NotCurrentlyValid);
        }
        Ok(())
    }

    /// Return the exact domain-separated bytes covered by the Ed25519 signature.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, AuthorizationAuthorityError> {
        self.validate_unsigned_fields()?;
        let mut bytes = Vec::with_capacity(512);
        bytes.extend_from_slice(AUTHORITY_PROOF_DOMAIN);
        field(&mut bytes, &self.authorization_edition.to_string());
        field(&mut bytes, &self.authority_id);
        field(&mut bytes, &self.authority_term.to_string());
        field(&mut bytes, &self.global_fence_sequence.to_string());
        field(&mut bytes, &self.scope.tenant_id.to_string());
        field(&mut bytes, &self.scope.card_id.to_string());
        field(&mut bytes, &optional_i64(self.scope.user_id));
        field(&mut bytes, &domain_scope_text(&self.scope.domain));
        field(&mut bytes, &self.scope_generation.to_string());
        field(&mut bytes, &self.revoke_watermark.to_string());
        field(&mut bytes, &self.snapshot_hash);
        field(&mut bytes, self.parent_hash.as_deref().unwrap_or("-"));
        field(&mut bytes, &self.operation_id);
        field(&mut bytes, &self.event_id);
        field(&mut bytes, &self.key_id);
        field(&mut bytes, &self.key_epoch.to_string());
        field(&mut bytes, &self.issued_at.to_string());
        field(&mut bytes, &self.not_before.to_string());
        field(&mut bytes, &self.expires_at.to_string());
        field(&mut bytes, &self.request_nonce);
        field(
            &mut bytes,
            self.request_binding_digest.as_deref().unwrap_or("-"),
        );
        field(
            &mut bytes,
            self.scope_certificate_hash.as_deref().unwrap_or("-"),
        );
        field(&mut bytes, &self.proof_id);
        Ok(bytes)
    }

    /// Verify the publisher signature and the proof's validity window.
    pub fn verify_at(
        &self,
        verifying_key: &VerifyingKey,
        now_seconds: i64,
    ) -> Result<(), AuthorizationAuthorityError> {
        self.validate_at(now_seconds)?;
        let signature_bytes = decode_hex::<64>(&self.signature)
            .ok_or(AuthorizationAuthorityError::InvalidSignatureEncoding)?;
        let signature = Signature::from_bytes(&signature_bytes);
        let message = self.signing_bytes()?;
        verifying_key
            .verify_strict(&message, &signature)
            .map_err(|_| AuthorizationAuthorityError::InvalidSignature)
    }

    /// Return the canonical hash of the complete evidence content.
    ///
    /// `read_unix_seconds` is intentionally excluded: it is the evaluator's
    /// observation clock, not an authorization-content identity.
    /// Canonical V7 content identity of one complete published card evidence.
    ///
    /// The hash covers ONLY the immutable publication content: the full
    /// manifest summary list and every verified record's immutable provenance
    /// plus the FULL grant content (state and validity windows included). The
    /// lens/time-derived projections — `effective_grants` membership,
    /// `accepted_into_effective_set`, `unaccepted_reason`, the `gate`
    /// counters and the read clock — are deliberately EXCLUDED: two strict
    /// reads of the same publication through different user/domain lenses or
    /// at different instants MUST produce the same hash, while ANY change to
    /// grant content, validity windows, or publication provenance MUST change
    /// it. The evidence must pass its full contract validation first; the
    /// hash never relaxes that gate.
    pub fn evidence_content_hash(
        evidence: &PublishedCardAuthorization,
    ) -> Result<String, AuthorizationAuthorityError> {
        evidence
            .validate()
            .map_err(|_| AuthorizationAuthorityError::EvidenceInvalid)?;
        let canonical = EvidenceContentSnapshotView::from(evidence);
        let encoded = serde_json::to_vec(&canonical)
            .map_err(|_| AuthorizationAuthorityError::CanonicalSerialization)?;
        let mut bytes = Vec::with_capacity(encoded.len() + 64);
        bytes.extend_from_slice(AUTHORIZATION_EVIDENCE_CONTENT_V7_DOMAIN);
        bytes.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&encoded);
        Ok(hex::encode(Sha256::digest(bytes)))
    }

    /// Return the canonical content frontier carried by a complete evidence object.
    ///
    /// The authority proof describes the whole card scope, so a certified proof must
    /// match the highest publication generation and revoke watermark represented by
    /// every manifest in that evidence object. An empty or structurally inconsistent
    /// evidence object is never eligible for certification.
    pub fn evidence_frontier(
        evidence: &PublishedCardAuthorization,
    ) -> Result<(u64, u64), AuthorizationAuthorityError> {
        evidence
            .validate()
            .map_err(|_| AuthorizationAuthorityError::EvidenceInvalid)?;
        let Some(first) = evidence.manifests.first() else {
            return Err(AuthorizationAuthorityError::EvidenceInvalid);
        };
        let mut highest_generation = 0;
        let mut highest_revoke_watermark = 0;
        for manifest in &evidence.manifests {
            if manifest.tenant_id != evidence.tenant_id || manifest.card_id != evidence.card_id {
                return Err(AuthorizationAuthorityError::EvidenceScopeMismatch);
            }
            if manifest.revoke_fence > manifest.generation {
                return Err(AuthorizationAuthorityError::EvidenceInvalid);
            }
            highest_generation = highest_generation.max(manifest.generation);
            highest_revoke_watermark = highest_revoke_watermark.max(manifest.revoke_fence);
        }
        if first.generation == 0 {
            return Err(AuthorizationAuthorityError::EvidenceInvalid);
        }
        Ok((highest_generation, highest_revoke_watermark))
    }

    /// Verify a proof and bind it to one complete, immutable evidence object.
    pub fn certify_evidence(
        self,
        evidence: Arc<PublishedCardAuthorization>,
        verifying_key: &VerifyingKey,
        now_seconds: i64,
        expected_scope: &PublishedCardEvidenceScope,
    ) -> Result<CertifiedAuthorizationState, AuthorizationAuthorityError> {
        self.verify_at(verifying_key, now_seconds)?;
        self.scope.matches_evidence_scope(expected_scope)?;
        let content_hash = Self::evidence_content_hash(&evidence)?;
        if content_hash != self.snapshot_hash {
            return Err(AuthorizationAuthorityError::EvidenceContentHashMismatch);
        }
        let (scope_generation, revoke_watermark) = Self::evidence_frontier(&evidence)?;
        if self.scope_generation != scope_generation || self.revoke_watermark != revoke_watermark {
            return Err(AuthorizationAuthorityError::EvidenceFrontierMismatch);
        }
        Ok(CertifiedAuthorizationState {
            evidence,
            proof: Arc::new(self),
            certificate: None,
        })
    }

    /// Compare only the current frontier identity. Request nonce, proof id and
    /// issuance timestamps are intentionally excluded because each read proof
    /// is independently minted.
    pub fn same_frontier_as(&self, other: &Self) -> Result<(), AuthorizationAuthorityError> {
        self.same_publication_frontier_as(other)?;
        if self.request_binding_digest != other.request_binding_digest
            || self.operation_id != other.operation_id
            || self.event_id != other.event_id
        {
            return Err(AuthorizationAuthorityError::ScopeMismatch);
        }
        Ok(())
    }

    /// Compare certified publication identity across independent policy requests.
    /// Request binding is intentionally checked separately by each fresh read.
    pub fn same_publication_frontier_as(
        &self,
        other: &Self,
    ) -> Result<(), AuthorizationAuthorityError> {
        self.validate()?;
        other.validate()?;
        if self.authority_id != other.authority_id
            || self.authority_term != other.authority_term
            || self.global_fence_sequence != other.global_fence_sequence
            || self.scope != other.scope
            || self.scope_generation != other.scope_generation
            || self.revoke_watermark != other.revoke_watermark
            || self.snapshot_hash != other.snapshot_hash
            || self.parent_hash != other.parent_hash
            || self.scope_certificate_hash != other.scope_certificate_hash
            || self.key_id != other.key_id
            || self.key_epoch != other.key_epoch
        {
            return Err(AuthorizationAuthorityError::ScopeMismatch);
        }
        Ok(())
    }

    /// Compare the proof's monotonic identity with a previously accepted proof.
    pub fn is_strictly_newer_than(
        &self,
        previous: &Self,
    ) -> Result<bool, AuthorizationAuthorityError> {
        self.validate()?;
        previous.validate()?;
        if self.scope != previous.scope || self.authority_id != previous.authority_id {
            return Err(AuthorizationAuthorityError::ScopeMismatch);
        }
        if self.authority_term < previous.authority_term
            || self.global_fence_sequence < previous.global_fence_sequence
            || self.scope_generation < previous.scope_generation
            || self.revoke_watermark < previous.revoke_watermark
            || self.key_epoch < previous.key_epoch
        {
            return Err(AuthorizationAuthorityError::NonMonotonicIdentity);
        }
        Ok(self.authority_term > previous.authority_term
            || self.global_fence_sequence > previous.global_fence_sequence
            || self.scope_generation > previous.scope_generation
            || self.revoke_watermark > previous.revoke_watermark
            || self.key_epoch > previous.key_epoch)
    }

    /// Compare a proof to the exact scope and content frontier requested by a reader.
    pub fn matches_frontier(
        &self,
        scope: &AuthorizationAuthorityScope,
        authority_term: u64,
        global_fence_sequence: u64,
        scope_generation: u64,
        revoke_watermark: u64,
        snapshot_hash: &str,
    ) -> Result<(), AuthorizationAuthorityError> {
        scope.validate()?;
        if &self.scope != scope
            || self.authority_term != authority_term
            || self.global_fence_sequence != global_fence_sequence
            || self.scope_generation != scope_generation
            || self.revoke_watermark != revoke_watermark
            || self.snapshot_hash != snapshot_hash
        {
            return Err(AuthorizationAuthorityError::ScopeMismatch);
        }
        Ok(())
    }
}

/// Immutable, authenticated evidence that is eligible for an in-memory root.
#[derive(Debug, Clone)]
pub struct CertifiedAuthorizationState {
    evidence: Arc<PublishedCardAuthorization>,
    proof: Arc<AuthorizationFenceProof>,
    certificate: Option<Arc<crate::AuthorityScopePublicationCertificate>>,
}

impl CertifiedAuthorizationState {
    /// Construct only through proof verification and content binding.
    pub fn new(
        proof: AuthorizationFenceProof,
        evidence: Arc<PublishedCardAuthorization>,
        verifying_key: &VerifyingKey,
        now_seconds: i64,
        expected_scope: &PublishedCardEvidenceScope,
    ) -> Result<Self, AuthorizationAuthorityError> {
        proof.certify_evidence(evidence, verifying_key, now_seconds, expected_scope)
    }

    /// Verify both signed objects and the exact manifest vector before installation.
    ///
    /// Card certificates are published at the CANONICAL card publication
    /// scope (`Card{tenant, card, user: None, domain: Any}`) while the request
    /// proof stays at the exact actor lens: the certificate scope must equal
    /// the canonical projection of the proof's card identity, and its
    /// tenant/card must equal the evidence identity. This normalization never
    /// loosens ORG matching (an ORG certificate scope is always rejected
    /// against a card proof) or the request-scope matching performed by
    /// [`AuthorizationFenceProof::certify_evidence`].
    pub fn new_with_certificate(
        proof: AuthorizationFenceProof,
        evidence: Arc<PublishedCardAuthorization>,
        certificate: crate::AuthorityScopePublicationCertificate,
        proof_key: &VerifyingKey,
        certificate_key: &VerifyingKey,
        now_seconds: i64,
        expected_scope: &PublishedCardEvidenceScope,
    ) -> Result<Self, AuthorizationAuthorityError> {
        certificate
            .verify_at(certificate_key, now_seconds)
            .map_err(|_| AuthorizationAuthorityError::InvalidSignature)?;
        let certificate_hash = certificate
            .record_digest()
            .map_err(|_| AuthorizationAuthorityError::EvidenceInvalid)?;
        let proof_card_scope = crate::AuthorityProtocolScope::Card(proof.scope.clone());
        let Some(canonical_publication_scope) = proof_card_scope.canonical_card_publication_scope()
        else {
            // Unreachable by type (a card proof is always a Card scope), but
            // fail closed rather than assume.
            return Err(AuthorizationAuthorityError::EvidenceInvalid);
        };
        let certificate_covers_evidence_identity = matches!(
            &certificate.scope,
            crate::AuthorityProtocolScope::Card(scope)
                if scope.tenant_id == evidence.tenant_id && scope.card_id == evidence.card_id
        );
        if proof.request_binding_digest.is_none()
            || proof.scope_certificate_hash.as_deref() != Some(certificate_hash.as_str())
            || certificate.scope != canonical_publication_scope
            || !certificate_covers_evidence_identity
            || certificate.authority_id != proof.authority_id
            || certificate.authority_term > proof.authority_term
            || certificate.global_fence_sequence > proof.global_fence_sequence
            || certificate.key_epoch > proof.key_epoch
            || certificate.snapshot_hash != proof.snapshot_hash
            || certificate.manifests.len() != evidence.manifests.len()
        {
            return Err(AuthorizationAuthorityError::EvidenceFrontierMismatch);
        }
        for (certified, manifest) in certificate.manifests.iter().zip(&evidence.manifests) {
            if certified.aggregate_type != manifest.aggregate_type
                || certified.aggregate_id != manifest.aggregate_id
                || certified.manifest_digest_hex != manifest.manifest_digest_hex
                || certified.dependency_hash_hex != manifest.dependency_hash_hex
                || certified.semantic_hash_hex != manifest.semantic_hash_hex
                || certified.generation != manifest.generation
                || certified.revoke_fence != manifest.revoke_fence
                || certified.event_id != manifest.event_id
                || certified.operation_id != manifest.operation_id
            {
                return Err(AuthorizationAuthorityError::EvidenceFrontierMismatch);
            }
        }
        let mut state = Self::new(proof, evidence, proof_key, now_seconds, expected_scope)?;
        state.certificate = Some(Arc::new(certificate));
        Ok(state)
    }

    /// The authenticated publication chain is independent of request proof identity.
    pub fn certificate(&self) -> Option<Arc<crate::AuthorityScopePublicationCertificate>> {
        self.certificate.as_ref().map(Arc::clone)
    }

    /// Check one publication successor without treating a fresh request as a publication.
    pub fn validate_successor_of(
        &self,
        previous: &Self,
    ) -> Result<(), AuthorizationAuthorityError> {
        let proof = self.proof();
        let old = previous.proof();
        let newer = proof.is_strictly_newer_than(&old)?;
        match (self.certificate.as_ref(), previous.certificate.as_ref()) {
            (Some(next), Some(prior)) => {
                let prior_hash = prior
                    .record_digest()
                    .map_err(|_| AuthorizationAuthorityError::EvidenceInvalid)?;
                if proof.scope_certificate_hash == old.scope_certificate_hash {
                    if next != prior
                        || proof.scope_generation != old.scope_generation
                        || proof.revoke_watermark != old.revoke_watermark
                        || proof.snapshot_hash != old.snapshot_hash
                    {
                        return Err(AuthorizationAuthorityError::EvidenceFrontierMismatch);
                    }
                } else if !newer
                    || next.parent_certificate_hash.as_deref() != Some(prior_hash.as_str())
                {
                    return Err(AuthorizationAuthorityError::NonMonotonicIdentity);
                }
            }
            (None, None)
                if proof.scope_certificate_hash.is_none()
                    && old.scope_certificate_hash.is_none() =>
            {
                if newer {
                    if proof.parent_hash.as_deref() != Some(old.snapshot_hash.as_str()) {
                        return Err(AuthorizationAuthorityError::NonMonotonicIdentity);
                    }
                } else {
                    proof.same_publication_frontier_as(&old)?;
                }
            }
            _ => return Err(AuthorizationAuthorityError::EvidenceFrontierMismatch),
        }
        Ok(())
    }

    /// Return the verified evidence without exposing mutable state.
    pub fn evidence(&self) -> Arc<PublishedCardAuthorization> {
        Arc::clone(&self.evidence)
    }

    /// Return the proof identity for admission/final recheck comparison.
    pub fn proof(&self) -> Arc<AuthorizationFenceProof> {
        Arc::clone(&self.proof)
    }

    /// Revalidate the immutable certified root without reloading the trust root.
    ///
    /// Signature verification is completed by [`Self::new`] before installation.
    /// Serving still rechecks the proof window, exact scope, content identity, and
    /// evidence frontier so an expired or structurally changed root cannot serve.
    pub fn validate_at(
        &self,
        now_seconds: i64,
        expected_scope: &PublishedCardEvidenceScope,
    ) -> Result<(), AuthorizationAuthorityError> {
        self.proof.validate_at(now_seconds)?;
        self.proof.scope.matches_evidence_scope(expected_scope)?;
        match (&self.proof.scope_certificate_hash, &self.certificate) {
            (Some(hash), Some(certificate)) => {
                if certificate
                    .record_digest()
                    .map_err(|_| AuthorizationAuthorityError::EvidenceInvalid)?
                    != *hash
                    || now_seconds < certificate.not_before
                    || certificate
                        .expires_at
                        .is_some_and(|expires| now_seconds >= expires)
                {
                    return Err(AuthorizationAuthorityError::EvidenceNotCurrentlyUsable);
                }
            }
            (None, None) => {}
            _ => return Err(AuthorizationAuthorityError::EvidenceFrontierMismatch),
        }
        if self.proof.expires_at <= self.evidence.read_unix_seconds
            || now_seconds < self.evidence.read_unix_seconds
            || self
                .evidence
                .effective_grants
                .iter()
                .any(|grant| !grant.validity.is_valid_at(now_seconds))
        {
            return Err(AuthorizationAuthorityError::EvidenceNotCurrentlyUsable);
        }
        let content_hash = AuthorizationFenceProof::evidence_content_hash(&self.evidence)?;
        if content_hash != self.proof.snapshot_hash {
            return Err(AuthorizationAuthorityError::EvidenceContentHashMismatch);
        }
        let (scope_generation, revoke_watermark) =
            AuthorizationFenceProof::evidence_frontier(&self.evidence)?;
        if self.proof.scope_generation != scope_generation
            || self.proof.revoke_watermark != revoke_watermark
        {
            return Err(AuthorizationAuthorityError::EvidenceFrontierMismatch);
        }
        Ok(())
    }
}

/// Canonical V7 content view: the immutable publication content only. The
/// lens/time-derived projections (`effective_grants`, the acceptance flags
/// and reasons on each record, the gate counters, the read clock) are
/// excluded on purpose — see [`AuthorizationFenceProof::evidence_content_hash`].
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceContentSnapshotView<'a> {
    tenant_id: i64,
    card_id: i64,
    manifests: &'a [crate::PublishedAggregateManifestSummary],
    /// Owned vector of borrowed immutable record projections; no allocation
    /// escapes this view and nothing is retained beyond the hash call.
    records: Vec<VerifiedPublishedGrantRecordSnapshotView<'a>>,
}

/// Immutable projection of one verified record: provenance plus the FULL
/// grant content (state and validity included). The acceptance flag and
/// reason are lens/time-derived and are never serialized here.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifiedPublishedGrantRecordSnapshotView<'a> {
    aggregate_type: &'a str,
    aggregate_id: i64,
    publication_generation: u64,
    revoke_fence: u64,
    manifest_id: i64,
    event_id: &'a str,
    operation_id: &'a str,
    semantic_hash_hex: &'a str,
    dependency_hash_hex: &'a str,
    compiler_version: &'a str,
    segment_ordinal: u64,
    position_in_segment: u64,
    grant: &'a crate::CanonicalGrant,
}

impl<'a> From<&'a crate::VerifiedPublishedGrantRecord>
    for VerifiedPublishedGrantRecordSnapshotView<'a>
{
    fn from(record: &'a crate::VerifiedPublishedGrantRecord) -> Self {
        Self {
            aggregate_type: &record.aggregate_type,
            aggregate_id: record.aggregate_id,
            publication_generation: record.publication_generation,
            revoke_fence: record.revoke_fence,
            manifest_id: record.manifest_id,
            event_id: &record.event_id,
            operation_id: &record.operation_id,
            semantic_hash_hex: &record.semantic_hash_hex,
            dependency_hash_hex: &record.dependency_hash_hex,
            compiler_version: &record.compiler_version,
            segment_ordinal: record.segment_ordinal,
            position_in_segment: record.position_in_segment,
            grant: &record.grant,
        }
    }
}

impl<'a> EvidenceContentSnapshotView<'a> {
    fn from(evidence: &'a PublishedCardAuthorization) -> Self {
        Self {
            tenant_id: evidence.tenant_id,
            card_id: evidence.card_id,
            manifests: &evidence.manifests,
            records: evidence
                .records
                .iter()
                .map(VerifiedPublishedGrantRecordSnapshotView::from)
                .collect(),
        }
    }
}

/// Node-level gate for serving positive in-memory authorization reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorizationAuthorityState {
    #[default]
    Cold,
    Warming,
    FenceSyncing,
    Serving,
    Pending,
    Suspect,
    Quarantined,
    Recovering,
    Draining,
}

impl AuthorizationAuthorityState {
    /// Whether this state may serve positive authorization from memory.
    pub const fn may_serve_positive(self) -> bool {
        matches!(self, Self::Serving)
    }

    /// Validate a state transition. Unknown or unsafe transitions fail closed.
    pub const fn can_transition_to(self, next: Self) -> bool {
        use AuthorizationAuthorityState::*;
        matches!(
            (self, next),
            (Cold, Warming)
                | (Warming, FenceSyncing)
                | (FenceSyncing, Serving | Pending | Suspect | Quarantined)
                | (Serving, Pending | Suspect | Quarantined | Draining)
                | (Pending, Recovering)
                | (Suspect, Recovering)
                | (Quarantined, Recovering)
                | (Recovering, FenceSyncing)
                | (Draining, Cold)
        )
    }
}

/// Scope-level lifecycle for one certified authorization publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorizationPublicationState {
    Active,
    ChangeReserved,
    Pending,
    Certifying,
    Quarantined,
}

impl AuthorizationPublicationState {
    /// Only an active state is eligible for positive policy evaluation.
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    /// Validate lifecycle transitions independently of the database status enum.
    pub const fn can_transition_to(self, next: Self) -> bool {
        use AuthorizationPublicationState::*;
        matches!(
            (self, next),
            (Active, ChangeReserved)
                | (ChangeReserved, Pending | Certifying | Quarantined)
                | (Pending, Certifying | Quarantined)
                | (Certifying, Active | Quarantined)
        )
    }
}

fn positive_id(value: i64, field_name: &'static str) -> Result<(), AuthorizationAuthorityError> {
    (value > 0)
        .then_some(())
        .ok_or(AuthorizationAuthorityError::InvalidIdentifier { field: field_name })
}

fn counter(value: u64, field_name: &'static str) -> Result<(), AuthorizationAuthorityError> {
    (value > 0)
        .then_some(())
        .ok_or(AuthorizationAuthorityError::InvalidCounter { field: field_name })
}

fn text(value: &str, field_name: &'static str) -> Result<(), AuthorizationAuthorityError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(AuthorizationAuthorityError::InvalidText { field: field_name });
    }
    Ok(())
}

fn digest(value: &str, field_name: &'static str) -> Result<(), AuthorizationAuthorityError> {
    if value.len() != SHA256_HEX_LEN
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AuthorizationAuthorityError::InvalidDigest { field: field_name });
    }
    Ok(())
}

fn optional_i64(value: Option<i64>) -> String {
    value.map_or_else(|| "-".to_owned(), |value| value.to_string())
}

fn domain_scope_text(scope: &AuthorizationDomainScope) -> String {
    match scope {
        AuthorizationDomainScope::Any => "ANY".to_owned(),
        AuthorizationDomainScope::NoDomain => "NONE".to_owned(),
        AuthorizationDomainScope::Exact(value) => format!("EXACT:{value}"),
    }
}

fn field(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn decode_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }
    let mut output = [0u8; N];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(output)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ed25519_dalek::{Signer, SigningKey};

    use crate::{
        CanonicalGrant, PublicationSeal, PublishedAggregateManifestSummary,
        PublishedCardAuthorizationGate, PublishedEvidenceGateStatus, UnacceptedGrantReason,
        VerifiedPublishedGrantRecord,
    };

    use super::*;

    fn evidence_scope() -> PublishedCardEvidenceScope {
        PublishedCardEvidenceScope {
            tenant_id: 7,
            card_id: 17,
            user_filter: None,
            domain: DomainScopeRequirement::Unconstrained,
        }
    }

    fn manifest(
        generation: u64,
        revoke_fence: u64,
        tenant_id: i64,
        card_id: i64,
        manifest_id: i64,
    ) -> PublishedAggregateManifestSummary {
        PublishedAggregateManifestSummary {
            seal: PublicationSeal::from_unix_seconds(1_700_000_000 + generation as i64)
                .expect("valid fixture seal"),
            tenant_id,
            card_id,
            aggregate_type: "USER_CARD".to_owned(),
            // Distinct aggregate identity per fixture manifest: a publication
            // certificate binds exactly one manifest per (type, aggregate_id),
            // so two fixture manifests must not collapse onto one identity.
            aggregate_id: manifest_id,
            manifest_id,
            generation,
            source_generation: generation,
            projected_generation: generation,
            revoke_fence,
            cas_version: generation as i64,
            semantic_hash_hex: "aa".repeat(32),
            dependency_hash_hex: "bb".repeat(32),
            manifest_digest_hex: "cc".repeat(32),
            compiler_version: crate::AUTHORIZATION_COMPILER_VERSION.to_owned(),
            event_id: format!("event-{manifest_id}"),
            operation_id: format!("operation-{manifest_id}"),
            parent_manifest_id: None,
            segment_count: 0,
            declared_grant_row_count: 0,
        }
    }

    fn fixture_evidence() -> PublishedCardAuthorization {
        PublishedCardAuthorization {
            tenant_id: 7,
            card_id: 17,
            read_unix_seconds: 100,
            gate: PublishedCardAuthorizationGate {
                status: PublishedEvidenceGateStatus::Ready,
                aggregate_manifest_count: 2,
                verified_record_count: 0,
                effective_grant_count: 0,
                not_in_effective_count: 0,
                equivalent_duplicate_collapsed_count: 0,
            },
            manifests: vec![manifest(1, 0, 7, 17, 101), manifest(3, 2, 7, 17, 102)],
            records: Vec::new(),
            effective_grants: Vec::new(),
        }
    }

    fn unsigned_proof() -> AuthorizationFenceProof {
        AuthorizationFenceProof {
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: "authority-a".to_owned(),
            authority_term: 1,
            global_fence_sequence: 2,
            scope: AuthorizationAuthorityScope {
                tenant_id: 7,
                card_id: 17,
                user_id: Some(23),
                domain: AuthorizationDomainScope::Exact(31),
            },
            scope_generation: 2,
            revoke_watermark: 1,
            snapshot_hash: "ab".repeat(32),
            parent_hash: Some("cd".repeat(32)),
            operation_id: "operation-1".to_owned(),
            event_id: "event-1".to_owned(),
            key_id: "key-1".to_owned(),
            key_epoch: 1,
            issued_at: 100,
            not_before: 99,
            expires_at: 110,
            request_nonce: "nonce-1".to_owned(),
            request_binding_digest: None,
            scope_certificate_hash: None,
            proof_id: "proof-1".to_owned(),
            signature: "00".repeat(64),
        }
    }

    fn signed_proof_for(
        evidence: &PublishedCardAuthorization,
        scope_generation: u64,
        revoke_watermark: u64,
        request_nonce: &str,
        proof_id: &str,
    ) -> (AuthorizationFenceProof, SigningKey) {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let scope = evidence_scope();
        let mut proof = unsigned_proof();
        proof.scope = AuthorizationAuthorityScope::from_evidence_scope(&scope);
        proof.scope_generation = scope_generation;
        proof.revoke_watermark = revoke_watermark;
        proof.snapshot_hash = AuthorizationFenceProof::evidence_content_hash(evidence)
            .expect("fixture evidence hash");
        proof.request_nonce = request_nonce.to_owned();
        proof.proof_id = proof_id.to_owned();
        proof.signature = hex::encode(signing_key.sign(&proof.signing_bytes().unwrap()).to_bytes());
        (proof, signing_key)
    }

    fn certified_publication(
        evidence: &PublishedCardAuthorization,
        fence: u64,
        parent: Option<String>,
    ) -> CertifiedAuthorizationState {
        let (generation, revoke) = AuthorizationFenceProof::evidence_frontier(evidence).unwrap();
        let (mut proof, key) = signed_proof_for(
            evidence,
            generation,
            revoke,
            "request-nonce",
            "request-proof",
        );
        proof.global_fence_sequence = fence;
        proof.parent_hash = None;
        proof.request_binding_digest = Some("11".repeat(32));
        let mut certificate = crate::AuthorityScopePublicationCertificate {
            protocol_version: crate::AUTHORITY_PROTOCOL_VERSION,
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: proof.authority_id.clone(),
            authority_term: proof.authority_term,
            global_fence_sequence: 2,
            certificate_id: format!("certificate-{generation}"),
            intent_digest: "22".repeat(32),
            reservation_id: "reservation-1".into(),
            operation_id: "publication-operation".into(),
            event_id: "publication-event".into(),
            scope: crate::AuthorityProtocolScope::Card(proof.scope.clone()),
            approved_request_digest: "33".repeat(32),
            before_image_digest: None,
            after_image_digest: "44".repeat(32),
            source_commit_digest: "55".repeat(32),
            source_outcome_digest: "99".repeat(32),
            completion_digest: "00".repeat(32),
            snapshot_hash: proof.snapshot_hash.clone(),
            parent_certificate_hash: parent,
            manifests: evidence
                .manifests
                .iter()
                .map(|manifest| crate::AuthorityManifestIdentity {
                    aggregate_type: manifest.aggregate_type.clone(),
                    aggregate_id: manifest.aggregate_id,
                    manifest_digest_hex: manifest.manifest_digest_hex.clone(),
                    dependency_hash_hex: manifest.dependency_hash_hex.clone(),
                    semantic_hash_hex: manifest.semantic_hash_hex.clone(),
                    generation: manifest.generation,
                    revoke_fence: manifest.revoke_fence,
                    event_id: manifest.event_id.clone(),
                    operation_id: manifest.operation_id.clone(),
                })
                .collect(),
            key_id: proof.key_id.clone(),
            key_epoch: proof.key_epoch,
            issued_at: 99,
            not_before: 99,
            expires_at: None,
            certificate_nonce: "certificate-nonce".into(),
            signature: String::new(),
        };
        certificate.completion_digest = certificate.recompute_completion_digest().unwrap();
        certificate.sign(&key).unwrap();
        proof.scope_certificate_hash = Some(certificate.record_digest().unwrap());
        proof.signature = hex::encode(key.sign(&proof.signing_bytes().unwrap()).to_bytes());
        CertifiedAuthorizationState::new_with_certificate(
            proof,
            Arc::new(evidence.clone()),
            certificate,
            &key.verifying_key(),
            &key.verifying_key(),
            100,
            &evidence_scope(),
        )
        .unwrap()
    }

    #[test]
    fn publication_lineage_is_separate_from_request_frontier() {
        let evidence = fixture_evidence();
        let previous = certified_publication(&evidence, 2, None);
        let refreshed = certified_publication(&evidence, 3, None);
        refreshed.validate_successor_of(&previous).unwrap();
        refreshed.validate_at(100, &evidence_scope()).unwrap();
        let mut changed = evidence.clone();
        changed.manifests[1].generation = 4;
        changed.manifests[1].source_generation = 4;
        changed.manifests[1].projected_generation = 4;
        let parent = previous.certificate().unwrap().record_digest().unwrap();
        let next = certified_publication(&changed, 4, Some(parent));
        next.validate_successor_of(&previous).unwrap();
        let fork = certified_publication(&changed, 4, Some("99".repeat(32)));
        assert!(fork.validate_successor_of(&previous).is_err());
        assert!(previous.validate_successor_of(&next).is_err());
    }

    #[test]
    fn certificate_must_bind_every_manifest_and_remain_attached() {
        let certified = certified_publication(&fixture_evidence(), 2, None);
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut certificate = (*certified.certificate().unwrap()).clone();
        certificate.manifests[0].dependency_hash_hex = "66".repeat(32);
        certificate.completion_digest = certificate.recompute_completion_digest().unwrap();
        certificate.sign(&key).unwrap();
        let mut proof = (*certified.proof()).clone();
        proof.scope_certificate_hash = Some(certificate.record_digest().unwrap());
        proof.signature = hex::encode(key.sign(&proof.signing_bytes().unwrap()).to_bytes());
        assert!(CertifiedAuthorizationState::new_with_certificate(
            proof,
            certified.evidence(),
            certificate,
            &key.verifying_key(),
            &key.verifying_key(),
            100,
            &evidence_scope()
        )
        .is_err());
        let detached = CertifiedAuthorizationState::new(
            (*certified.proof()).clone(),
            certified.evidence(),
            &key.verifying_key(),
            100,
            &evidence_scope(),
        )
        .unwrap();
        assert!(detached.validate_at(100, &evidence_scope()).is_err());
    }

    #[test]
    fn admission_consumes_once_across_clones() {
        let evidence = fixture_evidence();
        let (proof, _) = signed_proof_for(&evidence, 3, 2, "nonce-admission", "proof-admission");
        let admission = AuthorizationAdmission::from_verified_proof(proof).unwrap();
        let second_handle = admission.clone();

        second_handle
            .consume_once()
            .expect("the first source commit attempt may consume the admission");
        assert!(matches!(
            admission.consume_once(),
            Err(AuthorizationAuthorityError::AdmissionConsumed)
        ));
        assert_eq!(admission.proof(), second_handle.proof());
    }

    #[test]
    fn signature_binds_all_frontier_fields_and_verifies_strictly() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let mut proof = unsigned_proof();
        proof.signature = hex::encode(signing_key.sign(&proof.signing_bytes().unwrap()).to_bytes());
        proof.verify_at(&signing_key.verifying_key(), 100).unwrap();

        proof.global_fence_sequence += 1;
        assert_eq!(
            proof.verify_at(&signing_key.verifying_key(), 100),
            Err(AuthorizationAuthorityError::InvalidSignature)
        );
    }

    #[test]
    fn signature_binds_request_digest_and_publication_certificate() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut proof = unsigned_proof();
        proof.request_binding_digest = Some("11".repeat(32));
        proof.scope_certificate_hash = Some("22".repeat(32));
        proof.signature = hex::encode(key.sign(&proof.signing_bytes().unwrap()).to_bytes());
        proof.verify_at(&key.verifying_key(), 100).unwrap();
        let mut changed = proof.clone();
        changed.request_binding_digest = Some("33".repeat(32));
        assert_eq!(
            changed.verify_at(&key.verifying_key(), 100),
            Err(AuthorizationAuthorityError::InvalidSignature)
        );
        changed = proof;
        changed.scope_certificate_hash = Some("44".repeat(32));
        assert_eq!(
            changed.verify_at(&key.verifying_key(), 100),
            Err(AuthorizationAuthorityError::InvalidSignature)
        );
    }

    #[test]
    fn complete_evidence_frontier_uses_highest_generation_and_revoke_watermark() {
        let evidence = fixture_evidence();
        assert_eq!(
            AuthorizationFenceProof::evidence_frontier(&evidence).unwrap(),
            (3, 2)
        );
    }

    #[test]
    fn certification_requires_exact_evidence_frontier() {
        let evidence = fixture_evidence();
        let (proof, signing_key) = signed_proof_for(&evidence, 3, 2, "nonce-good", "proof-good");
        let certified = proof
            .clone()
            .certify_evidence(
                Arc::new(evidence.clone()),
                &signing_key.verifying_key(),
                100,
                &evidence_scope(),
            )
            .expect("matching frontier must certify");
        assert_eq!(certified.proof().scope_generation, 3);

        let (generation_drift, generation_key) =
            signed_proof_for(&evidence, 2, 2, "nonce-generation", "proof-generation");
        let generation_error = generation_drift
            .certify_evidence(
                Arc::new(evidence.clone()),
                &generation_key.verifying_key(),
                100,
                &evidence_scope(),
            )
            .expect_err("generation drift must not certify");
        assert_eq!(
            generation_error,
            AuthorizationAuthorityError::EvidenceFrontierMismatch
        );

        let (revoke_drift, revoke_key) =
            signed_proof_for(&evidence, 3, 1, "nonce-revoke", "proof-revoke");
        let revoke_error = revoke_drift
            .certify_evidence(
                Arc::new(evidence),
                &revoke_key.verifying_key(),
                100,
                &evidence_scope(),
            )
            .expect_err("revoke watermark drift must not certify");
        assert_eq!(
            revoke_error,
            AuthorizationAuthorityError::EvidenceFrontierMismatch
        );
    }

    #[test]
    fn certification_rejects_empty_or_cross_scope_evidence() {
        let empty = PublishedCardAuthorization {
            tenant_id: 7,
            card_id: 17,
            read_unix_seconds: 100,
            gate: PublishedCardAuthorizationGate {
                status: PublishedEvidenceGateStatus::Ready,
                aggregate_manifest_count: 0,
                verified_record_count: 0,
                effective_grant_count: 0,
                not_in_effective_count: 0,
                equivalent_duplicate_collapsed_count: 0,
            },
            manifests: Vec::new(),
            records: Vec::new(),
            effective_grants: Vec::new(),
        };
        assert_eq!(
            AuthorizationFenceProof::evidence_frontier(&empty),
            Err(AuthorizationAuthorityError::EvidenceInvalid)
        );
        let (empty_proof, empty_key) = signed_proof_for(&empty, 1, 0, "nonce-empty", "proof-empty");
        let empty_error = empty_proof
            .certify_evidence(
                Arc::new(empty),
                &empty_key.verifying_key(),
                100,
                &evidence_scope(),
            )
            .expect_err("empty evidence must not certify");
        assert_eq!(empty_error, AuthorizationAuthorityError::EvidenceInvalid);

        let mut cross_scope = fixture_evidence();
        cross_scope.manifests[0].tenant_id = 8;
        let (cross_scope_proof, cross_scope_key) =
            signed_proof_for(&cross_scope, 3, 2, "nonce-cross-scope", "proof-cross-scope");
        let cross_scope_error = cross_scope_proof
            .certify_evidence(
                Arc::new(cross_scope),
                &cross_scope_key.verifying_key(),
                100,
                &evidence_scope(),
            )
            .expect_err("cross-scope evidence must not certify");
        assert_eq!(
            cross_scope_error,
            AuthorizationAuthorityError::EvidenceScopeMismatch
        );
    }

    #[test]
    fn proof_time_window_and_same_frontier_contract_are_explicit() {
        let evidence = fixture_evidence();
        let (first, first_key) = signed_proof_for(&evidence, 3, 2, "nonce-first", "proof-first");
        assert_eq!(
            first.verify_at(&first_key.verifying_key(), 98),
            Err(AuthorizationAuthorityError::NotCurrentlyValid)
        );
        assert_eq!(
            first.verify_at(&first_key.verifying_key(), 110),
            Err(AuthorizationAuthorityError::NotCurrentlyValid)
        );

        let (second, second_key) =
            signed_proof_for(&evidence, 3, 2, "nonce-second", "proof-second");
        second
            .verify_at(&second_key.verifying_key(), 100)
            .expect("independent proof must verify");
        first
            .same_frontier_as(&second)
            .expect("independent proofs may share one exact frontier");
        assert_ne!(first.request_nonce, second.request_nonce);
        assert_ne!(first.proof_id, second.proof_id);

        let mut regressed = second;
        regressed.scope_generation = 2;
        assert_eq!(
            regressed.is_strictly_newer_than(&first),
            Err(AuthorizationAuthorityError::NonMonotonicIdentity)
        );
    }

    #[test]
    fn older_generation_cannot_become_newer() {
        let first = unsigned_proof();
        let mut older = first.clone();
        older.scope_generation = 1;
        assert_eq!(
            older.is_strictly_newer_than(&first),
            Err(AuthorizationAuthorityError::NonMonotonicIdentity)
        );
    }

    #[test]
    fn message_metadata_validates_and_serializes_canonically() {
        let metadata = AuthorizationMessageMetadata {
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: "authority-1".into(),
            authority_term: 4,
            global_fence_sequence: 9,
            key_id: "key-1".into(),
            key_epoch: 2,
            proof_id: "proof-1".into(),
            scope_generation: 12,
            revoke_watermark: 8,
            snapshot_hash: "aa".repeat(32),
        };
        metadata.validate().unwrap();
        assert_eq!(
            serde_json::to_string(&metadata).unwrap(),
            format!(
                r#"{{"authorizationEdition":{},"authorityId":"authority-1","authorityTerm":4,"globalFenceSequence":9,"keyId":"key-1","keyEpoch":2,"proofId":"proof-1","scopeGeneration":12,"revokeWatermark":8,"snapshotHash":"{}"}}"#,
                AUTHORIZATION_EDITION,
                "aa".repeat(32)
            )
        );
    }

    #[test]
    fn message_metadata_rejects_unknown_fields_and_invalid_frontier() {
        let json = format!(
            r#"{{"authorizationEdition":{},"authorityId":"authority-1","authorityTerm":4,"globalFenceSequence":9,"keyId":"key-1","keyEpoch":2,"proofId":"proof-1","scopeGeneration":12,"revokeWatermark":8,"snapshotHash":"{}","termHint":5}}"#,
            AUTHORIZATION_EDITION,
            "aa".repeat(32)
        );
        assert!(serde_json::from_str::<AuthorizationMessageMetadata>(&json).is_err());

        let mut invalid = AuthorizationMessageMetadata {
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: "authority-1".into(),
            authority_term: 4,
            global_fence_sequence: 9,
            key_id: "key-1".into(),
            key_epoch: 2,
            proof_id: "proof-1".into(),
            scope_generation: 12,
            revoke_watermark: 8,
            snapshot_hash: "aa".repeat(32),
        };
        invalid.revoke_watermark = invalid.scope_generation + 1;
        assert!(matches!(
            invalid.validate(),
            Err(AuthorizationAuthorityError::RevokeWatermarkAhead)
        ));
    }
    #[test]
    fn authority_state_machine_refuses_unsafe_edges() {
        assert!(AuthorizationAuthorityState::Cold
            .can_transition_to(AuthorizationAuthorityState::Warming));
        assert!(!AuthorizationAuthorityState::Serving
            .can_transition_to(AuthorizationAuthorityState::Cold));
        assert!(!AuthorizationAuthorityState::Suspect.may_serve_positive());
        assert!(AuthorizationPublicationState::Certifying
            .can_transition_to(AuthorizationPublicationState::Active));
        assert!(!AuthorizationPublicationState::Active
            .can_transition_to(AuthorizationPublicationState::Certifying));
    }

    fn record(
        grant: CanonicalGrant,
        accepted: bool,
        reason: Option<UnacceptedGrantReason>,
    ) -> VerifiedPublishedGrantRecord {
        VerifiedPublishedGrantRecord {
            aggregate_type: "USER_CARD".to_owned(),
            aggregate_id: 101,
            publication_generation: 1,
            revoke_fence: 0,
            manifest_id: 101,
            event_id: "event-101".to_owned(),
            operation_id: "operation-101".to_owned(),
            semantic_hash_hex: "aa".repeat(32),
            dependency_hash_hex: "bb".repeat(32),
            compiler_version: crate::AUTHORIZATION_COMPILER_VERSION.to_owned(),
            segment_ordinal: 0,
            position_in_segment: 0,
            grant,
            accepted_into_effective_set: accepted,
            unaccepted_reason: reason,
        }
    }

    fn fixture_evidence_with_records() -> PublishedCardAuthorization {
        let mut evidence = fixture_evidence();
        evidence.gate.verified_record_count = 1;
        evidence.gate.effective_grant_count = 1;
        evidence.gate.not_in_effective_count = 0;
        let grant = CanonicalGrant {
            grant_id: crate::GrantId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            revision: crate::GrantRevision::new(2).unwrap(),
            state: crate::GrantState::Active,
            source_kind: crate::GrantSourceKind::RuleSet,
            binding_layer: crate::BindingLayer::Overlay,
            tenant: crate::TenantScope::new(7, Some(11)).unwrap(),
            card_id: 17,
            user_id: 23,
            resource: " learn_subject ".to_owned(),
            action: " read ".to_owned(),
            effect: crate::GrantEffect::Allow,
            validity: crate::ValidityWindow::between(100, 200),
            provenance: crate::GrantProvenance {
                source_id: "rule-set-entry-9".to_owned(),
                source_entry: Some("rule-set-entry-9".to_owned()),
                binding_id: Some("binding-3".to_owned()),
                delegation_id: None,
                operation_id: "op-1".to_owned(),
                event_id: Some("event-1".to_owned()),
                actor_user_id: Some(42),
            },
        };
        let record = record(grant.clone(), true, None);
        evidence.records = vec![record];
        evidence.effective_grants = vec![grant];
        evidence
    }

    #[test]
    fn evidence_content_hash_is_lens_and_time_invariant() {
        let evidence = fixture_evidence_with_records();
        let hash = AuthorizationFenceProof::evidence_content_hash(&evidence).unwrap();
        // The same publication read at a different instant: validity
        // classification (accepted flags, gate counters, effective set) may
        // change with the clock, the canonical hash must not.
        let later_read = {
            let mut other = evidence.clone();
            other.read_unix_seconds = 150;
            other.gate.effective_grant_count = 0;
            other.gate.not_in_effective_count = 1;
            other.effective_grants = Vec::new();
            other.records[0].accepted_into_effective_set = false;
            other.records[0].unaccepted_reason = Some(UnacceptedGrantReason::Expired);
            other
        };
        assert_eq!(
            hash,
            AuthorizationFenceProof::evidence_content_hash(&later_read).unwrap()
        );
        // A pure gate-counter drift (as produced by a lensed re-read) also
        // keeps the same content identity.
        let relensed = {
            let mut other = evidence.clone();
            other.gate.equivalent_duplicate_collapsed_count = 3;
            other
        };
        assert_eq!(
            hash,
            AuthorizationFenceProof::evidence_content_hash(&relensed).unwrap()
        );
    }

    #[test]
    fn evidence_content_hash_binds_every_immutable_field() {
        let evidence = fixture_evidence_with_records();
        let hash = AuthorizationFenceProof::evidence_content_hash(&evidence).unwrap();

        let changed_validity = {
            let mut other = evidence.clone();
            other.records[0].grant.validity = crate::ValidityWindow::between(100, 201);
            // Keep the structural contract: the effective view mirrors the
            // accepted record content exactly.
            other.effective_grants[0].validity = crate::ValidityWindow::between(100, 201);
            other
        };
        assert_ne!(
            hash,
            AuthorizationFenceProof::evidence_content_hash(&changed_validity).unwrap()
        );

        let changed_state = {
            let mut other = evidence.clone();
            other.records[0].grant.state = crate::GrantState::Revoked;
            // Keep the fixture structurally valid: a revoked grant can no
            // longer be part of the accepted effective set. The acceptance
            // flip itself is hash-invisible (see the invariance test); the
            // hash changes because the grant STATE changed.
            other.records[0].accepted_into_effective_set = false;
            other.records[0].unaccepted_reason = Some(UnacceptedGrantReason::InactiveState);
            other.gate.effective_grant_count = 0;
            other.gate.not_in_effective_count = 1;
            other.effective_grants = Vec::new();
            other
        };
        assert_ne!(
            hash,
            AuthorizationFenceProof::evidence_content_hash(&changed_state).unwrap()
        );

        let changed_provenance = {
            let mut other = evidence.clone();
            other.records[0].operation_id = "operation-changed".to_owned();
            other
        };
        assert_ne!(
            hash,
            AuthorizationFenceProof::evidence_content_hash(&changed_provenance).unwrap()
        );

        let changed_manifest = {
            let mut other = evidence.clone();
            other.manifests[1].manifest_digest_hex = "dd".repeat(32);
            other
        };
        assert_ne!(
            hash,
            AuthorizationFenceProof::evidence_content_hash(&changed_manifest).unwrap()
        );

        let extra_record = {
            let mut other = evidence.clone();
            let mut grant = other.records[0].grant.clone();
            grant.user_id = 24;
            other.records.push(record(grant, true, None));
            other.gate.verified_record_count = 2;
            other.gate.effective_grant_count = 2;
            other.effective_grants.push(other.records[1].grant.clone());
            other
        };
        assert_ne!(
            hash,
            AuthorizationFenceProof::evidence_content_hash(&extra_record).unwrap()
        );
    }

    #[test]
    fn certificate_binds_canonical_card_scope_over_lensed_proof() {
        let evidence = fixture_evidence_with_records();
        // The request proof stays at the exact actor lens.
        let lensed_scope = PublishedCardEvidenceScope {
            tenant_id: 7,
            card_id: 17,
            user_filter: Some(23),
            domain: DomainScopeRequirement::ExactlySome(31),
        };
        let (generation, revoke) = AuthorizationFenceProof::evidence_frontier(&evidence).unwrap();
        let (mut proof, key) =
            signed_proof_for(&evidence, generation, revoke, "nonce-lens", "proof-lens");
        proof.scope = AuthorizationAuthorityScope::from_evidence_scope(&lensed_scope);
        proof.parent_hash = None;
        proof.request_binding_digest = Some("11".repeat(32));
        proof.signature = hex::encode(key.sign(&proof.signing_bytes().unwrap()).to_bytes());
        // The certificate is published at the CANONICAL card scope, not the
        // lensed request scope; the V7 content hash is lens-invariant so the
        // snapshot matches the lensed read as well.
        let mut certificate = {
            let mut certificate = crate::AuthorityScopePublicationCertificate {
                protocol_version: crate::AUTHORITY_PROTOCOL_VERSION,
                authorization_edition: AUTHORIZATION_EDITION,
                authority_id: proof.authority_id.clone(),
                authority_term: proof.authority_term,
                global_fence_sequence: proof.global_fence_sequence,
                certificate_id: "certificate-canonical".to_owned(),
                intent_digest: "22".repeat(32),
                reservation_id: "reservation-1".into(),
                operation_id: "publication-operation".into(),
                event_id: "publication-event".into(),
                scope: crate::AuthorityProtocolScope::Card(AuthorizationAuthorityScope {
                    tenant_id: 7,
                    card_id: 17,
                    user_id: None,
                    domain: AuthorizationDomainScope::Any,
                }),
                approved_request_digest: "33".repeat(32),
                before_image_digest: None,
                after_image_digest: "44".repeat(32),
                source_commit_digest: "55".repeat(32),
                source_outcome_digest: "99".repeat(32),
                completion_digest: "00".repeat(32),
                snapshot_hash: proof.snapshot_hash.clone(),
                parent_certificate_hash: None,
                manifests: evidence
                    .manifests
                    .iter()
                    .map(|manifest| crate::AuthorityManifestIdentity {
                        aggregate_type: manifest.aggregate_type.clone(),
                        aggregate_id: manifest.aggregate_id,
                        manifest_digest_hex: manifest.manifest_digest_hex.clone(),
                        dependency_hash_hex: manifest.dependency_hash_hex.clone(),
                        semantic_hash_hex: manifest.semantic_hash_hex.clone(),
                        generation: manifest.generation,
                        revoke_fence: manifest.revoke_fence,
                        event_id: manifest.event_id.clone(),
                        operation_id: manifest.operation_id.clone(),
                    })
                    .collect(),
                key_id: proof.key_id.clone(),
                key_epoch: proof.key_epoch,
                issued_at: 99,
                not_before: 99,
                expires_at: None,
                certificate_nonce: "certificate-nonce-canonical".into(),
                signature: String::new(),
            };
            certificate.completion_digest = certificate.recompute_completion_digest().unwrap();
            certificate.sign(&key).unwrap();
            certificate
        };
        proof.scope_certificate_hash = Some(certificate.record_digest().unwrap());
        proof.signature = hex::encode(key.sign(&proof.signing_bytes().unwrap()).to_bytes());
        let certified = CertifiedAuthorizationState::new_with_certificate(
            proof,
            Arc::new(evidence.clone()),
            certificate.clone(),
            &key.verifying_key(),
            &key.verifying_key(),
            100,
            &lensed_scope,
        )
        .expect("canonical card certificate must certify a lensed request proof");
        assert_eq!(certified.proof().scope.user_id, Some(23));

        // A lens-exact (non-canonical) certificate scope is rejected: card
        // certificates converge on the canonical publication identity.
        certificate.scope = crate::AuthorityProtocolScope::Card(AuthorizationAuthorityScope {
            tenant_id: 7,
            card_id: 17,
            user_id: Some(23),
            domain: AuthorizationDomainScope::Exact(31),
        });
        certificate.completion_digest = certificate.recompute_completion_digest().unwrap();
        certificate.sign(&key).unwrap();
        let mut lensed_proof = certified.proof().as_ref().clone();
        lensed_proof.scope_certificate_hash = Some(certificate.record_digest().unwrap());
        lensed_proof.signature =
            hex::encode(key.sign(&lensed_proof.signing_bytes().unwrap()).to_bytes());
        assert!(CertifiedAuthorizationState::new_with_certificate(
            lensed_proof,
            Arc::new(evidence.clone()),
            certificate,
            &key.verifying_key(),
            &key.verifying_key(),
            100,
            &lensed_scope,
        )
        .is_err());
    }

    #[test]
    fn certificate_never_binds_org_or_foreign_card_identity() {
        let evidence = fixture_evidence_with_records();
        let certified = certified_publication(&evidence, 2, None);
        let key = SigningKey::from_bytes(&[7; 32]);

        // An ORG certificate scope is always rejected against a card proof.
        let mut org_certificate = (*certified.certificate().unwrap()).clone();
        org_certificate.scope =
            crate::AuthorityProtocolScope::Org(crate::authority_protocol::AuthorityOrgScope {
                tenant_id: 7,
                root_tenant_id: None,
                member: crate::authority_protocol::AuthorityOrgMemberSubject {
                    user_id: 23,
                    identity_card_id: 1,
                    card_id: 17,
                },
            });
        org_certificate.completion_digest = org_certificate.recompute_completion_digest().unwrap();
        org_certificate.sign(&key).unwrap();
        assert!(CertifiedAuthorizationState::new_with_certificate(
            (*certified.proof()).clone(),
            certified.evidence(),
            org_certificate,
            &key.verifying_key(),
            &key.verifying_key(),
            100,
            &evidence_scope(),
        )
        .is_err());

        // A canonical card certificate for a DIFFERENT card identity is
        // rejected even when every manifest digest happens to match.
        let mut foreign_certificate = (*certified.certificate().unwrap()).clone();
        foreign_certificate.scope =
            crate::AuthorityProtocolScope::Card(AuthorizationAuthorityScope {
                tenant_id: 7,
                card_id: 18,
                user_id: None,
                domain: AuthorizationDomainScope::Any,
            });
        foreign_certificate.completion_digest =
            foreign_certificate.recompute_completion_digest().unwrap();
        foreign_certificate.sign(&key).unwrap();
        assert!(CertifiedAuthorizationState::new_with_certificate(
            (*certified.proof()).clone(),
            certified.evidence(),
            foreign_certificate,
            &key.verifying_key(),
            &key.verifying_key(),
            100,
            &evidence_scope(),
        )
        .is_err());
    }
}
