//! HTTP wire envelopes for the authority control plane.
//!
//! Every request carries a caller identity whose `service_id` must equal the
//! identity derived from the authenticated TLS transport (mTLS certificate
//! fingerprint pinning); the server rejects any mismatch. Every response that
//! reports authority state carries the current [`GlobalAuthorityFrontier`]
//! and the read gate so callers can persist and enforce them separately.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::{
    authority_counter, authority_digest, authority_field, authority_signature_encoding,
    authority_text, authority_time_window, authority_timestamp, authority_verify_strict,
    AuthorityProtocolError, AuthorityProtocolScope, AuthorityReadGate,
    AuthorityScopePublicationCertificate, GlobalAuthorityFrontier, AUTHORITY_PROTOCOL_VERSION,
};
use crate::{AuthorizationFenceProof, AUTHORIZATION_EDITION};

const STARTUP_ATTESTATION_DOMAIN: &[u8] = b"ASTRAL_AUTHORITY_STARTUP_ATTESTATION_V1\0";
const DEFAULT_PROOF_TTL_SECONDS: i64 = 300;
const MAX_PROOF_TTL_SECONDS: i64 = 3_600;

/// Frozen internal HTTP paths (plural resources, kebab-case, under the frozen
/// main prefix). Shared by the service and the client library.
pub const AUTHORITY_PATH_ATTESTATION_STARTUP: &str = "/main/api/v1/authority-attestations/startup";
pub const AUTHORITY_PATH_FENCE_CURRENT: &str = "/main/api/v1/authority-fences/current";
pub const AUTHORITY_PATH_SOURCE_INTENTS: &str = "/main/api/v1/authority-source-intents";
pub const AUTHORITY_PATH_SOURCE_COMMITS: &str = "/main/api/v1/authority-source-commits";
pub const AUTHORITY_PATH_PUBLICATION_CERTIFICATIONS: &str =
    "/main/api/v1/authority-publication-certifications";
pub const AUTHORITY_PATH_RESERVATION_RECONCILE: &str =
    "/main/api/v1/authority-reservations/reconcile";
pub const AUTHORITY_PATH_RESERVATION_CLOSE: &str = "/main/api/v1/authority-reservations/close";
// The eligibility-completions path lives in `eligibility_completion` next to
// its contract (glob-re-exported from the module root like every other path).

/// Authenticated caller identity. Bound to the mTLS transport identity by the
/// service; a body identity that differs from the transport identity fails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityCallerIdentity {
    pub service_id: String,
    pub request_nonce: String,
    pub issued_at: i64,
}

impl AuthorityCallerIdentity {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        authority_text(&self.service_id, "service_id")?;
        authority_text(&self.request_nonce, "request_nonce")?;
        authority_timestamp(self.issued_at, "issued_at")?;
        Ok(())
    }
}

/// Startup attestation: what a caller verifies before trusting the endpoint.
///
/// The attestation binds the protocol version, edition, current frontier and
/// the full public trust root under a fresh nonce and signature, so callers
/// pinning the genesis trust-root digest out-of-band can authenticate the
/// service before sending any mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityStartupAttestation {
    pub protocol_version: u16,
    pub authorization_edition: u16,
    pub authority_id: String,
    pub global_frontier: GlobalAuthorityFrontier,
    /// The ACTIVE trust root after all applied rotations.
    pub trust_root: super::AuthorityTrustRoot,
    /// The GENESIS trust root itself. Callers recompute its digest against
    /// their out-of-band pin; a copied digest string is never trusted.
    pub genesis_trust_root: super::AuthorityTrustRoot,
    /// The full rotation chain from genesis to the active root.
    pub rotations: Vec<super::AuthorityKeyRotationCertificate>,
    pub leader: bool,
    pub attestation_nonce: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub attestation_key_id: String,
    /// Lowercase hex Ed25519 signature by the authority signer.
    pub signature: String,
}

impl AuthorityStartupAttestation {
    /// Validate everything except the signature encoding; used on the
    /// unsigned signing path.
    pub fn validate_unsigned(&self) -> Result<(), AuthorityProtocolError> {
        if self.protocol_version != AUTHORITY_PROTOCOL_VERSION
            || self.authorization_edition != AUTHORIZATION_EDITION
        {
            return Err(AuthorityProtocolError::WrongEdition);
        }
        authority_text(&self.authority_id, "authority_id")?;
        self.global_frontier.validate()?;
        self.global_frontier.matches_trust_root(&self.trust_root)?;
        self.genesis_trust_root.validate()?;
        for rotation in &self.rotations {
            rotation.validate()?;
        }
        authority_text(&self.attestation_nonce, "attestation_nonce")?;
        authority_timestamp(self.issued_at, "issued_at")?;
        authority_time_window(self.issued_at, self.issued_at, self.expires_at)?;
        authority_text(&self.attestation_key_id, "attestation_key_id")?;
        Ok(())
    }

    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.validate_unsigned()?;
        authority_signature_encoding(&self.signature)
    }

    /// Full chain verification anchored at the caller's recomputed pin:
    ///
    /// 1. the genesis root digest must equal the out-of-band pin,
    /// 2. every rotation must verify under the previous root's ROOT key and
    ///    continue the digest chain exactly,
    /// 3. the derived active root must equal the attested active root,
    /// 4. the attestation signature must verify under the derived active
    ///    root's SIGNER key at `now_seconds`.
    ///
    /// A self-signed attestation with a copied pin string cannot pass: the
    /// pin is recomputed from the genesis root carried in the attestation,
    /// and the chain must reach that root from the pinned genesis.
    pub fn verify_chain_at(
        &self,
        pinned_genesis_digest: &str,
        now_seconds: i64,
    ) -> Result<(), AuthorityProtocolError> {
        self.validate_at_unsigned(now_seconds)?;
        let genesis_digest = self.genesis_trust_root.digest()?;
        if genesis_digest != pinned_genesis_digest {
            return Err(AuthorityProtocolError::TrustRootMismatch);
        }
        let mut active = self.genesis_trust_root.clone();
        for rotation in &self.rotations {
            let root_key = active.root_key()?.verifying_key()?;
            active = rotation.verify_after(&active, &root_key)?;
        }
        if active != self.trust_root {
            return Err(AuthorityProtocolError::TrustRootMismatch);
        }
        let signer_key = active.signer_key()?.verifying_key()?;
        self.verify_at(&signer_key, now_seconds)
    }

    /// Unsigned time-window check shared with the signing path.
    fn validate_at_unsigned(&self, now_seconds: i64) -> Result<(), AuthorityProtocolError> {
        self.validate_unsigned()?;
        if now_seconds < self.issued_at || now_seconds >= self.expires_at {
            return Err(AuthorityProtocolError::NotCurrentlyValid);
        }
        Ok(())
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, AuthorityProtocolError> {
        self.validate_unsigned()?;
        let frontier_bytes = serde_json::to_vec(&self.global_frontier)
            .map_err(|_| AuthorityProtocolError::CanonicalSerialization)?;
        let trust_root_bytes = serde_json::to_vec(&self.trust_root)
            .map_err(|_| AuthorityProtocolError::CanonicalSerialization)?;
        let genesis_root_bytes = serde_json::to_vec(&self.genesis_trust_root)
            .map_err(|_| AuthorityProtocolError::CanonicalSerialization)?;
        let rotations_bytes = serde_json::to_vec(&self.rotations)
            .map_err(|_| AuthorityProtocolError::CanonicalSerialization)?;
        let mut bytes = Vec::with_capacity(
            512 + frontier_bytes.len()
                + trust_root_bytes.len()
                + genesis_root_bytes.len()
                + rotations_bytes.len(),
        );
        bytes.extend_from_slice(STARTUP_ATTESTATION_DOMAIN);
        authority_field(&mut bytes, &self.protocol_version.to_string());
        authority_field(&mut bytes, &self.authorization_edition.to_string());
        authority_field(&mut bytes, &self.authority_id);
        authority_field(&mut bytes, &frontier_bytes.len().to_string());
        bytes.extend_from_slice(&frontier_bytes);
        authority_field(&mut bytes, &trust_root_bytes.len().to_string());
        bytes.extend_from_slice(&trust_root_bytes);
        authority_field(&mut bytes, &genesis_root_bytes.len().to_string());
        bytes.extend_from_slice(&genesis_root_bytes);
        authority_field(&mut bytes, &rotations_bytes.len().to_string());
        bytes.extend_from_slice(&rotations_bytes);
        authority_field(&mut bytes, if self.leader { "1" } else { "0" });
        authority_field(&mut bytes, &self.attestation_nonce);
        authority_field(&mut bytes, &self.issued_at.to_string());
        authority_field(&mut bytes, &self.expires_at.to_string());
        authority_field(&mut bytes, &self.attestation_key_id);
        Ok(bytes)
    }

    pub fn sign_with(&mut self, signing_key: &SigningKey) -> Result<(), AuthorityProtocolError> {
        self.signature = String::new();
        self.validate_unsigned()?;
        let signature = signing_key.sign(&self.signing_bytes()?);
        self.signature = hex::encode(signature.to_bytes());
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
        self.validate_at_unsigned(now_seconds)
    }
}

/// Requested per-read proof binding.
///
/// The proof identity and its server-side receipt are minted fresh by the
/// authority; the caller supplies the exact request nonce to bind, the actor
/// scope the proof is minted for, and the immutable policy-request digest the
/// proof may later authorize. The proof's content identity comes from the
/// certified `source_scope` publication (actor scope by default), so an ORG
/// fence read can mint an actor-card proof bound to the ORG evidence hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityReadProofRequest {
    /// Actor scope minted into the proof. The existing proof contract is
    /// actor-card scoped, so this must be a card scope.
    pub actor_scope: AuthorityProtocolScope,
    /// What the caller will do with this proof: authorization-source
    /// mutations participate in the read barrier, protected-business
    /// mutations never do. Recorded on the receipt; the later intent must
    /// carry the same kind.
    pub mutation_kind: crate::AuthorityMutationKind,
    /// Certified publication scope whose snapshot/generation/watermark the
    /// proof binds. `None` binds the actor scope itself.
    pub source_scope: Option<AuthorityProtocolScope>,
    /// Caller-chosen request nonce, enforced fresh by the authority and
    /// carried verbatim in the minted proof.
    pub request_nonce: String,
    /// Stable, non-secret operation identity of the policy request this read
    /// belongs to. Signed into the proof and recorded in the receipt; the
    /// later source intent must carry the same operation id.
    pub operation_id: String,
    /// Stable event identity paired with `operation_id`; repeated reads for
    /// one operation reuse it while nonce and proof identity stay fresh.
    pub event_id: String,
    /// SHA-256 of the immutable policy request content (actor, resource,
    /// action, target). Recorded in the durable proof receipt; a source
    /// intent may only reference a proof minted for the same digest.
    pub request_binding_digest: String,
    /// Optimistic consistency binding: when supplied and not exactly current,
    /// the read fails with the current view instead of minting a proof.
    pub expected_frontier: Option<AuthorityExpectedFrontier>,
    /// Requested proof lifetime in seconds, bounded by the server policy.
    pub proof_ttl_seconds: Option<i64>,
}

impl AuthorityReadProofRequest {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        if !matches!(self.actor_scope, AuthorityProtocolScope::Card(_)) {
            return Err(AuthorityProtocolError::ScopeMismatch);
        }
        self.actor_scope.validate()?;
        if let Some(source_scope) = &self.source_scope {
            source_scope.validate()?;
        }
        authority_text(&self.request_nonce, "request_nonce")?;
        authority_text(&self.operation_id, "operation_id")?;
        authority_text(&self.event_id, "event_id")?;
        authority_digest(&self.request_binding_digest, "request_binding_digest")?;
        if let Some(expected) = &self.expected_frontier {
            expected.validate()?;
        }
        if let Some(ttl) = self.proof_ttl_seconds {
            if ttl <= 0 || ttl > MAX_PROOF_TTL_SECONDS {
                return Err(AuthorityProtocolError::InvalidTimeWindow);
            }
        }
        Ok(())
    }

    /// The scope whose certified content identity the proof binds.
    pub fn bound_scope(&self) -> &AuthorityProtocolScope {
        self.source_scope.as_ref().unwrap_or(&self.actor_scope)
    }
}

/// Exact frontier identity a reader pins for proof issuance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityExpectedFrontier {
    pub authority_term: u64,
    pub global_fence_sequence: u64,
    pub scope_generation: u64,
    pub revoke_watermark: u64,
    pub snapshot_hash: String,
}

impl AuthorityExpectedFrontier {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        authority_counter(self.authority_term, "authority_term")?;
        authority_counter(self.global_fence_sequence, "global_fence_sequence")?;
        authority_counter(self.scope_generation, "scope_generation")?;
        authority_digest(&self.snapshot_hash, "snapshot_hash")?;
        if self.revoke_watermark > self.scope_generation {
            return Err(AuthorityProtocolError::RevokeWatermarkAhead);
        }
        Ok(())
    }
}

/// Linearizable fence read. Does not advance the global frontier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityFenceReadRequest {
    pub caller: AuthorityCallerIdentity,
    /// Optional exact scope whose current certificate is requested.
    pub scope: Option<AuthorityProtocolScope>,
    /// Caller-pinned certificate identity: when supplied and the current
    /// certificate for the scope differs, the read fails with the current
    /// certificate hash instead of silently returning a newer publication.
    pub expected_certificate_hash: Option<String>,
    /// When supplied, an [`AuthorizationFenceProof`] is minted fresh for this
    /// read (card scopes only; ORG scopes are certificate-scoped).
    pub read_proof: Option<AuthorityReadProofRequest>,
}

impl AuthorityFenceReadRequest {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.caller.validate()?;
        if let Some(scope) = &self.scope {
            scope.validate()?;
        }
        if let Some(expected_certificate_hash) = &self.expected_certificate_hash {
            authority_digest(expected_certificate_hash, "expected_certificate_hash")?;
        }
        if let Some(read_proof) = &self.read_proof {
            read_proof.validate()?;
        }
        Ok(())
    }
}

/// Verified read response: frontier, gate, current certificate, fresh proof.
/// Callers persist the proof, the certificate and the frontier separately.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityFenceReadResponse {
    pub protocol_version: u16,
    pub authorization_edition: u16,
    pub global_frontier: GlobalAuthorityFrontier,
    pub read_gate: AuthorityReadGate,
    /// Current certificate for the requested scope, when a scope was given.
    pub scope_certificate: Option<AuthorityScopePublicationCertificate>,
    /// Current certificate record digest, when a scope was given.
    pub scope_certificate_hash: Option<String>,
    /// Freshly minted proof for a requested card-scope read.
    pub proof: Option<AuthorizationFenceProof>,
    pub observed_at: i64,
}

impl AuthorityFenceReadResponse {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        if self.protocol_version != AUTHORITY_PROTOCOL_VERSION
            || self.authorization_edition != AUTHORIZATION_EDITION
        {
            return Err(AuthorityProtocolError::WrongEdition);
        }
        self.global_frontier.validate()?;
        self.read_gate.validate()?;
        if let Some(certificate) = &self.scope_certificate {
            certificate.validate()?;
            if self.scope_certificate_hash.as_deref() != Some(&certificate.record_digest()?) {
                return Err(AuthorityProtocolError::DigestMismatch {
                    field: "scope_certificate_hash",
                });
            }
        }
        if let Some(proof) = &self.proof {
            proof.validate()?;
        }
        authority_timestamp(self.observed_at, "observed_at")?;
        Ok(())
    }
}

/// Prepare: accept one approved source intent and reserve its scopes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityPrepareRequest {
    pub caller: AuthorityCallerIdentity,
    pub intent: super::AuthoritySourceIntent,
}

impl AuthorityPrepareRequest {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.caller.validate()?;
        self.intent.validate()?;
        if self.intent.service_id != self.caller.service_id {
            return Err(AuthorityProtocolError::CallerIdentityMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityPrepareResponse {
    pub acceptance: super::AuthorityIntentAcceptance,
    pub reservation: super::AuthorityScopeReservation,
    pub global_frontier: GlobalAuthorityFrontier,
    pub read_gate: AuthorityReadGate,
}

impl AuthorityPrepareResponse {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.acceptance.validate()?;
        self.reservation.validate()?;
        self.global_frontier.validate()?;
        self.read_gate.validate()?;
        if self.acceptance.reservation_id != self.reservation.reservation_id
            || self.acceptance.intent_digest != self.reservation.intent_digest
            || self.reservation.intent_digest != self.reservation.intent.digest()?
            || self.reservation.state != super::AuthorityReservationState::Reserved
            || self.acceptance.authority_id != self.global_frontier.authority_id
            || self.acceptance.authority_term != self.global_frontier.authority_term
            || self.acceptance.global_fence_sequence != self.global_frontier.global_fence_sequence
            || self.acceptance.key_id != self.global_frontier.key_id
            || self.acceptance.key_epoch != self.global_frontier.key_epoch
            || self.acceptance.accepted_at != self.reservation.created_at
            || self.reservation.authority_term != self.acceptance.authority_term
            || self.reservation.fence_sequence_at_prepare.checked_add(1)
                != Some(self.acceptance.global_fence_sequence)
        {
            return Err(AuthorityProtocolError::ScopeMismatch);
        }
        Ok(())
    }
}

/// Commit: record the durable source commit against a reserved scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityCommitRequest {
    pub caller: AuthorityCallerIdentity,
    pub commit: super::AuthoritySourceCommitRecord,
    /// Registered database identity executing the source transaction; must
    /// match both the reservation's intent and the configured registration.
    pub database_id: String,
    /// Typed declared coverage from the staged-evidence envelope. `None`
    /// means the selector could not prove a complete finite set: the
    /// reservation stays operator-closed (GLOBAL) or needs no coverage
    /// (ProtectedBusiness). Never guessed, never truncated.
    pub declared_coverage: Option<super::AuthorityStagedScopeCoverage>,
}

impl AuthorityCommitRequest {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.caller.validate()?;
        self.commit.validate()?;
        authority_text(&self.database_id, "database_id")?;
        if let Some(declared_coverage) = &self.declared_coverage {
            declared_coverage.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityCommitResponse {
    pub disposition: super::AuthorityReservationDisposition,
    pub reservation: Option<super::AuthorityScopeReservation>,
    /// Exact echoed binding: request/event/proof/kind/owner/digests. The
    /// client verifies every field against its own records.
    pub binding: super::AuthorityCommitBinding,
    pub global_frontier: GlobalAuthorityFrontier,
    pub read_gate: AuthorityReadGate,
}

impl AuthorityCommitResponse {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.binding.validate()?;
        self.global_frontier.validate()?;
        self.read_gate.validate()?;
        let reservation = self
            .reservation
            .as_ref()
            .ok_or(AuthorityProtocolError::ScopeMismatch)?;
        if self.disposition != super::AuthorityReservationDisposition::from_reservation(reservation)
            || !matches!(
                reservation.state,
                super::AuthorityReservationState::Committed
                    | super::AuthorityReservationState::Published
                    | super::AuthorityReservationState::Certified
                    | super::AuthorityReservationState::Completed
                    | super::AuthorityReservationState::Quarantined
            )
        {
            return Err(AuthorityProtocolError::ScopeMismatch);
        }
        if let Some(reservation) = &self.reservation {
            reservation.validate()?;
            // The reservation must agree with the echoed binding.
            if reservation.reservation_id != self.binding.reservation_id
                || reservation.intent.operation_id != self.binding.operation_id
                || reservation.intent.event_id != self.binding.event_id
                || reservation.intent.admission_proof_id != self.binding.admission_proof_id
                || reservation.intent.mutation_kind != self.binding.mutation_kind
                || reservation.intent.service_id != self.binding.service_id
                || reservation.intent.database_id != self.binding.database_id
                || reservation.intent.request_digest != self.binding.request_digest
                || reservation
                    .intent
                    .before_image_digest
                    .as_ref()
                    .is_some_and(|digest| self.binding.before_image_digest.as_ref() != Some(digest))
                || reservation.source_commit_digest.as_deref()
                    != Some(self.binding.source_commit_digest.as_str())
                || reservation.after_image_digest.as_deref()
                    != Some(self.binding.after_image_digest.as_str())
                || reservation.source_outcome_digest.as_deref()
                    != Some(self.binding.source_outcome_digest.as_str())
            {
                return Err(AuthorityProtocolError::ScopeMismatch);
            }
        }
        Ok(())
    }
}

/// Certify: issue the signed scope publication certificate (and a fresh card
/// proof when the scope is a card scope) for a committed reservation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityCertifyRequest {
    pub caller: AuthorityCallerIdentity,
    pub reservation_id: String,
    /// The scope being published. With EXACT reservation coverage this scope
    /// must be covered by the reservation; GLOBAL coverage permits any scope.
    pub scope: AuthorityProtocolScope,
    /// Actual before-image digest pinned by the source transaction (exact
    /// read of the affected pre-state rows). Two-phase binding: when the
    /// intent carried a before-image digest it must match exactly.
    pub before_image_digest: Option<String>,
    pub after_image_digest: String,
    /// Certified content identity of the published scope evidence
    /// (card evidence content hash, or ORG publication/member frontier hash).
    pub snapshot_hash: String,
    /// Canonical digest of the durable source-outcome record committed in the
    /// same source transaction; signed into the certificate as the exact
    /// evidence pointer.
    pub source_outcome_digest: String,
    pub manifests: Vec<super::AuthorityManifestIdentity>,
    /// Caller-submitted completion digest; the authority recomputes and signs
    /// only when both agree.
    pub completion_digest: String,
}

impl AuthorityCertifyRequest {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.caller.validate()?;
        authority_text(&self.reservation_id, "reservation_id")?;
        self.scope.validate()?;
        if let Some(before_image_digest) = &self.before_image_digest {
            authority_digest(before_image_digest, "before_image_digest")?;
        }
        authority_digest(&self.after_image_digest, "after_image_digest")?;
        authority_digest(&self.snapshot_hash, "snapshot_hash")?;
        authority_digest(&self.source_outcome_digest, "source_outcome_digest")?;
        authority_digest(&self.completion_digest, "completion_digest")?;
        authority_digest(&self.source_outcome_digest, "source_outcome_digest")?;
        if self.manifests.is_empty() || self.manifests.len() > 4096 {
            return Err(AuthorityProtocolError::InvalidText { field: "manifests" });
        }
        let mut aggregates = std::collections::BTreeSet::new();
        for manifest in &self.manifests {
            manifest.validate()?;
            if !aggregates.insert((&manifest.aggregate_type, manifest.aggregate_id)) {
                return Err(AuthorityProtocolError::InvalidText { field: "manifests" });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityCertifyResponse {
    pub certificate: AuthorityScopePublicationCertificate,
    /// Fresh card-scope proof minted in the same quorum step (card scopes only).
    pub proof: Option<AuthorizationFenceProof>,
    /// The reservation AFTER this certification: callers observe automatic
    /// EXACT closure (state Certified) and per-scope progress.
    pub reservation: super::AuthorityScopeReservation,
    pub global_frontier: GlobalAuthorityFrontier,
    pub read_gate: AuthorityReadGate,
}

impl AuthorityCertifyResponse {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.certificate.validate()?;
        self.reservation.validate()?;
        self.global_frontier.validate()?;
        self.read_gate.validate()?;
        self.certificate.verify_completion_digest()?;
        let certificate = &self.certificate;
        let reservation = &self.reservation;
        if !matches!(
            reservation.state,
            super::AuthorityReservationState::Published
                | super::AuthorityReservationState::Certified
        ) || reservation.intent.mutation_kind
            != super::AuthorityMutationKind::AuthorizationSource
            || reservation.reservation_id != certificate.reservation_id
            || reservation.intent_digest != certificate.intent_digest
            || reservation.intent.operation_id != certificate.operation_id
            || reservation.intent.event_id != certificate.event_id
            || reservation.intent.request_digest != certificate.approved_request_digest
            || reservation.source_commit_digest.as_deref()
                != Some(certificate.source_commit_digest.as_str())
            || reservation.after_image_digest.as_deref()
                != Some(certificate.after_image_digest.as_str())
            || reservation.source_outcome_digest.as_deref()
                != Some(certificate.source_outcome_digest.as_str())
            || reservation
                .intent
                .before_image_digest
                .as_ref()
                .is_some_and(|before| certificate.before_image_digest.as_ref() != Some(before))
            || reservation.authority_term != certificate.authority_term
            || reservation.fence_sequence_at_prepare != certificate.global_fence_sequence
            || !reservation
                .certified_scopes
                .contains(&certificate.scope.store_key_text()?)
            || certificate.authority_id != self.global_frontier.authority_id
            || certificate.authority_term > self.global_frontier.authority_term
            || certificate.global_fence_sequence > self.global_frontier.global_fence_sequence
        {
            return Err(AuthorityProtocolError::ScopeMismatch);
        }
        if let Some(proof) = &self.proof {
            proof.validate()?;
            let AuthorityProtocolScope::Card(scope) = &certificate.scope else {
                return Err(AuthorityProtocolError::ScopeMismatch);
            };
            if &proof.scope != scope
                || proof.authority_id != self.global_frontier.authority_id
                || proof.authority_term != self.global_frontier.authority_term
                || proof.global_fence_sequence != self.global_frontier.global_fence_sequence
                || proof.key_id != self.global_frontier.key_id
                || proof.key_epoch != self.global_frontier.key_epoch
                || proof.snapshot_hash != certificate.snapshot_hash
                || proof.scope_generation
                    != certificate
                        .manifests
                        .iter()
                        .map(|manifest| manifest.generation)
                        .max()
                        .unwrap_or(0)
                || proof.revoke_watermark
                    != certificate
                        .manifests
                        .iter()
                        .map(|manifest| manifest.revoke_fence)
                        .max()
                        .unwrap_or(0)
                || proof.operation_id != certificate.operation_id
                || proof.event_id != certificate.event_id
                || proof.request_binding_digest.as_deref()
                    != Some(certificate.approved_request_digest.as_str())
                || proof.scope_certificate_hash.as_deref()
                    != Some(certificate.record_digest()?.as_str())
            {
                return Err(AuthorityProtocolError::ScopeMismatch);
            }
        }
        Ok(())
    }
}

/// Reconcile one stable reservation identity. Never mutates; never retries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityReconcileRequest {
    pub caller: AuthorityCallerIdentity,
    pub reservation_id: String,
    pub operation_id: String,
}

impl AuthorityReconcileRequest {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.caller.validate()?;
        authority_text(&self.reservation_id, "reservation_id")?;
        authority_text(&self.operation_id, "operation_id")?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityReconcileResponse {
    pub reconciliation: super::AuthorityReconciliation,
    pub commit_binding: Option<super::AuthorityCommitBinding>,
    /// Immutable certificates indexed by this reservation, including scopes
    /// whose current pointer has since advanced. Never substitutes for a fresh read.
    pub certified_publications: Vec<AuthorityScopePublicationCertificate>,
    pub global_frontier: GlobalAuthorityFrontier,
    pub read_gate: AuthorityReadGate,
}

impl AuthorityReconcileResponse {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.reconciliation.validate()?;
        self.global_frontier.validate()?;
        self.read_gate.validate()?;
        let committed = matches!(
            self.reconciliation.disposition,
            super::AuthorityReservationDisposition::Committed
                | super::AuthorityReservationDisposition::Published
                | super::AuthorityReservationDisposition::Certified
                | super::AuthorityReservationDisposition::Completed
        );
        let quarantined =
            self.reconciliation.disposition == super::AuthorityReservationDisposition::Quarantined;
        match (&self.commit_binding, &self.reconciliation.reservation) {
            (Some(binding), Some(reservation)) if committed || quarantined => {
                AuthorityCommitResponse {
                    disposition: self.reconciliation.disposition,
                    reservation: Some(reservation.clone()),
                    binding: binding.clone(),
                    global_frontier: self.global_frontier.clone(),
                    read_gate: self.read_gate.clone(),
                }
                .validate()?;
            }
            (None, _) if !committed => {}
            _ => return Err(AuthorityProtocolError::ScopeMismatch),
        }
        let mut scopes = std::collections::BTreeSet::new();
        for certificate in &self.certified_publications {
            certificate.validate()?;
            certificate.verify_completion_digest()?;
            let reservation = self
                .reconciliation
                .reservation
                .as_ref()
                .ok_or(AuthorityProtocolError::ScopeMismatch)?;
            let binding = self
                .commit_binding
                .as_ref()
                .ok_or(AuthorityProtocolError::ScopeMismatch)?;
            let key = certificate.scope.store_key_text()?;
            if !scopes.insert(key.clone())
                || !reservation.certified_scopes.contains(&key)
                || certificate.authority_id != self.global_frontier.authority_id
                || certificate.authority_term != reservation.authority_term
                || certificate.global_fence_sequence != reservation.fence_sequence_at_prepare
                || certificate.authority_term > self.global_frontier.authority_term
                || certificate.global_fence_sequence > self.global_frontier.global_fence_sequence
                || certificate.reservation_id != reservation.reservation_id
                || certificate.intent_digest != reservation.intent_digest
                || certificate.operation_id != binding.operation_id
                || certificate.event_id != binding.event_id
                || certificate.approved_request_digest != binding.request_digest
                || certificate.before_image_digest != binding.before_image_digest
                || certificate.after_image_digest != binding.after_image_digest
                || certificate.source_commit_digest != binding.source_commit_digest
                || certificate.source_outcome_digest != binding.source_outcome_digest
            {
                return Err(AuthorityProtocolError::ScopeMismatch);
            }
        }
        if self
            .reconciliation
            .reservation
            .as_ref()
            .is_some_and(|reservation| reservation.certified_scopes.len() != scopes.len())
        {
            return Err(AuthorityProtocolError::ScopeMismatch);
        }
        // A Certified EXACT reservation must index exactly its full declared
        // scope set: the terminal state may never outrun the served
        // publication history. A Certified GLOBAL reservation serves exactly
        // the history it indexes — completeness beyond that set is the
        // operator close's assertion and is verified service-side against
        // the recorded declared coverage, never fabricated here.
        if let Some(reservation) = &self.reconciliation.reservation {
            if reservation.state == super::AuthorityReservationState::Certified {
                if let super::AuthorityReservationCoverage::Exact(declared) =
                    &reservation.intent.coverage
                {
                    let declared_keys: Result<std::collections::BTreeSet<String>, _> = declared
                        .iter()
                        .map(|scope| scope.store_key_text())
                        .collect();
                    let certified_keys: std::collections::BTreeSet<&str> = reservation
                        .certified_scopes
                        .iter()
                        .map(String::as_str)
                        .collect();
                    if declared_keys.map_or(true, |declared| {
                        declared
                            .iter()
                            .map(String::as_str)
                            .collect::<std::collections::BTreeSet<&str>>()
                            != certified_keys
                    }) {
                        return Err(AuthorityProtocolError::ScopeMismatch);
                    }
                }
            }
        }
        Ok(())
    }
}

/// Operator-authorized close of one PUBLISHED (GLOBAL) reservation.
///
/// Certification under GLOBAL coverage leaves the conservative barrier UP;
/// only an identity registered with the `close` operation (an operator, never
/// the committing source) may clear it, because the source cannot assert the
/// affected scope set of a global reservation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityCloseReservationRequest {
    pub caller: AuthorityCallerIdentity,
    pub reservation_id: String,
    pub operation_id: String,
    pub reason: String,
}

impl AuthorityCloseReservationRequest {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.caller.validate()?;
        authority_text(&self.reservation_id, "reservation_id")?;
        authority_text(&self.operation_id, "operation_id")?;
        // The close reason is an operator audit note: trimmed, bounded, and
        // free of control characters, but human-readable spaces are allowed.
        let reason = self.reason.trim();
        if reason.is_empty()
            || reason.len() > 256
            || reason.chars().any(|character| character.is_control())
        {
            return Err(AuthorityProtocolError::InvalidText { field: "reason" });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityCloseReservationResponse {
    pub reservation: super::AuthorityScopeReservation,
    pub global_frontier: GlobalAuthorityFrontier,
    pub read_gate: AuthorityReadGate,
}

impl AuthorityCloseReservationResponse {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.reservation.validate()?;
        self.global_frontier.validate()?;
        self.read_gate.validate()?;
        // A close response is the terminal receipt of one operator-authorized
        // completion: the reservation must be the terminally certified GLOBAL
        // reservation this operator closed, carrying its certificate identity
        // and a non-empty actual publication history. No field claims a
        // completeness the operator did not prove — the full reconcile
        // response remains the audit basis.
        if self.reservation.state != super::AuthorityReservationState::Certified
            || !self.reservation.intent.coverage.is_global()
            || self.reservation.certificate_id.is_none()
            || self.reservation.certified_scopes.is_empty()
        {
            return Err(AuthorityProtocolError::ScopeMismatch);
        }
        Ok(())
    }
}

/// Transport-level error body. `leader_hint` lets callers route mutations to
/// the leader without the protocol ever retrying automatically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityWireError {
    pub code: AuthorityWireErrorCode,
    pub message: String,
    pub leader_hint: Option<String>,
    pub current_frontier: Option<GlobalAuthorityFrontier>,
    pub current_certificate_hash: Option<String>,
    pub reservation_id: Option<String>,
}

impl AuthorityWireError {
    pub fn from_protocol(error: &AuthorityProtocolError) -> Self {
        let (code, reservation_id) = match error {
            AuthorityProtocolError::WrongEdition => (AuthorityWireErrorCode::EditionMismatch, None),
            AuthorityProtocolError::ReadsBlocked { reservation_id } => (
                AuthorityWireErrorCode::ReadsBlocked,
                Some(reservation_id.clone()),
            ),
            AuthorityProtocolError::LeaseExpired => (AuthorityWireErrorCode::LeaseExpired, None),
            AuthorityProtocolError::NotLeader => (AuthorityWireErrorCode::NotLeader, None),
            AuthorityProtocolError::UnknownOutcome { operation_hint } => (
                AuthorityWireErrorCode::UnknownOutcome,
                Some(operation_hint.clone()),
            ),
            AuthorityProtocolError::QuorumUnavailable => {
                (AuthorityWireErrorCode::QuorumUnavailable, None)
            }
            AuthorityProtocolError::NotFound { .. } => (AuthorityWireErrorCode::NotFound, None),
            AuthorityProtocolError::AlreadyExists { .. } => {
                (AuthorityWireErrorCode::AlreadyExists, None)
            }
            AuthorityProtocolError::StateConflict { .. } => {
                (AuthorityWireErrorCode::StateConflict, None)
            }
            AuthorityProtocolError::CallerIdentityMismatch => {
                (AuthorityWireErrorCode::CallerIdentityMismatch, None)
            }
            AuthorityProtocolError::FrontierDiverged => {
                (AuthorityWireErrorCode::FrontierDiverged, None)
            }
            AuthorityProtocolError::TrustRootMismatch => {
                (AuthorityWireErrorCode::TrustRootMismatch, None)
            }
            _ => (AuthorityWireErrorCode::Rejected, None),
        };
        Self {
            code,
            message: error.to_string(),
            leader_hint: None,
            current_frontier: None,
            current_certificate_hash: None,
            reservation_id,
        }
    }
}

/// Closed wire error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityWireErrorCode {
    Rejected,
    EditionMismatch,
    ReadsBlocked,
    LeaseExpired,
    NotLeader,
    UnknownOutcome,
    QuorumUnavailable,
    NotFound,
    AlreadyExists,
    StateConflict,
    CallerIdentityMismatch,
    FrontierDiverged,
    TrustRootMismatch,
    Internal,
}

/// Default proof window policy constant exposed for configuration parity.
pub const AUTHORITY_DEFAULT_PROOF_TTL_SECONDS: i64 = DEFAULT_PROOF_TTL_SECONDS;
/// Upper bound for a requested proof lifetime.
pub const AUTHORITY_MAX_PROOF_TTL_SECONDS: i64 = MAX_PROOF_TTL_SECONDS;

#[cfg(test)]
mod tests {
    use super::*;

    use crate::authority_protocol::AuthorityOrgScope;
    fn caller() -> AuthorityCallerIdentity {
        AuthorityCallerIdentity {
            service_id: "astral-db-primary".to_owned(),
            request_nonce: "request-nonce-1".to_owned(),
            issued_at: 1_700,
        }
    }

    #[test]
    fn attestation_signature_binds_frontier_and_trust_root() {
        let signing = SigningKey::from_bytes(&[6; 32]);
        let mut attestation = AuthorityStartupAttestation {
            protocol_version: AUTHORITY_PROTOCOL_VERSION,
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: "authority-1".to_owned(),
            global_frontier: GlobalAuthorityFrontier {
                authorization_edition: AUTHORIZATION_EDITION,
                authority_id: "authority-1".to_owned(),
                authority_term: 1,
                global_fence_sequence: 2,
                key_id: "signer-1".to_owned(),
                key_epoch: 1,
                root_id: "root-1".to_owned(),
                trust_root_digest: "aa".repeat(32),
                global_chain_digest: "bb".repeat(32),
                updated_at: 1_600,
            },
            genesis_trust_root: crate::authority_protocol::AuthorityTrustRoot {
                root_id: "root-1".to_owned(),
                keys: Vec::new(),
                created_at: 1_000,
            },
            rotations: Vec::new(),
            trust_root: crate::authority_protocol::AuthorityTrustRoot {
                root_id: "root-1".to_owned(),
                keys: Vec::new(),
                created_at: 1_000,
            },
            leader: true,
            attestation_nonce: "attest-nonce-1".to_owned(),
            issued_at: 1_700,
            expires_at: 2_000,
            attestation_key_id: "signer-1".to_owned(),
            signature: String::new(),
        };
        // Invalid trust root (no keys) must fail before signing.
        assert!(attestation.sign_with(&signing).is_err());

        let keys = vec![
            crate::authority_protocol::AuthorityRootKey {
                key_id: "signer-1".to_owned(),
                key_epoch: 1,
                role: crate::authority_protocol::AuthorityRootKeyRole::Signer,
                verifying_key_hex: hex::encode(signing.verifying_key().as_bytes()),
            },
            crate::authority_protocol::AuthorityRootKey {
                key_id: "root-1".to_owned(),
                key_epoch: 1,
                role: crate::authority_protocol::AuthorityRootKeyRole::Root,
                verifying_key_hex: hex::encode([2u8; 32]),
            },
            crate::authority_protocol::AuthorityRootKey {
                key_id: "genesis-1".to_owned(),
                key_epoch: 1,
                role: crate::authority_protocol::AuthorityRootKeyRole::Genesis,
                verifying_key_hex: hex::encode([3u8; 32]),
            },
        ];
        // Genesis root and active root are the same root before any rotation.
        attestation.trust_root.keys = keys.clone();
        attestation.genesis_trust_root.keys = keys;
        // Frontier digest fields are dummy values here; matches_trust_root
        // requires exact digests, so signature test uses direct bytes path.
        attestation.global_frontier.trust_root_digest = attestation.trust_root.digest().unwrap();
        attestation.sign_with(&signing).unwrap();
        attestation.verify(&signing.verifying_key()).unwrap();

        // Chain verification anchored at the recomputed pin passes for the
        // honest attestation (genesis root == active root, no rotations).
        let pin = attestation.genesis_trust_root.digest().unwrap();
        attestation.verify_chain_at(&pin, 1_700).unwrap();

        // Forgery: a copied pin string with a different genesis root fails.
        let mut forged = attestation.clone();
        forged.genesis_trust_root.root_id = "attacker-root".to_owned();
        assert!(matches!(
            forged.verify_chain_at(&pin, 1_700),
            Err(AuthorityProtocolError::TrustRootMismatch)
        ));

        let mut tampered = attestation.clone();
        tampered.leader = false;
        assert!(matches!(
            tampered.verify(&signing.verifying_key()),
            Err(AuthorityProtocolError::InvalidSignature)
        ));

        // Forgery: expired attestation fails the chain path.
        assert!(matches!(
            attestation.verify_chain_at(&pin, 9_999),
            Err(AuthorityProtocolError::NotCurrentlyValid)
        ));
    }

    #[test]
    fn fence_read_request_rejects_org_read_proofs_and_mismatched_callers() {
        let org_request = AuthorityFenceReadRequest {
            caller: caller(),
            scope: Some(AuthorityProtocolScope::Org(AuthorityOrgScope {
                tenant_id: 7,
                root_tenant_id: None,
                member: crate::authority_protocol::AuthorityOrgMemberSubject {
                    user_id: 1,
                    identity_card_id: 2,
                    card_id: 3,
                },
            })),
            expected_certificate_hash: Some("aa".repeat(32)),
            read_proof: Some(AuthorityReadProofRequest {
                actor_scope: AuthorityProtocolScope::Org(AuthorityOrgScope {
                    tenant_id: 7,
                    root_tenant_id: None,
                    member: crate::authority_protocol::AuthorityOrgMemberSubject {
                        user_id: 1,
                        identity_card_id: 2,
                        card_id: 3,
                    },
                }),
                mutation_kind:
                    crate::authority_protocol::AuthorityMutationKind::AuthorizationSource,
                operation_id: "operation-1".to_owned(),
                event_id: "event-1".to_owned(),
                source_scope: None,
                request_nonce: "request-nonce-2".to_owned(),
                request_binding_digest: "bb".repeat(32),
                expected_frontier: None,
                proof_ttl_seconds: None,
            }),
        };
        assert!(matches!(
            org_request.validate(),
            Err(AuthorityProtocolError::ScopeMismatch)
        ));

        let prepare = AuthorityPrepareRequest {
            caller: caller(),
            intent: crate::authority_protocol::AuthoritySourceIntent {
                authorization_edition: AUTHORIZATION_EDITION,
                mutation_kind:
                    crate::authority_protocol::AuthorityMutationKind::AuthorizationSource,
                operation_id: "operation-1".to_owned(),
                event_id: "event-1".to_owned(),
                admission_proof_id: "proof-1".to_owned(),
                request_digest: "ab".repeat(32),
                service_id: "astral-db-other".to_owned(),
                database_id: "db-1".to_owned(),
                coverage: crate::authority_protocol::AuthorityReservationCoverage::Global,
                before_image_digest: None,
                lease_not_before: 1_000,
                lease_expires_at: 2_000,
                intent_nonce: "intent-nonce-1".to_owned(),
            },
        };
        assert!(matches!(
            prepare.validate(),
            Err(AuthorityProtocolError::CallerIdentityMismatch)
        ));
    }

    #[test]
    fn prepare_response_binds_acceptance_to_intent_and_both_frontiers() {
        let intent = super::super::AuthoritySourceIntent {
            authorization_edition: AUTHORIZATION_EDITION,
            mutation_kind: super::super::AuthorityMutationKind::AuthorizationSource,
            operation_id: "operation-1".into(),
            event_id: "event-1".into(),
            admission_proof_id: "proof-1".into(),
            request_digest: "ab".repeat(32),
            service_id: "astral-db-primary".into(),
            database_id: "db-1".into(),
            coverage: super::super::AuthorityReservationCoverage::Global,
            before_image_digest: None,
            lease_not_before: 1_000,
            lease_expires_at: 2_000,
            intent_nonce: "intent-1".into(),
        };
        let digest = intent.digest().unwrap();
        let reservation = super::super::AuthorityScopeReservation {
            reservation_id: "reservation-1".into(),
            intent_digest: digest.clone(),
            intent,
            state: super::super::AuthorityReservationState::Reserved,
            authority_term: 1,
            fence_sequence_at_prepare: 4,
            created_at: 1_700,
            updated_at: 1_700,
            committed_at: None,
            source_commit_digest: None,
            after_image_digest: None,
            certificate_id: None,
            certified_scopes: Vec::new(),
            source_outcome_digest: None,
        };
        let response = AuthorityPrepareResponse {
            acceptance: super::super::AuthorityIntentAcceptance {
                authorization_edition: AUTHORIZATION_EDITION,
                authority_id: "authority-1".into(),
                intent_digest: digest,
                reservation_id: reservation.reservation_id.clone(),
                authority_term: 1,
                global_fence_sequence: 5,
                key_id: "signer-1".into(),
                key_epoch: 1,
                accepted_at: 1_700,
                acceptance_nonce: "acceptance-1".into(),
                signature: "00".repeat(64),
            },
            reservation,
            global_frontier: GlobalAuthorityFrontier {
                authorization_edition: AUTHORIZATION_EDITION,
                authority_id: "authority-1".into(),
                authority_term: 1,
                global_fence_sequence: 5,
                key_id: "signer-1".into(),
                key_epoch: 1,
                root_id: "root-1".into(),
                trust_root_digest: "aa".repeat(32),
                global_chain_digest: "bb".repeat(32),
                updated_at: 1_700,
            },
            read_gate: AuthorityReadGate::blocked(),
        };
        response.validate().unwrap();
        let mutations: &[fn(&mut AuthorityPrepareResponse)] = &[
            |value| value.acceptance.authority_id = "other-authority".into(),
            |value| value.acceptance.authority_term += 1,
            |value| value.acceptance.global_fence_sequence += 1,
            |value| value.acceptance.key_id = "other-signer".into(),
            |value| value.acceptance.key_epoch += 1,
            |value| value.acceptance.accepted_at += 1,
            |value| value.reservation.fence_sequence_at_prepare += 1,
            |value| value.reservation.intent.request_digest = "ee".repeat(32),
            |value| value.reservation.state = super::super::AuthorityReservationState::Aborted,
        ];
        for mutate in mutations {
            let mut changed = response.clone();
            mutate(&mut changed);
            assert!(changed.validate().is_err());
        }
    }

    #[test]
    fn wire_error_maps_protocol_cases() {
        let blocked = AuthorityWireError::from_protocol(&AuthorityProtocolError::ReadsBlocked {
            reservation_id: "reservation-1".to_owned(),
        });
        assert_eq!(blocked.code, AuthorityWireErrorCode::ReadsBlocked);
        assert_eq!(blocked.reservation_id.as_deref(), Some("reservation-1"));
        let unknown = AuthorityWireError::from_protocol(&AuthorityProtocolError::UnknownOutcome {
            operation_hint: "reservation-1".to_owned(),
        });
        assert_eq!(unknown.code, AuthorityWireErrorCode::UnknownOutcome);
    }
}
