//! Signed bootstrap (genesis scope publication) preflight artifact.
//!
//! The V7 genesis scope publication is an explicit, root-signed preflight
//! artifact ([`AuthorityBootstrapArtifact`]): the operator compiles the full
//! finite set of scope snapshots offline, the fixed trust root signs the exact
//! artifact, and the authority installs it as first certificates. The
//! bootstrap never depends on ordinary admission (no F0/F1 proof, no
//! reservation), never auto-trusts an empty or current database, and never
//! signs arbitrary database contents — the root approves every snapshot and
//! every manifest identity up front, and the artifact digest pins them.
//!
//! Provenance rules honored here and by the installer:
//! - Bootstrap certificates are not ordinary source publications. Their
//!   `intent_digest` is the artifact digest, their `reservation_id` is
//!   `bootstrap-<artifact digest>`, and the provenance helper digests below
//!   make the bootstrap operation and artifact identity recomputable from the
//!   certificate itself. No source-commit fact is fabricated.
//! - Signature verification always resolves the ROOT-role verifying key from
//!   the attested durable registry (trust root carried by the verified
//!   genesis/rotation chain). Callers can never pass a verifying key.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::{
    authority_counter, authority_digest, authority_field, authority_signature_encoding,
    authority_text, authority_time_window, authority_timestamp, authority_verify_strict,
    AuthorityManifestIdentity, AuthorityProtocolError, AuthorityProtocolScope,
};
use crate::{AuthorizationDomainScope, AUTHORIZATION_EDITION};

/// Domain separation of the bootstrap artifact signature.
const BOOTSTRAP_ARTIFACT_DOMAIN: &[u8] = b"ASTRAL_AUTHORITY_BOOTSTRAP_ARTIFACT_V1\0";
/// Domain separation of the artifact digest (over the signing bytes).
const BOOTSTRAP_ARTIFACT_DIGEST_DOMAIN: &[u8] = b"ASTRAL_AUTHORITY_BOOTSTRAP_ARTIFACT_DIGEST_V1\0";
/// Domain separation of one bootstrap scope snapshot inside the artifact.
const BOOTSTRAP_SCOPE_SNAPSHOT_DOMAIN: &[u8] = b"ASTRAL_AUTHORITY_BOOTSTRAP_SCOPE_SNAPSHOT_V1\0";
/// Domain separation of the per-scope root-approval digest.
const BOOTSTRAP_SCOPE_APPROVAL_DOMAIN: &[u8] = b"ASTRAL_AUTHORITY_BOOTSTRAP_SCOPE_APPROVAL_V1\0";
/// Domain separation of the bootstrap commit-provenance digest. Bootstrap
/// issues NO source commit; a bootstrap certificate's `source_commit_digest`
/// carries this recomputable provenance identity instead.
const BOOTSTRAP_COMMIT_PROVENANCE_DOMAIN: &[u8] =
    b"ASTRAL_AUTHORITY_BOOTSTRAP_COMMIT_PROVENANCE_V1\0";
/// Domain separation of the bootstrap outcome-provenance digest (no source
/// outcome row exists; the certificate carries this identity instead).
const BOOTSTRAP_OUTCOME_PROVENANCE_DOMAIN: &[u8] =
    b"ASTRAL_AUTHORITY_BOOTSTRAP_OUTCOME_PROVENANCE_V1\0";
/// Domain separation of the chain mutation digest of one bootstrap install.
const BOOTSTRAP_MUTATION_DIGEST_DOMAIN: &[u8] = b"ASTRAL_AUTHORITY_BOOTSTRAP_MUTATION_DIGEST_V1\0";

/// Hard cap on snapshots per artifact; the byte bound below is the primary
/// limit and this cap keeps canonical encoding and validation linear.
pub const BOOTSTRAP_MAX_SNAPSHOTS: usize = 4096;
/// Per-snapshot manifest cap; mirrors the publication-certificate contract
/// bound so a bootstrap certificate built from a snapshot always validates.
const MAX_SNAPSHOT_MANIFEST_IDENTITIES: usize = 4096;

/// One root-approved scope snapshot inside the bootstrap artifact.
///
/// The snapshot is complete: the exact protocol scope, the certified content
/// identity (`snapshot_hash`), the publication frontier (generation and
/// revoke watermark), and the full manifest identity vector. Card scopes must
/// be canonical (`user_id: None`, `domain: ANY`) so the trust anchor cannot
/// carry scope aliases; ORG scopes are their own typed scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityBootstrapScopeSnapshot {
    pub scope: AuthorityProtocolScope,
    /// Certified content identity of the published scope evidence.
    pub snapshot_hash: String,
    /// Publication generation; must equal the manifest frontier maximum.
    pub generation: u64,
    /// Revoke watermark; must equal the manifest frontier maximum.
    pub revoke_watermark: u64,
    /// Full manifest identity vector approved by the root. Never empty.
    pub manifests: Vec<AuthorityManifestIdentity>,
}

impl AuthorityBootstrapScopeSnapshot {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.scope.validate()?;
        authority_digest(&self.snapshot_hash, "snapshot_hash")?;
        authority_counter(self.generation, "generation")?;
        if self.revoke_watermark > self.generation {
            return Err(AuthorityProtocolError::RevokeWatermarkAhead);
        }
        // Card scopes in the trust anchor are canonical only: the optional
        // user claim is absent and the domain is the ANY domain.
        if let AuthorityProtocolScope::Card(card) = &self.scope {
            if card.user_id.is_some() || card.domain != AuthorizationDomainScope::Any {
                return Err(AuthorityProtocolError::InvalidText {
                    field: "card_scope",
                });
            }
        }
        if self.manifests.is_empty() || self.manifests.len() > MAX_SNAPSHOT_MANIFEST_IDENTITIES {
            return Err(AuthorityProtocolError::InvalidText { field: "manifests" });
        }
        let mut generation = 0u64;
        let mut revoke_watermark = 0u64;
        let mut aggregates = std::collections::BTreeSet::new();
        for manifest in &self.manifests {
            manifest.validate()?;
            if !aggregates.insert((&manifest.aggregate_type, manifest.aggregate_id)) {
                return Err(AuthorityProtocolError::InvalidText { field: "manifests" });
            }
            generation = generation.max(manifest.generation);
            revoke_watermark = revoke_watermark.max(manifest.revoke_fence);
        }
        // The pointer must be the exact projection of the manifest frontier,
        // otherwise the durable pointer/certificate pair would fail its
        // verification read-back after install.
        if generation != self.generation || revoke_watermark != self.revoke_watermark {
            return Err(AuthorityProtocolError::DigestMismatch {
                field: "manifest_frontier",
            });
        }
        Ok(())
    }

    /// Canonical, domain-separated digest of the full snapshot content
    /// including every manifest identity. Injective over validated values.
    pub fn digest(&self) -> Result<String, AuthorityProtocolError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(512);
        bytes.extend_from_slice(BOOTSTRAP_SCOPE_SNAPSHOT_DOMAIN);
        authority_field(&mut bytes, self.scope.kind_text());
        authority_field(&mut bytes, &self.scope.store_key_text()?);
        authority_field(&mut bytes, &self.snapshot_hash);
        authority_field(&mut bytes, &self.generation.to_string());
        authority_field(&mut bytes, &self.revoke_watermark.to_string());
        authority_field(&mut bytes, &self.manifests.len().to_string());
        for manifest in &self.manifests {
            authority_field(&mut bytes, &manifest.aggregate_type);
            authority_field(&mut bytes, &manifest.aggregate_id.to_string());
            authority_field(&mut bytes, &manifest.manifest_digest_hex);
            authority_field(&mut bytes, &manifest.dependency_hash_hex);
            authority_field(&mut bytes, &manifest.semantic_hash_hex);
            authority_field(&mut bytes, &manifest.generation.to_string());
            authority_field(&mut bytes, &manifest.revoke_fence.to_string());
            authority_field(&mut bytes, &manifest.event_id);
            authority_field(&mut bytes, &manifest.operation_id);
        }
        Ok(super::authority_sha256_hex(&bytes))
    }
}

/// The root-signed bootstrap preflight artifact.
///
/// The artifact pins, under the ROOT signature:
/// - the exact authority identity and the expected ACTIVE trust-root digest,
/// - the exact expected GLOBAL frontier (term, fence sequence, key epoch and
///   chain digest) at install time — the installer CASes the durable frontier
///   from exactly this state and refuses any divergence,
/// - the stable bootstrap operation identity, nonce and validity window,
/// - the full finite set of approved scope snapshots with full manifest
///   vectors.
///
/// The canonical byte encoding of the whole artifact is bounded by
/// [`super::AUTHORITY_MAX_BODY_BYTES`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityBootstrapArtifact {
    pub protocol_version: u16,
    pub authorization_edition: u16,
    pub authority_id: String,
    pub root_id: String,
    /// Expected ACTIVE trust-root digest at install time (the digest of the
    /// trust root the durable rotation chain folds to).
    pub trust_root_digest: String,
    /// Expected exact GLOBAL frontier at install time.
    pub expected_authority_term: u64,
    pub expected_global_fence_sequence: u64,
    pub expected_key_epoch: u64,
    pub expected_global_chain_digest: String,
    /// Stable bootstrap operation identity (receipt + reconciliation key).
    pub operation_id: String,
    /// Stable event identity bound into the issued certificates.
    pub event_id: String,
    pub nonce: String,
    pub issued_at: i64,
    pub not_before: i64,
    /// Explicit expiry: an expired artifact can never be newly installed.
    pub expires_at: i64,
    /// Full finite set of approved scope snapshots. Unique by exact scope.
    pub snapshots: Vec<AuthorityBootstrapScopeSnapshot>,
    /// The ROOT-role key id whose verifying key must verify the signature.
    /// The key itself always comes from the attested durable registry.
    pub root_key_id: String,
    /// Lowercase hex Ed25519 signature by the ROOT-role key.
    pub signature: String,
}

impl AuthorityBootstrapArtifact {
    /// Validate everything except the signature encoding; used on the
    /// unsigned signing path where the signature is not yet present.
    pub fn validate_unsigned(&self) -> Result<(), AuthorityProtocolError> {
        if self.protocol_version != super::AUTHORITY_PROTOCOL_VERSION
            || self.authorization_edition != AUTHORIZATION_EDITION
        {
            return Err(AuthorityProtocolError::WrongEdition);
        }
        authority_text(&self.authority_id, "authority_id")?;
        authority_text(&self.root_id, "root_id")?;
        authority_digest(&self.trust_root_digest, "trust_root_digest")?;
        authority_counter(self.expected_authority_term, "expected_authority_term")?;
        authority_counter(
            self.expected_global_fence_sequence,
            "expected_global_fence_sequence",
        )?;
        authority_counter(self.expected_key_epoch, "expected_key_epoch")?;
        authority_digest(
            &self.expected_global_chain_digest,
            "expected_global_chain_digest",
        )?;
        authority_text(&self.operation_id, "operation_id")?;
        authority_text(&self.event_id, "event_id")?;
        authority_text(&self.nonce, "nonce")?;
        authority_timestamp(self.issued_at, "issued_at")?;
        authority_time_window(self.not_before, self.issued_at, self.expires_at)?;
        if self.snapshots.is_empty() || self.snapshots.len() > BOOTSTRAP_MAX_SNAPSHOTS {
            return Err(AuthorityProtocolError::InvalidText { field: "snapshots" });
        }
        let mut scope_keys = std::collections::BTreeSet::new();
        for snapshot in &self.snapshots {
            snapshot.validate()?;
            if !scope_keys.insert(snapshot.scope.store_key_text()?) {
                return Err(AuthorityProtocolError::InvalidText { field: "snapshots" });
            }
        }
        authority_text(&self.root_key_id, "root_key_id")?;
        // The artifact is a preflight document transported and archived as a
        // JSON body; its canonical encoding stays within the authority
        // control-plane body bound.
        let encoded =
            serde_json::to_vec(self).map_err(|_| AuthorityProtocolError::CanonicalSerialization)?;
        if encoded.len() > super::AUTHORITY_MAX_BODY_BYTES {
            return Err(AuthorityProtocolError::InvalidText {
                field: "bootstrap_artifact_bytes",
            });
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.validate_unsigned()?;
        authority_signature_encoding(&self.signature)
    }

    /// Canonical bytes covered by the ROOT signature.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, AuthorityProtocolError> {
        self.validate_unsigned()?;
        let mut bytes = Vec::with_capacity(1024);
        bytes.extend_from_slice(BOOTSTRAP_ARTIFACT_DOMAIN);
        authority_field(&mut bytes, &self.protocol_version.to_string());
        authority_field(&mut bytes, &self.authorization_edition.to_string());
        authority_field(&mut bytes, &self.authority_id);
        authority_field(&mut bytes, &self.root_id);
        authority_field(&mut bytes, &self.trust_root_digest);
        authority_field(&mut bytes, &self.expected_authority_term.to_string());
        authority_field(&mut bytes, &self.expected_global_fence_sequence.to_string());
        authority_field(&mut bytes, &self.expected_key_epoch.to_string());
        authority_field(&mut bytes, &self.expected_global_chain_digest);
        authority_field(&mut bytes, &self.operation_id);
        authority_field(&mut bytes, &self.event_id);
        authority_field(&mut bytes, &self.nonce);
        authority_field(&mut bytes, &self.issued_at.to_string());
        authority_field(&mut bytes, &self.not_before.to_string());
        authority_field(&mut bytes, &self.expires_at.to_string());
        authority_field(&mut bytes, &self.snapshots.len().to_string());
        for snapshot in &self.snapshots {
            authority_field(&mut bytes, &snapshot.digest()?);
        }
        authority_field(&mut bytes, &self.root_key_id);
        Ok(bytes)
    }

    /// Canonical, injective digest of the complete signed artifact. This is
    /// the stable identity receipts and certificate provenance bind to.
    pub fn artifact_digest(&self) -> Result<String, AuthorityProtocolError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(1152);
        bytes.extend_from_slice(BOOTSTRAP_ARTIFACT_DIGEST_DOMAIN);
        bytes.extend_from_slice(&self.signing_bytes()?);
        authority_field(&mut bytes, &self.signature);
        Ok(super::authority_sha256_hex(&bytes))
    }

    /// Sign the artifact in place with the ROOT-role signing key. The
    /// signature is only ever VERIFIED against the attested registry's
    /// ROOT-role key at install time; signing here is offline.
    pub fn sign(&mut self, root_signing_key: &SigningKey) -> Result<(), AuthorityProtocolError> {
        self.signature = String::new();
        self.validate_unsigned()?;
        let signature = root_signing_key.sign(&self.signing_bytes()?);
        self.signature = hex::encode(signature.to_bytes());
        Ok(())
    }

    /// Verify the signature structure and encoding against the given ROOT
    /// verifying key. Time validity is NOT checked here: reconciliation of an
    /// already-durable artifact must not depend on the wall clock. New
    /// installs must additionally call [`Self::verify_at`].
    pub fn verify(&self, root_verifying_key: &VerifyingKey) -> Result<(), AuthorityProtocolError> {
        self.validate()?;
        authority_verify_strict(root_verifying_key, &self.signing_bytes()?, &self.signature)
    }

    /// Verify the signature AND the validity window at `now_seconds`; used
    /// before a NEW install.
    pub fn verify_at(
        &self,
        root_verifying_key: &VerifyingKey,
        now_seconds: i64,
    ) -> Result<(), AuthorityProtocolError> {
        self.verify(root_verifying_key)?;
        if now_seconds < self.not_before || now_seconds >= self.expires_at {
            return Err(AuthorityProtocolError::NotCurrentlyValid);
        }
        Ok(())
    }
}

/// Domain-separated per-scope root-approval digest: the approved artifact
/// identity bound to one exact scope. Bootstrap certificates carry it as
/// `approved_request_digest` — there is no target request; the root-signed
/// artifact itself is the approval.
pub fn bootstrap_scope_approval_digest(
    artifact_digest: &str,
    scope_key_text: &str,
) -> Result<String, AuthorityProtocolError> {
    authority_digest(artifact_digest, "artifact_digest")?;
    authority_text(scope_key_text, "scope_key_text")?;
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(BOOTSTRAP_SCOPE_APPROVAL_DOMAIN);
    authority_field(&mut bytes, artifact_digest);
    authority_field(&mut bytes, scope_key_text);
    Ok(super::authority_sha256_hex(&bytes))
}

/// Bootstrap commit-provenance digest. Bootstrap issues NO source commit; a
/// bootstrap certificate's `source_commit_digest` carries this recomputable
/// identity of the bootstrap operation itself, so provenance is obvious and
/// never masquerades as an ordinary source commit.
pub fn bootstrap_commit_provenance_digest(
    artifact_digest: &str,
    operation_id: &str,
) -> Result<String, AuthorityProtocolError> {
    authority_digest(artifact_digest, "artifact_digest")?;
    authority_text(operation_id, "operation_id")?;
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(BOOTSTRAP_COMMIT_PROVENANCE_DOMAIN);
    authority_field(&mut bytes, artifact_digest);
    authority_field(&mut bytes, operation_id);
    Ok(super::authority_sha256_hex(&bytes))
}

/// Bootstrap outcome-provenance digest for one exact scope. No source outcome
/// row exists; the certificate carries this recomputable identity instead.
pub fn bootstrap_scope_outcome_digest(
    artifact_digest: &str,
    scope_key_text: &str,
) -> Result<String, AuthorityProtocolError> {
    authority_digest(artifact_digest, "artifact_digest")?;
    authority_text(scope_key_text, "scope_key_text")?;
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(BOOTSTRAP_OUTCOME_PROVENANCE_DOMAIN);
    authority_field(&mut bytes, artifact_digest);
    authority_field(&mut bytes, scope_key_text);
    Ok(super::authority_sha256_hex(&bytes))
}

/// Chain mutation digest of one bootstrap install: derived from the artifact
/// digest and the ordered certificate record digests, so the global frontier
/// advance is deterministic and auditable from the receipt alone.
pub fn bootstrap_mutation_digest(
    artifact_digest: &str,
    certificate_hashes: &[String],
) -> Result<String, AuthorityProtocolError> {
    authority_digest(artifact_digest, "artifact_digest")?;
    if certificate_hashes.is_empty() {
        return Err(AuthorityProtocolError::InvalidText {
            field: "certificate_hashes",
        });
    }
    let mut bytes = Vec::with_capacity(256 + 64 * certificate_hashes.len());
    bytes.extend_from_slice(BOOTSTRAP_MUTATION_DIGEST_DOMAIN);
    authority_field(&mut bytes, artifact_digest);
    authority_field(&mut bytes, &certificate_hashes.len().to_string());
    for hash in certificate_hashes {
        authority_digest(hash, "certificate_hash")?;
        authority_field(&mut bytes, hash);
    }
    Ok(super::authority_sha256_hex(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuthorizationAuthorityScope;
    use ed25519_dalek::SigningKey;

    fn card_scope() -> AuthorityProtocolScope {
        AuthorityProtocolScope::Card(AuthorizationAuthorityScope {
            tenant_id: 7,
            card_id: 17,
            user_id: None,
            domain: AuthorizationDomainScope::Any,
        })
    }

    fn manifests() -> Vec<AuthorityManifestIdentity> {
        vec![AuthorityManifestIdentity {
            aggregate_type: "grant".to_owned(),
            aggregate_id: 1,
            manifest_digest_hex: "aa".repeat(32),
            dependency_hash_hex: "bb".repeat(32),
            semantic_hash_hex: "cc".repeat(32),
            generation: 1,
            revoke_fence: 0,
            event_id: "bootstrap-event".to_owned(),
            operation_id: "bootstrap-operation".to_owned(),
        }]
    }

    fn unsigned_artifact() -> AuthorityBootstrapArtifact {
        AuthorityBootstrapArtifact {
            protocol_version: crate::AUTHORITY_PROTOCOL_VERSION,
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: "authority-test".to_owned(),
            root_id: "root-test".to_owned(),
            trust_root_digest: "ab".repeat(32),
            expected_authority_term: 1,
            expected_global_fence_sequence: 1,
            expected_key_epoch: 1,
            expected_global_chain_digest: "cd".repeat(32),
            operation_id: "bootstrap-op-1".to_owned(),
            event_id: "bootstrap-event".to_owned(),
            nonce: "bootstrap-nonce-1".to_owned(),
            issued_at: 2_000,
            not_before: 2_000,
            expires_at: 3_000,
            snapshots: vec![AuthorityBootstrapScopeSnapshot {
                scope: card_scope(),
                snapshot_hash: "ee".repeat(32),
                generation: 1,
                revoke_watermark: 0,
                manifests: manifests(),
            }],
            root_key_id: "root-test".to_owned(),
            signature: String::new(),
        }
    }

    #[test]
    fn snapshot_and_artifact_digests_are_injective_and_validated() {
        let snapshot = AuthorityBootstrapScopeSnapshot {
            scope: card_scope(),
            snapshot_hash: "ee".repeat(32),
            generation: 1,
            revoke_watermark: 0,
            manifests: manifests(),
        };
        snapshot.validate().unwrap();
        let digest = snapshot.digest().unwrap();

        let mut changed = snapshot.clone();
        changed.snapshot_hash = "ef".repeat(32);
        assert_ne!(digest, changed.digest().unwrap());

        // Non-canonical card scope is refused in the trust anchor.
        let mut alias = snapshot.clone();
        alias.scope = AuthorityProtocolScope::Card(AuthorizationAuthorityScope {
            tenant_id: 7,
            card_id: 17,
            user_id: Some(3),
            domain: AuthorizationDomainScope::Any,
        });
        assert!(alias.validate().is_err());

        // Manifest frontier must match the declared snapshot frontier.
        let mut drifted = snapshot.clone();
        drifted.generation = 2;
        assert!(matches!(
            drifted.validate(),
            Err(AuthorityProtocolError::DigestMismatch { .. })
        ));

        // Duplicate scopes are refused.
        let mut artifact = unsigned_artifact();
        artifact.validate_unsigned().unwrap();
        artifact.snapshots.push(artifact.snapshots[0].clone());
        assert!(artifact.validate_unsigned().is_err());
    }

    #[test]
    fn signature_binds_full_artifact_and_rejects_tampering() {
        let root = SigningKey::from_bytes(&[11u8; 32]);
        let signer = SigningKey::from_bytes(&[12u8; 32]);
        let mut artifact = unsigned_artifact();
        artifact.sign(&root).unwrap();
        artifact.validate().unwrap();

        let digest = artifact.artifact_digest().unwrap();
        // Deterministic signing: same content, same digest.
        let mut again = unsigned_artifact();
        again.sign(&root).unwrap();
        assert_eq!(digest, again.artifact_digest().unwrap());

        artifact.verify(&root.verifying_key()).unwrap();
        artifact
            .verify_at(&root.verifying_key(), 2_500)
            .expect("inside window");
        assert!(matches!(
            artifact.verify_at(&root.verifying_key(), 3_000),
            Err(AuthorityProtocolError::NotCurrentlyValid)
        ));

        // A SIGNER-role key is not the ROOT key: verification fails.
        let mut rogue = unsigned_artifact();
        rogue.sign(&signer).unwrap();
        assert!(matches!(
            rogue.verify(&root.verifying_key()),
            Err(AuthorityProtocolError::InvalidSignature)
        ));

        // Any content change invalidates the signature.
        let mut tampered = artifact.clone();
        tampered.expected_global_fence_sequence = 2;
        assert!(tampered.verify(&root.verifying_key()).is_err());
    }

    #[test]
    fn provenance_digests_are_stable_and_field_bound() {
        let digest = "ab".repeat(32);
        let approval = bootstrap_scope_approval_digest(&digest, "CARD:7:17:-:ANY").unwrap();
        assert_eq!(
            approval,
            bootstrap_scope_approval_digest(&digest, "CARD:7:17:-:ANY").unwrap()
        );
        assert_ne!(
            approval,
            bootstrap_scope_approval_digest(&digest, "CARD:7:18:-:ANY").unwrap()
        );
        assert_ne!(
            bootstrap_commit_provenance_digest(&digest, "op-1").unwrap(),
            bootstrap_scope_outcome_digest(&digest, "op-1").unwrap()
        );
        let mutation =
            bootstrap_mutation_digest(&digest, &["11".repeat(32), "22".repeat(32)]).unwrap();
        assert_ne!(
            mutation,
            bootstrap_mutation_digest(&digest, &["11".repeat(32)]).unwrap()
        );
        assert!(bootstrap_mutation_digest(&digest, &[]).is_err());
    }
}
