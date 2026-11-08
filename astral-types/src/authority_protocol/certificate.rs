//! Scope publication certificate including dependency/manifest identities.
//!
//! The certificate is the authority-signed statement that one exact protocol
//! scope was published from an approved intent through a reserved, committed
//! source operation. The authority only signs a bundle it can re-verify
//! against its own durable reservation and intent records: approved intent
//! digest, before-image digest, after-image digest and a completion digest
//! recomputed over the manifest identities. Arbitrary database contents are
//! never signed.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::{
    authority_counter, authority_digest, authority_field, authority_positive_id,
    authority_signature_encoding, authority_text, authority_timestamp, authority_verify_strict,
    AuthorityProtocolError, AuthorityProtocolScope,
};
use crate::AUTHORIZATION_EDITION;

const PUBLICATION_CERT_DOMAIN: &[u8] = b"ASTRAL_AUTHORITY_SCOPE_PUBLICATION_CERT_V1\0";
const CERT_RECORD_DIGEST_DOMAIN: &[u8] = b"ASTRAL_AUTHORITY_SCOPE_PUBLICATION_CERT_RECORD_V1\0";
const COMPLETION_DIGEST_DOMAIN: &[u8] = b"ASTRAL_AUTHORITY_SCOPE_COMPLETION_DIGEST_V1\0";
const MAX_MANIFEST_IDENTITIES: usize = 4096;

/// One dependency/manifest identity bound into the completion digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityManifestIdentity {
    pub aggregate_type: String,
    pub aggregate_id: i64,
    /// Lowercase hex SHA-256 of the manifest content.
    pub manifest_digest_hex: String,
    /// Lowercase hex SHA-256 of the dependency set the manifest was compiled from.
    pub dependency_hash_hex: String,
    /// Lowercase hex SHA-256 of the semantic grant content.
    pub semantic_hash_hex: String,
    pub generation: u64,
    pub revoke_fence: u64,
    pub event_id: String,
    pub operation_id: String,
}

impl AuthorityManifestIdentity {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        authority_text(&self.aggregate_type, "aggregate_type")?;
        authority_positive_id(self.aggregate_id, "aggregate_id")?;
        authority_digest(&self.manifest_digest_hex, "manifest_digest_hex")?;
        authority_digest(&self.dependency_hash_hex, "dependency_hash_hex")?;
        authority_digest(&self.semantic_hash_hex, "semantic_hash_hex")?;
        authority_counter(self.generation, "generation")?;
        if self.revoke_fence > self.generation {
            return Err(AuthorityProtocolError::RevokeWatermarkAhead);
        }
        authority_text(&self.event_id, "event_id")?;
        authority_text(&self.operation_id, "operation_id")?;
        Ok(())
    }
}

/// The scope publication certificate.
///
/// `snapshot_hash` is the certified content identity of the published scope
/// evidence for this scope kind: the canonical evidence content hash for card
/// scopes, or the canonical ORG publication/member frontier hash for ORG
/// scopes. It is bound by signature, never recomputed from database rows by
/// the authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityScopePublicationCertificate {
    pub protocol_version: u16,
    pub authorization_edition: u16,
    pub authority_id: String,
    pub authority_term: u64,
    pub global_fence_sequence: u64,
    pub certificate_id: String,
    pub intent_digest: String,
    pub reservation_id: String,
    pub operation_id: String,
    pub event_id: String,
    pub scope: AuthorityProtocolScope,
    /// Approved immutable target request digest from the accepted intent.
    pub approved_request_digest: String,
    pub before_image_digest: Option<String>,
    pub after_image_digest: String,
    pub source_commit_digest: String,
    pub completion_digest: String,
    /// Certified content identity of the published scope evidence.
    pub snapshot_hash: String,
    /// Canonical digest of the durable source-outcome record committed in the
    /// same source transaction (exact read-back evidence pointer; the
    /// authority never reads the database, it signs the reference).
    pub source_outcome_digest: String,
    /// Record digest of the previous certificate for the same scope; None
    /// only for the first publication. The certification CAS binds the scope
    /// pointer to exactly this prior certificate.
    pub parent_certificate_hash: Option<String>,
    pub manifests: Vec<AuthorityManifestIdentity>,
    pub key_id: String,
    pub key_epoch: u64,
    pub issued_at: i64,
    pub not_before: i64,
    /// Optional far expiry; certificates are durable chain records.
    pub expires_at: Option<i64>,
    pub certificate_nonce: String,
    /// Lowercase hex Ed25519 signature by the authority signer.
    pub signature: String,
}

impl AuthorityScopePublicationCertificate {
    /// Validate everything except the signature encoding; used on the
    /// unsigned signing path where the signature is not yet present.
    pub fn validate_unsigned(&self) -> Result<(), AuthorityProtocolError> {
        if self.protocol_version != super::AUTHORITY_PROTOCOL_VERSION {
            return Err(AuthorityProtocolError::WrongEdition);
        }
        if self.authorization_edition != AUTHORIZATION_EDITION {
            return Err(AuthorityProtocolError::WrongEdition);
        }
        authority_text(&self.authority_id, "authority_id")?;
        authority_counter(self.authority_term, "authority_term")?;
        authority_counter(self.global_fence_sequence, "global_fence_sequence")?;
        authority_text(&self.certificate_id, "certificate_id")?;
        authority_digest(&self.intent_digest, "intent_digest")?;
        authority_text(&self.reservation_id, "reservation_id")?;
        authority_text(&self.operation_id, "operation_id")?;
        authority_text(&self.event_id, "event_id")?;
        self.scope.validate()?;
        authority_digest(&self.approved_request_digest, "approved_request_digest")?;
        if let Some(before_image_digest) = &self.before_image_digest {
            authority_digest(before_image_digest, "before_image_digest")?;
        }
        authority_digest(&self.after_image_digest, "after_image_digest")?;
        authority_digest(&self.source_commit_digest, "source_commit_digest")?;
        authority_digest(&self.completion_digest, "completion_digest")?;
        authority_digest(&self.snapshot_hash, "snapshot_hash")?;
        authority_digest(&self.source_outcome_digest, "source_outcome_digest")?;
        if let Some(parent_certificate_hash) = &self.parent_certificate_hash {
            authority_digest(parent_certificate_hash, "parent_certificate_hash")?;
        }
        if self.manifests.is_empty() || self.manifests.len() > MAX_MANIFEST_IDENTITIES {
            return Err(AuthorityProtocolError::InvalidText { field: "manifests" });
        }
        let mut aggregates = std::collections::BTreeSet::new();
        for manifest in &self.manifests {
            manifest.validate()?;
            if !aggregates.insert((&manifest.aggregate_type, manifest.aggregate_id)) {
                return Err(AuthorityProtocolError::InvalidText { field: "manifests" });
            }
        }
        authority_text(&self.key_id, "key_id")?;
        authority_counter(self.key_epoch, "key_epoch")?;
        authority_timestamp(self.issued_at, "issued_at")?;
        authority_timestamp(self.not_before, "not_before")?;
        if self.not_before > self.issued_at {
            return Err(AuthorityProtocolError::InvalidTimeWindow);
        }
        if let Some(expires_at) = self.expires_at {
            if expires_at <= self.issued_at {
                return Err(AuthorityProtocolError::InvalidTimeWindow);
            }
        }
        authority_text(&self.certificate_nonce, "certificate_nonce")?;
        Ok(())
    }

    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.validate_unsigned()?;
        authority_signature_encoding(&self.signature)
    }

    /// Canonical bytes covered by the signer signature.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, AuthorityProtocolError> {
        self.validate_unsigned()?;
        let mut bytes = Vec::with_capacity(1024);
        bytes.extend_from_slice(PUBLICATION_CERT_DOMAIN);
        authority_field(&mut bytes, &self.protocol_version.to_string());
        authority_field(&mut bytes, &self.authorization_edition.to_string());
        authority_field(&mut bytes, &self.authority_id);
        authority_field(&mut bytes, &self.authority_term.to_string());
        authority_field(&mut bytes, &self.global_fence_sequence.to_string());
        authority_field(&mut bytes, &self.certificate_id);
        authority_field(&mut bytes, &self.intent_digest);
        authority_field(&mut bytes, &self.reservation_id);
        authority_field(&mut bytes, &self.operation_id);
        authority_field(&mut bytes, &self.event_id);
        authority_field(&mut bytes, self.scope.kind_text());
        authority_field(&mut bytes, &self.scope.store_key_text()?);
        authority_field(&mut bytes, &self.approved_request_digest);
        authority_field(
            &mut bytes,
            self.before_image_digest.as_deref().unwrap_or("-"),
        );
        authority_field(&mut bytes, &self.after_image_digest);
        authority_field(&mut bytes, &self.source_commit_digest);
        authority_field(&mut bytes, &self.completion_digest);
        authority_field(&mut bytes, &self.snapshot_hash);
        authority_field(
            &mut bytes,
            self.parent_certificate_hash.as_deref().unwrap_or("-"),
        );
        authority_field(&mut bytes, &self.source_outcome_digest);
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
        authority_field(&mut bytes, &self.key_id);
        authority_field(&mut bytes, &self.key_epoch.to_string());
        authority_field(&mut bytes, &self.issued_at.to_string());
        authority_field(&mut bytes, &self.not_before.to_string());
        authority_field(
            &mut bytes,
            &self
                .expires_at
                .map_or_else(|| "-".to_owned(), |value| value.to_string()),
        );
        authority_field(&mut bytes, &self.certificate_nonce);
        Ok(bytes)
    }

    /// Digest of the complete record including the signature. This is the
    /// identity callers pin as `expected_certificate_hash` in fence reads.
    pub fn record_digest(&self) -> Result<String, AuthorityProtocolError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(1280);
        bytes.extend_from_slice(CERT_RECORD_DIGEST_DOMAIN);
        bytes.extend_from_slice(&self.signing_bytes()?);
        authority_field(&mut bytes, &self.signature);
        Ok(super::authority_sha256_hex(&bytes))
    }

    /// Recompute the completion digest over the verified bundle.
    ///
    /// The completion digest binds the IMMUTABLE RESERVATION FRONTIER — the
    /// certificate's `authority_term`/`global_fence_sequence` are the
    /// reservation-recorded values (not the current moving frontier), so the
    /// caller can compute exactly this digest from its prepare response
    /// before contacting the authority.
    pub fn recompute_completion_digest(&self) -> Result<String, AuthorityProtocolError> {
        let mut probe = self.clone();
        probe.completion_digest = "00".repeat(32);
        probe.validate_unsigned()?;
        let mut bytes = Vec::with_capacity(1024);
        bytes.extend_from_slice(COMPLETION_DIGEST_DOMAIN);
        authority_field(&mut bytes, &self.authorization_edition.to_string());
        authority_field(&mut bytes, &self.authority_id);
        authority_field(&mut bytes, &self.reservation_id);
        authority_field(&mut bytes, &self.intent_digest);
        authority_field(&mut bytes, &self.approved_request_digest);
        authority_field(&mut bytes, &self.authority_term.to_string());
        authority_field(&mut bytes, &self.global_fence_sequence.to_string());
        authority_field(
            &mut bytes,
            self.before_image_digest.as_deref().unwrap_or("-"),
        );
        authority_field(&mut bytes, &self.after_image_digest);
        authority_field(&mut bytes, &self.source_commit_digest);
        authority_field(&mut bytes, &self.source_outcome_digest);
        authority_field(&mut bytes, &self.snapshot_hash);
        authority_field(&mut bytes, &self.operation_id);
        authority_field(&mut bytes, &self.event_id);
        authority_field(&mut bytes, self.scope.kind_text());
        authority_field(&mut bytes, &self.scope.store_key_text()?);
        authority_field(
            &mut bytes,
            self.parent_certificate_hash.as_deref().unwrap_or("-"),
        );
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

    /// Verify-before-sign: fail when the caller-supplied completion digest is
    /// not the canonical recomputation of this bundle.
    pub fn verify_completion_digest(&self) -> Result<(), AuthorityProtocolError> {
        let recomputed = self.recompute_completion_digest()?;
        if recomputed != self.completion_digest {
            return Err(AuthorityProtocolError::DigestMismatch {
                field: "completion_digest",
            });
        }
        Ok(())
    }

    pub fn sign(&mut self, signing_key: &SigningKey) -> Result<(), AuthorityProtocolError> {
        self.signature = String::new();
        self.validate_unsigned()?;
        self.verify_completion_digest()?;
        let signature = signing_key.sign(&self.signing_bytes()?);
        self.signature = hex::encode(signature.to_bytes());
        Ok(())
    }

    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), AuthorityProtocolError> {
        self.validate()?;
        self.verify_completion_digest()?;
        authority_verify_strict(verifying_key, &self.signing_bytes()?, &self.signature)
    }

    pub fn verify_at(
        &self,
        verifying_key: &VerifyingKey,
        now_seconds: i64,
    ) -> Result<(), AuthorityProtocolError> {
        self.verify(verifying_key)?;
        if now_seconds < self.not_before {
            return Err(AuthorityProtocolError::NotCurrentlyValid);
        }
        if let Some(expires_at) = self.expires_at {
            if now_seconds >= expires_at {
                return Err(AuthorityProtocolError::NotCurrentlyValid);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuthorizationAuthorityScope;

    fn card_scope() -> AuthorityProtocolScope {
        AuthorityProtocolScope::Card(AuthorizationAuthorityScope {
            tenant_id: 7,
            card_id: 17,
            user_id: None,
            domain: crate::AuthorizationDomainScope::Any,
        })
    }

    fn manifests() -> Vec<AuthorityManifestIdentity> {
        vec![AuthorityManifestIdentity {
            aggregate_type: "USER_CARD".to_owned(),
            aggregate_id: 17,
            manifest_digest_hex: "aa".repeat(32),
            dependency_hash_hex: "bb".repeat(32),
            semantic_hash_hex: "cc".repeat(32),
            generation: 4,
            revoke_fence: 2,
            event_id: "event-1".to_owned(),
            operation_id: "operation-1".to_owned(),
        }]
    }

    #[test]
    fn certificate_rejects_duplicate_aggregate_identities() {
        let mut certificate = certificate();
        certificate.manifests.push(certificate.manifests[0].clone());
        assert!(certificate.validate_unsigned().is_err());
        assert!(certificate.recompute_completion_digest().is_err());
    }

    #[test]
    fn certificate_rejects_incoherent_validity_windows() {
        let mut certificate = certificate();
        certificate.completion_digest = "00".repeat(32);
        certificate.not_before = 0;
        assert!(certificate.validate_unsigned().is_err());
        certificate.not_before = certificate.issued_at + 1;
        assert!(certificate.validate_unsigned().is_err());
        certificate.not_before = certificate.issued_at - 1;
        certificate.expires_at = Some(certificate.issued_at);
        assert!(certificate.validate_unsigned().is_err());
        certificate.expires_at = Some(certificate.issued_at + 1);
        assert!(certificate.validate_unsigned().is_ok());
    }

    fn certificate() -> AuthorityScopePublicationCertificate {
        AuthorityScopePublicationCertificate {
            protocol_version: crate::authority_protocol::AUTHORITY_PROTOCOL_VERSION,
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: "authority-1".to_owned(),
            authority_term: 1,
            global_fence_sequence: 6,
            certificate_id: "certificate-1".to_owned(),
            intent_digest: "11".repeat(32),
            reservation_id: "reservation-1".to_owned(),
            operation_id: "operation-1".to_owned(),
            event_id: "event-1".to_owned(),
            scope: card_scope(),
            approved_request_digest: "22".repeat(32),
            before_image_digest: Some("33".repeat(32)),
            after_image_digest: "44".repeat(32),
            source_commit_digest: "55".repeat(32),
            completion_digest: String::new(),
            snapshot_hash: "66".repeat(32),
            parent_certificate_hash: None,
            source_outcome_digest: "99".repeat(32),
            manifests: manifests(),
            key_id: "signer-1".to_owned(),
            key_epoch: 1,
            issued_at: 2_000,
            not_before: 2_000,
            expires_at: None,
            certificate_nonce: "certificate-nonce-1".to_owned(),
            signature: String::new(),
        }
    }

    #[test]
    fn completion_digest_is_recomputed_and_enforced_before_signing() {
        let mut certificate = certificate();
        certificate.completion_digest = certificate.recompute_completion_digest().unwrap();
        assert!(certificate.verify_completion_digest().is_ok());
        let mut changed_snapshot = certificate.clone();
        changed_snapshot.snapshot_hash = "fe".repeat(32);
        assert_ne!(
            changed_snapshot.recompute_completion_digest().unwrap(),
            certificate.completion_digest
        );
        assert!(changed_snapshot.verify_completion_digest().is_err());

        let signing = SigningKey::from_bytes(&[8; 32]);
        certificate.sign(&signing).unwrap();
        certificate.verify(&signing.verifying_key()).unwrap();
        assert_eq!(
            certificate.recompute_completion_digest().unwrap(),
            certificate.completion_digest
        );

        let mut tampered = certificate.clone();
        tampered.completion_digest = "77".repeat(32);
        assert!(matches!(
            tampered.verify(&signing.verifying_key()),
            Err(AuthorityProtocolError::DigestMismatch {
                field: "completion_digest"
            })
        ));

        let mut forged = certificate.clone();
        forged.snapshot_hash = "88".repeat(32);
        assert!(matches!(
            forged.verify(&signing.verifying_key()),
            Err(AuthorityProtocolError::DigestMismatch {
                field: "completion_digest"
            })
        ));
        forged.completion_digest = forged.recompute_completion_digest().unwrap();
        assert!(matches!(
            forged.verify(&signing.verifying_key()),
            Err(AuthorityProtocolError::InvalidSignature)
        ));
    }

    #[test]
    fn record_digest_pins_full_record_for_expected_certificate_hash() {
        let mut certificate = certificate();
        certificate.completion_digest = certificate.recompute_completion_digest().unwrap();
        let signing = SigningKey::from_bytes(&[8; 32]);
        certificate.sign(&signing).unwrap();
        let record_digest = certificate.record_digest().unwrap();

        let mut other = certificate.clone();
        other.certificate_nonce = "certificate-nonce-2".to_owned();
        other.completion_digest = other.recompute_completion_digest().unwrap();
        other.sign(&signing).unwrap();
        assert_ne!(record_digest, other.record_digest().unwrap());
    }

    #[test]
    fn org_scope_certificate_binds_org_store_key() {
        let mut certificate = certificate();
        certificate.scope =
            AuthorityProtocolScope::Org(crate::authority_protocol::AuthorityOrgScope {
                tenant_id: 7,
                root_tenant_id: Some(1),
                member: crate::authority_protocol::AuthorityOrgMemberSubject {
                    user_id: 1,
                    identity_card_id: 2,
                    card_id: 3,
                },
            });
        certificate.completion_digest = certificate.recompute_completion_digest().unwrap();
        let signing = SigningKey::from_bytes(&[8; 32]);
        certificate.sign(&signing).unwrap();
        assert!(certificate
            .signing_bytes()
            .unwrap()
            .windows(7)
            .any(|window| window == b"ORG:7:1"));
        certificate.verify(&signing.verifying_key()).unwrap();

        let mut invalid_org = certificate.clone();
        invalid_org.scope =
            AuthorityProtocolScope::Org(crate::authority_protocol::AuthorityOrgScope {
                tenant_id: 0,
                root_tenant_id: None,
                member: crate::authority_protocol::AuthorityOrgMemberSubject {
                    user_id: 1,
                    identity_card_id: 2,
                    card_id: 3,
                },
            });
        assert!(matches!(
            invalid_org.validate(),
            Err(AuthorityProtocolError::InvalidIdentifier {
                field: "card_scope"
            }) | Err(AuthorityProtocolError::InvalidIdentifier { field: "tenant_id" })
        ));
    }

    #[test]
    fn manifest_identities_reject_revoke_fence_ahead_of_generation() {
        let mut certificate = certificate();
        certificate.completion_digest = certificate.recompute_completion_digest().unwrap();
        certificate.manifests[0].revoke_fence = certificate.manifests[0].generation + 1;
        assert!(matches!(
            certificate.validate(),
            Err(AuthorityProtocolError::RevokeWatermarkAhead)
        ));
    }
}
