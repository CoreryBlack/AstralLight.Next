//! Verification of immutable certificate records recovered by stable identity,
//! plus the verified read-back of the per-scope publication pointer.
//!
//! The `StoredScopeCurrent` pointer is a CACHE: it names the certificate that
//! is currently published for one scope. The immutable certificate record is
//! the fact. Every consumer (`read_fence`, read-proof minting, and the
//! certify parent read) must resolve the pointer through
//! [`load_verified_scope_publication`] — never trust the pointer alone.

use std::collections::BTreeMap;

use astral_types::{
    AuthorityCommitBinding, AuthorityManifestIdentity, AuthorityProtocolError,
    AuthorityProtocolScope, AuthorityReservationCoverage, AuthorityReservationState,
    AuthorityRootKeyRole, AuthorityScopePublicationCertificate, AuthorityScopeReservation,
    AuthorityStagedScopeCoverage, GlobalAuthorityFrontier,
};

use super::{
    decode, manifest_frontier, AuthorityServiceError, StoredScopeCurrent, VerifiedAuthorityState,
};
use crate::error::AuthorityStoreError;
use crate::store::{AuthorityStore, KeyLayout};

/// Publication pointer identity for one requested scope. CARD scopes resolve
/// through their canonical publication identity — the same `(tenant_id,
/// card_id)` with the user/domain lens dropped — so every lens of one card
/// reads the SAME immutable certificate. ORG scopes have no canonical card
/// form and stay exact (never normalized into card terms). Returns the
/// publication scope and its store key.
pub(super) fn publication_pointer_scope(
    scope: &AuthorityProtocolScope,
) -> Result<(AuthorityProtocolScope, String), AuthorityProtocolError> {
    let publication_scope = scope
        .canonical_card_publication_scope()
        .unwrap_or_else(|| scope.clone());
    let scope_key = publication_scope.store_key_text()?;
    Ok((publication_scope, scope_key))
}

pub(super) fn verify_certificate_record(
    state: &VerifiedAuthorityState,
    expected_id: &str,
    certificate: &AuthorityScopePublicationCertificate,
) -> Result<(), AuthorityServiceError> {
    let key = state
        .trust_root
        .keys
        .iter()
        .find(|key| {
            key.key_id == certificate.key_id
                && key.key_epoch == certificate.key_epoch
                && key.role == AuthorityRootKeyRole::Signer
        })
        .ok_or_else(|| {
            AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                "certificate signer is not registered".to_owned(),
            ))
        })?
        .verifying_key()
        .map_err(AuthorityServiceError::Protocol)?;
    certificate
        .verify(&key)
        .map_err(AuthorityServiceError::Protocol)?;
    if certificate.certificate_id != expected_id
        || certificate.authority_id != state.frontier.authority_id
        || certificate.authority_term > state.frontier.authority_term
        || certificate.global_fence_sequence > state.frontier.global_fence_sequence
    {
        return Err(AuthorityServiceError::Protocol(
            astral_types::AuthorityProtocolError::ScopeMismatch,
        ));
    }
    Ok(())
}

/// One scope's current publication: the durable pointer PLUS the certificate
/// record it resolves to, after full verification of the pair.
pub(super) struct VerifiedScopePublication {
    /// The pointer exactly as stored. Its raw bytes go back into the mint CAS.
    pub pointer: StoredScopeCurrent,
    /// Store revision of the pointer record (the CAS token).
    pub pointer_revision: u64,
    /// Raw stored pointer bytes (the mint CAS rewrites exactly these).
    pub pointer_value: Vec<u8>,
    /// The verified certificate the pointer names.
    pub certificate: AuthorityScopePublicationCertificate,
}

/// Read back one scope's current publication and verify it end to end.
///
/// Fails closed on any drift between the cached pointer and the immutable
/// certificate record: unregistered signer, broken signature or completion
/// digest, id/hash/snapshot mismatch, manifest-frontier (generation or revoke
/// watermark) mismatch, key-epoch mismatch, or a pointer stored under a
/// foreign scope key.
pub(super) async fn load_verified_scope_publication(
    store: &dyn AuthorityStore,
    keys: &KeyLayout,
    state: &VerifiedAuthorityState,
    scope_key_text: &str,
) -> Result<Option<VerifiedScopePublication>, AuthorityServiceError> {
    let pointer_record = match store.get(&keys.scope_current(scope_key_text)).await? {
        Some(record) => record,
        None => return Ok(None),
    };
    let pointer: StoredScopeCurrent = decode(&pointer_record.value, "scope current")?;
    let certificate_record = store
        .get(&keys.certificate(&pointer.certificate_id))
        .await?
        .ok_or_else(|| {
            AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                "certified certificate is missing".to_owned(),
            ))
        })?;
    let certificate: AuthorityScopePublicationCertificate =
        decode(&certificate_record.value, "certificate")?;
    verify_certificate_record(state, &pointer.certificate_id, &certificate)?;
    // The pointer must be the exact projection of the verified certificate:
    // every comparison below is against the record, never against itself.
    let certificate_scope_key = certificate
        .scope
        .store_key_text()
        .map_err(AuthorityServiceError::Protocol)?;
    if certificate_scope_key != scope_key_text || pointer.scope_key_text != scope_key_text {
        return Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::ScopeMismatch,
        ));
    }
    let certificate_hash = certificate
        .record_digest()
        .map_err(AuthorityServiceError::Protocol)?;
    let (generation, revoke_watermark) =
        manifest_frontier(&certificate.manifests).map_err(AuthorityServiceError::Protocol)?;
    if certificate_hash != pointer.certificate_hash
        || certificate.snapshot_hash != pointer.snapshot_hash
        || pointer.scope_generation != generation
        || pointer.revoke_watermark != revoke_watermark
        || pointer.key_epoch != certificate.key_epoch
    {
        return Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
            "scope current does not match its certificate".to_owned(),
        )));
    }
    Ok(Some(VerifiedScopePublication {
        pointer,
        pointer_revision: pointer_record.revision,
        pointer_value: pointer_record.value,
        certificate,
    }))
}

/// Publication continuity across one scope: the requested manifests must not
/// regress against the verified previous certificate.
///
/// - Aggregates already published may never be dropped.
/// - A published aggregate may never move its generation or revoke watermark
///   backwards, even when another aggregate raises the frontier maximum: the
///   maximum can never mask a per-aggregate regression.
/// - At an unchanged generation the complete manifest identity (digests,
///   revoke fence, event and operation identity) must be unchanged.
/// - NEW aggregates join freely; their content is bound by the completion
///   digest verification. Unchanged manifests remain legal.
pub(super) fn verify_publication_frontier_continuity(
    previous: Option<&AuthorityScopePublicationCertificate>,
    manifests: &[AuthorityManifestIdentity],
) -> Result<(), AuthorityProtocolError> {
    let Some(previous) = previous else {
        return Ok(());
    };
    let previous_by_aggregate: BTreeMap<(&str, i64), &AuthorityManifestIdentity> = previous
        .manifests
        .iter()
        .map(|manifest| {
            (
                (manifest.aggregate_type.as_str(), manifest.aggregate_id),
                manifest,
            )
        })
        .collect();
    let mut current_by_aggregate: BTreeMap<(&str, i64), &AuthorityManifestIdentity> =
        BTreeMap::new();
    for manifest in manifests {
        current_by_aggregate.insert(
            (manifest.aggregate_type.as_str(), manifest.aggregate_id),
            manifest,
        );
    }
    for (aggregate, old) in &previous_by_aggregate {
        let Some(new) = current_by_aggregate.get(aggregate) else {
            // A previously published aggregate vanished from the request.
            return Err(AuthorityProtocolError::FrontierDiverged);
        };
        if new.generation < old.generation || new.revoke_fence < old.revoke_fence {
            return Err(AuthorityProtocolError::FrontierDiverged);
        }
        if new.generation == old.generation
            && (new.manifest_digest_hex != old.manifest_digest_hex
                || new.dependency_hash_hex != old.dependency_hash_hex
                || new.semantic_hash_hex != old.semantic_hash_hex
                || new.revoke_fence != old.revoke_fence
                || new.event_id != old.event_id
                || new.operation_id != old.operation_id)
        {
            return Err(AuthorityProtocolError::FrontierDiverged);
        }
    }
    Ok(())
}

/// Durable operator close receipt: the stable audit and idempotency record of
/// one operator-authorized close, stored in the SAME CAS as the terminal
/// state flip. It carries the COMPLETE post-close frontier so an
/// unknown-outcome retry can read back the ORIGINAL result instead of
/// masquerading the current frontier. It is keyed inside the
/// per-reservation certificate-index namespace under a reserved synthetic
/// scope key that can never collide with a real CARD/ORG scope key and is
/// never part of `certified_scopes`, so the publication history iteration
/// never observes it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct StoredCloseReceipt {
    pub reservation_id: String,
    pub operation_id: String,
    pub operator: String,
    pub reason: String,
    pub closed_at: i64,
    pub certified_scopes: Vec<String>,
    pub frontier: GlobalAuthorityFrontier,
}

/// Reserved certificate-index slot key of the close receipt.
pub(super) const CLOSE_RECEIPT_SCOPE_KEY: &str = "OPERATOR-CLOSE";

pub(super) fn close_receipt_key(keys: &KeyLayout, reservation_id: &str) -> String {
    keys.reservation_certificate(reservation_id, CLOSE_RECEIPT_SCOPE_KEY)
}

/// The complete publication history of one reservation, verified end to end.
///
/// Every certified scope's index must resolve to an immutable certificate
/// record that verifies under the active signer, binds THIS reservation's
/// immutable prepare frontier, matches the indexed scope, and — when the
/// durable commit binding is available — mirrors that binding exactly.
/// Terminal completeness is enforced here: a Certified EXACT reservation
/// must index exactly its full declared scope set; a closing or Certified
/// GLOBAL reservation with a recorded declared finite coverage must have
/// certified that full set, while one WITHOUT a declared set must carry a
/// non-empty actual history — the operator close supplies the completeness
/// assertion and a fanout proof is never fabricated.
pub(super) async fn verify_reservation_history(
    store: &dyn AuthorityStore,
    keys: &KeyLayout,
    state: &VerifiedAuthorityState,
    reservation: &AuthorityScopeReservation,
    binding: Option<&AuthorityCommitBinding>,
    terminal_completeness: bool,
    declared_finite: Option<&AuthorityStagedScopeCoverage>,
) -> Result<Vec<AuthorityScopePublicationCertificate>, AuthorityServiceError> {
    let mut certificates = Vec::new();
    for scope_key in &reservation.certified_scopes {
        let indexed = store
            .get(&keys.reservation_certificate(&reservation.reservation_id, scope_key))
            .await?
            .ok_or_else(|| {
                AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                    "reservation certificate index missing".to_owned(),
                ))
            })?;
        let certificate_id: String = decode(&indexed.value, "reservation certificate index")?;
        let stored = store
            .get(&keys.certificate(&certificate_id))
            .await?
            .ok_or_else(|| {
                AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                    "reservation certificate missing".to_owned(),
                ))
            })?;
        let certificate: AuthorityScopePublicationCertificate =
            decode(&stored.value, "reservation certificate")?;
        verify_certificate_record(state, &certificate_id, &certificate)?;
        // Explicit identity bindings: the certificate must name THIS
        // reservation's accepted intent and the serving authority — never
        // rely on the binding alone (it does not carry the intent digest).
        if certificate.intent_digest != reservation.intent_digest
            || certificate.authority_id != state.frontier.authority_id
        {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::ScopeMismatch,
            ));
        }
        if certificate
            .scope
            .store_key_text()
            .map_err(AuthorityServiceError::Protocol)?
            != *scope_key
            || certificate.reservation_id != reservation.reservation_id
            || certificate.authority_term != reservation.authority_term
            || certificate.global_fence_sequence != reservation.fence_sequence_at_prepare
        {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::ScopeMismatch,
            ));
        }
        if let Some(binding) = binding {
            if certificate.operation_id != binding.operation_id
                || certificate.event_id != binding.event_id
                || certificate.approved_request_digest != binding.request_digest
                || certificate.before_image_digest != binding.before_image_digest
                || certificate.after_image_digest != binding.after_image_digest
                || certificate.source_commit_digest != binding.source_commit_digest
                || certificate.source_outcome_digest != binding.source_outcome_digest
            {
                return Err(AuthorityServiceError::Protocol(
                    AuthorityProtocolError::ScopeMismatch,
                ));
            }
        }
        certificates.push(certificate);
    }
    let terminal =
        terminal_completeness || reservation.state == AuthorityReservationState::Certified;
    if terminal {
        let certified_keys: std::collections::BTreeSet<String> =
            reservation.certified_scopes.iter().cloned().collect();
        let complete = match &reservation.intent.coverage {
            AuthorityReservationCoverage::Exact(scopes) => {
                let declared: Result<std::collections::BTreeSet<String>, AuthorityProtocolError> =
                    scopes.iter().map(|scope| scope.store_key_text()).collect();
                match declared {
                    Ok(declared) => declared == certified_keys,
                    Err(_) => false,
                }
            }
            AuthorityReservationCoverage::Global => match declared_finite {
                Some(declared) => {
                    let declared: Result<
                        std::collections::BTreeSet<String>,
                        AuthorityProtocolError,
                    > = declared
                        .scopes
                        .iter()
                        .map(|scope| scope.store_key_text())
                        .collect();
                    match declared {
                        Ok(declared) => declared == certified_keys,
                        Err(_) => false,
                    }
                }
                None => !certified_keys.is_empty(),
            },
        };
        if !complete {
            return Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                "certified reservation lacks its declared coverage".to_owned(),
            )));
        }
    }
    Ok(certificates)
}
