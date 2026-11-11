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
    AuthorityCertifiedMemoryPublicationProof, AuthorityCertifiedMemoryRoot,
    AuthorityCertifiedMemoryRootProposal, AuthorityCommitBinding, AuthorityManifestIdentity,
    AuthorityProtocolError, AuthorityProtocolScope, AuthorityReservationCoverage,
    AuthorityReservationState, AuthorityRootKeyRole, AuthorityScopePublicationCertificate,
    AuthorityScopeReservation, AuthorityStagedScopeCoverage, GlobalAuthorityFrontier,
};

use super::{
    decode, manifest_frontier, AuthorityServiceError, StoredScopeCurrent, VerifiedAuthorityState,
};
use crate::error::AuthorityStoreError;
use crate::store::{AuthorityStore, KeyLayout, SnapshotRead, StoreOp, StoreSnapshot, StoreTxn};

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

/// Verify an authority-owned certified-memory root after resolving its signer
/// from the attested trust root. The current pointer is only an index.
pub(super) fn verify_certified_memory_root(
    state: &VerifiedAuthorityState,
    expected_root_id: &str,
    expected_root_digest: &str,
    root: &AuthorityCertifiedMemoryRoot,
    now: i64,
) -> Result<(), AuthorityServiceError> {
    root.validate().map_err(AuthorityServiceError::Protocol)?;
    if root.root_id != expected_root_id
        || root.root_digest != expected_root_digest
        || root.authority_id != state.frontier.authority_id
        || root.authority_term > state.frontier.authority_term
        || root.global_fence_sequence > state.frontier.global_fence_sequence
        || root.key_epoch > state.frontier.key_epoch
    {
        return Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::ScopeMismatch,
        ));
    }
    let key = state
        .trust_root
        .keys
        .iter()
        .find(|key| {
            key.key_id == root.key_id
                && key.key_epoch == root.key_epoch
                && key.role == AuthorityRootKeyRole::Signer
        })
        .ok_or_else(|| {
            AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                "certified-memory root signer is not registered".to_owned(),
            ))
        })?
        .verifying_key()
        .map_err(AuthorityServiceError::Protocol)?;
    root.verify_at(&key, now)
        .map_err(AuthorityServiceError::Protocol)
}

/// Verify the current certified-memory pointer and resolve its immutable root.
pub(super) async fn load_verified_certified_memory_root(
    store: &dyn AuthorityStore,
    keys: &KeyLayout,
    state: &VerifiedAuthorityState,
    now: i64,
) -> Result<AuthorityCertifiedMemoryRoot, AuthorityServiceError> {
    let pointer_record = store
        .get(&keys.certified_memory_root_current())
        .await?
        .ok_or(AuthorityServiceError::Protocol(
            AuthorityProtocolError::NotFound {
                record: "certified_memory_root",
            },
        ))?;
    let pointer: super::StoredCertifiedMemoryRootPointer =
        decode(&pointer_record.value, "certified memory root pointer")?;
    let root_record = store
        .get(&keys.certified_memory_root(&pointer.root_id))
        .await?
        .ok_or_else(|| {
            AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                "certified-memory root record is missing".to_owned(),
            ))
        })?;
    let root: AuthorityCertifiedMemoryRoot = decode(&root_record.value, "certified memory root")?;
    verify_certified_memory_root(state, &pointer.root_id, &pointer.root_digest, &root, now)?;
    if root.operation_id != pointer.operation_id {
        return Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::ScopeMismatch,
        ));
    }
    Ok(root)
}

/// Publication pointer identity for one requested scope.
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

/// Evidence validated at one snapshot. These guards cover observed records only;
/// they cannot prevent a new key from appearing under an observed prefix.
pub(super) struct VerifiedPublicationSnapshot(StoreSnapshot);

impl VerifiedPublicationSnapshot {
    pub(super) fn fence_observed_records(self, mut txn: StoreTxn) -> StoreTxn {
        for (key, record) in self.0.reads.into_iter().flatten() {
            txn = txn.with_op(StoreOp::RequireRevision {
                key,
                expected_revision: record.revision,
            });
        }
        txn
    }
}

/// Verify the immutable certificate set at a single store revision. This is
/// evidence validation only: a later root installation must also fence every
/// relevant record and the authority frontier in its own atomic transaction.
pub(super) async fn verify_certified_memory_publication_snapshot(
    store: &dyn AuthorityStore,
    keys: &KeyLayout,
    state: &VerifiedAuthorityState,
    proposal: &AuthorityCertifiedMemoryRootProposal,
    proof: &AuthorityCertifiedMemoryPublicationProof,
) -> Result<VerifiedPublicationSnapshot, AuthorityServiceError> {
    proof.validate().map_err(AuthorityServiceError::Protocol)?;
    let reservation_key = keys.reservation(&proof.reservation_id);
    let binding_key = keys.commit_binding(&proof.reservation_id);
    let coverage_key = keys.commit_coverage(&proof.reservation_id);
    let index_prefix = keys.reservation_certificate(&proof.reservation_id, "");
    let mut reads = vec![
        SnapshotRead::Key(reservation_key.clone()),
        SnapshotRead::Key(binding_key.clone()),
        SnapshotRead::Key(coverage_key.clone()),
        SnapshotRead::Prefix(index_prefix.clone()),
    ];
    reads.extend(
        proof
            .certificates
            .iter()
            .map(|certificate| SnapshotRead::Key(keys.certificate(&certificate.certificate_id))),
    );
    let snapshot = store.read_snapshot(&reads).await?;
    if snapshot.reads.len() != reads.len() {
        return Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
            "publication snapshot read count mismatch".to_owned(),
        )));
    }
    let exact = |index: usize, key: &str| -> Result<&[u8], AuthorityServiceError> {
        match snapshot.reads[index].as_slice() {
            [(actual, record)] if actual == key => Ok(&record.value),
            _ => Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                "publication snapshot exact record missing".to_owned(),
            ))),
        }
    };
    let reservation: AuthorityScopeReservation =
        decode(exact(0, &reservation_key)?, "reservation")?;
    let binding: AuthorityCommitBinding = decode(exact(1, &binding_key)?, "source commit binding")?;
    let coverage: super::coverage::StoredCommitCoverage =
        decode(exact(2, &coverage_key)?, "source commit coverage")?;
    if coverage.binding() != &binding
        || coverage.declared_coverage() != Some(&proof.declared_coverage)
    {
        return Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::ScopeMismatch,
        ));
    }
    proof
        .validate_for_root(proposal, &reservation, &binding)
        .map_err(AuthorityServiceError::Protocol)?;
    let mut expected = BTreeMap::new();
    for (position, certificate) in proof.certificates.iter().enumerate() {
        let scope_key = certificate
            .scope
            .store_key_text()
            .map_err(AuthorityServiceError::Protocol)?;
        let index_key = keys.reservation_certificate(&proof.reservation_id, &scope_key);
        expected.insert(index_key, certificate.certificate_id.as_str());
        let certificate_key = keys.certificate(&certificate.certificate_id);
        let stored: AuthorityScopePublicationCertificate = decode(
            exact(position + 4, &certificate_key)?,
            "reservation certificate",
        )?;
        verify_certificate_record(state, &certificate.certificate_id, &stored)?;
        if &stored != certificate
            || stored.intent_digest != reservation.intent_digest
            || stored.authority_term != reservation.authority_term
            || stored.global_fence_sequence != reservation.fence_sequence_at_prepare
            || stored.approved_request_digest != binding.request_digest
            || stored.before_image_digest != binding.before_image_digest
            || stored.after_image_digest != binding.after_image_digest
        {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::ScopeMismatch,
            ));
        }
    }
    let expected_scopes: std::collections::BTreeSet<String> = proof
        .certificates
        .iter()
        .map(|certificate| certificate.scope.store_key_text())
        .collect::<Result<_, _>>()
        .map_err(AuthorityServiceError::Protocol)?;
    if reservation
        .certified_scopes
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        != expected_scopes
    {
        return Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::InvalidCoverage,
        ));
    }
    verify_certified_memory_index(&snapshot.reads[3], &expected)?;
    Ok(VerifiedPublicationSnapshot(snapshot))
}

fn verify_certified_memory_index(
    index: &[(String, crate::store::StoredRecord)],
    expected: &BTreeMap<String, &str>,
) -> Result<(), AuthorityServiceError> {
    if index.len() != expected.len() {
        return Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::InvalidCoverage,
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for (key, record) in index {
        let certificate_id: String = decode(&record.value, "reservation certificate index")?;
        if !seen.insert(key) || expected.get(key).copied() != Some(certificate_id.as_str()) {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::InvalidCoverage,
            ));
        }
    }
    Ok(())
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

#[cfg(test)]
mod certified_memory_snapshot_tests {
    use super::*;
    use crate::store::{memory::MemoryAuthorityStore, StoreTxnOutcome, StoredRecord};

    #[tokio::test]
    async fn observed_publication_records_fence_root_transaction_against_races() {
        let keys = [
            "reservation",
            "binding",
            "coverage",
            "index/a",
            "certificate/a",
        ];
        for changed in
            keys.iter()
                .copied()
                .chain(["index/a-deleted", "index/a-recreated", "unchanged"])
        {
            let store = MemoryAuthorityStore::new();
            for key in keys {
                store
                    .execute(StoreTxn::new().with_op(StoreOp::Put {
                        key: key.to_owned(),
                        value: b"observed".to_vec(),
                    }))
                    .await
                    .unwrap();
            }
            let reads = [
                SnapshotRead::Key("reservation".into()),
                SnapshotRead::Key("binding".into()),
                SnapshotRead::Key("coverage".into()),
                SnapshotRead::Prefix("index/".into()),
                SnapshotRead::Key("certificate/a".into()),
            ];
            let snapshot = VerifiedPublicationSnapshot(store.read_snapshot(&reads).await.unwrap());
            if changed == "index/a-deleted" || changed == "index/a-recreated" {
                store
                    .execute(StoreTxn::new().with_op(StoreOp::Delete {
                        key: "index/a".into(),
                    }))
                    .await
                    .unwrap();
                if changed == "index/a-recreated" {
                    store
                        .execute(StoreTxn::new().with_op(StoreOp::Put {
                            key: "index/a".into(),
                            value: b"observed".to_vec(),
                        }))
                        .await
                        .unwrap();
                }
            } else if changed != "unchanged" {
                store
                    .execute(StoreTxn::new().with_op(StoreOp::Put {
                        key: changed.into(),
                        value: b"observed".to_vec(),
                    }))
                    .await
                    .unwrap();
            }
            let txn =
                snapshot.fence_observed_records(StoreTxn::new().with_op(StoreOp::PutIfAbsent {
                    key: "root".into(),
                    value: b"installed".to_vec(),
                }));
            let outcome = store.execute(txn).await.unwrap();
            if changed == "unchanged" {
                assert!(matches!(outcome, StoreTxnOutcome::Applied { .. }));
                assert!(store.get("root").await.unwrap().is_some());
            } else {
                let expected = if changed == "index/a-deleted" || changed == "index/a-recreated" {
                    "index/a"
                } else {
                    changed
                };
                assert_eq!(
                    outcome,
                    StoreTxnOutcome::PreconditionFailed {
                        key: expected.into()
                    }
                );
                assert!(store.get("root").await.unwrap().is_none());
            }
        }
    }

    #[tokio::test]
    async fn observed_record_fences_do_not_seal_prefix_against_new_keys() {
        let store = MemoryAuthorityStore::new();
        store
            .execute(StoreTxn::new().with_op(StoreOp::Put {
                key: "index/a".into(),
                value: b"a".to_vec(),
            }))
            .await
            .unwrap();
        let snapshot = VerifiedPublicationSnapshot(
            store
                .read_snapshot(&[SnapshotRead::Prefix("index/".into())])
                .await
                .unwrap(),
        );
        store
            .execute(StoreTxn::new().with_op(StoreOp::Put {
                key: "index/b".into(),
                value: b"b".to_vec(),
            }))
            .await
            .unwrap();
        let txn = snapshot.fence_observed_records(StoreTxn::new().with_op(StoreOp::PutIfAbsent {
            key: "root".into(),
            value: b"installed".to_vec(),
        }));
        assert!(matches!(
            store.execute(txn).await.unwrap(),
            StoreTxnOutcome::Applied { .. }
        ));
        assert!(!super::super::AuthorityService::certified_memory_publication_proof_available());
    }

    #[test]
    fn exact_certificate_index_rejects_missing_foreign_and_changed_entries() {
        let expected = BTreeMap::from([
            ("index/a".to_owned(), "cert-a"),
            ("index/b".to_owned(), "cert-b"),
        ]);
        let record = |key: &str, id: &str| {
            (
                key.to_owned(),
                StoredRecord {
                    revision: 1,
                    value: serde_json::to_vec(id).unwrap(),
                },
            )
        };
        let valid = vec![record("index/a", "cert-a"), record("index/b", "cert-b")];
        assert!(verify_certified_memory_index(&valid, &expected).is_ok());
        assert!(verify_certified_memory_index(&valid[..1], &expected).is_err());
        assert!(verify_certified_memory_index(
            &[record("index/a", "cert-a"), record("index/b", "other")],
            &expected,
        )
        .is_err());
        assert!(verify_certified_memory_index(
            &[record("index/a", "cert-a"), record("index/other", "cert-b")],
            &expected,
        )
        .is_err());
        assert!(verify_certified_memory_index(
            &[record("index/a", "cert-a"), record("index/a", "cert-a")],
            &expected,
        )
        .is_err());
    }
}
