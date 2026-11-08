//! Bootstrap install: apply one root-signed preflight artifact as the first
//! scope certificates.
//!
//! Fail-closed rules implemented here (V7 §15.9.4 genesis contract):
//! - The installer runs only on the quorum leader. The in-process leader flag
//!   is the leadership gate; the exact-frontier CAS is a DURABLE DIVERGENCE
//!   fence (it refuses any state drift between the artifact's approval and
//!   the install), NOT a leadership lease fence. Callers that acquire
//!   leadership out-of-band (the CLI) must additionally pass an
//!   [`AuthorityLeaderFence`] so the final transaction compares the leader
//!   key: a stale leader whose lease was lost or taken over can never commit.
//! - The artifact signature is ALWAYS verified against the ROOT-role key of
//!   the verified durable registry (genesis + rotation chain). Callers can
//!   never pass a verifying key.
//! - A fresh install refuses while any blocking reservation exists, refuses
//!   any scope that already exists, and refuses when the durable GLOBAL
//!   frontier is not exactly the artifact's approved frontier (term, fence
//!   sequence, key epoch, chain digest).
//! - One atomic transaction installs: the stable operation index, the
//!   bootstrap receipt, every immutable certificate, every scope pointer
//!   (PutIfAbsent), the frontier advance (CAS) and the read-gate epoch (CAS).
//! - Unknown store outcomes surface as [`AuthorityServiceError::
//!   UnknownOutcome`]; reconciliation is a read-back by stable operation id /
//!   artifact digest. Nothing is ever blindly resent.
//! - The same artifact is idempotent: a re-install reconciles the durable
//!   receipt and re-verifies every certificate against the registry instead
//!   of re-issuing. The same operation id with a different artifact digest is
//!   refused.
//! - Bootstrap certificates carry obvious provenance (`intent_digest` is the
//!   artifact digest, `reservation_id` is `bootstrap-<artifact digest>` and
//!   the commit/outcome digests are the recomputable bootstrap provenance
//!   identities) and never masquerade as ordinary source commits.
//! - Reconciliation recovers the HISTORICAL certificates exactly: every
//!   artifact-derived field is re-derived from the signed artifact and
//!   compared field by field, and the receipt-pinned record digest pins the
//!   exact bytes (a re-signed substitute can never pass). The CURRENT scope
//!   pointer may have legally advanced after bootstrap; when it is read it is
//!   only verified (pointer/certificate pair) and must not have regressed
//!   below the bootstrapped frontier — it never substitutes for the
//!   historical certificate.

use ed25519_dalek::VerifyingKey;

use astral_types::{
    AuthorityBootstrapArtifact, AuthorityBootstrapScopeSnapshot, AuthorityProtocolError,
    AuthorityRootKeyRole, AuthorityScopePublicationCertificate, AUTHORITY_PROTOCOL_VERSION,
    AUTHORIZATION_EDITION,
};

use super::{
    certificate_records, decode, encode, now_unix, AuthorityService, AuthorityServiceError,
    StoredScopeCurrent, VerifiedAuthorityState,
};
use crate::error::AuthorityStoreError;
use crate::store::{StoreOp, StoreTxn, StoreTxnOutcome};

/// Durable operation index value: binds the stable bootstrap operation id to
/// exactly one artifact digest. Stored at `bootstrap-operations/<op id>`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredBootstrapOperation {
    pub artifact_digest: String,
}

/// Durable bootstrap receipt: the stable record of one installed artifact.
/// Stored at `bootstrap/<artifact digest>`. Recovery and reconciliation read
/// this record by stable identity; it is never a claim of source commit.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredBootstrapReceipt {
    pub artifact_digest: String,
    pub operation_id: String,
    /// Certificate ids in canonical (scope store key) order.
    pub certificate_ids: Vec<String>,
    /// Certificate record digests in the same order.
    pub certificate_hashes: Vec<String>,
    pub installed_at: i64,
}

/// Result of one bootstrap install or reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityBootstrapOutcome {
    pub receipt: StoredBootstrapReceipt,
    /// True when this call durably applied the artifact; false when an
    /// already-installed artifact was reconciled by read-back.
    pub newly_applied: bool,
}

// NOTE (leadership fencing): the install's final transaction goes through
// the shared `execute_leader_txn` wrapper owned by the store/leadership
// owner — the durable leadership gate (leader key + lease-bound leadership
// token), not the in-process flag alone. The frontier CAS below remains a
// DURABLE DIVERGENCE fence (state drift between approval and install), NOT a
// leadership lease fence. The CLI must reuse the same wrapper with
// `LeadershipTokenRecord{v, authority, instance, lease}` lease-attached key
// install and verification once the leader owner publishes the exact public
// bind signature; it must never self-assert the leader flag as its fence.

/// Key layout of the bootstrap records, under the configured quorum prefix.
/// Kept local because the shared [`crate::store::KeyLayout`] is owned by the
/// store contract; the convention (`prefix/suffix`) is identical.
struct BootstrapKeys {
    base: String,
}

impl BootstrapKeys {
    fn new(key_prefix: &str) -> Self {
        Self {
            base: key_prefix.trim_matches('/').to_owned(),
        }
    }

    fn operation(&self, operation_id: &str) -> String {
        format!("{}/bootstrap-operations/{}", self.base, operation_id)
    }

    fn receipt(&self, artifact_digest: &str) -> String {
        format!("{}/bootstrap/{}", self.base, artifact_digest)
    }
}

/// Snapshots in canonical (scope store key) order; the deterministic order
/// fixes certificate ids and receipt ordering.
fn ordered_bootstrap_snapshots(
    artifact: &AuthorityBootstrapArtifact,
) -> Result<Vec<(String, &AuthorityBootstrapScopeSnapshot)>, AuthorityServiceError> {
    let mut ordered = Vec::with_capacity(artifact.snapshots.len());
    for snapshot in &artifact.snapshots {
        let scope_key = snapshot
            .scope
            .store_key_text()
            .map_err(AuthorityServiceError::Protocol)?;
        ordered.push((scope_key, snapshot));
    }
    ordered.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(ordered)
}

/// The artifact-derived expected content of one bootstrap certificate:
/// everything except the signer binding, the install timestamps and the
/// signature. Both install and reconciliation derive it from the signed
/// artifact through this one function, so they can never drift apart.
struct ExpectedBootstrapCertificate {
    certificate_id: String,
    certificate_nonce: String,
    intent_digest: String,
    reservation_id: String,
    operation_id: String,
    event_id: String,
    scope: astral_types::AuthorityProtocolScope,
    approved_request_digest: String,
    before_image_digest: Option<String>,
    after_image_digest: String,
    source_commit_digest: String,
    source_outcome_digest: String,
    snapshot_hash: String,
    parent_certificate_hash: Option<String>,
    manifests: Vec<astral_types::AuthorityManifestIdentity>,
    authority_term: u64,
    global_fence_sequence: u64,
    expires_at: Option<i64>,
}

fn expected_bootstrap_certificate(
    artifact: &AuthorityBootstrapArtifact,
    artifact_digest: &str,
    scope_key: &str,
    snapshot: &AuthorityBootstrapScopeSnapshot,
    index: usize,
) -> Result<ExpectedBootstrapCertificate, AuthorityServiceError> {
    Ok(ExpectedBootstrapCertificate {
        certificate_id: format!("bt-{artifact_digest}-{index}"),
        certificate_nonce: format!("btn-{artifact_digest}-{index}"),
        // Provenance: the root-signed artifact IS the approved intent.
        intent_digest: artifact_digest.to_owned(),
        reservation_id: format!("bootstrap-{artifact_digest}"),
        operation_id: artifact.operation_id.clone(),
        event_id: artifact.event_id.clone(),
        scope: snapshot.scope.clone(),
        approved_request_digest: astral_types::bootstrap_scope_approval_digest(
            artifact_digest,
            scope_key,
        )
        .map_err(AuthorityServiceError::Protocol)?,
        // Bootstrap installs only absent scopes: always a first publication,
        // with no before image and no parent certificate.
        before_image_digest: None,
        after_image_digest: snapshot.snapshot_hash.clone(),
        source_commit_digest: astral_types::bootstrap_commit_provenance_digest(
            artifact_digest,
            &artifact.operation_id,
        )
        .map_err(AuthorityServiceError::Protocol)?,
        source_outcome_digest: astral_types::bootstrap_scope_outcome_digest(
            artifact_digest,
            scope_key,
        )
        .map_err(AuthorityServiceError::Protocol)?,
        snapshot_hash: snapshot.snapshot_hash.clone(),
        parent_certificate_hash: None,
        manifests: snapshot.manifests.clone(),
        // The certificate binds the artifact-approved immutable frontier,
        // exactly like an ordinary certificate binds the prepare frontier.
        authority_term: artifact.expected_authority_term,
        global_fence_sequence: artifact.expected_global_fence_sequence,
        expires_at: None,
    })
}

impl AuthorityService {
    /// Resolve the ROOT-role verifying key for `artifact.root_key_id` from
    /// the verified durable registry. The caller can never pass a key.
    fn bootstrap_root_verifying_key(
        &self,
        artifact: &AuthorityBootstrapArtifact,
        state: &VerifiedAuthorityState,
    ) -> Result<VerifyingKey, AuthorityServiceError> {
        if artifact.authority_id != self.config.identity.authority_id
            || artifact.root_id != state.trust_root.root_id
            || artifact.trust_root_digest
                != state
                    .trust_root
                    .digest()
                    .map_err(AuthorityServiceError::Protocol)?
        {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::TrustRootMismatch,
            ));
        }
        let root_entry = state
            .trust_root
            .key_by_id(&artifact.root_key_id)
            .filter(|key| key.role == AuthorityRootKeyRole::Root)
            .ok_or(AuthorityServiceError::Protocol(
                AuthorityProtocolError::NotFound { record: "root_key" },
            ))?;
        root_entry
            .verifying_key()
            .map_err(AuthorityServiceError::Protocol)
    }

    /// Build one bootstrap certificate for `snapshot` (in canonical order).
    /// The completion digest is recomputed (verify-before-sign) and the
    /// signature is minted by the protected, leader-gated signer.
    fn build_bootstrap_certificate(
        &self,
        artifact: &AuthorityBootstrapArtifact,
        artifact_digest: &str,
        scope_key: &str,
        snapshot: &AuthorityBootstrapScopeSnapshot,
        index: usize,
        now: i64,
    ) -> Result<AuthorityScopePublicationCertificate, AuthorityServiceError> {
        let expected =
            expected_bootstrap_certificate(artifact, artifact_digest, scope_key, snapshot, index)?;
        let mut certificate = AuthorityScopePublicationCertificate {
            protocol_version: AUTHORITY_PROTOCOL_VERSION,
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: self.config.identity.authority_id.clone(),
            authority_term: expected.authority_term,
            global_fence_sequence: expected.global_fence_sequence,
            certificate_id: expected.certificate_id.clone(),
            intent_digest: expected.intent_digest.clone(),
            reservation_id: expected.reservation_id.clone(),
            operation_id: expected.operation_id.clone(),
            event_id: expected.event_id.clone(),
            scope: expected.scope.clone(),
            approved_request_digest: expected.approved_request_digest.clone(),
            before_image_digest: expected.before_image_digest.clone(),
            after_image_digest: expected.after_image_digest.clone(),
            source_commit_digest: expected.source_commit_digest.clone(),
            completion_digest: "00".repeat(32),
            snapshot_hash: expected.snapshot_hash.clone(),
            parent_certificate_hash: expected.parent_certificate_hash.clone(),
            source_outcome_digest: expected.source_outcome_digest.clone(),
            manifests: expected.manifests.clone(),
            key_id: self.signer.key_id().to_owned(),
            key_epoch: self.signer.key_epoch(),
            issued_at: now,
            not_before: now,
            expires_at: expected.expires_at,
            certificate_nonce: expected.certificate_nonce.clone(),
            signature: String::new(),
        };
        certificate.completion_digest = certificate
            .recompute_completion_digest()
            .map_err(AuthorityServiceError::Protocol)?;
        let signing_bytes = certificate
            .signing_bytes()
            .map_err(AuthorityServiceError::Protocol)?;
        certificate.signature = self.signer.sign_checked(&signing_bytes, true)?;
        certificate
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        Ok(certificate)
    }

    /// Re-derive and compare EVERY artifact-derived field of one stored
    /// certificate against the expected content of the signed artifact. A
    /// re-signed substitute (same receipt slot, different bytes) cannot pass:
    /// the field comparison plus the receipt-pinned record digest pin both
    /// the content and the exact bytes.
    fn verify_certificate_matches_artifact(
        &self,
        certificate: &AuthorityScopePublicationCertificate,
        expected: &ExpectedBootstrapCertificate,
    ) -> Result<(), AuthorityServiceError> {
        let mismatch = |what: &str| {
            AuthorityServiceError::Store(AuthorityStoreError::Corrupt(format!(
                "bootstrap certificate does not match the artifact-derived expected content: {what}"
            )))
        };
        if certificate.certificate_id != expected.certificate_id {
            return Err(mismatch("certificate_id"));
        }
        if certificate.certificate_nonce != expected.certificate_nonce {
            return Err(mismatch("certificate_nonce"));
        }
        if certificate.intent_digest != expected.intent_digest {
            return Err(mismatch("intent_digest"));
        }
        if certificate.reservation_id != expected.reservation_id {
            return Err(mismatch("reservation_id"));
        }
        if certificate.operation_id != expected.operation_id {
            return Err(mismatch("operation_id"));
        }
        if certificate.event_id != expected.event_id {
            return Err(mismatch("event_id"));
        }
        if certificate.scope != expected.scope {
            return Err(mismatch("scope"));
        }
        if certificate.approved_request_digest != expected.approved_request_digest {
            return Err(mismatch("approved_request_digest"));
        }
        if certificate.before_image_digest != expected.before_image_digest {
            return Err(mismatch("before_image_digest"));
        }
        if certificate.after_image_digest != expected.after_image_digest {
            return Err(mismatch("after_image_digest"));
        }
        if certificate.source_commit_digest != expected.source_commit_digest {
            return Err(mismatch("source_commit_digest"));
        }
        if certificate.source_outcome_digest != expected.source_outcome_digest {
            return Err(mismatch("source_outcome_digest"));
        }
        if certificate.snapshot_hash != expected.snapshot_hash {
            return Err(mismatch("snapshot_hash"));
        }
        if certificate.parent_certificate_hash != expected.parent_certificate_hash {
            return Err(mismatch("parent_certificate_hash"));
        }
        if certificate.manifests != expected.manifests {
            return Err(mismatch("manifests"));
        }
        if certificate.authority_term != expected.authority_term
            || certificate.global_fence_sequence != expected.global_fence_sequence
        {
            return Err(mismatch("immutable frontier"));
        }
        if certificate.expires_at != expected.expires_at {
            return Err(mismatch("expires_at"));
        }
        Ok(())
    }

    /// Reconcile an artifact (or a candidate one) against the durable
    /// bootstrap records. Returns the reconciled outcome when the artifact is
    /// already installed, `None` when nothing durable exists for it.
    ///
    /// Same operation id with a different artifact digest is refused. Every
    /// receipt certificate is recovered HISTORICALLY by its receipt id and
    /// re-verified against the registry (signature, completion digest,
    /// registration) and against the artifact-derived expected content. The
    /// current scope pointer is NOT required to still name the bootstrap
    /// certificate: later legal publications may have advanced it. When the
    /// pointer is read it is only verified (pointer/certificate pair) and
    /// must not have regressed below the bootstrapped frontier.
    async fn readback_bootstrap(
        &self,
        artifact: &AuthorityBootstrapArtifact,
        artifact_digest: &str,
        state: &VerifiedAuthorityState,
    ) -> Result<Option<AuthorityBootstrapOutcome>, AuthorityServiceError> {
        let keys = BootstrapKeys::new(&self.config.quorum.key_prefix);
        let operation_record = self
            .store
            .get(&keys.operation(&artifact.operation_id))
            .await?;
        if let Some(record) = &operation_record {
            let stored: StoredBootstrapOperation = decode(&record.value, "bootstrap operation")?;
            if stored.artifact_digest != artifact_digest {
                // Same operation, different approved content: refuse.
                return Err(AuthorityServiceError::Protocol(
                    AuthorityProtocolError::AlreadyExists {
                        record: "bootstrap_operation",
                    },
                ));
            }
        }
        let receipt_record = match self.store.get(&keys.receipt(artifact_digest)).await? {
            Some(record) => record,
            None => {
                if operation_record.is_some() {
                    // One atomic transaction writes both records; a lone
                    // operation index is durable corruption. Fail closed.
                    return Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                        "bootstrap receipt missing for recorded operation".to_owned(),
                    )));
                }
                return Ok(None);
            }
        };
        if operation_record.is_none() {
            return Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                "bootstrap operation index missing for receipt".to_owned(),
            )));
        }
        let receipt: StoredBootstrapReceipt = decode(&receipt_record.value, "bootstrap receipt")?;
        if receipt.artifact_digest != artifact_digest
            || receipt.operation_id != artifact.operation_id
            || receipt.certificate_ids.len() != artifact.snapshots.len()
            || receipt.certificate_hashes.len() != artifact.snapshots.len()
        {
            return Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                "bootstrap receipt does not match the artifact".to_owned(),
            )));
        }
        let ordered = ordered_bootstrap_snapshots(artifact)?;
        for (index, (scope_key, snapshot)) in ordered.iter().enumerate() {
            let certificate_id = receipt
                .certificate_ids
                .get(index)
                .ok_or_else(|| {
                    AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                        "bootstrap receipt is shorter than the artifact".to_owned(),
                    ))
                })?
                .clone();
            let expected_hash = receipt
                .certificate_hashes
                .get(index)
                .ok_or_else(|| {
                    AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                        "bootstrap receipt is shorter than the artifact".to_owned(),
                    ))
                })?
                .clone();
            // Historical exact recovery: the receipt names the immutable
            // certificate id; the record is loaded by that id, never through
            // the (possibly advanced) current pointer.
            let certificate_record = self
                .store
                .get(&self.keys.certificate(&certificate_id))
                .await?
                .ok_or_else(|| {
                    AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                        "bootstrap certificate is missing".to_owned(),
                    ))
                })?;
            let certificate: AuthorityScopePublicationCertificate =
                decode(&certificate_record.value, "bootstrap certificate")?;
            // Registry verification: signer registration, strict signature,
            // completion-digest recomputation, authority/term/fence bounds.
            certificate_records::verify_certificate_record(state, &certificate_id, &certificate)?;
            // Full field-level re-derivation from the signed artifact.
            let expected = expected_bootstrap_certificate(
                artifact,
                artifact_digest,
                scope_key,
                snapshot,
                index,
            )?;
            self.verify_certificate_matches_artifact(&certificate, &expected)?;
            // The receipt-pinned record digest pins the exact bytes,
            // including the signer binding and install timestamps.
            let certificate_hash = certificate
                .record_digest()
                .map_err(AuthorityServiceError::Protocol)?;
            if certificate_hash != expected_hash {
                return Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                    "bootstrap certificate does not match the receipt-pinned record digest"
                        .to_owned(),
                )));
            }
            // The CURRENT pointer may have legally advanced. When present it
            // is only verified and must not have regressed; it never
            // substitutes for the historical certificate.
            if let Some(publication) = certificate_records::load_verified_scope_publication(
                self.store.as_ref(),
                &self.keys,
                state,
                scope_key,
            )
            .await?
            {
                if publication.pointer.scope_generation < snapshot.generation
                    || publication.pointer.revoke_watermark < snapshot.revoke_watermark
                {
                    return Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                        "current scope pointer regressed below the bootstrapped frontier"
                            .to_owned(),
                    )));
                }
            }
        }
        Ok(Some(AuthorityBootstrapOutcome {
            receipt,
            newly_applied: false,
        }))
    }

    /// Reconcile one bootstrap artifact by stable identity (operation id and
    /// artifact digest). Read-only: never retries, never re-issues, never
    /// requires leadership and never consults the reservation gate, so an
    /// already-installed artifact stays reconcilable while other source
    /// operations are pending. `Ok(None)` means nothing durable exists.
    pub async fn reconcile_bootstrap(
        &self,
        artifact: &AuthorityBootstrapArtifact,
    ) -> Result<Option<AuthorityBootstrapOutcome>, AuthorityServiceError> {
        artifact
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        let state = self.load_verified_state().await?;
        let root_verifying_key = self.bootstrap_root_verifying_key(artifact, &state)?;
        artifact
            .verify(&root_verifying_key)
            .map_err(AuthorityServiceError::Protocol)?;
        let artifact_digest = artifact
            .artifact_digest()
            .map_err(AuthorityServiceError::Protocol)?;
        self.readback_bootstrap(artifact, &artifact_digest, &state)
            .await
    }

    /// Install one root-signed bootstrap artifact as the first scope
    /// certificates. Refuses on a standby, over any blocking reservation,
    /// over any existing scope, and on any frontier divergence from the
    /// artifact's approved exact GLOBAL frontier.
    ///
    /// Order matters: the idempotent read-back runs BEFORE the reservation
    /// gate, so an already-installed artifact reconciles read-only (never
    /// re-issued, never rewritten) even while other source operations are
    /// pending — a legitimate repeat install is never falsely rejected by an
    /// unrelated barrier. The gate is enforced before every FRESH-install
    /// durable write, so a new artifact never lands over an unresolved source
    /// operation. The fully read-only entry point
    /// ([`Self::reconcile_bootstrap`]) additionally requires no leadership.
    pub async fn install_bootstrap(
        &self,
        artifact: &AuthorityBootstrapArtifact,
    ) -> Result<AuthorityBootstrapOutcome, AuthorityServiceError> {
        self.require_leader()?;
        artifact
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        let state = self.load_verified_state().await?;
        let root_verifying_key = self.bootstrap_root_verifying_key(artifact, &state)?;
        // Signature and structure first (no wall clock): this is the check
        // reconciliation shares, so it must not depend on freshness.
        artifact
            .verify(&root_verifying_key)
            .map_err(AuthorityServiceError::Protocol)?;
        let artifact_digest = artifact
            .artifact_digest()
            .map_err(AuthorityServiceError::Protocol)?;
        // Idempotency BEFORE the barrier AND before the active-signer gate:
        // an already-installed artifact reconciles by read-back (read-only,
        // no gate consulted, nothing newly signed) and never re-issues.
        // Historical recovery must not be blocked by a stale local signer.
        if let Some(outcome) = self
            .readback_bootstrap(artifact, &artifact_digest, &state)
            .await?
        {
            return Ok(outcome);
        }
        // Fresh install only: the local signer must be the ACTIVE signer of
        // the verified durable trust root before any new certificate is
        // signed (same helper as startup/mint/prepare/certify/rotation).
        self.require_active_signer(&state)?;
        // Fresh install only: no blocking reservation may exist — bootstrap
        // never lands over an unresolved source operation.
        let read_gate = self.evaluate_read_gate().await?;
        if !read_gate.positive_reads_allowed {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::ReadsBlocked {
                    reservation_id: read_gate
                        .blocking_reservations
                        .first()
                        .map(|summary| summary.reservation_id.clone())
                        .unwrap_or_default(),
                },
            ));
        }
        // A NEW install is time-bound: an expired preflight artifact can
        // never become trust.
        let now = now_unix();
        artifact
            .verify_at(&root_verifying_key, now)
            .map_err(AuthorityServiceError::Protocol)?;
        // The durable GLOBAL frontier must be exactly the approved one; the
        // install CASes the frontier from this exact state.
        if state.frontier.authority_term != artifact.expected_authority_term
            || state.frontier.global_fence_sequence != artifact.expected_global_fence_sequence
            || state.frontier.key_epoch != artifact.expected_key_epoch
            || state.frontier.global_chain_digest != artifact.expected_global_chain_digest
        {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::FrontierDiverged,
            ));
        }

        let ordered = ordered_bootstrap_snapshots(artifact)?;
        let mut entries = Vec::with_capacity(ordered.len());
        let mut certificate_ids = Vec::with_capacity(ordered.len());
        let mut certificate_hashes = Vec::with_capacity(ordered.len());
        for (index, (scope_key, snapshot)) in ordered.iter().enumerate() {
            if self
                .store
                .get(&self.keys.scope_current(scope_key))
                .await?
                .is_some()
            {
                return Err(AuthorityServiceError::Protocol(
                    AuthorityProtocolError::AlreadyExists {
                        record: "scope_publication",
                    },
                ));
            }
            let certificate = self.build_bootstrap_certificate(
                artifact,
                &artifact_digest,
                scope_key,
                snapshot,
                index,
                now,
            )?;
            let certificate_hash = certificate
                .record_digest()
                .map_err(AuthorityServiceError::Protocol)?;
            certificate_ids.push(certificate.certificate_id.clone());
            certificate_hashes.push(certificate_hash.clone());
            entries.push((scope_key.clone(), snapshot, certificate, certificate_hash));
        }

        let mutation_digest =
            astral_types::bootstrap_mutation_digest(&artifact_digest, &certificate_hashes)
                .map_err(AuthorityServiceError::Protocol)?;
        let next_frontier = state
            .frontier
            .advance(&artifact.operation_id, &mutation_digest, now)
            .map_err(AuthorityServiceError::Protocol)?;

        let receipt = StoredBootstrapReceipt {
            artifact_digest: artifact_digest.clone(),
            operation_id: artifact.operation_id.clone(),
            certificate_ids,
            certificate_hashes,
            installed_at: now,
        };
        let bootstrap_keys = BootstrapKeys::new(&self.config.quorum.key_prefix);
        let mut txn = StoreTxn::new()
            .with_op(StoreOp::PutIfAbsent {
                key: bootstrap_keys.operation(&artifact.operation_id),
                value: encode(&StoredBootstrapOperation {
                    artifact_digest: artifact_digest.clone(),
                })?,
            })
            .with_op(StoreOp::PutIfAbsent {
                key: bootstrap_keys.receipt(&artifact_digest),
                value: encode(&receipt)?,
            });
        for (scope_key, snapshot, certificate, certificate_hash) in &entries {
            txn = txn
                .with_op(StoreOp::PutIfAbsent {
                    key: self.keys.certificate(&certificate.certificate_id),
                    value: encode(certificate)?,
                })
                .with_op(StoreOp::PutIfAbsent {
                    key: self.keys.scope_current(scope_key),
                    value: encode(&StoredScopeCurrent {
                        scope_key_text: scope_key.clone(),
                        snapshot_hash: snapshot.snapshot_hash.clone(),
                        scope_generation: snapshot.generation,
                        revoke_watermark: snapshot.revoke_watermark,
                        certificate_hash: certificate_hash.clone(),
                        certificate_id: certificate.certificate_id.clone(),
                        key_epoch: state.frontier.key_epoch,
                        updated_at: now,
                    })?,
                });
        }
        txn = txn
            .with_op(StoreOp::ReplaceIfRevision {
                key: self.keys.frontier(),
                expected_revision: state.frontier_revision,
                value: encode(&next_frontier)?,
            })
            .with_op(self.bump_gate_epoch_op(&state)?);

        // The install commit goes through the shared leadership wrapper: the
        // final transaction is executed only while this instance durably
        // holds leadership (leader_key + leadership token verified by
        // execute_leader_txn). The in-process require_leader() above is only
        // a cheap early refusal; THIS is the durable leadership gate.
        let outcome = match self.execute_leader_txn(txn).await {
            Ok(outcome) => outcome,
            Err(error) => {
                return Err(self.map_store_error(error, &artifact.operation_id));
            }
        };
        match outcome {
            StoreTxnOutcome::Applied { .. } => Ok(AuthorityBootstrapOutcome {
                receipt,
                newly_applied: true,
            }),
            StoreTxnOutcome::PreconditionFailed { key } => {
                // Nothing was written: the state raced (frontier, gate epoch
                // or a scope pointer). Report the conflict; the operator
                // re-runs preflight against the new frontier.
                Err(AuthorityServiceError::Protocol(
                    AuthorityProtocolError::StateConflict {
                        record: "bootstrap_install",
                        state: key,
                    },
                ))
            }
        }
    }
}
