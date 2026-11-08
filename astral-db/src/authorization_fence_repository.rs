//! Durable reader for externally issued authorization-fence proofs.
//!
//! This module is a verifier/adapter, not an authority issuer. The global
//! authority owns the signing key and is responsible for writing the immutable
//! proof row and the current frontier row. The adapter only accepts a proof
//! when the durable authority frontier, the proof row, the fixed trust root and
//! the request scope all agree.
//!
//! A proof is reserved in the existing durable request-guard table in the same
//! short transaction that reads the frontier and proof row. A successful
//! reservation therefore means only that this exact proof was consumed once;
//! it never substitutes for signature verification, frontier comparison or
//! evidence certification. Unknown commit results are returned as errors and
//! the nonce must not be retried.

use std::sync::Arc;

use astral_types::{
    AuthorizationAdmission, AuthorizationAuthorityScope, AuthorizationDomainScope,
    AuthorizationFenceProof, AuthorizationIssuanceLease, CertifiedAuthorizationState,
    DomainScopeRequirement, PolicyError, PublishedCardAuthorization, PublishedCardEvidenceScope,
};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use policy_engine::AuthorizationFenceProvider;
use sha2::{Digest, Sha256};
use sqlx::{MySql, MySqlPool, Transaction};
use time::OffsetDateTime;

use crate::session_state_repository::{GuardClaim, GUARD_SCOPE_AUTHORITY_PROOF_REPLAY};

mod abort;
mod quorum;
mod source_outcome;

pub use abort::{
    abort_source_reservation, SourceAbortOutcome, SourceAbortReport, SourceReservationAbort,
    SourceReservationAbortGateway,
};
pub use source_outcome::{
    stage_admitted_source_outcome_in_tx, stage_admitted_source_outcome_with_coverage_in_tx,
};

/// Maximum accepted proof lifetime for a request-bound read proof.
///
/// A bounded window keeps the durable replay reservation finite without making
/// a still-valid proof replayable after its guard row expires. The authority
/// may issue a shorter proof; it may not silently widen this verifier's window.
pub const MAX_AUTHORITY_PROOF_WINDOW_SECONDS: i64 = 300;
const AUTHORITY_PROOF_REPLAY_KEY_DOMAIN: &[u8] = b"ASTRAL_AUTHORITY_PROOF_REPLAY_V1\0";
const AUTHORITY_FRONTIER_ROW_ID: i64 = 1;
const REPLAY_GUARD_SKEW_SECONDS: i64 = 60;

/// Fixed public trust-root configuration for one logical authorization
/// authority. No private key or issuer capability is held by this adapter.
pub struct AuthorizationTrustRoot {
    authority_id: String,
    key_id: String,
    key_epoch: u64,
    verifying_key: VerifyingKey,
}

impl AuthorizationTrustRoot {
    pub fn new(
        authority_id: String,
        key_id: String,
        key_epoch: u64,
        verifying_key: VerifyingKey,
    ) -> Result<Self, PolicyError> {
        if authority_id.trim().is_empty() || authority_id.len() > 128 {
            return Err(PolicyError::Repository(
                "authorization trust root authority id is invalid".to_owned(),
            ));
        }
        if key_id.trim().is_empty() || key_id.len() > 128 || key_epoch == 0 {
            return Err(PolicyError::Repository(
                "authorization trust root key identity is invalid".to_owned(),
            ));
        }
        Ok(Self {
            authority_id,
            key_id,
            key_epoch,
            verifying_key,
        })
    }

    pub fn authority_id(&self) -> &str {
        &self.authority_id
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
}

/// Public trust root for the external arbiter that leases an exact authority
/// frontier to the database-backed signer.
///
/// This root contains no signing capability. Rotation is explicit: a lease
/// signed by another arbiter key is rejected until the deployment installs a
/// new, separately approved trust root.
pub struct AuthorizationArbiterTrustRoot {
    arbiter_id: String,
    key_id: String,
    key_epoch: u64,
    verifying_key: VerifyingKey,
}

impl AuthorizationArbiterTrustRoot {
    pub fn new(
        arbiter_id: String,
        key_id: String,
        key_epoch: u64,
        verifying_key: VerifyingKey,
    ) -> Result<Self, PolicyError> {
        if arbiter_id.trim().is_empty() || arbiter_id.len() > 128 {
            return Err(PolicyError::Repository(
                "authorization arbiter id is invalid".to_owned(),
            ));
        }
        if key_id.trim().is_empty() || key_id.len() > 128 || key_epoch == 0 {
            return Err(PolicyError::Repository(
                "authorization arbiter key identity is invalid".to_owned(),
            ));
        }
        Ok(Self {
            arbiter_id,
            key_id,
            key_epoch,
            verifying_key,
        })
    }

    fn verify_lease(
        &self,
        lease: &AuthorizationIssuanceLease,
        now_seconds: i64,
    ) -> Result<(), PolicyError> {
        if lease.arbiter_id != self.arbiter_id
            || lease.arbiter_key_id != self.key_id
            || lease.arbiter_key_epoch != self.key_epoch
        {
            return Err(PolicyError::Repository(
                "authorization issuance lease arbiter trust root identity mismatch".to_owned(),
            ));
        }
        lease
            .verify_at(&self.verifying_key, now_seconds)
            .map_err(|error| {
                PolicyError::Repository(format!(
                    "authorization issuance lease arbiter signature verification failed: {error}"
                ))
            })
    }
}

/// Stable identity of the currently durable authority frontier.
///
/// This is readback evidence only. It is never an authority capability and it
/// cannot mint, extend, or refresh a proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityFrontierIdentity {
    pub authority_id: String,
    pub authority_term: u64,
    pub global_fence_sequence: u64,
    pub key_id: String,
    pub key_epoch: u64,
    pub snapshot_hash: Option<String>,
    pub status: String,
}

/// Read-only outcome of reconciling an authority issuance operation by its
/// stable lease identity. An `Unknown` result is intentionally terminal for the
/// caller until an independent readback proves a durable state; it is not a
/// retry instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum IssuanceLeaseReconciliation {
    Pending {
        lease_id: String,
        request_nonce: String,
    },
    Ready {
        lease_id: String,
        request_nonce: String,
        completion_hash: String,
        generation: u64,
        revoke_watermark: u64,
    },
    Consumed {
        proof: Box<AuthorizationFenceProof>,
        frontier: AuthorityFrontierIdentity,
    },
    Unknown {
        lease_id: String,
        reason: String,
    },
}

/// The only durable writer for the authority frontier and proof tables.
///
/// The issuer does not create an authority term or global fence. An external
/// arbiter signs an exact [`AuthorizationIssuanceLease`]; this component
/// verifies that lease, consumes it once, signs the corresponding proof, and
/// atomically persists the proof and frontier transition. The signing key must
/// be supplied by a protected deployment boundary and is never serialized by
/// this module.
pub struct SqlxAuthorizationAuthorityIssuer {
    pool: MySqlPool,
    trust_root: Arc<AuthorizationTrustRoot>,
    signing_key: Arc<SigningKey>,
    arbiter_trust_root: Arc<AuthorizationArbiterTrustRoot>,
}

impl SqlxAuthorizationAuthorityIssuer {
    pub fn new(
        pool: MySqlPool,
        trust_root: AuthorizationTrustRoot,
        signing_key: SigningKey,
        arbiter_trust_root: AuthorizationArbiterTrustRoot,
    ) -> Result<Self, PolicyError> {
        if signing_key.verifying_key().to_bytes() != trust_root.verifying_key.to_bytes() {
            return Err(PolicyError::Repository(
                "authorization issuer signing key does not match the configured trust root"
                    .to_owned(),
            ));
        }
        Ok(Self {
            pool,
            trust_root: Arc::new(trust_root),
            signing_key: Arc::new(signing_key),
            arbiter_trust_root: Arc::new(arbiter_trust_root),
        })
    }

    pub fn trust_root(&self) -> &AuthorizationTrustRoot {
        &self.trust_root
    }

    /// Reconcile one issuance lease by stable identity after an unknown
    /// transaction result. This method is read-only: it never retries ingress,
    /// consumes a lease, advances the frontier, or mints a proof.
    pub async fn reconcile_issuance_lease(
        &self,
        lease_id: &str,
    ) -> Result<IssuanceLeaseReconciliation, PolicyError> {
        validate_lease_id(lease_id)?;
        let mut tx = self.pool.begin().await.map_err(|error| {
            PolicyError::Repository(format!(
                "authorization issuance reconciliation transaction begin failed: {error}"
            ))
        })?;
        let row = sqlx::query_as::<_, DurableAuthorityIssuanceLeaseRow>(&format!(
            "SELECT {AUTHORITY_LEASE_ROW_COLUMNS} \
             FROM authorization_authority_issuance_lease \
             WHERE lease_id = ? FOR UPDATE"
        ))
        .bind(lease_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| {
            PolicyError::Repository(format!(
                "authorization issuance reconciliation lease read failed: {error}"
            ))
        })?;

        let Some(row) = row else {
            tx.rollback().await.map_err(|error| {
                PolicyError::Repository(format!(
                    "authorization issuance reconciliation rollback failed: {error}"
                ))
            })?;
            return Ok(IssuanceLeaseReconciliation::Unknown {
                lease_id: lease_id.to_owned(),
                reason: "durable issuance lease row is absent".to_owned(),
            });
        };

        let status = row.status.clone();
        let completion_hash = row.publication_completion_hash.clone().map(hex::encode);
        let completion_generation = row.publication_completion_generation;
        let completion_revoke_watermark = row.publication_completion_revoke_watermark;
        let lease = match row.into_lease() {
            Ok(lease) => lease,
            Err(error) => {
                tx.rollback().await.map_err(|rollback_error| {
                    PolicyError::Repository(format!(
                        "authorization issuance reconciliation rollback failed after invalid lease: {rollback_error}"
                    ))
                })?;
                return Ok(IssuanceLeaseReconciliation::Unknown {
                    lease_id: lease_id.to_owned(),
                    reason: format!("durable issuance lease identity is invalid: {error}"),
                });
            }
        };
        if lease.lease_id != lease_id {
            tx.rollback().await.map_err(|error| {
                PolicyError::Repository(format!(
                    "authorization issuance reconciliation rollback failed: {error}"
                ))
            })?;
            return Ok(IssuanceLeaseReconciliation::Unknown {
                lease_id: lease_id.to_owned(),
                reason: "durable issuance lease identity does not match the lookup key".to_owned(),
            });
        }
        verify_lease_signature_without_time(&self.arbiter_trust_root, &lease).map_err(|error| {
            PolicyError::Repository(format!(
                "authorization issuance reconciliation lease signature is invalid: {error}"
            ))
        })?;

        let outcome = match status.as_str() {
            "PENDING" => IssuanceLeaseReconciliation::Pending {
                lease_id: lease.lease_id.clone(),
                request_nonce: lease.request_nonce.clone(),
            },
            "READY" | "CONSUMED" => {
                let stored_hash = completion_hash.ok_or_else(|| {
                    PolicyError::Repository(
                        "authorization issuance reconciliation completion hash is missing"
                            .to_owned(),
                    )
                })?;
                let stored_generation = completion_generation.ok_or_else(|| {
                    PolicyError::Repository(
                        "authorization issuance reconciliation completion generation is missing"
                            .to_owned(),
                    )
                })?;
                let stored_revoke_watermark = completion_revoke_watermark.ok_or_else(|| {
                    PolicyError::Repository(
                        "authorization issuance reconciliation completion revoke watermark is missing"
                            .to_owned(),
                    )
                })?;
                let evidence_scope = evidence_scope_from_authority_scope(&lease.scope)?;
                let evidence =
                    crate::authorization_projection_repository::load_published_card_grant_evidence_in_tx(
                        &mut tx,
                        &evidence_scope,
                    )
                    .await
                    .map_err(|error| {
                        PolicyError::Repository(format!(
                            "authorization issuance reconciliation publication evidence is unavailable: {error}"
                        ))
                    })?;
                let expected_hash = lease
                    .publication_completion_digest(&evidence)
                    .map_err(|error| {
                        PolicyError::Repository(format!(
                            "authorization issuance reconciliation completion identity mismatch: {error}"
                        ))
                    })?;
                let expected_hash = digest_bytes(&expected_hash, "publication_completion_hash")?;
                if stored_hash != hex::encode(&expected_hash)
                    || stored_generation != lease.scope_generation as i64
                    || stored_revoke_watermark != lease.revoke_watermark as i64
                {
                    return finish_issuance_reconciliation_unknown(
                        &mut tx,
                        lease_id,
                        "durable publication completion does not match the lease frontier",
                    )
                    .await;
                }
                if status == "READY" {
                    IssuanceLeaseReconciliation::Ready {
                        lease_id: lease.lease_id.clone(),
                        request_nonce: lease.request_nonce.clone(),
                        completion_hash: hex::encode(expected_hash),
                        generation: lease.scope_generation,
                        revoke_watermark: lease.revoke_watermark,
                    }
                } else {
                    let frontier = lock_authority_frontier(&mut tx).await?;
                    let proof_row = sqlx::query_as::<_, DurableAuthorityProofRow>(
                        "SELECT proof_id, request_nonce, authorization_edition, authority_id, \
                                authority_term, global_fence_sequence, tenant_id, card_id, \
                                scope_user_id, scope_domain_kind, scope_domain_id, scope_generation, \
                                revoke_watermark, snapshot_hash, parent_hash, operation_id, \
                                event_id, key_id, key_epoch, issued_at, not_before, expires_at, \
                                signature, status \
                         FROM authorization_authority_proof \
                         WHERE proof_id = ? AND request_nonce = ? FOR UPDATE",
                    )
                    .bind(&lease.lease_id)
                    .bind(&lease.request_nonce)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|error| {
                        PolicyError::Repository(format!(
                            "authorization issuance reconciliation proof read failed: {error}"
                        ))
                    })?;
                    let Some(proof_row) = proof_row else {
                        return finish_issuance_reconciliation_unknown(
                            &mut tx,
                            lease_id,
                            "consumed lease has no matching durable proof",
                        )
                        .await;
                    };
                    let proof = match proof_row.into_proof() {
                        Ok(proof) => proof,
                        Err(error) => {
                            return finish_issuance_reconciliation_unknown(
                                &mut tx,
                                lease_id,
                                &format!("consumed proof is invalid: {error}"),
                            )
                            .await;
                        }
                    };
                    if !proof_matches_lease(&proof, &lease)
                        || !proof_matches_frontier(&proof, &frontier)?
                    {
                        return finish_issuance_reconciliation_unknown(
                            &mut tx,
                            lease_id,
                            "consumed proof and authority frontier do not match the lease",
                        )
                        .await;
                    }
                    verify_proof_signature_without_time(&self.trust_root, &proof)?;
                    IssuanceLeaseReconciliation::Consumed {
                        proof: Box::new(proof),
                        frontier: frontier.into_identity()?,
                    }
                }
            }
            other => {
                return finish_issuance_reconciliation_unknown(
                    &mut tx,
                    lease_id,
                    &format!("unsupported durable issuance lease status: {other}"),
                )
                .await;
            }
        };
        tx.rollback().await.map_err(|error| {
            PolicyError::Repository(format!(
                "authorization issuance reconciliation rollback failed: {error}"
            ))
        })?;
        Ok(outcome)
    }

    /// Ingest one exact lease from the external arbiter.
    ///
    /// Ingestion is deliberately not publication completion: the row starts in
    /// `PENDING` and cannot be consumed by the authority signer until
    /// [`Self::mark_issuance_lease_ready`] proves the durable published evidence
    /// in a separate locked transaction. Re-submitting the byte-identical lease
    /// is idempotent; any identity or payload conflict is rejected.
    pub async fn ingest_issuance_lease(
        &self,
        lease: &AuthorizationIssuanceLease,
    ) -> Result<(), PolicyError> {
        let now_seconds = OffsetDateTime::now_utc().unix_timestamp();
        self.arbiter_trust_root.verify_lease(lease, now_seconds)?;
        let mut tx = self.pool.begin().await.map_err(|error| {
            PolicyError::Repository(format!(
                "authorization issuance lease ingress transaction begin failed: {error}"
            ))
        })?;

        let existing = sqlx::query_as::<_, DurableAuthorityIssuanceLeaseRow>(
            "SELECT lease_id, request_nonce, authorization_edition, authority_id, \
                    authority_term, global_fence_sequence, previous_authority_term, \
                    previous_global_fence_sequence, previous_key_id, previous_key_epoch, \
                    tenant_id, card_id, scope_user_id, scope_domain_kind, scope_domain_id, \
                    scope_generation, revoke_watermark, snapshot_hash, parent_hash, \
                    operation_id, event_id, key_id, key_epoch, issued_at, not_before, \
                    expires_at, arbiter_id, arbiter_key_id, arbiter_key_epoch, \
                    arbiter_signature, status, consumed_at, publication_completion_hash, \
                    publication_completion_generation, publication_completion_revoke_watermark, \
                    publication_completion_at \
             FROM authorization_authority_issuance_lease \
             WHERE lease_id = ? FOR UPDATE",
        )
        .bind(&lease.lease_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| {
            PolicyError::Repository(format!(
                "authorization issuance lease ingress lookup failed: {error}"
            ))
        })?;
        if let Some(existing) = existing {
            let existing_lease = existing.into_lease()?;
            if existing_lease != *lease {
                return Err(PolicyError::Repository(
                    "authorization issuance lease identity conflict".to_owned(),
                ));
            }
            tx.commit().await.map_err(|error| {
                PolicyError::Repository(format!(
                    "authorization issuance lease ingress idempotency commit is unknown: {error}"
                ))
            })?;
            return Ok(());
        }

        let duplicate_nonce = sqlx::query_scalar::<_, String>(
            "SELECT lease_id FROM authorization_authority_issuance_lease \
             WHERE request_nonce = ? FOR UPDATE",
        )
        .bind(&lease.request_nonce)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| {
            PolicyError::Repository(format!(
                "authorization issuance lease nonce lookup failed: {error}"
            ))
        })?;
        if duplicate_nonce.is_some() {
            return Err(PolicyError::Repository(
                "authorization issuance lease request nonce is already reserved".to_owned(),
            ));
        }

        let (scope_domain_kind, scope_domain_id) = lease_scope_columns(&lease.scope);
        let snapshot_hash = digest_bytes(&lease.snapshot_hash, "snapshot_hash")?;
        let parent_hash = lease
            .parent_hash
            .as_deref()
            .map(|value| digest_bytes(value, "parent_hash"))
            .transpose()?;
        let arbiter_signature = signature_bytes(&lease.arbiter_signature)?;
        sqlx::query(
            "INSERT INTO authorization_authority_issuance_lease \
             (lease_id, request_nonce, authorization_edition, authority_id, authority_term, \
              global_fence_sequence, previous_authority_term, previous_global_fence_sequence, \
              previous_key_id, previous_key_epoch, tenant_id, card_id, scope_user_id, \
              scope_domain_kind, scope_domain_id, scope_generation, revoke_watermark, \
              snapshot_hash, parent_hash, operation_id, event_id, key_id, key_epoch, \
              issued_at, not_before, expires_at, arbiter_id, arbiter_key_id, \
              arbiter_key_epoch, arbiter_signature, status) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, \
                     ?, ?, ?, ?, ?, ?, ?, 'PENDING')",
        )
        .bind(&lease.lease_id)
        .bind(&lease.request_nonce)
        .bind(lease.authorization_edition)
        .bind(&lease.authority_id)
        .bind(lease.authority_term as i64)
        .bind(lease.global_fence_sequence as i64)
        .bind(lease.previous_authority_term as i64)
        .bind(lease.previous_global_fence_sequence as i64)
        .bind(&lease.previous_key_id)
        .bind(lease.previous_key_epoch as i64)
        .bind(lease.scope.tenant_id)
        .bind(lease.scope.card_id)
        .bind(lease.scope.user_id)
        .bind(scope_domain_kind)
        .bind(scope_domain_id)
        .bind(lease.scope_generation as i64)
        .bind(lease.revoke_watermark as i64)
        .bind(snapshot_hash)
        .bind(parent_hash)
        .bind(&lease.operation_id)
        .bind(&lease.event_id)
        .bind(&lease.key_id)
        .bind(lease.key_epoch as i64)
        .bind(lease.issued_at)
        .bind(lease.not_before)
        .bind(lease.expires_at)
        .bind(&lease.arbiter_id)
        .bind(&lease.arbiter_key_id)
        .bind(lease.arbiter_key_epoch as i64)
        .bind(arbiter_signature)
        .execute(&mut *tx)
        .await
        .map_err(|error| {
            PolicyError::Repository(format!(
                "authorization issuance lease ingress insert failed: {error}"
            ))
        })?;
        tx.commit().await.map_err(|error| {
            PolicyError::Repository(format!(
                "authorization issuance lease ingress commit is unknown: {error}"
            ))
        })?;
        Ok(())
    }

    /// Prove publication completion and atomically move one ingested lease to
    /// `READY`. The strict evidence reader locks every current pointer and
    /// verifies the committed manifest/segment chain before the CAS. No caller
    /// supplied snapshot or ACK is accepted as completion evidence.
    pub async fn mark_issuance_lease_ready(&self, lease_id: &str) -> Result<(), PolicyError> {
        validate_lease_id(lease_id)?;
        let now_seconds = OffsetDateTime::now_utc().unix_timestamp();
        let mut tx = self.pool.begin().await.map_err(|error| {
            PolicyError::Repository(format!(
                "authorization issuance completion transaction begin failed: {error}"
            ))
        })?;
        let lease_row = load_issuance_lease_row_for_update(&mut tx, lease_id).await?;
        if lease_row.status == "READY" || lease_row.status == "CONSUMED" {
            validate_ready_completion_columns(&lease_row)?;
            tx.commit().await.map_err(|error| {
                PolicyError::Repository(format!(
                    "authorization issuance completion idempotency commit is unknown: {error}"
                ))
            })?;
            return Ok(());
        }
        if lease_row.status != "PENDING" {
            return Err(PolicyError::Repository(format!(
                "authorization issuance lease is not pending: {}",
                lease_row.status
            )));
        }
        let lease = lease_row.into_lease()?;
        self.arbiter_trust_root.verify_lease(&lease, now_seconds)?;
        ensure_authority_frontier_bootstrap(&mut tx, self.trust_root.authority_id()).await?;
        let frontier = lock_authority_frontier(&mut tx).await?;
        validate_issuer_frontier(&frontier, &lease, &self.trust_root)?;
        let evidence_scope = evidence_scope_from_authority_scope(&lease.scope)?;
        let evidence =
            crate::authorization_projection_repository::load_published_card_grant_evidence_in_tx(
                &mut tx,
                &evidence_scope,
            )
            .await
            .map_err(|error| {
                PolicyError::Repository(format!(
                    "authorization publication completion evidence is not durable: {error}"
                ))
            })?;
        let completion_hash = lease
            .publication_completion_digest(&evidence)
            .map_err(|error| {
                PolicyError::Repository(format!(
                    "authorization publication completion identity mismatch: {error}"
                ))
            })?;
        let updated = sqlx::query(
            "UPDATE authorization_authority_issuance_lease \
             SET publication_completion_hash = ?, publication_completion_generation = ?, \
                 publication_completion_revoke_watermark = ?, publication_completion_at = ?, \
                 status = 'READY' \
             WHERE lease_id = ? AND status = 'PENDING' \
               AND publication_completion_hash IS NULL",
        )
        .bind(digest_bytes(
            &completion_hash,
            "publication_completion_hash",
        )?)
        .bind(lease.scope_generation as i64)
        .bind(lease.revoke_watermark as i64)
        .bind(now_seconds)
        .bind(&lease.lease_id)
        .execute(&mut *tx)
        .await
        .map_err(|error| {
            PolicyError::Repository(format!(
                "authorization issuance lease READY CAS failed: {error}"
            ))
        })?;
        if updated.rows_affected() != 1 {
            return Err(PolicyError::Repository(
                "authorization issuance lease READY CAS lost".to_owned(),
            ));
        }
        tx.commit().await.map_err(|error| {
            PolicyError::Repository(format!(
                "authorization issuance completion commit is unknown: {error}"
            ))
        })?;
        Ok(())
    }

    /// Consume one externally issued lease and publish its proof/frontier in a
    /// single short transaction. A commit error is deliberately reported as
    /// unknown: the caller must reconcile the lease and proof rows before any
    /// retry.
    pub async fn consume_issuance_lease(
        &self,
        lease_id: &str,
    ) -> Result<AuthorizationFenceProof, PolicyError> {
        validate_lease_id(lease_id)?;
        let now_seconds = OffsetDateTime::now_utc().unix_timestamp();
        let mut tx = self.pool.begin().await.map_err(|error| {
            PolicyError::Repository(format!(
                "authorization authority issuer transaction begin failed: {error}"
            ))
        })?;

        sqlx::query(
            "INSERT INTO authorization_authority_frontier \
             (frontier_id, authority_id, authority_term, global_fence_sequence, key_id, key_epoch, snapshot_hash, status) \
             VALUES (?, ?, 0, 0, '-', 0, NULL, 'COLD') \
             ON DUPLICATE KEY UPDATE frontier_id = frontier_id",
        )
        .bind(AUTHORITY_FRONTIER_ROW_ID)
        .bind(self.trust_root.authority_id())
        .execute(&mut *tx)
        .await
        .map_err(|error| {
            PolicyError::Repository(format!(
                "authorization authority frontier bootstrap failed: {error}"
            ))
        })?;

        let frontier = sqlx::query_as::<_, AuthorityFrontierRow>(
            "SELECT authority_id, authority_term, global_fence_sequence, key_id, key_epoch, \
                    snapshot_hash, status \
             FROM authorization_authority_frontier \
             WHERE frontier_id = ? FOR UPDATE",
        )
        .bind(AUTHORITY_FRONTIER_ROW_ID)
        .fetch_one(&mut *tx)
        .await
        .map_err(|error| {
            PolicyError::Repository(format!(
                "authorization authority issuer frontier lock failed: {error}"
            ))
        })?;

        let lease_row = sqlx::query_as::<_, DurableAuthorityIssuanceLeaseRow>(&format!(
            "SELECT {AUTHORITY_LEASE_ROW_COLUMNS} \
                 FROM authorization_authority_issuance_lease \
                 WHERE lease_id = ? FOR UPDATE"
        ))
        .bind(lease_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| {
            PolicyError::Repository(format!("authorization issuance lease lock failed: {error}"))
        })?
        .ok_or_else(|| {
            PolicyError::Repository(
                "authorization issuance lease is unavailable; proof remains pending".to_owned(),
            )
        })?;

        if lease_row.status != "READY" {
            return Err(PolicyError::Repository(format!(
                "authorization issuance lease is not READY: {}",
                lease_row.status
            )));
        }
        validate_ready_completion_columns(&lease_row)?;
        if lease_row.consumed_at.is_some() {
            return Err(PolicyError::Repository(
                "authorization issuance lease is marked READY after consumption".to_owned(),
            ));
        }
        let stored_completion_hash = lease_row.publication_completion_hash.clone();
        let stored_completion_generation = lease_row.publication_completion_generation;
        let stored_completion_revoke_watermark = lease_row.publication_completion_revoke_watermark;
        let lease = lease_row.into_lease()?;
        lease.validate_at(now_seconds).map_err(|error| {
            PolicyError::Repository(format!(
                "authorization issuance lease validation failed: {error}"
            ))
        })?;
        self.arbiter_trust_root.verify_lease(&lease, now_seconds)?;
        validate_issuer_frontier(&frontier, &lease, &self.trust_root)?;

        let evidence_scope = evidence_scope_from_authority_scope(&lease.scope)?;
        let evidence = crate::authorization_projection_repository::load_published_card_grant_evidence_in_tx(
            &mut tx,
            &evidence_scope,
        )
        .await
        .map_err(|error| {
            PolicyError::Repository(format!(
                "authorization publication completion evidence is not durable at consumption: {error}"
            ))
        })?;
        let completion_hash = lease
            .publication_completion_digest(&evidence)
            .map_err(|error| {
                PolicyError::Repository(format!(
                    "authorization publication completion identity mismatch at consumption: {error}"
                ))
            })?;
        let completion_hash = digest_bytes(&completion_hash, "publication_completion_hash")?;
        if stored_completion_hash.as_deref() != Some(completion_hash.as_slice())
            || stored_completion_generation != Some(lease.scope_generation as i64)
            || stored_completion_revoke_watermark != Some(lease.revoke_watermark as i64)
        {
            return Err(PolicyError::Repository(
                "authorization issuance lease publication completion is stale or inconsistent"
                    .to_owned(),
            ));
        }

        let proof = lease.sign_proof(&self.signing_key).map_err(|error| {
            PolicyError::Repository(format!(
                "authorization authority proof signing failed: {error}"
            ))
        })?;
        let frontier_snapshot_hash = digest_bytes(&lease.snapshot_hash, "snapshot_hash")?;
        proof
            .verify_at(self.trust_root.verifying_key(), now_seconds)
            .map_err(|error| {
                PolicyError::Repository(format!(
                    "authorization authority proof self-verification failed: {error}"
                ))
            })?;

        insert_authority_proof(&mut tx, &proof).await?;

        let lease_update = sqlx::query(
            "UPDATE authorization_authority_issuance_lease \
             SET status = 'CONSUMED', consumed_at = ? \
             WHERE lease_id = ? AND status = 'READY'",
        )
        .bind(now_seconds)
        .bind(&lease.lease_id)
        .execute(&mut *tx)
        .await
        .map_err(|error| {
            PolicyError::Repository(format!(
                "authorization issuance lease consumption failed: {error}"
            ))
        })?;
        if lease_update.rows_affected() != 1 {
            return Err(PolicyError::Repository(
                "authorization issuance lease consumption CAS failed".to_owned(),
            ));
        }

        let frontier_update = sqlx::query(
            "UPDATE authorization_authority_frontier \
             SET authority_id = ?, authority_term = ?, global_fence_sequence = ?, \
                 key_id = ?, key_epoch = ?, snapshot_hash = ?, status = 'SERVING' \
             WHERE frontier_id = ? AND authority_id = ? AND authority_term = ? \
               AND global_fence_sequence = ? AND key_id = ? AND key_epoch = ? \
               AND status = ? \
               AND (snapshot_hash <=> ?)",
        )
        .bind(&lease.authority_id)
        .bind(lease.authority_term as i64)
        .bind(lease.global_fence_sequence as i64)
        .bind(&lease.key_id)
        .bind(lease.key_epoch as i64)
        .bind(frontier_snapshot_hash)
        .bind(AUTHORITY_FRONTIER_ROW_ID)
        .bind(&frontier.authority_id)
        .bind(frontier.authority_term)
        .bind(frontier.global_fence_sequence)
        .bind(&frontier.key_id)
        .bind(frontier.key_epoch)
        .bind(&frontier.status)
        .bind(frontier.snapshot_hash.as_deref())
        .execute(&mut *tx)
        .await
        .map_err(|error| {
            PolicyError::Repository(format!(
                "authorization authority frontier transition failed: {error}"
            ))
        })?;
        if frontier_update.rows_affected() != 1 {
            return Err(PolicyError::Repository(
                "authorization authority frontier transition CAS failed".to_owned(),
            ));
        }

        tx.commit().await.map_err(|error| {
            PolicyError::Repository(format!(
                "authorization authority issuer commit is unknown: {error}"
            ))
        })?;
        Ok(proof)
    }
}

async fn insert_authority_proof(
    tx: &mut Transaction<'_, MySql>,
    proof: &AuthorizationFenceProof,
) -> Result<(), PolicyError> {
    let snapshot_hash = digest_bytes(&proof.snapshot_hash, "snapshot_hash")?;
    let parent_hash = proof
        .parent_hash
        .as_deref()
        .map(|hash| digest_bytes(hash, "parent_hash"))
        .transpose()?;
    let signature = signature_bytes(&proof.signature)?;
    let scope_domain_id = match proof.scope.domain {
        AuthorizationDomainScope::Exact(domain_id) => Some(domain_id),
        AuthorizationDomainScope::Any | AuthorizationDomainScope::NoDomain => None,
    };
    let scope_domain_kind = match proof.scope.domain {
        AuthorizationDomainScope::Any => "ANY",
        AuthorizationDomainScope::NoDomain => "NO_DOMAIN",
        AuthorizationDomainScope::Exact(_) => "EXACT",
    };
    sqlx::query(
        "INSERT INTO authorization_authority_proof \
         (proof_id, request_nonce, authorization_edition, authority_id, authority_term, \
          global_fence_sequence, tenant_id, card_id, scope_user_id, scope_domain_kind, \
          scope_domain_id, scope_generation, revoke_watermark, snapshot_hash, parent_hash, \
          operation_id, event_id, key_id, key_epoch, issued_at, not_before, expires_at, \
          signature, status) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE')",
    )
    .bind(&proof.proof_id)
    .bind(&proof.request_nonce)
    .bind(proof.authorization_edition)
    .bind(&proof.authority_id)
    .bind(proof.authority_term as i64)
    .bind(proof.global_fence_sequence as i64)
    .bind(proof.scope.tenant_id)
    .bind(proof.scope.card_id)
    .bind(proof.scope.user_id)
    .bind(scope_domain_kind)
    .bind(scope_domain_id)
    .bind(proof.scope_generation as i64)
    .bind(proof.revoke_watermark as i64)
    .bind(snapshot_hash)
    .bind(parent_hash)
    .bind(&proof.operation_id)
    .bind(&proof.event_id)
    .bind(&proof.key_id)
    .bind(proof.key_epoch as i64)
    .bind(proof.issued_at)
    .bind(proof.not_before)
    .bind(proof.expires_at)
    .bind(signature)
    .execute(&mut **tx)
    .await
    .map_err(|error| {
        PolicyError::Repository(format!(
            "authorization authority proof insertion failed: {error}"
        ))
    })?;
    Ok(())
}

fn validate_issuer_frontier(
    frontier: &AuthorityFrontierRow,
    lease: &AuthorizationIssuanceLease,
    trust_root: &AuthorizationTrustRoot,
) -> Result<(), PolicyError> {
    if lease.authority_id != trust_root.authority_id
        || lease.key_id != trust_root.key_id
        || lease.key_epoch != trust_root.key_epoch
    {
        return Err(PolicyError::Repository(
            "authorization issuance lease authority trust root identity mismatch".to_owned(),
        ));
    }
    let current_term = counter(frontier.authority_term, "frontier.authority_term")?;
    let current_fence = counter(
        frontier.global_fence_sequence,
        "frontier.global_fence_sequence",
    )?;
    let current_key_epoch = counter(frontier.key_epoch, "frontier.key_epoch")?;
    let bootstrap = current_term == 0
        && current_fence == 0
        && frontier.key_id == "-"
        && current_key_epoch == 0
        && frontier.status == "COLD";
    if !bootstrap && frontier.status != "SERVING" {
        return Err(PolicyError::Repository(
            "authorization authority frontier is not issuable".to_owned(),
        ));
    }
    if frontier.authority_id != trust_root.authority_id {
        return Err(PolicyError::Repository(
            "authorization authority frontier identity mismatch".to_owned(),
        ));
    }
    if lease.previous_authority_term != current_term
        || lease.previous_global_fence_sequence != current_fence
        || lease.previous_key_id != frontier.key_id
        || lease.previous_key_epoch != current_key_epoch
    {
        return Err(PolicyError::Repository(
            "authorization issuance lease parent frontier mismatch".to_owned(),
        ));
    }
    if bootstrap {
        if lease.parent_hash.is_some() || frontier.snapshot_hash.is_some() {
            return Err(PolicyError::Repository(
                "bootstrap authority frontier must not carry a parent snapshot hash".to_owned(),
            ));
        }
    } else {
        let frontier_snapshot_hash = frontier.snapshot_hash.as_deref().ok_or_else(|| {
            PolicyError::Repository(
                "served authority frontier has no durable snapshot hash".to_owned(),
            )
        })?;
        let lease_parent_hash = lease
            .parent_hash
            .as_deref()
            .map(|hash| digest_bytes(hash, "parent_hash"))
            .transpose()?;
        if frontier_snapshot_hash.len() != 32
            || lease_parent_hash.as_deref() != Some(frontier_snapshot_hash)
        {
            return Err(PolicyError::Repository(
                "authorization issuance lease parent snapshot hash mismatch".to_owned(),
            ));
        }
    }
    if lease.authority_term < current_term
        || lease.global_fence_sequence <= current_fence
        || lease.key_epoch < current_key_epoch
    {
        return Err(PolicyError::Repository(
            "authorization issuance lease frontier is not strictly newer".to_owned(),
        ));
    }
    if !bootstrap && lease.authority_term == current_term && lease.key_id != frontier.key_id {
        return Err(PolicyError::Repository(
            "authorization issuance lease changed key without a new authority term".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Debug, sqlx::FromRow)]
struct DurableAuthorityIssuanceLeaseRow {
    lease_id: String,
    request_nonce: String,
    authorization_edition: u16,
    authority_id: String,
    authority_term: i64,
    global_fence_sequence: i64,
    previous_authority_term: i64,
    previous_global_fence_sequence: i64,
    previous_key_id: String,
    previous_key_epoch: i64,
    tenant_id: i64,
    card_id: i64,
    scope_user_id: Option<i64>,
    scope_domain_kind: String,
    scope_domain_id: Option<i64>,
    scope_generation: i64,
    revoke_watermark: i64,
    snapshot_hash: Vec<u8>,
    parent_hash: Option<Vec<u8>>,
    operation_id: String,
    event_id: String,
    key_id: String,
    key_epoch: i64,
    issued_at: i64,
    not_before: i64,
    expires_at: i64,
    arbiter_id: String,
    arbiter_key_id: String,
    arbiter_key_epoch: i64,
    arbiter_signature: Vec<u8>,
    status: String,
    consumed_at: Option<i64>,
    publication_completion_hash: Option<Vec<u8>>,
    publication_completion_generation: Option<i64>,
    publication_completion_revoke_watermark: Option<i64>,
    publication_completion_at: Option<i64>,
}

impl DurableAuthorityIssuanceLeaseRow {
    fn into_lease(self) -> Result<AuthorizationIssuanceLease, PolicyError> {
        let domain = match (self.scope_domain_kind.as_str(), self.scope_domain_id) {
            ("ANY", None) => AuthorizationDomainScope::Any,
            ("NO_DOMAIN", None) => AuthorizationDomainScope::NoDomain,
            ("EXACT", Some(domain_id)) => AuthorizationDomainScope::Exact(domain_id),
            _ => {
                return Err(PolicyError::Repository(
                    "authorization issuance lease domain encoding is invalid".to_owned(),
                ));
            }
        };
        let lease = AuthorizationIssuanceLease {
            authorization_edition: self.authorization_edition,
            authority_id: self.authority_id,
            authority_term: counter(self.authority_term, "authority_term")?,
            global_fence_sequence: counter(self.global_fence_sequence, "global_fence_sequence")?,
            previous_authority_term: optional_counter(
                self.previous_authority_term,
                "previous_authority_term",
            )?
            .unwrap_or(0),
            previous_global_fence_sequence: optional_counter(
                self.previous_global_fence_sequence,
                "previous_global_fence_sequence",
            )?
            .unwrap_or(0),
            previous_key_id: self.previous_key_id,
            previous_key_epoch: optional_counter(self.previous_key_epoch, "previous_key_epoch")?
                .unwrap_or(0),
            scope: AuthorizationAuthorityScope {
                tenant_id: self.tenant_id,
                card_id: self.card_id,
                user_id: self.scope_user_id,
                domain,
            },
            scope_generation: counter(self.scope_generation, "scope_generation")?,
            revoke_watermark: counter(self.revoke_watermark, "revoke_watermark")?,
            snapshot_hash: digest_hex(self.snapshot_hash, "snapshot_hash")?,
            parent_hash: self
                .parent_hash
                .map(|hash| digest_hex(hash, "parent_hash"))
                .transpose()?,
            operation_id: self.operation_id,
            event_id: self.event_id,
            key_id: self.key_id,
            key_epoch: counter(self.key_epoch, "key_epoch")?,
            issued_at: self.issued_at,
            not_before: self.not_before,
            expires_at: self.expires_at,
            request_nonce: self.request_nonce,
            lease_id: self.lease_id,
            arbiter_id: self.arbiter_id,
            arbiter_key_id: self.arbiter_key_id,
            arbiter_key_epoch: counter(self.arbiter_key_epoch, "arbiter_key_epoch")?,
            arbiter_signature: signature_hex(self.arbiter_signature)?,
        };
        lease.validate().map_err(|error| {
            PolicyError::Repository(format!(
                "authorization issuance lease row is invalid: {error}"
            ))
        })?;
        Ok(lease)
    }
}

fn validate_lease_id(lease_id: &str) -> Result<(), PolicyError> {
    if lease_id.trim().is_empty()
        || lease_id.len() > 128
        || lease_id.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(PolicyError::InvalidContext(
            "authorization issuance lease id is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn lease_scope_columns(scope: &AuthorizationAuthorityScope) -> (&'static str, Option<i64>) {
    match scope.domain {
        AuthorizationDomainScope::Any => ("ANY", None),
        AuthorizationDomainScope::NoDomain => ("NO_DOMAIN", None),
        AuthorizationDomainScope::Exact(domain_id) => ("EXACT", Some(domain_id)),
    }
}

fn evidence_scope_from_authority_scope(
    scope: &AuthorizationAuthorityScope,
) -> Result<PublishedCardEvidenceScope, PolicyError> {
    scope.validate().map_err(|error| {
        PolicyError::InvalidContext(format!("invalid authority scope: {error}"))
    })?;
    let domain = match scope.domain {
        AuthorizationDomainScope::Any => DomainScopeRequirement::Unconstrained,
        AuthorizationDomainScope::NoDomain => DomainScopeRequirement::ExactlyNone,
        AuthorizationDomainScope::Exact(domain_id) => {
            DomainScopeRequirement::ExactlySome(domain_id)
        }
    };
    Ok(PublishedCardEvidenceScope {
        tenant_id: scope.tenant_id,
        card_id: scope.card_id,
        user_filter: scope.user_id,
        domain,
    })
}

const AUTHORITY_LEASE_ROW_COLUMNS: &str =
    "lease_id, request_nonce, authorization_edition, authority_id, \
    authority_term, global_fence_sequence, previous_authority_term, \
    previous_global_fence_sequence, previous_key_id, previous_key_epoch, tenant_id, card_id, \
    scope_user_id, scope_domain_kind, scope_domain_id, scope_generation, revoke_watermark, \
    snapshot_hash, parent_hash, operation_id, event_id, key_id, key_epoch, issued_at, \
    not_before, expires_at, arbiter_id, arbiter_key_id, arbiter_key_epoch, arbiter_signature, \
    status, consumed_at, publication_completion_hash, publication_completion_generation, \
    publication_completion_revoke_watermark, publication_completion_at";

async fn load_issuance_lease_row_for_update(
    tx: &mut Transaction<'_, MySql>,
    lease_id: &str,
) -> Result<DurableAuthorityIssuanceLeaseRow, PolicyError> {
    let statement = format!(
        "SELECT {AUTHORITY_LEASE_ROW_COLUMNS} \
         FROM authorization_authority_issuance_lease \
         WHERE lease_id = ? FOR UPDATE"
    );
    sqlx::query_as::<_, DurableAuthorityIssuanceLeaseRow>(&statement)
        .bind(lease_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| {
            PolicyError::Repository(format!("authorization issuance lease lock failed: {error}"))
        })?
        .ok_or_else(|| {
            PolicyError::Repository(
                "authorization issuance lease is unavailable; proof remains pending".to_owned(),
            )
        })
}

async fn ensure_authority_frontier_bootstrap(
    tx: &mut Transaction<'_, MySql>,
    authority_id: &str,
) -> Result<(), PolicyError> {
    sqlx::query(
        "INSERT INTO authorization_authority_frontier \
         (frontier_id, authority_id, authority_term, global_fence_sequence, key_id, key_epoch, snapshot_hash, status) \
         VALUES (?, ?, 0, 0, '-', 0, NULL, 'COLD') \
         ON DUPLICATE KEY UPDATE frontier_id = frontier_id",
    )
    .bind(AUTHORITY_FRONTIER_ROW_ID)
    .bind(authority_id)
    .execute(&mut **tx)
    .await
    .map_err(|error| {
        PolicyError::Repository(format!(
            "authorization authority frontier bootstrap failed: {error}"
        ))
    })?;
    Ok(())
}

async fn lock_authority_frontier(
    tx: &mut Transaction<'_, MySql>,
) -> Result<AuthorityFrontierRow, PolicyError> {
    sqlx::query_as::<_, AuthorityFrontierRow>(
        "SELECT authority_id, authority_term, global_fence_sequence, key_id, key_epoch, \
                snapshot_hash, status \
         FROM authorization_authority_frontier \
         WHERE frontier_id = ? FOR UPDATE",
    )
    .bind(AUTHORITY_FRONTIER_ROW_ID)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| {
        PolicyError::Repository(format!(
            "authorization authority frontier lock failed: {error}"
        ))
    })?
    .ok_or_else(|| {
        PolicyError::Repository(
            "authorization authority frontier is unavailable; proof remains pending".to_owned(),
        )
    })
}

fn validate_ready_completion_columns(
    row: &DurableAuthorityIssuanceLeaseRow,
) -> Result<(), PolicyError> {
    if row.status != "READY" && row.status != "CONSUMED" {
        return Err(PolicyError::Repository(
            "authorization issuance lease is not completion-ready".to_owned(),
        ));
    }
    if row
        .publication_completion_hash
        .as_ref()
        .is_none_or(|hash| hash.len() != 32)
        || row
            .publication_completion_generation
            .is_none_or(|value| value != row.scope_generation)
        || row
            .publication_completion_revoke_watermark
            .is_none_or(|value| value != row.revoke_watermark)
        || row.publication_completion_at.is_none()
    {
        return Err(PolicyError::Repository(
            "authorization issuance lease lacks durable publication completion proof".to_owned(),
        ));
    }
    Ok(())
}

fn digest_bytes(value: &str, field: &str) -> Result<Vec<u8>, PolicyError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(PolicyError::Repository(format!(
            "authorization authority {field} is not a 32-byte hex digest"
        )));
    }
    let bytes = hex::decode(value).map_err(|_| {
        PolicyError::Repository(format!(
            "authorization authority {field} is not a valid hex digest"
        ))
    })?;
    if bytes.len() != 32 {
        return Err(PolicyError::Repository(format!(
            "authorization authority {field} must be 32 bytes"
        )));
    }
    Ok(bytes)
}

fn signature_bytes(value: &str) -> Result<Vec<u8>, PolicyError> {
    if value.len() != 128 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(PolicyError::Repository(
            "authorization authority signature is not a 64-byte hex signature".to_owned(),
        ));
    }
    let bytes = hex::decode(value).map_err(|_| {
        PolicyError::Repository("authorization authority signature is not valid hex".to_owned())
    })?;
    if bytes.len() != 64 {
        return Err(PolicyError::Repository(
            "authorization authority signature must be 64 bytes".to_owned(),
        ));
    }
    Ok(bytes)
}

pub async fn authority_provider_from_env(
    pool: MySqlPool,
) -> Result<Option<Arc<SqlxAuthorizationFenceProvider>>, PolicyError> {
    quorum::provider_from_env(pool).await
}

/// Explicit offline compatibility construction; production listeners use the quorum client.
pub fn diagnostic_authority_provider_from_env(
    pool: MySqlPool,
) -> Result<Option<Arc<SqlxAuthorizationFenceProvider>>, PolicyError> {
    let values = [
        (
            "ASTRAL_AUTHORITY_ID",
            std::env::var("ASTRAL_AUTHORITY_ID").ok(),
        ),
        (
            "ASTRAL_AUTHORITY_KEY_ID",
            std::env::var("ASTRAL_AUTHORITY_KEY_ID").ok(),
        ),
        (
            "ASTRAL_AUTHORITY_KEY_EPOCH",
            std::env::var("ASTRAL_AUTHORITY_KEY_EPOCH").ok(),
        ),
        (
            "ASTRAL_AUTHORITY_PUBLIC_KEY_HEX",
            std::env::var("ASTRAL_AUTHORITY_PUBLIC_KEY_HEX").ok(),
        ),
    ];
    let configured = values.iter().any(|(_, value)| value.is_some());
    if !configured {
        return Ok(None);
    }
    let required = |name: &str, value: &Option<String>| {
        value
            .clone()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                PolicyError::Repository(format!(
                    "{name} is required when the authorization trust root is configured"
                ))
            })
    };
    let authority_id = required("ASTRAL_AUTHORITY_ID", &values[0].1)?;
    let key_id = required("ASTRAL_AUTHORITY_KEY_ID", &values[1].1)?;
    let key_epoch = required("ASTRAL_AUTHORITY_KEY_EPOCH", &values[2].1)?
        .parse::<u64>()
        .map_err(|_| PolicyError::Repository("ASTRAL_AUTHORITY_KEY_EPOCH is invalid".to_owned()))?;
    let public_key_hex = required("ASTRAL_AUTHORITY_PUBLIC_KEY_HEX", &values[3].1)?;
    let public_key_bytes = hex::decode(&public_key_hex).map_err(|_| {
        PolicyError::Repository("ASTRAL_AUTHORITY_PUBLIC_KEY_HEX is invalid hex".to_owned())
    })?;
    let public_key: [u8; 32] = public_key_bytes.try_into().map_err(|_| {
        PolicyError::Repository(
            "ASTRAL_AUTHORITY_PUBLIC_KEY_HEX must encode exactly 32 bytes".to_owned(),
        )
    })?;
    let verifying_key = VerifyingKey::from_bytes(&public_key).map_err(|_| {
        PolicyError::Repository("ASTRAL_AUTHORITY_PUBLIC_KEY_HEX is not an Ed25519 key".to_owned())
    })?;
    let trust_root = AuthorizationTrustRoot::new(authority_id, key_id, key_epoch, verifying_key)?;
    let provider = SqlxAuthorizationFenceProvider::new(pool, trust_root)?;
    Ok(Some(Arc::new(provider)))
}
/// MySQL adapter for proof rows written by the external global authority.
///
/// The provider is intentionally not constructed by the default repository
/// constructors. A deployment must explicitly inject it after configuring the
/// fixed trust root and proving that the authority frontier writer is active.
#[derive(Clone)]
pub struct SqlxAuthorizationFenceProvider {
    pool: MySqlPool,
    trust_root: Arc<AuthorizationTrustRoot>,
    quorum: Option<Arc<quorum::QuorumProvider>>,
}

impl SqlxAuthorizationFenceProvider {
    pub fn new(pool: MySqlPool, trust_root: AuthorizationTrustRoot) -> Result<Self, PolicyError> {
        Ok(Self {
            pool,
            trust_root: Arc::new(trust_root),
            quorum: None,
        })
    }

    /// Attest and install one bounded serving partition after durable recovery.
    pub async fn attest_memory_partition(
        &self,
        hub: &crate::MemoryProjectionHub,
    ) -> Result<usize, PolicyError> {
        self.quorum
            .as_ref()
            .ok_or_else(|| {
                PolicyError::Repository("startup attestation requires quorum authority".into())
            })?
            .attest_partition(&self.pool, hub)
            .await
    }

    /// Verify current authority reachability/frontier without refreshing serving evidence.
    pub async fn observe_memory_partition(
        &self,
        hub: &crate::MemoryProjectionHub,
    ) -> Result<(), PolicyError> {
        self.quorum
            .as_ref()
            .ok_or_else(|| {
                PolicyError::Repository("serving observation requires quorum authority".into())
            })?
            .observe_serving_partition(hub)
            .await
    }

    /// Abort one prepared reservation after the middleware observes handler
    /// completion. HTTP outcome is never used as rollback proof; the repository
    /// checks the durable same-row lock and tombstones only an unconsumed row.
    pub async fn abort_source_reservation(
        &self,
        abort: &SourceReservationAbort,
    ) -> Result<SourceAbortReport, PolicyError> {
        self.quorum
            .as_ref()
            .ok_or_else(|| {
                PolicyError::Repository("source abort requires quorum authority".into())
            })?
            .abort_reservation(&self.pool, abort)
            .await
    }

    /// Reconcile durable source outcomes for this registered service/database.
    /// This never replays the source mutation and performs no work in a source transaction.
    pub async fn reconcile_source_outcomes(
        &self,
        run_instance_id: &str,
    ) -> Result<crate::authority_source_outcome::AuthoritySourceOutcomeReconcileReport, PolicyError>
    {
        self.quorum
            .as_ref()
            .ok_or_else(|| {
                PolicyError::Repository(
                    "source outcome reconciliation requires quorum authority".into(),
                )
            })?
            .reconcile_source_outcomes(&self.pool, run_instance_id)
            .await
    }

    pub async fn reserve_mutation(
        &self,
        context: &astral_types::PolicyContext,
        admission: &AuthorizationAdmission,
    ) -> Result<(), PolicyError> {
        self.reserve_mutation_with_abort(context, admission)
            .await
            .map(|_| ())
    }

    /// Prepare a mutation and retain exact prepare evidence so its source owner
    /// can close only a durably proven rollback after the handler returns.
    pub async fn reserve_mutation_with_abort(
        &self,
        context: &astral_types::PolicyContext,
        admission: &AuthorizationAdmission,
    ) -> Result<SourceReservationAbort, PolicyError> {
        self.quorum
            .as_ref()
            .ok_or_else(|| {
                PolicyError::Repository("source reservation requires quorum authority".into())
            })?
            .reserve(&self.pool, context, admission)
            .await
    }

    pub fn trust_root(&self) -> &AuthorizationTrustRoot {
        &self.trust_root
    }

    async fn load_and_reserve(
        &self,
        scope: &PublishedCardEvidenceScope,
        request_nonce: &str,
    ) -> Result<AuthorizationFenceProof, PolicyError> {
        scope.validate().map_err(|error| {
            PolicyError::InvalidContext(format!("invalid authority proof scope: {error}"))
        })?;
        validate_request_nonce(request_nonce)?;

        let now_seconds = OffsetDateTime::now_utc().unix_timestamp();
        let mut tx = self.pool.begin().await.map_err(|error| {
            PolicyError::Repository(format!(
                "authorization authority proof transaction begin failed: {error}"
            ))
        })?;

        let frontier = sqlx::query_as::<_, AuthorityFrontierRow>(
            "SELECT authority_id, authority_term, global_fence_sequence, key_id, key_epoch, \
                    snapshot_hash, status \
             FROM authorization_authority_frontier \
             WHERE frontier_id = ? FOR UPDATE",
        )
        .bind(AUTHORITY_FRONTIER_ROW_ID)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| {
            PolicyError::Repository(format!(
                "authorization authority frontier read failed: {error}"
            ))
        })?
        .ok_or_else(|| {
            PolicyError::Repository(
                "authorization authority frontier is unavailable; positive authorization is pending"
                    .to_owned(),
            )
        })?;

        validate_frontier_row(&frontier, &self.trust_root)?;

        let proof_row = sqlx::query_as::<_, DurableAuthorityProofRow>(
            "SELECT proof_id, request_nonce, authorization_edition, authority_id, authority_term, \
                    global_fence_sequence, tenant_id, card_id, scope_user_id, \
                    scope_domain_kind, scope_domain_id, scope_generation, \
                    revoke_watermark, snapshot_hash, parent_hash, operation_id, \
                    event_id, key_id, key_epoch, issued_at, not_before, expires_at, \
                    signature, status \
             FROM authorization_authority_proof \
             WHERE request_nonce = ? FOR UPDATE",
        )
        .bind(request_nonce)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| {
            PolicyError::Repository(format!(
                "authorization authority proof read failed: {error}"
            ))
        })?
        .ok_or_else(|| {
            PolicyError::Repository(
                "authorization authority proof is unavailable; positive authorization is pending"
                    .to_owned(),
            )
        })?;

        let proof = proof_row.into_proof()?;
        validate_current_proof(
            &proof,
            scope,
            request_nonce,
            &frontier,
            &self.trust_root,
            now_seconds,
        )?;

        let replay_key = proof_replay_key(&proof)?;
        let reservation_ttl = proof
            .expires_at
            .saturating_sub(now_seconds)
            .saturating_add(REPLAY_GUARD_SKEW_SECONDS)
            .max(1);
        match crate::claim_replay_guard_in_tx(
            &mut tx,
            GUARD_SCOPE_AUTHORITY_PROOF_REPLAY,
            &replay_key,
            reservation_ttl,
        )
        .await
        .map_err(|error| {
            PolicyError::Repository(format!(
                "authorization authority proof replay reservation failed: {error}"
            ))
        })? {
            GuardClaim::Claimed => {}
            GuardClaim::Duplicate => {
                return Err(PolicyError::Repository(
                    "authorization authority proof replay reservation already claimed".to_owned(),
                ));
            }
        }

        tx.commit().await.map_err(|error| {
            PolicyError::Repository(format!(
                "authorization authority proof reservation commit is unknown: {error}"
            ))
        })?;
        Ok(proof)
    }

    fn verify_trust_root(
        &self,
        proof: &AuthorizationFenceProof,
        scope: &PublishedCardEvidenceScope,
        now_seconds: i64,
    ) -> Result<(), PolicyError> {
        if proof.authority_id != self.trust_root.authority_id
            || proof.key_id != self.trust_root.key_id
            || proof.key_epoch != self.trust_root.key_epoch
        {
            return Err(PolicyError::Repository(
                "authorization authority proof trust root identity mismatch".to_owned(),
            ));
        }
        proof.scope.matches_evidence_scope(scope).map_err(|error| {
            PolicyError::Repository(format!("authority proof scope mismatch: {error}"))
        })?;
        let window = proof
            .expires_at
            .checked_sub(proof.not_before)
            .ok_or_else(|| {
                PolicyError::Repository(
                    "authorization authority proof time window overflow".to_owned(),
                )
            })?;
        if window <= 0 || window > MAX_AUTHORITY_PROOF_WINDOW_SECONDS {
            return Err(PolicyError::Repository(
                "authorization authority proof validity window exceeds the verifier limit"
                    .to_owned(),
            ));
        }
        proof
            .verify_at(&self.trust_root.verifying_key, now_seconds)
            .map_err(|error| {
                PolicyError::Repository(format!(
                    "authorization authority proof verification failed: {error}"
                ))
            })
    }
}

/// Revalidate a request admission against the durable authority rows while the
/// source mutation transaction is still open.
///
/// This is intentionally independent from the read-side nonce reservation. A
/// request may have passed F1 and still lose its authority frontier before the
/// source commit; the source owner must lock both rows again and fail closed.
/// Source-aggregate generation/CAS remains the responsibility of the aggregate
/// owner, which knows the correct source table and lock order.
pub async fn validate_authorization_admission_in_tx(
    tx: &mut Transaction<'_, MySql>,
    admission: &AuthorizationAdmission,
) -> Result<(), PolicyError> {
    let proof = admission.proof();
    let now_seconds = OffsetDateTime::now_utc().unix_timestamp();
    proof.validate_at(now_seconds).map_err(|error| {
        PolicyError::Repository(format!(
            "authorization admission proof is not currently valid: {error}"
        ))
    })?;
    quorum::validate_in_tx(tx, admission).await
}

/// Offline diagnostic validation of the historical proof-row layout.
pub async fn validate_diagnostic_admission_in_tx(
    tx: &mut Transaction<'_, MySql>,
    admission: &AuthorizationAdmission,
) -> Result<(), PolicyError> {
    let proof = admission.proof();
    let frontier = sqlx::query_as::<_, AuthorityFrontierRow>(
        "SELECT authority_id, authority_term, global_fence_sequence, key_id, key_epoch, \
                    snapshot_hash, status \
             FROM authorization_authority_frontier \
             WHERE frontier_id = ? FOR UPDATE",
    )
    .bind(AUTHORITY_FRONTIER_ROW_ID)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| {
        PolicyError::Repository(format!(
            "authorization admission frontier lock failed: {error}"
        ))
    })?
    .ok_or_else(|| {
        PolicyError::Repository(
            "authorization admission frontier is unavailable; source commit is pending".to_owned(),
        )
    })?;

    let frontier_term = counter(frontier.authority_term, "frontier.authority_term")?;
    let frontier_fence = counter(
        frontier.global_fence_sequence,
        "frontier.global_fence_sequence",
    )?;
    let frontier_epoch = counter(frontier.key_epoch, "frontier.key_epoch")?;
    let frontier_snapshot_hash = frontier.snapshot_hash.as_deref().ok_or_else(|| {
        PolicyError::Repository("served authority frontier has no durable snapshot hash".to_owned())
    })?;
    let proof_snapshot_hash = digest_bytes(&proof.snapshot_hash, "snapshot_hash")?;
    if frontier.status != "SERVING"
        || frontier_snapshot_hash.len() != 32
        || proof.authority_id != frontier.authority_id
        || proof.authority_term != frontier_term
        || proof.global_fence_sequence != frontier_fence
        || proof.key_id != frontier.key_id
        || proof.key_epoch != frontier_epoch
        || proof_snapshot_hash != frontier_snapshot_hash
    {
        return Err(PolicyError::Repository(
            "authorization admission frontier changed before source commit".to_owned(),
        ));
    }

    let proof_row = sqlx::query_as::<_, DurableAuthorityProofRow>(
        "SELECT proof_id, request_nonce, authorization_edition, authority_id, \
                authority_term, global_fence_sequence, tenant_id, card_id, scope_user_id, \
                scope_domain_kind, scope_domain_id, scope_generation, revoke_watermark, \
                snapshot_hash, parent_hash, operation_id, event_id, key_id, key_epoch, \
                issued_at, not_before, expires_at, signature, status \
         FROM authorization_authority_proof \
         WHERE proof_id = ? AND request_nonce = ? FOR UPDATE",
    )
    .bind(&proof.proof_id)
    .bind(&proof.request_nonce)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| {
        PolicyError::Repository(format!(
            "authorization admission proof lock failed: {error}"
        ))
    })?
    .ok_or_else(|| {
        PolicyError::Repository(
            "authorization admission proof is unavailable; source commit is pending".to_owned(),
        )
    })?;

    if proof_row.status != "ACTIVE" {
        return Err(PolicyError::Repository(
            "authorization admission proof is no longer active".to_owned(),
        ));
    }
    let durable_proof = proof_row.into_proof()?;
    if durable_proof != *proof {
        return Err(PolicyError::Repository(
            "authorization admission proof row does not match the request capability".to_owned(),
        ));
    }
    Ok(())
}

#[async_trait::async_trait]
impl AuthorizationFenceProvider for SqlxAuthorizationFenceProvider {
    async fn read_authorization_fence(
        &self,
        scope: &PublishedCardEvidenceScope,
        request_nonce: &str,
    ) -> Result<AuthorizationFenceProof, PolicyError> {
        self.load_and_reserve(scope, request_nonce).await
    }

    async fn read_request_authorization_fence(
        &self,
        context: &astral_types::PolicyContext,
        scope: &PublishedCardEvidenceScope,
        request_nonce: &str,
    ) -> Result<AuthorizationFenceProof, PolicyError> {
        let quorum = self.quorum.as_ref().ok_or_else(|| {
            PolicyError::Repository("production requests require a quorum authority client".into())
        })?;
        quorum
            .read(&self.pool, context, scope, request_nonce, None)
            .await
    }

    async fn read_org_authorization_fence(
        &self,
        context: &astral_types::PolicyContext,
        evidence: &astral_types::org_scope::OrgAdmissionEvidence,
        request_nonce: &str,
    ) -> Result<AuthorizationFenceProof, PolicyError> {
        let quorum = self
            .quorum
            .as_ref()
            .ok_or_else(|| PolicyError::Repository("ORG reads require quorum authority".into()))?;
        let scope = astral_types::org_authority_evidence_scope(context)
            .map_err(|error| PolicyError::InvalidContext(error.to_string()))?;
        let source = astral_types::AuthorityProtocolScope::Org(astral_types::AuthorityOrgScope {
            tenant_id: evidence.publication.tenant_id,
            root_tenant_id: Some(evidence.publication.root_tenant_id),
            member: astral_types::AuthorityOrgMemberSubject {
                user_id: evidence.membership.user_id,
                identity_card_id: evidence.membership.identity_card_id,
                card_id: evidence.membership.card_id,
            },
        });
        let proof = quorum
            .read(&self.pool, context, &scope, request_nonce, Some(source))
            .await?;
        astral_types::validate_org_authority_proof(
            &proof,
            context,
            evidence,
            request_nonce,
            OffsetDateTime::now_utc().unix_timestamp(),
        )
        .map_err(|error| PolicyError::Repository(error.to_string()))?;
        Ok(proof)
    }

    fn certify_authorization_evidence(
        &self,
        proof: AuthorizationFenceProof,
        evidence: Arc<PublishedCardAuthorization>,
        scope: &PublishedCardEvidenceScope,
        now_seconds: i64,
    ) -> Result<CertifiedAuthorizationState, PolicyError> {
        if let Some(quorum) = &self.quorum {
            return quorum.certify(proof, evidence, scope, now_seconds);
        }
        self.verify_trust_root(&proof, scope, now_seconds)?;
        CertifiedAuthorizationState::new(
            proof,
            evidence,
            &self.trust_root.verifying_key,
            now_seconds,
            scope,
        )
        .map_err(|error| {
            PolicyError::Repository(format!(
                "authorization evidence certification failed: {error}"
            ))
        })
    }
}

#[derive(Debug, sqlx::FromRow)]
struct AuthorityFrontierRow {
    authority_id: String,
    authority_term: i64,
    global_fence_sequence: i64,
    key_id: String,
    key_epoch: i64,
    snapshot_hash: Option<Vec<u8>>,
    status: String,
}

impl AuthorityFrontierRow {
    fn into_identity(self) -> Result<AuthorityFrontierIdentity, PolicyError> {
        Ok(AuthorityFrontierIdentity {
            authority_id: self.authority_id,
            authority_term: counter(self.authority_term, "frontier.authority_term")?,
            global_fence_sequence: counter(
                self.global_fence_sequence,
                "frontier.global_fence_sequence",
            )?,
            key_id: self.key_id,
            key_epoch: counter(self.key_epoch, "frontier.key_epoch")?,
            snapshot_hash: self
                .snapshot_hash
                .map(|hash| digest_hex(hash, "frontier.snapshot_hash"))
                .transpose()?,
            status: self.status,
        })
    }
}

#[derive(Debug, sqlx::FromRow)]
struct DurableAuthorityProofRow {
    proof_id: String,
    request_nonce: String,
    authorization_edition: u16,
    authority_id: String,
    authority_term: i64,
    global_fence_sequence: i64,
    tenant_id: i64,
    card_id: i64,
    scope_user_id: Option<i64>,
    scope_domain_kind: String,
    scope_domain_id: Option<i64>,
    scope_generation: i64,
    revoke_watermark: i64,
    snapshot_hash: Vec<u8>,
    parent_hash: Option<Vec<u8>>,
    operation_id: String,
    event_id: String,
    key_id: String,
    key_epoch: i64,
    issued_at: i64,
    not_before: i64,
    expires_at: i64,
    signature: Vec<u8>,
    status: String,
}

impl DurableAuthorityProofRow {
    fn into_proof(self) -> Result<AuthorizationFenceProof, PolicyError> {
        if self.status != "ACTIVE" {
            return Err(PolicyError::Repository(
                "authorization authority proof is not active".to_owned(),
            ));
        }
        if self.authorization_edition != astral_types::AUTHORIZATION_EDITION {
            return Err(PolicyError::Repository(
                "authorization authority proof edition is not current".to_owned(),
            ));
        }
        let domain = match (self.scope_domain_kind.as_str(), self.scope_domain_id) {
            ("ANY", None) => AuthorizationDomainScope::Any,
            ("NO_DOMAIN", None) => AuthorizationDomainScope::NoDomain,
            ("EXACT", Some(domain_id)) => AuthorizationDomainScope::Exact(domain_id),
            _ => {
                return Err(PolicyError::Repository(
                    "authorization authority proof domain encoding is invalid".to_owned(),
                ));
            }
        };
        Ok(AuthorizationFenceProof {
            authorization_edition: self.authorization_edition,
            authority_id: self.authority_id,
            authority_term: counter(self.authority_term, "authority_term")?,
            global_fence_sequence: counter(self.global_fence_sequence, "global_fence_sequence")?,
            scope: AuthorizationAuthorityScope {
                tenant_id: self.tenant_id,
                card_id: self.card_id,
                user_id: self.scope_user_id,
                domain,
            },
            scope_generation: counter(self.scope_generation, "scope_generation")?,
            revoke_watermark: counter(self.revoke_watermark, "revoke_watermark")?,
            snapshot_hash: digest_hex(self.snapshot_hash, "snapshot_hash")?,
            parent_hash: self
                .parent_hash
                .map(|hash| digest_hex(hash, "parent_hash"))
                .transpose()?,
            operation_id: self.operation_id,
            event_id: self.event_id,
            key_id: self.key_id,
            key_epoch: counter(self.key_epoch, "key_epoch")?,
            issued_at: self.issued_at,
            not_before: self.not_before,
            expires_at: self.expires_at,
            request_nonce: self.request_nonce,
            request_binding_digest: None,
            scope_certificate_hash: None,
            proof_id: self.proof_id,
            signature: signature_hex(self.signature)?,
        })
    }
}

fn proof_matches_lease(
    proof: &AuthorizationFenceProof,
    lease: &AuthorizationIssuanceLease,
) -> bool {
    proof.proof_id == lease.lease_id
        && proof.request_nonce == lease.request_nonce
        && proof.authorization_edition == lease.authorization_edition
        && proof.authority_id == lease.authority_id
        && proof.authority_term == lease.authority_term
        && proof.global_fence_sequence == lease.global_fence_sequence
        && proof.scope == lease.scope
        && proof.scope_generation == lease.scope_generation
        && proof.revoke_watermark == lease.revoke_watermark
        && proof.snapshot_hash == lease.snapshot_hash
        && proof.parent_hash == lease.parent_hash
        && proof.operation_id == lease.operation_id
        && proof.event_id == lease.event_id
        && proof.key_id == lease.key_id
        && proof.key_epoch == lease.key_epoch
        && proof.issued_at == lease.issued_at
        && proof.not_before == lease.not_before
        && proof.expires_at == lease.expires_at
}

fn proof_matches_frontier(
    proof: &AuthorizationFenceProof,
    frontier: &AuthorityFrontierRow,
) -> Result<bool, PolicyError> {
    Ok(frontier.status == "SERVING"
        && proof.authority_id == frontier.authority_id
        && proof.authority_term == counter(frontier.authority_term, "frontier.authority_term")?
        && proof.global_fence_sequence
            == counter(
                frontier.global_fence_sequence,
                "frontier.global_fence_sequence",
            )?
        && proof.key_id == frontier.key_id
        && proof.key_epoch == counter(frontier.key_epoch, "frontier.key_epoch")?
        && frontier.snapshot_hash.as_deref().is_some_and(|hash| {
            digest_bytes(&proof.snapshot_hash, "snapshot_hash").is_ok_and(|value| value == hash)
        }))
}

fn verify_lease_signature_without_time(
    arbiter_trust_root: &AuthorizationArbiterTrustRoot,
    lease: &AuthorizationIssuanceLease,
) -> Result<(), PolicyError> {
    if lease.arbiter_id != arbiter_trust_root.arbiter_id
        || lease.arbiter_key_id != arbiter_trust_root.key_id
        || lease.arbiter_key_epoch != arbiter_trust_root.key_epoch
    {
        return Err(PolicyError::Repository(
            "authorization issuance lease arbiter trust root identity mismatch".to_owned(),
        ));
    }
    lease
        .validate()
        .map_err(|error| PolicyError::Repository(format!("invalid issuance lease: {error}")))?;
    let signature_bytes = signature_bytes(&lease.arbiter_signature)?;
    let signature = Signature::from_bytes(
        &signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| PolicyError::Repository("invalid arbiter signature length".to_owned()))?,
    );
    arbiter_trust_root
        .verifying_key
        .verify_strict(
            &lease.signing_bytes().map_err(|error| {
                PolicyError::Repository(format!("invalid issuance lease signing bytes: {error}"))
            })?,
            &signature,
        )
        .map_err(|_| PolicyError::Repository("invalid issuance lease arbiter signature".to_owned()))
}

fn verify_proof_signature_without_time(
    trust_root: &AuthorizationTrustRoot,
    proof: &AuthorizationFenceProof,
) -> Result<(), PolicyError> {
    if proof.authority_id != trust_root.authority_id
        || proof.key_id != trust_root.key_id
        || proof.key_epoch != trust_root.key_epoch
    {
        return Err(PolicyError::Repository(
            "authorization proof trust root identity mismatch".to_owned(),
        ));
    }
    proof
        .validate()
        .map_err(|error| PolicyError::Repository(format!("invalid authority proof: {error}")))?;
    let signature_bytes = signature_bytes(&proof.signature)?;
    let signature = Signature::from_bytes(
        &signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| PolicyError::Repository("invalid proof signature length".to_owned()))?,
    );
    trust_root
        .verifying_key
        .verify_strict(
            &proof.signing_bytes().map_err(|error| {
                PolicyError::Repository(format!("invalid authority proof signing bytes: {error}"))
            })?,
            &signature,
        )
        .map_err(|_| PolicyError::Repository("invalid authority proof signature".to_owned()))
}

async fn finish_issuance_reconciliation_unknown(
    _tx: &mut Transaction<'_, MySql>,
    lease_id: &str,
    reason: &str,
) -> Result<IssuanceLeaseReconciliation, PolicyError> {
    Ok(IssuanceLeaseReconciliation::Unknown {
        lease_id: lease_id.to_owned(),
        reason: reason.to_owned(),
    })
}

fn validate_current_proof(
    proof: &AuthorizationFenceProof,
    scope: &PublishedCardEvidenceScope,
    request_nonce: &str,
    frontier: &AuthorityFrontierRow,
    trust_root: &AuthorizationTrustRoot,
    now_seconds: i64,
) -> Result<(), PolicyError> {
    if proof.request_nonce != request_nonce {
        return Err(PolicyError::Repository(
            "authorization authority proof request nonce mismatch".to_owned(),
        ));
    }
    let frontier_snapshot_hash = frontier.snapshot_hash.as_deref().ok_or_else(|| {
        PolicyError::Repository("served authority frontier has no durable snapshot hash".to_owned())
    })?;
    let proof_snapshot_hash = digest_bytes(&proof.snapshot_hash, "snapshot_hash")?;
    if frontier.status != "SERVING"
        || frontier_snapshot_hash.len() != 32
        || proof.authority_id != frontier.authority_id
        || proof.authority_term != counter(frontier.authority_term, "frontier.authority_term")?
        || proof.global_fence_sequence
            != counter(
                frontier.global_fence_sequence,
                "frontier.global_fence_sequence",
            )?
        || proof.key_id != frontier.key_id
        || proof.key_epoch != counter(frontier.key_epoch, "frontier.key_epoch")?
        || proof_snapshot_hash != frontier_snapshot_hash
    {
        return Err(PolicyError::Repository(
            "authorization authority proof does not match the current durable frontier".to_owned(),
        ));
    }
    if proof.authority_id != trust_root.authority_id
        || proof.key_id != trust_root.key_id
        || proof.key_epoch != trust_root.key_epoch
    {
        return Err(PolicyError::Repository(
            "authorization authority proof trust root identity mismatch".to_owned(),
        ));
    }
    proof.scope.matches_evidence_scope(scope).map_err(|error| {
        PolicyError::Repository(format!("authority proof scope mismatch: {error}"))
    })?;
    let window = proof
        .expires_at
        .checked_sub(proof.not_before)
        .ok_or_else(|| {
            PolicyError::Repository("authorization authority proof time window overflow".to_owned())
        })?;
    if window <= 0 || window > MAX_AUTHORITY_PROOF_WINDOW_SECONDS {
        return Err(PolicyError::Repository(
            "authorization authority proof validity window exceeds the verifier limit".to_owned(),
        ));
    }
    proof
        .verify_at(&trust_root.verifying_key, now_seconds)
        .map_err(|error| {
            PolicyError::Repository(format!(
                "authorization authority proof verification failed: {error}"
            ))
        })
}

fn validate_frontier_row(
    frontier: &AuthorityFrontierRow,
    trust_root: &AuthorizationTrustRoot,
) -> Result<(), PolicyError> {
    if frontier.status != "SERVING"
        || frontier.authority_id != trust_root.authority_id
        || frontier.key_id != trust_root.key_id
        || frontier
            .snapshot_hash
            .as_ref()
            .is_none_or(|hash| hash.len() != 32)
        || counter(frontier.key_epoch, "frontier.key_epoch")? != trust_root.key_epoch
    {
        return Err(PolicyError::Repository(
            "authorization authority frontier is not served by the configured trust root"
                .to_owned(),
        ));
    }
    if frontier.authority_term <= 0 || frontier.global_fence_sequence <= 0 {
        return Err(PolicyError::Repository(
            "authorization authority frontier counters are invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_request_nonce(request_nonce: &str) -> Result<(), PolicyError> {
    if request_nonce.trim().is_empty()
        || request_nonce.len() > 255
        || request_nonce.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(PolicyError::InvalidContext(
            "authorization authority request nonce is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn counter(value: i64, field: &str) -> Result<u64, PolicyError> {
    u64::try_from(value).map_err(|_| {
        PolicyError::Repository(format!("authorization authority {field} is negative"))
    })
}

fn optional_counter(value: i64, field: &str) -> Result<Option<u64>, PolicyError> {
    if value == 0 {
        Ok(None)
    } else {
        counter(value, field).map(Some)
    }
}

fn digest_hex(value: Vec<u8>, field: &str) -> Result<String, PolicyError> {
    if value.len() != 32 {
        return Err(PolicyError::Repository(format!(
            "authorization authority {field} must be 32 bytes"
        )));
    }
    Ok(hex::encode(value))
}

fn signature_hex(value: Vec<u8>) -> Result<String, PolicyError> {
    if value.len() != 64 {
        return Err(PolicyError::Repository(
            "authorization authority signature must be 64 bytes".to_owned(),
        ));
    }
    Ok(hex::encode(value))
}

fn proof_replay_key(proof: &AuthorizationFenceProof) -> Result<String, PolicyError> {
    let signing_bytes = proof.signing_bytes().map_err(|error| {
        PolicyError::Repository(format!(
            "authorization authority proof replay key canonicalization failed: {error}"
        ))
    })?;
    let mut material =
        Vec::with_capacity(AUTHORITY_PROOF_REPLAY_KEY_DOMAIN.len() + signing_bytes.len());
    material.extend_from_slice(AUTHORITY_PROOF_REPLAY_KEY_DOMAIN);
    material.extend_from_slice(&signing_bytes);
    Ok(hex::encode(Sha256::digest(material)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn replay_key_binds_the_signed_proof_identity() {
        let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
        let mut proof = AuthorizationFenceProof {
            authorization_edition: astral_types::AUTHORIZATION_EDITION,
            authority_id: "authority-a".to_owned(),
            authority_term: 1,
            global_fence_sequence: 1,
            scope: AuthorizationAuthorityScope {
                tenant_id: 7,
                card_id: 17,
                user_id: Some(23),
                domain: AuthorizationDomainScope::Any,
            },
            scope_generation: 1,
            revoke_watermark: 1,
            snapshot_hash: "00".repeat(32),
            parent_hash: None,
            operation_id: "operation-1".to_owned(),
            event_id: "event-1".to_owned(),
            key_id: "key-1".to_owned(),
            key_epoch: 1,
            issued_at: 100,
            not_before: 100,
            expires_at: 200,
            request_nonce: "nonce-1".to_owned(),
            request_binding_digest: None,
            scope_certificate_hash: None,
            proof_id: "proof-1".to_owned(),
            signature: "00".repeat(64),
        };
        let first = proof_replay_key(&proof).expect("canonical replay key");
        proof.global_fence_sequence = 2;
        let second = proof_replay_key(&proof).expect("canonical replay key");
        assert_ne!(first, second);
        assert_eq!(signing_key.verifying_key().to_bytes().len(), 32);
    }

    #[test]
    fn issuer_accepts_only_a_strictly_new_frontier_with_exact_parent() {
        let signing_key = SigningKey::from_bytes(&[21_u8; 32]);
        let trust_root = AuthorizationTrustRoot::new(
            "authority".to_owned(),
            "key-1".to_owned(),
            1,
            signing_key.verifying_key(),
        )
        .expect("trust root");
        let frontier = AuthorityFrontierRow {
            authority_id: "authority".to_owned(),
            authority_term: 1,
            global_fence_sequence: 4,
            key_id: "key-1".to_owned(),
            key_epoch: 1,
            snapshot_hash: Some(vec![0; 32]),
            status: "SERVING".to_owned(),
        };
        let mut lease = test_issuance_lease(2, 5);
        lease.previous_authority_term = 1;
        lease.previous_global_fence_sequence = 4;
        lease.previous_key_id = "key-1".to_owned();
        lease.previous_key_epoch = 1;
        lease.parent_hash = Some("00".repeat(32));
        assert!(validate_issuer_frontier(&frontier, &lease, &trust_root).is_ok());

        lease.parent_hash = Some("11".repeat(32));
        assert!(validate_issuer_frontier(&frontier, &lease, &trust_root).is_err());

        lease.parent_hash = Some("00".repeat(32));
        lease.previous_global_fence_sequence = 3;
        assert!(validate_issuer_frontier(&frontier, &lease, &trust_root).is_err());
    }

    #[test]
    fn issuer_rejects_same_or_older_global_fence() {
        let signing_key = SigningKey::from_bytes(&[22_u8; 32]);
        let trust_root = AuthorizationTrustRoot::new(
            "authority".to_owned(),
            "key-1".to_owned(),
            1,
            signing_key.verifying_key(),
        )
        .expect("trust root");
        let frontier = AuthorityFrontierRow {
            authority_id: "authority".to_owned(),
            authority_term: 1,
            global_fence_sequence: 4,
            key_id: "key-1".to_owned(),
            key_epoch: 1,
            snapshot_hash: Some(vec![0; 32]),
            status: "SERVING".to_owned(),
        };
        let mut lease = test_issuance_lease(1, 4);
        lease.previous_authority_term = 1;
        lease.previous_global_fence_sequence = 4;
        lease.previous_key_id = "key-1".to_owned();
        lease.previous_key_epoch = 1;
        assert!(validate_issuer_frontier(&frontier, &lease, &trust_root).is_err());
    }

    #[test]
    fn issuer_accepts_zero_parent_only_for_bootstrap_frontier() {
        let signing_key = SigningKey::from_bytes(&[23_u8; 32]);
        let trust_root = AuthorizationTrustRoot::new(
            "authority".to_owned(),
            "key-1".to_owned(),
            1,
            signing_key.verifying_key(),
        )
        .expect("trust root");
        let frontier = AuthorityFrontierRow {
            authority_id: "authority".to_owned(),
            authority_term: 0,
            global_fence_sequence: 0,
            key_id: "-".to_owned(),
            key_epoch: 0,
            snapshot_hash: None,
            status: "COLD".to_owned(),
        };
        let lease = test_issuance_lease(1, 1);
        assert!(validate_issuer_frontier(&frontier, &lease, &trust_root).is_ok());
    }

    fn test_issuance_lease(
        authority_term: u64,
        global_fence_sequence: u64,
    ) -> AuthorizationIssuanceLease {
        AuthorizationIssuanceLease {
            authorization_edition: astral_types::AUTHORIZATION_EDITION,
            authority_id: "authority".to_owned(),
            authority_term,
            global_fence_sequence,
            previous_authority_term: 0,
            previous_global_fence_sequence: 0,
            previous_key_id: "-".to_owned(),
            previous_key_epoch: 0,
            scope: AuthorizationAuthorityScope {
                tenant_id: 7,
                card_id: 17,
                user_id: None,
                domain: AuthorizationDomainScope::Any,
            },
            scope_generation: 1,
            revoke_watermark: 1,
            snapshot_hash: "00".repeat(32),
            parent_hash: None,
            operation_id: "operation".to_owned(),
            event_id: "event".to_owned(),
            key_id: "key-1".to_owned(),
            key_epoch: 1,
            issued_at: 100,
            not_before: 100,
            expires_at: 200,
            request_nonce: format!("nonce-{authority_term}-{global_fence_sequence}"),
            lease_id: format!("lease-{authority_term}-{global_fence_sequence}"),
            arbiter_id: "arbiter".to_owned(),
            arbiter_key_id: "arbiter-key".to_owned(),
            arbiter_key_epoch: 1,
            arbiter_signature: "00".repeat(64),
        }
    }
}
