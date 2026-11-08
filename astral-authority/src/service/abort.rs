//! Owner-only explicit abort of one `Reserved` reservation (V7).
//!
//! The abort is the ONLY protocol path from `Reserved` to the terminal
//! `Aborted` state. Its fail-closed rules:
//! - Only the trusted source that owns the reservation may abort it, and only
//!   for the EXACT operation, database and approved request digest of the
//!   reserved intent. There is no operator path: operators close, owners
//!   abort.
//! - Every abort request must carry the canonical digest of the durable local
//!   tombstone row (`source_tombstone_digest`). The authority cannot read the
//!   source database, so it never verifies the row itself — it verifies the
//!   caller is the REGISTERED source and records the immutable tombstone
//!   identity in the receipt. A lease expiry, a transport error or the
//!   absence of an outcome row is never accepted as a rollback proof.
//! - The transition is accepted ONLY from `Reserved`. `Committed`,
//!   `Published`, `Certified`, `Quarantined` (and any future terminal
//!   committed state) are refused: an unknown source commit is reconciled by
//!   stable identity first and is NEVER aborted.
//! - The EXACT same abort (stable abort id, binding, reason and tombstone
//!   digest) replays idempotently from the stored receipt, serving the
//!   recorded post-abort frontier — the frontier never re-advances and the
//!   receipt is never rewritten. Any different binding is a genuine conflict.
//! - The terminal flip, the frontier advance, the read-gate epoch bump and
//!   the receipt happen in ONE leadership-fenced CAS transaction, so a
//!   concurrent commit and abort are mutually exclusive: exactly one wins,
//!   the loser sees a clean `StateConflict`.

use astral_types::{
    AuthorityAbortReceipt, AuthorityAbortRequest, AuthorityAbortResponse, AuthorityProtocolError,
    AuthorityReservationDisposition, AuthorityReservationState, AuthorityScopeReservation,
    AUTHORIZATION_EDITION,
};

use super::{
    decode, encode, mutation_digest, now_unix, AuthorityService, StoreOp, StoreTxn, StoreTxnOutcome,
};
use crate::error::{AuthorityServiceError, AuthorityStoreError};

impl AuthorityService {
    /// Owner-only explicit abort of one `Reserved` reservation after a
    /// PROVEN local rollback (durable tombstone) or a proven never-begun
    /// transaction.
    pub async fn abort_reservation(
        &self,
        request: &AuthorityAbortRequest,
    ) -> Result<AuthorityAbortResponse, AuthorityServiceError> {
        self.authorize(&request.caller, "abort")?;
        request
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        self.require_leader()?;
        let now = now_unix();

        let reservation_record = self
            .store
            .get(&self.keys.reservation(&request.reservation_id))
            .await?
            .ok_or(AuthorityServiceError::Protocol(
                AuthorityProtocolError::NotFound {
                    record: "reservation",
                },
            ))?;
        let reservation: AuthorityScopeReservation =
            decode(&reservation_record.value, "reservation")?;
        reservation
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;

        // Exact owner binding: the authenticated caller must be the trusted
        // source that reserved this intent, for the exact operation, database
        // and approved request digest.
        if reservation.intent.service_id != request.caller.service_id
            || reservation.intent.database_id != request.database_id
            || reservation.intent.operation_id != request.operation_id
            || reservation.intent.request_digest != request.request_digest
        {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::CallerIdentityMismatch,
            ));
        }

        // State gate: only `Reserved` aborts. The already-aborted state is
        // idempotent ONLY for the EXACT recorded abort (stable id, binding,
        // reason and tombstone digest); anything else — including every
        // committed/certified/published/quarantined state, present or added
        // later — is a genuine conflict.
        if reservation.state != AuthorityReservationState::Reserved {
            if reservation.state == AuthorityReservationState::Aborted {
                if let Some(record) = self
                    .store
                    .get(&self.keys.abort_receipt(&request.reservation_id))
                    .await?
                {
                    let receipt: AuthorityAbortReceipt = decode(&record.value, "abort receipt")?;
                    receipt
                        .validate()
                        .map_err(AuthorityServiceError::Protocol)?;
                    if receipt.matches_abort(request, &reservation) {
                        let state = self.load_verified_state().await?;
                        state.verify_historical_frontier(&receipt.global_frontier)?;
                        let read_gate = self.evaluate_read_gate().await?;
                        let recorded_frontier = receipt.global_frontier.clone();
                        return Ok(AuthorityAbortResponse {
                            disposition: AuthorityReservationDisposition::Aborted,
                            reservation,
                            receipt,
                            global_frontier: recorded_frontier,
                            read_gate,
                        });
                    }
                }
            }
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::StateConflict {
                    record: "reservation",
                    state: reservation.state.as_text().to_owned(),
                },
            ));
        }

        let state = self.load_verified_state().await?;
        let digest = mutation_digest("reservation-abort", &request.reservation_id);
        let next_frontier = state
            .frontier
            .advance(&request.operation_id, &digest, now)
            .map_err(AuthorityServiceError::Protocol)?;
        let mut aborted = reservation.clone();
        aborted.state = AuthorityReservationState::Aborted;
        aborted.updated_at = now;
        aborted
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;

        let receipt = AuthorityAbortReceipt {
            authorization_edition: AUTHORIZATION_EDITION,
            reservation_id: aborted.reservation_id.clone(),
            abort_id: request.abort_id.clone(),
            operation_id: aborted.intent.operation_id.clone(),
            event_id: aborted.intent.event_id.clone(),
            admission_proof_id: aborted.intent.admission_proof_id.clone(),
            request_digest: aborted.intent.request_digest.clone(),
            service_id: aborted.intent.service_id.clone(),
            database_id: aborted.intent.database_id.clone(),
            intent_digest: aborted.intent_digest.clone(),
            reason: request.reason.trim().to_owned(),
            source_tombstone_digest: request.source_tombstone_digest.clone(),
            aborted_at: now,
            global_frontier: next_frontier.clone(),
        };
        receipt
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;

        // One leadership-fenced CAS: the terminal flip competes with a
        // concurrent source commit on the SAME reservation-record revision,
        // so exactly one of commit/abort can ever apply.
        let lock_record = self
            .store
            .get(&self.keys.source_bootstrap_global_lock())
            .await?;
        let lock_revision = if reservation.intent.mutation_kind.blocks_positive_reads() {
            Some(
                lock_record
                    .as_ref()
                    .ok_or_else(|| {
                        AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                            "authorization reservation global lock is missing".to_owned(),
                        ))
                    })
                    .and_then(|record| {
                        let owner: (String, String, String) =
                            decode(&record.value, "authorization global lock")?;
                        if owner.0 != reservation.intent.operation_id
                            || owner.1 != reservation.reservation_id
                            || owner.2 != reservation.intent_digest
                        {
                            return Err(AuthorityServiceError::Store(
                                AuthorityStoreError::Corrupt(
                                    "authorization reservation global lock owner differs"
                                        .to_owned(),
                                ),
                            ));
                        }
                        Ok(record.revision)
                    })?,
            )
        } else {
            None
        };
        let mut txn = StoreTxn::new()
            .with_op(StoreOp::ReplaceIfRevision {
                key: self.keys.reservation(&request.reservation_id),
                expected_revision: reservation_record.revision,
                value: encode(&aborted)?,
            })
            .with_op(StoreOp::ReplaceIfRevision {
                key: self.keys.frontier(),
                expected_revision: state.frontier_revision,
                value: encode(&next_frontier)?,
            })
            .with_op(self.bump_gate_epoch_op(&state)?)
            .with_op(StoreOp::PutIfAbsent {
                key: self.keys.abort_receipt(&request.reservation_id),
                value: encode(&receipt)?,
            });
        if let Some(expected_revision) = lock_revision {
            txn = txn.with_op(StoreOp::DeleteIfRevision {
                key: self.keys.source_bootstrap_global_lock(),
                expected_revision,
            });
        }
        let outcome = self.execute_leader_txn(txn).await;
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => return Err(self.map_store_error(error, &request.reservation_id)),
        };
        match outcome {
            StoreTxnOutcome::PreconditionFailed { .. } => Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::StateConflict {
                    record: "reservation",
                    state: "CONCURRENT".to_owned(),
                },
            )),
            StoreTxnOutcome::Applied { .. } => {
                let read_gate = self.evaluate_read_gate().await?;
                Ok(AuthorityAbortResponse {
                    disposition: AuthorityReservationDisposition::Aborted,
                    reservation: aborted,
                    receipt,
                    global_frontier: next_frontier,
                    read_gate,
                })
            }
        }
    }
}
