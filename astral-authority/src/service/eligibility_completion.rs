//! Distinct production ELIGIBILITY completion (V7).
//!
//! The terminal completion path for eligibility-sync source mutations. It is
//! deliberately NOT the publication path: no certificate, no scope pointer,
//! no certified scope and no grant coverage is ever written here. The source
//! presents the FULL exact COMMITTED binding plus the retained staged
//! evidence bytes whose canonical digest was pinned at commit; this handler
//! re-proves the pin against the STORED commit binding, strict-decodes the
//! dedicated `ELIGIBILITY_COMPLETION` shape (envelope coverage must be
//! `None`; the verbatim source mirror inside stays opaque to the authority
//! and is validated by the registered DB source owner), and records an
//! immutable receipt in the SAME leader-fenced CAS that flips the
//! reservation to its terminal `Completed` state, advances the global
//! frontier and bumps the read-gate epoch.
//!
//! Fail-closed rules:
//! - Only a registered trusted source holding the explicit
//!   `eligibility_completion` allowed operation may call this endpoint, and
//!   only for `AuthorizationSource` mutations it owns on a registered
//!   database.
//! - The reservation must be exactly `Committed` with no publication state;
//!   `Reserved` is a stale/missing commit and every other state is a
//!   terminal conflict.
//! - The request binding must equal the stored binding field-for-field and
//!   the recomputed canonical digest of the retained bytes must equal the
//!   stored binding's `staged_evidence_digest`: a request can never declare
//!   a different completion than the one staged at commit, and a completed
//!   reservation replays only for the EXACT original request (anything else
//!   is a conflict, never a re-issue).
//! - Store-unavailable outcomes map to `UnknownOutcome` (reconcile by
//!   stable reservation identity; a source replay is never implied), and a
//!   lost CAS race is a `CONCURRENT` conflict.

use astral_types::{
    AuthorityCommitBinding, AuthorityEligibilityCompletionEvidence,
    AuthorityEligibilityCompletionReceipt, AuthorityEligibilityCompletionRequest,
    AuthorityEligibilityCompletionResponse, AuthorityMutationKind, AuthorityProtocolError,
    AuthorityReservationDisposition, AuthorityReservationState, AuthorityScopeReservation,
    AuthorityStagedSourceEvidence, AUTHORITY_OPERATION_ELIGIBILITY_COMPLETION,
};

use super::{
    decode, encode, fresh_id, mutation_digest, now_unix, AuthorityService, AuthorityServiceError,
};
use crate::error::AuthorityStoreError;
use crate::store::{StoreOp, StoreTxn, StoreTxnOutcome};

impl AuthorityService {
    /// Record the immutable eligibility completion receipt of one exactly
    /// committed reservation and move it to the terminal `Completed` state.
    pub async fn record_eligibility_completion(
        &self,
        request: &AuthorityEligibilityCompletionRequest,
    ) -> Result<AuthorityEligibilityCompletionResponse, AuthorityServiceError> {
        // Registered source + database + explicit operator-configured
        // `eligibility_completion` capability. Not arbitrary callers.
        self.authorize(&request.caller, AUTHORITY_OPERATION_ELIGIBILITY_COMPLETION)?;
        let source = self
            .config
            .trusted_source_by_id(&request.caller.service_id)
            .ok_or_else(|| AuthorityServiceError::NotAuthorized {
                caller: request.caller.service_id.clone(),
                operation: AUTHORITY_OPERATION_ELIGIBILITY_COMPLETION,
            })?;
        if source.allowed_database_ids.is_empty()
            || !source
                .allowed_database_ids
                .contains(&request.binding.database_id)
        {
            return Err(AuthorityServiceError::NotAuthorized {
                caller: request.binding.database_id.clone(),
                operation: AUTHORITY_OPERATION_ELIGIBILITY_COMPLETION,
            });
        }
        request
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        self.require_leader()?;
        let now = now_unix();

        let reservation_record = self
            .store
            .get(&self.keys.reservation(&request.binding.reservation_id))
            .await?
            .ok_or(AuthorityServiceError::Protocol(
                AuthorityProtocolError::NotFound {
                    record: "reservation",
                },
            ))?;
        let mut reservation: AuthorityScopeReservation =
            decode(&reservation_record.value, "reservation")?;
        reservation
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;

        // The authenticated caller must own the reservation.
        if reservation.intent.service_id != request.caller.service_id {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::CallerIdentityMismatch,
            ));
        }
        // Only AuthorizationSource mutations complete eligibility; a
        // ProtectedBusiness reservation has no eligibility semantics.
        if reservation.intent.mutation_kind != AuthorityMutationKind::AuthorizationSource {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::StateConflict {
                    record: "reservation",
                    state: reservation.intent.mutation_kind.as_text().to_owned(),
                },
            ));
        }
        // Exact identity binding: the echoed binding must be THIS
        // reservation's intent, field for field.
        if reservation.intent.mutation_kind != request.binding.mutation_kind
            || reservation.intent.service_id != request.binding.service_id
            || reservation.intent.database_id != request.binding.database_id
            || reservation.intent.operation_id != request.binding.operation_id
            || reservation.intent.event_id != request.binding.event_id
            || reservation.intent.admission_proof_id != request.binding.admission_proof_id
            || reservation.intent.request_digest != request.binding.request_digest
        {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::ScopeMismatch,
            ));
        }

        // Only an exact commit or its terminal completion can enter the
        // common verification path. Other terminal states never replay.
        if !matches!(
            reservation.state,
            AuthorityReservationState::Committed | AuthorityReservationState::Completed
        ) {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::StateConflict {
                    record: "reservation",
                    state: reservation.state.as_text().to_owned(),
                },
            ));
        }
        if reservation.certificate_id.is_some() || !reservation.certified_scopes.is_empty() {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::StateConflict {
                    record: "reservation",
                    state: "PUBLICATION_PATH".to_owned(),
                },
            ));
        }
        // The reservation source-commit fields must agree for both initial
        // completion and replay.
        if reservation.source_commit_digest.as_deref()
            != Some(request.binding.source_commit_digest.as_str())
            || reservation.after_image_digest.as_deref()
                != Some(request.binding.after_image_digest.as_str())
            || reservation.source_outcome_digest.as_deref()
                != Some(request.binding.source_outcome_digest.as_str())
        {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::ScopeMismatch,
            ));
        }

        if reservation.committed_at.is_none() {
            return Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                "committed eligibility reservation lacks commit timestamp".to_owned(),
            )));
        }

        // The STORED commit binding is the only trusted pin: the request
        // binding must equal it field-for-field before anything else is
        // believed. This applies equally to fresh completion and terminal
        // replay, so a replay cannot bypass the original DB/source binding.
        let binding_record = self
            .store
            .get(&self.keys.commit_binding(&reservation.reservation_id))
            .await?
            .ok_or_else(|| {
                AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                    "source commit binding is missing".to_owned(),
                ))
            })?;
        let stored_binding: AuthorityCommitBinding =
            decode(&binding_record.value, "source commit binding")?;
        stored_binding
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        if stored_binding != request.binding {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::ScopeMismatch,
            ));
        }

        // COMMIT-staged digest pin: recompute the canonical digest over the
        // retained envelope bytes and compare against the STORED binding.
        let retained_digest = request
            .retained_staged_evidence
            .canonical_digest()
            .map_err(AuthorityServiceError::Protocol)?;
        if retained_digest != stored_binding.staged_evidence_digest {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::DigestMismatch {
                    field: "staged_evidence_digest",
                },
            ));
        }
        // Strict dedicated eligibility shape: the envelope declares NO grant
        // coverage and its evidence is exactly the typed completion shape.
        let envelope: AuthorityStagedSourceEvidence = request
            .retained_staged_evidence
            .staged_envelope()
            .map_err(AuthorityServiceError::Protocol)?;
        let completion = AuthorityEligibilityCompletionEvidence::from_staged_envelope(&envelope)
            .map_err(AuthorityServiceError::Protocol)?;
        if completion != request.completion {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::DigestMismatch {
                    field: "declared_completion",
                },
            ));
        }

        // Stored commit coverage must bind to the exact commit and declare no
        // grant publication scopes. This is part of common verification and
        // applies to terminal replay as well as a fresh completion.
        let coverage = self
            .load_commit_coverage(&reservation, &stored_binding)
            .await?;
        if coverage.declared_coverage().is_some() {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::InvalidCoverage,
            ));
        }

        // Terminal replay: the original receipt is read-only and remains
        // valid after rotations/frontier advances, provided its recorded
        // frontier belongs to the verified authority history.
        if reservation.state == AuthorityReservationState::Completed {
            if reservation.committed_at.is_none() {
                return Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                    "completed eligibility reservation lacks commit timestamp".to_owned(),
                )));
            }
            let receipt_record = self
                .store
                .get(
                    &self
                        .keys
                        .eligibility_completion(&reservation.reservation_id),
                )
                .await?
                .ok_or_else(|| {
                    AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                        "eligibility completion receipt is missing".to_owned(),
                    ))
                })?;
            let receipt: AuthorityEligibilityCompletionReceipt =
                decode(&receipt_record.value, "eligibility completion receipt")?;
            receipt
                .validate()
                .map_err(AuthorityServiceError::Protocol)?;
            if receipt.binding != stored_binding
                || receipt.binding != request.binding
                || receipt.completion != completion
                || receipt.completion != request.completion
                || receipt.reservation_id != reservation.reservation_id
                || receipt.operation_id != reservation.intent.operation_id
                || receipt.event_id != reservation.intent.event_id
                || receipt.binding.database_id != reservation.intent.database_id
                || receipt.binding.service_id != reservation.intent.service_id
                || reservation.source_commit_digest.as_deref()
                    != Some(receipt.binding.source_commit_digest.as_str())
                || reservation.after_image_digest.as_deref()
                    != Some(receipt.binding.after_image_digest.as_str())
                || reservation.source_outcome_digest.as_deref()
                    != Some(receipt.binding.source_outcome_digest.as_str())
            {
                return Err(AuthorityServiceError::Protocol(
                    AuthorityProtocolError::ScopeMismatch,
                ));
            }
            let state = self.load_verified_state().await?;
            state.verify_historical_frontier(&receipt.global_frontier)?;
            if receipt.global_frontier.authority_id != state.frontier.authority_id
                || receipt.global_frontier.authority_term > state.frontier.authority_term
                || receipt.global_frontier.global_fence_sequence
                    > state.frontier.global_fence_sequence
            {
                return Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                    "eligibility completion receipt frontier is not in authority history"
                        .to_owned(),
                )));
            }
            let read_gate = self.evaluate_read_gate().await?;
            let response = AuthorityEligibilityCompletionResponse {
                disposition: AuthorityReservationDisposition::Completed,
                reservation,
                global_frontier: receipt.global_frontier.clone(),
                read_gate,
                receipt,
            };
            response
                .validate()
                .map_err(AuthorityServiceError::Protocol)?;
            return Ok(response);
        }
        // Only COMMITTED reaches the mutating path. COMPLETED returned above
        // after exact typed receipt verification; all remaining states fail.
        if reservation.state != AuthorityReservationState::Committed {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::StateConflict {
                    record: "reservation",
                    state: reservation.state.as_text().to_owned(),
                },
            ));
        }

        let state = self.load_verified_state().await?;
        let digest = mutation_digest("eligibility-completion", &reservation.reservation_id);
        let next_frontier = state
            .frontier
            .advance(&request.binding.operation_id, &digest, now)
            .map_err(AuthorityServiceError::Protocol)?;
        reservation.state = AuthorityReservationState::Completed;
        reservation.updated_at = now;
        reservation
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;

        let receipt = AuthorityEligibilityCompletionReceipt {
            receipt_id: fresh_id("elig"),
            reservation_id: reservation.reservation_id.clone(),
            operation_id: request.binding.operation_id.clone(),
            event_id: request.binding.event_id.clone(),
            binding: request.binding.clone(),
            completion: completion.clone(),
            completed_at: now,
            global_frontier: next_frontier.clone(),
        };
        receipt
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;

        let lock_record = self
            .store
            .get(&self.keys.source_bootstrap_global_lock())
            .await?;
        let lock_revision = lock_record
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
                    return Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                        "authorization reservation global lock owner differs".to_owned(),
                    )));
                }
                Ok(record.revision)
            })?;
        // One leader-fenced CAS: the immutable receipt, the terminal
        // reservation flip, the frontier advance and the read-gate epoch
        // land together or not at all. Zero grant/certificate writes.
        let outcome = self
            .execute_leader_txn(
                StoreTxn::new()
                    .with_op(StoreOp::PutIfAbsent {
                        key: self
                            .keys
                            .eligibility_completion(&reservation.reservation_id),
                        value: encode(&receipt)?,
                    })
                    .with_op(StoreOp::ReplaceIfRevision {
                        key: self.keys.reservation(&reservation.reservation_id),
                        expected_revision: reservation_record.revision,
                        value: encode(&reservation)?,
                    })
                    .with_op(StoreOp::ReplaceIfRevision {
                        key: self.keys.frontier(),
                        expected_revision: state.frontier_revision,
                        value: encode(&next_frontier)?,
                    })
                    .with_op(self.bump_gate_epoch_op(&state)?)
                    .with_op(StoreOp::DeleteIfRevision {
                        key: self.keys.source_bootstrap_global_lock(),
                        expected_revision: lock_revision,
                    }),
            )
            .await;
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => return Err(self.map_store_error(error, &reservation.reservation_id)),
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
                let response = AuthorityEligibilityCompletionResponse {
                    disposition: AuthorityReservationDisposition::Completed,
                    reservation,
                    receipt,
                    global_frontier: next_frontier,
                    read_gate,
                };
                response
                    .validate()
                    .map_err(AuthorityServiceError::Protocol)?;
                Ok(response)
            }
        }
    }
}
