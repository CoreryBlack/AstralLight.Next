//! Terminal completion for captured non-grant configuration source writes.
//!
//! This path is disjoint from publication: it accepts only the exact retained
//! configuration row-image/audit batch, requires all projection effects empty,
//! and atomically records a terminal receipt with the reservation/frontier/gate.

use astral_types::{
    AuthorityCommitBinding, AuthorityConfigCompletionEvidence, AuthorityConfigCompletionReceipt,
    AuthorityConfigCompletionRequest, AuthorityConfigCompletionResponse, AuthorityMutationKind,
    AuthorityProtocolError, AuthorityReservationDisposition, AuthorityReservationState,
    AuthorityScopeReservation, AuthorityStagedSourceEvidence,
    AUTHORITY_OPERATION_CONFIG_COMPLETION,
};

use super::{decode, encode, fresh_id, mutation_digest, now_unix, AuthorityService};
use crate::error::AuthorityStoreError;
use crate::store::{StoreOp, StoreTxn, StoreTxnOutcome};

impl AuthorityService {
    /// Record the immutable terminal receipt for exactly one committed config
    /// mutation. No publication certificate or scope pointer is produced.
    pub async fn record_config_completion(
        &self,
        request: &AuthorityConfigCompletionRequest,
    ) -> Result<AuthorityConfigCompletionResponse, super::AuthorityServiceError> {
        self.authorize(&request.caller, AUTHORITY_OPERATION_CONFIG_COMPLETION)?;
        let source = self
            .config
            .trusted_source_by_id(&request.caller.service_id)
            .ok_or_else(|| super::AuthorityServiceError::NotAuthorized {
                caller: request.caller.service_id.clone(),
                operation: AUTHORITY_OPERATION_CONFIG_COMPLETION,
            })?;
        if source.allowed_database_ids.is_empty()
            || !source
                .allowed_database_ids
                .contains(&request.binding.database_id)
        {
            return Err(super::AuthorityServiceError::NotAuthorized {
                caller: request.binding.database_id.clone(),
                operation: AUTHORITY_OPERATION_CONFIG_COMPLETION,
            });
        }
        request
            .validate()
            .map_err(super::AuthorityServiceError::Protocol)?;
        self.require_leader()?;

        let reservation_record = self
            .store
            .get(&self.keys.reservation(&request.binding.reservation_id))
            .await?
            .ok_or(super::AuthorityServiceError::Protocol(
                AuthorityProtocolError::NotFound {
                    record: "reservation",
                },
            ))?;
        let mut reservation: AuthorityScopeReservation =
            decode(&reservation_record.value, "reservation")?;
        reservation
            .validate()
            .map_err(super::AuthorityServiceError::Protocol)?;
        if reservation.intent.service_id != request.caller.service_id {
            return Err(super::AuthorityServiceError::Protocol(
                AuthorityProtocolError::CallerIdentityMismatch,
            ));
        }
        if reservation.intent.mutation_kind != AuthorityMutationKind::AuthorizationSource {
            return Err(super::AuthorityServiceError::Protocol(
                AuthorityProtocolError::StateConflict {
                    record: "reservation",
                    state: reservation.intent.mutation_kind.as_text().to_owned(),
                },
            ));
        }
        if !matches!(
            reservation.state,
            AuthorityReservationState::Committed | AuthorityReservationState::Completed
        ) {
            return Err(super::AuthorityServiceError::Protocol(
                AuthorityProtocolError::StateConflict {
                    record: "reservation",
                    state: reservation.state.as_text().to_owned(),
                },
            ));
        }
        if reservation.committed_at.is_none() {
            return Err(super::AuthorityServiceError::Store(
                AuthorityStoreError::Corrupt(
                    "committed config reservation lacks commit timestamp".to_owned(),
                ),
            ));
        }
        if reservation.intent.mutation_kind != request.binding.mutation_kind
            || reservation.intent.service_id != request.binding.service_id
            || reservation.intent.database_id != request.binding.database_id
            || reservation.intent.operation_id != request.binding.operation_id
            || reservation.intent.event_id != request.binding.event_id
            || reservation.intent.admission_proof_id != request.binding.admission_proof_id
            || reservation.intent.request_digest != request.binding.request_digest
        {
            return Err(super::AuthorityServiceError::Protocol(
                AuthorityProtocolError::ScopeMismatch,
            ));
        }

        if reservation.certificate_id.is_some() || !reservation.certified_scopes.is_empty() {
            return Err(super::AuthorityServiceError::Protocol(
                AuthorityProtocolError::StateConflict {
                    record: "reservation",
                    state: "PUBLICATION_PATH".to_owned(),
                },
            ));
        }
        let binding_record = self
            .store
            .get(&self.keys.commit_binding(&reservation.reservation_id))
            .await?
            .ok_or_else(|| {
                super::AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                    "source commit binding is missing".to_owned(),
                ))
            })?;
        let stored_binding: AuthorityCommitBinding =
            decode(&binding_record.value, "source commit binding")?;
        stored_binding
            .validate()
            .map_err(super::AuthorityServiceError::Protocol)?;
        if stored_binding != request.binding
            || reservation.source_commit_digest.as_deref()
                != Some(stored_binding.source_commit_digest.as_str())
            || reservation.after_image_digest.as_deref()
                != Some(stored_binding.after_image_digest.as_str())
            || reservation.source_outcome_digest.as_deref()
                != Some(stored_binding.source_outcome_digest.as_str())
        {
            return Err(super::AuthorityServiceError::Protocol(
                AuthorityProtocolError::ScopeMismatch,
            ));
        }
        if request
            .retained_staged_evidence
            .canonical_digest()
            .map_err(super::AuthorityServiceError::Protocol)?
            != stored_binding.staged_evidence_digest
        {
            return Err(super::AuthorityServiceError::Protocol(
                AuthorityProtocolError::DigestMismatch {
                    field: "staged_evidence_digest",
                },
            ));
        }
        let staged_envelope: AuthorityStagedSourceEvidence = request
            .retained_staged_evidence
            .staged_envelope()
            .map_err(super::AuthorityServiceError::Protocol)?;
        let staged_completion: AuthorityConfigCompletionEvidence =
            serde_json::from_value(staged_envelope.evidence).map_err(|_| {
                super::AuthorityServiceError::Protocol(AuthorityProtocolError::DigestMismatch {
                    field: "evidence",
                })
            })?;
        if staged_envelope.coverage.is_some() {
            return Err(super::AuthorityServiceError::Protocol(
                AuthorityProtocolError::InvalidCoverage,
            ));
        }
        staged_completion
            .validate(&request.binding.operation_id)
            .map_err(super::AuthorityServiceError::Protocol)?;
        let stored_coverage = self
            .load_commit_coverage(&reservation, &stored_binding)
            .await?;
        if stored_coverage.declared_coverage().is_some() {
            return Err(super::AuthorityServiceError::Protocol(
                AuthorityProtocolError::InvalidCoverage,
            ));
        }
        if staged_completion != request.completion {
            return Err(super::AuthorityServiceError::Protocol(
                AuthorityProtocolError::DigestMismatch {
                    field: "declared_completion",
                },
            ));
        }
        if reservation.state == AuthorityReservationState::Completed {
            let receipt_record = self
                .store
                .get(&self.keys.config_completion(&reservation.reservation_id))
                .await?
                .ok_or_else(|| {
                    super::AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                        "config completion receipt is missing".to_owned(),
                    ))
                })?;
            let receipt: AuthorityConfigCompletionReceipt =
                decode(&receipt_record.value, "config completion receipt")?;
            receipt
                .validate()
                .map_err(super::AuthorityServiceError::Protocol)?;
            if receipt.binding != stored_binding
                || receipt.binding != request.binding
                || receipt.completion != staged_completion
                || receipt.reservation_id != reservation.reservation_id
                || receipt.operation_id != reservation.intent.operation_id
                || receipt.event_id != reservation.intent.event_id
                || receipt.binding.mutation_kind != AuthorityMutationKind::AuthorizationSource
            {
                return Err(super::AuthorityServiceError::Protocol(
                    AuthorityProtocolError::StateConflict {
                        record: "reservation",
                        state: reservation.state.as_text().to_owned(),
                    },
                ));
            }
            let state = self.load_verified_state().await?;
            state.verify_historical_frontier(&receipt.global_frontier)?;
            let read_gate = self.evaluate_read_gate().await?;
            let response = AuthorityConfigCompletionResponse {
                disposition: AuthorityReservationDisposition::Completed,
                reservation,
                global_frontier: receipt.global_frontier.clone(),
                read_gate,
                receipt,
            };
            response
                .validate()
                .map_err(super::AuthorityServiceError::Protocol)?;
            return Ok(response);
        }
        if reservation.state != AuthorityReservationState::Committed {
            return Err(super::AuthorityServiceError::Protocol(
                AuthorityProtocolError::StateConflict {
                    record: "reservation",
                    state: reservation.state.as_text().to_owned(),
                },
            ));
        }
        let state = self.load_verified_state().await?;
        let now = now_unix();
        let digest = mutation_digest("config-completion", &reservation.reservation_id);
        let next_frontier = state
            .frontier
            .advance(&request.binding.operation_id, &digest, now)
            .map_err(super::AuthorityServiceError::Protocol)?;
        reservation.state = AuthorityReservationState::Completed;
        reservation.updated_at = now;
        reservation
            .validate()
            .map_err(super::AuthorityServiceError::Protocol)?;
        let receipt = AuthorityConfigCompletionReceipt {
            receipt_id: fresh_id("config"),
            reservation_id: reservation.reservation_id.clone(),
            operation_id: request.binding.operation_id.clone(),
            event_id: request.binding.event_id.clone(),
            binding: request.binding.clone(),
            completion: request.completion.clone(),
            completed_at: now,
            global_frontier: next_frontier.clone(),
        };
        receipt
            .validate()
            .map_err(super::AuthorityServiceError::Protocol)?;

        let lock_record = self
            .store
            .get(&self.keys.source_bootstrap_global_lock())
            .await?;
        let lock_revision = lock_record
            .as_ref()
            .ok_or_else(|| {
                super::AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
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
                    return Err(super::AuthorityServiceError::Store(
                        AuthorityStoreError::Corrupt(
                            "authorization reservation global lock owner differs".to_owned(),
                        ),
                    ));
                }
                Ok(record.revision)
            })?;
        let mut txn = StoreTxn::new()
            .with_op(StoreOp::PutIfAbsent {
                key: self.keys.config_completion(&reservation.reservation_id),
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
            .with_op(self.bump_gate_epoch_op(&state)?);
        txn = txn.with_op(StoreOp::DeleteIfRevision {
            key: self.keys.source_bootstrap_global_lock(),
            expected_revision: lock_revision,
        });
        let outcome = self.execute_leader_txn(txn).await;
        let outcome =
            outcome.map_err(|error| self.map_store_error(error, &reservation.reservation_id))?;
        match outcome {
            StoreTxnOutcome::PreconditionFailed { .. } => Err(
                super::AuthorityServiceError::Protocol(AuthorityProtocolError::StateConflict {
                    record: "reservation",
                    state: "CONCURRENT".to_owned(),
                }),
            ),
            StoreTxnOutcome::Applied { .. } => {
                let response = AuthorityConfigCompletionResponse {
                    disposition: AuthorityReservationDisposition::Completed,
                    reservation,
                    receipt,
                    global_frontier: next_frontier,
                    read_gate: self.evaluate_read_gate().await?,
                };
                response
                    .validate()
                    .map_err(super::AuthorityServiceError::Protocol)?;
                Ok(response)
            }
        }
    }
}
