//! Dedicated ROOT-signed source-bootstrap admission control.
//!
//! This module intentionally does not call ordinary `prepare_source_mutation`,
//! does not mint an `AuthorizationFenceProof`, and does not create a normal
//! scope reservation or publication certificate. Its reservation is a separate
//! durable record keyed by operation identity and ticket digest.

use astral_types::{
    AuthorityProtocolError, AuthoritySourceBootstrapCapability,
    AuthoritySourceBootstrapCompletionReceipt, AuthoritySourceBootstrapFinalizeRequest,
    AuthoritySourceBootstrapFinalizeResponse, AuthoritySourceBootstrapPrepareRequest,
    AuthoritySourceBootstrapPrepareResponse, AuthoritySourceBootstrapReconcileRequest,
    AuthoritySourceBootstrapReconcileResponse, AuthoritySourceBootstrapReservation,
    AuthoritySourceBootstrapState, AUTHORITY_OPERATION_SOURCE_BOOTSTRAP_FINALIZE,
    AUTHORITY_OPERATION_SOURCE_BOOTSTRAP_PREPARE, AUTHORITY_OPERATION_SOURCE_BOOTSTRAP_RECONCILE,
    AUTHORITY_PROTOCOL_VERSION, AUTHORIZATION_EDITION,
};
use serde::{Deserialize, Serialize};

use super::{decode, encode, fresh_id, mutation_digest, now_unix, AuthorityService};
use crate::error::{AuthorityServiceError, AuthorityStoreError};
use crate::store::{StoreOp, StoreTxn, StoreTxnOutcome};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredSourceBootstrapOperation {
    ticket_digest: String,
    payload_digest: String,
    service_id: String,
    database_id: String,
    capability: AuthoritySourceBootstrapCapability,
    reservation: AuthoritySourceBootstrapReservation,
    prepared_frontier: astral_types::GlobalAuthorityFrontier,
    prepared_gate_epoch: u64,
    prepared_read_gate: astral_types::AuthorityReadGate,
}

impl AuthorityService {
    /// Verify a ROOT-signed ticket against the currently attested durable root.
    /// The caller-supplied key is never trusted; the key is resolved by role and
    /// id from `load_verified_state`.
    fn verify_source_bootstrap_ticket(
        &self,
        ticket: &astral_types::AuthoritySourceBootstrapTicket,
        state: &super::VerifiedAuthorityState,
        now: Option<i64>,
    ) -> Result<String, AuthorityServiceError> {
        let trust_root_digest = state
            .trust_root
            .digest()
            .map_err(AuthorityServiceError::Protocol)?;
        if ticket.authority_id != self.config.identity.authority_id
            || ticket.root_id != state.trust_root.root_id
            || ticket.trust_root_digest != trust_root_digest
        {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::TrustRootMismatch,
            ));
        }
        let root = state
            .trust_root
            .key_by_id(&ticket.root_key_id)
            .filter(|key| key.role == astral_types::AuthorityRootKeyRole::Root)
            .ok_or(AuthorityServiceError::Protocol(
                AuthorityProtocolError::TrustRootMismatch,
            ))?;
        let root_key = root
            .verifying_key()
            .map_err(AuthorityServiceError::Protocol)?;
        match now {
            Some(now) => ticket
                .verify_at(&root_key, now)
                .map_err(AuthorityServiceError::Protocol)?,
            None => ticket
                .verify(&root_key)
                .map_err(AuthorityServiceError::Protocol)?,
        }
        ticket
            .artifact_digest()
            .map_err(AuthorityServiceError::Protocol)
    }

    fn validate_source_bootstrap_registration(
        &self,
        service_id: &str,
        database_id: &str,
        operation: &'static str,
    ) -> Result<(), AuthorityServiceError> {
        let source = self.config.trusted_source_by_id(service_id).ok_or(
            AuthorityServiceError::NotAuthorized {
                caller: service_id.to_owned(),
                operation,
            },
        )?;
        if !source
            .allowed_database_ids
            .iter()
            .any(|value| value == database_id)
        {
            return Err(AuthorityServiceError::NotAuthorized {
                caller: database_id.to_owned(),
                operation,
            });
        }
        Ok(())
    }

    fn source_bootstrap_lock_value(
        operation_id: &str,
        reservation_id: &str,
        ticket_digest: &str,
    ) -> Result<Vec<u8>, AuthorityServiceError> {
        encode(&(operation_id, reservation_id, ticket_digest))
    }

    pub async fn prepare_root_source_bootstrap(
        &self,
        request: &AuthoritySourceBootstrapPrepareRequest,
    ) -> Result<AuthoritySourceBootstrapPrepareResponse, AuthorityServiceError> {
        self.authorize(
            &request.caller,
            AUTHORITY_OPERATION_SOURCE_BOOTSTRAP_PREPARE,
        )?;
        request
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        self.validate_source_bootstrap_registration(
            &request.ticket.service_id,
            &request.ticket.database_id,
            AUTHORITY_OPERATION_SOURCE_BOOTSTRAP_PREPARE,
        )?;
        self.require_leader()?;
        let state = self.load_verified_state().await?;
        self.require_active_signer(&state)?;
        let ticket_digest = request
            .ticket
            .artifact_digest()
            .map_err(AuthorityServiceError::Protocol)?;
        let now = now_unix();

        // A durable operation is checked before the ticket's wall-clock window:
        // exact replay is a read-back, while a new operation must be currently
        // valid. This prevents expiry from turning a known result into replay.
        if let Some(record) = self
            .store
            .get(
                &self
                    .keys
                    .source_bootstrap_operation(&request.ticket.operation_id),
            )
            .await?
        {
            let stored: StoredSourceBootstrapOperation =
                decode(&record.value, "source bootstrap operation")?;
            if stored.ticket_digest != ticket_digest {
                return Err(AuthorityServiceError::Protocol(
                    AuthorityProtocolError::StateConflict {
                        record: "source_bootstrap_operation",
                        state: "OPERATION_DIGEST_CONFLICT".to_owned(),
                    },
                ));
            }
            self.verify_source_bootstrap_ticket(&request.ticket, &state, None)?;
            if stored.service_id != request.ticket.service_id
                || stored.database_id != request.ticket.database_id
            {
                return Err(AuthorityServiceError::Protocol(
                    AuthorityProtocolError::CallerIdentityMismatch,
                ));
            }
            stored
                .reservation
                .validate()
                .map_err(AuthorityServiceError::Protocol)?;
            stored
                .capability
                .validate()
                .map_err(AuthorityServiceError::Protocol)?;
            return Ok(AuthoritySourceBootstrapPrepareResponse {
                capability: stored.capability,
                reservation: stored.reservation,
                global_frontier: stored.prepared_frontier,
                gate_epoch: stored.prepared_gate_epoch,
                read_gate: stored.prepared_read_gate,
            });
        }

        self.verify_source_bootstrap_ticket(&request.ticket, &state, Some(now_unix()))?;
        let reservation_id = fresh_id("srcres");
        let mut reservation = AuthoritySourceBootstrapReservation {
            reservation_id: reservation_id.clone(),
            operation_id: request.ticket.operation_id.clone(),
            event_id: request.ticket.event_id.clone(),
            ticket_digest: ticket_digest.clone(),
            service_id: request.ticket.service_id.clone(),
            database_id: request.ticket.database_id.clone(),
            state: AuthoritySourceBootstrapState::Reserved,
            authority_term: state.frontier.authority_term,
            global_fence_sequence: state.frontier.global_fence_sequence,
            created_at: now,
            updated_at: now,
            completed_at: None,
        };
        reservation
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        let current_gate = self.evaluate_read_gate().await?;
        if !current_gate.blocking_reservations.is_empty() {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::ReadsBlocked {
                    reservation_id: current_gate
                        .blocking_reservations
                        .first()
                        .map(|summary| summary.reservation_id.clone())
                        .unwrap_or_default(),
                },
            ));
        }
        let prepared_read_gate = astral_types::AuthorityReadGate::evaluate(vec![
            astral_types::AuthorityReservationSummary {
                reservation_id: reservation_id.clone(),
                operation_id: request.ticket.operation_id.clone(),
                mutation_kind: astral_types::AuthorityMutationKind::AuthorizationSource,
                state: astral_types::AuthorityReservationState::Reserved,
                coverage: astral_types::AuthorityReservationCoverage::Global,
                created_at: now,
            },
        ])
        .map_err(AuthorityServiceError::Protocol)?;
        let prepared_gate_epoch =
            state
                .gate_epoch
                .checked_add(1)
                .ok_or(AuthorityServiceError::Protocol(
                    AuthorityProtocolError::InvalidCounter {
                        field: "gate_epoch",
                    },
                ))?;
        let prepared_read_gate_digest = prepared_read_gate
            .digest()
            .map_err(AuthorityServiceError::Protocol)?;
        let mutation = mutation_digest("source-bootstrap-prepare", &ticket_digest);
        let next_frontier = state
            .frontier
            .advance(&request.ticket.operation_id, &mutation, now)
            .map_err(AuthorityServiceError::Protocol)?;
        reservation.authority_term = next_frontier.authority_term;
        reservation.global_fence_sequence = next_frontier.global_fence_sequence;
        reservation
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        let mut capability = AuthoritySourceBootstrapCapability {
            protocol_version: AUTHORITY_PROTOCOL_VERSION,
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: self.config.identity.authority_id.clone(),
            operation_id: request.ticket.operation_id.clone(),
            event_id: request.ticket.event_id.clone(),
            ticket_digest: ticket_digest.clone(),
            reservation_id: reservation_id.clone(),
            service_id: request.ticket.service_id.clone(),
            database_id: request.ticket.database_id.clone(),
            root_key_id: request.ticket.root_key_id.clone(),
            trust_root_digest: request.ticket.trust_root_digest.clone(),
            authority_term: next_frontier.authority_term,
            global_fence_sequence: next_frontier.global_fence_sequence,
            gate_epoch: prepared_gate_epoch,
            read_gate_digest: prepared_read_gate_digest,
            key_id: self.signer.key_id().to_owned(),
            key_epoch: self.signer.key_epoch(),
            issued_at: now,
            not_before: now,
            expires_at: request.ticket.expires_at,
            capability_nonce: fresh_id("srccap"),
            signature: String::new(),
        };
        let capability_bytes = capability
            .signing_bytes()
            .map_err(AuthorityServiceError::Protocol)?;
        capability.signature = self.signer.sign_checked(&capability_bytes, true)?;

        let stored = StoredSourceBootstrapOperation {
            ticket_digest: ticket_digest.clone(),
            payload_digest: request
                .ticket
                .payload_digest()
                .map_err(AuthorityServiceError::Protocol)?,
            service_id: request.ticket.service_id.clone(),
            database_id: request.ticket.database_id.clone(),
            capability: capability.clone(),
            reservation: reservation.clone(),
            prepared_frontier: next_frontier.clone(),
            prepared_gate_epoch,
            prepared_read_gate: prepared_read_gate.clone(),
        };
        let outcome = self
            .execute_leader_txn(
                StoreTxn::new()
                    .with_op(StoreOp::PutIfAbsent {
                        key: self
                            .keys
                            .source_bootstrap_operation(&request.ticket.operation_id),
                        value: encode(&stored)?,
                    })
                    .with_op(StoreOp::PutIfAbsent {
                        key: self.keys.source_bootstrap_reservation(&reservation_id),
                        value: encode(&reservation)?,
                    })
                    .with_op(StoreOp::PutIfAbsent {
                        key: self.keys.source_bootstrap_global_lock(),
                        value: Self::source_bootstrap_lock_value(
                            &request.ticket.operation_id,
                            &reservation_id,
                            &ticket_digest,
                        )?,
                    })
                    .with_op(StoreOp::ReplaceIfRevision {
                        key: self.keys.frontier(),
                        expected_revision: state.frontier_revision,
                        value: encode(&next_frontier)?,
                    })
                    .with_op(self.bump_gate_epoch_op(&state)?),
            )
            .await
            .map_err(|error| self.map_store_error(error, &request.ticket.operation_id))?;
        match outcome {
            StoreTxnOutcome::Applied { .. } => Ok(AuthoritySourceBootstrapPrepareResponse {
                capability,
                reservation,
                global_frontier: next_frontier,
                gate_epoch: prepared_gate_epoch,
                read_gate: prepared_read_gate,
            }),
            StoreTxnOutcome::PreconditionFailed { .. } => Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::StateConflict {
                    record: "source_bootstrap_operation",
                    state: "CONCURRENT".to_owned(),
                },
            )),
        }
    }

    async fn load_source_bootstrap_reservation(
        &self,
        stored: &StoredSourceBootstrapOperation,
    ) -> Result<
        (
            AuthoritySourceBootstrapReservation,
            crate::store::StoredRecord,
        ),
        AuthorityServiceError,
    > {
        let record = self
            .store
            .get(
                &self
                    .keys
                    .source_bootstrap_reservation(&stored.reservation.reservation_id),
            )
            .await?
            .ok_or_else(|| {
                AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                    "source bootstrap reservation is missing".to_owned(),
                ))
            })?;
        let reservation: AuthoritySourceBootstrapReservation =
            decode(&record.value, "source bootstrap reservation")?;
        reservation
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        let mut prepare_identity = reservation.clone();
        prepare_identity.state = stored.reservation.state;
        prepare_identity.updated_at = stored.reservation.updated_at;
        prepare_identity.completed_at = stored.reservation.completed_at;
        if prepare_identity != stored.reservation {
            return Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                "source bootstrap operation and reservation identity differ".to_owned(),
            )));
        }
        Ok((reservation, record))
    }

    pub async fn finalize_root_source_bootstrap(
        &self,
        request: &AuthoritySourceBootstrapFinalizeRequest,
    ) -> Result<AuthoritySourceBootstrapFinalizeResponse, AuthorityServiceError> {
        self.authorize(
            &request.caller,
            AUTHORITY_OPERATION_SOURCE_BOOTSTRAP_FINALIZE,
        )?;
        request
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        self.require_leader()?;
        let record = self
            .store
            .get(
                &self
                    .keys
                    .source_bootstrap_operation(&request.capability.operation_id),
            )
            .await?
            .ok_or(AuthorityServiceError::Protocol(
                AuthorityProtocolError::NotFound {
                    record: "source_bootstrap_operation",
                },
            ))?;
        let stored: StoredSourceBootstrapOperation =
            decode(&record.value, "source bootstrap operation")?;
        if stored.capability != request.capability || stored.service_id != request.caller.service_id
        {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::CallerIdentityMismatch,
            ));
        }
        if request.completion.source_payload_digest != stored.payload_digest {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::DigestMismatch {
                    field: "source_payload_digest",
                },
            ));
        }
        let (reservation, reservation_record) =
            self.load_source_bootstrap_reservation(&stored).await?;
        let lock_key = self.keys.source_bootstrap_global_lock();
        let lock_value = Self::source_bootstrap_lock_value(
            &stored.reservation.operation_id,
            &stored.reservation.reservation_id,
            &stored.reservation.ticket_digest,
        )?;
        let lock_record = self.store.get(&lock_key).await?;

        if reservation.state == AuthoritySourceBootstrapState::Completed {
            if lock_record
                .as_ref()
                .is_some_and(|record| record.value == lock_value)
            {
                return Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                    "completed source bootstrap still owns the global lock".to_owned(),
                )));
            }
            let receipt_record = self
                .store
                .get(
                    &self
                        .keys
                        .source_bootstrap_completion(&reservation.reservation_id),
                )
                .await?
                .ok_or(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                    "source bootstrap completion is missing".to_owned(),
                )))?;
            let receipt: AuthoritySourceBootstrapCompletionReceipt =
                decode(&receipt_record.value, "source bootstrap completion")?;
            receipt
                .validate()
                .map_err(AuthorityServiceError::Protocol)?;
            if receipt.completion != request.completion {
                return Err(AuthorityServiceError::Protocol(
                    AuthorityProtocolError::StateConflict {
                        record: "source_bootstrap_completion",
                        state: "COMPLETION_CONFLICT".to_owned(),
                    },
                ));
            }
            let state = self.load_verified_state().await?;
            state.verify_source_bootstrap_completion_receipt(&receipt)?;
            return Ok(AuthoritySourceBootstrapFinalizeResponse {
                reservation,
                global_frontier: receipt.frontier.clone(),
                receipt,
            });
        }
        if reservation.state != AuthoritySourceBootstrapState::Reserved {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::StateConflict {
                    record: "source_bootstrap_reservation",
                    state: format!("{:?}", reservation.state),
                },
            ));
        }
        match lock_record.as_ref() {
            Some(record) if record.value == lock_value => {}
            Some(_) => {
                return Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                    "source bootstrap global lock belongs to another operation".to_owned(),
                )))
            }
            None => {
                return Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                    "reserved source bootstrap global lock is missing".to_owned(),
                )))
            }
        }
        let state = self.load_verified_state().await?;
        self.require_active_signer(&state)?;
        let now = now_unix();
        let completion_digest = request
            .completion
            .digest()
            .map_err(AuthorityServiceError::Protocol)?;
        let next_frontier = state
            .frontier
            .advance(
                &request.completion.operation_id,
                &mutation_digest("source-bootstrap-finalize", &completion_digest),
                now,
            )
            .map_err(AuthorityServiceError::Protocol)?;
        let mut completed = reservation.clone();
        completed.state = AuthoritySourceBootstrapState::Completed;
        completed.updated_at = now;
        completed.completed_at = Some(now);
        let mut receipt = AuthoritySourceBootstrapCompletionReceipt {
            completion: request.completion.clone(),
            authority_id: self.config.identity.authority_id.clone(),
            authority_term: next_frontier.authority_term,
            global_fence_sequence: next_frontier.global_fence_sequence,
            key_id: self.signer.key_id().to_owned(),
            key_epoch: self.signer.key_epoch(),
            frontier: next_frontier.clone(),
            completed_at: now,
            signature: String::new(),
        };
        let receipt_bytes = receipt
            .signing_bytes()
            .map_err(AuthorityServiceError::Protocol)?;
        receipt.signature = self.signer.sign_checked(&receipt_bytes, true)?;
        let outcome = self
            .execute_leader_txn(
                StoreTxn::new()
                    .with_op(StoreOp::ReplaceIfRevision {
                        key: self
                            .keys
                            .source_bootstrap_reservation(&reservation.reservation_id),
                        expected_revision: reservation_record.revision,
                        value: encode(&completed)?,
                    })
                    .with_op(StoreOp::PutIfAbsent {
                        key: self
                            .keys
                            .source_bootstrap_completion(&reservation.reservation_id),
                        value: encode(&receipt)?,
                    })
                    .with_op(StoreOp::ReplaceIfRevision {
                        key: self.keys.frontier(),
                        expected_revision: state.frontier_revision,
                        value: encode(&next_frontier)?,
                    })
                    .with_op(self.bump_gate_epoch_op(&state)?)
                    .with_op(StoreOp::DeleteIfRevision {
                        key: lock_key.clone(),
                        expected_revision: lock_record
                            .as_ref()
                            .map(|record| record.revision)
                            .ok_or_else(|| {
                                AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                                    "reserved source bootstrap global lock is missing".to_owned(),
                                ))
                            })?,
                    }),
            )
            .await
            .map_err(|error| self.map_store_error(error, &reservation.reservation_id))?;
        match outcome {
            StoreTxnOutcome::Applied { .. } => Ok(AuthoritySourceBootstrapFinalizeResponse {
                reservation: completed,
                receipt,
                global_frontier: next_frontier,
            }),
            StoreTxnOutcome::PreconditionFailed { .. } => Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::StateConflict {
                    record: "source_bootstrap_reservation",
                    state: "CONCURRENT".to_owned(),
                },
            )),
        }
    }

    pub async fn reconcile_root_source_bootstrap(
        &self,
        request: &AuthoritySourceBootstrapReconcileRequest,
    ) -> Result<AuthoritySourceBootstrapReconcileResponse, AuthorityServiceError> {
        self.authorize(
            &request.caller,
            AUTHORITY_OPERATION_SOURCE_BOOTSTRAP_RECONCILE,
        )?;
        request
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        let operation_record = self
            .store
            .get(&self.keys.source_bootstrap_operation(&request.operation_id))
            .await?;
        let Some(operation_record) = operation_record else {
            let frontier = self.load_verified_state().await?.frontier;
            return Ok(AuthoritySourceBootstrapReconcileResponse {
                operation_id: request.operation_id.clone(),
                ticket_digest: request.ticket_digest.clone(),
                reservation: None,
                capability: None,
                receipt: None,
                global_frontier: frontier,
                gate_epoch: self.load_verified_state().await?.gate_epoch,
                read_gate: self.evaluate_read_gate().await?,
            });
        };
        let stored: StoredSourceBootstrapOperation =
            decode(&operation_record.value, "source bootstrap operation")?;
        if stored.ticket_digest != request.ticket_digest
            || stored.service_id != request.caller.service_id
        {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::CallerIdentityMismatch,
            ));
        }
        let (reservation, _) = self.load_source_bootstrap_reservation(&stored).await?;
        let completion = self
            .store
            .get(
                &self
                    .keys
                    .source_bootstrap_completion(&stored.reservation.reservation_id),
            )
            .await?
            .map(|record| decode(&record.value, "source bootstrap completion"))
            .transpose()?;
        if let Some(receipt) = completion.as_ref() {
            let state = self.load_verified_state().await?;
            state.verify_source_bootstrap_completion_receipt(receipt)?;
        }
        let frontier = self.load_verified_state().await?.frontier;
        let state = self.load_verified_state().await?;
        let response = AuthoritySourceBootstrapReconcileResponse {
            operation_id: request.operation_id.clone(),
            ticket_digest: request.ticket_digest.clone(),
            reservation: Some(reservation),
            capability: Some(stored.capability),
            receipt: completion,
            global_frontier: frontier,
            gate_epoch: state.gate_epoch,
            read_gate: self.evaluate_read_gate().await?,
        };
        response
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        Ok(response)
    }
}
