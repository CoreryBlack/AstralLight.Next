//! Durable source-commit acknowledgement and exact unknown-outcome reconciliation.

use super::*;
use astral_types::{
    AuthorityCommitBinding, AuthorityCommitResponse, AuthorityReconcileResponse,
    AuthorityReservationDisposition, AuthorityScopeReservation, AuthorityStagedSourceEvidence,
};

fn reservation_matches(
    record: &AuthoritySourceOutcomeRecord,
    reservation: &AuthorityScopeReservation,
) -> bool {
    let intent = &reservation.intent;
    reservation.validate().is_ok()
        && reservation.reservation_id == record.reservation_id
        && intent.operation_id == record.operation_id
        && intent.event_id == record.event_id
        && intent.admission_proof_id == record.admission_proof_id
        && intent.request_digest == record.request_binding_digest
        && intent.mutation_kind == record.mutation_kind
        && intent.service_id == record.service_id
        && intent.database_id == record.database_id
        && intent
            .before_image_digest
            .as_ref()
            .is_none_or(|before| record.before_image_digest.as_ref() == Some(before))
}

fn expected_binding(
    record: &AuthoritySourceOutcomeRecord,
    commit: &AuthoritySourceCommitRecord,
) -> AuthorityCommitBinding {
    AuthorityCommitBinding {
        reservation_id: record.reservation_id.clone(),
        operation_id: record.operation_id.clone(),
        event_id: record.event_id.clone(),
        admission_proof_id: record.admission_proof_id.clone(),
        mutation_kind: record.mutation_kind,
        service_id: record.service_id.clone(),
        database_id: record.database_id.clone(),
        request_digest: record.request_binding_digest.clone(),
        source_commit_digest: record.source_commit_digest.clone(),
        before_image_digest: record.before_image_digest.clone(),
        after_image_digest: commit.after_image_digest.clone(),
        source_outcome_digest: commit.source_outcome_digest.clone(),
        staged_evidence_digest: commit.staged_evidence_digest.clone(),
    }
}

fn commit_matches(
    record: &AuthoritySourceOutcomeRecord,
    expected: &AuthorityCommitBinding,
    response: &AuthorityCommitResponse,
) -> bool {
    response.validate().is_ok()
        && response.disposition == AuthorityReservationDisposition::Committed
        && response.binding == *expected
        && response.reservation.as_ref().is_some_and(|reservation| {
            reservation_matches(record, reservation)
                && reservation.state == astral_types::AuthorityReservationState::Committed
        })
}

fn reconciliation_matches(
    record: &AuthoritySourceOutcomeRecord,
    expected: &AuthorityCommitBinding,
    response: &AuthorityReconcileResponse,
) -> bool {
    response.validate().is_ok()
        && response.reconciliation.reservation_id == record.reservation_id
        && response.reconciliation.operation_id == record.operation_id
        && response
            .reconciliation
            .reservation
            .as_ref()
            .is_some_and(|reservation| reservation_matches(record, reservation))
        && match response.reconciliation.disposition {
            AuthorityReservationDisposition::Committed
            | AuthorityReservationDisposition::Published
            | AuthorityReservationDisposition::Certified
            | AuthorityReservationDisposition::Completed => {
                response.commit_binding.as_ref() == Some(expected)
            }
            AuthorityReservationDisposition::Reserved => response.commit_binding.is_none(),
            _ => false,
        }
}

#[derive(Debug, PartialEq, Eq)]
enum CommitResolution {
    Confirm {
        disposition: AuthorityReservationDisposition,
        reconciled: bool,
    },
    Pending,
    Quarantine(&'static str),
}

async fn resolve_commit<G: AuthorityOutcomeGateway>(
    gateway: &G,
    attempts: u32,
    record: &AuthoritySourceOutcomeRecord,
    commit: &AuthoritySourceCommitRecord,
    envelope: &AuthorityStagedSourceEvidence,
) -> (CommitResolution, bool) {
    let expected = expected_binding(record, commit);
    if attempts <= 1 {
        let outcome = gateway
            .commit(
                commit.clone(),
                record.database_id.clone(),
                envelope.coverage.clone(),
            )
            .await;
        match commit_outcome_decision(&outcome) {
            AuthoritySourceOutcomeDecision::MarkCommitted => {
                let response = outcome.expect("a commit response was observed");
                return (
                    if commit_matches(record, &expected, &response) {
                        CommitResolution::Confirm {
                            disposition: response.disposition,
                            reconciled: false,
                        }
                    } else {
                        CommitResolution::Quarantine(
                            "authority response differs from the exact source commit binding",
                        )
                    },
                    false,
                );
            }
            AuthoritySourceOutcomeDecision::Quarantine(reason) => {
                return (CommitResolution::Quarantine(reason), false)
            }
            _ => {}
        }
    }
    // A reclaimed lease starts here, before any authority write. UNKNOWN is
    // resolved only from stable identity and the complete exact binding.
    let response = match gateway
        .reconcile(record.reservation_id.clone(), record.operation_id.clone())
        .await
    {
        Ok(response) => response,
        Err(_) => return (CommitResolution::Pending, false),
    };
    if !reconciliation_matches(record, &expected, &response) {
        return (
            CommitResolution::Quarantine(
                "authority reconciliation lacks the exact source commit binding",
            ),
            false,
        );
    }
    match unknown_outcome_action(Some(&response.reconciliation.disposition)) {
        UnknownOutcomeReconcileAction::ConfirmCommitted => (
            CommitResolution::Confirm {
                disposition: response.reconciliation.disposition,
                reconciled: true,
            },
            false,
        ),
        UnknownOutcomeReconcileAction::RetryCommitOnce => {
            let outcome = gateway
                .commit(
                    commit.clone(),
                    record.database_id.clone(),
                    envelope.coverage.clone(),
                )
                .await;
            (
                match outcome {
                    Ok(response) if commit_matches(record, &expected, &response) => {
                        CommitResolution::Confirm {
                            disposition: response.disposition,
                            reconciled: false,
                        }
                    }
                    Ok(_) => CommitResolution::Quarantine(
                        "authority retry response differs from the exact source commit binding",
                    ),
                    Err(_) => CommitResolution::Pending,
                },
                true,
            )
        }
        UnknownOutcomeReconcileAction::Quarantine(reason) => {
            (CommitResolution::Quarantine(reason), false)
        }
        UnknownOutcomeReconcileAction::StayPending => (CommitResolution::Pending, false),
    }
}

impl<G: AuthorityOutcomeGateway> AuthoritySourceOutcomeReconciler<G> {
    async fn quarantine_row(
        &self,
        row: &AuthoritySourceOutcomeRow,
        report: &mut AuthoritySourceOutcomeReconcileReport,
        reason: &str,
    ) -> Result<(), PolicyError> {
        if self
            .finalize(&row.reservation_id, row, false, None, Some(reason))
            .await?
        {
            report.quarantined += 1;
        } else {
            report.skipped += 1;
        }
        Ok(())
    }

    async fn confirm_row(
        &self,
        row: &AuthoritySourceOutcomeRow,
        report: &mut AuthoritySourceOutcomeReconcileReport,
        disposition: AuthorityReservationDisposition,
        reconciled: bool,
    ) -> Result<(), PolicyError> {
        if self
            .finalize(
                &row.reservation_id,
                row,
                true,
                Some(disposition.as_text()),
                None,
            )
            .await?
        {
            if reconciled {
                report.confirmed_committed += 1;
            } else {
                report.marked_committed += 1;
            }
        } else {
            report.skipped += 1;
        }
        Ok(())
    }

    /// Reconcile before any internal re-issue. Only an exact RESERVED response
    /// permits one further authority commit; no branch replays a source writer.
    async fn reconcile_commit(
        &self,
        row: &AuthoritySourceOutcomeRow,
        record: &AuthoritySourceOutcomeRecord,
        commit: &AuthoritySourceCommitRecord,
        envelope: &AuthorityStagedSourceEvidence,
        report: &mut AuthoritySourceOutcomeReconcileReport,
    ) -> Result<(), PolicyError> {
        let (resolution, retried) =
            resolve_commit(&*self.gateway, row.attempts, record, commit, envelope).await;
        if retried {
            report.retried_after_unknown += 1;
        }
        match resolution {
            CommitResolution::Confirm {
                disposition,
                reconciled,
            } => self.confirm_row(row, report, disposition, reconciled).await,
            CommitResolution::Pending => {
                report.stayed_pending += 1;
                Ok(())
            }
            CommitResolution::Quarantine(reason) => self.quarantine_row(row, report, reason).await,
        }
    }

    /// One bounded pass, using only independently read durable outcomes. A lease
    /// timeout leaves the source unresolved; it never authorizes source replay.
    pub async fn run_once(&self) -> Result<AuthoritySourceOutcomeReconcileReport, PolicyError> {
        let (rows, skipped, exhausted) = self.lease_batch().await?;
        let mut report = AuthoritySourceOutcomeReconcileReport {
            leased: rows.len() as u64,
            skipped,
            quarantined: exhausted,
            ..Default::default()
        };
        for row in &rows {
            let record = match row.to_verified_record() {
                Ok(record) => record,
                Err(_) => {
                    self.quarantine_row(
                        row,
                        &mut report,
                        "source outcome failed its durable self-digest",
                    )
                    .await?;
                    continue;
                }
            };
            let envelope = row
                .staged_evidence
                .as_deref()
                .and_then(|value| serde_json::from_str::<AuthorityStagedSourceEvidence>(value).ok())
                .filter(|value| value.validate().is_ok());
            let Some(envelope) = envelope else {
                self.quarantine_row(
                    row,
                    &mut report,
                    "source outcome has an invalid typed evidence envelope",
                )
                .await?;
                continue;
            };
            let Some(after_image_digest) = record.after_image_digest.clone() else {
                self.quarantine_row(
                    row,
                    &mut report,
                    "source outcome lacks its actual after-image",
                )
                .await?;
                continue;
            };
            let commit = AuthoritySourceCommitRecord {
                reservation_id: record.reservation_id.clone(),
                operation_id: record.operation_id.clone(),
                source_commit_digest: record.source_commit_digest.clone(),
                before_image_digest: record.before_image_digest.clone(),
                after_image_digest,
                source_outcome_digest: hex32(&row.outcome_digest, "outcome_digest")?,
                staged_evidence_digest: staged_evidence_digest(
                    row.staged_evidence.as_deref().unwrap_or_default(),
                )?,
                committed_at: record.committed_at,
            };
            self.reconcile_commit(row, &record, &commit, &envelope, &mut report)
                .await?;
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::tests::record;

    /// Queued transport stub: every call is recorded with its exact arguments
    /// and answered from the next queued result; an empty queue answers the
    /// unknown-transport error, like a real client that observed nothing.
    #[derive(Default)]
    struct OrderedGateway {
        calls: std::sync::Mutex<Vec<&'static str>>,
        reconciliations: std::sync::Mutex<
            std::collections::VecDeque<
                Result<AuthorityReconcileResponse, astral_authority::AuthorityClientError>,
            >,
        >,
        commit_results: std::sync::Mutex<
            std::collections::VecDeque<
                Result<AuthorityCommitResponse, astral_authority::AuthorityClientError>,
            >,
        >,
        commits: std::sync::Mutex<
            Vec<(
                AuthoritySourceCommitRecord,
                String,
                Option<astral_types::AuthorityStagedScopeCoverage>,
            )>,
        >,
    }

    #[async_trait::async_trait]
    impl AuthorityOutcomeGateway for OrderedGateway {
        async fn commit(
            &self,
            commit: AuthoritySourceCommitRecord,
            database_id: String,
            declared_coverage: Option<astral_types::AuthorityStagedScopeCoverage>,
        ) -> Result<AuthorityCommitResponse, astral_authority::AuthorityClientError> {
            self.calls.lock().unwrap().push("commit");
            self.commits
                .lock()
                .unwrap()
                .push((commit, database_id, declared_coverage));
            self.commit_results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| {
                    Err(astral_authority::AuthorityClientError::Protocol(
                        "unknown test transport result".into(),
                    ))
                })
        }
        async fn reconcile(
            &self,
            _: String,
            _: String,
        ) -> Result<AuthorityReconcileResponse, astral_authority::AuthorityClientError> {
            self.calls.lock().unwrap().push("reconcile");
            self.reconciliations
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| {
                    Err(astral_authority::AuthorityClientError::Protocol(
                        "unknown test transport result".into(),
                    ))
                })
        }
    }

    #[tokio::test]
    async fn reclaimed_attempt_reconciles_before_any_write_and_never_replays_unknown() {
        let record = record();
        let commit = AuthoritySourceCommitRecord {
            reservation_id: record.reservation_id.clone(),
            operation_id: record.operation_id.clone(),
            source_commit_digest: record.source_commit_digest.clone(),
            before_image_digest: record.before_image_digest.clone(),
            after_image_digest: record.after_image_digest.clone().unwrap(),
            source_outcome_digest: "ef".repeat(32),
            staged_evidence_digest: "ab".repeat(32),
            committed_at: record.committed_at,
        };
        let envelope = AuthorityStagedSourceEvidence {
            coverage: None,
            evidence: serde_json::json!({"delta":"actual"}),
        };
        let gateway = OrderedGateway::default();
        let (resolution, retried) = resolve_commit(&gateway, 2, &record, &commit, &envelope).await;
        assert_eq!(resolution, CommitResolution::Pending);
        assert!(!retried);
        assert_eq!(*gateway.calls.lock().unwrap(), ["reconcile"]);
        let first = OrderedGateway::default();
        let (resolution, _) = resolve_commit(&first, 1, &record, &commit, &envelope).await;
        assert_eq!(resolution, CommitResolution::Pending);
        assert_eq!(*first.calls.lock().unwrap(), ["commit", "reconcile"]);
    }

    #[test]
    fn binding_rejects_each_changed_identity_and_image() {
        let record = record();
        let commit = AuthoritySourceCommitRecord {
            reservation_id: record.reservation_id.clone(),
            operation_id: record.operation_id.clone(),
            source_commit_digest: record.source_commit_digest.clone(),
            before_image_digest: record.before_image_digest.clone(),
            after_image_digest: record.after_image_digest.clone().unwrap(),
            source_outcome_digest: "ef".repeat(32),
            staged_evidence_digest: "ab".repeat(32),
            committed_at: record.committed_at,
        };
        let binding = expected_binding(&record, &commit);
        let mut variants = vec![binding.clone(); 8];
        variants[0].event_id.push_str("-other");
        variants[1].admission_proof_id.push_str("-other");
        variants[2].service_id.push_str("-other");
        variants[3].database_id.push_str("-other");
        variants[4].request_digest = "01".repeat(32);
        variants[5].before_image_digest = Some("02".repeat(32));
        variants[6].source_outcome_digest = "03".repeat(32);
        variants[7].staged_evidence_digest = "04".repeat(32);
        let response = AuthorityCommitResponse {
            disposition: AuthorityReservationDisposition::Committed,
            reservation: Some(AuthorityScopeReservation {
                reservation_id: record.reservation_id.clone(),
                intent_digest: "11".repeat(32),
                intent: astral_types::AuthoritySourceIntent {
                    authorization_edition: AUTHORIZATION_EDITION,
                    mutation_kind: record.mutation_kind,
                    operation_id: record.operation_id.clone(),
                    event_id: record.event_id.clone(),
                    admission_proof_id: record.admission_proof_id.clone(),
                    request_digest: record.request_binding_digest.clone(),
                    service_id: record.service_id.clone(),
                    database_id: record.database_id.clone(),
                    coverage: astral_types::AuthorityReservationCoverage::Global,
                    before_image_digest: record.before_image_digest.clone(),
                    lease_not_before: record.committed_at - 10,
                    lease_expires_at: record.committed_at + 10,
                    intent_nonce: "intent-nonce".into(),
                },
                state: astral_types::AuthorityReservationState::Committed,
                authority_term: 1,
                fence_sequence_at_prepare: 1,
                created_at: record.committed_at,
                updated_at: record.committed_at,
                committed_at: Some(record.committed_at),
                source_commit_digest: Some(binding.source_commit_digest.clone()),
                after_image_digest: Some(binding.after_image_digest.clone()),
                source_outcome_digest: Some(binding.source_outcome_digest.clone()),
                certificate_id: None,
                certified_scopes: vec![],
            }),
            binding: binding.clone(),
            global_frontier: astral_types::GlobalAuthorityFrontier::genesis(
                "authority",
                "root",
                &"12".repeat(32),
                "signer",
                1,
                record.committed_at,
            )
            .unwrap(),
            read_gate: astral_types::AuthorityReadGate::blocked(),
        };
        assert!(commit_matches(&record, &binding, &response));
        let reconciled = AuthorityReconcileResponse {
            reconciliation: astral_types::AuthorityReconciliation {
                reservation_id: record.reservation_id.clone(),
                operation_id: record.operation_id.clone(),
                disposition: AuthorityReservationDisposition::Committed,
                reservation: response.reservation.clone(),
            },
            commit_binding: Some(binding.clone()),
            certified_publications: vec![],
            global_frontier: response.global_frontier.clone(),
            read_gate: response.read_gate.clone(),
        };
        assert!(reconciliation_matches(&record, &binding, &reconciled));
        for changed in variants {
            let mut direct = response.clone();
            direct.binding = changed.clone();
            assert!(!commit_matches(&record, &binding, &direct));
            let mut reconciled = reconciled.clone();
            reconciled.commit_binding = Some(changed);
            assert!(!reconciliation_matches(&record, &binding, &reconciled));
        }
        let mut missing = reconciled;
        missing.commit_binding = None;
        assert!(!reconciliation_matches(&record, &binding, &missing));
        let mut wrong_operation = response;
        wrong_operation
            .reservation
            .as_mut()
            .unwrap()
            .intent
            .operation_id = "other-operation".into();
        assert!(!commit_matches(&record, &binding, &wrong_operation));
    }

    // ---- resolve_commit call-order fixtures -------------------------------
    // The record/commit/envelope mirror what `run_once` derives from one
    // promoted durable row; the responses are protocol-valid shapes the
    // authority can return. No publication certificates are fabricated: the
    // reconcile fixtures carry an empty `certified_publications` set, so the
    // per-certificate signing rules stay out of scope for these tests.

    fn commit_record(record: &AuthoritySourceOutcomeRecord) -> AuthoritySourceCommitRecord {
        AuthoritySourceCommitRecord {
            reservation_id: record.reservation_id.clone(),
            operation_id: record.operation_id.clone(),
            source_commit_digest: record.source_commit_digest.clone(),
            before_image_digest: record.before_image_digest.clone(),
            after_image_digest: record.after_image_digest.clone().unwrap(),
            source_outcome_digest: "ef".repeat(32),
            staged_evidence_digest: "ab".repeat(32),
            committed_at: record.committed_at,
        }
    }

    fn envelope() -> AuthorityStagedSourceEvidence {
        AuthorityStagedSourceEvidence {
            coverage: None,
            evidence: serde_json::json!({"delta": "actual"}),
        }
    }

    fn frontier(record: &AuthoritySourceOutcomeRecord) -> astral_types::GlobalAuthorityFrontier {
        astral_types::GlobalAuthorityFrontier::genesis(
            "authority",
            "root",
            &"12".repeat(32),
            "signer",
            1,
            record.committed_at,
        )
        .unwrap()
    }

    /// An authority reservation whose intent matches the record field for
    /// field, in the given durable state (the exact-identity response shape).
    /// Post-commit states (including a reservation quarantined after commit)
    /// carry the actual commit digests, so an echoed exact binding stays
    /// consistent with the reservation under the response validation rules.
    fn reservation_in(
        record: &AuthoritySourceOutcomeRecord,
        state: astral_types::AuthorityReservationState,
    ) -> AuthorityScopeReservation {
        let carries_commit_evidence = matches!(
            state,
            astral_types::AuthorityReservationState::Committed
                | astral_types::AuthorityReservationState::Published
                | astral_types::AuthorityReservationState::Certified
                | astral_types::AuthorityReservationState::Quarantined
        );
        AuthorityScopeReservation {
            reservation_id: record.reservation_id.clone(),
            intent_digest: "11".repeat(32),
            intent: astral_types::AuthoritySourceIntent {
                authorization_edition: AUTHORIZATION_EDITION,
                mutation_kind: record.mutation_kind,
                operation_id: record.operation_id.clone(),
                event_id: record.event_id.clone(),
                admission_proof_id: record.admission_proof_id.clone(),
                request_digest: record.request_binding_digest.clone(),
                service_id: record.service_id.clone(),
                database_id: record.database_id.clone(),
                coverage: astral_types::AuthorityReservationCoverage::Global,
                before_image_digest: record.before_image_digest.clone(),
                lease_not_before: record.committed_at - 10,
                lease_expires_at: record.committed_at + 10,
                intent_nonce: "intent-nonce".into(),
            },
            state,
            authority_term: 1,
            fence_sequence_at_prepare: 1,
            created_at: record.committed_at,
            updated_at: record.committed_at,
            committed_at: carries_commit_evidence.then_some(record.committed_at),
            source_commit_digest: carries_commit_evidence
                .then(|| record.source_commit_digest.clone()),
            after_image_digest: carries_commit_evidence
                .then(|| record.after_image_digest.clone().unwrap()),
            source_outcome_digest: carries_commit_evidence.then(|| "ef".repeat(32)),
            certificate_id: None,
            certified_scopes: vec![],
        }
    }

    /// A reconcile response for the given reservation: the exact binding is
    /// attached exactly when the disposition is a committed family member
    /// (the only protocol-valid attachment point).
    fn reconcile_response(
        record: &AuthoritySourceOutcomeRecord,
        commit: &AuthoritySourceCommitRecord,
        reservation: AuthorityScopeReservation,
    ) -> AuthorityReconcileResponse {
        let disposition = AuthorityReservationDisposition::from_reservation(&reservation);
        let committed = matches!(
            disposition,
            AuthorityReservationDisposition::Committed
                | AuthorityReservationDisposition::Published
                | AuthorityReservationDisposition::Certified
        );
        AuthorityReconcileResponse {
            reconciliation: astral_types::AuthorityReconciliation {
                reservation_id: record.reservation_id.clone(),
                operation_id: record.operation_id.clone(),
                disposition,
                reservation: Some(reservation),
            },
            commit_binding: committed.then(|| expected_binding(record, commit)),
            certified_publications: vec![],
            global_frontier: frontier(record),
            read_gate: astral_types::AuthorityReadGate::blocked(),
        }
    }

    /// A protocol-valid commit acknowledgement for the exact binding.
    fn committed_commit_response(
        record: &AuthoritySourceOutcomeRecord,
        commit: &AuthoritySourceCommitRecord,
    ) -> AuthorityCommitResponse {
        AuthorityCommitResponse {
            disposition: AuthorityReservationDisposition::Committed,
            reservation: Some(reservation_in(
                record,
                astral_types::AuthorityReservationState::Committed,
            )),
            binding: expected_binding(record, commit),
            global_frontier: frontier(record),
            read_gate: astral_types::AuthorityReadGate::blocked(),
        }
    }

    fn queued<T>(
        values: impl IntoIterator<Item = T>,
    ) -> std::sync::Mutex<std::collections::VecDeque<T>> {
        std::sync::Mutex::new(values.into_iter().collect())
    }

    fn gateway_with(
        reconciliations: Vec<
            Result<AuthorityReconcileResponse, astral_authority::AuthorityClientError>,
        >,
        commits: Vec<Result<AuthorityCommitResponse, astral_authority::AuthorityClientError>>,
    ) -> OrderedGateway {
        OrderedGateway {
            reconciliations: queued(reconciliations),
            commit_results: queued(commits),
            ..Default::default()
        }
    }

    fn transport_error() -> astral_authority::AuthorityClientError {
        astral_authority::AuthorityClientError::Transport("connection reset".into())
    }

    #[tokio::test]
    async fn exact_reserved_reconcile_issues_exactly_one_internal_commit() {
        let record = record();
        let commit = commit_record(&record);
        let envelope = envelope();
        let gateway = gateway_with(
            vec![Ok(reconcile_response(
                &record,
                &commit,
                reservation_in(&record, astral_types::AuthorityReservationState::Reserved),
            ))],
            vec![Ok(committed_commit_response(&record, &commit))],
        );
        let (resolution, retried) = resolve_commit(&gateway, 2, &record, &commit, &envelope).await;
        assert_eq!(
            resolution,
            CommitResolution::Confirm {
                disposition: AuthorityReservationDisposition::Committed,
                reconciled: false,
            }
        );
        assert!(retried);
        // Reconcile first, exactly one bounded internal re-issue, nothing else.
        assert_eq!(*gateway.calls.lock().unwrap(), ["reconcile", "commit"]);
        // The re-issue carries the exact read-back commit, owner and coverage.
        let issued = gateway.commits.lock().unwrap();
        let (issued_commit, database_id, declared_coverage) = &issued[0];
        assert_eq!(*issued_commit, commit);
        assert_eq!(database_id, &record.database_id);
        assert_eq!(declared_coverage, &envelope.coverage);
    }

    #[tokio::test]
    async fn state_conflict_then_reserved_reissues_exactly_once() {
        let record = record();
        let commit = commit_record(&record);
        let envelope = envelope();
        let gateway = gateway_with(
            vec![Ok(reconcile_response(
                &record,
                &commit,
                reservation_in(&record, astral_types::AuthorityReservationState::Reserved),
            ))],
            vec![
                Err(astral_authority::AuthorityClientError::Rejected {
                    code: "StateConflict".into(),
                    message: "already committed".into(),
                }),
                Ok(committed_commit_response(&record, &commit)),
            ],
        );
        // The first commit already left this attempt (attempts == 1): the
        // conflict reconciles by stable identity, then RESERVED allows one
        // idempotent re-issue.
        let (resolution, retried) = resolve_commit(&gateway, 1, &record, &commit, &envelope).await;
        assert_eq!(
            resolution,
            CommitResolution::Confirm {
                disposition: AuthorityReservationDisposition::Committed,
                reconciled: false,
            }
        );
        assert!(retried);
        assert_eq!(
            *gateway.calls.lock().unwrap(),
            ["commit", "reconcile", "commit"]
        );
        assert_eq!(gateway.commits.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn committed_published_certified_confirm_without_any_write() {
        let record = record();
        let commit = commit_record(&record);
        let envelope = envelope();
        for state in [
            astral_types::AuthorityReservationState::Committed,
            astral_types::AuthorityReservationState::Published,
            astral_types::AuthorityReservationState::Certified,
        ] {
            let reservation = reservation_in(&record, state);
            let gateway = gateway_with(
                vec![Ok(reconcile_response(
                    &record,
                    &commit,
                    reservation.clone(),
                ))],
                vec![],
            );
            let (resolution, retried) =
                resolve_commit(&gateway, 2, &record, &commit, &envelope).await;
            assert_eq!(
                resolution,
                CommitResolution::Confirm {
                    disposition: AuthorityReservationDisposition::from_reservation(&reservation),
                    reconciled: true,
                }
            );
            assert!(!retried);
            // The authority already holds the outcome: no further authority
            // write of any kind is issued.
            assert_eq!(*gateway.calls.lock().unwrap(), ["reconcile"]);
            assert!(gateway.commits.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn mismatched_or_missing_bindings_quarantine_without_retry_or_write() {
        let record = record();
        let commit = commit_record(&record);
        let envelope = envelope();

        // A protocol-valid response whose echoed binding drifted from the
        // exact durable binding (binding and reservation agree with each
        // other, but not with the durable record): quarantined, never
        // confirmed.
        let mut drifted = reconcile_response(
            &record,
            &commit,
            reservation_in(&record, astral_types::AuthorityReservationState::Committed),
        );
        let other = "99".repeat(32);
        drifted.commit_binding.as_mut().unwrap().request_digest = other.clone();
        drifted
            .reconciliation
            .reservation
            .as_mut()
            .unwrap()
            .intent
            .request_digest = other;

        // A response that fails its own protocol validation (reservation and
        // binding disagree on the after-image): still fail-closed quarantine.
        let mut inconsistent = reconcile_response(
            &record,
            &commit,
            reservation_in(&record, astral_types::AuthorityReservationState::Committed),
        );
        inconsistent
            .commit_binding
            .as_mut()
            .unwrap()
            .after_image_digest = "04".repeat(32);

        // A committed reconciliation without any binding is protocol-invalid
        // and quarantined, never treated as success.
        let mut missing = reconcile_response(
            &record,
            &commit,
            reservation_in(&record, astral_types::AuthorityReservationState::Committed),
        );
        missing.commit_binding = None;

        // A RESERVED disposition that does not match the record exactly must
        // never trigger the one bounded re-issue either.
        let mut foreign_reserved = reconcile_response(
            &record,
            &commit,
            reservation_in(&record, astral_types::AuthorityReservationState::Reserved),
        );
        foreign_reserved.reconciliation.operation_id = "other-operation".into();
        foreign_reserved
            .reconciliation
            .reservation
            .as_mut()
            .unwrap()
            .intent
            .operation_id = "other-operation".into();

        // A quarantined reservation may retain its exact binding under the
        // updated protocol, but a terminal non-committed state is never
        // confirmed from it.
        let mut quarantined = reconcile_response(
            &record,
            &commit,
            reservation_in(
                &record,
                astral_types::AuthorityReservationState::Quarantined,
            ),
        );
        quarantined.commit_binding = Some(expected_binding(&record, &commit));
        assert!(quarantined.validate().is_ok());

        // NotFound is terminal for the attempt: quarantine, never a re-issue.
        let not_found = AuthorityReconcileResponse {
            reconciliation: astral_types::AuthorityReconciliation {
                reservation_id: record.reservation_id.clone(),
                operation_id: record.operation_id.clone(),
                disposition: AuthorityReservationDisposition::NotFound,
                reservation: None,
            },
            commit_binding: None,
            certified_publications: vec![],
            global_frontier: frontier(&record),
            read_gate: astral_types::AuthorityReadGate::blocked(),
        };

        for response in [
            drifted,
            inconsistent,
            missing,
            foreign_reserved,
            quarantined,
            not_found,
        ] {
            let gateway = gateway_with(vec![Ok(response)], vec![]);
            let (resolution, retried) =
                resolve_commit(&gateway, 2, &record, &commit, &envelope).await;
            assert!(matches!(resolution, CommitResolution::Quarantine(_)));
            assert!(!retried);
            assert_eq!(*gateway.calls.lock().unwrap(), ["reconcile"]);
            assert!(gateway.commits.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn transport_unknown_stays_pending_and_never_writes() {
        let record = record();
        let commit = commit_record(&record);
        let envelope = envelope();
        for error in [
            transport_error(),
            astral_authority::AuthorityClientError::UnknownOutcome {
                operation_hint: "res-abc".into(),
            },
        ] {
            let gateway = gateway_with(vec![Err(error)], vec![]);
            let (resolution, retried) =
                resolve_commit(&gateway, 2, &record, &commit, &envelope).await;
            assert_eq!(resolution, CommitResolution::Pending);
            assert!(!retried);
            assert_eq!(*gateway.calls.lock().unwrap(), ["reconcile"]);
            assert!(gateway.commits.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn reserved_reconcile_with_unknown_retry_stays_pending_after_one_attempt() {
        let record = record();
        let commit = commit_record(&record);
        let envelope = envelope();
        let gateway = gateway_with(
            vec![Ok(reconcile_response(
                &record,
                &commit,
                reservation_in(&record, astral_types::AuthorityReservationState::Reserved),
            ))],
            vec![Err(
                astral_authority::AuthorityClientError::UnknownOutcome {
                    operation_hint: "res-abc".into(),
                },
            )],
        );
        let (resolution, retried) = resolve_commit(&gateway, 2, &record, &commit, &envelope).await;
        assert_eq!(resolution, CommitResolution::Pending);
        assert!(retried);
        // Exactly one re-issue was attempted; the second unknown outcome stays
        // pending under the lease instead of a blind second retry.
        assert_eq!(*gateway.calls.lock().unwrap(), ["reconcile", "commit"]);
        assert_eq!(gateway.commits.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn reserved_reconcile_with_mismatched_retry_response_quarantines() {
        let record = record();
        let commit = commit_record(&record);
        let envelope = envelope();
        let mut drifted = committed_commit_response(&record, &commit);
        let other = "08".repeat(32);
        drifted.binding.source_commit_digest = other.clone();
        drifted.reservation.as_mut().unwrap().source_commit_digest = Some(other);
        let gateway = gateway_with(
            vec![Ok(reconcile_response(
                &record,
                &commit,
                reservation_in(&record, astral_types::AuthorityReservationState::Reserved),
            ))],
            vec![Ok(drifted)],
        );
        let (resolution, retried) = resolve_commit(&gateway, 2, &record, &commit, &envelope).await;
        assert!(matches!(resolution, CommitResolution::Quarantine(_)));
        // The re-issue WAS attempted after the unknown, so the report counts
        // it, but a drifted retry answer can never finalize as committed.
        assert!(retried);
        assert_eq!(*gateway.calls.lock().unwrap(), ["reconcile", "commit"]);
    }

    #[tokio::test]
    async fn first_commit_binding_mismatch_or_terminal_rejection_quarantines_locally() {
        let record = record();
        let commit = commit_record(&record);
        let envelope = envelope();

        // The direct commit answered with a protocol-valid response whose
        // binding differs from the exact durable binding: quarantine with no
        // reconciliation round-trip at all.
        let mut drifted = committed_commit_response(&record, &commit);
        let other = "07".repeat(32);
        drifted.binding.request_digest = other.clone();
        drifted.reservation.as_mut().unwrap().intent.request_digest = other;
        let gateway = gateway_with(vec![], vec![Ok(drifted)]);
        let (resolution, retried) = resolve_commit(&gateway, 1, &record, &commit, &envelope).await;
        assert!(matches!(resolution, CommitResolution::Quarantine(_)));
        assert!(!retried);
        assert_eq!(*gateway.calls.lock().unwrap(), ["commit"]);
        assert_eq!(gateway.commits.lock().unwrap().len(), 1);

        // A terminal authority rejection (unknown reservation) quarantines
        // without any reconciliation write attempt.
        let gateway = gateway_with(
            vec![],
            vec![Err(astral_authority::AuthorityClientError::Rejected {
                code: "NotFound".into(),
                message: "reservation missing".into(),
            })],
        );
        let (resolution, retried) = resolve_commit(&gateway, 1, &record, &commit, &envelope).await;
        assert!(matches!(resolution, CommitResolution::Quarantine(_)));
        assert!(!retried);
        assert_eq!(*gateway.calls.lock().unwrap(), ["commit"]);
    }

    #[tokio::test]
    async fn first_commit_transport_unknown_reconciles_by_stable_identity() {
        let record = record();
        let commit = commit_record(&record);
        let envelope = envelope();
        // The first commit's outcome is unknown (attempts == 1): reconcile by
        // stable identity, and an unknown reconciliation stays pending.
        let gateway = gateway_with(vec![Err(transport_error())], vec![Err(transport_error())]);
        let (resolution, retried) = resolve_commit(&gateway, 1, &record, &commit, &envelope).await;
        assert_eq!(resolution, CommitResolution::Pending);
        assert!(!retried);
        assert_eq!(*gateway.calls.lock().unwrap(), ["commit", "reconcile"]);
        assert_eq!(gateway.commits.lock().unwrap().len(), 1);
    }
}
