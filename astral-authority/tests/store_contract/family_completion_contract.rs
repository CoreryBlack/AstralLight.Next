//! Isolated V7 certified-memory family and root fail-closed contracts.
//!
//! These tests use the shared in-memory authority fixture from `store_contract`.
//! They do not start a service, connect to a quorum, or exercise migrations.

use super::*;
use astral_authority::error::AuthorityStoreError;
use astral_types::{
    AuthorityCertifiedMemoryFamily, AuthorityCertifiedMemoryRootInstallRequest,
    AuthorityCertifiedMemoryRootOperation, AuthorityCertifiedMemoryRootProposal,
    AuthorityCertifiedMemoryRootReadRequest, AuthorityFamilyCompletionCandidate,
    AuthorityFamilyCompletionRequest, AuthorityFamilyCompletionState,
    AuthorityFamilyDependencyFrontier, AuthorityFamilyInventoryItem, AuthorityFamilyScope,
    AuthorityReservationState, GlobalAuthorityFrontier,
};

fn family_scope() -> AuthorityFamilyScope {
    AuthorityFamilyScope {
        tenant_id: Some(7),
        scope: "tenant:7".to_owned(),
    }
}

fn family_candidate(
    reservation_id: &str,
    family: AuthorityCertifiedMemoryFamily,
) -> AuthorityFamilyCompletionCandidate {
    AuthorityFamilyCompletionCandidate {
        family,
        state: AuthorityFamilyCompletionState::CompleteEmpty,
        scope: family_scope(),
        reservation_id: reservation_id.to_owned(),
        operation_id: OPERATION_ID.to_owned(),
        event_id: "event-1".to_owned(),
        message_id: Some(format!("family-message-{}", family.as_text())),
        source_commit_digest: "11".repeat(32),
        source_outcome_digest: "99".repeat(32),
        before_content_digest: None,
        after_content_digest: None,
        complete_content_digest: Some("33".repeat(32)),
        audit_correlation_id: format!("family-audit-{}", family.as_text()),
        inventory: Vec::new(),
        scope_generation: 1,
        revoke_watermark: 0,
        dependency_frontier: AuthorityFamilyDependencyFrontier {
            authority_term: 1,
            global_fence_sequence: 1,
            dependency_generation: 1,
        },
    }
}

async fn committed_family_fixture() -> (
    AuthorityService,
    Arc<MemoryAuthorityStore>,
    KeyLayout,
    astral_types::AuthorityScopeReservation,
    astral_types::AuthorityCommitResponse,
) {
    let mut config = test_config();
    config.policy.exact_scope_coverage_enabled = true;
    config.trusted_sources[0].allowed_operations.extend([
        "family_completion".to_owned(),
        "commit_finite_coverage".to_owned(),
    ]);
    let (service, store, keys, signer_key) = test_service_with_config(config).await;
    seed_admission_proof(
        &service,
        &store,
        &keys,
        &signer_key,
        "prf-seed",
        REQUEST_DIGEST,
    )
    .await;

    let prepare = service
        .prepare_source_mutation(&AuthorityPrepareRequest {
            caller: caller(),
            intent: intent(AuthorityReservationCoverage::Global),
        })
        .await
        .unwrap();
    let committed = service
        .record_source_commit(&AuthorityCommitRequest {
            caller: caller(),
            database_id: DATABASE_ID.to_owned(),
            commit: AuthoritySourceCommitRecord {
                reservation_id: prepare.reservation.reservation_id.clone(),
                operation_id: OPERATION_ID.to_owned(),
                source_commit_digest: "11".repeat(32),
                before_image_digest: Some("cd".repeat(32)),
                after_image_digest: "22".repeat(32),
                source_outcome_digest: "99".repeat(32),
                staged_evidence_digest: "88".repeat(32),
                committed_at: 2_000,
            },
            declared_coverage: Some(astral_types::AuthorityStagedScopeCoverage {
                scopes: vec![card_scope()],
            }),
        })
        .await
        .unwrap();
    assert_eq!(
        committed.reservation.as_ref().unwrap().state,
        AuthorityReservationState::Committed
    );
    (service, store, keys, prepare.reservation, committed)
}

fn family_request(
    reservation_id: &str,
    family: AuthorityCertifiedMemoryFamily,
) -> AuthorityFamilyCompletionRequest {
    AuthorityFamilyCompletionRequest {
        caller: caller(),
        database_id: DATABASE_ID.to_owned(),
        completion: family_candidate(reservation_id, family),
    }
}

// Seed a pre-existing authority receipt without using the now-closed issuance
// endpoint. Its frontier comes from the already committed reservation.
async fn seed_historical_receipt(
    store: &MemoryAuthorityStore,
    keys: &KeyLayout,
    committed: &astral_types::AuthorityCommitResponse,
    request: &AuthorityFamilyCompletionRequest,
) -> astral_types::AuthorityFamilyCompletionReceipt {
    let receipt_id = format!("historical-{}", request.completion.family.as_text());
    let receipt = astral_types::AuthorityFamilyCompletionReceipt {
        completion: request
            .completion
            .clone()
            .into_receipted_completion(receipt_id.clone())
            .unwrap(),
        receipt_id,
        completed_at: 2_001,
        global_frontier: committed.global_frontier.clone(),
    };
    receipt.validate().unwrap();
    let bytes = serde_json::to_vec(&receipt).unwrap();
    store
        .execute(
            StoreTxn::new()
                .with_op(StoreOp::Put {
                    key: keys.family_completion(
                        &request.completion.reservation_id,
                        request.completion.family.as_text(),
                    ),
                    value: bytes.clone(),
                })
                .with_op(StoreOp::Put {
                    key: keys.family_completion_operation(
                        &request.completion.operation_id,
                        request.completion.family.as_text(),
                    ),
                    value: bytes,
                }),
        )
        .await
        .unwrap();
    receipt
}

#[tokio::test]
async fn family_completion_historical_replay_preserves_the_receipt_frontier() {
    let (service, store, keys, reservation, committed) = committed_family_fixture().await;
    let first_request = family_request(
        &reservation.reservation_id,
        AuthorityCertifiedMemoryFamily::CardContext,
    );
    let historical = seed_historical_receipt(&store, &keys, &committed, &first_request).await;
    let first_frontier: GlobalAuthorityFrontier = historical.global_frontier.clone();
    let revision_before_replay = store.current_revision();
    let replay = service
        .record_family_completion(&first_request)
        .await
        .unwrap();
    assert_eq!(replay.receipt, historical);
    assert_eq!(replay.global_frontier, first_frontier);
    assert_eq!(
        replay.reservation.state,
        AuthorityReservationState::Committed
    );
    assert!(!replay.read_gate.positive_reads_allowed);
    assert_eq!(store.current_revision(), revision_before_replay);

    let reconciled = service
        .reconcile_family_completion(&astral_types::AuthorityFamilyCompletionReconcileRequest {
            caller: caller(),
            database_id: DATABASE_ID.to_owned(),
            reservation_id: reservation.reservation_id,
            operation_id: OPERATION_ID.to_owned(),
            family: AuthorityCertifiedMemoryFamily::CardContext,
        })
        .await
        .unwrap();
    assert_eq!(reconciled.receipt, Some(historical));
    assert_eq!(reconciled.global_frontier, first_frontier);
    assert_eq!(store.current_revision(), revision_before_replay);
}

#[tokio::test]
async fn six_historical_receipts_replay_without_creating_an_aggregate() {
    let (service, store, keys, reservation, committed) = committed_family_fixture().await;
    for family in AuthorityCertifiedMemoryFamily::required() {
        let request = family_request(&reservation.reservation_id, family);
        seed_historical_receipt(&store, &keys, &committed, &request).await;
    }
    let revision = store.current_revision();
    for family in AuthorityCertifiedMemoryFamily::required() {
        let request = family_request(&reservation.reservation_id, family);
        let response = service.record_family_completion(&request).await.unwrap();
        assert_eq!(
            response.reservation.state,
            AuthorityReservationState::Committed
        );
        assert!(!response.read_gate.positive_reads_allowed);
        assert_eq!(store.current_revision(), revision);
    }
    assert!(store
        .get(&keys.family_completion_aggregate(&reservation.reservation_id))
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn historical_replay_keeps_binding_and_leadership_rejection_order() {
    let (service, store, keys, reservation, committed) = committed_family_fixture().await;
    let request = family_request(
        &reservation.reservation_id,
        AuthorityCertifiedMemoryFamily::CardContext,
    );
    let revision = store.current_revision();
    service
        .leader_flag()
        .store(false, std::sync::atomic::Ordering::Release);
    assert!(matches!(
        service.record_family_completion(&request).await,
        Err(AuthorityServiceError::NotLeader)
    ));
    assert_eq!(store.current_revision(), revision);

    let receipt = seed_historical_receipt(&store, &keys, &committed, &request).await;
    let revision = store.current_revision();
    let replay = service.record_family_completion(&request).await.unwrap();
    assert_eq!(replay.receipt, receipt);
    let mut drifted = request.clone();
    drifted.completion.audit_correlation_id = "different-audit".into();
    assert!(matches!(
        service.record_family_completion(&drifted).await,
        Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::DigestMismatch {
                field: "family_completion_request"
            }
        ))
    ));
    let mut binding_drift = request;
    binding_drift.completion.source_commit_digest = "55".repeat(32);
    assert!(matches!(
        service.record_family_completion(&binding_drift).await,
        Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::DigestMismatch {
                field: "source_binding"
            }
        ))
    ));
    assert_eq!(store.current_revision(), revision);
}

#[tokio::test]
async fn family_completion_rejects_missing_or_disagreeing_dual_indexes() {
    let (service, store, keys, reservation, committed) = committed_family_fixture().await;
    let request = family_request(
        &reservation.reservation_id,
        AuthorityCertifiedMemoryFamily::CardContext,
    );
    seed_historical_receipt(&store, &keys, &committed, &request).await;

    store
        .execute(StoreTxn::new().with_op(StoreOp::Delete {
            key: keys.family_completion_operation(
                OPERATION_ID,
                AuthorityCertifiedMemoryFamily::CardContext.as_text(),
            ),
        }))
        .await
        .unwrap();
    let revision_after_delete = store.current_revision();
    assert!(matches!(
        service.record_family_completion(&request).await,
        Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(message)))
            if message.contains("indexes are incomplete")
    ));
    assert_eq!(store.current_revision(), revision_after_delete);

    let (service, store, keys, reservation, committed) = committed_family_fixture().await;
    let request = family_request(
        &reservation.reservation_id,
        AuthorityCertifiedMemoryFamily::CardContext,
    );
    seed_historical_receipt(&store, &keys, &committed, &request).await;
    let operation_key = keys.family_completion_operation(
        OPERATION_ID,
        AuthorityCertifiedMemoryFamily::CardContext.as_text(),
    );
    let operation_record = store.get(&operation_key).await.unwrap().unwrap();
    let mut operation_receipt: astral_types::AuthorityFamilyCompletionReceipt =
        serde_json::from_slice(&operation_record.value).unwrap();
    operation_receipt.completed_at += 1;
    store
        .execute(StoreTxn::new().with_op(StoreOp::Put {
            key: operation_key,
            value: serde_json::to_vec(&operation_receipt).unwrap(),
        }))
        .await
        .unwrap();
    let revision_after_drift = store.current_revision();
    assert!(matches!(
        service.record_family_completion(&request).await,
        Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(message)))
            if message.contains("indexes disagree")
    ));
    assert_eq!(store.current_revision(), revision_after_drift);
}

#[tokio::test]
async fn family_reconcile_rejects_receipt_event_drift() {
    let (service, store, keys, reservation, committed) = committed_family_fixture().await;
    let family = AuthorityCertifiedMemoryFamily::CardContext;
    let request = family_request(&reservation.reservation_id, family);
    let mut receipt = seed_historical_receipt(&store, &keys, &committed, &request).await;
    receipt.completion.event_id = "other-event".to_owned();
    let bytes = serde_json::to_vec(&receipt).unwrap();
    store
        .execute(
            StoreTxn::new()
                .with_op(StoreOp::Put {
                    key: keys.family_completion(&reservation.reservation_id, family.as_text()),
                    value: bytes.clone(),
                })
                .with_op(StoreOp::Put {
                    key: keys.family_completion_operation(OPERATION_ID, family.as_text()),
                    value: bytes,
                }),
        )
        .await
        .unwrap();
    let revision = store.current_revision();
    let reconcile = astral_types::AuthorityFamilyCompletionReconcileRequest {
        caller: caller(),
        database_id: DATABASE_ID.to_owned(),
        reservation_id: reservation.reservation_id,
        operation_id: OPERATION_ID.to_owned(),
        family,
    };
    assert!(matches!(
        service.reconcile_family_completion(&reconcile).await,
        Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::ScopeMismatch
        ))
    ));
    assert_eq!(store.current_revision(), revision);
}

#[tokio::test]
async fn six_family_self_reports_cannot_issue_receipts_or_close_the_global_barrier() {
    let (service, store, keys, reservation, _committed) = committed_family_fixture().await;
    let revision = store.current_revision();
    for family in AuthorityCertifiedMemoryFamily::required() {
        for nonempty in [false, true] {
            let mut request = family_request(&reservation.reservation_id, family);
            if nonempty {
                request.completion.state = AuthorityFamilyCompletionState::Complete;
                request
                    .completion
                    .inventory
                    .push(AuthorityFamilyInventoryItem {
                        key: "self-reported-item".into(),
                        tenant_id: Some(7),
                        content_digest: "44".repeat(32),
                    });
            }
            request.validate().unwrap();
            assert!(matches!(
                service.record_family_completion(&request).await,
                Err(AuthorityServiceError::Protocol(AuthorityProtocolError::StateConflict {
                    record: "family_completion", state
                })) if state == "SOURCE_COMPLETENESS_UNVERIFIED"
            ));
            assert!(store
                .get(&keys.family_completion(&reservation.reservation_id, family.as_text()))
                .await
                .unwrap()
                .is_none());
            assert!(store
                .get(&keys.family_completion_operation(OPERATION_ID, family.as_text()))
                .await
                .unwrap()
                .is_none());
            assert_eq!(store.current_revision(), revision);
        }
    }
    let stored_reservation: astral_types::AuthorityScopeReservation = serde_json::from_slice(
        &store
            .get(&keys.reservation(&reservation.reservation_id))
            .await
            .unwrap()
            .unwrap()
            .value,
    )
    .unwrap();
    assert_eq!(
        stored_reservation.state,
        AuthorityReservationState::Committed
    );
    let reconciled = service
        .reconcile_family_completion(&astral_types::AuthorityFamilyCompletionReconcileRequest {
            caller: caller(),
            database_id: DATABASE_ID.to_owned(),
            reservation_id: reservation.reservation_id,
            operation_id: OPERATION_ID.to_owned(),
            family: AuthorityCertifiedMemoryFamily::CardContext,
        })
        .await
        .unwrap();
    assert!(reconciled.receipt.is_none());
    assert!(!reconciled.read_gate.positive_reads_allowed);
}

fn root_proposal() -> AuthorityCertifiedMemoryRootProposal {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    AuthorityCertifiedMemoryRootProposal {
        protocol_version: astral_types::AUTHORITY_PROTOCOL_VERSION,
        authorization_edition: AUTHORIZATION_EDITION,
        authority_id: "authority-test".to_owned(),
        reservation_id: "reservation-without-publication-proof".to_owned(),
        operation_id: "root-operation-without-publication-proof".to_owned(),
        event_id: "root-event-without-publication-proof".to_owned(),
        source_commit_digest: "11".repeat(32),
        source_outcome_digest: "22".repeat(32),
        family_bundle_digest: "33".repeat(32),
        publication_proof: None,
        snapshot_hash: "44".repeat(32),
        scope_generation: 1,
        revoke_watermark: 0,
        parent_root_digest: None,
        coverage: astral_types::AuthorityCertifiedMemoryCoverage::complete(),
        not_before: now,
        expires_at: now + 3_600,
    }
}

#[tokio::test]
async fn certified_memory_root_install_and_read_fail_closed_without_publication_proof() {
    let mut config = test_config();
    config.trusted_sources[0].allowed_operations.extend([
        "install_certified_memory".to_owned(),
        "read_certified_memory".to_owned(),
    ]);
    let (service, store, _keys, _signer_key) = test_service_with_config(config).await;
    let proposal = root_proposal();
    let install = AuthorityCertifiedMemoryRootInstallRequest {
        caller: caller(),
        operation: AuthorityCertifiedMemoryRootOperation::Install,
        proposal,
    };

    let revision_before_install = store.current_revision();
    assert!(matches!(
        service.install_certified_memory_root(&install).await,
        Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::NotFound {
                record: "certified_memory_publication_proof"
            }
        ))
    ));
    assert_eq!(store.current_revision(), revision_before_install);

    let read = AuthorityCertifiedMemoryRootReadRequest {
        caller: caller(),
        operation: AuthorityCertifiedMemoryRootOperation::Read,
        expected_root_digest: None,
    };
    let revision_before_read = store.current_revision();
    assert!(matches!(
        service.read_certified_memory_root(&read).await,
        Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::NotFound {
                record: "certified_memory_publication_proof"
            }
        ))
    ));
    assert_eq!(store.current_revision(), revision_before_read);
}
