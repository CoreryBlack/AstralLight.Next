//! Operator close history verification and terminal-state completeness.
//!
//! The operator close blesses a GLOBAL reservation's publication history as
//! complete: every certified scope's immutable certificate record is
//! verified end to end BEFORE the terminal flip, an empty actual history is
//! refused (the operator assertion never fabricates a fanout proof), a
//! recorded declared finite coverage must be fully certified, and the close
//! stores a stable operator/reason/operation receipt in the SAME CAS for
//! audit and idempotency — a repeated or recovered close reads back by
//! stable identity and never re-advances the frontier. Certified terminal
//! states must never outrun their served publication history. These
//! regressions run the real `AuthorityService` against
//! `MemoryAuthorityStore` — an in-process CAS mirror, NOT real etcd/quorum.

use super::*;

fn other_scope() -> AuthorityProtocolScope {
    AuthorityProtocolScope::Card(astral_types::AuthorizationAuthorityScope {
        tenant_id: 7,
        card_id: 18,
        user_id: None,
        domain: AuthorizationDomainScope::Any,
    })
}

fn operator_caller(nonce: &str) -> AuthorityCallerIdentity {
    AuthorityCallerIdentity {
        service_id: OPERATOR_ID.to_owned(),
        request_nonce: nonce.to_owned(),
        issued_at: 1_700,
    }
}

/// Test-local mirror of the durable close receipt (quorum-side record).
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CloseReceiptView {
    reservation_id: String,
    operation_id: String,
    operator: String,
    reason: String,
    closed_at: i64,
    certified_scopes: Vec<String>,
    frontier: astral_types::GlobalAuthorityFrontier,
}

async fn reconcile(
    service: &AuthorityService,
    reservation_id: &str,
) -> Result<astral_types::AuthorityReconcileResponse, AuthorityServiceError> {
    service
        .reconcile_reservation(&AuthorityReconcileRequest {
            caller: caller(),
            reservation_id: reservation_id.to_owned(),
            operation_id: OPERATION_ID.to_owned(),
        })
        .await
}

async fn operator_close(
    service: &AuthorityService,
    reservation_id: &str,
    reason: &str,
) -> Result<astral_types::AuthorityCloseReservationResponse, AuthorityServiceError> {
    service
        .close_reservation(&astral_types::AuthorityCloseReservationRequest {
            caller: operator_caller("operator-close-1"),
            reservation_id: reservation_id.to_owned(),
            operation_id: OPERATION_ID.to_owned(),
            reason: reason.to_owned(),
        })
        .await
}

/// Seed one GLOBAL lifecycle at the committed frontier: prepare + commit only
/// (no certification), so the reservation is Committed and the caller can
/// decide what to certify — or nothing at all.
#[allow(clippy::too_many_arguments)]
async fn seeded_committed_global(
    service: &AuthorityService,
    store: &MemoryAuthorityStore,
    keys: &KeyLayout,
    signer_key: &SigningKey,
    declared: Option<Vec<AuthorityProtocolScope>>,
) -> astral_types::AuthorityPrepareResponse {
    let one = op_one();
    seed_admission_proof(
        service,
        store,
        keys,
        signer_key,
        one.admission_proof_id,
        REQUEST_DIGEST,
    )
    .await;
    let prepare = service
        .prepare_source_mutation(&AuthorityPrepareRequest {
            caller: caller(),
            intent: op_intent(&one, AuthorityReservationCoverage::Global),
        })
        .await
        .unwrap();
    service
        .record_source_commit(&op_commit_request(
            &one,
            &prepare.reservation,
            declared.map(|scopes| astral_types::AuthorityStagedScopeCoverage { scopes }),
        ))
        .await
        .unwrap();
    prepare
}

#[tokio::test]
async fn service_index_writers_advance_reservation_revision_and_fence_stale_snapshot() {
    use astral_authority::store::{SnapshotRead, StoreTxnOutcome};

    let (service, store, keys, signer_key) = test_service().await;
    let prepare = seeded_committed_global(&service, &store, &keys, &signer_key, None).await;
    let reservation_id = &prepare.reservation.reservation_id;
    let reservation_key = keys.reservation(reservation_id);
    let index_key =
        keys.reservation_certificate(reservation_id, &card_scope().store_key_text().unwrap());
    let reads = [
        SnapshotRead::Key(reservation_key.clone()),
        SnapshotRead::Prefix(keys.reservation_certificate(reservation_id, "")),
    ];
    let before_certify = store.read_snapshot(&reads).await.unwrap();
    let old_reservation_revision = before_certify.reads[0][0].1.revision;
    assert!(before_certify.reads[1].is_empty());

    let certify_request = op_certify_request(&op_one(), &prepare.reservation, None, card_scope());
    let certified = service.certify_publication(&certify_request).await.unwrap();
    let reservation_after_certify = store.get(&reservation_key).await.unwrap().unwrap();
    let index_after_certify = store.get(&index_key).await.unwrap().unwrap();
    assert!(reservation_after_certify.revision > old_reservation_revision);
    assert_eq!(
        reservation_after_certify.revision,
        index_after_certify.revision
    );
    let stale_root = StoreTxn::new()
        .with_op(StoreOp::RequireRevision {
            key: reservation_key.clone(),
            expected_revision: old_reservation_revision,
        })
        .with_op(StoreOp::PutIfAbsent {
            key: "test/stale-root-after-certify".into(),
            value: vec![1],
        });
    assert!(matches!(
        store.execute(stale_root).await.unwrap(),
        StoreTxnOutcome::PreconditionFailed { .. }
    ));
    assert!(store
        .get("test/stale-root-after-certify")
        .await
        .unwrap()
        .is_none());

    let replay = service.certify_publication(&certify_request).await.unwrap();
    assert_eq!(replay.certificate, certified.certificate);
    assert_eq!(
        store.get(&reservation_key).await.unwrap().unwrap(),
        reservation_after_certify
    );
    assert_eq!(
        store.get(&index_key).await.unwrap().unwrap(),
        index_after_certify
    );

    let before_close = store.read_snapshot(&reads).await.unwrap();
    let before_close_revision = before_close.reads[0][0].1.revision;
    let closed = operator_close(&service, reservation_id, "complete history")
        .await
        .unwrap();
    let reservation_after_close = store.get(&reservation_key).await.unwrap().unwrap();
    let receipt_key = keys.reservation_certificate(reservation_id, "OPERATOR-CLOSE");
    let receipt = store.get(&receipt_key).await.unwrap().unwrap();
    assert!(reservation_after_close.revision > before_close_revision);
    assert_eq!(reservation_after_close.revision, receipt.revision);
    let stale_root = StoreTxn::new()
        .with_op(StoreOp::RequireRevision {
            key: reservation_key.clone(),
            expected_revision: before_close_revision,
        })
        .with_op(StoreOp::PutIfAbsent {
            key: "test/stale-root-after-close".into(),
            value: vec![1],
        });
    assert!(matches!(
        store.execute(stale_root).await.unwrap(),
        StoreTxnOutcome::PreconditionFailed { .. }
    ));
    assert!(store
        .get("test/stale-root-after-close")
        .await
        .unwrap()
        .is_none());

    let replay = operator_close(&service, reservation_id, "complete history")
        .await
        .unwrap();
    assert_eq!(replay.global_frontier, closed.global_frontier);
    assert_eq!(
        store.get(&reservation_key).await.unwrap().unwrap(),
        reservation_after_close
    );
    assert_eq!(store.get(&receipt_key).await.unwrap().unwrap(), receipt);
}

#[tokio::test]
async fn close_verifies_history_before_flip_and_records_stable_receipt() {
    let (service, store, keys, signer_key) = test_service().await;
    let one = op_one();
    let prepare = seeded_committed_global(&service, &store, &keys, &signer_key, None).await;
    let reservation_id = prepare.reservation.reservation_id.clone();
    let scope_key = card_scope().store_key_text().unwrap();

    let certify = service
        .certify_publication(&op_certify_request(
            &one,
            &prepare.reservation,
            None,
            card_scope(),
        ))
        .await
        .unwrap();
    assert_eq!(
        certify.reservation.state,
        astral_types::AuthorityReservationState::Published
    );

    // A tampered certificate record refuses BOTH the close and the
    // reconcile: the terminal flip can never bless broken history.
    let index_key = keys.reservation_certificate(&reservation_id, &scope_key);
    let certificate_id: String =
        serde_json::from_slice(&store.get(&index_key).await.unwrap().unwrap().value).unwrap();
    let certificate_key = keys.certificate(&certificate_id);
    let original_certificate = store.get(&certificate_key).await.unwrap().unwrap().value;
    let mut tampered: AuthorityScopePublicationCertificate =
        serde_json::from_slice(&original_certificate).unwrap();
    tampered.snapshot_hash = "7f".repeat(32);
    store
        .execute(StoreTxn::new().with_op(StoreOp::Put {
            key: certificate_key.clone(),
            value: serde_json::to_vec(&tampered).unwrap(),
        }))
        .await
        .unwrap();
    assert!(
        operator_close(&service, &reservation_id, "all approved scopes certified")
            .await
            .is_err(),
        "close must refuse tampered history"
    );
    assert!(reconcile(&service, &reservation_id).await.is_err());
    store
        .execute(StoreTxn::new().with_op(StoreOp::Put {
            key: certificate_key,
            value: original_certificate,
        }))
        .await
        .unwrap();

    // The verified close flips to the terminal state.
    let closed = operator_close(&service, &reservation_id, "all approved scopes certified")
        .await
        .unwrap();
    closed
        .validate()
        .expect("close response must satisfy the tightened terminal contract");
    assert_eq!(
        closed.reservation.state,
        astral_types::AuthorityReservationState::Certified
    );

    // The stable receipt is readable by identity for audit/idempotency.
    let receipt: CloseReceiptView = serde_json::from_slice(
        &store
            .get(&keys.reservation_certificate(&reservation_id, "OPERATOR-CLOSE"))
            .await
            .unwrap()
            .expect("close receipt is stored in the close CAS")
            .value,
    )
    .unwrap();
    assert_eq!(receipt.reservation_id, reservation_id);
    assert_eq!(receipt.operation_id, one.operation_id);
    assert_eq!(receipt.operator, OPERATOR_ID);
    assert_eq!(receipt.reason, "all approved scopes certified");
    assert_eq!(receipt.certified_scopes, vec![scope_key.clone()]);
    assert_eq!(
        receipt.frontier, closed.global_frontier,
        "the receipt preserves the COMPLETE post-close frontier"
    );

    // Unknown-outcome retry: the EXACT same close (stable operation, operator
    // and reason) reads back the terminal state and the ORIGINAL post-close
    // frontier from the receipt — the frontier never re-advances and the
    // receipt is never rewritten.
    let receipt_bytes_before = store
        .get(&keys.reservation_certificate(&reservation_id, "OPERATOR-CLOSE"))
        .await
        .unwrap()
        .unwrap()
        .value;
    let replayed = operator_close(&service, &reservation_id, "all approved scopes certified")
        .await
        .unwrap();
    replayed
        .validate()
        .expect("the idempotent replay must satisfy the terminal contract");
    assert_eq!(
        replayed.reservation.state,
        astral_types::AuthorityReservationState::Certified
    );
    assert_eq!(
        replayed.global_frontier, closed.global_frontier,
        "the replay serves the recorded post-close frontier"
    );
    assert_eq!(
        store
            .get(&keys.reservation_certificate(&reservation_id, "OPERATOR-CLOSE"))
            .await
            .unwrap()
            .unwrap()
            .value,
        receipt_bytes_before,
        "the replay must not rewrite the receipt"
    );

    // Any different binding is a genuine conflict.
    assert!(matches!(
        operator_close(&service, &reservation_id, "retry").await,
        Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::StateConflict { .. }
        ))
    ));
    assert!(matches!(
        service
            .close_reservation(&astral_types::AuthorityCloseReservationRequest {
                caller: operator_caller("operator-close-1"),
                reservation_id: reservation_id.clone(),
                operation_id: "operation-other".to_owned(),
                reason: "all approved scopes certified".to_owned(),
            })
            .await,
        Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::StateConflict { .. }
        ))
    ));

    // The current frontier moves on with a later lifecycle; the replay STILL
    // serves the original recorded frontier, never the current one.
    let two = op_two();
    seed_operation_proof(&store, &keys, &signer_key, &two, 1, 5).await;
    let prepare_two = service
        .prepare_source_mutation(&AuthorityPrepareRequest {
            caller: caller(),
            intent: op_intent(&two, AuthorityReservationCoverage::Global),
        })
        .await
        .unwrap();
    service
        .record_source_commit(&op_commit_request(&two, &prepare_two.reservation, None))
        .await
        .unwrap();
    service
        .certify_publication(&op_certify_request(
            &two,
            &prepare_two.reservation,
            Some(certify.certificate.record_digest().unwrap()),
            card_scope(),
        ))
        .await
        .unwrap();

    let replayed_again =
        operator_close(&service, &reservation_id, "all approved scopes certified").await;
    match replayed_again {
        Ok(replayed_again) => {
            replayed_again.validate().unwrap();
            assert_ne!(
                replayed_again.global_frontier.global_fence_sequence, 8,
                "sanity: the current frontier has advanced past the recorded one"
            );
            assert_eq!(
                replayed_again.global_frontier, closed.global_frontier,
                "the recorded frontier is served even after the authority moved on"
            );
        }
        other => panic!("the exact close retry must stay idempotent, got {other:?}"),
    }

    // The replay still re-verifies the terminal history: corrupting the
    // certified record after the close must fail the retry until restored.
    let certificate_id: String = serde_json::from_slice(
        &store
            .get(&keys.reservation_certificate(&reservation_id, &scope_key))
            .await
            .unwrap()
            .unwrap()
            .value,
    )
    .unwrap();
    let certificate_key = keys.certificate(&certificate_id);
    let intact_certificate = store.get(&certificate_key).await.unwrap().unwrap().value;
    let mut corrupted: AuthorityScopePublicationCertificate =
        serde_json::from_slice(&intact_certificate).unwrap();
    corrupted.snapshot_hash = "7e".repeat(32);
    store
        .execute(StoreTxn::new().with_op(StoreOp::Put {
            key: certificate_key.clone(),
            value: serde_json::to_vec(&corrupted).unwrap(),
        }))
        .await
        .unwrap();
    assert!(
        operator_close(&service, &reservation_id, "all approved scopes certified")
            .await
            .is_err(),
        "a replay must never succeed over corrupted terminal history"
    );
    store
        .execute(StoreTxn::new().with_op(StoreOp::Put {
            key: certificate_key,
            value: intact_certificate,
        }))
        .await
        .unwrap();

    // A receipt that no longer matches the actual certified history is
    // refused; so is a receipt frontier ahead of the authority chain.
    let receipt_key = keys.reservation_certificate(&reservation_id, "OPERATOR-CLOSE");
    let intact_receipt = store.get(&receipt_key).await.unwrap().unwrap().value;
    let mut drifting: CloseReceiptView = serde_json::from_slice(&intact_receipt).unwrap();
    drifting.certified_scopes.clear();
    store
        .execute(StoreTxn::new().with_op(StoreOp::Put {
            key: receipt_key.clone(),
            value: serde_json::to_vec(&drifting).unwrap(),
        }))
        .await
        .unwrap();
    match operator_close(&service, &reservation_id, "all approved scopes certified").await {
        Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(message))) => {
            assert_eq!(
                message,
                "close receipt does not match the certified history"
            );
        }
        other => panic!("drifting receipt must be refused, got {other:?}"),
    }
    let mut ahead: CloseReceiptView = serde_json::from_slice(&intact_receipt).unwrap();
    ahead.frontier.global_fence_sequence = 9_999;
    store
        .execute(StoreTxn::new().with_op(StoreOp::Put {
            key: receipt_key.clone(),
            value: serde_json::to_vec(&ahead).unwrap(),
        }))
        .await
        .unwrap();
    match operator_close(&service, &reservation_id, "all approved scopes certified").await {
        Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(message))) => {
            assert_eq!(
                message,
                "receipt frontier conflicts with the verified authority frontier"
            );
        }
        other => panic!("a non-historical receipt frontier must be refused, got {other:?}"),
    }
    store
        .execute(StoreTxn::new().with_op(StoreOp::Put {
            key: receipt_key,
            value: intact_receipt,
        }))
        .await
        .unwrap();

    // The recovery read by stable operation shows the same certified history.
    let reconciled = reconcile(&service, &reservation_id).await.unwrap();
    reconciled
        .validate()
        .expect("the certified history must satisfy the response contract");
    assert_eq!(reconciled.reconciliation.disposition.as_text(), "CERTIFIED");
    assert_eq!(reconciled.certified_publications.len(), 1);
}

#[tokio::test]
async fn close_refuses_empty_history_and_incomplete_declared_finite_coverage() {
    // (a) A GLOBAL reservation stripped of its actual history: the operator
    // close is refused — the assertion never fabricates a fanout proof.
    let (service, store, keys, signer_key) = test_service().await;
    let one = op_one();
    let prepare = seeded_committed_global(&service, &store, &keys, &signer_key, None).await;
    let reservation_id = prepare.reservation.reservation_id.clone();
    service
        .certify_publication(&op_certify_request(
            &one,
            &prepare.reservation,
            None,
            card_scope(),
        ))
        .await
        .unwrap();
    let reservation_key = keys.reservation(&reservation_id);
    let mut stripped: astral_types::AuthorityScopeReservation =
        serde_json::from_slice(&store.get(&reservation_key).await.unwrap().unwrap().value).unwrap();
    stripped.certified_scopes.clear();
    stripped.certificate_id = None;
    store
        .execute(StoreTxn::new().with_op(StoreOp::Put {
            key: reservation_key,
            value: serde_json::to_vec(&stripped).unwrap(),
        }))
        .await
        .unwrap();
    match operator_close(&service, &reservation_id, "empty history").await {
        Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(message))) => {
            assert_eq!(message, "certified reservation lacks its declared coverage");
        }
        other => panic!("empty history must fail the close, got {other:?}"),
    }

    // (b) A recorded declared finite coverage must be FULLY certified before
    // the operator close: partial certification refuses, while the read path
    // at PUBLISHED still serves the partial history as-is.
    let (service, store, keys, signer_key) = test_service().await;
    let one = op_one();
    let prepare = seeded_committed_global(
        &service,
        &store,
        &keys,
        &signer_key,
        Some(vec![card_scope(), other_scope()]),
    )
    .await;
    let reservation_id = prepare.reservation.reservation_id.clone();
    service
        .certify_publication(&op_certify_request(
            &one,
            &prepare.reservation,
            None,
            card_scope(),
        ))
        .await
        .unwrap();
    let reconciled = reconcile(&service, &reservation_id).await.unwrap();
    reconciled.validate().unwrap();
    assert_eq!(reconciled.certified_publications.len(), 1);
    match operator_close(&service, &reservation_id, "partial declared coverage").await {
        Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(message))) => {
            assert_eq!(message, "certified reservation lacks its declared coverage");
        }
        other => panic!("incomplete declared coverage must fail the close, got {other:?}"),
    }
}

#[tokio::test]
async fn certified_states_never_outrun_their_served_history() {
    // (a) Contract level: a response claiming Certified for a partially
    // certified EXACT reservation is rejected by the wire contract.
    let (service, store, keys, signer_key) = test_service_with_exact_coverage(true).await;
    let one = op_one();
    seed_admission_proof(
        &service,
        &store,
        &keys,
        &signer_key,
        one.admission_proof_id,
        REQUEST_DIGEST,
    )
    .await;
    let prepare = service
        .prepare_source_mutation(&AuthorityPrepareRequest {
            caller: caller(),
            intent: op_intent(
                &one,
                AuthorityReservationCoverage::Exact(vec![card_scope(), other_scope()]),
            ),
        })
        .await
        .unwrap();
    service
        .record_source_commit(&op_commit_request(
            &one,
            &prepare.reservation,
            Some(astral_types::AuthorityStagedScopeCoverage {
                scopes: vec![card_scope(), other_scope()],
            }),
        ))
        .await
        .unwrap();
    service
        .certify_publication(&op_certify_request(
            &one,
            &prepare.reservation,
            None,
            card_scope(),
        ))
        .await
        .unwrap();
    let reconciled = reconcile(&service, prepare.reservation.reservation_id.as_str())
        .await
        .unwrap();
    reconciled.validate().unwrap();
    let mut forged = reconciled.clone();
    forged.reconciliation.reservation.as_mut().unwrap().state =
        astral_types::AuthorityReservationState::Certified;
    assert!(
        forged.validate().is_err(),
        "Certified EXACT with a partial history must fail the wire contract"
    );

    // (b) Store level: a tampered Certified reservation with a partial set
    // is refused fail-closed by the recovery read.
    let reservation_key = keys.reservation(&prepare.reservation.reservation_id);
    let mut tampered: astral_types::AuthorityScopeReservation =
        serde_json::from_slice(&store.get(&reservation_key).await.unwrap().unwrap().value).unwrap();
    tampered.state = astral_types::AuthorityReservationState::Certified;
    store
        .execute(StoreTxn::new().with_op(StoreOp::Put {
            key: reservation_key,
            value: serde_json::to_vec(&tampered).unwrap(),
        }))
        .await
        .unwrap();
    match reconcile(&service, prepare.reservation.reservation_id.as_str()).await {
        Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(message))) => {
            assert_eq!(message, "certified reservation lacks its declared coverage");
        }
        other => panic!("tampered Certified partial history must be refused, got {other:?}"),
    }

    // (c) A validly-signed certificate bound to a FOREIGN frontier is
    // refused: the history binds each reservation's immutable prepare
    // frontier, not just the signer identity.
    let (service, store, keys, signer_key) = test_service().await;
    let one = op_one();
    let prepare = seeded_committed_global(&service, &store, &keys, &signer_key, None).await;
    let reservation_id = prepare.reservation.reservation_id.clone();
    service
        .certify_publication(&op_certify_request(
            &one,
            &prepare.reservation,
            None,
            card_scope(),
        ))
        .await
        .unwrap();
    let scope_key = card_scope().store_key_text().unwrap();
    let index_key = keys.reservation_certificate(&reservation_id, &scope_key);
    let certificate_id: String =
        serde_json::from_slice(&store.get(&index_key).await.unwrap().unwrap().value).unwrap();
    let certificate_key = keys.certificate(&certificate_id);
    let mut forged: AuthorityScopePublicationCertificate =
        serde_json::from_slice(&store.get(&certificate_key).await.unwrap().unwrap().value).unwrap();
    forged.global_fence_sequence = prepare.reservation.fence_sequence_at_prepare + 2;
    forged.completion_digest = forged.recompute_completion_digest().unwrap();
    forged.sign(&signer_key).unwrap();
    store
        .execute(StoreTxn::new().with_op(StoreOp::Put {
            key: certificate_key,
            value: serde_json::to_vec(&forged).unwrap(),
        }))
        .await
        .unwrap();
    assert!(matches!(
        reconcile(&service, &reservation_id).await,
        Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::ScopeMismatch
        ))
    ));
    assert!(matches!(
        operator_close(&service, &reservation_id, "foreign frontier").await,
        Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::ScopeMismatch
        ))
    ));
}
