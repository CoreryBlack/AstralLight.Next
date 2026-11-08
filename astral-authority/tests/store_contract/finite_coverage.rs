use super::*;
use astral_types::{AuthorityReservationState, AuthorityStagedScopeCoverage};

fn finite_config(enabled: bool, capability: bool) -> AuthorityServiceConfig {
    let mut config = test_config();
    config.policy.exact_scope_coverage_enabled = enabled;
    if capability {
        config.trusted_sources[0]
            .allowed_operations
            .push("commit_finite_coverage".into());
    }
    config
}

/// Bind the fixture service to the LIVE leadership term of the shared store:
/// join the existing lease-backed leader record when one is present (the
/// first service created it), otherwise seed a real one. Binding goes through
/// the production `bind_leadership_token` readback in both cases; raising
/// only the liveness flag would no longer authorize any mutation (§15.9.1).
async fn seed_or_join_fixture_leadership(
    service: &AuthorityService,
    store: &std::sync::Arc<MemoryAuthorityStore>,
) {
    let authority = service.config().quorum.authority_name.clone();
    let key = leader_key(&service.config().quorum.key_prefix, &authority);
    let value = if let Some(record) = store.get(&key).await.unwrap() {
        record.value
    } else {
        let lease = store.grant_lease(service.config().quorum.lease_ttl_seconds);
        let value =
            LeadershipTokenRecord::new(&authority, "finite-coverage-fixture", lease).encode();
        assert!(
            store.try_acquire_leader_key(&key, lease, &value),
            "fixture leader key must be free before acquisition"
        );
        value
    };
    let token = LeadershipToken::from_durable_bytes(key, value);
    service.bind_leadership_token(&token).await.unwrap();
}

/// A second authority service over the SAME durable store, with the source
/// capability optionally removed: the close decision must re-check the
/// CURRENT configuration, never the right stored at commit time.
async fn second_service(
    store: &std::sync::Arc<MemoryAuthorityStore>,
    capability: bool,
) -> AuthorityService {
    let (trust_root, _signer_key, _genesis_key) = test_trust_root();
    let signer = std::sync::Arc::new(
        astral_authority::signing::ProtectedAuthoritySigner::from_seed(
            [7u8; 32],
            "signer-test",
            &trust_root,
        )
        .unwrap(),
    );
    let service = astral_authority::service::AuthorityService::new(
        finite_config(true, capability),
        store.clone(),
        signer,
    );
    seed_or_join_fixture_leadership(&service, store).await;
    service
}

/// Seed one admission proof whose RECEIPT carries the given mutation kind
/// (the proof itself is kind-free; the intent must match the receipt).
async fn seed_operation_proof_with_kind(
    store: &MemoryAuthorityStore,
    keys: &KeyLayout,
    signer_key: &SigningKey,
    op: &OperationFixture,
    authority_term: u64,
    global_fence_sequence: u64,
    mutation_kind: astral_types::AuthorityMutationKind,
) {
    let mut proof = AuthorizationFenceProof {
        authorization_edition: AUTHORIZATION_EDITION,
        authority_id: "authority-test".to_owned(),
        authority_term,
        global_fence_sequence,
        scope: astral_types::AuthorizationAuthorityScope {
            tenant_id: 7,
            card_id: 17,
            user_id: None,
            domain: AuthorizationDomainScope::Any,
        },
        scope_generation: 1,
        revoke_watermark: 0,
        snapshot_hash: "bb".repeat(32),
        parent_hash: None,
        operation_id: op.operation_id.to_owned(),
        event_id: op.event_id.to_owned(),
        key_id: "signer-test".to_owned(),
        key_epoch: 1,
        issued_at: 1_700_000_000,
        not_before: 1_700_000_000,
        expires_at: 4_000_000_000,
        request_nonce: format!("seed-nonce-{}", op.admission_proof_id),
        proof_id: op.admission_proof_id.to_owned(),
        scope_certificate_hash: None,
        request_binding_digest: Some(op.request_digest.clone()),
        signature: String::new(),
    };
    let bytes = proof.signing_bytes().unwrap();
    proof.signature = hex::encode(signer_key.sign(&bytes).to_bytes());
    let receipt = StoredProofReceipt {
        proof_id: op.admission_proof_id.to_owned(),
        request_nonce: proof.request_nonce.clone(),
        request_binding_digest: op.request_digest.clone(),
        mutation_kind,
        operation_id: op.operation_id.to_owned(),
        event_id: op.event_id.to_owned(),
        caller_service_id: SERVICE_ID.to_owned(),
        actor_scope_key: "CARD:7:17:-:ANY".to_owned(),
        source_scope_key: "CARD:7:17:-:ANY".to_owned(),
        authority_term,
        global_fence_sequence,
        key_epoch: 1,
        issued_at: 1_700_000_000,
        expires_at: 4_000_000_000,
    };
    let outcome = store
        .execute(
            StoreTxn::new()
                .with_op(StoreOp::PutIfAbsent {
                    key: keys.proof_receipt(op.admission_proof_id),
                    value: serde_json::to_vec(&proof).unwrap(),
                })
                .with_op(StoreOp::PutIfAbsent {
                    key: keys.proof_binding(op.admission_proof_id),
                    value: serde_json::to_vec(&receipt).unwrap(),
                }),
        )
        .await
        .unwrap();
    assert!(matches!(
        outcome,
        astral_authority::store::StoreTxnOutcome::Applied { .. }
    ));
}

#[tokio::test]
async fn global_finite_coverage_closes_only_after_every_approved_publication() {
    let (service, store, keys, signing) = test_service_with_config(finite_config(true, true)).await;
    let op = op_one();
    seed_operation_proof(&store, &keys, &signing, &op, 1, 1).await;
    let prepared = service
        .prepare_source_mutation(&AuthorityPrepareRequest {
            caller: caller(),
            intent: op_intent(&op, AuthorityReservationCoverage::Global),
        })
        .await
        .unwrap();
    let first_scope = card_scope();
    let mut second_scope = first_scope.clone();
    if let AuthorityProtocolScope::Card(card) = &mut second_scope {
        card.card_id += 1;
    }
    let committed = service
        .record_source_commit(&op_commit_request(
            &op,
            &prepared.reservation,
            Some(AuthorityStagedScopeCoverage {
                scopes: vec![first_scope.clone(), second_scope.clone()],
            }),
        ))
        .await
        .unwrap();
    assert!(committed.read_gate.global_pending);
    assert_eq!(
        committed.reservation.as_ref().unwrap().intent,
        prepared.reservation.intent
    );
    let mut outsider = first_scope.clone();
    if let AuthorityProtocolScope::Card(card) = &mut outsider {
        card.tenant_id += 1;
    }
    assert!(matches!(
        service
            .certify_publication(&op_certify_request(
                &op,
                &prepared.reservation,
                None,
                outsider,
            ))
            .await,
        Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::ScopeMismatch
        ))
    ));
    let first = service
        .certify_publication(&op_certify_request(
            &op,
            &prepared.reservation,
            None,
            first_scope,
        ))
        .await
        .unwrap();
    assert_eq!(
        first.reservation.state,
        AuthorityReservationState::Published
    );
    assert!(first.read_gate.global_pending);
    assert_eq!(first.reservation.intent, prepared.reservation.intent);
    let last = service
        .certify_publication(&op_certify_request(
            &op,
            &prepared.reservation,
            None,
            second_scope,
        ))
        .await
        .unwrap();
    assert_eq!(last.reservation.state, AuthorityReservationState::Certified);
    assert!(!last.read_gate.global_pending);
    assert!(last.read_gate.positive_reads_allowed);
    assert_eq!(last.reservation.intent, prepared.reservation.intent);
    let reconciled = service
        .reconcile_reservation(&AuthorityReconcileRequest {
            caller: caller(),
            reservation_id: prepared.reservation.reservation_id.clone(),
            operation_id: op.operation_id.into(),
        })
        .await
        .unwrap();
    reconciled.validate().unwrap();
    assert_eq!(reconciled.certified_publications.len(), 2);
    let replay = service
        .certify_publication(&op_certify_request(
            &op,
            &prepared.reservation,
            None,
            last.certificate.scope.clone(),
        ))
        .await
        .unwrap();
    assert_eq!(replay.certificate, last.certificate);
    assert_eq!(replay.global_frontier, last.global_frontier);
}

#[tokio::test]
async fn global_finite_closure_requires_both_policy_and_explicit_source_capability() {
    for (enabled, capability, declare) in [
        (false, true, true),
        (true, false, true),
        (true, true, false),
    ] {
        let (service, store, keys, signing) =
            test_service_with_config(finite_config(enabled, capability)).await;
        let op = op_one();
        seed_operation_proof(&store, &keys, &signing, &op, 1, 1).await;
        let prepared = service
            .prepare_source_mutation(&AuthorityPrepareRequest {
                caller: caller(),
                intent: op_intent(&op, AuthorityReservationCoverage::Global),
            })
            .await
            .unwrap();
        service
            .record_source_commit(&op_commit_request(
                &op,
                &prepared.reservation,
                declare.then(|| AuthorityStagedScopeCoverage {
                    scopes: vec![card_scope()],
                }),
            ))
            .await
            .unwrap();
        let certified = service
            .certify_publication(&op_certify_request(
                &op,
                &prepared.reservation,
                None,
                card_scope(),
            ))
            .await
            .unwrap();
        assert_eq!(
            certified.reservation.state,
            AuthorityReservationState::Published
        );
        assert!(certified.read_gate.global_pending);
        assert!(!certified.read_gate.positive_reads_allowed);
    }
}

#[tokio::test]
async fn commit_coverage_rejects_missing_records_and_binding_substitution() {
    for corrupt_binding in [false, true] {
        let (service, store, keys, signing) =
            test_service_with_config(finite_config(true, true)).await;
        let op = op_one();
        seed_operation_proof(&store, &keys, &signing, &op, 1, 1).await;
        let prepared = service
            .prepare_source_mutation(&AuthorityPrepareRequest {
                caller: caller(),
                intent: op_intent(&op, AuthorityReservationCoverage::Global),
            })
            .await
            .unwrap();
        service
            .record_source_commit(&op_commit_request(
                &op,
                &prepared.reservation,
                Some(AuthorityStagedScopeCoverage {
                    scopes: vec![card_scope()],
                }),
            ))
            .await
            .unwrap();
        let key = keys.commit_coverage(&prepared.reservation.reservation_id);
        let record = store.get(&key).await.unwrap().unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&record.value).unwrap();
        if corrupt_binding {
            value["binding"]["stagedEvidenceDigest"] = serde_json::json!("ff".repeat(32));
        } else {
            value = serde_json::Value::Null;
        }
        store
            .execute(StoreTxn::new().with_op(StoreOp::ReplaceIfRevision {
                key,
                expected_revision: record.revision,
                value: serde_json::to_vec(&value).unwrap(),
            }))
            .await
            .unwrap();
        assert!(service
            .certify_publication(&op_certify_request(
                &op,
                &prepared.reservation,
                None,
                card_scope(),
            ))
            .await
            .is_err());
        let gate = service
            .read_fence(&AuthorityFenceReadRequest {
                caller: caller(),
                scope: None,
                expected_certificate_hash: None,
                read_proof: None,
            })
            .await
            .unwrap()
            .read_gate;
        assert!(gate.global_pending);
    }
}

#[tokio::test]
async fn global_finite_close_refuses_when_capability_removed_after_commit() {
    let (service, store, keys, signing) = test_service_with_config(finite_config(true, true)).await;
    let op = op_one();
    seed_operation_proof(&store, &keys, &signing, &op, 1, 1).await;
    let prepared = service
        .prepare_source_mutation(&AuthorityPrepareRequest {
            caller: caller(),
            intent: op_intent(&op, AuthorityReservationCoverage::Global),
        })
        .await
        .unwrap();
    service
        .record_source_commit(&op_commit_request(
            &op,
            &prepared.reservation,
            Some(AuthorityStagedScopeCoverage {
                scopes: vec![card_scope()],
            }),
        ))
        .await
        .unwrap();
    // The same durable store, but the source capability has been removed:
    // the stored automatic-closure right must not survive the removal.
    let stripped = second_service(&store, false).await;
    let certified = stripped
        .certify_publication(&op_certify_request(
            &op,
            &prepared.reservation,
            None,
            card_scope(),
        ))
        .await
        .unwrap();
    assert_eq!(
        certified.reservation.state,
        AuthorityReservationState::Published
    );
    assert!(certified.read_gate.global_pending);
    assert!(!certified.read_gate.positive_reads_allowed);
    // The original service is equally refused on replay: the close-time
    // check re-reads the CURRENT configuration.
    let replay = service
        .certify_publication(&op_certify_request(
            &op,
            &prepared.reservation,
            None,
            card_scope(),
        ))
        .await
        .unwrap();
    assert_eq!(
        replay.reservation.state,
        AuthorityReservationState::Published
    );
    assert!(replay.read_gate.global_pending);
}

#[tokio::test]
async fn global_finite_close_refuses_when_historical_certificate_is_missing_or_drifted() {
    for corrupt_record in [false, true] {
        let (service, store, keys, signing) =
            test_service_with_config(finite_config(true, true)).await;
        let op = op_one();
        seed_operation_proof(&store, &keys, &signing, &op, 1, 1).await;
        let prepared = service
            .prepare_source_mutation(&AuthorityPrepareRequest {
                caller: caller(),
                intent: op_intent(&op, AuthorityReservationCoverage::Global),
            })
            .await
            .unwrap();
        let first_scope = card_scope();
        let mut second_scope = first_scope.clone();
        if let AuthorityProtocolScope::Card(card) = &mut second_scope {
            card.card_id += 1;
        }
        service
            .record_source_commit(&op_commit_request(
                &op,
                &prepared.reservation,
                Some(AuthorityStagedScopeCoverage {
                    scopes: vec![first_scope.clone(), second_scope.clone()],
                }),
            ))
            .await
            .unwrap();
        let first = service
            .certify_publication(&op_certify_request(
                &op,
                &prepared.reservation,
                None,
                first_scope.clone(),
            ))
            .await
            .unwrap();
        assert_eq!(
            first.reservation.state,
            AuthorityReservationState::Published
        );
        let certificate_key = keys.certificate(&first.certificate.certificate_id);
        let index_key = keys.reservation_certificate(
            &prepared.reservation.reservation_id,
            &first_scope.store_key_text().unwrap(),
        );
        if corrupt_record {
            // Drift the immutable record: the signature no longer verifies.
            let record = store.get(&certificate_key).await.unwrap().unwrap();
            let mut value: serde_json::Value = serde_json::from_slice(&record.value).unwrap();
            value["signature"] = serde_json::json!("ff".repeat(64));
            store
                .execute(StoreTxn::new().with_op(StoreOp::ReplaceIfRevision {
                    key: certificate_key,
                    expected_revision: record.revision,
                    value: serde_json::to_vec(&value).unwrap(),
                }))
                .await
                .unwrap();
            // A drifted historical certificate is a loud error: the certify
            // refuses instead of closing over unknown evidence.
            assert!(service
                .certify_publication(&op_certify_request(
                    &op,
                    &prepared.reservation,
                    None,
                    second_scope.clone(),
                ))
                .await
                .is_err());
        } else {
            // Remove the historical index entry: the declared scope is no
            // longer proven, so the close is refused and the barrier stays
            // up — the certify itself (a new publication) still lands.
            store
                .execute(StoreTxn::new().with_op(StoreOp::Delete { key: index_key }))
                .await
                .unwrap();
            let last = service
                .certify_publication(&op_certify_request(
                    &op,
                    &prepared.reservation,
                    None,
                    second_scope.clone(),
                ))
                .await
                .unwrap();
            assert_eq!(last.reservation.state, AuthorityReservationState::Published);
            assert!(last.read_gate.global_pending);
            assert!(!last.read_gate.positive_reads_allowed);
        }
        // Either way the global barrier never opens.
        let gate = service
            .read_fence(&AuthorityFenceReadRequest {
                caller: caller(),
                scope: None,
                expected_certificate_hash: None,
                read_proof: None,
            })
            .await
            .unwrap()
            .read_gate;
        assert!(gate.global_pending);
        assert!(!gate.positive_reads_allowed);
    }
}

#[tokio::test]
async fn protected_business_commit_may_not_declare_coverage() {
    let (service, store, keys, signing) = test_service_with_config(finite_config(true, true)).await;
    let op = op_one();
    seed_operation_proof_with_kind(
        &store,
        &keys,
        &signing,
        &op,
        1,
        1,
        astral_types::AuthorityMutationKind::ProtectedBusiness,
    )
    .await;
    let mut intent = op_intent(&op, AuthorityReservationCoverage::Global);
    intent.mutation_kind = astral_types::AuthorityMutationKind::ProtectedBusiness;
    let prepared = service
        .prepare_source_mutation(&AuthorityPrepareRequest {
            caller: caller(),
            intent,
        })
        .await
        .unwrap();
    // A ProtectedBusiness mutation may never declare a finite coverage.
    assert!(matches!(
        service
            .record_source_commit(&op_commit_request(
                &op,
                &prepared.reservation,
                Some(AuthorityStagedScopeCoverage {
                    scopes: vec![card_scope()],
                }),
            ))
            .await,
        Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::InvalidCoverage
        ))
    ));
    // Without a declaration the commit proceeds; no finite coverage exists,
    // so no automatic close is ever recorded for it.
    let committed = service
        .record_source_commit(&op_commit_request(&op, &prepared.reservation, None))
        .await
        .unwrap();
    assert_eq!(
        committed.reservation.as_ref().unwrap().state,
        AuthorityReservationState::Committed
    );
}

/// A second authority service over the SAME durable store whose CURRENT
/// source registration is stripped: the commit gate re-checks registration
/// against the live configuration, while the stable identity preconditions
/// (intent service/database ids) still bind the request unchanged.
async fn service_with_stripped_source_registration(
    store: &std::sync::Arc<MemoryAuthorityStore>,
    keep_source: bool,
    keep_database: bool,
) -> AuthorityService {
    let (trust_root, _signer_key, _genesis_key) = test_trust_root();
    let signer = std::sync::Arc::new(
        astral_authority::signing::ProtectedAuthoritySigner::from_seed(
            [7u8; 32],
            "signer-test",
            &trust_root,
        )
        .unwrap(),
    );
    let mut config = finite_config(true, true);
    let source = config
        .trusted_sources
        .iter_mut()
        .find(|source| source.service_id == SERVICE_ID)
        .unwrap();
    if keep_database {
        source.allowed_database_ids = vec![DATABASE_ID.to_owned()];
    } else {
        source.allowed_database_ids = Vec::new();
    }
    if !keep_source {
        config
            .trusted_sources
            .retain(|source| source.service_id != SERVICE_ID);
    }
    let service = astral_authority::service::AuthorityService::new(config, store.clone(), signer);
    seed_or_join_fixture_leadership(&service, store).await;
    service
}

#[tokio::test]
async fn commit_coverage_requires_registered_source_and_database() {
    // Prepared under the fully registered configuration; the commit is then
    // presented to services whose CURRENT registration no longer matches.
    // The request stays identity-bound (intent service/database ids
    // unchanged), so the stable-identity preconditions pass and the
    // source_commit_coverage registration gate is what refuses.
    let (service, store, keys, signing) = test_service_with_config(finite_config(true, true)).await;
    let op = op_one();
    seed_operation_proof(&store, &keys, &signing, &op, 1, 1).await;
    let prepared = service
        .prepare_source_mutation(&AuthorityPrepareRequest {
            caller: caller(),
            intent: op_intent(&op, AuthorityReservationCoverage::Global),
        })
        .await
        .unwrap();

    // (a) The source is still registered but no longer for this database.
    let unregistered_database =
        service_with_stripped_source_registration(&store, true, false).await;
    assert!(matches!(
        unregistered_database
            .record_source_commit(&op_commit_request(&op, &prepared.reservation, None,))
            .await,
        Err(AuthorityServiceError::NotAuthorized { .. })
    ));

    // (b) The source registration is gone entirely: the caller check inside
    // source_commit_coverage refuses before any durable write.
    let unregistered_source = service_with_stripped_source_registration(&store, false, true).await;
    assert!(matches!(
        unregistered_source
            .record_source_commit(&op_commit_request(&op, &prepared.reservation, None,))
            .await,
        Err(AuthorityServiceError::NotAuthorized { .. })
    ));

    // The fully registered service still commits: both refusals were scoped
    // to the current registration, not to the durable reservation.
    let committed = service
        .record_source_commit(&op_commit_request(&op, &prepared.reservation, None))
        .await
        .unwrap();
    assert_eq!(
        committed.reservation.as_ref().unwrap().state,
        AuthorityReservationState::Committed
    );
}
