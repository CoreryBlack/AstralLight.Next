//! Eligibility completion behavior contract, exercised through the real
//! service and the leader-fenced in-memory CAS implementation.

use super::*;
use astral_types::{
    AuthorityEligibilityCardCompletion, AuthorityEligibilityCompletionEvidence,
    AuthorityEligibilityCompletionRequest, AuthorityProtocolScope, AuthorityRetainedStagedEvidence,
    GlobalAuthorityFrontier,
};

fn completion_evidence() -> AuthorityEligibilityCompletionEvidence {
    AuthorityEligibilityCompletionEvidence {
        zero_card_selection: None,
        cards: vec![AuthorityEligibilityCardCompletion {
            scope: AuthorityProtocolScope::Card(astral_types::AuthorizationAuthorityScope {
                tenant_id: 7,
                card_id: 17,
                user_id: None,
                domain: AuthorizationDomainScope::Any,
            }),
            generation: 4,
            revoke_watermark: 2,
            outbox_event_id: "elig-outbox-1".to_owned(),
            message_id: "elig-message-1".to_owned(),
        }],
    }
}

fn retained_evidence(
    completion: &AuthorityEligibilityCompletionEvidence,
) -> AuthorityRetainedStagedEvidence {
    let envelope = completion
        .to_staged_envelope(serde_json::json!({
            "targets": [{"tenantId": 7, "cardId": 17}],
            "receipts": [{"receiptId": "identity-receipt-1"}],
            "audit": {"eventId": "event-1"},
            "fanout": [{"messageId": "elig-message-1"}]
        }))
        .unwrap();
    AuthorityRetainedStagedEvidence::new(serde_json::to_string(&envelope).unwrap())
}

#[tokio::test]
async fn exact_eligibility_completion_is_atomic_terminal_and_replay_is_read_only() {
    let mut config = test_config();
    config.trusted_sources[0]
        .allowed_operations
        .push("eligibility_completion".to_owned());
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
    let completion = completion_evidence();
    let retained_staged_evidence = retained_evidence(&completion);
    let staged_digest = retained_staged_evidence.canonical_digest().unwrap();
    let commit = service
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
                staged_evidence_digest: staged_digest,
                committed_at: 2_000,
            },
            declared_coverage: None,
        })
        .await
        .unwrap();
    assert!(!commit.read_gate.positive_reads_allowed);

    let request = AuthorityEligibilityCompletionRequest {
        caller: caller(),
        binding: commit.binding,
        completion: completion.clone(),
        retained_staged_evidence: retained_staged_evidence.clone(),
    };
    let completed = service
        .record_eligibility_completion(&request)
        .await
        .unwrap();
    assert_eq!(
        completed.reservation.state,
        astral_types::AuthorityReservationState::Completed
    );
    assert!(completed.read_gate.positive_reads_allowed);
    assert!(completed.reservation.certificate_id.is_none());
    assert!(completed.reservation.certified_scopes.is_empty());
    assert!(store
        .get(&keys.eligibility_completion(&prepare.reservation.reservation_id))
        .await
        .unwrap()
        .is_some());
    assert!(store
        .get(&keys.reservation_certificate(&prepare.reservation.reservation_id, "CARD:7:17:-:ANY"))
        .await
        .unwrap()
        .is_none());
    assert!(store
        .get(&keys.scope_current("CARD:7:17:-:ANY"))
        .await
        .unwrap()
        .is_none());

    let revision_after_completion = store.current_revision();
    let frontier_after_completion: GlobalAuthorityFrontier =
        serde_json::from_slice(&store.get(&keys.frontier()).await.unwrap().unwrap().value).unwrap();

    // Advance authority history with a genuine root-authorized key rotation.
    // Receipt replay must continue to return the exact original frontier.
    let old_state = service.load_verified_state().await.unwrap();
    let root_signing = SigningKey::from_bytes(&[2u8; 32]);
    let next_signing = SigningKey::from_bytes(&[8u8; 32]);
    let new_key = AuthorityRootKey {
        key_id: "signer-next".to_owned(),
        key_epoch: old_state.trust_root.signer_key().unwrap().key_epoch + 1,
        role: AuthorityRootKeyRole::Signer,
        verifying_key_hex: hex::encode(next_signing.verifying_key().as_bytes()),
    };
    let rotation_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut next_root = old_state.trust_root.clone();
    next_root.keys.push(new_key.clone());
    next_root.created_at = rotation_now;
    let next_signer = Arc::new(
        ProtectedAuthoritySigner::from_seed([8u8; 32], "signer-next", &next_root).unwrap(),
    );
    let mut rotation = astral_types::AuthorityKeyRotationCertificate {
        authorization_edition: AUTHORIZATION_EDITION,
        authority_id: old_state.frontier.authority_id.clone(),
        root_id: old_state.trust_root.root_id.clone(),
        previous_key_epoch: old_state.trust_root.root_key().unwrap().key_epoch,
        new_key,
        previous_trust_root_digest: old_state.trust_root.digest().unwrap(),
        new_trust_root_digest: next_root.digest().unwrap(),
        rotation_nonce: "eligibility-replay-rotation".to_owned(),
        issued_at: rotation_now,
        not_before: rotation_now,
        expires_at: rotation_now + 3600,
        signed_by_key_id: String::new(),
        signature: String::new(),
    };
    rotation
        .sign(
            &root_signing,
            old_state.trust_root.root_key().unwrap().key_id.as_str(),
        )
        .unwrap();
    service
        .apply_rotation(&rotation, next_signer)
        .await
        .unwrap();
    let revision_before_replay = store.current_revision();

    let replay = service
        .record_eligibility_completion(&request)
        .await
        .unwrap();
    assert_eq!(replay.receipt, completed.receipt);
    assert_eq!(replay.global_frontier, completed.global_frontier);
    assert!(revision_before_replay > revision_after_completion);
    assert_eq!(store.current_revision(), revision_before_replay);
    let frontier_after_rotation: GlobalAuthorityFrontier =
        serde_json::from_slice(&store.get(&keys.frontier()).await.unwrap().unwrap().value).unwrap();
    assert_ne!(frontier_after_rotation, frontier_after_completion);
    assert_eq!(
        replay.global_frontier, completed.global_frontier,
        "terminal replay must preserve the original frontier after key rotation"
    );
    assert!(store
        .get(&keys.eligibility_completion(&prepare.reservation.reservation_id))
        .await
        .unwrap()
        .is_some());

    let mut substituted = request.clone();
    substituted.completion.cards[0].generation += 1;
    assert!(service
        .record_eligibility_completion(&substituted)
        .await
        .is_err());
    assert_eq!(store.current_revision(), revision_before_replay);
}

#[tokio::test]
async fn eligibility_completion_requires_explicit_source_capability() {
    // The default test source may prepare and commit, but lacks the dedicated
    // eligibility_completion capability. A fully formed request must still be
    // denied before any terminal receipt is written.
    let config = test_config();
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
    let completion = completion_evidence();
    let retained = retained_evidence(&completion);
    let commit = service
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
                staged_evidence_digest: retained.canonical_digest().unwrap(),
                committed_at: 2_000,
            },
            declared_coverage: None,
        })
        .await
        .unwrap();
    let request = AuthorityEligibilityCompletionRequest {
        caller: caller(),
        binding: commit.binding,
        completion,
        retained_staged_evidence: retained,
    };

    assert!(matches!(
        service.record_eligibility_completion(&request).await,
        Err(AuthorityServiceError::NotAuthorized {
            operation: "eligibility_completion",
            ..
        })
    ));
    assert!(store
        .get(&keys.eligibility_completion(&prepare.reservation.reservation_id))
        .await
        .unwrap()
        .is_none());
}
