//! CONFIG_COMPLETION V7 contract against the real authority service and memory store.
//!
//! This path proves a committed non-grant configuration mutation without
//! manufacturing a grant certificate or a scope-current pointer. The tests
//! retain the exact source images, audit correlation, and binding supplied by
//! the source owner, then exercise terminal replay and rejection boundaries.

use super::*;
use astral_types::{
    config_image_digests, config_source_commit_digest, AuthorityCommitRequest,
    AuthorityConfigAudit, AuthorityConfigCompletionEvidence, AuthorityConfigCompletionKind,
    AuthorityConfigGateContract, AuthorityConfigSourceBatch, AuthorityConfigSourceImage,
    AuthorityConfigSourceLookup, AuthorityConfigSourceOperation, AuthorityConfigSourceTable,
    AuthorityRetainedStagedEvidence, AuthoritySourceCommitRecord, AuthorityStagedSourceEvidence,
    GlobalAuthorityFrontier,
};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

fn digest(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn group_image(id: i64, name: &str) -> String {
    format!(
        "{{\"id\":{id},\"name\":\"{name}\",\"description\":null,\"scope\":null,\"created_at\":null}}"
    )
}

fn completion(operation_id: &str) -> AuthorityConfigCompletionEvidence {
    let before = group_image(7, "before");
    let after = group_image(7, "after");
    AuthorityConfigCompletionEvidence {
        kind: AuthorityConfigCompletionKind::ConfigCompletion,
        gate_contract: AuthorityConfigGateContract::DurableConfigV7,
        source_batch: AuthorityConfigSourceBatch {
            delta: None,
            source_images: vec![AuthorityConfigSourceImage {
                table: AuthorityConfigSourceTable::AdminGroup,
                key: 7,
                lookup: serde_json::to_string(&AuthorityConfigSourceLookup::PrimaryId { id: 7 })
                    .unwrap(),
                operation: AuthorityConfigSourceOperation::Update,
                before_image_digest: digest(&before),
                after_image_digest: digest(&after),
                before_image: before,
                after_image: after,
            }],
            audits: vec![AuthorityConfigAudit {
                audit_log_id: 7,
                user_id: 3,
                action: "UPDATE".to_owned(),
                resource: "admin-group".to_owned(),
                decision: "ALLOW".to_owned(),
                event_type: "CONFIG_MUTATION".to_owned(),
                request_id: Some(operation_id.to_owned()),
            }],
            source_projection: Vec::new(),
            invalidations: Vec::new(),
        },
    }
}

fn retained(completion: &AuthorityConfigCompletionEvidence) -> AuthorityRetainedStagedEvidence {
    let envelope = AuthorityStagedSourceEvidence {
        coverage: None,
        evidence: serde_json::to_value(completion).unwrap(),
    };
    AuthorityRetainedStagedEvidence::new(serde_json::to_string(&envelope).unwrap())
}

fn config_test_config() -> astral_authority::config::AuthorityServiceConfig {
    let mut config = test_config();
    config.trusted_sources[0]
        .allowed_operations
        .push("config_completion".to_owned());
    config
}

async fn committed_config_request(
    config: astral_authority::config::AuthorityServiceConfig,
) -> (
    AuthorityService,
    Arc<MemoryAuthorityStore>,
    KeyLayout,
    astral_types::AuthorityConfigCompletionRequest,
) {
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
    let completion = completion(OPERATION_ID);
    let retained = retained(&completion);
    let (before_image_digest, after_image_digest) =
        config_image_digests(&completion.source_batch.source_images).unwrap();
    let source_commit_digest = config_source_commit_digest(&completion).unwrap();
    let commit = service
        .record_source_commit(&AuthorityCommitRequest {
            caller: caller(),
            database_id: DATABASE_ID.to_owned(),
            commit: AuthoritySourceCommitRecord {
                reservation_id: prepare.reservation.reservation_id.clone(),
                operation_id: OPERATION_ID.to_owned(),
                source_commit_digest,
                before_image_digest: Some(before_image_digest),
                after_image_digest,
                source_outcome_digest: "99".repeat(32),
                staged_evidence_digest: retained.canonical_digest().unwrap(),
                committed_at: 2_000,
            },
            declared_coverage: None,
        })
        .await
        .unwrap();
    (
        service,
        store,
        keys,
        astral_types::AuthorityConfigCompletionRequest {
            caller: caller(),
            binding: commit.binding,
            completion,
            retained_staged_evidence: retained,
        },
    )
}

#[tokio::test]
async fn config_completion_is_terminal_without_grant_publication_and_replay_is_read_only() {
    let (service, store, keys, request) = committed_config_request(config_test_config()).await;
    let completed = service.record_config_completion(&request).await.unwrap();

    assert_eq!(
        completed.reservation.state,
        astral_types::AuthorityReservationState::Completed
    );
    assert!(completed.read_gate.positive_reads_allowed);
    assert!(completed.reservation.certificate_id.is_none());
    assert!(completed.reservation.certified_scopes.is_empty());
    assert!(store
        .get(&keys.config_completion(&request.binding.reservation_id))
        .await
        .unwrap()
        .is_some());
    assert!(store
        .get(&keys.reservation_certificate(&request.binding.reservation_id, "CARD:7:17:-:ANY"))
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

    let old_state = service.load_verified_state().await.unwrap();
    let root_signing = SigningKey::from_bytes(&[2u8; 32]);
    let next_signing = SigningKey::from_bytes(&[8u8; 32]);
    let new_key = AuthorityRootKey {
        key_id: "signer-config-next".to_owned(),
        key_epoch: old_state.trust_root.signer_key().unwrap().key_epoch + 1,
        role: AuthorityRootKeyRole::Signer,
        verifying_key_hex: hex::encode(next_signing.verifying_key().as_bytes()),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut next_root = old_state.trust_root.clone();
    next_root.keys.push(new_key.clone());
    next_root.created_at = now;
    let next_signer = Arc::new(
        ProtectedAuthoritySigner::from_seed([8u8; 32], "signer-config-next", &next_root).unwrap(),
    );
    let mut rotation = astral_types::AuthorityKeyRotationCertificate {
        authorization_edition: AUTHORIZATION_EDITION,
        authority_id: old_state.frontier.authority_id.clone(),
        root_id: old_state.trust_root.root_id.clone(),
        previous_key_epoch: old_state.trust_root.root_key().unwrap().key_epoch,
        new_key,
        previous_trust_root_digest: old_state.trust_root.digest().unwrap(),
        new_trust_root_digest: next_root.digest().unwrap(),
        rotation_nonce: "config-completion-rotation".to_owned(),
        issued_at: now,
        not_before: now,
        expires_at: now + 3_600,
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
    let rotated_state = service.load_verified_state().await.unwrap();
    assert_eq!(rotated_state.rotations.len(), 1);
    assert_eq!(
        rotated_state.rotations[0].new_key.key_id,
        "signer-config-next"
    );
    assert!(rotated_state.trust_root.key_by_id("signer-test").is_some());
    assert_eq!(rotated_state.frontier.key_epoch, 2);
    let revision_before_replay = store.current_revision();

    let replay = service.record_config_completion(&request).await.unwrap();
    assert_eq!(replay.receipt, completed.receipt);
    assert_eq!(replay.global_frontier, completed.global_frontier);
    assert_eq!(replay.global_frontier, frontier_after_completion);
    assert!(revision_before_replay > revision_after_completion);
    assert_eq!(store.current_revision(), revision_before_replay);
}

#[tokio::test]
async fn config_completion_rejects_binding_retained_audit_and_registration_mismatches() {
    let (service, store, keys, request) = committed_config_request(config_test_config()).await;
    let before = store.current_revision();

    let mut wrong_binding = request.clone();
    wrong_binding.binding.source_commit_digest = "ab".repeat(32);
    assert!(service
        .record_config_completion(&wrong_binding)
        .await
        .is_err());
    assert_eq!(store.current_revision(), before);

    let mut wrong_before = request.clone();
    wrong_before.binding.before_image_digest = Some("ab".repeat(32));
    assert!(service
        .record_config_completion(&wrong_before)
        .await
        .is_err());
    assert_eq!(store.current_revision(), before);

    let mut wrong_after = request.clone();
    wrong_after.binding.after_image_digest = "ab".repeat(32);
    assert!(service
        .record_config_completion(&wrong_after)
        .await
        .is_err());
    assert_eq!(store.current_revision(), before);

    let mut wrong_retained = request.clone();
    wrong_retained.retained_staged_evidence = AuthorityRetainedStagedEvidence::new(
        wrong_retained
            .retained_staged_evidence
            .as_str()
            .replace("after", "drifted"),
    );
    assert!(service
        .record_config_completion(&wrong_retained)
        .await
        .is_err());
    assert_eq!(store.current_revision(), before);

    let mut wrong_audit = request.clone();
    wrong_audit.completion.source_batch.audits[0].action = "DELETE".to_owned();
    wrong_audit.retained_staged_evidence = retained(&wrong_audit.completion);
    assert!(service
        .record_config_completion(&wrong_audit)
        .await
        .is_err());
    assert_eq!(store.current_revision(), before);

    let mut wrong_database = request.clone();
    wrong_database.binding.database_id = "db-unregistered".to_owned();
    assert!(service
        .record_config_completion(&wrong_database)
        .await
        .is_err());
    assert_eq!(store.current_revision(), before);
    assert!(store
        .get(&keys.config_completion(&request.binding.reservation_id))
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn config_completion_requires_explicit_capability() {
    let config = test_config();
    let (service, store, keys, request) = committed_config_request(config).await;
    assert!(matches!(
        service.record_config_completion(&request).await,
        Err(AuthorityServiceError::NotAuthorized {
            operation: "config_completion",
            ..
        })
    ));
    assert!(store
        .get(&keys.config_completion(&request.binding.reservation_id))
        .await
        .unwrap()
        .is_none());
}
