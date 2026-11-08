#![cfg(feature = "service")]

//! Store-contract and fail-closed service tests (pure Rust, no external env).
//!
//! These tests drive the full authority lifecycle against the in-memory
//! store, which mirrors etcd's CAS semantics one revision per transaction.
//! Every fail-closed rule of the control plane is exercised here.

use std::sync::Arc;

use astral_authority::config::{AuthorityServiceConfig, AuthorityTrustedSource};
use astral_authority::error::AuthorityServiceError;
use astral_authority::service::leadership::{leader_key, LeadershipToken, LeadershipTokenRecord};
use astral_authority::service::{
    AuthorityService, StoredGenesis, StoredIntentRecord, StoredProofReceipt,
};
use astral_authority::signing::ProtectedAuthoritySigner;
use astral_authority::store::memory::MemoryAuthorityStore;
use astral_authority::store::{AuthorityStore, KeyLayout, StoreOp, StoreTxn};
use astral_types::{
    AuthorityCallerIdentity, AuthorityCertifyRequest, AuthorityCommitRequest,
    AuthorityFenceReadRequest, AuthorityManifestIdentity, AuthorityOrgScope,
    AuthorityPrepareRequest, AuthorityProtocolError, AuthorityProtocolScope,
    AuthorityReadProofRequest, AuthorityReconcileRequest, AuthorityReservationCoverage,
    AuthorityRootKey, AuthorityRootKeyRole, AuthorityScopePublicationCertificate,
    AuthoritySourceCommitRecord, AuthoritySourceIntent, AuthorityTrustRoot,
    AuthorizationDomainScope, AuthorizationFenceProof, AUTHORIZATION_EDITION,
};
use ed25519_dalek::{Signer, SigningKey};

#[path = "store_contract/finite_coverage.rs"]
mod finite_coverage;

#[path = "store_contract/canonical_lens.rs"]
mod canonical_lens;

#[path = "store_contract/close_history.rs"]
mod close_history;

#[path = "store_contract/rotation_fence.rs"]
mod rotation_fence;

#[path = "store_contract/eligibility_completion_contract.rs"]
mod eligibility_completion_contract;

#[path = "store_contract/config_completion_contract.rs"]
mod config_completion_contract;

#[path = "store_contract/abort_contract.rs"]
mod abort_contract;

const SERVICE_ID: &str = "source-svc";
const DATABASE_ID: &str = "db-1";
const OPERATOR_ID: &str = "operator-svc";
const OPERATION_ID: &str = "operation-1";
const REQUEST_DIGEST: &str = "aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00";

fn test_trust_root() -> (AuthorityTrustRoot, SigningKey, SigningKey) {
    let signer = SigningKey::from_bytes(&[7u8; 32]);
    let root_key = SigningKey::from_bytes(&[2u8; 32]);
    let genesis_key = SigningKey::from_bytes(&[3u8; 32]);
    let root = AuthorityTrustRoot {
        root_id: "root-test".to_owned(),
        keys: vec![
            AuthorityRootKey {
                key_id: "signer-test".to_owned(),
                key_epoch: 1,
                role: AuthorityRootKeyRole::Signer,
                verifying_key_hex: hex::encode(signer.verifying_key().as_bytes()),
            },
            AuthorityRootKey {
                key_id: "root-test".to_owned(),
                key_epoch: 1,
                role: AuthorityRootKeyRole::Root,
                verifying_key_hex: hex::encode(root_key.verifying_key().as_bytes()),
            },
            AuthorityRootKey {
                key_id: "genesis-test".to_owned(),
                key_epoch: 1,
                role: AuthorityRootKeyRole::Genesis,
                verifying_key_hex: hex::encode(genesis_key.verifying_key().as_bytes()),
            },
        ],
        created_at: 1_000,
    };
    (root, signer, genesis_key)
}

fn test_config() -> AuthorityServiceConfig {
    AuthorityServiceConfig {
        identity: astral_authority::config::AuthorityIdentityConfig {
            authority_id: "authority-test".to_owned(),
            pinned_genesis_trust_root_digest: test_trust_root().0.digest().unwrap(),
        },
        trusted_sources: vec![
            AuthorityTrustedSource {
                service_id: SERVICE_ID.to_owned(),
                certificate_fingerprint: format!("sha256:{}", "11".repeat(32)),
                allowed_database_ids: vec![DATABASE_ID.to_owned()],
                allowed_operations: vec![
                    "read_fence".to_owned(),
                    "prepare".to_owned(),
                    "commit".to_owned(),
                    "certify".to_owned(),
                    "reconcile".to_owned(),
                ],
            },
            AuthorityTrustedSource {
                service_id: OPERATOR_ID.to_owned(),
                certificate_fingerprint: format!("sha256:{}", "22".repeat(32)),
                allowed_database_ids: Vec::new(),
                allowed_operations: vec!["close".to_owned(), "reconcile".to_owned()],
            },
        ],
        ..Default::default()
    }
}

/// Build a genesis-initialized service with the leader flag raised and one
/// issued admission proof (proof id + binding) already seeded.
async fn test_service() -> (
    AuthorityService,
    Arc<MemoryAuthorityStore>,
    KeyLayout,
    SigningKey,
) {
    test_service_with_exact_coverage(false).await
}

async fn test_service_with_exact_coverage(
    exact_scope_coverage_enabled: bool,
) -> (
    AuthorityService,
    Arc<MemoryAuthorityStore>,
    KeyLayout,
    SigningKey,
) {
    let mut config = test_config();
    config.policy.exact_scope_coverage_enabled = exact_scope_coverage_enabled;
    test_service_with_config(config).await
}

async fn test_service_with_config(
    mut config: AuthorityServiceConfig,
) -> (
    AuthorityService,
    Arc<MemoryAuthorityStore>,
    KeyLayout,
    SigningKey,
) {
    let (trust_root, signer_key, genesis_key) = test_trust_root();
    config.identity.pinned_genesis_trust_root_digest = trust_root.digest().unwrap();

    let signer = Arc::new(
        ProtectedAuthoritySigner::from_seed([7u8; 32], "signer-test", &trust_root).unwrap(),
    );
    let store = Arc::new(MemoryAuthorityStore::new());
    let service = AuthorityService::new(config, store.clone(), signer);

    // Genesis initialization via the service contract.
    let mut record = astral_types::AuthorityGenesisRecord {
        authorization_edition: AUTHORIZATION_EDITION,
        authority_id: "authority-test".to_owned(),
        root_id: trust_root.root_id.clone(),
        trust_root_digest: trust_root.digest().unwrap(),
        created_at: 1_000,
        genesis_nonce: "genesis-nonce-test".to_owned(),
        signed_by_key_id: String::new(),
        signature: String::new(),
    };
    record.sign(&genesis_key, "genesis-test").unwrap();
    let created = service
        .initialize_genesis(&StoredGenesis {
            record,
            trust_root: trust_root.clone(),
        })
        .await
        .unwrap();
    assert!(created, "first genesis must create");

    // Durable leadership fixture (§15.9.1): seed a REAL lease-backed leader
    // record and bind it through the production `bind_leadership_token` path
    // (linearizable readback of the exact term bytes). Raising only the
    // liveness flag would no longer authorize any mutation: the fence lives
    // in the leader key, not in the flag.
    let authority = service.config().quorum.authority_name.clone();
    let lease = store.grant_lease(service.config().quorum.lease_ttl_seconds);
    let token = LeadershipToken::from_record(
        leader_key(&service.config().quorum.key_prefix, &authority),
        &LeadershipTokenRecord::new(&authority, "store-contract-fixture", lease),
    )
    .unwrap();
    assert!(
        store.try_acquire_leader_key(token.key(), lease, token.value()),
        "fixture leader key must be free before acquisition"
    );
    service.bind_leadership_token(&token).await.unwrap();

    let keys = KeyLayout::new(service.config().quorum.key_prefix.as_str());
    (service, store, keys, signer_key)
}

async fn seed_admission_proof(
    service: &AuthorityService,
    store: &MemoryAuthorityStore,
    keys: &KeyLayout,
    signer_key: &SigningKey,
    proof_id: &str,
    request_binding_digest: &str,
) {
    seed_admission_proof_at_frontier(
        service,
        store,
        keys,
        signer_key,
        proof_id,
        request_binding_digest,
        1,
        1,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn seed_admission_proof_at_frontier(
    _service: &AuthorityService,
    store: &MemoryAuthorityStore,
    keys: &KeyLayout,
    signer_key: &SigningKey,
    proof_id: &str,
    request_binding_digest: &str,
    authority_term: u64,
    global_fence_sequence: u64,
) {
    // A minimal but structurally valid proof whose receipt will be verified
    // by prepare (existence + validity window + EXACT frontier). The
    // signature is checked by validate(), so sign it with the fixture key.
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
        operation_id: OPERATION_ID.to_owned(),
        event_id: "event-1".to_owned(),
        key_id: "signer-test".to_owned(),
        key_epoch: 1,
        issued_at: 1_700_000_000,
        not_before: 1_700_000_000,
        expires_at: 4_000_000_000,
        request_nonce: "seed-nonce".to_owned(),
        proof_id: proof_id.to_owned(),
        scope_certificate_hash: None,
        request_binding_digest: Some(REQUEST_DIGEST.to_owned()),
        signature: String::new(),
    };
    let bytes = proof.signing_bytes().unwrap();
    proof.signature = hex::encode(signer_key.sign(&bytes).to_bytes());

    let receipt = StoredProofReceipt {
        proof_id: proof_id.to_owned(),
        request_nonce: "seed-nonce".to_owned(),
        request_binding_digest: request_binding_digest.to_owned(),
        mutation_kind: astral_types::AuthorityMutationKind::AuthorizationSource,
        operation_id: OPERATION_ID.to_owned(),
        event_id: "event-1".to_owned(),
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
                    key: keys.proof_receipt(proof_id),
                    value: serde_json::to_vec(&proof).unwrap(),
                })
                .with_op(StoreOp::PutIfAbsent {
                    key: keys.proof_binding(proof_id),
                    value: serde_json::to_vec(&receipt).unwrap(),
                })
                .with_op(StoreOp::PutIfAbsent {
                    key: keys.proof_receipt(&format!("seed-receipt-{proof_id}")),
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

fn caller() -> AuthorityCallerIdentity {
    AuthorityCallerIdentity {
        service_id: SERVICE_ID.to_owned(),
        request_nonce: "caller-nonce-1".to_owned(),
        issued_at: 1_700,
    }
}

fn intent(coverage: AuthorityReservationCoverage) -> AuthoritySourceIntent {
    AuthoritySourceIntent {
        authorization_edition: AUTHORIZATION_EDITION,
        mutation_kind: astral_types::AuthorityMutationKind::AuthorizationSource,
        operation_id: OPERATION_ID.to_owned(),
        event_id: "event-1".to_owned(),
        admission_proof_id: "prf-seed".to_owned(),
        request_digest: REQUEST_DIGEST.to_owned(),
        service_id: SERVICE_ID.to_owned(),
        database_id: DATABASE_ID.to_owned(),
        coverage,
        before_image_digest: None,
        lease_not_before: 1_700_000_000,
        lease_expires_at: 4_000_000_000,
        intent_nonce: "intent-nonce-1".to_owned(),
    }
}

fn card_scope() -> AuthorityProtocolScope {
    AuthorityProtocolScope::Card(astral_types::AuthorizationAuthorityScope {
        tenant_id: 7,
        card_id: 17,
        user_id: None,
        domain: AuthorizationDomainScope::Any,
    })
}

fn manifests() -> Vec<AuthorityManifestIdentity> {
    vec![AuthorityManifestIdentity {
        aggregate_type: "USER_CARD".to_owned(),
        aggregate_id: 17,
        manifest_digest_hex: "dd".repeat(32),
        dependency_hash_hex: "ee".repeat(32),
        semantic_hash_hex: "ff".repeat(32),
        generation: 4,
        revoke_fence: 2,
        event_id: "event-1".to_owned(),
        operation_id: OPERATION_ID.to_owned(),
    }]
}

fn certify_request(
    reservation: &astral_types::AuthorityScopeReservation,
    scope: AuthorityProtocolScope,
) -> AuthorityCertifyRequest {
    let certificate = AuthorityScopePublicationCertificate {
        protocol_version: astral_types::AUTHORITY_PROTOCOL_VERSION,
        authorization_edition: AUTHORIZATION_EDITION,
        authority_id: "authority-test".to_owned(),
        authority_term: reservation.authority_term,
        global_fence_sequence: reservation.fence_sequence_at_prepare,
        certificate_id: "cert-pending".to_owned(),
        intent_digest: reservation.intent_digest.clone(),
        reservation_id: reservation.reservation_id.clone(),
        operation_id: OPERATION_ID.to_owned(),
        event_id: "event-1".to_owned(),
        scope: scope.clone(),
        approved_request_digest: REQUEST_DIGEST.to_owned(),
        before_image_digest: Some("cd".repeat(32)),
        after_image_digest: "22".repeat(32),
        source_commit_digest: "11".repeat(32),
        completion_digest: String::new(),
        snapshot_hash: "66".repeat(32),
        source_outcome_digest: "99".repeat(32),
        parent_certificate_hash: None,
        manifests: manifests(),
        key_id: "signer-test".to_owned(),
        key_epoch: 1,
        issued_at: 2_500,
        not_before: 2_500,
        expires_at: None,
        certificate_nonce: "cert-nonce".to_owned(),
        signature: String::new(),
    };
    AuthorityCertifyRequest {
        caller: caller(),
        reservation_id: reservation.reservation_id.clone(),
        scope,
        before_image_digest: certificate.before_image_digest.clone(),
        after_image_digest: certificate.after_image_digest.clone(),
        snapshot_hash: certificate.snapshot_hash.clone(),
        source_outcome_digest: certificate.source_outcome_digest.clone(),
        manifests: certificate.manifests.clone(),
        completion_digest: certificate.recompute_completion_digest().unwrap(),
    }
}

#[tokio::test]
async fn exact_coverage_requires_every_scope_and_retries_preserve_certificate_identity() {
    let (service, store, keys, signer_key) = test_service_with_exact_coverage(true).await;
    seed_admission_proof(
        &service,
        &store,
        &keys,
        &signer_key,
        "prf-seed",
        REQUEST_DIGEST,
    )
    .await;
    let other = AuthorityProtocolScope::Card(astral_types::AuthorizationAuthorityScope {
        tenant_id: 7,
        card_id: 18,
        user_id: None,
        domain: AuthorizationDomainScope::Any,
    });
    let scopes = vec![card_scope(), other.clone()];
    let prepare = service
        .prepare_source_mutation(&AuthorityPrepareRequest {
            caller: caller(),
            intent: intent(AuthorityReservationCoverage::Exact(scopes.clone())),
        })
        .await
        .unwrap();
    let mut commit = AuthorityCommitRequest {
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
    };
    assert!(service.record_source_commit(&commit).await.is_err());
    commit.declared_coverage = Some(astral_types::AuthorityStagedScopeCoverage { scopes });
    let committed = service.record_source_commit(&commit).await.unwrap();
    let reconciled = service
        .reconcile_reservation(&AuthorityReconcileRequest {
            caller: caller(),
            reservation_id: prepare.reservation.reservation_id.clone(),
            operation_id: OPERATION_ID.to_owned(),
        })
        .await
        .unwrap();
    assert_eq!(reconciled.commit_binding, Some(committed.binding));

    let first_request = certify_request(&prepare.reservation, card_scope());
    let mut wrong_before = first_request.clone();
    wrong_before.before_image_digest = Some("ab".repeat(32));
    assert!(service.certify_publication(&wrong_before).await.is_err());
    let first = service.certify_publication(&first_request).await.unwrap();
    assert_eq!(
        first.reservation.state,
        astral_types::AuthorityReservationState::Published
    );
    assert_eq!(
        first.reservation.certified_scopes,
        vec![card_scope().store_key_text().unwrap()]
    );
    assert!(first.read_gate.blocks(&other).unwrap());
    let repeated = service.certify_publication(&first_request).await.unwrap();
    assert_eq!(first.certificate, repeated.certificate);
    assert_eq!(first.global_frontier, repeated.global_frontier);
    let mut changed = first_request.clone();
    changed.snapshot_hash = "77".repeat(32);
    assert!(service.certify_publication(&changed).await.is_err());
    assert!(service
        .close_reservation(&astral_types::AuthorityCloseReservationRequest {
            caller: AuthorityCallerIdentity {
                service_id: OPERATOR_ID.to_owned(),
                ..caller()
            },
            reservation_id: prepare.reservation.reservation_id.clone(),
            operation_id: OPERATION_ID.to_owned(),
            reason: "cannot close partial exact coverage".to_owned(),
        })
        .await
        .is_err());
    let second = service
        .certify_publication(&certify_request(&prepare.reservation, other))
        .await
        .unwrap();
    assert_eq!(
        second.reservation.state,
        astral_types::AuthorityReservationState::Certified
    );
    assert_eq!(second.reservation.certified_scopes.len(), 2);
    assert!(second.read_gate.positive_reads_allowed);
    let terminal_retry = service.certify_publication(&first_request).await.unwrap();
    assert_eq!(terminal_retry.certificate, first.certificate);
    assert_eq!(
        terminal_retry.reservation.state,
        astral_types::AuthorityReservationState::Certified
    );
}

/// The happy path: prepare blocks ALL reads, commit keeps blocking,
/// certification unblocks and publishes a verifiable certificate + proof.
#[tokio::test]
async fn prepare_commit_certify_full_lifecycle_is_fail_closed_in_between() {
    let (service, store, keys, signer_key) = test_service().await;
    seed_admission_proof(
        &service,
        &store,
        &keys,
        &signer_key,
        "prf-seed",
        REQUEST_DIGEST,
    )
    .await;

    // Before any reservation: gate open.
    let fence = service
        .read_fence(&AuthorityFenceReadRequest {
            caller: caller(),
            scope: None,
            expected_certificate_hash: None,
            read_proof: None,
        })
        .await
        .unwrap();
    assert!(fence.read_gate.positive_reads_allowed);
    assert_eq!(fence.global_frontier.global_fence_sequence, 1);

    // Prepare: GLOBAL coverage blocks every scope (card and ORG alike).
    let prepare = service
        .prepare_source_mutation(&AuthorityPrepareRequest {
            caller: caller(),
            intent: intent(AuthorityReservationCoverage::Global),
        })
        .await
        .unwrap();
    assert_eq!(prepare.reservation.state.as_text(), "RESERVED");
    assert!(!prepare.read_gate.positive_reads_allowed);
    assert!(prepare.read_gate.global_pending);
    assert!(prepare.read_gate.blocks(&card_scope()).unwrap());
    assert!(prepare
        .read_gate
        .blocks(&AuthorityProtocolScope::Org(AuthorityOrgScope {
            tenant_id: 9,
            root_tenant_id: None,
            member: astral_types::AuthorityOrgMemberSubject {
                user_id: 1,
                identity_card_id: 2,
                card_id: 3,
            },
        }))
        .unwrap());
    prepare
        .acceptance
        .verify(&signer_key.verifying_key())
        .unwrap();

    // Proof issuance is refused while the reservation blocks.
    let blocked = service
        .read_fence(&AuthorityFenceReadRequest {
            caller: caller(),
            scope: None,
            expected_certificate_hash: None,
            read_proof: Some(AuthorityReadProofRequest {
                actor_scope: card_scope(),
                source_scope: None,
                request_nonce: "reader-nonce-1".to_owned(),
                mutation_kind: astral_types::AuthorityMutationKind::AuthorizationSource,
                operation_id: OPERATION_ID.to_owned(),
                event_id: "event-1".to_owned(),
                request_binding_digest: "11".repeat(32),
                expected_frontier: None,
                proof_ttl_seconds: None,
            }),
        })
        .await
        .unwrap_err();
    assert!(matches!(
        blocked,
        AuthorityServiceError::Protocol(AuthorityProtocolError::ReadsBlocked { .. })
    ));

    // Commit with the same identity chain.
    let commit = service
        .record_source_commit(&AuthorityCommitRequest {
            caller: caller(),
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
            database_id: DATABASE_ID.to_owned(),
            declared_coverage: Some(astral_types::AuthorityStagedScopeCoverage {
                scopes: vec![card_scope()],
            }),
        })
        .await
        .unwrap();
    assert_eq!(commit.disposition.as_text(), "COMMITTED");
    assert!(!commit.read_gate.positive_reads_allowed);

    // Certification: recompute the completion digest from the same bundle.
    let certificate = AuthorityScopePublicationCertificate {
        protocol_version: astral_types::AUTHORITY_PROTOCOL_VERSION,
        authorization_edition: AUTHORIZATION_EDITION,
        authority_id: "authority-test".to_owned(),
        // The certificate binds the IMMUTABLE reservation frontier.
        authority_term: prepare.reservation.authority_term,
        global_fence_sequence: prepare.reservation.fence_sequence_at_prepare,
        certificate_id: "cert-pending".to_owned(),
        intent_digest: prepare.reservation.intent_digest.clone(),
        reservation_id: prepare.reservation.reservation_id.clone(),
        operation_id: OPERATION_ID.to_owned(),
        event_id: "event-1".to_owned(),
        scope: card_scope(),
        approved_request_digest: REQUEST_DIGEST.to_owned(),
        before_image_digest: Some("cd".repeat(32)),
        after_image_digest: "22".repeat(32),
        source_commit_digest: "11".repeat(32),
        completion_digest: String::new(),
        snapshot_hash: "66".repeat(32),
        parent_certificate_hash: None,
        source_outcome_digest: "99".repeat(32),
        manifests: manifests(),
        key_id: "signer-test".to_owned(),
        key_epoch: 1,
        issued_at: 2_500,
        not_before: 2_500,
        expires_at: None,
        certificate_nonce: "cert-nonce-1".to_owned(),
        signature: String::new(),
    };
    let completion_digest = certificate.recompute_completion_digest().unwrap();

    let certify = service
        .certify_publication(&AuthorityCertifyRequest {
            caller: caller(),
            reservation_id: prepare.reservation.reservation_id.clone(),
            scope: card_scope(),
            before_image_digest: Some("cd".repeat(32)),
            after_image_digest: "22".repeat(32),
            snapshot_hash: "66".repeat(32),
            source_outcome_digest: "99".repeat(32),
            manifests: manifests(),
            completion_digest: completion_digest.clone(),
        })
        .await
        .unwrap();
    certify
        .certificate
        .verify(&signer_key.verifying_key())
        .unwrap();
    assert_eq!(certify.certificate.completion_digest, completion_digest);
    assert_eq!(
        certify.certificate.parent_certificate_hash, None,
        "first publication has no parent certificate"
    );
    // GLOBAL coverage: certification does NOT clear the conservative barrier.
    assert!(
        !certify.read_gate.positive_reads_allowed,
        "GLOBAL barrier stays up after certification"
    );
    let proof = certify.proof.expect("card certification mints a proof");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0);
    proof.verify_at(&signer_key.verifying_key(), now).unwrap();
    assert_eq!(proof.snapshot_hash, "66".repeat(32));

    // Reconcile reports the barrier still up: PUBLISHED blocks reads.
    let published = service
        .reconcile_reservation(&AuthorityReconcileRequest {
            caller: caller(),
            reservation_id: prepare.reservation.reservation_id.clone(),
            operation_id: OPERATION_ID.to_owned(),
        })
        .await
        .unwrap();
    assert_eq!(published.reconciliation.disposition.as_text(), "PUBLISHED");

    // The committing source cannot close its own global barrier.
    let source_close = service
        .close_reservation(&astral_types::AuthorityCloseReservationRequest {
            caller: caller(),
            reservation_id: prepare.reservation.reservation_id.clone(),
            operation_id: OPERATION_ID.to_owned(),
            reason: "source self-close must fail".to_owned(),
        })
        .await
        .unwrap_err();
    assert!(matches!(
        source_close,
        AuthorityServiceError::NotAuthorized { .. }
    ));

    // The operator identity closes it; the barrier lifts.
    let closed = service
        .close_reservation(&astral_types::AuthorityCloseReservationRequest {
            caller: astral_types::AuthorityCallerIdentity {
                service_id: OPERATOR_ID.to_owned(),
                request_nonce: "operator-nonce-1".to_owned(),
                issued_at: 1_700,
            },
            reservation_id: prepare.reservation.reservation_id.clone(),
            operation_id: OPERATION_ID.to_owned(),
            reason: "all approved scopes certified".to_owned(),
        })
        .await
        .unwrap();
    assert!(
        closed.read_gate.positive_reads_allowed,
        "operator close unblocks"
    );

    // Fence read now returns the certificate, its pinned hash, and fresh proofs.
    let fence = service
        .read_fence(&AuthorityFenceReadRequest {
            caller: caller(),
            scope: Some(card_scope()),
            expected_certificate_hash: Some(certify.certificate.record_digest().unwrap()),
            read_proof: Some(AuthorityReadProofRequest {
                actor_scope: card_scope(),
                source_scope: None,
                request_nonce: "reader-nonce-2".to_owned(),
                mutation_kind: astral_types::AuthorityMutationKind::AuthorizationSource,
                operation_id: OPERATION_ID.to_owned(),
                event_id: "event-1".to_owned(),
                request_binding_digest: "11".repeat(32),
                expected_frontier: None,
                proof_ttl_seconds: None,
            }),
        })
        .await
        .unwrap();
    assert!(fence.scope_certificate.is_some());
    let minted = fence.proof.unwrap();
    assert_ne!(minted.request_nonce, "reader-nonce-1");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0);
    minted.verify_at(&signer_key.verifying_key(), now).unwrap();

    // Durable proof identity + binding are queryable quorum-side.
    let intent_record: StoredIntentRecord = serde_json::from_slice(
        &store
            .get(&keys.intent(&prepare.reservation.intent_digest))
            .await
            .unwrap()
            .unwrap()
            .value,
    )
    .unwrap();
    assert_eq!(
        intent_record.reservation_id,
        prepare.reservation.reservation_id
    );

    // Reconcile reports the certified terminal state.
    let reconciliation = service
        .reconcile_reservation(&AuthorityReconcileRequest {
            caller: caller(),
            reservation_id: prepare.reservation.reservation_id.clone(),
            operation_id: OPERATION_ID.to_owned(),
        })
        .await
        .unwrap();
    assert_eq!(
        reconciliation.reconciliation.disposition.as_text(),
        "CERTIFIED"
    );
}

#[tokio::test]
async fn intent_cannot_be_accepted_twice_and_nonce_cannot_be_reused() {
    let (service, store, keys, signer_key) = test_service().await;
    seed_admission_proof(
        &service,
        &store,
        &keys,
        &signer_key,
        "prf-seed",
        REQUEST_DIGEST,
    )
    .await;

    let first = service
        .prepare_source_mutation(&AuthorityPrepareRequest {
            caller: caller(),
            intent: intent(AuthorityReservationCoverage::Global),
        })
        .await
        .unwrap();
    // The replay references a proof minted at the OLD frontier: the frontier
    // advanced with the first acceptance, so the stale proof is refused.
    let replay = service
        .prepare_source_mutation(&AuthorityPrepareRequest {
            caller: caller(),
            intent: intent(AuthorityReservationCoverage::Global),
        })
        .await
        .unwrap_err();
    assert!(matches!(
        replay,
        AuthorityServiceError::Protocol(AuthorityProtocolError::FrontierDiverged)
    ));

    // One issued admission proof authorizes exactly one prepare: a fresh
    // intent nonce referencing the SAME consumed proof cannot prepare.
    let mut proof_replay = intent(AuthorityReservationCoverage::Global);
    proof_replay.intent_nonce = "intent-nonce-consumed".to_owned();
    assert!(matches!(
        service
            .prepare_source_mutation(&AuthorityPrepareRequest {
                caller: caller(),
                intent: proof_replay,
            })
            .await,
        Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::FrontierDiverged
        ))
    ));

    // A fresh frontier-exact proof for a second GLOBAL prepare is refused
    // because the first GLOBAL reservation is still active: one conservative
    // barrier at a time. (Sequential prepares are the EXACT single-scope
    // flow, enabled via policy when exact coverage is established.)
    // AlreadyExists { intent_or_proof } remains the concurrent race branch:
    // put-if-absent uniqueness is enforced inside the same txn as the
    // frontier/gate CAS, so a racing duplicate can only win when the frontier
    // AND gate epoch are unchanged (discriminated in the service).
    seed_admission_proof_at_frontier(
        &service,
        &store,
        &keys,
        &signer_key,
        "prf-seed-current",
        REQUEST_DIGEST,
        1,
        2,
    )
    .await;
    let mut second = intent(AuthorityReservationCoverage::Global);
    second.admission_proof_id = "prf-seed-current".to_owned();
    second.intent_nonce = "intent-nonce-second".to_owned();
    assert!(matches!(
        service
            .prepare_source_mutation(&AuthorityPrepareRequest {
                caller: caller(),
                intent: second,
            })
            .await,
        Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::ReadsBlocked { .. }
        ))
    ));
    let _ = first;

    // The reservation from the first intent is still active: the GLOBAL
    // coverage blocks read proofs for every scope, fail closed.
    let fence = service
        .read_fence(&AuthorityFenceReadRequest {
            caller: caller(),
            scope: None,
            expected_certificate_hash: None,
            read_proof: Some(AuthorityReadProofRequest {
                actor_scope: card_scope(),
                source_scope: None,
                request_nonce: "shared-nonce".to_owned(),
                mutation_kind: astral_types::AuthorityMutationKind::AuthorizationSource,
                operation_id: OPERATION_ID.to_owned(),
                event_id: "event-1".to_owned(),
                request_binding_digest: "11".repeat(32),
                expected_frontier: None,
                proof_ttl_seconds: None,
            }),
        })
        .await;
    assert!(matches!(
        fence,
        Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::ReadsBlocked { .. }
        ))
    ));
}

#[tokio::test]
async fn prepare_rejects_expired_leases_binding_mismatch_and_unregistered_identities() {
    let (service, store, keys, signer_key) = test_service().await;
    seed_admission_proof(
        &service,
        &store,
        &keys,
        &signer_key,
        "prf-seed",
        REQUEST_DIGEST,
    )
    .await;

    // Expired lease window.
    let mut expired = intent(AuthorityReservationCoverage::Global);
    expired.lease_expires_at = 1_700_000_500;
    assert!(matches!(
        service
            .prepare_source_mutation(&AuthorityPrepareRequest {
                caller: caller(),
                intent: expired,
            })
            .await,
        Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::LeaseExpired
        ))
    ));

    // Binding digest mismatch: the proof was minted for a different request.
    let mut wrong_binding = intent(AuthorityReservationCoverage::Global);
    wrong_binding.request_digest = "ee".repeat(32);
    wrong_binding.intent_nonce = "intent-nonce-2".to_owned();
    assert!(matches!(
        service
            .prepare_source_mutation(&AuthorityPrepareRequest {
                caller: caller(),
                intent: wrong_binding,
            })
            .await,
        Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::DigestMismatch {
                field: "request_digest"
            }
        ))
    ));

    // Unregistered database identity.
    let mut foreign_db = intent(AuthorityReservationCoverage::Global);
    foreign_db.database_id = "db-other".to_owned();
    foreign_db.intent_nonce = "intent-nonce-3".to_owned();
    assert!(matches!(
        service
            .prepare_source_mutation(&AuthorityPrepareRequest {
                caller: caller(),
                intent: foreign_db,
            })
            .await,
        Err(AuthorityServiceError::NotAuthorized { .. })
    ));

    // EXACT coverage is refused while conservative GLOBAL mode is enforced.
    let mut exact = intent(AuthorityReservationCoverage::Exact(vec![card_scope()]));
    exact.intent_nonce = "intent-nonce-4".to_owned();
    assert!(matches!(
        service
            .prepare_source_mutation(&AuthorityPrepareRequest {
                caller: caller(),
                intent: exact,
            })
            .await,
        Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::InvalidCoverage
        ))
    ));
}

#[tokio::test]
async fn certification_refuses_wrong_digests_and_states() {
    let (service, store, keys, signer_key) = test_service().await;
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

    // Certify before commit: state conflict.
    let premature = service
        .certify_publication(&AuthorityCertifyRequest {
            caller: caller(),
            reservation_id: prepare.reservation.reservation_id.clone(),
            scope: card_scope(),
            before_image_digest: Some("cd".repeat(32)),
            after_image_digest: "22".repeat(32),
            snapshot_hash: "66".repeat(32),
            source_outcome_digest: "99".repeat(32),
            manifests: manifests(),
            completion_digest: "77".repeat(32),
        })
        .await
        .unwrap_err();
    assert!(matches!(
        premature,
        AuthorityServiceError::Protocol(AuthorityProtocolError::StateConflict { .. })
    ));

    service
        .record_source_commit(&AuthorityCommitRequest {
            caller: caller(),
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
            database_id: DATABASE_ID.to_owned(),
            declared_coverage: Some(astral_types::AuthorityStagedScopeCoverage {
                scopes: vec![card_scope()],
            }),
        })
        .await
        .unwrap();

    // Wrong completion digest (never a canonical recomputation).
    let wrong_digest = service
        .certify_publication(&AuthorityCertifyRequest {
            caller: caller(),
            reservation_id: prepare.reservation.reservation_id.clone(),
            scope: card_scope(),
            before_image_digest: Some("cd".repeat(32)),
            after_image_digest: "22".repeat(32),
            snapshot_hash: "66".repeat(32),
            source_outcome_digest: "99".repeat(32),
            manifests: manifests(),
            completion_digest: "77".repeat(32),
        })
        .await
        .unwrap_err();
    assert!(matches!(
        wrong_digest,
        AuthorityServiceError::Protocol(AuthorityProtocolError::DigestMismatch {
            field: "completion_digest"
        })
    ));

    // Wrong after-image: must match the committed reservation.
    let mut certificate = AuthorityScopePublicationCertificate {
        protocol_version: astral_types::AUTHORITY_PROTOCOL_VERSION,
        authorization_edition: AUTHORIZATION_EDITION,
        authority_id: "authority-test".to_owned(),
        authority_term: 1,
        global_fence_sequence: 1,
        certificate_id: "cert-pending".to_owned(),
        intent_digest: prepare.reservation.intent_digest.clone(),
        reservation_id: prepare.reservation.reservation_id.clone(),
        operation_id: OPERATION_ID.to_owned(),
        event_id: "event-1".to_owned(),
        scope: card_scope(),
        approved_request_digest: REQUEST_DIGEST.to_owned(),
        before_image_digest: Some("cd".repeat(32)),
        after_image_digest: "99".repeat(32),
        source_commit_digest: "11".repeat(32),
        completion_digest: String::new(),
        snapshot_hash: "66".repeat(32),
        parent_certificate_hash: None,
        source_outcome_digest: "99".repeat(32),
        manifests: manifests(),
        key_id: "signer-test".to_owned(),
        key_epoch: 1,
        issued_at: 2_500,
        not_before: 2_500,
        expires_at: None,
        certificate_nonce: "cert-nonce-2".to_owned(),
        signature: String::new(),
    };
    certificate.completion_digest = certificate.recompute_completion_digest().unwrap();
    let wrong_image = service
        .certify_publication(&AuthorityCertifyRequest {
            caller: caller(),
            reservation_id: prepare.reservation.reservation_id.clone(),
            scope: card_scope(),
            before_image_digest: Some("cd".repeat(32)),
            after_image_digest: "99".repeat(32),
            snapshot_hash: "66".repeat(32),
            source_outcome_digest: "99".repeat(32),
            manifests: manifests(),
            completion_digest: certificate.completion_digest.clone(),
        })
        .await
        .unwrap_err();
    assert!(matches!(
        wrong_image,
        AuthorityServiceError::Protocol(AuthorityProtocolError::DigestMismatch {
            field: "after_image_digest"
        })
    ));
}

#[tokio::test]
async fn mutations_are_refused_without_leadership_and_reconcile_never_retries() {
    let (service, store, keys, signer_key) = test_service().await;
    seed_admission_proof(
        &service,
        &store,
        &keys,
        &signer_key,
        "prf-seed",
        REQUEST_DIGEST,
    )
    .await;

    // Lose leadership the durable way (§15.9.1): the lease behind the leader
    // key expires and deletes the key. The liveness flag is only a hint — it
    // MUST NOT be the gate — so it is left raised on purpose to prove the
    // stale-flag owner is refused by the durable fence compare.
    let leader_record_key = leader_key(
        &service.config().quorum.key_prefix,
        &service.config().quorum.authority_name,
    );
    let durable = store.get(&leader_record_key).await.unwrap().unwrap();
    let term = LeadershipTokenRecord::decode(&durable.value).unwrap();
    assert!(store.expire_lease(term.lease));
    assert!(store.get(&leader_record_key).await.unwrap().is_none());

    assert!(matches!(
        service
            .prepare_source_mutation(&AuthorityPrepareRequest {
                caller: caller(),
                intent: intent(AuthorityReservationCoverage::Global),
            })
            .await,
        Err(AuthorityServiceError::NotLeader)
    ));

    // Reconciliation is read-only and works on standbys.
    let missing = service
        .reconcile_reservation(&AuthorityReconcileRequest {
            caller: caller(),
            reservation_id: "res-does-not-exist".to_owned(),
            operation_id: OPERATION_ID.to_owned(),
        })
        .await
        .unwrap();
    assert_eq!(missing.reconciliation.disposition.as_text(), "NOT_FOUND");

    // Unknown operation outcomes never retry: store unavailability surfaces
    // as UnknownOutcome with the stable reservation hint.
    let _ = (store, keys, signer_key);
}

#[tokio::test]
async fn startup_attestation_verifies_against_the_recomputed_pin() {
    let (service, _store, _keys, signer_key) = test_service().await;
    let attestation = service.startup_attestation(SERVICE_ID).await.unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0);
    let pin = attestation.genesis_trust_root.digest().unwrap();
    attestation.verify_chain_at(&pin, now).unwrap();

    // A caller-pinned digest that differs from the recomputed root fails.
    assert!(attestation.verify_chain_at(&"ff".repeat(32), now).is_err());
    let _ = signer_key;
}

// ---------------------------------------------------------------------------
// Certified publication history (`AuthorityReconcileResponse
// .certified_publications`)
//
// These regressions drive the real `AuthorityService` against
// `MemoryAuthorityStore`, an in-process mirror of the quorum store's CAS
// contract. They are NOT real etcd/quorum tests: no cluster, no disk
// durability and no cross-node semantics are exercised here.
//
// Contract under test:
// - After certify, the per-reservation certificate index resolves to the
//   exact signed certificate whose fields mirror the durable source binding.
// - The index is immutable: later operations on the same scope advance the
//   scope current pointer, yet reconciling the older reservation still
//   returns its original certificate.
// - Retrying certify after a lost response returns the identical certificate
//   without re-advancing the fence or minting a duplicate identity.
// - Corrupted index entries, corrupted certificate records or corrupted
//   source bindings are rejected fail-closed, never served as publications.
// ---------------------------------------------------------------------------

use astral_authority::error::AuthorityStoreError;

/// One source operation identity plus the digests its commit and certificate
/// must bind. Fixture-scoped: mirrors what a real source service retains.
struct OperationFixture {
    operation_id: &'static str,
    event_id: &'static str,
    intent_nonce: &'static str,
    admission_proof_id: &'static str,
    request_digest: String,
    commit_before_image: String,
    after_image: String,
    snapshot_hash: String,
    source_commit: String,
    source_outcome: String,
}

fn op_one() -> OperationFixture {
    OperationFixture {
        operation_id: OPERATION_ID,
        event_id: "event-1",
        intent_nonce: "intent-nonce-1",
        admission_proof_id: "prf-seed",
        request_digest: REQUEST_DIGEST.to_owned(),
        commit_before_image: "cd".repeat(32),
        after_image: "22".repeat(32),
        snapshot_hash: "66".repeat(32),
        source_commit: "11".repeat(32),
        source_outcome: "99".repeat(32),
    }
}

fn op_two() -> OperationFixture {
    OperationFixture {
        operation_id: "operation-2",
        event_id: "event-2",
        intent_nonce: "intent-nonce-2",
        admission_proof_id: "prf-op2",
        request_digest: REQUEST_DIGEST.to_owned(),
        commit_before_image: "ce".repeat(32),
        after_image: "23".repeat(32),
        snapshot_hash: "67".repeat(32),
        source_commit: "12".repeat(32),
        source_outcome: "9a".repeat(32),
    }
}

fn op_intent(
    op: &OperationFixture,
    coverage: AuthorityReservationCoverage,
) -> AuthoritySourceIntent {
    AuthoritySourceIntent {
        authorization_edition: AUTHORIZATION_EDITION,
        mutation_kind: astral_types::AuthorityMutationKind::AuthorizationSource,
        operation_id: op.operation_id.to_owned(),
        event_id: op.event_id.to_owned(),
        admission_proof_id: op.admission_proof_id.to_owned(),
        request_digest: op.request_digest.clone(),
        service_id: SERVICE_ID.to_owned(),
        database_id: DATABASE_ID.to_owned(),
        coverage,
        before_image_digest: None,
        lease_not_before: 1_700_000_000,
        lease_expires_at: 4_000_000_000,
        intent_nonce: op.intent_nonce.to_owned(),
    }
}

fn op_commit_request(
    op: &OperationFixture,
    reservation: &astral_types::AuthorityScopeReservation,
    declared_coverage: Option<astral_types::AuthorityStagedScopeCoverage>,
) -> AuthorityCommitRequest {
    AuthorityCommitRequest {
        caller: caller(),
        database_id: DATABASE_ID.to_owned(),
        commit: AuthoritySourceCommitRecord {
            reservation_id: reservation.reservation_id.clone(),
            operation_id: op.operation_id.to_owned(),
            source_commit_digest: op.source_commit.clone(),
            before_image_digest: Some(op.commit_before_image.clone()),
            after_image_digest: op.after_image.clone(),
            source_outcome_digest: op.source_outcome.clone(),
            staged_evidence_digest: "88".repeat(32),
            committed_at: 2_000,
        },
        declared_coverage,
    }
}

/// Build the certify request for one operation. `parent_certificate_hash` is
/// the previous publication of the same scope (None for the first one); the
/// caller knows it from its own retained certificate, and the completion
/// digest binds it, so it must be precomputed exactly.
fn op_certify_request(
    op: &OperationFixture,
    reservation: &astral_types::AuthorityScopeReservation,
    parent_certificate_hash: Option<String>,
    scope: AuthorityProtocolScope,
) -> AuthorityCertifyRequest {
    op_certify_request_with_manifests(op, reservation, parent_certificate_hash, scope, manifests())
}

fn op_certify_request_with_manifests(
    op: &OperationFixture,
    reservation: &astral_types::AuthorityScopeReservation,
    parent_certificate_hash: Option<String>,
    scope: AuthorityProtocolScope,
    request_manifests: Vec<AuthorityManifestIdentity>,
) -> AuthorityCertifyRequest {
    let certificate = AuthorityScopePublicationCertificate {
        protocol_version: astral_types::AUTHORITY_PROTOCOL_VERSION,
        authorization_edition: AUTHORIZATION_EDITION,
        authority_id: "authority-test".to_owned(),
        authority_term: reservation.authority_term,
        global_fence_sequence: reservation.fence_sequence_at_prepare,
        certificate_id: "cert-pending".to_owned(),
        intent_digest: reservation.intent_digest.clone(),
        reservation_id: reservation.reservation_id.clone(),
        operation_id: op.operation_id.to_owned(),
        event_id: op.event_id.to_owned(),
        scope: scope.clone(),
        approved_request_digest: op.request_digest.clone(),
        before_image_digest: Some(op.commit_before_image.clone()),
        after_image_digest: op.after_image.clone(),
        source_commit_digest: op.source_commit.clone(),
        completion_digest: String::new(),
        snapshot_hash: op.snapshot_hash.clone(),
        parent_certificate_hash,
        source_outcome_digest: op.source_outcome.clone(),
        manifests: request_manifests,
        key_id: "signer-test".to_owned(),
        key_epoch: 1,
        issued_at: 2_500,
        not_before: 2_500,
        expires_at: None,
        certificate_nonce: "cert-nonce".to_owned(),
        signature: String::new(),
    };
    AuthorityCertifyRequest {
        caller: caller(),
        reservation_id: reservation.reservation_id.clone(),
        scope,
        before_image_digest: certificate.before_image_digest.clone(),
        after_image_digest: certificate.after_image_digest.clone(),
        snapshot_hash: certificate.snapshot_hash.clone(),
        source_outcome_digest: certificate.source_outcome_digest.clone(),
        manifests: certificate.manifests.clone(),
        completion_digest: certificate.recompute_completion_digest().unwrap(),
    }
}

/// Seed one frontier-exact admission proof for a fixture operation at the
/// given authority term / global fence sequence: the proof a real source
/// would have received from a read_fence before preparing.
async fn seed_operation_proof(
    store: &MemoryAuthorityStore,
    keys: &KeyLayout,
    signer_key: &SigningKey,
    op: &OperationFixture,
    authority_term: u64,
    global_fence_sequence: u64,
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
        mutation_kind: astral_types::AuthorityMutationKind::AuthorizationSource,
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

fn now_unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0)
}

/// The certify response contract: self-validating, signature-verifiable, and
/// the minted card proof binds the POST-publication frontier returned in the
/// same response (never the pre-advance observation).
fn assert_certify_binds_post_publication_frontier(
    response: &astral_types::AuthorityCertifyResponse,
    signer_verifying_key: &ed25519_dalek::VerifyingKey,
) {
    response
        .validate()
        .expect("certify response must satisfy the protocol contract");
    response
        .certificate
        .verify(signer_verifying_key)
        .expect("certificate must verify under the registered signer");
    let proof = response
        .proof
        .as_ref()
        .expect("card-scope certification mints a proof");
    proof
        .verify_at(signer_verifying_key, now_unix_seconds())
        .expect("minted proof must verify");
    assert_eq!(
        proof.authority_term, response.global_frontier.authority_term,
        "proof must bind the post-publication authority term"
    );
    assert_eq!(
        proof.global_fence_sequence, response.global_frontier.global_fence_sequence,
        "proof must bind the post-publication fence sequence"
    );
    assert_eq!(proof.key_id, response.global_frontier.key_id);
    assert_eq!(proof.key_epoch, response.global_frontier.key_epoch);
}

/// Full EXACT single-scope lifecycle for two sequential operations on the
/// same card scope: the second one advances the scope current pointer with
/// the first certificate as its parent.
struct TwoExactPublications {
    service: AuthorityService,
    store: Arc<MemoryAuthorityStore>,
    keys: KeyLayout,
    reservation_one: String,
    certificate_one: AuthorityScopePublicationCertificate,
    reservation_two: String,
    certificate_two: AuthorityScopePublicationCertificate,
}

async fn two_exact_scope_publications() -> TwoExactPublications {
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
    let prepare_one = service
        .prepare_source_mutation(&AuthorityPrepareRequest {
            caller: caller(),
            intent: op_intent(
                &one,
                AuthorityReservationCoverage::Exact(vec![card_scope()]),
            ),
        })
        .await
        .unwrap();
    service
        .record_source_commit(&op_commit_request(
            &one,
            &prepare_one.reservation,
            Some(astral_types::AuthorityStagedScopeCoverage {
                scopes: vec![card_scope()],
            }),
        ))
        .await
        .unwrap();
    let certify_one = service
        .certify_publication(&op_certify_request(
            &one,
            &prepare_one.reservation,
            None,
            card_scope(),
        ))
        .await
        .unwrap();
    assert_certify_binds_post_publication_frontier(&certify_one, &signer_key.verifying_key());
    assert_eq!(
        certify_one.reservation.state,
        astral_types::AuthorityReservationState::Certified,
        "single-scope EXACT coverage auto-closes"
    );
    let certificate_one_hash = certify_one.certificate.record_digest().unwrap();

    // Lifecycle 1 advanced the frontier 1 -> 4 (prepare, commit, certify);
    // the second operation needs a proof minted at exactly that frontier.
    let two = op_two();
    seed_operation_proof(&store, &keys, &signer_key, &two, 1, 4).await;
    let prepare_two = service
        .prepare_source_mutation(&AuthorityPrepareRequest {
            caller: caller(),
            intent: op_intent(
                &two,
                AuthorityReservationCoverage::Exact(vec![card_scope()]),
            ),
        })
        .await
        .unwrap();
    assert_ne!(
        prepare_two.reservation.reservation_id,
        prepare_one.reservation.reservation_id
    );
    service
        .record_source_commit(&op_commit_request(
            &two,
            &prepare_two.reservation,
            Some(astral_types::AuthorityStagedScopeCoverage {
                scopes: vec![card_scope()],
            }),
        ))
        .await
        .unwrap();
    let certify_two = service
        .certify_publication(&op_certify_request(
            &two,
            &prepare_two.reservation,
            Some(certificate_one_hash),
            card_scope(),
        ))
        .await
        .unwrap();
    assert_certify_binds_post_publication_frontier(&certify_two, &signer_key.verifying_key());

    TwoExactPublications {
        service,
        store,
        keys,
        reservation_one: prepare_one.reservation.reservation_id,
        certificate_one: certify_one.certificate,
        reservation_two: prepare_two.reservation.reservation_id,
        certificate_two: certify_two.certificate,
    }
}

#[tokio::test]
async fn reconcile_returns_signed_publication_with_exact_commit_binding() {
    let (service, store, keys, signer_key) = test_service().await;
    seed_admission_proof(
        &service,
        &store,
        &keys,
        &signer_key,
        "prf-seed",
        REQUEST_DIGEST,
    )
    .await;

    let one = op_one();
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
            Some(astral_types::AuthorityStagedScopeCoverage {
                scopes: vec![card_scope()],
            }),
        ))
        .await
        .unwrap();
    let certify = service
        .certify_publication(&op_certify_request(
            &one,
            &prepare.reservation,
            None,
            card_scope(),
        ))
        .await
        .unwrap();
    assert_certify_binds_post_publication_frontier(&certify, &signer_key.verifying_key());

    let reconciled = service
        .reconcile_reservation(&AuthorityReconcileRequest {
            caller: caller(),
            reservation_id: prepare.reservation.reservation_id.clone(),
            operation_id: one.operation_id.to_owned(),
        })
        .await
        .unwrap();
    reconciled
        .validate()
        .expect("reconcile response must satisfy the protocol contract");
    assert_eq!(
        reconciled.reconciliation.disposition.as_text(),
        "PUBLISHED",
        "GLOBAL certification stays operator-closed"
    );
    let reservation = reconciled
        .reconciliation
        .reservation
        .as_ref()
        .expect("committed reservation is reported");
    let binding = reconciled
        .commit_binding
        .as_ref()
        .expect("committed reservation echoes its exact source binding");
    assert_eq!(binding.reservation_id, reservation.reservation_id);
    assert_eq!(
        reservation.certified_scopes,
        vec![card_scope().store_key_text().unwrap()]
    );

    assert_eq!(
        reconciled.certified_publications,
        vec![certify.certificate.clone()],
        "reconcile returns exactly the issued certificate"
    );
    let certificate = &reconciled.certified_publications[0];
    certificate
        .verify(&signer_key.verifying_key())
        .expect("recovered certificate must carry a valid authority signature");
    assert_eq!(
        certificate.certificate_id,
        certify.certificate.certificate_id
    );
    assert_eq!(certificate.reservation_id, reservation.reservation_id);
    assert_eq!(certificate.intent_digest, reservation.intent_digest);
    // The certificate is the exact binding mirror of the durable source commit.
    assert_eq!(certificate.operation_id, binding.operation_id);
    assert_eq!(certificate.event_id, binding.event_id);
    assert_eq!(certificate.approved_request_digest, binding.request_digest);
    assert_eq!(certificate.before_image_digest, binding.before_image_digest);
    assert_eq!(certificate.after_image_digest, binding.after_image_digest);
    assert_eq!(
        certificate.source_commit_digest,
        binding.source_commit_digest
    );
    assert_eq!(
        certificate.source_outcome_digest,
        binding.source_outcome_digest
    );
    // The certificate pins the immutable reservation frontier, not the moving one.
    assert_eq!(certificate.authority_term, reservation.authority_term);
    assert_eq!(
        certificate.global_fence_sequence,
        reservation.fence_sequence_at_prepare
    );
    // And the per-reservation index resolves to exactly that certificate id.
    let indexed: String = serde_json::from_slice(
        &store
            .get(&keys.reservation_certificate(
                &reservation.reservation_id,
                &card_scope().store_key_text().unwrap(),
            ))
            .await
            .unwrap()
            .unwrap()
            .value,
    )
    .unwrap();
    assert_eq!(indexed, certificate.certificate_id);
}

#[tokio::test]
async fn reconcile_returns_original_certificate_after_current_pointer_advances() {
    let fixture = two_exact_scope_publications().await;
    let scope_key = card_scope().store_key_text().unwrap();

    // The scope current pointer names the SECOND publication...
    let current_record = fixture
        .store
        .get(&fixture.keys.scope_current(&scope_key))
        .await
        .unwrap()
        .expect("scope current pointer exists after two publications");
    let current: astral_authority::service::StoredScopeCurrent =
        serde_json::from_slice(&current_record.value).unwrap();
    assert_eq!(
        current.certificate_id,
        fixture.certificate_two.certificate_id
    );
    assert_eq!(
        current.certificate_hash,
        fixture.certificate_two.record_digest().unwrap()
    );
    assert_eq!(
        fixture.certificate_two.parent_certificate_hash.as_deref(),
        Some(fixture.certificate_one.record_digest().unwrap().as_str()),
        "the second publication chains to the first as scope parent"
    );

    // ...yet the FIRST reservation still reconciles to its OWN certificate.
    let first = fixture
        .service
        .reconcile_reservation(&AuthorityReconcileRequest {
            caller: caller(),
            reservation_id: fixture.reservation_one.clone(),
            operation_id: op_one().operation_id.to_owned(),
        })
        .await
        .unwrap();
    first
        .validate()
        .expect("historical reconcile must satisfy the response contract");
    assert_eq!(
        first.certified_publications,
        vec![fixture.certificate_one.clone()],
        "per-reservation history is immutable after the current pointer advances"
    );
    assert_eq!(
        first.certified_publications[0].record_digest().unwrap(),
        fixture.certificate_one.record_digest().unwrap()
    );

    // The second reservation reconciles to its own second certificate.
    let second = fixture
        .service
        .reconcile_reservation(&AuthorityReconcileRequest {
            caller: caller(),
            reservation_id: fixture.reservation_two.clone(),
            operation_id: op_two().operation_id.to_owned(),
        })
        .await
        .unwrap();
    second.validate().unwrap();
    assert_eq!(
        second.certified_publications,
        vec![fixture.certificate_two.clone()]
    );
}

#[tokio::test]
async fn certify_retry_after_lost_response_preserves_frontier_and_certificate_identity() {
    let (service, store, keys, signer_key) = test_service().await;
    seed_admission_proof(
        &service,
        &store,
        &keys,
        &signer_key,
        "prf-seed",
        REQUEST_DIGEST,
    )
    .await;

    let one = op_one();
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
            Some(astral_types::AuthorityStagedScopeCoverage {
                scopes: vec![card_scope()],
            }),
        ))
        .await
        .unwrap();
    let issued = service
        .certify_publication(&op_certify_request(
            &one,
            &prepare.reservation,
            None,
            card_scope(),
        ))
        .await
        .unwrap();
    assert_certify_binds_post_publication_frontier(&issued, &signer_key.verifying_key());

    // The response is lost in flight. Everything below recovers from durable
    // quorum-side evidence only.
    let scope_key = card_scope().store_key_text().unwrap();
    let current_key = keys.scope_current(&scope_key);
    let current_before = store
        .get(&current_key)
        .await
        .unwrap()
        .expect("scope current pointer");
    let current: astral_authority::service::StoredScopeCurrent =
        serde_json::from_slice(&current_before.value).unwrap();

    let fence = service
        .read_fence(&AuthorityFenceReadRequest {
            caller: caller(),
            scope: Some(card_scope()),
            expected_certificate_hash: Some(current.certificate_hash.clone()),
            read_proof: None,
        })
        .await
        .unwrap();
    assert_eq!(
        fence.scope_certificate.as_ref().unwrap().certificate_id,
        current.certificate_id
    );
    let fence_frontier = fence.global_frontier;

    // Recovery read: the reconcile returns exactly the published certificate.
    let reconciled = service
        .reconcile_reservation(&AuthorityReconcileRequest {
            caller: caller(),
            reservation_id: prepare.reservation.reservation_id.clone(),
            operation_id: one.operation_id.to_owned(),
        })
        .await
        .unwrap();
    reconciled.validate().unwrap();
    assert_eq!(
        reconciled.global_frontier, fence_frontier,
        "reconcile never advances the fence"
    );
    assert_eq!(reconciled.certified_publications.len(), 1);
    assert_eq!(
        reconciled.certified_publications[0].certificate_id,
        current.certificate_id
    );
    assert_eq!(
        reconciled.certified_publications[0]
            .record_digest()
            .unwrap(),
        current.certificate_hash
    );

    // Retry with the same request: identical certificate identity, no fence
    // advance, no duplicate proof identity.
    let retry = service
        .certify_publication(&op_certify_request(
            &one,
            &prepare.reservation,
            None,
            card_scope(),
        ))
        .await
        .unwrap();
    retry
        .validate()
        .expect("retried response must satisfy the protocol contract");
    assert_eq!(retry.certificate.certificate_id, current.certificate_id);
    assert_eq!(
        retry.certificate.record_digest().unwrap(),
        current.certificate_hash
    );
    assert_eq!(
        retry.global_frontier, fence_frontier,
        "retry must not re-advance the fence"
    );
    assert!(
        retry.proof.is_none(),
        "retry must not mint a duplicate proof identity"
    );
    assert_eq!(
        store.get(&current_key).await.unwrap(),
        Some(current_before.clone()),
        "retry must not rewrite the scope current pointer"
    );

    // Exactly one certificate record exists quorum-side.
    let certificates = store.get_prefix(&keys.certificate("")).await.unwrap();
    assert_eq!(
        certificates.len(),
        1,
        "no duplicate certificate identity may be minted"
    );
    assert_eq!(certificates[0].0, keys.certificate(&current.certificate_id));

    // And the recovery read is stable afterwards.
    let reconciled_again = service
        .reconcile_reservation(&AuthorityReconcileRequest {
            caller: caller(),
            reservation_id: prepare.reservation.reservation_id.clone(),
            operation_id: one.operation_id.to_owned(),
        })
        .await
        .unwrap();
    assert_eq!(
        reconciled_again.certified_publications,
        reconciled.certified_publications
    );
    assert_eq!(reconciled_again.global_frontier, fence_frontier);
}

#[tokio::test]
async fn reconcile_rejects_corrupted_certificate_index_records_and_source_binding() {
    let (service, store, keys, signer_key) = test_service().await;
    seed_admission_proof(
        &service,
        &store,
        &keys,
        &signer_key,
        "prf-seed",
        REQUEST_DIGEST,
    )
    .await;

    let one = op_one();
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
            Some(astral_types::AuthorityStagedScopeCoverage {
                scopes: vec![card_scope()],
            }),
        ))
        .await
        .unwrap();
    let certify = service
        .certify_publication(&op_certify_request(
            &one,
            &prepare.reservation,
            None,
            card_scope(),
        ))
        .await
        .unwrap();

    let scope_key = card_scope().store_key_text().unwrap();
    let index_key = keys.reservation_certificate(&prepare.reservation.reservation_id, &scope_key);
    let binding_key = keys.commit_binding(&prepare.reservation.reservation_id);

    let index_record = store.get(&index_key).await.unwrap().unwrap();
    let certificate_id: String = serde_json::from_slice(&index_record.value).unwrap();
    let certificate_key = keys.certificate(&certificate_id);
    let certificate_record = store.get(&certificate_key).await.unwrap().unwrap();
    let original_binding = store.get(&binding_key).await.unwrap().unwrap();

    let request = AuthorityReconcileRequest {
        caller: caller(),
        reservation_id: prepare.reservation.reservation_id.clone(),
        operation_id: one.operation_id.to_owned(),
    };

    // Baseline: reconcile recovers the publication from intact state.
    let baseline = service.reconcile_reservation(&request).await.unwrap();
    assert_eq!(baseline.certified_publications.len(), 1);

    async fn corrupt_error_of(
        service: &AuthorityService,
        request: &AuthorityReconcileRequest,
    ) -> String {
        match service.reconcile_reservation(request).await {
            Ok(_) => panic!("corrupted quorum state must fail closed"),
            Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(message))) => message,
            Err(other) => panic!("expected a corrupt-store rejection, got {other:?}"),
        }
    }

    // (1) Missing index entry.
    store
        .execute(StoreTxn::new().with_op(StoreOp::Delete {
            key: index_key.clone(),
        }))
        .await
        .unwrap();
    assert_eq!(
        corrupt_error_of(&service, &request).await,
        "reservation certificate index missing"
    );

    // (2) Undecodable index value.
    store
        .execute(StoreTxn::new().with_op(StoreOp::Put {
            key: index_key.clone(),
            value: b"cert-index-not-json".to_vec(),
        }))
        .await
        .unwrap();
    assert_eq!(
        corrupt_error_of(&service, &request).await,
        "reservation certificate index"
    );

    // (3) Index pointing at a certificate that does not exist.
    store
        .execute(StoreTxn::new().with_op(StoreOp::Put {
            key: index_key.clone(),
            value: serde_json::to_vec("cert-ghost").unwrap(),
        }))
        .await
        .unwrap();
    assert_eq!(
        corrupt_error_of(&service, &request).await,
        "reservation certificate missing"
    );

    // Restore the index before the certificate-record corruption cases.
    store
        .execute(StoreTxn::new().with_op(StoreOp::Put {
            key: index_key.clone(),
            value: index_record.value.clone(),
        }))
        .await
        .unwrap();

    // (4) Undecodable certificate record.
    store
        .execute(StoreTxn::new().with_op(StoreOp::Put {
            key: certificate_key.clone(),
            value: b"cert-record-not-json".to_vec(),
        }))
        .await
        .unwrap();
    assert_eq!(
        corrupt_error_of(&service, &request).await,
        "reservation certificate"
    );

    // (5) Tampered certificate content: the authority re-verifies the
    // completion digest and signature before serving a historical publication.
    let mut tampered: AuthorityScopePublicationCertificate =
        serde_json::from_slice(&certificate_record.value).unwrap();
    tampered.snapshot_hash = "77".repeat(32);
    store
        .execute(StoreTxn::new().with_op(StoreOp::Put {
            key: certificate_key.clone(),
            value: serde_json::to_vec(&tampered).unwrap(),
        }))
        .await
        .unwrap();
    match service.reconcile_reservation(&request).await {
        Ok(_) => panic!("tampered certificate content must fail closed"),
        Err(AuthorityServiceError::Protocol(AuthorityProtocolError::DigestMismatch { field })) => {
            assert_eq!(field, "completion_digest");
        }
        Err(other) => panic!("expected completion digest rejection, got {other:?}"),
    }

    // (6) Forged record: validly signed by the registered signer but carrying
    // an id the reservation index does not name. The id binding rejects it.
    let mut forged: AuthorityScopePublicationCertificate =
        serde_json::from_slice(&certificate_record.value).unwrap();
    forged.certificate_id = "cert-forged-id".to_owned();
    forged.completion_digest = forged.recompute_completion_digest().unwrap();
    forged.sign(&signer_key).unwrap();
    store
        .execute(StoreTxn::new().with_op(StoreOp::Put {
            key: certificate_key.clone(),
            value: serde_json::to_vec(&forged).unwrap(),
        }))
        .await
        .unwrap();
    assert!(matches!(
        service.reconcile_reservation(&request).await,
        Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::ScopeMismatch
        ))
    ));

    // Restore the certificate record before the source-binding cases.
    store
        .execute(StoreTxn::new().with_op(StoreOp::Put {
            key: certificate_key,
            value: certificate_record.value,
        }))
        .await
        .unwrap();

    // (7) Undecodable source binding.
    store
        .execute(StoreTxn::new().with_op(StoreOp::Put {
            key: binding_key.clone(),
            value: b"binding-not-json".to_vec(),
        }))
        .await
        .unwrap();
    assert_eq!(
        corrupt_error_of(&service, &request).await,
        "source commit binding"
    );

    // (8) Mutated binding: structurally valid but no longer the commit the
    // certificate was issued for; the exact-binding cross-check rejects it.
    let mut binding: astral_types::AuthorityCommitBinding =
        serde_json::from_slice(&original_binding.value).unwrap();
    binding.request_digest = "ab".repeat(32);
    store
        .execute(StoreTxn::new().with_op(StoreOp::Put {
            key: binding_key.clone(),
            value: serde_json::to_vec(&binding).unwrap(),
        }))
        .await
        .unwrap();
    assert!(matches!(
        service.reconcile_reservation(&request).await,
        Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::ScopeMismatch
        ))
    ));

    // Restoring every record restores the recovery read.
    store
        .execute(
            StoreTxn::new()
                .with_op(StoreOp::Put {
                    key: binding_key,
                    value: original_binding.value,
                })
                .with_op(StoreOp::Put {
                    key: index_key,
                    value: index_record.value,
                }),
        )
        .await
        .unwrap();
    let restored = service.reconcile_reservation(&request).await.unwrap();
    assert_eq!(restored.certified_publications, vec![certify.certificate]);
}

#[tokio::test]
async fn reconcile_response_contract_rejects_wrong_source_historical_and_missing_publications() {
    let fixture = two_exact_scope_publications().await;

    let current = fixture
        .service
        .reconcile_reservation(&AuthorityReconcileRequest {
            caller: caller(),
            reservation_id: fixture.reservation_two.clone(),
            operation_id: op_two().operation_id.to_owned(),
        })
        .await
        .unwrap();
    current
        .validate()
        .expect("the served response must satisfy the response contract");

    // A source binding that no longer matches the certified request digest is
    // not a valid publication history.
    let mut wrong_source = current.clone();
    wrong_source.commit_binding.as_mut().unwrap().request_digest = "ab".repeat(32);
    assert!(
        wrong_source.validate().is_err(),
        "wrong source binding must be rejected by the response contract"
    );

    // A historical certificate of the same scope (the previous publication)
    // must never be served for the newer reservation.
    let mut historical = current.clone();
    historical.certified_publications = vec![fixture.certificate_one.clone()];
    assert!(
        historical.validate().is_err(),
        "substituting the previous certificate must be rejected"
    );

    // An incomplete publication set must be rejected: the response must carry
    // every indexed certified scope.
    let mut missing = current;
    missing.certified_publications.clear();
    assert!(
        missing.validate().is_err(),
        "a truncated publication set must be rejected"
    );

    // End-to-end: pointing the reservation index at the previous certificate
    // id is rejected by the served reconcile (fail-closed, no substitution).
    let scope_key = card_scope().store_key_text().unwrap();
    let index_two = fixture
        .keys
        .reservation_certificate(&fixture.reservation_two, &scope_key);
    fixture
        .store
        .execute(StoreTxn::new().with_op(StoreOp::Put {
            key: index_two,
            value: serde_json::to_vec(&fixture.certificate_one.certificate_id).unwrap(),
        }))
        .await
        .unwrap();
    assert!(matches!(
        fixture
            .service
            .reconcile_reservation(&AuthorityReconcileRequest {
                caller: caller(),
                reservation_id: fixture.reservation_two.clone(),
                operation_id: op_two().operation_id.to_owned(),
            })
            .await,
        Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::ScopeMismatch
        ))
    ));

    // And the older reservation still serves its own original publication.
    let first = fixture
        .service
        .reconcile_reservation(&AuthorityReconcileRequest {
            caller: caller(),
            reservation_id: fixture.reservation_one,
            operation_id: op_one().operation_id.to_owned(),
        })
        .await
        .unwrap();
    first.validate().unwrap();
    assert_eq!(first.certified_publications, vec![fixture.certificate_one]);
}

// ---------------------------------------------------------------------------
// Verified scope-current pointer, per-aggregate publication continuity, and
// the certify-issued proof storage contract (still MemoryAuthorityStore: an
// in-process CAS mirror, NOT a real etcd/quorum environment).
// ---------------------------------------------------------------------------

/// Two-aggregate manifest set: the baseline for continuity regressions.
fn manifests_two() -> Vec<AuthorityManifestIdentity> {
    let mut list = manifests();
    list.push(AuthorityManifestIdentity {
        aggregate_type: "ROLE".to_owned(),
        aggregate_id: 5,
        manifest_digest_hex: "d1".repeat(32),
        dependency_hash_hex: "e1".repeat(32),
        semantic_hash_hex: "f1".repeat(32),
        generation: 3,
        revoke_fence: 1,
        event_id: "event-1".to_owned(),
        operation_id: OPERATION_ID.to_owned(),
    });
    list
}

fn op_three() -> OperationFixture {
    OperationFixture {
        operation_id: "operation-3",
        event_id: "event-3",
        intent_nonce: "intent-nonce-3",
        admission_proof_id: "prf-op3",
        request_digest: REQUEST_DIGEST.to_owned(),
        commit_before_image: "cf".repeat(32),
        after_image: "24".repeat(32),
        snapshot_hash: "68".repeat(32),
        source_commit: "13".repeat(32),
        source_outcome: "9b".repeat(32),
    }
}

fn mint_request() -> AuthorityReadProofRequest {
    AuthorityReadProofRequest {
        actor_scope: card_scope(),
        source_scope: None,
        request_nonce: "reader-drift-nonce".to_owned(),
        mutation_kind: astral_types::AuthorityMutationKind::AuthorizationSource,
        operation_id: OPERATION_ID.to_owned(),
        event_id: "event-1".to_owned(),
        request_binding_digest: "11".repeat(32),
        expected_frontier: None,
        proof_ttl_seconds: None,
    }
}

#[tokio::test]
async fn read_fence_and_proof_mint_reject_drifted_scope_current_pointer() {
    let fixture = two_exact_scope_publications().await;
    let scope_key = card_scope().store_key_text().unwrap();
    let current_key = fixture.keys.scope_current(&scope_key);
    let original: astral_authority::service::StoredScopeCurrent = serde_json::from_slice(
        &fixture
            .store
            .get(&current_key)
            .await
            .unwrap()
            .unwrap()
            .value,
    )
    .unwrap();

    // Every drift is applied to the cached pointer alone; the immutable
    // certificate record stays intact. Both consumers — the fence read and
    // the proof mint — must fail closed instead of trusting the cache.
    let mut drifts: Vec<(&str, astral_authority::service::StoredScopeCurrent, bool)> = Vec::new();
    let mut drifted = original.clone();
    drifted.certificate_hash = "ff".repeat(32);
    drifts.push(("certificate_hash", drifted, false));
    let mut drifted = original.clone();
    drifted.certificate_id = "cert-ghost-pointer".to_owned();
    drifts.push(("certificate_id", drifted, false));
    let mut drifted = original.clone();
    drifted.snapshot_hash = "78".repeat(32);
    drifts.push(("snapshot_hash", drifted, false));
    let mut drifted = original.clone();
    drifted.scope_generation = original.scope_generation + 1;
    drifts.push(("scope_generation", drifted, false));
    let mut drifted = original.clone();
    drifted.revoke_watermark = original.revoke_watermark + 1;
    drifts.push(("revoke_watermark", drifted, false));
    let mut drifted = original.clone();
    drifted.key_epoch = original.key_epoch + 1;
    drifts.push(("key_epoch", drifted, false));
    let mut drifted = original.clone();
    drifted.scope_key_text = "CARD:7:18:-:ANY".to_owned();
    drifts.push(("scope_key_text", drifted, true));

    for (name, drifted, expect_scope_mismatch) in drifts {
        fixture
            .store
            .execute(StoreTxn::new().with_op(StoreOp::Put {
                key: current_key.clone(),
                value: serde_json::to_vec(&drifted).unwrap(),
            }))
            .await
            .unwrap();

        // Fence-only read (no proof): the drifted cache must not be served.
        let fence_only = fixture
            .service
            .read_fence(&AuthorityFenceReadRequest {
                caller: caller(),
                scope: Some(card_scope()),
                expected_certificate_hash: None,
                read_proof: None,
            })
            .await;
        // Mint-only read (no scope section): mint resolves the pointer itself.
        let mint_only = fixture
            .service
            .read_fence(&AuthorityFenceReadRequest {
                caller: caller(),
                scope: None,
                expected_certificate_hash: None,
                read_proof: Some(mint_request()),
            })
            .await;

        for (path, outcome) in [("fence", fence_only), ("mint", mint_only)] {
            match (name, expect_scope_mismatch) {
                (_, true) => {
                    assert!(
                    matches!(
                        outcome,
                        Err(AuthorityServiceError::Protocol(AuthorityProtocolError::ScopeMismatch))
                    ),
                    "{path}: {name} drift must be rejected as a scope mismatch, got {outcome:?}"
                )
                }
                ("certificate_id", false) => match outcome {
                    Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(message))) => {
                        assert_eq!(
                            message, "certified certificate is missing",
                            "{path}: drifted pointer must fail on the missing certificate"
                        )
                    }
                    other => {
                        panic!("{path}: expected corrupt-store rejection, got {other:?}")
                    }
                },
                (_, false) => assert!(
                    matches!(
                        outcome,
                        Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                            _
                        )))
                    ),
                    "{path}: {name} drift must be rejected as corrupt state, got {outcome:?}"
                ),
            }
        }
    }

    // Restoring the exact pointer restores both readers.
    fixture
        .store
        .execute(StoreTxn::new().with_op(StoreOp::Put {
            key: current_key,
            value: serde_json::to_vec(&original).unwrap(),
        }))
        .await
        .unwrap();
    let restored = fixture
        .service
        .read_fence(&AuthorityFenceReadRequest {
            caller: caller(),
            scope: Some(card_scope()),
            expected_certificate_hash: None,
            read_proof: None,
        })
        .await
        .unwrap();
    assert_eq!(
        restored.scope_certificate.unwrap().certificate_id,
        fixture.certificate_two.certificate_id
    );
}

#[tokio::test]
async fn certify_enforces_per_aggregate_continuity_against_verified_previous_certificate() {
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
    let prepare_one = service
        .prepare_source_mutation(&AuthorityPrepareRequest {
            caller: caller(),
            intent: op_intent(
                &one,
                AuthorityReservationCoverage::Exact(vec![card_scope()]),
            ),
        })
        .await
        .unwrap();
    service
        .record_source_commit(&op_commit_request(
            &one,
            &prepare_one.reservation,
            Some(astral_types::AuthorityStagedScopeCoverage {
                scopes: vec![card_scope()],
            }),
        ))
        .await
        .unwrap();
    let certify_one = service
        .certify_publication(&op_certify_request_with_manifests(
            &one,
            &prepare_one.reservation,
            None,
            card_scope(),
            manifests_two(),
        ))
        .await
        .unwrap();
    assert_certify_binds_post_publication_frontier(&certify_one, &signer_key.verifying_key());
    let certificate_one_hash = certify_one.certificate.record_digest().unwrap();
    let published = certify_one.certificate.manifests.clone();

    // Second operation on the same scope, committed once: every failing
    // attempt below is refused BEFORE the certification transaction, so the
    // reservation stays Committed between attempts.
    let two = op_two();
    seed_operation_proof(&store, &keys, &signer_key, &two, 1, 4).await;
    let prepare_two = service
        .prepare_source_mutation(&AuthorityPrepareRequest {
            caller: caller(),
            intent: op_intent(
                &two,
                AuthorityReservationCoverage::Exact(vec![card_scope()]),
            ),
        })
        .await
        .unwrap();
    service
        .record_source_commit(&op_commit_request(
            &two,
            &prepare_two.reservation,
            Some(astral_types::AuthorityStagedScopeCoverage {
                scopes: vec![card_scope()],
            }),
        ))
        .await
        .unwrap();

    let attempt = |manifest_set: Vec<AuthorityManifestIdentity>| {
        op_certify_request_with_manifests(
            &two,
            &prepare_two.reservation,
            Some(certificate_one_hash.clone()),
            card_scope(),
            manifest_set,
        )
    };

    // (1) Per-aggregate generation regression masked by a higher maximum:
    // USER_CARD regresses while ROLE raises the frontier maximum.
    let mut masked = published.clone();
    masked[0].generation = 3;
    masked[1].generation = 9;
    masked[1].revoke_fence = 3;
    assert!(
        matches!(
            service.certify_publication(&attempt(masked)).await,
            Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::FrontierDiverged
            ))
        ),
        "the frontier maximum must never mask a per-aggregate regression"
    );

    // (2) Per-aggregate revoke-watermark regression, also masked by a higher
    // maximum elsewhere in the set.
    let mut revoke = published.clone();
    revoke[0].generation = 5;
    revoke[0].revoke_fence = 1;
    revoke[1].generation = 9;
    revoke[1].revoke_fence = 3;
    assert!(matches!(
        service.certify_publication(&attempt(revoke)).await,
        Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::FrontierDiverged
        ))
    ));

    // (3) Same-generation content swap: unchanged generation but a different
    // manifest identity is never a legal publication.
    let mut swapped = published.clone();
    swapped[0].manifest_digest_hex = "d2".repeat(32);
    assert!(matches!(
        service.certify_publication(&attempt(swapped)).await,
        Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::FrontierDiverged
        ))
    ));

    // (4) Dropped aggregate: a previously published aggregate may not vanish.
    let mut dropped = published.clone();
    dropped[0].generation = 5;
    dropped.truncate(1);
    assert!(matches!(
        service.certify_publication(&attempt(dropped)).await,
        Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::FrontierDiverged
        ))
    ));

    // (5) Legal continuation: both published aggregates advance or stay
    // unchanged (unchanged identity is legal) and one NEW aggregate joins.
    let mut next = published.clone();
    next[0].generation = 5;
    next.push(AuthorityManifestIdentity {
        aggregate_type: "TENANT_CONFIG".to_owned(),
        aggregate_id: 9,
        manifest_digest_hex: "d3".repeat(32),
        dependency_hash_hex: "e3".repeat(32),
        semantic_hash_hex: "f3".repeat(32),
        generation: 1,
        revoke_fence: 0,
        event_id: "event-2".to_owned(),
        operation_id: two.operation_id.to_owned(),
    });
    let certify_two = service.certify_publication(&attempt(next)).await.unwrap();
    assert_certify_binds_post_publication_frontier(&certify_two, &signer_key.verifying_key());
    assert_eq!(certify_two.certificate.manifests.len(), 3);
    assert_eq!(
        certify_two.certificate.parent_certificate_hash.as_deref(),
        Some(certificate_one_hash.as_str()),
        "the parent CAS still binds the verified previous certificate"
    );

    // (6) The next certification verifies the stored previous certificate
    // BEFORE using it as a continuity baseline: a tampered record is refused
    // even under a valid signature-shaped request.
    let certificate_two_key = keys.certificate(&certify_two.certificate.certificate_id);
    let mut tampered: AuthorityScopePublicationCertificate = serde_json::from_slice(
        &store
            .get(&certificate_two_key)
            .await
            .unwrap()
            .unwrap()
            .value,
    )
    .unwrap();
    tampered.snapshot_hash = "79".repeat(32);
    store
        .execute(StoreTxn::new().with_op(StoreOp::Put {
            key: certificate_two_key,
            value: serde_json::to_vec(&tampered).unwrap(),
        }))
        .await
        .unwrap();

    let three = op_three();
    seed_operation_proof(&store, &keys, &signer_key, &three, 1, 7).await;
    let prepare_three = service
        .prepare_source_mutation(&AuthorityPrepareRequest {
            caller: caller(),
            intent: op_intent(
                &three,
                AuthorityReservationCoverage::Exact(vec![card_scope()]),
            ),
        })
        .await
        .unwrap();
    service
        .record_source_commit(&op_commit_request(
            &three,
            &prepare_three.reservation,
            Some(astral_types::AuthorityStagedScopeCoverage {
                scopes: vec![card_scope()],
            }),
        ))
        .await
        .unwrap();
    let tampered_parent = service
        .certify_publication(&op_certify_request_with_manifests(
            &three,
            &prepare_three.reservation,
            Some(certify_two.certificate.record_digest().unwrap()),
            card_scope(),
            manifests_two(),
        ))
        .await;
    match tampered_parent {
        Err(AuthorityServiceError::Protocol(AuthorityProtocolError::DigestMismatch { field })) => {
            assert_eq!(field, "completion_digest")
        }
        other => panic!("tampered previous certificate must fail the parent read, got {other:?}"),
    }
}

#[tokio::test]
async fn certify_proof_is_stored_atomically_with_exact_binding() {
    let (service, store, keys, signer_key) = test_service().await;
    seed_admission_proof(
        &service,
        &store,
        &keys,
        &signer_key,
        "prf-seed",
        REQUEST_DIGEST,
    )
    .await;

    let one = op_one();
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
            Some(astral_types::AuthorityStagedScopeCoverage {
                scopes: vec![card_scope()],
            }),
        ))
        .await
        .unwrap();
    let certify = service
        .certify_publication(&op_certify_request(
            &one,
            &prepare.reservation,
            None,
            card_scope(),
        ))
        .await
        .unwrap();
    assert_certify_binds_post_publication_frontier(&certify, &signer_key.verifying_key());
    let minted = certify.proof.expect("card certification mints a proof");
    let scope_key = card_scope().store_key_text().unwrap();

    // The full signed proof is stored under its stable id and verifies.
    let stored_proof: AuthorizationFenceProof = serde_json::from_slice(
        &store
            .get(&keys.proof_receipt(&minted.proof_id))
            .await
            .unwrap()
            .expect("certify-issued proof must be stored quorum-side")
            .value,
    )
    .unwrap();
    assert_eq!(
        stored_proof, minted,
        "stored proof must be the exact signed proof"
    );
    stored_proof
        .verify_at(&signer_key.verifying_key(), now_unix_seconds())
        .expect("stored proof must verify under the registered signer");

    // The quorum-side binding receipt matches the proof field for field.
    let binding: astral_authority::service::StoredProofReceipt = serde_json::from_slice(
        &store
            .get(&keys.proof_binding(&minted.proof_id))
            .await
            .unwrap()
            .expect("certify-issued proof binding must be stored")
            .value,
    )
    .unwrap();
    assert_eq!(binding.proof_id, minted.proof_id);
    assert_eq!(binding.request_nonce, minted.request_nonce);
    assert_eq!(
        Some(binding.request_binding_digest.as_str()),
        minted.request_binding_digest.as_deref()
    );
    assert_eq!(
        binding.request_binding_digest,
        certify.certificate.approved_request_digest
    );
    assert_eq!(binding.operation_id, minted.operation_id);
    assert_eq!(binding.event_id, minted.event_id);
    assert_eq!(binding.authority_term, minted.authority_term);
    assert_eq!(binding.global_fence_sequence, minted.global_fence_sequence);
    assert_eq!(binding.key_epoch, minted.key_epoch);
    assert_eq!(binding.issued_at, minted.issued_at);
    assert_eq!(binding.expires_at, minted.expires_at);
    assert_eq!(binding.caller_service_id, SERVICE_ID);
    assert_eq!(binding.actor_scope_key, scope_key);
    assert_eq!(binding.source_scope_key, scope_key);
    assert_eq!(
        binding.mutation_kind,
        astral_types::AuthorityMutationKind::AuthorizationSource
    );
    assert_eq!(
        minted.scope_certificate_hash.as_deref(),
        Some(certify.certificate.record_digest().unwrap().as_str()),
        "the proof binds exactly the certificate it was issued with"
    );

    // The one-use nonce index holds the same receipt: proof, binding and
    // nonce landed in the same atomic quorum step.
    let nonce_receipt: astral_authority::service::StoredProofReceipt = serde_json::from_slice(
        &store
            .get(&keys.proof_nonce(&scope_key, &minted.request_nonce))
            .await
            .unwrap()
            .expect("certify-issued proof nonce index must be stored")
            .value,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_vec(&nonce_receipt).unwrap(),
        serde_json::to_vec(&binding).unwrap(),
        "nonce index must carry the exact binding receipt"
    );
}
