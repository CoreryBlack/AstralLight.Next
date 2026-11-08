#![cfg(feature = "service")]

//! Root-signed source bootstrap contracts against the real service and memory
//! store. The memory store is used only as the deterministic etcd/CAS test
//! backend; all lifecycle assertions go through AuthorityService APIs.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use astral_authority::config::{
    AuthorityIdentityConfig, AuthorityServiceConfig, AuthoritySignerConfig, AuthorityTrustedSource,
};
use astral_authority::error::AuthorityServiceError;
use astral_authority::service::leadership::{leader_key, LeadershipToken, LeadershipTokenRecord};
use astral_authority::service::{AuthorityService, StoredGenesis, StoredProofReceipt};
use astral_authority::signing::ProtectedAuthoritySigner;
use astral_authority::store::memory::MemoryAuthorityStore;
use astral_authority::store::{AuthorityStore, KeyLayout, StoreOp, StoreTxn};
use astral_types::{
    AuthorityCallerIdentity, AuthorityMutationKind, AuthorityPrepareRequest,
    AuthorityProtocolError, AuthorityReservationCoverage, AuthorityRootKey, AuthorityRootKeyRole,
    AuthoritySourceBootstrapBundle, AuthoritySourceBootstrapCompletion,
    AuthoritySourceBootstrapFinalizeRequest, AuthoritySourceBootstrapKind,
    AuthoritySourceBootstrapPrepareRequest, AuthoritySourceBootstrapReconcileRequest,
    AuthoritySourceBootstrapState, AuthoritySourceBootstrapTicket, AuthoritySourceIntent,
    AuthorityTrustRoot, AuthorizationAuthorityScope, AuthorizationDomainScope, ResourceRegistry,
    SourceBootstrapRuleSetEntry, SourceBootstrapRuleSetRoot, SourceBootstrapTemplateRoot,
    SourceBootstrapTemplateRule, AUTHORITY_OPERATION_SOURCE_BOOTSTRAP_FINALIZE,
    AUTHORITY_OPERATION_SOURCE_BOOTSTRAP_PREPARE, AUTHORITY_OPERATION_SOURCE_BOOTSTRAP_RECONCILE,
    AUTHORITY_PROTOCOL_VERSION, AUTHORIZATION_EDITION,
};
use ed25519_dalek::{Signer, SigningKey};

const AUTHORITY_ID: &str = "authority-source-bootstrap-test";
const AUTHORITY_NAME: &str = "authority-source-bootstrap-test";
const SERVICE_ID: &str = "source-bootstrap-runner";
const DATABASE_ID: &str = "db-source-bootstrap";

struct Fixture {
    service: AuthorityService,
    store: Arc<MemoryAuthorityStore>,
    trust_root: AuthorityTrustRoot,
    signer_key: SigningKey,
    root_key: SigningKey,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after unix epoch")
        .as_secs() as i64
}

fn digest(byte: &str) -> String {
    byte.repeat(64)
}

fn trust_root_fixture() -> (AuthorityTrustRoot, SigningKey, SigningKey, SigningKey) {
    let signer_key = SigningKey::from_bytes(&[7u8; 32]);
    let root_key = SigningKey::from_bytes(&[17u8; 32]);
    let genesis_key = SigningKey::from_bytes(&[27u8; 32]);
    let trust_root = AuthorityTrustRoot {
        root_id: "root-source-bootstrap".to_owned(),
        keys: vec![
            AuthorityRootKey {
                key_id: "signer-source-bootstrap".to_owned(),
                key_epoch: 1,
                role: AuthorityRootKeyRole::Signer,
                verifying_key_hex: hex::encode(signer_key.verifying_key().as_bytes()),
            },
            AuthorityRootKey {
                key_id: "root-source-bootstrap".to_owned(),
                key_epoch: 1,
                role: AuthorityRootKeyRole::Root,
                verifying_key_hex: hex::encode(root_key.verifying_key().as_bytes()),
            },
            AuthorityRootKey {
                key_id: "genesis-source-bootstrap".to_owned(),
                key_epoch: 1,
                role: AuthorityRootKeyRole::Genesis,
                verifying_key_hex: hex::encode(genesis_key.verifying_key().as_bytes()),
            },
        ],
        created_at: 1_000,
    };
    (trust_root, signer_key, root_key, genesis_key)
}

fn config(trust_root: &AuthorityTrustRoot) -> AuthorityServiceConfig {
    AuthorityServiceConfig {
        identity: AuthorityIdentityConfig {
            authority_id: AUTHORITY_ID.to_owned(),
            pinned_genesis_trust_root_digest: trust_root.digest().unwrap(),
        },
        quorum: astral_authority::config::AuthorityQuorumConfig {
            authority_name: AUTHORITY_NAME.to_owned(),
            ..Default::default()
        },
        signer: AuthoritySignerConfig {
            signing_key_path: Some("/keys/source-bootstrap-test.seed".into()),
            signing_key_env: None,
            expected_signer_key_id: "signer-source-bootstrap".to_owned(),
        },
        trusted_sources: vec![AuthorityTrustedSource {
            service_id: SERVICE_ID.to_owned(),
            certificate_fingerprint: format!("sha256:{}", "33".repeat(32)),
            allowed_database_ids: vec![DATABASE_ID.to_owned()],
            allowed_operations: vec![
                "read_fence".to_owned(),
                "prepare".to_owned(),
                "reconcile".to_owned(),
                AUTHORITY_OPERATION_SOURCE_BOOTSTRAP_PREPARE.to_owned(),
                AUTHORITY_OPERATION_SOURCE_BOOTSTRAP_FINALIZE.to_owned(),
                AUTHORITY_OPERATION_SOURCE_BOOTSTRAP_RECONCILE.to_owned(),
            ],
        }],
        ..Default::default()
    }
}

async fn bind_fixture_leadership(
    service: &AuthorityService,
    store: &MemoryAuthorityStore,
    instance: &str,
) {
    let lease = store.grant_lease(service.config().quorum.lease_ttl_seconds);
    let token = LeadershipToken::from_record(
        leader_key(
            &service.config().quorum.key_prefix,
            &service.config().quorum.authority_name,
        ),
        &LeadershipTokenRecord::new(&service.config().quorum.authority_name, instance, lease),
    )
    .unwrap();
    assert!(store.try_acquire_leader_key(token.key(), lease, token.value()));
    service.bind_leadership_token(&token).await.unwrap();
}

async fn fixture() -> Fixture {
    let (trust_root, signer_key, root_key, genesis_key) = trust_root_fixture();
    let store = Arc::new(MemoryAuthorityStore::new());
    let service = AuthorityService::new(
        config(&trust_root),
        store.clone(),
        Arc::new(
            ProtectedAuthoritySigner::from_seed([7u8; 32], "signer-source-bootstrap", &trust_root)
                .unwrap(),
        ),
    );
    let mut record = astral_types::AuthorityGenesisRecord {
        authorization_edition: AUTHORIZATION_EDITION,
        authority_id: AUTHORITY_ID.to_owned(),
        root_id: trust_root.root_id.clone(),
        trust_root_digest: trust_root.digest().unwrap(),
        created_at: 1_000,
        genesis_nonce: "genesis-source-bootstrap".to_owned(),
        signed_by_key_id: String::new(),
        signature: String::new(),
    };
    record
        .sign(&genesis_key, "genesis-source-bootstrap")
        .unwrap();
    assert!(service
        .initialize_genesis(&StoredGenesis {
            record,
            trust_root: trust_root.clone()
        })
        .await
        .unwrap());
    bind_fixture_leadership(&service, &store, "source-bootstrap-fixture").await;
    Fixture {
        service,
        store,
        trust_root,
        signer_key,
        root_key,
    }
}

fn source_caller(nonce: &str) -> AuthorityCallerIdentity {
    AuthorityCallerIdentity {
        service_id: SERVICE_ID.to_owned(),
        request_nonce: nonce.to_owned(),
        issued_at: now(),
    }
}

fn bootstrap_bundle() -> AuthoritySourceBootstrapBundle {
    let registry = ResourceRegistry::global();
    let mut template_rules = Vec::new();
    let mut rule_set_entries = Vec::new();
    for resource in registry.list_resources() {
        for action in registry.list_actions(&resource).unwrap_or_default() {
            let priority = 100_000 - template_rules.len() as i32;
            template_rules.push(SourceBootstrapTemplateRule {
                resource_type: resource.clone(),
                resource_id: None,
                action_code: action.clone(),
                effect: "ALLOW".to_owned(),
                condition_json: None,
                priority,
                enabled: true,
            });
            rule_set_entries.push(SourceBootstrapRuleSetEntry {
                resource_type: resource.clone(),
                resource_id: None,
                action_code: action,
                effect: "ALLOW".to_owned(),
                condition_json: None,
                priority,
                enabled: true,
                valid_from: None,
                valid_to: None,
                tenant_id: None,
            });
        }
    }
    AuthoritySourceBootstrapBundle {
        kind: AuthoritySourceBootstrapKind::TemplateRuleSet,
        template: SourceBootstrapTemplateRoot {
            domain_id: 1,
            tenant_id: None,
            parent_template_id: None,
            template_code: "source-bootstrap-template".to_owned(),
            template_name: "source bootstrap".to_owned(),
            card_type: "SYSTEM".to_owned(),
            template_scope: Some("SYSTEM".to_owned()),
            version_no: Some(1),
            default_priority: Some(100),
            default_roles_json: None,
            resource_scope_json: None,
            status: "ACTIVE".to_owned(),
        },
        template_rules,
        rule_set: SourceBootstrapRuleSetRoot {
            name: "source-bootstrap-template".to_owned(),
            code: "source-bootstrap-template".to_owned(),
            description: Some("source bootstrap contract".to_owned()),
            source_type: "TEMPLATE".to_owned(),
            enabled: true,
            tenant_id: None,
        },
        rule_set_entries,
        bindings: Vec::new(),
    }
}

async fn bootstrap_ticket(
    service: &AuthorityService,
    root_key: &SigningKey,
    operation_id: &str,
) -> AuthoritySourceBootstrapTicket {
    let state = service.load_verified_state().await.unwrap();
    let issued_at = now();
    let mut ticket = AuthoritySourceBootstrapTicket {
        protocol_version: AUTHORITY_PROTOCOL_VERSION,
        authorization_edition: AUTHORIZATION_EDITION,
        authority_id: AUTHORITY_ID.to_owned(),
        root_id: state.trust_root.root_id.clone(),
        trust_root_digest: state.trust_root.digest().unwrap(),
        root_key_id: "root-source-bootstrap".to_owned(),
        operation_id: operation_id.to_owned(),
        event_id: format!("event-{operation_id}"),
        nonce: format!("nonce-{operation_id}"),
        issued_at,
        not_before: issued_at,
        expires_at: issued_at + 3_600,
        service_id: SERVICE_ID.to_owned(),
        database_id: DATABASE_ID.to_owned(),
        payload: bootstrap_bundle(),
        signature: String::new(),
    };
    ticket.sign(root_key).unwrap();
    ticket
}

fn bootstrap_prepare(
    ticket: AuthoritySourceBootstrapTicket,
) -> AuthoritySourceBootstrapPrepareRequest {
    AuthoritySourceBootstrapPrepareRequest {
        caller: source_caller("bootstrap-prepare-caller"),
        ticket,
    }
}

fn source_completion(
    prepared: &astral_types::AuthoritySourceBootstrapPrepareResponse,
    source_payload_digest: String,
) -> AuthoritySourceBootstrapCompletion {
    AuthoritySourceBootstrapCompletion {
        reservation_id: prepared.reservation.reservation_id.clone(),
        operation_id: prepared.reservation.operation_id.clone(),
        event_id: prepared.reservation.event_id.clone(),
        ticket_digest: prepared.reservation.ticket_digest.clone(),
        source_payload_digest,
        before_image_digest: digest("2"),
        source_commit_digest: digest("3"),
        after_image_digest: digest("4"),
        source_outcome_digest: digest("5"),
        staged_evidence_digest: digest("6"),
        audit_receipt_digest: digest("7"),
        committed_at: now(),
    }
}

async fn ordinary_proof(
    service: &AuthorityService,
    store: &MemoryAuthorityStore,
    signer_key: &SigningKey,
    request_digest: &str,
) {
    let state = service.load_verified_state().await.unwrap();
    let scope_key = "CARD:7:17:-:ANY".to_owned();
    let issued_at = now();
    let mut proof = astral_types::AuthorizationFenceProof {
        authorization_edition: AUTHORIZATION_EDITION,
        authority_id: AUTHORITY_ID.to_owned(),
        authority_term: state.frontier.authority_term,
        global_fence_sequence: state.frontier.global_fence_sequence,
        scope: AuthorizationAuthorityScope {
            tenant_id: 7,
            card_id: 17,
            user_id: None,
            domain: AuthorizationDomainScope::Any,
        },
        scope_generation: 1,
        revoke_watermark: 0,
        snapshot_hash: digest("8"),
        parent_hash: None,
        scope_certificate_hash: None,
        request_binding_digest: Some(request_digest.to_owned()),
        operation_id: "ordinary-source-operation".to_owned(),
        event_id: "ordinary-source-event".to_owned(),
        key_id: state.frontier.key_id.clone(),
        key_epoch: state.frontier.key_epoch,
        issued_at,
        not_before: issued_at,
        expires_at: issued_at + 3_600,
        request_nonce: "ordinary-proof-nonce".to_owned(),
        proof_id: "ordinary-proof".to_owned(),
        signature: String::new(),
    };
    proof.signature = hex::encode(signer_key.sign(&proof.signing_bytes().unwrap()).to_bytes());
    let receipt = StoredProofReceipt {
        proof_id: proof.proof_id.clone(),
        request_nonce: proof.request_nonce.clone(),
        request_binding_digest: request_digest.to_owned(),
        mutation_kind: AuthorityMutationKind::AuthorizationSource,
        operation_id: proof.operation_id.clone(),
        event_id: proof.event_id.clone(),
        caller_service_id: SERVICE_ID.to_owned(),
        actor_scope_key: scope_key.clone(),
        source_scope_key: scope_key,
        authority_term: state.frontier.authority_term,
        global_fence_sequence: state.frontier.global_fence_sequence,
        key_epoch: state.frontier.key_epoch,
        issued_at,
        expires_at: issued_at + 3_600,
    };
    let keys = KeyLayout::new(&service.config().quorum.key_prefix);
    store
        .execute(
            StoreTxn::new()
                .with_op(StoreOp::PutIfAbsent {
                    key: keys.proof_receipt(&proof.proof_id),
                    value: serde_json::to_vec(&proof).unwrap(),
                })
                .with_op(StoreOp::PutIfAbsent {
                    key: keys.proof_binding(&proof.proof_id),
                    value: serde_json::to_vec(&receipt).unwrap(),
                }),
        )
        .await
        .unwrap();
}

fn ordinary_intent(request_digest: &str) -> AuthoritySourceIntent {
    AuthoritySourceIntent {
        authorization_edition: AUTHORIZATION_EDITION,
        mutation_kind: AuthorityMutationKind::AuthorizationSource,
        operation_id: "ordinary-source-operation".to_owned(),
        event_id: "ordinary-source-event".to_owned(),
        admission_proof_id: "ordinary-proof".to_owned(),
        request_digest: request_digest.to_owned(),
        service_id: SERVICE_ID.to_owned(),
        database_id: DATABASE_ID.to_owned(),
        coverage: AuthorityReservationCoverage::Global,
        before_image_digest: None,
        lease_not_before: now() - 1,
        lease_expires_at: now() + 3_600,
        intent_nonce: "ordinary-intent-nonce".to_owned(),
    }
}

fn protocol_error(error: AuthorityServiceError) -> AuthorityProtocolError {
    match error {
        AuthorityServiceError::Protocol(error) => error,
        other => panic!("expected protocol error, got {other:?}"),
    }
}

#[tokio::test]
async fn source_bootstrap_prepare_finalize_reconcile_is_exact_and_historical() {
    let fixture = fixture().await;
    let ticket = bootstrap_ticket(
        &fixture.service,
        &fixture.root_key,
        "source-bootstrap-normal",
    )
    .await;
    let ticket_digest = ticket.artifact_digest().unwrap();
    let payload_digest = ticket.payload_digest().unwrap();
    let prepare_request = bootstrap_prepare(ticket.clone());
    let prepared = fixture
        .service
        .prepare_root_source_bootstrap(&prepare_request)
        .await
        .unwrap();
    prepared.validate().unwrap();
    assert_eq!(
        prepared.reservation.state,
        AuthoritySourceBootstrapState::Reserved
    );
    assert!(!prepared.read_gate.positive_reads_allowed);
    assert!(prepared.read_gate.global_pending);

    let before_finalize = fixture
        .service
        .reconcile_root_source_bootstrap(&AuthoritySourceBootstrapReconcileRequest {
            caller: source_caller("reconcile-before-finalize"),
            operation_id: ticket.operation_id.clone(),
            ticket_digest: ticket_digest.clone(),
        })
        .await
        .unwrap();
    before_finalize.validate().unwrap();
    assert_eq!(
        before_finalize.reservation.as_ref().unwrap().state,
        AuthoritySourceBootstrapState::Reserved
    );
    assert!(before_finalize.receipt.is_none());

    let completion = source_completion(&prepared, payload_digest.clone());
    let finalize_request = AuthoritySourceBootstrapFinalizeRequest {
        caller: source_caller("finalize-normal"),
        capability: prepared.capability.clone(),
        completion: completion.clone(),
    };
    let finalized = fixture
        .service
        .finalize_root_source_bootstrap(&finalize_request)
        .await
        .unwrap();
    finalized.validate().unwrap();
    assert_eq!(
        finalized.reservation.state,
        AuthoritySourceBootstrapState::Completed
    );
    finalized
        .receipt
        .verify(&fixture.signer_key.verifying_key())
        .unwrap();
    let after_finalize = fixture
        .service
        .reconcile_root_source_bootstrap(&AuthoritySourceBootstrapReconcileRequest {
            caller: source_caller("reconcile-after-finalize"),
            operation_id: ticket.operation_id.clone(),
            ticket_digest: ticket_digest.clone(),
        })
        .await
        .unwrap();
    assert!(after_finalize.read_gate.positive_reads_allowed);
    assert_eq!(
        after_finalize.reservation.as_ref().unwrap(),
        &finalized.reservation
    );
    let mut stale = after_finalize.clone();
    stale.reservation = Some(prepared.reservation.clone());
    assert!(
        stale.validate().is_err(),
        "a terminal receipt cannot accompany a RESERVED copy"
    );
    let mut missing_receipt = after_finalize.clone();
    missing_receipt.receipt = None;
    assert!(missing_receipt.validate().is_err());
    for field in ["operationId", "eventId", "ticketDigest"] {
        let mut tampered = serde_json::to_value(&after_finalize).unwrap();
        tampered["receipt"]["completion"][field] = if field == "ticketDigest" {
            serde_json::json!(digest("a"))
        } else {
            serde_json::json!("different-identity")
        };
        let tampered: astral_types::AuthoritySourceBootstrapReconcileResponse =
            serde_json::from_value(tampered).unwrap();
        assert!(
            tampered.validate().is_err(),
            "accepted completion mismatch in {field}"
        );
    }

    let revision_after_finalize = fixture.store.current_revision();
    let retry = fixture
        .service
        .finalize_root_source_bootstrap(&finalize_request)
        .await
        .unwrap();
    assert_eq!(retry, finalized);
    assert_eq!(fixture.store.current_revision(), revision_after_finalize);

    let mut conflicting_completion = completion;
    conflicting_completion.after_image_digest = digest("9");
    let conflict = fixture
        .service
        .finalize_root_source_bootstrap(&AuthoritySourceBootstrapFinalizeRequest {
            caller: source_caller("finalize-conflict"),
            capability: prepared.capability.clone(),
            completion: conflicting_completion,
        })
        .await
        .unwrap_err();
    assert!(matches!(
        protocol_error(conflict),
        AuthorityProtocolError::StateConflict {
            record: "source_bootstrap_completion",
            state
        } if state == "COMPLETION_CONFLICT"
    ));

    let second_ticket = bootstrap_ticket(
        &fixture.service,
        &fixture.root_key,
        "source-bootstrap-second",
    )
    .await;
    let second_prepared = fixture
        .service
        .prepare_root_source_bootstrap(&bootstrap_prepare(second_ticket.clone()))
        .await
        .unwrap();
    let historical_retry = fixture
        .service
        .finalize_root_source_bootstrap(&finalize_request)
        .await
        .unwrap();
    assert_eq!(
        historical_retry, finalized,
        "another GLOBAL owner cannot invalidate an exact historical receipt"
    );
    let second_finalized = fixture
        .service
        .finalize_root_source_bootstrap(&AuthoritySourceBootstrapFinalizeRequest {
            caller: source_caller("finalize-second"),
            capability: second_prepared.capability.clone(),
            completion: source_completion(
                &second_prepared,
                second_ticket.payload_digest().unwrap(),
            ),
        })
        .await
        .unwrap();
    assert!(
        second_finalized.global_frontier.global_fence_sequence
            > finalized.global_frontier.global_fence_sequence
    );

    let reconciled = fixture
        .service
        .reconcile_root_source_bootstrap(&AuthoritySourceBootstrapReconcileRequest {
            caller: source_caller("reconcile-history"),
            operation_id: ticket.operation_id,
            ticket_digest,
        })
        .await
        .unwrap();
    reconciled.validate().unwrap();
    assert_eq!(reconciled.receipt, Some(finalized.receipt.clone()));
    assert_eq!(
        reconciled.receipt.as_ref().unwrap().frontier,
        finalized.receipt.frontier
    );
    assert_eq!(reconciled.global_frontier, second_finalized.global_frontier);
}

#[tokio::test]
async fn root_ticket_tamper_wrong_binding_and_expiry_are_refused() {
    let fixture = fixture().await;

    let mut tampered = bootstrap_ticket(
        &fixture.service,
        &fixture.root_key,
        "source-bootstrap-tamper",
    )
    .await;
    tampered.payload.template.template_name = "tampered".to_owned();
    let error = fixture
        .service
        .prepare_root_source_bootstrap(&bootstrap_prepare(tampered))
        .await
        .unwrap_err();
    assert!(matches!(
        protocol_error(error),
        AuthorityProtocolError::InvalidSignature
    ));

    let mut wrong_binding = bootstrap_ticket(
        &fixture.service,
        &fixture.root_key,
        "source-bootstrap-binding",
    )
    .await;
    wrong_binding.root_id = "other-root".to_owned();
    wrong_binding.sign(&fixture.root_key).unwrap();
    let error = fixture
        .service
        .prepare_root_source_bootstrap(&bootstrap_prepare(wrong_binding))
        .await
        .unwrap_err();
    assert!(matches!(
        protocol_error(error),
        AuthorityProtocolError::TrustRootMismatch
    ));

    let current = now();
    let mut expired = bootstrap_ticket(
        &fixture.service,
        &fixture.root_key,
        "source-bootstrap-expired",
    )
    .await;
    expired.issued_at = current - 100;
    expired.not_before = current - 100;
    expired.expires_at = current - 1;
    expired.sign(&fixture.root_key).unwrap();
    let error = fixture
        .service
        .prepare_root_source_bootstrap(&bootstrap_prepare(expired))
        .await
        .unwrap_err();
    assert!(matches!(
        protocol_error(error),
        AuthorityProtocolError::NotCurrentlyValid
    ));
}

#[tokio::test]
async fn bootstrap_and_ordinary_global_source_reservations_are_mutually_exclusive() {
    let first = fixture().await;
    let first_ticket =
        bootstrap_ticket(&first.service, &first.root_key, "bootstrap-blocks-source").await;
    first
        .service
        .prepare_root_source_bootstrap(&bootstrap_prepare(first_ticket))
        .await
        .unwrap();
    ordinary_proof(
        &first.service,
        &first.store,
        &first.signer_key,
        &digest("1"),
    )
    .await;
    let ordinary_error = first
        .service
        .prepare_source_mutation(&AuthorityPrepareRequest {
            caller: source_caller("ordinary-after-bootstrap"),
            intent: ordinary_intent(&digest("1")),
        })
        .await
        .unwrap_err();
    assert!(matches!(
        protocol_error(ordinary_error),
        AuthorityProtocolError::ReadsBlocked { .. }
    ));

    let second = fixture().await;
    ordinary_proof(
        &second.service,
        &second.store,
        &second.signer_key,
        &digest("1"),
    )
    .await;
    second
        .service
        .prepare_source_mutation(&AuthorityPrepareRequest {
            caller: source_caller("ordinary-before-bootstrap"),
            intent: ordinary_intent(&digest("1")),
        })
        .await
        .unwrap();
    let second_ticket =
        bootstrap_ticket(&second.service, &second.root_key, "source-blocks-bootstrap").await;
    let bootstrap_error = second
        .service
        .prepare_root_source_bootstrap(&bootstrap_prepare(second_ticket))
        .await
        .unwrap_err();
    assert!(matches!(
        protocol_error(bootstrap_error),
        AuthorityProtocolError::ReadsBlocked { .. }
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_root_source_bootstrap_prepare_uses_frontier_and_lock_cas() {
    let first = fixture().await;
    let store = first.store.clone();
    let trust_root = first.trust_root.clone();
    let second = AuthorityService::new(
        config(&trust_root),
        store.clone(),
        Arc::new(
            ProtectedAuthoritySigner::from_seed([7u8; 32], "signer-source-bootstrap", &trust_root)
                .unwrap(),
        ),
    );
    let leader_record = store
        .get(&leader_key(
            &first.service.config().quorum.key_prefix,
            AUTHORITY_NAME,
        ))
        .await
        .unwrap()
        .unwrap();
    let second_token = LeadershipToken::from_durable_bytes(
        leader_key(&first.service.config().quorum.key_prefix, AUTHORITY_NAME),
        leader_record.value,
    );
    second.bind_leadership_token(&second_token).await.unwrap();

    let first_service = Arc::new(first.service);
    let second_service = Arc::new(second);
    let first_ticket = bootstrap_ticket(&first_service, &first.root_key, "bootstrap-cas-one").await;
    let second_ticket =
        bootstrap_ticket(&second_service, &first.root_key, "bootstrap-cas-two").await;
    let first_request = bootstrap_prepare(first_ticket);
    let second_request = bootstrap_prepare(second_ticket);

    let first_task = {
        let service = first_service.clone();
        tokio::spawn(async move { service.prepare_root_source_bootstrap(&first_request).await })
    };
    let second_task = {
        let service = second_service.clone();
        tokio::spawn(async move { service.prepare_root_source_bootstrap(&second_request).await })
    };
    let first_result = first_task.await.unwrap();
    let second_result = second_task.await.unwrap();
    let successes = (first_result.is_ok() as usize) + (second_result.is_ok() as usize);
    assert_eq!(
        successes, 1,
        "one CAS winner must own the global bootstrap lock"
    );
    let loser = if first_result.is_err() {
        first_result.unwrap_err()
    } else {
        second_result.unwrap_err()
    };
    assert!(matches!(
        loser,
        AuthorityServiceError::Protocol(AuthorityProtocolError::ReadsBlocked { .. })
            | AuthorityServiceError::Protocol(AuthorityProtocolError::StateConflict { .. })
    ));
}

#[tokio::test]
async fn finalize_requires_exact_commit_binding_and_never_replays_source() {
    let fixture = fixture().await;
    let ticket = bootstrap_ticket(
        &fixture.service,
        &fixture.root_key,
        "source-bootstrap-binding-proof",
    )
    .await;
    let payload_digest = ticket.payload_digest().unwrap();
    let prepared = fixture
        .service
        .prepare_root_source_bootstrap(&bootstrap_prepare(ticket.clone()))
        .await
        .unwrap();

    let mut wrong_payload = source_completion(&prepared, payload_digest.clone());
    wrong_payload.source_payload_digest = digest("f");
    let error = fixture
        .service
        .finalize_root_source_bootstrap(&AuthoritySourceBootstrapFinalizeRequest {
            caller: source_caller("wrong-source-payload"),
            capability: prepared.capability.clone(),
            completion: wrong_payload,
        })
        .await
        .unwrap_err();
    assert!(matches!(
        protocol_error(error),
        AuthorityProtocolError::DigestMismatch {
            field: "source_payload_digest"
        }
    ));

    let mut wrong_reservation = prepared.capability.clone();
    wrong_reservation.reservation_id = "different-reservation".to_owned();
    let error = fixture
        .service
        .finalize_root_source_bootstrap(&AuthoritySourceBootstrapFinalizeRequest {
            caller: source_caller("wrong-reservation-binding"),
            capability: wrong_reservation,
            completion: source_completion(&prepared, payload_digest.clone()),
        })
        .await
        .unwrap_err();
    assert!(matches!(
        protocol_error(error),
        AuthorityProtocolError::ScopeMismatch
    ));

    let finalize_request = AuthoritySourceBootstrapFinalizeRequest {
        caller: source_caller("exact-source-commit"),
        capability: prepared.capability.clone(),
        completion: source_completion(&prepared, payload_digest),
    };
    let finalized = fixture
        .service
        .finalize_root_source_bootstrap(&finalize_request)
        .await
        .unwrap();
    let frontier_after_commit = finalized.global_frontier.clone();
    let revision_after_commit = fixture.store.current_revision();

    let retry = fixture
        .service
        .finalize_root_source_bootstrap(&finalize_request)
        .await
        .unwrap();
    assert_eq!(retry.receipt, finalized.receipt);
    assert_eq!(retry.global_frontier, frontier_after_commit);
    assert_eq!(fixture.store.current_revision(), revision_after_commit);

    let reconciled = fixture
        .service
        .reconcile_root_source_bootstrap(&AuthoritySourceBootstrapReconcileRequest {
            caller: source_caller("exact-source-reconcile"),
            operation_id: finalized.reservation.operation_id.clone(),
            ticket_digest: finalized.reservation.ticket_digest.clone(),
        })
        .await
        .unwrap();
    assert_eq!(reconciled.receipt, Some(finalized.receipt));
    assert_eq!(
        reconciled.reservation.unwrap().state,
        AuthoritySourceBootstrapState::Completed
    );
}
