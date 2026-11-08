#![cfg(feature = "service")]

//! Bootstrap contract tests (pure Rust, no external environment).
//!
//! These tests drive the root-signed bootstrap artifact lifecycle against a
//! real [`AuthorityService`] over the in-memory store (etcd-equivalent CAS
//! semantics). They cover the §15.9.4 genesis contract: root-registry
//! signature verification, expiry, exact-frontier CAS, idempotent re-install
//! with same-operation/different-digest refusal, unknown-outcome
//! reconciliation by stable identity, first-certificate provenance, fresh
//! proof reads after bootstrap, historical reconciliation across a legally
//! advanced pointer, and re-signed-substitute rejection. Overlaps
//! deliberately avoided with `store_contract.rs` (the ordinary
//! prepare/commit/certify lifecycle).

use std::path::PathBuf;
use std::sync::Arc;

use astral_authority::bootstrap::run_sign_bootstrap;
use astral_authority::config::{
    AuthorityIdentityConfig, AuthorityServiceConfig, AuthoritySignerConfig, AuthorityTrustedSource,
};
use astral_authority::error::AuthorityServiceError;
use astral_authority::service::leadership::{leader_key, LeadershipToken, LeadershipTokenRecord};
use astral_authority::service::AuthorityService;
use astral_authority::service::StoredScopeCurrent;
use astral_authority::signing::ProtectedAuthoritySigner;
use astral_authority::store::memory::MemoryAuthorityStore;
use astral_authority::store::{AuthorityStore, KeyLayout, StoreOp, StoreTxn};
use astral_types::{
    AuthorityBootstrapArtifact, AuthorityBootstrapScopeSnapshot, AuthorityCallerIdentity,
    AuthorityFenceReadRequest, AuthorityManifestIdentity, AuthorityMutationKind,
    AuthorityOrgMemberSubject, AuthorityOrgScope, AuthorityProtocolError, AuthorityProtocolScope,
    AuthorityReadProofRequest, AuthorityReservationCoverage, AuthorityReservationState,
    AuthorityRootKey, AuthorityRootKeyRole, AuthorityScopePublicationCertificate,
    AuthorityScopeReservation, AuthoritySourceIntent, AuthorityTrustRoot,
    AuthorizationAuthorityScope, AuthorizationDomainScope, GlobalAuthorityFrontier,
    AUTHORITY_PROTOCOL_VERSION, AUTHORIZATION_EDITION,
};
use ed25519_dalek::SigningKey;

const SERVICE_ID: &str = "bootstrap-source-svc";
const DATABASE_ID: &str = "db-bootstrap";
const REQUEST_DIGEST: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
const CARD_SCOPE_KEY: &str = "CARD:7:17:-:ANY";

fn trust_root_fixture() -> (AuthorityTrustRoot, SigningKey, SigningKey, SigningKey) {
    let signer = SigningKey::from_bytes(&[7u8; 32]);
    let root = SigningKey::from_bytes(&[21u8; 32]);
    let genesis = SigningKey::from_bytes(&[22u8; 32]);
    let trust_root = AuthorityTrustRoot {
        root_id: "root-bootstrap".to_owned(),
        keys: vec![
            AuthorityRootKey {
                key_id: "signer-bootstrap".to_owned(),
                key_epoch: 1,
                role: AuthorityRootKeyRole::Signer,
                verifying_key_hex: hex::encode(signer.verifying_key().as_bytes()),
            },
            AuthorityRootKey {
                key_id: "root-bootstrap".to_owned(),
                key_epoch: 1,
                role: AuthorityRootKeyRole::Root,
                verifying_key_hex: hex::encode(root.verifying_key().as_bytes()),
            },
            AuthorityRootKey {
                key_id: "genesis-bootstrap".to_owned(),
                key_epoch: 1,
                role: AuthorityRootKeyRole::Genesis,
                verifying_key_hex: hex::encode(genesis.verifying_key().as_bytes()),
            },
        ],
        created_at: 1_000,
    };
    (trust_root, signer, root, genesis)
}

fn test_config() -> AuthorityServiceConfig {
    let (trust_root, _, _, _) = trust_root_fixture();
    AuthorityServiceConfig {
        identity: AuthorityIdentityConfig {
            authority_id: "authority-bootstrap".to_owned(),
            pinned_genesis_trust_root_digest: trust_root.digest().unwrap(),
        },
        signer: AuthoritySignerConfig {
            signing_key_path: Some(PathBuf::from("/keys/signer.seed")),
            signing_key_env: None,
            expected_signer_key_id: "signer-bootstrap".to_owned(),
        },
        // Registered trusted source so the post-bootstrap read path
        // (read_fence + fresh proof) can authorize callers.
        trusted_sources: vec![AuthorityTrustedSource {
            service_id: SERVICE_ID.to_owned(),
            certificate_fingerprint: format!("sha256:{}", "33".repeat(32)),
            allowed_database_ids: vec![DATABASE_ID.to_owned()],
            allowed_operations: vec!["read_fence".to_owned()],
        }],
        ..Default::default()
    }
}

/// Seed a REAL lease-backed leadership record for the fixture service and
/// bind it through the production `bind_leadership_token` readback. Raising
/// only the liveness flag would no longer authorize any mutation (§15.9.1):
/// the durable fence lives in the lease-backed leader key.
async fn seed_fixture_leadership(service: &AuthorityService, store: &MemoryAuthorityStore) {
    let authority = service.config().quorum.authority_name.clone();
    let lease = store.grant_lease(service.config().quorum.lease_ttl_seconds);
    let token = LeadershipToken::from_record(
        leader_key(&service.config().quorum.key_prefix, &authority),
        &LeadershipTokenRecord::new(&authority, "bootstrap-contract-fixture", lease),
    )
    .unwrap();
    assert!(
        store.try_acquire_leader_key(
            token.key(),
            lease,
            &token.record().expect("fixture token decodes").encode()
        ),
        "fixture leader key must be free before acquisition"
    );
    service.bind_leadership_token(&token).await.unwrap();
}

/// Genesis-initialized service with a bound lease-backed leadership term.
async fn bootstrap_service() -> (
    AuthorityService,
    Arc<MemoryAuthorityStore>,
    KeyLayout,
    SigningKey,
    SigningKey,
) {
    let (trust_root, signer_key, root_key, genesis_key) = trust_root_fixture();
    let config = test_config();
    let signer = Arc::new(
        ProtectedAuthoritySigner::from_seed([7u8; 32], "signer-bootstrap", &trust_root).unwrap(),
    );
    let store = Arc::new(MemoryAuthorityStore::new());
    let service = AuthorityService::new(config, store.clone(), signer);

    let mut record = astral_types::AuthorityGenesisRecord {
        authorization_edition: AUTHORIZATION_EDITION,
        authority_id: "authority-bootstrap".to_owned(),
        root_id: trust_root.root_id.clone(),
        trust_root_digest: trust_root.digest().unwrap(),
        created_at: 1_000,
        genesis_nonce: "genesis-nonce-bootstrap".to_owned(),
        signed_by_key_id: String::new(),
        signature: String::new(),
    };
    record.sign(&genesis_key, "genesis-bootstrap").unwrap();
    let created = service
        .initialize_genesis(&astral_authority::service::StoredGenesis {
            record,
            trust_root: trust_root.clone(),
        })
        .await
        .unwrap();
    assert!(created, "first genesis must create");

    seed_fixture_leadership(&service, &store).await;

    let keys = KeyLayout::new(service.config().quorum.key_prefix.as_str());
    (service, store, keys, signer_key, root_key)
}

fn card_snapshot(operation_id: &str) -> AuthorityBootstrapScopeSnapshot {
    AuthorityBootstrapScopeSnapshot {
        scope: AuthorityProtocolScope::Card(AuthorizationAuthorityScope {
            tenant_id: 7,
            card_id: 17,
            user_id: None,
            domain: AuthorizationDomainScope::Any,
        }),
        snapshot_hash: "b1".repeat(32),
        generation: 1,
        revoke_watermark: 0,
        manifests: vec![AuthorityManifestIdentity {
            aggregate_type: "grant".to_owned(),
            aggregate_id: 1,
            manifest_digest_hex: "aa".repeat(32),
            dependency_hash_hex: "bb".repeat(32),
            semantic_hash_hex: "cc".repeat(32),
            generation: 1,
            revoke_fence: 0,
            event_id: "bootstrap-event".to_owned(),
            operation_id: operation_id.to_owned(),
        }],
    }
}

fn org_snapshot(operation_id: &str) -> AuthorityBootstrapScopeSnapshot {
    AuthorityBootstrapScopeSnapshot {
        scope: AuthorityProtocolScope::Org(AuthorityOrgScope {
            tenant_id: 5,
            root_tenant_id: None,
            member: AuthorityOrgMemberSubject {
                user_id: 11,
                identity_card_id: 12,
                card_id: 13,
            },
        }),
        snapshot_hash: "b2".repeat(32),
        generation: 1,
        revoke_watermark: 0,
        manifests: vec![AuthorityManifestIdentity {
            aggregate_type: "org_publication".to_owned(),
            aggregate_id: 2,
            manifest_digest_hex: "ad".repeat(32),
            dependency_hash_hex: "be".repeat(32),
            semantic_hash_hex: "cf".repeat(32),
            generation: 1,
            revoke_fence: 0,
            event_id: "bootstrap-event".to_owned(),
            operation_id: operation_id.to_owned(),
        }],
    }
}

/// Unsigned preflight artifact bound to the CURRENT durable frontier. The
/// validity window is anchored at the real wall clock so a fresh install
/// accepts it while an artificially backdated window expires.
async fn build_unsigned_artifact(
    service: &AuthorityService,
    operation_id: &str,
) -> AuthorityBootstrapArtifact {
    let state = service.load_verified_state().await.unwrap();
    let frontier: &GlobalAuthorityFrontier = &state.frontier;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0);
    AuthorityBootstrapArtifact {
        protocol_version: AUTHORITY_PROTOCOL_VERSION,
        authorization_edition: AUTHORIZATION_EDITION,
        authority_id: "authority-bootstrap".to_owned(),
        root_id: state.trust_root.root_id.clone(),
        trust_root_digest: state.trust_root.digest().unwrap(),
        expected_authority_term: frontier.authority_term,
        expected_global_fence_sequence: frontier.global_fence_sequence,
        expected_key_epoch: frontier.key_epoch,
        expected_global_chain_digest: frontier.global_chain_digest.clone(),
        operation_id: operation_id.to_owned(),
        event_id: "bootstrap-event".to_owned(),
        nonce: format!("nonce-{operation_id}"),
        issued_at: now,
        not_before: now,
        expires_at: now + 3_600,
        snapshots: vec![card_snapshot(operation_id), org_snapshot(operation_id)],
        root_key_id: "root-bootstrap".to_owned(),
        signature: String::new(),
    }
}

fn sign_artifact(
    mut artifact: AuthorityBootstrapArtifact,
    root_key: &SigningKey,
) -> AuthorityBootstrapArtifact {
    artifact.sign(root_key).unwrap();
    artifact
}

/// Snapshots in the canonical (scope store key) order used by the installer.
fn canonical_snapshot_order(
    artifact: &AuthorityBootstrapArtifact,
) -> Vec<(String, &AuthorityBootstrapScopeSnapshot)> {
    let mut ordered: Vec<(String, &AuthorityBootstrapScopeSnapshot)> = artifact
        .snapshots
        .iter()
        .map(|snapshot| (snapshot.scope.store_key_text().unwrap(), snapshot))
        .collect();
    ordered.sort_by(|left, right| left.0.cmp(&right.0));
    ordered
}

fn assert_service_error(
    error: AuthorityServiceError,
    expected: impl Fn(&AuthorityServiceError) -> bool,
    context: &str,
) {
    assert!(expected(&error), "{context}: unexpected error {error:?}");
}

async fn seed_blocking_reservation(store: &MemoryAuthorityStore, keys: &KeyLayout) {
    let intent = AuthoritySourceIntent {
        authorization_edition: AUTHORIZATION_EDITION,
        mutation_kind: AuthorityMutationKind::AuthorizationSource,
        operation_id: "op-blocking".to_owned(),
        event_id: "evt-blocking".to_owned(),
        admission_proof_id: "prf-blocked".to_owned(),
        request_digest: REQUEST_DIGEST.to_owned(),
        service_id: SERVICE_ID.to_owned(),
        database_id: DATABASE_ID.to_owned(),
        coverage: AuthorityReservationCoverage::Global,
        before_image_digest: None,
        lease_not_before: 1_000,
        lease_expires_at: 9_000,
        intent_nonce: "intent-nonce-block".to_owned(),
    };
    let reservation = AuthorityScopeReservation {
        reservation_id: "res-blocking".to_owned(),
        intent_digest: "7a".repeat(32),
        intent,
        state: AuthorityReservationState::Reserved,
        authority_term: 1,
        fence_sequence_at_prepare: 1,
        created_at: 1_000,
        updated_at: 1_000,
        committed_at: None,
        source_commit_digest: None,
        after_image_digest: None,
        certificate_id: None,
        certified_scopes: Vec::new(),
        source_outcome_digest: None,
    };
    store
        .execute(StoreTxn::new().with_op(StoreOp::Put {
            key: keys.reservation("res-blocking"),
            value: serde_json::to_vec(&reservation).unwrap(),
        }))
        .await
        .unwrap();
}

#[tokio::test]
async fn artifact_signature_binds_registry_and_reconciles_to_none_before_install() {
    let (service, _store, _keys, _signer_key, root_key) = bootstrap_service().await;
    let unsigned = build_unsigned_artifact(&service, "op-sign").await;
    let signed = sign_artifact(unsigned.clone(), &root_key);
    let digest = signed.artifact_digest().unwrap();

    // Deterministic signing: the same content yields the same digest.
    let again = sign_artifact(unsigned, &root_key);
    assert_eq!(digest, again.artifact_digest().unwrap());

    let (trust_root, _, _, _) = trust_root_fixture();
    let root_entry = trust_root.root_key().unwrap();
    signed.verify(&root_entry.verifying_key().unwrap()).unwrap();

    // Any content change invalidates the signature.
    let mut tampered = signed.clone();
    tampered.expected_global_fence_sequence = 99;
    assert!(matches!(
        tampered.verify(&root_entry.verifying_key().unwrap()),
        Err(AuthorityProtocolError::InvalidSignature)
    ));

    // Nothing durable exists for this artifact: reconcile reports None and
    // never resends anything.
    assert!(service
        .reconcile_bootstrap(&signed)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn bootstrap_installs_first_certificates_with_full_provenance() {
    let (service, store, keys, signer_key, root_key) = bootstrap_service().await;
    let signed = sign_artifact(
        build_unsigned_artifact(&service, "op-install").await,
        &root_key,
    );
    let artifact_digest = signed.artifact_digest().unwrap();

    let outcome = service.install_bootstrap(&signed).await.unwrap();
    assert!(outcome.newly_applied);
    assert_eq!(outcome.receipt.certificate_hashes.len(), 2);
    assert_eq!(outcome.receipt.certificate_ids.len(), 2);

    let state = service.load_verified_state().await.unwrap();
    // The frontier advanced exactly once; the certificates bind the
    // artifact-approved frontier (term 1, fence 1), not the post-install one.
    assert_eq!(state.frontier.global_fence_sequence, 2);
    assert_eq!(state.frontier.authority_term, 1);

    let ordered = canonical_snapshot_order(&signed);
    for (index, certificate_id) in outcome.receipt.certificate_ids.iter().enumerate() {
        let (scope_key, snapshot) = &ordered[index];
        let record = store
            .get(&keys.certificate(certificate_id))
            .await
            .unwrap()
            .expect("bootstrap certificate is durable");
        let certificate: AuthorityScopePublicationCertificate =
            serde_json::from_slice(&record.value).unwrap();
        // Signature verifies against the attested SIGNER key; provenance is
        // obvious and recomputable from the artifact digest.
        certificate.verify(&signer_key.verifying_key()).unwrap();
        assert_eq!(&certificate.scope.store_key_text().unwrap(), scope_key);
        assert_eq!(certificate.certificate_id, *certificate_id);
        assert_eq!(certificate.intent_digest, artifact_digest);
        assert_eq!(
            certificate.reservation_id,
            format!("bootstrap-{artifact_digest}")
        );
        assert_eq!(certificate.operation_id, signed.operation_id);
        assert_eq!(certificate.event_id, signed.event_id);
        assert_eq!(certificate.parent_certificate_hash, None);
        assert_eq!(certificate.before_image_digest, None);
        assert_eq!(certificate.authority_term, 1);
        assert_eq!(certificate.global_fence_sequence, 1);
        assert_eq!(
            certificate.manifests, snapshot.manifests,
            "full manifest vector is bound"
        );
        // The receipt hash is the record digest of the installed certificate.
        assert_eq!(
            certificate.record_digest().unwrap(),
            outcome.receipt.certificate_hashes[index]
        );
    }

    // Durable scope pointers project the approved snapshots.
    for (scope_key, snapshot) in &ordered {
        let pointer_record = store
            .get(&keys.scope_current(scope_key))
            .await
            .unwrap()
            .expect("bootstrap pointer is durable");
        let pointer: StoredScopeCurrent = serde_json::from_slice(&pointer_record.value).unwrap();
        assert_eq!(pointer.scope_key_text, *scope_key);
        assert_eq!(pointer.snapshot_hash, snapshot.snapshot_hash);
        assert_eq!(pointer.scope_generation, 1);
        assert_eq!(pointer.revoke_watermark, 0);
    }

    // Stable operation identity: the operation index and the receipt are
    // durable under both stable keys.
    let prefix = service.config().quorum.key_prefix.trim_matches('/');
    let operation_key = format!("{prefix}/bootstrap-operations/{}", signed.operation_id);
    assert!(store.get(&operation_key).await.unwrap().is_some());
    let receipt_key = format!("{prefix}/bootstrap/{artifact_digest}");
    assert!(store.get(&receipt_key).await.unwrap().is_some());
}

#[tokio::test]
async fn bootstrap_reinstall_is_idempotent_and_same_operation_with_other_digest_is_refused() {
    let (service, _store, _keys, _signer_key, root_key) = bootstrap_service().await;
    let signed = sign_artifact(
        build_unsigned_artifact(&service, "op-idempotent").await,
        &root_key,
    );
    let first = service.install_bootstrap(&signed).await.unwrap();
    assert!(first.newly_applied);

    // Same artifact: reconciled by read-back, no re-issue.
    let second = service.install_bootstrap(&signed).await.unwrap();
    assert!(!second.newly_applied);
    assert_eq!(first.receipt, second.receipt);

    // Same operation id with DIFFERENT approved content: refused.
    let mut conflicting = build_unsigned_artifact(&service, "op-idempotent").await;
    conflicting.snapshots[0].snapshot_hash = "cd".repeat(32);
    let conflicting = sign_artifact(conflicting, &root_key);
    assert_ne!(
        conflicting.artifact_digest().unwrap(),
        signed.artifact_digest().unwrap()
    );
    let error = service.install_bootstrap(&conflicting).await.unwrap_err();
    assert_service_error(
        error,
        |error| {
            matches!(
                error,
                AuthorityServiceError::Protocol(AuthorityProtocolError::AlreadyExists { .. })
            )
        },
        "same operation with different digest must be refused",
    );
}

#[tokio::test]
async fn bootstrap_rejects_expired_artifact_and_stale_frontier() {
    let (service, _store, _keys, _signer_key, root_key) = bootstrap_service().await;

    // Expired artifact: never newly installable.
    let mut expired = build_unsigned_artifact(&service, "op-expired").await;
    expired.issued_at -= 3_800;
    expired.not_before -= 3_800;
    expired.expires_at -= 3_700;
    let expired = sign_artifact(expired, &root_key);
    let error = service.install_bootstrap(&expired).await.unwrap_err();
    assert_service_error(
        error,
        |error| {
            matches!(
                error,
                AuthorityServiceError::Protocol(AuthorityProtocolError::NotCurrentlyValid)
            )
        },
        "expired artifact must be refused",
    );

    // Stale expected frontier: exact CAS refuses any divergence.
    let mut stale = build_unsigned_artifact(&service, "op-stale").await;
    stale.expected_global_chain_digest = "ef".repeat(32);
    let stale = sign_artifact(stale, &root_key);
    let error = service.install_bootstrap(&stale).await.unwrap_err();
    assert_service_error(
        error,
        |error| {
            matches!(
                error,
                AuthorityServiceError::Protocol(AuthorityProtocolError::FrontierDiverged)
            )
        },
        "stale expected frontier must be refused",
    );

    // After one install, a different operation pinned to the OLD frontier is
    // also refused: the durable frontier moved. The scopes differ from the
    // first artifact so the refusal lands on the frontier check, not on the
    // scope-absence check.
    let genesis_chain_digest = service
        .load_verified_state()
        .await
        .unwrap()
        .frontier
        .global_chain_digest;
    let first = sign_artifact(
        build_unsigned_artifact(&service, "op-first").await,
        &root_key,
    );
    service.install_bootstrap(&first).await.unwrap();
    let mut second = build_unsigned_artifact(&service, "op-second").await;
    second.expected_authority_term = 1;
    second.expected_global_fence_sequence = 1;
    second.expected_global_chain_digest = genesis_chain_digest;
    second.snapshots[0] = card_snapshot("op-second-card-18");
    second.snapshots[0].scope = AuthorityProtocolScope::Card(AuthorizationAuthorityScope {
        tenant_id: 7,
        card_id: 18,
        user_id: None,
        domain: AuthorizationDomainScope::Any,
    });
    assert_eq!(second.expected_global_fence_sequence, 1);
    let second = sign_artifact(second, &root_key);
    let error = service.install_bootstrap(&second).await.unwrap_err();
    assert_service_error(
        error,
        |error| {
            matches!(
                error,
                AuthorityServiceError::Protocol(AuthorityProtocolError::FrontierDiverged)
            )
        },
        "post-install artifact pinned to the old frontier must be refused",
    );
}

#[tokio::test]
async fn bootstrap_rejects_existing_scope_and_never_lands_over_reservations() {
    let (service, store, keys, _signer_key, root_key) = bootstrap_service().await;
    let signed = sign_artifact(
        build_unsigned_artifact(&service, "op-existing").await,
        &root_key,
    );

    // An existing scope pointer refuses the whole artifact.
    store
        .execute(StoreTxn::new().with_op(StoreOp::Put {
            key: keys.scope_current(CARD_SCOPE_KEY),
            value: b"pre-existing".to_vec(),
        }))
        .await
        .unwrap();
    let error = service.install_bootstrap(&signed).await.unwrap_err();
    assert_service_error(
        error,
        |error| {
            matches!(
                error,
                AuthorityServiceError::Protocol(AuthorityProtocolError::AlreadyExists { .. })
            )
        },
        "existing scope must be refused",
    );
    store
        .execute(StoreTxn::new().with_op(StoreOp::Delete {
            key: keys.scope_current(CARD_SCOPE_KEY),
        }))
        .await
        .unwrap();

    // A blocking reservation keeps a FRESH bootstrap out entirely.
    seed_blocking_reservation(&store, &keys).await;
    let error = service.install_bootstrap(&signed).await.unwrap_err();
    assert_service_error(
        error,
        |error| {
            matches!(
                error,
                AuthorityServiceError::Protocol(AuthorityProtocolError::ReadsBlocked { .. })
            )
        },
        "blocking reservation must refuse the fresh install",
    );
}

#[tokio::test]
async fn bootstrap_reinstall_reconciles_before_the_barrier_while_other_source_is_pending() {
    let (service, store, keys, _signer_key, root_key) = bootstrap_service().await;
    let signed = sign_artifact(
        build_unsigned_artifact(&service, "op-pending-reinstall").await,
        &root_key,
    );
    let installed = service.install_bootstrap(&signed).await.unwrap();
    assert!(installed.newly_applied);

    // Another legitimate source operation is now pending (GLOBAL coverage).
    seed_blocking_reservation(&store, &keys).await;

    // A repeat install of the SAME artifact must reconcile read-back before
    // any barrier refusal: it is read-only, re-issues nothing, and is not
    // falsely rejected by the unrelated pending source operation.
    let again = service.install_bootstrap(&signed).await.unwrap();
    assert!(!again.newly_applied);
    assert_eq!(again.receipt, installed.receipt);

    // A FRESH artifact under the same pending barrier is still refused.
    let fresh = sign_artifact(
        build_unsigned_artifact(&service, "op-pending-fresh").await,
        &root_key,
    );
    let error = service.install_bootstrap(&fresh).await.unwrap_err();
    assert_service_error(
        error,
        |error| {
            matches!(
                error,
                AuthorityServiceError::Protocol(AuthorityProtocolError::ReadsBlocked { .. })
            )
        },
        "fresh install must still refuse under a pending source operation",
    );
}

#[tokio::test]
async fn bootstrap_refuses_standby_and_foreign_role_signature() {
    let (service, store, _keys, signer_key, root_key) = bootstrap_service().await;
    let signed = sign_artifact(
        build_unsigned_artifact(&service, "op-standby").await,
        &root_key,
    );

    // A standby never installs. Under the §15.9.1 fence the durable term —
    // not the liveness flag — is what refuses: expire the lease so the
    // leader key (and the fence) disappears, exactly like an etcd TTL.
    let leader_record_key = leader_key(
        &service.config().quorum.key_prefix,
        &service.config().quorum.authority_name,
    );
    let durable = store.get(&leader_record_key).await.unwrap().unwrap();
    let term = LeadershipTokenRecord::decode(&durable.value).unwrap();
    assert!(store.expire_lease(term.lease));
    let error = service.install_bootstrap(&signed).await.unwrap_err();
    assert_service_error(
        error,
        |error| matches!(error, AuthorityServiceError::NotLeader),
        "standby must refuse the install",
    );
    // Re-elect (new lease, new term) so the following cases run serving-side.
    seed_fixture_leadership(&service, &store).await;

    // An artifact signed by the SIGNER-role key is not ROOT-signed: the
    // registry verification refuses it (the declared root_key_id names the
    // ROOT key, so the signature cannot verify).
    let mut rogue = build_unsigned_artifact(&service, "op-rogue").await;
    let rogue_signature = ed25519_dalek::Signer::sign(&signer_key, &rogue.signing_bytes().unwrap());
    rogue.signature = hex::encode(rogue_signature.to_bytes());
    let error = service.install_bootstrap(&rogue).await.unwrap_err();
    assert_service_error(
        error,
        |error| {
            matches!(
                error,
                AuthorityServiceError::Protocol(AuthorityProtocolError::InvalidSignature)
            )
        },
        "signer-role signature must be refused",
    );
}

#[tokio::test]
async fn bootstrap_unknown_reconciles_by_operation_id_without_resending() {
    let (service, _store, _keys, _signer_key, root_key) = bootstrap_service().await;
    let signed = sign_artifact(
        build_unsigned_artifact(&service, "op-unknown").await,
        &root_key,
    );
    let installed = service.install_bootstrap(&signed).await.unwrap();
    assert!(installed.newly_applied);

    // Read-back reconciliation by stable identity re-verifies every receipt
    // certificate against the registry and returns the same receipt.
    let reconciled = service.reconcile_bootstrap(&signed).await.unwrap().unwrap();
    assert!(!reconciled.newly_applied);
    assert_eq!(reconciled.receipt, installed.receipt);

    // A never-installed artifact reconciles to None: nothing durable, and
    // nothing is resent.
    let other = sign_artifact(
        build_unsigned_artifact(&service, "op-never-installed").await,
        &root_key,
    );
    assert!(service.reconcile_bootstrap(&other).await.unwrap().is_none());
}

/// One legal follow-up publication for the card scope, generation 2, parented
/// on the bootstrapped certificate — the shape a later ordinary certify would
/// produce. Returns (certificate, certificate record digest).
fn follow_up_publication(
    parent_hash: &str,
    signer_key: &SigningKey,
) -> (AuthorityScopePublicationCertificate, String) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0);
    let mut certificate = AuthorityScopePublicationCertificate {
        protocol_version: AUTHORITY_PROTOCOL_VERSION,
        authorization_edition: AUTHORIZATION_EDITION,
        authority_id: "authority-bootstrap".to_owned(),
        authority_term: 1,
        global_fence_sequence: 2,
        certificate_id: "cert-follow-up".to_owned(),
        intent_digest: "88".repeat(32),
        reservation_id: "res-follow-up".to_owned(),
        operation_id: "op-follow-up".to_owned(),
        event_id: "evt-follow-up".to_owned(),
        scope: AuthorityProtocolScope::Card(AuthorizationAuthorityScope {
            tenant_id: 7,
            card_id: 17,
            user_id: None,
            domain: AuthorizationDomainScope::Any,
        }),
        approved_request_digest: "77".repeat(32),
        before_image_digest: Some("b1".repeat(32)),
        after_image_digest: "b9".repeat(32),
        source_commit_digest: "7c".repeat(32),
        completion_digest: "00".repeat(32),
        snapshot_hash: "b9".repeat(32),
        parent_certificate_hash: Some(parent_hash.to_owned()),
        source_outcome_digest: "7d".repeat(32),
        manifests: vec![AuthorityManifestIdentity {
            aggregate_type: "grant".to_owned(),
            aggregate_id: 1,
            manifest_digest_hex: "aa".repeat(32),
            dependency_hash_hex: "bb".repeat(32),
            semantic_hash_hex: "cc".repeat(32),
            generation: 2,
            revoke_fence: 0,
            event_id: "evt-follow-up".to_owned(),
            operation_id: "op-follow-up".to_owned(),
        }],
        key_id: "signer-bootstrap".to_owned(),
        key_epoch: 1,
        issued_at: now,
        not_before: now,
        expires_at: None,
        certificate_nonce: "certn-follow-up".to_owned(),
        signature: String::new(),
    };
    certificate.completion_digest = certificate.recompute_completion_digest().unwrap();
    certificate.sign(signer_key).unwrap();
    let hash = certificate.record_digest().unwrap();
    (certificate, hash)
}

#[tokio::test]
async fn reconcile_survives_legal_pointer_advance_and_rejects_substitute_certificate() {
    let (service, store, keys, signer_key, root_key) = bootstrap_service().await;
    let signed = sign_artifact(
        build_unsigned_artifact(&service, "op-advance").await,
        &root_key,
    );
    let installed = service.install_bootstrap(&signed).await.unwrap();
    assert!(installed.newly_applied);
    let bootstrap_certificate_id = installed.receipt.certificate_ids[0].clone();
    let bootstrap_certificate_hash = installed.receipt.certificate_hashes[0].clone();

    // A legal later publication advances the card pointer to generation 2,
    // parented on the bootstrapped certificate.
    let (follow_up, follow_up_hash) =
        follow_up_publication(&bootstrap_certificate_hash, &signer_key);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0);
    let advanced_pointer = StoredScopeCurrent {
        scope_key_text: CARD_SCOPE_KEY.to_owned(),
        snapshot_hash: "b9".repeat(32),
        scope_generation: 2,
        revoke_watermark: 0,
        certificate_hash: follow_up_hash.clone(),
        certificate_id: follow_up.certificate_id.clone(),
        key_epoch: 1,
        updated_at: now,
    };
    store
        .execute(
            StoreTxn::new()
                .with_op(StoreOp::Put {
                    key: keys.certificate(&follow_up.certificate_id),
                    value: serde_json::to_vec(&follow_up).unwrap(),
                })
                .with_op(StoreOp::Put {
                    key: keys.scope_current(CARD_SCOPE_KEY),
                    value: serde_json::to_vec(&advanced_pointer).unwrap(),
                }),
        )
        .await
        .unwrap();

    // Reconciliation recovers the HISTORICAL bootstrap certificates exactly,
    // even though the current pointer no longer names them. Re-install stays
    // idempotent and never rewrites anything.
    let reconciled = service.reconcile_bootstrap(&signed).await.unwrap().unwrap();
    assert!(!reconciled.newly_applied);
    assert_eq!(reconciled.receipt, installed.receipt);
    let again = service.install_bootstrap(&signed).await.unwrap();
    assert!(!again.newly_applied);
    assert_eq!(again.receipt, installed.receipt);
    // The historical certificate bytes are untouched by reconciliation.
    let historical: AuthorityScopePublicationCertificate = serde_json::from_slice(
        &store
            .get(&keys.certificate(&bootstrap_certificate_id))
            .await
            .unwrap()
            .unwrap()
            .value,
    )
    .unwrap();
    assert_eq!(
        historical.record_digest().unwrap(),
        bootstrap_certificate_hash
    );

    // A re-signed substitute (same receipt slot, tampered provenance field)
    // must never pass the field-level re-derivation.
    let mut substitute = historical.clone();
    substitute.event_id = "evt-substitute".to_owned();
    substitute.completion_digest = substitute.recompute_completion_digest().unwrap();
    substitute.sign(&signer_key).unwrap();
    store
        .execute(StoreTxn::new().with_op(StoreOp::Put {
            key: keys.certificate(&bootstrap_certificate_id),
            value: serde_json::to_vec(&substitute).unwrap(),
        }))
        .await
        .unwrap();
    let error = service.reconcile_bootstrap(&signed).await.unwrap_err();
    assert_service_error(
        error,
        |error| matches!(error, AuthorityServiceError::Store(_)),
        "re-signed substitute must be refused",
    );

    // A pointer that regresses below the bootstrapped frontier is corrupt.
    // Restore the historical certificate first, then regress the pointer.
    store
        .execute(StoreTxn::new().with_op(StoreOp::Put {
            key: keys.certificate(&bootstrap_certificate_id),
            value: serde_json::to_vec(&historical).unwrap(),
        }))
        .await
        .unwrap();
    let mut regressed_pointer = advanced_pointer.clone();
    regressed_pointer.scope_generation = 0;
    store
        .execute(StoreTxn::new().with_op(StoreOp::Put {
            key: keys.scope_current(CARD_SCOPE_KEY),
            value: serde_json::to_vec(&regressed_pointer).unwrap(),
        }))
        .await
        .unwrap();
    let error = service.reconcile_bootstrap(&signed).await.unwrap_err();
    assert_service_error(
        error,
        |error| matches!(error, AuthorityServiceError::Store(_)),
        "regressed pointer must be refused",
    );
}

#[tokio::test]
async fn bootstrap_first_certificate_supports_fresh_proofs_after_install() {
    let (service, _store, _keys, signer_key, root_key) = bootstrap_service().await;
    let signed = sign_artifact(
        build_unsigned_artifact(&service, "op-freshproof").await,
        &root_key,
    );
    let installed = service.install_bootstrap(&signed).await.unwrap();
    let artifact_digest = signed.artifact_digest().unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0);
    let request = AuthorityFenceReadRequest {
        caller: AuthorityCallerIdentity {
            service_id: SERVICE_ID.to_owned(),
            request_nonce: "read-nonce-1".to_owned(),
            issued_at: now.max(2),
        },
        scope: Some(AuthorityProtocolScope::Card(AuthorizationAuthorityScope {
            tenant_id: 7,
            card_id: 17,
            user_id: None,
            domain: AuthorizationDomainScope::Any,
        })),
        expected_certificate_hash: Some(installed.receipt.certificate_hashes[0].clone()),
        read_proof: Some(AuthorityReadProofRequest {
            actor_scope: AuthorityProtocolScope::Card(AuthorizationAuthorityScope {
                tenant_id: 7,
                card_id: 17,
                user_id: None,
                domain: AuthorizationDomainScope::Any,
            }),
            mutation_kind: AuthorityMutationKind::AuthorizationSource,
            source_scope: None,
            request_nonce: "fresh-nonce-1".to_owned(),
            operation_id: "op-fresh-read".to_owned(),
            event_id: "evt-fresh-read".to_owned(),
            request_binding_digest: REQUEST_DIGEST.to_owned(),
            expected_frontier: None,
            proof_ttl_seconds: None,
        }),
    };
    let response = service.read_fence(&request).await.unwrap();
    response.validate().unwrap();

    // Positive reads are allowed after bootstrap and the current certificate
    // is exactly the bootstrapped first certificate, with its provenance.
    assert!(response.read_gate.positive_reads_allowed);
    let certificate = response.scope_certificate.as_ref().unwrap();
    assert_eq!(
        response.scope_certificate_hash.as_deref(),
        Some(installed.receipt.certificate_hashes[0].as_str())
    );
    assert_eq!(certificate.intent_digest, artifact_digest);
    assert_eq!(
        certificate.reservation_id,
        format!("bootstrap-{artifact_digest}")
    );
    assert_eq!(certificate.snapshot_hash, "b1".repeat(32));

    // A fresh proof was minted, bound to the bootstrapped certificate, and
    // verifies against the attested signer key.
    let proof = response.proof.as_ref().unwrap();
    proof
        .verify_at(&signer_key.verifying_key(), now + 1)
        .unwrap();
    assert_eq!(proof.snapshot_hash, "b1".repeat(32));
    assert_eq!(
        proof.scope_certificate_hash.as_deref(),
        Some(installed.receipt.certificate_hashes[0].as_str())
    );
    assert_eq!(proof.request_nonce, "fresh-nonce-1");
}

#[tokio::test]
async fn bootstrap_rejects_non_canonical_card_scope() {
    let (service, _store, _keys, _signer_key, root_key) = bootstrap_service().await;
    let mut artifact = build_unsigned_artifact(&service, "op-alias").await;
    artifact.snapshots[0].scope = AuthorityProtocolScope::Card(AuthorizationAuthorityScope {
        tenant_id: 7,
        card_id: 17,
        user_id: Some(3),
        domain: AuthorizationDomainScope::Any,
    });
    // The non-canonical card scope is refused at the contract layer: the
    // artifact cannot be signed at all.
    assert!(matches!(
        artifact.sign(&root_key),
        Err(AuthorityProtocolError::InvalidText {
            field: "card_scope"
        })
    ));
    // Defense in depth: install refuses before any durable write even if a
    // malformed artifact is handed in directly.
    let error = service.install_bootstrap(&artifact).await.unwrap_err();
    assert_service_error(
        error,
        |error| {
            matches!(
                error,
                AuthorityServiceError::Protocol(AuthorityProtocolError::InvalidText { .. })
            )
        },
        "non-canonical card scope must be refused",
    );
}

#[tokio::test]
async fn sign_bootstrap_cli_writes_verifiable_signed_artifact() {
    let (service, _store, _keys, _signer_key, root_key) = bootstrap_service().await;
    let unsigned = build_unsigned_artifact(&service, "op-cli").await;
    let temp_dir = std::env::temp_dir().join(format!(
        "astral-bootstrap-contract-{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let output_path = temp_dir.join("signed-bootstrap.json");

    let config = test_config();
    let digest = run_sign_bootstrap(&config, unsigned.clone(), &root_key, &output_path).unwrap();

    // The written artifact parses, matches the reported digest, and verifies
    // against the ROOT verifying key of the registry.
    let written: AuthorityBootstrapArtifact =
        serde_json::from_str(&std::fs::read_to_string(&output_path).unwrap()).unwrap();
    assert_eq!(written.artifact_digest().unwrap(), digest);
    let (trust_root, _, _, _) = trust_root_fixture();
    written
        .verify(&trust_root.root_key().unwrap().verifying_key().unwrap())
        .unwrap();

    // The authority_id of the artifact must bind the configuration.
    let mut foreign_config = test_config();
    foreign_config.identity.authority_id = "other-authority".to_owned();
    assert!(
        run_sign_bootstrap(&foreign_config, unsigned, &root_key, &output_path).is_err(),
        "authority mismatch must refuse signing"
    );

    // An existing signed artifact is never silently overwritten.
    let other_unsigned = build_unsigned_artifact(&service, "op-cli-overwrite").await;
    assert!(
        run_sign_bootstrap(&config, other_unsigned, &root_key, &output_path).is_err(),
        "overwrite of an existing signed artifact must be refused"
    );

    std::fs::remove_dir_all(&temp_dir).ok();
}
