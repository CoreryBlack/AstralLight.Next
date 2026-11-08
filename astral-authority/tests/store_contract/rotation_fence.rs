//! Post-rotation leadership regression (append-only module owned by the
//! leadership-fence task, per coordination with the rotation owner).
//!
//! Contract under test (Rust后端编码规范 §15.9.1/§15.9.4): after a key
//! rotation the OLD signer must never produce NEW signed artifacts — startup
//! attestation, prepare/mint — even while the leadership fence is still bound
//! and the liveness flag is raised. Historical keys stay retained for
//! verification and the full trust chain remains readback-able. The
//! main-owned methods (`apply_rotation`, `require_active_signer`) are
//! exercised, never modified, here.

use super::*;
use astral_authority::service::leadership::{leader_key, LeadershipToken};
use ed25519_dalek::SigningKey;

/// Fold one rotation: retain the full key history, add a strictly
/// higher-epoch SIGNER key, and sign the certificate with the fixture ROOT
/// key (seed 2, "root-test"). Wall-clock `now` keeps `validate_at` honest.
fn rotated_root_and_certificate(
    active: &AuthorityTrustRoot,
) -> (
    AuthorityTrustRoot,
    astral_types::AuthorityKeyRotationCertificate,
    SigningKey,
) {
    let new_signing = SigningKey::from_bytes(&[9u8; 32]);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0);
    let new_key = AuthorityRootKey {
        key_id: "signer-test-2".to_owned(),
        key_epoch: 2,
        role: AuthorityRootKeyRole::Signer,
        verifying_key_hex: hex::encode(new_signing.verifying_key().as_bytes()),
    };
    let mut keys = active.keys.clone();
    keys.push(new_key.clone());
    let next_root = AuthorityTrustRoot {
        root_id: active.root_id.clone(),
        keys,
        created_at: now,
    };
    let mut certificate = astral_types::AuthorityKeyRotationCertificate {
        authorization_edition: AUTHORIZATION_EDITION,
        authority_id: "authority-test".to_owned(),
        root_id: active.root_id.clone(),
        previous_key_epoch: active.root_key().unwrap().key_epoch,
        new_key,
        previous_trust_root_digest: active.digest().unwrap(),
        new_trust_root_digest: next_root.digest().unwrap(),
        rotation_nonce: uuid::Uuid::new_v4().simple().to_string(),
        issued_at: now,
        not_before: now,
        expires_at: now + 600,
        signed_by_key_id: String::new(),
        signature: String::new(),
    };
    let root_entry = active.root_key().unwrap();
    let root_signing = SigningKey::from_bytes(&[2u8; 32]);
    certificate.sign(&root_signing, &root_entry.key_id).unwrap();
    (next_root, certificate, new_signing)
}

#[tokio::test]
async fn post_rotation_old_signer_never_signs_and_history_stays_readable() {
    let (service, store, keys, signer_key) = test_service().await;

    // A valid, current admission proof is seeded BEFORE the rotation, so the
    // post-rotation prepare passes every request-shape gate and the refusal
    // comes exactly from the active-signer gate (not from a malformed input).
    // The shared intent fixture references proof id "prf-seed".
    seed_admission_proof(
        &service,
        &store,
        &keys,
        &signer_key,
        "prf-seed",
        REQUEST_DIGEST,
    )
    .await;

    // Rotate: fold the rotated root, sign the certificate with the ROOT key,
    // and apply through the main-owned `apply_rotation` (fenced itself).
    let active_before = service.load_verified_state().await.unwrap();
    let (next_root, certificate, _new_signing) =
        rotated_root_and_certificate(&active_before.trust_root);
    let new_signer = Arc::new(
        ProtectedAuthoritySigner::from_seed([9u8; 32], "signer-test-2", &next_root)
            .expect("new signer must bind to the rotated root"),
    );
    service
        .apply_rotation(&certificate, new_signer)
        .await
        .expect("the rotation must apply under the still-valid leadership fence");

    // History readback: the full chain verifies, the rotated root is ACTIVE,
    // the old signer is RETAINED for verification of historical artifacts.
    let state = service.load_verified_state().await.unwrap();
    assert_eq!(
        state.trust_root.signer_key().unwrap().key_id,
        "signer-test-2"
    );
    assert_eq!(state.rotations.len(), 1);
    assert_eq!(state.rotations[0].new_key.key_id, "signer-test-2");
    assert!(state.trust_root.key_by_id("signer-test").is_some());
    assert_eq!(state.frontier.key_id, "signer-test-2");
    assert_eq!(state.frontier.key_epoch, 2);

    // Startup attestation with the OLD signer still configured: the
    // leadership fence passes (the term is rotation-independent), then the
    // active-signer gate refuses — nothing is signed.
    let attestation = service.startup_attestation(SERVICE_ID).await;
    assert!(
        matches!(
            attestation,
            Err(AuthorityServiceError::SignerUnavailable)
        ),
        "post-rotation startup attestation must be refused by the active-signer gate, got {attestation:?}"
    );

    // Prepare/mint with the OLD signer: refused; the seeded proof is NOT
    // consumed and nothing is signed or reserved.
    let prepare = service
        .prepare_source_mutation(&AuthorityPrepareRequest {
            caller: caller(),
            intent: intent(AuthorityReservationCoverage::Global),
        })
        .await;
    assert!(
        matches!(prepare, Err(AuthorityServiceError::SignerUnavailable)),
        "post-rotation prepare/mint must be refused by the active-signer gate, got {prepare:?}"
    );
    assert!(
        store
            .get(
                &keys.proof_consumed(
                    &intent(AuthorityReservationCoverage::Global).admission_proof_id
                )
            )
            .await
            .unwrap()
            .is_none(),
        "the refused prepare must not consume the seeded proof"
    );

    // The same request with a service bound to the NEW signer succeeds past
    // the signer gate (construct the rotated service over the SAME store and
    // term; the durable leadership term is rotation-independent).
    let rotated_service = AuthorityService::new(
        {
            let mut config = test_config();
            config.identity.pinned_genesis_trust_root_digest =
                state.genesis_trust_root.digest().unwrap();
            config
        },
        store.clone(),
        Arc::new(
            ProtectedAuthoritySigner::from_seed([9u8; 32], "signer-test-2", &state.trust_root)
                .unwrap(),
        ),
    );

    let token_value = store
        .get(&leader_key(
            &rotated_service.config().quorum.key_prefix,
            &rotated_service.config().quorum.authority_name,
        ))
        .await
        .unwrap()
        .unwrap()
        .value;
    rotated_service
        .bind_leadership_token(&LeadershipToken::from_durable_bytes(
            leader_key(
                &rotated_service.config().quorum.key_prefix,
                &rotated_service.config().quorum.authority_name,
            ),
            token_value,
        ))
        .await
        .unwrap();
    let attestation = rotated_service.startup_attestation(SERVICE_ID).await;
    assert!(
        attestation.is_ok(),
        "the ACTIVE signer must be able to sign again after rotation, got {attestation:?}"
    );
}
