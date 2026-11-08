#![cfg(feature = "service")]

//! Owner abort contract tests. These exercise the real service path after a
//! GLOBAL source reservation, including the durable lock-owner corruption gate.

use astral_authority::error::{AuthorityServiceError, AuthorityStoreError};
use astral_authority::store::{AuthorityStore, StoreOp, StoreTxn};
use astral_types::{
    AuthorityAbortRequest, AuthorityPrepareRequest, AuthorityProtocolError,
    AuthorityReservationCoverage, AuthorityReservationDisposition, AuthorityReservationState,
    AuthorityScopeReservation,
};

#[derive(Clone, Copy)]
enum LockCorruption {
    Operation,
    Reservation,
    Intent,
    Malformed,
}

fn abort_config() -> astral_authority::config::AuthorityServiceConfig {
    let mut config = super::test_config();
    let source = config
        .trusted_sources
        .iter_mut()
        .find(|source| source.service_id == super::SERVICE_ID)
        .expect("parent fixture registers the source");
    source.allowed_operations.push("abort".to_owned());
    config
}

fn abort_request(reservation_id: &str) -> AuthorityAbortRequest {
    AuthorityAbortRequest {
        caller: super::caller(),
        reservation_id: reservation_id.to_owned(),
        operation_id: super::OPERATION_ID.to_owned(),
        database_id: super::DATABASE_ID.to_owned(),
        request_digest: super::REQUEST_DIGEST.to_owned(),
        abort_id: AuthorityAbortRequest::stable_abort_id(reservation_id).unwrap(),
        source_tombstone_digest: "ab".repeat(32),
        reason: "local rollback proven".to_owned(),
    }
}

async fn fixture_with_reservation() -> (
    astral_authority::service::AuthorityService,
    std::sync::Arc<astral_authority::store::memory::MemoryAuthorityStore>,
    astral_authority::store::KeyLayout,
    String,
) {
    let (service, store, keys, signer_key) = super::test_service_with_config(abort_config()).await;
    super::seed_admission_proof(
        &service,
        &store,
        &keys,
        &signer_key,
        "prf-seed",
        super::REQUEST_DIGEST,
    )
    .await;
    let prepared = service
        .prepare_source_mutation(&AuthorityPrepareRequest {
            caller: super::caller(),
            intent: super::intent(AuthorityReservationCoverage::Global),
        })
        .await
        .expect("GLOBAL source reservation prepares");
    (service, store, keys, prepared.reservation.reservation_id)
}

async fn lock_corruption_case(corruption: LockCorruption) {
    let (service, store, keys, reservation_id) = fixture_with_reservation().await;
    let lock_key = keys.source_bootstrap_global_lock();
    let reservation_key = keys.reservation(&reservation_id);
    let frontier_key = keys.frontier();
    let abort_receipt_key = keys.abort_receipt(&reservation_id);
    let reservation: AuthorityScopeReservation = serde_json::from_slice(
        &store
            .get(&reservation_key)
            .await
            .unwrap()
            .expect("prepared reservation is durable")
            .value,
    )
    .unwrap();
    let original_lock = store
        .get(&lock_key)
        .await
        .unwrap()
        .expect("GLOBAL reservation owns the durable lock");
    let owner: (String, String, String) = serde_json::from_slice(&original_lock.value).unwrap();
    assert_eq!(owner.0, reservation.intent.operation_id);
    assert_eq!(owner.1, reservation.reservation_id);
    assert_eq!(owner.2, reservation.intent_digest);
    let lock_value = match corruption {
        LockCorruption::Operation => serde_json::to_vec(&(
            "tampered-operation".to_owned(),
            owner.1.clone(),
            owner.2.clone(),
        )),
        LockCorruption::Reservation => serde_json::to_vec(&(
            owner.0.clone(),
            "tampered-reservation".to_owned(),
            owner.2.clone(),
        )),
        LockCorruption::Intent => {
            serde_json::to_vec(&(owner.0.clone(), owner.1.clone(), "bb".repeat(32)))
        }
        LockCorruption::Malformed => Ok(b"not-json-lock-owner".to_vec()),
    }
    .unwrap();

    store
        .execute(StoreTxn::new().with_op(StoreOp::Put {
            key: lock_key.clone(),
            value: lock_value,
        }))
        .await
        .unwrap();

    let lock_before = store.get(&lock_key).await.unwrap();
    let reservation_before = store.get(&reservation_key).await.unwrap();
    let frontier_before = store.get(&frontier_key).await.unwrap();
    let abort_receipt_before = store.get(&abort_receipt_key).await.unwrap();
    assert!(abort_receipt_before.is_none());

    let error = service
        .abort_reservation(&abort_request(&reservation_id))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        AuthorityServiceError::Store(AuthorityStoreError::Corrupt(_))
    ));

    assert_eq!(store.get(&lock_key).await.unwrap(), lock_before);
    assert_eq!(
        store.get(&reservation_key).await.unwrap(),
        reservation_before
    );
    assert_eq!(store.get(&frontier_key).await.unwrap(), frontier_before);
    assert_eq!(
        store.get(&abort_receipt_key).await.unwrap(),
        abort_receipt_before
    );
}

#[tokio::test]
async fn abort_lock_owner_corruption_is_fail_closed_without_side_effects() {
    for corruption in [
        LockCorruption::Operation,
        LockCorruption::Reservation,
        LockCorruption::Intent,
        LockCorruption::Malformed,
    ] {
        lock_corruption_case(corruption).await;
    }
}

#[tokio::test]
async fn abort_exact_owner_is_terminal_and_exact_retry_replays_without_advancing() {
    let (service, store, keys, reservation_id) = fixture_with_reservation().await;
    let request = abort_request(&reservation_id);
    let frontier_before = service.load_verified_state().await.unwrap().frontier;
    let revision_before_abort = store.current_revision();

    let first = service.abort_reservation(&request).await.unwrap();
    first.validate().unwrap();
    assert_eq!(first.disposition, AuthorityReservationDisposition::Aborted);
    assert_eq!(first.reservation.state, AuthorityReservationState::Aborted);
    assert!(first.read_gate.positive_reads_allowed);
    assert!(first.global_frontier.global_fence_sequence > frontier_before.global_fence_sequence);
    assert!(store
        .get(&keys.source_bootstrap_global_lock())
        .await
        .unwrap()
        .is_none());
    assert!(store
        .get(&keys.abort_receipt(&reservation_id))
        .await
        .unwrap()
        .is_some());

    let revision_after_abort = store.current_revision();
    assert!(revision_after_abort > revision_before_abort);
    let retry = service.abort_reservation(&request).await.unwrap();
    retry.validate().unwrap();
    assert_eq!(retry, first);
    assert_eq!(store.current_revision(), revision_after_abort);
}

#[tokio::test]
async fn abort_rejects_wrong_owner_binding_before_any_state_change() {
    let (service, store, keys, reservation_id) = fixture_with_reservation().await;
    let reservation_before = store.get(&keys.reservation(&reservation_id)).await.unwrap();
    let frontier_before = store.get(&keys.frontier()).await.unwrap();
    let lock_before = store
        .get(&keys.source_bootstrap_global_lock())
        .await
        .unwrap();

    let mut request = abort_request(&reservation_id);
    request.operation_id = "wrong-operation".to_owned();
    let error = service.abort_reservation(&request).await.unwrap_err();
    assert!(matches!(
        error,
        AuthorityServiceError::Protocol(AuthorityProtocolError::CallerIdentityMismatch)
    ));
    assert_eq!(
        store.get(&keys.reservation(&reservation_id)).await.unwrap(),
        reservation_before
    );
    assert_eq!(store.get(&keys.frontier()).await.unwrap(), frontier_before);
    assert_eq!(
        store
            .get(&keys.source_bootstrap_global_lock())
            .await
            .unwrap(),
        lock_before
    );
    assert!(store
        .get(&keys.abort_receipt(&reservation_id))
        .await
        .unwrap()
        .is_none());
}
