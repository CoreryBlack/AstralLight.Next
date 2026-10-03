//! Pure (no-DB) tests for the in-process projection delta bus: bounds, FIFO,
//! duplicate bounding, close semantics, one-owner receiver, start-once install.

use std::sync::Arc;
use std::thread;

use super::{
    dispatch_committed_projection_delta, install_local_projection_bus,
    local_projection_bus_installed, take_global_local_projection_receiver,
    LocalProjectionBusConfig, LocalProjectionDispatchError, LocalProjectionInstallError,
    LocalProjectionOwnerTaken, LOCAL_PROJECTION_BUS_MAX_CAPACITY,
};
use crate::grant_repository::{DeltaEventAppendRequest, DeltaEventType};
use astral_types::GrantId;

const TEST_GRANT_UUID: &str = "550e8400-e29b-41d4-a716-446655440001";

fn base_request(event_id: &str, target_version: i64) -> DeltaEventAppendRequest {
    DeltaEventAppendRequest {
        tenant_id: 7,
        card_id: Some(11),
        aggregate_type: "card".to_owned(),
        aggregate_id: 42,
        grant_id: GrantId::parse(TEST_GRANT_UUID).expect("test grant id"),
        event_id: event_id.to_owned(),
        operation_id: format!("op-{event_id}"),
        event_type: DeltaEventType::Add,
        base_version: target_version - 1,
        target_version,
        source_generation: 5,
        revoke_fence: 0,
        invalidates_published_evidence: false,
        before_image_json: None,
        before_digest_hex: None,
        delta_json: format!(r#"{{"event":"{event_id}"}}"#),
        semantic_hash_hex: "aa".repeat(32),
        dependency_hash_hex: "bb".repeat(32),
        compiler_version: "test-compiler".to_owned(),
        next_attempt_at: None,
    }
}

#[test]
fn default_config_passes_validation() {
    let validated = LocalProjectionBusConfig::default().validated();
    assert!(validated.is_ok());
}

#[test]
fn zero_capacity_fails_validation() {
    let error = LocalProjectionBusConfig {
        capacity: 0,
        ..LocalProjectionBusConfig::default()
    }
    .validated()
    .expect_err("zero capacity must fail validation");
    assert!(matches!(
        error,
        LocalProjectionInstallError::InvalidConfig { .. }
    ));
}

#[test]
fn oversized_capacity_fails_validation() {
    let error = LocalProjectionBusConfig {
        capacity: LOCAL_PROJECTION_BUS_MAX_CAPACITY + 1,
        ..LocalProjectionBusConfig::default()
    }
    .validated()
    .expect_err("oversized capacity must fail validation");
    assert!(matches!(
        error,
        LocalProjectionInstallError::InvalidConfig { .. }
    ));
}

#[test]
fn total_bytes_below_payload_bound_fails_validation() {
    let error = LocalProjectionBusConfig {
        capacity: 8,
        max_payload_bytes: 1024,
        max_total_bytes: 512,
        max_queued_per_aggregate: 4,
    }
    .validated()
    .expect_err("total bytes below payload bound must fail validation");
    assert!(matches!(
        error,
        LocalProjectionInstallError::InvalidConfig { .. }
    ));
}

#[test]
fn empty_stable_identity_is_invalid_payload() {
    let (bus, _receiver) = {
        let (bus, receiver) = super::LocalProjectionBus::new_for_tests(
            LocalProjectionBusConfig::default()
                .validated()
                .expect("valid"),
        );
        (bus, receiver)
    };
    let mut request = base_request("evt-empty-identity", 1);
    request.event_id = "   ".to_owned();
    let error = bus
        .dispatch(request)
        .expect_err("empty event id must be rejected");
    assert!(matches!(
        error,
        LocalProjectionDispatchError::InvalidPayload { .. }
    ));
}

#[test]
fn bounded_capacity_reports_overflow_and_accepts_after_drain() {
    let config = LocalProjectionBusConfig {
        capacity: 2,
        max_payload_bytes: 4096,
        max_total_bytes: 1 << 20,
        max_queued_per_aggregate: 64,
    }
    .validated()
    .expect("valid");
    let (bus, mut receiver) = super::LocalProjectionBus::new_for_tests(config);

    bus.dispatch(base_request("evt-c1", 1)).expect("admit 1");
    bus.dispatch(base_request("evt-c2", 2)).expect("admit 2");
    let error = bus
        .dispatch(base_request("evt-c3", 3))
        .expect_err("third envelope must overflow");
    assert!(matches!(
        error,
        LocalProjectionDispatchError::Overflow { .. }
    ));

    let first = receiver.try_recv().expect("first envelope");
    bus.acknowledge(&first);
    bus.dispatch(base_request("evt-c3", 3))
        .expect("slot released by acknowledge, admission succeeds");
}

#[test]
fn per_aggregate_cap_bounds_a_single_scope() {
    let config = LocalProjectionBusConfig {
        capacity: 64,
        max_payload_bytes: 4096,
        max_total_bytes: 1 << 20,
        max_queued_per_aggregate: 2,
    }
    .validated()
    .expect("valid");
    let (bus, _receiver) = super::LocalProjectionBus::new_for_tests(config);

    bus.dispatch(base_request("evt-a1", 1)).expect("admit 1");
    bus.dispatch(base_request("evt-a2", 2)).expect("admit 2");
    let error = bus
        .dispatch(base_request("evt-a3", 3))
        .expect_err("third same-aggregate envelope must overflow");
    assert!(matches!(
        error,
        LocalProjectionDispatchError::Overflow {
            reason: "per_aggregate_cap"
        }
    ));
}

#[test]
fn duplicate_admission_is_idempotent_noop() {
    let config = LocalProjectionBusConfig {
        capacity: 8,
        max_payload_bytes: 4096,
        max_total_bytes: 1 << 20,
        max_queued_per_aggregate: 8,
    }
    .validated()
    .expect("valid");
    let (bus, mut receiver) = super::LocalProjectionBus::new_for_tests(config);

    bus.dispatch(base_request("evt-dup", 1))
        .expect("first admission");
    bus.dispatch(base_request("evt-dup", 1))
        .expect("duplicate admission is an idempotent Ok");
    // Exactly one envelope physically queued.
    receiver.try_recv().expect("one envelope");
    assert!(
        receiver.try_recv().is_err(),
        "duplicate must not enqueue twice"
    );
}

#[test]
fn fifo_per_exact_aggregate_under_concurrent_dispatchers() {
    let config = LocalProjectionBusConfig {
        capacity: 256,
        max_payload_bytes: 4096,
        max_total_bytes: 1 << 20,
        max_queued_per_aggregate: 64,
    }
    .validated()
    .expect("valid");
    let (bus, mut receiver) = super::LocalProjectionBus::new_for_tests(config);
    let bus = Arc::new(bus);

    // Four dispatch threads each enqueue their OWN aggregate chain 0..50 with
    // disjoint event ids; the bus must deliver every event exactly once and
    // preserve per-aggregate relative order (each thread's events are a
    // subsequence of the receive order).
    const THREADS: usize = 4;
    const PER_THREAD: usize = 50;
    let mut handles = Vec::new();
    for thread_index in 0..THREADS {
        let bus = Arc::clone(&bus);
        handles.push(thread::spawn(move || {
            for step in 0..PER_THREAD {
                let mut request =
                    base_request(&format!("evt-t{thread_index}-{step}"), (step + 1) as i64);
                // One exact aggregate per thread so per-aggregate FIFO is the
                // property under test (and per-aggregate caps never interfere).
                request.aggregate_id = 42 + thread_index as i64;
                bus.dispatch(request).expect("admission under capacity");
            }
        }));
    }
    for handle in handles {
        handle.join().expect("dispatcher thread");
    }

    let mut seen = Vec::new();
    for _ in 0..THREADS * PER_THREAD {
        let envelope = receiver.blocking_recv().expect("envelope");
        bus.acknowledge(&envelope);
        seen.push(envelope);
    }
    assert_eq!(seen.len(), THREADS * PER_THREAD);
    // Every event id exactly once.
    let mut ids: Vec<&str> = seen.iter().map(|envelope| envelope.event_id()).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), THREADS * PER_THREAD);
    // Per-thread subsequence order preserved (dispatch holds the admission
    // lock through try_send, so same-aggregate FIFO = dispatch order).
    for thread_index in 0..THREADS {
        let positions: Vec<usize> = seen
            .iter()
            .enumerate()
            .filter_map(|(position, envelope)| {
                envelope
                    .event_id()
                    .starts_with(&format!("evt-t{thread_index}-"))
                    .then_some(position)
            })
            .collect();
        let mut ordered = positions.clone();
        ordered.sort_unstable();
        assert_eq!(positions, ordered, "thread {thread_index} order preserved");
    }
}

#[test]
fn total_bytes_cap_overflows_before_admission() {
    // Deterministic bounds derived from the actual payload size of one probe
    // request (private helper accessible to this child test module).
    let probe = base_request("evt-bytes-1", 1);
    let payload = super::payload_bytes_of(&probe);
    let config = LocalProjectionBusConfig {
        capacity: 64,
        max_payload_bytes: payload,
        max_total_bytes: payload * 2 - 1,
        max_queued_per_aggregate: 64,
    }
    .validated()
    .expect("valid");
    let (bus, _receiver) = super::LocalProjectionBus::new_for_tests(config);

    bus.dispatch(base_request("evt-bytes-1", 1))
        .expect("first payload fits the total cap");
    let error = bus
        .dispatch(base_request("evt-bytes-2", 2))
        .expect_err("cumulative payload must stop the second envelope");
    assert!(matches!(
        error,
        LocalProjectionDispatchError::Overflow {
            reason: "total_bytes_cap"
        }
    ));
}

#[test]
fn close_rejects_new_admissions_and_drains_remaining() {
    let config = LocalProjectionBusConfig::default()
        .validated()
        .expect("valid");
    let (bus, mut receiver) = super::LocalProjectionBus::new_for_tests(config);

    bus.dispatch(base_request("evt-pre-close", 1))
        .expect("admit");
    bus.close("test-shutdown");
    assert!(bus.is_closed());
    let error = bus
        .dispatch(base_request("evt-post-close", 2))
        .expect_err("closed bus must reject");
    assert!(matches!(error, LocalProjectionDispatchError::Closed));

    let envelope = receiver.blocking_recv().expect("drain still works");
    assert_eq!(envelope.event_id(), "evt-pre-close");
    assert!(receiver.blocking_recv().is_none());
}

#[test]
fn envelope_carries_strict_durable_source_facts() {
    let config = LocalProjectionBusConfig::default()
        .validated()
        .expect("valid");
    let (bus, mut receiver) = super::LocalProjectionBus::new_for_tests(config);

    let request = base_request("evt-facts", 9);
    let request_clone = request.clone();
    bus.dispatch(request).expect("admit");
    let envelope = receiver.blocking_recv().expect("envelope");
    assert_eq!(envelope.request, request_clone, "same strict durable DTO");
    assert_eq!(envelope.aggregate_key().tenant_id, 7);
    assert_eq!(envelope.aggregate_key().aggregate_id, 42);
    assert!(envelope.dispatch_sequence >= 1);
}

#[test]
fn global_install_is_start_once_and_receiver_is_single_owner() {
    // NOTE: this test depends on process-global statics; it must own the
    // install. Guard against accidental double-install from another test by
    // tolerating AlreadyInstalled only when this process installed earlier.
    let install_result = install_local_projection_bus(LocalProjectionBusConfig {
        capacity: 4,
        max_payload_bytes: 4096,
        max_total_bytes: 1 << 20,
        max_queued_per_aggregate: 4,
    });
    match install_result {
        Ok(bus) => {
            assert!(local_projection_bus_installed());
            let again = install_local_projection_bus(LocalProjectionBusConfig::default());
            assert!(matches!(
                again,
                Err(LocalProjectionInstallError::AlreadyInstalled)
            ));

            // The receiver MUST stay alive: dropping the only receiver closes
            // the channel and dispatch would report Closed.
            let _owner = take_global_local_projection_receiver().expect("first owner wins");
            let second = take_global_local_projection_receiver();
            assert!(matches!(second, Err(LocalProjectionOwnerTaken)));

            bus.dispatch(base_request("evt-global", 1))
                .expect("global dispatch admits");
            let dispatched =
                dispatch_committed_projection_delta(base_request("evt-global-free-fn", 2));
            assert!(dispatched.is_ok());
        }
        Err(LocalProjectionInstallError::AlreadyInstalled) => {
            // Another test in this binary installed first; receiver already
            // taken by that test. Verify the idempotent install error only.
            assert!(local_projection_bus_installed());
        }
        Err(error @ LocalProjectionInstallError::InvalidConfig { .. }) => {
            panic!("unexpected config rejection: {error}");
        }
    }
}

#[test]
fn dispatch_sequence_is_monotonic() {
    let config = LocalProjectionBusConfig {
        capacity: 16,
        max_payload_bytes: 4096,
        max_total_bytes: 1 << 20,
        max_queued_per_aggregate: 16,
    }
    .validated()
    .expect("valid");
    let (bus, mut receiver) = super::LocalProjectionBus::new_for_tests(config);

    bus.dispatch(base_request("evt-seq-1", 1)).expect("admit 1");
    bus.dispatch(base_request("evt-seq-2", 2)).expect("admit 2");
    bus.dispatch(base_request("evt-seq-3", 3)).expect("admit 3");
    let first = receiver.blocking_recv().expect("1");
    let second = receiver.blocking_recv().expect("2");
    let third = receiver.blocking_recv().expect("3");
    assert!(first.dispatch_sequence < second.dispatch_sequence);
    assert!(second.dispatch_sequence < third.dispatch_sequence);
}

#[test]
fn oversized_payload_is_invalid_not_overflow() {
    let config = LocalProjectionBusConfig {
        capacity: 8,
        max_payload_bytes: 16,
        max_total_bytes: 4096,
        max_queued_per_aggregate: 8,
    }
    .validated()
    .expect("valid");
    let (bus, _receiver) = super::LocalProjectionBus::new_for_tests(config);

    let mut request = base_request("evt-huge", 1);
    request.delta_json = "x".repeat(64);
    let error = bus
        .dispatch(request)
        .expect_err("oversized payload must be invalid");
    assert!(matches!(
        error,
        LocalProjectionDispatchError::InvalidPayload { .. }
    ));
}

#[test]
fn acknowledge_releases_duplicate_guard_slot() {
    let config = LocalProjectionBusConfig {
        capacity: 8,
        max_payload_bytes: 4096,
        max_total_bytes: 1 << 20,
        max_queued_per_aggregate: 1,
    }
    .validated()
    .expect("valid");
    let (bus, mut receiver) = super::LocalProjectionBus::new_for_tests(config);

    bus.dispatch(base_request("evt-ack-1", 1)).expect("admit 1");
    let error = bus
        .dispatch(base_request("evt-ack-2", 2))
        .expect_err("per-aggregate cap of 1 holds");
    assert!(matches!(
        error,
        LocalProjectionDispatchError::Overflow { .. }
    ));

    let envelope = receiver.blocking_recv().expect("envelope");
    bus.acknowledge(&envelope);
    bus.dispatch(base_request("evt-ack-2", 2))
        .expect("acknowledge released the slot");
}
