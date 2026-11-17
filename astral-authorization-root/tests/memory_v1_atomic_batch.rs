#![cfg(feature = "test-support")]

use std::sync::{mpsc, Arc, Barrier};
use std::thread;

use astral_authorization_root::memory_v1_db_rows::{
    BinaryId, BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, CurrentSelection,
    IdentityCardRow, RuleSetChangeConfirmationRow, RuleSetRow, RuleSetVersionRow, TenantRow,
    UserCardRow, UserCardStatus, UserRow,
};
use astral_authorization_root::memory_v1_hamt::CandidateBudget;
use astral_authorization_root::memory_v1_root::{
    install_process_root, ManagementMutationV2, MutationError, MutationPrecondition,
    RequestRootReader,
};
use astral_authorization_root::memory_v1_rules::{
    canonical_version_bytes, MemoryV1OwnerScope, MemoryV1TenantScope,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const USER: u64 = 1;
const TENANT: u64 = 3;
const RULE_SET: u64 = 4;
const CARD_INITIAL: u64 = 10;
const CARD_BATCH_ONE: u64 = 11;
const CARD_BATCH_TWO: u64 = 12;
const CARD_RACE: u64 = 13;
const BINDING_INITIAL: u64 = 20;
const BINDING_BATCH_ONE: u64 = 21;
const BINDING_BATCH_TWO: u64 = 22;
const BINDING_RACE: u64 = 23;
const CONFIRMATION_INITIAL: u64 = 30;
const CONFIRMATION_BATCH_ONE: u64 = 31;
const CONFIRMATION_BATCH_TWO: u64 = 32;
const CONFIRMATION_RACE_LEFT: u64 = 33;
const CONFIRMATION_RACE_RIGHT: u64 = 34;

// memory—v1: Keep fixture identifiers deterministic while retaining the real BINARY(16) shape.
fn id(value: u64) -> BinaryId {
    (value as u128).to_be_bytes()
}

// memory—v1: Construct one active BASE binding in the same shape as the existing fixture.
fn binding(binding_id: u64, card_id: u64) -> BindingRow {
    BindingRow {
        binding_id: id(binding_id),
        user_card_id: id(card_id),
        rule_set_id: id(RULE_SET),
        binding_layer: BindingLayer::Base,
        valid_from: None,
        valid_until: None,
        owner_scope: MemoryV1OwnerScope::default(),
        tenant_scope: MemoryV1TenantScope::default(),
        removed_at: None,
        removed_by: None,
    }
}

// memory—v1: Construct a complete confirmation row for a supplied binding candidate.
fn confirmation(confirmation_id: u64, binding_id: u64) -> BindingConfirmationRow {
    BindingConfirmationRow {
        confirmation_id: id(confirmation_id),
        binding_id: id(binding_id),
        rule_set_id: id(RULE_SET),
        version_bytes: vec![1],
        confirmer_user_id: id(USER),
        scope_bytes: vec![1],
        operation_id: confirmation_id.to_be_bytes().to_vec(),
        confirmed_at_bytes: vec![1],
        revoked_at: None,
        revoked_by: None,
    }
}

// memory—v1: Build one bounded candidate with two batch targets and one race target.
fn fixture() -> (CandidateRows, Vec<CurrentSelection>, CandidateBudget) {
    let version_bytes = vec![1];
    let content_bytes =
        br#"{"rules":[{"ruleId":"R1","resource":"document","action":"read","effect":"ALLOW"}]}"#
            .to_vec();
    let timestamp_bytes = vec![1];
    let hash_input_bytes =
        canonical_version_bytes(&version_bytes, &content_bytes, &timestamp_bytes);
    let hash_bytes = Sha256::digest(&hash_input_bytes).to_vec();

    let rows = CandidateRows {
        users: vec![UserRow { user_id: id(USER) }],
        identity_cards: vec![IdentityCardRow {
            identity_card_id: id(USER),
            user_id: id(USER),
        }],
        tenants: vec![TenantRow {
            tenant_id: id(TENANT),
            parent_tenant_id: None,
        }],
        user_cards: [CARD_INITIAL, CARD_BATCH_ONE, CARD_BATCH_TWO, CARD_RACE]
            .into_iter()
            .map(|user_card_id| UserCardRow {
                user_card_id: id(user_card_id),
                user_id: id(USER),
                tenant_id: id(TENANT),
                status: UserCardStatus::Active,
            })
            .collect(),
        rule_sets: vec![RuleSetRow {
            status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
            rule_set_id: id(RULE_SET),
            owner_tenant_id: id(TENANT),
            current_version_bytes: version_bytes.clone(),
        }],
        rule_set_versions: vec![RuleSetVersionRow {
            rule_set_id: id(RULE_SET),
            version_bytes: version_bytes.clone(),
            content_bytes,
            timestamp_bytes,
            hash_input_bytes,
            hash_bytes,
        }],
        bindings: [
            (BINDING_INITIAL, CARD_INITIAL),
            (BINDING_BATCH_ONE, CARD_BATCH_ONE),
            (BINDING_BATCH_TWO, CARD_BATCH_TWO),
            (BINDING_RACE, CARD_RACE),
        ]
        .into_iter()
        .map(|(binding_id, card_id)| binding(binding_id, card_id))
        .collect(),
        binding_confirmations: vec![confirmation(CONFIRMATION_INITIAL, BINDING_INITIAL)],
        rule_set_change_confirmations: vec![RuleSetChangeConfirmationRow {
            confirmation_id: id(40),
            rule_set_id: id(RULE_SET),
            version_bytes: version_bytes.clone(),
            confirmer_user_id: id(USER),
            affected_scope_bytes: vec![1],
            operation_id: vec![1],
            confirmed_at_bytes: vec![1],
            revoked_at: None,
            revoked_by: None,
        }],
    };
    let selections = vec![CurrentSelection {
        rule_set_id: id(RULE_SET),
        version_bytes,
    }];
    let budget = CandidateBudget {
        max_table_rows: 64,
        max_bindings_per_read: 8,
    };
    (rows, selections, budget)
}

#[derive(Debug, PartialEq, Eq)]
struct ReaderObservation {
    version: u64,
    digest: astral_authorization_root::memory_v1_digest::ContentDigest,
    batch_one_confirmations: Vec<BinaryId>,
    batch_two_confirmations: Vec<BinaryId>,
    race_confirmations: Vec<BinaryId>,
    impact_binding_ids: Vec<BinaryId>,
}

// memory—v1: Read facts, relationship indexes, and the summary only through one reader snapshot.
fn observe(reader: &RequestRootReader) -> ReaderObservation {
    // memory—v1: Collect confirmation identities from this same reader phase.
    fn confirmation_ids(reader: &RequestRootReader, card_id: u64) -> Vec<BinaryId> {
        let mut ids = reader
            .read_card(id(card_id), |context| {
                context
                    .bindings
                    .into_iter()
                    .flat_map(|binding| {
                        binding
                            .confirmations
                            .into_iter()
                            .map(|confirmation| confirmation.confirmation_id)
                    })
                    .collect::<Vec<_>>()
            })
            .expect("card facts must be readable");
        ids.sort();
        ids
    }

    let mut impact_binding_ids = reader
        .read_impact(id(RULE_SET))
        .expect("rule-set impact must be readable")
        .binding_ids
        .into_iter()
        .collect::<Vec<_>>();
    impact_binding_ids.sort();
    reader
        .publication_validation_timings_for_test()
        .expect("snapshot indexes and reconstructed digest must match");
    let metadata = reader.metadata();
    ReaderObservation {
        version: metadata.version,
        digest: metadata.digest,
        batch_one_confirmations: confirmation_ids(reader, CARD_BATCH_ONE),
        batch_two_confirmations: confirmation_ids(reader, CARD_BATCH_TWO),
        race_confirmations: confirmation_ids(reader, CARD_RACE),
        impact_binding_ids,
    }
}

// memory—v1: Assert that a reader sees both batch targets in one complete phase.
fn assert_batch_phase(observation: &ReaderObservation, expected_confirmed: bool) {
    let (expected_one, expected_two) = if expected_confirmed {
        (
            vec![id(CONFIRMATION_BATCH_ONE)],
            vec![id(CONFIRMATION_BATCH_TWO)],
        )
    } else {
        (Vec::new(), Vec::new())
    };
    assert_eq!(observation.batch_one_confirmations, expected_one);
    assert_eq!(observation.batch_two_confirmations, expected_two);
    assert_eq!(
        (
            observation.batch_one_confirmations.is_empty(),
            observation.batch_two_confirmations.is_empty(),
        ),
        (!expected_confirmed, !expected_confirmed),
        "a reader must not observe one batch confirmation without the other"
    );
}

#[test]
// memory—v1: Prove atomic batch visibility and one-winner stale-version publication.
fn memory_v1_atomic_batch_and_competing_cas() {
    let (rows, selections, budget) = fixture();
    let owner = install_process_root(rows, selections, budget).expect("install test root");
    let handle = owner.handle();

    const OLD_READERS: usize = 4;
    const NEW_READERS: usize = 4;
    let old_barrier = Arc::new(Barrier::new(OLD_READERS + 1));
    let (ready_tx, ready_rx) = mpsc::channel();
    let mut old_threads = Vec::with_capacity(OLD_READERS);
    for index in 0..OLD_READERS {
        let thread_handle = handle.clone();
        let barrier = Arc::clone(&old_barrier);
        let ready_tx = ready_tx.clone();
        old_threads.push(thread::spawn(move || {
            let reader = thread_handle
                .begin_request(Uuid::from_u128(index as u128 + 1))
                .expect("capture old request reader");
            ready_tx.send(reader.metadata()).expect("report old reader");
            barrier.wait();
            let observation = observe(&reader);
            (reader, observation)
        }));
    }
    drop(ready_tx);

    let before_batch = handle.metadata().expect("read initial metadata");
    for _ in 0..OLD_READERS {
        let metadata = ready_rx.recv().expect("all old readers must capture");
        assert_eq!(metadata, before_batch);
    }

    let batch = ManagementMutationV2::ConfirmationBatch {
        rows: vec![
            confirmation(CONFIRMATION_BATCH_ONE, BINDING_BATCH_ONE),
            confirmation(CONFIRMATION_BATCH_TWO, BINDING_BATCH_TWO),
        ],
    };
    let after_batch = owner
        .execute_mutation_with_precondition_for_isolated_tests(
            &batch,
            &MutationPrecondition {
                evaluated_root_version: before_batch.version,
            },
        )
        .expect("batch confirmation publication");
    assert_eq!(after_batch.version, before_batch.version + 1);
    assert_ne!(after_batch.digest, before_batch.digest);

    old_barrier.wait();
    let old_observations = old_threads
        .into_iter()
        .map(|thread| thread.join().expect("old reader thread"))
        .map(|(_, observation)| observation)
        .collect::<Vec<_>>();
    for observation in &old_observations {
        assert_eq!(observation.version, before_batch.version);
        assert_eq!(observation.digest, before_batch.digest);
        assert_batch_phase(observation, false);
    }

    let new_barrier = Arc::new(Barrier::new(NEW_READERS + 1));
    let (new_ready_tx, new_ready_rx) = mpsc::channel();
    let mut new_threads = Vec::with_capacity(NEW_READERS);
    for index in 0..NEW_READERS {
        let thread_handle = handle.clone();
        let barrier = Arc::clone(&new_barrier);
        let ready_tx = new_ready_tx.clone();
        new_threads.push(thread::spawn(move || {
            let reader = thread_handle
                .begin_request(Uuid::from_u128(100 + index as u128))
                .expect("capture new request reader");
            ready_tx.send(reader.metadata()).expect("report new reader");
            barrier.wait();
            let observation = observe(&reader);
            (reader, observation)
        }));
    }
    drop(new_ready_tx);
    for _ in 0..NEW_READERS {
        let metadata = new_ready_rx.recv().expect("all new readers must capture");
        assert_eq!(metadata, after_batch);
    }
    new_barrier.wait();
    let new_observations = new_threads
        .into_iter()
        .map(|thread| thread.join().expect("new reader thread"))
        .map(|(_, observation)| observation)
        .collect::<Vec<_>>();
    for observation in &new_observations {
        assert_eq!(observation.version, after_batch.version);
        assert_eq!(observation.digest, after_batch.digest);
        assert_batch_phase(observation, true);
    }

    let expected_impact = new_observations[0].impact_binding_ids.clone();
    assert_eq!(expected_impact.len(), 4);
    assert!(new_observations
        .iter()
        .all(|observation| observation.impact_binding_ids == expected_impact));

    let race_precondition = MutationPrecondition {
        evaluated_root_version: after_batch.version,
    };
    let race_mutations = [
        ManagementMutationV2::ConfirmationCreate {
            row: confirmation(CONFIRMATION_RACE_LEFT, BINDING_RACE),
        },
        ManagementMutationV2::ConfirmationCreate {
            row: confirmation(CONFIRMATION_RACE_RIGHT, BINDING_RACE),
        },
    ];
    let race_barrier = Arc::new(Barrier::new(race_mutations.len() + 1));
    let (result_tx, result_rx) = mpsc::channel();
    let executor = owner.mutation_executor();
    let mut race_threads = Vec::with_capacity(race_mutations.len());
    for (index, mutation) in race_mutations.into_iter().enumerate() {
        let barrier = Arc::clone(&race_barrier);
        let result_tx = result_tx.clone();
        let executor = executor.clone();
        race_threads.push(thread::spawn(move || {
            barrier.wait();
            let result = executor.execute_for_isolated_tests(&mutation, &race_precondition);
            result_tx.send((index, result)).expect("report race result");
        }));
    }
    drop(result_tx);
    race_barrier.wait();
    for thread in race_threads {
        thread.join().expect("race thread");
    }

    let mut outcomes = result_rx.into_iter().collect::<Vec<_>>();
    outcomes.sort_by_key(|(index, _)| *index);
    assert_eq!(outcomes.len(), 2);
    let success_count = outcomes.iter().filter(|(_, result)| result.is_ok()).count();
    assert_eq!(
        success_count, 1,
        "the shared old version permits one winner"
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|(_, result)| matches!(result, Err(MutationError::ConcurrentModification)))
            .count(),
        1,
        "the stale candidate must report a conflict"
    );
    assert!(outcomes.iter().all(|(_, result)| {
        result.is_ok() || matches!(result, Err(MutationError::ConcurrentModification))
    }));

    let (winner_index, winner_metadata) = outcomes
        .iter()
        .find_map(|(index, result)| result.as_ref().ok().map(|metadata| (*index, *metadata)))
        .expect("one competing candidate must publish");
    let winner_confirmation = if winner_index == 0 {
        id(CONFIRMATION_RACE_LEFT)
    } else {
        id(CONFIRMATION_RACE_RIGHT)
    };
    let loser_confirmation = if winner_index == 0 {
        id(CONFIRMATION_RACE_RIGHT)
    } else {
        id(CONFIRMATION_RACE_LEFT)
    };
    assert_eq!(winner_metadata.version, after_batch.version + 1);
    assert_ne!(winner_metadata.digest, after_batch.digest);

    let final_reader = handle
        .begin_request(Uuid::new_v4())
        .expect("capture final reader");
    let final_observation = observe(&final_reader);
    assert_eq!(final_observation.version, winner_metadata.version);
    assert_eq!(final_observation.digest, winner_metadata.digest);
    assert_eq!(
        final_observation.race_confirmations,
        vec![winner_confirmation],
        "the winner's fact is present and the losing candidate did not insert a row"
    );
    assert!(!final_observation
        .race_confirmations
        .contains(&loser_confirmation));
    assert_eq!(final_observation.impact_binding_ids, expected_impact);
    assert_eq!(
        handle.metadata().expect("read final metadata"),
        winner_metadata,
        "the losing stale candidate did not alter the winner's summary"
    );
}
