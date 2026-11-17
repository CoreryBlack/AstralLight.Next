//! memory—v1: Offline confirmation-history scaling experiment using isolated roots.
//!
//! Run alone with `cargo test --offline --locked --release -p
//! astral-authorization-root --features test-support --test
//! memory_v1_confirmation_scale -- --ignored --nocapture`.
//! To run only the change-confirmation experiment, append the test filter
//! `change_confirmation_history_scale` after `--`, together with `--ignored
//! --exact --nocapture`.
//! Each sample is a fresh process because the process root can only be installed
//! once. The mutation timing includes candidate construction, validation,
//! digest maintenance and CAS. The diagnostic timings are separate passes over
//! the resulting snapshot, not a breakdown of that mutation. The relationship
//! timing includes both binding and confirmation index validation.

#![cfg(feature = "test-support")]

use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use astral_authorization_root::memory_v1_db_rows::{
    BinaryId, BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, CurrentSelection,
    IdentityCardRow, RuleSetChangeConfirmationRow, RuleSetRow, RuleSetVersionRow, TenantRow,
    UserCardRow, UserCardStatus, UserRow,
};
use astral_authorization_root::memory_v1_digest::MAX_ROOT_DIGEST_KEYS;
use astral_authorization_root::memory_v1_hamt::CandidateBudget;
use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
use astral_authorization_root::memory_v1_root::{
    install_process_root, ManagementMutationV2, MutationPrecondition, RequestRootReader, RootStatus,
};
use astral_authorization_root::memory_v1_rules::{
    canonical_version_bytes, classify_binding_confirmations, classify_change_confirmations,
    BindingConfirmationState, ChangeConfirmationState, MemoryV1OwnerScope, MemoryV1TenantScope,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const HISTORIES: [usize; 4] = [0, 100, 1_000, 4_000];
const SAMPLES: usize = 3;
const TIME_LIMIT: Duration = Duration::from_secs(110);
const USER: u64 = 1;
const CARD: u64 = 2;
const TENANT: u64 = 3;
const RULE_SET: u64 = 4;
const BINDING: u64 = 5;
const ACTIVE_CONFIRMATION: u64 = 10;
const HISTORY_FIRST: u64 = 1_000;

// memory—v1: Use deterministic identifiers in each isolated fixture.
fn id(value: u64) -> BinaryId {
    (value as u128).to_be_bytes()
}

// memory—v1: Construct either the active confirmation or a complete revocation tombstone.
fn confirmation(value: u64, revoked: bool) -> BindingConfirmationRow {
    BindingConfirmationRow {
        confirmation_id: id(value),
        binding_id: id(BINDING),
        rule_set_id: id(RULE_SET),
        version_bytes: vec![1],
        confirmer_user_id: id(USER),
        scope_bytes: vec![1],
        operation_id: value.to_be_bytes().to_vec(),
        confirmed_at_bytes: vec![1],
        revoked_at: revoked.then_some(10),
        revoked_by: revoked.then_some(id(USER)),
    }
}

// memory—v1: Keep the binding graph fixed while varying only confirmation history.
fn fixture(history: usize) -> (CandidateRows, Vec<CurrentSelection>, CandidateBudget) {
    let version = vec![1];
    let content =
        br#"{"rules":[{"ruleId":"R1","resource":"document","action":"read","effect":"ALLOW"}]}"#
            .to_vec();
    let timestamp = vec![1];
    let hash_input = canonical_version_bytes(&version, &content, &timestamp);
    let hash = Sha256::digest(&hash_input).to_vec();
    let mut confirmations = Vec::with_capacity(history + 1);
    confirmations.push(confirmation(ACTIVE_CONFIRMATION, false));
    confirmations.extend((0..history).map(|n| confirmation(HISTORY_FIRST + n as u64, true)));
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
        user_cards: vec![UserCardRow {
            user_card_id: id(CARD),
            user_id: id(USER),
            tenant_id: id(TENANT),
            status: UserCardStatus::Active,
        }],
        rule_sets: vec![RuleSetRow {
            status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
            rule_set_id: id(RULE_SET),
            owner_tenant_id: id(TENANT),
            current_version_bytes: version.clone(),
        }],
        rule_set_versions: vec![RuleSetVersionRow {
            rule_set_id: id(RULE_SET),
            version_bytes: version.clone(),
            content_bytes: content,
            timestamp_bytes: timestamp,
            hash_input_bytes: hash_input,
            hash_bytes: hash,
        }],
        bindings: vec![BindingRow {
            binding_id: id(BINDING),
            user_card_id: id(CARD),
            rule_set_id: id(RULE_SET),
            binding_layer: BindingLayer::Base,
            valid_from: None,
            valid_until: None,
            owner_scope: MemoryV1OwnerScope::default(),
            tenant_scope: MemoryV1TenantScope::default(),
            removed_at: None,
            removed_by: None,
        }],
        binding_confirmations: confirmations,
        rule_set_change_confirmations: vec![RuleSetChangeConfirmationRow {
            confirmation_id: id(1),
            rule_set_id: id(RULE_SET),
            version_bytes: version.clone(),
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
        version_bytes: version,
    }];
    let budget = CandidateBudget {
        max_table_rows: history + 32,
        max_bindings_per_read: 1,
    };
    (rows, selections, budget)
}

// memory—v1: Compare every reader-visible confirmation with its full expected row.
fn assert_history(reader: &RequestRootReader, history: usize) {
    reader
        .read_card(id(CARD), |context| {
            assert_eq!(context.card.status, UserCardStatus::Active);
            assert_eq!(context.bindings.len(), 1);
            let binding = &context.bindings[0];
            assert_eq!(binding.binding.binding_id, id(BINDING));
            assert_eq!(binding.confirmations.len(), history + 1);
            assert_eq!(
                classify_binding_confirmations(
                    binding.confirmations.iter().copied(),
                    id(BINDING),
                    id(RULE_SET),
                ),
                BindingConfirmationState::Active
            );
            let mut actual = binding
                .confirmations
                .iter()
                .map(|row| (*row).clone())
                .collect::<Vec<_>>();
            actual.sort_unstable_by_key(|row| row.confirmation_id);
            let mut expected = Vec::with_capacity(history + 1);
            expected.push(confirmation(ACTIVE_CONFIRMATION, false));
            expected.extend((0..history).map(|n| confirmation(HISTORY_FIRST + n as u64, true)));
            expected.sort_unstable_by_key(|row| row.confirmation_id);
            assert_eq!(actual, expected);
        })
        .expect("complete confirmation history must be readable");
}

// memory—v1: Measure one independent installation, adoption, mutation and diagnostic pass.
fn measure(history: usize, sample: usize) {
    let run_started = Instant::now();
    let started = Instant::now();
    let (rows, selections, budget) = fixture(history);
    let fixture_ns = started.elapsed().as_nanos();
    let row_count = rows.users.len()
        + rows.identity_cards.len()
        + rows.tenants.len()
        + rows.user_cards.len()
        + rows.rule_sets.len()
        + rows.rule_set_versions.len()
        + rows.bindings.len()
        + rows.binding_confirmations.len()
        + rows.rule_set_change_confirmations.len();
    let digest_keys = row_count + selections.len();
    if digest_keys > MAX_ROOT_DIGEST_KEYS {
        println!("history={history} sample={sample} digest_keys={digest_keys} outcome=SKIP_DIGEST_KEY_LIMIT");
        return;
    }
    let started = Instant::now();
    let owner = install_process_root(rows, selections, budget).expect("install candidate");
    let install_ns = started.elapsed().as_nanos();
    assert_eq!(owner.handle().metadata().unwrap().row_count, row_count);
    owner
        .install_registry(&[RegistryDeclaration {
            resource: "document".to_owned(),
            actions: vec!["read".to_owned()],
        }])
        .expect("install registry");
    let started = Instant::now();
    let adopted = owner
        .adopt_serving_for_isolated_tests()
        .expect("adopt fixture");
    let adoption_ns = started.elapsed().as_nanos();
    assert_eq!(adopted.status, RootStatus::Serving);
    let handle = owner.handle();
    let before = handle
        .begin_request(Uuid::nil())
        .expect("capture old reader");
    assert_history(&before, history);
    let started = Instant::now();
    let published = owner
        .execute_mutation_with_precondition_for_isolated_tests(
            &ManagementMutationV2::UserCardStatus {
                user_card_id: id(CARD),
                status: UserCardStatus::Active,
            },
            &MutationPrecondition {
                evaluated_root_version: before.metadata().version,
            },
        )
        .expect("publish active-to-active card status");
    let candidate_cas_ns = started.elapsed().as_nanos();
    assert_eq!(published.version, before.metadata().version + 1);
    assert_eq!(published.digest, before.metadata().digest);
    assert_eq!(published.row_count, row_count);
    assert!(!before.is_current().unwrap());
    assert_history(&before, history);
    let after = handle
        .begin_request(Uuid::nil())
        .expect("capture new reader");
    assert_eq!(after.metadata(), published);
    assert_history(&after, history);
    let (relationship_ns, digest_ns) = after
        .publication_validation_timings_for_test()
        .expect("relationship indexes and reconstructed digest must agree");
    println!("history={history} sample={sample} digest_keys={digest_keys} fixture_ns={fixture_ns} install_candidate_ns={install_ns} isolated_adoption_ns={adoption_ns} active_to_active_candidate_cas_ns={candidate_cas_ns} separate_binding_and_confirmation_index_validation_ns={relationship_ns} separate_full_digest_rebuild_ns={digest_ns} sample_execution_ns={} outcome=MEASURED", run_started.elapsed().as_nanos());
}

#[test]
#[ignore = "offline scaling experiment; run explicitly without concurrent tests"]
// memory—v1: Run bounded independent samples, terminating a child on the deadline.
fn confirmation_history_scale() {
    if let Ok(value) = std::env::var("MEMORY_V1_CONFIRMATION_SCALE_CHILD") {
        let (history, sample) = value.split_once(':').expect("child parameters");
        let history = history.parse::<usize>().expect("child history");
        let sample = sample.parse::<usize>().expect("child sample");
        assert!(HISTORIES.contains(&history) && sample < SAMPLES);
        measure(history, sample);
        return;
    }
    let run_started = Instant::now();
    let mut timed_out = false;
    let mut skipped = false;
    println!("scope=isolated_test clock=Instant unit=ns samples={SAMPLES} execution_limit_s={} relationship_timing=binding_and_confirmation_indexes", TIME_LIMIT.as_secs());
    for history in HISTORIES {
        for sample in 0..SAMPLES {
            // This fixture has nine fixed table rows plus one current-selection key.
            if history + 10 > MAX_ROOT_DIGEST_KEYS {
                skipped = true;
                println!("history={history} sample={sample} outcome=SKIP_DIGEST_KEY_LIMIT");
                continue;
            }
            if timed_out || run_started.elapsed() >= TIME_LIMIT {
                timed_out = true;
                skipped = true;
                println!("history={history} sample={sample} outcome=SKIP_EXECUTION_TIME_LIMIT");
                continue;
            }
            let mut child = Command::new(std::env::current_exe().expect("test executable"))
                .args([
                    "--ignored",
                    "--exact",
                    "confirmation_history_scale",
                    "--nocapture",
                ])
                .env(
                    "MEMORY_V1_CONFIRMATION_SCALE_CHILD",
                    format!("{history}:{sample}"),
                )
                .spawn()
                .expect("start isolated sample");
            loop {
                if let Some(status) = child.try_wait().expect("poll isolated sample") {
                    assert!(
                        status.success(),
                        "history={history} sample={sample} child failed: {status}"
                    );
                    break;
                }
                if run_started.elapsed() >= TIME_LIMIT {
                    child.kill().expect("terminate overdue sample");
                    child.wait().expect("reap overdue sample");
                    timed_out = true;
                    skipped = true;
                    println!("history={history} sample={sample} outcome=SKIP_EXECUTION_TIME_LIMIT");
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
    println!(
        "total_execution_ns={} outcome={}",
        run_started.elapsed().as_nanos(),
        if skipped { "SKIP" } else { "COMPLETE" }
    );
}

// memory—v1: Construct complete change-confirmation rows, including historical tombstones.
fn change_confirmation(value: u64, revoked: bool) -> RuleSetChangeConfirmationRow {
    RuleSetChangeConfirmationRow {
        confirmation_id: id(value),
        rule_set_id: id(RULE_SET),
        version_bytes: vec![1],
        confirmer_user_id: id(USER),
        affected_scope_bytes: vec![1],
        operation_id: value.to_be_bytes().to_vec(),
        confirmed_at_bytes: vec![1],
        revoked_at: revoked.then_some(10),
        revoked_by: revoked.then_some(id(USER)),
    }
}

// memory—v1: Check every change-confirmation row and classify the entire history.
fn assert_change_history(reader: &RequestRootReader, history: usize) {
    reader
        .read_card(id(CARD), |context| {
            assert_eq!(context.bindings.len(), 1);
            let binding = &context.bindings[0];
            assert_eq!(binding.binding.binding_id, id(BINDING));
            assert_eq!(binding.change_confirmations.len(), history + 1);
            assert_eq!(
                classify_change_confirmations(
                    binding.change_confirmations.iter().copied(),
                    id(RULE_SET),
                    &[1],
                ),
                ChangeConfirmationState::Active
            );
            let mut actual = binding
                .change_confirmations
                .iter()
                .map(|row| (*row).clone())
                .collect::<Vec<_>>();
            actual.sort_unstable_by_key(|row| row.confirmation_id);
            let mut expected = Vec::with_capacity(history + 1);
            expected.push(change_confirmation(ACTIVE_CONFIRMATION, false));
            expected
                .extend((0..history).map(|n| change_confirmation(HISTORY_FIRST + n as u64, true)));
            expected.sort_unstable_by_key(|row| row.confirmation_id);
            assert_eq!(actual, expected);
        })
        .expect("complete change-confirmation history must be readable");
}

// memory—v1: Measure publication and independent validation for one isolated history sample.
fn measure_change_confirmation(binding_history: usize, change_history: usize, sample: usize) {
    let run_started = Instant::now();
    let started = Instant::now();
    let (mut rows, selections, mut budget) = fixture(binding_history);
    rows.rule_set_change_confirmations =
        std::iter::once(change_confirmation(ACTIVE_CONFIRMATION, false))
            .chain((0..change_history).map(|n| change_confirmation(HISTORY_FIRST + n as u64, true)))
            .collect();
    budget.max_table_rows += change_history;
    let fixture_ns = started.elapsed().as_nanos();
    let row_count = rows.users.len()
        + rows.identity_cards.len()
        + rows.tenants.len()
        + rows.user_cards.len()
        + rows.rule_sets.len()
        + rows.rule_set_versions.len()
        + rows.bindings.len()
        + rows.binding_confirmations.len()
        + rows.rule_set_change_confirmations.len();
    let digest_keys = row_count + selections.len();
    assert!(digest_keys <= MAX_ROOT_DIGEST_KEYS, "digest key limit");

    let started = Instant::now();
    let owner = install_process_root(rows, selections, budget).expect("install candidate");
    let install_ns = started.elapsed().as_nanos();
    assert_eq!(owner.handle().metadata().unwrap().row_count, row_count);
    owner
        .install_registry(&[RegistryDeclaration {
            resource: "document".to_owned(),
            actions: vec!["read".to_owned()],
        }])
        .expect("install registry");
    let started = Instant::now();
    let adopted = owner
        .adopt_serving_for_isolated_tests()
        .expect("adopt fixture");
    let adoption_ns = started.elapsed().as_nanos();
    assert_eq!(adopted.status, RootStatus::Serving);
    let handle = owner.handle();
    let before = handle
        .begin_request(Uuid::nil())
        .expect("capture old reader");
    assert_history(&before, binding_history);
    assert_change_history(&before, change_history);
    let started = Instant::now();
    let published = owner
        .execute_mutation_with_precondition_for_isolated_tests(
            &ManagementMutationV2::UserCardStatus {
                user_card_id: id(CARD),
                status: UserCardStatus::Active,
            },
            &MutationPrecondition {
                evaluated_root_version: before.metadata().version,
            },
        )
        .expect("publish active-to-active card status");
    let candidate_cas_ns = started.elapsed().as_nanos();
    assert_eq!(published.version, before.metadata().version + 1);
    assert_eq!(published.digest, before.metadata().digest);
    assert_eq!(published.row_count, row_count);
    assert!(!before.is_current().unwrap());
    assert_history(&before, binding_history);
    assert_change_history(&before, change_history);
    let after = handle
        .begin_request(Uuid::nil())
        .expect("capture new reader");
    assert_eq!(after.metadata(), published);
    assert_history(&after, binding_history);
    assert_change_history(&after, change_history);
    let (relationship_ns, digest_ns) = after
        .publication_validation_timings_for_test()
        .expect("relationship indexes and reconstructed digest must agree");
    println!("binding_history={binding_history} change_history={change_history} sample={sample} digest_keys={digest_keys} fixture_ns={fixture_ns} install_candidate_ns={install_ns} isolated_adoption_ns={adoption_ns} active_to_active_candidate_cas_ns={candidate_cas_ns} separate_binding_and_confirmation_index_validation_ns={relationship_ns} separate_full_digest_rebuild_ns={digest_ns} sample_execution_ns={} outcome=MEASURED", run_started.elapsed().as_nanos());
}

#[test]
#[ignore = "offline scaling experiment; run explicitly without concurrent tests"]
// memory—v1: Bound each change-history sample in a fresh process and report every skip.
fn change_confirmation_history_scale() {
    const CASES: [(usize, usize); 5] = [(0, 0), (0, 100), (0, 1_000), (0, 4_000), (2_000, 2_000)];
    if let Ok(value) = std::env::var("MEMORY_V1_CHANGE_CONFIRMATION_SCALE_CHILD") {
        let mut parameters = value.split(':');
        let binding_history = parameters
            .next()
            .expect("binding history")
            .parse::<usize>()
            .expect("binding history number");
        let change_history = parameters
            .next()
            .expect("change history")
            .parse::<usize>()
            .expect("change history number");
        let sample = parameters
            .next()
            .expect("sample")
            .parse::<usize>()
            .expect("sample number");
        assert!(parameters.next().is_none());
        assert!(CASES.contains(&(binding_history, change_history)) && sample < SAMPLES);
        measure_change_confirmation(binding_history, change_history, sample);
        return;
    }
    let run_started = Instant::now();
    let mut timed_out = false;
    let mut skipped = false;
    println!("scope=isolated_change_confirmation_test clock=Instant unit=ns samples={SAMPLES} execution_limit_s={} relationship_timing=binding_and_confirmation_indexes", TIME_LIMIT.as_secs());
    for (binding_history, change_history) in CASES {
        for sample in 0..SAMPLES {
            // Nine fixed rows and one selection, plus both historical populations.
            if binding_history + change_history + 10 > MAX_ROOT_DIGEST_KEYS {
                skipped = true;
                println!("binding_history={binding_history} change_history={change_history} sample={sample} outcome=SKIP_DIGEST_KEY_LIMIT");
                continue;
            }
            if timed_out || run_started.elapsed() >= TIME_LIMIT {
                timed_out = true;
                skipped = true;
                println!("binding_history={binding_history} change_history={change_history} sample={sample} outcome=SKIP_EXECUTION_TIME_LIMIT");
                continue;
            }
            let mut child = Command::new(std::env::current_exe().expect("test executable"))
                .args([
                    "--ignored",
                    "--exact",
                    "change_confirmation_history_scale",
                    "--nocapture",
                ])
                .env(
                    "MEMORY_V1_CHANGE_CONFIRMATION_SCALE_CHILD",
                    format!("{binding_history}:{change_history}:{sample}"),
                )
                .spawn()
                .expect("start isolated sample");
            loop {
                if let Some(status) = child.try_wait().expect("poll isolated sample") {
                    assert!(status.success(), "binding_history={binding_history} change_history={change_history} sample={sample} child failed: {status}");
                    break;
                }
                if run_started.elapsed() >= TIME_LIMIT {
                    child.kill().expect("terminate overdue sample");
                    child.wait().expect("reap overdue sample");
                    timed_out = true;
                    skipped = true;
                    println!("binding_history={binding_history} change_history={change_history} sample={sample} outcome=SKIP_EXECUTION_TIME_LIMIT");
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
    println!(
        "total_execution_ns={} outcome={}",
        run_started.elapsed().as_nanos(),
        if skipped { "SKIP" } else { "COMPLETE" }
    );
}
