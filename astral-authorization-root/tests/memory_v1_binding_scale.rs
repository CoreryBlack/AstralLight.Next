//! memory—v1: Bounded, isolated measurements of binding history and root writes.
//!
//! Run explicitly with `cargo test --offline --locked -p astral-authorization-root
//! --features test-support --test memory_v1_binding_scale -- --ignored --nocapture`.
//! `MEMORY_V1_SCALE_MAX_HISTORY` may lower (never raise) the largest fixture.
//! The last size also verifies that the digest's bounded row limit fails closed.
//! The management call combines candidate construction, validation, hashing and
//! CAS publication. A separate pass measures binding and confirmation index
//! validation and complete digest reconstruction on the resulting immutable
//! snapshot; it is not a phase trace of the timed mutation itself.

#![cfg(feature = "test-support")]

use std::process::Command;
use std::time::Instant;

use astral_authorization_root::memory_v1_db_rows::{
    BinaryId, BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, CurrentSelection,
    IdentityCardRow, RuleSetChangeConfirmationRow, RuleSetRow, RuleSetVersionRow, TenantRow,
    UserCardRow, UserCardStatus, UserRow,
};
use astral_authorization_root::memory_v1_digest::DigestError;
use astral_authorization_root::memory_v1_hamt::CandidateBudget;
use astral_authorization_root::memory_v1_hamt_runtime::RuntimeError;
use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
use astral_authorization_root::memory_v1_root::{
    install_process_root, ManagementMutationV2, MutationPrecondition, RequestRootReader, RootError,
    RootStatus,
};
use astral_authorization_root::memory_v1_rules::{
    canonical_version_bytes, MemoryV1OwnerScope, MemoryV1TenantScope,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const HISTORY_SIZES: [usize; 5] = [0, 100, 1_000, 4_080, 5_000];
const ROUNDS: usize = 3;
const USER: u64 = 1;
const CARD: u64 = 2;
const TENANT: u64 = 3;
const RULE_SET: u64 = 4;
const INITIAL_BINDING: u64 = 10;
const HISTORY_FIRST: u64 = 1_000;
const CREATED_FIRST: u64 = 100_000;

// memory—v1: Generate deterministic table-local identifiers for the isolated fixture.
fn id(value: u64) -> BinaryId {
    (value as u128).to_be_bytes()
}

// memory—v1: Construct a direct binding, optionally retained as a tombstone.
fn binding(value: u64, removed: bool) -> BindingRow {
    BindingRow {
        binding_id: id(value),
        user_card_id: id(CARD),
        rule_set_id: id(RULE_SET),
        binding_layer: BindingLayer::Base,
        valid_from: None,
        valid_until: None,
        owner_scope: MemoryV1OwnerScope::default(),
        tenant_scope: MemoryV1TenantScope::default(),
        removed_at: removed.then_some(10),
        removed_by: removed.then_some(id(USER)),
    }
}

// memory—v1: Construct the confirmation required by the real binding-create operation.
fn confirmation(value: u64) -> BindingConfirmationRow {
    BindingConfirmationRow {
        confirmation_id: id(value),
        binding_id: id(value),
        rule_set_id: id(RULE_SET),
        version_bytes: vec![1],
        confirmer_user_id: id(USER),
        scope_bytes: vec![1],
        operation_id: value.to_be_bytes().to_vec(),
        confirmed_at_bytes: vec![1],
        revoked_at: None,
        revoked_by: None,
    }
}

// memory—v1: Supply one active binding plus same-card, same-rule tombstone history.
fn fixture(history: usize) -> (CandidateRows, Vec<CurrentSelection>, CandidateBudget) {
    let version_bytes = vec![1];
    let content_bytes =
        br#"{"rules":[{"ruleId":"R1","resource":"document","action":"read","effect":"ALLOW"}]}"#
            .to_vec();
    let timestamp_bytes = vec![1];
    let hash_input_bytes =
        canonical_version_bytes(&version_bytes, &content_bytes, &timestamp_bytes);
    let hash_bytes = Sha256::digest(&hash_input_bytes).to_vec();
    let mut bindings = Vec::with_capacity(history + 1);
    bindings.push(binding(INITIAL_BINDING, false));
    bindings.extend((0..history).map(|n| binding(HISTORY_FIRST + n as u64, true)));
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
        bindings,
        binding_confirmations: vec![confirmation(INITIAL_BINDING)],
        rule_set_change_confirmations: vec![RuleSetChangeConfirmationRow {
            confirmation_id: id(1),
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
        max_table_rows: history + 32,
        max_bindings_per_read: history + ROUNDS + 1,
    };
    (rows, selections, budget)
}

// memory—v1: Check both the full historical read and the unremoved authorization view.
fn assert_snapshot(reader: &RequestRootReader, history: usize, active: Option<u64>) {
    let (total, removed, active_ids) = reader
        .read_card(id(CARD), |context| {
            let mut active_ids = Vec::new();
            let mut removed = 0;
            for item in &context.bindings {
                match (item.binding.removed_at, item.binding.removed_by) {
                    (Some(_), Some(by)) => {
                        assert_eq!(by, id(USER));
                        removed += 1;
                    }
                    (None, None) => active_ids.push(item.binding.binding_id),
                    _ => panic!("incomplete binding tombstone"),
                }
            }
            (context.bindings.len(), removed, active_ids)
        })
        .unwrap();
    assert_eq!(total, history + usize::from(active.is_some()));
    assert_eq!(removed, history);
    assert_eq!(active_ids, active.map(id).into_iter().collect::<Vec<_>>());
    let (unremoved, has_history) = reader
        .read_card_for_authorization(id(CARD), |context, has_history| {
            (
                context
                    .bindings
                    .iter()
                    .map(|item| item.binding.binding_id)
                    .collect::<Vec<_>>(),
                has_history,
            )
        })
        .unwrap();
    assert_eq!(unremoved, active.map(id).into_iter().collect::<Vec<_>>());
    assert_eq!(has_history, total > 0);
}

#[test]
#[ignore = "bounded performance experiment; run explicitly without other heavy workloads"]
// memory—v1: Measure real candidate management writes and their atomic root publication.
fn binding_history_scale() {
    if let Ok(value) = std::env::var("MEMORY_V1_SCALE_CHILD_HISTORY") {
        let history = value
            .parse::<usize>()
            .expect("child history must be an integer");
        assert!(
            HISTORY_SIZES.contains(&history),
            "unsupported child history"
        );
        measure_history(history);
        return;
    }
    let max_history = std::env::var("MEMORY_V1_SCALE_MAX_HISTORY")
        .ok()
        .map(|value| {
            value
                .parse::<usize>()
                .expect("history limit must be an integer")
        })
        .unwrap_or(5_000)
        .min(5_000);
    println!("scope=isolated_test clock=Instant unit=ns rounds={ROUNDS} max_history={max_history} mutation_timing=combined_candidate_validation_digest_cas");
    for history in HISTORY_SIZES {
        if history > max_history {
            println!("history={history} outcome=SKIP_CONFIGURED_HISTORY_LIMIT");
            continue;
        }
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "binding_history_scale",
                "--nocapture",
            ])
            .env("MEMORY_V1_SCALE_CHILD_HISTORY", history.to_string())
            .status()
            .expect("start isolated fixture process");
        assert!(status.success(), "history={history} child failed: {status}");
    }
}

// memory—v1: Measure retirement over the same bounded historical relationships.
#[test]
#[ignore = "bounded performance experiment; run explicitly without other heavy workloads"]
fn rule_set_retirement_history_scale() {
    const SIZES: [usize; 4] = [0, 100, 1_000, 4_080];
    if let Ok(value) = std::env::var("MEMORY_V1_RETIRE_SCALE_CHILD_HISTORY") {
        let history = value.parse::<usize>().expect("child history is an integer");
        assert!(SIZES.contains(&history), "unsupported child history");
        let (mut rows, selections, budget) = fixture(history);
        rows.bindings[0].removed_at = Some(10);
        rows.bindings[0].removed_by = Some(id(USER));
        let owner = install_process_root(rows, selections, budget).expect("install candidate");
        owner
            .install_registry(&[RegistryDeclaration {
                resource: "document".to_owned(),
                actions: vec!["read".to_owned()],
            }])
            .expect("install registry");
        owner
            .adopt_serving_for_isolated_tests()
            .expect("adopt isolated root");
        let before = owner
            .handle()
            .metadata()
            .expect("metadata before retirement");
        let started = Instant::now();
        let after = owner
            .execute_mutation_with_precondition_for_isolated_tests(
                &ManagementMutationV2::RuleSetRetire {
                    rule_set_id: id(RULE_SET),
                },
                &MutationPrecondition {
                    evaluated_root_version: before.version,
                },
            )
            .expect("retire without active bindings");
        let retire_ns = started.elapsed().as_nanos();
        assert_eq!(after.version, before.version + 1);
        assert_ne!(after.digest, before.digest);
        let reader = owner.handle().begin_request(Uuid::nil()).unwrap();
        assert_snapshot(&reader, history + 1, None);
        println!("history={history} retire_and_publish_ns={retire_ns} outcome=COMPLETE");
        return;
    }
    println!("scope=isolated_test clock=Instant unit=ns rounds={ROUNDS} mutation_timing=combined_candidate_validation_digest_cas");
    for history in SIZES {
        for round in 0..ROUNDS {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "rule_set_retirement_history_scale",
                    "--nocapture",
                ])
                .env("MEMORY_V1_RETIRE_SCALE_CHILD_HISTORY", history.to_string())
                .output()
                .expect("start isolated retirement fixture");
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success()
                    && stdout.contains("1 passed")
                    && stdout.contains("outcome=COMPLETE"),
                "history={history} round={round} failed\nstdout:\n{stdout}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
            print!("round={round} {stdout}");
        }
    }
}

// memory—v1: Build one fixture per process because the public root slot is write-once.
fn measure_history(history: usize) {
    let started = Instant::now();
    let (rows, selections, budget) = fixture(history);
    let fixture_ns = started.elapsed().as_nanos();
    let started = Instant::now();
    let installed = install_process_root(rows, selections, budget);
    let install_ns = started.elapsed().as_nanos();
    if history == 5_000 {
        assert!(matches!(
            installed,
            Err(RootError::Runtime(RuntimeError::Digest(
                DigestError::LimitExceeded
            )))
        ));
        let (small_rows, small_selections, small_budget) = fixture(0);
        let owner = install_process_root(small_rows, small_selections, small_budget).unwrap();
        assert_eq!(
            owner.handle().metadata().unwrap().status,
            RootStatus::Candidate
        );
        println!("history={history} fixture_ns={fixture_ns} install_candidate_ns={install_ns} outcome=SKIP_MUTATION_DIGEST_ROW_LIMIT");
        return;
    }
    let owner = installed.unwrap();
    owner
        .install_registry(&[RegistryDeclaration {
            resource: "document".to_owned(),
            actions: vec!["read".to_owned()],
        }])
        .unwrap();
    let started = Instant::now();
    let adopted = owner.adopt_serving_for_isolated_tests().unwrap();
    let adopt_ns = started.elapsed().as_nanos();
    assert_eq!(adopted.status, RootStatus::Serving);
    println!("history={history} fixture_ns={fixture_ns} install_candidate_ns={install_ns} isolated_adoption_ns={adopt_ns}");
    let handle = owner.handle();
    let mut active = INITIAL_BINDING;
    for round in 0..ROUNDS {
        let before = handle.begin_request(Uuid::nil()).unwrap();
        let previous = before.metadata();
        let previous_history = history + round;
        assert_snapshot(&before, previous_history, Some(active));
        let remove = ManagementMutationV2::BindingRemove {
            binding_id: id(active),
            removed_at: 20 + round as i64,
            removed_by: id(USER),
        };
        let started = Instant::now();
        let removed = owner
            .execute_mutation_with_precondition_for_isolated_tests(
                &remove,
                &MutationPrecondition {
                    evaluated_root_version: previous.version,
                },
            )
            .unwrap();
        let remove_ns = started.elapsed().as_nanos();
        assert_eq!(removed.version, previous.version + 1);
        assert!(!before.is_current().unwrap());
        assert_snapshot(&before, previous_history, Some(active));
        let after_remove = handle.begin_request(Uuid::nil()).unwrap();
        assert_eq!(after_remove.metadata(), removed);
        assert_snapshot(&after_remove, previous_history + 1, None);

        let new_binding = CREATED_FIRST + round as u64;
        let create = ManagementMutationV2::BindingCreate {
            row: binding(new_binding, false),
            confirmation: confirmation(new_binding),
        };
        let started = Instant::now();
        let created = owner
            .execute_mutation_with_precondition_for_isolated_tests(
                &create,
                &MutationPrecondition {
                    evaluated_root_version: removed.version,
                },
            )
            .unwrap();
        let create_ns = started.elapsed().as_nanos();
        assert_eq!(created.version, removed.version + 1);
        assert!(!after_remove.is_current().unwrap());
        assert_snapshot(&after_remove, previous_history + 1, None);
        let after_create = handle.begin_request(Uuid::nil()).unwrap();
        assert_eq!(after_create.metadata(), created);
        assert_snapshot(&after_create, previous_history + 1, Some(new_binding));
        let (validation_ns, digest_ns) = after_create
            .publication_validation_timings_for_test()
            .expect("isolated snapshot validation and digest agree");
        println!("history_before_remove={previous_history} round={round} remove_and_publish_ns={remove_ns} create_and_publish_ns={create_ns} separate_relationship_index_validation_ns={validation_ns} separate_full_digest_rebuild_ns={digest_ns}");
        active = new_binding;
    }
}
