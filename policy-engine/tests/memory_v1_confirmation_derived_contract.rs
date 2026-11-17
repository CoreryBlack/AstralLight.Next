//! memory—v1: Offline contracts for binding confirmation state and evaluation.
//!
//! Each scenario installs its process root in a separate child test process.
//! The test-only mutation seam proves in-memory behavior, not governance admission,
//! production adoption, persistence, or external integration.

use std::process::Command;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use astral_authorization_root::memory_v1_db_rows::{
    BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, CurrentSelection,
    IdentityCardRow, RuleSetChangeConfirmationRow, RuleSetRow, RuleSetVersionRow, TenantRow,
    UserCardRow, UserCardStatus, UserRow,
};
use astral_authorization_root::memory_v1_hamt::{CandidateBudget, CandidateError};
use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
use astral_authorization_root::memory_v1_request::{RequestRootExtension, RequestRootScope};
use astral_authorization_root::memory_v1_root::{
    install_process_root, process_root_handle, ManagementMutationV2, MutationPrecondition,
    RootError, RootOwner,
};
use astral_authorization_root::memory_v1_rules::{
    canonical_version_bytes, version_digest, MemoryV1OwnerScope, MemoryV1TenantScope,
};
use astral_authorization_root::memory_v1_session::RequestSessionExtension;
use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority;
use astral_types::memory_v1::{CandidateIdentity, MemoryId};
use policy_engine::memory_v1_formal::{
    MemoryV1Decision, MemoryV1DenySource, MemoryV1Evaluation, MemoryV1Request,
};
use policy_engine::PolicyEngine;

const CHILD_SCENARIO: &str = "ASTRAL_CONFIRMATION_DERIVED_SCENARIO";

// memory—v1: Keep fixture identifiers distinct and in the database ID shape.
fn id(value: u8) -> [u8; 16] {
    [value; 16]
}

// memory—v1: Use the real session verifier's trusted time input.
fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

// memory—v1: Construct a complete confirmation for the retained binding.
fn confirmation(value: u8) -> BindingConfirmationRow {
    BindingConfirmationRow {
        confirmation_id: id(value),
        binding_id: id(20),
        rule_set_id: id(10),
        version_bytes: vec![1],
        confirmer_user_id: id(1),
        scope_bytes: vec![1],
        operation_id: vec![value],
        confirmed_at_bytes: vec![1],
        revoked_at: None,
        revoked_by: None,
    }
}

// memory—v1: Construct a structurally complete ALLOW fixture with one binding.
fn fixture() -> (CandidateRows, Vec<CurrentSelection>) {
    let content =
        br#"{"rules":[{"ruleId":"read","resource":"document","action":"read","effect":"ALLOW"}]}"#;
    let version = vec![1];
    let timestamp = vec![2];
    let input = canonical_version_bytes(&version, content, &timestamp);
    (
        CandidateRows {
            users: vec![UserRow { user_id: id(1) }],
            identity_cards: vec![IdentityCardRow {
                identity_card_id: id(2),
                user_id: id(1),
            }],
            tenants: vec![TenantRow {
                tenant_id: id(3),
                parent_tenant_id: None,
            }],
            user_cards: vec![UserCardRow {
                user_card_id: id(4),
                user_id: id(1),
                tenant_id: id(3),
                status: UserCardStatus::Active,
            }],
            rule_sets: vec![RuleSetRow {
                status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
                rule_set_id: id(10),
                owner_tenant_id: id(3),
                current_version_bytes: version.clone(),
            }],
            rule_set_versions: vec![RuleSetVersionRow {
                rule_set_id: id(10),
                version_bytes: version.clone(),
                content_bytes: content.to_vec(),
                timestamp_bytes: timestamp,
                hash_bytes: version_digest(&input),
                hash_input_bytes: input,
            }],
            bindings: vec![BindingRow {
                binding_id: id(20),
                user_card_id: id(4),
                rule_set_id: id(10),
                binding_layer: BindingLayer::Base,
                valid_from: None,
                valid_until: None,
                owner_scope: MemoryV1OwnerScope::SelfUser,
                tenant_scope: MemoryV1TenantScope::SelfTenant,
                removed_at: None,
                removed_by: None,
            }],
            binding_confirmations: vec![confirmation(120)],
            rule_set_change_confirmations: vec![RuleSetChangeConfirmationRow {
                confirmation_id: id(220),
                rule_set_id: id(10),
                version_bytes: version.clone(),
                confirmer_user_id: id(1),
                affected_scope_bytes: vec![1],
                operation_id: vec![220],
                confirmed_at_bytes: vec![1],
                revoked_at: None,
                revoked_by: None,
            }],
        },
        vec![CurrentSelection {
            rule_set_id: id(10),
            version_bytes: version,
        }],
    )
}

// memory—v1: Bound each independent process root's fixture size.
fn budget() -> CandidateBudget {
    CandidateBudget {
        max_table_rows: 256,
        max_bindings_per_read: 16,
    }
}

// memory—v1: Adopt only the isolated fixture after registering its rule action.
fn serving_owner() -> RootOwner {
    let (rows, selections) = fixture();
    serving_owner_from(rows, selections)
}

// memory—v1: Install a supplied complete candidate in an isolated process.
fn serving_owner_from(rows: CandidateRows, selections: Vec<CurrentSelection>) -> RootOwner {
    let owner = install_process_root(rows, selections, budget()).expect("install candidate");
    owner
        .install_registry(&[RegistryDeclaration {
            resource: "document".to_owned(),
            actions: vec!["read".to_owned()],
        }])
        .expect("install registry");
    owner
        .adopt_serving_for_isolated_tests()
        .expect("adopt fixture");
    owner
}

// memory—v1: Issue and verify a real test session against the request snapshot.
fn session(
    authority: &MemoryV1SessionAuthority,
    root: &RequestRootExtension,
) -> RequestSessionExtension {
    let principal = CandidateIdentity {
        user_id: MemoryId::from_bytes(id(1)),
        identity_card_id: MemoryId::from_bytes(id(2)),
        user_card_id: MemoryId::from_bytes(id(4)),
        tenant_id: MemoryId::from_bytes(id(3)),
    };
    let issued = authority
        .identity_session_adapter()
        .issue_unchecked_for_test(principal, now() - 60, 3600)
        .expect("issue test session");
    authority
        .verifier()
        .verify_and_bind(issued.credential(), now(), root)
        .expect("bind test session")
}

// memory—v1: Evaluate the same fully attributed resource through the real engine.
fn evaluate(
    engine: &PolicyEngine,
    root: &RequestRootExtension,
    session: &RequestSessionExtension,
) -> MemoryV1Evaluation {
    let tenant = id(3);
    let user = id(1);
    engine.evaluate_memory_v1(
        root,
        session,
        &MemoryV1Request {
            resource: "document",
            action: "read",
            target: Some(b"object"),
            target_tenant: Some(&tenant),
            target_owner: Some(&user),
            operation_id: b"confirmation-derived-contract",
            operation_fingerprint: b"confirmation-derived-fingerprint",
        },
    )
}

// memory—v1: Check the whole result so non-ALLOW decisions cannot carry admission.
fn assert_pending(result: MemoryV1Evaluation) {
    assert_eq!(result.decision, MemoryV1Decision::Pending);
    assert!(result.pending_source.is_some());
    assert!(result.admission.is_none());
}

// memory—v1: A withdrawn sole binding deterministically has no matching grant.
fn assert_withdrawn(result: MemoryV1Evaluation) {
    assert_eq!(result.decision, MemoryV1Decision::Deny);
    assert_eq!(result.deny_source, Some(MemoryV1DenySource::NoMatch));
    assert!(result.admission.is_none());
}

// memory—v1: Publish a test-only mutation using the current root version.
fn mutate(owner: &RootOwner, mutation: ManagementMutationV2) -> u64 {
    let before = owner.handle().metadata().expect("metadata before mutation");
    let after = owner
        .execute_mutation_with_precondition_for_isolated_tests(
            &mutation,
            &MutationPrecondition {
                evaluated_root_version: before.version,
            },
        )
        .expect("isolated mutation succeeds");
    assert_eq!(after.version, before.version + 1);
    assert_ne!(after.digest, before.digest);
    after.version
}

// memory—v1: An old ALLOW cannot be reused; an old withdrawal remains DENY.
fn revoke_and_reconfirm() {
    let owner = serving_owner();
    let authority = MemoryV1SessionAuthority::new();
    authority.bind_to_root(&owner).unwrap();
    let engine = PolicyEngine::new();
    let old_scope = RequestRootScope::new(owner.handle(), Default::default());
    let old_root = old_scope.extension();
    let old_session = session(&authority, &old_root);
    let first = evaluate(&engine, &old_root, &old_session);
    assert_eq!(first.decision, MemoryV1Decision::Allow);
    let before = first.admission.expect("initial admission").root().version;
    let revoked = mutate(
        &owner,
        ManagementMutationV2::ConfirmationRevoke {
            confirmation_id: id(120),
            revoked_at: now(),
            revoked_by: id(1),
        },
    );
    assert_eq!(revoked, before + 1);
    assert_pending(evaluate(&engine, &old_root, &old_session));

    let withdrawn_scope = RequestRootScope::new(owner.handle(), Default::default());
    let withdrawn_root = withdrawn_scope.extension();
    let withdrawn_session = session(&authority, &withdrawn_root);
    assert_withdrawn(evaluate(&engine, &withdrawn_root, &withdrawn_session));

    let restored = mutate(
        &owner,
        ManagementMutationV2::ConfirmationCreate {
            row: confirmation(121),
        },
    );
    assert_eq!(restored, revoked + 1);
    assert_pending(evaluate(&engine, &old_root, &old_session));
    assert_withdrawn(evaluate(&engine, &withdrawn_root, &withdrawn_session));
    let fresh_scope = RequestRootScope::new(owner.handle(), Default::default());
    let fresh_root = fresh_scope.extension();
    let fresh_session = session(&authority, &fresh_root);
    let result = evaluate(&engine, &fresh_root, &fresh_session);
    assert_eq!(result.decision, MemoryV1Decision::Allow);
    assert_eq!(result.pending_source, None);
    assert_eq!(result.deny_source, None);
    assert_eq!(
        result
            .admission
            .expect("reconfirmation admits")
            .root()
            .version,
        restored
    );
    let history = owner
        .handle()
        .read_card(id(4), |context| {
            context.bindings[0]
                .confirmations
                .iter()
                .map(|row| (row.confirmation_id, row.revoked_at.is_some()))
                .collect::<Vec<_>>()
        })
        .expect("read retained confirmation history")
        .value;
    assert_eq!(history.len(), 2);
    assert!(history.contains(&(id(120), true)));
    assert!(history.contains(&(id(121), false)));
}

// memory—v1: Each version keeps its own confirmation state across revocations
// and publication; old readers can no longer reuse an ALLOW after either change.
fn change_confirmation_lifecycle() {
    let (mut rows, selections) = fixture();
    let mut second = rows.rule_set_change_confirmations[0].clone();
    second.confirmation_id = id(221);
    second.operation_id = vec![221];
    rows.rule_set_change_confirmations.push(second);
    let mut historical = rows.rule_set_change_confirmations[0].clone();
    historical.confirmation_id = id(222);
    historical.operation_id = vec![222];
    historical.version_bytes = vec![9];
    rows.rule_set_change_confirmations.push(historical);
    let mut old_version = rows.rule_set_versions[0].clone();
    old_version.version_bytes = vec![9];
    old_version.hash_input_bytes = canonical_version_bytes(
        &old_version.version_bytes,
        &old_version.content_bytes,
        &old_version.timestamp_bytes,
    );
    old_version.hash_bytes = version_digest(&old_version.hash_input_bytes);
    rows.rule_set_versions.push(old_version);
    let owner = serving_owner_from(rows, selections);
    let authority = MemoryV1SessionAuthority::new();
    authority.bind_to_root(&owner).unwrap();
    let engine = PolicyEngine::new();
    let old_scope = RequestRootScope::new(owner.handle(), Default::default());
    let old_root = old_scope.extension();
    let old_session = session(&authority, &old_root);
    assert_eq!(
        evaluate(&engine, &old_root, &old_session).decision,
        MemoryV1Decision::Allow
    );

    mutate(
        &owner,
        ManagementMutationV2::RuleSetChangeConfirmationRevoke {
            confirmation_id: id(220),
            revoked_at: now(),
            revoked_by: id(1),
        },
    );
    assert_pending(evaluate(&engine, &old_root, &old_session));
    let middle_scope = RequestRootScope::new(owner.handle(), Default::default());
    let middle_root = middle_scope.extension();
    let middle_session = session(&authority, &middle_root);
    let middle = evaluate(&engine, &middle_root, &middle_session);
    assert_eq!(middle.decision, MemoryV1Decision::Allow);
    assert!(middle.admission.is_some());

    mutate(
        &owner,
        ManagementMutationV2::RuleSetChangeConfirmationRevoke {
            confirmation_id: id(221),
            revoked_at: now(),
            revoked_by: id(1),
        },
    );
    assert_pending(evaluate(&engine, &middle_root, &middle_session));
    let withdrawn_scope = RequestRootScope::new(owner.handle(), Default::default());
    let withdrawn_root = withdrawn_scope.extension();
    let withdrawn_session = session(&authority, &withdrawn_root);
    assert_pending(evaluate(&engine, &withdrawn_root, &withdrawn_session));

    let (rows, _) = fixture();
    let mut new_version = rows.rule_set_versions[0].clone();
    new_version.version_bytes = vec![2];
    new_version.hash_input_bytes = canonical_version_bytes(
        &new_version.version_bytes,
        &new_version.content_bytes,
        &new_version.timestamp_bytes,
    );
    new_version.hash_bytes = version_digest(&new_version.hash_input_bytes);
    let mut new_confirmation = rows.rule_set_change_confirmations[0].clone();
    new_confirmation.confirmation_id = id(223);
    new_confirmation.version_bytes = vec![2];
    new_confirmation.operation_id = vec![223];
    let restored = mutate(
        &owner,
        ManagementMutationV2::VersionPublish {
            rule_set_id: id(10),
            version_row: new_version,
            new_current_version: vec![2],
            change_confirmation: new_confirmation,
        },
    );
    assert_pending(evaluate(&engine, &withdrawn_root, &withdrawn_session));
    let current_scope = RequestRootScope::new(owner.handle(), Default::default());
    let current_root = current_scope.extension();
    let current_session = session(&authority, &current_root);
    let result = evaluate(&engine, &current_root, &current_session);
    assert_eq!(result.decision, MemoryV1Decision::Allow);
    assert_eq!(
        result
            .admission
            .expect("new version admission")
            .root()
            .version,
        restored
    );
    let (selected, mut history) = owner
        .handle()
        .read_card(id(4), |context| {
            let binding = &context.bindings[0];
            (
                binding.selected.unwrap().version_bytes.clone(),
                binding
                    .change_confirmations
                    .iter()
                    .map(|row| {
                        (
                            row.confirmation_id,
                            row.version_bytes.clone(),
                            row.revoked_at.is_some(),
                        )
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .unwrap()
        .value;
    history.sort_unstable_by_key(|row| row.0);
    assert_eq!(selected, vec![2]);
    assert_eq!(
        history,
        vec![
            (id(220), vec![1], true),
            (id(221), vec![1], true),
            (id(222), vec![9], false),
            (id(223), vec![2], false),
        ]
    );
}

// memory—v1: Reject structurally loadable malformed or duplicate active rows at adoption.
fn rejected_adoption(scenario: &str) {
    let (mut rows, selections) = fixture();
    match scenario {
        "malformed-first" | "malformed-last" => {
            let mut malformed = confirmation(if scenario == "malformed-first" {
                119
            } else {
                121
            });
            malformed.scope_bytes.clear();
            if scenario == "malformed-first" {
                rows.binding_confirmations.insert(0, malformed);
            } else {
                rows.binding_confirmations.push(malformed);
            }
        }
        "duplicate-first" | "duplicate-last" => {
            let duplicate = confirmation(121);
            if scenario == "duplicate-first" {
                rows.binding_confirmations.insert(0, duplicate);
            } else {
                rows.binding_confirmations.push(duplicate);
            }
        }
        "missing" => rows.binding_confirmations.clear(),
        _ => panic!("unknown adoption scenario: {scenario}"),
    }
    let owner = install_process_root(rows, selections, budget())
        .expect("these rows pass relational candidate loading");
    owner
        .install_registry(&[RegistryDeclaration {
            resource: "document".to_owned(),
            actions: vec!["read".to_owned()],
        }])
        .unwrap();
    let result = owner.adopt_serving_for_isolated_tests();
    assert!(
        matches!(result, Err(RootError::Candidate(CandidateError::MissingConfirmation {
        binding_id, rule_set_id, ..
    })) if binding_id == id(20) && rule_set_id == id(10)),
        "unexpected adoption result: {result:?}"
    );
}

// memory—v1: An incomplete tombstone fails candidate loading, before adoption.
fn rejected_load() {
    let (mut rows, selections) = fixture();
    rows.binding_confirmations[0].revoked_at = Some(100);
    let result = install_process_root(rows, selections, budget());
    assert!(
        matches!(result, Err(RootError::Candidate(CandidateError::Rows(_)))),
        "incomplete tombstone must fail relational loading"
    );
    assert!(matches!(
        process_root_handle(),
        Err(RootError::NotInstalled)
    ));
}

// memory—v1: Every concurrent reader proves both sides of the revoke boundary.
fn concurrent_readers() {
    const READERS: usize = 8;
    let owner = serving_owner();
    let authority = MemoryV1SessionAuthority::new();
    authority.bind_to_root(&owner).unwrap();
    let principal = CandidateIdentity {
        user_id: MemoryId::from_bytes(id(1)),
        identity_card_id: MemoryId::from_bytes(id(2)),
        user_card_id: MemoryId::from_bytes(id(4)),
        tenant_id: MemoryId::from_bytes(id(3)),
    };
    let credential = Arc::new(
        authority
            .identity_session_adapter()
            .issue_unchecked_for_test(principal, now() - 60, 3600)
            .unwrap()
            .credential()
            .to_owned(),
    );
    let before = owner.handle().metadata().unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();
    let mut workers = Vec::new();
    let mut releases = Vec::new();
    for index in 0..READERS {
        let handle = owner.handle();
        let verifier = authority.verifier();
        let credential = Arc::clone(&credential);
        let ready = ready_tx.clone();
        let (release, wait) = mpsc::channel();
        releases.push(release);
        workers.push(thread::spawn(move || {
            let engine = PolicyEngine::new();
            let scope = RequestRootScope::new(handle.clone(), Default::default());
            let root = scope.extension();
            let bound = verifier
                .verify_and_bind(&credential, now(), &root)
                .expect("bind old session");
            let first = evaluate(&engine, &root, &bound);
            assert_eq!(first.decision, MemoryV1Decision::Allow, "reader {index}");
            assert_eq!(
                first.admission.expect("old admission").root().version,
                before.version
            );
            ready.send(index).expect("report pre-revoke evaluation");
            wait.recv_timeout(Duration::from_secs(10))
                .expect("release after revoke");
            assert_pending(evaluate(&engine, &root, &bound));
            let new_scope = RequestRootScope::new(handle, Default::default());
            let new_root = new_scope.extension();
            let new_bound = verifier
                .verify_and_bind(&credential, now(), &new_root)
                .expect("bind fresh session");
            assert_withdrawn(evaluate(&engine, &new_root, &new_bound));
            index
        }));
    }
    drop(ready_tx);
    let mut ready = Vec::new();
    for _ in 0..READERS {
        ready.push(
            ready_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("each reader evaluates before revoke"),
        );
    }
    ready.sort_unstable();
    assert_eq!(ready, (0..READERS).collect::<Vec<_>>());
    let after = mutate(
        &owner,
        ManagementMutationV2::ConfirmationRevoke {
            confirmation_id: id(120),
            revoked_at: now(),
            revoked_by: id(1),
        },
    );
    assert_eq!(after, before.version + 1);
    for release in releases {
        release.send(()).expect("reader remains active");
    }
    let mut completed = workers
        .into_iter()
        .map(|worker| worker.join().expect("reader succeeds"))
        .collect::<Vec<_>>();
    completed.sort_unstable();
    assert_eq!(completed, (0..READERS).collect::<Vec<_>>());
}

// memory—v1: Run each candidate and its single process-root installation in isolation.
#[test]
fn confirmation_derived_contract() {
    if let Ok(scenario) = std::env::var(CHILD_SCENARIO) {
        match scenario.as_str() {
            "revoke-reconfirm" => revoke_and_reconfirm(),
            "change-lifecycle" => change_confirmation_lifecycle(),
            "concurrent" => concurrent_readers(),
            "load-tombstone" => rejected_load(),
            _ => rejected_adoption(&scenario),
        }
        return;
    }
    for scenario in [
        "revoke-reconfirm",
        "change-lifecycle",
        "concurrent",
        "load-tombstone",
        "malformed-first",
        "malformed-last",
        "duplicate-first",
        "duplicate-last",
        "missing",
    ] {
        let output = Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", "confirmation_derived_contract", "--nocapture"])
            .env(CHILD_SCENARIO, scenario)
            .output()
            .expect("start isolated scenario");
        assert!(
            output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "scenario {scenario} failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
