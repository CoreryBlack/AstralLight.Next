//! Offline contracts for rule-set retirement and the real memory-v1 evaluator.
//!
//! Each case owns its process root. The test-only mutation interface bypasses
//! governance admission and proves neither durable audit nor persistence.

use std::process::Command;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use astral_authorization_root::memory_v1_db_rows::{
    BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, CurrentSelection,
    IdentityCardRow, RuleSetChangeConfirmationRow, RuleSetRow, RuleSetStatus, RuleSetVersionRow,
    TenantRow, UserCardRow, UserCardStatus, UserRow,
};
use astral_authorization_root::memory_v1_hamt::CandidateBudget;
use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
use astral_authorization_root::memory_v1_request::{RequestRootExtension, RequestRootScope};
use astral_authorization_root::memory_v1_root::{
    install_process_root, ManagementMutationV2, MutationPrecondition, RootOwner,
};
use astral_authorization_root::memory_v1_rules::{
    canonical_version_bytes, version_digest, MemoryV1OwnerScope, MemoryV1TenantScope,
};
use astral_authorization_root::memory_v1_session::RequestSessionExtension;
use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority;
use astral_types::memory_v1::{CandidateIdentity, MemoryId};
use policy_engine::memory_v1_compound::{
    MemoryV1CompoundAction, MemoryV1CompoundRequest, MemoryV1CompoundTargetKind,
};
use policy_engine::memory_v1_formal::{
    MemoryV1Decision, MemoryV1DenySource, MemoryV1Evaluation, MemoryV1Request,
    MemoryV1RuleSetChangeIntent,
};
use policy_engine::PolicyEngine;

const CHILD_SCENARIO: &str = "ASTRAL_RULESET_RETIREMENT_SCENARIO";

// memory—v1: Keep fixture identifiers distinct and in the database ID shape.
fn id(value: u8) -> [u8; 16] {
    [value; 16]
}

// memory—v1: Use the session verifier's time input for each isolated request.
fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_secs(),
    )
    .expect("time fits i64")
}

// memory—v1: Build one confirmed binding and its real evaluator rule.
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
                rule_set_id: id(10),
                owner_tenant_id: id(3),
                current_version_bytes: version.clone(),
                status: RuleSetStatus::Active,
            }],
            rule_set_versions: vec![RuleSetVersionRow {
                rule_set_id: id(10),
                version_bytes: version.clone(),
                content_bytes: content.to_vec(),
                timestamp_bytes: timestamp,
                hash_input_bytes: input.clone(),
                hash_bytes: version_digest(&input),
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
            binding_confirmations: vec![BindingConfirmationRow {
                confirmation_id: id(21),
                binding_id: id(20),
                rule_set_id: id(10),
                version_bytes: version.clone(),
                confirmer_user_id: id(1),
                scope_bytes: vec![1],
                operation_id: vec![1],
                confirmed_at_bytes: vec![1],
                revoked_at: None,
                revoked_by: None,
            }],
            rule_set_change_confirmations: vec![RuleSetChangeConfirmationRow {
                confirmation_id: id(22),
                rule_set_id: id(10),
                version_bytes: version.clone(),
                confirmer_user_id: id(1),
                affected_scope_bytes: vec![1],
                operation_id: vec![2],
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

// memory—v1: Install and adopt only an isolated, explicitly supplied root.
fn serving_owner(rows: CandidateRows, selections: Vec<CurrentSelection>) -> RootOwner {
    let owner = install_process_root(
        rows,
        selections,
        CandidateBudget {
            max_table_rows: 128,
            max_bindings_per_read: 16,
        },
    )
    .expect("install candidate");
    owner
        .install_registry(&[RegistryDeclaration {
            resource: "document".into(),
            actions: vec!["read".into()],
        }])
        .expect("register request");
    owner
        .adopt_serving_for_isolated_tests()
        .expect("adopt isolated root");
    owner
}

// memory—v1: Bind a real test session to the exact request scope.
fn session(
    authority: &MemoryV1SessionAuthority,
    root: &RequestRootExtension,
) -> RequestSessionExtension {
    let identity = CandidateIdentity {
        user_id: MemoryId::from_bytes(id(1)),
        identity_card_id: MemoryId::from_bytes(id(2)),
        user_card_id: MemoryId::from_bytes(id(4)),
        tenant_id: MemoryId::from_bytes(id(3)),
    };
    let issued = authority
        .identity_session_adapter()
        .issue_unchecked_for_test(identity, now() - 60, 3600)
        .expect("issue session");
    authority
        .verifier()
        .verify_and_bind(issued.credential(), now(), root)
        .expect("bind session")
}

// memory—v1: Evaluate a fully attributed request through the real engine.
fn evaluate(
    engine: &PolicyEngine,
    root: &RequestRootExtension,
    session: &RequestSessionExtension,
) -> MemoryV1Evaluation {
    let tenant = id(3);
    let owner = id(1);
    engine.evaluate_memory_v1(
        root,
        session,
        &MemoryV1Request {
            resource: "document",
            action: "read",
            target: Some(b"object"),
            target_tenant: Some(&tenant),
            target_owner: Some(&owner),
            operation_id: b"retirement-contract",
            operation_fingerprint: b"retirement-contract-fingerprint",
        },
    )
}

// memory—v1: Read metadata immediately before an isolated CAS mutation.
fn mutate(owner: &RootOwner, mutation: &ManagementMutationV2) -> bool {
    let metadata = owner.handle().metadata().expect("root metadata");
    owner
        .execute_mutation_with_precondition_for_isolated_tests(
            mutation,
            &MutationPrecondition {
                evaluated_root_version: metadata.version,
            },
        )
        .is_ok()
}

// memory—v1: A zero-binding retirement preserves history but cannot revive it.
fn retired_after_remove() {
    let (rows, selections) = fixture();
    let owner = serving_owner(rows, selections);
    let authority = MemoryV1SessionAuthority::new();
    authority.bind_to_root(&owner).expect("bind authority");
    let engine = PolicyEngine::new();
    let old_scope = RequestRootScope::new(owner.handle(), Default::default());
    let old_root = old_scope.extension();
    let old_session = session(&authority, &old_root);
    assert_eq!(
        evaluate(&engine, &old_root, &old_session).decision,
        MemoryV1Decision::Allow
    );
    assert!(!mutate(
        &owner,
        &ManagementMutationV2::RuleSetRetire {
            rule_set_id: id(10),
        },
    ));
    assert!(mutate(
        &owner,
        &ManagementMutationV2::BindingRemove {
            binding_id: id(20),
            removed_at: now(),
            removed_by: id(1),
        },
    ));
    let before_retire = owner
        .handle()
        .metadata()
        .expect("metadata before retirement");
    assert!(mutate(
        &owner,
        &ManagementMutationV2::RuleSetRetire {
            rule_set_id: id(10),
        },
    ));
    let retired = owner
        .handle()
        .metadata()
        .expect("metadata after retirement");
    assert_eq!(retired.version, before_retire.version + 1);
    assert_ne!(retired.digest, before_retire.digest);
    let old = evaluate(&engine, &old_root, &old_session);
    assert_ne!(old.decision, MemoryV1Decision::Allow);
    assert!(old.admission.is_none());
    let fresh_scope = RequestRootScope::new(owner.handle(), Default::default());
    let fresh_root = fresh_scope.extension();
    let fresh_session = session(&authority, &fresh_root);
    let fresh = evaluate(&engine, &fresh_root, &fresh_session);
    assert_eq!(fresh.decision, MemoryV1Decision::Deny);
    assert!(matches!(
        fresh.deny_source,
        Some(MemoryV1DenySource::CardUnbound | MemoryV1DenySource::NoMatch)
    ));
    assert!(fresh.admission.is_none());
    let unchanged = owner.handle().metadata().expect("retired metadata");
    assert!(!mutate(
        &owner,
        &ManagementMutationV2::RuleSetRetire {
            rule_set_id: id(10),
        },
    ));
    assert_eq!(owner.handle().metadata().unwrap(), unchanged);
}

// memory—v1: Retiring a set on a disabled card must not let enabling revive it.
fn disabled_card_cannot_revive() {
    let (mut rows, selections) = fixture();
    rows.user_cards[0].status = UserCardStatus::Disabled;
    let owner = serving_owner(rows, selections);
    assert!(mutate(
        &owner,
        &ManagementMutationV2::RuleSetRetire {
            rule_set_id: id(10),
        },
    ));
    let before_enable = owner.handle().metadata().expect("retired metadata");
    assert!(!mutate(
        &owner,
        &ManagementMutationV2::UserCardStatus {
            user_card_id: id(4),
            status: UserCardStatus::Active,
        },
    ));
    assert_eq!(owner.handle().metadata().unwrap(), before_enable);
    let status = owner
        .handle()
        .read_card(id(4), |context| context.card.status)
        .expect("read disabled card")
        .value;
    assert_eq!(status, UserCardStatus::Disabled);
}

// memory—v1: Two writers with the same root precondition cannot both commit.
fn competing_retirements() {
    const WRITERS: usize = 16;
    let (mut rows, selections) = fixture();
    rows.bindings[0].removed_at = Some(now());
    rows.bindings[0].removed_by = Some(id(1));
    let owner = serving_owner(rows, selections);
    let before = owner.handle().metadata().expect("metadata before race");
    let barrier = Arc::new(Barrier::new(WRITERS));
    let mut workers = Vec::new();
    for _ in 0..WRITERS {
        let executor = owner.mutation_executor();
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            executor
                .execute_for_isolated_tests(
                    &ManagementMutationV2::RuleSetRetire {
                        rule_set_id: id(10),
                    },
                    &MutationPrecondition {
                        evaluated_root_version: before.version,
                    },
                )
                .is_ok()
        }));
    }
    let successes = workers
        .into_iter()
        .map(|worker| usize::from(worker.join().expect("writer completes")))
        .sum::<usize>();
    assert_eq!(successes, 1);
    let after = owner.handle().metadata().expect("metadata after race");
    assert_eq!(after.version, before.version + 1);
    assert_ne!(after.digest, before.digest);
}

// memory—v1: A cold candidate cannot activate a retired set through a live card.
fn reject_active_retired_candidate() {
    let (mut rows, selections) = fixture();
    rows.rule_sets[0].status = RuleSetStatus::Retired;
    match install_process_root(
        rows,
        selections,
        CandidateBudget {
            max_table_rows: 128,
            max_bindings_per_read: 16,
        },
    ) {
        Err(_) => {}
        Ok(owner) => {
            owner
                .install_registry(&[RegistryDeclaration {
                    resource: "document".into(),
                    actions: vec!["read".into()],
                }])
                .expect("register request");
            assert!(owner.adopt_serving_for_isolated_tests().is_err());
        }
    }
}

// memory—v1: A retire admission requires an active target at the read phase.
fn retired_target_cannot_receive_retirement_admission() {
    let (mut rows, mut selections) = fixture();
    let content = br#"{"rules":[{"ruleId":"retire","resource":"rule_set","action":"retire","effect":"ALLOW","ownerScope":"all"}]}"#;
    let version = vec![1];
    let timestamp = vec![2];
    let input = canonical_version_bytes(&version, content, &timestamp);
    rows.rule_set_versions[0].content_bytes = content.to_vec();
    rows.rule_set_versions[0].hash_input_bytes = input.clone();
    rows.rule_set_versions[0].hash_bytes = version_digest(&input);
    rows.bindings[0].owner_scope = MemoryV1OwnerScope::AllUsers;
    for (rule_set_id, status) in [
        (id(11), RuleSetStatus::Active),
        (id(12), RuleSetStatus::Retired),
    ] {
        rows.rule_sets.push(RuleSetRow {
            rule_set_id,
            owner_tenant_id: id(3),
            current_version_bytes: version.clone(),
            status,
        });
        rows.rule_set_versions.push(RuleSetVersionRow {
            rule_set_id,
            version_bytes: version.clone(),
            content_bytes: content.to_vec(),
            timestamp_bytes: timestamp.clone(),
            hash_input_bytes: input.clone(),
            hash_bytes: version_digest(&input),
        });
        selections.push(CurrentSelection {
            rule_set_id,
            version_bytes: version.clone(),
        });
        rows.rule_set_change_confirmations
            .push(RuleSetChangeConfirmationRow {
                confirmation_id: if rule_set_id == id(11) {
                    id(23)
                } else {
                    id(24)
                },
                rule_set_id,
                version_bytes: version.clone(),
                confirmer_user_id: id(1),
                affected_scope_bytes: vec![1],
                operation_id: vec![3, rule_set_id[0]],
                confirmed_at_bytes: vec![1],
                revoked_at: None,
                revoked_by: None,
            });
    }
    let owner = install_process_root(
        rows,
        selections,
        CandidateBudget {
            max_table_rows: 128,
            max_bindings_per_read: 16,
        },
    )
    .expect("install candidate");
    owner
        .install_registry(&[RegistryDeclaration {
            resource: "rule_set".into(),
            actions: vec!["retire".into()],
        }])
        .expect("register retirement");
    owner
        .adopt_serving_for_isolated_tests()
        .expect("adopt isolated root");
    let authority = MemoryV1SessionAuthority::new();
    authority.bind_to_root(&owner).expect("bind authority");
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let session = session(&authority, &root);
    let engine = PolicyEngine::new();
    let tenant = id(3);
    let before = owner
        .handle()
        .metadata()
        .expect("metadata before evaluation");
    for (target, expected) in [
        (id(11), MemoryV1Decision::Allow),
        (id(12), MemoryV1Decision::Pending),
    ] {
        let facts = root
            .with_reader(|reader| reader.rule_set_target(target))
            .expect("read target")
            .expect("target facts");
        let actions = [MemoryV1CompoundAction {
            request: MemoryV1Request {
                resource: "rule_set",
                action: "retire",
                target: Some(&target),
                target_tenant: Some(&tenant),
                target_owner: None,
                operation_id: b"retirement-target-status",
                operation_fingerprint: b"retirement-target-status-fingerprint",
            },
            change_intent: None,
            target_facts: facts,
            target_kind: MemoryV1CompoundTargetKind::Existing,
        }];
        let result = engine.evaluate_memory_v1_compound(
            &root,
            &session,
            &MemoryV1CompoundRequest { actions: &actions },
        );
        assert_eq!(result.decision, expected, "target status must be checked");
        assert_eq!(
            result.admissions.len(),
            usize::from(expected == MemoryV1Decision::Allow)
        );
        if expected == MemoryV1Decision::Pending {
            assert_eq!(
                result.pending_source,
                Some(policy_engine::memory_v1_formal::MemoryV1PendingSource::ContextInvalid)
            );
            assert!(result.deny_observation.is_none());
        }
    }
    assert_eq!(owner.handle().metadata().unwrap(), before);
}

// memory—v1: Retained rule-set history cannot authorize a new binding or publish.
fn retired_target_cannot_receive_create_or_publish_admission() {
    let (mut rows, mut selections) = fixture();
    let content = br#"{"rules":[{"ruleId":"create","resource":"binding","action":"create","effect":"ALLOW","ownerScope":"all"},{"ruleId":"confirm","resource":"binding","action":"confirm","effect":"ALLOW","ownerScope":"all"},{"ruleId":"publish","resource":"rule_set","action":"version-publish","effect":"ALLOW","ownerScope":"all"},{"ruleId":"confirm-change","resource":"rule_set","action":"confirm-change","effect":"ALLOW","ownerScope":"all"}]}"#;
    let version = vec![1];
    let timestamp = vec![2];
    let input = canonical_version_bytes(&version, content, &timestamp);
    rows.rule_set_versions[0].content_bytes = content.to_vec();
    rows.rule_set_versions[0].hash_input_bytes = input.clone();
    rows.rule_set_versions[0].hash_bytes = version_digest(&input);
    rows.bindings[0].owner_scope = MemoryV1OwnerScope::AllUsers;
    for (rule_set_id, status) in [
        (id(11), RuleSetStatus::Active),
        (id(12), RuleSetStatus::Retired),
    ] {
        rows.rule_sets.push(RuleSetRow {
            rule_set_id,
            owner_tenant_id: id(3),
            current_version_bytes: version.clone(),
            status,
        });
        rows.rule_set_versions.push(RuleSetVersionRow {
            rule_set_id,
            version_bytes: version.clone(),
            content_bytes: content.to_vec(),
            timestamp_bytes: timestamp.clone(),
            hash_input_bytes: input.clone(),
            hash_bytes: version_digest(&input),
        });
        selections.push(CurrentSelection {
            rule_set_id,
            version_bytes: version.clone(),
        });
        rows.rule_set_change_confirmations
            .push(RuleSetChangeConfirmationRow {
                confirmation_id: if rule_set_id == id(11) {
                    id(23)
                } else {
                    id(24)
                },
                rule_set_id,
                version_bytes: version.clone(),
                confirmer_user_id: id(1),
                affected_scope_bytes: vec![1],
                operation_id: vec![3, rule_set_id[0]],
                confirmed_at_bytes: vec![1],
                revoked_at: None,
                revoked_by: None,
            });
    }
    rows.users.push(UserRow { user_id: id(30) });
    rows.identity_cards.push(IdentityCardRow {
        identity_card_id: id(31),
        user_id: id(30),
    });
    rows.user_cards.push(UserCardRow {
        user_card_id: id(32),
        user_id: id(30),
        tenant_id: id(3),
        status: UserCardStatus::Active,
    });
    let owner = install_process_root(
        rows,
        selections,
        CandidateBudget {
            max_table_rows: 128,
            max_bindings_per_read: 16,
        },
    )
    .expect("install candidate");
    owner
        .install_registry(&[
            RegistryDeclaration {
                resource: "binding".into(),
                actions: vec!["create".into(), "confirm".into()],
            },
            RegistryDeclaration {
                resource: "rule_set".into(),
                actions: vec!["version-publish".into(), "confirm-change".into()],
            },
        ])
        .expect("register governance actions");
    owner
        .adopt_serving_for_isolated_tests()
        .expect("adopt isolated root");
    let authority = MemoryV1SessionAuthority::new();
    authority.bind_to_root(&owner).expect("bind authority");
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let session = session(&authority, &root);
    let engine = PolicyEngine::new();
    let tenant = id(3);
    let beneficiary = id(30);
    let card = id(32);
    let binding = id(33);
    let before = owner.handle().metadata().unwrap();
    let expect_admission = |decision, actual, expected| {
        assert_eq!(decision, expected);
        assert_eq!(actual, usize::from(expected == MemoryV1Decision::Allow));
    };
    for (target, expected) in [
        (id(11), MemoryV1Decision::Allow),
        (id(12), MemoryV1Decision::Pending),
    ] {
        let facts = root
            .with_reader(|reader| {
                let rule_set = reader.rule_set_target(target)?;
                let card = reader.user_card_target(card)?;
                Ok::<_, astral_authorization_root::memory_v1_root::RootError>(
                    astral_authorization_root::memory_v1_root::GovernanceTargetFacts {
                        user_card_id: card.user_card_id,
                        rule_set_id: rule_set.rule_set_id,
                        owner_user_id: card.owner_user_id,
                        tenant_id: card.tenant_id,
                    },
                )
            })
            .unwrap()
            .unwrap();
        let binding_request = MemoryV1Request {
            resource: "binding",
            action: "create",
            target: Some(&binding),
            target_tenant: Some(&tenant),
            target_owner: Some(&beneficiary),
            operation_id: b"retired-binding-target",
            operation_fingerprint: b"retired-binding-target-fingerprint",
        };
        let binding_actions = [
            MemoryV1CompoundAction {
                request: binding_request,
                change_intent: None,
                target_facts: facts,
                target_kind: MemoryV1CompoundTargetKind::BindingCreate,
            },
            MemoryV1CompoundAction {
                request: MemoryV1Request {
                    action: "confirm",
                    ..binding_request
                },
                change_intent: None,
                target_facts: facts,
                target_kind: MemoryV1CompoundTargetKind::BindingCreate,
            },
        ];
        let result = engine.evaluate_memory_v1_compound(
            &root,
            &session,
            &MemoryV1CompoundRequest {
                actions: &binding_actions,
            },
        );
        assert_eq!(result.decision, expected);
        assert_eq!(
            result.admissions.len(),
            if expected == MemoryV1Decision::Allow {
                2
            } else {
                0
            }
        );

        let rule_set_facts = root
            .with_reader(|reader| reader.rule_set_target(target))
            .unwrap()
            .unwrap();
        let publish_request = MemoryV1Request {
            resource: "rule_set",
            action: "version-publish",
            target: Some(&target),
            target_tenant: Some(&tenant),
            target_owner: None,
            operation_id: b"retired-publish-target",
            operation_fingerprint: b"retired-publish-target-fingerprint",
        };
        let confirm_request = MemoryV1Request {
            action: "confirm-change",
            ..publish_request
        };
        let change = engine.evaluate_memory_v1_rule_set_change(
            &root,
            &session,
            &confirm_request,
            MemoryV1RuleSetChangeIntent::Publish,
        );
        expect_admission(
            change.decision,
            usize::from(change.admission.is_some()),
            expected,
        );
        let publish_actions = [
            MemoryV1CompoundAction {
                request: publish_request,
                change_intent: None,
                target_facts: rule_set_facts,
                target_kind: MemoryV1CompoundTargetKind::Existing,
            },
            MemoryV1CompoundAction {
                request: confirm_request,
                change_intent: Some(MemoryV1RuleSetChangeIntent::Publish),
                target_facts: rule_set_facts,
                target_kind: MemoryV1CompoundTargetKind::Existing,
            },
        ];
        let result = engine.evaluate_memory_v1_compound(
            &root,
            &session,
            &MemoryV1CompoundRequest {
                actions: &publish_actions,
            },
        );
        assert_eq!(result.decision, expected);
        assert_eq!(
            result.admissions.len(),
            if expected == MemoryV1Decision::Allow {
                2
            } else {
                0
            }
        );
    }
    assert_eq!(owner.handle().metadata().unwrap(), before);
}

// memory—v1: Keep once-per-process root installations isolated and visible.
#[test]
fn rule_set_retirement_contract() {
    if let Ok(scenario) = std::env::var(CHILD_SCENARIO) {
        match scenario.as_str() {
            "remove-retire" => retired_after_remove(),
            "disabled-revival" => disabled_card_cannot_revive(),
            "competing-retirements" => competing_retirements(),
            "invalid-cold-candidate" => reject_active_retired_candidate(),
            "retired-target-admission" => retired_target_cannot_receive_retirement_admission(),
            "retired-create-publish" => retired_target_cannot_receive_create_or_publish_admission(),
            _ => panic!("unknown retirement scenario: {scenario}"),
        }
        return;
    }
    for scenario in [
        "remove-retire",
        "disabled-revival",
        "competing-retirements",
        "invalid-cold-candidate",
        "retired-target-admission",
        "retired-create-publish",
    ] {
        let output = Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", "rule_set_retirement_contract", "--nocapture"])
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
