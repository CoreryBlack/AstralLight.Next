//! memory—v1 compound authorization contract tests.
//!
//! These tests use the real process root, request root scope, authenticated
//! session authority, and PolicyEngine. Each root-backed case runs in a child
//! process because the process root is installed only once. No service, listener,
//! database, queue, or migration is started.

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use astral_authorization_root::memory_v1_adoption::{
    AdoptionLimit, ColdLoadFacts, MEMORY_V1_CANDIDATE_SCHEMA_VERSION,
};
use astral_authorization_root::memory_v1_db_rows::{
    BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, CurrentSelection,
    IdentityCardRow, RuleSetChangeConfirmationRow, RuleSetRow, RuleSetVersionRow, TenantRow,
    UserCardRow, UserCardStatus, UserRow,
};
use astral_authorization_root::memory_v1_fence::FenceDeclaration;
use astral_authorization_root::memory_v1_hamt::CandidateBudget;
use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
use astral_authorization_root::memory_v1_request::RequestRootScope;
use astral_authorization_root::memory_v1_root::{
    install_process_root, DependencyRecord, EvaluationDependency, ManagementMutationV2,
    MutationPrecondition, RootOwner,
};
use astral_authorization_root::memory_v1_rules::{canonical_version_bytes, version_digest};
use astral_authorization_root::memory_v1_session::{
    FinalCheckTimeConstraints, FinalCheckWindow, RequestSessionExtension,
};
use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority;
use astral_types::memory_v1::{CandidateIdentity, MemoryId};
use policy_engine::memory_v1_batch::{MemoryV1BatchItem, MemoryV1BatchRequest};
use policy_engine::memory_v1_compound::{
    MemoryV1CompoundAction, MemoryV1CompoundRequest, MemoryV1CompoundTargetKind,
};
use policy_engine::memory_v1_formal::{
    MemoryV1Decision, MemoryV1DenySource, MemoryV1PendingSource, MemoryV1Request,
    MemoryV1RuleSetChangeIntent,
};
use policy_engine::PolicyEngine;

const CHILD_ENV: &str = "ASTRAL_MEMORY_V1_COMPOUND_CONTRACT_CHILD";

fn id(value: u8) -> [u8; 16] {
    [value; 16]
}

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after unix epoch")
            .as_secs(),
    )
    .expect("test clock fits in i64")
}

fn version(content: &[u8]) -> RuleSetVersionRow {
    let version_bytes = vec![1];
    let timestamp_bytes = vec![2];
    let hash_input_bytes = canonical_version_bytes(&version_bytes, content, &timestamp_bytes);
    RuleSetVersionRow {
        rule_set_id: id(30),
        version_bytes,
        content_bytes: content.to_vec(),
        timestamp_bytes,
        hash_input_bytes: hash_input_bytes.clone(),
        hash_bytes: version_digest(&hash_input_bytes),
    }
}

fn fixture(confirm_effect: &str) -> (RootOwner, MemoryV1SessionAuthority) {
    fixture_with_rule_set_scope(confirm_effect, "all")
}

fn fixture_with_rule_set_scope(
    confirm_effect: &str,
    rule_set_owner_scope: &str,
) -> (RootOwner, MemoryV1SessionAuthority) {
    fixture_with_adoption(confirm_effect, rule_set_owner_scope, false)
}

// memory—v1: Keep the existing fixtures while permitting a distinct target rule set.
fn fixture_with_adoption(
    confirm_effect: &str,
    rule_set_owner_scope: &str,
    experimental: bool,
) -> (RootOwner, MemoryV1SessionAuthority) {
    fixture_with_distinct_target(confirm_effect, rule_set_owner_scope, experimental, false)
}

// memory—v1: Experimental adoption exercises the real acknowledged-limit path;
// isolated-test adoption is reserved for the rule algorithm fixtures below.
fn fixture_with_distinct_target(
    confirm_effect: &str,
    rule_set_owner_scope: &str,
    experimental: bool,
    distinct_target: bool,
) -> (RootOwner, MemoryV1SessionAuthority) {
    fixture_with_create_target_facts(
        confirm_effect,
        rule_set_owner_scope,
        experimental,
        distinct_target,
        false,
    )
}

// memory—v1: The create-target fixture includes a user without cards and an
// existing tenant without a user relationship, without changing other fixtures.
fn fixture_with_create_target_facts(
    confirm_effect: &str,
    rule_set_owner_scope: &str,
    experimental: bool,
    distinct_target: bool,
    create_target_facts: bool,
) -> (RootOwner, MemoryV1SessionAuthority) {
    let create_scope = if distinct_target { "self" } else { "all" };
    let content = format!(
        "{{\"rules\":[{{\"ruleId\":\"create\",\"resource\":\"binding\",\"action\":\"create\",\"effect\":\"ALLOW\",\"ownerScope\":\"{}\",\"tenantScope\":\"self\"}},{{\"ruleId\":\"confirm\",\"resource\":\"binding\",\"action\":\"confirm\",\"effect\":\"{}\",\"ownerScope\":\"all\",\"tenantScope\":\"self\"}},{{\"ruleId\":\"rule-set-create\",\"resource\":\"rule_set\",\"action\":\"create\",\"effect\":\"ALLOW\",\"ownerScope\":\"{}\",\"tenantScope\":\"self\"}},{{\"ruleId\":\"rule-set-confirm\",\"resource\":\"rule_set\",\"action\":\"confirm-change\",\"effect\":\"ALLOW\",\"ownerScope\":\"{}\",\"tenantScope\":\"self\"}},{{\"ruleId\":\"disable\",\"resource\":\"user_card\",\"action\":\"disable\",\"effect\":\"ALLOW\",\"ownerScope\":\"all\",\"tenantScope\":\"self\"}}]}}",
        create_scope, confirm_effect, rule_set_owner_scope, rule_set_owner_scope
    );
    let content = content.into_bytes();
    let mut rows = CandidateRows {
        users: vec![UserRow { user_id: id(1) }, UserRow { user_id: id(2) }],
        identity_cards: vec![
            IdentityCardRow {
                identity_card_id: id(3),
                user_id: id(1),
            },
            IdentityCardRow {
                identity_card_id: id(4),
                user_id: id(2),
            },
        ],
        tenants: vec![TenantRow {
            tenant_id: id(10),
            parent_tenant_id: None,
        }],
        user_cards: vec![
            UserCardRow {
                user_card_id: id(20),
                user_id: id(1),
                tenant_id: id(10),
                status: UserCardStatus::Active,
            },
            UserCardRow {
                user_card_id: id(21),
                user_id: id(2),
                tenant_id: id(10),
                status: UserCardStatus::Active,
            },
        ],
        rule_sets: vec![RuleSetRow {
            status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
            rule_set_id: id(30),
            owner_tenant_id: id(10),
            current_version_bytes: vec![1],
        }],
        rule_set_versions: vec![version(&content)],
        bindings: vec![BindingRow {
            binding_id: id(40),
            user_card_id: id(20),
            rule_set_id: id(30),
            binding_layer: BindingLayer::Base,
            valid_from: None,
            valid_until: None,
            owner_scope: astral_authorization_root::memory_v1_rules::MemoryV1OwnerScope::AllUsers,
            tenant_scope:
                astral_authorization_root::memory_v1_rules::MemoryV1TenantScope::SelfTenant,
            removed_at: None,
            removed_by: None,
        }],
        binding_confirmations: vec![BindingConfirmationRow {
            confirmation_id: id(50),
            binding_id: id(40),
            rule_set_id: id(30),
            version_bytes: vec![1],
            confirmer_user_id: id(2),
            scope_bytes: vec![1],
            operation_id: vec![50],
            confirmed_at_bytes: vec![1],
            revoked_at: None,
            revoked_by: None,
        }],
        rule_set_change_confirmations: vec![RuleSetChangeConfirmationRow {
            confirmation_id: id(60),
            rule_set_id: id(30),
            version_bytes: vec![1],
            confirmer_user_id: id(2),
            affected_scope_bytes: vec![1],
            operation_id: vec![60],
            confirmed_at_bytes: vec![1],
            revoked_at: None,
            revoked_by: None,
        }],
    };
    if create_target_facts {
        rows.users.push(UserRow { user_id: id(5) });
        rows.identity_cards.push(IdentityCardRow {
            identity_card_id: id(6),
            user_id: id(5),
        });
        rows.tenants.push(TenantRow {
            tenant_id: id(11),
            parent_tenant_id: None,
        });
    }
    let mut selections = vec![CurrentSelection {
        rule_set_id: id(30),
        version_bytes: vec![1],
    }];
    if distinct_target {
        rows.user_cards.push(UserCardRow {
            user_card_id: id(22),
            user_id: id(1),
            tenant_id: id(10),
            status: UserCardStatus::Active,
        });
        for rule_set_id in [31, 32] {
            rows.rule_sets.push(RuleSetRow {
                status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
                rule_set_id: id(rule_set_id),
                owner_tenant_id: id(10),
                current_version_bytes: vec![1],
            });
            let mut rule_version = version(&content);
            rule_version.rule_set_id = id(rule_set_id);
            rows.rule_set_versions.push(rule_version);
            rows.rule_set_change_confirmations
                .push(RuleSetChangeConfirmationRow {
                    confirmation_id: id(rule_set_id + 30),
                    rule_set_id: id(rule_set_id),
                    version_bytes: vec![1],
                    confirmer_user_id: id(2),
                    affected_scope_bytes: vec![1],
                    operation_id: vec![rule_set_id + 30],
                    confirmed_at_bytes: vec![1],
                    revoked_at: None,
                    revoked_by: None,
                });
            selections.push(CurrentSelection {
                rule_set_id: id(rule_set_id),
                version_bytes: vec![1],
            });
        }
        rows.bindings.push(BindingRow {
            binding_id: id(41),
            user_card_id: id(22),
            rule_set_id: id(31),
            binding_layer: BindingLayer::Base,
            valid_from: None,
            valid_until: None,
            owner_scope: astral_authorization_root::memory_v1_rules::MemoryV1OwnerScope::AllUsers,
            tenant_scope:
                astral_authorization_root::memory_v1_rules::MemoryV1TenantScope::SelfTenant,
            removed_at: None,
            removed_by: None,
        });
        rows.binding_confirmations.push(BindingConfirmationRow {
            confirmation_id: id(51),
            binding_id: id(41),
            rule_set_id: id(31),
            version_bytes: vec![1],
            confirmer_user_id: id(2),
            scope_bytes: vec![1],
            operation_id: vec![51],
            confirmed_at_bytes: vec![1],
            revoked_at: None,
            revoked_by: None,
        });
        rows.bindings.push(BindingRow {
            binding_id: id(42),
            user_card_id: id(22),
            rule_set_id: id(32),
            binding_layer: BindingLayer::Overlay,
            valid_from: None,
            valid_until: None,
            owner_scope: astral_authorization_root::memory_v1_rules::MemoryV1OwnerScope::AllUsers,
            tenant_scope:
                astral_authorization_root::memory_v1_rules::MemoryV1TenantScope::SelfTenant,
            removed_at: None,
            removed_by: None,
        });
        rows.binding_confirmations.push(BindingConfirmationRow {
            confirmation_id: id(52),
            binding_id: id(42),
            rule_set_id: id(32),
            version_bytes: vec![1],
            confirmer_user_id: id(2),
            scope_bytes: vec![1],
            operation_id: vec![52],
            confirmed_at_bytes: vec![1],
            revoked_at: None,
            revoked_by: None,
        });
    }
    let counts = rows.table_counts();
    let owner = install_process_root(
        rows,
        selections,
        CandidateBudget {
            max_table_rows: 128,
            max_bindings_per_read: 16,
        },
    )
    .expect("compound fixture root installs");
    owner
        .install_registry(&[
            RegistryDeclaration {
                resource: "binding".to_owned(),
                actions: vec![
                    "create".to_owned(),
                    "confirm".to_owned(),
                    "remove".to_owned(),
                ],
            },
            RegistryDeclaration {
                resource: "rule_set".to_owned(),
                actions: vec!["create".to_owned(), "confirm-change".to_owned()],
            },
            RegistryDeclaration {
                resource: "user_card".to_owned(),
                actions: vec!["disable".to_owned()],
            },
        ])
        .expect("compound fixture registry installs");
    if experimental {
        owner
            .adopt_experimental(
                &ColdLoadFacts {
                    schema_contract_version: MEMORY_V1_CANDIDATE_SCHEMA_VERSION,
                    schema_fingerprint: [1; 32],
                    snapshot_counts: counts,
                    scanned_counts: counts,
                    captured_at_unix_seconds: now(),
                },
                &AdoptionLimit::EXPERIMENTAL,
            )
            .expect("experimental fixture becomes serving with acknowledged limits");
    } else {
        owner
            .adopt_serving_for_isolated_tests()
            .expect("compound fixture becomes serving");
    }
    let authority = MemoryV1SessionAuthority::new();
    authority
        .bind_to_root(&owner)
        .expect("session authority binds to fixture root");
    (owner, authority)
}

fn principal() -> CandidateIdentity {
    CandidateIdentity {
        user_id: MemoryId::from_bytes(id(1)),
        identity_card_id: MemoryId::from_bytes(id(3)),
        user_card_id: MemoryId::from_bytes(id(20)),
        tenant_id: MemoryId::from_bytes(id(10)),
    }
}

fn session_for(
    authority: &MemoryV1SessionAuthority,
    root: &astral_authorization_root::memory_v1_request::RequestRootExtension,
) -> (RequestSessionExtension, String) {
    let issued = authority
        .identity_session_adapter()
        .issue_unchecked_for_test(principal(), now() - 60, 3_600)
        .expect("compound session issues");
    let credential = issued.credential().to_owned();
    let session = authority
        .verifier()
        .verify_and_bind(issued.credential(), now(), root)
        .expect("compound session binds");
    (session, credential)
}

fn action<'a>(
    action: &'a str,
    target: &'a [u8; 16],
    tenant: &'a [u8; 16],
    owner: &'a [u8; 16],
    facts: astral_authorization_root::memory_v1_root::GovernanceTargetFacts,
) -> MemoryV1CompoundAction<'a> {
    MemoryV1CompoundAction {
        request: MemoryV1Request {
            resource: "binding",
            action,
            target: Some(target),
            target_tenant: Some(tenant),
            target_owner: Some(owner),
            operation_id: b"compound-operation",
            operation_fingerprint: b"compound-fingerprint",
        },
        change_intent: None,
        target_facts: facts,
        target_kind: MemoryV1CompoundTargetKind::BindingCreate,
    }
}

fn rule_set_create_action<'a>(
    action: &'a str,
    target: &'a [u8; 16],
    tenant: &'a [u8; 16],
    facts: astral_authorization_root::memory_v1_root::GovernanceTargetFacts,
    change_intent: Option<MemoryV1RuleSetChangeIntent>,
) -> MemoryV1CompoundAction<'a> {
    MemoryV1CompoundAction {
        request: MemoryV1Request {
            resource: "rule_set",
            action,
            target: Some(target),
            target_tenant: Some(tenant),
            target_owner: None,
            operation_id: b"rule-set-compound-operation",
            operation_fingerprint: b"rule-set-compound-fingerprint",
        },
        change_intent,
        target_facts: facts,
        target_kind: MemoryV1CompoundTargetKind::RuleSetCreate,
    }
}

fn run_isolated(test_name: &str) {
    if std::env::var_os(CHILD_ENV).is_some() {
        return;
    }
    let output = Command::new(std::env::current_exe().expect("test executable exists"))
        .args(["--exact", test_name, "--nocapture"])
        .env(CHILD_ENV, "1")
        .output()
        .expect("start isolated compound contract test");
    assert!(
        output.status.success(),
        "isolated test failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "isolated test did not report one passing test\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

// memory—v1: Exercise target windows through the real root and evaluator, with
// actor and target rule sets separated so actor dependency fencing cannot mask it.
#[test]
fn compound_checks_distinct_target_fences_before_denials() {
    run_isolated("compound_checks_distinct_target_fences_before_denials");
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    let (owner, authority) = fixture_with_distinct_target("DENY", "all", false, true);
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let (session, _) = session_for(&authority, &root);
    let engine = PolicyEngine::new();
    let target = id(70);
    let tenant = id(10);
    let other_user = id(2);
    let actor = id(1);
    let other_facts = root
        .with_reader(|reader| reader.binding_create_target(id(21), id(31)))
        .unwrap()
        .unwrap();
    let actor_facts = root
        .with_reader(|reader| reader.binding_create_target(id(22), id(31)))
        .unwrap()
        .unwrap();
    let existing_facts = root
        .with_reader(|reader| reader.binding_target(id(41)))
        .unwrap()
        .unwrap();
    assert_eq!(existing_facts.owner_user_id, actor);
    assert_eq!(existing_facts.rule_set_id, id(31));
    let existing_target = id(41);
    let mut existing_self = action("confirm", &existing_target, &tenant, &actor, existing_facts);
    existing_self.target_kind = MemoryV1CompoundTargetKind::Existing;
    let rule_deny = action("confirm", &target, &tenant, &other_user, other_facts);
    let scope_deny = action("create", &target, &tenant, &other_user, other_facts);
    let allowed = action("create", &target, &tenant, &actor, actor_facts);
    let self_confirm = action("confirm", &target, &tenant, &actor, actor_facts);
    let evaluate_phase =
        |root: &astral_authorization_root::memory_v1_request::RequestRootExtension,
         session: &RequestSessionExtension,
         actions: &[MemoryV1CompoundAction<'_>]| {
            engine.evaluate_memory_v1_compound(root, session, &MemoryV1CompoundRequest { actions })
        };
    let evaluate =
        |actions: &[MemoryV1CompoundAction<'_>]| evaluate_phase(&root, &session, actions);
    let assert_deny = |actions: &[MemoryV1CompoundAction<'_>], source| {
        let result = evaluate(actions);
        assert_eq!(result.decision, MemoryV1Decision::Deny);
        assert_eq!(result.deny_source, Some(source));
        assert_eq!(result.pending_source, None);
        assert!(result.admissions.is_empty());
    };
    let assert_pending = |actions: &[MemoryV1CompoundAction<'_>]| {
        let result = evaluate(actions);
        assert_eq!(result.decision, MemoryV1Decision::Pending);
        assert_eq!(
            result.pending_source,
            Some(MemoryV1PendingSource::FenceActive)
        );
        assert_eq!(result.deny_source, None);
        assert!(result.admissions.is_empty());
        assert!(result.deny_observation.is_none());
    };
    let open = |rule_set_id| {
        let metadata = owner.handle().metadata().unwrap();
        owner
            .begin_modification_fence(
                id(rule_set_id),
                &FenceDeclaration {
                    rule_set_version: vec![1],
                    root_version: metadata.version,
                    digest: metadata.digest,
                },
            )
            .unwrap();
    };

    assert_deny(&[rule_deny], MemoryV1DenySource::RuleDenied);
    assert_deny(&[scope_deny], MemoryV1DenySource::ScopeDenied);
    for (actions, expected_source, expected_action) in [
        (
            [scope_deny, rule_deny],
            MemoryV1DenySource::ScopeDenied,
            "create",
        ),
        (
            [rule_deny, scope_deny],
            MemoryV1DenySource::RuleDenied,
            "confirm",
        ),
    ] {
        let result = evaluate(&actions);
        let observation = result.deny_observation.as_deref().unwrap();
        assert_eq!(result.deny_source, Some(expected_source));
        assert_eq!(observation.source(), expected_source);
        assert_eq!(observation.action(), expected_action);
    }
    assert_deny(&[existing_self], MemoryV1DenySource::SelfConfirmation);
    assert_eq!(evaluate(&[allowed]).decision, MemoryV1Decision::Allow);
    open(31);
    assert_pending(&[rule_deny]);
    assert_pending(&[scope_deny]);
    assert_pending(&[existing_self]);
    assert_pending(&[allowed]);
    assert_pending(&[allowed, self_confirm]);
    assert_pending(&[self_confirm, allowed]);
    owner.abort_modification_fence(id(31)).unwrap();
    assert_deny(&[rule_deny], MemoryV1DenySource::RuleDenied);
    assert_deny(&[scope_deny], MemoryV1DenySource::ScopeDenied);
    assert_deny(&[existing_self], MemoryV1DenySource::SelfConfirmation);
    assert_deny(
        &[allowed, self_confirm],
        MemoryV1DenySource::SelfConfirmation,
    );
    assert_eq!(evaluate(&[allowed]).decision, MemoryV1Decision::Pending);
    let fresh_scope = RequestRootScope::new(owner.handle(), Default::default());
    let fresh_root = fresh_scope.extension();
    let (fresh_session, _) = session_for(&authority, &fresh_root);
    let evaluate = |actions: &[MemoryV1CompoundAction<'_>]| {
        evaluate_phase(&fresh_root, &fresh_session, actions)
    };
    assert_eq!(evaluate(&[allowed]).decision, MemoryV1Decision::Allow);

    // Rule set 32 is unrelated to the binding target but is the second active
    // binding of card 22; disabling the card must check both derived targets.
    open(32);
    assert_deny(&[rule_deny], MemoryV1DenySource::RuleDenied);
    assert_eq!(evaluate(&[allowed]).decision, MemoryV1Decision::Allow);
    let card = id(22);
    let card_facts = root
        .with_reader(|reader| reader.user_card_target(card))
        .unwrap()
        .unwrap();
    let disable = MemoryV1CompoundAction {
        request: MemoryV1Request {
            resource: "user_card",
            action: "disable",
            target: Some(&card),
            target_tenant: Some(&tenant),
            target_owner: Some(&actor),
            operation_id: b"disable-card",
            operation_fingerprint: b"disable-card-fingerprint",
        },
        change_intent: None,
        target_facts: card_facts,
        target_kind: MemoryV1CompoundTargetKind::UserCardDisable,
    };
    assert_pending(&[disable]);
    assert_eq!(
        evaluate(&[disable]).pending_source,
        Some(MemoryV1PendingSource::FenceActive)
    );
    owner.abort_modification_fence(id(32)).unwrap();
    assert_eq!(evaluate(&[disable]).decision, MemoryV1Decision::Pending);
    let final_scope = RequestRootScope::new(owner.handle(), Default::default());
    let final_root = final_scope.extension();
    let (final_session, _) = session_for(&authority, &final_root);
    let evaluate = |actions: &[MemoryV1CompoundAction<'_>]| {
        evaluate_phase(&final_root, &final_session, actions)
    };
    assert_eq!(evaluate(&[disable]).decision, MemoryV1Decision::Allow);

    // A forged expected rule-set ID cannot replace the binding's root-derived ID.
    let mut forged = existing_self;
    forged.target_facts.rule_set_id = id(32);
    let result = evaluate(&[forged]);
    assert_eq!(result.decision, MemoryV1Decision::Pending);
    assert_eq!(
        result.pending_source,
        Some(MemoryV1PendingSource::ContextInvalid)
    );
}

// memory—v1: A poisoned target-fence registry cannot establish either an
// unfenced target or a deterministic denial. It must fail closed.
#[test]
fn compound_target_fence_read_failure_is_pending() {
    run_isolated("compound_target_fence_read_failure_is_pending");
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    let (owner, authority) = fixture_with_distinct_target("DENY", "all", false, true);
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let (session, _) = session_for(&authority, &root);
    let facts = root
        .with_reader(|reader| reader.binding_create_target(id(21), id(31)))
        .unwrap()
        .unwrap();
    let target = id(70);
    let tenant = id(10);
    let beneficiary = id(2);
    let request = action("confirm", &target, &tenant, &beneficiary, facts);
    let engine = PolicyEngine::new();
    let evaluate = || {
        engine.evaluate_memory_v1_compound(
            &root,
            &session,
            &MemoryV1CompoundRequest {
                actions: &[request],
            },
        )
    };
    let before = evaluate();
    assert_eq!(before.decision, MemoryV1Decision::Deny);
    assert_eq!(before.deny_source, Some(MemoryV1DenySource::RuleDenied));

    let injection = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        root.with_reader(|reader| {
            reader
                .with_final_check_lock_for_test("fence", || panic!("inject fence writer poison"))
                .unwrap();
        })
        .unwrap();
    }));
    assert!(injection.is_err());
    assert!(root
        .with_reader(|reader| reader.is_fenced(id(31)))
        .unwrap()
        .is_err());
    let failed = evaluate();
    assert_eq!(failed.decision, MemoryV1Decision::Pending);
    assert_eq!(
        failed.pending_source,
        Some(MemoryV1PendingSource::RootUnavailable)
    );
    assert_eq!(failed.deny_source, None);
    assert!(failed.admissions.is_empty());
}

// memory—v1: A create target is re-resolved under the same exact-root and
// live-session guards; this observation is not an admission or a commit.
#[test]
fn user_card_create_final_check_requires_exact_live_root_target() {
    run_isolated("user_card_create_final_check_requires_exact_live_root_target");
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    use astral_authorization_root::memory_v1_request::RequestRootExtension;
    use astral_authorization_root::memory_v1_root::{GovernanceTargetFacts, RootMetadata};

    let (owner, authority) = fixture_with_create_target_facts("ALLOW", "all", false, false, true);
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let (session, credential) = session_for(&authority, &root);
    let target = root
        .with_reader(|reader| reader.user_card_create_target(id(70), id(2), id(10)))
        .unwrap()
        .expect("existing card establishes the target user/tenant relationship");
    let check = |root: &RequestRootExtension,
                 session: &RequestSessionExtension,
                 target: GovernanceTargetFacts,
                 expected: Option<RootMetadata>,
                 wrong_actor: bool| {
        session
            .with_authoritative_context(root, |_, reader, final_check| {
                let (tenant_tree_version, registry_version) = reader.dependency_versions().unwrap();
                let record = DependencyRecord {
                    card_id: if wrong_actor { id(21) } else { id(20) },
                    instance_id: reader.metadata().instance_id,
                    bindings: vec![EvaluationDependency {
                        binding_id: id(40),
                        rule_set_id: id(30),
                        version_bytes: vec![1],
                    }],
                    tenant_tree_version,
                    registry_version,
                };
                let windows = [FinalCheckWindow {
                    entry_validity: None,
                    binding_from: None,
                    binding_until: None,
                }];
                let constraints = FinalCheckTimeConstraints {
                    start_time: now() - 1,
                    future_boundaries: &[],
                    winning_windows: &windows,
                };
                final_check.unwrap().try_final_time_exact_user_card_create(
                    &record,
                    &constraints,
                    expected.unwrap_or_else(|| reader.metadata()),
                    target,
                )
            })
            .unwrap()
    };
    assert!(check(&root, &session, target, None, false).is_some());

    // User 5 and tenant 11 both exist: first-card and cross-tenant proposals
    // must still fail because no card establishes the required relationship.
    for invalid in [
        GovernanceTargetFacts {
            owner_user_id: id(5),
            ..target
        },
        GovernanceTargetFacts {
            tenant_id: id(11),
            ..target
        },
        GovernanceTargetFacts {
            user_card_id: id(21),
            ..target
        },
        GovernanceTargetFacts {
            owner_user_id: id(99),
            ..target
        },
        GovernanceTargetFacts {
            tenant_id: id(99),
            ..target
        },
        GovernanceTargetFacts {
            user_card_id: [0; 16],
            ..target
        },
        GovernanceTargetFacts {
            owner_user_id: [0; 16],
            ..target
        },
        GovernanceTargetFacts {
            tenant_id: [0; 16],
            ..target
        },
        GovernanceTargetFacts {
            rule_set_id: id(30),
            ..target
        },
    ] {
        assert_eq!(check(&root, &session, invalid, None, false), None);
    }
    assert_eq!(check(&root, &session, target, None, true), None);
    let metadata = owner.handle().metadata().unwrap();
    let mut stale = metadata;
    stale.version += 1;
    assert_eq!(check(&root, &session, target, Some(stale), false), None);

    owner
        .begin_modification_fence(
            id(30),
            &FenceDeclaration {
                rule_set_version: vec![1],
                root_version: metadata.version,
                digest: metadata.digest,
            },
        )
        .unwrap();
    assert_eq!(check(&root, &session, target, None, false), None);
    owner.abort_modification_fence(id(30)).unwrap();
    assert_eq!(check(&root, &session, target, None, false), None);
    let fresh_scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = fresh_scope.extension();
    let session = authority
        .verifier()
        .verify_and_bind(&credential, now(), &root)
        .unwrap();
    assert!(check(&root, &session, target, None, false).is_some());

    let issued_at = now() - 120;
    let expired = authority
        .identity_session_adapter()
        .issue_unchecked_for_test(principal(), issued_at, 60)
        .unwrap();
    let expired_session = authority
        .verifier()
        .verify_and_bind(expired.credential(), issued_at, &root)
        .unwrap();
    assert_eq!(check(&root, &expired_session, target, None, false), None);

    // Isolated candidate publication simulates a concurrent creation of the
    // exact proposed ID; it is not a governance write or durable proof.
    owner
        .execute_mutation_with_precondition_for_isolated_tests(
            &ManagementMutationV2::UserCardCreate {
                row: UserCardRow {
                    user_card_id: target.user_card_id,
                    user_id: target.owner_user_id,
                    tenant_id: target.tenant_id,
                    status: UserCardStatus::Active,
                },
            },
            &MutationPrecondition {
                evaluated_root_version: metadata.version,
            },
        )
        .unwrap();
    assert_eq!(check(&root, &session, target, Some(metadata), false), None);
    let latest_scope = RequestRootScope::new(owner.handle(), Default::default());
    let latest_root = latest_scope.extension();
    let (latest_session, latest_credential) = session_for(&authority, &latest_root);
    assert_eq!(
        check(&latest_root, &latest_session, target, None, false),
        None
    );
    let latest_target = GovernanceTargetFacts {
        user_card_id: id(71),
        ..target
    };
    assert!(check(&latest_root, &latest_session, latest_target, None, false).is_some());
    authority
        .identity_session_adapter()
        .revoke(&latest_credential)
        .unwrap();
    assert_eq!(
        check(&latest_root, &latest_session, latest_target, None, false),
        None
    );
    authority
        .identity_session_adapter()
        .revoke(&credential)
        .unwrap();
}

// memory—v1: This is an exact-root prerequisite observation, never an enable
// admission or commit. Real session and root guards must all remain effective.
#[test]
fn empty_disabled_card_final_check_requires_exact_live_facts() {
    run_isolated("empty_disabled_card_final_check_requires_exact_live_facts");
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    use astral_authorization_root::memory_v1_request::RequestRootExtension;
    use astral_authorization_root::memory_v1_root::{GovernanceTargetFacts, RootMetadata};

    let (owner, authority) = fixture_with_distinct_target("ALLOW", "all", false, true);
    let target = GovernanceTargetFacts {
        user_card_id: id(21),
        rule_set_id: [0; 16],
        owner_user_id: id(2),
        tenant_id: id(10),
    };
    let check = |root: &RequestRootExtension,
                 session: &RequestSessionExtension,
                 target: GovernanceTargetFacts,
                 expected: Option<RootMetadata>,
                 wrong_actor: bool| {
        session
            .with_authoritative_context(root, |_, reader, final_check| {
                let (tenant_tree_version, registry_version) = reader.dependency_versions().unwrap();
                let record = DependencyRecord {
                    card_id: if wrong_actor { id(21) } else { id(20) },
                    instance_id: reader.metadata().instance_id,
                    bindings: vec![EvaluationDependency {
                        binding_id: id(40),
                        rule_set_id: id(30),
                        version_bytes: vec![1],
                    }],
                    tenant_tree_version,
                    registry_version,
                };
                let windows = [FinalCheckWindow {
                    entry_validity: None,
                    binding_from: None,
                    binding_until: None,
                }];
                let constraints = FinalCheckTimeConstraints {
                    start_time: now() - 1,
                    future_boundaries: &[],
                    winning_windows: &windows,
                };
                final_check
                    .unwrap()
                    .try_final_time_exact_empty_disabled_card(
                        &record,
                        &constraints,
                        expected.unwrap_or_else(|| reader.metadata()),
                        target,
                    )
            })
            .unwrap()
    };

    // The old active-card operation remains distinct from the new disabled one.
    let active_scope = RequestRootScope::new(owner.handle(), Default::default());
    let active_root = active_scope.extension();
    let (active_session, _) = session_for(&authority, &active_root);
    assert_eq!(
        check(&active_root, &active_session, target, None, false),
        None
    );

    // Disable only via the explicit isolated coordinator; card 22 retains two
    // unremoved bindings, including one whose rule set differs from the actor's.
    for card in [21, 22] {
        let metadata = owner.handle().metadata().unwrap();
        authority
            .disable_card_with_sessions_for_isolated_tests(
                &owner.mutation_executor(),
                MemoryId::from_bytes(id(card)),
                metadata,
            )
            .unwrap();
    }
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let (session, credential) = session_for(&authority, &root);
    assert!(check(&root, &session, target, None, false).is_some());
    session
        .with_authoritative_context(&root, |_, reader, final_check| {
            let (tenant_tree_version, registry_version) = reader.dependency_versions().unwrap();
            let record = DependencyRecord {
                card_id: id(20),
                instance_id: reader.metadata().instance_id,
                bindings: vec![EvaluationDependency {
                    binding_id: id(40),
                    rule_set_id: id(30),
                    version_bytes: vec![1],
                }],
                tenant_tree_version,
                registry_version,
            };
            let windows = [FinalCheckWindow {
                entry_validity: None,
                binding_from: None,
                binding_until: None,
            }];
            let constraints = FinalCheckTimeConstraints {
                start_time: now() - 1,
                future_boundaries: &[],
                winning_windows: &windows,
            };
            assert_eq!(
                final_check.unwrap().try_final_time_exact_empty_card(
                    &record,
                    &constraints,
                    reader.metadata(),
                    target,
                ),
                None,
                "disable's active-card check must still reject a disabled card"
            );
        })
        .unwrap();
    for invalid in [
        GovernanceTargetFacts {
            user_card_id: id(99),
            ..target
        },
        GovernanceTargetFacts {
            user_card_id: [0; 16],
            ..target
        },
        GovernanceTargetFacts {
            owner_user_id: id(1),
            ..target
        },
        GovernanceTargetFacts {
            owner_user_id: [0; 16],
            ..target
        },
        GovernanceTargetFacts {
            tenant_id: id(11),
            ..target
        },
        GovernanceTargetFacts {
            tenant_id: [0; 16],
            ..target
        },
        GovernanceTargetFacts {
            rule_set_id: id(30),
            ..target
        },
        GovernanceTargetFacts {
            user_card_id: id(22),
            owner_user_id: id(1),
            ..target
        },
        GovernanceTargetFacts {
            user_card_id: id(20),
            owner_user_id: id(1),
            ..target
        },
    ] {
        assert_eq!(check(&root, &session, invalid, None, false), None);
    }
    assert_eq!(check(&root, &session, target, None, true), None);
    let metadata = owner.handle().metadata().unwrap();
    let mut wrong_metadata = metadata;
    wrong_metadata.version += 1;
    assert_eq!(
        check(&root, &session, target, Some(wrong_metadata), false),
        None
    );

    // No target rule sets exist, but the actor's dependencies still fence it.
    owner
        .begin_modification_fence(
            id(30),
            &FenceDeclaration {
                rule_set_version: vec![1],
                root_version: metadata.version,
                digest: metadata.digest,
            },
        )
        .unwrap();
    assert_eq!(check(&root, &session, target, None, false), None);
    owner.abort_modification_fence(id(30)).unwrap();
    assert_eq!(check(&root, &session, target, None, false), None);
    let fresh_scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = fresh_scope.extension();
    let session = authority
        .verifier()
        .verify_and_bind(&credential, now(), &root)
        .unwrap();
    assert!(check(&root, &session, target, None, false).is_some());

    // A session verified at its issuance time must still be live at final time.
    let issued_at = now() - 120;
    let expired = authority
        .identity_session_adapter()
        .issue_unchecked_for_test(principal(), issued_at, 60)
        .unwrap();
    let expired_session = authority
        .verifier()
        .verify_and_bind(expired.credential(), issued_at, &root)
        .unwrap();
    assert_eq!(check(&root, &expired_session, target, None, false), None);

    // A publication invalidates an old exact-root observation even when the
    // target itself is unchanged. Removed history is not an unremoved binding.
    for binding_id in [41, 42] {
        let before = owner.handle().metadata().unwrap();
        owner
            .execute_mutation_with_precondition_for_isolated_tests(
                &ManagementMutationV2::BindingRemove {
                    binding_id: id(binding_id),
                    removed_at: now(),
                    removed_by: id(1),
                },
                &MutationPrecondition {
                    evaluated_root_version: before.version,
                },
            )
            .unwrap();
    }
    assert_eq!(check(&root, &session, target, Some(metadata), false), None);
    let history_scope = RequestRootScope::new(owner.handle(), Default::default());
    let history_root = history_scope.extension();
    let (history_session, _) = session_for(&authority, &history_root);
    let history_target = GovernanceTargetFacts {
        user_card_id: id(22),
        owner_user_id: id(1),
        ..target
    };
    assert_eq!(
        history_root
            .with_reader(
                |reader| reader.read_card_for_authorization(id(22), |ctx, history| {
                    (ctx.bindings.len(), history)
                })
            )
            .unwrap()
            .unwrap(),
        (0, true)
    );
    assert!(check(&history_root, &history_session, history_target, None, false).is_some());
    authority
        .identity_session_adapter()
        .revoke(&credential)
        .unwrap();
    assert_eq!(check(&root, &session, target, None, false), None);
    let (revoked_session, revoked_credential) = session_for(&authority, &history_root);
    authority
        .identity_session_adapter()
        .revoke(&revoked_credential)
        .unwrap();
    assert_eq!(
        check(&history_root, &revoked_session, history_target, None, false),
        None
    );
}

// memory—v1: Empty-target disable plans only after the root proves the card and
// the final check independently proves the same empty unremoved-binding set.
#[test]
fn compound_disables_unbound_and_history_only_cards() {
    run_isolated("compound_disables_unbound_and_history_only_cards");
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    let (owner, authority) = fixture("ALLOW");
    let tenant = id(10);
    let beneficiary = id(2);
    let card = id(21);
    let engine = PolicyEngine::new();
    let evaluate = |scope: &RequestRootScope,
                    expected: Option<
        astral_authorization_root::memory_v1_root::GovernanceTargetFacts,
    >| {
        let root = scope.extension();
        let (session, _) = session_for(&authority, &root);
        let facts = expected.unwrap_or_else(|| {
            root.with_reader(|reader| reader.user_card_target(card))
                .unwrap()
                .unwrap()
        });
        let disable = MemoryV1CompoundAction {
            request: MemoryV1Request {
                resource: "user_card",
                action: "disable",
                target: Some(&card),
                target_tenant: Some(&tenant),
                target_owner: Some(&beneficiary),
                operation_id: b"empty-card-disable",
                operation_fingerprint: b"empty-card-disable-fingerprint",
            },
            change_intent: None,
            target_facts: facts,
            target_kind: MemoryV1CompoundTargetKind::UserCardDisable,
        };
        engine.evaluate_memory_v1_compound(
            &root,
            &session,
            &MemoryV1CompoundRequest {
                actions: &[disable],
            },
        )
    };
    let initial = RequestRootScope::new(owner.handle(), Default::default());
    let unbound = evaluate(&initial, None);
    assert_eq!(unbound.decision, MemoryV1Decision::Allow);
    assert_eq!(unbound.admissions.len(), 1);

    // memory—v1: The public empty-card observation derives its own proof; a
    // caller-supplied target or the batch API's empty list cannot forge it.
    let direct_root = initial.extension();
    let (direct_session, _) = session_for(&authority, &direct_root);
    direct_session
        .with_authoritative_context(&direct_root, |_, reader, final_check| {
            let final_check = final_check.unwrap();
            let (tenant_tree_version, registry_version) = reader.dependency_versions().unwrap();
            let record = DependencyRecord {
                card_id: id(20),
                instance_id: reader.metadata().instance_id,
                bindings: vec![EvaluationDependency {
                    binding_id: id(40),
                    rule_set_id: id(30),
                    version_bytes: vec![1],
                }],
                tenant_tree_version,
                registry_version,
            };
            let windows = [FinalCheckWindow {
                entry_validity: None,
                binding_from: None,
                binding_until: None,
            }];
            let constraints = FinalCheckTimeConstraints {
                start_time: now() - 1,
                future_boundaries: &[],
                winning_windows: &windows,
            };
            let metadata = reader.metadata();
            let facts = reader.user_card_target(card).unwrap();
            assert!(final_check
                .try_final_time_exact_empty_card(&record, &constraints, metadata, facts)
                .is_some());
            assert_eq!(
                final_check.try_final_time_exact_batch(&record, &constraints, metadata, &[]),
                None
            );
            let bound_card = reader.user_card_target(id(20)).unwrap();
            assert_eq!(
                final_check.try_final_time_exact_empty_card(
                    &record,
                    &constraints,
                    metadata,
                    bound_card,
                ),
                None
            );
            let mut wrong_owner = facts;
            wrong_owner.owner_user_id = id(1);
            assert_eq!(
                final_check.try_final_time_exact_empty_card(
                    &record,
                    &constraints,
                    metadata,
                    wrong_owner,
                ),
                None
            );
            let mut wrong_card = facts;
            wrong_card.user_card_id = id(99);
            assert_eq!(
                final_check.try_final_time_exact_empty_card(
                    &record,
                    &constraints,
                    metadata,
                    wrong_card,
                ),
                None
            );
            let mut stale = metadata;
            stale.version += 1;
            assert_eq!(
                final_check.try_final_time_exact_empty_card(&record, &constraints, stale, facts),
                None
            );
        })
        .unwrap();
    let mut forged = initial
        .extension()
        .with_reader(|reader| reader.user_card_target(card))
        .unwrap()
        .unwrap();
    forged.owner_user_id = id(1);
    assert_eq!(
        evaluate(&initial, Some(forged)).decision,
        MemoryV1Decision::Pending
    );

    let before = owner.handle().metadata().unwrap();
    owner
        .execute_mutation_with_precondition_for_isolated_tests(
            &ManagementMutationV2::BindingCreate {
                row: BindingRow {
                    binding_id: id(41),
                    user_card_id: card,
                    rule_set_id: id(30),
                    binding_layer: BindingLayer::Base,
                    valid_from: None,
                    valid_until: None,
                    owner_scope:
                        astral_authorization_root::memory_v1_rules::MemoryV1OwnerScope::AllUsers,
                    tenant_scope:
                        astral_authorization_root::memory_v1_rules::MemoryV1TenantScope::SelfTenant,
                    removed_at: None,
                    removed_by: None,
                },
                confirmation: BindingConfirmationRow {
                    confirmation_id: id(51),
                    binding_id: id(41),
                    rule_set_id: id(30),
                    version_bytes: vec![1],
                    confirmer_user_id: id(1),
                    scope_bytes: vec![1],
                    operation_id: vec![51],
                    confirmed_at_bytes: vec![1],
                    revoked_at: None,
                    revoked_by: None,
                },
            },
            &MutationPrecondition {
                evaluated_root_version: before.version,
            },
        )
        .unwrap();
    let bound_scope = RequestRootScope::new(owner.handle(), Default::default());
    assert_eq!(
        evaluate(&bound_scope, None).decision,
        MemoryV1Decision::Allow
    );
    let metadata = owner.handle().metadata().unwrap();
    owner
        .begin_modification_fence(
            id(30),
            &FenceDeclaration {
                rule_set_version: vec![1],
                root_version: metadata.version,
                digest: metadata.digest,
            },
        )
        .unwrap();
    let fenced = evaluate(&bound_scope, None);
    assert_eq!(fenced.decision, MemoryV1Decision::Pending);
    assert_eq!(
        fenced.pending_source,
        Some(MemoryV1PendingSource::FenceActive)
    );
    owner.abort_modification_fence(id(30)).unwrap();

    let before = owner.handle().metadata().unwrap();
    owner
        .execute_mutation_with_precondition_for_isolated_tests(
            &ManagementMutationV2::BindingRemove {
                binding_id: id(41),
                removed_at: now(),
                removed_by: id(1),
            },
            &MutationPrecondition {
                evaluated_root_version: before.version,
            },
        )
        .unwrap();
    let history_scope = RequestRootScope::new(owner.handle(), Default::default());
    let history_root = history_scope.extension();
    assert_eq!(
        history_root
            .with_reader(|reader| reader
                .read_card_for_authorization(card, |ctx, history| (ctx.bindings.len(), history)))
            .unwrap()
            .unwrap(),
        (0, true)
    );
    let history = evaluate(&history_scope, None);
    assert_eq!(history.decision, MemoryV1Decision::Allow);
    assert_eq!(history.admissions.len(), 1);

    let mut wrong_kind = MemoryV1CompoundAction {
        request: MemoryV1Request {
            resource: "binding",
            action: "create",
            target: Some(&card),
            target_tenant: Some(&tenant),
            target_owner: Some(&beneficiary),
            operation_id: b"wrong-action",
            operation_fingerprint: b"wrong-action-fingerprint",
        },
        change_intent: None,
        target_facts: history_root
            .with_reader(|reader| reader.user_card_target(card))
            .unwrap()
            .unwrap(),
        target_kind: MemoryV1CompoundTargetKind::UserCardDisable,
    };
    let (session, _) = session_for(&authority, &history_root);
    let result = engine.evaluate_memory_v1_compound(
        &history_root,
        &session,
        &MemoryV1CompoundRequest {
            actions: &[wrong_kind],
        },
    );
    assert_eq!(result.decision, MemoryV1Decision::Pending);
    assert!(result.admissions.is_empty());
    wrong_kind.target_kind = MemoryV1CompoundTargetKind::BindingCreate;
    let result = engine.evaluate_memory_v1_compound(
        &history_root,
        &session,
        &MemoryV1CompoundRequest {
            actions: &[wrong_kind],
        },
    );
    assert_eq!(result.decision, MemoryV1Decision::Pending);
    assert!(result.admissions.is_empty());

    let missing = id(99);
    wrong_kind.request.resource = "user_card";
    wrong_kind.request.action = "disable";
    wrong_kind.request.target = Some(&missing);
    wrong_kind.target_kind = MemoryV1CompoundTargetKind::UserCardDisable;
    let result = engine.evaluate_memory_v1_compound(
        &history_root,
        &session,
        &MemoryV1CompoundRequest {
            actions: &[wrong_kind],
        },
    );
    assert_eq!(result.decision, MemoryV1Decision::Pending);
    assert!(result.admissions.is_empty());
}

#[test]
fn compound_rule_set_create_uses_ownerless_root_target() {
    run_isolated("compound_rule_set_create_uses_ownerless_root_target");
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    let (owner, authority) = fixture_with_rule_set_scope("ALLOW", "all");
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let (session, _) = session_for(&authority, &root);
    let target = id(70);
    let tenant = id(10);
    let facts = root
        .with_reader(|reader| reader.rule_set_create_target(target, tenant))
        .unwrap()
        .expect("new rule-set target facts");
    assert_eq!(facts.owner_user_id, [0; 16]);
    let actions = [
        rule_set_create_action("create", &target, &tenant, facts, None),
        rule_set_create_action(
            "confirm-change",
            &target,
            &tenant,
            facts,
            Some(MemoryV1RuleSetChangeIntent::Create),
        ),
    ];
    let result = PolicyEngine::new().evaluate_memory_v1_compound(
        &root,
        &session,
        &MemoryV1CompoundRequest { actions: &actions },
    );
    assert_eq!(result.decision, MemoryV1Decision::Allow);
    assert_eq!(result.admissions.len(), 2);
    assert!(result
        .admissions
        .iter()
        .all(|admission| admission.target_owner().is_none()));
}

#[test]
fn compound_rule_set_create_self_owner_scope_is_denied() {
    run_isolated("compound_rule_set_create_self_owner_scope_is_denied");
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    let (owner, authority) = fixture_with_rule_set_scope("ALLOW", "self");
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let (session, _) = session_for(&authority, &root);
    let target = id(70);
    let tenant = id(10);
    let facts = root
        .with_reader(|reader| reader.rule_set_create_target(target, tenant))
        .unwrap()
        .expect("new rule-set target facts");
    let actions = [
        rule_set_create_action("create", &target, &tenant, facts, None),
        rule_set_create_action(
            "confirm-change",
            &target,
            &tenant,
            facts,
            Some(MemoryV1RuleSetChangeIntent::Create),
        ),
    ];
    let result = PolicyEngine::new().evaluate_memory_v1_compound(
        &root,
        &session,
        &MemoryV1CompoundRequest { actions: &actions },
    );
    assert_eq!(result.decision, MemoryV1Decision::Deny);
    assert!(result.admissions.is_empty());
}

#[test]
fn experimental_unproven_confirmations_cannot_issue_admissions() {
    run_isolated("experimental_unproven_confirmations_cannot_issue_admissions");
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    let (owner, authority) = fixture_with_adoption("ALLOW", "all", true);
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let (session, _) = session_for(&authority, &root);
    let record = owner.handle().adoption_record().unwrap().unwrap();
    assert!(record
        .unverified
        .contains(&AdoptionLimit::ConfirmationAuthority));
    assert!(!root
        .with_reader(|reader| reader.confirmation_authority_available_for_evaluation())
        .unwrap());

    let facts = root
        .with_reader(|reader| reader.binding_create_target(id(21), id(30)))
        .unwrap()
        .expect("binding-create target facts");
    let target = id(70);
    let tenant = id(10);
    let beneficiary = id(2);
    let actions = [
        action("create", &target, &tenant, &beneficiary, facts),
        action("confirm", &target, &tenant, &beneficiary, facts),
    ];
    let engine = PolicyEngine::new();
    let single = engine.evaluate_memory_v1(&root, &session, &actions[0].request);
    assert_eq!(single.decision, MemoryV1Decision::Pending);
    assert_eq!(
        single.pending_source,
        Some(MemoryV1PendingSource::ContextInvalid)
    );
    assert!(single.admission.is_none());
    assert!(single.deny_observation.is_none());

    let rule_set_target = id(71);
    let rule_set_request = MemoryV1Request {
        resource: "rule_set",
        action: "confirm-change",
        target: Some(&rule_set_target),
        target_tenant: Some(&tenant),
        target_owner: None,
        operation_id: b"new-rule-set",
        operation_fingerprint: b"new-rule-set-fingerprint",
    };
    let change = engine.evaluate_memory_v1_rule_set_change(
        &root,
        &session,
        &rule_set_request,
        MemoryV1RuleSetChangeIntent::Create,
    );
    assert_eq!(change.decision, MemoryV1Decision::Pending);
    assert_eq!(
        change.pending_source,
        Some(MemoryV1PendingSource::ContextInvalid)
    );
    assert!(change.admission.is_none());

    let compound = engine.evaluate_memory_v1_compound(
        &root,
        &session,
        &MemoryV1CompoundRequest { actions: &actions },
    );
    assert_eq!(compound.decision, MemoryV1Decision::Pending);
    assert_eq!(
        compound.pending_source,
        Some(MemoryV1PendingSource::ContextInvalid)
    );
    assert!(compound.admissions.is_empty());
    assert!(compound.deny_observation.is_none());

    let existing_target = id(40);
    let actor = id(1);
    let self_confirmation = MemoryV1Request {
        resource: "binding",
        action: "confirm",
        target: Some(&existing_target),
        target_tenant: Some(&tenant),
        target_owner: Some(&actor),
        operation_id: b"self-confirmation",
        operation_fingerprint: b"self-confirmation-fingerprint",
    };
    let denied = engine.evaluate_memory_v1(&root, &session, &self_confirmation);
    assert_eq!(denied.decision, MemoryV1Decision::Deny);
    assert_eq!(
        denied.deny_source,
        Some(MemoryV1DenySource::SelfConfirmation)
    );
    assert!(denied.admission.is_none());

    let items = [MemoryV1BatchItem {
        sequence: 0,
        binding_id: existing_target,
        confirmation_id: id(51),
    }];
    let batch = engine.evaluate_memory_v1_confirmation_batch(
        &root,
        &session,
        &MemoryV1BatchRequest {
            operation_id: b"self-confirmation-batch",
            operation_fingerprint:
                b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            items: &items,
        },
    );
    assert_eq!(batch.decision, MemoryV1Decision::Deny);
    assert_eq!(
        batch.deny_source,
        Some(MemoryV1DenySource::SelfConfirmation)
    );
    assert!(batch.admission.is_none());
}

#[test]
fn unproven_confirmation_cannot_establish_rule_deny_or_no_match() {
    run_isolated("unproven_confirmation_cannot_establish_rule_deny_or_no_match");
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    let (owner, authority) = fixture_with_adoption("DENY", "all", true);
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let (session, _) = session_for(&authority, &root);
    let facts = root
        .with_reader(|reader| reader.binding_create_target(id(21), id(30)))
        .unwrap()
        .expect("binding-create target facts");
    let target = id(70);
    let tenant = id(10);
    let beneficiary = id(2);
    let engine = PolicyEngine::new();
    let explicit_deny = action("confirm", &target, &tenant, &beneficiary, facts);
    let result = engine.evaluate_memory_v1(&root, &session, &explicit_deny.request);
    assert_eq!(result.decision, MemoryV1Decision::Pending);
    assert_eq!(
        result.pending_source,
        Some(MemoryV1PendingSource::ContextInvalid)
    );
    assert_eq!(result.deny_source, None);
    assert!(result.admission.is_none());

    let no_match = MemoryV1Request {
        action: "remove",
        ..explicit_deny.request
    };
    let result = engine.evaluate_memory_v1(&root, &session, &no_match);
    assert_eq!(result.decision, MemoryV1Decision::Pending);
    assert_eq!(
        result.pending_source,
        Some(MemoryV1PendingSource::ContextInvalid)
    );
    assert_eq!(result.deny_source, None);
    assert!(result.admission.is_none());

    // An unregistered resource/action remains a structural denial.
    let unregistered = MemoryV1Request {
        action: "confirm",
        resource: "rule_set",
        ..explicit_deny.request
    };
    let result = engine.evaluate_memory_v1(&root, &session, &unregistered);
    assert_eq!(result.decision, MemoryV1Decision::Deny);
    assert_eq!(
        result.deny_source,
        Some(MemoryV1DenySource::UnregisteredResource)
    );
    assert!(result.admission.is_none());
}

#[test]
fn compound_allows_multiple_actions_with_one_final_time() {
    run_isolated("compound_allows_multiple_actions_with_one_final_time");
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    let (owner, authority) = fixture("ALLOW");
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let (session, _) = session_for(&authority, &root);
    let facts = root
        .with_reader(|reader| reader.binding_create_target(id(21), id(30)))
        .unwrap()
        .expect("binding-create target facts");
    let target = id(70);
    let tenant = id(10);
    let beneficiary = id(2);
    let actions = [
        action("create", &target, &tenant, &beneficiary, facts),
        action("confirm", &target, &tenant, &beneficiary, facts),
    ];
    let result = PolicyEngine::new().evaluate_memory_v1_compound(
        &root,
        &session,
        &MemoryV1CompoundRequest { actions: &actions },
    );
    assert_eq!(result.decision, MemoryV1Decision::Allow);
    assert_eq!(result.admissions.len(), 2);
    assert_eq!(
        result.admissions[0].trusted_time_unix_seconds(),
        result.admissions[1].trusted_time_unix_seconds()
    );
    assert_eq!(result.admissions[0].operation_id(), b"compound-operation");
    assert_eq!(
        result.admissions[1].operation_fingerprint(),
        b"compound-fingerprint"
    );
}

#[test]
fn compound_denies_when_one_action_is_denied() {
    run_isolated("compound_denies_when_one_action_is_denied");
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    let (owner, authority) = fixture("DENY");
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let (session, _) = session_for(&authority, &root);
    let facts = root
        .with_reader(|reader| reader.binding_create_target(id(21), id(30)))
        .unwrap()
        .expect("binding-create target facts");
    let target = id(70);
    let tenant = id(10);
    let beneficiary = id(2);
    let actions = [
        action("create", &target, &tenant, &beneficiary, facts),
        action("confirm", &target, &tenant, &beneficiary, facts),
    ];
    let result = PolicyEngine::new().evaluate_memory_v1_compound(
        &root,
        &session,
        &MemoryV1CompoundRequest { actions: &actions },
    );
    assert_eq!(result.decision, MemoryV1Decision::Deny);
    assert_eq!(result.deny_source, Some(MemoryV1DenySource::RuleDenied));
    assert!(result.pending_source.is_none());
    assert!(result.admissions.is_empty());
    let observation = result.deny_observation.as_deref().expect("selected denial");
    assert_eq!(
        observation.root(),
        root.with_reader(|reader| reader.metadata()).unwrap()
    );
    assert_eq!(observation.identity().user_id.into_bytes(), id(1));
    assert_eq!(observation.resource(), "binding");
    assert_eq!(observation.action(), "confirm");
    assert_eq!(observation.target(), Some(target.as_slice()));
    assert_eq!(observation.target_tenant(), Some(tenant.as_slice()));
    assert_eq!(observation.target_owner(), Some(beneficiary.as_slice()));
    assert_eq!(observation.operation_id(), b"compound-operation");
    assert_eq!(observation.operation_fingerprint(), b"compound-fingerprint");
    assert_eq!(observation.source(), MemoryV1DenySource::RuleDenied);
    assert!(observation.read_started_at_unix_seconds() > 0);
    let first = PolicyEngine::new().evaluate_memory_v1_compound(
        &root,
        &session,
        &MemoryV1CompoundRequest {
            actions: &[actions[1], actions[0]],
        },
    );
    assert_eq!(
        first.deny_observation.as_deref().unwrap().action(),
        "confirm"
    );
}

#[test]
fn compound_rejects_target_kind_and_target_mismatch() {
    run_isolated("compound_rejects_target_kind_and_target_mismatch");
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    let (owner, authority) = fixture("ALLOW");
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let (session, _) = session_for(&authority, &root);
    let facts = root
        .with_reader(|reader| reader.binding_create_target(id(21), id(30)))
        .unwrap()
        .expect("binding-create target facts");
    let target = id(70);
    let other_target = id(71);
    let tenant = id(10);
    let beneficiary = id(2);
    let mut spoofed = action("create", &target, &tenant, &beneficiary, facts);
    spoofed.target_kind = MemoryV1CompoundTargetKind::RuleSetCreate;
    let result = PolicyEngine::new().evaluate_memory_v1_compound(
        &root,
        &session,
        &MemoryV1CompoundRequest {
            actions: &[spoofed],
        },
    );
    assert_eq!(result.decision, MemoryV1Decision::Pending);
    assert_eq!(
        result.pending_source,
        Some(MemoryV1PendingSource::ContextInvalid)
    );

    let actions = [
        action("create", &target, &tenant, &beneficiary, facts),
        action("confirm", &other_target, &tenant, &beneficiary, facts),
    ];
    let result = PolicyEngine::new().evaluate_memory_v1_compound(
        &root,
        &session,
        &MemoryV1CompoundRequest { actions: &actions },
    );
    assert_eq!(result.decision, MemoryV1Decision::Pending);
    assert_eq!(
        result.pending_source,
        Some(MemoryV1PendingSource::ContextInvalid)
    );
}

#[test]
fn compound_stays_pending_after_session_revoke_or_target_fence() {
    run_isolated("compound_stays_pending_after_session_revoke_or_target_fence");
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    let (owner, authority) = fixture("ALLOW");
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let (session, credential) = session_for(&authority, &root);
    let facts = root
        .with_reader(|reader| reader.binding_create_target(id(21), id(30)))
        .unwrap()
        .expect("binding-create target facts");
    let target = id(70);
    let tenant = id(10);
    let beneficiary = id(2);
    let actions = [
        action("create", &target, &tenant, &beneficiary, facts),
        action("confirm", &target, &tenant, &beneficiary, facts),
    ];
    let metadata = owner.handle().metadata().expect("root metadata");
    owner
        .begin_modification_fence(
            id(30),
            &FenceDeclaration {
                rule_set_version: vec![1],
                root_version: metadata.version,
                digest: metadata.digest,
            },
        )
        .expect("target fence opens");
    let fenced = PolicyEngine::new().evaluate_memory_v1_compound(
        &root,
        &session,
        &MemoryV1CompoundRequest { actions: &actions },
    );
    assert_eq!(fenced.decision, MemoryV1Decision::Pending);
    assert_eq!(
        fenced.pending_source,
        Some(MemoryV1PendingSource::FenceActive)
    );
    owner
        .abort_modification_fence(id(30))
        .expect("target fence closes");

    authority
        .identity_session_adapter()
        .revoke(&credential)
        .expect("session revokes");
    let revoked = PolicyEngine::new().evaluate_memory_v1_compound(
        &root,
        &session,
        &MemoryV1CompoundRequest { actions: &actions },
    );
    assert_eq!(revoked.decision, MemoryV1Decision::Pending);
    assert!(revoked.admissions.is_empty());
}
