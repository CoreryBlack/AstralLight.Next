//! Batch B memory—v1 contract tests.
//!
//! These tests exercise the public process-root mutation and typed evaluator
//! surfaces. Every test that installs `PROCESS_ROOT` runs its body in a child
//! test process because the production installation slot is once-per-process.

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use astral_authorization_root::memory_v1_db_rows::{
    BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, CurrentSelection,
    IdentityCardRow, RuleSetChangeConfirmationRow, RuleSetRow, RuleSetVersionRow, Table, TenantRow,
    UserCardRow, UserCardStatus, UserRow, ValidationError,
};
use astral_authorization_root::memory_v1_hamt::{CandidateBudget, CandidateError};
use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
use astral_authorization_root::memory_v1_request::{RequestRootExtension, RequestRootScope};
use astral_authorization_root::memory_v1_root::{
    install_process_root, ManagementMutationV2, MutationError, MutationPrecondition, RootOwner,
};
use astral_authorization_root::memory_v1_rules::{
    canonical_version_bytes, version_digest, MemoryV1OwnerScope, MemoryV1TenantScope,
};
use astral_authorization_root::memory_v1_session::RequestSessionExtension;
use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority;
use astral_types::memory_v1::{CandidateIdentity, MemoryId};
use policy_engine::memory_v1_batch::{
    MemoryV1BatchEvaluation, MemoryV1BatchItem, MemoryV1BatchRequest,
    MAX_MEMORY_V1_BINDING_CONFIRMATION_BATCH,
};
use policy_engine::memory_v1_compound::{
    MemoryV1CompoundAction, MemoryV1CompoundRequest, MemoryV1CompoundTargetKind,
};
use policy_engine::memory_v1_formal::{
    MemoryV1Decision, MemoryV1DenySource, MemoryV1Evaluation, MemoryV1PendingSource,
    MemoryV1Request, MemoryV1RuleSetChangeIntent,
};
use policy_engine::PolicyEngine;

const CHILD_ENV: &str = "ASTRAL_MEMORY_V1_BATCH_B_CHILD";
const CHANGE_SCENARIO_ENV: &str = "ASTRAL_MEMORY_V1_BATCH_B_CHANGE_SCENARIO";

fn run_isolated(test_name: &str) {
    if std::env::var_os(CHILD_ENV).is_some() {
        return;
    }
    let output = Command::new(std::env::current_exe().expect("test executable is available"))
        .args(["--exact", test_name, "--nocapture"])
        .env(CHILD_ENV, "1")
        .output()
        .expect("failed to start isolated memory-v1 contract test");
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

fn id(value: u8) -> [u8; 16] {
    [value; 16]
}

fn identity(card: u8, tenant: u8) -> CandidateIdentity {
    CandidateIdentity {
        user_id: MemoryId::from_bytes(id(1)),
        identity_card_id: MemoryId::from_bytes(id(2)),
        user_card_id: MemoryId::from_bytes(id(card)),
        tenant_id: MemoryId::from_bytes(id(tenant)),
    }
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

fn version(rule_set: u8, content: &[u8]) -> RuleSetVersionRow {
    let version_bytes = vec![1];
    let timestamp_bytes = vec![2];
    let hash_input_bytes = canonical_version_bytes(&version_bytes, content, &timestamp_bytes);
    RuleSetVersionRow {
        rule_set_id: id(rule_set),
        version_bytes,
        content_bytes: content.to_vec(),
        timestamp_bytes,
        hash_bytes: version_digest(&hash_input_bytes),
        hash_input_bytes,
    }
}

fn binding(
    binding_id: u8,
    card: u8,
    rule_set: u8,
    layer: BindingLayer,
    owner_scope: MemoryV1OwnerScope,
    tenant_scope: MemoryV1TenantScope,
) -> BindingRow {
    BindingRow {
        binding_id: id(binding_id),
        user_card_id: id(card),
        rule_set_id: id(rule_set),
        binding_layer: layer,
        valid_from: None,
        valid_until: None,
        owner_scope,
        tenant_scope,
        removed_at: None,
        removed_by: None,
    }
}

fn binding_confirmation(
    confirmation_id: u8,
    binding_id: u8,
    rule_set: u8,
    revoked_at: Option<i64>,
) -> BindingConfirmationRow {
    BindingConfirmationRow {
        confirmation_id: id(confirmation_id),
        binding_id: id(binding_id),
        rule_set_id: id(rule_set),
        version_bytes: vec![1],
        confirmer_user_id: id(1),
        scope_bytes: vec![1],
        operation_id: vec![confirmation_id],
        confirmed_at_bytes: vec![1],
        revoked_at,
        revoked_by: revoked_at.map(|_| id(1)),
    }
}

fn change_confirmation(
    confirmation_id: u8,
    rule_set: u8,
    version_bytes: Vec<u8>,
    revoked_at: Option<i64>,
) -> RuleSetChangeConfirmationRow {
    RuleSetChangeConfirmationRow {
        confirmation_id: id(confirmation_id),
        rule_set_id: id(rule_set),
        version_bytes,
        confirmer_user_id: id(1),
        affected_scope_bytes: vec![1],
        operation_id: vec![confirmation_id],
        confirmed_at_bytes: vec![1],
        revoked_at,
        revoked_by: revoked_at.map(|_| id(1)),
    }
}

fn budget() -> CandidateBudget {
    CandidateBudget {
        max_table_rows: 256,
        max_bindings_per_read: 16,
    }
}

fn serving_owner(rows: CandidateRows, selections: Vec<CurrentSelection>) -> RootOwner {
    let owner = install_process_root(rows, selections, budget()).expect("candidate root installs");
    owner
        .install_registry(&[RegistryDeclaration {
            resource: "document".to_owned(),
            actions: vec!["read".to_owned()],
        }])
        .expect("registry installs once");
    owner
        .adopt_serving_for_isolated_tests()
        .expect("fixture is structurally serving-ready");
    owner
}

fn session_for(
    authority: &MemoryV1SessionAuthority,
    root: &RequestRootExtension,
    principal: CandidateIdentity,
) -> RequestSessionExtension {
    let issued = authority
        .identity_session_adapter()
        .issue_unchecked_for_test(principal, now() - 60, 3_600)
        .expect("test session issues");
    authority
        .verifier()
        .verify_and_bind(issued.credential(), now(), root)
        .expect("test session binds to request root")
}

fn request<'a>(
    target_tenant: Option<&'a [u8]>,
    target_owner: Option<&'a [u8]>,
) -> MemoryV1Request<'a> {
    MemoryV1Request {
        resource: "document",
        action: "read",
        target: Some(b"object"),
        target_tenant,
        target_owner,
        operation_id: b"batch-b-op",
        operation_fingerprint: b"batch-b-fingerprint",
    }
}

fn evaluate(
    owner: &RootOwner,
    authority: &MemoryV1SessionAuthority,
    principal: CandidateIdentity,
    target_tenant: Option<&[u8]>,
    target_owner: Option<&[u8]>,
) -> MemoryV1Evaluation {
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let session = session_for(authority, &root, principal);
    PolicyEngine::new().evaluate_memory_v1(&root, &session, &request(target_tenant, target_owner))
}

fn overlay_fixture() -> (CandidateRows, Vec<CurrentSelection>) {
    let base_content =
        br#"{"rules":[{"ruleId":"base-read","resource":"document","action":"read","effect":"ALLOW"}]}"#;
    let overlay_content =
        br#"{"rules":[{"ruleId":"overlay-deny","resource":"document","action":"read","effect":"DENY"}]}"#;
    let base_version = version(10, base_content);
    let overlay_version = version(11, overlay_content);
    let rows = CandidateRows {
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
        rule_sets: vec![
            RuleSetRow {
                status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
                rule_set_id: id(10),
                owner_tenant_id: id(3),
                current_version_bytes: vec![1],
            },
            RuleSetRow {
                status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
                rule_set_id: id(11),
                owner_tenant_id: id(3),
                current_version_bytes: vec![1],
            },
        ],
        rule_set_versions: vec![base_version, overlay_version],
        bindings: vec![
            binding(
                20,
                4,
                10,
                BindingLayer::Base,
                MemoryV1OwnerScope::SelfUser,
                MemoryV1TenantScope::SelfTenant,
            ),
            binding(
                21,
                4,
                11,
                BindingLayer::Overlay,
                MemoryV1OwnerScope::SelfUser,
                MemoryV1TenantScope::SelfTenant,
            ),
        ],
        binding_confirmations: vec![
            binding_confirmation(120, 20, 10, None),
            binding_confirmation(121, 21, 11, None),
        ],
        rule_set_change_confirmations: vec![
            change_confirmation(220, 10, vec![1], None),
            change_confirmation(221, 11, vec![1], None),
        ],
    };
    (
        rows,
        vec![
            CurrentSelection {
                rule_set_id: id(10),
                version_bytes: vec![1],
            },
            CurrentSelection {
                rule_set_id: id(11),
                version_bytes: vec![1],
            },
        ],
    )
}

#[test]
fn batch_b_base_allow_overlay_deny_then_revoke_restores_base() {
    let test_name = "batch_b_base_allow_overlay_deny_then_revoke_restores_base";
    if std::env::var_os(CHILD_ENV).is_none() {
        run_isolated(test_name);
        return;
    }

    let (rows, selections) = overlay_fixture();
    let owner = serving_owner(rows, selections);
    let authority = MemoryV1SessionAuthority::new();
    authority
        .bind_to_root(&owner)
        .expect("session authority binds to the fixture root");
    let target_tenant = id(3);
    let target_owner = id(1);

    let denied = evaluate(
        &owner,
        &authority,
        identity(4, 3),
        Some(&target_tenant),
        Some(&target_owner),
    );
    assert_eq!(denied.decision, MemoryV1Decision::Deny);
    assert_eq!(denied.deny_source, Some(MemoryV1DenySource::RuleDenied));

    let before = owner
        .handle()
        .metadata()
        .expect("root metadata is readable");
    let revoke = ManagementMutationV2::ConfirmationRevoke {
        confirmation_id: id(121),
        revoked_at: now(),
        revoked_by: id(1),
    };
    let after = owner
        .execute_mutation_with_precondition_for_isolated_tests(
            &revoke,
            &MutationPrecondition {
                evaluated_root_version: before.version,
            },
        )
        .expect("overlay confirmation revoke publishes one new snapshot");
    assert_eq!(after.version, before.version + 1);
    assert_ne!(after.digest, before.digest);

    // A request reader is phase-bound. The new request below deliberately captures
    // the post-revocation snapshot rather than reusing the old denied phase.
    let restored = evaluate(
        &owner,
        &authority,
        identity(4, 3),
        Some(&target_tenant),
        Some(&target_owner),
    );
    assert_eq!(restored.decision, MemoryV1Decision::Allow);
    assert_eq!(restored.deny_source, None);
    assert_eq!(restored.pending_source, None);
    assert_eq!(
        restored
            .admission
            .expect("BASE permission is admitted")
            .root()
            .version,
        after.version
    );

    // REVOKE preserves the binding. A new confirmation restores that same
    // relationship, so the overlay's explicit DENY takes effect again.
    let reconfirmed = owner
        .execute_mutation_with_precondition_for_isolated_tests(
            &ManagementMutationV2::ConfirmationCreate {
                row: binding_confirmation(122, 21, 11, None),
            },
            &MutationPrecondition {
                evaluated_root_version: after.version,
            },
        )
        .expect("a new confirmation restores the retained binding");
    assert_eq!(reconfirmed.version, after.version + 1);
    let confirmations = owner
        .handle()
        .read_card(id(4), |context| {
            context
                .bindings
                .iter()
                .find(|binding| binding.binding.binding_id == id(21))
                .unwrap()
                .confirmations
                .iter()
                .map(|row| (row.confirmation_id, row.revoked_at.is_some()))
                .collect::<Vec<_>>()
        })
        .expect("the retained overlay is readable")
        .value;
    assert_eq!(confirmations.len(), 2);
    assert!(confirmations.contains(&(id(121), true)));
    assert!(confirmations.contains(&(id(122), false)));
    let denied_again = evaluate(
        &owner,
        &authority,
        identity(4, 3),
        Some(&target_tenant),
        Some(&target_owner),
    );
    assert_eq!(denied_again.decision, MemoryV1Decision::Deny);
    assert_eq!(
        denied_again.deny_source,
        Some(MemoryV1DenySource::RuleDenied)
    );
}

#[test]
// memory—v1: Removing a current version's confirmation closes that rule set
// for new and in-flight evaluations without deleting the historical row.
fn batch_b_revoke_change_confirmation_closes_version() {
    let test_name = "batch_b_revoke_change_confirmation_closes_version";
    if std::env::var_os(CHILD_ENV).is_none() {
        run_isolated(test_name);
        return;
    }

    let (mut rows, mut selections) = overlay_fixture();
    rows.rule_sets.retain(|row| row.rule_set_id == id(10));
    rows.rule_set_versions
        .retain(|row| row.rule_set_id == id(10));
    rows.bindings.retain(|row| row.rule_set_id == id(10));
    rows.binding_confirmations
        .retain(|row| row.rule_set_id == id(10));
    rows.rule_set_change_confirmations
        .retain(|row| row.rule_set_id == id(10));
    selections.retain(|selection| selection.rule_set_id == id(10));
    let owner = serving_owner(rows, selections);
    let authority = MemoryV1SessionAuthority::new();
    authority.bind_to_root(&owner).unwrap();
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let session = session_for(&authority, &root, identity(4, 3));
    let tenant = id(3);
    let target_owner = id(1);
    let request = request(Some(&tenant), Some(&target_owner));
    let engine = PolicyEngine::new();
    assert_eq!(
        engine
            .evaluate_memory_v1(&root, &session, &request)
            .decision,
        MemoryV1Decision::Allow
    );
    let before = owner.handle().metadata().unwrap();
    let after = owner
        .execute_mutation_with_precondition_for_isolated_tests(
            &ManagementMutationV2::RuleSetChangeConfirmationRevoke {
                confirmation_id: id(220),
                revoked_at: now(),
                revoked_by: id(1),
            },
            &MutationPrecondition {
                evaluated_root_version: before.version,
            },
        )
        .unwrap();
    assert_eq!(after.version, before.version + 1);
    assert_eq!(
        engine
            .evaluate_memory_v1(&root, &session, &request)
            .decision,
        MemoryV1Decision::Pending
    );
    let fresh = evaluate(
        &owner,
        &authority,
        identity(4, 3),
        Some(&tenant),
        Some(&target_owner),
    );
    assert_eq!(fresh.decision, MemoryV1Decision::Pending);
    assert_eq!(
        fresh.pending_source,
        Some(MemoryV1PendingSource::ContextInvalid)
    );
    assert!(fresh.admission.is_none());
}

#[test]
// memory—v1: Removed history must not consume the budget for active bindings,
// and an older evaluation cannot survive removal of its last active binding.
fn batch_b_binding_history_does_not_exhaust_authorization_budget() {
    let test_name = "batch_b_binding_history_does_not_exhaust_authorization_budget";
    if std::env::var_os(CHILD_ENV).is_none() {
        run_isolated(test_name);
        return;
    }

    let (mut rows, mut selections) = overlay_fixture();
    rows.rule_sets.retain(|row| row.rule_set_id == id(10));
    rows.rule_set_versions
        .retain(|row| row.rule_set_id == id(10));
    rows.bindings.retain(|row| row.rule_set_id == id(10));
    rows.binding_confirmations
        .retain(|row| row.rule_set_id == id(10));
    rows.rule_set_change_confirmations
        .retain(|row| row.rule_set_id == id(10));
    selections.retain(|selection| selection.rule_set_id == id(10));
    for binding_id in 30..50 {
        let mut historical = binding(
            binding_id,
            4,
            10,
            BindingLayer::Base,
            MemoryV1OwnerScope::SelfUser,
            MemoryV1TenantScope::SelfTenant,
        );
        historical.removed_at = Some(100);
        historical.removed_by = Some(id(1));
        rows.bindings.push(historical);
    }

    let owner = serving_owner(rows, selections);
    let authority = MemoryV1SessionAuthority::new();
    authority.bind_to_root(&owner).unwrap();
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let session = session_for(&authority, &root, identity(4, 3));
    let tenant = id(3);
    let target_owner = id(1);
    let request = request(Some(&tenant), Some(&target_owner));
    let engine = PolicyEngine::new();
    let historical = owner.handle().read_card(id(4), |_| ());
    assert!(matches!(
        historical,
        Err(
            astral_authorization_root::memory_v1_root::RootError::Candidate(
                CandidateError::BindingBudgetExceeded {
                    max: 16,
                    actual: 21
                }
            )
        )
    ));
    let initial = engine.evaluate_memory_v1(&root, &session, &request);
    assert_eq!(initial.decision, MemoryV1Decision::Allow);
    assert!(initial.admission.is_some());

    let before = owner.handle().metadata().unwrap();
    owner
        .execute_mutation_with_precondition_for_isolated_tests(
            &ManagementMutationV2::BindingRemove {
                binding_id: id(20),
                removed_at: now(),
                removed_by: id(1),
            },
            &MutationPrecondition {
                evaluated_root_version: before.version,
            },
        )
        .unwrap();
    let stale = engine.evaluate_memory_v1(&root, &session, &request);
    assert_eq!(stale.decision, MemoryV1Decision::Pending);
    assert!(stale.admission.is_none());
    let fresh = evaluate(
        &owner,
        &authority,
        identity(4, 3),
        Some(&tenant),
        Some(&target_owner),
    );
    assert_eq!(fresh.decision, MemoryV1Decision::Deny);
    assert_eq!(fresh.deny_source, Some(MemoryV1DenySource::NoMatch));
    assert!(fresh.admission.is_none());
}

fn scoped_fixture() -> (CandidateRows, Vec<CurrentSelection>) {
    let wide_content =
        br#"{"rules":[{"ruleId":"wide","resource":"document","action":"read","effect":"ALLOW","ownerScope":"all","tenantScope":"self+descendants"}]}"#;
    let strict_content =
        br#"{"rules":[{"ruleId":"strict","resource":"document","action":"read","effect":"ALLOW","ownerScope":"self","tenantScope":"self"}]}"#;
    let rows = CandidateRows {
        users: vec![UserRow { user_id: id(1) }],
        identity_cards: vec![IdentityCardRow {
            identity_card_id: id(2),
            user_id: id(1),
        }],
        tenants: vec![
            TenantRow {
                tenant_id: id(3),
                parent_tenant_id: None,
            },
            TenantRow {
                tenant_id: id(30),
                parent_tenant_id: Some(id(3)),
            },
            TenantRow {
                tenant_id: id(99),
                parent_tenant_id: None,
            },
        ],
        user_cards: vec![
            UserCardRow {
                user_card_id: id(4),
                user_id: id(1),
                tenant_id: id(3),
                status: UserCardStatus::Active,
            },
            UserCardRow {
                user_card_id: id(5),
                user_id: id(1),
                tenant_id: id(3),
                status: UserCardStatus::Active,
            },
        ],
        rule_sets: vec![
            RuleSetRow {
                status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
                rule_set_id: id(10),
                owner_tenant_id: id(3),
                current_version_bytes: vec![1],
            },
            RuleSetRow {
                status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
                rule_set_id: id(11),
                owner_tenant_id: id(3),
                current_version_bytes: vec![1],
            },
        ],
        rule_set_versions: vec![version(10, wide_content), version(11, strict_content)],
        bindings: vec![
            // Wide entry ∩ strict binding = strict effective scope.
            binding(
                20,
                4,
                10,
                BindingLayer::Base,
                MemoryV1OwnerScope::SelfUser,
                MemoryV1TenantScope::SelfTenant,
            ),
            // Strict entry ∩ wide binding = strict effective scope.
            binding(
                21,
                5,
                11,
                BindingLayer::Base,
                MemoryV1OwnerScope::AllUsers,
                MemoryV1TenantScope::SelfAndDescendants,
            ),
        ],
        binding_confirmations: vec![
            binding_confirmation(120, 20, 10, None),
            binding_confirmation(121, 21, 11, None),
        ],
        rule_set_change_confirmations: vec![
            change_confirmation(220, 10, vec![1], None),
            change_confirmation(221, 11, vec![1], None),
        ],
    };
    (
        rows,
        vec![
            CurrentSelection {
                rule_set_id: id(10),
                version_bytes: vec![1],
            },
            CurrentSelection {
                rule_set_id: id(11),
                version_bytes: vec![1],
            },
        ],
    )
}

#[test]
fn batch_b_entry_and_binding_scopes_intersect_and_missing_targets_fail_closed() {
    let test_name = "batch_b_entry_and_binding_scopes_intersect_and_missing_targets_fail_closed";
    if std::env::var_os(CHILD_ENV).is_none() {
        run_isolated(test_name);
        return;
    }

    let (rows, selections) = scoped_fixture();
    let owner = serving_owner(rows, selections);
    let authority = MemoryV1SessionAuthority::new();
    authority
        .bind_to_root(&owner)
        .expect("session authority binds to the fixture root");
    let own_tenant = id(3);
    let child_tenant = id(30);
    let foreign_tenant = id(99);
    let own_owner = id(1);
    let foreign_owner = id(9);

    // Both directions of the intersection permit the exact trusted object.
    for card in [4, 5] {
        let allowed = evaluate(
            &owner,
            &authority,
            identity(card, 3),
            Some(&own_tenant),
            Some(&own_owner),
        );
        assert_eq!(allowed.decision, MemoryV1Decision::Allow);
        let admission = allowed.admission.expect("exact scope is admitted");
        assert_eq!(
            admission.effective_owner_scope(),
            MemoryV1OwnerScope::SelfUser
        );
        assert_eq!(
            admission.effective_tenant_scope(),
            MemoryV1TenantScope::SelfTenant
        );
    }

    // Passing an attribution outside the effective scope cannot widen either layer.
    for (card, target_tenant, target_owner) in [
        (4, child_tenant, own_owner),
        (4, own_tenant, foreign_owner),
        (4, foreign_tenant, own_owner),
        (5, child_tenant, own_owner),
        (5, own_tenant, foreign_owner),
        (5, foreign_tenant, own_owner),
    ] {
        let denied = evaluate(
            &owner,
            &authority,
            identity(card, 3),
            Some(&target_tenant),
            Some(&target_owner),
        );
        assert_eq!(denied.decision, MemoryV1Decision::Deny);
        assert_eq!(denied.deny_source, Some(MemoryV1DenySource::ScopeDenied));
        assert!(denied.admission.is_none());
    }

    // An object-bearing request with a missing trusted attribution cannot be
    // widened by the client and remains a non-allowing fail-closed outcome.
    let missing_owner = evaluate(&owner, &authority, identity(4, 3), Some(&own_tenant), None);
    assert_eq!(missing_owner.decision, MemoryV1Decision::Pending);
    assert_eq!(
        missing_owner.pending_source,
        Some(MemoryV1PendingSource::ContextInvalid)
    );
    assert!(missing_owner.admission.is_none());

    let missing_tenant = evaluate(&owner, &authority, identity(5, 3), None, Some(&own_owner));
    assert_eq!(missing_tenant.decision, MemoryV1Decision::Pending);
    assert_eq!(
        missing_tenant.pending_source,
        Some(MemoryV1PendingSource::ContextInvalid)
    );
    assert!(missing_tenant.admission.is_none());
}

#[test]
fn batch_b_scope_filtering_preserves_deny_wins_and_pending() {
    let test_name = "batch_b_scope_filtering_preserves_deny_wins_and_pending";
    if std::env::var_os(CHILD_ENV).is_none() {
        run_isolated(test_name);
        return;
    }

    let wide_allow = br#"{"rules":[{"ruleId":"wide","resource":"document","action":"read","effect":"ALLOW","ownerScope":"all","tenantScope":"self+descendants"}]}"#;
    let mixed_deny_first = br#"{"rules":[{"ruleId":"strict-deny","resource":"document","action":"read","effect":"DENY"},{"ruleId":"wide-allow","resource":"document","action":"read","effect":"ALLOW","ownerScope":"all","tenantScope":"self+descendants"}]}"#;
    let mixed_allow_first = br#"{"rules":[{"ruleId":"wide-allow","resource":"document","action":"read","effect":"ALLOW","ownerScope":"all","tenantScope":"self+descendants"},{"ruleId":"strict-deny","resource":"document","action":"read","effect":"DENY"}]}"#;
    let missing_owner_deny = br#"{"rules":[{"ruleId":"narrow-deny","resource":"document","action":"read","effect":"DENY","ownerScope":"self","tenantScope":"self+descendants"},{"ruleId":"wide-allow","resource":"document","action":"read","effect":"ALLOW","ownerScope":"all","tenantScope":"self+descendants"}]}"#;
    let in_scope_deny = br#"{"rules":[{"ruleId":"wide-deny","resource":"document","action":"read","effect":"DENY","ownerScope":"all","tenantScope":"self+descendants"}]}"#;
    let contents: &[(u8, &[u8])] = &[
        (10, wide_allow),
        (11, mixed_deny_first),
        (12, mixed_allow_first),
        (13, missing_owner_deny),
        (14, in_scope_deny),
    ];
    let mut rows = CandidateRows {
        users: vec![UserRow { user_id: id(1) }],
        identity_cards: vec![IdentityCardRow {
            identity_card_id: id(2),
            user_id: id(1),
        }],
        tenants: vec![
            TenantRow {
                tenant_id: id(3),
                parent_tenant_id: None,
            },
            TenantRow {
                tenant_id: id(30),
                parent_tenant_id: Some(id(3)),
            },
        ],
        user_cards: (4..=8)
            .map(|card| UserCardRow {
                user_card_id: id(card),
                user_id: id(1),
                tenant_id: id(3),
                status: UserCardStatus::Active,
            })
            .collect(),
        ..CandidateRows::default()
    };
    let mut selections = Vec::new();
    for &(set, content) in contents {
        rows.rule_sets.push(RuleSetRow {
            status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
            rule_set_id: id(set),
            owner_tenant_id: id(3),
            current_version_bytes: vec![1],
        });
        rows.rule_set_versions.push(version(set, content));
        rows.rule_set_change_confirmations
            .push(change_confirmation(200 + set, set, vec![1], None));
        selections.push(CurrentSelection {
            rule_set_id: id(set),
            version_bytes: vec![1],
        });
    }
    for (binding_id, card, set, layer, owner_scope, tenant_scope) in [
        (
            20,
            4,
            10,
            BindingLayer::Base,
            MemoryV1OwnerScope::AllUsers,
            MemoryV1TenantScope::SelfAndDescendants,
        ),
        (
            21,
            4,
            11,
            BindingLayer::Overlay,
            MemoryV1OwnerScope::SelfUser,
            MemoryV1TenantScope::SelfTenant,
        ),
        (
            22,
            5,
            11,
            BindingLayer::Base,
            MemoryV1OwnerScope::AllUsers,
            MemoryV1TenantScope::SelfAndDescendants,
        ),
        (
            23,
            6,
            12,
            BindingLayer::Base,
            MemoryV1OwnerScope::AllUsers,
            MemoryV1TenantScope::SelfAndDescendants,
        ),
        (
            24,
            7,
            13,
            BindingLayer::Base,
            MemoryV1OwnerScope::AllUsers,
            MemoryV1TenantScope::SelfAndDescendants,
        ),
        (
            25,
            8,
            11,
            BindingLayer::Base,
            MemoryV1OwnerScope::SelfUser,
            MemoryV1TenantScope::SelfTenant,
        ),
        (
            26,
            8,
            14,
            BindingLayer::Overlay,
            MemoryV1OwnerScope::AllUsers,
            MemoryV1TenantScope::SelfAndDescendants,
        ),
    ] {
        rows.bindings.push(binding(
            binding_id,
            card,
            set,
            layer,
            owner_scope,
            tenant_scope,
        ));
        rows.binding_confirmations.push(binding_confirmation(
            binding_id + 100,
            binding_id,
            set,
            None,
        ));
    }

    let owner = serving_owner(rows, selections);
    let authority = MemoryV1SessionAuthority::new();
    authority
        .bind_to_root(&owner)
        .expect("session authority binds to the fixture root");
    let child_tenant = id(30);
    let foreign_owner = id(9);

    // An unrelated narrow binding does not suppress a wide ALLOW.
    for card in [4, 5, 6] {
        let allowed = evaluate(
            &owner,
            &authority,
            identity(card, 3),
            Some(&child_tenant),
            Some(&foreign_owner),
        );
        assert_eq!(allowed.decision, MemoryV1Decision::Allow, "card {card}");
        let admission = allowed.admission.expect("matching wide rule is admitted");
        assert_eq!(
            admission.effective_owner_scope(),
            MemoryV1OwnerScope::AllUsers
        );
        assert_eq!(
            admission.effective_tenant_scope(),
            MemoryV1TenantScope::SelfAndDescendants
        );
    }

    // A narrow rule whose owner is unknown might be a DENY; a separate wide
    // ALLOW cannot hide that missing fact.
    let pending = evaluate(
        &owner,
        &authority,
        identity(7, 3),
        Some(&child_tenant),
        None,
    );
    assert_eq!(pending.decision, MemoryV1Decision::Pending);
    assert_eq!(
        pending.pending_source,
        Some(MemoryV1PendingSource::ContextInvalid)
    );
    assert!(pending.admission.is_none());

    // A genuine matching DENY remains determinate even when another rule is
    // outside the target's scope and must not replace the deny source.
    let denied = evaluate(
        &owner,
        &authority,
        identity(8, 3),
        Some(&child_tenant),
        Some(&foreign_owner),
    );
    assert_eq!(denied.decision, MemoryV1Decision::Deny);
    assert_eq!(denied.deny_source, Some(MemoryV1DenySource::RuleDenied));
    assert!(denied.admission.is_none());
}

// memory—v1 §4.11: Explicit confirmation derives every beneficiary from the
// same root; the old interface cannot produce a confirmation admission.
#[test]
fn batch_b_change_confirmation_derives_beneficiaries_and_fails_closed() {
    const SCENARIO: &str = "ASTRAL_BATCH_B_IMPACT_SCENARIO";
    let test_name = "batch_b_change_confirmation_derives_beneficiaries_and_fails_closed";
    if std::env::var_os(CHILD_ENV).is_none() {
        for scenario in [
            "self",
            "two",
            "narrow",
            "narrow_binding",
            "narrow_owner_entry",
            "explicit_self_owner_entry",
            "narrow_owner_binding",
            "wide",
            "empty",
            "empty_narrow",
            "bad_target",
            "budget",
            "history_wide",
            "history_self",
            "history_budget",
        ] {
            let output = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", test_name, "--nocapture"])
                .env(CHILD_ENV, "1")
                .env(SCENARIO, scenario)
                .output()
                .expect("start isolated impact scenario");
            assert!(
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
                "scenario {scenario} failed\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        return;
    }
    let scenario = std::env::var(SCENARIO).unwrap();
    let (mut rows, mut selections) = batch_fixture();
    let grant = if scenario == "narrow" || scenario == "empty_narrow" {
        br#"{"rules":[{"ruleId":"confirm","resource":"rule_set","action":"confirm-change","effect":"ALLOW","ownerScope":"all"}]}"#.as_slice()
    } else if scenario == "narrow_owner_entry" {
        br#"{"rules":[{"ruleId":"confirm","resource":"rule_set","action":"confirm-change","effect":"ALLOW","tenantScope":"self+descendants"}]}"#.as_slice()
    } else if scenario == "explicit_self_owner_entry" {
        br#"{"rules":[{"ruleId":"confirm","resource":"rule_set","action":"confirm-change","effect":"ALLOW","ownerScope":"self","tenantScope":"self+descendants"}]}"#.as_slice()
    } else {
        br#"{"rules":[{"ruleId":"confirm","resource":"rule_set","action":"confirm-change","effect":"ALLOW","ownerScope":"all","tenantScope":"self+descendants"}]}"#.as_slice()
    };
    rows.rule_set_versions[0] = version(10, grant);
    rows.bindings[0].owner_scope = if scenario == "narrow_owner_binding" {
        MemoryV1OwnerScope::SelfUser
    } else {
        MemoryV1OwnerScope::AllUsers
    };
    rows.bindings[0].tenant_scope = if scenario == "narrow_binding" {
        MemoryV1TenantScope::SelfTenant
    } else {
        MemoryV1TenantScope::SelfAndDescendants
    };
    rows.rule_set_change_confirmations
        .push(change_confirmation(220, 10, vec![1], None));
    rows.tenants.push(TenantRow {
        tenant_id: id(30),
        parent_tenant_id: Some(id(3)),
    });
    rows.users.push(UserRow { user_id: id(31) });
    rows.identity_cards.push(IdentityCardRow {
        identity_card_id: id(32),
        user_id: id(31),
    });
    rows.user_cards.push(UserCardRow {
        user_card_id: id(33),
        user_id: id(31),
        tenant_id: id(30),
        status: UserCardStatus::Active,
    });
    rows.rule_sets.push(RuleSetRow {
        status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
        rule_set_id: id(40),
        owner_tenant_id: id(30),
        current_version_bytes: vec![1],
    });
    rows.rule_set_versions.push(version(40, br#"{"rules":[]}"#));
    rows.bindings.push(binding(
        41,
        33,
        40,
        BindingLayer::Base,
        MemoryV1OwnerScope::SelfUser,
        MemoryV1TenantScope::SelfTenant,
    ));
    rows.binding_confirmations
        .push(binding_confirmation(141, 41, 40, None));
    rows.rule_set_change_confirmations
        .push(change_confirmation(240, 40, vec![1], None));
    selections.push(CurrentSelection {
        rule_set_id: id(40),
        version_bytes: vec![1],
    });
    if matches!(
        scenario.as_str(),
        "self" | "budget" | "history_self" | "history_budget"
    ) {
        rows.user_cards.push(UserCardRow {
            user_card_id: id(34),
            user_id: id(1),
            tenant_id: id(30),
            status: if scenario == "history_self" {
                UserCardStatus::Disabled
            } else {
                UserCardStatus::Active
            },
        });
        rows.bindings.push(binding(
            42,
            34,
            40,
            BindingLayer::Base,
            MemoryV1OwnerScope::SelfUser,
            MemoryV1TenantScope::SelfTenant,
        ));
        let mut confirmation = binding_confirmation(142, 42, 40, None);
        if scenario == "history_self" {
            confirmation.revoked_at = Some(100);
            confirmation.revoked_by = Some(id(1));
        }
        rows.binding_confirmations.push(confirmation);
    }
    if scenario.starts_with("history_") {
        for n in 50..70 {
            let mut old = binding(
                n,
                33,
                40,
                BindingLayer::Base,
                MemoryV1OwnerScope::SelfUser,
                MemoryV1TenantScope::SelfTenant,
            );
            old.removed_at = Some(100);
            old.removed_by = Some(id(1));
            rows.bindings.push(old);
        }
    }
    if scenario == "two" {
        rows.users.push(UserRow { user_id: id(35) });
        rows.identity_cards.push(IdentityCardRow {
            identity_card_id: id(36),
            user_id: id(35),
        });
        rows.user_cards.push(UserCardRow {
            user_card_id: id(37),
            user_id: id(35),
            tenant_id: id(30),
            status: UserCardStatus::Active,
        });
        rows.bindings.push(binding(
            43,
            37,
            40,
            BindingLayer::Base,
            MemoryV1OwnerScope::SelfUser,
            MemoryV1TenantScope::SelfTenant,
        ));
        rows.binding_confirmations
            .push(binding_confirmation(143, 43, 40, None));
    }
    if scenario == "empty" || scenario == "empty_narrow" {
        rows.bindings.retain(|row| row.binding_id != id(41));
        rows.binding_confirmations
            .retain(|row| row.binding_id != id(41));
    }
    let mut limits = budget();
    if scenario == "budget" || scenario.starts_with("history_") {
        limits.max_bindings_per_read = if scenario == "history_self" { 2 } else { 1 };
    }
    let owner = install_process_root(rows, selections, limits).expect("candidate root installs");
    owner
        .install_registry(&[RegistryDeclaration {
            resource: "rule_set".to_owned(),
            actions: vec!["confirm-change".to_owned()],
        }])
        .expect("registry installs");
    owner
        .adopt_serving_for_isolated_tests()
        .expect("fixture adopts");
    let authority = MemoryV1SessionAuthority::new();
    authority
        .bind_to_root(&owner)
        .expect("session authority binds to the fixture root");
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let session = session_for(&authority, &root, identity(4, 3));
    let target = id(40);
    let tenant = id(30);
    let forged_owner = id(31);
    let request = MemoryV1Request {
        resource: "rule_set",
        action: "confirm-change",
        target: Some(&target),
        target_tenant: Some(&tenant),
        target_owner: (scenario == "self").then_some(forged_owner.as_slice()),
        operation_id: b"impact-op",
        operation_fingerprint: b"impact-fingerprint",
    };
    let engine = PolicyEngine::new();
    let result = engine.evaluate_memory_v1(&root, &session, &request);
    match scenario.as_str() {
        "self" | "history_self" => {
            assert_eq!(result.decision, MemoryV1Decision::Deny);
            assert_eq!(
                result.deny_source,
                Some(MemoryV1DenySource::SelfConfirmation)
            );
        }
        "narrow"
        | "narrow_binding"
        | "narrow_owner_entry"
        | "explicit_self_owner_entry"
        | "narrow_owner_binding" => {
            assert_eq!(result.decision, MemoryV1Decision::Deny);
            assert_eq!(result.deny_source, Some(MemoryV1DenySource::ScopeDenied));
        }
        _ => {
            assert_eq!(result.decision, MemoryV1Decision::Pending);
        }
    }
    assert!(result.admission.is_none());
    let mut explicit_request = request;
    explicit_request.target_owner = None;
    let stats_before = engine.get_stats();
    let explicit = engine.evaluate_memory_v1_rule_set_change(
        &root,
        &session,
        &explicit_request,
        MemoryV1RuleSetChangeIntent::Publish,
    );
    let stats_after = engine.get_stats();
    assert_eq!(
        stats_after.evaluation_count,
        stats_before.evaluation_count + 1
    );
    match scenario.as_str() {
        "wide" | "two" | "empty" | "bad_target" | "history_wide" => {
            assert_eq!(explicit.decision, MemoryV1Decision::Allow);
            let admission = explicit.admission.expect("single action is admitted");
            assert_eq!(
                admission.change_intent(),
                Some(MemoryV1RuleSetChangeIntent::Publish)
            );
            assert_eq!(admission.target(), Some(target.as_slice()));
        }
        "self" | "history_self" => {
            assert_eq!(explicit.decision, MemoryV1Decision::Deny);
            assert_eq!(
                explicit.deny_source,
                Some(MemoryV1DenySource::SelfConfirmation)
            );
        }
        "narrow"
        | "narrow_binding"
        | "narrow_owner_entry"
        | "explicit_self_owner_entry"
        | "narrow_owner_binding" => {
            assert_eq!(explicit.decision, MemoryV1Decision::Deny);
            assert_eq!(explicit.deny_source, Some(MemoryV1DenySource::ScopeDenied));
        }
        "empty_narrow" => {
            assert_eq!(explicit.decision, MemoryV1Decision::Deny);
            assert_eq!(explicit.deny_source, Some(MemoryV1DenySource::ScopeDenied));
        }
        "budget" | "history_budget" => assert_eq!(explicit.decision, MemoryV1Decision::Pending),
        _ => unreachable!(),
    }
    if scenario == "bad_target" {
        let fresh_id = id(50);
        let create = MemoryV1Request {
            target: Some(&fresh_id),
            ..explicit_request
        };
        let result = engine.evaluate_memory_v1_rule_set_change(
            &root,
            &session,
            &create,
            MemoryV1RuleSetChangeIntent::Create,
        );
        assert_eq!(result.decision, MemoryV1Decision::Allow);
        assert_eq!(
            result.admission.unwrap().change_intent(),
            Some(MemoryV1RuleSetChangeIntent::Create)
        );
        assert_eq!(
            engine
                .evaluate_memory_v1_rule_set_change(
                    &root,
                    &session,
                    &create,
                    MemoryV1RuleSetChangeIntent::Publish,
                )
                .decision,
            MemoryV1Decision::Pending
        );
        assert_eq!(
            engine
                .evaluate_memory_v1_rule_set_change(
                    &root,
                    &session,
                    &explicit_request,
                    MemoryV1RuleSetChangeIntent::Create,
                )
                .decision,
            MemoryV1Decision::Pending
        );
        let forged = MemoryV1Request {
            target_owner: Some(&forged_owner),
            ..explicit_request
        };
        assert_eq!(
            engine
                .evaluate_memory_v1_rule_set_change(
                    &root,
                    &session,
                    &forged,
                    MemoryV1RuleSetChangeIntent::Publish,
                )
                .decision,
            MemoryV1Decision::Pending
        );
    }
    if scenario == "bad_target" {
        let forged = MemoryV1Request {
            target_owner: Some(&forged_owner),
            ..request
        };
        assert_eq!(
            engine.evaluate_memory_v1(&root, &session, &forged).decision,
            MemoryV1Decision::Pending
        );
        let wrong_tenant = id(3);
        let forged = MemoryV1Request {
            target_tenant: Some(&wrong_tenant),
            ..request
        };
        assert_eq!(
            engine.evaluate_memory_v1(&root, &session, &forged).decision,
            MemoryV1Decision::Pending
        );
    }
}

// memory—v1: Impact denials retain the rule-set target and separately name the
// root-derived binding that made the confirmation fail.
#[test]
fn change_confirmation_deny_preserves_rule_set_and_affected_binding() {
    if std::env::var_os(CHILD_ENV).is_none() {
        for scenario in [
            "explicit", "compound", "ordinary", "self", "forged", "wide", "empty",
        ] {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "change_confirmation_deny_preserves_rule_set_and_affected_binding",
                    "--nocapture",
                ])
                .env(CHILD_ENV, "1")
                .env("ASTRAL_IMPACT_ATTRIBUTION_SCENARIO", scenario)
                .output()
                .expect("start isolated attribution scenario");
            assert!(
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
                "scenario {scenario} failed\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
        return;
    }
    let scenario = std::env::var("ASTRAL_IMPACT_ATTRIBUTION_SCENARIO").unwrap();
    let (mut rows, mut selections) = batch_fixture();
    let rule = match scenario.as_str() {
        "explicit" | "compound" | "forged" | "wide" | "empty" => br#"{"rules":[{"ruleId":"allow","resource":"rule_set","action":"confirm-change","effect":"ALLOW","ownerScope":"all","tenantScope":"self+descendants"}]}"#.as_slice(),
        "ordinary" | "self" => br#"{"rules":[{"ruleId":"deny","resource":"rule_set","action":"confirm-change","effect":"DENY","ownerScope":"all","tenantScope":"self+descendants"}]}"#.as_slice(),
        _ => unreachable!(),
    };
    rows.rule_set_versions[0] = version(10, rule);
    rows.bindings[0].owner_scope = MemoryV1OwnerScope::AllUsers;
    rows.bindings[0].tenant_scope =
        if matches!(scenario.as_str(), "explicit" | "compound" | "forged") {
            MemoryV1TenantScope::SelfTenant
        } else {
            MemoryV1TenantScope::SelfAndDescendants
        };
    rows.rule_set_change_confirmations
        .push(change_confirmation(220, 10, vec![1], None));
    rows.users.push(UserRow { user_id: id(31) });
    rows.identity_cards.push(IdentityCardRow {
        identity_card_id: id(32),
        user_id: id(31),
    });
    let target_tenant = if matches!(scenario.as_str(), "explicit" | "compound" | "forged") {
        rows.tenants.push(TenantRow {
            tenant_id: id(30),
            parent_tenant_id: Some(id(3)),
        });
        id(30)
    } else {
        id(3)
    };
    rows.user_cards.push(UserCardRow {
        user_card_id: id(33),
        user_id: id(31),
        tenant_id: target_tenant,
        status: UserCardStatus::Active,
    });
    rows.rule_sets.push(RuleSetRow {
        status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
        rule_set_id: id(40),
        owner_tenant_id: target_tenant,
        current_version_bytes: vec![1],
    });
    rows.rule_set_versions.push(version(40, br#"{"rules":[]}"#));
    rows.bindings.push(binding(
        41,
        33,
        40,
        BindingLayer::Base,
        MemoryV1OwnerScope::SelfUser,
        MemoryV1TenantScope::SelfTenant,
    ));
    rows.binding_confirmations
        .push(binding_confirmation(141, 41, 40, None));
    rows.rule_set_change_confirmations
        .push(change_confirmation(240, 40, vec![1], None));
    if scenario == "empty" {
        rows.bindings.retain(|row| row.binding_id != id(41));
        rows.binding_confirmations
            .retain(|row| row.binding_id != id(41));
    }
    if scenario == "self" {
        rows.user_cards.push(UserCardRow {
            user_card_id: id(34),
            user_id: id(1),
            tenant_id: target_tenant,
            status: UserCardStatus::Active,
        });
        rows.bindings.push(binding(
            42,
            34,
            40,
            BindingLayer::Base,
            MemoryV1OwnerScope::SelfUser,
            MemoryV1TenantScope::SelfTenant,
        ));
        rows.binding_confirmations
            .push(binding_confirmation(142, 42, 40, None));
    }
    selections.push(CurrentSelection {
        rule_set_id: id(40),
        version_bytes: vec![1],
    });
    let owner = install_process_root(rows, selections, budget()).unwrap();
    owner
        .install_registry(&[RegistryDeclaration {
            resource: "rule_set".to_owned(),
            actions: vec!["confirm-change".to_owned()],
        }])
        .unwrap();
    owner.adopt_serving_for_isolated_tests().unwrap();
    let authority = MemoryV1SessionAuthority::new();
    authority.bind_to_root(&owner).unwrap();
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let session = session_for(&authority, &root, identity(4, 3));
    let target = id(40);
    let tenant = target_tenant;
    let request = MemoryV1Request {
        resource: "rule_set",
        action: "confirm-change",
        target: Some(&target),
        target_tenant: Some(&tenant),
        target_owner: None,
        operation_id: b"impact-observation-op",
        operation_fingerprint: b"impact-observation-fingerprint",
    };
    let facts = root
        .with_reader(|reader| reader.rule_set_target(target))
        .unwrap()
        .unwrap();
    let compound_action = MemoryV1CompoundAction {
        request,
        change_intent: Some(MemoryV1RuleSetChangeIntent::Publish),
        target_facts: facts,
        target_kind: MemoryV1CompoundTargetKind::Existing,
    };
    let engine = PolicyEngine::new();
    let before = owner.handle().metadata().unwrap();
    let ordinary = engine.evaluate_memory_v1(&root, &session, &request);
    let explicit = engine.evaluate_memory_v1_rule_set_change(
        &root,
        &session,
        &request,
        MemoryV1RuleSetChangeIntent::Publish,
    );
    let compound = engine.evaluate_memory_v1_compound(
        &root,
        &session,
        &MemoryV1CompoundRequest {
            actions: &[compound_action],
        },
    );
    let expected_source = if scenario == "self" {
        MemoryV1DenySource::SelfConfirmation
    } else if matches!(scenario.as_str(), "ordinary" | "wide" | "empty") {
        MemoryV1DenySource::RuleDenied
    } else {
        MemoryV1DenySource::ScopeDenied
    };
    let expected_bindings = [false, false, false];
    if scenario == "forged" {
        let forged_owner = id(31);
        let forged_request = MemoryV1Request {
            target_owner: Some(&forged_owner),
            ..request
        };
        let result = engine.evaluate_memory_v1_rule_set_change(
            &root,
            &session,
            &forged_request,
            MemoryV1RuleSetChangeIntent::Publish,
        );
        assert_eq!(result.decision, MemoryV1Decision::Pending);
        assert!(result.deny_observation.is_none());
        let mut forged_action = compound_action;
        forged_action.request = forged_request;
        let result = engine.evaluate_memory_v1_compound(
            &root,
            &session,
            &MemoryV1CompoundRequest {
                actions: &[forged_action],
            },
        );
        assert_eq!(result.decision, MemoryV1Decision::Pending);
        assert!(result.deny_observation.is_none());
    }
    if matches!(scenario.as_str(), "wide" | "empty") {
        assert_eq!(ordinary.decision, MemoryV1Decision::Pending);
        assert!(ordinary.deny_observation.is_none());
        assert_eq!(explicit.decision, MemoryV1Decision::Allow);
        assert!(explicit.deny_observation.is_none());
        assert_eq!(compound.decision, MemoryV1Decision::Allow);
        assert!(compound.deny_observation.is_none());
        assert_eq!(owner.handle().metadata().unwrap(), before);
        return;
    }
    for (index, (name, decision, source, pending, observation)) in [
        (
            "ordinary",
            ordinary.decision,
            ordinary.deny_source,
            ordinary.pending_source,
            ordinary.deny_observation.as_deref(),
        ),
        (
            "explicit",
            explicit.decision,
            explicit.deny_source,
            explicit.pending_source,
            explicit.deny_observation.as_deref(),
        ),
        (
            "compound",
            compound.decision,
            compound.deny_source,
            compound.pending_source,
            compound.deny_observation.as_deref(),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let expected_binding = expected_bindings[index];
        assert_eq!(
            decision,
            MemoryV1Decision::Deny,
            "{name}: source={source:?} pending={pending:?} observation={observation:?}"
        );
        assert_eq!(source, Some(expected_source));
        let observation = observation.expect("denial is attributable");
        assert_eq!(observation.root(), before);
        assert_eq!(observation.identity(), identity(4, 3));
        assert_eq!(observation.resource(), "rule_set");
        assert_eq!(observation.action(), "confirm-change");
        assert_eq!(observation.target(), Some(target.as_slice()));
        assert_eq!(observation.target_tenant(), Some(tenant.as_slice()));
        assert_eq!(observation.target_owner(), None);
        match observation.affected_binding() {
            Some(binding) => {
                assert!(expected_binding, "{name}: unexpected binding attribution");
                assert_eq!(binding.binding_id(), id(41));
                assert_eq!(binding.user_card_id(), id(33));
                assert_eq!(binding.owner_user_id(), id(31));
                assert_eq!(binding.tenant_id(), target_tenant);
                assert_eq!(
                    format!("{binding:?}"),
                    "MemoryV1AffectedBindingObservation(<redacted>)"
                );
            }
            None => assert!(!expected_binding, "{name}: missing binding attribution"),
        }
        assert_eq!(observation.operation_id(), b"impact-observation-op");
        assert_eq!(
            observation.operation_fingerprint(),
            b"impact-observation-fingerprint"
        );
        assert_eq!(observation.source(), expected_source);
        assert_eq!(observation.batch_sequence(), None);
        assert_eq!(
            format!("{observation:?}"),
            "MemoryV1DenyObservation(<redacted>)"
        );
    }
    assert!(ordinary.admission.is_none());
    assert!(explicit.admission.is_none());
    assert!(compound.admissions.is_empty());
    assert_eq!(owner.handle().metadata().unwrap(), before);
}

fn batch_fixture() -> (CandidateRows, Vec<CurrentSelection>) {
    let content =
        br#"{"rules":[{"ruleId":"read","resource":"document","action":"read","effect":"ALLOW"}]}"#;
    let rows = CandidateRows {
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
            current_version_bytes: vec![1],
        }],
        rule_set_versions: vec![version(10, content)],
        bindings: vec![binding(
            20,
            4,
            10,
            BindingLayer::Base,
            MemoryV1OwnerScope::SelfUser,
            MemoryV1TenantScope::SelfTenant,
        )],
        // One pre-existing row makes a successful batch row observable.
        binding_confirmations: vec![binding_confirmation(120, 20, 10, None)],
        ..CandidateRows::default()
    };
    (
        rows,
        vec![CurrentSelection {
            rule_set_id: id(10),
            version_bytes: vec![1],
        }],
    )
}

// memory—v1 §4.9: A matching rule cannot conceal another inactive reference.
#[test]
fn batch_b_inactive_sibling_resource_makes_binding_pending() {
    let test_name = "batch_b_inactive_sibling_resource_makes_binding_pending";
    if std::env::var_os(CHILD_ENV).is_none() {
        run_isolated(test_name);
        return;
    }

    let (mut rows, selections) = batch_fixture();
    rows.rule_set_versions[0] = version(
        10,
        br#"{"rules":[{"ruleId":"read","resource":"document","action":"read","effect":"ALLOW"},{"ruleId":"other-read","resource":"other","action":"read","effect":"ALLOW"}]}"#,
    );
    rows.rule_set_change_confirmations
        .push(change_confirmation(220, 10, vec![1], None));
    let owner = install_process_root(rows, selections, budget()).expect("candidate root installs");
    owner
        .install_registry(&[
            RegistryDeclaration {
                resource: "document".to_owned(),
                actions: vec!["read".to_owned()],
            },
            RegistryDeclaration {
                resource: "other".to_owned(),
                actions: vec!["read".to_owned()],
            },
        ])
        .expect("both resources are registered before adoption");
    owner
        .adopt_serving_for_isolated_tests()
        .expect("both rule references are initially active");

    let authority = MemoryV1SessionAuthority::new();
    authority
        .bind_to_root(&owner)
        .expect("session authority binds to the fixture root");
    let target_tenant = id(3);
    let target_owner = id(1);
    let evaluate_document = || {
        evaluate(
            &owner,
            &authority,
            identity(4, 3),
            Some(&target_tenant),
            Some(&target_owner),
        )
    };
    let allowed = evaluate_document();
    assert_eq!(allowed.decision, MemoryV1Decision::Allow);
    assert!(allowed.admission.is_some());

    owner
        .request_registry_retirement_for_test("other")
        .expect("other becomes RetireRequested");
    let pending = evaluate_document();
    assert_eq!(pending.decision, MemoryV1Decision::Pending);
    assert_eq!(
        pending.pending_source,
        Some(MemoryV1PendingSource::ContextInvalid)
    );
    assert!(pending.deny_source.is_none());
    assert!(pending.admission.is_none());
}

// memory—v1: A valid ALLOW binding cannot hide an unverifiable active binding.
#[test]
fn batch_b_allow_binding_cannot_hide_inactive_resource_in_another_binding() {
    let test_name = "batch_b_allow_binding_cannot_hide_inactive_resource_in_another_binding";
    if std::env::var_os(CHILD_ENV).is_none() {
        run_isolated(test_name);
        return;
    }

    let (mut rows, selections) = overlay_fixture();
    rows.rule_set_versions[1] = version(
        11,
        br#"{"rules":[{"ruleId":"other-read","resource":"other","action":"read","effect":"ALLOW"}]}"#,
    );
    let owner = install_process_root(rows, selections, budget()).expect("candidate root installs");
    owner
        .install_registry(&[
            RegistryDeclaration {
                resource: "document".to_owned(),
                actions: vec!["read".to_owned()],
            },
            RegistryDeclaration {
                resource: "other".to_owned(),
                actions: vec!["read".to_owned()],
            },
            RegistryDeclaration {
                resource: "unused".to_owned(),
                actions: vec!["read".to_owned()],
            },
        ])
        .expect("both resources and the unused control are registered before adoption");
    owner
        .adopt_serving_for_isolated_tests()
        .expect("both active bindings are initially serving-ready");

    let authority = MemoryV1SessionAuthority::new();
    authority
        .bind_to_root(&owner)
        .expect("session authority binds to the fixture root");
    let target_tenant = id(3);
    let target_owner = id(1);
    let evaluate_document = || {
        evaluate(
            &owner,
            &authority,
            identity(4, 3),
            Some(&target_tenant),
            Some(&target_owner),
        )
    };
    let allowed = evaluate_document();
    assert_eq!(allowed.decision, MemoryV1Decision::Allow);
    assert!(allowed.admission.is_some());

    owner
        .request_registry_retirement_for_test("unused")
        .expect("the unreferenced resource becomes RetireRequested");
    let after_unrelated_retirement = evaluate_document();
    assert_eq!(after_unrelated_retirement.decision, MemoryV1Decision::Allow);
    assert!(after_unrelated_retirement.admission.is_some());

    owner
        .request_registry_retirement_for_test("other")
        .expect("the second binding's resource becomes RetireRequested");
    let pending = evaluate_document();
    assert_eq!(pending.decision, MemoryV1Decision::Pending);
    assert_eq!(
        pending.pending_source,
        Some(MemoryV1PendingSource::ContextInvalid)
    );
    assert!(pending.deny_source.is_none());
    assert!(pending.admission.is_none());
}

fn confirmation_ids(owner: &RootOwner) -> Vec<[u8; 16]> {
    owner
        .handle()
        .read_card(id(4), |context| {
            context.bindings[0]
                .confirmations
                .iter()
                .map(|confirmation| confirmation.confirmation_id)
                .collect()
        })
        .expect("candidate card is readable")
        .value
}

// memory—v1: An invalid batch entry leaves the valid reconfirmation unpublished.
#[test]
fn batch_b_confirmation_batch_is_atomic_when_one_item_is_invalid() {
    let test_name = "batch_b_confirmation_batch_is_atomic_when_one_item_is_invalid";
    if std::env::var_os(CHILD_ENV).is_none() {
        run_isolated(test_name);
        return;
    }

    let (mut rows, selections) = batch_fixture();
    rows.binding_confirmations[0].revoked_at = Some(100);
    rows.binding_confirmations[0].revoked_by = Some(id(1));
    let owner = install_process_root(rows, selections, budget()).expect("candidate root installs");
    let handle = owner.handle();
    let before = handle.metadata().expect("candidate metadata is readable");
    assert_eq!(confirmation_ids(&owner), vec![id(120)]);

    let valid = binding_confirmation(121, 20, 10, None);
    let invalid = BindingConfirmationRow {
        confirmation_id: id(122),
        binding_id: id(99),
        rule_set_id: id(10),
        version_bytes: vec![1],
        confirmer_user_id: id(1),
        scope_bytes: vec![1],
        operation_id: vec![122],
        confirmed_at_bytes: vec![1],
        revoked_at: None,
        revoked_by: None,
    };
    let mutation = ManagementMutationV2::ConfirmationBatch {
        rows: vec![valid, invalid],
    };
    let result = owner.execute_mutation_with_precondition(
        &mutation,
        &MutationPrecondition {
            evaluated_root_version: before.version,
        },
    );
    assert!(matches!(
        result,
        Err(MutationError::Candidate(CandidateError::UnknownId {
            table: Table::Binding,
            id
        })) if id == [99; 16]
    ));

    // Preflight rejects the batch before publication, so metadata and every
    // confirmation row remain unchanged.
    assert_eq!(
        handle.metadata().expect("metadata remains readable"),
        before
    );
    let ids = confirmation_ids(&owner);
    assert_eq!(ids.len(), 1);
    assert!(ids.contains(&id(120)));
    assert!(!ids.contains(&id(121)));
    assert!(!ids.contains(&id(122)));
}

// memory—v1 §4.11 N-10: A rejected batch changes neither card's effective
// permission; one successful root publication restores both confirmations.
#[test]
fn batch_b_confirmation_batch_changes_both_cards_or_neither() {
    let test_name = "batch_b_confirmation_batch_changes_both_cards_or_neither";
    if std::env::var_os(CHILD_ENV).is_none() {
        run_isolated(test_name);
        return;
    }

    let (mut rows, selections) = batch_fixture();
    rows.user_cards.push(UserCardRow {
        user_card_id: id(5),
        user_id: id(1),
        tenant_id: id(3),
        status: UserCardStatus::Active,
    });
    rows.bindings.push(binding(
        21,
        5,
        10,
        BindingLayer::Base,
        MemoryV1OwnerScope::SelfUser,
        MemoryV1TenantScope::SelfTenant,
    ));
    rows.binding_confirmations[0].revoked_at = Some(100);
    rows.binding_confirmations[0].revoked_by = Some(id(1));
    rows.binding_confirmations
        .push(binding_confirmation(121, 21, 10, Some(100)));
    rows.rule_set_change_confirmations
        .push(change_confirmation(220, 10, vec![1], None));
    let owner = serving_owner(rows, selections);
    let authority = MemoryV1SessionAuthority::new();
    authority
        .bind_to_root(&owner)
        .expect("authority binds to root");
    let tenant = id(3);
    let target_owner = id(1);
    let evaluate_card = |card| {
        evaluate(
            &owner,
            &authority,
            identity(card, 3),
            Some(&tenant),
            Some(&target_owner),
        )
    };
    for card in [4, 5] {
        let result = evaluate_card(card);
        assert_eq!(result.decision, MemoryV1Decision::Deny);
        assert_eq!(result.deny_source, Some(MemoryV1DenySource::NoMatch));
        assert!(result.admission.is_none());
    }

    let before = owner
        .handle()
        .metadata()
        .expect("root metadata is readable");
    let precondition = MutationPrecondition {
        evaluated_root_version: before.version,
    };
    let first = binding_confirmation(130, 20, 10, None);
    let second = binding_confirmation(131, 21, 10, None);
    let invalid = binding_confirmation(132, 99, 10, None);
    let rejected = ManagementMutationV2::ConfirmationBatch {
        rows: vec![first.clone(), invalid],
    };
    assert!(matches!(
        owner.execute_mutation_with_precondition_for_isolated_tests(&rejected, &precondition),
        Err(MutationError::Candidate(CandidateError::UnknownId {
            table: Table::Binding,
            id: missing,
        })) if missing == id(99)
    ));
    assert_eq!(owner.handle().metadata().unwrap(), before);
    for card in [4, 5] {
        let result = evaluate_card(card);
        assert_eq!(result.decision, MemoryV1Decision::Deny);
        assert_eq!(result.deny_source, Some(MemoryV1DenySource::NoMatch));
        assert!(result.admission.is_none());
    }

    // This isolated mutation tests the root publication, not a governance admission.
    let batch = ManagementMutationV2::ConfirmationBatch {
        rows: vec![first, second],
    };
    let after = owner
        .execute_mutation_with_precondition_for_isolated_tests(&batch, &precondition)
        .expect("both confirmations publish together");
    assert_eq!(after.version, before.version + 1);
    assert_ne!(after.digest, before.digest);
    for card in [4, 5] {
        let result = evaluate_card(card);
        assert_eq!(result.decision, MemoryV1Decision::Allow);
        assert_eq!(result.deny_source, None);
        assert_eq!(result.pending_source, None);
        assert_eq!(
            result.admission.expect("card is admitted").root().version,
            after.version
        );
    }
    assert!(matches!(
        owner.execute_mutation_with_precondition_for_isolated_tests(&batch, &precondition),
        Err(MutationError::ConcurrentModification)
    ));
    assert_eq!(owner.handle().metadata().unwrap(), after);
}

// memory—v1: A single version confirmation applies to every existing binding.
#[test]
fn batch_b_one_change_confirmation_covers_all_existing_bindings() {
    let test_name = "batch_b_one_change_confirmation_covers_all_existing_bindings";
    if std::env::var_os(CHILD_ENV).is_none() {
        run_isolated(test_name);
        return;
    }

    let (mut rows, selections) = batch_fixture();
    rows.user_cards.push(UserCardRow {
        user_card_id: id(5),
        user_id: id(1),
        tenant_id: id(3),
        status: UserCardStatus::Active,
    });
    rows.bindings.push(binding(
        21,
        5,
        10,
        BindingLayer::Base,
        MemoryV1OwnerScope::SelfUser,
        MemoryV1TenantScope::SelfTenant,
    ));
    rows.binding_confirmations
        .push(binding_confirmation(121, 21, 10, None));
    rows.rule_set_change_confirmations
        .push(change_confirmation(220, 10, vec![1], None));
    let owner = serving_owner(rows, selections);
    let authority = MemoryV1SessionAuthority::new();
    authority
        .bind_to_root(&owner)
        .expect("session authority binds to the fixture root");
    let target_tenant = id(3);
    let target_owner = id(1);
    for card in [4, 5] {
        assert_eq!(
            evaluate(
                &owner,
                &authority,
                identity(card, 3),
                Some(&target_tenant),
                Some(&target_owner),
            )
            .decision,
            MemoryV1Decision::Allow
        );
    }

    let before = owner
        .handle()
        .metadata()
        .expect("root metadata is readable");
    let precondition = MutationPrecondition {
        evaluated_root_version: before.version,
    };
    let content = br#"{"rules":[{"ruleId":"new-deny","resource":"document","action":"read","effect":"DENY"}]}"#;
    let mut new_version = version(10, content);
    new_version.version_bytes = vec![2];
    new_version.hash_input_bytes = canonical_version_bytes(
        &new_version.version_bytes,
        &new_version.content_bytes,
        &new_version.timestamp_bytes,
    );
    new_version.hash_bytes = version_digest(&new_version.hash_input_bytes);

    let publish = |confirmation| ManagementMutationV2::VersionPublish {
        rule_set_id: id(10),
        version_row: new_version.clone(),
        new_current_version: vec![2],
        change_confirmation: confirmation,
    };
    assert!(owner
        .execute_mutation_with_precondition_for_isolated_tests(
            &publish(change_confirmation(221, 10, vec![1], None)),
            &precondition,
        )
        .is_err());
    assert_eq!(owner.handle().metadata().unwrap(), before);
    for card in [4, 5] {
        assert_eq!(
            evaluate(
                &owner,
                &authority,
                identity(card, 3),
                Some(&target_tenant),
                Some(&target_owner),
            )
            .decision,
            MemoryV1Decision::Allow
        );
    }

    let mutation = publish(change_confirmation(221, 10, vec![2], None));
    let after = owner
        .execute_mutation_with_precondition_for_isolated_tests(&mutation, &precondition)
        .expect("one matching confirmation publishes the new version");
    assert_eq!(after.version, before.version + 1);
    assert_ne!(after.digest, before.digest);
    assert!(matches!(
        owner.execute_mutation_with_precondition_for_isolated_tests(&mutation, &precondition),
        Err(MutationError::ConcurrentModification)
    ));
    for card in [4, 5] {
        let observed = owner
            .handle()
            .read_card(id(card), |context| {
                let binding = &context.bindings[0];
                (
                    binding.selected.unwrap().version_bytes.clone(),
                    binding.confirmations.len(),
                    binding.confirmations[0].version_bytes.clone(),
                )
            })
            .expect("the existing binding remains readable");
        assert_eq!(observed.value, (vec![2], 1, vec![1]));
        let decision = evaluate(
            &owner,
            &authority,
            identity(card, 3),
            Some(&target_tenant),
            Some(&target_owner),
        );
        assert_eq!(decision.decision, MemoryV1Decision::Deny);
        assert_eq!(decision.deny_source, Some(MemoryV1DenySource::RuleDenied));
    }
}

fn first_version_fixture() -> (
    RootOwner,
    RuleSetRow,
    RuleSetVersionRow,
    MutationPrecondition,
) {
    let rows = CandidateRows {
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
        ..CandidateRows::default()
    };
    let owner = install_process_root(rows, Vec::new(), budget()).expect("empty root installs");
    owner
        .install_registry(&[RegistryDeclaration {
            resource: "document".to_owned(),
            actions: vec!["read".to_owned()],
        }])
        .expect("registry installs before creating a rule-set version");
    let rule_set = RuleSetRow {
        status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
        rule_set_id: id(50),
        owner_tenant_id: id(3),
        current_version_bytes: vec![1],
    };
    let version_row = version(
        50,
        br#"{"rules":[{"ruleId":"first","resource":"document","action":"read","effect":"ALLOW"}]}"#,
    );
    (
        owner,
        rule_set,
        version_row,
        MutationPrecondition {
            evaluated_root_version: 0,
        },
    )
}

fn execute_first_version(
    owner: &RootOwner,
    rule_set: &RuleSetRow,
    version_row: &RuleSetVersionRow,
    confirmation: RuleSetChangeConfirmationRow,
    precondition: &MutationPrecondition,
) -> Result<astral_authorization_root::memory_v1_root::RootMetadata, MutationError> {
    owner.execute_mutation_with_precondition(
        &ManagementMutationV2::RuleSetCreate {
            rule_set: rule_set.clone(),
            version: version_row.clone(),
            change_confirmation: confirmation,
        },
        precondition,
    )
}

fn assert_initial_change_scenario(scenario: &str) {
    let (owner, rule_set, version_row, precondition) = first_version_fixture();
    let before = owner.handle().metadata().expect("metadata is readable");
    assert_eq!(before.version, 0);

    match scenario {
        "missing" => {
            // The mutation surface has no Option hole: an absent confirmation is
            // represented by an unconstructible/structurally empty confirmation.
            let mut missing = change_confirmation(230, 50, vec![1], None);
            missing.confirmer_user_id = [0; 16];
            missing.affected_scope_bytes.clear();
            assert!(matches!(
                execute_first_version(&owner, &rule_set, &version_row, missing, &precondition,),
                Err(MutationError::Candidate(CandidateError::Rows(
                    ValidationError::MissingReference {
                        table: Table::RuleSetChangeConfirmation,
                        ..
                    }
                )))
            ));
        }
        "wrong-version" => {
            let wrong = change_confirmation(231, 50, vec![9], None);
            assert!(matches!(
                execute_first_version(
                    &owner,
                    &rule_set,
                    &version_row,
                    wrong,
                    &precondition,
                ),
                Err(MutationError::Candidate(CandidateError::Rows(
                    ValidationError::MissingVersionReference {
                        table: Table::RuleSetChangeConfirmation,
                        rule_set_id,
                        version_bytes,
                    }
                ))) if rule_set_id == id(50) && version_bytes == vec![9]
            ));
        }
        "revoked" => {
            let revoked = change_confirmation(232, 50, vec![1], Some(100));
            assert!(
                execute_first_version(&owner, &rule_set, &version_row, revoked, &precondition,)
                    .is_err(),
                "a revoked first-version confirmation must fail closed"
            );
        }
        "exact" => {
            let exact = change_confirmation(233, 50, vec![1], None);
            let published =
                execute_first_version(&owner, &rule_set, &version_row, exact, &precondition)
                    .expect("the exact active confirmation permits first-version creation");
            assert_eq!(published.version, 1);
            assert_eq!(
                owner
                    .handle()
                    .metadata()
                    .expect("metadata is readable")
                    .version,
                1
            );
            assert!(owner
                .handle()
                .read_impact(id(50))
                .expect("the new rule set is present")
                .value
                .binding_ids
                .is_empty());
        }
        other => panic!("unknown change-confirmation scenario: {other}"),
    }

    if scenario != "exact" {
        assert_eq!(
            owner
                .handle()
                .metadata()
                .expect("metadata is readable")
                .version,
            before.version,
            "rejected first-version confirmation must not publish a root snapshot"
        );
    }
}

#[test]
fn batch_b_initial_change_confirmation_is_fail_closed_and_exact_allows() {
    if let Some(scenario) = std::env::var_os(CHANGE_SCENARIO_ENV) {
        assert_initial_change_scenario(scenario.to_str().expect("scenario marker is valid UTF-8"));
        return;
    }

    let test_name = "batch_b_initial_change_confirmation_is_fail_closed_and_exact_allows";
    for scenario in ["missing", "wrong-version", "revoked", "exact"] {
        let output = Command::new(std::env::current_exe().expect("test executable is available"))
            .args(["--exact", test_name, "--nocapture"])
            .env(CHILD_ENV, "1")
            .env(CHANGE_SCENARIO_ENV, scenario)
            .output()
            .expect("failed to start isolated change-confirmation scenario");
        assert!(
            output.status.success(),
            "scenario {scenario} failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "scenario {scenario} did not report one passing test\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

const BATCH_TARGET_SCENARIO_ENV: &str = "ASTRAL_MEMORY_V1_BATCH_B_TARGET_SCENARIO";
const BATCH_OPERATION_ID: &[u8] = b"batch-confirmation-operation";
const BATCH_OPERATION_FINGERPRINT: &[u8] =
    b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

// memory—v1: Build a serving root with one confirming card and several proposed
// confirmation targets. Target bindings carry revoked historical confirmations,
// so a new confirmation ID is structurally available for the valid cases.
fn confirmation_batch_fixture() -> (CandidateRows, Vec<CurrentSelection>) {
    let governance = br#"{"rules":[{"ruleId":"confirm","resource":"binding","action":"confirm","effect":"ALLOW","ownerScope":"all","tenantScope":"self+descendants"}]}"#;
    let empty = br#"{"rules":[]}"#;
    let rows = CandidateRows {
        users: (1..=4)
            .map(|user_id| UserRow {
                user_id: id(user_id),
            })
            .collect(),
        identity_cards: vec![
            IdentityCardRow {
                identity_card_id: id(2),
                user_id: id(1),
            },
            IdentityCardRow {
                identity_card_id: id(5),
                user_id: id(2),
            },
            IdentityCardRow {
                identity_card_id: id(6),
                user_id: id(3),
            },
            IdentityCardRow {
                identity_card_id: id(7),
                user_id: id(4),
            },
        ],
        tenants: vec![
            TenantRow {
                tenant_id: id(3),
                parent_tenant_id: None,
            },
            TenantRow {
                tenant_id: id(99),
                parent_tenant_id: None,
            },
        ],
        user_cards: vec![
            UserCardRow {
                user_card_id: id(4),
                user_id: id(1),
                tenant_id: id(3),
                status: UserCardStatus::Active,
            },
            UserCardRow {
                user_card_id: id(5),
                user_id: id(2),
                tenant_id: id(3),
                status: UserCardStatus::Active,
            },
            UserCardRow {
                user_card_id: id(6),
                user_id: id(3),
                tenant_id: id(3),
                status: UserCardStatus::Active,
            },
            UserCardRow {
                user_card_id: id(7),
                user_id: id(4),
                tenant_id: id(99),
                status: UserCardStatus::Active,
            },
        ],
        rule_sets: (10..=14)
            .map(|rule_set_id| RuleSetRow {
                status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
                rule_set_id: id(rule_set_id),
                owner_tenant_id: if rule_set_id == 14 { id(99) } else { id(3) },
                current_version_bytes: vec![1],
            })
            .collect(),
        rule_set_versions: vec![
            version(10, governance),
            version(11, empty),
            version(12, empty),
            version(13, empty),
            version(14, empty),
        ],
        bindings: vec![
            binding(
                20,
                4,
                10,
                BindingLayer::Base,
                MemoryV1OwnerScope::AllUsers,
                MemoryV1TenantScope::SelfAndDescendants,
            ),
            binding(
                21,
                5,
                11,
                BindingLayer::Base,
                MemoryV1OwnerScope::SelfUser,
                MemoryV1TenantScope::SelfTenant,
            ),
            binding(
                22,
                6,
                12,
                BindingLayer::Base,
                MemoryV1OwnerScope::SelfUser,
                MemoryV1TenantScope::SelfTenant,
            ),
            binding(
                23,
                4,
                13,
                BindingLayer::Overlay,
                MemoryV1OwnerScope::SelfUser,
                MemoryV1TenantScope::SelfTenant,
            ),
            binding(
                24,
                7,
                14,
                BindingLayer::Base,
                MemoryV1OwnerScope::SelfUser,
                MemoryV1TenantScope::SelfTenant,
            ),
        ],
        binding_confirmations: vec![
            binding_confirmation(120, 20, 10, None),
            binding_confirmation(121, 21, 11, Some(100)),
            binding_confirmation(122, 22, 12, Some(100)),
            binding_confirmation(123, 23, 13, Some(100)),
            binding_confirmation(124, 24, 14, Some(100)),
        ],
        rule_set_change_confirmations: (10..=14)
            .map(|rule_set_id| change_confirmation(200 + rule_set_id, rule_set_id, vec![1], None))
            .collect(),
    };
    (
        rows,
        (10..=14)
            .map(|rule_set_id| CurrentSelection {
                rule_set_id: id(rule_set_id),
                version_bytes: vec![1],
            })
            .collect(),
    )
}

// memory—v1: Install the batch-specific registry before adopting its isolated
// serving root; no listener, database, or external service is involved.
fn confirmation_serving_owner(rows: CandidateRows, selections: Vec<CurrentSelection>) -> RootOwner {
    let owner = install_process_root(rows, selections, budget()).expect("candidate root installs");
    owner
        .install_registry(&[RegistryDeclaration {
            resource: "binding".to_owned(),
            actions: vec!["confirm".to_owned()],
        }])
        .expect("batch registry installs once");
    owner
        .adopt_serving_for_isolated_tests()
        .expect("batch fixture is structurally serving-ready");
    owner
}

// memory—v1: Evaluate the public batch entry with a fresh request root and
// authority-bound session for every assertion.
fn evaluate_batch_with(
    owner: &RootOwner,
    authority: &MemoryV1SessionAuthority,
    principal: CandidateIdentity,
    request: &MemoryV1BatchRequest<'_>,
) -> MemoryV1BatchEvaluation {
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let session = session_for(authority, &root, principal);
    PolicyEngine::new().evaluate_memory_v1_confirmation_batch(&root, &session, request)
}

// memory—v1: Use only request correlation values accepted by the batch contract.
fn evaluate_confirmation_batch(
    owner: &RootOwner,
    authority: &MemoryV1SessionAuthority,
    principal: CandidateIdentity,
    items: &[MemoryV1BatchItem],
) -> MemoryV1BatchEvaluation {
    let request = MemoryV1BatchRequest {
        operation_id: BATCH_OPERATION_ID,
        operation_fingerprint: BATCH_OPERATION_FINGERPRINT,
        items,
    };
    evaluate_batch_with(owner, authority, principal, &request)
}

// memory—v1: Assert that a batch has no transferable admission on a pending path.
fn assert_batch_pending(result: MemoryV1BatchEvaluation) {
    assert_eq!(result.decision, MemoryV1Decision::Pending);
    assert_eq!(
        result.pending_source,
        Some(MemoryV1PendingSource::ContextInvalid)
    );
    assert!(result.deny_source.is_none());
    assert!(result.admission.is_none());
    assert!(result.deny_observation.is_none());
}

// memory—v1 §4.11 N-10: A valid batch preserves caller order and derives every
// target attribution from the root while returning one read-side admission.
#[test]
fn batch_b_confirmation_evaluator_allows_ordered_multi_target_batch() {
    let test_name = "batch_b_confirmation_evaluator_allows_ordered_multi_target_batch";
    if std::env::var_os(CHILD_ENV).is_none() {
        run_isolated(test_name);
        return;
    }

    let (rows, selections) = confirmation_batch_fixture();
    let owner = confirmation_serving_owner(rows, selections);
    let authority = MemoryV1SessionAuthority::new();
    authority
        .bind_to_root(&owner)
        .expect("batch authority binds to root");
    let items = [
        MemoryV1BatchItem {
            sequence: 0,
            binding_id: id(21),
            confirmation_id: id(150),
        },
        MemoryV1BatchItem {
            sequence: 1,
            binding_id: id(22),
            confirmation_id: id(151),
        },
    ];

    let result = evaluate_confirmation_batch(&owner, &authority, identity(4, 3), &items);
    assert_eq!(result.decision, MemoryV1Decision::Allow);
    assert!(result.deny_source.is_none());
    assert!(result.pending_source.is_none());
    let admission = result.admission.expect("valid batch carries an admission");
    assert_eq!(
        admission.root().status,
        astral_authorization_root::memory_v1_root::RootStatus::Serving
    );
    assert_eq!(admission.identity(), identity(4, 3));
    assert_eq!(admission.operation_id(), BATCH_OPERATION_ID);
    assert_eq!(
        admission.operation_fingerprint(),
        BATCH_OPERATION_FINGERPRINT
    );
    assert!(admission.trusted_time_unix_seconds() > 0);
    assert_eq!(admission.targets().len(), 2);
    assert_eq!(admission.targets()[0].item, items[0]);
    assert_eq!(admission.targets()[0].user_card_id, id(5));
    assert_eq!(admission.targets()[0].rule_set_id, id(11));
    assert_eq!(admission.targets()[0].beneficiary_user_id, id(2));
    assert_eq!(admission.targets()[0].tenant_id, id(3));
    assert_eq!(admission.targets()[1].item, items[1]);
    assert_eq!(admission.targets()[1].user_card_id, id(6));
    assert_eq!(admission.targets()[1].rule_set_id, id(12));
    assert_eq!(admission.targets()[1].beneficiary_user_id, id(3));
    assert_eq!(admission.targets()[1].tenant_id, id(3));
}

// memory—v1 §4.11 N-10: One target without the actor's confirmation scope
// rejects the complete batch, even when another target is otherwise eligible.
#[test]
fn batch_b_confirmation_evaluator_denies_when_one_target_lacks_qualification() {
    let test_name = "batch_b_confirmation_evaluator_denies_when_one_target_lacks_qualification";
    if std::env::var_os(CHILD_ENV).is_none() {
        run_isolated(test_name);
        return;
    }

    let (rows, selections) = confirmation_batch_fixture();
    let owner = confirmation_serving_owner(rows, selections);
    let authority = MemoryV1SessionAuthority::new();
    authority
        .bind_to_root(&owner)
        .expect("batch authority binds to root");
    let items = [
        MemoryV1BatchItem {
            sequence: 0,
            binding_id: id(21),
            confirmation_id: id(150),
        },
        MemoryV1BatchItem {
            sequence: 1,
            binding_id: id(24),
            confirmation_id: id(151),
        },
    ];

    let result = evaluate_confirmation_batch(&owner, &authority, identity(4, 3), &items);
    assert_eq!(result.decision, MemoryV1Decision::Deny);
    assert_eq!(result.deny_source, Some(MemoryV1DenySource::ScopeDenied));
    assert!(result.pending_source.is_none());
    assert!(result.admission.is_none());
    let observation = result
        .deny_observation
        .as_deref()
        .expect("out-of-scope item");
    assert_eq!(observation.batch_sequence(), Some(1));
    assert!(observation.affected_binding().is_none());
    assert_eq!(observation.resource(), "binding");
    assert_eq!(observation.action(), "confirm");
    assert_eq!(observation.target(), Some(id(24).as_slice()));
    assert_eq!(observation.target_tenant(), Some(id(99).as_slice()));
    assert_eq!(observation.target_owner(), Some(id(4).as_slice()));
    assert_eq!(observation.source(), MemoryV1DenySource::ScopeDenied);
    assert_eq!(observation.root(), owner.handle().metadata().unwrap());
    assert_eq!(observation.identity(), identity(4, 3));
    assert_eq!(observation.operation_id(), BATCH_OPERATION_ID);
    assert_eq!(
        observation.operation_fingerprint(),
        BATCH_OPERATION_FINGERPRINT
    );
}

// memory—v1: A proven out-of-scope target dominates a resolved structural
// conflict in either order; the conflict alone remains pending without admission.
#[test]
fn batch_b_qualification_denial_precedes_resolved_invalid_targets_in_both_orders() {
    let test_name = "batch_b_qualification_denial_precedes_resolved_invalid_targets_in_both_orders";
    if std::env::var_os(CHILD_ENV).is_none() {
        run_isolated(test_name);
        return;
    }

    let (mut rows, selections) = confirmation_batch_fixture();
    let active = rows
        .binding_confirmations
        .iter_mut()
        .find(|row| row.confirmation_id == id(121))
        .expect("target confirmation exists");
    active.revoked_at = None;
    active.revoked_by = None;
    let owner = confirmation_serving_owner(rows, selections);
    let authority = MemoryV1SessionAuthority::new();
    authority
        .bind_to_root(&owner)
        .expect("authority binds to root");

    let unqualified = MemoryV1BatchItem {
        sequence: 0,
        binding_id: id(24),
        confirmation_id: id(151),
    };
    let alone = evaluate_confirmation_batch(&owner, &authority, identity(4, 3), &[unqualified]);
    assert_eq!(alone.decision, MemoryV1Decision::Deny);
    assert_eq!(alone.deny_source, Some(MemoryV1DenySource::ScopeDenied));
    assert!(alone.pending_source.is_none());
    assert!(alone.admission.is_none());

    for (name, invalid) in [
        (
            "active confirmation",
            MemoryV1BatchItem {
                sequence: 0,
                binding_id: id(21),
                confirmation_id: id(150),
            },
        ),
        (
            "reused confirmation ID",
            MemoryV1BatchItem {
                sequence: 0,
                binding_id: id(22),
                confirmation_id: id(122),
            },
        ),
    ] {
        assert_batch_pending(evaluate_confirmation_batch(
            &owner,
            &authority,
            identity(4, 3),
            &[invalid],
        ));
        for unqualified_first in [true, false] {
            let mut items = if unqualified_first {
                [unqualified, invalid]
            } else {
                [invalid, unqualified]
            };
            items[0].sequence = 0;
            items[1].sequence = 1;
            let result = evaluate_confirmation_batch(&owner, &authority, identity(4, 3), &items);
            assert_eq!(
                result.decision,
                MemoryV1Decision::Deny,
                "{name}, unqualified_first={unqualified_first}"
            );
            assert_eq!(
                result.deny_source,
                Some(MemoryV1DenySource::ScopeDenied),
                "{name}, unqualified_first={unqualified_first}"
            );
            assert!(result.pending_source.is_none());
            assert!(result.admission.is_none());
        }
    }
}

// memory—v1: An unverified policy reference prevents treating an apparent
// scope miss as proof of ineligibility, even alongside an invalid target.
#[test]
fn batch_b_invalid_target_and_incomplete_qualification_remain_pending() {
    let test_name = "batch_b_invalid_target_and_incomplete_qualification_remain_pending";
    if std::env::var_os(CHILD_ENV).is_none() {
        run_isolated(test_name);
        return;
    }

    let (mut rows, selections) = confirmation_batch_fixture();
    rows.rule_set_versions[0] = version(10, br#"{"rules":[{"ruleId":"confirm","resource":"binding","action":"confirm","effect":"ALLOW","ownerScope":"all","tenantScope":"self+descendants"},{"ruleId":"other","resource":"other","action":"read","effect":"ALLOW"}]}"#);
    let owner = install_process_root(rows, selections, budget()).expect("candidate root installs");
    owner
        .install_registry(&[
            RegistryDeclaration {
                resource: "binding".to_owned(),
                actions: vec!["confirm".to_owned()],
            },
            RegistryDeclaration {
                resource: "other".to_owned(),
                actions: vec!["read".to_owned()],
            },
        ])
        .expect("registry installs");
    owner
        .adopt_serving_for_isolated_tests()
        .expect("fixture adopts");
    let authority = MemoryV1SessionAuthority::new();
    authority
        .bind_to_root(&owner)
        .expect("authority binds to root");
    owner
        .request_registry_retirement_for_test("other")
        .expect("policy reference becomes inactive");

    let invalid = MemoryV1BatchItem {
        sequence: 0,
        binding_id: id(21),
        confirmation_id: id(121),
    };
    let out_of_scope = MemoryV1BatchItem {
        sequence: 1,
        binding_id: id(24),
        confirmation_id: id(151),
    };
    for invalid_first in [true, false] {
        let mut items = if invalid_first {
            [invalid, out_of_scope]
        } else {
            [out_of_scope, invalid]
        };
        items[0].sequence = 0;
        items[1].sequence = 1;
        assert_batch_pending(evaluate_confirmation_batch(
            &owner,
            &authority,
            identity(4, 3),
            &items,
        ));
    }
}

// memory—v1 §4.11 N-7/N-10: A self-beneficiary anywhere in the batch is a
// deterministic whole-batch denial, regardless of the other target's result.
#[test]
fn batch_b_confirmation_evaluator_denies_any_self_signed_target() {
    let test_name = "batch_b_confirmation_evaluator_denies_any_self_signed_target";
    if std::env::var_os(CHILD_ENV).is_none() {
        run_isolated(test_name);
        return;
    }

    let (rows, selections) = confirmation_batch_fixture();
    let owner = confirmation_serving_owner(rows, selections);
    let authority = MemoryV1SessionAuthority::new();
    authority
        .bind_to_root(&owner)
        .expect("batch authority binds to root");
    let items = [
        MemoryV1BatchItem {
            sequence: 0,
            binding_id: id(21),
            confirmation_id: id(150),
        },
        MemoryV1BatchItem {
            sequence: 1,
            binding_id: id(23),
            confirmation_id: id(151),
        },
    ];

    let result = evaluate_confirmation_batch(&owner, &authority, identity(4, 3), &items);
    assert_eq!(result.decision, MemoryV1Decision::Deny);
    assert_eq!(
        result.deny_source,
        Some(MemoryV1DenySource::SelfConfirmation)
    );
    assert!(result.pending_source.is_none());
    assert!(result.admission.is_none());
}

// memory—v1: A resolved self-confirmation dominates another resolved invalid
// target, and also dominates an unknown binding; an unknown binding alone or
// beside a legal target remains pending.
#[test]
fn batch_b_self_confirmation_precedes_resolved_invalid_targets_in_both_orders() {
    let test_name = "batch_b_self_confirmation_precedes_resolved_invalid_targets_in_both_orders";
    if std::env::var_os(CHILD_ENV).is_none() {
        run_isolated(test_name);
        return;
    }
    let (mut rows, selections) = confirmation_batch_fixture();
    let active = rows
        .binding_confirmations
        .iter_mut()
        .find(|row| row.confirmation_id == id(121))
        .expect("target confirmation exists");
    active.revoked_at = None;
    active.revoked_by = None;
    let owner = confirmation_serving_owner(rows, selections);
    let authority = MemoryV1SessionAuthority::new();
    authority
        .bind_to_root(&owner)
        .expect("authority binds to root");

    let self_target = MemoryV1BatchItem {
        sequence: 0,
        binding_id: id(23),
        confirmation_id: id(151),
    };
    for (name, invalid) in [
        (
            "active confirmation",
            MemoryV1BatchItem {
                sequence: 0,
                binding_id: id(21),
                confirmation_id: id(150),
            },
        ),
        (
            "reused confirmation ID",
            MemoryV1BatchItem {
                sequence: 0,
                binding_id: id(22),
                confirmation_id: id(121),
            },
        ),
    ] {
        assert_batch_pending(evaluate_confirmation_batch(
            &owner,
            &authority,
            identity(4, 3),
            std::slice::from_ref(&invalid),
        ));
        for self_first in [true, false] {
            let mut items = if self_first {
                [self_target, invalid]
            } else {
                [invalid, self_target]
            };
            items[0].sequence = 0;
            items[1].sequence = 1;
            let result = evaluate_confirmation_batch(&owner, &authority, identity(4, 3), &items);
            assert_eq!(
                result.decision,
                MemoryV1Decision::Deny,
                "{name}, self_first={self_first}"
            );
            assert_eq!(
                result.deny_source,
                Some(MemoryV1DenySource::SelfConfirmation),
                "{name}, self_first={self_first}"
            );
            assert!(result.pending_source.is_none());
            assert!(result.admission.is_none());
            let observation = result.deny_observation.as_deref().expect("self target");
            assert_eq!(
                observation.batch_sequence(),
                Some(if self_first { 0 } else { 1 })
            );
            assert_eq!(observation.target(), Some(id(23).as_slice()));
            assert_eq!(observation.source(), MemoryV1DenySource::SelfConfirmation);
        }
    }
    let unknown = MemoryV1BatchItem {
        sequence: 0,
        binding_id: id(250),
        confirmation_id: id(150),
    };
    assert_batch_pending(evaluate_confirmation_batch(
        &owner,
        &authority,
        identity(4, 3),
        std::slice::from_ref(&unknown),
    ));

    let legal = MemoryV1BatchItem {
        sequence: 0,
        binding_id: id(21),
        confirmation_id: id(150),
    };
    for unknown_first in [true, false] {
        let mut items = if unknown_first {
            [unknown, legal]
        } else {
            [legal, unknown]
        };
        items[0].sequence = 0;
        items[1].sequence = 1;
        assert_batch_pending(evaluate_confirmation_batch(
            &owner,
            &authority,
            identity(4, 3),
            &items,
        ));
    }

    for self_first in [true, false] {
        let mut items = if self_first {
            [self_target, unknown]
        } else {
            [unknown, self_target]
        };
        items[0].sequence = 0;
        items[1].sequence = 1;
        let result = evaluate_confirmation_batch(&owner, &authority, identity(4, 3), &items);
        assert_eq!(
            result.decision,
            MemoryV1Decision::Deny,
            "unknown binding, self_first={self_first}"
        );
        assert_eq!(
            result.deny_source,
            Some(MemoryV1DenySource::SelfConfirmation),
            "unknown binding, self_first={self_first}"
        );
        assert!(result.pending_source.is_none());
        assert!(result.admission.is_none());
        let observation = result.deny_observation.as_deref().expect("self target");
        assert_eq!(
            observation.batch_sequence(),
            Some(if self_first { 0 } else { 1 })
        );
        assert_eq!(observation.target(), Some(id(23).as_slice()));
        assert_eq!(observation.source(), MemoryV1DenySource::SelfConfirmation);
    }
}

// memory—v1 §4.11 N-6/N-10: A proposed confirmation is pending when its
// binding or confirmation identity is unavailable, revoked, removed, active,
// or attached to a disabled target card.
#[test]
fn batch_b_confirmation_evaluator_pending_for_unavailable_targets() {
    if let Some(scenario) = std::env::var_os(BATCH_TARGET_SCENARIO_ENV) {
        let scenario = scenario.to_str().expect("target scenario is valid UTF-8");
        let (mut rows, selections) = confirmation_batch_fixture();
        match scenario {
            "removed-binding" => {
                let binding = rows
                    .bindings
                    .iter_mut()
                    .find(|row| row.binding_id == id(21))
                    .expect("target binding exists");
                binding.removed_at = Some(100);
                binding.removed_by = Some(id(1));
            }
            "active-confirmation" => {
                let confirmation = rows
                    .binding_confirmations
                    .iter_mut()
                    .find(|row| row.confirmation_id == id(121))
                    .expect("target confirmation exists");
                confirmation.revoked_at = None;
                confirmation.revoked_by = None;
            }
            "disabled-card" => {}
            "unknown-binding" | "reused-confirmation" => {}
            other => panic!("unknown target scenario: {other}"),
        }
        let owner = confirmation_serving_owner(rows, selections);
        let authority = MemoryV1SessionAuthority::new();
        authority
            .bind_to_root(&owner)
            .expect("batch authority binds to root");
        if scenario == "disabled-card" {
            let before = owner
                .handle()
                .metadata()
                .expect("root metadata is readable before card disable");
            authority
                .disable_card_with_sessions_for_isolated_tests(
                    &owner.mutation_executor(),
                    MemoryId::from_bytes(id(5)),
                    before,
                )
                .expect("bound authority disables the target card");
        }
        let item = match scenario {
            "unknown-binding" => MemoryV1BatchItem {
                sequence: 0,
                binding_id: id(250),
                confirmation_id: id(150),
            },
            "reused-confirmation" => MemoryV1BatchItem {
                sequence: 0,
                binding_id: id(21),
                confirmation_id: id(121),
            },
            _ => MemoryV1BatchItem {
                sequence: 0,
                binding_id: id(21),
                confirmation_id: id(150),
            },
        };
        assert_batch_pending(evaluate_confirmation_batch(
            &owner,
            &authority,
            identity(4, 3),
            std::slice::from_ref(&item),
        ));
        return;
    }

    let test_name = "batch_b_confirmation_evaluator_pending_for_unavailable_targets";
    for scenario in [
        "unknown-binding",
        "removed-binding",
        "active-confirmation",
        "reused-confirmation",
        "disabled-card",
    ] {
        let output = Command::new(std::env::current_exe().expect("test executable is available"))
            .args(["--exact", test_name, "--nocapture"])
            .env(CHILD_ENV, "1")
            .env(BATCH_TARGET_SCENARIO_ENV, scenario)
            .output()
            .expect("failed to start isolated target scenario");
        assert!(
            output.status.success(),
            "scenario {scenario} failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "scenario {scenario} did not report one passing test\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

// memory—v1 §4.11 N-10: Ordered sequence, unique target IDs, and the local
// maximum are request-shape gates that fail closed before target evaluation.
#[test]
fn batch_b_confirmation_evaluator_rejects_order_duplicates_and_oversize() {
    let test_name = "batch_b_confirmation_evaluator_rejects_order_duplicates_and_oversize";
    if std::env::var_os(CHILD_ENV).is_none() {
        run_isolated(test_name);
        return;
    }

    let (rows, selections) = confirmation_batch_fixture();
    let owner = confirmation_serving_owner(rows, selections);
    let authority = MemoryV1SessionAuthority::new();
    authority
        .bind_to_root(&owner)
        .expect("batch authority binds to root");

    let wrong_sequence = [
        MemoryV1BatchItem {
            sequence: 1,
            binding_id: id(21),
            confirmation_id: id(150),
        },
        MemoryV1BatchItem {
            sequence: 2,
            binding_id: id(22),
            confirmation_id: id(151),
        },
    ];
    assert_batch_pending(evaluate_confirmation_batch(
        &owner,
        &authority,
        identity(4, 3),
        &wrong_sequence,
    ));

    let duplicate_binding = [
        MemoryV1BatchItem {
            sequence: 0,
            binding_id: id(21),
            confirmation_id: id(150),
        },
        MemoryV1BatchItem {
            sequence: 1,
            binding_id: id(21),
            confirmation_id: id(151),
        },
    ];
    assert_batch_pending(evaluate_confirmation_batch(
        &owner,
        &authority,
        identity(4, 3),
        &duplicate_binding,
    ));

    let duplicate_confirmation = [
        MemoryV1BatchItem {
            sequence: 0,
            binding_id: id(21),
            confirmation_id: id(150),
        },
        MemoryV1BatchItem {
            sequence: 1,
            binding_id: id(22),
            confirmation_id: id(150),
        },
    ];
    assert_batch_pending(evaluate_confirmation_batch(
        &owner,
        &authority,
        identity(4, 3),
        &duplicate_confirmation,
    ));

    let oversized: Vec<_> = (0..=MAX_MEMORY_V1_BINDING_CONFIRMATION_BATCH)
        .map(|sequence| MemoryV1BatchItem {
            sequence: sequence as u32,
            binding_id: id(sequence as u8),
            confirmation_id: id((sequence as u8).wrapping_add(100)),
        })
        .collect();
    assert_batch_pending(evaluate_confirmation_batch(
        &owner,
        &authority,
        identity(4, 3),
        &oversized,
    ));
}

// memory—v1 §4.6/N-10: An active fence on any target rule set makes the whole
// batch pending; after a fresh request phase observes the released fence it can
// evaluate normally.
#[test]
fn batch_b_confirmation_evaluator_respects_target_rule_set_fence() {
    let test_name = "batch_b_confirmation_evaluator_respects_target_rule_set_fence";
    if std::env::var_os(CHILD_ENV).is_none() {
        run_isolated(test_name);
        return;
    }

    let (rows, selections) = confirmation_batch_fixture();
    let owner = confirmation_serving_owner(rows, selections);
    let authority = MemoryV1SessionAuthority::new();
    authority
        .bind_to_root(&owner)
        .expect("batch authority binds to root");
    let items = [
        MemoryV1BatchItem {
            sequence: 0,
            binding_id: id(21),
            confirmation_id: id(150),
        },
        MemoryV1BatchItem {
            sequence: 1,
            binding_id: id(22),
            confirmation_id: id(151),
        },
    ];
    let before = evaluate_confirmation_batch(&owner, &authority, identity(4, 3), &items);
    assert_eq!(before.decision, MemoryV1Decision::Allow);
    assert!(before.admission.is_some());

    for rule_set in [11, 12] {
        let metadata = owner
            .handle()
            .metadata()
            .expect("root metadata is readable");
        owner
            .begin_modification_fence(
                id(rule_set),
                &astral_authorization_root::memory_v1_fence::FenceDeclaration {
                    rule_set_version: vec![1],
                    root_version: metadata.version,
                    digest: metadata.digest,
                },
            )
            .expect("target rule set fence opens");

        let fenced = evaluate_confirmation_batch(&owner, &authority, identity(4, 3), &items);
        assert_eq!(fenced.decision, MemoryV1Decision::Pending);
        assert_eq!(
            fenced.pending_source,
            Some(MemoryV1PendingSource::FenceActive)
        );
        assert!(fenced.deny_source.is_none());
        assert!(fenced.admission.is_none());

        owner
            .abort_modification_fence(id(rule_set))
            .expect("target rule set fence closes");
        let released = evaluate_confirmation_batch(&owner, &authority, identity(4, 3), &items);
        assert_eq!(released.decision, MemoryV1Decision::Allow);
        assert!(released.admission.is_some());
    }
}

// memory—v1: Correlation fields are checked before any batch can be admitted.
#[test]
fn batch_b_confirmation_evaluator_validates_correlation_shape() {
    let test_name = "batch_b_confirmation_evaluator_validates_correlation_shape";
    if std::env::var_os(CHILD_ENV).is_none() {
        run_isolated(test_name);
        return;
    }

    let (rows, selections) = confirmation_batch_fixture();
    let owner = confirmation_serving_owner(rows, selections);
    let authority = MemoryV1SessionAuthority::new();
    authority
        .bind_to_root(&owner)
        .expect("authority binds to root");
    let items = [
        MemoryV1BatchItem {
            sequence: 0,
            binding_id: id(21),
            confirmation_id: id(150),
        },
        MemoryV1BatchItem {
            sequence: 1,
            binding_id: id(22),
            confirmation_id: id(151),
        },
    ];
    let long_id = vec![b'a'; 65];
    let short_fingerprint = vec![b'a'; 63];
    let long_fingerprint = vec![b'a'; 65];
    let upper_fingerprint = vec![b'A'; 64];
    let non_hex_fingerprint = vec![b'g'; 64];
    let binary_fingerprint = vec![0xff; 64];
    let cases: &[(&str, &[u8], &[u8])] = &[
        ("empty id", b"", BATCH_OPERATION_FINGERPRINT),
        ("oversized id", &long_id, BATCH_OPERATION_FINGERPRINT),
        ("space in id", b"bad id", BATCH_OPERATION_FINGERPRINT),
        ("newline in id", b"bad\nid", BATCH_OPERATION_FINGERPRINT),
        ("non-ascii id", b"bad\xffid", BATCH_OPERATION_FINGERPRINT),
        ("empty fingerprint", BATCH_OPERATION_ID, b""),
        ("short fingerprint", BATCH_OPERATION_ID, &short_fingerprint),
        ("long fingerprint", BATCH_OPERATION_ID, &long_fingerprint),
        (
            "uppercase fingerprint",
            BATCH_OPERATION_ID,
            &upper_fingerprint,
        ),
        (
            "non-hex fingerprint",
            BATCH_OPERATION_ID,
            &non_hex_fingerprint,
        ),
        (
            "binary fingerprint",
            BATCH_OPERATION_ID,
            &binary_fingerprint,
        ),
    ];
    for &(name, operation_id, operation_fingerprint) in cases {
        let request = MemoryV1BatchRequest {
            operation_id,
            operation_fingerprint,
            items: &items,
        };
        let result = evaluate_batch_with(&owner, &authority, identity(4, 3), &request);
        assert_eq!(result.decision, MemoryV1Decision::Pending, "{name}");
        assert_eq!(
            result.pending_source,
            Some(MemoryV1PendingSource::ContextInvalid),
            "{name}"
        );
        assert!(result.deny_source.is_none(), "{name}");
        assert!(result.admission.is_none(), "{name}");
    }

    let max_id = vec![b'z'; 64];
    for operation_id in [b"A0-_.:/".as_slice(), max_id.as_slice()] {
        let request = MemoryV1BatchRequest {
            operation_id,
            operation_fingerprint: BATCH_OPERATION_FINGERPRINT,
            items: &items,
        };
        let result = evaluate_batch_with(&owner, &authority, identity(4, 3), &request);
        assert_eq!(result.decision, MemoryV1Decision::Allow);
        let admission = result
            .admission
            .expect("valid boundary request is admitted");
        assert_eq!(admission.operation_id(), operation_id);
        assert_eq!(
            admission.operation_fingerprint(),
            BATCH_OPERATION_FINGERPRINT
        );
    }
}

// memory—v1: A previously bound session is rechecked after a completed revoke.
#[test]
fn batch_b_confirmation_evaluator_rechecks_revoked_session() {
    let test_name = "batch_b_confirmation_evaluator_rechecks_revoked_session";
    if std::env::var_os(CHILD_ENV).is_none() {
        run_isolated(test_name);
        return;
    }
    let (rows, selections) = confirmation_batch_fixture();
    let owner = confirmation_serving_owner(rows, selections);
    let authority = MemoryV1SessionAuthority::new();
    authority
        .bind_to_root(&owner)
        .expect("authority binds to root");
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let adapter = authority.identity_session_adapter();
    let issued = adapter
        .issue_unchecked_for_test(identity(4, 3), now() - 60, 3_600)
        .expect("session issues");
    let session = authority
        .verifier()
        .verify_and_bind(issued.credential(), now(), &root)
        .expect("session binds");
    let items = [MemoryV1BatchItem {
        sequence: 0,
        binding_id: id(21),
        confirmation_id: id(150),
    }];
    let request = MemoryV1BatchRequest {
        operation_id: BATCH_OPERATION_ID,
        operation_fingerprint: BATCH_OPERATION_FINGERPRINT,
        items: &items,
    };
    let engine = PolicyEngine::new();
    let before = engine.evaluate_memory_v1_confirmation_batch(&root, &session, &request);
    assert_eq!(before.decision, MemoryV1Decision::Allow);
    assert!(before.admission.is_some());
    adapter
        .revoke(issued.credential())
        .expect("session revoked");
    assert_batch_pending(engine.evaluate_memory_v1_confirmation_batch(&root, &session, &request));
    assert!(authority
        .verifier()
        .verify_and_bind(issued.credential(), now(), &root)
        .is_err());
}

// memory—v1: Target disable invalidates the old phase and remains invalid for a fresh request.
#[test]
fn batch_b_confirmation_evaluator_rechecks_target_after_root_change() {
    let test_name = "batch_b_confirmation_evaluator_rechecks_target_after_root_change";
    if std::env::var_os(CHILD_ENV).is_none() {
        run_isolated(test_name);
        return;
    }
    let (rows, selections) = confirmation_batch_fixture();
    let owner = confirmation_serving_owner(rows, selections);
    let authority = MemoryV1SessionAuthority::new();
    authority
        .bind_to_root(&owner)
        .expect("authority binds to root");
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let session = session_for(&authority, &root, identity(4, 3));
    let items = [
        MemoryV1BatchItem {
            sequence: 0,
            binding_id: id(21),
            confirmation_id: id(150),
        },
        MemoryV1BatchItem {
            sequence: 1,
            binding_id: id(22),
            confirmation_id: id(151),
        },
    ];
    let request = MemoryV1BatchRequest {
        operation_id: BATCH_OPERATION_ID,
        operation_fingerprint: BATCH_OPERATION_FINGERPRINT,
        items: &items,
    };
    let engine = PolicyEngine::new();
    let before = engine.evaluate_memory_v1_confirmation_batch(&root, &session, &request);
    assert_eq!(before.decision, MemoryV1Decision::Allow);
    assert!(before.admission.is_some());
    let metadata = owner.handle().metadata().expect("root metadata available");
    authority
        .disable_card_with_sessions_for_isolated_tests(
            &owner.mutation_executor(),
            MemoryId::from_bytes(id(5)),
            metadata,
        )
        .expect("target card disabled");
    let after = owner
        .handle()
        .metadata()
        .expect("updated root metadata available");
    assert_ne!(metadata.version, after.version);
    assert_batch_pending(engine.evaluate_memory_v1_confirmation_batch(&root, &session, &request));
    assert_batch_pending(evaluate_confirmation_batch(
        &owner,
        &authority,
        identity(4, 3),
        &items,
    ));
}

// memory—v1: A retired registry cannot authorize a subsequent complete batch.
#[test]
fn batch_b_confirmation_evaluator_rechecks_retired_registry() {
    let test_name = "batch_b_confirmation_evaluator_rechecks_retired_registry";
    if std::env::var_os(CHILD_ENV).is_none() {
        run_isolated(test_name);
        return;
    }
    let (rows, selections) = confirmation_batch_fixture();
    let owner = confirmation_serving_owner(rows, selections);
    let authority = MemoryV1SessionAuthority::new();
    authority
        .bind_to_root(&owner)
        .expect("authority binds to root");
    let items = [
        MemoryV1BatchItem {
            sequence: 0,
            binding_id: id(21),
            confirmation_id: id(150),
        },
        MemoryV1BatchItem {
            sequence: 1,
            binding_id: id(22),
            confirmation_id: id(151),
        },
    ];
    let before = evaluate_confirmation_batch(&owner, &authority, identity(4, 3), &items);
    assert_eq!(before.decision, MemoryV1Decision::Allow);
    assert!(before.admission.is_some());
    let registry_version = owner.registry_version();
    owner
        .request_registry_retirement_for_test("binding")
        .expect("registry retirement requested");
    assert_ne!(owner.registry_version(), registry_version);
    let after = evaluate_confirmation_batch(&owner, &authority, identity(4, 3), &items);
    assert_ne!(after.decision, MemoryV1Decision::Allow);
    assert!(after.admission.is_none());
}
