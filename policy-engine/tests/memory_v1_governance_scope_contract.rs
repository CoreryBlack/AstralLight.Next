//! Single-target Batch B governance scope contract against the shared root.
//!
//! Each test runs in a child process because the process-root owner is installed
//! only once. The fixture does not start a listener or use external services.

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use astral_authorization_root::memory_v1_db_rows::{
    BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, CurrentSelection,
    IdentityCardRow, RuleSetChangeConfirmationRow, RuleSetRow, RuleSetVersionRow, TenantRow,
    UserCardRow, UserCardStatus, UserRow,
};
use astral_authorization_root::memory_v1_hamt::CandidateBudget;
use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
use astral_authorization_root::memory_v1_request::RequestRootScope;
use astral_authorization_root::memory_v1_root::{install_process_root, RootOwner};
use astral_authorization_root::memory_v1_rules::{
    canonical_version_bytes, version_digest, MemoryV1OwnerScope, MemoryV1TenantScope,
};
use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority;
use astral_types::memory_v1::{CandidateIdentity, MemoryId};
use policy_engine::memory_v1_formal::{
    MemoryV1Decision, MemoryV1DenySource, MemoryV1Evaluation, MemoryV1PendingSource,
    MemoryV1Request,
};
use policy_engine::PolicyEngine;

const CHILD: &str = "ASTRAL_GOVERNANCE_SCOPE_CONTRACT_CHILD";

// memory—v1: Isolate the once-per-process root and propagate child failures.
fn isolated(test: &str) -> bool {
    if std::env::var_os(CHILD).is_some() {
        return false;
    }
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env(CHILD, "1")
        .output()
        .expect("start isolated contract test");
    assert!(
        output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "isolated test failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    true
}

// memory—v1: Keep fixture identifiers distinct and deterministic.
fn id(n: u8) -> [u8; 16] {
    [n; 16]
}

// memory—v1: Build valid version bytes for the isolated candidate root.
fn version(set: u8, content: &[u8]) -> RuleSetVersionRow {
    let version_bytes = vec![1];
    let timestamp_bytes = vec![2];
    let hash_input_bytes = canonical_version_bytes(&version_bytes, content, &timestamp_bytes);
    RuleSetVersionRow {
        rule_set_id: id(set),
        version_bytes,
        content_bytes: content.to_vec(),
        timestamp_bytes,
        hash_bytes: version_digest(&hash_input_bytes),
        hash_input_bytes,
    }
}

// memory—v1: Give one card exactly one active, confirmed binding.
fn add_binding(
    rows: &mut CandidateRows,
    binding: u8,
    card: u8,
    set: u8,
    owner_scope: MemoryV1OwnerScope,
    tenant_scope: MemoryV1TenantScope,
) {
    rows.bindings.push(BindingRow {
        binding_id: id(binding),
        user_card_id: id(card),
        rule_set_id: id(set),
        binding_layer: BindingLayer::Base,
        valid_from: None,
        valid_until: None,
        owner_scope,
        tenant_scope,
        removed_at: None,
        removed_by: None,
    });
    rows.binding_confirmations.push(BindingConfirmationRow {
        confirmation_id: id(binding + 80),
        binding_id: id(binding),
        rule_set_id: id(set),
        version_bytes: vec![1],
        confirmer_user_id: id(1),
        scope_bytes: vec![1],
        operation_id: vec![binding],
        confirmed_at_bytes: vec![1],
        revoked_at: None,
        revoked_by: None,
    });
}

// memory—v1: Use four operator cards to isolate entry and binding scopes.
fn fixture() -> (RootOwner, MemoryV1SessionAuthority) {
    let mut rows = CandidateRows {
        users: [1, 2, 3, 4]
            .into_iter()
            .map(|n| UserRow { user_id: id(n) })
            .collect(),
        identity_cards: [
            IdentityCardRow {
                identity_card_id: id(5),
                user_id: id(1),
            },
            IdentityCardRow {
                identity_card_id: id(6),
                user_id: id(2),
            },
            IdentityCardRow {
                identity_card_id: id(7),
                user_id: id(3),
            },
            IdentityCardRow {
                identity_card_id: id(8),
                user_id: id(4),
            },
        ]
        .into(),
        tenants: [
            TenantRow {
                tenant_id: id(10),
                parent_tenant_id: None,
            },
            TenantRow {
                tenant_id: id(11),
                parent_tenant_id: Some(id(10)),
            },
            TenantRow {
                tenant_id: id(12),
                parent_tenant_id: None,
            },
        ]
        .into(),
        user_cards: [
            (20, 1, 10),
            (21, 1, 10),
            (22, 1, 10),
            (23, 2, 10),
            (24, 3, 11),
            (25, 4, 12),
            (26, 1, 10),
        ]
        .into_iter()
        .map(|(card, user, tenant)| UserCardRow {
            user_card_id: id(card),
            user_id: id(user),
            tenant_id: id(tenant),
            status: UserCardStatus::Active,
        })
        .collect(),
        ..CandidateRows::default()
    };
    let default_entry = br#"{"rules":[{"ruleId":"confirm","resource":"binding","action":"confirm","effect":"ALLOW","tenantScope":"self+descendants"}]}"#;
    let self_entry = br#"{"rules":[{"ruleId":"confirm","resource":"binding","action":"confirm","effect":"ALLOW","ownerScope":"self","tenantScope":"self+descendants"}]}"#;
    let wide_entry = br#"{"rules":[{"ruleId":"confirm","resource":"binding","action":"confirm","effect":"ALLOW","ownerScope":"all","tenantScope":"self+descendants"}]}"#;
    let empty = br#"{"rules":[]}"#;
    for (set, tenant, content) in [
        (30, 10, default_entry.as_slice()),
        (31, 10, wide_entry.as_slice()),
        (32, 10, wide_entry.as_slice()),
        (33, 10, empty.as_slice()),
        (34, 11, empty.as_slice()),
        (35, 12, empty.as_slice()),
        (36, 10, self_entry.as_slice()),
    ] {
        rows.rule_sets.push(RuleSetRow {
            status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
            rule_set_id: id(set),
            owner_tenant_id: id(tenant),
            current_version_bytes: vec![1],
        });
        rows.rule_set_versions.push(version(set, content));
        rows.rule_set_change_confirmations
            .push(RuleSetChangeConfirmationRow {
                confirmation_id: id(set + 100),
                rule_set_id: id(set),
                version_bytes: vec![1],
                confirmer_user_id: id(1),
                affected_scope_bytes: vec![1],
                operation_id: vec![set],
                confirmed_at_bytes: vec![1],
                revoked_at: None,
                revoked_by: None,
            });
    }
    let wide = MemoryV1TenantScope::SelfAndDescendants;
    add_binding(&mut rows, 40, 20, 30, MemoryV1OwnerScope::AllUsers, wide);
    add_binding(&mut rows, 41, 21, 31, MemoryV1OwnerScope::default(), wide);
    add_binding(&mut rows, 42, 22, 32, MemoryV1OwnerScope::AllUsers, wide);
    add_binding(
        &mut rows,
        43,
        23,
        33,
        MemoryV1OwnerScope::default(),
        MemoryV1TenantScope::default(),
    );
    add_binding(
        &mut rows,
        44,
        24,
        34,
        MemoryV1OwnerScope::default(),
        MemoryV1TenantScope::default(),
    );
    add_binding(
        &mut rows,
        45,
        25,
        35,
        MemoryV1OwnerScope::default(),
        MemoryV1TenantScope::default(),
    );
    add_binding(&mut rows, 46, 26, 36, MemoryV1OwnerScope::AllUsers, wide);
    let selections = (30..=36)
        .map(|set| CurrentSelection {
            rule_set_id: id(set),
            version_bytes: vec![1],
        })
        .collect();
    let owner = install_process_root(
        rows,
        selections,
        CandidateBudget {
            max_table_rows: 128,
            max_bindings_per_read: 16,
        },
    )
    .expect("fixture root installs");
    owner
        .install_registry(&[RegistryDeclaration {
            resource: "binding".into(),
            actions: vec!["confirm".into()],
        }])
        .unwrap();
    owner.adopt_serving_for_isolated_tests().unwrap();
    let authority = MemoryV1SessionAuthority::new();
    authority.bind_to_root(&owner).unwrap();
    (owner, authority)
}

#[derive(Clone, Copy)]
enum Missing {
    None,
    Owner,
    Tenant,
}

// memory—v1: Derive attribution from the same request reader used by the real evaluator.
fn evaluate(
    owner: &RootOwner,
    authority: &MemoryV1SessionAuthority,
    card: u8,
    binding: u8,
    missing: Missing,
) -> MemoryV1Evaluation {
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let target = id(binding);
    let facts = root
        .with_reader(|reader| reader.binding_target(target))
        .unwrap()
        .unwrap();
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let identity = CandidateIdentity {
        user_id: MemoryId::from_bytes(id(1)),
        identity_card_id: MemoryId::from_bytes(id(5)),
        user_card_id: MemoryId::from_bytes(id(card)),
        tenant_id: MemoryId::from_bytes(id(10)),
    };
    let issued = authority
        .identity_session_adapter()
        .issue_unchecked_for_test(identity, now - 60, 3600)
        .unwrap();
    let session = authority
        .verifier()
        .verify_and_bind(issued.credential(), now, &root)
        .unwrap();
    let request = MemoryV1Request {
        resource: "binding",
        action: "confirm",
        target: Some(&target),
        target_owner: (!matches!(missing, Missing::Owner))
            .then_some(facts.owner_user_id.as_slice()),
        target_tenant: (!matches!(missing, Missing::Tenant)).then_some(facts.tenant_id.as_slice()),
        operation_id: b"scope-contract",
        operation_fingerprint: b"scope-contract-fingerprint",
    };
    PolicyEngine::new().evaluate_memory_v1(&root, &session, &request)
}

// memory—v1: Verify deterministic denial and the absence of any admission.
fn assert_deny(result: MemoryV1Evaluation, source: MemoryV1DenySource) {
    assert_eq!(result.decision, MemoryV1Decision::Deny);
    assert_eq!(result.deny_source, Some(source));
    assert!(result.pending_source.is_none());
    assert!(result.admission.is_none());
}

// memory—v1: Verify unverifiable attribution never yields an admission.
fn assert_pending(result: MemoryV1Evaluation) {
    assert_eq!(result.decision, MemoryV1Decision::Pending);
    assert_eq!(
        result.pending_source,
        Some(MemoryV1PendingSource::ContextInvalid)
    );
    assert!(result.deny_source.is_none());
    assert!(result.admission.is_none());
}

#[test]
// memory—v1: Both entry and binding must explicitly grant all owners.
fn confirm_requires_both_owner_scopes_wide() {
    if isolated("confirm_requires_both_owner_scopes_wide") {
        return;
    }
    let (owner, authority) = fixture();
    for card in [20, 21, 26] {
        assert_deny(
            evaluate(&owner, &authority, card, 43, Missing::None),
            MemoryV1DenySource::ScopeDenied,
        );
        assert_deny(
            evaluate(&owner, &authority, card, 44, Missing::None),
            MemoryV1DenySource::ScopeDenied,
        );
    }
    for binding in [43, 44] {
        let result = evaluate(&owner, &authority, 22, binding, Missing::None);
        assert_eq!(result.decision, MemoryV1Decision::Allow);
        assert!(result.deny_source.is_none() && result.pending_source.is_none());
        let admission = result
            .admission
            .expect("wide governance grant admits target");
        assert_eq!(admission.target(), Some(id(binding).as_slice()));
        let (expected_user, expected_tenant) = if binding == 43 { (2, 10) } else { (3, 11) };
        assert_eq!(admission.target_owner(), Some(id(expected_user).as_slice()));
        assert_eq!(
            admission.target_tenant(),
            Some(id(expected_tenant).as_slice())
        );
        assert_eq!(
            admission.effective_owner_scope(),
            MemoryV1OwnerScope::AllUsers
        );
        assert_eq!(
            admission.effective_tenant_scope(),
            MemoryV1TenantScope::SelfAndDescendants
        );
    }
}

#[test]
// memory—v1: Descendant scope cannot authorize a separate tenant tree.
fn confirm_excludes_unrelated_tenant() {
    if isolated("confirm_excludes_unrelated_tenant") {
        return;
    }
    let (owner, authority) = fixture();
    assert_deny(
        evaluate(&owner, &authority, 22, 45, Missing::None),
        MemoryV1DenySource::ScopeDenied,
    );
}

#[test]
// memory—v1: Self-confirmation takes priority over even a wide grant.
fn confirm_denies_self_before_scope_grant() {
    if isolated("confirm_denies_self_before_scope_grant") {
        return;
    }
    let (owner, authority) = fixture();
    for card in [20, 21, 22, 26] {
        assert_deny(
            evaluate(&owner, &authority, card, 42, Missing::None),
            MemoryV1DenySource::SelfConfirmation,
        );
    }
}

#[test]
// memory—v1: Missing trusted target attribution must not become an ALLOW.
fn confirm_missing_attribution_is_pending() {
    if isolated("confirm_missing_attribution_is_pending") {
        return;
    }
    let (owner, authority) = fixture();
    assert_pending(evaluate(&owner, &authority, 21, 43, Missing::Owner));
    assert_pending(evaluate(&owner, &authority, 22, 43, Missing::Tenant));
    assert_pending(evaluate(&owner, &authority, 22, 43, Missing::Owner));
}
