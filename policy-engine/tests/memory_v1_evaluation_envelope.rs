//! memory—v1: Isolated public API tests for same-call evaluation envelopes.

use std::time::{SystemTime, UNIX_EPOCH};

use astral_authorization_root::memory_v1_db_rows::{
    BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, CurrentSelection,
    IdentityCardRow, RuleSetChangeConfirmationRow, RuleSetRow, RuleSetStatus, RuleSetVersionRow,
    TenantRow, UserCardRow, UserCardStatus, UserRow,
};
use astral_authorization_root::memory_v1_hamt::CandidateBudget;
use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
use astral_authorization_root::memory_v1_request::RequestRootScope;
use astral_authorization_root::memory_v1_root::install_process_root;
use astral_authorization_root::memory_v1_rules::{
    canonical_version_bytes, version_digest, MemoryV1OwnerScope, MemoryV1TenantScope,
};
use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority;
use astral_types::memory_v1::{CandidateIdentity, MemoryId};
use policy_engine::memory_v1_batch::{MemoryV1BatchItem, MemoryV1BatchRequest};
use policy_engine::memory_v1_compound::{
    MemoryV1CompoundAction, MemoryV1CompoundRequest, MemoryV1CompoundTargetKind,
};
use policy_engine::memory_v1_formal::{
    MemoryV1Decision, MemoryV1DenySource, MemoryV1Request, MemoryV1RuleSetChangeIntent,
};
use policy_engine::PolicyEngine;

// memory—v1: Build stable nonzero identifiers for the isolated root.
fn id(value: u8) -> [u8; 16] {
    [value; 16]
}

// memory—v1: Exercise all public envelopes against a single in-memory root.
#[test]
fn envelopes_preserve_exact_call_inputs_and_results() {
    let content = br#"{"rules":[{"ruleId":"create","resource":"binding","action":"create","effect":"ALLOW","ownerScope":"all","tenantScope":"self"},{"ruleId":"confirm","resource":"binding","action":"confirm","effect":"ALLOW","ownerScope":"all","tenantScope":"self"},{"ruleId":"change","resource":"rule_set","action":"confirm-change","effect":"ALLOW","ownerScope":"all","tenantScope":"self"}]}"#;
    let version_bytes = vec![1];
    let timestamp_bytes = vec![2];
    let hash_input = canonical_version_bytes(&version_bytes, content, &timestamp_bytes);
    let rows = CandidateRows {
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
            status: RuleSetStatus::Active,
            rule_set_id: id(30),
            owner_tenant_id: id(10),
            current_version_bytes: version_bytes.clone(),
        }],
        rule_set_versions: vec![RuleSetVersionRow {
            rule_set_id: id(30),
            version_bytes: version_bytes.clone(),
            content_bytes: content.to_vec(),
            timestamp_bytes,
            hash_bytes: version_digest(&hash_input),
            hash_input_bytes: hash_input,
        }],
        bindings: vec![BindingRow {
            binding_id: id(40),
            user_card_id: id(20),
            rule_set_id: id(30),
            binding_layer: BindingLayer::Base,
            valid_from: None,
            valid_until: None,
            owner_scope: MemoryV1OwnerScope::AllUsers,
            tenant_scope: MemoryV1TenantScope::SelfTenant,
            removed_at: None,
            removed_by: None,
        }],
        binding_confirmations: vec![BindingConfirmationRow {
            confirmation_id: id(50),
            binding_id: id(40),
            rule_set_id: id(30),
            version_bytes: version_bytes.clone(),
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
            version_bytes: version_bytes.clone(),
            confirmer_user_id: id(2),
            affected_scope_bytes: vec![1],
            operation_id: vec![60],
            confirmed_at_bytes: vec![1],
            revoked_at: None,
            revoked_by: None,
        }],
    };
    let owner = install_process_root(
        rows,
        vec![CurrentSelection {
            rule_set_id: id(30),
            version_bytes,
        }],
        CandidateBudget {
            max_table_rows: 128,
            max_bindings_per_read: 16,
        },
    )
    .unwrap();
    owner
        .install_registry(&[
            RegistryDeclaration {
                resource: "binding".into(),
                actions: vec!["create".into(), "confirm".into()],
            },
            RegistryDeclaration {
                resource: "rule_set".into(),
                actions: vec!["confirm-change".into()],
            },
        ])
        .unwrap();
    owner.adopt_serving_for_isolated_tests().unwrap();
    let authority = MemoryV1SessionAuthority::new();
    authority.bind_to_root(&owner).unwrap();
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let identity = CandidateIdentity {
        user_id: MemoryId::from_bytes(id(1)),
        identity_card_id: MemoryId::from_bytes(id(3)),
        user_card_id: MemoryId::from_bytes(id(20)),
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
    let engine = PolicyEngine::new();
    let target = id(70);
    let tenant = id(10);
    let beneficiary = id(2);
    let request = MemoryV1Request {
        resource: "binding",
        action: "create",
        target: Some(&target),
        target_tenant: Some(&tenant),
        target_owner: Some(&beneficiary),
        operation_id: b"op-a",
        operation_fingerprint: b"fingerprint-a",
    };
    let ordinary = engine.evaluate_memory_v1_enveloped(&root, &session, &request);
    assert_eq!(engine.get_stats().evaluation_count, 1);
    assert!(std::ptr::eq(ordinary.root(), &root));
    assert!(std::ptr::eq(ordinary.session(), &session));
    assert!(std::ptr::eq(ordinary.request(), &request));
    assert_eq!(ordinary.intent(), None);
    assert_eq!(ordinary.evaluation().decision, MemoryV1Decision::Allow);
    let expected = ordinary.evaluation().clone();
    assert_eq!(ordinary.into_evaluation(), expected);

    let different = MemoryV1Request {
        action: "confirm",
        operation_id: b"op-b",
        ..request
    };
    let first = engine.evaluate_memory_v1_enveloped(&root, &session, &request);
    let second = engine.evaluate_memory_v1_enveloped(&root, &session, &different);
    assert_eq!(first.request().operation_id, b"op-a");
    assert_eq!(second.request().operation_id, b"op-b");
    assert_eq!(first.request().action, "create");
    assert_eq!(second.request().action, "confirm");
    assert_eq!(engine.get_stats().evaluation_count, 3);

    let change_request = MemoryV1Request {
        resource: "rule_set",
        action: "confirm-change",
        target: Some(&target),
        target_tenant: Some(&tenant),
        target_owner: None,
        operation_id: b"change",
        operation_fingerprint: b"change-fingerprint",
    };
    let change = engine.evaluate_memory_v1_rule_set_change_enveloped(
        &root,
        &session,
        &change_request,
        MemoryV1RuleSetChangeIntent::Create,
    );
    assert_eq!(engine.get_stats().evaluation_count, 4);
    assert!(std::ptr::eq(change.request(), &change_request));
    assert_eq!(change.intent(), Some(MemoryV1RuleSetChangeIntent::Create));
    assert_eq!(change.evaluation().decision, MemoryV1Decision::Allow);
    let expected = change.evaluation().clone();
    assert_eq!(change.into_evaluation(), expected);

    let facts = root
        .with_reader(|reader| reader.binding_create_target(id(21), id(30)))
        .unwrap()
        .unwrap();
    let actions = [MemoryV1CompoundAction {
        request,
        change_intent: None,
        target_facts: facts,
        target_kind: MemoryV1CompoundTargetKind::BindingCreate,
    }];
    let compound_request = MemoryV1CompoundRequest { actions: &actions };
    let compound = engine.evaluate_memory_v1_compound_enveloped(&root, &session, &compound_request);
    assert_eq!(engine.get_stats().evaluation_count, 5);
    assert!(std::ptr::eq(compound.root(), &root));
    assert!(std::ptr::eq(compound.session(), &session));
    assert!(std::ptr::eq(compound.request(), &compound_request));
    assert_eq!(compound.evaluation().decision, MemoryV1Decision::Allow);
    let expected = compound.evaluation().clone();
    assert_eq!(compound.into_evaluation(), expected);

    let items = [MemoryV1BatchItem {
        sequence: 0,
        binding_id: id(40),
        confirmation_id: id(51),
    }];
    let batch_request = MemoryV1BatchRequest {
        operation_id: b"batch",
        operation_fingerprint: b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        items: &items,
    };
    let batch =
        engine.evaluate_memory_v1_confirmation_batch_enveloped(&root, &session, &batch_request);
    assert_eq!(engine.get_stats().evaluation_count, 6);
    assert!(std::ptr::eq(batch.root(), &root));
    assert!(std::ptr::eq(batch.session(), &session));
    assert!(std::ptr::eq(batch.request(), &batch_request));
    assert_eq!(batch.evaluation().decision, MemoryV1Decision::Deny);
    assert_eq!(
        batch.evaluation().deny_source,
        Some(MemoryV1DenySource::SelfConfirmation)
    );
    let expected = batch.evaluation().clone();
    assert_eq!(batch.into_evaluation(), expected);

    let empty = MemoryV1BatchRequest {
        items: &[],
        ..batch_request
    };
    let pending = engine.evaluate_memory_v1_confirmation_batch_enveloped(&root, &session, &empty);
    assert_eq!(pending.evaluation().decision, MemoryV1Decision::Pending);
    assert_eq!(pending.request().items.len(), 0);
    assert_eq!(engine.get_stats().evaluation_count, 7);

    // A mismatched actor in a separately bound session triggers the compound
    // rule-set planner's actual DENY without an attributable observation.
    let mismatched = CandidateIdentity {
        identity_card_id: MemoryId::from_bytes(id(4)),
        ..identity
    };
    let issued_bad = authority
        .identity_session_adapter()
        .issue_unchecked_for_test(mismatched, now - 60, 3600)
        .unwrap();
    let session_bad = authority
        .verifier()
        .verify_and_bind(issued_bad.credential(), now, &root)
        .unwrap();
    let change_facts = root
        .with_reader(|reader| reader.rule_set_create_target(target, tenant))
        .unwrap()
        .unwrap();
    let actions_bad = [MemoryV1CompoundAction {
        request: change_request,
        change_intent: Some(MemoryV1RuleSetChangeIntent::Create),
        target_facts: change_facts,
        target_kind: MemoryV1CompoundTargetKind::RuleSetCreate,
    }];
    let request_bad = MemoryV1CompoundRequest {
        actions: &actions_bad,
    };
    let denied = engine.evaluate_memory_v1_compound_enveloped(&root, &session_bad, &request_bad);
    assert_eq!(denied.evaluation().decision, MemoryV1Decision::Deny);
    assert_eq!(
        denied.evaluation().deny_source,
        Some(MemoryV1DenySource::IdentityMismatch)
    );
    assert!(denied.evaluation().deny_observation.is_none());
    let direct_deny = engine.evaluate_memory_v1_compound(&root, &session_bad, &request_bad);
    assert_eq!(denied.evaluation(), &direct_deny);
    assert_eq!(denied.into_evaluation(), direct_deny);
    assert_eq!(engine.get_stats().evaluation_count, 9);

    // Different root scopes are distinct inputs even if they share the same root
    // owner. Keeping an older envelope is possible and proves no freshness.
    let old = engine.evaluate_memory_v1_enveloped(&root, &session, &request);
    let another_scope = RequestRootScope::new(owner.handle(), Default::default());
    let another_root = another_scope.extension();
    let mismatched_scope = engine.evaluate_memory_v1_enveloped(&another_root, &session, &request);
    assert!(std::ptr::eq(old.root(), &root));
    assert!(std::ptr::eq(mismatched_scope.root(), &another_root));
    assert_eq!(old.evaluation().decision, MemoryV1Decision::Allow);
    assert_eq!(
        mismatched_scope.evaluation().decision,
        MemoryV1Decision::Pending
    );

    // Invalid inputs must preserve each old entry's complete PENDING result.
    let invalid = MemoryV1Request {
        operation_id: b"",
        ..request
    };
    let ordinary_pending = engine.evaluate_memory_v1_enveloped(&root, &session, &invalid);
    assert_eq!(
        ordinary_pending.evaluation(),
        &engine.evaluate_memory_v1(&root, &session, &invalid)
    );
    assert_eq!(
        ordinary_pending.evaluation().decision,
        MemoryV1Decision::Pending
    );
    let change_pending = engine.evaluate_memory_v1_rule_set_change_enveloped(
        &root,
        &session,
        &invalid,
        MemoryV1RuleSetChangeIntent::Publish,
    );
    assert_eq!(
        change_pending.intent(),
        Some(MemoryV1RuleSetChangeIntent::Publish)
    );
    assert_eq!(
        change_pending.evaluation(),
        &engine.evaluate_memory_v1_rule_set_change(
            &root,
            &session,
            &invalid,
            MemoryV1RuleSetChangeIntent::Publish
        )
    );
    assert_eq!(
        change_pending.evaluation().decision,
        MemoryV1Decision::Pending
    );
    let empty_compound = MemoryV1CompoundRequest { actions: &[] };
    let compound_pending =
        engine.evaluate_memory_v1_compound_enveloped(&root, &session, &empty_compound);
    assert_eq!(
        compound_pending.evaluation(),
        &engine.evaluate_memory_v1_compound(&root, &session, &empty_compound)
    );
    assert_eq!(
        compound_pending.evaluation().decision,
        MemoryV1Decision::Pending
    );
    assert_eq!(
        pending.evaluation(),
        &engine.evaluate_memory_v1_confirmation_batch(&root, &session, &empty)
    );
}
