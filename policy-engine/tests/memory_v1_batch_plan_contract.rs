//! Offline structural plan tests using only genuine batch-evaluator admissions.

use std::time::{SystemTime, UNIX_EPOCH};

use astral_authorization_root::memory_v1_db_rows::{
    BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, CurrentSelection,
    IdentityCardRow, RuleSetChangeConfirmationRow, RuleSetRow, RuleSetVersionRow, TenantRow,
    UserCardRow, UserCardStatus, UserRow,
};
use astral_authorization_root::memory_v1_hamt::CandidateBudget;
use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
use astral_authorization_root::memory_v1_request::RequestRootScope;
use astral_authorization_root::memory_v1_root::{install_process_root, ManagementMutationV2};
use astral_authorization_root::memory_v1_rules::{
    canonical_version_bytes, version_digest, MemoryV1OwnerScope, MemoryV1TenantScope,
};
use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority;
use astral_types::memory_v1::{CandidateIdentity, MemoryId};
use policy_engine::memory_v1_batch::{
    MemoryV1BatchItem, MemoryV1BatchRequest, MAX_MEMORY_V1_BINDING_CONFIRMATION_BATCH,
};
use policy_engine::memory_v1_batch_plan::{
    MemoryV1BatchPlan, MemoryV1BatchPlanError, MemoryV1BatchPlanItem, MAX_BATCH_PLAN_SCOPE_BYTES,
    MAX_BATCH_PLAN_VERSION_BYTES,
};
use policy_engine::memory_v1_formal::MemoryV1Decision;
use policy_engine::PolicyEngine;

const CHILD: &str = "ASTRAL_MEMORY_V1_BATCH_PLAN_TEST_CHILD";
const OPERATION: &[u8] = b"batch-plan-test";
const FINGERPRINT: &[u8] = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

// memory—v1: Produce fixed binary identifiers for the isolated fixture.
fn id(n: u8) -> [u8; 16] {
    [n; 16]
}

// memory—v1: Build an existing or proposed confirmation with bounded local fields.
fn confirmation(
    confirmation: u8,
    binding: u8,
    rule_set: u8,
    revoked: bool,
) -> BindingConfirmationRow {
    BindingConfirmationRow {
        confirmation_id: id(confirmation),
        binding_id: id(binding),
        rule_set_id: id(rule_set),
        version_bytes: vec![1],
        confirmer_user_id: id(1),
        scope_bytes: vec![1],
        operation_id: OPERATION.to_vec(),
        confirmed_at_bytes: vec![1],
        revoked_at: revoked.then_some(1),
        revoked_by: revoked.then_some(id(1)),
    }
}

// memory—v1: Run all assertions against one real serving test root in a child process.
#[test]
fn structural_plan_binds_real_evaluator_admission() {
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "structural_plan_binds_real_evaluator_admission",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        return;
    }
    let mut rows = CandidateRows {
        users: (1..=3).map(|n| UserRow { user_id: id(n) }).collect(),
        identity_cards: (1..=3)
            .map(|n| IdentityCardRow {
                identity_card_id: id(n + 10),
                user_id: id(n),
            })
            .collect(),
        tenants: vec![TenantRow {
            tenant_id: id(4),
            parent_tenant_id: None,
        }],
        user_cards: (1..=3)
            .map(|n| UserCardRow {
                user_card_id: id(n + 20),
                user_id: id(n),
                tenant_id: id(4),
                status: UserCardStatus::Active,
            })
            .collect(),
        ..CandidateRows::default()
    };
    let mut selections = Vec::new();
    for n in 1..=3 {
        let rule_set_id = id(n + 30);
        let content: &[u8] = if n == 1 {
            br#"{"rules":[{"ruleId":"confirm","resource":"binding","action":"confirm","effect":"ALLOW","ownerScope":"all","tenantScope":"self"}]}"#
        } else {
            br#"{"rules":[]}"#
        };
        let version = vec![1];
        let timestamp = vec![1];
        let input = canonical_version_bytes(&version, content, &timestamp);
        rows.rule_sets.push(RuleSetRow {
            status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
            rule_set_id,
            owner_tenant_id: id(4),
            current_version_bytes: version.clone(),
        });
        rows.rule_set_versions.push(RuleSetVersionRow {
            rule_set_id,
            version_bytes: version.clone(),
            content_bytes: content.to_vec(),
            timestamp_bytes: timestamp,
            hash_bytes: version_digest(&input),
            hash_input_bytes: input,
        });
        rows.bindings.push(BindingRow {
            binding_id: id(n + 40),
            user_card_id: id(n + 20),
            rule_set_id,
            binding_layer: BindingLayer::Base,
            valid_from: None,
            valid_until: None,
            owner_scope: MemoryV1OwnerScope::AllUsers,
            tenant_scope: MemoryV1TenantScope::SelfTenant,
            removed_at: None,
            removed_by: None,
        });
        rows.binding_confirmations
            .push(confirmation(n + 50, n + 40, n + 30, n != 1));
        rows.rule_set_change_confirmations
            .push(RuleSetChangeConfirmationRow {
                confirmation_id: id(n + 60),
                rule_set_id,
                version_bytes: version.clone(),
                confirmer_user_id: id(1),
                affected_scope_bytes: vec![1],
                operation_id: OPERATION.to_vec(),
                confirmed_at_bytes: vec![1],
                revoked_at: None,
                revoked_by: None,
            });
        selections.push(CurrentSelection {
            rule_set_id,
            version_bytes: version,
        });
    }
    let owner = install_process_root(
        rows,
        selections,
        CandidateBudget {
            max_table_rows: 64,
            max_bindings_per_read: 4,
        },
    )
    .unwrap();
    owner
        .install_registry(&[RegistryDeclaration {
            resource: "binding".into(),
            actions: vec!["confirm".into()],
        }])
        .unwrap();
    owner.adopt_serving_for_isolated_tests().unwrap();
    let authority = MemoryV1SessionAuthority::new();
    authority.bind_to_root(&owner).unwrap();
    let identity = CandidateIdentity {
        user_id: MemoryId::from_bytes(id(1)),
        identity_card_id: MemoryId::from_bytes(id(11)),
        user_card_id: MemoryId::from_bytes(id(21)),
        tenant_id: MemoryId::from_bytes(id(4)),
    };
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let issued = authority
        .identity_session_adapter()
        .issue_unchecked_for_test(identity, now - 60, 3600)
        .unwrap();
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let session = authority
        .verifier()
        .verify_and_bind(issued.credential(), now, &root)
        .unwrap();
    let targets = [
        MemoryV1BatchItem {
            sequence: 0,
            binding_id: id(42),
            confirmation_id: id(71),
        },
        MemoryV1BatchItem {
            sequence: 1,
            binding_id: id(43),
            confirmation_id: id(72),
        },
    ];
    let engine = PolicyEngine::new();
    let evaluate = |fingerprint| {
        engine.evaluate_memory_v1_confirmation_batch(
            &root,
            &session,
            &MemoryV1BatchRequest {
                operation_id: OPERATION,
                operation_fingerprint: fingerprint,
                items: &targets,
            },
        )
    };
    let result = evaluate(FINGERPRINT);
    assert_eq!(result.decision, MemoryV1Decision::Allow);
    let admission = result.admission.unwrap();
    let items: Vec<_> = [(71, 42, 32), (72, 43, 33)]
        .into_iter()
        .enumerate()
        .map(|(sequence, (c, b, r))| {
            let mut row = confirmation(c, b, r, false);
            row.confirmed_at_bytes = admission.trusted_time_unix_seconds().to_be_bytes().to_vec();
            MemoryV1BatchPlanItem {
                sequence: sequence as u32,
                confirmation: row,
            }
        })
        .collect();
    let plan = MemoryV1BatchPlan::new(&admission, &items).unwrap();
    assert_eq!(plan.root(), admission.root());
    assert_eq!(plan.identity(), identity);
    assert_eq!(plan.operation_fingerprint(), FINGERPRINT);
    assert!(plan.matches(&items, &plan.digest()));
    assert_eq!(
        plan.digest(),
        MemoryV1BatchPlan::new(&admission, &items).unwrap().digest()
    );
    match plan.mutation() {
        ManagementMutationV2::ConfirmationBatch { rows } => assert_eq!(
            rows,
            &items
                .iter()
                .map(|i| i.confirmation.clone())
                .collect::<Vec<_>>()
        ),
        _ => panic!("unexpected mutation"),
    }
    let mut claimed = plan.digest();
    claimed[0] ^= 1;
    assert!(!plan.matches(&items, &claimed));

    let mut altered = items.clone();
    altered.swap(0, 1);
    assert!(MemoryV1BatchPlan::new(&admission, &altered).is_err());
    assert!(!plan.matches(&altered, &plan.digest()));
    altered[0].sequence = 0;
    altered[1].sequence = 1;
    assert!(MemoryV1BatchPlan::new(&admission, &altered).is_err());
    for change in 0..7 {
        let mut altered = items.clone();
        let row = &mut altered[0].confirmation;
        match change {
            0 => row.binding_id = id(43),
            1 => row.confirmation_id = id(72),
            2 => row.rule_set_id = id(33),
            3 => row.confirmer_user_id = id(2),
            4 => row.operation_id = b"another-operation".to_vec(),
            5 => row.revoked_at = Some(1),
            6 => row.revoked_by = Some(id(1)),
            _ => unreachable!(),
        }
        assert!(
            MemoryV1BatchPlan::new(&admission, &altered).is_err(),
            "change {change}"
        );
        assert!(!plan.matches(&altered, &plan.digest()));
    }
    let mut altered = items.clone();
    altered[0].confirmation.confirmed_at_bytes[7] ^= 1;
    assert_eq!(
        MemoryV1BatchPlan::new(&admission, &altered).unwrap_err(),
        MemoryV1BatchPlanError::InvalidTime
    );
    assert!(!plan.matches(&altered, &plan.digest()));
    let mut altered = items.clone();
    altered[0].confirmation.confirmed_at_bytes.pop();
    assert_eq!(
        MemoryV1BatchPlan::new(&admission, &altered).unwrap_err(),
        MemoryV1BatchPlanError::InvalidTime
    );
    for change in 0..2 {
        let mut altered = items.clone();
        if change == 0 {
            altered[0].confirmation.version_bytes = vec![2];
        } else {
            altered[0].confirmation.scope_bytes = vec![2];
        }
        let different = MemoryV1BatchPlan::new(&admission, &altered).unwrap();
        assert_ne!(plan.mutation_digest(), different.mutation_digest());
        assert_ne!(plan.digest(), different.digest());
        assert!(!plan.matches(&altered, &plan.digest()));
    }
    for change in 0..4 {
        let mut altered = items.clone();
        match change {
            0 => altered[0].confirmation.version_bytes.clear(),
            1 => altered[0].confirmation.version_bytes = vec![1; MAX_BATCH_PLAN_VERSION_BYTES + 1],
            2 => altered[0].confirmation.scope_bytes.clear(),
            3 => altered[0].confirmation.scope_bytes = vec![1; MAX_BATCH_PLAN_SCOPE_BYTES + 1],
            _ => unreachable!(),
        }
        assert_eq!(
            MemoryV1BatchPlan::new(&admission, &altered).unwrap_err(),
            MemoryV1BatchPlanError::InvalidConfirmation
        );
    }
    let mut altered = items.clone();
    altered[1] = altered[0].clone();
    altered[1].sequence = 1;
    assert!(!plan.matches(&altered, &plan.digest()));
    assert_eq!(
        MemoryV1BatchPlan::new(&admission, &altered).unwrap_err(),
        MemoryV1BatchPlanError::TargetMismatch
    );
    let mut largest = items.clone();
    largest[0].confirmation.version_bytes = vec![1; MAX_BATCH_PLAN_VERSION_BYTES];
    largest[0].confirmation.scope_bytes = vec![1; MAX_BATCH_PLAN_SCOPE_BYTES];
    assert!(MemoryV1BatchPlan::new(&admission, &largest).is_ok());
    assert_eq!(
        MemoryV1BatchPlan::new(&admission, &[]).unwrap_err(),
        MemoryV1BatchPlanError::InvalidCount
    );
    assert_eq!(
        MemoryV1BatchPlan::new(&admission, &items[..1]).unwrap_err(),
        MemoryV1BatchPlanError::InvalidCount
    );
    assert_eq!(
        MemoryV1BatchPlan::new(
            &admission,
            &vec![items[0].clone(); MAX_MEMORY_V1_BINDING_CONFIRMATION_BATCH + 1]
        )
        .unwrap_err(),
        MemoryV1BatchPlanError::InvalidCount
    );
    let other = evaluate(b"1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    assert_eq!(other.decision, MemoryV1Decision::Allow);
    let other = other.admission.unwrap();
    let mut other_items = items.clone();
    for item in &mut other_items {
        item.confirmation.confirmed_at_bytes =
            other.trusted_time_unix_seconds().to_be_bytes().to_vec();
    }
    assert_ne!(
        plan.digest(),
        MemoryV1BatchPlan::new(&other, &other_items)
            .unwrap()
            .digest()
    );
}
