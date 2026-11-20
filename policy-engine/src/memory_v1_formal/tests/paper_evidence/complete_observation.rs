//! memory—v1: Compare the real evaluator with a scan of the supplied rows.

use astral_authorization_root::memory_v1_root::install_isolated_test_root;
use serde_json::{json, Value};

use super::*;

const VERSION: &[u8] = &[2];
const OLD_VERSION: &[u8] = &[1];
const USER: u8 = 1;
const OTHER_USER: u8 = 7;
const PARENT: u8 = 3;
const CHILD: u8 = 6;
const GRANDCHILD: u8 = 9;
const SIBLING: u8 = 11;
const OTHER_CARD: u8 = 12;
const UNBOUND_CARD: u8 = 13;
const TARGET_ID: [u8; 16] = [123; 16];

#[derive(Clone, Copy, Debug)]
struct Shape {
    size: usize,
    reverse: bool,
    binding_descendants: bool,
    rule_self: bool,
    overlay_confirmed: bool,
}

#[derive(Clone, Copy, Debug)]
enum Target {
    None,
    Object {
        owner: Option<u8>,
        tenant: Option<u8>,
    },
}

// memory—v1: Construct both current and historical versions in each generated root.
fn fixture(shape: Shape) -> CandidateRows {
    let owner_scope = if shape.rule_self { "self" } else { "all" };
    let mut entries = vec![
        json!({"ruleId":"ordinary", "resource":"document", "action":"read", "effect":"ALLOW",
               "ownerScope":owner_scope, "tenantScope":"self+descendants", "validity":{"from":109,"until":120}}),
        json!({"ruleId":"same-pair", "resource":"document", "action":"read", "effect":"ALLOW",
               "ownerScope":"self", "tenantScope":"self", "validity":{"from":109,"until":120}}),
    ];
    entries.extend((entries.len()..shape.size).map(|index| {
        json!({"ruleId":format!("padding-{index}"), "resource":format!("pad_{}", index % 5),
               "action":"read", "effect":"ALLOW"})
    }));
    if shape.reverse {
        entries.reverse();
    }
    let mut rows = CandidateRows {
        users: [USER, OTHER_USER].map(|id| UserRow { user_id: [id; 16] }).to_vec(),
        identity_cards: [(2, USER), (8, OTHER_USER)].map(|(id, user)| IdentityCardRow {
            identity_card_id: [id; 16], user_id: [user; 16],
        }).to_vec(),
        tenants: [(PARENT, None), (CHILD, Some(PARENT)), (GRANDCHILD, Some(CHILD)), (SIBLING, None)]
            .map(|(id, parent)| TenantRow {
                tenant_id: [id; 16], parent_tenant_id: parent.map(|id| [id; 16]),
            }).to_vec(),
        user_cards: [(SUBJECT, USER, PARENT), (OTHER_CARD, OTHER_USER, CHILD), (UNBOUND_CARD, USER, CHILD)]
            .map(|(id, user, tenant)| UserCardRow {
                user_card_id: [id; 16], user_id: [user; 16], tenant_id: [tenant; 16], status: UserCardStatus::Active,
            }).to_vec(),
        rule_sets: vec![rule_set(20, VERSION), rule_set(21, VERSION), RuleSetRow {
            owner_tenant_id: [CHILD; 16], ..rule_set(22, VERSION)
        }],
        rule_set_versions: vec![
            version_row([20; 16], OLD_VERSION, &rule_content("historical", "DENY")),
            version_row([20; 16], VERSION, &json!({"rules":entries}).to_string()),
            version_row([21; 16], VERSION, &json!({"rules":[{
                "ruleId":"scheduled", "resource":"document", "action":"read", "effect":"DENY",
                "ownerScope":"all", "tenantScope":"self+descendants", "validity":{"from":112,"until":116}
            }]}).to_string()),
            version_row([22; 16], VERSION, &rule_content("child", "ALLOW")),
        ],
        bindings: vec![
            BindingRow { owner_scope: MemoryV1OwnerScope::AllUsers,
                tenant_scope: if shape.binding_descendants { MemoryV1TenantScope::SelfAndDescendants } else { MemoryV1TenantScope::SelfTenant },
                ..binding_row(30, SUBJECT, 20, BindingLayer::Base) },
            BindingRow { valid_from: Some(111), valid_until: Some(118), owner_scope: MemoryV1OwnerScope::AllUsers,
                tenant_scope: MemoryV1TenantScope::SelfAndDescendants,
                ..binding_row(31, SUBJECT, 21, BindingLayer::Overlay) },
            binding_row(32, OTHER_CARD, 22, BindingLayer::Base),
        ],
        binding_confirmations: vec![
            binding_confirmation(40, 30, 20, VERSION, false),
            binding_confirmation(41, 31, 21, VERSION, !shape.overlay_confirmed),
            binding_confirmation(42, 32, 22, VERSION, false),
        ],
        rule_set_change_confirmations: vec![
            change_confirmation(50, 20, OLD_VERSION),
            change_confirmation(51, 20, VERSION),
            change_confirmation(52, 21, VERSION),
            change_confirmation(53, 22, VERSION),
        ],
    };
    if shape.reverse {
        rows.bindings.reverse();
        rows.rule_set_versions.reverse();
        rows.binding_confirmations.reverse();
    }
    rows
}

// memory—v1: Walk parent links in the supplied rows, independently of the root's descendant index.
fn descendant_or_self(rows: &CandidateRows, base: [u8; 16], mut target: [u8; 16]) -> bool {
    for _ in &rows.tenants {
        if target == base {
            return true;
        }
        let Some(parent) = rows
            .tenants
            .iter()
            .find(|row| row.tenant_id == target)
            .and_then(|row| row.parent_tenant_id)
        else {
            return false;
        };
        target = parent;
    }
    panic!("fixture contains a tenant cycle");
}

// memory—v1: Scan the fixture's raw rows and JSON. No prepared plan, registry index,
// dependency recorder, scope resolver or policy-engine predicate feeds this oracle.
fn scan(rows: &CandidateRows, card: u8, target: Target, action: &str, at: i64) -> MemoryV1Decision {
    let card = rows
        .user_cards
        .iter()
        .find(|row| row.user_card_id == [card; 16])
        .unwrap();
    let mut permits = 0;
    let mut forbids = 0;
    let mut unresolved = false;
    for binding in rows
        .bindings
        .iter()
        .filter(|row| row.user_card_id == card.user_card_id)
    {
        if binding.removed_at.is_some()
            || at < binding.valid_from.unwrap_or(i64::MIN)
            || at >= binding.valid_until.unwrap_or(i64::MAX)
        {
            continue;
        }
        let set = rows
            .rule_sets
            .iter()
            .find(|row| row.rule_set_id == binding.rule_set_id)
            .unwrap();
        assert_eq!(set.owner_tenant_id, card.tenant_id);
        if !rows
            .binding_confirmations
            .iter()
            .any(|row| row.binding_id == binding.binding_id && row.revoked_at.is_none())
        {
            continue;
        }
        let version = rows
            .rule_set_versions
            .iter()
            .find(|row| {
                row.rule_set_id == set.rule_set_id && row.version_bytes == set.current_version_bytes
            })
            .unwrap();
        assert!(rows
            .rule_set_change_confirmations
            .iter()
            .any(|row| row.rule_set_id == version.rule_set_id
                && row.version_bytes == version.version_bytes
                && row.revoked_at.is_none()));
        let content: Value = serde_json::from_slice(&version.content_bytes).unwrap();
        for entry in content["rules"].as_array().unwrap() {
            if entry["resource"] != "document" || entry["action"] != action {
                continue;
            }
            if at < entry["validity"]["from"].as_i64().unwrap_or(i64::MIN)
                || at >= entry["validity"]["until"].as_i64().unwrap_or(i64::MAX)
            {
                continue;
            }
            if let Target::Object { owner, tenant } = target {
                let (Some(owner), Some(tenant)) = (owner, tenant) else {
                    unresolved = true;
                    continue;
                };
                let owner_ok = [owner; 16] == card.user_id
                    || (entry["ownerScope"] == "all"
                        && binding.owner_scope == MemoryV1OwnerScope::AllUsers);
                let tenant_ok = [tenant; 16] == card.tenant_id
                    || (entry["tenantScope"] == "self+descendants"
                        && binding.tenant_scope == MemoryV1TenantScope::SelfAndDescendants
                        && descendant_or_self(rows, card.tenant_id, [tenant; 16]));
                if !owner_ok || !tenant_ok {
                    continue;
                }
            }
            match entry["effect"].as_str().unwrap() {
                "ALLOW" => permits += 1,
                "DENY" => forbids += 1,
                _ => panic!("unexpected fixture rule effect"),
            }
        }
    }
    match (forbids, unresolved, permits) {
        (1.., _, _) => MemoryV1Decision::Deny,
        (_, true, _) => MemoryV1Decision::Pending,
        (_, false, 1..) => MemoryV1Decision::Allow,
        _ => MemoryV1Decision::Deny,
    }
}

// memory—v1: Install a checked fixture before starting a reader.
fn install(rows: &CandidateRows) -> RootOwner {
    let selections = rows.current_version_selections().unwrap();
    let owner = install_isolated_test_root(
        rows.clone(),
        selections,
        CandidateBudget {
            max_table_rows: 128,
            max_bindings_per_read: 8,
        },
    )
    .unwrap();
    let mut registry = vec![RegistryDeclaration {
        resource: "document".into(),
        actions: vec!["read".into(), "write".into()],
    }];
    registry.extend((0..5).map(|index| RegistryDeclaration {
        resource: format!("pad_{index}"),
        actions: vec!["read".into()],
    }));
    owner.install_registry(&registry).unwrap();
    owner.adopt_serving_for_isolated_tests().unwrap();
    owner
}

// memory—v1: Evaluate stable cuts so any difference is resolution, not a moving time envelope.
fn compare(shape: Shape) -> [usize; 3] {
    let rows = fixture(shape);
    let owner = install(&rows);
    let authority = MemoryV1SessionAuthority::new();
    authority.bind_to_root(&owner).unwrap();
    let mut results = [0; 3];
    for card in &rows.user_cards {
        let identity_card = rows
            .identity_cards
            .iter()
            .find(|row| row.user_id == card.user_id)
            .unwrap();
        let identity = CandidateIdentity {
            user_id: MemoryId::from_bytes(card.user_id),
            identity_card_id: MemoryId::from_bytes(identity_card.identity_card_id),
            user_card_id: MemoryId::from_bytes(card.user_card_id),
            tenant_id: MemoryId::from_bytes(card.tenant_id),
        };
        let issued = authority
            .identity_session_adapter()
            .issue_unchecked_for_test(identity, 100, 100)
            .unwrap();
        let scope = RequestRootScope::new(owner.handle(), Default::default());
        let root = scope.extension();
        let session = authority
            .verifier()
            .verify_and_bind(issued.credential(), 100, &root)
            .unwrap();
        let mut targets = vec![Target::None];
        for owner in [Some(USER), Some(OTHER_USER), None] {
            for tenant in [
                Some(PARENT),
                Some(CHILD),
                Some(GRANDCHILD),
                Some(SIBLING),
                None,
            ] {
                targets.push(Target::Object { owner, tenant });
            }
        }
        for target in targets {
            for action in ["read", "write"] {
                for at in [108, 109, 110, 111, 112, 115, 116, 118, 119, 120] {
                    let (target_id, target_owner, target_tenant) = match target {
                        Target::None => (None, None, None),
                        Target::Object { owner, tenant } => (
                            Some(TARGET_ID),
                            owner.map(|id| [id; 16]),
                            tenant.map(|id| [id; 16]),
                        ),
                    };
                    let request = MemoryV1Request {
                        resource: "document",
                        action,
                        target: target_id.as_ref().map(<[u8; 16]>::as_slice),
                        target_owner: target_owner.as_ref().map(<[u8; 16]>::as_slice),
                        target_tenant: target_tenant.as_ref().map(<[u8; 16]>::as_slice),
                        operation_id: b"fixture-op",
                        operation_fingerprint: b"fixture-fingerprint",
                    };
                    let expected = scan(&rows, card.user_card_id[0], target, action, at);
                    let actual = evaluate_with(&root, &session, &request, || Some(at), || {});
                    assert_eq!(
                        actual.decision, expected,
                        "{shape:?}, card={}, {target:?}, {action}, t={at}",
                        card.user_card_id[0]
                    );
                    assert_eq!(
                        actual.admission.is_some(),
                        expected == MemoryV1Decision::Allow
                    );
                    results[match expected {
                        MemoryV1Decision::Allow => 0,
                        MemoryV1Decision::Deny => 1,
                        MemoryV1Decision::Pending => 2,
                    }] += 1;
                }
            }
        }
    }
    results
}

// memory—v1: Run one deterministic non-winning dependency schedule.
fn changed_nonwinning_dependency(
    change: impl FnOnce(&RootOwner),
) -> (MemoryV1Decision, MemoryV1Decision) {
    let mut rows = fixture(Shape {
        size: 9,
        reverse: false,
        binding_descendants: true,
        rule_self: false,
        overlay_confirmed: true,
    });
    let overlay = rows
        .bindings
        .iter_mut()
        .find(|row| row.binding_id == [31; 16])
        .unwrap();
    overlay.valid_from = None;
    let miss = r#"{"rules":[{"ruleId":"nonmatching","resource":"pad_0","action":"read","effect":"DENY"}]}"#;
    *rows
        .rule_set_versions
        .iter_mut()
        .find(|row| row.rule_set_id == [21; 16])
        .unwrap() = version_row([21; 16], VERSION, miss);
    assert_eq!(
        scan(&rows, SUBJECT, Target::None, "read", 110),
        MemoryV1Decision::Allow
    );
    let owner = install(&rows);
    let authority = MemoryV1SessionAuthority::new();
    authority.bind_to_root(&owner).unwrap();
    let issued = t1_issue(&authority, SUBJECT);
    let request = MemoryV1Request {
        resource: "document",
        action: "read",
        target: None,
        target_tenant: None,
        target_owner: None,
        operation_id: b"nonwinning-check",
        operation_fingerprint: b"nonwinning-check-fingerprint",
    };
    let evaluate = |after_read: &mut dyn FnMut()| {
        let scope = RequestRootScope::new(owner.handle(), Default::default());
        let root = scope.extension();
        let session = authority
            .verifier()
            .verify_and_bind(issued.credential(), 110, &root)
            .unwrap();
        let result = evaluate_with(&root, &session, &request, || Some(110), after_read);
        assert_eq!(
            result.admission.is_some(),
            result.decision == MemoryV1Decision::Allow
        );
        result.decision
    };
    assert_eq!(evaluate(&mut || {}), MemoryV1Decision::Allow);
    let mut change = Some(change);
    let inflight = evaluate(&mut || change.take().unwrap()(&owner));
    assert!(
        change.is_none(),
        "the change must run after a positive candidate"
    );
    (inflight, evaluate(&mut || {}))
}

#[test]
fn a_nonmatching_binding_and_its_registry_pairs_remain_dependencies() {
    let (inflight, fresh) = changed_nonwinning_dependency(|owner| {
        let next = [3];
        let previous = owner.handle().metadata().unwrap();
        let after = owner
            .execute_mutation_with_precondition_for_isolated_tests(
                &ManagementMutationV2::VersionPublish {
                    rule_set_id: [21; 16],
                    version_row: version_row(
                        [21; 16],
                        &next,
                        &rule_content("current-deny", "DENY"),
                    ),
                    new_current_version: next.to_vec(),
                    change_confirmation: change_confirmation(54, 21, &next),
                },
                &MutationPrecondition {
                    evaluated_root_version: previous.version,
                },
            )
            .unwrap();
        assert_eq!(after.version, previous.version + 1);
    });
    assert_eq!(
        (inflight, fresh),
        (MemoryV1Decision::Pending, MemoryV1Decision::Deny)
    );

    let (inflight, fresh) = changed_nonwinning_dependency(|owner| {
        let before = owner.handle().metadata().unwrap();
        let registry_version = owner.registry_version();
        owner.request_registry_retirement_for_test("pad_0").unwrap();
        assert_eq!(owner.registry_version(), registry_version + 1);
        assert_eq!(owner.handle().metadata().unwrap(), before);
    });
    assert_eq!(
        (inflight, fresh),
        (MemoryV1Decision::Pending, MemoryV1Decision::Pending)
    );
    println!("nonwinning dependencies: 2 baseline ALLOW; version change yields PENDING/DENY; registry change yields PENDING/PENDING (in-flight/fresh)");
}

#[test]
fn held_reader_cannot_admit_after_owner_stops() {
    let rows = fixture(Shape {
        size: 8,
        reverse: false,
        binding_descendants: false,
        rule_self: true,
        overlay_confirmed: true,
    });
    let mut owner = Some(install(&rows));
    let authority = MemoryV1SessionAuthority::new();
    let installed = owner.as_ref().unwrap();
    authority.bind_to_root(installed).unwrap();
    let issued = t1_issue(&authority, SUBJECT);
    let scope = RequestRootScope::new(installed.handle(), Default::default());
    let root = scope.extension();
    let session = authority
        .verifier()
        .verify_and_bind(issued.credential(), 110, &root)
        .unwrap();
    let request = MemoryV1Request {
        resource: "document",
        action: "read",
        target: None,
        target_owner: None,
        target_tenant: None,
        operation_id: b"owner-stop",
        operation_fingerprint: b"owner-stop-fingerprint",
    };
    let baseline = evaluate_with(&root, &session, &request, || Some(110), || {});
    assert_eq!(baseline.decision, MemoryV1Decision::Allow);
    let result = evaluate_with(
        &root,
        &session,
        &request,
        || Some(110),
        || {
            drop(owner.take().expect("owner survives to the candidate"));
        },
    );
    assert!(
        owner.is_none(),
        "shutdown must occur between the candidate and final check"
    );
    assert_eq!(result.decision, MemoryV1Decision::Pending);
    assert!(result.admission.is_none());
    println!("owner stop: ALLOW control; candidate followed by owner drop returns PENDING without admission");
}

#[test]
fn indexed_policy_agrees_with_raw_row_scan() {
    let mut total = [0; 3];
    for size in [8, 9, 128, 129] {
        let mut counts = [0; 3];
        for reverse in [false, true] {
            for binding_descendants in [false, true] {
                for rule_self in [false, true] {
                    for overlay_confirmed in [false, true] {
                        let outcomes = compare(Shape {
                            size,
                            reverse,
                            binding_descendants,
                            rule_self,
                            overlay_confirmed,
                        });
                        for (count, cases) in counts.iter_mut().zip(outcomes) {
                            *count += cases;
                        }
                    }
                }
            }
        }
        assert_eq!(counts.iter().sum::<usize>(), 15_360);
        assert!(counts.iter().all(|count| *count > 0));
        for (count, cases) in total.iter_mut().zip(counts) {
            *count += cases;
        }
        println!(
            "complete observation: size={size}, allow={}, deny={}, pending={}",
            counts[0], counts[1], counts[2]
        );
    }
    assert_eq!(total.iter().sum::<usize>(), 61_440);
    println!(
        "complete observation: 61,440 comparisons, allow={}, deny={}, pending={}",
        total[0], total[1], total[2]
    );
}
