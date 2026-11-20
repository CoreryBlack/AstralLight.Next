//! memory—v1 paper envelope boundary differential (T2, integration).
//!
//! The time gate of the final check is compared with an oracle written from the paper's envelope
//! I_q = [T0, b) ∩ ⋂ W_e. The check runs against the real process root, request scope, and bound
//! session authority. The process root is one-shot, so each root-backed test runs in a child
//! process. No service, listener, database, queue, or migration is started.

use std::process::Command;

use astral_authorization_root::memory_v1_db_rows::{
    BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, CurrentSelection,
    IdentityCardRow, RuleSetChangeConfirmationRow, RuleSetRow, RuleSetStatus, RuleSetVersionRow,
    TenantRow, UserCardRow, UserCardStatus, UserRow,
};
use astral_authorization_root::memory_v1_hamt::CandidateBudget;
use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
use astral_authorization_root::memory_v1_request::RequestRootScope;
use astral_authorization_root::memory_v1_root::{
    install_process_root, DependencyRecord, EvaluationDependency, RootInstanceId, RootOwner,
};
use astral_authorization_root::memory_v1_rules::{
    canonical_version_bytes, version_digest, MemoryV1OwnerScope, MemoryV1TenantScope,
    MemoryV1Validity,
};
use astral_authorization_root::memory_v1_session::{FinalCheckTimeConstraints, FinalCheckWindow};
use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority;
use astral_types::memory_v1::{CandidateIdentity, MemoryId};

const CHILD_ENV: &str = "ASTRAL_MEMORY_V1_PAPER_ENVELOPE_CHILD";
const EMPTY_ENV: &str = "ASTRAL_MEMORY_V1_PAPER_EMPTY_WINDOW_SCENARIO";

/// memory—v1: The session is issued at 0 with the maximum lifetime, so it is valid on [0, 86400).
/// Samples at 86399 and 86400 check the session's own exclusive expiry against the same gate.
const SESSION_EXPIRES_AT: i64 = 86_400;
/// memory—v1: Trusted start times T0 for the final check.
const STARTS: [i64; 2] = [1000, 1003];
/// memory—v1: Future boundary sets. A boundary at or before the sample refuses the candidate.
const BOUNDARY_SETS: [&[i64]; 5] = [&[], &[1002], &[1006], &[1002, 1006], &[1000]];
/// memory—v1: Final samples. The set includes the start, both ends of each window, and session expiry.
const SAMPLES: [i64; 11] = [
    999, 1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 86_399, 86_400,
];

// memory—v1: Fixed-width identifier used by the fixture rows.
fn id(value: u8) -> [u8; 16] {
    [value; 16]
}

/// memory—v1: One winning-window candidate: an optional entry validity and a binding window.
#[derive(Clone, Copy)]
struct Window {
    entry: Option<(Option<i64>, Option<i64>)>,
    binding: (Option<i64>, Option<i64>),
}

/// memory—v1: Every window list used by the grid: empty, each single window, and each ordered pair.
/// The empty list must be refused by the time gate, so it is part of the grid.
fn window_grid() -> Vec<Vec<Window>> {
    let entries: [Option<(Option<i64>, Option<i64>)>; 4] = [
        None,
        Some((Some(1001), Some(1005))),
        Some((Some(1002), None)),
        Some((None, Some(1004))),
    ];
    let bindings: [(Option<i64>, Option<i64>); 3] =
        [(None, None), (Some(1001), Some(1005)), (Some(1003), None)];
    let singles: Vec<Window> = entries
        .iter()
        .flat_map(|entry| {
            bindings.iter().map(move |binding| Window {
                entry: *entry,
                binding: *binding,
            })
        })
        .collect();
    let mut lists = vec![Vec::new()];
    lists.extend(singles.iter().map(|window| vec![*window]));
    for first in &singles {
        for second in &singles {
            lists.push(vec![*first, *second]);
        }
    }
    lists
}

/// memory—v1: Whether a window `(from, until)` is active at `t`: `from` inclusive, `until` exclusive.
fn window_active(from: Option<i64>, until: Option<i64>, t: i64) -> bool {
    from.is_none_or(|from| from <= t) && until.is_none_or(|until| t < until)
}

/// memory—v1: The paper's envelope for the time gate, written independently of the implementation.
/// A sample is admitted iff it is at or after the trusted start, inside the session validity, before
/// every future boundary, and inside every winning window. An empty winning list is never admitted.
fn expected_admit(start: i64, boundaries: &[i64], windows: &[Window], t: i64) -> bool {
    t >= start
        && (0..SESSION_EXPIRES_AT).contains(&t)
        && boundaries.iter().all(|boundary| *boundary > t)
        && !windows.is_empty()
        && windows.iter().all(|window| {
            window
                .entry
                .is_none_or(|(from, until)| window_active(from, until, t))
                && window_active(window.binding.0, window.binding.1, t)
        })
}

/// memory—v1: Convert one grid window into the final-check input type.
fn final_window(window: &Window) -> FinalCheckWindow {
    FinalCheckWindow {
        entry_validity: window
            .entry
            .map(|(from, until)| MemoryV1Validity { from, until }),
        binding_from: window.binding.0,
        binding_until: window.binding.1,
    }
}

/// memory—v1: Candidate rows for one ALLOW rule set bound to one card, with the given binding window
/// and rule content. Both the binding and the rule content are supplied by the caller so that the
/// empty-window scenarios can reuse the fixture.
#[allow(clippy::needless_update)] // memory—v1: CandidateRows gains rows over time; base stays default
fn rows(binding: (Option<i64>, Option<i64>), content: &str) -> CandidateRows {
    let version_bytes = vec![1];
    let timestamp_bytes = vec![2];
    let input = canonical_version_bytes(&version_bytes, content.as_bytes(), &timestamp_bytes);
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
            status: RuleSetStatus::Active,
            rule_set_id: id(10),
            owner_tenant_id: id(3),
            current_version_bytes: version_bytes.clone(),
        }],
        rule_set_versions: vec![RuleSetVersionRow {
            rule_set_id: id(10),
            version_bytes: version_bytes.clone(),
            content_bytes: content.as_bytes().to_vec(),
            timestamp_bytes: timestamp_bytes.clone(),
            hash_bytes: version_digest(&input),
            hash_input_bytes: input,
        }],
        bindings: vec![BindingRow {
            binding_id: id(20),
            user_card_id: id(4),
            rule_set_id: id(10),
            binding_layer: BindingLayer::Base,
            valid_from: binding.0,
            valid_until: binding.1,
            owner_scope: MemoryV1OwnerScope::AllUsers,
            tenant_scope: MemoryV1TenantScope::SelfTenant,
            removed_at: None,
            removed_by: None,
        }],
        binding_confirmations: vec![BindingConfirmationRow {
            confirmation_id: id(40),
            binding_id: id(20),
            rule_set_id: id(10),
            version_bytes: version_bytes.clone(),
            confirmer_user_id: id(1),
            scope_bytes: vec![1],
            operation_id: vec![40],
            confirmed_at_bytes: vec![1],
            revoked_at: None,
            revoked_by: None,
        }],
        rule_set_change_confirmations: vec![RuleSetChangeConfirmationRow {
            confirmation_id: id(50),
            rule_set_id: id(10),
            version_bytes: version_bytes.clone(),
            confirmer_user_id: id(1),
            affected_scope_bytes: vec![1],
            operation_id: vec![50],
            confirmed_at_bytes: vec![1],
            revoked_at: None,
            revoked_by: None,
        }],
        // memory—v1: remaining rows are defaults; all consumed fields are set above.
        ..CandidateRows::default()
    }
}

/// memory—v1: The fixture rule content for the time-gate grid: one ALLOW rule without validity.
const OPEN_CONTENT: &str =
    r#"{"rules":[{"ruleId":"R","resource":"document","action":"read","effect":"ALLOW"}]}"#;

/// memory—v1: Install the fixture as the serving root with the same registry the rules use.
fn install(candidate: CandidateRows) -> Result<RootOwner, String> {
    let selections = vec![CurrentSelection {
        rule_set_id: id(10),
        version_bytes: vec![1],
    }];
    install_process_root(
        candidate,
        selections,
        CandidateBudget {
            max_table_rows: 128,
            max_bindings_per_read: 16,
        },
    )
    .map_err(|error| format!("{error:?}"))
}

/// memory—v1: The grid fixture: an open binding and the open ALLOW rule, adopted as serving.
fn fixture() -> (RootOwner, MemoryV1SessionAuthority) {
    let owner = install(rows((None, None), OPEN_CONTENT)).expect("the open fixture installs");
    owner
        .install_registry(&[RegistryDeclaration {
            resource: "document".to_owned(),
            actions: vec!["read".to_owned()],
        }])
        .expect("the fixture registry installs");
    owner
        .adopt_serving_for_isolated_tests()
        .expect("the fixture becomes serving");
    let authority = MemoryV1SessionAuthority::new();
    authority
        .bind_to_root(&owner)
        .expect("the session authority binds to the fixture root");
    (owner, authority)
}

/// memory—v1: The principal whose identity matches the fixture's user card.
// memory—v1: The principal whose identity matches card 4.
fn principal() -> CandidateIdentity {
    CandidateIdentity {
        user_id: MemoryId::from_bytes(id(1)),
        identity_card_id: MemoryId::from_bytes(id(2)),
        user_card_id: MemoryId::from_bytes(id(4)),
        tenant_id: MemoryId::from_bytes(id(3)),
    }
}

/// memory—v1: Run one isolated test in a child process with the given environment label.
fn run_isolated(test_name: &str, env: &str, label: &str) {
    let output = Command::new(std::env::current_exe().expect("test executable exists"))
        .args(["--exact", test_name, "--nocapture"])
        .env(env, label)
        .output()
        .expect("start the isolated envelope test");
    assert!(
        output.status.success(),
        "isolated envelope test {label} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "isolated envelope test {label} did not report one passing test"
    );
}

/// memory—v1: The final check's time gate matches the paper's envelope on every grid point. The
/// grid covers two trusted starts, five boundary sets, 157 window lists (including empty and every
/// ordered pair), and eleven samples that include the start, every window end, and session expiry.
/// Both admissions and refusals must occur, so the grid is not vacuous.
#[test]
fn paper_envelope_final_check_time_gate_matches_closed_form() {
    if std::env::var_os(CHILD_ENV).is_none() {
        run_isolated(
            "paper_envelope_final_check_time_gate_matches_closed_form",
            CHILD_ENV,
            "1",
        );
        return;
    }
    let (owner, authority) = fixture();
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let issued = authority
        .identity_session_adapter()
        .issue_unchecked_for_test(principal(), 0, SESSION_EXPIRES_AT)
        .expect("the grid session issues");
    let session = authority
        .verifier()
        .verify_and_bind(issued.credential(), 0, &root)
        .expect("the grid session binds");
    let grid = window_grid();
    assert_eq!(
        grid.len(),
        157,
        "empty list, 12 singles, and 144 ordered pairs"
    );
    let mut checks = 0_usize;
    let mut admitted = 0_usize;
    for start in STARTS {
        for boundaries in BOUNDARY_SETS {
            for windows in &grid {
                for sample in SAMPLES {
                    let expected = expected_admit(start, boundaries, windows, sample);
                    let actual = session
                        .with_authoritative_context(&root, |_, reader, final_check| {
                            let (tenant_tree_version, registry_version) = reader
                                .dependency_versions()
                                .expect("the fixture root reports dependency versions");
                            let record = DependencyRecord {
                                card_id: id(4),
                                instance_id: reader.metadata().instance_id,
                                bindings: vec![EvaluationDependency {
                                    binding_id: id(20),
                                    rule_set_id: id(10),
                                    version_bytes: vec![1],
                                }],
                                tenant_tree_version,
                                registry_version,
                            };
                            let final_windows: Vec<FinalCheckWindow> =
                                windows.iter().map(final_window).collect();
                            let constraints = FinalCheckTimeConstraints {
                                start_time: start,
                                future_boundaries: boundaries,
                                winning_windows: &final_windows,
                            };
                            final_check
                                .expect("the bound session carries a final check")
                                .try_final_time_for_test(&record, &constraints, || Some(sample))
                        })
                        .expect("the request scope matches the session");
                    assert_eq!(
                        actual,
                        expected.then_some(sample),
                        "time gate mismatch: start={start} boundaries={boundaries:?} sample={sample} windows={}",
                        windows.len()
                    );
                    checks += 1;
                    admitted += usize::from(expected);
                }
            }
        }
    }
    assert!(
        admitted > 0 && admitted < checks,
        "the grid must exercise both admissions and refusals"
    );
    println!("T2 envelope time gate: checks={checks} admitted={admitted}");
}

/// memory—v1: Empty windows are outside the grid because no serving root can carry them. An empty
/// binding window is refused at candidate build (`InvalidBindingWindow`). An empty rule-entry
/// validity is accepted into the candidate row set, because build does not parse unselected
/// content, but adoption parses the selected version and refuses it before any serving read, so
/// that case is checked at adoption.
#[test]
fn paper_empty_windows_are_refused_at_install() {
    if let Ok(label) = std::env::var(EMPTY_ENV) {
        let refusal = match label.as_str() {
            "binding" => install(rows((Some(1005), Some(1005)), OPEN_CONTENT))
                .err()
                .map(|error| format!("install: {error}")),
            "entry" => {
                let owner = install(rows(
                    (None, None),
                    r#"{"rules":[{"ruleId":"R","resource":"document","action":"read","effect":"ALLOW","validity":{"from":1005,"until":1005}}]}"#,
                ))
                .expect("an empty entry validity is not refused at candidate build");
                owner
                    .adopt_serving_for_isolated_tests()
                    .err()
                    .map(|error| format!("adopt: {error:?}"))
            }
            other => panic!("unknown empty-window scenario {other}"),
        };
        let refusal = refusal.expect("an empty window must not become serving");
        println!("empty window {label} refused at {refusal}");
        return;
    }
    for label in ["binding", "entry"] {
        run_isolated(
            "paper_empty_windows_are_refused_at_install",
            EMPTY_ENV,
            label,
        );
    }
}

const KEYS_ENV: &str = "ASTRAL_MEMORY_V1_PAPER_DEPENDENCY_KEYS_CHILD";

/// memory—v1: The single-card fixture plus three valid neighbours: a second active card of the same
/// user and tenant (card 5), a second binding of rule set 10 that belongs to that card (binding 21),
/// and a second active rule set (11) with its own selected version. Every neighbour passes the
/// root's own checks. A record that names a neighbour in place of the object it should name is
/// therefore refused only because the neighbour is not the object the session, binding or rule set
/// recorded, and not because the neighbour is malformed.
fn neighbour_rows() -> CandidateRows {
    let mut candidate = rows((None, None), OPEN_CONTENT);
    candidate.user_cards.push(UserCardRow {
        user_card_id: id(5),
        user_id: id(1),
        tenant_id: id(3),
        status: UserCardStatus::Active,
    });
    let mut second_binding = candidate.bindings[0].clone();
    second_binding.binding_id = id(21);
    second_binding.user_card_id = id(5);
    candidate.bindings.push(second_binding);
    let mut second_confirmation = candidate.binding_confirmations[0].clone();
    second_confirmation.confirmation_id = id(41);
    second_confirmation.binding_id = id(21);
    second_confirmation.operation_id = vec![41];
    candidate.binding_confirmations.push(second_confirmation);
    let version_bytes = vec![1];
    let timestamp_bytes = vec![2];
    let input = canonical_version_bytes(&version_bytes, OPEN_CONTENT.as_bytes(), &timestamp_bytes);
    candidate.rule_sets.push(RuleSetRow {
        status: RuleSetStatus::Active,
        rule_set_id: id(11),
        owner_tenant_id: id(3),
        current_version_bytes: version_bytes.clone(),
    });
    candidate.rule_set_versions.push(RuleSetVersionRow {
        rule_set_id: id(11),
        version_bytes,
        content_bytes: OPEN_CONTENT.as_bytes().to_vec(),
        timestamp_bytes,
        hash_bytes: version_digest(&input),
        hash_input_bytes: input,
    });
    let mut change_confirmation = candidate.rule_set_change_confirmations[0].clone();
    change_confirmation.confirmation_id = id(51);
    change_confirmation.rule_set_id = id(11);
    change_confirmation.operation_id = vec![51];
    candidate
        .rule_set_change_confirmations
        .push(change_confirmation);
    candidate
}

/// memory—v1: One edit of an otherwise consistent dependency record, with the expected outcome of
/// the final check. `admitted` is false when the edited field must refuse the candidate.
struct RecordCase {
    label: &'static str,
    admitted: bool,
    edit: fn(&mut DependencyRecord),
}

/// memory—v1: The record cases. The control is the record that the reader would produce for card 4.
/// Each other case changes one field (or one pair that must change together to stay valid) and names
/// a real neighbour from `neighbour_rows`, so a mutation that removes the matching comparison from
/// the final check changes the outcome of exactly that case.
fn record_cases() -> Vec<RecordCase> {
    vec![
        RecordCase {
            label: "consistent record (control)",
            admitted: true,
            edit: |_| {},
        },
        RecordCase {
            label: "record omits its bindings: the root re-derives the actor card's bindings",
            admitted: true,
            edit: |record| record.bindings.clear(),
        },
        RecordCase {
            label: "record names another active card of the same user",
            admitted: false,
            edit: |record| {
                record.card_id = id(5);
                record.bindings[0].binding_id = id(21);
            },
        },
        RecordCase {
            label: "recorded binding belongs to another card",
            admitted: false,
            edit: |record| record.bindings[0].binding_id = id(21),
        },
        RecordCase {
            label: "recorded binding names another rule set",
            admitted: false,
            edit: |record| record.bindings[0].rule_set_id = id(11),
        },
        RecordCase {
            label: "recorded version is not the selected version",
            admitted: false,
            edit: |record| record.bindings[0].version_bytes = vec![2],
        },
        RecordCase {
            label: "recorded binding does not exist",
            admitted: false,
            edit: |record| record.bindings[0].binding_id = id(99),
        },
        RecordCase {
            // memory—v1: The nil UUID is never a process root instance, which is random version 4.
            label: "record is bound to another root instance",
            admitted: false,
            edit: |record| record.instance_id = RootInstanceId::from_uuid(Default::default()),
        },
        RecordCase {
            label: "stale tenant-tree version",
            admitted: false,
            edit: |record| record.tenant_tree_version += 1,
        },
        RecordCase {
            label: "stale registry version",
            admitted: false,
            edit: |record| record.registry_version += 1,
        },
        RecordCase {
            label: "exhausted tenant-tree version",
            admitted: false,
            edit: |record| record.tenant_tree_version = u64::MAX,
        },
        RecordCase {
            label: "exhausted registry version",
            admitted: false,
            edit: |record| record.registry_version = u64::MAX,
        },
    ]
}

/// memory—v1: Each identity key of the final check refuses a record that disagrees with the root.
/// The T2 grid varies time and always hands the check a consistent record. This test holds time at
/// an admitting sample and edits the record instead: the candidate card, the recorded binding's
/// owner card and rule set, the recorded selected version, the root instance, and the two global
/// versions. The control and the bindings-omitted case must be admitted, so a refusal is
/// attributable to the edited field.
/// The first mutation analysis of the production final check found that no earlier test refused
/// these records.
#[test]
fn paper_final_check_refuses_each_inconsistent_dependency_key() {
    if std::env::var_os(KEYS_ENV).is_none() {
        run_isolated(
            "paper_final_check_refuses_each_inconsistent_dependency_key",
            KEYS_ENV,
            "1",
        );
        return;
    }
    let owner = install_process_root(
        neighbour_rows(),
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
        CandidateBudget {
            max_table_rows: 128,
            max_bindings_per_read: 16,
        },
    )
    .expect("the neighbour fixture installs");
    owner
        .install_registry(&[RegistryDeclaration {
            resource: "document".to_owned(),
            actions: vec!["read".to_owned()],
        }])
        .expect("the fixture registry installs");
    owner
        .adopt_serving_for_isolated_tests()
        .expect("the neighbour fixture becomes serving");
    let authority = MemoryV1SessionAuthority::new();
    authority
        .bind_to_root(&owner)
        .expect("the session authority binds to the fixture root");
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let issued = authority
        .identity_session_adapter()
        .issue_unchecked_for_test(principal(), 0, SESSION_EXPIRES_AT)
        .expect("the session for card 4 issues");
    let session = authority
        .verifier()
        .verify_and_bind(issued.credential(), 0, &root)
        .expect("the session for card 4 binds");
    let sample = 1001;
    let open_window = [FinalCheckWindow {
        entry_validity: None,
        binding_from: None,
        binding_until: None,
    }];
    let mut admitted = 0_usize;
    let cases = record_cases();
    for case in &cases {
        let actual = session
            .with_authoritative_context(&root, |_, reader, final_check| {
                let (tenant_tree_version, registry_version) = reader
                    .dependency_versions()
                    .expect("the fixture root reports dependency versions");
                let mut record = DependencyRecord {
                    card_id: id(4),
                    instance_id: reader.metadata().instance_id,
                    bindings: vec![EvaluationDependency {
                        binding_id: id(20),
                        rule_set_id: id(10),
                        version_bytes: vec![1],
                    }],
                    tenant_tree_version,
                    registry_version,
                };
                (case.edit)(&mut record);
                let constraints = FinalCheckTimeConstraints {
                    start_time: 1000,
                    future_boundaries: &[],
                    winning_windows: &open_window,
                };
                final_check
                    .expect("the bound session carries a final check")
                    .try_final_time_for_test(&record, &constraints, || Some(sample))
            })
            .expect("the request scope matches the session");
        assert_eq!(
            actual,
            case.admitted.then_some(sample),
            "dependency record case `{}`",
            case.label
        );
        admitted += usize::from(case.admitted);
    }
    assert!(
        admitted == 2 && admitted < cases.len(),
        "the control and the bindings-omitted case are admitted and every other case is refused"
    );
    println!(
        "T2 dependency keys: cases={} admitted={admitted} refused={}",
        cases.len(),
        cases.len() - admitted
    );
}
