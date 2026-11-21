//! memory—v1 paper writer coverage (T1 public surface and T3 source pin, integration).
//!
//! Three properties are checked against the real process root, request scope, and session authority.
//! First, every management mutation variant is refused on the public serving path, and the decision
//! of the bound session does not change. Second, the one public writer that changes serving state,
//! the card-disable coordinator, is gated by the bound authority and the exact serving metadata, and
//! a successful disable changes the decision of the affected card only. Third, a source pin scans
//! the workspace and pins the production opener to the governed root preparation path.
//! Root-backed tests run in child processes because the process root is one-shot. No service,
//! listener, database, queue, or migration is started.
//!
//! A fourth test drives the exact-root final check, which governance commits use. It holds the
//! record and the clock fixed and shows that a request snapshot older than the expected root is
//! refused, although the ordinary check admits the same snapshot.
//!
//! A fifth test opens a modification fence on the rule set of the subject's active binding and shows
//! that the ordinary and the exact-root final checks refuse while the fence is open and admit again
//! once it is closed without publishing. The isolated test controls the window independently
//! of the production commit owner so a publication cannot mask this check.
//!
//! A sixth test revokes the subject's session between the request and the final check, by credential
//! and by user card, and shows that both final checks refuse while a session issued afterwards for the
//! same card is admitted.
//!
//! The source pin checks ownership of the production call; the read-side tests
//! do not replace end-to-end coverage of the durable commit owner.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use astral_authorization_root::memory_v1_db_rows::{
    BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, CurrentSelection,
    IdentityCardRow, RuleSetChangeConfirmationRow, RuleSetRow, RuleSetStatus, RuleSetVersionRow,
    TenantRow, UserCardRow, UserCardStatus, UserRow,
};
use astral_authorization_root::memory_v1_fence::FenceDeclaration;
use astral_authorization_root::memory_v1_hamt::CandidateBudget;
use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
use astral_authorization_root::memory_v1_request::{RequestRootExtension, RequestRootScope};
use astral_authorization_root::memory_v1_root::{
    install_process_root, DependencyRecord, EvaluationDependency, ManagementMutationV2,
    MutationError, MutationPrecondition, RequestRootReader, RootMetadata, RootOwner,
};
use astral_authorization_root::memory_v1_rules::{
    canonical_version_bytes, version_digest, MemoryV1OwnerScope, MemoryV1TenantScope,
};
use astral_authorization_root::memory_v1_session::{
    FinalCheckTimeConstraints, FinalCheckWindow, RequestSessionExtension,
};
use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority;
use astral_types::memory_v1::{CandidateIdentity, MemoryId};
use policy_engine::memory_v1_formal::{MemoryV1Decision, MemoryV1Request};
use policy_engine::PolicyEngine;

const CHILD_ENV: &str = "ASTRAL_MEMORY_V1_PAPER_WRITER_CHILD";
const REFUSAL_TEST: &str = "paper_public_writers_are_refused_on_serving_root";
const COORDINATOR_TEST: &str = "paper_card_disable_coordinator_gates_and_advances";
/// memory—v1: Only governed root preparation may call the owned production opener.
const FENCE_OPENERS: [&str; 2] = ["begin_modification_fence", "begin_owned_modification_fence"];

// memory—v1: Fixed-width identifier used by the fixture rows.
fn id(value: u8) -> [u8; 16] {
    [value; 16]
}

// memory—v1: Wall-clock seconds for session issuance and binding.
fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after unix epoch")
            .as_secs(),
    )
    .expect("test clock fits in i64")
}

/// memory—v1: The single ALLOW rule of the fixture, without owner or tenant scope.
const OPEN_CONTENT: &str =
    r#"{"rules":[{"ruleId":"R","resource":"document","action":"read","effect":"ALLOW"}]}"#;

/// memory—v1: Build a version row with a digest that matches its canonical input.
fn version_row(rule_set: u8, version: Vec<u8>, content: &str) -> RuleSetVersionRow {
    let timestamp = vec![2];
    let input = canonical_version_bytes(&version, content.as_bytes(), &timestamp);
    RuleSetVersionRow {
        rule_set_id: id(rule_set),
        version_bytes: version,
        content_bytes: content.as_bytes().to_vec(),
        timestamp_bytes: timestamp,
        hash_bytes: version_digest(&input),
        hash_input_bytes: input,
    }
}

// memory—v1: Active rule-set row for the writer fixture.
fn rule_set_row(rule_set: u8, current: Vec<u8>) -> RuleSetRow {
    RuleSetRow {
        status: RuleSetStatus::Active,
        rule_set_id: id(rule_set),
        owner_tenant_id: id(3),
        current_version_bytes: current,
    }
}

// memory—v1: Active change confirmation for one rule-set version.
fn change_confirmation(
    confirmation: u8,
    rule_set: u8,
    version: Vec<u8>,
) -> RuleSetChangeConfirmationRow {
    RuleSetChangeConfirmationRow {
        confirmation_id: id(confirmation),
        rule_set_id: id(rule_set),
        version_bytes: version,
        confirmer_user_id: id(1),
        affected_scope_bytes: vec![1],
        operation_id: vec![confirmation],
        confirmed_at_bytes: vec![1],
        revoked_at: None,
        revoked_by: None,
    }
}

// memory—v1: Base binding row with the fixture's shared scopes.
fn binding_row(binding: u8, card: u8, rule_set: u8) -> BindingRow {
    BindingRow {
        binding_id: id(binding),
        user_card_id: id(card),
        rule_set_id: id(rule_set),
        binding_layer: BindingLayer::Base,
        valid_from: None,
        valid_until: None,
        owner_scope: MemoryV1OwnerScope::AllUsers,
        tenant_scope: MemoryV1TenantScope::SelfTenant,
        removed_at: None,
        removed_by: None,
    }
}

// memory—v1: Active binding confirmation for one binding and version.
fn binding_confirmation(
    confirmation: u8,
    binding: u8,
    rule_set: u8,
    version: Vec<u8>,
) -> BindingConfirmationRow {
    BindingConfirmationRow {
        confirmation_id: id(confirmation),
        binding_id: id(binding),
        rule_set_id: id(rule_set),
        version_bytes: version,
        confirmer_user_id: id(1),
        scope_bytes: vec![1],
        operation_id: vec![confirmation],
        confirmed_at_bytes: vec![1],
        revoked_at: None,
        revoked_by: None,
    }
}

// memory—v1: User card row in the fixture user and tenant.
fn user_card(card: u8, status: UserCardStatus) -> UserCardRow {
    UserCardRow {
        user_card_id: id(card),
        user_id: id(1),
        tenant_id: id(3),
        status,
    }
}

/// memory—v1: Two active cards: card 4 is the session's subject, card 8 is unrelated. Both bind the
/// same ALLOW rule set, so the decision of card 4 is the subject decision and the card-8 writes are
/// unrelated writes.
#[allow(clippy::needless_update)] // memory—v1: CandidateRows gains rows over time; base stays default
fn fixture() -> (RootOwner, MemoryV1SessionAuthority) {
    let version = vec![1];
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
        user_cards: vec![
            user_card(4, UserCardStatus::Active),
            user_card(8, UserCardStatus::Active),
        ],
        rule_sets: vec![rule_set_row(10, version.clone())],
        rule_set_versions: vec![version_row(10, version.clone(), OPEN_CONTENT)],
        bindings: vec![binding_row(20, 4, 10), binding_row(21, 8, 10)],
        binding_confirmations: vec![
            binding_confirmation(40, 20, 10, version.clone()),
            binding_confirmation(41, 21, 10, version.clone()),
        ],
        rule_set_change_confirmations: vec![change_confirmation(50, 10, version.clone())],
        // memory—v1: remaining rows are defaults; all consumed fields are set above.
        ..CandidateRows::default()
    };
    let owner = install_process_root(
        rows,
        vec![CurrentSelection {
            rule_set_id: id(10),
            version_bytes: version,
        }],
        CandidateBudget {
            max_table_rows: 128,
            max_bindings_per_read: 16,
        },
    )
    .expect("the writer fixture root installs");
    owner
        .install_registry(&[RegistryDeclaration {
            resource: "document".to_owned(),
            actions: vec!["read".to_owned()],
        }])
        .expect("the writer fixture registry installs");
    owner
        .adopt_serving_for_isolated_tests()
        .expect("the writer fixture becomes serving");
    let authority = MemoryV1SessionAuthority::new();
    authority
        .bind_to_root(&owner)
        .expect("the session authority binds to the writer fixture root");
    (owner, authority)
}

// memory—v1: The principal whose identity matches card 4.
fn principal() -> CandidateIdentity {
    CandidateIdentity {
        user_id: MemoryId::from_bytes(id(1)),
        identity_card_id: MemoryId::from_bytes(id(2)),
        user_card_id: MemoryId::from_bytes(id(4)),
        tenant_id: MemoryId::from_bytes(id(3)),
    }
}

/// memory—v1: Issue and bind the subject's session at the current wall clock.
fn subject_session(
    authority: &MemoryV1SessionAuthority,
    root: &RequestRootExtension,
) -> RequestSessionExtension {
    let issued = authority
        .identity_session_adapter()
        .issue_unchecked_for_test(principal(), now() - 60, 3_600)
        .expect("the subject session issues");
    authority
        .verifier()
        .verify_and_bind(issued.credential(), now(), root)
        .expect("the subject session binds")
}

// memory—v1: The document read request used for every sequential decision.
fn read_request() -> MemoryV1Request<'static> {
    MemoryV1Request {
        resource: "document",
        action: "read",
        target: None,
        target_tenant: None,
        target_owner: None,
        operation_id: b"writer-op",
        operation_fingerprint: b"writer-fp",
    }
}

// memory—v1: The subject decision of the bound session on the serving root.
fn decision(
    engine: &PolicyEngine,
    root: &RequestRootExtension,
    session: &RequestSessionExtension,
) -> MemoryV1Decision {
    engine
        .evaluate_memory_v1(root, session, &read_request())
        .decision
}

/// memory—v1: One representative mutation for every variant of the management enum. Each payload is
/// well formed for the fixture so that a refusal cannot be attributed to a malformed row.
fn mutations() -> Vec<(&'static str, ManagementMutationV2)> {
    vec![
        (
            "BindingCreate",
            ManagementMutationV2::BindingCreate {
                row: binding_row(30, 4, 10),
                confirmation: binding_confirmation(42, 30, 10, vec![1]),
            },
        ),
        (
            "BindingRemove",
            ManagementMutationV2::BindingRemove {
                binding_id: id(20),
                removed_at: 50,
                removed_by: id(1),
            },
        ),
        (
            "ConfirmationCreate",
            ManagementMutationV2::ConfirmationCreate {
                row: binding_confirmation(43, 20, 10, vec![1]),
            },
        ),
        (
            "ConfirmationRevoke",
            ManagementMutationV2::ConfirmationRevoke {
                confirmation_id: id(40),
                revoked_at: 50,
                revoked_by: id(1),
            },
        ),
        (
            "RuleSetChangeConfirmationRevoke",
            ManagementMutationV2::RuleSetChangeConfirmationRevoke {
                confirmation_id: id(50),
                revoked_at: 50,
                revoked_by: id(1),
            },
        ),
        (
            "ConfirmationBatch",
            ManagementMutationV2::ConfirmationBatch {
                rows: vec![binding_confirmation(44, 20, 10, vec![1])],
            },
        ),
        (
            "UserCardCreate",
            ManagementMutationV2::UserCardCreate {
                row: user_card(9, UserCardStatus::Active),
            },
        ),
        (
            "UserCardStatus",
            ManagementMutationV2::UserCardStatus {
                user_card_id: id(8),
                status: UserCardStatus::Disabled,
            },
        ),
        (
            "RuleSetCreate",
            ManagementMutationV2::RuleSetCreate {
                rule_set: rule_set_row(12, vec![1]),
                version: version_row(12, vec![1], OPEN_CONTENT),
                change_confirmation: change_confirmation(52, 12, vec![1]),
            },
        ),
        (
            "RuleSetRetire",
            ManagementMutationV2::RuleSetRetire {
                rule_set_id: id(10),
            },
        ),
        (
            "VersionPublish",
            ManagementMutationV2::VersionPublish {
                rule_set_id: id(10),
                version_row: version_row(10, vec![2], OPEN_CONTENT),
                new_current_version: vec![2],
                change_confirmation: change_confirmation(53, 10, vec![2]),
            },
        ),
    ]
}

/// memory—v1: Run one root-backed test in a child process. The label selects the child body.
fn run_child(test_name: &str, label: &str) {
    let output = Command::new(std::env::current_exe().expect("test executable exists"))
        .args(["--exact", test_name, "--nocapture"])
        .env(CHILD_ENV, label)
        .output()
        .expect("start the isolated writer test");
    assert!(
        output.status.success(),
        "isolated writer test {label} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "isolated writer test {label} did not report one passing test"
    );
}

/// memory—v1 (T1 public): Every management variant is refused on the public serving path, through both
/// the owner entry and the mutation executor, with `ConcurrentModification`. The version does not move,
/// and the bound session's decision stays `Allow` after each refusal. A card-disable request is refused
/// by the same serving check, so the coordinator error is not reached through this path.
#[test]
fn paper_public_writers_are_refused_on_serving_root() {
    if std::env::var(CHILD_ENV).as_deref() != Ok("refusal") {
        run_child(REFUSAL_TEST, "refusal");
        return;
    }
    let all = mutations();
    assert_eq!(all.len(), 11, "one representative per management variant");
    let (owner, authority) = fixture();
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let session = subject_session(&authority, &root);
    let engine = PolicyEngine::new();
    assert_eq!(decision(&engine, &root, &session), MemoryV1Decision::Allow);

    for (name, mutation) in &all {
        let before = owner.handle().metadata().expect("serving metadata");
        let precondition = MutationPrecondition {
            evaluated_root_version: before.version,
        };
        let via_owner = owner.execute_mutation_with_precondition(mutation, &precondition);
        assert!(
            matches!(via_owner, Err(MutationError::ConcurrentModification)),
            "{name} via owner must be refused on the serving path, got {via_owner:?}"
        );
        let via_executor = owner.mutation_executor().execute(mutation, &precondition);
        assert!(
            matches!(via_executor, Err(MutationError::ConcurrentModification)),
            "{name} via executor must be refused on the serving path, got {via_executor:?}"
        );
        let after = owner.handle().metadata().expect("serving metadata");
        assert_eq!(
            after, before,
            "{name} refusal must not move the serving root"
        );
        assert_eq!(
            decision(&engine, &root, &session),
            MemoryV1Decision::Allow,
            "the decision must hold after the refused {name}"
        );
    }
    println!("public writer refusals: variants={}", all.len());
}

/// memory—v1 (T1 public coordinator): The card-disable coordinator is the only public path that changes
/// serving state. It refuses an unbound authority and stale metadata with `ConcurrentModification`. With
/// the bound authority and current metadata it advances the version. A disable of the unrelated card 8
/// leaves the subject decision at `Allow`; a disable of the subject card 4 moves it off `Allow`.
#[test]
fn paper_card_disable_coordinator_gates_and_advances() {
    if std::env::var(CHILD_ENV).as_deref() != Ok("coordinator") {
        run_child(COORDINATOR_TEST, "coordinator");
        return;
    }
    let (owner, authority) = fixture();
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let session = subject_session(&authority, &root);
    let engine = PolicyEngine::new();
    assert_eq!(decision(&engine, &root, &session), MemoryV1Decision::Allow);

    let before = owner.handle().metadata().expect("serving metadata");
    let stranger = MemoryV1SessionAuthority::new();
    let unbound = owner.mutation_executor().disable_card_with_session_updates(
        &stranger,
        id(8),
        before,
        || {},
    );
    assert!(
        matches!(unbound, Err(MutationError::ConcurrentModification)),
        "an authority not bound to this root must be refused, got {unbound:?}"
    );
    let stale = RootMetadata {
        version: before.version.wrapping_add(1),
        ..before
    };
    let stale_result = owner.mutation_executor().disable_card_with_session_updates(
        &authority,
        id(8),
        stale,
        || {},
    );
    assert!(
        matches!(stale_result, Err(MutationError::ConcurrentModification)),
        "stale expected metadata must be refused, got {stale_result:?}"
    );
    assert_eq!(owner.handle().metadata().expect("serving metadata"), before);
    assert_eq!(decision(&engine, &root, &session), MemoryV1Decision::Allow);

    let unrelated = owner
        .mutation_executor()
        .disable_card_with_session_updates(&authority, id(8), before, || {})
        .expect("the bound coordinator disables the unrelated card");
    assert_eq!(
        unrelated.version,
        before.version + 1,
        "an accepted coordinator write advances the version by one"
    );
    assert_eq!(
        decision(&engine, &root, &session),
        MemoryV1Decision::Allow,
        "disabling the unrelated card must not change the subject decision"
    );

    let subject = owner
        .mutation_executor()
        .disable_card_with_session_updates(&authority, id(4), unrelated, || {})
        .expect("the bound coordinator disables the subject card");
    assert_eq!(subject.version, unrelated.version + 1);
    assert_ne!(
        decision(&engine, &root, &session),
        MemoryV1Decision::Allow,
        "disabling the subject card must move the decision off Allow"
    );
    println!(
        "coordinator: unrelated_version={} subject_version={}",
        unrelated.version, subject.version
    );
}

const EXACT_ROOT_TEST: &str = "paper_exact_root_check_refuses_a_stale_request_snapshot";

/// memory—v1: The dependency record that the reader would produce for card 4 on this fixture.
fn subject_record(reader: &RequestRootReader) -> DependencyRecord {
    let (tenant_tree_version, registry_version) = reader
        .dependency_versions()
        .expect("the fixture root reports dependency versions");
    DependencyRecord {
        card_id: id(4),
        instance_id: reader.metadata().instance_id,
        bindings: vec![EvaluationDependency {
            binding_id: id(20),
            rule_set_id: id(10),
            version_bytes: vec![1],
        }],
        tenant_tree_version,
        registry_version,
    }
}

/// memory—v1 (V3, exact root): The exact-root final check compares the expected root metadata with
/// both the request snapshot and the live root. An unrelated card disable advances the root while
/// every identity that card 4 depends on stays unchanged, so the ordinary check admits the stale
/// snapshot and only the exact-root equality can refuse it. The cases hold the record, the target
/// rule set and the clock fixed. A request that begins after the write is the control and is
/// admitted. A stale request is refused whether the expected metadata is its own snapshot or the
/// live root. The first mutation analysis found that no earlier test refused the second case.
#[test]
fn paper_exact_root_check_refuses_a_stale_request_snapshot() {
    if std::env::var(CHILD_ENV).as_deref() != Ok("exact-root") {
        run_child(EXACT_ROOT_TEST, "exact-root");
        return;
    }
    let (owner, authority) = fixture();
    let sample = now();
    let open_window = [FinalCheckWindow {
        entry_validity: None,
        binding_from: None,
        binding_until: None,
    }];
    let constraints = FinalCheckTimeConstraints {
        start_time: sample - 1,
        future_boundaries: &[],
        winning_windows: &open_window,
    };

    let stale_scope = RequestRootScope::new(owner.handle(), Default::default());
    let stale_root = stale_scope.extension();
    let stale_session = subject_session(&authority, &stale_root);
    let snapshot_metadata = stale_session
        .with_authoritative_context(&stale_root, |_, reader, _| reader.metadata())
        .expect("the stale request reads its snapshot");
    assert_eq!(
        snapshot_metadata,
        owner.handle().metadata().expect("serving metadata"),
        "the request snapshot is the live root before the write"
    );

    let live_metadata = owner
        .mutation_executor()
        .disable_card_with_session_updates(&authority, id(8), snapshot_metadata, || {})
        .expect("the bound coordinator disables the unrelated card");
    assert_eq!(live_metadata.version, snapshot_metadata.version + 1);
    assert_ne!(live_metadata, snapshot_metadata);

    let exact =
        |session: &RequestSessionExtension, root: &RequestRootExtension, expected: RootMetadata| {
            session
                .with_authoritative_context(root, |_, reader, final_check| {
                    final_check
                        .expect("the bound session carries a final check")
                        .try_final_time_exact_root_for_test(
                            &subject_record(reader),
                            &constraints,
                            expected,
                            id(10),
                            || Some(sample),
                        )
                })
                .expect("the request scope matches the session")
        };

    let ordinary = stale_session
        .with_authoritative_context(&stale_root, |_, reader, final_check| {
            assert_eq!(
                reader.metadata(),
                snapshot_metadata,
                "the snapshot is stale"
            );
            final_check
                .expect("the bound session carries a final check")
                .try_final_time_for_test(&subject_record(reader), &constraints, || Some(sample))
        })
        .expect("the request scope matches the session");
    assert_eq!(
        ordinary,
        Some(sample),
        "the ordinary check admits the stale snapshot, so the writes below are refused by the exact-root equality only"
    );
    assert_eq!(
        exact(&stale_session, &stale_root, snapshot_metadata),
        None,
        "expected metadata equal to the stale snapshot disagrees with the live root"
    );
    assert_eq!(
        exact(&stale_session, &stale_root, live_metadata),
        None,
        "expected metadata equal to the live root disagrees with the stale snapshot"
    );

    let fresh_scope = RequestRootScope::new(owner.handle(), Default::default());
    let fresh_root = fresh_scope.extension();
    let fresh_session = subject_session(&authority, &fresh_root);
    assert_eq!(
        exact(&fresh_session, &fresh_root, live_metadata),
        Some(sample),
        "a request that begins after the write agrees with the live root"
    );
    println!(
        "exact root: stale_version={} live_version={}",
        snapshot_metadata.version, live_metadata.version
    );
}

const FENCE_ROOT_TEST: &str = "paper_open_fence_at_the_final_check_refuses_and_close_restores";

/// memory—v1 (V5, root level): A modification fence that is open on the rule set of the subject's
/// active binding when the final check starts makes both the ordinary and the exact-root check refuse.
/// Closing without publication restores availability for a fresh request, not for the phase that
/// overlapped the window. Both checks use the same policy snapshot and clock sample.
#[test]
fn paper_open_fence_at_the_final_check_refuses_and_close_restores() {
    if std::env::var(CHILD_ENV).as_deref() != Ok("fence-root") {
        run_child(FENCE_ROOT_TEST, "fence-root");
        return;
    }
    let (owner, authority) = fixture();
    let sample = now();
    let open_window = [FinalCheckWindow {
        entry_validity: None,
        binding_from: None,
        binding_until: None,
    }];
    let constraints = FinalCheckTimeConstraints {
        start_time: sample - 1,
        future_boundaries: &[],
        winning_windows: &open_window,
    };
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let session = subject_session(&authority, &root);
    let metadata = session
        .with_authoritative_context(&root, |_, reader, _| reader.metadata())
        .expect("the request reads its snapshot");

    let ordinary = |root: &RequestRootExtension, session: &RequestSessionExtension| {
        session
            .with_authoritative_context(root, |_, reader, final_check| {
                final_check
                    .expect("the bound session carries a final check")
                    .try_final_time_for_test(&subject_record(reader), &constraints, || Some(sample))
            })
            .expect("the request scope matches the session")
    };
    let exact = |root: &RequestRootExtension, session: &RequestSessionExtension| {
        session
            .with_authoritative_context(root, |_, reader, final_check| {
                final_check
                    .expect("the bound session carries a final check")
                    .try_final_time_exact_root_for_test(
                        &subject_record(reader),
                        &constraints,
                        metadata,
                        id(10),
                        || Some(sample),
                    )
            })
            .expect("the request scope matches the session")
    };

    assert_eq!(
        ordinary(&root, &session),
        Some(sample),
        "control: no fence is open"
    );
    assert_eq!(
        exact(&root, &session),
        Some(sample),
        "control: no fence is open"
    );

    let declaration = FenceDeclaration {
        rule_set_version: vec![1],
        root_version: metadata.version,
        digest: metadata.digest,
    };
    owner
        .begin_modification_fence(id(10), &declaration)
        .expect("the fence opens against the live premise");
    assert_eq!(
        ordinary(&root, &session),
        None,
        "an open fence on the card's rule set refuses the ordinary check"
    );
    assert_eq!(
        exact(&root, &session),
        None,
        "an open fence on the target rule set refuses the exact-root check"
    );

    owner
        .abort_modification_fence(id(10))
        .expect("the fence closes without publishing");
    assert_eq!(ordinary(&root, &session), None);
    assert_eq!(exact(&root, &session), None);
    let fresh_scope = RequestRootScope::new(owner.handle(), Default::default());
    let fresh = fresh_scope.extension();
    let fresh_session = subject_session(&authority, &fresh);
    assert_eq!(ordinary(&fresh, &fresh_session), Some(sample));
    assert_eq!(exact(&fresh, &fresh_session), Some(sample));
    println!("fence root: version={}", metadata.version);
}

const SESSION_REVOKE_TEST: &str = "paper_session_revocation_in_flight_refuses_the_final_check";

/// memory—v1: Issue and bind a subject session and keep its credential so that a test can revoke it.
fn subject_session_with_credential(
    authority: &MemoryV1SessionAuthority,
    root: &RequestRootExtension,
) -> (RequestSessionExtension, String) {
    let issued = authority
        .identity_session_adapter()
        .issue_unchecked_for_test(principal(), now() - 60, 3_600)
        .expect("the subject session issues");
    let credential = issued.credential().to_owned();
    let session = authority
        .verifier()
        .verify_and_bind(&credential, now(), root)
        .expect("the subject session binds");
    (session, credential)
}

/// memory—v1 (V2, session writers): Revoking the subject's session after the request has bound it,
/// whether by credential or for every session of the user card, makes the ordinary and the exact-root
/// final check refuse. The root, the record, the constraints and the clock are fixed, so only the live
/// session record can refuse. A session that is issued for the same card after the revocation is the
/// control and is admitted. The session writers are outside the management mutation matrix.
#[test]
fn paper_session_revocation_in_flight_refuses_the_final_check() {
    if std::env::var(CHILD_ENV).as_deref() != Ok("session-revoke") {
        run_child(SESSION_REVOKE_TEST, "session-revoke");
        return;
    }
    let (owner, authority) = fixture();
    let sample = now();
    let open_window = [FinalCheckWindow {
        entry_validity: None,
        binding_from: None,
        binding_until: None,
    }];
    let constraints = FinalCheckTimeConstraints {
        start_time: sample - 1,
        future_boundaries: &[],
        winning_windows: &open_window,
    };
    let metadata = owner.handle().metadata().expect("serving metadata");

    let ordinary = |session: &RequestSessionExtension, root: &RequestRootExtension| {
        session
            .with_authoritative_context(root, |_, reader, final_check| {
                final_check
                    .expect("the bound session carries a final check")
                    .try_final_time_for_test(&subject_record(reader), &constraints, || Some(sample))
            })
            .expect("the request scope matches the session")
    };
    let exact = |session: &RequestSessionExtension, root: &RequestRootExtension| {
        session
            .with_authoritative_context(root, |_, reader, final_check| {
                final_check
                    .expect("the bound session carries a final check")
                    .try_final_time_exact_root_for_test(
                        &subject_record(reader),
                        &constraints,
                        metadata,
                        id(10),
                        || Some(sample),
                    )
            })
            .expect("the request scope matches the session")
    };

    // Revocation by credential.
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let (session, credential) = subject_session_with_credential(&authority, &root);
    assert_eq!(
        ordinary(&session, &root),
        Some(sample),
        "control: session is live"
    );
    assert_eq!(
        exact(&session, &root),
        Some(sample),
        "control: session is live"
    );
    authority
        .identity_session_adapter()
        .revoke(&credential)
        .expect("the credential revokes");
    assert_eq!(
        ordinary(&session, &root),
        None,
        "a revoked session refuses the ordinary check"
    );
    assert_eq!(
        exact(&session, &root),
        None,
        "a revoked session refuses the exact-root check"
    );

    // Revocation of every session of the user card, then a session issued afterwards.
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let (session, _credential) = subject_session_with_credential(&authority, &root);
    assert_eq!(
        ordinary(&session, &root),
        Some(sample),
        "control: session is live"
    );
    let revoked = authority
        .identity_session_adapter()
        .revoke_sessions_for_user_card(MemoryId::from_bytes(id(4)))
        .expect("the card's sessions revoke");
    assert_eq!(revoked, 1, "exactly the live session of card 4 is revoked");
    assert_eq!(
        ordinary(&session, &root),
        None,
        "a session revoked with its card refuses the ordinary check"
    );
    assert_eq!(
        exact(&session, &root),
        None,
        "a session revoked with its card refuses the exact-root check"
    );

    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let (fresh, _credential) = subject_session_with_credential(&authority, &root);
    assert_eq!(
        ordinary(&fresh, &root),
        Some(sample),
        "a session issued after the revocation is admitted: only the session was refused"
    );
    println!("session revoke: version={}", metadata.version);
}

// ---------------------------------------------------------------------------------------------
// T3 source pin
// ---------------------------------------------------------------------------------------------

/// memory—v1 (T3): One production source file after lexing. Comments and string literal contents are
/// removed, so a name in a doc comment or a literal cannot count as a call.
struct ScannedFile {
    path: PathBuf,
    production_lines: Vec<(usize, String)>,
    test_modules: Vec<String>,
    balanced: bool,
}

/// memory—v1 (T3): A minimal Rust lexer that removes comments and string literals per line and keeps
/// the state across lines. Raw strings, nested block comments, byte strings, and char literals are
/// handled. The scanner then marks items gated by `#[cfg(test)]` or `#[test]` and reports their
/// out-of-line test module declarations. Brace balance is checked at end of file as a self-check.
fn scan_source(path: PathBuf, text: &str) -> ScannedFile {
    let mut block_depth = 0_usize;
    let mut raw_hashes: Option<usize> = None;
    let mut in_string = false;
    let mut global_depth: i64 = 0;
    let mut item: Option<(i64, bool)> = None;
    let mut pending = false;
    let mut production_lines = Vec::new();
    let mut test_modules = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let cleaned = lex_line(line, &mut block_depth, &mut raw_hashes, &mut in_string);
        let trimmed = cleaned.trim();
        if item.is_none() && !pending {
            if trimmed.starts_with("#[") && is_test_attribute(trimmed) {
                pending = true;
                continue;
            }
            production_lines.push((index + 1, cleaned.clone()));
        } else if pending {
            if trimmed.is_empty() || trimmed.starts_with("#[") {
                continue;
            }
            if let Some(name) = out_of_line_module(trimmed) {
                test_modules.push(name);
                pending = false;
                continue;
            }
            pending = false;
            item = Some((global_depth, false));
        }
        for ch in cleaned.chars() {
            match ch {
                '{' => {
                    global_depth += 1;
                    if let Some((_, opened)) = item.as_mut() {
                        *opened = true;
                    }
                }
                '}' => {
                    global_depth -= 1;
                    if let Some((start, opened)) = item {
                        if opened && global_depth == start {
                            item = None;
                        }
                    }
                }
                ';' => {
                    if let Some((start, opened)) = item {
                        if !opened && global_depth == start {
                            item = None;
                        }
                    }
                }
                _ => {}
            }
        }
    }
    ScannedFile {
        path,
        production_lines,
        test_modules,
        balanced: global_depth == 0
            && item.is_none()
            && !pending
            && block_depth == 0
            && !in_string
            && raw_hashes.is_none(),
    }
}

/// memory—v1 (T3): Attributes that gate the following item to test builds. `not(test)` is production.
fn is_test_attribute(trimmed: &str) -> bool {
    if trimmed.starts_with("#[test]") {
        return true;
    }
    trimmed.starts_with("#[cfg(") && trimmed.contains("test") && !trimmed.contains("not(test")
}

/// memory—v1 (T3): The module name of an out-of-line `mod name;` declaration.
fn out_of_line_module(trimmed: &str) -> Option<String> {
    let rest = trimmed.strip_prefix("pub ").unwrap_or(trimmed);
    let rest = rest.strip_prefix("mod ")?;
    let name = rest.strip_suffix(';')?.trim();
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some(name.to_owned())
}

// memory—v1 (T3): Identifier character for the lexer's raw-string check.
fn is_ident(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

/// memory—v1 (T3): Remove comments and literal contents from one line, keeping the lexer state.
fn lex_line(
    line: &str,
    block_depth: &mut usize,
    raw_hashes: &mut Option<usize>,
    in_string: &mut bool,
) -> String {
    let chars: Vec<char> = line.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        let next = chars.get(i + 1).copied();
        if *block_depth > 0 {
            if chars[i] == '/' && next == Some('*') {
                *block_depth += 1;
                i += 2;
            } else if chars[i] == '*' && next == Some('/') {
                *block_depth -= 1;
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        if let Some(hashes) = *raw_hashes {
            if chars[i] == '"' && (1..=hashes).all(|k| chars.get(i + k) == Some(&'#')) {
                *raw_hashes = None;
                i += 1 + hashes;
            } else {
                i += 1;
            }
            continue;
        }
        if *in_string {
            if chars[i] == '\\' {
                i += 2;
            } else {
                if chars[i] == '"' {
                    *in_string = false;
                }
                i += 1;
            }
            continue;
        }
        match chars[i] {
            '/' if next == Some('/') => break,
            '/' if next == Some('*') => {
                *block_depth = 1;
                i += 2;
            }
            'r' if (i == 0 || !is_ident(chars[i - 1]) || chars[i - 1] == 'b')
                && (next == Some('"') || next == Some('#')) =>
            {
                let hashes = chars[i + 1..].iter().take_while(|c| **c == '#').count();
                if chars.get(i + 1 + hashes) == Some(&'"') {
                    *raw_hashes = Some(hashes);
                    i += 2 + hashes;
                } else {
                    out.push(chars[i]);
                    i += 1;
                }
            }
            '"' => {
                *in_string = true;
                i += 1;
            }
            '\'' => {
                if next == Some('\\') {
                    let mut j = i + 2;
                    while j < chars.len() && chars[j] != '\'' {
                        j += 1;
                    }
                    i = j + 1;
                } else if chars.get(i + 2) == Some(&'\'') {
                    i += 3;
                } else {
                    out.push(chars[i]);
                    i += 1;
                }
            }
            ch => {
                out.push(ch);
                i += 1;
            }
        }
    }
    out
}

/// memory—v1 (T3): Walk the workspace for production sources. `target`, hidden directories, and test,
/// bench, and example directories are skipped. Out-of-line test modules are removed afterwards.
fn collect_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("the workspace directory is readable") {
        let path = entry.expect("the directory entry is readable").path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();
        if path.is_dir() {
            if name == "target"
                || name == "tests"
                || name == "benches"
                || name == "examples"
                || name.starts_with('.')
            {
                continue;
            }
            collect_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// memory—v1 (T3): The directory that holds the submodules of a source file, and the file itself, for
/// the out-of-line test module `name` declared in `declaring`.
fn test_module_roots(declaring: &Path, name: &str) -> [PathBuf; 2] {
    let stem = declaring
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();
    let base = if matches!(stem, "mod" | "lib" | "main") {
        declaring
            .parent()
            .expect("a source file has a parent")
            .to_path_buf()
    } else {
        declaring
            .parent()
            .expect("a source file has a parent")
            .join(stem)
    };
    [base.join(format!("{name}.rs")), base.join(name)]
}

/// memory—v1 (T3): Pin the sole production call to the owned opener and exclude the legacy opener.
/// The scan is self-checking: every file must end with balanced items and literals.
#[test]
fn paper_fence_has_one_governed_production_opener() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("policy-engine has a workspace parent");
    let mut paths = Vec::new();
    collect_sources(workspace, &mut paths);
    paths.sort();
    let scanned: Vec<ScannedFile> = paths
        .iter()
        .map(|path| {
            let text = fs::read_to_string(path).expect("the source file is readable as UTF-8");
            scan_source(path.clone(), &text)
        })
        .collect();
    assert!(
        scanned.len() > 100,
        "the scan must cover the workspace sources, found {}",
        scanned.len()
    );
    let unbalanced: Vec<String> = scanned
        .iter()
        .filter(|file| !file.balanced)
        .map(|file| file.path.display().to_string())
        .collect();
    assert!(
        unbalanced.is_empty(),
        "the lexer must balance every source file, unbalanced: {unbalanced:?}"
    );

    let test_roots: Vec<[PathBuf; 2]> = scanned
        .iter()
        .flat_map(|file| {
            file.test_modules
                .iter()
                .map(|name| test_module_roots(&file.path, name))
                .collect::<Vec<_>>()
        })
        .collect();
    let is_test_file = |path: &Path| {
        test_roots
            .iter()
            .any(|[file, dir]| path == file || path.starts_with(dir))
    };

    let mut definitions = Vec::new();
    let mut production_calls = Vec::new();
    for file in scanned.iter().filter(|file| !is_test_file(&file.path)) {
        let relative = file
            .path
            .strip_prefix(workspace)
            .unwrap_or(&file.path)
            .display()
            .to_string();
        for (line_no, line) in &file.production_lines {
            for opener in FENCE_OPENERS {
                if !line.contains(opener) {
                    continue;
                }
                if FENCE_OPENERS
                    .iter()
                    .any(|name| line.contains(&format!("fn {name}")))
                {
                    if !definitions.contains(&relative) {
                        definitions.push(relative.clone());
                    }
                } else {
                    production_calls.push(format!("{relative}:{line_no}: {}", line.trim()));
                }
                break;
            }
        }
    }
    assert_eq!(
        definitions,
        vec!["astral-authorization-root/src/memory_v1_root.rs".to_owned()],
        "the fence openers are defined only in the root owner file"
    );
    assert_eq!(
        production_calls.len(),
        1,
        "unexpected openers: {production_calls:#?}"
    );
    let call = &production_calls[0];
    assert!(
        call.starts_with("astral-authorization-root/src/memory_v1_root/governed.rs:")
            && call.contains(".begin_owned_modification_fence("),
        "only the governed preparation may open an owned fence: {call}"
    );
    println!(
        "fence source pin: files={} production_callers=1 definition_files={}",
        scanned.len(),
        definitions.len()
    );
}

/// memory—v1 (T3): Scanner control. The source pin is only meaningful if the scanner counts a real
/// production call and ignores test items, doc comments, and literals. Braces inside char and raw
/// string literals must not unbalance the file.
#[test]
fn paper_fence_scanner_self_test() {
    let text = r##"fn production() { root.begin_modification_fence(); }
/// The doc comment names begin_modification_fence and is not a call.
let literal = "begin_owned_modification_fence";
let brace = '{'; let raw = r#"{"k":1}"#; root.begin_owned_modification_fence();
#[cfg(test)]
mod tests {
    fn helper() { root.begin_owned_modification_fence(); }
}
#[test]
fn case() { root.begin_modification_fence(); }
"##;
    let scanned = scan_source(PathBuf::from("synthetic.rs"), text);
    assert!(
        scanned.balanced,
        "literal braces must not unbalance the lexer"
    );
    let calls: Vec<&str> = scanned
        .production_lines
        .iter()
        .filter(|(_, line)| FENCE_OPENERS.iter().any(|opener| line.contains(opener)))
        .map(|(_, line)| line.as_str())
        .collect();
    assert_eq!(
        calls.len(),
        2,
        "exactly the two production calls are visible: {calls:?}"
    );
    assert!(calls[0].contains("fn production"));
    assert!(calls[1].contains("let brace"));
}

// ---------------------------------------------------------------------------------------------
// T4 random walk (stretch)
// ---------------------------------------------------------------------------------------------

/// memory—v1 (T4): Fixed seeds for the default walk. Each seed runs in its own child process because
/// the process root is one-shot.
const T4_DEFAULT_SEEDS: [u64; 8] = [1, 2, 3, 5, 8, 13, 21, 34];
/// memory—v1 (T4): Steps per default walk.
const T4_DEFAULT_STEPS: usize = 32;
/// memory—v1 (T4): Steps per heavy walk. The heavy test runs seeds 1 through 256.
const T4_HEAVY_STEPS: usize = 64;
/// memory—v1 (T4): Name of the child body that runs one walk. It is a no-op outside a child process.
const T4_CHILD_TEST: &str = "paper_random_walk_child";

/// memory—v1 (T4): splitmix64 step. The state advances by the golden-ratio increment and the output is
/// the standard finalizer. The walk is reproducible from its seed alone.
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// memory—v1 (T4): One public refusal check: owner entry and mutation executor both refuse with
/// `ConcurrentModification`, and the serving metadata does not move.
fn assert_public_refusal(owner: &RootOwner, name: &str, mutation: &ManagementMutationV2) {
    let before = owner.handle().metadata().expect("serving metadata");
    let precondition = MutationPrecondition {
        evaluated_root_version: before.version,
    };
    let via_owner = owner.execute_mutation_with_precondition(mutation, &precondition);
    assert!(
        matches!(via_owner, Err(MutationError::ConcurrentModification)),
        "{name} via owner must be refused, got {via_owner:?}"
    );
    let via_executor = owner.mutation_executor().execute(mutation, &precondition);
    assert!(
        matches!(via_executor, Err(MutationError::ConcurrentModification)),
        "{name} via executor must be refused, got {via_executor:?}"
    );
    assert_eq!(
        owner.handle().metadata().expect("serving metadata"),
        before,
        "{name} refusal must not move the serving root"
    );
}

/// memory—v1 (T4): Model-based walk over the public surface. The model state is the version (advanced
/// only by accepted coordinator writes) and whether the subject card is disabled (the subject decision
/// is `Allow` exactly while it is not). Each step draws one operation: a public management refusal, an
/// accepted coordinator disable of card 8 or card 4 (each at most once), or a refused coordinator write
/// with stale metadata or an unbound authority. The check after every step compares both the version
/// and the subject decision with the model. The model covers the public surface only; the in-flight
/// write space is covered by the T1 matrix.
fn run_walk(seed: u64, steps: usize) -> (usize, u64) {
    let (owner, authority) = fixture();
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let session = subject_session(&authority, &root);
    let engine = PolicyEngine::new();
    let stranger = MemoryV1SessionAuthority::new();
    let all = mutations();
    let mut state = seed;
    let mut card4_disabled = false;
    let mut card8_disabled = false;
    let mut expected_version = owner.handle().metadata().expect("serving metadata").version;
    let mut accepted = 0_usize;
    for step in 0..steps {
        let draw = splitmix64(&mut state);
        match draw % 16 {
            op @ 0..=10 => {
                let (name, mutation) = &all[op as usize];
                assert_public_refusal(&owner, name, mutation);
            }
            11 if !card8_disabled => {
                let before = owner.handle().metadata().expect("serving metadata");
                owner
                    .mutation_executor()
                    .disable_card_with_session_updates(&authority, id(8), before, || {})
                    .unwrap_or_else(|error| {
                        panic!("seed {seed} step {step}: card 8 disable: {error:?}")
                    });
                card8_disabled = true;
                expected_version += 1;
                accepted += 1;
            }
            12 if !card4_disabled => {
                let before = owner.handle().metadata().expect("serving metadata");
                owner
                    .mutation_executor()
                    .disable_card_with_session_updates(&authority, id(4), before, || {})
                    .unwrap_or_else(|error| {
                        panic!("seed {seed} step {step}: card 4 disable: {error:?}")
                    });
                card4_disabled = true;
                expected_version += 1;
                accepted += 1;
            }
            _ => {
                let before = owner.handle().metadata().expect("serving metadata");
                let refused = if (draw >> 8) & 1 == 0 {
                    let stale = RootMetadata {
                        version: before.version.wrapping_add(1),
                        ..before
                    };
                    owner.mutation_executor().disable_card_with_session_updates(
                        &authority,
                        id(8),
                        stale,
                        || {},
                    )
                } else {
                    owner.mutation_executor().disable_card_with_session_updates(
                        &stranger,
                        id(8),
                        before,
                        || {},
                    )
                };
                assert!(
                    matches!(refused, Err(MutationError::ConcurrentModification)),
                    "seed {seed} step {step}: a stale or unbound coordinator write must be refused, got {refused:?}"
                );
            }
        }
        let version = owner.handle().metadata().expect("serving metadata").version;
        assert_eq!(
            version, expected_version,
            "seed {seed} step {step}: the version tracks accepted writes only"
        );
        let observed = decision(&engine, &root, &session);
        if card4_disabled {
            assert_ne!(
                observed,
                MemoryV1Decision::Allow,
                "seed {seed} step {step}: a disabled subject must not be allowed"
            );
        } else {
            assert_eq!(
                observed,
                MemoryV1Decision::Allow,
                "seed {seed} step {step}: an enabled subject is allowed"
            );
        }
    }
    (accepted, expected_version)
}

/// memory—v1 (T4): Child body for one walk. The label is `walk-<seed>-<steps>`. Outside a child
/// process this test does nothing, so the parent tests below are the entry points.
#[test]
fn paper_random_walk_child() {
    let Ok(label) = std::env::var(CHILD_ENV) else {
        return;
    };
    let Some(spec) = label.strip_prefix("walk-") else {
        return;
    };
    let (seed, steps) = spec
        .split_once('-')
        .expect("walk label carries seed and steps");
    let seed: u64 = seed.parse().expect("walk seed is a number");
    let steps: usize = steps.parse().expect("walk steps is a number");
    let (accepted, final_version) = run_walk(seed, steps);
    println!("walk seed={seed} steps={steps} accepted={accepted} final_version={final_version}");
}

/// memory—v1 (T4): Default walks over the fixed seeds, each in its own child process.
#[test]
fn paper_random_walk_default_seeds() {
    for seed in T4_DEFAULT_SEEDS {
        run_child(T4_CHILD_TEST, &format!("walk-{seed}-{T4_DEFAULT_STEPS}"));
    }
}

/// memory—v1 (T4): Heavy walks over seeds 1 through 256, each in its own child process. Excluded from
/// the default run. Run with:
/// `cargo test -p policy-engine --locked --offline --test memory_v1_paper_writer_coverage paper_random_walk_heavy -- --ignored`
#[test]
#[ignore = "heavy: 256 seeds x 64 steps; see the doc comment for the exact command"]
fn paper_random_walk_heavy() {
    for seed in 1..=256_u64 {
        run_child(T4_CHILD_TEST, &format!("walk-{seed}-{T4_HEAVY_STEPS}"));
    }
}
