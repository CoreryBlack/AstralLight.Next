//! memory—v1: Theorem 1 implementation evidence that needs in-crate hooks.
//!
//! The in-flight hook (`evaluate_with`) and the injected clock exist only in
//! unit-test builds, so these scenarios live here instead of under `tests/`.
//! The root slot is process-wide and one-shot: every scenario therefore runs in
//! its own child process, selected by an environment variable.

use astral_authorization_root::memory_v1_db_rows::{
    BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, CurrentSelection,
    IdentityCardRow, RuleSetChangeConfirmationRow, RuleSetRow, RuleSetStatus, RuleSetVersionRow,
    TenantRow, UserCardRow, UserCardStatus, UserRow,
};
use astral_authorization_root::memory_v1_hamt::CandidateBudget;
use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
use astral_authorization_root::memory_v1_request::RequestRootScope;
use astral_authorization_root::memory_v1_root::{
    install_process_root, ManagementMutationV2, MutationError, MutationPrecondition, RootOwner,
};
use astral_authorization_root::memory_v1_rules::{
    canonical_version_bytes, version_digest, MemoryV1OwnerScope, MemoryV1TenantScope,
};
use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority;
use astral_types::memory_v1::{CandidateIdentity, MemoryId};

use super::super::{
    evaluate_with, MemoryV1Decision, MemoryV1Evaluation, MemoryV1PendingSource, MemoryV1Request,
};

// memory—v1: Independent row-scan reference for complete observation.
#[path = "paper_evidence/complete_observation.rs"]
mod complete_observation;

/// memory—v1 (T1): Environment gate selecting one matrix scenario per child process.
const T1_ENV: &str = "ASTRAL_MEMORY_V1_PAPER_T1_SCENARIO";
/// memory—v1 (T1): Fixed trusted clock sample for every decision in the matrix.
const T1_NOW: i64 = 110;
/// memory—v1 (T1): Session issue time; the session is valid on [100, 200).
const T1_ISSUED: i64 = 100;
/// memory—v1 (T1): Session lifetime in seconds.
const T1_LIFETIME: i64 = 100;
/// memory—v1 (T1): The subject card whose ALLOW the in-flight writes may or may not disturb.
const SUBJECT: u8 = 4;
/// memory—v1 (T1): The unrelated card used by the isolation rows.
const OTHER: u8 = 8;

/// memory—v1 (T1): Every mutation kind of `ManagementMutationV2`, one per variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    BindingCreate,
    BindingRemove,
    ConfirmationCreate,
    ConfirmationRevoke,
    RuleSetChangeConfirmationRevoke,
    ConfirmationBatch,
    UserCardCreate,
    UserCardStatus,
    RuleSetCreate,
    RuleSetRetire,
    VersionPublish,
}

/// memory—v1 (T1): Every kind, in declaration order; the coverage test checks each has rows.
const ALL_KINDS: [Kind; 11] = [
    Kind::BindingCreate,
    Kind::BindingRemove,
    Kind::ConfirmationCreate,
    Kind::ConfirmationRevoke,
    Kind::RuleSetChangeConfirmationRevoke,
    Kind::ConfirmationBatch,
    Kind::UserCardCreate,
    Kind::UserCardStatus,
    Kind::RuleSetCreate,
    Kind::RuleSetRetire,
    Kind::VersionPublish,
];

/// memory—v1 (T1): Dependency class of the evaluated request relative to the write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    /// The write changes a fact the subject's ALLOW reads (its own binding, confirmation or rule set).
    Subject,
    /// The write changes only objects the subject's predicate does not read.
    Unrelated,
    /// The write changes a subject-read object without changing the predicate's truth value.
    SubjectNeutral,
}

/// memory—v1 (T1): The in-flight decision a row requires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    Allow,
    Pending,
}

/// memory—v1 (T1): Truth value of the sequential predicate after the write, derived from the rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Predicate {
    /// The subject still holds an ALLOW with no active DENY: a fresh evaluation must return Allow.
    Holds,
    /// The subject no longer holds: a fresh evaluation must not return Allow.
    Fails,
}

/// memory—v1 (T1): One matrix row. `applied` says whether the executor must accept the write.
struct Row {
    kind: Kind,
    class: Class,
    applied: bool,
    in_flight: Expect,
    after: Predicate,
    /// True only where the in-flight outcome is a conservative rejection of a predicate that still holds.
    conservative: bool,
    why: &'static str,
}

/// memory—v1 (T1): The writer-coverage matrix as data. Premise 3 of guarantee.tex requires
/// that every writer changing a fact either advances the identity the candidate checks or
/// causes validation to fail; each row records how that obligation is discharged.
const MATRIX: &[Row] = &[
    Row { kind: Kind::BindingCreate, class: Class::Subject, applied: true, in_flight: Expect::Pending, after: Predicate::Fails, conservative: false,
        why: "Adds an active overlay DENY to the subject's card. Its card generation advances and the in-flight ALLOW is refused; deny precedence makes the sequential answer Deny." },
    Row { kind: Kind::BindingCreate, class: Class::Unrelated, applied: true, in_flight: Expect::Allow, after: Predicate::Holds, conservative: false,
        why: "Adds a binding to card 8 on rule set 16. The subject reads neither card 8 nor rule set 16, so the recheck keeps the ALLOW." },
    Row { kind: Kind::BindingRemove, class: Class::Subject, applied: true, in_flight: Expect::Pending, after: Predicate::Fails, conservative: false,
        why: "Tombstones the subject's only ALLOW binding. The card generation advances and the sequential answer becomes NoMatch." },
    Row { kind: Kind::BindingRemove, class: Class::Unrelated, applied: true, in_flight: Expect::Allow, after: Predicate::Holds, conservative: false,
        why: "Tombstones card 8's binding. Card 4's generation, its binding and rule set 10 are unchanged." },
    Row { kind: Kind::ConfirmationCreate, class: Class::Subject, applied: true, in_flight: Expect::Pending, after: Predicate::Fails, conservative: false,
        why: "Activates the withdrawn overlay DENY on the subject. Binding confirmation state flips Withdrawn to Active, so the denial now applies." },
    Row { kind: Kind::ConfirmationCreate, class: Class::Unrelated, applied: true, in_flight: Expect::Allow, after: Predicate::Holds, conservative: false,
        why: "Activates a withdrawn ALLOW on card 8 for rule set 14. Card 4 does not depend on rule set 14." },
    Row { kind: Kind::ConfirmationRevoke, class: Class::Subject, applied: true, in_flight: Expect::Pending, after: Predicate::Fails, conservative: false,
        why: "Revokes the only active confirmation of the subject's binding. The binding becomes Withdrawn and the ALLOW disappears." },
    Row { kind: Kind::ConfirmationRevoke, class: Class::Unrelated, applied: true, in_flight: Expect::Allow, after: Predicate::Holds, conservative: false,
        why: "Revokes card 8's confirmation. Card 4's binding and rule set are untouched." },
    Row { kind: Kind::RuleSetChangeConfirmationRevoke, class: Class::Subject, applied: true, in_flight: Expect::Pending, after: Predicate::Fails, conservative: false,
        why: "GAP (witness_ test): the mutation path applies a revocation of rule set 10's CURRENT-version freshness row on an isolated serving root. The mutation path runs only validate_binding_indexes and validate_confirmation_indexes; the freshness rule lives in validate_for_serving, which runs only at adoption. Reads then fail closed (Pending), so no unsound Allow results, but the writer does not re-establish the adoption invariant." },
    Row { kind: Kind::RuleSetChangeConfirmationRevoke, class: Class::Unrelated, applied: true, in_flight: Expect::Allow, after: Predicate::Holds, conservative: false,
        why: "Revokes the confirmation of a HISTORICAL version of rule set 14. Only the current version is read by the predicate; the current row stays active." },
    Row { kind: Kind::ConfirmationBatch, class: Class::Subject, applied: true, in_flight: Expect::Pending, after: Predicate::Fails, conservative: false,
        why: "All-or-nothing batch activating the subject's withdrawn overlay DENY. Same outcome as the single confirmation." },
    Row { kind: Kind::ConfirmationBatch, class: Class::Unrelated, applied: true, in_flight: Expect::Allow, after: Predicate::Holds, conservative: false,
        why: "Batch activating card 8's withdrawn ALLOW on rule set 14; the subject does not read it." },
    Row { kind: Kind::UserCardCreate, class: Class::Subject, applied: false, in_flight: Expect::Allow, after: Predicate::Holds, conservative: false,
        why: "Re-creating the subject's card id is refused as a duplicate. A refused write publishes nothing, so the admitted cut still holds." },
    Row { kind: Kind::UserCardCreate, class: Class::Unrelated, applied: true, in_flight: Expect::Allow, after: Predicate::Holds, conservative: false,
        why: "A new card for the same principal. The predicate names only card 4 and its own bindings, so the new card is not in its dependency set." },
    Row { kind: Kind::UserCardStatus, class: Class::Subject, applied: true, in_flight: Expect::Pending, after: Predicate::Fails, conservative: false,
        why: "Coordinated disable revokes the subject's live session. The plain Disabled write through the executor is refused (CardDisableRequiresSessionCoordinator), and the refusal is asserted in flight." },
    Row { kind: Kind::UserCardStatus, class: Class::Unrelated, applied: true, in_flight: Expect::Allow, after: Predicate::Holds, conservative: false,
        why: "Coordinated disable of card 8 revokes only card 8's sessions; card 4's session remains live and its card generation is unchanged." },
    Row { kind: Kind::RuleSetCreate, class: Class::Subject, applied: false, in_flight: Expect::Allow, after: Predicate::Holds, conservative: false,
        why: "Re-creating rule set 10 is refused as a duplicate; nothing is published." },
    Row { kind: Kind::RuleSetCreate, class: Class::Unrelated, applied: true, in_flight: Expect::Allow, after: Predicate::Holds, conservative: false,
        why: "A new rule set with no bindings. No binding of the subject references it." },
    Row { kind: Kind::RuleSetRetire, class: Class::Subject, applied: false, in_flight: Expect::Allow, after: Predicate::Holds, conservative: false,
        why: "Retiring rule set 10 while the subject's binding is active is refused (InconsistentBinding). Retirement requires the bindings to be withdrawn first." },
    Row { kind: Kind::RuleSetRetire, class: Class::Unrelated, applied: true, in_flight: Expect::Allow, after: Predicate::Holds, conservative: false,
        why: "Retiring an unbound rule set changes no binding of the subject." },
    Row { kind: Kind::VersionPublish, class: Class::Subject, applied: true, in_flight: Expect::Pending, after: Predicate::Fails, conservative: false,
        why: "Publishes a DENY as the current version of rule set 10. The selected version identity changes and the sequential answer is Deny." },
    Row { kind: Kind::VersionPublish, class: Class::Unrelated, applied: true, in_flight: Expect::Allow, after: Predicate::Holds, conservative: false,
        why: "Publishes a new version of rule set 13, which only card 8 reads." },
    Row { kind: Kind::VersionPublish, class: Class::SubjectNeutral, applied: true, in_flight: Expect::Pending, after: Predicate::Holds, conservative: true,
        why: "Publishes a semantically identical ALLOW as rule set 10's new current version. The predicate still holds, but the selected version identity changes, so the recheck rejects. This is a conservative precision loss: allowed, and unsound acceptance is not." },
];

/// memory—v1 (T1): Exhaustive projection of governed writers. A service-period
/// load is a separate write family; it must be tested by the context-load suite.
fn kind_of(mutation: &ManagementMutationV2) -> Kind {
    match mutation {
        ManagementMutationV2::BindingCreate { .. } => Kind::BindingCreate,
        ManagementMutationV2::BindingRemove { .. } => Kind::BindingRemove,
        ManagementMutationV2::ConfirmationCreate { .. } => Kind::ConfirmationCreate,
        ManagementMutationV2::ConfirmationRevoke { .. } => Kind::ConfirmationRevoke,
        ManagementMutationV2::RuleSetChangeConfirmationRevoke { .. } => {
            Kind::RuleSetChangeConfirmationRevoke
        }
        ManagementMutationV2::ConfirmationBatch { .. } => Kind::ConfirmationBatch,
        ManagementMutationV2::UserCardCreate { .. } => Kind::UserCardCreate,
        ManagementMutationV2::UserCardStatus { .. } => Kind::UserCardStatus,
        ManagementMutationV2::RuleSetCreate { .. } => Kind::RuleSetCreate,
        ManagementMutationV2::RuleSetRetire { .. } => Kind::RuleSetRetire,
        ManagementMutationV2::VersionPublish { .. } => Kind::VersionPublish,
        ManagementMutationV2::ContextLoad { .. } => {
            unreachable!("service-period context load is outside the governance writer matrix")
        }
    }
}

/// memory—v1 (T1): Locate the single matrix row for a kind and class.
fn row_for(kind: Kind, class: Class) -> &'static Row {
    let mut found = MATRIX
        .iter()
        .filter(|row| row.kind == kind && row.class == class);
    let row = found
        .next()
        .unwrap_or_else(|| panic!("no matrix row for {kind:?}/{class:?}"));
    assert!(
        found.next().is_none(),
        "duplicate matrix row for {kind:?}/{class:?}"
    );
    row
}

/// memory—v1 (T1): Writes executed inside the after-read hook of one evaluation.
enum Write {
    /// A governance-shaped mutation through the isolated executor; success is required only when the row says so.
    Mutation(Box<ManagementMutationV2>),
    /// The coordinated card disable; always expected to succeed.
    Disable(u8),
    /// A plain Disabled status write, which must be refused (no session coordinator).
    PlainDisable(u8),
}

/// memory—v1 (T1): Rule-set content in the canonical grammar used by the fixture.
fn rule_content(rule_id: &str, effect: &str) -> String {
    format!(
        r#"{{"rules":[{{"ruleId":"{rule_id}","resource":"document","action":"read","effect":"{effect}"}}]}}"#
    )
}

/// memory—v1 (T1): Build a canonical rule-set version row with its digest.
fn version_row(rule_set_id: [u8; 16], version: &[u8], content: &str) -> RuleSetVersionRow {
    let timestamp = vec![2];
    let input = canonical_version_bytes(version, content.as_bytes(), &timestamp);
    RuleSetVersionRow {
        rule_set_id,
        version_bytes: version.to_vec(),
        content_bytes: content.as_bytes().to_vec(),
        timestamp_bytes: timestamp,
        hash_bytes: version_digest(&input),
        hash_input_bytes: input,
    }
}

/// memory—v1 (T1): A rule set row pointing at its current version.
fn rule_set(id: u8, current: &[u8]) -> RuleSetRow {
    RuleSetRow {
        status: RuleSetStatus::Active,
        rule_set_id: [id; 16],
        owner_tenant_id: [3; 16],
        current_version_bytes: current.to_vec(),
    }
}

/// memory—v1 (T1): A change confirmation for one rule-set version.
fn change_confirmation(id: u8, rule_set: u8, version: &[u8]) -> RuleSetChangeConfirmationRow {
    RuleSetChangeConfirmationRow {
        confirmation_id: [id; 16],
        rule_set_id: [rule_set; 16],
        version_bytes: version.to_vec(),
        confirmer_user_id: [1; 16],
        affected_scope_bytes: vec![1],
        operation_id: vec![1],
        confirmed_at_bytes: vec![1],
        revoked_at: None,
        revoked_by: None,
    }
}

/// memory—v1 (T1): A binding with no time window and default scopes.
fn binding_row(id: u8, card: u8, set: u8, layer: BindingLayer) -> BindingRow {
    BindingRow {
        binding_id: [id; 16],
        user_card_id: [card; 16],
        rule_set_id: [set; 16],
        binding_layer: layer,
        valid_from: None,
        valid_until: None,
        owner_scope: MemoryV1OwnerScope::default(),
        tenant_scope: MemoryV1TenantScope::default(),
        removed_at: None,
        removed_by: None,
    }
}

/// memory—v1 (T1): A binding confirmation; `revoked` makes it a withdrawal tombstone.
fn binding_confirmation(
    id: u8,
    binding: u8,
    set: u8,
    version: &[u8],
    revoked: bool,
) -> BindingConfirmationRow {
    BindingConfirmationRow {
        confirmation_id: [id; 16],
        binding_id: [binding; 16],
        rule_set_id: [set; 16],
        version_bytes: version.to_vec(),
        confirmer_user_id: [1; 16],
        scope_bytes: vec![1],
        operation_id: vec![1],
        confirmed_at_bytes: vec![1],
        revoked_at: revoked.then_some(50),
        revoked_by: revoked.then_some([1; 16]),
    }
}

/// memory—v1 (T1): Shared base fixture. Card 4 (subject) holds ALLOW R1 through binding 20
/// on rule set 10. When `subject_withdrawn_overlay` is set, it also carries a withdrawn
/// overlay DENY (binding 24, rule set 17) that contributes nothing until confirmed; the
/// candidate allows one non-removed overlay per card, so the scenario that adds a fresh
/// subject overlay omits it. Card 8 (other) holds ALLOW R4 through binding 23 and a
/// withdrawn ALLOW (binding 25, rule set 14 current version 2). Rule set 14 also has a
/// historical version 1; rule set 16 is unbound; rule set 12 is an unbound DENY. Every
/// rule set's current version carries an active change confirmation, as the candidate
/// invariant requires.
// memory—v1 (T1): Base fixture constructor for one scenario.
fn t1_base_rows(subject_withdrawn_overlay: bool) -> (CandidateRows, Vec<CurrentSelection>) {
    let rows = CandidateRows {
        users: vec![UserRow { user_id: [1; 16] }],
        identity_cards: vec![IdentityCardRow {
            identity_card_id: [2; 16],
            user_id: [1; 16],
        }],
        tenants: vec![TenantRow {
            tenant_id: [3; 16],
            parent_tenant_id: None,
        }],
        user_cards: [SUBJECT, OTHER]
            .into_iter()
            .map(|card| UserCardRow {
                user_card_id: [card; 16],
                user_id: [1; 16],
                tenant_id: [3; 16],
                status: UserCardStatus::Active,
            })
            .collect(),
        rule_sets: vec![
            rule_set(10, &[1]),
            rule_set(12, &[1]),
            rule_set(13, &[1]),
            rule_set(14, &[2]),
            rule_set(16, &[1]),
            rule_set(17, &[1]),
        ],
        rule_set_versions: vec![
            version_row([10; 16], &[1], &rule_content("R1", "ALLOW")),
            version_row([12; 16], &[1], &rule_content("R3", "DENY")),
            version_row([13; 16], &[1], &rule_content("R4", "ALLOW")),
            version_row([14; 16], &[1], &rule_content("R5", "ALLOW")),
            version_row([14; 16], &[2], &rule_content("R6", "ALLOW")),
            version_row([16; 16], &[1], &rule_content("R7", "ALLOW")),
            version_row([17; 16], &[1], &rule_content("R9", "DENY")),
        ],
        bindings: {
            let mut bindings = vec![
                binding_row(20, SUBJECT, 10, BindingLayer::Base),
                binding_row(23, OTHER, 13, BindingLayer::Overlay),
                binding_row(25, OTHER, 14, BindingLayer::Base),
            ];
            if subject_withdrawn_overlay {
                bindings.push(binding_row(24, SUBJECT, 17, BindingLayer::Overlay));
            }
            bindings
        },
        binding_confirmations: {
            let mut confirmations = vec![
                binding_confirmation(40, 20, 10, &[1], false),
                binding_confirmation(43, 23, 13, &[1], false),
                binding_confirmation(45, 25, 14, &[2], true),
            ];
            if subject_withdrawn_overlay {
                confirmations.push(binding_confirmation(44, 24, 17, &[1], true));
            }
            confirmations
        },
        rule_set_change_confirmations: vec![
            change_confirmation(210, 10, &[1]),
            change_confirmation(212, 12, &[1]),
            change_confirmation(213, 13, &[1]),
            change_confirmation(214, 14, &[1]),
            change_confirmation(215, 14, &[2]),
            change_confirmation(216, 16, &[1]),
            change_confirmation(217, 17, &[1]),
        ],
    };
    let selections = vec![
        CurrentSelection {
            rule_set_id: [10; 16],
            version_bytes: vec![1],
        },
        CurrentSelection {
            rule_set_id: [12; 16],
            version_bytes: vec![1],
        },
        CurrentSelection {
            rule_set_id: [13; 16],
            version_bytes: vec![1],
        },
        CurrentSelection {
            rule_set_id: [14; 16],
            version_bytes: vec![2],
        },
        CurrentSelection {
            rule_set_id: [16; 16],
            version_bytes: vec![1],
        },
        CurrentSelection {
            rule_set_id: [17; 16],
            version_bytes: vec![1],
        },
    ];
    (rows, selections)
}

/// memory—v1 (T1): Build the identity of one card of the single fixture user.
fn subject_identity(card: u8) -> CandidateIdentity {
    CandidateIdentity {
        user_id: MemoryId::from_bytes([1; 16]),
        identity_card_id: MemoryId::from_bytes([2; 16]),
        user_card_id: MemoryId::from_bytes([card; 16]),
        tenant_id: MemoryId::from_bytes([3; 16]),
    }
}

/// memory—v1 (T1): The request every matrix row evaluates.
fn t1_request() -> MemoryV1Request<'static> {
    MemoryV1Request {
        resource: "document",
        action: "read",
        target: None,
        target_tenant: None,
        target_owner: None,
        operation_id: b"op",
        operation_fingerprint: b"fp",
    }
}

/// memory—v1 (T1): The writes a row applies in flight. Each write's expected success is
/// fixed by its kind (see `Write`); the row's `applied` flag governs the main write.
fn t1_writes(kind: Kind, class: Class) -> Vec<Write> {
    let row = row_for(kind, class);
    let main = |mutation: ManagementMutationV2| Write::Mutation(Box::new(mutation));
    match (kind, class) {
        (Kind::BindingCreate, Class::Subject) => vec![main(ManagementMutationV2::BindingCreate {
            row: binding_row(26, SUBJECT, 12, BindingLayer::Overlay),
            confirmation: binding_confirmation(46, 26, 12, &[1], false),
        })],
        (Kind::BindingCreate, Class::Unrelated) => {
            vec![main(ManagementMutationV2::BindingCreate {
                row: binding_row(27, OTHER, 16, BindingLayer::Base),
                confirmation: binding_confirmation(47, 27, 16, &[1], false),
            })]
        }
        (Kind::BindingRemove, Class::Subject) => vec![main(ManagementMutationV2::BindingRemove {
            binding_id: [20; 16],
            removed_at: T1_NOW,
            removed_by: [1; 16],
        })],
        (Kind::BindingRemove, Class::Unrelated) => {
            vec![main(ManagementMutationV2::BindingRemove {
                binding_id: [23; 16],
                removed_at: T1_NOW,
                removed_by: [1; 16],
            })]
        }
        (Kind::ConfirmationCreate, Class::Subject) => {
            vec![main(ManagementMutationV2::ConfirmationCreate {
                row: binding_confirmation(48, 24, 17, &[1], false),
            })]
        }
        (Kind::ConfirmationCreate, Class::Unrelated) => {
            vec![main(ManagementMutationV2::ConfirmationCreate {
                row: binding_confirmation(49, 25, 14, &[2], false),
            })]
        }
        (Kind::ConfirmationRevoke, Class::Subject) => {
            vec![main(ManagementMutationV2::ConfirmationRevoke {
                confirmation_id: [40; 16],
                revoked_at: T1_NOW,
                revoked_by: [1; 16],
            })]
        }
        (Kind::ConfirmationRevoke, Class::Unrelated) => {
            vec![main(ManagementMutationV2::ConfirmationRevoke {
                confirmation_id: [43; 16],
                revoked_at: T1_NOW,
                revoked_by: [1; 16],
            })]
        }
        (Kind::RuleSetChangeConfirmationRevoke, Class::Subject) => {
            vec![main(
                ManagementMutationV2::RuleSetChangeConfirmationRevoke {
                    confirmation_id: [210; 16],
                    revoked_at: T1_NOW,
                    revoked_by: [1; 16],
                },
            )]
        }
        (Kind::RuleSetChangeConfirmationRevoke, Class::Unrelated) => {
            vec![main(
                ManagementMutationV2::RuleSetChangeConfirmationRevoke {
                    confirmation_id: [214; 16],
                    revoked_at: T1_NOW,
                    revoked_by: [1; 16],
                },
            )]
        }
        (Kind::ConfirmationBatch, Class::Subject) => {
            vec![main(ManagementMutationV2::ConfirmationBatch {
                rows: vec![binding_confirmation(50, 24, 17, &[1], false)],
            })]
        }
        (Kind::ConfirmationBatch, Class::Unrelated) => {
            vec![main(ManagementMutationV2::ConfirmationBatch {
                rows: vec![binding_confirmation(51, 25, 14, &[2], false)],
            })]
        }
        (Kind::UserCardCreate, Class::Subject) => {
            vec![main(ManagementMutationV2::UserCardCreate {
                row: UserCardRow {
                    user_card_id: [SUBJECT; 16],
                    user_id: [1; 16],
                    tenant_id: [3; 16],
                    status: UserCardStatus::Active,
                },
            })]
        }
        (Kind::UserCardCreate, Class::Unrelated) => {
            vec![main(ManagementMutationV2::UserCardCreate {
                row: UserCardRow {
                    user_card_id: [9; 16],
                    user_id: [1; 16],
                    tenant_id: [3; 16],
                    status: UserCardStatus::Active,
                },
            })]
        }
        (Kind::UserCardStatus, Class::Subject) => {
            vec![Write::PlainDisable(SUBJECT), Write::Disable(SUBJECT)]
        }
        (Kind::UserCardStatus, Class::Unrelated) => {
            vec![Write::PlainDisable(OTHER), Write::Disable(OTHER)]
        }
        (Kind::RuleSetCreate, Class::Subject) => vec![main(ManagementMutationV2::RuleSetCreate {
            rule_set: rule_set(10, &[1]),
            version: version_row([10; 16], &[1], &rule_content("R1", "ALLOW")),
            change_confirmation: change_confirmation(220, 10, &[1]),
        })],
        (Kind::RuleSetCreate, Class::Unrelated) => {
            vec![main(ManagementMutationV2::RuleSetCreate {
                rule_set: rule_set(15, &[1]),
                version: version_row([15; 16], &[1], &rule_content("R8", "ALLOW")),
                change_confirmation: change_confirmation(221, 15, &[1]),
            })]
        }
        (Kind::RuleSetRetire, Class::Subject) => vec![main(ManagementMutationV2::RuleSetRetire {
            rule_set_id: [10; 16],
        })],
        (Kind::RuleSetRetire, Class::Unrelated) => {
            vec![main(ManagementMutationV2::RuleSetRetire {
                rule_set_id: [16; 16],
            })]
        }
        (Kind::VersionPublish, Class::Subject) => {
            vec![main(ManagementMutationV2::VersionPublish {
                rule_set_id: [10; 16],
                version_row: version_row([10; 16], &[3], &rule_content("R1", "DENY")),
                new_current_version: vec![3],
                change_confirmation: change_confirmation(222, 10, &[3]),
            })]
        }
        (Kind::VersionPublish, Class::Unrelated) => {
            vec![main(ManagementMutationV2::VersionPublish {
                rule_set_id: [13; 16],
                version_row: version_row([13; 16], &[2], &rule_content("R4b", "ALLOW")),
                new_current_version: vec![2],
                change_confirmation: change_confirmation(223, 13, &[2]),
            })]
        }
        (Kind::VersionPublish, Class::SubjectNeutral) => {
            vec![main(ManagementMutationV2::VersionPublish {
                rule_set_id: [10; 16],
                version_row: version_row([10; 16], &[3], &rule_content("R1b", "ALLOW")),
                new_current_version: vec![3],
                change_confirmation: change_confirmation(224, 10, &[3]),
            })]
        }
        // memory—v1 (T1): A matrix row without a write plan is a table error, not a pass.
        _ => panic!("no write plan for {:?}/{:?}", row.kind, row.class),
    }
}

/// memory—v1 (T1): Install the base fixture as the process root and open the serving authority.
fn t1_install(subject_withdrawn_overlay: bool) -> (RootOwner, MemoryV1SessionAuthority) {
    let (rows, selections) = t1_base_rows(subject_withdrawn_overlay);
    let owner = install_process_root(
        rows,
        selections,
        CandidateBudget {
            max_table_rows: 256,
            max_bindings_per_read: 16,
        },
    )
    .expect("install the base fixture");
    owner
        .install_registry(&[RegistryDeclaration {
            resource: "document".to_owned(),
            actions: vec!["read".to_owned()],
        }])
        .expect("install registry");
    owner
        .adopt_serving_for_isolated_tests()
        .expect("adopt base fixture as serving");
    let authority = MemoryV1SessionAuthority::new();
    authority.bind_to_root(&owner).expect("bind authority");
    (owner, authority)
}

/// memory—v1 (T1): Issue the session for one card; sessions are valid on the fixed clock.
fn t1_issue(
    authority: &MemoryV1SessionAuthority,
    card: u8,
) -> astral_authorization_root::memory_v1_session_authority::MemoryV1IssuedSession {
    authority
        .identity_session_adapter()
        .issue_unchecked_for_test(subject_identity(card), T1_ISSUED, T1_LIFETIME)
        .expect("issue session")
}

/// memory—v1 (T1): Apply one write through the isolated executor and report whether it was accepted.
fn t1_apply(
    owner: &RootOwner,
    authority: &MemoryV1SessionAuthority,
    write: &Write,
    row: &Row,
) -> Result<(), String> {
    let before = owner.handle().metadata().expect("metadata").version;
    let result = match write {
        Write::Mutation(mutation) => {
            assert_eq!(
                kind_of(mutation),
                row.kind,
                "write does not match its matrix row"
            );
            owner
                .execute_mutation_with_precondition_for_isolated_tests(
                    mutation,
                    &MutationPrecondition {
                        evaluated_root_version: before,
                    },
                )
                .map(|_| ())
                .map_err(|error| format!("{error:?}"))
        }
        Write::Disable(card) => authority
            .disable_card_with_sessions_for_isolated_tests(
                &owner.mutation_executor(),
                MemoryId::from_bytes([*card; 16]),
                owner.handle().metadata().expect("metadata"),
            )
            .map(|_| ())
            .map_err(|error| format!("{error:?}")),
        Write::PlainDisable(card) => {
            let plain = ManagementMutationV2::UserCardStatus {
                user_card_id: [*card; 16],
                status: UserCardStatus::Disabled,
            };
            let refused = owner.execute_mutation_with_precondition_for_isolated_tests(
                &plain,
                &MutationPrecondition {
                    evaluated_root_version: before,
                },
            );
            // memory—v1 (T1): A plain disable must be refused before any candidate is built.
            assert!(
                matches!(
                    refused,
                    Err(MutationError::CardDisableRequiresSessionCoordinator)
                ),
                "plain Disabled write must require the session coordinator, got {refused:?}"
            );
            Err("refused: CardDisableRequiresSessionCoordinator".to_owned())
        }
    };
    let after = owner.handle().metadata().expect("metadata").version;
    match &result {
        Ok(()) => assert_eq!(
            after,
            before + 1,
            "an accepted write publishes exactly one version"
        ),
        Err(_) => assert_eq!(after, before, "a refused write must not advance the root"),
    }
    result
}

/// memory—v1 (T1): Fresh sequential evaluation of the subject after the write; None when
/// the session can no longer be bound (a revoked or disabled session has no live proof).
fn t1_fresh(
    owner: &RootOwner,
    authority: &MemoryV1SessionAuthority,
    issued: &astral_authorization_root::memory_v1_session_authority::MemoryV1IssuedSession,
    request: &MemoryV1Request<'_>,
) -> Option<MemoryV1Evaluation> {
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let session = authority
        .verifier()
        .verify_and_bind(issued.credential(), T1_ISSUED, &root)
        .ok()?;
    Some(evaluate_with(
        &root,
        &session,
        request,
        || Some(T1_NOW),
        || {},
    ))
}

/// memory—v1 (T1): Run one matrix row in the current process. The root is fresh, the
/// subject's ALLOW is verified before any write, and the in-flight decision and the
/// sequential predicate after the write must both agree with the row.
fn run_t1_scenario(kind: Kind, class: Class) {
    let row = row_for(kind, class);
    // memory—v1 (T1): Only the fresh subject overlay row must start without a subject overlay.
    let subject_withdrawn_overlay = !(kind == Kind::BindingCreate && class == Class::Subject);
    let (owner, authority) = t1_install(subject_withdrawn_overlay);
    let subject_issued = t1_issue(&authority, SUBJECT);
    let scope = RequestRootScope::new(owner.handle(), Default::default());
    let root = scope.extension();
    let session = authority
        .verifier()
        .verify_and_bind(subject_issued.credential(), T1_ISSUED, &root)
        .expect("bind subject session");
    let request = t1_request();

    // memory—v1 (T1): Baseline: the subject is admitted before any write, so the in-flight
    // result is a statement about the write and not about the fixture.
    let baseline = evaluate_with(&root, &session, &request, || Some(T1_NOW), || {});
    assert_eq!(
        baseline.decision,
        MemoryV1Decision::Allow,
        "baseline must admit the subject"
    );
    assert!(baseline.admission.is_some());

    let writes = t1_writes(kind, class);
    let mut outcomes: Vec<Result<(), String>> = Vec::new();
    let in_flight = evaluate_with(
        &root,
        &session,
        &request,
        || Some(T1_NOW),
        || {
            for write in &writes {
                outcomes.push(t1_apply(&owner, &authority, write, row));
            }
        },
    );

    // memory—v1 (T1): Each main write must succeed exactly when the row says it is applied.
    // Disable and PlainDisable carry their own expectation in `t1_apply`.
    for (write, outcome) in writes.iter().zip(&outcomes) {
        let expect_ok = match write {
            Write::Mutation(_) => row.applied,
            Write::Disable(_) => true,
            Write::PlainDisable(_) => false,
        };
        assert_eq!(
            outcome.is_ok(),
            expect_ok,
            "{kind:?}/{class:?}: write outcome {outcome:?} does not match the row"
        );
    }
    assert_eq!(
        outcomes.len(),
        writes.len(),
        "every write must run in flight"
    );

    match row.in_flight {
        Expect::Allow => {
            assert_eq!(
                in_flight.decision,
                MemoryV1Decision::Allow,
                "{kind:?}/{class:?}: in-flight decision must stay Allow: {}",
                row.why
            );
            assert!(in_flight.admission.is_some());
        }
        Expect::Pending => {
            assert_eq!(
                in_flight.decision,
                MemoryV1Decision::Pending,
                "{kind:?}/{class:?}: in-flight decision must be Pending: {}",
                row.why
            );
            assert!(
                in_flight.admission.is_none(),
                "a Pending result carries no admission"
            );
            assert_eq!(
                in_flight.pending_source,
                Some(MemoryV1PendingSource::ContextInvalid),
                "{kind:?}/{class:?}: the recheck must fail closed as ContextInvalid"
            );
        }
    }

    // memory—v1 (T1): Independent expectation from the rules: the sequential answer after
    // the write. A fresh evaluation must return Allow exactly where the predicate holds.
    let after = t1_fresh(&owner, &authority, &subject_issued, &request);
    match row.after {
        Predicate::Holds => {
            let after = after.expect("subject session must still bind when the predicate holds");
            assert_eq!(
                after.decision,
                MemoryV1Decision::Allow,
                "{kind:?}/{class:?}: sequential predicate should hold after the write"
            );
        }
        Predicate::Fails => {
            let admitted = after
                .as_ref()
                .is_some_and(|evaluation| evaluation.decision == MemoryV1Decision::Allow);
            assert!(
                !admitted,
                "{kind:?}/{class:?}: sequential predicate fails after the write; a fresh Allow is unsound"
            );
        }
    }

    // memory—v1 (T1): Consistency between the table and the evidence: an in-flight Allow is
    // sound only if the predicate holds; a Pending that is not a conservative rejection must
    // match a failing predicate.
    if row.in_flight == Expect::Allow {
        assert_eq!(row.after, Predicate::Holds, "table admits an unsound row");
    }
    let conservative = row.in_flight == Expect::Pending && row.after == Predicate::Holds;
    assert_eq!(
        conservative, row.conservative,
        "{kind:?}/{class:?}: the conservative flag must match the observed precision loss"
    );
}

/// memory—v1 (T1): Every (kind, class) pair that has a matrix row, as a child-process label.
fn t1_labels() -> Vec<String> {
    MATRIX
        .iter()
        .map(|row| format!("{:?}/{:?}", row.kind, row.class))
        .collect()
}

/// memory—v1 (T1): Parse a child label back to its kind and class.
fn parse_t1_label(label: &str) -> (Kind, Class) {
    let row = MATRIX
        .iter()
        .find(|row| format!("{:?}/{:?}", row.kind, row.class) == label)
        .unwrap_or_else(|| panic!("unknown T1 scenario {label}"));
    (row.kind, row.class)
}

/// memory—v1 (T1): Re-run this test binary once per scenario so each scenario owns the
/// process-wide root slot. A child process runs only the scenario named in the environment.
fn run_children(test_name: &str, env: &str, labels: &[String]) {
    for label in labels {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test_name, "--nocapture"])
            .env(env, label)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "scenario {label} failed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "scenario {label} did not report one passing test\nstdout: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

// memory—v1 (T1): Writer-coverage matrix, in flight. Every row runs in its own process
// against the real isolated executor and the real evaluator with the after-read hook.
#[test]
fn paper_t1_writer_matrix_in_flight() {
    if let Ok(label) = std::env::var(T1_ENV) {
        let (kind, class) = parse_t1_label(&label);
        run_t1_scenario(kind, class);
        return;
    }
    run_children(
        "memory_v1_formal::tests::paper_evidence::paper_t1_writer_matrix_in_flight",
        T1_ENV,
        &t1_labels(),
    );
}

// memory—v1 (T1): The matrix is data with one row per (kind, class), and every kind is
// exercised. A new variant fails `kind_of` at compile time before this test can run.
#[test]
fn paper_t1_matrix_has_one_row_per_kind_and_class() {
    for kind in ALL_KINDS {
        let subject = MATRIX
            .iter()
            .filter(|row| row.kind == kind && row.class == Class::Subject)
            .count();
        let unrelated = MATRIX
            .iter()
            .filter(|row| row.kind == kind && row.class == Class::Unrelated)
            .count();
        assert_eq!(subject, 1, "{kind:?} needs exactly one Subject row");
        assert_eq!(unrelated, 1, "{kind:?} needs exactly one Unrelated row");
    }
    // memory—v1 (T1): The table never admits a row whose predicate fails.
    for row in MATRIX {
        if row.in_flight == Expect::Allow {
            assert_eq!(
                row.after,
                Predicate::Holds,
                "{:?}/{:?}",
                row.kind,
                row.class
            );
        }
    }
    // memory—v1 (T1): A Pending row can only come from a write the executor applied; a refused
    // write leaves the admitted cut intact and must expect Allow.
    assert!(MATRIX
        .iter()
        .filter(|row| row.in_flight == Expect::Pending)
        .all(|row| row.applied));
}

/// memory—v1 (T1 witness): Environment gate for the witness child process.
const WITNESS_ENV: &str = "ASTRAL_MEMORY_V1_PAPER_WITNESS_SCENARIO";

// memory—v1 (T1 witness): The same freshness-violating state that the serving mutation path
// applies (matrix row RuleSetChangeConfirmationRevoke/Subject) is refused when installed as
// a candidate and adopted. Asserts current behaviour disclosed as a gap; update when fixed.
#[test]
fn witness_freshness_revocation_is_refused_only_at_adoption() {
    if let Ok(label) = std::env::var(WITNESS_ENV) {
        assert_eq!(label, "adoption", "unknown witness scenario");
        let (mut rows, selections) = t1_base_rows(true);
        let freshness = rows
            .rule_set_change_confirmations
            .iter_mut()
            .find(|row| row.confirmation_id == [210; 16])
            .expect("the subject's current-version freshness row exists in the base fixture");
        freshness.revoked_at = Some(T1_NOW);
        freshness.revoked_by = Some([1; 16]);
        let owner = install_process_root(
            rows,
            selections,
            CandidateBudget {
                max_table_rows: 256,
                max_bindings_per_read: 16,
            },
        )
        .expect("a candidate with a withdrawn current version still installs");
        owner
            .install_registry(&[RegistryDeclaration {
                resource: "document".to_owned(),
                actions: vec!["read".to_owned()],
            }])
            .expect("install registry");
        // memory—v1 (T1 witness): The adoption gate runs validate_for_serving and must refuse.
        let adopted = owner.adopt_serving_for_isolated_tests();
        assert!(
            adopted.is_err(),
            "adoption must refuse a current version without an active change confirmation: {adopted:?}"
        );
        return;
    }
    run_children(
        "memory_v1_formal::tests::paper_evidence::witness_freshness_revocation_is_refused_only_at_adoption",
        WITNESS_ENV,
        &["adoption".to_owned()],
    );
}

/// memory—v1 (T2): Environment gate for the envelope grid child process. The value is a chunk index.
const T2_ENV: &str = "ASTRAL_MEMORY_V1_PAPER_T2_SCENARIO";
/// memory—v1 (T2): Shapes per root. The digest caps one root at 4096 keys, and a shape adds at
/// most five keys (one user card, up to two bindings, and up to two binding confirmations), so
/// 256 shapes stay far inside the cap. The process-wide root slot is one-shot, so each chunk runs
/// in its own child process with its own root.
const T2_CHUNK: usize = 256;
/// memory—v1 (T2): A window `(from, until)`: `from` inclusive, `until` exclusive.
type T2Window = (Option<i64>, Option<i64>);
/// memory—v1 (T2): Window grammar. Empty windows (from >= until) are refused by the rule parser and
/// the binding validator, so they are not representable in the grid.
const T2_WINDOWS: [T2Window; 6] = [
    (None, None),
    (Some(10), Some(12)),
    (Some(11), Some(13)),
    (Some(12), Some(14)),
    (Some(13), None),
    (None, Some(12)),
];
/// memory—v1 (T2): Trusted clock values at the initial stage (T0).
const T2_T0: [i64; 4] = [10, 11, 12, 13];
/// memory—v1 (T2): Final samples. The set includes values before T0 (rollback) and past every end.
const T2_SAMPLES: [i64; 7] = [9, 10, 11, 12, 13, 14, 15];

/// memory—v1 (T2): One grid shape: an ALLOW pair and an optional DENY pair, each a
/// (binding window, entry window). Each shape is one card in a chunk root.
#[derive(Clone, Copy, Debug)]
struct T2Shape {
    allow_binding: T2Window,
    allow_entry: T2Window,
    deny: Option<(T2Window, T2Window)>,
}

// memory—v1 (T2): Every shape: 36 allow pairs, each with no DENY or one of 36 DENY pairs (1332).
fn t2_shapes() -> Vec<T2Shape> {
    let mut shapes = Vec::new();
    for allow_binding in T2_WINDOWS {
        for allow_entry in T2_WINDOWS {
            shapes.push(T2Shape {
                allow_binding,
                allow_entry,
                deny: None,
            });
            for deny_binding in T2_WINDOWS {
                for deny_entry in T2_WINDOWS {
                    shapes.push(T2Shape {
                        allow_binding,
                        allow_entry,
                        deny: Some((deny_binding, deny_entry)),
                    });
                }
            }
        }
    }
    shapes
}

// memory—v1 (T2): The shapes of one chunk, in grid order.
fn t2_chunk(index: usize) -> Vec<T2Shape> {
    t2_shapes()
        .chunks(T2_CHUNK)
        .nth(index)
        .expect("the T2 chunk index is in range")
        .to_vec()
}

// memory—v1 (T2): Rule content for one effect with an optional validity window.
fn t2_rule_content(effect: &str, window: T2Window) -> String {
    let mut fields = Vec::new();
    if let Some(from) = window.0 {
        fields.push(format!(r#""from":{from}"#));
    }
    if let Some(until) = window.1 {
        fields.push(format!(r#""until":{until}"#));
    }
    let validity = if fields.is_empty() {
        String::new()
    } else {
        format!(r#","validity":{{{}}}"#, fields.join(","))
    };
    format!(
        r#"{{"rules":[{{"ruleId":"R","resource":"document","action":"read","effect":"{effect}"{validity}}}]}}"#
    )
}

// memory—v1 (T2): Identifier with a distinct tag and an index in the first two bytes.
fn t2_id(tag: u8, index: usize) -> [u8; 16] {
    let mut id = [tag; 16];
    id[0] = (index >> 8) as u8;
    id[1] = index as u8;
    id
}

// memory—v1 (T2): Rule-set identifier for the allow (kind 0) or deny (kind 1) set of one window.
fn t2_set_id(kind: u8, window: usize) -> [u8; 16] {
    [0x40 + kind * 0x10 + window as u8; 16]
}

/// memory—v1 (T2): Scan oracle. A sample is admitted iff it is at or after T0, the ALLOW pair and
/// no DENY are active at T0, and at every integer instant from T0 to the sample the ALLOW pair is
/// active and no DENY is active. This is the soundness reference: it defines what a read may admit.
fn t2_scan_allow(shape: &T2Shape, t0: i64, sample: i64) -> bool {
    let active = |(from, until): T2Window, t: i64| {
        from.is_none_or(|from| from <= t) && until.is_none_or(|until| t < until)
    };
    let allow_at = |t: i64| active(shape.allow_binding, t) && active(shape.allow_entry, t);
    let deny_at = |t: i64| {
        shape
            .deny
            .is_some_and(|(binding, entry)| active(binding, t) && active(entry, t))
    };
    if sample < t0 || !(allow_at(t0) && !deny_at(t0)) {
        return false;
    }
    (t0..=sample).all(|t| allow_at(t) && !deny_at(t))
}

/// memory—v1 (T2): The paper's closed form I_q = [T0, b) ∩ W_A, with b the smallest future start in
/// B_q. A not-yet-open DENY binding contributes its own start, and an open binding contributes the
/// start of its entry. Expiry never adds a threshold. The closed form is contained in the scan
/// oracle; the gap is the disclosed dormant-DENY precision loss.
fn t2_paper_allow(shape: &T2Shape, t0: i64, sample: i64) -> bool {
    t2_paper_allow_with(shape, t0, sample, Mutant::None)
}

/// memory—v1 (T2): Oracle mutants. Each one is a plausible implementation error in the envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mutant {
    /// The faithful closed form.
    None,
    /// Treats the until bound as inclusive, admitting the instant at the end of a window.
    InclusiveUntil,
    /// Drops the rollback check, admitting samples before T0.
    NoRollbackCheck,
    /// Ignores every recorded future threshold, so a later DENY never cuts the envelope.
    NoThresholds,
    /// Ignores the binding start of a dormant DENY binding, using its entry start instead.
    NoDormantBindingThreshold,
}

// memory—v1 (T2): The closed-form oracle with a selectable mutation.
fn t2_paper_allow_with(shape: &T2Shape, t0: i64, sample: i64, mutant: Mutant) -> bool {
    let active = |(from, until): T2Window, t: i64| {
        from.is_none_or(|from| from <= t)
            && until.is_none_or(|until| {
                if mutant == Mutant::InclusiveUntil {
                    t <= until
                } else {
                    t < until
                }
            })
    };
    let allow_at = |t: i64| active(shape.allow_binding, t) && active(shape.allow_entry, t);
    let deny_at = |t: i64| {
        shape
            .deny
            .is_some_and(|(binding, entry)| active(binding, t) && active(entry, t))
    };
    if (sample < t0 && mutant != Mutant::NoRollbackCheck) || !(allow_at(t0) && !deny_at(t0)) {
        return false;
    }
    // A recorded threshold for a pair, following the paper's B_q: a binding not yet open at T0
    // cuts at its own start; a binding open at T0 cuts at the future start of its entry; a binding
    // already expired at T0 can never become active again and records nothing.
    let threshold = |(binding, entry): (T2Window, T2Window)| {
        let dormant = binding.0.is_some_and(|start| start > t0);
        let open =
            binding.0.is_none_or(|start| start <= t0) && binding.1.is_none_or(|until| t0 < until);
        if dormant && mutant != Mutant::NoDormantBindingThreshold {
            binding.0
        } else if dormant || open {
            entry.0.filter(|start| *start > t0)
        } else {
            None
        }
    };
    let mut thresholds = vec![threshold((shape.allow_binding, shape.allow_entry))];
    if let Some(deny) = shape.deny {
        thresholds.push(threshold(deny));
    }
    let bound = if mutant == Mutant::NoThresholds {
        i64::MAX
    } else {
        thresholds.into_iter().flatten().min().unwrap_or(i64::MAX)
    };
    sample < bound && allow_at(sample)
}

// memory—v1 (T2): Build one chunk root: one card per shape, an active base ALLOW binding and, when
// present, an active overlay DENY binding, each on its own window rule set.
fn t2_install(shapes: &[T2Shape]) -> (RootOwner, MemoryV1SessionAuthority) {
    let mut rows = CandidateRows {
        users: vec![UserRow { user_id: [1; 16] }],
        identity_cards: vec![IdentityCardRow {
            identity_card_id: [2; 16],
            user_id: [1; 16],
        }],
        tenants: vec![TenantRow {
            tenant_id: [3; 16],
            parent_tenant_id: None,
        }],
        ..CandidateRows::default()
    };
    let version = vec![1];
    let timestamp = vec![2];
    for (kind, contents) in [
        (
            0_u8,
            T2_WINDOWS.map(|window| t2_rule_content("ALLOW", window)),
        ),
        (
            1_u8,
            T2_WINDOWS.map(|window| t2_rule_content("DENY", window)),
        ),
    ] {
        for (index, content) in contents.iter().enumerate() {
            let set = t2_set_id(kind, index);
            let input = canonical_version_bytes(&version, content.as_bytes(), &timestamp);
            rows.rule_sets.push(RuleSetRow {
                status: RuleSetStatus::Active,
                rule_set_id: set,
                owner_tenant_id: [3; 16],
                current_version_bytes: version.clone(),
            });
            rows.rule_set_versions.push(RuleSetVersionRow {
                rule_set_id: set,
                version_bytes: version.clone(),
                content_bytes: content.as_bytes().to_vec(),
                timestamp_bytes: timestamp.clone(),
                hash_bytes: version_digest(&input),
                hash_input_bytes: input,
            });
            rows.rule_set_change_confirmations
                .push(RuleSetChangeConfirmationRow {
                    confirmation_id: t2_id(0xE0, usize::from(kind) * 16 + index),
                    rule_set_id: set,
                    version_bytes: version.clone(),
                    confirmer_user_id: [1; 16],
                    affected_scope_bytes: vec![1],
                    operation_id: vec![1],
                    confirmed_at_bytes: vec![1],
                    revoked_at: None,
                    revoked_by: None,
                });
        }
    }
    let mut selections = Vec::new();
    for kind in [0_u8, 1_u8] {
        for index in 0..T2_WINDOWS.len() {
            selections.push(CurrentSelection {
                rule_set_id: t2_set_id(kind, index),
                version_bytes: version.clone(),
            });
        }
    }
    let window_index = |window: T2Window| {
        T2_WINDOWS
            .iter()
            .position(|candidate| *candidate == window)
            .expect("the grid window is in the fixed set")
    };
    for (index, shape) in shapes.iter().enumerate() {
        let card = t2_id(0xC1, index);
        rows.user_cards.push(UserCardRow {
            user_card_id: card,
            user_id: [1; 16],
            tenant_id: [3; 16],
            status: UserCardStatus::Active,
        });
        let allow_binding = t2_id(0xB1, 2 * index);
        rows.bindings.push(BindingRow {
            binding_id: allow_binding,
            user_card_id: card,
            rule_set_id: t2_set_id(0, window_index(shape.allow_entry)),
            binding_layer: BindingLayer::Base,
            valid_from: shape.allow_binding.0,
            valid_until: shape.allow_binding.1,
            owner_scope: MemoryV1OwnerScope::default(),
            tenant_scope: MemoryV1TenantScope::default(),
            removed_at: None,
            removed_by: None,
        });
        rows.binding_confirmations.push(BindingConfirmationRow {
            confirmation_id: t2_id(0xD1, 2 * index),
            binding_id: allow_binding,
            rule_set_id: t2_set_id(0, window_index(shape.allow_entry)),
            version_bytes: version.clone(),
            confirmer_user_id: [1; 16],
            scope_bytes: vec![1],
            operation_id: vec![1],
            confirmed_at_bytes: vec![1],
            revoked_at: None,
            revoked_by: None,
        });
        if let Some((deny_binding, deny_entry)) = shape.deny {
            let overlay = t2_id(0xB1, 2 * index + 1);
            rows.bindings.push(BindingRow {
                binding_id: overlay,
                user_card_id: card,
                rule_set_id: t2_set_id(1, window_index(deny_entry)),
                binding_layer: BindingLayer::Overlay,
                valid_from: deny_binding.0,
                valid_until: deny_binding.1,
                owner_scope: MemoryV1OwnerScope::default(),
                tenant_scope: MemoryV1TenantScope::default(),
                removed_at: None,
                removed_by: None,
            });
            rows.binding_confirmations.push(BindingConfirmationRow {
                confirmation_id: t2_id(0xD1, 2 * index + 1),
                binding_id: overlay,
                rule_set_id: t2_set_id(1, window_index(deny_entry)),
                version_bytes: version.clone(),
                confirmer_user_id: [1; 16],
                scope_bytes: vec![1],
                operation_id: vec![1],
                confirmed_at_bytes: vec![1],
                revoked_at: None,
                revoked_by: None,
            });
        }
    }
    let owner = install_process_root(
        rows,
        selections,
        CandidateBudget {
            max_table_rows: 16_384,
            max_bindings_per_read: 8,
        },
    )
    .expect("install the envelope chunk");
    owner
        .install_registry(&[RegistryDeclaration {
            resource: "document".to_owned(),
            actions: vec!["read".to_owned()],
        }])
        .expect("install registry");
    owner
        .adopt_serving_for_isolated_tests()
        .expect("adopt the envelope chunk as serving");
    let authority = MemoryV1SessionAuthority::new();
    authority.bind_to_root(&owner).expect("bind authority");
    (owner, authority)
}

// memory—v1 (T2): Run one chunk in its own root and check every evaluation against both oracles.
// Hard assertions: production never admits where the scan oracle refuses (soundness), and production
// admits exactly where the paper's closed form admits (envelope).
fn run_t2_chunk(chunk: usize) {
    let shapes = t2_chunk(chunk);
    let (owner, authority) = t2_install(&shapes);
    let request = t1_request();
    let mut evaluations = 0_usize;
    let mut production_allows = 0_usize;
    for (index, shape) in shapes.iter().enumerate() {
        let card = t2_id(0xC1, index);
        let issued = authority
            .identity_session_adapter()
            .issue_unchecked_for_test(
                CandidateIdentity {
                    user_id: MemoryId::from_bytes([1; 16]),
                    identity_card_id: MemoryId::from_bytes([2; 16]),
                    user_card_id: MemoryId::from_bytes(card),
                    tenant_id: MemoryId::from_bytes([3; 16]),
                },
                0,
                86_400,
            )
            .expect("issue the grid session");
        let scope = RequestRootScope::new(owner.handle(), Default::default());
        let root = scope.extension();
        let session = authority
            .verifier()
            .verify_and_bind(issued.credential(), 0, &root)
            .expect("bind the grid session");
        for t0 in T2_T0 {
            for sample in T2_SAMPLES {
                let mut clock_values = [t0, sample].into_iter();
                let result =
                    evaluate_with(&root, &session, &request, || clock_values.next(), || {});
                let allowed = result.decision == MemoryV1Decision::Allow;
                if allowed {
                    let admission = result
                        .admission
                        .as_ref()
                        .expect("Allow carries an admission");
                    assert_eq!(
                        admission.trusted_time_unix_seconds(),
                        sample,
                        "an admission records the final sample"
                    );
                } else {
                    assert!(result.admission.is_none());
                }
                let sound = t2_scan_allow(shape, t0, sample);
                let paper = t2_paper_allow(shape, t0, sample);
                assert!(
                    !allowed || sound,
                    "UNSOUND: shape {shape:?} T0={t0} sample={sample} admitted outside the scan oracle"
                );
                assert_eq!(
                    allowed, paper,
                    "envelope mismatch: shape {shape:?} T0={t0} sample={sample}"
                );
                evaluations += 1;
                production_allows += usize::from(allowed);
            }
        }
    }
    assert!(
        production_allows > 0 && production_allows < evaluations,
        "a chunk must exercise both outcomes"
    );
    println!(
        "T2 chunk {chunk}: shapes={} evaluations={evaluations} production_allow={production_allows}",
        shapes.len()
    );
}

// memory—v1 (T2): Full-evaluator envelope differential. Each chunk runs in a child process with its
// own root; together the chunks cover every shape of the grid.
#[test]
fn paper_t2_envelope_grid_matches_closed_form() {
    if let Ok(label) = std::env::var(T2_ENV) {
        let chunk = label.parse::<usize>().expect("T2 chunk index");
        run_t2_chunk(chunk);
        return;
    }
    let chunks = t2_shapes().len().div_ceil(T2_CHUNK);
    let labels: Vec<String> = (0..chunks).map(|chunk| chunk.to_string()).collect();
    run_children(
        "memory_v1_formal::tests::paper_evidence::paper_t2_envelope_grid_matches_closed_form",
        T2_ENV,
        &labels,
    );
}

// memory—v1 (T2): Pure oracle properties over the whole grid, with no root. The closed form lies
// inside the scan oracle, the grid separates the two (the dormant-DENY gap is exhibited), and every
// mutant disagrees with the faithful closed form somewhere. Because the chunk test requires
// production to equal the faithful closed form on every shape, a mutant disagreement here means the
// chunk test would reject that mutant's envelope on the same point.
#[test]
fn paper_t2_oracle_properties_hold_on_the_full_grid() {
    let shapes = t2_shapes();
    assert_eq!(
        shapes.len(),
        1332,
        "36 allow pairs, each with 37 DENY options"
    );
    let mut total = 0_usize;
    let mut admitted = 0_usize;
    let mut conservative = 0_usize;
    for shape in &shapes {
        for t0 in T2_T0 {
            for sample in T2_SAMPLES {
                let sound = t2_scan_allow(shape, t0, sample);
                let paper = t2_paper_allow(shape, t0, sample);
                assert!(
                    !paper || sound,
                    "closed form admits outside the scan oracle: {shape:?} T0={t0} sample={sample}"
                );
                total += 1;
                admitted += usize::from(paper);
                conservative += usize::from(sound && !paper);
            }
        }
    }
    assert!(
        admitted > 0 && admitted < total,
        "the grid must exercise both outcomes"
    );
    assert!(
        conservative > 0,
        "the grid must exhibit the disclosed dormant-DENY precision loss"
    );
    // The paper quotes these three counts, so they are pinned: 1,332 shapes x 4 starts x 7 samples,
    // the points the closed form admits, and the points the scan oracle admits but the closed form
    // abstains on (the disclosed dormant-DENY gap). A change here is a change to a quoted number.
    assert_eq!(
        (total, admitted, conservative),
        (37_296, 1_661, 128),
        "the T2 grid counts quoted in the paper must be re-derived before they change"
    );
    for mutant in [
        Mutant::InclusiveUntil,
        Mutant::NoRollbackCheck,
        Mutant::NoThresholds,
        Mutant::NoDormantBindingThreshold,
    ] {
        let mut disagreements = 0_usize;
        for shape in &shapes {
            for t0 in T2_T0 {
                for sample in T2_SAMPLES {
                    disagreements += usize::from(
                        t2_paper_allow_with(shape, t0, sample, mutant)
                            != t2_paper_allow(shape, t0, sample),
                    );
                }
            }
        }
        assert!(
            disagreements > 0,
            "mutant {mutant:?} must be distinguishable on the grid"
        );
    }
    println!(
        "T2 oracle: shapes={} evaluations={total} closed_form_allow={admitted} dormant_deny_gap={conservative}",
        shapes.len()
    );
}

// ---------------------------------------------------------------------------------------------
// T2b: two ALLOW pairs on one card
// ---------------------------------------------------------------------------------------------

/// memory—v1 (T2b): Environment gate for the two-allow grid child process. The value is a chunk index.
const T2B_ENV: &str = "ASTRAL_MEMORY_V1_PAPER_T2B_SCENARIO";

/// memory—v1 (T2b): One shape of the two-allow grid: two ALLOW pairs on one card, each a
/// (binding window, entry window), and no DENY. The shapes are ordered pairs, so every pair is the
/// first allow in half of the shapes and the second in the other half. A mutation that counts the
/// window of one allow only is therefore exercised whichever allow the evaluator visits first.
#[derive(Clone, Copy, Debug)]
struct T2bShape {
    first: (T2Window, T2Window),
    second: (T2Window, T2Window),
}

// memory—v1 (T2b): Every ordered pair of ALLOW pairs: 36 x 36 = 1,296 shapes.
fn t2b_shapes() -> Vec<T2bShape> {
    let pairs: Vec<(T2Window, T2Window)> = T2_WINDOWS
        .iter()
        .flat_map(|binding| T2_WINDOWS.iter().map(move |entry| (*binding, *entry)))
        .collect();
    pairs
        .iter()
        .flat_map(|first| {
            pairs.iter().map(move |second| T2bShape {
                first: *first,
                second: *second,
            })
        })
        .collect()
}

// memory—v1 (T2b): The shapes of one chunk, in grid order.
fn t2b_chunk(index: usize) -> Vec<T2bShape> {
    t2b_shapes()
        .chunks(T2_CHUNK)
        .nth(index)
        .expect("the T2b chunk index is in range")
        .to_vec()
}

// memory—v1 (T2b): Whether a window contains the instant.
fn t2b_active((from, until): T2Window, t: i64) -> bool {
    from.is_none_or(|from| from <= t) && until.is_none_or(|until| t < until)
}

/// memory—v1 (T2b): Scan oracle for two allows. A sample is admitted iff it is at or after T0 and,
/// at every integer instant from T0 to the sample, at least one allow pair is active. This is the
/// soundness reference: a read must not admit where no allow holds at some instant of the range.
fn t2b_scan_allow(shape: &T2bShape, t0: i64, sample: i64) -> bool {
    let any_allow = |t: i64| {
        [shape.first, shape.second]
            .into_iter()
            .any(|(binding, entry)| t2b_active(binding, t) && t2b_active(entry, t))
    };
    sample >= t0 && any_allow(t0) && (t0..=sample).all(any_allow)
}

/// memory—v1 (T2b): Mutants of the closed form that count the windows of fewer allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum T2bMutant {
    /// The faithful closed form: every winning allow's window must contain the sample.
    None,
    /// Only the first winning allow's window must contain the sample.
    FirstWinningOnly,
    /// Only the last winning allow's window must contain the sample.
    LastWinningOnly,
}

/// memory—v1 (T2b): Why the closed form refuses a sample, or that it admits it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum T2bVerdict {
    /// The sample lies in I_q.
    Admit,
    /// The sample precedes T0, or no allow pair contains T0.
    NoWinningAllow,
    /// The sample is at or after the smallest future start recorded by a binding.
    Threshold,
    /// The sample lies in [T0, b), but a counted winning window no longer contains it.
    WindowEnded,
}

/// memory—v1 (T2b): The paper's closed form I_q = [T0, b) ∩ ⋂ W_e over every winning allow, with b
/// the smallest future start recorded by any binding. A pair wins when its binding window and its
/// entry window both contain T0. A winning window that has ended refuses the sample even when the
/// other allow still holds; that is the precision loss of Lemma `abstain`.
fn t2b_paper_verdict(shape: &T2bShape, t0: i64, sample: i64, mutant: T2bMutant) -> T2bVerdict {
    let pairs = [shape.first, shape.second];
    let winning: Vec<(T2Window, T2Window)> = pairs
        .into_iter()
        .filter(|(binding, entry)| t2b_active(*binding, t0) && t2b_active(*entry, t0))
        .collect();
    if sample < t0 || winning.is_empty() {
        return T2bVerdict::NoWinningAllow;
    }
    let threshold = |(binding, entry): (T2Window, T2Window)| {
        let dormant = binding.0.is_some_and(|start| start > t0);
        let open =
            binding.0.is_none_or(|start| start <= t0) && binding.1.is_none_or(|until| t0 < until);
        if dormant {
            binding.0
        } else if open {
            entry.0.filter(|start| *start > t0)
        } else {
            None
        }
    };
    let bound = pairs
        .into_iter()
        .filter_map(threshold)
        .min()
        .unwrap_or(i64::MAX);
    if sample >= bound {
        return T2bVerdict::Threshold;
    }
    let counted: &[(T2Window, T2Window)] = match mutant {
        T2bMutant::None => &winning,
        T2bMutant::FirstWinningOnly => &winning[..1],
        T2bMutant::LastWinningOnly => &winning[winning.len() - 1..],
    };
    if counted
        .iter()
        .all(|(binding, entry)| t2b_active(*binding, sample) && t2b_active(*entry, sample))
    {
        T2bVerdict::Admit
    } else {
        T2bVerdict::WindowEnded
    }
}

// memory—v1 (T2b): The closed form with a selectable mutation, as a Boolean.
fn t2b_paper_allow_with(shape: &T2bShape, t0: i64, sample: i64, mutant: T2bMutant) -> bool {
    t2b_paper_verdict(shape, t0, sample, mutant) == T2bVerdict::Admit
}

// memory—v1 (T2b): The faithful closed form for two allows.
fn t2b_paper_allow(shape: &T2bShape, t0: i64, sample: i64) -> bool {
    t2b_paper_allow_with(shape, t0, sample, T2bMutant::None)
}

// memory—v1 (T2b): Build one chunk root: one card per shape with two active base ALLOW bindings.
// The first binding uses a rule set of the first family and the second a rule set of the second
// family, so both allows may carry the same entry window without binding one rule set twice.
fn t2b_install(shapes: &[T2bShape]) -> (RootOwner, MemoryV1SessionAuthority) {
    let mut rows = CandidateRows {
        users: vec![UserRow { user_id: [1; 16] }],
        identity_cards: vec![IdentityCardRow {
            identity_card_id: [2; 16],
            user_id: [1; 16],
        }],
        tenants: vec![TenantRow {
            tenant_id: [3; 16],
            parent_tenant_id: None,
        }],
        ..CandidateRows::default()
    };
    let version = vec![1];
    let timestamp = vec![2];
    let mut selections = Vec::new();
    for family in [0_u8, 2_u8] {
        for (index, window) in T2_WINDOWS.iter().enumerate() {
            let content = t2_rule_content("ALLOW", *window);
            let set = t2_set_id(family, index);
            let input = canonical_version_bytes(&version, content.as_bytes(), &timestamp);
            rows.rule_sets.push(RuleSetRow {
                status: RuleSetStatus::Active,
                rule_set_id: set,
                owner_tenant_id: [3; 16],
                current_version_bytes: version.clone(),
            });
            rows.rule_set_versions.push(RuleSetVersionRow {
                rule_set_id: set,
                version_bytes: version.clone(),
                content_bytes: content.as_bytes().to_vec(),
                timestamp_bytes: timestamp.clone(),
                hash_bytes: version_digest(&input),
                hash_input_bytes: input,
            });
            rows.rule_set_change_confirmations
                .push(RuleSetChangeConfirmationRow {
                    confirmation_id: t2_id(0xE0, usize::from(family) * 16 + index),
                    rule_set_id: set,
                    version_bytes: version.clone(),
                    confirmer_user_id: [1; 16],
                    affected_scope_bytes: vec![1],
                    operation_id: vec![1],
                    confirmed_at_bytes: vec![1],
                    revoked_at: None,
                    revoked_by: None,
                });
            selections.push(CurrentSelection {
                rule_set_id: set,
                version_bytes: version.clone(),
            });
        }
    }
    let window_index = |window: T2Window| {
        T2_WINDOWS
            .iter()
            .position(|candidate| *candidate == window)
            .expect("the grid window is in the fixed set")
    };
    for (index, shape) in shapes.iter().enumerate() {
        let card = t2_id(0xC1, index);
        rows.user_cards.push(UserCardRow {
            user_card_id: card,
            user_id: [1; 16],
            tenant_id: [3; 16],
            status: UserCardStatus::Active,
        });
        for (slot, (family, (binding_window, entry_window))) in
            [(0_u8, shape.first), (2_u8, shape.second)]
                .into_iter()
                .enumerate()
        {
            let binding = t2_id(0xB1, 2 * index + slot);
            let set = t2_set_id(family, window_index(entry_window));
            rows.bindings.push(BindingRow {
                binding_id: binding,
                user_card_id: card,
                rule_set_id: set,
                binding_layer: BindingLayer::Base,
                valid_from: binding_window.0,
                valid_until: binding_window.1,
                owner_scope: MemoryV1OwnerScope::default(),
                tenant_scope: MemoryV1TenantScope::default(),
                removed_at: None,
                removed_by: None,
            });
            rows.binding_confirmations.push(BindingConfirmationRow {
                confirmation_id: t2_id(0xD1, 2 * index + slot),
                binding_id: binding,
                rule_set_id: set,
                version_bytes: version.clone(),
                confirmer_user_id: [1; 16],
                scope_bytes: vec![1],
                operation_id: vec![1],
                confirmed_at_bytes: vec![1],
                revoked_at: None,
                revoked_by: None,
            });
        }
    }
    let owner = install_process_root(
        rows,
        selections,
        CandidateBudget {
            max_table_rows: 16_384,
            max_bindings_per_read: 8,
        },
    )
    .expect("install the two-allow chunk");
    owner
        .install_registry(&[RegistryDeclaration {
            resource: "document".to_owned(),
            actions: vec!["read".to_owned()],
        }])
        .expect("install registry");
    owner
        .adopt_serving_for_isolated_tests()
        .expect("adopt the two-allow chunk as serving");
    let authority = MemoryV1SessionAuthority::new();
    authority.bind_to_root(&owner).expect("bind authority");
    (owner, authority)
}

// memory—v1 (T2b): Run one chunk in its own root and check every evaluation against both oracles.
// Hard assertions: production never admits where the scan oracle refuses, and production admits
// exactly where the closed form over every winning window admits.
fn run_t2b_chunk(chunk: usize) {
    let shapes = t2b_chunk(chunk);
    let (owner, authority) = t2b_install(&shapes);
    let request = t1_request();
    let mut evaluations = 0_usize;
    let mut production_allows = 0_usize;
    for (index, shape) in shapes.iter().enumerate() {
        let card = t2_id(0xC1, index);
        let issued = authority
            .identity_session_adapter()
            .issue_unchecked_for_test(
                CandidateIdentity {
                    user_id: MemoryId::from_bytes([1; 16]),
                    identity_card_id: MemoryId::from_bytes([2; 16]),
                    user_card_id: MemoryId::from_bytes(card),
                    tenant_id: MemoryId::from_bytes([3; 16]),
                },
                0,
                86_400,
            )
            .expect("issue the two-allow session");
        let scope = RequestRootScope::new(owner.handle(), Default::default());
        let root = scope.extension();
        let session = authority
            .verifier()
            .verify_and_bind(issued.credential(), 0, &root)
            .expect("bind the two-allow session");
        for t0 in T2_T0 {
            for sample in T2_SAMPLES {
                let mut clock_values = [t0, sample].into_iter();
                let result =
                    evaluate_with(&root, &session, &request, || clock_values.next(), || {});
                let allowed = result.decision == MemoryV1Decision::Allow;
                if allowed {
                    let admission = result
                        .admission
                        .as_ref()
                        .expect("Allow carries an admission");
                    assert_eq!(
                        admission.trusted_time_unix_seconds(),
                        sample,
                        "an admission records the final sample"
                    );
                } else {
                    assert!(result.admission.is_none());
                }
                assert!(
                    !allowed || t2b_scan_allow(shape, t0, sample),
                    "UNSOUND: shape {shape:?} T0={t0} sample={sample} admitted outside the scan oracle"
                );
                assert_eq!(
                    allowed,
                    t2b_paper_allow(shape, t0, sample),
                    "envelope mismatch: shape {shape:?} T0={t0} sample={sample}"
                );
                evaluations += 1;
                production_allows += usize::from(allowed);
            }
        }
    }
    assert!(
        production_allows > 0 && production_allows < evaluations,
        "a chunk must exercise both outcomes"
    );
    println!(
        "T2b chunk {chunk}: shapes={} evaluations={evaluations} production_allow={production_allows}",
        shapes.len()
    );
}

// memory—v1 (T2b): Full-evaluator envelope differential for two allows. Each chunk runs in a child
// process with its own root; together the chunks cover every shape of the grid.
#[test]
fn paper_t2b_two_allow_envelope_matches_closed_form() {
    if let Ok(label) = std::env::var(T2B_ENV) {
        let chunk = label.parse::<usize>().expect("T2b chunk index");
        run_t2b_chunk(chunk);
        return;
    }
    let chunks = t2b_shapes().len().div_ceil(T2_CHUNK);
    let labels: Vec<String> = (0..chunks).map(|chunk| chunk.to_string()).collect();
    run_children(
        "memory_v1_formal::tests::paper_evidence::paper_t2b_two_allow_envelope_matches_closed_form",
        T2B_ENV,
        &labels,
    );
}

// memory—v1 (T2b): Pure oracle properties over the whole two-allow grid, with no root. The closed
// form lies inside the scan oracle, the grid separates the two (a winning window that has ended
// refuses a sample although another allow remains), and each mutant that counts fewer windows
// disagrees with the faithful closed form somewhere. A mutant here is sound but admits more, so
// only the equality with the faithful closed form, which the chunk test requires of production,
// can detect it.
#[test]
fn paper_t2b_oracle_properties_hold_on_the_full_grid() {
    let shapes = t2b_shapes();
    assert_eq!(shapes.len(), 1296, "36 allow pairs, ordered, twice");
    let mut total = 0_usize;
    let mut admitted = 0_usize;
    let mut at_threshold = 0_usize;
    let mut window_ended = 0_usize;
    for shape in &shapes {
        for t0 in T2_T0 {
            for sample in T2_SAMPLES {
                let sound = t2b_scan_allow(shape, t0, sample);
                let verdict = t2b_paper_verdict(shape, t0, sample, T2bMutant::None);
                let paper = verdict == T2bVerdict::Admit;
                assert!(
                    !paper || sound,
                    "closed form admits outside the scan oracle: {shape:?} T0={t0} sample={sample}"
                );
                if sound && !paper {
                    match verdict {
                        T2bVerdict::Threshold => at_threshold += 1,
                        T2bVerdict::WindowEnded => window_ended += 1,
                        other => panic!("scan-admitted point refused as {other:?}: {shape:?}"),
                    }
                }
                total += 1;
                admitted += usize::from(paper);
            }
        }
    }
    println!(
        "T2b oracle counts: total={total} closed_form_allow={admitted} gap_at_threshold={at_threshold} gap_window_ended={window_ended}"
    );
    assert!(
        admitted > 0 && admitted < total,
        "the grid must exercise both outcomes"
    );
    assert!(
        window_ended > 0,
        "the grid must exhibit the precision loss of intersecting every winning window"
    );
    // The paper quotes these counts, so they are pinned: 1,296 ordered shapes x 4 starts x 7 samples,
    // the points the closed form admits, and the scan-oracle points it refuses because a recorded
    // start lies at or before the sample or because a winning window has ended while another allow
    // remains. A change here is a change to a quoted number.
    assert_eq!(
        (total, admitted, at_threshold, window_ended),
        (36_288, 3_821, 1_266, 402),
        "the T2b grid counts quoted in the paper must be re-derived before they change"
    );
    for mutant in [T2bMutant::FirstWinningOnly, T2bMutant::LastWinningOnly] {
        let mut disagreements = 0_usize;
        for shape in &shapes {
            for t0 in T2_T0 {
                for sample in T2_SAMPLES {
                    disagreements += usize::from(
                        t2b_paper_allow_with(shape, t0, sample, mutant)
                            != t2b_paper_allow(shape, t0, sample),
                    );
                }
            }
        }
        assert!(
            disagreements > 0,
            "mutant {mutant:?} must be distinguishable on the grid"
        );
    }
}
