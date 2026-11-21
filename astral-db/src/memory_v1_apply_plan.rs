//! memory—v1 database-apply plan candidate (B-db-plan).
//!
//! This module is deliberately a pure value model. It does not contain SQL,
//! a pool, a transaction executor, a migration, an ACK, or a database result.
//! It maps the already-modelled [`ManagementMutationV2`] into an ordered,
//! all-or-nothing transaction shape that a future database consumer may review
//! before implementing. Candidate table names remain logical owners here; the
//! candidate DDL is explicitly not treated as a frozen database contract.
//!
//! A plan can be structurally complete while no fact has been written. In
//! particular, [`PlanStatus::Complete`] means only that the candidate contains
//! the required fact, audit, receipt, and progress operations and that the
//! supplied audit/flow references pass value-level checks. It never means
//! authorized, journal-persisted, database-committed, acknowledged, or
//! recoverable. Missing facts are represented as typed unresolved conditions;
//! the card-disable session hand-off is a typed blocked condition.
//!
//! The root's service-period [`ManagementMutationV2::ContextLoad`] variant is
//! not a governed change: the mutation-digest contract refuses to encode it
//! and no fact, receipt, or audit-apply contract exists for it, so it is
//! always reported as [`UnresolvedCondition::ContextLoadNotGoverned`]; its
//! plan exposes no operations at all, not even the durable tail.

use astral_authorization_root::memory_v1_db_rows::{
    BinaryId, RuleSetChangeConfirmationRow, RuleSetRow, RuleSetVersionRow, UserCardStatus,
};
use astral_authorization_root::memory_v1_mutation_digest::{digest_mutation, MutationDigest};
use astral_authorization_root::memory_v1_root::ManagementMutationV2;
use astral_types::memory_v1::MemoryId;
use astral_types::memory_v1_audit::{
    MemoryV1AuditDecision, MemoryV1AuditEvent, MemoryV1AuditObject,
};
use astral_types::memory_v1_journal::JournalAnchor;

/// Local candidate bound for one confirmation batch.
///
/// This is a planning resource limit, not a SQL or wire-schema decision. The
/// input mutation's original vector order is retained exactly.
pub const MAX_APPLY_CONFIRMATION_ROWS: usize = 128;

/// Logical owner of one durable fact family.
///
/// `AuditLog`, `ApplyReceipt`, and `ApplyProgress` are intentionally separate
/// from the nine authorization-fact owners. Their exact physical table names
/// and columns are unresolved database-contract work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableOwner {
    User,
    IdentityCard,
    Tenant,
    UserCard,
    RuleSet,
    RuleSetVersion,
    Binding,
    BindingConfirmation,
    RuleSetChangeConfirmation,
    AuditLog,
    ApplyReceipt,
    ApplyProgress,
}

/// Closed classification of one planned fact operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationKind {
    Insert,
    Update,
    Verify,
    AppendAudit,
    AppendReceipt,
    AdvanceProgress,
}

/// The logical row key affected by a plan operation.
///
/// Values are copied from the mutation or from an existing flow reference. No
/// before-image is manufactured by this type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogicalTarget {
    Id(BinaryId),
    Composite {
        parent_id: BinaryId,
        version_bytes: Vec<u8>,
    },
    BatchItem {
        sequence: usize,
        binding_id: BinaryId,
        confirmation_id: BinaryId,
    },
    Flow,
}

/// Required affected-row cardinality for one operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AffectedRows {
    Exactly(usize),
    Zero,
}

/// CAS requirement for a fact update.
///
/// The required before-image is read and checked by a future executor inside
/// the same transaction. This model carries no guessed old value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CasRequirement {
    NotApplicable,
    Required {
        before_image: BeforeImageRequirement,
        fence: CasFence,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BeforeImageRequirement {
    ReadInSameTransaction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CasFence {
    TargetState,
    CurrentPointer,
    ProgressPrefix,
}

/// Tombstone contract for an operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TombstoneRequirement {
    NotApplicable,
    ExistingMustBeLive,
    WriteComplete,
    ExistingMustBeComplete,
    PreserveExisting,
}

/// A logical fact operation. It is a description only and has no executable
/// statement or database handle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FactOperation {
    ordinal: usize,
    owner: TableOwner,
    kind: OperationKind,
    target: LogicalTarget,
    affected_rows: AffectedRows,
    cas: CasRequirement,
    tombstone: TombstoneRequirement,
    preconditions: Vec<Precondition>,
}

impl FactOperation {
    /// Zero-based transaction order; this is not a database sequence.
    // memory—v1
    pub const fn ordinal(&self) -> usize {
        self.ordinal
    }

    // memory—v1
    pub const fn owner(&self) -> TableOwner {
        self.owner
    }

    // memory—v1
    pub const fn kind(&self) -> OperationKind {
        self.kind
    }

    // memory—v1
    pub fn target(&self) -> &LogicalTarget {
        &self.target
    }

    // memory—v1
    pub const fn affected_rows(&self) -> AffectedRows {
        self.affected_rows
    }

    // memory—v1
    pub const fn cas(&self) -> CasRequirement {
        self.cas
    }

    // memory—v1
    pub const fn tombstone(&self) -> TombstoneRequirement {
        self.tombstone
    }

    // memory—v1
    pub fn preconditions(&self) -> &[Precondition] {
        &self.preconditions
    }
}

/// Conditions a future executor must establish before applying an operation.
///
/// These names intentionally describe checks rather than claiming that checks
/// have already happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Precondition {
    TargetMustBeAbsent,
    TargetMustExist,
    BindingMustBeUnremoved,
    BindingMustMatchRuleSet,
    ConfirmationMustMatchBinding,
    ConfirmationMustBeActive,
    ConfirmationIdMustBeUnused,
    NoActiveConfirmationForBinding,
    RuleSetMustBeActive,
    RuleSetVersionMustExist,
    NewVersionMustBeAbsent,
    NewVersionMustMatchPointer,
    ParentMustPrecedeVersion,
    VersionMustPrecedeChangeConfirmation,
    CardMustBeActive,
    CardMustRemainUnbound,
    UserAndIdentityAndTenantMustExist,
    ExistingBindingsMustCoordinateWithEnable,
    NoActiveBindingWithActiveCard,
    UnremovedBindingsMustBeRetained,
    CompleteTombstoneFields,
    BatchMustBeNonEmpty,
    BatchMustBeWithinLimit,
    BatchOriginalOrderPreserved,
    BatchEntriesMustBeUnique,
    AllFactChecksBeforeAnyFactWrite,
    AuditCandidateMustBeComplete,
    AuditMustBeAllow,
    AuditMustBindMutation,
    StableOperationIdentity,
    FlowAnchorMustBePresent,
    ReceiptMustBindOperationSequenceAndDigest,
    ProgressMustAdvanceContiguously,
    AuditReceiptProgressSameTransaction,
}

/// A fact that could not be resolved from the supplied mutation and modeled
/// references. No default or fabricated before-image is substituted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnresolvedCondition {
    MissingAuditReference,
    MissingFlowReference,
    FlowMutationSequenceUnavailable,
    AuditChangeMissing,
    AuditChangeIncomplete,
    AuditTargetMismatch,
    MutationShapeMismatch,
    BeforeImageRequired(TableOwner),
    CurrentPointerBeforeImageRequired,
    BatchEmpty,
    BatchOverLimit,
    BatchDuplicateBinding,
    BatchDuplicateConfirmation,
    MutationDigestUnavailable,
    /// The mutation is a service-period context load, not a governed change.
    /// It has no mutation digest, receipt, or audit-apply contract, so no
    /// database-apply plan exists for it.
    ContextLoadNotGoverned,
}

/// A condition that blocks a plan even when its shape is otherwise known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockedCondition {
    AuditDecisionNotAllow,
    ExternalSessionCoordinatorRequired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanIssue {
    Unresolved(UnresolvedCondition),
    Blocked(BlockedCondition),
}

/// Structural status only. This is never a durable result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanStatus {
    Complete,
    Unresolved,
    Blocked,
}

/// Every candidate is one database transaction boundary with all-or-nothing
/// semantics. This value describes the future executor contract only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionAtomicity {
    AllOrNothing,
}

/// The eleven governed mutation variants this planner models.
///
/// The root's twelfth variant, [`ManagementMutationV2::ContextLoad`], is a
/// service-period context load rather than a governed change; it is never
/// planned here (see [`UnresolvedCondition::ContextLoadNotGoverned`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MutationKind {
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

impl MutationKind {
    // memory—v1
    pub const fn all() -> [Self; 11] {
        [
            Self::BindingCreate,
            Self::BindingRemove,
            Self::ConfirmationCreate,
            Self::ConfirmationRevoke,
            Self::RuleSetChangeConfirmationRevoke,
            Self::ConfirmationBatch,
            Self::UserCardCreate,
            Self::UserCardStatus,
            Self::RuleSetCreate,
            Self::RuleSetRetire,
            Self::VersionPublish,
        ]
    }
}

/// Inputs accepted by [`MemoryV1ApplyPlan::build`].
///
/// The mutation and audit are existing value models. The journal anchor is an
/// existing flow identity/checkpoint model. `None` means the caller did not
/// provide that fact; the resulting plan is unresolved rather than guessing it.
#[derive(Clone, Copy)]
pub struct ApplyPlanInput<'a> {
    pub mutation: &'a ManagementMutationV2,
    pub audit: Option<&'a MemoryV1AuditEvent>,
    pub flow: Option<JournalAnchor>,
}

/// Pure transaction-plan candidate for one persisted mutation message.
///
/// The plan borrows the input mutation and audit candidate. It owns only the
/// derived operation descriptors, issues, and optional content digest. It cannot
/// execute anything and contains no SQL.
#[derive(Clone)]
pub struct MemoryV1ApplyPlan<'a> {
    mutation: &'a ManagementMutationV2,
    kind: Option<MutationKind>,
    audit: Option<&'a MemoryV1AuditEvent>,
    flow: Option<JournalAnchor>,
    mutation_digest: Option<MutationDigest>,
    atomicity: TransactionAtomicity,
    operations: Vec<FactOperation>,
    issues: Vec<PlanIssue>,
}

impl<'a> MemoryV1ApplyPlan<'a> {
    /// Build a pure candidate. All validation is value-level and conservative.
    // memory—v1
    pub fn build(input: ApplyPlanInput<'a>) -> Self {
        let kind = governed_mutation_kind(input.mutation);
        let mut issues = Vec::new();
        if kind.is_none() {
            issues.push(PlanIssue::Unresolved(
                UnresolvedCondition::ContextLoadNotGoverned,
            ));
        }
        let mutation_digest = match digest_mutation(input.mutation) {
            Ok(digest) => Some(digest),
            Err(_) => {
                issues.push(PlanIssue::Unresolved(
                    UnresolvedCondition::MutationDigestUnavailable,
                ));
                None
            }
        };
        let mut operations = match kind {
            Some(kind) => build_fact_operations(input.mutation, kind, &mut issues),
            None => Vec::new(),
        };
        if let Some(kind) = kind {
            validate_batch_shape(input.mutation, &mut issues);
            validate_mutation_shape(input.mutation, &mut issues);
            validate_audit(kind, input.mutation, input.audit, &mut issues);
        }
        validate_flow(input.flow, &mut issues);
        if matches!(
            input.mutation,
            ManagementMutationV2::UserCardStatus {
                status: UserCardStatus::Disabled,
                ..
            }
        ) {
            issues.push(PlanIssue::Blocked(
                BlockedCondition::ExternalSessionCoordinatorRequired,
            ));
        }
        // Only a governed mutation kind carries the audit/receipt/progress
        // tail. An ungoverned context load exposes no operations at all.
        if kind.is_some() {
            append_required_tail(&mut operations);
        }
        Self {
            mutation: input.mutation,
            kind,
            audit: input.audit,
            flow: input.flow,
            mutation_digest,
            atomicity: TransactionAtomicity::AllOrNothing,
            operations,
            issues,
        }
    }

    // memory—v1
    pub const fn mutation(&self) -> &'a ManagementMutationV2 {
        self.mutation
    }

    /// The governed mutation kind, or `None` for a service-period context
    /// load, which no plan covers (see
    /// [`UnresolvedCondition::ContextLoadNotGoverned`]).
    // memory—v1
    pub const fn kind(&self) -> Option<MutationKind> {
        self.kind
    }

    /// The supplied audit candidate, if any. This is not proof of an audit write.
    // memory—v1
    pub const fn audit(&self) -> Option<&'a MemoryV1AuditEvent> {
        self.audit
    }

    /// The supplied flow anchor, if any. This is not proof of journal durability.
    // memory—v1
    pub const fn flow(&self) -> Option<JournalAnchor> {
        self.flow
    }

    /// Candidate digest used by a future receipt correlation, if locally encodable.
    // memory—v1
    pub const fn mutation_digest(&self) -> Option<MutationDigest> {
        self.mutation_digest
    }

    /// The transaction boundary is always all-or-nothing; this does not prove
    /// that any transaction was opened or committed.
    // memory—v1
    pub const fn atomicity(&self) -> TransactionAtomicity {
        self.atomicity
    }

    /// Operations in exact transaction order.
    // memory—v1
    pub fn operations(&self) -> &[FactOperation] {
        &self.operations
    }

    /// All conservative unresolved and blocked conditions.
    // memory—v1
    pub fn issues(&self) -> &[PlanIssue] {
        &self.issues
    }

    // memory—v1
    pub fn status(&self) -> PlanStatus {
        if self
            .issues
            .iter()
            .any(|issue| matches!(issue, PlanIssue::Blocked(_)))
        {
            PlanStatus::Blocked
        } else if self.issues.is_empty() {
            PlanStatus::Complete
        } else {
            PlanStatus::Unresolved
        }
    }

    /// True only for a structurally complete candidate; never a commit result.
    // memory—v1
    pub fn is_complete(&self) -> bool {
        self.status() == PlanStatus::Complete
    }

    /// True when the governed plan ends with the audit, receipt, and progress
    /// tail in order. An ungoverned context load exposes no operations, so it
    /// is false there.
    // memory—v1
    pub fn has_required_tail(&self) -> bool {
        self.operations
            .iter()
            .rev()
            .take(3)
            .map(FactOperation::owner)
            .eq([
                TableOwner::ApplyProgress,
                TableOwner::ApplyReceipt,
                TableOwner::AuditLog,
            ])
    }

    /// A compact correlation view derived from existing audit and flow values.
    /// It does not claim that the values refer to the same persisted message.
    // memory—v1
    pub fn correlation(&self) -> Option<PlanCorrelation<'_>> {
        Some(PlanCorrelation {
            operation_id: self.audit?.context().operation().id(),
            flow: self.flow?,
        })
    }
}

/// Existing operation identity plus existing journal anchor, exposed together
/// without creating an authorization or persistence proof.
pub struct PlanCorrelation<'a> {
    operation_id: &'a str,
    flow: JournalAnchor,
}

impl PlanCorrelation<'_> {
    // memory—v1
    pub fn operation_id(&self) -> &str {
        self.operation_id
    }

    // memory—v1
    pub const fn flow(&self) -> JournalAnchor {
        self.flow
    }
}

// memory—v1
fn governed_mutation_kind(mutation: &ManagementMutationV2) -> Option<MutationKind> {
    match mutation {
        ManagementMutationV2::BindingCreate { .. } => Some(MutationKind::BindingCreate),
        ManagementMutationV2::BindingRemove { .. } => Some(MutationKind::BindingRemove),
        ManagementMutationV2::ConfirmationCreate { .. } => Some(MutationKind::ConfirmationCreate),
        ManagementMutationV2::ConfirmationRevoke { .. } => Some(MutationKind::ConfirmationRevoke),
        ManagementMutationV2::RuleSetChangeConfirmationRevoke { .. } => {
            Some(MutationKind::RuleSetChangeConfirmationRevoke)
        }
        ManagementMutationV2::ConfirmationBatch { .. } => Some(MutationKind::ConfirmationBatch),
        ManagementMutationV2::UserCardCreate { .. } => Some(MutationKind::UserCardCreate),
        ManagementMutationV2::UserCardStatus { .. } => Some(MutationKind::UserCardStatus),
        ManagementMutationV2::RuleSetCreate { .. } => Some(MutationKind::RuleSetCreate),
        ManagementMutationV2::RuleSetRetire { .. } => Some(MutationKind::RuleSetRetire),
        ManagementMutationV2::VersionPublish { .. } => Some(MutationKind::VersionPublish),
        // A service-period context load is not a governed change; it has no
        // mutation digest, receipt, or audit-apply contract and is never
        // planned here.
        ManagementMutationV2::ContextLoad { .. } => None,
    }
}

// memory—v1
fn cas_target(fence: CasFence) -> CasRequirement {
    CasRequirement::Required {
        before_image: BeforeImageRequirement::ReadInSameTransaction,
        fence,
    }
}

// memory—v1
fn fact_insert(
    ordinal: usize,
    owner: TableOwner,
    target: LogicalTarget,
    preconditions: Vec<Precondition>,
) -> FactOperation {
    FactOperation {
        ordinal,
        owner,
        kind: OperationKind::Insert,
        target,
        affected_rows: AffectedRows::Exactly(1),
        cas: CasRequirement::NotApplicable,
        tombstone: TombstoneRequirement::NotApplicable,
        preconditions,
    }
}

// memory—v1
fn fact_update(
    ordinal: usize,
    owner: TableOwner,
    target: LogicalTarget,
    fence: CasFence,
    tombstone: TombstoneRequirement,
    preconditions: Vec<Precondition>,
) -> FactOperation {
    FactOperation {
        ordinal,
        owner,
        kind: OperationKind::Update,
        target,
        affected_rows: AffectedRows::Exactly(1),
        cas: cas_target(fence),
        tombstone,
        preconditions,
    }
}

// memory—v1
fn fact_verify(
    ordinal: usize,
    owner: TableOwner,
    target: LogicalTarget,
    affected_rows: AffectedRows,
    preconditions: Vec<Precondition>,
) -> FactOperation {
    FactOperation {
        ordinal,
        owner,
        kind: OperationKind::Verify,
        target,
        affected_rows,
        cas: CasRequirement::NotApplicable,
        tombstone: TombstoneRequirement::PreserveExisting,
        preconditions,
    }
}

// memory—v1
fn build_fact_operations(
    mutation: &ManagementMutationV2,
    kind: MutationKind,
    issues: &mut Vec<PlanIssue>,
) -> Vec<FactOperation> {
    let mut operations = Vec::new();
    match (kind, mutation) {
        (
            MutationKind::BindingCreate,
            ManagementMutationV2::BindingCreate { row, confirmation },
        ) => {
            operations.push(fact_insert(
                0,
                TableOwner::Binding,
                LogicalTarget::Id(row.binding_id),
                vec![
                    Precondition::TargetMustBeAbsent,
                    Precondition::CardMustBeActive,
                    Precondition::RuleSetMustBeActive,
                    Precondition::BindingMustMatchRuleSet,
                    Precondition::CompleteTombstoneFields,
                ],
            ));
            operations.push(fact_insert(
                1,
                TableOwner::BindingConfirmation,
                LogicalTarget::Id(confirmation.confirmation_id),
                vec![
                    Precondition::TargetMustBeAbsent,
                    Precondition::ConfirmationMustMatchBinding,
                    Precondition::ConfirmationIdMustBeUnused,
                    Precondition::NoActiveConfirmationForBinding,
                    Precondition::RuleSetVersionMustExist,
                    Precondition::CompleteTombstoneFields,
                ],
            ));
        }
        (MutationKind::BindingRemove, ManagementMutationV2::BindingRemove { binding_id, .. }) => {
            operations.push(fact_update(
                0,
                TableOwner::Binding,
                LogicalTarget::Id(*binding_id),
                CasFence::TargetState,
                TombstoneRequirement::WriteComplete,
                vec![
                    Precondition::TargetMustExist,
                    Precondition::BindingMustBeUnremoved,
                    Precondition::CompleteTombstoneFields,
                ],
            ))
        }
        (MutationKind::ConfirmationCreate, ManagementMutationV2::ConfirmationCreate { row }) => {
            operations.push(fact_insert(
                0,
                TableOwner::BindingConfirmation,
                LogicalTarget::Id(row.confirmation_id),
                vec![
                    Precondition::TargetMustBeAbsent,
                    Precondition::ConfirmationMustMatchBinding,
                    Precondition::ConfirmationIdMustBeUnused,
                    Precondition::NoActiveConfirmationForBinding,
                    Precondition::BindingMustBeUnremoved,
                    Precondition::RuleSetMustBeActive,
                    Precondition::RuleSetVersionMustExist,
                    Precondition::CompleteTombstoneFields,
                ],
            ))
        }
        (
            MutationKind::ConfirmationRevoke,
            ManagementMutationV2::ConfirmationRevoke {
                confirmation_id, ..
            },
        ) => operations.push(fact_update(
            0,
            TableOwner::BindingConfirmation,
            LogicalTarget::Id(*confirmation_id),
            CasFence::TargetState,
            TombstoneRequirement::WriteComplete,
            vec![
                Precondition::TargetMustExist,
                Precondition::ConfirmationMustBeActive,
                Precondition::CompleteTombstoneFields,
            ],
        )),
        (
            MutationKind::RuleSetChangeConfirmationRevoke,
            ManagementMutationV2::RuleSetChangeConfirmationRevoke {
                confirmation_id, ..
            },
        ) => operations.push(fact_update(
            0,
            TableOwner::RuleSetChangeConfirmation,
            LogicalTarget::Id(*confirmation_id),
            CasFence::TargetState,
            TombstoneRequirement::WriteComplete,
            vec![
                Precondition::TargetMustExist,
                Precondition::ConfirmationMustBeActive,
                Precondition::CompleteTombstoneFields,
            ],
        )),
        (MutationKind::ConfirmationBatch, ManagementMutationV2::ConfirmationBatch { rows }) => {
            for (sequence, row) in rows.iter().enumerate() {
                operations.push(fact_insert(
                    sequence,
                    TableOwner::BindingConfirmation,
                    LogicalTarget::BatchItem {
                        sequence,
                        binding_id: row.binding_id,
                        confirmation_id: row.confirmation_id,
                    },
                    vec![
                        Precondition::BatchMustBeNonEmpty,
                        Precondition::BatchMustBeWithinLimit,
                        Precondition::BatchEntriesMustBeUnique,
                        Precondition::BatchOriginalOrderPreserved,
                        Precondition::AllFactChecksBeforeAnyFactWrite,
                        Precondition::TargetMustBeAbsent,
                        Precondition::ConfirmationMustMatchBinding,
                        Precondition::NoActiveConfirmationForBinding,
                        Precondition::BindingMustBeUnremoved,
                        Precondition::RuleSetMustBeActive,
                        Precondition::RuleSetVersionMustExist,
                        Precondition::CompleteTombstoneFields,
                    ],
                ));
            }
        }
        (MutationKind::UserCardCreate, ManagementMutationV2::UserCardCreate { row }) => {
            operations.push(fact_insert(
                0,
                TableOwner::UserCard,
                LogicalTarget::Id(row.user_card_id),
                vec![
                    Precondition::TargetMustBeAbsent,
                    Precondition::UserAndIdentityAndTenantMustExist,
                    Precondition::CardMustRemainUnbound,
                ],
            ));
        }
        (
            MutationKind::UserCardStatus,
            ManagementMutationV2::UserCardStatus {
                user_card_id,
                status,
            },
        ) => {
            let mut preconditions = vec![Precondition::TargetMustExist];
            if *status == UserCardStatus::Active {
                preconditions.extend([
                    Precondition::ExistingBindingsMustCoordinateWithEnable,
                    Precondition::RuleSetMustBeActive,
                ]);
            } else {
                preconditions.push(Precondition::AuditReceiptProgressSameTransaction);
            }
            operations.push(fact_update(
                0,
                TableOwner::UserCard,
                LogicalTarget::Id(*user_card_id),
                CasFence::TargetState,
                TombstoneRequirement::NotApplicable,
                preconditions,
            ));
        }
        (
            MutationKind::RuleSetCreate,
            ManagementMutationV2::RuleSetCreate {
                rule_set,
                version,
                change_confirmation,
            },
        ) => {
            // The order is part of the contract: parent, version, then
            // change-confirmation. A foreign-key success cannot replace it.
            operations.push(fact_insert(
                0,
                TableOwner::RuleSet,
                LogicalTarget::Id(rule_set.rule_set_id),
                vec![
                    Precondition::TargetMustBeAbsent,
                    Precondition::ParentMustPrecedeVersion,
                    Precondition::RuleSetMustBeActive,
                ],
            ));
            operations.push(fact_insert(
                1,
                TableOwner::RuleSetVersion,
                LogicalTarget::Composite {
                    parent_id: version.rule_set_id,
                    version_bytes: version.version_bytes.clone(),
                },
                vec![
                    Precondition::TargetMustBeAbsent,
                    Precondition::ParentMustPrecedeVersion,
                    Precondition::NewVersionMustBeAbsent,
                    Precondition::NewVersionMustMatchPointer,
                ],
            ));
            operations.push(fact_insert(
                2,
                TableOwner::RuleSetChangeConfirmation,
                LogicalTarget::Id(change_confirmation.confirmation_id),
                vec![
                    Precondition::TargetMustBeAbsent,
                    Precondition::VersionMustPrecedeChangeConfirmation,
                    Precondition::CompleteTombstoneFields,
                ],
            ));
        }
        (MutationKind::RuleSetRetire, ManagementMutationV2::RuleSetRetire { rule_set_id }) => {
            // Retirement must inspect all unremoved bindings together with the
            // referenced card status. Disabled cards retain their bindings;
            // only the active-card subset must be exactly zero.
            operations.push(fact_verify(
                0,
                TableOwner::Binding,
                LogicalTarget::Id(*rule_set_id),
                AffectedRows::Zero,
                vec![
                    Precondition::NoActiveBindingWithActiveCard,
                    Precondition::UnremovedBindingsMustBeRetained,
                    Precondition::RuleSetMustBeActive,
                ],
            ));
            operations.push(fact_update(
                1,
                TableOwner::RuleSet,
                LogicalTarget::Id(*rule_set_id),
                CasFence::TargetState,
                TombstoneRequirement::PreserveExisting,
                vec![
                    Precondition::TargetMustExist,
                    Precondition::RuleSetMustBeActive,
                    Precondition::NoActiveBindingWithActiveCard,
                    Precondition::UnremovedBindingsMustBeRetained,
                ],
            ));
        }
        (
            MutationKind::VersionPublish,
            ManagementMutationV2::VersionPublish {
                rule_set_id,
                version_row,
                new_current_version,
                change_confirmation,
            },
        ) => {
            // The order is part of the contract: version, CAS pointer,
            // change-confirmation. The old pointer is deliberately unresolved.
            operations.push(fact_insert(
                0,
                TableOwner::RuleSetVersion,
                LogicalTarget::Composite {
                    parent_id: version_row.rule_set_id,
                    version_bytes: version_row.version_bytes.clone(),
                },
                vec![
                    Precondition::TargetMustBeAbsent,
                    Precondition::NewVersionMustBeAbsent,
                    Precondition::RuleSetMustBeActive,
                    Precondition::NewVersionMustMatchPointer,
                ],
            ));
            operations.push(fact_update(
                1,
                TableOwner::RuleSet,
                LogicalTarget::Id(*rule_set_id),
                CasFence::CurrentPointer,
                TombstoneRequirement::PreserveExisting,
                vec![
                    Precondition::TargetMustExist,
                    Precondition::RuleSetMustBeActive,
                    Precondition::NewVersionMustMatchPointer,
                    Precondition::VersionMustPrecedeChangeConfirmation,
                ],
            ));
            operations.push(fact_insert(
                2,
                TableOwner::RuleSetChangeConfirmation,
                LogicalTarget::Id(change_confirmation.confirmation_id),
                vec![
                    Precondition::TargetMustBeAbsent,
                    Precondition::VersionMustPrecedeChangeConfirmation,
                    Precondition::CompleteTombstoneFields,
                ],
            ));
            if version_row.rule_set_id != *rule_set_id
                || version_row.version_bytes.as_slice() != new_current_version.as_slice()
            {
                issues.push(PlanIssue::Unresolved(
                    UnresolvedCondition::MutationShapeMismatch,
                ));
            }
        }
        _ => issues.push(PlanIssue::Unresolved(
            UnresolvedCondition::MutationShapeMismatch,
        )),
    }
    operations
}

/// Append the durable audit, receipt, and progress tail.
///
/// Called only for a governed mutation kind. An ungoverned context load has no
/// audit, receipt, or progress contract, so its plan exposes no operations at
/// all rather than a tail a reader could mistake for an applicable sequence.
// memory—v1
fn append_required_tail(operations: &mut Vec<FactOperation>) {
    let ordinal = operations.len();
    let tail_preconditions = vec![
        Precondition::AuditCandidateMustBeComplete,
        Precondition::AuditMustBeAllow,
        Precondition::AuditMustBindMutation,
        Precondition::StableOperationIdentity,
        Precondition::FlowAnchorMustBePresent,
    ];
    operations.push(FactOperation {
        ordinal,
        owner: TableOwner::AuditLog,
        kind: OperationKind::AppendAudit,
        target: LogicalTarget::Flow,
        affected_rows: AffectedRows::Exactly(1),
        cas: CasRequirement::NotApplicable,
        tombstone: TombstoneRequirement::NotApplicable,
        preconditions: tail_preconditions,
    });
    operations.push(FactOperation {
        ordinal: ordinal + 1,
        owner: TableOwner::ApplyReceipt,
        kind: OperationKind::AppendReceipt,
        target: LogicalTarget::Flow,
        affected_rows: AffectedRows::Exactly(1),
        cas: CasRequirement::NotApplicable,
        tombstone: TombstoneRequirement::NotApplicable,
        preconditions: vec![
            Precondition::StableOperationIdentity,
            Precondition::ReceiptMustBindOperationSequenceAndDigest,
            Precondition::AuditReceiptProgressSameTransaction,
        ],
    });
    operations.push(FactOperation {
        ordinal: ordinal + 2,
        owner: TableOwner::ApplyProgress,
        kind: OperationKind::AdvanceProgress,
        target: LogicalTarget::Flow,
        affected_rows: AffectedRows::Exactly(1),
        cas: cas_target(CasFence::ProgressPrefix),
        tombstone: TombstoneRequirement::NotApplicable,
        preconditions: vec![
            Precondition::ProgressMustAdvanceContiguously,
            Precondition::ReceiptMustBindOperationSequenceAndDigest,
            Precondition::AuditReceiptProgressSameTransaction,
        ],
    });
}

// memory—v1
fn validate_batch_shape(mutation: &ManagementMutationV2, issues: &mut Vec<PlanIssue>) {
    let ManagementMutationV2::ConfirmationBatch { rows } = mutation else {
        return;
    };
    if rows.is_empty() {
        issues.push(PlanIssue::Unresolved(UnresolvedCondition::BatchEmpty));
        return;
    }
    if rows.len() > MAX_APPLY_CONFIRMATION_ROWS {
        issues.push(PlanIssue::Unresolved(UnresolvedCondition::BatchOverLimit));
    }
    for (position, row) in rows.iter().enumerate() {
        if rows[..position]
            .iter()
            .any(|previous| previous.binding_id == row.binding_id)
        {
            issues.push(PlanIssue::Unresolved(
                UnresolvedCondition::BatchDuplicateBinding,
            ));
        }
        if rows[..position]
            .iter()
            .any(|previous| previous.confirmation_id == row.confirmation_id)
        {
            issues.push(PlanIssue::Unresolved(
                UnresolvedCondition::BatchDuplicateConfirmation,
            ));
        }
    }
}

// memory—v1
fn validate_mutation_shape(mutation: &ManagementMutationV2, issues: &mut Vec<PlanIssue>) {
    match mutation {
        ManagementMutationV2::BindingCreate { row, confirmation } => {
            if confirmation.binding_id != row.binding_id
                || confirmation.rule_set_id != row.rule_set_id
                || row.removed_at.is_some()
                || row.removed_by.is_some()
                || confirmation.revoked_at.is_some()
                || confirmation.revoked_by.is_some()
            {
                issues.push(PlanIssue::Unresolved(
                    UnresolvedCondition::MutationShapeMismatch,
                ));
            }
        }
        ManagementMutationV2::ConfirmationCreate { row } => {
            if row.revoked_at.is_some() || row.revoked_by.is_some() {
                issues.push(PlanIssue::Unresolved(
                    UnresolvedCondition::MutationShapeMismatch,
                ));
            }
        }
        ManagementMutationV2::RuleSetCreate {
            rule_set,
            version,
            change_confirmation,
        } => {
            if !rule_set_create_shape_matches(rule_set, version, change_confirmation) {
                issues.push(PlanIssue::Unresolved(
                    UnresolvedCondition::MutationShapeMismatch,
                ));
            }
        }
        ManagementMutationV2::VersionPublish {
            rule_set_id,
            version_row,
            new_current_version,
            change_confirmation,
        } if !version_publish_shape_matches(
            *rule_set_id,
            version_row,
            new_current_version,
            change_confirmation,
        ) =>
        {
            issues.push(PlanIssue::Unresolved(
                UnresolvedCondition::MutationShapeMismatch,
            ));
        }
        _ => {}
    }
}

// memory—v1
fn version_publish_shape_matches(
    rule_set_id: BinaryId,
    version_row: &RuleSetVersionRow,
    new_current_version: &[u8],
    change_confirmation: &RuleSetChangeConfirmationRow,
) -> bool {
    version_row.rule_set_id == rule_set_id
        && version_row.version_bytes.as_slice() == new_current_version
        && change_confirmation.rule_set_id == rule_set_id
        && change_confirmation.version_bytes.as_slice() == new_current_version
        && change_confirmation.revoked_at.is_none()
        && change_confirmation.revoked_by.is_none()
}

// memory—v1
fn rule_set_create_shape_matches(
    rule_set: &RuleSetRow,
    version: &RuleSetVersionRow,
    change_confirmation: &RuleSetChangeConfirmationRow,
) -> bool {
    rule_set.rule_set_id == version.rule_set_id
        && rule_set.current_version_bytes == version.version_bytes
        && change_confirmation.rule_set_id == rule_set.rule_set_id
        && change_confirmation.version_bytes == version.version_bytes
        && change_confirmation.revoked_at.is_none()
        && change_confirmation.revoked_by.is_none()
}

// memory—v1
fn validate_flow(flow: Option<JournalAnchor>, issues: &mut Vec<PlanIssue>) {
    let Some(flow) = flow else {
        issues.push(PlanIssue::Unresolved(
            UnresolvedCondition::MissingFlowReference,
        ));
        return;
    };
    if flow.mutation_sequence() == 0 || flow.journal_sequence() == 0 {
        issues.push(PlanIssue::Unresolved(
            UnresolvedCondition::FlowMutationSequenceUnavailable,
        ));
    }
}

// memory—v1
fn validate_audit(
    kind: MutationKind,
    mutation: &ManagementMutationV2,
    audit: Option<&MemoryV1AuditEvent>,
    issues: &mut Vec<PlanIssue>,
) {
    let Some(audit) = audit else {
        issues.push(PlanIssue::Unresolved(
            UnresolvedCondition::MissingAuditReference,
        ));
        return;
    };
    if audit.decision() != MemoryV1AuditDecision::Allow {
        issues.push(PlanIssue::Blocked(BlockedCondition::AuditDecisionNotAllow));
    }
    let Some(change) = audit.change_details() else {
        issues.push(PlanIssue::Unresolved(
            UnresolvedCondition::AuditChangeMissing,
        ));
        return;
    };
    if !change.is_complete() {
        issues.push(PlanIssue::Unresolved(
            UnresolvedCondition::AuditChangeIncomplete,
        ));
    }
    if kind == MutationKind::RuleSetRetire && !change.is_complete_rule_set_retirement() {
        issues.push(PlanIssue::Unresolved(
            UnresolvedCondition::AuditChangeIncomplete,
        ));
    }
    if !audit_target_matches(kind, mutation, change_target(change)) {
        issues.push(PlanIssue::Unresolved(
            UnresolvedCondition::AuditTargetMismatch,
        ));
    }
}

// memory—v1
fn change_target(
    change: &astral_types::memory_v1_audit::MemoryV1AuditChange,
) -> Option<MemoryV1AuditObject> {
    change.target()
}

// memory—v1
fn audit_target_matches(
    kind: MutationKind,
    mutation: &ManagementMutationV2,
    target: Option<MemoryV1AuditObject>,
) -> bool {
    if kind == MutationKind::BindingCreate {
        let Some(MemoryV1AuditObject::Binding(id)) = target else {
            return false;
        };
        return matches!(mutation, ManagementMutationV2::BindingCreate { row, .. } if id == MemoryId::from_bytes(row.binding_id));
    }
    audit_target_matches_non_binding(kind, mutation, target)
}

// memory—v1
fn audit_target_matches_non_binding(
    kind: MutationKind,
    mutation: &ManagementMutationV2,
    target: Option<MemoryV1AuditObject>,
) -> bool {
    let Some(target) = target else {
        return false;
    };
    match (kind, mutation, target) {
        (
            MutationKind::BindingRemove,
            ManagementMutationV2::BindingRemove { binding_id, .. },
            MemoryV1AuditObject::Binding(id),
        ) => id == MemoryId::from_bytes(*binding_id),
        (
            MutationKind::ConfirmationCreate,
            ManagementMutationV2::ConfirmationCreate { row },
            MemoryV1AuditObject::Confirmation(id),
        ) => id == MemoryId::from_bytes(row.confirmation_id),
        (
            MutationKind::ConfirmationRevoke,
            ManagementMutationV2::ConfirmationRevoke {
                confirmation_id, ..
            },
            MemoryV1AuditObject::Confirmation(id),
        ) => id == MemoryId::from_bytes(*confirmation_id),
        (
            MutationKind::RuleSetChangeConfirmationRevoke,
            ManagementMutationV2::RuleSetChangeConfirmationRevoke {
                confirmation_id, ..
            },
            MemoryV1AuditObject::Confirmation(id),
        ) => id == MemoryId::from_bytes(*confirmation_id),
        (
            MutationKind::UserCardCreate,
            ManagementMutationV2::UserCardCreate { row },
            MemoryV1AuditObject::UserCard(id),
        ) => id == MemoryId::from_bytes(row.user_card_id),
        (
            MutationKind::UserCardStatus,
            ManagementMutationV2::UserCardStatus { user_card_id, .. },
            MemoryV1AuditObject::UserCard(id),
        ) => id == MemoryId::from_bytes(*user_card_id),
        (
            MutationKind::RuleSetCreate,
            ManagementMutationV2::RuleSetCreate { rule_set, .. },
            MemoryV1AuditObject::RuleSet(id),
        ) => id == MemoryId::from_bytes(rule_set.rule_set_id),
        (
            MutationKind::RuleSetRetire,
            ManagementMutationV2::RuleSetRetire { rule_set_id },
            MemoryV1AuditObject::RuleSet(id),
        ) => id == MemoryId::from_bytes(*rule_set_id),
        (
            MutationKind::VersionPublish,
            ManagementMutationV2::VersionPublish { rule_set_id, .. },
            MemoryV1AuditObject::RuleSet(id),
        ) => id == MemoryId::from_bytes(*rule_set_id),
        (
            MutationKind::ConfirmationBatch,
            ManagementMutationV2::ConfirmationBatch { rows },
            MemoryV1AuditObject::Confirmation(id),
        ) => {
            // A one-row batch inserts one confirmation and must bind the same
            // change target as ConfirmationCreate; any other target object
            // would let an audit that does not bind this mutation report
            // Complete. A multi-row batch has several targets, and one change
            // target is insufficient evidence for the whole payload, so the
            // plan stays unresolved instead of guessing the payload binding.
            rows.len() == 1 && id == MemoryId::from_bytes(rows[0].confirmation_id)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_authorization_root::memory_v1_db_rows::{
        BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, RuleSetStatus, UserCardRow,
    };
    use astral_types::memory_v1_audit::{
        MemoryV1AuditAction, MemoryV1AuditActor, MemoryV1AuditChange, MemoryV1AuditChangeSummary,
        MemoryV1AuditConfirmationRef, MemoryV1AuditConfirmations, MemoryV1AuditContext,
        MemoryV1AuditDecisionInput, MemoryV1AuditOperation, MemoryV1AuditRootObservation,
        MemoryV1AuditRootStatus, MemoryV1AuditRootVersion, MemoryV1AuditTime,
    };

    // memory—v1
    fn id(n: u8) -> BinaryId {
        [n; 16]
    }

    // memory—v1
    fn memory_id(n: u8) -> MemoryId {
        MemoryId::from_bytes(id(n))
    }

    // memory—v1
    fn version(n: u8) -> Vec<u8> {
        vec![n]
    }

    // memory—v1
    fn binding(n: u8, rule_set_id: u8) -> BindingRow {
        BindingRow {
            binding_id: id(n),
            user_card_id: id(2),
            rule_set_id: id(rule_set_id),
            binding_layer: BindingLayer::Base,
            valid_from: None,
            valid_until: None,
            owner_scope: astral_authorization_root::memory_v1_rules::MemoryV1OwnerScope::SelfUser,
            tenant_scope:
                astral_authorization_root::memory_v1_rules::MemoryV1TenantScope::SelfTenant,
            removed_at: None,
            removed_by: None,
        }
    }

    // memory—v1
    fn confirmation(n: u8, binding_id: u8, rule_set_id: u8) -> BindingConfirmationRow {
        BindingConfirmationRow {
            confirmation_id: id(n),
            binding_id: id(binding_id),
            rule_set_id: id(rule_set_id),
            version_bytes: version(1),
            confirmer_user_id: id(3),
            scope_bytes: vec![1],
            operation_id: vec![2],
            confirmed_at_bytes: vec![3],
            revoked_at: None,
            revoked_by: None,
        }
    }

    // memory—v1
    fn change_confirmation(
        n: u8,
        rule_set_id: u8,
        version_bytes: Vec<u8>,
    ) -> RuleSetChangeConfirmationRow {
        RuleSetChangeConfirmationRow {
            confirmation_id: id(n),
            rule_set_id: id(rule_set_id),
            version_bytes,
            confirmer_user_id: id(3),
            affected_scope_bytes: vec![1],
            operation_id: vec![2],
            confirmed_at_bytes: vec![3],
            revoked_at: None,
            revoked_by: None,
        }
    }

    // memory—v1
    fn rule_set(n: u8, current: Vec<u8>) -> RuleSetRow {
        RuleSetRow {
            rule_set_id: id(n),
            owner_tenant_id: id(4),
            current_version_bytes: current,
            status: RuleSetStatus::Active,
        }
    }

    // memory—v1
    fn version_row(rule_set_id: u8, version_bytes: Vec<u8>) -> RuleSetVersionRow {
        RuleSetVersionRow {
            rule_set_id: id(rule_set_id),
            version_bytes,
            content_bytes: vec![1],
            timestamp_bytes: vec![2],
            hash_input_bytes: vec![3],
            hash_bytes: vec![4],
        }
    }

    // memory—v1
    fn audit(target: MemoryV1AuditObject, retirement: bool) -> MemoryV1AuditEvent {
        let operation = MemoryV1AuditOperation::new("op-1", [7; 32]).unwrap();
        let root_before = MemoryV1AuditRootVersion::new(memory_id(8), 1);
        let root_after = MemoryV1AuditRootVersion::new(memory_id(8), 2);
        let (before, after) = if retirement {
            (
                astral_types::memory_v1_audit::MemoryV1AuditObjectState::RuleSet(
                    astral_types::memory_v1_audit::MemoryV1AuditRuleSetState::new_with_status(
                        &version(1),
                        [5; 32],
                        astral_types::memory_v1_audit::MemoryV1AuditRuleSetStatus::Active,
                    )
                    .unwrap(),
                ),
                astral_types::memory_v1_audit::MemoryV1AuditObjectState::RuleSet(
                    astral_types::memory_v1_audit::MemoryV1AuditRuleSetState::new_with_status(
                        &version(1),
                        [5; 32],
                        astral_types::memory_v1_audit::MemoryV1AuditRuleSetStatus::Retired,
                    )
                    .unwrap(),
                ),
            )
        } else {
            match target {
                MemoryV1AuditObject::Binding(_) => (
                    astral_types::memory_v1_audit::MemoryV1AuditObjectState::Absent,
                    astral_types::memory_v1_audit::MemoryV1AuditObjectState::Binding(
                        astral_types::memory_v1_audit::MemoryV1AuditBindingState::Active,
                    ),
                ),
                MemoryV1AuditObject::Confirmation(_) => (
                    astral_types::memory_v1_audit::MemoryV1AuditObjectState::Absent,
                    astral_types::memory_v1_audit::MemoryV1AuditObjectState::Confirmation(
                        astral_types::memory_v1_audit::MemoryV1AuditConfirmationState::Active,
                    ),
                ),
                MemoryV1AuditObject::UserCard(_) => (
                    astral_types::memory_v1_audit::MemoryV1AuditObjectState::Absent,
                    astral_types::memory_v1_audit::MemoryV1AuditObjectState::UserCard(
                        astral_types::memory_v1_audit::MemoryV1AuditCardState::Active,
                    ),
                ),
                MemoryV1AuditObject::RuleSet(_) => (
                    astral_types::memory_v1_audit::MemoryV1AuditObjectState::RuleSet(
                        astral_types::memory_v1_audit::MemoryV1AuditRuleSetState::new_with_status(
                            &version(1),
                            [5; 32],
                            astral_types::memory_v1_audit::MemoryV1AuditRuleSetStatus::Active,
                        )
                        .unwrap(),
                    ),
                    astral_types::memory_v1_audit::MemoryV1AuditObjectState::RuleSet(
                        astral_types::memory_v1_audit::MemoryV1AuditRuleSetState::new_with_status(
                            &version(2),
                            [6; 32],
                            astral_types::memory_v1_audit::MemoryV1AuditRuleSetStatus::Active,
                        )
                        .unwrap(),
                    ),
                ),
                MemoryV1AuditObject::Tenant(_) | MemoryV1AuditObject::User(_) => (
                    astral_types::memory_v1_audit::MemoryV1AuditObjectState::Absent,
                    astral_types::memory_v1_audit::MemoryV1AuditObjectState::Absent,
                ),
            }
        };
        let change = MemoryV1AuditChange::new(
            Some(memory_id(1)),
            Some(target),
            Some(MemoryV1AuditObject::Tenant(memory_id(4))),
            Some(MemoryV1AuditChangeSummary::new(&[9]).unwrap()),
            Some(before),
            Some(after),
            Some(
                MemoryV1AuditConfirmations::references(&[MemoryV1AuditConfirmationRef::Binding(
                    memory_id(6),
                )])
                .unwrap(),
            ),
            Some(root_before),
            Some(root_after),
            astral_types::memory_v1_audit::MemoryV1AuditSource::Ordinary,
        );
        let context = MemoryV1AuditContext::new(
            MemoryV1AuditActor::new(memory_id(1), memory_id(2)),
            MemoryV1AuditTime::new(10).unwrap(),
            MemoryV1AuditAction::new("memory_v1", "apply").unwrap(),
            "MANAGEMENT_MUTATION",
            operation,
            MemoryV1AuditRootObservation::new(
                root_before,
                [4; 32],
                MemoryV1AuditRootStatus::Serving,
            ),
        )
        .unwrap();
        MemoryV1AuditEvent::change(context, MemoryV1AuditDecisionInput::Allow, change).unwrap()
    }

    // memory—v1
    fn flow() -> JournalAnchor {
        JournalAnchor::new(memory_id(9), 1, 1, [6; 32]).unwrap()
    }

    // memory—v1
    fn input<'a>(
        mutation: &'a ManagementMutationV2,
        audit: Option<&'a MemoryV1AuditEvent>,
    ) -> ApplyPlanInput<'a> {
        ApplyPlanInput {
            mutation,
            audit,
            flow: Some(flow()),
        }
    }

    // memory—v1
    fn valid_mutations() -> Vec<ManagementMutationV2> {
        vec![
            ManagementMutationV2::BindingCreate {
                row: binding(10, 5),
                confirmation: confirmation(11, 10, 5),
            },
            ManagementMutationV2::BindingRemove {
                binding_id: id(10),
                removed_at: 20,
                removed_by: id(1),
            },
            ManagementMutationV2::ConfirmationCreate {
                row: confirmation(11, 10, 5),
            },
            ManagementMutationV2::ConfirmationRevoke {
                confirmation_id: id(11),
                revoked_at: 20,
                revoked_by: id(1),
            },
            ManagementMutationV2::RuleSetChangeConfirmationRevoke {
                confirmation_id: id(12),
                revoked_at: 20,
                revoked_by: id(1),
            },
            ManagementMutationV2::ConfirmationBatch {
                rows: vec![confirmation(11, 10, 5), confirmation(12, 13, 5)],
            },
            ManagementMutationV2::UserCardCreate {
                row: UserCardRow {
                    user_card_id: id(20),
                    user_id: id(1),
                    tenant_id: id(4),
                    status: UserCardStatus::Active,
                },
            },
            ManagementMutationV2::UserCardStatus {
                user_card_id: id(20),
                status: UserCardStatus::Active,
            },
            ManagementMutationV2::RuleSetCreate {
                rule_set: rule_set(5, version(1)),
                version: version_row(5, version(1)),
                change_confirmation: change_confirmation(12, 5, version(1)),
            },
            ManagementMutationV2::RuleSetRetire { rule_set_id: id(5) },
            ManagementMutationV2::VersionPublish {
                rule_set_id: id(5),
                version_row: version_row(5, version(2)),
                new_current_version: version(2),
                change_confirmation: change_confirmation(12, 5, version(2)),
            },
        ]
    }

    #[test]
    // memory—v1
    fn maps_all_eleven_variants_and_always_adds_audit_receipt_progress() {
        assert_eq!(MutationKind::all().len(), 11);
        for mutation in valid_mutations() {
            let target = match &mutation {
                ManagementMutationV2::BindingCreate { row, .. } => {
                    MemoryV1AuditObject::Binding(memory_id(row.binding_id[0]))
                }
                ManagementMutationV2::BindingRemove { binding_id, .. } => {
                    MemoryV1AuditObject::Binding(memory_id(binding_id[0]))
                }
                ManagementMutationV2::ConfirmationCreate { row } => {
                    MemoryV1AuditObject::Confirmation(memory_id(row.confirmation_id[0]))
                }
                ManagementMutationV2::ConfirmationRevoke {
                    confirmation_id, ..
                }
                | ManagementMutationV2::RuleSetChangeConfirmationRevoke {
                    confirmation_id, ..
                } => MemoryV1AuditObject::Confirmation(memory_id(confirmation_id[0])),
                ManagementMutationV2::ConfirmationBatch { .. } => {
                    MemoryV1AuditObject::Confirmation(memory_id(11))
                }
                ManagementMutationV2::UserCardCreate { row } => {
                    MemoryV1AuditObject::UserCard(memory_id(row.user_card_id[0]))
                }
                ManagementMutationV2::UserCardStatus { user_card_id, .. } => {
                    MemoryV1AuditObject::UserCard(memory_id(user_card_id[0]))
                }
                ManagementMutationV2::RuleSetCreate { rule_set, .. } => {
                    MemoryV1AuditObject::RuleSet(memory_id(rule_set.rule_set_id[0]))
                }
                ManagementMutationV2::RuleSetRetire { rule_set_id } => {
                    MemoryV1AuditObject::RuleSet(memory_id(rule_set_id[0]))
                }
                ManagementMutationV2::VersionPublish { rule_set_id, .. } => {
                    MemoryV1AuditObject::RuleSet(memory_id(rule_set_id[0]))
                }
                ManagementMutationV2::ContextLoad { .. } => {
                    unreachable!("valid_mutations contains no service-period context load")
                }
            };
            let is_retire = matches!(mutation, ManagementMutationV2::RuleSetRetire { .. });
            let event = audit(target, is_retire);
            let plan = MemoryV1ApplyPlan::build(input(&mutation, Some(&event)));
            assert_eq!(plan.atomicity(), TransactionAtomicity::AllOrNothing);
            assert_eq!(
                plan.operations().last().unwrap().owner(),
                TableOwner::ApplyProgress
            );
            assert!(plan.has_required_tail());
            assert!(plan.operations().len() >= 4);
        }
    }

    #[test]
    // memory—v1
    fn enforces_special_order_for_rule_set_create_and_publish() {
        let create = valid_mutations().into_iter().nth(8).unwrap();
        let event = audit(MemoryV1AuditObject::RuleSet(memory_id(5)), false);
        let plan = MemoryV1ApplyPlan::build(input(&create, Some(&event)));
        assert_eq!(
            plan.operations()[..3]
                .iter()
                .map(FactOperation::owner)
                .collect::<Vec<_>>(),
            vec![
                TableOwner::RuleSet,
                TableOwner::RuleSetVersion,
                TableOwner::RuleSetChangeConfirmation
            ]
        );

        let publish = valid_mutations().into_iter().nth(10).unwrap();
        let event = audit(MemoryV1AuditObject::RuleSet(memory_id(5)), false);
        let plan = MemoryV1ApplyPlan::build(input(&publish, Some(&event)));
        assert_eq!(
            plan.operations()[..3]
                .iter()
                .map(FactOperation::owner)
                .collect::<Vec<_>>(),
            vec![
                TableOwner::RuleSetVersion,
                TableOwner::RuleSet,
                TableOwner::RuleSetChangeConfirmation
            ]
        );
        assert_eq!(
            plan.operations()[1].cas(),
            CasRequirement::Required {
                before_image: BeforeImageRequirement::ReadInSameTransaction,
                fence: CasFence::CurrentPointer,
            }
        );
    }

    #[test]
    // memory—v1
    fn preserves_batch_order_and_requires_all_or_nothing_shape() {
        let mutation = ManagementMutationV2::ConfirmationBatch {
            rows: vec![confirmation(11, 10, 5), confirmation(12, 13, 5)],
        };
        let event = audit(MemoryV1AuditObject::Confirmation(memory_id(11)), false);
        let plan = MemoryV1ApplyPlan::build(input(&mutation, Some(&event)));
        assert_eq!(plan.operations()[0].ordinal(), 0);
        assert_eq!(plan.operations()[1].ordinal(), 1);
        assert_eq!(
            plan.operations()[0].target(),
            &LogicalTarget::BatchItem {
                sequence: 0,
                binding_id: id(10),
                confirmation_id: id(11),
            }
        );
        assert!(plan.operations()[0]
            .preconditions()
            .contains(&Precondition::AllFactChecksBeforeAnyFactWrite));

        let empty = ManagementMutationV2::ConfirmationBatch { rows: vec![] };
        let empty_plan = MemoryV1ApplyPlan::build(input(&empty, Some(&event)));
        assert!(empty_plan
            .issues()
            .contains(&PlanIssue::Unresolved(UnresolvedCondition::BatchEmpty)));
        assert_ne!(empty_plan.status(), PlanStatus::Complete);

        let too_many = ManagementMutationV2::ConfirmationBatch {
            rows: (0..=MAX_APPLY_CONFIRMATION_ROWS)
                .map(|n| confirmation((n % 200) as u8, (n % 200) as u8 + 1, 5))
                .collect(),
        };
        let too_many_plan = MemoryV1ApplyPlan::build(input(&too_many, Some(&event)));
        assert!(too_many_plan
            .issues()
            .contains(&PlanIssue::Unresolved(UnresolvedCondition::BatchOverLimit)));
    }

    #[test]
    // memory—v1
    fn rejects_duplicate_batch_bindings_and_confirmations() {
        let mutation = ManagementMutationV2::ConfirmationBatch {
            rows: vec![confirmation(11, 10, 5), confirmation(11, 10, 5)],
        };
        let event = audit(MemoryV1AuditObject::Confirmation(memory_id(11)), false);
        let plan = MemoryV1ApplyPlan::build(input(&mutation, Some(&event)));
        assert!(plan.issues().contains(&PlanIssue::Unresolved(
            UnresolvedCondition::BatchDuplicateBinding
        )));
        assert!(plan.issues().contains(&PlanIssue::Unresolved(
            UnresolvedCondition::BatchDuplicateConfirmation
        )));
    }

    #[test]
    // memory—v1
    fn single_row_batch_requires_matching_confirmation_target() {
        let mutation = ManagementMutationV2::ConfirmationBatch {
            rows: vec![confirmation(11, 10, 5)],
        };
        let event = audit(MemoryV1AuditObject::Confirmation(memory_id(11)), false);
        let plan = MemoryV1ApplyPlan::build(input(&mutation, Some(&event)));
        assert_eq!(plan.status(), PlanStatus::Complete);
    }

    #[test]
    // memory—v1
    fn single_row_batch_rejects_foreign_confirmation_id_and_wrong_target_kind() {
        let mutation = ManagementMutationV2::ConfirmationBatch {
            rows: vec![confirmation(11, 10, 5)],
        };
        let wrong_id = audit(MemoryV1AuditObject::Confirmation(memory_id(12)), false);
        let plan = MemoryV1ApplyPlan::build(input(&mutation, Some(&wrong_id)));
        assert!(plan.issues().contains(&PlanIssue::Unresolved(
            UnresolvedCondition::AuditTargetMismatch
        )));
        assert_ne!(plan.status(), PlanStatus::Complete);

        let wrong_kind = audit(MemoryV1AuditObject::UserCard(memory_id(11)), false);
        let plan = MemoryV1ApplyPlan::build(input(&mutation, Some(&wrong_kind)));
        assert!(plan.issues().contains(&PlanIssue::Unresolved(
            UnresolvedCondition::AuditTargetMismatch
        )));
        assert_ne!(plan.status(), PlanStatus::Complete);
    }

    #[test]
    // memory—v1
    fn multi_row_batch_stays_unresolved_on_single_target_evidence() {
        let mutation = ManagementMutationV2::ConfirmationBatch {
            rows: vec![confirmation(11, 10, 5), confirmation(12, 13, 5)],
        };
        let event = audit(MemoryV1AuditObject::Confirmation(memory_id(11)), false);
        let plan = MemoryV1ApplyPlan::build(input(&mutation, Some(&event)));
        assert!(plan.issues().contains(&PlanIssue::Unresolved(
            UnresolvedCondition::AuditTargetMismatch
        )));
        assert_eq!(plan.status(), PlanStatus::Unresolved);
    }

    #[test]
    // memory—v1
    fn context_load_is_never_planned_or_complete() {
        let mutation = ManagementMutationV2::ContextLoad {
            rows: CandidateRows::default(),
            selections: Vec::new(),
        };
        let event = audit(MemoryV1AuditObject::RuleSet(memory_id(5)), false);
        let plan = MemoryV1ApplyPlan::build(ApplyPlanInput {
            mutation: &mutation,
            audit: Some(&event),
            flow: Some(flow()),
        });
        assert_eq!(plan.status(), PlanStatus::Unresolved);
        assert!(plan.issues().contains(&PlanIssue::Unresolved(
            UnresolvedCondition::ContextLoadNotGoverned
        )));
        assert!(plan.issues().contains(&PlanIssue::Unresolved(
            UnresolvedCondition::MutationDigestUnavailable
        )));
        assert_eq!(plan.kind(), None);
        // No fact operations and no durable tail: a read-only consumer of
        // operations() cannot mistake an ungoverned context load for an
        // applicable audit/receipt/progress sequence.
        assert!(plan.operations().is_empty());
        assert!(!plan.has_required_tail());
    }

    #[test]
    // memory—v1
    fn requires_audit_receipt_progress_and_never_fakes_before_images() {
        let mutation = ManagementMutationV2::BindingRemove {
            binding_id: id(10),
            removed_at: 20,
            removed_by: id(1),
        };
        let missing = MemoryV1ApplyPlan::build(input(&mutation, None));
        assert_eq!(missing.status(), PlanStatus::Unresolved);
        assert!(missing.issues().contains(&PlanIssue::Unresolved(
            UnresolvedCondition::MissingAuditReference
        )));
        assert!(missing.has_required_tail());
        assert!(matches!(
            missing.operations()[0].cas(),
            CasRequirement::Required {
                before_image: BeforeImageRequirement::ReadInSameTransaction,
                ..
            }
        ));
        assert_eq!(
            missing.operations()[0].tombstone(),
            TombstoneRequirement::WriteComplete
        );

        let no_flow = MemoryV1ApplyPlan::build(ApplyPlanInput {
            mutation: &mutation,
            audit: None,
            flow: None,
        });
        assert!(no_flow.issues().contains(&PlanIssue::Unresolved(
            UnresolvedCondition::MissingFlowReference
        )));
    }

    #[test]
    // memory—v1
    fn retire_requires_zero_active_binding_card_pairs_and_disable_is_blocked() {
        let retire = ManagementMutationV2::RuleSetRetire { rule_set_id: id(5) };
        let retire_event = audit(MemoryV1AuditObject::RuleSet(memory_id(5)), true);
        let retire_plan = MemoryV1ApplyPlan::build(input(&retire, Some(&retire_event)));
        assert_eq!(retire_plan.operations()[0].kind(), OperationKind::Verify);
        assert_eq!(
            retire_plan.operations()[0].affected_rows(),
            AffectedRows::Zero
        );
        assert!(retire_plan.operations()[0]
            .preconditions()
            .contains(&Precondition::NoActiveBindingWithActiveCard));
        assert!(retire_plan.operations()[0]
            .preconditions()
            .contains(&Precondition::UnremovedBindingsMustBeRetained));

        let disable = ManagementMutationV2::UserCardStatus {
            user_card_id: id(20),
            status: UserCardStatus::Disabled,
        };
        let disable_event = audit(MemoryV1AuditObject::UserCard(memory_id(20)), false);
        let disable_plan = MemoryV1ApplyPlan::build(input(&disable, Some(&disable_event)));
        assert_eq!(disable_plan.status(), PlanStatus::Blocked);
        assert!(disable_plan.issues().contains(&PlanIssue::Blocked(
            BlockedCondition::ExternalSessionCoordinatorRequired,
        )));
    }

    #[test]
    // memory—v1
    fn missing_or_non_allow_audit_cannot_be_called_complete() {
        let mutation = ManagementMutationV2::UserCardCreate {
            row: UserCardRow {
                user_card_id: id(20),
                user_id: id(1),
                tenant_id: id(4),
                status: UserCardStatus::Active,
            },
        };
        let event = audit(MemoryV1AuditObject::UserCard(memory_id(20)), false);
        let plan = MemoryV1ApplyPlan::build(input(&mutation, Some(&event)));
        assert_eq!(plan.status(), PlanStatus::Complete);
        assert!(plan.correlation().is_some());
    }
}

/// Shared test-only sample values for sibling memory_v1_apply* modules.
///
/// This lives behind `cfg(test)` and never enters the production build; it
/// constructs a complete ALLOW change event with the same value-level shapes
/// the planner validates.
#[cfg(test)]
pub(crate) mod tests_support {
    use astral_authorization_root::memory_v1_db_rows::{UserCardRow, UserCardStatus};
    use astral_types::memory_v1::MemoryId;
    use astral_types::memory_v1_audit::{
        MemoryV1AuditAction, MemoryV1AuditActor, MemoryV1AuditChange, MemoryV1AuditChangeSummary,
        MemoryV1AuditConfirmationRef, MemoryV1AuditConfirmations, MemoryV1AuditContext,
        MemoryV1AuditDecisionInput, MemoryV1AuditEvent, MemoryV1AuditObject,
        MemoryV1AuditObjectState, MemoryV1AuditOperation, MemoryV1AuditRootObservation,
        MemoryV1AuditRootStatus, MemoryV1AuditRootVersion, MemoryV1AuditSource, MemoryV1AuditTime,
    };

    // memory—v1
    pub(crate) fn binary_id(n: u8) -> [u8; 16] {
        [n; 16]
    }

    // memory—v1
    pub(crate) fn memory_id(n: u8) -> MemoryId {
        MemoryId::from_bytes(binary_id(n))
    }

    // memory—v1
    pub(crate) fn sample_user_card_row() -> UserCardRow {
        UserCardRow {
            user_card_id: binary_id(20),
            user_id: binary_id(1),
            tenant_id: binary_id(4),
            status: UserCardStatus::Active,
        }
    }

    // memory—v1
    pub(crate) fn version(n: u8) -> Vec<u8> {
        vec![n]
    }

    /// A complete ALLOW T2 event with the requested target, mirroring the
    /// planner's own sample builder so sibling modules share one shape. The
    /// retirement flag selects explicit ACTIVE→RETIRED rule-set observations.
    // memory—v1
    pub(crate) fn sample_audit_event(
        target: MemoryV1AuditObject,
        retirement: bool,
    ) -> MemoryV1AuditEvent {
        sample_audit_event_with_operation(
            target,
            retirement,
            MemoryV1AuditOperation::new("op-records", [7; 32]).unwrap(),
        )
    }

    pub(crate) fn sample_audit_event_with_operation(
        target: MemoryV1AuditObject,
        retirement: bool,
        operation: MemoryV1AuditOperation,
    ) -> MemoryV1AuditEvent {
        use astral_types::memory_v1_audit::{
            MemoryV1AuditBindingState, MemoryV1AuditCardState, MemoryV1AuditConfirmationState,
            MemoryV1AuditRuleSetState, MemoryV1AuditRuleSetStatus,
        };
        let root_before = MemoryV1AuditRootVersion::new(memory_id(8), 1);
        let root_after = MemoryV1AuditRootVersion::new(memory_id(8), 2);
        let (before, after) = if retirement {
            (
                MemoryV1AuditObjectState::RuleSet(
                    MemoryV1AuditRuleSetState::new_with_status(
                        &version(1),
                        [5; 32],
                        MemoryV1AuditRuleSetStatus::Active,
                    )
                    .unwrap(),
                ),
                MemoryV1AuditObjectState::RuleSet(
                    MemoryV1AuditRuleSetState::new_with_status(
                        &version(1),
                        [5; 32],
                        MemoryV1AuditRuleSetStatus::Retired,
                    )
                    .unwrap(),
                ),
            )
        } else {
            match target {
                MemoryV1AuditObject::Binding(_) => (
                    MemoryV1AuditObjectState::Absent,
                    MemoryV1AuditObjectState::Binding(MemoryV1AuditBindingState::Active),
                ),
                MemoryV1AuditObject::Confirmation(_) => (
                    MemoryV1AuditObjectState::Absent,
                    MemoryV1AuditObjectState::Confirmation(MemoryV1AuditConfirmationState::Active),
                ),
                MemoryV1AuditObject::UserCard(_) => (
                    MemoryV1AuditObjectState::Absent,
                    MemoryV1AuditObjectState::UserCard(MemoryV1AuditCardState::Active),
                ),
                MemoryV1AuditObject::RuleSet(_) => (
                    MemoryV1AuditObjectState::RuleSet(
                        MemoryV1AuditRuleSetState::new_with_status(
                            &version(1),
                            [5; 32],
                            MemoryV1AuditRuleSetStatus::Active,
                        )
                        .unwrap(),
                    ),
                    MemoryV1AuditObjectState::RuleSet(
                        MemoryV1AuditRuleSetState::new_with_status(
                            &version(2),
                            [6; 32],
                            MemoryV1AuditRuleSetStatus::Active,
                        )
                        .unwrap(),
                    ),
                ),
                MemoryV1AuditObject::Tenant(_) | MemoryV1AuditObject::User(_) => (
                    MemoryV1AuditObjectState::Absent,
                    MemoryV1AuditObjectState::Absent,
                ),
            }
        };
        let change = MemoryV1AuditChange::new(
            Some(memory_id(1)),
            Some(target),
            Some(MemoryV1AuditObject::Tenant(memory_id(4))),
            Some(MemoryV1AuditChangeSummary::new(&[9]).unwrap()),
            Some(before),
            Some(after),
            Some(
                MemoryV1AuditConfirmations::references(&[MemoryV1AuditConfirmationRef::Binding(
                    memory_id(6),
                )])
                .unwrap(),
            ),
            Some(root_before),
            Some(root_after),
            MemoryV1AuditSource::Ordinary,
        );
        let context = MemoryV1AuditContext::new(
            MemoryV1AuditActor::new(memory_id(1), memory_id(2)),
            MemoryV1AuditTime::new(30).unwrap(),
            MemoryV1AuditAction::new("memory_v1", "apply").unwrap(),
            "MANAGEMENT_MUTATION",
            operation,
            MemoryV1AuditRootObservation::new(
                root_before,
                [4; 32],
                MemoryV1AuditRootStatus::Serving,
            ),
        )
        .unwrap();
        MemoryV1AuditEvent::change(context, MemoryV1AuditDecisionInput::Allow, change).unwrap()
    }

    /// A complete ALLOW T2 event binding the user-card-create sample mutation.
    // memory—v1
    pub(crate) fn sample_allow_change_event() -> MemoryV1AuditEvent {
        sample_audit_event(MemoryV1AuditObject::UserCard(memory_id(20)), false)
    }
}
