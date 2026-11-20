//! memory—v1: Paper evidence at the owner, writer and recovery level for the
//! Computers & Security DarkStar paper (sections 4 and 5). Journal-only cases
//! live in `memory_v1_durable_journal::paper_evidence`. The fixtures are
//! duplicated from `memory_v1_governance_owner_tests` because that module keeps
//! them private. A name starting `witness_` asserts current behaviour that is a
//! known gap; update it when the gap is fixed.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use astral_authorization_root::memory_v1_adoption::{
    AdoptionLimit, ColdLoadFacts, ProductionEvidenceInput, ProvenFamily,
    MEMORY_V1_CANDIDATE_SCHEMA_VERSION,
};
use astral_authorization_root::memory_v1_db_rows::{
    BindingLayer, BindingRow, CandidateRows, CurrentSelection, IdentityCardRow, RuleSetRow,
    RuleSetStatus, RuleSetVersionRow, TableCounts, TenantRow, UserCardRow, UserCardStatus, UserRow,
};
use astral_authorization_root::memory_v1_hamt::CandidateBudget;
use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
use astral_authorization_root::memory_v1_root::{
    install_isolated_test_root, ManagementMutationV2, ProductionAdmission, RootMetadata, RootOwner,
};
use astral_authorization_root::memory_v1_rules::{MemoryV1OwnerScope, MemoryV1TenantScope};
use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority;
use astral_trustgraph::service::memory_v1_governance_commit::{
    MemoryV1DenyProofPort, MemoryV1GovernanceCommitPort, MemoryV1GovernanceCommitRequest,
};
use astral_trustgraph::service::memory_v1_mutation_coordinator::{
    AuthorizationStatePrefixProof, CoordinatorError, DenyAuditProof, DenyProofGate,
    DenyProofRequest, DenyResponse, JournalIdentity, JournalReadWatermark, MutationAuditCandidate,
    MutationRequest, RootBinding, VerifiedRootAdmission,
};
use astral_types::memory_v1::MemoryId;
use astral_types::memory_v1_audit::{
    MemoryV1AuditAction, MemoryV1AuditActor, MemoryV1AuditCardState, MemoryV1AuditChange,
    MemoryV1AuditConfirmations, MemoryV1AuditContext, MemoryV1AuditDecisionInput,
    MemoryV1AuditDenySource, MemoryV1AuditEvent, MemoryV1AuditObject, MemoryV1AuditObjectState,
    MemoryV1AuditOperation, MemoryV1AuditRootObservation, MemoryV1AuditRootStatus,
    MemoryV1AuditRootVersion, MemoryV1AuditSource, MemoryV1AuditT2SingleChangeCandidate,
    MemoryV1AuditTime,
};
use astral_types::memory_v1_deny_observation::{
    MemoryV1DenyAffectedBindingState, MemoryV1DenyObservation, MemoryV1DenyRootObservation,
};
use astral_types::memory_v1_journal::{JournalAnchor, RecordKind};
use astral_types::AstralError;

use crate::memory_v1_durable_journal::{
    DurableJournalLimits, JournalDurability, MemoryV1DurableJournal,
};
use crate::memory_v1_governance_owner::MemoryV1DurableCommitOwner;
use crate::memory_v1_recovery_owner::{recover_root, RecoveryError};
use crate::memory_v1_root_writer::{RootMutationWriter, RootMutationWriterError};

// memory—v1: Serving-root and structural-coverage evidence for ordinary admission.
#[path = "memory_v1_paper_evidence_tests/ordinary_admission.rs"]
mod ordinary_admission;

// memory—v1: Separating warm-path recheck cost from memory-authority benefit.
#[path = "memory_v1_paper_evidence_tests/recheck_cost.rs"]
mod recheck_cost;

#[path = "memory_v1_paper_evidence_tests/governed_fence.rs"]
mod governed_fence;

const ACTOR: [u8; 16] = [1; 16];
const CARD: [u8; 16] = [4; 16];
const TENANT: [u8; 16] = [3; 16];
const STREAM: [u8; 16] = [10; 16];
const EPOCH: [u8; 16] = [11; 16];
const GENESIS_HASH: [u8; 32] = [5; 32];
const TRUSTED_TIME: i64 = 1_700_000_000;

// memory—v1: The registry declaration the fixture root installs before adoption.
fn registry_declarations() -> Vec<RegistryDeclaration> {
    vec![RegistryDeclaration {
        resource: "document".to_owned(),
        actions: vec!["read".to_owned()],
    }]
}

// memory—v1: The serving budget every fixture root uses.
fn budget() -> CandidateBudget {
    CandidateBudget {
        max_table_rows: 32,
        max_bindings_per_read: 4,
    }
}

// memory—v1: The candidate fixture: one user, one identity card, one tenant, one
// active card, one serving rule set with a hashed body, and one binding.
fn fixture_rows() -> (CandidateRows, Vec<CurrentSelection>) {
    use astral_authorization_root::memory_v1_rules::canonical_version_bytes;
    use sha2::{Digest, Sha256};
    let id = |value: u8| [value; 16];
    let content =
        br#"{"rules":[{"ruleId":"R9","resource":"document","action":"read","effect":"ALLOW"}]}"#
            .to_vec();
    let version_bytes = vec![1u8];
    let timestamp_bytes = vec![1u8];
    let hash_input = canonical_version_bytes(&version_bytes, &content, &timestamp_bytes);
    let hash = Sha256::digest(&hash_input).to_vec();
    let mut candidate = CandidateRows {
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
            rule_set_id: id(5),
            owner_tenant_id: id(3),
            current_version_bytes: Vec::new(),
            status: RuleSetStatus::Active,
        }],
        rule_set_versions: vec![RuleSetVersionRow {
            rule_set_id: id(5),
            version_bytes: version_bytes.clone(),
            content_bytes: content.clone(),
            timestamp_bytes: timestamp_bytes.clone(),
            hash_input_bytes: hash_input.clone(),
            hash_bytes: hash.clone(),
        }],
        bindings: vec![BindingRow {
            binding_id: id(6),
            user_card_id: id(4),
            rule_set_id: id(5),
            binding_layer: BindingLayer::Base,
            valid_from: None,
            valid_until: None,
            owner_scope: MemoryV1OwnerScope::default(),
            tenant_scope: MemoryV1TenantScope::default(),
            removed_at: None,
            removed_by: None,
        }],
        ..CandidateRows::default()
    };
    candidate.binding_confirmations.push(
        astral_authorization_root::memory_v1_db_rows::BindingConfirmationRow {
            confirmation_id: id(7),
            binding_id: id(6),
            rule_set_id: id(5),
            version_bytes: version_bytes.clone(),
            confirmer_user_id: id(1),
            scope_bytes: vec![1],
            operation_id: vec![1],
            confirmed_at_bytes: vec![1],
            revoked_at: None,
            revoked_by: None,
        },
    );
    candidate.rule_sets[0].current_version_bytes = vec![1];
    candidate.rule_set_change_confirmations.push(
        astral_authorization_root::memory_v1_db_rows::RuleSetChangeConfirmationRow {
            confirmation_id: id(8),
            rule_set_id: id(5),
            version_bytes: version_bytes.clone(),
            confirmer_user_id: id(1),
            affected_scope_bytes: vec![1],
            operation_id: vec![1],
            confirmed_at_bytes: vec![1],
            revoked_at: None,
            revoked_by: None,
        },
    );
    (
        candidate,
        vec![CurrentSelection {
            rule_set_id: id(5),
            version_bytes: vec![1],
        }],
    )
}

// memory—v1: Cold-load facts whose counts are the given snapshot counts.
fn cold_facts(counts: TableCounts) -> ColdLoadFacts {
    ColdLoadFacts {
        schema_contract_version: MEMORY_V1_CANDIDATE_SCHEMA_VERSION,
        schema_fingerprint: [7; 32],
        snapshot_counts: counts,
        scanned_counts: counts,
        captured_at_unix_seconds: 1_700_000_000,
    }
}

// memory—v1: Every production evidence family proven at the fixture time.
fn sealed_input() -> ProductionEvidenceInput {
    let sealed = ProvenFamily::proven_for;
    let mut input = ProductionEvidenceInput::default();
    input
        .with_source_provenance(sealed(AdoptionLimit::SourceProvenance))
        .with_snapshot_identity(sealed(AdoptionLimit::SnapshotIdentity))
        .with_lifecycle_and_validity(sealed(AdoptionLimit::LifecycleAndValidity))
        .with_confirmation_authority(sealed(AdoptionLimit::ConfirmationAuthority))
        .with_resource_ownership(sealed(AdoptionLimit::ResourceOwnership))
        .with_eligibility(sealed(AdoptionLimit::Eligibility))
        .with_separation_of_duties(sealed(AdoptionLimit::SeparationOfDuties))
        .with_writer_coverage(sealed(AdoptionLimit::WriterCoverage))
        .with_audit_correlation(sealed(AdoptionLimit::AuditCorrelation))
        .with_persistence_recovery(sealed(AdoptionLimit::PersistenceRecovery))
        .with_trusted_time(TRUSTED_TIME);
    input
}

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

// memory—v1: A private scratch directory named by process id and a counter. No
// wall clock or OS randomness is used to name it.
fn scratch_dir(label: &str) -> PathBuf {
    let index = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "astral-paper-owner-{label}-{}-{index}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    path
}

// memory—v1: A production root adopted from the fixture rows, with its scratch
// directory for the journal file. The directory is removed on drop.
struct TestRoot {
    owner: Arc<RootOwner>,
    admission: Arc<ProductionAdmission>,
    dir: PathBuf,
}

// memory—v1: Remove the scratch directory when the test root drops.
impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// memory—v1: The adopted production root used by every owner-level case.
fn production_root(label: &str) -> TestRoot {
    let (rows, selections) = fixture_rows();
    let counts = rows.table_counts();
    let owner = install_isolated_test_root(rows, selections, budget()).unwrap();
    owner.install_registry(&registry_declarations()).unwrap();
    let (_, admission) = owner
        .adopt_with_production_evidence(&cold_facts(counts), &sealed_input())
        .unwrap();
    TestRoot {
        owner: Arc::new(owner),
        admission: Arc::new(admission),
        dir: scratch_dir(label),
    }
}

// memory—v1: The journal file inside a test root's scratch directory.
fn journal_path(root: &TestRoot) -> PathBuf {
    root.dir.join("journal.bin")
}

// memory—v1: The genesis baseline every owner-level journal starts from.
fn genesis() -> JournalAnchor {
    JournalAnchor::new(MemoryId::from_bytes(STREAM), 0, 0, GENESIS_HASH).unwrap()
}

// memory—v1: Create a fresh journal in the root's directory at the given baseline.
fn create_journal(
    root: &TestRoot,
    limits: DurableJournalLimits,
    baseline: JournalAnchor,
) -> (MemoryV1DurableJournal, JournalDurability) {
    MemoryV1DurableJournal::create(
        &journal_path(root),
        MemoryId::from_bytes(STREAM),
        MemoryId::from_bytes(EPOCH),
        baseline,
        limits,
    )
    .unwrap()
}

// memory—v1: Reopen the root's journal through the service's scan-then-open path,
// against a chosen external baseline.
fn reopen_journal_at(
    root: &TestRoot,
    baseline: JournalAnchor,
) -> (MemoryV1DurableJournal, JournalDurability) {
    let tail = MemoryV1DurableJournal::scan_tail(
        &journal_path(root),
        MemoryId::from_bytes(STREAM),
        MemoryId::from_bytes(EPOCH),
        baseline,
        DurableJournalLimits::conservative(),
    )
    .unwrap();
    MemoryV1DurableJournal::open(
        &journal_path(root),
        MemoryId::from_bytes(STREAM),
        MemoryId::from_bytes(EPOCH),
        baseline,
        tail,
        DurableJournalLimits::conservative(),
    )
    .unwrap()
}

// memory—v1: Reopen the root's journal against the default genesis baseline.
fn reopen_journal(root: &TestRoot) -> (MemoryV1DurableJournal, JournalDurability) {
    reopen_journal_at(root, genesis())
}

// memory—v1: The limits of production with only the record cap changed.
fn limits_with_records(max_records: u64) -> DurableJournalLimits {
    DurableJournalLimits {
        max_records,
        ..DurableJournalLimits::conservative()
    }
}

// memory—v1: A commit owner over a fresh journal with the given record cap.
fn owner_with_records(root: &TestRoot, max_records: u64) -> MemoryV1DurableCommitOwner {
    let writer = writer_for(root);
    MemoryV1DurableCommitOwner::new(
        create_journal(root, limits_with_records(max_records), genesis()),
        writer,
    )
}

// memory—v1: A commit owner over a fresh conservative journal.
fn assembled_owner(root: &TestRoot) -> MemoryV1DurableCommitOwner {
    owner_with_records(root, DurableJournalLimits::conservative().max_records)
}

// memory—v1: The root writer bound to a production root.
fn writer_for(root: &TestRoot) -> RootMutationWriter {
    RootMutationWriter::new(Arc::clone(&root.owner), Arc::clone(&root.admission)).unwrap()
}

// memory—v1: The byte length of a file on disk.
fn file_len(path: &Path) -> u64 {
    std::fs::metadata(path).unwrap().len()
}

// memory—v1: The fingerprint the governance fixtures use, as hex.
fn fingerprint_hex() -> String {
    "ab".repeat(32)
}

// memory—v1: Build one enable request for a card, as the HTTP seam would carry it.
// The audit binds the same actor, card, observed root and trusted time.
fn enable_request(
    actor: [u8; 16],
    card: [u8; 16],
    root_metadata: RootMetadata,
    operation_id: &str,
    fingerprint: String,
) -> MemoryV1GovernanceCommitRequest {
    let mutation = ManagementMutationV2::UserCardStatus {
        user_card_id: card,
        status: UserCardStatus::Active,
    };
    let fingerprint_bytes = <[u8; 32]>::try_from(hex::decode(&fingerprint).unwrap()).unwrap();
    let summary = MutationAuditCandidate::governance_mutation_summary(&mutation).unwrap();
    let instance = MemoryId::from_bytes(*root_metadata.instance_id.as_uuid().as_bytes());
    let root_version = MemoryV1AuditRootVersion::new(instance, root_metadata.version);
    let context = MemoryV1AuditContext::new(
        MemoryV1AuditActor::new(MemoryId::from_bytes(actor), MemoryId::from_bytes([2; 16])),
        MemoryV1AuditTime::new(TRUSTED_TIME).unwrap(),
        MemoryV1AuditAction::new("user_card", "enable").unwrap(),
        "GOVERNANCE_USER_CARD_ENABLE",
        MemoryV1AuditOperation::new(operation_id, fingerprint_bytes).unwrap(),
        MemoryV1AuditRootObservation::new(
            root_version,
            root_metadata.digest,
            MemoryV1AuditRootStatus::Serving,
        ),
    )
    .unwrap();
    let change = MemoryV1AuditChange::new(
        Some(MemoryId::from_bytes(actor)),
        Some(MemoryV1AuditObject::UserCard(MemoryId::from_bytes(card))),
        Some(MemoryV1AuditObject::Tenant(MemoryId::from_bytes(TENANT))),
        Some(summary),
        Some(MemoryV1AuditObjectState::UserCard(
            MemoryV1AuditCardState::Disabled,
        )),
        Some(MemoryV1AuditObjectState::UserCard(
            MemoryV1AuditCardState::Active,
        )),
        Some(MemoryV1AuditConfirmations::not_applicable()),
        Some(root_version),
        Some(MemoryV1AuditRootVersion::new(
            instance,
            root_metadata.version + 1,
        )),
        MemoryV1AuditSource::Ordinary,
    );
    MemoryV1GovernanceCommitRequest {
        operation_id: operation_id.to_owned(),
        request_fingerprint: fingerprint,
        root: root_metadata,
        actor,
        target: card,
        target_tenant: TENANT,
        target_owner: Some(ACTOR),
        trusted_time_unix_seconds: TRUSTED_TIME,
        mutation,
        audit: MutationAuditCandidate::Single(
            MemoryV1AuditT2SingleChangeCandidate::try_from(
                MemoryV1AuditEvent::change(context, MemoryV1AuditDecisionInput::Allow, change)
                    .unwrap(),
            )
            .unwrap(),
        ),
    }
}

// memory—v1: The default enable request: the fixture actor and card.
fn default_enable(
    root_metadata: RootMetadata,
    operation_id: &str,
) -> MemoryV1GovernanceCommitRequest {
    enable_request(ACTOR, CARD, root_metadata, operation_id, fingerprint_hex())
}

// memory—v1: The live-root DENY observation for the current metadata.
fn live_deny_observation(root: &TestRoot, operation_id: &str) -> MemoryV1DenyObservation {
    let metadata = root.owner.handle().metadata().unwrap();
    let observed = MemoryV1DenyRootObservation::try_from_usize(
        MemoryId::from_bytes(*metadata.instance_id.as_uuid().as_bytes()),
        metadata.version,
        metadata.digest,
        MemoryV1AuditRootStatus::Serving,
        metadata.budget.max_table_rows,
        metadata.budget.max_bindings_per_read,
        metadata.row_count,
    )
    .unwrap();
    deny_observation_at(observed, operation_id)
}

// memory—v1: A DENY observation for the given root observation, with the fixture
// identity and a fixed fingerprint.
fn deny_observation_at(
    root_observation: MemoryV1DenyRootObservation,
    operation_id: &str,
) -> MemoryV1DenyObservation {
    use astral_types::memory_v1::CandidateIdentity;
    MemoryV1DenyObservation::new(
        root_observation,
        CandidateIdentity {
            user_id: MemoryId::from_bytes(ACTOR),
            identity_card_id: MemoryId::from_bytes([2; 16]),
            user_card_id: MemoryId::from_bytes(CARD),
            tenant_id: MemoryId::from_bytes(TENANT),
        },
        TRUSTED_TIME,
        "permission_rule",
        "read",
        None,
        Some(Vec::new()),
        None,
        MemoryV1DenyAffectedBindingState::inapplicable(),
        operation_id.as_bytes().to_vec(),
        [9; 32].to_vec(),
        MemoryV1AuditDenySource::RuleDeny,
        None,
    )
    .unwrap()
}

// memory—v1: One coordinator mutation request bound to an observed root. The
// admission is minted by the caller from the same observation, so the audit and
// the root binding agree.
fn coordinator_request(
    operation_id: &str,
    fingerprint: [u8; 32],
    mutation: ManagementMutationV2,
    observed: RootMetadata,
    admission: VerifiedRootAdmission,
    identity: JournalIdentity,
) -> MutationRequest {
    let instance = MemoryId::from_bytes(*observed.instance_id.as_uuid().as_bytes());
    let root_version = MemoryV1AuditRootVersion::new(instance, observed.version);
    let summary = MutationAuditCandidate::governance_mutation_summary(&mutation).unwrap();
    let context = MemoryV1AuditContext::new(
        MemoryV1AuditActor::new(MemoryId::from_bytes(ACTOR), MemoryId::from_bytes([2; 16])),
        MemoryV1AuditTime::new(TRUSTED_TIME).unwrap(),
        MemoryV1AuditAction::new("user_card", "enable").unwrap(),
        "GOVERNANCE_USER_CARD_ENABLE",
        MemoryV1AuditOperation::new(operation_id, fingerprint).unwrap(),
        MemoryV1AuditRootObservation::new(
            root_version,
            observed.digest,
            MemoryV1AuditRootStatus::Serving,
        ),
    )
    .unwrap();
    let change = MemoryV1AuditChange::new(
        Some(MemoryId::from_bytes(ACTOR)),
        Some(MemoryV1AuditObject::UserCard(MemoryId::from_bytes(CARD))),
        Some(MemoryV1AuditObject::Tenant(MemoryId::from_bytes(TENANT))),
        Some(summary),
        Some(MemoryV1AuditObjectState::UserCard(
            MemoryV1AuditCardState::Disabled,
        )),
        Some(MemoryV1AuditObjectState::UserCard(
            MemoryV1AuditCardState::Active,
        )),
        Some(MemoryV1AuditConfirmations::not_applicable()),
        Some(root_version),
        Some(MemoryV1AuditRootVersion::new(
            instance,
            observed.version + 1,
        )),
        MemoryV1AuditSource::Ordinary,
    );
    let event =
        MemoryV1AuditEvent::change(context, MemoryV1AuditDecisionInput::Allow, change).unwrap();
    let audit = MutationAuditCandidate::Single(
        MemoryV1AuditT2SingleChangeCandidate::try_from(event).unwrap(),
    );
    MutationRequest::try_new(
        operation_id,
        fingerprint,
        mutation,
        audit,
        admission,
        identity,
    )
    .unwrap()
}

// memory—v1: The journal identity for one governance position in the fixture stream.
fn identity(journal_sequence: u64, mutation_sequence: u64, message: u8) -> JournalIdentity {
    JournalIdentity::new(
        MemoryId::from_bytes(STREAM),
        MemoryId::from_bytes(EPOCH),
        journal_sequence,
        mutation_sequence,
        MemoryId::from_bytes([message; 16]),
    )
    .unwrap()
}

// memory—v1: The card-status mutation a writer publishes directly.
fn set_card(status: UserCardStatus) -> ManagementMutationV2 {
    ManagementMutationV2::UserCardStatus {
        user_card_id: CARD,
        status,
    }
}

// memory—v1: Whether the card is active in the root's serving snapshot.
fn card_is_active(owner: &RootOwner) -> bool {
    owner
        .handle()
        .read_card(CARD, |context| {
            matches!(context.card.status, UserCardStatus::Active)
        })
        .unwrap()
        .value
}

// memory—v1: A fresh candidate from the same baseline rows, with the baseline
// counts the adoption facts were captured from.
fn fresh_candidate() -> (RootOwner, TableCounts) {
    let (rows, selections) = fixture_rows();
    let counts = rows.table_counts();
    let owner = install_isolated_test_root(rows, selections, budget()).unwrap();
    owner.install_registry(&registry_declarations()).unwrap();
    (owner, counts)
}

// memory—v1: The error text a pending governance refusal carries.
fn pending_reason(error: &AstralError) -> &str {
    match error {
        AstralError::Pending(reason) => reason.as_str(),
        other => panic!("expected a pending refusal, got {other:?}"),
    }
}

// memory—v1: J2 at the owner. DENY appends fill the cap shared with governance.
// The next governance commit fails closed with the journal's capacity error,
// publishes nothing and writes no byte. Both refusals count no sync.
#[test]
fn j2_deny_flood_refuses_governance_and_writes_nothing() {
    let root = production_root("j2-deny-flood");
    let owner = owner_with_records(&root, 2);
    assert_eq!(
        owner
            .prove_deny(live_deny_observation(&root, "cap-d1"))
            .unwrap(),
        DenyResponse::Forbidden
    );
    assert_eq!(
        owner
            .prove_deny(live_deny_observation(&root, "cap-d2"))
            .unwrap(),
        DenyResponse::Forbidden
    );
    let length = file_len(&journal_path(&root));
    let before = root.owner.handle().metadata().unwrap();

    let deny = owner
        .prove_deny(live_deny_observation(&root, "cap-d3"))
        .unwrap_err();
    assert!(
        pending_reason(&deny).contains("CapacityExceeded"),
        "{deny:?}"
    );

    let governance = owner.commit(default_enable(before, "cap-g1")).unwrap_err();
    assert!(
        pending_reason(&governance).contains("CapacityExceeded"),
        "{governance:?}"
    );
    assert_eq!(root.owner.handle().metadata().unwrap(), before);
    assert_eq!(
        file_len(&journal_path(&root)),
        length,
        "no frame was written"
    );
    assert_eq!(owner.journal_sync_calls(), 2, "the refusals never synced");
}

// memory—v1: J2 at the owner, the reverse direction. Two governance commits fill
// the cap; the next DENY is refused with a pending error rather than a response.
#[test]
fn j2_governance_fill_refuses_deny_with_a_pending_error() {
    let root = production_root("j2-gov-fill");
    let owner = owner_with_records(&root, 2);
    let first = root.owner.handle().metadata().unwrap();
    owner.commit(default_enable(first, "cap-g1")).unwrap();
    let second = root.owner.handle().metadata().unwrap();
    owner.commit(default_enable(second, "cap-g2")).unwrap();
    let before = root.owner.handle().metadata().unwrap();
    let length = file_len(&journal_path(&root));

    let deny = owner
        .prove_deny(live_deny_observation(&root, "cap-d1"))
        .unwrap_err();
    assert!(
        pending_reason(&deny).contains("CapacityExceeded"),
        "{deny:?}"
    );
    assert_eq!(root.owner.handle().metadata().unwrap(), before);
    assert_eq!(file_len(&journal_path(&root)), length);
    assert_eq!(owner.journal_sync_calls(), 2);
}

// memory—v1: J2 witness. A capacity refusal happens after the operation ledger
// claim, so the claim is kept with no frame behind it. The retry is refused by
// the ledger, not by the journal, which is the observable difference.
// asserts current behaviour that is a known gap; update when fixed.
#[test]
fn witness_j2_capacity_refusal_retains_the_operation_claim() {
    let root = production_root("j2-claim");
    let owner = owner_with_records(&root, 1);
    let first = root.owner.handle().metadata().unwrap();
    owner.commit(default_enable(first, "cap-g1")).unwrap();
    let before = root.owner.handle().metadata().unwrap();

    let refused = owner.commit(default_enable(before, "cap-g2")).unwrap_err();
    assert!(
        pending_reason(&refused).contains("CapacityExceeded"),
        "{refused:?}"
    );
    let retry = owner.commit(default_enable(before, "cap-g2")).unwrap_err();
    assert!(
        pending_reason(&retry).contains("operation ledger refused"),
        "{retry:?}"
    );
    assert_eq!(root.owner.handle().metadata().unwrap(), before);
}

// memory—v1: G1 regression. The reserved predecessor is carried into publication;
// a stale request cannot obtain another reservation against the newer root.
#[test]
fn regression_g1_publication_keeps_the_authorized_predecessor() {
    let root = production_root("g1");
    let writer = writer_for(&root);
    let observed = root.owner.handle().metadata().unwrap();
    let mutation = set_card(UserCardStatus::Active);
    let (_, publication) = writer.prepare(&observed, &mutation).unwrap();
    assert!(writer.prepare(&observed, &mutation).is_err());
    let published = publication.publish().unwrap();
    assert_eq!(published.version, observed.version + 1);
    assert!(writer.prepare(&observed, &mutation).is_err());
    assert_eq!(root.owner.handle().metadata().unwrap(), published);
}

// memory—v1: The session-coordinated publish of a card disable, bound the way the
// composition binds it. The owner calls this same method on its disable path.
fn disable_through_writer(writer: &RootMutationWriter, authority: &Arc<MemoryV1SessionAuthority>) {
    writer
        .disable_card_with_sessions(authority, MemoryId::from_bytes(CARD))
        .unwrap();
}

// memory—v1: G2 regression at the composition owner. Two requests with the
// same predecessor can race, but exactly one can journal and publish it.
#[test]
fn regression_g2_competing_commits_preserve_journal_and_root_order() {
    let root = production_root("g2");
    let owner = assembled_owner(&root);
    let observed = root.owner.handle().metadata().unwrap();
    let ready = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            ready.wait();
            owner.commit(default_enable(observed, "g2-first"))
        });
        let second = scope.spawn(|| {
            ready.wait();
            owner.commit(default_enable(observed, "g2-second"))
        });
        let results = [first.join().unwrap(), second.join().unwrap()];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert!(results
            .iter()
            .any(|result| matches!(result, Err(AstralError::Pending(_)))));
    });
    let live = root.owner.handle().metadata().unwrap();
    assert_eq!(live.version, observed.version + 1);
    drop(owner);

    let (journal, _durability) = reopen_journal(&root);
    assert_eq!(journal.record_count(), 1);
    assert_eq!(journal.position().mutation_sequence(), live.version);
    let (candidate, counts) = fresh_candidate();
    let recovered =
        recover_root(candidate, &journal, &cold_facts(counts), &sealed_input()).unwrap();
    let replayed = recovered.owner.handle().metadata().unwrap();
    assert_eq!(
        (replayed.version, replayed.digest),
        (live.version, live.digest)
    );
}

// memory—v1: G2 control. The same two mutations journaled and published in one
// order replay to the live card state. The divergence above comes from the
// order, not from the fixture or the replay path.
#[test]
fn g2_control_matching_orders_replay_to_the_live_state() {
    let root = production_root("g2-control");
    let mut writer = writer_for(&root);
    let authority = Arc::new(MemoryV1SessionAuthority::new());
    authority.bind_to_root(&root.owner).unwrap();
    writer.set_session_authority(Some(Arc::clone(&authority)));
    let observed = root.owner.handle().metadata().unwrap();
    let (mut journal, durability) =
        create_journal(&root, DurableJournalLimits::conservative(), genesis());

    let enable = coordinator_request(
        "g2c-enable",
        [0x23; 32],
        set_card(UserCardStatus::Active),
        observed,
        writer.verified_admission(&observed).unwrap(),
        identity(1, 1, 1),
    );
    let disable = coordinator_request(
        "g2c-disable",
        [0x24; 32],
        set_card(UserCardStatus::Disabled),
        observed,
        writer.verified_admission(&observed).unwrap(),
        identity(2, 2, 2),
    );
    journal
        .prepare_mutation(&enable, &durability)
        .unwrap()
        .into_durable_receipt(&durability)
        .unwrap();
    journal
        .prepare_mutation(&disable, &durability)
        .unwrap()
        .into_durable_receipt(&durability)
        .unwrap();

    writer.publish(&set_card(UserCardStatus::Active)).unwrap();
    disable_through_writer(&writer, &authority);
    assert!(!card_is_active(&root.owner));
    drop(writer);
    drop(journal);
    drop(durability);

    let (reopened, _durability) = reopen_journal(&root);
    let (candidate, counts) = fresh_candidate();
    let recovered =
        recover_root(candidate, &reopened, &cold_facts(counts), &sealed_input()).unwrap();
    assert!(!card_is_active(&recovered.owner));
}

// memory—v1: G3 regression. Candidate validation precedes append, so a known
// invalid mutation cannot leave a replayable frame or block a later startup.
#[test]
fn regression_g3_invalid_successor_never_reaches_the_journal() {
    let root = production_root("g3");
    let owner = assembled_owner(&root);
    let before = root.owner.handle().metadata().unwrap();
    let missing_card = [99; 16];
    let request = enable_request(ACTOR, missing_card, before, "g3-op", fingerprint_hex());

    let error = owner.commit(request).unwrap_err();
    assert!(pending_reason(&error).contains("root mutation preparation refused"));
    assert_eq!(root.owner.handle().metadata().unwrap(), before);
    assert_eq!(file_len(&journal_path(&root)), 0, "no replayable frame");
    let corrected = owner
        .commit(default_enable(before, "g3-corrected"))
        .unwrap();
    drop(owner);

    let (journal, _durability) = reopen_journal(&root);
    assert_eq!(journal.record_count(), 1);
    assert_eq!(journal.recovery_records()[0].operation_id, "g3-corrected");
    let (candidate, counts) = fresh_candidate();
    let recovered =
        recover_root(candidate, &journal, &cold_facts(counts), &sealed_input()).unwrap();
    assert_eq!(recovered.replayed_mutations, 1);
    assert_eq!(
        recovered.owner.handle().metadata().unwrap().digest,
        corrected.root.digest
    );
}

// memory—v1: Value-only DENYs require an exact live observation.
#[test]
fn regression_d1_delayed_denial_fails_closed_without_a_historical_proof() {
    let root = production_root("d1-delayed");
    let owner = assembled_owner(&root);
    let observed = root.owner.handle().metadata().unwrap();
    let observation = live_deny_observation(&root, "d1-delayed");
    owner.commit(default_enable(observed, "d1-mut")).unwrap();
    assert_eq!(
        owner.prove_deny(observation).unwrap(),
        DenyResponse::ServiceUnavailable
    );
    drop(owner);
    let (journal, _durability) = reopen_journal(&root);
    assert_eq!(journal.recovery_records().len(), 1);
    assert_eq!(journal.last_mutation().mutation_sequence(), 1);
}

#[test]
fn regression_d1_unpublished_observation_is_refused_without_an_append() {
    let root = production_root("d1-foreign");
    let owner = assembled_owner(&root);
    let unknown = MemoryV1DenyRootObservation::try_from_usize(
        MemoryId::from_bytes([0x55; 16]),
        999,
        [0xAB; 32],
        MemoryV1AuditRootStatus::Serving,
        32,
        4,
        9,
    )
    .unwrap();
    assert_eq!(
        owner
            .prove_deny(deny_observation_at(unknown, "d1-foreign"))
            .unwrap(),
        DenyResponse::ServiceUnavailable
    );
    assert_eq!(owner.journal_sync_calls(), 0);
    assert_eq!(file_len(&journal_path(&root)), 0);
}

// memory—v1: A context load is neither a governance record nor replay input.
#[test]
fn regression_context_load_preserves_governance_prefix_across_recovery() {
    use astral_authorization_root::memory_v1_root::MutationPrecondition;

    let root = production_root("context-prefix");
    let owner = assembled_owner(&root);
    let before = root.owner.handle().metadata().unwrap();
    let first = owner.commit(default_enable(before, "context-g1")).unwrap();
    let added = CandidateRows {
        users: vec![UserRow {
            user_id: [0x71; 16],
        }],
        identity_cards: vec![IdentityCardRow {
            identity_card_id: [0x72; 16],
            user_id: [0x71; 16],
        }],
        ..CandidateRows::default()
    };
    let mutation = ManagementMutationV2::ContextLoad {
        rows: added.clone(),
        selections: vec![],
    };
    assert!(
        root.owner
            .execute_mutation_with_precondition_for_isolated_tests(
                &mutation,
                &MutationPrecondition {
                    evaluated_root_version: first.root.version
                },
            )
            .is_err(),
        "ordinary loads cannot publish on a production-adopted fixture"
    );
    assert_eq!(root.owner.handle().metadata().unwrap(), first.root);
    let loaded = root
        .owner
        .execute_context_load_from_verified_cold_fixture_for_test(
            &root.admission,
            &mutation,
            &first.root,
        )
        .unwrap();
    assert_eq!(loaded.version, 2);
    assert!(owner
        .commit(default_enable(first.root, "context-stale"))
        .is_err());
    assert_eq!(
        owner
            .prove_deny(live_deny_observation(&root, "context-deny"))
            .unwrap(),
        DenyResponse::Forbidden
    );
    let second = owner.commit(default_enable(loaded, "context-g2")).unwrap();
    assert_eq!(second.root.version, 3);
    drop(owner);

    let (journal, durability) = reopen_journal(&root);
    let records = journal.recovery_records();
    assert_eq!(
        records
            .iter()
            .map(|record| (record.kind, record.mutation_sequence))
            .collect::<Vec<_>>(),
        [
            (RecordKind::Mutation, 1),
            (RecordKind::Deny, 1),
            (RecordKind::Mutation, 2)
        ]
    );
    let (mut rows, selections) = fixture_rows();
    rows.users.extend(added.users);
    rows.identity_cards.extend(added.identity_cards);
    let counts = rows.table_counts();
    let candidate = install_isolated_test_root(rows, selections, before.budget).unwrap();
    candidate
        .install_registry(&registry_declarations())
        .unwrap();
    let recovered =
        recover_root(candidate, &journal, &cold_facts(counts), &sealed_input()).unwrap();
    let after = recovered.owner.handle().metadata().unwrap();
    assert_eq!((after.version, after.digest), (2, second.root.digest));
    assert_eq!(
        (recovered.replayed_mutations, recovered.observed_denies),
        (2, 1)
    );
    let writer = RootMutationWriter::new(recovered.owner, recovered.admission).unwrap();
    let owner = MemoryV1DurableCommitOwner::new((journal, durability), writer);
    owner.commit(default_enable(after, "context-g3")).unwrap();
}

// memory—v1: The live root metadata with its digest replaced. The result binds an
// observation of a state whose digest the caller chooses.
fn observed_root_with_digest(root: &TestRoot, digest: [u8; 32]) -> RootBinding {
    let metadata = root.owner.handle().metadata().unwrap();
    RootBinding::from_metadata(RootMetadata { digest, ..metadata })
}

// memory—v1: A DENY journal identity in the fixture stream at a chosen journal
// position. The mutation sequence and message identifier are fixed.
fn deny_identity(journal_sequence: u64) -> JournalIdentity {
    JournalIdentity::new_deny(
        MemoryId::from_bytes(STREAM),
        MemoryId::from_bytes(EPOCH),
        journal_sequence,
        1,
        MemoryId::from_bytes([7; 16]),
    )
    .unwrap()
}

// memory—v1: A DENY proof gate for one observed root, with the read watermark at
// journal position 2 and the audit proof already recorded. The D1 witness and its
// controls differ only in the prefix proof they record.
fn d1_gate(observed_root: RootBinding) -> DenyProofGate {
    let admission = VerifiedRootAdmission::mint_from_production_owner(observed_root);
    let watermark = JournalReadWatermark::new_deny(
        MemoryId::from_bytes(STREAM),
        MemoryId::from_bytes(EPOCH),
        2,
        1,
    )
    .unwrap();
    let request = DenyProofRequest::try_new(
        "d1-gate",
        [9; 32],
        admission,
        watermark,
        MemoryV1AuditDenySource::RuleDeny,
    )
    .unwrap();
    let mut gate = DenyProofGate::new(request);
    gate.record_audit(DenyAuditProof::mint_for_owner(
        "d1-gate",
        [9; 32],
        observed_root,
        MemoryV1AuditDenySource::RuleDeny,
        [8; 32],
    ))
    .unwrap();
    gate
}

// memory—v1: D1 witness. The gate accepts a prefix proof at any journal position
// at or after the watermark, with a state digest that the live root does not
// carry. The digest comparison at coordinator line 2021 adds no check: the proof's
// state digest is copied from its own root (line 1951), and root equality at line
// 2012 already holds. The operative checks are the lower bounds at lines 2015-2016
// and the root equality, which the controls below show refuse their inputs.
// asserts current behaviour that is a known gap; update when fixed.
#[test]
fn witness_d1_prefix_proof_accepts_any_later_position_and_its_own_digest() {
    let root = production_root("d1-gate");
    let observed_root = observed_root_with_digest(&root, [0xCD; 32]);
    let mut gate = d1_gate(observed_root);
    gate.record_prefix(AuthorizationStatePrefixProof::mint_for_owner(
        "d1-gate",
        [9; 32],
        observed_root,
        deny_identity(7),
        [6; 32],
    ))
    .expect("the gate accepts a later position with an unpublished digest");
    assert_eq!(gate.response(), DenyResponse::Forbidden);
}

// memory—v1: D1 control. The same gate refuses a prefix proof below the watermark
// journal position, so the lower bound is operative and the witness above is not a
// gate that accepts every proof. A refused proof leaves the gate unanswered.
#[test]
fn d1_control_gate_refuses_a_prefix_below_the_watermark() {
    let root = production_root("d1-below");
    let observed_root = observed_root_with_digest(&root, [0xCD; 32]);
    let mut gate = d1_gate(observed_root);
    let refused = gate.record_prefix(AuthorizationStatePrefixProof::mint_for_owner(
        "d1-gate",
        [9; 32],
        observed_root,
        deny_identity(1),
        [6; 32],
    ));
    assert_eq!(refused, Err(CoordinatorError::InvalidDenyProof));
    assert_eq!(gate.response(), DenyResponse::ServiceUnavailable);
}

// memory—v1: D1 control. A prefix proof minted for another root digest is refused
// by root equality, so the prefix is bound to the admitted root. The digest check
// that follows root equality is redundant and is not the control here.
#[test]
fn d1_control_gate_refuses_a_prefix_for_another_root_digest() {
    let root = production_root("d1-other-root");
    let observed_root = observed_root_with_digest(&root, [0xCD; 32]);
    let other_root = observed_root_with_digest(&root, [0xEE; 32]);
    let mut gate = d1_gate(observed_root);
    let refused = gate.record_prefix(AuthorizationStatePrefixProof::mint_for_owner(
        "d1-gate",
        [9; 32],
        other_root,
        deny_identity(7),
        [6; 32],
    ));
    assert_eq!(refused, Err(CoordinatorError::InvalidDenyProof));
    assert_eq!(gate.response(), DenyResponse::ServiceUnavailable);
}

// memory—v1: Recovery candidate for a journal whose single mutation adds a card
// row. The journal is valid. The candidate gains one row during replay.
fn row_adding_journal(root: &TestRoot) -> MemoryV1DurableJournal {
    let writer = writer_for(root);
    let observed = root.owner.handle().metadata().unwrap();
    let (mut journal, durability) =
        create_journal(root, DurableJournalLimits::conservative(), genesis());
    let create = ManagementMutationV2::UserCardCreate {
        row: UserCardRow {
            user_card_id: [8; 16],
            user_id: ACTOR,
            tenant_id: TENANT,
            status: UserCardStatus::Active,
        },
    };
    let request = coordinator_request(
        "r1-create",
        [0x31; 32],
        create,
        observed,
        writer.verified_admission(&observed).unwrap(),
        identity(1, 1, 1),
    );
    journal
        .prepare_mutation(&request, &durability)
        .unwrap()
        .into_durable_receipt(&durability)
        .unwrap();
    drop(journal);
    drop(durability);
    reopen_journal(root).0
}

// memory—v1: R1 witness. A valid journal whose one mutation adds a card row is
// refused by recovery when the adoption facts are the baseline snapshot counts.
// Replay adds the row, so the coverage check compares post-replay counts with
// facts that were captured before the row existed. The check is at
// memory_v1_adoption.rs:698-700 (counts equal the snapshot and scanned counts, and
// the total equals the row count), feeding complete_coverage at line 721. That
// path is production: adopt_with_production_evidence (memory_v1_root.rs:586) calls
// AdoptionEvidence::production (adoption.rs:755), which reaches build_evidence. The
// startup consequence is memory_v1_service.rs:617-630. A journaled Mutation record
// sends startup through recovery, and this refusal aborts the start, because the
// facts come from the database snapshot taken before replay (service.rs:612-613).
// The refusal is fail-closed. asserts current behaviour that is a known gap; update when fixed.
#[test]
fn witness_r1_recovery_refuses_a_valid_row_adding_journal_against_baseline_counts() {
    let root = production_root("r1-baseline");
    let journal = row_adding_journal(&root);
    assert_eq!(journal.record_count(), 1);
    let (candidate, baseline) = fresh_candidate();

    let refusal =
        recover_root(candidate, &journal, &cold_facts(baseline), &sealed_input()).unwrap_err();
    assert_eq!(refusal, RecoveryError::AdoptionRefused);
}

// memory—v1: R1 control. The same journal recovers when the facts describe the
// state after replay. The refusal above therefore comes from the coverage
// comparison, not from the journal or the replayed mutation.
#[test]
fn r1_control_post_replay_counts_adopt_the_row_adding_journal() {
    let root = production_root("r1-control");
    let journal = row_adding_journal(&root);
    let (candidate, baseline) = fresh_candidate();
    let mut post_replay = baseline;
    post_replay.user_cards += 1;

    let recovered = recover_root(
        candidate,
        &journal,
        &cold_facts(post_replay),
        &sealed_input(),
    )
    .expect("post-replay counts cover the replayed row");
    assert_eq!(recovered.replayed_mutations, 1);
    assert_eq!(
        recovered.owner.handle().metadata().unwrap().row_count,
        baseline.total().unwrap() + 1
    );
}

// memory—v1: The recovery owner reports a sequence gap when the first replayed
// mutation is not sequence 1, which is the case for a journal whose baseline is
// above zero (recovery_owner.rs:101-106). The existing governance owner test
// `recovery_refuses_a_sequence_gap` (governance_owner_tests.rs:708-752) has a name
// for a sequence gap, but it advances the candidate by one version and so reports
// ReplayConflict from the version check at recovery_owner.rs:118-119. Among the
// cases added here, this is the one that reaches SequenceGap.
#[test]
fn j3_recovery_reports_sequence_gap_for_a_nonzero_baseline() {
    let root = production_root("j3-gap");
    let shifted = JournalAnchor::new(MemoryId::from_bytes(STREAM), 0, 1, GENESIS_HASH).unwrap();
    let writer = writer_for(&root);
    let observed = root.owner.handle().metadata().unwrap();
    let (mut journal, durability) = MemoryV1DurableJournal::create(
        &journal_path(&root),
        MemoryId::from_bytes(STREAM),
        MemoryId::from_bytes(EPOCH),
        shifted,
        DurableJournalLimits::conservative(),
    )
    .unwrap();
    let request = coordinator_request(
        "j3-gap-op",
        [0x41; 32],
        set_card(UserCardStatus::Active),
        observed,
        writer.verified_admission(&observed).unwrap(),
        identity(1, 2, 1),
    );
    journal
        .prepare_mutation(&request, &durability)
        .unwrap()
        .into_durable_receipt(&durability)
        .unwrap();

    let (candidate, counts) = fresh_candidate();
    drop(journal);
    drop(durability);
    let (journal, _durability) = reopen_journal_at(&root, shifted);
    let error =
        recover_root(candidate, &journal, &cold_facts(counts), &sealed_input()).unwrap_err();
    assert_eq!(error, RecoveryError::SequenceGap);
}

// memory—v1: J5 witness at the owner. The operation ledger is keyed by the
// client-chosen identifier alone. A second actor that reuses an identifier is
// refused by the ledger before its own frame is written.
// asserts current behaviour that is a known gap; update when fixed.
#[test]
fn witness_j5_cross_actor_operation_id_is_refused_by_the_global_ledger() {
    let root = production_root("j5-actor");
    let owner = assembled_owner(&root);
    let first = root.owner.handle().metadata().unwrap();
    owner
        .commit(enable_request(
            ACTOR,
            CARD,
            first,
            "shared-op",
            fingerprint_hex(),
        ))
        .unwrap();
    let second = root.owner.handle().metadata().unwrap();

    let refused = owner
        .commit(enable_request(
            [7; 16],
            CARD,
            second,
            "shared-op",
            fingerprint_hex(),
        ))
        .unwrap_err();
    assert!(
        pending_reason(&refused).contains("operation ledger refused"),
        "{refused:?}"
    );
    assert_eq!(root.owner.handle().metadata().unwrap(), second);
    assert_eq!(owner.journal_sync_calls(), 1);
}

// memory—v1: J1 witness (source-shape presence pin, not behavioural evidence). The
// service's missing-journal branch is the else of the existence test, and it calls
// create with no refusal in between. The check reads the production region of the
// service source, which only the binary compiles. It does not detect a refusal
// inserted before the existence test. The behavioural evidence for the journal
// owner's refusal of a missing file is j1_missing_file_is_refused_by_the_journal_owner.
// asserts current behaviour that is a known gap; update when fixed.
#[test]
fn witness_j1_missing_journal_file_is_created_as_genesis_by_the_service() {
    let source = include_str!("memory_v1_service.rs");
    let production = &source[..source
        .find("#[cfg(test)]")
        .expect("the service keeps its tests after production code")];
    let function = production
        .find("pub(crate) fn open_durable_journal(")
        .expect("open_durable_journal exists in the production region");
    let body = &production[function..];
    let existing = body
        .find("if target.exists()")
        .expect("the existing-file branch is present");
    let create = body
        .find("MemoryV1DurableJournal::create(")
        .expect("the missing-file branch creates the journal");
    assert!(
        existing < create,
        "create is the fallback of the existence test"
    );
    let else_at = body[existing..]
        .find("} else {")
        .map(|offset| existing + offset)
        .expect("the missing-file branch is an else branch");
    let fallback = &body[else_at..create];
    assert!(
        !fallback.contains("bail!") && !fallback.contains("return") && !fallback.contains("Err("),
        "the missing-file fallback must not refuse before create"
    );
    assert!(body.contains("journal_genesis_anchor()"));
}

// memory—v1: J1 witness (source-shape presence pin, not behavioural evidence). The
// external baseline the service reopens against is a constant derived from a fixed
// string (memory_v1_service.rs:160-166). It is not a checkpoint bound to the
// database, so a reconciled MySQL checkpoint does not supply it. The pin shows the
// constant text only. The 04 section states the related limit that an external
// tail cannot exclude a missing suffix on its own (04-implementation.tex line 55).
// asserts current behaviour that is a known gap; update when fixed.
#[test]
fn witness_j1_journal_genesis_anchor_is_a_constant_not_a_checkpoint() {
    let source = include_str!("memory_v1_service.rs");
    let production = &source[..source
        .find("#[cfg(test)]")
        .expect("the service keeps its tests after production code")];
    let function = production
        .find("fn journal_genesis_anchor()")
        .expect("the genesis anchor function exists");
    let body = &production[function..];
    assert!(body.contains(r#"Sha256::digest(b"astrallight/memory-v1/journal-genesis/1\0")"#));
    assert!(body.contains("JournalAnchor::new(stream, 0, 0, genesis)"));
}

// memory—v1: Append raw bytes to the journal file through a second handle, as a
// torn or foreign write would. The owner's own handle is not told.
fn append_foreign_bytes(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

// memory—v1: J1. Once the journal has gone sticky the DENY port stops answering
// from the journal. The first DENY after a foreign write fails at the pre-write
// length check, marks the journal sticky and surfaces the cause as a pending
// error; every later DENY gets the unavailable response without a frame being
// attempted. The answer differs from the pending error of the failing call, so
// the test separates the explicit state test at the top of `prove_deny` from the
// refusal that `prepare_deny` would give anyway.
#[test]
fn j1_deny_port_answers_unavailable_once_the_journal_is_sticky() {
    let root = production_root("j1-deny-sticky");
    let owner = assembled_owner(&root);
    assert_eq!(
        owner
            .prove_deny(live_deny_observation(&root, "sticky-d1"))
            .unwrap(),
        DenyResponse::Forbidden
    );
    append_foreign_bytes(&journal_path(&root), &[0xAB; 7]);
    let tampered = file_len(&journal_path(&root));

    let failing = owner
        .prove_deny(live_deny_observation(&root, "sticky-d2"))
        .unwrap_err();
    assert!(
        pending_reason(&failing).contains("FileChanged"),
        "{failing:?}"
    );

    assert_eq!(
        owner
            .prove_deny(live_deny_observation(&root, "sticky-d3"))
            .unwrap(),
        DenyResponse::ServiceUnavailable,
        "a sticky journal is answered as unavailable, not as a pending error"
    );
    assert_eq!(
        file_len(&journal_path(&root)),
        tampered,
        "no frame is attempted once the journal is sticky"
    );
}
