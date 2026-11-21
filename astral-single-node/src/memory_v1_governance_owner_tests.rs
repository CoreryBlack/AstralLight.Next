//! memory—v1: contract tests for the single-node durable commit owner.
//!
//! The tests exercise the full A/A1 commit chain on a real process-local root:
//! sealed production adoption → root writer → opened journal → governed commit
//! (ledger claim, journal fsync, root CAS). Every test uses only the public
//! production APIs and real files; no mock substitutes for the durable journal
//! or the root.

use std::sync::Arc;

use astral_authorization_root::memory_v1_adoption::{
    ColdLoadFacts, MEMORY_V1_CANDIDATE_SCHEMA_VERSION,
};
use astral_authorization_root::memory_v1_db_rows::{
    BindingLayer, BindingRow, CandidateRows, CurrentSelection, IdentityCardRow, RuleSetRow,
    RuleSetStatus, RuleSetVersionRow, TenantRow, UserCardRow, UserCardStatus, UserRow,
};
use astral_authorization_root::memory_v1_hamt::CandidateBudget;
use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
use astral_authorization_root::memory_v1_root::{
    install_isolated_test_root, ProductionAdmission, RootOwner, RootStatus,
};
use astral_authorization_root::memory_v1_rules::{MemoryV1OwnerScope, MemoryV1TenantScope};
use astral_types::memory_v1::MemoryId;
use uuid::Uuid;

use super::memory_v1_governance_owner::MemoryV1DurableCommitOwner;
use super::memory_v1_root_writer::RootMutationWriter;
use astral_trustgraph::service::memory_v1_governance_commit::{
    MemoryV1GovernanceCommitPort, MemoryV1GovernanceCommitRequest,
};
use astral_trustgraph::service::memory_v1_mutation_coordinator::MutationAuditCandidate;
use astral_types::memory_v1_audit::{
    MemoryV1AuditAction, MemoryV1AuditActor, MemoryV1AuditCardState, MemoryV1AuditChange,
    MemoryV1AuditConfirmations, MemoryV1AuditContext, MemoryV1AuditDecisionInput,
    MemoryV1AuditEvent, MemoryV1AuditObject, MemoryV1AuditObjectState, MemoryV1AuditOperation,
    MemoryV1AuditRootObservation, MemoryV1AuditRootStatus, MemoryV1AuditRootVersion,
    MemoryV1AuditSource, MemoryV1AuditT2SingleChangeCandidate, MemoryV1AuditTime,
};

// The registry declaration the fixture root installs before adoption.
fn registry_declarations() -> Vec<RegistryDeclaration> {
    vec![RegistryDeclaration {
        resource: "document".to_owned(),
        actions: vec!["read".to_owned()],
    }]
}

// The candidate fixture: one user, one identity card, one tenant, one active
// card, one serving rule set with a hashed body, and one binding.
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
    // The structural serving checks require a binding confirmation and a
    // change confirmation bound to the selected version of the one rule set.
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
    // The structural serving checks require a change confirmation bound to the
    // selected version of the one rule set.
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

fn cold_facts(counts: astral_authorization_root::memory_v1_db_rows::TableCounts) -> ColdLoadFacts {
    ColdLoadFacts {
        schema_contract_version: MEMORY_V1_CANDIDATE_SCHEMA_VERSION,
        schema_fingerprint: [7; 32],
        snapshot_counts: counts,
        scanned_counts: counts,
        captured_at_unix_seconds: 1_700_000_000,
    }
}

fn sealed_input() -> astral_authorization_root::memory_v1_adoption::ProductionEvidenceInput {
    use astral_authorization_root::memory_v1_adoption::{AdoptionLimit, ProvenFamily};
    let sealed = ProvenFamily::proven_for;
    let mut input =
        astral_authorization_root::memory_v1_adoption::ProductionEvidenceInput::default();
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
        .with_trusted_time(1_700_000_000);
    input
}

struct TestRoot {
    owner: Arc<RootOwner>,
    admission: Arc<ProductionAdmission>,
    dir: std::path::PathBuf,
}

impl TestRoot {
    /// The metadata observed at adoption; the writer re-checks it at commit.
    fn metadata(
        &self,
    ) -> Result<
        astral_authorization_root::memory_v1_root::RootMetadata,
        astral_authorization_root::memory_v1_root::RootError,
    > {
        self.owner.handle().metadata()
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn production_root() -> TestRoot {
    let (rows, selections) = fixture_rows();
    let counts = rows.table_counts();
    let owner = install_isolated_test_root(
        rows,
        selections,
        CandidateBudget {
            max_table_rows: 32,
            max_bindings_per_read: 4,
        },
    )
    .unwrap();
    owner.install_registry(&registry_declarations()).unwrap();
    let (_, admission) = owner
        .adopt_with_production_evidence(&cold_facts(counts), &sealed_input())
        .unwrap();
    let dir = std::env::temp_dir().join(format!("astral-governance-owner-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    TestRoot {
        owner: Arc::new(owner),
        admission: Arc::new(admission),
        dir,
    }
}

fn reopened_journal(
    root: &TestRoot,
) -> (
    super::memory_v1_durable_journal::MemoryV1DurableJournal,
    super::memory_v1_durable_journal::JournalDurability,
) {
    use astral_types::memory_v1::MemoryId;
    use astral_types::memory_v1_journal::JournalAnchor;
    let target = root.dir.join("journal.bin");
    let anchor = JournalAnchor::new(MemoryId::from_bytes([10; 16]), 0, 0, [5; 32]).unwrap();
    let tail = super::memory_v1_durable_journal::MemoryV1DurableJournal::scan_tail(
        &target,
        MemoryId::from_bytes([10; 16]),
        MemoryId::from_bytes([11; 16]),
        anchor,
        super::memory_v1_durable_journal::DurableJournalLimits::conservative(),
    )
    .unwrap();
    super::memory_v1_durable_journal::MemoryV1DurableJournal::open(
        &target,
        MemoryId::from_bytes([10; 16]),
        MemoryId::from_bytes([11; 16]),
        anchor,
        tail,
        super::memory_v1_durable_journal::DurableJournalLimits::conservative(),
    )
    .unwrap()
}

fn opened_journal(
    root: &TestRoot,
) -> (
    super::memory_v1_durable_journal::MemoryV1DurableJournal,
    super::memory_v1_durable_journal::JournalDurability,
) {
    use astral_types::memory_v1::MemoryId;
    use astral_types::memory_v1_journal::JournalAnchor;
    let anchor = JournalAnchor::new(MemoryId::from_bytes([10; 16]), 0, 0, [5; 32]).unwrap();
    super::memory_v1_durable_journal::MemoryV1DurableJournal::create(
        &root.dir.join("journal.bin"),
        MemoryId::from_bytes([10; 16]),
        MemoryId::from_bytes([11; 16]),
        anchor,
        super::memory_v1_durable_journal::DurableJournalLimits::conservative(),
    )
    .unwrap()
}

fn assembled_owner(root: &TestRoot) -> MemoryV1DurableCommitOwner {
    let writer =
        RootMutationWriter::new(Arc::clone(&root.owner), Arc::clone(&root.admission)).unwrap();
    MemoryV1DurableCommitOwner::new(opened_journal(root), writer)
}

// memory—v1: Build the request the HTTP seam would carry for an enable.
fn enable_request(
    root_metadata: astral_authorization_root::memory_v1_root::RootMetadata,
    operation_id: &str,
    fingerprint_hex: String,
    trusted_time: i64,
) -> MemoryV1GovernanceCommitRequest {
    let mutation =
        astral_authorization_root::memory_v1_root::ManagementMutationV2::UserCardStatus {
            user_card_id: [4; 16],
            status: UserCardStatus::Active,
        };
    let fingerprint = {
        let bytes = hex::decode(&fingerprint_hex).unwrap();
        <[u8; 32]>::try_from(bytes).unwrap()
    };
    let summary = MutationAuditCandidate::governance_mutation_summary(&mutation).unwrap();
    let instance = MemoryId::from_bytes(*root_metadata.instance_id.as_uuid().as_bytes());
    let root_version = MemoryV1AuditRootVersion::new(instance, root_metadata.version);
    let context = MemoryV1AuditContext::new(
        MemoryV1AuditActor::new(MemoryId::from_bytes([1; 16]), MemoryId::from_bytes([2; 16])),
        MemoryV1AuditTime::new(trusted_time).unwrap(),
        MemoryV1AuditAction::new("user_card", "enable").unwrap(),
        "GOVERNANCE_USER_CARD_ENABLE",
        MemoryV1AuditOperation::new(operation_id, fingerprint).unwrap(),
        MemoryV1AuditRootObservation::new(
            root_version,
            root_metadata.digest,
            MemoryV1AuditRootStatus::Serving,
        ),
    )
    .unwrap();
    let change = MemoryV1AuditChange::new(
        Some(MemoryId::from_bytes([1; 16])),
        Some(MemoryV1AuditObject::UserCard(MemoryId::from_bytes([4; 16]))),
        Some(MemoryV1AuditObject::Tenant(MemoryId::from_bytes([3; 16]))),
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
        request_fingerprint: fingerprint_hex,
        root: root_metadata,
        actor: [1; 16],
        target: [4; 16],
        target_tenant: [3; 16],
        target_owner: Some([1; 16]),
        trusted_time_unix_seconds: trusted_time,
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

// memory—v1: The complete happy path: value-level binding, ledger claim, one
// fsynced journal append, one serving-root CAS, and a proof-backed response
// whose metadata is the root's new serving snapshot.
#[test]
fn commit_publishes_journal_and_root_and_returns_the_published_metadata() {
    let root = production_root();
    let owner = assembled_owner(&root);
    let before = root.metadata().unwrap();
    let request = enable_request(before, "op-1", "ab".repeat(32), 1_700_000_000);

    let response = owner.commit(request).unwrap();

    assert_eq!(response.operation_id, "op-1");
    assert_eq!(response.root.status, RootStatus::Serving);
    assert_eq!(response.root.version, before.version + 1);
    assert_ne!(response.root.digest, [0; 32]);
    // The root really published the new snapshot.
    assert_eq!(root.metadata().unwrap(), response.root);
}

// memory—v1: The same operation replayed against the same owner is refused
// before any second journal append or root CAS.
#[test]
fn commit_refuses_an_operation_replay_without_a_second_write() {
    let root = production_root();
    let owner = assembled_owner(&root);
    let before = root.metadata().unwrap();
    let request = enable_request(before, "op-1", "ab".repeat(32), 1_700_000_000);
    owner.commit(request.clone()).unwrap();

    let error = owner.commit(request).unwrap_err();
    assert!(
        matches!(error, astral_types::AstralError::Pending(_)),
        "the replay must fail closed, got {error:?}"
    );
    assert_eq!(root.metadata().unwrap().version, before.version + 1);
}

// memory—v1: The fixed refusal reason for a recorded operation identity,
// asserted as a literal so the production constant cannot drift silently.
const RECORDED_IDENTITY_REASON: &str = "governance operation identity is already \
     recorded in the retained durable journal; no record was written for this request and the \
     recorded result requires reconciliation";

// memory—v1: Rebuild a second-boot owner over the same durable journal: a
// fresh candidate, the verified reopen, the real recovery replay, and a new
// writer and owner over the retained file. Returns the owner, the recovered
// serving metadata, and the retained file length.
fn second_boot(
    root: &TestRoot,
) -> (
    MemoryV1DurableCommitOwner,
    astral_authorization_root::memory_v1_root::RootMetadata,
    u64,
) {
    use crate::memory_v1_recovery_owner::recover_root;

    let (rows, _) = fixture_rows();
    let counts = rows.table_counts();
    let fresh = install_isolated_test_root(
        rows,
        vec![CurrentSelection {
            rule_set_id: [5; 16],
            version_bytes: vec![1],
        }],
        CandidateBudget {
            max_table_rows: 32,
            max_bindings_per_read: 4,
        },
    )
    .unwrap();
    fresh.install_registry(&registry_declarations()).unwrap();
    let facts = cold_facts(counts);
    let input = sealed_input();
    let (journal, durability) = reopened_journal(root);
    let recovered = recover_root(fresh, &journal, &facts, &input).unwrap();
    let metadata = recovered.owner.handle().metadata().unwrap();
    let writer = RootMutationWriter::new(
        Arc::clone(&recovered.owner),
        Arc::clone(&recovered.admission),
    )
    .unwrap();
    let owner = MemoryV1DurableCommitOwner::new((journal, durability), writer);
    let retained_bytes = std::fs::metadata(root.dir.join("journal.bin"))
        .unwrap()
        .len();
    (owner, metadata, retained_bytes)
}

// memory—v1: A second boot over the reopened journal must refuse a retained
// operation identity without any durable write and while staying Ready; the
// refusal reason is the fixed literal and claims no outcome or provenance.
#[test]
fn reopened_owner_refuses_a_prior_boot_operation_id_without_a_write() {
    let root = production_root();
    let first = assembled_owner(&root);
    let before = root.metadata().unwrap();
    first
        .commit(enable_request(
            before,
            "op-1",
            "ab".repeat(32),
            1_700_000_000,
        ))
        .unwrap();
    drop(first);
    let target = root.dir.join("journal.bin");
    let boot1_bytes = std::fs::metadata(&target).unwrap().len();

    let (second, metadata_after, retained_bytes) = second_boot(&root);
    assert_eq!(metadata_after.version, before.version + 1);
    assert_eq!(retained_bytes, boot1_bytes);

    let retry = enable_request(metadata_after, "op-1", "ab".repeat(32), 1_700_000_000);
    let error = second.commit(retry).unwrap_err();
    let reason = match &error {
        astral_types::AstralError::Pending(reason) => reason.clone(),
        other => panic!("the cross-boot replay must fail closed, got {other:?}"),
    };
    assert_eq!(reason, RECORDED_IDENTITY_REASON);
    assert_eq!(
        std::fs::metadata(&target).unwrap().len(),
        boot1_bytes,
        "the refused retry must not append or sync any byte"
    );

    // The owner stays Ready: an unrelated operation commits normally. The
    // refused retry published nothing, so the observation is still live.
    let next = enable_request(metadata_after, "op-2", "cd".repeat(32), 1_700_000_001);
    let response = second.commit(next).unwrap();
    assert_eq!(response.root.version, metadata_after.version + 1);
    assert!(std::fs::metadata(&target).unwrap().len() > boot1_bytes);
    drop(second);

    // The durable file holds exactly the two committed mutations.
    let (journal, _) = reopened_journal(&root);
    assert_eq!(journal.position().journal_sequence(), 2);
    assert_eq!(journal.position().mutation_sequence(), 2);
    assert_eq!(journal.recovery_records().len(), 2);
}

// memory—v1: A retained operation identity resubmitted with different content
// is refused with the same fixed reason and no write.
#[test]
fn reopened_owner_refuses_an_altered_prior_boot_operation_without_a_write() {
    let root = production_root();
    let first = assembled_owner(&root);
    let before = root.metadata().unwrap();
    first
        .commit(enable_request(
            before,
            "op-1",
            "ab".repeat(32),
            1_700_000_000,
        ))
        .unwrap();
    drop(first);
    let target = root.dir.join("journal.bin");
    let boot1_bytes = std::fs::metadata(&target).unwrap().len();

    let (second, metadata_after, retained_bytes) = second_boot(&root);
    assert_eq!(retained_bytes, boot1_bytes);

    let altered = enable_request(metadata_after, "op-1", "cd".repeat(32), 1_700_000_000);
    let error = second.commit(altered).unwrap_err();
    let reason = match &error {
        astral_types::AstralError::Pending(reason) => reason.clone(),
        other => panic!("the altered replay must fail closed, got {other:?}"),
    };
    assert_eq!(reason, RECORDED_IDENTITY_REASON);
    assert_eq!(
        std::fs::metadata(&target).unwrap().len(),
        boot1_bytes,
        "the refused altered replay must not append or sync any byte"
    );
    drop(second);

    // The retained file is unchanged: exactly the one boot-1 record.
    let (journal, _) = reopened_journal(&root);
    assert_eq!(journal.position().journal_sequence(), 1);
    assert_eq!(journal.position().mutation_sequence(), 1);
    assert_eq!(journal.recovery_records().len(), 1);
}

// memory—v1: An operation identity already recorded as a DENY in the same
// boot is refused for a governance mutation with the same fixed reason and
// no second record; the refusal must not assume a foreign or earlier boot.
#[test]
fn commit_refuses_an_operation_id_already_recorded_as_a_deny() {
    use astral_trustgraph::service::memory_v1_governance_commit::MemoryV1DenyProofPort;
    use astral_trustgraph::service::memory_v1_mutation_coordinator::DenyResponse;

    let root = production_root();
    let owner = assembled_owner(&root);
    let before = root.metadata().unwrap();
    owner
        .commit(enable_request(
            before,
            "op-1",
            "ab".repeat(32),
            1_700_000_000,
        ))
        .unwrap();
    assert_eq!(
        owner
            .prove_deny(deny_observation(&root, "shared-op-1".into()))
            .unwrap(),
        DenyResponse::Forbidden
    );
    let target = root.dir.join("journal.bin");
    let recorded_bytes = std::fs::metadata(&target).unwrap().len();

    let error = owner
        .commit(enable_request(
            root.metadata().unwrap(),
            "shared-op-1",
            "cd".repeat(32),
            1_700_000_001,
        ))
        .unwrap_err();
    let reason = match &error {
        astral_types::AstralError::Pending(reason) => reason.clone(),
        other => panic!("the cross-kind identity conflict must fail closed, got {other:?}"),
    };
    assert_eq!(reason, RECORDED_IDENTITY_REASON);
    assert_eq!(
        std::fs::metadata(&target).unwrap().len(),
        recorded_bytes,
        "the refused mutation must not append or sync any byte"
    );

    // The owner stays Ready for an unrelated operation.
    let next = enable_request(
        root.metadata().unwrap(),
        "op-2",
        "ef".repeat(32),
        1_700_000_002,
    );
    let response = owner.commit(next).unwrap();
    assert_eq!(response.root.version, before.version + 2);
}

// memory—v1: A stale root observation is refused before any journal write.
#[test]
fn commit_refuses_a_stale_root_observation() {
    let root = production_root();
    let owner = assembled_owner(&root);
    let before = root.metadata().unwrap();
    // Advance the root past the observation through the controlled writer.
    root.owner
        .execute_serving_mutation_with_admission(
            root.admission.as_ref(),
            &astral_authorization_root::memory_v1_root::ManagementMutationV2::UserCardStatus {
                user_card_id: [4; 16],
                status: UserCardStatus::Active,
            },
            &astral_authorization_root::memory_v1_root::MutationPrecondition {
                evaluated_root_version: before.version,
            },
        )
        .unwrap();

    let error = owner
        .commit(enable_request(
            before,
            "op-2",
            "cd".repeat(32),
            1_700_000_001,
        ))
        .unwrap_err();
    assert!(
        matches!(error, astral_types::AstralError::Pending(_)),
        "the stale observation must fail closed, got {error:?}"
    );
    assert_eq!(root.metadata().unwrap().version, before.version + 1);
}

// memory—v1: Give each fresh DENY a unique stable operation identity.
fn deny_observation(
    root: &TestRoot,
    operation_id: String,
) -> astral_types::memory_v1_deny_observation::MemoryV1DenyObservation {
    use astral_types::memory_v1::CandidateIdentity;
    use astral_types::memory_v1_audit::MemoryV1AuditDenySource;
    use astral_types::memory_v1_deny_observation::{
        MemoryV1DenyAffectedBindingState, MemoryV1DenyObservation, MemoryV1DenyRootObservation,
    };

    let metadata = root.metadata().unwrap();
    let root_observation = MemoryV1DenyRootObservation::try_from_usize(
        MemoryId::from_bytes(*metadata.instance_id.as_uuid().as_bytes()),
        metadata.version,
        metadata.digest,
        MemoryV1AuditRootStatus::Serving,
        metadata.budget.max_table_rows,
        metadata.budget.max_bindings_per_read,
        metadata.row_count,
    )
    .unwrap();
    MemoryV1DenyObservation::new(
        root_observation,
        CandidateIdentity {
            user_id: MemoryId::from_bytes([1; 16]),
            identity_card_id: MemoryId::from_bytes([2; 16]),
            user_card_id: MemoryId::from_bytes([4; 16]),
            tenant_id: MemoryId::from_bytes([3; 16]),
        },
        1_700_000_000,
        "permission_rule",
        "read",
        None,
        Some(Vec::new()),
        None,
        MemoryV1DenyAffectedBindingState::inapplicable(),
        operation_id.into_bytes(),
        [9; 32].to_vec(),
        MemoryV1AuditDenySource::RuleDeny,
        None,
    )
    .unwrap()
}

// memory—v1: Both proofs mint from the receipt; a replay writes no new frame.
#[test]
fn deny_issuer_appends_a_deny_record_and_returns_forbidden() {
    use astral_trustgraph::service::memory_v1_governance_commit::MemoryV1DenyProofPort;

    let root = production_root();
    let owner = assembled_owner(&root);
    let observation = deny_observation(&root, "deny-op-1".into());
    let outcome = owner.prove_deny(observation.clone()).unwrap();
    assert_eq!(
        outcome,
        astral_trustgraph::service::memory_v1_mutation_coordinator::DenyResponse::Forbidden
    );

    // A replay of the same observation keeps one record and stays Forbidden.
    let outcome = owner.prove_deny(observation).unwrap();
    assert_eq!(
        outcome,
        astral_trustgraph::service::memory_v1_mutation_coordinator::DenyResponse::Forbidden
    );
    // Verify through an independent scan of the durable file: exactly one
    // record exists after the append and its replay.
    {
        use astral_types::memory_v1_journal::JournalAnchor;
        let anchor = JournalAnchor::new(MemoryId::from_bytes([10; 16]), 0, 0, [5; 32]).unwrap();
        let tail = crate::memory_v1_durable_journal::MemoryV1DurableJournal::scan_tail(
            &root.dir.join("journal.bin"),
            MemoryId::from_bytes([10; 16]),
            MemoryId::from_bytes([11; 16]),
            anchor,
            crate::memory_v1_durable_journal::DurableJournalLimits::conservative(),
        )
        .unwrap();
        assert_eq!(tail.journal_sequence(), 1, "one deny record was appended");
    }
    assert_eq!(
        owner.journal_sync_calls(),
        1,
        "a replay does not sync again"
    );
}

// memory—v1: Exercise distinct DENY observations through the production proof
// owner, then reopen the journal to verify the complete audit prefix.
#[test]
#[ignore = "local release DENY proof load; run explicitly with --ignored"]
fn deny_proof_concurrency_curve() {
    use std::sync::{mpsc, Barrier};
    use std::time::{Duration, Instant};

    use astral_trustgraph::service::memory_v1_governance_commit::MemoryV1DenyProofPort;
    use astral_trustgraph::service::memory_v1_mutation_coordinator::DenyResponse;

    const ROUNDS: usize = 3;
    const PER_WORKER: usize = 24;
    for workers in [1, 2, 4, 8, 16] {
        for round in 0..ROUNDS {
            let root = production_root();
            let owner = Arc::new(assembled_owner(&root));
            let start = Arc::new(Barrier::new(workers + 1));
            let (done, results) = mpsc::channel();
            let mut joins = Vec::with_capacity(workers);
            for worker in 0..workers {
                let observations: Vec<_> = (0..PER_WORKER)
                    .map(|i| deny_observation(&root, format!("deny-{worker}-{i}")))
                    .collect();
                let (owner, start, done) = (Arc::clone(&owner), Arc::clone(&start), done.clone());
                joins.push(std::thread::spawn(move || {
                    let mut latency = Vec::with_capacity(PER_WORKER);
                    start.wait();
                    for observation in observations {
                        let began = Instant::now();
                        assert_eq!(
                            owner.prove_deny(observation).unwrap(),
                            DenyResponse::Forbidden
                        );
                        latency.push(began.elapsed().as_micros());
                    }
                    done.send(latency).unwrap();
                }));
            }
            drop(done);
            let began = Instant::now();
            start.wait();
            let mut latency = Vec::with_capacity(workers * PER_WORKER);
            let deadline = began + Duration::from_secs(15);
            for _ in 0..workers {
                latency.extend(
                    results
                        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                        .expect("DENY proof must complete"),
                );
            }
            let elapsed = began.elapsed();
            for worker in joins {
                worker.join().unwrap();
            }
            let syncs = owner.journal_sync_calls();
            let operations = workers * PER_WORKER;
            assert!((1..=operations as u64).contains(&syncs));
            if workers == 1 {
                assert_eq!(syncs, operations as u64);
            }
            drop(owner);
            let (journal, _) = reopened_journal(&root);
            assert_eq!(journal.position().journal_sequence(), operations as u64);
            assert_eq!(journal.position().mutation_sequence(), 0);
            assert_eq!(journal.recovery_records().len(), operations);
            latency.sort_unstable();
            let percentile = |p: usize| latency[(latency.len() * p).div_ceil(100) - 1];
            println!(
                "deny_owner workers={workers} round={round} operations={operations} syncs={syncs} ops_per_sec={:.2} p50_us={} p95_us={} p99_us={}",
                operations as f64 / elapsed.as_secs_f64(), percentile(50), percentile(95), percentile(99),
            );
        }
    }
}

// memory—v1: The deny payload round-trips: encode, decode, digest match.
#[test]
fn deny_journal_payload_round_trips() {
    use astral_trustgraph::service::memory_v1_mutation_coordinator::{
        decode_deny_journal_payload, DenyJournalRequest,
    };
    use astral_types::memory_v1::CandidateIdentity;
    use astral_types::memory_v1_audit::{MemoryV1AuditDenySource, MemoryV1AuditRootStatus};
    use astral_types::memory_v1_deny_observation::{
        MemoryV1DenyAffectedBindingState, MemoryV1DenyObservation, MemoryV1DenyRootObservation,
    };

    let root_observation = MemoryV1DenyRootObservation::try_from_usize(
        MemoryId::from_bytes([1; 16]),
        7,
        [7; 32],
        MemoryV1AuditRootStatus::Serving,
        32,
        4,
        9,
    )
    .unwrap();
    let observation = MemoryV1DenyObservation::new(
        root_observation,
        CandidateIdentity {
            user_id: MemoryId::from_bytes([1; 16]),
            identity_card_id: MemoryId::from_bytes([2; 16]),
            user_card_id: MemoryId::from_bytes([4; 16]),
            tenant_id: MemoryId::from_bytes([3; 16]),
        },
        42,
        "permission_rule",
        "read",
        None,
        None,
        None,
        MemoryV1DenyAffectedBindingState::inapplicable(),
        b"deny-op-2".to_vec(),
        [8; 32].to_vec(),
        MemoryV1AuditDenySource::NoMatch,
        None,
    )
    .unwrap();
    let identity =
        astral_trustgraph::service::memory_v1_mutation_coordinator::JournalIdentity::new(
            MemoryId::from_bytes([10; 16]),
            MemoryId::from_bytes([11; 16]),
            3,
            2,
            MemoryId::from_bytes([12; 16]),
        )
        .unwrap();
    let request = DenyJournalRequest::try_new(observation, identity).unwrap();
    let payload = request.journal_payload().unwrap();
    assert_eq!(payload.len(), request.payload_bytes());
    let decoded = decode_deny_journal_payload(&payload).unwrap();
    assert_eq!(decoded.operation_id(), b"deny-op-2");
}

// memory—v1: Crash recovery: one journaled mutation is replayed on top of the
// captured candidate, the root is adopted at the production grade, and the
// replayed state is visible to readers.
#[test]
fn recovery_replays_a_journaled_mutation_before_adoption() {
    use crate::memory_v1_recovery_owner::recover_root;

    let root = production_root();
    // The journal starts fresh; the commit owner appends one mutation.
    let owner = assembled_owner(&root);
    let before = root.metadata().unwrap();
    let request = enable_request(before, "replay-op-1", "ab".repeat(32), 1_700_000_000);
    owner.commit(request).unwrap();
    assert_eq!(root.metadata().unwrap().version, before.version + 1);
    drop(owner);

    // Recovery from a candidate reinstalled from the same base rows: the
    // journal carries the mutation; the candidate does not have it yet.
    let (rows, _selections) = fixture_rows();
    let counts = rows.table_counts();
    let fresh = install_isolated_test_root(
        rows,
        vec![CurrentSelection {
            rule_set_id: [5; 16],
            version_bytes: vec![1],
        }],
        CandidateBudget {
            max_table_rows: 32,
            max_bindings_per_read: 4,
        },
    )
    .unwrap();
    fresh.install_registry(&registry_declarations()).unwrap();
    let facts = cold_facts(counts);
    let input = sealed_input();
    let (journal, _durability) = reopened_journal(&root);
    let recovered = recover_root(fresh, &journal, &facts, &input).unwrap();
    assert_eq!(recovered.replayed_mutations, 1);
    let metadata = recovered.owner.handle().metadata().unwrap();
    assert_eq!(metadata.status, RootStatus::Serving);
    assert_eq!(metadata.version, before.version + 1);
    // The production admission validates against the recovered root.
    assert_eq!(
        recovered
            .owner
            .handle()
            .validate_production_admission(recovered.admission.as_ref())
            .unwrap(),
        metadata
    );
}

// memory—v1: A journal whose records exceed the candidate's version is a
// sequence gap; recovery refuses instead of starting a half-recovered root.
#[test]
fn recovery_refuses_a_sequence_gap() {
    use crate::memory_v1_recovery_owner::{recover_root, RecoveryError};

    let root = production_root();
    let owner = assembled_owner(&root);
    let before = root.metadata().unwrap();
    let request = enable_request(before, "gap-op-1", "cd".repeat(32), 1_700_000_000);
    owner.commit(request).unwrap();
    drop(owner);

    // A candidate that already contains the replayed change cannot be the
    // base of this journal: version 0 + one record would double-apply.
    let (rows, _selections) = fixture_rows();
    let counts = rows.table_counts();
    let advanced = install_isolated_test_root(
        rows,
        vec![CurrentSelection {
            rule_set_id: [5; 16],
            version_bytes: vec![1],
        }],
        CandidateBudget {
            max_table_rows: 32,
            max_bindings_per_read: 4,
        },
    )
    .unwrap();
    advanced.install_registry(&registry_declarations()).unwrap();
    // Advance the candidate by one so the journal record's precondition
    // (version 0) no longer matches.
    advanced
        .execute_recovery_mutation(
            &astral_authorization_root::memory_v1_root::ManagementMutationV2::UserCardStatus {
                user_card_id: [4; 16],
                status: UserCardStatus::Active,
            },
            &astral_authorization_root::memory_v1_root::MutationPrecondition {
                evaluated_root_version: 0,
            },
        )
        .unwrap();
    let facts = cold_facts(counts);
    let input = sealed_input();
    let (journal, _durability) = reopened_journal(&root);
    let error = recover_root(advanced, &journal, &facts, &input).unwrap_err();
    assert!(matches!(error, RecoveryError::ReplayConflict), "{error:?}");
}

// memory—v1: The published snapshot carries the complete reserved record:
// the facts, the governance position and the frame are retrievable from the
// snapshot itself, the decoded frame binds the exact operation after the
// request and the temporary encoding are gone, and the durable file holds
// exactly the published bytes at the reserved span.
#[test]
fn commit_publishes_facts_position_and_reserved_frame_under_one_cas() {
    use astral_types::memory_v1_journal::decode_record;

    let root = production_root();
    let owner = assembled_owner(&root);
    let before = root.metadata().unwrap();
    let request = enable_request(before, "op-1", "ab".repeat(32), 1_700_000_000);
    let operation_id = request.operation_id.clone();

    let response = owner.commit(request).unwrap();

    // The published metadata is the root's serving snapshot.
    assert_eq!(root.metadata().unwrap(), response.root);
    // The governance position anchors the first mutation of the journal epoch.
    let frontier = root
        .owner
        .current_governance_frontier(&root.admission, &response.root)
        .unwrap();
    match frontier {
        astral_authorization_root::memory_v1_root::GovernanceFrontier::Published(prefix) => {
            assert_eq!(prefix.epoch(), MemoryId::from_bytes([11; 16]));
            assert_eq!(prefix.anchor().journal_sequence(), 1);
            assert_eq!(prefix.anchor().mutation_sequence(), 1);
        }
        other => panic!("the published frontier must be Published, got {other:?}"),
    }
    // The snapshot carries the complete reserved frame, decodable after the
    // request and the temporary encoding are gone.
    let record = root
        .owner
        .published_governance_record(&root.admission, &response.root)
        .unwrap()
        .expect("the governed publication carries its reserved record");
    assert_eq!(record.journal_sequence(), 1);
    assert_eq!(record.mutation_sequence(), 1);
    assert_eq!(record.start_offset(), 0);
    let decoded = decode_record(record.frame()).unwrap();
    assert_eq!(decoded.record.operation_id, operation_id.as_str());
    assert_eq!(decoded.digest, record.tail_hash());
    assert_eq!(decoded.record.mutation_sequence, 1);
    // The durable file holds exactly the published bytes at the reserved span.
    let bytes = std::fs::read(root.dir.join("journal.bin")).unwrap();
    assert_eq!(record.end_offset() as usize, bytes.len());
    assert_eq!(
        &bytes[record.start_offset() as usize..record.end_offset() as usize],
        record.frame()
    );
    // The chain tail of the reopened journal is the reserved record's digest.
    // The owner is dropped first so the writer lock is released for the
    // verified reopen.
    drop(owner);
    let (journal, _) = reopened_journal(&root);
    assert_eq!(journal.position().frame_hash(), &record.tail_hash());
    assert_eq!(journal.position().journal_sequence(), 1);
    assert_eq!(journal.recovery_records().len(), 1);
}

// memory—v1: The baseline snapshot publishes no reservation; only the governed
// publication path attaches one.
#[test]
fn the_baseline_snapshot_publishes_no_reservation() {
    let root = production_root();
    let before = root.metadata().unwrap();
    assert!(root
        .owner
        .published_governance_record(&root.admission, &before)
        .unwrap()
        .is_none());
}

// memory—v1: An exhausted journal refuses the reservation before the CAS:
// nothing is published, no byte is written, no sync is spent, and the
// operation claim is not retained, so a retry is refused by the reservation
// again with the same precise reason.
#[test]
fn a_capacity_exhausted_reservation_refuses_before_any_publication() {
    use crate::memory_v1_durable_journal::DurableJournalLimits;

    let root = production_root();
    let writer =
        RootMutationWriter::new(Arc::clone(&root.owner), Arc::clone(&root.admission)).unwrap();
    let limits = DurableJournalLimits {
        max_records: 1,
        ..DurableJournalLimits::conservative()
    };
    let (journal, durability) = {
        let anchor = astral_types::memory_v1_journal::JournalAnchor::new(
            MemoryId::from_bytes([10; 16]),
            0,
            0,
            [5; 32],
        )
        .unwrap();
        crate::memory_v1_durable_journal::MemoryV1DurableJournal::create(
            &root.dir.join("journal.bin"),
            MemoryId::from_bytes([10; 16]),
            MemoryId::from_bytes([11; 16]),
            anchor,
            limits,
        )
        .unwrap()
    };
    let owner = MemoryV1DurableCommitOwner::new((journal, durability), writer);
    let before = root.metadata().unwrap();
    owner
        .commit(enable_request(
            before,
            "cap-g1",
            "ab".repeat(32),
            1_700_000_000,
        ))
        .unwrap();
    let after = root.metadata().unwrap();
    let target = root.dir.join("journal.bin");
    let length = std::fs::metadata(&target).unwrap().len();

    let refused = owner
        .commit(enable_request(
            after,
            "cap-g2",
            "cd".repeat(32),
            1_700_000_001,
        ))
        .unwrap_err();
    assert!(
        matches!(&refused, astral_types::AstralError::Pending(reason) if reason.contains("CapacityExceeded")),
        "{refused:?}"
    );
    assert_eq!(root.metadata().unwrap(), after, "nothing was published");
    assert_eq!(
        std::fs::metadata(&target).unwrap().len(),
        length,
        "no byte was written"
    );
    assert_eq!(owner.journal_sync_calls(), 1, "the refusal never synced");

    // The retry is refused by the reservation again: the claim was never
    // retained, and no byte appears for either attempt.
    let retry = owner
        .commit(enable_request(
            after,
            "cap-g2",
            "cd".repeat(32),
            1_700_000_001,
        ))
        .unwrap_err();
    assert!(
        matches!(&retry, astral_types::AstralError::Pending(reason) if reason.contains("CapacityExceeded")),
        "{retry:?}"
    );
    assert_eq!(std::fs::metadata(&target).unwrap().len(), length);
}
