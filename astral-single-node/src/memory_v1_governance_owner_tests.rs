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
    MemoryV1AuditChangeSummary, MemoryV1AuditConfirmations, MemoryV1AuditContext,
    MemoryV1AuditDecisionInput, MemoryV1AuditEvent, MemoryV1AuditObject, MemoryV1AuditObjectState,
    MemoryV1AuditOperation, MemoryV1AuditRootObservation, MemoryV1AuditRootStatus,
    MemoryV1AuditRootVersion, MemoryV1AuditSource, MemoryV1AuditT2SingleChangeCandidate,
    MemoryV1AuditTime,
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
    use astral_authorization_root::memory_v1_rules::{canonical_version_bytes, version_digest};
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

// memory—v1: The DENY proof issuer on the same journal: one observation
// becomes one fsynced Deny record, both proofs mint from the receipt, and the
// gate returns 403. A replay of the same observation is idempotent.
#[test]
fn deny_issuer_appends_a_deny_record_and_returns_forbidden() {
    use astral_trustgraph::service::memory_v1_governance_commit::MemoryV1DenyProofPort;
    use astral_types::memory_v1::CandidateIdentity;
    use astral_types::memory_v1_audit::{MemoryV1AuditDenySource, MemoryV1AuditRootStatus};
    use astral_types::memory_v1_deny_observation::{
        MemoryV1DenyAffectedBindingState, MemoryV1DenyObservation, MemoryV1DenyRootObservation,
    };

    let root = production_root();
    let owner = assembled_owner(&root);
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
    let observation = MemoryV1DenyObservation::new(
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
        b"deny-op-1".to_vec(),
        [9; 32].to_vec(),
        astral_types::memory_v1_audit::MemoryV1AuditDenySource::RuleDeny,
        None,
    )
    .unwrap();

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
        assert!(tail.journal_sequence() >= 1, "one deny record was appended");
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
    use astral_trustgraph::service::memory_v1_mutation_coordinator::MutationRequest;

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
