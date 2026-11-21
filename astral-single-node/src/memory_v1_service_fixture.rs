//! memory—v1: Synthetic inputs for the production-port contract tests. None of
//! these inputs establish an independent fact on the installed process root.

use std::path::Path;

use astral_authorization_root::memory_v1_adoption::{
    AdoptionLimit, ProductionEvidenceInput, ProvenFamily,
};
use astral_authorization_root::memory_v1_db_rows::CandidateRows;
use astral_authorization_root::memory_v1_hamt::CandidateBudget;
use astral_authorization_root::memory_v1_root::{install_isolated_test_root, RootOwner};
use astral_single_node::memory_v1_durable_journal::{
    DurableJournalLimits, JournalDurability, MemoryV1DurableJournal,
};

pub(super) fn owner(rows: CandidateRows) -> RootOwner {
    let selections = rows.current_version_selections().unwrap();
    install_isolated_test_root(
        rows,
        selections,
        CandidateBudget {
            max_table_rows: 1024,
            max_bindings_per_read: 64,
        },
    )
    .unwrap()
}

pub(super) const INSTALLATION: astral_types::memory_v1::MemoryId =
    astral_types::memory_v1::MemoryId::from_bytes([61; 16]);

pub(super) fn journal(dir: &Path) -> (MemoryV1DurableJournal, JournalDurability) {
    let (stream, epoch, anchor) = super::initial_history(INSTALLATION);
    use astral_single_node::memory_v1_durable_journal::{
        CheckpointInstallId, LocalCheckpointCoverage, LocalCheckpointStore,
    };
    let limits = DurableJournalLimits::conservative();
    let (journal, durability) = MemoryV1DurableJournal::create(
        &dir.join(super::JOURNAL_FILE_NAME),
        stream,
        epoch,
        anchor,
        limits,
    )
    .unwrap();
    let (store, _) = LocalCheckpointStore::bootstrap(
        &dir.join(super::CHECKPOINT_BASE),
        CheckpointInstallId::from_install_uuid(INSTALLATION.into_bytes()).unwrap(),
        stream,
        epoch,
        anchor,
        LocalCheckpointCoverage::from_anchor(anchor, 0),
        limits,
    )
    .unwrap();
    journal.attach_checkpoint(&durability, store).unwrap();
    (journal, durability)
}

pub(super) fn input(time: i64) -> ProductionEvidenceInput {
    let declared = ProvenFamily::proven_for;
    let mut input = ProductionEvidenceInput::default();
    input
        .with_source_provenance(declared(AdoptionLimit::SourceProvenance))
        .with_snapshot_identity(declared(AdoptionLimit::SnapshotIdentity))
        .with_lifecycle_and_validity(declared(AdoptionLimit::LifecycleAndValidity))
        .with_confirmation_authority(declared(AdoptionLimit::ConfirmationAuthority))
        .with_resource_ownership(declared(AdoptionLimit::ResourceOwnership))
        .with_eligibility(declared(AdoptionLimit::Eligibility))
        .with_separation_of_duties(declared(AdoptionLimit::SeparationOfDuties))
        .with_writer_coverage(declared(AdoptionLimit::WriterCoverage))
        .with_audit_correlation(declared(AdoptionLimit::AuditCorrelation))
        .with_persistence_recovery(declared(AdoptionLimit::PersistenceRecovery))
        .with_trusted_time(time);
    input
}
