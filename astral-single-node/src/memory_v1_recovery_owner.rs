//! memory—v1: Ordered replay into a candidate root. This checks journal values
//! and root transitions, not MySQL application, audit receipts or progress.
//! Normal startup cannot use it instead of reconciling the database before
//! cold capture (§15.10.4). Only the adoption gate may publish Serving.

mod applied_history;
pub use applied_history::verify_applied_history;

use std::sync::Arc;

use astral_authorization_root::memory_v1_adoption::ColdLoadFacts;
use astral_authorization_root::memory_v1_root::{
    GovernanceFrontier, GovernancePrefix, ManagementMutationV2, MutationPrecondition,
    ProductionAdmission, RootOwner, RootStatus,
};
use astral_trustgraph::service::memory_v1_mutation_coordinator::{
    decode_deny_journal_payload, decode_journal_payload, MutationAuditCandidate,
};
use astral_types::memory_v1_journal::{JournalAnchor, RecordKind};
use thiserror::Error;

use crate::memory_v1_durable_journal::MemoryV1DurableJournal;

/// Recovery failures; every variant stops the start before any listener.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RecoveryError {
    #[error("recovery journal replay is unavailable or unknown")]
    ReplayUnknown,
    #[error("recovery journal mutation does not match the candidate state")]
    ReplayConflict,
    #[error("recovery journal mutation sequence has a gap")]
    SequenceGap,
    #[error("recovery journal deny record is invalid")]
    InvalidDenyRecord,
    #[error("recovery adoption was refused")]
    AdoptionRefused,
}

/// The outcome of a completed recovery: the adopted serving root and the
/// production admission minted from its winning CAS.
pub struct RecoveredRoot {
    pub owner: Arc<RootOwner>,
    pub admission: Arc<ProductionAdmission>,
    /// Journal mutation records replayed on top of the captured snapshot.
    pub replayed_mutations: u64,
    /// Journal deny records observed (skipped; already durable audit values).
    pub observed_denies: u64,
}

impl std::fmt::Debug for RecoveredRoot {
    // memory—v1
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveredRoot")
            .field("owner", &"[REDACTED]")
            .field("admission", &"[REDACTED]")
            .field("replayed_mutations", &self.replayed_mutations)
            .field("observed_denies", &self.observed_denies)
            .finish()
    }
}

/// Replay every journaled mutation onto the candidate and adopt the result.
///
/// `owner` holds the pristine Candidate from the cold capture. Replay follows
/// the verified governance sequence, not the old process's snapshot versions.
/// A context load is not replay input: any required fact must already exist in
/// the capture or be established by an earlier governance record.
pub fn recover_root(
    owner: RootOwner,
    journal: &MemoryV1DurableJournal,
    facts: &ColdLoadFacts,
    sealed_input: &astral_authorization_root::memory_v1_adoption::ProductionEvidenceInput,
) -> Result<RecoveredRoot, RecoveryError> {
    let initial = owner
        .handle()
        .metadata()
        .map_err(|_| RecoveryError::ReplayUnknown)?;
    if initial.status != RootStatus::Candidate
        || initial.version != 0
        || owner.candidate_governance_frontier() != Ok(GovernanceFrontier::Baseline)
    {
        return Err(RecoveryError::ReplayConflict);
    }
    let mut replayed_mutations = 0_u64;
    let mut observed_denies = 0_u64;

    for record in journal.recovery_records() {
        match record.kind {
            RecordKind::Mutation => {
                let expected = replayed_mutations
                    .checked_add(1)
                    .ok_or(RecoveryError::SequenceGap)?;
                if record.mutation_sequence != expected {
                    return Err(RecoveryError::SequenceGap);
                }
                let anchor = JournalAnchor::new(
                    journal.stream_id(),
                    record.journal_sequence,
                    expected,
                    record.frame_hash,
                )
                .map_err(|_| RecoveryError::ReplayConflict)?;
                let prefix = GovernancePrefix::new(anchor, journal.epoch_id())
                    .ok_or(RecoveryError::ReplayConflict)?;
                let decoded = decode_journal_payload(&record.payload)
                    .map_err(|_| RecoveryError::ReplayConflict)?;
                let mutation: &ManagementMutationV2 = decoded.mutation();
                let metadata = owner
                    .handle()
                    .metadata()
                    .map_err(|_| RecoveryError::ReplayUnknown)?;
                owner
                    .execute_recovery_mutation_with_prefix(
                        mutation,
                        &MutationPrecondition {
                            evaluated_root_version: metadata.version,
                        },
                        prefix,
                    )
                    .map_err(|_| RecoveryError::ReplayConflict)?;
                replayed_mutations = expected;
            }
            RecordKind::Deny => {
                decode_deny_journal_payload(&record.payload)
                    .map_err(|_| RecoveryError::InvalidDenyRecord)?;
                observed_denies += 1;
            }
        }
    }
    let boundary = journal.last_mutation();
    let expected_frontier = if replayed_mutations == 0 {
        GovernanceFrontier::Baseline
    } else {
        GovernanceFrontier::Published(
            GovernancePrefix::new(boundary, journal.epoch_id())
                .ok_or(RecoveryError::ReplayConflict)?,
        )
    };
    if replayed_mutations != boundary.mutation_sequence()
        || journal.position().mutation_sequence() != boundary.mutation_sequence()
        || owner.candidate_governance_frontier() != Ok(expected_frontier)
    {
        return Err(RecoveryError::SequenceGap);
    }
    let input = sealed_input;
    let (metadata, admission) = owner
        .adopt_with_production_evidence(facts, input)
        .map_err(|_| RecoveryError::AdoptionRefused)?;
    if metadata.status != RootStatus::Serving {
        return Err(RecoveryError::AdoptionRefused);
    }
    Ok(RecoveredRoot {
        owner: Arc::new(owner),
        admission: Arc::new(admission),
        replayed_mutations,
        observed_denies,
    })
}

// memory—v1: The audit candidate recovered from one journal record is a value
// re-derived by the coordinator's decoder; it is retained for the apply owner
// that later reconciles MySQL. The type keeps the binding explicit.
#[allow(dead_code)]
fn recovered_audit_of(
    record: &astral_trustgraph::service::memory_v1_mutation_coordinator::DecodedJournalPayload,
) -> &MutationAuditCandidate {
    record.audit()
}
