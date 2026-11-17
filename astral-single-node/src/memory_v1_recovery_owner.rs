//! memory—v1: the crash-recovery owner of the unified single-node path.
//!
//! Recovery runs before adoption and before any listener exists. The order is
//! the A/A1 contract:
//!
//! 1. the durable journal is opened and fully chain-verified (the caller owns
//!    the open); the journal's own record sequence is the authoritative order;
//! 2. the captured MySQL candidate is installed as a Candidate root;
//! 3. every journaled mutation is replayed in order against that candidate
//!    through the root's controlled recovery path. A replay failure, a
//!    sequence gap, or any uncertain result stops recovery and the process
//!    refuses to serve — there is no partial-start and no automatic retry;
//! 4. DENY records are skipped here: their audit value is already durable and
//!    they carry no state change;
//! 5. after replay the root is adopted at the production grade with the same
//!    sealed startup bundle as a fresh start; the adoption's structural gate
//!    revalidates the full replayed state.
//!
//! The database apply direction stays one-way: MySQL is the cold-start
//! source, and journaled in-memory changes are backed up asynchronously. A
//! replayed change is therefore applied to the root only; reconciling MySQL
//! rows against the replayed state is the apply owner's later task and this
//! module never writes to the database.

use std::sync::Arc;

use astral_authorization_root::memory_v1_adoption::ColdLoadFacts;
use astral_authorization_root::memory_v1_root::{
    ManagementMutationV2, MutationPrecondition, ProductionAdmission, RootOwner, RootStatus,
};
use astral_trustgraph::service::memory_v1_mutation_coordinator::{
    decode_deny_journal_payload, decode_journal_payload, MutationAuditCandidate,
};
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
/// `owner` holds the Candidate root installed from the captured MySQL rows.
/// The journal mutation sequence must continue from the candidate's root
/// version: record N carries the mutation that advances the root to version
/// `base + N`, so a gap or a conflicting candidate is refused outright.
pub fn recover_root(
    owner: RootOwner,
    journal: &MemoryV1DurableJournal,
    facts: &ColdLoadFacts,
    sealed_input: &astral_authorization_root::memory_v1_adoption::ProductionEvidenceInput,
) -> Result<RecoveredRoot, RecoveryError> {
    let mut replayed_mutations = 0_u64;
    let mut observed_denies = 0_u64;
    // The mutation sequence the replay expects next: each journaled Mutation
    // record carries its own new sequence starting at 1, so recovery expects
    // 1, 2, ... in append order regardless of how many the journal holds.
    let mut expected_mutation_sequence = 0_u64;

    for record in journal.recovery_records() {
        match record.kind {
            astral_types::memory_v1_journal::RecordKind::Mutation => {
                // The record's mutation sequence must continue the observed
                // baseline; a gap means the candidate does not correspond to
                // this journal.
                expected_mutation_sequence = expected_mutation_sequence
                    .checked_add(1)
                    .ok_or(RecoveryError::SequenceGap)?;
                if record.mutation_sequence != expected_mutation_sequence {
                    return Err(RecoveryError::SequenceGap);
                }
                let metadata = owner
                    .handle()
                    .metadata()
                    .map_err(|_| RecoveryError::ReplayUnknown)?;
                if metadata.status != RootStatus::Candidate {
                    return Err(RecoveryError::ReplayConflict);
                }
                // The journal's mutation sequence and the candidate root's
                // version advance together: record N (mutation sequence N)
                // applies to root version N-1. A candidate that has already
                // advanced past the record is a double-apply conflict.
                if metadata.version != record.mutation_sequence - 1 {
                    return Err(RecoveryError::ReplayConflict);
                }
                let decoded = decode_journal_payload(&record.payload)
                    .map_err(|_| RecoveryError::ReplayConflict)?;
                let mutation: ManagementMutationV2 = decoded.mutation().clone();
                let precondition = MutationPrecondition {
                    evaluated_root_version: metadata.version,
                };
                owner
                    .execute_recovery_mutation(&mutation, &precondition)
                    .map_err(|_| RecoveryError::ReplayConflict)?;
                replayed_mutations += 1;
            }
            astral_types::memory_v1_journal::RecordKind::Deny => {
                // The deny value must decode; anything else is corruption.
                decode_deny_journal_payload(&record.payload)
                    .map_err(|_| RecoveryError::InvalidDenyRecord)?;
                observed_denies += 1;
            }
        }
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
