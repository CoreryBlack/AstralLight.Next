//! memory—v1: the single-node governed-mutation durable commit owner.
//!
//! This owner is the only concrete [`MemoryV1GovernanceCommitPort`] in the
//! unified loopback service. It connects one admitted governance request to the
//! A/A1 local durable prefix:
//!
//! 1. value-level audit binding (`request.validate()`), which checks the
//!    complete T2 candidate against the operation, fingerprint, root
//!    observation, actor, target, tenant, trusted time and mutation summary;
//! 2. reserve the exact authorized root and prepare its successor, without
//!    modifying the serving snapshot or writing a journal record;
//! 3. allocate the journal identity, claim the operation and sync its record;
//! 4. publish that same prepared successor before releasing the reservation.
//!
//! An uncertain append or publication must be reconciled before any later
//! mutation or DENY proof. No repository fallback, automatic retry or
//! synchronous MySQL apply is part of this path.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use astral_authorization_root::memory_v1_root::{GovernanceFrontier, GovernancePrefix};
use astral_trustgraph::observability::{
    record_memory_v1_commit_phase, record_memory_v1_deny_phase, MemoryV1CommitPhase,
    MemoryV1DenyPhase,
};
use astral_trustgraph::service::memory_v1_governance_commit::{
    MemoryV1GovernanceCommitPort, MemoryV1GovernanceCommitRequest, MemoryV1GovernanceCommitResponse,
};
use astral_trustgraph::service::memory_v1_mutation_coordinator::{
    JournalCapacityReservation, JournalIdentity, MemoryV1OperationLedger, MutationRequest,
    UnknownReason,
};
use astral_types::memory_v1::MemoryId;
use astral_types::AstralError;
use std::time::Instant;
use uuid::Uuid;

use crate::memory_v1_durable_journal::{
    DurableJournalState, JournalAppendDisposition, JournalDurability, MemoryV1DurableJournal,
};
use crate::memory_v1_root_writer::RootMutationWriter;

/// The journal identity range assigned by this process at runtime.
///
/// Stream and epoch identifiers are fixed per owner instance; the journal and
/// mutation sequences follow the opened journal's anchor contiguously, and one
/// message ID is drawn per operation from a process-local counter.
struct JournalIdentityAllocator {
    stream_id: MemoryId,
    epoch_id: MemoryId,
    next_message: AtomicU64,
}

impl JournalIdentityAllocator {
    /// Bind the allocator to the journal's own stream and epoch. Sequence and
    /// identity allocation are only valid under the journal lock for this
    /// exact owner, so a foreign stream would fail the append anyway.
    fn for_journal(stream_id: MemoryId, epoch_id: MemoryId) -> Self {
        Self {
            stream_id,
            epoch_id,
            next_message: AtomicU64::new(1),
        }
    }

    /// Build the identity for the next contiguous append from the journal's
    /// observed position. Called only while the journal lock is held and the
    /// state is `Ready`, so no previously allocated identity can be skipped or
    /// reused.
    fn allocate(
        &self,
        journal_sequence: u64,
        mutation_sequence: u64,
    ) -> Result<JournalIdentity, AstralError> {
        let message = self.next_message.fetch_add(1, Ordering::AcqRel);
        let mut message_bytes = [0u8; 16];
        message_bytes[..8].copy_from_slice(&message.to_be_bytes());
        message_bytes[8..].copy_from_slice(&Uuid::new_v4().into_bytes()[..8]);
        JournalIdentity::new(
            self.stream_id,
            self.epoch_id,
            journal_sequence,
            mutation_sequence,
            MemoryId::from_bytes(message_bytes),
        )
        .map_err(|_| pending_error("journal identity allocation failed"))
    }

    /// Build the identity for the next DENY record. A DENY advances the
    /// journal sequence only; the mutation sequence stays at the observed
    /// value, including the zero baseline. Called only while the journal lock
    /// is held and state is `Ready`.
    fn allocate_deny(
        &self,
        journal_sequence: u64,
        mutation_sequence: u64,
    ) -> Result<JournalIdentity, AstralError> {
        let message = self.next_message.fetch_add(1, Ordering::AcqRel);
        let mut message_bytes = [0u8; 16];
        message_bytes[..8].copy_from_slice(&message.to_be_bytes());
        message_bytes[8..].copy_from_slice(&Uuid::new_v4().into_bytes()[..8]);
        JournalIdentity::new_deny(
            self.stream_id,
            self.epoch_id,
            journal_sequence,
            mutation_sequence,
            MemoryId::from_bytes(message_bytes),
        )
        .map_err(|_| pending_error("journal identity allocation failed"))
    }
}

/// The concrete fail-closed commit owner for the unified single-node path.
pub struct MemoryV1DurableCommitOwner {
    /// Serializes identity allocation and frame writes. Governed mutations
    /// retain this lock across sync; DENY requests release it before waiting.
    journal: Mutex<MemoryV1DurableJournal>,
    /// Shared durability coordinator; `ensure_durable` takes `&self` so
    /// concurrent waiters group-commit into one fdatasync.
    durability: JournalDurability,
    writer: RootMutationWriter,
    identities: JournalIdentityAllocator,
    ledger: Mutex<MemoryV1OperationLedger>,
    #[cfg(test)]
    before_append: Option<Box<dyn Fn() + Send + Sync>>,
}

impl std::fmt::Debug for MemoryV1DurableCommitOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MemoryV1DurableCommitOwner([REDACTED])")
    }
}

impl MemoryV1DurableCommitOwner {
    /// Assemble the owner around one opened journal and one validated root
    /// writer. The caller (composition/startup owner) is responsible for the
    /// recovery and production-adoption gate that produced both values.
    pub fn new(
        (journal, durability): (MemoryV1DurableJournal, JournalDurability),
        writer: RootMutationWriter,
    ) -> Self {
        let stream_id = journal.stream_id();
        let epoch_id = journal.epoch_id();
        Self {
            journal: Mutex::new(journal),
            durability,
            writer,
            identities: JournalIdentityAllocator::for_journal(stream_id, epoch_id),
            ledger: Mutex::new(
                MemoryV1OperationLedger::new(65_536).expect("owner ledger capacity is a constant"),
            ),
            #[cfg(test)]
            before_append: None,
        }
    }

    // memory—v1: Pause the real commit after preparation and before durable I/O.
    #[cfg(test)]
    pub(crate) fn set_before_append(&mut self, hook: impl Fn() + Send + Sync + 'static) {
        self.before_append = Some(Box::new(hook));
    }

    // memory—v1: Exclude startup syncs from the DENY proof load report.
    #[cfg(test)]
    pub(crate) fn journal_sync_calls(&self) -> u64 {
        self.durability.sync_calls()
    }
}

impl MemoryV1GovernanceCommitPort for MemoryV1DurableCommitOwner {
    fn commit(
        &self,
        request: MemoryV1GovernanceCommitRequest,
    ) -> Result<MemoryV1GovernanceCommitResponse, AstralError> {
        let commit_started = Instant::now();
        // 1. Value-level audit and request binding before any side effect.
        let binding_started = Instant::now();
        request.validate().map_err(|error| {
            pending_error(format!("governance request binding rejected: {error}"))
        })?;
        record_memory_v1_commit_phase(MemoryV1CommitPhase::Binding, binding_started.elapsed());

        let (admission, publication) = self
            .writer
            .prepare(&request.root, &request.mutation)
            .map_err(|error| {
                pending_error(format!("root mutation preparation refused: {error}"))
            })?;

        // Keep the journal prefix and the reserved root in the same order.
        // Readers never take the reservation or the journal lock for ALLOW.
        let Ok(mut journal) = self.journal.lock() else {
            publication.require_reconciliation();
            return Err(pending_error("journal owner is unavailable"));
        };
        if journal.state() != DurableJournalState::Ready || self.durability.is_failed() {
            publication.require_reconciliation();
            return Err(pending_error("journal owner requires reconciliation"));
        }
        if !frontier_matches_journal(publication.predecessor_frontier(), &journal) {
            publication.require_reconciliation();
            journal.require_reconciliation();
            return Err(pending_error(
                "journal prefix does not match the authorized root",
            ));
        }
        let journal_sequence = journal
            .position()
            .journal_sequence()
            .checked_add(1)
            .ok_or_else(|| pending_error("journal sequence exhausted"))?;
        let mutation_sequence = journal
            .last_mutation()
            .mutation_sequence()
            .checked_add(1)
            .ok_or_else(|| pending_error("mutation sequence exhausted"))?;
        let identity = self
            .identities
            .allocate(journal_sequence, mutation_sequence)?;
        let fingerprint = decode_fingerprint(&request.request_fingerprint)?;
        let coordinator_request = MutationRequest::try_new(
            &request.operation_id,
            fingerprint,
            request.mutation,
            request.audit,
            admission,
            identity,
        )
        .map_err(|error| pending_error(format!("coordinator request binding rejected: {error}")))?;
        let mut ledger = self
            .ledger
            .lock()
            .map_err(|_| pending_error("operation ledger is unavailable"))?;
        let claim = ledger.try_claim(&coordinator_request).map_err(|error| {
            pending_error(format!(
                "operation ledger refused the governance claim: {error:?}"
            ))
        })?;

        #[cfg(test)]
        if let Some(hook) = &self.before_append {
            hook();
        }
        let journal_io_started = Instant::now();
        let before_append = journal.position();
        let before_offset = journal.file_position();
        let receipt = journal
            .prepare_mutation(&coordinator_request, &self.durability)
            .and_then(|record| record.into_durable_receipt(&self.durability));
        record_memory_v1_commit_phase(MemoryV1CommitPhase::JournalIo, journal_io_started.elapsed());
        let receipt = receipt.map_err(|error| {
            if journal.position() != before_append
                || journal.file_position() != before_offset
                || journal.state() != DurableJournalState::Ready
                || self.durability.is_failed()
            {
                publication.require_reconciliation();
                journal.require_reconciliation();
                let _ = ledger.mark_unknown(&claim);
            }
            pending_error(format!(
                "durable journal append is unavailable or unknown: {error:?}"
            ))
        })?;
        if receipt.disposition() != JournalAppendDisposition::Appended
            || receipt.identity() != identity
            || receipt.tail_hash() != journal.position().frame_hash()
            || receipt.start_offset() != before_offset
            || receipt.end_offset() != journal.file_position()
            || receipt.operation_id() != coordinator_request.operation_id()
            || receipt.request_fingerprint() != coordinator_request.request_fingerprint()
            || receipt.mutation_digest() != coordinator_request.mutation_digest()
            || receipt.audit_digest() != coordinator_request.audit_digest()
        {
            publication.require_reconciliation();
            journal.require_reconciliation();
            let _ = ledger.mark_unknown(&claim);
            return Err(pending_error(
                "durable journal replay requires reconciliation",
            ));
        }

        let cas_started = Instant::now();
        let after = GovernancePrefix::new(journal.last_mutation(), journal.epoch_id())
            .ok_or("invalid journal boundary")
            .and_then(|prefix| {
                publication
                    .publish_with_prefix(prefix)
                    .map_err(|_| "root CAS refused")
            })
            .map_err(|error| {
                publication.require_reconciliation();
                journal.require_reconciliation();
                let _ = ledger.mark_unknown(&claim);
                pending_error(format!(
                    "durable mutation requires root reconciliation: {error}"
                ))
            })?;
        record_memory_v1_commit_phase(MemoryV1CommitPhase::RootCas, cas_started.elapsed());

        record_memory_v1_commit_phase(MemoryV1CommitPhase::Total, commit_started.elapsed());
        Ok(MemoryV1GovernanceCommitResponse {
            operation_id: request.operation_id.clone(),
            root: after,
        })
    }
}

// memory—v1: A DENY-only tail may be ahead of this exact mutation boundary.
fn frontier_matches_journal(
    frontier: GovernanceFrontier,
    journal: &MemoryV1DurableJournal,
) -> bool {
    let boundary = journal.last_mutation();
    match frontier {
        GovernanceFrontier::Baseline => {
            boundary.journal_sequence() == 0 && boundary.mutation_sequence() == 0
        }
        GovernanceFrontier::Published(prefix) => {
            prefix.anchor() == boundary && prefix.epoch() == journal.epoch_id()
        }
        GovernanceFrontier::Unproven => false,
    }
}

fn decode_fingerprint(value: &str) -> Result<[u8; 32], AstralError> {
    let bytes = hex::decode(value).map_err(|_| pending_error("request fingerprint is invalid"))?;
    <[u8; 32]>::try_from(bytes).map_err(|_| pending_error("request fingerprint is invalid"))
}

// memory—v1: One PENDING error with a fixed reason; the response adapter maps
// it to 503 with `Retry-After: 3` and the refusal marker.
fn pending_error(reason: impl std::fmt::Display) -> AstralError {
    AstralError::Pending(reason.to_string())
}

// memory—v1: Unknown reasons are retained for the reconciliation owner; the
// commit path maps them to PENDING and never retries automatically.
#[allow(dead_code)]
fn unknown_reason_for(
    phase: astral_trustgraph::service::memory_v1_mutation_coordinator::OperationStatus,
) -> UnknownReason {
    match phase {
        astral_trustgraph::service::memory_v1_mutation_coordinator::OperationStatus::Claimed
        | astral_trustgraph::service::memory_v1_mutation_coordinator::OperationStatus::JournalPrepared => {
            UnknownReason::JournalWrite
        }
        astral_trustgraph::service::memory_v1_mutation_coordinator::OperationStatus::JournalDurable => {
            UnknownReason::RootPublication
        }
        _ => UnknownReason::RecoveryBoundary,
    }
}

// memory—v1: Reserved proof types retained for the reconciliation owner.
#[allow(dead_code)]
type ReservedReservation = JournalCapacityReservation;

/// The unified owner is also the only DENY proof issuer: one evaluator
/// observation becomes one DENY frame under the same append lock as mutations.
/// The lock is released before waiting for durability so independent DENYs
/// can share a sync. Both proofs still come from the frame's own durable
/// receipt; anything else remains a fail-closed 503.
impl astral_trustgraph::service::memory_v1_governance_commit::MemoryV1DenyProofPort
    for MemoryV1DurableCommitOwner
{
    fn prove_deny(
        &self,
        observation: astral_types::memory_v1_deny_observation::MemoryV1DenyObservation,
    ) -> Result<astral_trustgraph::service::memory_v1_mutation_coordinator::DenyResponse, AstralError>
    {
        use astral_trustgraph::service::memory_v1_mutation_coordinator::{
            AuthorizationStatePrefixProof, DenyAuditProof, DenyJournalRequest, DenyProofGate,
            DenyProofRequest, DenyResponse, JournalReadWatermark, RootBinding,
        };
        let deny_total_started = Instant::now();
        let Ok(mut journal) = self.journal.lock() else {
            return Ok(DenyResponse::ServiceUnavailable);
        };
        if journal.state() != DurableJournalState::Ready || self.durability.is_failed() {
            return Ok(DenyResponse::ServiceUnavailable);
        }
        let observed = observation.root();
        let metadata = {
            use astral_authorization_root::memory_v1_root::{
                RootInstanceId, RootMetadata, RootStatus,
            };
            if observed.status() != astral_types::memory_v1_audit::MemoryV1AuditRootStatus::Serving
            {
                return Ok(DenyResponse::ServiceUnavailable);
            }
            RootMetadata {
                instance_id: RootInstanceId::from_uuid(uuid::Uuid::from_bytes(
                    *observed.instance().as_bytes(),
                )),
                version: observed.version(),
                digest: *observed.digest(),
                budget: astral_authorization_root::memory_v1_hamt::CandidateBudget {
                    max_table_rows: usize::try_from(observed.budget().max_table_rows())
                        .unwrap_or(0),
                    max_bindings_per_read: usize::try_from(
                        observed.budget().max_bindings_per_read(),
                    )
                    .unwrap_or(0),
                },
                row_count: usize::try_from(observed.row_count()).unwrap_or(0),
                status: RootStatus::Serving,
            }
        };
        let Ok(frontier) = self.writer.deny_frontier(&metadata) else {
            return Ok(DenyResponse::ServiceUnavailable);
        };
        if !frontier_matches_journal(frontier, &journal) {
            return Ok(DenyResponse::ServiceUnavailable);
        }
        let boundary = journal.last_mutation();
        let watermark = JournalReadWatermark::new_deny(
            journal.stream_id(),
            journal.epoch_id(),
            boundary.journal_sequence(),
            boundary.mutation_sequence(),
        )
        .map_err(|error| pending_error(format!("deny watermark rejected: {error}")))?;
        let sequence = journal
            .position()
            .journal_sequence()
            .checked_add(1)
            .ok_or_else(|| pending_error("journal sequence exhausted"))?;
        let identity = self
            .identities
            .allocate_deny(sequence, watermark.mutation_sequence())?;
        let request = DenyJournalRequest::try_new(observation, identity)
            .map_err(|error| pending_error(format!("deny request binding rejected: {error}")))?;
        let root = RootBinding::from_metadata(metadata);
        let fingerprint = request.request_fingerprint();

        let deny_io_started = Instant::now();
        let prepared = journal
            .prepare_deny(&request, &self.durability)
            .map_err(|error| pending_error(format!("durable deny append failed: {error:?}")))?;
        drop(journal);
        let receipt = prepared
            .into_durable_receipt(&self.durability)
            .map_err(|error| pending_error(format!("durable deny append failed: {error:?}")))?;
        record_memory_v1_deny_phase(MemoryV1DenyPhase::JournalIo, deny_io_started.elapsed());
        // Both an original append and an idempotent replay prove the same
        // durable record; the receipt carries the recorded identity and tail.
        if receipt.operation_id() != request.operation_id()
            || *receipt.request_fingerprint() != fingerprint
            || receipt.audit_digest() != request.audit_digest()
            || receipt.identity().mutation_sequence() != watermark.mutation_sequence()
        {
            return Ok(DenyResponse::ServiceUnavailable);
        }

        let proof_request = DenyProofRequest::try_new(
            request.operation_id(),
            fingerprint,
            // The gate needs a VerifiedRootAdmission; mint it for this owner:
            // the root observation was captured by the evaluator and bound into
            // the durable record.
            {
                astral_trustgraph::service::memory_v1_mutation_coordinator::VerifiedRootAdmission::mint_from_production_owner(root)
            },
            watermark,
            request.observation().source(),
        )
        .map_err(|error| pending_error(format!("deny proof request rejected: {error}")))?;
        let mut gate = DenyProofGate::new(proof_request);
        gate.record_audit(DenyAuditProof::mint_for_owner(
            request.operation_id(),
            fingerprint,
            root,
            request.observation().source(),
            request.audit_digest(),
        ))
        .map_err(|error| pending_error(format!("deny audit proof rejected: {error}")))?;
        gate.record_prefix(AuthorizationStatePrefixProof::mint_for_owner(
            request.operation_id(),
            fingerprint,
            root,
            receipt.identity(),
            *receipt.tail_hash(),
        ))
        .map_err(|error| pending_error(format!("deny prefix proof rejected: {error}")))?;
        record_memory_v1_deny_phase(MemoryV1DenyPhase::Total, deny_total_started.elapsed());
        Ok(gate.response())
    }
}
