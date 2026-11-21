//! memory—v1: the single-node governed-mutation durable commit owner.
//!
//! This owner is the only concrete [`MemoryV1GovernanceCommitPort`] in the
//! unified loopback service. It connects one admitted governance request to the
//! A/A1 local durable prefix:
//!
//! 1. value-level audit binding (`request.validate()`), which checks the
//!    complete T2 candidate against the operation, fingerprint, root
//!    observation, actor, target, tenant, trusted time and mutation summary;
//! 2. reserve the exact authorized root and prepare its successor, and
//!    reserve the complete immutable journal payload in memory — the
//!    journal's read-only admission probe reuses its bounded operations
//!    index and runs exactly the write-path checks, then the canonical
//!    frame bytes, chain digest and offset span are fixed. Nothing is
//!    written and nothing is published yet;
//! 3. publish the authorization facts, the governance position and the
//!    reserved record under one CAS: the record rides inside the published
//!    snapshot's governance prefix and is taken from that snapshot after the
//!    CAS. The journal is not written before the publication;
//! 4. write exactly the published reservation, verify it byte-for-byte
//!    against the reservation, flush it, and confirm the contiguous durable
//!    prefix through this record before the success response.
//!
//! No byte is written or flushed before its facts are published, and a
//! flushed byte always belongs to a published record: a refusal before the
//! CAS leaves no record anywhere, and every failure after the publication
//! leaves the published facts unverifiable against the durable prefix, so
//! both owners require reconciliation before any later mutation or DENY
//! proof. No repository fallback, automatic retry or synchronous MySQL apply
//! is part of this path.
//!
//! A recorded operation identity is never written twice: the reservation
//! probe refuses identity conflicts before the publication, for retained
//! records and same-boot records of either kind alike. The commit owner
//! reports that refusal with one fixed, non-leaking PENDING reason; uncertain
//! I/O still requires reconciliation.
//!
//! The DENY proof issuer shares the same journal lock discipline: the commit
//! holds the lock from the reservation through the write and its flush, so a
//! DENY can never observe a published governance position whose record is
//! not yet durable, and cannot disguise a new in-memory prefix as durable.

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
use astral_types::memory_v1_journal::JournalAnchor;
use astral_types::AstralError;
use std::time::{Duration, Instant};
use uuid::Uuid;

use crate::memory_v1_durable_journal::{
    DurableJournalError, DurableJournalState, JournalAppendDisposition, JournalDurability,
    MemoryV1DurableJournal,
};
use crate::memory_v1_governance_payload::ReservedGovernancePayload;
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

struct JournalLockTiming {
    waiting: Duration,
    acquired: Instant,
}

impl Drop for JournalLockTiming {
    // memory—v1: Measure first, then update the recorder after the guard drops.
    fn drop(&mut self) {
        let held = self.acquired.elapsed();
        record_memory_v1_commit_phase(MemoryV1CommitPhase::JournalLockHeld, held);
        record_memory_v1_commit_phase(MemoryV1CommitPhase::JournalLockWait, self.waiting);
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

        let writer_started = Instant::now();
        let prepared = self.writer.prepare(&request.root, &request.mutation);
        record_memory_v1_commit_phase(MemoryV1CommitPhase::Prepare, writer_started.elapsed());
        let (admission, publication) = prepared.map_err(|error| {
            pending_error(format!("root mutation preparation refused: {error}"))
        })?;

        // The journal lock pins the position from the reservation through the
        // post-publication write: the reserved record occupies exactly the
        // offset observed here, and no reader takes this lock for ALLOW.
        let _journal_timing;
        let journal_wait = Instant::now();
        let locked = self.journal.lock();
        let acquired = Instant::now();
        let Ok(mut journal) = locked else {
            publication.require_reconciliation();
            return Err(pending_error("journal owner is unavailable"));
        };
        // Declared before the guard so metrics dispatch does not extend its hold.
        _journal_timing = JournalLockTiming {
            waiting: acquired.duration_since(journal_wait),
            acquired,
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

        // 2. Reserve the complete immutable journal payload in memory. The
        //    journal's read-only admission probe reuses its bounded operations
        //    index and runs exactly the write-path checks; the canonical frame
        //    bytes, their chain digest and the offset span are fixed here.
        //    Nothing is written and nothing is published yet.
        let reserved =
            ReservedGovernancePayload::reserve(&journal, &coordinator_request, &self.durability)
                .map_err(reservation_refusal_reason)?;

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

        // 3. Publish the authorization facts, the governance position and the
        //    reserved record under one CAS. The journal is not written here:
        //    the reserved frame and its offset are pinned by this lock, so the
        //    write after this publication can only materialize exactly the
        //    published reservation.
        let cas_started = Instant::now();
        let prefix = GovernancePrefix::new(journal_boundary(&reserved), journal.epoch_id())
            .ok_or_else(|| pending_error("reserved governance anchor is invalid"))?;
        let published = publication
            .publish_with_reserved_record(prefix, reserved.record())
            .map_err(|error| {
                // Refused before the journal was touched: nothing was
                // published and no byte exists to flush. Both owners are
                // reconciled because their correspondence can no longer be
                // trusted.
                publication.require_reconciliation();
                journal.require_reconciliation();
                let _ = ledger.mark_unknown(&claim);
                pending_error(format!("governance publication was refused: {error:?}"))
            })?;
        record_memory_v1_commit_phase(MemoryV1CommitPhase::RootCas, cas_started.elapsed());

        // 4. Take the reserved record from the published snapshot itself, so
        //    the record written below is the one the published state claims.
        let reserved_record = match self.writer.published_record(&published) {
            Ok(Some(record)) => record,
            Ok(None) => {
                publication.require_reconciliation();
                journal.require_reconciliation();
                let _ = ledger.mark_unknown(&claim);
                return Err(pending_error(
                    "the published snapshot carries no reserved record; reconciliation required",
                ));
            }
            Err(error) => {
                publication.require_reconciliation();
                journal.require_reconciliation();
                let _ = ledger.mark_unknown(&claim);
                return Err(pending_error(format!(
                    "the published governance record is not retrievable: {error:?}"
                )));
            }
        };

        // 5. Append exactly the frame bytes held by the published record —
        //    not a re-encoding of the request — and verify the written
        //    record against the reservation. A refusal here leaves the
        //    published facts unverifiable against the durable prefix, so
        //    both owners require reconciliation before any later mutation
        //    or DENY proof.
        let journal_io_started = Instant::now();
        let prepared =
            match journal.prepare_reserved_frame(reserved_record.frame(), &self.durability) {
                Ok(prepared) if reserved.matches_written(&prepared) => prepared,
                Ok(_) => {
                    publication.require_reconciliation();
                    journal.require_reconciliation();
                    let _ = ledger.mark_unknown(&claim);
                    return Err(pending_error(
                        "the written journal record does not match the published reservation; \
                     reconciliation required",
                    ));
                }
                Err(error) => {
                    publication.require_reconciliation();
                    journal.require_reconciliation();
                    let _ = ledger.mark_unknown(&claim);
                    return Err(pending_error(format!(
                        "the published reservation could not be written to the durable journal: \
                     {error:?}"
                    )));
                }
            };

        // 6. Flush only this published record and confirm the contiguous
        //    durable prefix through it from the record's own receipt.
        let durability_started = Instant::now();
        let receipt = prepared.into_durable_receipt(&self.durability);
        record_memory_v1_commit_phase(
            MemoryV1CommitPhase::JournalDurability,
            durability_started.elapsed(),
        );
        let _confirmed = match receipt {
            Ok(receipt)
                if receipt.disposition() == JournalAppendDisposition::Appended
                    && receipt.identity().stream_id() == reserved_record.stream_id()
                    && receipt.identity().epoch_id() == reserved_record.epoch_id()
                    && receipt.identity().journal_sequence()
                        == reserved_record.journal_sequence()
                    && receipt.identity().mutation_sequence()
                        == reserved_record.mutation_sequence()
                    && receipt.identity().message_id() == reserved_record.message_id()
                    && *receipt.tail_hash() == reserved_record.tail_hash()
                    && receipt.start_offset() == reserved_record.start_offset()
                    && receipt.end_offset() == reserved_record.end_offset()
                    && receipt.end_offset() == journal.file_position()
                    && receipt.operation_id() == coordinator_request.operation_id()
                    && receipt.request_fingerprint()
                        == coordinator_request.request_fingerprint()
                    && receipt.mutation_digest() == coordinator_request.mutation_digest()
                    && receipt.audit_digest() == coordinator_request.audit_digest() =>
            {
                receipt
            }
            Ok(_) => {
                publication.require_reconciliation();
                journal.require_reconciliation();
                let _ = ledger.mark_unknown(&claim);
                return Err(pending_error(
                    "durable journal replay requires reconciliation",
                ));
            }
            Err(error) => {
                publication.require_reconciliation();
                journal.require_reconciliation();
                let _ = ledger.mark_unknown(&claim);
                return Err(pending_error(format!(
                    "the durable prefix confirmation failed after publication: {error:?}"
                )));
            }
        };
        record_memory_v1_commit_phase(MemoryV1CommitPhase::JournalIo, journal_io_started.elapsed());

        record_memory_v1_commit_phase(MemoryV1CommitPhase::Total, commit_started.elapsed());
        Ok(MemoryV1GovernanceCommitResponse {
            operation_id: request.operation_id.clone(),
            root: published,
        })
    }
}

// memory—v1: The governance position of one reserved record: the anchor of
// its own journal frame, which the published snapshot claims as its boundary.
fn journal_boundary(reserved: &ReservedGovernancePayload) -> JournalAnchor {
    let record = reserved.record();
    // The record was constructed from a decoded canonical frame, so every
    // field is valid; the constructor cannot fail here.
    JournalAnchor::new(
        record.stream_id(),
        record.journal_sequence(),
        record.mutation_sequence(),
        record.tail_hash(),
    )
    .expect("reserved record fields are validated at construction")
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

// memory—v1: The reservation refusal happens before anything is written or
// published, so every variant is a definite refusal with the journal
// position, offsets and state unchanged. A recorded operation identity is
// reported with one fixed, non-leaking reason: it does not echo the ID,
// claim when or by which record kind it was retained, or assert any outcome;
// it states only that the retained journal already uses the identity, this
// request wrote nothing, and the recorded result requires reconciliation.
fn reservation_refusal_reason(error: DurableJournalError) -> AstralError {
    if matches!(
        error,
        DurableJournalError::ExistingOperation | DurableJournalError::OperationConflict
    ) {
        return pending_error(OPERATION_IDENTITY_RECORDED_REASON);
    }
    match error {
        DurableJournalError::CapacityExceeded => pending_error(
            "durable journal capacity is exhausted before the publication (CapacityExceeded)",
        ),
        DurableJournalError::StickyUnknown | DurableJournalError::UnknownAfterIo => {
            pending_error("durable journal owner requires reconciliation before the reservation")
        }
        other => pending_error(format!(
            "the reserved journal payload was refused before the publication: {other:?}"
        )),
    }
}

// memory—v1: Fixed, non-leaking PENDING reason for a recorded operation
// identity: it does not echo the ID, claim when or by which record kind it
// was retained, or assert any outcome; it states only that the retained
// journal already uses the identity, this request wrote nothing, and the
// recorded result requires reconciliation.
const OPERATION_IDENTITY_RECORDED_REASON: &str = "governance operation identity is already \
     recorded in the retained durable journal; no record was written for this request and the \
     recorded result requires reconciliation";

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
