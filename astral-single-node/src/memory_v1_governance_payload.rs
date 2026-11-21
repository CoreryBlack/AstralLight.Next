//! memory—v1: the complete immutable journal payload of one governed mutation.
//!
//! The reservation is formed entirely in memory while the journal lock is
//! held, before the operation claim and before the publication CAS. The
//! journal's own read-only admission probe (`probe_mutation`) reuses the
//! bounded operations index and runs exactly the checks of the write path —
//! coordinator payload binding, recorded identity, sequence identity and
//! capacity measured on the exact encoded bytes — with no write, no
//! durability effect and no state change. The reservation then fixes the
//! canonical frame bytes, their chain digest, the file offset span and the
//! identity of the record in a [`ReservedGovernanceRecord`]; nothing about
//! it can change afterwards, because the journal position cannot move while
//! the lock is held.
//!
//! The commit owner publishes the authorization facts, the governance
//! position and this reservation under one CAS: the complete frame rides in
//! the published snapshot's `reservation` field and is retrieved from that
//! snapshot after the CAS. The owner then appends exactly the published
//! frame bytes — not a re-encoding of the request — verifies the written
//! record against the reservation, and confirms the local durable prefix
//! from the record's own receipt. No byte is written or flushed before its
//! facts are published, and a flushed byte always belongs to a published
//! record.

use std::sync::Arc;

use astral_authorization_root::memory_v1_root::ReservedGovernanceRecord;
use astral_trustgraph::service::memory_v1_mutation_coordinator::{
    JournalIdentity, MutationRequest,
};
use astral_types::memory_v1_journal::{decode_record, encode_record, JournalRecord, RecordKind};

use crate::memory_v1_durable_journal::{
    JournalAppendDisposition, MemoryV1DurableJournal, PreparedAppend,
};

/// The exact journal record one governed mutation will publish, fixed in
/// memory before the publication CAS.
#[derive(Clone, Debug)]
pub(crate) struct ReservedGovernancePayload {
    identity: JournalIdentity,
    /// The root-owned value attached to the published snapshot's governance
    /// prefix and retrieved from it after the CAS.
    record: ReservedGovernanceRecord,
}

impl ReservedGovernancePayload {
    /// Reserve the exact record for `request` at the journal's observed
    /// position. Called only while the journal lock is held and the journal
    /// is ready, so the reserved offset cannot move before the write.
    ///
    /// The admission probe performs no I/O and mutates nothing; the frame is
    /// then encoded and decoded in memory from the immutable request envelope
    /// and the journal's observed chain tail, and every field is cross-checked
    /// against the request. This is a reservation of in-memory state only: it
    /// proves nothing about the device.
    pub(crate) fn reserve(
        journal: &MemoryV1DurableJournal,
        request: &MutationRequest,
        durability: &crate::memory_v1_durable_journal::JournalDurability,
    ) -> Result<Self, crate::memory_v1_durable_journal::DurableJournalError> {
        journal.probe_mutation(request, durability)?;
        let payload = request
            .journal_payload()
            .map_err(|_| crate::memory_v1_durable_journal::DurableJournalError::InvalidRecord)?;
        let identity = request.journal();
        let frame = encode_record(&JournalRecord {
            stream_id: identity.stream_id(),
            epoch_id: identity.epoch_id(),
            journal_sequence: identity.journal_sequence(),
            message_id: identity.message_id(),
            operation_id: request.operation_id(),
            request_fingerprint: *request.request_fingerprint(),
            kind: RecordKind::Mutation,
            mutation_sequence: identity.mutation_sequence(),
            prev_hash: *journal.position().frame_hash(),
            payload: &payload,
        })
        .map_err(crate::memory_v1_durable_journal::DurableJournalError::Frame)?;
        let decoded = decode_record(&frame)
            .map_err(crate::memory_v1_durable_journal::DurableJournalError::Frame)?;
        // The reserved frame must describe exactly this request; the journal
        // re-checks the same bindings when it writes the record.
        if decoded.record.stream_id != identity.stream_id()
            || decoded.record.epoch_id != identity.epoch_id()
            || decoded.record.journal_sequence != identity.journal_sequence()
            || decoded.record.message_id != identity.message_id()
            || decoded.record.mutation_sequence != identity.mutation_sequence()
            || decoded.record.operation_id != request.operation_id()
            || decoded.record.request_fingerprint != *request.request_fingerprint()
            || decoded.record.kind != RecordKind::Mutation
            || decoded.record.payload != payload.as_slice()
        {
            return Err(crate::memory_v1_durable_journal::DurableJournalError::InvalidRecord);
        }
        let start_offset = journal.file_position();
        let record = ReservedGovernanceRecord::new(
            identity.stream_id(),
            identity.epoch_id(),
            identity.journal_sequence(),
            identity.mutation_sequence(),
            identity.message_id(),
            start_offset,
            decoded.digest,
            Arc::from(frame),
        )
        .ok_or(crate::memory_v1_durable_journal::DurableJournalError::InvalidRecord)?;
        Ok(Self { identity, record })
    }

    /// The root-owned record value attached to the published snapshot.
    pub(crate) fn record(&self) -> ReservedGovernanceRecord {
        self.record.clone()
    }

    /// Whether the journal's written record is exactly the reserved payload:
    /// appended at the reserved position with the reserved identity, chain
    /// digest and length. A mismatch is an invariant violation; the commit
    /// owner must reconcile instead of writing a second record.
    pub(crate) fn matches_written(&self, prepared: &PreparedAppend) -> bool {
        prepared.disposition == JournalAppendDisposition::Appended
            && prepared.identity == self.identity
            && prepared.tail_hash == self.record.tail_hash()
            && prepared.start_offset == self.record.start_offset()
            && prepared.durable_end == self.record.end_offset()
    }
}
