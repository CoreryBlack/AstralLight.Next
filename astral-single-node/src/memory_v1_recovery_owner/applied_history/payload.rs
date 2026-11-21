//! memory—v1: Bind decoded audit values to the producer recorded by the journal scan.

use anyhow::{bail, ensure, Result};
use astral_db::memory_v1_apply::{MemoryV1ApplyIdentity, MemoryV1ApplyVerifiedFrameContent};
use astral_trustgraph::service::memory_v1_mutation_coordinator::{
    decode_deny_journal_payload_with_origin, decode_journal_payload, DecodedJournalPayload,
    MutationAuditCandidate,
};
use astral_types::memory_v1_audit::MemoryV1AuditEvent;
use astral_types::memory_v1_deny_observation::MemoryV1DenyObservation;
use astral_types::memory_v1_journal::RecordKind;

use super::RecoveryRecord;

pub(super) enum RetainedPayload {
    Mutation(Box<DecodedJournalPayload>),
    Deny(Box<MemoryV1DenyObservation>),
}

impl RetainedPayload {
    // memory—v1: Each recovered value must carry its original producer identity.
    pub(super) fn decode(
        record: &RecoveryRecord,
        identity: &MemoryV1ApplyIdentity,
    ) -> Result<Self> {
        let (origin, payload) = match record.kind {
            RecordKind::Mutation => {
                let decoded = decode_journal_payload(&record.payload)?;
                (decoded.origin_boot_id(), Self::Mutation(Box::new(decoded)))
            }
            RecordKind::Deny => {
                let (origin, observation) =
                    decode_deny_journal_payload_with_origin(&record.payload)?;
                (origin, Self::Deny(Box::new(observation)))
            }
        };
        ensure!(
            origin == Some(identity.origin_boot_id),
            "retained producer mismatch"
        );
        Ok(payload)
    }

    // memory—v1: Compare the same canonical value used by the apply transaction.
    pub(super) fn audit_content(&self) -> Result<MemoryV1ApplyVerifiedFrameContent<'_>> {
        Ok(match self {
            Self::Mutation(decoded) => {
                MemoryV1ApplyVerifiedFrameContent::Event(single_event(decoded)?)
            }
            Self::Deny(observation) => {
                MemoryV1ApplyVerifiedFrameContent::DenyObservation(observation)
            }
        })
    }
}

// memory—v1: Batch audit shapes require their own reviewed apply transaction.
pub(super) fn single_event(decoded: &DecodedJournalPayload) -> Result<&MemoryV1AuditEvent> {
    match decoded.audit() {
        MutationAuditCandidate::Single(candidate) => Ok(candidate.as_event()),
        MutationAuditCandidate::Event(_) => bail!("no recovery transaction for batch audit events"),
    }
}
