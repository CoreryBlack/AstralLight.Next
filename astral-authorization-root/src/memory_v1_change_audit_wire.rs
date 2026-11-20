//! Untrusted, local exploration codec combining one mutation and one T2 value.
//!
//! This format is a candidate, not a frozen message or storage protocol. Only
//! user-card status values are currently supported. The audit component can
//! carry only the card's status, not its complete row or tenant relationship.
//! Scope, summary, actor, approver, time, hashes, and all other observations are
//! supplied by the caller; matching values do not establish their truth, clock
//! trust, authorization, confirmation applicability, execution, or durability.
//!
//! Before any future root CAS, the root owner must derive the T2 facts and the
//! complete pending message from the actual current and candidate snapshots,
//! bind them to the authorized operation, reserve capacity and publish the
//! facts and message together. This codec is not that owner or a commit API.
//! Operation ID and fingerprint are retained only in the T2 component.
//!
//! Frame: domain, big-endian u16 version, one-byte shape tag, then tagged
//! mutation and audit components, each followed by a big-endian u32 length and
//! the complete corresponding reversible wire. All bytes count toward the
//! journal payload ceiling, but this format does not define a journal record.

use std::fmt;

use astral_types::memory_v1::MemoryId;
use astral_types::memory_v1_audit::{
    MemoryV1AuditCardState, MemoryV1AuditDecision, MemoryV1AuditObject, MemoryV1AuditObjectState,
    MemoryV1AuditSource, MemoryV1AuditT2SingleChangeCandidate,
};
use astral_types::memory_v1_audit_wire::{
    decode_t2_single_change_candidate, encode_t2_single_change_candidate, MemoryV1AuditWireError,
};
use astral_types::memory_v1_journal::MAX_PAYLOAD_BYTES;
use thiserror::Error;

use crate::memory_v1_db_rows::UserCardStatus;
use crate::memory_v1_mutation_wire::{decode_mutation, encode_mutation, MutationWireError};
use crate::memory_v1_root::ManagementMutationV2;

const DOMAIN: &[u8] = b"astrallight/memory-v1/untrusted-change-audit-candidate\0";
const VERSION: u16 = 1;
const SINGLE_CARD_STATUS: u8 = 1;
const MUTATION_COMPONENT: u8 = 1;
const AUDIT_COMPONENT: u8 = 2;

/// Caller-supplied values, with no admission or authenticity implied.
#[derive(Clone)]
pub struct UntrustedChangeAuditCandidate {
    /// The proposed mutation value.
    pub mutation: ManagementMutationV2,
    /// The supplied single-change audit value, including operation correlation.
    pub audit: MemoryV1AuditT2SingleChangeCandidate,
}

/// memory—v1: Keep candidate Debug output fixed and redact mutation and audit values.
impl fmt::Debug for UntrustedChangeAuditCandidate {
    // memory—v1
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UntrustedChangeAuditCandidate([REDACTED])")
    }
}

/// Value, framing, component, or bounded-allocation failure; contains no input bytes.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum CandidateChangeAuditWireError {
    /// This candidate codec only handles user-card status mutations.
    #[error("unsupported candidate mutation")]
    UnsupportedMutation,
    /// The audit target does not identify the mutation's card.
    #[error("audit target does not match candidate mutation")]
    TargetMismatch,
    /// The audit states are not two card states or the after state differs.
    #[error("audit card states do not match candidate mutation")]
    StateMismatch,
    /// The context, before and after root versions do not form the required transition.
    #[error("audit root transition is inconsistent")]
    RootMismatch,
    /// The supplied audit decision is not ALLOW.
    #[error("audit decision is not allow")]
    WrongDecision,
    /// The card mutation does not describe a matching confirmation or special source.
    #[error("unsupported confirmation or audit source")]
    UnsupportedConfirmationOrSource,
    /// A nested mutation codec rejected the supplied value or bytes.
    #[error("mutation component: {0}")]
    Mutation(#[from] MutationWireError),
    /// A nested audit codec rejected the supplied value or bytes.
    #[error("audit component: {0}")]
    Audit(#[from] MemoryV1AuditWireError),
    /// The frame or a declared size exceeds the overall journal payload budget.
    #[error("candidate payload exceeds its size budget")]
    LimitExceeded,
    /// A size could not be represented or safely calculated.
    #[error("candidate payload length overflow")]
    LengthOverflow,
    /// The candidate frame could not reserve its required buffer.
    #[error("candidate payload allocation failed")]
    AllocationFailed,
    /// The frame ended before all declared bytes were available.
    #[error("truncated candidate payload")]
    Truncated,
    /// Domain or version was not recognized.
    #[error("invalid candidate domain or version")]
    InvalidDomainOrVersion,
    /// A shape or component tag was not recognized in its position.
    #[error("invalid candidate shape or component tag")]
    InvalidTag,
    /// Bytes remained after the complete frame.
    #[error("candidate payload has trailing bytes")]
    TrailingBytes,
    /// Decoded data did not reproduce the same canonical bytes.
    #[error("noncanonical candidate payload")]
    NonCanonical,
}

// memory—v1: Validate relationships only; caller-supplied facts remain untrusted.
fn validate(
    candidate: &UntrustedChangeAuditCandidate,
) -> Result<(), CandidateChangeAuditWireError> {
    let (card_id, expected_state) = match &candidate.mutation {
        ManagementMutationV2::UserCardStatus {
            user_card_id,
            status,
        } => {
            let state = match status {
                UserCardStatus::Active => MemoryV1AuditCardState::Active,
                UserCardStatus::Disabled => MemoryV1AuditCardState::Disabled,
            };
            (MemoryId::from_bytes(*user_card_id), state)
        }
        ManagementMutationV2::BindingCreate { .. }
        | ManagementMutationV2::BindingRemove { .. }
        | ManagementMutationV2::ConfirmationCreate { .. }
        | ManagementMutationV2::ConfirmationRevoke { .. }
        | ManagementMutationV2::RuleSetChangeConfirmationRevoke { .. }
        | ManagementMutationV2::ConfirmationBatch { .. }
        | ManagementMutationV2::UserCardCreate { .. }
        | ManagementMutationV2::RuleSetCreate { .. }
        | ManagementMutationV2::RuleSetRetire { .. }
        | ManagementMutationV2::VersionPublish { .. }
        | ManagementMutationV2::ContextLoad { .. } => {
            return Err(CandidateChangeAuditWireError::UnsupportedMutation);
        }
    };
    let audit = &candidate.audit;
    if audit.decision() != MemoryV1AuditDecision::Allow {
        return Err(CandidateChangeAuditWireError::WrongDecision);
    }
    if audit.target() != MemoryV1AuditObject::UserCard(card_id) {
        return Err(CandidateChangeAuditWireError::TargetMismatch);
    }
    // Same-state updates are accepted: the current candidate root permits them
    // and advances a dependency even when the status itself is unchanged.
    match (audit.before(), audit.after()) {
        (MemoryV1AuditObjectState::UserCard(before), MemoryV1AuditObjectState::UserCard(after)) => {
            match before {
                MemoryV1AuditCardState::Active | MemoryV1AuditCardState::Disabled => {}
            }
            match after {
                MemoryV1AuditCardState::Active | MemoryV1AuditCardState::Disabled => {}
            }
            if *after != expected_state {
                return Err(CandidateChangeAuditWireError::StateMismatch);
            }
        }
        _ => return Err(CandidateChangeAuditWireError::StateMismatch),
    }
    // The mutation contains no confirmation and the available reference types
    // describe binding/rule-set changes, not card-status confirmations. This
    // conservative restriction does not assert that real confirmation is unnecessary.
    if !audit.confirmations().is_not_applicable()
        || !matches!(audit.source(), MemoryV1AuditSource::Ordinary)
    {
        return Err(CandidateChangeAuditWireError::UnsupportedConfirmationOrSource);
    }
    let before = audit.root_before();
    let after = audit.root_after();
    if audit.context().root().version() != before
        || before.instance() != after.instance()
        || before.version().checked_add(1) != Some(after.version())
    {
        return Err(CandidateChangeAuditWireError::RootMismatch);
    }
    Ok(())
}

// memory—v1: Calculate the whole size before reserving the final candidate buffer.
fn frame_len(
    mutation_len: usize,
    audit_len: usize,
) -> Result<usize, CandidateChangeAuditWireError> {
    u32::try_from(mutation_len).map_err(|_| CandidateChangeAuditWireError::LengthOverflow)?;
    u32::try_from(audit_len).map_err(|_| CandidateChangeAuditWireError::LengthOverflow)?;
    let total = DOMAIN
        .len()
        .checked_add(2 + 1 + 1 + 4 + 1 + 4)
        .and_then(|n| n.checked_add(mutation_len))
        .and_then(|n| n.checked_add(audit_len))
        .ok_or(CandidateChangeAuditWireError::LengthOverflow)?;
    if total > MAX_PAYLOAD_BYTES {
        return Err(CandidateChangeAuditWireError::LimitExceeded);
    }
    Ok(total)
}

// memory—v1: Assemble already-encoded components using checked lengths and one reservation.
fn frame(mutation: &[u8], audit: &[u8]) -> Result<Vec<u8>, CandidateChangeAuditWireError> {
    let total = frame_len(mutation.len(), audit.len())?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(total)
        .map_err(|_| CandidateChangeAuditWireError::AllocationFailed)?;
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.push(SINGLE_CARD_STATUS);
    bytes.push(MUTATION_COMPONENT);
    bytes.extend_from_slice(&(mutation.len() as u32).to_be_bytes());
    bytes.extend_from_slice(mutation);
    bytes.push(AUDIT_COMPONENT);
    bytes.extend_from_slice(&(audit.len() as u32).to_be_bytes());
    bytes.extend_from_slice(audit);
    Ok(bytes)
}

/// memory—v1: Encode a structurally correlated, untrusted local candidate.
///
/// Success asserts only the documented value-level checks, never authorization,
/// factual correctness, publication, or persistence.
pub fn encode_untrusted_change_audit_candidate(
    candidate: &UntrustedChangeAuditCandidate,
) -> Result<Vec<u8>, CandidateChangeAuditWireError> {
    validate(candidate)?;
    let mutation = encode_mutation(&candidate.mutation)?;
    let audit = encode_t2_single_change_candidate(&candidate.audit)?;
    frame(&mutation, &audit)
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    // memory—v1: Bound every slice with checked arithmetic before accessing it.
    fn take(&mut self, len: usize) -> Result<&'a [u8], CandidateChangeAuditWireError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(CandidateChangeAuditWireError::LengthOverflow)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(CandidateChangeAuditWireError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    // memory—v1: Read the one valid component tag and bounded, framed component.
    fn component(&mut self, tag: u8) -> Result<&'a [u8], CandidateChangeAuditWireError> {
        if self.take(1)?[0] != tag {
            return Err(CandidateChangeAuditWireError::InvalidTag);
        }
        let length_bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| CandidateChangeAuditWireError::Truncated)?;
        let len = u32::from_be_bytes(length_bytes) as usize;
        if len > MAX_PAYLOAD_BYTES {
            return Err(CandidateChangeAuditWireError::LimitExceeded);
        }
        self.take(len)
    }
}

/// memory—v1: Decode one canonical untrusted candidate and recheck correlations.
///
/// Canonical re-encoding detects alternate representations; it is not a MAC,
/// signature, authenticity check, or evidence that supplied facts are true.
pub fn decode_untrusted_change_audit_candidate(
    bytes: &[u8],
) -> Result<UntrustedChangeAuditCandidate, CandidateChangeAuditWireError> {
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(CandidateChangeAuditWireError::LimitExceeded);
    }
    let mut reader = Reader { bytes, offset: 0 };
    if reader.take(DOMAIN.len())? != DOMAIN || reader.take(2)? != VERSION.to_be_bytes() {
        return Err(CandidateChangeAuditWireError::InvalidDomainOrVersion);
    }
    if reader.take(1)?[0] != SINGLE_CARD_STATUS {
        return Err(CandidateChangeAuditWireError::InvalidTag);
    }
    let mutation_bytes = reader.component(MUTATION_COMPONENT)?;
    let audit_bytes = reader.component(AUDIT_COMPONENT)?;
    if reader.offset != bytes.len() {
        return Err(CandidateChangeAuditWireError::TrailingBytes);
    }
    let candidate = UntrustedChangeAuditCandidate {
        mutation: decode_mutation(mutation_bytes)?,
        audit: decode_t2_single_change_candidate(audit_bytes)?,
    };
    validate(&candidate)?;
    if encode_untrusted_change_audit_candidate(&candidate)? != bytes {
        return Err(CandidateChangeAuditWireError::NonCanonical);
    }
    Ok(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::memory_v1_audit::{
        MemoryV1AuditAction, MemoryV1AuditActor, MemoryV1AuditChange, MemoryV1AuditChangeSummary,
        MemoryV1AuditConfirmationRef, MemoryV1AuditConfirmations, MemoryV1AuditContext,
        MemoryV1AuditDecisionInput, MemoryV1AuditEvent, MemoryV1AuditOperation,
        MemoryV1AuditOverlayOnly, MemoryV1AuditRootObservation, MemoryV1AuditRootStatus,
        MemoryV1AuditRootVersion, MemoryV1AuditTime,
    };

    // memory—v1
    fn id(n: u8) -> MemoryId {
        MemoryId::from_bytes([n; 16])
    }

    // memory—v1
    fn root(instance: u8, version: u64) -> MemoryV1AuditRootVersion {
        MemoryV1AuditRootVersion::new(id(instance), version)
    }

    // memory—v1
    #[allow(clippy::too_many_arguments)]
    fn audit(
        card: u8,
        before: MemoryV1AuditObjectState,
        after: MemoryV1AuditObjectState,
        context_root: MemoryV1AuditRootVersion,
        root_before: MemoryV1AuditRootVersion,
        root_after: MemoryV1AuditRootVersion,
        confirmations: MemoryV1AuditConfirmations,
        source: MemoryV1AuditSource,
    ) -> MemoryV1AuditT2SingleChangeCandidate {
        let context = MemoryV1AuditContext::new(
            MemoryV1AuditActor::new(id(1), id(2)),
            MemoryV1AuditTime::new(42).unwrap(),
            MemoryV1AuditAction::new("user-card", "update").unwrap(),
            "supplied",
            MemoryV1AuditOperation::new("op-1", [3; 32]).unwrap(),
            MemoryV1AuditRootObservation::new(
                context_root,
                [4; 32],
                MemoryV1AuditRootStatus::Serving,
            ),
        )
        .unwrap();
        let change = MemoryV1AuditChange::new(
            Some(id(5)),
            Some(MemoryV1AuditObject::UserCard(id(card))),
            Some(MemoryV1AuditObject::Tenant(id(7))),
            Some(MemoryV1AuditChangeSummary::new(b"supplied summary").unwrap()),
            Some(before),
            Some(after),
            Some(confirmations),
            Some(root_before),
            Some(root_after),
            source,
        );
        MemoryV1AuditT2SingleChangeCandidate::try_from(
            MemoryV1AuditEvent::change(context, MemoryV1AuditDecisionInput::Allow, change).unwrap(),
        )
        .unwrap()
    }

    // memory—v1
    fn state(value: MemoryV1AuditCardState) -> MemoryV1AuditObjectState {
        MemoryV1AuditObjectState::UserCard(value)
    }

    // memory—v1
    fn candidate(
        before: MemoryV1AuditCardState,
        status: UserCardStatus,
    ) -> UntrustedChangeAuditCandidate {
        let after = match status {
            UserCardStatus::Active => MemoryV1AuditCardState::Active,
            UserCardStatus::Disabled => MemoryV1AuditCardState::Disabled,
        };
        UntrustedChangeAuditCandidate {
            mutation: ManagementMutationV2::UserCardStatus {
                user_card_id: [6; 16],
                status,
            },
            audit: audit(
                6,
                state(before),
                state(after),
                root(9, 1),
                root(9, 1),
                root(9, 2),
                MemoryV1AuditConfirmations::not_applicable(),
                MemoryV1AuditSource::Ordinary,
            ),
        }
    }

    // memory—v1
    fn raw_frame(value: &UntrustedChangeAuditCandidate) -> Vec<u8> {
        frame(
            &encode_mutation(&value.mutation).unwrap(),
            &encode_t2_single_change_candidate(&value.audit).unwrap(),
        )
        .unwrap()
    }

    #[test]
    // memory—v1
    fn roundtrip_both_transitions_and_same_status() {
        for (before, status) in [
            (MemoryV1AuditCardState::Active, UserCardStatus::Disabled),
            (MemoryV1AuditCardState::Disabled, UserCardStatus::Active),
            (MemoryV1AuditCardState::Active, UserCardStatus::Active),
            (MemoryV1AuditCardState::Disabled, UserCardStatus::Disabled),
        ] {
            let original = candidate(before, status);
            let bytes = encode_untrusted_change_audit_candidate(&original).unwrap();
            let decoded = decode_untrusted_change_audit_candidate(&bytes).unwrap();
            assert_eq!(
                encode_mutation(&decoded.mutation).unwrap(),
                encode_mutation(&original.mutation).unwrap()
            );
            assert_eq!(decoded.audit, original.audit);
            assert_eq!(
                encode_untrusted_change_audit_candidate(&decoded).unwrap(),
                bytes
            );
        }
    }

    #[test]
    // memory—v1
    fn rejects_cross_component_mismatch_on_encode_and_decode() {
        let mut value = candidate(MemoryV1AuditCardState::Active, UserCardStatus::Disabled);
        value.mutation = ManagementMutationV2::UserCardStatus {
            user_card_id: [8; 16],
            status: UserCardStatus::Disabled,
        };
        assert_eq!(
            encode_untrusted_change_audit_candidate(&value).unwrap_err(),
            CandidateChangeAuditWireError::TargetMismatch
        );
        assert_eq!(
            decode_untrusted_change_audit_candidate(&raw_frame(&value)).unwrap_err(),
            CandidateChangeAuditWireError::TargetMismatch
        );
        value.mutation = ManagementMutationV2::UserCardStatus {
            user_card_id: [6; 16],
            status: UserCardStatus::Active,
        };
        assert_eq!(
            encode_untrusted_change_audit_candidate(&value).unwrap_err(),
            CandidateChangeAuditWireError::StateMismatch
        );
        assert_eq!(
            decode_untrusted_change_audit_candidate(&raw_frame(&value)).unwrap_err(),
            CandidateChangeAuditWireError::StateMismatch
        );
        value.mutation = ManagementMutationV2::RuleSetRetire {
            rule_set_id: [6; 16],
        };
        assert_eq!(
            encode_untrusted_change_audit_candidate(&value).unwrap_err(),
            CandidateChangeAuditWireError::UnsupportedMutation
        );
        assert_eq!(
            decode_untrusted_change_audit_candidate(&raw_frame(&value)).unwrap_err(),
            CandidateChangeAuditWireError::UnsupportedMutation
        );
    }

    #[test]
    // memory—v1
    fn rejects_absent_before_invalid_roots_and_unrelated_confirmations() {
        let mut value = candidate(MemoryV1AuditCardState::Active, UserCardStatus::Disabled);
        let make = |before, context, previous, next, confirmations, source| {
            audit(
                6,
                before,
                state(MemoryV1AuditCardState::Disabled),
                context,
                previous,
                next,
                confirmations,
                source,
            )
        };
        let none = || MemoryV1AuditConfirmations::not_applicable();
        value.audit = make(
            MemoryV1AuditObjectState::Absent,
            root(9, 1),
            root(9, 1),
            root(9, 2),
            none(),
            MemoryV1AuditSource::Ordinary,
        );
        assert_eq!(
            encode_untrusted_change_audit_candidate(&value).unwrap_err(),
            CandidateChangeAuditWireError::StateMismatch
        );
        for (context, previous, next) in [
            (root(8, 1), root(9, 1), root(9, 2)),
            (root(9, 0), root(9, 1), root(9, 2)),
            (root(9, 1), root(9, 1), root(8, 2)),
            (root(9, 1), root(9, 1), root(9, 1)),
            (root(9, 1), root(9, 1), root(9, 3)),
            (root(9, u64::MAX), root(9, u64::MAX), root(9, 0)),
        ] {
            value.audit = make(
                state(MemoryV1AuditCardState::Active),
                context,
                previous,
                next,
                none(),
                MemoryV1AuditSource::Ordinary,
            );
            assert_eq!(
                encode_untrusted_change_audit_candidate(&value).unwrap_err(),
                CandidateChangeAuditWireError::RootMismatch
            );
            assert_eq!(
                decode_untrusted_change_audit_candidate(&raw_frame(&value)).unwrap_err(),
                CandidateChangeAuditWireError::RootMismatch
            );
        }
        value.audit = make(
            state(MemoryV1AuditCardState::Active),
            root(9, 1),
            root(9, 1),
            root(9, 2),
            MemoryV1AuditConfirmations::references(&[MemoryV1AuditConfirmationRef::Binding(id(8))])
                .unwrap(),
            MemoryV1AuditSource::Ordinary,
        );
        assert_eq!(
            encode_untrusted_change_audit_candidate(&value).unwrap_err(),
            CandidateChangeAuditWireError::UnsupportedConfirmationOrSource
        );
        value.audit = make(
            state(MemoryV1AuditCardState::Active),
            root(9, 1),
            root(9, 1),
            root(9, 2),
            none(),
            MemoryV1AuditSource::OverlayOnlyCreation(MemoryV1AuditOverlayOnly::new(
                id(1),
                id(2),
                id(3),
            )),
        );
        assert_eq!(
            encode_untrusted_change_audit_candidate(&value).unwrap_err(),
            CandidateChangeAuditWireError::UnsupportedConfirmationOrSource
        );
    }

    #[test]
    // memory—v1
    fn rejects_truncation_trailing_tags_lengths_and_payload_limit() {
        let value = candidate(MemoryV1AuditCardState::Active, UserCardStatus::Disabled);
        let bytes = encode_untrusted_change_audit_candidate(&value).unwrap();
        for n in 0..bytes.len() {
            assert!(
                decode_untrusted_change_audit_candidate(&bytes[..n]).is_err(),
                "truncation {n}"
            );
        }
        let mut altered = bytes.clone();
        altered.push(0);
        assert_eq!(
            decode_untrusted_change_audit_candidate(&altered).unwrap_err(),
            CandidateChangeAuditWireError::TrailingBytes
        );
        for offset in [DOMAIN.len() + 2, DOMAIN.len() + 3] {
            let mut altered = bytes.clone();
            altered[offset] = 255;
            assert_eq!(
                decode_untrusted_change_audit_candidate(&altered).unwrap_err(),
                CandidateChangeAuditWireError::InvalidTag
            );
        }
        let audit_tag =
            DOMAIN.len() + 2 + 1 + 1 + 4 + encode_mutation(&value.mutation).unwrap().len();
        let mut altered = bytes.clone();
        altered[audit_tag] = 255;
        assert_eq!(
            decode_untrusted_change_audit_candidate(&altered).unwrap_err(),
            CandidateChangeAuditWireError::InvalidTag
        );
        let mut altered = bytes.clone();
        altered[DOMAIN.len() + 4..DOMAIN.len() + 8].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            decode_untrusted_change_audit_candidate(&altered).unwrap_err(),
            CandidateChangeAuditWireError::LimitExceeded
        );
        assert_eq!(
            decode_untrusted_change_audit_candidate(&vec![0; MAX_PAYLOAD_BYTES + 1]).unwrap_err(),
            CandidateChangeAuditWireError::LimitExceeded
        );
        assert_eq!(
            frame_len(MAX_PAYLOAD_BYTES, 1).unwrap_err(),
            CandidateChangeAuditWireError::LimitExceeded
        );
        assert!(frame_len(usize::MAX, 1).is_err());
    }

    #[test]
    // memory—v1
    fn rejects_nested_tampering_but_does_not_claim_authenticity() {
        let value = candidate(MemoryV1AuditCardState::Active, UserCardStatus::Disabled);
        let mut mutation = encode_mutation(&value.mutation).unwrap();
        let audit = encode_t2_single_change_candidate(&value.audit).unwrap();
        let last = mutation.len() - 1;
        mutation[last] = 1;
        assert_eq!(
            decode_untrusted_change_audit_candidate(&frame(&mutation, &audit).unwrap())
                .unwrap_err(),
            CandidateChangeAuditWireError::StateMismatch
        );
        mutation[last] = 255;
        assert!(
            decode_untrusted_change_audit_candidate(&frame(&mutation, &audit).unwrap()).is_err()
        );
        let mut invalid_audit = audit.clone();
        invalid_audit[10] = 255;
        assert!(decode_untrusted_change_audit_candidate(
            &frame(&encode_mutation(&value.mutation).unwrap(), &invalid_audit).unwrap()
        )
        .is_err());
        // A valid but different operation fingerprint remains caller-supplied and
        // cannot be detected as a forgery by an unsigned value codec.
        let mut other = value.clone();
        let replacement = MemoryV1AuditOperation::new("op-1", [8; 32]).unwrap();
        let old = other.audit.context();
        let context = MemoryV1AuditContext::new(
            old.actor(),
            old.time(),
            old.action().clone(),
            old.reason_code(),
            replacement,
            old.root(),
        )
        .unwrap();
        let event = MemoryV1AuditEvent::change(
            context,
            MemoryV1AuditDecisionInput::Allow,
            other.audit.change_details().clone(),
        )
        .unwrap();
        other.audit = MemoryV1AuditT2SingleChangeCandidate::try_from(event).unwrap();
        assert_ne!(
            encode_untrusted_change_audit_candidate(&value).unwrap(),
            encode_untrusted_change_audit_candidate(&other).unwrap()
        );
        assert!(decode_untrusted_change_audit_candidate(
            &encode_untrusted_change_audit_candidate(&other).unwrap()
        )
        .is_ok());
    }

    #[test]
    // memory—v1: Debug for a candidate redacts sensitive fields from other mutations.
    fn debug_redacts_sensitive_other_mutation_fields() {
        let candidate = UntrustedChangeAuditCandidate {
            mutation: ManagementMutationV2::RuleSetCreate {
                rule_set: crate::memory_v1_db_rows::RuleSetRow {
                    rule_set_id: [7; 16],
                    owner_tenant_id: [8; 16],
                    current_version_bytes: b"current-version-secret".to_vec(),
                    status: crate::memory_v1_db_rows::RuleSetStatus::Active,
                },
                version: crate::memory_v1_db_rows::RuleSetVersionRow {
                    rule_set_id: [7; 16],
                    version_bytes: b"version-secret".to_vec(),
                    content_bytes: b"rule-content-secret".to_vec(),
                    timestamp_bytes: b"timestamp-secret".to_vec(),
                    hash_input_bytes: b"hash-input-secret".to_vec(),
                    hash_bytes: b"hash-secret".to_vec(),
                },
                change_confirmation: crate::memory_v1_db_rows::RuleSetChangeConfirmationRow {
                    confirmation_id: [9; 16],
                    rule_set_id: [7; 16],
                    version_bytes: b"confirmation-version-secret".to_vec(),
                    confirmer_user_id: [10; 16],
                    affected_scope_bytes: b"affected-scope-secret".to_vec(),
                    operation_id: b"operation-secret".to_vec(),
                    confirmed_at_bytes: b"confirmed-at-secret".to_vec(),
                    revoked_at: None,
                    revoked_by: None,
                },
            },
            audit: candidate(MemoryV1AuditCardState::Active, UserCardStatus::Disabled).audit,
        };
        let debug = format!("{candidate:?}");

        assert_eq!(debug, "UntrustedChangeAuditCandidate([REDACTED])");
        for secret in [
            "current-version-secret",
            "version-secret",
            "rule-content-secret",
            "timestamp-secret",
            "hash-input-secret",
            "hash-secret",
            "confirmation-version-secret",
            "affected-scope-secret",
            "operation-secret",
            "confirmed-at-secret",
        ] {
            assert!(!debug.contains(secret), "debug leaked {secret}");
        }
    }
}
