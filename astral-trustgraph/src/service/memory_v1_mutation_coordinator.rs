//! memory—v1: typed governance-mutation proof contract.
//!
//! This module is deliberately a contract seam, not a durable owner. It binds a
//! mutation, its complete T2 audit candidate, a stable operation identity and a
//! root observation before any proof token can be accepted. The proof tokens have
//! no public constructors yet: a future journal/root/DB owner must mint them only
//! after it has verified the corresponding durable postcondition.
//!
//! The state machine is intentionally one-way:
//!
//! `claimed -> journal prepared -> journal durable -> root published -> complete`
//!
//! An unknown result is terminal until an explicit reconciliation owner resolves
//! it. There is no retry method on `UnknownMutation`. Database progress can be
//! attached after root publication because memory-v1 A/A1 does not make MySQL a
//! synchronous management-success prerequisite; it never substitutes for the
//! local durable prefix or atomic root-publication proof.

use std::collections::BTreeMap;

use astral_authorization_root::memory_v1_db_rows::UserCardStatus;
use astral_authorization_root::memory_v1_mutation_digest::digest_mutation;
use astral_authorization_root::memory_v1_mutation_wire::{decode_mutation, encode_mutation};
use astral_authorization_root::memory_v1_root::{
    ManagementMutationV2, RootInstanceId, RootMetadata, RootStatus,
};
use astral_types::memory_v1::MemoryId;
use astral_types::memory_v1_audit::{
    MemoryV1AuditBindingState, MemoryV1AuditCardState, MemoryV1AuditConfirmationState,
    MemoryV1AuditDecision, MemoryV1AuditDenySource, MemoryV1AuditObject, MemoryV1AuditObjectState,
    MemoryV1AuditRootStatus, MemoryV1AuditRuleSetStatus, MemoryV1AuditT2EventCandidate,
    MemoryV1AuditT2SingleChangeCandidate,
};
use astral_types::memory_v1_audit_wire::{
    decode_t2_candidate, decode_t2_single_change_candidate, encode_t2_candidate,
    encode_t2_single_change_candidate,
};
use astral_types::memory_v1_deny_observation::MemoryV1DenyObservation;
use sha2::{Digest, Sha256};
use thiserror::Error;

const MAX_OPERATION_ID_BYTES: usize = 64;
const MAX_LEDGER_ENTRIES: usize = 65_536;
const AUDIT_DIGEST_DOMAIN: &[u8] = b"astrallight/memory-v1/coordinator/audit/1\0";
const PUBLICATION_LINK_DOMAIN: &[u8] = b"astrallight/memory-v1/coordinator/publication/1\0";
const JOURNAL_PAYLOAD_DOMAIN: &[u8] = b"astrallight/memory-v1/journal/mutation-envelope/1\0";
const JOURNAL_PAYLOAD_VERSION: u16 = 1;
const JOURNAL_PAYLOAD_SINGLE: u8 = 1;
const JOURNAL_PAYLOAD_EVENT: u8 = 2;
const JOURNAL_PAYLOAD_FLAGS: u8 = 0;
const JOURNAL_PAYLOAD_HEADER_BYTES: usize =
    JOURNAL_PAYLOAD_DOMAIN.len() + 2 + 1 + 1 + 4 + 4 + 4 + 32 + 32;
const DENY_PAYLOAD_DOMAIN: &[u8] = b"astrallight/memory-v1/journal/deny-envelope/1\0";
const DENY_PAYLOAD_VERSION: u16 = 1;
const DENY_PAYLOAD_HEADER_BYTES: usize = DENY_PAYLOAD_DOMAIN.len() + 2 + 1 + 4 + 4 + 32;
const DENY_AUDIT_DIGEST_DOMAIN: &[u8] = b"astrallight/memory-v1/coordinator/deny-audit-value/1\0";

/// A SHA-256 value bound to one mutation or proof envelope.
pub type CoordinatorDigest = [u8; 32];

/// Errors exposed by the value-level coordinator contract.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CoordinatorError {
    #[error("operation identity is invalid")]
    InvalidOperationId,
    #[error("request fingerprint is invalid")]
    InvalidFingerprint,
    #[error("root observation is not a serving root")]
    RootUnavailable,
    #[error("root observation has an invalid identity or digest")]
    InvalidRootObservation,
    #[error("journal identity is invalid")]
    InvalidJournalIdentity,
    #[error("mutation or audit candidate cannot be encoded within its bounds")]
    CandidateUnavailable,
    #[error("audit target or resulting state does not match the mutation")]
    MutationAuditMismatch,
    #[error("audit candidate is not a successful T2 candidate")]
    InvalidAuditCandidate,
    #[error("audit candidate does not match the mutation request")]
    AuditBindingMismatch,
    #[error("journal mutation payload envelope is invalid")]
    InvalidJournalPayload,
    #[error("operation already has an existing outcome")]
    ExistingOperation,
    #[error("operation identity is already bound to another mutation")]
    DigestConflict,
    #[error("operation ledger capacity is exhausted")]
    CapacityExceeded,
    #[error("state transition is not permitted")]
    InvalidTransition,
    #[error("journal capacity reservation is insufficient or mismatched")]
    InvalidJournalReservation,
    #[error("durable proof does not match the request")]
    ProofMismatch,
    #[error("an unknown result requires reconciliation before another action")]
    UnknownRequiresReconciliation,
    #[error("database progress proof does not match the published mutation")]
    InvalidDatabaseProgress,
    #[error("DENY proof does not match the observed request")]
    InvalidDenyProof,
}

/// The root facts captured by the admission/evaluation phase.
///
/// This is an observation value. It is not an adoption certificate and cannot
/// make a candidate root serve.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootBinding {
    instance_id: RootInstanceId,
    version: u64,
    digest: CoordinatorDigest,
    status: RootStatus,
}

impl RootBinding {
    /// Capture the exact metadata returned by a root read.
    pub const fn from_metadata(metadata: RootMetadata) -> Self {
        Self {
            instance_id: metadata.instance_id,
            version: metadata.version,
            digest: metadata.digest,
            status: metadata.status,
        }
    }

    /// Construct an untrusted read observation for an upper-layer contract.
    ///
    /// This constructor creates no serving or publication proof.
    pub const fn new(
        instance_id: RootInstanceId,
        version: u64,
        digest: CoordinatorDigest,
        status: RootStatus,
    ) -> Self {
        Self {
            instance_id,
            version,
            digest,
            status,
        }
    }

    pub const fn instance_id(self) -> RootInstanceId {
        self.instance_id
    }

    pub const fn version(self) -> u64 {
        self.version
    }

    pub const fn digest(self) -> CoordinatorDigest {
        self.digest
    }

    pub const fn status(self) -> RootStatus {
        self.status
    }

    fn valid(self) -> bool {
        self.status == RootStatus::Serving
            && !self.instance_id.as_uuid().is_nil()
            && self.digest.iter().any(|byte| *byte != 0)
    }
}

/// An opaque admission capability for a root that has passed the production
/// adoption/evidence gate.
///
/// There is intentionally no production constructor in this module. A future
/// composition owner must obtain the sealed value from the root/adoption owner;
/// `RootStatus::Serving` alone is insufficient because experimental and isolated
/// test roots can also report that status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedRootAdmission {
    binding: RootBinding,
    _seal: RootAdmissionSeal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RootAdmissionSeal;

impl VerifiedRootAdmission {
    pub const fn binding(self) -> RootBinding {
        self.binding
    }

    /// memory—v1: Mint this admission only inside the crate that owns the
    /// composition-level root capability. The caller must have validated a
    /// root-owned `ProductionAdmission` for this exact runtime in the same
    /// task; minting from an unverified observation stays forbidden.
    /// Trust-boundary API: only the composition owner may call this.
    #[doc(hidden)]
    pub const fn mint_from_production_owner(binding: RootBinding) -> Self {
        Self {
            binding,
            _seal: RootAdmissionSeal,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub const fn for_contract_tests(binding: RootBinding) -> Self {
        Self {
            binding,
            _seal: RootAdmissionSeal,
        }
    }
}

/// The stable identifiers assigned to one journal message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalIdentity {
    stream_id: MemoryId,
    epoch_id: MemoryId,
    journal_sequence: u64,
    mutation_sequence: u64,
    message_id: MemoryId,
}

impl JournalIdentity {
    /// Capture a candidate identity; no storage or sequence ownership is implied.
    pub fn new(
        stream_id: MemoryId,
        epoch_id: MemoryId,
        journal_sequence: u64,
        mutation_sequence: u64,
        message_id: MemoryId,
    ) -> Result<Self, CoordinatorError> {
        if !nonzero_id(stream_id)
            || !nonzero_id(epoch_id)
            || !nonzero_id(message_id)
            || journal_sequence == 0
            || mutation_sequence == 0
        {
            return Err(CoordinatorError::InvalidJournalIdentity);
        }
        Ok(Self {
            stream_id,
            epoch_id,
            journal_sequence,
            mutation_sequence,
            message_id,
        })
    }

    /// Identity for one DENY record. A DENY carries the mutation sequence it
    /// observed; zero is the legitimate external baseline and does not advance
    /// that sequence. Stream, epoch, message and journal sequence stay strict.
    pub fn new_deny(
        stream_id: MemoryId,
        epoch_id: MemoryId,
        journal_sequence: u64,
        mutation_sequence: u64,
        message_id: MemoryId,
    ) -> Result<Self, CoordinatorError> {
        if !nonzero_id(stream_id)
            || !nonzero_id(epoch_id)
            || !nonzero_id(message_id)
            || journal_sequence == 0
        {
            return Err(CoordinatorError::InvalidJournalIdentity);
        }
        Ok(Self {
            stream_id,
            epoch_id,
            journal_sequence,
            mutation_sequence,
            message_id,
        })
    }

    pub const fn stream_id(self) -> MemoryId {
        self.stream_id
    }

    pub const fn epoch_id(self) -> MemoryId {
        self.epoch_id
    }

    pub const fn journal_sequence(self) -> u64 {
        self.journal_sequence
    }

    pub const fn mutation_sequence(self) -> u64 {
        self.mutation_sequence
    }

    pub const fn message_id(self) -> MemoryId {
        self.message_id
    }
}

/// A complete, value-level T2 audit candidate accepted by the coordinator.
///
/// The candidate remains untrusted until a future audit owner mints a durable
/// proof. Keeping the concrete candidate here prevents a caller from replacing
/// a batch audit with a single-row placeholder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MutationAuditCandidate {
    Single(MemoryV1AuditT2SingleChangeCandidate),
    Event(MemoryV1AuditT2EventCandidate),
}

impl MutationAuditCandidate {
    fn operation_id(&self) -> &str {
        match self {
            Self::Single(candidate) => candidate.operation().id(),
            Self::Event(candidate) => candidate.operation().id(),
        }
    }

    fn fingerprint(&self) -> &CoordinatorDigest {
        match self {
            Self::Single(candidate) => candidate.operation().fingerprint(),
            Self::Event(candidate) => candidate.operation().fingerprint(),
        }
    }

    fn decision(&self) -> MemoryV1AuditDecision {
        match self {
            Self::Single(candidate) => candidate.decision(),
            Self::Event(candidate) => candidate.decision(),
        }
    }

    fn root_matches(&self, root: RootBinding) -> bool {
        let (observation, before, after) = match self {
            Self::Single(candidate) => (
                candidate.context().root(),
                candidate.root_before(),
                candidate.root_after(),
            ),
            Self::Event(candidate) => (
                candidate.context().root(),
                candidate.root_before(),
                candidate.root_after(),
            ),
        };
        let instance = MemoryId::from_bytes(*root.instance_id().as_uuid().as_bytes());
        observation.version().instance() == instance
            && observation.version().version() == root.version()
            && observation.content_hash() == &root.digest()
            && observation.status() == MemoryV1AuditRootStatus::Serving
            && before.instance() == instance
            && before.version() == root.version()
            && after.instance() == instance
            && root
                .version()
                .checked_add(1)
                .is_some_and(|next| after.version() == next)
    }

    /// Validate the value-level bindings required at the HTTP commit seam.
    /// The future durable owner must still recheck the candidate against its exact root snapshot.
    #[allow(clippy::too_many_arguments)] // one explicit parameter per bound fact
    pub fn validate_governance_binding(
        &self,
        operation_id: &str,
        request_fingerprint: &CoordinatorDigest,
        root: RootMetadata,
        actor: [u8; 16],
        target: [u8; 16],
        target_tenant: [u8; 16],
        trusted_time_unix_seconds: i64,
        mutation: &ManagementMutationV2,
    ) -> Result<(), CoordinatorError> {
        if self.operation_id() != operation_id
            || self.fingerprint() != request_fingerprint
            || self.decision() != MemoryV1AuditDecision::Allow
            || !self.root_matches(RootBinding::from_metadata(root))
        {
            return Err(CoordinatorError::AuditBindingMismatch);
        }

        let Self::Single(candidate) = self else {
            return Err(CoordinatorError::InvalidAuditCandidate);
        };
        let expected_target = match mutation {
            ManagementMutationV2::BindingCreate { row, .. } => {
                MemoryV1AuditObject::Binding(MemoryId::from_bytes(row.binding_id))
            }
            ManagementMutationV2::BindingRemove { binding_id, .. } => {
                MemoryV1AuditObject::Binding(MemoryId::from_bytes(*binding_id))
            }
            ManagementMutationV2::ConfirmationCreate { row } => {
                MemoryV1AuditObject::Confirmation(MemoryId::from_bytes(row.confirmation_id))
            }
            ManagementMutationV2::ConfirmationRevoke {
                confirmation_id, ..
            }
            | ManagementMutationV2::RuleSetChangeConfirmationRevoke {
                confirmation_id, ..
            } => MemoryV1AuditObject::Confirmation(MemoryId::from_bytes(*confirmation_id)),
            ManagementMutationV2::ConfirmationBatch { rows } => {
                // The batch audit event targets the first confirmation's
                // binding; every item is retained in the confirmations value.
                rows.first()
                    .map(|row| MemoryV1AuditObject::Binding(MemoryId::from_bytes(row.binding_id)))
                    .ok_or(CoordinatorError::InvalidAuditCandidate)?
            }
            ManagementMutationV2::UserCardCreate { row } => {
                MemoryV1AuditObject::UserCard(MemoryId::from_bytes(row.user_card_id))
            }
            ManagementMutationV2::UserCardStatus { user_card_id, .. } => {
                MemoryV1AuditObject::UserCard(MemoryId::from_bytes(*user_card_id))
            }
            ManagementMutationV2::RuleSetCreate { rule_set, .. } => {
                MemoryV1AuditObject::RuleSet(MemoryId::from_bytes(rule_set.rule_set_id))
            }
            ManagementMutationV2::RuleSetRetire { rule_set_id }
            | ManagementMutationV2::VersionPublish { rule_set_id, .. } => {
                MemoryV1AuditObject::RuleSet(MemoryId::from_bytes(*rule_set_id))
            }
            // memory—v1 §15.10.3: A context load is not a governed mutation;
            // it never carries a governance audit candidate.
            ManagementMutationV2::ContextLoad { .. } => {
                return Err(CoordinatorError::InvalidAuditCandidate);
            }
        };
        let (expected_resource, expected_action) = match mutation {
            ManagementMutationV2::BindingCreate { .. } => ("binding", "create"),
            ManagementMutationV2::BindingRemove { .. } => ("binding", "remove"),
            ManagementMutationV2::ConfirmationCreate { .. } => ("binding", "confirm"),
            ManagementMutationV2::ConfirmationRevoke { .. }
            | ManagementMutationV2::RuleSetChangeConfirmationRevoke { .. } => {
                ("binding", "revoke-confirmation")
            }
            ManagementMutationV2::ConfirmationBatch { .. } => ("binding", "confirm"),
            ManagementMutationV2::UserCardCreate { .. } => ("user_card", "create"),
            ManagementMutationV2::UserCardStatus { status, .. } => match status {
                UserCardStatus::Active => ("user_card", "enable"),
                UserCardStatus::Disabled => ("user_card", "disable"),
            },
            ManagementMutationV2::RuleSetCreate { .. } => ("rule_set", "create"),
            ManagementMutationV2::RuleSetRetire { .. } => ("rule_set", "retire"),
            ManagementMutationV2::VersionPublish { .. } => ("rule_set", "version-publish"),
            ManagementMutationV2::ContextLoad { .. } => {
                return Err(CoordinatorError::InvalidAuditCandidate);
            }
        };
        let context = candidate.context();
        let actor_observation = context.actor();
        let scope = candidate.scope();
        let digest =
            digest_mutation(mutation).map_err(|_| CoordinatorError::CandidateUnavailable)?;
        let mut expected_summary =
            b"astrallight/memory-v1/governance-mutation-summary/1\0".to_vec();
        expected_summary.extend_from_slice(&digest);
        let summary_matches = candidate.change_summary().as_bytes() == expected_summary;
        let after_matches = match mutation {
            ManagementMutationV2::BindingCreate { .. } => matches!(
                candidate.after(),
                MemoryV1AuditObjectState::Binding(MemoryV1AuditBindingState::Active)
            ),
            ManagementMutationV2::BindingRemove { .. } => matches!(
                candidate.after(),
                MemoryV1AuditObjectState::Binding(MemoryV1AuditBindingState::Removed)
            ),
            ManagementMutationV2::ConfirmationCreate { .. } => matches!(
                candidate.after(),
                MemoryV1AuditObjectState::Confirmation(MemoryV1AuditConfirmationState::Active)
            ),
            ManagementMutationV2::ConfirmationRevoke { .. }
            | ManagementMutationV2::RuleSetChangeConfirmationRevoke { .. } => matches!(
                candidate.after(),
                MemoryV1AuditObjectState::Confirmation(MemoryV1AuditConfirmationState::Revoked)
            ),
            ManagementMutationV2::UserCardCreate { .. } => matches!(
                candidate.after(),
                MemoryV1AuditObjectState::UserCard(MemoryV1AuditCardState::Active)
            ),
            ManagementMutationV2::UserCardStatus { status, .. } => matches!(
                (status, candidate.after()),
                (
                    UserCardStatus::Active,
                    MemoryV1AuditObjectState::UserCard(MemoryV1AuditCardState::Active)
                ) | (
                    UserCardStatus::Disabled,
                    MemoryV1AuditObjectState::UserCard(MemoryV1AuditCardState::Disabled)
                )
            ),
            ManagementMutationV2::RuleSetCreate { .. } => matches!(
                candidate.after(),
                MemoryV1AuditObjectState::RuleSet(state)
                    if state.status() == Some(MemoryV1AuditRuleSetStatus::Active)
            ),
            ManagementMutationV2::RuleSetRetire { .. } => matches!(
                candidate.after(),
                MemoryV1AuditObjectState::RuleSet(state)
                    if state.status() == Some(MemoryV1AuditRuleSetStatus::Retired)
            ),
            ManagementMutationV2::VersionPublish { .. } => matches!(
                candidate.after(),
                MemoryV1AuditObjectState::RuleSet(state)
                    if state.status() == Some(MemoryV1AuditRuleSetStatus::Active)
            ),
            ManagementMutationV2::ConfirmationBatch { .. } => matches!(
                candidate.after(),
                MemoryV1AuditObjectState::Confirmation(MemoryV1AuditConfirmationState::Active)
            ),
            ManagementMutationV2::ContextLoad { .. } => {
                return Err(CoordinatorError::InvalidAuditCandidate);
            }
        };
        if actor_observation.user().into_bytes() != actor
            || candidate.target() != expected_target
            || scope != MemoryV1AuditObject::Tenant(MemoryId::from_bytes(target_tenant))
            || context.time().unix_seconds() != trusted_time_unix_seconds
            || context.action().resource() != expected_resource
            || context.action().action() != expected_action
            || !summary_matches
            || !after_matches
        {
            return Err(CoordinatorError::MutationAuditMismatch);
        }

        let audit_target_id = match candidate.target() {
            MemoryV1AuditObject::Tenant(id)
            | MemoryV1AuditObject::UserCard(id)
            | MemoryV1AuditObject::RuleSet(id)
            | MemoryV1AuditObject::Binding(id)
            | MemoryV1AuditObject::Confirmation(id)
            | MemoryV1AuditObject::User(id) => id.into_bytes(),
        };
        if audit_target_id != target {
            return Err(CoordinatorError::MutationAuditMismatch);
        }
        Ok(())
    }

    /// Build the exact mutation summary required by `validate_governance_binding`.
    pub fn governance_mutation_summary(
        mutation: &ManagementMutationV2,
    ) -> Result<astral_types::memory_v1_audit::MemoryV1AuditChangeSummary, CoordinatorError> {
        let digest =
            digest_mutation(mutation).map_err(|_| CoordinatorError::CandidateUnavailable)?;
        let mut summary = b"astrallight/memory-v1/governance-mutation-summary/1\0".to_vec();
        summary.extend_from_slice(&digest);
        astral_types::memory_v1_audit::MemoryV1AuditChangeSummary::new(&summary)
            .map_err(|_| CoordinatorError::CandidateUnavailable)
    }

    fn encode(&self) -> Result<Vec<u8>, CoordinatorError> {
        match self {
            Self::Single(candidate) => encode_t2_single_change_candidate(candidate),
            Self::Event(candidate) => encode_t2_candidate(candidate),
        }
        .map_err(|_| CoordinatorError::CandidateUnavailable)
    }

    fn kind_tag(&self) -> u8 {
        match self {
            Self::Single(_) => JOURNAL_PAYLOAD_SINGLE,
            Self::Event(_) => JOURNAL_PAYLOAD_EVENT,
        }
    }
}

/// Decoded mutation and complete audit values recovered from one journal payload.
///
/// This is a value-level recovery result. It proves that the bounded envelope and
/// both nested canonical wires agree with their recorded digests; it does not mint
/// a durable proof, establish root adoption, or authorize a replay.
#[derive(Clone, Debug)]
pub struct DecodedJournalPayload {
    mutation: ManagementMutationV2,
    audit: MutationAuditCandidate,
    mutation_digest: CoordinatorDigest,
    audit_digest: CoordinatorDigest,
}

impl DecodedJournalPayload {
    pub const fn mutation(&self) -> &ManagementMutationV2 {
        &self.mutation
    }

    pub const fn audit(&self) -> &MutationAuditCandidate {
        &self.audit
    }

    pub fn operation_id(&self) -> &str {
        self.audit.operation_id()
    }

    pub fn request_fingerprint(&self) -> &CoordinatorDigest {
        self.audit.fingerprint()
    }

    pub const fn mutation_digest(&self) -> CoordinatorDigest {
        self.mutation_digest
    }

    pub const fn audit_digest(&self) -> CoordinatorDigest {
        self.audit_digest
    }
}

/// Decode and verify one complete, canonical journal mutation envelope.
///
/// The outer journal frame remains responsible for stream ordering and checksum
/// chaining. This function only validates the bounded inner mutation envelope,
/// its component lengths, canonical nested wires, and independent value digests.
pub fn decode_journal_payload(bytes: &[u8]) -> Result<DecodedJournalPayload, CoordinatorError> {
    if bytes.len() > astral_types::memory_v1_journal::MAX_PAYLOAD_BYTES
        || bytes.len() < JOURNAL_PAYLOAD_HEADER_BYTES
    {
        return Err(CoordinatorError::InvalidJournalPayload);
    }
    let mut offset = 0_usize;
    let take = |offset: &mut usize, len: usize| -> Result<&[u8], CoordinatorError> {
        let end = offset
            .checked_add(len)
            .ok_or(CoordinatorError::InvalidJournalPayload)?;
        let value = bytes
            .get(*offset..end)
            .ok_or(CoordinatorError::InvalidJournalPayload)?;
        *offset = end;
        Ok(value)
    };
    if take(&mut offset, JOURNAL_PAYLOAD_DOMAIN.len())? != JOURNAL_PAYLOAD_DOMAIN {
        return Err(CoordinatorError::InvalidJournalPayload);
    }
    let version = u16::from_be_bytes(
        take(&mut offset, 2)?
            .try_into()
            .map_err(|_| CoordinatorError::InvalidJournalPayload)?,
    );
    if version != JOURNAL_PAYLOAD_VERSION {
        return Err(CoordinatorError::InvalidJournalPayload);
    }
    let kind = take(&mut offset, 1)?[0];
    if !matches!(kind, JOURNAL_PAYLOAD_SINGLE | JOURNAL_PAYLOAD_EVENT)
        || take(&mut offset, 1)?[0] != JOURNAL_PAYLOAD_FLAGS
    {
        return Err(CoordinatorError::InvalidJournalPayload);
    }
    let total_len = u32::from_be_bytes(
        take(&mut offset, 4)?
            .try_into()
            .map_err(|_| CoordinatorError::InvalidJournalPayload)?,
    ) as usize;
    let mutation_len = u32::from_be_bytes(
        take(&mut offset, 4)?
            .try_into()
            .map_err(|_| CoordinatorError::InvalidJournalPayload)?,
    ) as usize;
    let audit_len = u32::from_be_bytes(
        take(&mut offset, 4)?
            .try_into()
            .map_err(|_| CoordinatorError::InvalidJournalPayload)?,
    ) as usize;
    let mutation_digest: CoordinatorDigest = take(&mut offset, 32)?
        .try_into()
        .map_err(|_| CoordinatorError::InvalidJournalPayload)?;
    let audit_digest: CoordinatorDigest = take(&mut offset, 32)?
        .try_into()
        .map_err(|_| CoordinatorError::InvalidJournalPayload)?;
    let expected_total = JOURNAL_PAYLOAD_HEADER_BYTES
        .checked_add(mutation_len)
        .and_then(|value| value.checked_add(audit_len))
        .ok_or(CoordinatorError::InvalidJournalPayload)?;
    if total_len != bytes.len()
        || total_len != expected_total
        || total_len > astral_types::memory_v1_journal::MAX_PAYLOAD_BYTES
        || mutation_len == 0
        || audit_len == 0
    {
        return Err(CoordinatorError::InvalidJournalPayload);
    }
    let mutation_wire = take(&mut offset, mutation_len)?;
    let audit_wire = take(&mut offset, audit_len)?;
    if offset != bytes.len() {
        return Err(CoordinatorError::InvalidJournalPayload);
    }
    let mutation =
        decode_mutation(mutation_wire).map_err(|_| CoordinatorError::InvalidJournalPayload)?;
    if encode_mutation(&mutation).map_err(|_| CoordinatorError::InvalidJournalPayload)?
        != mutation_wire
    {
        return Err(CoordinatorError::InvalidJournalPayload);
    }
    let audit = match kind {
        JOURNAL_PAYLOAD_SINGLE => MutationAuditCandidate::Single(
            decode_t2_single_change_candidate(audit_wire)
                .map_err(|_| CoordinatorError::InvalidJournalPayload)?,
        ),
        JOURNAL_PAYLOAD_EVENT => MutationAuditCandidate::Event(
            decode_t2_candidate(audit_wire).map_err(|_| CoordinatorError::InvalidJournalPayload)?,
        ),
        _ => return Err(CoordinatorError::InvalidJournalPayload),
    };
    if audit
        .encode()
        .map_err(|_| CoordinatorError::InvalidJournalPayload)?
        != audit_wire
    {
        return Err(CoordinatorError::InvalidJournalPayload);
    }
    let computed_mutation_digest =
        digest_mutation(&mutation).map_err(|_| CoordinatorError::InvalidJournalPayload)?;
    let computed_audit_digest = digest_bytes(AUDIT_DIGEST_DOMAIN, audit_wire);
    if mutation_digest != computed_mutation_digest || audit_digest != computed_audit_digest {
        return Err(CoordinatorError::InvalidJournalPayload);
    }
    Ok(DecodedJournalPayload {
        mutation,
        audit,
        mutation_digest,
        audit_digest,
    })
}

fn journal_payload_len(mutation_len: usize, audit_len: usize) -> Result<usize, CoordinatorError> {
    let total = JOURNAL_PAYLOAD_HEADER_BYTES
        .checked_add(mutation_len)
        .and_then(|value| value.checked_add(audit_len))
        .ok_or(CoordinatorError::CandidateUnavailable)?;
    if mutation_len == 0
        || audit_len == 0
        || mutation_len > u32::MAX as usize
        || audit_len > u32::MAX as usize
        || total > u32::MAX as usize
        || total > astral_types::memory_v1_journal::MAX_PAYLOAD_BYTES
    {
        return Err(CoordinatorError::CandidateUnavailable);
    }
    Ok(total)
}

fn encode_journal_payload(
    mutation_wire: &[u8],
    audit_wire: &[u8],
    mutation_digest: CoordinatorDigest,
    audit_digest: CoordinatorDigest,
    kind: u8,
) -> Result<Vec<u8>, CoordinatorError> {
    let total = journal_payload_len(mutation_wire.len(), audit_wire.len())?;
    if !matches!(kind, JOURNAL_PAYLOAD_SINGLE | JOURNAL_PAYLOAD_EVENT) {
        return Err(CoordinatorError::InvalidJournalPayload);
    }
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(total)
        .map_err(|_| CoordinatorError::CandidateUnavailable)?;
    payload.extend_from_slice(JOURNAL_PAYLOAD_DOMAIN);
    payload.extend_from_slice(&JOURNAL_PAYLOAD_VERSION.to_be_bytes());
    payload.push(kind);
    payload.push(JOURNAL_PAYLOAD_FLAGS);
    payload.extend_from_slice(&(total as u32).to_be_bytes());
    payload.extend_from_slice(&(mutation_wire.len() as u32).to_be_bytes());
    payload.extend_from_slice(&(audit_wire.len() as u32).to_be_bytes());
    payload.extend_from_slice(&mutation_digest);
    payload.extend_from_slice(&audit_digest);
    payload.extend_from_slice(mutation_wire);
    payload.extend_from_slice(audit_wire);
    if payload.len() != total {
        return Err(CoordinatorError::CandidateUnavailable);
    }
    Ok(payload)
}

/// The immutable request envelope handed to the coordinator.
#[derive(Clone, Debug)]
pub struct MutationRequest {
    operation_id: String,
    request_fingerprint: CoordinatorDigest,
    mutation: ManagementMutationV2,
    mutation_digest: CoordinatorDigest,
    audit: MutationAuditCandidate,
    audit_digest: CoordinatorDigest,
    root: RootBinding,
    journal: JournalIdentity,
    payload_bytes: usize,
}

impl MutationRequest {
    /// Bind the mutation and complete T2 candidate to one operation identity.
    pub fn try_new(
        operation_id: &str,
        request_fingerprint: CoordinatorDigest,
        mutation: ManagementMutationV2,
        audit: MutationAuditCandidate,
        root: VerifiedRootAdmission,
        journal: JournalIdentity,
    ) -> Result<Self, CoordinatorError> {
        let root = root.binding();
        validate_operation_id(operation_id)?;
        if !nonzero_digest(&request_fingerprint) {
            return Err(CoordinatorError::InvalidFingerprint);
        }
        if !root.valid() {
            return Err(if root.status() == RootStatus::Serving {
                CoordinatorError::InvalidRootObservation
            } else {
                CoordinatorError::RootUnavailable
            });
        }
        if audit.decision() != MemoryV1AuditDecision::Allow {
            return Err(CoordinatorError::InvalidAuditCandidate);
        }
        if audit.operation_id() != operation_id || audit.fingerprint() != &request_fingerprint {
            return Err(CoordinatorError::AuditBindingMismatch);
        }
        if !audit.root_matches(root) {
            return Err(CoordinatorError::AuditBindingMismatch);
        }
        if audit
            .operation_id()
            .as_bytes()
            .iter()
            .any(|byte| !valid_operation_byte(*byte))
        {
            return Err(CoordinatorError::InvalidOperationId);
        }

        let mutation_wire =
            encode_mutation(&mutation).map_err(|_| CoordinatorError::CandidateUnavailable)?;
        let audit_wire = audit.encode()?;
        let mutation_digest =
            digest_mutation(&mutation).map_err(|_| CoordinatorError::CandidateUnavailable)?;
        let audit_digest = digest_bytes(AUDIT_DIGEST_DOMAIN, &audit_wire);
        let payload_bytes = journal_payload_len(mutation_wire.len(), audit_wire.len())?;
        Ok(Self {
            operation_id: operation_id.to_owned(),
            request_fingerprint,
            mutation,
            mutation_digest,
            audit,
            audit_digest,
            root,
            journal,
            payload_bytes,
        })
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub const fn request_fingerprint(&self) -> &CoordinatorDigest {
        &self.request_fingerprint
    }

    pub const fn mutation(&self) -> &ManagementMutationV2 {
        &self.mutation
    }

    pub const fn mutation_digest(&self) -> CoordinatorDigest {
        self.mutation_digest
    }

    pub const fn audit(&self) -> &MutationAuditCandidate {
        &self.audit
    }

    pub const fn audit_digest(&self) -> CoordinatorDigest {
        self.audit_digest
    }

    pub const fn root(&self) -> RootBinding {
        self.root
    }

    pub const fn journal(&self) -> JournalIdentity {
        self.journal
    }

    pub const fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }

    /// Encode the mutation and complete T2 audit candidate as one bounded journal
    /// payload. The returned bytes are a value envelope only; a journal owner
    /// must still bind the record to its operation identity and prove the durable
    /// prefix before constructing a `JournalDurableProof`.
    pub fn journal_payload(&self) -> Result<Vec<u8>, CoordinatorError> {
        let mutation_wire =
            encode_mutation(&self.mutation).map_err(|_| CoordinatorError::CandidateUnavailable)?;
        let audit_wire = self.audit.encode()?;
        let payload = encode_journal_payload(
            &mutation_wire,
            &audit_wire,
            self.mutation_digest,
            self.audit_digest,
            self.audit.kind_tag(),
        )?;
        if payload.len() != self.payload_bytes {
            return Err(CoordinatorError::CandidateUnavailable);
        }
        Ok(payload)
    }
}

/// Operation phases stored by the replay ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationStatus {
    Claimed,
    JournalPrepared,
    JournalDurable,
    RootPublished,
    Completed,
    Unknown,
}

/// A finite, in-process model of the operation identity gate.
///
/// This is intentionally not a durable ledger. Its purpose is to make replay,
/// digest conflict and capacity behavior explicit before a persistent owner is
/// implemented. Restarting it provides no evidence about an earlier operation.
#[derive(Debug)]
pub struct MemoryV1OperationLedger {
    capacity: usize,
    entries: BTreeMap<String, LedgerEntry>,
}

#[derive(Clone, Debug)]
struct LedgerEntry {
    digest: CoordinatorDigest,
    status: OperationStatus,
}

/// Opaque claim returned for a new operation identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationClaim {
    operation_id: String,
    mutation_digest: CoordinatorDigest,
}

impl OperationClaim {
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub const fn mutation_digest(&self) -> CoordinatorDigest {
        self.mutation_digest
    }
}

impl MemoryV1OperationLedger {
    pub fn new(capacity: usize) -> Result<Self, CoordinatorError> {
        if capacity == 0 || capacity > MAX_LEDGER_ENTRIES {
            return Err(CoordinatorError::CapacityExceeded);
        }
        Ok(Self {
            capacity,
            entries: BTreeMap::new(),
        })
    }

    /// Claim a new operation, or return a stable replay/conflict result.
    pub fn try_claim(
        &mut self,
        request: &MutationRequest,
    ) -> Result<OperationClaim, CoordinatorError> {
        if let Some(entry) = self.entries.get(request.operation_id()) {
            if entry.digest != request.mutation_digest() {
                return Err(CoordinatorError::DigestConflict);
            }
            return Err(CoordinatorError::ExistingOperation);
        }
        if self.entries.len() >= self.capacity {
            return Err(CoordinatorError::CapacityExceeded);
        }
        let claim = OperationClaim {
            operation_id: request.operation_id().to_owned(),
            mutation_digest: request.mutation_digest(),
        };
        self.entries.insert(
            claim.operation_id.clone(),
            LedgerEntry {
                digest: claim.mutation_digest,
                status: OperationStatus::Claimed,
            },
        );
        Ok(claim)
    }

    /// Inspect an existing identity without attempting a replay.
    pub fn status(&self, operation_id: &str) -> Option<OperationStatus> {
        self.entries.get(operation_id).map(|entry| entry.status)
    }

    /// Advance a claimed identity through the closed monotonic phase set.
    fn record_phase(
        &mut self,
        claim: &OperationClaim,
        next: OperationStatus,
    ) -> Result<(), CoordinatorError> {
        let entry = self
            .entries
            .get_mut(&claim.operation_id)
            .ok_or(CoordinatorError::ExistingOperation)?;
        if entry.digest != claim.mutation_digest || !valid_transition(entry.status, next) {
            return Err(CoordinatorError::InvalidTransition);
        }
        entry.status = next;
        Ok(())
    }

    /// Mark a known in-flight operation unknown; no automatic replay is exposed.
    pub fn mark_unknown(&mut self, claim: &OperationClaim) -> Result<(), CoordinatorError> {
        let entry = self
            .entries
            .get_mut(&claim.operation_id)
            .ok_or(CoordinatorError::ExistingOperation)?;
        if entry.digest != claim.mutation_digest
            || matches!(
                entry.status,
                OperationStatus::Completed | OperationStatus::Unknown
            )
        {
            return Err(CoordinatorError::InvalidTransition);
        }
        entry.status = OperationStatus::Unknown;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A newly claimed operation. It has no journal or root side effect yet.
#[derive(Clone, Debug)]
pub struct ClaimedMutation {
    request: MutationRequest,
    claim: OperationClaim,
}

impl ClaimedMutation {
    pub fn claim(
        ledger: &mut MemoryV1OperationLedger,
        request: MutationRequest,
    ) -> Result<Self, CoordinatorError> {
        let claim = ledger.try_claim(&request)?;
        Ok(Self { request, claim })
    }

    pub const fn request(&self) -> &MutationRequest {
        &self.request
    }

    pub const fn claim_token(&self) -> &OperationClaim {
        &self.claim
    }

    pub const fn phase(&self) -> OperationStatus {
        OperationStatus::Claimed
    }

    /// Accept only a reservation bound to this exact operation and payload size.
    pub fn prepare(
        self,
        ledger: &mut MemoryV1OperationLedger,
        reservation: JournalCapacityReservation,
    ) -> Result<JournalPreparedMutation, CoordinatorError> {
        if reservation.operation_id != self.request.operation_id
            || reservation.mutation_digest != self.request.mutation_digest
            || reservation.audit_digest != self.request.audit_digest
            || reservation.bytes < self.request.payload_bytes
            || reservation.slot == 0
        {
            return Err(CoordinatorError::InvalidJournalReservation);
        }
        ledger.record_phase(&self.claim, OperationStatus::JournalPrepared)?;
        Ok(JournalPreparedMutation {
            request: self.request,
            claim: self.claim,
            reservation,
        })
    }

    /// Convert a failure with unknown external outcome into a terminal local value.
    pub fn unknown(
        self,
        ledger: &mut MemoryV1OperationLedger,
        reason: UnknownReason,
    ) -> Result<UnknownMutation, CoordinatorError> {
        ledger.mark_unknown(&self.claim)?;
        Ok(UnknownMutation {
            operation_id: self.request.operation_id,
            mutation_digest: self.request.mutation_digest,
            phase: OperationStatus::Claimed,
            reason,
        })
    }
}

/// A bounded reservation made before constructing the journal message.
///
/// This is a candidate reservation only. It does not reserve allocator/RSS
/// memory and does not prove a file or device write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalCapacityReservation {
    operation_id: String,
    mutation_digest: CoordinatorDigest,
    audit_digest: CoordinatorDigest,
    bytes: usize,
    slot: u64,
}

impl JournalCapacityReservation {
    /// Create a value-level reservation request. A real owner must replace this
    /// with an actual CAS/lease-backed capacity reservation before adoption.
    pub fn candidate(
        operation_id: &str,
        mutation_digest: CoordinatorDigest,
        audit_digest: CoordinatorDigest,
        bytes: usize,
        slot: u64,
    ) -> Result<Self, CoordinatorError> {
        validate_operation_id(operation_id)?;
        if bytes == 0 || slot == 0 {
            return Err(CoordinatorError::InvalidJournalReservation);
        }
        Ok(Self {
            operation_id: operation_id.to_owned(),
            mutation_digest,
            audit_digest,
            bytes,
            slot,
        })
    }

    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    pub const fn slot(&self) -> u64 {
        self.slot
    }
}

/// A mutation whose message and audit bytes have been prepared under a bound reservation.
#[derive(Clone, Debug)]
pub struct JournalPreparedMutation {
    request: MutationRequest,
    claim: OperationClaim,
    reservation: JournalCapacityReservation,
}

impl JournalPreparedMutation {
    pub const fn request(&self) -> &MutationRequest {
        &self.request
    }

    pub const fn claim(&self) -> &OperationClaim {
        &self.claim
    }

    pub const fn reservation(&self) -> &JournalCapacityReservation {
        &self.reservation
    }

    pub const fn phase(&self) -> OperationStatus {
        OperationStatus::JournalPrepared
    }

    /// Accept a proof minted by the journal owner after durable prefix advancement.
    pub fn record_journal_durable(
        self,
        ledger: &mut MemoryV1OperationLedger,
        proof: JournalDurableProof,
    ) -> Result<JournalDurableMutation, CoordinatorError> {
        proof.matches_request(&self.request)?;
        ledger.record_phase(&self.claim, OperationStatus::JournalDurable)?;
        Ok(JournalDurableMutation {
            request: self.request,
            claim: self.claim,
            reservation: self.reservation,
            proof,
        })
    }

    pub fn unknown(
        self,
        ledger: &mut MemoryV1OperationLedger,
        reason: UnknownReason,
    ) -> Result<UnknownMutation, CoordinatorError> {
        ledger.mark_unknown(&self.claim)?;
        Ok(UnknownMutation {
            operation_id: self.request.operation_id,
            mutation_digest: self.request.mutation_digest,
            phase: OperationStatus::JournalPrepared,
            reason,
        })
    }
}

/// A mutation covered by a trusted continuous local durable-prefix proof.
#[derive(Clone, Debug)]
pub struct JournalDurableMutation {
    request: MutationRequest,
    claim: OperationClaim,
    reservation: JournalCapacityReservation,
    proof: JournalDurableProof,
}

impl JournalDurableMutation {
    pub const fn request(&self) -> &MutationRequest {
        &self.request
    }

    pub const fn claim(&self) -> &OperationClaim {
        &self.claim
    }

    pub const fn proof(&self) -> &JournalDurableProof {
        &self.proof
    }

    pub const fn phase(&self) -> OperationStatus {
        OperationStatus::JournalDurable
    }

    /// Publish only with a proof that binds the exact journal prefix to one root CAS.
    pub fn publish_root(
        self,
        ledger: &mut MemoryV1OperationLedger,
        proof: RootPublicationProof,
    ) -> Result<RootPublishedMutation, CoordinatorError> {
        proof.matches_request_and_journal(&self.request, &self.proof)?;
        ledger.record_phase(&self.claim, OperationStatus::RootPublished)?;
        Ok(RootPublishedMutation {
            request: self.request,
            claim: self.claim,
            reservation: self.reservation,
            journal_proof: self.proof,
            root_proof: proof,
            db_progress: None,
        })
    }

    pub fn unknown(
        self,
        ledger: &mut MemoryV1OperationLedger,
        reason: UnknownReason,
    ) -> Result<UnknownMutation, CoordinatorError> {
        ledger.mark_unknown(&self.claim)?;
        Ok(UnknownMutation {
            operation_id: self.request.operation_id,
            mutation_digest: self.request.mutation_digest,
            phase: OperationStatus::JournalDurable,
            reason,
        })
    }
}

/// A proof that the root owner atomically published facts, indexes and the
/// pending message link represented by one journal durable proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootPublicationProof {
    operation_id: String,
    mutation_digest: CoordinatorDigest,
    audit_digest: CoordinatorDigest,
    journal: JournalIdentity,
    before: RootBinding,
    after: RootBinding,
    atomic_link: CoordinatorDigest,
}

impl RootPublicationProof {
    fn matches_request_and_journal(
        &self,
        request: &MutationRequest,
        journal: &JournalDurableProof,
    ) -> Result<(), CoordinatorError> {
        if self.operation_id != request.operation_id
            || self.mutation_digest != request.mutation_digest
            || self.audit_digest != request.audit_digest
            || self.journal != journal.identity
            || self.before != request.root
            || self.after.instance_id() != self.before.instance_id()
            || self.after.version() != self.before.version().saturating_add(1)
            || !self.after.valid()
            || self.atomic_link
                != publication_link(
                    &self.operation_id,
                    self.mutation_digest,
                    self.audit_digest,
                    self.journal,
                    self.before,
                    self.after,
                )
        {
            return Err(CoordinatorError::ProofMismatch);
        }
        Ok(())
    }
}

impl RootPublicationProof {
    /// Mint the publication proof for one verified root CAS performed by the
    /// single-node commit owner while it already holds the journal durable proof.
    /// The proof is only as trustworthy as its issuer: the owner must have
    /// observed both `before` and `after` metadata under the root writer lock
    /// and published them in the exact journal identity of the durable proof.
    /// This stays a trust-boundary API for the composition owner only.
    #[doc(hidden)]
    pub fn mint_for_owner(
        request: &MutationRequest,
        journal: &JournalDurableProof,
        after: RootBinding,
    ) -> Self {
        Self {
            operation_id: request.operation_id().to_owned(),
            mutation_digest: request.mutation_digest(),
            audit_digest: request.audit_digest(),
            journal: journal.identity(),
            before: request.root(),
            after,
            atomic_link: publication_link(
                request.operation_id(),
                request.mutation_digest(),
                request.audit_digest(),
                journal.identity(),
                request.root(),
                after,
            ),
        }
    }
}

impl JournalDurableProof {
    /// Mint the durable-prefix proof from the journal owner's own receipt.
    /// The receipt is only trustworthy when its issuer is this process's single
    /// durable journal owner; a caller who did not observe the file/directory
    /// synchronization cannot mint it. Trust-boundary API for the owner only.
    #[doc(hidden)]
    pub fn mint_for_owner(
        request: &MutationRequest,
        operation_id: &str,
        request_fingerprint: CoordinatorDigest,
        mutation_digest: CoordinatorDigest,
        audit_digest: CoordinatorDigest,
        identity: JournalIdentity,
        tail_hash: CoordinatorDigest,
    ) -> Self {
        let _ = request;
        Self {
            operation_id: operation_id.to_owned(),
            request_fingerprint,
            mutation_digest,
            audit_digest,
            identity,
            tail_hash,
        }
    }
}

/// A mutation after the root/pending-message atomic publication boundary.
#[derive(Clone, Debug)]
pub struct RootPublishedMutation {
    request: MutationRequest,
    claim: OperationClaim,
    reservation: JournalCapacityReservation,
    journal_proof: JournalDurableProof,
    root_proof: RootPublicationProof,
    db_progress: Option<DatabaseProgressProof>,
}

impl RootPublishedMutation {
    pub const fn request(&self) -> &MutationRequest {
        &self.request
    }

    pub const fn claim(&self) -> &OperationClaim {
        &self.claim
    }

    pub const fn root_proof(&self) -> &RootPublicationProof {
        &self.root_proof
    }

    pub const fn reservation(&self) -> &JournalCapacityReservation {
        &self.reservation
    }

    pub const fn phase(&self) -> OperationStatus {
        OperationStatus::RootPublished
    }

    pub const fn has_db_progress(&self) -> bool {
        self.db_progress.is_some()
    }

    pub fn attach_db_progress(
        mut self,
        proof: DatabaseProgressProof,
    ) -> Result<Self, CoordinatorError> {
        proof.matches_request_and_journal(&self.request, &self.journal_proof)?;
        self.db_progress = Some(proof);
        Ok(self)
    }

    pub fn complete(
        self,
        ledger: &mut MemoryV1OperationLedger,
    ) -> Result<MutationCompletion, CoordinatorError> {
        ledger.record_phase(&self.claim, OperationStatus::Completed)?;
        Ok(MutationCompletion {
            operation_id: self.request.operation_id,
            mutation_digest: self.request.mutation_digest,
            root: self.root_proof.after,
            journal: self.journal_proof.identity,
            db_progress: self.db_progress,
        })
    }

    pub fn unknown(
        self,
        ledger: &mut MemoryV1OperationLedger,
        reason: UnknownReason,
    ) -> Result<UnknownMutation, CoordinatorError> {
        ledger.mark_unknown(&self.claim)?;
        Ok(UnknownMutation {
            operation_id: self.request.operation_id,
            mutation_digest: self.request.mutation_digest,
            phase: OperationStatus::RootPublished,
            reason,
        })
    }
}

/// A response-ready candidate after local durable prefix and root publication.
///
/// This value is not an HTTP response and does not install a route or listener.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationCompletion {
    operation_id: String,
    mutation_digest: CoordinatorDigest,
    root: RootBinding,
    journal: JournalIdentity,
    db_progress: Option<DatabaseProgressProof>,
}

impl MutationCompletion {
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub const fn mutation_digest(&self) -> CoordinatorDigest {
        self.mutation_digest
    }

    pub const fn root(&self) -> RootBinding {
        self.root
    }

    pub const fn journal(&self) -> JournalIdentity {
        self.journal
    }

    pub const fn has_db_progress(&self) -> bool {
        self.db_progress.is_some()
    }

    pub const fn phase(&self) -> OperationStatus {
        OperationStatus::Completed
    }
}

/// An external outcome that cannot be classified as committed or absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnknownReason {
    JournalWrite,
    JournalFlush,
    RootPublication,
    DatabaseCommit,
    RecoveryBoundary,
}

/// Terminal local representation of an unknown outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnknownMutation {
    operation_id: String,
    mutation_digest: CoordinatorDigest,
    phase: OperationStatus,
    reason: UnknownReason,
}

impl UnknownMutation {
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub const fn mutation_digest(&self) -> CoordinatorDigest {
        self.mutation_digest
    }

    pub const fn phase(&self) -> OperationStatus {
        self.phase
    }

    pub const fn reason(&self) -> UnknownReason {
        self.reason
    }

    /// Unknown outcomes are never automatically replayable.
    pub const fn can_auto_retry(&self) -> bool {
        false
    }
}

/// Proof minted only after the journal owner has verified a continuous durable prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalDurableProof {
    operation_id: String,
    request_fingerprint: CoordinatorDigest,
    mutation_digest: CoordinatorDigest,
    audit_digest: CoordinatorDigest,
    identity: JournalIdentity,
    tail_hash: CoordinatorDigest,
}

impl JournalDurableProof {
    fn matches_request(&self, request: &MutationRequest) -> Result<(), CoordinatorError> {
        if self.operation_id != request.operation_id
            || self.request_fingerprint != request.request_fingerprint
            || self.mutation_digest != request.mutation_digest
            || self.audit_digest != request.audit_digest
            || self.identity != request.journal
            || !nonzero_digest(&self.tail_hash)
        {
            return Err(CoordinatorError::ProofMismatch);
        }
        Ok(())
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub const fn identity(&self) -> JournalIdentity {
        self.identity
    }

    pub const fn tail_hash(&self) -> &CoordinatorDigest {
        &self.tail_hash
    }
}

/// Ordered DB receipt/progress proof. It is optional for A/A1 success.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DatabaseProgressProof {
    operation_id: String,
    mutation_digest: CoordinatorDigest,
    audit_digest: CoordinatorDigest,
    journal: JournalIdentity,
    receipt_id: MemoryId,
    progress_sequence: u64,
}

impl DatabaseProgressProof {
    fn matches_request_and_journal(
        &self,
        request: &MutationRequest,
        journal: &JournalDurableProof,
    ) -> Result<(), CoordinatorError> {
        if self.operation_id != request.operation_id
            || self.mutation_digest != request.mutation_digest
            || self.audit_digest != request.audit_digest
            || self.journal != journal.identity
            || !nonzero_id(self.receipt_id)
            || self.progress_sequence < self.journal.journal_sequence()
        {
            return Err(CoordinatorError::InvalidDatabaseProgress);
        }
        Ok(())
    }
}

/// One complete DENY value bound to one journal identity.
///
/// The observation is the evaluator's complete read-phase value; the journal
/// identity is the append target. The payload envelope and its digest are
/// derived here so the journal owner appends exactly these bytes.
#[derive(Clone, Debug)]
pub struct DenyJournalRequest {
    observation: MemoryV1DenyObservation,
    identity: JournalIdentity,
    operation_id: String,
    payload_bytes: usize,
}

impl DenyJournalRequest {
    /// Bind one observation to the next contiguous journal identity.
    pub fn try_new(
        observation: MemoryV1DenyObservation,
        identity: JournalIdentity,
    ) -> Result<Self, CoordinatorError> {
        let operation_id_bytes = observation.operation_id().to_vec();
        let operation_id = std::str::from_utf8(&operation_id_bytes)
            .map_err(|_| CoordinatorError::InvalidOperationId)?
            .to_owned();
        validate_operation_id(&operation_id)?;
        if observation.root().status() != MemoryV1AuditRootStatus::Serving {
            return Err(CoordinatorError::RootUnavailable);
        }
        if observation.root().digest() == &[0; 32] {
            return Err(CoordinatorError::InvalidRootObservation);
        }
        if observation.operation_fingerprint().len() != 32 {
            return Err(CoordinatorError::InvalidFingerprint);
        }
        let wire = astral_types::memory_v1_deny_observation::encode_memory_v1_deny_observation(
            &observation,
        )
        .map_err(|_| CoordinatorError::CandidateUnavailable)?;
        let payload_len = DENY_PAYLOAD_HEADER_BYTES
            .checked_add(wire.len())
            .ok_or(CoordinatorError::CandidateUnavailable)?;
        if payload_len > astral_types::memory_v1_journal::MAX_PAYLOAD_BYTES {
            return Err(CoordinatorError::CandidateUnavailable);
        }
        Ok(Self {
            observation,
            identity,
            operation_id,
            payload_bytes: payload_len,
        })
    }

    /// The observation supplied at construction.
    pub const fn observation(&self) -> &MemoryV1DenyObservation {
        &self.observation
    }

    /// The append target identity.
    pub const fn journal(&self) -> JournalIdentity {
        self.identity
    }

    /// The operation identifier of the denied request.
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// The exact encoded payload length.
    pub const fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }

    /// The domain-separated digest of the durable observation value.
    pub fn audit_digest(&self) -> CoordinatorDigest {
        let wire = astral_types::memory_v1_deny_observation::encode_memory_v1_deny_observation(
            &self.observation,
        )
        .expect("validated observation re-encodes");
        digest_bytes(DENY_AUDIT_DIGEST_DOMAIN, &wire)
    }

    /// The exact journal payload: domain, version, flags, total length,
    /// observation length, observation digest, then the observation wire.
    pub fn journal_payload(&self) -> Result<Vec<u8>, CoordinatorError> {
        let wire = astral_types::memory_v1_deny_observation::encode_memory_v1_deny_observation(
            &self.observation,
        )
        .map_err(|_| CoordinatorError::CandidateUnavailable)?;
        let observation_digest = digest_bytes(DENY_AUDIT_DIGEST_DOMAIN, &wire);
        let total = DENY_PAYLOAD_HEADER_BYTES
            .checked_add(wire.len())
            .ok_or(CoordinatorError::CandidateUnavailable)?;
        if total > astral_types::memory_v1_journal::MAX_PAYLOAD_BYTES {
            return Err(CoordinatorError::CandidateUnavailable);
        }
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(total)
            .map_err(|_| CoordinatorError::CandidateUnavailable)?;
        payload.extend_from_slice(DENY_PAYLOAD_DOMAIN);
        payload.extend_from_slice(&DENY_PAYLOAD_VERSION.to_be_bytes());
        payload.push(JOURNAL_PAYLOAD_FLAGS);
        payload.extend_from_slice(&(total as u32).to_be_bytes());
        payload.extend_from_slice(&(wire.len() as u32).to_be_bytes());
        payload.extend_from_slice(&observation_digest);
        payload.extend_from_slice(&wire);
        if payload.len() != self.payload_bytes {
            return Err(CoordinatorError::CandidateUnavailable);
        }
        Ok(payload)
    }

    /// The fingerprint carried by the observation (32 bytes, validated).
    pub fn request_fingerprint(&self) -> CoordinatorDigest {
        self.observation
            .operation_fingerprint()
            .try_into()
            .expect("validated fingerprint length")
    }
}

/// Decode and verify one canonical DENY journal payload.
///
/// The outer journal frame still owns stream ordering and checksum chaining;
/// this validates the bounded inner envelope and its observation digest.
pub fn decode_deny_journal_payload(
    bytes: &[u8],
) -> Result<MemoryV1DenyObservation, CoordinatorError> {
    if bytes.len() > astral_types::memory_v1_journal::MAX_PAYLOAD_BYTES
        || bytes.len() < DENY_PAYLOAD_HEADER_BYTES
    {
        return Err(CoordinatorError::InvalidJournalPayload);
    }
    let mut offset = 0_usize;
    let take = |offset: &mut usize, len: usize| -> Result<&[u8], CoordinatorError> {
        let end = offset
            .checked_add(len)
            .ok_or(CoordinatorError::InvalidJournalPayload)?;
        let value = bytes
            .get(*offset..end)
            .ok_or(CoordinatorError::InvalidJournalPayload)?;
        *offset = end;
        Ok(value)
    };
    if take(&mut offset, DENY_PAYLOAD_DOMAIN.len())? != DENY_PAYLOAD_DOMAIN {
        return Err(CoordinatorError::InvalidJournalPayload);
    }
    let version = u16::from_be_bytes(
        take(&mut offset, 2)?
            .try_into()
            .map_err(|_| CoordinatorError::InvalidJournalPayload)?,
    );
    if version != DENY_PAYLOAD_VERSION || take(&mut offset, 1)?[0] != JOURNAL_PAYLOAD_FLAGS {
        return Err(CoordinatorError::InvalidJournalPayload);
    }
    let total_len = u32::from_be_bytes(
        take(&mut offset, 4)?
            .try_into()
            .map_err(|_| CoordinatorError::InvalidJournalPayload)?,
    ) as usize;
    let observation_len = u32::from_be_bytes(
        take(&mut offset, 4)?
            .try_into()
            .map_err(|_| CoordinatorError::InvalidJournalPayload)?,
    ) as usize;
    let observation_digest: CoordinatorDigest = take(&mut offset, 32)?
        .try_into()
        .map_err(|_| CoordinatorError::InvalidJournalPayload)?;
    if total_len != bytes.len()
        || DENY_PAYLOAD_HEADER_BYTES
            .checked_add(observation_len)
            .is_none_or(|expected| expected != total_len)
    {
        return Err(CoordinatorError::InvalidJournalPayload);
    }
    let observation_wire = take(&mut offset, observation_len)?;
    if offset != bytes.len() {
        return Err(CoordinatorError::InvalidJournalPayload);
    }
    if digest_bytes(DENY_AUDIT_DIGEST_DOMAIN, observation_wire) != observation_digest {
        return Err(CoordinatorError::InvalidJournalPayload);
    }
    astral_types::memory_v1_deny_observation::decode_memory_v1_deny_observation(observation_wire)
        .map_err(|_| CoordinatorError::InvalidJournalPayload)
}

/// A journal stream/epoch watermark identifying the authorization state read by
/// a DENY evaluation. The sequence values are evidence inputs only; they are
/// not a durable-prefix proof until a journal owner verifies them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalReadWatermark {
    stream_id: MemoryId,
    epoch_id: MemoryId,
    journal_sequence: u64,
    mutation_sequence: u64,
}

impl JournalReadWatermark {
    pub fn new(
        stream_id: MemoryId,
        epoch_id: MemoryId,
        journal_sequence: u64,
        mutation_sequence: u64,
    ) -> Result<Self, CoordinatorError> {
        if !nonzero_id(stream_id)
            || !nonzero_id(epoch_id)
            || journal_sequence == 0
            || mutation_sequence == 0
        {
            return Err(CoordinatorError::InvalidJournalIdentity);
        }
        Ok(Self {
            stream_id,
            epoch_id,
            journal_sequence,
            mutation_sequence,
        })
    }

    /// Watermark for a DENY, including the verified external baseline `(0, 0)`.
    pub fn new_deny(
        stream_id: MemoryId,
        epoch_id: MemoryId,
        journal_sequence: u64,
        mutation_sequence: u64,
    ) -> Result<Self, CoordinatorError> {
        if !nonzero_id(stream_id) || !nonzero_id(epoch_id) || mutation_sequence > journal_sequence {
            return Err(CoordinatorError::InvalidJournalIdentity);
        }
        Ok(Self {
            stream_id,
            epoch_id,
            journal_sequence,
            mutation_sequence,
        })
    }

    pub const fn stream_id(self) -> MemoryId {
        self.stream_id
    }

    pub const fn epoch_id(self) -> MemoryId {
        self.epoch_id
    }

    pub const fn journal_sequence(self) -> u64 {
        self.journal_sequence
    }

    pub const fn mutation_sequence(self) -> u64 {
        self.mutation_sequence
    }
}

/// The two independent proofs required before a DENY may become HTTP 403.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DenyProofRequest {
    operation_id: [u8; MAX_OPERATION_ID_BYTES],
    operation_id_len: u8,
    request_fingerprint: CoordinatorDigest,
    root: RootBinding,
    read_journal: JournalReadWatermark,
    source: MemoryV1AuditDenySource,
}

impl DenyProofRequest {
    pub fn try_new(
        operation_id: &str,
        request_fingerprint: CoordinatorDigest,
        root: VerifiedRootAdmission,
        read_journal: JournalReadWatermark,
        source: MemoryV1AuditDenySource,
    ) -> Result<Self, CoordinatorError> {
        let root = root.binding();
        validate_operation_id(operation_id)?;
        // A read DENY may carry the zero fingerprint when the request had no
        // operation binding; the value is proven as-is by the durable record.
        if !root.valid() {
            return Err(CoordinatorError::RootUnavailable);
        }
        let mut stored = [0u8; MAX_OPERATION_ID_BYTES];
        stored[..operation_id.len()].copy_from_slice(operation_id.as_bytes());
        Ok(Self {
            operation_id: stored,
            operation_id_len: operation_id.len() as u8,
            request_fingerprint,
            root,
            read_journal,
            source,
        })
    }

    pub fn operation_id(&self) -> &str {
        std::str::from_utf8(&self.operation_id[..self.operation_id_len as usize])
            .expect("validated operation identity")
    }

    pub const fn root(&self) -> RootBinding {
        self.root
    }

    pub const fn source(&self) -> MemoryV1AuditDenySource {
        self.source
    }

    pub const fn read_journal(&self) -> JournalReadWatermark {
        self.read_journal
    }
}

/// A DENY audit proof with no authorization-state coverage claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenyAuditProof {
    operation_id: String,
    request_fingerprint: CoordinatorDigest,
    root: RootBinding,
    source: MemoryV1AuditDenySource,
    audit_digest: CoordinatorDigest,
}

impl DenyAuditProof {
    /// Mint the audit proof from the journal owner's own DENY receipt. The
    /// digest binds the exact durable observation bytes; only the single
    /// journal owner that synchronized them may call this.
    #[doc(hidden)]
    pub fn mint_for_owner(
        operation_id: &str,
        request_fingerprint: CoordinatorDigest,
        root: RootBinding,
        source: MemoryV1AuditDenySource,
        audit_digest: CoordinatorDigest,
    ) -> Self {
        Self {
            operation_id: operation_id.to_owned(),
            request_fingerprint,
            root,
            source,
            audit_digest,
        }
    }
}

/// A prefix proof covering the exact authorization state read by the DENY.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationStatePrefixProof {
    operation_id: String,
    request_fingerprint: CoordinatorDigest,
    root: RootBinding,
    stream_id: MemoryId,
    epoch_id: MemoryId,
    journal_sequence: u64,
    mutation_sequence: u64,
    tail_hash: CoordinatorDigest,
    state_digest: CoordinatorDigest,
}

impl AuthorizationStatePrefixProof {
    /// Mint the prefix proof from the journal owner's own tail after the DENY
    /// record appended. The state digest must equal the read root's digest;
    /// only the single journal owner may call this.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn mint_for_owner(
        operation_id: &str,
        request_fingerprint: CoordinatorDigest,
        root: RootBinding,
        identity: JournalIdentity,
        tail_hash: CoordinatorDigest,
    ) -> Self {
        Self {
            operation_id: operation_id.to_owned(),
            request_fingerprint,
            root,
            stream_id: identity.stream_id(),
            epoch_id: identity.epoch_id(),
            journal_sequence: identity.journal_sequence(),
            mutation_sequence: identity.mutation_sequence(),
            tail_hash,
            state_digest: root.digest(),
        }
    }
}

/// HTTP-level outcome selected by the DENY proof gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenyResponse {
    Forbidden,
    ServiceUnavailable,
}

impl DenyResponse {
    pub const fn status_code(self) -> u16 {
        match self {
            Self::Forbidden => 403,
            Self::ServiceUnavailable => 503,
        }
    }
}

/// Independent DENY proof collector. Missing or mismatched proof remains 503.
#[derive(Clone, Debug)]
pub struct DenyProofGate {
    request: DenyProofRequest,
    audit: Option<DenyAuditProof>,
    prefix: Option<AuthorizationStatePrefixProof>,
}

impl DenyProofGate {
    pub const fn new(request: DenyProofRequest) -> Self {
        Self {
            request,
            audit: None,
            prefix: None,
        }
    }

    pub const fn request(&self) -> &DenyProofRequest {
        &self.request
    }

    pub fn record_audit(&mut self, proof: DenyAuditProof) -> Result<(), CoordinatorError> {
        if proof.operation_id != self.request.operation_id()
            || proof.request_fingerprint != self.request.request_fingerprint
            || proof.root != self.request.root
            || proof.source != self.request.source
            || !nonzero_digest(&proof.audit_digest)
        {
            return Err(CoordinatorError::InvalidDenyProof);
        }
        self.audit = Some(proof);
        Ok(())
    }

    pub fn record_prefix(
        &mut self,
        proof: AuthorizationStatePrefixProof,
    ) -> Result<(), CoordinatorError> {
        if proof.operation_id != self.request.operation_id()
            || proof.request_fingerprint != self.request.request_fingerprint
            || proof.root != self.request.root
            || proof.stream_id != self.request.read_journal.stream_id
            || proof.epoch_id != self.request.read_journal.epoch_id
            || proof.journal_sequence < self.request.read_journal.journal_sequence
            || proof.mutation_sequence < self.request.read_journal.mutation_sequence
            || !nonzero_id(proof.stream_id)
            || !nonzero_id(proof.epoch_id)
            || proof.journal_sequence == 0
            || !nonzero_digest(&proof.tail_hash)
            || proof.state_digest != self.request.root.digest()
        {
            return Err(CoordinatorError::InvalidDenyProof);
        }
        self.prefix = Some(proof);
        Ok(())
    }

    pub const fn response(&self) -> DenyResponse {
        if self.audit.is_some() && self.prefix.is_some() {
            DenyResponse::Forbidden
        } else {
            DenyResponse::ServiceUnavailable
        }
    }
}

fn validate_operation_id(operation_id: &str) -> Result<(), CoordinatorError> {
    if operation_id.is_empty()
        || operation_id.len() > MAX_OPERATION_ID_BYTES
        || !operation_id.bytes().all(valid_operation_byte)
    {
        return Err(CoordinatorError::InvalidOperationId);
    }
    Ok(())
}

fn valid_operation_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-_.:/".contains(&byte)
}

fn nonzero_id(id: MemoryId) -> bool {
    id.as_bytes().iter().any(|byte| *byte != 0)
}

fn nonzero_digest(digest: &CoordinatorDigest) -> bool {
    digest.iter().any(|byte| *byte != 0)
}

fn digest_bytes(domain: &[u8], bytes: &[u8]) -> CoordinatorDigest {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    hash.finalize().into()
}

fn publication_link(
    operation_id: &str,
    mutation_digest: CoordinatorDigest,
    audit_digest: CoordinatorDigest,
    journal: JournalIdentity,
    before: RootBinding,
    after: RootBinding,
) -> CoordinatorDigest {
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(operation_id.as_bytes());
    bytes.extend_from_slice(&mutation_digest);
    bytes.extend_from_slice(&audit_digest);
    bytes.extend_from_slice(journal.stream_id.as_bytes());
    bytes.extend_from_slice(journal.epoch_id.as_bytes());
    bytes.extend_from_slice(&journal.journal_sequence.to_be_bytes());
    bytes.extend_from_slice(&journal.mutation_sequence.to_be_bytes());
    bytes.extend_from_slice(journal.message_id.as_bytes());
    bytes.extend_from_slice(before.instance_id.as_uuid().as_bytes());
    bytes.extend_from_slice(&before.version.to_be_bytes());
    bytes.extend_from_slice(&before.digest);
    bytes.extend_from_slice(after.instance_id.as_uuid().as_bytes());
    bytes.extend_from_slice(&after.version.to_be_bytes());
    bytes.extend_from_slice(&after.digest);
    digest_bytes(PUBLICATION_LINK_DOMAIN, &bytes)
}

fn valid_transition(from: OperationStatus, to: OperationStatus) -> bool {
    matches!(
        (from, to),
        (OperationStatus::Claimed, OperationStatus::JournalPrepared)
            | (OperationStatus::Claimed, OperationStatus::Unknown)
            | (
                OperationStatus::JournalPrepared,
                OperationStatus::JournalDurable
            )
            | (OperationStatus::JournalPrepared, OperationStatus::Unknown)
            | (
                OperationStatus::JournalDurable,
                OperationStatus::RootPublished
            )
            | (OperationStatus::JournalDurable, OperationStatus::Unknown)
            | (OperationStatus::RootPublished, OperationStatus::Completed)
            | (OperationStatus::RootPublished, OperationStatus::Unknown)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_authorization_root::memory_v1_db_rows::UserCardStatus;
    use astral_types::memory_v1_audit::{
        MemoryV1AuditAction, MemoryV1AuditActor, MemoryV1AuditChange, MemoryV1AuditChangeSummary,
        MemoryV1AuditConfirmationRef, MemoryV1AuditConfirmations, MemoryV1AuditContext,
        MemoryV1AuditDecisionInput, MemoryV1AuditEvent, MemoryV1AuditObject,
        MemoryV1AuditObjectState, MemoryV1AuditRootObservation, MemoryV1AuditRootStatus,
        MemoryV1AuditRootVersion, MemoryV1AuditSource, MemoryV1AuditT2SingleChangeCandidate,
        MemoryV1AuditTime,
    };
    use uuid::Uuid;

    fn id(value: u8) -> MemoryId {
        MemoryId::from_bytes([value; 16])
    }

    fn root() -> VerifiedRootAdmission {
        VerifiedRootAdmission::for_contract_tests(RootBinding::new(
            RootInstanceId::from_uuid(Uuid::from_bytes([1; 16])),
            7,
            [7; 32],
            RootStatus::Serving,
        ))
    }

    fn audit(operation_id: &str, fingerprint: CoordinatorDigest) -> MutationAuditCandidate {
        let context = MemoryV1AuditContext::new(
            MemoryV1AuditActor::new(id(2), id(3)),
            MemoryV1AuditTime::new(100).unwrap(),
            MemoryV1AuditAction::new("user_card", "disable").unwrap(),
            "MANAGEMENT_MUTATION",
            astral_types::memory_v1_audit::MemoryV1AuditOperation::new(operation_id, fingerprint)
                .unwrap(),
            MemoryV1AuditRootObservation::new(
                MemoryV1AuditRootVersion::new(id(1), 7),
                [7; 32],
                MemoryV1AuditRootStatus::Serving,
            ),
        )
        .unwrap();
        let change = MemoryV1AuditChange::new(
            Some(id(2)),
            Some(MemoryV1AuditObject::UserCard(id(4))),
            Some(MemoryV1AuditObject::Tenant(id(5))),
            Some(MemoryV1AuditChangeSummary::new(&[6; 32]).unwrap()),
            Some(MemoryV1AuditObjectState::UserCard(
                astral_types::memory_v1_audit::MemoryV1AuditCardState::Active,
            )),
            Some(MemoryV1AuditObjectState::UserCard(
                astral_types::memory_v1_audit::MemoryV1AuditCardState::Disabled,
            )),
            Some(
                MemoryV1AuditConfirmations::references(&[MemoryV1AuditConfirmationRef::Binding(
                    id(8),
                )])
                .unwrap(),
            ),
            Some(MemoryV1AuditRootVersion::new(id(1), 7)),
            Some(MemoryV1AuditRootVersion::new(id(1), 8)),
            MemoryV1AuditSource::Ordinary,
        );
        MutationAuditCandidate::Single(
            MemoryV1AuditT2SingleChangeCandidate::try_from(
                MemoryV1AuditEvent::change(context, MemoryV1AuditDecisionInput::Allow, change)
                    .unwrap(),
            )
            .unwrap(),
        )
    }

    fn request(operation_id: &str, status: UserCardStatus) -> MutationRequest {
        let fingerprint = [4; 32];
        MutationRequest::try_new(
            operation_id,
            fingerprint,
            ManagementMutationV2::UserCardStatus {
                user_card_id: [9; 16],
                status,
            },
            audit(operation_id, fingerprint),
            root(),
            JournalIdentity::new(id(10), id(11), 8, 8, id(12)).unwrap(),
        )
        .unwrap()
    }

    fn reservation(request: &MutationRequest) -> JournalCapacityReservation {
        JournalCapacityReservation::candidate(
            request.operation_id(),
            request.mutation_digest(),
            request.audit_digest(),
            request.payload_bytes(),
            1,
        )
        .unwrap()
    }

    fn journal_proof(request: &MutationRequest) -> JournalDurableProof {
        JournalDurableProof {
            operation_id: request.operation_id().to_owned(),
            request_fingerprint: *request.request_fingerprint(),
            mutation_digest: request.mutation_digest(),
            audit_digest: request.audit_digest(),
            identity: request.journal(),
            tail_hash: [13; 32],
        }
    }

    fn root_proof(
        request: &MutationRequest,
        journal: &JournalDurableProof,
    ) -> RootPublicationProof {
        let after = RootBinding::new(
            request.root().instance_id(),
            request.root().version() + 1,
            [8; 32],
            RootStatus::Serving,
        );
        let atomic_link = publication_link(
            request.operation_id(),
            request.mutation_digest(),
            request.audit_digest(),
            journal.identity,
            request.root(),
            after,
        );
        RootPublicationProof {
            operation_id: request.operation_id().to_owned(),
            mutation_digest: request.mutation_digest(),
            audit_digest: request.audit_digest(),
            journal: journal.identity,
            before: request.root(),
            after,
            atomic_link,
        }
    }

    const DENY_AUDIT_DOMAIN: &[u8] = b"astrallight/memory-v1/coordinator/deny-audit/1\0";

    fn deny_request() -> DenyProofRequest {
        DenyProofRequest::try_new(
            "deny-op",
            [21; 32],
            root(),
            JournalReadWatermark::new(id(30), id(31), 7, 7).unwrap(),
            MemoryV1AuditDenySource::NoMatch,
        )
        .unwrap()
    }

    fn deny_audit(request: &DenyProofRequest) -> DenyAuditProof {
        DenyAuditProof {
            operation_id: request.operation_id().to_owned(),
            request_fingerprint: request.request_fingerprint,
            root: request.root,
            source: request.source,
            audit_digest: digest_bytes(DENY_AUDIT_DOMAIN, b"deny"),
        }
    }

    fn prefix(request: &DenyProofRequest) -> AuthorizationStatePrefixProof {
        let watermark = request.read_journal();
        AuthorizationStatePrefixProof {
            operation_id: request.operation_id().to_owned(),
            request_fingerprint: request.request_fingerprint,
            root: request.root,
            stream_id: watermark.stream_id(),
            epoch_id: watermark.epoch_id(),
            journal_sequence: watermark.journal_sequence() + 1,
            mutation_sequence: watermark.mutation_sequence() + 1,
            tail_hash: [32; 32],
            state_digest: request.root.digest(),
        }
    }

    #[test]
    fn journal_payload_round_trip_reconstructs_both_value_digests() {
        let request = request("op", UserCardStatus::Disabled);
        let payload = request.journal_payload().unwrap();
        assert_eq!(payload.len(), request.payload_bytes());
        let decoded = decode_journal_payload(&payload).unwrap();
        assert_eq!(
            encode_mutation(decoded.mutation()).unwrap(),
            encode_mutation(request.mutation()).unwrap()
        );
        assert_eq!(
            decoded.audit().encode().unwrap(),
            request.audit().encode().unwrap()
        );
        assert_eq!(decoded.operation_id(), request.operation_id());
        assert_eq!(decoded.request_fingerprint(), request.request_fingerprint());
        assert_eq!(decoded.mutation_digest(), request.mutation_digest());
        assert_eq!(decoded.audit_digest(), request.audit_digest());
    }

    #[test]
    fn journal_payload_rejects_truncation_and_forged_lengths() {
        let request = request("op", UserCardStatus::Disabled);
        let payload = request.journal_payload().unwrap();
        assert!(matches!(
            decode_journal_payload(&payload[..payload.len() - 1]),
            Err(CoordinatorError::InvalidJournalPayload)
        ));

        let total_offset = JOURNAL_PAYLOAD_DOMAIN.len() + 4;
        let mut forged_total = payload.clone();
        forged_total[total_offset..total_offset + 4]
            .copy_from_slice(&((payload.len() as u32) + 1).to_be_bytes());
        assert!(matches!(
            decode_journal_payload(&forged_total),
            Err(CoordinatorError::InvalidJournalPayload)
        ));

        let mutation_length_offset = total_offset + 4;
        let mut forged_mutation_length = payload;
        forged_mutation_length[mutation_length_offset..mutation_length_offset + 4]
            .copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            decode_journal_payload(&forged_mutation_length),
            Err(CoordinatorError::InvalidJournalPayload)
        ));
    }

    #[test]
    fn journal_payload_rejects_mutation_and_audit_digest_tampering() {
        let request = request("op", UserCardStatus::Disabled);
        let payload = request.journal_payload().unwrap();
        let mutation_digest_offset = JOURNAL_PAYLOAD_DOMAIN.len() + 2 + 1 + 1 + 4 + 4 + 4;
        let audit_digest_offset = mutation_digest_offset + 32;

        let mut mutation_tampered = payload.clone();
        mutation_tampered[mutation_digest_offset] ^= 1;
        assert!(matches!(
            decode_journal_payload(&mutation_tampered),
            Err(CoordinatorError::InvalidJournalPayload)
        ));

        let mut audit_tampered = payload;
        audit_tampered[audit_digest_offset] ^= 1;
        assert!(matches!(
            decode_journal_payload(&audit_tampered),
            Err(CoordinatorError::InvalidJournalPayload)
        ));
    }

    #[test]
    fn deny_payload_is_not_a_mutation_envelope() {
        assert!(matches!(
            decode_journal_payload(b"deny-record"),
            Err(CoordinatorError::InvalidJournalPayload)
        ));
    }

    #[test]
    fn request_binds_mutation_and_complete_audit_identity() {
        let request = request("op", UserCardStatus::Disabled);
        assert_eq!(request.operation_id(), "op");
        assert!(request.payload_bytes() > 0);
        assert_ne!(request.mutation_digest(), [0; 32]);
        assert_ne!(request.audit_digest(), [0; 32]);

        let mismatch = MutationRequest::try_new(
            "other-op",
            [4; 32],
            request.mutation().clone(),
            request.audit().clone(),
            root(),
            request.journal(),
        );
        assert!(matches!(
            mismatch,
            Err(CoordinatorError::AuditBindingMismatch)
        ));
    }

    #[test]
    fn operation_ledger_rejects_replay_conflict_and_capacity_overrun() {
        let mut ledger = MemoryV1OperationLedger::new(1).unwrap();
        let first = request("op", UserCardStatus::Disabled);
        let claim = ledger.try_claim(&first).unwrap();
        assert_eq!(ledger.status("op"), Some(OperationStatus::Claimed));
        assert_eq!(ledger.len(), 1);
        assert_eq!(
            ledger.try_claim(&first),
            Err(CoordinatorError::ExistingOperation)
        );

        let conflicting = request("op", UserCardStatus::Active);
        assert_eq!(
            ledger.try_claim(&conflicting),
            Err(CoordinatorError::DigestConflict)
        );
        let exhausted = request("other", UserCardStatus::Disabled);
        assert_eq!(
            ledger.try_claim(&exhausted),
            Err(CoordinatorError::CapacityExceeded)
        );

        ledger.mark_unknown(&claim).unwrap();
        assert_eq!(ledger.status("op"), Some(OperationStatus::Unknown));
        assert_eq!(
            ledger.record_phase(&claim, OperationStatus::Completed),
            Err(CoordinatorError::InvalidTransition)
        );
    }

    #[test]
    fn proof_order_is_closed_and_root_publish_requires_atomic_link() {
        let mut ledger = MemoryV1OperationLedger::new(4).unwrap();
        let request = request("op", UserCardStatus::Disabled);
        let claimed = ClaimedMutation::claim(&mut ledger, request.clone()).unwrap();
        let prepared = claimed.prepare(&mut ledger, reservation(&request)).unwrap();
        assert_eq!(ledger.status("op"), Some(OperationStatus::JournalPrepared));
        assert_eq!(prepared.phase(), OperationStatus::JournalPrepared);

        let journal = journal_proof(&request);
        let durable = prepared
            .record_journal_durable(&mut ledger, journal.clone())
            .unwrap();
        assert_eq!(ledger.status("op"), Some(OperationStatus::JournalDurable));
        assert_eq!(durable.phase(), OperationStatus::JournalDurable);

        let mut invalid = root_proof(&request, &journal);
        invalid.atomic_link[0] ^= 1;
        assert!(matches!(
            durable.clone().publish_root(&mut ledger, invalid),
            Err(CoordinatorError::ProofMismatch)
        ));
        assert_eq!(ledger.status("op"), Some(OperationStatus::JournalDurable));

        let published = durable
            .publish_root(&mut ledger, root_proof(&request, &journal))
            .unwrap();
        assert_eq!(ledger.status("op"), Some(OperationStatus::RootPublished));
        assert_eq!(published.phase(), OperationStatus::RootPublished);
        let completed = published.complete(&mut ledger).unwrap();
        assert_eq!(ledger.status("op"), Some(OperationStatus::Completed));
        assert_eq!(completed.phase(), OperationStatus::Completed);
        assert!(!completed.has_db_progress());
    }

    #[test]
    fn unknown_result_cannot_be_automatically_replayed() {
        let request = request("op", UserCardStatus::Disabled);
        let mut ledger = MemoryV1OperationLedger::new(1).unwrap();
        let claim = ClaimedMutation::claim(&mut ledger, request.clone()).unwrap();
        let unknown = claim
            .unknown(&mut ledger, UnknownReason::JournalFlush)
            .unwrap();
        assert_eq!(ledger.status("op"), Some(OperationStatus::Unknown));
        assert_eq!(unknown.phase(), OperationStatus::Claimed);
        assert_eq!(unknown.reason(), UnknownReason::JournalFlush);
        assert!(!unknown.can_auto_retry());
    }

    #[test]
    fn deny_requires_both_independent_proofs_for_403() {
        let request = deny_request();
        let mut gate = DenyProofGate::new(request);
        assert_eq!(gate.response(), DenyResponse::ServiceUnavailable);
        gate.record_audit(deny_audit(&request)).unwrap();
        assert_eq!(gate.response(), DenyResponse::ServiceUnavailable);
        gate.record_prefix(prefix(&request)).unwrap();
        assert_eq!(gate.response(), DenyResponse::Forbidden);
        assert_eq!(gate.response().status_code(), 403);
    }

    #[test]
    fn mismatched_deny_proof_keeps_fail_closed_503() {
        let request = deny_request();
        let mut gate = DenyProofGate::new(request);
        let mut wrong = prefix(&request);
        wrong.state_digest[0] ^= 1;
        assert_eq!(
            gate.record_prefix(wrong),
            Err(CoordinatorError::InvalidDenyProof)
        );
        assert_eq!(gate.response(), DenyResponse::ServiceUnavailable);
        assert_eq!(gate.response().status_code(), 503);
    }

    #[test]
    fn database_progress_is_optional_after_local_durable_proof() {
        let mut ledger = MemoryV1OperationLedger::new(2).unwrap();
        let request = request("op", UserCardStatus::Disabled);
        let claimed = ClaimedMutation::claim(&mut ledger, request.clone()).unwrap();
        let prepared = claimed.prepare(&mut ledger, reservation(&request)).unwrap();
        let journal = journal_proof(&request);
        let durable = prepared
            .record_journal_durable(&mut ledger, journal.clone())
            .unwrap();
        let published = durable
            .publish_root(&mut ledger, root_proof(&request, &journal))
            .unwrap();
        assert!(!published.has_db_progress());
        let completed = published.complete(&mut ledger).unwrap();
        assert!(!completed.has_db_progress());
    }

    #[test]
    fn database_progress_can_only_be_attached_after_root_publication() {
        let mut ledger = MemoryV1OperationLedger::new(2).unwrap();
        let request = request("op", UserCardStatus::Disabled);
        let claimed = ClaimedMutation::claim(&mut ledger, request.clone()).unwrap();
        let prepared = claimed.prepare(&mut ledger, reservation(&request)).unwrap();
        let journal = journal_proof(&request);
        let durable = prepared
            .record_journal_durable(&mut ledger, journal.clone())
            .unwrap();
        let published = durable
            .publish_root(&mut ledger, root_proof(&request, &journal))
            .unwrap();
        let receipt = DatabaseProgressProof {
            operation_id: request.operation_id().to_owned(),
            mutation_digest: request.mutation_digest(),
            audit_digest: request.audit_digest(),
            journal: request.journal(),
            receipt_id: id(40),
            progress_sequence: request.journal().journal_sequence(),
        };
        let published = published.attach_db_progress(receipt).unwrap();
        assert!(published.has_db_progress());
        let completed = published.complete(&mut ledger).unwrap();
        assert!(completed.has_db_progress());
        assert_eq!(ledger.status("op"), Some(OperationStatus::Completed));
    }
}
