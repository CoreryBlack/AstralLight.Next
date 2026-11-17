//! Lossless, bounded read observations for memory-v1 DENY candidates.
//!
//! This module stores only data observed during a read phase.  It does not
//! represent a decision, a final trusted time, an authorization, an audit
//! event, a journal append, or durable evidence.  In particular, the read
//! start timestamp is not the B-4 final trusted time, and the root metadata is
//! caller-supplied observation data rather than proof of root provenance.
//!
//! The binary codec is deliberately local to this value.  It is a fixed,
//! versioned, big-endian format with bounded lengths and no extensible tail.
//! Decoding validates shape and framing only; callers must independently bind
//! an observation to the evaluator result and any later audit contract.

use std::fmt;

use crate::memory_v1::{CandidateIdentity, MemoryId};
use crate::memory_v1_audit::{MemoryV1AuditDenySource, MemoryV1AuditRootStatus};

/// Maximum encoded size of one DENY observation value.
pub const MEMORY_V1_DENY_OBSERVATION_MAX_BYTES: usize = 64 * 1024;
/// Fixed header size: magic, version, kind, flags, and declared length.
pub const MEMORY_V1_DENY_OBSERVATION_HEADER_BYTES: usize = 16;
/// Fixed value-level schema version.
pub const MEMORY_V1_DENY_OBSERVATION_VERSION: u16 = 1;
/// Maximum evaluator resource byte length.
pub const MEMORY_V1_DENY_OBSERVATION_MAX_RESOURCE_BYTES: usize = 256;
/// Maximum evaluator action byte length.
pub const MEMORY_V1_DENY_OBSERVATION_MAX_ACTION_BYTES: usize = 256;
/// Maximum raw target, operation-id, and fingerprint byte length.
pub const MEMORY_V1_DENY_OBSERVATION_MAX_RAW_BYTES: usize = 4096;

const MAGIC: &[u8; 8] = b"ALM1DNO\0";
const KIND_OBSERVATION: u8 = 1;
const FLAGS_RESERVED: u8 = 0;
const ID_BYTES: usize = 16;
const DIGEST_BYTES: usize = 32;

/// A closed root lifecycle status copied into a read observation.
///
/// This is an observation tag.  It does not make a candidate root serving or
/// establish that the status was obtained from an authoritative owner.
pub type MemoryV1DenyRootStatus = MemoryV1AuditRootStatus;

/// A root budget represented with fixed-width values for cross-platform codec
/// stability.  `usize` values from a concrete root must be checked before being
/// converted to this type; zero is preserved and has no authentication meaning.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MemoryV1DenyRootBudget {
    max_table_rows: u64,
    max_bindings_per_read: u64,
}

impl MemoryV1DenyRootBudget {
    /// Capture a budget without interpreting zero as an invalid or valid proof.
    /// memory—v1
    pub const fn new(max_table_rows: u64, max_bindings_per_read: u64) -> Self {
        Self {
            max_table_rows,
            max_bindings_per_read,
        }
    }

    /// Convert platform-sized values using checked conversions.
    /// memory—v1
    pub fn try_from_usize(
        max_table_rows: usize,
        max_bindings_per_read: usize,
    ) -> Result<Self, MemoryV1DenyObservationError> {
        Ok(Self::new(
            u64::try_from(max_table_rows)
                .map_err(|_| MemoryV1DenyObservationError::InvalidField)?,
            u64::try_from(max_bindings_per_read)
                .map_err(|_| MemoryV1DenyObservationError::InvalidField)?,
        ))
    }

    /// Return the maximum combined table-row count observed in the root budget.
    /// memory—v1
    pub const fn max_table_rows(self) -> u64 {
        self.max_table_rows
    }

    /// Return the maximum binding traversal count observed in the root budget.
    /// memory—v1
    pub const fn max_bindings_per_read(self) -> u64 {
        self.max_bindings_per_read
    }
}

impl fmt::Debug for MemoryV1DenyRootBudget {
    // memory—v1
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MemoryV1DenyRootBudget(<redacted>)")
    }
}

/// Root metadata copied with one coherent read-phase observation.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MemoryV1DenyRootObservation {
    instance: MemoryId,
    version: u64,
    digest: [u8; DIGEST_BYTES],
    status: MemoryV1DenyRootStatus,
    budget: MemoryV1DenyRootBudget,
    row_count: u64,
}

impl MemoryV1DenyRootObservation {
    /// Capture root metadata without proving ownership, freshness, or coverage.
    /// memory—v1
    pub const fn new(
        instance: MemoryId,
        version: u64,
        digest: [u8; DIGEST_BYTES],
        status: MemoryV1DenyRootStatus,
        budget: MemoryV1DenyRootBudget,
        row_count: u64,
    ) -> Self {
        Self {
            instance,
            version,
            digest,
            status,
            budget,
            row_count,
        }
    }

    /// Capture a root budget and row count from `usize` values with checks.
    /// memory—v1
    pub fn try_from_usize(
        instance: MemoryId,
        version: u64,
        digest: [u8; DIGEST_BYTES],
        status: MemoryV1DenyRootStatus,
        max_table_rows: usize,
        max_bindings_per_read: usize,
        row_count: usize,
    ) -> Result<Self, MemoryV1DenyObservationError> {
        Ok(Self::new(
            instance,
            version,
            digest,
            status,
            MemoryV1DenyRootBudget::try_from_usize(max_table_rows, max_bindings_per_read)?,
            u64::try_from(row_count).map_err(|_| MemoryV1DenyObservationError::InvalidField)?,
        ))
    }

    /// Return the observed process-local root instance bytes.
    /// memory—v1
    pub const fn instance(self) -> MemoryId {
        self.instance
    }

    /// Alias for callers that use the root terminology.
    /// memory—v1
    pub const fn root_instance(self) -> MemoryId {
        self.instance
    }

    /// Return the root version in the instance's local sequence domain.
    /// memory—v1
    pub const fn version(self) -> u64 {
        self.version
    }

    /// Alias for callers that use the root terminology.
    /// memory—v1
    pub const fn root_version(self) -> u64 {
        self.version
    }

    /// Return the observed root digest bytes.
    /// memory—v1
    pub const fn digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.digest
    }

    /// Alias for callers that use the root terminology.
    /// memory—v1
    pub const fn root_digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.digest
    }

    /// Return the observed lifecycle status.
    /// memory—v1
    pub const fn status(self) -> MemoryV1DenyRootStatus {
        self.status
    }

    /// Alias for callers that use the root terminology.
    /// memory—v1
    pub const fn root_status(self) -> MemoryV1DenyRootStatus {
        self.status
    }

    /// Return the fixed-width budget observation.
    /// memory—v1
    pub const fn budget(self) -> MemoryV1DenyRootBudget {
        self.budget
    }

    /// Return the observed combined table-row count.
    /// memory—v1
    pub const fn row_count(self) -> u64 {
        self.row_count
    }
}

impl fmt::Debug for MemoryV1DenyRootObservation {
    // memory—v1
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MemoryV1DenyRootObservation(<redacted>)")
    }
}

/// The four identifiers of a binding that was associated with a denial.
///
/// The identifiers are copied bytes only.  Their presence does not prove that
/// the relationship exists, is current, or is authorized.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MemoryV1DenyAffectedBinding {
    binding: MemoryId,
    user_card: MemoryId,
    owner: MemoryId,
    tenant: MemoryId,
}

impl MemoryV1DenyAffectedBinding {
    /// Capture the four raw identifiers without relationship validation.
    /// memory—v1
    pub const fn new(
        binding: MemoryId,
        user_card: MemoryId,
        owner: MemoryId,
        tenant: MemoryId,
    ) -> Self {
        Self {
            binding,
            user_card,
            owner,
            tenant,
        }
    }

    /// Return the binding identifier.
    /// memory—v1
    pub const fn binding(&self) -> MemoryId {
        self.binding
    }

    /// Alias for the conventional identifier name.
    /// memory—v1
    pub const fn binding_id(&self) -> MemoryId {
        self.binding
    }

    /// Return the user-card identifier.
    /// memory—v1
    pub const fn user_card(&self) -> MemoryId {
        self.user_card
    }

    /// Alias for the conventional identifier name.
    /// memory—v1
    pub const fn user_card_id(&self) -> MemoryId {
        self.user_card
    }

    /// Return the owner-user identifier.
    /// memory—v1
    pub const fn owner(&self) -> MemoryId {
        self.owner
    }

    /// Alias for the conventional identifier name.
    /// memory—v1
    pub const fn owner_user_id(&self) -> MemoryId {
        self.owner
    }

    /// Return the tenant identifier.
    /// memory—v1
    pub const fn tenant(&self) -> MemoryId {
        self.tenant
    }

    /// Alias for the conventional identifier name.
    /// memory—v1
    pub const fn tenant_id(&self) -> MemoryId {
        self.tenant
    }
}

impl fmt::Debug for MemoryV1DenyAffectedBinding {
    // memory—v1
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MemoryV1DenyAffectedBinding(<redacted>)")
    }
}

/// Three-state association result for a denial read.
///
/// `Unknown` means the read did not establish whether a binding was affected;
/// `Inapplicable` means the operation has no affected-binding concept.  They
/// are intentionally separate, and neither state means that no relationship
/// exists.  `Present` only preserves the observed association values.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum MemoryV1DenyAffectedBindingState {
    /// The read did not establish the association.
    Unknown,
    /// The operation has no affected-binding field for this observation.
    Inapplicable,
    /// A binding/card/owner/tenant association was observed.
    Present(MemoryV1DenyAffectedBinding),
}

impl MemoryV1DenyAffectedBindingState {
    /// Construct the unknown state explicitly.
    /// memory—v1
    pub const fn unknown() -> Self {
        Self::Unknown
    }

    /// Construct the inapplicable state explicitly.
    /// memory—v1
    pub const fn inapplicable() -> Self {
        Self::Inapplicable
    }

    /// Construct a present association explicitly.
    /// memory—v1
    pub const fn present(value: MemoryV1DenyAffectedBinding) -> Self {
        Self::Present(value)
    }

    /// Return the observed association when it is present.
    /// memory—v1
    pub const fn as_present(&self) -> Option<&MemoryV1DenyAffectedBinding> {
        match self {
            Self::Present(value) => Some(value),
            Self::Unknown | Self::Inapplicable => None,
        }
    }

    /// Return whether the association is unknown.
    /// memory—v1
    pub const fn is_unknown(self) -> bool {
        matches!(self, Self::Unknown)
    }

    /// Return whether the association is explicitly inapplicable.
    /// memory—v1
    pub const fn is_inapplicable(self) -> bool {
        matches!(self, Self::Inapplicable)
    }
}

impl fmt::Debug for MemoryV1DenyAffectedBindingState {
    // memory—v1
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => f.write_str("MemoryV1DenyAffectedBindingState::Unknown"),
            Self::Inapplicable => f.write_str("MemoryV1DenyAffectedBindingState::Inapplicable"),
            Self::Present(_) => {
                f.write_str("MemoryV1DenyAffectedBindingState::Present(<redacted>)")
            }
        }
    }
}

/// Compatibility alias for code that names the present binding observation.
pub type MemoryV1AffectedBindingObservation = MemoryV1DenyAffectedBinding;
/// Compatibility alias for code that names the three-state association.
pub type MemoryV1AffectedBindingState = MemoryV1DenyAffectedBindingState;
/// The frozen deny-source vocabulary used by the existing audit value module.
pub type MemoryV1DenySource = MemoryV1AuditDenySource;

/// A shape or framing failure.  No supplied bytes are retained in an error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryV1DenyObservationError {
    /// Magic, version, kind, flags, option tag, enum tag, or UTF-8 is invalid.
    InvalidEncoding,
    /// The input is truncated, has trailing bytes, or disagrees with its length.
    InvalidLength,
    /// A field or encoded value exceeds its fixed local bound.
    LimitExceeded,
    /// A text or fixed field cannot be represented by this value.
    InvalidField,
    /// PENDING has no observation representation and cannot be encoded as DENY.
    PendingCannotBeRepresented,
}

impl fmt::Display for MemoryV1DenyObservationError {
    // memory—v1
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid memory-v1 deny observation: {self:?}")
    }
}

impl std::error::Error for MemoryV1DenyObservationError {}

/// Lossless read-phase data for one selected DENY candidate.
///
/// This value contains no decision capability.  It is deliberately separate
/// from [`MemoryV1AuditEvent`](crate::memory_v1_audit::MemoryV1AuditEvent):
/// converting or encoding this value does not create an audit event, a journal
/// record, a 403 response, a durable prefix, or final trusted time.
#[derive(Clone, Eq, PartialEq)]
pub struct MemoryV1DenyObservation {
    root: MemoryV1DenyRootObservation,
    identity: CandidateIdentity,
    read_started_at_unix_seconds: i64,
    resource: String,
    action: String,
    target: Option<Vec<u8>>,
    target_tenant: Option<Vec<u8>>,
    target_owner: Option<Vec<u8>>,
    affected_binding: MemoryV1DenyAffectedBindingState,
    operation_id: Vec<u8>,
    operation_fingerprint: Vec<u8>,
    source: MemoryV1DenySource,
    batch_sequence: Option<u32>,
}

impl fmt::Debug for MemoryV1DenyObservation {
    // memory—v1
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MemoryV1DenyObservation(<redacted>)")
    }
}

impl MemoryV1DenyObservation {
    /// Construct a bounded candidate from owned raw fields.
    ///
    /// Resource and action follow the evaluator's nonempty UTF-8 string shape.
    /// All opaque byte fields, including `Some(Vec::new())`, are preserved
    /// exactly.  No zero-value or source tag is treated as authentication.
    #[allow(clippy::too_many_arguments)]
    /// memory—v1
    pub fn new(
        root: MemoryV1DenyRootObservation,
        identity: CandidateIdentity,
        read_started_at_unix_seconds: i64,
        resource: impl Into<String>,
        action: impl Into<String>,
        target: Option<Vec<u8>>,
        target_tenant: Option<Vec<u8>>,
        target_owner: Option<Vec<u8>>,
        affected_binding: MemoryV1DenyAffectedBindingState,
        operation_id: Vec<u8>,
        operation_fingerprint: Vec<u8>,
        source: MemoryV1DenySource,
        batch_sequence: Option<u32>,
    ) -> Result<Self, MemoryV1DenyObservationError> {
        let observation = Self {
            root,
            identity,
            read_started_at_unix_seconds,
            resource: resource.into(),
            action: action.into(),
            target,
            target_tenant,
            target_owner,
            affected_binding,
            operation_id,
            operation_fingerprint,
            source,
            batch_sequence,
        };
        observation.validate_shape()?;
        Ok(observation)
    }

    /// Construct the same value from borrowed raw byte fields.
    #[allow(clippy::too_many_arguments)]
    /// memory—v1
    pub fn from_slices(
        root: MemoryV1DenyRootObservation,
        identity: CandidateIdentity,
        read_started_at_unix_seconds: i64,
        resource: &str,
        action: &str,
        target: Option<&[u8]>,
        target_tenant: Option<&[u8]>,
        target_owner: Option<&[u8]>,
        affected_binding: MemoryV1DenyAffectedBindingState,
        operation_id: &[u8],
        operation_fingerprint: &[u8],
        source: MemoryV1DenySource,
        batch_sequence: Option<u32>,
    ) -> Result<Self, MemoryV1DenyObservationError> {
        Self::new(
            root,
            identity,
            read_started_at_unix_seconds,
            resource,
            action,
            target.map(<[u8]>::to_vec),
            target_tenant.map(<[u8]>::to_vec),
            target_owner.map(<[u8]>::to_vec),
            affected_binding,
            operation_id.to_vec(),
            operation_fingerprint.to_vec(),
            source,
            batch_sequence,
        )
    }

    // memory—v1
    fn validate_shape(&self) -> Result<(), MemoryV1DenyObservationError> {
        let resource_len = self.resource.len();
        let action_len = self.action.len();
        if resource_len == 0
            || resource_len > MEMORY_V1_DENY_OBSERVATION_MAX_RESOURCE_BYTES
            || action_len == 0
            || action_len > MEMORY_V1_DENY_OBSERVATION_MAX_ACTION_BYTES
        {
            return Err(MemoryV1DenyObservationError::InvalidField);
        }
        for value in [
            self.target.as_deref(),
            self.target_tenant.as_deref(),
            self.target_owner.as_deref(),
            Some(self.operation_id.as_slice()),
            Some(self.operation_fingerprint.as_slice()),
        ] {
            if value.is_some_and(|bytes| bytes.len() > MEMORY_V1_DENY_OBSERVATION_MAX_RAW_BYTES) {
                return Err(MemoryV1DenyObservationError::LimitExceeded);
            }
        }
        Ok(())
    }

    /// Return the read root metadata.
    /// memory—v1
    pub const fn root(&self) -> MemoryV1DenyRootObservation {
        self.root
    }

    /// Return the four candidate identity values.
    /// memory—v1
    pub const fn identity(&self) -> CandidateIdentity {
        self.identity
    }

    /// Alias emphasizing that these are candidate values, not proof.
    /// memory—v1
    pub const fn candidate_identity(&self) -> CandidateIdentity {
        self.identity
    }

    /// Return the read-start sample, which is not final trusted time.
    /// memory—v1
    pub const fn read_started_at_unix_seconds(&self) -> i64 {
        self.read_started_at_unix_seconds
    }

    /// Return the exact resource string.
    /// memory—v1
    pub fn resource(&self) -> &str {
        &self.resource
    }

    /// Return the exact action string.
    /// memory—v1
    pub fn action(&self) -> &str {
        &self.action
    }

    /// Return target bytes while preserving `None` versus `Some(empty)`.
    /// memory—v1
    pub fn target(&self) -> Option<&[u8]> {
        self.target.as_deref()
    }

    /// Return target-tenant bytes while preserving `None` versus `Some(empty)`.
    /// memory—v1
    pub fn target_tenant(&self) -> Option<&[u8]> {
        self.target_tenant.as_deref()
    }

    /// Return target-owner bytes while preserving `None` versus `Some(empty)`.
    /// memory—v1
    pub fn target_owner(&self) -> Option<&[u8]> {
        self.target_owner.as_deref()
    }

    /// Return the three-state affected-binding observation.
    /// memory—v1
    pub const fn affected_binding(&self) -> &MemoryV1DenyAffectedBindingState {
        &self.affected_binding
    }

    /// Alias for callers that use the state terminology.
    /// memory—v1
    pub const fn affected_binding_state(&self) -> &MemoryV1DenyAffectedBindingState {
        &self.affected_binding
    }

    /// Return the raw operation identifier bytes.
    /// memory—v1
    pub fn operation_id(&self) -> &[u8] {
        &self.operation_id
    }

    /// Return the raw operation fingerprint bytes.
    /// memory—v1
    pub fn operation_fingerprint(&self) -> &[u8] {
        &self.operation_fingerprint
    }

    /// Return the frozen source tag, without claiming it was authenticated.
    /// memory—v1
    pub const fn source(&self) -> MemoryV1DenySource {
        self.source
    }

    /// Return the original batch sequence when one was supplied.
    /// memory—v1
    pub const fn batch_sequence(&self) -> Option<u32> {
        self.batch_sequence
    }

    /// Encode this candidate using the strict value-level codec.
    /// memory—v1
    pub fn encode(&self) -> Result<Vec<u8>, MemoryV1DenyObservationError> {
        encode_memory_v1_deny_observation(self)
    }

    /// Decode exactly one candidate and reject any trailing bytes.
    /// memory—v1
    pub fn decode(bytes: &[u8]) -> Result<Self, MemoryV1DenyObservationError> {
        decode_memory_v1_deny_observation(bytes)
    }
}

struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    // memory—v1
    fn new() -> Result<Self, MemoryV1DenyObservationError> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(MEMORY_V1_DENY_OBSERVATION_HEADER_BYTES)
            .map_err(|_| MemoryV1DenyObservationError::LimitExceeded)?;
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&MEMORY_V1_DENY_OBSERVATION_VERSION.to_be_bytes());
        bytes.push(KIND_OBSERVATION);
        bytes.push(FLAGS_RESERVED);
        bytes.extend_from_slice(&[0; 4]);
        Ok(Self { bytes })
    }

    // memory—v1
    fn ensure(&mut self, additional: usize) -> Result<(), MemoryV1DenyObservationError> {
        let next = self
            .bytes
            .len()
            .checked_add(additional)
            .ok_or(MemoryV1DenyObservationError::LimitExceeded)?;
        if next > MEMORY_V1_DENY_OBSERVATION_MAX_BYTES {
            return Err(MemoryV1DenyObservationError::LimitExceeded);
        }
        self.bytes
            .try_reserve(additional)
            .map_err(|_| MemoryV1DenyObservationError::LimitExceeded)
    }

    // memory—v1
    fn raw(&mut self, value: &[u8]) -> Result<(), MemoryV1DenyObservationError> {
        self.ensure(value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    // memory—v1
    fn u8(&mut self, value: u8) -> Result<(), MemoryV1DenyObservationError> {
        self.raw(&[value])
    }

    // memory—v1
    fn u32(&mut self, value: u32) -> Result<(), MemoryV1DenyObservationError> {
        self.raw(&value.to_be_bytes())
    }

    // memory—v1
    fn u64(&mut self, value: u64) -> Result<(), MemoryV1DenyObservationError> {
        self.raw(&value.to_be_bytes())
    }

    // memory—v1
    fn i64(&mut self, value: i64) -> Result<(), MemoryV1DenyObservationError> {
        self.raw(&value.to_be_bytes())
    }

    // memory—v1
    fn len(&mut self, length: usize) -> Result<(), MemoryV1DenyObservationError> {
        self.u32(u32::try_from(length).map_err(|_| MemoryV1DenyObservationError::LimitExceeded)?)
    }

    // memory—v1
    fn bounded_bytes(&mut self, value: &[u8]) -> Result<(), MemoryV1DenyObservationError> {
        if value.len() > MEMORY_V1_DENY_OBSERVATION_MAX_RAW_BYTES {
            return Err(MemoryV1DenyObservationError::LimitExceeded);
        }
        self.len(value.len())?;
        self.raw(value)
    }

    // memory—v1
    fn text(&mut self, value: &str, max: usize) -> Result<(), MemoryV1DenyObservationError> {
        if value.is_empty() || value.len() > max {
            return Err(MemoryV1DenyObservationError::InvalidField);
        }
        self.len(value.len())?;
        self.raw(value.as_bytes())
    }

    // memory—v1
    fn finish(mut self) -> Result<Vec<u8>, MemoryV1DenyObservationError> {
        if self.bytes.len() < MEMORY_V1_DENY_OBSERVATION_HEADER_BYTES
            || self.bytes.len() > MEMORY_V1_DENY_OBSERVATION_MAX_BYTES
        {
            return Err(MemoryV1DenyObservationError::LimitExceeded);
        }
        let length = u32::try_from(self.bytes.len())
            .map_err(|_| MemoryV1DenyObservationError::LimitExceeded)?;
        self.bytes[12..16].copy_from_slice(&length.to_be_bytes());
        Ok(self.bytes)
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    // memory—v1
    fn new(bytes: &'a [u8]) -> Result<Self, MemoryV1DenyObservationError> {
        if bytes.len() < MEMORY_V1_DENY_OBSERVATION_HEADER_BYTES {
            return Err(MemoryV1DenyObservationError::InvalidLength);
        }
        if bytes.len() > MEMORY_V1_DENY_OBSERVATION_MAX_BYTES {
            return Err(MemoryV1DenyObservationError::LimitExceeded);
        }
        if &bytes[..8] != MAGIC
            || u16::from_be_bytes(
                bytes[8..10]
                    .try_into()
                    .expect("fixed observation header slice"),
            ) != MEMORY_V1_DENY_OBSERVATION_VERSION
            || bytes[10] != KIND_OBSERVATION
            || bytes[11] != FLAGS_RESERVED
        {
            return Err(MemoryV1DenyObservationError::InvalidEncoding);
        }
        let declared = u32::from_be_bytes(
            bytes[12..16]
                .try_into()
                .expect("fixed observation header slice"),
        ) as usize;
        if declared < MEMORY_V1_DENY_OBSERVATION_HEADER_BYTES {
            return Err(MemoryV1DenyObservationError::InvalidLength);
        }
        if declared > MEMORY_V1_DENY_OBSERVATION_MAX_BYTES {
            return Err(MemoryV1DenyObservationError::LimitExceeded);
        }
        if declared != bytes.len() {
            return Err(MemoryV1DenyObservationError::InvalidLength);
        }
        Ok(Self {
            bytes,
            offset: MEMORY_V1_DENY_OBSERVATION_HEADER_BYTES,
        })
    }

    // memory—v1
    fn take(&mut self, length: usize) -> Result<&'a [u8], MemoryV1DenyObservationError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(MemoryV1DenyObservationError::InvalidLength)?;
        if end > self.bytes.len() {
            return Err(MemoryV1DenyObservationError::InvalidLength);
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    // memory—v1
    fn u8(&mut self) -> Result<u8, MemoryV1DenyObservationError> {
        Ok(self.take(1)?[0])
    }

    // memory—v1
    fn u32(&mut self) -> Result<u32, MemoryV1DenyObservationError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .expect("fixed observation integer slice"),
        ))
    }

    // memory—v1
    fn u64(&mut self) -> Result<u64, MemoryV1DenyObservationError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .expect("fixed observation integer slice"),
        ))
    }

    // memory—v1
    fn i64(&mut self) -> Result<i64, MemoryV1DenyObservationError> {
        Ok(i64::from_be_bytes(
            self.take(8)?
                .try_into()
                .expect("fixed observation integer slice"),
        ))
    }

    // memory—v1
    fn id(&mut self) -> Result<MemoryId, MemoryV1DenyObservationError> {
        Ok(MemoryId::from_bytes(
            self.take(ID_BYTES)?
                .try_into()
                .expect("fixed observation id slice"),
        ))
    }

    // memory—v1
    fn digest(&mut self) -> Result<[u8; DIGEST_BYTES], MemoryV1DenyObservationError> {
        Ok(self
            .take(DIGEST_BYTES)?
            .try_into()
            .expect("fixed observation digest slice"))
    }

    // memory—v1
    fn bounded_bytes(&mut self) -> Result<&'a [u8], MemoryV1DenyObservationError> {
        let length = self.u32()? as usize;
        if length > MEMORY_V1_DENY_OBSERVATION_MAX_RAW_BYTES {
            return Err(MemoryV1DenyObservationError::LimitExceeded);
        }
        self.take(length)
    }

    // memory—v1
    fn owned_bounded_bytes(&mut self) -> Result<Vec<u8>, MemoryV1DenyObservationError> {
        let bytes = self.bounded_bytes()?;
        let mut value = Vec::new();
        value
            .try_reserve_exact(bytes.len())
            .map_err(|_| MemoryV1DenyObservationError::LimitExceeded)?;
        value.extend_from_slice(bytes);
        Ok(value)
    }

    // memory—v1
    fn text(&mut self, max: usize) -> Result<String, MemoryV1DenyObservationError> {
        let length = self.u32()? as usize;
        if length == 0 || length > max {
            return Err(MemoryV1DenyObservationError::InvalidField);
        }
        let bytes = self.take(length)?;
        let text = std::str::from_utf8(bytes)
            .map_err(|_| MemoryV1DenyObservationError::InvalidEncoding)?;
        let mut value = String::new();
        value
            .try_reserve_exact(text.len())
            .map_err(|_| MemoryV1DenyObservationError::LimitExceeded)?;
        value.push_str(text);
        Ok(value)
    }

    // memory—v1
    fn optional_bytes(&mut self) -> Result<Option<Vec<u8>>, MemoryV1DenyObservationError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.owned_bounded_bytes()?)),
            _ => Err(MemoryV1DenyObservationError::InvalidEncoding),
        }
    }

    // memory—v1
    fn done(&self) -> Result<(), MemoryV1DenyObservationError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(MemoryV1DenyObservationError::InvalidLength)
        }
    }
}

// memory—v1
fn write_id(writer: &mut Writer, value: MemoryId) -> Result<(), MemoryV1DenyObservationError> {
    writer.raw(value.as_bytes())
}

// memory—v1
fn write_optional_bytes(
    writer: &mut Writer,
    value: Option<&[u8]>,
) -> Result<(), MemoryV1DenyObservationError> {
    match value {
        None => writer.u8(0),
        Some(value) => {
            writer.u8(1)?;
            writer.bounded_bytes(value)
        }
    }
}

// memory—v1
fn write_status(
    writer: &mut Writer,
    status: MemoryV1DenyRootStatus,
) -> Result<(), MemoryV1DenyObservationError> {
    writer.u8(match status {
        MemoryV1DenyRootStatus::Candidate => 1,
        MemoryV1DenyRootStatus::Serving => 2,
        MemoryV1DenyRootStatus::Invalid => 3,
        MemoryV1DenyRootStatus::Stopped => 4,
    })
}

// memory—v1
fn read_status(
    reader: &mut Reader<'_>,
) -> Result<MemoryV1DenyRootStatus, MemoryV1DenyObservationError> {
    match reader.u8()? {
        1 => Ok(MemoryV1DenyRootStatus::Candidate),
        2 => Ok(MemoryV1DenyRootStatus::Serving),
        3 => Ok(MemoryV1DenyRootStatus::Invalid),
        4 => Ok(MemoryV1DenyRootStatus::Stopped),
        _ => Err(MemoryV1DenyObservationError::InvalidEncoding),
    }
}

// memory—v1
fn write_source(
    writer: &mut Writer,
    source: MemoryV1DenySource,
) -> Result<(), MemoryV1DenyObservationError> {
    writer.u8(match source {
        MemoryV1DenySource::RuleDeny => 1,
        MemoryV1DenySource::NoMatch => 2,
        MemoryV1DenySource::ScopeDenied => 3,
        MemoryV1DenySource::CardUnbound => 4,
        MemoryV1DenySource::IdentityMismatch => 5,
        MemoryV1DenySource::UnregisteredResource => 6,
        MemoryV1DenySource::SelfConfirmation => 7,
        MemoryV1DenySource::CardDisabled => 8,
        // OverlayOnly is retained by the closed source vocabulary but is not
        // produced by the ordinary evaluator path.
        MemoryV1DenySource::OverlayOnlyCreation => 9,
    })
}

// memory—v1
fn read_source(
    reader: &mut Reader<'_>,
) -> Result<MemoryV1DenySource, MemoryV1DenyObservationError> {
    match reader.u8()? {
        1 => Ok(MemoryV1DenySource::RuleDeny),
        2 => Ok(MemoryV1DenySource::NoMatch),
        3 => Ok(MemoryV1DenySource::ScopeDenied),
        4 => Ok(MemoryV1DenySource::CardUnbound),
        5 => Ok(MemoryV1DenySource::IdentityMismatch),
        6 => Ok(MemoryV1DenySource::UnregisteredResource),
        7 => Ok(MemoryV1DenySource::SelfConfirmation),
        8 => Ok(MemoryV1DenySource::CardDisabled),
        9 => Ok(MemoryV1DenySource::OverlayOnlyCreation),
        _ => Err(MemoryV1DenyObservationError::InvalidEncoding),
    }
}

// memory—v1
fn write_affected_binding(
    writer: &mut Writer,
    value: MemoryV1DenyAffectedBindingState,
) -> Result<(), MemoryV1DenyObservationError> {
    match value {
        MemoryV1DenyAffectedBindingState::Unknown => writer.u8(0),
        MemoryV1DenyAffectedBindingState::Inapplicable => writer.u8(1),
        MemoryV1DenyAffectedBindingState::Present(value) => {
            writer.u8(2)?;
            write_id(writer, value.binding)?;
            write_id(writer, value.user_card)?;
            write_id(writer, value.owner)?;
            write_id(writer, value.tenant)
        }
    }
}

// memory—v1
fn read_affected_binding(
    reader: &mut Reader<'_>,
) -> Result<MemoryV1DenyAffectedBindingState, MemoryV1DenyObservationError> {
    match reader.u8()? {
        0 => Ok(MemoryV1DenyAffectedBindingState::Unknown),
        1 => Ok(MemoryV1DenyAffectedBindingState::Inapplicable),
        2 => Ok(MemoryV1DenyAffectedBindingState::Present(
            MemoryV1DenyAffectedBinding::new(
                reader.id()?,
                reader.id()?,
                reader.id()?,
                reader.id()?,
            ),
        )),
        _ => Err(MemoryV1DenyObservationError::InvalidEncoding),
    }
}

// memory—v1
fn write_optional_sequence(
    writer: &mut Writer,
    value: Option<u32>,
) -> Result<(), MemoryV1DenyObservationError> {
    match value {
        None => writer.u8(0),
        Some(value) => {
            writer.u8(1)?;
            writer.u32(value)
        }
    }
}

// memory—v1
fn read_optional_sequence(
    reader: &mut Reader<'_>,
) -> Result<Option<u32>, MemoryV1DenyObservationError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => Ok(Some(reader.u32()?)),
        _ => Err(MemoryV1DenyObservationError::InvalidEncoding),
    }
}

/// Encode one canonical, fixed-order DENY observation.
/// memory—v1
pub fn encode_memory_v1_deny_observation(
    observation: &MemoryV1DenyObservation,
) -> Result<Vec<u8>, MemoryV1DenyObservationError> {
    observation.validate_shape()?;
    let mut writer = Writer::new()?;
    write_id(&mut writer, observation.root.instance)?;
    writer.u64(observation.root.version)?;
    writer.raw(&observation.root.digest)?;
    write_status(&mut writer, observation.root.status)?;
    writer.u64(observation.root.budget.max_table_rows)?;
    writer.u64(observation.root.budget.max_bindings_per_read)?;
    writer.u64(observation.root.row_count)?;
    write_id(&mut writer, observation.identity.user_id)?;
    write_id(&mut writer, observation.identity.identity_card_id)?;
    write_id(&mut writer, observation.identity.user_card_id)?;
    write_id(&mut writer, observation.identity.tenant_id)?;
    writer.i64(observation.read_started_at_unix_seconds)?;
    writer.text(
        &observation.resource,
        MEMORY_V1_DENY_OBSERVATION_MAX_RESOURCE_BYTES,
    )?;
    writer.text(
        &observation.action,
        MEMORY_V1_DENY_OBSERVATION_MAX_ACTION_BYTES,
    )?;
    write_optional_bytes(&mut writer, observation.target.as_deref())?;
    write_optional_bytes(&mut writer, observation.target_tenant.as_deref())?;
    write_optional_bytes(&mut writer, observation.target_owner.as_deref())?;
    write_affected_binding(&mut writer, observation.affected_binding)?;
    writer.bounded_bytes(&observation.operation_id)?;
    writer.bounded_bytes(&observation.operation_fingerprint)?;
    write_source(&mut writer, observation.source)?;
    write_optional_sequence(&mut writer, observation.batch_sequence)?;
    writer.finish()
}

/// Decode exactly one canonical DENY observation.
/// memory—v1
pub fn decode_memory_v1_deny_observation(
    bytes: &[u8],
) -> Result<MemoryV1DenyObservation, MemoryV1DenyObservationError> {
    let mut reader = Reader::new(bytes)?;
    let root = MemoryV1DenyRootObservation::new(
        reader.id()?,
        reader.u64()?,
        reader.digest()?,
        read_status(&mut reader)?,
        MemoryV1DenyRootBudget::new(reader.u64()?, reader.u64()?),
        reader.u64()?,
    );
    let identity = CandidateIdentity {
        user_id: reader.id()?,
        identity_card_id: reader.id()?,
        user_card_id: reader.id()?,
        tenant_id: reader.id()?,
    };
    let read_started_at_unix_seconds = reader.i64()?;
    let resource = reader.text(MEMORY_V1_DENY_OBSERVATION_MAX_RESOURCE_BYTES)?;
    let action = reader.text(MEMORY_V1_DENY_OBSERVATION_MAX_ACTION_BYTES)?;
    let target = reader.optional_bytes()?;
    let target_tenant = reader.optional_bytes()?;
    let target_owner = reader.optional_bytes()?;
    let affected_binding = read_affected_binding(&mut reader)?;
    let operation_id = reader.owned_bounded_bytes()?;
    let operation_fingerprint = reader.owned_bounded_bytes()?;
    let source = read_source(&mut reader)?;
    let batch_sequence = read_optional_sequence(&mut reader)?;
    reader.done()?;
    MemoryV1DenyObservation::new(
        root,
        identity,
        read_started_at_unix_seconds,
        resource,
        action,
        target,
        target_tenant,
        target_owner,
        affected_binding,
        operation_id,
        operation_fingerprint,
        source,
        batch_sequence,
    )
}

/// Short free-function alias for callers that use `encode` naming.
/// memory—v1
pub fn encode(
    observation: &MemoryV1DenyObservation,
) -> Result<Vec<u8>, MemoryV1DenyObservationError> {
    encode_memory_v1_deny_observation(observation)
}

/// Short free-function alias for callers that use `decode` naming.
/// memory—v1
pub fn decode(bytes: &[u8]) -> Result<MemoryV1DenyObservation, MemoryV1DenyObservationError> {
    decode_memory_v1_deny_observation(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // memory—v1
    fn id(seed: u8) -> MemoryId {
        MemoryId::from_bytes([seed; 16])
    }

    // memory—v1
    fn root(status: MemoryV1DenyRootStatus) -> MemoryV1DenyRootObservation {
        MemoryV1DenyRootObservation::new(
            id(0x10),
            u64::MAX - 7,
            [0xa5; 32],
            status,
            MemoryV1DenyRootBudget::new(0, u64::MAX),
            u64::MAX - 1,
        )
    }

    // memory—v1
    fn identity() -> CandidateIdentity {
        CandidateIdentity {
            user_id: id(0x01),
            identity_card_id: id(0x02),
            user_card_id: id(0x03),
            tenant_id: id(0x04),
        }
    }

    // memory—v1
    fn observation(affected_binding: MemoryV1DenyAffectedBindingState) -> MemoryV1DenyObservation {
        MemoryV1DenyObservation::new(
            root(MemoryV1DenyRootStatus::Serving),
            identity(),
            i64::MIN + 17,
            "resource",
            "action",
            Some(Vec::new()),
            None,
            Some(vec![0, 0xff, 0x80]),
            affected_binding,
            Vec::new(),
            vec![0xff, 0, 0x80],
            MemoryV1DenySource::NoMatch,
            Some(u32::MAX),
        )
        .expect("test observation has valid shape")
    }

    // memory—v1
    fn all_sources() -> [MemoryV1DenySource; 9] {
        [
            MemoryV1DenySource::RuleDeny,
            MemoryV1DenySource::NoMatch,
            MemoryV1DenySource::ScopeDenied,
            MemoryV1DenySource::CardUnbound,
            MemoryV1DenySource::IdentityMismatch,
            MemoryV1DenySource::UnregisteredResource,
            MemoryV1DenySource::SelfConfirmation,
            MemoryV1DenySource::CardDisabled,
            MemoryV1DenySource::OverlayOnlyCreation,
        ]
    }

    #[test]
    // memory—v1
    fn every_field_round_trips_without_authenticating_it() {
        let original = observation(MemoryV1DenyAffectedBindingState::Present(
            MemoryV1DenyAffectedBinding::new(id(0x20), id(0x21), id(0x22), id(0x23)),
        ));
        let encoded = original.encode().expect("encode");
        let decoded = MemoryV1DenyObservation::decode(&encoded).expect("decode");
        assert_eq!(decoded, original);
        assert_eq!(decoded.identity(), identity());
        assert_eq!(decoded.root().instance(), id(0x10));
        assert_eq!(decoded.root().version(), u64::MAX - 7);
        assert_eq!(decoded.root().digest(), &[0xa5; 32]);
        assert_eq!(decoded.root().status(), MemoryV1DenyRootStatus::Serving);
        assert_eq!(decoded.root().budget().max_table_rows(), 0);
        assert_eq!(decoded.root().budget().max_bindings_per_read(), u64::MAX);
        assert_eq!(decoded.root().row_count(), u64::MAX - 1);
        assert_eq!(decoded.read_started_at_unix_seconds(), i64::MIN + 17);
        assert_eq!(decoded.resource(), "resource");
        assert_eq!(decoded.action(), "action");
        assert_eq!(decoded.target(), Some([].as_slice()));
        assert_eq!(decoded.target_tenant(), None);
        assert_eq!(decoded.target_owner(), Some([0, 0xff, 0x80].as_slice()));
        assert_eq!(decoded.operation_id(), b"");
        assert_eq!(decoded.operation_fingerprint(), &[0xff, 0, 0x80]);
        assert_eq!(decoded.batch_sequence(), Some(u32::MAX));
        assert_eq!(
            decoded
                .affected_binding()
                .as_present()
                .unwrap()
                .binding_id(),
            id(0x20)
        );
    }

    #[test]
    // memory—v1
    fn unknown_and_inapplicable_are_distinct_from_present() {
        let unknown = MemoryV1DenyObservation::decode(
            &observation(MemoryV1DenyAffectedBindingState::Unknown)
                .encode()
                .unwrap(),
        )
        .unwrap();
        let inapplicable = MemoryV1DenyObservation::decode(
            &observation(MemoryV1DenyAffectedBindingState::Inapplicable)
                .encode()
                .unwrap(),
        )
        .unwrap();
        assert!(unknown.affected_binding().is_unknown());
        assert!(inapplicable.affected_binding().is_inapplicable());
        assert_ne!(unknown, inapplicable);
        assert_ne!(
            unknown.affected_binding(),
            &MemoryV1DenyAffectedBindingState::Present(MemoryV1DenyAffectedBinding::new(
                id(0),
                id(0),
                id(0),
                id(0),
            ))
        );
    }

    #[test]
    // memory—v1
    fn arbitrary_non_uuid_target_bytes_are_preserved() {
        let original = MemoryV1DenyObservation::new(
            root(MemoryV1DenyRootStatus::Candidate),
            identity(),
            0,
            "r",
            "a",
            Some(vec![0, 1, 2, 0xff, 0x80]),
            Some(vec![0xff]),
            Some(vec![]),
            MemoryV1DenyAffectedBindingState::Unknown,
            vec![0xff, 0],
            vec![0],
            MemoryV1DenySource::RuleDeny,
            None,
        )
        .unwrap();
        assert_eq!(
            MemoryV1DenyObservation::decode(&original.encode().unwrap()).unwrap(),
            original
        );
    }

    #[test]
    // memory—v1
    fn all_closed_sources_round_trip_including_non_engine_overlay_marker() {
        for source in all_sources() {
            let mut value = observation(MemoryV1DenyAffectedBindingState::Inapplicable);
            value.source = source;
            assert_eq!(
                MemoryV1DenyObservation::decode(&value.encode().unwrap()).unwrap(),
                value
            );
        }
    }

    #[test]
    // memory—v1
    fn root_status_and_signed_read_time_round_trip() {
        for status in [
            MemoryV1DenyRootStatus::Candidate,
            MemoryV1DenyRootStatus::Serving,
            MemoryV1DenyRootStatus::Invalid,
            MemoryV1DenyRootStatus::Stopped,
        ] {
            let mut value = observation(MemoryV1DenyAffectedBindingState::Unknown);
            value.root = root(status);
            value.read_started_at_unix_seconds = i64::MAX;
            let decoded = MemoryV1DenyObservation::decode(&value.encode().unwrap()).unwrap();
            assert_eq!(decoded.root().status(), status);
            assert_eq!(decoded.read_started_at_unix_seconds(), i64::MAX);
        }
    }

    #[test]
    // memory—v1
    fn malformed_tag_version_truncation_tail_and_declared_length_are_rejected() {
        let encoded = observation(MemoryV1DenyAffectedBindingState::Unknown)
            .encode()
            .unwrap();

        let mut bad_version = encoded.clone();
        bad_version[9] ^= 1;
        assert_eq!(
            MemoryV1DenyObservation::decode(&bad_version),
            Err(MemoryV1DenyObservationError::InvalidEncoding)
        );

        let mut bad_kind = encoded.clone();
        bad_kind[10] = 0xff;
        assert_eq!(
            MemoryV1DenyObservation::decode(&bad_kind),
            Err(MemoryV1DenyObservationError::InvalidEncoding)
        );

        let mut bad_status = encoded.clone();
        // Header (16) + instance (16) + version (8) + digest (32).
        bad_status[16 + 16 + 8 + 32] = 0xff;
        assert_eq!(
            MemoryV1DenyObservation::decode(&bad_status),
            Err(MemoryV1DenyObservationError::InvalidEncoding)
        );

        assert_eq!(
            MemoryV1DenyObservation::decode(&encoded[..encoded.len() - 1]),
            Err(MemoryV1DenyObservationError::InvalidLength)
        );

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            MemoryV1DenyObservation::decode(&trailing),
            Err(MemoryV1DenyObservationError::InvalidLength)
        );

        let mut wrong_declared_length = encoded;
        wrong_declared_length[15] = wrong_declared_length[15].wrapping_add(1);
        assert_eq!(
            MemoryV1DenyObservation::decode(&wrong_declared_length),
            Err(MemoryV1DenyObservationError::InvalidLength)
        );
    }

    #[test]
    // memory—v1
    fn malformed_option_and_enum_tags_are_rejected() {
        let mut encoded = observation(MemoryV1DenyAffectedBindingState::Unknown)
            .encode()
            .unwrap();
        // Locate the first optional target tag by decoding the fixed prefix.
        let mut offset = MEMORY_V1_DENY_OBSERVATION_HEADER_BYTES + 16 + 8 + 32 + 1 + 8 + 8 + 8;
        offset += 16 * 4 + 8;
        offset += 4 + "resource".len();
        offset += 4 + "action".len();
        encoded[offset] = 0xff;
        assert_eq!(
            MemoryV1DenyObservation::decode(&encoded),
            Err(MemoryV1DenyObservationError::InvalidEncoding)
        );

        let mut encoded = observation(MemoryV1DenyAffectedBindingState::Unknown)
            .encode()
            .unwrap();
        // Fixed prefix through three optional fields, then affected-binding tag.
        let mut offset = MEMORY_V1_DENY_OBSERVATION_HEADER_BYTES + 16 + 8 + 32 + 1 + 8 + 8 + 8;
        offset += 16 * 4 + 8;
        offset += 4 + "resource".len() + 4 + "action".len();
        offset += 1 + 4; // target: Some(empty)
        offset += 1; // target_tenant: None
        offset += 1 + 4 + 3; // target_owner: Some(three bytes)
        encoded[offset] = 0xff;
        assert_eq!(
            MemoryV1DenyObservation::decode(&encoded),
            Err(MemoryV1DenyObservationError::InvalidEncoding)
        );
    }

    #[test]
    // memory—v1
    fn declared_raw_length_over_bound_and_total_over_bound_are_rejected() {
        let mut encoded = observation(MemoryV1DenyAffectedBindingState::Unknown)
            .encode()
            .unwrap();
        // The first target option tag is followed by its u32 length.
        let mut offset = MEMORY_V1_DENY_OBSERVATION_HEADER_BYTES + 16 + 8 + 32 + 1 + 8 + 8 + 8;
        offset += 16 * 4 + 8;
        offset += 4 + "resource".len() + 4 + "action".len();
        encoded[offset + 1..offset + 5].copy_from_slice(
            &(u32::try_from(MEMORY_V1_DENY_OBSERVATION_MAX_RAW_BYTES + 1).unwrap()).to_be_bytes(),
        );
        assert_eq!(
            MemoryV1DenyObservation::decode(&encoded),
            Err(MemoryV1DenyObservationError::LimitExceeded)
        );

        let mut oversized = vec![0u8; MEMORY_V1_DENY_OBSERVATION_MAX_BYTES + 1];
        oversized[..8].copy_from_slice(MAGIC);
        oversized[8..10].copy_from_slice(&MEMORY_V1_DENY_OBSERVATION_VERSION.to_be_bytes());
        oversized[10] = KIND_OBSERVATION;
        let declared_length = u32::try_from(oversized.len()).unwrap();
        oversized[12..16].copy_from_slice(&declared_length.to_be_bytes());
        assert_eq!(
            MemoryV1DenyObservation::decode(&oversized),
            Err(MemoryV1DenyObservationError::LimitExceeded)
        );
    }

    #[test]
    // memory—v1
    fn debug_redacts_observation_and_nested_sensitive_values() {
        let value = observation(MemoryV1DenyAffectedBindingState::Present(
            MemoryV1DenyAffectedBinding::new(id(0x77), id(0x78), id(0x79), id(0x7a)),
        ));
        let output = format!(
            "{value:?} {:?} {:?}",
            value.root(),
            value.affected_binding()
        );
        assert!(output.contains("<redacted>"));
        assert!(!output.contains("resource"));
        assert!(!output.contains("77777777"));
    }

    #[test]
    // memory—v1
    fn pending_has_no_representable_observation_variant() {
        // The value has no decision field or Pending variant.  A codec tag of
        // zero is also rejected, so a pending outcome cannot be smuggled in as
        // a DENY observation.
        let mut encoded = observation(MemoryV1DenyAffectedBindingState::Unknown)
            .encode()
            .unwrap();
        let source_offset = encoded.len() - 6; // source, batch tag, and batch u32
        encoded[source_offset] = 0;
        assert_eq!(
            MemoryV1DenyObservation::decode(&encoded),
            Err(MemoryV1DenyObservationError::InvalidEncoding)
        );
    }

    #[test]
    // memory—v1
    fn checked_usize_root_conversion_is_explicit() {
        let root = MemoryV1DenyRootObservation::try_from_usize(
            id(1),
            2,
            [3; 32],
            MemoryV1DenyRootStatus::Serving,
            4,
            5,
            6,
        )
        .unwrap();
        assert_eq!(root.budget().max_table_rows(), 4);
        assert_eq!(root.budget().max_bindings_per_read(), 5);
        assert_eq!(root.row_count(), 6);
    }
}
