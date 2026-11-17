//! Structured memory-v1 audit values, independent of storage and authorization.
//!
//! Construction validates shape and resource bounds only. These values do not
//! prove identity, trusted time, a root observation, an authorization decision,
//! an append-only write, or persistence. The caller must supply actual facts;
//! unknown T2 facts must not be substituted with invented values. No storage
//! encoding, C-2 ordering, or audit delivery protocol is defined here.

use std::{fmt, str::FromStr};

use crate::memory_v1::MemoryId;

/// Maximum bytes accepted by the current evaluator for a request resource.
pub const MEMORY_V1_AUDIT_MAX_RESOURCE_BYTES: usize = 256;
/// Maximum bytes accepted by the current evaluator for a request action.
pub const MEMORY_V1_AUDIT_MAX_ACTION_BYTES: usize = 256;
/// Local resource bound for an audit reason code.
pub const MEMORY_V1_AUDIT_MAX_REASON_CODE_BYTES: usize = 128;
/// Maximum bytes for an operation identifier.
pub const MEMORY_V1_AUDIT_MAX_OPERATION_ID_BYTES: usize = 64;
/// Local resource limit covering the candidate 128-row batch, not a business batch limit.
pub const MEMORY_V1_AUDIT_MAX_CONFIRMATIONS: usize = 128;
/// Local byte limit for an opaque change summary; this is not a wire contract.
pub const MEMORY_V1_AUDIT_MAX_CHANGE_SUMMARY_BYTES: usize = 4096;
/// Maximum byte length of the explicit rule-set version pointer in the candidate schema.
pub const MEMORY_V1_AUDIT_MAX_RULE_SET_VERSION_BYTES: usize = 255;

/// Maximum byte length of a registry resource identifier.
///
/// This follows the memory-v1 registry contract: a bounded lowercase ASCII
/// identifier, not a UUID. The value layer does not prove registry membership.
pub const MEMORY_V1_AUDIT_MAX_REGISTRY_RESOURCE_BYTES: usize = 128;
/// Maximum number of independent T2 items in one local audit batch.
pub const MEMORY_V1_AUDIT_MAX_T2_BATCH_ITEMS: usize = 128;
/// Exact length of the lowercase hexadecimal representation of a SHA-256 value.
pub const MEMORY_V1_AUDIT_FINGERPRINT_HEX_BYTES: usize = 64;

/// A shape or resource-bound error. It never contains supplied values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryV1AuditError {
    /// A required text field is empty, too long, or contains control characters.
    InvalidText,
    /// A request resource or action is empty or exceeds the evaluator's byte limit.
    InvalidResourceOrAction,
    /// Operation identifier does not follow the request-binding contract.
    InvalidOperationId,
    /// The timestamp is outside the supported nonnegative Unix-second range.
    InvalidTime,
    /// A pending decision may only be observed through logs and metrics.
    PendingCannotBePersisted,
    /// This constructor requires a different decision.
    WrongDecision,
    /// A successful T2 record requires all frozen change fields.
    IncompleteChange,
    /// The supplied target and before/after states are structurally inconsistent.
    InconsistentChangeState,
    /// Reference list is empty, exceeds the local bound, or has invalid batch correlation.
    InvalidConfirmations,
    /// An overlay-only denial requires its explicit special-source details.
    MissingOverlaySource,
    /// The observed current rule-set version is empty or exceeds the schema bound.
    InvalidRuleSetVersion,
}

impl fmt::Display for MemoryV1AuditError {
    // memory—v1
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid memory-v1 audit value: {self:?}")
    }
}
impl std::error::Error for MemoryV1AuditError {}

// Prevent accidental disclosure through nested Debug formatting. Read-only
// accessors are deliberate: sinks must implement their own redaction policy.
macro_rules! redacted_debug {
    ($($name:ident),+ $(,)?) => {$ (
        impl fmt::Debug for $name {
            // memory—v1
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    )+};
}

/// Identity and identity-card values observed for the request.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MemoryV1AuditActor {
    user: MemoryId,
    identity_card: MemoryId,
}
impl MemoryV1AuditActor {
    /// memory—v1: Capture both values; does not verify their relationship.
    pub const fn new(user: MemoryId, identity_card: MemoryId) -> Self {
        Self {
            user,
            identity_card,
        }
    }
    /// memory—v1: Return the observed user identifier.
    pub const fn user(&self) -> MemoryId {
        self.user
    }
    /// memory—v1: Return the observed identity-card identifier.
    pub const fn identity_card(&self) -> MemoryId {
        self.identity_card
    }
}

/// Exact request values, without normalizing or asserting registration or authorization.
/// They may contain control characters; logging and output sinks must escape or redact them.
#[derive(Clone, Eq, PartialEq)]
pub struct MemoryV1AuditAction {
    resource: String,
    action: String,
}
impl MemoryV1AuditAction {
    /// memory—v1: Preserve nonempty request values within evaluator byte limits.
    pub fn new(resource: &str, action: &str) -> Result<Self, MemoryV1AuditError> {
        if resource.is_empty()
            || resource.len() > MEMORY_V1_AUDIT_MAX_RESOURCE_BYTES
            || action.is_empty()
            || action.len() > MEMORY_V1_AUDIT_MAX_ACTION_BYTES
        {
            return Err(MemoryV1AuditError::InvalidResourceOrAction);
        }
        Ok(Self {
            resource: resource.into(),
            action: action.into(),
        })
    }
    /// memory—v1: Return the resource name.
    pub fn resource(&self) -> &str {
        &self.resource
    }
    /// memory—v1: Return the action name.
    pub fn action(&self) -> &str {
        &self.action
    }
}

/// Operation identifier and SHA-256 request fingerprint as supplied by the caller.
#[derive(Clone, Eq, PartialEq)]
pub struct MemoryV1AuditOperation {
    id: String,
    fingerprint: [u8; 32],
}

fn decode_audit_fingerprint_hex(value: &str) -> Result<[u8; 32], MemoryV1AuditError> {
    let bytes = value.as_bytes();
    if bytes.len() != MEMORY_V1_AUDIT_FINGERPRINT_HEX_BYTES
        || !bytes
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(MemoryV1AuditError::InvalidText);
    }
    let mut fingerprint = [0u8; 32];
    for (index, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
        let high = match pair[0] {
            b'0'..=b'9' => pair[0] - b'0',
            b'a'..=b'f' => pair[0] - b'a' + 10,
            _ => unreachable!("validated lowercase hexadecimal input"),
        };
        let low = match pair[1] {
            b'0'..=b'9' => pair[1] - b'0',
            b'a'..=b'f' => pair[1] - b'a' + 10,
            _ => unreachable!("validated lowercase hexadecimal input"),
        };
        fingerprint[index] = (high << 4) | low;
    }
    Ok(fingerprint)
}

fn encode_audit_fingerprint_hex(fingerprint: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(MEMORY_V1_AUDIT_FINGERPRINT_HEX_BYTES);
    for byte in fingerprint {
        value.push(HEX[(byte >> 4) as usize] as char);
        value.push(HEX[(byte & 0x0f) as usize] as char);
    }
    value
}

/// Convert an explicit 64-character lowercase hexadecimal fingerprint to bytes.
///
/// This is a representation conversion only. It does not establish who supplied
/// the value, how it was computed, or whether it is trusted.
pub fn memory_v1_audit_fingerprint_from_hex(value: &str) -> Result<[u8; 32], MemoryV1AuditError> {
    decode_audit_fingerprint_hex(value)
}

/// Convert an explicit 32-byte fingerprint to its lowercase hexadecimal form.
///
/// This is a representation conversion only and makes no provenance claim.
pub fn memory_v1_audit_fingerprint_to_hex(fingerprint: &[u8; 32]) -> String {
    encode_audit_fingerprint_hex(fingerprint)
}

impl MemoryV1AuditOperation {
    /// memory—v1: Check the request-ID format; no uniqueness or hash provenance is proven.
    pub fn new(id: &str, fingerprint: [u8; 32]) -> Result<Self, MemoryV1AuditError> {
        if id.is_empty()
            || id.len() > MEMORY_V1_AUDIT_MAX_OPERATION_ID_BYTES
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.:/".contains(&b))
        {
            return Err(MemoryV1AuditError::InvalidOperationId);
        }
        Ok(Self {
            id: id.into(),
            fingerprint,
        })
    }

    /// memory—v1: Construct from an explicit lowercase hexadecimal fingerprint.
    /// The decoded bytes remain caller-supplied and untrusted.
    pub fn from_hex(id: &str, fingerprint_hex: &str) -> Result<Self, MemoryV1AuditError> {
        Self::new(id, decode_audit_fingerprint_hex(fingerprint_hex)?)
    }

    /// Compatibility spelling for callers that prefer constructor-style naming.
    pub fn new_from_hex(id: &str, fingerprint_hex: &str) -> Result<Self, MemoryV1AuditError> {
        Self::from_hex(id, fingerprint_hex)
    }

    /// memory—v1: Return the operation identifier.
    pub fn id(&self) -> &str {
        &self.id
    }
    /// memory—v1: Return the raw SHA-256 fingerprint bytes.
    pub const fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }
    /// memory—v1: Return the explicit lowercase hexadecimal representation.
    /// This does not prove the fingerprint's origin or trustworthiness.
    pub fn fingerprint_hex(&self) -> String {
        encode_audit_fingerprint_hex(&self.fingerprint)
    }
    /// Convert explicit fingerprint bytes to lowercase hexadecimal.
    pub fn fingerprint_to_hex(fingerprint: &[u8; 32]) -> String {
        encode_audit_fingerprint_hex(fingerprint)
    }
    /// Convert explicit lowercase hexadecimal to fingerprint bytes.
    pub fn fingerprint_from_hex(value: &str) -> Result<[u8; 32], MemoryV1AuditError> {
        decode_audit_fingerprint_hex(value)
    }
}

/// Observed lifecycle of the root, not evidence of its readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryV1AuditRootStatus {
    /// Candidate state.
    Candidate,
    /// Serving state.
    Serving,
    /// Invalid state.
    Invalid,
    /// Stopped state.
    Stopped,
}

/// Root version in its process-instance domain, distinct from rule-set versions.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MemoryV1AuditRootVersion {
    instance: MemoryId,
    version: u64,
}
impl MemoryV1AuditRootVersion {
    /// memory—v1: Capture supplied root instance and version without proving freshness.
    pub const fn new(instance: MemoryId, version: u64) -> Self {
        Self { instance, version }
    }
    /// memory—v1: Return the process instance identifier.
    pub const fn instance(&self) -> MemoryId {
        self.instance
    }
    /// memory—v1: Return the process-local version.
    pub const fn version(&self) -> u64 {
        self.version
    }
}

/// Complete metadata observed for one root reading phase.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MemoryV1AuditRootObservation {
    version: MemoryV1AuditRootVersion,
    content_hash: [u8; 32],
    status: MemoryV1AuditRootStatus,
}
impl MemoryV1AuditRootObservation {
    /// memory—v1: Capture supplied root metadata; no hash provenance is checked.
    pub const fn new(
        version: MemoryV1AuditRootVersion,
        content_hash: [u8; 32],
        status: MemoryV1AuditRootStatus,
    ) -> Self {
        Self {
            version,
            content_hash,
            status,
        }
    }
    /// memory—v1: Return the instance and version.
    pub const fn version(&self) -> MemoryV1AuditRootVersion {
        self.version
    }
    /// memory—v1: Return the observed precomputed content hash.
    pub const fn content_hash(&self) -> &[u8; 32] {
        &self.content_hash
    }
    /// memory—v1: Return the observed root lifecycle state.
    pub const fn status(&self) -> MemoryV1AuditRootStatus {
        self.status
    }
}

/// Caller-supplied final trusted-clock observation in Unix seconds.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MemoryV1AuditTime(i64);
impl MemoryV1AuditTime {
    /// memory—v1: Reject negative seconds; does not establish clock trust or freshness.
    pub fn new(unix_seconds: i64) -> Result<Self, MemoryV1AuditError> {
        if unix_seconds < 0 {
            return Err(MemoryV1AuditError::InvalidTime);
        }
        Ok(Self(unix_seconds))
    }
    /// memory—v1: Return the supplied Unix seconds.
    pub const fn unix_seconds(&self) -> i64 {
        self.0
    }
}

/// Frozen internal DENY sources; independent of external reason codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryV1AuditDenySource {
    /// Explicit rule denial.
    RuleDeny,
    /// Complete context had no matching authorization.
    NoMatch,
    /// Target outside scope.
    ScopeDenied,
    /// Card has no bindings.
    CardUnbound,
    /// Identity relationship mismatch.
    IdentityMismatch,
    /// Resource/action not registered.
    UnregisteredResource,
    /// Confirmation of one's own authority.
    SelfConfirmation,
    /// User card disabled.
    CardDisabled,
    /// Overlay-only creation denial.
    OverlayOnlyCreation,
}

impl MemoryV1AuditDenySource {
    /// memory—v1: Return the frozen source name without claiming an audit write.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RuleDeny => "rule_deny",
            Self::NoMatch => "no_match",
            Self::ScopeDenied => "scope_denied",
            Self::CardUnbound => "card_unbound",
            Self::IdentityMismatch => "identity_mismatch",
            Self::UnregisteredResource => "unregistered_resource",
            Self::SelfConfirmation => "self_confirmation",
            Self::CardDisabled => "card_disabled",
            Self::OverlayOnlyCreation => "overlay_only_creation",
        }
    }
}

/// Decision input, including PENDING so persistence attempts can be rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryV1AuditDecisionInput {
    /// An ALLOW decision.
    Allow,
    /// A DENY decision and its required internal source.
    Deny(MemoryV1AuditDenySource),
    /// A PENDING decision, which is not a persistent audit event.
    Pending,
}

/// Persistable decisions only; DENY always includes its source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryV1AuditDecision {
    /// An ALLOW decision.
    Allow,
    /// A DENY decision with a frozen internal source.
    Deny(MemoryV1AuditDenySource),
}
impl TryFrom<MemoryV1AuditDecisionInput> for MemoryV1AuditDecision {
    type Error = MemoryV1AuditError;
    // memory—v1
    fn try_from(value: MemoryV1AuditDecisionInput) -> Result<Self, Self::Error> {
        match value {
            MemoryV1AuditDecisionInput::Allow => Ok(Self::Allow),
            MemoryV1AuditDecisionInput::Deny(source) => Ok(Self::Deny(source)),
            MemoryV1AuditDecisionInput::Pending => {
                Err(MemoryV1AuditError::PendingCannotBePersisted)
            }
        }
    }
}

/// Common fields of a determinate request audit record.
#[derive(Clone, Eq, PartialEq)]
pub struct MemoryV1AuditContext {
    actor: MemoryV1AuditActor,
    time: MemoryV1AuditTime,
    action: MemoryV1AuditAction,
    reason_code: String,
    operation: MemoryV1AuditOperation,
    root: MemoryV1AuditRootObservation,
}
impl MemoryV1AuditContext {
    /// memory—v1: Require all common fields. Reason-code vocabulary is not inferred here.
    pub fn new(
        actor: MemoryV1AuditActor,
        time: MemoryV1AuditTime,
        action: MemoryV1AuditAction,
        reason_code: &str,
        operation: MemoryV1AuditOperation,
        root: MemoryV1AuditRootObservation,
    ) -> Result<Self, MemoryV1AuditError> {
        if reason_code.is_empty()
            || reason_code.len() > MEMORY_V1_AUDIT_MAX_REASON_CODE_BYTES
            || reason_code.chars().any(char::is_control)
        {
            return Err(MemoryV1AuditError::InvalidText);
        }
        Ok(Self {
            actor,
            time,
            action,
            reason_code: reason_code.into(),
            operation,
            root,
        })
    }
    /// memory—v1: Return both actor identifiers.
    pub const fn actor(&self) -> MemoryV1AuditActor {
        self.actor
    }
    /// memory—v1: Return the supplied clock observation.
    pub const fn time(&self) -> MemoryV1AuditTime {
        self.time
    }
    /// memory—v1: Return resource and action.
    pub const fn action(&self) -> &MemoryV1AuditAction {
        &self.action
    }
    /// memory—v1: Return the supplied reason code.
    pub fn reason_code(&self) -> &str {
        &self.reason_code
    }
    /// memory—v1: Return operation correlation.
    pub const fn operation(&self) -> &MemoryV1AuditOperation {
        &self.operation
    }
    /// memory—v1: Return the root reading-phase observation.
    pub const fn root(&self) -> MemoryV1AuditRootObservation {
        self.root
    }
}

/// A typed management target or scope identifier; no existence is implied.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum MemoryV1AuditObject {
    /// Tenant.
    Tenant(MemoryId),
    /// User card.
    UserCard(MemoryId),
    /// Rule set.
    RuleSet(MemoryId),
    /// Binding.
    Binding(MemoryId),
    /// Confirmation.
    Confirmation(MemoryId),
    /// User.
    User(MemoryId),
}

/// A bounded registry resource identifier used as an audit target.
///
/// Registry resources are lowercase bounded identifiers such as `binding`, not
/// UUID values. This type validates shape only; it does not prove registration,
/// lifecycle, ownership, or authorization.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MemoryV1AuditRegistryResource {
    bytes: [u8; MEMORY_V1_AUDIT_MAX_REGISTRY_RESOURCE_BYTES],
    len: u8,
}

impl MemoryV1AuditRegistryResource {
    /// memory—v1: Capture a nonempty bounded registry resource identifier.
    pub fn new(value: &str) -> Result<Self, MemoryV1AuditError> {
        let bytes = value.as_bytes();
        let Some(first) = bytes.first() else {
            return Err(MemoryV1AuditError::InvalidResourceOrAction);
        };
        if bytes.len() > MEMORY_V1_AUDIT_MAX_REGISTRY_RESOURCE_BYTES
            || !first.is_ascii_lowercase()
            || !bytes[1..].iter().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_' || *byte == b'-'
            })
        {
            return Err(MemoryV1AuditError::InvalidResourceOrAction);
        }
        let mut stored = [0u8; MEMORY_V1_AUDIT_MAX_REGISTRY_RESOURCE_BYTES];
        stored[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            bytes: stored,
            len: bytes.len() as u8,
        })
    }

    /// memory—v1: Return the exact supplied identifier.
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.len as usize])
            .expect("registry resource bytes are validated ASCII")
    }

    /// memory—v1: Return the exact identifier bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// memory—v1: Return the bounded identifier length.
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// memory—v1: Return whether the identifier is empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl FromStr for MemoryV1AuditRegistryResource {
    type Err = MemoryV1AuditError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<&str> for MemoryV1AuditRegistryResource {
    type Error = MemoryV1AuditError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// A registry target kept separate from [`MemoryV1AuditObject`] so adding this
/// value does not add a variant to the existing public enum or break exhaustive
/// matches and existing `Copy` callers.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MemoryV1AuditRegistryTarget {
    resource: MemoryV1AuditRegistryResource,
}

impl MemoryV1AuditRegistryTarget {
    /// memory—v1: Capture a registry resource target by bounded identifier.
    pub const fn new(resource: MemoryV1AuditRegistryResource) -> Self {
        Self { resource }
    }

    /// memory—v1: Return the registry resource identifier.
    pub const fn resource(&self) -> MemoryV1AuditRegistryResource {
        self.resource
    }

    /// memory—v1: Return the registry resource as text.
    pub fn as_str(&self) -> &str {
        self.resource.as_str()
    }

    /// memory—v1: Match only the supplied registry state family.
    pub fn matches_state(&self, state: &MemoryV1AuditObjectState) -> bool {
        matches!(state, MemoryV1AuditObjectState::Registry(_))
    }

    /// memory—v1: Match a creation or update transition without proving facts.
    pub fn matches_transition(
        &self,
        before: &MemoryV1AuditObjectState,
        after: &MemoryV1AuditObjectState,
    ) -> bool {
        self.matches_state(after)
            && (matches!(before, MemoryV1AuditObjectState::Absent) || self.matches_state(before))
    }
}

impl FromStr for MemoryV1AuditRegistryTarget {
    type Err = MemoryV1AuditError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(MemoryV1AuditRegistryResource::new(value)?))
    }
}

/// A target or scope in a new value-level T2 shape. Existing object enums remain
/// unchanged for source compatibility.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum MemoryV1AuditTarget {
    /// A typed UUID-backed management object.
    Object(MemoryV1AuditObject),
    /// A bounded registry resource identifier.
    Registry(MemoryV1AuditRegistryTarget),
}

impl MemoryV1AuditTarget {
    /// memory—v1: Match the target family to an observed state.
    pub fn matches_state(&self, state: &MemoryV1AuditObjectState) -> bool {
        match self {
            Self::Object(target) => target.matches_state(state),
            Self::Registry(target) => target.matches_state(state),
        }
    }

    /// memory—v1: Match a target against before/after state shape.
    pub fn matches_transition(
        &self,
        before: &MemoryV1AuditObjectState,
        after: &MemoryV1AuditObjectState,
    ) -> bool {
        match self {
            Self::Object(target) => target.matches_transition(before, after),
            Self::Registry(target) => target.matches_transition(before, after),
        }
    }
}

impl MemoryV1AuditObject {
    /// memory—v1: Match an existing UUID-backed target to its state family.
    pub fn matches_state(&self, state: &MemoryV1AuditObjectState) -> bool {
        matches!(
            (self, state),
            (Self::UserCard(_), MemoryV1AuditObjectState::UserCard(_))
                | (Self::Binding(_), MemoryV1AuditObjectState::Binding(_))
                | (
                    Self::Confirmation(_),
                    MemoryV1AuditObjectState::Confirmation(_)
                )
                | (Self::RuleSet(_), MemoryV1AuditObjectState::RuleSet(_))
        )
    }

    /// memory—v1: Match an existing target to a creation or update transition.
    pub fn matches_transition(
        &self,
        before: &MemoryV1AuditObjectState,
        after: &MemoryV1AuditObjectState,
    ) -> bool {
        self.matches_state(after)
            && (matches!(before, MemoryV1AuditObjectState::Absent) || self.matches_state(before))
            && compatible_rule_set_lifecycle_observations(before, after)
    }
}

/// Frozen user-card state values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryV1AuditCardState {
    /// Card active.
    Active,
    /// Card disabled.
    Disabled,
}
/// Frozen binding state values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryV1AuditBindingState {
    /// Binding active.
    Active,
    /// Binding removed.
    Removed,
}
/// Frozen confirmation state values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryV1AuditConfirmationState {
    /// Confirmation not revoked.
    Active,
    /// Confirmation revoked.
    Revoked,
}
/// Frozen registry lifecycle values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryV1AuditRegistryState {
    /// Registered and active.
    Active,
    /// Retirement requested.
    RetireRequested,
    /// Retired.
    Retired,
}
/// Observed rule-set lifecycle values; these assertions do not prove the facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryV1AuditRuleSetStatus {
    /// The rule set is active.
    Active,
    /// The rule set is retired.
    Retired,
}

/// An observed rule-set current version, stored content digest, and optional lifecycle.
/// These supplied values do not prove that the version or lifecycle facts are valid.
#[derive(Clone, Eq, PartialEq)]
pub struct MemoryV1AuditRuleSetState {
    current_version: Vec<u8>,
    content_hash: [u8; 32],
    status: Option<MemoryV1AuditRuleSetStatus>,
}

impl MemoryV1AuditRuleSetState {
    /// memory—v1: Preserve a bounded version and hash with an unknown lifecycle.
    /// This legacy constructor must not be used as evidence of active status.
    pub fn new(current_version: &[u8], content_hash: [u8; 32]) -> Result<Self, MemoryV1AuditError> {
        if current_version.is_empty()
            || current_version.len() > MEMORY_V1_AUDIT_MAX_RULE_SET_VERSION_BYTES
        {
            return Err(MemoryV1AuditError::InvalidRuleSetVersion);
        }
        Ok(Self {
            current_version: current_version.to_vec(),
            content_hash,
            status: None,
        })
    }

    /// memory—v1: Preserve an explicitly observed lifecycle with the version and hash.
    pub fn new_with_status(
        current_version: &[u8],
        content_hash: [u8; 32],
        status: MemoryV1AuditRuleSetStatus,
    ) -> Result<Self, MemoryV1AuditError> {
        let mut state = Self::new(current_version, content_hash)?;
        state.status = Some(status);
        Ok(state)
    }

    /// memory—v1: Return the observed status, or unknown for a legacy value.
    pub const fn status(&self) -> Option<MemoryV1AuditRuleSetStatus> {
        self.status
    }

    /// memory—v1: Return the exact observed current-version bytes.
    pub fn current_version(&self) -> &[u8] {
        &self.current_version
    }

    /// memory—v1: Return the supplied current-version content hash.
    pub const fn content_hash(&self) -> &[u8; 32] {
        &self.content_hash
    }
}

/// Structured before/after state. Absent is an observed fact, not unknown.
/// A rule-set state built with the legacy constructor has an unknown lifecycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemoryV1AuditObjectState {
    /// Object is proven absent at this point.
    Absent,
    /// User-card lifecycle.
    UserCard(MemoryV1AuditCardState),
    /// Binding lifecycle.
    Binding(MemoryV1AuditBindingState),
    /// Confirmation lifecycle.
    Confirmation(MemoryV1AuditConfirmationState),
    /// Registry lifecycle.
    Registry(MemoryV1AuditRegistryState),
    /// Current rule-set version pointer, stored digest, and observed lifecycle if known.
    RuleSet(MemoryV1AuditRuleSetState),
}

// Mixed known/unknown observations cannot describe a complete lifecycle transition.
// Both unknown remain accepted for legacy version/hash-only records; callers that
// require retirement facts must use the explicit retirement checks below.
fn compatible_rule_set_lifecycle_observations(
    before: &MemoryV1AuditObjectState,
    after: &MemoryV1AuditObjectState,
) -> bool {
    match (before, after) {
        (MemoryV1AuditObjectState::RuleSet(before), MemoryV1AuditObjectState::RuleSet(after)) => {
            before.status().is_some() == after.status().is_some()
        }
        _ => true,
    }
}

impl MemoryV1AuditObject {
    /// memory—v1: Check an ACTIVE to RETIRED observation with unchanged version and hash.
    /// This does not verify the observations, eligibility, authorization, or execution.
    pub fn matches_rule_set_retirement(
        &self,
        before: &MemoryV1AuditObjectState,
        after: &MemoryV1AuditObjectState,
    ) -> bool {
        matches!(self, Self::RuleSet(_))
            && matches!(
                (before, after),
                (MemoryV1AuditObjectState::RuleSet(before), MemoryV1AuditObjectState::RuleSet(after))
                    if before.status() == Some(MemoryV1AuditRuleSetStatus::Active)
                        && after.status() == Some(MemoryV1AuditRuleSetStatus::Retired)
                        && before.current_version() == after.current_version()
                        && before.content_hash() == after.content_hash()
            )
    }
}

/// One independent T2 audit item. Every field is retained exactly as supplied;
/// the value proves only local shape and correlation, never execution or storage.
#[derive(Clone, Eq, PartialEq)]
pub struct MemoryV1AuditT2BatchItem {
    sequence: u32,
    target: MemoryV1AuditTarget,
    scope: MemoryV1AuditTarget,
    before: MemoryV1AuditObjectState,
    after: MemoryV1AuditObjectState,
    confirmation: MemoryV1AuditConfirmationRef,
    operation: MemoryV1AuditOperation,
}

impl MemoryV1AuditT2BatchItem {
    /// memory—v1: Capture one complete, caller-supplied T2 audit item.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequence: u32,
        target: MemoryV1AuditTarget,
        scope: MemoryV1AuditTarget,
        before: MemoryV1AuditObjectState,
        after: MemoryV1AuditObjectState,
        confirmation: MemoryV1AuditConfirmationRef,
        operation: MemoryV1AuditOperation,
    ) -> Self {
        Self {
            sequence,
            target,
            scope,
            before,
            after,
            confirmation,
            operation,
        }
    }

    /// memory—v1: Return whether explicit observations have retirement shape.
    /// This is a shape check, not proof of retirement or authorization.
    pub fn is_rule_set_retirement(&self) -> bool {
        match self.target {
            MemoryV1AuditTarget::Object(target) => {
                target.matches_rule_set_retirement(&self.before, &self.after)
            }
            MemoryV1AuditTarget::Registry(_) => false,
        }
    }

    /// memory—v1: Return the caller-supplied sequence number.
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    /// memory—v1: Return the target object or registry resource.
    pub const fn target(&self) -> MemoryV1AuditTarget {
        self.target
    }

    /// memory—v1: Return the target scope.
    pub const fn scope(&self) -> MemoryV1AuditTarget {
        self.scope
    }

    /// memory—v1: Return the observed before state.
    pub const fn before(&self) -> &MemoryV1AuditObjectState {
        &self.before
    }

    /// memory—v1: Return the observed after state.
    pub const fn after(&self) -> &MemoryV1AuditObjectState {
        &self.after
    }

    /// memory—v1: Return the confirmation reference.
    pub const fn confirmation(&self) -> MemoryV1AuditConfirmationRef {
        self.confirmation
    }

    /// memory—v1: Return this item's operation correlation.
    pub const fn operation(&self) -> &MemoryV1AuditOperation {
        &self.operation
    }
}

/// An independent, bounded T2 audit batch.
///
/// The batch preserves item order and each item's complete target/scope/state/
/// confirmation/operation tuple. It is a value-layer candidate only: it does
/// not prove authorization, root membership, confirmation validity, atomicity,
/// append-only behavior, or persistence.
#[derive(Clone, Eq, PartialEq)]
pub struct MemoryV1AuditT2Batch {
    operation: MemoryV1AuditOperation,
    items: Vec<MemoryV1AuditT2BatchItem>,
}

impl MemoryV1AuditT2Batch {
    /// memory—v1: Build a nonempty bounded batch from items with one operation.
    pub fn new(
        items: &[MemoryV1AuditT2BatchItem],
        max_items: usize,
    ) -> Result<Self, MemoryV1AuditError> {
        Self::new_with_source(items, max_items, MemoryV1AuditSource::Ordinary)
    }

    /// memory—v1: Build a batch while enforcing the source-specific §4.15 rule.
    /// OVERLAY-only creation is always represented by one explicit audit value,
    /// so it cannot be wrapped in this multi-item batch. This validates shape only.
    pub fn new_with_source(
        items: &[MemoryV1AuditT2BatchItem],
        max_items: usize,
        source: MemoryV1AuditSource,
    ) -> Result<Self, MemoryV1AuditError> {
        if matches!(source, MemoryV1AuditSource::OverlayOnlyCreation(_)) {
            return Err(MemoryV1AuditError::InvalidConfirmations);
        }
        Self::new_unchecked_source(items, max_items)
    }

    fn new_unchecked_source(
        items: &[MemoryV1AuditT2BatchItem],
        max_items: usize,
    ) -> Result<Self, MemoryV1AuditError> {
        if max_items == 0
            || max_items > MEMORY_V1_AUDIT_MAX_T2_BATCH_ITEMS
            || items.is_empty()
            || items.len() > max_items
        {
            return Err(MemoryV1AuditError::InvalidConfirmations);
        }

        let operation = items[0].operation.clone();
        for (position, item) in items.iter().enumerate() {
            if usize::try_from(item.sequence) != Ok(position)
                || item.operation != operation
                || !item.target.matches_transition(&item.before, &item.after)
                || items[..position]
                    .iter()
                    .any(|previous| previous.target == item.target)
                || items[..position].iter().any(|previous| {
                    previous.confirmation.confirmation_id() == item.confirmation.confirmation_id()
                })
            {
                return Err(MemoryV1AuditError::InvalidConfirmations);
            }
        }

        Ok(Self {
            operation,
            items: items.to_vec(),
        })
    }

    /// memory—v1: Return the one operation shared by every item.
    pub const fn operation(&self) -> &MemoryV1AuditOperation {
        &self.operation
    }

    /// memory—v1: Return all retained items in validated sequence order.
    pub fn items(&self) -> &[MemoryV1AuditT2BatchItem] {
        &self.items
    }

    /// memory—v1: Return the item count.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// memory—v1: Return whether this batch has no items.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Reject this batch when its caller-supplied source is OVERLAY-only.
    ///
    /// §4.15 requires one explicit audit record per OVERLAY-only creation. This
    /// checks only the value shape and does not prove the target's root category
    /// or the caller's authorization.
    pub fn validate_source(&self, source: MemoryV1AuditSource) -> Result<(), MemoryV1AuditError> {
        if matches!(source, MemoryV1AuditSource::OverlayOnlyCreation(_)) {
            return Err(MemoryV1AuditError::InvalidConfirmations);
        }
        Ok(())
    }
}

/// A confirmation reference, preserving its type without asserting validity.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum MemoryV1AuditConfirmationRef {
    /// Binding confirmation.
    Binding(MemoryId),
    /// Rule-set version change confirmation.
    RuleSetChange(MemoryId),
}
impl MemoryV1AuditConfirmationRef {
    /// memory—v1: Return the supplied confirmation identifier without proving its origin.
    pub const fn confirmation_id(&self) -> MemoryId {
        match self {
            Self::Binding(id) | Self::RuleSetChange(id) => *id,
        }
    }
}

/// One ordered confirmation entry in a caller-supplied batch.
///
/// The sequence is a correlation value only. It does not prove that the entry was
/// processed, committed, or written to an append-only sink.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MemoryV1AuditConfirmationBatchItem {
    sequence: u32,
    confirmation: MemoryV1AuditConfirmationRef,
}
impl MemoryV1AuditConfirmationBatchItem {
    /// memory—v1: Capture an explicit zero-based position and typed confirmation reference.
    pub const fn new(sequence: u32, confirmation: MemoryV1AuditConfirmationRef) -> Self {
        Self {
            sequence,
            confirmation,
        }
    }

    /// memory—v1: Return the caller-supplied zero-based position.
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    /// memory—v1: Return the typed confirmation reference.
    pub const fn confirmation(&self) -> MemoryV1AuditConfirmationRef {
        self.confirmation
    }
}

/// An ordered, bounded confirmation batch correlated to one operation.
///
/// This is a pure value candidate for an audit event. It preserves caller-supplied
/// order and correlation, but cannot prove confirmation validity, source provenance,
/// processing order, a successful root CAS, or durable persistence.
#[derive(Clone, Eq, PartialEq)]
pub struct MemoryV1AuditConfirmationBatch {
    operation: MemoryV1AuditOperation,
    items: Vec<MemoryV1AuditConfirmationBatchItem>,
}
impl MemoryV1AuditConfirmationBatch {
    /// memory—v1: Build a nonempty ordered batch under an explicit caller limit.
    ///
    /// `max_items` is an operational input, not a frozen configuration. The model
    /// additionally enforces `MEMORY_V1_AUDIT_MAX_CONFIRMATIONS` as a hard local
    /// safety bound. Items must be numbered contiguously from zero, and every
    /// confirmation identifier must be unique across reference variants.
    pub fn new(
        operation: MemoryV1AuditOperation,
        items: &[MemoryV1AuditConfirmationBatchItem],
        max_items: usize,
    ) -> Result<Self, MemoryV1AuditError> {
        if max_items == 0
            || max_items > MEMORY_V1_AUDIT_MAX_CONFIRMATIONS
            || items.is_empty()
            || items.len() > max_items
        {
            return Err(MemoryV1AuditError::InvalidConfirmations);
        }

        for (position, item) in items.iter().enumerate() {
            if usize::try_from(item.sequence) != Ok(position)
                || items[..position].iter().any(|previous| {
                    previous.confirmation.confirmation_id() == item.confirmation.confirmation_id()
                })
            {
                return Err(MemoryV1AuditError::InvalidConfirmations);
            }
        }

        Ok(Self {
            operation,
            items: items.to_vec(),
        })
    }

    /// memory—v1: Return the operation correlation supplied for every batch item.
    pub const fn operation(&self) -> &MemoryV1AuditOperation {
        &self.operation
    }

    /// memory—v1: Return the immutable ordered item sequence.
    pub fn items(&self) -> &[MemoryV1AuditConfirmationBatchItem] {
        &self.items
    }
}
/// Bounded confirmation facts. Unknown is `None` on `MemoryV1AuditChange`.
#[derive(Clone, Eq, PartialEq)]
pub struct MemoryV1AuditConfirmations(ConfirmationFacts);

#[derive(Clone, Eq, PartialEq)]
enum ConfirmationFacts {
    NotApplicable,
    References(Vec<MemoryV1AuditConfirmationRef>),
    Batch(MemoryV1AuditConfirmationBatch),
}

impl MemoryV1AuditConfirmations {
    /// memory—v1: Record the caller's explicit assertion that confirmation is inapplicable.
    pub const fn not_applicable() -> Self {
        Self(ConfirmationFacts::NotApplicable)
    }

    /// memory—v1: Validate reference count; it does not verify their existence.
    pub fn references(values: &[MemoryV1AuditConfirmationRef]) -> Result<Self, MemoryV1AuditError> {
        if values.is_empty() || values.len() > MEMORY_V1_AUDIT_MAX_CONFIRMATIONS {
            return Err(MemoryV1AuditError::InvalidConfirmations);
        }
        Ok(Self(ConfirmationFacts::References(values.to_vec())))
    }

    /// memory—v1: Capture an ordered operation-correlated confirmation batch.
    pub fn batch(
        operation: MemoryV1AuditOperation,
        items: &[MemoryV1AuditConfirmationBatchItem],
        max_items: usize,
    ) -> Result<Self, MemoryV1AuditError> {
        Ok(Self(ConfirmationFacts::Batch(
            MemoryV1AuditConfirmationBatch::new(operation, items, max_items)?,
        )))
    }

    /// memory—v1: Return true only for explicitly inapplicable confirmation.
    pub fn is_not_applicable(&self) -> bool {
        matches!(self.0, ConfirmationFacts::NotApplicable)
    }

    /// memory—v1: Return references, or none when explicitly inapplicable or batched.
    pub fn as_references(&self) -> Option<&[MemoryV1AuditConfirmationRef]> {
        match &self.0 {
            ConfirmationFacts::NotApplicable | ConfirmationFacts::Batch(_) => None,
            ConfirmationFacts::References(refs) => Some(refs),
        }
    }

    /// memory—v1: Return the operation-correlated batch, if this is a batch value.
    pub const fn as_batch(&self) -> Option<&MemoryV1AuditConfirmationBatch> {
        match &self.0 {
            ConfirmationFacts::Batch(batch) => Some(batch),
            ConfirmationFacts::NotApplicable | ConfirmationFacts::References(_) => None,
        }
    }
}

/// Explicit OVERLAY-only source with creator, beneficiary and rule-set references.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MemoryV1AuditOverlayOnly {
    creator: MemoryId,
    beneficiary: MemoryId,
    rule_set: MemoryId,
}
impl MemoryV1AuditOverlayOnly {
    /// memory—v1: Preserve the three supplied references, without validating authorization.
    pub const fn new(creator: MemoryId, beneficiary: MemoryId, rule_set: MemoryId) -> Self {
        Self {
            creator,
            beneficiary,
            rule_set,
        }
    }
    /// memory—v1: Return the creator user ID.
    pub const fn creator(&self) -> MemoryId {
        self.creator
    }
    /// memory—v1: Return the beneficiary user ID.
    pub const fn beneficiary(&self) -> MemoryId {
        self.beneficiary
    }
    /// memory—v1: Return the rule-set ID.
    pub const fn rule_set(&self) -> MemoryId {
        self.rule_set
    }
}

/// Special audit source, separate from the reason for a DENY.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum MemoryV1AuditSource {
    /// No special source marker.
    Ordinary,
    /// OVERLAY-only creation, including all three highlighted references.
    OverlayOnlyCreation(MemoryV1AuditOverlayOnly),
}

/// A typed, nonempty, bounded change summary. Its encoding and hash algorithm
/// are not frozen; the supplied bytes are not proof of their origin or binding.
#[derive(Clone, Eq, PartialEq)]
pub struct MemoryV1AuditChangeSummary(Vec<u8>);
impl MemoryV1AuditChangeSummary {
    /// memory—v1: Capture a bounded opaque summary without interpreting it.
    pub fn new(bytes: &[u8]) -> Result<Self, MemoryV1AuditError> {
        if bytes.is_empty() || bytes.len() > MEMORY_V1_AUDIT_MAX_CHANGE_SUMMARY_BYTES {
            return Err(MemoryV1AuditError::InvalidText);
        }
        Ok(Self(bytes.to_vec()))
    }
    /// memory—v1: Return the supplied bytes for an appropriately protected sink.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Complete value-level T2 details for one registry resource transition.
///
/// This is a candidate payload only. It preserves the operation, target, scope,
/// confirmation and observed states without proving registry membership, root
/// mutation, authorization, or persistence.
#[derive(Clone, Eq, PartialEq)]
struct MemoryV1AuditT2RegistryInner {
    operation: MemoryV1AuditOperation,
    target: MemoryV1AuditRegistryTarget,
    scope: MemoryV1AuditTarget,
    before: MemoryV1AuditObjectState,
    after: MemoryV1AuditObjectState,
    confirmation: MemoryV1AuditConfirmationRef,
}

#[derive(Clone, Eq, PartialEq)]
pub struct MemoryV1AuditT2Registry(Box<MemoryV1AuditT2RegistryInner>);

impl MemoryV1AuditT2Registry {
    /// memory—v1: Construct one complete registry transition payload.
    pub fn new(
        operation: MemoryV1AuditOperation,
        target: MemoryV1AuditRegistryTarget,
        scope: MemoryV1AuditTarget,
        before: MemoryV1AuditObjectState,
        after: MemoryV1AuditObjectState,
        confirmation: MemoryV1AuditConfirmationRef,
    ) -> Result<Self, MemoryV1AuditError> {
        if !target.matches_transition(&before, &after) {
            return Err(MemoryV1AuditError::InconsistentChangeState);
        }
        Ok(Self(Box::new(MemoryV1AuditT2RegistryInner {
            operation,
            target,
            scope,
            before,
            after,
            confirmation,
        })))
    }

    /// memory—v1: Return the operation correlation supplied for this payload.
    pub const fn operation(&self) -> &MemoryV1AuditOperation {
        &self.0.operation
    }

    /// memory—v1: Return the registry target.
    pub const fn target(&self) -> MemoryV1AuditRegistryTarget {
        self.0.target
    }

    /// memory—v1: Return the target scope.
    pub const fn scope(&self) -> MemoryV1AuditTarget {
        self.0.scope
    }

    /// memory—v1: Return the observed before state.
    pub const fn before(&self) -> &MemoryV1AuditObjectState {
        &self.0.before
    }

    /// memory—v1: Return the observed after state.
    pub const fn after(&self) -> &MemoryV1AuditObjectState {
        &self.0.after
    }

    /// memory—v1: Return the confirmation reference.
    pub const fn confirmation(&self) -> MemoryV1AuditConfirmationRef {
        self.0.confirmation
    }
}

/// Complete T2 payload shape: one registry transition or an ordered item batch.
#[derive(Clone, Eq, PartialEq)]
pub enum MemoryV1AuditT2EventPayload {
    /// One explicit registry transition.
    Registry(MemoryV1AuditT2Registry),
    /// Multiple explicit T2 items retained in sequence order.
    Batch(MemoryV1AuditT2Batch),
}

/// A complete T2 audit event candidate, independent of any storage sink.
///
/// Construction rejects PENDING, requires the common operation to match the
/// payload operation, retains approver/summary/root observations/source, and
/// rejects OVERLAY-only batches. It does not prove any supplied fact or claim a
/// durable audit write.
#[derive(Clone, Eq, PartialEq)]
pub struct MemoryV1AuditT2EventCandidate {
    context: MemoryV1AuditContext,
    decision: MemoryV1AuditDecision,
    approver: MemoryId,
    change_summary: MemoryV1AuditChangeSummary,
    root_before: MemoryV1AuditRootVersion,
    root_after: MemoryV1AuditRootVersion,
    source: MemoryV1AuditSource,
    payload: MemoryV1AuditT2EventPayload,
}

impl MemoryV1AuditT2EventCandidate {
    /// memory—v1: Construct a complete single-registry T2 candidate.
    #[allow(clippy::too_many_arguments)]
    pub fn registry(
        context: MemoryV1AuditContext,
        decision: MemoryV1AuditDecisionInput,
        approver: MemoryId,
        change_summary: MemoryV1AuditChangeSummary,
        root_before: MemoryV1AuditRootVersion,
        root_after: MemoryV1AuditRootVersion,
        source: MemoryV1AuditSource,
        registry: MemoryV1AuditT2Registry,
    ) -> Result<Self, MemoryV1AuditError> {
        Self::new(
            context,
            decision,
            approver,
            change_summary,
            root_before,
            root_after,
            source,
            MemoryV1AuditT2EventPayload::Registry(registry),
        )
    }

    /// memory—v1: Construct a complete ordered batch T2 candidate.
    #[allow(clippy::too_many_arguments)]
    pub fn batch(
        context: MemoryV1AuditContext,
        decision: MemoryV1AuditDecisionInput,
        approver: MemoryId,
        change_summary: MemoryV1AuditChangeSummary,
        root_before: MemoryV1AuditRootVersion,
        root_after: MemoryV1AuditRootVersion,
        source: MemoryV1AuditSource,
        batch: MemoryV1AuditT2Batch,
    ) -> Result<Self, MemoryV1AuditError> {
        Self::new(
            context,
            decision,
            approver,
            change_summary,
            root_before,
            root_after,
            source,
            MemoryV1AuditT2EventPayload::Batch(batch),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        context: MemoryV1AuditContext,
        decision: MemoryV1AuditDecisionInput,
        approver: MemoryId,
        change_summary: MemoryV1AuditChangeSummary,
        root_before: MemoryV1AuditRootVersion,
        root_after: MemoryV1AuditRootVersion,
        source: MemoryV1AuditSource,
        payload: MemoryV1AuditT2EventPayload,
    ) -> Result<Self, MemoryV1AuditError> {
        let decision = decision.try_into()?;
        if decision == MemoryV1AuditDecision::Deny(MemoryV1AuditDenySource::OverlayOnlyCreation)
            && !matches!(source, MemoryV1AuditSource::OverlayOnlyCreation(_))
        {
            return Err(MemoryV1AuditError::MissingOverlaySource);
        }
        match &payload {
            MemoryV1AuditT2EventPayload::Registry(registry) => {
                if registry.operation() != context.operation() {
                    return Err(MemoryV1AuditError::InvalidConfirmations);
                }
            }
            MemoryV1AuditT2EventPayload::Batch(batch) => {
                if matches!(source, MemoryV1AuditSource::OverlayOnlyCreation(_)) {
                    return Err(MemoryV1AuditError::InvalidConfirmations);
                }
                if batch.operation() != context.operation() {
                    return Err(MemoryV1AuditError::InvalidConfirmations);
                }
            }
        }
        Ok(Self {
            context,
            decision,
            approver,
            change_summary,
            root_before,
            root_after,
            source,
            payload,
        })
    }

    /// memory—v1: Return the common request context.
    pub const fn context(&self) -> &MemoryV1AuditContext {
        &self.context
    }

    /// memory—v1: Return the determinate decision and DENY source.
    pub const fn decision(&self) -> MemoryV1AuditDecision {
        self.decision
    }

    /// memory—v1: Return the required approver observation.
    pub const fn approver(&self) -> MemoryId {
        self.approver
    }

    /// memory—v1: Return the complete supplied change summary.
    pub const fn change_summary(&self) -> &MemoryV1AuditChangeSummary {
        &self.change_summary
    }

    /// memory—v1: Return the root version observed before the change.
    pub const fn root_before(&self) -> MemoryV1AuditRootVersion {
        self.root_before
    }

    /// memory—v1: Return the root version observed after the change.
    pub const fn root_after(&self) -> MemoryV1AuditRootVersion {
        self.root_after
    }

    /// memory—v1: Return the separate source marker.
    pub const fn source(&self) -> MemoryV1AuditSource {
        self.source
    }

    /// memory—v1: Return the complete registry-or-batch payload.
    pub const fn payload(&self) -> &MemoryV1AuditT2EventPayload {
        &self.payload
    }

    /// memory—v1: Return the operation bound to the common context.
    pub const fn operation(&self) -> &MemoryV1AuditOperation {
        self.context.operation()
    }

    /// memory—v1: Return the registry payload when this is a single-registry candidate.
    pub const fn registry_payload(&self) -> Option<&MemoryV1AuditT2Registry> {
        match &self.payload {
            MemoryV1AuditT2EventPayload::Registry(registry) => Some(registry),
            MemoryV1AuditT2EventPayload::Batch(_) => None,
        }
    }

    /// memory—v1: Return the batch payload when this is a batch candidate.
    pub const fn batch_payload(&self) -> Option<&MemoryV1AuditT2Batch> {
        match &self.payload {
            MemoryV1AuditT2EventPayload::Registry(_) => None,
            MemoryV1AuditT2EventPayload::Batch(batch) => Some(batch),
        }
    }
}

/// Caller-provided T2 facts. `None` means unknown, not absent or inapplicable.
/// A partial value supports DENY audit records without fabricating execution facts.
#[derive(Clone, Eq, PartialEq)]
pub struct MemoryV1AuditChange {
    approver: Option<MemoryId>,
    target: Option<MemoryV1AuditObject>,
    scope: Option<MemoryV1AuditObject>,
    change_summary: Option<MemoryV1AuditChangeSummary>,
    before: Option<MemoryV1AuditObjectState>,
    after: Option<MemoryV1AuditObjectState>,
    confirmations: Option<MemoryV1AuditConfirmations>,
    root_before: Option<MemoryV1AuditRootVersion>,
    root_after: Option<MemoryV1AuditRootVersion>,
    source: MemoryV1AuditSource,
}
impl MemoryV1AuditChange {
    /// memory—v1: Capture each known fact, without supplying defaults for unknowns.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        approver: Option<MemoryId>,
        target: Option<MemoryV1AuditObject>,
        scope: Option<MemoryV1AuditObject>,
        change_summary: Option<MemoryV1AuditChangeSummary>,
        before: Option<MemoryV1AuditObjectState>,
        after: Option<MemoryV1AuditObjectState>,
        confirmations: Option<MemoryV1AuditConfirmations>,
        root_before: Option<MemoryV1AuditRootVersion>,
        root_after: Option<MemoryV1AuditRootVersion>,
        source: MemoryV1AuditSource,
    ) -> Self {
        Self {
            approver,
            target,
            scope,
            change_summary,
            before,
            after,
            confirmations,
            root_before,
            root_after,
            source,
        }
    }
    /// memory—v1: Whether all outer change fields are supplied and paired rule-set
    /// lifecycle observations are either both known or both unknown. Two unknown
    /// statuses preserve legacy version/hash-only behavior, not retirement completeness.
    pub fn is_complete(&self) -> bool {
        self.approver.is_some()
            && self.target.is_some()
            && self.scope.is_some()
            && self.change_summary.is_some()
            && self.before.is_some()
            && self.after.is_some()
            && self.confirmations.is_some()
            && self.root_before.is_some()
            && self.root_after.is_some()
            && match (&self.before, &self.after) {
                (Some(before), Some(after)) => {
                    compatible_rule_set_lifecycle_observations(before, after)
                }
                _ => false,
            }
    }

    /// memory—v1: Require explicit ACTIVE and RETIRED observations in a complete,
    /// target-compatible change. This checks shape, not the truth of any fact.
    pub fn is_complete_rule_set_retirement(&self) -> bool {
        match (self.target, &self.before, &self.after) {
            (Some(target), Some(before), Some(after)) => {
                self.is_complete() && target.matches_rule_set_retirement(before, after)
            }
            _ => false,
        }
    }

    /// memory—v1: Check target/state shape only; this does not validate a transition or its facts.
    fn has_consistent_states(&self) -> bool {
        let (Some(target), Some(before), Some(after)) = (self.target, &self.before, &self.after)
        else {
            return false;
        };
        target.matches_transition(before, after)
    }

    /// memory—v1: Return the known approver, if supplied.
    pub const fn approver(&self) -> Option<MemoryId> {
        self.approver
    }
    /// memory—v1: Return the known target, if supplied.
    pub const fn target(&self) -> Option<MemoryV1AuditObject> {
        self.target
    }
    /// memory—v1: Return the known scope, if supplied.
    pub const fn scope(&self) -> Option<MemoryV1AuditObject> {
        self.scope
    }
    /// memory—v1: Return the supplied summary, if known.
    pub const fn change_summary(&self) -> Option<&MemoryV1AuditChangeSummary> {
        self.change_summary.as_ref()
    }
    /// memory—v1: Return the known before state.
    pub const fn before(&self) -> Option<&MemoryV1AuditObjectState> {
        self.before.as_ref()
    }
    /// memory—v1: Return the known after state.
    pub const fn after(&self) -> Option<&MemoryV1AuditObjectState> {
        self.after.as_ref()
    }
    /// memory—v1: Return confirmation references or explicit inapplicability, if known.
    pub const fn confirmations(&self) -> Option<&MemoryV1AuditConfirmations> {
        self.confirmations.as_ref()
    }
    /// memory—v1: Return the root version observed before the change, if known.
    pub const fn root_before(&self) -> Option<MemoryV1AuditRootVersion> {
        self.root_before
    }
    /// memory—v1: Return the root version observed after the change, if known.
    pub const fn root_after(&self) -> Option<MemoryV1AuditRootVersion> {
        self.root_after
    }
    /// memory—v1: Return the special-source marker.
    pub const fn source(&self) -> MemoryV1AuditSource {
        self.source
    }
}

/// Whether persistence is required or optional for a persistent event candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryV1AuditPersistence {
    /// Every DENY and T2 change requires persistent audit.
    Required,
    /// Ordinary ALLOW read persistence is optional.
    Optional,
}

/// A value eligible for a persistent audit sink, not proof of an actual write.
#[derive(Clone, Eq, PartialEq)]
pub struct MemoryV1AuditEvent {
    context: MemoryV1AuditContext,
    decision: MemoryV1AuditDecision,
    change: Option<MemoryV1AuditChange>,
}
impl MemoryV1AuditEvent {
    /// memory—v1: Build a T1 record. PENDING cannot be persisted.
    pub fn read(
        context: MemoryV1AuditContext,
        decision: MemoryV1AuditDecisionInput,
    ) -> Result<Self, MemoryV1AuditError> {
        let decision = decision.try_into()?;
        if decision == MemoryV1AuditDecision::Deny(MemoryV1AuditDenySource::OverlayOnlyCreation) {
            return Err(MemoryV1AuditError::MissingOverlaySource);
        }
        Ok(Self {
            context,
            decision,
            change: None,
        })
    }
    /// memory—v1: Build a T2 record. ALLOW requires all fields and compatible state kinds;
    /// DENY may carry partial facts. Callers must verify the facts and transition.
    pub fn change(
        context: MemoryV1AuditContext,
        decision: MemoryV1AuditDecisionInput,
        change: MemoryV1AuditChange,
    ) -> Result<Self, MemoryV1AuditError> {
        let decision = decision.try_into()?;
        if decision == MemoryV1AuditDecision::Deny(MemoryV1AuditDenySource::OverlayOnlyCreation)
            && !matches!(change.source, MemoryV1AuditSource::OverlayOnlyCreation(_))
        {
            return Err(MemoryV1AuditError::MissingOverlaySource);
        }
        if let Some(MemoryV1AuditConfirmations(ConfirmationFacts::Batch(batch))) =
            change.confirmations.as_ref()
        {
            if batch.operation() != context.operation() {
                return Err(MemoryV1AuditError::InvalidConfirmations);
            }
            if matches!(change.source, MemoryV1AuditSource::OverlayOnlyCreation(_)) {
                return Err(MemoryV1AuditError::InvalidConfirmations);
            }
        }
        if decision == MemoryV1AuditDecision::Allow {
            if !change.is_complete() {
                return Err(MemoryV1AuditError::IncompleteChange);
            }
            if !change.has_consistent_states() {
                return Err(MemoryV1AuditError::InconsistentChangeState);
            }
        }
        Ok(Self {
            context,
            decision,
            change: Some(change),
        })
    }
    /// memory—v1: Return the required versus optional persistence classification.
    pub fn persistence(&self) -> MemoryV1AuditPersistence {
        if self.change.is_some() || matches!(self.decision, MemoryV1AuditDecision::Deny(_)) {
            MemoryV1AuditPersistence::Required
        } else {
            MemoryV1AuditPersistence::Optional
        }
    }
    /// memory—v1: Return the common request fields.
    pub const fn context(&self) -> &MemoryV1AuditContext {
        &self.context
    }
    /// memory—v1: Return the decision and any DENY source.
    pub const fn decision(&self) -> MemoryV1AuditDecision {
        self.decision
    }
    /// memory—v1: Return the T2 details, or none for T1.
    pub const fn change_details(&self) -> Option<&MemoryV1AuditChange> {
        self.change.as_ref()
    }
}

/// A single successful T2 change candidate backed by the existing event value.
///
/// This is a transparent value-level wrapper: it can only be built from an
/// existing `MemoryV1AuditEvent` after checking an ALLOW decision, a present and
/// complete change, and target/state consistency. It preserves the original
/// event losslessly and makes the B-4 single-change shape distinct from reads,
/// DENY values, and batch candidates. It proves neither authorization nor
/// durable persistence and is not a submission receipt.
#[derive(Clone, Eq, PartialEq)]
pub struct MemoryV1AuditT2SingleChangeCandidate(MemoryV1AuditEvent);

impl TryFrom<MemoryV1AuditEvent> for MemoryV1AuditT2SingleChangeCandidate {
    type Error = MemoryV1AuditError;

    /// memory—v1: Admit only a complete successful, target-compatible T2 event.
    fn try_from(event: MemoryV1AuditEvent) -> Result<Self, Self::Error> {
        if event.decision != MemoryV1AuditDecision::Allow {
            return Err(MemoryV1AuditError::WrongDecision);
        }
        let Some(change) = event.change.as_ref() else {
            return Err(MemoryV1AuditError::IncompleteChange);
        };
        if !change.is_complete() {
            return Err(MemoryV1AuditError::IncompleteChange);
        }
        if !change.has_consistent_states() {
            return Err(MemoryV1AuditError::InconsistentChangeState);
        }
        if let Some(MemoryV1AuditConfirmations(ConfirmationFacts::Batch(_))) =
            change.confirmations.as_ref()
        {
            return Err(MemoryV1AuditError::InvalidConfirmations);
        }
        Ok(Self(event))
    }
}

impl MemoryV1AuditT2SingleChangeCandidate {
    /// memory—v1: Borrow the losslessly retained event value.
    pub const fn as_event(&self) -> &MemoryV1AuditEvent {
        &self.0
    }

    /// memory—v1: Return the retained event and all of its supplied values.
    pub fn into_event(self) -> MemoryV1AuditEvent {
        self.0
    }

    /// memory—v1: Return the complete common request context.
    pub const fn context(&self) -> &MemoryV1AuditContext {
        self.0.context()
    }

    /// memory—v1: Return the operation from the common context.
    pub const fn operation(&self) -> &MemoryV1AuditOperation {
        self.0.context().operation()
    }

    /// memory—v1: Return the admitted successful decision.
    pub const fn decision(&self) -> MemoryV1AuditDecision {
        self.0.decision()
    }

    /// memory—v1: Return the required approver observation.
    pub const fn approver(&self) -> MemoryId {
        self.change_details()
            .approver()
            .expect("validated complete change")
    }

    /// memory—v1: Return the target object.
    pub const fn target(&self) -> MemoryV1AuditObject {
        self.change_details()
            .target()
            .expect("validated complete change")
    }

    /// memory—v1: Return the target scope.
    pub const fn scope(&self) -> MemoryV1AuditObject {
        self.change_details()
            .scope()
            .expect("validated complete change")
    }

    /// memory—v1: Return the complete change summary.
    pub const fn change_summary(&self) -> &MemoryV1AuditChangeSummary {
        self.change_details()
            .change_summary()
            .expect("validated complete change")
    }

    /// memory—v1: Return the observed state before the change.
    pub const fn before(&self) -> &MemoryV1AuditObjectState {
        self.change_details()
            .before()
            .expect("validated complete change")
    }

    /// memory—v1: Return the observed state after the change.
    pub const fn after(&self) -> &MemoryV1AuditObjectState {
        self.change_details()
            .after()
            .expect("validated complete change")
    }

    /// memory—v1: Return the complete confirmation references value.
    pub const fn confirmations(&self) -> &MemoryV1AuditConfirmations {
        self.change_details()
            .confirmations()
            .expect("validated complete change")
    }

    /// memory—v1: Return the root version observed before the change.
    pub const fn root_before(&self) -> MemoryV1AuditRootVersion {
        self.change_details()
            .root_before()
            .expect("validated complete change")
    }

    /// memory—v1: Return the root version observed after the change.
    pub const fn root_after(&self) -> MemoryV1AuditRootVersion {
        self.change_details()
            .root_after()
            .expect("validated complete change")
    }

    /// memory—v1: Return the separate source marker without inferring one.
    pub const fn source(&self) -> MemoryV1AuditSource {
        self.change_details().source()
    }

    /// memory—v1: Return the complete retained change details.
    pub const fn change_details(&self) -> &MemoryV1AuditChange {
        self.0
            .change_details()
            .expect("single candidate always retains a change")
    }
}

/// Ordinary ALLOW read intended for a log sink; logging policy remains with the caller.
#[derive(Clone, Eq, PartialEq)]
pub struct MemoryV1AuditAllowReadLog(MemoryV1AuditContext);
impl MemoryV1AuditAllowReadLog {
    /// memory—v1: Construct a log-only value from the complete common context.
    pub const fn new(context: MemoryV1AuditContext) -> Self {
        Self(context)
    }
    /// memory—v1: Return common fields for a suitably redacting log sink.
    pub const fn context(&self) -> &MemoryV1AuditContext {
        &self.0
    }
    /// memory—v1: Explicitly choose optional persistence for this read.
    pub fn into_optional_event(self) -> MemoryV1AuditEvent {
        MemoryV1AuditEvent {
            context: self.0,
            decision: MemoryV1AuditDecision::Allow,
            change: None,
        }
    }
}

redacted_debug!(
    MemoryV1AuditActor,
    MemoryV1AuditAction,
    MemoryV1AuditOperation,
    MemoryV1AuditRootVersion,
    MemoryV1AuditRootObservation,
    MemoryV1AuditTime,
    MemoryV1AuditContext,
    MemoryV1AuditObject,
    MemoryV1AuditRegistryResource,
    MemoryV1AuditRegistryTarget,
    MemoryV1AuditTarget,
    MemoryV1AuditRuleSetState,
    MemoryV1AuditT2BatchItem,
    MemoryV1AuditT2Batch,
    MemoryV1AuditT2Registry,
    MemoryV1AuditT2EventPayload,
    MemoryV1AuditT2EventCandidate,
    MemoryV1AuditConfirmationRef,
    MemoryV1AuditConfirmationBatchItem,
    MemoryV1AuditConfirmationBatch,
    MemoryV1AuditConfirmations,
    MemoryV1AuditOverlayOnly,
    MemoryV1AuditSource,
    MemoryV1AuditChangeSummary,
    MemoryV1AuditChange,
    MemoryV1AuditEvent,
    MemoryV1AuditT2SingleChangeCandidate,
    MemoryV1AuditAllowReadLog
);

#[cfg(test)]
mod tests {
    use super::*;

    // memory—v1
    fn id(n: u8) -> MemoryId {
        MemoryId::from_bytes([n; 16])
    }
    // memory—v1
    fn root(n: u64) -> MemoryV1AuditRootVersion {
        MemoryV1AuditRootVersion::new(id(9), n)
    }
    // memory—v1
    fn context() -> MemoryV1AuditContext {
        MemoryV1AuditContext::new(
            MemoryV1AuditActor::new(id(1), id(2)),
            MemoryV1AuditTime::new(100).unwrap(),
            MemoryV1AuditAction::new("permission_rule", "read").unwrap(),
            "AUTHORIZATION_NO_MATCH",
            MemoryV1AuditOperation::new("sensitive-operation", [3; 32]).unwrap(),
            MemoryV1AuditRootObservation::new(root(1), [4; 32], MemoryV1AuditRootStatus::Serving),
        )
        .unwrap()
    }
    // memory—v1
    fn context_with_operation(operation: MemoryV1AuditOperation) -> MemoryV1AuditContext {
        let base = context();
        MemoryV1AuditContext::new(
            base.actor(),
            base.time(),
            base.action().clone(),
            base.reason_code(),
            operation,
            base.root(),
        )
        .unwrap()
    }
    // memory—v1
    fn change() -> MemoryV1AuditChange {
        MemoryV1AuditChange::new(
            Some(id(1)),
            Some(MemoryV1AuditObject::UserCard(id(3))),
            Some(MemoryV1AuditObject::Tenant(id(4))),
            Some(MemoryV1AuditChangeSummary::new(&[5; 32]).unwrap()),
            Some(MemoryV1AuditObjectState::UserCard(
                MemoryV1AuditCardState::Active,
            )),
            Some(MemoryV1AuditObjectState::UserCard(
                MemoryV1AuditCardState::Disabled,
            )),
            Some(
                MemoryV1AuditConfirmations::references(&[MemoryV1AuditConfirmationRef::Binding(
                    id(6),
                )])
                .unwrap(),
            ),
            Some(root(1)),
            Some(root(2)),
            MemoryV1AuditSource::Ordinary,
        )
    }

    #[test]
    // memory—v1
    fn requires_valid_common_values_and_preserves_observation() {
        let c = context();
        assert_eq!(c.actor().user(), id(1));
        assert_eq!(c.actor().identity_card(), id(2));
        assert_eq!(c.time().unix_seconds(), 100);
        assert_eq!(c.action().resource(), "permission_rule");
        assert_eq!(c.action().action(), "read");
        assert_eq!(c.reason_code(), "AUTHORIZATION_NO_MATCH");
        assert_eq!(c.operation().id(), "sensitive-operation");
        assert_eq!(c.operation().fingerprint(), &[3; 32]);
        assert_eq!(c.root().version(), root(1));
        assert_eq!(c.root().content_hash(), &[4; 32]);
        assert_eq!(c.root().status(), MemoryV1AuditRootStatus::Serving);
        for reason in ["", "bad\ncode"] {
            assert_eq!(
                MemoryV1AuditContext::new(
                    c.actor(),
                    c.time(),
                    c.action().clone(),
                    reason,
                    c.operation().clone(),
                    c.root()
                ),
                Err(MemoryV1AuditError::InvalidText)
            );
        }
        assert!(MemoryV1AuditContext::new(
            c.actor(),
            c.time(),
            c.action().clone(),
            &"a".repeat(129),
            c.operation().clone(),
            c.root()
        )
        .is_err());
    }

    #[test]
    // memory—v1
    fn validates_time_ids_and_byte_boundaries_without_inventing_uuid_rules() {
        assert_eq!(
            MemoryV1AuditTime::new(-1),
            Err(MemoryV1AuditError::InvalidTime)
        );
        assert_eq!(MemoryV1AuditTime::new(0).unwrap().unix_seconds(), 0);
        assert_eq!(
            MemoryV1AuditTime::new(i64::MAX).unwrap().unix_seconds(),
            i64::MAX
        );
        assert_eq!(MemoryV1AuditActor::new(id(0), id(0)).user(), id(0));
        for bad in ["", "a b", "é", "bad\n"] {
            assert_eq!(
                MemoryV1AuditOperation::new(bad, [0; 32]),
                Err(MemoryV1AuditError::InvalidOperationId)
            );
        }
        assert!(MemoryV1AuditOperation::new(&"a".repeat(64), [0; 32]).is_ok());
        assert!(MemoryV1AuditOperation::new(&"a".repeat(65), [0; 32]).is_err());
        assert!(MemoryV1AuditOperation::new("a-_.:/Z09", [0; 32]).is_ok());
        assert!(MemoryV1AuditAction::new(&"a".repeat(256), &"b".repeat(256)).is_ok());
        for (resource, action) in [("", "read"), ("a", "")] {
            assert_eq!(
                MemoryV1AuditAction::new(resource, action),
                Err(MemoryV1AuditError::InvalidResourceOrAction)
            );
        }
        assert!(MemoryV1AuditAction::new(&"a".repeat(257), "read").is_err());
        assert!(MemoryV1AuditAction::new("a", &"b".repeat(257)).is_err());
        assert!(MemoryV1AuditChangeSummary::new(&[]).is_err());
        assert!(MemoryV1AuditChangeSummary::new(&vec![
            0;
            MEMORY_V1_AUDIT_MAX_CHANGE_SUMMARY_BYTES
        ])
        .is_ok());
        assert!(MemoryV1AuditChangeSummary::new(&vec![
            0;
            MEMORY_V1_AUDIT_MAX_CHANGE_SUMMARY_BYTES + 1
        ])
        .is_err());
    }

    #[test]
    // memory—v1
    fn unregistered_deny_preserves_exact_request_values_and_redacts_debug() {
        let cases = [
            ("Unregistered/Resource".to_owned(), "READ!\n".to_owned()),
            ("é".repeat(128), "界".repeat(85) + "x"),
            ("a".repeat(129), "b".repeat(65)),
            ("a".repeat(256), "b".repeat(256)),
        ];
        for (resource, action) in cases {
            let values = MemoryV1AuditAction::new(&resource, &action).unwrap();
            let base = context();
            let event_context = MemoryV1AuditContext::new(
                base.actor(),
                base.time(),
                values,
                "AUTHORIZATION_NO_MATCH",
                base.operation().clone(),
                base.root(),
            )
            .unwrap();
            let event = MemoryV1AuditEvent::read(
                event_context,
                MemoryV1AuditDecisionInput::Deny(MemoryV1AuditDenySource::UnregisteredResource),
            )
            .unwrap();
            assert_eq!(event.context().action().resource(), resource);
            assert_eq!(event.context().action().action(), action);
            assert_eq!(event.persistence(), MemoryV1AuditPersistence::Required);
            assert!(!format!("{:?}", event.context().action()).contains(&resource));
        }
        assert!(MemoryV1AuditAction::new(&"é".repeat(129), "read").is_err());
        assert!(MemoryV1AuditAction::new("a", &"界".repeat(86)).is_err());
    }

    #[test]
    // memory—v1
    fn pending_cannot_be_persistent_and_deny_requires_source() {
        assert_eq!(
            MemoryV1AuditEvent::read(context(), MemoryV1AuditDecisionInput::Pending),
            Err(MemoryV1AuditError::PendingCannotBePersisted)
        );
        assert_eq!(
            MemoryV1AuditEvent::change(context(), MemoryV1AuditDecisionInput::Pending, change()),
            Err(MemoryV1AuditError::PendingCannotBePersisted)
        );
        for source in [
            MemoryV1AuditDenySource::RuleDeny,
            MemoryV1AuditDenySource::NoMatch,
            MemoryV1AuditDenySource::ScopeDenied,
            MemoryV1AuditDenySource::CardUnbound,
            MemoryV1AuditDenySource::IdentityMismatch,
            MemoryV1AuditDenySource::UnregisteredResource,
            MemoryV1AuditDenySource::SelfConfirmation,
            MemoryV1AuditDenySource::CardDisabled,
        ] {
            let event =
                MemoryV1AuditEvent::read(context(), MemoryV1AuditDecisionInput::Deny(source))
                    .unwrap();
            assert_eq!(event.decision(), MemoryV1AuditDecision::Deny(source));
            assert_eq!(event.persistence(), MemoryV1AuditPersistence::Required);
        }
    }

    #[test]
    // memory—v1
    fn read_allow_logging_and_optional_persistence_are_distinct() {
        let log = MemoryV1AuditAllowReadLog::new(context());
        assert_eq!(log.context().actor(), context().actor());
        let event = log.into_optional_event();
        assert_eq!(event.decision(), MemoryV1AuditDecision::Allow);
        assert_eq!(event.persistence(), MemoryV1AuditPersistence::Optional);
        assert!(event.change_details().is_none());
    }

    #[test]
    // memory—v1
    fn t2_requires_complete_execution_facts_for_allow_but_not_deny() {
        let complete = change();
        assert!(complete.is_complete());
        let event = MemoryV1AuditEvent::change(
            context(),
            MemoryV1AuditDecisionInput::Allow,
            complete.clone(),
        )
        .unwrap();
        assert_eq!(event.persistence(), MemoryV1AuditPersistence::Required);
        assert_eq!(event.change_details(), Some(&complete));
        let mut variants = vec![complete.clone(); 9];
        variants[0].approver = None;
        variants[1].target = None;
        variants[2].scope = None;
        variants[3].change_summary = None;
        variants[4].before = None;
        variants[5].after = None;
        variants[6].confirmations = None;
        variants[7].root_before = None;
        variants[8].root_after = None;
        for partial in variants {
            assert!(!partial.is_complete());
            assert_eq!(
                MemoryV1AuditEvent::change(
                    context(),
                    MemoryV1AuditDecisionInput::Allow,
                    partial.clone()
                ),
                Err(MemoryV1AuditError::IncompleteChange)
            );
            let denied = MemoryV1AuditEvent::change(
                context(),
                MemoryV1AuditDecisionInput::Deny(MemoryV1AuditDenySource::NoMatch),
                partial.clone(),
            )
            .unwrap();
            assert_eq!(denied.persistence(), MemoryV1AuditPersistence::Required);
            assert_eq!(denied.change_details(), Some(&partial));
        }
    }

    #[test]
    // memory—v1: An ALLOW candidate must describe the same object kind before and after.
    fn t2_allow_rejects_wrong_state_families_and_absent_after() {
        let rule_set = MemoryV1AuditObjectState::RuleSet(
            MemoryV1AuditRuleSetState::new(b"v1", [7; 32]).unwrap(),
        );
        let registry = MemoryV1AuditObjectState::Registry(MemoryV1AuditRegistryState::Active);
        let mut wrong_before = change();
        wrong_before.before = Some(rule_set.clone());
        let mut wrong_after = change();
        wrong_after.after = Some(rule_set);
        let mut absent_after = change();
        absent_after.after = Some(MemoryV1AuditObjectState::Absent);
        let mut registry_before = change();
        registry_before.before = Some(registry.clone());
        let mut registry_after = change();
        registry_after.after = Some(registry);
        let mut unmodeled_target = change();
        unmodeled_target.target = Some(MemoryV1AuditObject::Tenant(id(4)));

        for inconsistent in [
            wrong_before,
            wrong_after,
            absent_after,
            registry_before,
            registry_after,
            unmodeled_target,
        ] {
            assert!(inconsistent.is_complete());
            assert_eq!(
                MemoryV1AuditEvent::change(
                    context(),
                    MemoryV1AuditDecisionInput::Allow,
                    inconsistent.clone(),
                ),
                Err(MemoryV1AuditError::InconsistentChangeState)
            );
            let denied = MemoryV1AuditEvent::change(
                context(),
                MemoryV1AuditDecisionInput::Deny(MemoryV1AuditDenySource::NoMatch),
                inconsistent.clone(),
            )
            .unwrap();
            assert_eq!(denied.change_details(), Some(&inconsistent));
        }
    }

    #[test]
    // memory—v1: Each modeled object kind accepts matching states and an absent creation state.
    fn t2_allow_accepts_matching_state_families() {
        let cases = [
            (
                MemoryV1AuditObject::UserCard(id(3)),
                MemoryV1AuditObjectState::UserCard(MemoryV1AuditCardState::Active),
            ),
            (
                MemoryV1AuditObject::Binding(id(3)),
                MemoryV1AuditObjectState::Binding(MemoryV1AuditBindingState::Active),
            ),
            (
                MemoryV1AuditObject::Confirmation(id(3)),
                MemoryV1AuditObjectState::Confirmation(MemoryV1AuditConfirmationState::Active),
            ),
            (
                MemoryV1AuditObject::RuleSet(id(3)),
                MemoryV1AuditObjectState::RuleSet(
                    MemoryV1AuditRuleSetState::new(b"v1", [7; 32]).unwrap(),
                ),
            ),
        ];
        for (target, state) in cases {
            for before in [MemoryV1AuditObjectState::Absent, state.clone()] {
                let mut candidate = change();
                candidate.target = Some(target);
                candidate.before = Some(before);
                candidate.after = Some(state.clone());
                assert!(MemoryV1AuditEvent::change(
                    context(),
                    MemoryV1AuditDecisionInput::Allow,
                    candidate,
                )
                .is_ok());
            }
        }
    }

    #[test]
    // memory—v1: Retirement observations retain exact facts and require both statuses.
    fn rule_set_retirement_requires_explicit_lifecycle_observations() {
        let version = [0, 0xff, 0x80, 1];
        let hash = [0xa5; 32];
        let active = MemoryV1AuditRuleSetState::new_with_status(
            &version,
            hash,
            MemoryV1AuditRuleSetStatus::Active,
        )
        .unwrap();
        let retired = MemoryV1AuditRuleSetState::new_with_status(
            &version,
            hash,
            MemoryV1AuditRuleSetStatus::Retired,
        )
        .unwrap();
        let unknown = MemoryV1AuditRuleSetState::new(&version, hash).unwrap();
        assert_eq!(active.current_version(), &version);
        assert_eq!(retired.current_version(), &version);
        assert_eq!(active.content_hash(), &hash);
        assert_eq!(retired.content_hash(), &hash);
        assert_eq!(active.status(), Some(MemoryV1AuditRuleSetStatus::Active));
        assert_eq!(retired.status(), Some(MemoryV1AuditRuleSetStatus::Retired));
        assert_eq!(unknown.status(), None);
        assert_ne!(active, retired);
        assert_ne!(active, unknown);
        assert_ne!(retired, unknown);
        assert!(MemoryV1AuditRuleSetState::new_with_status(
            &[],
            hash,
            MemoryV1AuditRuleSetStatus::Active,
        )
        .is_err());
        assert!(MemoryV1AuditRuleSetState::new_with_status(
            &[1; 256],
            hash,
            MemoryV1AuditRuleSetStatus::Retired,
        )
        .is_err());

        let target = MemoryV1AuditObject::RuleSet(id(3));
        let before = MemoryV1AuditObjectState::RuleSet(active);
        let after = MemoryV1AuditObjectState::RuleSet(retired);
        let unknown = MemoryV1AuditObjectState::RuleSet(unknown);
        assert!(target.matches_state(&before));
        assert!(target.matches_state(&after));
        assert!(target.matches_rule_set_retirement(&before, &after));
        assert!(!target.matches_rule_set_retirement(&after, &before));
        assert!(!target.matches_rule_set_retirement(&unknown, &after));
        assert!(!target.matches_rule_set_retirement(&before, &unknown));
        assert!(!target.matches_rule_set_retirement(&unknown, &unknown));
        let changed_version = MemoryV1AuditObjectState::RuleSet(
            MemoryV1AuditRuleSetState::new_with_status(
                b"another-version",
                hash,
                MemoryV1AuditRuleSetStatus::Retired,
            )
            .unwrap(),
        );
        let changed_hash = MemoryV1AuditObjectState::RuleSet(
            MemoryV1AuditRuleSetState::new_with_status(
                &version,
                [0x5a; 32],
                MemoryV1AuditRuleSetStatus::Retired,
            )
            .unwrap(),
        );
        assert!(!target.matches_rule_set_retirement(&before, &changed_version));
        assert!(!target.matches_rule_set_retirement(&before, &changed_hash));
        assert!(!MemoryV1AuditObject::UserCard(id(3)).matches_rule_set_retirement(&before, &after));

        let mut retirement = change();
        retirement.target = Some(target);
        retirement.before = Some(before.clone());
        retirement.after = Some(after.clone());
        assert!(retirement.is_complete());
        assert!(retirement.is_complete_rule_set_retirement());
        let event = MemoryV1AuditEvent::change(
            context(),
            MemoryV1AuditDecisionInput::Allow,
            retirement.clone(),
        )
        .unwrap();
        assert_eq!(event.change_details(), Some(&retirement));
        assert_eq!(
            MemoryV1AuditEvent::change(context(), MemoryV1AuditDecisionInput::Pending, retirement),
            Err(MemoryV1AuditError::PendingCannotBePersisted)
        );

        for (before, after) in [
            (unknown.clone(), after.clone()),
            (before.clone(), unknown.clone()),
        ] {
            let mut partial = change();
            partial.target = Some(target);
            partial.before = Some(before);
            partial.after = Some(after);
            assert!(!partial.is_complete());
            assert!(!partial.is_complete_rule_set_retirement());
            assert_eq!(
                MemoryV1AuditEvent::change(
                    context(),
                    MemoryV1AuditDecisionInput::Allow,
                    partial.clone(),
                ),
                Err(MemoryV1AuditError::IncompleteChange)
            );
            assert!(MemoryV1AuditEvent::change(
                context(),
                MemoryV1AuditDecisionInput::Deny(MemoryV1AuditDenySource::NoMatch),
                partial,
            )
            .is_ok());
        }

        // Legacy records remain valid version/hash-only values, never retirement facts.
        let mut legacy = change();
        legacy.target = Some(target);
        legacy.before = Some(unknown.clone());
        legacy.after = Some(unknown);
        assert!(legacy.is_complete());
        assert!(!legacy.is_complete_rule_set_retirement());
        assert!(
            MemoryV1AuditEvent::change(context(), MemoryV1AuditDecisionInput::Allow, legacy)
                .is_ok()
        );
    }

    #[test]
    // memory—v1: Batch validation retains the lifecycle shape and rejects partial observations.
    fn rule_set_retirement_batch_checks_lifecycle_shape() {
        let target = MemoryV1AuditObject::RuleSet(id(3));
        let scope = MemoryV1AuditTarget::Object(MemoryV1AuditObject::Tenant(id(4)));
        let state = |status| {
            MemoryV1AuditObjectState::RuleSet(
                MemoryV1AuditRuleSetState::new_with_status(b"v1", [7; 32], status).unwrap(),
            )
        };
        let active = state(MemoryV1AuditRuleSetStatus::Active);
        let retired = state(MemoryV1AuditRuleSetStatus::Retired);
        let unknown = MemoryV1AuditObjectState::RuleSet(
            MemoryV1AuditRuleSetState::new(b"v1", [7; 32]).unwrap(),
        );
        let item = |before, after| {
            MemoryV1AuditT2BatchItem::new(
                0,
                MemoryV1AuditTarget::Object(target),
                scope,
                before,
                after,
                MemoryV1AuditConfirmationRef::RuleSetChange(id(6)),
                context().operation().clone(),
            )
        };
        let retirement = item(active.clone(), retired.clone());
        assert!(retirement.is_rule_set_retirement());
        let batch = MemoryV1AuditT2Batch::new(std::slice::from_ref(&retirement), 1).unwrap();
        assert_eq!(batch.items()[0].before(), &active);
        assert_eq!(batch.items()[0].after(), &retired);
        for partial in [
            item(unknown.clone(), retired),
            item(active, unknown.clone()),
        ] {
            assert!(!partial.is_rule_set_retirement());
            assert_eq!(
                MemoryV1AuditT2Batch::new(&[partial], 1),
                Err(MemoryV1AuditError::InvalidConfirmations)
            );
        }
        let legacy = item(unknown.clone(), unknown);
        assert!(!legacy.is_rule_set_retirement());
        assert!(MemoryV1AuditT2Batch::new(&[legacy], 1).is_ok());
    }

    #[test]
    // memory—v1
    fn rule_set_creation_and_publication_preserve_exact_states() {
        let first = MemoryV1AuditRuleSetState::new(&[0, 0xff], [7; 32]).unwrap();
        let second = MemoryV1AuditRuleSetState::new(&[0, 0xfe], [8; 32]).unwrap();
        assert_eq!(first.current_version(), &[0, 0xff]);
        assert_eq!(first.content_hash(), &[7; 32]);
        assert!(MemoryV1AuditRuleSetState::new(&[], [0; 32]).is_err());
        assert!(MemoryV1AuditRuleSetState::new(&[1; 255], [0; 32]).is_ok());
        assert!(MemoryV1AuditRuleSetState::new(&[1; 256], [0; 32]).is_err());

        let mut creation = change();
        creation.target = Some(MemoryV1AuditObject::RuleSet(id(3)));
        creation.before = Some(MemoryV1AuditObjectState::Absent);
        creation.after = Some(MemoryV1AuditObjectState::RuleSet(first.clone()));
        let event =
            MemoryV1AuditEvent::change(context(), MemoryV1AuditDecisionInput::Allow, creation)
                .unwrap();
        let creation = event.change_details().unwrap();
        assert_eq!(creation.before(), Some(&MemoryV1AuditObjectState::Absent));
        assert_eq!(
            creation.after(),
            Some(&MemoryV1AuditObjectState::RuleSet(first.clone()))
        );
        assert_eq!(event.persistence(), MemoryV1AuditPersistence::Required);

        let mut publication = change();
        publication.target = Some(MemoryV1AuditObject::RuleSet(id(3)));
        publication.before = Some(MemoryV1AuditObjectState::RuleSet(first));
        publication.after = Some(MemoryV1AuditObjectState::RuleSet(second.clone()));
        let event =
            MemoryV1AuditEvent::change(context(), MemoryV1AuditDecisionInput::Allow, publication)
                .unwrap();
        assert_ne!(
            event.change_details().unwrap().before(),
            event.change_details().unwrap().after()
        );
        assert_eq!(
            event.change_details().unwrap().after(),
            Some(&MemoryV1AuditObjectState::RuleSet(second))
        );
        assert!(!format!("{:?}", event.change_details().unwrap().after()).contains("255"));
    }

    #[test]
    // memory—v1
    fn overlay_source_and_confirmation_limits_are_explicit() {
        let special = MemoryV1AuditOverlayOnly::new(id(1), id(2), id(3));
        let mut c = change();
        c.source = MemoryV1AuditSource::OverlayOnlyCreation(special);
        let event = MemoryV1AuditEvent::change(
            context(),
            MemoryV1AuditDecisionInput::Deny(MemoryV1AuditDenySource::OverlayOnlyCreation),
            c,
        )
        .unwrap();
        match event.change_details().unwrap().source() {
            MemoryV1AuditSource::OverlayOnlyCreation(details) => {
                assert_eq!(details.creator(), id(1));
                assert_eq!(details.beneficiary(), id(2));
                assert_eq!(details.rule_set(), id(3));
            }
            MemoryV1AuditSource::Ordinary => panic!("missing marker"),
        }
        assert!(MemoryV1AuditConfirmations::references(&[]).is_err());
        let item = MemoryV1AuditConfirmationRef::Binding(id(1));
        assert!(MemoryV1AuditConfirmations::references(&vec![
            item;
            MEMORY_V1_AUDIT_MAX_CONFIRMATIONS
        ])
        .is_ok());
        assert!(MemoryV1AuditConfirmations::references(&vec![
            item;
            MEMORY_V1_AUDIT_MAX_CONFIRMATIONS + 1
        ])
        .is_err());
        let references: Vec<_> = (0..128)
            .map(|n| MemoryV1AuditConfirmationRef::Binding(id(n)))
            .collect();
        let mut batch = change();
        batch.confirmations = Some(MemoryV1AuditConfirmations::references(&references).unwrap());
        let batch_event =
            MemoryV1AuditEvent::change(context(), MemoryV1AuditDecisionInput::Allow, batch)
                .unwrap();
        assert_eq!(
            batch_event
                .change_details()
                .unwrap()
                .confirmations()
                .unwrap()
                .as_references(),
            Some(references.as_slice())
        );
        assert!(MemoryV1AuditConfirmations::references(&vec![item; 129]).is_err());
        let na = MemoryV1AuditConfirmations::not_applicable();
        assert!(na.is_not_applicable());
        assert!(na.as_references().is_none());
        assert_eq!(
            MemoryV1AuditEvent::read(
                context(),
                MemoryV1AuditDecisionInput::Deny(MemoryV1AuditDenySource::OverlayOnlyCreation)
            ),
            Err(MemoryV1AuditError::MissingOverlaySource)
        );
        assert_eq!(
            MemoryV1AuditEvent::change(
                context(),
                MemoryV1AuditDecisionInput::Deny(MemoryV1AuditDenySource::OverlayOnlyCreation),
                change()
            ),
            Err(MemoryV1AuditError::MissingOverlaySource)
        );
    }

    #[test]
    // memory—v1: Both successful and denied special creations preserve supplied references.
    fn overlay_creation_preserves_source_for_allow_and_denial_reasons() {
        let mut binding_context = context();
        binding_context.action = MemoryV1AuditAction::new("binding", "create").unwrap();
        let details = MemoryV1AuditOverlayOnly::new(id(1), id(7), id(8));
        let mut creation = change();
        creation.target = Some(MemoryV1AuditObject::Binding(id(3)));
        creation.before = Some(MemoryV1AuditObjectState::Absent);
        creation.after = Some(MemoryV1AuditObjectState::Binding(
            MemoryV1AuditBindingState::Active,
        ));
        creation.source = MemoryV1AuditSource::OverlayOnlyCreation(details);

        for decision in [
            MemoryV1AuditDecisionInput::Allow,
            MemoryV1AuditDecisionInput::Deny(MemoryV1AuditDenySource::NoMatch),
            MemoryV1AuditDecisionInput::Deny(MemoryV1AuditDenySource::SelfConfirmation),
        ] {
            let mut facts = creation.clone();
            if decision != MemoryV1AuditDecisionInput::Allow {
                facts.after = None;
                facts.root_after = None;
            }
            let event =
                MemoryV1AuditEvent::change(binding_context.clone(), decision, facts).unwrap();
            assert_eq!(event.persistence(), MemoryV1AuditPersistence::Required);
            assert_eq!(event.context().actor().user(), id(1));
            match event.change_details().unwrap().source() {
                MemoryV1AuditSource::OverlayOnlyCreation(source) => {
                    assert_eq!(source.creator(), id(1));
                    assert_eq!(source.beneficiary(), id(7));
                    assert_eq!(source.rule_set(), id(8));
                }
                MemoryV1AuditSource::Ordinary => panic!("missing special source"),
            }
            match decision {
                MemoryV1AuditDecisionInput::Allow => {
                    assert_eq!(event.decision(), MemoryV1AuditDecision::Allow);
                }
                MemoryV1AuditDecisionInput::Deny(reason) => {
                    assert_eq!(event.decision(), MemoryV1AuditDecision::Deny(reason));
                    assert!(event.change_details().unwrap().after().is_none());
                }
                MemoryV1AuditDecisionInput::Pending => unreachable!(),
            }
        }
    }

    #[test]
    // memory—v1: Generic creation facts do not distinguish normal from OVERLAY-only creation.
    fn ordinary_creation_source_is_caller_supplied_not_inferred() {
        let mut binding_context = context();
        binding_context.action = MemoryV1AuditAction::new("binding", "create").unwrap();
        let mut creation = change();
        creation.target = Some(MemoryV1AuditObject::Binding(id(3)));
        creation.before = Some(MemoryV1AuditObjectState::Absent);
        creation.after = Some(MemoryV1AuditObjectState::Binding(
            MemoryV1AuditBindingState::Active,
        ));
        for decision in [
            MemoryV1AuditDecisionInput::Allow,
            MemoryV1AuditDecisionInput::Deny(MemoryV1AuditDenySource::NoMatch),
        ] {
            let event =
                MemoryV1AuditEvent::change(binding_context.clone(), decision, creation.clone())
                    .unwrap();
            assert_eq!(event.persistence(), MemoryV1AuditPersistence::Required);
            assert_eq!(
                event.change_details().unwrap().source(),
                MemoryV1AuditSource::Ordinary
            );
            assert_eq!(event.context().action().resource(), "binding");
            assert_eq!(event.context().action().action(), "create");
        }
    }

    #[test]
    // memory—v1: Batch correlation preserves item order and rejects malformed input.
    fn confirmation_batch_is_ordered_bounded_and_operation_correlated() {
        let operation = MemoryV1AuditOperation::new("batch-operation", [8; 32]).unwrap();
        let items = [
            MemoryV1AuditConfirmationBatchItem::new(
                0,
                MemoryV1AuditConfirmationRef::Binding(id(1)),
            ),
            MemoryV1AuditConfirmationBatchItem::new(
                1,
                MemoryV1AuditConfirmationRef::RuleSetChange(id(2)),
            ),
        ];
        let confirmations =
            MemoryV1AuditConfirmations::batch(operation.clone(), &items, 8).unwrap();
        let batch = confirmations.as_batch().unwrap();
        assert_eq!(batch.operation(), &operation);
        assert_eq!(batch.items(), &items);
        assert_eq!(batch.items()[0].sequence(), 0);
        assert_eq!(batch.items()[1].confirmation().confirmation_id(), id(2));
        assert!(confirmations.as_references().is_none());

        assert_eq!(
            MemoryV1AuditConfirmations::batch(operation.clone(), &[], 8),
            Err(MemoryV1AuditError::InvalidConfirmations)
        );
        assert_eq!(
            MemoryV1AuditConfirmations::batch(operation.clone(), &items, 0),
            Err(MemoryV1AuditError::InvalidConfirmations)
        );
        assert_eq!(
            MemoryV1AuditConfirmations::batch(
                operation.clone(),
                &items,
                MEMORY_V1_AUDIT_MAX_CONFIRMATIONS + 1
            ),
            Err(MemoryV1AuditError::InvalidConfirmations)
        );

        let repeated_sequence = [
            MemoryV1AuditConfirmationBatchItem::new(
                0,
                MemoryV1AuditConfirmationRef::Binding(id(1)),
            ),
            MemoryV1AuditConfirmationBatchItem::new(
                0,
                MemoryV1AuditConfirmationRef::RuleSetChange(id(2)),
            ),
        ];
        assert_eq!(
            MemoryV1AuditConfirmations::batch(operation.clone(), &repeated_sequence, 8),
            Err(MemoryV1AuditError::InvalidConfirmations)
        );

        let repeated_id = [
            MemoryV1AuditConfirmationBatchItem::new(
                0,
                MemoryV1AuditConfirmationRef::Binding(id(1)),
            ),
            MemoryV1AuditConfirmationBatchItem::new(
                1,
                MemoryV1AuditConfirmationRef::RuleSetChange(id(1)),
            ),
        ];
        assert_eq!(
            MemoryV1AuditConfirmations::batch(operation.clone(), &repeated_id, 8),
            Err(MemoryV1AuditError::InvalidConfirmations)
        );

        let too_many: Vec<_> = (0..9)
            .map(|sequence| {
                MemoryV1AuditConfirmationBatchItem::new(
                    sequence,
                    MemoryV1AuditConfirmationRef::Binding(id(sequence as u8)),
                )
            })
            .collect();
        assert_eq!(
            MemoryV1AuditConfirmations::batch(operation, &too_many, 8),
            Err(MemoryV1AuditError::InvalidConfirmations)
        );
    }

    #[test]
    // memory—v1: A batch attached to an event must share the common operation value.
    fn confirmation_batch_must_match_event_operation() {
        let matching = MemoryV1AuditOperation::new("batch-operation", [8; 32]).unwrap();
        let different = MemoryV1AuditOperation::new("other-operation", [9; 32]).unwrap();
        let items = [MemoryV1AuditConfirmationBatchItem::new(
            0,
            MemoryV1AuditConfirmationRef::Binding(id(1)),
        )];
        let matching_confirmations =
            MemoryV1AuditConfirmations::batch(matching.clone(), &items, 8).unwrap();
        let different_confirmations =
            MemoryV1AuditConfirmations::batch(different, &items, 8).unwrap();

        let mut matching_change = change();
        matching_change.confirmations = Some(matching_confirmations.clone());
        let event = MemoryV1AuditEvent::change(
            context_with_operation(matching),
            MemoryV1AuditDecisionInput::Allow,
            matching_change,
        )
        .unwrap();
        assert_eq!(
            event
                .change_details()
                .unwrap()
                .confirmations()
                .unwrap()
                .as_batch()
                .unwrap(),
            matching_confirmations.as_batch().unwrap()
        );

        let mut different_change = change();
        different_change.confirmations = Some(different_confirmations);
        assert_eq!(
            MemoryV1AuditEvent::change(
                context(),
                MemoryV1AuditDecisionInput::Allow,
                different_change,
            ),
            Err(MemoryV1AuditError::InvalidConfirmations)
        );
    }

    #[test]
    // memory—v1: Registry resources are bounded names and match registry state families.
    fn registry_target_matches_registry_states_without_uuid_semantics() {
        let registry = "binding".parse::<MemoryV1AuditRegistryTarget>().unwrap();
        assert_eq!(registry.as_str(), "binding");
        assert_eq!(registry.resource().as_bytes(), b"binding");
        assert_eq!(registry.resource().len(), 7);

        let active = MemoryV1AuditObjectState::Registry(MemoryV1AuditRegistryState::Active);
        let retired = MemoryV1AuditObjectState::Registry(MemoryV1AuditRegistryState::Retired);
        let absent = MemoryV1AuditObjectState::Absent;
        let binding = MemoryV1AuditObjectState::Binding(MemoryV1AuditBindingState::Active);
        assert!(registry.matches_state(&active));
        assert!(registry.matches_state(&retired));
        assert!(registry.matches_transition(&absent, &active));
        assert!(registry.matches_transition(&active, &retired));
        assert!(!registry.matches_state(&binding));
        assert!(!registry.matches_transition(&active, &binding));

        for invalid in ["", "Binding", "binding:uuid", "1binding", "binding.uuid"] {
            assert_eq!(
                MemoryV1AuditRegistryResource::new(invalid),
                Err(MemoryV1AuditError::InvalidResourceOrAction)
            );
        }
        assert!(MemoryV1AuditRegistryResource::new(&"a".repeat(128)).is_ok());
        assert!(MemoryV1AuditRegistryResource::new(&"a".repeat(129)).is_err());
    }

    #[test]
    // memory—v1: T2 batches retain two distinct target/state pairs and every field.
    fn t2_batch_retains_two_targets_and_rejects_operation_mismatch() {
        let operation = MemoryV1AuditOperation::new("t2-batch", [0x11; 32]).unwrap();
        let other_operation = MemoryV1AuditOperation::new("other-t2", [0x22; 32]).unwrap();
        let registry = MemoryV1AuditTarget::Registry(
            "binding".parse::<MemoryV1AuditRegistryTarget>().unwrap(),
        );
        let binding = MemoryV1AuditTarget::Object(MemoryV1AuditObject::Binding(id(7)));
        let scope = MemoryV1AuditTarget::Object(MemoryV1AuditObject::Tenant(id(8)));
        let registry_before =
            MemoryV1AuditObjectState::Registry(MemoryV1AuditRegistryState::Active);
        let registry_after =
            MemoryV1AuditObjectState::Registry(MemoryV1AuditRegistryState::RetireRequested);
        let binding_after = MemoryV1AuditObjectState::Binding(MemoryV1AuditBindingState::Active);
        let items = [
            MemoryV1AuditT2BatchItem::new(
                0,
                registry,
                scope,
                registry_before.clone(),
                registry_after.clone(),
                MemoryV1AuditConfirmationRef::Binding(id(9)),
                operation.clone(),
            ),
            MemoryV1AuditT2BatchItem::new(
                1,
                binding,
                scope,
                MemoryV1AuditObjectState::Absent,
                binding_after.clone(),
                MemoryV1AuditConfirmationRef::RuleSetChange(id(10)),
                operation.clone(),
            ),
        ];
        let batch = MemoryV1AuditT2Batch::new(&items, 2).unwrap();
        assert_eq!(batch.len(), 2);
        assert!(!batch.is_empty());
        assert_eq!(batch.operation(), &operation);
        assert_eq!(batch.items(), &items);
        assert_eq!(batch.items()[0].target(), registry);
        assert_eq!(batch.items()[0].before(), &registry_before);
        assert_eq!(batch.items()[0].after(), &registry_after);
        assert_eq!(batch.items()[1].target(), binding);
        assert_eq!(batch.items()[1].after(), &binding_after);
        assert_eq!(
            batch.items()[1].confirmation(),
            MemoryV1AuditConfirmationRef::RuleSetChange(id(10))
        );

        let mut mismatched = items.clone();
        mismatched[1] = MemoryV1AuditT2BatchItem::new(
            1,
            binding,
            scope,
            MemoryV1AuditObjectState::Absent,
            binding_after,
            MemoryV1AuditConfirmationRef::RuleSetChange(id(10)),
            other_operation,
        );
        assert_eq!(
            MemoryV1AuditT2Batch::new(&mismatched, 2),
            Err(MemoryV1AuditError::InvalidConfirmations)
        );

        let duplicate_target = [
            items[0].clone(),
            MemoryV1AuditT2BatchItem::new(
                1,
                registry,
                scope,
                registry_before,
                registry_after,
                MemoryV1AuditConfirmationRef::RuleSetChange(id(10)),
                operation.clone(),
            ),
        ];
        assert_eq!(
            MemoryV1AuditT2Batch::new(&duplicate_target, 2),
            Err(MemoryV1AuditError::InvalidConfirmations)
        );
        assert_eq!(
            MemoryV1AuditT2Batch::new_with_source(
                &items,
                2,
                MemoryV1AuditSource::OverlayOnlyCreation(MemoryV1AuditOverlayOnly::new(
                    id(1),
                    id(2),
                    id(3),
                )),
            ),
            Err(MemoryV1AuditError::InvalidConfirmations)
        );
    }

    #[test]
    // memory—v1: Fingerprint conversion is strict and preserves exact bytes.
    fn fingerprint_hex_roundtrip_is_lowercase_and_strict() {
        let fingerprint = [
            0x00, 0x01, 0x0a, 0xab, 0xff, 0x42, 0x80, 0x7f, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xf0, 0x10, 0x20, 0x30, 0x40, 0x50,
            0x60, 0x70, 0x80, 0x90,
        ];
        let hex = memory_v1_audit_fingerprint_to_hex(&fingerprint);
        assert_eq!(hex.len(), MEMORY_V1_AUDIT_FINGERPRINT_HEX_BYTES);
        assert_eq!(hex, hex.to_ascii_lowercase());
        assert_eq!(memory_v1_audit_fingerprint_from_hex(&hex), Ok(fingerprint));

        let operation = MemoryV1AuditOperation::from_hex("hex-operation", &hex).unwrap();
        assert_eq!(operation.fingerprint(), &fingerprint);
        assert_eq!(operation.fingerprint_hex(), hex);
        assert_eq!(
            MemoryV1AuditOperation::fingerprint_from_hex(&hex),
            Ok(fingerprint)
        );
        for invalid in [
            "",
            "0",
            &"0".repeat(63),
            &"0".repeat(65),
            &"A".repeat(64),
            &format!("{}g", "0".repeat(63)),
        ] {
            assert_eq!(
                memory_v1_audit_fingerprint_from_hex(invalid),
                Err(MemoryV1AuditError::InvalidText)
            );
        }
    }
    #[test]
    // memory—v1: Complete registry and batch candidates bind to common context.
    fn complete_t2_candidates_retain_common_facts_and_reject_pending_or_overlay_batch() {
        let operation = MemoryV1AuditOperation::new("complete-t2", [0x31; 32]).unwrap();
        let context = context_with_operation(operation.clone());
        let summary = MemoryV1AuditChangeSummary::new(b"registry transition").unwrap();
        let target = "binding".parse::<MemoryV1AuditRegistryTarget>().unwrap();
        let scope = MemoryV1AuditTarget::Object(MemoryV1AuditObject::Tenant(id(4)));
        let registry = MemoryV1AuditT2Registry::new(
            operation.clone(),
            target,
            scope,
            MemoryV1AuditObjectState::Registry(MemoryV1AuditRegistryState::Active),
            MemoryV1AuditObjectState::Registry(MemoryV1AuditRegistryState::RetireRequested),
            MemoryV1AuditConfirmationRef::Binding(id(5)),
        )
        .unwrap();
        let candidate = MemoryV1AuditT2EventCandidate::registry(
            context.clone(),
            MemoryV1AuditDecisionInput::Allow,
            id(6),
            summary.clone(),
            root(7),
            root(8),
            MemoryV1AuditSource::Ordinary,
            registry.clone(),
        )
        .unwrap();
        assert_eq!(candidate.context(), &context);
        assert_eq!(candidate.operation(), &operation);
        assert_eq!(candidate.decision(), MemoryV1AuditDecision::Allow);
        assert_eq!(candidate.approver(), id(6));
        assert_eq!(candidate.change_summary(), &summary);
        assert_eq!(candidate.root_before(), root(7));
        assert_eq!(candidate.root_after(), root(8));
        assert_eq!(candidate.source(), MemoryV1AuditSource::Ordinary);
        assert_eq!(candidate.registry_payload(), Some(&registry));
        assert!(candidate.batch_payload().is_none());

        let item = MemoryV1AuditT2BatchItem::new(
            0,
            MemoryV1AuditTarget::Registry(target),
            scope,
            MemoryV1AuditObjectState::Absent,
            MemoryV1AuditObjectState::Registry(MemoryV1AuditRegistryState::Active),
            MemoryV1AuditConfirmationRef::RuleSetChange(id(9)),
            operation.clone(),
        );
        let batch = MemoryV1AuditT2Batch::new(&[item], 1).unwrap();
        let batch_candidate = MemoryV1AuditT2EventCandidate::batch(
            context.clone(),
            MemoryV1AuditDecisionInput::Deny(MemoryV1AuditDenySource::NoMatch),
            id(6),
            summary.clone(),
            root(7),
            root(8),
            MemoryV1AuditSource::Ordinary,
            batch.clone(),
        )
        .unwrap();
        assert_eq!(batch_candidate.batch_payload(), Some(&batch));
        assert_eq!(batch_candidate.registry_payload(), None);
        assert_eq!(
            batch_candidate.decision(),
            MemoryV1AuditDecision::Deny(MemoryV1AuditDenySource::NoMatch)
        );

        assert_eq!(
            MemoryV1AuditT2EventCandidate::registry(
                context.clone(),
                MemoryV1AuditDecisionInput::Pending,
                id(6),
                summary.clone(),
                root(7),
                root(8),
                MemoryV1AuditSource::Ordinary,
                registry.clone(),
            ),
            Err(MemoryV1AuditError::PendingCannotBePersisted)
        );
        let other_operation = MemoryV1AuditOperation::new("other-complete-t2", [0x32; 32]).unwrap();
        let mismatched_registry = MemoryV1AuditT2Registry::new(
            other_operation,
            target,
            scope,
            MemoryV1AuditObjectState::Registry(MemoryV1AuditRegistryState::Active),
            MemoryV1AuditObjectState::Registry(MemoryV1AuditRegistryState::Retired),
            MemoryV1AuditConfirmationRef::Binding(id(10)),
        )
        .unwrap();
        assert_eq!(
            MemoryV1AuditT2EventCandidate::registry(
                context.clone(),
                MemoryV1AuditDecisionInput::Allow,
                id(6),
                summary.clone(),
                root(7),
                root(8),
                MemoryV1AuditSource::Ordinary,
                mismatched_registry,
            ),
            Err(MemoryV1AuditError::InvalidConfirmations)
        );
        assert_eq!(
            MemoryV1AuditT2EventCandidate::batch(
                context,
                MemoryV1AuditDecisionInput::Allow,
                id(6),
                summary,
                root(7),
                root(8),
                MemoryV1AuditSource::OverlayOnlyCreation(MemoryV1AuditOverlayOnly::new(
                    id(1),
                    id(2),
                    id(3),
                )),
                batch,
            ),
            Err(MemoryV1AuditError::InvalidConfirmations)
        );
    }

    #[test]
    // memory—v1: Legacy change() remains compatible but refuses overlay plus old batch facts.
    fn legacy_change_rejects_overlay_only_with_confirmation_batch() {
        let operation = context().operation().clone();
        let items = [MemoryV1AuditConfirmationBatchItem::new(
            0,
            MemoryV1AuditConfirmationRef::Binding(id(11)),
        )];
        let confirmations = MemoryV1AuditConfirmations::batch(operation, &items, 1).unwrap();
        let mut facts = change();
        facts.confirmations = Some(confirmations);
        facts.source = MemoryV1AuditSource::OverlayOnlyCreation(MemoryV1AuditOverlayOnly::new(
            id(1),
            id(2),
            id(3),
        ));
        assert_eq!(
            MemoryV1AuditEvent::change(
                context(),
                MemoryV1AuditDecisionInput::Deny(MemoryV1AuditDenySource::NoMatch),
                facts,
            ),
            Err(MemoryV1AuditError::InvalidConfirmations)
        );
    }
    #[test]
    // memory—v1
    fn debug_redacts_values_and_event_is_unchanged_by_accessors() {
        let event =
            MemoryV1AuditEvent::change(context(), MemoryV1AuditDecisionInput::Allow, change())
                .unwrap();
        let copy = event.clone();
        let output = format!(
            "{event:?} {:?} {:?} {:?} {:?}",
            event.context().operation(),
            event.context().actor(),
            event.change_details().unwrap().target(),
            event.change_details().unwrap().confirmations()
        );
        assert!(!output.contains("sensitive-operation"));
        assert!(!output.contains("[1, 1, 1"));
        assert_eq!(event, copy);
    }

    #[test]
    // memory—v1: A successful single T2 candidate retains every B-4 field and round-trips.
    fn single_success_t2_candidate_retains_b4_fields_and_round_trips() {
        let event =
            MemoryV1AuditEvent::change(context(), MemoryV1AuditDecisionInput::Allow, change())
                .unwrap();
        let details = event.change_details().unwrap();
        let candidate = MemoryV1AuditT2SingleChangeCandidate::try_from(event.clone()).unwrap();

        assert_eq!(candidate.context(), event.context());
        assert_eq!(candidate.operation(), event.context().operation());
        assert_eq!(candidate.decision(), MemoryV1AuditDecision::Allow);
        assert_eq!(candidate.approver(), id(1));
        assert_eq!(candidate.target(), MemoryV1AuditObject::UserCard(id(3)));
        assert_eq!(candidate.scope(), MemoryV1AuditObject::Tenant(id(4)));
        assert_eq!(
            candidate.change_summary(),
            details.change_summary().unwrap()
        );
        assert_eq!(candidate.before(), details.before().unwrap());
        assert_eq!(candidate.after(), details.after().unwrap());
        assert_eq!(candidate.confirmations(), details.confirmations().unwrap());
        assert_eq!(candidate.root_before(), root(1));
        assert_eq!(candidate.root_after(), root(2));
        assert_eq!(candidate.source(), MemoryV1AuditSource::Ordinary);
        assert_eq!(candidate.change_details(), details);
        assert_eq!(candidate.clone().into_event(), event);
    }

    #[test]
    // memory—v1: Only complete ALLOW changes are eligible for the single-success wrapper.
    fn single_success_t2_candidate_rejects_deny_read_incomplete_and_mismatched_target() {
        let denied = MemoryV1AuditEvent::change(
            context(),
            MemoryV1AuditDecisionInput::Deny(MemoryV1AuditDenySource::NoMatch),
            change(),
        )
        .unwrap();
        assert_eq!(
            MemoryV1AuditT2SingleChangeCandidate::try_from(denied),
            Err(MemoryV1AuditError::WrongDecision)
        );

        let ordinary_read =
            MemoryV1AuditEvent::read(context(), MemoryV1AuditDecisionInput::Allow).unwrap();
        assert_eq!(
            MemoryV1AuditT2SingleChangeCandidate::try_from(ordinary_read),
            Err(MemoryV1AuditError::IncompleteChange)
        );

        let mut incomplete = change();
        incomplete.after = None;
        let incomplete_event = MemoryV1AuditEvent {
            context: context(),
            decision: MemoryV1AuditDecision::Allow,
            change: Some(incomplete),
        };
        assert_eq!(
            MemoryV1AuditT2SingleChangeCandidate::try_from(incomplete_event),
            Err(MemoryV1AuditError::IncompleteChange)
        );

        let mut mismatched = change();
        mismatched.target = Some(MemoryV1AuditObject::Tenant(id(4)));
        let mismatched_event = MemoryV1AuditEvent {
            context: context(),
            decision: MemoryV1AuditDecision::Allow,
            change: Some(mismatched),
        };
        assert_eq!(
            MemoryV1AuditT2SingleChangeCandidate::try_from(mismatched_event),
            Err(MemoryV1AuditError::InconsistentChangeState)
        );
    }

    #[test]
    // memory—v1: Debug output for a single candidate never exposes nested audit values.
    fn single_success_t2_candidate_debug_is_redacted() {
        let event =
            MemoryV1AuditEvent::change(context(), MemoryV1AuditDecisionInput::Allow, change())
                .unwrap();
        let candidate = MemoryV1AuditT2SingleChangeCandidate::try_from(event).unwrap();
        let debug = format!("{candidate:?}");

        assert_eq!(debug, "MemoryV1AuditT2SingleChangeCandidate([REDACTED])");
        assert!(!debug.contains("sensitive-operation"));
        assert!(!debug.contains("[1, 1, 1"));
    }

    #[test]
    // memory—v1: Overlay, batch, and explicit rule-set retirement keep their existing shape rules.
    fn single_success_t2_candidate_preserves_overlay_batch_and_retirement_semantics() {
        let overlay = MemoryV1AuditOverlayOnly::new(id(1), id(7), id(8));
        let mut overlay_change = change();
        overlay_change.target = Some(MemoryV1AuditObject::Binding(id(3)));
        overlay_change.before = Some(MemoryV1AuditObjectState::Absent);
        overlay_change.after = Some(MemoryV1AuditObjectState::Binding(
            MemoryV1AuditBindingState::Active,
        ));
        overlay_change.source = MemoryV1AuditSource::OverlayOnlyCreation(overlay);
        let overlay_event = MemoryV1AuditEvent::change(
            context(),
            MemoryV1AuditDecisionInput::Allow,
            overlay_change,
        )
        .unwrap();
        let overlay_candidate =
            MemoryV1AuditT2SingleChangeCandidate::try_from(overlay_event).unwrap();
        assert_eq!(
            overlay_candidate.source(),
            MemoryV1AuditSource::OverlayOnlyCreation(overlay)
        );

        let operation = context().operation().clone();
        let items = [MemoryV1AuditConfirmationBatchItem::new(
            0,
            MemoryV1AuditConfirmationRef::Binding(id(11)),
        )];
        let mut batch_change = change();
        batch_change.confirmations =
            Some(MemoryV1AuditConfirmations::batch(operation, &items, 1).unwrap());
        let batch_event =
            MemoryV1AuditEvent::change(context(), MemoryV1AuditDecisionInput::Allow, batch_change)
                .unwrap();
        assert_eq!(
            MemoryV1AuditT2SingleChangeCandidate::try_from(batch_event),
            Err(MemoryV1AuditError::InvalidConfirmations)
        );

        let version = [0, 0xff, 0x80, 1];
        let hash = [0xa5; 32];
        let mut retirement = change();
        retirement.target = Some(MemoryV1AuditObject::RuleSet(id(3)));
        retirement.before = Some(MemoryV1AuditObjectState::RuleSet(
            MemoryV1AuditRuleSetState::new_with_status(
                &version,
                hash,
                MemoryV1AuditRuleSetStatus::Active,
            )
            .unwrap(),
        ));
        retirement.after = Some(MemoryV1AuditObjectState::RuleSet(
            MemoryV1AuditRuleSetState::new_with_status(
                &version,
                hash,
                MemoryV1AuditRuleSetStatus::Retired,
            )
            .unwrap(),
        ));
        let retirement_event =
            MemoryV1AuditEvent::change(context(), MemoryV1AuditDecisionInput::Allow, retirement)
                .unwrap();
        let retirement_candidate =
            MemoryV1AuditT2SingleChangeCandidate::try_from(retirement_event).unwrap();
        assert!(retirement_candidate
            .change_details()
            .is_complete_rule_set_retirement());
    }
}
