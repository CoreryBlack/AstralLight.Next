//! Typed contracts for versioned hot-state authorization projections.
//!
//! This module deliberately contains only value types and deterministic validation. It
//! does not know about SQL, Redis, MQ, HTTP, or any projection worker implementation.
//! The types are suitable for the source/evidence boundary and for serializing a
//! generation-fenced incremental projection event.

use std::fmt;
use std::str::FromStr;

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

/// Validation failures shared by the phase-one contracts.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum GrantContractError {
    #[error("{field} must not be empty")]
    EmptyIdentifier { field: &'static str },

    #[error("{field} contains whitespace or a control character")]
    MalformedIdentifier { field: &'static str },

    #[error("{field} is too long")]
    IdentifierTooLong { field: &'static str },

    #[error("{field} must be positive, got {value}")]
    NonPositiveId { field: &'static str, value: i64 },

    #[error("{field} must be greater than zero")]
    InvalidRevision { field: &'static str },

    #[error("{field} must be greater than zero")]
    InvalidGeneration { field: &'static str },

    #[error("revoke fence {fence} cannot exceed generation {generation}")]
    InvalidFence { generation: u64, fence: u64 },

    #[error("{field} must not be the nil UUID")]
    NilUuid { field: &'static str },

    #[error("validity window must satisfy not_before < expires_at in UTC Unix seconds")]
    InvalidValidity { not_before: i64, expires_at: i64 },

    #[error("source kind {source_kind} is not aligned with binding layer {binding_layer}")]
    SourceLayerMismatch {
        source_kind: &'static str,
        binding_layer: &'static str,
    },

    #[error("invalid provenance: {0}")]
    InvalidProvenance(String),

    #[error("tenant scope is malformed: {0}")]
    InvalidTenantScope(String),

    #[error("dependency '{dependency_id}' occurs more than once")]
    DuplicateDependency { dependency_id: String },

    #[error("{field} must be a lowercase 64-character SHA-256 hex digest")]
    InvalidHash { field: &'static str },

    #[error("segment ordinal {actual} is invalid; expected {expected}")]
    InvalidSegmentOrder { expected: u64, actual: u64 },

    #[error(
        "segment grant count {segment_count} does not sum to manifest grant count {manifest_count}"
    )]
    GrantCountMismatch {
        segment_count: u64,
        manifest_count: u64,
    },

    #[error("grant tenant scope does not match projection tenant scope")]
    TenantScopeMismatch,

    #[error("invalid grant delta: {0}")]
    InvalidDelta(String),

    #[error("canonical serialization failed: {0}")]
    CanonicalSerialization(String),

    #[error("archive proof does not match the archive operation")]
    ArchiveIdentityMismatch,

    #[error(
        "grant identity key schema version {actual} does not match contract schema version {expected}"
    )]
    IdentitySchemaVersionMismatch { expected: u32, actual: u32 },

    #[error("{field} is required for {source_kind} grant identity keys")]
    MissingRequiredComponent {
        field: &'static str,
        source_kind: &'static str,
    },
}

/// Result alias for typed contract validation and canonicalization.
pub type GrantContractResult<T> = Result<T, GrantContractError>;

fn normalize_identifier(value: &str, field: &'static str) -> GrantContractResult<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(GrantContractError::EmptyIdentifier { field });
    }
    if normalized.len() > 512 {
        return Err(GrantContractError::IdentifierTooLong { field });
    }
    if normalized
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(GrantContractError::MalformedIdentifier { field });
    }
    Ok(normalized.to_owned())
}

fn validate_positive_id(value: i64, field: &'static str) -> GrantContractResult<()> {
    if value <= 0 {
        Err(GrantContractError::NonPositiveId { field, value })
    } else {
        Ok(())
    }
}

fn validate_generation(value: u64, field: &'static str) -> GrantContractResult<()> {
    if value == 0 {
        Err(GrantContractError::InvalidGeneration { field })
    } else {
        Ok(())
    }
}

fn validate_fence(generation: u64, fence: u64) -> GrantContractResult<()> {
    // A zero fence is the valid initial "no revoke has happened" value. A fence
    // may never outrun the source generation that produced it.
    if fence > generation {
        Err(GrantContractError::InvalidFence { generation, fence })
    } else {
        Ok(())
    }
}

fn validate_uuid(value: Uuid, field: &'static str) -> GrantContractResult<()> {
    if value.is_nil() {
        Err(GrantContractError::NilUuid { field })
    } else {
        Ok(())
    }
}

fn validate_sha256_hex(value: &str, field: &'static str) -> GrantContractResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
    {
        return Err(GrantContractError::InvalidHash { field });
    }
    Ok(())
}

fn canonical_json<T: Serialize>(value: &T) -> GrantContractResult<String> {
    serde_json::to_string(value)
        .map_err(|error| GrantContractError::CanonicalSerialization(error.to_string()))
}

fn sha256_hex(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    hex::encode(digest)
}

/// A stable, non-nil UUID identity for one logical authorization grant.
///
/// The canonical storage expression of a [`GrantId`] is its lowercase hyphenated
/// UUID text form (36 characters), exactly as produced by `Display`/`as_str` and
/// by serde. Durable SQL columns (`grant_id CHAR(36)`) must store this exact text
/// form; never an uppercased, braced, or binary re-encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GrantId(Uuid);

impl GrantId {
    /// Construct a grant identity, rejecting the nil UUID.
    pub fn new(value: Uuid) -> GrantContractResult<Self> {
        validate_uuid(value, "grant_id")?;
        Ok(Self(value))
    }

    /// Construct a random UUID identity.
    pub fn random() -> Self {
        // `new_v4` cannot produce the nil UUID in normal operation; retaining
        // the private representation keeps the cheap random constructor infallible.
        Self(Uuid::new_v4())
    }

    /// Parse a canonical UUID string.
    pub fn parse(value: &str) -> GrantContractResult<Self> {
        let uuid = Uuid::parse_str(value)
            .map_err(|_| GrantContractError::MalformedIdentifier { field: "grant_id" })?;
        Self::new(uuid)
    }

    pub fn as_uuid(self) -> Uuid {
        self.0
    }

    pub fn as_str(&self) -> String {
        self.0.to_string()
    }

    pub fn validate(&self) -> GrantContractResult<()> {
        validate_uuid(self.0, "grant_id")
    }

    /// Derive a stable grant identity from a canonical [`GrantIdentityKey`] using
    /// the fixed UUID v5 namespace and key schema version of this contract.
    ///
    /// The derived value is checked through [`GrantId::new`], so the nil UUID can
    /// never be produced, and the result keeps the lowercase hyphenated CHAR(36)
    /// canonical text form for Display/serde/storage. There is intentionally no
    /// random fallback here: production derivation must remain deterministic, and
    /// callers cannot supply a custom namespace.
    pub fn derive_deterministic(identity: &GrantIdentityKey) -> GrantContractResult<Self> {
        identity.derive_grant_id()
    }
}

impl Default for GrantId {
    fn default() -> Self {
        Self::random()
    }
}

impl fmt::Display for GrantId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for GrantId {
    type Err = GrantContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl TryFrom<Uuid> for GrantId {
    type Error = GrantContractError;

    fn try_from(value: Uuid) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl Serialize for GrantId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for GrantId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Uuid::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// Positive per-grant revision. Revisions start at one and never use zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GrantRevision(u64);

impl GrantRevision {
    pub fn new(value: u64) -> GrantContractResult<Self> {
        if value == 0 {
            return Err(GrantContractError::InvalidRevision {
                field: "grant_revision",
            });
        }
        Ok(Self(value))
    }

    pub const fn initial() -> Self {
        Self(1)
    }

    pub fn next(self) -> GrantContractResult<Self> {
        let next = self
            .0
            .checked_add(1)
            .ok_or(GrantContractError::InvalidRevision {
                field: "grant_revision",
            })?;
        Self::new(next)
    }

    pub const fn value(self) -> u64 {
        self.0
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }

    pub fn validate(self) -> GrantContractResult<()> {
        Self::new(self.0).map(|_| ())
    }
}

impl Default for GrantRevision {
    fn default() -> Self {
        Self::initial()
    }
}

impl From<GrantRevision> for u64 {
    fn from(value: GrantRevision) -> Self {
        value.0
    }
}

impl TryFrom<u64> for GrantRevision {
    type Error = GrantContractError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl Serialize for GrantRevision {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for GrantRevision {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// Logical lifecycle state of a grant in the hot projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GrantState {
    Pending,
    Active,
    Revoked,
    Removed,
    Expired,
    Archived,
}

impl GrantState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Active => "ACTIVE",
            Self::Revoked => "REVOKED",
            Self::Removed => "REMOVED",
            Self::Expired => "EXPIRED",
            Self::Archived => "ARCHIVED",
        }
    }
}

/// Source family that owns the grant mutation.
///
/// This is the closed set of grant origins. There is no execution-method source:
/// migration/backfill runs that need provenance use [`GrantSourceKind::System`]
/// plus explicit `source_id`/`operation_id` values on
/// [`GrantProvenance`], because *how* a record was produced is not an
/// authorization origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GrantSourceKind {
    RuleSet,
    Direct,
    Delegation,
    Approval,
    /// Reserved-unused provenance kind: declared for contract completeness, but
    /// with no production writer today - no source mutation emits `SYSTEM`
    /// grants and the trustgraph `grant_ledger_adapter` exposes no `SYSTEM`
    /// append path (only contract tests construct values of this kind).
    ///
    /// Future writers (e.g. migration/backfill tooling per the enum-level doc)
    /// MUST first add an explicit `SYSTEM` append function to
    /// `grant_ledger_adapter` that materializes the revision/delta pair
    /// together with its same-transaction audit correlation. Assembling
    /// `SYSTEM` payloads through any other side door is forbidden
    /// (fail-closed); [`GrantIdentityKey::system`] only pins canonical
    /// identity facts and is not an authorization path by itself.
    System,
}

impl GrantSourceKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RuleSet => "RULE_SET",
            Self::Direct => "DIRECT",
            Self::Delegation => "DELEGATION",
            Self::Approval => "APPROVAL",
            Self::System => "SYSTEM",
        }
    }
}

/// Binding precedence label of a grant within the rule-set model.
///
/// `OVERLAY` takes precedence over `BASE` inside one user-card/rule-set binding;
/// both labels exist only for `RULE_SET` contributions. Every other contribution
/// kind is bound straight onto its carrier and therefore carries `NONE`.
/// Delegation identity is expressed by `provenance.delegation_id` together with
/// the identity key's stable source-entry/binding scope - never by the layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BindingLayer {
    Base,
    Overlay,
    None,
}

impl BindingLayer {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Base => "BASE",
            Self::Overlay => "OVERLAY",
            Self::None => "NONE",
        }
    }
}

/// Canonical source-kind to binding-layer alignment.
///
/// A [`GrantSourceKind`] may only materialize through the binding layers it owns:
///
/// - `RULE_SET` contributions arrive through a shared rule set and therefore carry
///   the precedence labels `BASE` or `OVERLAY` only.
/// - `DIRECT`, `DELEGATION`, `APPROVAL`, and `SYSTEM` contributions have no
///   rule-set precedence and are always bound with layer `NONE`.
pub fn source_kind_aligns_with_binding_layer(
    source_kind: GrantSourceKind,
    binding_layer: BindingLayer,
) -> bool {
    match source_kind {
        GrantSourceKind::RuleSet => {
            matches!(binding_layer, BindingLayer::Base | BindingLayer::Overlay)
        }
        GrantSourceKind::Direct
        | GrantSourceKind::Delegation
        | GrantSourceKind::Approval
        | GrantSourceKind::System => binding_layer == BindingLayer::None,
    }
}

/// Phase-one grants are intentionally ALLOW-only. DENY remains a rule/evaluation
/// concern and cannot be smuggled into the positive grant hot-state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GrantEffect {
    Allow,
}

impl GrantEffect {
    pub const fn as_str(self) -> &'static str {
        "ALLOW"
    }

    pub fn validate(self) -> GrantContractResult<()> {
        match self {
            Self::Allow => Ok(()),
        }
    }
}

/// The physical tenant boundary carried by a user card and its grants.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantScope {
    pub tenant_id: i64,
    pub domain_id: Option<i64>,
}

impl TenantScope {
    pub fn new(tenant_id: i64, domain_id: Option<i64>) -> GrantContractResult<Self> {
        let value = Self {
            tenant_id,
            domain_id,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> GrantContractResult<()> {
        validate_positive_id(self.tenant_id, "tenant_id")?;
        if let Some(domain_id) = self.domain_id {
            validate_positive_id(domain_id, "domain_id")?;
        }
        Ok(())
    }

    pub fn canonicalized(&self) -> GrantContractResult<Self> {
        self.validate()?;
        Ok(self.clone())
    }
}

impl fmt::Display for TenantScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.domain_id {
            Some(domain_id) => write!(formatter, "{}/{}", self.tenant_id, domain_id),
            None => self.tenant_id.fmt(formatter),
        }
    }
}

impl FromStr for TenantScope {
    type Err = GrantContractError;

    /// Parse the canonical `tenant_id` or `tenant_id/domain_id` form.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parts: Vec<_> = value.trim().split('/').collect();
        if parts.is_empty() || parts.len() > 2 || parts.iter().any(|part| part.is_empty()) {
            return Err(GrantContractError::InvalidTenantScope(value.to_owned()));
        }
        let tenant_id = parts[0]
            .parse::<i64>()
            .map_err(|_| GrantContractError::InvalidTenantScope(value.to_owned()))?;
        let domain_id = if parts.len() == 2 {
            Some(
                parts[1]
                    .parse::<i64>()
                    .map_err(|_| GrantContractError::InvalidTenantScope(value.to_owned()))?,
            )
        } else {
            None
        };
        Self::new(tenant_id, domain_id)
            .map_err(|_| GrantContractError::InvalidTenantScope(value.to_owned()))
    }
}

/// Unified validity window in UTC Unix seconds.
///
/// All grant/evidence timestamps share one clock expression: UTC Unix seconds.
/// The lower bound is inclusive and the upper bound is exclusive, so a record is
/// valid exactly when `not_before <= now < expires_at`. A window in which
/// `not_before >= expires_at` is empty or inverted and fails validation instead of
/// silently matching nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidityWindow {
    pub not_before: Option<i64>,
    pub expires_at: Option<i64>,
}

/// Alias that makes the grant domain wording explicit at call sites.
pub type GrantValidity = ValidityWindow;

impl ValidityWindow {
    pub const fn perpetual() -> Self {
        Self {
            not_before: None,
            expires_at: None,
        }
    }

    pub const fn between(not_before: i64, expires_at: i64) -> Self {
        Self {
            not_before: Some(not_before),
            expires_at: Some(expires_at),
        }
    }

    pub fn validate(&self) -> GrantContractResult<()> {
        if let (Some(not_before), Some(expires_at)) = (self.not_before, self.expires_at) {
            // not_before is inclusive and expires_at is exclusive; the window must
            // therefore be strictly non-empty to be representable.
            if not_before >= expires_at {
                return Err(GrantContractError::InvalidValidity {
                    not_before,
                    expires_at,
                });
            }
        }
        Ok(())
    }

    /// Whether an instant expressed in UTC Unix seconds falls inside this window
    /// (`not_before` inclusive, `expires_at` exclusive).
    pub fn is_valid_at(&self, unix_seconds: i64) -> bool {
        self.not_before
            .map(|not_before| unix_seconds >= not_before)
            .unwrap_or(true)
            && self
                .expires_at
                .map(|expires_at| unix_seconds < expires_at)
                .unwrap_or(true)
    }
}

impl Default for ValidityWindow {
    fn default() -> Self {
        Self::perpetual()
    }
}

/// Source/evidence provenance for one canonical grant.
///
/// Together with the identity fields on [`CanonicalGrant`] and the fence fields on
/// [`GrantEvidence`], this record explicitly expresses the full provenance chain:
///
/// - `source_id`: stable identity of the owning source aggregate (for example
///   the rule set id, user-card binding id, delegation id, approval request id,
///   or backfill record id depending on `source_kind`).
/// - `source_entry`: optional stable entry inside that source (the individual rule
///   set entry, template line, or delegation clause backing this grant).
/// - `binding_id`: optional stable identity of the user-card/rule-set binding that
///   carried the contribution onto the effective-authorization path.
/// - `delegation_id`: required exactly when `source_kind == DELEGATION`, proving a
///   delegated grant traces to one durable delegation record.
/// - `operation_id` / `event_id`: the durable operation and event identities.
/// - `actor_user_id`: administrative actor, when known.
///
/// Source kind, binding layer, card/user/tenant/domain identity live on
/// [`CanonicalGrant`]; source generation and revoke fence live on [`GrantEvidence`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantProvenance {
    pub source_id: String,
    pub source_entry: Option<String>,
    pub binding_id: Option<String>,
    pub delegation_id: Option<String>,
    pub operation_id: String,
    pub event_id: Option<String>,
    pub actor_user_id: Option<i64>,
}

impl GrantProvenance {
    pub fn validate(&self) -> GrantContractResult<()> {
        normalize_identifier(&self.source_id, "provenance.source_id")?;
        if let Some(source_entry) = &self.source_entry {
            normalize_identifier(source_entry, "provenance.source_entry")?;
        }
        if let Some(binding_id) = &self.binding_id {
            normalize_identifier(binding_id, "provenance.binding_id")?;
        }
        if let Some(delegation_id) = &self.delegation_id {
            normalize_identifier(delegation_id, "provenance.delegation_id")?;
        }
        normalize_identifier(&self.operation_id, "provenance.operation_id")?;
        if let Some(event_id) = &self.event_id {
            normalize_identifier(event_id, "provenance.event_id")?;
        }
        if let Some(actor_user_id) = self.actor_user_id {
            validate_positive_id(actor_user_id, "provenance.actor_user_id")?;
        }
        Ok(())
    }

    pub fn canonicalized(&self) -> GrantContractResult<Self> {
        let value = Self {
            source_id: normalize_identifier(&self.source_id, "provenance.source_id")?,
            source_entry: self
                .source_entry
                .as_deref()
                .map(|entry| normalize_identifier(entry, "provenance.source_entry"))
                .transpose()?,
            binding_id: self
                .binding_id
                .as_deref()
                .map(|binding| normalize_identifier(binding, "provenance.binding_id"))
                .transpose()?,
            delegation_id: self
                .delegation_id
                .as_deref()
                .map(|delegation| normalize_identifier(delegation, "provenance.delegation_id"))
                .transpose()?,
            operation_id: normalize_identifier(&self.operation_id, "provenance.operation_id")?,
            event_id: self
                .event_id
                .as_deref()
                .map(|event_id| normalize_identifier(event_id, "provenance.event_id"))
                .transpose()?,
            actor_user_id: self.actor_user_id,
        };
        value.validate()?;
        Ok(value)
    }
}

/// Fixed wire/schema version of the grant identity key contract.
///
/// This value is part of the canonical identity input and is not configurable at
/// runtime. Bumping it, or replacing the namespace value below, is a breaking
/// contract change by design: previously derived [`GrantId`] values become
/// incomparable and no silent compatibility mapping exists.
pub const GRANT_IDENTITY_KEY_SCHEMA_VERSION: u32 = 1;

/// Opaque, fixed UUID v5 namespace for deterministic grant identity derivation,
/// expressed as its exact u128 value so construction is const-time safe.
///
/// The ASCII spelling of this constant is
/// `a3d13f7e-8c41-4b2a-9e15-6f70d4a51b32`; the pinned-namespace test in this
/// module fails if the text form ever drifts. Callers cannot pass a custom
/// namespace anywhere in the derivation API.
const GRANT_IDENTITY_NAMESPACE_VALUE: u128 = 0xa3d1_3f7e_8c41_4b2a_9e15_6f70_d4a5_1b32;

/// The non-configurable namespace used by [`GrantIdentityKey::derive_grant_id`].
pub fn grant_identity_namespace() -> Uuid {
    Uuid::from_u128(GRANT_IDENTITY_NAMESPACE_VALUE)
}

/// Shared injective encoder for canonical identity text: a unit separator
/// followed by an explicit UTF-8 byte-length prefix and the component value.
/// The UTF-8 byte-length prefix keeps component boundaries unambiguous
/// regardless of content. Both grant identity and contribution delta event
/// identity reuse this one encoder so their encodings never drift apart.
fn push_identity_component(out: &mut String, component: &str) {
    out.push(GRANT_IDENTITY_UNIT_SEPARATOR);
    out.push_str(&component.len().to_string());
    out.push(':');
    out.push_str(component);
}

/// Field separator used inside the canonical identity encoding.
///
/// Free-form components reject all control characters (including this byte) via
/// `normalize_identifier`, and every free-form component additionally carries an
/// explicit byte-length prefix, so component boundaries are always unambiguous:
/// field positions are fixed and neither the separator nor length-prefix syntax
/// can occur inside a validated value.
const GRANT_IDENTITY_UNIT_SEPARATOR: char = '\u{1F}';

/// Fixed header prefix of every canonical identity encoding.
const GRANT_IDENTITY_KEY_HEADER: &str = "ASTRAL_GRANT_IDENTITY";

/// Canonical, serde-checkable identity key of one logical authorization grant.
///
/// # Identity granularity
///
/// One identity key names exactly one *independently mutable canonical grant
/// contribution*: the smallest unit that can be added, updated, revoked, or
/// removed on its own without touching sibling contributions of the same
/// source aggregate. The authorization ledger admits at most one ACTIVE record
/// per derived [`GrantId`] (a second ADD fails closed with
/// `DuplicateActiveGrant`), so two sibling contributions under one
/// card/source/binding MUST derive different identities even when they differ
/// only in mutable attributes.
///
/// The key therefore carries only stable identity dimensions: schema version,
/// source kind, binding layer, tenant scope, aggregate type/id, the mandatory
/// stable `source_entry`, and the mandatory binding / card scope identity
/// (`binding_key`). Mutable or event-owned attributes - resource, action,
/// priority, validity window, actor, operation/event ids, and revisions - are
/// deliberately excluded so updating them reuses the same [`GrantId`] instead
/// of re-keying the grant.
///
/// # Mandatory source entry per source kind
///
/// `source_entry` identifies the single contribution inside the source
/// aggregate and MUST be a stable, immutable identifier supplied by the owning
/// adapter:
///
/// | source_kind | expected `source_entry` |
/// |-------------|-------------------------|
/// | `RULE_SET` | stable id of the individual rule set entry / template line |
/// | `DIRECT` | stable id of the individual permission entry carried by the user card (for example the backing direct permission_rule id) |
/// | `DELEGATION` | stable id of the individual delegation clause/contribution |
/// | `APPROVAL` | stable id of the individual approved line/contribution inside the approval request |
/// | `SYSTEM` | stable administrative entry id (for example a backfill record id) |
///
/// A source family that cannot supply such an entry cannot participate at all:
/// every constructor validates `source_entry` and `binding_key` as non-empty
/// normalized identifiers and rejects anything else fail-closed instead of
/// letting siblings collapse onto one shared [`GrantId`]. There is no optional
/// slot, random fallback, array-index, or payload-derived identity anywhere in
/// this contract.
///
/// # Card/user/binding scope
///
/// `binding_key` carries the card/user-card/binding scope that materialized the
/// contribution onto the effective-authorization path: for `DIRECT` it equals
/// the card binding id, for `DELEGATION` it is the delegation chain identity
/// (mirroring the delegated provenance invariant on [`CanonicalGrant`] which
/// requires `delegation_id`), for `RULE_SET` it is the user-card/rule-set
/// binding id, and for `APPROVAL`/`SYSTEM` it is the explicit carrier binding
/// scope recorded with the source record. It is mandatory for every kind, so
/// the same stable source entry under a different tenant, domain, card,
/// binding, or binding layer always derives a different [`GrantId`]; crossing
/// tenants or domains is never identity-preserving.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantIdentityKey {
    pub schema_version: u32,
    pub source_kind: GrantSourceKind,
    pub binding_layer: BindingLayer,
    pub tenant: TenantScope,
    pub aggregate_type: String,
    pub aggregate_id: String,
    /// Stable identifier of the contribution inside the source aggregate.
    ///
    /// Mandatory for every source kind: distinct sibling contributions must not
    /// share one [`GrantId`] because the ledger keeps one ACTIVE record per
    /// identity and rejects duplicates fail-closed.
    pub source_entry: String,
    /// Mandatory card/user-card/binding scope that carried this contribution.
    pub binding_key: String,
}

impl GrantIdentityKey {
    /// Construct and canonicalize an identity key under the current contract
    /// schema version.
    ///
    /// Both `source_entry` and `binding_key` are mandatory for every source
    /// kind; empty, whitespace-only, separator-carrying, or otherwise malformed
    /// values fail closed. Prefer the per-source-kind constructors below
    /// ([`GrantIdentityKey::rule_set`], [`GrantIdentityKey::direct`],
    /// [`GrantIdentityKey::delegation`], [`GrantIdentityKey::approval`],
    /// [`GrantIdentityKey::system`]) which pin the aligned layer for their kind;
    /// `new` keeps only the shared fail-closed checks and is the entry point for
    /// callers that already hold a validated (kind, layer) pair.
    pub fn new(
        tenant: TenantScope,
        source_kind: GrantSourceKind,
        binding_layer: BindingLayer,
        aggregate_type: &str,
        aggregate_id: &str,
        source_entry: &str,
        binding_key: &str,
    ) -> GrantContractResult<Self> {
        let value = Self {
            schema_version: GRANT_IDENTITY_KEY_SCHEMA_VERSION,
            source_kind,
            binding_layer,
            tenant,
            aggregate_type: aggregate_type.to_owned(),
            aggregate_id: aggregate_id.to_owned(),
            source_entry: source_entry.to_owned(),
            binding_key: binding_key.to_owned(),
        };
        value.canonicalized()
    }

    /// RuleSet contribution: BASE/OVERLAY precedence label plus the mandatory
    /// rule set id, stable per-contribution entry inside the rule set (the
    /// individual entry or template line), and user-card binding scope.
    pub fn rule_set(
        tenant: TenantScope,
        binding_layer: BindingLayer,
        rule_set_id: &str,
        source_entry: &str,
        binding_key: &str,
    ) -> GrantContractResult<Self> {
        Self::new(
            tenant,
            GrantSourceKind::RuleSet,
            binding_layer,
            "RULE_SET",
            rule_set_id,
            source_entry,
            binding_key,
        )
    }

    /// Direct contribution bound straight onto one user card; the layer is
    /// always [`BindingLayer::None`].
    ///
    /// `card_binding_id` identifies both the source aggregate (`USER_CARD`) and
    /// the binding scope; `source_entry` must be the stable id of the single
    /// permission entry contributed by that card (for example the backing direct
    /// permission_rule id), so sibling entries of one card never share a
    /// derived grant id.
    pub fn direct(
        tenant: TenantScope,
        card_binding_id: &str,
        source_entry: &str,
    ) -> GrantContractResult<Self> {
        Self::new(
            tenant,
            GrantSourceKind::Direct,
            BindingLayer::None,
            "USER_CARD",
            card_binding_id,
            source_entry,
            card_binding_id,
        )
    }

    /// Delegation contribution; the layer is always [`BindingLayer::None`].
    ///
    /// The delegation chain identity is mandatory both as the source aggregate
    /// and as the binding scope, while the durable delegation proof lives on
    /// `GrantProvenance.delegation_id`. `source_entry` must be the stable id of
    /// the individual delegation clause/contribution so separate clauses never
    /// collide onto one identity.
    pub fn delegation(
        tenant: TenantScope,
        delegation_identity: &str,
        source_entry: &str,
    ) -> GrantContractResult<Self> {
        Self::new(
            tenant,
            GrantSourceKind::Delegation,
            BindingLayer::None,
            "DELEGATION",
            delegation_identity,
            source_entry,
            delegation_identity,
        )
    }

    /// Contribution materialized by an explicit approval record; the layer is
    /// always [`BindingLayer::None`].
    ///
    /// The approval request is the source aggregate (`APPROVAL`); `source_entry`
    /// is the stable id of the individual approved line, and `binding_key` is
    /// the mandatory carrier binding scope through which the approved grant
    /// becomes effective, so two carriers granted by one approval request never
    /// share an identity.
    pub fn approval(
        tenant: TenantScope,
        approval_request_id: &str,
        source_entry: &str,
        binding_key: &str,
    ) -> GrantContractResult<Self> {
        Self::new(
            tenant,
            GrantSourceKind::Approval,
            BindingLayer::None,
            "APPROVAL",
            approval_request_id,
            source_entry,
            binding_key,
        )
    }

    /// System contribution (administrative tooling such as migration backfill);
    /// the layer is always [`BindingLayer::None`].
    ///
    /// A backfill/migration run is *not* an authorization origin of its own:
    /// it records provenance as a `SYSTEM` source whose
    /// [`GrantProvenance`] carries explicit `source_id` / `operation_id` values.
    /// The identity therefore still needs a real administrative aggregate type
    /// and id, a stable contribution entry, and a carrier binding scope - there
    /// is no empty-identity or random fallback.
    pub fn system(
        tenant: TenantScope,
        system_aggregate_type: &str,
        system_aggregate_id: &str,
        source_entry: &str,
        binding_key: &str,
    ) -> GrantContractResult<Self> {
        Self::new(
            tenant,
            GrantSourceKind::System,
            BindingLayer::None,
            system_aggregate_type,
            system_aggregate_id,
            source_entry,
            binding_key,
        )
    }

    pub fn validate(&self) -> GrantContractResult<()> {
        if self.schema_version != GRANT_IDENTITY_KEY_SCHEMA_VERSION {
            return Err(GrantContractError::IdentitySchemaVersionMismatch {
                expected: GRANT_IDENTITY_KEY_SCHEMA_VERSION,
                actual: self.schema_version,
            });
        }
        self.tenant.validate()?;
        normalize_identifier(&self.aggregate_type, "identity.aggregate_type")?;
        normalize_identifier(&self.aggregate_id, "identity.aggregate_id")?;
        // Both identity scopes are mandatory for every source kind. An empty or
        // malformed source entry would silently merge sibling contributions of
        // the same aggregate onto one shared grant identity, which the ledger
        // then rejects fail-closed (DuplicateActiveGrant); rejection here is
        // cheaper and unambiguous.
        normalize_identifier(&self.source_entry, "identity.source_entry")?;
        normalize_identifier(&self.binding_key, "identity.binding_key")?;
        if !source_kind_aligns_with_binding_layer(self.source_kind, self.binding_layer) {
            return Err(GrantContractError::SourceLayerMismatch {
                source_kind: self.source_kind.as_str(),
                binding_layer: self.binding_layer.as_str(),
            });
        }
        Ok(())
    }

    /// Trim identifier edges and return a stable canonical value. Unknown future
    /// schema versions fail closed instead of being silently accepted.
    pub fn canonicalized(&self) -> GrantContractResult<Self> {
        let value = Self {
            schema_version: self.schema_version,
            source_kind: self.source_kind,
            binding_layer: self.binding_layer,
            tenant: self.tenant.canonicalized()?,
            aggregate_type: normalize_identifier(&self.aggregate_type, "identity.aggregate_type")?,
            aggregate_id: normalize_identifier(&self.aggregate_id, "identity.aggregate_id")?,
            source_entry: normalize_identifier(&self.source_entry, "identity.source_entry")?,
            binding_key: normalize_identifier(&self.binding_key, "identity.binding_key")?,
        };
        value.validate()?;
        Ok(value)
    }

    /// Deterministic encoding of a canonicalized key: fixed header, schema
    /// version token, enum tokens, numeric tenant fields, then byte-length-prefixed
    /// free-form components separated by U+001F. Every free-form component is
    /// mandatory under this schema version, so all four slots always carry a
    /// value; the positions stay fixed, keeping the encoding injective over
    /// validated keys.
    pub fn canonical_text(&self) -> GrantContractResult<String> {
        let canonical = self.canonicalized()?;
        let mut out = String::new();
        out.push_str(GRANT_IDENTITY_KEY_HEADER);
        out.push(GRANT_IDENTITY_UNIT_SEPARATOR);
        out.push_str(&format!("V{}", canonical.schema_version));
        out.push(GRANT_IDENTITY_UNIT_SEPARATOR);
        out.push_str(canonical.source_kind.as_str());
        out.push(GRANT_IDENTITY_UNIT_SEPARATOR);
        out.push_str(canonical.binding_layer.as_str());
        out.push(GRANT_IDENTITY_UNIT_SEPARATOR);
        out.push_str(&canonical.tenant.tenant_id.to_string());
        out.push(GRANT_IDENTITY_UNIT_SEPARATOR);
        if let Some(domain_id) = canonical.tenant.domain_id {
            out.push_str(&domain_id.to_string());
        }
        push_identity_component(&mut out, &canonical.aggregate_type);
        push_identity_component(&mut out, &canonical.aggregate_id);
        push_identity_component(&mut out, &canonical.source_entry);
        push_identity_component(&mut out, &canonical.binding_key);
        Ok(out)
    }

    /// Derive the deterministic [`GrantId`] for this identity key via UUID v5
    /// under the fixed contract namespace. Producing the nil UUID is impossible
    /// because the derivation passes through [`GrantId::new`].
    ///
    /// Re-keying contract: an UPDATE of one contribution must keep its derived
    /// [`GrantId`] and may only change mutable payload attributes (resource,
    /// action, priority, validity window). If the underlying stable source-entry
    /// identity changes, the mutation is semantically REMOVE(old id) + ADD(new
    /// id) - never an UPDATE carrying a re-derived id against the old head.
    pub fn derive_grant_id(&self) -> GrantContractResult<GrantId> {
        self.validate()?;
        let input = self.canonical_text()?;
        let uuid = Uuid::new_v5(&grant_identity_namespace(), input.as_bytes());
        GrantId::new(uuid)
    }
}

// ---------------------------------------------------------------------------
// Contribution delta event identity（与 grant identity 严格域分离）
// ---------------------------------------------------------------------------

/// Fixed wire/schema version of the contribution delta event identity contract.
///
/// Bumping it, or changing the header text below, is a breaking contract change
/// by design: previously derived contribution event ids become incomparable and
/// no silent compatibility mapping exists.
pub const DELTA_EVENT_IDENTITY_SCHEMA_VERSION: u32 = 1;

/// Fixed header prefix that domain-separates contribution delta event identity
/// from [`GRANT_IDENTITY_KEY_HEADER`]: a derived event id can never equal the
/// derived id of a grant identity because their canonical texts start with
/// different fixed headers under the same UUID v5 namespace.
const DELTA_EVENT_IDENTITY_HEADER: &str = "ASTRAL_DELTA_EVENT_IDENTITY";

/// Canonical inputs of one deterministic contribution delta event id.
///
/// Every independently persisted grant contribution (its immutable revision +
/// its delta-event row) must carry a stable, replayable event id. Sibling
/// contributions recorded under one shared batch operation therefore never
/// collide on `authorization_delta_event.uk_ade_event`: each row derives its id
/// from the same `operation_id` plus this contribution's stable identity
/// dimensions (tenant, aggregate, source entry) and mutation kind.
///
/// This type names *one recorded mutation event*, never one logical
/// authorization grant - it is deliberately a distinct struct from
/// [`GrantIdentityKey`] so an event identity cannot be confused with (or
/// substituted for) a grant identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaEventIdentity<'a> {
    /// Durable operation id shared by every contribution of the same batch
    /// invocation; identical retries of the same logical operation reuse it.
    pub operation_id: &'a str,
    /// Tenant boundary of the contribution; crossing tenants is never
    /// identity-preserving even when every other dimension matches.
    pub tenant_id: i64,
    pub aggregate_type: &'a str,
    /// Primary key of the source aggregate (e.g. the carrying user card id).
    pub aggregate_id: i64,
    /// Stable id of the individual contribution inside the aggregate (e.g. the
    /// permission_rule primary key).
    pub source_entry: &'a str,
    /// Typed mutation kind token (`add`, `update`, `remove`, ...). Distinct
    /// kinds over one contribution never share an event identity.
    pub mutation_kind: &'a str,
}

impl DeltaEventIdentity<'_> {
    fn validate(&self) -> GrantContractResult<()> {
        validate_positive_id(self.tenant_id, "delta_event.tenant_id")?;
        validate_positive_id(self.aggregate_id, "delta_event.aggregate_id")?;
        normalize_identifier(self.operation_id, "delta_event.operation_id")?;
        normalize_identifier(self.aggregate_type, "delta_event.aggregate_type")?;
        normalize_identifier(self.source_entry, "delta_event.source_entry")?;
        normalize_identifier(self.mutation_kind, "delta_event.mutation_kind")?;
        Ok(())
    }

    /// Deterministic canonical encoding with fixed field positions: header,
    /// schema version token, then length-prefixed free-form components around
    /// numeric scope ids. Every component carries an explicit byte-length
    /// prefix via [`push_identity_component`], keeping the encoding injective
    /// over validated inputs.
    fn canonical_text(&self) -> GrantContractResult<String> {
        self.validate()?;
        let mut out = String::new();
        out.push_str(DELTA_EVENT_IDENTITY_HEADER);
        out.push(GRANT_IDENTITY_UNIT_SEPARATOR);
        out.push_str(&format!("V{DELTA_EVENT_IDENTITY_SCHEMA_VERSION}"));
        push_identity_component(&mut out, self.operation_id.trim());
        out.push(GRANT_IDENTITY_UNIT_SEPARATOR);
        out.push_str(&self.tenant_id.to_string());
        push_identity_component(&mut out, self.aggregate_type.trim());
        out.push(GRANT_IDENTITY_UNIT_SEPARATOR);
        out.push_str(&self.aggregate_id.to_string());
        push_identity_component(&mut out, self.source_entry.trim());
        push_identity_component(&mut out, self.mutation_kind.trim());
        Ok(out)
    }

    /// Derive the deterministic contribution event id as lowercase hyphenated
    /// UUID v5 text under the fixed [`grant_identity_namespace`]. The result is
    /// always 36 characters (well within any column limit for event ids),
    /// stable across retries of the same logical operation, and guaranteed to
    /// differ for different operation/tenant/aggregate/source-entry/kind
    /// combinations.
    pub fn derive_event_id(&self) -> GrantContractResult<String> {
        let input = self.canonical_text()?;
        Ok(Uuid::new_v5(&grant_identity_namespace(), input.as_bytes()).to_string())
    }
}

/// One canonical positive authorization grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalGrant {
    pub grant_id: GrantId,
    pub revision: GrantRevision,
    pub state: GrantState,
    pub source_kind: GrantSourceKind,
    pub binding_layer: BindingLayer,
    pub tenant: TenantScope,
    pub card_id: i64,
    pub user_id: i64,
    pub resource: String,
    pub action: String,
    pub effect: GrantEffect,
    pub validity: ValidityWindow,
    pub provenance: GrantProvenance,
}

impl CanonicalGrant {
    pub fn validate(&self) -> GrantContractResult<()> {
        self.grant_id.validate()?;
        self.revision.validate()?;
        self.tenant.validate()?;
        validate_positive_id(self.card_id, "card_id")?;
        validate_positive_id(self.user_id, "user_id")?;
        normalize_identifier(&self.resource, "resource")?;
        normalize_identifier(&self.action, "action")?;
        self.effect.validate()?;
        self.validity.validate()?;
        self.provenance.validate()?;
        self.validate_source_binding_alignment()?;
        Ok(())
    }

    /// Enforce canonical source-kind/binding-layer alignment and the provenance
    /// invariants: `DELEGATION` carries a delegation id exactly, every other
    /// non-RuleSet kind never carries one, and a `RULE_SET` contribution must
    /// carry the user-card/rule-set binding that put it on the
    /// effective-authorization path.
    fn validate_source_binding_alignment(&self) -> GrantContractResult<()> {
        if !source_kind_aligns_with_binding_layer(self.source_kind, self.binding_layer) {
            return Err(GrantContractError::SourceLayerMismatch {
                source_kind: self.source_kind.as_str(),
                binding_layer: self.binding_layer.as_str(),
            });
        }
        match self.source_kind {
            GrantSourceKind::Delegation => {
                if self.provenance.delegation_id.is_none() {
                    return Err(GrantContractError::InvalidProvenance(
                        "DELEGATION grants must carry a delegation_id".to_owned(),
                    ));
                }
            }
            GrantSourceKind::RuleSet => {
                if self.provenance.binding_id.is_none() {
                    return Err(GrantContractError::InvalidProvenance(
                        "RULE_SET grants must carry the carrying user-card binding_id".to_owned(),
                    ));
                }
            }
            GrantSourceKind::Direct | GrantSourceKind::Approval | GrantSourceKind::System => {
                if self.provenance.delegation_id.is_some() {
                    return Err(GrantContractError::InvalidProvenance(
                        "delegation_id is reserved for DELEGATION grants".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Trim identifier edges and return a stable canonical value.
    pub fn canonicalized(&self) -> GrantContractResult<Self> {
        let value = Self {
            grant_id: self.grant_id,
            revision: self.revision,
            state: self.state,
            source_kind: self.source_kind,
            binding_layer: self.binding_layer,
            tenant: self.tenant.canonicalized()?,
            card_id: self.card_id,
            user_id: self.user_id,
            resource: normalize_identifier(&self.resource, "resource")?,
            action: normalize_identifier(&self.action, "action")?,
            effect: self.effect,
            validity: self.validity,
            provenance: self.provenance.canonicalized()?,
        };
        value.validate()?;
        Ok(value)
    }

    /// Deterministic JSON input used by the evidence/hash boundary.
    pub fn canonical_input(&self) -> GrantContractResult<String> {
        canonical_json(&self.canonicalized()?)
    }

    /// Lowercase SHA-256 of the deterministic canonical input.
    pub fn canonical_hash(&self) -> GrantContractResult<String> {
        Ok(sha256_hex(&self.canonical_input()?))
    }
}

/// Evidence binding one grant to a generation-fenced source event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantEvidence {
    pub grant: CanonicalGrant,
    pub event_id: String,
    pub operation_id: String,
    pub source_generation: u64,
    pub revoke_fence: u64,
    pub dependency_vector: DependencyVector,
}

/// Descriptive alias for callers that prefer the fully qualified name.
pub type CanonicalGrantEvidence = GrantEvidence;

impl GrantEvidence {
    pub fn validate(&self) -> GrantContractResult<()> {
        self.grant.validate()?;
        normalize_identifier(&self.event_id, "event_id")?;
        normalize_identifier(&self.operation_id, "operation_id")?;
        validate_generation(self.source_generation, "source_generation")?;
        validate_fence(self.source_generation, self.revoke_fence)?;
        self.dependency_vector.validate()?;
        if self.grant.provenance.operation_id != self.operation_id {
            return Err(GrantContractError::InvalidDelta(
                "grant provenance operation_id does not match evidence operation_id".to_owned(),
            ));
        }
        if let Some(provenance_event_id) = &self.grant.provenance.event_id {
            if provenance_event_id != &self.event_id {
                return Err(GrantContractError::InvalidDelta(
                    "grant provenance event_id does not match evidence event_id".to_owned(),
                ));
            }
        }
        Ok(())
    }

    pub fn canonicalized(&self) -> GrantContractResult<Self> {
        let value = Self {
            grant: self.grant.canonicalized()?,
            event_id: normalize_identifier(&self.event_id, "event_id")?,
            operation_id: normalize_identifier(&self.operation_id, "operation_id")?,
            source_generation: self.source_generation,
            revoke_fence: self.revoke_fence,
            dependency_vector: self.dependency_vector.canonicalized()?,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn canonical_input(&self) -> GrantContractResult<String> {
        canonical_json(&self.canonicalized()?)
    }

    pub fn canonical_hash(&self) -> GrantContractResult<String> {
        Ok(sha256_hex(&self.canonical_input()?))
    }
}

/// A typed source mutation for the hot-state projection.
///
/// `UPDATE`, `REMOVE`, and `REVOKE` explicitly carry `expected_revision`: the CAS
/// revision the caller believes is current in the projection ledger. Applying such a
/// delta is fail-closed against unknown identities, stale (`expected < ledger`),
/// gapped (`expected > ledger`), or duplicated mutations; the consumer must return an
/// explicit conflict instead of silently skipping. A resulting tombstone always
/// advances to `expected_revision + 1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum GrantDelta {
    #[serde(rename = "ADD")]
    Add { grant: CanonicalGrant },
    #[serde(rename = "UPDATE")]
    Update {
        grant: CanonicalGrant,
        expected_revision: GrantRevision,
    },
    #[serde(rename = "REMOVE")]
    Remove {
        grant_id: GrantId,
        expected_revision: GrantRevision,
    },
    #[serde(rename = "REVOKE")]
    Revoke {
        grant_id: GrantId,
        expected_revision: GrantRevision,
    },
}

impl GrantDelta {
    pub fn add(grant: CanonicalGrant) -> Self {
        Self::Add { grant }
    }

    pub fn update(grant: CanonicalGrant, expected_revision: GrantRevision) -> Self {
        Self::Update {
            grant,
            expected_revision,
        }
    }

    pub fn remove(grant_id: GrantId, expected_revision: GrantRevision) -> Self {
        Self::Remove {
            grant_id,
            expected_revision,
        }
    }

    pub fn revoke(grant_id: GrantId, expected_revision: GrantRevision) -> Self {
        Self::Revoke {
            grant_id,
            expected_revision,
        }
    }

    pub fn validate(&self) -> GrantContractResult<()> {
        match self {
            Self::Add { grant } => {
                grant.validate()?;
                if grant.state != GrantState::Active {
                    return Err(GrantContractError::InvalidDelta(
                        "ADD requires an ACTIVE grant".to_owned(),
                    ));
                }
            }
            Self::Update {
                grant,
                expected_revision,
            } => {
                grant.validate()?;
                expected_revision.validate()?;
                if grant.state == GrantState::Removed {
                    return Err(GrantContractError::InvalidDelta(
                        "UPDATE cannot carry a REMOVED grant".to_owned(),
                    ));
                }
                // The payload must be the structural CAS successor of the expected
                // revision; anything else cannot be applied atomically.
                if grant.revision != expected_revision.next()? {
                    return Err(GrantContractError::InvalidDelta(
                        "UPDATE grant revision must equal expected_revision + 1".to_owned(),
                    ));
                }
            }
            Self::Remove {
                grant_id,
                expected_revision,
            }
            | Self::Revoke {
                grant_id,
                expected_revision,
            } => {
                grant_id.validate()?;
                expected_revision.validate()?;
            }
        }
        Ok(())
    }

    pub fn target_grant_id(&self) -> GrantContractResult<GrantId> {
        self.validate()?;
        Ok(match self {
            Self::Add { grant } | Self::Update { grant, .. } => grant.grant_id,
            Self::Remove { grant_id, .. } | Self::Revoke { grant_id, .. } => *grant_id,
        })
    }

    /// The explicit CAS revision carried by UPDATE/REMOVE/REVOKE. ADD does not
    /// address an existing record and therefore carries none.
    pub fn expected_revision(&self) -> Option<GrantRevision> {
        match self {
            Self::Add { .. } => None,
            Self::Update {
                expected_revision, ..
            }
            | Self::Remove {
                expected_revision, ..
            }
            | Self::Revoke {
                expected_revision, ..
            } => Some(*expected_revision),
        }
    }

    /// The revision this delta produces when applied: the successor of
    /// `expected_revision` for tombstones, or the payload revision for ADD/UPDATE.
    pub fn revision(&self) -> GrantContractResult<GrantRevision> {
        self.validate()?;
        Ok(match self {
            Self::Add { grant } | Self::Update { grant, .. } => grant.revision,
            Self::Remove {
                expected_revision, ..
            }
            | Self::Revoke {
                expected_revision, ..
            } => expected_revision.next()?,
        })
    }

    pub fn operation_name(&self) -> &'static str {
        match self {
            Self::Add { .. } => "ADD",
            Self::Update { .. } => "UPDATE",
            Self::Remove { .. } => "REMOVE",
            Self::Revoke { .. } => "REVOKE",
        }
    }

    pub fn canonicalized(&self) -> GrantContractResult<Self> {
        let value = match self {
            Self::Add { grant } => Self::Add {
                grant: grant.canonicalized()?,
            },
            Self::Update {
                grant,
                expected_revision,
            } => Self::Update {
                grant: grant.canonicalized()?,
                expected_revision: *expected_revision,
            },
            Self::Remove {
                grant_id,
                expected_revision,
            } => Self::Remove {
                grant_id: *grant_id,
                expected_revision: *expected_revision,
            },
            Self::Revoke {
                grant_id,
                expected_revision,
            } => Self::Revoke {
                grant_id: *grant_id,
                expected_revision: *expected_revision,
            },
        };
        value.validate()?;
        Ok(value)
    }
}

/// How a projection compiler produced its candidate state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProjectionCompileMode {
    Incremental,
    FullRebuild,
    Replay,
}

impl ProjectionCompileMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Incremental => "INCREMENTAL",
            Self::FullRebuild => "FULL_REBUILD",
            Self::Replay => "REPLAY",
        }
    }
}

/// Explicit reasons an incremental candidate must fall back to another mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FallbackReason {
    DeltaTooLarge,
    WildcardImpact,
    VersionConflict,
    DependencyUnavailable,
    InvalidDelta,
    LeaseLost,
    ArchiveRequired,
}

impl FallbackReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeltaTooLarge => "DELTA_TOO_LARGE",
            Self::WildcardImpact => "WILDCARD_IMPACT",
            Self::VersionConflict => "VERSION_CONFLICT",
            Self::DependencyUnavailable => "DEPENDENCY_UNAVAILABLE",
            Self::InvalidDelta => "INVALID_DELTA",
            Self::LeaseLost => "LEASE_LOST",
            Self::ArchiveRequired => "ARCHIVE_REQUIRED",
        }
    }
}

/// One generation/fence pair in a projection dependency vector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DependencyVersion {
    pub dependency_id: String,
    pub generation: u64,
    pub fence: u64,
}

impl DependencyVersion {
    pub fn new(
        dependency_id: impl Into<String>,
        generation: u64,
        fence: u64,
    ) -> GrantContractResult<Self> {
        let value = Self {
            dependency_id: dependency_id.into(),
            generation,
            fence,
        };
        value.canonicalized()
    }

    pub fn validate(&self) -> GrantContractResult<()> {
        normalize_identifier(&self.dependency_id, "dependency_id")?;
        validate_generation(self.generation, "dependency.generation")?;
        validate_fence(self.generation, self.fence)?;
        Ok(())
    }

    pub fn canonicalized(&self) -> GrantContractResult<Self> {
        let value = Self {
            dependency_id: normalize_identifier(&self.dependency_id, "dependency_id")?,
            generation: self.generation,
            fence: self.fence,
        };
        value.validate()?;
        Ok(value)
    }
}

/// Sorted, duplicate-free dependency versions used as a deterministic vector.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DependencyVector {
    pub versions: Vec<DependencyVersion>,
}

impl DependencyVector {
    pub fn new(versions: Vec<DependencyVersion>) -> GrantContractResult<Self> {
        let value = Self { versions };
        value.canonicalized()
    }

    pub fn validate(&self) -> GrantContractResult<()> {
        let mut identifiers = self
            .versions
            .iter()
            .map(|version| {
                version.validate()?;
                Ok(version.dependency_id.trim().to_owned())
            })
            .collect::<GrantContractResult<Vec<_>>>()?;
        identifiers.sort();
        for pair in identifiers.windows(2) {
            if pair[0] == pair[1] {
                return Err(GrantContractError::DuplicateDependency {
                    dependency_id: pair[0].clone(),
                });
            }
        }
        Ok(())
    }

    /// Sort dependencies by their normalized identifier and reject duplicates.
    pub fn canonicalized(&self) -> GrantContractResult<Self> {
        let mut versions = self
            .versions
            .iter()
            .map(DependencyVersion::canonicalized)
            .collect::<GrantContractResult<Vec<_>>>()?;
        versions.sort_by(|left, right| left.dependency_id.cmp(&right.dependency_id));
        let value = Self { versions };
        value.validate()?;
        Ok(value)
    }

    pub fn is_canonical(&self) -> bool {
        self.canonicalized()
            .map(|value| value == *self)
            .unwrap_or(false)
    }

    pub fn canonical_input(&self) -> GrantContractResult<String> {
        canonical_json(&self.canonicalized()?)
    }

    pub fn canonical_hash(&self) -> GrantContractResult<String> {
        Ok(sha256_hex(&self.canonical_input()?))
    }
}

/// A generation-fenced event carrying one source mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectionEventEnvelope {
    pub event_id: Uuid,
    pub operation_id: Uuid,
    pub tenant: TenantScope,
    pub aggregate_id: String,
    pub source_generation: u64,
    pub revoke_fence: u64,
    pub dependency_vector: DependencyVector,
    pub compile_mode: ProjectionCompileMode,
    pub fallback_reason: Option<FallbackReason>,
    pub delta: GrantDelta,
    pub emitted_at: i64,
}

/// Short alias used by event consumers.
pub type ProjectionEvent = ProjectionEventEnvelope;

impl ProjectionEventEnvelope {
    pub fn validate(&self) -> GrantContractResult<()> {
        validate_uuid(self.event_id, "event_id")?;
        validate_uuid(self.operation_id, "operation_id")?;
        self.tenant.validate()?;
        normalize_identifier(&self.aggregate_id, "aggregate_id")?;
        validate_generation(self.source_generation, "source_generation")?;
        validate_fence(self.source_generation, self.revoke_fence)?;
        self.dependency_vector.validate()?;
        self.delta.validate()?;
        let delta_revision = self.delta.revision()?.value();
        if delta_revision > self.source_generation {
            return Err(GrantContractError::InvalidDelta(
                "delta revision exceeds source generation".to_owned(),
            ));
        }
        if let GrantDelta::Add { grant } | GrantDelta::Update { grant, .. } = &self.delta {
            if grant.tenant != self.tenant {
                return Err(GrantContractError::TenantScopeMismatch);
            }
        }
        Ok(())
    }

    pub fn canonicalized(&self) -> GrantContractResult<Self> {
        let delta = self.delta.canonicalized()?;
        let value = Self {
            event_id: self.event_id,
            operation_id: self.operation_id,
            tenant: self.tenant.canonicalized()?,
            aggregate_id: normalize_identifier(&self.aggregate_id, "aggregate_id")?,
            source_generation: self.source_generation,
            revoke_fence: self.revoke_fence,
            dependency_vector: self.dependency_vector.canonicalized()?,
            compile_mode: self.compile_mode,
            fallback_reason: self.fallback_reason,
            delta,
            emitted_at: self.emitted_at,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn canonical_input(&self) -> GrantContractResult<String> {
        canonical_json(&self.canonicalized()?)
    }

    pub fn canonical_hash(&self) -> GrantContractResult<String> {
        Ok(sha256_hex(&self.canonical_input()?))
    }
}

/// A content-addressed segment in a projection manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SegmentReference {
    pub segment_id: String,
    pub ordinal: u64,
    pub generation: u64,
    pub grant_count: u64,
    pub content_hash: String,
}

/// Short alias for callers that use `SegmentRef` terminology.
pub type SegmentRef = SegmentReference;

impl SegmentReference {
    pub fn validate(&self) -> GrantContractResult<()> {
        normalize_identifier(&self.segment_id, "segment_id")?;
        validate_generation(self.generation, "segment.generation")?;
        validate_sha256_hex(&self.content_hash, "segment.content_hash")?;
        Ok(())
    }

    pub fn canonicalized(&self) -> GrantContractResult<Self> {
        let value = Self {
            segment_id: normalize_identifier(&self.segment_id, "segment_id")?,
            ordinal: self.ordinal,
            generation: self.generation,
            grant_count: self.grant_count,
            content_hash: self.content_hash.to_ascii_lowercase(),
        };
        value.validate()?;
        Ok(value)
    }
}

/// A generation-bound manifest for a compiled hot-state projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectionManifest {
    pub manifest_id: Uuid,
    pub tenant: TenantScope,
    pub generation: u64,
    pub revoke_fence: u64,
    pub compile_mode: ProjectionCompileMode,
    pub fallback_reason: Option<FallbackReason>,
    pub dependency_vector: DependencyVector,
    pub segments: Vec<SegmentReference>,
    pub grant_count: u64,
    pub content_hash: String,
}

impl ProjectionManifest {
    pub fn validate(&self) -> GrantContractResult<()> {
        validate_uuid(self.manifest_id, "manifest_id")?;
        self.tenant.validate()?;
        validate_generation(self.generation, "manifest.generation")?;
        validate_fence(self.generation, self.revoke_fence)?;
        self.dependency_vector.validate()?;
        validate_sha256_hex(&self.content_hash, "manifest.content_hash")?;

        let mut segments = self
            .segments
            .iter()
            .map(SegmentReference::canonicalized)
            .collect::<GrantContractResult<Vec<_>>>()?;
        segments.sort_by_key(|segment| segment.ordinal);
        let mut total_grants = 0u64;
        for (expected, segment) in segments.iter().enumerate() {
            let expected = expected as u64;
            if segment.ordinal != expected {
                return Err(GrantContractError::InvalidSegmentOrder {
                    expected,
                    actual: segment.ordinal,
                });
            }
            if segment.generation != self.generation {
                return Err(GrantContractError::InvalidGeneration {
                    field: "segment.generation",
                });
            }
            total_grants = total_grants.checked_add(segment.grant_count).ok_or(
                GrantContractError::GrantCountMismatch {
                    segment_count: u64::MAX,
                    manifest_count: self.grant_count,
                },
            )?;
        }
        if total_grants != self.grant_count {
            return Err(GrantContractError::GrantCountMismatch {
                segment_count: total_grants,
                manifest_count: self.grant_count,
            });
        }
        Ok(())
    }

    pub fn canonicalized(&self) -> GrantContractResult<Self> {
        let mut segments = self
            .segments
            .iter()
            .map(SegmentReference::canonicalized)
            .collect::<GrantContractResult<Vec<_>>>()?;
        segments.sort_by_key(|segment| segment.ordinal);
        let value = Self {
            manifest_id: self.manifest_id,
            tenant: self.tenant.canonicalized()?,
            generation: self.generation,
            revoke_fence: self.revoke_fence,
            compile_mode: self.compile_mode,
            fallback_reason: self.fallback_reason,
            dependency_vector: self.dependency_vector.canonicalized()?,
            segments,
            grant_count: self.grant_count,
            content_hash: self.content_hash.to_ascii_lowercase(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn canonical_input(&self) -> GrantContractResult<String> {
        canonical_json(&self.canonicalized()?)
    }

    pub fn canonical_hash(&self) -> GrantContractResult<String> {
        Ok(sha256_hex(&self.canonical_input()?))
    }
}

/// Archive operation kind for a manifest and its segments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ArchiveOperationKind {
    Create,
    Verify,
    Restore,
    Delete,
}

/// Stable identity for an archive attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveOperation {
    pub operation_id: Uuid,
    pub archive_id: Uuid,
    pub manifest_id: Uuid,
    pub tenant: TenantScope,
    pub generation: u64,
    pub kind: ArchiveOperationKind,
    pub requested_by_user_id: Option<i64>,
}

impl ArchiveOperation {
    pub fn validate(&self) -> GrantContractResult<()> {
        validate_uuid(self.operation_id, "archive.operation_id")?;
        validate_uuid(self.archive_id, "archive.archive_id")?;
        validate_uuid(self.manifest_id, "archive.manifest_id")?;
        self.tenant.validate()?;
        validate_generation(self.generation, "archive.generation")?;
        if let Some(user_id) = self.requested_by_user_id {
            validate_positive_id(user_id, "archive.requested_by_user_id")?;
        }
        Ok(())
    }

    pub fn canonicalized(&self) -> GrantContractResult<Self> {
        self.validate()?;
        Ok(self.clone())
    }
}

/// Durable evidence that an archive operation refers to one exact manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveProof {
    pub operation_id: Uuid,
    pub archive_id: Uuid,
    pub manifest_id: Uuid,
    pub tenant: TenantScope,
    pub generation: u64,
    pub segment_count: u64,
    pub content_hash: String,
    pub created_at: i64,
}

impl ArchiveProof {
    pub fn validate(&self) -> GrantContractResult<()> {
        validate_uuid(self.operation_id, "archive_proof.operation_id")?;
        validate_uuid(self.archive_id, "archive_proof.archive_id")?;
        validate_uuid(self.manifest_id, "archive_proof.manifest_id")?;
        self.tenant.validate()?;
        validate_generation(self.generation, "archive_proof.generation")?;
        validate_sha256_hex(&self.content_hash, "archive_proof.content_hash")?;
        Ok(())
    }

    pub fn proves(&self, operation: &ArchiveOperation) -> GrantContractResult<bool> {
        self.validate()?;
        operation.validate()?;
        Ok(self.operation_id == operation.operation_id
            && self.archive_id == operation.archive_id
            && self.manifest_id == operation.manifest_id
            && self.tenant == operation.tenant
            && self.generation == operation.generation)
    }

    pub fn canonicalized(&self) -> GrantContractResult<Self> {
        let value = Self {
            operation_id: self.operation_id,
            archive_id: self.archive_id,
            manifest_id: self.manifest_id,
            tenant: self.tenant.canonicalized()?,
            generation: self.generation,
            segment_count: self.segment_count,
            content_hash: self.content_hash.to_ascii_lowercase(),
            created_at: self.created_at,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn canonical_input(&self) -> GrantContractResult<String> {
        canonical_json(&self.canonicalized()?)
    }

    pub fn canonical_hash(&self) -> GrantContractResult<String> {
        Ok(sha256_hex(&self.canonical_input()?))
    }
}

// ---------------------------------------------------------------------------
// Published card authorization evidence（读侧纯 typed contract）
// ---------------------------------------------------------------------------

/// 整体读门（read gate）的三态词汇表。
///
/// 这是已发布授权证据读取的稳定分类边界：PolicyEngine 侧用它把
/// 非 `Ready` 结果一律映射为 PENDING/DENY，绝不把旧快照/缓存/raw source
/// 回退放行。三个变体全部是长期契约（`pub` API），不要求读取方在本切片内
/// 构造出每一种。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PublishedEvidenceGateStatus {
    /// 全部聚合在同一事务一致性快照下逐 manifest 通过严格校验，
    /// 有效授权集合可证明。
    Ready,
    /// durable 证据缺失或基础设施未知（缺 current 指针、DB 查询失败等）。
    /// 必须按 PENDING/DENY 处理，不得回退任何旧数据。
    Pending,
    /// durable 状态自相矛盾或违反合同（代数/scope/hash 冲突、未知聚合类型）。
    /// 必须按拒绝处理并触发人工对账，不得静默丢弃。
    Corrupt,
}

impl PublishedEvidenceGateStatus {
    /// Ready 状态的稳定代码字符串（供日志/审计/跨语言桥接）。
    pub const READY_CODE: &'static str = "published_card_evidence.ready";
    /// Pending 状态的稳定代码字符串。
    pub const PENDING_CODE: &'static str = "published_card_evidence.pending";
    /// Corrupt 状态的稳定代码字符串。
    pub const CORRUPT_CODE: &'static str = "published_card_evidence.corrupt";

    pub const fn code(self) -> &'static str {
        match self {
            Self::Ready => Self::READY_CODE,
            Self::Pending => Self::PENDING_CODE,
            Self::Corrupt => Self::CORRUPT_CODE,
        }
    }

    /// 只有 `Ready` 允许参与正式授权语义；其余状态一律不得放行。
    pub const fn is_authorization_usable(self) -> bool {
        matches!(self, Self::Ready)
    }
}

impl fmt::Display for PublishedEvidenceGateStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

/// domain 维度的显式过滤要求。
///
/// 刻意使用三态枚举而不是裸 `Option<i64>`：裸 `None` 无法区分"不限制
/// domain"与"必须没有 domain"，而这两者都是合法的读侧需求。该过滤只收窄
/// 结果集合（lens），不构成完整性判定；DB 侧没有权威 domain 列可以交叉
/// 验证，domain 的唯一来源是 grant 自己声明的 [`TenantScope`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainScopeRequirement {
    /// 接受任意（含无）domain 的 grant。
    Unconstrained,
    /// 要求 `grant.tenant.domain_id == Some(exact)`。
    ExactlySome(i64),
    /// 要求 `grant.tenant.domain_id.is_none()`。
    ExactlyNone,
}

impl DomainScopeRequirement {
    pub fn matches(&self, domain_id: Option<i64>) -> bool {
        match self {
            Self::Unconstrained => true,
            Self::ExactlySome(required) => domain_id == Some(*required),
            Self::ExactlyNone => domain_id.is_none(),
        }
    }
}

/// 一次已发布卡证据读取的范围输入（纯值，无 I/O）。
///
/// `user_filter == None` 表示不按 user 收窄（仍保留每条 grant 自己的
/// user_id）。tenant/card 是必须的强标识；domain 过滤见
/// [`DomainScopeRequirement`]。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedCardEvidenceScope {
    pub tenant_id: i64,
    pub card_id: i64,
    pub user_filter: Option<i64>,
    pub domain: DomainScopeRequirement,
}

impl PublishedCardEvidenceScope {
    pub fn validate(&self) -> GrantContractResult<()> {
        validate_positive_id(self.tenant_id, "evidence_scope.tenant_id")?;
        validate_positive_id(self.card_id, "evidence_scope.card_id")?;
        if let Some(user_id) = self.user_filter {
            validate_positive_id(user_id, "evidence_scope.user_filter")?;
        }
        if let DomainScopeRequirement::ExactlySome(domain_id) = self.domain {
            validate_positive_id(domain_id, "evidence_scope.domain")?;
        }
        Ok(())
    }

    /// 该 grant 是否通过本 scope 的窄化 lens（不含完整性判定）。
    pub fn narrows(&self, grant: &CanonicalGrant) -> bool {
        let user_ok = match self.user_filter {
            Some(user_id) => grant.user_id == user_id,
            None => true,
        };
        user_ok && self.domain.matches(grant.tenant.domain_id)
    }
}

/// 一条 grant 未进入有效授权集合的纯原因记录。
///
/// 过期/未生效/非 ACTIVE 与 user/domain 收窄都不再是错误，而是安全地
/// 不 ALLOW；scope 的结构性不一致（grant 的 tenant/card 与所属聚合矛盾）
/// 不属于这里——那是 Corrupt，整读失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UnacceptedGrantReason {
    /// `state != ACTIVE`（含 REVOKED/tombstone 语义）；只排除，不删除痕迹。
    InactiveState,
    /// `expires_at <= now`（窗口上界排他）。
    Expired,
    /// `not_before > now`（窗口下界包含）。
    NotYetValid,
    /// 被 scope 的 user 过滤条件收窄掉。
    OutOfUserFilter,
    /// 被 scope 的 domain 过滤条件收窄掉。
    OutOfDomainFilter,
}

/// 单条已验证 published grant 记录，保留完整 provenance。
///
/// `publication_generation` 只描述该 grant 所在 manifest 的发布代数；
/// 它与 `grant.revision`（账本修订号）属于两个命名空间，本合同禁止把两者
/// 相互比较或推断 successor 关系。所有 hash 字段是小写 64 位十六进制。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedPublishedGrantRecord {
    /// 来源聚合身份（provenance 的一部分；绝不与其它来源合并）。
    pub aggregate_type: String,
    pub aggregate_id: i64,
    /// 该 manifest 的 publication generation。
    pub publication_generation: u64,
    /// 发布时经指针 CAS 钉住的 revoke fence。
    pub revoke_fence: u64,
    pub manifest_id: i64,
    pub event_id: String,
    pub operation_id: String,
    pub semantic_hash_hex: String,
    pub dependency_hash_hex: String,
    pub compiler_version: String,
    /// grant 所属 segment 的 ordinal。
    pub segment_ordinal: u64,
    /// grant 在该 segment 规范载荷内的位置（从 0 起）。
    pub position_in_segment: u64,
    pub grant: CanonicalGrant,
    /// 是否进入有效授权集合。
    pub accepted_into_effective_set: bool,
    /// 未进入时的原因（`accepted == false` 时必为 `Some`）。
    pub unaccepted_reason: Option<UnacceptedGrantReason>,
}

impl VerifiedPublishedGrantRecord {
    fn validate_fields(&self) -> GrantContractResult<()> {
        self.grant.validate()?;
        validate_sha256_hex(&self.semantic_hash_hex, "record.semantic_hash_hex")?;
        validate_sha256_hex(&self.dependency_hash_hex, "record.dependency_hash_hex")?;
        normalize_identifier(&self.aggregate_type, "record.aggregate_type")?;
        normalize_identifier(&self.event_id, "record.event_id")?;
        normalize_identifier(&self.operation_id, "record.operation_id")?;
        normalize_identifier(&self.compiler_version, "record.compiler_version")?;
        validate_positive_id(self.aggregate_id, "record.aggregate_id")?;
        if self.accepted_into_effective_set && self.unaccepted_reason.is_some() {
            return Err(GrantContractError::InvalidProvenance(
                "accepted record must not carry an unaccepted reason".to_owned(),
            ));
        }
        if !self.accepted_into_effective_set && self.unaccepted_reason.is_none() {
            return Err(GrantContractError::InvalidProvenance(
                "rejected record must carry an unaccepted reason".to_owned(),
            ));
        }
        Ok(())
    }
}

/// 一个已发布聚合（同一 current 指针下的 COMMITTED manifest）的证据摘要。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishedAggregateManifestSummary {
    pub tenant_id: i64,
    pub card_id: i64,
    pub aggregate_type: String,
    pub aggregate_id: i64,
    pub manifest_id: i64,
    pub generation: u64,
    pub source_generation: u64,
    pub projected_generation: u64,
    pub revoke_fence: u64,
    pub cas_version: i64,
    pub semantic_hash_hex: String,
    pub dependency_hash_hex: String,
    pub manifest_digest_hex: String,
    pub compiler_version: String,
    pub event_id: String,
    pub operation_id: String,
    pub parent_manifest_id: Option<i64>,
    pub segment_count: u64,
    /// 各 segment 声明 row_count 之和（DB loader 已核对过与解码载荷一致）。
    pub declared_grant_row_count: u64,
}

/// 整体 read gate 摘要（成功路径恒为 `Ready`，但结构上保留三态词汇）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishedCardAuthorizationGate {
    pub status: PublishedEvidenceGateStatus,
    pub aggregate_manifest_count: usize,
    pub verified_record_count: usize,
    pub effective_grant_count: usize,
    /// verified 但被安全排除（过期/未生效/非 ACTIVE/user-domain 收窄）的条数。
    pub not_in_effective_count: usize,
    /// 因完全等价且同源而折叠掉的重复记录条数。
    pub equivalent_duplicate_collapsed_count: usize,
}

/// 一个 `(tenant, card)` 范围内全部已发布授权的最终 typed evidence。
///
/// # 语义边界（重要）
///
/// - status 只表达“已发布 COMMITTED”语义：本类型只能由严格 DB reader 在
///   所有不变式通过后构造；不存在半成品形态，也从不接受 legacy snapshot /
///   raw source / cache fallback 或任何 partial segment 回退。
/// - `effective_grants` 中每条 grant 都满足：ACTIVE + ALLOW + 统一 UTC now
///   下 validity 通过 + tenant/card 完整性验证 + 调用方 user/domain lens。
/// - 本类型是只读 strict evidence，也是正式授权输入：repository 侧声明
///   `requires_published_card_evidence == true` 时（Sqlx 生产实现即如此），
///   `PolicyEngine.evaluate()` 直接消费本类型并跳过 L1/L2/L2.5 读取器；
///   CACHE 包装层对同一端口透明转发，MQ 侧不消费该端口。
/// - 真实 MySQL integration 属后续门禁，当前仅纯测试覆盖。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishedCardAuthorization {
    pub tenant_id: i64,
    pub card_id: i64,
    /// 本次读取统一使用的 UTC Unix 秒 now（validity 判定的唯一时钟）。
    pub read_unix_seconds: i64,
    pub gate: PublishedCardAuthorizationGate,
    /// 按 `(aggregate_type, aggregate_id)` 升序排好的摘要。
    pub manifests: Vec<PublishedAggregateManifestSummary>,
    /// 全局确定性排序后的已验证记录（保留 provenance，包含被排除项）。
    pub records: Vec<VerifiedPublishedGrantRecord>,
    /// `records` 中 accepted 子集（保持同样顺序）的展开视图。
    pub effective_grants: Vec<CanonicalGrant>,
}

impl PublishedCardAuthorization {
    pub fn validate(&self) -> GrantContractResult<()> {
        validate_positive_id(self.tenant_id, "card_authorization.tenant_id")?;
        validate_positive_id(self.card_id, "card_authorization.card_id")?;
        if !self.gate.status.is_authorization_usable() {
            return Err(GrantContractError::InvalidProvenance(
                "published card authorization must carry a Ready gate".to_owned(),
            ));
        }
        for record in &self.records {
            record.validate_fields()?;
        }
        if self.effective_grants.len() != self.gate.effective_grant_count
            || self.records.len() != self.gate.verified_record_count
            || self.manifests.len() != self.gate.aggregate_manifest_count
        {
            return Err(GrantContractError::InvalidProvenance(
                "gate counters disagree with the actual collections".to_owned(),
            ));
        }
        // 结构一致性：`effective_grants` 必须恰好等于 `records` 中 accepted
        // 子集（同序同内容）。被排除记录是被刻意保留的，因此这里只按记录上
        // 的 `accepted_into_effective_set` 标志对位比较，绝不重新推导
        // ALLOW/validity/scope 判定，也不假设全部 records 都生效。
        let mut effective_iter = self.effective_grants.iter();
        let mut accepted_count = 0usize;
        for record in &self.records {
            if !record.accepted_into_effective_set {
                continue;
            }
            accepted_count += 1;
            match effective_iter.next() {
                Some(effective) if *effective == record.grant => {}
                _ => {
                    return Err(GrantContractError::InvalidProvenance(
                        "effective_grants must be exactly the accepted subset of records in the same order"
                            .to_owned(),
                    ));
                }
            }
        }
        if effective_iter.next().is_some() {
            return Err(GrantContractError::InvalidProvenance(
                "effective_grants must not exceed the accepted records".to_owned(),
            ));
        }
        // 计数一致性：verified 记录要么进入 effective 集合，要么被安全排除
        // （折叠的等价重复项不会保留为 record）。
        if self.gate.not_in_effective_count != self.records.len() - accepted_count {
            return Err(GrantContractError::InvalidProvenance(
                "gate not_in_effective_count disagrees with the excluded records".to_owned(),
            ));
        }
        // 每条 record 都来自某个 manifest；有记录却无 manifest 属于结构断裂。
        if (!self.records.is_empty() || !self.effective_grants.is_empty())
            && self.manifests.is_empty()
        {
            return Err(GrantContractError::InvalidProvenance(
                "records without a manifest have no provenance".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant() -> TenantScope {
        TenantScope::new(7, Some(11)).unwrap()
    }

    fn provenance(operation_id: &str, event_id: &str) -> GrantProvenance {
        GrantProvenance {
            source_id: "rule-set-entry-9".to_owned(),
            source_entry: Some("rule-set-entry-9".to_owned()),
            binding_id: Some("binding-3".to_owned()),
            delegation_id: None,
            operation_id: operation_id.to_owned(),
            event_id: Some(event_id.to_owned()),
            actor_user_id: Some(42),
        }
    }

    fn grant() -> CanonicalGrant {
        CanonicalGrant {
            grant_id: GrantId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            revision: GrantRevision::new(2).unwrap(),
            state: GrantState::Active,
            source_kind: GrantSourceKind::RuleSet,
            binding_layer: BindingLayer::Overlay,
            tenant: tenant(),
            card_id: 17,
            user_id: 42,
            resource: " learn_subject ".to_owned(),
            action: " read ".to_owned(),
            effect: GrantEffect::Allow,
            validity: ValidityWindow::between(100, 200),
            provenance: provenance("op-1", "event-1"),
        }
    }

    fn dependency_vector() -> DependencyVector {
        DependencyVector::new(vec![
            DependencyVersion::new("rule-set", 3, 1).unwrap(),
            DependencyVersion::new("card", 4, 0).unwrap(),
        ])
        .unwrap()
    }

    fn digest() -> String {
        "a".repeat(64)
    }

    #[test]
    fn grant_id_is_stable_through_parse_and_serde() {
        let id = GrantId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let encoded = serde_json::to_string(&id).unwrap();
        assert_eq!(encoded, "\"550e8400-e29b-41d4-a716-446655440000\"");
        let decoded: GrantId = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, id);
        assert_eq!(id.to_string(), "550e8400-e29b-41d4-a716-446655440000");
        assert!(GrantId::parse("00000000-0000-0000-0000-000000000000").is_err());
    }

    #[test]
    fn canonical_grant_normalizes_and_is_allow_only() {
        let value = grant();
        let canonical = value.canonicalized().unwrap();
        assert_eq!(canonical.resource, "learn_subject");
        assert_eq!(canonical.action, "read");
        assert_eq!(canonical.effect.as_str(), "ALLOW");
        assert!(canonical.canonical_hash().unwrap().len() == 64);

        let mut invalid = canonical;
        // GrantEffect is intentionally ALLOW-only, so a DENY payload is rejected
        // at the serde boundary rather than becoming a positive hot-state grant.
        let error = serde_json::from_str::<GrantEffect>("\"DENY\"").unwrap_err();
        assert!(error.to_string().contains("unknown variant"));
        invalid.card_id = 0;
        assert!(matches!(
            invalid.validate(),
            Err(GrantContractError::NonPositiveId {
                field: "card_id",
                ..
            })
        ));
    }

    #[test]
    fn delta_variants_validate_identity_and_cas_structure() {
        assert!(GrantDelta::add(grant()).validate().is_ok());
        let mut removed = grant();
        removed.state = GrantState::Removed;
        assert!(GrantDelta::add(removed).validate().is_err());

        let id = grant().grant_id;
        let expected = GrantRevision::new(3).unwrap();
        let remove = GrantDelta::remove(id, expected);
        let revoke = GrantDelta::revoke(id, expected);
        assert_eq!(remove.target_grant_id().unwrap(), id);
        // Tombstones apply at the successor of the carried CAS revision.
        assert_eq!(revoke.revision().unwrap().value(), 4);
        assert_eq!(remove.expected_revision(), Some(expected));
        assert_eq!(revoke.operation_name(), "REVOKE");
        assert_eq!(GrantDelta::add(grant()).expected_revision(), None);

        // UPDATE must carry payload revision = expected_revision + 1.
        let mut updated = grant();
        updated.revision = GrantRevision::new(2).unwrap();
        let gap = GrantRevision::new(5).unwrap();
        assert!(
            GrantDelta::update(updated.clone(), gap).validate().is_err(),
            "gap between expected revision and payload revision is rejected"
        );
        assert!(GrantDelta::update(updated, GrantRevision::initial())
            .validate()
            .is_ok());

        let invalid_revision: Result<GrantRevision, _> = 0u64.try_into();
        assert!(invalid_revision.is_err());
    }

    #[test]
    fn source_kind_and_binding_layer_are_aligned_fail_closed() {
        assert!(source_kind_aligns_with_binding_layer(
            GrantSourceKind::RuleSet,
            BindingLayer::Base
        ));
        assert!(source_kind_aligns_with_binding_layer(
            GrantSourceKind::RuleSet,
            BindingLayer::Overlay
        ));

        let mut mismatched = grant();
        // Base/Overlay labels exist only for RULE_SET; any other kind carrying
        // them is rejected instead of silently inheriting rule-set precedence.
        mismatched.source_kind = GrantSourceKind::Direct;
        assert!(matches!(
            mismatched.validate(),
            Err(GrantContractError::SourceLayerMismatch { .. })
        ));

        let mut mismatched_system = grant();
        mismatched_system.source_kind = GrantSourceKind::System;
        assert!(matches!(
            mismatched_system.validate(),
            Err(GrantContractError::SourceLayerMismatch { .. })
        ));

        let mut delegating_without_id = grant();
        delegating_without_id.source_kind = GrantSourceKind::Delegation;
        delegating_without_id.binding_layer = BindingLayer::None;
        assert!(matches!(
            delegating_without_id.validate(),
            Err(GrantContractError::InvalidProvenance(_))
        ));

        delegating_without_id.provenance.delegation_id = Some("delegation-7".to_owned());
        assert!(delegating_without_id.validate().is_ok());

        // delegation_id is exclusive to DELEGATION contributions.
        let mut direct_with_delegation = grant();
        direct_with_delegation.source_kind = GrantSourceKind::Direct;
        direct_with_delegation.binding_layer = BindingLayer::None;
        direct_with_delegation.provenance.delegation_id = Some("delegation-7".to_owned());
        assert!(matches!(
            direct_with_delegation.validate(),
            Err(GrantContractError::InvalidProvenance(_))
        ));

        for kind in [
            GrantSourceKind::Approval,
            GrantSourceKind::System,
            GrantSourceKind::Direct,
        ] {
            let mut value = grant();
            value.source_kind = kind;
            value.binding_layer = BindingLayer::None;
            value.provenance.delegation_id = Some("delegation-9".to_owned());
            assert!(matches!(
                value.validate(),
                Err(GrantContractError::InvalidProvenance(_))
            ));
            value.provenance.delegation_id = None;
            assert!(value.validate().is_ok());
        }
    }

    #[test]
    fn rule_set_grants_require_the_carrying_binding_id() {
        let mut unbound = grant();
        unbound.provenance.binding_id = None;
        assert!(matches!(
            unbound.validate(),
            Err(GrantContractError::InvalidProvenance(_))
        ));

        unbound.provenance.binding_id = Some("binding-3".to_owned());
        assert!(unbound.validate().is_ok());

        // Non-RuleSet kinds are not required to carry a rule binding; only the
        // alignment and delegation exclusivity rules apply to them.
        let mut direct_bound_optional = grant();
        direct_bound_optional.source_kind = GrantSourceKind::Direct;
        direct_bound_optional.binding_layer = BindingLayer::None;
        assert!(direct_bound_optional.validate().is_ok());
    }

    #[test]
    fn source_kinds_serde_roundtrip_exact_screaming_snake_names() {
        let expected_pairs = [
            (GrantSourceKind::RuleSet, "RULE_SET"),
            (GrantSourceKind::Direct, "DIRECT"),
            (GrantSourceKind::Delegation, "DELEGATION"),
            (GrantSourceKind::Approval, "APPROVAL"),
            (GrantSourceKind::System, "SYSTEM"),
        ];
        for (kind, token) in expected_pairs {
            assert_eq!(kind.as_str(), token);
            let encoded = serde_json::to_string(&kind).unwrap();
            assert_eq!(encoded, format!("\"{token}\""));
            let decoded: GrantSourceKind = serde_json::from_str(&encoded).unwrap();
            assert_eq!(decoded, kind);
        }

        let expected_layers = [
            (BindingLayer::Base, "BASE"),
            (BindingLayer::Overlay, "OVERLAY"),
            (BindingLayer::None, "NONE"),
        ];
        for (layer, token) in expected_layers {
            assert_eq!(layer.as_str(), token);
            let encoded = serde_json::to_string(&layer).unwrap();
            assert_eq!(encoded, format!("\"{token}\""));
            let decoded: BindingLayer = serde_json::from_str(&encoded).unwrap();
            assert_eq!(decoded, layer);
        }
    }

    /// Convention guard: `GrantSourceKind::System` stays reserved-unused.
    ///
    /// 1. Compile-time closed-set lock - the exhaustive match below fails to
    ///    compile if any variant is added or removed, forcing a review of this
    ///    contract surface.
    /// 2. Annotation lock - the variant's doc block must keep declaring the
    ///    reserved-unused status and the integration preconditions (an explicit
    ///    `grant_ledger_adapter` append function plus same-transaction audit
    ///    correlation before any future writer may emit `SYSTEM` grants).
    ///    Changing the annotation requires updating this guard in the same
    ///    change; side-door assembly stays forbidden (fail-closed).
    #[test]
    fn system_source_kind_stays_reserved_unused_with_locked_annotation() {
        // 1. Closed-set compile lock: adding/removing a variant breaks the
        //    exhaustive match instead of silently widening the origin family.
        let system_token = match GrantSourceKind::System {
            GrantSourceKind::RuleSet
            | GrantSourceKind::Direct
            | GrantSourceKind::Delegation
            | GrantSourceKind::Approval => unreachable!("matched the wrong source kind"),
            GrantSourceKind::System => GrantSourceKind::System.as_str(),
        };
        assert_eq!(system_token, "SYSTEM");

        // 2. Annotation lock: extract the doc block directly preceding the
        //    `System` variant (text between the `Approval` variant arm and the
        //    `System` variant arm inside the enum body only).
        let source = include_str!("grant.rs");
        let enum_body = source
            .split("pub enum GrantSourceKind")
            .nth(1)
            .and_then(|rest| rest.split('}').next())
            .expect("GrantSourceKind enum body must exist");
        let system_doc = enum_body
            .split("System,")
            .next()
            .and_then(|head| head.rsplit("Approval,").next())
            .expect("System variant doc block must follow the Approval variant");
        for marker in [
            "Reserved-unused",
            "grant_ledger_adapter",
            "same-transaction audit correlation",
        ] {
            assert!(
                system_doc.contains(marker),
                "GrantSourceKind::System must stay annotated as reserved-unused (missing marker: {marker}); \
                 a future writer must first add an explicit adapter append path with same-transaction audit"
            );
        }
    }

    #[test]
    fn legacy_wire_tokens_fail_deserialization() {
        // The removed source kinds have no alias: durable payloads carrying them
        // must fail loudly at the contract boundary instead of being silently
        // re-interpreted under the closed five-kind model.
        for legacy in ["CARD", "MANUAL", "MIGRATION"] {
            let error = serde_json::from_str::<GrantSourceKind>(&format!("\"{legacy}\""))
                .expect_err("legacy source kinds must not deserialize");
            assert!(
                error.to_string().contains("unknown variant"),
                "unexpected error for {legacy:?}: {error}"
            );
        }

        // DIRECT/DELEGATION were layers in the drifted contract and are now
        // source kinds only; they are not valid layer tokens anymore.
        for legacy_layer in ["DIRECT", "DELEGATION"] {
            let error = serde_json::from_str::<BindingLayer>(&format!("\"{legacy_layer}\""))
                .expect_err("legacy binding layers must not deserialize");
            assert!(
                error.to_string().contains("unknown variant"),
                "unexpected error for {legacy_layer:?}: {error}"
            );
        }
    }

    #[test]
    fn validity_window_is_utc_inclusive_exclusive() {
        let window = ValidityWindow::between(100, 200);
        assert!(window.is_valid_at(100), "not_before is inclusive");
        assert!(window.is_valid_at(199));
        assert!(!window.is_valid_at(200), "expires_at is exclusive");

        // An empty (not_before == expires_at) or inverted window fails validation
        // instead of silently matching nothing.
        assert!(ValidityWindow::between(200, 200).validate().is_err());
        assert!(ValidityWindow::between(20, 10).validate().is_err());
    }

    #[test]
    fn dependency_vector_sorts_and_hashes_deterministically() {
        let first = dependency_vector();
        let second = DependencyVector::new(vec![
            DependencyVersion::new("card", 4, 0).unwrap(),
            DependencyVersion::new("rule-set", 3, 1).unwrap(),
        ])
        .unwrap();
        assert_eq!(first, second);
        assert!(first.is_canonical());
        assert_eq!(
            first.canonical_hash().unwrap(),
            second.canonical_hash().unwrap()
        );

        let duplicate = DependencyVector {
            versions: vec![
                DependencyVersion::new("card", 1, 0).unwrap(),
                DependencyVersion::new("card", 2, 0).unwrap(),
            ],
        };
        assert!(matches!(
            duplicate.validate(),
            Err(GrantContractError::DuplicateDependency { .. })
        ));
    }

    #[test]
    fn event_envelope_checks_generation_and_tenant_scope() {
        let event_id = Uuid::new_v4();
        let operation_id = Uuid::new_v4();
        let envelope = ProjectionEventEnvelope {
            event_id,
            operation_id,
            tenant: tenant(),
            aggregate_id: "card:17".to_owned(),
            source_generation: 3,
            revoke_fence: 1,
            dependency_vector: dependency_vector(),
            compile_mode: ProjectionCompileMode::Incremental,
            fallback_reason: None,
            delta: GrantDelta::add(grant()),
            emitted_at: 1_700_000_000,
        };
        assert!(envelope.validate().is_ok());
        assert!(envelope.canonical_hash().unwrap().len() == 64);

        let mut invalid = envelope;
        invalid.revoke_fence = 4;
        assert!(matches!(
            invalid.validate(),
            Err(GrantContractError::InvalidFence { .. })
        ));

        let mut mismatched = invalid;
        mismatched.revoke_fence = 1;
        mismatched.tenant = TenantScope::new(8, None).unwrap();
        assert_eq!(
            mismatched.validate(),
            Err(GrantContractError::TenantScopeMismatch)
        );
    }

    #[test]
    fn manifest_and_segment_validation_is_ordered_and_counted() {
        let manifest = ProjectionManifest {
            manifest_id: Uuid::new_v4(),
            tenant: tenant(),
            generation: 5,
            revoke_fence: 0,
            compile_mode: ProjectionCompileMode::FullRebuild,
            fallback_reason: Some(FallbackReason::VersionConflict),
            dependency_vector: dependency_vector(),
            segments: vec![
                SegmentReference {
                    segment_id: "segment-1".to_owned(),
                    ordinal: 1,
                    generation: 5,
                    grant_count: 1,
                    content_hash: digest(),
                },
                SegmentReference {
                    segment_id: "segment-0".to_owned(),
                    ordinal: 0,
                    generation: 5,
                    grant_count: 2,
                    content_hash: digest(),
                },
            ],
            grant_count: 3,
            content_hash: digest(),
        };
        assert!(manifest.validate().is_ok());
        let canonical = manifest.canonicalized().unwrap();
        assert_eq!(canonical.segments[0].ordinal, 0);
        assert_eq!(canonical.segments[1].ordinal, 1);

        let mut invalid = canonical;
        invalid.grant_count = 4;
        assert!(matches!(
            invalid.validate(),
            Err(GrantContractError::GrantCountMismatch { .. })
        ));
        invalid.grant_count = 3;
        invalid.segments[0].content_hash = "not-a-hash".to_owned();
        assert!(matches!(
            invalid.validate(),
            Err(GrantContractError::InvalidHash {
                field: "segment.content_hash"
            })
        ));
    }

    #[test]
    fn archive_proof_binds_stable_archive_identity() {
        let operation = ArchiveOperation {
            operation_id: Uuid::new_v4(),
            archive_id: Uuid::new_v4(),
            manifest_id: Uuid::new_v4(),
            tenant: tenant(),
            generation: 9,
            kind: ArchiveOperationKind::Create,
            requested_by_user_id: Some(42),
        };
        let proof = ArchiveProof {
            operation_id: operation.operation_id,
            archive_id: operation.archive_id,
            manifest_id: operation.manifest_id,
            tenant: operation.tenant.clone(),
            generation: operation.generation,
            segment_count: 2,
            content_hash: digest(),
            created_at: 1_700_000_001,
        };
        assert!(operation.validate().is_ok());
        assert!(proof.proves(&operation).unwrap());

        let mut wrong = proof;
        wrong.archive_id = Uuid::new_v4();
        assert!(!wrong.proves(&operation).unwrap());
    }

    #[test]
    fn malformed_scope_and_versions_are_rejected() {
        assert!(TenantScope::from_str("7/").is_err());
        assert!(TenantScope::from_str("0/11").is_err());
        assert!(TenantScope::from_str("7/11/13").is_err());
        assert!(DependencyVersion::new("dependency", 0, 0).is_err());
        assert!(DependencyVersion::new("dependency", 2, 3).is_err());
        assert!(ValidityWindow::between(20, 10).validate().is_err());

        let mut value = grant();
        value.provenance.source_id = "   ".to_owned();
        assert!(matches!(
            value.validate(),
            Err(GrantContractError::EmptyIdentifier {
                field: "provenance.source_id"
            })
        ));
    }

    fn identity_key() -> GrantIdentityKey {
        GrantIdentityKey {
            schema_version: GRANT_IDENTITY_KEY_SCHEMA_VERSION,
            source_kind: GrantSourceKind::RuleSet,
            binding_layer: BindingLayer::Overlay,
            tenant: TenantScope::new(7, Some(11)).unwrap(),
            aggregate_type: "RULE_SET".to_owned(),
            aggregate_id: "rs-42".to_owned(),
            source_entry: "entry-17".to_owned(),
            binding_key: "user-card-3".to_owned(),
        }
    }

    #[test]
    fn derived_grant_identity_is_deterministic_and_canonical() {
        let first = identity_key().derive_grant_id().unwrap();
        let second = identity_key().derive_grant_id().unwrap();
        assert_eq!(first, second);
        assert!(!first.as_uuid().is_nil());

        // Identifier edges are normalized before hashing, so padding cannot fork
        // one logical grant into several identities.
        let mut padded = identity_key();
        padded.aggregate_id = "  rs-42 ".to_owned();
        assert_eq!(padded.derive_grant_id().unwrap(), first);

        let rebuilt = GrantIdentityKey::new(
            TenantScope::new(7, Some(11)).unwrap(),
            GrantSourceKind::RuleSet,
            BindingLayer::Overlay,
            "RULE_SET",
            "rs-42",
            "entry-17",
            "user-card-3",
        )
        .unwrap();
        assert_eq!(rebuilt.derive_grant_id().unwrap(), first);
        assert_eq!(GrantId::derive_deterministic(&rebuilt).unwrap(), first);

        // Output stays the CHAR(36) lowercase hyphenated canonical text across
        // Display, parse, and serde.
        let text = first.as_str();
        assert_eq!(text.len(), 36);
        assert!(text
            .chars()
            .all(|character| character.is_ascii_hexdigit() || character == '-'));
        assert_eq!(GrantId::parse(&text).unwrap(), first);

        let encoded = serde_json::to_string(&first).unwrap();
        assert_eq!(encoded, format!("\"{text}\""));
        let decoded: GrantId = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, first);
    }

    #[test]
    fn every_identity_dimension_changes_the_derived_id() {
        let base = identity_key().derive_grant_id().unwrap();

        let mut mutations = Vec::new();

        let mut value = identity_key();
        value.tenant = TenantScope::new(8, Some(11)).unwrap();
        mutations.push(value);

        let mut value = identity_key();
        value.tenant = TenantScope::new(7, None).unwrap();
        mutations.push(value);

        let mut value = identity_key();
        value.tenant = TenantScope::new(7, Some(12)).unwrap();
        mutations.push(value);

        let mut value = identity_key();
        value.binding_layer = BindingLayer::Base;
        mutations.push(value);

        let mut value = identity_key();
        value.source_entry = "entry-18".to_owned();
        mutations.push(value);

        let mut value = identity_key();
        value.binding_key = "user-card-4".to_owned();
        mutations.push(value);

        let mut value = identity_key();
        value.aggregate_id = "rs-43".to_owned();
        mutations.push(value);

        let mut value = identity_key();
        value.aggregate_type = "RULE_SET_V2".to_owned();
        mutations.push(value);

        for value in mutations {
            value.validate().expect("mutation must stay valid");
            assert_ne!(value.derive_grant_id().unwrap(), base);
        }
    }

    #[test]
    fn mutable_fields_change_under_update_while_identity_is_reused() {
        let key = identity_key();
        let base_id = key.derive_grant_id().unwrap();

        let build = |revision: u64, resource: &str, action: &str, validity: ValidityWindow| {
            CanonicalGrant {
                grant_id: base_id,
                revision: GrantRevision::new(revision).unwrap(),
                state: GrantState::Active,
                source_kind: GrantSourceKind::RuleSet,
                binding_layer: BindingLayer::Overlay,
                tenant: TenantScope::new(7, Some(11)).unwrap(),
                card_id: 17,
                user_id: 42,
                resource: resource.to_owned(),
                action: action.to_owned(),
                effect: GrantEffect::Allow,
                validity,
                provenance: provenance("op-shared-key", "event-shared"),
            }
        };

        // One contribution evolves through UPDATEs: the mutable payload
        // attributes (resource, action, priority, validity window) change
        // freely while grant_id stays pinned to the same derived identity.
        let v1 = build(
            2,
            "learn_subject",
            "read",
            ValidityWindow::between(100, 200),
        );
        let v2 = build(3, "learn_subject_v2", "manage", ValidityWindow::perpetual());
        assert!(v1.validate().is_ok());
        assert!(v2.validate().is_ok());
        assert_ne!(v1.resource, v2.resource);
        assert_ne!(v1.action, v2.action);
        assert_ne!(v1.validity, v2.validity);
        assert_eq!(v1.grant_id, v2.grant_id);
        assert_eq!(v1.grant_id, key.derive_grant_id().unwrap());

        // UPDATE deltas built from successive versions keep targeting exactly
        // one identity and satisfy the structural CAS chain: payload revision 3
        // must arrive with expected_revision 2.
        let delta = GrantDelta::update(v2.clone(), GrantRevision::new(2).unwrap());
        assert!(delta.validate().is_ok());
        assert_eq!(delta.target_grant_id().unwrap(), base_id);
        assert_eq!(delta.revision().unwrap(), v2.revision);
    }

    #[test]
    fn sibling_contributions_never_share_one_grant_identity() {
        // The ledger keeps one ACTIVE record per derived id and fails closed on
        // a second ADD (DuplicateActiveGrant). Therefore two independently
        // mutable contributions under the SAME card/source/binding - differing
        // only in which stable entry they represent - must derive different
        // identities. Sharing one id would make the second ADD unrepresentable.
        let first = identity_key().derive_grant_id().unwrap();
        let mut second_entry = identity_key();
        second_entry.source_entry = "entry-18".to_owned();
        assert_ne!(second_entry.derive_grant_id().unwrap(), first);

        // Direct contributions coming through one card binding follow the same
        // rule: one permission_rule per identity, never one card-wide identity.
        let tenant = TenantScope::new(7, Some(11)).unwrap();
        let card_entry_one =
            GrantIdentityKey::direct(tenant.clone(), "user-card-17", "permission-rule-42").unwrap();
        let card_entry_two =
            GrantIdentityKey::direct(tenant.clone(), "user-card-17", "permission-rule-77").unwrap();
        assert_ne!(
            card_entry_one.derive_grant_id().unwrap(),
            card_entry_two.derive_grant_id().unwrap()
        );

        // Delegation clauses behave identically inside one delegation chain.
        let clause_one = GrantIdentityKey::delegation(tenant.clone(), "del-7", "clause-1").unwrap();
        let clause_two = GrantIdentityKey::delegation(tenant.clone(), "del-7", "clause-2").unwrap();
        assert_ne!(
            clause_one.derive_grant_id().unwrap(),
            clause_two.derive_grant_id().unwrap()
        );

        // Conversely, deriving twice from the same stable entry + scope yields
        // ONE identity for that single contribution; re-keying that
        // contribution happens exclusively through REMOVE(old) + ADD(new).
        assert_eq!(identity_key().derive_grant_id().unwrap(), first);
    }

    #[test]
    fn canonical_text_uses_fixed_positions_and_length_prefixes() {
        let canonical = identity_key().canonicalized().unwrap();
        let text = canonical.canonical_text().unwrap();
        assert_eq!(
            text,
            concat!(
                "ASTRAL_GRANT_IDENTITY\u{1F}V1\u{1F}RULE_SET\u{1F}OVERLAY\u{1F}",
                "7\u{1F}11\u{1F}8:RULE_SET\u{1F}5:rs-42\u{1F}8:entry-17\u{1F}11:user-card-3"
            )
        );
        // Printable ASCII plus the unit separator byte only.
        assert!(text
            .bytes()
            .all(|byte| (0x20..=0x7E).contains(&byte) || byte == 0x1F));
        assert!(!text.contains('{') && !text.contains('}'));
        assert!(!text.starts_with("urn:"));

        // Administrative SYSTEM sources carry real, mandatory aggregate, entry,
        // and carrier values; under this schema version every slot is
        // length-prefixed and filled - there are no empty optional slots left
        // in the encoding.
        let backfill = GrantIdentityKey::system(
            TenantScope::new(7, Some(11)).unwrap(),
            "BACKFILL",
            "backfill-2026",
            "approval-request-9",
            "carrier-binding-1",
        )
        .unwrap()
        .canonicalized()
        .unwrap();
        assert_eq!(backfill.source_kind, GrantSourceKind::System);
        assert_eq!(backfill.binding_layer, BindingLayer::None);
        let backfill_text = backfill.canonical_text().unwrap();
        assert!(backfill_text.contains("8:BACKFILL"));
        assert!(backfill_text.ends_with("17:carrier-binding-1"));

        // Byte-length prefixes keep component boundaries unambiguous even when
        // naive concatenation would collapse onto the same bytes.
        let alpha = GrantIdentityKey::system(
            TenantScope::new(7, Some(11)).unwrap(),
            "ab",
            "cx",
            "e1",
            "b1",
        )
        .unwrap();
        let beta = GrantIdentityKey::system(
            TenantScope::new(7, Some(11)).unwrap(),
            "abc",
            "x",
            "e1",
            "b1",
        )
        .unwrap();
        assert_ne!(
            alpha.derive_grant_id().unwrap(),
            beta.derive_grant_id().unwrap()
        );
    }

    #[test]
    fn identity_component_validation_fails_closed() {
        for bad in ["", "   ", "\u{1F}", "a\nb", "a b", "a\tb"] {
            let error = GrantIdentityKey::new(
                TenantScope::new(7, Some(11)).unwrap(),
                GrantSourceKind::Direct,
                BindingLayer::None,
                bad,
                "agg",
                "card-entry-1",
                "card-scope",
            )
            .unwrap_err();
            assert!(
                matches!(
                    error,
                    GrantContractError::EmptyIdentifier { .. }
                        | GrantContractError::MalformedIdentifier { .. }
                ),
                "unexpected error for {bad:?}: {error}"
            );
        }

        // Identifier length boundary: 512 accepted, 513 rejected.
        let long_ok = "a".repeat(512);
        assert!(GrantIdentityKey::new(
            TenantScope::new(7, Some(11)).unwrap(),
            GrantSourceKind::Direct,
            BindingLayer::None,
            "AGGREGATE",
            &long_ok,
            "card-entry-1",
            "card-scope",
        )
        .is_ok());
        let long_bad = "a".repeat(513);
        assert!(matches!(
            GrantIdentityKey::new(
                TenantScope::new(7, Some(11)).unwrap(),
                GrantSourceKind::Direct,
                BindingLayer::None,
                "AGGREGATE",
                &long_bad,
                "card-entry-1",
                "card-scope",
            )
            .unwrap_err(),
            GrantContractError::IdentifierTooLong { .. }
        ));

        // Numeric tenant scope bounds stay strictly positive.
        let mut zero_tenant = identity_key();
        zero_tenant.tenant = TenantScope {
            tenant_id: 0,
            domain_id: None,
        };
        assert!(matches!(
            zero_tenant.validate(),
            Err(GrantContractError::NonPositiveId {
                field: "tenant_id",
                ..
            })
        ));

        let mut negative_domain = identity_key();
        negative_domain.tenant = TenantScope {
            tenant_id: 7,
            domain_id: Some(-1),
        };
        assert!(matches!(
            negative_domain.validate(),
            Err(GrantContractError::NonPositiveId {
                field: "domain_id",
                ..
            })
        ));

        // Any schema version other than the contract constant fails closed.
        for stale_version in [0u32, GRANT_IDENTITY_KEY_SCHEMA_VERSION + 1] {
            let mut stale = identity_key();
            stale.schema_version = stale_version;
            assert!(matches!(
                stale.validate(),
                Err(GrantContractError::IdentitySchemaVersionMismatch { .. })
            ));
        }

        // Source kind / binding layer combinations always pass through the
        // canonical alignment rule.
        let mut wrong_rule_set_layer = identity_key();
        wrong_rule_set_layer.binding_layer = BindingLayer::None;
        assert!(matches!(
            wrong_rule_set_layer.validate(),
            Err(GrantContractError::SourceLayerMismatch { .. })
        ));

        let mut wrong_direct_layer = identity_key();
        wrong_direct_layer.source_kind = GrantSourceKind::Direct;
        assert!(matches!(
            wrong_direct_layer.validate(),
            Err(GrantContractError::SourceLayerMismatch { .. })
        ));

        let mut wrong_delegation_layer = identity_key();
        wrong_delegation_layer.source_kind = GrantSourceKind::Delegation;
        wrong_delegation_layer.binding_layer = BindingLayer::Base;
        assert!(matches!(
            wrong_delegation_layer.validate(),
            Err(GrantContractError::SourceLayerMismatch { .. })
        ));

        // Missing, empty, or blank entry/binding scopes never fall back to
        // weaker shared identities: mandatory components are enforced at both
        // the typed-field level and inside every convenience constructor.
        assert!(matches!(
            GrantIdentityKey::rule_set(tenant(), BindingLayer::Overlay, "rs-1", "", "uc-1")
                .unwrap_err(),
            GrantContractError::EmptyIdentifier {
                field: "identity.source_entry"
            }
        ));
        assert!(matches!(
            GrantIdentityKey::direct(tenant(), "card-binding-1", "   ").unwrap_err(),
            GrantContractError::EmptyIdentifier {
                field: "identity.source_entry"
            }
        ));
        assert!(matches!(
            GrantIdentityKey::delegation(tenant(), "delegation-7", "").unwrap_err(),
            GrantContractError::EmptyIdentifier {
                field: "identity.source_entry"
            }
        ));
        assert!(matches!(
            GrantIdentityKey::approval(tenant(), "approval-9", "line-1", "").unwrap_err(),
            GrantContractError::EmptyIdentifier {
                field: "identity.binding_key"
            }
        ));
        assert!(matches!(
            GrantIdentityKey::rule_set(tenant(), BindingLayer::Base, "rs-1", "entry-1", " ")
                .unwrap_err(),
            GrantContractError::EmptyIdentifier {
                field: "identity.binding_key"
            }
        ));

        // The same rejections apply when any source kind bypasses its
        // convenience constructor through `new`: each kind is tested across
        // every layer it may legally carry.
        let aligned_layers: &[(GrantSourceKind, &[BindingLayer])] = &[
            (
                GrantSourceKind::RuleSet,
                &[BindingLayer::Base, BindingLayer::Overlay],
            ),
            (GrantSourceKind::Direct, &[BindingLayer::None]),
            (GrantSourceKind::Delegation, &[BindingLayer::None]),
            (GrantSourceKind::Approval, &[BindingLayer::None]),
            (GrantSourceKind::System, &[BindingLayer::None]),
        ];
        for (kind, layers) in aligned_layers {
            for layer in layers.iter().copied() {
                let missing_entry = GrantIdentityKey::new(
                    tenant(),
                    *kind,
                    layer,
                    "admin_aggregate",
                    "agg-1",
                    "",
                    "carrier-1",
                )
                .unwrap_err();
                assert!(
                    matches!(
                        missing_entry,
                        GrantContractError::EmptyIdentifier { .. }
                            | GrantContractError::MalformedIdentifier { .. }
                    ),
                    "unexpected error for {kind:?}/{layer:?} missing entry"
                );
                let missing_scope = GrantIdentityKey::new(
                    tenant(),
                    *kind,
                    layer,
                    "admin_aggregate",
                    "agg-1",
                    "entry-1",
                    "",
                )
                .unwrap_err();
                assert!(
                    matches!(
                        missing_scope,
                        GrantContractError::EmptyIdentifier { .. }
                            | GrantContractError::MalformedIdentifier { .. }
                    ),
                    "unexpected error for {kind:?}/{layer:?} missing binding"
                );
            }
        }
    }

    #[test]
    fn nil_uuid_is_never_a_valid_grant_identity() {
        assert!(GrantId::new(Uuid::nil()).is_err());
        assert!(GrantId::parse("00000000-0000-0000-0000-000000000000").is_err());
        let derived = identity_key().derive_grant_id().unwrap();
        assert!(!derived.as_uuid().is_nil());
    }

    #[test]
    fn grant_identity_namespace_is_pinned() {
        assert_eq!(
            grant_identity_namespace().to_string(),
            "a3d13f7e-8c41-4b2a-9e15-6f70d4a51b32"
        );
    }

    /// Golden fixture：批量删除共享 operation id 下的单条 REMOVE 贡献身份。
    /// canonical text 的字节序列与 UUIDv5 结果都钉死（golden 由独立的
    /// RFC4122 实现离线计算并复核），任何字段布局漂移都会被立刻发现。
    #[test]
    fn delta_event_identity_has_pinned_golden_encoding_and_uuid() {
        let identity = DeltaEventIdentity {
            operation_id: "permission-rule:remove-by-card:29",
            tenant_id: 7,
            aggregate_type: "USER_CARD",
            aggregate_id: 21,
            source_entry: "5077",
            mutation_kind: "remove",
        };
        let expected_text = "ASTRAL_DELTA_EVENT_IDENTITY\u{1F}V1\
             \u{1F}33:permission-rule:remove-by-card:29\
             \u{1F}7\
             \u{1F}9:USER_CARD\
             \u{1F}21\
             \u{1F}4:5077\
             \u{1F}6:remove";
        assert_eq!(identity.canonical_text().unwrap(), expected_text);
        assert_eq!(
            identity.derive_event_id().unwrap(),
            "0e88bcb4-08e4-5707-87d3-7bb8842a903e"
        );
        // 重试同一 (operation, tenant, aggregate, entry, kind) 必须得到相同 id。
        assert_eq!(
            identity.derive_event_id().unwrap(),
            identity.derive_event_id().unwrap()
        );
    }

    /// 每个 identity 维度都必须改变派生结果；输出恒为 36 字符小写
    /// hyphenated UUID，且永不与同维度 grant identity 混淆（域分离 header）。
    #[test]
    fn delta_event_ids_vary_per_dimension_and_never_equal_grant_ids() {
        let base = DeltaEventIdentity {
            operation_id: "req-batch-1",
            tenant_id: 7,
            aggregate_type: "USER_CARD",
            aggregate_id: 21,
            source_entry: "77",
            mutation_kind: "remove",
        };
        let base_id = base.derive_event_id().unwrap();

        for (label, mutated) in [
            (
                "operation",
                DeltaEventIdentity {
                    operation_id: "req-batch-2",
                    ..base.clone()
                },
            ),
            (
                "tenant",
                DeltaEventIdentity {
                    tenant_id: 8,
                    ..base.clone()
                },
            ),
            (
                "aggregate type",
                DeltaEventIdentity {
                    aggregate_type: "APPROVAL",
                    ..base.clone()
                },
            ),
            (
                "aggregate id",
                DeltaEventIdentity {
                    aggregate_id: 22,
                    ..base.clone()
                },
            ),
            (
                "source entry",
                DeltaEventIdentity {
                    source_entry: "78",
                    ..base.clone()
                },
            ),
            (
                "mutation kind",
                DeltaEventIdentity {
                    mutation_kind: "update",
                    ..base.clone()
                },
            ),
        ] {
            let other = mutated.derive_event_id().unwrap();
            assert_ne!(base_id, other, "{label} must change the derived event id");
            assert_eq!(other.len(), 36, "event id must stay a bare UUID string");
            assert!(
                other
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() || byte == b'-'),
                "event id must be lowercase hyphenated UUID: {other}"
            );
        }

        // 与对齐维度的 grant identity 永不相等：不同固定 header 域分离。
        let aligned_grant =
            GrantIdentityKey::direct(TenantScope::new(7, None).unwrap(), "21", "77")
                .unwrap()
                .derive_grant_id()
                .unwrap();
        assert_ne!(
            GrantId::parse(&base_id).unwrap().as_uuid(),
            aligned_grant.as_uuid()
        );
    }

    /// 非法输入一律 fail-closed：空/空白/控制字符文本与非正数数值域。
    #[test]
    fn delta_event_identity_validation_fails_closed_on_malformed_input() {
        fn assert_rejected(label: &str, identity: DeltaEventIdentity<'_>) {
            match identity.derive_event_id() {
                Err(error) => assert!(
                    matches!(
                        error,
                        GrantContractError::EmptyIdentifier { .. }
                            | GrantContractError::MalformedIdentifier { .. }
                            | GrantContractError::NonPositiveId { .. }
                            | GrantContractError::IdentifierTooLong { .. }
                    ),
                    "malformed {label} must fail closed with a shape error, got {error:?}"
                ),
                Ok(event_id) => panic!("malformed {label} must fail closed, got {event_id}"),
            }
        }
        let base = || DeltaEventIdentity {
            operation_id: "op-1",
            tenant_id: 7,
            aggregate_type: "USER_CARD",
            aggregate_id: 21,
            source_entry: "77",
            mutation_kind: "remove",
        };

        // 合法基线必须成功。
        assert!(base().derive_event_id().is_ok());

        // 空 / 空白 / 控制字符 / 超长文本全部拒绝。
        for (label, identity) in [
            (
                "empty operation",
                DeltaEventIdentity {
                    operation_id: "",
                    ..base()
                },
            ),
            (
                "blank operation",
                DeltaEventIdentity {
                    operation_id: " ",
                    ..base()
                },
            ),
            (
                "control char kind",
                DeltaEventIdentity {
                    mutation_kind: "rem\u{7F}ove",
                    ..base()
                },
            ),
            (
                "newline entry",
                DeltaEventIdentity {
                    source_entry: "a\nb",
                    ..base()
                },
            ),
        ] {
            assert_rejected(label, identity);
        }

        // 超过标识符上限的文本同样 fail-closed（保持绑定的局部字符串）。
        let oversized_entry = "x".repeat(600);
        assert_rejected(
            "oversized source entry",
            DeltaEventIdentity {
                source_entry: &oversized_entry,
                ..base()
            },
        );

        // 非正数值域拒绝。
        assert_rejected(
            "zero tenant",
            DeltaEventIdentity {
                tenant_id: 0,
                ..base()
            },
        );
        assert_rejected(
            "negative aggregate id",
            DeltaEventIdentity {
                aggregate_id: -1,
                ..base()
            },
        );
    }

    #[test]
    fn identity_key_serde_roundtrip_preserves_derivation() {
        let key = identity_key().canonicalized().unwrap();
        let encoded = serde_json::to_string(&key).unwrap();
        assert!(encoded.contains("\"schemaVersion\""));
        assert!(encoded.contains("\"aggregateType\""));
        assert!(encoded.contains("\"sourceEntry\""));
        assert!(!encoded.contains("null"));
        let decoded: GrantIdentityKey = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, key);
        assert_eq!(
            decoded.derive_grant_id().unwrap(),
            key.derive_grant_id().unwrap()
        );
    }

    #[test]
    fn every_source_kind_maps_to_its_binding_layer_matrix() {
        let tenant = TenantScope::new(7, Some(11)).unwrap();

        // The complete closed source/layer matrix: RULE_SET owns BASE/OVERLAY,
        // everything else is exactly NONE. Asserted exhaustively against an
        // independent test oracle so a future drift cannot reintroduce
        // layer-as-source-kind semantics.
        let expected_alignment = |kind, layer| {
            matches!(
                (kind, layer),
                (GrantSourceKind::RuleSet, BindingLayer::Base)
                    | (GrantSourceKind::RuleSet, BindingLayer::Overlay)
                    | (GrantSourceKind::Direct, BindingLayer::None)
                    | (GrantSourceKind::Delegation, BindingLayer::None)
                    | (GrantSourceKind::Approval, BindingLayer::None)
                    | (GrantSourceKind::System, BindingLayer::None)
            )
        };
        for kind in [
            GrantSourceKind::RuleSet,
            GrantSourceKind::Direct,
            GrantSourceKind::Delegation,
            GrantSourceKind::Approval,
            GrantSourceKind::System,
        ] {
            for layer in [
                BindingLayer::Base,
                BindingLayer::Overlay,
                BindingLayer::None,
            ] {
                assert_eq!(
                    source_kind_aligns_with_binding_layer(kind, layer),
                    expected_alignment(kind, layer),
                    "unexpected alignment for {kind:?}/{layer:?}"
                );
            }
        }

        // RULE_SET: BASE/OVERLAY only; entry and binding are always mandatory.
        for layer in [BindingLayer::Base, BindingLayer::Overlay] {
            let key = GrantIdentityKey::rule_set(tenant.clone(), layer, "rs-1", "entry-1", "uc-1")
                .unwrap();
            assert_eq!(key.source_kind, GrantSourceKind::RuleSet);
            assert_eq!(key.binding_layer, layer);
            assert!(key.validate().is_ok());
        }
        assert!(GrantIdentityKey::rule_set(
            tenant.clone(),
            BindingLayer::None,
            "rs-1",
            "entry-1",
            "uc-1"
        )
        .is_err());

        // DIRECT: NONE only, and the card binding scope is carried in both
        // the aggregate id and binding scope while each permission entry is
        // the contribution identity.
        let direct = GrantIdentityKey::direct(tenant.clone(), "ub-9", "rule-42").unwrap();
        assert_eq!(direct.source_kind, GrantSourceKind::Direct);
        assert_eq!(direct.binding_layer, BindingLayer::None);
        assert_eq!(direct.binding_key, direct.aggregate_id);
        assert!(direct.validate().is_ok());

        // DELEGATION: NONE only; the chain scope is carried in both the
        // aggregate id and binding scope while each clause is the entry.
        let delegation = GrantIdentityKey::delegation(tenant.clone(), "del-7", "clause-1").unwrap();
        assert_eq!(delegation.source_kind, GrantSourceKind::Delegation);
        assert_eq!(delegation.binding_layer, BindingLayer::None);
        assert_eq!(delegation.binding_key, delegation.aggregate_id);
        assert!(delegation.validate().is_ok());

        // APPROVAL / SYSTEM: NONE only with explicit carrier scopes.
        let approval = GrantIdentityKey::approval(
            tenant.clone(),
            "approval-12",
            "request-line-1",
            "user-card-21",
        )
        .unwrap();
        assert_eq!(approval.source_kind, GrantSourceKind::Approval);
        assert_eq!(approval.binding_layer, BindingLayer::None);
        assert_ne!(approval.aggregate_id, approval.binding_key);
        assert!(approval.validate().is_ok());

        let system =
            GrantIdentityKey::system(tenant.clone(), "BACKFILL", "bf-1", "record-4", "uc-33")
                .unwrap();
        assert_eq!(system.source_kind, GrantSourceKind::System);
        assert_eq!(system.binding_layer, BindingLayer::None);
        assert!(system.validate().is_ok());

        // A cross-scope change of tenant or domain forks the identity even for
        // an otherwise identical stable entry + binding pair.
        let same_entry = identity_key();
        let other_tenant = GrantIdentityKey {
            tenant: TenantScope::new(8, Some(11)).unwrap(),
            ..same_entry.clone()
        };
        let no_domain = GrantIdentityKey {
            tenant: TenantScope::new(7, None).unwrap(),
            ..same_entry
        };
        let base_id = identity_key().derive_grant_id().unwrap();
        assert_ne!(other_tenant.derive_grant_id().unwrap(), base_id);
        assert_ne!(no_domain.derive_grant_id().unwrap(), base_id);
    }

    #[test]
    fn same_scope_contributions_of_different_kinds_never_share_one_identity() {
        // Identical aggregate type/id, entry, tenant, and carrier scope - only
        // the source family differs. Identity must still fork per source kind
        // so a DIRECT, DELEGATION, APPROVAL, and SYSTEM contribution under one
        // scope stay independently mutable records.
        let tenant = TenantScope::new(7, Some(11)).unwrap();
        let kinds = [
            GrantSourceKind::Direct,
            GrantSourceKind::Delegation,
            GrantSourceKind::Approval,
            GrantSourceKind::System,
        ];
        let keys: Vec<_> = kinds
            .iter()
            .map(|kind| {
                GrantIdentityKey::new(
                    tenant.clone(),
                    *kind,
                    BindingLayer::None,
                    "USER_CARD",
                    "carrier-9",
                    "entry-1",
                    "carrier-9",
                )
                .unwrap()
            })
            .collect();
        for left in &keys {
            assert!(left.validate().is_ok());
        }
        for (index, left) in keys.iter().enumerate() {
            for right in keys.iter().skip(index + 1) {
                assert_ne!(
                    left.derive_grant_id().unwrap(),
                    right.derive_grant_id().unwrap()
                );
            }
        }

        // The fork also holds at the CanonicalGrant boundary through the
        // canonical hash, not just the identity key.
        let grant_for = |kind: GrantSourceKind| CanonicalGrant {
            grant_id: GrantId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            revision: GrantRevision::initial(),
            state: GrantState::Active,
            source_kind: kind,
            binding_layer: BindingLayer::None,
            tenant: tenant.clone(),
            card_id: 17,
            user_id: 42,
            resource: "learn_subject".to_owned(),
            action: "read".to_owned(),
            effect: GrantEffect::Allow,
            validity: ValidityWindow::perpetual(),
            provenance: GrantProvenance {
                source_id: format!("source-{kind:?}"),
                source_entry: Some("entry-1".to_owned()),
                binding_id: None,
                delegation_id: (kind == GrantSourceKind::Delegation)
                    .then(|| "delegation-shared".to_owned()),
                operation_id: "op-shared".to_owned(),
                event_id: Some("event-shared".to_owned()),
                actor_user_id: None,
            },
        };
        let hashes: Vec<_> = kinds
            .iter()
            .map(|kind| grant_for(*kind).canonical_hash().unwrap())
            .collect();
        for (index, left) in hashes.iter().enumerate() {
            for right in hashes.iter().skip(index + 1) {
                assert_ne!(left, right);
            }
        }
    }

    #[test]
    fn derived_ids_match_pinned_golden_uuids() {
        // Golden anchors are RFC 4122 v5 derivations over the pinned namespace
        // a3d13f7e-8c41-4b2a-9e15-6f70d4a51b32 and the exact canonical texts
        // below; any change to namespace, schema version, wire tokens, or
        // encoding breaks these pins loudly instead of silently re-keying
        // durable grants. One anchor per source kind pins the closed matrix.
        let rule_set_text = concat!(
            "ASTRAL_GRANT_IDENTITY\u{1F}V1\u{1F}RULE_SET\u{1F}OVERLAY\u{1F}",
            "7\u{1F}11\u{1F}8:RULE_SET\u{1F}5:rs-42\u{1F}8:entry-17\u{1F}11:user-card-3"
        );
        assert_eq!(identity_key().canonical_text().unwrap(), rule_set_text);
        assert_eq!(
            identity_key().derive_grant_id().unwrap().as_uuid(),
            Uuid::parse_str("df8bbc19-1b19-55d7-a84e-8eb485625d86").unwrap()
        );

        let direct_key = GrantIdentityKey::direct(
            TenantScope::new(7, None).unwrap(),
            "user-card-17",
            "permission-rule-42",
        )
        .unwrap();
        let direct_text = concat!(
            "ASTRAL_GRANT_IDENTITY\u{1F}V1\u{1F}DIRECT\u{1F}NONE\u{1F}",
            "7\u{1F}\u{1F}9:USER_CARD\u{1F}12:user-card-17\u{1F}18:permission-rule-42\u{1F}",
            "12:user-card-17"
        );
        assert_eq!(direct_key.canonical_text().unwrap(), direct_text);
        assert_eq!(
            direct_key.derive_grant_id().unwrap().as_uuid(),
            Uuid::parse_str("e317b374-6001-5977-9de1-007ab4a3a8b1").unwrap()
        );

        let delegation_key =
            GrantIdentityKey::delegation(TenantScope::new(7, None).unwrap(), "del-7", "clause-1")
                .unwrap();
        let delegation_text = concat!(
            "ASTRAL_GRANT_IDENTITY\u{1F}V1\u{1F}DELEGATION\u{1F}NONE\u{1F}",
            "7\u{1F}\u{1F}10:DELEGATION\u{1F}5:del-7\u{1F}8:clause-1\u{1F}5:del-7"
        );
        assert_eq!(delegation_key.canonical_text().unwrap(), delegation_text);
        assert_eq!(
            delegation_key.derive_grant_id().unwrap().as_uuid(),
            Uuid::parse_str("666ae07e-ad49-5d5e-a00a-7c70310a1096").unwrap()
        );

        let approval_key = GrantIdentityKey::approval(
            TenantScope::new(7, None).unwrap(),
            "approval-12",
            "request-line-1",
            "user-card-21",
        )
        .unwrap();
        let approval_text = concat!(
            "ASTRAL_GRANT_IDENTITY\u{1F}V1\u{1F}APPROVAL\u{1F}NONE\u{1F}",
            "7\u{1F}\u{1F}8:APPROVAL\u{1F}11:approval-12\u{1F}14:request-line-1\u{1F}",
            "12:user-card-21"
        );
        assert_eq!(approval_key.canonical_text().unwrap(), approval_text);
        assert_eq!(
            approval_key.derive_grant_id().unwrap().as_uuid(),
            Uuid::parse_str("f08a85f1-6c62-5d6d-987b-bbeb89a2d6fa").unwrap()
        );

        let system_key = GrantIdentityKey::system(
            TenantScope::new(7, None).unwrap(),
            "BACKFILL",
            "backfill-2026",
            "record-4",
            "carrier-binding-1",
        )
        .unwrap();
        let system_text = concat!(
            "ASTRAL_GRANT_IDENTITY\u{1F}V1\u{1F}SYSTEM\u{1F}NONE\u{1F}",
            "7\u{1F}\u{1F}8:BACKFILL\u{1F}13:backfill-2026\u{1F}8:record-4\u{1F}",
            "17:carrier-binding-1"
        );
        assert_eq!(system_key.canonical_text().unwrap(), system_text);
        assert_eq!(
            system_key.derive_grant_id().unwrap().as_uuid(),
            Uuid::parse_str("e1b34feb-df79-545b-8914-9f7655f7b572").unwrap()
        );
    }

    // ── Published card evidence contract purity ────────────────────────────

    #[test]
    fn gate_status_codes_are_stable_and_only_ready_is_usable() {
        assert_eq!(
            PublishedEvidenceGateStatus::Ready.code(),
            "published_card_evidence.ready"
        );
        assert_eq!(
            PublishedEvidenceGateStatus::Pending.code(),
            "published_card_evidence.pending"
        );
        assert_eq!(
            PublishedEvidenceGateStatus::Corrupt.code(),
            "published_card_evidence.corrupt"
        );
        assert!(PublishedEvidenceGateStatus::Ready.is_authorization_usable());
        assert!(!PublishedEvidenceGateStatus::Pending.is_authorization_usable());
        assert!(!PublishedEvidenceGateStatus::Corrupt.is_authorization_usable());
    }

    #[test]
    fn domain_requirement_matches_explicitly() {
        let unconstrained = DomainScopeRequirement::Unconstrained;
        let exact = DomainScopeRequirement::ExactlySome(11);
        let none = DomainScopeRequirement::ExactlyNone;
        assert!(unconstrained.matches(None) && unconstrained.matches(Some(3)));
        assert!(exact.matches(Some(11)));
        assert!(!exact.matches(Some(12)) && !exact.matches(None));
        assert!(none.matches(None));
        assert!(!none.matches(Some(11)));
    }

    #[test]
    fn scope_validation_rejects_non_positive_ids() {
        let mut scope = PublishedCardEvidenceScope {
            tenant_id: 7,
            card_id: 17,
            user_filter: None,
            domain: DomainScopeRequirement::Unconstrained,
        };
        scope.validate().unwrap();
        scope.tenant_id = 0;
        assert!(scope.validate().is_err());
        scope.tenant_id = 7;
        scope.user_filter = Some(-1);
        assert!(scope.validate().is_err());
        scope.user_filter = None;
        scope.domain = DomainScopeRequirement::ExactlySome(0);
        assert!(scope.validate().is_err());
    }

    #[test]
    fn scope_narrows_only_through_the_declared_lens() {
        let mut sample = grant();
        sample.tenant = TenantScope::new(7, Some(11)).unwrap();
        let scope = PublishedCardEvidenceScope {
            tenant_id: 7,
            card_id: 17,
            user_filter: Some(42),
            domain: DomainScopeRequirement::ExactlySome(11),
        };
        assert!(scope.narrows(&sample));

        let other_user = {
            let mut candidate = sample.clone();
            candidate.user_id = 43;
            candidate
        };
        assert!(!scope.narrows(&other_user));
        let other_domain = {
            let mut candidate = sample.clone();
            candidate.tenant.domain_id = Some(12);
            candidate
        };
        assert!(!scope.narrows(&other_domain));
        assert!(PublishedCardEvidenceScope {
            user_filter: None,
            ..scope.clone()
        }
        .narrows(&sample));
    }

    #[test]
    fn card_authorization_validate_locks_gate_counter_agreement() {
        let base_grant = grant();
        let record = VerifiedPublishedGrantRecord {
            aggregate_type: "USER_CARD".to_owned(),
            aggregate_id: 17,
            publication_generation: 4,
            revoke_fence: 1,
            manifest_id: 9,
            event_id: "event-1".to_owned(),
            operation_id: "op-1".to_owned(),
            semantic_hash_hex: "a".repeat(64),
            dependency_hash_hex: "b".repeat(64),
            compiler_version: "phase2-authorization-kernel-v1".to_owned(),
            segment_ordinal: 0,
            position_in_segment: 0,
            grant: base_grant.clone(),
            accepted_into_effective_set: true,
            unaccepted_reason: None,
        };
        let manifest = PublishedAggregateManifestSummary {
            tenant_id: 7,
            card_id: 17,
            aggregate_type: "USER_CARD".to_owned(),
            aggregate_id: 17,
            manifest_id: 9,
            generation: 4,
            source_generation: 4,
            projected_generation: 4,
            revoke_fence: 1,
            cas_version: 1,
            semantic_hash_hex: "a".repeat(64),
            dependency_hash_hex: "b".repeat(64),
            manifest_digest_hex: "c".repeat(64),
            compiler_version: "phase2-authorization-kernel-v1".to_owned(),
            event_id: "event-1".to_owned(),
            operation_id: "op-1".to_owned(),
            parent_manifest_id: None,
            segment_count: 1,
            declared_grant_row_count: 1,
        };
        let authorization = PublishedCardAuthorization {
            tenant_id: 7,
            card_id: 17,
            read_unix_seconds: 100,
            gate: PublishedCardAuthorizationGate {
                status: PublishedEvidenceGateStatus::Ready,
                aggregate_manifest_count: 1,
                verified_record_count: 1,
                effective_grant_count: 1,
                not_in_effective_count: 0,
                equivalent_duplicate_collapsed_count: 0,
            },
            manifests: vec![manifest],
            records: vec![record.clone()],
            effective_grants: vec![base_grant],
        };
        authorization.validate().unwrap();

        // Accepted-with-reason pairing is contractual, not cosmetic.
        assert!(VerifiedPublishedGrantRecord {
            accepted_into_effective_set: false,
            ..record.clone()
        }
        .validate_fields()
        .is_err());

        let counter_drifted = PublishedCardAuthorization {
            gate: PublishedCardAuthorizationGate {
                verified_record_count: 2,
                ..authorization.gate.clone()
            },
            ..authorization.clone()
        };
        assert!(counter_drifted.validate().is_err());
    }

    #[test]
    fn card_authorization_validate_requires_effective_set_to_mirror_accepted_records() {
        let accepted_grant = grant();
        let mut excluded_grant = grant();
        excluded_grant.resource = " learn_course ".to_owned();
        let manifest = PublishedAggregateManifestSummary {
            tenant_id: 7,
            card_id: 17,
            aggregate_type: "USER_CARD".to_owned(),
            aggregate_id: 17,
            manifest_id: 9,
            generation: 4,
            source_generation: 4,
            projected_generation: 4,
            revoke_fence: 1,
            cas_version: 1,
            semantic_hash_hex: "a".repeat(64),
            dependency_hash_hex: "b".repeat(64),
            manifest_digest_hex: "c".repeat(64),
            compiler_version: "phase2-authorization-kernel-v1".to_owned(),
            event_id: "event-1".to_owned(),
            operation_id: "op-1".to_owned(),
            parent_manifest_id: None,
            segment_count: 2,
            declared_grant_row_count: 2,
        };
        let accepted_record = |grant: CanonicalGrant| VerifiedPublishedGrantRecord {
            aggregate_type: "USER_CARD".to_owned(),
            aggregate_id: 17,
            publication_generation: 4,
            revoke_fence: 1,
            manifest_id: 9,
            event_id: "event-1".to_owned(),
            operation_id: "op-1".to_owned(),
            semantic_hash_hex: "a".repeat(64),
            dependency_hash_hex: "b".repeat(64),
            compiler_version: "phase2-authorization-kernel-v1".to_owned(),
            segment_ordinal: 0,
            position_in_segment: 0,
            grant,
            accepted_into_effective_set: true,
            unaccepted_reason: None,
        };
        // 被排除记录被刻意保留：effective 只镜像 accepted 子集是合法形态。
        let authorization = PublishedCardAuthorization {
            tenant_id: 7,
            card_id: 17,
            read_unix_seconds: 100,
            gate: PublishedCardAuthorizationGate {
                status: PublishedEvidenceGateStatus::Ready,
                aggregate_manifest_count: 1,
                verified_record_count: 2,
                effective_grant_count: 1,
                not_in_effective_count: 1,
                equivalent_duplicate_collapsed_count: 0,
            },
            manifests: vec![manifest],
            records: vec![
                accepted_record(accepted_grant.clone()),
                VerifiedPublishedGrantRecord {
                    accepted_into_effective_set: false,
                    unaccepted_reason: Some(UnacceptedGrantReason::Expired),
                    ..accepted_record(excluded_grant.clone())
                },
            ],
            effective_grants: vec![accepted_grant.clone()],
        };
        authorization.validate().unwrap();

        // 内容漂移：effective 条目与 accepted record 的 grant 不一致。
        let mut content_drifted = authorization.clone();
        content_drifted.effective_grants[0] = excluded_grant.clone();
        assert!(content_drifted.validate().is_err());

        // 多余 effective：超出 accepted 子集（计数同步改大也不能通过）。
        let mut extra_effective = authorization.clone();
        extra_effective
            .effective_grants
            .push(excluded_grant.clone());
        extra_effective.gate.effective_grant_count = 2;
        extra_effective.gate.not_in_effective_count = 0;
        assert!(extra_effective.validate().is_err());

        // 缺失 effective：accepted 记录没有对应展开条目。
        let mut missing_effective = authorization.clone();
        missing_effective.effective_grants.clear();
        missing_effective.gate.effective_grant_count = 0;
        assert!(missing_effective.validate().is_err());

        // 计数漂移：not_in_effective_count 与被排除记录数不一致。
        let mut not_in_effective_drifted = authorization.clone();
        not_in_effective_drifted.gate.not_in_effective_count = 0;
        assert!(not_in_effective_drifted.validate().is_err());

        // 有记录却无 manifest：provenance 断裂。
        let mut manifest_less = authorization.clone();
        manifest_less.manifests.clear();
        manifest_less.gate.aggregate_manifest_count = 0;
        assert!(manifest_less.validate().is_err());

        // 顺序漂移：两条 accepted 记录对调时 effective 必须跟随同序。
        let second_grant = excluded_grant;
        let mut reordered = PublishedCardAuthorization {
            records: vec![
                accepted_record(accepted_grant),
                accepted_record(second_grant.clone()),
            ],
            gate: PublishedCardAuthorizationGate {
                status: PublishedEvidenceGateStatus::Ready,
                aggregate_manifest_count: 1,
                verified_record_count: 2,
                effective_grant_count: 2,
                not_in_effective_count: 0,
                equivalent_duplicate_collapsed_count: 0,
            },
            effective_grants: vec![second_grant, grant()],
            ..authorization.clone()
        };
        assert!(reordered.validate().is_err());
        reordered.effective_grants = reordered
            .records
            .iter()
            .map(|record| record.grant.clone())
            .collect();
        reordered.validate().unwrap();
    }

    #[test]
    fn non_ready_gates_never_validate_as_evidence() {
        let authorization = PublishedCardAuthorization {
            tenant_id: 7,
            card_id: 17,
            read_unix_seconds: 1,
            gate: PublishedCardAuthorizationGate {
                status: PublishedEvidenceGateStatus::Pending,
                aggregate_manifest_count: 0,
                verified_record_count: 0,
                effective_grant_count: 0,
                not_in_effective_count: 0,
                equivalent_duplicate_collapsed_count: 0,
            },
            manifests: Vec::new(),
            records: Vec::new(),
            effective_grants: Vec::new(),
        };
        assert!(authorization.validate().is_err());
    }
}
