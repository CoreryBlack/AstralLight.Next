//! Cross-city authorization contract layer (proposal → node evidence → city vote →
//! agreement → 2PC-style states).
//!
//! This module is the pure "contract layer" of the approved cross-city authorization
//! plan. It contains only serde-friendly value types, deterministic canonical digests,
//! and fail-closed validation logic. It performs no I/O and knows nothing about SQL,
//! Redis, MQ, HTTP, projection workers, or the existing grant writers.
//!
//! Cross-city mode is DEFAULT-OFF: nothing in this module is wired into any writer,
//! runtime, projection, or message path, and [`CROSS_CITY_MODE_DEFAULT_ENABLED`] is
//! `false`. Enabling the mode is a separate, auditable decision outside this crate.
//!
//! Trust model and fail-closed rules:
//! - A [`MutationProposal`] pins the operation identity, the exact request/mutation
//!   content digests, the base frontier/generation/fence it was compiled against, the
//!   target generation/fence it claims to produce, and a hard expiry (UTC Unix seconds).
//! - Each city independently re-evaluates the proposal and records a
//!   [`ZeroDecisionEvidence`] whose `decision` is strictly `ALLOW` or `DENY` and
//!   whose signed payload binds the FULL proposal through its `proposal_digest`
//!   field (in addition to the frontier/mutation digests), so one evidence -
//!   including its signature - can never be replayed against a different proposal.
//!   The evidence digest is recomputed on every validation, so any field tampering
//!   is rejected fail-closed.
//! - A [`CityVoteCertificate`] can only be issued from two *distinct* node evidences
//!   of the *same* city, both `ALLOW`, each carrying the exact `proposal_digest` of
//!   the proposal being certified and agreeing on frontier/mutation digests and
//!   expiry, and unexpired at issue time. Evidences are validated exactly as
//!   received - `issue` never canonicalizes or repairs them first - and each must
//!   already be in canonical form, so tampered or whitespace-padded inputs are
//!   rejected instead of silently fixed. There is intentionally no bool-typed
//!   shortcut constructor: `DENY` (or any non-`ALLOW`) evidence can never produce a
//!   vote.
//! - A [`CrossCityAgreementCertificate`] can only be reached from two vote
//!   certificates of two *distinct* cities that agree with the proposal on operation,
//!   frontier, mutation, and expiry. Each vote is validated exactly as received AND
//!   strictly proven canonical (`is_canonical`), so padded spellings of one city can
//!   never inflate the city count. Target generation/revoke fence consistency is
//!   enforced through the exact `proposal_digest` binding (the certificate records the
//!   digest of the whole proposal, so any target-field difference is a strict,
//!   field-named mismatch error).
//! - [`CrossCityOperationState`] is a guarded 2PC-style state machine: illegal
//!   transitions are errors, terminal states never transition again, and `IN_DOUBT`
//!   only resolves to `ACTIVE` (with durable proof) or `QUARANTINED` — an unknown
//!   commit outcome is never discarded as `REJECTED`.
//! - [`CrossCityGateState`] is `BLOCKED` by default. Only `ACTIVE` reports
//!   [`CrossCityGateState::is_authorization_ready`].
//!
//! Authorization boundary: these types never produce an authorization decision and
//! never grant anything by themselves. There is no executor/sword-bearer `ALLOW` in
//! this module. The only authorization entry point remains `PolicyEngine.evaluate()`
//! over the regular fail-closed permission path; a cross-city agreement only permits
//! the coordinator state machine to proceed, and effective authorization still
//! requires the normal projection/read-gate conditions.
//!
//! Canonical digests: every digest is `SHA-256` over a fixed domain-separation header
//! followed by explicit byte-length-prefixed fields (`U+001F` separator, decimal byte
//! length, `:`, value). The encoding never depends on `serde_json` map order, is
//! injective over validated values (identifiers reject whitespace and control
//! characters, including the separator), and always renders as 64 lowercase hex
//! characters. `operation_id` is a canonical lowercase hyphenated UUID; expiry
//! timestamps are UTC Unix seconds; generation/fence values follow the same
//! semantics as the grant contracts (`fence <= generation`, target generation never
//! regresses behind base source generation).
//!
//! Cross-city message delivery contracts (outbox/inbox transport, DEFAULT-OFF
//! like everything else in this module):
//! - [`CrossCityMessagePhase`] is the closed set of message phases (`VOTE`,
//!   `PREPARE`, `ACTIVATE`, `COMMIT_CONFIRMED`, `RECONCILE`). A phase names the
//!   transport/business stage a MESSAGE belongs to; it is a different namespace
//!   from [`CrossCityOperationState`], and a phase value alone must never
//!   advance, infer, or repair the operation state machine.
//! - [`CrossCityDeliveryStatus`] is the closed set of outbox/inbox delivery
//!   statuses. Transitions are split into three separate guarded families -
//!   normal worker, reconcile, and operator requeue - and there is deliberately
//!   no universal transition: an MQ ACK or a bare boolean can never change a
//!   status. `IN_DOUBT` is invisible to the normal worker (unknown outcomes are
//!   never retried in place) and must be resolved only through reconciliation;
//!   `SUCCEEDED` is terminal.
//! - [`CrossCityMessageIdentity`] derives the stable idempotent business id
//!   (`message_id`) of one message from its identity tuple (operation, phase,
//!   source city, destination city). `message_id` is an idempotency key ONLY:
//!   it is not a proof of delivery, not a proof of durable success, and not an
//!   authorization. An MQ ACK is not a durable success - an unknown outcome
//!   must surface as `IN_DOUBT` and be reconciled. The payload bytes and any
//!   signature stay outside the identity.
//! - [`cross_city_payload_digest`] is the raw SHA-256 over the exact published
//!   wire bytes: the one deliberate exception to the domain-separated canonical
//!   encoding above, because the schema `payload_digest` records what was
//!   actually published - never a re-canonicalized JSON form.
//! - The legacy `astral.permission.refresh` path is NOT part of this contract
//!   and must not be routed through these types.
//!
//! Cross-city conflict arbitration audit contract (stage-1, contract-only):
//! - [`CrossCityConflictOutcome`] and [`CrossCityConflictReason`] are the
//!   shared, closed conflict-arbitration enums (`REJECT`/`DEFER`, 15 stable
//!   reason codes with a fixed reason→outcome mapping). They are the canonical
//!   contract types owned here so audit records can bind them; the
//!   policy-engine conflict module re-exports them unchanged for API
//!   compatibility.
//! - [`CrossCityConflictAuditRecord`] is the shared, closed, serde-friendly
//!   evidence shape for one arbitrated conflict. Its `event_id` is a
//!   domain-separated SHA-256 over `(operation_id, proposal_digest, outcome
//!   code, reason code)` under the versioned header
//!   `ASTRAL_CROSS_CITY_CONFLICT_AUDIT_V1` - deliberately excluding the
//!   observed time, so a retried build of the same verdict reuses the same
//!   durable identity. The record copies the canonical proposal fields for
//!   durable correlation, proves them consistent with the bound
//!   `proposal_digest`, validates the reason/outcome pairing, and accepts
//!   EXPIRED proposals (audit must capture stale evidence). There is
//!   deliberately no `tenant_id` field: proposal/certificate inputs carry no
//!   trusted tenant, and tenant binding is a later authenticated boundary.
//! - This is a contract/mapping ONLY: nothing here persists, sends, or reads
//!   anything. A future durable writer must use a NEW append-only idempotent
//!   table keyed by `event_id` - never `audit_log`, `operation.last_error`,
//!   the vote tables, or the outbox - and must not translate an arbiter
//!   `DEFER` into [`CrossCityOperationState::Deferred`] or a `REJECT` into any
//!   state transition in this batch.
//!
//! Deserialization is not trust: every struct can be deserialized from wire/JSON for
//! transport, but callers MUST run `validate`/`validate_at` before relying on any
//! deserialized value; all constructors re-derive every digest fail-closed.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

/// Compile-time marker that the cross-city authorization mode is DEFAULT-OFF.
///
/// Nothing in this module connects to a writer, runtime, projection, or message
/// path. Any future enablement must be an explicit, auditable configuration change
/// outside this crate - never a change to this constant being silently consulted
/// from an authorization path.
pub const CROSS_CITY_MODE_DEFAULT_ENABLED: bool = false;

/// Exactly how many distinct node evidences one city vote requires.
pub const CROSS_CITY_EVIDENCE_COUNT: usize = 2;

/// Exactly how many distinct city votes one cross-city agreement requires.
pub const CROSS_CITY_CITY_COUNT: usize = 2;

/// Validation failures shared by the cross-city contracts.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CrossCityContractError {
    #[error("{field} must not be empty")]
    EmptyIdentifier { field: &'static str },

    #[error("{field} contains whitespace or a control character")]
    MalformedIdentifier { field: &'static str },

    #[error("{field} is too long")]
    IdentifierTooLong { field: &'static str },

    #[error("{field} must be a lowercase 64-character SHA-256 hex digest")]
    InvalidDigest { field: &'static str },

    #[error("{field} must be a canonical lowercase hyphenated UUID")]
    InvalidOperationId { field: &'static str },

    #[error("{field} must not be the nil UUID")]
    NilOperationId { field: &'static str },

    #[error("{field} must be positive, got {value}")]
    NonPositiveNumber { field: &'static str, value: u64 },

    #[error("{field} must be a positive Unix timestamp in seconds, got {value}")]
    InvalidExpiry { field: &'static str, value: i64 },

    #[error("revoke fence {fence} cannot exceed generation {generation}")]
    InvalidFence { generation: u64, fence: u64 },

    #[error(
        "target generation {target_generation} must not regress behind base source generation {base_source_generation}"
    )]
    GenerationRegressed {
        base_source_generation: u64,
        target_generation: u64,
    },

    #[error("{what} expired at Unix second {expires_at} (now {now_seconds})")]
    Expired {
        what: &'static str,
        now_seconds: i64,
        expires_at: i64,
    },

    #[error("{field} does not match the recomputed canonical digest (expected {expected}, got {actual})")]
    DigestMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },

    #[error("{field} is not in canonical form")]
    NonCanonicalForm { field: &'static str },

    #[error("exactly {expected} node evidences are required, got {actual}")]
    EvidenceCountMismatch { expected: usize, actual: usize },

    #[error("exactly {expected} city vote certificates are required, got {actual}")]
    CityVoteCountMismatch { expected: usize, actual: usize },

    #[error("node '{node_id}' provided more than one evidence in city '{city_id}'")]
    DuplicateNode { city_id: String, node_id: String },

    #[error("city '{city_id}' provided more than one vote certificate")]
    DuplicateCity { city_id: String },

    #[error("evidences disagree on city: expected '{expected}', got '{actual}'")]
    CityMismatch { expected: String, actual: String },

    #[error("node '{node_id}' decided {decision}; a city vote certificate requires ALLOW")]
    DecisionNotAllow {
        node_id: String,
        decision: &'static str,
    },

    #[error("{field} mismatch: expected {expected}, got {actual}")]
    FieldMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },

    #[error("illegal state transition from {from} to {to}")]
    InvalidTransition {
        from: &'static str,
        to: &'static str,
    },

    #[error("cross-city gate is not ACTIVE (state {state}); authorization is not ready")]
    GateNotActive { state: &'static str },

    #[error("'{value}' is not a known cross-city message phase (exact wire spelling required)")]
    UnknownMessagePhase { value: String },

    #[error("'{value}' is not a known cross-city delivery status (exact wire spelling required)")]
    UnknownDeliveryStatus { value: String },

    #[error("illegal delivery status transition from {from} to {to} by {actor}")]
    InvalidDeliveryTransition {
        from: &'static str,
        to: &'static str,
        actor: &'static str,
    },

    #[error("source_city_id and destination_city_id must differ (both are '{city_id}')")]
    SelfRoutedMessage { city_id: String },
}

/// Result alias for cross-city contract validation and digest derivation.
pub type CrossCityContractResult<T> = Result<T, CrossCityContractError>;

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Maximum byte length of a normalized identifier (city/node/nonce/version fields).
const IDENTIFIER_MAX_LEN: usize = 512;

/// Maximum byte length of an opaque signature blob.
const SIGNATURE_MAX_LEN: usize = 4096;

/// Unicode General_Category=Cf (format) ranges treated as invisible poison in
/// every normalized identifier (and signature blob). Format characters are
/// neither whitespace nor `control`, survive every trim, render as nothing,
/// and can make two visually identical city/node ids disagree at the byte
/// level (or smuggle bidi/direction overrides). Inclusive `(low, high)` code
/// point ranges, checked without any external dependency; legitimate Unicode
/// letters and digits are NOT in these ranges and stay fully usable.
const FORMAT_CHARACTER_RANGES: [(u32, u32); 21] = [
    (0x00AD, 0x00AD),   // SOFT HYPHEN
    (0x0600, 0x0605),   // Arabic number signs
    (0x061C, 0x061C),   // ARABIC LETTER MARK
    (0x06DD, 0x06DD),   // ARABIC END OF AYAH
    (0x070F, 0x070F),   // SYRIAC ABBREVIATION MARK
    (0x0890, 0x0891),   // Arabic pound/percent signs
    (0x08E2, 0x08E2),   // ARABIC DISPUTED END OF AYAH
    (0x180E, 0x180E),   // MONGOLIAN VOWEL SEPARATOR
    (0x200B, 0x200F),   // ZWSP/ZWNJ/ZWJ/LRM/RLM
    (0x202A, 0x202E),   // bidi embedding and override controls
    (0x2060, 0x2064),   // word joiner and invisible operators
    (0x2066, 0x206F),   // bidi isolates and deprecated formats
    (0xFEFF, 0xFEFF),   // ZERO WIDTH NO-BREAK SPACE (BOM)
    (0xFFF9, 0xFFFB),   // interlinear annotation anchors
    (0x110BD, 0x110BD), // KAITHI NUMBER SIGN
    (0x110CD, 0x110CD), // KAITHI NUMBER SIGN ABOVE
    (0x13430, 0x1343F), // Egyptian hieroglyph format controls
    (0x1BCA0, 0x1BCA3), // shorthand format controls
    (0x1D173, 0x1D17A), // musical format controls
    (0xE0001, 0xE0001), // LANGUAGE TAG
    (0xE0020, 0xE007F), // tag characters
];

/// Whether `character` is one of the invisible Unicode format characters
/// rejected by [`normalize_identifier`] (and [`normalize_signature`]).
fn is_unicode_format_character(character: char) -> bool {
    let code_point = character as u32;
    FORMAT_CHARACTER_RANGES
        .iter()
        .any(|(low, high)| code_point >= *low && code_point <= *high)
}

/// Normalize one identifier (city/node/nonce/version fields): trim, enforce
/// the non-empty/length bounds, refuse whitespace/control characters AND
/// invisible Unicode Cf format characters, and accept every legitimate
/// Unicode letter/digit otherwise.
fn normalize_identifier(value: &str, field: &'static str) -> CrossCityContractResult<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(CrossCityContractError::EmptyIdentifier { field });
    }
    if normalized.len() > IDENTIFIER_MAX_LEN {
        return Err(CrossCityContractError::IdentifierTooLong { field });
    }
    if normalized
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(CrossCityContractError::MalformedIdentifier { field });
    }
    if normalized.chars().any(is_unicode_format_character) {
        return Err(CrossCityContractError::MalformedIdentifier { field });
    }
    Ok(normalized.to_owned())
}

fn normalize_signature(value: &str, field: &'static str) -> CrossCityContractResult<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(CrossCityContractError::EmptyIdentifier { field });
    }
    if normalized.len() > SIGNATURE_MAX_LEN {
        return Err(CrossCityContractError::IdentifierTooLong { field });
    }
    if normalized
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(CrossCityContractError::MalformedIdentifier { field });
    }
    // Same Cf poison rejection as identifiers: format characters are equally
    // invisible inside an opaque signature blob.
    if normalized.chars().any(is_unicode_format_character) {
        return Err(CrossCityContractError::MalformedIdentifier { field });
    }
    Ok(normalized.to_owned())
}

/// A digest must be exactly 64 lowercase hex characters (SHA-256 output form).
fn validate_digest(value: &str, field: &'static str) -> CrossCityContractResult<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(CrossCityContractError::InvalidDigest { field })
    }
}

/// Trim a digest field, then validate its canonical lowercase hex form.
fn normalize_digest(value: &str, field: &'static str) -> CrossCityContractResult<String> {
    let normalized = value.trim();
    validate_digest(normalized, field)?;
    Ok(normalized.to_owned())
}

/// The operation id must be a canonical lowercase hyphenated UUID text form, as
/// produced by `Uuid::to_string`; nil, braced, uppercased, or URN forms fail closed.
fn normalize_operation_id(value: &str, field: &'static str) -> CrossCityContractResult<String> {
    let trimmed = value.trim();
    let uuid = Uuid::parse_str(trimmed)
        .map_err(|_| CrossCityContractError::InvalidOperationId { field })?;
    if uuid.is_nil() {
        return Err(CrossCityContractError::NilOperationId { field });
    }
    if uuid.to_string() != trimmed {
        return Err(CrossCityContractError::InvalidOperationId { field });
    }
    Ok(trimmed.to_owned())
}

fn validate_positive_u64(value: u64, field: &'static str) -> CrossCityContractResult<()> {
    if value == 0 {
        Err(CrossCityContractError::NonPositiveNumber { field, value })
    } else {
        Ok(())
    }
}

fn validate_expiry(value: i64, field: &'static str) -> CrossCityContractResult<()> {
    if value <= 0 {
        Err(CrossCityContractError::InvalidExpiry { field, value })
    } else {
        Ok(())
    }
}

/// A zero fence is the valid initial "no revoke has happened" value; a fence may
/// never outrun the generation that produced it (same semantics as the grant
/// contracts).
fn validate_fence(generation: u64, fence: u64) -> CrossCityContractResult<()> {
    if fence > generation {
        Err(CrossCityContractError::InvalidFence { generation, fence })
    } else {
        Ok(())
    }
}

/// Base and target generation/fence pairs of one proposal: both generations are
/// positive, each fence stays within its generation, and the target never regresses
/// behind the base.
fn validate_generation_pair(
    base_source_generation: u64,
    base_revoke_fence: u64,
    target_generation: u64,
    target_revoke_fence: u64,
) -> CrossCityContractResult<()> {
    validate_positive_u64(base_source_generation, "base_source_generation")?;
    validate_fence(base_source_generation, base_revoke_fence)?;
    validate_positive_u64(target_generation, "target_generation")?;
    validate_fence(target_generation, target_revoke_fence)?;
    if target_generation < base_source_generation {
        return Err(CrossCityContractError::GenerationRegressed {
            base_source_generation,
            target_generation,
        });
    }
    Ok(())
}

fn ensure_not_expired(
    what: &'static str,
    now_seconds: i64,
    expires_at: i64,
) -> CrossCityContractResult<()> {
    // `expires_at` is an exclusive upper bound: the record is valid exactly when
    // `now < expires_at`.
    if now_seconds >= expires_at {
        Err(CrossCityContractError::Expired {
            what,
            now_seconds,
            expires_at,
        })
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Canonical digest encoding (domain-separated, length-delimited)
// ---------------------------------------------------------------------------

/// Field separator of the canonical encoding. Validated values reject every control
/// character (including this byte), and every field additionally carries an explicit
/// UTF-8 byte-length prefix, so field boundaries are always unambiguous.
const FIELD_SEPARATOR: char = '\u{1F}';

/// Domain-separation header of the [`MutationProposal`] digest.
const PROPOSAL_DIGEST_HEADER: &str = "ASTRAL_CROSS_CITY_PROPOSAL_V1";

/// Domain-separation header of the [`ZeroDecisionEvidence`] digest.
const NODE_EVIDENCE_DIGEST_HEADER: &str = "ASTRAL_CROSS_CITY_NODE_EVIDENCE_V1";

/// Domain-separation header of the [`CityVoteCertificate`] digest.
const CITY_VOTE_DIGEST_HEADER: &str = "ASTRAL_CROSS_CITY_CITY_VOTE_V1";

/// Domain-separation header of the [`CrossCityAgreementCertificate`] digest.
const AGREEMENT_DIGEST_HEADER: &str = "ASTRAL_CROSS_CITY_AGREEMENT_V1";

/// Domain-separation header of the [`CrossCityMessageIdentity`] id derivation.
const MESSAGE_IDENTITY_DIGEST_HEADER: &str = "ASTRAL_CROSS_CITY_MESSAGE_IDENTITY_V1";

/// Domain-separation header of the [`CrossCityConflictAuditRecord`] event id.
const CONFLICT_AUDIT_EVENT_ID_DIGEST_HEADER: &str = "ASTRAL_CROSS_CITY_CONFLICT_AUDIT_V1";

/// Append one length-delimited field to the canonical encoding: unit separator,
/// decimal UTF-8 byte length, `:`, then the raw value. Identical to the grant
/// identity encoder so cross-city encodings follow the same proven pattern.
fn push_field(out: &mut String, value: &str) {
    out.push(FIELD_SEPARATOR);
    out.push_str(&value.len().to_string());
    out.push(':');
    out.push_str(value);
}

/// Deterministic canonical digest: the fixed domain header first (so two digest
/// kinds can never collide even over identical field tuples), then every field in a
/// fixed order, length-delimited. The output is always 64 lowercase hex characters.
/// This deliberately does NOT go through `serde_json` - map ordering must never be
/// able to influence a digest.
fn canonical_digest(header: &str, fields: &[&str]) -> String {
    let mut encoded = String::with_capacity(header.len() + 24 * fields.len());
    encoded.push_str(header);
    for field in fields {
        push_field(&mut encoded, field);
    }
    let digest = Sha256::digest(encoded.as_bytes());
    hex::encode(digest)
}

// ---------------------------------------------------------------------------
// MutationProposal
// ---------------------------------------------------------------------------

/// A compiled proposal to apply one authorization mutation across cities.
///
/// The proposal is the single pinned input of the whole cross-city flow: every
/// evidence, vote, and agreement must agree with it on the content digests
/// (`scope_digest`, `request_digest`, `mutation_digest`), the base frontier digest
/// it was compiled against, and the hard expiry. Generation/fence semantics match
/// the grant contracts: generations are positive, `fence <= generation`, and the
/// target generation never regresses behind `base_source_generation`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MutationProposal {
    /// Canonical lowercase hyphenated UUID of the durable cross-city operation.
    pub operation_id: String,
    /// Digest of the authorization scope the mutation applies to.
    pub scope_digest: String,
    /// Digest of the canonical request that triggered the mutation.
    pub request_digest: String,
    /// Digest of the exact mutation payload to be applied.
    pub mutation_digest: String,
    /// Digest of the base frontier the proposal was compiled against.
    pub base_frontier_digest: String,
    /// Source generation the proposal was compiled against (positive).
    pub base_source_generation: u64,
    /// Revoke fence of the base generation (`<= base_source_generation`).
    pub base_revoke_fence: u64,
    /// Generation the proposal claims to produce (`>= base_source_generation`).
    pub target_generation: u64,
    /// Revoke fence the proposal claims to produce (`<= target_generation`).
    pub target_revoke_fence: u64,
    /// Version of the compiler that produced this proposal.
    pub compiler_version: String,
    /// Version of the policy/contract the proposal was compiled under.
    pub policy_version: String,
    /// Exclusive expiry bound in UTC Unix seconds; the proposal is valid exactly
    /// when `now < expires_at`.
    pub expires_at: i64,
}

impl MutationProposal {
    /// Construct and canonicalize a proposal, rejecting every malformed input.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation_id: &str,
        scope_digest: &str,
        request_digest: &str,
        mutation_digest: &str,
        base_frontier_digest: &str,
        base_source_generation: u64,
        base_revoke_fence: u64,
        target_generation: u64,
        target_revoke_fence: u64,
        compiler_version: &str,
        policy_version: &str,
        expires_at: i64,
    ) -> CrossCityContractResult<Self> {
        Self {
            operation_id: operation_id.to_owned(),
            scope_digest: scope_digest.to_owned(),
            request_digest: request_digest.to_owned(),
            mutation_digest: mutation_digest.to_owned(),
            base_frontier_digest: base_frontier_digest.to_owned(),
            base_source_generation,
            base_revoke_fence,
            target_generation,
            target_revoke_fence,
            compiler_version: compiler_version.to_owned(),
            policy_version: policy_version.to_owned(),
            expires_at,
        }
        .canonicalized()
    }

    /// Validate all fields fail-closed without producing a new value.
    pub fn validate(&self) -> CrossCityContractResult<()> {
        normalize_operation_id(&self.operation_id, "operation_id").map(|_| ())?;
        validate_digest(&self.scope_digest, "scope_digest")?;
        validate_digest(&self.request_digest, "request_digest")?;
        validate_digest(&self.mutation_digest, "mutation_digest")?;
        validate_digest(&self.base_frontier_digest, "base_frontier_digest")?;
        validate_generation_pair(
            self.base_source_generation,
            self.base_revoke_fence,
            self.target_generation,
            self.target_revoke_fence,
        )?;
        normalize_identifier(&self.compiler_version, "compiler_version").map(|_| ())?;
        normalize_identifier(&self.policy_version, "policy_version").map(|_| ())?;
        validate_expiry(self.expires_at, "expires_at")?;
        Ok(())
    }

    /// Trim identifier edges and return the stable canonical value.
    pub fn canonicalized(&self) -> CrossCityContractResult<Self> {
        let value = Self {
            operation_id: normalize_operation_id(&self.operation_id, "operation_id")?,
            scope_digest: normalize_digest(&self.scope_digest, "scope_digest")?,
            request_digest: normalize_digest(&self.request_digest, "request_digest")?,
            mutation_digest: normalize_digest(&self.mutation_digest, "mutation_digest")?,
            base_frontier_digest: normalize_digest(
                &self.base_frontier_digest,
                "base_frontier_digest",
            )?,
            base_source_generation: self.base_source_generation,
            base_revoke_fence: self.base_revoke_fence,
            target_generation: self.target_generation,
            target_revoke_fence: self.target_revoke_fence,
            compiler_version: normalize_identifier(&self.compiler_version, "compiler_version")?,
            policy_version: normalize_identifier(&self.policy_version, "policy_version")?,
            expires_at: self.expires_at,
        };
        value.validate()?;
        Ok(value)
    }

    /// Deterministic domain-separated digest of the canonical proposal.
    pub fn proposal_digest(&self) -> CrossCityContractResult<String> {
        let canonical = self.canonicalized()?;
        let base_source_generation = canonical.base_source_generation.to_string();
        let base_revoke_fence = canonical.base_revoke_fence.to_string();
        let target_generation = canonical.target_generation.to_string();
        let target_revoke_fence = canonical.target_revoke_fence.to_string();
        let expires_at = canonical.expires_at.to_string();
        Ok(canonical_digest(
            PROPOSAL_DIGEST_HEADER,
            &[
                canonical.operation_id.as_str(),
                canonical.scope_digest.as_str(),
                canonical.request_digest.as_str(),
                canonical.mutation_digest.as_str(),
                canonical.base_frontier_digest.as_str(),
                base_source_generation.as_str(),
                base_revoke_fence.as_str(),
                target_generation.as_str(),
                target_revoke_fence.as_str(),
                canonical.compiler_version.as_str(),
                canonical.policy_version.as_str(),
                expires_at.as_str(),
            ],
        ))
    }

    /// Whether the proposal has expired at the given UTC Unix second.
    pub fn is_expired_at(&self, now_seconds: i64) -> bool {
        now_seconds >= self.expires_at
    }

    /// Validate and additionally require the proposal to be unexpired at `now`.
    pub fn ensure_valid_at(&self, now_seconds: i64) -> CrossCityContractResult<()> {
        self.validate()?;
        ensure_not_expired("proposal", now_seconds, self.expires_at)
    }
}

// ---------------------------------------------------------------------------
// ZeroDecisionEvidence
// ---------------------------------------------------------------------------

/// The closed set of decisions one city node may record for a proposal.
///
/// `DENY` is a valid, auditable decision value - but only `ALLOW` can ever
/// contribute to a [`CityVoteCertificate`]. There is deliberately no third
/// "abstain/unknown" variant: an unavailable node simply produces no evidence, and
/// missing evidence can never be promoted into a vote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NodeDecision {
    Allow,
    Deny,
}

impl NodeDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::Deny => "DENY",
        }
    }
}

/// One city node's independently signed zero-decision over a proposal.
///
/// `evidence_digest` is not a free-form field: it is the deterministic canonical
/// digest of the signed payload (`city_id`, `node_id`, `node_epoch`, `decision`,
/// `proposal_digest`, `frontier_digest`, `mutation_digest`, `nonce`, `expires_at`)
/// and is recomputed on every validation, so any tampering with the payload (or the
/// digest itself) is rejected fail-closed.
///
/// The signed payload binds the FULL proposal through `proposal_digest`: the
/// digest of the complete canonical [`MutationProposal`] this node decided over.
/// One evidence - including its signature - can therefore never be replayed
/// against a different proposal, not even one that agrees on frontier/mutation
/// digests. [`CityVoteCertificate::issue`] enforces that every evidence's
/// `proposal_digest` equals the digest of the exact proposal being certified.
///
/// `signature` is an opaque node signature over `evidence_digest`; cryptographic
/// signature verification belongs to a transport layer and is intentionally out of
/// scope for this pure contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZeroDecisionEvidence {
    pub city_id: String,
    pub node_id: String,
    /// Positive epoch of the node software/state that produced the decision.
    pub node_epoch: u64,
    pub decision: NodeDecision,
    /// Digest of the complete canonical [`MutationProposal`] this node decided
    /// over; part of the signed payload, so evidence cannot be replayed across
    /// proposals. [`CityVoteCertificate::issue`] requires it to equal the digest
    /// of the exact proposal being certified.
    pub proposal_digest: String,
    /// Frontier digest the node evaluated against (must match the proposal's base
    /// frontier digest when the evidence contributes to a city vote).
    pub frontier_digest: String,
    /// Mutation digest the node evaluated (must match the proposal's mutation
    /// digest when the evidence contributes to a city vote).
    pub mutation_digest: String,
    /// Canonical digest over the signed payload; recomputed on every validation.
    pub evidence_digest: String,
    /// Non-replaying per-evidence nonce.
    pub nonce: String,
    /// Exclusive expiry bound in UTC Unix seconds.
    pub expires_at: i64,
    /// Opaque node signature over `evidence_digest`.
    pub signature: String,
}

impl ZeroDecisionEvidence {
    /// Construct a self-consistent evidence: fields are validated and the
    /// `evidence_digest` is derived from the canonical signed payload, which
    /// includes `proposal_digest`. The `proposal_digest` argument must be the
    /// canonical digest of the exact proposal this node decided over (as produced
    /// by [`MutationProposal::proposal_digest`]); the binding against the proposal
    /// itself is enforced fail-closed by [`CityVoteCertificate::issue`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        city_id: &str,
        node_id: &str,
        node_epoch: u64,
        decision: NodeDecision,
        proposal_digest: &str,
        frontier_digest: &str,
        mutation_digest: &str,
        nonce: &str,
        expires_at: i64,
        signature: &str,
    ) -> CrossCityContractResult<Self> {
        let partial = Self {
            city_id: normalize_identifier(city_id, "city_id")?,
            node_id: normalize_identifier(node_id, "node_id")?,
            node_epoch,
            decision,
            proposal_digest: normalize_digest(proposal_digest, "proposal_digest")?,
            frontier_digest: normalize_digest(frontier_digest, "frontier_digest")?,
            mutation_digest: normalize_digest(mutation_digest, "mutation_digest")?,
            evidence_digest: String::new(),
            nonce: normalize_identifier(nonce, "nonce")?,
            expires_at,
            signature: normalize_signature(signature, "signature")?,
        };
        let value = Self {
            evidence_digest: partial.compute_digest(),
            ..partial
        };
        value.validate()?;
        Ok(value)
    }

    /// Canonical digest over the signed payload (everything except
    /// `evidence_digest` and `signature`; the signature covers this digest, so it
    /// must stay outside it). The payload binds the full proposal through
    /// `proposal_digest`, so one evidence can never be replayed against a
    /// different proposal.
    fn compute_digest(&self) -> String {
        let node_epoch = self.node_epoch.to_string();
        let expires_at = self.expires_at.to_string();
        canonical_digest(
            NODE_EVIDENCE_DIGEST_HEADER,
            &[
                self.city_id.as_str(),
                self.node_id.as_str(),
                node_epoch.as_str(),
                self.decision.as_str(),
                self.proposal_digest.as_str(),
                self.frontier_digest.as_str(),
                self.mutation_digest.as_str(),
                self.nonce.as_str(),
                expires_at.as_str(),
            ],
        )
    }

    /// Validate every field fail-closed (empty, malformed, non-positive, and
    /// unknown-decision inputs are impossible to represent through the enum, and
    /// digest re-derivation catches any tampering - including tampering with the
    /// bound `proposal_digest`).
    pub fn validate(&self) -> CrossCityContractResult<()> {
        normalize_identifier(&self.city_id, "city_id").map(|_| ())?;
        normalize_identifier(&self.node_id, "node_id").map(|_| ())?;
        validate_positive_u64(self.node_epoch, "node_epoch")?;
        normalize_digest(&self.proposal_digest, "proposal_digest").map(|_| ())?;
        normalize_digest(&self.frontier_digest, "frontier_digest").map(|_| ())?;
        normalize_digest(&self.mutation_digest, "mutation_digest").map(|_| ())?;
        normalize_identifier(&self.nonce, "nonce").map(|_| ())?;
        validate_expiry(self.expires_at, "expires_at")?;
        normalize_signature(&self.signature, "signature").map(|_| ())?;
        let recomputed = self.compute_digest();
        if recomputed != self.evidence_digest {
            return Err(CrossCityContractError::DigestMismatch {
                field: "evidence_digest",
                expected: recomputed,
                actual: self.evidence_digest.clone(),
            });
        }
        Ok(())
    }

    /// Validate and additionally require the evidence to be unexpired at `now`.
    pub fn validate_at(&self, now_seconds: i64) -> CrossCityContractResult<()> {
        self.validate()?;
        ensure_not_expired("node_evidence", now_seconds, self.expires_at)
    }

    /// Whether the evidence has expired at the given UTC Unix second.
    pub fn is_expired_at(&self, now_seconds: i64) -> bool {
        now_seconds >= self.expires_at
    }

    /// Trim identifier edges and re-derive the canonical evidence (including a
    /// freshly computed `evidence_digest`).
    pub fn canonicalized(&self) -> CrossCityContractResult<Self> {
        Self::new(
            &self.city_id,
            &self.node_id,
            self.node_epoch,
            self.decision,
            &self.proposal_digest,
            &self.frontier_digest,
            &self.mutation_digest,
            &self.nonce,
            self.expires_at,
            &self.signature,
        )
    }
}

// ---------------------------------------------------------------------------
// CityVoteCertificate
// ---------------------------------------------------------------------------

/// The per-node attestation recorded inside a [`CityVoteCertificate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeAttestation {
    pub node_id: String,
    pub node_epoch: u64,
    /// Digest of the underlying [`ZeroDecisionEvidence`] signed payload.
    pub evidence_digest: String,
    /// Opaque node signature (carried from the evidence).
    pub signature: String,
}

impl NodeAttestation {
    pub fn validate(&self) -> CrossCityContractResult<()> {
        normalize_identifier(&self.node_id, "node_id").map(|_| ())?;
        validate_positive_u64(self.node_epoch, "node_epoch")?;
        validate_digest(&self.evidence_digest, "evidence_digest")?;
        normalize_signature(&self.signature, "signature").map(|_| ())?;
        Ok(())
    }

    /// Strictly rebuild the canonical form: identifiers are trimmed, the evidence
    /// digest is trimmed and re-validated.
    pub fn canonicalized(&self) -> CrossCityContractResult<Self> {
        let value = Self {
            node_id: normalize_identifier(&self.node_id, "node_id")?,
            node_epoch: self.node_epoch,
            evidence_digest: normalize_digest(&self.evidence_digest, "evidence_digest")?,
            signature: normalize_signature(&self.signature, "signature")?,
        };
        value.validate()?;
        Ok(value)
    }
}

/// A city-level certificate that two distinct nodes of one city both decided
/// `ALLOW` over exactly the same proposal content.
///
/// There is intentionally no free-form constructor: the only entry point is
/// [`CityVoteCertificate::issue`], which re-validates both evidences fail-closed
/// and rejects duplicate nodes, cross-city evidences, `DENY` decisions, digest or
/// expiry disagreement with the proposal, and expired inputs. `certificate_digest`
/// is recomputed on every validation, so a tampered certificate never validates.
///
/// The two node attestations are stored in canonical ascending `node_id` order;
/// any other ordering is rejected as non-canonical. [`CityVoteCertificate::canonicalized`]
/// is a strict rebuild (not a validating clone) and [`CityVoteCertificate::is_canonical`]
/// proves the original equals its own rebuild, so a self-consistent but padded or
/// otherwise normalizable serialization is always detectable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CityVoteCertificate {
    /// Copied from the proposal; every vote of one operation shares it.
    pub operation_id: String,
    /// The single city both evidences came from.
    pub city_id: String,
    /// Digest of the whole proposal this vote certifies.
    pub proposal_digest: String,
    /// Copied from the proposal's base frontier digest.
    pub frontier_digest: String,
    /// Copied from the proposal's mutation digest.
    pub mutation_digest: String,
    /// Exactly two attestations, canonically sorted by `node_id`.
    pub nodes: Vec<NodeAttestation>,
    /// Canonical digest over the certificate content; recomputed on validation.
    pub certificate_digest: String,
    /// Exclusive expiry bound in UTC Unix seconds (inherited from the proposal).
    pub expires_at: i64,
}

impl CityVoteCertificate {
    /// Issue a city vote certificate from exactly two node evidences.
    ///
    /// Fail-closed requirements:
    /// - the proposal is valid and unexpired at `now_seconds`;
    /// - exactly [`CROSS_CITY_EVIDENCE_COUNT`] evidences are supplied;
    /// - every evidence is validated EXACTLY AS RECEIVED: `issue` never
    ///   canonicalizes or repairs inputs before validation, so any tampering with
    ///   a field or the stored `evidence_digest` surfaces directly as a
    ///   `DigestMismatch`, and a self-consistent but non-canonical (e.g.
    ///   whitespace-padded) evidence is rejected as `NonCanonicalForm` instead of
    ///   being silently fixed;
    /// - both evidences come from the same city and distinct nodes;
    /// - both decisions are `ALLOW`;
    /// - every evidence's `proposal_digest` equals the digest of the exact
    ///   canonical proposal being certified (full-proposal binding, so evidence -
    ///   including its signature - cannot be replayed across proposals), and both
    ///   evidences agree with the proposal on `frontier_digest`, `mutation_digest`,
    ///   and `expires_at`.
    ///
    /// The stored [`NodeAttestation`] values are taken from the original,
    /// as-received evidences (whose canonical form has just been proven); each
    /// `evidence_digest` transitively binds the full proposal through the signed
    /// `proposal_digest` payload.
    pub fn issue(
        proposal: &MutationProposal,
        evidences: &[ZeroDecisionEvidence],
        now_seconds: i64,
    ) -> CrossCityContractResult<Self> {
        if evidences.len() != CROSS_CITY_EVIDENCE_COUNT {
            return Err(CrossCityContractError::EvidenceCountMismatch {
                expected: CROSS_CITY_EVIDENCE_COUNT,
                actual: evidences.len(),
            });
        }
        let canonical_proposal = proposal.canonicalized()?;
        canonical_proposal.ensure_valid_at(now_seconds)?;
        let proposal_digest = canonical_proposal.proposal_digest()?;
        for evidence in evidences {
            // As-received validation: catches field-format violations, expiry,
            // and any field/digest tampering directly on the original values.
            evidence.validate_at(now_seconds)?;
            // Canonical-form proof: a self-consistent but padded/normalized
            // input must not be silently repaired into a different value.
            if evidence.canonicalized()? != *evidence {
                return Err(CrossCityContractError::NonCanonicalForm {
                    field: "node_evidences",
                });
            }
            if evidence.decision != NodeDecision::Allow {
                return Err(CrossCityContractError::DecisionNotAllow {
                    node_id: evidence.node_id.clone(),
                    decision: evidence.decision.as_str(),
                });
            }
            // Full-proposal binding: the evidence's signed payload must certify
            // the exact proposal being voted on.
            if evidence.proposal_digest != proposal_digest {
                return Err(CrossCityContractError::FieldMismatch {
                    field: "proposal_digest",
                    expected: proposal_digest.clone(),
                    actual: evidence.proposal_digest.clone(),
                });
            }
            if evidence.frontier_digest != canonical_proposal.base_frontier_digest {
                return Err(CrossCityContractError::FieldMismatch {
                    field: "frontier_digest",
                    expected: canonical_proposal.base_frontier_digest.clone(),
                    actual: evidence.frontier_digest.clone(),
                });
            }
            if evidence.mutation_digest != canonical_proposal.mutation_digest {
                return Err(CrossCityContractError::FieldMismatch {
                    field: "mutation_digest",
                    expected: canonical_proposal.mutation_digest.clone(),
                    actual: evidence.mutation_digest.clone(),
                });
            }
            if evidence.expires_at != canonical_proposal.expires_at {
                return Err(CrossCityContractError::FieldMismatch {
                    field: "expires_at",
                    expected: canonical_proposal.expires_at.to_string(),
                    actual: evidence.expires_at.to_string(),
                });
            }
        }
        let first = &evidences[0];
        let second = &evidences[1];
        if first.city_id != second.city_id {
            return Err(CrossCityContractError::CityMismatch {
                expected: first.city_id.clone(),
                actual: second.city_id.clone(),
            });
        }
        if first.node_id == second.node_id {
            return Err(CrossCityContractError::DuplicateNode {
                city_id: first.city_id.clone(),
                node_id: first.node_id.clone(),
            });
        }
        let mut nodes: Vec<NodeAttestation> = evidences
            .iter()
            .map(|evidence| NodeAttestation {
                node_id: evidence.node_id.clone(),
                node_epoch: evidence.node_epoch,
                evidence_digest: evidence.evidence_digest.clone(),
                signature: evidence.signature.clone(),
            })
            .collect();
        nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        let certificate = Self {
            operation_id: canonical_proposal.operation_id.clone(),
            city_id: first.city_id.clone(),
            proposal_digest,
            frontier_digest: canonical_proposal.base_frontier_digest.clone(),
            mutation_digest: canonical_proposal.mutation_digest.clone(),
            nodes,
            certificate_digest: String::new(),
            expires_at: canonical_proposal.expires_at,
        };
        let value = Self {
            certificate_digest: certificate.compute_digest(),
            ..certificate
        };
        value.validate()?;
        Ok(value)
    }

    /// Canonical digest over the certificate content (everything except
    /// `certificate_digest` itself). Nodes are hashed in stored order; the
    /// canonical ascending order is enforced by `validate`, so exactly one
    /// serialization of one certificate can ever produce this digest.
    fn compute_digest(&self) -> String {
        let expires_at = self.expires_at.to_string();
        let mut fields: Vec<String> = vec![
            self.operation_id.clone(),
            self.city_id.clone(),
            self.proposal_digest.clone(),
            self.frontier_digest.clone(),
            self.mutation_digest.clone(),
        ];
        for node in &self.nodes {
            fields.push(node.node_id.clone());
            fields.push(node.node_epoch.to_string());
            fields.push(node.evidence_digest.clone());
            fields.push(node.signature.clone());
        }
        fields.push(expires_at);
        let field_refs: Vec<&str> = fields.iter().map(String::as_str).collect();
        canonical_digest(CITY_VOTE_DIGEST_HEADER, &field_refs)
    }

    /// Validate the certificate fail-closed. This proves internal integrity of the
    /// certificate only; the underlying evidences are not stored here, so callers
    /// that need the full audit trail must retain them separately.
    pub fn validate(&self) -> CrossCityContractResult<()> {
        normalize_operation_id(&self.operation_id, "operation_id").map(|_| ())?;
        normalize_identifier(&self.city_id, "city_id").map(|_| ())?;
        validate_digest(&self.proposal_digest, "proposal_digest")?;
        validate_digest(&self.frontier_digest, "frontier_digest")?;
        validate_digest(&self.mutation_digest, "mutation_digest")?;
        validate_expiry(self.expires_at, "expires_at")?;
        if self.nodes.len() != CROSS_CITY_EVIDENCE_COUNT {
            return Err(CrossCityContractError::EvidenceCountMismatch {
                expected: CROSS_CITY_EVIDENCE_COUNT,
                actual: self.nodes.len(),
            });
        }
        let mut previous_node_id: Option<&str> = None;
        for node in &self.nodes {
            node.validate()?;
            if let Some(previous) = previous_node_id {
                if node.node_id == previous {
                    return Err(CrossCityContractError::DuplicateNode {
                        city_id: self.city_id.clone(),
                        node_id: node.node_id.clone(),
                    });
                }
                if node.node_id.as_str() < previous {
                    return Err(CrossCityContractError::NonCanonicalForm { field: "nodes" });
                }
            }
            previous_node_id = Some(node.node_id.as_str());
        }
        let recomputed = self.compute_digest();
        if recomputed != self.certificate_digest {
            return Err(CrossCityContractError::DigestMismatch {
                field: "certificate_digest",
                expected: recomputed,
                actual: self.certificate_digest.clone(),
            });
        }
        Ok(())
    }

    /// Validate and additionally require the certificate to be unexpired at `now`.
    pub fn validate_at(&self, now_seconds: i64) -> CrossCityContractResult<()> {
        self.validate()?;
        ensure_not_expired("city_vote_certificate", now_seconds, self.expires_at)
    }

    /// Whether the certificate has expired at the given UTC Unix second.
    pub fn is_expired_at(&self, now_seconds: i64) -> bool {
        now_seconds >= self.expires_at
    }

    /// Strictly rebuild the canonical form of this certificate: identifiers and
    /// digests are trimmed and re-validated, node attestations are rebuilt and
    /// re-sorted, and `certificate_digest` is re-derived over the rebuilt values.
    ///
    /// The original is canonical exactly when the rebuild equals it; a
    /// self-consistent but padded/normalizable certificate (e.g. a whitespace
    /// padded `city_id` whose stored digest was derived over the padded payload)
    /// rebuilds to a DIFFERENT value, which is how [`CityVoteCertificate::is_canonical`]
    /// detects it.
    pub fn canonicalized(&self) -> CrossCityContractResult<Self> {
        let mut nodes = self
            .nodes
            .iter()
            .map(NodeAttestation::canonicalized)
            .collect::<CrossCityContractResult<Vec<_>>>()?;
        nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        let partial = Self {
            operation_id: normalize_operation_id(&self.operation_id, "operation_id")?,
            city_id: normalize_identifier(&self.city_id, "city_id")?,
            proposal_digest: normalize_digest(&self.proposal_digest, "proposal_digest")?,
            frontier_digest: normalize_digest(&self.frontier_digest, "frontier_digest")?,
            mutation_digest: normalize_digest(&self.mutation_digest, "mutation_digest")?,
            nodes,
            certificate_digest: String::new(),
            expires_at: self.expires_at,
        };
        let value = Self {
            certificate_digest: partial.compute_digest(),
            ..partial
        };
        value.validate()?;
        Ok(value)
    }

    /// Whether this certificate is exactly its own canonical rebuild: already
    /// trimmed, canonically ordered, and digested over exactly these values.
    pub fn is_canonical(&self) -> bool {
        self.canonicalized()
            .map(|canonical| canonical == *self)
            .unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// CrossCityAgreementCertificate
// ---------------------------------------------------------------------------

/// The per-city summary recorded inside a [`CrossCityAgreementCertificate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CityVoteSummary {
    pub city_id: String,
    /// Digest of the underlying [`CityVoteCertificate`].
    pub certificate_digest: String,
}

impl CityVoteSummary {
    pub fn validate(&self) -> CrossCityContractResult<()> {
        normalize_identifier(&self.city_id, "city_id").map(|_| ())?;
        validate_digest(&self.certificate_digest, "certificate_digest")?;
        Ok(())
    }

    /// Strictly rebuild the canonical form: the city id is trimmed and the
    /// certificate digest is trimmed and re-validated.
    pub fn canonicalized(&self) -> CrossCityContractResult<Self> {
        let value = Self {
            city_id: normalize_identifier(&self.city_id, "city_id")?,
            certificate_digest: normalize_digest(&self.certificate_digest, "certificate_digest")?,
        };
        value.validate()?;
        Ok(value)
    }
}

/// The cross-city agreement that two distinct cities both certified the same
/// proposal through valid, unexpired city vote certificates.
///
/// The only entry point is [`CrossCityAgreementCertificate::reach`]; every
/// disagreement with the proposal (operation, frontier, mutation, expiry, or - via
/// the exact `proposal_digest` binding - target generation/revoke fence) is a
/// strict, field-named mismatch error. City votes are stored in canonical
/// ascending `city_id` order; any other ordering is rejected as non-canonical.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CrossCityAgreementCertificate {
    /// Copied from the proposal; every vote and the agreement share it.
    pub operation_id: String,
    /// Digest of the whole proposal both cities certified.
    pub proposal_digest: String,
    /// Copied from the proposal's base frontier digest.
    pub frontier_digest: String,
    /// Copied from the proposal's mutation digest.
    pub mutation_digest: String,
    /// Copied from the proposal's target generation.
    pub target_generation: u64,
    /// Copied from the proposal's target revoke fence.
    pub target_revoke_fence: u64,
    /// Exactly two city vote summaries, canonically sorted by `city_id`.
    pub city_votes: Vec<CityVoteSummary>,
    /// Canonical digest over the agreement content; recomputed on validation.
    pub agreement_digest: String,
    /// Exclusive expiry bound in UTC Unix seconds (inherited from the proposal).
    pub expires_at: i64,
}

impl CrossCityAgreementCertificate {
    /// Reach a cross-city agreement from exactly two city vote certificates.
    ///
    /// Fail-closed requirements:
    /// - the proposal is valid and unexpired at `now_seconds`;
    /// - exactly [`CROSS_CITY_CITY_COUNT`] votes are supplied;
    /// - every vote is validated EXACTLY AS RECEIVED (its `certificate_digest` is
    ///   re-derived over the stored values, so any tampering with the digest or
    ///   with operation/city/proposal/frontier/mutation/expiry fields surfaces
    ///   directly as a `DigestMismatch`) and then strictly proven canonical via
    ///   [`CityVoteCertificate::is_canonical`]: a self-consistent but padded or
    ///   otherwise normalizable vote is rejected as `NonCanonicalForm` instead of
    ///   being silently repaired, and two spellings of one city can therefore
    ///   never count as two cities;
    /// - the votes come from two distinct cities;
    /// - every vote agrees with the proposal on `operation_id`, `frontier_digest`,
    ///   `mutation_digest`, and `expires_at`;
    /// - every vote certifies exactly this proposal through its `proposal_digest`,
    ///   which transitively pins the proposal's target generation, target revoke
    ///   fence, and every other pinned field.
    pub fn reach(
        proposal: &MutationProposal,
        votes: &[CityVoteCertificate],
        now_seconds: i64,
    ) -> CrossCityContractResult<Self> {
        if votes.len() != CROSS_CITY_CITY_COUNT {
            return Err(CrossCityContractError::CityVoteCountMismatch {
                expected: CROSS_CITY_CITY_COUNT,
                actual: votes.len(),
            });
        }
        let canonical_proposal = proposal.canonicalized()?;
        canonical_proposal.ensure_valid_at(now_seconds)?;
        for vote in votes {
            // As-received validation: field format, expiry, and any digest/field
            // tampering are judged directly on the original values.
            vote.validate_at(now_seconds)?;
            // Strict canonical-form proof: a self-consistent but padded or
            // otherwise normalizable vote must not be silently repaired, so two
            // spellings of one city can never count as two cities.
            if !vote.is_canonical() {
                return Err(CrossCityContractError::NonCanonicalForm {
                    field: "city_votes",
                });
            }
        }
        if votes[0].city_id == votes[1].city_id {
            return Err(CrossCityContractError::DuplicateCity {
                city_id: votes[0].city_id.clone(),
            });
        }
        let proposal_digest = canonical_proposal.proposal_digest()?;
        for vote in votes {
            if vote.operation_id != canonical_proposal.operation_id {
                return Err(CrossCityContractError::FieldMismatch {
                    field: "operation_id",
                    expected: canonical_proposal.operation_id.clone(),
                    actual: vote.operation_id.clone(),
                });
            }
            if vote.frontier_digest != canonical_proposal.base_frontier_digest {
                return Err(CrossCityContractError::FieldMismatch {
                    field: "frontier_digest",
                    expected: canonical_proposal.base_frontier_digest.clone(),
                    actual: vote.frontier_digest.clone(),
                });
            }
            if vote.mutation_digest != canonical_proposal.mutation_digest {
                return Err(CrossCityContractError::FieldMismatch {
                    field: "mutation_digest",
                    expected: canonical_proposal.mutation_digest.clone(),
                    actual: vote.mutation_digest.clone(),
                });
            }
            if vote.expires_at != canonical_proposal.expires_at {
                return Err(CrossCityContractError::FieldMismatch {
                    field: "expires_at",
                    expected: canonical_proposal.expires_at.to_string(),
                    actual: vote.expires_at.to_string(),
                });
            }
            if vote.proposal_digest != proposal_digest {
                return Err(CrossCityContractError::FieldMismatch {
                    field: "proposal_digest",
                    expected: proposal_digest.clone(),
                    actual: vote.proposal_digest.clone(),
                });
            }
        }
        let mut city_votes: Vec<CityVoteSummary> = votes
            .iter()
            .map(|vote| CityVoteSummary {
                city_id: vote.city_id.clone(),
                certificate_digest: vote.certificate_digest.clone(),
            })
            .collect();
        city_votes.sort_by(|left, right| left.city_id.cmp(&right.city_id));
        let agreement = Self {
            operation_id: canonical_proposal.operation_id.clone(),
            proposal_digest,
            frontier_digest: canonical_proposal.base_frontier_digest.clone(),
            mutation_digest: canonical_proposal.mutation_digest.clone(),
            target_generation: canonical_proposal.target_generation,
            target_revoke_fence: canonical_proposal.target_revoke_fence,
            city_votes,
            agreement_digest: String::new(),
            expires_at: canonical_proposal.expires_at,
        };
        let value = Self {
            agreement_digest: agreement.compute_digest(),
            ..agreement
        };
        value.validate()?;
        Ok(value)
    }

    /// Canonical digest over the agreement content (everything except
    /// `agreement_digest` itself), hashed in stored order; the canonical ascending
    /// city order is enforced by `validate`.
    fn compute_digest(&self) -> String {
        let target_generation = self.target_generation.to_string();
        let target_revoke_fence = self.target_revoke_fence.to_string();
        let expires_at = self.expires_at.to_string();
        let mut fields: Vec<String> = vec![
            self.operation_id.clone(),
            self.proposal_digest.clone(),
            self.frontier_digest.clone(),
            self.mutation_digest.clone(),
            target_generation,
            target_revoke_fence,
        ];
        for vote in &self.city_votes {
            fields.push(vote.city_id.clone());
            fields.push(vote.certificate_digest.clone());
        }
        fields.push(expires_at);
        let field_refs: Vec<&str> = fields.iter().map(String::as_str).collect();
        canonical_digest(AGREEMENT_DIGEST_HEADER, &field_refs)
    }

    /// Validate the agreement fail-closed. This proves internal integrity of the
    /// agreement record; callers must retain the underlying city vote certificates
    /// for the full audit trail.
    pub fn validate(&self) -> CrossCityContractResult<()> {
        normalize_operation_id(&self.operation_id, "operation_id").map(|_| ())?;
        validate_digest(&self.proposal_digest, "proposal_digest")?;
        validate_digest(&self.frontier_digest, "frontier_digest")?;
        validate_digest(&self.mutation_digest, "mutation_digest")?;
        validate_positive_u64(self.target_generation, "target_generation")?;
        validate_fence(self.target_generation, self.target_revoke_fence)?;
        validate_expiry(self.expires_at, "expires_at")?;
        if self.city_votes.len() != CROSS_CITY_CITY_COUNT {
            return Err(CrossCityContractError::CityVoteCountMismatch {
                expected: CROSS_CITY_CITY_COUNT,
                actual: self.city_votes.len(),
            });
        }
        let mut previous_city_id: Option<&str> = None;
        for vote in &self.city_votes {
            vote.validate()?;
            if let Some(previous) = previous_city_id {
                if vote.city_id == previous {
                    return Err(CrossCityContractError::DuplicateCity {
                        city_id: vote.city_id.clone(),
                    });
                }
                if vote.city_id.as_str() < previous {
                    return Err(CrossCityContractError::NonCanonicalForm {
                        field: "city_votes",
                    });
                }
            }
            previous_city_id = Some(vote.city_id.as_str());
        }
        let recomputed = self.compute_digest();
        if recomputed != self.agreement_digest {
            return Err(CrossCityContractError::DigestMismatch {
                field: "agreement_digest",
                expected: recomputed,
                actual: self.agreement_digest.clone(),
            });
        }
        Ok(())
    }

    /// Validate and additionally require the agreement to be unexpired at `now`.
    pub fn validate_at(&self, now_seconds: i64) -> CrossCityContractResult<()> {
        self.validate()?;
        ensure_not_expired("cross_city_agreement", now_seconds, self.expires_at)
    }

    /// Whether the agreement has expired at the given UTC Unix second.
    pub fn is_expired_at(&self, now_seconds: i64) -> bool {
        now_seconds >= self.expires_at
    }

    /// Strictly rebuild the canonical form of this agreement: identifiers and
    /// digests are trimmed and re-validated, city vote summaries are rebuilt and
    /// re-sorted, and `agreement_digest` is re-derived over the rebuilt values.
    /// The original is canonical exactly when the rebuild equals it (see
    /// [`CrossCityAgreementCertificate::is_canonical`]).
    pub fn canonicalized(&self) -> CrossCityContractResult<Self> {
        let mut city_votes = self
            .city_votes
            .iter()
            .map(CityVoteSummary::canonicalized)
            .collect::<CrossCityContractResult<Vec<_>>>()?;
        city_votes.sort_by(|left, right| left.city_id.cmp(&right.city_id));
        let partial = Self {
            operation_id: normalize_operation_id(&self.operation_id, "operation_id")?,
            proposal_digest: normalize_digest(&self.proposal_digest, "proposal_digest")?,
            frontier_digest: normalize_digest(&self.frontier_digest, "frontier_digest")?,
            mutation_digest: normalize_digest(&self.mutation_digest, "mutation_digest")?,
            target_generation: self.target_generation,
            target_revoke_fence: self.target_revoke_fence,
            city_votes,
            agreement_digest: String::new(),
            expires_at: self.expires_at,
        };
        let value = Self {
            agreement_digest: partial.compute_digest(),
            ..partial
        };
        value.validate()?;
        Ok(value)
    }

    /// Whether this agreement is exactly its own canonical rebuild: already
    /// trimmed, canonically ordered, and digested over exactly these values.
    pub fn is_canonical(&self) -> bool {
        self.canonicalized()
            .map(|canonical| canonical == *self)
            .unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// Cross-city conflict arbitration outcome, reason, and audit record
// ---------------------------------------------------------------------------

/// The closed authority of the cross-city conflict operator.
///
/// Exactly two variants exist, and neither is an approval: `REJECT` records a
/// definite, machine-provable conflict; `DEFER` records that no definite conflict
/// is provable right now (the operation stays pending and fail-closed). This type
/// is deliberately NOT `policy_engine::ArbitrationVerdict` (which contains
/// `Allow`) and must never be widened to carry an allow variant: approving
/// cross-city operations is out of this component's authority forever.
///
/// This is the shared contract type, owned here in `astral-types` so audit
/// records can bind it; the policy-engine conflict module re-exports it
/// unchanged for API compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CrossCityConflictOutcome {
    /// A definite, known conflict between the proposal and the city votes.
    Reject,
    /// No definite conflict is provable from the given evidence; fail closed.
    Defer,
}

impl CrossCityConflictOutcome {
    /// Stable, secret-free machine code for audit/metrics pipelines.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reject => "REJECT",
            Self::Defer => "DEFER",
        }
    }
}

impl fmt::Display for CrossCityConflictOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Closed set of stable, machine-readable reason codes for the conflict verdict.
///
/// Every variant binds to exactly one outcome via [`Self::outcome`], so a reason
/// code can never be paired with the wrong verdict. Codes are static text with no
/// embedded caller input, suitable for audit records and metrics labels.
///
/// This is the shared contract type, owned here in `astral-types` so audit
/// records can bind it; the policy-engine conflict module re-exports it
/// unchanged for API compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CrossCityConflictReason {
    /// No city vote certificate was supplied. → `DEFER`
    EvidenceMissing,
    /// The vote count is not exactly the required two. → `DEFER`
    EvidenceCountInvalid,
    /// The proposal or a vote certificate is expired at the caller-supplied time.
    /// → `DEFER`
    EvidenceExpired,
    /// Structural validation could not establish a provable, verifiable state:
    /// malformed proposal, proposal not presentable in canonical form (never
    /// repaired here), or an unknown/unclassifiable contract error. → `DEFER`
    EvidenceUnverifiable,
    /// The pair is structurally consistent, but this component has no authority to
    /// approve: approval belongs exclusively to the cross-city agreement path.
    /// → `DEFER`
    ArbiterAllowOutOfScope,
    /// A vote's `operation_id` disagrees with the proposal. → `REJECT`
    OperationMismatch,
    /// A vote's `proposal_digest` — which binds the full proposal content
    /// (scope, request, generations, versions) — disagrees with the proposal.
    /// → `REJECT`
    ScopeMismatch,
    /// A vote's `frontier_digest` disagrees with the proposal's base frontier
    /// digest. → `REJECT`
    FrontierMismatch,
    /// A vote's `mutation_digest` disagrees with the proposal. → `REJECT`
    MutationMismatch,
    /// A vote's `expires_at` disagrees with the proposal's expiry binding.
    /// → `REJECT`
    ExpiryMismatch,
    /// Recorded decision content conflicts with the vote context. Reserved for
    /// explicit decision disagreement: city vote certificates are allow-only by
    /// construction, so the pure stage cannot produce this code from certificate
    /// input, but the closed set keeps the mapping explicit. → `REJECT`
    DecisionMismatch,
    /// Node identity evidence is invalid, or one node attested twice inside a
    /// vote. → `REJECT`
    NodeIdentityInvalid,
    /// The two votes claim the same city identity. → `REJECT`
    CityIdentityDuplicate,
    /// A vote's opaque signature blob is malformed. Format-only check: real
    /// cryptographic verification is the caller's duty (see the policy-engine
    /// conflict module docs). → `REJECT`
    SignatureInvalid,
    /// A vote certificate fails integrity or canonical-form proof: tampered
    /// digest, non-canonical ordering, or otherwise not a certificate the issuing
    /// contract could have produced. → `REJECT`
    CertificateInvalid,
}

impl CrossCityConflictReason {
    /// Every reason code, in stable order. Used by tests and audit tooling; the
    /// order is part of the stage-1 contract and must not be reordered.
    pub const ALL: [CrossCityConflictReason; 15] = [
        Self::EvidenceMissing,
        Self::EvidenceCountInvalid,
        Self::EvidenceExpired,
        Self::EvidenceUnverifiable,
        Self::ArbiterAllowOutOfScope,
        Self::OperationMismatch,
        Self::ScopeMismatch,
        Self::FrontierMismatch,
        Self::MutationMismatch,
        Self::ExpiryMismatch,
        Self::DecisionMismatch,
        Self::NodeIdentityInvalid,
        Self::CityIdentityDuplicate,
        Self::SignatureInvalid,
        Self::CertificateInvalid,
    ];

    /// Stable, secret-free machine code for audit/metrics pipelines.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EvidenceMissing => "EVIDENCE_MISSING",
            Self::EvidenceCountInvalid => "EVIDENCE_COUNT_INVALID",
            Self::EvidenceExpired => "EVIDENCE_EXPIRED",
            Self::EvidenceUnverifiable => "EVIDENCE_UNVERIFIABLE",
            Self::ArbiterAllowOutOfScope => "ARBITER_ALLOW_OUT_OF_SCOPE",
            Self::OperationMismatch => "OPERATION_MISMATCH",
            Self::ScopeMismatch => "SCOPE_MISMATCH",
            Self::FrontierMismatch => "FRONTIER_MISMATCH",
            Self::MutationMismatch => "MUTATION_MISMATCH",
            Self::ExpiryMismatch => "EXPIRY_MISMATCH",
            Self::DecisionMismatch => "DECISION_MISMATCH",
            Self::NodeIdentityInvalid => "NODE_IDENTITY_INVALID",
            Self::CityIdentityDuplicate => "CITY_IDENTITY_DUPLICATE",
            Self::SignatureInvalid => "SIGNATURE_INVALID",
            Self::CertificateInvalid => "CERTIFICATE_INVALID",
        }
    }

    /// The one outcome this reason can ever produce. This makes the reason→outcome
    /// pairing unfalsifiable: the resolution is always built through this mapping.
    pub const fn outcome(self) -> CrossCityConflictOutcome {
        match self {
            Self::EvidenceMissing
            | Self::EvidenceCountInvalid
            | Self::EvidenceExpired
            | Self::EvidenceUnverifiable
            | Self::ArbiterAllowOutOfScope => CrossCityConflictOutcome::Defer,
            Self::OperationMismatch
            | Self::ScopeMismatch
            | Self::FrontierMismatch
            | Self::MutationMismatch
            | Self::ExpiryMismatch
            | Self::DecisionMismatch
            | Self::NodeIdentityInvalid
            | Self::CityIdentityDuplicate
            | Self::SignatureInvalid
            | Self::CertificateInvalid => CrossCityConflictOutcome::Reject,
        }
    }
}

impl fmt::Display for CrossCityConflictReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Typed, closed failure of building or validating a conflict-audit record.
///
/// Fail-closed by construction: every invalid input (malformed proposal,
/// non-canonical proposal or record fields, pairing violation, non-positive
/// observed time, or a tampered `event_id`) is an error — never a degraded or
/// "best effort" record.
///
/// The wrapped contract error remains available for typed pattern matching, but
/// this error deliberately has a payload-free `Debug`/`Display`/`Error` surface:
/// contract variants can carry caller-controlled identifiers and digest strings,
/// so generic logging must not reproduce them.
#[derive(Clone, PartialEq, Eq)]
pub enum CrossCityConflictAuditError {
    /// The reason code's fixed outcome disagrees with the supplied outcome.
    ReasonOutcomeMismatch {
        reason_code: &'static str,
        expected_outcome: &'static str,
        actual_outcome: &'static str,
    },

    /// The caller-supplied observation time is not a positive UTC Unix second.
    InvalidObservedTime { value: i64 },

    /// The proposal, or the record fields copied from it, failed the shared
    /// cross-city contract validation (structural, canonical-form, or digest
    /// consistency); the source error is retained for typed matching but never
    /// rendered by this wrapper.
    Contract(CrossCityContractError),

    /// The stored `event_id` is not the digest recomputed over the record's own
    /// content: the record was tampered with, or was built by an incompatible
    /// derivation.
    EventIdMismatch { expected: String, actual: String },
}

impl CrossCityConflictAuditError {
    /// Stable, payload-free diagnostic category for safe metrics and logs.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ReasonOutcomeMismatch { .. } => "REASON_OUTCOME_MISMATCH",
            Self::InvalidObservedTime { .. } => "INVALID_OBSERVED_TIME",
            Self::Contract(_) => "CONTRACT_VALIDATION_FAILED",
            Self::EventIdMismatch { .. } => "EVENT_ID_MISMATCH",
        }
    }
}

impl fmt::Debug for CrossCityConflictAuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CrossCityConflictAuditError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for CrossCityConflictAuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for CrossCityConflictAuditError {}

impl From<CrossCityContractError> for CrossCityConflictAuditError {
    fn from(error: CrossCityContractError) -> Self {
        Self::Contract(error)
    }
}

/// Typed, closed audit record for one already-resolved cross-city conflict
/// verdict (contract ONLY — no persistence, no I/O, no runtime caller).
///
/// # What this type is (and is not)
///
/// [`CrossCityConflictAuditRecord`] is the shared, serde-friendly evidence shape
/// for one arbitrated conflict over one [`MutationProposal`]. It is structured
/// and closed: every field is a canonical digest/identifier, a number, or a
/// closed shared enum ([`CrossCityConflictOutcome`]/[`CrossCityConflictReason`]).
/// There is deliberately no free-form reason/detail/message field, so no
/// caller-controlled text enters the record shape, and `Debug`/`Display` render
/// only closed values (the compiler/policy version identifiers are redacted in
/// `Debug` because they are the only free-text fields a proposal carries).
///
/// `event_id` is the durable identity of the record: a domain-separated SHA-256
/// over `(operation_id, proposal_digest, outcome code, reason code)` under the
/// versioned header `ASTRAL_CROSS_CITY_CONFLICT_AUDIT_V1`. The observed time is
/// deliberately EXCLUDED, so rebuilding the record for the same verdict (e.g.
/// across retries) reuses the same identity. `event_id` is an idempotency and
/// correlation key, NOT a signature — it proves internal consistency, never
/// authenticity or authorization. Like every cross-city digest it is recomputed
/// by [`CrossCityConflictAuditRecord::validate`], so any tampering with a bound
/// field or with the stored id fails closed.
///
/// All proposal fields are copied from the canonical proposal and bound to
/// `proposal_digest` (the contract's own full-proposal digest): `validate`
/// reconstructs a [`MutationProposal`] from the copied fields, requires the
/// result to equal the stored field values exactly (canonical form), and requires
/// its digest to equal the stored one, so any copied-field tampering is rejected.
///
/// # Tenant boundary
///
/// There is intentionally no `tenant_id` field: [`MutationProposal`] and the
/// certificate inputs do not carry a trusted tenant identity. Tenant binding is
/// a later, authenticated boundary and must not be improvised into this record.
///
/// # Expiry semantics
///
/// An EXPIRED proposal can still be recorded (audit must capture stale
/// evidence): construction validates the proposal structurally and requires
/// canonical-form equality, but never checks expiry against the observed time.
///
/// # Durable writer boundary (future batch)
///
/// This type is a contract/mapping only — nothing in this crate persists or
/// reads it. The future durable writer MUST use a NEW append-only idempotent
/// table keyed by `event_id`; it must NOT reuse `audit_log`,
/// `operation.last_error`, the vote tables, or the outbox. It must also not
/// translate an arbiter `DEFER` into [`CrossCityOperationState::Deferred`] or a
/// `REJECT` into any state transition: the coordinator state machine keeps its
/// own guarded transitions, and conflict-audit records are evidence, not
/// commands.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CrossCityConflictAuditRecord {
    /// Domain-separated SHA-256 event identity over
    /// `(operation_id, proposal_digest, outcome code, reason code)`; stable
    /// across retries (the observed time is not an input) and recomputed on
    /// every validation.
    pub event_id: String,
    /// Digest of the complete canonical [`MutationProposal`] the verdict was
    /// arbitrated over; binds every copied proposal field below.
    pub proposal_digest: String,
    /// Copied from the proposal: canonical lowercase hyphenated UUID.
    pub operation_id: String,
    /// Copied from the proposal.
    pub scope_digest: String,
    /// Copied from the proposal.
    pub request_digest: String,
    /// Copied from the proposal.
    pub mutation_digest: String,
    /// Copied from the proposal.
    pub base_frontier_digest: String,
    /// Copied from the proposal.
    pub base_source_generation: u64,
    /// Copied from the proposal.
    pub base_revoke_fence: u64,
    /// Copied from the proposal.
    pub target_generation: u64,
    /// Copied from the proposal.
    pub target_revoke_fence: u64,
    /// Copied from the proposal (validated free-text identifier; redacted in
    /// `Debug`).
    pub compiler_version: String,
    /// Copied from the proposal (validated free-text identifier; redacted in
    /// `Debug`).
    pub policy_version: String,
    /// Copied from the proposal: exclusive expiry bound in UTC Unix seconds.
    /// NOT compared against `observed_at_seconds`: expired proposals stay
    /// recordable (audit captures stale evidence).
    pub expires_at: i64,
    /// Closed verdict outcome (`REJECT`/`DEFER` - never an approval).
    pub outcome: CrossCityConflictOutcome,
    /// Closed reason code; its fixed outcome must equal `outcome`.
    pub reason_code: CrossCityConflictReason,
    /// Caller-supplied UTC Unix second at which the verdict was observed;
    /// validated positive, never part of `event_id`.
    pub observed_at_seconds: i64,
}

impl CrossCityConflictAuditRecord {
    /// Build the audit record for one arbitrated conflict over `proposal`.
    ///
    /// Fail-closed requirements:
    /// - `reason_code`'s fixed outcome ([`CrossCityConflictReason::outcome`])
    ///   equals `outcome` — the pairing is checked, never assumed;
    /// - `observed_at_seconds` is a positive UTC Unix second;
    /// - the proposal validates structurally and is EXACTLY its own canonical
    ///   form (never repaired, never substituted);
    /// - the proposal may be EXPIRED: expiry is deliberately not checked, so
    ///   stale evidence stays recordable.
    ///
    /// The canonical proposal fields are copied verbatim, `proposal_digest` is
    /// recomputed from the proposal, and `event_id` is derived over
    /// `(operation_id, proposal_digest, outcome code, reason code)` — the
    /// observed time is not an input, so retries of the same verdict reuse the
    /// same identity.
    pub fn new(
        proposal: &MutationProposal,
        outcome: CrossCityConflictOutcome,
        reason_code: CrossCityConflictReason,
        observed_at_seconds: i64,
    ) -> Result<Self, CrossCityConflictAuditError> {
        ensure_reason_outcome_pair(reason_code, outcome)?;
        if observed_at_seconds <= 0 {
            return Err(CrossCityConflictAuditError::InvalidObservedTime {
                value: observed_at_seconds,
            });
        }
        // Structural validation + canonical-form equality: judged exactly as
        // received, never repaired. Deliberately NO expiry check — audit must
        // be able to capture stale evidence.
        if proposal.canonicalized()? != *proposal {
            return Err(CrossCityContractError::NonCanonicalForm { field: "proposal" }.into());
        }
        let partial = Self {
            event_id: String::new(),
            proposal_digest: proposal.proposal_digest()?,
            operation_id: proposal.operation_id.clone(),
            scope_digest: proposal.scope_digest.clone(),
            request_digest: proposal.request_digest.clone(),
            mutation_digest: proposal.mutation_digest.clone(),
            base_frontier_digest: proposal.base_frontier_digest.clone(),
            base_source_generation: proposal.base_source_generation,
            base_revoke_fence: proposal.base_revoke_fence,
            target_generation: proposal.target_generation,
            target_revoke_fence: proposal.target_revoke_fence,
            compiler_version: proposal.compiler_version.clone(),
            policy_version: proposal.policy_version.clone(),
            expires_at: proposal.expires_at,
            outcome,
            reason_code,
            observed_at_seconds,
        };
        let value = Self {
            event_id: partial.compute_event_id(),
            ..partial
        };
        value.validate()?;
        Ok(value)
    }

    /// The versioned, domain-separated event identity of this record:
    /// `(operation_id, proposal_digest, outcome code, reason code)`. The
    /// observed time is deliberately not an input, so the same verdict always
    /// reuses the same durable identity across retries.
    fn compute_event_id(&self) -> String {
        canonical_digest(
            CONFLICT_AUDIT_EVENT_ID_DIGEST_HEADER,
            &[
                self.operation_id.as_str(),
                self.proposal_digest.as_str(),
                self.outcome.as_str(),
                self.reason_code.as_str(),
            ],
        )
    }

    /// Rebuild the proposal from the copied correlation fields. Structural
    /// validation of every field rides on [`MutationProposal::new`]; the
    /// digest-consistency and canonical-form checks live in
    /// [`CrossCityConflictAuditRecord::validate`].
    fn reconstruct_proposal(&self) -> CrossCityContractResult<MutationProposal> {
        MutationProposal::new(
            &self.operation_id,
            &self.scope_digest,
            &self.request_digest,
            &self.mutation_digest,
            &self.base_frontier_digest,
            self.base_source_generation,
            self.base_revoke_fence,
            self.target_generation,
            self.target_revoke_fence,
            &self.compiler_version,
            &self.policy_version,
            self.expires_at,
        )
    }

    /// Validate the record fail-closed:
    /// 1. every field satisfies the shared cross-city field rules (canonical
    ///    UUID, lowercase hex digests, generation/fence consistency, positive
    ///    expiry, non-empty identifiers, positive observed time);
    /// 2. the reason code's fixed outcome equals the stored outcome;
    /// 3. the copied proposal fields are EXACTLY the canonical values whose
    ///    digest is the stored `proposal_digest` (tampering with any copied
    ///    field, or with the digest, is rejected);
    /// 4. `event_id` equals its recomputation over
    ///    `(operation_id, proposal_digest, outcome code, reason code)`.
    ///
    /// This proves internal consistency only: `event_id` is a correlation/
    /// idempotency identity, not a signature, and carries no authorization.
    pub fn validate(&self) -> Result<(), CrossCityConflictAuditError> {
        normalize_operation_id(&self.operation_id, "operation_id").map(|_| ())?;
        validate_digest(&self.event_id, "event_id")?;
        validate_digest(&self.proposal_digest, "proposal_digest")?;
        validate_digest(&self.scope_digest, "scope_digest")?;
        validate_digest(&self.request_digest, "request_digest")?;
        validate_digest(&self.mutation_digest, "mutation_digest")?;
        validate_digest(&self.base_frontier_digest, "base_frontier_digest")?;
        validate_generation_pair(
            self.base_source_generation,
            self.base_revoke_fence,
            self.target_generation,
            self.target_revoke_fence,
        )?;
        normalize_identifier(&self.compiler_version, "compiler_version").map(|_| ())?;
        normalize_identifier(&self.policy_version, "policy_version").map(|_| ())?;
        validate_expiry(self.expires_at, "expires_at")?;
        if self.observed_at_seconds <= 0 {
            return Err(CrossCityConflictAuditError::InvalidObservedTime {
                value: self.observed_at_seconds,
            });
        }
        ensure_reason_outcome_pair(self.reason_code, self.outcome)?;

        // Copied fields: exactly the canonical proposal content bound by the
        // stored digest — never padded, never normalized into a new value.
        let reconstructed = self.reconstruct_proposal()?;
        let as_stored = MutationProposal {
            operation_id: self.operation_id.clone(),
            scope_digest: self.scope_digest.clone(),
            request_digest: self.request_digest.clone(),
            mutation_digest: self.mutation_digest.clone(),
            base_frontier_digest: self.base_frontier_digest.clone(),
            base_source_generation: self.base_source_generation,
            base_revoke_fence: self.base_revoke_fence,
            target_generation: self.target_generation,
            target_revoke_fence: self.target_revoke_fence,
            compiler_version: self.compiler_version.clone(),
            policy_version: self.policy_version.clone(),
            expires_at: self.expires_at,
        };
        if reconstructed != as_stored {
            return Err(CrossCityContractError::NonCanonicalForm {
                field: "proposal_fields",
            }
            .into());
        }
        let recomputed_proposal_digest = reconstructed.proposal_digest()?;
        if recomputed_proposal_digest != self.proposal_digest {
            return Err(CrossCityContractError::DigestMismatch {
                field: "proposal_digest",
                expected: recomputed_proposal_digest,
                actual: self.proposal_digest.clone(),
            }
            .into());
        }

        let recomputed_event_id = self.compute_event_id();
        if recomputed_event_id != self.event_id {
            return Err(CrossCityConflictAuditError::EventIdMismatch {
                expected: recomputed_event_id,
                actual: self.event_id.clone(),
            });
        }
        Ok(())
    }
}

/// Check the reason→outcome pairing. Shared by construction and validation so
/// the pair can never drift in only one place.
fn ensure_reason_outcome_pair(
    reason_code: CrossCityConflictReason,
    outcome: CrossCityConflictOutcome,
) -> Result<(), CrossCityConflictAuditError> {
    let expected = reason_code.outcome();
    if expected != outcome {
        return Err(CrossCityConflictAuditError::ReasonOutcomeMismatch {
            reason_code: reason_code.as_str(),
            expected_outcome: expected.as_str(),
            actual_outcome: outcome.as_str(),
        });
    }
    Ok(())
}

/// Redacted rendering of a validated free-text identifier: only the byte length
/// is diagnostic-safe; the content itself never enters `Debug` output.
fn redacted_identifier(value: &str) -> String {
    format!("<validated identifier, {} bytes, redacted>", value.len())
}

impl fmt::Debug for CrossCityConflictAuditRecord {
    /// Renders only closed/safe values: canonical digests, the canonical
    /// operation UUID, numbers, and closed enums. The compiler/policy version
    /// identifiers are the record's only free-text fields and are redacted, so
    /// no caller-controlled text can leak into diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CrossCityConflictAuditRecord")
            .field("event_id", &self.event_id)
            .field("proposal_digest", &self.proposal_digest)
            .field("operation_id", &self.operation_id)
            .field("scope_digest", &self.scope_digest)
            .field("request_digest", &self.request_digest)
            .field("mutation_digest", &self.mutation_digest)
            .field("base_frontier_digest", &self.base_frontier_digest)
            .field("base_source_generation", &self.base_source_generation)
            .field("base_revoke_fence", &self.base_revoke_fence)
            .field("target_generation", &self.target_generation)
            .field("target_revoke_fence", &self.target_revoke_fence)
            .field(
                "compiler_version",
                &redacted_identifier(&self.compiler_version),
            )
            .field("policy_version", &redacted_identifier(&self.policy_version))
            .field("expires_at", &self.expires_at)
            .field("outcome", &self.outcome)
            .field("reason_code", &self.reason_code)
            .field("observed_at_seconds", &self.observed_at_seconds)
            .finish()
    }
}

impl fmt::Display for CrossCityConflictAuditRecord {
    /// Machine-readable one-line form: the event identity plus the closed
    /// verdict codes only.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:{}:{}",
            self.event_id,
            self.outcome.as_str(),
            self.reason_code.as_str()
        )
    }
}

// ---------------------------------------------------------------------------
// Coordinator state machine and cross-city gate
// ---------------------------------------------------------------------------

/// Lifecycle state of one cross-city operation in the coordinator.
///
/// The shape follows a 2PC-style flow (`PROPOSED` → `VOTING` → `AGREED` →
/// `PREPARING` → `PREPARED` → `ACTIVATING` → `ACTIVE`) with fail-closed recovery:
/// `DEFERRED` re-enters voting, `IN_DOUBT` only resolves with durable proof
/// (`ACTIVE`) or converges to `QUARANTINED` — never `REJECTED` (a plan-side
/// unknown commit result may only forward-complete on the same operation or be
/// quarantined; it can never be discarded without a durable outcome), and
/// `ACTIVE`/`REJECTED`/`EXPIRED`/`QUARANTINED` are terminal. Transitions are only
/// legal through [`CrossCityOperationState::transition`]; there is no public way to
/// skip states or leave a terminal state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CrossCityOperationState {
    Proposed,
    Voting,
    Agreed,
    Preparing,
    Prepared,
    Activating,
    InDoubt,
    Active,
    Rejected,
    Deferred,
    Quarantined,
    Expired,
}

impl CrossCityOperationState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "PROPOSED",
            Self::Voting => "VOTING",
            Self::Agreed => "AGREED",
            Self::Preparing => "PREPARING",
            Self::Prepared => "PREPARED",
            Self::Activating => "ACTIVATING",
            Self::InDoubt => "IN_DOUBT",
            Self::Active => "ACTIVE",
            Self::Rejected => "REJECTED",
            Self::Deferred => "DEFERRED",
            Self::Quarantined => "QUARANTINED",
            Self::Expired => "EXPIRED",
        }
    }

    /// The closed set of legal successor states. Terminal states have none.
    fn allowed_transitions(self) -> &'static [Self] {
        match self {
            Self::Proposed => &[Self::Voting, Self::Rejected, Self::Expired],
            Self::Voting => &[Self::Agreed, Self::Deferred, Self::Rejected, Self::Expired],
            Self::Deferred => &[Self::Voting, Self::Expired],
            Self::Agreed => &[Self::Preparing, Self::Expired],
            Self::Preparing => &[Self::Prepared, Self::InDoubt, Self::Rejected, Self::Expired],
            Self::Prepared => &[Self::Activating, Self::InDoubt, Self::Expired],
            Self::Activating => &[Self::Active, Self::InDoubt, Self::Quarantined],
            Self::InDoubt => &[Self::Active, Self::Quarantined],
            Self::Active | Self::Rejected | Self::Expired | Self::Quarantined => &[],
        }
    }

    /// Whether `target` is a legal successor of this state.
    pub fn can_transition_to(self, target: Self) -> bool {
        self.allowed_transitions().contains(&target)
    }

    /// Perform a guarded transition, returning the target state or
    /// [`CrossCityContractError::InvalidTransition`] for every illegal move
    /// (including self-transitions and transitions out of terminal states).
    pub fn transition(self, target: Self) -> CrossCityContractResult<Self> {
        if self.can_transition_to(target) {
            Ok(target)
        } else {
            Err(CrossCityContractError::InvalidTransition {
                from: self.as_str(),
                to: target.as_str(),
            })
        }
    }

    /// Whether this state can never transition again.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Rejected | Self::Expired | Self::Quarantined
        )
    }
}

/// Synchronization gate of the cross-city subsystem.
///
/// The default is [`CrossCityGateState::Blocked`]: cross-city mode is default-off
/// and fail-closed. Only [`CrossCityGateState::Active`] reports
/// [`CrossCityGateState::is_authorization_ready`]. Being `ACTIVE` signals that the
/// cross-city synchronization subsystem is ready - it does NOT authorize anything
/// by itself, and there is no executor/sword-bearer `ALLOW` in this module: the
/// only authorization entry point remains `PolicyEngine.evaluate()` over the
/// regular fail-closed permission path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CrossCityGateState {
    Syncing,
    Active,
    Blocked,
}

impl CrossCityGateState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Syncing => "SYNCING",
            Self::Active => "ACTIVE",
            Self::Blocked => "BLOCKED",
        }
    }

    /// Only an `ACTIVE` gate is ready for the cross-city path; every other state
    /// must fail closed.
    pub const fn is_authorization_ready(self) -> bool {
        matches!(self, Self::Active)
    }

    /// Erroring form of [`CrossCityGateState::is_authorization_ready`] so callers
    /// can propagate a typed, observable failure instead of a silent `false`.
    pub fn ensure_authorization_ready(self) -> CrossCityContractResult<()> {
        if self.is_authorization_ready() {
            Ok(())
        } else {
            Err(CrossCityContractError::GateNotActive {
                state: self.as_str(),
            })
        }
    }
}

impl Default for CrossCityGateState {
    /// Fail-closed default: cross-city mode is default-off, so the gate starts
    /// `BLOCKED` until an explicit, auditable enablement moves it.
    fn default() -> Self {
        Self::Blocked
    }
}

// ---------------------------------------------------------------------------
// Cross-city message delivery contracts (phase, delivery status, identity)
// ---------------------------------------------------------------------------

/// The closed set of cross-city message phases (exact wire/DB strings: `VOTE`,
/// `PREPARE`, `ACTIVATE`, `COMMIT_CONFIRMED`, `RECONCILE`).
///
/// A phase is the TRANSPORT/BUSINESS STAGE of one cross-city message. It is
/// deliberately a different namespace from [`CrossCityOperationState`]: the
/// phase says what a message is for, while the operation state belongs to the
/// coordinator state machine. A phase value alone must NEVER be used to
/// advance, infer, or repair a [`CrossCityOperationState`] - operation state
/// changes require their own guarded transitions backed by durable evidence
/// (votes, agreements, durable commit proof), never a message label.
///
/// Serialization uses the exact `SCREAMING_SNAKE_CASE` strings on both the wire
/// (serde) and in the DB; [`CrossCityMessagePhase::parse_str`] is strict, so
/// unknown values and case drift (`"vote"`, `"Vote"`) are rejected fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CrossCityMessagePhase {
    Vote,
    Prepare,
    Activate,
    CommitConfirmed,
    Reconcile,
}

impl CrossCityMessagePhase {
    /// Every phase of the closed set, in canonical (wire/DB) order.
    pub const ALL: [CrossCityMessagePhase; 5] = [
        Self::Vote,
        Self::Prepare,
        Self::Activate,
        Self::CommitConfirmed,
        Self::Reconcile,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Vote => "VOTE",
            Self::Prepare => "PREPARE",
            Self::Activate => "ACTIVATE",
            Self::CommitConfirmed => "COMMIT_CONFIRMED",
            Self::Reconcile => "RECONCILE",
        }
    }

    /// Strictly parse the exact wire/DB spelling. There is no trimming or
    /// case-folding: unknown values and any case drift are rejected fail-closed.
    pub fn parse_str(value: &str) -> CrossCityContractResult<Self> {
        Self::ALL
            .iter()
            .find(|candidate| candidate.as_str() == value)
            .copied()
            .ok_or_else(|| CrossCityContractError::UnknownMessagePhase {
                value: value.to_owned(),
            })
    }
}

/// The closed set of cross-city outbox/inbox delivery statuses (exact wire/DB
/// strings: `PENDING`, `LEASED`, `IN_DOUBT`, `SUCCEEDED`, `QUARANTINED`).
///
/// Status transitions are deliberately split into three separate guarded
/// families so that no single entry point can bypass a responsibility
/// boundary. There is intentionally NO universal transition function: an MQ
/// ACK, a bare boolean, or a caller-supplied "success" flag can never change a
/// status on its own - every change must go through one of these guards:
///
/// - [`CrossCityDeliveryStatus::transition_by_worker`] is the only path of the
///   normal worker: lease a `PENDING` message, release it after a KNOWN failure
///   that is proven to have produced no external result, mark it `IN_DOUBT`
///   when the publish/process outcome is unknown, complete it with
///   durable/confirmed proof, or quarantine it on a deterministic conflict or
///   exhausted budget. A worker can NEVER touch an `IN_DOUBT` message: unknown
///   outcomes are never retried in place.
/// - [`CrossCityDeliveryStatus::transition_by_reconcile`] is the only path out
///   of `IN_DOUBT`: each target requires an independently proven fact (not
///   published / not processed, proven external or durable outcome, or
///   unrecoverable).
/// - [`CrossCityDeliveryStatus::transition_by_operator`] is the operator
///   requeue: a `QUARANTINED` message may only return to `PENDING`.
///
/// Only [`CrossCityDeliveryStatus::Succeeded`] is terminal. `QUARANTINED` is
/// deliberately NOT terminal (the operator requeue is its single recovery
/// path), and `IN_DOUBT` is deliberately NOT terminal (reconciliation is its
/// only resolution path); neither can the normal worker advance them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CrossCityDeliveryStatus {
    Pending,
    Leased,
    InDoubt,
    Succeeded,
    Quarantined,
}

impl CrossCityDeliveryStatus {
    /// Every status of the closed set, in canonical (wire/DB) order.
    pub const ALL: [CrossCityDeliveryStatus; 5] = [
        Self::Pending,
        Self::Leased,
        Self::InDoubt,
        Self::Succeeded,
        Self::Quarantined,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Leased => "LEASED",
            Self::InDoubt => "IN_DOUBT",
            Self::Succeeded => "SUCCEEDED",
            Self::Quarantined => "QUARANTINED",
        }
    }

    /// Strictly parse the exact wire/DB spelling. There is no trimming or
    /// case-folding: unknown values and any case drift are rejected fail-closed.
    pub fn parse_str(value: &str) -> CrossCityContractResult<Self> {
        Self::ALL
            .iter()
            .find(|candidate| candidate.as_str() == value)
            .copied()
            .ok_or_else(|| CrossCityContractError::UnknownDeliveryStatus {
                value: value.to_owned(),
            })
    }

    /// Whether this status can never transition again. Only `SUCCEEDED` is
    /// terminal: delivery is durably proven complete.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded)
    }

    /// Guarded transitions of the normal worker.
    ///
    /// Allowed (anything else is an [`CrossCityContractError::InvalidDeliveryTransition`]):
    /// - `PENDING -> LEASED`: the worker takes exclusive ownership of the message.
    /// - `LEASED -> PENDING`: release after a KNOWN failure already proven to
    ///   have produced no external result (a plain transport error before any
    ///   publish/process happened is the canonical case).
    /// - `LEASED -> IN_DOUBT`: the publish/process outcome is unknown; the
    ///   worker hands the message to reconciliation and gives up ownership.
    /// - `LEASED -> SUCCEEDED`: a durable/confirmed proof of delivery exists.
    /// - `LEASED -> QUARANTINED`: a deterministic conflict (e.g. duplicate
    ///   message id) or an exhausted retry budget.
    ///
    /// Notably absent: every transition out of `IN_DOUBT` (an unknown outcome
    /// is never retried by the normal worker - reconciliation owns it), every
    /// transition out of `SUCCEEDED` (terminal), and every transition out of
    /// `QUARANTINED` (operator requeue owns it).
    pub fn transition_by_worker(self, target: Self) -> CrossCityContractResult<Self> {
        self.guarded_transition(
            target,
            "worker",
            &[
                (Self::Pending, Self::Leased),
                (Self::Leased, Self::Pending),
                (Self::Leased, Self::InDoubt),
                (Self::Leased, Self::Succeeded),
                (Self::Leased, Self::Quarantined),
            ],
        )
    }

    /// Guarded transitions of the reconcile path - the ONLY way out of
    /// `IN_DOUBT`. Every accepted transition represents an independently
    /// proven fact, never a guess or a retry:
    /// - `IN_DOUBT -> PENDING`: reconciliation has independently proven the
    ///   message was NOT published / NOT processed (no external result exists),
    ///   so it safely re-enters the normal worker flow.
    /// - `IN_DOUBT -> SUCCEEDED`: the external/durable outcome has been proven
    ///   (e.g. the destination city durably applied the message).
    /// - `IN_DOUBT -> QUARANTINED`: reconciliation cannot resolve the outcome
    ///   and the message must be held for operator handling.
    ///
    /// Everything else is rejected: reconciliation may never invent worker
    /// transitions (`PENDING`/`LEASED` are the worker's), may never re-lease an
    /// unresolved message, and may never discard an unresolved outcome as
    /// `SUCCEEDED` without proof.
    pub fn transition_by_reconcile(self, target: Self) -> CrossCityContractResult<Self> {
        self.guarded_transition(
            target,
            "reconcile",
            &[
                (Self::InDoubt, Self::Pending),
                (Self::InDoubt, Self::Succeeded),
                (Self::InDoubt, Self::Quarantined),
            ],
        )
    }

    /// Guarded transitions of the operator requeue path: a `QUARANTINED`
    /// message may only return to `PENDING` (fresh worker lease cycle).
    /// Everything else is rejected - operators may never complete, lease, or
    /// doubt a message directly.
    pub fn transition_by_operator(self, target: Self) -> CrossCityContractResult<Self> {
        self.guarded_transition(target, "operator", &[(Self::Quarantined, Self::Pending)])
    }

    /// Shared guard for the actor-specific transition families: `target` is
    /// returned only when `(self, target)` is one of the actor's allowed pairs;
    /// every other pair fails closed with a typed, actor-named error.
    fn guarded_transition(
        self,
        target: Self,
        actor: &'static str,
        allowed: &[(Self, Self)],
    ) -> CrossCityContractResult<Self> {
        if allowed.contains(&(self, target)) {
            Ok(target)
        } else {
            Err(CrossCityContractError::InvalidDeliveryTransition {
                from: self.as_str(),
                to: target.as_str(),
                actor,
            })
        }
    }
}

/// The stable identity of one cross-city message: the idempotent business key
/// of the outbox/inbox path.
///
/// `message_id` is derived - never caller-supplied - from the identity tuple
/// (`operation_id`, `phase`, `source_city_id`, `destination_city_id`) via a
/// domain-separated SHA-256 over the same length-prefix/`U+001F` canonical
/// encoding as every other cross-city digest, using the independent header
/// `ASTRAL_CROSS_CITY_MESSAGE_IDENTITY_V1`. Retrying the exact same tuple
/// reproduces the same `message_id`; changing the phase, the source city, the
/// destination city, or the operation produces a different one.
///
/// Trust boundary of `message_id`: it is an IDEMPOTENCY KEY ONLY. It is not a
/// proof of delivery, not a proof of durable success, not a signature, and not
/// an authorization. An MQ ACK observed for a `message_id` is not a durable
/// success: an unknown outcome must surface as
/// [`CrossCityDeliveryStatus::InDoubt`] and be reconciled. The actual payload
/// bytes and any signature over them stay OUT of the identity; content is
/// described separately by [`cross_city_payload_digest`].
///
/// Like every other digest-bearing contract, `message_id` is recomputed on
/// every [`CrossCityMessageIdentity::validate`], so caller tampering with the
/// stored id (or with any tuple field) is rejected fail-closed; `validate`
/// proves self-consistency, while [`CrossCityMessageIdentity::canonicalized`]
/// and [`CrossCityMessageIdentity::is_canonical`] prove canonical form (a
/// padded but self-consistent rebuild must never silently pass as canonical).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CrossCityMessageIdentity {
    /// Canonical lowercase hyphenated UUID of the durable cross-city operation.
    pub operation_id: String,
    /// The message phase this identity belongs to (part of the id tuple).
    pub phase: CrossCityMessagePhase,
    /// Sending city identifier (non-empty, no whitespace/control characters,
    /// no invisible Unicode format characters, at most
    /// [`IDENTIFIER_MAX_LEN`] bytes).
    pub source_city_id: String,
    /// Receiving city identifier; must differ from `source_city_id`.
    pub destination_city_id: String,
    /// Domain-separated SHA-256 over the canonical identity tuple; recomputed
    /// on every validation, so caller tampering is rejected fail-closed.
    pub message_id: String,
}

/// Derive the stable `message_id` over the exact values given: the fixed
/// domain header first (so a message id can never collide with any other
/// cross-city digest, nor with a raw payload digest), then every tuple field
/// in a fixed order, length-delimited. The output is always 64 lowercase hex
/// characters and contains no prefix beyond the digest itself.
fn derive_message_id(
    operation_id: &str,
    phase: CrossCityMessagePhase,
    source_city_id: &str,
    destination_city_id: &str,
) -> String {
    canonical_digest(
        MESSAGE_IDENTITY_DIGEST_HEADER,
        &[
            operation_id,
            phase.as_str(),
            source_city_id,
            destination_city_id,
        ],
    )
}

impl CrossCityMessageIdentity {
    /// Construct a self-consistent identity: the four identity inputs are
    /// strictly normalized (canonical non-nil lowercase UUID operation, cities
    /// trimmed to the existing identifier bounds and distinct) and
    /// `message_id` is derived from exactly those canonical values, so the
    /// same tuple always reproduces the same id.
    pub fn new(
        operation_id: &str,
        phase: CrossCityMessagePhase,
        source_city_id: &str,
        destination_city_id: &str,
    ) -> CrossCityContractResult<Self> {
        let canonical_operation_id = normalize_operation_id(operation_id, "operation_id")?;
        let canonical_source = normalize_identifier(source_city_id, "source_city_id")?;
        let canonical_destination =
            normalize_identifier(destination_city_id, "destination_city_id")?;
        if canonical_source == canonical_destination {
            return Err(CrossCityContractError::SelfRoutedMessage {
                city_id: canonical_source,
            });
        }
        let message_id = derive_message_id(
            &canonical_operation_id,
            phase,
            &canonical_source,
            &canonical_destination,
        );
        let value = Self {
            operation_id: canonical_operation_id,
            phase,
            source_city_id: canonical_source,
            destination_city_id: canonical_destination,
            message_id,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate fail-closed: the operation id and both city ids are checked
    /// against their existing normalization rules, the route must not be
    /// self-directed — decided on the NORMALIZED source/destination values,
    /// not the raw stored ones, so a padded spelling of one city can never
    /// dress a self-route up as a cross-city hop — and `message_id` is
    /// recomputed over the stored tuple so any caller tampering with the id
    /// (or with a tuple field) surfaces as a digest mismatch. This proves
    /// internal consistency; canonical FORM is proven separately by
    /// [`CrossCityMessageIdentity::is_canonical`].
    pub fn validate(&self) -> CrossCityContractResult<()> {
        normalize_operation_id(&self.operation_id, "operation_id").map(|_| ())?;
        let normalized_source = normalize_identifier(&self.source_city_id, "source_city_id")?;
        let normalized_destination =
            normalize_identifier(&self.destination_city_id, "destination_city_id")?;
        // Compare the NORMALIZED values: raw stored spellings may differ only
        // by trim-stripped padding while normalizing to the same city, which
        // is still a self-routed message.
        if normalized_source == normalized_destination {
            return Err(CrossCityContractError::SelfRoutedMessage {
                city_id: normalized_source,
            });
        }
        let recomputed = derive_message_id(
            &self.operation_id,
            self.phase,
            &self.source_city_id,
            &self.destination_city_id,
        );
        if recomputed != self.message_id {
            return Err(CrossCityContractError::DigestMismatch {
                field: "message_id",
                expected: recomputed,
                actual: self.message_id.clone(),
            });
        }
        Ok(())
    }

    /// Strictly rebuild the canonical form. BEFORE any repair, the stored
    /// `message_id` is re-derived over the stored tuple, so a caller-tampered
    /// id is rejected instead of being silently recomputed; only then are the
    /// fields re-normalized and `message_id` re-derived over the canonical
    /// values. A merely padded (self-consistent) input rebuilds to a DIFFERENT
    /// id, which is how [`CrossCityMessageIdentity::is_canonical`] detects it.
    pub fn canonicalized(&self) -> CrossCityContractResult<Self> {
        let recomputed = derive_message_id(
            &self.operation_id,
            self.phase,
            &self.source_city_id,
            &self.destination_city_id,
        );
        if recomputed != self.message_id {
            return Err(CrossCityContractError::DigestMismatch {
                field: "message_id",
                expected: recomputed,
                actual: self.message_id.clone(),
            });
        }
        Self::new(
            &self.operation_id,
            self.phase,
            &self.source_city_id,
            &self.destination_city_id,
        )
    }

    /// Whether this identity is exactly its own canonical rebuild: already
    /// trimmed, not self-routed, and `message_id` derived over exactly these
    /// canonical values. A caller-tampered `message_id` fails the rebuild and
    /// reports `false` instead of panicking or silently passing.
    pub fn is_canonical(&self) -> bool {
        self.canonicalized()
            .map(|canonical| canonical == *self)
            .unwrap_or(false)
    }
}

/// Raw SHA-256 digest over the EXACT published wire payload bytes, rendered as
/// 64 lowercase hex characters.
///
/// This is deliberately domain-independent and canonicalization-free: the
/// schema `payload_digest` records the bytes that were actually published, so
/// the digest MUST be computed over the raw wire bytes - never over a
/// re-serialized or canonically normalized JSON form, and never behind a
/// domain header (the digest describes content, it does not identify a
/// message; the identity of a message is [`CrossCityMessageIdentity`]). Callers
/// therefore invoke this on the exact byte slice handed to the MQ client, and
/// the same value can be verified byte-for-byte by any consumer without
/// knowing this crate's encoding.
pub fn cross_city_payload_digest(payload: &[u8]) -> String {
    hex::encode(Sha256::digest(payload))
}

// ---------------------------------------------------------------------------
// Tests (pure: no DB, no network, no external system)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const OPERATION_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
    const OPERATION_ID_ALT: &str = "0b9e6b1e-3d0a-4d0f-8d5f-2f1a0b9c8d7e";
    const CITY_ALPHA: &str = "city-alpha";
    const CITY_BETA: &str = "city-beta";
    const NOW: i64 = 999_999;
    const EXPIRES_AT: i64 = 1_000_000;

    /// Deterministic 64-character lowercase hex digest placeholder, distinct per
    /// seed byte.
    fn digest(seed: u8) -> String {
        format!("{seed:02x}").repeat(32)
    }

    fn try_proposal(operation_id: &str) -> CrossCityContractResult<MutationProposal> {
        MutationProposal::new(
            operation_id,
            &digest(0x01),
            &digest(0x02),
            &digest(0x03),
            &digest(0x04),
            4,
            1,
            5,
            1,
            "compiler-1",
            "policy-1",
            EXPIRES_AT,
        )
    }

    fn proposal() -> MutationProposal {
        try_proposal(OPERATION_ID).unwrap()
    }

    /// Evidence over the exact proposal, with explicit frontier/mutation/expiry
    /// overrides for mismatch scenarios. The signed payload binds the proposal
    /// through its full canonical digest.
    fn evidence_bound(
        proposal: &MutationProposal,
        city: &str,
        node: &str,
        decision: NodeDecision,
        frontier_digest: &str,
        mutation_digest: &str,
        expires_at: i64,
    ) -> ZeroDecisionEvidence {
        ZeroDecisionEvidence::new(
            city,
            node,
            3,
            decision,
            &proposal.proposal_digest().unwrap(),
            frontier_digest,
            mutation_digest,
            &format!("nonce-{node}"),
            expires_at,
            &format!("sig-{node}"),
        )
        .unwrap()
    }

    /// Evidence bound to the proposal with its default frontier/mutation/expiry.
    fn evidence(
        proposal: &MutationProposal,
        city: &str,
        node: &str,
        decision: NodeDecision,
    ) -> ZeroDecisionEvidence {
        evidence_bound(
            proposal,
            city,
            node,
            decision,
            &digest(0x04),
            &digest(0x03),
            EXPIRES_AT,
        )
    }

    fn allow_pair(
        proposal: &MutationProposal,
        city: &str,
        first: &str,
        second: &str,
    ) -> Vec<ZeroDecisionEvidence> {
        vec![
            evidence(proposal, city, first, NodeDecision::Allow),
            evidence(proposal, city, second, NodeDecision::Allow),
        ]
    }

    fn city_vote_custom(
        proposal: &MutationProposal,
        city: &str,
        frontier_digest: &str,
        mutation_digest: &str,
        expires_at: i64,
    ) -> CityVoteCertificate {
        let evidences = vec![
            evidence_bound(
                proposal,
                city,
                "node-a",
                NodeDecision::Allow,
                frontier_digest,
                mutation_digest,
                expires_at,
            ),
            evidence_bound(
                proposal,
                city,
                "node-b",
                NodeDecision::Allow,
                frontier_digest,
                mutation_digest,
                expires_at,
            ),
        ];
        CityVoteCertificate::issue(proposal, &evidences, NOW).unwrap()
    }

    fn city_vote(proposal: &MutationProposal, city: &str) -> CityVoteCertificate {
        city_vote_custom(proposal, city, &digest(0x04), &digest(0x03), EXPIRES_AT)
    }

    #[test]
    fn canonical_digest_is_deterministic_length_delimited_and_domain_separated() {
        let fields = ["alpha", "beta"];
        assert_eq!(
            canonical_digest(PROPOSAL_DIGEST_HEADER, &fields),
            canonical_digest(PROPOSAL_DIGEST_HEADER, &fields)
        );
        // Domain separation: identical fields under different headers never collide.
        assert_ne!(
            canonical_digest(PROPOSAL_DIGEST_HEADER, &fields),
            canonical_digest(NODE_EVIDENCE_DIGEST_HEADER, &fields)
        );
        let headers = [
            PROPOSAL_DIGEST_HEADER,
            NODE_EVIDENCE_DIGEST_HEADER,
            CITY_VOTE_DIGEST_HEADER,
            AGREEMENT_DIGEST_HEADER,
        ];
        for (index, header) in headers.iter().enumerate() {
            for other in &headers[index + 1..] {
                assert_ne!(header, other);
            }
        }
        // Length-delimited encoding is injective: separator/length ambiguity
        // cannot merge two different field tuples into one encoding.
        assert_ne!(
            canonical_digest(PROPOSAL_DIGEST_HEADER, &["a", "b|c"]),
            canonical_digest(PROPOSAL_DIGEST_HEADER, &["a|b", "c"])
        );
        assert_ne!(
            canonical_digest(PROPOSAL_DIGEST_HEADER, &["1:ab", "c"]),
            canonical_digest(PROPOSAL_DIGEST_HEADER, &["1", "ab:c"])
        );
        // Output shape: exactly 64 lowercase hex characters.
        let output = canonical_digest(PROPOSAL_DIGEST_HEADER, &fields);
        assert_eq!(output.len(), 64);
        assert!(output
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
    }

    #[test]
    fn proposal_digest_is_deterministic_and_field_sensitive() {
        let value = proposal();
        let first = value.proposal_digest().unwrap();
        assert_eq!(first, value.proposal_digest().unwrap());
        assert_eq!(first.len(), 64);
        assert!(first
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));

        let mut changed = value.clone();
        changed.base_frontier_digest = digest(0x0a);
        assert_ne!(first, changed.proposal_digest().unwrap());

        let mut changed = value.clone();
        changed.target_generation = 6;
        assert_ne!(first, changed.proposal_digest().unwrap());

        let mut changed = value.clone();
        changed.compiler_version = "compiler-2".to_owned();
        assert_ne!(first, changed.proposal_digest().unwrap());

        let mut changed = value.clone();
        changed.expires_at = EXPIRES_AT + 1;
        assert_ne!(first, changed.proposal_digest().unwrap());
    }

    #[test]
    fn proposal_requires_canonical_uuid_lowercase_digests_and_consistent_generations() {
        // Canonical lowercase hyphenated UUID only.
        assert!(try_proposal(OPERATION_ID).is_ok());
        assert!(matches!(
            try_proposal("550E8400-E29B-41D4-A716-446655440000"),
            Err(CrossCityContractError::InvalidOperationId {
                field: "operation_id"
            })
        ));
        assert!(matches!(
            try_proposal("urn:uuid:550e8400-e29b-41d4-a716-446655440000"),
            Err(CrossCityContractError::InvalidOperationId { .. })
        ));
        assert!(matches!(
            try_proposal("not-a-uuid"),
            Err(CrossCityContractError::InvalidOperationId { .. })
        ));
        assert!(matches!(
            try_proposal("00000000-0000-0000-0000-000000000000"),
            Err(CrossCityContractError::NilOperationId { .. })
        ));

        // Digests must be lowercase 64-character hex.
        let uppercase_scope = MutationProposal::new(
            OPERATION_ID,
            &"A".repeat(64),
            &digest(0x02),
            &digest(0x03),
            &digest(0x04),
            4,
            1,
            5,
            1,
            "compiler-1",
            "policy-1",
            EXPIRES_AT,
        );
        assert!(matches!(
            uppercase_scope,
            Err(CrossCityContractError::InvalidDigest {
                field: "scope_digest"
            })
        ));
        let short_scope = MutationProposal::new(
            OPERATION_ID,
            "abcd",
            &digest(0x02),
            &digest(0x03),
            &digest(0x04),
            4,
            1,
            5,
            1,
            "compiler-1",
            "policy-1",
            EXPIRES_AT,
        );
        assert!(matches!(
            short_scope,
            Err(CrossCityContractError::InvalidDigest {
                field: "scope_digest"
            })
        ));

        // The target generation must not regress behind the base.
        let regressed = MutationProposal::new(
            OPERATION_ID,
            &digest(0x01),
            &digest(0x02),
            &digest(0x03),
            &digest(0x04),
            6,
            1,
            5,
            1,
            "compiler-1",
            "policy-1",
            EXPIRES_AT,
        );
        assert!(matches!(
            regressed,
            Err(CrossCityContractError::GenerationRegressed {
                base_source_generation: 6,
                target_generation: 5,
            })
        ));

        // A fence may never exceed its generation.
        let base_fence = MutationProposal::new(
            OPERATION_ID,
            &digest(0x01),
            &digest(0x02),
            &digest(0x03),
            &digest(0x04),
            4,
            9,
            5,
            1,
            "compiler-1",
            "policy-1",
            EXPIRES_AT,
        );
        assert!(matches!(
            base_fence,
            Err(CrossCityContractError::InvalidFence {
                generation: 4,
                fence: 9,
            })
        ));

        // Expiry must be a positive Unix timestamp; identifiers must be non-empty.
        let zero_expiry = MutationProposal::new(
            OPERATION_ID,
            &digest(0x01),
            &digest(0x02),
            &digest(0x03),
            &digest(0x04),
            4,
            1,
            5,
            1,
            "compiler-1",
            "policy-1",
            0,
        );
        assert!(matches!(
            zero_expiry,
            Err(CrossCityContractError::InvalidExpiry {
                field: "expires_at",
                value: 0,
            })
        ));
        let empty_version = MutationProposal::new(
            OPERATION_ID,
            &digest(0x01),
            &digest(0x02),
            &digest(0x03),
            &digest(0x04),
            4,
            1,
            5,
            1,
            "  ",
            "policy-1",
            EXPIRES_AT,
        );
        assert!(matches!(
            empty_version,
            Err(CrossCityContractError::EmptyIdentifier {
                field: "compiler_version"
            })
        ));
    }

    #[test]
    fn two_distinct_allow_evidences_of_one_city_issue_a_certificate() {
        let value = proposal();
        let evidences = allow_pair(&value, CITY_ALPHA, "node-a", "node-b");
        let certificate = CityVoteCertificate::issue(&value, &evidences, NOW).unwrap();
        assert_eq!(certificate.operation_id, OPERATION_ID);
        assert_eq!(certificate.city_id, CITY_ALPHA);
        assert_eq!(
            certificate.proposal_digest,
            value.proposal_digest().unwrap()
        );
        assert_eq!(certificate.frontier_digest, digest(0x04));
        assert_eq!(certificate.mutation_digest, digest(0x03));
        assert_eq!(certificate.expires_at, EXPIRES_AT);
        assert_eq!(certificate.nodes.len(), 2);
        // Canonical ascending node order.
        assert_eq!(certificate.nodes[0].node_id, "node-a");
        assert_eq!(certificate.nodes[1].node_id, "node-b");
        assert_eq!(certificate.certificate_digest.len(), 64);
        certificate.validate_at(NOW).unwrap();

        // Evidence input order must not change the certificate.
        let reordered =
            CityVoteCertificate::issue(&value, &[evidences[1].clone(), evidences[0].clone()], NOW)
                .unwrap();
        assert_eq!(reordered, certificate);
    }

    #[test]
    fn city_vote_rejects_duplicate_nodes_cross_city_non_allow_and_bad_counts() {
        let value = proposal();

        // The same node may not vote twice.
        let duplicate = vec![
            evidence(&value, CITY_ALPHA, "node-a", NodeDecision::Allow),
            evidence(&value, CITY_ALPHA, "node-a", NodeDecision::Allow),
        ];
        assert!(matches!(
            CityVoteCertificate::issue(&value, &duplicate, NOW),
            Err(CrossCityContractError::DuplicateNode { city_id, node_id })
                if city_id == CITY_ALPHA && node_id == "node-a"
        ));

        // Evidences from different cities can never form one city vote.
        let mixed = vec![
            evidence(&value, CITY_ALPHA, "node-a", NodeDecision::Allow),
            evidence(&value, CITY_BETA, "node-b", NodeDecision::Allow),
        ];
        assert!(matches!(
            CityVoteCertificate::issue(&value, &mixed, NOW),
            Err(CrossCityContractError::CityMismatch {
                expected,
                actual
            }) if expected == CITY_ALPHA && actual == CITY_BETA
        ));

        // A DENY decision can never contribute to a vote.
        let denying = vec![
            evidence(&value, CITY_ALPHA, "node-a", NodeDecision::Allow),
            evidence(&value, CITY_ALPHA, "node-b", NodeDecision::Deny),
        ];
        assert!(matches!(
            CityVoteCertificate::issue(&value, &denying, NOW),
            Err(CrossCityContractError::DecisionNotAllow { node_id, decision })
                if node_id == "node-b" && decision == "DENY"
        ));

        // Exactly two evidences are required.
        let single = vec![evidence(&value, CITY_ALPHA, "node-a", NodeDecision::Allow)];
        assert!(matches!(
            CityVoteCertificate::issue(&value, &single, NOW),
            Err(CrossCityContractError::EvidenceCountMismatch {
                expected: 2,
                actual: 1,
            })
        ));
        let triple = allow_pair(&value, CITY_ALPHA, "node-a", "node-b");
        let triple = [
            triple[0].clone(),
            triple[1].clone(),
            evidence(&value, CITY_ALPHA, "node-c", NodeDecision::Allow),
        ];
        assert!(matches!(
            CityVoteCertificate::issue(&value, &triple, NOW),
            Err(CrossCityContractError::EvidenceCountMismatch {
                expected: 2,
                actual: 3,
            })
        ));

        // Unknown decision tokens are rejected at the serde boundary.
        assert!(serde_json::from_str::<NodeDecision>("\"MAYBE\"").is_err());
        assert!(serde_json::from_str::<NodeDecision>("\"DENY\"").is_ok());
    }

    #[test]
    fn city_vote_rejects_digest_expiry_and_disagreement_with_proposal() {
        let value = proposal();

        // An evidence compiled against a different frontier is rejected.
        let stale_frontier = vec![
            evidence_bound(
                &value,
                CITY_ALPHA,
                "node-a",
                NodeDecision::Allow,
                &digest(0x05),
                &digest(0x03),
                EXPIRES_AT,
            ),
            evidence(&value, CITY_ALPHA, "node-b", NodeDecision::Allow),
        ];
        assert!(matches!(
            CityVoteCertificate::issue(&value, &stale_frontier, NOW),
            Err(CrossCityContractError::FieldMismatch {
                field: "frontier_digest",
                ..
            })
        ));

        // An evidence over a different mutation payload is rejected.
        let other_mutation = vec![
            evidence(&value, CITY_ALPHA, "node-a", NodeDecision::Allow),
            evidence_bound(
                &value,
                CITY_ALPHA,
                "node-b",
                NodeDecision::Allow,
                &digest(0x04),
                &digest(0x06),
                EXPIRES_AT,
            ),
        ];
        assert!(matches!(
            CityVoteCertificate::issue(&value, &other_mutation, NOW),
            Err(CrossCityContractError::FieldMismatch {
                field: "mutation_digest",
                ..
            })
        ));

        // An evidence with a different expiry window is rejected.
        let other_expiry = vec![
            evidence(&value, CITY_ALPHA, "node-a", NodeDecision::Allow),
            evidence_bound(
                &value,
                CITY_ALPHA,
                "node-b",
                NodeDecision::Allow,
                &digest(0x04),
                &digest(0x03),
                EXPIRES_AT + 60,
            ),
        ];
        assert!(matches!(
            CityVoteCertificate::issue(&value, &other_expiry, NOW),
            Err(CrossCityContractError::FieldMismatch {
                field: "expires_at",
                ..
            })
        ));

        // Expired proposal or expired evidence can never vote.
        let evidences = allow_pair(&value, CITY_ALPHA, "node-a", "node-b");
        assert!(matches!(
            CityVoteCertificate::issue(&value, &evidences, EXPIRES_AT),
            Err(CrossCityContractError::Expired { .. })
        ));
        assert!(matches!(
            CityVoteCertificate::issue(&value, &evidences, EXPIRES_AT + 1),
            Err(CrossCityContractError::Expired { .. })
        ));
        let short_lived = evidence_bound(
            &value,
            CITY_ALPHA,
            "node-a",
            NodeDecision::Allow,
            &digest(0x04),
            &digest(0x03),
            NOW - 1,
        );
        assert!(matches!(
            short_lived.validate_at(NOW),
            Err(CrossCityContractError::Expired { .. })
        ));
        assert!(short_lived.is_expired_at(NOW));
    }

    #[test]
    fn evidence_and_certificate_validation_fail_closed_on_tampering() {
        let value = proposal();

        // A tampered payload no longer matches the recomputed evidence digest.
        let mut tampered = evidence(&value, CITY_ALPHA, "node-a", NodeDecision::Allow);
        tampered.nonce = "tampered".to_owned();
        assert!(matches!(
            tampered.validate_at(NOW),
            Err(CrossCityContractError::DigestMismatch {
                field: "evidence_digest",
                ..
            })
        ));

        // A replaced digest is also caught.
        let mut replaced = evidence(&value, CITY_ALPHA, "node-a", NodeDecision::Allow);
        replaced.evidence_digest = digest(0x0b);
        assert!(matches!(
            replaced.validate_at(NOW),
            Err(CrossCityContractError::DigestMismatch {
                field: "evidence_digest",
                ..
            })
        ));

        // Empty fields fail closed.
        let empty_city = ZeroDecisionEvidence::new(
            "   ",
            "node-a",
            3,
            NodeDecision::Allow,
            &digest(0x07),
            &digest(0x04),
            &digest(0x03),
            "nonce",
            EXPIRES_AT,
            "sig",
        );
        assert!(matches!(
            empty_city,
            Err(CrossCityContractError::EmptyIdentifier { field: "city_id" })
        ));
        let zero_epoch = ZeroDecisionEvidence::new(
            CITY_ALPHA,
            "node-a",
            0,
            NodeDecision::Allow,
            &digest(0x07),
            &digest(0x04),
            &digest(0x03),
            "nonce",
            EXPIRES_AT,
            "sig",
        );
        assert!(matches!(
            zero_epoch,
            Err(CrossCityContractError::NonPositiveNumber {
                field: "node_epoch",
                value: 0,
            })
        ));
        let missing_signature = ZeroDecisionEvidence::new(
            CITY_ALPHA,
            "node-a",
            3,
            NodeDecision::Allow,
            &digest(0x07),
            &digest(0x04),
            &digest(0x03),
            "nonce",
            EXPIRES_AT,
            "",
        );
        assert!(matches!(
            missing_signature,
            Err(CrossCityContractError::EmptyIdentifier { field: "signature" })
        ));

        // A tampered certificate digest is caught on validation.
        let value = proposal();
        let mut certificate = city_vote(&value, CITY_ALPHA);
        certificate.certificate_digest = digest(0x0c);
        assert!(matches!(
            certificate.validate_at(NOW),
            Err(CrossCityContractError::DigestMismatch {
                field: "certificate_digest",
                ..
            })
        ));

        // Reordered (non-canonical) node attestations are rejected.
        let mut reordered = city_vote(&value, CITY_ALPHA);
        reordered.nodes.reverse();
        assert!(matches!(
            reordered.validate_at(NOW),
            Err(CrossCityContractError::NonCanonicalForm { field: "nodes" })
        ));

        // Expired certificates fail closed.
        let certificate = city_vote(&value, CITY_ALPHA);
        assert!(matches!(
            certificate.validate_at(EXPIRES_AT),
            Err(CrossCityContractError::Expired { .. })
        ));
    }

    #[test]
    fn two_distinct_city_votes_reach_an_agreement() {
        let value = proposal();
        let alpha = city_vote(&value, CITY_ALPHA);
        let beta = city_vote(&value, CITY_BETA);
        let agreement = CrossCityAgreementCertificate::reach(&value, &[alpha, beta], NOW).unwrap();
        assert_eq!(agreement.operation_id, OPERATION_ID);
        assert_eq!(agreement.proposal_digest, value.proposal_digest().unwrap());
        assert_eq!(agreement.frontier_digest, digest(0x04));
        assert_eq!(agreement.mutation_digest, digest(0x03));
        assert_eq!(agreement.target_generation, 5);
        assert_eq!(agreement.target_revoke_fence, 1);
        assert_eq!(agreement.expires_at, EXPIRES_AT);
        // Canonical ascending city order.
        assert_eq!(agreement.city_votes.len(), 2);
        assert_eq!(agreement.city_votes[0].city_id, CITY_ALPHA);
        assert_eq!(agreement.city_votes[1].city_id, CITY_BETA);
        assert_eq!(agreement.agreement_digest.len(), 64);
        agreement.validate_at(NOW).unwrap();

        // Vote input order must not change the agreement.
        let value = proposal();
        let alpha = city_vote(&value, CITY_ALPHA);
        let beta = city_vote(&value, CITY_BETA);
        let reordered = CrossCityAgreementCertificate::reach(&value, &[beta, alpha], NOW).unwrap();
        assert_eq!(reordered.agreement_digest, agreement.agreement_digest);
        assert_eq!(reordered, agreement);
    }

    #[test]
    fn agreement_rejects_strict_mismatches() {
        let value = proposal();
        let alpha = city_vote(&value, CITY_ALPHA);
        let beta = city_vote(&value, CITY_BETA);

        // The same city may not vote twice.
        let alpha_second = city_vote(&value.clone(), CITY_ALPHA);
        assert!(matches!(
            CrossCityAgreementCertificate::reach(&value, &[alpha.clone(), alpha_second], NOW),
            Err(CrossCityContractError::DuplicateCity { city_id }) if city_id == CITY_ALPHA
        ));

        // Exactly two votes are required.
        assert!(matches!(
            CrossCityAgreementCertificate::reach(&value, std::slice::from_ref(&alpha), NOW),
            Err(CrossCityContractError::CityVoteCountMismatch {
                expected: 2,
                actual: 1,
            })
        ));

        // A different operation id mismatches first.
        let other_operation = try_proposal(OPERATION_ID_ALT).unwrap();
        let beta_of_other = city_vote(&other_operation, CITY_BETA);
        assert!(matches!(
            CrossCityAgreementCertificate::reach(&value, &[alpha.clone(), beta_of_other], NOW),
            Err(CrossCityContractError::FieldMismatch {
                field: "operation_id",
                ..
            })
        ));

        // A proposal differing only in its base frontier digest mismatches on the
        // frontier the votes certified.
        let mut other = value.clone();
        other.base_frontier_digest = digest(0x05);
        other.validate().unwrap();
        let beta_of_other =
            city_vote_custom(&other, CITY_BETA, &digest(0x05), &digest(0x03), EXPIRES_AT);
        assert!(matches!(
            CrossCityAgreementCertificate::reach(&value, &[alpha.clone(), beta_of_other], NOW),
            Err(CrossCityContractError::FieldMismatch {
                field: "frontier_digest",
                ..
            })
        ));

        // A proposal differing only in its mutation digest mismatches on the
        // mutation the votes certified.
        let mut other = value.clone();
        other.mutation_digest = digest(0x06);
        other.validate().unwrap();
        let beta_of_other =
            city_vote_custom(&other, CITY_BETA, &digest(0x04), &digest(0x06), EXPIRES_AT);
        assert!(matches!(
            CrossCityAgreementCertificate::reach(&value, &[alpha.clone(), beta_of_other], NOW),
            Err(CrossCityContractError::FieldMismatch {
                field: "mutation_digest",
                ..
            })
        ));

        // A proposal with a different expiry window mismatches on expiry.
        let mut other = value.clone();
        other.expires_at = EXPIRES_AT + 60;
        other.validate().unwrap();
        let beta_of_other = city_vote_custom(
            &other,
            CITY_BETA,
            &digest(0x04),
            &digest(0x03),
            EXPIRES_AT + 60,
        );
        assert!(matches!(
            CrossCityAgreementCertificate::reach(&value, &[alpha.clone(), beta_of_other], NOW),
            Err(CrossCityContractError::FieldMismatch {
                field: "expires_at",
                ..
            })
        ));

        // A proposal differing only in its target generation is caught through the
        // exact proposal_digest binding: the votes certified a different proposal.
        let mut other = value.clone();
        other.target_generation = 6;
        other.target_revoke_fence = 2;
        other.validate().unwrap();
        let beta_of_other = city_vote(&other, CITY_BETA);
        assert!(matches!(
            CrossCityAgreementCertificate::reach(&value, &[alpha.clone(), beta_of_other], NOW),
            Err(CrossCityContractError::FieldMismatch {
                field: "proposal_digest",
                ..
            })
        ));

        // A proposal differing only in its scope digest is likewise caught.
        let mut other = value.clone();
        other.scope_digest = digest(0x0e);
        other.validate().unwrap();
        let beta_of_other = city_vote(&other, CITY_BETA);
        assert!(matches!(
            CrossCityAgreementCertificate::reach(&value, &[alpha.clone(), beta_of_other], NOW),
            Err(CrossCityContractError::FieldMismatch {
                field: "proposal_digest",
                ..
            })
        ));

        // Expired agreement or expired votes fail closed.
        assert!(matches!(
            CrossCityAgreementCertificate::reach(
                &value,
                &[alpha.clone(), beta.clone()],
                EXPIRES_AT
            ),
            Err(CrossCityContractError::Expired { .. })
        ));

        // A tampered agreement digest is caught on validation.
        let agreement = CrossCityAgreementCertificate::reach(&value, &[alpha, beta], NOW).unwrap();
        let mut tampered = agreement.clone();
        tampered.agreement_digest = digest(0x0d);
        assert!(matches!(
            tampered.validate_at(NOW),
            Err(CrossCityContractError::DigestMismatch {
                field: "agreement_digest",
                ..
            })
        ));
        let mut reordered = agreement;
        reordered.city_votes.reverse();
        assert!(matches!(
            reordered.validate_at(NOW),
            Err(CrossCityContractError::NonCanonicalForm {
                field: "city_votes"
            })
        ));
    }

    #[test]
    fn reach_rejects_non_canonical_city_votes_instead_of_repairing_them() {
        let value = proposal();

        // A whitespace-padded but self-consistent vote (its stored digest was
        // re-derived over the padded payload) validates as received...
        let mut padded = city_vote(&value, CITY_ALPHA);
        padded.city_id = format!(" {} ", CITY_ALPHA);
        padded.certificate_digest = padded.compute_digest();
        assert!(padded.validate_at(NOW).is_ok());
        // ...but it is not canonical, and `reach` must reject it instead of
        // silently repairing it into a different value.
        assert!(!padded.is_canonical());

        let beta = city_vote(&value, CITY_BETA);
        assert!(matches!(
            CrossCityAgreementCertificate::reach(&value, &[padded.clone(), beta.clone()], NOW),
            Err(CrossCityContractError::NonCanonicalForm {
                field: "city_votes",
            })
        ));
        // Input order must not matter: the padded vote is rejected either way.
        assert!(matches!(
            CrossCityAgreementCertificate::reach(&value, &[beta, padded], NOW),
            Err(CrossCityContractError::NonCanonicalForm {
                field: "city_votes",
            })
        ));

        // Two spellings of one city must never count as two cities: the padded
        // spelling is rejected as non-canonical rather than paired with the
        // canonical one into an agreement.
        let canonical_alpha = city_vote(&value, CITY_ALPHA);
        let mut padded_alpha = canonical_alpha.clone();
        padded_alpha.city_id = format!("  {} ", CITY_ALPHA);
        padded_alpha.certificate_digest = padded_alpha.compute_digest();
        assert!(padded_alpha.validate_at(NOW).is_ok());
        assert!(!padded_alpha.is_canonical());
        assert!(matches!(
            CrossCityAgreementCertificate::reach(&value, &[canonical_alpha, padded_alpha], NOW),
            Err(CrossCityContractError::NonCanonicalForm {
                field: "city_votes",
            })
        ));

        // A padded operation_id is likewise rejected through the canonical-form
        // proof (the certificate digest was re-derived over the padded value).
        let mut padded_operation = city_vote(&value, CITY_BETA);
        padded_operation.operation_id = format!(" {OPERATION_ID}");
        padded_operation.certificate_digest = padded_operation.compute_digest();
        assert!(padded_operation.validate_at(NOW).is_ok());
        assert!(!padded_operation.is_canonical());
        let alpha = city_vote(&value, CITY_ALPHA);
        assert!(matches!(
            CrossCityAgreementCertificate::reach(&value, &[alpha, padded_operation], NOW),
            Err(CrossCityContractError::NonCanonicalForm {
                field: "city_votes",
            })
        ));
    }

    #[test]
    fn two_votes_of_one_city_cannot_reach_an_agreement() {
        let value = proposal();

        // Two certificates of one city - even byte-identical ones - can never
        // reach an agreement.
        let alpha_first = city_vote(&value, CITY_ALPHA);
        let alpha_second = city_vote(&value, CITY_ALPHA);
        assert!(matches!(
            CrossCityAgreementCertificate::reach(&value, &[alpha_first, alpha_second], NOW),
            Err(CrossCityContractError::DuplicateCity { city_id }) if city_id == CITY_ALPHA
        ));

        // Distinct node pairs of one city are still one city.
        let alpha_nodes_ab = CityVoteCertificate::issue(
            &value,
            &allow_pair(&value, CITY_ALPHA, "node-a", "node-b"),
            NOW,
        )
        .unwrap();
        let alpha_nodes_cd = CityVoteCertificate::issue(
            &value,
            &allow_pair(&value, CITY_ALPHA, "node-c", "node-d"),
            NOW,
        )
        .unwrap();
        // The rejection is precisely DuplicateCity, not any other error path.
        let error =
            CrossCityAgreementCertificate::reach(&value, &[alpha_nodes_ab, alpha_nodes_cd], NOW)
                .unwrap_err();
        assert_eq!(
            error,
            CrossCityContractError::DuplicateCity {
                city_id: CITY_ALPHA.to_owned(),
            }
        );
    }

    #[test]
    fn state_machine_accepts_only_guarded_transitions() {
        use CrossCityOperationState as State;

        // Happy path of the 2PC-style flow.
        for (from, to) in [
            (State::Proposed, State::Voting),
            (State::Voting, State::Agreed),
            (State::Agreed, State::Preparing),
            (State::Preparing, State::Prepared),
            (State::Prepared, State::Activating),
            (State::Activating, State::Active),
        ] {
            assert_eq!(from.transition(to).unwrap(), to);
        }

        // Fail-closed recovery paths.
        for (from, to) in [
            (State::Proposed, State::Rejected),
            (State::Proposed, State::Expired),
            (State::Voting, State::Deferred),
            (State::Voting, State::Rejected),
            (State::Voting, State::Expired),
            (State::Deferred, State::Voting),
            (State::Deferred, State::Expired),
            (State::Agreed, State::Expired),
            (State::Preparing, State::InDoubt),
            (State::Preparing, State::Rejected),
            (State::Preparing, State::Expired),
            (State::Prepared, State::InDoubt),
            (State::Prepared, State::Expired),
            (State::Activating, State::InDoubt),
            (State::Activating, State::Quarantined),
            (State::InDoubt, State::Active),
            (State::InDoubt, State::Quarantined),
        ] {
            assert_eq!(from.transition(to).unwrap(), to);
        }

        // Illegal transitions: skipping, self-transitions, leaving terminal
        // states, and regressing within the flow all fail closed. `IN_DOUBT`
        // can never be discarded as `REJECTED`: an unknown commit outcome may
        // only forward-complete (`ACTIVE`, with durable proof) or be
        // quarantined.
        for (from, to) in [
            (State::Proposed, State::Agreed),
            (State::Proposed, State::Prepared),
            (State::Proposed, State::Proposed),
            (State::Voting, State::Preparing),
            (State::Voting, State::Active),
            (State::Deferred, State::Agreed),
            (State::Agreed, State::Prepared),
            (State::Agreed, State::Active),
            (State::Preparing, State::Active),
            (State::Prepared, State::Active),
            (State::Activating, State::Prepared),
            (State::Activating, State::Activating),
            (State::InDoubt, State::Voting),
            (State::InDoubt, State::Prepared),
            (State::InDoubt, State::InDoubt),
            (State::InDoubt, State::Rejected),
            (State::Active, State::Rejected),
            (State::Active, State::Active),
            (State::Rejected, State::Voting),
            (State::Expired, State::Voting),
            (State::Quarantined, State::Active),
        ] {
            assert!(matches!(
                from.transition(to),
                Err(CrossCityContractError::InvalidTransition { .. })
            ));
            assert!(!from.can_transition_to(to));
        }

        // Terminal states never transition again.
        for terminal in [
            State::Active,
            State::Rejected,
            State::Expired,
            State::Quarantined,
        ] {
            assert!(terminal.is_terminal());
            for target in [
                State::Proposed,
                State::Voting,
                State::Agreed,
                State::Preparing,
                State::Prepared,
                State::Activating,
                State::InDoubt,
                State::Active,
                State::Rejected,
                State::Deferred,
                State::Quarantined,
                State::Expired,
            ] {
                assert!(matches!(
                    terminal.transition(target),
                    Err(CrossCityContractError::InvalidTransition { .. })
                ));
            }
        }
        for non_terminal in [
            State::Proposed,
            State::Voting,
            State::Agreed,
            State::Preparing,
            State::Prepared,
            State::Activating,
            State::InDoubt,
            State::Deferred,
        ] {
            assert!(!non_terminal.is_terminal());
        }
    }

    #[test]
    fn only_an_active_gate_is_authorization_ready() {
        assert!(CrossCityGateState::Active.is_authorization_ready());
        assert!(!CrossCityGateState::Syncing.is_authorization_ready());
        assert!(!CrossCityGateState::Blocked.is_authorization_ready());
        assert!(CrossCityGateState::Active
            .ensure_authorization_ready()
            .is_ok());
        for gate in [CrossCityGateState::Syncing, CrossCityGateState::Blocked] {
            assert!(matches!(
                gate.ensure_authorization_ready(),
                Err(CrossCityContractError::GateNotActive { .. })
            ));
        }
        // Fail-closed defaults: cross-city mode is default-off and the gate starts
        // BLOCKED until an explicit enablement. The mode flag is a compile-time
        // constant, so its fail-closed value is pinned at compile time.
        const {
            assert!(!CROSS_CITY_MODE_DEFAULT_ENABLED);
        }
        assert_eq!(CrossCityGateState::default(), CrossCityGateState::Blocked);
    }

    #[test]
    fn contracts_roundtrip_through_serde() {
        // Proposal roundtrip, including the camelCase wire form.
        let value = proposal();
        let encoded = serde_json::to_string(&value).unwrap();
        assert!(encoded.contains("\"operationId\""));
        assert!(encoded.contains("\"baseSourceGeneration\""));
        let decoded: MutationProposal = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(
            decoded.proposal_digest().unwrap(),
            value.proposal_digest().unwrap()
        );

        // Evidence roundtrip stays valid.
        let evidence = evidence(&value, CITY_ALPHA, "node-a", NodeDecision::Allow);
        let encoded = serde_json::to_string(&evidence).unwrap();
        assert!(encoded.contains("\"proposalDigest\""));
        let decoded: ZeroDecisionEvidence = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, evidence);
        decoded.validate_at(NOW).unwrap();

        // Certificate roundtrip stays valid.
        let value = proposal();
        let certificate = city_vote(&value, CITY_ALPHA);
        let encoded = serde_json::to_string(&certificate).unwrap();
        let decoded: CityVoteCertificate = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, certificate);
        decoded.validate_at(NOW).unwrap();

        // Agreement roundtrip stays valid.
        let alpha = city_vote(&value, CITY_ALPHA);
        let beta = city_vote(&value, CITY_BETA);
        let agreement = CrossCityAgreementCertificate::reach(&value, &[alpha, beta], NOW).unwrap();
        let encoded = serde_json::to_string(&agreement).unwrap();
        let decoded: CrossCityAgreementCertificate = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, agreement);
        decoded.validate_at(NOW).unwrap();

        // State and gate enums roundtrip in SCREAMING_SNAKE_CASE and reject
        // unknown variants.
        assert_eq!(
            serde_json::to_string(&CrossCityOperationState::InDoubt).unwrap(),
            "\"IN_DOUBT\""
        );
        let state: CrossCityOperationState = serde_json::from_str("\"AGREED\"").unwrap();
        assert_eq!(state, CrossCityOperationState::Agreed);
        assert!(serde_json::from_str::<CrossCityOperationState>("\"UNKNOWN\"").is_err());
        assert_eq!(
            serde_json::to_string(&CrossCityGateState::Syncing).unwrap(),
            "\"SYNCING\""
        );
        let gate: CrossCityGateState = serde_json::from_str("\"BLOCKED\"").unwrap();
        assert_eq!(gate, CrossCityGateState::Blocked);
        assert!(serde_json::from_str::<CrossCityGateState>("\"OPEN\"").is_err());
    }

    #[test]
    fn canonicalization_trims_identifiers_and_rerives_digests() {
        // Identifiers are trimmed; digest fields are trimmed then strictly
        // validated; UUIDs and signatures must already be canonical.
        let evidence = ZeroDecisionEvidence::new(
            "  city-alpha  ",
            " node-a ",
            3,
            NodeDecision::Allow,
            &digest(0x07),
            &digest(0x04),
            &digest(0x03),
            " nonce-a ",
            EXPIRES_AT,
            " sig-a ",
        )
        .unwrap();
        assert_eq!(evidence.city_id, CITY_ALPHA);
        assert_eq!(evidence.node_id, "node-a");
        assert_eq!(evidence.nonce, "nonce-a");
        assert_eq!(evidence.signature, "sig-a");
        let canonical = evidence.canonicalized().unwrap();
        assert_eq!(canonical, evidence);

        // Digest fields are trimmed before strict validation, so a padded valid
        // digest canonicalizes to its trimmed form; a genuinely invalid digest
        // (wrong case) still fails closed.
        let padded = ZeroDecisionEvidence::new(
            CITY_ALPHA,
            "node-a",
            3,
            NodeDecision::Allow,
            &digest(0x07),
            &format!(" {} ", digest(0x04)),
            &digest(0x03),
            "nonce-a",
            EXPIRES_AT,
            "sig-a",
        )
        .unwrap();
        assert_eq!(padded.frontier_digest, digest(0x04));

        let uppercase = ZeroDecisionEvidence::new(
            CITY_ALPHA,
            "node-a",
            3,
            NodeDecision::Allow,
            &digest(0x07),
            &"A".repeat(64),
            &digest(0x03),
            "nonce-a",
            EXPIRES_AT,
            "sig-a",
        );
        assert!(matches!(
            uppercase,
            Err(CrossCityContractError::InvalidDigest {
                field: "frontier_digest",
            })
        ));
    }

    #[test]
    fn evidence_cannot_be_replayed_against_a_different_proposal() {
        let value = proposal();
        let evidences = allow_pair(&value, CITY_ALPHA, "node-a", "node-b");

        // The exact same evidences (same signatures and digests) must not certify
        // a different proposal, even one that agrees on frontier/mutation digests:
        // the signed payload binds the full proposal through `proposal_digest`.
        let other_operation = try_proposal(OPERATION_ID_ALT).unwrap();
        assert!(matches!(
            CityVoteCertificate::issue(&other_operation, &evidences, NOW),
            Err(CrossCityContractError::FieldMismatch {
                field: "proposal_digest",
                ..
            })
        ));

        // A proposal differing only in its scope digest is likewise rejected.
        let mut other_scope = value.clone();
        other_scope.scope_digest = digest(0x0e);
        other_scope.validate().unwrap();
        assert!(matches!(
            CityVoteCertificate::issue(&other_scope, &evidences, NOW),
            Err(CrossCityContractError::FieldMismatch {
                field: "proposal_digest",
                ..
            })
        ));

        // An evidence whose proposal_digest field points at another proposal
        // fails the binding check against the proposal being certified.
        let wrong_binding = ZeroDecisionEvidence::new(
            CITY_ALPHA,
            "node-a",
            3,
            NodeDecision::Allow,
            &try_proposal(OPERATION_ID_ALT)
                .unwrap()
                .proposal_digest()
                .unwrap(),
            &digest(0x04),
            &digest(0x03),
            "nonce-a",
            EXPIRES_AT,
            "sig-a",
        )
        .unwrap();
        let pair = [
            wrong_binding,
            evidence(&value, CITY_ALPHA, "node-b", NodeDecision::Allow),
        ];
        assert!(matches!(
            CityVoteCertificate::issue(&value, &pair, NOW),
            Err(CrossCityContractError::FieldMismatch {
                field: "proposal_digest",
                ..
            })
        ));
    }

    #[test]
    fn issue_rejects_tampered_evidences_exactly_as_received() {
        let value = proposal();
        let baseline = allow_pair(&value, CITY_ALPHA, "node-a", "node-b");

        // Tampering with the nonce must surface directly on the as-received
        // evidence (no canonicalization pass may mask it).
        let mut tampered_nonce = baseline[0].clone();
        tampered_nonce.nonce = "replayed-nonce".to_owned();
        let pair = [tampered_nonce, baseline[1].clone()];
        assert!(matches!(
            CityVoteCertificate::issue(&value, &pair, NOW),
            Err(CrossCityContractError::DigestMismatch {
                field: "evidence_digest",
                ..
            })
        ));

        // Tampering with the frontier digest is caught the same way: the
        // evidence digest no longer matches the payload.
        let mut tampered_frontier = baseline[0].clone();
        tampered_frontier.frontier_digest = digest(0x05);
        let pair = [tampered_frontier, baseline[1].clone()];
        assert!(matches!(
            CityVoteCertificate::issue(&value, &pair, NOW),
            Err(CrossCityContractError::DigestMismatch {
                field: "evidence_digest",
                ..
            })
        ));

        // Tampering with the bound proposal digest breaks the signed payload.
        let mut tampered_binding = baseline[0].clone();
        tampered_binding.proposal_digest = digest(0x0f);
        let pair = [tampered_binding, baseline[1].clone()];
        assert!(matches!(
            CityVoteCertificate::issue(&value, &pair, NOW),
            Err(CrossCityContractError::DigestMismatch {
                field: "evidence_digest",
                ..
            })
        ));

        // A replaced evidence digest is rejected without any repair attempt.
        let mut replaced_digest = baseline[0].clone();
        replaced_digest.evidence_digest = digest(0x0b);
        let pair = [replaced_digest, baseline[1].clone()];
        assert!(matches!(
            CityVoteCertificate::issue(&value, &pair, NOW),
            Err(CrossCityContractError::DigestMismatch {
                field: "evidence_digest",
                ..
            })
        ));
    }

    #[test]
    fn issue_rejects_non_canonical_evidences_instead_of_repairing_them() {
        let value = proposal();

        // A whitespace-padded but self-consistent evidence (its stored digest was
        // derived over the padded payload) must not be silently repaired into a
        // different canonical value by `issue`.
        let mut padded = evidence(&value, CITY_ALPHA, "node-a", NodeDecision::Allow);
        padded.city_id = format!(" {CITY_ALPHA} ");
        padded.nonce = "  nonce-a  ".to_owned();
        padded.evidence_digest = padded.compute_digest();
        assert!(padded.validate_at(NOW).is_ok());

        let pair = [
            padded,
            evidence(&value, CITY_ALPHA, "node-b", NodeDecision::Allow),
        ];
        assert!(matches!(
            CityVoteCertificate::issue(&value, &pair, NOW),
            Err(CrossCityContractError::NonCanonicalForm {
                field: "node_evidences",
            })
        ));
    }

    #[test]
    fn message_phase_wire_strings_strict_parse_and_serde() {
        use CrossCityMessagePhase as Phase;

        // Exact wire/DB strings, in canonical order.
        let expected = [
            (Phase::Vote, "VOTE"),
            (Phase::Prepare, "PREPARE"),
            (Phase::Activate, "ACTIVATE"),
            (Phase::CommitConfirmed, "COMMIT_CONFIRMED"),
            (Phase::Reconcile, "RECONCILE"),
        ];
        assert_eq!(Phase::ALL.len(), expected.len());
        for (index, (phase, spelling)) in expected.iter().enumerate() {
            assert_eq!(Phase::ALL[index], *phase);
            assert_eq!(phase.as_str(), *spelling);
            assert_eq!(Phase::parse_str(spelling).unwrap(), *phase);
            // Serde uses the same exact string on the wire.
            let encoded = format!("\"{spelling}\"");
            assert_eq!(serde_json::to_string(phase).unwrap(), encoded);
            assert_eq!(serde_json::from_str::<Phase>(&encoded).unwrap(), *phase);
        }

        // Strict parsing rejects unknown values and case drift: no trimming,
        // no case-folding, at the parse boundary or the serde boundary.
        for drifted in [
            "vote",
            "Vote",
            "VOTE ",
            " VOTE",
            "commit_confirmed",
            "COMMIT-CONFIRMED",
            "UNKNOWN",
            "",
        ] {
            assert!(matches!(
                Phase::parse_str(drifted),
                Err(CrossCityContractError::UnknownMessagePhase { .. })
            ));
            assert!(serde_json::from_str::<Phase>(&format!("\"{drifted}\"")).is_err());
        }

        // A phase is not a coordinator state: no phase spelling parses as a
        // CrossCityOperationState, and no state spelling parses as a phase.
        for phase in Phase::ALL {
            assert!(serde_json::from_str::<CrossCityOperationState>(&format!(
                "\"{}\"",
                phase.as_str()
            ))
            .is_err());
        }
        for state in [
            CrossCityOperationState::Proposed,
            CrossCityOperationState::Voting,
            CrossCityOperationState::Agreed,
            CrossCityOperationState::Preparing,
            CrossCityOperationState::Prepared,
            CrossCityOperationState::Activating,
            CrossCityOperationState::InDoubt,
            CrossCityOperationState::Active,
            CrossCityOperationState::Rejected,
            CrossCityOperationState::Deferred,
            CrossCityOperationState::Quarantined,
            CrossCityOperationState::Expired,
        ] {
            assert!(Phase::parse_str(state.as_str()).is_err());
        }
    }

    #[test]
    fn delivery_status_wire_strings_strict_parse_and_serde() {
        use CrossCityDeliveryStatus as Status;

        // Exact wire/DB strings, in canonical order.
        let expected = [
            (Status::Pending, "PENDING"),
            (Status::Leased, "LEASED"),
            (Status::InDoubt, "IN_DOUBT"),
            (Status::Succeeded, "SUCCEEDED"),
            (Status::Quarantined, "QUARANTINED"),
        ];
        assert_eq!(Status::ALL.len(), expected.len());
        for (index, (status, spelling)) in expected.iter().enumerate() {
            assert_eq!(Status::ALL[index], *status);
            assert_eq!(status.as_str(), *spelling);
            assert_eq!(Status::parse_str(spelling).unwrap(), *status);
            let encoded = format!("\"{spelling}\"");
            assert_eq!(serde_json::to_string(status).unwrap(), encoded);
            assert_eq!(serde_json::from_str::<Status>(&encoded).unwrap(), *status);
        }

        // Strict parsing rejects unknown values and case drift.
        for drifted in [
            "pending",
            "Leased",
            "in_doubt",
            "IN-DOUBT",
            "DONE",
            "",
            "SUCCEEDED ",
        ] {
            assert!(matches!(
                Status::parse_str(drifted),
                Err(CrossCityContractError::UnknownDeliveryStatus { .. })
            ));
            assert!(serde_json::from_str::<Status>(&format!("\"{drifted}\"")).is_err());
        }

        // Only SUCCEEDED is terminal; every other status keeps a guarded way
        // forward (worker flow, reconcile, or operator requeue).
        assert!(Status::Succeeded.is_terminal());
        for status in [
            Status::Pending,
            Status::Leased,
            Status::InDoubt,
            Status::Quarantined,
        ] {
            assert!(!status.is_terminal());
        }
    }

    #[test]
    fn delivery_status_worker_transition_matrix_is_exhaustive() {
        use CrossCityDeliveryStatus as Status;

        // The exact worker allowlist: lease, release after a known
        // no-external-result failure, mark unknown, complete with proof,
        // quarantine on deterministic conflict / budget exhaustion.
        let allowed = |from: Status, to: Status| {
            matches!(
                (from, to),
                (Status::Pending, Status::Leased)
                    | (Status::Leased, Status::Pending)
                    | (Status::Leased, Status::InDoubt)
                    | (Status::Leased, Status::Succeeded)
                    | (Status::Leased, Status::Quarantined)
            )
        };
        for from in Status::ALL {
            for to in Status::ALL {
                assert_eq!(
                    from.transition_by_worker(to).is_ok(),
                    allowed(from, to),
                    "worker {from:?} -> {to:?}"
                );
                if !allowed(from, to) {
                    assert!(matches!(
                        from.transition_by_worker(to),
                        Err(CrossCityContractError::InvalidDeliveryTransition {
                            from: reported_from,
                            to: reported_to,
                            actor: "worker",
                        }) if reported_from == from.as_str() && reported_to == to.as_str()
                    ));
                }
            }
        }

        // Fail-closed core, asserted explicitly: an IN_DOUBT outcome is never
        // retried by the normal worker, and SUCCEEDED is terminal.
        for to in Status::ALL {
            assert!(Status::InDoubt.transition_by_worker(to).is_err());
            assert!(Status::Succeeded.transition_by_worker(to).is_err());
        }
    }

    #[test]
    fn delivery_status_reconcile_transition_matrix_is_exhaustive() {
        use CrossCityDeliveryStatus as Status;

        // The exact reconcile allowlist: only IN_DOUBT may be resolved, and
        // every resolution represents an independently proven fact.
        let allowed = |from: Status, to: Status| {
            matches!(
                (from, to),
                (Status::InDoubt, Status::Pending)
                    | (Status::InDoubt, Status::Succeeded)
                    | (Status::InDoubt, Status::Quarantined)
            )
        };
        for from in Status::ALL {
            for to in Status::ALL {
                assert_eq!(
                    from.transition_by_reconcile(to).is_ok(),
                    allowed(from, to),
                    "reconcile {from:?} -> {to:?}"
                );
                if !allowed(from, to) {
                    assert!(matches!(
                        from.transition_by_reconcile(to),
                        Err(CrossCityContractError::InvalidDeliveryTransition {
                            actor: "reconcile",
                            ..
                        })
                    ));
                }
            }
        }

        // Reconcile may never invent worker-owned or operator-owned
        // transitions: it acts only on IN_DOUBT and never leases anything.
        for to in Status::ALL {
            assert!(Status::Pending.transition_by_reconcile(to).is_err());
            assert!(Status::Leased.transition_by_reconcile(to).is_err());
        }
    }

    #[test]
    fn delivery_status_operator_transition_matrix_is_exhaustive() {
        use CrossCityDeliveryStatus as Status;

        // Exactly one operator transition: the QUARANTINED requeue.
        for from in Status::ALL {
            for to in Status::ALL {
                let ok = from == Status::Quarantined && to == Status::Pending;
                assert_eq!(
                    from.transition_by_operator(to).is_ok(),
                    ok,
                    "operator {from:?} -> {to:?}"
                );
                if !ok {
                    assert!(matches!(
                        from.transition_by_operator(to),
                        Err(CrossCityContractError::InvalidDeliveryTransition {
                            actor: "operator",
                            ..
                        })
                    ));
                }
            }
        }

        // The requeue only resets the delivery attempt; it never fabricates a
        // proof, and SUCCEEDED can never be reopened by anyone.
        assert_eq!(
            Status::Quarantined
                .transition_by_operator(Status::Pending)
                .unwrap(),
            Status::Pending
        );
        for to in Status::ALL {
            assert!(Status::Succeeded.transition_by_operator(to).is_err());
        }
    }

    #[test]
    fn message_identity_is_stable_domain_separated_and_golden_pinned() {
        // Golden vector: pins the exact domain header, field order, and
        // length-delimited encoding. The encoded form is
        // ASTRAL_CROSS_CITY_MESSAGE_IDENTITY_V1 + U+001F"36:"<operation_id> +
        // U+001F"4:VOTE" + U+001F"10:city-alpha" + U+001F"9:city-beta".
        let identity = CrossCityMessageIdentity::new(
            OPERATION_ID,
            CrossCityMessagePhase::Vote,
            CITY_ALPHA,
            CITY_BETA,
        )
        .unwrap();
        assert_eq!(
            identity.message_id,
            "68f01c7fad252d78c9201e4c95ac6ac45e57196b594bbf0d1cc7df83144d79b1"
        );
        assert_eq!(identity.message_id.len(), 64);
        assert!(identity
            .message_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
        assert!(identity.is_canonical());
        identity.validate().unwrap();

        // Retrying the exact same tuple is stable.
        let retried = CrossCityMessageIdentity::new(
            OPERATION_ID,
            CrossCityMessagePhase::Vote,
            CITY_ALPHA,
            CITY_BETA,
        )
        .unwrap();
        assert_eq!(retried, identity);
        assert_eq!(retried.message_id, identity.message_id);

        // Any tuple change produces a different id: phase, source,
        // destination, or operation.
        let phase_change = CrossCityMessageIdentity::new(
            OPERATION_ID,
            CrossCityMessagePhase::Prepare,
            CITY_ALPHA,
            CITY_BETA,
        )
        .unwrap();
        assert_ne!(phase_change.message_id, identity.message_id);
        let swapped = CrossCityMessageIdentity::new(
            OPERATION_ID,
            CrossCityMessagePhase::Vote,
            CITY_BETA,
            CITY_ALPHA,
        )
        .unwrap();
        assert_ne!(swapped.message_id, identity.message_id);
        let other_destination = CrossCityMessageIdentity::new(
            OPERATION_ID,
            CrossCityMessagePhase::Vote,
            CITY_ALPHA,
            "city-gamma",
        )
        .unwrap();
        assert_ne!(other_destination.message_id, identity.message_id);
        let other_operation = CrossCityMessageIdentity::new(
            OPERATION_ID_ALT,
            CrossCityMessagePhase::Vote,
            CITY_ALPHA,
            CITY_BETA,
        )
        .unwrap();
        assert_ne!(other_operation.message_id, identity.message_id);

        // The length-prefix/U+001F encoding is injective over the tuple:
        // moving text across a field boundary can never merge two tuples.
        let boundary_first =
            CrossCityMessageIdentity::new(OPERATION_ID, CrossCityMessagePhase::Vote, "x:1", "y")
                .unwrap();
        let boundary_second =
            CrossCityMessageIdentity::new(OPERATION_ID, CrossCityMessagePhase::Vote, "x", "1:y")
                .unwrap();
        assert_ne!(boundary_first.message_id, boundary_second.message_id);
        let split_first =
            CrossCityMessageIdentity::new(OPERATION_ID, CrossCityMessagePhase::Vote, "ab", "c")
                .unwrap();
        let split_second =
            CrossCityMessageIdentity::new(OPERATION_ID, CrossCityMessagePhase::Vote, "a", "bc")
                .unwrap();
        assert_ne!(split_first.message_id, split_second.message_id);

        // Domain separation: the same tuple under a different cross-city
        // header can never produce the message id.
        assert_ne!(
            derive_message_id(
                OPERATION_ID,
                CrossCityMessagePhase::Vote,
                CITY_ALPHA,
                CITY_BETA
            ),
            canonical_digest(
                PROPOSAL_DIGEST_HEADER,
                &[OPERATION_ID, "VOTE", CITY_ALPHA, CITY_BETA],
            )
        );
    }

    #[test]
    fn message_identity_rejects_invalid_fields_and_tampered_ids() {
        // Self-routed messages are rejected, including after normalization.
        assert!(matches!(
            CrossCityMessageIdentity::new(
                OPERATION_ID,
                CrossCityMessagePhase::Vote,
                CITY_ALPHA,
                CITY_ALPHA
            ),
            Err(CrossCityContractError::SelfRoutedMessage { city_id })
                if city_id == CITY_ALPHA
        ));
        assert!(matches!(
            CrossCityMessageIdentity::new(
                OPERATION_ID,
                CrossCityMessagePhase::Vote,
                " city-x ",
                "city-x"
            ),
            Err(CrossCityContractError::SelfRoutedMessage { city_id })
                if city_id == "city-x"
        ));

        // The operation id must be a canonical non-nil lowercase UUID.
        for bad_operation in [
            "550E8400-E29B-41D4-A716-446655440000",
            "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
            "not-a-uuid",
            "00000000-0000-0000-0000-000000000000",
        ] {
            assert!(CrossCityMessageIdentity::new(
                bad_operation,
                CrossCityMessagePhase::Vote,
                CITY_ALPHA,
                CITY_BETA
            )
            .is_err());
        }

        // City ids follow the existing identifier bounds: non-empty, no
        // whitespace/control characters, at most IDENTIFIER_MAX_LEN bytes.
        assert!(matches!(
            CrossCityMessageIdentity::new(
                OPERATION_ID,
                CrossCityMessagePhase::Vote,
                "   ",
                CITY_BETA
            ),
            Err(CrossCityContractError::EmptyIdentifier {
                field: "source_city_id"
            })
        ));
        assert!(matches!(
            CrossCityMessageIdentity::new(
                OPERATION_ID,
                CrossCityMessagePhase::Vote,
                CITY_ALPHA,
                "city\u{1F}x"
            ),
            Err(CrossCityContractError::MalformedIdentifier {
                field: "destination_city_id"
            })
        ));
        assert!(matches!(
            CrossCityMessageIdentity::new(
                OPERATION_ID,
                CrossCityMessagePhase::Vote,
                CITY_ALPHA,
                &"y".repeat(IDENTIFIER_MAX_LEN + 1)
            ),
            Err(CrossCityContractError::IdentifierTooLong {
                field: "destination_city_id"
            })
        ));

        // A caller-tampered message_id is rejected by validate and by
        // canonicalized, and reported as non-canonical - never repaired,
        // never trusted.
        let mut tampered = CrossCityMessageIdentity::new(
            OPERATION_ID,
            CrossCityMessagePhase::Vote,
            CITY_ALPHA,
            CITY_BETA,
        )
        .unwrap();
        tampered.message_id = digest(0x0b);
        assert!(matches!(
            tampered.validate(),
            Err(CrossCityContractError::DigestMismatch {
                field: "message_id",
                ..
            })
        ));
        assert!(matches!(
            tampered.canonicalized(),
            Err(CrossCityContractError::DigestMismatch {
                field: "message_id",
                ..
            })
        ));
        assert!(!tampered.is_canonical());

        // Tampering with a tuple field is caught the same way: the stored id
        // no longer matches the recomputation over the stored values.
        let mut tampered_field = CrossCityMessageIdentity::new(
            OPERATION_ID,
            CrossCityMessagePhase::Vote,
            CITY_ALPHA,
            CITY_BETA,
        )
        .unwrap();
        tampered_field.destination_city_id = "city-gamma".to_owned();
        assert!(matches!(
            tampered_field.validate(),
            Err(CrossCityContractError::DigestMismatch {
                field: "message_id",
                ..
            })
        ));

        // A self-consistent but padded (non-canonical) serialization
        // validates as received, but is not canonical and rebuilds to a
        // different id over the trimmed values.
        let mut padded = CrossCityMessageIdentity::new(
            OPERATION_ID,
            CrossCityMessagePhase::Vote,
            CITY_ALPHA,
            CITY_BETA,
        )
        .unwrap();
        padded.source_city_id = format!(" {CITY_ALPHA} ");
        padded.message_id = derive_message_id(
            &padded.operation_id,
            padded.phase,
            &padded.source_city_id,
            &padded.destination_city_id,
        );
        assert!(padded.validate().is_ok());
        assert!(!padded.is_canonical());
        let rebuilt = padded.canonicalized().unwrap();
        assert_ne!(rebuilt.message_id, padded.message_id);
        assert_eq!(rebuilt.source_city_id, CITY_ALPHA);
        assert!(rebuilt.is_canonical());

        // Serde roundtrip preserves the identity and stays valid, canonical,
        // and in camelCase wire form with the exact phase spelling.
        let identity = CrossCityMessageIdentity::new(
            OPERATION_ID,
            CrossCityMessagePhase::CommitConfirmed,
            CITY_ALPHA,
            CITY_BETA,
        )
        .unwrap();
        let encoded = serde_json::to_string(&identity).unwrap();
        assert!(encoded.contains("\"messageId\""));
        assert!(encoded.contains("\"phase\":\"COMMIT_CONFIRMED\""));
        let decoded: CrossCityMessageIdentity = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, identity);
        decoded.validate().unwrap();
        assert!(decoded.is_canonical());
    }

    #[test]
    fn message_identity_validate_rejects_padded_self_route_on_normalized_values() {
        // `validate` must decide the self-route question on the NORMALIZED
        // source/destination values, not the raw stored spellings: a wire/
        // deserialized struct whose source and destination differ only by
        // trim-stripped padding normalizes to the SAME city and is a
        // self-routed message, even when its message_id is self-consistent
        // over the raw (padded) stored tuple.
        for (raw_source, raw_destination) in
            [(" city-alpha ", "city-alpha"), (CITY_ALPHA, " city-alpha ")]
        {
            let padded = CrossCityMessageIdentity {
                operation_id: OPERATION_ID.to_owned(),
                phase: CrossCityMessagePhase::Vote,
                source_city_id: raw_source.to_owned(),
                destination_city_id: raw_destination.to_owned(),
                message_id: derive_message_id(
                    OPERATION_ID,
                    CrossCityMessagePhase::Vote,
                    raw_source,
                    raw_destination,
                ),
            };
            // The stored id is self-consistent over the padded tuple…
            assert!(matches!(
                padded.validate(),
                Err(CrossCityContractError::SelfRoutedMessage { city_id })
                    if city_id == CITY_ALPHA
            ));
        }
        // Control: padding over two GENUINELY different cities stays valid
        // (consistency holds, the normalized route is cross-city); canonical
        // FORM is a separate concern proven by `is_canonical`.
        let mut padded = CrossCityMessageIdentity::new(
            OPERATION_ID,
            CrossCityMessagePhase::Vote,
            CITY_ALPHA,
            CITY_BETA,
        )
        .unwrap();
        padded.source_city_id = format!(" {CITY_ALPHA} ");
        padded.message_id = derive_message_id(
            &padded.operation_id,
            padded.phase,
            &padded.source_city_id,
            &padded.destination_city_id,
        );
        assert!(padded.validate().is_ok());
        assert!(!padded.is_canonical());
    }

    #[test]
    fn normalize_identifier_rejects_unicode_format_characters() {
        // Representative Unicode General_Category=Cf (format) characters from
        // every banned range: invisible, trim-surviving, and able to make two
        // visually identical ids disagree at the byte level. Prefix, middle,
        // and suffix positions are all refused.
        let format_probes = [
            '\u{00AD}',  // SOFT HYPHEN
            '\u{0600}',  // Arabic number sign
            '\u{061C}',  // ARABIC LETTER MARK
            '\u{06DD}',  // ARABIC END OF AYAH
            '\u{070F}',  // SYRIAC ABBREVIATION MARK
            '\u{0890}',  // Arabic pound sign
            '\u{08E2}',  // ARABIC DISPUTED END OF AYAH
            '\u{180E}',  // MONGOLIAN VOWEL SEPARATOR
            '\u{200B}',  // ZERO WIDTH SPACE
            '\u{200E}',  // LEFT-TO-RIGHT MARK
            '\u{202E}',  // RIGHT-TO-LEFT OVERRIDE
            '\u{2060}',  // WORD JOINER
            '\u{2066}',  // LEFT-TO-RIGHT ISOLATE
            '\u{FEFF}',  // ZERO WIDTH NO-BREAK SPACE
            '\u{FFF9}',  // INTERLINEAR ANNOTATION ANCHOR
            '\u{110BD}', // KAITHI NUMBER SIGN
            '\u{110CD}', // KAITHI NUMBER SIGN ABOVE
            '\u{13430}', // Egyptian hieroglyph format control
            '\u{1BCA0}', // shorthand format control
            '\u{1D173}', // musical format control
            '\u{E0001}', // LANGUAGE TAG
            '\u{E0020}', // tag character
        ];
        for probe in format_probes {
            for (position, spelling) in [
                ("prefix", format!("{probe}city")),
                ("middle", format!("ci{probe}ty")),
                ("suffix", format!("city{probe}")),
            ] {
                assert!(
                    normalize_identifier(&spelling, "city_id").is_err(),
                    "Cf probe at {position} must be refused: U+{:04X}",
                    probe as u32
                );
                assert!(matches!(
                    normalize_identifier(&spelling, "city_id"),
                    Err(CrossCityContractError::MalformedIdentifier { field: "city_id" })
                ));
            }
        }
        // The rejection is inherited by the public contract surfaces that
        // normalize these fields: message identity source/destination…
        assert!(CrossCityMessageIdentity::new(
            OPERATION_ID,
            CrossCityMessagePhase::Vote,
            "city\u{200B}-a",
            CITY_BETA
        )
        .is_err());
        assert!(CrossCityMessageIdentity::new(
            OPERATION_ID,
            CrossCityMessagePhase::Vote,
            CITY_ALPHA,
            "city\u{FEFF}-b"
        )
        .is_err());
        // …node evidence (node id and signature blob)…
        let proposal = proposal();
        let evidence = ZeroDecisionEvidence::new(
            CITY_ALPHA,
            "node\u{200C}x",
            3,
            NodeDecision::Allow,
            &proposal.proposal_digest().unwrap(),
            &proposal.base_frontier_digest,
            &proposal.mutation_digest,
            "nonce-1",
            EXPIRES_AT,
            &format!("sig-{}", '\u{2060}'),
        );
        assert!(evidence.is_err());
        // …and compiler/policy version fields of a proposal.
        assert!(MutationProposal::new(
            OPERATION_ID,
            &digest(0x01),
            &digest(0x02),
            &digest(0x03),
            &digest(0x04),
            4,
            1,
            5,
            1,
            "compiler\u{00AD}-1",
            "policy-1",
            EXPIRES_AT,
        )
        .is_err());
        // Legitimate Unicode letters and digits are NOT format characters and
        // stay fully usable in every language.
        for legit in ["北京-节点-1", "münchen-2", "мост-3", "مدينة-4", "Ω-5"] {
            assert_eq!(
                normalize_identifier(legit, "city_id").unwrap(),
                *legit,
                "legitimate Unicode identifier must not be refused"
            );
        }
    }

    #[test]
    fn cross_city_payload_digest_is_raw_bytes_sha256_golden() {
        // Published SHA-256 vectors over the exact bytes (FIPS 180 empty
        // vector and the classic "abc" vector): the digest is raw SHA-256 of
        // the wire bytes with no domain header and no canonicalization.
        assert_eq!(
            cross_city_payload_digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            cross_city_payload_digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        // Deterministic for identical bytes.
        let payload = b"{\"operationId\":\"550e8400-e29b-41d4-a716-446655440000\"}";
        assert_eq!(
            cross_city_payload_digest(payload),
            cross_city_payload_digest(payload)
        );

        // Sensitive to every byte of the actual wire form: JSON is never
        // re-canonicalized in between, so even whitespace changes the digest,
        // and any tampered payload is detectable.
        assert_ne!(
            cross_city_payload_digest(b"{\"a\":1}"),
            cross_city_payload_digest(b"{ \"a\" : 1 }")
        );
        assert_ne!(
            cross_city_payload_digest(b"grant-payload"),
            cross_city_payload_digest(b"grant-payload-tampered")
        );

        // Output shape: exactly 64 lowercase hex characters.
        let digest = cross_city_payload_digest(b"abc");
        assert_eq!(digest.len(), 64);
        assert!(digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
    }

    // ===== conflict outcome/reason shared enums + audit record =====

    #[test]
    fn conflict_outcome_and_reason_wire_contract_is_stable() {
        // Compile-time exhaustive shape: exactly Reject and Defer - and never
        // an allow variant - or this match fails to build.
        fn outcome_code(outcome: CrossCityConflictOutcome) -> &'static str {
            match outcome {
                CrossCityConflictOutcome::Reject => "REJECT",
                CrossCityConflictOutcome::Defer => "DEFER",
            }
        }
        assert_eq!(CrossCityConflictOutcome::Reject.as_str(), "REJECT");
        assert_eq!(CrossCityConflictOutcome::Defer.as_str(), "DEFER");
        assert_eq!(outcome_code(CrossCityConflictOutcome::Reject), "REJECT");
        assert_eq!(outcome_code(CrossCityConflictOutcome::Defer), "DEFER");
        assert_eq!(CrossCityConflictOutcome::Reject.to_string(), "REJECT");
        assert_eq!(CrossCityConflictOutcome::Defer.to_string(), "DEFER");
        for outcome in [
            CrossCityConflictOutcome::Reject,
            CrossCityConflictOutcome::Defer,
        ] {
            let encoded = format!("\"{}\"", outcome.as_str());
            assert_eq!(serde_json::to_string(&outcome).unwrap(), encoded);
            assert_eq!(
                serde_json::from_str::<CrossCityConflictOutcome>(&encoded).unwrap(),
                outcome
            );
        }
        // Unknown outcome tokens are rejected at the serde boundary.
        for drifted in ["ALLOW", "APPROVE", "reject", "DEFER ", ""] {
            assert!(
                serde_json::from_str::<CrossCityConflictOutcome>(&format!("\"{drifted}\""))
                    .is_err()
            );
        }

        // The 15 reason codes: stable order, exact spelling, serde wire form,
        // Display, and closed outcome pairing (5 defer, 10 reject).
        const EXPECTED_CODES: [&str; 15] = [
            "EVIDENCE_MISSING",
            "EVIDENCE_COUNT_INVALID",
            "EVIDENCE_EXPIRED",
            "EVIDENCE_UNVERIFIABLE",
            "ARBITER_ALLOW_OUT_OF_SCOPE",
            "OPERATION_MISMATCH",
            "SCOPE_MISMATCH",
            "FRONTIER_MISMATCH",
            "MUTATION_MISMATCH",
            "EXPIRY_MISMATCH",
            "DECISION_MISMATCH",
            "NODE_IDENTITY_INVALID",
            "CITY_IDENTITY_DUPLICATE",
            "SIGNATURE_INVALID",
            "CERTIFICATE_INVALID",
        ];
        assert_eq!(CrossCityConflictReason::ALL.len(), EXPECTED_CODES.len());
        for (index, reason) in CrossCityConflictReason::ALL.iter().enumerate() {
            assert_eq!(reason.as_str(), EXPECTED_CODES[index]);
            assert_eq!(reason.to_string(), reason.as_str());
            let encoded = format!("\"{}\"", reason.as_str());
            assert_eq!(serde_json::to_string(reason).unwrap(), encoded);
            assert_eq!(
                serde_json::from_str::<CrossCityConflictReason>(&encoded).unwrap(),
                *reason
            );
            assert!(matches!(
                reason.outcome(),
                CrossCityConflictOutcome::Reject | CrossCityConflictOutcome::Defer
            ));
        }
        let defer_count = CrossCityConflictReason::ALL
            .iter()
            .filter(|reason| reason.outcome() == CrossCityConflictOutcome::Defer)
            .count();
        let reject_count = CrossCityConflictReason::ALL
            .iter()
            .filter(|reason| reason.outcome() == CrossCityConflictOutcome::Reject)
            .count();
        assert_eq!(defer_count, 5);
        assert_eq!(reject_count, 10);
        // Unknown reason tokens are rejected at the serde boundary.
        for drifted in [
            "EVIDENCE_ABSENT",
            "evidence_missing",
            "OPERATION_MISMATCH ",
            "",
        ] {
            assert!(
                serde_json::from_str::<CrossCityConflictReason>(&format!("\"{drifted}\"")).is_err()
            );
        }
    }

    #[test]
    fn conflict_audit_record_copies_canonical_proposal_for_reject_and_defer() {
        let value = proposal();
        let expected_digest = value.proposal_digest().unwrap();

        let reject = CrossCityConflictAuditRecord::new(
            &value,
            CrossCityConflictOutcome::Reject,
            CrossCityConflictReason::OperationMismatch,
            NOW,
        )
        .unwrap();
        assert_eq!(reject.event_id.len(), 64);
        assert!(reject
            .event_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
        assert_eq!(reject.proposal_digest, expected_digest);
        assert_eq!(reject.operation_id, OPERATION_ID);
        assert_eq!(reject.scope_digest, digest(0x01));
        assert_eq!(reject.request_digest, digest(0x02));
        assert_eq!(reject.mutation_digest, digest(0x03));
        assert_eq!(reject.base_frontier_digest, digest(0x04));
        assert_eq!(reject.base_source_generation, 4);
        assert_eq!(reject.base_revoke_fence, 1);
        assert_eq!(reject.target_generation, 5);
        assert_eq!(reject.target_revoke_fence, 1);
        assert_eq!(reject.compiler_version, "compiler-1");
        assert_eq!(reject.policy_version, "policy-1");
        assert_eq!(reject.expires_at, EXPIRES_AT);
        assert_eq!(reject.outcome, CrossCityConflictOutcome::Reject);
        assert_eq!(
            reject.reason_code,
            CrossCityConflictReason::OperationMismatch
        );
        assert_eq!(reject.observed_at_seconds, NOW);
        reject.validate().unwrap();

        let defer = CrossCityConflictAuditRecord::new(
            &value,
            CrossCityConflictOutcome::Defer,
            CrossCityConflictReason::ArbiterAllowOutOfScope,
            NOW,
        )
        .unwrap();
        defer.validate().unwrap();
        assert_ne!(defer.event_id, reject.event_id);
        assert_eq!(defer.proposal_digest, expected_digest);

        // Serde roundtrip stays valid, in the camelCase wire form with the
        // exact SCREAMING_SNAKE_CASE outcome/reason spellings.
        let encoded = serde_json::to_string(&reject).unwrap();
        assert!(encoded.contains("\"eventId\""));
        assert!(encoded.contains("\"proposalDigest\""));
        assert!(encoded.contains("\"outcome\":\"REJECT\""));
        assert!(encoded.contains("\"reasonCode\":\"OPERATION_MISMATCH\""));
        assert!(encoded.contains("\"observedAtSeconds\""));
        let decoded: CrossCityConflictAuditRecord = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, reject);
        decoded.validate().unwrap();
    }

    #[test]
    fn conflict_audit_event_id_is_deterministic_time_independent_and_golden_pinned() {
        let value = proposal();
        // Golden proposal digest of the fixture (pins the shared encoder).
        assert_eq!(
            value.proposal_digest().unwrap(),
            "4866375f4b463dd988a0760455c13392a6320aa4ab552af0f30ebbe9b0f4222f"
        );

        // Golden vectors pin the versioned audit domain, field order, and
        // length-delimited encoding of the event id.
        let stale = CrossCityConflictAuditRecord::new(
            &value,
            CrossCityConflictOutcome::Defer,
            CrossCityConflictReason::EvidenceExpired,
            1,
        )
        .unwrap();
        assert_eq!(
            stale.event_id,
            "d3e2d3d3edae8d1370e4d5c8f0c47ab8d8de000d3913f918d49e3c689f50da4a"
        );
        let reject = CrossCityConflictAuditRecord::new(
            &value,
            CrossCityConflictOutcome::Reject,
            CrossCityConflictReason::OperationMismatch,
            1,
        )
        .unwrap();
        assert_eq!(
            reject.event_id,
            "2b2d9aa9bb406d975bceba706c744de9d4b23d420900b0430540b6b6735de428"
        );

        // Determinism and time independence: the same verdict at a different
        // observed time reproduces the same event_id (retry identity).
        let retried = CrossCityConflictAuditRecord::new(
            &value,
            CrossCityConflictOutcome::Defer,
            CrossCityConflictReason::EvidenceExpired,
            42,
        )
        .unwrap();
        assert_ne!(retried.observed_at_seconds, stale.observed_at_seconds);
        assert_eq!(retried.event_id, stale.event_id);

        // Every identity input changes the event id: outcome, reason, proposal
        // content, and operation.
        assert_ne!(
            CrossCityConflictAuditRecord::new(
                &value,
                CrossCityConflictOutcome::Defer,
                CrossCityConflictReason::EvidenceUnverifiable,
                1,
            )
            .unwrap()
            .event_id,
            stale.event_id
        );
        assert_ne!(reject.event_id, stale.event_id);
        let other_operation = try_proposal(OPERATION_ID_ALT).unwrap();
        assert_ne!(
            CrossCityConflictAuditRecord::new(
                &other_operation,
                CrossCityConflictOutcome::Defer,
                CrossCityConflictReason::EvidenceExpired,
                1,
            )
            .unwrap()
            .event_id,
            stale.event_id
        );

        // Domain separation: the event id is not any other digest of the same
        // record content.
        assert_ne!(stale.event_id, stale.proposal_digest);
        assert_ne!(
            stale.event_id,
            canonical_digest(
                PROPOSAL_DIGEST_HEADER,
                &[
                    stale.operation_id.as_str(),
                    stale.proposal_digest.as_str(),
                    stale.outcome.as_str(),
                    stale.reason_code.as_str(),
                ]
            )
        );
    }

    #[test]
    fn conflict_audit_record_rejects_tampering_and_bad_inputs() {
        let value = proposal();
        let record = CrossCityConflictAuditRecord::new(
            &value,
            CrossCityConflictOutcome::Reject,
            CrossCityConflictReason::ScopeMismatch,
            NOW,
        )
        .unwrap();

        // Tampered event_id: the recomputation no longer matches.
        let mut tampered = record.clone();
        tampered.event_id = digest(0x0b);
        assert!(matches!(
            tampered.validate(),
            Err(CrossCityConflictAuditError::EventIdMismatch { .. })
        ));

        // Tampered copied field: the reconstructed proposal digest no longer
        // matches the stored proposal_digest.
        let mut tampered = record.clone();
        tampered.scope_digest = digest(0x0e);
        assert!(matches!(
            tampered.validate(),
            Err(CrossCityConflictAuditError::Contract(
                CrossCityContractError::DigestMismatch {
                    field: "proposal_digest",
                    ..
                }
            ))
        ));

        // Tampered proposal_digest itself.
        let mut tampered = record.clone();
        tampered.proposal_digest = digest(0x0f);
        assert!(matches!(
            tampered.validate(),
            Err(CrossCityConflictAuditError::Contract(
                CrossCityContractError::DigestMismatch {
                    field: "proposal_digest",
                    ..
                }
            ))
        ));

        // Tampered generation: the digest binding catches it.
        let mut tampered = record.clone();
        tampered.target_generation = 6;
        assert!(matches!(
            tampered.validate(),
            Err(CrossCityConflictAuditError::Contract(
                CrossCityContractError::DigestMismatch {
                    field: "proposal_digest",
                    ..
                }
            ))
        ));

        // Tampered operation id (still a valid UUID): the digest binding
        // catches it, because the event id and proposal digest both bind it.
        let mut tampered = record.clone();
        tampered.operation_id = OPERATION_ID_ALT.to_owned();
        assert!(matches!(
            tampered.validate(),
            Err(CrossCityConflictAuditError::Contract(
                CrossCityContractError::DigestMismatch {
                    field: "proposal_digest",
                    ..
                }
            ))
        ));

        // Padded (non-canonical) copied field: the reconstruction trims it, so
        // it no longer equals the stored value - rejected, never repaired.
        let mut padded = record.clone();
        padded.compiler_version = " compiler-1".to_owned();
        assert!(matches!(
            padded.validate(),
            Err(CrossCityConflictAuditError::Contract(
                CrossCityContractError::NonCanonicalForm { .. }
            ))
        ));

        // Non-positive observed time.
        let mut tampered = record.clone();
        tampered.observed_at_seconds = 0;
        assert!(matches!(
            tampered.validate(),
            Err(CrossCityConflictAuditError::InvalidObservedTime { value: 0 })
        ));
        let mut tampered = record.clone();
        tampered.observed_at_seconds = -5;
        assert!(matches!(
            tampered.validate(),
            Err(CrossCityConflictAuditError::InvalidObservedTime { value: -5 })
        ));

        // Mismatched reason/outcome pairing is caught on validation (e.g. a
        // deserialized record with a flipped outcome).
        let mut tampered = record.clone();
        tampered.outcome = CrossCityConflictOutcome::Defer;
        assert!(matches!(
            tampered.validate(),
            Err(CrossCityConflictAuditError::ReasonOutcomeMismatch { .. })
        ));

        // Construction-side pairing mismatch: a defer-only reason can never be
        // paired with REJECT.
        assert!(matches!(
            CrossCityConflictAuditRecord::new(
                &value,
                CrossCityConflictOutcome::Reject,
                CrossCityConflictReason::EvidenceMissing,
                NOW,
            ),
            Err(CrossCityConflictAuditError::ReasonOutcomeMismatch {
                reason_code: "EVIDENCE_MISSING",
                expected_outcome: "DEFER",
                actual_outcome: "REJECT",
            })
        ));

        // Construction-side invalid observation time.
        assert!(matches!(
            CrossCityConflictAuditRecord::new(
                &value,
                CrossCityConflictOutcome::Reject,
                CrossCityConflictReason::ScopeMismatch,
                0,
            ),
            Err(CrossCityConflictAuditError::InvalidObservedTime { value: 0 })
        ));

        // A non-canonical proposal input is rejected, never repaired.
        let mut padded_proposal = value.clone();
        padded_proposal.compiler_version = " compiler-1".to_owned();
        assert!(matches!(
            CrossCityConflictAuditRecord::new(
                &padded_proposal,
                CrossCityConflictOutcome::Reject,
                CrossCityConflictReason::ScopeMismatch,
                NOW,
            ),
            Err(CrossCityConflictAuditError::Contract(
                CrossCityContractError::NonCanonicalForm { field: "proposal" }
            ))
        ));

        // A malformed proposal input fails closed.
        let mut malformed = value.clone();
        malformed.scope_digest = "not-a-digest".to_owned();
        assert!(CrossCityConflictAuditRecord::new(
            &malformed,
            CrossCityConflictOutcome::Reject,
            CrossCityConflictReason::ScopeMismatch,
            NOW,
        )
        .is_err());
    }

    #[test]
    fn conflict_audit_record_accepts_expired_proposals() {
        // The proposal expires before the observation time: audit must still
        // capture the stale evidence (no expiry check on the record path).
        let value = proposal();
        assert!(value.is_expired_at(EXPIRES_AT));
        let observed = EXPIRES_AT + 3_600;
        let record = CrossCityConflictAuditRecord::new(
            &value,
            CrossCityConflictOutcome::Defer,
            CrossCityConflictReason::EvidenceExpired,
            observed,
        )
        .unwrap();
        assert_eq!(record.expires_at, EXPIRES_AT);
        assert!(record.observed_at_seconds >= record.expires_at);
        record.validate().unwrap();

        // The stale record survives a serde roundtrip and stays valid.
        let encoded = serde_json::to_string(&record).unwrap();
        let decoded: CrossCityConflictAuditRecord = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, record);
        decoded.validate().unwrap();
    }

    #[test]
    fn conflict_audit_record_diagnostics_do_not_leak_caller_text() {
        const MARKER: &str = "LEAK_MARKER_7f3a";
        let marked = MutationProposal::new(
            OPERATION_ID,
            &digest(0x01),
            &digest(0x02),
            &digest(0x03),
            &digest(0x04),
            4,
            1,
            5,
            1,
            MARKER,
            MARKER,
            EXPIRES_AT,
        )
        .unwrap();
        let record = CrossCityConflictAuditRecord::new(
            &marked,
            CrossCityConflictOutcome::Reject,
            CrossCityConflictReason::ScopeMismatch,
            NOW,
        )
        .unwrap();
        // The marker IS carried in the durable evidence fields...
        assert_eq!(record.compiler_version, MARKER);
        assert_eq!(record.policy_version, MARKER);
        // ...but never surfaces through Debug/Display of the record or of its
        // closed enums (the only free-text fields are redacted in Debug, and
        // Display renders the event id plus the closed codes only).
        let rendered = format!(
            "{:?}|{}|{:?}|{}|{:?}|{}",
            record, record, record.outcome, record.outcome, record.reason_code, record.reason_code
        );
        assert!(!rendered.contains(MARKER));
        assert!(rendered.contains(record.event_id.as_str()));
        assert!(rendered.contains("REJECT"));
        assert!(rendered.contains("SCOPE_MISMATCH"));
    }

    #[test]
    fn conflict_audit_errors_redact_caller_controlled_payloads() {
        const MARKER: &str = "ERROR_LEAK_MARKER_7f3a";
        let errors = [
            CrossCityConflictAuditError::Contract(CrossCityContractError::DuplicateNode {
                city_id: MARKER.to_owned(),
                node_id: MARKER.to_owned(),
            }),
            CrossCityConflictAuditError::Contract(CrossCityContractError::DuplicateCity {
                city_id: MARKER.to_owned(),
            }),
            CrossCityConflictAuditError::Contract(CrossCityContractError::CityMismatch {
                expected: MARKER.to_owned(),
                actual: MARKER.to_owned(),
            }),
            CrossCityConflictAuditError::Contract(CrossCityContractError::DecisionNotAllow {
                node_id: MARKER.to_owned(),
                decision: "DENY",
            }),
            CrossCityConflictAuditError::Contract(CrossCityContractError::UnknownMessagePhase {
                value: MARKER.to_owned(),
            }),
            CrossCityConflictAuditError::Contract(CrossCityContractError::UnknownDeliveryStatus {
                value: MARKER.to_owned(),
            }),
            CrossCityConflictAuditError::Contract(CrossCityContractError::SelfRoutedMessage {
                city_id: MARKER.to_owned(),
            }),
            CrossCityConflictAuditError::EventIdMismatch {
                expected: MARKER.to_owned(),
                actual: MARKER.to_owned(),
            },
        ];

        for error in errors {
            let rendered = format!("{:?}|{}", error, error);
            assert!(!rendered.contains(MARKER));
            assert!(rendered.contains(error.code()));
        }
    }

    #[test]
    fn conflict_audit_record_shape_guard_is_closed_and_tenant_free() {
        const SOURCE: &str = include_str!("cross_city.rs");
        let struct_start = SOURCE
            .find("pub struct CrossCityConflictAuditRecord {")
            .expect("audit record struct exists");
        let struct_end = struct_start
            + SOURCE[struct_start..]
                .find("\n}")
                .expect("audit record struct ends");
        let struct_block = &SOURCE[struct_start..struct_end];

        // No tenant binding: proposal/certificate inputs carry no trusted
        // tenant; tenant binding is a later authenticated boundary.
        assert!(!struct_block.contains("tenant"));

        // Closed fields only: every field is a digest/id, a number, or a
        // closed shared enum. There is no free-form reason/detail/message
        // string field.
        for field in [
            "pub event_id",
            "pub proposal_digest",
            "pub operation_id",
            "pub scope_digest",
            "pub request_digest",
            "pub mutation_digest",
            "pub base_frontier_digest",
            "pub base_source_generation",
            "pub base_revoke_fence",
            "pub target_generation",
            "pub target_revoke_fence",
            "pub compiler_version",
            "pub policy_version",
            "pub expires_at",
            "pub outcome",
            "pub reason_code",
            "pub observed_at_seconds",
        ] {
            assert!(struct_block.contains(field), "missing closed field {field}");
        }
        assert!(!struct_block.contains("pub detail"));
        assert!(!struct_block.contains("pub reason_text"));
        assert!(!struct_block.contains("pub message"));
    }
}
