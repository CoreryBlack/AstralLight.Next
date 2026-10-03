//! Rust-owned grant revision / delta persistence primitives (Phase 3 / P1).
//!
//! This module is the durable boundary for the versioned mutable authorization
//! hot state described by [`astral_types`] grant contracts. It owns exactly two
//! tables created by migration
//! `20260825000002_incremental_projection_archive.sql`:
//!
//! - `authorization_grant_revision`: an append-only, immutable per-grant
//!   revision ledger (including tombstones). Existing revisions are never
//!   `UPDATE`d or deleted by this module.
//! - `authorization_delta_event`: a durable typed delta work queue with CAS
//!   lease claim / mark / release semantics for the future incremental
//!   projection worker.
//!
//! The `authorization_impact_plan(_item)`, projection manifest chain and
//! archive outbox tables of the same migration are owned by
//! [`crate::authorization_projection_repository`] as of this slice; this module
//! never writes them. Both modules write ONLY the new Rust-owned tables of
//! migration `20260825000002_incremental_projection_archive.sql`. The legacy
//! `permission_rule_snapshot` / `rule_set_snapshot` tables, the legacy
//! `authorization_projection_head`/outbox path, MQ queues and caches stay under
//! the exclusive ownership of the existing worker — no statement here may touch
//! them (no double writer).
//!
//! # Canonical identity and hash boundary
//!
//! - SQL `grant_id CHAR(36)` stores the canonical text form of a typed
//!   [`astral_types::GrantId`]: lowercase hyphenated 36-character UUID, exactly
//!   as produced by [`astral_types::GrantId::as_str`]. Uppercase, braced,
//!   urn-prefixed, short or binary re-encodings are rejected on encode and
//!   decode ([`encode_grant_id_sql`] / [`decode_grant_id_sql`]).
//! - Every `*_hash` / `*_digest` / `lease_token_hash BINARY(32)` column stores
//!   a raw SHA-256 digest. The Rust wire form is the lowercase 64-character hex
//!   string; [`Sha256Digest`] is the single centralized round-trip-tested codec
//!   and rejects wrong lengths, non-hex characters and uppercase input.
//!
//! # Lock order (single MySQL session/transaction)
//!
//! All statements below are plain bind-parameter SQL with no client-side
//! string interpolation. Locks must be acquired in this fixed order:
//!
//! 1. `authorization_grant_revision`: latest revision of one aggregate + grant
//!    read `FOR UPDATE` before any append decision.
//! 2. `authorization_delta_event`: candidate row read `FOR UPDATE` during a
//!    lease claim; appends are arbitrated by the table's unique keys.
//! 3. `authorization_impact_plan(_item)`: untouched in this phase (P2).
//!
//! No network, Redis, RabbitMQ, compilation, retry loops or sleep/backoff work
//! runs inside these transactions; callers own commit/rollback and every
//! post-commit side effect.
//!
//! # Identity ownership
//!
//! Business identities (`operation_id`, `event_id`) are always caller-supplied
//! parameters; this repository never invents or substitutes them. The only
//! value generated here is the random run-scoped lease token of a claim
//! ([`DeltaLeaseToken`]), which exists solely to fence one lease: the database
//! stores only its SHA-256 hash. A message/MQ ACK never counts as durable
//! proof here; only an explicit worker mark transitions the queue status.
//!
//! # Failure policy
//!
//! Everything fails closed. Unknown/stale/gapped/duplicated revisions,
//! resurrection revisions that skip history, cross-tenant or cross-scope rows,
//! non-ACTIVE ledger status, malformed stored hashes or payloads, lease
//! owner/token/expiry mismatches and any affected_rows != 1 mutation surface as
//! explicit errors. Nothing silently skips rows, falls back to raw source
//! reads, or authorizes through older snapshots.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use policy_engine::{CompilerResult, HotState};
use sha2::{Digest, Sha256};
use sqlx::{Executor, MySql, Transaction};
use time::PrimitiveDateTime;
use uuid::Uuid;

use astral_types::{
    CanonicalGrant, DependencyVector, GrantDelta, GrantId, GrantRevision, GrantState, TenantScope,
    SYSTEM_ACTOR_ID,
};

/// Ledger row status allowed to receive new revisions.
pub const STATUS_ACTIVE: &str = "ACTIVE";
/// Delta event status while unclaimed.
pub const DELTA_STATUS_PENDING: &str = "PENDING";
/// Delta event status while leased to exactly one worker.
pub const DELTA_STATUS_LEASED: &str = "LEASED";
/// Terminal delta event status after a worker proves a durable result.
pub const DELTA_STATUS_SUCCEEDED: &str = "SUCCEEDED";
/// Operator-quarantined terminal delta event status (`QUARANTINED`).
///
/// The `status` column carries no CHECK constraint, so the type system and
/// every statement in this module enforce the vocabulary instead:
/// - [`claim_next_delta_event_in_tx`] only ever selects `PENDING` rows whose
///   backoff window elapsed or `LEASED` rows whose lease expired; a
///   quarantined row is never selectable again.
/// - [`load_claimed_delta_event_for_update_in_tx`] (read_claimed) accepts
///   `LEASED` rows only and re-checks the status inside its decode, so a
///   quarantined row can never be surfaced to a worker through recovery.
/// - Only [`requeue_quarantined_delta_event`] moves a row out of quarantine,
///   back to `PENDING`; no other mutation knows this state and nothing may
///   jump from `PENDING`/`SUCCEEDED` directly into it except
///   [`mark_delta_event_quarantined`] applied to a live lease.
///
/// Because the schema has no `quarantined_at` column, `updated_at`
/// (`ON UPDATE CURRENT_TIMESTAMP`) is the minimal durable terminal-state
/// timestamp evidence; the operator audit trail consists solely of
/// `event_id`/`operation_id`/`cas_version`/`last_error`. A full audit trail
/// would require a future ADDITIVE migration and is deliberately not invented
/// here (no standalone quarantine-audit table exists for delta events).
pub const DELTA_STATUS_QUARANTINED: &str = "QUARANTINED";

/// Column-width contracts mirrored from migration
/// `20260825000002_incremental_projection_archive.sql`.
pub const MAX_AGGREGATE_TYPE_LENGTH: usize = 32;
pub const MAX_EVENT_ID_LENGTH: usize = 128;
/// Grant-ledger operation identity width (disambiguated from quarantine).
pub const MAX_GRANT_OPERATION_ID_LENGTH: usize = 128;
pub const MAX_COMPILER_VERSION_LENGTH: usize = 64;
/// Grant delta lease owner width (disambiguated from quarantine).
pub const MAX_GRANT_LEASE_OWNER_LENGTH: usize = 128;
pub const MAX_LAST_ERROR_LENGTH: usize = 512;
/// Defensive capacity cap for any JSON document bound into a JSON column.
pub const MAX_JSON_BYTES: usize = 4 * 1024 * 1024;
/// Upper bound for one lease duration in seconds (mirrors quarantine policy).
pub const MAX_DELTA_LEASE_SECONDS: i64 = 3_600;
/// Upper bound for one failure backoff step in seconds.
pub const MAX_BACKOFF_SECONDS: i64 = 3_600;
/// Hard row cap for one ledger load (defense against unbounded scans).
pub const MAX_LEDGER_ROWS: i64 = 100_000;
/// Hard row cap for one status-filtered delta queue listing (operators only).
pub const MAX_DELTA_STATUS_LIST_ROWS: i64 = 500;

use std::collections::{BTreeMap, HashSet};

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Repository errors. Every variant is fail-closed; none authorizes anything.
#[derive(Debug, thiserror::Error)]
pub enum GrantRepositoryError {
    /// A shared grant contract rejected the input.
    #[error("grant contract validation failed: {0}")]
    Contract(#[from] astral_types::GrantContractError),

    /// Stored data violated its declared shape; refused instead of normalized.
    #[error("row mapping failed: {0}")]
    Mapping(String),

    /// A database driver error occurred.
    #[error("database query failed: {0}")]
    Query(#[from] sqlx::Error),

    /// A revision append was refused by the ledger transition rules.
    #[error("grant revision conflict: {0}")]
    RevisionConflict(#[from] LedgerTransitionConflict),

    /// Request fields disagreed with each other or with the declared scope.
    #[error("scope violation: {0}")]
    ScopeViolation(String),

    /// An insert lost the delta-event uniqueness race.
    #[error("duplicate delta event: {0}")]
    DuplicateDeltaEvent(String),

    /// A lease-guarded mutation matched zero rows (expired/stolen/unknown).
    #[error("delta lease CAS failed: {0}")]
    LeaseCasFailed(String),

    /// A row locked in the same transaction changed underneath a claim update.
    #[error("claim race while holding the row lock; refusing to continue")]
    ClaimRace,
}

// ─────────────────────────────────────────────────────────────────────────────
// Canonical SQL-boundary helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Encode a typed [`GrantId`] into the canonical `CHAR(36)` SQL wire form.
///
/// Returns the lowercase hyphenated UUID text guaranteed by `Uuid`'s Display
/// implementation; the typed contract still rejects nil identities.
pub fn encode_grant_id_sql(grant_id: GrantId) -> Result<String, GrantRepositoryError> {
    grant_id.validate()?;
    let encoded = grant_id.as_str();
    debug_assert_eq!(encoded.len(), 36);
    Ok(encoded)
}

/// Decode a `grant_id CHAR(36)` column back into a typed [`GrantId`].
///
/// Strictly accepts only the exact canonical spelling (36 lowercase hexadecimal
/// characters separated by hyphens in the UUID positions); anything else is
/// treated as poisoned storage rather than being repaired.
pub fn decode_grant_id_sql(value: &str) -> Result<GrantId, GrantRepositoryError> {
    let bytes = value.as_bytes();
    let hyphen_ok = |index: usize| index < bytes.len() && bytes[index] == b'-';
    let length_ok =
        bytes.len() == 36 && hyphen_ok(8) && hyphen_ok(13) && hyphen_ok(18) && hyphen_ok(23);
    let lowercase_ok = bytes.iter().enumerate().all(|(index, byte)| {
        hyphen_ok(index) || byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
    });
    if !length_ok || !lowercase_ok {
        return Err(GrantRepositoryError::Mapping(
            "code=grant_repository.invalid_char36_grant_id".to_owned(),
        ));
    }
    let parsed = GrantId::parse(value).map_err(|_| {
        GrantRepositoryError::Mapping("code=grant_repository.unparsable_char36_grant_id".to_owned())
    })?;
    if parsed.as_str() != value {
        return Err(GrantRepositoryError::Mapping(
            "code=grant_repository.noncanonical_char36_grant_id".to_owned(),
        ));
    }
    Ok(parsed)
}

/// One SHA-256 digest crossing the `BINARY(32)` SQL boundary.
///
/// Centralized codec between the lowercase hex wire form used by typed
/// contracts and the 32 raw bytes stored in MySQL columns.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Decode from the canonical lowercase 64-character hex wire form.
    pub fn from_hex(value: &str) -> Result<Self, GrantRepositoryError> {
        let lowercase_ok = value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !lowercase_ok {
            return Err(GrantRepositoryError::Mapping(
                "code=grant_repository.invalid_sha256_hex".to_owned(),
            ));
        }
        let mut bytes = [0u8; 32];
        for (index, chunk) in value.as_bytes().chunks(2).enumerate() {
            let high = hex_value(chunk[0]);
            let low = hex_value(chunk[1]);
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }

    /// Adopt 32 raw bytes read from a `BINARY(32)` column.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, GrantRepositoryError> {
        <[u8; 32]>::try_from(bytes).map(Self).map_err(|bytes| {
            GrantRepositoryError::Mapping(format!(
                "code=grant_repository.invalid_binary32;length={}",
                bytes.len()
            ))
        })
    }

    /// Optional-column adapter mirroring the fail-closed mapping policy.
    pub fn from_optional_bytes(value: Option<&[u8]>) -> Result<Option<Self>, GrantRepositoryError> {
        match value {
            None => Ok(None),
            Some(bytes) => Self::from_bytes(bytes.to_vec()).map(Some),
        }
    }

    /// Adopt an infallible 32-byte value (used by the lease-token hasher).
    pub fn from_raw_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Lowercase 64-character hex wire form used by typed contracts.
    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Raw digest bytes suitable for binding into `BINARY(32)` columns.
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Sha256Digest(")?;
        formatter.write_str(&self.as_hex())?;
        formatter.write_str(")")
    }
}

// Typed serde wire form: exactly the canonical lowercase 64-character hex
// string (`as_hex`), decoded strictly through `from_hex` (uppercase, wrong
// length, non-hex and non-lowercase input all fail closed). No bracketed or
// byte-array alternative forms exist, so a snapshot can never smuggle a
// divergent digest encoding past this single round-trip implementation.
impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.as_hex())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_hex(&value).map_err(serde::de::Error::custom)
    }
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0, // Callers validate the alphabet before decoding.
    }
}

fn sha256_digest_bytes(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

/// Bound a contract-side unsigned value into the signed `BIGINT` SQL domain.
fn bind_i64(value: u64, field: &'static str) -> Result<i64, GrantRepositoryError> {
    i64::try_from(value).map_err(|_| {
        GrantRepositoryError::Mapping(format!(
            "code=grant_repository.bigint_overflow;field={field}"
        ))
    })
}

fn positive_i64(value: i64, field: &'static str) -> Result<(), GrantRepositoryError> {
    if value <= 0 {
        return Err(GrantRepositoryError::ScopeViolation(format!(
            "code=grant_repository.non_positive_id;field={field};value={value}"
        )));
    }
    Ok(())
}

fn validated_text(
    value: &str,
    max_length: usize,
    field: &'static str,
) -> Result<(), GrantRepositoryError> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.len() > max_length
        || trimmed
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(GrantRepositoryError::ScopeViolation(format!(
            "code=grant_repository.invalid_field;field={field};max_length={max_length}"
        )));
    }
    Ok(())
}

fn validated_aggregate_type(value: &str) -> Result<(), GrantRepositoryError> {
    validated_text(value, MAX_AGGREGATE_TYPE_LENGTH, "aggregate_type")?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(GrantRepositoryError::ScopeViolation(
            "code=grant_repository.invalid_aggregate_type_charset".to_owned(),
        ));
    }
    Ok(())
}

fn validated_json(value: &str, field: &'static str) -> Result<(), GrantRepositoryError> {
    if value.len() > MAX_JSON_BYTES {
        return Err(GrantRepositoryError::ScopeViolation(format!(
            "code=grant_repository.json_too_large;field={field};limit={MAX_JSON_BYTES}"
        )));
    }
    serde_json::from_str::<serde_json::Value>(value).map_err(|error| {
        GrantRepositoryError::ScopeViolation(format!(
            "code=grant_repository.invalid_json;field={field};error={error}"
        ))
    })?;
    Ok(())
}

fn truncate_last_error(message: &str) -> String {
    message.chars().take(MAX_LAST_ERROR_LENGTH).collect()
}

fn db_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(|database| database.is_unique_violation())
}

/// Parse and fully validate one stored canonical grant payload.
///
/// Stored payloads were written through [`CanonicalGrant::canonical_input`];
/// rows that no longer reproduce their canonical form exactly are treated as
/// poisoned storage and refused instead of being quietly repaired.
pub fn decode_stored_grant_payload(payload: &str) -> Result<CanonicalGrant, GrantRepositoryError> {
    let grant: CanonicalGrant = serde_json::from_str(payload).map_err(|_| {
        GrantRepositoryError::Mapping("code=grant_repository.invalid_grant_payload".to_owned())
    })?;
    let canonical = grant.canonicalized()?;
    if grant != canonical {
        return Err(GrantRepositoryError::Mapping(
            "code=grant_repository.noncanonical_grant_payload".to_owned(),
        ));
    }
    Ok(grant)
}

/// Parse and validate one stored delta-event payload.
pub fn decode_delta_event_payload(payload: &str) -> Result<GrantDelta, GrantRepositoryError> {
    let delta: GrantDelta = serde_json::from_str(payload).map_err(|_| {
        GrantRepositoryError::Mapping("code=grant_repository.invalid_delta_payload".to_owned())
    })?;
    delta.validate().map_err(|_| {
        GrantRepositoryError::Mapping("code=grant_repository.invalid_delta_payload".to_owned())
    })?;
    Ok(delta)
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure ledger transition rules (mirror of the Phase 2 compiler semantics)
// ─────────────────────────────────────────────────────────────────────────────

/// The current durable head of one stable grant identity in the ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CurrentLedgerEntry {
    /// Highest persisted revision number for the identity.
    pub revision: GrantRevision,
    /// Lifecycle state carried by that latest revision payload.
    pub state: GrantState,
    /// Whether the row's `status` gate allows new revisions.
    pub status_active: bool,
}

/// Why a revision append was refused. Variant semantics mirror the Phase 2
/// compiler conflicts (`apply_deltas_to_records`) so database behavior and pure
/// behavior remain comparable:
///
/// - ADD over an ACTIVE record duplicates it; ADD over a tombstone is accepted
///   only as the strict revision successor ("resurrection"); ADD onto an empty
///   ledger requires revision 1 because durable history cannot hide
///   predecessors (strictly stronger than the pure compiler, which cannot see
///   whether history was lost outside its window).
/// - UPDATE demands an ACTIVE head and exact CAS equality; the payload revision
///   must already equal expected + 1 (enforced again below defensively).
/// - REMOVE/REVOKE demand an ACTIVE head plus exact CAS equality, refuse to
///   repeat an identical tombstone, refuse cross-kind tombstones, and yield the
///   successor revision.
/// - Any non-ACTIVE row `status` freezes the identity entirely (archive
///   awareness arrives with P2 and must never authorize through old rows).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LedgerTransitionConflict {
    /// UPDATE/REMOVE/REVOKE addressed an identity absent from the ledger.
    #[error("delta targets unknown grant {grant_id}")]
    UnknownGrant { grant_id: GrantId },
    /// ADD targeted an identity whose latest record is still ACTIVE.
    #[error("ADD targets an existing active grant {grant_id}")]
    DuplicateActiveGrant { grant_id: GrantId },
    /// The first revision of a fresh identity must be revision 1.
    #[error("first revision of {grant_id} must be 1, got {attempted}")]
    FirstRevisionNotInitial { grant_id: GrantId, attempted: u64 },
    /// Expected revision precedes the ledger head.
    #[error("stale expected revision {expected} behind ledger head {actual} for {grant_id}")]
    StaleExpectedRevision {
        grant_id: GrantId,
        expected: u64,
        actual: u64,
    },
    /// Expected revision exceeds the ledger head (missing history).
    #[error("gapped expected revision {expected} ahead of ledger head {actual} for {grant_id}")]
    GappedExpectedRevision {
        grant_id: GrantId,
        expected: u64,
        actual: u64,
    },
    /// Resurrecting ADD skipped or repeated past revisions.
    #[error(
        "resurrecting ADD for {grant_id} must advance to the strict successor, got {attempted}"
    )]
    ResurrectionRevisionConflict { grant_id: GrantId, attempted: u64 },
    /// Payload revision is not the structural successor demanded by the delta.
    #[error("payload revision {attempted} is not the required successor for {grant_id}")]
    PayloadRevisionMismatch { grant_id: GrantId, attempted: u64 },
    /// UPDATE addressed a record already carrying a tombstone state.
    #[error("UPDATE targets inactive grant {grant_id} in state {state:?}")]
    InactiveLedgerRecord {
        grant_id: GrantId,
        state: GrantState,
    },
    /// REMOVE/REVOKE repeated the tombstone already sitting at the head.
    #[error("identical tombstone already recorded for {grant_id} in state {state:?}")]
    DuplicateTombstone {
        grant_id: GrantId,
        state: GrantState,
    },
    /// REMOVE arrived for REVOKED (or vice versa) at the expected revision.
    #[error("cross-kind tombstone present for {grant_id} in state {state:?}")]
    CrossTombstoneKind {
        grant_id: GrantId,
        state: GrantState,
    },
    /// Row `status` is frozen; nothing may append to it.
    #[error("ledger row status is frozen for {grant_id}")]
    FrozenStatus { grant_id: GrantId },
    /// The delta failed typed-contract validation before reaching the ledger.
    #[error("delta failed typed-contract validation for {grant_id}")]
    ContractInvalid { grant_id: GrantId },
}

fn expectation_conflict(
    grant_id: GrantId,
    expected: GrantRevision,
    actual: GrantRevision,
) -> LedgerTransitionConflict {
    if expected.value() < actual.value() {
        LedgerTransitionConflict::StaleExpectedRevision {
            grant_id,
            expected: expected.value(),
            actual: actual.value(),
        }
    } else {
        LedgerTransitionConflict::GappedExpectedRevision {
            grant_id,
            expected: expected.value(),
            actual: actual.value(),
        }
    }
}

fn successor(grant_id: GrantId, revision: GrantRevision) -> Result<u64, LedgerTransitionConflict> {
    revision
        .next()
        .map(|next| next.value())
        .map_err(|_| LedgerTransitionConflict::ContractInvalid { grant_id })
}

/// Decide, purely, whether `delta` may be appended onto `current`, and the
/// immutable revision number the resulting row receives.
///
/// Precondition: `delta` passed [`GrantDelta::validate`]; the function repeats
/// that validation defensively and reports [`LedgerTransitionConflict::
/// ContractInvalid`] when the caller skipped it. ALLOW-only enforcement is part
/// of that contract validation (`ADD`/`UPDATE` payloads must be positive
/// grants; DENY is never representable).
pub fn decide_revision_transition(
    grant_id: GrantId,
    current: Option<CurrentLedgerEntry>,
    delta: &GrantDelta,
) -> Result<u64, LedgerTransitionConflict> {
    if delta.validate().is_err() {
        return Err(LedgerTransitionConflict::ContractInvalid { grant_id });
    }
    let attempted = delta
        .revision()
        .map(|revision| revision.value())
        .map_err(|_| LedgerTransitionConflict::ContractInvalid { grant_id })?;

    match (&current, delta) {
        (None, GrantDelta::Add { grant }) => {
            if grant.revision != GrantRevision::initial() {
                return Err(LedgerTransitionConflict::FirstRevisionNotInitial {
                    grant_id,
                    attempted,
                });
            }
            Ok(attempted)
        }
        (Some(entry), GrantDelta::Add { grant }) => {
            if !entry.status_active {
                return Err(LedgerTransitionConflict::FrozenStatus { grant_id });
            }
            if entry.state == GrantState::Active {
                return Err(LedgerTransitionConflict::DuplicateActiveGrant { grant_id });
            }
            let expected_successor = entry.revision.next().map_err(|_| {
                LedgerTransitionConflict::ResurrectionRevisionConflict {
                    grant_id,
                    attempted,
                }
            })?;
            if grant.revision != expected_successor {
                return Err(LedgerTransitionConflict::ResurrectionRevisionConflict {
                    grant_id,
                    attempted,
                });
            }
            Ok(attempted)
        }
        (None, _) => Err(LedgerTransitionConflict::UnknownGrant { grant_id }),
        (
            Some(entry),
            GrantDelta::Update {
                grant,
                expected_revision,
            },
        ) => {
            if !entry.status_active {
                return Err(LedgerTransitionConflict::FrozenStatus { grant_id });
            }
            if entry.revision != *expected_revision {
                return Err(expectation_conflict(
                    grant_id,
                    *expected_revision,
                    entry.revision,
                ));
            }
            if entry.state != GrantState::Active {
                return Err(LedgerTransitionConflict::InactiveLedgerRecord {
                    grant_id,
                    state: entry.state,
                });
            }
            if grant.revision
                != expected_revision
                    .next()
                    .map_err(|_| LedgerTransitionConflict::ContractInvalid { grant_id })?
            {
                return Err(LedgerTransitionConflict::PayloadRevisionMismatch {
                    grant_id,
                    attempted,
                });
            }
            Ok(attempted)
        }
        (
            Some(entry),
            GrantDelta::Remove {
                expected_revision, ..
            }
            | GrantDelta::Revoke {
                expected_revision, ..
            },
        ) => {
            if !entry.status_active {
                return Err(LedgerTransitionConflict::FrozenStatus { grant_id });
            }
            if entry.revision != *expected_revision {
                return Err(expectation_conflict(
                    grant_id,
                    *expected_revision,
                    entry.revision,
                ));
            }
            if entry.state != GrantState::Active {
                let same_kind = matches!(
                    (&entry.state, delta),
                    (GrantState::Removed, GrantDelta::Remove { .. })
                        | (GrantState::Revoked, GrantDelta::Revoke { .. })
                );
                return Err(if same_kind {
                    LedgerTransitionConflict::DuplicateTombstone {
                        grant_id,
                        state: entry.state,
                    }
                } else {
                    LedgerTransitionConflict::CrossTombstoneKind {
                        grant_id,
                        state: entry.state,
                    }
                });
            }
            successor(grant_id, *expected_revision)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Source revision append (fenced mutation primitive)
// ─────────────────────────────────────────────────────────────────────────────

/// Everything one fenced grant-revision append needs.
///
/// Business identity fields (`event_id`, `operation_id`) arrive from the
/// service boundary; the repository consumes but never generates them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRevisionAppendRequest {
    /// Physical tenant owning the aggregate. Must match the delta payload.
    pub tenant_id: i64,
    /// Card scope the writer believes it is mutating. When set, it must equal
    /// the card identity of the resulting record; removal/revoke requests use
    /// it to prove they target the intended card-scoped ledger entry.
    pub card_id_scope: Option<i64>,
    /// Aggregate family (for example `RULE_SET` or `CARD`).
    pub aggregate_type: String,
    /// Aggregate identity (> 0).
    pub aggregate_id: i64,
    /// Typed mutation validated against the shared contract.
    pub delta: GrantDelta,
    /// Durable event identity of the producing source event (<= 128 chars).
    pub event_id: String,
    /// Durable operation identity of the producing command (<= 128 chars).
    pub operation_id: String,
    /// Lowercase SHA-256 wire hash of the semantic content.
    pub semantic_hash_hex: String,
    /// Lowercase SHA-256 wire hash of the dependency vector.
    pub dependency_hash_hex: String,
    /// Semantic compiler version (<= 64 chars) that produced the payload.
    pub compiler_version: String,
}

/// Durable evidence returned by a successful revision append.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendedGrantRevision {
    pub revision_id: i64,
    pub grant_id: GrantId,
    pub tenant_id: i64,
    pub card_id: Option<i64>,
    pub aggregate_type: String,
    pub aggregate_id: i64,
    pub revision_no: u64,
    pub is_tombstone: bool,
}

/// Locked durable head snapshot of one stable grant identity.
///
/// Returned by [`read_grant_head_for_update_in_tx`]: the latest revision row is
/// already locked `FOR UPDATE` inside the caller's transaction, so callers may
/// safely use `payload` as the authoritative before-image and `entry` as the
/// CAS expectation for a subsequent append in the same transaction.
#[derive(Debug, Clone, PartialEq)]
pub struct GrantHeadSnapshot {
    pub grant_id: GrantId,
    /// Latest stored canonical payload (including tombstone payloads).
    pub payload: CanonicalGrant,
    /// Pure transition input derived from the latest revision row.
    pub entry: CurrentLedgerEntry,
}

/// Latest-revision read. `ORDER BY revision_no DESC LIMIT 1 FOR UPDATE` keeps
/// append decisions serialized per (tenant, aggregate, grant) identity; the
/// table's unique key blocks concurrent equal-revision inserts at commit time.
const REVISION_LATEST_FOR_UPDATE_SQL: &str = "SELECT revision_no, status, is_tombstone, \
    aggregate_type, aggregate_id, card_id, grant_id, CAST(grant_payload AS CHAR) AS grant_payload \
    FROM authorization_grant_revision \
    WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ? AND grant_id = ? \
    ORDER BY revision_no DESC LIMIT 1 FOR UPDATE";

/// Immutable append. Append-only: there is deliberately no UPDATE statement for
/// existing revisions anywhere in this module.
const GRANT_REVISION_INSERT_SQL: &str = "INSERT INTO authorization_grant_revision \
    (tenant_id, card_id, aggregate_type, aggregate_id, grant_id, revision_no, operation_id, \
     event_id, status, is_tombstone, grant_payload, semantic_hash, dependency_hash, \
     compiler_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

#[derive(Debug, sqlx::FromRow)]
struct LatestRevisionRow {
    revision_no: i64,
    status: String,
    is_tombstone: i8,
    aggregate_type: String,
    aggregate_id: i64,
    card_id: Option<i64>,
    grant_id: String,
    grant_payload: String,
}

impl LatestRevisionRow {
    fn decode(
        &self,
        expected_tenant_id: i64,
    ) -> Result<(GrantId, CanonicalGrant, CurrentLedgerEntry), GrantRepositoryError> {
        if self.revision_no <= 0 {
            return Err(GrantRepositoryError::Mapping(
                "code=grant_repository.invalid_revision_no".to_owned(),
            ));
        }
        let grant_id = decode_grant_id_sql(&self.grant_id)?;
        let payload = decode_stored_grant_payload(&self.grant_payload)?;
        if payload.grant_id != grant_id {
            return Err(GrantRepositoryError::Mapping(
                "code=grant_repository.payload_identity_mismatch".to_owned(),
            ));
        }
        if payload.revision.value() != self.revision_no as u64 {
            return Err(GrantRepositoryError::Mapping(
                "code=grant_repository.payload_revision_mismatch".to_owned(),
            ));
        }
        // The SELECT predicate carries this trusted tenant bind value; a
        // payload claiming another tenant is poisoned storage.
        if payload.tenant.tenant_id != expected_tenant_id {
            return Err(GrantRepositoryError::ScopeViolation(
                "code=grant_repository.cross_tenant_payload".to_owned(),
            ));
        }
        let persisted_flag = self.is_tombstone != 0;
        let payload_is_tombstone =
            matches!(payload.state, GrantState::Removed | GrantState::Revoked);
        if persisted_flag != payload_is_tombstone {
            return Err(GrantRepositoryError::Mapping(
                "code=grant_repository.tombstone_flag_mismatch".to_owned(),
            ));
        }
        if let Some(persisted_card) = self.card_id {
            if persisted_card != payload.card_id {
                return Err(GrantRepositoryError::Mapping(
                    "code=grant_repository.row_card_mismatch".to_owned(),
                ));
            }
        }
        let entry = CurrentLedgerEntry {
            revision: GrantRevision::new(self.revision_no as u64).map_err(|_| {
                GrantRepositoryError::Mapping(
                    "code=grant_repository.invalid_revision_no".to_owned(),
                )
            })?,
            state: payload.state,
            status_active: self.status == STATUS_ACTIVE,
        };
        Ok((grant_id, payload, entry))
    }
}

/// Validate all request-level scope/identity fields once, up front.
fn validate_revision_request(
    request: &GrantRevisionAppendRequest,
) -> Result<(Sha256Digest, Sha256Digest), GrantRepositoryError> {
    positive_i64(request.tenant_id, "tenant_id")?;
    positive_i64(request.aggregate_id, "aggregate_id")?;
    validated_aggregate_type(&request.aggregate_type)?;
    validated_text(&request.event_id, MAX_EVENT_ID_LENGTH, "event_id")?;
    validated_text(
        &request.operation_id,
        MAX_GRANT_OPERATION_ID_LENGTH,
        "operation_id",
    )?;
    validated_text(
        &request.compiler_version,
        MAX_COMPILER_VERSION_LENGTH,
        "compiler_version",
    )?;
    if let Some(card_id) = request.card_id_scope {
        positive_i64(card_id, "card_id_scope")?;
    }
    request.delta.validate()?;
    let semantic = Sha256Digest::from_hex(&request.semantic_hash_hex)?;
    let dependency = Sha256Digest::from_hex(&request.dependency_hash_hex)?;
    Ok((semantic, dependency))
}

/// Locked read of the durable head of one stable grant identity, inside the
/// caller's transaction.
///
/// Mirrors the lock the append primitive takes (`REVISION_LATEST_FOR_UPDATE_SQL`)
/// so a caller that needs the before-image / CAS expectation *before* building
/// its delta can serialize against every other writer of the same identity
/// without duplicating the transition logic. All strict decode rules apply:
/// cross-tenant/card/tombstone poisoning aborts instead of being normalized.
pub async fn read_grant_head_for_update_in_tx(
    tx: &mut Transaction<'_, MySql>,
    tenant_id: i64,
    aggregate_type: &str,
    aggregate_id: i64,
    grant_id: GrantId,
) -> Result<Option<GrantHeadSnapshot>, GrantRepositoryError> {
    positive_i64(tenant_id, "tenant_id")?;
    validated_aggregate_type(aggregate_type)?;
    positive_i64(aggregate_id, "aggregate_id")?;
    grant_id.validate()?;
    let encoded_grant_id = encode_grant_id_sql(grant_id)?;

    let head: Option<LatestRevisionRow> = sqlx::query_as(REVISION_LATEST_FOR_UPDATE_SQL)
        .bind(tenant_id)
        .bind(aggregate_type)
        .bind(aggregate_id)
        .bind(&encoded_grant_id)
        .fetch_optional(&mut **tx)
        .await?;

    let Some(row) = head else {
        return Ok(None);
    };
    if row.aggregate_type != aggregate_type || row.aggregate_id != aggregate_id {
        return Err(GrantRepositoryError::Mapping(
            "code=grant_repository.head_aggregate_mismatch".to_owned(),
        ));
    }
    let (decoded_grant_id, payload, entry) = row.decode(tenant_id)?;
    if decoded_grant_id != grant_id {
        return Err(GrantRepositoryError::Mapping(
            "code=grant_repository.head_identity_mismatch".to_owned(),
        ));
    }
    Ok(Some(GrantHeadSnapshot {
        grant_id,
        payload,
        entry,
    }))
}

/// Last `target_version` persisted for one stable grant identity, locked inside
/// the caller's transaction.
///
/// The delta-event table's unique key `uk_ade_target_version` guarantees one
/// event per (tenant, aggregate, grant, target_version); this helper gives the
/// writer a locked, race-free view so it can chain `base = last`, `target =
/// last + 1` without relying on an unlocked `MAX()` or a fixed version. Callers
/// must hold the revision-head lock first (see
/// [`read_grant_head_for_update_in_tx`]) to preserve the documented lock order.
const DELTA_LATEST_TARGET_VERSION_SQL: &str = "SELECT target_version \
    FROM authorization_delta_event \
    WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ? AND grant_id = ? \
    ORDER BY target_version DESC LIMIT 1 FOR UPDATE";

pub async fn read_latest_delta_target_version_for_update_in_tx(
    tx: &mut Transaction<'_, MySql>,
    tenant_id: i64,
    aggregate_type: &str,
    aggregate_id: i64,
    grant_id: GrantId,
) -> Result<Option<i64>, GrantRepositoryError> {
    positive_i64(tenant_id, "tenant_id")?;
    validated_aggregate_type(aggregate_type)?;
    positive_i64(aggregate_id, "aggregate_id")?;
    grant_id.validate()?;
    let encoded_grant_id = encode_grant_id_sql(grant_id)?;

    let last: Option<i64> = sqlx::query_scalar(DELTA_LATEST_TARGET_VERSION_SQL)
        .bind(tenant_id)
        .bind(aggregate_type)
        .bind(aggregate_id)
        .bind(&encoded_grant_id)
        .fetch_optional(&mut **tx)
        .await?;
    match last {
        // No delta event exists yet; the first event chains from base 0 → 1.
        None => Ok(None),
        Some(version) if version < 0 => Err(GrantRepositoryError::Mapping(
            "code=grant_repository.negative_delta_version".to_owned(),
        )),
        Some(version) => Ok(Some(version)),
    }
}

/// Pure version successor for one delta event of one grant identity.
///
/// `last == None` means no prior event exists (`base 0 → target 1`). Overflowing
/// the SQL `BIGINT` domain fails closed instead of wrapping.
pub fn next_delta_version(last: Option<i64>) -> Result<(i64, i64), GrantRepositoryError> {
    let base = last.unwrap_or(0);
    let target = base.checked_add(1).ok_or_else(|| {
        GrantRepositoryError::Mapping("code=grant_repository.delta_version_overflow".to_owned())
    })?;
    Ok((base, target))
}

/// Append one immutable grant revision inside the caller's transaction.
///
/// Steps, in lock order:
/// 1. validates the typed delta and scope identities (pure work, no SQL);
/// 2. locks the aggregate's latest revision row for the target grant id
///    (`FOR UPDATE`);
/// 3. decodes that head strictly (cross-tenant/card/tombstone poisoning
///    aborts);
/// 4. applies the pure transition rules to classify unknown / stale / gapped /
///    duplicate / tombstone conflicts and the ALLOW-only contract gates;
/// 5. INSERTs exactly one immutable revision row (no UPDATE is ever issued).
///
/// When the `REMOVE`/`REVOKE` tombstone is appended, its payload is rebuilt
/// from the previous head: identity, tenants, card, resource/action/effect and
/// validity stay as the before-image values while revision advances to the
/// successor and provenance binds to the mutating `event_id`/`operation_id`.
pub async fn append_grant_revision_in_tx(
    tx: &mut Transaction<'_, MySql>,
    request: &GrantRevisionAppendRequest,
) -> Result<AppendedGrantRevision, GrantRepositoryError> {
    let (semantic, dependency) = validate_revision_request(request)?;
    let grant_id = request.delta.target_grant_id()?;
    let encoded_grant_id = encode_grant_id_sql(grant_id)?;

    let head: Option<LatestRevisionRow> = sqlx::query_as(REVISION_LATEST_FOR_UPDATE_SQL)
        .bind(request.tenant_id)
        .bind(&request.aggregate_type)
        .bind(request.aggregate_id)
        .bind(&encoded_grant_id)
        .fetch_optional(&mut **tx)
        .await?;

    let (existing_grant, current_entry, existing_card_id) = match head {
        Some(row) => {
            if row.aggregate_type != request.aggregate_type
                || row.aggregate_id != request.aggregate_id
            {
                return Err(GrantRepositoryError::Mapping(
                    "code=grant_repository.head_aggregate_mismatch".to_owned(),
                ));
            }
            let (decoded_grant_id, payload, entry) = row.decode(request.tenant_id)?;
            if decoded_grant_id != grant_id {
                return Err(GrantRepositoryError::Mapping(
                    "code=grant_repository.head_identity_mismatch".to_owned(),
                ));
            }
            (Some(payload), Some(entry), row.card_id)
        }
        None => (None, None, None),
    };

    let target_revision_no = decide_revision_transition(grant_id, current_entry, &request.delta)?;

    let (resulting_card_id, payload_json, is_tombstone) = match &request.delta {
        GrantDelta::Add { grant } | GrantDelta::Update { grant, .. } => {
            if grant.tenant.tenant_id != request.tenant_id {
                return Err(GrantRepositoryError::ScopeViolation(
                    "code=grant_repository.cross_tenant_delta".to_owned(),
                ));
            }
            (Some(grant.card_id), grant.canonical_input()?, false)
        }
        GrantDelta::Remove { .. } | GrantDelta::Revoke { .. } => {
            let previous = existing_grant.as_ref().ok_or_else(|| {
                GrantRepositoryError::Mapping(
                    "code=grant_repository.missing_head_for_tombstone".to_owned(),
                )
            })?;
            let mut tombstone = previous.clone();
            tombstone.revision = GrantRevision::new(target_revision_no).map_err(|_| {
                GrantRepositoryError::Mapping(
                    "code=grant_repository.invalid_tombstone_revision".to_owned(),
                )
            })?;
            tombstone.state = match request.delta {
                GrantDelta::Remove { .. } => GrantState::Removed,
                _ => GrantState::Revoked,
            };
            tombstone.provenance.operation_id = request.operation_id.clone();
            tombstone.provenance.event_id = Some(request.event_id.clone());
            (Some(previous.card_id), tombstone.canonical_input()?, true)
        }
    };

    if let Some(scope_card) = request.card_id_scope {
        if resulting_card_id != Some(scope_card) {
            return Err(GrantRepositoryError::ScopeViolation(
                "code=grant_repository.card_scope_mismatch".to_owned(),
            ));
        }
    }

    let insert_result = sqlx::query(GRANT_REVISION_INSERT_SQL)
        .bind(request.tenant_id)
        .bind(resulting_card_id)
        .bind(&request.aggregate_type)
        .bind(request.aggregate_id)
        .bind(&encoded_grant_id)
        .bind(bind_i64(target_revision_no, "revision_no")?)
        .bind(&request.operation_id)
        .bind(&request.event_id)
        .bind(STATUS_ACTIVE)
        .bind(is_tombstone)
        .bind(&payload_json)
        .bind(semantic.as_bytes().to_vec())
        .bind(dependency.as_bytes().to_vec())
        .bind(&request.compiler_version)
        .execute(&mut **tx)
        .await?;

    let revision_id = i64::try_from(insert_result.last_insert_id()).map_err(|_| {
        GrantRepositoryError::Mapping(
            "code=grant_repository.bigint_overflow;field=revision_id".to_owned(),
        )
    })?;
    if insert_result.rows_affected() != 1 || revision_id == 0 {
        return Err(GrantRepositoryError::Mapping(
            "code=grant_repository.revision_insert_not_applied".to_owned(),
        ));
    }

    Ok(AppendedGrantRevision {
        revision_id,
        grant_id,
        tenant_id: request.tenant_id,
        card_id: existing_card_id.or(resulting_card_id),
        aggregate_type: request.aggregate_type.clone(),
        aggregate_id: request.aggregate_id,
        revision_no: target_revision_no,
        is_tombstone,
    })
}

/// Strictness shared by the append path and the claimed-delta readback: a
/// bound or stored `delta_json` document must parse into a valid typed
/// [`GrantDelta`], carry exactly `event_type`'s operation and address
/// `grant_id`.
fn validate_delta_payload_pairing(
    delta_json: &str,
    event_type: DeltaEventType,
    grant_id: GrantId,
) -> Result<GrantDelta, GrantRepositoryError> {
    validated_json(delta_json, "delta_json")?;
    let delta = decode_delta_event_payload(delta_json)?;
    if delta.operation_name() != event_type.as_str() {
        return Err(GrantRepositoryError::ScopeViolation(
            "code=grant_repository.event_type_delta_mismatch".to_owned(),
        ));
    }
    if delta.target_grant_id()? != grant_id {
        return Err(GrantRepositoryError::ScopeViolation(
            "code=grant_repository.delta_grant_mismatch".to_owned(),
        ));
    }
    Ok(delta)
}

/// Revoke-fence relation enforced at the delta append AND every claimed-delta
/// readback boundary, mirroring the typed contract (`fence <= source_generation`;
/// zero stays the valid initial "no revoke happened" value). Rows or requests
/// violating it fail closed instead of being stored or surfaced.
///
/// `pub(crate)` so the projection repository can re-verify the same relation
/// on frontier planning reads; the delta vocabulary itself stays owned here.
pub(crate) fn validate_delta_fence_relation(
    source_generation: u64,
    revoke_fence: u64,
) -> Result<(), GrantRepositoryError> {
    if revoke_fence > source_generation {
        return Err(GrantRepositoryError::ScopeViolation(format!(
            "code=grant_repository.revoke_fence_exceeds_source_generation;source_generation={source_generation};revoke_fence={revoke_fence}"
        )));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Durable delta event primitives
// ─────────────────────────────────────────────────────────────────────────────

/// Event kind carried by one durable delta row. Kept in lockstep with the
/// [`GrantDelta::operation_name`] vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaEventType {
    Add,
    Update,
    Remove,
    Revoke,
}

impl DeltaEventType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Add => "ADD",
            Self::Update => "UPDATE",
            Self::Remove => "REMOVE",
            Self::Revoke => "REVOKE",
        }
    }

    pub(crate) fn from_sql(value: &str) -> Result<Self, GrantRepositoryError> {
        match value {
            "ADD" => Ok(Self::Add),
            "UPDATE" => Ok(Self::Update),
            "REMOVE" => Ok(Self::Remove),
            "REVOKE" => Ok(Self::Revoke),
            other => Err(GrantRepositoryError::Mapping(format!(
                "code=grant_repository.unknown_delta_event_type;value={other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaEventAppendRequest {
    pub tenant_id: i64,
    pub card_id: Option<i64>,
    pub aggregate_type: String,
    pub aggregate_id: i64,
    pub grant_id: GrantId,
    pub event_id: String,
    pub operation_id: String,
    pub event_type: DeltaEventType,
    /// Projection version the delta chains from (may be 0 for the first event).
    pub base_version: i64,
    /// Projection version this event targets; must exceed `base_version`.
    pub target_version: i64,
    /// Positive source generation observed with the mutation.
    pub source_generation: u64,
    /// Revoke fence observed with the mutation (0 = no revoke happened).
    pub revoke_fence: u64,
    /// Whether this unfinished delta can leave already-published evidence
    /// authorizing access that the source mutation has removed or narrowed.
    /// Writers must set this from the source-side authorization-content
    /// comparison; legacy/defaulted rows intentionally remain fail-closed.
    pub invalidates_published_evidence: bool,
    /// Optional canonical before-image document; paired with `before_digest`.
    pub before_image_json: Option<String>,
    /// Optional lowercase SHA-256 of `before_image_json`.
    pub before_digest_hex: Option<String>,
    /// Serialized typed [`GrantDelta`] matching `event_type` and `grant_id`.
    pub delta_json: String,
    pub semantic_hash_hex: String,
    pub dependency_hash_hex: String,
    pub compiler_version: String,
    pub next_attempt_at: Option<PrimitiveDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendedDeltaEvent {
    pub delta_event_id: i64,
    pub cas_version: i64,
}

const DELTA_EVENT_INSERT_SQL: &str = "INSERT INTO authorization_delta_event \
    (tenant_id, card_id, aggregate_type, aggregate_id, grant_id, event_id, operation_id, \
     event_type, base_version, target_version, source_generation, revoke_fence, \
     invalidates_published_evidence, \
     before_image_json, before_digest, delta_json, semantic_hash, dependency_hash, \
     compiler_version, status, next_attempt_at) \
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

#[cfg(feature = "e3-observability")]
fn log_e3_enqueue_staged(request: &DeltaEventAppendRequest, appended: &AppendedDeltaEvent) {
    let stamp = astral_common::experiment_observation::stamp();
    tracing::info!(
        target: "authz_e3",
        event = "enqueue_staged",
        process_observation_id = %stamp.process_observation_id,
        event_sequence = stamp.event_sequence,
        wall_unix_ns = %stamp.wall_unix_ns,
        delta_event_id = appended.delta_event_id,
        event_id = %request.event_id,
        operation_id = %request.operation_id,
        tenant_id = request.tenant_id,
        card_id = ?request.card_id,
        aggregate_type = %request.aggregate_type,
        aggregate_id = request.aggregate_id,
        grant_id = %request.grant_id,
        target_version = request.target_version,
        invalidates_published_evidence = request.invalidates_published_evidence,
        durable = false,
        "e3 projector observation"
    );
}

/// Append one durable delta event.
///
/// Uniqueness is delegated to the schema keys `uk_ade_event` (stable event
/// identity) and `uk_ade_target_version` (one event per target projection
/// version); losing either race surfaces as
/// [`GrantRepositoryError::DuplicateDeltaEvent`] instead of a silent overwrite.
/// Impact-plan linkage is intentionally absent — see the module documentation.
pub async fn append_delta_event<'e, E>(
    executor: E,
    request: &DeltaEventAppendRequest,
) -> Result<AppendedDeltaEvent, GrantRepositoryError>
where
    E: Executor<'e, Database = MySql>,
{
    positive_i64(request.tenant_id, "tenant_id")?;
    positive_i64(request.aggregate_id, "aggregate_id")?;
    if let Some(card_id) = request.card_id {
        positive_i64(card_id, "card_id")?;
    }
    validated_aggregate_type(&request.aggregate_type)?;
    validated_text(&request.event_id, MAX_EVENT_ID_LENGTH, "event_id")?;
    validated_text(
        &request.operation_id,
        MAX_GRANT_OPERATION_ID_LENGTH,
        "operation_id",
    )?;
    validated_text(
        &request.compiler_version,
        MAX_COMPILER_VERSION_LENGTH,
        "compiler_version",
    )?;
    if request.base_version < 0 || request.target_version < 0 {
        return Err(GrantRepositoryError::ScopeViolation(
            "code=grant_repository.negative_version".to_owned(),
        ));
    }
    if request.target_version <= request.base_version {
        return Err(GrantRepositoryError::ScopeViolation(
            "code=grant_repository.non_advancing_target_version".to_owned(),
        ));
    }
    if request.source_generation == 0 {
        return Err(GrantRepositoryError::ScopeViolation(
            "code=grant_repository.invalid_source_generation".to_owned(),
        ));
    }
    if request.source_generation > i64::MAX as u64 || request.revoke_fence > i64::MAX as u64 {
        return Err(GrantRepositoryError::Mapping(
            "code=grant_repository.bigint_overflow;field=source_generation".to_owned(),
        ));
    }
    validate_delta_fence_relation(request.source_generation, request.revoke_fence)?;
    if matches!(
        request.event_type,
        DeltaEventType::Remove | DeltaEventType::Revoke
    ) && !request.invalidates_published_evidence
    {
        return Err(GrantRepositoryError::ScopeViolation(
            "code=grant_repository.revoke_class_requires_published_evidence_invalidation"
                .to_owned(),
        ));
    }
    let before_digest = match (&request.before_image_json, &request.before_digest_hex) {
        (Some(image), Some(digest)) => {
            validated_json(image, "before_image_json")?;
            Some((image, Sha256Digest::from_hex(digest)?))
        }
        (None, None) => None,
        _ => {
            return Err(GrantRepositoryError::ScopeViolation(
                "code=grant_repository.before_image_digest_pairing".to_owned(),
            ))
        }
    };
    validate_delta_payload_pairing(&request.delta_json, request.event_type, request.grant_id)?;
    let semantic = Sha256Digest::from_hex(&request.semantic_hash_hex)?;
    let dependency = Sha256Digest::from_hex(&request.dependency_hash_hex)?;

    let insert_result = sqlx::query(DELTA_EVENT_INSERT_SQL)
        .bind(request.tenant_id)
        .bind(request.card_id)
        .bind(&request.aggregate_type)
        .bind(request.aggregate_id)
        .bind(encode_grant_id_sql(request.grant_id)?)
        .bind(&request.event_id)
        .bind(&request.operation_id)
        .bind(request.event_type.as_str())
        .bind(request.base_version)
        .bind(request.target_version)
        .bind(bind_i64(request.source_generation, "source_generation")?)
        .bind(bind_i64(request.revoke_fence, "revoke_fence")?)
        .bind(request.invalidates_published_evidence)
        .bind(request.before_image_json.clone())
        .bind(before_digest.map(|(_, digest)| digest.as_bytes().to_vec()))
        .bind(&request.delta_json)
        .bind(semantic.as_bytes().to_vec())
        .bind(dependency.as_bytes().to_vec())
        .bind(&request.compiler_version)
        .bind(DELTA_STATUS_PENDING)
        .bind(request.next_attempt_at)
        .execute(executor)
        .await
        .map_err(|error| {
            if db_unique_violation(&error) {
                GrantRepositoryError::DuplicateDeltaEvent(error.to_string())
            } else {
                GrantRepositoryError::Query(error)
            }
        })?;

    let delta_event_id = i64::try_from(insert_result.last_insert_id()).map_err(|_| {
        GrantRepositoryError::Mapping(
            "code=grant_repository.bigint_overflow;field=delta_event_id".to_owned(),
        )
    })?;
    if insert_result.rows_affected() != 1 || delta_event_id == 0 {
        return Err(GrantRepositoryError::Mapping(
            "code=grant_repository.delta_insert_not_applied".to_owned(),
        ));
    }
    let appended = AppendedDeltaEvent {
        delta_event_id,
        cas_version: 0,
    };
    // Register before source commit; only this event's committed publication
    // can clear the intent. Rollback residue conservatively defers to DB.
    if let Some(hub) = crate::memory_projection_hub::memory_projection_hub() {
        hub.record_pending_delta(request);
    }
    #[cfg(feature = "e3-observability")]
    log_e3_enqueue_staged(request, &appended);
    Ok(appended)
}

/// Run-scoped secret fencing one lease attempt.
///
/// Generated by the repository during a claim (a random UUID v4 string). Its
/// `Debug` output is redacted; the database stores only the SHA-256 hash, so a
/// leaked metadata dump cannot renew or finish someone else's lease.
#[derive(Clone)]
pub struct DeltaLeaseToken {
    secret: String,
    audit_correlation_id: Uuid,
}

impl PartialEq for DeltaLeaseToken {
    fn eq(&self, other: &Self) -> bool {
        self.secret == other.secret
    }
}

impl Eq for DeltaLeaseToken {}

impl DeltaLeaseToken {
    pub fn new_run_scoped() -> Self {
        Self {
            secret: Uuid::new_v4().to_string(),
            audit_correlation_id: Uuid::new_v4(),
        }
    }

    /// Fixed non-secret placeholder for PURE command-assembly paths (e.g.
    /// cross-crate projectors building publish commands before an executor is
    /// known). Every orchestrator MUST overwrite it with the live claimed
    /// token before running ANY lease-guarded mutation; `Debug` stays redacted
    /// and the value is deliberately, visibly invalid.
    ///
    /// Always available (not gated behind `test`/`test-support`) so that
    /// library consumers do not need conditional compilation for their pure
    /// decision pipelines.
    pub fn placeholder_for_assembly() -> Self {
        Self {
            secret: "__assembly_placeholder_never_executed__".to_owned(),
            audit_correlation_id: Uuid::new_v4(),
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(token: &str) -> Self {
        Self {
            secret: token.to_owned(),
            audit_correlation_id: Uuid::new_v4(),
        }
    }

    #[cfg(test)]
    fn with_audit_correlation_id_for_test(token: &str, audit_correlation_id: Uuid) -> Self {
        Self {
            secret: token.to_owned(),
            audit_correlation_id,
        }
    }

    pub fn as_str(&self) -> &str {
        &self.secret
    }

    /// A non-secret identifier for one in-memory lease ownership episode. It is
    /// generated independently from the fencing secret and may appear in audit
    /// detail solely to correlate lifecycle records.
    fn audit_correlation_id(&self) -> Uuid {
        self.audit_correlation_id
    }

    pub fn token_hash(&self) -> Sha256Digest {
        Sha256Digest::from_raw_bytes(sha256_digest_bytes(self.secret.as_bytes()))
    }
}

impl fmt::Debug for DeltaLeaseToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeltaLeaseToken(REDACTED)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeltaEventClaimScope {
    pub tenant_id: i64,
    pub card_id: Option<i64>,
}

/// Eligibility predicate text embedded verbatim into BOTH claim statements
/// below.
///
/// Semantics:
/// - A `PENDING` row is claimable only once its optional backoff window has
///   elapsed (`next_attempt_at IS NULL OR next_attempt_at <= UTC_TIMESTAMP()`);
///   a future-scheduled retry is never hot-looped.
/// - An EXPIRED `LEASED` row is an unknown-result takeover and must NOT be
///   gated by any stale `next_attempt_at`: reconciliation of the unknown
///   outcome takes precedence over an old failure schedule, so this branch
///   deliberately ignores that column entirely.
/// - No other status (`SUCCEEDED`, `QUARANTINED`, …) is ever selectable.
///
/// The install UPDATE embeds this exact text so a selected row cannot be
/// seized by an inconsistent condition afterwards; char-for-char mirroring
/// between candidate and install copies is pinned by
/// [`delta_event_statements_match_their_bind_lists`] (no DRY cross-statement
/// construction exists because `concat!` only accepts literals).
///
/// Index note: `idx_ade_lease(status, lease_expires_at, delta_event_id)`
/// serves both arms of the row-level eligibility predicate through its
/// `status` prefix, and `idx_ade_grant_chain(tenant_id, grant_id, status,
/// target_version)` (migration 20260903000001) serves the sibling-ordering
/// gate's per-grant seek.
#[cfg(test)]
const DELTA_CLAIM_ELIGIBLE_PREDICATE: &str = "((status = 'PENDING' \
    AND (next_attempt_at IS NULL OR next_attempt_at <= UTC_TIMESTAMP())) \
    OR (status = 'LEASED' \
        AND lease_expires_at IS NOT NULL \
        AND lease_expires_at <= UTC_TIMESTAMP()))";

/// Claim-side per-grant chain ordering gate (campaign finding 10.D-2).
///
/// An event whose same-grant chain predecessor is still non-terminal
/// (PENDING / LEASED) must NOT be claimed: the partitioner would deterministically
/// answer `claimed_behind_unpublished_siblings` (a per-grant chain revision can
/// never skip an unpublished predecessor), so claiming would only burn the
/// attempt budget (`attempts = attempts + 1` at install) with zero progress and
/// eventually park the sibling under the maximal backoff — the high-churn
/// drainage pathology. Deferring the claim keeps `attempts` at zero; the event
/// becomes claimable the moment its predecessor reaches a terminal state.
///
/// QUARANTINED predecessors deliberately do NOT gate the claim: the event stays
/// claimable so the decision path surfaces the unorderable chain through its
/// observable Blocked / budget-exhausted path instead of a silent stall.
///
/// The correlated NOT EXISTS reads the same table as the outer SELECT — legal
/// for SELECT, but MySQL's error 1093 forbids it inside
/// [`DELTA_CLAIM_INSTALL_SQL`]. The install therefore keeps only the row-level
/// eligibility mirror: the candidate row is already `FOR UPDATE`-locked in the
/// same transaction, and any cross-row race (predecessor published/claimed
/// between candidate read and install) is fail-closed by the partitioner
/// decision, never by a silent skip.
///
/// Reference text for the watchdog probe in astral-trustgraph, which must stay
/// same-shaped with the claim candidate predicate (`has_claimable_work`).
pub const DELTA_CLAIM_SIBLING_ORDER_GATE: &str =
    "AND NOT EXISTS (SELECT 1 FROM authorization_delta_event pred \
    WHERE pred.tenant_id = authorization_delta_event.tenant_id \
      AND pred.grant_id = authorization_delta_event.grant_id \
      AND pred.target_version < authorization_delta_event.target_version \
      AND pred.status IN ('PENDING', 'LEASED'))";

/// Candidate selection for a claim. Ordered deterministically; expired leases
/// are reclaimable exactly like pending rows whose backoff window ended, and
/// the per-grant sibling-ordering gate (pinned byte-equal to
/// [`DELTA_CLAIM_SIBLING_ORDER_GATE`] by the statement-shape tests — no DRY
/// cross-statement construction exists because `concat!` only accepts
/// literals) defers any event whose own chain has a non-terminal predecessor.
/// Locks the candidate row.
const DELTA_CLAIM_CANDIDATE_UNSCOPED_SQL: &str = "SELECT delta_event_id, event_id, operation_id, \
    event_type, tenant_id, card_id, aggregate_type, aggregate_id, grant_id, base_version, \
    target_version, source_generation, revoke_fence, CAST(before_image_json AS CHAR) AS before_image_json, before_digest, \
    CAST(delta_json AS CHAR) AS delta_json, semantic_hash, dependency_hash, compiler_version, status, attempts, cas_version \
    FROM authorization_delta_event \
    WHERE tenant_id = ? \
      AND ((status = 'PENDING' \
           AND (next_attempt_at IS NULL OR next_attempt_at <= UTC_TIMESTAMP())) \
          OR (status = 'LEASED' \
              AND lease_expires_at IS NOT NULL \
              AND lease_expires_at <= UTC_TIMESTAMP())) \
      AND NOT EXISTS (SELECT 1 FROM authorization_delta_event pred \
          WHERE pred.tenant_id = authorization_delta_event.tenant_id \
            AND pred.grant_id = authorization_delta_event.grant_id \
            AND pred.target_version < authorization_delta_event.target_version \
            AND pred.status IN ('PENDING', 'LEASED')) \
    ORDER BY COALESCE(next_attempt_at, created_at), delta_event_id \
    LIMIT 1 FOR UPDATE";

const DELTA_CLAIM_CANDIDATE_CARD_SCOPED_SQL: &str =
    "SELECT delta_event_id, event_id, operation_id, \
    event_type, tenant_id, card_id, aggregate_type, aggregate_id, grant_id, base_version, \
    target_version, source_generation, revoke_fence, CAST(before_image_json AS CHAR) AS before_image_json, before_digest, \
    CAST(delta_json AS CHAR) AS delta_json, semantic_hash, dependency_hash, compiler_version, status, attempts, cas_version \
    FROM authorization_delta_event \
    WHERE tenant_id = ? AND card_id = ? \
      AND ((status = 'PENDING' \
           AND (next_attempt_at IS NULL OR next_attempt_at <= UTC_TIMESTAMP())) \
          OR (status = 'LEASED' \
              AND lease_expires_at IS NOT NULL \
              AND lease_expires_at <= UTC_TIMESTAMP())) \
      AND NOT EXISTS (SELECT 1 FROM authorization_delta_event pred \
          WHERE pred.tenant_id = authorization_delta_event.tenant_id \
            AND pred.grant_id = authorization_delta_event.grant_id \
            AND pred.target_version < authorization_delta_event.target_version \
            AND pred.status IN ('PENDING', 'LEASED')) \
    ORDER BY COALESCE(next_attempt_at, created_at), delta_event_id \
    LIMIT 1 FOR UPDATE";

/// Defense-in-depth install: the row is already locked, but the row-level
/// eligibility predicate (mirroring the candidate statements verbatim) is
/// repeated here so the mutation can never promote a row that became
/// ineligible between candidate read and install. The sibling-ordering gate
/// is deliberately absent: MySQL's error 1093 forbids a correlated subquery
/// on the UPDATE target table, the gate's cross-row state is re-evaluated by
/// the partitioner decision anyway (fail-closed), and the candidate→install
/// window holds the row lock so its own eligibility cannot change.
const DELTA_CLAIM_INSTALL_SQL: &str = "UPDATE authorization_delta_event \
    SET status = 'LEASED', \
        lease_owner = ?, \
        lease_token_hash = ?, \
        lease_expires_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP()), \
        cas_version = cas_version + 1, \
        attempts = attempts + 1 \
    WHERE delta_event_id = ? \
      AND ((status = 'PENDING' \
           AND (next_attempt_at IS NULL OR next_attempt_at <= UTC_TIMESTAMP())) \
          OR (status = 'LEASED' \
              AND lease_expires_at IS NOT NULL \
              AND lease_expires_at <= UTC_TIMESTAMP()))";

/// Authoritative post-install readback: server-side expiry PLUS the durable
/// attempt counter written by this very claim (`attempts = attempts + 1`),
/// so [`DeltaEventClaim::attempts`] always equals the persisted row value.
/// Worker budget decisions MUST consume this current attempt count, never a
/// pre-install view.
const DELTA_CLAIM_READBACK_SQL: &str =
    "SELECT lease_expires_at, attempts FROM authorization_delta_event WHERE delta_event_id = ?";

// ─────────────────────────────────────────────────────────────────────────────
// Partition lease (multi-tenant redesign Phase 1; design doc
// Rust多租户聚合分区与组织层级设计_V0.1.md §3.3). Scheduling-only primitive:
// never authorizes a source mutation, never substitutes for the per-event
// delta lease, never widens authorization.
// ─────────────────────────────────────────────────────────────────────────────

/// Fresh partition: plain INSERT, generation starts at 1.
const PARTITION_LEASE_INSERT_SQL: &str = "INSERT INTO authorization_projection_partition_lease \
    (tenant_id, aggregate_type, aggregate_id, lease_owner, lease_token_hash, lease_expires_at) \
    VALUES (?, ?, ?, ?, ?, TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP()))";

/// Expired takeover on an existing row. A live lease held by ANOTHER owner
/// matches nothing: the loser observes zero rows and must skip the partition.
/// An expired reclaim bumps generation + cas_version. The owner/token branch is
/// retained as a fenced SQL safety condition, but public acquire always mints a
/// fresh token and therefore cannot match it.
const PARTITION_LEASE_TAKEOVER_SQL: &str = "UPDATE authorization_projection_partition_lease \
    SET lease_owner = ?, lease_token_hash = ?, \
        lease_expires_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP()), \
        last_renewed_at = UTC_TIMESTAMP(), \
        generation = generation + 1, cas_version = cas_version + 1 \
    WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ? \
      AND (lease_expires_at <= UTC_TIMESTAMP() \
           OR (lease_owner = ? AND lease_token_hash = ?))";

/// Heartbeat while a worker keeps draining one partition. Exactly the
/// delta-event heartbeat contract: owner + token hash matched, one row.
const PARTITION_LEASE_RENEW_SQL: &str = "UPDATE authorization_projection_partition_lease \
    SET lease_expires_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP()), \
        last_renewed_at = UTC_TIMESTAMP(), cas_version = cas_version + 1 \
    WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ? \
      AND lease_owner = ? AND lease_token_hash = ?";

/// Best-effort release; expiry is the crash safety net, so a zero-row delete
/// (already expired and taken over) is NOT an error.
const PARTITION_LEASE_RELEASE_SQL: &str = "DELETE FROM authorization_projection_partition_lease \
    WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ? \
    AND lease_owner = ? AND lease_token_hash = ?";

/// Exact owner/token-pinned row read used only by the partition-lease audit
/// boundary. The `FOR UPDATE` lock makes a successful release and its durable
/// audit correlation one atomic state transition instead of an untraceable
/// delete followed by a best-effort write.
const PARTITION_LEASE_AUDIT_STATE_FOR_UPDATE_SQL: &str = "SELECT generation, cas_version \
    FROM authorization_projection_partition_lease \
    WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ? \
      AND lease_owner = ? AND lease_token_hash = ? FOR UPDATE";

/// Scheduling leases are internal system work, not authorization decisions.
/// `INTERNAL` deliberately keeps these lifecycle records out of the legacy
/// `ALLOW`/`DENY` authorization counters while retaining one shared durable
/// audit surface indexed by event type and tenant.
const PARTITION_LEASE_AUDIT_INSERT_SQL: &str = "INSERT INTO audit_log \
    (user_id, card_id, action, resource, decision, reason, event_type, request_id, tenant_id, detail) \
    VALUES (?, NULL, ?, 'authorization_projection_partition_lease', 'INTERNAL', \
            ?, 'AUTHZ_PARTITION_LEASE', ?, ?, ?)";

const PARTITION_LEASE_AUDIT_DETAIL_MAX_BYTES: usize =
    astral_common::service::AUDIT_DETAIL_MAX_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PartitionLeaseAuditOutcome {
    Acquire,
    Reclaim,
    Release,
    RenewLost,
}

impl PartitionLeaseAuditOutcome {
    const fn action(self) -> &'static str {
        match self {
            Self::Acquire => "partition_lease_acquire",
            Self::Reclaim => "partition_lease_reclaim",
            Self::Release => "partition_lease_release",
            Self::RenewLost => "partition_lease_renew_lost",
        }
    }

    const fn reason(self) -> &'static str {
        match self {
            Self::Acquire => "code=grant_repository.partition_lease;outcome=acquire",
            Self::Reclaim => "code=grant_repository.partition_lease;outcome=reclaim",
            Self::Release => "code=grant_repository.partition_lease;outcome=release",
            Self::RenewLost => "code=grant_repository.partition_lease;outcome=renew_lost",
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Acquire => "ACQUIRE",
            Self::Reclaim => "RECLAIM",
            Self::Release => "RELEASE",
            Self::RenewLost => "RENEW_LOST",
        }
    }
}

const PARTITION_LEASE_AUDIT_REQUEST_ID_DOMAIN: &[u8] = b"v1\0partition-lease-audit\0";

fn append_partition_lease_audit_component(canonical: &mut Vec<u8>, component: &[u8]) {
    let length = u32::try_from(component.len())
        .expect("partition lease audit component length always fits u32");
    canonical.extend_from_slice(&length.to_be_bytes());
    canonical.extend_from_slice(component);
}

fn append_partition_lease_audit_optional_i64(canonical: &mut Vec<u8>, value: Option<i64>) {
    match value {
        Some(value) => {
            canonical.push(1);
            canonical.extend_from_slice(&value.to_be_bytes());
        }
        None => canonical.push(0),
    }
}

/// A stable idempotency key for one audit outcome within one non-secret lease
/// ownership episode. Repeated `RENEW_LOST` observations for the same handle
/// deliberately derive the same key; distinct acquire/reclaim episodes and
/// distinct transition outcomes derive different keys.
fn partition_lease_audit_request_id(
    handle: &PartitionLeaseHandle,
    generation: Option<i64>,
    cas_version: Option<i64>,
    outcome: PartitionLeaseAuditOutcome,
) -> String {
    let mut canonical = Vec::with_capacity(256);
    canonical.extend_from_slice(PARTITION_LEASE_AUDIT_REQUEST_ID_DOMAIN);
    append_partition_lease_audit_component(
        &mut canonical,
        handle.token.audit_correlation_id().as_bytes(),
    );
    append_partition_lease_audit_component(
        &mut canonical,
        &handle.identity.tenant_id.to_be_bytes(),
    );
    append_partition_lease_audit_component(
        &mut canonical,
        handle.identity.aggregate_type.as_bytes(),
    );
    append_partition_lease_audit_component(
        &mut canonical,
        &handle.identity.aggregate_id.to_be_bytes(),
    );
    append_partition_lease_audit_component(&mut canonical, handle.lease_owner.as_bytes());
    append_partition_lease_audit_component(&mut canonical, outcome.as_str().as_bytes());
    append_partition_lease_audit_optional_i64(&mut canonical, generation);
    append_partition_lease_audit_optional_i64(&mut canonical, cas_version);
    hex::encode(sha256_digest_bytes(&canonical))
}

fn partition_lease_audit_detail(
    handle: &PartitionLeaseHandle,
    generation: Option<i64>,
    cas_version: Option<i64>,
    outcome: PartitionLeaseAuditOutcome,
    request_id: &str,
) -> Result<String, GrantRepositoryError> {
    let detail = serde_json::to_string(&serde_json::json!({
        "code": "grant_repository.partition_lease",
        "outcome": outcome.as_str(),
        "tenantId": handle.identity.tenant_id,
        "aggregateType": handle.identity.aggregate_type,
        "aggregateId": handle.identity.aggregate_id,
        "leaseOwner": handle.lease_owner,
        "leaseCorrelationId": handle.token.audit_correlation_id().to_string(),
        "generation": generation,
        "casVersion": cas_version,
        "requestId": request_id,
    }))
    .map_err(|error| {
        GrantRepositoryError::Mapping(format!(
            "code=grant_repository.partition_lease_audit_detail_unserializable;error={error}"
        ))
    })?;
    if detail.len() > PARTITION_LEASE_AUDIT_DETAIL_MAX_BYTES {
        return Err(GrantRepositoryError::Mapping(format!(
            "code=grant_repository.partition_lease_audit_detail_too_large;bytes={}",
            detail.len()
        )));
    }
    Ok(detail)
}

async fn insert_partition_lease_audit_in_tx(
    tx: &mut Transaction<'_, MySql>,
    handle: &PartitionLeaseHandle,
    generation: Option<i64>,
    cas_version: Option<i64>,
    outcome: PartitionLeaseAuditOutcome,
) -> Result<(), GrantRepositoryError> {
    let request_id = partition_lease_audit_request_id(handle, generation, cas_version, outcome);
    let detail =
        partition_lease_audit_detail(handle, generation, cas_version, outcome, &request_id)?;
    sqlx::query(PARTITION_LEASE_AUDIT_INSERT_SQL)
        .bind(SYSTEM_ACTOR_ID)
        .bind(outcome.action())
        .bind(outcome.reason())
        .bind(request_id)
        .bind(handle.identity.tenant_id)
        .bind(detail)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn read_partition_lease_audit_state_for_update_in_tx(
    tx: &mut Transaction<'_, MySql>,
    identity: &crate::authorization_projection_repository::ProjectionAggregateIdentity,
    lease_owner: &str,
    token: &DeltaLeaseToken,
) -> Result<Option<(i64, i64)>, GrantRepositoryError> {
    Ok(sqlx::query_as(PARTITION_LEASE_AUDIT_STATE_FOR_UPDATE_SQL)
        .bind(identity.tenant_id)
        .bind(&identity.aggregate_type)
        .bind(identity.aggregate_id)
        .bind(lease_owner)
        .bind(token.token_hash().as_bytes().to_vec())
        .fetch_optional(&mut **tx)
        .await?)
}

/// Partition discovery inside the configured tenant allowlist. The eligibility
/// predicate and the sibling-ordering gate MIRROR the delta claim candidate
/// statements verbatim, so a discovered partition always has at least one
/// claimable event right now — acquiring its lease can never immediately
/// starve. Ordering: oldest due first, then stable identity order.
/// The tenant IN-list is bound dynamically from validated positive i64 ids.
const PARTITION_DISCOVERY_FROM_SQL: &str = "SELECT tenant_id, aggregate_type, aggregate_id, \
        MIN(COALESCE(next_attempt_at, created_at)) AS oldest_due \
    FROM authorization_delta_event \
    WHERE tenant_id IN ";

const PARTITION_DISCOVERY_ELIGIBILITY_SQL: &str = " \
      AND ((status = 'PENDING' \
           AND (next_attempt_at IS NULL OR next_attempt_at <= UTC_TIMESTAMP())) \
          OR (status = 'LEASED' \
              AND lease_expires_at IS NOT NULL \
              AND lease_expires_at <= UTC_TIMESTAMP())) \
      AND NOT EXISTS (SELECT 1 FROM authorization_delta_event pred \
          WHERE pred.tenant_id = authorization_delta_event.tenant_id \
            AND pred.grant_id = authorization_delta_event.grant_id \
            AND pred.target_version < authorization_delta_event.target_version \
            AND pred.status IN ('PENDING', 'LEASED')) \
    GROUP BY tenant_id, aggregate_type, aggregate_id \
    ORDER BY oldest_due, tenant_id, aggregate_type, aggregate_id \
    LIMIT ?";

/// Partition-scoped claim candidate: the unscoped candidate statement plus the
/// partition identity filter. Everything else — eligibility, sibling-ordering
/// gate, ordering, locking — is byte-identical to the tenant claim.
const DELTA_CLAIM_CANDIDATE_PARTITION_SQL: &str = "SELECT delta_event_id, event_id, operation_id, \
    event_type, tenant_id, card_id, aggregate_type, aggregate_id, grant_id, base_version, \
    target_version, source_generation, revoke_fence, CAST(before_image_json AS CHAR) AS before_image_json, before_digest, \
    CAST(delta_json AS CHAR) AS delta_json, semantic_hash, dependency_hash, compiler_version, status, attempts, cas_version \
    FROM authorization_delta_event \
    WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ? \
      AND ((status = 'PENDING' \
           AND (next_attempt_at IS NULL OR next_attempt_at <= UTC_TIMESTAMP())) \
          OR (status = 'LEASED' \
              AND lease_expires_at IS NOT NULL \
              AND lease_expires_at <= UTC_TIMESTAMP())) \
      AND NOT EXISTS (SELECT 1 FROM authorization_delta_event pred \
          WHERE pred.tenant_id = authorization_delta_event.tenant_id \
            AND pred.grant_id = authorization_delta_event.grant_id \
            AND pred.target_version < authorization_delta_event.target_version \
            AND pred.status IN ('PENDING', 'LEASED')) \
    ORDER BY COALESCE(next_attempt_at, created_at), delta_event_id \
    LIMIT 1 FOR UPDATE";

#[derive(Debug, sqlx::FromRow)]
struct DeltaClaimCandidateRow {
    delta_event_id: i64,
    event_id: String,
    operation_id: String,
    event_type: String,
    tenant_id: i64,
    card_id: Option<i64>,
    aggregate_type: String,
    aggregate_id: i64,
    grant_id: String,
    base_version: i64,
    target_version: i64,
    source_generation: i64,
    revoke_fence: i64,
    before_image_json: Option<String>,
    before_digest: Option<Vec<u8>>,
    delta_json: String,
    semantic_hash: Vec<u8>,
    dependency_hash: Vec<u8>,
    compiler_version: String,
    status: String,
    attempts: i64,
    cas_version: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaEventClaim {
    pub delta_event_id: i64,
    pub event_id: String,
    pub operation_id: String,
    pub event_type: DeltaEventType,
    pub tenant_id: i64,
    pub card_id: Option<i64>,
    pub aggregate_type: String,
    pub aggregate_id: i64,
    pub grant_id: GrantId,
    pub base_version: i64,
    pub target_version: i64,
    pub source_generation: u64,
    pub revoke_fence: u64,
    pub before_image_json: Option<String>,
    pub before_digest: Option<Sha256Digest>,
    pub delta_json: String,
    pub semantic_hash: Sha256Digest,
    pub dependency_hash: Sha256Digest,
    pub compiler_version: String,
    /// Durable attempt counter read back AFTER this claim's install
    /// (`attempts = attempts + 1` already applied); first-ever attempt = 1.
    /// Worker budget decisions must treat this as the current persisted value.
    pub attempts: i64,
    pub cas_version: i64,
    pub lease_owner: String,
    pub lease_token: DeltaLeaseToken,
    pub lease_expires_at: PrimitiveDateTime,
}

/// Shared lease-window gate for claim installs and heartbeat renewals: a
/// window must be positive and never exceed [`MAX_DELTA_LEASE_SECONDS`].
fn validate_lease_seconds(lease_seconds: i64) -> Result<(), GrantRepositoryError> {
    if !(1..=MAX_DELTA_LEASE_SECONDS).contains(&lease_seconds) {
        return Err(GrantRepositoryError::ScopeViolation(format!(
            "code=grant_repository.invalid_lease_seconds;value={lease_seconds}"
        )));
    }
    Ok(())
}

/// Claim the next claimable delta event for `scope` inside the caller's
/// transaction.
///
/// - Only rows whose lease expired (`lease_expires_at <= UTC_TIMESTAMP()`) are
///   taken over regardless of schedule history, and `PENDING` rows are eligible
///   only once their optional `next_attempt_at` window has elapsed; live leases
///   are never stolen and future-scheduled backoffs are never jumped.
/// - Generates a fresh run-scoped [`DeltaLeaseToken`], installs owner + token
///   hash + server-side expiry atomically and bumps `attempts`/`cas_version`.
/// - The returned `attempts` value is read back AFTER the install, i.e. it is
///   the durable post-increment row value (first-ever attempt = 1); workers
///   must base attempt budgets on it, never on a pre-claim counter.
/// - Returns `Ok(None)` when nothing is claimable; the transaction stays open
///   (no rows locked) and the caller decides commit/rollback.
/// - A zero-row install while holding the row lock means the engine betrayed
///   the read snapshot; that becomes [`GrantRepositoryError::ClaimRace`]
///   instead of a silent retry.
pub async fn claim_next_delta_event_in_tx(
    tx: &mut Transaction<'_, MySql>,
    scope: DeltaEventClaimScope,
    lease_owner: &str,
    lease_seconds: i64,
) -> Result<Option<DeltaEventClaim>, GrantRepositoryError> {
    positive_i64(scope.tenant_id, "tenant_id")?;
    if let Some(card_id) = scope.card_id {
        positive_i64(card_id, "card_id")?;
    }
    validated_text(lease_owner, MAX_GRANT_LEASE_OWNER_LENGTH, "lease_owner")?;
    validate_lease_seconds(lease_seconds)?;

    let candidate: Option<DeltaClaimCandidateRow> = if scope.card_id.is_some() {
        sqlx::query_as(DELTA_CLAIM_CANDIDATE_CARD_SCOPED_SQL)
            .bind(scope.tenant_id)
            .bind(scope.card_id)
            .fetch_optional(&mut **tx)
            .await?
    } else {
        sqlx::query_as(DELTA_CLAIM_CANDIDATE_UNSCOPED_SQL)
            .bind(scope.tenant_id)
            .fetch_optional(&mut **tx)
            .await?
    };
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    // The SQL predicate already restricts eligibility; this mirror check makes
    // the invariant explicit and keeps every row field read defensively.
    if candidate.status != DELTA_STATUS_PENDING && candidate.status != DELTA_STATUS_LEASED {
        return Err(GrantRepositoryError::Mapping(format!(
            "code=grant_repository.claim_ineligible_status;value={}",
            candidate.status
        )));
    }
    // Defensive sanity on the pre-install snapshot; the AUTHORITATIVE attempt
    // counter returned to workers comes from DELTA_CLAIM_READBACK_SQL below.
    if candidate.attempts < 0 {
        return Err(GrantRepositoryError::Mapping(format!(
            "code=grant_repository.claim_negative_attempts_snapshot;value={}",
            candidate.attempts
        )));
    }

    install_claimed_event(tx, candidate, lease_owner, lease_seconds)
        .await
        .map(Some)
}

/// Shared claim tail for every candidate flavor (tenant/card-scoped and
/// partition-scoped): install the lease, read back the authoritative expiry
/// AND the durable post-install attempt counter, and assemble the claim. The
/// eligibility mirror checks ride along so no candidate flavor can skip them.
async fn install_claimed_event(
    tx: &mut Transaction<'_, MySql>,
    candidate: DeltaClaimCandidateRow,
    lease_owner: &str,
    lease_seconds: i64,
) -> Result<DeltaEventClaim, GrantRepositoryError> {
    // The SQL predicate already restricts eligibility; this mirror check makes
    // the invariant explicit and keeps every row field read defensively.
    if candidate.status != DELTA_STATUS_PENDING && candidate.status != DELTA_STATUS_LEASED {
        return Err(GrantRepositoryError::Mapping(format!(
            "code=grant_repository.claim_ineligible_status;value={}",
            candidate.status
        )));
    }
    // Defensive sanity on the pre-install snapshot; the AUTHORITATIVE attempt
    // counter returned to workers comes from DELTA_CLAIM_READBACK_SQL below.
    if candidate.attempts < 0 {
        return Err(GrantRepositoryError::Mapping(format!(
            "code=grant_repository.claim_negative_attempts_snapshot;value={}",
            candidate.attempts
        )));
    }

    let token = DeltaLeaseToken::new_run_scoped();
    let install = sqlx::query(DELTA_CLAIM_INSTALL_SQL)
        .bind(lease_owner)
        .bind(token.token_hash().as_bytes().to_vec())
        .bind(lease_seconds)
        .bind(candidate.delta_event_id)
        .execute(&mut **tx)
        .await?;
    if install.rows_affected() != 1 {
        return Err(GrantRepositoryError::ClaimRace);
    }

    // Read the authoritative server-side expiry AND the durable post-install
    // attempt counter back instead of mirroring a client clock or reusing the
    // pre-install candidate snapshot, keeping the returned claim honest.
    let (expires_at, installed_attempts): (Option<PrimitiveDateTime>, i64) =
        sqlx::query_as(DELTA_CLAIM_READBACK_SQL)
            .bind(candidate.delta_event_id)
            .fetch_one(&mut **tx)
            .await?;
    let Some(lease_expires_at) = expires_at else {
        return Err(GrantRepositoryError::Mapping(
            "code=grant_repository.claim_expiry_missing".to_owned(),
        ));
    };

    Ok(DeltaEventClaim {
        delta_event_id: candidate.delta_event_id,
        event_id: candidate.event_id,
        operation_id: candidate.operation_id,
        event_type: DeltaEventType::from_sql(&candidate.event_type)?,
        tenant_id: candidate.tenant_id,
        card_id: candidate.card_id,
        aggregate_type: candidate.aggregate_type,
        aggregate_id: candidate.aggregate_id,
        grant_id: decode_grant_id_sql(&candidate.grant_id)?,
        base_version: candidate.base_version,
        target_version: candidate.target_version,
        source_generation: u64::try_from(candidate.source_generation).map_err(|_| {
            GrantRepositoryError::Mapping(
                "code=grant_repository.invalid_source_generation".to_owned(),
            )
        })?,
        revoke_fence: {
            let revoke_fence = u64::try_from(candidate.revoke_fence).map_err(|_| {
                GrantRepositoryError::Mapping(
                    "code=grant_repository.invalid_revoke_fence".to_owned(),
                )
            })?;
            validate_delta_fence_relation(
                u64::try_from(candidate.source_generation).map_err(|_| {
                    GrantRepositoryError::Mapping(
                        "code=grant_repository.invalid_source_generation".to_owned(),
                    )
                })?,
                revoke_fence,
            )?;
            revoke_fence
        },
        before_image_json: candidate.before_image_json,
        before_digest: Sha256Digest::from_optional_bytes(candidate.before_digest.as_deref())?,
        delta_json: candidate.delta_json,
        semantic_hash: Sha256Digest::from_bytes(candidate.semantic_hash)?,
        dependency_hash: Sha256Digest::from_bytes(candidate.dependency_hash)?,
        compiler_version: candidate.compiler_version,
        attempts: installed_attempts,
        cas_version: candidate.cas_version,
        lease_owner: lease_owner.to_owned(),
        lease_token: token,
        lease_expires_at,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Partition lease operations. Exclusive SCHEDULING ownership of one
// (tenant_id, aggregate_type, aggregate_id) partition; never an authorization
// decision, never a substitute for the per-event delta lease.
// ─────────────────────────────────────────────────────────────────────────────

/// Lease handle for one partition. The raw token only travels between acquire
/// and release inside one worker process, exactly like the delta event token.
#[derive(Debug, Clone)]
pub struct PartitionLeaseHandle {
    pub identity: crate::authorization_projection_repository::ProjectionAggregateIdentity,
    pub lease_owner: String,
    pub token: DeltaLeaseToken,
}

fn validate_partition_lease_handle(
    handle: &PartitionLeaseHandle,
) -> Result<(), GrantRepositoryError> {
    handle.identity.validate().map_err(|error| {
        GrantRepositoryError::Mapping(format!(
            "code=grant_repository.invalid_partition_identity;error={error}"
        ))
    })?;
    validated_text(
        &handle.lease_owner,
        MAX_GRANT_LEASE_OWNER_LENGTH,
        "lease_owner",
    )?;
    if handle.token.as_str().trim().is_empty() {
        return Err(GrantRepositoryError::ScopeViolation(
            "code=grant_repository.empty_partition_lease_token".to_owned(),
        ));
    }
    if handle.token.audit_correlation_id().is_nil() {
        return Err(GrantRepositoryError::ScopeViolation(
            "code=grant_repository.nil_partition_lease_audit_correlation_id".to_owned(),
        ));
    }
    Ok(())
}

/// Acquire the exclusive scheduling lease for one partition. `Ok(None)` means a
/// live lease held by another worker: skip the partition, never wait, never
/// retry in a hot loop. Fresh acquire and expired reclaim each commit their
/// `audit_log` correlation in the same short transaction as the lease mutation;
/// a live foreign lease remains an unaudited no-op.
pub async fn acquire_partition_lease(
    pool: &sqlx::MySqlPool,
    identity: &crate::authorization_projection_repository::ProjectionAggregateIdentity,
    lease_owner: &str,
    lease_seconds: i64,
) -> Result<Option<PartitionLeaseHandle>, GrantRepositoryError> {
    identity.validate().map_err(|error| {
        GrantRepositoryError::Mapping(format!(
            "code=grant_repository.invalid_partition_identity;error={error}"
        ))
    })?;
    validated_text(lease_owner, MAX_GRANT_LEASE_OWNER_LENGTH, "lease_owner")?;
    validate_lease_seconds(lease_seconds)?;
    let token = DeltaLeaseToken::new_run_scoped();
    let handle = PartitionLeaseHandle {
        identity: identity.clone(),
        lease_owner: lease_owner.to_owned(),
        token,
    };
    let token_hash = handle.token.token_hash().as_bytes().to_vec();
    let mut insert_tx = pool.begin().await?;

    let insert = sqlx::query(PARTITION_LEASE_INSERT_SQL)
        .bind(identity.tenant_id)
        .bind(&identity.aggregate_type)
        .bind(identity.aggregate_id)
        .bind(lease_owner)
        .bind(token_hash.clone())
        .bind(lease_seconds)
        .execute(&mut *insert_tx)
        .await;
    match insert {
        Ok(result) if result.rows_affected() == 1 => {
            let Some((generation, cas_version)) =
                read_partition_lease_audit_state_for_update_in_tx(
                    &mut insert_tx,
                    &handle.identity,
                    &handle.lease_owner,
                    &handle.token,
                )
                .await?
            else {
                return Err(GrantRepositoryError::Mapping(
                    "code=grant_repository.partition_lease_acquire_state_missing".to_owned(),
                ));
            };
            insert_partition_lease_audit_in_tx(
                &mut insert_tx,
                &handle,
                Some(generation),
                Some(cas_version),
                PartitionLeaseAuditOutcome::Acquire,
            )
            .await?;
            insert_tx.commit().await?;
            return Ok(Some(handle));
        }
        // Duplicate-key detection can hold an InnoDB shared lock until this
        // transaction ends. Roll it back before the guarded takeover so two
        // concurrent expired-reclaim probes never deadlock S->X on the same
        // partition row.
        Err(error)
            if error
                .as_database_error()
                .is_some_and(|db| db.is_unique_violation()) =>
        {
            insert_tx.rollback().await?;
        }
        Err(error) => return Err(error.into()),
        Ok(_) => {
            return Err(GrantRepositoryError::Mapping(
                "code=grant_repository.partition_lease_insert_no_row".to_owned(),
            ))
        }
    }

    let mut takeover_tx = pool.begin().await?;
    let takeover = sqlx::query(PARTITION_LEASE_TAKEOVER_SQL)
        .bind(lease_owner)
        .bind(token_hash)
        .bind(lease_seconds)
        .bind(identity.tenant_id)
        .bind(&identity.aggregate_type)
        .bind(identity.aggregate_id)
        .bind(&handle.lease_owner)
        .bind(handle.token.token_hash().as_bytes().to_vec())
        .execute(&mut *takeover_tx)
        .await?;
    if takeover.rows_affected() != 1 {
        takeover_tx.commit().await?;
        return Ok(None);
    }
    let Some((generation, cas_version)) = read_partition_lease_audit_state_for_update_in_tx(
        &mut takeover_tx,
        &handle.identity,
        &handle.lease_owner,
        &handle.token,
    )
    .await?
    else {
        return Err(GrantRepositoryError::Mapping(
            "code=grant_repository.partition_lease_reclaim_state_missing".to_owned(),
        ));
    };
    insert_partition_lease_audit_in_tx(
        &mut takeover_tx,
        &handle,
        Some(generation),
        Some(cas_version),
        PartitionLeaseAuditOutcome::Reclaim,
    )
    .await?;
    takeover_tx.commit().await?;
    Ok(Some(handle))
}

/// Heartbeat the partition lease before each claim iteration while draining a
/// batch. Successful heartbeats intentionally have no audit row: their durable
/// liveness proof is `last_renewed_at`/`cas_version` on the live lease row.
/// If the CAS is lost, an auditable `RENEW_LOST` observation is recorded; the
/// caller must stop touching the partition immediately.
pub async fn renew_partition_lease(
    pool: &sqlx::MySqlPool,
    handle: &PartitionLeaseHandle,
    lease_seconds: i64,
) -> Result<(), GrantRepositoryError> {
    validate_partition_lease_handle(handle)?;
    validate_lease_seconds(lease_seconds)?;
    let mut tx = pool.begin().await?;
    let result = sqlx::query(PARTITION_LEASE_RENEW_SQL)
        .bind(lease_seconds)
        .bind(handle.identity.tenant_id)
        .bind(&handle.identity.aggregate_type)
        .bind(handle.identity.aggregate_id)
        .bind(&handle.lease_owner)
        .bind(handle.token.token_hash().as_bytes().to_vec())
        .execute(&mut *tx)
        .await?;
    if result.rows_affected() == 1 {
        tx.commit().await?;
        return Ok(());
    }
    insert_partition_lease_audit_in_tx(
        &mut tx,
        handle,
        None,
        None,
        PartitionLeaseAuditOutcome::RenewLost,
    )
    .await?;
    tx.commit().await?;
    Err(GrantRepositoryError::LeaseCasFailed(format!(
        "code=grant_repository.partition_lease_lost;aggregate={}:{}",
        handle.identity.aggregate_type, handle.identity.aggregate_id
    )))
}

/// Best-effort release. The owner/token-pinned delete and its audit correlation
/// commit together on a real release. A zero-row delete means the handle is
/// stale or already released and remains an unaudited successful no-op; expiry
/// and a later `RENEW_LOST`/`RECLAIM` record remain the recovery witnesses.
pub async fn release_partition_lease(
    pool: &sqlx::MySqlPool,
    handle: &PartitionLeaseHandle,
) -> Result<(), GrantRepositoryError> {
    validate_partition_lease_handle(handle)?;
    let mut tx = pool.begin().await?;
    let audit_state = read_partition_lease_audit_state_for_update_in_tx(
        &mut tx,
        &handle.identity,
        &handle.lease_owner,
        &handle.token,
    )
    .await?;
    let result = sqlx::query(PARTITION_LEASE_RELEASE_SQL)
        .bind(handle.identity.tenant_id)
        .bind(&handle.identity.aggregate_type)
        .bind(handle.identity.aggregate_id)
        .bind(&handle.lease_owner)
        .bind(handle.token.token_hash().as_bytes().to_vec())
        .execute(&mut *tx)
        .await?;
    if result.rows_affected() != 1 {
        tx.commit().await?;
        return Ok(());
    }
    let Some((generation, cas_version)) = audit_state else {
        return Err(GrantRepositoryError::Mapping(
            "code=grant_repository.partition_lease_release_state_missing".to_owned(),
        ));
    };
    insert_partition_lease_audit_in_tx(
        &mut tx,
        handle,
        Some(generation),
        Some(cas_version),
        PartitionLeaseAuditOutcome::Release,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

#[derive(Debug, sqlx::FromRow)]
pub struct PartitionCandidateRow {
    pub tenant_id: i64,
    pub aggregate_type: String,
    pub aggregate_id: i64,
    pub oldest_due: Option<PrimitiveDateTime>,
}

/// Discover partitions (inside the validated tenant allowlist) that currently
/// hold at least one claimable delta event, oldest due first. The eligibility
/// predicate and sibling-ordering gate mirror the claim candidate statements
/// verbatim: a discovered partition is claimable right now.
pub async fn discover_claimable_partitions(
    pool: &sqlx::MySqlPool,
    tenants: &[i64],
    limit: i64,
) -> Result<Vec<PartitionCandidateRow>, GrantRepositoryError> {
    if tenants.is_empty() {
        return Ok(Vec::new());
    }
    for tenant_id in tenants {
        positive_i64(*tenant_id, "tenant_id")?;
    }
    if !(1..=1024).contains(&limit) {
        return Err(GrantRepositoryError::ScopeViolation(
            "code=grant_repository.partition_discovery_limit_out_of_bounds".to_owned(),
        ));
    }
    let placeholders = vec!["?"; tenants.len()].join(", ");
    let statement = format!(
        "{}({}){}",
        PARTITION_DISCOVERY_FROM_SQL, placeholders, PARTITION_DISCOVERY_ELIGIBILITY_SQL
    );
    let mut query = sqlx::query_as::<_, PartitionCandidateRow>(&statement);
    for tenant_id in tenants {
        query = query.bind(*tenant_id);
    }
    let rows = query.bind(limit).fetch_all(pool).await?;
    Ok(rows)
}

/// Partition-scoped claim: identical contract to
/// [`claim_next_delta_event_in_tx`] but restricted to one
/// `(tenant_id, aggregate_type, aggregate_id)` partition. The caller MUST hold
/// that partition's lease; the lease is what makes per-partition publication
/// serialization real, this function only narrows the candidate surface.
pub async fn claim_next_delta_event_in_partition_tx(
    tx: &mut Transaction<'_, MySql>,
    scope: DeltaEventClaimScope,
    identity: &crate::authorization_projection_repository::ProjectionAggregateIdentity,
    lease_owner: &str,
    lease_seconds: i64,
) -> Result<Option<DeltaEventClaim>, GrantRepositoryError> {
    positive_i64(scope.tenant_id, "tenant_id")?;
    if let Some(card_id) = scope.card_id {
        positive_i64(card_id, "card_id")?;
    }
    validated_text(lease_owner, MAX_GRANT_LEASE_OWNER_LENGTH, "lease_owner")?;
    validate_lease_seconds(lease_seconds)?;
    identity.validate().map_err(|error| {
        GrantRepositoryError::Mapping(format!(
            "code=grant_repository.invalid_partition_identity;error={error}"
        ))
    })?;

    let candidate: Option<DeltaClaimCandidateRow> =
        sqlx::query_as(DELTA_CLAIM_CANDIDATE_PARTITION_SQL)
            .bind(scope.tenant_id)
            .bind(&identity.aggregate_type)
            .bind(identity.aggregate_id)
            .fetch_optional(&mut **tx)
            .await?;
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    install_claimed_event(tx, candidate, lease_owner, lease_seconds)
        .await
        .map(Some)
}

/// Pointer-advance reclaim (multi-tenant redesign M3; the ~898s finding):
/// a budget-exhausted event parks under the maximal `BACKOFF_CAP_SECS`
/// backoff with the stable exhaustion marker in `last_error`, and a parked
/// row makes its WHOLE partition undiscoverable (the scheduler's discovery
/// predicate mirrors claim eligibility). When the aggregate's pointer
/// ADVANCES — durable proof that the world moved and contention may have
/// cleared — every parked exhausted event of THAT aggregate gets its
/// `next_attempt_at` pulled back to now, so the next claim is a real chance
/// instead of a ~15-minute wait. Rows in ordinary short backoff (no marker)
/// and already-due rows match nothing. Scheduling metadata only: `attempts`
/// stays authoritative, no authorization surface involved.
const PARTITION_BUDGET_RECLAIM_SQL: &str = "UPDATE authorization_delta_event \
    SET next_attempt_at = UTC_TIMESTAMP(), cas_version = cas_version + 1 \
    WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ? \
      AND status = 'PENDING' \
      AND next_attempt_at IS NOT NULL AND next_attempt_at > UTC_TIMESTAMP() \
      AND last_error LIKE '%code=auth_projector.attempt_budget_exhausted%'";

/// Pull the `next_attempt_at` of one aggregate's budget-exhausted parked
/// events back to now. Returns the number of rows pulled forward (0 is the
/// normal no-op case). Scoped to exactly one partition identity.
pub async fn reclaim_budget_exhausted_events(
    pool: &sqlx::MySqlPool,
    identity: &crate::authorization_projection_repository::ProjectionAggregateIdentity,
) -> Result<u64, GrantRepositoryError> {
    identity.validate().map_err(|error| {
        GrantRepositoryError::Mapping(format!(
            "code=grant_repository.invalid_partition_identity;error={error}"
        ))
    })?;
    let result = sqlx::query(PARTITION_BUDGET_RECLAIM_SQL)
        .bind(identity.tenant_id)
        .bind(&identity.aggregate_type)
        .bind(identity.aggregate_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

/// Owner + token + event identity triple every lease-guarded mutation must
/// present. The token is matched by hash, so the raw secret only ever travels
/// between claim and mark inside one worker process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaLeaseIdentity {
    pub delta_event_id: i64,
    pub event_id: String,
    pub lease_owner: String,
    pub lease_token: DeltaLeaseToken,
}

fn validate_lease_identity(identity: &DeltaLeaseIdentity) -> Result<(), GrantRepositoryError> {
    positive_i64(identity.delta_event_id, "delta_event_id")?;
    validated_text(&identity.event_id, MAX_EVENT_ID_LENGTH, "event_id")?;
    validated_text(
        &identity.lease_owner,
        MAX_GRANT_LEASE_OWNER_LENGTH,
        "lease_owner",
    )?;
    if identity.lease_token.as_str().trim().is_empty() {
        return Err(GrantRepositoryError::ScopeViolation(
            "code=grant_repository.empty_lease_token".to_owned(),
        ));
    }
    Ok(())
}

/// Shared guard fragment: mark/release mutate only the exact leased row and
/// only while the lease is provably alive. affected_rows != 1 fails closed.
const LEASE_GUARD_SUFFIX: &str = "WHERE delta_event_id = ? AND event_id = ? \
    AND lease_owner = ? AND lease_token_hash = ? \
    AND status = 'LEASED' \
    AND lease_expires_at IS NOT NULL \
    AND lease_expires_at > UTC_TIMESTAMP()";

/// Terminal completion. The worker must call this only after it holds durable
/// proof of the applied result; a transport/mq ACK is not such proof.
const DELTA_COMPLETE_SQL_BASE: &str = "UPDATE authorization_delta_event \
    SET status = 'SUCCEEDED', lease_owner = NULL, lease_token_hash = NULL, \
        lease_expires_at = NULL, last_error = NULL ";

const DELTA_FAIL_SQL_BASE: &str = "UPDATE authorization_delta_event \
    SET status = 'PENDING', lease_owner = NULL, lease_token_hash = NULL, \
        lease_expires_at = NULL, next_attempt_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP()), \
        last_error = ? ";

const DELTA_RELEASE_SQL_BASE: &str = "UPDATE authorization_delta_event \
    SET status = 'PENDING', lease_owner = NULL, lease_token_hash = NULL, \
        lease_expires_at = NULL, next_attempt_at = NULL ";

async fn guarded_update<'e, E>(
    executor: E,
    statement_base: &str,
    identity: &DeltaLeaseIdentity,
) -> Result<u64, GrantRepositoryError>
where
    E: Executor<'e, Database = MySql>,
{
    validate_lease_identity(identity)?;
    let statement: String = format!("{statement_base}{LEASE_GUARD_SUFFIX}");
    let result = sqlx::query(&statement)
        .bind(identity.delta_event_id)
        .bind(&identity.event_id)
        .bind(&identity.lease_owner)
        .bind(identity.lease_token.token_hash().as_bytes().to_vec())
        .execute(executor)
        .await?;
    Ok(result.rows_affected())
}

/// Mark a claimed event durably succeeded.
///
/// Fails closed unless exactly one leased, unexpired row owned by
/// `identity.lease_owner` carrying the claimed token hash matches.
pub async fn complete_delta_event<'e, E>(
    executor: E,
    identity: &DeltaLeaseIdentity,
) -> Result<(), GrantRepositoryError>
where
    E: Executor<'e, Database = MySql>,
{
    if guarded_update(executor, DELTA_COMPLETE_SQL_BASE, identity).await? != 1 {
        return Err(GrantRepositoryError::LeaseCasFailed(format!(
            "code=grant_repository.complete_lost_lease;event={}",
            identity.event_id
        )));
    }
    Ok(())
}

/// Record a processing failure: release the lease, schedule a bounded retry and
/// persist the (truncated) error. Attempt budgets stay a worker policy (P2).
///
/// Bind order follows the statement text: the two `SET` placeholders
/// (`backoff_seconds`, `last_error`) precede the four guard parameters.
pub async fn fail_delta_event<'e, E>(
    executor: E,
    identity: &DeltaLeaseIdentity,
    backoff_seconds: i64,
    last_error: &str,
) -> Result<(), GrantRepositoryError>
where
    E: Executor<'e, Database = MySql>,
{
    if !(0..=MAX_BACKOFF_SECONDS).contains(&backoff_seconds) {
        return Err(GrantRepositoryError::ScopeViolation(format!(
            "code=grant_repository.invalid_backoff_seconds;value={backoff_seconds}"
        )));
    }
    validate_lease_identity(identity)?;
    let statement: String = format!("{DELTA_FAIL_SQL_BASE}{LEASE_GUARD_SUFFIX}");
    let result = sqlx::query(&statement)
        .bind(backoff_seconds)
        .bind(truncate_last_error(last_error))
        .bind(identity.delta_event_id)
        .bind(&identity.event_id)
        .bind(&identity.lease_owner)
        .bind(identity.lease_token.token_hash().as_bytes().to_vec())
        .execute(executor)
        .await?;
    if result.rows_affected() != 1 {
        return Err(GrantRepositoryError::LeaseCasFailed(format!(
            "code=grant_repository.fail_lost_lease;event={}",
            identity.event_id
        )));
    }
    Ok(())
}

/// Relinquish a claim without recording failure; the event becomes immediately
/// retryable. Same owner/token/expiry guards apply.
pub async fn release_delta_event_lease<'e, E>(
    executor: E,
    identity: &DeltaLeaseIdentity,
) -> Result<(), GrantRepositoryError>
where
    E: Executor<'e, Database = MySql>,
{
    if guarded_update(executor, DELTA_RELEASE_SQL_BASE, identity).await? != 1 {
        return Err(GrantRepositoryError::LeaseCasFailed(format!(
            "code=grant_repository.release_lost_lease;event={}",
            identity.event_id
        )));
    }
    Ok(())
}

/// Lease heartbeat for potentially long publish transactions.
///
/// A claim's window (e.g. 120s) can elapse while pure planning/compile phases
/// run or while a large publish transaction waits on locks; the in-transaction
/// completion ([`complete_delta_event`]) would then fail its live-expiry guard
/// and roll back an otherwise valid publication merely because time passed.
/// This heartbeat renews `lease_expires_at` from SERVER time inside the same
/// transaction, before the publish work runs, under a strict ownership CAS:
///
/// - `status = 'LEASED'` + exact `lease_owner` + `lease_token_hash` is a
///   complete ownership proof WITHOUT a liveness predicate. The only way to
///   lose an expired lease is a reclaim, and every reclaim necessarily
///   rewrites `lease_owner`/`lease_token_hash` (install) or moves the row out
///   of `LEASED` (fail/complete/quarantine) — either fails this CAS. Reviving
///   an expired-but-never-reclaimed lease is exactly the point: the durable
///   ownership row, not the wall clock, decides. Callers MUST run this inside
///   the transaction whose later statements depend on the renewal (same lock
///   scope, same commit); a heartbeat on a separate connection proves nothing
///   for the dependent transaction.
/// - The renewal deliberately does NOT touch `attempts` (a heartbeat is not an
///   attempt — attempt budgets stay exact), `cas_version` (no publish-path CAS
///   pins the delta row's version), `next_attempt_at` (stale schedule
///   bookkeeping) or any lease-clearing column.
/// - Zero affected rows is a LOST lease surfaced as
///   [`GrantRepositoryError::LeaseCasFailed`] with the stable
///   `code=grant_repository.heartbeat_lost_lease` token: callers must classify
///   it as LeaseLost/UNKNOWN and issue NO further mutation (no fail, no
///   release, no retry) until reconciliation.
///
/// Bind order follows the statement text: the one `SET` placeholder
/// (`lease_seconds`) precedes the four guard parameters.
const DELTA_LEASE_HEARTBEAT_SQL: &str = "UPDATE authorization_delta_event \
    SET lease_expires_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP()) \
    WHERE delta_event_id = ? AND event_id = ? \
      AND lease_owner = ? AND lease_token_hash = ? \
      AND status = 'LEASED'";

/// Renew one claimed delta event's lease expiry for another `lease_seconds`
/// measured from the database server's clock.
///
/// Fails closed unless exactly one row is still `LEASED` under
/// `identity.lease_owner` carrying the claimed token hash; expired rows match
/// as long as nobody took them over (see the SQL contract above).
pub async fn extend_delta_event_lease<'e, E>(
    executor: E,
    identity: &DeltaLeaseIdentity,
    lease_seconds: i64,
) -> Result<(), GrantRepositoryError>
where
    E: Executor<'e, Database = MySql>,
{
    validate_lease_seconds(lease_seconds)?;
    validate_lease_identity(identity)?;
    let result = sqlx::query(DELTA_LEASE_HEARTBEAT_SQL)
        .bind(lease_seconds)
        .bind(identity.delta_event_id)
        .bind(&identity.event_id)
        .bind(&identity.lease_owner)
        .bind(identity.lease_token.token_hash().as_bytes().to_vec())
        .execute(executor)
        .await?;
    if result.rows_affected() != 1 {
        return Err(GrantRepositoryError::LeaseCasFailed(format!(
            "code=grant_repository.heartbeat_lost_lease;event={}",
            identity.event_id
        )));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Terminal QUARANTINED state and explicit operator requeue
// ─────────────────────────────────────────────────────────────────────────────

/// Quarantine transition: a live `LEASED` row becomes terminal `QUARANTINED`.
///
/// Same guard family as complete/fail/release (`status = 'LEASED'`, live
/// server-side expiry, owner + token hash) — an affected-rows count of zero is
/// a lost lease surfaced as [`GrantRepositoryError::LeaseCasFailed`]; the
/// caller must reconcile unknown results instead of retrying blindly. Rows in
/// `PENDING`/`SUCCEEDED` can never enter quarantine through this boundary.
const DELTA_QUARANTINE_SQL_BASE: &str = "UPDATE authorization_delta_event \
    SET status = 'QUARANTINED', lease_owner = NULL, lease_token_hash = NULL, \
        lease_expires_at = NULL, next_attempt_at = NULL, last_error = ? ";

/// Pure input gate shared by [`mark_delta_event_quarantined`] and its tests:
/// composes the stable `code=...;detail=...` audit text or refuses empty codes.
fn compose_quarantine_last_error(
    reason_code: &str,
    reason_detail: &str,
) -> Result<String, GrantRepositoryError> {
    if reason_code.trim().is_empty() {
        return Err(GrantRepositoryError::ScopeViolation(
            "code=grant_repository.empty_quarantine_reason_code".to_owned(),
        ));
    }
    Ok(truncate_last_error(&format!(
        "code={reason_code};detail={reason_detail}"
    )))
}

/// Pure input gate for [`requeue_quarantined_delta_event`]; on success returns
/// the deterministic post-CAS version.
#[allow(clippy::result_large_err)]
fn validate_requeue_inputs(
    request: &QuarantinedDeltaRequeueRequest,
) -> Result<i64, GrantRepositoryError> {
    positive_i64(request.delta_event_id, "delta_event_id")?;
    validated_text(&request.event_id, MAX_EVENT_ID_LENGTH, "event_id")?;
    validated_text(
        &request.operation_id,
        MAX_GRANT_OPERATION_ID_LENGTH,
        "operation_id",
    )?;
    validated_text(
        &request.operator_operation_id,
        MAX_GRANT_OPERATION_ID_LENGTH,
        "operator_operation_id",
    )?;
    if request.reason.trim().is_empty() {
        return Err(GrantRepositoryError::ScopeViolation(
            "code=grant_repository.empty_requeue_reason".to_owned(),
        ));
    }
    // Audit reasons are free text (spaces allowed) but bounded and free of
    // control characters — mirrors the durable last_error budget.
    if request.reason.chars().count() > MAX_LAST_ERROR_LENGTH
        || request
            .reason
            .chars()
            .any(|character| character.is_control())
    {
        return Err(GrantRepositoryError::ScopeViolation(
            "code=grant_repository.invalid_requeue_reason".to_owned(),
        ));
    }
    if request.expected_cas_version < 0 {
        return Err(GrantRepositoryError::Mapping(
            "code=grant_repository.negative_cas_version".to_owned(),
        ));
    }
    request.expected_cas_version.checked_add(1).ok_or_else(|| {
        GrantRepositoryError::Mapping("code=grant_repository.cas_version_overflow".to_owned())
    })
}

/// Move one live leased delta event into terminal [`DELTA_STATUS_QUARANTINED`].
///
/// Writes a stable `code=...;detail=...` reason into `last_error` (truncated to
/// the column limit), clears the schedule and every lease column, keeps the
/// attempt counter and PRESERVES the row's current `cas_version` (quarantine
/// deliberately does not bump it). That stability is what makes operator
/// revival safe: [`requeue_quarantined_delta_event`] captures this untouched
/// `cas_version` as its `expected_cas_version` pin and advances it exactly
/// once during requeue (`cas_version = cas_version + 1`). Normal claim paths
/// never select a quarantined row again; only
/// [`requeue_quarantined_delta_event`] revives it.
/// Never call this for a row whose outcome is unknown — reconcile first.
pub async fn mark_delta_event_quarantined<'e, E>(
    executor: E,
    identity: &DeltaLeaseIdentity,
    reason_code: &str,
    reason_detail: &str,
) -> Result<(), GrantRepositoryError>
where
    E: Executor<'e, Database = MySql>,
{
    let last_error = compose_quarantine_last_error(reason_code, reason_detail)?;
    validate_lease_identity(identity)?;
    let statement: String = format!("{DELTA_QUARANTINE_SQL_BASE}{LEASE_GUARD_SUFFIX}");
    let result = sqlx::query(&statement)
        .bind(last_error)
        .bind(identity.delta_event_id)
        .bind(&identity.event_id)
        .bind(&identity.lease_owner)
        .bind(identity.lease_token.token_hash().as_bytes().to_vec())
        .execute(executor)
        .await?;
    if result.rows_affected() != 1 {
        return Err(GrantRepositoryError::LeaseCasFailed(format!(
            "code=grant_repository.quarantine_lost_lease;event={}",
            identity.event_id
        )));
    }
    Ok(())
}

/// Explicit operator requeue request for one quarantined delta event.
///
/// Every field participates in the guarded mutation; `expected_cas_version`
/// pins the durable CAS so a concurrent state change cannot be overwritten.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantinedDeltaRequeueRequest {
    pub delta_event_id: i64,
    pub event_id: String,
    /// Must match the stored operation identity exactly.
    pub operation_id: String,
    /// Durable CAS pin captured while reading the quarantined row.
    pub expected_cas_version: i64,
    /// Stable operator action identity. NOT persisted (no schema column);
    /// audit evidence stays with the operator log together with `reason`
    /// (see the [`DELTA_STATUS_QUARANTINED`] vocabulary documentation).
    pub operator_operation_id: String,
    pub reason: String,
    /// Given by the caller; `None` leaves `next_attempt_at` NULL so the event
    /// becomes claimable immediately. Never chosen automatically here.
    pub next_attempt_at: Option<PrimitiveDateTime>,
}

/// Operator-only revival of a quarantined event back into the work queue.
///
/// Guarded by delta-event id, event id, operation id, `QUARANTINED` status and
/// the exact CAS version; anything else fails closed with zero rows touched.
/// No HTTP/worker path may invoke this — scheduling (`next_attempt_at`) is the
/// caller's explicit decision. The pre-existing quarantine `last_error` text is
/// deliberately KEPT (never cleared) so the durable why-it-was-quarantined
/// evidence survives until a future attempt overwrites it with its own outcome;
/// this function does not fake success anywhere. Returns the deterministic new
/// CAS value (`expected_cas_version + 1`).
const DELTA_REQUEUE_SQL: &str = "UPDATE authorization_delta_event \
    SET status = 'PENDING', next_attempt_at = ?, cas_version = cas_version + 1 \
    WHERE delta_event_id = ? AND event_id = ? AND operation_id = ? \
      AND status = 'QUARANTINED' AND cas_version = ?";

pub async fn requeue_quarantined_delta_event<'e, E>(
    executor: E,
    request: &QuarantinedDeltaRequeueRequest,
) -> Result<i64, GrantRepositoryError>
where
    E: Executor<'e, Database = MySql>,
{
    let _cas_after = validate_requeue_inputs(request)?;

    let result = sqlx::query(DELTA_REQUEUE_SQL)
        .bind(request.next_attempt_at)
        .bind(request.delta_event_id)
        .bind(&request.event_id)
        .bind(&request.operation_id)
        .bind(request.expected_cas_version)
        .execute(executor)
        .await?;
    if result.rows_affected() != 1 {
        return Err(GrantRepositoryError::LeaseCasFailed(format!(
            "code=grant_repository.quarantine_requeue_not_applied;event={}",
            request.event_id
        )));
    }
    // Under the exact-row CAS pin the new durable value is deterministic.
    validate_requeue_inputs(request)
}

// ─────────────────────────────────────────────────────────────────────────────
// Strict read/list of queue rows by status (bounded, operator tooling)
// ─────────────────────────────────────────────────────────────────────────────

/// Typed filter for bounded status listings; unknown stored strings fail closed
/// via [`decode_delta_status_row`], never normalize into a variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaQueueStatus {
    Pending,
    Leased,
    Succeeded,
    Quarantined,
}

impl DeltaQueueStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => DELTA_STATUS_PENDING,
            Self::Leased => DELTA_STATUS_LEASED,
            Self::Succeeded => DELTA_STATUS_SUCCEEDED,
            Self::Quarantined => DELTA_STATUS_QUARANTINED,
        }
    }
}

/// One strictly decoded queue fact set for operator inspection (payloads are
/// intentionally excluded; secrets stay out of listings by construction).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaQueueEventRecord {
    pub delta_event_id: i64,
    pub event_id: String,
    pub operation_id: String,
    pub tenant_id: i64,
    pub card_id: Option<i64>,
    pub aggregate_type: String,
    pub aggregate_id: i64,
    pub grant_id: GrantId,
    pub base_version: i64,
    pub target_version: i64,
    pub source_generation: u64,
    pub revoke_fence: u64,
    pub attempts: i64,
    pub cas_version: i64,
    pub last_error: Option<String>,
}

const DELTA_STATUS_LIST_COLUMNS: &str = "delta_event_id, event_id, operation_id, tenant_id, \
    card_id, aggregate_type, aggregate_id, grant_id, base_version, target_version, \
    source_generation, revoke_fence, status, attempts, cas_version, last_error";
const DELTA_STATUS_LIST_TAIL: &str = " FROM authorization_delta_event WHERE tenant_id = ? \
    AND status = ? ORDER BY delta_event_id ASC LIMIT ?";

#[derive(Debug, sqlx::FromRow)]
struct DeltaStatusRawRow {
    delta_event_id: i64,
    event_id: String,
    operation_id: String,
    tenant_id: i64,
    card_id: Option<i64>,
    aggregate_type: String,
    aggregate_id: i64,
    grant_id: String,
    base_version: i64,
    target_version: i64,
    source_generation: i64,
    revoke_fence: i64,
    status: String,
    attempts: i64,
    cas_version: i64,
    last_error: Option<String>,
}

/// Fail-closed decode shared by the status listing and its unit tests.
fn decode_delta_status_row(
    row: DeltaStatusRawRow,
    expected_status: &str,
) -> Result<DeltaQueueEventRecord, GrantRepositoryError> {
    if row.status != expected_status {
        return Err(GrantRepositoryError::Mapping(format!(
            "code=grant_repository.delta_status_row_drift;expected={expected_status};actual={}",
            row.status
        )));
    }
    if row.delta_event_id <= 0 {
        return Err(GrantRepositoryError::Mapping(
            "code=grant_repository.invalid_delta_event_id".to_owned(),
        ));
    }
    positive_i64(row.tenant_id, "tenant_id")?;
    positive_i64(row.aggregate_id, "aggregate_id")?;
    if let Some(card_id) = row.card_id {
        positive_i64(card_id, "card_id")?;
    }
    validated_aggregate_type(&row.aggregate_type)?;
    validated_text(&row.event_id, MAX_EVENT_ID_LENGTH, "event_id")?;
    validated_text(
        &row.operation_id,
        MAX_GRANT_OPERATION_ID_LENGTH,
        "operation_id",
    )?;
    if let Some(last_error) = &row.last_error {
        validated_text(last_error, MAX_LAST_ERROR_LENGTH, "last_error")?;
    }
    if row.attempts < 0 || row.cas_version < 0 {
        return Err(GrantRepositoryError::Mapping(
            "code=grant_repository.negative_queue_counter".to_owned(),
        ));
    }
    if row.base_version < 0 || row.target_version <= row.base_version {
        return Err(GrantRepositoryError::Mapping(
            "code=grant_repository.non_advancing_target_version".to_owned(),
        ));
    }
    if row.source_generation <= 0 {
        return Err(GrantRepositoryError::Mapping(
            "code=grant_repository.invalid_source_generation".to_owned(),
        ));
    }
    let source_generation = u64::try_from(row.source_generation).map_err(|_| {
        GrantRepositoryError::Mapping("code=grant_repository.invalid_source_generation".to_owned())
    })?;
    let revoke_fence = u64::try_from(row.revoke_fence).map_err(|_| {
        GrantRepositoryError::Mapping("code=grant_repository.invalid_revoke_fence".to_owned())
    })?;
    validate_delta_fence_relation(source_generation, revoke_fence)?;

    Ok(DeltaQueueEventRecord {
        delta_event_id: row.delta_event_id,
        event_id: row.event_id,
        operation_id: row.operation_id,
        tenant_id: row.tenant_id,
        card_id: row.card_id,
        aggregate_type: row.aggregate_type,
        aggregate_id: row.aggregate_id,
        grant_id: decode_grant_id_sql(&row.grant_id)?,
        base_version: row.base_version,
        target_version: row.target_version,
        source_generation,
        revoke_fence,
        attempts: row.attempts,
        cas_version: row.cas_version,
        last_error: row.last_error,
    })
}

/// Bounded strict listing of one tenant's delta rows filtered by typed status,
/// ordered deterministically by `delta_event_id`. Read-only diagnostics for
/// operators (quarantine backlog review); no payload columns and no lease
/// secrets ever leave the database through this API.
pub async fn load_delta_events_by_status<'e, E>(
    executor: E,
    tenant_id: i64,
    status: DeltaQueueStatus,
    limit: i64,
) -> Result<Vec<DeltaQueueEventRecord>, GrantRepositoryError>
where
    E: Executor<'e, Database = MySql>,
{
    positive_i64(tenant_id, "tenant_id")?;
    if !(1..=MAX_DELTA_STATUS_LIST_ROWS).contains(&limit) {
        return Err(GrantRepositoryError::ScopeViolation(format!(
            "code=grant_repository.invalid_status_list_limit;limit={limit}"
        )));
    }
    let statement = format!("{DELTA_STATUS_LIST_COLUMNS}{DELTA_STATUS_LIST_TAIL}");
    let raws: Vec<DeltaStatusRawRow> = sqlx::query_as(statement.as_str())
        .bind(tenant_id)
        .bind(status.as_str())
        .bind(limit)
        .fetch_all(executor)
        .await?;
    let mut records = Vec::with_capacity(raws.len());
    for raw in raws {
        records.push(decode_delta_status_row(raw, status.as_str())?);
    }
    Ok(records)
}

// ─────────────────────────────────────────────────────────────────────────────
// Strict claimed-delta readback (worker-side safety verification)
// ─────────────────────────────────────────────────────────────────────────────

/// Strict decoded readback of one row known to be LEASED.
///
/// Mirrors [`DeltaEventClaim`] field for field except it carries no lease
/// token: only the SHA-256 hash persists, so a recovery read can never
/// reconstruct a secret. A claim ACK or queue status alone is not durable
/// proof — this type exists so a worker can re-verify its own lease and fetch
/// the full processing input inside one transaction before touching anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedDeltaEvent {
    pub delta_event_id: i64,
    pub event_id: String,
    pub operation_id: String,
    pub event_type: DeltaEventType,
    pub tenant_id: i64,
    pub card_id: Option<i64>,
    pub aggregate_type: String,
    pub aggregate_id: i64,
    pub grant_id: GrantId,
    pub base_version: i64,
    pub target_version: i64,
    pub source_generation: u64,
    pub revoke_fence: u64,
    pub before_image_json: Option<String>,
    pub before_digest: Option<Sha256Digest>,
    pub delta_json: String,
    pub semantic_hash: Sha256Digest,
    pub dependency_hash: Sha256Digest,
    pub compiler_version: String,
    /// Claim-attempt counter; the reader requires `>= 1` for a LEASED row.
    pub attempts: i64,
    pub cas_version: i64,
    pub lease_owner: String,
    pub lease_expires_at: PrimitiveDateTime,
}

const CLAIMED_DELTA_COLUMNS: &str = "delta_event_id, event_id, operation_id, event_type, \
    tenant_id, card_id, aggregate_type, aggregate_id, grant_id, base_version, target_version, \
    source_generation, revoke_fence, CAST(before_image_json AS CHAR) AS before_image_json, before_digest, CAST(delta_json AS CHAR) AS delta_json, \
    semantic_hash, dependency_hash, compiler_version, status, attempts, cas_version, \
    lease_owner, lease_token_hash, lease_expires_at";

/// Readback guard: the caller's complete lease identity plus server-side
/// liveness and status are re-checked inside SQL before any decode happens.
const CLAIMED_DELTA_LIVE_TAIL: &str = " FROM authorization_delta_event WHERE delta_event_id = ? \
    AND event_id = ? AND status = 'LEASED' AND lease_owner = ? AND lease_token_hash = ? \
    AND lease_expires_at IS NOT NULL AND lease_expires_at > UTC_TIMESTAMP() FOR UPDATE";

#[derive(Debug, Clone, sqlx::FromRow)]
struct ClaimedDeltaRawRow {
    delta_event_id: i64,
    event_id: String,
    operation_id: String,
    event_type: String,
    tenant_id: i64,
    card_id: Option<i64>,
    aggregate_type: String,
    aggregate_id: i64,
    grant_id: String,
    base_version: i64,
    target_version: i64,
    source_generation: i64,
    revoke_fence: i64,
    before_image_json: Option<String>,
    before_digest: Option<Vec<u8>>,
    delta_json: String,
    semantic_hash: Vec<u8>,
    dependency_hash: Vec<u8>,
    compiler_version: String,
    status: String,
    attempts: i64,
    cas_version: i64,
    lease_owner: Option<String>,
    lease_token_hash: Option<Vec<u8>>,
    lease_expires_at: Option<PrimitiveDateTime>,
}

impl ClaimedDeltaRawRow {
    /// Fail-closed decode of one claimed row against the caller's lease
    /// proof (token hash bytes are compared byte-wise; raw secrets never
    /// reach storage).
    fn decode(
        self,
        expected_owner: &str,
        expected_token_hash_bytes: &[u8],
    ) -> Result<ClaimedDeltaEvent, GrantRepositoryError> {
        // The SELECT predicate already enforced these; repeating them keeps
        // the decoder independently safe against future statement edits.
        if self.status != DELTA_STATUS_LEASED {
            return Err(GrantRepositoryError::Mapping(format!(
                "code=grant_repository.claimed_row_not_leased;status={}",
                self.status
            )));
        }
        let Some(lease_expires_at) = self.lease_expires_at else {
            return Err(GrantRepositoryError::Mapping(
                "code=grant_repository.claimed_expiry_missing".to_owned(),
            ));
        };
        if self.lease_owner.as_deref() != Some(expected_owner) {
            return Err(GrantRepositoryError::LeaseCasFailed(
                "code=grant_repository.claimed_owner_mismatch".to_owned(),
            ));
        }
        match &self.lease_token_hash {
            Some(bytes) if bytes.as_slice() == expected_token_hash_bytes => {}
            _ => {
                return Err(GrantRepositoryError::LeaseCasFailed(
                    "code=grant_repository.claimed_token_mismatch".to_owned(),
                ))
            }
        }

        positive_i64(self.tenant_id, "tenant_id")?;
        positive_i64(self.aggregate_id, "aggregate_id")?;
        if let Some(card_id) = self.card_id {
            positive_i64(card_id, "card_id")?;
        }
        validated_aggregate_type(&self.aggregate_type)?;
        validated_text(&self.event_id, MAX_EVENT_ID_LENGTH, "event_id")?;
        validated_text(
            &self.operation_id,
            MAX_GRANT_OPERATION_ID_LENGTH,
            "operation_id",
        )?;
        validated_text(
            &self.compiler_version,
            MAX_COMPILER_VERSION_LENGTH,
            "compiler_version",
        )?;
        if self.attempts < 1 {
            return Err(GrantRepositoryError::Mapping(format!(
                "code=grant_repository.claimed_attempts_below_one;value={}",
                self.attempts
            )));
        }
        if self.cas_version < 0 {
            return Err(GrantRepositoryError::Mapping(
                "code=grant_repository.negative_cas_version".to_owned(),
            ));
        }
        if self.base_version < 0 || self.target_version < 0 {
            return Err(GrantRepositoryError::Mapping(
                "code=grant_repository.negative_version".to_owned(),
            ));
        }
        if self.target_version <= self.base_version {
            return Err(GrantRepositoryError::Mapping(
                "code=grant_repository.non_advancing_target_version".to_owned(),
            ));
        }
        if self.source_generation <= 0 {
            return Err(GrantRepositoryError::Mapping(
                "code=grant_repository.invalid_source_generation".to_owned(),
            ));
        }
        let source_generation = u64::try_from(self.source_generation).map_err(|_| {
            GrantRepositoryError::Mapping(
                "code=grant_repository.invalid_source_generation".to_owned(),
            )
        })?;
        if self.revoke_fence < 0 {
            return Err(GrantRepositoryError::Mapping(
                "code=grant_repository.invalid_revoke_fence".to_owned(),
            ));
        }
        let revoke_fence = u64::try_from(self.revoke_fence).map_err(|_| {
            GrantRepositoryError::Mapping("code=grant_repository.invalid_revoke_fence".to_owned())
        })?;

        match (&self.before_image_json, self.before_digest.as_ref()) {
            (Some(image), Some(_)) => {
                validated_json(image, "before_image_json")?;
            }
            (None, None) => {}
            _ => {
                return Err(GrantRepositoryError::Mapping(
                    "code=grant_repository.before_image_digest_pairing".to_owned(),
                ))
            }
        }
        let event_type = DeltaEventType::from_sql(&self.event_type)?;
        let grant_id = decode_grant_id_sql(&self.grant_id)?;
        validate_delta_payload_pairing(&self.delta_json, event_type, grant_id)?;
        // Readback fence relation: a stored row violating the typed contract
        // is poisoned and refused instead of surfaced to a worker.
        validate_delta_fence_relation(source_generation, revoke_fence)?;

        Ok(ClaimedDeltaEvent {
            delta_event_id: self.delta_event_id,
            event_id: self.event_id,
            operation_id: self.operation_id,
            event_type,
            tenant_id: self.tenant_id,
            card_id: self.card_id,
            aggregate_type: self.aggregate_type,
            aggregate_id: self.aggregate_id,
            grant_id,
            base_version: self.base_version,
            target_version: self.target_version,
            source_generation,
            revoke_fence,
            before_image_json: self.before_image_json,
            before_digest: Sha256Digest::from_optional_bytes(self.before_digest.as_deref())?,
            delta_json: self.delta_json,
            semantic_hash: Sha256Digest::from_bytes(self.semantic_hash)?,
            dependency_hash: Sha256Digest::from_bytes(self.dependency_hash)?,
            compiler_version: self.compiler_version,
            attempts: self.attempts,
            cas_version: self.cas_version,
            lease_owner: expected_owner.to_owned(),
            lease_expires_at,
        })
    }
}

/// Re-read one claimed delta event under lock and prove the caller still owns
/// its live lease.
///
/// Fails closed with [`GrantRepositoryError::LeaseCasFailed`] when the row is
/// absent, no longer `LEASED`, owned by someone else, carrying another token
/// hash, or expired. Zero diagnosis is surfaced about *why* ownership failed
/// so concurrent workers cannot be distinguished from expired ones. On
/// success every stored value has been strictly revalidated (canonical UUID,
/// BINARY(32) digests, positive identities, version relation, before-image /
/// digest pairing, payload/event-type/grant agreement), never normalized.
pub async fn load_claimed_delta_event_for_update_in_tx(
    tx: &mut Transaction<'_, MySql>,
    identity: &DeltaLeaseIdentity,
) -> Result<ClaimedDeltaEvent, GrantRepositoryError> {
    validate_lease_identity(identity)?;
    let token_hash_bytes = identity.lease_token.token_hash().as_bytes().to_vec();
    let statement = format!("SELECT {CLAIMED_DELTA_COLUMNS}{CLAIMED_DELTA_LIVE_TAIL}");
    let row: ClaimedDeltaRawRow = sqlx::query_as(statement.as_str())
        .bind(identity.delta_event_id)
        .bind(&identity.event_id)
        .bind(&identity.lease_owner)
        .bind(token_hash_bytes.clone())
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| {
            GrantRepositoryError::LeaseCasFailed(format!(
                "code=grant_repository.claimed_readback_not_leased;event={}",
                identity.event_id
            ))
        })?;
    row.decode(&identity.lease_owner, &token_hash_bytes)
}

// ─────────────────────────────────────────────────────────────────────────────
// Hot-state recovery loader
// ─────────────────────────────────────────────────────────────────────────────

const LEDGER_LOAD_COLUMNS: &str = "revision_no, tenant_id, card_id, aggregate_type, aggregate_id, \
    grant_id, status, is_tombstone, CAST(grant_payload AS CHAR) AS grant_payload, semantic_hash, dependency_hash, operation_id, \
    event_id, compiler_version";

/// Read-side scope selection; every variant keeps tenant isolation mandatory.
const LEDGER_LOAD_TENANT_SQL_TEMPLATE_HEAD: &str = "SELECT ";
const LEDGER_LOAD_TENANT_SQL_TEMPLATE_MIDDLE: &str = " FROM authorization_grant_revision \
    WHERE tenant_id = ? ";
const LEDGER_LOAD_TENANT_ORDER_TAIL: &str = "ORDER BY grant_id ASC, revision_no ASC LIMIT ?";

/// Compose the fixed load statement for a scope variant.
///
/// Variants are composed from three constant fragments (never user input) so
/// the WHERE-clause combinations stay reviewable; all values travel as binds.
fn ledger_load_statement(aggregate_filtered: bool, card_filtered: bool) -> String {
    let mut statement = String::with_capacity(512);
    statement.push_str(LEDGER_LOAD_TENANT_SQL_TEMPLATE_HEAD);
    statement.push_str(LEDGER_LOAD_COLUMNS);
    statement.push_str(LEDGER_LOAD_TENANT_SQL_TEMPLATE_MIDDLE);
    if aggregate_filtered {
        statement.push_str("AND aggregate_type = ? AND aggregate_id = ? ");
    }
    if card_filtered {
        statement.push_str("AND card_id = ? ");
    }
    statement.push_str(LEDGER_LOAD_TENANT_ORDER_TAIL);
    statement
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RawLedgerRow {
    pub revision_no: i64,
    pub tenant_id: i64,
    pub card_id: Option<i64>,
    pub aggregate_type: String,
    pub aggregate_id: i64,
    pub grant_id: String,
    pub status: String,
    pub is_tombstone: i8,
    pub grant_payload: String,
    pub semantic_hash: Vec<u8>,
    pub dependency_hash: Vec<u8>,
    pub operation_id: String,
    pub event_id: String,
    pub compiler_version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GrantLedgerLoadScope<'a> {
    pub tenant_id: i64,
    pub card_id: Option<i64>,
    /// Optional `(aggregate_type, aggregate_id)` narrowing.
    pub aggregate: Option<(&'a str, i64)>,
}

/// Load the complete revision history for the scope, ordered deterministically
/// by (`grant_id`, `revision_no`). Read-only: no `FOR UPDATE`, no fallback to
/// raw sources; results feed the pure recovery builder below.
pub async fn load_grant_ledger_rows<'e, E>(
    executor: E,
    scope: GrantLedgerLoadScope<'_>,
) -> Result<Vec<RawLedgerRow>, GrantRepositoryError>
where
    E: Executor<'e, Database = MySql>,
{
    positive_i64(scope.tenant_id, "tenant_id")?;
    if let Some(card_id) = scope.card_id {
        positive_i64(card_id, "card_id")?;
    }
    if let Some((aggregate_type, aggregate_id)) = scope.aggregate {
        validated_aggregate_type(aggregate_type)?;
        positive_i64(aggregate_id, "aggregate_id")?;
    }

    let aggregate_filtered = scope.aggregate.is_some();
    let card_filtered = scope.card_id.is_some();
    let statement = ledger_load_statement(aggregate_filtered, card_filtered);

    let mut query = sqlx::query_as::<_, RawLedgerRow>(&statement).bind(scope.tenant_id);
    if let Some((aggregate_type, aggregate_id)) = scope.aggregate {
        query = query.bind(aggregate_type).bind(aggregate_id);
    }
    if let Some(card_id) = scope.card_id {
        query = query.bind(card_id);
    }
    query = query.bind(MAX_LEDGER_ROWS);
    let rows: Vec<RawLedgerRow> = query.fetch_all(executor).await?;
    if rows.len() as i64 >= MAX_LEDGER_ROWS {
        return Err(GrantRepositoryError::Mapping(
            "code=grant_repository.ledger_load_overflow".to_owned(),
        ));
    }
    Ok(rows)
}

/// One fully decoded ledger entry (latest surviving revision of a grant).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantLedgerEntry {
    pub grant: CanonicalGrant,
    pub revision_no: u64,
    pub is_tombstone: bool,
    pub tenant_id: i64,
    pub card_id: Option<i64>,
    pub aggregate_type: String,
    pub aggregate_id: i64,
    pub operation_id: String,
    pub event_id: String,
    pub semantic_hash: Sha256Digest,
    pub dependency_hash: Sha256Digest,
    pub compiler_version: String,
}

/// Decode and validate one raw revision row, failing closed on any drift
/// between columns and payload (identity, tenant, card, revision numbers,
/// tombstone flag, hash widths, canonical payload form).
pub fn decode_ledger_row(row: &RawLedgerRow) -> Result<GrantLedgerEntry, GrantRepositoryError> {
    if row.revision_no <= 0 {
        return Err(GrantRepositoryError::Mapping(
            "code=grant_repository.invalid_revision_no".to_owned(),
        ));
    }
    positive_i64(row.tenant_id, "tenant_id")?;
    if let Some(card_id) = row.card_id {
        positive_i64(card_id, "card_id")?;
    }
    validated_aggregate_type(&row.aggregate_type)?;
    positive_i64(row.aggregate_id, "aggregate_id")?;
    if row.status != STATUS_ACTIVE {
        return Err(GrantRepositoryError::Mapping(format!(
            "code=grant_repository.frozen_status;value={}",
            row.status
        )));
    }
    let grant_id = decode_grant_id_sql(&row.grant_id)?;
    let payload = decode_stored_grant_payload(&row.grant_payload)?;
    if payload.grant_id != grant_id {
        return Err(GrantRepositoryError::Mapping(
            "code=grant_repository.payload_identity_mismatch".to_owned(),
        ));
    }
    if payload.revision.value() != row.revision_no as u64 {
        return Err(GrantRepositoryError::Mapping(
            "code=grant_repository.payload_revision_mismatch".to_owned(),
        ));
    }
    if payload.tenant.tenant_id != row.tenant_id {
        return Err(GrantRepositoryError::ScopeViolation(
            "code=grant_repository.cross_tenant_payload".to_owned(),
        ));
    }
    if row.card_id.is_some() && row.card_id != Some(payload.card_id) {
        return Err(GrantRepositoryError::Mapping(
            "code=grant_repository.row_card_mismatch".to_owned(),
        ));
    }
    let is_tombstone = row.is_tombstone != 0;
    if is_tombstone != matches!(payload.state, GrantState::Removed | GrantState::Revoked) {
        return Err(GrantRepositoryError::Mapping(
            "code=grant_repository.tombstone_flag_mismatch".to_owned(),
        ));
    }
    validated_text(
        &row.operation_id,
        MAX_GRANT_OPERATION_ID_LENGTH,
        "operation_id",
    )?;
    validated_text(&row.event_id, MAX_EVENT_ID_LENGTH, "event_id")?;
    validated_text(
        &row.compiler_version,
        MAX_COMPILER_VERSION_LENGTH,
        "compiler_version",
    )?;
    Ok(GrantLedgerEntry {
        grant: payload,
        revision_no: row.revision_no as u64,
        is_tombstone,
        tenant_id: row.tenant_id,
        card_id: row.card_id,
        aggregate_type: row.aggregate_type.clone(),
        aggregate_id: row.aggregate_id,
        operation_id: row.operation_id.clone(),
        event_id: row.event_id.clone(),
        semantic_hash: Sha256Digest::from_bytes(row.semantic_hash.clone())?,
        dependency_hash: Sha256Digest::from_bytes(row.dependency_hash.clone())?,
        compiler_version: row.compiler_version.clone(),
    })
}

/// Reduce an ordered history into the latest entry per stable grant identity.
///
/// Fail-closed rules beyond per-row decoding:
/// - revision sequences must start at 1 and advance contiguously (missing
///   intermediate revisions mean lost history and abort the recovery);
/// - duplicate head revisions are impossible under the schema key and would
///   equally violate contiguity;
/// - the latest row decides lifecycle: ACTIVE records feed effective segments,
///   tombstones stay in the recovered ledger for future CAS decisions but
///   never authorize anything.
pub fn latest_entries_from_history(
    rows: &[RawLedgerRow],
) -> Result<Vec<GrantLedgerEntry>, GrantRepositoryError> {
    let mut latest: Vec<GrantLedgerEntry> = Vec::new();
    // (grant_id text, revision number the next row of this group must carry).
    let mut current_group: Option<(String, u64)> = None;
    for row in rows {
        let entry = decode_ledger_row(row)?;
        let identity = row.grant_id.clone();
        if let Some((group_id, next_expected)) = current_group.as_mut() {
            if group_id == &identity {
                if entry.revision_no != *next_expected {
                    return Err(GrantRepositoryError::Mapping(format!(
                        "code=grant_repository.revision_gap;grant_id={identity};expected={next_expected};actual={}",
                        entry.revision_no
                    )));
                }
                *next_expected = entry.revision_no.saturating_add(1);
                *latest.last_mut().expect("group opened with entry") = entry;
                continue;
            }
        }
        if entry.revision_no != GrantRevision::initial().value() {
            return Err(GrantRepositoryError::Mapping(format!(
                "code=grant_repository.revision_gap;grant_id={identity};expected=1;actual={}",
                entry.revision_no
            )));
        }
        current_group = Some((identity, GrantRevision::initial().next()?.value()));
        latest.push(entry);
    }
    Ok(latest)
}

/// Build the recoverable hot-state candidate from decoded ledger entries.
///
/// Thin composition over the Phase 2 compiler: tombstones stay in the mutable
/// ledger (`all_grants`) while only ACTIVE ALLOW contributions enter segments,
/// giving deterministic ordering and hashes for free. This is a candidate
/// builder — wiring it behind the read-gate remains P2/P3 work, and raw source
/// tables are never consulted as a fallback.
pub fn hot_state_from_entries(
    tenant: &TenantScope,
    version: u64,
    dependency_vector: DependencyVector,
    compiler_version: impl Into<String>,
    entries: &[GrantLedgerEntry],
) -> CompilerResult<HotState> {
    let grants = entries.iter().map(|entry| entry.grant.clone());
    HotState::from_grants_with_compiler(
        tenant.clone(),
        version,
        grants,
        dependency_vector,
        compiler_version,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Ledger ⇆ published-frontier partition (pure planning boundary)
// ─────────────────────────────────────────────────────────────────────────────

/// Classification of one revision row that is NOT proven published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerExclusionKind {
    /// The row's event is not part of the published frontier and was not
    /// claimed (`PENDING`, `LEASED`, `QUARANTINED` or otherwise unknown).
    NotProvenPublished,
    /// The row's event is claimed but sits behind an unpublished sibling
    /// revision of the same grant; it can only become a candidate once every
    /// predecessor is proven. Excluded rather than mixed into the base.
    ClaimedBehindUnpublishedSiblings,
    /// The row's event is claimed but its target version is at or below this
    /// grant's already-proven published top — a stale/unknown-result claim
    /// that must be reconciled, never re-applied.
    StaleClaimBehindPublishedFrontier,
}

/// One ledger head proven published through a frontier event.
///
/// Tombstones keep their flag here; consumers still keep them in the ledger
/// for CAS decisions while they authorize nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedLedgerHead {
    pub entry: GrantLedgerEntry,
    /// Aggregate generation whose frontier event proves exactly this state.
    pub proving_generation: u64,
    /// Per-grant base/target projection versions from the proving delta.
    pub delta_base_version: i64,
    pub delta_target_version: i64,
}

/// A claimed continuation row eligible to become the next candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateLedgerRow {
    pub entry: GrantLedgerEntry,
}

/// An excluded revision row together with its classification reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExcludedLedgerRow {
    pub entry: GrantLedgerEntry,
    pub kind: LedgerExclusionKind,
}

/// Result of [`partition_ledger_at_published_frontier`]: per-grant decisions
/// over the decoded ledger rows.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PartitionedGrantLedgerAtFrontier {
    /// Latest PROVEN-PUBLISHED entry per grant that has any published history
    /// (continuous revisions 1..=k). This preserves every grant's continuous
    /// published past even when unbuilt tail rows exist behind it.
    pub published_heads: Vec<PublishedLedgerHead>,
    /// Claimed continuation rows directly on top of a published prefix.
    pub candidate_rows: Vec<CandidateLedgerRow>,
    /// Rows excluded from the published base, with reasons.
    pub excluded_rows: Vec<ExcludedLedgerRow>,
}

/// Partition append-only ledger rows against a strictly verified published
/// aggregate frontier (pure — no SQL, no I/O).
///
/// Precondition: `rows` is the ordered output of `load_grant_ledger_rows`
/// (`ORDER BY grant_id ASC, revision_no ASC`); ordering violations fail closed
/// instead of being silently repaired ([`RawLedgerRow`] carries no timestamps,
/// so ordering is never guessed via `created_at` or `MAX(...)`).
///
/// Bridge contract (the stable identity chain):
/// - `authorization_grant_revision.event_id` must map to EXACTLY ONE frontier
///   delta event;
/// - the frontier delta's `grant_id` must equal the ledger row's `grant_id`;
/// - the frontier delta's `target_version` must equal the ledger row's
///   `revision_no`.
///
/// Aggregate generations and per-grant versions are different domains and are
/// never compared directly; the frontier events connect them.
///
/// Fail-closed rules:
/// - unsorted input, duplicate `(grant_id, revision_no)` rows or revision gaps
///   abort (lost/mutated history);
/// - a duplicate ledger `event_id` aborts;
/// - a PUBLISHED row sitting behind a non-published earlier sibling of the
///   same grant is a lineage gap and aborts (honest writers cannot produce
///   it);
/// - per grant, proven generations must regress never;
/// - a bridge mismatch (foreign grant / wrong target_version) aborts;
/// - every frontier event must be consumed by exactly one matching ledger row;
///   unconsumed extras mean missing revision proof and abort.
///
/// Never-published tails are classified, not errors: unclaimed unknown-status
/// rows stay `NotProvenPublished`; claimed continuations directly on top of
/// the published prefix become candidates; all other claimed positions are
/// excluded with their specific reason. Tombstone rows participate exactly
/// like active ones (their non-authorizing nature is carried by
/// [`GrantLedgerEntry::is_tombstone`], not by special-casing here).
pub fn partition_ledger_at_published_frontier(
    rows: &[RawLedgerRow],
    frontier: &crate::authorization_projection_repository::PublishedAggregateFrontier,
    claimed_event_ids: &[String],
) -> Result<PartitionedGrantLedgerAtFrontier, GrantRepositoryError> {
    let mut frontier_by_event: BTreeMap<
        &str,
        &crate::authorization_projection_repository::PublishedFrontierEvent,
    > = frontier
        .events
        .iter()
        .map(|event| (event.event_id.as_str(), event))
        .collect();
    if frontier_by_event.len() != frontier.events.len() {
        return Err(GrantRepositoryError::Mapping(
            "code=grant_repository.partition_duplicate_frontier_event".to_owned(),
        ));
    }
    let claimed: HashSet<&str> = claimed_event_ids.iter().map(String::as_str).collect();
    let mut seen_ledger_events: HashSet<&str> = HashSet::new();

    let mut outcome = PartitionedGrantLedgerAtFrontier::default();

    // Walker state for the currently open `(grant_id)` group.
    struct GroupState {
        /// Revision number the next row of this group must carry.
        expected_next_revision: u64,
        /// Highest PROVEN-PUBLISHED revision so far (`0` before any).
        published_end: u64,
        /// Frontier generation proven by `published_end` (`0` before any).
        last_published_generation: u64,
    }
    let mut group = GroupState {
        expected_next_revision: 1,
        published_end: 0,
        last_published_generation: 0,
    };
    let mut current_key: Option<String> = None;

    // Latest proven head per open group must emit exactly once.
    let mut head_entry: Option<GrantLedgerEntry> = None;
    let mut head_proof: Option<(u64, i64, i64)> = None;
    let flush_pending_head =
        |outcome: &mut PartitionedGrantLedgerAtFrontier,
         head_entry: &mut Option<GrantLedgerEntry>,
         head_proof: &mut Option<(u64, i64, i64)>| {
            if let (Some(entry), Some(proof)) = (head_entry.take(), head_proof.take()) {
                outcome.published_heads.push(PublishedLedgerHead {
                    entry,
                    proving_generation: proof.0,
                    delta_base_version: proof.1,
                    delta_target_version: proof.2,
                });
            }
        };

    for row in rows {
        if row.revision_no <= 0 || row.event_id.is_empty() {
            return Err(GrantRepositoryError::Mapping(
                "code=grant_repository.partition_invalid_revision_row".to_owned(),
            ));
        }
        let new_group = match &current_key {
            None => true,
            Some(key) => {
                if row.grant_id == *key {
                    false
                } else {
                    if row.grant_id.as_str() < key.as_str() {
                        return Err(GrantRepositoryError::Mapping(
                            "code=grant_repository.partition_unsorted_input".to_owned(),
                        ));
                    }
                    true
                }
            }
        };
        if new_group {
            // Flush the previous grant's proven head before opening a new one.
            flush_pending_head(&mut outcome, &mut head_entry, &mut head_proof);
            current_key = Some(row.grant_id.clone());
            group.expected_next_revision = 1;
            group.published_end = 0;
            group.last_published_generation = 0;
        }
        let revision = u64::try_from(row.revision_no).map_err(|_| {
            GrantRepositoryError::Mapping("code=grant_repository.invalid_revision_no".to_owned())
        })?;
        if revision != group.expected_next_revision {
            return Err(GrantRepositoryError::Mapping(format!(
                "code=grant_repository.partition_revision_gap;grant_id={};expected={};actual={revision}",
                row.grant_id, group.expected_next_revision
            )));
        }
        if !seen_ledger_events.insert(row.event_id.as_str()) {
            return Err(GrantRepositoryError::Mapping(format!(
                "code=grant_repository.partition_duplicate_ledger_event;event={}",
                row.event_id
            )));
        }
        let entry = decode_ledger_row(row)?;
        let advance_expected = |state: &mut GroupState| -> Result<(), GrantRepositoryError> {
            state.expected_next_revision =
                state.expected_next_revision.checked_add(1).ok_or_else(|| {
                    GrantRepositoryError::Mapping(
                        "code=grant_repository.revision_overflow".to_owned(),
                    )
                })?;
            Ok(())
        };
        match frontier_by_event.remove(row.event_id.as_str()) {
            Some(event) => {
                // Published branches require an intact published prefix below.
                if group.published_end != revision.saturating_sub(1) {
                    return Err(GrantRepositoryError::Mapping(format!(
                        "code=grant_repository.partition_published_prefix_gap;grant_id={};revision={revision}",
                        row.grant_id
                    )));
                }
                if decode_grant_id_sql(&row.grant_id)? != event.grant_id
                    || event.delta_target_version
                        != i64::try_from(revision).map_err(|_| {
                            GrantRepositoryError::Mapping(
                                "code=grant_repository.revision_overflow".to_owned(),
                            )
                        })?
                {
                    return Err(GrantRepositoryError::Mapping(format!(
                        "code=grant_repository.partition_frontier_proof_mismatch;event={};revision={revision}",
                        row.event_id
                    )));
                }
                if event.generation <= group.last_published_generation {
                    return Err(GrantRepositoryError::Mapping(format!(
                        "code=grant_repository.partition_published_generation_regression;grant_id={};generation={}",
                        row.grant_id, event.generation
                    )));
                }
                group.published_end = revision;
                group.last_published_generation = event.generation;
                head_entry = Some(entry);
                head_proof = Some((
                    event.generation,
                    event.delta_base_version,
                    event.delta_target_version,
                ));
                advance_expected(&mut group)?;
            }
            None => {
                let expected_candidate_revision = group.published_end.saturating_add(1);
                if claimed.contains(row.event_id.as_str()) {
                    match revision.cmp(&expected_candidate_revision) {
                        std::cmp::Ordering::Equal => {
                            outcome.candidate_rows.push(CandidateLedgerRow { entry });
                            advance_expected(&mut group)?;
                        }
                        std::cmp::Ordering::Less => {
                            outcome.excluded_rows.push(ExcludedLedgerRow {
                                entry,
                                kind: LedgerExclusionKind::StaleClaimBehindPublishedFrontier,
                            });
                            advance_expected(&mut group)?;
                        }
                        std::cmp::Ordering::Greater => {
                            outcome.excluded_rows.push(ExcludedLedgerRow {
                                entry,
                                kind: LedgerExclusionKind::ClaimedBehindUnpublishedSiblings,
                            });
                            advance_expected(&mut group)?;
                        }
                    }
                } else {
                    outcome.excluded_rows.push(ExcludedLedgerRow {
                        entry,
                        kind: LedgerExclusionKind::NotProvenPublished,
                    });
                    advance_expected(&mut group)?;
                }
            }
        }
    }
    flush_pending_head(&mut outcome, &mut head_entry, &mut head_proof);

    if !frontier_by_event.is_empty() {
        let leftover = frontier_by_event.keys().next().cloned().unwrap_or("");
        return Err(GrantRepositoryError::Mapping(format!(
            "code=grant_repository.partition_frontier_event_without_ledger_row;event={leftover}"
        )));
    }
    Ok(outcome)
}

// ─────────────────────────────────────────────────────────────────────────────
// Stable-event direct claim (local in-process projection dispatch path)
// ─────────────────────────────────────────────────────────────────────────────

/// One `authorization_delta_event` row as observed by the stable-event claim.
/// Mirrors [`DeltaClaimCandidateRow`] plus the evidence-invalidation flag so
/// the direct-dispatch path can re-bind EVERY durable field against the
/// commit-proven [`DeltaEventAppendRequest`] the source wrapper carries.
#[derive(Debug, sqlx::FromRow)]
struct StableEventClaimRow {
    delta_event_id: i64,
    event_id: String,
    operation_id: String,
    event_type: String,
    tenant_id: i64,
    card_id: Option<i64>,
    aggregate_type: String,
    aggregate_id: i64,
    grant_id: String,
    base_version: i64,
    target_version: i64,
    source_generation: i64,
    revoke_fence: i64,
    invalidates_published_evidence: i8,
    before_image_json: Option<String>,
    before_digest: Option<Vec<u8>>,
    delta_json: String,
    semantic_hash: Vec<u8>,
    dependency_hash: Vec<u8>,
    compiler_version: String,
    status: String,
    attempts: i64,
    cas_version: i64,
}

impl StableEventClaimRow {
    fn to_candidate(&self) -> DeltaClaimCandidateRow {
        DeltaClaimCandidateRow {
            delta_event_id: self.delta_event_id,
            event_id: self.event_id.clone(),
            operation_id: self.operation_id.clone(),
            event_type: self.event_type.clone(),
            tenant_id: self.tenant_id,
            card_id: self.card_id,
            aggregate_type: self.aggregate_type.clone(),
            aggregate_id: self.aggregate_id,
            grant_id: self.grant_id.clone(),
            base_version: self.base_version,
            target_version: self.target_version,
            source_generation: self.source_generation,
            revoke_fence: self.revoke_fence,
            before_image_json: self.before_image_json.clone(),
            before_digest: self.before_digest.clone(),
            delta_json: self.delta_json.clone(),
            semantic_hash: self.semantic_hash.clone(),
            dependency_hash: self.dependency_hash.clone(),
            compiler_version: self.compiler_version.clone(),
            status: self.status.clone(),
            attempts: self.attempts,
            cas_version: self.cas_version,
        }
    }
}

/// Stable-event claim select: locks the exact row behind the globally unique
/// `event_id` (`uk_ade_event`) inside the caller's transaction so the payload
/// re-binding and the lease install observe one committed row version.
const STABLE_EVENT_CLAIM_SELECT_SQL: &str = "SELECT delta_event_id, event_id, operation_id, \
    event_type, tenant_id, card_id, aggregate_type, aggregate_id, grant_id, base_version, \
    target_version, source_generation, revoke_fence, invalidates_published_evidence, \
    CAST(before_image_json AS CHAR) AS before_image_json, before_digest, \
    CAST(delta_json AS CHAR) AS delta_json, semantic_hash, dependency_hash, compiler_version, \
    status, attempts, cas_version \
    FROM authorization_delta_event \
    WHERE event_id = ? AND tenant_id = ? FOR UPDATE";

/// Locking predecessor probe for the direct-dispatch path. The stable-event
/// row is already locked by [`STABLE_EVENT_CLAIM_SELECT_SQL`], but a direct
/// envelope can arrive before an earlier same-grant event's envelope. Probe
/// the durable predecessor under the same transaction and return `Busy` before
/// installing a lease, so out-of-order delivery cannot burn attempts.
const STABLE_EVENT_SIBLING_ORDER_PROBE_SQL: &str = "SELECT pred.delta_event_id \
    FROM authorization_delta_event pred \
    WHERE pred.tenant_id = ? \
      AND pred.grant_id = ? \
      AND pred.target_version < ? \
      AND pred.status IN ('PENDING', 'LEASED') \
    ORDER BY pred.target_version, pred.delta_event_id \
    LIMIT 1 FOR UPDATE";

/// Field-by-field binding between the dispatch request and the durable row.
/// Any drift means the envelope does not describe the durable delta it claims
/// to carry: fail closed, never claim, never replay.
fn verify_stable_event_request_binding(
    request: &DeltaEventAppendRequest,
    row: &StableEventClaimRow,
) -> Result<(), GrantRepositoryError> {
    let mismatch = |field: &str| {
        GrantRepositoryError::ScopeViolation(format!(
            "code=grant_repository.claim_by_event_payload_mismatch;field={field}"
        ))
    };
    if row.event_id != request.event_id {
        return Err(mismatch("event_id"));
    }
    if row.operation_id != request.operation_id {
        return Err(mismatch("operation_id"));
    }
    let row_event_type = DeltaEventType::from_sql(&row.event_type)?;
    if row_event_type != request.event_type {
        return Err(mismatch("event_type"));
    }
    if row.tenant_id != request.tenant_id {
        return Err(mismatch("tenant_id"));
    }
    if row.card_id != request.card_id {
        return Err(mismatch("card_id"));
    }
    if row.aggregate_type != request.aggregate_type || row.aggregate_id != request.aggregate_id {
        return Err(mismatch("aggregate_identity"));
    }
    if decode_grant_id_sql(&row.grant_id)? != request.grant_id {
        return Err(mismatch("grant_id"));
    }
    if row.base_version != request.base_version {
        return Err(mismatch("base_version"));
    }
    if row.target_version != request.target_version {
        return Err(mismatch("target_version"));
    }
    if row.source_generation < 0
        || u64::try_from(row.source_generation).unwrap_or(u64::MAX) != request.source_generation
    {
        return Err(mismatch("source_generation"));
    }
    if row.revoke_fence < 0
        || u64::try_from(row.revoke_fence).unwrap_or(u64::MAX) != request.revoke_fence
    {
        return Err(mismatch("revoke_fence"));
    }
    let row_invalidates = row.invalidates_published_evidence != 0;
    if row_invalidates != request.invalidates_published_evidence {
        return Err(mismatch("invalidates_published_evidence"));
    }
    match (&request.before_image_json, &request.before_digest_hex) {
        (Some(image), Some(digest)) => {
            if row.before_image_json.as_deref() != Some(image.as_str()) {
                return Err(mismatch("before_image_json"));
            }
            let row_digest = Sha256Digest::from_optional_bytes(row.before_digest.as_deref())?;
            if row_digest != Some(Sha256Digest::from_hex(digest)?) {
                return Err(mismatch("before_digest"));
            }
        }
        (None, None) => {
            if row.before_image_json.is_some() || row.before_digest.is_some() {
                return Err(mismatch("before_image_absent"));
            }
        }
        _ => {
            return Err(GrantRepositoryError::ScopeViolation(
                "code=grant_repository.before_image_digest_pairing".to_owned(),
            ))
        }
    }
    if row.delta_json != request.delta_json {
        return Err(mismatch("delta_json"));
    }
    if Sha256Digest::from_bytes(row.semantic_hash.clone())?
        != Sha256Digest::from_hex(&request.semantic_hash_hex)?
    {
        return Err(mismatch("semantic_hash"));
    }
    if Sha256Digest::from_bytes(row.dependency_hash.clone())?
        != Sha256Digest::from_hex(&request.dependency_hash_hex)?
    {
        return Err(mismatch("dependency_hash"));
    }
    if row.compiler_version != request.compiler_version {
        return Err(mismatch("compiler_version"));
    }
    Ok(())
}

/// Outcome of [`claim_delta_event_by_stable_event_in_tx`]: everything except
/// [`ClaimedStableEventOutcome::Claimed`] leaves the row untouched.
#[derive(Debug)]
pub enum ClaimedStableEventOutcome {
    /// Lease installed inside the caller's transaction; both forms returned in
    /// the SAME transaction (no readback reload, no id-only DB round trip).
    Claimed {
        claim: Box<DeltaEventClaim>,
        event: Box<ClaimedDeltaEvent>,
    },
    /// Durable `SUCCEEDED` proven: processed, skip without replay and without
    /// any mutation.
    AlreadyProcessed { event_id: String },
    /// Durable terminal gate (`QUARANTINED`): this is NOT a success skip. The
    /// row keeps its gate; the dispatcher must not replay it, and the worker
    /// surfaces it for reconciliation instead of treating it as processed.
    TerminalGated {
        event_id: String,
        status: &'static str,
    },
    /// Live lease held elsewhere, or the row-level eligibility window has not
    /// opened (future backoff). Not claimable now; durable recovery converges.
    Busy { event_id: String },
    /// Unresolvable row state (unknown status vocabulary). NEVER blindly
    /// replayed; surfaces for reconciliation.
    InDoubt { event_id: String, reason: String },
}

/// Claim ONE delta event by its stable event identity inside the caller's
/// single transaction, reusing the exact claim predicates of
/// [`claim_next_delta_event_in_tx`] and the shared claim install tail.
///
/// Direct-dispatch contract (local in-process projector path):
/// 1. Locks the row behind the globally unique `event_id` (`uk_ade_event`)
///    and re-binds EVERY durable field against the commit-proven
///    [`DeltaEventAppendRequest`] the source wrapper carries — a mismatch is
///    a fail-closed [`GrantRepositoryError::ScopeViolation`], never a claim.
/// 2. `SUCCEEDED` rows return [`ClaimedStableEventOutcome::AlreadyProcessed`]
///    — processed durably, skip silently, never replay. `QUARANTINED` rows
///    return [`ClaimedStableEventOutcome::TerminalGated`] — the gate stays
///    in force (never a success skip, never replayed).
/// 3. Eligible rows (`PENDING` past backoff, `LEASED` with expired lease) get
///    the same lease install as the queue claim (fresh run-scoped token,
///    owner, server-side expiry, `attempts + 1`, `cas_version + 1`). A zero-row
///    install (future backoff / live foreign lease) returns
///    [`ClaimedStableEventOutcome::Busy`] instead of inventing a claim.
/// 4. Unknown status vocabulary returns [`ClaimedStableEventOutcome::InDoubt`]
///    and performs NO mutation — unknown results are never blindly replayed.
///
/// The commit/rollback of the transaction stays with the caller, exactly like
/// every other `*_in_tx` primitive in this module.
pub async fn claim_delta_event_by_stable_event_in_tx(
    tx: &mut Transaction<'_, MySql>,
    request: &DeltaEventAppendRequest,
    lease_owner: &str,
    lease_seconds: i64,
) -> Result<ClaimedStableEventOutcome, GrantRepositoryError> {
    positive_i64(request.tenant_id, "tenant_id")?;
    validated_text(&request.event_id, MAX_EVENT_ID_LENGTH, "event_id")?;
    validated_text(lease_owner, MAX_GRANT_LEASE_OWNER_LENGTH, "lease_owner")?;
    validate_lease_seconds(lease_seconds)?;

    let row: Option<StableEventClaimRow> = sqlx::query_as(STABLE_EVENT_CLAIM_SELECT_SQL)
        .bind(&request.event_id)
        .bind(request.tenant_id)
        .fetch_optional(&mut **tx)
        .await?;
    let Some(row) = row else {
        // A commit-proven dispatch always references a committed row; a
        // missing row is a contract violation and fails closed.
        return Err(GrantRepositoryError::ScopeViolation(format!(
            "code=grant_repository.claim_by_event_row_missing;event_id={}",
            request.event_id
        )));
    };
    verify_stable_event_request_binding(request, &row)?;

    match row.status.as_str() {
        DELTA_STATUS_SUCCEEDED => Ok(ClaimedStableEventOutcome::AlreadyProcessed {
            event_id: row.event_id.clone(),
        }),
        DELTA_STATUS_QUARANTINED => Ok(ClaimedStableEventOutcome::TerminalGated {
            event_id: row.event_id.clone(),
            status: DELTA_STATUS_QUARANTINED,
        }),
        DELTA_STATUS_PENDING | DELTA_STATUS_LEASED => {
            let predecessor: Option<(i64,)> = sqlx::query_as(STABLE_EVENT_SIBLING_ORDER_PROBE_SQL)
                .bind(row.tenant_id)
                .bind(&row.grant_id)
                .bind(row.target_version)
                .fetch_optional(&mut **tx)
                .await?;
            if predecessor.is_some() {
                return Ok(ClaimedStableEventOutcome::Busy {
                    event_id: row.event_id.clone(),
                });
            }
            let candidate = row.to_candidate();
            match install_claimed_event(tx, candidate, lease_owner, lease_seconds).await {
                Ok(claim) => {
                    let event = ClaimedDeltaEvent {
                        delta_event_id: row.delta_event_id,
                        event_id: row.event_id.clone(),
                        operation_id: row.operation_id.clone(),
                        event_type: DeltaEventType::from_sql(&row.event_type)?,
                        tenant_id: row.tenant_id,
                        card_id: row.card_id,
                        aggregate_type: row.aggregate_type.clone(),
                        aggregate_id: row.aggregate_id,
                        grant_id: decode_grant_id_sql(&row.grant_id)?,
                        base_version: row.base_version,
                        target_version: row.target_version,
                        source_generation: u64::try_from(row.source_generation).map_err(|_| {
                            GrantRepositoryError::Mapping(
                                "code=grant_repository.invalid_source_generation".to_owned(),
                            )
                        })?,
                        revoke_fence: {
                            let revoke_fence = u64::try_from(row.revoke_fence).map_err(|_| {
                                GrantRepositoryError::Mapping(
                                    "code=grant_repository.invalid_revoke_fence".to_owned(),
                                )
                            })?;
                            let source_generation =
                                u64::try_from(row.source_generation).map_err(|_| {
                                    GrantRepositoryError::Mapping(
                                        "code=grant_repository.invalid_source_generation"
                                            .to_owned(),
                                    )
                                })?;
                            validate_delta_fence_relation(source_generation, revoke_fence)?;
                            revoke_fence
                        },
                        before_image_json: row.before_image_json.clone(),
                        before_digest: Sha256Digest::from_optional_bytes(
                            row.before_digest.as_deref(),
                        )?,
                        delta_json: row.delta_json.clone(),
                        semantic_hash: Sha256Digest::from_bytes(row.semantic_hash.clone())?,
                        dependency_hash: Sha256Digest::from_bytes(row.dependency_hash.clone())?,
                        compiler_version: row.compiler_version.clone(),
                        // Same-transaction authoritative values from the claim
                        // install (post-increment attempts + server expiry).
                        attempts: claim.attempts,
                        cas_version: row.cas_version,
                        lease_owner: claim.lease_owner.clone(),
                        lease_expires_at: claim.lease_expires_at,
                    };
                    Ok(ClaimedStableEventOutcome::Claimed {
                        claim: Box::new(claim),
                        event: Box::new(event),
                    })
                }
                Err(GrantRepositoryError::ClaimRace) => {
                    // Zero-row install: future backoff window or a live foreign
                    // lease won between our locked read and the install. The
                    // row stays untouched; recovery converges durably.
                    Ok(ClaimedStableEventOutcome::Busy {
                        event_id: row.event_id.clone(),
                    })
                }
                Err(error) => Err(error),
            }
        }
        other => Ok(ClaimedStableEventOutcome::InDoubt {
            event_id: row.event_id.clone(),
            reason: format!("code=grant_repository.claim_by_event_unknown_status;status={other}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization_projection_repository::{
        PublishedAggregateFrontier, PublishedFrontierEvent, PublishedGenerationSummary,
    };
    use astral_types::{
        BindingLayer, GrantEffect, GrantProvenance, GrantSourceKind, GrantState, ValidityWindow,
    };

    // ── Partition lease / discovery contracts (multi-tenant redesign Phase 1) ──

    /// Direct stable-event claims perform the same durable sibling ordering
    /// probe as the partition claim path before installing a lease.
    #[test]
    fn stable_event_claim_has_a_separate_sibling_probe() {
        assert!(STABLE_EVENT_SIBLING_ORDER_PROBE_SQL.contains("pred.grant_id = ?"));
        assert!(STABLE_EVENT_SIBLING_ORDER_PROBE_SQL.contains("pred.target_version < ?"));
        assert!(
            STABLE_EVENT_SIBLING_ORDER_PROBE_SQL.contains("pred.status IN ('PENDING', 'LEASED')")
        );
        assert!(STABLE_EVENT_SIBLING_ORDER_PROBE_SQL.contains("FOR UPDATE"));
        assert_eq!(placeholder_count(STABLE_EVENT_SIBLING_ORDER_PROBE_SQL), 3);
    }
    #[test]
    fn partition_lease_audit_contract_is_bounded_and_non_authorizing() {
        assert!(PARTITION_LEASE_AUDIT_INSERT_SQL.starts_with("INSERT INTO audit_log"));
        assert!(PARTITION_LEASE_AUDIT_INSERT_SQL.contains("'AUTHZ_PARTITION_LEASE'"));
        assert!(PARTITION_LEASE_AUDIT_INSERT_SQL.contains("'INTERNAL'"));
        assert!(PARTITION_LEASE_AUDIT_INSERT_SQL.contains("tenant_id"));
        assert!(PARTITION_LEASE_AUDIT_STATE_FOR_UPDATE_SQL.contains("FOR UPDATE"));
        assert!(PARTITION_LEASE_AUDIT_STATE_FOR_UPDATE_SQL.contains("lease_token_hash = ?"));

        let identity =
            crate::authorization_projection_repository::ProjectionAggregateIdentity::new(
                7, "CARD", 17,
            )
            .expect("valid partition identity");
        let handle = PartitionLeaseHandle {
            identity: identity.clone(),
            lease_owner: "auth-projector-p0:run-123".to_owned(),
            token: DeltaLeaseToken::with_audit_correlation_id_for_test(
                "audit-test-token",
                Uuid::parse_str("00000000-0000-4000-8000-000000000001")
                    .expect("valid fixed correlation UUID"),
            ),
        };
        let request_id = partition_lease_audit_request_id(
            &handle,
            Some(2),
            Some(5),
            PartitionLeaseAuditOutcome::Reclaim,
        );
        assert_eq!(request_id.len(), 64, "audit_log.request_id width");
        assert_eq!(
            request_id,
            partition_lease_audit_request_id(
                &handle,
                Some(2),
                Some(5),
                PartitionLeaseAuditOutcome::Reclaim,
            )
        );
        assert_ne!(
            request_id,
            partition_lease_audit_request_id(
                &handle,
                Some(2),
                Some(5),
                PartitionLeaseAuditOutcome::Release,
            ),
            "one lease episode needs a distinct key for each state transition"
        );
        let other_episode = PartitionLeaseHandle {
            identity: identity.clone(),
            lease_owner: handle.lease_owner.clone(),
            token: DeltaLeaseToken::with_audit_correlation_id_for_test(
                "other-audit-test-token",
                Uuid::parse_str("00000000-0000-4000-8000-000000000002")
                    .expect("valid fixed correlation UUID"),
            ),
        };
        assert_ne!(
            request_id,
            partition_lease_audit_request_id(
                &other_episode,
                Some(2),
                Some(5),
                PartitionLeaseAuditOutcome::Reclaim,
            ),
            "separate acquire cycles under one worker must not collide"
        );

        let detail = partition_lease_audit_detail(
            &handle,
            Some(2),
            Some(5),
            PartitionLeaseAuditOutcome::Reclaim,
            &request_id,
        )
        .expect("bounded detail");
        assert!(detail.len() <= PARTITION_LEASE_AUDIT_DETAIL_MAX_BYTES);
        let value: serde_json::Value = serde_json::from_str(&detail).expect("valid JSON detail");
        assert_eq!(value["outcome"], "RECLAIM");
        assert_eq!(value["tenantId"], 7);
        assert_eq!(value["aggregateType"], "CARD");
        assert_eq!(value["aggregateId"], 17);
        assert_eq!(value["leaseOwner"], handle.lease_owner);
        assert_eq!(
            value["leaseCorrelationId"],
            handle.token.audit_correlation_id().to_string()
        );
        assert_eq!(value["requestId"], request_id);
        assert_eq!(value["generation"], 2);
        assert_eq!(value["casVersion"], 5);
        assert!(
            !detail.contains(handle.token.as_str())
                && !detail.contains(&handle.token.token_hash().as_hex()),
            "audit detail must never expose the raw lease token or its hash"
        );
    }

    #[test]
    fn partition_lease_audit_outcomes_are_exhaustive_and_heartbeat_success_is_absent() {
        let cases = [
            (
                PartitionLeaseAuditOutcome::Acquire,
                "partition_lease_acquire",
                "ACQUIRE",
            ),
            (
                PartitionLeaseAuditOutcome::Reclaim,
                "partition_lease_reclaim",
                "RECLAIM",
            ),
            (
                PartitionLeaseAuditOutcome::Release,
                "partition_lease_release",
                "RELEASE",
            ),
            (
                PartitionLeaseAuditOutcome::RenewLost,
                "partition_lease_renew_lost",
                "RENEW_LOST",
            ),
        ];
        for (outcome, action, label) in cases {
            assert_eq!(outcome.action(), action);
            assert_eq!(outcome.as_str(), label);
            assert!(outcome
                .reason()
                .contains("code=grant_repository.partition_lease"));
        }
        assert!(
            !PARTITION_LEASE_RENEW_SQL.contains("audit_log"),
            "successful heartbeats must stay on the lease-table liveness path"
        );
    }

    #[test]
    fn partition_claim_candidate_narrows_identity_and_mirrors_the_claim_gate() {
        // Partition narrowing: the identity filter rides on the tenant filter.
        assert!(DELTA_CLAIM_CANDIDATE_PARTITION_SQL
            .contains("WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ?"));
        // Sibling-ordering gate must mirror the tenant claim statements.
        assert!(DELTA_CLAIM_CANDIDATE_PARTITION_SQL
            .contains("pred.grant_id = authorization_delta_event.grant_id"));
        assert!(DELTA_CLAIM_CANDIDATE_PARTITION_SQL
            .contains("pred.target_version < authorization_delta_event.target_version"));
        assert!(DELTA_CLAIM_CANDIDATE_PARTITION_SQL.contains("LIMIT 1 FOR UPDATE"));
    }

    #[test]
    fn partition_discovery_mirrors_claim_eligibility_and_gate() {
        assert!(PARTITION_DISCOVERY_FROM_SQL
            .contains("MIN(COALESCE(next_attempt_at, created_at)) AS oldest_due"));
        assert!(PARTITION_DISCOVERY_ELIGIBILITY_SQL
            .contains("GROUP BY tenant_id, aggregate_type, aggregate_id"));
        assert!(PARTITION_DISCOVERY_ELIGIBILITY_SQL.contains("ORDER BY oldest_due"));
        // Eligibility predicate mirrors the claim candidate: due PENDING or
        // expired LEASED, and the sibling gate keeps discovered partitions
        // claimable right now (no discover-then-starve).
        assert!(PARTITION_DISCOVERY_ELIGIBILITY_SQL
            .contains("next_attempt_at IS NULL OR next_attempt_at <= UTC_TIMESTAMP()"));
        assert!(
            PARTITION_DISCOVERY_ELIGIBILITY_SQL.contains("pred.status IN ('PENDING', 'LEASED')")
        );
    }

    #[test]
    fn partition_lease_takeover_only_matches_expiry_or_self() {
        // A live lease held by ANOTHER owner matches nothing: zero rows -> Busy.
        assert!(PARTITION_LEASE_TAKEOVER_SQL.contains(
            "lease_expires_at <= UTC_TIMESTAMP() OR (lease_owner = ? AND lease_token_hash = ?)"
        ));
        assert!(PARTITION_LEASE_TAKEOVER_SQL.contains("generation = generation + 1"));
        // Renewal is owner+token pinned, exactly like the delta heartbeat.
        assert!(PARTITION_LEASE_RENEW_SQL.contains("AND lease_owner = ? AND lease_token_hash = ?"));
        assert!(PARTITION_LEASE_RELEASE_SQL
            .contains("DELETE FROM authorization_projection_partition_lease"));
    }

    #[test]
    fn budget_reclaim_pulls_only_parked_exhausted_rows_of_one_aggregate() {
        // Partition scoping: one aggregate identity, nothing cross-aggregate.
        assert!(PARTITION_BUDGET_RECLAIM_SQL
            .contains("WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ?"));
        // Only PENDING rows parked in a FUTURE window carry the exhaustion
        // marker; ordinary short-backoff rows and already-due rows match nothing.
        assert!(PARTITION_BUDGET_RECLAIM_SQL.contains("AND status = 'PENDING'"));
        assert!(PARTITION_BUDGET_RECLAIM_SQL
            .contains("AND next_attempt_at IS NOT NULL AND next_attempt_at > UTC_TIMESTAMP()"));
        assert!(PARTITION_BUDGET_RECLAIM_SQL
            .contains("AND last_error LIKE '%code=auth_projector.attempt_budget_exhausted%'"));
        // Durable row-version discipline applies to this mutation too.
        assert!(PARTITION_BUDGET_RECLAIM_SQL.contains("cas_version = cas_version + 1"));
    }

    #[tokio::test]
    async fn partition_lease_validation_fails_before_any_database_call() {
        let pool = sqlx::MySqlPool::connect_lazy("mysql://partition-lease-validation.invalid/none")
            .expect("lazy pool for validation-only tests");
        // Invalid identity (zero tenant) never reaches the database.
        let identity = crate::authorization_projection_repository::ProjectionAggregateIdentity::new(
            0, "CARD", 1,
        );
        assert!(identity.is_err());
        // Invalid lease window fails fast too.
        let identity =
            crate::authorization_projection_repository::ProjectionAggregateIdentity::new(
                1, "CARD", 1,
            )
            .expect("valid identity");
        let error = acquire_partition_lease(&pool, &identity, "owner", 0)
            .await
            .expect_err("zero lease seconds must fail closed");
        assert!(format!("{error}").contains("lease"));
        // Discovery bounds are validated before any query as well.
        let error = discover_claimable_partitions(&pool, &[0], 8)
            .await
            .expect_err("non-positive tenant id must fail closed");
        assert!(format!("{error}").contains("tenant_id"));
        let error = discover_claimable_partitions(&pool, &[1], 0)
            .await
            .expect_err("zero limit must fail closed");
        assert!(format!("{error}").contains("partition_discovery_limit_out_of_bounds"));

        let invalid_handle = PartitionLeaseHandle {
            identity: identity.clone(),
            lease_owner: "".to_owned(),
            token: DeltaLeaseToken::with_audit_correlation_id_for_test("token", Uuid::nil()),
        };
        let error = renew_partition_lease(&pool, &invalid_handle, 60)
            .await
            .expect_err("invalid handle must fail before a database transaction");
        assert!(format!("{error}").contains("lease_owner"));
        let error = release_partition_lease(&pool, &invalid_handle)
            .await
            .expect_err("invalid handle must fail before a database transaction");
        assert!(format!("{error}").contains("lease_owner"));
        let nil_correlation_handle = PartitionLeaseHandle {
            identity,
            lease_owner: "owner".to_owned(),
            token: DeltaLeaseToken::with_audit_correlation_id_for_test("token", Uuid::nil()),
        };
        let error = renew_partition_lease(&pool, &nil_correlation_handle, 60)
            .await
            .expect_err("nil audit correlation must fail before a database transaction");
        assert!(format!("{error}").contains("audit_correlation_id"));
    }

    fn test_tenant() -> TenantScope {
        TenantScope::new(7, Some(11)).unwrap()
    }

    fn other_tenant_typed() -> TenantScope {
        TenantScope::new(8, None).unwrap()
    }

    fn grant_a() -> GrantId {
        GrantId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap()
    }

    fn active_grant(revision_value: u64) -> CanonicalGrant {
        CanonicalGrant {
            grant_id: grant_a(),
            revision: GrantRevision::new(revision_value).unwrap(),
            state: GrantState::Active,
            source_kind: GrantSourceKind::RuleSet,
            binding_layer: BindingLayer::Overlay,
            tenant: test_tenant(),
            card_id: 17,
            user_id: 42,
            resource: "learn_subject".to_owned(),
            action: "read".to_owned(),
            effect: GrantEffect::Allow,
            validity: ValidityWindow::between(100, 200),
            provenance: GrantProvenance {
                source_id: "rule-set-entry-9".to_owned(),
                source_entry: Some("rule-set-entry-9".to_owned()),
                binding_id: Some("binding-3".to_owned()),
                delegation_id: None,
                operation_id: "op-1".to_owned(),
                event_id: Some("event-1".to_owned()),
                actor_user_id: Some(42),
            },
        }
    }

    fn entry_with(revision: u64, state: GrantState, status_active: bool) -> CurrentLedgerEntry {
        CurrentLedgerEntry {
            revision: GrantRevision::new(revision).unwrap(),
            state,
            status_active,
        }
    }

    fn ledger_row(grant: &CanonicalGrant) -> RawLedgerRow {
        let payload = serde_json::to_string(&grant.canonicalized().unwrap()).unwrap();
        RawLedgerRow {
            revision_no: grant.revision.value() as i64,
            tenant_id: grant.tenant.tenant_id,
            card_id: Some(grant.card_id),
            aggregate_type: "CARD".to_owned(),
            aggregate_id: 17,
            grant_id: encode_grant_id_sql(grant.grant_id).unwrap(),
            status: STATUS_ACTIVE.to_owned(),
            is_tombstone: matches!(grant.state, GrantState::Removed | GrantState::Revoked) as i8,
            grant_payload: payload,
            semantic_hash: vec![1u8; 32],
            dependency_hash: vec![2u8; 32],
            operation_id: "op-1".to_owned(),
            event_id: "event-1".to_owned(),
            compiler_version: "phase2-authorization-kernel-v1".to_owned(),
        }
    }

    // ── canonical SQL boundary helpers ──────────────────────────────────────

    #[test]
    fn grant_id_sql_round_trip_and_rejections() {
        let id = grant_a();
        let encoded = encode_grant_id_sql(id).unwrap();
        assert_eq!(encoded.len(), 36);
        assert_eq!(encoded.as_str(), "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(decode_grant_id_sql(&encoded).unwrap(), id);

        for poisoned in [
            "550E8400-E29B-41D4-A716-446655440000",          // uppercase
            "{550e8400-e29b-41d4-a716-44665544000}",         // braces
            "urn:uuid:550e8400-e29b-41d4-a716-446655440000", // urn prefix
            "550e8400e29b41d4a716446655440000",              // missing hyphens
            "550e8400-e29b-41d4-a716-44665544000",           // short
            "550e8400-e29b-41d4-a716-4466554400000",         // long
            "550e8400-e29b-g1d4-a716-446655440000",          // non-hex char
            "550e8400_e29b_41d4_a716_446655440000",          // wrong separators
            "00000000-0000-0000-0000-000000000000",          // nil
        ] {
            assert!(
                decode_grant_id_sql(poisoned).is_err(),
                "poisoned spelling must be rejected: {poisoned}"
            );
        }
    }

    #[test]
    fn sha256_digest_round_trip_matches_known_vector() {
        // sha256("abc") reference vector.
        let expected_hex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let digest = Sha256Digest::from_raw_bytes(sha256_digest_bytes(b"abc"));
        assert_eq!(digest.as_hex(), expected_hex);
        assert_eq!(
            format!("{digest:?}"),
            format!("Sha256Digest({expected_hex})")
        );

        let decoded = Sha256Digest::from_hex(expected_hex).unwrap();
        assert_eq!(decoded, digest);
        assert_eq!(decoded.as_bytes().len(), 32);

        let from_column = Sha256Digest::from_bytes(decoded.as_bytes().to_vec()).unwrap();
        assert_eq!(from_column, decoded);

        assert!(Sha256Digest::from_optional_bytes(None).unwrap().is_none());
        assert_eq!(
            Sha256Digest::from_optional_bytes(Some(decoded.as_bytes().as_slice())).unwrap(),
            Some(decoded)
        );
    }

    #[test]
    fn sha256_digest_rejects_wrong_wire_forms() {
        let valid_hex = Sha256Digest::from_raw_bytes(sha256_digest_bytes(b"x")).as_hex();
        for poisoned in [
            String::new(),
            valid_hex.to_ascii_uppercase(),
            String::from("g").repeat(64),
            String::from("a").repeat(63),
            String::from("a").repeat(65),
        ] {
            assert!(
                Sha256Digest::from_hex(&poisoned).is_err(),
                "poisoned digest wire form must be rejected"
            );
        }
        assert!(Sha256Digest::from_bytes(vec![0u8; 31]).is_err());
        assert!(Sha256Digest::from_bytes(vec![0u8; 33]).is_err());
        assert!(Sha256Digest::from_optional_bytes(Some([0u8; 31].as_slice())).is_err());
    }

    #[test]
    fn bigint_binds_reject_overflow() {
        assert_eq!(bind_i64(1, "f").unwrap(), 1i64);
        assert!(bind_i64(u64::MAX, "f").is_err());
    }

    #[test]
    fn last_error_is_truncated_to_column_limit() {
        let oversized = String::from("x").repeat(MAX_LAST_ERROR_LENGTH + 50);
        assert_eq!(
            truncate_last_error(&oversized).chars().count(),
            MAX_LAST_ERROR_LENGTH
        );
        assert_eq!(truncate_last_error("short"), "short");
    }

    #[test]
    fn lease_token_hash_is_deterministic_and_debug_redacted() {
        let token = DeltaLeaseToken::for_test("run-token-1");
        let again = DeltaLeaseToken::for_test("run-token-1");
        assert_eq!(token.token_hash(), again.token_hash());

        let other = DeltaLeaseToken::for_test("run-token-2");
        assert_ne!(token.token_hash(), other.token_hash());

        let rendered = format!("{token:?}");
        assert!(rendered.contains("REDACTED"), "{rendered}");
        assert!(!rendered.contains("run-token-1"), "{rendered}");

        // Repository-generated tokens stay run-scoped random UUID strings and
        // hash to distinct fence values per claim attempt.
        let fresh_one = DeltaLeaseToken::new_run_scoped();
        let fresh_two = DeltaLeaseToken::new_run_scoped();
        assert_eq!(fresh_one.as_str().len(), 36);
        assert_ne!(fresh_one.token_hash(), fresh_two.token_hash());
        assert_ne!(fresh_one.token_hash(), token.token_hash());
    }

    // ── pure ledger transition rules ────────────────────────────────────────

    #[test]
    fn transition_add_requires_initial_revision_one() {
        let fresh_add = GrantDelta::add(active_grant(1));
        assert_eq!(
            decide_revision_transition(grant_a(), None, &fresh_add).unwrap(),
            1
        );

        // A brand-new durable identity claiming any later revision implies lost
        // history and is refused fail-closed.
        let gapped_first = GrantDelta::add(active_grant(2));
        assert_eq!(
            decide_revision_transition(grant_a(), None, &gapped_first),
            Err(LedgerTransitionConflict::FirstRevisionNotInitial {
                grant_id: grant_a(),
                attempted: 2
            })
        );
    }

    #[test]
    fn transition_add_duplicate_active_and_frozen_rejected() {
        let duplicate = GrantDelta::add(active_grant(1));
        assert_eq!(
            decide_revision_transition(
                grant_a(),
                Some(entry_with(1, GrantState::Active, true)),
                &duplicate
            ),
            Err(LedgerTransitionConflict::DuplicateActiveGrant {
                grant_id: grant_a()
            })
        );

        // A frozen (non-ACTIVE) row can never be extended, not even by ADD.
        let frozen_ledger = Some(entry_with(3, GrantState::Active, false));
        assert_eq!(
            decide_revision_transition(grant_a(), frozen_ledger, &duplicate),
            Err(LedgerTransitionConflict::FrozenStatus {
                grant_id: grant_a()
            })
        );
    }

    #[test]
    fn transition_add_resurrection_requires_strict_successor() {
        let stale_resurrect = GrantDelta::add(active_grant(2));
        assert_eq!(
            decide_revision_transition(
                grant_a(),
                Some(entry_with(2, GrantState::Revoked, true)),
                &stale_resurrect
            ),
            Err(LedgerTransitionConflict::ResurrectionRevisionConflict {
                grant_id: grant_a(),
                attempted: 2
            })
        );

        let resurrect = GrantDelta::add(active_grant(3));
        assert_eq!(
            decide_revision_transition(
                grant_a(),
                Some(entry_with(2, GrantState::Removed, true)),
                &resurrect
            )
            .unwrap(),
            3
        );
    }

    #[test]
    fn transition_update_enforces_cas_stale_gap_unknown() {
        let update_ok = GrantDelta::update(active_grant(2), GrantRevision::new(1).unwrap());
        assert_eq!(
            decide_revision_transition(
                grant_a(),
                Some(entry_with(1, GrantState::Active, true)),
                &update_ok
            )
            .unwrap(),
            2
        );

        // Stale expectation (expected < head).
        let stale = GrantDelta::update(active_grant(2), GrantRevision::new(1).unwrap());
        assert_eq!(
            decide_revision_transition(
                grant_a(),
                Some(entry_with(5, GrantState::Active, true)),
                &stale
            ),
            Err(LedgerTransitionConflict::StaleExpectedRevision {
                grant_id: grant_a(),
                expected: 1,
                actual: 5
            })
        );

        // Gapped expectation (expected > head). The payload stays the valid
        // structural successor of its own expected revision, so the conflict
        // comes purely from the durable head lagging behind.
        let gapped = GrantDelta::update(active_grant(7), GrantRevision::new(6).unwrap());
        assert_eq!(
            decide_revision_transition(
                grant_a(),
                Some(entry_with(2, GrantState::Active, true)),
                &gapped
            ),
            Err(LedgerTransitionConflict::GappedExpectedRevision {
                grant_id: grant_a(),
                expected: 6,
                actual: 2
            })
        );

        // Unknown identity for UPDATE.
        assert_eq!(
            decide_revision_transition(grant_a(), None, &gapped),
            Err(LedgerTransitionConflict::UnknownGrant {
                grant_id: grant_a()
            })
        );

        // UPDATE over an existing tombstone is refused even at exact CAS.
        let over_tombstone = GrantDelta::update(active_grant(3), GrantRevision::new(2).unwrap());
        assert_eq!(
            decide_revision_transition(
                grant_a(),
                Some(entry_with(2, GrantState::Revoked, true)),
                &over_tombstone
            ),
            Err(LedgerTransitionConflict::InactiveLedgerRecord {
                grant_id: grant_a(),
                state: GrantState::Revoked
            })
        );
    }

    #[test]
    fn transition_tombstones_append_strict_successor_only_once() {
        let revoke = GrantDelta::revoke(grant_a(), GrantRevision::new(4).unwrap());
        assert_eq!(
            decide_revision_transition(
                grant_a(),
                Some(entry_with(4, GrantState::Active, true)),
                &revoke
            )
            .unwrap(),
            5
        );
        let remove = GrantDelta::remove(grant_a(), GrantRevision::new(4).unwrap());
        assert_eq!(
            decide_revision_transition(
                grant_a(),
                Some(entry_with(4, GrantState::Active, true)),
                &remove
            )
            .unwrap(),
            5
        );

        // Identical tombstone replay.
        assert_eq!(
            decide_revision_transition(
                grant_a(),
                Some(entry_with(4, GrantState::Revoked, true)),
                &revoke
            ),
            Err(LedgerTransitionConflict::DuplicateTombstone {
                grant_id: grant_a(),
                state: GrantState::Revoked
            })
        );

        // Cross-kind tombstone at the same CAS revision.
        assert_eq!(
            decide_revision_transition(
                grant_a(),
                Some(entry_with(4, GrantState::Revoked, true)),
                &remove
            ),
            Err(LedgerTransitionConflict::CrossTombstoneKind {
                grant_id: grant_a(),
                state: GrantState::Revoked
            })
        );

        // Tombstones against unknown identities stay unknown.
        assert_eq!(
            decide_revision_transition(grant_a(), None, &revoke),
            Err(LedgerTransitionConflict::UnknownGrant {
                grant_id: grant_a()
            })
        );

        // Frozen rows refuse everything, including tombstoning.
        assert_eq!(
            decide_revision_transition(
                grant_a(),
                Some(entry_with(4, GrantState::Active, false)),
                &revoke
            ),
            Err(LedgerTransitionConflict::FrozenStatus {
                grant_id: grant_a()
            })
        );
    }

    #[test]
    fn transition_invalid_delta_is_flagged_not_panic() {
        // Payload skipping its successor revision violates the typed contract
        // and maps to ContractInvalid instead of panicking.
        let malformed = GrantDelta::update(active_grant(9), GrantRevision::new(1).unwrap());
        assert_eq!(
            decide_revision_transition(
                grant_a(),
                Some(entry_with(1, GrantState::Active, true)),
                &malformed
            ),
            Err(LedgerTransitionConflict::ContractInvalid {
                grant_id: grant_a()
            })
        );
    }

    #[test]
    fn delta_event_type_vocabulary_and_payload_decoding_are_locked() {
        assert_eq!(DeltaEventType::Add.as_str(), "ADD");
        assert_eq!(DeltaEventType::Update.as_str(), "UPDATE");
        assert_eq!(DeltaEventType::Remove.as_str(), "REMOVE");
        assert_eq!(DeltaEventType::Revoke.as_str(), "REVOKE");
        for kind in [
            DeltaEventType::Add,
            DeltaEventType::Update,
            DeltaEventType::Remove,
            DeltaEventType::Revoke,
        ] {
            assert_eq!(DeltaEventType::from_sql(kind.as_str()).unwrap(), kind);
        }
        assert!(DeltaEventType::from_sql("UPSERT").is_err());

        let payload = serde_json::to_string(&GrantDelta::add(active_grant(1))).unwrap();
        let decoded = decode_delta_event_payload(&payload).unwrap();
        assert_eq!(decoded.operation_name(), "ADD");

        let stored_grant =
            decode_stored_grant_payload(&serde_json::to_string(&active_grant(3)).unwrap()).unwrap();
        assert_eq!(stored_grant.revision.value(), 3);

        // Non-canonical payloads (whitespace around identifiers survive only if
        // serialization was not canonical) are treated as poisoned storage.
        let mut noncanonical = active_grant(3);
        noncanonical.resource = String::from(" padded_resource ");
        let serialized = serde_json::to_string(&noncanonical).unwrap();
        assert!(decode_stored_grant_payload(&serialized).is_err());
    }

    // ── SQL shape contracts ─────────────────────────────────────────────────

    fn placeholder_count(sql: &str) -> usize {
        sql.bytes().filter(|byte| *byte == b'?').count()
    }

    #[test]
    fn revision_statements_match_their_bind_lists() {
        assert_eq!(placeholder_count(GRANT_REVISION_INSERT_SQL), 14);
        // tenant, type, aggregate, grant id.
        assert_eq!(placeholder_count(REVISION_LATEST_FOR_UPDATE_SQL), 4);
        assert!(REVISION_LATEST_FOR_UPDATE_SQL.contains("FOR UPDATE"));
        assert!(REVISION_LATEST_FOR_UPDATE_SQL.contains("ORDER BY revision_no DESC LIMIT 1"));
        // Append-only invariant: existing revisions are never mutated.
        assert!(!GRANT_REVISION_INSERT_SQL.contains("ON DUPLICATE KEY"));
        assert!(!GRANT_REVISION_INSERT_SQL.to_uppercase().contains(" DELETE"));
    }

    #[tokio::test]
    async fn revoke_class_delta_requires_published_evidence_invalidation_flag() {
        let pool = sqlx::MySqlPool::connect_lazy("mysql://localhost:1/astral_test")
            .expect("lazy pool construction must not connect");
        for (event_type, delta) in [
            (
                DeltaEventType::Remove,
                GrantDelta::remove(grant_a(), GrantRevision::initial()),
            ),
            (
                DeltaEventType::Revoke,
                GrantDelta::revoke(grant_a(), GrantRevision::initial()),
            ),
        ] {
            let request = DeltaEventAppendRequest {
                tenant_id: 7,
                card_id: Some(17),
                aggregate_type: "CARD".to_owned(),
                aggregate_id: 17,
                grant_id: grant_a(),
                event_id: format!("flag-test-{}", event_type.as_str()),
                operation_id: "flag-test-operation".to_owned(),
                event_type,
                base_version: 0,
                target_version: 1,
                source_generation: 1,
                revoke_fence: 0,
                invalidates_published_evidence: false,
                before_image_json: None,
                before_digest_hex: None,
                delta_json: serde_json::to_string(&delta).unwrap(),
                semantic_hash_hex: "a".repeat(64),
                dependency_hash_hex: "b".repeat(64),
                compiler_version: "test".to_owned(),
                next_attempt_at: None,
            };
            let error = append_delta_event(&pool, &request)
                .await
                .expect_err("revoke-class delta without the flag must fail before SQL");
            assert!(
                matches!(error, GrantRepositoryError::ScopeViolation(message)
                if message.contains("revoke_class_requires_published_evidence_invalidation"))
            );
        }
    }

    #[test]
    fn delta_event_statements_match_their_bind_lists() {
        assert_eq!(placeholder_count(DELTA_EVENT_INSERT_SQL), 21);
        assert!(!DELTA_EVENT_INSERT_SQL.contains("ON DUPLICATE KEY"));
        assert!(
            DELTA_EVENT_INSERT_SQL.contains(format!("'{}'", DELTA_STATUS_PENDING).as_str())
                || placeholder_count(DELTA_EVENT_INSERT_SQL) == 21
        );

        // Claim selection locks exactly one deterministic candidate row.
        for candidate_sql in [
            DELTA_CLAIM_CANDIDATE_UNSCOPED_SQL,
            DELTA_CLAIM_CANDIDATE_CARD_SCOPED_SQL,
        ] {
            assert!(candidate_sql.contains("FOR UPDATE"));
            assert!(candidate_sql.contains("LIMIT 1"));
            assert!(candidate_sql.contains("ORDER BY COALESCE(next_attempt_at, created_at)"));
            assert!(candidate_sql.contains("lease_expires_at <= UTC_TIMESTAMP()"));
            // Future-scheduled PENDING rows are gated; expired-LEASED takeover
            // and every other status rule live in the shared predicate.
            assert!(candidate_sql.contains(DELTA_CLAIM_ELIGIBLE_PREDICATE));
            // The per-grant sibling-ordering gate rides on BOTH candidate
            // statements byte-equal to the reference const: claiming an event
            // whose chain predecessor is non-terminal would only burn the
            // attempt budget (partitioner deterministically blocks it).
            assert!(
                candidate_sql.contains(DELTA_CLAIM_SIBLING_ORDER_GATE),
                "claim candidate must carry the sibling-ordering gate"
            );
        }
        assert_eq!(placeholder_count(DELTA_CLAIM_CANDIDATE_UNSCOPED_SQL), 1);
        assert_eq!(placeholder_count(DELTA_CLAIM_CANDIDATE_CARD_SCOPED_SQL), 2);
        assert!(DELTA_CLAIM_CANDIDATE_UNSCOPED_SQL.starts_with("SELECT delta_event_id"));
        assert!(DELTA_CLAIM_CANDIDATE_CARD_SCOPED_SQL.contains("tenant_id = ? AND card_id = ?"));

        // Install = owner + token hash + server-side expiry, guarded by the
        // SAME row-level eligibility text as candidate selection (defensive
        // mirror). The sibling-ordering gate is deliberately NOT here: MySQL
        // error 1093 forbids a correlated subquery on the UPDATE target, the
        // row is already FOR UPDATE-locked, and the partitioner decision
        // fail-closes any cross-row race — a gate here could not even compile
        // as SQL without a whole-table materialized workaround.
        assert_eq!(placeholder_count(DELTA_CLAIM_INSTALL_SQL), 4);
        assert!(DELTA_CLAIM_INSTALL_SQL.contains(DELTA_CLAIM_ELIGIBLE_PREDICATE));
        assert!(!DELTA_CLAIM_INSTALL_SQL.contains("NOT EXISTS"));
        assert!(DELTA_CLAIM_INSTALL_SQL.contains("status = 'LEASED'"));
        assert!(DELTA_CLAIM_INSTALL_SQL.contains("lease_token_hash = ?"));
        assert!(DELTA_CLAIM_INSTALL_SQL.contains("attempts = attempts + 1"));
        assert!(DELTA_CLAIM_INSTALL_SQL.contains("cas_version = cas_version + 1"));
        assert!(DELTA_CLAIM_INSTALL_SQL.contains("TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP())"));
        assert!(DELTA_CLAIM_INSTALL_SQL.contains("lease_expires_at <= UTC_TIMESTAMP()"));

        // Post-install readback surfaces expiry AND the durable attempts.
        assert!(DELTA_CLAIM_READBACK_SQL.contains("SELECT lease_expires_at, attempts "));
        assert_eq!(placeholder_count(DELTA_CLAIM_READBACK_SQL), 1);
    }

    #[test]
    fn claim_predicate_gates_future_pending_rows_but_takes_over_expired_leases() {
        // The PENDING arm is the only arm allowed to consult next_attempt_at:
        // a scheduled retry must cool down before re-entering the queue.
        let pending_arm_start = DELTA_CLAIM_ELIGIBLE_PREDICATE
            .find("status = 'PENDING'")
            .expect("predicate must gate PENDING");
        let leased_arm_offset = DELTA_CLAIM_ELIGIBLE_PREDICATE
            .find("status = 'LEASED'")
            .expect("predicate must reclaim LEASED");
        assert!(pending_arm_start < leased_arm_offset);
        let pending_arm = &DELTA_CLAIM_ELIGIBLE_PREDICATE[pending_arm_start..leased_arm_offset];
        assert!(
            pending_arm.contains("next_attempt_at IS NULL OR next_attempt_at <= UTC_TIMESTAMP()")
        );
        // The expired-LEASED branch is an unknown-result takeover: it MUST NOT
        // be blocked by any stale next_attempt_at (reconcile first), so that
        // column appears nowhere inside it.
        let leased_arm = &DELTA_CLAIM_ELIGIBLE_PREDICATE[leased_arm_offset..];
        assert!(!leased_arm.contains("next_attempt_at"), "{leased_arm}");
        assert!(leased_arm.contains("lease_expires_at IS NOT NULL"));
        assert!(leased_arm.contains("lease_expires_at <= UTC_TIMESTAMP()"));

        // Terminal rows are unreachable through both statements.
        for sql in [
            DELTA_CLAIM_CANDIDATE_UNSCOPED_SQL,
            DELTA_CLAIM_CANDIDATE_CARD_SCOPED_SQL,
            DELTA_CLAIM_INSTALL_SQL,
        ] {
            assert!(!sql.contains(DELTA_STATUS_SUCCEEDED));
            assert!(sql.contains(DELTA_STATUS_PENDING) && sql.contains(DELTA_STATUS_LEASED));
        }

        // Sibling-ordering gate shape: same-grant predecessors block the
        // claim only while non-terminal; a published (SUCCEEDED) or
        // quarantined predecessor never appears in the gate, so the gate can
        // neither skip a published chain nor silently stall an unorderable one.
        assert!(
            DELTA_CLAIM_SIBLING_ORDER_GATE
                .contains("pred.grant_id = authorization_delta_event.grant_id"),
            "the gate must key on the per-grant chain, not the aggregate"
        );
        assert!(
            DELTA_CLAIM_SIBLING_ORDER_GATE
                .contains("pred.target_version < authorization_delta_event.target_version"),
            "only strict chain predecessors may gate"
        );
        assert!(
            DELTA_CLAIM_SIBLING_ORDER_GATE.contains("pred.status IN ('PENDING', 'LEASED')"),
            "terminal predecessors (SUCCEEDED/QUARANTINED) must never gate"
        );
        assert_eq!(placeholder_count(DELTA_CLAIM_SIBLING_ORDER_GATE), 0);
    }

    #[test]
    fn lease_guard_requires_identity_status_and_liveness() {
        let guard = LEASE_GUARD_SUFFIX;
        assert!(guard.contains("delta_event_id = ?"));
        assert!(guard.contains("event_id = ?"));
        assert!(guard.contains("lease_owner = ?"));
        assert!(guard.contains("lease_token_hash = ?"));
        assert!(guard.contains("status = 'LEASED'"));
        assert!(guard.contains("lease_expires_at IS NOT NULL"));
        assert!(guard.contains("lease_expires_at > UTC_TIMESTAMP()"));
        assert_eq!(placeholder_count(guard), 4);

        for base in [
            DELTA_COMPLETE_SQL_BASE,
            DELTA_FAIL_SQL_BASE,
            DELTA_RELEASE_SQL_BASE,
        ] {
            assert!(base.starts_with("UPDATE authorization_delta_event"));
            assert!(base.contains("lease_owner = NULL"));
            assert!(base.contains("lease_token_hash = NULL"));
            assert!(base.contains("lease_expires_at = NULL"));
        }
        // Completion clears the error field; failure records it; release keeps
        // the event immediately retryable.
        assert!(DELTA_COMPLETE_SQL_BASE.contains("last_error = NULL"));
        assert!(DELTA_COMPLETE_SQL_BASE.contains("'SUCCEEDED'"));
        assert!(DELTA_FAIL_SQL_BASE.contains("last_error = ?"));
        assert!(DELTA_FAIL_SQL_BASE
            .contains("next_attempt_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP())"));
        assert!(DELTA_RELEASE_SQL_BASE.contains("next_attempt_at = NULL"));

        // Fail-path SET placeholders precede the four guard parameters.
        let composed = format!("{DELTA_FAIL_SQL_BASE}{LEASE_GUARD_SUFFIX}");
        assert_eq!(placeholder_count(&composed), 6);
        assert!(composed.rfind("last_error = ?").unwrap() < composed.find("WHERE").unwrap());

        assert_eq!(STATUS_ACTIVE, "ACTIVE");
        assert_eq!(DELTA_STATUS_PENDING, "PENDING");
        assert_eq!(DELTA_STATUS_LEASED, "LEASED");
        assert_eq!(DELTA_STATUS_SUCCEEDED, "SUCCEEDED");
    }

    #[test]
    fn lease_heartbeat_guard_is_owner_token_status_without_liveness() {
        // Exactly one SET placeholder (lease_seconds) precedes the four guard
        // parameters — bind order mirrors the fail path contract.
        assert_eq!(placeholder_count(DELTA_LEASE_HEARTBEAT_SQL), 5);
        assert!(DELTA_LEASE_HEARTBEAT_SQL.starts_with("UPDATE authorization_delta_event"));
        let where_offset = DELTA_LEASE_HEARTBEAT_SQL
            .find("WHERE")
            .expect("heartbeat guard");
        let set_clause = &DELTA_LEASE_HEARTBEAT_SQL[..where_offset];
        // Server-side time is authoritative; no client clock ever crosses.
        assert_eq!(
            set_clause.trim(),
            "UPDATE authorization_delta_event \
             SET lease_expires_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP())"
        );

        // Ownership proof: exact row + event + owner + token hash + LEASED.
        let guard = &DELTA_LEASE_HEARTBEAT_SQL[where_offset..];
        for fragment in [
            "delta_event_id = ?",
            "event_id = ?",
            "lease_owner = ?",
            "lease_token_hash = ?",
            "status = 'LEASED'",
        ] {
            assert!(guard.contains(fragment), "heartbeat guard needs {fragment}");
        }
        // Deliberately NO liveness predicate: reviving an expired-but-never-
        // reclaimed lease is the point of the heartbeat; any real takeover
        // rewrites owner/token (or leaves LEASED) and fails the CAS instead.
        assert!(!guard.contains("lease_expires_at"));
        // The heartbeat is not an attempt and not a CAS-version bump: attempt
        // budgets stay exact and no publish-path pin depends on the version.
        assert!(!DELTA_LEASE_HEARTBEAT_SQL.contains("attempts"));
        assert!(!DELTA_LEASE_HEARTBEAT_SQL.contains("cas_version"));
        assert!(!DELTA_LEASE_HEARTBEAT_SQL.contains("next_attempt_at"));
        // Nothing else is cleared or rescheduled: only lease_expires_at moves.
        assert!(!DELTA_LEASE_HEARTBEAT_SQL.contains("NULL"));
        // Terminal rows are unreachable through the heartbeat.
        assert!(!DELTA_LEASE_HEARTBEAT_SQL.contains(DELTA_STATUS_SUCCEEDED));
        assert!(!DELTA_LEASE_HEARTBEAT_SQL.contains(DELTA_STATUS_QUARANTINED));
        assert!(!DELTA_LEASE_HEARTBEAT_SQL.contains(DELTA_STATUS_PENDING));
    }

    #[test]
    fn lease_window_gate_is_shared_by_claim_and_heartbeat() {
        assert!(validate_lease_seconds(1).is_ok());
        assert!(validate_lease_seconds(MAX_DELTA_LEASE_SECONDS).is_ok());
        for invalid in [0, -1, MAX_DELTA_LEASE_SECONDS + 1, i64::MAX] {
            let error = validate_lease_seconds(invalid).expect_err("must refuse window");
            assert!(matches!(error, GrantRepositoryError::ScopeViolation(_)));
            assert!(error.to_string().contains("invalid_lease_seconds"));
            assert!(error.to_string().contains(&format!("value={invalid}")));
        }
    }

    #[test]
    fn lease_identity_gate_covers_heartbeat_inputs() {
        let identity = DeltaLeaseIdentity {
            delta_event_id: 9,
            event_id: "evt-hb".to_owned(),
            lease_owner: "auth-projector:run".to_owned(),
            lease_token: DeltaLeaseToken::for_test("heartbeat-token"),
        };
        assert!(validate_lease_identity(&identity).is_ok());
        let token = identity.lease_token.token_hash();
        // The token never reaches the database in raw form.
        assert_ne!(
            token.as_bytes(),
            identity.lease_token.as_str().as_bytes(),
            "raw secret must not double as its own hash"
        );
        for broken in [
            DeltaLeaseIdentity {
                delta_event_id: 0,
                ..identity.clone()
            },
            DeltaLeaseIdentity {
                event_id: String::new(),
                ..identity.clone()
            },
            DeltaLeaseIdentity {
                lease_owner: " ".to_owned(),
                ..identity.clone()
            },
            DeltaLeaseIdentity {
                lease_token: DeltaLeaseToken::for_test("   "),
                ..identity
            },
        ] {
            let error = validate_lease_identity(&broken).expect_err("must refuse identity");
            assert!(matches!(error, GrantRepositoryError::ScopeViolation(_)));
        }
    }

    #[test]
    fn load_statement_scope_variants_bind_expected_values() {
        let variants = [
            ledger_load_statement(false, false),
            ledger_load_statement(true, false),
            ledger_load_statement(false, true),
            ledger_load_statement(true, true),
        ];
        let expected_binds = [2usize, 4, 3, 5]; // (tenant, LIMIT) plus scope values
        for (statement, expected) in variants.iter().zip(expected_binds) {
            assert_eq!(placeholder_count(statement), expected, "{statement}");
            assert!(statement.contains("FROM authorization_grant_revision"));
            assert!(statement.contains("tenant_id = ?"));
            assert!(statement.contains("ORDER BY grant_id ASC, revision_no ASC LIMIT ?"));
        }
        assert!(variants[1].contains("aggregate_type = ? AND aggregate_id = ?"));
        assert!(variants[2].contains("card_id = ?"));
        assert!(variants[3].contains("card_id = ?"));
        assert!(variants[3].contains("aggregate_type = ?"));
    }

    // ── ledger row/history decoding (pure loader side) ──────────────────────

    #[test]
    fn decode_ledger_row_accepts_consistent_rows() {
        let row = ledger_row(&active_grant(4));
        let entry = decode_ledger_row(&row).unwrap();
        assert_eq!(entry.revision_no, 4);
        assert!(!entry.is_tombstone);
        assert_eq!(entry.grant.state, GrantState::Active);
        assert_eq!(entry.tenant_id, test_tenant().tenant_id);
        assert_eq!(entry.card_id, Some(17));
        assert_eq!(
            entry.semantic_hash.as_hex(),
            Sha256Digest::from_bytes(vec![1; 32]).unwrap().as_hex()
        );
        assert_eq!(entry.compiler_version, "phase2-authorization-kernel-v1");
        assert_eq!(entry.operation_id, "op-1");
    }

    #[test]
    fn decode_ledger_row_fails_closed_on_drift() {
        // Row column claiming a different tenant than its payload is poisoned.
        let mut tenant_drift = ledger_row(&active_grant(1));
        tenant_drift.tenant_id = other_tenant_typed().tenant_id;
        assert!(decode_ledger_row(&tenant_drift).is_err());

        // A self-consistent foreign-tenant row decodes: tenant *filtering* is
        // enforced by the SQL predicates / scope parameters and again at
        // hot-state composition (see the isolation test below).
        let mut foreign = active_grant(1);
        foreign.tenant = other_tenant_typed();
        let foreign_entry = decode_ledger_row(&ledger_row(&foreign)).unwrap();
        assert_eq!(foreign_entry.tenant_id, other_tenant_typed().tenant_id);

        // Tombstone flag disagreeing with the payload state.
        let mut wrong_flag = ledger_row(&active_grant(1));
        wrong_flag.is_tombstone = 1;
        assert!(decode_ledger_row(&wrong_flag).is_err());

        // Missing tombstone flag on a tombstoned payload.
        let mut tombstoned = active_grant(2);
        tombstoned.state = GrantState::Removed;
        let mut missing_flag_row = ledger_row(&tombstoned);
        missing_flag_row.is_tombstone = 0;
        assert!(decode_ledger_row(&missing_flag_row).is_err());

        // Revision number drift between column and payload.
        let mut drifted = ledger_row(&active_grant(3));
        drifted.revision_no = 9;
        assert!(decode_ledger_row(&drifted).is_err());

        // Hash width poisoning from the binary columns.
        let mut bad_hash = ledger_row(&active_grant(1));
        bad_hash.semantic_hash = vec![1u8; 16];
        assert!(decode_ledler_row_is_error(&bad_hash));

        // Frozen/unrecognized status never feeds recovery.
        let mut frozen = ledger_row(&active_grant(1));
        frozen.status = "ARCHIVED".to_owned();
        assert!(decode_ledger_row(&frozen).is_err());

        // Identity spelling must stay canonical CHAR(36).
        let mut uppercased = ledger_row(&active_grant(1));
        uppercased.grant_id = uppercased.grant_id.to_ascii_uppercase();
        assert!(decode_ledger_row(&uppercased).is_err());

        // Card identity drift between row and payload.
        let mut card_drift = ledger_row(&active_grant(1));
        card_drift.card_id = Some(99);
        assert!(decode_ledger_row(&card_drift).is_err());

        // Non-positive scope columns are poisoned too.
        let mut zero_aggregate = ledger_row(&active_grant(1));
        zero_aggregate.aggregate_id = 0;
        assert!(decode_ledger_row(&zero_aggregate).is_err());
    }

    fn decode_ledler_row_is_error(row: &RawLedgerRow) -> bool {
        decode_ledger_row(row).is_err()
    }

    #[test]
    fn history_reduction_picks_latest_and_detects_gaps() {
        let updated = {
            let mut value = active_grant(2);
            value.resource = String::from("other_resource");
            value
        };
        let history = vec![ledger_row(&active_grant(1)), ledger_row(&updated)];
        let latest = latest_entries_from_history(&history).unwrap();
        assert_eq!(latest.len(), 1);
        assert_eq!(latest[0].revision_no, 2);
        assert_eq!(latest[0].grant.resource, "other_resource");

        // Tombstone history survives reduction as the latest record.
        let removed = {
            let mut value = active_grant(2);
            value.state = GrantState::Removed;
            value.provenance.operation_id = String::from("op-2");
            value.provenance.event_id = Some(String::from("event-2"));
            value
        };
        let mut removed_row = ledger_row(&removed);
        removed_row.operation_id = String::from("op-2");
        removed_row.event_id = String::from("event-2");
        let tombstoned_history = vec![ledger_row(&active_grant(1)), removed_row];
        let reduced = latest_entries_from_history(&tombstoned_history).unwrap();
        assert_eq!(reduced.len(), 1);
        assert!(reduced[0].is_tombstone);
        assert_eq!(reduced[0].grant.state, GrantState::Removed);
        assert_eq!(reduced[0].operation_id, "op-2");
        assert_eq!(
            reduced[0].grant.provenance.operation_id, "op-2",
            "payload provenance and row column stay consistent"
        );

        // Missing intermediate revision => lost history => abort.
        let gapped = vec![ledger_row(&active_grant(1)), ledger_row(&active_grant(3))];
        assert!(latest_entries_from_history(&gapped).is_err());

        // History not starting at one likewise.
        let unrooted = vec![ledger_row(&active_grant(2))];
        assert!(latest_entries_from_history(&unrooted).is_err());

        // Empty ledger recovers to an empty set.
        assert!(latest_entries_from_history(&[]).unwrap().is_empty());
    }

    #[test]
    fn hot_state_builder_segregates_tombstones_from_effective_segments() {
        let first = active_grant(1);
        // Identity B carries a full two-revision history ending as tombstone.
        let b_id = GrantId::parse("7c9e6679-7425-40de-944b-e07fc1f90ae7").unwrap();
        let mut b_first = active_grant(1);
        b_first.grant_id = b_id;
        let mut b_removed = active_grant(2);
        b_removed.grant_id = b_id;
        b_removed.state = GrantState::Removed;
        let mut live = active_grant(1);
        live.grant_id = GrantId::parse("7c9e6679-7425-40de-944b-e07fc1f90ae8").unwrap();

        let history = vec![
            ledger_row(&first),
            ledger_row(&b_first),
            ledger_row(&b_removed),
            ledger_row(&live),
        ];
        let entries = latest_entries_from_history(&history).unwrap();
        assert_eq!(entries.len(), 3);

        let hot_state = hot_state_from_entries(
            &test_tenant(),
            9,
            DependencyVector::default(),
            policy_engine::COMPILER_VERSION,
            &entries,
        )
        .unwrap();

        // The recovered ledger keeps all three records including the tombstone.
        assert_eq!(hot_state.all_grants().len(), 3);
        // Only ACTIVE ALLOW grants form effective segments.
        assert_eq!(hot_state.active_grants().len(), 2);
        let tombstoned_state = hot_state
            .grant(GrantId::parse("7c9e6679-7425-40de-944b-e07fc1f90ae7").unwrap())
            .is_some_and(|grant| grant.state == GrantState::Removed);
        assert!(tombstoned_state);
        assert!(!hot_state.segments.is_empty());

        // Deterministic rebuild ordering/hashes for identical inputs.
        let again = hot_state_from_entries(
            &test_tenant(),
            9,
            DependencyVector::default(),
            policy_engine::COMPILER_VERSION,
            &entries,
        )
        .unwrap();
        assert_eq!(again.semantic_hash, hot_state.semantic_hash);
        assert_eq!(again.segment_keys(), hot_state.segment_keys());
    }

    #[test]
    fn hot_state_composition_refuses_cross_tenant_entries() {
        // A self-consistent foreign-tenant entry is valid on its own but must
        // never compose into another tenant's hot state.
        let mut foreign = active_grant(1);
        foreign.tenant = other_tenant_typed();
        let entries = latest_entries_from_history(&[ledger_row(&foreign)]).unwrap();
        assert_eq!(entries.len(), 1);

        let outcome = hot_state_from_entries(
            &test_tenant(),
            9,
            DependencyVector::default(),
            policy_engine::COMPILER_VERSION,
            &entries,
        );
        assert!(
            matches!(outcome, Err(policy_engine::CompilerError::InvalidState(ref message))
                if message.contains("tenant")),
            "cross-tenant composition must fail closed, got {outcome:?}"
        );
    }

    #[test]
    fn capacity_and_duration_caps_stay_bounded() {
        assert_eq!(MAX_LEDGER_ROWS, 100_000);
        assert_eq!(MAX_DELTA_LEASE_SECONDS, 3_600);
        assert_eq!(MAX_BACKOFF_SECONDS, 3_600);
        assert_eq!(MAX_JSON_BYTES, 4 * 1024 * 1024);
        assert_eq!(MAX_GRANT_OPERATION_ID_LENGTH, 128);
        assert_eq!(MAX_GRANT_LEASE_OWNER_LENGTH, 128);
        assert_eq!(MAX_EVENT_ID_LENGTH, 128);
        assert_eq!(MAX_COMPILER_VERSION_LENGTH, 64);
        assert_eq!(MAX_AGGREGATE_TYPE_LENGTH, 32);
        assert!(!validated_text_locked_length(129));
    }

    fn validated_text_locked_length(length: usize) -> bool {
        length <= MAX_EVENT_ID_LENGTH
    }

    /// 无历史 delta 时第一个事件从 base 0 → target 1；之后严格 +1；溢出 fail-closed。
    #[test]
    fn next_delta_version_chains_monotonically_and_fails_closed_on_overflow() {
        assert_eq!(next_delta_version(None).unwrap(), (0, 1));
        assert_eq!(next_delta_version(Some(1)).unwrap(), (1, 2));
        assert_eq!(next_delta_version(Some(41)).unwrap(), (41, 42));
        assert!(
            next_delta_version(Some(i64::MAX)).is_err(),
            "overflow must be refused instead of wrapping"
        );
    }

    // ── strict claimed-delta readback decoder ───────────────────────────────

    fn claimed_raw_row() -> ClaimedDeltaRawRow {
        let delta_json =
            serde_json::to_string(&GrantDelta::add(active_grant(1))).expect("delta json");
        ClaimedDeltaRawRow {
            delta_event_id: 11,
            event_id: "event-claim-1".to_owned(),
            operation_id: "op-claim-1".to_owned(),
            event_type: "ADD".to_owned(),
            tenant_id: 7,
            card_id: Some(17),
            aggregate_type: "CARD".to_owned(),
            aggregate_id: 17,
            grant_id: encode_grant_id_sql(grant_a()).unwrap(),
            base_version: 0,
            target_version: 1,
            source_generation: 4,
            revoke_fence: 2,
            before_image_json: None,
            before_digest: None,
            delta_json,
            semantic_hash: vec![9u8; 32],
            dependency_hash: vec![8u8; 32],
            compiler_version: "phase2-authorization-kernel-v1".to_owned(),
            status: DELTA_STATUS_LEASED.to_owned(),
            attempts: 3,
            cas_version: 5,
            lease_owner: Some("worker-a".to_owned()),
            lease_token_hash: Some(vec![7u8; 32]),
            lease_expires_at: Some(time::PrimitiveDateTime::new(
                time::Date::from_calendar_date(2030, time::Month::January, 1).unwrap(),
                time::Time::MIDNIGHT,
            )),
        }
    }

    #[test]
    fn claimed_readback_decode_happy_path_is_complete_and_typed() {
        let row = claimed_raw_row();
        let decoded = row
            .clone()
            .decode("worker-a", &[7u8; 32])
            .expect("well-formed LEASED row must decode");
        assert_eq!(decoded.delta_event_id, 11);
        assert_eq!(decoded.event_id, "event-claim-1");
        assert_eq!(decoded.operation_id, "op-claim-1");
        assert_eq!(decoded.event_type, DeltaEventType::Add);
        assert_eq!(decoded.tenant_id, 7);
        assert_eq!(decoded.card_id, Some(17));
        assert_eq!(decoded.aggregate_type, "CARD");
        assert_eq!(decoded.aggregate_id, 17);
        assert_eq!(decoded.grant_id, grant_a());
        assert_eq!((decoded.base_version, decoded.target_version), (0, 1));
        assert_eq!(decoded.source_generation, 4);
        assert_eq!(decoded.revoke_fence, 2);
        assert!(decoded.before_image_json.is_none() && decoded.before_digest.is_none());
        assert_eq!(decoded.semantic_hash.as_bytes(), [9u8; 32]);
        assert_eq!(decoded.dependency_hash.as_bytes(), [8u8; 32]);
        assert_eq!(decoded.compiler_version, "phase2-authorization-kernel-v1");
        assert_eq!(decoded.attempts, 3);
        assert_eq!(decoded.cas_version, 5);
        assert_eq!(decoded.lease_owner, "worker-a");
    }

    #[test]
    fn claimed_readback_refuses_lease_and_liveness_drift_without_diagnosis_leakage() {
        // Owner mismatch → LeaseCasFailed; token hash mismatch likewise.
        assert_eq!(
            claimed_raw_row()
                .decode("worker-b", &[7u8; 32])
                .unwrap_err()
                .to_string(),
            GrantRepositoryError::LeaseCasFailed(
                "code=grant_repository.claimed_owner_mismatch".to_owned()
            )
            .to_string()
        );
        assert!(matches!(
            claimed_raw_row().decode("worker-a", &[6u8; 32]),
            Err(GrantRepositoryError::LeaseCasFailed(ref message))
                if message.contains("claimed_token_mismatch")
        ));
        // Not leased / missing expiry are poisoned storage.
        let mut pending = claimed_raw_row();
        pending.status = DELTA_STATUS_PENDING.to_owned();
        assert!(matches!(
            pending.decode("worker-a", &[7u8; 32]),
            Err(GrantRepositoryError::Mapping(ref message))
                if message.contains("claimed_row_not_leased")
        ));
        let mut unexpired_missing = claimed_raw_row();
        unexpired_missing.lease_expires_at = None;
        assert!(matches!(
            unexpired_missing.decode("worker-a", &[7u8; 32]),
            Err(GrantRepositoryError::Mapping(ref message))
                if message.contains("claimed_expiry_missing")
        ));
        // Half lease evidence (owner set but no hash) is refused the same way.
        let mut half_lease = claimed_raw_row();
        half_lease.lease_token_hash = None;
        assert!(half_lease.decode("worker-a", &[7u8; 32]).is_err());
    }

    #[test]
    fn claimed_readback_enforces_numeric_identity_and_payload_contracts() {
        let expect_failure = |mutate: &dyn Fn(&mut ClaimedDeltaRawRow), needle: &str| {
            let mut row = claimed_raw_row();
            mutate(&mut row);
            let error = row.decode("worker-a", &[7u8; 32]).unwrap_err().to_string();
            assert!(error.contains(needle), "expected {needle} inside: {error}");
        };

        expect_failure(&|row| row.attempts = 0, "claimed_attempts_below_one");
        expect_failure(&|row| row.cas_version = -1, "negative_cas_version");
        expect_failure(&|row| row.base_version = -1, "negative_version");
        expect_failure(
            &|row| row.target_version = row.base_version,
            "non_advancing_target_version",
        );
        expect_failure(
            &|row| row.source_generation = 0,
            "invalid_source_generation",
        );
        expect_failure(&|row| row.revoke_fence = -3, "invalid_revoke_fence");
        expect_failure(&|row| row.tenant_id = 0, "non_positive_id");

        // Canonical UUID boundary on CHAR(36).
        expect_failure(
            &|row| row.grant_id = row.grant_id.to_ascii_uppercase(),
            "invalid_char36_grant_id",
        );

        // Payload must agree with stored event type and grant identity.
        expect_failure(
            &|row| row.event_type = "REVOKE".to_owned(),
            "event_type_delta_mismatch",
        );
        expect_failure(
            &|row| {
                row.grant_id = encode_grant_id_sql(
                    GrantId::parse("550e8400-e29b-41d4-a716-44665544ffff").unwrap(),
                )
                .unwrap()
            },
            "delta_grant_mismatch",
        );

        // before-image/digest pairing stays atomic.
        expect_failure(
            &|row| row.before_image_json = Some("{\"x\":1}".to_owned()),
            "before_image_digest_pairing",
        );

        // Hash width enforcement (BINARY(32)).
        expect_failure(&|row| row.semantic_hash.truncate(31), "invalid_binary32");
    }

    #[test]
    fn claimed_readback_statement_shape_pins_status_owner_token_liveness() {
        for fragment in [
            "AND status = 'LEASED'",
            "AND lease_owner = ?",
            "AND lease_token_hash = ?",
            "lease_expires_at IS NOT NULL",
            "lease_expires_at > UTC_TIMESTAMP()",
            "FOR UPDATE",
        ] {
            assert!(
                CLAIMED_DELTA_LIVE_TAIL.contains(fragment),
                "missing {fragment}"
            );
        }
        assert!(CLAIMED_DELTA_LIVE_TAIL.starts_with(" FROM authorization_delta_event"));
        assert!(CLAIMED_DELTA_COLUMNS.contains("before_image_json"));
        assert!(CLAIMED_DELTA_COLUMNS.contains("lease_token_hash"));
    }

    #[test]
    fn delta_fence_relation_is_enforced_at_append_and_readback_boundaries() {
        // Zero stays the valid initial fence; equality with the source
        // generation is the contract ceiling.
        assert!(validate_delta_fence_relation(5, 0).is_ok());
        assert!(validate_delta_fence_relation(1, 0).is_ok());
        assert!(validate_delta_fence_relation(3, 3).is_ok());

        // A fence may never outrun the source generation that produced it —
        // mirroring astral-types validate_fence so every append and every
        // stored-row readback fails closed on the same relation.
        let error = validate_delta_fence_relation(2, 3).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("revoke_fence_exceeds_source_generation"),
            "unexpected refusal: {error}"
        );
    }

    // ── QUARANTINED terminal state (planning slice) ─────────────────────────

    fn projection_identity_fixture(
    ) -> crate::authorization_projection_repository::ProjectionAggregateIdentity {
        crate::authorization_projection_repository::ProjectionAggregateIdentity::new(7, "CARD", 17)
            .unwrap()
    }

    fn partition_grant_id(tail: u16) -> GrantId {
        GrantId::parse(&format!("550e8400-e29b-41d4-a716-44665544{tail:04x}")).unwrap()
    }

    fn ledger_row_for(
        grant_id: GrantId,
        revision: u64,
        event: &str,
        state: GrantState,
    ) -> RawLedgerRow {
        let mut grant = active_grant(revision);
        grant.grant_id = grant_id;
        grant.state = state;
        RawLedgerRow {
            revision_no: revision as i64,
            tenant_id: grant.tenant.tenant_id,
            card_id: Some(grant.card_id),
            aggregate_type: "CARD".to_owned(),
            aggregate_id: 17,
            grant_id: encode_grant_id_sql(grant_id).unwrap(),
            status: STATUS_ACTIVE.to_owned(),
            is_tombstone: matches!(state, GrantState::Removed | GrantState::Revoked) as i8,
            grant_payload: serde_json::to_string(&grant.canonicalized().unwrap()).unwrap(),
            semantic_hash: vec![1u8; 32],
            dependency_hash: vec![2u8; 32],
            operation_id: format!("op-{event}"),
            event_id: event.to_owned(),
            compiler_version: "phase2-authorization-kernel-v1".to_owned(),
        }
    }

    #[derive(Clone, Copy)]
    struct FixtureDelta {
        generation: u64,
        event: &'static str,
        grant: GrantId,
        base: i64,
        target: i64,
    }

    fn frontier_fixture(generation: u64, deltas: &[FixtureDelta]) -> PublishedAggregateFrontier {
        let identity = projection_identity_fixture();
        let pointer =
            crate::authorization_projection_repository::AuthorizationCurrentPointerRecord {
                pointer_id: 1,
                identity: identity.clone(),
                card_id: Some(17),
                current_generation: generation,
                manifest_id: 100 + generation as i64,
                event_id: deltas
                    .last()
                    .map(|delta| delta.event.to_owned())
                    .unwrap_or_default(),
                operation_id: "op-frontier".to_owned(),
                semantic_hash: Sha256Digest::from_raw_bytes(sha256_digest_bytes(b"semantic")),
                dependency_hash: Sha256Digest::from_raw_bytes(sha256_digest_bytes(b"dependency")),
                compiler_version: "phase2-authorization-kernel-v1".to_owned(),
                revoke_fence: 0,
                revoke_fence_proven: true,
                cas_version: 3,
            };
        let manifest = PublishedGenerationSummary {
            manifest_id: pointer.manifest_id,
            generation,
            source_generation: 9,
            projected_generation: 9,
            event_id: pointer.event_id.clone(),
            operation_id: "op-frontier".to_owned(),
            semantic_hash: Sha256Digest::from_raw_bytes(sha256_digest_bytes(b"semantic")),
            dependency_hash: Sha256Digest::from_raw_bytes(sha256_digest_bytes(b"dependency")),
            compiler_version: "phase2-authorization-kernel-v1".to_owned(),
            manifest_digest: Sha256Digest::from_raw_bytes(sha256_digest_bytes(b"manifest")),
            parent_manifest_id: None,
            revoke_fence: 0,
            card_id: Some(17),
        };
        let events = deltas
            .iter()
            .map(|delta| PublishedFrontierEvent {
                generation: delta.generation,
                plan_id: delta.generation as i64,
                event_id: delta.event.to_owned(),
                operation_id: format!("op-{}", delta.event),
                grant_id: delta.grant,
                event_type: DeltaEventType::Add,
                delta_base_version: delta.base,
                delta_target_version: delta.target,
                source_generation: delta.generation * 10,
                revoke_fence: 0,
                semantic_hash: Sha256Digest::from_raw_bytes(sha256_digest_bytes(b"semantic")),
                dependency_hash: Sha256Digest::from_raw_bytes(sha256_digest_bytes(b"dependency")),
                compiler_version: "phase2-authorization-kernel-v1".to_owned(),
            })
            .collect();
        PublishedAggregateFrontier {
            identity,
            card_id: Some(17),
            pointer,
            manifest,
            events,
        }
    }

    #[test]
    fn quarantine_statements_pin_shape_guards_and_cas() {
        // Quarantine = same live-lease guard family, one extra last_error bind.
        let composed = format!("{DELTA_QUARANTINE_SQL_BASE}{LEASE_GUARD_SUFFIX}");
        assert_eq!(placeholder_count(&composed), 5);
        for fragment in [
            "SET status = 'QUARANTINED'",
            "next_attempt_at = NULL",
            "lease_owner = NULL",
            "lease_token_hash = NULL",
            "AND status = 'LEASED'",
            "lease_token_hash = ?",
            "lease_expires_at > UTC_TIMESTAMP()",
        ] {
            assert!(composed.contains(fragment), "missing {fragment}");
        }
        // Quarantine deliberately leaves `cas_version` untouched: the stable
        // post-quarantine CAS is the operator requeue's expected pin, bumped
        // only once by `cas_version = cas_version + 1` in DELTA_REQUEUE_SQL.
        assert!(
            !DELTA_QUARANTINE_SQL_BASE.contains("cas_version"),
            "quarantine must preserve cas_version for the requeue CAS pin"
        );

        // Operator requeue: exactly the QUARANTINED row pinned by CAS; no lease
        // guards (a quarantined row owns none), no automatic scheduling.
        assert_eq!(placeholder_count(DELTA_REQUEUE_SQL), 5);
        assert!(DELTA_REQUEUE_SQL.contains("SET status = 'PENDING'"));
        assert!(DELTA_REQUEUE_SQL.contains("cas_version = cas_version + 1"));
        assert!(
            DELTA_REQUEUE_SQL.contains("status = 'QUARANTINED' AND cas_version = ?"),
            "CAS pin required"
        );
        assert!(
            !DELTA_REQUEUE_SQL.contains("last_error"),
            "quarantine reason text must survive a requeue"
        );

        // Bounded status listing stays deterministic and parameterized.
        let list_statement = format!("{DELTA_STATUS_LIST_COLUMNS}{DELTA_STATUS_LIST_TAIL}");
        assert_eq!(placeholder_count(&list_statement), 3);
        assert!(list_statement.contains("ORDER BY delta_event_id ASC LIMIT ?"));
        assert!(!list_statement.contains("grant_payload"));
        assert!(!list_statement.contains("lease_token_hash"));
    }

    #[test]
    fn quarantined_rows_are_never_claimable_and_never_readable_as_claimed() {
        // Claim candidate SQL arms only ever mention PENDING / expired LEASED.
        for sql in [
            DELTA_CLAIM_CANDIDATE_UNSCOPED_SQL,
            DELTA_CLAIM_CANDIDATE_CARD_SCOPED_SQL,
            DELTA_CLAIM_INSTALL_SQL,
        ] {
            assert!(
                !sql.contains(DELTA_STATUS_QUARANTINED),
                "claim statements must never select quarantined rows"
            );
            assert!(sql.contains("'PENDING'") && sql.contains("'LEASED'"));
        }
        // read_claimed accepts LEASED only: a stored QUARANTINED status is
        // refused by the WHERE guard AND re-checked in the decoder.
        let mut row = claimed_raw_row();
        row.status = DELTA_STATUS_QUARANTINED.to_owned();
        let error = row.decode("worker-a", &[7u8; 32]).unwrap_err().to_string();
        assert!(error.contains("claimed_row_not_leased"), "{error}");
    }

    #[test]
    fn quarantine_and_requeue_input_gates_fail_closed() {
        // Stable code + detail composition; empty codes refused.
        let composed =
            compose_quarantine_last_error("projection_verify_failed", "digest drift").unwrap();
        assert_eq!(
            composed,
            "code=projection_verify_failed;detail=digest drift"
        );
        let oversized_code = String::from("x").repeat(MAX_LAST_ERROR_LENGTH + 10);
        let truncated = compose_quarantine_last_error(&oversized_code, "").unwrap();
        assert_eq!(truncated.chars().count(), MAX_LAST_ERROR_LENGTH);
        assert!(
            compose_quarantine_last_error("   ", "detail").is_err()
                || compose_quarantine_last_error("", "detail").is_err()
                || compose_quarantine_last_error("\t", "detail").is_err()
        );

        let base_request = QuarantinedDeltaRequeueRequest {
            delta_event_id: 41,
            event_id: "event-q".to_owned(),
            operation_id: "op-q".to_owned(),
            expected_cas_version: 6,
            operator_operation_id: "operator-op-1".to_owned(),
            reason: "manual verification".to_owned(),
            next_attempt_at: None,
        };
        assert_eq!(validate_requeue_inputs(&base_request).unwrap(), 7);
        let mut negative_cas = base_request.clone();
        negative_cas.expected_cas_version = -1_i64;
        assert!(validate_requeue_inputs(&negative_cas).is_err());
        let mut overflowed = base_request.clone();
        overflowed.expected_cas_version = i64::MAX;
        assert!(validate_requeue_inputs(&overflowed)
            .unwrap_err()
            .to_string()
            .contains("cas_version_overflow"));
        let mut without_reason = base_request.clone();
        without_reason.reason = " ".to_owned();
        assert!(validate_requeue_inputs(&without_reason).is_err());
        let mut oversize_operator = base_request.clone();
        oversize_operator.operator_operation_id = "o".repeat(MAX_GRANT_OPERATION_ID_LENGTH + 1);
        assert!(validate_requeue_inputs(&oversize_operator).is_err());
        let mut oversized_reason = base_request.clone();
        oversized_reason.reason = "r".repeat(MAX_LAST_ERROR_LENGTH + 1);
        assert!(validate_requeue_inputs(&oversized_reason)
            .unwrap_err()
            .to_string()
            .contains("invalid_requeue_reason"));
        let mut control_reason = base_request.clone();
        control_reason.reason = "bad\u{7}reason".to_owned();
        assert!(validate_requeue_inputs(&control_reason).is_err());
    }

    #[test]
    fn delta_status_list_decode_is_strict_fail_closed() {
        let raw_row = |status: &str| DeltaStatusRawRow {
            delta_event_id: 91,
            event_id: "event-list".to_owned(),
            operation_id: "op-list".to_owned(),
            tenant_id: 7,
            card_id: Some(17),
            aggregate_type: "CARD".to_owned(),
            aggregate_id: 17,
            grant_id: encode_grant_id_sql(grant_a()).unwrap(),
            base_version: 0,
            target_version: 1,
            source_generation: 5,
            revoke_fence: 2,
            status: status.to_owned(),
            attempts: 1,
            cas_version: 9,
            last_error: Some("code=x;detail=y".to_owned()),
        };
        let decoded =
            decode_delta_status_row(raw_row(DELTA_STATUS_QUARANTINED), DELTA_STATUS_QUARANTINED)
                .expect("well-formed quarantine row must decode");
        assert_eq!(decoded.delta_event_id, 91);
        assert_eq!(decoded.grant_id, grant_a());
        assert_eq!(decoded.source_generation, 5);
        assert_eq!(decoded.last_error.as_deref(), Some("code=x;detail=y"));

        // Drifted status never normalizes.
        let error =
            decode_delta_status_row(raw_row(DELTA_STATUS_PENDING), DELTA_STATUS_QUARANTINED)
                .unwrap_err()
                .to_string();
        assert!(error.contains("delta_status_row_drift"), "{error}");

        // Fence relation violations are poisoned rows.
        let mut poisoned = raw_row(DELTA_STATUS_QUARANTINED);
        poisoned.revoke_fence = 6; // > source_generation 5
        assert!(decode_delta_status_row(poisoned, DELTA_STATUS_QUARANTINED)
            .unwrap_err()
            .to_string()
            .contains("revoke_fence_exceeds_source_generation"));

        // Canonical CHAR(36) enforcement is shared.
        let mut bad_uuid = raw_row(DELTA_STATUS_QUARANTINED);
        bad_uuid.grant_id = bad_uuid.grant_id.to_ascii_uppercase();
        assert!(decode_delta_status_row(bad_uuid, DELTA_STATUS_QUARANTINED).is_err());
    }

    fn fixture_a() -> GrantId {
        partition_grant_id(1)
    }
    fn fixture_b() -> GrantId {
        partition_grant_id(2)
    }
    fn fixture_c() -> GrantId {
        partition_grant_id(3)
    }

    #[test]
    fn partition_publishes_multi_grant_chains_with_tombstones_and_classifies_tails() {
        // Two fully published chains (one ending in a tombstone) plus:
        // - an unclaimed sibling head (excluded / not proven published);
        // - a claimed continuation directly on top (candidate).
        let frontier = frontier_fixture(
            4,
            &[
                FixtureDelta {
                    generation: 1,
                    event: "e-a1",
                    grant: fixture_a(),
                    base: 0,
                    target: 1,
                },
                FixtureDelta {
                    generation: 2,
                    event: "e-b1",
                    grant: fixture_b(),
                    base: 0,
                    target: 1,
                },
                FixtureDelta {
                    generation: 3,
                    event: "e-a2",
                    grant: fixture_a(),
                    base: 1,
                    target: 2,
                },
                FixtureDelta {
                    generation: 4,
                    event: "e-b2",
                    grant: fixture_b(),
                    base: 1,
                    target: 2,
                },
            ],
        );
        let rows = vec![
            ledger_row_for(fixture_a(), 1, "e-a1", GrantState::Active),
            ledger_row_for(fixture_a(), 2, "e-a2", GrantState::Active),
            ledger_row_for(fixture_b(), 1, "e-b1", GrantState::Active),
            ledger_row_for(fixture_b(), 2, "e-b2", GrantState::Revoked),
            ledger_row_for(fixture_c(), 1, "e-c-pending", GrantState::Active),
            ledger_row_for(partition_grant_id(4), 1, "e-d-claimed", GrantState::Active),
        ];
        let claimed = vec![String::from("e-d-claimed")];

        let outcome =
            partition_ledger_at_published_frontier(&rows, &frontier, &claimed).expect("partition");
        assert_eq!(outcome.published_heads.len(), 2);
        let head_a = &outcome.published_heads[0];
        assert_eq!(head_a.entry.grant.revision.value(), 2);
        assert_eq!(head_a.proving_generation, 3);
        assert_eq!(
            (head_a.delta_base_version, head_a.delta_target_version),
            (1, 2)
        );
        assert_eq!(outcome.published_heads[1].proving_generation, 4);
        assert!(outcome.published_heads[1].entry.is_tombstone);

        assert_eq!(outcome.candidate_rows.len(), 1);
        assert_eq!(
            outcome.candidate_rows[0].entry.event_id, "e-d-claimed",
            "claimed continuations become candidates, never assumed published"
        );
        assert_eq!(outcome.excluded_rows.len(), 1);
        assert_eq!(
            outcome.excluded_rows[0].kind,
            LedgerExclusionKind::NotProvenPublished
        );
        // Tombstones stay visible in the ledger buckets while authorizing
        // nothing: the tombstoned head kept its flag end-to-end.
        assert!(frontier.frontier_generation("e-b2").is_some());
        assert!(frontier.frontier_generation("missing").is_none());
    }

    #[test]
    fn partition_fails_closed_on_unsorted_gap_duplicate_or_mismatch_proofs() {
        let frontier = frontier_fixture(
            2,
            &[
                FixtureDelta {
                    generation: 1,
                    event: "e-a1",
                    grant: fixture_a(),
                    base: 0,
                    target: 1,
                },
                FixtureDelta {
                    generation: 2,
                    event: "e-b1",
                    grant: fixture_b(),
                    base: 0,
                    target: 1,
                },
            ],
        );
        let happy_rows = [
            ledger_row_for(fixture_a(), 1, "e-a1", GrantState::Active),
            ledger_row_for(fixture_b(), 1, "e-b1", GrantState::Active),
        ];

        // Unsorted input is poison, never silently repaired.
        let swapped = [happy_rows[1].clone(), happy_rows[0].clone()];
        assert!(
            partition_ledger_at_published_frontier(&swapped, &frontier, &[])
                .unwrap_err()
                .to_string()
                .contains("partition_unsorted_input")
        );

        // Missing intermediate revisions abort (lost history).
        let gapped = vec![
            ledger_row_for(fixture_a(), 1, "e-a1", GrantState::Active),
            ledger_row_for(fixture_a(), 3, "e-a3-unknown", GrantState::Active),
        ];
        assert!(
            partition_ledger_at_published_frontier(&gapped, &frontier, &[])
                .unwrap_err()
                .to_string()
                .contains("partition_revision_gap")
        );

        // Duplicate ledger event ids abort.
        let duplicated = vec![
            ledger_row_for(fixture_a(), 1, "e-dup", GrantState::Active),
            ledger_row_for(fixture_b(), 1, "e-dup", GrantState::Active),
        ];
        assert!(
            partition_ledger_at_published_frontier(&duplicated, &frontier, &[])
                .unwrap_err()
                .to_string()
                .contains("partition_duplicate_ledger_event")
        );

        // A frontier delta proving the WRONG per-grant target aborts.
        let mismatched_frontier = frontier_fixture(
            2,
            &[
                FixtureDelta {
                    generation: 1,
                    event: "e-a1",
                    grant: fixture_a(),
                    base: 0,
                    target: 9,
                },
                FixtureDelta {
                    generation: 2,
                    event: "e-b1",
                    grant: fixture_b(),
                    base: 0,
                    target: 1,
                },
            ],
        );
        assert!(
            partition_ledger_at_published_frontier(&happy_rows, &mismatched_frontier, &[])
                .unwrap_err()
                .to_string()
                .contains("partition_frontier_proof_mismatch")
        );

        // A foreign grant id inside the proving delta aborts too.
        let foreign_frontier = frontier_fixture(
            2,
            &[
                FixtureDelta {
                    generation: 1,
                    event: "e-a1",
                    grant: fixture_c(),
                    base: 0,
                    target: 1,
                },
                FixtureDelta {
                    generation: 2,
                    event: "e-b1",
                    grant: fixture_b(),
                    base: 0,
                    target: 1,
                },
            ],
        );
        assert!(
            partition_ledger_at_published_frontier(&happy_rows, &foreign_frontier, &[])
                .unwrap_err()
                .to_string()
                .contains("partition_frontier_proof_mismatch")
        );
    }

    #[test]
    fn partition_refuses_lineage_gaps_behind_unpublished_prefixes() {
        // rev1 unpublished while rev2 claims proof — honest writers cannot
        // produce this; it means someone tried to publish over a hole.
        let frontier = frontier_fixture(
            1,
            &[FixtureDelta {
                generation: 1,
                event: "e-g2",
                grant: fixture_a(),
                base: 1,
                target: 2,
            }],
        );
        let rows = vec![
            ledger_row_for(fixture_a(), 1, "e-unpublished-sibling", GrantState::Active),
            ledger_row_for(fixture_a(), 2, "e-g2", GrantState::Active),
        ];
        assert!(
            partition_ledger_at_published_frontier(&rows, &frontier, &[])
                .unwrap_err()
                .to_string()
                .contains("partition_published_prefix_gap")
        );
    }

    #[test]
    fn partition_keeps_claimed_rows_behind_unpublished_siblings_blocked() {
        let frontier = frontier_fixture(
            2,
            &[
                FixtureDelta {
                    generation: 1,
                    event: "e-a1",
                    grant: fixture_a(),
                    base: 0,
                    target: 1,
                },
                FixtureDelta {
                    generation: 2,
                    event: "e-a2",
                    grant: fixture_a(),
                    base: 1,
                    target: 2,
                },
            ],
        );
        let rows = vec![
            ledger_row_for(fixture_a(), 1, "e-a1", GrantState::Active),
            ledger_row_for(fixture_a(), 2, "e-a2", GrantState::Active),
            // blocked middle sibling then a claimed further tail
            ledger_row_for(fixture_b(), 1, "e-b-pending", GrantState::Active),
            ledger_row_for(fixture_b(), 2, "e-b-claimed", GrantState::Active),
        ];
        let claimed = vec![String::from("e-b-claimed")];
        let outcome =
            partition_ledger_at_published_frontier(&rows, &frontier, &claimed).expect("partition");
        // Grant A stays fully proven.
        assert_eq!(outcome.published_heads.len(), 1);
        assert_eq!(outcome.published_heads[0].entry.event_id, "e-a2");
        // The behind claim is excluded, NOT promoted to candidate; the pending
        // sibling stays excluded as well.
        assert!(outcome.candidate_rows.is_empty());
        assert_eq!(outcome.excluded_rows.len(), 2);
        assert_eq!(
            outcome.excluded_rows[1].kind,
            LedgerExclusionKind::ClaimedBehindUnpublishedSiblings
        );
    }

    #[test]
    fn partition_requires_every_frontier_event_to_be_ledger_proved() {
        let frontier = frontier_fixture(
            2,
            &[
                FixtureDelta {
                    generation: 1,
                    event: "e-a1",
                    grant: fixture_a(),
                    base: 0,
                    target: 1,
                },
                FixtureDelta {
                    generation: 2,
                    event: "e-missing-row",
                    grant: fixture_b(),
                    base: 0,
                    target: 1,
                },
            ],
        );
        let rows = vec![ledger_row_for(fixture_a(), 1, "e-a1", GrantState::Active)];
        let error = partition_ledger_at_published_frontier(&rows, &frontier, &[])
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("partition_frontier_event_without_ledger_row"),
            "{error}"
        );
    }
}

// Pure tests for the stable-event direct-claim binding contract live in their
// own file (new-file discipline; existing module content untouched).
#[cfg(test)]
mod stable_event_claim_tests;
