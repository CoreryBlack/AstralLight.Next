//! Cross-city durable repository primitives (first slice: four tables only).
//!
//! This module is the pure database boundary for the default-off cross-city
//! subsystem described by [`astral_types`] cross-city contracts. It owns EXACTLY
//! four tables created by migration `20260831000002_cross_city_schema.sql`:
//!
//! - `authorization_cross_city_operation`: one row per durable cross-city
//!   operation (insert-only root; the `state` column moves through the guarded
//!   [`astral_types::CrossCityOperationState`] machine via CAS).
//! - `authorization_cross_city_vote`: insert-only per-node decision evidence;
//!   duplicate keys are durable conflicts, never overwrites.
//! - `authorization_cross_city_city_state`: per-city phase mirror with a
//!   claim/heartbeat/transition/release CAS lease (no `attempts` column exists
//!   in this schema, so none is invented here).
//! - `authorization_cross_city_gate`: per-aggregate synchronization gate whose
//!   `ACTIVE` state can only be reached through an unforgeable internal
//!   activation proof.
//!
//! The two message-queue work-item tables of the same migration are owned by a
//! later slice and are never referenced here. The legacy snapshot/head tables,
//! the grant revision/delta tables, MQ queues and caches stay under their
//! existing owners — no statement in this module may touch them (no double
//! writer). A source-anchored test pins this boundary.
//!
//! # Execution boundary (default-off subsystem)
//!
//! Nothing in this module is wired into any writer, runtime, projection, or
//! message path, and nothing here produces an authorization decision. Every
//! function below is an explicit primitive for a FUTURE coordinator; there is
//! no runtime caller today. All statements run inside the caller's
//! `Transaction`; this module never commits, rolls back, retries, sleeps, or
//! touches the network/Redis/MQ. Loading a stored vote never implies an ALLOW:
//! stored decisions are durable evidence only, and the only authorization
//! entry point remains `PolicyEngine.evaluate()`.
//!
//! # Canonical identity and hash boundary
//!
//! - `operation_id CHAR(36)` stores the canonical lowercase hyphenated UUID
//!   text form enforced by the cross-city contracts; any other spelling is
//!   rejected on encode and decode.
//! - Every `*_digest` / `lease_token_hash BINARY(32)` column stores a raw
//!   SHA-256 digest; the wire form is the lowercase 64-character hex string.
//!   The centralized [`Sha256Digest`] codec is reused (no `Vec<u8>` bypass).
//! - `DATETIME` columns are UTC wall-clock values; contract expiry instants
//!   (UTC Unix seconds) convert at this boundary through checked helpers, and
//!   lease expiry is computed server-side (`TIMESTAMPADD` over
//!   `UTC_TIMESTAMP()`) and read back — the client clock is never trusted.
//!
//! # Failure policy
//!
//! Everything fails closed. Unknown stored states/phases/decisions, malformed
//! or mismatched digests, poisoned rows, missing parent rows, stale expected
//! states/epochs, lost leases, duplicate durable records, and any
//! `rows_affected() != 1` mutation surface as explicit typed errors carrying a
//! stable `code=cross_city_repository.*` identifier. Nothing silently skips
//! rows, repairs stored data, falls back to raw source reads, or upserts over
//! immutable evidence. No secret material (lease tokens, signatures,
//! connection strings) is ever embedded into an error message.
//!
//! # Signature and activation boundary (explicit residual risk)
//!
//! Cryptographic signature verification is a HARD PRECONDITION for inserting
//! vote evidence, deriving agreement certificates, and minting either
//! activation proof in a future transport layer. This repository NEVER
//! verifies signatures: signatures are carried opaquely, digest checks prove
//! integrity and proposal binding only, and every public document here says
//! so. Likewise, no commit-confirmed producer exists in this slice, so
//! nothing mints a [`CrossCityOperationActivationProof`] or a
//! [`CrossCityGateActivationProof`] — the operation-`ACTIVE` and gate-`ACTIVE`
//! entry points are intentionally unreachable until a future, separately
//! reviewed slice provides them. No bool, no caller string, and no cache can
//! substitute for either proof.
//!
//! Both activation-proof constructors are MODULE-PRIVATE (no `pub` or
//! `pub(crate)` mint entry point): today only this file's pure tests may build
//! them, and in the future ONLY a mint primitive added inside this module —
//! deriving its inputs from durable city-state/commit-confirmation rows — may
//! construct them. The operation proof's `commit_digest` is an opaque witness
//! of that future mint step, never a claim re-verified against the stored
//! record (this slice has no such durable column). A source-anchored guard
//! test proves production code contains no mint call (neither through the
//! guarded constructors nor through a struct-literal bypass).
//!
//! RESIDUAL BOUNDARY (deferred, deliberately not improvised): re-binding an
//! existing gate scope to a NEW operation (e.g. after a failed operation) is
//! NOT provided here. It requires a separately reviewed, audited CAS rebind
//! primitive in a future slice; no upsert form exists in this module and none
//! may be added implicitly.
//!
//! # Recovery semantics (expiry, catch-up, takeover)
//!
//! Proposal expiry blocks NEW work (city-row inserts/claims, new votes, gate
//! creation over pre-commit parents) but never blocks durable convergence:
//!
//! - Past the bound, ordinary pre-commit states may only collapse to
//!   `EXPIRED`; the commit-unknown `ACTIVATING`/`IN_DOUBT` states keep their
//!   fail-closed recovery edges (`ACTIVATING -> IN_DOUBT`/`QUARANTINED`,
//!   `IN_DOUBT -> QUARANTINED`) plus the `ACTIVE` path, which still requires
//!   the full durable activation-proof verification. An expired `IN_DOUBT`
//!   can never be discarded as `REJECTED`.
//! - A new coordinator epoch may take over even expired `ACTIVATING`/
//!   `IN_DOUBT` rows for reconciliation (monotonic-epoch CAS takeover); the
//!   takeover also clears every city-state lease of that operation in the
//!   same transaction, so live proofs minted under the old epoch die with the
//!   commit.
//! - Lagging city rows catch up hop-by-hop along the unique shortest legal
//!   path of the closed state machine; leading, divergent, and ambiguous rows
//!   fail closed. Terminal city phases are never written by ordinary workers —
//!   the future commit-confirmation mint primitive must update them atomically
//!   with the parent.
//! - `PREPARING`/`PREPARED` past their proposal bound may still collapse to
//!   `EXPIRED`: per the plan, the source mutation happens ONLY inside the
//!   activation transaction, so `PREPARED` is durable staging — never a
//!   source commit proof. Collapsing it to `EXPIRED` therefore loses no
//!   committed source change.
//!
//! # Lock order (single MySQL session/transaction)
//!
//! All statements are plain bind-parameter SQL with no client-side string
//! assembly. Locks are acquired in this fixed order, and every city-state
//! primitive locks its parent operation row FIRST:
//!
//! 1. `authorization_cross_city_operation` (parent liveness/expiry/state
//!    checks happen on the locked row before any child mutation).
//! 2. `authorization_cross_city_vote` / `authorization_cross_city_city_state`
//!    / `authorization_cross_city_gate`.
//!
//! The gate-row loader is module-private, so no external caller can take the
//! gate lock before the parent operation lock (no reverse gate → operation
//! lock order is even expressible outside this file).
//!
//! No network, Redis, MQ, retry loop, or sleep runs inside these
//! transactions; callers own commit/rollback and every post-commit effect.

use std::collections::VecDeque;
use std::fmt;

use sha2::{Digest, Sha256};
use sqlx::{MySql, Transaction};
use time::{OffsetDateTime, PrimitiveDateTime};
use uuid::Uuid;

use astral_types::{
    CityVoteCertificate, CrossCityAgreementCertificate, CrossCityContractError, CrossCityGateState,
    CrossCityOperationState, MutationProposal, NodeDecision, ZeroDecisionEvidence,
    CROSS_CITY_CITY_COUNT, CROSS_CITY_EVIDENCE_COUNT,
};

use crate::grant_repository::Sha256Digest;

/// Upper bound for one cross-city lease duration in seconds.
pub const MAX_CROSS_CITY_LEASE_SECONDS: i64 = 3_600;
/// Identifier width mirrored from the migration (`VARCHAR(191)` city/node/nonce).
pub const MAX_CROSS_CITY_IDENTIFIER_LENGTH: usize = 191;
/// Version-field width mirrored from the migration (`VARCHAR(64)`).
pub const MAX_CROSS_CITY_VERSION_LENGTH: usize = 64;
/// Lease owner width mirrored from the migration (`VARCHAR(128)`).
pub const MAX_CROSS_CITY_LEASE_OWNER_LENGTH: usize = 128;
/// Failure-text width mirrored from the migration (`VARCHAR(512)`).
pub const MAX_CROSS_CITY_LAST_ERROR_LENGTH: usize = 512;

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Repository errors. Every variant is fail-closed; none authorizes anything.
/// String variants embed a stable `code=cross_city_repository.*` identifier and
/// never carry secrets (lease tokens, signatures, connection material).
#[derive(Debug, thiserror::Error)]
pub enum CrossCityRepositoryError {
    /// A cross-city contract rejected the input.
    #[error("cross-city contract validation failed: {0}")]
    Contract(#[from] CrossCityContractError),

    /// Stored data violated its declared shape; refused instead of normalized.
    #[error("row mapping failed: {0}")]
    Mapping(String),

    /// A database driver error occurred.
    #[error("database query failed: {0}")]
    Query(#[from] sqlx::Error),

    /// A durable record already exists for the requested identity.
    #[error("durable record conflict: {0}")]
    Conflict(String),

    /// A requested row (or referenced parent row) is absent.
    #[error("record not found: {0}")]
    NotFound(String),

    /// A lease-guarded mutation lost its lease (expired/stolen/unknown).
    #[error("cross-city lease CAS failed: {0}")]
    LeaseCasFailed(String),

    /// A state/phase move refused by the closed transition rules.
    #[error("illegal transition: {0}")]
    InvalidTransition(String),

    /// An insert-only durable record was asked to change retroactively.
    #[error("immutable record conflict: {0}")]
    ImmutableConflict(String),

    /// Request fields disagreed with each other or with the declared scope.
    #[error("scope violation: {0}")]
    ScopeViolation(String),
}

fn mapping(code: &str) -> CrossCityRepositoryError {
    CrossCityRepositoryError::Mapping(format!("code=cross_city_repository.{code}"))
}

fn scope_violation(code: &str) -> CrossCityRepositoryError {
    CrossCityRepositoryError::ScopeViolation(format!("code=cross_city_repository.{code}"))
}

fn conflict(code: &str) -> CrossCityRepositoryError {
    CrossCityRepositoryError::Conflict(format!("code=cross_city_repository.{code}"))
}

fn not_found(code: &str) -> CrossCityRepositoryError {
    CrossCityRepositoryError::NotFound(format!("code=cross_city_repository.{code}"))
}

fn db_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(|database| database.is_unique_violation())
}

// ─────────────────────────────────────────────────────────────────────────────
// Canonical SQL-boundary helpers
// ─────────────────────────────────────────────────────────────────────────────

fn digest_from_hex(value: &str) -> Result<Sha256Digest, CrossCityRepositoryError> {
    Sha256Digest::from_hex(value).map_err(|_| mapping("invalid_sha256_hex"))
}

fn digest_from_bytes(bytes: Vec<u8>) -> Result<Sha256Digest, CrossCityRepositoryError> {
    Sha256Digest::from_bytes(bytes).map_err(|_| mapping("invalid_binary32"))
}

fn digest_from_optional_bytes(
    value: Option<&[u8]>,
) -> Result<Option<Sha256Digest>, CrossCityRepositoryError> {
    Sha256Digest::from_optional_bytes(value).map_err(|_| mapping("invalid_binary32"))
}

/// Strict canonical lowercase hyphenated UUID boundary (nil and every other
/// spelling is refused; poisoned storage is never repaired).
fn validated_operation_id(value: &str) -> Result<String, CrossCityRepositoryError> {
    let bytes = value.as_bytes();
    let hyphen_ok = |index: usize| index < bytes.len() && bytes[index] == b'-';
    let length_ok =
        bytes.len() == 36 && hyphen_ok(8) && hyphen_ok(13) && hyphen_ok(18) && hyphen_ok(23);
    let lowercase_ok = bytes.iter().enumerate().all(|(index, byte)| {
        hyphen_ok(index) || byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
    });
    if !length_ok || !lowercase_ok {
        return Err(mapping("invalid_operation_id"));
    }
    let parsed = Uuid::parse_str(value).map_err(|_| mapping("unparsable_operation_id"))?;
    if parsed.is_nil() || parsed.to_string() != value {
        return Err(mapping("noncanonical_operation_id"));
    }
    Ok(value.to_owned())
}

fn validated_text(
    value: &str,
    max_length: usize,
    field: &'static str,
) -> Result<(), CrossCityRepositoryError> {
    // Reject padded spellings outright instead of silently normalizing them:
    // whatever reaches SQL must be byte-identical to its canonical form.
    if value.trim() != value {
        return Err(scope_violation(&format!("padded_field;field={field}")));
    }
    if value.is_empty()
        || value.len() > max_length
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(scope_violation(&format!(
            "invalid_field;field={field};max_length={max_length}"
        )));
    }
    Ok(())
}

/// Canonical raw-vs-normalized check for stored text: a padded, empty,
/// oversized, or whitespace/control-carrying column value is poisoned storage
/// and fails closed on read (never repaired).
fn stored_text_is_canonical(value: &str, max_length: usize) -> bool {
    value.trim() == value
        && !value.is_empty()
        && value.len() <= max_length
        && !value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
}

fn validated_aggregate_type(value: &str) -> Result<(), CrossCityRepositoryError> {
    validated_text(value, 32, "aggregate_type")?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(scope_violation("invalid_aggregate_type_charset"));
    }
    Ok(())
}

/// Bound a contract-side unsigned value into the signed `BIGINT` SQL domain.
fn bind_i64(value: u64, field: &'static str) -> Result<i64, CrossCityRepositoryError> {
    i64::try_from(value).map_err(|_| {
        CrossCityRepositoryError::Mapping(format!(
            "code=cross_city_repository.bigint_overflow;field={field}"
        ))
    })
}

/// Read an unsigned contract value out of a signed `BIGINT` column.
fn read_u64(value: i64, field: &'static str) -> Result<u64, CrossCityRepositoryError> {
    u64::try_from(value).map_err(|_| {
        CrossCityRepositoryError::Mapping(format!(
            "code=cross_city_repository.negative_bigint;field={field}"
        ))
    })
}

fn positive_i64(value: i64, field: &'static str) -> Result<(), CrossCityRepositoryError> {
    if value <= 0 {
        return Err(scope_violation(&format!(
            "non_positive_id;field={field};value={value}"
        )));
    }
    Ok(())
}

/// Convert a contract-side UTC Unix-second instant into a UTC `DATETIME` value.
/// Out-of-range instants are refused instead of wrapped.
fn unix_seconds_to_datetime(
    value: i64,
    field: &'static str,
) -> Result<PrimitiveDateTime, CrossCityRepositoryError> {
    let instant = OffsetDateTime::from_unix_timestamp(value).map_err(|_| {
        CrossCityRepositoryError::Mapping(format!(
            "code=cross_city_repository.datetime_out_of_range;field={field}"
        ))
    })?;
    Ok(PrimitiveDateTime::new(instant.date(), instant.time()))
}

/// Convert a UTC `DATETIME` column value back into UTC Unix seconds.
fn datetime_to_unix_seconds(value: PrimitiveDateTime) -> i64 {
    value.assume_utc().unix_timestamp()
}

fn truncate_last_error(message: &str) -> String {
    message
        .chars()
        .take(MAX_CROSS_CITY_LAST_ERROR_LENGTH)
        .collect()
}

fn validate_lease_material(
    lease_owner: &str,
    lease_seconds: i64,
) -> Result<(), CrossCityRepositoryError> {
    validated_text(
        lease_owner,
        MAX_CROSS_CITY_LEASE_OWNER_LENGTH,
        "lease_owner",
    )?;
    if !(1..=MAX_CROSS_CITY_LEASE_SECONDS).contains(&lease_seconds) {
        return Err(scope_violation(&format!(
            "invalid_lease_seconds;value={lease_seconds};max={MAX_CROSS_CITY_LEASE_SECONDS}"
        )));
    }
    Ok(())
}

fn sha256_digest_bytes(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Lease token (run-scoped, DB stores only its SHA-256 hash)
// ─────────────────────────────────────────────────────────────────────────────

/// Run-scoped secret fencing one cross-city lease attempt.
///
/// Generated by the repository during a claim (a random UUID v4 string). Its
/// `Debug`/`Display` output is redacted; the database stores only the SHA-256
/// hash, so a leaked metadata dump cannot renew or finish someone else's lease.
/// The plaintext token lives only in the coordinator's memory for the lease
/// lifetime and never enters SQL, logs, or error messages.
#[derive(Clone, PartialEq, Eq)]
pub struct CrossCityLeaseToken(String);

impl CrossCityLeaseToken {
    fn new_run_scoped() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// SHA-256 over the plaintext token; the only form that ever reaches SQL.
    pub fn token_hash(&self) -> Sha256Digest {
        Sha256Digest::from_raw_bytes(sha256_digest_bytes(self.0.as_bytes()))
    }
}

impl fmt::Debug for CrossCityLeaseToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CrossCityLeaseToken(REDACTED)")
    }
}

impl fmt::Display for CrossCityLeaseToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CrossCityLeaseToken(REDACTED)")
    }
}

/// Owner + token proof every lease-guarded city-state mutation must present.
///
/// The proof pins the exact parent operation and city identity (canonical
/// text, re-validated against the locked rows at mutation time); the lease
/// token itself is never bound into SQL — only its SHA-256 hash is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossCityCityStateLeaseProof {
    pub state_id: i64,
    pub operation_id: String,
    pub city_id: String,
    pub lease_owner: String,
    pub lease_token: CrossCityLeaseToken,
}

fn validate_city_state_lease_proof(
    proof: &CrossCityCityStateLeaseProof,
) -> Result<(), CrossCityRepositoryError> {
    positive_i64(proof.state_id, "state_id")?;
    validated_operation_id(&proof.operation_id)?;
    validated_text(&proof.city_id, MAX_CROSS_CITY_IDENTIFIER_LENGTH, "city_id")?;
    validated_text(
        &proof.lease_owner,
        MAX_CROSS_CITY_LEASE_OWNER_LENGTH,
        "lease_owner",
    )?;
    if proof.lease_token.as_str().trim().is_empty() {
        return Err(scope_violation("empty_lease_token"));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Closed-set parsers (stored text is never trusted)
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a stored operation-state string into the closed contract set.
pub fn parse_cross_city_operation_state(
    value: &str,
) -> Result<CrossCityOperationState, CrossCityRepositoryError> {
    match value {
        "PROPOSED" => Ok(CrossCityOperationState::Proposed),
        "VOTING" => Ok(CrossCityOperationState::Voting),
        "AGREED" => Ok(CrossCityOperationState::Agreed),
        "PREPARING" => Ok(CrossCityOperationState::Preparing),
        "PREPARED" => Ok(CrossCityOperationState::Prepared),
        "ACTIVATING" => Ok(CrossCityOperationState::Activating),
        "IN_DOUBT" => Ok(CrossCityOperationState::InDoubt),
        "ACTIVE" => Ok(CrossCityOperationState::Active),
        "REJECTED" => Ok(CrossCityOperationState::Rejected),
        "DEFERRED" => Ok(CrossCityOperationState::Deferred),
        "QUARANTINED" => Ok(CrossCityOperationState::Quarantined),
        "EXPIRED" => Ok(CrossCityOperationState::Expired),
        _ => Err(mapping("unknown_operation_state")),
    }
}

/// Parse a stored gate-state string into the closed contract set.
pub fn parse_cross_city_gate_state(
    value: &str,
) -> Result<CrossCityGateState, CrossCityRepositoryError> {
    match value {
        "SYNCING" => Ok(CrossCityGateState::Syncing),
        "ACTIVE" => Ok(CrossCityGateState::Active),
        "BLOCKED" => Ok(CrossCityGateState::Blocked),
        _ => Err(mapping("unknown_gate_state")),
    }
}

/// A terminal phase is finished work: never a claim target, never an initial
/// phase. Terminal operation rows keep their state; city rows never lease for
/// them.
fn validate_work_phase(phase: CrossCityOperationState) -> Result<(), CrossCityRepositoryError> {
    if phase.is_terminal() {
        return Err(scope_violation(&format!(
            "terminal_phase_not_claimable;phase={}",
            phase.as_str()
        )));
    }
    Ok(())
}

/// Whitelist over the CLOSED [`CrossCityOperationState`] set that still
/// accepts new vote evidence: only `PROPOSED` and `VOTING`. Every other state
/// — AGREED and everything after it, all terminal states, DEFERRED included —
/// refuses new evidence, so a sealed agreement can never be polluted
/// retroactively (pure; no state is special-cased outside this whitelist).
fn validate_vote_accepting_state(
    state: CrossCityOperationState,
) -> Result<(), CrossCityRepositoryError> {
    if matches!(
        state,
        CrossCityOperationState::Proposed | CrossCityOperationState::Voting
    ) {
        Ok(())
    } else {
        Err(conflict(&format!(
            "vote_state_closed;state={}",
            state.as_str()
        )))
    }
}

/// Per-city evidence capacity (pure): a city contributes exactly
/// [`CROSS_CITY_EVIDENCE_COUNT`] (2) evidences to the certified agreement, so
/// once that many durable evidences already exist for the city, another node
/// is refused — a third (or later) node can never permanently poison the
/// city's certificate selection.
fn validate_vote_city_capacity(
    existing_city_evidence_count: usize,
) -> Result<(), CrossCityRepositoryError> {
    if existing_city_evidence_count >= CROSS_CITY_EVIDENCE_COUNT {
        Err(CrossCityRepositoryError::ImmutableConflict(
            format!(
                "code=cross_city_repository.vote_city_evidence_cap_reached;city_count={existing_city_evidence_count};cap={CROSS_CITY_EVIDENCE_COUNT}"
            ),
        ))
    } else {
        Ok(())
    }
}

/// Exclusive-expiry check against the caller-supplied unified UTC now
/// (`now >= expires_at` means expired; pure).
fn ensure_not_expired(
    what: &str,
    expires_at: i64,
    now_seconds: i64,
) -> Result<(), CrossCityRepositoryError> {
    if now_seconds >= expires_at {
        Err(conflict(&format!(
            "{what}_expired;expires_at={expires_at};now={now_seconds}"
        )))
    } else {
        Ok(())
    }
}

/// Parent-operation liveness for EVERY city-state primitive: a parent in any
/// terminal state (`ACTIVE`/`REJECTED`/`EXPIRED`/`QUARANTINED`) or past its
/// exclusive expiry bound refuses all city work with a typed error — a lease
/// grant, phase move, heartbeat, or release can never report success for a
/// dead parent (pure).
fn ensure_parent_operation_live(
    parent: &CrossCityOperationRecord,
    now_seconds: i64,
) -> Result<(), CrossCityRepositoryError> {
    if parent.state.is_terminal() {
        return Err(conflict(&format!(
            "parent_operation_terminal;state={}",
            parent.state.as_str()
        )));
    }
    ensure_not_expired("parent_operation", parent.expires_at, now_seconds)
}

/// Expiry admission for ONE operation transition from `current` to `target`
/// (pure; the closed state-machine guard still applies independently at the
/// caller).
///
/// Before the exclusive bound (`now_seconds < expires_at`) every target is
/// admitted; the state machine alone decides reachability.
///
/// Past the bound the guard keeps convergence fail-closed but never blocks it:
///
/// - Ordinary pre-commit states may only collapse to `EXPIRED` — an expired
///   operation can never advance `AGREED → PREPARING → …`.
/// - The commit-unknown states converge fail-closed instead: `ACTIVATING` may
///   still move to `IN_DOUBT` or `QUARANTINED`, and `IN_DOUBT` to
///   `QUARANTINED`; `ACTIVATING`/`IN_DOUBT → ACTIVE` stays admitted here but
///   is reachable ONLY through the caller's full durable activation-proof
///   verification. An expired `IN_DOUBT` can never be discarded as
///   `REJECTED` (the state machine itself no longer offers that edge, and
///   this guard refuses it regardless — an unknown commit outcome has no
///   durable outcome to reject with), and `EXPIRED` is not admitted for
///   either commit-unknown state (it is not even a legal successor), so an
///   unknown commit outcome is never auto-discarded.
fn ensure_transition_within_expiry(
    current: CrossCityOperationState,
    target_state: CrossCityOperationState,
    expires_at: i64,
    now_seconds: i64,
) -> Result<(), CrossCityRepositoryError> {
    use CrossCityOperationState as S;
    if now_seconds < expires_at {
        return Ok(());
    }
    if matches!(current, S::Activating | S::InDoubt) {
        // Commit-unknown: fail-closed convergence edges only. `ACTIVE` is
        // admitted here solely so the durable activation-proof path at the
        // caller can close the unknown outcome; every other divergence is
        // refused.
        if matches!(target_state, S::InDoubt | S::Quarantined | S::Active) {
            Ok(())
        } else {
            Err(conflict(&format!(
                "expired_commit_unknown_target_refused;current={};target={}",
                current.as_str(),
                target_state.as_str()
            )))
        }
    } else {
        // Ordinary pre-commit states: only the EXPIRED cleanup successor.
        if target_state == S::Expired {
            Ok(())
        } else {
            Err(conflict(&format!(
                "expired_operation_target_refused;current={};target={}",
                current.as_str(),
                target_state.as_str()
            )))
        }
    }
}

/// The INITIAL city phase must mirror the parent operation state exactly at
/// insert time (`phase == parent.state`; pure) — a city row can never be born
/// ahead of or beside its parent. Post-insert drift (a parent that advanced
/// while a lease lapsed) is handled by the catch-up oracle
/// ([`next_catchup_hop`]), not by this rule.
fn verify_city_phase_mirrors_parent(
    parent: &CrossCityOperationRecord,
    phase: CrossCityOperationState,
) -> Result<(), CrossCityRepositoryError> {
    if parent.state != phase {
        return Err(conflict(&format!(
            "city_phase_mirror_mismatch;parent={};phase={}",
            parent.state.as_str(),
            phase.as_str()
        )));
    }
    Ok(())
}

/// Closed set of every [`CrossCityOperationState`] (drive table for the
/// deterministic catch-up oracle below).
const CROSS_CITY_OPERATION_STATES: [CrossCityOperationState; 12] = [
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
];

fn operation_state_index(state: CrossCityOperationState) -> usize {
    // Compile-time exhaustive 12-arm match over the closed enum: the indices
    // MUST mirror the order of [`CROSS_CITY_OPERATION_STATES`].
    match state {
        CrossCityOperationState::Proposed => 0,
        CrossCityOperationState::Voting => 1,
        CrossCityOperationState::Agreed => 2,
        CrossCityOperationState::Preparing => 3,
        CrossCityOperationState::Prepared => 4,
        CrossCityOperationState::Activating => 5,
        CrossCityOperationState::InDoubt => 6,
        CrossCityOperationState::Active => 7,
        CrossCityOperationState::Rejected => 8,
        CrossCityOperationState::Deferred => 9,
        CrossCityOperationState::Quarantined => 10,
        CrossCityOperationState::Expired => 11,
    }
}

/// Shortest legal-edge distance between two states over the closed machine
/// (pure, deterministic BFS; `None` when `to` is unreachable from `from`).
fn state_distance(from: CrossCityOperationState, to: CrossCityOperationState) -> Option<usize> {
    if from == to {
        return Some(0);
    }
    let mut distance = [usize::MAX; 12];
    distance[operation_state_index(from)] = 0;
    let mut queue = VecDeque::new();
    queue.push_back(from);
    while let Some(state) = queue.pop_front() {
        for successor in CROSS_CITY_OPERATION_STATES {
            if !state.can_transition_to(successor) {
                continue;
            }
            let successor_index = operation_state_index(successor);
            if distance[successor_index] != usize::MAX {
                continue;
            }
            distance[successor_index] = distance[operation_state_index(state)] + 1;
            if successor == to {
                return Some(distance[successor_index]);
            }
            queue.push_back(successor);
        }
    }
    None
}

/// Deterministic catch-up oracle for one lagging city row (pure).
///
/// Returns `Ok(None)` when the row is in sync with its parent
/// (`current == parent`), `Ok(Some(next))` with the UNIQUE next hop on a
/// shortest legal path from `current` to the parent state, and a typed error
/// when the row is leading or divergent (no legal path exists) or ambiguous
/// (several shortest paths diverge at the first hop — e.g. `PREPARED` can
/// reach `ACTIVE` or `QUARANTINED` through either `ACTIVATING` or
/// `IN_DOUBT`). A worker may therefore never pick a branch unilaterally, and
/// multi-phase catch-up happens one hop per guarded transition across fresh
/// leases.
fn next_catchup_hop(
    current: CrossCityOperationState,
    parent: CrossCityOperationState,
) -> Result<Option<CrossCityOperationState>, CrossCityRepositoryError> {
    let Some(distance) = state_distance(current, parent) else {
        // No legal path exists from the row's phase to the parent state (a
        // leading or divergent row): fail closed.
        return Err(scope_violation(&format!(
            "city_phase_not_catchable;phase={};parent={}",
            current.as_str(),
            parent.as_str()
        )));
    };
    if distance == 0 {
        return Ok(None);
    }
    let next_hops: Vec<CrossCityOperationState> = CROSS_CITY_OPERATION_STATES
        .iter()
        .copied()
        .filter(|successor| {
            current.can_transition_to(*successor)
                && state_distance(*successor, parent) == Some(distance - 1)
        })
        .collect();
    if next_hops.len() != 1 {
        // Ambiguous shortest paths: no worker may pick a branch unilaterally;
        // fail closed (len == 0 cannot occur when a distance exists, but it
        // fails closed here all the same).
        return Err(scope_violation(&format!(
            "city_phase_catchup_ambiguous;phase={};parent={};candidates={}",
            current.as_str(),
            parent.as_str(),
            next_hops.len()
        )));
    }
    Ok(Some(next_hops[0]))
}

/// A live lease may be held only over a row that is in sync with its parent
/// or deterministically catchable to it (pure). Leading, divergent, and
/// ambiguous rows fail closed via [`next_catchup_hop`].
fn verify_city_phase_catchable(
    parent: &CrossCityOperationRecord,
    row_phase: CrossCityOperationState,
) -> Result<(), CrossCityRepositoryError> {
    next_catchup_hop(row_phase, parent.state).map(|_| ())
}

// ─────────────────────────────────────────────────────────────────────────────
// SQL statements (fixed literals; bind parameters only — no string assembly)
// ─────────────────────────────────────────────────────────────────────────────

const OPERATION_INSERT_SQL: &str = "INSERT INTO authorization_cross_city_operation \
    (operation_id, scope_digest, request_digest, mutation_digest, base_frontier_digest, \
     base_source_generation, base_revoke_fence, target_generation, target_revoke_fence, \
     proposal_digest, compiler_version, policy_version, home_city, coordinator_epoch, \
     state, expires_at) \
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

const OPERATION_SELECT_FOR_UPDATE_SQL: &str = "SELECT operation_id, scope_digest, request_digest, \
    mutation_digest, base_frontier_digest, base_source_generation, base_revoke_fence, \
    target_generation, target_revoke_fence, proposal_digest, compiler_version, policy_version, \
    home_city, coordinator_epoch, state, agreement_digest, expires_at, last_error \
    FROM authorization_cross_city_operation WHERE operation_id = ? FOR UPDATE";

const OPERATION_TRANSITION_SQL: &str = "UPDATE authorization_cross_city_operation SET state = ? \
    WHERE operation_id = ? AND state = ? AND coordinator_epoch = ?";

const OPERATION_TRANSITION_AGREED_SQL: &str = "UPDATE authorization_cross_city_operation \
    SET state = ?, agreement_digest = ? \
    WHERE operation_id = ? AND state = ? AND coordinator_epoch = ?";

const OPERATION_FAILURE_SQL: &str = "UPDATE authorization_cross_city_operation \
    SET last_error = ? WHERE operation_id = ? AND state = ? AND coordinator_epoch = ?";

/// Monotonic coordinator-epoch takeover fence: CAS on operation identity +
/// expected state + the OLD epoch (the parent row is locked first at the
/// call site, keeping the operation-first lock order).
const OPERATION_TAKEOVER_SQL: &str = "UPDATE authorization_cross_city_operation \
    SET coordinator_epoch = ? WHERE operation_id = ? AND state = ? AND coordinator_epoch = ?";

/// Takeover lease revocation: clears ONLY the lease material of every
/// city-state row of the taken-over operation (phase and digests untouched),
/// selected purely by `operation_id` where lease material is present. Runs in
/// the same transaction AFTER the epoch CAS, under the fixed
/// operation → city_state lock order.
const OPERATION_TAKEOVER_REVOKE_LEASES_SQL: &str = "UPDATE authorization_cross_city_city_state \
    SET lease_owner = NULL, lease_token_hash = NULL, lease_expires_at = NULL \
    WHERE operation_id = ? \
      AND (lease_owner IS NOT NULL OR lease_token_hash IS NOT NULL \
           OR lease_expires_at IS NOT NULL)";

const VOTE_INSERT_SQL: &str = "INSERT INTO authorization_cross_city_vote \
    (operation_id, city_id, node_id, node_epoch, decision, proposal_digest, frontier_digest, \
     mutation_digest, evidence_digest, nonce, signature, expires_at) \
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

const VOTE_SELECT_FOR_OPERATION_SQL: &str = "SELECT vote_id, operation_id, city_id, node_id, \
    node_epoch, decision, proposal_digest, frontier_digest, mutation_digest, evidence_digest, \
    nonce, signature, expires_at \
    FROM authorization_cross_city_vote WHERE operation_id = ? ORDER BY vote_id FOR UPDATE";

const CITY_STATE_INSERT_SQL: &str = "INSERT INTO authorization_cross_city_city_state \
    (operation_id, city_id, phase, local_base_digest) VALUES (?, ?, ?, ?)";

/// Phase-free claim candidate: whichever (operation, city) row exists with an
/// inactive lease, whatever its phase — the claimant must prove catchability
/// against the locked parent before the lease installs (see
/// [`next_catchup_hop`]).
const CITY_STATE_CLAIM_CANDIDATE_SQL: &str = "SELECT state_id, operation_id, city_id, phase \
    FROM authorization_cross_city_city_state \
    WHERE operation_id = ? AND city_id = ? \
      AND (lease_owner IS NULL OR lease_token_hash IS NULL OR lease_expires_at IS NULL \
           OR lease_expires_at <= UTC_TIMESTAMP()) \
    LIMIT 1 FOR UPDATE";

const CITY_STATE_CLAIM_INSTALL_SQL: &str = "UPDATE authorization_cross_city_city_state \
    SET lease_owner = ?, lease_token_hash = ?, \
        lease_expires_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP()) \
    WHERE state_id = ? AND phase = ? \
      AND (lease_owner IS NULL OR lease_token_hash IS NULL OR lease_expires_at IS NULL \
           OR lease_expires_at <= UTC_TIMESTAMP())";

const CITY_STATE_CLAIM_READBACK_SQL: &str =
    "SELECT operation_id, city_id, phase, lease_expires_at \
    FROM authorization_cross_city_city_state WHERE state_id = ?";

const CITY_STATE_LOCK_SQL: &str = "SELECT state_id, operation_id, city_id, phase \
    FROM authorization_cross_city_city_state WHERE state_id = ? FOR UPDATE";

const CITY_STATE_TRANSITION_SQL: &str = "UPDATE authorization_cross_city_city_state SET phase = ? \
    WHERE state_id = ? AND phase = ? AND lease_owner = ? AND lease_token_hash = ? \
      AND lease_expires_at IS NOT NULL AND lease_expires_at > UTC_TIMESTAMP()";

const CITY_STATE_HEARTBEAT_SQL: &str = "UPDATE authorization_cross_city_city_state \
    SET lease_expires_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP()) \
    WHERE state_id = ? AND lease_owner = ? AND lease_token_hash = ? \
      AND lease_expires_at IS NOT NULL AND lease_expires_at > UTC_TIMESTAMP()";

const CITY_STATE_RELEASE_SQL: &str = "UPDATE authorization_cross_city_city_state \
    SET lease_owner = NULL, lease_token_hash = NULL, lease_expires_at = NULL \
    WHERE state_id = ? AND lease_owner = ? AND lease_token_hash = ? \
      AND lease_expires_at IS NOT NULL AND lease_expires_at > UTC_TIMESTAMP()";

const GATE_INSERT_SQL: &str = "INSERT INTO authorization_cross_city_gate \
    (tenant_id, aggregate_type, aggregate_id, operation_id, certificate_digest, \
     target_generation, revoke_fence, state, content_hash) \
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";

const GATE_SELECT_FOR_UPDATE_SQL: &str =
    "SELECT gate_id, tenant_id, aggregate_type, aggregate_id, \
    operation_id, certificate_digest, target_generation, revoke_fence, state, content_hash \
    FROM authorization_cross_city_gate \
    WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ? FOR UPDATE";

const GATE_TRANSITION_SQL: &str = "UPDATE authorization_cross_city_gate \
    SET state = ?, certificate_digest = ?, target_generation = ?, revoke_fence = ?, \
        content_hash = ? \
    WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ? AND state = ?";

// ─────────────────────────────────────────────────────────────────────────────
// Operation primitives
// ─────────────────────────────────────────────────────────────────────────────

/// Durable cross-city operation root, strictly decoded from storage.
///
/// Every field passed the closed-set/codec checks on decode, and `proposal` is
/// the canonical proposal rebuilt (and digest-verified) from the stored fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossCityOperationRecord {
    pub operation_id: String,
    pub scope_digest: String,
    pub request_digest: String,
    pub mutation_digest: String,
    pub base_frontier_digest: String,
    pub base_source_generation: u64,
    pub base_revoke_fence: u64,
    pub target_generation: u64,
    pub target_revoke_fence: u64,
    pub proposal_digest: String,
    pub compiler_version: String,
    pub policy_version: String,
    pub home_city: String,
    pub coordinator_epoch: u64,
    pub state: CrossCityOperationState,
    pub agreement_digest: Option<String>,
    /// Exclusive expiry bound in UTC Unix seconds.
    pub expires_at: i64,
    pub last_error: Option<String>,
    /// Canonical proposal rebuilt from the stored fields; never re-parsed from
    /// untrusted wire data.
    pub proposal: MutationProposal,
}

#[derive(Debug, sqlx::FromRow)]
struct OperationRow {
    operation_id: String,
    scope_digest: Vec<u8>,
    request_digest: Vec<u8>,
    mutation_digest: Vec<u8>,
    base_frontier_digest: Vec<u8>,
    base_source_generation: i64,
    base_revoke_fence: i64,
    target_generation: i64,
    target_revoke_fence: i64,
    proposal_digest: Vec<u8>,
    compiler_version: String,
    policy_version: String,
    home_city: String,
    coordinator_epoch: i64,
    state: String,
    agreement_digest: Option<Vec<u8>>,
    expires_at: PrimitiveDateTime,
    last_error: Option<String>,
}

/// States strictly before AGREED must not yet carry an agreement digest; every
/// state reachable only through AGREED must carry one. REJECTED/EXPIRED may
/// occur on either side of the AGREED boundary.
fn validate_agreement_presence(
    state: CrossCityOperationState,
    has_agreement: bool,
) -> Result<(), CrossCityRepositoryError> {
    use CrossCityOperationState as S;
    let poisoned = matches!(state, S::Proposed | S::Voting | S::Deferred) && has_agreement
        || matches!(
            state,
            S::Agreed
                | S::Preparing
                | S::Prepared
                | S::Activating
                | S::InDoubt
                | S::Active
                | S::Quarantined
        ) && !has_agreement;
    if poisoned {
        Err(mapping("poisoned_operation_agreement_presence"))
    } else {
        Ok(())
    }
}

/// Decide whether a transition may write an agreement digest, purely from the
/// contract rules: it can only be installed while entering AGREED, must be a
/// valid digest, and can never overwrite a different stored value.
fn resolve_agreement_digest_update(
    target: CrossCityOperationState,
    provided: Option<&str>,
    existing: Option<Sha256Digest>,
) -> Result<Option<Sha256Digest>, CrossCityRepositoryError> {
    match (target, provided) {
        (CrossCityOperationState::Agreed, None) => {
            Err(scope_violation("agreement_digest_required_for_agreed"))
        }
        (CrossCityOperationState::Agreed, Some(hex)) => {
            let decoded = digest_from_hex(hex)?;
            if let Some(existing) = existing {
                if existing != decoded {
                    return Err(CrossCityRepositoryError::ImmutableConflict(
                        "code=cross_city_repository.agreement_digest_immutable".to_owned(),
                    ));
                }
            }
            Ok(Some(decoded))
        }
        (_, Some(_)) => Err(scope_violation("agreement_digest_out_of_scope")),
        (_, None) => Ok(None),
    }
}

fn decode_operation_row(
    row: OperationRow,
) -> Result<CrossCityOperationRecord, CrossCityRepositoryError> {
    let operation_id = validated_operation_id(&row.operation_id)?;
    let state = parse_cross_city_operation_state(&row.state)?;
    let scope_digest = digest_from_bytes(row.scope_digest)?;
    let request_digest = digest_from_bytes(row.request_digest)?;
    let mutation_digest = digest_from_bytes(row.mutation_digest)?;
    let base_frontier_digest = digest_from_bytes(row.base_frontier_digest)?;
    let proposal_digest = digest_from_bytes(row.proposal_digest)?;
    let agreement_digest = digest_from_optional_bytes(row.agreement_digest.as_deref())?;
    let base_source_generation = read_u64(row.base_source_generation, "base_source_generation")?;
    let base_revoke_fence = read_u64(row.base_revoke_fence, "base_revoke_fence")?;
    let target_generation = read_u64(row.target_generation, "target_generation")?;
    let target_revoke_fence = read_u64(row.target_revoke_fence, "target_revoke_fence")?;
    let coordinator_epoch = read_u64(row.coordinator_epoch, "coordinator_epoch")?;
    if coordinator_epoch == 0 {
        return Err(mapping("poisoned_operation_coordinator_epoch"));
    }
    // Stored text must already be canonical; padded values are poisoned rows.
    for (value, max_length, field) in [
        (
            row.home_city.as_str(),
            MAX_CROSS_CITY_IDENTIFIER_LENGTH,
            "home_city",
        ),
        (
            row.compiler_version.as_str(),
            MAX_CROSS_CITY_VERSION_LENGTH,
            "compiler_version",
        ),
        (
            row.policy_version.as_str(),
            MAX_CROSS_CITY_VERSION_LENGTH,
            "policy_version",
        ),
    ] {
        if !stored_text_is_canonical(value, max_length) {
            return Err(mapping(&format!("poisoned_operation_text;field={field}")));
        }
    }
    if let Some(last_error) = &row.last_error {
        if last_error.chars().count() > MAX_CROSS_CITY_LAST_ERROR_LENGTH {
            return Err(mapping("poisoned_operation_last_error"));
        }
    }
    validate_agreement_presence(state, agreement_digest.is_some())?;

    let expires_at = datetime_to_unix_seconds(row.expires_at);
    let proposal = MutationProposal::new(
        &operation_id,
        &scope_digest.as_hex(),
        &request_digest.as_hex(),
        &mutation_digest.as_hex(),
        &base_frontier_digest.as_hex(),
        base_source_generation,
        base_revoke_fence,
        target_generation,
        target_revoke_fence,
        &row.compiler_version,
        &row.policy_version,
        expires_at,
    )
    .map_err(|_| mapping("poisoned_operation_row"))?;
    let recomputed = proposal
        .proposal_digest()
        .map_err(|_| mapping("poisoned_operation_row"))?;
    if recomputed != proposal_digest.as_hex() {
        return Err(mapping("poisoned_operation_proposal_digest"));
    }

    Ok(CrossCityOperationRecord {
        operation_id,
        scope_digest: scope_digest.as_hex(),
        request_digest: request_digest.as_hex(),
        mutation_digest: mutation_digest.as_hex(),
        base_frontier_digest: base_frontier_digest.as_hex(),
        base_source_generation,
        base_revoke_fence,
        target_generation,
        target_revoke_fence,
        proposal_digest: proposal_digest.as_hex(),
        compiler_version: row.compiler_version,
        policy_version: row.policy_version,
        home_city: row.home_city,
        coordinator_epoch,
        state,
        agreement_digest: agreement_digest.map(|digest| digest.as_hex()),
        expires_at,
        last_error: row.last_error,
        proposal,
    })
}

/// Insert the durable operation root for a validated, unexpired, canonical
/// proposal. Plain INSERT: a repeated `operation_id` is an explicit conflict,
/// never an overwrite. The stored `proposal_digest` is derived here from the
/// proposal itself (never accepted from the caller).
///
/// The caller owns the transaction (and any post-commit side effects); no
/// commit, retry, or network work happens inside this function.
pub async fn insert_operation_in_tx(
    tx: &mut Transaction<'_, MySql>,
    proposal: &MutationProposal,
    home_city: &str,
    coordinator_epoch: u64,
    now_seconds: i64,
) -> Result<(), CrossCityRepositoryError> {
    proposal.ensure_valid_at(now_seconds)?;
    // Canonical-form proof: a self-consistent but padded/normalizable proposal
    // is refused instead of being silently repaired into a different value.
    if proposal.canonicalized()? != *proposal {
        return Err(scope_violation("operation_proposal_non_canonical"));
    }
    if coordinator_epoch == 0 {
        return Err(scope_violation("non_positive_coordinator_epoch"));
    }
    validated_text(home_city, MAX_CROSS_CITY_IDENTIFIER_LENGTH, "home_city")?;
    validated_text(
        &proposal.compiler_version,
        MAX_CROSS_CITY_VERSION_LENGTH,
        "compiler_version",
    )?;
    validated_text(
        &proposal.policy_version,
        MAX_CROSS_CITY_VERSION_LENGTH,
        "policy_version",
    )?;

    let proposal_digest = proposal.proposal_digest()?;
    let scope = digest_from_hex(&proposal.scope_digest)?;
    let request = digest_from_hex(&proposal.request_digest)?;
    let mutation = digest_from_hex(&proposal.mutation_digest)?;
    let base_frontier = digest_from_hex(&proposal.base_frontier_digest)?;
    let derived = digest_from_hex(&proposal_digest)?;
    let expires_at = unix_seconds_to_datetime(proposal.expires_at, "expires_at")?;

    let result = sqlx::query(OPERATION_INSERT_SQL)
        .bind(&proposal.operation_id)
        .bind(scope.as_bytes().to_vec())
        .bind(request.as_bytes().to_vec())
        .bind(mutation.as_bytes().to_vec())
        .bind(base_frontier.as_bytes().to_vec())
        .bind(bind_i64(
            proposal.base_source_generation,
            "base_source_generation",
        )?)
        .bind(bind_i64(proposal.base_revoke_fence, "base_revoke_fence")?)
        .bind(bind_i64(proposal.target_generation, "target_generation")?)
        .bind(bind_i64(
            proposal.target_revoke_fence,
            "target_revoke_fence",
        )?)
        .bind(derived.as_bytes().to_vec())
        .bind(&proposal.compiler_version)
        .bind(&proposal.policy_version)
        .bind(home_city)
        .bind(bind_i64(coordinator_epoch, "coordinator_epoch")?)
        .bind(CrossCityOperationState::Proposed.as_str())
        .bind(expires_at)
        .execute(&mut **tx)
        .await;
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            if db_unique_violation(&error) {
                // A repeated operation_id is a durable conflict, never an
                // overwrite (plain INSERT; no upsert form exists).
                return Err(conflict("operation_exists"));
            }
            return Err(error.into());
        }
    };
    if result.rows_affected() != 1 {
        return Err(mapping("operation_insert_not_applied"));
    }
    Ok(())
}

/// Lock and strictly decode one operation row inside the caller's transaction.
/// Missing rows are explicit `NotFound`; any poisoned field fails closed.
pub async fn load_operation_for_update_in_tx(
    tx: &mut Transaction<'_, MySql>,
    operation_id: &str,
) -> Result<CrossCityOperationRecord, CrossCityRepositoryError> {
    let id = validated_operation_id(operation_id)?;
    let row: Option<OperationRow> = sqlx::query_as(OPERATION_SELECT_FOR_UPDATE_SQL)
        .bind(&id)
        .fetch_optional(&mut **tx)
        .await?;
    let Some(row) = row else {
        return Err(not_found(&format!("operation_not_found;operation_id={id}")));
    };
    decode_operation_row(row)
}

/// Explicit, fully-bound request for one guarded operation-state move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossCityOperationTransitionRequest {
    pub operation_id: String,
    /// State the caller believes the row is in; must equal the locked row.
    pub expected_state: CrossCityOperationState,
    pub target_state: CrossCityOperationState,
    /// Must equal the locked row's epoch (monotonic coordinator fence).
    pub coordinator_epoch: u64,
    /// Required for (and only accepted with) a transition INTO `AGREED`; the
    /// digest is verified against the certificate re-derived from the durable
    /// votes and is never itself the source of truth.
    pub agreement_digest: Option<String>,
    /// Required for (and only accepted with) a transition INTO `ACTIVE`;
    /// supplying it with any other target is refused.
    pub activation_proof: Option<CrossCityOperationActivationProof>,
}

/// Guarded operation-state move under the caller's transaction.
///
/// Sequence: lock + strict decode, stale-state/stale-epoch CAS preconditions,
/// [`CrossCityOperationState::transition`] guard, then a CAS `UPDATE` bound to
/// `operation_id + expected state + coordinator_epoch`. Terminal, illegal, and
/// stale moves are explicit errors — never silent rewrites.
///
/// Expiry: before the exclusive bound (`now_seconds < expires_at`) every
/// machine-legal target passes. Past the bound, ordinary pre-commit states may
/// only collapse to `EXPIRED`, while the commit-unknown `ACTIVATING`/`IN_DOUBT`
/// states keep their fail-closed recovery edges (`ACTIVATING ->
/// IN_DOUBT`/`QUARANTINED`, `IN_DOUBT -> QUARANTINED`) plus the `ACTIVE` path,
/// which additionally requires the full durable activation-proof verification
/// below; an expired `IN_DOUBT` can never be discarded as `REJECTED`. A
/// monotonic-epoch takeover ([`take_over_operation_in_tx`]) may hand an expired
/// `ACTIVATING`/`IN_DOUBT` row to a new coordinator for reconciliation.
///
/// The agreement digest is EVIDENCE-DERIVED, never free-form: a transition
/// into AGREED re-derives the [`CrossCityAgreementCertificate`] from the
/// durably stored votes inside this same transaction (two distinct cities ×
/// two ALLOW evidences, contract-validated and unexpired) and accepts the
/// request-provided digest ONLY when it equals the derived certificate digest.
/// After AGREED, the stored digest can never be overwritten with a different
/// value.
///
/// ACTIVE entry (`ACTIVATING -> ACTIVE`, `IN_DOUBT -> ACTIVE`) requires the
/// unforgeable [`CrossCityOperationActivationProof`]: its operation id,
/// agreement digest, target generation, and revoke fence are re-verified
/// field-by-field against the locked record; `commit_digest` is an opaque
/// mint-time witness (the record carries no such column, so it is never
/// re-compared here). A missing or mismatched proof is a hard error. NOTHING
/// in this slice mints such a proof, so the ACTIVE entry point is
/// intentionally unreachable until a future commit-confirmed mint primitive
/// (inside this module) lands.
pub async fn transition_operation_in_tx(
    tx: &mut Transaction<'_, MySql>,
    request: &CrossCityOperationTransitionRequest,
    now_seconds: i64,
) -> Result<CrossCityOperationState, CrossCityRepositoryError> {
    let id = validated_operation_id(&request.operation_id)?;
    let expected_state = request.expected_state;
    let target_state = request.target_state;
    let coordinator_epoch = request.coordinator_epoch;
    if coordinator_epoch == 0 {
        return Err(scope_violation("non_positive_coordinator_epoch"));
    }
    let record = load_operation_for_update_in_tx(tx, &id).await?;
    if record.state != expected_state {
        return Err(conflict(&format!(
            "stale_operation_state;expected={};actual={}",
            expected_state.as_str(),
            record.state.as_str()
        )));
    }
    if record.coordinator_epoch != coordinator_epoch {
        return Err(conflict(&format!(
            "stale_coordinator_epoch;expected={coordinator_epoch};actual={}",
            record.coordinator_epoch
        )));
    }
    record.state.transition(target_state).map_err(|_| {
        CrossCityRepositoryError::InvalidTransition(format!(
            "code=cross_city_repository.illegal_operation_transition;from={};to={}",
            record.state.as_str(),
            target_state.as_str()
        ))
    })?;
    ensure_transition_within_expiry(record.state, target_state, record.expires_at, now_seconds)?;
    if target_state == CrossCityOperationState::Active {
        // No bool form, no direct IN_DOUBT/ACTIVATING -> ACTIVE path: the
        // commit-confirmed proof is mandatory and field-verified (including
        // for an expired commit-unknown parent — proposal expiry never blocks
        // durable convergence).
        let Some(proof) = &request.activation_proof else {
            return Err(scope_violation("operation_activation_requires_proof"));
        };
        verify_operation_activation_binding(&record, proof)?;
    } else if request.activation_proof.is_some() {
        // The proof is a capability for the ACTIVE entry only; carrying it
        // into any other transition is refused so it cannot circulate.
        return Err(scope_violation("operation_activation_proof_not_applicable"));
    }
    let existing = match &record.agreement_digest {
        Some(hex) => Some(digest_from_hex(hex)?),
        None => None,
    };
    let agreement_update = if target_state == CrossCityOperationState::Agreed {
        // The certificate is re-derived from the locked durable votes; the
        // request-supplied digest is verified against it and is never itself
        // the source of truth.
        let votes = load_bound_votes_in_tx(tx, &record).await?;
        let certificate = assemble_agreement_certificate(&record.proposal, &votes, now_seconds)?;
        verify_provided_agreement_digest(request.agreement_digest.as_deref(), &certificate)?;
        resolve_agreement_digest_update(
            target_state,
            Some(certificate.agreement_digest.as_str()),
            existing,
        )?
    } else {
        resolve_agreement_digest_update(
            target_state,
            request.agreement_digest.as_deref(),
            existing,
        )?
    };

    let bound_epoch = bind_i64(coordinator_epoch, "coordinator_epoch")?;
    let result = match agreement_update {
        Some(agreement) => {
            sqlx::query(OPERATION_TRANSITION_AGREED_SQL)
                .bind(target_state.as_str())
                .bind(agreement.as_bytes().to_vec())
                .bind(&id)
                .bind(expected_state.as_str())
                .bind(bound_epoch)
                .execute(&mut **tx)
                .await?
        }
        None => {
            sqlx::query(OPERATION_TRANSITION_SQL)
                .bind(target_state.as_str())
                .bind(&id)
                .bind(expected_state.as_str())
                .bind(bound_epoch)
                .execute(&mut **tx)
                .await?
        }
    };
    if result.rows_affected() != 1 {
        // The row was locked above; a zero-row CAS here means engine-level
        // inconsistency and fails closed instead of being retried blindly.
        return Err(conflict("operation_cas_unexpected"));
    }
    Ok(target_state)
}

/// Explicit request to record one truncated failure reason (512-character
/// bound) on an operation row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossCityOperationFailureRequest {
    pub operation_id: String,
    /// State the caller believes the row is in; must equal the locked row.
    pub expected_state: CrossCityOperationState,
    /// Coordinator epoch of the CALLER; a stale coordinator can never
    /// overwrite another epoch's diagnostics.
    pub coordinator_epoch: u64,
    pub message: String,
}

/// Record a truncated failure reason (512-character bound) on an operation row
/// still in the expected state AND still owned by the caller's coordinator
/// epoch. CAS-guarded on `operation_id + state + coordinator_epoch`; stale
/// states and stale epochs are explicit errors, so an old coordinator can
/// never overwrite the diagnostics of a newer one.
pub async fn record_operation_failure_in_tx(
    tx: &mut Transaction<'_, MySql>,
    request: &CrossCityOperationFailureRequest,
) -> Result<(), CrossCityRepositoryError> {
    let id = validated_operation_id(&request.operation_id)?;
    if request.coordinator_epoch == 0 {
        return Err(scope_violation("non_positive_coordinator_epoch"));
    }
    let trimmed = request.message.trim();
    if trimmed.is_empty() {
        return Err(scope_violation("empty_failure_message"));
    }
    let result = sqlx::query(OPERATION_FAILURE_SQL)
        .bind(truncate_last_error(trimmed))
        .bind(&id)
        .bind(request.expected_state.as_str())
        .bind(bind_i64(request.coordinator_epoch, "coordinator_epoch")?)
        .execute(&mut **tx)
        .await?;
    if result.rows_affected() != 1 {
        return Err(conflict("failure_record_cas_missed"));
    }
    Ok(())
}

/// Explicit coordinator-epoch takeover request (monotonic fence CAS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossCityOperationTakeoverRequest {
    pub operation_id: String,
    /// Expected current state; MUST be non-terminal.
    pub expected_state: CrossCityOperationState,
    /// Epoch the caller believes is current; must equal the locked row.
    pub current_epoch: u64,
    /// New epoch; must be strictly greater than `current_epoch`.
    pub new_epoch: u64,
}

/// Outcome of one successful coordinator-epoch takeover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossCityOperationTakeoverOutcome {
    /// The epoch the takeover installed (monotonically greater than the old
    /// one).
    pub new_epoch: u64,
    /// Number of city-state rows whose lease material was cleared in the same
    /// transaction (any count `0..=[CROSS_CITY_CITY_COUNT]` is legal: a taken-
    /// over operation may have zero live city leases).
    pub revoked_city_leases: u64,
}

/// Pure takeover admission (no DB): canonical operation id, strictly
/// monotonic epoch move, and a non-terminal expected state.
fn validate_takeover_request(
    request: &CrossCityOperationTakeoverRequest,
) -> Result<(), CrossCityRepositoryError> {
    validated_operation_id(&request.operation_id)?;
    if request.current_epoch == 0 {
        return Err(scope_violation("non_positive_coordinator_epoch"));
    }
    if request.new_epoch <= request.current_epoch {
        return Err(scope_violation(&format!(
            "takeover_epoch_not_monotonic;current={};new={}",
            request.current_epoch, request.new_epoch
        )));
    }
    if request.expected_state.is_terminal() {
        return Err(scope_violation(&format!(
            "takeover_terminal_state_not_allowed;state={}",
            request.expected_state.as_str()
        )));
    }
    Ok(())
}

/// Take over a non-terminal operation row by advancing its coordinator epoch
/// (monotonic fence CAS) and revoking every city-state lease of that
/// operation, inside the caller's transaction.
///
/// Sequence: strict request validation, lock + strict decode of the parent
/// operation row FIRST (fixed operation-first lock order), stale-state and
/// stale-epoch preconditions against the locked row, then a CAS `UPDATE`
/// bound to `operation_id + expected state + OLD epoch` writing the new
/// epoch; `rows_affected() != 1` fails closed. After the epoch CAS succeeds,
/// in the SAME transaction and still under the fixed operation → city_state
/// lock order, [`OPERATION_TAKEOVER_REVOKE_LEASES_SQL`] clears ONLY the lease
/// material (`lease_owner`/`lease_token_hash`/`lease_expires_at`) of every
/// city row selected purely by `operation_id` — phases and digests are never
/// touched, and any row count `0..=[CROSS_CITY_CITY_COUNT]` is a legal
/// outcome. Live lease proofs minted before the takeover therefore die with
/// the transaction commit; the old epoch can never renew or complete them.
///
/// EXPIRY-TOLERANT BY DESIGN: an expired `ACTIVATING`/`IN_DOUBT` row MUST be
/// take-over-able for reconciliation — proposal expiry never gates this
/// primitive, so a new coordinator can always pick up an unknown-outcome row.
/// The schema has no coordinator-owner column: this primitive ONLY advances
/// the monotonic epoch fence and revokes child leases; home-city/lease
/// ownership semantics stay the caller's responsibility and are deliberately
/// not encoded here.
pub async fn take_over_operation_in_tx(
    tx: &mut Transaction<'_, MySql>,
    request: &CrossCityOperationTakeoverRequest,
) -> Result<CrossCityOperationTakeoverOutcome, CrossCityRepositoryError> {
    validate_takeover_request(request)?;
    let id = validated_operation_id(&request.operation_id)?;
    let record = load_operation_for_update_in_tx(tx, &id).await?;
    if record.state != request.expected_state {
        return Err(conflict(&format!(
            "stale_operation_state;expected={};actual={}",
            request.expected_state.as_str(),
            record.state.as_str()
        )));
    }
    if record.coordinator_epoch != request.current_epoch {
        return Err(conflict(&format!(
            "stale_coordinator_epoch;expected={};actual={}",
            request.current_epoch, record.coordinator_epoch
        )));
    }
    // Belt-and-braces re-check on the locked record: terminal rows are never
    // take-over-able even if the request was constructed before a concurrent
    // terminal move became visible.
    if record.state.is_terminal() {
        return Err(conflict(&format!(
            "takeover_terminal_state_not_allowed;state={}",
            record.state.as_str()
        )));
    }
    let result = sqlx::query(OPERATION_TAKEOVER_SQL)
        .bind(bind_i64(request.new_epoch, "coordinator_epoch")?)
        .bind(&id)
        .bind(request.expected_state.as_str())
        .bind(bind_i64(request.current_epoch, "coordinator_epoch")?)
        .execute(&mut **tx)
        .await?;
    if result.rows_affected() != 1 {
        // The row was locked above; a zero-row CAS here fails closed.
        return Err(conflict("takeover_cas_unexpected"));
    }
    // Epoch fence installed: revoke the child leases in the same transaction
    // (operation is already locked, so taking the city_state row locks here
    // preserves the fixed operation -> city_state order). Only lease material
    // is cleared; 0..2 revoked rows are all legal outcomes.
    let revoked_city_leases = sqlx::query(OPERATION_TAKEOVER_REVOKE_LEASES_SQL)
        .bind(&id)
        .execute(&mut **tx)
        .await?
        .rows_affected();
    Ok(CrossCityOperationTakeoverOutcome {
        new_epoch: request.new_epoch,
        revoked_city_leases,
    })
}

/// Unforgeable internal proof that one cross-city operation's durable
/// commit/pointer result landed (commit-confirmed), entitling EXACTLY this
/// operation to move to `ACTIVE` (from `ACTIVATING` or `IN_DOUBT`).
///
/// There is intentionally no public constructor and no `bool` form: the
/// constructor below is MODULE-PRIVATE, so only code inside this file can
/// build a proof — today exclusively this module's pure tests, and in the
/// future ONLY a durable city-state/commit-confirmation mint primitive added
/// inside this module. At use time every verifiable pin (operation id,
/// certified agreement digest, target generation, revoke fence) is re-checked
/// field-by-field against the locked operation record. `commit_digest` is
/// deliberately NOT compared there: the stored record/schema carries no such
/// field, so no honest per-field check exists in this slice. It is an OPAQUE
/// WITNESS — the future mint primitive must derive it from durable
/// commit-confirmed rows and verify it at mint time. This module never
/// pretends to have verified it and never drops it. `Debug` redacts the
/// digest fields so a log line can never reproduce the full minted value.
///
/// RESIDUAL RISK: because no mint primitive exists in this slice, no code
/// path mints this proof and the operation-`ACTIVE` entry point is
/// intentionally unreachable. Minting MUST remain gated on the future
/// transport-layer crypto verification of the underlying evidence — nothing
/// here verifies signatures.
#[derive(Clone, PartialEq, Eq)]
pub struct CrossCityOperationActivationProof {
    operation_id: String,
    agreement_digest: String,
    target_generation: u64,
    target_revoke_fence: u64,
    commit_digest: String,
}

impl CrossCityOperationActivationProof {
    /// Mint a proof from a commit-confirmed durable result. MODULE-PRIVATE:
    /// reserved for a future commit-confirmation mint primitive inside this
    /// module; every validated pin is checked here.
    // No caller exists in this slice by design (the ACTIVE entry stays
    // unreachable), so the never-used lint is silenced explicitly instead of
    // weakening the gate.
    #[allow(dead_code)]
    fn new(
        operation_id: String,
        agreement_digest: String,
        target_generation: u64,
        target_revoke_fence: u64,
        commit_digest: String,
    ) -> Result<Self, CrossCityRepositoryError> {
        let operation_id = validated_operation_id(&operation_id)?;
        let agreement_digest = digest_from_hex(&agreement_digest)?.as_hex();
        let commit_digest = digest_from_hex(&commit_digest)?.as_hex();
        if target_generation == 0 {
            return Err(scope_violation("operation_proof_non_positive_generation"));
        }
        if target_revoke_fence > target_generation {
            return Err(scope_violation(&format!(
                "operation_proof_fence_exceeds_generation;generation={target_generation};fence={target_revoke_fence}"
            )));
        }
        Ok(Self {
            operation_id,
            agreement_digest,
            target_generation,
            target_revoke_fence,
            commit_digest,
        })
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn agreement_digest(&self) -> &str {
        &self.agreement_digest
    }

    pub fn target_generation(&self) -> u64 {
        self.target_generation
    }

    pub fn target_revoke_fence(&self) -> u64 {
        self.target_revoke_fence
    }

    pub fn commit_digest(&self) -> &str {
        &self.commit_digest
    }
}

impl fmt::Debug for CrossCityOperationActivationProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The proof is a capability token: its digest fields are redacted so a
        // Debug log can never reproduce the full minted value.
        formatter
            .debug_struct("CrossCityOperationActivationProof")
            .field("operation_id", &self.operation_id)
            .field("agreement_digest", &"<sha256>")
            .field("target_generation", &self.target_generation)
            .field("target_revoke_fence", &self.target_revoke_fence)
            .field("commit_digest", &"<sha256>")
            .finish()
    }
}

/// Field-by-field binding of an [`CrossCityOperationActivationProof`] to the
/// locked operation record (pure): identity, certified agreement digest, and
/// the target generation/fence must all match exactly; any disagreement is a
/// typed refusal.
///
/// `commit_digest` is deliberately absent from this comparison: the record
/// carries no such durable column, so no honest per-field check exists here.
/// It stays an opaque mint-time witness derived and verified by the future
/// mint primitive (see the proof type's documentation) — it is never dropped
/// and never claimed as verified by this module.
fn verify_operation_activation_binding(
    record: &CrossCityOperationRecord,
    proof: &CrossCityOperationActivationProof,
) -> Result<(), CrossCityRepositoryError> {
    if proof.operation_id() != record.operation_id {
        return Err(scope_violation("operation_activation_operation_mismatch"));
    }
    let Some(record_agreement) = &record.agreement_digest else {
        // Unreachable for decoded AGREED-successor rows (agreement-presence
        // invariant), but kept fail-closed for any future caller.
        return Err(mapping("poisoned_operation_agreement_presence"));
    };
    if record_agreement != proof.agreement_digest() {
        return Err(scope_violation("operation_activation_agreement_mismatch"));
    }
    if record.target_generation != proof.target_generation() {
        return Err(scope_violation("operation_activation_generation_mismatch"));
    }
    if record.target_revoke_fence != proof.target_revoke_fence() {
        return Err(scope_violation("operation_activation_fence_mismatch"));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Vote primitives (insert-only evidence)
// ─────────────────────────────────────────────────────────────────────────────

/// One durably stored per-node vote.
///
/// `evidence` is the reconstructed, digest-verified
/// [`ZeroDecisionEvidence`]: its stored `evidence_digest` was re-derived from
/// the stored payload and every binding field was checked against the parent
/// operation. The `signature` inside the evidence is OPAQUE: crypto
/// verification is a REQUIRED gate of a future transport layer, and presence
/// in storage never means the signature was verified. A stored decision
/// (including ALLOW) is durable evidence only — never an authorization result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCityVote {
    pub vote_id: i64,
    pub evidence: ZeroDecisionEvidence,
}

#[derive(Debug, sqlx::FromRow)]
struct VoteRow {
    vote_id: i64,
    operation_id: String,
    city_id: String,
    node_id: String,
    node_epoch: i64,
    decision: String,
    proposal_digest: Vec<u8>,
    frontier_digest: Vec<u8>,
    mutation_digest: Vec<u8>,
    evidence_digest: Vec<u8>,
    nonce: String,
    signature: String,
    expires_at: PrimitiveDateTime,
}

fn decode_vote_row(row: VoteRow) -> Result<StoredCityVote, CrossCityRepositoryError> {
    if row.vote_id <= 0 {
        return Err(mapping("poisoned_vote_row"));
    }
    let decision = match row.decision.as_str() {
        "ALLOW" => NodeDecision::Allow,
        "DENY" => NodeDecision::Deny,
        _ => return Err(mapping("unknown_vote_decision")),
    };
    let node_epoch = read_u64(row.node_epoch, "node_epoch")?;
    let proposal_digest = digest_from_bytes(row.proposal_digest)?;
    let frontier_digest = digest_from_bytes(row.frontier_digest)?;
    let mutation_digest = digest_from_bytes(row.mutation_digest)?;
    let evidence_digest = digest_from_bytes(row.evidence_digest)?;
    let expires_at = datetime_to_unix_seconds(row.expires_at);

    let evidence = ZeroDecisionEvidence::new(
        &row.city_id,
        &row.node_id,
        node_epoch,
        decision,
        &proposal_digest.as_hex(),
        &frontier_digest.as_hex(),
        &mutation_digest.as_hex(),
        &row.nonce,
        expires_at,
        &row.signature,
    )
    .map_err(|_| mapping("poisoned_vote_row"))?;
    // Canonical-form proof on the reconstructed value: any padding stored in
    // the row would normalize away and surface as a strict mismatch here.
    if evidence.city_id != row.city_id
        || evidence.node_id != row.node_id
        || evidence.nonce != row.nonce
        || evidence.signature != row.signature
    {
        return Err(mapping("noncanonical_vote_row"));
    }
    if evidence.evidence_digest != evidence_digest.as_hex() {
        return Err(mapping("poisoned_vote_evidence_digest"));
    }
    Ok(StoredCityVote {
        vote_id: row.vote_id,
        evidence,
    })
}

/// Insert one node's decision evidence for an operation. The evidence must be
/// valid, unexpired, canonical, and bound to the EXACT stored proposal (its
/// signed `proposal_digest` plus frontier/mutation/expiry agreement with the
/// parent operation row, which is locked in the same transaction — a missing
/// parent is a fail-closed write error).
///
/// Evidence is accepted ONLY while the locked parent operation is in
/// `PROPOSED` or `VOTING` (closed whitelist, see
/// [`validate_vote_accepting_state`]): once an agreement is sealed, the
/// evidence set is immutable and any later vote attempt is a typed conflict —
/// the certified evidence can never be polluted retroactively.
///
/// Plain INSERT only: a repeated node, a reused nonce, or ANY duplicate key is
/// an immutable-evidence conflict — never an upsert and never "equivalent
/// success". Signatures are stored opaquely and never verified here; crypto
/// verification of every accepted evidence is a HARD PRECONDITION the future
/// transport layer owes this table.
///
/// Per-city CAP: before the INSERT, the durable evidences of the locked
/// parent are loaded (strictly decoded; any poisoned stored vote fails
/// closed) and the same-city count is checked — at
/// [`CROSS_CITY_EVIDENCE_COUNT`] (2) the insert is refused as an immutable
/// conflict, so a third node can never permanently poison a city's
/// certificate selection.
pub async fn insert_vote_in_tx(
    tx: &mut Transaction<'_, MySql>,
    operation_id: &str,
    evidence: &ZeroDecisionEvidence,
    now_seconds: i64,
) -> Result<i64, CrossCityRepositoryError> {
    let id = validated_operation_id(operation_id)?;
    evidence.validate_at(now_seconds)?;
    if evidence.canonicalized()? != *evidence {
        return Err(scope_violation("vote_evidence_non_canonical"));
    }
    validated_text(
        &evidence.city_id,
        MAX_CROSS_CITY_IDENTIFIER_LENGTH,
        "city_id",
    )?;
    validated_text(
        &evidence.node_id,
        MAX_CROSS_CITY_IDENTIFIER_LENGTH,
        "node_id",
    )?;
    validated_text(&evidence.nonce, MAX_CROSS_CITY_IDENTIFIER_LENGTH, "nonce")?;

    let operation = load_operation_for_update_in_tx(tx, &id).await?;
    // Sealed agreements never accept new evidence (closed whitelist).
    validate_vote_accepting_state(operation.state)?;
    if evidence.proposal_digest != operation.proposal_digest {
        return Err(scope_violation(
            "vote_proposal_binding_mismatch;field=proposal_digest",
        ));
    }
    if evidence.frontier_digest != operation.base_frontier_digest {
        return Err(scope_violation(
            "vote_proposal_binding_mismatch;field=frontier_digest",
        ));
    }
    if evidence.mutation_digest != operation.mutation_digest {
        return Err(scope_violation(
            "vote_proposal_binding_mismatch;field=mutation_digest",
        ));
    }
    if evidence.expires_at != operation.expires_at {
        return Err(scope_violation(
            "vote_proposal_binding_mismatch;field=expires_at",
        ));
    }

    // Per-city capacity from DURABLE rows (parent already locked; the vote
    // loader reuses it without re-locking). A poisoned stored vote fails
    // closed inside the loader.
    let votes = load_bound_votes_in_tx(tx, &operation).await?;
    let existing_city_count = votes
        .iter()
        .filter(|vote| vote.evidence.city_id == evidence.city_id)
        .count();
    validate_vote_city_capacity(existing_city_count)?;

    let proposal_digest = digest_from_hex(&evidence.proposal_digest)?;
    let frontier_digest = digest_from_hex(&evidence.frontier_digest)?;
    let mutation_digest = digest_from_hex(&evidence.mutation_digest)?;
    let evidence_digest = digest_from_hex(&evidence.evidence_digest)?;
    let expires_at = unix_seconds_to_datetime(evidence.expires_at, "vote.expires_at")?;

    let result = sqlx::query(VOTE_INSERT_SQL)
        .bind(&id)
        .bind(&evidence.city_id)
        .bind(&evidence.node_id)
        .bind(bind_i64(evidence.node_epoch, "node_epoch")?)
        .bind(evidence.decision.as_str())
        .bind(proposal_digest.as_bytes().to_vec())
        .bind(frontier_digest.as_bytes().to_vec())
        .bind(mutation_digest.as_bytes().to_vec())
        .bind(evidence_digest.as_bytes().to_vec())
        .bind(&evidence.nonce)
        .bind(&evidence.signature)
        .bind(expires_at)
        .execute(&mut **tx)
        .await;
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            if db_unique_violation(&error) {
                return Err(CrossCityRepositoryError::ImmutableConflict(
                    "code=cross_city_repository.vote_evidence_conflict".to_owned(),
                ));
            }
            return Err(error.into());
        }
    };
    if result.rows_affected() != 1 {
        return Err(mapping("vote_insert_not_applied"));
    }
    let vote_id = i64::try_from(result.last_insert_id()).map_err(|_| {
        CrossCityRepositoryError::Mapping(
            "code=cross_city_repository.bigint_overflow;field=vote_id".to_owned(),
        )
    })?;
    if vote_id == 0 {
        return Err(mapping("vote_insert_not_applied"));
    }
    Ok(vote_id)
}

/// Lock and load every stored vote of one operation (deterministic
/// `vote_id` order), each strictly decoded, digest-verified, and checked for
/// full agreement with the parent operation on proposal/frontier/mutation/
/// expiry. A loaded vote is evidence, never an ALLOW, and its signature is
/// unverified until the future transport-layer crypto gate runs.
pub async fn load_votes_for_operation_in_tx(
    tx: &mut Transaction<'_, MySql>,
    operation_id: &str,
) -> Result<Vec<StoredCityVote>, CrossCityRepositoryError> {
    let operation = load_operation_for_update_in_tx(tx, operation_id).await?;
    load_bound_votes_in_tx(tx, &operation).await
}

/// Load and strictly validate every stored vote of an ALREADY-LOCKED
/// operation row (module-private): no parent re-lock, deterministic `vote_id`
/// order, digest-verified, and fully bound to the parent operation on
/// proposal/frontier/mutation/expiry. Any poisoned stored vote fails closed.
async fn load_bound_votes_in_tx(
    tx: &mut Transaction<'_, MySql>,
    operation: &CrossCityOperationRecord,
) -> Result<Vec<StoredCityVote>, CrossCityRepositoryError> {
    let rows: Vec<VoteRow> = sqlx::query_as(VOTE_SELECT_FOR_OPERATION_SQL)
        .bind(&operation.operation_id)
        .fetch_all(&mut **tx)
        .await?;
    let mut votes = Vec::with_capacity(rows.len());
    for row in rows {
        if row.operation_id != operation.operation_id {
            return Err(mapping("poisoned_vote_operation_identity"));
        }
        let vote = decode_vote_row(row)?;
        if vote.evidence.proposal_digest != operation.proposal_digest
            || vote.evidence.frontier_digest != operation.base_frontier_digest
            || vote.evidence.mutation_digest != operation.mutation_digest
            || vote.evidence.expires_at != operation.expires_at
        {
            return Err(mapping("poisoned_vote_operation_binding"));
        }
        votes.push(vote);
    }
    Ok(votes)
}

/// Issue the pure-contract [`CityVoteCertificate`] for one city of an
/// operation, from the durably stored evidences only.
///
/// The operation row and its votes are locked and re-validated; the two stored
/// evidences of the requested city are handed to
/// [`CityVoteCertificate::issue`] exactly as stored (which re-derives every
/// digest and enforces the ALLOW/distinct-node/proposal-binding rules). No
/// certificate is ever fabricated from booleans or partial data here, and a
/// missing/incomplete evidence set is an explicit error.
pub async fn issue_city_vote_certificate_in_tx(
    tx: &mut Transaction<'_, MySql>,
    operation_id: &str,
    city_id: &str,
    now_seconds: i64,
) -> Result<CityVoteCertificate, CrossCityRepositoryError> {
    validated_text(city_id, MAX_CROSS_CITY_IDENTIFIER_LENGTH, "city_id")?;
    let operation = load_operation_for_update_in_tx(tx, operation_id).await?;
    let votes = load_bound_votes_in_tx(tx, &operation).await?;
    let evidences: Vec<ZeroDecisionEvidence> = votes
        .into_iter()
        .filter(|vote| vote.evidence.city_id == city_id)
        .map(|vote| vote.evidence)
        .collect();
    if evidences.len() != 2 {
        return Err(scope_violation(&format!(
            "city_vote_evidence_count;city_id={city_id};actual={}",
            evidences.len()
        )));
    }
    Ok(CityVoteCertificate::issue(
        &operation.proposal,
        &evidences,
        now_seconds,
    )?)
}

// ─────────────────────────────────────────────────────────────────────────────
// Agreement assembly (durable votes → contract certificate)
// ─────────────────────────────────────────────────────────────────────────────

/// Assemble the pure-contract [`CrossCityAgreementCertificate`] from the
/// durably stored votes of one operation. PURE: no DB access.
///
/// Fail-closed requirements: exactly [`CROSS_CITY_CITY_COUNT`] distinct cities
/// are represented, each contributing exactly [`CROSS_CITY_EVIDENCE_COUNT`]
/// `ALLOW` evidences bound to the same proposal; missing city pairs, extra
/// nodes in one city, any `DENY` evidence, duplicate nodes, and every
/// contract-level disagreement (proposal/frontier/mutation/expiry) surface as
/// explicit errors via [`CityVoteCertificate::issue`] and
/// [`CrossCityAgreementCertificate::reach`]. The certificate digest returned
/// here is the ONLY agreement digest a transition into AGREED may install —
/// it is never taken from a caller-supplied string alone.
///
/// Signatures remain opaque: crypto verification is a REQUIRED gate of the
/// future transport layer and is NOT performed or implied here.
fn assemble_agreement_certificate(
    proposal: &MutationProposal,
    votes: &[StoredCityVote],
    now_seconds: i64,
) -> Result<CrossCityAgreementCertificate, CrossCityRepositoryError> {
    use std::collections::BTreeMap;
    let mut by_city: BTreeMap<&str, Vec<&ZeroDecisionEvidence>> = BTreeMap::new();
    for vote in votes {
        by_city
            .entry(vote.evidence.city_id.as_str())
            .or_default()
            .push(&vote.evidence);
    }
    if by_city.len() != CROSS_CITY_CITY_COUNT {
        return Err(scope_violation(&format!(
            "agreement_city_vote_count;actual={};expected={CROSS_CITY_CITY_COUNT}",
            by_city.len()
        )));
    }
    let mut city_votes = Vec::with_capacity(by_city.len());
    for (city_id, evidences) in by_city {
        if evidences.len() != CROSS_CITY_EVIDENCE_COUNT {
            return Err(scope_violation(&format!(
                "agreement_city_evidence_count;city_id={city_id};actual={};expected={CROSS_CITY_EVIDENCE_COUNT}",
                evidences.len()
            )));
        }
        for evidence in &evidences {
            if evidence.decision != NodeDecision::Allow {
                return Err(scope_violation(&format!(
                    "agreement_vote_not_allow;city_id={city_id};node_id={}",
                    evidence.node_id
                )));
            }
        }
        let owned: Vec<ZeroDecisionEvidence> = evidences.into_iter().cloned().collect();
        city_votes.push(CityVoteCertificate::issue(proposal, &owned, now_seconds)?);
    }
    Ok(CrossCityAgreementCertificate::reach(
        proposal,
        &city_votes,
        now_seconds,
    )?)
}

/// Verify that the caller-supplied agreement digest equals the digest of the
/// independently re-derived certificate (pure). A missing or malformed digest
/// and any mismatch are fail-closed; the derived certificate stays the single
/// source of truth.
fn verify_provided_agreement_digest(
    provided: Option<&str>,
    certificate: &CrossCityAgreementCertificate,
) -> Result<(), CrossCityRepositoryError> {
    let Some(provided) = provided else {
        return Err(scope_violation("agreement_digest_required_for_agreed"));
    };
    let decoded = digest_from_hex(provided)?;
    if decoded.as_hex() != certificate.agreement_digest {
        return Err(scope_violation(
            "agreement_digest_mismatch_with_derived_certificate",
        ));
    }
    Ok(())
}

/// Lock the operation and its durable votes inside the caller's transaction
/// and re-derive the [`CrossCityAgreementCertificate`] from storage only.
///
/// This is the authoritative evidence-derived agreement for a future
/// coordinator: no bool, no caller string, no cache, and no legacy table can
/// substitute for it. Stored signatures stay opaque until the future
/// transport-layer crypto gate verifies them (residual risk: this derivation
/// proves digest-level integrity and proposal binding, NOT signature
/// authenticity).
pub async fn derive_cross_city_agreement_certificate_in_tx(
    tx: &mut Transaction<'_, MySql>,
    operation_id: &str,
    now_seconds: i64,
) -> Result<CrossCityAgreementCertificate, CrossCityRepositoryError> {
    let record = load_operation_for_update_in_tx(tx, operation_id).await?;
    let votes = load_bound_votes_in_tx(tx, &record).await?;
    assemble_agreement_certificate(&record.proposal, &votes, now_seconds)
}

// ─────────────────────────────────────────────────────────────────────────────
// City-state lease/phase primitives
// ─────────────────────────────────────────────────────────────────────────────

/// Lease granted on one per-city work row. The schema has no `attempts`
/// column, so no attempt counter is invented here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossCityCityStateLeaseGrant {
    pub state_id: i64,
    pub operation_id: String,
    pub city_id: String,
    pub phase: CrossCityOperationState,
    pub lease_owner: String,
    pub lease_token: CrossCityLeaseToken,
    /// Server-side UTC expiry read back after install.
    pub lease_expires_at: PrimitiveDateTime,
}

#[derive(Debug, sqlx::FromRow)]
struct CityStateLockRow {
    state_id: i64,
    operation_id: String,
    city_id: String,
    phase: String,
}

/// Lock one city-state row by primary key inside the caller's transaction
/// (fixed lock order: the parent operation row is already locked first).
async fn lock_city_state_row(
    tx: &mut Transaction<'_, MySql>,
    state_id: i64,
) -> Result<CityStateLockRow, CrossCityRepositoryError> {
    sqlx::query_as(CITY_STATE_LOCK_SQL)
        .bind(state_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| not_found(&format!("city_state_not_found;state_id={state_id}")))
}

/// Identity proof of the locked city row against the presented lease proof
/// (pure): primary key, parent operation, and city must match exactly — a
/// mutated or cross-wired row can never be mutated further.
fn verify_city_row_identity(
    row: &CityStateLockRow,
    proof: &CrossCityCityStateLeaseProof,
) -> Result<(), CrossCityRepositoryError> {
    if row.state_id != proof.state_id
        || row.operation_id != proof.operation_id
        || row.city_id != proof.city_id
    {
        return Err(mapping("poisoned_city_state_identity"));
    }
    Ok(())
}

/// Insert one per-city work row with the fixed lock order operation →
/// city_state: the parent operation row is locked first (missing parent =
/// explicit `NotFound`), must be live (non-terminal, unexpired), and the
/// initial phase must mirror it exactly (`phase == parent.state`) — a city
/// row can never be born ahead of or beside its parent. Plain INSERT: a
/// repeated (operation, city) pair is an explicit conflict. Terminal parents
/// are never touched here (or by any ordinary worker): the future
/// commit-confirmation mint primitive must write terminal city phases
/// atomically with the parent.
pub async fn insert_city_state_in_tx(
    tx: &mut Transaction<'_, MySql>,
    operation_id: &str,
    city_id: &str,
    phase: CrossCityOperationState,
    local_base_digest_hex: &str,
    now_seconds: i64,
) -> Result<i64, CrossCityRepositoryError> {
    let id = validated_operation_id(operation_id)?;
    validated_text(city_id, MAX_CROSS_CITY_IDENTIFIER_LENGTH, "city_id")?;
    validate_work_phase(phase)?;
    let local_base_digest = digest_from_hex(local_base_digest_hex)?;

    let parent = load_operation_for_update_in_tx(tx, &id).await?;
    ensure_parent_operation_live(&parent, now_seconds)?;
    verify_city_phase_mirrors_parent(&parent, phase)?;

    let result = sqlx::query(CITY_STATE_INSERT_SQL)
        .bind(&id)
        .bind(city_id)
        .bind(phase.as_str())
        .bind(local_base_digest.as_bytes().to_vec())
        .execute(&mut **tx)
        .await;
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            if db_unique_violation(&error) {
                return Err(conflict("city_state_exists"));
            }
            return Err(error.into());
        }
    };
    if result.rows_affected() != 1 {
        return Err(mapping("city_state_insert_not_applied"));
    }
    let state_id = i64::try_from(result.last_insert_id()).map_err(|_| {
        CrossCityRepositoryError::Mapping(
            "code=cross_city_repository.bigint_overflow;field=state_id".to_owned(),
        )
    })?;
    if state_id == 0 {
        return Err(mapping("city_state_insert_not_applied"));
    }
    Ok(state_id)
}

/// Claim the per-city work row of one (operation, city) whose lease is absent
/// or expired — WHATEVER its phase — with the fixed lock order operation →
/// city_state: the parent operation is locked first and must be live
/// (non-terminal, unexpired). The row's actual stored phase is parsed through
/// the closed-set parser and must be IN SYNC with the parent state or sit on a
/// deterministic catch-up path to it ([`next_catchup_hop`]); leading,
/// divergent, and ambiguous rows are poisoned for claiming and fail closed.
/// This is what lets a lease that lapsed across a parent advance be re-claimed
/// and catch up hop-by-hop. Live leases are never stolen. Installs a fresh
/// run-scoped [`CrossCityLeaseToken`] (only its SHA-256 hash persists), with
/// the expiry computed server-side and read back; the grant carries the row's
/// ACTUAL phase. Returns `Ok(None)` when nothing is claimable; a lost install
/// race is an explicit conflict. No network or waiting happens inside the
/// transaction.
pub async fn claim_city_state_in_tx(
    tx: &mut Transaction<'_, MySql>,
    operation_id: &str,
    city_id: &str,
    lease_owner: &str,
    lease_seconds: i64,
    now_seconds: i64,
) -> Result<Option<CrossCityCityStateLeaseGrant>, CrossCityRepositoryError> {
    let id = validated_operation_id(operation_id)?;
    validated_text(city_id, MAX_CROSS_CITY_IDENTIFIER_LENGTH, "city_id")?;
    validate_lease_material(lease_owner, lease_seconds)?;

    let parent = load_operation_for_update_in_tx(tx, &id).await?;
    ensure_parent_operation_live(&parent, now_seconds)?;

    let candidate: Option<CityStateLockRow> = sqlx::query_as(CITY_STATE_CLAIM_CANDIDATE_SQL)
        .bind(&id)
        .bind(city_id)
        .fetch_optional(&mut **tx)
        .await?;
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    // Identity predicate after taking the row lock (defense-in-depth against
    // engine snapshot drift; matches the delta-queue claim discipline).
    if candidate.operation_id != id || candidate.city_id != city_id {
        return Err(CrossCityRepositoryError::Conflict(
            "code=cross_city_repository.claim_race".to_owned(),
        ));
    }
    let actual_phase = parse_cross_city_operation_state(&candidate.phase)?;
    // In sync or deterministically catchable only: leading, divergent, and
    // ambiguous rows can never be (re)claimed.
    next_catchup_hop(actual_phase, parent.state)?;

    let token = CrossCityLeaseToken::new_run_scoped();
    let install = sqlx::query(CITY_STATE_CLAIM_INSTALL_SQL)
        .bind(lease_owner)
        .bind(token.token_hash().as_bytes().to_vec())
        .bind(lease_seconds)
        .bind(candidate.state_id)
        .bind(actual_phase.as_str())
        .execute(&mut **tx)
        .await?;
    if install.rows_affected() != 1 {
        return Err(CrossCityRepositoryError::Conflict(
            "code=cross_city_repository.claim_race".to_owned(),
        ));
    }

    #[derive(Debug, sqlx::FromRow)]
    struct ClaimReadbackRow {
        operation_id: String,
        city_id: String,
        phase: String,
        lease_expires_at: Option<PrimitiveDateTime>,
    }
    let readback: ClaimReadbackRow = sqlx::query_as(CITY_STATE_CLAIM_READBACK_SQL)
        .bind(candidate.state_id)
        .fetch_one(&mut **tx)
        .await?;
    if readback.operation_id != id
        || readback.city_id != city_id
        || parse_cross_city_operation_state(&readback.phase)? != actual_phase
    {
        return Err(mapping("claim_identity_drift"));
    }
    let Some(lease_expires_at) = readback.lease_expires_at else {
        return Err(mapping("claim_expiry_missing"));
    };

    Ok(Some(CrossCityCityStateLeaseGrant {
        state_id: candidate.state_id,
        operation_id: id,
        city_id: city_id.to_owned(),
        phase: actual_phase,
        lease_owner: lease_owner.to_owned(),
        lease_token: token,
        lease_expires_at,
    }))
}

/// Extend a live city-state lease with the fixed lock order operation →
/// city_state: the parent operation is locked first and must be live
/// (non-terminal, unexpired), the locked row identity must match the proof,
/// and the row phase must be in sync with the parent state or deterministically
/// catchable to it ([`next_catchup_hop`] — a lagging row that outlived a lease
/// across a parent advance may still be heartbeated); then a strict
/// owner + token-hash + server-side liveness CAS extends the lease. A lost
/// lease, dead parent, or leading/divergent/ambiguous row is an explicit
/// error — never a silent success.
pub async fn heartbeat_city_state_in_tx(
    tx: &mut Transaction<'_, MySql>,
    proof: &CrossCityCityStateLeaseProof,
    extension_seconds: i64,
    now_seconds: i64,
) -> Result<(), CrossCityRepositoryError> {
    validate_city_state_lease_proof(proof)?;
    validate_lease_material(&proof.lease_owner, extension_seconds)?;
    let parent = load_operation_for_update_in_tx(tx, &proof.operation_id).await?;
    ensure_parent_operation_live(&parent, now_seconds)?;
    let row = lock_city_state_row(tx, proof.state_id).await?;
    verify_city_row_identity(&row, proof)?;
    let row_phase = parse_cross_city_operation_state(&row.phase)?;
    verify_city_phase_catchable(&parent, row_phase)?;
    let result = sqlx::query(CITY_STATE_HEARTBEAT_SQL)
        .bind(extension_seconds)
        .bind(proof.state_id)
        .bind(&proof.lease_owner)
        .bind(proof.lease_token.token_hash().as_bytes().to_vec())
        .execute(&mut **tx)
        .await?;
    if result.rows_affected() != 1 {
        return Err(CrossCityRepositoryError::LeaseCasFailed(
            "code=cross_city_repository.heartbeat_lost_lease".to_owned(),
        ));
    }
    Ok(())
}

/// Guarded city-phase move under a live lease, with the fixed lock order
/// operation → city_state: the parent operation is locked first and must be
/// live (non-terminal, unexpired); the locked row identity is verified
/// against the proof and its phase is re-parsed through the closed-set
/// parser. The ONLY admitted target is the unique next hop the deterministic
/// catch-up oracle ([`next_catchup_hop`]) derives from the row's current
/// phase toward the locked parent state: an in-sync row has nothing to
/// transition, a lagging row advances exactly one shortest-path hop (multi-
/// phase catch-up happens across fresh leases), and leading, divergent, and
/// ambiguous rows are refused. The requested target must equal that next hop
/// AND stay a legal state-machine edge (the oracle is derived from the same
/// closed edges, checked again for defense-in-depth), then a CAS `UPDATE`
/// bound to the observed phase, owner, token hash, and server-side liveness
/// installs the target phase. Lost leases, dead parents, illegal moves, and
/// leading/divergent/ambiguous targets are explicit errors.
pub async fn transition_city_state_in_tx(
    tx: &mut Transaction<'_, MySql>,
    proof: &CrossCityCityStateLeaseProof,
    target_phase: CrossCityOperationState,
    now_seconds: i64,
) -> Result<CrossCityOperationState, CrossCityRepositoryError> {
    validate_city_state_lease_proof(proof)?;
    let parent = load_operation_for_update_in_tx(tx, &proof.operation_id).await?;
    ensure_parent_operation_live(&parent, now_seconds)?;
    let row = lock_city_state_row(tx, proof.state_id).await?;
    verify_city_row_identity(&row, proof)?;
    let current = parse_cross_city_operation_state(&row.phase)?;
    // Deterministic single-hop catch-up: the only admitted target is the
    // unique shortest-path next hop toward the locked parent state.
    let next = next_catchup_hop(current, parent.state)?;
    let Some(next) = next else {
        // In sync: a worker has nothing to transition.
        return Err(conflict(&format!(
            "city_state_in_sync;phase={};parent={}",
            current.as_str(),
            parent.state.as_str()
        )));
    };
    if target_phase != next {
        return Err(scope_violation(&format!(
            "city_phase_catchup_target_mismatch;required_next={};target={}",
            next.as_str(),
            target_phase.as_str()
        )));
    }
    // Defense-in-depth: the oracle is derived from these same closed edges,
    // so this can only fail if the machine regressed underneath it.
    current.transition(target_phase).map_err(|_| {
        CrossCityRepositoryError::InvalidTransition(format!(
            "code=cross_city_repository.illegal_city_phase_transition;from={};to={}",
            current.as_str(),
            target_phase.as_str()
        ))
    })?;
    let result = sqlx::query(CITY_STATE_TRANSITION_SQL)
        .bind(target_phase.as_str())
        .bind(proof.state_id)
        .bind(current.as_str())
        .bind(&proof.lease_owner)
        .bind(proof.lease_token.token_hash().as_bytes().to_vec())
        .execute(&mut **tx)
        .await?;
    if result.rows_affected() != 1 {
        return Err(CrossCityRepositoryError::LeaseCasFailed(
            "code=cross_city_repository.phase_transition_lost_lease".to_owned(),
        ));
    }
    Ok(target_phase)
}

/// Relinquish a live city-state lease without changing the phase, with the
/// fixed lock order operation → city_state: the parent operation is locked
/// first and must be live (non-terminal, unexpired), the locked row identity
/// must match the proof, and the row phase must be in sync with the parent
/// state or deterministically catchable to it ([`next_catchup_hop`]);
/// then a strict owner + token-hash + liveness CAS clears the lease. A lost
/// lease, dead parent, or leading/divergent/ambiguous row is an explicit
/// error — releasing a lease over a dead parent can never report success.
pub async fn release_city_state_in_tx(
    tx: &mut Transaction<'_, MySql>,
    proof: &CrossCityCityStateLeaseProof,
    now_seconds: i64,
) -> Result<(), CrossCityRepositoryError> {
    validate_city_state_lease_proof(proof)?;
    let parent = load_operation_for_update_in_tx(tx, &proof.operation_id).await?;
    ensure_parent_operation_live(&parent, now_seconds)?;
    let row = lock_city_state_row(tx, proof.state_id).await?;
    verify_city_row_identity(&row, proof)?;
    let row_phase = parse_cross_city_operation_state(&row.phase)?;
    verify_city_phase_catchable(&parent, row_phase)?;
    let result = sqlx::query(CITY_STATE_RELEASE_SQL)
        .bind(proof.state_id)
        .bind(&proof.lease_owner)
        .bind(proof.lease_token.token_hash().as_bytes().to_vec())
        .execute(&mut **tx)
        .await?;
    if result.rows_affected() != 1 {
        return Err(CrossCityRepositoryError::LeaseCasFailed(
            "code=cross_city_repository.release_lost_lease".to_owned(),
        ));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate primitives (BLOCKED default; ACTIVE only via unforgeable proof)
// ─────────────────────────────────────────────────────────────────────────────

/// Durable per-aggregate cross-city synchronization gate, strictly decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossCityGateRecord {
    pub gate_id: i64,
    pub tenant_id: i64,
    pub aggregate_type: String,
    pub aggregate_id: i64,
    pub operation_id: String,
    pub certificate_digest: String,
    pub target_generation: u64,
    pub revoke_fence: u64,
    pub state: CrossCityGateState,
    pub content_hash: String,
}

/// Insert-only creation request for one gate row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossCityGateInsert {
    pub tenant_id: i64,
    pub aggregate_type: String,
    pub aggregate_id: i64,
    pub operation_id: String,
    /// Already-verified certificate digest (hex) bound to the gate. Must equal
    /// the parent operation's stored agreement digest; gate creation without
    /// a certified parent agreement is refused.
    pub certificate_digest: String,
    pub target_generation: u64,
    pub revoke_fence: u64,
    /// Digest of the content the gate authorizes (hex). Provided by the
    /// future deterministic activation artifact; the parent operation has no
    /// such column today, but once written the row/proof/request binding is
    /// enforced field-by-field at every transition.
    pub content_hash: String,
    /// Initial state: `SYNCING` or `BLOCKED` only. `ACTIVE` at creation is a
    /// fail-closed error — activation requires [`CrossCityGateActivationProof`]
    /// through [`transition_gate_in_tx`].
    pub initial_state: CrossCityGateState,
}

/// Transition request for one gate row (explicit CAS update; no SQL upsert
/// form exists anywhere in this module). Every transition re-binds the
/// coordinator-verified certificate digest, target generation/fence, and
/// content hash to the row. The request names the parent operation so the
/// fixed lock order (operation → gate) and the parent binding checks can be
/// enforced before any gate mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossCityGateTransitionRequest {
    pub tenant_id: i64,
    pub aggregate_type: String,
    pub aggregate_id: i64,
    /// Parent operation of the gate; must equal the locked gate row's pinned
    /// operation and is loaded FOR UPDATE first.
    pub operation_id: String,
    pub target_state: CrossCityGateState,
    pub certificate_digest: String,
    pub target_generation: u64,
    pub revoke_fence: u64,
    pub content_hash: String,
    /// Required for (and only accepted with) a transition INTO `ACTIVE`;
    /// supplying it with any other target is refused.
    pub activation_proof: Option<CrossCityGateActivationProof>,
}

/// Unforgeable internal proof that a cross-city operation reached its
/// commit-confirmed durable state, entitling EXACTLY ONE gate scope of that
/// operation to move to `ACTIVE`.
///
/// The proof is pinned to one concrete gate scope — `tenant_id` +
/// `aggregate_type` + `aggregate_id`, the stable unique business key the gate
/// row is locked by. The auto-increment surrogate `gate_id` is deliberately
/// not pinned: the scope key is the durable identity the repository itself
/// locks on, and pinning a surrogate id would couple the proof to a value
/// that only exists after the row insert. The scope binding plus the pinned
/// operation makes cross-gate reuse impossible: a proof minted for one gate
/// can never activate a different one. Each proof is additionally pinned to
/// one operation, its certified agreement digest, and the exact target
/// generation / revoke fence / content hash it was confirmed for. All pinned
/// fields are re-checked field-by-field, three-way, against the locked parent
/// operation, the locked gate row, and the transition request at activation
/// time, so one proof can never activate an arbitrary scope, content, or
/// version.
///
/// There is intentionally no public constructor and no `bool` form: the
/// constructor below is MODULE-PRIVATE, so only code inside this file can
/// build a proof — today exclusively this module's pure tests, and in the
/// future ONLY a durable commit-confirmation mint primitive added inside this
/// module. Mint inputs are validated (positive scope ids, canonical
/// aggregate type, canonical UUID, canonical digests, positive generation,
/// `fence <= generation`) so a proof can only be derived from well-formed,
/// canonical records. Re-synchronization reuse is RETAINED by the state
/// machine: proofs are pure values and are never consumed, so the same gate
/// may present the same proof again (e.g. `ACTIVE -> SYNCING -> ACTIVE`
/// re-sync) while the parent is still the same commit-confirmed `ACTIVE`
/// operation and every bound field still matches — the proposal expiry bound
/// never blocks durable convergence — no one-time-use ledger and no new
/// table. Deriving `Clone` only widens an already-minted proof, never forges
/// one; `Debug` redacts the digest fields so a log line can never reproduce
/// the full minted value.
#[derive(Clone, PartialEq, Eq)]
pub struct CrossCityGateActivationProof {
    tenant_id: i64,
    aggregate_type: String,
    aggregate_id: i64,
    operation_id: String,
    agreement_digest: String,
    target_generation: u64,
    target_revoke_fence: u64,
    content_hash: String,
}

impl CrossCityGateActivationProof {
    /// Mint a proof for exactly one gate scope of one commit-confirmed
    /// operation. MODULE-PRIVATE: reserved for a future commit-confirmation
    /// mint primitive inside this module; every pinned field is validated
    /// here.
    // No caller exists in this slice by design (the gate-ACTIVE entry stays
    // unreachable), so the never-used lint is silenced explicitly instead of
    // weakening the gate.
    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    fn new(
        tenant_id: i64,
        aggregate_type: String,
        aggregate_id: i64,
        operation_id: String,
        agreement_digest: String,
        target_generation: u64,
        target_revoke_fence: u64,
        content_hash: String,
    ) -> Result<Self, CrossCityRepositoryError> {
        positive_i64(tenant_id, "gate_proof_tenant_id")?;
        validated_aggregate_type(&aggregate_type)?;
        positive_i64(aggregate_id, "gate_proof_aggregate_id")?;
        let operation_id = validated_operation_id(&operation_id)?;
        let agreement_digest = digest_from_hex(&agreement_digest)?.as_hex();
        let content_hash = digest_from_hex(&content_hash)?.as_hex();
        if target_generation == 0 {
            return Err(scope_violation("gate_proof_non_positive_generation"));
        }
        validate_gate_generation_pair(target_generation, target_revoke_fence)?;
        Ok(Self {
            tenant_id,
            aggregate_type,
            aggregate_id,
            operation_id,
            agreement_digest,
            target_generation,
            target_revoke_fence,
            content_hash,
        })
    }

    pub fn tenant_id(&self) -> i64 {
        self.tenant_id
    }

    pub fn aggregate_type(&self) -> &str {
        &self.aggregate_type
    }

    pub fn aggregate_id(&self) -> i64 {
        self.aggregate_id
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn agreement_digest(&self) -> &str {
        &self.agreement_digest
    }

    pub fn target_generation(&self) -> u64 {
        self.target_generation
    }

    pub fn target_revoke_fence(&self) -> u64 {
        self.target_revoke_fence
    }

    pub fn content_hash(&self) -> &str {
        &self.content_hash
    }
}

impl fmt::Debug for CrossCityGateActivationProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The proof is a capability token: its digest fields are redacted so a
        // Debug log can never reproduce the full minted value. The gate scope
        // and generation pins are non-secret identifiers and stay visible.
        formatter
            .debug_struct("CrossCityGateActivationProof")
            .field("tenant_id", &self.tenant_id)
            .field("aggregate_type", &self.aggregate_type)
            .field("aggregate_id", &self.aggregate_id)
            .field("operation_id", &self.operation_id)
            .field("agreement_digest", &"<sha256>")
            .field("target_generation", &self.target_generation)
            .field("target_revoke_fence", &self.target_revoke_fence)
            .field("content_hash", &"<sha256>")
            .finish()
    }
}

/// Pure fail-closed gate transition rules over the closed
/// [`CrossCityGateState`] set: no self-transitions, and every move INTO
/// `ACTIVE` requires an activation proof. Moves that only reduce readiness
/// (`ACTIVE -> SYNCING`/`BLOCKED`, `SYNCING -> BLOCKED`) and the honest work
/// moves (`BLOCKED -> SYNCING`) are free.
pub fn evaluate_gate_transition(
    current: CrossCityGateState,
    target: CrossCityGateState,
    has_activation_proof: bool,
) -> Result<(), CrossCityRepositoryError> {
    use CrossCityGateState as G;
    if current == target {
        return Err(CrossCityRepositoryError::InvalidTransition(
            "code=cross_city_repository.gate_self_transition".to_owned(),
        ));
    }
    let legal = match (current, target) {
        (G::Blocked, G::Syncing) | (G::Syncing, G::Blocked) => true,
        (G::Active, G::Blocked) | (G::Active, G::Syncing) => true,
        (G::Blocked, G::Active) | (G::Syncing, G::Active) => has_activation_proof,
        // Equal pairs were refused above; this arm only satisfies the
        // exhaustiveness check and always fails closed.
        (G::Syncing, G::Syncing) | (G::Active, G::Active) | (G::Blocked, G::Blocked) => false,
    };
    if legal {
        Ok(())
    } else {
        Err(CrossCityRepositoryError::InvalidTransition(format!(
            "code=cross_city_repository.gate_transition_not_allowed;from={};to={};activation_proof={has_activation_proof}",
            current.as_str(),
            target.as_str()
        )))
    }
}

fn validate_gate_generation_pair(
    target_generation: u64,
    revoke_fence: u64,
) -> Result<(), CrossCityRepositoryError> {
    if revoke_fence > target_generation {
        return Err(scope_violation(&format!(
            "gate_fence_exceeds_generation;generation={target_generation};fence={revoke_fence}"
        )));
    }
    Ok(())
}

/// Gate creation may only reference a parent operation that already carries
/// its certified agreement digest, and the request's certificate digest must
/// equal it (pure). No gate record can exist without an approved certificate.
fn validate_gate_parent_binding(
    parent_agreement_digest: Option<&str>,
    request_certificate_digest: &str,
) -> Result<(), CrossCityRepositoryError> {
    let Some(parent_agreement) = parent_agreement_digest else {
        return Err(scope_violation("gate_requires_parent_agreement"));
    };
    if parent_agreement != request_certificate_digest {
        return Err(scope_violation("gate_certificate_digest_mismatch"));
    }
    Ok(())
}

/// Full parent/row/proof/request binding for a gate entering `ACTIVE` (pure).
///
/// Three-way, field-by-field: every proof pin must equal BOTH the locked gate
/// row and the transition request wherever they overlap, and the parent
/// operation must agree everywhere it is involved:
///
/// - the parent operation must be in its commit-confirmed terminal state
///   (`ACTIVE` — the only state of the current enum that proves a confirmed
///   commit; any stricter internal proof state would only tighten this);
/// - the gate scope (`tenant_id`, `aggregate_type`, `aggregate_id`) must be
///   identical across proof, locked row, and request, so a proof minted for
///   one gate can never activate a different one;
/// - the pinned operation must equal the parent's, the row's, and the
///   request's operation id;
/// - the certified agreement digest must agree across parent, proof, and
///   request;
/// - the target generation and revoke fence must agree across parent, locked
///   row, proof, and request — an `ACTIVE` transition NEVER silently repairs
///   a wrong-version row;
/// - the content hash must agree across locked row, proof, and request.
///
/// `content_hash` is a distinct commit-confirmed content binding — it is NOT
/// assumed to equal the operation's `mutation_digest`. Proof values are never
/// consumed here: re-presenting the same proof for the same gate scope is
/// decided by the state machine (see [`evaluate_gate_transition`]), not by
/// this check.
fn verify_gate_activation_binding(
    parent: &CrossCityOperationRecord,
    record: &CrossCityGateRecord,
    proof: &CrossCityGateActivationProof,
    request: &CrossCityGateTransitionRequest,
) -> Result<(), CrossCityRepositoryError> {
    if parent.state != CrossCityOperationState::Active {
        return Err(scope_violation(&format!(
            "gate_parent_not_commit_confirmed;state={}",
            parent.state.as_str()
        )));
    }
    let Some(parent_agreement) = &parent.agreement_digest else {
        // Unreachable for a decoded ACTIVE row (agreement-presence invariant),
        // but kept fail-closed for any future caller.
        return Err(mapping("poisoned_operation_agreement_presence"));
    };
    if parent_agreement != proof.agreement_digest() {
        return Err(scope_violation("gate_activation_parent_agreement_mismatch"));
    }
    // Operation identity: parent == proof == locked row == request.
    if proof.operation_id() != parent.operation_id
        || proof.operation_id() != record.operation_id
        || proof.operation_id() != request.operation_id
    {
        return Err(scope_violation("gate_activation_operation_mismatch"));
    }
    // Gate scope: proof == locked row == request. One proof activates exactly
    // the one gate scope it was minted for.
    if proof.tenant_id() != record.tenant_id || proof.tenant_id() != request.tenant_id {
        return Err(scope_violation("gate_activation_tenant_mismatch"));
    }
    if proof.aggregate_type() != record.aggregate_type
        || proof.aggregate_type() != request.aggregate_type
    {
        return Err(scope_violation("gate_activation_aggregate_type_mismatch"));
    }
    if proof.aggregate_id() != record.aggregate_id || proof.aggregate_id() != request.aggregate_id {
        return Err(scope_violation("gate_activation_aggregate_id_mismatch"));
    }
    if proof.agreement_digest() != request.certificate_digest {
        return Err(scope_violation("gate_activation_digest_mismatch"));
    }
    // Direct row-vs-request certificate binding — kept alongside the
    // transitive parent → proof → request chain above so a drifted row
    // certificate can never be activated even if another link were loosened.
    if record.certificate_digest != request.certificate_digest {
        return Err(scope_violation("gate_activation_row_certificate_mismatch"));
    }
    // Versions: parent == proof == locked row == request. A wrong-version row
    // is refused, never silently repaired into the activated version.
    if parent.target_generation != request.target_generation
        || proof.target_generation() != request.target_generation
        || record.target_generation != request.target_generation
    {
        return Err(scope_violation("gate_activation_generation_mismatch"));
    }
    if parent.target_revoke_fence != request.revoke_fence
        || proof.target_revoke_fence() != request.revoke_fence
        || record.revoke_fence != request.revoke_fence
    {
        return Err(scope_violation("gate_activation_fence_mismatch"));
    }
    // Content binding: locked row == proof == request.
    if record.content_hash != request.content_hash || proof.content_hash() != request.content_hash {
        return Err(scope_violation("gate_activation_content_hash_mismatch"));
    }
    Ok(())
}

/// Gate transitions may not rewrite ANY bound metadata: the request must
/// restate exactly the locked row's certificate digest, target generation,
/// revoke fence, and content hash (pure). The activation path is bound by the
/// same rule ([`verify_gate_activation_binding`] compares the row's versions
/// too), so bound metadata is immutable for the row's lifetime — a
/// wrong-version row can only be abandoned, never repaired in place.
fn verify_gate_metadata_unchanged(
    record: &CrossCityGateRecord,
    request_certificate_digest: &str,
    request_target_generation: u64,
    request_revoke_fence: u64,
    request_content_hash: &str,
) -> Result<(), CrossCityRepositoryError> {
    if record.certificate_digest != request_certificate_digest {
        return Err(scope_violation(
            "gate_binding_immutable;field=certificate_digest",
        ));
    }
    if record.target_generation != request_target_generation {
        return Err(scope_violation(
            "gate_binding_immutable;field=target_generation",
        ));
    }
    if record.revoke_fence != request_revoke_fence {
        return Err(scope_violation("gate_binding_immutable;field=revoke_fence"));
    }
    if record.content_hash != request_content_hash {
        return Err(scope_violation("gate_binding_immutable;field=content_hash"));
    }
    Ok(())
}

/// The gate's pinned certificate must always equal the parent operation's
/// stored agreement digest, for EVERY transition (pure). A drifted gate or a
/// gate over a different agreement can never be mutated further.
fn verify_gate_certificate_matches_parent(
    parent: &CrossCityOperationRecord,
    record: &CrossCityGateRecord,
) -> Result<(), CrossCityRepositoryError> {
    let Some(parent_agreement) = &parent.agreement_digest else {
        // Gate creation already required a certified parent; a parent without
        // an agreement digest is poisoned storage here.
        return Err(mapping("poisoned_operation_agreement_presence"));
    };
    if parent_agreement.as_str() != record.certificate_digest {
        return Err(scope_violation("gate_parent_certificate_mismatch"));
    }
    Ok(())
}

/// Gate-creation parent admission (pure):
/// - `ACTIVE` parents are admitted REGARDLESS of the proposal expiry bound:
///   (re)creating a gate over a commit-confirmed operation is recovery work,
///   and proposal expiry must never block durable convergence;
/// - `REJECTED`/`EXPIRED`/`QUARANTINED` parents are refused outright — no
///   certified outcome exists for a new gate to bind;
/// - every other (pre-terminal) parent must be unexpired: proposal expiry
///   forbids STARTING new synchronization work.
fn ensure_gate_parent_insertable(
    parent: &CrossCityOperationRecord,
    now_seconds: i64,
) -> Result<(), CrossCityRepositoryError> {
    use CrossCityOperationState as S;
    match parent.state {
        // Commit-confirmed terminal: recovery admission, expiry-tolerant.
        S::Active => Ok(()),
        // Terminal without a confirmed commit: nothing to synchronize.
        S::Rejected | S::Expired | S::Quarantined => Err(scope_violation(&format!(
            "gate_parent_terminal_not_insertable;state={}",
            parent.state.as_str()
        ))),
        // Pre-terminal states: new synchronization work must start within the
        // proposal window.
        _ => ensure_not_expired("gate_parent_operation", parent.expires_at, now_seconds),
    }
}

/// Gate creation must bind the parent's EXACT target generation and revoke
/// fence (pure): a row can never be created with versions that disagree with
/// the parent's certified target.
fn validate_gate_parent_version_binding(
    parent: &CrossCityOperationRecord,
    request_target_generation: u64,
    request_revoke_fence: u64,
) -> Result<(), CrossCityRepositoryError> {
    if parent.target_generation != request_target_generation
        || parent.target_revoke_fence != request_revoke_fence
    {
        return Err(scope_violation(&format!(
            "gate_parent_version_mismatch;parent_generation={};parent_fence={};request_generation={};request_fence={}",
            parent.target_generation,
            parent.target_revoke_fence,
            request_target_generation,
            request_revoke_fence
        )));
    }
    Ok(())
}

/// Insert-only gate creation. Plain INSERT: an existing gate for the same
/// (tenant, aggregate_type, aggregate_id) is an explicit conflict — there is
/// no upsert form that could overwrite unknown values.
///
/// Referential, certificate, version, and expiry binding are enforced inside
/// the caller's transaction with the fixed lock order operation → gate: the
/// parent operation row is locked first (missing parent = explicit
/// `NotFound`), it must already carry its certified agreement digest, the
/// request's certificate digest must equal it, the request's target
/// generation/revoke fence must equal the parent's certified target versions,
/// and the parent must be admissible: `ACTIVE` parents (commit-confirmed
/// recovery) are admitted even past the proposal expiry bound, terminal
/// `REJECTED`/`EXPIRED`/`QUARANTINED` parents are refused outright, and every
/// pre-terminal parent must be unexpired. `content_hash` is provided by the
/// future deterministic activation artifact — the parent operation has no
/// such column today, but once written the row/proof/request binding is
/// enforced field-by-field at every transition (including activation).
pub async fn insert_gate_in_tx(
    tx: &mut Transaction<'_, MySql>,
    request: &CrossCityGateInsert,
    now_seconds: i64,
) -> Result<i64, CrossCityRepositoryError> {
    positive_i64(request.tenant_id, "tenant_id")?;
    positive_i64(request.aggregate_id, "aggregate_id")?;
    validated_aggregate_type(&request.aggregate_type)?;
    let operation_id = validated_operation_id(&request.operation_id)?;
    let certificate_digest = digest_from_hex(&request.certificate_digest)?;
    let content_hash = digest_from_hex(&request.content_hash)?;
    validate_gate_generation_pair(request.target_generation, request.revoke_fence)?;
    if !matches!(
        request.initial_state,
        CrossCityGateState::Syncing | CrossCityGateState::Blocked
    ) {
        return Err(scope_violation("gate_initial_state_not_allowed"));
    }

    // Fixed lock order: operation -> gate. Fail-closed parent existence,
    // certified-agreement binding, target-version binding, and parent
    // admission before any gate row can be created.
    let parent = load_operation_for_update_in_tx(tx, &operation_id).await?;
    validate_gate_parent_binding(
        parent.agreement_digest.as_deref(),
        &request.certificate_digest,
    )?;
    validate_gate_parent_version_binding(&parent, request.target_generation, request.revoke_fence)?;
    ensure_gate_parent_insertable(&parent, now_seconds)?;

    let result = sqlx::query(GATE_INSERT_SQL)
        .bind(request.tenant_id)
        .bind(&request.aggregate_type)
        .bind(request.aggregate_id)
        .bind(&operation_id)
        .bind(certificate_digest.as_bytes().to_vec())
        .bind(bind_i64(request.target_generation, "target_generation")?)
        .bind(bind_i64(request.revoke_fence, "revoke_fence")?)
        .bind(request.initial_state.as_str())
        .bind(content_hash.as_bytes().to_vec())
        .execute(&mut **tx)
        .await;
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            if db_unique_violation(&error) {
                return Err(conflict("gate_exists"));
            }
            return Err(error.into());
        }
    };
    if result.rows_affected() != 1 {
        return Err(mapping("gate_insert_not_applied"));
    }
    let gate_id = i64::try_from(result.last_insert_id()).map_err(|_| {
        CrossCityRepositoryError::Mapping(
            "code=cross_city_repository.bigint_overflow;field=gate_id".to_owned(),
        )
    })?;
    if gate_id == 0 {
        return Err(mapping("gate_insert_not_applied"));
    }
    Ok(gate_id)
}

#[derive(Debug, sqlx::FromRow)]
struct GateRow {
    gate_id: i64,
    tenant_id: i64,
    aggregate_type: String,
    aggregate_id: i64,
    operation_id: String,
    certificate_digest: Vec<u8>,
    target_generation: i64,
    revoke_fence: i64,
    state: String,
    content_hash: Vec<u8>,
}

fn decode_gate_row(row: GateRow) -> Result<CrossCityGateRecord, CrossCityRepositoryError> {
    if row.gate_id <= 0 || row.tenant_id <= 0 || row.aggregate_id <= 0 {
        return Err(mapping("poisoned_gate_identity"));
    }
    validated_aggregate_type(&row.aggregate_type)
        .map_err(|_| mapping("poisoned_gate_aggregate_type"))?;
    let operation_id = validated_operation_id(&row.operation_id)?;
    let certificate_digest = digest_from_bytes(row.certificate_digest)?;
    let content_hash = digest_from_bytes(row.content_hash)?;
    let state = parse_cross_city_gate_state(&row.state)?;
    let target_generation = read_u64(row.target_generation, "target_generation")?;
    let revoke_fence = read_u64(row.revoke_fence, "revoke_fence")?;
    validate_gate_generation_pair(target_generation, revoke_fence)
        .map_err(|_| mapping("poisoned_gate_generation_pair"))?;
    Ok(CrossCityGateRecord {
        gate_id: row.gate_id,
        tenant_id: row.tenant_id,
        aggregate_type: row.aggregate_type,
        aggregate_id: row.aggregate_id,
        operation_id,
        certificate_digest: certificate_digest.as_hex(),
        target_generation,
        revoke_fence,
        state,
        content_hash: content_hash.as_hex(),
    })
}

/// Lock and strictly decode one gate row inside the caller's transaction.
/// Missing rows are explicit `NotFound`; poisoned rows fail closed. Stored
/// gates are never replaced by cached values.
///
/// MODULE-PRIVATE by lock-order design: this takes the gate row lock, so it
/// may only be called after the parent operation row is already locked (the
/// fixed operation → gate order). Keeping it private makes the reverse
/// gate → operation lock order unexpressible for every caller outside this
/// file; the only in-module caller ([`transition_gate_in_tx`]) locks the
/// parent first.
async fn load_gate_for_update_in_tx(
    tx: &mut Transaction<'_, MySql>,
    tenant_id: i64,
    aggregate_type: &str,
    aggregate_id: i64,
) -> Result<CrossCityGateRecord, CrossCityRepositoryError> {
    positive_i64(tenant_id, "tenant_id")?;
    positive_i64(aggregate_id, "aggregate_id")?;
    validated_aggregate_type(aggregate_type)?;
    let row: Option<GateRow> = sqlx::query_as(GATE_SELECT_FOR_UPDATE_SQL)
        .bind(tenant_id)
        .bind(aggregate_type)
        .bind(aggregate_id)
        .fetch_optional(&mut **tx)
        .await?;
    let Some(row) = row else {
        return Err(not_found(&format!(
            "gate_not_found;tenant_id={tenant_id};aggregate_type={aggregate_type};aggregate_id={aggregate_id}"
        )));
    };
    decode_gate_row(row)
}

/// Explicit CAS gate transition (no SQL upsert form exists). Lock order is
/// fixed: operation → gate.
///
/// For EVERY target the locked gate's pinned certificate must equal the
/// parent operation's stored agreement digest, and the request must restate
/// the locked row's certificate digest, target generation, revoke fence, and
/// content hash exactly — bound metadata is immutable for the row's lifetime
/// and an `ACTIVE` transition never silently repairs a wrong-version row.
/// The activation path INTO `ACTIVE` additionally requires a
/// [`CrossCityGateActivationProof`] whose pinned gate scope (`tenant_id` +
/// `aggregate_type` + `aggregate_id`), operation, agreement digest, target
/// generation/revoke fence, and content hash agree, three-way and
/// field-by-field, with the locked parent operation (which must be in its
/// commit-confirmed terminal state `ACTIVE`), the locked gate row, and the
/// request — so one proof can never activate a different gate or an arbitrary
/// content or version. The parent's PROPOSAL expiry bound deliberately does
/// not gate activation: proposal expiry blocks new work, never the
/// convergence of a durable commit-confirmed operation. The proof value is
/// never consumed: the same gate may re-present it for a re-sync
/// (`ACTIVE -> SYNCING -> ACTIVE`).
///
/// No `now_seconds` parameter: the parent-state admission (commit-confirmed
/// `ACTIVE`) is the only activation liveness this primitive needs, and
/// proposal expiry is deliberately not consulted (see above).
pub async fn transition_gate_in_tx(
    tx: &mut Transaction<'_, MySql>,
    request: &CrossCityGateTransitionRequest,
) -> Result<CrossCityGateState, CrossCityRepositoryError> {
    positive_i64(request.tenant_id, "tenant_id")?;
    positive_i64(request.aggregate_id, "aggregate_id")?;
    validated_aggregate_type(&request.aggregate_type)?;
    let operation_id = validated_operation_id(&request.operation_id)?;
    let certificate_digest = digest_from_hex(&request.certificate_digest)?;
    let content_hash = digest_from_hex(&request.content_hash)?;
    validate_gate_generation_pair(request.target_generation, request.revoke_fence)?;

    // Fixed lock order: operation -> gate. The parent operation is locked and
    // strictly decoded first; the gate's pinned operation must match it.
    let parent = load_operation_for_update_in_tx(tx, &operation_id).await?;
    let record = load_gate_for_update_in_tx(
        tx,
        request.tenant_id,
        &request.aggregate_type,
        request.aggregate_id,
    )
    .await?;
    if record.operation_id != operation_id {
        return Err(scope_violation("gate_operation_identity_mismatch"));
    }
    // Every transition: the gate stays pinned to the parent's certified
    // agreement.
    verify_gate_certificate_matches_parent(&parent, &record)?;
    evaluate_gate_transition(
        record.state,
        request.target_state,
        request.activation_proof.is_some(),
    )?;
    match (request.target_state, &request.activation_proof) {
        (CrossCityGateState::Active, Some(proof)) => {
            // Commit-confirmed convergence: the parent must be ACTIVE (the
            // binding check enforces it), but the proposal expiry bound
            // deliberately does NOT block an ACTIVE re-sync — proposal expiry
            // blocks new work, never durable convergence. No expiry check
            // here on purpose.
            verify_gate_activation_binding(&parent, &record, proof, request)?;
        }
        (CrossCityGateState::Active, None) => {
            // evaluate_gate_transition already refuses this; kept fail-closed
            // so the binding rules can never be bypassed by construction.
            return Err(scope_violation("gate_activation_requires_proof"));
        }
        (_, Some(_)) => {
            // A proof is a capability for activation only; carrying it into a
            // readiness-reducing or work transition is refused so the minted
            // value cannot silently circulate.
            return Err(scope_violation("gate_activation_proof_not_applicable"));
        }
        (_, None) => {
            // Non-ACTIVE transitions restate the locked bindings verbatim;
            // nothing can be smuggled in.
            verify_gate_metadata_unchanged(
                &record,
                &request.certificate_digest,
                request.target_generation,
                request.revoke_fence,
                &request.content_hash,
            )?;
        }
    }

    let result = sqlx::query(GATE_TRANSITION_SQL)
        .bind(request.target_state.as_str())
        .bind(certificate_digest.as_bytes().to_vec())
        .bind(bind_i64(request.target_generation, "target_generation")?)
        .bind(bind_i64(request.revoke_fence, "revoke_fence")?)
        .bind(content_hash.as_bytes().to_vec())
        .bind(request.tenant_id)
        .bind(&request.aggregate_type)
        .bind(request.aggregate_id)
        .bind(record.state.as_str())
        .execute(&mut **tx)
        .await?;
    if result.rows_affected() != 1 {
        // The row was locked above; a zero-row CAS here fails closed.
        return Err(conflict("gate_cas_unexpected"));
    }
    Ok(request.target_state)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests (pure: no DB, no network, no external system)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const OPERATION_ID: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn digest_hex(seed: u8) -> String {
        format!("{seed:02x}").repeat(32)
    }

    // ── codec / identity boundary ──────────────────────────────────────────

    #[test]
    fn sha256_digest_adapters_roundtrip_and_reject_malformed() {
        let hex = digest_hex(0x2a);
        let decoded = digest_from_hex(&hex).unwrap();
        assert_eq!(decoded.as_hex(), hex);
        let round = digest_from_bytes(decoded.as_bytes().to_vec()).unwrap();
        assert_eq!(round, decoded);
        let optional = digest_from_optional_bytes(Some(decoded.as_bytes().as_slice())).unwrap();
        assert_eq!(optional, Some(decoded));
        assert!(digest_from_optional_bytes(None).unwrap().is_none());

        // Uppercase, wrong length, and non-hex are all refused.
        assert!(digest_from_hex(&hex.to_uppercase()).is_err());
        assert!(digest_from_hex(&hex[..63]).is_err());
        assert!(digest_from_hex(&format!("{hex}0")).is_err());
        assert!(digest_from_hex(&"g".repeat(64)).is_err());
        assert!(digest_from_bytes(vec![0u8; 31]).is_err());
        assert!(digest_from_bytes(vec![0u8; 33]).is_err());
    }

    #[test]
    fn operation_id_boundary_rejects_noncanonical_forms() {
        assert_eq!(
            validated_operation_id(OPERATION_ID).unwrap().as_str(),
            OPERATION_ID
        );
        assert!(validated_operation_id("550E8400-E29B-41D4-A716-446655440000").is_err());
        assert!(validated_operation_id("{550e8400-e29b-41d4-a716-446655440000}").is_err());
        assert!(validated_operation_id("urn:uuid:550e8400-e29b-41d4-a716-446655440000").is_err());
        assert!(validated_operation_id("00000000-0000-0000-0000-000000000000").is_err());
        assert!(validated_operation_id("not-a-uuid").is_err());
        assert!(validated_operation_id("550e8400-e29b-41d4-a716-44665544000").is_err());
    }

    #[test]
    fn datetime_helpers_roundtrip_and_reject_out_of_range() {
        let instant = unix_seconds_to_datetime(1_000_000_000, "expires_at").unwrap();
        assert_eq!(datetime_to_unix_seconds(instant), 1_000_000_000);
        let instant = unix_seconds_to_datetime(1, "expires_at").unwrap();
        assert_eq!(datetime_to_unix_seconds(instant), 1);
        assert!(unix_seconds_to_datetime(i64::MAX, "expires_at").is_err());
        assert!(unix_seconds_to_datetime(i64::MIN, "expires_at").is_err());
    }

    #[test]
    fn bigint_boundary_rejects_overflow_and_negative_reads() {
        assert_eq!(bind_i64(1, "field").unwrap(), 1);
        assert!(bind_i64(u64::MAX, "field").is_err());
        assert!(bind_i64(i64::MAX as u64 + 1, "field").is_err());
        assert_eq!(read_u64(i64::MAX, "field").unwrap(), i64::MAX as u64);
        assert!(read_u64(-1, "field").is_err());
        assert!(positive_i64(0, "field").is_err());
        assert!(positive_i64(-3, "field").is_err());
        assert!(positive_i64(7, "field").is_ok());
    }

    // ── lease token redaction and hashing ──────────────────────────────────

    #[test]
    fn lease_token_is_redacted_and_hash_is_deterministic() {
        let token = CrossCityLeaseToken::new_run_scoped();
        let other = CrossCityLeaseToken::new_run_scoped();
        assert_ne!(token, other);
        assert_ne!(token.as_str(), other.as_str());

        let debug = format!("{token:?}");
        let display = format!("{token}");
        for output in [debug, display] {
            assert!(output.contains("REDACTED"));
            assert!(!output.contains(token.as_str()));
        }

        let expected = hex::encode(Sha256::digest(token.as_str().as_bytes()));
        assert_eq!(token.token_hash().as_hex(), expected);
        assert_eq!(token.token_hash(), token.token_hash());
        assert_ne!(token.token_hash(), other.token_hash());
    }

    #[test]
    fn lease_material_bounds_are_enforced() {
        assert!(validate_lease_material("worker-1", 1).is_ok());
        assert!(validate_lease_material("worker-1", MAX_CROSS_CITY_LEASE_SECONDS).is_ok());
        assert!(validate_lease_material("worker-1", 0).is_err());
        assert!(validate_lease_material("worker-1", -5).is_err());
        assert!(validate_lease_material("worker-1", MAX_CROSS_CITY_LEASE_SECONDS + 1).is_err());
        assert!(validate_lease_material("", 10).is_err());
        assert!(validate_lease_material("  ", 10).is_err());
        assert!(validate_lease_material("worker with space", 10).is_err());
        // Padded spellings are refused outright, never normalized.
        assert!(validate_lease_material(" worker-1", 10).is_err());
        assert!(validate_lease_material("worker-1 ", 10).is_err());

        let token = CrossCityLeaseToken::new_run_scoped();
        let proof = CrossCityCityStateLeaseProof {
            state_id: 1,
            operation_id: OPERATION_ID.to_owned(),
            city_id: "city-alpha".to_owned(),
            lease_owner: "worker-1".to_owned(),
            lease_token: token,
        };
        assert!(validate_city_state_lease_proof(&proof).is_ok());
        assert!(
            validate_city_state_lease_proof(&CrossCityCityStateLeaseProof {
                state_id: 0,
                operation_id: OPERATION_ID.to_owned(),
                city_id: "city-alpha".to_owned(),
                lease_owner: "worker-1".to_owned(),
                lease_token: CrossCityLeaseToken::new_run_scoped(),
            })
            .is_err()
        );
        // Proof identity text must be canonical: a noncanonical operation id
        // or a padded city id is refused outright.
        assert!(
            validate_city_state_lease_proof(&CrossCityCityStateLeaseProof {
                state_id: 1,
                operation_id: "550E8400-E29B-41D4-A716-446655440000".to_owned(),
                city_id: "city-alpha".to_owned(),
                lease_owner: "worker-1".to_owned(),
                lease_token: CrossCityLeaseToken::new_run_scoped(),
            })
            .is_err()
        );
        assert!(
            validate_city_state_lease_proof(&CrossCityCityStateLeaseProof {
                state_id: 1,
                operation_id: OPERATION_ID.to_owned(),
                city_id: " city-alpha".to_owned(),
                lease_owner: "worker-1".to_owned(),
                lease_token: CrossCityLeaseToken::new_run_scoped(),
            })
            .is_err()
        );
    }

    #[test]
    fn last_error_truncation_bounds_to_512() {
        let long = "x".repeat(600);
        assert_eq!(truncate_last_error(&long).chars().count(), 512);
        assert_eq!(truncate_last_error("short"), "short");
    }

    // ── closed-set parsers and work phases ─────────────────────────────────

    #[test]
    fn operation_state_parser_is_a_closed_set() {
        let all = [
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
        ];
        for state in all {
            assert_eq!(
                parse_cross_city_operation_state(state.as_str()).unwrap(),
                state
            );
        }
        assert!(parse_cross_city_operation_state("BOGUS").is_err());
        assert!(parse_cross_city_operation_state("proposed").is_err());
        assert!(parse_cross_city_operation_state("").is_err());
    }

    #[test]
    fn gate_state_parser_is_a_closed_set() {
        for state in [
            CrossCityGateState::Syncing,
            CrossCityGateState::Active,
            CrossCityGateState::Blocked,
        ] {
            assert_eq!(parse_cross_city_gate_state(state.as_str()).unwrap(), state);
        }
        assert!(parse_cross_city_gate_state("READY").is_err());
        assert!(parse_cross_city_gate_state("").is_err());
    }

    #[test]
    fn terminal_phases_are_never_claimable() {
        for terminal in [
            CrossCityOperationState::Active,
            CrossCityOperationState::Rejected,
            CrossCityOperationState::Expired,
            CrossCityOperationState::Quarantined,
        ] {
            assert!(validate_work_phase(terminal).is_err());
        }
        for workable in [
            CrossCityOperationState::Proposed,
            CrossCityOperationState::Voting,
            CrossCityOperationState::Agreed,
            CrossCityOperationState::Preparing,
            CrossCityOperationState::Prepared,
            CrossCityOperationState::Activating,
            CrossCityOperationState::InDoubt,
            CrossCityOperationState::Deferred,
        ] {
            assert!(validate_work_phase(workable).is_ok());
        }
    }

    // ── pure transition rules ──────────────────────────────────────────────

    #[test]
    fn agreement_digest_placement_rule_is_strict() {
        let digest = digest_from_hex(&digest_hex(0x01)).unwrap();
        let other = digest_from_hex(&digest_hex(0x02)).unwrap();
        let hex = digest_hex(0x01);

        // Entering AGREED requires the digest.
        assert!(
            resolve_agreement_digest_update(CrossCityOperationState::Agreed, Some(&hex), None)
                .unwrap()
                .is_some()
        );
        assert!(
            resolve_agreement_digest_update(CrossCityOperationState::Agreed, None, None).is_err()
        );
        // Any other transition refuses an agreement digest.
        assert!(
            resolve_agreement_digest_update(CrossCityOperationState::Voting, Some(&hex), None)
                .is_err()
        );
        assert!(resolve_agreement_digest_update(
            CrossCityOperationState::Preparing,
            Some(&hex),
            Some(digest)
        )
        .is_err());
        // Stored agreement digests are immutable against different values.
        assert!(resolve_agreement_digest_update(
            CrossCityOperationState::Agreed,
            Some(&hex),
            Some(other)
        )
        .is_err());
        assert!(resolve_agreement_digest_update(
            CrossCityOperationState::Agreed,
            Some(&hex),
            Some(digest)
        )
        .is_ok());
        // Digest-free transitions keep the stored value untouched.
        assert!(resolve_agreement_digest_update(
            CrossCityOperationState::Preparing,
            None,
            Some(digest)
        )
        .unwrap()
        .is_none());
        // Malformed digests are refused even in the AGREED position.
        assert!(resolve_agreement_digest_update(
            CrossCityOperationState::Agreed,
            Some("nothex"),
            None
        )
        .is_err());
    }

    #[test]
    fn gate_transition_matrix_is_fail_closed() {
        use CrossCityGateState as G;
        let states = [G::Syncing, G::Active, G::Blocked];
        for &current in &states {
            for &target in &states {
                let result_without_proof = evaluate_gate_transition(current, target, false).is_ok();
                let result_with_proof = evaluate_gate_transition(current, target, true).is_ok();
                if current == target {
                    // No self-transitions, with or without proof.
                    assert!(!result_without_proof && !result_with_proof);
                } else if matches!(
                    (current, target),
                    (G::Blocked, G::Syncing)
                        | (G::Syncing, G::Blocked)
                        | (G::Active, G::Blocked)
                        | (G::Active, G::Syncing)
                ) {
                    // Readiness-reducing and honest work moves are free.
                    assert!(result_without_proof && result_with_proof);
                } else {
                    // Into ACTIVE only with the unforgeable proof.
                    assert!(!result_without_proof && result_with_proof);
                }
            }
        }
    }

    #[test]
    fn operation_transition_guard_refuses_illegal_and_terminal_moves() {
        // Terminal states never transition again.
        for terminal in [
            CrossCityOperationState::Active,
            CrossCityOperationState::Rejected,
            CrossCityOperationState::Expired,
            CrossCityOperationState::Quarantined,
        ] {
            assert!(terminal
                .transition(CrossCityOperationState::Voting)
                .is_err());
        }
        // Arbitrary skips are refused; the guarded legal move works.
        assert!(CrossCityOperationState::Proposed
            .transition(CrossCityOperationState::Active)
            .is_err());
        assert!(CrossCityOperationState::Proposed
            .transition(CrossCityOperationState::Voting)
            .is_ok());
    }

    // ── agreement assembly and gate parent binding (review regressions) ───

    const EXPIRES_AT: i64 = 1_000_000;
    const NOW: i64 = 999_999;
    const CITY_ALPHA: &str = "city-alpha";
    const CITY_BETA: &str = "city-beta";
    const OPERATION_ID_ALT: &str = "0b9e6b1e-3d0a-4d0f-8d5f-2f1a0b9c8d7e";
    const GATE_TENANT_ID: i64 = 7;
    const GATE_AGGREGATE_TYPE: &str = "CARD";
    const GATE_AGGREGATE_ID: i64 = 9;
    const GATE_TENANT_ID_ALT: i64 = 8;
    const GATE_AGGREGATE_TYPE_ALT: &str = "ROLE";
    const GATE_AGGREGATE_ID_ALT: i64 = 10;

    fn test_proposal() -> MutationProposal {
        MutationProposal::new(
            OPERATION_ID,
            &digest_hex(0x01),
            &digest_hex(0x02),
            &digest_hex(0x03),
            &digest_hex(0x04),
            4,
            1,
            5,
            1,
            "compiler-1",
            "policy-1",
            EXPIRES_AT,
        )
        .unwrap()
    }

    fn decision_vote(
        proposal: &MutationProposal,
        city: &str,
        node: &str,
        decision: NodeDecision,
    ) -> ZeroDecisionEvidence {
        ZeroDecisionEvidence::new(
            city,
            node,
            3,
            decision,
            &proposal.proposal_digest().unwrap(),
            &proposal.base_frontier_digest,
            &proposal.mutation_digest,
            &format!("nonce-{node}"),
            proposal.expires_at,
            &format!("sig-{node}"),
        )
        .unwrap()
    }

    fn allow_vote(proposal: &MutationProposal, city: &str, node: &str) -> ZeroDecisionEvidence {
        decision_vote(proposal, city, node, NodeDecision::Allow)
    }

    fn deny_vote(proposal: &MutationProposal, city: &str, node: &str) -> ZeroDecisionEvidence {
        decision_vote(proposal, city, node, NodeDecision::Deny)
    }

    fn stored_vote(vote_id: i64, evidence: ZeroDecisionEvidence) -> StoredCityVote {
        StoredCityVote { vote_id, evidence }
    }

    fn two_city_allow_votes(proposal: &MutationProposal) -> Vec<StoredCityVote> {
        vec![
            stored_vote(1, allow_vote(proposal, CITY_ALPHA, "node-a1")),
            stored_vote(2, allow_vote(proposal, CITY_ALPHA, "node-a2")),
            stored_vote(3, allow_vote(proposal, CITY_BETA, "node-b1")),
            stored_vote(4, allow_vote(proposal, CITY_BETA, "node-b2")),
        ]
    }

    fn parent_record(
        state: CrossCityOperationState,
        agreement_digest: Option<&str>,
    ) -> CrossCityOperationRecord {
        let proposal = test_proposal();
        CrossCityOperationRecord {
            operation_id: proposal.operation_id.clone(),
            scope_digest: proposal.scope_digest.clone(),
            request_digest: proposal.request_digest.clone(),
            mutation_digest: proposal.mutation_digest.clone(),
            base_frontier_digest: proposal.base_frontier_digest.clone(),
            base_source_generation: proposal.base_source_generation,
            base_revoke_fence: proposal.base_revoke_fence,
            target_generation: proposal.target_generation,
            target_revoke_fence: proposal.target_revoke_fence,
            proposal_digest: proposal.proposal_digest().unwrap(),
            compiler_version: proposal.compiler_version.clone(),
            policy_version: proposal.policy_version.clone(),
            home_city: "home-city".to_owned(),
            coordinator_epoch: 1,
            state,
            agreement_digest: agreement_digest.map(str::to_owned),
            expires_at: proposal.expires_at,
            last_error: None,
            proposal,
        }
    }

    fn activation_proof(
        parent: &CrossCityOperationRecord,
        content_hash: &str,
    ) -> CrossCityGateActivationProof {
        CrossCityGateActivationProof::new(
            GATE_TENANT_ID,
            GATE_AGGREGATE_TYPE.to_owned(),
            GATE_AGGREGATE_ID,
            parent.operation_id.clone(),
            parent.agreement_digest.clone().unwrap(),
            parent.target_generation,
            parent.target_revoke_fence,
            content_hash.to_owned(),
        )
        .unwrap()
    }

    fn gate_record(state: CrossCityGateState) -> CrossCityGateRecord {
        CrossCityGateRecord {
            gate_id: 1,
            tenant_id: GATE_TENANT_ID,
            aggregate_type: GATE_AGGREGATE_TYPE.to_owned(),
            aggregate_id: GATE_AGGREGATE_ID,
            operation_id: OPERATION_ID.to_owned(),
            certificate_digest: digest_hex(0x05),
            target_generation: 5,
            revoke_fence: 1,
            state,
            content_hash: digest_hex(0x06),
        }
    }

    /// The fully-bound baseline request for the default gate scope. Variant
    /// requests in the tests below are derived from this baseline by single-
    /// field mutation instead of an 8-argument helper.
    fn bound_gate_request(agreement: &str, content: &str) -> CrossCityGateTransitionRequest {
        CrossCityGateTransitionRequest {
            tenant_id: GATE_TENANT_ID,
            aggregate_type: GATE_AGGREGATE_TYPE.to_owned(),
            aggregate_id: GATE_AGGREGATE_ID,
            operation_id: OPERATION_ID.to_owned(),
            target_state: CrossCityGateState::Active,
            certificate_digest: agreement.to_owned(),
            target_generation: 5,
            revoke_fence: 1,
            content_hash: content.to_owned(),
            activation_proof: None,
        }
    }

    #[test]
    fn validated_text_rejects_padded_and_malformed_values() {
        assert!(validated_text("worker-1", 128, "lease_owner").is_ok());
        assert!(validated_text(" worker-1", 128, "lease_owner").is_err());
        assert!(validated_text("worker-1 ", 128, "lease_owner").is_err());
        assert!(validated_text("worker\t1", 128, "lease_owner").is_err());
        assert!(validated_text("", 128, "lease_owner").is_err());
        assert!(validated_text(&"x".repeat(129), 128, "lease_owner").is_err());
        assert!(validated_aggregate_type(" CARD").is_err());
        assert!(validated_aggregate_type("CARD ").is_err());
        assert!(validated_text("home-city", MAX_CROSS_CITY_IDENTIFIER_LENGTH, "home_city").is_ok());
        assert!(
            validated_text(" home-city", MAX_CROSS_CITY_IDENTIFIER_LENGTH, "home_city").is_err()
        );
    }

    #[test]
    fn agreement_assembly_requires_two_complete_city_pairs() {
        let proposal = test_proposal();
        let alpha_first = allow_vote(&proposal, CITY_ALPHA, "node-a1");
        let alpha_second = allow_vote(&proposal, CITY_ALPHA, "node-a2");
        let beta_first = allow_vote(&proposal, CITY_BETA, "node-b1");
        let beta_second = allow_vote(&proposal, CITY_BETA, "node-b2");

        // No votes at all.
        assert!(assemble_agreement_certificate(&proposal, &[], NOW).is_err());
        // Only one city voted.
        let one_city = vec![
            stored_vote(1, alpha_first.clone()),
            stored_vote(2, alpha_second.clone()),
        ];
        assert!(assemble_agreement_certificate(&proposal, &one_city, NOW).is_err());
        // The second city contributed only one of its two evidences.
        let half_city = vec![
            stored_vote(1, alpha_first.clone()),
            stored_vote(2, alpha_second.clone()),
            stored_vote(3, beta_first.clone()),
        ];
        assert!(assemble_agreement_certificate(&proposal, &half_city, NOW).is_err());
        // One city produced three evidences (ambiguous pair selection).
        let third_node = allow_vote(&proposal, CITY_ALPHA, "node-a3");
        let triple = vec![
            stored_vote(1, alpha_first.clone()),
            stored_vote(2, alpha_second.clone()),
            stored_vote(3, third_node),
        ];
        assert!(assemble_agreement_certificate(&proposal, &triple, NOW).is_err());
        // A DENY evidence can never be promoted into a city vote.
        let denying = vec![
            stored_vote(1, alpha_first.clone()),
            stored_vote(2, deny_vote(&proposal, CITY_ALPHA, "node-a2")),
            stored_vote(3, beta_first.clone()),
            stored_vote(4, beta_second.clone()),
        ];
        assert!(assemble_agreement_certificate(&proposal, &denying, NOW).is_err());

        // Two complete, distinct, all-ALLOW city pairs reach the agreement.
        let complete = two_city_allow_votes(&proposal);
        let certificate = assemble_agreement_certificate(&proposal, &complete, NOW).unwrap();
        certificate.validate_at(NOW).unwrap();
        assert_eq!(certificate.operation_id, OPERATION_ID);
        // The derivation is deterministic over the same durable votes.
        let again = assemble_agreement_certificate(&proposal, &complete, NOW).unwrap();
        assert_eq!(certificate.agreement_digest, again.agreement_digest);
    }

    #[test]
    fn provided_agreement_digest_must_match_derived_certificate() {
        let proposal = test_proposal();
        let complete = two_city_allow_votes(&proposal);
        let certificate = assemble_agreement_certificate(&proposal, &complete, NOW).unwrap();

        // A missing digest never enters AGREED.
        assert!(verify_provided_agreement_digest(None, &certificate).is_err());
        // Any caller-supplied string that is not the derived digest fails.
        assert!(verify_provided_agreement_digest(Some(&digest_hex(0x7f)), &certificate).is_err());
        assert!(verify_provided_agreement_digest(Some("nothex"), &certificate).is_err());
        // Only the evidence-derived certificate digest is accepted.
        assert!(verify_provided_agreement_digest(
            Some(&certificate.agreement_digest),
            &certificate
        )
        .is_ok());
    }

    #[test]
    fn gate_parent_binding_requires_certified_agreement() {
        // No parent agreement digest: gate creation is refused (no orphan
        // gate without an approved certificate).
        assert!(validate_gate_parent_binding(None, &digest_hex(0x05)).is_err());
        // The certificate digest must equal the parent's stored agreement.
        assert!(validate_gate_parent_binding(Some(&digest_hex(0x05)), &digest_hex(0x06)).is_err());
        assert!(validate_gate_parent_binding(Some(&digest_hex(0x05)), &digest_hex(0x05)).is_ok());
    }

    #[test]
    fn gate_insert_parent_admission_matrix_is_fail_closed() {
        // Pre-terminal parents: new synchronization work must start within
        // the proposal window…
        let agreed = parent_record(CrossCityOperationState::Agreed, Some(&digest_hex(0x05)));
        let preparing = parent_record(CrossCityOperationState::Preparing, Some(&digest_hex(0x05)));
        assert!(ensure_gate_parent_insertable(&agreed, NOW).is_ok());
        assert!(ensure_gate_parent_insertable(&preparing, NOW).is_ok());
        assert!(ensure_gate_parent_insertable(&agreed, EXPIRES_AT).is_err());
        assert!(ensure_gate_parent_insertable(&preparing, EXPIRES_AT + 1).is_err());
        // …ACTIVE parents are commit-confirmed recovery targets and are
        // admitted even past the proposal expiry bound…
        let active = parent_record(CrossCityOperationState::Active, Some(&digest_hex(0x05)));
        assert!(ensure_gate_parent_insertable(&active, NOW).is_ok());
        assert!(ensure_gate_parent_insertable(&active, EXPIRES_AT).is_ok());
        assert!(ensure_gate_parent_insertable(&active, EXPIRES_AT + 1).is_ok());
        // …while terminal parents without a confirmed commit are refused
        // outright, expired or not.
        for terminal in [
            CrossCityOperationState::Rejected,
            CrossCityOperationState::Expired,
            CrossCityOperationState::Quarantined,
        ] {
            let parent = parent_record(terminal, Some(&digest_hex(0x05)));
            assert!(ensure_gate_parent_insertable(&parent, NOW).is_err());
            assert!(ensure_gate_parent_insertable(&parent, EXPIRES_AT + 1).is_err());
        }
    }

    #[test]
    fn gate_insert_binds_parent_target_versions() {
        // parent_record carries the proposal's certified target: generation 5,
        // fence 1.
        let parent = parent_record(CrossCityOperationState::Agreed, Some(&digest_hex(0x05)));
        assert!(validate_gate_parent_version_binding(&parent, 5, 1).is_ok());
        assert!(validate_gate_parent_version_binding(&parent, 6, 1).is_err());
        assert!(validate_gate_parent_version_binding(&parent, 5, 2).is_err());
        assert!(validate_gate_parent_version_binding(&parent, 6, 2).is_err());
    }

    #[test]
    fn gate_activation_binds_parent_state_scope_and_versions() {
        let agreement = digest_hex(0x05);
        let content = digest_hex(0x06);
        let parent = parent_record(CrossCityOperationState::Active, Some(&agreement));
        let record = gate_record(CrossCityGateState::Syncing);
        let proof = activation_proof(&parent, &content);
        let request = bound_gate_request(&agreement, &content);

        // Fully bound parent/row/proof/request passes.
        assert!(verify_gate_activation_binding(&parent, &record, &proof, &request).is_ok());

        // Parent missing is structural (async load returns NotFound); any
        // non-commit-confirmed parent state is refused here.
        let preparing = parent_record(CrossCityOperationState::Preparing, Some(&agreement));
        assert!(verify_gate_activation_binding(&preparing, &record, &proof, &request).is_err());
        let voting = parent_record(CrossCityOperationState::Voting, None);
        assert!(verify_gate_activation_binding(&voting, &record, &proof, &request).is_err());

        // Gate scope must agree three-way: request side. Each variant is the
        // baseline request with exactly one scope field mutated.
        let mut wrong_tenant_request = bound_gate_request(&agreement, &content);
        wrong_tenant_request.tenant_id = GATE_TENANT_ID_ALT;
        assert!(
            verify_gate_activation_binding(&parent, &record, &proof, &wrong_tenant_request)
                .is_err()
        );
        let mut wrong_type_request = bound_gate_request(&agreement, &content);
        wrong_type_request.aggregate_type = GATE_AGGREGATE_TYPE_ALT.to_owned();
        assert!(
            verify_gate_activation_binding(&parent, &record, &proof, &wrong_type_request).is_err()
        );
        let mut wrong_id_request = bound_gate_request(&agreement, &content);
        wrong_id_request.aggregate_id = GATE_AGGREGATE_ID_ALT;
        assert!(
            verify_gate_activation_binding(&parent, &record, &proof, &wrong_id_request).is_err()
        );

        // Gate scope must agree three-way: locked-row side.
        let foreign_tenant = CrossCityGateRecord {
            tenant_id: GATE_TENANT_ID_ALT,
            ..gate_record(CrossCityGateState::Syncing)
        };
        assert!(
            verify_gate_activation_binding(&parent, &foreign_tenant, &proof, &request).is_err()
        );
        let foreign_type = CrossCityGateRecord {
            aggregate_type: GATE_AGGREGATE_TYPE_ALT.to_owned(),
            ..gate_record(CrossCityGateState::Syncing)
        };
        assert!(verify_gate_activation_binding(&parent, &foreign_type, &proof, &request).is_err());
        let foreign_id = CrossCityGateRecord {
            aggregate_id: GATE_AGGREGATE_ID_ALT,
            ..gate_record(CrossCityGateState::Syncing)
        };
        assert!(verify_gate_activation_binding(&parent, &foreign_id, &proof, &request).is_err());
        // A row pinned to another operation can never be activated.
        let foreign_operation = CrossCityGateRecord {
            operation_id: OPERATION_ID_ALT.to_owned(),
            ..gate_record(CrossCityGateState::Syncing)
        };
        assert!(
            verify_gate_activation_binding(&parent, &foreign_operation, &proof, &request).is_err()
        );

        // Locked-row version mismatches: an ACTIVE transition NEVER silently
        // repairs a wrong-version row — generation, revoke fence, and content
        // hash must already equal both proof and request.
        let wrong_generation = CrossCityGateRecord {
            target_generation: 6,
            ..gate_record(CrossCityGateState::Syncing)
        };
        assert!(
            verify_gate_activation_binding(&parent, &wrong_generation, &proof, &request).is_err()
        );
        let wrong_fence = CrossCityGateRecord {
            revoke_fence: 2,
            ..gate_record(CrossCityGateState::Syncing)
        };
        assert!(verify_gate_activation_binding(&parent, &wrong_fence, &proof, &request).is_err());
        let wrong_content = CrossCityGateRecord {
            content_hash: digest_hex(0x08),
            ..gate_record(CrossCityGateState::Syncing)
        };
        assert!(verify_gate_activation_binding(&parent, &wrong_content, &proof, &request).is_err());
        // Direct row certificate binding: a drifted row certificate is refused
        // even though the transitive parent -> proof -> request chain would
        // still hold.
        let wrong_certificate = CrossCityGateRecord {
            certificate_digest: digest_hex(0x0b),
            ..gate_record(CrossCityGateState::Syncing)
        };
        assert!(
            verify_gate_activation_binding(&parent, &wrong_certificate, &proof, &request).is_err()
        );

        // Certificate digest disagreement between request and proof.
        assert!(verify_gate_activation_binding(
            &parent,
            &record,
            &proof,
            &bound_gate_request(&digest_hex(0x07), &content)
        )
        .is_err());
        // Generation/fence must agree with BOTH the proof and the parent.
        let mut wrong_generation_request = bound_gate_request(&agreement, &content);
        wrong_generation_request.target_generation = 6;
        assert!(verify_gate_activation_binding(
            &parent,
            &record,
            &proof,
            &wrong_generation_request
        )
        .is_err());
        let mut wrong_fence_request = bound_gate_request(&agreement, &content);
        wrong_fence_request.revoke_fence = 2;
        assert!(
            verify_gate_activation_binding(&parent, &record, &proof, &wrong_fence_request).is_err()
        );
        // Content hash must equal the proof's pinned value.
        assert!(verify_gate_activation_binding(
            &parent,
            &record,
            &proof,
            &bound_gate_request(&agreement, &digest_hex(0x08))
        )
        .is_err());
        // A proof minted for another operation can never activate this gate.
        let foreign = CrossCityGateActivationProof::new(
            GATE_TENANT_ID,
            GATE_AGGREGATE_TYPE.to_owned(),
            GATE_AGGREGATE_ID,
            OPERATION_ID_ALT.to_owned(),
            agreement.clone(),
            5,
            1,
            content.clone(),
        )
        .unwrap();
        assert!(verify_gate_activation_binding(&parent, &record, &foreign, &request).is_err());
        // A proof minted for a different gate scope can never activate this
        // gate (each scope dimension individually).
        let foreign_tenant_proof = CrossCityGateActivationProof::new(
            GATE_TENANT_ID_ALT,
            GATE_AGGREGATE_TYPE.to_owned(),
            GATE_AGGREGATE_ID,
            OPERATION_ID.to_owned(),
            agreement.clone(),
            5,
            1,
            content.clone(),
        )
        .unwrap();
        assert!(
            verify_gate_activation_binding(&parent, &record, &foreign_tenant_proof, &request)
                .is_err()
        );
        let foreign_type_proof = CrossCityGateActivationProof::new(
            GATE_TENANT_ID,
            GATE_AGGREGATE_TYPE_ALT.to_owned(),
            GATE_AGGREGATE_ID,
            OPERATION_ID.to_owned(),
            agreement.clone(),
            5,
            1,
            content.clone(),
        )
        .unwrap();
        assert!(
            verify_gate_activation_binding(&parent, &record, &foreign_type_proof, &request)
                .is_err()
        );
        let foreign_id_proof = CrossCityGateActivationProof::new(
            GATE_TENANT_ID,
            GATE_AGGREGATE_TYPE.to_owned(),
            GATE_AGGREGATE_ID_ALT,
            OPERATION_ID.to_owned(),
            agreement.clone(),
            5,
            1,
            content.clone(),
        )
        .unwrap();
        assert!(
            verify_gate_activation_binding(&parent, &record, &foreign_id_proof, &request).is_err()
        );
    }

    #[test]
    fn same_gate_resync_may_reuse_the_same_unconsumed_proof() {
        // Re-synchronization reuse is retained by the state machine: proofs
        // are pure values and are never consumed, so the same gate may present
        // the same proof again (ACTIVE -> SYNCING -> ACTIVE) while the parent
        // is still the same commit-confirmed ACTIVE operation and every bound
        // field still matches — regardless of the proposal expiry bound,
        // which never blocks durable convergence. No one-time-use ledger and
        // no new table.
        let agreement = digest_hex(0x05);
        let content = digest_hex(0x06);
        let parent = parent_record(CrossCityOperationState::Active, Some(&agreement));
        let record = gate_record(CrossCityGateState::Syncing);
        let proof = activation_proof(&parent, &content);
        let request = bound_gate_request(&agreement, &content);

        let first = verify_gate_activation_binding(&parent, &record, &proof, &request);
        let second = verify_gate_activation_binding(&parent, &record, &proof, &request);
        assert!(
            first.is_ok() && second.is_ok(),
            "re-presented proof must still bind"
        );

        // The resync path itself stays open for the same gate…
        assert!(evaluate_gate_transition(
            CrossCityGateState::Active,
            CrossCityGateState::Syncing,
            false
        )
        .is_ok());
        assert!(evaluate_gate_transition(
            CrossCityGateState::Syncing,
            CrossCityGateState::Active,
            true
        )
        .is_ok());
        // …while a different gate can never reuse the proof.
        let other_gate = CrossCityGateRecord {
            tenant_id: GATE_TENANT_ID_ALT,
            aggregate_id: GATE_AGGREGATE_ID_ALT,
            ..gate_record(CrossCityGateState::Syncing)
        };
        assert!(verify_gate_activation_binding(&parent, &other_gate, &proof, &request).is_err());
    }

    #[test]
    fn activation_proof_constructor_validates_and_debug_redacts() {
        // Malformed scope, identity, or digest material can never be minted.
        assert!(CrossCityGateActivationProof::new(
            0,
            GATE_AGGREGATE_TYPE.to_owned(),
            GATE_AGGREGATE_ID,
            OPERATION_ID.to_owned(),
            digest_hex(0x05),
            5,
            1,
            digest_hex(0x06),
        )
        .is_err());
        assert!(CrossCityGateActivationProof::new(
            -1,
            GATE_AGGREGATE_TYPE.to_owned(),
            GATE_AGGREGATE_ID,
            OPERATION_ID.to_owned(),
            digest_hex(0x05),
            5,
            1,
            digest_hex(0x06),
        )
        .is_err());
        assert!(CrossCityGateActivationProof::new(
            GATE_TENANT_ID,
            "CARD ".to_owned(),
            GATE_AGGREGATE_ID,
            OPERATION_ID.to_owned(),
            digest_hex(0x05),
            5,
            1,
            digest_hex(0x06),
        )
        .is_err());
        assert!(CrossCityGateActivationProof::new(
            GATE_TENANT_ID,
            GATE_AGGREGATE_TYPE.to_owned(),
            0,
            OPERATION_ID.to_owned(),
            digest_hex(0x05),
            5,
            1,
            digest_hex(0x06),
        )
        .is_err());
        assert!(CrossCityGateActivationProof::new(
            GATE_TENANT_ID,
            GATE_AGGREGATE_TYPE.to_owned(),
            GATE_AGGREGATE_ID,
            "not-a-uuid".to_owned(),
            digest_hex(0x05),
            5,
            1,
            digest_hex(0x06),
        )
        .is_err());
        assert!(CrossCityGateActivationProof::new(
            GATE_TENANT_ID,
            GATE_AGGREGATE_TYPE.to_owned(),
            GATE_AGGREGATE_ID,
            OPERATION_ID.to_owned(),
            "nothex".to_owned(),
            5,
            1,
            digest_hex(0x06),
        )
        .is_err());
        assert!(CrossCityGateActivationProof::new(
            GATE_TENANT_ID,
            GATE_AGGREGATE_TYPE.to_owned(),
            GATE_AGGREGATE_ID,
            OPERATION_ID.to_owned(),
            digest_hex(0x05),
            0,
            0,
            digest_hex(0x06),
        )
        .is_err());
        assert!(CrossCityGateActivationProof::new(
            GATE_TENANT_ID,
            GATE_AGGREGATE_TYPE.to_owned(),
            GATE_AGGREGATE_ID,
            OPERATION_ID.to_owned(),
            digest_hex(0x05),
            5,
            6,
            digest_hex(0x06),
        )
        .is_err());

        let proof = CrossCityGateActivationProof::new(
            GATE_TENANT_ID,
            GATE_AGGREGATE_TYPE.to_owned(),
            GATE_AGGREGATE_ID,
            OPERATION_ID.to_owned(),
            digest_hex(0x05),
            5,
            1,
            digest_hex(0x06),
        )
        .unwrap();
        let debug = format!("{proof:?}");
        assert!(debug.contains("CrossCityGateActivationProof"));
        // The capability's digest fields never leak through Debug.
        assert!(!debug.contains(&digest_hex(0x05)));
        assert!(!debug.contains(&digest_hex(0x06)));
        // The non-secret gate scope pins stay visible for diagnostics.
        assert!(debug.contains("CARD"));
        assert!(debug.contains("operation_id"));
    }

    // ── review regressions: evidence window, gate immutability, liveness ──

    #[test]
    fn vote_accepting_states_are_a_closed_whitelist() {
        // PROPOSED and VOTING are the only states that still accept evidence.
        assert!(validate_vote_accepting_state(CrossCityOperationState::Proposed).is_ok());
        assert!(validate_vote_accepting_state(CrossCityOperationState::Voting).is_ok());
        // Every other state of the closed set refuses new evidence — the
        // whitelist is exhaustive, so no state can be "forgotten".
        for closed in [
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
            assert!(validate_vote_accepting_state(closed).is_err());
        }
    }

    #[test]
    fn vote_city_capacity_is_enforced_at_the_cap() {
        // A city contributes exactly CROSS_CITY_EVIDENCE_COUNT (2) evidences:
        // 0/1 existing are fine, 2+ refuse the third node so it can never
        // permanently poison the city's certificate selection.
        assert_eq!(CROSS_CITY_EVIDENCE_COUNT, 2);
        assert!(validate_vote_city_capacity(0).is_ok());
        assert!(validate_vote_city_capacity(1).is_ok());
        assert!(validate_vote_city_capacity(2).is_err());
        assert!(validate_vote_city_capacity(3).is_err());
    }

    fn takeover_request(
        operation_id: &str,
        expected_state: CrossCityOperationState,
        current_epoch: u64,
        new_epoch: u64,
    ) -> CrossCityOperationTakeoverRequest {
        CrossCityOperationTakeoverRequest {
            operation_id: operation_id.to_owned(),
            expected_state,
            current_epoch,
            new_epoch,
        }
    }

    #[test]
    fn takeover_request_validation_is_monotonic_and_non_terminal() {
        use CrossCityOperationState as S;
        // Canonical operation id required.
        assert!(
            validate_takeover_request(&takeover_request("not-a-uuid", S::Agreed, 1, 2)).is_err()
        );
        // Epoch zero is never a valid current epoch.
        assert!(
            validate_takeover_request(&takeover_request(OPERATION_ID, S::Agreed, 0, 1)).is_err()
        );
        // The epoch fence is strictly monotonic: equal and lower are refused.
        assert!(
            validate_takeover_request(&takeover_request(OPERATION_ID, S::Agreed, 3, 3)).is_err()
        );
        assert!(
            validate_takeover_request(&takeover_request(OPERATION_ID, S::Agreed, 3, 2)).is_err()
        );
        // Terminal states are never take-over-able.
        for terminal in [S::Active, S::Rejected, S::Expired, S::Quarantined] {
            assert!(
                validate_takeover_request(&takeover_request(OPERATION_ID, terminal, 1, 2)).is_err()
            );
        }
        // A strictly monotonic, non-terminal move is admitted — including the
        // commit-unknown states, so an expired ACTIVATING/IN_DOUBT row can be
        // taken over for reconciliation.
        assert!(
            validate_takeover_request(&takeover_request(OPERATION_ID, S::Agreed, 3, 4)).is_ok()
        );
        assert!(
            validate_takeover_request(&takeover_request(OPERATION_ID, S::Activating, 3, 4)).is_ok()
        );
        assert!(
            validate_takeover_request(&takeover_request(OPERATION_ID, S::InDoubt, 3, 4)).is_ok()
        );
    }

    #[test]
    fn gate_metadata_is_immutable_outside_activation() {
        let record = CrossCityGateRecord {
            gate_id: 1,
            tenant_id: 7,
            aggregate_type: "CARD".to_owned(),
            aggregate_id: 9,
            operation_id: OPERATION_ID.to_owned(),
            certificate_digest: digest_hex(0x05),
            target_generation: 5,
            revoke_fence: 1,
            state: CrossCityGateState::Syncing,
            content_hash: digest_hex(0x06),
        };

        // Restating the locked bindings verbatim passes…
        assert!(verify_gate_metadata_unchanged(
            &record,
            &digest_hex(0x05),
            5,
            1,
            &digest_hex(0x06)
        )
        .is_ok());
        // …but each of the four bound fields refuses any rewrite.
        assert!(verify_gate_metadata_unchanged(
            &record,
            &digest_hex(0x07),
            5,
            1,
            &digest_hex(0x06)
        )
        .is_err());
        assert!(verify_gate_metadata_unchanged(
            &record,
            &digest_hex(0x05),
            6,
            1,
            &digest_hex(0x06)
        )
        .is_err());
        assert!(verify_gate_metadata_unchanged(
            &record,
            &digest_hex(0x05),
            5,
            2,
            &digest_hex(0x06)
        )
        .is_err());
        assert!(verify_gate_metadata_unchanged(
            &record,
            &digest_hex(0x05),
            5,
            1,
            &digest_hex(0x08)
        )
        .is_err());

        // The gate certificate must always match the parent agreement.
        let parent = parent_record(CrossCityOperationState::Agreed, Some(&digest_hex(0x05)));
        assert!(verify_gate_certificate_matches_parent(&parent, &record).is_ok());
        let other_agreement =
            parent_record(CrossCityOperationState::Agreed, Some(&digest_hex(0x09)));
        assert!(verify_gate_certificate_matches_parent(&other_agreement, &record).is_err());
        let uncertified = parent_record(CrossCityOperationState::Voting, None);
        assert!(verify_gate_certificate_matches_parent(&uncertified, &record).is_err());
    }

    #[test]
    fn parent_operation_liveness_rules_are_fail_closed() {
        // Every terminal parent state refuses city work, even unexpired.
        for terminal in [
            CrossCityOperationState::Active,
            CrossCityOperationState::Rejected,
            CrossCityOperationState::Expired,
            CrossCityOperationState::Quarantined,
        ] {
            let parent = parent_record(terminal, Some(&digest_hex(0x05)));
            assert!(ensure_parent_operation_live(&parent, NOW).is_err());
        }
        // An expired parent refuses city work even in a live state.
        let parent = parent_record(CrossCityOperationState::Agreed, Some(&digest_hex(0x05)));
        assert!(ensure_parent_operation_live(&parent, EXPIRES_AT).is_err());
        assert!(ensure_parent_operation_live(&parent, EXPIRES_AT + 1).is_err());
        // A live, non-terminal parent passes.
        assert!(ensure_parent_operation_live(&parent, NOW).is_ok());
    }

    #[test]
    fn expired_recovery_matrix_is_fail_closed() {
        use CrossCityOperationState as S;
        let all = CROSS_CITY_OPERATION_STATES;
        for current in all {
            for target in all {
                // Before the exclusive bound the expiry guard admits every
                // target; the closed state machine still applies independently.
                assert!(
                    ensure_transition_within_expiry(current, target, EXPIRES_AT, NOW).is_ok(),
                    "unexpired {} -> {} must pass the expiry guard",
                    current.as_str(),
                    target.as_str()
                );
                // Past the bound: ordinary pre-commit states may only collapse
                // to EXPIRED; commit-unknown states keep their fail-closed
                // recovery edges (IN_DOUBT/QUARANTINED) plus the proof-gated
                // ACTIVE path. Nothing else — an unknown commit outcome is
                // never auto-discarded (EXPIRED is not even a legal successor
                // of ACTIVATING/IN_DOUBT).
                let helper_admits = match current {
                    S::Activating | S::InDoubt => {
                        matches!(target, S::InDoubt | S::Quarantined | S::Active)
                    }
                    _ => target == S::Expired,
                };
                assert_eq!(
                    ensure_transition_within_expiry(current, target, EXPIRES_AT, EXPIRES_AT)
                        .is_ok(),
                    helper_admits,
                    "expired {} -> {} admission drifted",
                    current.as_str(),
                    target.as_str()
                );
                // Combined gate: past expiry a move is reachable only when the
                // helper AND the state machine both admit it (ACTIVE from a
                // commit-unknown state additionally requires the full durable
                // activation-proof verification at the caller; ordinary
                // pre-commit states keep only their EXPIRED cleanup edge).
                let machine_admits = current.can_transition_to(target);
                if helper_admits && machine_admits {
                    assert!(matches!(
                        (current, target),
                        (S::Activating, S::InDoubt)
                            | (S::Activating, S::Quarantined)
                            | (S::Activating, S::Active)
                            | (S::InDoubt, S::Quarantined)
                            | (S::InDoubt, S::Active)
                            | (S::Proposed, S::Expired)
                            | (S::Voting, S::Expired)
                            | (S::Deferred, S::Expired)
                            | (S::Agreed, S::Expired)
                            | (S::Preparing, S::Expired)
                            | (S::Prepared, S::Expired)
                    ));
                }
            }
        }
        // Explicit pins.
        // Expired ordinary pre-commit states: EXPIRED only.
        assert!(
            ensure_transition_within_expiry(S::Agreed, S::Expired, EXPIRES_AT, EXPIRES_AT).is_ok()
        );
        assert!(
            ensure_transition_within_expiry(S::Agreed, S::Preparing, EXPIRES_AT, EXPIRES_AT)
                .is_err()
        );
        // Expired IN_DOUBT can never be discarded as REJECTED: the state
        // machine no longer offers the edge at all, and the expiry guard
        // refuses it regardless.
        assert!(
            ensure_transition_within_expiry(S::InDoubt, S::Rejected, EXPIRES_AT, EXPIRES_AT)
                .is_err()
        );
        // Expired ACTIVATING keeps IN_DOUBT/QUARANTINED convergence plus the
        // proof-gated ACTIVE path; nothing else (no auto-EXPIRED).
        assert!(
            ensure_transition_within_expiry(S::Activating, S::InDoubt, EXPIRES_AT, EXPIRES_AT)
                .is_ok()
        );
        assert!(ensure_transition_within_expiry(
            S::Activating,
            S::Quarantined,
            EXPIRES_AT,
            EXPIRES_AT
        )
        .is_ok());
        assert!(
            ensure_transition_within_expiry(S::Activating, S::Active, EXPIRES_AT, EXPIRES_AT)
                .is_ok()
        );
        assert!(
            ensure_transition_within_expiry(S::Activating, S::Expired, EXPIRES_AT, EXPIRES_AT)
                .is_err()
        );
    }

    #[test]
    fn city_phase_mirror_rule_is_exact() {
        // INSERT-time rule: the initial phase must mirror the parent exactly —
        // a city row can never be born ahead of or beside its parent.
        let parent = parent_record(CrossCityOperationState::Agreed, Some(&digest_hex(0x05)));
        assert!(verify_city_phase_mirrors_parent(&parent, CrossCityOperationState::Agreed).is_ok());
        // Leading or lagging initial phases are mirror mismatches.
        assert!(
            verify_city_phase_mirrors_parent(&parent, CrossCityOperationState::Voting).is_err()
        );
        assert!(
            verify_city_phase_mirrors_parent(&parent, CrossCityOperationState::Preparing).is_err()
        );
    }

    #[test]
    fn catchup_oracle_is_deterministic_and_fail_closed() {
        use CrossCityOperationState as S;
        // In sync: nothing to do.
        for state in CROSS_CITY_OPERATION_STATES {
            assert_eq!(next_catchup_hop(state, state).unwrap(), None);
        }
        // Single-hop lag: the unique next hop is the parent's state itself…
        assert_eq!(
            next_catchup_hop(S::Voting, S::Agreed).unwrap(),
            Some(S::Agreed)
        );
        assert_eq!(
            next_catchup_hop(S::Prepared, S::InDoubt).unwrap(),
            Some(S::InDoubt)
        );
        assert_eq!(
            next_catchup_hop(S::Activating, S::Quarantined).unwrap(),
            Some(S::Quarantined)
        );
        // …and there is NO bypass while catching up to an AGREED parent: the
        // required next hop is AGREED itself (asserted above), so a DEFERRED
        // target — a legal edge from VOTING, but not the required next hop —
        // is refused by transition_city_state_in_tx's target comparison. When
        // the parent itself legitimately sits in DEFERRED, the required hop
        // IS DEFERRED.
        assert_eq!(
            next_catchup_hop(S::Voting, S::Deferred).unwrap(),
            Some(S::Deferred)
        );
        // Multi-phase lag is caught up one shortest-path hop at a time:
        // Proposed -> Voting -> Agreed -> Preparing.
        assert_eq!(
            next_catchup_hop(S::Proposed, S::Preparing).unwrap(),
            Some(S::Voting)
        );
        assert_eq!(
            next_catchup_hop(S::Voting, S::Preparing).unwrap(),
            Some(S::Agreed)
        );
        assert_eq!(
            next_catchup_hop(S::Agreed, S::Preparing).unwrap(),
            Some(S::Preparing)
        );
        // Leading rows (parent behind the child) and divergent rows (no legal
        // path to the parent) fail closed.
        assert!(next_catchup_hop(S::Preparing, S::Agreed).is_err());
        assert!(next_catchup_hop(S::Prepared, S::Voting).is_err());
        assert!(next_catchup_hop(S::Active, S::Proposed).is_err());
        assert!(next_catchup_hop(S::InDoubt, S::Expired).is_err());
        // Ambiguous shortest paths (two legal branches of equal length) fail
        // closed: PREPARED reaches ACTIVE/QUARANTINED through either
        // ACTIVATING or IN_DOUBT, and no worker may pick a branch alone.
        assert!(next_catchup_hop(S::Prepared, S::Active).is_err());
        assert!(next_catchup_hop(S::Prepared, S::Quarantined).is_err());
    }

    #[test]
    fn city_phase_catchable_allows_sync_and_lagging_only() {
        // heartbeat/release rule: the row may be in sync with its parent OR
        // deterministically catchable to it (a lease that lapsed across a
        // parent advance may be re-held); leading/divergent/ambiguous rows
        // are refused.
        let parent = parent_record(CrossCityOperationState::Agreed, Some(&digest_hex(0x05)));
        assert!(verify_city_phase_catchable(&parent, CrossCityOperationState::Agreed).is_ok());
        // Deterministically catchable lag.
        assert!(verify_city_phase_catchable(&parent, CrossCityOperationState::Voting).is_ok());
        assert!(verify_city_phase_catchable(&parent, CrossCityOperationState::Proposed).is_ok());
        // Leading row.
        assert!(verify_city_phase_catchable(&parent, CrossCityOperationState::Preparing).is_err());
        // Ambiguous catch-up from PREPARED toward ACTIVE (parent advanced
        // through PREPARING→IN_DOUBT→ACTIVE…): ambiguous rows fail closed
        // wherever they appear.
        let active_parent = parent_record(CrossCityOperationState::Active, Some(&digest_hex(0x05)));
        assert!(
            verify_city_phase_catchable(&active_parent, CrossCityOperationState::Prepared).is_err()
        );
    }

    #[test]
    fn operation_activation_proof_binds_record_and_debug_redacts() {
        let agreement = digest_hex(0x0a);
        let commit = digest_hex(0x0b);
        let record = parent_record(CrossCityOperationState::Activating, Some(&agreement));

        // Malformed mint inputs can never produce a proof.
        assert!(CrossCityOperationActivationProof::new(
            "not-a-uuid".to_owned(),
            agreement.clone(),
            5,
            1,
            commit.clone(),
        )
        .is_err());
        assert!(CrossCityOperationActivationProof::new(
            OPERATION_ID.to_owned(),
            "nothex".to_owned(),
            5,
            1,
            commit.clone(),
        )
        .is_err());
        assert!(CrossCityOperationActivationProof::new(
            OPERATION_ID.to_owned(),
            agreement.clone(),
            5,
            1,
            "nothex".to_owned(),
        )
        .is_err());
        assert!(CrossCityOperationActivationProof::new(
            OPERATION_ID.to_owned(),
            agreement.clone(),
            0,
            0,
            commit.clone(),
        )
        .is_err());
        assert!(CrossCityOperationActivationProof::new(
            OPERATION_ID.to_owned(),
            agreement.clone(),
            5,
            6,
            commit.clone(),
        )
        .is_err());

        let proof = CrossCityOperationActivationProof::new(
            OPERATION_ID.to_owned(),
            agreement.clone(),
            5,
            1,
            commit.clone(),
        )
        .unwrap();
        // Fully bound proof passes against the locked record…
        assert!(verify_operation_activation_binding(&record, &proof).is_ok());
        // …and every mismatched pin is refused.
        let foreign = CrossCityOperationActivationProof::new(
            OPERATION_ID_ALT.to_owned(),
            agreement.clone(),
            5,
            1,
            commit.clone(),
        )
        .unwrap();
        assert!(verify_operation_activation_binding(&record, &foreign).is_err());
        let other_agreement = CrossCityOperationActivationProof::new(
            OPERATION_ID.to_owned(),
            digest_hex(0x0c),
            5,
            1,
            commit.clone(),
        )
        .unwrap();
        assert!(verify_operation_activation_binding(&record, &other_agreement).is_err());
        let other_generation = CrossCityOperationActivationProof::new(
            OPERATION_ID.to_owned(),
            agreement.clone(),
            6,
            1,
            commit.clone(),
        )
        .unwrap();
        assert!(verify_operation_activation_binding(&record, &other_generation).is_err());
        let other_fence = CrossCityOperationActivationProof::new(
            OPERATION_ID.to_owned(),
            agreement.clone(),
            5,
            2,
            commit.clone(),
        )
        .unwrap();
        assert!(verify_operation_activation_binding(&record, &other_fence).is_err());

        // Debug never leaks the capability's digest fields.
        let debug = format!("{proof:?}");
        assert!(debug.contains("CrossCityOperationActivationProof"));
        assert!(!debug.contains(&agreement));
        assert!(!debug.contains(&commit));
    }

    // ── SQL shape (placeholders, locking, no upsert, table boundary) ───────

    /// The complete statement registry: every production SQL statement as a
    /// (constant NAME, statement value) pair. The name is written once here
    /// and the value is referenced as the real constant, so name and value can
    /// never drift apart; the source-shape guard below proves the production
    /// `sqlx::query*` call sites match this registry exactly.
    const ALL_STATEMENTS: [(&str, &str); 20] = [
        ("OPERATION_INSERT_SQL", OPERATION_INSERT_SQL),
        (
            "OPERATION_SELECT_FOR_UPDATE_SQL",
            OPERATION_SELECT_FOR_UPDATE_SQL,
        ),
        ("OPERATION_TRANSITION_SQL", OPERATION_TRANSITION_SQL),
        (
            "OPERATION_TRANSITION_AGREED_SQL",
            OPERATION_TRANSITION_AGREED_SQL,
        ),
        ("OPERATION_FAILURE_SQL", OPERATION_FAILURE_SQL),
        ("OPERATION_TAKEOVER_SQL", OPERATION_TAKEOVER_SQL),
        (
            "OPERATION_TAKEOVER_REVOKE_LEASES_SQL",
            OPERATION_TAKEOVER_REVOKE_LEASES_SQL,
        ),
        ("VOTE_INSERT_SQL", VOTE_INSERT_SQL),
        (
            "VOTE_SELECT_FOR_OPERATION_SQL",
            VOTE_SELECT_FOR_OPERATION_SQL,
        ),
        ("CITY_STATE_INSERT_SQL", CITY_STATE_INSERT_SQL),
        (
            "CITY_STATE_CLAIM_CANDIDATE_SQL",
            CITY_STATE_CLAIM_CANDIDATE_SQL,
        ),
        ("CITY_STATE_CLAIM_INSTALL_SQL", CITY_STATE_CLAIM_INSTALL_SQL),
        (
            "CITY_STATE_CLAIM_READBACK_SQL",
            CITY_STATE_CLAIM_READBACK_SQL,
        ),
        ("CITY_STATE_LOCK_SQL", CITY_STATE_LOCK_SQL),
        ("CITY_STATE_TRANSITION_SQL", CITY_STATE_TRANSITION_SQL),
        ("CITY_STATE_HEARTBEAT_SQL", CITY_STATE_HEARTBEAT_SQL),
        ("CITY_STATE_RELEASE_SQL", CITY_STATE_RELEASE_SQL),
        ("GATE_INSERT_SQL", GATE_INSERT_SQL),
        ("GATE_SELECT_FOR_UPDATE_SQL", GATE_SELECT_FOR_UPDATE_SQL),
        ("GATE_TRANSITION_SQL", GATE_TRANSITION_SQL),
    ];

    fn placeholder_count(statement: &str) -> usize {
        statement.bytes().filter(|byte| *byte == b'?').count()
    }

    // ── source-shape guards (pure: scan this file's own source) ────────────

    fn full_source() -> &'static str {
        include_str!("cross_city_repository.rs")
    }

    /// The PRODUCTION slice of this file: everything before the test-module
    /// marker. Scanning only this slice means needle literals written inside
    /// these tests can never match this file's own test code. The marker is
    /// assembled from concatenated fragments so this helper's own source can
    /// never contain — or miscount — the real marker itself.
    fn production_source() -> &'static str {
        const TEST_MODULE_MARKER: &str = concat!("#[", "cfg(test)]");
        let source = full_source();
        assert_eq!(
            source.matches(TEST_MODULE_MARKER).count(),
            1,
            "test-module marker drifted; production slice is ambiguous"
        );
        source
            .split_once(TEST_MODULE_MARKER)
            .map(|(production, _)| production)
            .expect("test-module marker present")
    }

    /// The body of one named production function: from its signature line to
    /// the first closing brace at column zero (all inner braces are indented).
    fn production_function_body(signature_needle: &str) -> &'static str {
        let production = production_source();
        let start = production
            .find(signature_needle)
            .unwrap_or_else(|| panic!("production function missing: {signature_needle}"));
        let end = production[start..]
            .find("\n}")
            .map(|position| start + position)
            .unwrap_or_else(|| panic!("function body unterminated: {signature_needle}"));
        &production[start..end]
    }

    #[test]
    fn every_sqlx_call_uses_the_registered_statement_constants() {
        let production = production_source();
        // Non-registry SQL paths are banned outright: no raw strings, no
        // scalar shortcuts, no compile-time macros — every statement must be
        // one of the fixed, reviewed constants (scanning the production slice
        // only, so these needles can never match this test's own text).
        for forbidden_path in [
            "sqlx::raw_sql",
            "raw_sql(",
            "query_scalar",
            "query_unchecked",
            "query_as_unchecked",
            "query!(",
            "query_as!(",
        ] {
            assert!(
                !production.contains(forbidden_path),
                "non-registry SQL path present: {forbidden_path}"
            );
        }
        let needle = "sqlx::query";
        let mut call_sites: Vec<&str> = Vec::new();
        let mut rest = production;
        while let Some(position) = rest.find(needle) {
            let after = &rest[position + needle.len()..];
            let after = if let Some(rest) = after.strip_prefix("_as(") {
                rest
            } else if let Some(rest) = after.strip_prefix('(') {
                rest
            } else {
                panic!("unexpected sqlx::query call form: {after:?}");
            };
            let name_end = after
                .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
                .expect("statement constant name not terminated");
            call_sites.push(&after[..name_end]);
            rest = after;
        }
        // Every production call must reference a registered constant — no
        // inline SQL and no unregistered statement can execute.
        for name in &call_sites {
            assert!(
                ALL_STATEMENTS
                    .iter()
                    .any(|(registered, _)| registered == name),
                "inline or unregistered SQL statement: {name}"
            );
        }
        // …and the registry must cover the calls exactly: no missed
        // registration and no unused registration.
        assert_eq!(
            call_sites.len(),
            ALL_STATEMENTS.len(),
            "production sqlx::query* call count drifted from the registry"
        );
        let mut used: Vec<&str> = call_sites.clone();
        used.sort_unstable();
        let mut registered: Vec<&str> = ALL_STATEMENTS.iter().map(|(name, _)| *name).collect();
        registered.sort_unstable();
        assert_eq!(used, registered, "registry and call sites drifted apart");
    }

    #[test]
    fn transition_city_state_locks_parent_first_and_targets_next_catchup_hop() {
        let body = production_function_body("pub async fn transition_city_state_in_tx");
        let parent_lock = body
            .find("load_operation_for_update_in_tx")
            .expect("parent operation lock missing");
        let row_lock = body
            .find("lock_city_state_row")
            .expect("city-state row lock missing");
        let oracle = body
            .find("next_catchup_hop(current, parent.state)")
            .expect("catch-up oracle missing");
        let target_check = body
            .find("target_phase != next")
            .expect("next-hop target comparison missing");
        let machine_edge = body
            .find("current.transition(target_phase)")
            .expect("state-machine edge check missing");
        // Fixed lock order operation -> city_state; the target must equal the
        // oracle's unique next hop AND remain a legal state-machine edge
        // (so e.g. VOTING can catch up to AGREED but can never bypass to
        // DEFERRED).
        assert!(parent_lock < row_lock && row_lock < oracle && oracle < target_check);
        assert!(machine_edge > target_check);
    }

    #[test]
    fn claim_city_state_proves_catchup_without_phase_filter() {
        let body = production_function_body("pub async fn claim_city_state_in_tx");
        // The claim candidate is phase-free (the over-tight phase == expected
        // filter is gone), the row's ACTUAL phase is parsed, and catchability
        // against the locked parent is proven BEFORE the lease installs.
        assert!(
            !body.contains("expected_phase"),
            "claim must not filter by an expected phase"
        );
        let parent_lock = body
            .find("load_operation_for_update_in_tx")
            .expect("parent operation lock missing");
        let oracle = body
            .find("next_catchup_hop(actual_phase, parent.state)")
            .expect("claim-time catch-up proof missing");
        let install = body
            .find("sqlx::query(CITY_STATE_CLAIM_INSTALL_SQL)")
            .expect("lease install missing");
        assert!(parent_lock < oracle && oracle < install);
        // The grant carries the row's ACTUAL phase.
        assert!(body.contains("phase: actual_phase"));
    }

    #[test]
    fn insert_vote_enforces_city_capacity_before_insert() {
        let body = production_function_body("pub async fn insert_vote_in_tx");
        let votes = body
            .find("load_bound_votes_in_tx(tx, &operation)")
            .expect("durable vote load missing (parent must not be re-locked)");
        let capacity = body
            .find("validate_vote_city_capacity(existing_city_count)")
            .expect("per-city capacity check missing");
        let insert = body
            .find("sqlx::query(VOTE_INSERT_SQL)")
            .expect("vote insert missing");
        // The cap is taken from the durable rows strictly before the INSERT.
        assert!(votes < capacity && capacity < insert);
    }

    #[test]
    fn insert_gate_admission_and_version_binding_are_shape_pinned() {
        let body = production_function_body("pub async fn insert_gate_in_tx");
        let parent_lock = body
            .find("load_operation_for_update_in_tx")
            .expect("parent operation lock missing");
        let version_binding = body
            .find("validate_gate_parent_version_binding(")
            .expect("parent target-version binding missing");
        let admission = body
            .find("ensure_gate_parent_insertable(&parent, now_seconds)")
            .expect("parent admission guard missing");
        assert!(parent_lock < version_binding && version_binding < admission);
        // The pure admission helper branches on the locked parent state:
        // ACTIVE is admitted (recovery, expiry-tolerant), terminal
        // non-commit states are refused, pre-terminal states enforce expiry.
        let helper = production_function_body("fn ensure_gate_parent_insertable");
        assert!(helper.contains("parent.state"));
        assert!(helper.contains("S::Active => Ok(())"));
        assert!(helper.contains("S::Rejected | S::Expired | S::Quarantined"));
        assert!(helper.contains("ensure_not_expired"));
    }

    #[test]
    fn transition_operation_takes_a_named_request() {
        // The over-long positional transition API is gone: the production
        // slice carries exactly the named-request form.
        let production = production_source();
        assert!(production.contains("pub struct CrossCityOperationTransitionRequest"));
        assert!(production.contains("pub async fn transition_operation_in_tx("));
        let body = production_function_body("pub async fn transition_operation_in_tx");
        assert!(body.contains("request: &CrossCityOperationTransitionRequest"));
        assert!(body.contains("now_seconds"));
        assert!(!body.contains("expected_state: CrossCityOperationState,"));
        // The stale diagnostics carry the same codes as before.
        assert!(body.contains("stale_operation_state"));
        assert!(body.contains("stale_coordinator_epoch"));
    }

    #[test]
    fn takeover_locks_parent_and_cas_matches_state_and_old_epoch() {
        let body = production_function_body("pub async fn take_over_operation_in_tx");
        let validation = body
            .find("validate_takeover_request(request)")
            .expect("pure request validation missing");
        let parent_lock = body
            .find("load_operation_for_update_in_tx")
            .expect("parent operation lock missing");
        let state_check = body.find("record.state != request.expected_state");
        let epoch_check = body.find("record.coordinator_epoch != request.current_epoch");
        let cas = body
            .find("sqlx::query(OPERATION_TAKEOVER_SQL)")
            .expect("takeover CAS missing");
        let revoke = body
            .find("sqlx::query(OPERATION_TAKEOVER_REVOKE_LEASES_SQL)")
            .expect("lease revocation missing");
        assert!(validation < parent_lock && parent_lock < cas);
        assert!(state_check.is_some() && epoch_check.is_some());
        // Fixed order inside the same transaction: the epoch CAS strictly
        // precedes the city-lease revocation, and the revoke clears ONLY
        // lease material (no phase/digest rewrite).
        assert!(cas < revoke);
        assert!(body.contains("revoked_city_leases"));
        assert!(body.contains("CrossCityOperationTakeoverOutcome"));
        // Terminal rows are re-checked on the locked record.
        assert!(body.contains("record.state.is_terminal()"));
        // The revoke SQL is bound by operation id alone and clears only the
        // three lease-material columns.
        let revoke_sql = ALL_STATEMENTS
            .iter()
            .find(|(name, _)| *name == "OPERATION_TAKEOVER_REVOKE_LEASES_SQL")
            .map(|(_, statement)| *statement)
            .expect("revoke statement registered");
        assert!(revoke_sql.contains("WHERE operation_id = ?"));
        assert!(revoke_sql
            .contains("SET lease_owner = NULL, lease_token_hash = NULL, lease_expires_at = NULL"));
        assert!(!revoke_sql.contains("phase ="));
    }

    #[test]
    fn activation_proofs_are_module_private_and_never_minted_in_production() {
        let production = production_source();
        let source = full_source();
        // No production code path mints either proof: the constructors are
        // `fn new` definitions, and a mint would have to appear as a
        // `...ActivationProof::new(` call, of which the production slice has
        // none.
        assert_eq!(
            production.matches("ActivationProof::new(").count(),
            0,
            "production code must never mint an activation proof"
        );
        // The constructors are module-private (no pub/pub(crate) mint entry
        // point), so nothing outside this file can mint either proof.
        assert!(
            !production.contains("pub(crate) fn new")
                && !production.contains("pub fn new")
                && !production.contains("pub async fn new"),
            "activation proof constructors must stay module-private"
        );
        // Exactly the two guarded constructors exist.
        assert_eq!(
            production.matches("fn new(").count(),
            2,
            "activation proof constructor set drifted"
        );
        // Struct-literal blind spot: the proof structs have private fields, so
        // the ONLY legitimate occurrences of `<Type> {` in production are the
        // struct definition and the two impl headers. Any additional
        // occurrence would be a value literal bypassing the guarded
        // constructors.
        for type_name in [
            "CrossCityOperationActivationProof",
            "CrossCityGateActivationProof",
        ] {
            let needle = format!("{type_name} {{");
            let definition_forms = [
                format!("pub struct {type_name} {{"),
                format!("impl fmt::Debug for {type_name} {{"),
                format!("impl {type_name} {{"),
            ];
            let total = production.matches(needle.as_str()).count();
            let declared = definition_forms
                .iter()
                .filter(|form| production.contains(form.as_str()))
                .count();
            assert_eq!(
                total, declared,
                "unexpected struct literal (or drifted definition) for {type_name}"
            );
        }
        // …and the pure test harness below can still construct proofs.
        assert!(
            source.matches("ActivationProof::new(").count() > 0,
            "test harness must retain proof-construction capability"
        );
    }

    #[test]
    fn statements_bind_exactly_the_expected_parameter_counts() {
        let expected: [(&str, usize); 20] = [
            (OPERATION_INSERT_SQL, 16),
            (OPERATION_SELECT_FOR_UPDATE_SQL, 1),
            (OPERATION_TRANSITION_SQL, 4),
            (OPERATION_TRANSITION_AGREED_SQL, 5),
            (OPERATION_FAILURE_SQL, 4),
            (OPERATION_TAKEOVER_SQL, 4),
            (OPERATION_TAKEOVER_REVOKE_LEASES_SQL, 1),
            (VOTE_INSERT_SQL, 12),
            (VOTE_SELECT_FOR_OPERATION_SQL, 1),
            (CITY_STATE_INSERT_SQL, 4),
            (CITY_STATE_CLAIM_CANDIDATE_SQL, 2),
            (CITY_STATE_CLAIM_INSTALL_SQL, 5),
            (CITY_STATE_CLAIM_READBACK_SQL, 1),
            (CITY_STATE_LOCK_SQL, 1),
            (CITY_STATE_TRANSITION_SQL, 5),
            (CITY_STATE_HEARTBEAT_SQL, 4),
            (CITY_STATE_RELEASE_SQL, 3),
            (GATE_INSERT_SQL, 9),
            (GATE_SELECT_FOR_UPDATE_SQL, 3),
            (GATE_TRANSITION_SQL, 9),
        ];
        for (statement, count) in expected {
            assert_eq!(
                placeholder_count(statement),
                count,
                "placeholder drift in: {statement}"
            );
        }
        assert_eq!(ALL_STATEMENTS.len(), expected.len());
    }

    #[test]
    fn locking_selects_declare_for_update_and_nothing_else_locks() {
        let locking = [
            OPERATION_SELECT_FOR_UPDATE_SQL,
            VOTE_SELECT_FOR_OPERATION_SQL,
            CITY_STATE_CLAIM_CANDIDATE_SQL,
            CITY_STATE_LOCK_SQL,
            GATE_SELECT_FOR_UPDATE_SQL,
        ];
        for statement in locking {
            assert!(statement.contains("FOR UPDATE"));
        }
        let total: usize = ALL_STATEMENTS
            .iter()
            .map(|(_, statement)| *statement)
            .filter(|statement| statement.contains("FOR UPDATE"))
            .count();
        assert_eq!(total, locking.len());
    }

    #[test]
    fn statements_never_use_upsert_forms() {
        for statement in ALL_STATEMENTS.iter().map(|(_, statement)| *statement) {
            assert!(!statement.contains("ON DUPLICATE"));
            assert!(!statement.contains("REPLACE INTO"));
            assert!(!statement.contains("INSERT IGNORE"));
        }
    }

    #[test]
    fn module_source_touches_only_the_four_cross_city_tables() {
        let source = full_source();
        let production = production_source();
        for owned in [
            "authorization_cross_city_operation",
            "authorization_cross_city_vote",
            "authorization_cross_city_city_state",
            "authorization_cross_city_gate",
        ] {
            assert!(source.contains(owned), "owned table missing: {owned}");
        }
        // Tables owned by OTHER modules must never be referenced anywhere in
        // the production slice (SQL or prose). Only the PRODUCTION slice is
        // scanned, so the needle literals below — written inside this test
        // module — can never match this file's own test code. Bare-name
        // matching is deliberately stronger than SQL-marker matching: even a
        // prose mention or a composite name containing these fragments fails
        // the boundary.
        let forbidden = [
            // Later-slice work-item tables of the same migration.
            "authorization_cross_city_outbox",
            "authorization_cross_city_inbox",
            // Legacy delta/revision/impact owners.
            "authorization_delta_event",
            "authorization_grant_revision",
            "authorization_impact_plan",
            "authorization_impact_plan_item",
            // Projection snapshot/head/segment/manifest owners.
            "authorization_projection_head",
            "authorization_projection_manifest",
            "authorization_projection_segment",
            "authorization_projection_current",
            "authorization_projection_outbox",
            // Archive owners.
            "authorization_archive_manifest",
            "authorization_archive_outbox",
            // Core authorization source/projection owners.
            "permission_rule",
            "rule_set",
            "identity_card",
            "user_card",
            "cross_org_grant",
            "permission_request",
        ];
        for needle in forbidden {
            assert!(
                !production.contains(needle),
                "forbidden table referenced: {needle}"
            );
        }
    }
}
