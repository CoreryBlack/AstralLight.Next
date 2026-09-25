//! Cross-city durable transport repository primitives (second slice: outbox +
//! inbox work items).
//!
//! This module is the pure database boundary for the default-off cross-city
//! transport subsystem described by [`astral_types`] cross-city contracts. It
//! owns EXACTLY two tables created by migration
//! `20260831000002_cross_city_schema.sql`:
//!
//! - `authorization_cross_city_outbox`: one durable outbound work item per
//!   message id, carrying the raw payload bytes, a delivery status, an attempt
//!   budget, a `next_attempt_at` backoff schedule, and a claim lease.
//! - `authorization_cross_city_inbox`: one durable inbound work item per
//!   message id (idempotent receive; NO payload and NO destination column).
//!
//! The four operation/vote/city-state/gate tables of the same migration are
//! owned by [`crate::cross_city_repository`] and are never referenced here;
//! legacy source/projection tables stay under their existing owners. A
//! source-anchored test pins this boundary. There are no foreign keys between
//! the transport tables and the operation root: parent operation liveness is
//! deliberately NOT checked here (no cross-table access); admission of a
//! message into an operation's flow is owned by the future transport layer.
//!
//! # Execution boundary (default-off subsystem)
//!
//! Nothing in this module is wired into any writer, MQ client, HTTP handler,
//! coordinator, or Redis path, and nothing here produces an authorization
//! decision. Recording or delivering a message is NOT an ALLOW: transport
//! success never implies authorization, and the only authorization entry point
//! remains `PolicyEngine.evaluate()`. Every function below is an explicit
//! primitive for a FUTURE transport layer; there is no runtime caller today.
//! No network, Redis, MQ, retry loop, or sleep runs inside these transactions;
//! callers own commit/rollback and every post-commit effect.
//!
//! # Durable-before-ACK boundary (the core contract of this slice)
//!
//! - Every `record`/`claim`/`mark`/`reconcile`/`requeue` primitive executes
//!   inside the CALLER's `Transaction`;
//!   the caller's COMMIT is the only durable point. Nothing in this module
//!   commits, and nothing here is durable before that commit.
//! - No MQ, Redis, or cache acknowledgement is consulted anywhere in this
//!   module. An ACK is NOT a durable success proof and must never be
//!   presented as one: the only worker path into
//!   [`CrossCityDeliveryStatus::Succeeded`] is
//!   [`mark_outbox_succeeded_in_tx`] / [`mark_inbox_processed_in_tx`] backed
//!   by the caller's own durable/confirmed delivery evidence.
//! - A publish/process outcome that is UNKNOWN (timeout, stream disconnect,
//!   lost connection) can ONLY enter `IN_DOUBT`, via
//!   [`mark_outbox_publish_in_doubt_in_tx`] /
//!   [`mark_inbox_process_in_doubt_in_tx`]. No method creates a new operation
//!   or message id after an unknown outcome, and no unknown outcome can be
//!   recorded as `SUCCEEDED`.
//! - Only the reconcile primitives may resolve an `IN_DOUBT` row, and each
//!   target names an independently proven fact (not applied / applied /
//!   unresolvable) — never a guess or an in-place retry.
//! - Redis idempotency is not durable proof; nothing here reads or writes
//!   Redis, and no cache state can move a status.
//!
//! # Identity and digest binding
//!
//! - OUTBOX: `message_id` is DERIVED, never caller-supplied:
//!   `CrossCityMessageIdentity::new(operation_id, phase, source, destination)`
//!   produces the stable identity, and `payload_digest` is
//!   `astral_types::cross_city_payload_digest` over the EXACT payload bytes
//!   handed in. A duplicate insert (same `message_id`) with the same
//!   operation/phase/source/destination/payload-digest binding returns the
//!   idempotent existing record; ANY binding or digest difference is an
//!   immutable conflict — evidence and payload are never overwritten.
//! - INBOX: the schema has no payload and no destination column, so the
//!   stored fields cannot re-derive the id alone. The receiver therefore
//!   passes its OWN city id (the message's destination):
//!   [`record_inbox_in_tx`] re-derives the identity over
//!   `(operation, phase, source -> local city)` and rejects any wire
//!   `message_id` that does not equal the derivation (fail-closed tamper,
//!   swap, and misroute detection). The receiver also hands in the RAW
//!   received payload bytes and the repository computes the stored
//!   `payload_digest` over them itself — a caller-supplied digest string is
//!   never trusted (the payload itself is not stored, so the digest is the
//!   only content evidence the inbox keeps). A duplicate record compares
//!   operation/source/phase/payload-digest and never blindly updates.
//! - Direction integrity: source/destination are compared positionally, so a
//!   swapped route is a DIFFERENT message id (a different message), and any
//!   stored row whose `message_id` does not equal the derivation of its own
//!   stored tuple fails closed on read (poisoned row).
//! - Storage bounds: the identity contract admits identifiers beyond the
//!   schema's `VARCHAR(191)` city columns, so BOTH insert paths enforce the
//!   191-byte repository boundary themselves — anything the DB could truncate
//!   is refused before any SQL, never silently clipped.
//!
//! # Inbox retry/backoff semantics (there is NO `next_attempt_at` column)
//!
//! `lease_expires_at` doubles as the inbox's next-eligible-time fence. After a
//! KNOWN processing failure, [`fail_inbox_in_tx`] clears the lease identity
//! (owner/token) but deliberately RETAINS `lease_expires_at`, server-computed
//! as `UTC_TIMESTAMP() + backoff`. The claim predicate gates purely on
//! `lease_expires_at IS NULL OR lease_expires_at <= UTC_TIMESTAMP()`, so a
//! failed message cannot be re-claimed until its fence passes: no hot loop,
//! and no `next_attempt_at` column is invented. Requeue clears the fence so a
//! quarantined message becomes immediately eligible. A source-anchored test
//! pins both the inbox fence and the outbox's separate `next_attempt_at`
//! schedule.
//!
//! # Attempt budget and backoff
//!
//! `attempts` counts KNOWN failed attempts only. `fail_*` consumes exactly one
//! attempt and either schedules a retry (outbox: `next_attempt_at`; inbox: the
//! `lease_expires_at` fence) or — when [`MAX_CROSS_CITY_TRANSPORT_ATTEMPTS`]
//! is reached — quarantines the row (the worker never silently drops or
//! retries forever). `IN_DOUBT` does not consume budget: an unknown outcome is
//! never retried in place; reconciliation owns it. Operator requeue resets
//! `attempts` to 0 (a fresh budget is an explicit operator decision). Backoff
//! doubles from [`CROSS_CITY_TRANSPORT_BACKOFF_BASE_SECONDS`] and is capped at
//! [`CROSS_CITY_TRANSPORT_BACKOFF_MAX_SECONDS`] (see
//! [`transport_backoff_seconds`]); overflow and negative/zero attempts fail
//! closed.
//!
//! The bound is also a decode invariant: only a `QUARANTINED` row may sit AT
//! [`MAX_CROSS_CITY_TRANSPORT_ATTEMPTS`] — every writer reaches the bound only
//! through the exhausted-budget quarantine, so any other status at the bound
//! is poisoned storage and fails closed on read.
//! [`resolve_transport_budget`] refuses `current_attempts >= MAX` outright
//! (it never returns `MAX + 1`), and the claim candidate scans no longer
//! pre-filter on the attempt bound: an exhausted (`attempts == MAX`) or
//! out-of-range ACTIVE row SURFACES at the claim's fail-closed gate — or in
//! the full decode itself — instead of being silently skipped forever, while
//! the install CAS retains `attempts < MAX` (see the lease-free poison
//! quarantine section for the operator's onward path).
//!
//! # Lease-free poison quarantine (explicit operator path)
//!
//! A poisoned row (any row whose FULL decode fails) is untouchable by the
//! normal worker/reconcile/requeue paths: those paths require the relevant
//! decoded state and actor guard. One explicit, LEASE-FREE operator path
//! quarantines rows whose decode failure is independently observed. It is a
//! recovery boundary for poison, not a general worker transition.
//! It targets a row by its stable `message_id`, locks exactly that row, and
//! PROVES the poison by running the full record decode on the locked row:
//! only a decode FAILURE quarantines. A healthy row (any fully decodable
//! state, including an already-`QUARANTINED` or an expired-`LEASED` row) is
//! refused untouched, a terminal `SUCCEEDED` row is never rewritten (even
//! when poisoned), and a LIVE lease is never stolen — the UPDATE's WHERE
//! clause re-checks server-side, at write time, that no complete lease is
//! unexpired; losing that guard is an explicit refusal, never a partial
//! write. The update clears ONLY the mutable lease/schedule/status fields:
//! the immutable identity/payload/digest evidence, `attempts`, and the
//! received/created history are never rewritten. Whether the row can later be
//! requeued depends on which field was poisoned: a poison confined to mutable
//! state may become recoverable after quarantine, while poison in immutable
//! evidence remains an auditable dead-end for out-of-band repair. In neither
//! case can the operator path manufacture `SUCCEEDED` or resurrect payload
//! evidence. A bounded
//! `poison_quarantine;operator=…;ref=…;reason=…` marker is written into
//! `last_error` ONLY if the operator context and the reason are safe (no
//! control characters, CR/LF, NUL, ANSI escapes, invisible format/bidi
//! characters, or unsafe line separators, all within bounds); anything unsafe
//! fails the whole request closed and persists nothing.
//!
//! TRUST BOUNDARY: this repository cannot authenticate an operator — it has
//! no session, token, identity, or policy source of its own. The caller MUST
//! mint the [`CrossCityTransportOperatorAuthorization`] at an AUTHENTICATED
//! boundary (after proving who the operator is and that this administrative
//! action is authorized, e.g. via `PolicyEngine.evaluate()`); the repository
//! validates only the SHAPE of that context and binds it verbatim into the
//! durable forensic marker. Minting it from unauthenticated input is a
//! caller defect this module cannot detect.
//!
//! # Lease and token discipline
//!
//! Claims install a run-scoped [`CrossCityTransportLeaseToken`]; only its
//! SHA-256 hash is persisted, the plaintext never enters SQL, logs, error
//! messages, or `Debug`/`Display` output. Every lease-bound mutation CASes on
//! row identity + owner + token hash + server-side liveness
//! (`lease_expires_at > UTC_TIMESTAMP()`); expiry is computed server-side and
//! read back, so the client clock is never trusted.
//!
//! Expired-lease reclaim (worker crash recovery) is explicit, actor-specific,
//! and never bypasses the state machine: a claim admits ONLY a `PENDING` row
//! with its lease FULLY cleared (and the outbox schedule due), or a `LEASED`
//! row whose lease is complete AND expired server-side. The reclaim applies,
//! in order, the two legal worker edges `LEASED -> PENDING` then
//! `PENDING -> LEASED` (both through
//! [`CrossCityDeliveryStatus::transition_by_worker`]) before one atomic
//! install CAS — whose WHERE clause re-checks the EXACT candidate disjunction
//! under the row lock — flips the row to `LEASED` and installs the fresh
//! lease; a readback proves the flip. A LIVE lease can never reach the
//! reclaim (both predicates require `lease_expires_at <= UTC_TIMESTAMP()`),
//! and a row carrying PARTIAL lease material matches neither branch: it is
//! poison, refused on the locked row — never repaired by an overwrite.
//!
//! # Actor-specific status transitions
//!
//! Status movement strictly follows the [`CrossCityDeliveryStatus`] guarded
//! families — there is NO universal transition and no caller-supplied success
//! flag: the worker primitives use `transition_by_worker`, the reconcile
//! primitives use `transition_by_reconcile`, and the operator requeue uses
//! `transition_by_operator`. Unknown stored status strings fail closed via the
//! contract's strict parser; illegal transitions fail closed with typed
//! errors.
//!
//! # Failure policy
//!
//! Everything fails closed. Unknown stored statuses/phases, malformed or
//! mismatched digests, padded or oversized text, poisoned rows (lease material
//! inconsistent with the status, payload bytes disagreeing with
//! `payload_digest`, a `message_id` that is not the derivation of its own
//! tuple, a stale retry schedule on a row that left the worker cycle, a
//! non-quarantined row AT the attempt bound, an out-of-range attempt counter),
//! an exhausted or out-of-range ACTIVE row surfaced by the claim candidate
//! scan, a poison-quarantine request against a healthy, terminal, or
//! live-leased row, lost leases, duplicate records with changed bindings,
//! attempts overflow, and any `rows_affected() != 1` mutation surface as
//! explicit typed errors carrying a stable
//! `code=cross_city_transport_repository.*` identifier. Nothing
//! silently skips rows, repairs stored data, or upserts over immutable
//! evidence. No secret material (lease tokens, connection strings) ever enters
//! an error message.
//!
//! Concurrent duplicate INSERTs (KNOWN RESIDUAL, deliberately not hidden): two
//! sessions inserting the same `message_id` race on the unique key. The loser
//! re-reads the conflicting row `FOR UPDATE` inside its own transaction and
//! either proves exact-binding idempotency or fails as an immutable conflict;
//! if the winner rolls back, the re-read finds nothing and the loser fails
//! with an explicit conflict — idempotency is never fabricated. Under InnoDB,
//! that lock wait can also surface as a deadlock or lock-wait timeout
//! (`sqlx::Error`): this module NEVER retries, re-executes the INSERT, or
//! treats an unknown outcome as success — the caller owns re-running the WHOLE
//! transaction (fresh, bounded attempts), and only after observing that its
//! transaction rolled back.
//!
//! # Lock order (single MySQL session/transaction)
//!
//! Every primitive locks AT MOST ONE row — the message row of its own table —
//! via `SELECT ... FOR UPDATE` before mutating it. No primitive spans both
//! tables, and no parent table is ever locked, so no cross-table or reverse
//! parent lock order is even expressible. All statements are plain
//! bind-parameter SQL from a fixed statement registry; no client-side string
//! assembly, no query macros, no upsert forms (`INSERT IGNORE`, `REPLACE`,
//! `ON DUPLICATE KEY`) exist anywhere in this module.
//!
//! # Residual trust boundary
//!
//! The repository cannot itself prove external facts: the reconcile outcome is
//! an assertion by the future transport layer that the named fact was
//! independently proven (e.g. the destination city's own durable record); this
//! module records it durably and nothing more. Signature verification of
//! message content likewise stays outside this slice, exactly as in the first
//! cross-city slice.

use std::fmt;

use sha2::{Digest, Sha256};
use sqlx::{MySql, Transaction};
use time::PrimitiveDateTime;
use uuid::Uuid;

use astral_types::{
    cross_city_payload_digest, CrossCityDeliveryStatus, CrossCityMessageIdentity,
    CrossCityMessagePhase,
};

use crate::grant_repository::Sha256Digest;

// ─────────────────────────────────────────────────────────────────────────────
// Schema-mirrored bounds and policy constants
// ─────────────────────────────────────────────────────────────────────────────

/// Upper bound for one transport lease duration (and heartbeat extension) in
/// seconds.
pub const MAX_CROSS_CITY_TRANSPORT_LEASE_SECONDS: i64 = 3_600;
/// Hard attempt budget: on the attempt that reaches this bound the worker
/// quarantines instead of scheduling another retry.
pub const MAX_CROSS_CITY_TRANSPORT_ATTEMPTS: i64 = 8;
/// Payload size bound mirrored from the `MEDIUMBLOB` column (16 MiB - 1).
pub const MAX_CROSS_CITY_TRANSPORT_PAYLOAD_BYTES: usize = 16_777_215;
/// First (and doubling) retry backoff step in seconds.
pub const CROSS_CITY_TRANSPORT_BACKOFF_BASE_SECONDS: i64 = 30;
/// Backoff cap in seconds; every later retry waits at most this long.
pub const CROSS_CITY_TRANSPORT_BACKOFF_MAX_SECONDS: i64 = 3_600;
/// `message_id` width mirrored from the migration (`VARCHAR(128)`); the
/// canonical form is the 64-character hex identity digest.
pub const MAX_CROSS_CITY_TRANSPORT_MESSAGE_ID_LENGTH: usize = 128;
/// City identifier width mirrored from the migration (`VARCHAR(191)`).
pub const MAX_CROSS_CITY_TRANSPORT_CITY_LENGTH: usize = 191;
/// Lease owner width mirrored from the migration (`VARCHAR(128)`).
pub const MAX_CROSS_CITY_TRANSPORT_LEASE_OWNER_LENGTH: usize = 128;
/// Operator authorization-field bound for the lease-free poison quarantine
/// forensic marker (both the operator subject and the authorization
/// reference; the marker itself is bounded by
/// [`MAX_CROSS_CITY_TRANSPORT_LAST_ERROR_LENGTH`]).
pub const MAX_CROSS_CITY_TRANSPORT_OPERATOR_LENGTH: usize = 128;
/// Failure-text width mirrored from the migration (`VARCHAR(512)`).
pub const MAX_CROSS_CITY_TRANSPORT_LAST_ERROR_LENGTH: usize = 512;

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Transport repository errors. Every variant is fail-closed; none authorizes
/// anything. String variants embed a stable
/// `code=cross_city_transport_repository.*` identifier and never carry secrets
/// (lease tokens, connection material).
#[derive(Debug, thiserror::Error)]
pub enum CrossCityTransportRepositoryError {
    /// A cross-city contract rejected the input.
    #[error("cross-city contract validation failed: {0}")]
    Contract(#[from] astral_types::CrossCityContractError),

    /// Stored data violated its declared shape; refused instead of normalized.
    #[error("row mapping failed: {0}")]
    Mapping(String),

    /// A database driver error occurred.
    #[error("database query failed: {0}")]
    Query(#[from] sqlx::Error),

    /// A durable record already exists for the requested identity.
    #[error("durable record conflict: {0}")]
    Conflict(String),

    /// A requested row is absent.
    #[error("record not found: {0}")]
    NotFound(String),

    /// A lease-guarded mutation lost its lease (expired/stolen/absent).
    #[error("cross-city transport lease CAS failed: {0}")]
    LeaseCasFailed(String),

    /// An immutable durable record was asked to change retroactively.
    #[error("immutable record conflict: {0}")]
    ImmutableConflict(String),

    /// Request fields disagreed with each other or with the declared scope.
    #[error("scope violation: {0}")]
    ScopeViolation(String),

    /// A lease-free poison-quarantine request was REFUSED and the locked row
    /// left untouched: the row is not provably poisoned (its full decode
    /// succeeded), it is a terminal `SUCCEEDED` row, or the server-side
    /// live-lease guard held at write time. Never a silent success and never
    /// a partial write.
    #[error("poison quarantine refused: {0}")]
    PoisonQuarantineRefused(String),
}

fn mapping(code: &str) -> CrossCityTransportRepositoryError {
    CrossCityTransportRepositoryError::Mapping(format!(
        "code=cross_city_transport_repository.{code}"
    ))
}

fn scope_violation(code: &str) -> CrossCityTransportRepositoryError {
    CrossCityTransportRepositoryError::ScopeViolation(format!(
        "code=cross_city_transport_repository.{code}"
    ))
}

fn conflict(code: &str) -> CrossCityTransportRepositoryError {
    CrossCityTransportRepositoryError::Conflict(format!(
        "code=cross_city_transport_repository.{code}"
    ))
}

fn not_found(code: &str) -> CrossCityTransportRepositoryError {
    CrossCityTransportRepositoryError::NotFound(format!(
        "code=cross_city_transport_repository.{code}"
    ))
}

fn lease_cas(code: &str) -> CrossCityTransportRepositoryError {
    CrossCityTransportRepositoryError::LeaseCasFailed(format!(
        "code=cross_city_transport_repository.{code}"
    ))
}

fn immutable_conflict(code: &str) -> CrossCityTransportRepositoryError {
    CrossCityTransportRepositoryError::ImmutableConflict(format!(
        "code=cross_city_transport_repository.{code}"
    ))
}

fn poison_refused(code: &str) -> CrossCityTransportRepositoryError {
    CrossCityTransportRepositoryError::PoisonQuarantineRefused(format!(
        "code=cross_city_transport_repository.{code}"
    ))
}

fn db_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(|database| database.is_unique_violation())
}

// ─────────────────────────────────────────────────────────────────────────────
// Canonical SQL-boundary helpers
// ─────────────────────────────────────────────────────────────────────────────

fn digest_from_hex(value: &str) -> Result<Sha256Digest, CrossCityTransportRepositoryError> {
    Sha256Digest::from_hex(value).map_err(|_| mapping("invalid_sha256_hex"))
}

fn digest_from_bytes(bytes: Vec<u8>) -> Result<Sha256Digest, CrossCityTransportRepositoryError> {
    Sha256Digest::from_bytes(bytes).map_err(|_| mapping("invalid_binary32"))
}

fn digest_from_optional_bytes(
    value: Option<&[u8]>,
) -> Result<Option<Sha256Digest>, CrossCityTransportRepositoryError> {
    Sha256Digest::from_optional_bytes(value).map_err(|_| mapping("invalid_binary32"))
}

/// Strict canonical lowercase hyphenated UUID boundary (nil and every other
/// spelling is refused; poisoned storage is never repaired).
fn validated_operation_id(value: &str) -> Result<String, CrossCityTransportRepositoryError> {
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
) -> Result<(), CrossCityTransportRepositoryError> {
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

/// A `message_id` is always the domain-separated SHA-256 identity digest:
/// exactly 64 lowercase hex characters, never padded and never truncated.
fn validated_message_id_shape(value: &str) -> Result<(), CrossCityTransportRepositoryError> {
    digest_from_hex(value).map(|_| ())
}

/// Convert a UTC `DATETIME` column value back into UTC Unix seconds.
fn datetime_to_unix_seconds(value: PrimitiveDateTime) -> i64 {
    value.assume_utc().unix_timestamp()
}

/// Char-bounded last-error text (`VARCHAR(512)`); truncation is the ONLY
/// lenient transform in this module and applies solely to this forensic field.
fn truncate_transport_last_error(message: &str) -> String {
    message
        .chars()
        .take(MAX_CROSS_CITY_TRANSPORT_LAST_ERROR_LENGTH)
        .collect()
}

fn validate_transport_lease_material(
    lease_owner: &str,
    lease_seconds: i64,
) -> Result<(), CrossCityTransportRepositoryError> {
    validated_text(
        lease_owner,
        MAX_CROSS_CITY_TRANSPORT_LEASE_OWNER_LENGTH,
        "lease_owner",
    )?;
    if !(1..=MAX_CROSS_CITY_TRANSPORT_LEASE_SECONDS).contains(&lease_seconds) {
        return Err(scope_violation(&format!(
            "invalid_lease_seconds;value={lease_seconds};max={MAX_CROSS_CITY_TRANSPORT_LEASE_SECONDS}"
        )));
    }
    Ok(())
}

/// Decode-time attempt bound: negative values are poisoned storage, and no
/// non-quarantined status can legitimately exceed the budget.
fn validated_attempts(value: i64) -> Result<i64, CrossCityTransportRepositoryError> {
    if !(0..=MAX_CROSS_CITY_TRANSPORT_ATTEMPTS).contains(&value) {
        return Err(mapping("attempts_out_of_range"));
    }
    Ok(value)
}

/// Doubling retry backoff: `attempts` is the 1-based index of the attempt that
/// just failed (1 -> base, 2 -> 2x base, ...), capped at
/// [`CROSS_CITY_TRANSPORT_BACKOFF_MAX_SECONDS`]. Overflow and non-positive
/// attempts fail closed instead of wrapping.
pub fn transport_backoff_seconds(attempts: i64) -> Result<i64, CrossCityTransportRepositoryError> {
    if attempts < 1 {
        return Err(scope_violation(&format!(
            "backoff_requires_positive_attempts;value={attempts}"
        )));
    }
    let mut backoff = CROSS_CITY_TRANSPORT_BACKOFF_BASE_SECONDS;
    for _ in 1..attempts {
        backoff = match backoff.checked_mul(2) {
            Some(doubled) if doubled < CROSS_CITY_TRANSPORT_BACKOFF_MAX_SECONDS => doubled,
            _ => {
                return Ok(CROSS_CITY_TRANSPORT_BACKOFF_MAX_SECONDS);
            }
        };
    }
    Ok(backoff)
}

/// Pure budget decision for one KNOWN failure: the attempt that reaches the
/// hard budget is quarantined instead of retried (the worker never silently
/// drops a message, and never retries forever).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrossCityTransportBudgetOutcome {
    /// Budget remains: retry after the computed backoff.
    Retry {
        /// Attempt counter AFTER consuming this failure.
        new_attempts: i64,
        /// Server-side wait before the row becomes eligible again.
        backoff_seconds: i64,
    },
    /// Budget exhausted: the row must be quarantined (operator requeue or
    /// reconciliation are the only onward paths).
    Exhausted {
        /// Attempt counter AFTER consuming this failure.
        new_attempts: i64,
    },
}

/// Resolve the attempt budget for the attempt following `current_attempts`.
///
/// `current_attempts >= MAX` is an EXPLICIT error — an exhausted counter is
/// never reported as one more failure and `MAX + 1` is never returned or
/// written (a counter beyond the decodable bound would be poisoned storage).
/// Out-of-range and overflow inputs fail closed.
pub fn resolve_transport_budget(
    current_attempts: i64,
) -> Result<CrossCityTransportBudgetOutcome, CrossCityTransportRepositoryError> {
    let current = validated_attempts(current_attempts)?;
    if current >= MAX_CROSS_CITY_TRANSPORT_ATTEMPTS {
        return Err(mapping("attempts_budget_exhausted"));
    }
    let new_attempts = current
        .checked_add(1)
        .ok_or_else(|| mapping("attempts_overflow"))?;
    if new_attempts >= MAX_CROSS_CITY_TRANSPORT_ATTEMPTS {
        Ok(CrossCityTransportBudgetOutcome::Exhausted { new_attempts })
    } else {
        Ok(CrossCityTransportBudgetOutcome::Retry {
            new_attempts,
            backoff_seconds: transport_backoff_seconds(new_attempts)?,
        })
    }
}

/// Attempt counter written by an explicit quarantine mark: the previous value
/// must be a valid in-budget counter (a negative or over-budget value is
/// poisoned storage and fails closed — never silently written onward), and the
/// incremented value must stay within the decodable `0..=MAX` bound.
fn quarantined_attempt_budget(
    current_attempts: i64,
) -> Result<i64, CrossCityTransportRepositoryError> {
    let current = validated_attempts(current_attempts)?;
    if current >= MAX_CROSS_CITY_TRANSPORT_ATTEMPTS {
        return Err(mapping("attempts_budget_exhausted"));
    }
    current
        .checked_add(1)
        .ok_or_else(|| mapping("attempts_overflow"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Lease token (run-scoped; the DB stores only its SHA-256 hash)
// ─────────────────────────────────────────────────────────────────────────────

/// Run-scoped secret fencing one transport lease attempt.
///
/// Generated by the repository during a claim (a random UUID v4 string). Its
/// `Debug`/`Display` output is redacted; the database stores only the SHA-256
/// hash, so a leaked metadata dump cannot renew or finish someone else's
/// lease. The plaintext token lives only in the caller's memory for the lease
/// lifetime and never enters SQL, logs, or error messages.
#[derive(Clone, PartialEq, Eq)]
pub struct CrossCityTransportLeaseToken(String);

impl CrossCityTransportLeaseToken {
    fn new_run_scoped() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// SHA-256 over the plaintext token; the only form that ever reaches SQL.
    pub fn token_hash(&self) -> Sha256Digest {
        let bytes: [u8; 32] = Sha256::digest(self.0.as_bytes()).into();
        Sha256Digest::from_raw_bytes(bytes)
    }
}

impl fmt::Debug for CrossCityTransportLeaseToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CrossCityTransportLeaseToken(REDACTED)")
    }
}

impl fmt::Display for CrossCityTransportLeaseToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CrossCityTransportLeaseToken(REDACTED)")
    }
}

/// Owner + token proof every lease-bound transport mutation must present.
///
/// Shared by the outbox and the inbox: the proof pins the exact message row
/// (by its `message_id` primary key) and the lease identity; the lease token
/// itself is never bound into SQL — only its SHA-256 hash is. Presenting a
/// proof to the wrong table simply finds no row (`NotFound`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossCityTransportLeaseProof {
    pub message_id: String,
    pub lease_owner: String,
    pub lease_token: CrossCityTransportLeaseToken,
}

fn validate_transport_lease_proof(
    proof: &CrossCityTransportLeaseProof,
) -> Result<(), CrossCityTransportRepositoryError> {
    validated_message_id_shape(&proof.message_id)?;
    validated_text(
        &proof.lease_owner,
        MAX_CROSS_CITY_TRANSPORT_LEASE_OWNER_LENGTH,
        "lease_owner",
    )?;
    if proof.lease_token.as_str().trim().is_empty() {
        return Err(scope_violation("empty_lease_token"));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Identity decode and poison checks
// ─────────────────────────────────────────────────────────────────────────────

/// Rebuild and verify the stable message identity from stored/claimed fields.
///
/// The stored text must ALREADY be canonical (padded spellings are poisoned
/// rows, never normalized), and the stored `message_id` must equal the
/// derivation over the stored tuple — so any tampering with the id, an
/// operation/phase/city field, or a swapped source/destination direction fails
/// closed on read.
fn decode_transport_message_identity(
    operation_id: &str,
    phase: &str,
    source_city_id: &str,
    destination_city_id: &str,
    stored_message_id: &str,
) -> Result<CrossCityMessageIdentity, CrossCityTransportRepositoryError> {
    validated_operation_id(operation_id)?;
    validated_text(
        source_city_id,
        MAX_CROSS_CITY_TRANSPORT_CITY_LENGTH,
        "source_city_id",
    )?;
    validated_text(
        destination_city_id,
        MAX_CROSS_CITY_TRANSPORT_CITY_LENGTH,
        "destination_city_id",
    )?;
    validated_message_id_shape(stored_message_id)?;
    let identity = CrossCityMessageIdentity::new(
        operation_id,
        CrossCityMessagePhase::parse_str(phase)?,
        source_city_id,
        destination_city_id,
    )?;
    // Raw stored spellings must already be canonical: `new` normalizes, and a
    // difference here means poisoned storage (never silently repaired).
    if identity.operation_id != operation_id
        || identity.source_city_id != source_city_id
        || identity.destination_city_id != destination_city_id
    {
        return Err(mapping("poisoned_identity_text"));
    }
    if identity.message_id != stored_message_id {
        return Err(mapping("poisoned_message_id"));
    }
    Ok(identity)
}

/// Status/lease-material consistency of a stored row. Every writer path in
/// this module maintains these invariants, so a violation is poisoned storage
/// and fails closed on read:
///
/// - `LEASED`: owner + token hash + expiry must ALL be present.
/// - `PENDING`: owner and token hash must be absent; expiry must be absent for
///   the outbox, and may be present for the inbox (it is the deliberate
///   next-eligible-time backoff fence — see the module docs).
/// - `IN_DOUBT` / `SUCCEEDED` / `QUARANTINED`: all lease material absent.
fn validate_transport_status_lease_consistency(
    status: CrossCityDeliveryStatus,
    lease_owner_present: bool,
    lease_token_present: bool,
    lease_expiry_present: bool,
    is_inbox: bool,
) -> Result<(), CrossCityTransportRepositoryError> {
    let consistent = match status {
        CrossCityDeliveryStatus::Leased => {
            lease_owner_present && lease_token_present && lease_expiry_present
        }
        CrossCityDeliveryStatus::Pending => {
            !lease_owner_present && !lease_token_present && (is_inbox || !lease_expiry_present)
        }
        CrossCityDeliveryStatus::InDoubt
        | CrossCityDeliveryStatus::Succeeded
        | CrossCityDeliveryStatus::Quarantined => {
            !lease_owner_present && !lease_token_present && !lease_expiry_present
        }
    };
    if consistent {
        Ok(())
    } else {
        Err(mapping("poisoned_status_lease_consistency"))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public records, requests, outcomes, grants
// ─────────────────────────────────────────────────────────────────────────────

/// Strictly decoded durable outbox row. The `identity` was rebuilt from the
/// stored fields and verified against the stored `message_id`, and the stored
/// payload bytes hash to `payload_digest`.
#[derive(Clone, PartialEq, Eq)]
pub struct CrossCityOutboxRecord {
    pub message_id: String,
    pub identity: CrossCityMessageIdentity,
    pub payload_digest: String,
    pub payload: Vec<u8>,
    pub status: CrossCityDeliveryStatus,
    pub attempts: i64,
    /// Backoff schedule in UTC Unix seconds (`None` = immediately eligible).
    pub next_attempt_at_seconds: Option<i64>,
    pub lease_owner: Option<String>,
    pub lease_expires_at_seconds: Option<i64>,
    pub last_error: Option<String>,
}

impl fmt::Debug for CrossCityOutboxRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CrossCityOutboxRecord")
            .field("message_id", &self.message_id)
            .field("identity", &self.identity)
            .field("payload_digest", &self.payload_digest)
            .field("payload_len", &self.payload.len())
            .field("status", &self.status.as_str())
            .field("attempts", &self.attempts)
            .field("next_attempt_at_seconds", &self.next_attempt_at_seconds)
            .field("lease_owner", &self.lease_owner)
            .field("lease_expires_at_seconds", &self.lease_expires_at_seconds)
            .field("last_error", &self.last_error)
            .finish()
    }
}

/// Insert request for one outbound work item. `message_id` is DERIVED by the
/// repository from `(operation_id, phase, source_city_id, destination_city_id)`
/// and is never accepted from the caller.
#[derive(Clone, PartialEq, Eq)]
pub struct CrossCityOutboxInsert {
    pub operation_id: String,
    pub phase: CrossCityMessagePhase,
    pub source_city_id: String,
    pub destination_city_id: String,
    /// The exact wire bytes to publish; `payload_digest` is computed over
    /// these raw bytes (never over a re-serialization).
    pub payload: Vec<u8>,
}

impl fmt::Debug for CrossCityOutboxInsert {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CrossCityOutboxInsert")
            .field("operation_id", &self.operation_id)
            .field("phase", &self.phase.as_str())
            .field("source_city_id", &self.source_city_id)
            .field("destination_city_id", &self.destination_city_id)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

/// Outcome of [`insert_outbox_in_tx`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrossCityOutboxInsertOutcome {
    /// The message was recorded inside the caller's transaction; it becomes
    /// durable ONLY after the caller's COMMIT (never before).
    Created(Box<CrossCityOutboxRecord>),
    /// A record with the SAME message id and the SAME
    /// operation/phase/source/destination/payload-digest binding already
    /// exists: the insert is an idempotent replay and the durable record is
    /// returned unchanged (never overwritten).
    IdempotentExisting(Box<CrossCityOutboxRecord>),
}

/// A live outbox lease grant. The payload bytes are the exact bytes to publish;
/// `payload_digest` is their raw SHA-256 hex form. `Debug` deliberately prints
/// ONLY the payload length — the raw bytes never appear in logs.
#[derive(Clone, PartialEq, Eq)]
pub struct CrossCityOutboxLeaseGrant {
    pub message_id: String,
    pub identity: CrossCityMessageIdentity,
    pub payload: Vec<u8>,
    pub payload_digest: String,
    /// KNOWN failed attempts already consumed before this lease.
    pub attempts: i64,
    pub lease_owner: String,
    pub lease_token: CrossCityTransportLeaseToken,
    /// Exclusive server-side expiry in UTC Unix seconds.
    pub lease_expires_at_seconds: i64,
}

impl fmt::Debug for CrossCityOutboxLeaseGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CrossCityOutboxLeaseGrant")
            .field("message_id", &self.message_id)
            .field("identity", &self.identity)
            .field("payload_len", &self.payload.len())
            .field("payload_digest", &self.payload_digest)
            .field("attempts", &self.attempts)
            .field("lease_owner", &self.lease_owner)
            .field("lease_token", &self.lease_token)
            .field("lease_expires_at_seconds", &self.lease_expires_at_seconds)
            .finish()
    }
}

/// Strictly decoded durable inbox row. The inbox schema has no payload and no
/// destination column, so `message_id` cannot be re-derived from the row
/// alone; its derivation was proven at record time against the receiver's own
/// city id (see [`record_inbox_in_tx`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossCityInboxRecord {
    pub message_id: String,
    pub operation_id: String,
    pub phase: CrossCityMessagePhase,
    pub source_city_id: String,
    pub payload_digest: String,
    pub status: CrossCityDeliveryStatus,
    pub attempts: i64,
    pub lease_owner: Option<String>,
    /// For `PENDING` rows this is ALSO the next-eligible-time backoff fence
    /// (the inbox has no `next_attempt_at` column — see the module docs).
    pub lease_expires_at_seconds: Option<i64>,
    pub received_at_seconds: i64,
    pub processed_at_seconds: Option<i64>,
    pub last_error: Option<String>,
}

/// Record request for one inbound work item. `message_id` arrives on the wire
/// and is verified against the derivation over
/// `(operation_id, phase, source_city_id -> destination_city_id)`; the
/// receiving city's own id is never stored (the schema has no destination
/// column) and exists only to make that derivation checkable. The RAW received
/// payload bytes are handed in and the repository computes the stored digest
/// over them itself (`cross_city_payload_digest`) — a caller-supplied digest
/// string is never trusted. The `Debug` output deliberately prints ONLY the
/// payload length — the raw received bytes never appear in logs.
#[derive(Clone, PartialEq, Eq)]
pub struct CrossCityInboxRecordInsert {
    /// Wire-supplied message id; must equal the identity derivation.
    pub message_id: String,
    pub operation_id: String,
    pub phase: CrossCityMessagePhase,
    pub source_city_id: String,
    /// The receiving city's OWN identifier (the message's destination). Used
    /// only for the derivation check; never stored.
    pub destination_city_id: String,
    /// The EXACT received wire payload bytes; the stored `payload_digest` is
    /// computed over these bytes inside this repository (the inbox schema does
    /// not store the payload, so byte-for-byte re-verification after the fact
    /// is impossible and the digest must be derived here, not passed in).
    pub payload: Vec<u8>,
}

impl fmt::Debug for CrossCityInboxRecordInsert {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CrossCityInboxRecordInsert")
            .field("message_id", &self.message_id)
            .field("operation_id", &self.operation_id)
            .field("phase", &self.phase.as_str())
            .field("source_city_id", &self.source_city_id)
            .field("destination_city_id", &self.destination_city_id)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

/// Outcome of [`record_inbox_in_tx`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrossCityInboxInsertOutcome {
    /// The message was recorded inside the caller's transaction; it becomes
    /// durable ONLY after the caller's COMMIT (never before).
    Created(Box<CrossCityInboxRecord>),
    /// A record with the SAME message id and the SAME
    /// operation/source/phase/payload-digest binding already exists: the
    /// record is an idempotent replay and the durable record is returned
    /// unchanged (never blindly updated).
    IdempotentExisting(Box<CrossCityInboxRecord>),
}

/// A live inbox lease grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossCityInboxLeaseGrant {
    pub message_id: String,
    pub operation_id: String,
    pub phase: CrossCityMessagePhase,
    pub source_city_id: String,
    pub payload_digest: String,
    /// KNOWN failed attempts already consumed before this lease.
    pub attempts: i64,
    pub lease_owner: String,
    pub lease_token: CrossCityTransportLeaseToken,
    /// Exclusive server-side expiry in UTC Unix seconds.
    pub lease_expires_at_seconds: i64,
}

/// Outcome of a KNOWN failure reported through [`fail_outbox_in_tx`] /
/// [`fail_inbox_in_tx`]. The worker never decides silently: the budget
/// decision is explicit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrossCityTransportFailureOutcome {
    /// The row returns to `PENDING` and becomes eligible again after the
    /// backoff (outbox: `next_attempt_at`; inbox: the `lease_expires_at`
    /// fence).
    RetryScheduled { attempts: i64, backoff_seconds: i64 },
    /// The attempt budget is exhausted: the row is `QUARANTINED` and only the
    /// operator requeue (or reconciliation) can move it onward.
    Quarantined { attempts: i64 },
}

/// Reconcile outcome for one `IN_DOUBT` row. Every variant names an
/// independently PROVEN fact; the repository records the caller's assertion
/// and cannot verify external state itself (residual trust boundary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossCityTransportReconcileOutcome {
    /// Independently proven: the message was NOT published / NOT processed —
    /// no external result exists, so the row safely re-enters the worker flow
    /// (`PENDING`).
    NotApplied,
    /// Independently proven durable outcome (e.g. the destination city durably
    /// applied the message): the row closes as `SUCCEEDED`.
    Applied,
    /// The outcome cannot be resolved: hold the row for operator handling
    /// (`QUARANTINED`).
    Unresolvable,
}

fn reconcile_target(outcome: CrossCityTransportReconcileOutcome) -> CrossCityDeliveryStatus {
    match outcome {
        CrossCityTransportReconcileOutcome::NotApplied => CrossCityDeliveryStatus::Pending,
        CrossCityTransportReconcileOutcome::Applied => CrossCityDeliveryStatus::Succeeded,
        CrossCityTransportReconcileOutcome::Unresolvable => CrossCityDeliveryStatus::Quarantined,
    }
}

/// Exact duplicate-binding comparison for the outbox: EVERY binding field and
/// the payload digest must match; anything less is an immutable conflict.
fn outbox_duplicate_binding_matches(
    existing: &CrossCityOutboxRecord,
    identity: &CrossCityMessageIdentity,
    payload_digest_hex: &str,
) -> bool {
    existing.identity == *identity && existing.payload_digest == payload_digest_hex
}

/// Exact duplicate-binding comparison for the inbox (no payload and no
/// destination column): operation/source/phase/payload-digest must ALL match;
/// anything less is an immutable conflict — never a blind update.
fn inbox_duplicate_binding_matches(
    existing: &CrossCityInboxRecord,
    request: &CrossCityInboxRecordInsert,
    payload_digest_hex: &str,
) -> bool {
    existing.operation_id == request.operation_id
        && existing.phase == request.phase
        && existing.source_city_id == request.source_city_id
        && existing.payload_digest == payload_digest_hex
}

// ─────────────────────────────────────────────────────────────────────────────
// Statement registry (fixed SQL; no client-side assembly, no macros)
// ─────────────────────────────────────────────────────────────────────────────

const OUTBOX_INSERT_SQL: &str = "INSERT INTO authorization_cross_city_outbox \
    (message_id, operation_id, source_city_id, destination_city_id, phase, \
     payload_digest, payload, status, attempts) \
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";

const OUTBOX_SELECT_FOR_UPDATE_SQL: &str = "SELECT message_id, operation_id, source_city_id, \
    destination_city_id, phase, payload_digest, payload, status, attempts, next_attempt_at, \
    lease_owner, lease_token_hash, lease_expires_at, last_error \
    FROM authorization_cross_city_outbox WHERE message_id = ? FOR UPDATE";

/// Claim candidate: the earliest due claimable row. The predicate is an EXACT
/// disjunction of the only two consistent claimable states — a `PENDING` row
/// with its lease FULLY cleared (and the `next_attempt_at` schedule due), or a
/// `LEASED` row whose lease is complete AND expired (worker crash reclaim).
/// A row with PARTIAL lease material matches neither branch: it is poisoned
/// storage and is refused by the Rust-side consistency check — never repaired
/// by an overwriting claim. Server-side clock only.
///
/// The candidate scan deliberately does NOT pre-filter on the attempt bound:
/// an exhausted (`attempts == MAX`) or out-of-range ACTIVE row matches the
/// disjunction, is fully decoded on the locked row, and then FAILS the claim
/// closed at the explicit budget gate (or in the decode itself) — it is
/// surfaced to the operator paths, never silently skipped forever. The
/// install CAS retains `attempts < MAX` (see [`OUTBOX_CLAIM_INSTALL_SQL`]).
/// The candidate SELECT returns the FULL row shape and the locked candidate is
/// FULLY poison-decoded (identical validation to every record-returning path)
/// before the claim proceeds.
const OUTBOX_CLAIM_CANDIDATE_SQL: &str = "SELECT message_id, operation_id, source_city_id, \
    destination_city_id, phase, payload_digest, payload, status, attempts, next_attempt_at, \
    lease_owner, lease_token_hash, lease_expires_at, last_error \
    FROM authorization_cross_city_outbox \
    WHERE ( \
      (status = 'PENDING' AND lease_owner IS NULL AND lease_token_hash IS NULL \
       AND (lease_expires_at IS NULL OR lease_expires_at <= UTC_TIMESTAMP()) \
       AND (next_attempt_at IS NULL OR next_attempt_at <= UTC_TIMESTAMP())) \
   OR (status = 'LEASED' AND lease_owner IS NOT NULL AND lease_token_hash IS NOT NULL \
       AND lease_expires_at IS NOT NULL AND lease_expires_at <= UTC_TIMESTAMP())) \
    ORDER BY next_attempt_at ASC, created_at ASC, message_id ASC \
    LIMIT 1 FOR UPDATE";

/// Lease install: atomically flips the observed state to `LEASED` (WITHOUT
/// this flip every worker mutation would refuse the claimed row) and installs
/// the fresh lease. The WHERE re-checks, under the row lock, the EXACT
/// candidate disjunction (defense-in-depth against engine snapshot drift) and
/// RETAINS `attempts < MAX` — the install never leases an exhausted row — so
/// a live lease can never be overwritten and a partial lease can never be
/// repaired: the claim of an expired `LEASED` row is the deliberate, in-lock,
/// actor-specific reclaim proven by the two guarded worker edges (see
/// [`claim_next_outbox_in_tx`]).
const OUTBOX_CLAIM_INSTALL_SQL: &str = "UPDATE authorization_cross_city_outbox \
    SET status = 'LEASED', lease_owner = ?, lease_token_hash = ?, \
        lease_expires_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP()) \
    WHERE message_id = ? AND attempts < ? AND ( \
      (status = 'PENDING' AND lease_owner IS NULL AND lease_token_hash IS NULL \
       AND (lease_expires_at IS NULL OR lease_expires_at <= UTC_TIMESTAMP()) \
       AND (next_attempt_at IS NULL OR next_attempt_at <= UTC_TIMESTAMP())) \
   OR (status = 'LEASED' AND lease_owner IS NOT NULL AND lease_token_hash IS NOT NULL \
       AND lease_expires_at IS NOT NULL AND lease_expires_at <= UTC_TIMESTAMP()))";

const OUTBOX_CLAIM_READBACK_SQL: &str = "SELECT message_id, operation_id, source_city_id, \
    destination_city_id, phase, status, lease_expires_at \
    FROM authorization_cross_city_outbox WHERE message_id = ?";

const OUTBOX_HEARTBEAT_SQL: &str = "UPDATE authorization_cross_city_outbox \
    SET lease_expires_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP()) \
    WHERE message_id = ? AND status = 'LEASED' AND lease_owner = ? AND lease_token_hash = ? \
      AND lease_expires_at IS NOT NULL AND lease_expires_at > UTC_TIMESTAMP()";

const OUTBOX_SUCCEED_SQL: &str = "UPDATE authorization_cross_city_outbox \
    SET status = 'SUCCEEDED', next_attempt_at = NULL, lease_owner = NULL, \
        lease_token_hash = NULL, lease_expires_at = NULL, last_error = NULL \
    WHERE message_id = ? AND status = 'LEASED' AND lease_owner = ? AND lease_token_hash = ? \
      AND lease_expires_at IS NOT NULL AND lease_expires_at > UTC_TIMESTAMP()";

/// KNOWN failure with remaining budget: back to `PENDING`, one attempt
/// consumed, backoff scheduled into `next_attempt_at`, lease fully cleared.
const OUTBOX_FAIL_RETRY_SQL: &str = "UPDATE authorization_cross_city_outbox \
    SET status = 'PENDING', attempts = ?, \
        next_attempt_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP()), \
        lease_owner = NULL, lease_token_hash = NULL, lease_expires_at = NULL, last_error = ? \
    WHERE message_id = ? AND status = 'LEASED' AND lease_owner = ? AND lease_token_hash = ? \
      AND lease_expires_at IS NOT NULL AND lease_expires_at > UTC_TIMESTAMP() AND attempts = ?";

/// Quarantine (deterministic conflict OR exhausted budget): one attempt
/// consumed, no schedule, lease fully cleared.
const OUTBOX_QUARANTINE_SQL: &str = "UPDATE authorization_cross_city_outbox \
    SET status = 'QUARANTINED', attempts = ?, next_attempt_at = NULL, \
        lease_owner = NULL, lease_token_hash = NULL, lease_expires_at = NULL, last_error = ? \
    WHERE message_id = ? AND status = 'LEASED' AND lease_owner = ? AND lease_token_hash = ? \
      AND lease_expires_at IS NOT NULL AND lease_expires_at > UTC_TIMESTAMP() AND attempts = ?";

/// Graceful worker release without consuming the attempt budget (the known
/// failure produced no external result and the row keeps its schedule).
const OUTBOX_RELEASE_SQL: &str = "UPDATE authorization_cross_city_outbox \
    SET status = 'PENDING', lease_owner = NULL, lease_token_hash = NULL, \
        lease_expires_at = NULL \
    WHERE message_id = ? AND status = 'LEASED' AND lease_owner = ? AND lease_token_hash = ? \
      AND lease_expires_at IS NOT NULL AND lease_expires_at > UTC_TIMESTAMP()";

/// UNKNOWN publish outcome: the worker hands the row to reconciliation and
/// gives up ownership (no retry in place, no budget consumed); any stale retry
/// schedule is cleared — the schedule belongs to the worker flow, and
/// reconciliation owns what happens next.
const OUTBOX_IN_DOUBT_SQL: &str = "UPDATE authorization_cross_city_outbox \
    SET status = 'IN_DOUBT', next_attempt_at = NULL, \
        lease_owner = NULL, lease_token_hash = NULL, lease_expires_at = NULL, last_error = ? \
    WHERE message_id = ? AND status = 'LEASED' AND lease_owner = ? AND lease_token_hash = ? \
      AND lease_expires_at IS NOT NULL AND lease_expires_at > UTC_TIMESTAMP()";

/// Reconcile resolution of an `IN_DOUBT` row: the target is one of the three
/// proven facts (see [`CrossCityTransportReconcileOutcome`]); the schedule is
/// cleared so a `PENDING` resolution is immediately eligible.
const OUTBOX_RECONCILE_SQL: &str = "UPDATE authorization_cross_city_outbox \
    SET status = ?, next_attempt_at = NULL, \
        lease_owner = NULL, lease_token_hash = NULL, lease_expires_at = NULL, last_error = ? \
    WHERE message_id = ? AND status = 'IN_DOUBT'";
/// Operator requeue: a quarantined row returns to `PENDING` with a FRESH
/// attempt budget (`attempts = 0`) and no schedule; lease material is cleared.
const OUTBOX_REQUEUE_SQL: &str = "UPDATE authorization_cross_city_outbox \
    SET status = 'PENDING', attempts = 0, next_attempt_at = NULL, \
        lease_owner = NULL, lease_token_hash = NULL, lease_expires_at = NULL \
    WHERE message_id = ? AND status = 'QUARANTINED'";

/// Lease-free poison quarantine of an outbox row PROVEN poisoned by its full
/// decode (see [`quarantine_poisoned_outbox_in_tx`]). Only the MUTABLE
/// lease/schedule/status fields move: `message_id`, `operation_id`, both city
/// columns, `phase`, `payload_digest`, `payload`, `attempts`, and the
/// `created_at`/`updated_at` history are never touched. The WHERE pins the
/// exact raw status observed under the row lock, refuses the terminal
/// `SUCCEEDED` status server-side, and refuses a LIVE lease server-side
/// (`lease_expires_at > UTC_TIMESTAMP()`): a live lease is never stolen by
/// this path, and losing the guard is an explicit refusal, never a partial
/// write.
const OUTBOX_POISON_QUARANTINE_SQL: &str = "UPDATE authorization_cross_city_outbox \
    SET status = 'QUARANTINED', next_attempt_at = NULL, lease_owner = NULL, \
        lease_token_hash = NULL, lease_expires_at = NULL, last_error = ? \
    WHERE message_id = ? AND BINARY status = BINARY ? \
      AND BINARY status <> BINARY 'SUCCEEDED' \
      AND NOT (lease_owner IS NOT NULL AND lease_token_hash IS NOT NULL \
               AND lease_expires_at IS NOT NULL AND lease_expires_at > UTC_TIMESTAMP())";

const INBOX_RECORD_INSERT_SQL: &str = "INSERT INTO authorization_cross_city_inbox \
    (message_id, operation_id, source_city_id, phase, payload_digest, status, attempts) \
    VALUES (?, ?, ?, ?, ?, ?, ?)";

const INBOX_SELECT_FOR_UPDATE_SQL: &str = "SELECT message_id, operation_id, source_city_id, \
    phase, payload_digest, status, attempts, lease_owner, lease_token_hash, lease_expires_at, \
    received_at, processed_at, last_error \
    FROM authorization_cross_city_inbox WHERE message_id = ? FOR UPDATE";

/// Claim candidate: the earliest eligible row. There is NO `next_attempt_at`
/// column in this schema: the lease fence is the ONLY eligibility gate, which
/// is exactly how the inbox carries retry backoff without hot-looping (see the
/// module docs). The predicate is an EXACT disjunction of the only two
/// consistent claimable states — a `PENDING` row with owner/token FULLY
/// cleared (fence passed or absent), or a `LEASED` row whose lease is complete
/// AND expired (worker crash reclaim). Partial lease material matches neither
/// branch and is refused on the locked row — never repaired.
///
/// The candidate scan deliberately does NOT pre-filter on the attempt bound:
/// an exhausted (`attempts == MAX`) or out-of-range ACTIVE row matches the
/// disjunction and FAILS the claim closed at the explicit budget gate (or in
/// the full decode itself) — surfaced to the operator paths, never silently
/// skipped forever. The install CAS retains `attempts < MAX` (see
/// [`INBOX_CLAIM_INSTALL_SQL`]).
const INBOX_CLAIM_CANDIDATE_SQL: &str = "SELECT message_id, operation_id, source_city_id, \
    phase, payload_digest, status, attempts, lease_owner, lease_token_hash, lease_expires_at, \
    received_at, processed_at, last_error \
    FROM authorization_cross_city_inbox \
    WHERE ( \
      (status = 'PENDING' AND lease_owner IS NULL AND lease_token_hash IS NULL \
       AND (lease_expires_at IS NULL OR lease_expires_at <= UTC_TIMESTAMP())) \
   OR (status = 'LEASED' AND lease_owner IS NOT NULL AND lease_token_hash IS NOT NULL \
       AND lease_expires_at IS NOT NULL AND lease_expires_at <= UTC_TIMESTAMP())) \
    ORDER BY lease_expires_at ASC, received_at ASC, message_id ASC \
    LIMIT 1 FOR UPDATE";

/// Lease install: atomically flips the observed state to `LEASED` (WITHOUT
/// this flip every worker mutation would refuse the claimed row) and installs
/// the fresh lease; the WHERE re-checks the EXACT candidate disjunction under
/// the row lock (no live-lease steal, no partial-lease repair — see
/// [`claim_inbox_in_tx`]) and RETAINS `attempts < MAX` — the install never
/// leases an exhausted row.
const INBOX_CLAIM_INSTALL_SQL: &str = "UPDATE authorization_cross_city_inbox \
    SET status = 'LEASED', lease_owner = ?, lease_token_hash = ?, \
        lease_expires_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP()) \
    WHERE message_id = ? AND attempts < ? AND ( \
      (status = 'PENDING' AND lease_owner IS NULL AND lease_token_hash IS NULL \
       AND (lease_expires_at IS NULL OR lease_expires_at <= UTC_TIMESTAMP())) \
   OR (status = 'LEASED' AND lease_owner IS NOT NULL AND lease_token_hash IS NOT NULL \
       AND lease_expires_at IS NOT NULL AND lease_expires_at <= UTC_TIMESTAMP()))";

const INBOX_CLAIM_READBACK_SQL: &str = "SELECT message_id, operation_id, source_city_id, \
    phase, status, lease_expires_at \
    FROM authorization_cross_city_inbox WHERE message_id = ?";

const INBOX_HEARTBEAT_SQL: &str = "UPDATE authorization_cross_city_inbox \
    SET lease_expires_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP()) \
    WHERE message_id = ? AND status = 'LEASED' AND lease_owner = ? AND lease_token_hash = ? \
      AND lease_expires_at IS NOT NULL AND lease_expires_at > UTC_TIMESTAMP()";

const INBOX_PROCESSED_SQL: &str = "UPDATE authorization_cross_city_inbox \
    SET status = 'SUCCEEDED', processed_at = UTC_TIMESTAMP(), lease_owner = NULL, \
        lease_token_hash = NULL, lease_expires_at = NULL, last_error = NULL \
    WHERE message_id = ? AND status = 'LEASED' AND lease_owner = ? AND lease_token_hash = ? \
      AND lease_expires_at IS NOT NULL AND lease_expires_at > UTC_TIMESTAMP()";

/// KNOWN processing failure with remaining budget: back to `PENDING`, one
/// attempt consumed. The lease identity is cleared but `lease_expires_at` is
/// deliberately RETAINED as `UTC_TIMESTAMP() + backoff`: it is the inbox's
/// next-eligible-time fence (no `next_attempt_at` column exists).
const INBOX_FAIL_RETRY_SQL: &str = "UPDATE authorization_cross_city_inbox \
    SET status = 'PENDING', attempts = ?, lease_owner = NULL, lease_token_hash = NULL, \
        lease_expires_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP()), last_error = ? \
    WHERE message_id = ? AND status = 'LEASED' AND lease_owner = ? AND lease_token_hash = ? \
      AND lease_expires_at IS NOT NULL AND lease_expires_at > UTC_TIMESTAMP() AND attempts = ?";

/// Quarantine (deterministic conflict OR exhausted budget): one attempt
/// consumed, lease material fully cleared (no fence on a quarantined row).
const INBOX_QUARANTINE_SQL: &str = "UPDATE authorization_cross_city_inbox \
    SET status = 'QUARANTINED', attempts = ?, lease_owner = NULL, lease_token_hash = NULL, \
        lease_expires_at = NULL, last_error = ? \
    WHERE message_id = ? AND status = 'LEASED' AND lease_owner = ? AND lease_token_hash = ? \
      AND lease_expires_at IS NOT NULL AND lease_expires_at > UTC_TIMESTAMP() AND attempts = ?";

/// UNKNOWN processing outcome: the worker hands the row to reconciliation and
/// gives up ownership (no retry in place, no budget consumed).
const INBOX_IN_DOUBT_SQL: &str = "UPDATE authorization_cross_city_inbox \
    SET status = 'IN_DOUBT', lease_owner = NULL, lease_token_hash = NULL, \
        lease_expires_at = NULL, last_error = ? \
    WHERE message_id = ? AND status = 'LEASED' AND lease_owner = ? AND lease_token_hash = ? \
      AND lease_expires_at IS NOT NULL AND lease_expires_at > UTC_TIMESTAMP()";

/// Reconcile resolution of an `IN_DOUBT` inbox row to `PENDING` (proven not
/// processed) or `QUARANTINED` (unresolvable) — see
/// [`CrossCityTransportReconcileOutcome`].
const INBOX_RECONCILE_SQL: &str = "UPDATE authorization_cross_city_inbox \
    SET status = ?, lease_owner = NULL, lease_token_hash = NULL, \
        lease_expires_at = NULL, last_error = ? \
    WHERE message_id = ? AND status = 'IN_DOUBT'";

/// Reconcile resolution of an `IN_DOUBT` inbox row to `SUCCEEDED` (proven
/// durably processed): `Applied` IS the processed fact, so the row is closed
/// exactly once with the server-side `processed_at` stamp the decode
/// invariant requires of every `SUCCEEDED` row.
const INBOX_RECONCILE_APPLIED_SQL: &str = "UPDATE authorization_cross_city_inbox \
    SET status = 'SUCCEEDED', processed_at = UTC_TIMESTAMP(), lease_owner = NULL, \
        lease_token_hash = NULL, lease_expires_at = NULL, last_error = ? \
    WHERE message_id = ? AND status = 'IN_DOUBT'";

/// Operator requeue: a quarantined row returns to `PENDING` with a FRESH
/// attempt budget (`attempts = 0`) and a cleared lease fence, so it becomes
/// immediately eligible; `processed_at` history is never rewritten.
const INBOX_REQUEUE_SQL: &str = "UPDATE authorization_cross_city_inbox \
    SET status = 'PENDING', attempts = 0, lease_owner = NULL, lease_token_hash = NULL, \
        lease_expires_at = NULL \
    WHERE message_id = ? AND status = 'QUARANTINED'";

/// Lease-free poison quarantine of an inbox row PROVEN poisoned by its full
/// decode (see [`quarantine_poisoned_inbox_in_tx`]). Only the MUTABLE
/// lease/status fields move: `message_id`, `operation_id`, `source_city_id`,
/// `phase`, `payload_digest`, `attempts`, and the `received_at`/
/// `processed_at` history are never touched. The WHERE pins the exact raw
/// status observed under the row lock, refuses the terminal `SUCCEEDED`
/// status server-side, and refuses a LIVE lease server-side
/// (`lease_expires_at > UTC_TIMESTAMP()`): a live lease is never stolen by
/// this path, and losing the guard is an explicit refusal, never a partial
/// write.
const INBOX_POISON_QUARANTINE_SQL: &str = "UPDATE authorization_cross_city_inbox \
    SET status = 'QUARANTINED', lease_owner = NULL, lease_token_hash = NULL, \
        lease_expires_at = NULL, last_error = ? \
    WHERE message_id = ? AND BINARY status = BINARY ? \
      AND BINARY status <> BINARY 'SUCCEEDED' \
      AND NOT (lease_owner IS NOT NULL AND lease_token_hash IS NOT NULL \
               AND lease_expires_at IS NOT NULL AND lease_expires_at > UTC_TIMESTAMP())";

// ─────────────────────────────────────────────────────────────────────────────
// Row codecs
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, sqlx::FromRow)]
struct OutboxRow {
    message_id: String,
    operation_id: String,
    source_city_id: String,
    destination_city_id: String,
    phase: String,
    payload_digest: Vec<u8>,
    payload: Vec<u8>,
    status: String,
    attempts: i32,
    next_attempt_at: Option<PrimitiveDateTime>,
    lease_owner: Option<String>,
    lease_token_hash: Option<Vec<u8>>,
    lease_expires_at: Option<PrimitiveDateTime>,
    last_error: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct OutboxClaimReadbackRow {
    message_id: String,
    operation_id: String,
    source_city_id: String,
    destination_city_id: String,
    phase: String,
    status: String,
    lease_expires_at: Option<PrimitiveDateTime>,
}

#[derive(Debug, sqlx::FromRow)]
struct InboxRow {
    message_id: String,
    operation_id: String,
    source_city_id: String,
    phase: String,
    payload_digest: Vec<u8>,
    status: String,
    attempts: i32,
    lease_owner: Option<String>,
    lease_token_hash: Option<Vec<u8>>,
    lease_expires_at: Option<PrimitiveDateTime>,
    received_at: PrimitiveDateTime,
    processed_at: Option<PrimitiveDateTime>,
    last_error: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct InboxClaimReadbackRow {
    message_id: String,
    operation_id: String,
    source_city_id: String,
    phase: String,
    status: String,
    lease_expires_at: Option<PrimitiveDateTime>,
}

/// Full fail-closed decode of an outbox row (used on every path that RETURNS a
/// record): identity derivation, digest binding, payload bounds, text
/// canonicality, attempt bounds (including the only-`QUARANTINED`-may-sit-AT-
/// the-bound invariant), and status/lease consistency.
fn decode_outbox_row(
    row: OutboxRow,
) -> Result<CrossCityOutboxRecord, CrossCityTransportRepositoryError> {
    let identity = decode_transport_message_identity(
        &row.operation_id,
        &row.phase,
        &row.source_city_id,
        &row.destination_city_id,
        &row.message_id,
    )?;
    let status = CrossCityDeliveryStatus::parse_str(&row.status)?;
    let attempts = validated_attempts(i64::from(row.attempts))?;
    // `attempts == MAX` is only legal on a QUARANTINED row: the
    // exhausted-budget quarantine is the only writer that reaches the bound.
    // A non-quarantined row at the bound is poisoned storage — the claim
    // candidate scan no longer pre-filters on the bound, so such a row
    // SURFACES there (and to the lease-free poison quarantine) instead of
    // being silently skipped forever.
    if attempts == MAX_CROSS_CITY_TRANSPORT_ATTEMPTS
        && status != CrossCityDeliveryStatus::Quarantined
    {
        return Err(mapping("poisoned_outbox_attempts_at_budget"));
    }
    let payload_digest = digest_from_bytes(row.payload_digest)?.as_hex();
    if row.payload.is_empty() {
        return Err(mapping("poisoned_outbox_empty_payload"));
    }
    if row.payload.len() > MAX_CROSS_CITY_TRANSPORT_PAYLOAD_BYTES {
        return Err(mapping("poisoned_outbox_oversized_payload"));
    }
    if cross_city_payload_digest(&row.payload) != payload_digest {
        return Err(mapping("poisoned_outbox_payload_digest"));
    }
    if let Some(owner) = &row.lease_owner {
        if !stored_text_is_canonical(owner, MAX_CROSS_CITY_TRANSPORT_LEASE_OWNER_LENGTH) {
            return Err(mapping("poisoned_outbox_lease_owner"));
        }
    }
    let lease_token_hash = digest_from_optional_bytes(row.lease_token_hash.as_deref())?;
    if row.lease_owner.is_some() != lease_token_hash.is_some() {
        return Err(mapping("poisoned_outbox_lease_pairing"));
    }
    validate_transport_status_lease_consistency(
        status,
        row.lease_owner.is_some(),
        lease_token_hash.is_some(),
        row.lease_expires_at.is_some(),
        false,
    )?;
    // Schedule invariants: the retry schedule is the worker flow's own
    // bookkeeping — every row that has left the normal worker cycle
    // (IN_DOUBT), been completed (SUCCEEDED), or been held (QUARANTINED)
    // carries NO stale schedule; every writer path clears it.
    if matches!(
        status,
        CrossCityDeliveryStatus::Quarantined
            | CrossCityDeliveryStatus::InDoubt
            | CrossCityDeliveryStatus::Succeeded
    ) && row.next_attempt_at.is_some()
    {
        return Err(mapping("poisoned_outbox_stale_schedule"));
    }
    if let Some(last_error) = &row.last_error {
        if last_error.chars().count() > MAX_CROSS_CITY_TRANSPORT_LAST_ERROR_LENGTH
            || !stored_forensic_text_is_safe(last_error)
        {
            return Err(mapping("poisoned_outbox_last_error"));
        }
    }
    Ok(CrossCityOutboxRecord {
        message_id: identity.message_id.clone(),
        identity,
        payload_digest,
        payload: row.payload,
        status,
        attempts,
        next_attempt_at_seconds: row.next_attempt_at.map(datetime_to_unix_seconds),
        lease_owner: row.lease_owner,
        lease_expires_at_seconds: row.lease_expires_at.map(datetime_to_unix_seconds),
        last_error: row.last_error,
    })
}

/// Full fail-closed decode of an inbox row (including the
/// only-`QUARANTINED`-may-sit-AT-the-attempt-bound invariant).
fn decode_inbox_row(
    row: InboxRow,
) -> Result<CrossCityInboxRecord, CrossCityTransportRepositoryError> {
    validated_message_id_shape(&row.message_id)?;
    validated_operation_id(&row.operation_id)?;
    validated_text(
        &row.source_city_id,
        MAX_CROSS_CITY_TRANSPORT_CITY_LENGTH,
        "source_city_id",
    )?;
    let phase = CrossCityMessagePhase::parse_str(&row.phase)?;
    let status = CrossCityDeliveryStatus::parse_str(&row.status)?;
    let attempts = validated_attempts(i64::from(row.attempts))?;
    // Mirror of the outbox invariant: only a QUARANTINED row may sit AT the
    // attempt bound; any other status there is poisoned storage that the
    // claim scan surfaces instead of silently skipping.
    if attempts == MAX_CROSS_CITY_TRANSPORT_ATTEMPTS
        && status != CrossCityDeliveryStatus::Quarantined
    {
        return Err(mapping("poisoned_inbox_attempts_at_budget"));
    }
    let payload_digest = digest_from_bytes(row.payload_digest)?.as_hex();
    if let Some(owner) = &row.lease_owner {
        if !stored_text_is_canonical(owner, MAX_CROSS_CITY_TRANSPORT_LEASE_OWNER_LENGTH) {
            return Err(mapping("poisoned_inbox_lease_owner"));
        }
    }
    let lease_token_hash = digest_from_optional_bytes(row.lease_token_hash.as_deref())?;
    if row.lease_owner.is_some() != lease_token_hash.is_some() {
        return Err(mapping("poisoned_inbox_lease_pairing"));
    }
    validate_transport_status_lease_consistency(
        status,
        row.lease_owner.is_some(),
        lease_token_hash.is_some(),
        row.lease_expires_at.is_some(),
        true,
    )?;
    // `processed_at` is written exactly once, on the transition into
    // `SUCCEEDED`; a timestamp on any other status is poisoned, and a
    // `SUCCEEDED` row without its durable server-side stamp is equally
    // incomplete and therefore poisoned.
    if (status == CrossCityDeliveryStatus::Succeeded) != row.processed_at.is_some() {
        return Err(mapping("poisoned_inbox_processed_at"));
    }
    if let Some(last_error) = &row.last_error {
        if last_error.chars().count() > MAX_CROSS_CITY_TRANSPORT_LAST_ERROR_LENGTH
            || !stored_forensic_text_is_safe(last_error)
        {
            return Err(mapping("poisoned_inbox_last_error"));
        }
    }
    Ok(CrossCityInboxRecord {
        message_id: row.message_id,
        operation_id: row.operation_id,
        phase,
        source_city_id: row.source_city_id,
        payload_digest,
        status,
        attempts,
        lease_owner: row.lease_owner,
        lease_expires_at_seconds: row.lease_expires_at.map(datetime_to_unix_seconds),
        received_at_seconds: datetime_to_unix_seconds(row.received_at),
        processed_at_seconds: row.processed_at.map(datetime_to_unix_seconds),
        last_error: row.last_error,
    })
}

async fn lock_outbox_for_update(
    tx: &mut Transaction<'_, MySql>,
    message_id: &str,
) -> Result<Option<OutboxRow>, CrossCityTransportRepositoryError> {
    let row: Option<OutboxRow> = sqlx::query_as(OUTBOX_SELECT_FOR_UPDATE_SQL)
        .bind(message_id)
        .fetch_optional(&mut **tx)
        .await?;
    Ok(row)
}

async fn lock_inbox_for_update(
    tx: &mut Transaction<'_, MySql>,
    message_id: &str,
) -> Result<Option<InboxRow>, CrossCityTransportRepositoryError> {
    let row: Option<InboxRow> = sqlx::query_as(INBOX_SELECT_FOR_UPDATE_SQL)
        .bind(message_id)
        .fetch_optional(&mut **tx)
        .await?;
    Ok(row)
}

/// Lease-context verification on the LOCKED outbox row: identity, owner, token
/// hash, and expiry presence. Liveness (`lease_expires_at >
/// UTC_TIMESTAMP()`) is enforced by every mutation's SQL CAS.
fn verify_outbox_lease_material(
    row: &OutboxRow,
    proof: &CrossCityTransportLeaseProof,
) -> Result<(), CrossCityTransportRepositoryError> {
    if row.message_id != proof.message_id {
        return Err(mapping("outbox_lease_identity_drift"));
    }
    let Some(owner) = row.lease_owner.as_deref() else {
        return Err(lease_cas("outbox_lease_absent"));
    };
    if owner != proof.lease_owner {
        return Err(lease_cas("outbox_lease_owner_mismatch"));
    }
    let stored_hash = digest_from_optional_bytes(row.lease_token_hash.as_deref())?;
    let Some(stored_hash) = stored_hash else {
        return Err(lease_cas("outbox_lease_token_absent"));
    };
    if stored_hash.as_bytes() != proof.lease_token.token_hash().as_bytes() {
        return Err(lease_cas("outbox_lease_token_mismatch"));
    }
    if row.lease_expires_at.is_none() {
        return Err(lease_cas("outbox_lease_expiry_absent"));
    }
    Ok(())
}

/// Lease-context verification on the LOCKED inbox row (mirror of the outbox
/// check).
fn verify_inbox_lease_material(
    row: &InboxRow,
    proof: &CrossCityTransportLeaseProof,
) -> Result<(), CrossCityTransportRepositoryError> {
    if row.message_id != proof.message_id {
        return Err(mapping("inbox_lease_identity_drift"));
    }
    let Some(owner) = row.lease_owner.as_deref() else {
        return Err(lease_cas("inbox_lease_absent"));
    };
    if owner != proof.lease_owner {
        return Err(lease_cas("inbox_lease_owner_mismatch"));
    }
    let stored_hash = digest_from_optional_bytes(row.lease_token_hash.as_deref())?;
    let Some(stored_hash) = stored_hash else {
        return Err(lease_cas("inbox_lease_token_absent"));
    };
    if stored_hash.as_bytes() != proof.lease_token.token_hash().as_bytes() {
        return Err(lease_cas("inbox_lease_token_mismatch"));
    }
    if row.lease_expires_at.is_none() {
        return Err(lease_cas("inbox_lease_expiry_absent"));
    }
    Ok(())
}

/// An `IN_DOUBT` row must not carry any lease material: the worker gave up
/// ownership on the unknown outcome, and reconciliation is lease-free.
fn ensure_in_doubt_lease_absent(
    lease_owner_present: bool,
    lease_token_present: bool,
    lease_expiry_present: bool,
    table: &'static str,
) -> Result<(), CrossCityTransportRepositoryError> {
    if lease_owner_present || lease_token_present || lease_expiry_present {
        return Err(mapping(&format!(
            "poisoned_{table}_in_doubt_lease_material"
        )));
    }
    Ok(())
}

/// A character that must NEVER enter a persisted forensic text field: NUL,
/// CR/LF and every other Unicode control character (this includes the ANSI
/// escape `ESC` and the whole C1 control range, so escape-sequence injection
/// and log/terminal forging are refused at the source), plus the Unicode line
/// and paragraph separators `U+2028`/`U+2029`, which are `Zl`/`Zp` (not `Cc`)
/// but would still break single-line forensic text.
fn is_unsafe_forensic_char(character: char) -> bool {
    character.is_control() || matches!(character, '\u{2028}' | '\u{2029}')
}

/// Unicode format and bidirectional-control characters are not accepted in
/// operator marker fields. They can be invisible or reorder rendered text even
/// though they are not `char::is_control()` characters. The list mirrors the
/// Unicode `Cf`/bidi ranges relevant to identifiers and log display; rejecting
/// them is deliberately stricter than the general forensic-text boundary.
fn is_unicode_format_or_bidi_char(character: char) -> bool {
    matches!(
        character,
        '\u{00AD}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
    )
}

/// Read-side counterpart to [`validated_reason`]. Existing rows are never
/// normalized, but a control-carrying or invisible-format `last_error` is still
/// poisoned rather than returned to logging or audit presentation paths.
fn stored_forensic_text_is_safe(value: &str) -> bool {
    !value.chars().any(|character| {
        is_unsafe_forensic_char(character) || is_unicode_format_or_bidi_char(character)
    })
}

/// Operator marker fields use a stricter grammar than ordinary reasons:
/// delimiters cannot be smuggled into the `key=value;key=value` marker, and
/// invisible format/bidi characters cannot spoof its rendered meaning.
fn is_unsafe_operator_field_char(character: char) -> bool {
    is_unsafe_forensic_char(character)
        || is_unicode_format_or_bidi_char(character)
        || matches!(character, ';' | '=')
}

/// Forensic reason/note boundary: non-empty, unpadded, free of control
/// characters (CR/LF/NUL/ANSI escapes included), unsafe line separators, and
/// invisible Unicode format/bidi characters, then char-truncated into the
/// `VARCHAR(512)` `last_error` bound. The truncation is UTF-8-safe by
/// construction (it never splits a code point). Anything unsafe is refused —
/// never sanitized in place.
fn validated_reason(reason: &str) -> Result<String, CrossCityTransportRepositoryError> {
    if reason.trim().is_empty() {
        return Err(scope_violation("empty_reason"));
    }
    if reason.chars().any(|character| {
        is_unsafe_forensic_char(character) || is_unicode_format_or_bidi_char(character)
    }) {
        return Err(scope_violation("unsafe_reason_characters"));
    }
    Ok(truncate_transport_last_error(reason))
}

// ─────────────────────────────────────────────────────────────────────────────
// Operator authorization context (lease-free poison quarantine)
// ─────────────────────────────────────────────────────────────────────────────

/// Operator authorization context for the LEASE-FREE poison quarantine path
/// ([`quarantine_poisoned_outbox_in_tx`] / [`quarantine_poisoned_inbox_in_tx`]).
///
/// # Trust boundary (the repository cannot authenticate the operator)
///
/// This repository has no session, token, identity, or policy source of its
/// own and CANNOT authenticate anyone. The caller MUST mint this context at
/// an AUTHENTICATED boundary — after verifying who the operator is and that
/// the operator is authorized for this administrative action (e.g. via
/// `PolicyEngine.evaluate()`). Both fields are treated as forensic
/// ASSERTIONS: the repository validates only their shape (bounded, unpadded,
/// no whitespace, no control characters) and binds them verbatim into the
/// durable `last_error` marker. Neither field may carry a secret or bearer
/// material; minting this context from unauthenticated input is a caller
/// defect this module cannot detect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossCityTransportOperatorAuthorization {
    /// The verified principal id of the operator (minted at the caller's
    /// authenticated boundary).
    pub operator_subject: String,
    /// A reference to the authorization decision the caller relied on (e.g.
    /// the `PolicyEngine.evaluate()` decision/trace id). Never a token.
    pub authorization_reference: String,
}

/// One operator authorization field: bounded by
/// [`MAX_CROSS_CITY_TRANSPORT_OPERATOR_LENGTH`], unpadded, and free of
/// whitespace and control characters (the same strictness as every other
/// stored text field, plus the forensic-character refusal).
fn validated_operator_field(
    value: &str,
    field: &'static str,
) -> Result<String, CrossCityTransportRepositoryError> {
    validated_text(value, MAX_CROSS_CITY_TRANSPORT_OPERATOR_LENGTH, field)?;
    if value.chars().any(is_unsafe_operator_field_char) {
        return Err(scope_violation(&format!(
            "unsafe_operator_field;field={field}"
        )));
    }
    Ok(value.to_owned())
}

/// Fixed prefix of the poison-quarantine forensic marker persisted into
/// `last_error`.
const POISON_QUARANTINE_MARKER_OPERATOR_PREFIX: &str = "poison_quarantine;operator=";
/// Fixed separator before the authorization reference.
const POISON_QUARANTINE_MARKER_REFERENCE_PREFIX: &str = ";ref=";
/// Fixed separator before the validated reason.
const POISON_QUARANTINE_MARKER_REASON_PREFIX: &str = ";reason=";

/// Compose the bounded, single-line forensic marker persisted into
/// `last_error` by the poison quarantine path:
/// `poison_quarantine;operator=<subject>;ref=<reference>;reason=<reason>`.
///
/// Every input is validated BEFORE composition — an unsafe character fails
/// the whole request closed and persists NOTHING (no silent sanitizing). The
/// reason is truncated on char boundaries to whatever budget remains after
/// the fixed prefixes and the operator fields, so the composed marker always
/// fits the `VARCHAR(512)` `last_error` column and UTF-8 truncation never
/// splits a code point. The marker adds no control character of its own.
fn poison_quarantine_forensic_marker(
    authorization: &CrossCityTransportOperatorAuthorization,
    reason: &str,
) -> Result<String, CrossCityTransportRepositoryError> {
    let subject = validated_operator_field(&authorization.operator_subject, "operator_subject")?;
    let reference = validated_operator_field(
        &authorization.authorization_reference,
        "authorization_reference",
    )?;
    let reason = validated_reason(reason)?;
    let fixed_chars = POISON_QUARANTINE_MARKER_OPERATOR_PREFIX.chars().count()
        + subject.chars().count()
        + POISON_QUARANTINE_MARKER_REFERENCE_PREFIX.chars().count()
        + reference.chars().count()
        + POISON_QUARANTINE_MARKER_REASON_PREFIX.chars().count();
    let reason_budget = MAX_CROSS_CITY_TRANSPORT_LAST_ERROR_LENGTH.saturating_sub(fixed_chars);
    if reason_budget == 0 {
        return Err(scope_violation("poison_marker_reason_budget_exhausted"));
    }
    let bounded_reason: String = reason.chars().take(reason_budget).collect();
    let marker = format!(
        "{POISON_QUARANTINE_MARKER_OPERATOR_PREFIX}{subject}\
         {POISON_QUARANTINE_MARKER_REFERENCE_PREFIX}{reference}\
         {POISON_QUARANTINE_MARKER_REASON_PREFIX}{bounded_reason}"
    );
    // Defensive re-check: the marker is char-bounded and control-free by
    // construction; refuse rather than persist if that ever drifts.
    if marker.chars().count() > MAX_CROSS_CITY_TRANSPORT_LAST_ERROR_LENGTH
        || marker.chars().any(is_unsafe_forensic_char)
    {
        return Err(scope_violation("unsafe_poison_marker"));
    }
    Ok(marker)
}

// ─────────────────────────────────────────────────────────────────────────────
// Outbox primitives
// ─────────────────────────────────────────────────────────────────────────────

/// Durably record one outbound cross-city message (inside the caller's
/// transaction — the commit is the only durable point).
///
/// The `message_id` is DERIVED via
/// [`CrossCityMessageIdentity::new`] over `(operation_id, phase,
/// source_city_id, destination_city_id)` and is never caller-supplied;
/// `payload_digest` is computed over the EXACT payload bytes handed in. A
/// duplicate insert (same derived id) with the SAME
/// operation/phase/source/destination/payload-digest binding returns the
/// idempotent existing record unchanged; ANY binding or digest difference is
/// an immutable conflict — evidence and payload are never overwritten. There
/// is no upsert form: the plain `INSERT` either applies or the unique key
/// surfaces the duplicate for exact comparison.
pub async fn insert_outbox_in_tx(
    tx: &mut Transaction<'_, MySql>,
    request: &CrossCityOutboxInsert,
) -> Result<CrossCityOutboxInsertOutcome, CrossCityTransportRepositoryError> {
    // Repository storage boundary: the identity contract admits identifiers up
    // to its own (larger) bound, but the schema columns are VARCHAR(191), so
    // anything the DB could truncate is refused HERE, before any SQL.
    validated_text(
        &request.source_city_id,
        MAX_CROSS_CITY_TRANSPORT_CITY_LENGTH,
        "source_city_id",
    )?;
    validated_text(
        &request.destination_city_id,
        MAX_CROSS_CITY_TRANSPORT_CITY_LENGTH,
        "destination_city_id",
    )?;
    let identity = CrossCityMessageIdentity::new(
        &request.operation_id,
        request.phase,
        &request.source_city_id,
        &request.destination_city_id,
    )?;
    // Raw caller spellings must already be canonical: the contract normalizes,
    // and a difference here means the caller relied on silent repair.
    if identity.operation_id != request.operation_id
        || identity.source_city_id != request.source_city_id
        || identity.destination_city_id != request.destination_city_id
    {
        return Err(scope_violation("noncanonical_outbox_identity_input"));
    }
    if request.payload.is_empty() {
        return Err(scope_violation("empty_outbox_payload"));
    }
    if request.payload.len() > MAX_CROSS_CITY_TRANSPORT_PAYLOAD_BYTES {
        return Err(scope_violation("oversized_outbox_payload"));
    }
    let payload_digest = cross_city_payload_digest(&request.payload);
    let digest = digest_from_hex(&payload_digest)?;

    let insert = sqlx::query(OUTBOX_INSERT_SQL)
        .bind(&identity.message_id)
        .bind(&identity.operation_id)
        .bind(&identity.source_city_id)
        .bind(&identity.destination_city_id)
        .bind(identity.phase.as_str())
        .bind(digest.as_bytes().to_vec())
        .bind(request.payload.as_slice())
        .bind(CrossCityDeliveryStatus::Pending.as_str())
        .bind(0_i64)
        .execute(&mut **tx)
        .await;
    match insert {
        Ok(result) => {
            if result.rows_affected() != 1 {
                return Err(mapping("outbox_insert_not_applied"));
            }
            Ok(CrossCityOutboxInsertOutcome::Created(Box::new(
                CrossCityOutboxRecord {
                    message_id: identity.message_id.clone(),
                    payload_digest,
                    payload: request.payload.clone(),
                    status: CrossCityDeliveryStatus::Pending,
                    attempts: 0,
                    next_attempt_at_seconds: None,
                    lease_owner: None,
                    lease_expires_at_seconds: None,
                    last_error: None,
                    identity,
                },
            )))
        }
        Err(error) => {
            if !db_unique_violation(&error) {
                return Err(error.into());
            }
            // Duplicate message id: the durable record is immutable evidence.
            // Re-read under the row lock and compare EVERY binding exactly.
            let row = lock_outbox_for_update(tx, &identity.message_id)
                .await?
                .ok_or_else(|| conflict("outbox_duplicate_vanished"))?;
            let existing = decode_outbox_row(row)?;
            if outbox_duplicate_binding_matches(&existing, &identity, &payload_digest) {
                Ok(CrossCityOutboxInsertOutcome::IdempotentExisting(Box::new(
                    existing,
                )))
            } else {
                Err(immutable_conflict("outbox_identity_immutable"))
            }
        }
    }
}

/// Claim the earliest due claimable outbox row under a fresh run-scoped lease
/// token (only its SHA-256 hash persists; expiry is computed server-side and
/// read back), flipping the row to `LEASED` atomically in the install CAS.
///
/// Two — and only two — states are claimable, each in one fully-consistent
/// shape (a partial lease is poisoned storage and is REFUSED by the consistency
/// check, never repaired by an overwriting claim):
/// - `PENDING` with the lease fully cleared and the `next_attempt_at` schedule
///   due: the fresh-claim path (`PENDING -> LEASED`, one worker edge).
/// - `LEASED` with a complete lease (owner + token hash + expiry all present)
///   that has EXPIRED server-side: the expired-lease reclaim for a crashed
///   worker. It is explicitly actor-specific and never bypasses the state
///   machine — the reclaim applies, in order, the two legal worker edges
///   `LEASED -> PENDING` (dead-lease release) then `PENDING -> LEASED` (fresh
///   claim), both through [`CrossCityDeliveryStatus::transition_by_worker`],
///   before the single atomic install CAS re-checks the exact candidate
///   disjunction under the row lock. A LIVE lease can never reach this path:
///   both the candidate and the install predicates require
///   `lease_expires_at <= UTC_TIMESTAMP()`, so live leases are never stolen.
///   The reclaim consumes no attempt budget (the crashed attempt's outcome is
///   unknown, not a known failure; repeated crashes surface as repeated
///   re-claims for the transport layer to observe, never as silent success).
///
/// Returns `Ok(None)` when nothing is claimable; a lost install race is an
/// explicit conflict. The candidate scan does NOT pre-filter on the attempt
/// bound, so an exhausted (`attempts == MAX`) or out-of-range ACTIVE row
/// SURFACES here and FAILS the claim closed (never silently skipped forever):
/// the full decode already refuses an out-of-range counter and any
/// non-quarantined row AT the bound, and the explicit budget gate after the
/// decode re-asserts the same invariant — the row is left untouched for the
/// operator paths (requeue or the lease-free poison quarantine). The candidate
/// row is fully verified before the lease
/// installs: identity derivation, payload-digest binding over the stored
/// bytes, attempt bounds, and status/lease consistency all fail closed on
/// poisoned storage; the readback additionally proves the installed row is
/// `LEASED`.
pub async fn claim_next_outbox_in_tx(
    tx: &mut Transaction<'_, MySql>,
    lease_owner: &str,
    lease_seconds: i64,
) -> Result<Option<CrossCityOutboxLeaseGrant>, CrossCityTransportRepositoryError> {
    validate_transport_lease_material(lease_owner, lease_seconds)?;
    let row: Option<OutboxRow> = sqlx::query_as(OUTBOX_CLAIM_CANDIDATE_SQL)
        .fetch_optional(&mut **tx)
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    // FULL poison decode of the LOCKED candidate — byte-identical validation
    // to every record-returning path (identity derivation, token-hash
    // BINARY(32), owner canonicality, payload bounds and digest binding,
    // last_error length, stale-schedule invariants, attempt bounds including
    // the only-QUARANTINED-may-sit-AT-the-bound invariant, status/lease
    // consistency). A poisoned candidate fails closed here and is NEVER
    // overwritten by the expired-lease reclaim; there is no presence-boolean
    // shortcut.
    let record = decode_outbox_row(row)?;
    let CrossCityOutboxRecord {
        message_id,
        identity,
        payload_digest,
        payload,
        status: claimed_status,
        attempts,
        ..
    } = record;
    // Fail-closed budget gate (defense-in-depth; the decode above already
    // refuses a non-quarantined row AT the bound and any out-of-range
    // counter): the install below retains `attempts < MAX`, so an exhausted
    // row is refused HERE with a stable code — surfaced, never silently
    // skipped, never leased.
    if attempts >= MAX_CROSS_CITY_TRANSPORT_ATTEMPTS {
        return Err(mapping("outbox_claim_attempts_exhausted"));
    }
    // Actor-specific, in-lock takeover proof: exactly the guarded worker
    // edges, applied in order AFTER the full decode. The liveness/expiry of
    // the observed lease is enforced server-side by the candidate SELECT and
    // re-checked by the install CAS under the same row lock.
    match claimed_status {
        CrossCityDeliveryStatus::Pending => {
            claimed_status.transition_by_worker(CrossCityDeliveryStatus::Leased)?;
        }
        CrossCityDeliveryStatus::Leased => {
            claimed_status.transition_by_worker(CrossCityDeliveryStatus::Pending)?;
            CrossCityDeliveryStatus::Pending
                .transition_by_worker(CrossCityDeliveryStatus::Leased)?;
        }
        _ => return Err(mapping("outbox_claim_unclaimable_status")),
    }

    let token = CrossCityTransportLeaseToken::new_run_scoped();
    let install = sqlx::query(OUTBOX_CLAIM_INSTALL_SQL)
        .bind(lease_owner)
        .bind(token.token_hash().as_bytes().to_vec())
        .bind(lease_seconds)
        .bind(&message_id)
        .bind(MAX_CROSS_CITY_TRANSPORT_ATTEMPTS)
        .execute(&mut **tx)
        .await?;
    if install.rows_affected() != 1 {
        return Err(conflict("outbox_claim_race"));
    }

    let readback: OutboxClaimReadbackRow = sqlx::query_as(OUTBOX_CLAIM_READBACK_SQL)
        .bind(&message_id)
        .fetch_one(&mut **tx)
        .await?;
    if readback.message_id != message_id
        || readback.operation_id != identity.operation_id
        || readback.source_city_id != identity.source_city_id
        || readback.destination_city_id != identity.destination_city_id
        || CrossCityMessagePhase::parse_str(&readback.phase)? != identity.phase
    {
        return Err(mapping("outbox_claim_identity_drift"));
    }
    // The install must have flipped the row to LEASED: every worker mutation
    // below requires that status, so a missed flip is a hard drift.
    if CrossCityDeliveryStatus::parse_str(&readback.status)? != CrossCityDeliveryStatus::Leased {
        return Err(mapping("outbox_claim_status_drift"));
    }
    let Some(lease_expires_at) = readback.lease_expires_at else {
        return Err(mapping("outbox_claim_expiry_missing"));
    };

    Ok(Some(CrossCityOutboxLeaseGrant {
        message_id,
        identity,
        payload,
        payload_digest,
        attempts,
        lease_owner: lease_owner.to_owned(),
        lease_token: token,
        lease_expires_at_seconds: datetime_to_unix_seconds(lease_expires_at),
    }))
}

/// Extend a live outbox lease with a strict owner + token-hash + server-side
/// liveness CAS. A lost or expired lease is an explicit error — never a silent
/// success.
pub async fn heartbeat_outbox_in_tx(
    tx: &mut Transaction<'_, MySql>,
    proof: &CrossCityTransportLeaseProof,
    extension_seconds: i64,
) -> Result<(), CrossCityTransportRepositoryError> {
    validate_transport_lease_proof(proof)?;
    validate_transport_lease_material(&proof.lease_owner, extension_seconds)?;
    let row = lock_outbox_for_update(tx, &proof.message_id)
        .await?
        .ok_or_else(|| not_found("outbox_row_missing"))?;
    let status = CrossCityDeliveryStatus::parse_str(&row.status)?;
    if status != CrossCityDeliveryStatus::Leased {
        return Err(lease_cas("outbox_heartbeat_requires_leased_status"));
    }
    verify_outbox_lease_material(&row, proof)?;
    let result = sqlx::query(OUTBOX_HEARTBEAT_SQL)
        .bind(extension_seconds)
        .bind(&proof.message_id)
        .bind(&proof.lease_owner)
        .bind(proof.lease_token.token_hash().as_bytes().to_vec())
        .execute(&mut **tx)
        .await?;
    if result.rows_affected() != 1 {
        return Err(lease_cas("outbox_heartbeat_lost_lease"));
    }
    Ok(())
}

/// Complete an outbox delivery as `SUCCEEDED` under a live lease.
///
/// This is a durable status record, NOT an authorization and NOT an
/// acknowledgement: the caller must already hold its own durable/confirmed
/// delivery evidence (e.g. the destination city's durable record). A bare MQ
/// ACK, a boolean, or a cache can never substitute for that evidence, and the
/// only admitted source state is a live `LEASED` row owned by this proof.
pub async fn mark_outbox_succeeded_in_tx(
    tx: &mut Transaction<'_, MySql>,
    proof: &CrossCityTransportLeaseProof,
) -> Result<(), CrossCityTransportRepositoryError> {
    validate_transport_lease_proof(proof)?;
    let row = lock_outbox_for_update(tx, &proof.message_id)
        .await?
        .ok_or_else(|| not_found("outbox_row_missing"))?;
    let status = CrossCityDeliveryStatus::parse_str(&row.status)?;
    status.transition_by_worker(CrossCityDeliveryStatus::Succeeded)?;
    verify_outbox_lease_material(&row, proof)?;
    let result = sqlx::query(OUTBOX_SUCCEED_SQL)
        .bind(&proof.message_id)
        .bind(&proof.lease_owner)
        .bind(proof.lease_token.token_hash().as_bytes().to_vec())
        .execute(&mut **tx)
        .await?;
    if result.rows_affected() != 1 {
        return Err(lease_cas("outbox_succeed_lost_lease"));
    }
    Ok(())
}

/// Report a KNOWN publish failure that already produced no external result.
///
/// Consumes exactly one attempt: with remaining budget the row returns to
/// `PENDING` and is scheduled for retry after the doubling backoff (outbox:
/// `next_attempt_at`, server-computed); when the attempt budget is exhausted
/// the row is quarantined instead (the worker never retries forever, and never
/// silently drops). The reason text is char-truncated into the forensic
/// `last_error` column.
pub async fn fail_outbox_in_tx(
    tx: &mut Transaction<'_, MySql>,
    proof: &CrossCityTransportLeaseProof,
    reason: &str,
) -> Result<CrossCityTransportFailureOutcome, CrossCityTransportRepositoryError> {
    validate_transport_lease_proof(proof)?;
    let reason = validated_reason(reason)?;
    let row = lock_outbox_for_update(tx, &proof.message_id)
        .await?
        .ok_or_else(|| not_found("outbox_row_missing"))?;
    let status = CrossCityDeliveryStatus::parse_str(&row.status)?;
    let budget = resolve_transport_budget(i64::from(row.attempts))?;
    match budget {
        CrossCityTransportBudgetOutcome::Retry {
            new_attempts,
            backoff_seconds,
        } => {
            status.transition_by_worker(CrossCityDeliveryStatus::Pending)?;
            verify_outbox_lease_material(&row, proof)?;
            let result = sqlx::query(OUTBOX_FAIL_RETRY_SQL)
                .bind(new_attempts)
                .bind(backoff_seconds)
                .bind(&reason)
                .bind(&proof.message_id)
                .bind(&proof.lease_owner)
                .bind(proof.lease_token.token_hash().as_bytes().to_vec())
                .bind(i64::from(row.attempts))
                .execute(&mut **tx)
                .await?;
            if result.rows_affected() != 1 {
                return Err(lease_cas("outbox_fail_lost_lease"));
            }
            Ok(CrossCityTransportFailureOutcome::RetryScheduled {
                attempts: new_attempts,
                backoff_seconds,
            })
        }
        CrossCityTransportBudgetOutcome::Exhausted { new_attempts } => {
            status.transition_by_worker(CrossCityDeliveryStatus::Quarantined)?;
            verify_outbox_lease_material(&row, proof)?;
            let result = sqlx::query(OUTBOX_QUARANTINE_SQL)
                .bind(new_attempts)
                .bind(&reason)
                .bind(&proof.message_id)
                .bind(&proof.lease_owner)
                .bind(proof.lease_token.token_hash().as_bytes().to_vec())
                .bind(i64::from(row.attempts))
                .execute(&mut **tx)
                .await?;
            if result.rows_affected() != 1 {
                return Err(lease_cas("outbox_fail_lost_lease"));
            }
            Ok(CrossCityTransportFailureOutcome::Quarantined {
                attempts: new_attempts,
            })
        }
    }
}

/// Gracefully relinquish a live outbox lease WITHOUT consuming the attempt
/// budget (the known failure produced no external result): the row returns to
/// `PENDING` and keeps its existing schedule (which is `NULL` or already due
/// for any row that was claimable).
pub async fn release_outbox_lease_in_tx(
    tx: &mut Transaction<'_, MySql>,
    proof: &CrossCityTransportLeaseProof,
) -> Result<(), CrossCityTransportRepositoryError> {
    validate_transport_lease_proof(proof)?;
    let row = lock_outbox_for_update(tx, &proof.message_id)
        .await?
        .ok_or_else(|| not_found("outbox_row_missing"))?;
    let status = CrossCityDeliveryStatus::parse_str(&row.status)?;
    status.transition_by_worker(CrossCityDeliveryStatus::Pending)?;
    verify_outbox_lease_material(&row, proof)?;
    let result = sqlx::query(OUTBOX_RELEASE_SQL)
        .bind(&proof.message_id)
        .bind(&proof.lease_owner)
        .bind(proof.lease_token.token_hash().as_bytes().to_vec())
        .execute(&mut **tx)
        .await?;
    if result.rows_affected() != 1 {
        return Err(lease_cas("outbox_release_lost_lease"));
    }
    Ok(())
}

/// Quarantine a leased outbox row under a live lease: a deterministic conflict
/// (e.g. a duplicate that disagrees with the recorded binding) or an explicit
/// operator decision. One attempt is consumed — the previous counter must be a
/// valid in-budget value (negative or over-budget poisoned storage fails
/// closed and is never written onward); only the operator requeue (or
/// reconciliation) can move a quarantined row onward.
pub async fn mark_outbox_quarantined_in_tx(
    tx: &mut Transaction<'_, MySql>,
    proof: &CrossCityTransportLeaseProof,
    reason: &str,
) -> Result<(), CrossCityTransportRepositoryError> {
    validate_transport_lease_proof(proof)?;
    let reason = validated_reason(reason)?;
    let row = lock_outbox_for_update(tx, &proof.message_id)
        .await?
        .ok_or_else(|| not_found("outbox_row_missing"))?;
    let status = CrossCityDeliveryStatus::parse_str(&row.status)?;
    status.transition_by_worker(CrossCityDeliveryStatus::Quarantined)?;
    verify_outbox_lease_material(&row, proof)?;
    let current_attempts = validated_attempts(i64::from(row.attempts))?;
    let new_attempts = quarantined_attempt_budget(current_attempts)?;
    let result = sqlx::query(OUTBOX_QUARANTINE_SQL)
        .bind(new_attempts)
        .bind(&reason)
        .bind(&proof.message_id)
        .bind(&proof.lease_owner)
        .bind(proof.lease_token.token_hash().as_bytes().to_vec())
        .bind(current_attempts)
        .execute(&mut **tx)
        .await?;
    if result.rows_affected() != 1 {
        return Err(lease_cas("outbox_quarantine_lost_lease"));
    }
    Ok(())
}

/// Record an UNKNOWN publish outcome (`IN_DOUBT`) under a live lease: a
/// timeout, stream disconnect, or lost connection can never be retried in
/// place, never create a new operation or message id, and never be recorded as
/// `SUCCEEDED`. The worker gives up ownership (the lease is cleared), the
/// attempt budget is NOT consumed, and only the reconcile primitive may
/// resolve the row — each of its targets naming an independently proven fact.
pub async fn mark_outbox_publish_in_doubt_in_tx(
    tx: &mut Transaction<'_, MySql>,
    proof: &CrossCityTransportLeaseProof,
    reason: &str,
) -> Result<(), CrossCityTransportRepositoryError> {
    validate_transport_lease_proof(proof)?;
    let reason = validated_reason(reason)?;
    let row = lock_outbox_for_update(tx, &proof.message_id)
        .await?
        .ok_or_else(|| not_found("outbox_row_missing"))?;
    let status = CrossCityDeliveryStatus::parse_str(&row.status)?;
    status.transition_by_worker(CrossCityDeliveryStatus::InDoubt)?;
    verify_outbox_lease_material(&row, proof)?;
    let result = sqlx::query(OUTBOX_IN_DOUBT_SQL)
        .bind(&reason)
        .bind(&proof.message_id)
        .bind(&proof.lease_owner)
        .bind(proof.lease_token.token_hash().as_bytes().to_vec())
        .execute(&mut **tx)
        .await?;
    if result.rows_affected() != 1 {
        return Err(lease_cas("outbox_in_doubt_lost_lease"));
    }
    Ok(())
}

/// Resolve an `IN_DOUBT` outbox row through the reconcile path — the ONLY way
/// out of `IN_DOUBT`. The outcome names an independently PROVEN fact (not
/// published / proven durable delivery / unresolvable); the repository records
/// the caller's assertion and cannot verify external state itself (residual
/// trust boundary). No lease is required: an `IN_DOUBT` row has no owner, and
/// a row still carrying lease material is poisoned and fails closed. Before
/// the state machine advances at all, the locked row is FULLY poison-decoded —
/// identity derivation, payload-digest binding over the stored bytes, text
/// canonicality, attempt bounds, and status/lease consistency — so a poisoned
/// row is never advanced (in particular, never closed as `SUCCEEDED`).
pub async fn reconcile_outbox_publish_outcome_in_tx(
    tx: &mut Transaction<'_, MySql>,
    message_id: &str,
    outcome: CrossCityTransportReconcileOutcome,
    note: &str,
) -> Result<CrossCityDeliveryStatus, CrossCityTransportRepositoryError> {
    validated_message_id_shape(message_id)?;
    let note = validated_reason(note)?;
    let target = reconcile_target(outcome);
    let row = lock_outbox_for_update(tx, message_id)
        .await?
        .ok_or_else(|| not_found("outbox_row_missing"))?;
    ensure_in_doubt_lease_absent(
        row.lease_owner.is_some(),
        row.lease_token_hash.is_some(),
        row.lease_expires_at.is_some(),
        "outbox",
    )?;
    let record = decode_outbox_row(row)?;
    record.status.transition_by_reconcile(target)?;
    let result = sqlx::query(OUTBOX_RECONCILE_SQL)
        .bind(target.as_str())
        .bind(&note)
        .bind(message_id)
        .execute(&mut **tx)
        .await?;
    if result.rows_affected() != 1 {
        return Err(conflict("outbox_reconcile_race"));
    }
    Ok(target)
}

/// Operator requeue of a `QUARANTINED` outbox row: back to `PENDING` with a
/// FRESH attempt budget (`attempts = 0`), no schedule, and no lease material —
/// immediately claimable. This is the quarantine recovery path; nothing else
/// may move a quarantined row.
pub async fn requeue_quarantined_outbox_in_tx(
    tx: &mut Transaction<'_, MySql>,
    message_id: &str,
) -> Result<CrossCityOutboxRecord, CrossCityTransportRepositoryError> {
    validated_message_id_shape(message_id)?;
    let row = lock_outbox_for_update(tx, message_id)
        .await?
        .ok_or_else(|| not_found("outbox_row_missing"))?;
    let mut record = decode_outbox_row(row)?;
    record
        .status
        .transition_by_operator(CrossCityDeliveryStatus::Pending)?;
    let result = sqlx::query(OUTBOX_REQUEUE_SQL)
        .bind(&record.message_id)
        .execute(&mut **tx)
        .await?;
    if result.rows_affected() != 1 {
        return Err(conflict("outbox_requeue_race"));
    }
    record.status = CrossCityDeliveryStatus::Pending;
    record.attempts = 0;
    record.next_attempt_at_seconds = None;
    record.lease_owner = None;
    record.lease_expires_at_seconds = None;
    Ok(record)
}

/// Lease-free poison quarantine of one OUTBOX row whose FULL decode fails —
/// the operator-path sibling of the worker/lease quarantine, and the onward
/// path for the exhausted/out-of-range rows the claim candidate scan surfaces.
///
/// # Trust boundary (the repository cannot authenticate the operator)
///
/// This repository has no session, token, identity, or policy source of its
/// own and CANNOT authenticate anyone. The caller MUST mint
/// [`CrossCityTransportOperatorAuthorization`] at an AUTHENTICATED boundary —
/// after verifying who the operator is and that the operator is authorized
/// for this administrative action (e.g. via `PolicyEngine.evaluate()`) — and
/// the repository treats that context purely as a forensic assertion,
/// validating only its shape and binding it verbatim into the durable
/// `last_error` marker. Minting it from unauthenticated input is a caller
/// defect this module cannot detect.
///
/// # Contract
///
/// - The exact row is locked `FOR UPDATE` by its stable `message_id`. The
///   path is LEASE-FREE: no lease proof is presented or required, and no
///   lease is created.
/// - The locked row is FULLY poison-decoded first: only a decode FAILURE
///   proves the poison. A healthy row (any fully decodable state, including
///   an already-`QUARANTINED` or an expired-`LEASED` row) is REFUSED
///   untouched — this path never manufactures a quarantine.
/// - A terminal `SUCCEEDED` row is refused even when poisoned: delivered
///   history is never rewritten.
/// - A LIVE lease is never stolen: the UPDATE's WHERE clause re-checks,
///   server-side at write time (no client clock is trusted), that no complete
///   lease is unexpired. Under the held row lock, losing that guard is
///   reported as an explicit live-lease refusal — never a partial write.
/// - Only MUTABLE fields move: status becomes `QUARANTINED` and the lease
///   identity, lease fence, and retry schedule are cleared. The immutable
///   identity/payload/digest evidence, `attempts`, and the `created_at`
///   history are never touched — the poison stays decodable-as-poison for
///   forensics, and [`requeue_quarantined_outbox_in_tx`] (which requires a
///   FULL decode to succeed) deliberately cannot resurrect a
///   poison-quarantined row.
/// - A bounded `poison_quarantine;operator=…;ref=…;reason=…` forensic marker
///   is written into `last_error` ONLY if the operator context and the reason
///   are safe (no control characters, CR/LF, NUL, ANSI escapes, or unsafe
///   line separators, all within bounds); anything unsafe fails the whole
///   request closed BEFORE any SQL and persists nothing. An already
///   quarantined-but-poisoned row may be re-marked: its status is unchanged
///   and only the mutable forensic `last_error` is refreshed.
pub async fn quarantine_poisoned_outbox_in_tx(
    tx: &mut Transaction<'_, MySql>,
    message_id: &str,
    authorization: &CrossCityTransportOperatorAuthorization,
    reason: &str,
) -> Result<(), CrossCityTransportRepositoryError> {
    validated_message_id_shape(message_id)?;
    // Validate the forensic inputs BEFORE touching any row: an unsafe
    // operator context or reason persists nothing and fails closed.
    let marker = poison_quarantine_forensic_marker(authorization, reason)?;
    let row = lock_outbox_for_update(tx, message_id)
        .await?
        .ok_or_else(|| not_found("outbox_row_missing"))?;
    // A terminal SUCCEEDED row is refused even when poisoned: delivered
    // history is never rewritten. An unparseable status string is NOT the
    // terminal status — it is poison and stays quarantine-able.
    if matches!(
        CrossCityDeliveryStatus::parse_str(&row.status),
        Ok(CrossCityDeliveryStatus::Succeeded)
    ) {
        return Err(poison_refused("outbox_poison_quarantine_terminal_row"));
    }
    // Poison proof: the FULL decode must FAIL. A decodable (healthy) row is
    // refused untouched — a quarantine is never manufactured for a row the
    // record codec accepts (this includes healthy expired-LEASED rows, which
    // belong to the claim's reclaim path).
    let raw_status = row.status.clone();
    if decode_outbox_row(row).is_ok() {
        return Err(poison_refused("outbox_poison_quarantine_not_poisoned"));
    }
    // The row is proven poisoned. The UPDATE clears ONLY the mutable
    // lease/schedule/status fields; its WHERE clause re-checks — server-side,
    // at write time — the exact observed status and that no LIVE lease exists
    // (defense-in-depth under the held row lock). A live lease is never
    // stolen; losing the guard is an explicit refusal, never a partial write.
    let result = sqlx::query(OUTBOX_POISON_QUARANTINE_SQL)
        .bind(&marker)
        .bind(message_id)
        .bind(&raw_status)
        .execute(&mut **tx)
        .await?;
    if result.rows_affected() != 1 {
        // Under the held row lock the only way to lose this CAS is the
        // server-side live-lease guard: the row is leased and unexpired.
        return Err(poison_refused("outbox_poison_quarantine_live_lease"));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Inbox primitives
// ─────────────────────────────────────────────────────────────────────────────

/// Durably record one inbound cross-city message (idempotent receive, inside
/// the caller's transaction — the commit is the only durable point).
///
/// The wire `message_id` is verified fail-closed against the identity
/// derivation over `(operation_id, phase, source_city_id -> destination_city_id)`
/// where `destination_city_id` is the receiving city's OWN id (never stored;
/// the schema has no destination column). A duplicate record (same
/// `message_id`) with the SAME operation/source/phase/payload-digest binding
/// returns the idempotent existing record unchanged; ANY binding or digest
/// difference is an immutable conflict — the durable record is never blindly
/// updated.
pub async fn record_inbox_in_tx(
    tx: &mut Transaction<'_, MySql>,
    request: &CrossCityInboxRecordInsert,
) -> Result<CrossCityInboxInsertOutcome, CrossCityTransportRepositoryError> {
    validated_message_id_shape(&request.message_id)?;
    // Repository storage boundary (schema VARCHAR(191)) on BOTH city ids — the
    // destination is derivation input only, but the same fail-closed bound
    // applies; anything the contract would admit and the DB could truncate is
    // refused here, before any SQL.
    validated_text(
        &request.source_city_id,
        MAX_CROSS_CITY_TRANSPORT_CITY_LENGTH,
        "source_city_id",
    )?;
    validated_text(
        &request.destination_city_id,
        MAX_CROSS_CITY_TRANSPORT_CITY_LENGTH,
        "destination_city_id",
    )?;
    let identity = CrossCityMessageIdentity::new(
        &request.operation_id,
        request.phase,
        &request.source_city_id,
        &request.destination_city_id,
    )?;
    if identity.operation_id != request.operation_id
        || identity.source_city_id != request.source_city_id
        || identity.destination_city_id != request.destination_city_id
    {
        return Err(scope_violation("noncanonical_inbox_identity_input"));
    }
    // Fail-closed derivation check: a tampered, misrouted, swapped, or
    // otherwise unbound wire id can never be recorded.
    if identity.message_id != request.message_id {
        return Err(scope_violation("inbox_message_id_derivation_mismatch"));
    }
    // The digest is computed HERE over the exact received bytes — a
    // caller-supplied digest string is never trusted (the inbox does not store
    // the payload, so the digest is the only content evidence it keeps).
    if request.payload.is_empty() {
        return Err(scope_violation("empty_inbox_payload"));
    }
    if request.payload.len() > MAX_CROSS_CITY_TRANSPORT_PAYLOAD_BYTES {
        return Err(scope_violation("oversized_inbox_payload"));
    }
    let payload_digest = cross_city_payload_digest(&request.payload);
    let digest = digest_from_hex(&payload_digest)?;

    let insert = sqlx::query(INBOX_RECORD_INSERT_SQL)
        .bind(&request.message_id)
        .bind(&identity.operation_id)
        .bind(&identity.source_city_id)
        .bind(identity.phase.as_str())
        .bind(digest.as_bytes().to_vec())
        .bind(CrossCityDeliveryStatus::Pending.as_str())
        .bind(0_i64)
        .execute(&mut **tx)
        .await;
    match insert {
        Ok(result) => {
            if result.rows_affected() != 1 {
                return Err(mapping("inbox_record_not_applied"));
            }
            // The durable record carries server-assigned fields (received_at
            // DEFAULT CURRENT_TIMESTAMP); read the row back under the lock so
            // the returned record is the exact durable state, re-validated by
            // the fail-closed decode — never a client-side reconstruction.
            let row = lock_inbox_for_update(tx, &request.message_id)
                .await?
                .ok_or_else(|| mapping("inbox_record_vanished"))?;
            Ok(CrossCityInboxInsertOutcome::Created(Box::new(
                decode_inbox_row(row)?,
            )))
        }
        Err(error) => {
            if !db_unique_violation(&error) {
                return Err(error.into());
            }
            // Duplicate message id: compare operation/source/phase/digest
            // exactly; never blindly update the durable record.
            let row = lock_inbox_for_update(tx, &request.message_id)
                .await?
                .ok_or_else(|| conflict("inbox_duplicate_vanished"))?;
            let existing = decode_inbox_row(row)?;
            if inbox_duplicate_binding_matches(&existing, request, &payload_digest) {
                Ok(CrossCityInboxInsertOutcome::IdempotentExisting(Box::new(
                    existing,
                )))
            } else {
                Err(immutable_conflict("inbox_identity_immutable"))
            }
        }
    }
}

/// Claim the earliest eligible inbox row under a fresh run-scoped lease token,
/// flipping the row to `LEASED` atomically in the install CAS. Eligibility is
/// gated purely by `lease_expires_at` (absent or expired): a row that failed
/// recently carries its backoff fence there and is NOT claimable until the
/// fence passes — there is no `next_attempt_at` column and none is invented.
///
/// Two — and only two — states are claimable, each in one fully-consistent
/// shape (a partial lease is poisoned storage and is REFUSED by the
/// consistency check, never repaired by an overwriting claim):
/// - `PENDING` with owner/token fully cleared and the lease fence passed (or
///   absent): the fresh-claim path (`PENDING -> LEASED`, one worker edge).
/// - `LEASED` with a complete lease (owner + token hash + expiry all present)
///   that has EXPIRED server-side: the expired-lease reclaim for a crashed
///   worker — explicitly actor-specific and never bypassing the state machine:
///   the reclaim applies, in order, the two legal worker edges
///   `LEASED -> PENDING` then `PENDING -> LEASED`, both through
///   [`CrossCityDeliveryStatus::transition_by_worker`], before the single
///   atomic install CAS re-checks the exact candidate disjunction under the
///   row lock. A LIVE lease can never reach this path: both predicates require
///   `lease_expires_at <= UTC_TIMESTAMP()`, so live leases are never stolen.
///   The reclaim consumes no attempt budget (the crashed attempt's outcome is
///   unknown, not a known failure).
///
/// Returns `Ok(None)` when nothing is claimable; a lost install race is an
/// explicit conflict; the readback proves the installed row is `LEASED`. The
/// candidate scan does NOT pre-filter on the attempt bound, so an exhausted
/// (`attempts == MAX`) or out-of-range ACTIVE row SURFACES here and FAILS the
/// claim closed (never silently skipped forever): the full decode already
/// refuses an out-of-range counter and any non-quarantined row AT the bound,
/// and the explicit budget gate after the decode re-asserts the same
/// invariant — the row is left untouched for the operator paths (requeue or
/// the lease-free poison quarantine).
pub async fn claim_inbox_in_tx(
    tx: &mut Transaction<'_, MySql>,
    lease_owner: &str,
    lease_seconds: i64,
) -> Result<Option<CrossCityInboxLeaseGrant>, CrossCityTransportRepositoryError> {
    validate_transport_lease_material(lease_owner, lease_seconds)?;
    let row: Option<InboxRow> = sqlx::query_as(INBOX_CLAIM_CANDIDATE_SQL)
        .fetch_optional(&mut **tx)
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    // FULL poison decode of the LOCKED candidate — identical validation to
    // every record-returning path (message-id digest shape, canonical
    // operation/source, phase parse, token-hash BINARY(32), owner
    // canonicality, attempt bounds including the
    // only-QUARANTINED-may-sit-AT-the-bound invariant, the one-time
    // processed_at invariant, last_error length, and status/lease
    // consistency). A poisoned candidate fails closed here and is NEVER
    // overwritten by the expired-lease reclaim; there is no presence-boolean
    // shortcut. For a PENDING inbox row the lease_expires_at fence is
    // legitimate (it is the backoff schedule); the candidate predicate
    // already required it to have passed.
    let record = decode_inbox_row(row)?;
    let CrossCityInboxRecord {
        message_id,
        operation_id,
        phase,
        source_city_id,
        payload_digest,
        status: claimed_status,
        attempts,
        ..
    } = record;
    // Fail-closed budget gate (defense-in-depth; the decode above already
    // refuses a non-quarantined row AT the bound and any out-of-range
    // counter): the install below retains `attempts < MAX`, so an exhausted
    // row is refused HERE with a stable code — surfaced, never silently
    // skipped, never leased.
    if attempts >= MAX_CROSS_CITY_TRANSPORT_ATTEMPTS {
        return Err(mapping("inbox_claim_attempts_exhausted"));
    }
    // Actor-specific, in-lock takeover proof: exactly the guarded worker
    // edges, applied in order AFTER the full decode (see the doc comment for
    // the reclaim contract).
    match claimed_status {
        CrossCityDeliveryStatus::Pending => {
            claimed_status.transition_by_worker(CrossCityDeliveryStatus::Leased)?;
        }
        CrossCityDeliveryStatus::Leased => {
            claimed_status.transition_by_worker(CrossCityDeliveryStatus::Pending)?;
            CrossCityDeliveryStatus::Pending
                .transition_by_worker(CrossCityDeliveryStatus::Leased)?;
        }
        _ => return Err(mapping("inbox_claim_unclaimable_status")),
    }

    let token = CrossCityTransportLeaseToken::new_run_scoped();
    let install = sqlx::query(INBOX_CLAIM_INSTALL_SQL)
        .bind(lease_owner)
        .bind(token.token_hash().as_bytes().to_vec())
        .bind(lease_seconds)
        .bind(&message_id)
        .bind(MAX_CROSS_CITY_TRANSPORT_ATTEMPTS)
        .execute(&mut **tx)
        .await?;
    if install.rows_affected() != 1 {
        return Err(conflict("inbox_claim_race"));
    }

    let readback: InboxClaimReadbackRow = sqlx::query_as(INBOX_CLAIM_READBACK_SQL)
        .bind(&message_id)
        .fetch_one(&mut **tx)
        .await?;
    if readback.message_id != message_id
        || readback.operation_id != operation_id
        || readback.source_city_id != source_city_id
        || CrossCityMessagePhase::parse_str(&readback.phase)? != phase
    {
        return Err(mapping("inbox_claim_identity_drift"));
    }
    // The install must have flipped the row to LEASED: every worker mutation
    // below requires that status, so a missed flip is a hard drift.
    if CrossCityDeliveryStatus::parse_str(&readback.status)? != CrossCityDeliveryStatus::Leased {
        return Err(mapping("inbox_claim_status_drift"));
    }
    let Some(lease_expires_at) = readback.lease_expires_at else {
        return Err(mapping("inbox_claim_expiry_missing"));
    };

    Ok(Some(CrossCityInboxLeaseGrant {
        message_id,
        operation_id,
        phase,
        source_city_id,
        payload_digest,
        attempts,
        lease_owner: lease_owner.to_owned(),
        lease_token: token,
        lease_expires_at_seconds: datetime_to_unix_seconds(lease_expires_at),
    }))
}

/// Extend a live inbox lease with a strict owner + token-hash + server-side
/// liveness CAS. A lost or expired lease is an explicit error — never a silent
/// success.
pub async fn heartbeat_inbox_in_tx(
    tx: &mut Transaction<'_, MySql>,
    proof: &CrossCityTransportLeaseProof,
    extension_seconds: i64,
) -> Result<(), CrossCityTransportRepositoryError> {
    validate_transport_lease_proof(proof)?;
    validate_transport_lease_material(&proof.lease_owner, extension_seconds)?;
    let row = lock_inbox_for_update(tx, &proof.message_id)
        .await?
        .ok_or_else(|| not_found("inbox_row_missing"))?;
    let status = CrossCityDeliveryStatus::parse_str(&row.status)?;
    if status != CrossCityDeliveryStatus::Leased {
        return Err(lease_cas("inbox_heartbeat_requires_leased_status"));
    }
    verify_inbox_lease_material(&row, proof)?;
    let result = sqlx::query(INBOX_HEARTBEAT_SQL)
        .bind(extension_seconds)
        .bind(&proof.message_id)
        .bind(&proof.lease_owner)
        .bind(proof.lease_token.token_hash().as_bytes().to_vec())
        .execute(&mut **tx)
        .await?;
    if result.rows_affected() != 1 {
        return Err(lease_cas("inbox_heartbeat_lost_lease"));
    }
    Ok(())
}

/// Close an inbound message as processed (`SUCCEEDED`) under a live lease.
///
/// This records that the destination city durably processed the message; it is
/// a durable status record, NOT an authorization and NOT an acknowledgement. A
/// bare MQ ACK, a boolean, or a cache can never substitute for the caller's
/// own durable processing evidence, and the only admitted source state is a
/// live `LEASED` row owned by this proof.
pub async fn mark_inbox_processed_in_tx(
    tx: &mut Transaction<'_, MySql>,
    proof: &CrossCityTransportLeaseProof,
) -> Result<(), CrossCityTransportRepositoryError> {
    validate_transport_lease_proof(proof)?;
    let row = lock_inbox_for_update(tx, &proof.message_id)
        .await?
        .ok_or_else(|| not_found("inbox_row_missing"))?;
    let status = CrossCityDeliveryStatus::parse_str(&row.status)?;
    status.transition_by_worker(CrossCityDeliveryStatus::Succeeded)?;
    verify_inbox_lease_material(&row, proof)?;
    let result = sqlx::query(INBOX_PROCESSED_SQL)
        .bind(&proof.message_id)
        .bind(&proof.lease_owner)
        .bind(proof.lease_token.token_hash().as_bytes().to_vec())
        .execute(&mut **tx)
        .await?;
    if result.rows_affected() != 1 {
        return Err(lease_cas("inbox_processed_lost_lease"));
    }
    Ok(())
}

/// Report a KNOWN processing failure that already produced no external result.
///
/// Consumes exactly one attempt: with remaining budget the row returns to
/// `PENDING` and its `lease_expires_at` is retained as the server-computed
/// backoff fence (`UTC_TIMESTAMP() + backoff`) — the inbox's
/// next-eligible-time semantics, since there is no `next_attempt_at` column.
/// When the attempt budget is exhausted the row is quarantined instead. The
/// reason text is char-truncated into the forensic `last_error` column.
pub async fn fail_inbox_in_tx(
    tx: &mut Transaction<'_, MySql>,
    proof: &CrossCityTransportLeaseProof,
    reason: &str,
) -> Result<CrossCityTransportFailureOutcome, CrossCityTransportRepositoryError> {
    validate_transport_lease_proof(proof)?;
    let reason = validated_reason(reason)?;
    let row = lock_inbox_for_update(tx, &proof.message_id)
        .await?
        .ok_or_else(|| not_found("inbox_row_missing"))?;
    let status = CrossCityDeliveryStatus::parse_str(&row.status)?;
    let budget = resolve_transport_budget(i64::from(row.attempts))?;
    match budget {
        CrossCityTransportBudgetOutcome::Retry {
            new_attempts,
            backoff_seconds,
        } => {
            status.transition_by_worker(CrossCityDeliveryStatus::Pending)?;
            verify_inbox_lease_material(&row, proof)?;
            let result = sqlx::query(INBOX_FAIL_RETRY_SQL)
                .bind(new_attempts)
                .bind(backoff_seconds)
                .bind(&reason)
                .bind(&proof.message_id)
                .bind(&proof.lease_owner)
                .bind(proof.lease_token.token_hash().as_bytes().to_vec())
                .bind(i64::from(row.attempts))
                .execute(&mut **tx)
                .await?;
            if result.rows_affected() != 1 {
                return Err(lease_cas("inbox_fail_lost_lease"));
            }
            Ok(CrossCityTransportFailureOutcome::RetryScheduled {
                attempts: new_attempts,
                backoff_seconds,
            })
        }
        CrossCityTransportBudgetOutcome::Exhausted { new_attempts } => {
            status.transition_by_worker(CrossCityDeliveryStatus::Quarantined)?;
            verify_inbox_lease_material(&row, proof)?;
            let result = sqlx::query(INBOX_QUARANTINE_SQL)
                .bind(new_attempts)
                .bind(&reason)
                .bind(&proof.message_id)
                .bind(&proof.lease_owner)
                .bind(proof.lease_token.token_hash().as_bytes().to_vec())
                .bind(i64::from(row.attempts))
                .execute(&mut **tx)
                .await?;
            if result.rows_affected() != 1 {
                return Err(lease_cas("inbox_fail_lost_lease"));
            }
            Ok(CrossCityTransportFailureOutcome::Quarantined {
                attempts: new_attempts,
            })
        }
    }
}

/// Quarantine a leased inbox row under a live lease: a deterministic conflict
/// (e.g. a duplicate record that disagrees with the recorded binding) or an
/// explicit operator decision. One attempt is consumed — the previous counter
/// must be a valid in-budget value (negative or over-budget poisoned storage
/// fails closed and is never written onward); only the operator requeue (or
/// reconciliation) can move a quarantined row onward.
pub async fn mark_inbox_quarantined_in_tx(
    tx: &mut Transaction<'_, MySql>,
    proof: &CrossCityTransportLeaseProof,
    reason: &str,
) -> Result<(), CrossCityTransportRepositoryError> {
    validate_transport_lease_proof(proof)?;
    let reason = validated_reason(reason)?;
    let row = lock_inbox_for_update(tx, &proof.message_id)
        .await?
        .ok_or_else(|| not_found("inbox_row_missing"))?;
    let status = CrossCityDeliveryStatus::parse_str(&row.status)?;
    status.transition_by_worker(CrossCityDeliveryStatus::Quarantined)?;
    verify_inbox_lease_material(&row, proof)?;
    let current_attempts = validated_attempts(i64::from(row.attempts))?;
    let new_attempts = quarantined_attempt_budget(current_attempts)?;
    let result = sqlx::query(INBOX_QUARANTINE_SQL)
        .bind(new_attempts)
        .bind(&reason)
        .bind(&proof.message_id)
        .bind(&proof.lease_owner)
        .bind(proof.lease_token.token_hash().as_bytes().to_vec())
        .bind(current_attempts)
        .execute(&mut **tx)
        .await?;
    if result.rows_affected() != 1 {
        return Err(lease_cas("inbox_quarantine_lost_lease"));
    }
    Ok(())
}

/// Record an UNKNOWN processing outcome (`IN_DOUBT`) under a live lease: a
/// timeout, stream disconnect, or lost connection can never be retried in
/// place, never create a new operation or message id, and never be recorded as
/// processed. The worker gives up ownership (the lease is cleared), the
/// attempt budget is NOT consumed, and only the reconcile primitive may
/// resolve the row — each of its targets naming an independently proven fact.
pub async fn mark_inbox_process_in_doubt_in_tx(
    tx: &mut Transaction<'_, MySql>,
    proof: &CrossCityTransportLeaseProof,
    reason: &str,
) -> Result<(), CrossCityTransportRepositoryError> {
    validate_transport_lease_proof(proof)?;
    let reason = validated_reason(reason)?;
    let row = lock_inbox_for_update(tx, &proof.message_id)
        .await?
        .ok_or_else(|| not_found("inbox_row_missing"))?;
    let status = CrossCityDeliveryStatus::parse_str(&row.status)?;
    status.transition_by_worker(CrossCityDeliveryStatus::InDoubt)?;
    verify_inbox_lease_material(&row, proof)?;
    let result = sqlx::query(INBOX_IN_DOUBT_SQL)
        .bind(&reason)
        .bind(&proof.message_id)
        .bind(&proof.lease_owner)
        .bind(proof.lease_token.token_hash().as_bytes().to_vec())
        .execute(&mut **tx)
        .await?;
    if result.rows_affected() != 1 {
        return Err(lease_cas("inbox_in_doubt_lost_lease"));
    }
    Ok(())
}

/// Resolve an `IN_DOUBT` inbox row through the reconcile path — the ONLY way
/// out of `IN_DOUBT`. The outcome names an independently PROVEN fact (not
/// processed / proven durable processing / unresolvable); the repository
/// records the caller's assertion and cannot verify external state itself
/// (residual trust boundary). No lease is required: an `IN_DOUBT` row has no
/// owner, and a row still carrying lease material is poisoned and fails
/// closed. Before the state machine advances at all, the locked row is FULLY
/// poison-decoded (identity text, digest shape, attempt bounds, processed_at
/// and status/lease consistency), so a poisoned row is never advanced — in
/// particular, never closed as `SUCCEEDED`. The `Applied` resolution is the
/// processed fact: the row is closed exactly once WITH the server-side
/// `processed_at` stamp every `SUCCEEDED` row must carry.
pub async fn reconcile_inbox_process_outcome_in_tx(
    tx: &mut Transaction<'_, MySql>,
    message_id: &str,
    outcome: CrossCityTransportReconcileOutcome,
    note: &str,
) -> Result<CrossCityDeliveryStatus, CrossCityTransportRepositoryError> {
    validated_message_id_shape(message_id)?;
    let note = validated_reason(note)?;
    let target = reconcile_target(outcome);
    let row = lock_inbox_for_update(tx, message_id)
        .await?
        .ok_or_else(|| not_found("inbox_row_missing"))?;
    ensure_in_doubt_lease_absent(
        row.lease_owner.is_some(),
        row.lease_token_hash.is_some(),
        row.lease_expires_at.is_some(),
        "inbox",
    )?;
    let record = decode_inbox_row(row)?;
    record.status.transition_by_reconcile(target)?;
    let update = match outcome {
        CrossCityTransportReconcileOutcome::Applied => sqlx::query(INBOX_RECONCILE_APPLIED_SQL)
            .bind(&note)
            .bind(message_id),
        _ => sqlx::query(INBOX_RECONCILE_SQL)
            .bind(target.as_str())
            .bind(&note)
            .bind(message_id),
    };
    let result = update.execute(&mut **tx).await?;
    if result.rows_affected() != 1 {
        return Err(conflict("inbox_reconcile_race"));
    }
    Ok(target)
}

/// Operator requeue of a `QUARANTINED` inbox row: back to `PENDING` with a
/// FRESH attempt budget (`attempts = 0`) and a cleared lease fence —
/// immediately claimable. `processed_at` history is never rewritten; the
/// forensic `last_error` is kept.
pub async fn requeue_quarantined_inbox_in_tx(
    tx: &mut Transaction<'_, MySql>,
    message_id: &str,
) -> Result<CrossCityInboxRecord, CrossCityTransportRepositoryError> {
    validated_message_id_shape(message_id)?;
    let row = lock_inbox_for_update(tx, message_id)
        .await?
        .ok_or_else(|| not_found("inbox_row_missing"))?;
    let mut record = decode_inbox_row(row)?;
    record
        .status
        .transition_by_operator(CrossCityDeliveryStatus::Pending)?;
    let result = sqlx::query(INBOX_REQUEUE_SQL)
        .bind(&record.message_id)
        .execute(&mut **tx)
        .await?;
    if result.rows_affected() != 1 {
        return Err(conflict("inbox_requeue_race"));
    }
    record.status = CrossCityDeliveryStatus::Pending;
    record.attempts = 0;
    record.lease_owner = None;
    record.lease_expires_at_seconds = None;
    Ok(record)
}

/// Lease-free poison quarantine of one INBOX row whose FULL decode fails —
/// the operator-path sibling of the worker/lease quarantine, and the onward
/// path for the exhausted/out-of-range rows the claim candidate scan surfaces.
///
/// # Trust boundary (the repository cannot authenticate the operator)
///
/// This repository has no session, token, identity, or policy source of its
/// own and CANNOT authenticate anyone. The caller MUST mint
/// [`CrossCityTransportOperatorAuthorization`] at an AUTHENTICATED boundary —
/// after verifying who the operator is and that the operator is authorized
/// for this administrative action (e.g. via `PolicyEngine.evaluate()`) — and
/// the repository treats that context purely as a forensic assertion,
/// validating only its shape and binding it verbatim into the durable
/// `last_error` marker. Minting it from unauthenticated input is a caller
/// defect this module cannot detect.
///
/// # Contract
///
/// - The exact row is locked `FOR UPDATE` by its stable `message_id`. The
///   path is LEASE-FREE: no lease proof is presented or required, and no
///   lease is created.
/// - The locked row is FULLY poison-decoded first: only a decode FAILURE
///   proves the poison. A healthy row (any fully decodable state, including
///   an already-`QUARANTINED` or an expired-`LEASED` row) is REFUSED
///   untouched — this path never manufactures a quarantine.
/// - A terminal `SUCCEEDED` row is refused even when poisoned: processed
///   history is never rewritten.
/// - A LIVE lease is never stolen: the UPDATE's WHERE clause re-checks,
///   server-side at write time (no client clock is trusted), that no complete
///   lease is unexpired. Under the held row lock, losing that guard is
///   reported as an explicit live-lease refusal — never a partial write.
/// - Only MUTABLE fields move: status becomes `QUARANTINED` and the lease
///   identity and fence are cleared. The immutable identity/digest evidence,
///   `attempts`, and the `received_at`/`processed_at` history are never
///   touched — the poison stays decodable-as-poison for forensics, and
///   [`requeue_quarantined_inbox_in_tx`] (which requires a FULL decode to
///   succeed) deliberately cannot resurrect a poison-quarantined row.
/// - A bounded `poison_quarantine;operator=…;ref=…;reason=…` forensic marker
///   is written into `last_error` ONLY if the operator context and the reason
///   are safe (no control characters, CR/LF, NUL, ANSI escapes, or unsafe
///   line separators, all within bounds); anything unsafe fails the whole
///   request closed BEFORE any SQL and persists nothing. An already
///   quarantined-but-poisoned row may be re-marked: its status is unchanged
///   and only the mutable forensic `last_error` is refreshed.
pub async fn quarantine_poisoned_inbox_in_tx(
    tx: &mut Transaction<'_, MySql>,
    message_id: &str,
    authorization: &CrossCityTransportOperatorAuthorization,
    reason: &str,
) -> Result<(), CrossCityTransportRepositoryError> {
    validated_message_id_shape(message_id)?;
    // Validate the forensic inputs BEFORE touching any row: an unsafe
    // operator context or reason persists nothing and fails closed.
    let marker = poison_quarantine_forensic_marker(authorization, reason)?;
    let row = lock_inbox_for_update(tx, message_id)
        .await?
        .ok_or_else(|| not_found("inbox_row_missing"))?;
    // A terminal SUCCEEDED row is refused even when poisoned: processed
    // history is never rewritten. An unparseable status string is NOT the
    // terminal status — it is poison and stays quarantine-able.
    if matches!(
        CrossCityDeliveryStatus::parse_str(&row.status),
        Ok(CrossCityDeliveryStatus::Succeeded)
    ) {
        return Err(poison_refused("inbox_poison_quarantine_terminal_row"));
    }
    // Poison proof: the FULL decode must FAIL. A decodable (healthy) row is
    // refused untouched — a quarantine is never manufactured for a row the
    // record codec accepts (this includes healthy expired-LEASED rows, which
    // belong to the claim's reclaim path).
    let raw_status = row.status.clone();
    if decode_inbox_row(row).is_ok() {
        return Err(poison_refused("inbox_poison_quarantine_not_poisoned"));
    }
    // The row is proven poisoned. The UPDATE clears ONLY the mutable
    // lease/status fields; its WHERE clause re-checks — server-side, at
    // write time — the exact observed status and that no LIVE lease exists
    // (defense-in-depth under the held row lock). A live lease is never
    // stolen; losing the guard is an explicit refusal, never a partial write.
    let result = sqlx::query(INBOX_POISON_QUARANTINE_SQL)
        .bind(&marker)
        .bind(message_id)
        .bind(&raw_status)
        .execute(&mut **tx)
        .await?;
    if result.rows_affected() != 1 {
        // Under the held row lock the only way to lose this CAS is the
        // server-side live-lease guard: the row is leased and unexpired.
        return Err(poison_refused("inbox_poison_quarantine_live_lease"));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests (pure: no DB, no network, no external system)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const OPERATION_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
    const CITY_ALPHA: &str = "city-alpha";
    const CITY_BETA: &str = "city-beta";

    /// Golden message id of (OPERATION_ID, VOTE, city-alpha -> city-beta),
    /// pinned so the derivation can never drift silently.
    const GOLDEN_VOTE_ALPHA_TO_BETA: &str =
        "68f01c7fad252d78c9201e4c95ac6ac45e57196b594bbf0d1cc7df83144d79b1";
    /// Golden message id of the same tuple with phase PREPARE.
    const GOLDEN_PREPARE_ALPHA_TO_BETA: &str =
        "f7dcc62a12cce77ff746c7194af0f112b9d8a4f30c4c8bccd3274513a9eeca6f";
    /// Golden message id of the SWAPPED direction (city-beta -> city-alpha):
    /// a different message, never a re-spelling of the first.
    const GOLDEN_VOTE_SWAPPED: &str =
        "e7daf97f27596f89b6d2c30852facf882e96936f2d89b168b2c8d7c7c704ebea";

    fn vote_identity() -> CrossCityMessageIdentity {
        CrossCityMessageIdentity::new(
            OPERATION_ID,
            CrossCityMessagePhase::Vote,
            CITY_ALPHA,
            CITY_BETA,
        )
        .expect("canonical identity")
    }

    fn outbox_record(identity: &CrossCityMessageIdentity, digest: &str) -> CrossCityOutboxRecord {
        CrossCityOutboxRecord {
            message_id: identity.message_id.clone(),
            identity: identity.clone(),
            payload_digest: digest.to_owned(),
            payload: b"payload".to_vec(),
            status: CrossCityDeliveryStatus::Pending,
            attempts: 0,
            next_attempt_at_seconds: None,
            lease_owner: None,
            lease_expires_at_seconds: None,
            last_error: None,
        }
    }

    fn inbox_record(
        message_id: &str,
        operation_id: &str,
        phase: CrossCityMessagePhase,
        source: &str,
        digest: &str,
    ) -> CrossCityInboxRecord {
        CrossCityInboxRecord {
            message_id: message_id.to_owned(),
            operation_id: operation_id.to_owned(),
            phase,
            source_city_id: source.to_owned(),
            payload_digest: digest.to_owned(),
            status: CrossCityDeliveryStatus::Pending,
            attempts: 0,
            lease_owner: None,
            lease_expires_at_seconds: None,
            received_at_seconds: 1_000,
            processed_at_seconds: None,
            last_error: None,
        }
    }

    fn inbox_request(
        message_id: &str,
        operation_id: &str,
        phase: CrossCityMessagePhase,
        source: &str,
        payload: &[u8],
    ) -> CrossCityInboxRecordInsert {
        CrossCityInboxRecordInsert {
            message_id: message_id.to_owned(),
            operation_id: operation_id.to_owned(),
            phase,
            source_city_id: source.to_owned(),
            destination_city_id: CITY_BETA.to_owned(),
            payload: payload.to_vec(),
        }
    }

    const DIGEST_A: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const DIGEST_B: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    // ── identity golden / stability / direction ─────────────────────────────

    #[test]
    fn outbox_message_identity_is_golden_stable_and_direction_sensitive() {
        let identity = vote_identity();
        assert_eq!(identity.message_id, GOLDEN_VOTE_ALPHA_TO_BETA);
        assert!(identity.is_canonical());
        identity.validate().expect("self-consistent");
        // Stable across independent reconstruction.
        assert_eq!(vote_identity(), identity);
        // The phase is part of the identity tuple.
        let prepare = CrossCityMessageIdentity::new(
            OPERATION_ID,
            CrossCityMessagePhase::Prepare,
            CITY_ALPHA,
            CITY_BETA,
        )
        .expect("canonical identity");
        assert_eq!(prepare.message_id, GOLDEN_PREPARE_ALPHA_TO_BETA);
        assert_ne!(prepare.message_id, identity.message_id);
        // A swapped route is a DIFFERENT message id — and the repository's
        // positional binding compare must treat it as a different message,
        // never as an idempotent replay of the original.
        let swapped = CrossCityMessageIdentity::new(
            OPERATION_ID,
            CrossCityMessagePhase::Vote,
            CITY_BETA,
            CITY_ALPHA,
        )
        .expect("canonical identity");
        assert_eq!(swapped.message_id, GOLDEN_VOTE_SWAPPED);
        assert_ne!(swapped.message_id, identity.message_id);
    }

    #[test]
    fn payload_digest_is_raw_sha256_over_the_exact_bytes() {
        // Independent SHA-256 test vectors (raw, domain-free): the contract
        // helper must be plain SHA-256 over the exact byte slice — no domain
        // header, no canonicalization, no re-serialization.
        assert_eq!(
            cross_city_payload_digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            cross_city_payload_digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // Length-delimited-looking bytes are digested RAW (no encoder runs).
        let raw = b"\x1f4:VOTE\x1f10:city-alpha";
        let expected: [u8; 32] = Sha256::digest(raw).into();
        assert_eq!(cross_city_payload_digest(raw), hex::encode(expected));
        // Any single-byte change changes the digest.
        assert_ne!(
            cross_city_payload_digest(b"payload-1"),
            cross_city_payload_digest(b"payload-2")
        );
    }

    #[test]
    fn self_route_is_refused_and_poisoned_direction_fails_closed() {
        let error = CrossCityMessageIdentity::new(
            OPERATION_ID,
            CrossCityMessagePhase::Vote,
            CITY_ALPHA,
            CITY_ALPHA,
        )
        .expect_err("self-routed message must be refused");
        assert!(matches!(
            error,
            astral_types::CrossCityContractError::SelfRoutedMessage { .. }
        ));
        // A stored row whose message_id does not equal the derivation of its
        // own tuple (here: the id of the swapped direction over alpha/beta
        // fields) is poisoned and fails closed — the direction can never be
        // silently re-interpreted.
        let identity = vote_identity();
        let error = decode_transport_message_identity(
            &identity.operation_id,
            identity.phase.as_str(),
            CITY_ALPHA,
            CITY_BETA,
            GOLDEN_VOTE_SWAPPED,
        )
        .expect_err("stored message_id must equal its own derivation");
        assert!(error.to_string().contains("poisoned_message_id"));
        // The honest decode succeeds and round-trips the identity.
        let decoded = decode_transport_message_identity(
            &identity.operation_id,
            identity.phase.as_str(),
            CITY_ALPHA,
            CITY_BETA,
            &identity.message_id,
        )
        .expect("honest stored identity decodes");
        assert_eq!(decoded, identity);
    }

    // ── duplicate-binding comparison (idempotent vs immutable conflict) ────

    #[test]
    fn outbox_duplicate_same_binding_is_idempotent_and_any_mismatch_is_conflict() {
        let identity = vote_identity();
        assert!(outbox_duplicate_binding_matches(
            &outbox_record(&identity, DIGEST_A),
            &identity,
            DIGEST_A
        ));
        // Every binding field participates: a difference in any one of them is
        // an immutable conflict, never an overwrite of evidence/payload.
        let digest_mismatch = {
            let mut record = outbox_record(&identity, DIGEST_A);
            record.payload_digest = DIGEST_B.to_owned();
            record
        };
        assert!(!outbox_duplicate_binding_matches(
            &digest_mismatch,
            &identity,
            DIGEST_A
        ));
        let operation_mismatch = CrossCityMessageIdentity::new(
            "0b9e6b1e-3d0a-4d0f-8d5f-2f1a0b9c8d7e",
            CrossCityMessagePhase::Vote,
            CITY_ALPHA,
            CITY_BETA,
        )
        .expect("canonical identity");
        assert!(!outbox_duplicate_binding_matches(
            &outbox_record(&identity, DIGEST_A),
            &operation_mismatch,
            DIGEST_A
        ));
        let phase_mismatch = CrossCityMessageIdentity::new(
            OPERATION_ID,
            CrossCityMessagePhase::Prepare,
            CITY_ALPHA,
            CITY_BETA,
        )
        .expect("canonical identity");
        assert!(!outbox_duplicate_binding_matches(
            &outbox_record(&identity, DIGEST_A),
            &phase_mismatch,
            DIGEST_A
        ));
        let source_mismatch = CrossCityMessageIdentity::new(
            OPERATION_ID,
            CrossCityMessagePhase::Vote,
            "city-gamma",
            CITY_BETA,
        )
        .expect("canonical identity");
        assert!(!outbox_duplicate_binding_matches(
            &outbox_record(&identity, DIGEST_A),
            &source_mismatch,
            DIGEST_A
        ));
        let destination_mismatch = CrossCityMessageIdentity::new(
            OPERATION_ID,
            CrossCityMessagePhase::Vote,
            CITY_ALPHA,
            "city-delta",
        )
        .expect("canonical identity");
        assert!(!outbox_duplicate_binding_matches(
            &outbox_record(&identity, DIGEST_A),
            &destination_mismatch,
            DIGEST_A
        ));
    }

    #[test]
    fn inbox_duplicate_same_binding_is_idempotent_and_any_mismatch_is_conflict() {
        // The request carries RAW bytes; the compared digest is what the
        // repository computes over them — never a caller-supplied string.
        let payload = b"delivered-payload";
        let computed_digest = cross_city_payload_digest(payload);
        let request = inbox_request(
            GOLDEN_VOTE_ALPHA_TO_BETA,
            OPERATION_ID,
            CrossCityMessagePhase::Vote,
            CITY_ALPHA,
            payload,
        );
        let existing = inbox_record(
            GOLDEN_VOTE_ALPHA_TO_BETA,
            OPERATION_ID,
            CrossCityMessagePhase::Vote,
            CITY_ALPHA,
            &computed_digest,
        );
        assert!(inbox_duplicate_binding_matches(
            &existing,
            &request,
            &computed_digest
        ));
        // Different raw bytes compute a different digest: an immutable
        // conflict, never an update of the durable record.
        let other_digest = cross_city_payload_digest(b"tampered-payload");
        assert_ne!(other_digest, computed_digest);
        assert!(!inbox_duplicate_binding_matches(
            &existing,
            &request,
            &other_digest
        ));
        // Operation mismatch.
        assert!(!inbox_duplicate_binding_matches(
            &existing,
            &inbox_request(
                GOLDEN_VOTE_ALPHA_TO_BETA,
                "0b9e6b1e-3d0a-4d0f-8d5f-2f1a0b9c8d7e",
                CrossCityMessagePhase::Vote,
                CITY_ALPHA,
                payload
            ),
            &computed_digest
        ));
        // Phase mismatch.
        assert!(!inbox_duplicate_binding_matches(
            &existing,
            &inbox_request(
                GOLDEN_VOTE_ALPHA_TO_BETA,
                OPERATION_ID,
                CrossCityMessagePhase::Prepare,
                CITY_ALPHA,
                payload
            ),
            &computed_digest
        ));
        // Source mismatch (direction is positional: the inbox never treats a
        // different claimed source as the same message).
        assert!(!inbox_duplicate_binding_matches(
            &existing,
            &inbox_request(
                GOLDEN_VOTE_ALPHA_TO_BETA,
                OPERATION_ID,
                CrossCityMessagePhase::Vote,
                "city-gamma",
                payload
            ),
            &computed_digest
        ));
    }

    #[test]
    fn inbox_record_digest_is_computed_over_raw_bytes_never_trusted() {
        // Parity with the raw SHA-256 vectors: the record path derives the
        // stored digest with the same contract function over the exact bytes.
        assert_eq!(
            cross_city_payload_digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // A city id at the schema boundary is admitted; one byte beyond is
        // refused by the repository's own 191-byte check (both insert paths
        // enforce it before any SQL — the contract alone would admit it).
        let boundary_city = "c".repeat(MAX_CROSS_CITY_TRANSPORT_CITY_LENGTH);
        assert!(
            validated_text(&boundary_city, MAX_CROSS_CITY_TRANSPORT_CITY_LENGTH, "city").is_ok()
        );
        let oversized_city = "c".repeat(MAX_CROSS_CITY_TRANSPORT_CITY_LENGTH + 1);
        assert!(validated_text(
            &oversized_city,
            MAX_CROSS_CITY_TRANSPORT_CITY_LENGTH,
            "city"
        )
        .is_err());
    }

    #[test]
    fn inbox_message_id_must_equal_the_derivation_over_the_local_city() {
        let identity = CrossCityMessageIdentity::new(
            OPERATION_ID,
            CrossCityMessagePhase::Vote,
            CITY_ALPHA,
            CITY_BETA,
        )
        .expect("canonical identity");
        // The honest wire id passes the shape + derivation check.
        assert_eq!(identity.message_id, GOLDEN_VOTE_ALPHA_TO_BETA);
        // A wire id derived over a DIFFERENT tuple (wrong phase) is refused —
        // the receiver's own city id makes the binding checkable even though
        // the destination is not stored.
        assert_ne!(GOLDEN_PREPARE_ALPHA_TO_BETA, identity.message_id);
        // Shape failures (uppercase, wrong length, non-hex) are refused by the
        // same boundary that validates stored ids.
        for bad in [
            "68F01C7FAD252D78C9201E4C95AC6AC45E57196B594BBF0D1CC7DF83144D79B1",
            "68f01c7fad252d78c9201e4c95ac6ac45e57196b594bbf0d1cc7df83144d79b",
            "68f01c7fad252d78c9201e4c95ac6ac45e57196b594bbf0d1cc7df83144d79bZ",
        ] {
            assert!(validated_message_id_shape(bad).is_err());
        }
        assert!(validated_message_id_shape(GOLDEN_VOTE_ALPHA_TO_BETA).is_ok());
    }

    // ── actor-specific status transition matrix ─────────────────────────────

    #[test]
    fn delivery_status_actor_transition_matrix_fails_closed() {
        use CrossCityDeliveryStatus::*;
        let all = [Pending, Leased, InDoubt, Succeeded, Quarantined];
        // Worker: lease, release, doubt, complete, quarantine — and nothing
        // else.
        let worker_allowed = [
            (Pending, Leased),
            (Leased, Pending),
            (Leased, InDoubt),
            (Leased, Succeeded),
            (Leased, Quarantined),
        ];
        for from in all {
            for to in all {
                let allowed = worker_allowed.contains(&(from, to));
                assert_eq!(
                    from.transition_by_worker(to).is_ok(),
                    allowed,
                    "worker edge {from:?}->{to:?} drifted"
                );
            }
        }
        // The worker can NEVER touch an IN_DOUBT message and can never move a
        // terminal or quarantined row.
        for to in all {
            assert!(InDoubt.transition_by_worker(to).is_err());
            assert!(Succeeded.transition_by_worker(to).is_err());
            assert!(Quarantined.transition_by_worker(to).is_err());
        }
        // Reconcile: the ONLY way out of IN_DOUBT, into the three proven
        // facts; never into LEASED, never from a live worker state.
        let reconcile_allowed = [
            (InDoubt, Pending),
            (InDoubt, Succeeded),
            (InDoubt, Quarantined),
        ];
        for from in all {
            for to in all {
                let allowed = reconcile_allowed.contains(&(from, to));
                assert_eq!(
                    from.transition_by_reconcile(to).is_ok(),
                    allowed,
                    "reconcile edge {from:?}->{to:?} drifted"
                );
            }
        }
        // Operator: QUARANTINED -> PENDING only.
        for from in all {
            for to in all {
                let allowed = from == Quarantined && to == Pending;
                assert_eq!(
                    from.transition_by_operator(to).is_ok(),
                    allowed,
                    "operator edge {from:?}->{to:?} drifted"
                );
            }
        }
        // Unknown stored spellings fail closed (no trimming, no case folding).
        for bad in ["pending", "PENDING ", "UNKNOWN", ""] {
            assert!(CrossCityDeliveryStatus::parse_str(bad).is_err());
            assert!(CrossCityMessagePhase::parse_str(bad).is_err());
        }
        // Only SUCCEEDED is terminal.
        assert!(Succeeded.is_terminal());
        assert!(!Quarantined.is_terminal());
        assert!(!InDoubt.is_terminal());
    }

    // ── lease token redaction and hash binding ──────────────────────────────

    #[test]
    fn transport_lease_token_is_redacted_and_hash_bound() {
        let token = CrossCityTransportLeaseToken::new_run_scoped();
        let plaintext = token.as_str().to_owned();
        assert!(!plaintext.is_empty());
        // Debug/Display redact the plaintext.
        let debug = format!("{token:?}");
        let display = format!("{token}");
        assert_eq!(debug, "CrossCityTransportLeaseToken(REDACTED)");
        assert_eq!(display, "CrossCityTransportLeaseToken(REDACTED)");
        assert!(!debug.contains(&plaintext));
        assert!(!display.contains(&plaintext));
        // The hash is stable per token, 64 lowercase hex, and distinct across
        // tokens; it is the only form that ever reaches SQL.
        let hash = token.token_hash();
        assert_eq!(hash.as_hex().len(), 64);
        assert_eq!(hash.as_hex(), token.token_hash().as_hex());
        assert_ne!(
            hash.as_hex(),
            CrossCityTransportLeaseToken::new_run_scoped()
                .token_hash()
                .as_hex()
        );
    }

    #[test]
    fn lease_material_and_proof_validation_fail_closed() {
        // Lease material bounds.
        assert!(validate_transport_lease_material("worker-1", 30).is_ok());
        for bad_owner in [
            "",
            " ",
            " padded",
            &"x".repeat(MAX_CROSS_CITY_TRANSPORT_LEASE_OWNER_LENGTH + 1),
        ] {
            assert!(validate_transport_lease_material(bad_owner, 30).is_err());
        }
        for bad_seconds in [0, -1, MAX_CROSS_CITY_TRANSPORT_LEASE_SECONDS + 1] {
            assert!(validate_transport_lease_material("worker-1", bad_seconds).is_err());
        }
        // Proof shape.
        let token = CrossCityTransportLeaseToken::new_run_scoped();
        let good = CrossCityTransportLeaseProof {
            message_id: GOLDEN_VOTE_ALPHA_TO_BETA.to_owned(),
            lease_owner: "worker-1".to_owned(),
            lease_token: token,
        };
        assert!(validate_transport_lease_proof(&good).is_ok());
        for bad_message_id in [
            "",
            "not-a-digest",
            "68F01C7FAD252D78C9201E4C95AC6AC45E57196B594BBF0D1CC7DF83144D79B1",
        ] {
            let bad = CrossCityTransportLeaseProof {
                message_id: bad_message_id.to_owned(),
                lease_owner: "worker-1".to_owned(),
                lease_token: CrossCityTransportLeaseToken::new_run_scoped(),
            };
            assert!(validate_transport_lease_proof(&bad).is_err());
        }
        let empty_token = CrossCityTransportLeaseProof {
            message_id: GOLDEN_VOTE_ALPHA_TO_BETA.to_owned(),
            lease_owner: "worker-1".to_owned(),
            lease_token: CrossCityTransportLeaseToken::new_run_scoped(),
        };
        assert!(validate_transport_lease_proof(&empty_token).is_ok());
        // Reason text must be present and is char-truncated into last_error.
        assert!(validated_reason("").is_err());
        assert!(validated_reason("   ").is_err());
        let long = "x".repeat(MAX_CROSS_CITY_TRANSPORT_LAST_ERROR_LENGTH + 100);
        let truncated = validated_reason(&long).expect("long reason truncates");
        assert_eq!(
            truncated.chars().count(),
            MAX_CROSS_CITY_TRANSPORT_LAST_ERROR_LENGTH
        );
        // Multi-byte characters are truncated on char boundaries.
        let multi = "城市".repeat(400);
        assert_eq!(
            validated_reason(&multi)
                .expect("multi-byte reason truncates")
                .chars()
                .count(),
            MAX_CROSS_CITY_TRANSPORT_LAST_ERROR_LENGTH
        );
        assert_eq!(truncate_transport_last_error("abc"), "abc");
        // CR/LF/NUL, ANSI escapes, every other control character, and the
        // Unicode line/paragraph separators are REFUSED — never sanitized,
        // never persisted (log/terminal forging is rejected at the source).
        for unsafe_fragment in [
            "\u{0000}",
            "\u{0009}",
            "\n",
            "\r",
            "\r\n",
            "\u{001B}",
            "\u{001B}[31mred",
            "\u{007F}",
            "\u{0085}",
            "\u{009B}",
            "\u{2028}",
            "\u{2029}",
        ] {
            let reason = format!("before{unsafe_fragment}after");
            assert!(
                validated_reason(&reason).is_err(),
                "reason accepted unsafe fragment {unsafe_fragment:?}"
            );
        }
        assert!(validated_reason("plain safe reason").is_ok());
        assert!(validated_reason("冻结原因 ok").is_ok());
    }

    // ── attempts / backoff / budget ─────────────────────────────────────────

    #[test]
    fn transport_backoff_doubles_is_capped_and_fails_closed() {
        assert_eq!(transport_backoff_seconds(1).expect("first"), 30);
        assert_eq!(transport_backoff_seconds(2).expect("second"), 60);
        assert_eq!(transport_backoff_seconds(3).expect("third"), 120);
        assert_eq!(transport_backoff_seconds(6).expect("sixth"), 960);
        assert_eq!(transport_backoff_seconds(7).expect("seventh"), 1920);
        // The cap holds from the attempt whose doubling would exceed it.
        assert_eq!(
            transport_backoff_seconds(8).expect("eighth"),
            CROSS_CITY_TRANSPORT_BACKOFF_MAX_SECONDS
        );
        assert_eq!(
            transport_backoff_seconds(1_000).expect("capped"),
            CROSS_CITY_TRANSPORT_BACKOFF_MAX_SECONDS
        );
        assert_eq!(
            transport_backoff_seconds(i64::MAX).expect("capped"),
            CROSS_CITY_TRANSPORT_BACKOFF_MAX_SECONDS
        );
        for bad in [0, -1, -100] {
            assert!(transport_backoff_seconds(bad).is_err());
        }
    }

    #[test]
    fn attempt_budget_quarantines_at_exhaustion_and_fails_closed() {
        // Fresh budget: retries are scheduled with the doubling backoff.
        assert_eq!(
            resolve_transport_budget(0).expect("first failure"),
            CrossCityTransportBudgetOutcome::Retry {
                new_attempts: 1,
                backoff_seconds: 30
            }
        );
        assert_eq!(
            resolve_transport_budget(6).expect("seventh failure"),
            CrossCityTransportBudgetOutcome::Retry {
                new_attempts: 7,
                backoff_seconds: 1920
            }
        );
        // The attempt that reaches the hard budget quarantines instead of
        // scheduling another retry.
        assert_eq!(
            resolve_transport_budget(MAX_CROSS_CITY_TRANSPORT_ATTEMPTS - 1).expect("final failure"),
            CrossCityTransportBudgetOutcome::Exhausted {
                new_attempts: MAX_CROSS_CITY_TRANSPORT_ATTEMPTS
            }
        );
        // An already-exhausted counter is an EXPLICIT error — never MAX+1
        // (a counter beyond the decodable bound would be poisoned storage).
        assert!(resolve_transport_budget(MAX_CROSS_CITY_TRANSPORT_ATTEMPTS).is_err());
        // Out-of-range current counters fail closed (never wrap).
        for bad in [-1, MAX_CROSS_CITY_TRANSPORT_ATTEMPTS + 1, i64::MAX] {
            assert!(resolve_transport_budget(bad).is_err());
        }
        assert!(validated_attempts(-1).is_err());
        assert!(validated_attempts(0).is_ok());
        assert!(validated_attempts(MAX_CROSS_CITY_TRANSPORT_ATTEMPTS).is_ok());
    }

    #[test]
    fn quarantine_mark_budget_fails_closed_on_poisoned_counters() {
        // A quarantined row must stay decodable: the mark writes current+1 and
        // that value must remain within the 0..=MAX bound.
        assert_eq!(quarantined_attempt_budget(0).expect("first quarantine"), 1);
        assert_eq!(
            quarantined_attempt_budget(MAX_CROSS_CITY_TRANSPORT_ATTEMPTS - 1)
                .expect("final quarantine"),
            MAX_CROSS_CITY_TRANSPORT_ATTEMPTS
        );
        // A poisoned counter (negative or already at/over budget) is refused
        // instead of being silently written onward.
        for bad in [-1, MAX_CROSS_CITY_TRANSPORT_ATTEMPTS, i64::MAX] {
            assert!(quarantined_attempt_budget(bad).is_err());
        }
    }

    // ── status/lease consistency poison checks ──────────────────────────────

    #[test]
    fn status_lease_consistency_fails_closed() {
        use CrossCityDeliveryStatus::*;
        // LEASED requires full lease material — on both tables.
        for is_inbox in [false, true] {
            assert!(validate_transport_status_lease_consistency(
                Leased, true, true, true, is_inbox
            )
            .is_ok());
            assert!(validate_transport_status_lease_consistency(
                Leased, false, true, true, is_inbox
            )
            .is_err());
            assert!(validate_transport_status_lease_consistency(
                Leased, true, false, true, is_inbox
            )
            .is_err());
            assert!(validate_transport_status_lease_consistency(
                Leased, true, true, false, is_inbox
            )
            .is_err());
        }
        // PENDING has no lease identity; the OUTBOX additionally requires the
        // expiry to be cleared, while the INBOX deliberately allows a
        // lease_expires_at fence (its next-eligible-time backoff).
        assert!(
            validate_transport_status_lease_consistency(Pending, false, false, false, false)
                .is_ok()
        );
        assert!(
            validate_transport_status_lease_consistency(Pending, false, false, true, false)
                .is_err()
        );
        assert!(
            validate_transport_status_lease_consistency(Pending, false, false, false, true).is_ok()
        );
        assert!(
            validate_transport_status_lease_consistency(Pending, false, false, true, true).is_ok()
        );
        assert!(
            validate_transport_status_lease_consistency(Pending, true, false, false, false)
                .is_err()
        );
        assert!(
            validate_transport_status_lease_consistency(Pending, false, true, false, true).is_err()
        );
        // IN_DOUBT / SUCCEEDED / QUARANTINED carry no lease material at all.
        for status in [InDoubt, Succeeded, Quarantined] {
            for is_inbox in [false, true] {
                assert!(validate_transport_status_lease_consistency(
                    status, false, false, false, is_inbox
                )
                .is_ok());
                assert!(validate_transport_status_lease_consistency(
                    status, true, false, false, is_inbox
                )
                .is_err());
                assert!(validate_transport_status_lease_consistency(
                    status, false, true, false, is_inbox
                )
                .is_err());
                assert!(validate_transport_status_lease_consistency(
                    status, false, false, true, is_inbox
                )
                .is_err());
            }
        }
    }

    #[test]
    fn reconcile_outcomes_map_only_to_proven_facts() {
        // Unknown publish/process outcomes can only ever enter IN_DOUBT
        // (worker edge, pinned by the matrix test); reconciliation is the only
        // way out, and each target names one proven fact. An unknown outcome
        // has NO path to SUCCEEDED: there is no "maybe delivered" outcome.
        assert_eq!(
            reconcile_target(CrossCityTransportReconcileOutcome::NotApplied),
            CrossCityDeliveryStatus::Pending
        );
        assert_eq!(
            reconcile_target(CrossCityTransportReconcileOutcome::Applied),
            CrossCityDeliveryStatus::Succeeded
        );
        assert_eq!(
            reconcile_target(CrossCityTransportReconcileOutcome::Unresolvable),
            CrossCityDeliveryStatus::Quarantined
        );
    }

    // ── SQL shape (placeholders, locking, no upsert, table boundary) ───────

    /// The complete statement registry: every production SQL statement as a
    /// (constant NAME, statement value) pair. The name is written once here
    /// and the value is referenced as the real constant, so name and value can
    /// never drift apart; the source-shape guard below proves the production
    /// `sqlx::query*` call sites match this registry exactly.
    const ALL_STATEMENTS: [(&str, &str); 28] = [
        ("OUTBOX_INSERT_SQL", OUTBOX_INSERT_SQL),
        ("OUTBOX_SELECT_FOR_UPDATE_SQL", OUTBOX_SELECT_FOR_UPDATE_SQL),
        ("OUTBOX_CLAIM_CANDIDATE_SQL", OUTBOX_CLAIM_CANDIDATE_SQL),
        ("OUTBOX_CLAIM_INSTALL_SQL", OUTBOX_CLAIM_INSTALL_SQL),
        ("OUTBOX_CLAIM_READBACK_SQL", OUTBOX_CLAIM_READBACK_SQL),
        ("OUTBOX_HEARTBEAT_SQL", OUTBOX_HEARTBEAT_SQL),
        ("OUTBOX_SUCCEED_SQL", OUTBOX_SUCCEED_SQL),
        ("OUTBOX_FAIL_RETRY_SQL", OUTBOX_FAIL_RETRY_SQL),
        ("OUTBOX_QUARANTINE_SQL", OUTBOX_QUARANTINE_SQL),
        ("OUTBOX_RELEASE_SQL", OUTBOX_RELEASE_SQL),
        ("OUTBOX_IN_DOUBT_SQL", OUTBOX_IN_DOUBT_SQL),
        ("OUTBOX_RECONCILE_SQL", OUTBOX_RECONCILE_SQL),
        ("OUTBOX_REQUEUE_SQL", OUTBOX_REQUEUE_SQL),
        ("OUTBOX_POISON_QUARANTINE_SQL", OUTBOX_POISON_QUARANTINE_SQL),
        ("INBOX_RECORD_INSERT_SQL", INBOX_RECORD_INSERT_SQL),
        ("INBOX_SELECT_FOR_UPDATE_SQL", INBOX_SELECT_FOR_UPDATE_SQL),
        ("INBOX_CLAIM_CANDIDATE_SQL", INBOX_CLAIM_CANDIDATE_SQL),
        ("INBOX_CLAIM_INSTALL_SQL", INBOX_CLAIM_INSTALL_SQL),
        ("INBOX_CLAIM_READBACK_SQL", INBOX_CLAIM_READBACK_SQL),
        ("INBOX_HEARTBEAT_SQL", INBOX_HEARTBEAT_SQL),
        ("INBOX_PROCESSED_SQL", INBOX_PROCESSED_SQL),
        ("INBOX_FAIL_RETRY_SQL", INBOX_FAIL_RETRY_SQL),
        ("INBOX_QUARANTINE_SQL", INBOX_QUARANTINE_SQL),
        ("INBOX_IN_DOUBT_SQL", INBOX_IN_DOUBT_SQL),
        ("INBOX_RECONCILE_SQL", INBOX_RECONCILE_SQL),
        ("INBOX_RECONCILE_APPLIED_SQL", INBOX_RECONCILE_APPLIED_SQL),
        ("INBOX_REQUEUE_SQL", INBOX_REQUEUE_SQL),
        ("INBOX_POISON_QUARANTINE_SQL", INBOX_POISON_QUARANTINE_SQL),
    ];

    fn placeholder_count(statement: &str) -> usize {
        statement.bytes().filter(|byte| *byte == b'?').count()
    }

    // ── source-shape guards (pure: scan this file's own source) ────────────

    fn full_source() -> &'static str {
        include_str!("cross_city_transport_repository.rs")
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
        // one of the fixed, reviewed constants.
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
        for name in &call_sites {
            assert!(
                ALL_STATEMENTS
                    .iter()
                    .any(|(registered, _)| registered == name),
                "inline or unregistered SQL statement: {name}"
            );
        }
        // …and the registry must cover the call sites exactly: no missed
        // registration and no unused registration. Call SITES may exceed the
        // registry because one reviewed statement may be deliberately shared
        // by two paths (the quarantine mutation is used by both the
        // exhausted-budget fail path and the explicit quarantine mark), so
        // the comparison is on the DISTINCT statement set.
        let mut used: Vec<&str> = call_sites.clone();
        used.sort_unstable();
        used.dedup();
        let mut registered: Vec<&str> = ALL_STATEMENTS.iter().map(|(name, _)| *name).collect();
        registered.sort_unstable();
        assert_eq!(used, registered, "registry and call sites drifted apart");
    }

    #[test]
    fn statements_bind_exactly_the_expected_parameter_counts() {
        let expected: [(&str, usize); 28] = [
            (OUTBOX_INSERT_SQL, 9),
            (OUTBOX_SELECT_FOR_UPDATE_SQL, 1),
            // The claim candidate scans no longer bind an attempt bound: the
            // bound moved to the install CAS and the Rust-side budget gate so
            // exhausted/out-of-range rows surface instead of being skipped.
            (OUTBOX_CLAIM_CANDIDATE_SQL, 0),
            (OUTBOX_CLAIM_INSTALL_SQL, 5),
            (OUTBOX_CLAIM_READBACK_SQL, 1),
            (OUTBOX_HEARTBEAT_SQL, 4),
            (OUTBOX_SUCCEED_SQL, 3),
            (OUTBOX_FAIL_RETRY_SQL, 7),
            (OUTBOX_QUARANTINE_SQL, 6),
            (OUTBOX_RELEASE_SQL, 3),
            (OUTBOX_IN_DOUBT_SQL, 4),
            (OUTBOX_RECONCILE_SQL, 3),
            (OUTBOX_REQUEUE_SQL, 1),
            (OUTBOX_POISON_QUARANTINE_SQL, 3),
            (INBOX_RECORD_INSERT_SQL, 7),
            (INBOX_SELECT_FOR_UPDATE_SQL, 1),
            (INBOX_CLAIM_CANDIDATE_SQL, 0),
            (INBOX_CLAIM_INSTALL_SQL, 5),
            (INBOX_CLAIM_READBACK_SQL, 1),
            (INBOX_HEARTBEAT_SQL, 4),
            (INBOX_PROCESSED_SQL, 3),
            (INBOX_FAIL_RETRY_SQL, 7),
            (INBOX_QUARANTINE_SQL, 6),
            (INBOX_IN_DOUBT_SQL, 4),
            (INBOX_RECONCILE_SQL, 3),
            (INBOX_RECONCILE_APPLIED_SQL, 2),
            (INBOX_REQUEUE_SQL, 1),
            (INBOX_POISON_QUARANTINE_SQL, 3),
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
            OUTBOX_SELECT_FOR_UPDATE_SQL,
            OUTBOX_CLAIM_CANDIDATE_SQL,
            INBOX_SELECT_FOR_UPDATE_SQL,
            INBOX_CLAIM_CANDIDATE_SQL,
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
        // Exactly one row is ever locked per locking statement: the full row
        // selects key on the message_id primary key; the claim candidates key
        // on their eligibility predicate and stop at the first row.
        for statement in [OUTBOX_SELECT_FOR_UPDATE_SQL, INBOX_SELECT_FOR_UPDATE_SQL] {
            assert!(statement.contains("WHERE message_id = ? FOR UPDATE"));
        }
        for statement in [OUTBOX_CLAIM_CANDIDATE_SQL, INBOX_CLAIM_CANDIDATE_SQL] {
            assert!(statement.contains("LIMIT 1 FOR UPDATE"));
            assert!(!statement.contains("JOIN"));
        }
    }

    #[test]
    fn statements_never_use_upsert_forms() {
        for statement in ALL_STATEMENTS.iter().map(|(_, statement)| *statement) {
            assert!(!statement.contains("ON DUPLICATE"));
            assert!(!statement.contains("REPLACE INTO"));
            assert!(!statement.contains("INSERT IGNORE"));
        }
        // The duplicate path is an exact-compare replay: the plain INSERT
        // constant plus the unique-violation compare, never an upsert.
        let insert_body = production_function_body("pub async fn insert_outbox_in_tx");
        assert!(insert_body.contains("db_unique_violation"));
        assert!(insert_body.contains("outbox_duplicate_binding_matches"));
        let record_body = production_function_body("pub async fn record_inbox_in_tx");
        assert!(record_body.contains("db_unique_violation"));
        assert!(record_body.contains("inbox_duplicate_binding_matches"));
    }

    #[test]
    fn module_source_touches_only_the_two_transport_tables() {
        let source = full_source();
        let production = production_source();
        for owned in [
            "authorization_cross_city_outbox",
            "authorization_cross_city_inbox",
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
            // First-slice cross-city owners.
            "authorization_cross_city_operation",
            "authorization_cross_city_vote",
            "authorization_cross_city_city_state",
            "authorization_cross_city_gate",
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

    #[test]
    fn claim_predicates_pin_eligibility_and_backoff_schedules() {
        // OUTBOX: eligibility = the EXACT two-branch claimable disjunction
        // (fresh PENDING with fully cleared lease + due schedule, or fully
        // materialized LEASED whose lease expired) — server-side clock only.
        let candidate = OUTBOX_CLAIM_CANDIDATE_SQL;
        assert!(candidate.contains("status = 'PENDING'"));
        // The candidate scan does NOT pre-filter on the attempt bound: an
        // exhausted or out-of-range ACTIVE row must surface (and fail closed
        // at the Rust-side gate), never be silently skipped.
        assert!(!candidate.contains("attempts <"));
        assert!(candidate.contains(
            "(status = 'PENDING' AND lease_owner IS NULL AND lease_token_hash IS NULL \
             AND (lease_expires_at IS NULL OR lease_expires_at <= UTC_TIMESTAMP()) \
             AND (next_attempt_at IS NULL OR next_attempt_at <= UTC_TIMESTAMP()))"
        ));
        assert!(candidate.contains("next_attempt_at IS NULL OR next_attempt_at <= UTC_TIMESTAMP()"));
        let install = OUTBOX_CLAIM_INSTALL_SQL;
        assert!(install.contains("TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP())"));
        assert!(install.contains("next_attempt_at IS NULL OR next_attempt_at <= UTC_TIMESTAMP()"));
        // The install CAS RETAINS the attempt bound: an exhausted row is
        // never leased, even under engine-level drift.
        assert!(install.contains("attempts < ?"));
        // INBOX: there is NO next_attempt_at column; the lease fence is the
        // ONLY eligibility gate (lease_expires_at doubles as the backoff
        // schedule). This pins the no-hot-loop inbox design.
        let inbox_candidate = INBOX_CLAIM_CANDIDATE_SQL;
        assert!(inbox_candidate.contains("status = 'PENDING'"));
        assert!(!inbox_candidate.contains("attempts <"));
        assert!(inbox_candidate
            .contains("lease_expires_at IS NULL OR lease_expires_at <= UTC_TIMESTAMP()"));
        assert!(!inbox_candidate.contains("next_attempt_at"));
        assert!(!INBOX_CLAIM_INSTALL_SQL.contains("next_attempt_at"));
        assert!(INBOX_CLAIM_INSTALL_SQL.contains("attempts < ?"));
        for (_, statement) in ALL_STATEMENTS {
            if statement.contains("authorization_cross_city_inbox") {
                assert!(
                    !statement.contains("next_attempt_at"),
                    "inbox statement references the nonexistent next_attempt_at column"
                );
            }
        }
    }

    #[test]
    fn claim_install_flips_status_to_leased_and_matches_candidate_exactly() {
        // Blocking-fix guard: WITHOUT the status flip in the install, every
        // worker mutation (heartbeat/succeed/fail/in-doubt, all of which CAS
        // on status = 'LEASED') would refuse the just-claimed row.
        for install in [OUTBOX_CLAIM_INSTALL_SQL, INBOX_CLAIM_INSTALL_SQL] {
            assert!(
                install.contains("SET status = 'LEASED', lease_owner = ?, lease_token_hash = ?,"),
                "claim install must flip the row to LEASED: {install}"
            );
        }
        // Candidate and install predicates must be the SAME exact two-branch
        // disjunction; the loose OR-form (which accepted partial lease
        // material and repaired poison rows) is banned from both.
        for statement in [
            OUTBOX_CLAIM_CANDIDATE_SQL,
            OUTBOX_CLAIM_INSTALL_SQL,
            INBOX_CLAIM_CANDIDATE_SQL,
            INBOX_CLAIM_INSTALL_SQL,
        ] {
            assert!(statement.contains(
                "(status = 'PENDING' AND lease_owner IS NULL AND lease_token_hash IS NULL"
            ));
            assert!(statement.contains(
                "OR (status = 'LEASED' AND lease_owner IS NOT NULL \
                 AND lease_token_hash IS NOT NULL \
                 AND lease_expires_at IS NOT NULL AND lease_expires_at <= UTC_TIMESTAMP()))"
            ));
            // The rejected loose form must not appear anywhere in the claim
            // statements.
            assert!(!statement.contains("lease_owner IS NULL OR lease_token_hash IS NULL"));
        }
        // The readbacks prove the installed status (status drift = hard error).
        for readback in [OUTBOX_CLAIM_READBACK_SQL, INBOX_CLAIM_READBACK_SQL] {
            assert!(readback.contains("status"));
        }
    }

    #[test]
    fn claim_reclaim_is_actor_specific_and_partial_lease_is_refused() {
        // Both claim paths must, in order: FULLY poison-decode the LOCKED
        // candidate (the same decode as every record-returning path — no
        // presence-boolean shortcut), prove the takeover strictly through the
        // guarded worker edges (PENDING -> LEASED; or for an expired LEASED
        // row the LEASED -> PENDING then PENDING -> LEASED pair), and read the
        // installed status back.
        for (signature, decode_call, drift_code) in [
            (
                "pub async fn claim_next_outbox_in_tx",
                "decode_outbox_row(row)",
                "outbox_claim_status_drift",
            ),
            (
                "pub async fn claim_inbox_in_tx",
                "decode_inbox_row(row)",
                "inbox_claim_status_drift",
            ),
        ] {
            let body = production_function_body(signature);
            let decode = body
                .find(decode_call)
                .expect("full candidate poison decode missing");
            // The dead-lease release edge exists ONLY inside the expired
            // LEASED reclaim arm; the reclaim's fresh-claim edge is its LAST
            // Leased-edge occurrence (the fresh PENDING arm's edge appears
            // earlier in the source).
            let dead_release = body
                .find("claimed_status.transition_by_worker(CrossCityDeliveryStatus::Pending)")
                .expect("dead-lease release edge missing");
            let fresh_claim = body
                .rfind("transition_by_worker(CrossCityDeliveryStatus::Leased)")
                .expect("fresh-claim edge missing");
            let install = body.find("_CLAIM_INSTALL_SQL").expect("install missing");
            let readback = body
                .find("claim_status_drift")
                .expect("status readback missing");
            assert!(decode < dead_release && dead_release < fresh_claim);
            assert!(fresh_claim < install && install < readback);
            assert!(body.contains(drift_code));
            // The unclaimable-status arm fails closed; the presence-boolean
            // consistency shortcut must NOT have returned.
            assert!(body.contains("claim_unclaimable_status"));
            assert!(!body.contains("validate_transport_status_lease_consistency"));
        }
    }

    #[test]
    fn claim_candidates_select_the_full_row_shape_for_poison_decode() {
        // The candidate SELECT must return EVERY decode input so the claim can
        // run the exact record codec on the locked row (no presence-boolean
        // shortcut, no partial shape).
        let outbox = OUTBOX_CLAIM_CANDIDATE_SQL;
        for column in [
            "payload_digest",
            "payload",
            "status",
            "attempts",
            "next_attempt_at",
            "lease_owner",
            "lease_token_hash",
            "lease_expires_at",
            "last_error",
        ] {
            assert!(outbox.contains(column), "outbox candidate missing {column}");
        }
        let inbox = INBOX_CLAIM_CANDIDATE_SQL;
        for column in [
            "payload_digest",
            "status",
            "attempts",
            "lease_owner",
            "lease_token_hash",
            "lease_expires_at",
            "received_at",
            "processed_at",
            "last_error",
        ] {
            assert!(inbox.contains(column), "inbox candidate missing {column}");
        }
    }

    #[test]
    fn public_debug_output_never_contains_payload_bytes() {
        let payload = b"secret-payload-bytes-123";
        // Outbox lease grant: Debug prints payload_len only (and the lease
        // token stays redacted).
        let grant = CrossCityOutboxLeaseGrant {
            message_id: GOLDEN_VOTE_ALPHA_TO_BETA.to_owned(),
            identity: vote_identity(),
            payload: payload.to_vec(),
            payload_digest: DIGEST_A.to_owned(),
            attempts: 1,
            lease_owner: "worker-1".to_owned(),
            lease_token: CrossCityTransportLeaseToken::new_run_scoped(),
            lease_expires_at_seconds: 1_000,
        };
        let grant_debug = format!("{grant:?}");
        assert!(grant_debug.contains("payload_len"));
        assert!(!grant_debug.contains("secret-payload-bytes"));
        assert!(!grant_debug.contains(grant.lease_token.as_str()));
        // Inbox record request: Debug prints payload_len only.
        let request = inbox_request(
            GOLDEN_VOTE_ALPHA_TO_BETA,
            OPERATION_ID,
            CrossCityMessagePhase::Vote,
            CITY_ALPHA,
            payload,
        );
        let request_debug = format!("{request:?}");
        assert!(request_debug.contains("payload_len"));
        assert!(!request_debug.contains("secret-payload-bytes"));
        // The outbox insert request and record keep their payload_len-only
        // Debug as well.
        let insert = CrossCityOutboxInsert {
            operation_id: OPERATION_ID.to_owned(),
            phase: CrossCityMessagePhase::Vote,
            source_city_id: CITY_ALPHA.to_owned(),
            destination_city_id: CITY_BETA.to_owned(),
            payload: payload.to_vec(),
        };
        let insert_debug = format!("{insert:?}");
        assert!(insert_debug.contains("payload_len"));
        assert!(!insert_debug.contains("secret-payload-bytes"));
        let mut record = outbox_record(&vote_identity(), DIGEST_A);
        record.payload = b"record-secret-bytes".to_vec();
        let record_debug = format!("{record:?}");
        assert!(record_debug.contains("payload_len"));
        assert!(!record_debug.contains("record-secret-bytes"));
    }

    #[test]
    fn fail_paths_pin_attempts_and_inbox_fence_shape() {
        // OUTBOX retry: one attempt consumed, backoff into next_attempt_at,
        // lease fully cleared.
        let outbox_retry = OUTBOX_FAIL_RETRY_SQL;
        assert!(outbox_retry.contains("attempts = ?"));
        assert!(outbox_retry.contains("next_attempt_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP())"));
        assert!(outbox_retry
            .contains("lease_owner = NULL, lease_token_hash = NULL, lease_expires_at = NULL"));
        assert!(outbox_retry.contains("attempts = ?"));
        // INBOX retry: one attempt consumed, lease identity cleared, and the
        // lease_expires_at fence RETAINED as the server-computed backoff.
        let inbox_retry = INBOX_FAIL_RETRY_SQL;
        assert!(inbox_retry.contains("attempts = ?"));
        assert!(inbox_retry.contains("lease_owner = NULL, lease_token_hash = NULL"));
        assert!(inbox_retry.contains("lease_expires_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP())"));
        // Quarantine consumes an attempt and leaves no schedule/fence.
        for quarantine in [OUTBOX_QUARANTINE_SQL, INBOX_QUARANTINE_SQL] {
            assert!(quarantine.contains("status = 'QUARANTINED'"));
            assert!(quarantine.contains("attempts = ?"));
            assert!(quarantine.contains("lease_expires_at = NULL"));
        }
        // Operator requeue grants a fresh budget (attempts = 0) and clears
        // every schedule/fence column.
        for requeue in [OUTBOX_REQUEUE_SQL, INBOX_REQUEUE_SQL] {
            assert!(requeue.contains("status = 'PENDING'"));
            assert!(requeue.contains("attempts = 0"));
            assert!(requeue.contains("lease_expires_at = NULL"));
            assert!(requeue.contains("status = 'QUARANTINED'"));
        }
        assert!(OUTBOX_REQUEUE_SQL.contains("next_attempt_at = NULL"));
        // Processed closes server-side with a processed_at timestamp.
        assert!(INBOX_PROCESSED_SQL.contains("processed_at = UTC_TIMESTAMP()"));
        // IN_DOUBT hands ownership back (lease cleared), consumes no budget,
        // and clears any stale retry schedule.
        for in_doubt in [OUTBOX_IN_DOUBT_SQL, INBOX_IN_DOUBT_SQL] {
            assert!(in_doubt.contains("status = 'IN_DOUBT'"));
            assert!(in_doubt
                .contains("lease_owner = NULL, lease_token_hash = NULL, lease_expires_at = NULL"));
            assert!(!in_doubt.contains("attempts"));
        }
        assert!(OUTBOX_IN_DOUBT_SQL.contains("next_attempt_at = NULL"));
        // SUCCEEDED outbox rows leave no stale schedule behind either.
        assert!(OUTBOX_SUCCEED_SQL.contains("next_attempt_at = NULL"));
        // Reconcile is lease-free and binds the proven target status.
        for reconcile in [OUTBOX_RECONCILE_SQL, INBOX_RECONCILE_SQL] {
            assert!(reconcile.contains("status = ?"));
            assert!(reconcile.contains("status = 'IN_DOUBT'"));
            assert!(reconcile.contains("lease_owner = NULL"));
        }
        assert!(OUTBOX_RECONCILE_SQL.contains("next_attempt_at = NULL"));
        // The Applied inbox resolution IS the processed fact: it closes the
        // row exactly once WITH the server-side processed_at stamp every
        // SUCCEEDED row must carry (the decode invariant).
        assert!(INBOX_RECONCILE_APPLIED_SQL.contains("status = 'SUCCEEDED'"));
        assert!(INBOX_RECONCILE_APPLIED_SQL.contains("processed_at = UTC_TIMESTAMP()"));
        assert!(INBOX_RECONCILE_APPLIED_SQL.contains("status = 'IN_DOUBT'"));
        assert!(!INBOX_RECONCILE_APPLIED_SQL.contains("status = ?"));
    }

    #[test]
    fn worker_completion_paths_require_the_actor_transition_and_live_lease() {
        // SUCCEEDED is reachable ONLY through the worker guard with a live
        // lease CAS — never through a bare flag, an ACK, or the reconcile path
        // alone.
        for (body, sql) in [
            (
                production_function_body("pub async fn mark_outbox_succeeded_in_tx"),
                OUTBOX_SUCCEED_SQL,
            ),
            (
                production_function_body("pub async fn mark_inbox_processed_in_tx"),
                INBOX_PROCESSED_SQL,
            ),
        ] {
            assert!(body.contains("transition_by_worker(CrossCityDeliveryStatus::Succeeded)"));
            assert!(body.contains("verify_"));
            assert!(sql.contains("status = 'LEASED'"));
            assert!(sql.contains("lease_expires_at > UTC_TIMESTAMP()"));
        }
        // In-doubt is the ONLY worker path for unknown outcomes, guarded by
        // the same lease CAS, and never touches SUCCEEDED.
        for (signature, sql) in [
            (
                "pub async fn mark_outbox_publish_in_doubt_in_tx",
                OUTBOX_IN_DOUBT_SQL,
            ),
            (
                "pub async fn mark_inbox_process_in_doubt_in_tx",
                INBOX_IN_DOUBT_SQL,
            ),
        ] {
            let body = production_function_body(signature);
            assert!(body.contains("transition_by_worker(CrossCityDeliveryStatus::InDoubt)"));
            assert!(sql.contains("status = 'IN_DOUBT'"));
            assert!(!sql.contains("SUCCEEDED"));
        }
        // Reconcile is the only way OUT of IN_DOUBT and goes through the
        // reconcile guard exclusively — and the locked row is FULLY
        // poison-decoded BEFORE the state machine advances, so a poisoned row
        // is never advanced (never closed as SUCCEEDED).
        for (signature, decode_call) in [
            (
                "pub async fn reconcile_outbox_publish_outcome_in_tx",
                "decode_outbox_row(row)",
            ),
            (
                "pub async fn reconcile_inbox_process_outcome_in_tx",
                "decode_inbox_row(row)",
            ),
        ] {
            let body = production_function_body(signature);
            let lease_absent = body
                .find("ensure_in_doubt_lease_absent")
                .expect("in-doubt lease-absence guard missing");
            let decode = body.find(decode_call).expect("full poison decode missing");
            let transition = body
                .find("transition_by_reconcile(target)")
                .expect("reconcile guard missing");
            assert!(
                lease_absent < decode && decode < transition,
                "reconcile must decode before advancing"
            );
            assert!(!body.contains("transition_by_worker"));
        }
        // Operator requeue goes through the operator guard exclusively.
        for signature in [
            "pub async fn requeue_quarantined_outbox_in_tx",
            "pub async fn requeue_quarantined_inbox_in_tx",
        ] {
            let body = production_function_body(signature);
            assert!(body.contains("transition_by_operator(CrossCityDeliveryStatus::Pending)"));
            assert!(!body.contains("transition_by_worker"));
            assert!(!body.contains("transition_by_reconcile"));
        }
    }

    #[test]
    fn durable_before_ack_boundary_is_pinned_in_the_module_docs() {
        let production = production_source();
        assert!(
            production.contains("Durable-before-ACK boundary"),
            "the durable-before-ACK boundary must be named in the module docs"
        );
        assert!(
            production.contains("the caller's COMMIT is the only durable point"),
            "the commit-only durable point must be stated in the module docs"
        );
        assert!(
            production.contains("An ACK is NOT a durable success proof"),
            "the ACK non-proof rule must be stated in the module docs"
        );
        assert!(
            production.contains("Redis idempotency is not durable proof"),
            "the Redis non-proof rule must be stated in the module docs"
        );
    }

    #[test]
    fn inbox_record_insert_has_no_destination_or_payload_column() {
        // The inbox schema carries no payload and no destination column; the
        // record statement must not reference either (the destination exists
        // only as the receiver-side derivation input).
        assert!(!INBOX_RECORD_INSERT_SQL.contains("destination_city_id"));
        assert!(!INBOX_RECORD_INSERT_SQL.contains("payload,"));
        assert!(INBOX_RECORD_INSERT_SQL.contains("payload_digest"));
        assert!(!INBOX_SELECT_FOR_UPDATE_SQL.contains("destination_city_id"));
    }

    #[test]
    fn claim_and_insert_bind_only_the_fixed_bound_constants() {
        // The attempt budget in every claim predicate is the single fixed
        // constant — never a caller-supplied bound.
        let claim_body = production_function_body("pub async fn claim_next_outbox_in_tx");
        assert!(claim_body.contains("MAX_CROSS_CITY_TRANSPORT_ATTEMPTS"));
        let inbox_claim_body = production_function_body("pub async fn claim_inbox_in_tx");
        assert!(inbox_claim_body.contains("MAX_CROSS_CITY_TRANSPORT_ATTEMPTS"));
        // The outbox message id is always derived, never caller-supplied.
        let insert_body = production_function_body("pub async fn insert_outbox_in_tx");
        assert!(insert_body.contains("CrossCityMessageIdentity::new"));
        assert!(insert_body.contains("cross_city_payload_digest"));
        // The inbox message id is always verified against the derivation.
        let record_body = production_function_body("pub async fn record_inbox_in_tx");
        assert!(record_body.contains("inbox_message_id_derivation_mismatch"));
        assert!(record_body.contains("CrossCityMessageIdentity::new"));
    }

    // ── lease-free poison quarantine (explicit operator path) ──────────────

    fn operator_authorization(
        subject: &str,
        reference: &str,
    ) -> CrossCityTransportOperatorAuthorization {
        CrossCityTransportOperatorAuthorization {
            operator_subject: subject.to_owned(),
            authorization_reference: reference.to_owned(),
        }
    }

    fn attempts_i32(value: i64) -> i32 {
        i32::try_from(value).expect("attempt value fits i32")
    }

    /// A valid DATETIME far in the future (for complete lease material).
    fn future_datetime() -> PrimitiveDateTime {
        PrimitiveDateTime::new(
            time::Date::from_calendar_date(2030, time::Month::January, 1).expect("valid date"),
            time::Time::MIDNIGHT,
        )
    }

    fn outbox_row_for_decode(status: &str, attempts: i32) -> OutboxRow {
        let payload = b"payload".to_vec();
        OutboxRow {
            message_id: vote_identity().message_id,
            operation_id: OPERATION_ID.to_owned(),
            source_city_id: CITY_ALPHA.to_owned(),
            destination_city_id: CITY_BETA.to_owned(),
            phase: CrossCityMessagePhase::Vote.as_str().to_owned(),
            payload_digest: Sha256::digest(payload.as_slice()).to_vec(),
            payload,
            status: status.to_owned(),
            attempts,
            next_attempt_at: None,
            lease_owner: None,
            lease_token_hash: None,
            lease_expires_at: None,
            last_error: None,
        }
    }

    fn inbox_row_for_decode(status: &str, attempts: i32) -> InboxRow {
        InboxRow {
            message_id: GOLDEN_VOTE_ALPHA_TO_BETA.to_owned(),
            operation_id: OPERATION_ID.to_owned(),
            source_city_id: CITY_ALPHA.to_owned(),
            phase: CrossCityMessagePhase::Vote.as_str().to_owned(),
            payload_digest: Sha256::digest(b"payload".as_slice()).to_vec(),
            status: status.to_owned(),
            attempts,
            lease_owner: None,
            lease_token_hash: None,
            lease_expires_at: None,
            received_at: future_datetime(),
            processed_at: None,
            last_error: None,
        }
    }

    #[test]
    fn decode_refuses_attempts_at_the_bound_on_non_quarantined_rows() {
        // Only a QUARANTINED row may sit AT the attempt bound: the
        // exhausted-budget quarantine is the only writer that reaches it. Any
        // other status at the bound is poisoned storage — the claim scan
        // (which no longer pre-filters the bound) surfaces it and the
        // lease-free poison quarantine can take it; it is never silently
        // skipped.
        for status in ["PENDING", "LEASED", "IN_DOUBT", "SUCCEEDED"] {
            let error = decode_outbox_row(outbox_row_for_decode(
                status,
                attempts_i32(MAX_CROSS_CITY_TRANSPORT_ATTEMPTS),
            ))
            .expect_err("non-quarantined outbox row AT the bound must be poisoned");
            assert!(error
                .to_string()
                .contains("poisoned_outbox_attempts_at_budget"));
            let error = decode_inbox_row(inbox_row_for_decode(
                status,
                attempts_i32(MAX_CROSS_CITY_TRANSPORT_ATTEMPTS),
            ))
            .expect_err("non-quarantined inbox row AT the bound must be poisoned");
            assert!(error
                .to_string()
                .contains("poisoned_inbox_attempts_at_budget"));
        }
        // The exhausted-but-legal QUARANTINED state at the bound decodes.
        assert!(decode_outbox_row(outbox_row_for_decode(
            "QUARANTINED",
            attempts_i32(MAX_CROSS_CITY_TRANSPORT_ATTEMPTS)
        ))
        .is_ok());
        assert!(decode_inbox_row(inbox_row_for_decode(
            "QUARANTINED",
            attempts_i32(MAX_CROSS_CITY_TRANSPORT_ATTEMPTS)
        ))
        .is_ok());
        // One below the bound on an active status is still decodable.
        assert!(decode_outbox_row(outbox_row_for_decode(
            "PENDING",
            attempts_i32(MAX_CROSS_CITY_TRANSPORT_ATTEMPTS - 1)
        ))
        .is_ok());
        assert!(decode_inbox_row(inbox_row_for_decode(
            "PENDING",
            attempts_i32(MAX_CROSS_CITY_TRANSPORT_ATTEMPTS - 1)
        ))
        .is_ok());
        // Out-of-range counters are poisoned storage in any status.
        for bad in [-1, MAX_CROSS_CITY_TRANSPORT_ATTEMPTS + 1] {
            assert!(
                decode_outbox_row(outbox_row_for_decode("PENDING", attempts_i32(bad))).is_err()
            );
            assert!(decode_inbox_row(inbox_row_for_decode("PENDING", attempts_i32(bad))).is_err());
        }
    }

    #[test]
    fn decode_failure_is_the_poison_proof_and_healthy_rows_stay_healthy() {
        // Healthy rows decode on both tables.
        assert!(decode_outbox_row(outbox_row_for_decode("PENDING", 0)).is_ok());
        assert!(decode_inbox_row(inbox_row_for_decode("PENDING", 0)).is_ok());
        // Tampered payload bytes (digest disagreement) are poison — exactly
        // the proof the lease-free poison quarantine requires.
        let mut tampered = outbox_row_for_decode("PENDING", 0);
        tampered.payload = b"tampered-bytes".to_vec();
        assert!(decode_outbox_row(tampered).is_err());
        // A noncanonical stored text field is poison as well.
        let mut tampered_inbox = inbox_row_for_decode("PENDING", 0);
        tampered_inbox.source_city_id = " city-alpha".to_owned();
        assert!(decode_inbox_row(tampered_inbox).is_err());
    }

    #[test]
    fn decode_enforces_forensic_schedule_and_processed_timestamp_invariants() {
        // Read-side forensic text must obey the same control/format-character
        // boundary as every write path; poisoned stored text is never returned.
        let mut outbox_with_control_error = outbox_row_for_decode("PENDING", 0);
        outbox_with_control_error.last_error = Some("bad\nerror".to_owned());
        let error = decode_outbox_row(outbox_with_control_error)
            .expect_err("outbox control-carrying last_error must be poison");
        assert!(error.to_string().contains("poisoned_outbox_last_error"));

        let mut inbox_with_format_error = inbox_row_for_decode("PENDING", 0);
        inbox_with_format_error.last_error = Some("bad\u{202E}error".to_owned());
        let error = decode_inbox_row(inbox_with_format_error)
            .expect_err("inbox format-carrying last_error must be poison");
        assert!(error.to_string().contains("poisoned_inbox_last_error"));

        // A schedule is valid for a live worker-cycle PENDING row, but stale
        // schedule metadata on a completed/held row is poisoned.
        let mut outbox_with_stale_schedule = outbox_row_for_decode("QUARANTINED", 0);
        outbox_with_stale_schedule.next_attempt_at = Some(future_datetime());
        let error = decode_outbox_row(outbox_with_stale_schedule)
            .expect_err("quarantined outbox schedule must be poison");
        assert!(error.to_string().contains("poisoned_outbox_stale_schedule"));

        // `SUCCEEDED` and `processed_at` are a bidirectional durable invariant:
        // neither a missing stamp nor a stamp on another status is readable.
        let missing_processed_at = inbox_row_for_decode("SUCCEEDED", 0);
        let error = decode_inbox_row(missing_processed_at)
            .expect_err("succeeded inbox row without processed_at must be poison");
        assert!(error.to_string().contains("poisoned_inbox_processed_at"));

        let mut unexpected_processed_at = inbox_row_for_decode("PENDING", 0);
        unexpected_processed_at.processed_at = Some(future_datetime());
        let error = decode_inbox_row(unexpected_processed_at)
            .expect_err("pending inbox row with processed_at must be poison");
        assert!(error.to_string().contains("poisoned_inbox_processed_at"));

        let mut complete_success = inbox_row_for_decode("SUCCEEDED", 0);
        complete_success.processed_at = Some(future_datetime());
        assert!(decode_inbox_row(complete_success).is_ok());
    }

    #[test]
    fn poison_quarantine_forensic_marker_is_bounded_and_single_line() {
        let marker = poison_quarantine_forensic_marker(
            &operator_authorization("op-1", "policy-decision-42"),
            "payload digest mismatch; hold for forensics",
        )
        .expect("valid marker");
        assert!(marker.starts_with(
            "poison_quarantine;operator=op-1;ref=policy-decision-42;reason=payload digest mismatch; hold for forensics"
        ));
        assert!(marker.chars().count() <= MAX_CROSS_CITY_TRANSPORT_LAST_ERROR_LENGTH);
        assert!(!marker.chars().any(is_unsafe_forensic_char));
        // Worst-case field lengths still fit: a maximal subject/reference
        // leaves a non-empty reason budget and the composed marker stays
        // within the VARCHAR(512) bound, with the reason char-truncated
        // (UTF-8 boundaries preserved).
        let subject = "s".repeat(MAX_CROSS_CITY_TRANSPORT_OPERATOR_LENGTH);
        let reference = "r".repeat(MAX_CROSS_CITY_TRANSPORT_OPERATOR_LENGTH);
        let reason = "城".repeat(MAX_CROSS_CITY_TRANSPORT_LAST_ERROR_LENGTH);
        let marker = poison_quarantine_forensic_marker(
            &operator_authorization(&subject, &reference),
            &reason,
        )
        .expect("worst-case marker");
        assert_eq!(
            marker.chars().count(),
            MAX_CROSS_CITY_TRANSPORT_LAST_ERROR_LENGTH
        );
        assert!(marker.starts_with(&format!(
            "poison_quarantine;operator={subject};ref={reference};reason="
        )));
        assert!(!marker.ends_with(&reason));
        assert!(marker.contains("城"));
    }

    #[test]
    fn poison_quarantine_forensic_marker_rejects_unsafe_input_without_sanitizing() {
        // Control characters, CR/LF, NUL, ANSI escapes, and the Unicode
        // line/paragraph separators are refused in ANY input — the whole
        // request fails closed and nothing is persisted.
        for unsafe_fragment in [
            "\u{0000}",
            "\u{0009}",
            "\n",
            "\r\n",
            "\u{001B}",
            "\u{001B}[31mred",
            "\u{007F}",
            "\u{0085}",
            "\u{009B}",
            "\u{2028}",
            "\u{2029}",
        ] {
            let reason = format!("reason{unsafe_fragment}tail");
            assert!(
                poison_quarantine_forensic_marker(
                    &operator_authorization("op-1", "ref-1"),
                    &reason
                )
                .is_err(),
                "marker accepted unsafe reason fragment {unsafe_fragment:?}"
            );
            let subject = format!("op{unsafe_fragment}");
            assert!(poison_quarantine_forensic_marker(
                &operator_authorization(&subject, "ref-1"),
                "reason"
            )
            .is_err());
            let reference = format!("ref{unsafe_fragment}");
            assert!(poison_quarantine_forensic_marker(
                &operator_authorization("op-1", &reference),
                "reason"
            )
            .is_err());
        }
        // Padded, empty, whitespace-carrying, or oversized operator fields are
        // refused (id-shaped, bounded by the operator length constant).
        let oversized = "x".repeat(MAX_CROSS_CITY_TRANSPORT_OPERATOR_LENGTH + 1);
        for bad_field in [
            "",
            " ",
            " padded",
            "trailing ",
            "has space",
            oversized.as_str(),
        ] {
            assert!(validated_operator_field(bad_field, "operator_subject").is_err());
            assert!(poison_quarantine_forensic_marker(
                &operator_authorization(bad_field, "ref-1"),
                "reason"
            )
            .is_err());
            assert!(poison_quarantine_forensic_marker(
                &operator_authorization("op-1", bad_field),
                "reason"
            )
            .is_err());
        }
        // A valid context passes shape validation.
        assert!(validated_operator_field("op-1", "operator_subject").is_ok());
        assert!(validated_operator_field("policy-decision-42", "authorization_reference").is_ok());
        // An empty reason stays refused.
        assert!(
            poison_quarantine_forensic_marker(&operator_authorization("op-1", "ref-1"), "")
                .is_err()
        );
        assert!(
            poison_quarantine_forensic_marker(&operator_authorization("op-1", "ref-1"), "   ")
                .is_err()
        );
    }

    #[test]
    fn poison_quarantine_sql_touches_only_mutable_fields_and_never_steals_a_live_lease() {
        // OUTBOX: only the mutable lease/schedule/status fields move; the
        // forensic marker is the only written evidence field. Immutable
        // identity/payload/evidence columns and history are never touched.
        let outbox = OUTBOX_POISON_QUARANTINE_SQL;
        assert!(outbox.contains("UPDATE authorization_cross_city_outbox"));
        assert!(outbox.contains(
            "SET status = 'QUARANTINED', next_attempt_at = NULL, lease_owner = NULL, \
             lease_token_hash = NULL, lease_expires_at = NULL, last_error = ? WHERE"
        ));
        for immutable in [
            "operation_id",
            "source_city_id",
            "destination_city_id",
            "phase",
            "payload_digest",
            "payload",
            "attempts",
            "created_at",
            "updated_at",
        ] {
            assert!(
                !outbox.contains(immutable),
                "outbox poison update touches {immutable}"
            );
        }
        // The WHERE pins the observed status, refuses the terminal status
        // server-side, and refuses a LIVE lease server-side (no client clock).
        assert!(outbox.contains("WHERE message_id = ? AND BINARY status = BINARY ?"));
        assert!(outbox.contains("AND BINARY status <> BINARY 'SUCCEEDED'"));
        assert!(outbox.contains(
            "AND NOT (lease_owner IS NOT NULL AND lease_token_hash IS NOT NULL \
             AND lease_expires_at IS NOT NULL AND lease_expires_at > UTC_TIMESTAMP())"
        ));
        assert!(!outbox.contains("FOR UPDATE"));
        assert!(!outbox.contains("lease_owner = ?"));

        // INBOX: same contract, no next_attempt_at column, and the received/
        // processed history is never rewritten.
        let inbox = INBOX_POISON_QUARANTINE_SQL;
        assert!(inbox.contains("UPDATE authorization_cross_city_inbox"));
        assert!(inbox.contains(
            "SET status = 'QUARANTINED', lease_owner = NULL, lease_token_hash = NULL, \
             lease_expires_at = NULL, last_error = ? WHERE"
        ));
        for immutable in [
            "operation_id",
            "source_city_id",
            "phase",
            "payload_digest",
            "payload",
            "attempts",
            "received_at",
            "processed_at",
            "next_attempt_at",
            "created_at",
            "updated_at",
        ] {
            assert!(
                !inbox.contains(immutable),
                "inbox poison update touches {immutable}"
            );
        }
        assert!(inbox.contains("WHERE message_id = ? AND BINARY status = BINARY ?"));
        assert!(inbox.contains("AND BINARY status <> BINARY 'SUCCEEDED'"));
        assert!(inbox.contains(
            "AND NOT (lease_owner IS NOT NULL AND lease_token_hash IS NOT NULL \
             AND lease_expires_at IS NOT NULL AND lease_expires_at > UTC_TIMESTAMP())"
        ));
        assert!(!inbox.contains("FOR UPDATE"));
        assert!(!inbox.contains("lease_owner = ?"));
    }

    #[test]
    fn poison_quarantine_paths_are_lease_free_and_fail_closed() {
        for (signature, sql, decode_call, table) in [
            (
                "pub async fn quarantine_poisoned_outbox_in_tx",
                "OUTBOX_POISON_QUARANTINE_SQL",
                "decode_outbox_row(row)",
                "outbox",
            ),
            (
                "pub async fn quarantine_poisoned_inbox_in_tx",
                "INBOX_POISON_QUARANTINE_SQL",
                "decode_inbox_row(row)",
                "inbox",
            ),
        ] {
            let body = production_function_body(signature);
            // The forensic inputs are validated BEFORE the row lock: unsafe
            // operator context or reason persists nothing.
            let marker = body
                .find("poison_quarantine_forensic_marker(authorization, reason)")
                .expect("forensic marker validation missing");
            let lock = body
                .find(&format!("lock_{table}_for_update"))
                .expect("row lock missing");
            assert!(
                marker < lock,
                "forensic inputs must be validated before the row lock"
            );
            // Terminal refusal precedes the decode; the decode IS the poison
            // proof and precedes the guarded UPDATE; the live-lease refusal is
            // the CAS-lost outcome.
            let terminal = body
                .find(&format!("{table}_poison_quarantine_terminal_row"))
                .expect("terminal-row refusal missing");
            let decode = body.find(decode_call).expect("full poison decode missing");
            let not_poisoned = body
                .find(&format!("{table}_poison_quarantine_not_poisoned"))
                .expect("healthy-row refusal missing");
            let update = body.find(sql).expect("quarantine update missing");
            let live = body
                .find(&format!("{table}_poison_quarantine_live_lease"))
                .expect("live-lease refusal missing");
            assert!(terminal < decode && decode < not_poisoned);
            assert!(decode < update && update < live);
            // The poison proof is a decode FAILURE: a decodable (healthy) row
            // is refused untouched.
            assert!(body.contains(".is_ok()"));
            // Lease-free: no lease proof, no lease material handling, and no
            // state-machine transition (a poisoned row cannot be decoded into
            // the machine).
            assert!(!body.contains("LeaseProof"));
            assert!(!body.contains("lease_token"));
            assert!(!body.contains("transition_by_"));
        }
    }

    #[test]
    fn claim_candidates_do_not_prefilter_attempts_and_claims_fail_closed_on_exhaustion() {
        // The candidate scans no longer pre-filter on the attempt bound: an
        // exhausted or out-of-range ACTIVE row must SURFACE (and fail closed),
        // never be silently skipped forever.
        for candidate in [OUTBOX_CLAIM_CANDIDATE_SQL, INBOX_CLAIM_CANDIDATE_SQL] {
            assert!(!candidate.contains("attempts <"));
            assert!(candidate.contains("attempts"));
        }
        // The install CAS retains `attempts < MAX`: an exhausted row is never
        // leased, even under engine-level drift.
        for install in [OUTBOX_CLAIM_INSTALL_SQL, INBOX_CLAIM_INSTALL_SQL] {
            assert!(install.contains("attempts < ?"));
        }
        for (signature, exhausted_code) in [
            (
                "pub async fn claim_next_outbox_in_tx",
                "outbox_claim_attempts_exhausted",
            ),
            (
                "pub async fn claim_inbox_in_tx",
                "inbox_claim_attempts_exhausted",
            ),
        ] {
            let body = production_function_body(signature);
            // The fail-closed budget gate sits AFTER the full decode of the
            // locked candidate.
            let decode = body.find("decode_").expect("candidate decode missing");
            let gate = body
                .find("attempts >= MAX_CROSS_CITY_TRANSPORT_ATTEMPTS")
                .expect("fail-closed budget gate missing");
            assert!(decode < gate);
            assert!(body.contains(exhausted_code));
            // The candidate fetch binds nothing (the bound left the scan);
            // MAX is bound again only for the INSTALL.
            let candidate_query = body
                .find("_CLAIM_CANDIDATE_SQL")
                .expect("candidate query missing");
            let fetch = body
                .find("fetch_optional")
                .expect("candidate fetch missing");
            assert!(!body[candidate_query..fetch].contains(".bind("));
        }
    }
}
