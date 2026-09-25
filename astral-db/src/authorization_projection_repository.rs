//! Rust-owned versioned authorization projection persistence primitives
//! (Phase 3 / P2 second slice).
//!
//! This module is the durable boundary for the generation-scoped authorization
//! projection chain owned by migration
//! `20260825000002_incremental_projection_archive.sql`. It implements staging,
//! atomic current-pointer publication, strict recovery reads, manifest lease
//! fencing, durable impact-plan persistence, delta-to-manifest publish linkage
//! validation and archive-outbox intents over these tables:
//!
//! - `authorization_grant_revision`: append-only revision ledger (owner:
//!   [`crate::grant_repository`]; listed here only because the combined
//!   projector contract documents the shared transaction story).
//! - `authorization_delta_event`: durable typed delta work queue with CAS
//!   lease claim / mark / release semantics (owner:
//!   [`crate::grant_repository`]).
//! - `authorization_impact_plan` + `authorization_impact_plan_item`: the
//!   durable compiler impact evidence per processed generation. Rows are
//!   appended idempotently; a replayed request resumes only when every
//!   immutable field and the full item list agree byte-for-byte.
//! - `authorization_projection_manifest`: one generation-scoped semantic proof.
//!   Rows leave `BUILDING` only through a lease-holding writer and reach
//!   `COMMITTED` only together with a successful current-pointer CAS.
//! - `authorization_projection_segment`: immutable content-addressed payload
//!   store keyed by `(tenant_id, content_digest)`. Existing rows are never
//!   updated or deleted; digest collisions must reproduce identical bytes and
//!   metadata or they are refused.
//! - `authorization_projection_manifest_segment`: ordinal references binding a
//!   manifest to its ordered segment list. Unchanged segments are reused by
//!   copying the parent reference row — never by deleting and re-inserting.
//! - `authorization_projection_current`: the per-aggregate current pointer,
//!   moved exclusively by an affected-rows-exactly-one CAS on
//!   `(generation, manifest_id, cas_version)`.
//! - `authorization_archive_outbox`: durable intent evidencing that the
//!   superseded parent manifest of a publication became asynchronous archive
//!   work. Writing the intent never proves archiving happened.
//! - `authorization_archive_manifest`: DB-resident durable proof that one
//!   superseded generation's full chain was re-read, re-digested and sealed
//!   under lock by this module ([`record_authorization_archive_proof_in_tx`]).
//!   It is a rehearsal/verification boundary INSIDE the database — it never
//!   claims an external backup succeeded, and no external storage or GC is
//!   implemented here. An outbox row may leave `LEASED` only through
//!   [`complete_authorization_archive_intent`], which requires exactly the
//!   terminal `ARCHIVED` proof first.
//!
//! # No double writer
//!
//! Every statement below writes ONLY the Rust-owned tables created by
//! migration `20260825000002_incremental_projection_archive.sql`, with ONE
//! explicit exception: the operator-driven legacy fence-proof rehearsal
//! ([`rehearse_legacy_fence_proof_in_tx`]) additionally appends one durable
//! audit correlation row to the shared `audit_log` table inside the SAME
//! transaction as its guarded pointer latch, reusing the established
//! in-transaction audit INSERT shape (see the trustgraph audit repository) so
//! the durable mutation can never exist without its audit evidence. The legacy
//! `permission_rule_snapshot` / `rule_set_snapshot` tables, the legacy
//! `authorization_projection_head`/outbox path, MQ queues and caches remain
//! exclusively owned by the existing worker; nothing in this module reads or
//! writes them, now or later. Conversely [`crate::grant_repository`] stays the
//! sole owner of the revision ledger and delta queue; the impact-plan /
//! manifest / segment / pointer / archive tables are solely owned here. The
//! future incremental projector will become the exclusive owner of the new
//! tables; until then nothing else may write them either.
//!
//! # Deliberately not implemented here
//!
//! No `authorization_delta_event` consumer loop, no ArchiveWorker, no source
//! writers, no legacy table access and no PolicyEngine wiring. The module
//! provides the primitives and a documented single-transaction orchestration
//! ([`project_authorization_delta_in_tx`]); background execution, retry
//! budgeting and scheduling stay outside. Callers own commit / rollback; this
//! module never commits, never touches Redis/MQ/network and performs no
//! compilation.
//!
//! # Lineage and revoke-fence persistence (migration 20260827000001)
//!
//! The additive migration `20260827000001_authorization_projection_lineage_fence.sql`
//! makes both remaining chain lines durable and this module enforces them on
//! every write and read:
//!
//! 1. `authorization_projection_manifest.parent_manifest_id` — staging writes
//!    NULL for a first generation and the locked current manifest id for every
//!    subsequent generation (whose own generation must equal target − 1 inside
//!    the same aggregate scope). Interrupted-retry replays of an identical
//!    `BUILDING` manifest compare BOTH new columns byte-for-byte; any drift is
//!    a conflict, never a silent resume.
//! 2. Revoke fences live on `authorization_projection_manifest.revoke_fence`,
//!    `authorization_projection_current.revoke_fence`,
//!    `authorization_archive_outbox.archived_revoke_fence` and
//!    `authorization_archive_manifest.archived_revoke_fence`. Publication
//!    takes the AUTHORITATIVE previous fence from the locked current pointer
//!    (`0` when absent) and refuses caller evidence that disagrees with it;
//!    the same value pins the pointer CAS `WHERE` clause and moves atomically
//!    inside that single `UPDATE`. The promoted manifest's fence is pinned to
//!    `evidence.new` by the guarded promotion statement. Archive intents and
//!    proofs copy the superseded parent's fence from the locked durable rows —
//!    callers may never guess or hand-supply it.
//!
//! # Zero sentinel (fail-closed historical boundary)
//!
//! Every `BIGINT NOT NULL DEFAULT 0` fence column starts at `0`, which means
//! "no revoke observed" OR "history predates this column and is not proven".
//! A stored `0` therefore never counts as positive proof of any fence level.
//! While a live pointer still carries the unproven sentinel, processing a
//! claimed delta whose stored `revoke_fence` requires more than 0 fails closed
//! ([`validate_zero_sentinel_fence_history`]) and demands an explicit
//! backfill/rehearsal pass; history is never inferred. Because raising a
//! fence only narrows authorization, a first honest publication with a higher
//! new fence remains representable — widening authorization from sentinel
//! state never is. The only legitimate escape from an unproven pointer is the
//! explicit per-pointer operator rehearsal
//! ([`rehearse_legacy_fence_proof_in_tx`]); there is no blanket, scheduled or
//! startup-time latch path anywhere in this module, and history is never
//! inferred from stored values.
//!
//! # Remaining known gaps (explicit, not silently worked around)
//!
//! The impact-plan tables still carry no compiler-side `full_rebuild` / reason
//! columns. That evidence survives only in the publish-time linkage check
//! ([`validate_compile_mode_evidence`]); there is no durable column, so
//! nothing is invented or silently dropped beyond that boundary.
//!
//! # Canonical identity and hash boundary
//!
//! - All `*_hash` / `*_digest` columns are `BINARY(32)` raw SHA-256 digests.
//!   The Rust wire form is the lowercase 64-character hex string; the shared
//!   [`Sha256Digest`] codec from the grant repository is the single round-trip
//!   implementation and rejects wrong lengths, non-hex characters and
//!   uppercase input.
//! - Segment rows are content-addressed and immutable. Their
//!   `content_digest` is SHA-256 over the canonical serialized grant vector
//!   (exactly [`encode_segment_payload`]'s bytes). Their `semantic_hash` /
//!   `dependency_hash` columns store SEGMENT-LOCAL seals
//!   ([`compute_segment_semantic_hash`] /
//!   [`compute_segment_dependency_hash`]) derived ONLY from the immutable
//!   segment-local dimensions: canonical payload bytes (through the verified
//!   content digest), tenant/aggregate/card scope, row count, storage format
//!   and the producing compiler version. Identical segments yield identical
//!   local seals across ANY number of generations, so unchanged segments are
//!   legitimately reused while a real delta moves the GLOBAL hashes. The
//!   manifest/global semantic and dependency hashes live exclusively on the
//!   delta-event, impact-plan, projection-manifest, projection-current and
//!   archive rows; they are NEVER compared against segment-local seals.
//!   Because the per-tenant content-address key `(tenant_id, content_digest)`
//!   holds exactly one row per payload, a byte-identical payload stamped by a
//!   different aggregate/card scope cannot mint a second row and fails closed
//!   as a [`AuthorizationProjectionError::SegmentDigestCollision`] — that is
//!   the Phase 1 modeling limit, reported loudly instead of hidden. The
//!   compiler-version stamp is the ONE carve-out: when ONLY the producing
//!   compiler version disagrees (payload bytes, scope and format all proven
//!   equal), the row reports the stable machine code
//!   [`SEGMENT_COMPILER_STAMP_DIVERGENCE_CODE`]. The payload is proven
//!   intact there, so a future compiler upgrade that legitimately reuses
//!   content is a stamp-ownership decision for operators — NOT durable data
//!   corruption — while still refusing to mint a second row or publish a
//!   manifest that disagrees with its referenced segment stamps.
//! - Grant identities inside segment payloads are typed
//!   [`astral_types::GrantId`] UUIDs serialized as lowercase hyphenated text;
//!   payload decoding revalidates every grant contractually and rejects any
//!   non-canonical re-encoding.
//! - Logical versions (`generation`, `source_generation`,
//!   `projected_generation`) use the unsigned `u64` domain; SQL `BIGINT`
//!   storage uses checked conversions failing closed on overflow or negative
//!   read-backs ([`bind_u64`] / [`read_counter_i64`]). Per-grant projection
//!   `*_version` pairs follow the delta-event convention (`i64`, `0 <= base <
//!   target`).
//! - Aggregate identity is `(tenant_id, aggregate_type, aggregate_id)`; every
//!   cross-row consistency check covers all three parts plus the optional card
//!   scope. Any inconsistency fails closed with an explicit error.
//!
//! # DB DTO conversion boundary
//!
//! This module owns independent database DTOs because the SQL primary keys are
//! `BIGINT` while [`astral_types::ProjectionManifest`] types manifest identity
//! as a UUID and carries fields (compile mode, fallback reason) this slice
//! intentionally persists nowhere. Bridging stays an explicit caller concern
//! so no implicit lossy coercion exists between the two layers. Compiler
//! `ImpactPlan`/`SegmentImpact` values enter through
//! [`impact_plan_request_from_compiler_plan`] which drops what the schema
//! cannot store (stable segment-id strings; ordering is carried by
//! `projection_key`) rather than inventing columns.
//!
//! # Statuses and transitions
//!
//! Manifest: `BUILDING -> READY -> COMMITTED -> SUPERSEDED` (plus quarantine
//! from `BUILDING`/`READY` while leased). `SUPERSEDED` is terminal so history
//! stays readable; hot rows are never deleted anywhere in this module.
//! Promotion to `COMMITTED` clears the builder lease columns inside the same
//! CAS-pinned update, so no manifest leaves `READY` still carrying residual
//! owner/token/expiry evidence and recovery reads never report a terminal
//! manifest as leased.
//! Pointer/reference/segment statuses stay `READY`; unknown stored status
//! strings are refused, never normalized.
//! Impact-plan root: `PENDING -> SUCCEEDED` (parsed strictly, unknown strings
//! refused; items require `PENDING` while this module exposes no item
//! mutation). Archive outbox: `PENDING -> LEASED` on claim, `LEASED ->
//! SUCCEEDED` only after a verified durable archive-manifest proof exists
//! (stamping `archived_at`), `LEASED/PENDING -> PENDING` on failure/release
//! backoff, operator quarantine from `PENDING`/`LEASED` with live lease proof.
//! Archive manifest: schema-default `STAGED`, terminal `ARCHIVED` with an
//! exclusive `archived_at` stamp; unknown strings are corrupt storage.
//!
//! # Lock order (single MySQL session/transaction)
//!
//! Legacy-projector order used by stage/publish/recover paths:
//! 1. `authorization_projection_current` — pointer row `FOR UPDATE`.
//! 2. `authorization_projection_manifest` — parent then target rows.
//! 3. `authorization_projection_manifest_segment` — references of locked
//!    manifests ordered by `segment_ordinal`.
//! 4. `authorization_projection_segment` — referenced content rows.
//!
//! The combined projector contract
//! ([`project_authorization_delta_in_tx`]) prefixes a fixed head so no
//! statement cycle can ever form with the owner modules of the other tables:
//! 0. `authorization_delta_event` row `FOR UPDATE` (granted identity,
//!    locked by [`crate::grant_repository::load_claimed_delta_event_for_update_in_tx`])
//!    — no other path ever takes a manifest-chain lock while holding this one,
//!    and the delta owner never takes a pointer lock afterwards inside one
//!    transaction. The full fixed sequence is therefore acyclic:
//!    `delta -> current-pointer observation -> impact_plan(_item) ->
//!    projection_manifest(+segments, finalize) -> archive_outbox(intent) ->
//!    projection_current pointer CAS -> plan/delta completion`.
//! Staging inserts are additionally arbitrated by the table unique keys.
//! Archive intents are written strictly after the target manifest finalized
//! and strictly before the pointer CAS, inside the caller's transaction.
//! `complete_authorization_archive_intent` reads the archive-manifest proof
//! under `FOR UPDATE` BEFORE flipping its outbox row to `SUCCEEDED` inside
//! that same transaction: durable proof first, terminal intent second.
//!
//! Planning readers ([`load_published_aggregate_frontier_in_tx`] /
//! [`load_published_parent_reference_views_in_tx`]) extend the same fixed
//! sequence with read-side locks:
//! current-pointer → manifest (+ references/segments through
//! [`read_published_authorization_state_in_tx`]) → impact plans
//! (`target_generation <= G`, ascending) → one delta row per plan event.
//! Concurrent projectors acquire the delta row FIRST (step 0 above), so
//! opposite acquisition orders can surface engine-detected deadlocks; callers
//! treat those aborts as retryable whole-transaction failures. Planning
//! outputs are HINTS for pure scheduling code, never publish proofs — every
//! stage/publish transaction repeats all verification inside its guarded
//! statements.
//!
//! # Delta-event quarantine vocabulary pointer
//!
//! The `authorization_delta_event` owner module defines the terminal
//! `QUARANTINED` state (`crate::grant_repository::DELTA_STATUS_QUARANTINED`)
//! including its claim/readback exclusions and the explicit operator-only
//! requeue boundary. Nothing in this module writes or bypasses that state;
//! frontier assembly additionally refuses any non-`SUCCEEDED` delta row, so a
//! quarantined event can never prove an aggregate generation here. Because
//! the queue schema carries no `quarantined_at` column, `updated_at` is the
//! minimal durable terminal timestamp evidence and operator audit trails stay
//! composed of `event_id`/`operation_id`/`cas_version`/`last_error`.

use std::fmt;

use sha2::{Digest, Sha256};
use sqlx::{Executor, MySql, MySqlPool, Transaction};
use time::{OffsetDateTime, PrimitiveDateTime};

use astral_types::{
    CanonicalGrant, GrantContractError, GrantId, GrantState, ProjectionCompileMode,
    PublishedAggregateManifestSummary, PublishedCardAuthorization, PublishedCardAuthorizationGate,
    PublishedCardEvidenceScope, PublishedEvidenceGateStatus, UnacceptedGrantReason, ValidityWindow,
    VerifiedPublishedGrantRecord,
};

pub use crate::grant_repository::Sha256Digest;

// ─────────────────────────────────────────────────────────────────────────────
// Constants mirrored from migration 20260825000002_incremental_projection_archive.sql
// ─────────────────────────────────────────────────────────────────────────────

/// Manifest status while a builder is assembling references (schema default).
pub const MANIFEST_STATUS_BUILDING: &str = "BUILDING";
/// Manifest status after completeness validation succeeded.
pub const MANIFEST_STATUS_READY: &str = "READY";
/// Manifest status once it became the current pointer target.
pub const MANIFEST_STATUS_COMMITTED: &str = "COMMITTED";
/// Terminal status of a previous current manifest after a successful CAS.
pub const MANIFEST_STATUS_SUPERSEDED: &str = "SUPERSEDED";
/// Operator-quarantined status; never publishes again without intervention.
pub const MANIFEST_STATUS_QUARANTINED: &str = "QUARANTINED";

/// Reference and segment readiness status used by the schema defaults.
pub const PROJECTION_STATUS_READY: &str = "READY";

/// Storage format tag of segment payloads written and verified by this module.
pub const SEGMENT_FORMAT_AUTHORIZATION_GRANTS_JSON_V1: &str = "authorization_grants_json_v1";

/// Stable machine code for the compiler-stamp-only segment divergence: a
/// byte-identical payload already exists under `(tenant_id, content_digest)`
/// but was stamped by a different producer compiler version.
///
/// The content digest lookup plus the identity/card/format equality checks in
/// [`assert_identical_segment`] PROVE the payload bytes are intact, so this is
/// the documented Phase 1 modeling limit for a compiler upgrade that
/// legitimately reuses content — a stamp-ownership decision for operators,
/// never an "accidental permanent data corruption" signal. It is still
/// deterministically unresolvable inside one worker attempt (the row is
/// immutable and the key admits one row per payload), so callers must fail
/// closed WITHOUT publishing; the dedicated code lets downstream routers pick
/// a distinct conservative quarantine path instead of the corruption family.
pub const SEGMENT_COMPILER_STAMP_DIVERGENCE_CODE: &str =
    "code=authorization_projection.segment_compiler_stamp_divergence";

// Column-width contracts are single-sourced from the grant repository module
// so both slices can never drift apart on the mirrored migration limits.
use crate::grant_repository::{
    ClaimedDeltaEvent, DeltaEventClaim, DeltaEventType, DeltaLeaseIdentity, DELTA_STATUS_SUCCEEDED,
    MAX_AGGREGATE_TYPE_LENGTH, MAX_COMPILER_VERSION_LENGTH, MAX_EVENT_ID_LENGTH,
    MAX_GRANT_LEASE_OWNER_LENGTH, MAX_GRANT_OPERATION_ID_LENGTH, MAX_LAST_ERROR_LENGTH,
};

/// Defensive capacity caps for one manifest build.
pub const MAX_SEGMENTS_PER_MANIFEST: usize = 100_000;
pub const MAX_SEGMENT_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
/// Upper bound for one manifest lease duration in seconds.
pub const MAX_MANIFEST_LEASE_SECONDS: i64 = 3_600;

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Repository errors. Every variant fails closed; none authorizes anything.
#[derive(Debug, thiserror::Error)]
pub enum AuthorizationProjectionError {
    /// A shared grant contract rejected the input.
    #[error("grant contract validation failed: {0}")]
    Contract(#[from] GrantContractError),

    /// Stored data violated its declared shape; refused instead of normalized.
    #[error("row mapping failed: {0}")]
    Mapping(String),

    /// A database driver error occurred.
    #[error("database query failed: {0}")]
    Query(#[from] sqlx::Error),

    /// Request fields disagreed with each other or with the declared scope.
    #[error("scope violation: {0}")]
    ScopeViolation(String),

    /// An insert lost a unique-key race and the winner could not be proven
    /// byte-for-byte identical.
    #[error("duplicate durable row: {0}")]
    DuplicateRow(String),

    /// A replayed idempotent append disagreed with the durable winner on at
    /// least one immutable field (or an extra/missing item, hash drift or
    /// foreign-event unique-key occupation was proven). Never swallowed via
    /// `ON DUPLICATE KEY`; the caller must quarantine or escalate.
    #[error("immutable conflict: {0}")]
    ImmutableConflict(String),

    /// Two different payloads claimed one content digest (or identical bytes
    /// collide across aggregates, or a stored row disagrees with its own
    /// recomputed local seals / format stamp); storage stays untouched either
    /// way. EXCEPT the compiler-stamp-only divergence, which carries
    /// [`SEGMENT_COMPILER_STAMP_DIVERGENCE_CODE`] instead: byte-identical
    /// content is proven there, so that case is a metadata modeling limit,
    /// never corruption.
    #[error("segment digest collision: {0}")]
    SegmentDigestCollision(String),

    /// A row's tenant/aggregate/card identity disagreed with the request.
    #[error("projection identity mismatch: {0}")]
    IdentityMismatch(String),

    /// A lease-guarded mutation matched zero rows (expired/stolen/unknown).
    #[error("manifest lease CAS failed: {0}")]
    LeaseCasFailed(String),

    /// A row locked in the same transaction changed underneath a claim update.
    #[error("claim race while holding the row lock; refusing to continue")]
    ClaimRace,

    /// The current-pointer CAS matched zero rows; nothing was published.
    #[error("current pointer CAS conflict: {0}")]
    CurrentPointerCasConflict(String),

    /// Publish preconditions rejected the target manifest transition.
    #[error("manifest publish conflict: {0}")]
    ManifestPublishConflict(String),

    /// Read-back found missing/incomplete durable evidence.
    #[error("projection state not ready: {0}")]
    NotReady(String),

    /// Read-back found corrupt or inconsistent projection data.
    #[error("corrupt projection state: {0}")]
    Corrupt(String),

    /// An illegal manifest status transition was attempted.
    #[error("illegal manifest status transition from '{from}' to '{to}'")]
    IllegalStatusTransition { from: String, to: String },
}

/// Uniform conversion so the shared [`Sha256Digest`] codec (which reports
/// `GrantRepositoryError`) composes directly with this module's fail-closed
/// error type; variant semantics map one-to-one.
impl From<crate::grant_repository::GrantRepositoryError> for AuthorizationProjectionError {
    fn from(error: crate::grant_repository::GrantRepositoryError) -> Self {
        use crate::grant_repository::GrantRepositoryError as GrantError;
        match error {
            GrantError::Contract(inner) => AuthorizationProjectionError::Contract(inner),
            GrantError::Mapping(message) => AuthorizationProjectionError::Mapping(message),
            GrantError::Query(inner) => AuthorizationProjectionError::Query(inner),
            GrantError::ScopeViolation(message) => {
                AuthorizationProjectionError::ScopeViolation(message)
            }
            GrantError::RevisionConflict(conflict) => AuthorizationProjectionError::Mapping(
                format!("code=authorization_projection.grant_ledger_conflict;conflict={conflict}"),
            ),
            GrantError::DuplicateDeltaEvent(message) => {
                AuthorizationProjectionError::DuplicateRow(message)
            }
            GrantError::LeaseCasFailed(message) => {
                AuthorizationProjectionError::LeaseCasFailed(message)
            }
            GrantError::ClaimRace => AuthorizationProjectionError::ClaimRace,
        }
    }
}

fn scope_violation(code: &str) -> AuthorizationProjectionError {
    AuthorizationProjectionError::ScopeViolation(format!("code={code}"))
}

fn mapping_error(code: String) -> AuthorizationProjectionError {
    AuthorizationProjectionError::Mapping(code)
}

fn unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(|database| database.is_unique_violation())
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared checked numeric conversions (fail-closed BIGINT/INT boundary)
// ─────────────────────────────────────────────────────────────────────────────

/// Bind an unsigned logical version into the signed `BIGINT` SQL domain.
fn bind_u64(value: u64, field: &'static str) -> Result<i64, AuthorizationProjectionError> {
    i64::try_from(value).map_err(|_| {
        mapping_error(format!(
            "code=authorization_projection.bigint_overflow;field={field}"
        ))
    })
}

/// Accept a stored `BIGINT` counter only when non-negative and convertible.
fn read_counter_i64(value: i64, field: &'static str) -> Result<u64, AuthorizationProjectionError> {
    u64::try_from(value).map_err(|_| {
        mapping_error(format!(
            "code=authorization_projection.negative_bigint;field={field};value={value}"
        ))
    })
}

/// Bind an unsigned ordinal into the signed `INT` column domain.
fn bind_i32(value: u64, field: &'static str) -> Result<i32, AuthorizationProjectionError> {
    i32::try_from(value).map_err(|_| {
        mapping_error(format!(
            "code=authorization_projection.int32_overflow;field={field}"
        ))
    })
}

fn positive_i64(value: i64, field: &'static str) -> Result<(), AuthorizationProjectionError> {
    if value <= 0 {
        return Err(scope_violation(&format!(
            "authorization_projection.non_positive_id;field={field};value={value}"
        )));
    }
    Ok(())
}

fn validated_text(
    value: &str,
    max_length: usize,
    field: &str,
) -> Result<(), AuthorizationProjectionError> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.len() > max_length
        || trimmed
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(scope_violation(&format!(
            "authorization_projection.invalid_field;field={field};max_length={max_length}"
        )));
    }
    Ok(())
}

fn validated_aggregate_type(value: &str) -> Result<(), AuthorizationProjectionError> {
    validated_text(value, MAX_AGGREGATE_TYPE_LENGTH, "aggregate_type")?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(scope_violation(
            "authorization_projection.invalid_aggregate_type_charset",
        ));
    }
    Ok(())
}

fn truncate_last_error(reason: &str) -> String {
    reason.chars().take(MAX_LAST_ERROR_LENGTH).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Statuses
// ─────────────────────────────────────────────────────────────────────────────

/// Typed manifest lifecycle state. Unknown stored strings are refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationManifestStatus {
    Building,
    Ready,
    Committed,
    Superseded,
    Quarantined,
}

impl AuthorizationManifestStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Building => MANIFEST_STATUS_BUILDING,
            Self::Ready => MANIFEST_STATUS_READY,
            Self::Committed => MANIFEST_STATUS_COMMITTED,
            Self::Superseded => MANIFEST_STATUS_SUPERSEDED,
            Self::Quarantined => MANIFEST_STATUS_QUARANTINED,
        }
    }

    pub fn parse(value: &str) -> Result<Self, AuthorizationProjectionError> {
        match value {
            MANIFEST_STATUS_BUILDING => Ok(Self::Building),
            MANIFEST_STATUS_READY => Ok(Self::Ready),
            MANIFEST_STATUS_COMMITTED => Ok(Self::Committed),
            MANIFEST_STATUS_SUPERSEDED => Ok(Self::Superseded),
            MANIFEST_STATUS_QUARANTINED => Ok(Self::Quarantined),
            other => Err(mapping_error(format!(
                "code=authorization_projection.unknown_manifest_status;value={other}"
            ))),
        }
    }

    /// Pure transition gate mirroring the SQL guarded updates.
    ///
    /// Allowed edges: BUILDING→READY, BUILDING→QUARANTINED, READY→COMMITTED,
    /// READY→QUARANTINED, COMMITTED→SUPERSEDED, COMMITTED→QUARANTINED.
    /// Everything else (including self-edges and any move out of `SUPERSEDED`)
    /// is refused.
    pub const fn can_transition_to(self, next: Self) -> bool {
        use AuthorizationManifestStatus::*;
        matches!(
            (self, next),
            (Building, Ready)
                | (Building, Quarantined)
                | (Ready, Committed)
                | (Ready, Quarantined)
                | (Committed, Superseded)
                | (Committed, Quarantined)
        )
    }

    pub fn validate_transition(self, next: Self) -> Result<(), AuthorizationProjectionError> {
        if self.can_transition_to(next) {
            Ok(())
        } else {
            Err(AuthorizationProjectionError::IllegalStatusTransition {
                from: self.as_str().to_owned(),
                to: next.as_str().to_owned(),
            })
        }
    }
}

impl fmt::Display for AuthorizationManifestStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Identity and staging value types
// ─────────────────────────────────────────────────────────────────────────────

/// Canonical aggregate identity `(tenant_id, aggregate_type, aggregate_id)`.
///
/// Every statement binds all three fields together with the optional card
/// scope, so cross-tenant/cross-aggregate rows can never be mistaken for each
/// other even when digest keys collide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionAggregateIdentity {
    pub tenant_id: i64,
    pub aggregate_type: String,
    pub aggregate_id: i64,
}

impl ProjectionAggregateIdentity {
    pub fn new(
        tenant_id: i64,
        aggregate_type: impl Into<String>,
        aggregate_id: i64,
    ) -> Result<Self, AuthorizationProjectionError> {
        let identity = Self {
            tenant_id,
            aggregate_type: aggregate_type.into(),
            aggregate_id,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<(), AuthorizationProjectionError> {
        positive_i64(self.tenant_id, "tenant_id")?;
        positive_i64(self.aggregate_id, "aggregate_id")?;
        validated_aggregate_type(&self.aggregate_type)?;
        Ok(())
    }
}

fn validated_option_card_id(card_id: Option<i64>) -> Result<(), AuthorizationProjectionError> {
    match card_id {
        None => Ok(()),
        Some(card_id) => positive_i64(card_id, "card_id"),
    }
}

/// One ordered segment entry inside a staging plan.
///
/// `New` serializes compiler-side contributions into fresh canonical payload
/// bytes; `ReuseParent` copies one unchanged parent reference (resolved under
/// lock during staging). Ordinals are the vector positions: contiguous from
/// zero by construction and re-validated before any write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StagedSegmentContent {
    New(Vec<CanonicalGrant>),
    ReuseParent { parent_ordinal: u64 },
}

/// Fully validated staging input for one target manifest generation.
#[derive(Debug, Clone)]
pub struct AuthorizationStageRequest {
    pub identity: ProjectionAggregateIdentity,
    /// Card scope carried into every written row (`None` = aggregate-wide).
    pub card_id: Option<i64>,
    /// Target generation; equals `current + 1` when a pointer already exists,
    /// otherwise exactly `1`.
    pub target_generation: u64,
    /// Highest source generation observed by the compiling caller.
    pub source_generation: u64,
    /// Source generation covered by this projected candidate; may not exceed
    /// `source_generation`.
    pub projected_generation: u64,
    pub event_id: String,
    pub operation_id: String,
    pub semantic_hash_hex: String,
    pub dependency_hash_hex: String,
    pub compiler_version: String,
    /// Revoke fence this generation will be published under. Persisted on the
    /// `BUILDING` manifest row and re-pinned by the publish promotion; the
    /// staged value must equal `evidence.new` at publication time.
    pub revoke_fence: u64,
    pub segments: Vec<StagedSegmentContent>,
}

/// Durable evidence returned by successful staging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationStageOutcome {
    pub manifest_id: i64,
    pub manifest_digest: Sha256Digest,
    pub target_generation: u64,
    pub total_grant_count: u64,
    pub new_segment_count: u64,
    pub reused_segment_count: u64,
    /// True when the manifest row already existed byte-for-byte identically
    /// (interrupted-retry resume); false after a fresh insert.
    pub resumed_existing_manifest: bool,
    /// Locked pointer state seen before staging.
    pub base_pointer: Option<AuthorizationCurrentPointerRecord>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure codecs and validators (no I/O; unit-tested below)
// ─────────────────────────────────────────────────────────────────────────────

/// Serialize one exact-key segment payload canonically and return its bytes.
///
/// Layout is `serde_json` over an ordered vector of canonical grants using the
/// shared camelCase contract wire form. Content addressing covers these exact
/// bytes, so read-back verification can recompute the digest without trusting
/// metadata.
pub fn encode_segment_payload(
    grants: &[CanonicalGrant],
) -> Result<Vec<u8>, AuthorizationProjectionError> {
    for grant in grants {
        grant.canonicalized()?;
    }
    let bytes = serde_json::to_vec(grants).map_err(|error| {
        scope_violation(&format!(
            "authorization_projection.segment_payload_serialization;error={error}"
        ))
    })?;
    if bytes.len() > MAX_SEGMENT_PAYLOAD_BYTES {
        return Err(scope_violation(
            "authorization_projection.segment_payload_too_large",
        ));
    }
    Ok(bytes)
}

/// Decode and fully revalidate one stored segment payload.
///
/// Rows whose bytes no longer parse back to their canonical form are poisoned
/// storage and refused instead of being repaired silently.
pub fn decode_segment_payload(
    bytes: &[u8],
) -> Result<Vec<CanonicalGrant>, AuthorizationProjectionError> {
    let grants: Vec<CanonicalGrant> = serde_json::from_slice(bytes).map_err(|_| {
        mapping_error("code=authorization_projection.segment_payload_unparsable".to_owned())
    })?;
    for grant in &grants {
        grant.canonicalized()?;
    }
    let recanonicalized = serde_json::to_vec(&grants).map_err(|error| {
        mapping_error(format!(
            "code=authorization_projection.segment_payload_reserialization_failed;error={error}"
        ))
    })?;
    if recanonicalized != bytes {
        return Err(mapping_error(
            "code=authorization_projection.noncanonical_segment_payload".to_owned(),
        ));
    }
    Ok(grants)
}

/// Raw SHA-256 over arbitrary canonical bytes.
fn sha256_digest_bytes(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

/// Deterministic manifest digest composition input.
///
/// The digest seals the whole semantic proof: aggregate identity, generation
/// fences, provenance ids, hashes, compiler version and the ordered digest
/// list of every referenced segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestDigestInput<'a> {
    pub tenant_id: i64,
    pub aggregate_type: &'a str,
    pub aggregate_id: i64,
    pub card_id: Option<i64>,
    pub generation: u64,
    pub source_generation: u64,
    pub projected_generation: u64,
    pub event_id: &'a str,
    pub operation_id: &'a str,
    pub semantic_hash_hex: &'a str,
    pub dependency_hash_hex: &'a str,
    pub compiler_version: &'a str,
    /// Durable parent lineage (`None` only for the first generation).
    pub parent_manifest_id: Option<i64>,
    /// Revoke fence sealed into this manifest generation.
    pub revoke_fence: u64,
    /// Ordered lowercase-hex content digests of the manifest's segments.
    pub segment_content_digests_hex: Vec<String>,
}

impl<'a> ManifestDigestInput<'a> {
    fn digest_hexes(&self) -> Result<Vec<[u8; 32]>, AuthorizationProjectionError> {
        self.segment_content_digests_hex
            .iter()
            .map(|hex| {
                Sha256Digest::from_hex(hex)
                    .map(|digest| digest.as_bytes())
                    .map_err(AuthorizationProjectionError::from)
            })
            .collect()
    }
}

/// Compute the sealed `authorization_projection_manifest.manifest_digest`.
///
/// Fixed-width big-endian counters plus length-prefixed ASCII keep the binary
/// encoding unambiguous without depending on serializer key ordering; empty
/// versus missing strings stay distinguishable.
pub fn compute_manifest_digest(
    input: &ManifestDigestInput<'_>,
) -> Result<Sha256Digest, AuthorizationProjectionError> {
    if !input.aggregate_type.is_ascii() || !input.compiler_version.is_ascii() {
        return Err(scope_violation(
            "authorization_projection.non_ascii_manifest_digest_field",
        ));
    }
    if !input.event_id.is_ascii() || !input.operation_id.is_ascii() {
        return Err(scope_violation(
            "authorization_projection.non_ascii_provenance_digest_field",
        ));
    }
    let mut material = Vec::with_capacity(280);
    material.extend_from_slice(b"astral-auth-manifest-v2");
    material.extend_from_slice(&input.tenant_id.to_be_bytes());
    material.extend_from_slice(input.aggregate_type.as_bytes());
    material.push(b'\x00');
    material.extend_from_slice(&input.aggregate_id.to_be_bytes());
    match input.card_id {
        None => material.extend_from_slice(&(-1_i64).to_be_bytes()),
        Some(card_id) => material.extend_from_slice(&card_id.to_be_bytes()),
    }
    material.extend_from_slice(&bind_u64(input.generation, "generation")?.to_be_bytes());
    material
        .extend_from_slice(&bind_u64(input.source_generation, "source_generation")?.to_be_bytes());
    material.extend_from_slice(
        &bind_u64(input.projected_generation, "projected_generation")?.to_be_bytes(),
    );
    material.extend_from_slice(&encode_len_prefixed_text(input.event_id, "event_id"));
    material.extend_from_slice(&encode_len_prefixed_text(
        input.operation_id,
        "operation_id",
    ));
    material.extend_from_slice(&Sha256Digest::from_hex(input.semantic_hash_hex)?.as_bytes());
    material.extend_from_slice(&Sha256Digest::from_hex(input.dependency_hash_hex)?.as_bytes());
    material.extend_from_slice(&encode_len_prefixed_text(
        input.compiler_version,
        "compiler_version",
    ));
    match input.parent_manifest_id {
        None => material.extend_from_slice(&(-1_i64).to_be_bytes()),
        Some(parent_manifest_id) => {
            positive_i64(parent_manifest_id, "parent_manifest_id")?;
            material.extend_from_slice(&parent_manifest_id.to_be_bytes());
        }
    }
    material.extend_from_slice(&bind_u64(input.revoke_fence, "revoke_fence")?.to_be_bytes());
    for digest in input.digest_hexes()? {
        material.extend_from_slice(&digest);
    }
    Ok(Sha256Digest::from_raw_bytes(sha256_digest_bytes(&material)))
}

fn encode_len_prefixed_text(value: &str, field: &'static str) -> Vec<u8> {
    // Length prefixes keep empty strings distinguishable from absent fields;
    // upstream validation caps every participating field far below u32::MAX.
    let length = u32::try_from(value.len())
        .unwrap_or_else(|_| panic!("{field} exceeded digest encoding budget"));
    let mut encoded = length.to_be_bytes().to_vec();
    encoded.extend_from_slice(value.as_bytes());
    encoded
}

// ─────────────────────────────────────────────────────────────────────────────
// Segment-local seals (immutable per segment; independent of any generation)
// ─────────────────────────────────────────────────────────────────────────────

/// Domain separator of the SEGMENT-LOCAL semantic seal.
pub const SEGMENT_SEAL_DOMAIN_SEMANTIC: &[u8] = b"astral-auth-segment-seal-v1/semantic";
/// Domain separator of the SEGMENT-LOCAL dependency seal.
pub const SEGMENT_SEAL_DOMAIN_DEPENDENCY: &[u8] = b"astral-auth-segment-seal-v1/dependency";

/// Every immutable local dimension a segment row's hash columns must seal.
///
/// This is the complete seal surface — nothing else may enter. The canonical
/// payload bytes and their grant set enter through `content_digest`, which is
/// verified byte-for-byte against `segment_payload` on every read; identity,
/// card scope, format, row count and compiler version are stored next to it
/// and re-validated together with the seals on every decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentLocalSealInput<'a> {
    pub identity: &'a ProjectionAggregateIdentity,
    pub card_id: Option<i64>,
    pub compiler_version: &'a str,
    pub segment_format: &'a str,
    pub row_count: u64,
    /// Verified digest over the canonical segment payload bytes.
    pub content_digest: &'a Sha256Digest,
}

/// Compute one deterministic segment-local seal under an explicit domain tag.
///
/// Encoding mirrors [`compute_manifest_digest`] (big-endian counters plus
/// length-prefixed text) so fields cannot alias. These seals answer exactly
/// one question: "is this immutable segment content still what its hash columns
/// claim?" They deliberately EXCLUDE the manifest's global semantic/dependency
/// hashes, generation numbers, event ids and provenance, so unchanged segments
/// keep equal seals across generations while global hashes legitimately move.
pub fn compute_segment_local_seal(
    domain_tag: &[u8],
    input: &SegmentLocalSealInput<'_>,
) -> Result<Sha256Digest, AuthorizationProjectionError> {
    input.identity.validate()?;
    validated_option_card_id(input.card_id)?;
    if !input.identity.aggregate_type.is_ascii()
        || !input.compiler_version.is_ascii()
        || !input.segment_format.is_ascii()
    {
        return Err(scope_violation(
            "authorization_projection.non_ascii_segment_seal_field",
        ));
    }
    let mut material = Vec::with_capacity(192);
    material.extend_from_slice(domain_tag);
    material.extend_from_slice(&input.identity.tenant_id.to_be_bytes());
    material.push(b'\x00');
    material.extend_from_slice(input.identity.aggregate_type.as_bytes());
    material.extend_from_slice(&input.identity.aggregate_id.to_be_bytes());
    match input.card_id {
        None => material.extend_from_slice(&(-1_i64).to_be_bytes()),
        Some(card_id) => material.extend_from_slice(&card_id.to_be_bytes()),
    }
    material.extend_from_slice(&bind_u64(input.row_count, "segment.row_count")?.to_be_bytes());
    material.extend_from_slice(&encode_len_prefixed_text(
        input.compiler_version,
        "segment.compiler_version",
    ));
    material.extend_from_slice(&encode_len_prefixed_text(
        input.segment_format,
        "segment.segment_format",
    ));
    material.extend_from_slice(&input.content_digest.as_bytes());
    Ok(Sha256Digest::from_raw_bytes(sha256_digest_bytes(&material)))
}

/// The segment-row `semantic_hash` column's pure meaning: a local seal over
/// only the segment's own immutable content ([`SegmentLocalSealInput`]).
pub fn compute_segment_semantic_hash(
    input: &SegmentLocalSealInput<'_>,
) -> Result<Sha256Digest, AuthorizationProjectionError> {
    compute_segment_local_seal(SEGMENT_SEAL_DOMAIN_SEMANTIC, input)
}

/// The segment-row `dependency_hash` column's pure meaning: a sibling local
/// seal with a distinct domain tag, never colliding with the semantic seal.
pub fn compute_segment_dependency_hash(
    input: &SegmentLocalSealInput<'_>,
) -> Result<Sha256Digest, AuthorizationProjectionError> {
    compute_segment_local_seal(SEGMENT_SEAL_DOMAIN_DEPENDENCY, input)
}

/// Re-derive and enforce a decoded segment snapshot's LOCAL seal pair.
///
/// This is the only admissibility rule for a segment row's hash columns:
/// recomputation from the immutable local dimensions must reproduce exactly
/// what is stored. Tampered payload digests, card scopes, compiler stamps,
/// formats, row counts or either hash column fail closed as corrupt storage.
pub fn verify_segment_local_seal(
    snapshot: &AuthorizationSegmentSnapshot,
) -> Result<(), AuthorizationProjectionError> {
    let input = SegmentLocalSealInput {
        identity: &snapshot.identity,
        card_id: snapshot.card_id,
        compiler_version: &snapshot.compiler_version,
        segment_format: &snapshot.format,
        row_count: snapshot.row_count,
        content_digest: &snapshot.content_digest,
    };
    let expected_semantic = compute_segment_semantic_hash(&input)?;
    let expected_dependency = compute_segment_dependency_hash(&input)?;
    if snapshot.semantic_hash != expected_semantic
        || snapshot.dependency_hash != expected_dependency
    {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.segment_local_seal_mismatch".to_owned(),
        ));
    }
    Ok(())
}

/// Prove one manifest-reference row and its referenced content row agree on
/// every reuse-relevant immutable dimension.
///
/// Used while staging `ReuseParent` entries, by every strict
/// finalize/publish/read/recovery segment load, and mirrored by the pure tests:
/// the reference must carry the same aggregate identity as the manifest chain,
/// point at the verified content digest it claims, and the segment must pass
/// its own LOCAL seal ([`verify_segment_local_seal`]). No comparison against
/// any manifest-global hash happens here by design — requiring segments to
/// equal their manifest's global hashes was exactly the bug this module fixed
/// (unchanged segments must survive global-hash movement across generations).
pub fn verify_reference_content_pair(
    reference: &AuthorizationSegmentReferenceRecord,
    snapshot: &AuthorizationSegmentSnapshot,
    identity: &ProjectionAggregateIdentity,
) -> Result<(), AuthorizationProjectionError> {
    if reference.identity != *identity || snapshot.identity != *identity {
        return Err(AuthorizationProjectionError::IdentityMismatch(
            "code=authorization_projection.parent_reference_identity_mismatch".to_owned(),
        ));
    }
    if snapshot.content_digest != reference.content_digest {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.parent_reference_digest_mismatch".to_owned(),
        ));
    }
    verify_segment_local_seal(snapshot)
}

/// Re-prove a PARENT manifest's own sealed digest chain before its segments
/// may be reused across generations.
///
/// The check is strictly self-referential: it recomputes the parent manifest
/// digest from the PARENT ROW'S OWN stored global hashes plus its ordered
/// reference content digests and compares with the stored seal. It never
/// involves the target generation's global hashes — a real delta moves those
/// without invalidating parent-chain evidence.
fn verify_parent_manifest_chain(
    parent: &ManifestRawSqlRow,
    references: &[AuthorizationSegmentReferenceRecord],
) -> Result<(), AuthorizationProjectionError> {
    let counted: Vec<(u64, u64)> = references.iter().map(|r| (r.ordinal, 0_u64)).collect();
    validate_contiguous_ordinals(&counted)?;
    let recomputed = parent.recomputed_digest(
        references
            .iter()
            .map(|r| r.content_digest.as_hex())
            .collect(),
    )?;
    let (_, _, stored) = parent.decode_hashes()?;
    if recomputed != stored {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.parent_manifest_digest_seal_broken".to_owned(),
        ));
    }
    Ok(())
}

/// Validate that `(ordinal, count)` pairs enumerate a contiguous
/// duplicate-free sequence starting at zero and sum the counts.
pub fn validate_contiguous_ordinals(
    entries: &[(u64, u64)],
) -> Result<u64, AuthorizationProjectionError> {
    let mut total: u64 = 0;
    for (position, (ordinal, count)) in entries.iter().enumerate() {
        let expected = position as u64;
        if *ordinal != expected {
            return Err(mapping_error(format!(
                "code=authorization_projection.ordinal_gap;expected={expected};actual={ordinal}"
            )));
        }
        total = total.checked_add(*count).ok_or_else(|| {
            mapping_error("code=authorization_projection.grant_count_overflow".to_owned())
        })?;
    }
    Ok(total)
}

/// Minimal borrowed view of one parent reference row used by pure validators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentReferenceView {
    pub ordinal: u64,
    pub identity: ProjectionAggregateIdentity,
    pub segment_id: i64,
    pub content_digest_hex: String,
}

/// Validate one staged plan against the locked parent reference records.
///
/// Rules enforced purely:
/// - plan size caps at [`MAX_SEGMENTS_PER_MANIFEST`];
/// - reused ordinals must exist in the parent set;
/// - each parent ordinal may be reused by at most ONE plan entry (duplicate
///   `ReuseParent` entries are refused before any write happens);
/// - likewise every parent segment may only be claimed once, so two distinct
///   parent ordinals sharing a corrupt duplicate segment row also refuse;
/// - reuse demands the same tenant AND aggregate identity on the parent
///   reference (cross-aggregate digest sharing is refused even though the
///   storage index only deduplicates per tenant);
/// - returns `(new_count, reused_count)` so transactional execution proves its
///   bookkeeping agrees with the plan.
pub fn validate_staging_plan_against_parent(
    identity: &ProjectionAggregateIdentity,
    plan: &[StagedSegmentContent],
    parent_references: Option<&[(u64, ParentReferenceView)]>,
) -> Result<(u64, u64), AuthorizationProjectionError> {
    if plan.len() > MAX_SEGMENTS_PER_MANIFEST {
        return Err(scope_violation(
            "authorization_projection.too_many_segments_per_manifest",
        ));
    }
    let mut new_total: u64 = 0;
    let mut reused_total: u64 = 0;
    // Duplicate `ReuseParent` entries would materialize two reference rows
    // carrying the same segment_id (violating uk_apms_segment and the
    // duplicate-segment read guard). Refuse them here, before any write.
    let mut seen_parent_ordinals = std::collections::BTreeSet::new();
    let mut seen_reused_segment_ids = std::collections::BTreeSet::new();
    for entry in plan {
        match entry {
            StagedSegmentContent::New(_) => new_total += 1,
            StagedSegmentContent::ReuseParent { parent_ordinal } => {
                let references = parent_references.ok_or_else(|| {
                    AuthorizationProjectionError::NotReady(
                        "code=authorization_projection.reuse_without_parent".to_owned(),
                    )
                })?;
                let reference = references
                    .iter()
                    .find(|(ordinal, _)| ordinal == parent_ordinal)
                    .map(|(_, view)| view)
                    .ok_or_else(|| {
                        mapping_error(format!(
                            "code=authorization_projection.parent_reference_missing;ordinal={parent_ordinal}"
                        ))
                    })?;
                if !seen_parent_ordinals.insert(*parent_ordinal) {
                    return Err(mapping_error(format!(
                        "code=authorization_projection.duplicate_parent_ordinal_reuse;ordinal={parent_ordinal}"
                    )));
                }
                if reference.identity != *identity {
                    return Err(AuthorizationProjectionError::IdentityMismatch(
                        "code=authorization_projection.cross_aggregate_segment_reuse".to_owned(),
                    ));
                }
                if !seen_reused_segment_ids.insert(reference.segment_id) {
                    return Err(mapping_error(format!(
                        "code=authorization_projection.duplicate_parent_segment_reuse;segment_id={}",
                        reference.segment_id
                    )));
                }
                reused_total += 1;
            }
        }
    }
    Ok((new_total, reused_total))
}

/// View of the current pointer relevant to publish validation (pure).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentPointerView {
    pub identity: ProjectionAggregateIdentity,
    /// Stored `authorization_projection_current.card_id` (`None` =
    /// aggregate-wide projection). Participates in stale-view comparisons so a
    /// scope flip can never slip through unnoticed.
    pub card_id: Option<i64>,
    pub current_generation: u64,
    pub manifest_id: i64,
    /// Authoritative revoke fence of the live pointer (`0` = first generation
    /// or unproven pre-migration history). Publish evidence must equal it.
    pub revoke_fence: u64,
    /// Durable proof latch for the zero-fence history. `false` means the row
    /// predates this Rust contract and requires explicit backfill/rehearsal.
    pub revoke_fence_proven: bool,
    pub cas_version: i64,
}

/// View of the ready target manifest relevant to publish validation (pure).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetManifestView {
    pub identity: ProjectionAggregateIdentity,
    /// Stored manifest `card_id`; must equal the pointer's scope before
    /// publication may proceed.
    pub card_id: Option<i64>,
    pub manifest_id: i64,
    /// Immutable lineage sealed into the manifest digest. It is `None` only
    /// for generation one and otherwise must equal the locked pointer target.
    pub parent_manifest_id: Option<i64>,
    pub generation: u64,
    pub status_str: String,
    pub semantic_hash_hex: String,
    pub dependency_hash_hex: String,
    pub compiler_version: String,
    pub reference_count: u64,
}

/// Durable expectations guarding one publication attempt.
///
/// Every field must be freshly re-read by the caller right before publishing;
/// unknown values are never invented by this repository. Hash triples must
/// agree exactly between the caller's compile output and the locked rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationPublishExpectation {
    /// Expected locked pointer state; `None` demands a first-ever publication.
    pub current_pointer: Option<CurrentPointerView>,
    /// The semantic hash the compile produced for the target generation.
    pub expected_target_semantic_hash_hex: String,
    /// The dependency hash the compile produced for the target generation.
    pub expected_target_dependency_hash_hex: String,
    /// The compiler version that produced the candidate segments.
    pub expected_target_compiler_version: String,
}

/// PAIRED revoke-fence evidence for one publication.
///
/// Both fences are MANDATORY typed values (not options): half-supplied pairs
/// and defaults are unrepresentable by construction. Since migration
/// 20260827000001 the AUTHORITATIVE previous fence is the locked current
/// pointer row (`0` when absent); this struct acts as the caller's stated
/// expectation and the CAS pin, never as the authority —
/// [`validate_publish_previous_fence_authority`] rejects any disagreement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishRevokeFenceEvidence {
    pub previous_revoke_fence: u64,
    pub new_revoke_fence: u64,
}

/// Enforce revoke-fence monotonicity between mandatory paired evidence.
///
/// Fence semantics mirror the typed contract ([`astral_types`] fence rules):
/// zero is the initial "no revoke happened" value and a fence regresses under
/// no circumstances.
pub fn validate_publish_fence_continuity(
    previous_revoke_fence: u64,
    new_revoke_fence: u64,
) -> Result<(), AuthorizationProjectionError> {
    if new_revoke_fence < previous_revoke_fence {
        return Err(AuthorizationProjectionError::ManifestPublishConflict(format!(
            "code=authorization_projection.fence_regression;previous={previous_revoke_fence};new={new_revoke_fence}"
        )));
    }
    Ok(())
}

/// Pure gate tying mandatory fence evidence to the observed pointer state:
/// a FIRST publication (no current pointer) must present `previous = 0`,
/// never a defaulted or invented higher value; non-first publications may not
/// default the previous fence at all (it must arrive as proven evidence).
pub fn validate_first_publication_previous_fence(
    pointer_exists: bool,
    previous_revoke_fence: u64,
) -> Result<(), AuthorizationProjectionError> {
    if !pointer_exists && previous_revoke_fence != 0 {
        return Err(AuthorizationProjectionError::ManifestPublishConflict(
            format!(
                "code=authorization_projection.first_publication_requires_zero_previous_fence;previous={previous_revoke_fence}"
            ),
        ));
    }
    Ok(())
}

/// Enforce that the caller's stated previous fence equals the AUTHORITATIVE
/// durable value read from the locked current pointer (`None` ⇒ 0).
///
/// A forged, stale or guessed previous fence can no longer widen or skew a
/// publication: the database row is the only authority and every mismatch is
/// refused with an explicit conflict before any statement runs.
pub fn validate_publish_previous_fence_authority(
    locked_pointer_previous_revoke_fence: Option<u64>,
    evidence_previous_revoke_fence: u64,
) -> Result<(), AuthorizationProjectionError> {
    let authoritative = locked_pointer_previous_revoke_fence.unwrap_or(0);
    if authoritative != evidence_previous_revoke_fence {
        return Err(AuthorizationProjectionError::CurrentPointerCasConflict(format!(
            "code=authorization_projection.previous_fence_not_authoritative;durable={authoritative};evidence={evidence_previous_revoke_fence}"
        )));
    }
    Ok(())
}

/// Durable proof gate for the current pointer's revoke-fence history.
///
/// A current row carrying `revoke_fence_proven = false` predates this Rust
/// publication contract. Its numeric fence, including zero, is therefore not
/// evidence of historical completeness and cannot be advanced or used by a
/// formal authorization read. A pointer written by this contract is proven even
/// when its honest initial fence is zero, so a later zero-to-positive advance is
/// legal. The distinction is the durable latch, never the numeric value.
pub fn validate_pointer_proof_state(
    revoke_fence: u64,
    revoke_fence_proven: bool,
) -> Result<(), AuthorizationProjectionError> {
    if !revoke_fence_proven {
        return Err(AuthorizationProjectionError::NotReady(
            format!(
                "code=authorization_projection.backfill_or_rehearsal_required;pointer_proof_unproven;pointer_fence={revoke_fence}"
            ),
        ));
    }
    Ok(())
}

pub fn validate_current_pointer_proof(
    pointer: Option<&CurrentPointerView>,
) -> Result<(), AuthorizationProjectionError> {
    if let Some(pointer) = pointer {
        validate_pointer_proof_state(pointer.revoke_fence, pointer.revoke_fence_proven)?;
    }
    Ok(())
}

/// Validate a claimed delta against the locked pointer's fence history.
///
/// `None` means first publication. A present pointer must carry the durable
/// proof latch; its numeric fence is then authoritative, including a proven
/// zero that may advance to a positive value.
pub fn validate_zero_sentinel_fence_history(
    claimed_delta_revoke_fence: u64,
    locked_pointer: Option<(u64, bool)>,
) -> Result<(), AuthorizationProjectionError> {
    let Some((pointer_fence, pointer_fence_proven)) = locked_pointer else {
        return Ok(());
    };
    validate_pointer_proof_state(pointer_fence, pointer_fence_proven)?;
    if claimed_delta_revoke_fence < pointer_fence {
        return Err(AuthorizationProjectionError::ManifestPublishConflict(format!(
            "code=authorization_projection.fence_regression;previous={pointer_fence};new={claimed_delta_revoke_fence}"
        )));
    }
    Ok(())
}

/// Validate the full preconditions of one publication attempt (pure).
///
/// Mirrors the SQL guards line by line so unit tests cover the decision table
/// without MySQL; the transactional function calls this first and then repeats
/// every predicate inside its guarded statements.
pub fn validate_manifest_publish(
    expectation: &AuthorizationPublishExpectation,
    target: &TargetManifestView,
) -> Result<(), AuthorizationProjectionError> {
    if target.status_str != MANIFEST_STATUS_READY {
        return Err(AuthorizationProjectionError::NotReady(format!(
            "code=authorization_projection.target_not_ready;status={}",
            target.status_str
        )));
    }
    if Sha256Digest::from_hex(&expectation.expected_target_semantic_hash_hex).is_err() {
        return Err(AuthorizationProjectionError::ManifestPublishConflict(
            "code=authorization_projection.publish_expected_semantic_hash_invalid".to_owned(),
        ));
    }
    if Sha256Digest::from_hex(&expectation.expected_target_dependency_hash_hex).is_err() {
        return Err(AuthorizationProjectionError::ManifestPublishConflict(
            "code=authorization_projection.publish_expected_dependency_hash_invalid".to_owned(),
        ));
    }
    validated_text(
        &expectation.expected_target_compiler_version,
        MAX_COMPILER_VERSION_LENGTH,
        "expected_target_compiler_version",
    )?;

    // Hash/compiler agreement between expectation and locked target row.
    if target.semantic_hash_hex != expectation.expected_target_semantic_hash_hex {
        return Err(AuthorizationProjectionError::ManifestPublishConflict(
            "code=authorization_projection.publish_target_semantic_mismatch".to_owned(),
        ));
    }
    if target.dependency_hash_hex != expectation.expected_target_dependency_hash_hex {
        return Err(AuthorizationProjectionError::ManifestPublishConflict(
            "code=authorization_projection.publish_target_dependency_mismatch".to_owned(),
        ));
    }
    if target.compiler_version != expectation.expected_target_compiler_version {
        return Err(AuthorizationProjectionError::ManifestPublishConflict(
            "code=authorization_projection.publish_target_compiler_mismatch".to_owned(),
        ));
    }

    match &expectation.current_pointer {
        Some(pointer) => {
            validate_current_pointer_proof(Some(pointer))?;
            if pointer.identity != target.identity {
                return Err(AuthorizationProjectionError::IdentityMismatch(
                    "code=authorization_projection.pointer_target_identity_mismatch".to_owned(),
                ));
            }
            // Card-scope continuity: a card-scoped pointer can only ever be
            // advanced by the matching card-scoped manifest (and vice versa);
            // None-vs-Some splits are corrupt state and refuse here.
            if pointer.card_id != target.card_id {
                return Err(AuthorizationProjectionError::IdentityMismatch(
                    "code=authorization_projection.publish_pointer_target_card_scope_mismatch"
                        .to_owned(),
                ));
            }
            let expected_next = pointer.current_generation.checked_add(1).ok_or_else(|| {
                mapping_error("code=authorization_projection.generation_overflow".to_owned())
            })?;
            if expected_next != target.generation {
                return Err(AuthorizationProjectionError::ManifestPublishConflict(format!(
                    "code=authorization_projection.publish_generation_gap;expected={expected_next};actual={}",
                    target.generation
                )));
            }
            if pointer.manifest_id == target.manifest_id {
                return Err(AuthorizationProjectionError::ManifestPublishConflict(
                    "code=authorization_projection.publish_same_manifest".to_owned(),
                ));
            }
            if target.parent_manifest_id != Some(pointer.manifest_id) {
                return Err(AuthorizationProjectionError::ManifestPublishConflict(format!(
                    "code=authorization_projection.publish_parent_manifest_mismatch;expected={};actual={:?}",
                    pointer.manifest_id, target.parent_manifest_id
                )));
            }
        }
        None => {
            if target.parent_manifest_id.is_some() {
                return Err(AuthorizationProjectionError::ManifestPublishConflict(
                    "code=authorization_projection.first_publication_requires_no_parent".to_owned(),
                ));
            }
            if target.generation != 1 {
                return Err(AuthorizationProjectionError::ManifestPublishConflict(format!(
                    "code=authorization_projection.first_publication_requires_generation_one;actual={}",
                    target.generation
                )));
            }
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Decoded row DTOs
// ─────────────────────────────────────────────────────────────────────────────

/// Decoded `authorization_projection_current` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationCurrentPointerRecord {
    pub pointer_id: i64,
    pub identity: ProjectionAggregateIdentity,
    pub card_id: Option<i64>,
    pub current_generation: u64,
    pub manifest_id: i64,
    pub event_id: String,
    pub operation_id: String,
    pub semantic_hash: Sha256Digest,
    pub dependency_hash: Sha256Digest,
    pub compiler_version: String,
    pub revoke_fence: u64,
    pub revoke_fence_proven: bool,
    pub cas_version: i64,
}

impl AuthorizationCurrentPointerRecord {
    pub fn as_view(&self) -> CurrentPointerView {
        CurrentPointerView {
            identity: self.identity.clone(),
            card_id: self.card_id,
            current_generation: self.current_generation,
            manifest_id: self.manifest_id,
            revoke_fence: self.revoke_fence,
            revoke_fence_proven: self.revoke_fence_proven,
            cas_version: self.cas_version,
        }
    }
}

/// Decoded `authorization_projection_manifest_segment` reference row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationSegmentReferenceRecord {
    pub reference_id: i64,
    pub manifest_id: i64,
    pub identity: ProjectionAggregateIdentity,
    pub card_id: Option<i64>,
    pub generation: u64,
    pub ordinal: u64,
    pub segment_id: i64,
    pub content_digest: Sha256Digest,
    pub event_id: String,
    pub operation_id: String,
}

impl AuthorizationSegmentReferenceRecord {
    pub fn as_parent_view(&self) -> ParentReferenceView {
        ParentReferenceView {
            ordinal: self.ordinal,
            identity: self.identity.clone(),
            segment_id: self.segment_id,
            content_digest_hex: self.content_digest.as_hex(),
        }
    }
}

/// Decoded `authorization_projection_segment` content row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationSegmentSnapshot {
    pub segment_id: i64,
    pub identity: ProjectionAggregateIdentity,
    pub card_id: Option<i64>,
    pub content_digest: Sha256Digest,
    pub semantic_hash: Sha256Digest,
    pub dependency_hash: Sha256Digest,
    pub compiler_version: String,
    pub format: String,
    pub row_count: u64,
    pub byte_size: u64,
    pub grants: Vec<CanonicalGrant>,
}

/// One fully verified published projection: pointer + manifest + ordered
/// segments. Returned only after every invariant held; partial failures abort
/// the whole read with an explicit error, never a degraded result.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthorizationPublishedState {
    pub pointer: AuthorizationCurrentPointerRecord,
    pub manifest_id: i64,
    pub generation: u64,
    pub source_generation: u64,
    pub projected_generation: u64,
    pub event_id: String,
    pub operation_id: String,
    pub semantic_hash: Sha256Digest,
    pub dependency_hash: Sha256Digest,
    pub compiler_version: String,
    pub manifest_digest: Sha256Digest,
    /// Durable lineage of the published manifest (`None` = first generation).
    pub parent_manifest_id: Option<i64>,
    /// Revoke fence the publication is proven under (manifest row == pointer).
    pub revoke_fence: u64,
    pub segments: Vec<AuthorizationSegmentSnapshot>,
    /// Verified ordered reference rows behind [`Self::segments`] (same order).
    pub references: Vec<AuthorizationSegmentReferenceRecord>,
    pub total_grant_count: u64,
}

/// Diagnostic snapshot of a non-published (`BUILDING`/`READY`) manifest for
/// recovery tooling. Integrity requirements are identical to published reads;
/// only the accepted status set differs, so corruption still fails closed.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthorizationRecoveryState {
    pub manifest_id: i64,
    pub identity: ProjectionAggregateIdentity,
    pub card_id: Option<i64>,
    pub generation: u64,
    pub source_generation: u64,
    pub projected_generation: u64,
    pub event_id: String,
    pub operation_id: String,
    pub status: AuthorizationManifestStatus,
    pub cas_version: i64,
    pub semantic_hash: Sha256Digest,
    pub dependency_hash: Sha256Digest,
    pub compiler_version: String,
    pub manifest_digest: Sha256Digest,
    /// Durable lineage of this manifest (`None` = first generation).
    pub parent_manifest_id: Option<i64>,
    /// Durable revoke fence (`0` = no revoke observed or unproven history).
    pub revoke_fence: u64,
    /// True when a lease owner string is present (token hash never leaves DB).
    pub leased: bool,
    pub segments: Vec<AuthorizationSegmentSnapshot>,
    pub total_grant_count: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Raw row shapes and decoding (fail-closed on malformed stored values)
// ─────────────────────────────────────────────────────────────────────────────

const MANIFEST_ROW_COLUMNS: &str = "manifest_id, tenant_id, card_id, aggregate_type, \
    aggregate_id, generation, source_generation, projected_generation, event_id, \
    operation_id, semantic_hash, dependency_hash, compiler_version, manifest_digest, \
    status, cas_version, lease_owner, lease_token_hash, lease_expires_at, \
    parent_manifest_id, revoke_fence";

const REFERENCE_ROW_COLUMNS: &str = "reference_id, manifest_id, tenant_id, card_id, \
    aggregate_type, aggregate_id, generation, segment_ordinal, segment_id, \
    content_digest, event_id, operation_id, status";

const SEGMENT_ROW_COLUMNS: &str = "segment_id, tenant_id, card_id, aggregate_type, \
    aggregate_id, content_digest, semantic_hash, dependency_hash, compiler_version, \
    segment_format, row_count, byte_size, segment_payload, status";

const POINTER_ROW_COLUMNS: &str = "pointer_id, tenant_id, card_id, aggregate_type, \
    aggregate_id, current_generation, manifest_id, event_id, operation_id, \
    semantic_hash, dependency_hash, compiler_version, revoke_fence, revoke_fence_proven, \
    status, cas_version";

const SELECT_PREFIX: &str = "SELECT ";

const MANIFEST_BY_ID_TAIL: &str =
    " FROM authorization_projection_manifest WHERE manifest_id = ? FOR UPDATE";

const MANIFEST_BY_DIGEST_TAIL: &str = " FROM authorization_projection_manifest \
    WHERE tenant_id = ? AND manifest_digest = ? FOR UPDATE";

const MANIFEST_BY_GENERATION_TAIL: &str = " FROM authorization_projection_manifest \
    WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ? AND generation = ? \
    FOR UPDATE";

const REFERENCES_BY_MANIFEST_TAIL: &str = " FROM authorization_projection_manifest_segment \
    WHERE manifest_id = ? ORDER BY segment_ordinal ASC FOR UPDATE";

const REFERENCE_BY_MANIFEST_ORDINAL_TAIL: &str = " FROM authorization_projection_manifest_segment \
    WHERE manifest_id = ? AND segment_ordinal = ? FOR UPDATE";

const SEGMENT_BY_ID_TAIL: &str =
    " FROM authorization_projection_segment WHERE segment_id = ? FOR UPDATE";

const POINTER_BY_IDENTITY_LOCKED_TAIL: &str = " FROM authorization_projection_current \
    WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ? FOR UPDATE";

const POINTER_BY_IDENTITY_TAIL: &str = " FROM authorization_projection_current \
    WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ?";

#[derive(Debug, Clone, sqlx::FromRow)]
struct ManifestRawSqlRow {
    manifest_id: i64,
    tenant_id: i64,
    card_id: Option<i64>,
    aggregate_type: String,
    aggregate_id: i64,
    generation: i64,
    source_generation: i64,
    projected_generation: i64,
    event_id: String,
    operation_id: String,
    semantic_hash: Vec<u8>,
    dependency_hash: Vec<u8>,
    compiler_version: String,
    manifest_digest: Vec<u8>,
    status: String,
    cas_version: i64,
    lease_owner: Option<String>,
    lease_token_hash: Option<Vec<u8>>,
    lease_expires_at: Option<PrimitiveDateTime>,
    parent_manifest_id: Option<i64>,
    revoke_fence: i64,
}

impl ManifestRawSqlRow {
    fn decode_identity(&self) -> Result<ProjectionAggregateIdentity, AuthorizationProjectionError> {
        ProjectionAggregateIdentity::new(
            self.tenant_id,
            self.aggregate_type.clone(),
            self.aggregate_id,
        )
    }

    /// Durable lineage of this manifest row (`None` = first generation).
    fn decode_parent_manifest_id(&self) -> Result<Option<i64>, AuthorizationProjectionError> {
        match self.parent_manifest_id {
            None => Ok(None),
            Some(parent) => {
                positive_i64(parent, "manifest.parent_manifest_id")?;
                Ok(Some(parent))
            }
        }
    }

    /// Durable revoke fence of this manifest row (fail-closed on negatives;
    /// `0` keeps the documented unproven-history sentinel meaning).
    fn decode_revoke_fence(&self) -> Result<u64, AuthorizationProjectionError> {
        read_counter_i64(self.revoke_fence, "manifest.revoke_fence")
    }

    fn decode_hashes(
        &self,
    ) -> Result<(Sha256Digest, Sha256Digest, Sha256Digest), AuthorizationProjectionError> {
        Ok((
            Sha256Digest::from_bytes(self.semantic_hash.clone())?,
            Sha256Digest::from_bytes(self.dependency_hash.clone())?,
            Sha256Digest::from_bytes(self.manifest_digest.clone())?,
        ))
    }

    fn decode_generations(&self) -> Result<(u64, u64, u64), AuthorizationProjectionError> {
        Ok((
            read_counter_i64(self.generation, "manifest.generation")?,
            read_counter_i64(self.source_generation, "manifest.source_generation")?,
            read_counter_i64(self.projected_generation, "manifest.projected_generation")?,
        ))
    }

    fn decode_status(&self) -> Result<AuthorizationManifestStatus, AuthorizationProjectionError> {
        AuthorizationManifestStatus::parse(&self.status)
    }

    /// Recompute the sealed manifest digest from this row plus the verified
    /// ordered segment digests.
    fn recomputed_digest(
        &self,
        segment_content_digests_hex: Vec<String>,
    ) -> Result<Sha256Digest, AuthorizationProjectionError> {
        let (generation, source_generation, projected_generation) = self.decode_generations()?;
        compute_manifest_digest(&ManifestDigestInput {
            tenant_id: self.tenant_id,
            aggregate_type: &self.aggregate_type,
            aggregate_id: self.aggregate_id,
            card_id: self.card_id,
            generation,
            source_generation,
            projected_generation,
            event_id: &self.event_id,
            operation_id: &self.operation_id,
            semantic_hash_hex: &hex::encode(&self.semantic_hash),
            dependency_hash_hex: &hex::encode(&self.dependency_hash),
            compiler_version: &self.compiler_version,
            parent_manifest_id: self.decode_parent_manifest_id()?,
            revoke_fence: self.decode_revoke_fence()?,
            segment_content_digests_hex,
        })
    }
}

#[derive(Debug, sqlx::FromRow)]
struct ReferenceRawSqlRow {
    reference_id: i64,
    manifest_id: i64,
    tenant_id: i64,
    card_id: Option<i64>,
    aggregate_type: String,
    aggregate_id: i64,
    generation: i64,
    segment_ordinal: i32,
    segment_id: i64,
    content_digest: Vec<u8>,
    event_id: String,
    operation_id: String,
    status: String,
}

impl ReferenceRawSqlRow {
    fn decode(&self) -> Result<AuthorizationSegmentReferenceRecord, AuthorizationProjectionError> {
        if self.segment_ordinal < 0 {
            return Err(mapping_error(
                "code=authorization_projection.negative_reference_ordinal".to_owned(),
            ));
        }
        if self.status != PROJECTION_STATUS_READY {
            return Err(AuthorizationProjectionError::NotReady(format!(
                "code=authorization_projection.reference_not_ready;status={}",
                self.status
            )));
        }
        Ok(AuthorizationSegmentReferenceRecord {
            reference_id: self.reference_id,
            manifest_id: self.manifest_id,
            identity: ProjectionAggregateIdentity::new(
                self.tenant_id,
                self.aggregate_type.clone(),
                self.aggregate_id,
            )?,
            card_id: self.card_id,
            generation: read_counter_i64(self.generation, "reference.generation")?,
            ordinal: self.segment_ordinal as u64,
            segment_id: self.segment_id,
            content_digest: Sha256Digest::from_bytes(self.content_digest.clone())?,
            event_id: self.event_id.clone(),
            operation_id: self.operation_id.clone(),
        })
    }
}

#[derive(Debug, sqlx::FromRow)]
struct SegmentRawSqlRow {
    segment_id: i64,
    tenant_id: i64,
    card_id: Option<i64>,
    aggregate_type: String,
    aggregate_id: i64,
    content_digest: Vec<u8>,
    semantic_hash: Vec<u8>,
    dependency_hash: Vec<u8>,
    compiler_version: String,
    segment_format: String,
    row_count: i64,
    byte_size: i64,
    segment_payload: Vec<u8>,
    status: String,
}

impl SegmentRawSqlRow {
    fn decode_with_payload(
        &self,
    ) -> Result<AuthorizationSegmentSnapshot, AuthorizationProjectionError> {
        if self.row_count < 0 || self.byte_size < 0 {
            return Err(mapping_error(
                "code=authorization_projection.negative_segment_counters".to_owned(),
            ));
        }
        if self.status != PROJECTION_STATUS_READY {
            return Err(AuthorizationProjectionError::NotReady(format!(
                "code=authorization_projection.segment_not_ready;status={}",
                self.status
            )));
        }
        if self.segment_format != SEGMENT_FORMAT_AUTHORIZATION_GRANTS_JSON_V1 {
            return Err(mapping_error(format!(
                "code=authorization_projection.unknown_segment_format;value={}",
                self.segment_format
            )));
        }
        let grants = decode_segment_payload(&self.segment_payload)?;
        if grants.len() as i64 != self.row_count {
            return Err(mapping_error(format!(
                "code=authorization_projection.segment_row_count_mismatch;declared={};decoded={}",
                self.row_count,
                grants.len()
            )));
        }
        if self.byte_size as usize != self.segment_payload.len() {
            return Err(mapping_error(
                "code=authorization_projection.segment_byte_size_mismatch".to_owned(),
            ));
        }
        let digest = Sha256Digest::from_bytes(self.content_digest.clone())?;
        let computed = Sha256Digest::from_raw_bytes(sha256_digest_bytes(&self.segment_payload));
        if digest != computed {
            return Err(AuthorizationProjectionError::Corrupt(
                "code=authorization_projection.segment_digest_mismatch".to_owned(),
            ));
        }
        let snapshot = AuthorizationSegmentSnapshot {
            segment_id: self.segment_id,
            identity: ProjectionAggregateIdentity::new(
                self.tenant_id,
                self.aggregate_type.clone(),
                self.aggregate_id,
            )?,
            card_id: self.card_id,
            content_digest: digest,
            semantic_hash: Sha256Digest::from_bytes(self.semantic_hash.clone())?,
            dependency_hash: Sha256Digest::from_bytes(self.dependency_hash.clone())?,
            compiler_version: self.compiler_version.clone(),
            format: self.segment_format.clone(),
            row_count: self.row_count as u64,
            byte_size: self.byte_size as u64,
            grants,
        };
        // The hash columns of an immutable segment mean the SEGMENT-LOCAL
        // seals only; re-deriving them from stored metadata is mandatory on
        // every read (finalize/publish/read/recovery share this single gate).
        verify_segment_local_seal(&snapshot)?;
        Ok(snapshot)
    }
}

#[derive(Debug, sqlx::FromRow)]
struct PointerRawSqlRow {
    pointer_id: i64,
    tenant_id: i64,
    card_id: Option<i64>,
    aggregate_type: String,
    aggregate_id: i64,
    current_generation: i64,
    manifest_id: i64,
    event_id: String,
    operation_id: String,
    semantic_hash: Vec<u8>,
    dependency_hash: Vec<u8>,
    compiler_version: String,
    revoke_fence: i64,
    revoke_fence_proven: i64,
    status: String,
    cas_version: i64,
}

impl PointerRawSqlRow {
    fn decode(&self) -> Result<AuthorizationCurrentPointerRecord, AuthorizationProjectionError> {
        if self.status != PROJECTION_STATUS_READY {
            return Err(AuthorizationProjectionError::NotReady(format!(
                "code=authorization_projection.pointer_not_ready;status={}",
                self.status
            )));
        }
        Ok(AuthorizationCurrentPointerRecord {
            pointer_id: self.pointer_id,
            identity: ProjectionAggregateIdentity::new(
                self.tenant_id,
                self.aggregate_type.clone(),
                self.aggregate_id,
            )?,
            card_id: self.card_id,
            current_generation: read_counter_i64(
                self.current_generation,
                "pointer.current_generation",
            )?,
            manifest_id: self.manifest_id,
            event_id: self.event_id.clone(),
            operation_id: self.operation_id.clone(),
            semantic_hash: Sha256Digest::from_bytes(self.semantic_hash.clone())?,
            dependency_hash: Sha256Digest::from_bytes(self.dependency_hash.clone())?,
            compiler_version: self.compiler_version.clone(),
            revoke_fence: read_counter_i64(self.revoke_fence, "pointer.revoke_fence")?,
            revoke_fence_proven: match self.revoke_fence_proven {
                0 => false,
                1 => true,
                _ => {
                    return Err(AuthorizationProjectionError::Corrupt(
                        "code=authorization_projection.pointer.revoke_fence_proven_invalid"
                            .to_owned(),
                    ))
                }
            },
            cas_version: self.cas_version,
        })
    }
}

async fn fetch_manifest_for_update(
    tx: &mut Transaction<'_, MySql>,
    manifest_id: i64,
) -> Result<Option<ManifestRawSqlRow>, AuthorizationProjectionError> {
    positive_i64(manifest_id, "manifest_id")?;
    let statement = format!("{SELECT_PREFIX}{MANIFEST_ROW_COLUMNS}{MANIFEST_BY_ID_TAIL}");
    let row: Option<ManifestRawSqlRow> = sqlx::query_as(statement.as_str())
        .bind(manifest_id)
        .fetch_optional(&mut **tx)
        .await?;
    Ok(row)
}

// ─────────────────────────────────────────────────────────────────────────────
// Pointer locking / reading
// ─────────────────────────────────────────────────────────────────────────────

/// Lock and return the current pointer row for the aggregate, if any.
///
/// Taking the pointer lock first serializes publications and staging decisions
/// for one aggregate; callers must hold it before resolving parents or
/// enforcing target-generation sequencing.
pub async fn lock_current_pointer_in_tx(
    tx: &mut Transaction<'_, MySql>,
    identity: &ProjectionAggregateIdentity,
) -> Result<Option<AuthorizationCurrentPointerRecord>, AuthorizationProjectionError> {
    identity.validate()?;
    let statement =
        format!("{SELECT_PREFIX}{POINTER_ROW_COLUMNS}{POINTER_BY_IDENTITY_LOCKED_TAIL}");
    let row: Option<PointerRawSqlRow> = sqlx::query_as(statement.as_str())
        .bind(identity.tenant_id)
        .bind(&identity.aggregate_type)
        .bind(identity.aggregate_id)
        .fetch_optional(&mut **tx)
        .await?;
    row.map(|raw| raw.decode()).transpose()
}

/// Strict consistency read of the pointer without taking locks.
///
/// This helper is not an authorization read: callers that need a durable
/// authorization decision must use [`read_published_authorization_state_in_tx`]
/// so pointer, manifest and segments are locked and verified together. Even as
/// a consistency observation it never returns an unproven legacy pointer.
pub async fn load_current_pointer_in_tx(
    tx: &mut Transaction<'_, MySql>,
    identity: &ProjectionAggregateIdentity,
) -> Result<Option<AuthorizationCurrentPointerRecord>, AuthorizationProjectionError> {
    identity.validate()?;
    let statement = format!("{SELECT_PREFIX}{POINTER_ROW_COLUMNS}{POINTER_BY_IDENTITY_TAIL}");
    let row: Option<PointerRawSqlRow> = sqlx::query_as(statement.as_str())
        .bind(identity.tenant_id)
        .bind(&identity.aggregate_type)
        .bind(identity.aggregate_id)
        .fetch_optional(&mut **tx)
        .await?;
    let pointer = row.map(|raw| raw.decode()).transpose()?;
    let pointer_view = pointer
        .as_ref()
        .map(AuthorizationCurrentPointerRecord::as_view);
    validate_current_pointer_proof(pointer_view.as_ref())?;
    Ok(pointer)
}

// ─────────────────────────────────────────────────────────────────────────────
// Staging: immutable segments, reference rows, BUILDING manifest insert
// ─────────────────────────────────────────────────────────────────────────────

const SEGMENT_SELECT_BY_DIGEST_SQL: &str = "SELECT segment_id, tenant_id, card_id, \
    aggregate_type, aggregate_id, content_digest, semantic_hash, dependency_hash, \
    compiler_version, segment_format, row_count, byte_size, segment_payload, status \
    FROM authorization_projection_segment \
    WHERE tenant_id = ? AND content_digest = ? FOR UPDATE";

const SEGMENT_INSERT_SQL: &str = "INSERT INTO authorization_projection_segment \
    (tenant_id, card_id, aggregate_type, aggregate_id, content_digest, semantic_hash, \
     dependency_hash, compiler_version, segment_format, row_count, byte_size, \
     segment_payload, status) \
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'READY')";

const REFERENCE_INSERT_SQL: &str = "INSERT INTO authorization_projection_manifest_segment \
    (manifest_id, segment_id, tenant_id, card_id, aggregate_type, aggregate_id, generation, \
     segment_ordinal, content_digest, event_id, operation_id, status) \
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'READY')";

const MANIFEST_INSERT_SQL: &str = "INSERT INTO authorization_projection_manifest \
    (tenant_id, card_id, aggregate_type, aggregate_id, generation, source_generation, \
     projected_generation, event_id, operation_id, semantic_hash, dependency_hash, \
     compiler_version, manifest_digest, parent_manifest_id, revoke_fence, status) \
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'BUILDING')";

struct ResolvedSegment {
    snapshot: AuthorizationSegmentSnapshot,
}

/// Compute the local seal pair stored on one segment row.
///
/// Single constructor so insert and verification can never drift apart on the
/// sealed dimension set. The grant SET and payload bytes enter through
/// `content_digest` (verified against `segment_payload` on every read);
/// identity, card scope, compiler stamp, format and row count enter directly.
fn segment_local_seal_pair(
    identity: &ProjectionAggregateIdentity,
    card_id: Option<i64>,
    compiler_version: &str,
    row_count: u64,
    content_digest: &Sha256Digest,
) -> Result<(Sha256Digest, Sha256Digest), AuthorizationProjectionError> {
    let input = SegmentLocalSealInput {
        identity,
        card_id,
        compiler_version,
        segment_format: SEGMENT_FORMAT_AUTHORIZATION_GRANTS_JSON_V1,
        row_count,
        content_digest,
    };
    Ok((
        compute_segment_semantic_hash(&input)?,
        compute_segment_dependency_hash(&input)?,
    ))
}

fn assert_identical_segment(
    snapshot: &AuthorizationSegmentSnapshot,
    request: &AuthorizationStageRequest,
    content_digest: &Sha256Digest,
    semantic_seal: &Sha256Digest,
    dependency_seal: &Sha256Digest,
    compiler_version: &str,
) -> Result<(), AuthorizationProjectionError> {
    if snapshot.content_digest != *content_digest {
        return Err(AuthorizationProjectionError::SegmentDigestCollision(
            "code=authorization_projection.digest_decode_mismatch".to_owned(),
        ));
    }
    if snapshot.identity != request.identity {
        return Err(AuthorizationProjectionError::SegmentDigestCollision(
            "code=authorization_projection.cross_aggregate_digest_collision".to_owned(),
        ));
    }
    // Card scope participates in the local seals; an equal pair therefore
    // implies equal scope. Kept explicit because cross-card payload sharing is
    // a REAL collision for `(tenant_id, content_digest)` storage, not a skip.
    if snapshot.card_id != request.card_id {
        return Err(AuthorizationProjectionError::SegmentDigestCollision(
            "code=authorization_projection.cross_card_digest_collision".to_owned(),
        ));
    }
    // Only the LOCAL seals decide collision admissibility. Global hashes vary
    // with every real delta and must never turn identical immutable content
    // into a "collision". The checks below are ORDERED so each divergence
    // reports its own stable machine code:
    //
    // 1. A foreign storage format is a foreign writer — corruption family.
    // 2. A compiler-stamp-only divergence (payload bytes, identity, card scope
    //    and format all proven equal above) is the documented Phase 1 modeling
    //    limit for compiler upgrades reusing content: proven-intact payload,
    //    metadata stamp disagreement only — its own machine code, NOT
    //    corruption. Checked BEFORE the seals because the segment-local seals
    //    hash the compiler version, so a stamp divergence always shifts them.
    // 3. A seal mismatch with the SAME stamp means the stored columns disagree
    //    with recomputation from the row's own metadata — tampering or a seal
    //    bug; corruption family.
    if snapshot.format != SEGMENT_FORMAT_AUTHORIZATION_GRANTS_JSON_V1 {
        return Err(AuthorizationProjectionError::SegmentDigestCollision(
            "code=authorization_projection.digest_metadata_collision".to_owned(),
        ));
    }
    if snapshot.compiler_version != compiler_version {
        return Err(AuthorizationProjectionError::SegmentDigestCollision(
            SEGMENT_COMPILER_STAMP_DIVERGENCE_CODE.to_owned(),
        ));
    }
    if snapshot.semantic_hash.as_bytes() != semantic_seal.as_bytes()
        || snapshot.dependency_hash.as_bytes() != dependency_seal.as_bytes()
    {
        return Err(AuthorizationProjectionError::SegmentDigestCollision(
            "code=authorization_projection.digest_metadata_collision".to_owned(),
        ));
    }
    Ok(())
}

/// Insert-or-verify one immutable content-addressed segment row.
///
/// Same digest must reproduce identical payload bytes AND the same segment-
/// local stamp (aggregate/card scope, compiler version, format, row count) —
/// anything else reports [`AuthorizationProjectionError::SegmentDigestCollision`]
/// with the stable machine code for the divergent dimension; the proven-
/// intact compiler-stamp-only case reports
/// [`SEGMENT_COMPILER_STAMP_DIVERGENCE_CODE`] so callers can keep it out of
/// the corruption family. The stored `semantic_hash`/`dependency_hash` columns
/// receive the computed SEGMENT-LOCAL seals ([`compute_segment_semantic_hash`]
/// / [`compute_segment_dependency_hash`]); manifest-global hashes never touch
/// this row.
async fn upsert_content_addressed_segment(
    tx: &mut Transaction<'_, MySql>,
    request: &AuthorizationStageRequest,
    compiler_version: &str,
    grants: &[CanonicalGrant],
) -> Result<AuthorizationSegmentSnapshot, AuthorizationProjectionError> {
    let payload = encode_segment_payload(grants)?;
    let content_digest = Sha256Digest::from_raw_bytes(sha256_digest_bytes(&payload));
    let row_count = grants.len() as i64;
    let byte_size = i64::try_from(payload.len())
        .map_err(|_| scope_violation("authorization_projection.payload_size_overflow"))?;
    let (semantic_seal, dependency_seal) = segment_local_seal_pair(
        &request.identity,
        request.card_id,
        compiler_version,
        row_count as u64,
        &content_digest,
    )?;

    let existing: Option<SegmentRawSqlRow> = sqlx::query_as(SEGMENT_SELECT_BY_DIGEST_SQL)
        .bind(request.identity.tenant_id)
        .bind(content_digest.as_bytes().to_vec())
        .fetch_optional(&mut **tx)
        .await?;

    if let Some(existing) = existing {
        let snapshot = existing.decode_with_payload()?;
        assert_identical_segment(
            &snapshot,
            request,
            &content_digest,
            &semantic_seal,
            &dependency_seal,
            compiler_version,
        )?;
        return Ok(snapshot);
    }

    let inserted = sqlx::query(SEGMENT_INSERT_SQL)
        .bind(request.identity.tenant_id)
        .bind(request.card_id)
        .bind(&request.identity.aggregate_type)
        .bind(request.identity.aggregate_id)
        .bind(content_digest.as_bytes().to_vec())
        .bind(semantic_seal.as_bytes().to_vec())
        .bind(dependency_seal.as_bytes().to_vec())
        .bind(compiler_version)
        .bind(SEGMENT_FORMAT_AUTHORIZATION_GRANTS_JSON_V1)
        .bind(row_count)
        .bind(byte_size)
        .bind(payload.as_slice())
        .execute(&mut **tx)
        .await;
    match inserted {
        Ok(result) => {
            if result.rows_affected() != 1 {
                return Err(AuthorizationProjectionError::DuplicateRow(
                    "code=authorization_projection.segment_insert_not_applied".to_owned(),
                ));
            }
            let segment_id = i64::try_from(result.last_insert_id()).map_err(|_| {
                mapping_error(
                    "code=authorization_projection.bigint_overflow;field=segment_id".to_owned(),
                )
            })?;
            Ok(AuthorizationSegmentSnapshot {
                segment_id,
                identity: request.identity.clone(),
                card_id: request.card_id,
                content_digest,
                semantic_hash: semantic_seal,
                dependency_hash: dependency_seal,
                compiler_version: compiler_version.to_owned(),
                format: SEGMENT_FORMAT_AUTHORIZATION_GRANTS_JSON_V1.to_owned(),
                row_count: row_count as u64,
                byte_size: payload.len() as u64,
                grants: grants.to_vec(),
            })
        }
        Err(error) => {
            // Lost a concurrent insert race on uk_aps_content: re-read under
            // the uniqueness key and enforce byte equality so the primitive
            // stays retry-safe instead of optimistic.
            if unique_violation(&error) {
                let raced: Option<SegmentRawSqlRow> = sqlx::query_as(SEGMENT_SELECT_BY_DIGEST_SQL)
                    .bind(request.identity.tenant_id)
                    .bind(content_digest.as_bytes().to_vec())
                    .fetch_optional(&mut **tx)
                    .await?;
                if let Some(raced) = raced {
                    let snapshot = raced.decode_with_payload()?;
                    assert_identical_segment(
                        &snapshot,
                        request,
                        &content_digest,
                        &semantic_seal,
                        &dependency_seal,
                        compiler_version,
                    )?;
                    return Ok(snapshot);
                }
                return Err(AuthorizationProjectionError::SegmentDigestCollision(
                    "code=authorization_projection.concurrent_insert_unknown_winner".to_owned(),
                ));
            }
            Err(error.into())
        }
    }
}

/// Every durable dimension a committed reference winner must reproduce before
/// a resumed staging attempt may treat the duplicate insert as an idempotent
/// skip instead of a conflict.
struct ResumedReferenceExpectation<'a> {
    identity: &'a ProjectionAggregateIdentity,
    card_id: Option<i64>,
    event_id: &'a str,
    operation_id: &'a str,
    manifest_id: i64,
    generation: u64,
    ordinal: u64,
    snapshot: &'a AuthorizationSegmentSnapshot,
}

/// Pure equivalence proof used by reference resume: the committed winner of a
/// unique-key race (an interrupted retry of the same staging request) must
/// agree with the planned reference on every durable dimension; anything else
/// fails closed rather than silently continuing on top of divergent history.
fn resumed_reference_matches(
    record: &AuthorizationSegmentReferenceRecord,
    expectation: &ResumedReferenceExpectation<'_>,
) -> bool {
    record.manifest_id == expectation.manifest_id
        && record.ordinal == expectation.ordinal
        && record.generation == expectation.generation
        && record.identity == *expectation.identity
        && record.card_id == expectation.card_id
        && record.segment_id == expectation.snapshot.segment_id
        && record.content_digest == expectation.snapshot.content_digest
        && record.event_id == expectation.event_id
        && record.operation_id == expectation.operation_id
}

/// Insert one reference row, or prove an interrupted-retry winner equivalent.
///
/// Append-only discipline: references are only ever inserted or read-verified;
/// neither this helper nor anything else in the module deletes, rewrites or
/// "repairs" an existing reference row. When the insert loses a unique-key
/// race against a row committed by a prior attempt of the same staging
/// request (`uk_apms_ordinal` / `uk_apms_segment`), the conflicting row is
/// re-read under `(manifest_id, segment_ordinal)` and must reproduce every
/// durable field byte-for-byte ([`resumed_reference_matches`]); anything else
/// fails closed with [`AuthorizationProjectionError::DuplicateRow`].
async fn ensure_reference_row_in_tx(
    tx: &mut Transaction<'_, MySql>,
    request: &AuthorizationStageRequest,
    manifest_id: i64,
    generation: u64,
    ordinal: u64,
    resolved: &ResolvedSegment,
) -> Result<(), AuthorizationProjectionError> {
    let attempted_insert = sqlx::query(REFERENCE_INSERT_SQL)
        .bind(manifest_id)
        .bind(resolved.snapshot.segment_id)
        .bind(request.identity.tenant_id)
        .bind(request.card_id)
        .bind(&request.identity.aggregate_type)
        .bind(request.identity.aggregate_id)
        .bind(bind_u64(generation, "reference.generation")?)
        .bind(bind_i32(ordinal, "segment_ordinal")?)
        .bind(resolved.snapshot.content_digest.as_bytes().to_vec())
        .bind(&request.event_id)
        .bind(&request.operation_id)
        .execute(&mut **tx)
        .await;
    match attempted_insert {
        Ok(outcome) => {
            if outcome.rows_affected() != 1 {
                return Err(AuthorizationProjectionError::DuplicateRow(
                    "code=authorization_projection.reference_insert_not_applied".to_owned(),
                ));
            }
            Ok(())
        }
        Err(error) => {
            if !unique_violation(&error) {
                return Err(error.into());
            }
            // A previous attempt of this same request already committed the
            // slot. Fail closed unless the winner proves byte-for-byte equal.
            let statement = format!(
                "{SELECT_PREFIX}{REFERENCE_ROW_COLUMNS}{REFERENCE_BY_MANIFEST_ORDINAL_TAIL}"
            );
            let existing: Option<ReferenceRawSqlRow> = sqlx::query_as(statement.as_str())
                .bind(manifest_id)
                .bind(bind_i32(ordinal, "resume.segment_ordinal")?)
                .fetch_optional(&mut **tx)
                .await?;
            match existing {
                Some(existing) => {
                    let record = existing.decode()?;
                    let expectation = ResumedReferenceExpectation {
                        identity: &request.identity,
                        card_id: request.card_id,
                        event_id: &request.event_id,
                        operation_id: &request.operation_id,
                        manifest_id,
                        generation,
                        ordinal,
                        snapshot: &resolved.snapshot,
                    };
                    if !resumed_reference_matches(&record, &expectation) {
                        return Err(AuthorizationProjectionError::DuplicateRow(
                            "code=authorization_projection.resumed_reference_conflict".to_owned(),
                        ));
                    }
                    Ok(())
                }
                None => Err(AuthorizationProjectionError::DuplicateRow(
                    "code=authorization_projection.resume_reference_race_unknown_winner".to_owned(),
                )),
            }
        }
    }
}

/// Stage one target manifest generation and its ordered references inside the
/// caller's transaction.
///
/// Behavior:
/// - locks the current pointer first (or observes its absence for first
///   builds), refusing any generation that is not exactly the next one;
/// - resolves the parent manifest through the locked pointer and loads its
///   ordered references and content rows under lock; first builds have no
///   parent and reject `ReuseParent` entries;
/// - inserts or verifies immutable content-addressed segments (digest
///   collisions must reproduce identical content or fail closed);
/// - inserts the target manifest row as `BUILDING` together with every
///   reference row; no existing row is updated or deleted;
/// - resumes an interrupted retry of the same request idempotently: when the
///   identical `BUILDING` manifest plus its references already committed in a
///   prior transaction, every reference slot is re-verified per ordinal and
///   the equivalent winner is skipped instead of re-inserted; inequivalent
///   winners abort with [`AuthorizationProjectionError::DuplicateRow`].
///   References are never deleted, reordered or rewritten on resume.
///
/// The function neither commits nor releases locks; callers own commit /
/// rollback plus the subsequent claim/finalize/publish steps.
pub async fn stage_authorization_manifest_in_tx(
    tx: &mut Transaction<'_, MySql>,
    request: &AuthorizationStageRequest,
) -> Result<AuthorizationStageOutcome, AuthorizationProjectionError> {
    request.identity.validate()?;
    validated_option_card_id(request.card_id)?;
    if request.target_generation == 0
        || bind_u64(request.target_generation, "stage.target_generation").is_err()
    {
        return Err(scope_violation(
            "authorization_projection.invalid_stage_generation",
        ));
    }
    bind_u64(request.source_generation, "stage.source_generation")?;
    bind_u64(request.projected_generation, "stage.projected_generation")?;
    if request.source_generation < request.projected_generation {
        return Err(scope_violation(
            "authorization_projection.projected_generation_exceeds_source",
        ));
    }
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
    let semantic_hash = Sha256Digest::from_hex(&request.semantic_hash_hex)?;
    let dependency_hash = Sha256Digest::from_hex(&request.dependency_hash_hex)?;
    if request.segments.len() > MAX_SEGMENTS_PER_MANIFEST {
        return Err(scope_violation(
            "authorization_projection.too_many_segments_per_manifest",
        ));
    }

    // (1) Lock/observe the current pointer; enforce generation sequencing.
    let base_pointer = lock_current_pointer_in_tx(tx, &request.identity).await?;
    if let Some(pointer) = &base_pointer {
        validate_pointer_proof_state(pointer.revoke_fence, pointer.revoke_fence_proven)?;
    }
    // Authoritative parent lineage for the durable `parent_manifest_id`
    // column: NULL only for a genuine first build, otherwise the locked
    // current manifest id. Never taken from the request.
    let resolved_parent_manifest_id = base_pointer.as_ref().map(|pointer| pointer.manifest_id);
    if let Some(pointer) = &base_pointer {
        if pointer.card_id != request.card_id {
            return Err(AuthorizationProjectionError::IdentityMismatch(
                "code=authorization_projection.stage_card_scope_mismatch".to_owned(),
            ));
        }
        let expected_generation = pointer.current_generation.checked_add(1).ok_or_else(|| {
            mapping_error("code=authorization_projection.generation_overflow".to_owned())
        })?;
        if expected_generation != request.target_generation {
            return Err(AuthorizationProjectionError::NotReady(format!(
                "code=authorization_projection.stage_generation_gap;expected={expected_generation};actual={}",
                request.target_generation
            )));
        }
    } else if request.target_generation != 1 {
        return Err(AuthorizationProjectionError::NotReady(format!(
            "code=authorization_projection.first_build_requires_generation_one;actual={}",
            request.target_generation
        )));
    }

    // (2) Resolve the parent manifest and its ordered references under lock.
    let mut parent_records: Vec<AuthorizationSegmentReferenceRecord> = Vec::new();
    if let Some(pointer) = &base_pointer {
        let parent = fetch_manifest_for_update(tx, pointer.manifest_id)
            .await?
            .ok_or_else(|| {
                AuthorizationProjectionError::Corrupt(
                    "code=authorization_projection.parent_manifest_missing".to_owned(),
                )
            })?;
        if parent.decode_identity()? != request.identity {
            return Err(AuthorizationProjectionError::IdentityMismatch(
                "code=authorization_projection.parent_identity_mismatch".to_owned(),
            ));
        }
        if parent.status != MANIFEST_STATUS_COMMITTED {
            return Err(AuthorizationProjectionError::NotReady(format!(
                "code=authorization_projection.parent_not_committed;status={}",
                parent.status
            )));
        }
        if parent.decode_generations()?.0 != pointer.current_generation {
            return Err(AuthorizationProjectionError::Corrupt(
                "code=authorization_projection.parent_generation_mismatch".to_owned(),
            ));
        }
        // Durable lineage rows must agree with the locked pointer on the
        // fence level: the pointer mirrors the COMMITTED parent manifest.
        // A split means restart reconciliation must complete before staging.
        let parent_revoke_fence = parent.decode_revoke_fence()?;
        if parent_revoke_fence != pointer.revoke_fence {
            return Err(AuthorizationProjectionError::Corrupt(format!(
                "code=authorization_projection.parent_fence_split;manifest={parent_revoke_fence};pointer={}",
                pointer.revoke_fence
            )));
        }
        let reference_rows: Vec<ReferenceRawSqlRow> = sqlx::query_as(
            format!("{SELECT_PREFIX}{REFERENCE_ROW_COLUMNS}{REFERENCES_BY_MANIFEST_TAIL}").as_str(),
        )
        .bind(pointer.manifest_id)
        .fetch_all(&mut **tx)
        .await?;
        for raw in &reference_rows {
            parent_records.push(raw.decode()?);
        }
        let counted: Vec<(u64, u64)> = parent_records.iter().map(|r| (r.ordinal, 0u64)).collect();
        validate_contiguous_ordinals(&counted)?;
        for record in &parent_records {
            if record.generation != pointer.current_generation {
                return Err(AuthorizationProjectionError::Corrupt(
                    "code=authorization_projection.parent_reference_generation_mismatch".to_owned(),
                ));
            }
        }
        // Prove the PARENT manifest's own sealed digest chain (its own stored
        // global hashes plus its ordered reference digests) before any of its
        // segments may be reused. The TARGET generation's global hashes are
        // intentionally absent from this comparison.
        verify_parent_manifest_chain(&parent, &parent_records)?;
    }

    // Load every parent segment content row once under lock so reuse decisions
    // rest on verified rows and grant counting stays honest.
    let mut parent_segments: Vec<AuthorizationSegmentSnapshot> = Vec::new();
    if let Some(_pointer) = &base_pointer {
        for record in &parent_records {
            let segment_statement =
                format!("{SELECT_PREFIX}{SEGMENT_ROW_COLUMNS}{SEGMENT_BY_ID_TAIL}");
            let row: Option<SegmentRawSqlRow> = sqlx::query_as(segment_statement.as_str())
                .bind(record.segment_id)
                .fetch_optional(&mut **tx)
                .await?;
            let Some(row) = row else {
                return Err(AuthorizationProjectionError::Corrupt(
                    "code=authorization_projection.parent_segment_missing".to_owned(),
                ));
            };
            let snapshot = row.decode_with_payload()?;
            // Identity, reference-digest agreement and the SEGMENT-LOCAL seal
            // are the only reuse requirements. Comparing this parent segment
            // against the TARGET manifest's global semantic/dependency hashes
            // here would break every real delta (unchanged segments keep their
            // local seals while global hashes legitimately move) — that gate
            // was removed with its `parent_segment_hash_chain_break` error.
            verify_reference_content_pair(record, &snapshot, &request.identity)?;
            parent_segments.push(snapshot);
        }
    }

    // (3) Pure plan validation, then resolve each entry in deterministic order.
    let parent_views: Vec<(u64, ParentReferenceView)> = parent_records
        .iter()
        .map(|record| (record.ordinal, record.as_parent_view()))
        .collect();
    let plan_counts = validate_staging_plan_against_parent(
        &request.identity,
        &request.segments,
        if parent_views.is_empty() {
            None
        } else {
            Some(parent_views.as_slice())
        },
    )?;

    let mut resolved_segments: Vec<ResolvedSegment> = Vec::with_capacity(request.segments.len());
    let mut new_count: u64 = 0;
    let mut reused_count: u64 = 0;
    let mut total_grant_count: u64 = 0;
    for entry in &request.segments {
        match entry {
            StagedSegmentContent::New(grants) => {
                let snapshot = upsert_content_addressed_segment(
                    tx,
                    request,
                    &request.compiler_version,
                    grants,
                )
                .await?;
                total_grant_count = total_grant_count
                    .checked_add(snapshot.row_count)
                    .ok_or_else(|| {
                        mapping_error(
                            "code=authorization_projection.grant_count_overflow".to_owned(),
                        )
                    })?;
                new_count += 1;
                resolved_segments.push(ResolvedSegment { snapshot });
            }
            StagedSegmentContent::ReuseParent { parent_ordinal } => {
                let resolved_snapshot = parent_records
                    .iter()
                    .find(|record| record.ordinal == *parent_ordinal)
                    .and_then(|record| {
                        parent_segments
                            .iter()
                            .find(|snapshot| snapshot.segment_id == record.segment_id)
                    });
                let Some(snapshot) = resolved_snapshot else {
                    return Err(AuthorizationProjectionError::Corrupt(format!(
                        "code=authorization_projection.parent_reference_unresolvable;ordinal={parent_ordinal}"
                    )));
                };
                total_grant_count = total_grant_count
                    .checked_add(snapshot.row_count)
                    .ok_or_else(|| {
                        mapping_error(
                            "code=authorization_projection.grant_count_overflow".to_owned(),
                        )
                    })?;
                reused_count += 1;
                resolved_segments.push(ResolvedSegment {
                    snapshot: snapshot.clone(),
                });
            }
        }
    }
    if plan_counts != (new_count, reused_count) {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.plan_validation_disagrees_with_execution".to_owned(),
        ));
    }

    // (4) Seal the manifest digest over the final ordered reference list.
    let manifest_digest = compute_manifest_digest(&ManifestDigestInput {
        tenant_id: request.identity.tenant_id,
        aggregate_type: &request.identity.aggregate_type,
        aggregate_id: request.identity.aggregate_id,
        card_id: request.card_id,
        generation: request.target_generation,
        source_generation: request.source_generation,
        projected_generation: request.projected_generation,
        event_id: &request.event_id,
        operation_id: &request.operation_id,
        semantic_hash_hex: &request.semantic_hash_hex,
        dependency_hash_hex: &request.dependency_hash_hex,
        compiler_version: &request.compiler_version,
        parent_manifest_id: resolved_parent_manifest_id,
        revoke_fence: request.revoke_fence,
        segment_content_digests_hex: resolved_segments
            .iter()
            .map(|resolved| resolved.snapshot.content_digest.as_hex())
            .collect(),
    })?;

    // (5) Insert the BUILDING manifest row; tolerate idempotent retries by
    // proving the winner is byte-for-byte identical.
    let inserted = sqlx::query(MANIFEST_INSERT_SQL)
        .bind(request.identity.tenant_id)
        .bind(request.card_id)
        .bind(&request.identity.aggregate_type)
        .bind(request.identity.aggregate_id)
        .bind(bind_u64(request.target_generation, "manifest.generation")?)
        .bind(bind_u64(
            request.source_generation,
            "manifest.source_generation",
        )?)
        .bind(bind_u64(
            request.projected_generation,
            "manifest.projected_generation",
        )?)
        .bind(&request.event_id)
        .bind(&request.operation_id)
        .bind(semantic_hash.as_bytes().to_vec())
        .bind(dependency_hash.as_bytes().to_vec())
        .bind(&request.compiler_version)
        .bind(manifest_digest.as_bytes().to_vec())
        .bind(resolved_parent_manifest_id)
        .bind(bind_u64(request.revoke_fence, "manifest.revoke_fence")?)
        .execute(&mut **tx)
        .await;
    let (manifest_id, resumed) = match inserted {
        Ok(result) => {
            if result.rows_affected() != 1 {
                return Err(AuthorizationProjectionError::DuplicateRow(
                    "code=authorization_projection.manifest_insert_not_applied".to_owned(),
                ));
            }
            (
                i64::try_from(result.last_insert_id()).map_err(|_| {
                    mapping_error(
                        "code=authorization_projection.bigint_overflow;field=manifest_id"
                            .to_owned(),
                    )
                })?,
                false,
            )
        }
        Err(error) => {
            if !unique_violation(&error) {
                return Err(error.into());
            }
            let statement =
                format!("{SELECT_PREFIX}{MANIFEST_ROW_COLUMNS}{MANIFEST_BY_DIGEST_TAIL}");
            let existing: Option<ManifestRawSqlRow> = sqlx::query_as(statement.as_str())
                .bind(request.identity.tenant_id)
                .bind(manifest_digest.as_bytes().to_vec())
                .fetch_optional(&mut **tx)
                .await?;
            let Some(existing) = existing else {
                return Err(AuthorizationProjectionError::DuplicateRow(
                    "code=authorization_projection.manifest_race_unknown_winner".to_owned(),
                ));
            };
            let identical = existing.tenant_id == request.identity.tenant_id
                && existing.card_id == request.card_id
                && existing.aggregate_type == request.identity.aggregate_type
                && existing.aggregate_id == request.identity.aggregate_id
                && existing.generation
                    == bind_u64(request.target_generation, "manifest.generation")?
                && existing.source_generation
                    == bind_u64(request.source_generation, "manifest.source_generation")?
                && existing.projected_generation
                    == bind_u64(
                        request.projected_generation,
                        "manifest.projected_generation",
                    )?
                && existing.event_id == request.event_id
                && existing.operation_id == request.operation_id
                && existing.semantic_hash == semantic_hash.as_bytes().to_vec()
                && existing.dependency_hash == dependency_hash.as_bytes().to_vec()
                && existing.compiler_version == request.compiler_version
                && existing.manifest_digest == manifest_digest.as_bytes().to_vec()
                // Immutable replay compares BOTH new durable columns: lineage
                // parent and revoke fence must match the resolved authoritative
                // values, never a stale or divergent winner. Decoding fails
                // closed on malformed (negative / overflowing) stored values.
                && existing.decode_parent_manifest_id()? == resolved_parent_manifest_id
                && existing.decode_revoke_fence()?
                    == request.revoke_fence;
            if !identical {
                return Err(AuthorizationProjectionError::DuplicateRow(
                    "code=authorization_projection.manifest_identity_conflict".to_owned(),
                ));
            }
            (existing.manifest_id, true)
        }
    };

    // (6) Write the reference rows in deterministic ordinal order. A retry of
    // an already-committed staging attempt skips the byte-identical winners
    // (proven per ordinal) instead of duplicating the inserts; equivalent
    // rows are never deleted or rewritten (append-only semantics preserved).
    for (ordinal, resolved) in resolved_segments.iter().enumerate() {
        ensure_reference_row_in_tx(
            tx,
            request,
            manifest_id,
            request.target_generation,
            ordinal as u64,
            resolved,
        )
        .await?;
    }

    Ok(AuthorizationStageOutcome {
        manifest_id,
        manifest_digest,
        target_generation: request.target_generation,
        total_grant_count,
        new_segment_count: new_count,
        reused_segment_count: reused_count,
        resumed_existing_manifest: resumed,
        base_pointer,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Manifest lease primitives (claim / heartbeat / release / quarantine)
// ─────────────────────────────────────────────────────────────────────────────

/// Run-scoped secret fencing one manifest lease; identical policy to the delta
/// queue lease: the database stores only the SHA-256 token hash.
#[derive(Clone, PartialEq, Eq)]
pub struct ManifestLeaseToken(String);

impl ManifestLeaseToken {
    fn new_run_scoped() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(token: &str) -> Self {
        Self(token.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn token_hash(&self) -> Sha256Digest {
        Sha256Digest::from_raw_bytes(sha256_digest_bytes(self.0.as_bytes()))
    }
}

impl fmt::Debug for ManifestLeaseToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ManifestLeaseToken(REDACTED)")
    }
}

/// Owner + token proof every lease-guarded manifest mutation must present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestLeaseProof {
    pub manifest_id: i64,
    pub lease_owner: String,
    pub lease_token: ManifestLeaseToken,
}

fn validate_lease_material(
    lease_owner: &str,
    lease_seconds: i64,
) -> Result<(), AuthorizationProjectionError> {
    validated_text(lease_owner, MAX_GRANT_LEASE_OWNER_LENGTH, "lease_owner")?;
    if !(1..=MAX_MANIFEST_LEASE_SECONDS).contains(&lease_seconds) {
        return Err(scope_violation(&format!(
            "authorization_projection.invalid_lease_seconds;value={lease_seconds}"
        )));
    }
    Ok(())
}

fn validate_lease_proof(proof: &ManifestLeaseProof) -> Result<(), AuthorizationProjectionError> {
    positive_i64(proof.manifest_id, "manifest_id")?;
    validated_text(
        &proof.lease_owner,
        MAX_GRANT_LEASE_OWNER_LENGTH,
        "lease_owner",
    )?;
    if proof.lease_token.as_str().trim().is_empty() {
        return Err(scope_violation(
            "authorization_projection.empty_lease_token",
        ));
    }
    Ok(())
}

/// Lease granted on one `BUILDING` manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationManifestLeaseGrant {
    pub manifest_id: i64,
    pub identity: ProjectionAggregateIdentity,
    pub generation: u64,
    pub lease_owner: String,
    pub lease_token: ManifestLeaseToken,
    pub lease_expires_at: PrimitiveDateTime,
    pub cas_version_after_claim: i64,
}

const MANIFEST_CLAIM_CANDIDATE_SQL: &str = "SELECT manifest_id, status \
    FROM authorization_projection_manifest \
    WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ? AND generation = ? \
      AND status = 'BUILDING' \
      AND (lease_owner IS NULL OR lease_token_hash IS NULL OR lease_expires_at IS NULL \
           OR lease_expires_at <= UTC_TIMESTAMP()) \
    LIMIT 1 FOR UPDATE";

const MANIFEST_CLAIM_INSTALL_SQL: &str = "UPDATE authorization_projection_manifest \
    SET lease_owner = ?, lease_token_hash = ?, \
        lease_expires_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP()), \
        cas_version = cas_version + 1 \
    WHERE manifest_id = ? AND status = 'BUILDING' \
      AND (lease_owner IS NULL OR lease_token_hash IS NULL OR lease_expires_at IS NULL \
           OR lease_expires_at <= UTC_TIMESTAMP())";

const MANIFEST_CLAIM_READBACK_SQL: &str = "SELECT lease_expires_at, cas_version, \
    tenant_id, aggregate_type, aggregate_id, generation FROM authorization_projection_manifest \
    WHERE manifest_id = ?";

/// Claim the unique `BUILDING` manifest for an aggregate generation.
///
/// Live leases are never stolen; expired leases are reclaimable exactly like
/// unleased rows. Returns `Ok(None)` when nothing is claimable. Generates a
/// fresh run-scoped [`ManifestLeaseToken`]; only its SHA-256 hash persists.
pub async fn claim_authorization_manifest_in_tx(
    tx: &mut Transaction<'_, MySql>,
    identity: &ProjectionAggregateIdentity,
    generation: u64,
    lease_owner: &str,
    lease_seconds: i64,
) -> Result<Option<AuthorizationManifestLeaseGrant>, AuthorizationProjectionError> {
    identity.validate()?;
    if generation == 0 || bind_u64(generation, "claim.generation").is_err() {
        return Err(scope_violation(
            "authorization_projection.invalid_claim_generation",
        ));
    }
    validate_lease_material(lease_owner, lease_seconds)?;

    let bound_generation = bind_u64(generation, "claim.generation")?;
    let candidate_statement = MANIFEST_CLAIM_CANDIDATE_SQL;
    let candidate: Option<ManifestClaimCandidateRow> = sqlx::query_as(candidate_statement)
        .bind(identity.tenant_id)
        .bind(&identity.aggregate_type)
        .bind(identity.aggregate_id)
        .bind(bound_generation)
        .fetch_optional(&mut **tx)
        .await?;
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    // Mirror predicate after taking the row lock (defense-in-depth against
    // engine snapshot drift; matches the delta-queue claim discipline).
    if candidate.status != MANIFEST_STATUS_BUILDING {
        return Err(AuthorizationProjectionError::ClaimRace);
    }

    let token = ManifestLeaseToken::new_run_scoped();
    let install = sqlx::query(MANIFEST_CLAIM_INSTALL_SQL)
        .bind(lease_owner)
        .bind(token.token_hash().as_bytes().to_vec())
        .bind(lease_seconds)
        .bind(candidate.manifest_id)
        .execute(&mut **tx)
        .await?;
    if install.rows_affected() != 1 {
        return Err(AuthorizationProjectionError::ClaimRace);
    }

    #[derive(Debug, sqlx::FromRow)]
    struct ClaimReadbackRow {
        lease_expires_at: Option<PrimitiveDateTime>,
        cas_version: i64,
        tenant_id: i64,
        aggregate_type: String,
        aggregate_id: i64,
        generation: i64,
    }
    let readback: ClaimReadbackRow = sqlx::query_as(MANIFEST_CLAIM_READBACK_SQL)
        .bind(candidate.manifest_id)
        .fetch_one(&mut **tx)
        .await?;
    let Some(lease_expires_at) = readback.lease_expires_at else {
        return Err(mapping_error(
            "code=authorization_projection.claim_expiry_missing".to_owned(),
        ));
    };
    let claimed_identity = ProjectionAggregateIdentity::new(
        readback.tenant_id,
        readback.aggregate_type,
        readback.aggregate_id,
    )?;
    if claimed_identity != *identity {
        return Err(AuthorizationProjectionError::IdentityMismatch(
            "code=authorization_projection.claim_identity_drift".to_owned(),
        ));
    }

    Ok(Some(AuthorizationManifestLeaseGrant {
        manifest_id: candidate.manifest_id,
        identity: identity.clone(),
        generation: read_counter_i64(readback.generation, "claim.generation")?,
        lease_owner: lease_owner.to_owned(),
        lease_token: token,
        lease_expires_at,
        cas_version_after_claim: readback.cas_version,
    }))
}

#[derive(Debug, sqlx::FromRow)]
struct ManifestClaimCandidateRow {
    manifest_id: i64,
    status: String,
}

/// Extend a live lease keeping the SAME run-scoped token (expiry forward,
/// cas + 1).
///
/// Fails closed unless exactly one live leased row owned by
/// `proof.lease_owner` carrying the claimed token hash matches. With
/// `expected_cas_version` present the mutation additionally pins the row to
/// that CAS counter before advancing it.
pub async fn heartbeat_authorization_manifest_lease<'e, E>(
    executor: E,
    proof: &ManifestLeaseProof,
    expected_cas_version: Option<i64>,
    extension_seconds: i64,
) -> Result<(), AuthorizationProjectionError>
where
    E: Executor<'e, Database = MySql>,
{
    validate_lease_proof(proof)?;
    validate_lease_material(&proof.lease_owner, extension_seconds)?;
    let token_hash_bytes = proof.lease_token.token_hash().as_bytes().to_vec();
    let result = match expected_cas_version {
        None => {
            // Bind order follows statement text: SET expiry, then guard
            // (manifest_id, owner, token hash).
            sqlx::query(MANIFEST_HEARTBEAT_SQL)
                .bind(extension_seconds)
                .bind(proof.manifest_id)
                .bind(&proof.lease_owner)
                .bind(token_hash_bytes.clone())
                .execute(executor)
                .await?
        }
        Some(expected_cas) => {
            sqlx::query(MANIFEST_HEARTBEAT_WITH_CAS_SQL)
                .bind(extension_seconds)
                .bind(proof.manifest_id)
                .bind(expected_cas)
                .bind(&proof.lease_owner)
                .bind(token_hash_bytes)
                .execute(executor)
                .await?
        }
    };
    if result.rows_affected() != 1 {
        return Err(AuthorizationProjectionError::LeaseCasFailed(
            "code=authorization_projection.heartbeat_lost_lease".to_owned(),
        ));
    }
    Ok(())
}

const MANIFEST_HEARTBEAT_SQL: &str = "UPDATE authorization_projection_manifest \
    SET lease_expires_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP()), \
        cas_version = cas_version + 1 \
    WHERE manifest_id = ? AND lease_owner = ? AND lease_token_hash = ? \
      AND lease_expires_at IS NOT NULL AND lease_expires_at > UTC_TIMESTAMP()";

const MANIFEST_HEARTBEAT_WITH_CAS_SQL: &str = "UPDATE authorization_projection_manifest \
    SET lease_expires_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP()), \
        cas_version = cas_version + 1 \
    WHERE manifest_id = ? AND cas_version = ? AND lease_owner = ? AND lease_token_hash = ? \
      AND lease_expires_at IS NOT NULL AND lease_expires_at > UTC_TIMESTAMP()";

/// Relinquish the lease without changing the manifest status (it stays
/// `BUILDING`, remaining safely unpublishable until someone claims again).
pub async fn release_authorization_manifest_lease<'e, E>(
    executor: E,
    proof: &ManifestLeaseProof,
) -> Result<(), AuthorizationProjectionError>
where
    E: Executor<'e, Database = MySql>,
{
    validate_lease_proof(proof)?;
    let result = sqlx::query(MANIFEST_RELEASE_SQL)
        .bind(proof.manifest_id)
        .bind(&proof.lease_owner)
        .bind(proof.lease_token.token_hash().as_bytes().to_vec())
        .execute(executor)
        .await?;
    if result.rows_affected() != 1 {
        return Err(AuthorizationProjectionError::LeaseCasFailed(
            "code=authorization_projection.release_lost_lease".to_owned(),
        ));
    }
    Ok(())
}

const MANIFEST_RELEASE_SQL: &str = "UPDATE authorization_projection_manifest \
    SET lease_owner = NULL, lease_token_hash = NULL, lease_expires_at = NULL \
    WHERE manifest_id = ? AND lease_owner = ? AND lease_token_hash = ? \
      AND status = 'BUILDING' \
      AND lease_expires_at IS NOT NULL AND lease_expires_at > UTC_TIMESTAMP()";

/// Operator-quarantine of a `BUILDING`/`READY` manifest held under a live
/// lease; stores a truncated failure reason and clears the lease.
///
/// Historical states (`COMMITTED`/`SUPERSEDED`) stay untouched here so the
/// readable evidence trail cannot be flipped by one operator action.
pub async fn mark_authorization_manifest_quarantined<'e, E>(
    executor: E,
    proof: &ManifestLeaseProof,
    reason: &str,
) -> Result<(), AuthorizationProjectionError>
where
    E: Executor<'e, Database = MySql>,
{
    validate_lease_proof(proof)?;
    let result = sqlx::query(MANIFEST_QUARANTINE_SQL)
        .bind(truncate_last_error(reason))
        .bind(proof.manifest_id)
        .bind(&proof.lease_owner)
        .bind(proof.lease_token.token_hash().as_bytes().to_vec())
        .execute(executor)
        .await?;
    if result.rows_affected() != 1 {
        return Err(AuthorizationProjectionError::LeaseCasFailed(
            "code=authorization_projection.quarantine_lost_lease".to_owned(),
        ));
    }
    Ok(())
}

const MANIFEST_QUARANTINE_SQL: &str = "UPDATE authorization_projection_manifest \
    SET status = 'QUARANTINED', lease_owner = NULL, lease_token_hash = NULL, \
        lease_expires_at = NULL, last_error = ? \
    WHERE manifest_id = ? AND lease_owner = ? AND lease_token_hash = ? \
      AND status IN ('BUILDING', 'READY') \
      AND lease_expires_at IS NOT NULL AND lease_expires_at > UTC_TIMESTAMP()";

// ─────────────────────────────────────────────────────────────────────────────
// Finalize: BUILDING -> READY after full completeness verification
// ─────────────────────────────────────────────────────────────────────────────

/// Inputs for finalizing a staged manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationFinalizeRequest {
    pub identity: ProjectionAggregateIdentity,
    pub target_generation: u64,
    pub manifest_id: i64,
    pub lease_owner: String,
    pub lease_token: ManifestLeaseToken,
    /// Stronger CAS bound observed from the lease grant.
    pub expected_cas_version: i64,
    /// When set, the reference count found on disk must equal this value.
    pub expected_reference_count: Option<u64>,
}

/// Move a fully verified manifest from `BUILDING` to `READY`.
///
/// Verifies, under lock: identity/generation agreement, active lease ownership
/// (owner + token hash + live expiry + expected CAS), complete ordinal-
/// continuous references and every referenced segment being READY with an
/// unchanged hash chain. Completeness violations abort BEFORE the status
/// update; the manifest simply stays `BUILDING` (unpublishable).
pub async fn finalize_authorization_manifest_in_tx(
    tx: &mut Transaction<'_, MySql>,
    request: &AuthorizationFinalizeRequest,
) -> Result<(), AuthorizationProjectionError> {
    request.identity.validate()?;
    positive_i64(request.manifest_id, "manifest_id")?;
    validated_text(
        &request.lease_owner,
        MAX_GRANT_LEASE_OWNER_LENGTH,
        "lease_owner",
    )?;
    if request.lease_token.as_str().trim().is_empty() {
        return Err(scope_violation(
            "authorization_projection.empty_finalize_token",
        ));
    }
    bind_u64(request.target_generation, "finalize.target_generation")?;
    let token_hash = request.lease_token.token_hash();

    let manifest = fetch_manifest_for_update(tx, request.manifest_id)
        .await?
        .ok_or_else(|| {
            AuthorizationProjectionError::NotReady(
                "code=authorization_projection.finalize_manifest_missing".to_owned(),
            )
        })?;
    if manifest.decode_identity()? != request.identity {
        return Err(AuthorizationProjectionError::IdentityMismatch(
            "code=authorization_projection.finalize_identity_mismatch".to_owned(),
        ));
    }
    if manifest.decode_generations()?.0 != request.target_generation {
        return Err(AuthorizationProjectionError::ManifestPublishConflict(
            "code=authorization_projection.finalize_generation_mismatch".to_owned(),
        ));
    }
    if manifest.status != MANIFEST_STATUS_BUILDING {
        return Err(AuthorizationProjectionError::NotReady(format!(
            "code=authorization_projection.finalize_requires_building;status={}",
            manifest.status
        )));
    }
    if manifest.lease_owner.as_deref() != Some(request.lease_owner.as_str())
        || manifest.lease_token_hash != Some(token_hash.as_bytes().to_vec())
        || manifest.lease_expires_at.is_none()
    {
        return Err(AuthorizationProjectionError::LeaseCasFailed(
            "code=authorization_projection.finalize_lease_mismatch".to_owned(),
        ));
    }
    if manifest.cas_version != request.expected_cas_version {
        return Err(AuthorizationProjectionError::LeaseCasFailed(
            "code=authorization_projection.finalize_cas_mismatch".to_owned(),
        ));
    }

    // Full completeness proof mirrors the strict read/recovery verification.
    let references = load_and_verify_references(
        tx,
        request.manifest_id,
        &request.identity,
        manifest.card_id,
        request.target_generation,
        &manifest.event_id,
        &manifest.operation_id,
    )
    .await?;
    if let Some(expected) = request.expected_reference_count {
        if expected != references.len() as u64 {
            return Err(AuthorizationProjectionError::Corrupt(
                "code=authorization_projection.finalize_reference_count_mismatch".to_owned(),
            ));
        }
    }
    let (_, _, manifest_digest) = manifest.decode_hashes()?;
    for reference in &references {
        fetch_and_verify_segment_row(tx, reference, &request.identity).await?;
    }

    // The seal must still reproduce before anything may leave BUILDING.
    let recomputed = manifest.recomputed_digest(
        references
            .iter()
            .map(|record| record.content_digest.as_hex())
            .collect(),
    )?;
    if recomputed != manifest_digest {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.finalize_digest_seal_broken".to_owned(),
        ));
    }

    AuthorizationManifestStatus::Building
        .validate_transition(AuthorizationManifestStatus::Ready)?;

    let updated = sqlx::query(MANIFEST_FINALIZE_SQL)
        .bind(request.manifest_id)
        .bind(request.identity.tenant_id)
        .bind(&request.identity.aggregate_type)
        .bind(request.identity.aggregate_id)
        .bind(bind_u64(request.target_generation, "finalize.generation")?)
        .bind(request.expected_cas_version)
        .bind(&request.lease_owner)
        .bind(token_hash.as_bytes().to_vec())
        .execute(&mut **tx)
        .await?;
    if updated.rows_affected() != 1 {
        return Err(AuthorizationProjectionError::LeaseCasFailed(
            "code=authorization_projection.finalize_lost_lease_or_race".to_owned(),
        ));
    }
    Ok(())
}

const MANIFEST_FINALIZE_SQL: &str = "UPDATE authorization_projection_manifest \
    SET status = 'READY', last_error = NULL \
    WHERE manifest_id = ? AND tenant_id = ? AND aggregate_type = ? AND aggregate_id = ? \
      AND generation = ? AND status = 'BUILDING' AND cas_version = ? \
      AND lease_owner = ? AND lease_token_hash = ? \
      AND lease_expires_at IS NOT NULL AND lease_expires_at > UTC_TIMESTAMP()";

// ─────────────────────────────────────────────────────────────────────────────
// Atomic current-pointer publication
// ─────────────────────────────────────────────────────────────────────────────

/// Durable expectations for one publication attempt (SQL level).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationPublishRequest {
    pub identity: ProjectionAggregateIdentity,
    /// Card scope of this publication chain (`None` = aggregate-wide). Must
    /// agree with the locked pointer AND the stored target manifest row; the
    /// first pointer `INSERT` persists it and the CAS `UPDATE` re-pins it.
    pub card_id: Option<i64>,
    pub target_manifest_id: i64,
    pub target_generation: u64,
    /// Freshly read-and-locked pointer state; `None` performs a strictly gated
    /// first publication (target generation must be 1).
    pub current_pointer: Option<CurrentPointerView>,
    pub expected_target_semantic_hash_hex: String,
    pub expected_target_dependency_hash_hex: String,
    pub expected_target_compiler_version: String,
    /// MANDATORY paired revoke-fence evidence: first publications present
    /// `previous = 0`; any regression is refused. Half-evidence and defaults
    /// are unrepresentable by construction.
    pub fences: PublishRevokeFenceEvidence,
}

/// Evidence returned by a successful publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationPublishOutcome {
    pub pointer: AuthorizationCurrentPointerRecord,
    pub published_manifest_id: i64,
    pub previous_superseded_manifest_id: Option<i64>,
    /// True when this was the first-ever pointer row for the aggregate.
    pub initialized_first_pointer: bool,
}

/// Pure post-CAS readback agreement check: the authoritative pointer row read
/// back inside the publishing transaction must carry exactly the published
/// evidence — including the target manifest's own `event_id`/`operation_id`
/// provenance — otherwise the durable pointer diverged from the CAS it claims
/// to reflect and the publication fails closed.
fn post_publish_pointer_agrees(
    pointer: &AuthorizationCurrentPointerRecord,
    request: &AuthorizationPublishRequest,
    target_event_id: &str,
    target_operation_id: &str,
    target_semantic: &Sha256Digest,
    target_dependency: &Sha256Digest,
) -> bool {
    pointer.manifest_id == request.target_manifest_id
        && pointer.current_generation == request.target_generation
        // Card scope round-trips through the durable row: a card-scoped
        // publication can never read back a NULL/foreign scope here.
        && pointer.card_id == request.card_id
        && pointer.event_id == target_event_id
        && pointer.operation_id == target_operation_id
        && pointer.semantic_hash == *target_semantic
        && pointer.dependency_hash == *target_dependency
        && pointer.compiler_version == request.expected_target_compiler_version
        // The fence round-trips too: the moved pointer must carry exactly the
        // published evidence.new value.
        && pointer.revoke_fence == request.fences.new_revoke_fence
        && pointer.revoke_fence_proven
}

/// Publish the target manifest atomically: guarded `READY -> COMMITTED`
/// promotion plus exactly-one-row current-pointer CAS (`parent -> target`).
///
/// Ordering inside the caller's transaction:
/// 1. pure precondition validation against fresh locked views,
/// 2. guarded promotion of the target manifest, pinned to status/CAS/hash
///    predicates re-checked server-side,
/// 3. the pointer CAS `UPDATE` (or strictly-gated first `INSERT`) afterwards;
///    any zero-row or uniqueness-loss outcome raises
///    [`AuthorizationProjectionError::CurrentPointerCasConflict`] so the
///    caller rolls the whole transaction back and target state plus pointer
///    movement stay mutually atomic,
/// 4. the previous current manifest becomes `SUPERSEDED` ONLY after the CAS
///    succeeded (history preserved; nothing deleted anywhere).
///
/// Card scope: `request.card_id` must agree with the locked pointer AND the
/// target manifest row; the first pointer `INSERT` persists it and the CAS
/// `UPDATE` re-pins it server-side (`card_id <=> ?`). Card-scoped aggregates
/// therefore never leave a NULL `card_id` behind on any generation, while
/// aggregate-wide projections (`None`) legitimately persist NULL.
///
/// There is no unconditional overwrite path: with an existing pointer the
/// statement always demands `current_generation`, `manifest_id` and
/// `cas_version` to match the freshly locked expectation exactly.
pub async fn publish_current_pointer_in_tx(
    tx: &mut Transaction<'_, MySql>,
    request: &AuthorizationPublishRequest,
) -> Result<AuthorizationPublishOutcome, AuthorizationProjectionError> {
    request.identity.validate()?;
    validated_option_card_id(request.card_id)?;
    positive_i64(request.target_manifest_id, "target_manifest_id")?;
    bind_u64(request.target_generation, "publish.target_generation")?;
    let target_semantic = Sha256Digest::from_hex(&request.expected_target_semantic_hash_hex)?;
    let target_dependency = Sha256Digest::from_hex(&request.expected_target_dependency_hash_hex)?;
    validated_text(
        &request.expected_target_compiler_version,
        MAX_COMPILER_VERSION_LENGTH,
        "expected_target_compiler_version",
    )?;

    // (1) Lock pointer state exactly as the caller claims it exists.
    let locked_pointer = lock_current_pointer_in_tx(tx, &request.identity).await?;
    if let Some(pointer) = &locked_pointer {
        validate_pointer_proof_state(pointer.revoke_fence, pointer.revoke_fence_proven)?;
    }
    if let Some(actual) = &locked_pointer {
        if actual.card_id != request.card_id {
            return Err(AuthorizationProjectionError::IdentityMismatch(
                "code=authorization_projection.publish_pointer_card_scope_mismatch".to_owned(),
            ));
        }
    }
    match (&locked_pointer, &request.current_pointer) {
        (Some(actual), Some(expected)) => {
            if actual.as_view() != *expected {
                return Err(AuthorizationProjectionError::CurrentPointerCasConflict(
                    "code=authorization_projection.publish_stale_pointer_view".to_owned(),
                ));
            }
        }
        (Some(_actual), None) => {
            return Err(AuthorizationProjectionError::ManifestPublishConflict(
                "code=authorization_projection.publish_expected_first_but_pointer_exists"
                    .to_owned(),
            ));
        }
        (None, Some(_)) => {
            return Err(AuthorizationProjectionError::CurrentPointerCasConflict(
                "code=authorization_projection.publish_expected_pointer_but_missing".to_owned(),
            ));
        }
        (None, None) => {}
    }

    // Load and verify the target manifest under lock.
    let target = fetch_manifest_for_update(tx, request.target_manifest_id)
        .await?
        .ok_or_else(|| {
            AuthorizationProjectionError::NotReady(
                "code=authorization_projection.publish_target_missing".to_owned(),
            )
        })?;
    if target.decode_identity()? != request.identity {
        return Err(AuthorizationProjectionError::IdentityMismatch(
            "code=authorization_projection.publish_target_identity_mismatch".to_owned(),
        ));
    }
    // The staged manifest's card scope must equal the requested publication
    // scope; publishing a manifest built under a different scope is refused
    // even though its aggregate identity matches.
    if target.card_id != request.card_id {
        return Err(AuthorizationProjectionError::IdentityMismatch(
            "code=authorization_projection.publish_target_card_scope_mismatch".to_owned(),
        ));
    }
    if target.decode_generations()?.0 != request.target_generation {
        return Err(AuthorizationProjectionError::ManifestPublishConflict(
            "code=authorization_projection.publish_target_generation_mismatch".to_owned(),
        ));
    }

    let reference_records = load_and_verify_references(
        tx,
        request.target_manifest_id,
        &request.identity,
        target.card_id,
        request.target_generation,
        &target.event_id,
        &target.operation_id,
    )
    .await?;
    let (target_semantic_stored, target_dependency_stored, _) = target.decode_hashes()?;
    for reference in &reference_records {
        fetch_and_verify_segment_row(tx, reference, &request.identity).await?;
    }

    let target_view = TargetManifestView {
        identity: request.identity.clone(),
        card_id: target.card_id,
        manifest_id: target.manifest_id,
        parent_manifest_id: target.decode_parent_manifest_id()?,
        generation: request.target_generation,
        status_str: target.status.clone(),
        semantic_hash_hex: target_semantic_stored.as_hex(),
        dependency_hash_hex: target_dependency_stored.as_hex(),
        compiler_version: target.compiler_version.clone(),
        reference_count: reference_records.len() as u64,
    };
    let expectation = AuthorizationPublishExpectation {
        current_pointer: locked_pointer.as_ref().map(|pointer| pointer.as_view()),
        expected_target_semantic_hash_hex: target_semantic.as_hex(),
        expected_target_dependency_hash_hex: target_dependency.as_hex(),
        expected_target_compiler_version: request.expected_target_compiler_version.clone(),
    };
    validate_manifest_publish(&expectation, &target_view)?;
    // Mandatory paired fence evidence; overflow-checked into the SQL BIGINT
    // domain, then monotonicity plus the first-publication previous-fence gate.
    bind_u64(
        request.fences.previous_revoke_fence,
        "publish.previous_revoke_fence",
    )?;
    bind_u64(request.fences.new_revoke_fence, "publish.new_revoke_fence")?;
    validate_publish_fence_continuity(
        request.fences.previous_revoke_fence,
        request.fences.new_revoke_fence,
    )?;
    validate_first_publication_previous_fence(
        locked_pointer.is_some(),
        request.fences.previous_revoke_fence,
    )?;
    // The locked current pointer row is the ONLY authority for the previous
    // fence (0 when absent). Caller evidence acts as the stated expectation /
    // CAS pin and must match it exactly; a forged or stale value refuses here
    // before anything is written. After a worker restart this still works with
    // DB rows alone: no caller-retained history participates in the decision.
    let authoritative_previous_revoke_fence = locked_pointer.as_ref().map(|p| p.revoke_fence);
    validate_publish_previous_fence_authority(
        authoritative_previous_revoke_fence,
        request.fences.previous_revoke_fence,
    )?;
    // Stored hash bytes must equal the parsed expectation digests.
    if target_semantic_stored != target_semantic || target_dependency_stored != target_dependency {
        return Err(AuthorizationProjectionError::ManifestPublishConflict(
            "code=authorization_projection.publish_stored_hash_diverges_from_expectation"
                .to_owned(),
        ));
    }

    // (2) Guarded promotion READY -> COMMITTED pinned to observed CAS + hashes
    // AND the target's own revoke fence: the manifest row may only leave READY
    // when its stored fence equals the evidence being published.
    let promoted = sqlx::query(MANIFEST_PROMOTE_SQL)
        .bind(request.target_manifest_id)
        .bind(request.identity.tenant_id)
        .bind(&request.identity.aggregate_type)
        .bind(request.identity.aggregate_id)
        .bind(bind_u64(request.target_generation, "publish.generation")?)
        .bind(target.cas_version)
        .bind(bind_u64(
            request.fences.new_revoke_fence,
            "publish.promote_revoke_fence",
        )?)
        .bind(target_semantic_stored.as_bytes().to_vec())
        .bind(target_dependency_stored.as_bytes().to_vec())
        .bind(&target.compiler_version)
        .execute(&mut **tx)
        .await?;
    if promoted.rows_affected() != 1 {
        return Err(AuthorizationProjectionError::ManifestPublishConflict(
            "code=authorization_projection.publish_promotion_race".to_owned(),
        ));
    }

    // (3) Current-pointer movement.
    let (previous_manifest_id, initialized_first_pointer) = match &locked_pointer {
        Some(previous) => {
            // Bind order follows statement text: SET columns first
            // (generation, card scope, manifest id, provenance, hashes,
            // compiler, revoke fence), then WHERE guards (identity, null-safe
            // card scope, expected generation/manifest/cas fence AND the
            // pinned previous revoke fence — the CAS itself refuses any move
            // off a pointer whose durable fence no longer equals evidence).
            let cas_update = sqlx::query(POINTER_CAS_UPDATE_SQL)
                .bind(bind_u64(
                    request.target_generation,
                    "publish.current_generation",
                )?)
                .bind(request.card_id)
                .bind(request.target_manifest_id)
                .bind(&target.event_id)
                .bind(&target.operation_id)
                .bind(target_semantic.as_bytes().to_vec())
                .bind(target_dependency.as_bytes().to_vec())
                .bind(&request.expected_target_compiler_version)
                .bind(bind_u64(
                    request.fences.new_revoke_fence,
                    "publish.cas_revoke_fence",
                )?)
                .bind(previous.identity.tenant_id)
                .bind(&previous.identity.aggregate_type)
                .bind(previous.identity.aggregate_id)
                .bind(request.card_id)
                .bind(bind_u64(
                    previous.current_generation,
                    "publish.expected_current_generation",
                )?)
                .bind(previous.manifest_id)
                .bind(previous.cas_version)
                .bind(bind_u64(
                    previous.revoke_fence,
                    "publish.expected_previous_revoke_fence",
                )?)
                .execute(&mut **tx)
                .await?;
            if cas_update.rows_affected() != 1 {
                return Err(AuthorizationProjectionError::CurrentPointerCasConflict(format!(
                    "code=authorization_projection.pointer_cas_zero_rows;expected_manifest={};expected_generation={};expected_cas={}",
                    previous.manifest_id, previous.current_generation, previous.cas_version
                )));
            }
            (Some(previous.manifest_id), false)
        }
        None => {
            // Bind order follows statement text: tenant, card scope,
            // aggregate identity, generation, manifest, provenance, hashes,
            // compiler, revoke fence (first publication with a proven
            // `previous = 0` evidence). The card scope is persisted explicitly
            // so a card-scoped chain never leaves a NULL `card_id` on its
            // pointer.
            let insert_result = sqlx::query(POINTER_FIRST_INSERT_SQL)
                .bind(request.identity.tenant_id)
                .bind(request.card_id)
                .bind(&request.identity.aggregate_type)
                .bind(request.identity.aggregate_id)
                .bind(bind_u64(
                    request.target_generation,
                    "publish.current_generation",
                )?)
                .bind(request.target_manifest_id)
                .bind(&target.event_id)
                .bind(&target.operation_id)
                .bind(target_semantic.as_bytes().to_vec())
                .bind(target_dependency.as_bytes().to_vec())
                .bind(&request.expected_target_compiler_version)
                .bind(bind_u64(
                    request.fences.new_revoke_fence,
                    "publish.first_revoke_fence",
                )?)
                .execute(&mut **tx)
                .await;
            match insert_result {
                Ok(result) => {
                    if result.rows_affected() != 1 {
                        return Err(AuthorizationProjectionError::CurrentPointerCasConflict(
                            "code=authorization_projection.first_pointer_insert_not_applied"
                                .to_owned(),
                        ));
                    }
                }
                Err(error) if unique_violation(&error) => {
                    // A concurrent first publisher won uk_apc_aggregate.
                    return Err(AuthorizationProjectionError::CurrentPointerCasConflict(
                        "code=authorization_projection.first_pointer_race".to_owned(),
                    ));
                }
                Err(error) => return Err(error.into()),
            }
            (None, true)
        }
    };

    // (4) Mark the previous current manifest SUPERSEDED, only after success.
    if let Some(previous_manifest_id) = previous_manifest_id {
        let superseded = sqlx::query(MANIFEST_SUPERSEDE_SQL)
            .bind(previous_manifest_id)
            .bind(request.identity.tenant_id)
            .bind(&request.identity.aggregate_type)
            .bind(request.identity.aggregate_id)
            .execute(&mut **tx)
            .await?;
        if superseded.rows_affected() != 1 {
            return Err(AuthorizationProjectionError::Corrupt(
                "code=authorization_projection.supersede_failed".to_owned(),
            ));
        }
    }

    // Read the authoritative post-state back within the same transaction.
    let statement = format!("{SELECT_PREFIX}{POINTER_ROW_COLUMNS}{POINTER_BY_IDENTITY_TAIL}");
    let pointer_after: Option<PointerRawSqlRow> = sqlx::query_as(statement.as_str())
        .bind(request.identity.tenant_id)
        .bind(&request.identity.aggregate_type)
        .bind(request.identity.aggregate_id)
        .fetch_optional(&mut **tx)
        .await?;
    let pointer_record = pointer_after
        .ok_or_else(|| {
            AuthorizationProjectionError::Corrupt(
                "code=authorization_projection.post_publish_pointer_missing".to_owned(),
            )
        })?
        .decode()?;
    if !post_publish_pointer_agrees(
        &pointer_record,
        request,
        &target.event_id,
        &target.operation_id,
        &target_semantic,
        &target_dependency,
    ) {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.post_publish_pointer_diverged".to_owned(),
        ));
    }

    Ok(AuthorizationPublishOutcome {
        pointer: pointer_record,
        published_manifest_id: request.target_manifest_id,
        previous_superseded_manifest_id: previous_manifest_id,
        initialized_first_pointer,
    })
}

const MANIFEST_SUPERSEDE_SQL: &str = "UPDATE authorization_projection_manifest \
    SET status = 'SUPERSEDED' \
    WHERE manifest_id = ? AND tenant_id = ? AND aggregate_type = ? AND aggregate_id = ? \
      AND status = 'COMMITTED'";

const MANIFEST_PROMOTE_SQL: &str = "UPDATE authorization_projection_manifest \
    SET status = 'COMMITTED', last_error = NULL, \
        lease_owner = NULL, lease_token_hash = NULL, lease_expires_at = NULL \
    WHERE manifest_id = ? AND tenant_id = ? AND aggregate_type = ? AND aggregate_id = ? \
      AND generation = ? AND status = 'READY' AND cas_version = ? AND revoke_fence = ? \
      AND semantic_hash = ? AND dependency_hash = ? AND compiler_version = ?";

const POINTER_CAS_UPDATE_SQL: &str = "UPDATE authorization_projection_current \
    SET current_generation = ?, card_id = ?, manifest_id = ?, event_id = ?, operation_id = ?, \
        semantic_hash = ?, dependency_hash = ?, compiler_version = ?, revoke_fence = ?, \
        revoke_fence_proven = 1, status = 'READY', cas_version = cas_version + 1, last_error = NULL \
    WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ? AND card_id <=> ? \
      AND current_generation = ? AND manifest_id = ? AND cas_version = ? AND revoke_fence = ? \
      AND revoke_fence_proven = 1";

const POINTER_FIRST_INSERT_SQL: &str = "INSERT INTO authorization_projection_current \
    (tenant_id, card_id, aggregate_type, aggregate_id, current_generation, manifest_id, event_id, \
     operation_id, semantic_hash, dependency_hash, compiler_version, revoke_fence, \
     revoke_fence_proven, status) \
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'READY')";

// ─────────────────────────────────────────────────────────────────────────────
// Strict reads and recovery
// ─────────────────────────────────────────────────────────────────────────────

/// Pure card-scope agreement check: every reference row must belong to exactly
/// the card scope of the manifest that references it. `None` on both sides is
/// the legitimate aggregate-wide case; any NULL/foreign disagreement is
/// cross-scope contamination and is refused before the reference is used.
fn verify_reference_card_scope(
    record_card_id: Option<i64>,
    manifest_card_id: Option<i64>,
) -> Result<(), AuthorizationProjectionError> {
    if record_card_id != manifest_card_id {
        return Err(AuthorizationProjectionError::IdentityMismatch(
            "code=authorization_projection.reference_card_scope_mismatch".to_owned(),
        ));
    }
    Ok(())
}

/// Pure reference-count cap check mirroring the staging-plan bound: a durable
/// manifest carrying more reference rows than [`MAX_SEGMENTS_PER_MANIFEST`] is
/// refused before any of its references are processed (fail-closed, same code
/// as the write side).
fn enforce_segment_reference_cap(count: usize) -> Result<(), AuthorizationProjectionError> {
    if count > MAX_SEGMENTS_PER_MANIFEST {
        return Err(scope_violation(
            "authorization_projection.too_many_segments_per_manifest",
        ));
    }
    Ok(())
}

async fn load_and_verify_references(
    tx: &mut Transaction<'_, MySql>,
    manifest_id: i64,
    identity: &ProjectionAggregateIdentity,
    manifest_card_id: Option<i64>,
    generation: u64,
    manifest_event_id: &str,
    manifest_operation_id: &str,
) -> Result<Vec<AuthorizationSegmentReferenceRecord>, AuthorizationProjectionError> {
    let statement = format!("{SELECT_PREFIX}{REFERENCE_ROW_COLUMNS}{REFERENCES_BY_MANIFEST_TAIL}");
    let rows: Vec<ReferenceRawSqlRow> = sqlx::query_as(statement.as_str())
        .bind(manifest_id)
        .fetch_all(&mut **tx)
        .await?;
    enforce_segment_reference_cap(rows.len())?;
    let mut references: Vec<AuthorizationSegmentReferenceRecord> = Vec::with_capacity(rows.len());
    for raw in &rows {
        references.push(raw.decode()?);
    }
    let counted: Vec<(u64, u64)> = references
        .iter()
        .map(|record| (record.ordinal, 0u64))
        .collect();
    validate_contiguous_ordinals(&counted)?;
    let mut seen_segment_ids = std::collections::BTreeSet::new();
    for record in &references {
        if record.identity != *identity {
            return Err(AuthorizationProjectionError::IdentityMismatch(
                "code=authorization_projection.reference_identity_mismatch".to_owned(),
            ));
        }
        verify_reference_card_scope(record.card_id, manifest_card_id)?;
        if record.generation != generation {
            return Err(AuthorizationProjectionError::Corrupt(
                "code=authorization_projection.reference_generation_mismatch".to_owned(),
            ));
        }
        if record.event_id != manifest_event_id || record.operation_id != manifest_operation_id {
            return Err(AuthorizationProjectionError::Corrupt(
                "code=authorization_projection.reference_provenance_mismatch".to_owned(),
            ));
        }
        if !seen_segment_ids.insert(record.segment_id) {
            return Err(AuthorizationProjectionError::Corrupt(
                "code=authorization_projection.duplicate_reference_segment".to_owned(),
            ));
        }
    }
    Ok(references)
}

async fn fetch_and_verify_segment_row(
    tx: &mut Transaction<'_, MySql>,
    reference: &AuthorizationSegmentReferenceRecord,
    identity: &ProjectionAggregateIdentity,
) -> Result<AuthorizationSegmentSnapshot, AuthorizationProjectionError> {
    let statement = format!("{SELECT_PREFIX}{SEGMENT_ROW_COLUMNS}{SEGMENT_BY_ID_TAIL}");
    let row: Option<SegmentRawSqlRow> = sqlx::query_as(statement.as_str())
        .bind(reference.segment_id)
        .fetch_optional(&mut **tx)
        .await?;
    let Some(row) = row else {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.referenced_segment_missing".to_owned(),
        ));
    };
    // decode_with_payload already re-derives the SEGMENT-LOCAL seals; the
    // reference/digest/identity pairing completes the evidence. Manifest-global
    // hashes are deliberately NOT compared against segment rows: unchanged
    // segments legitimately outlive any single generation's global hashes.
    let snapshot = row.decode_with_payload()?;
    verify_reference_content_pair(reference, &snapshot, identity)?;
    Ok(snapshot)
}

async fn load_verified_chain(
    tx: &mut Transaction<'_, MySql>,
    identity: &ProjectionAggregateIdentity,
    manifest: &ManifestRawSqlRow,
) -> Result<Vec<AuthorizationSegmentSnapshot>, AuthorizationProjectionError> {
    Ok(load_verified_chain_with_references(tx, identity, manifest)
        .await?
        .1)
}

/// Combined variant of [`load_verified_chain`] that also returns the verified
/// ordered reference records, so planning readers can expose parent views
/// without re-reading payload blobs a second time.
async fn load_verified_chain_with_references(
    tx: &mut Transaction<'_, MySql>,
    identity: &ProjectionAggregateIdentity,
    manifest: &ManifestRawSqlRow,
) -> Result<
    (
        Vec<AuthorizationSegmentReferenceRecord>,
        Vec<AuthorizationSegmentSnapshot>,
    ),
    AuthorizationProjectionError,
> {
    let generation = manifest.decode_generations()?.0;
    let references = load_and_verify_references(
        tx,
        manifest.manifest_id,
        identity,
        manifest.card_id,
        generation,
        &manifest.event_id,
        &manifest.operation_id,
    )
    .await?;
    let mut segments = Vec::with_capacity(references.len());
    for reference in &references {
        segments.push(fetch_and_verify_segment_row(tx, reference, identity).await?);
    }
    Ok((references, segments))
}

/// Consistency read of the complete published state behind the current
/// pointer, with pointer/manifest locks taken to serialize against publishers.
///
/// Failure policy: missing pointer, missing manifest, non-`COMMITTED` status,
/// any ordinal gap/duplicate, any identity/generation/digest/hash/compiler
/// disagreement or any unreadable segment payload aborts the ENTIRE read with
/// an explicit error. Old snapshots, raw-source fallbacks and partial segment
/// lists are never returned.
pub async fn read_published_authorization_state_in_tx(
    tx: &mut Transaction<'_, MySql>,
    identity: &ProjectionAggregateIdentity,
) -> Result<AuthorizationPublishedState, AuthorizationProjectionError> {
    identity.validate()?;
    let pointer = lock_current_pointer_in_tx(tx, identity)
        .await?
        .ok_or_else(|| {
            AuthorizationProjectionError::NotReady(
                "code=authorization_projection.current_pointer_missing".to_owned(),
            )
        })?;
    validate_pointer_proof_state(pointer.revoke_fence, pointer.revoke_fence_proven)?;
    let manifest = fetch_manifest_for_update(tx, pointer.manifest_id)
        .await?
        .ok_or_else(|| {
            AuthorizationProjectionError::NotReady(
                "code=authorization_projection.published_manifest_missing".to_owned(),
            )
        })?;
    let (generation, source_generation, projected_generation) = manifest.decode_generations()?;
    if generation != pointer.current_generation {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.pointer_manifest_generation_split".to_owned(),
        ));
    }
    if manifest.status != MANIFEST_STATUS_COMMITTED {
        return Err(AuthorizationProjectionError::NotReady(format!(
            "code=authorization_projection.published_manifest_not_committed;status={}",
            manifest.status
        )));
    }
    if manifest.decode_identity()? != pointer.identity {
        return Err(AuthorizationProjectionError::IdentityMismatch(
            "code=authorization_projection.pointer_manifest_identity_split".to_owned(),
        ));
    }
    // The pointer and its committed manifest must also agree on the durable
    // fence level; a split is corrupt state that no read may launder.
    if manifest.decode_revoke_fence()? != pointer.revoke_fence {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.pointer_manifest_fence_split".to_owned(),
        ));
    }
    // Card-scope continuity: the manifest row must carry exactly the pointer's
    // durable scope; a None-vs-Some or foreign-card flip is corrupt state and
    // fails closed instead of surfacing through any read.
    if manifest.card_id != pointer.card_id {
        return Err(AuthorizationProjectionError::IdentityMismatch(
            "code=authorization_projection.pointer_manifest_card_split".to_owned(),
        ));
    }
    let (semantic_hash, dependency_hash, manifest_digest) = manifest.decode_hashes()?;
    if semantic_hash != pointer.semantic_hash
        || dependency_hash != pointer.dependency_hash
        || manifest.compiler_version != pointer.compiler_version
    {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.pointer_hash_chain_break".to_owned(),
        ));
    }

    let (references, segments) =
        load_verified_chain_with_references(tx, identity, &manifest).await?;
    let recomputed = manifest.recomputed_digest(
        segments
            .iter()
            .map(|snapshot| snapshot.content_digest.as_hex())
            .collect(),
    )?;
    if recomputed != manifest_digest {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.manifest_digest_seal_broken".to_owned(),
        ));
    }
    let total_grant_count = sum_grant_counts(&segments)?;

    Ok(AuthorizationPublishedState {
        pointer,
        manifest_id: manifest.manifest_id,
        generation,
        source_generation,
        projected_generation,
        event_id: manifest.event_id.clone(),
        operation_id: manifest.operation_id.clone(),
        semantic_hash,
        dependency_hash,
        compiler_version: manifest.compiler_version.clone(),
        manifest_digest,
        parent_manifest_id: manifest.decode_parent_manifest_id()?,
        revoke_fence: manifest.decode_revoke_fence()?,
        segments,
        references,
        total_grant_count,
    })
}

fn sum_grant_counts(
    segments: &[AuthorizationSegmentSnapshot],
) -> Result<u64, AuthorizationProjectionError> {
    segments
        .iter()
        .try_fold(0_u64, |acc, snapshot| acc.checked_add(snapshot.row_count))
        .ok_or_else(|| {
            mapping_error("code=authorization_projection.grant_count_overflow".to_owned())
        })
}

/// Recovery reader accepting non-published (`BUILDING`/`READY`) targets for a
/// given generation, with identical integrity enforcement.
///
/// Used by future workers/rescue tooling to inspect a stalled chain without
/// bypassing any invariant: corrupt payloads, gapped ordinals or hash-chain
/// disagreements fail closed exactly like the strict read.
pub async fn load_authorization_recovery_state_in_tx(
    tx: &mut Transaction<'_, MySql>,
    identity: &ProjectionAggregateIdentity,
    generation: u64,
) -> Result<Option<AuthorizationRecoveryState>, AuthorizationProjectionError> {
    identity.validate()?;
    if generation == 0 || bind_u64(generation, "recovery.generation").is_err() {
        return Err(scope_violation(
            "authorization_projection.invalid_recovery_generation",
        ));
    }
    let current_pointer = lock_current_pointer_in_tx(tx, identity).await?;
    if let Some(pointer) = &current_pointer {
        validate_pointer_proof_state(pointer.revoke_fence, pointer.revoke_fence_proven)?;
    }
    let statement = format!("{SELECT_PREFIX}{MANIFEST_ROW_COLUMNS}{MANIFEST_BY_GENERATION_TAIL}");
    let manifest: Option<ManifestRawSqlRow> = sqlx::query_as(statement.as_str())
        .bind(identity.tenant_id)
        .bind(&identity.aggregate_type)
        .bind(identity.aggregate_id)
        .bind(bind_u64(generation, "recovery.generation")?)
        .fetch_optional(&mut **tx)
        .await?;
    let Some(manifest) = manifest else {
        return Ok(None);
    };
    if manifest.decode_identity()? != *identity {
        return Err(AuthorizationProjectionError::IdentityMismatch(
            "code=authorization_projection.recovery_identity_mismatch".to_owned(),
        ));
    }
    let status = manifest.decode_status()?;
    let (recovered_generation, recovered_source, recovered_projected) =
        manifest.decode_generations()?;
    let segments = load_verified_chain(tx, identity, &manifest).await?;
    let (semantic_hash, dependency_hash, manifest_digest) = manifest.decode_hashes()?;
    let recomputed = manifest.recomputed_digest(
        segments
            .iter()
            .map(|snapshot| snapshot.content_digest.as_hex())
            .collect(),
    )?;
    if recomputed != manifest_digest {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.recovery_digest_seal_broken".to_owned(),
        ));
    }
    let total_grant_count = sum_grant_counts(&segments)?;

    Ok(Some(AuthorizationRecoveryState {
        manifest_id: manifest.manifest_id,
        identity: identity.clone(),
        card_id: manifest.card_id,
        generation: recovered_generation,
        source_generation: recovered_source,
        projected_generation: recovered_projected,
        event_id: manifest.event_id.clone(),
        operation_id: manifest.operation_id.clone(),
        status,
        cas_version: manifest.cas_version,
        semantic_hash,
        dependency_hash,
        compiler_version: manifest.compiler_version.clone(),
        manifest_digest,
        parent_manifest_id: manifest.decode_parent_manifest_id()?,
        revoke_fence: manifest.decode_revoke_fence()?,
        leased: manifest.lease_owner.is_some(),
        segments,
        total_grant_count,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Legacy fence-proof latch rehearsal (operator-driven, explicit, per-pointer)
// ─────────────────────────────────────────────────────────────────────────────
//
// `revoke_fence_proven = 0` marks a current pointer row that predates the
// durable latch column (migration 20260827000001). Such a row fails closed
// everywhere ([`validate_pointer_proof_state`]) and the ONLY way out is this
// explicit operator primitive — never a blanket update, never a scheduled or
// startup-time pass, and never an inference from stored numeric values.
//
// Contract of [`rehearse_legacy_fence_proof_in_tx`]:
//
// 1. The caller supplies a request carrying a verified operator id, a stable
//    operator operation id (the audit correlation id) and the EXACT pointer
//    evidence it just read and locked (manifest, generation, hashes, compiler,
//    fence, CAS). Every field must be freshly re-read; stale evidence is
//    refused, never healed.
// 2. The pointer row is locked `FOR UPDATE` and revalidated against the
//    request. A pointer that is ALREADY proven is accepted only as a verified
//    idempotent no-op when every expected dimension matches exactly (including
//    the CAS counter and the fence); any drift is refused. A no-op writes
//    nothing — not even audit — because it performs no durable mutation.
// 3. An unproven legacy pointer is rehearsed ONLY when its numeric fence is 0
//    AND its generation is 1: this is the only chain shape whose completeness
//    is provable from the durable rows alone. Multi-generation legacy chains
//    (or a pointer whose aggregate carries any other COMMITTED/SUPERSEDED/READY
//    generation) are refused with stable machine codes instead of silently
//    filling parent lineage. The target manifest is re-proven under lock:
//    `COMMITTED`, parentless, zero-fence, identity/card-scoped, hash-chain
//    equal to the pointer, all references ordinal-continuous, every segment
//    payload re-verified, and the manifest digest seal re-derived.
// 4. Success applies a SINGLE guarded CAS `UPDATE` setting ONLY
//    `revoke_fence_proven = 1` and `cas_version = cas_version + 1`, pinned to
//    identity, card scope, manifest id, generation, expected CAS, expected
//    fence and the old latch `= 0`. Zero affected rows is a CAS conflict and
//    rolls the caller's transaction back.
// 5. The durable audit correlation row (shared `audit_log` table, established
//    in-transaction INSERT shape) is written in the SAME transaction, BEFORE
//    the CAS: the latch can never exist without its audit evidence, and an
//    audit failure aborts the whole mutation. No external side effect happens
//    anywhere in this primitive; callers own commit/rollback.
//
// There is deliberately no HTTP route, no worker loop and no startup execution
// wired to this function; invoking it is an explicit operator decision.

/// Conservative bound for the operator rehearsal operation id as stored in the
/// shared `audit_log.request_id` correlation column.
pub const MAX_FENCE_PROOF_REHEARSAL_OPERATION_ID_LENGTH: usize = 64;

/// Conservative bound for the free-text reason stored in
/// `audit_log.reason`.
pub const MAX_FENCE_PROOF_REHEARSAL_REASON_LENGTH: usize = 255;

/// Exact pointer evidence a rehearsal request pins. Every field must equal the
/// freshly locked durable row; there are no defaults and no options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationFenceProofRehearsalExpectation {
    pub manifest_id: i64,
    pub generation: u64,
    pub semantic_hash_hex: String,
    pub dependency_hash_hex: String,
    pub compiler_version: String,
    pub revoke_fence: u64,
    pub cas_version: i64,
}

/// Explicit, per-pointer operator rehearsal request.
///
/// `operator_id` MUST be the Gateway-verified acting user; `operation_id` is
/// the stable correlation id under which the durable audit row can be found
/// (and replayed/deduplicated by operators). `reason` is the short
/// justification token stored with the audit evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationFenceProofRehearsalRequest {
    pub identity: ProjectionAggregateIdentity,
    /// Card scope of the pointer (`None` = aggregate-wide); must match the
    /// durable row exactly.
    pub card_id: Option<i64>,
    /// Verified operator user id (audit `user_id`); never a free-text claim.
    pub operator_id: i64,
    /// Stable operator operation id (audit `request_id` correlation key).
    pub operation_id: String,
    pub expectation: AuthorizationFenceProofRehearsalExpectation,
    /// Whitespace-free bounded justification token stored in `audit_log.reason`
    /// (this module's strict-text rules reject spaces/controls by design; the
    /// structured audit `detail` JSON carries the full context).
    pub reason: String,
}

/// Pure decision of a rehearsal request against the locked pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceProofRehearsalDecision {
    /// The latch is already proven and every expected dimension matches
    /// exactly: the call is a verified idempotent no-op that writes nothing.
    AlreadyProven,
    /// Unproven legacy zero-fence generation-one pointer: the full chain
    /// rehearsal and the guarded latch CAS may proceed.
    RehearseLegacyZeroFence,
}

/// Evidence returned by a rehearsal call (latch applied or verified no-op).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationFenceProofRehearsalOutcome {
    /// Authoritative pointer state as re-read inside the same transaction.
    pub pointer: AuthorizationCurrentPointerRecord,
    /// `true` when THIS call applied the latch; `false` for a verified no-op
    /// replay (nothing was written, no audit row was appended).
    pub latched_now: bool,
}

/// Validate the static shape of a rehearsal request (pure).
pub fn validate_fence_proof_rehearsal_request(
    request: &AuthorizationFenceProofRehearsalRequest,
) -> Result<(), AuthorizationProjectionError> {
    request.identity.validate()?;
    validated_option_card_id(request.card_id)?;
    positive_i64(request.operator_id, "operator_id")?;
    validated_text(
        &request.operation_id,
        MAX_FENCE_PROOF_REHEARSAL_OPERATION_ID_LENGTH,
        "operation_id",
    )?;
    // `validated_text` judges the TRIMMED value while the raw string is bound
    // verbatim into the durable `audit_log` correlation columns; any padding it
    // would silently accept must be refused here so the audited evidence equals
    // the validated form exactly.
    if request.operation_id.trim() != request.operation_id {
        return Err(scope_violation(
            "authorization_projection.invalid_rehearsal_operation_id_padding",
        ));
    }
    validated_text(
        &request.reason,
        MAX_FENCE_PROOF_REHEARSAL_REASON_LENGTH,
        "reason",
    )?;
    if request.reason.trim() != request.reason {
        return Err(scope_violation(
            "authorization_projection.invalid_rehearsal_reason_padding",
        ));
    }
    let expectation = &request.expectation;
    positive_i64(expectation.manifest_id, "expectation.manifest_id")?;
    if expectation.generation == 0 {
        return Err(scope_violation(
            "authorization_projection.invalid_rehearsal_generation",
        ));
    }
    bind_u64(expectation.generation, "rehearsal.generation")?;
    if Sha256Digest::from_hex(&expectation.semantic_hash_hex).is_err() {
        return Err(scope_violation(
            "authorization_projection.invalid_rehearsal_semantic_hash",
        ));
    }
    if Sha256Digest::from_hex(&expectation.dependency_hash_hex).is_err() {
        return Err(scope_violation(
            "authorization_projection.invalid_rehearsal_dependency_hash",
        ));
    }
    validated_text(
        &expectation.compiler_version,
        MAX_COMPILER_VERSION_LENGTH,
        "expectation.compiler_version",
    )?;
    bind_u64(expectation.revoke_fence, "rehearsal.revoke_fence")?;
    Ok(())
}

/// Revalidate the locked pointer against the request evidence (pure).
///
/// Any disagreement between the request and the locked row means the caller's
/// evidence is stale or forged and is refused — never healed, never narrowed.
/// A fully matching proven pointer yields [`FenceProofRehearsalDecision::AlreadyProven`];
/// a fully matching unproven zero-fence generation-one pointer yields
/// [`FenceProofRehearsalDecision::RehearseLegacyZeroFence`].
pub fn decide_fence_proof_rehearsal(
    request: &AuthorizationFenceProofRehearsalRequest,
    pointer: &AuthorizationCurrentPointerRecord,
) -> Result<FenceProofRehearsalDecision, AuthorizationProjectionError> {
    if pointer.identity != request.identity {
        return Err(AuthorizationProjectionError::IdentityMismatch(
            "code=authorization_projection.fence_proof_identity_mismatch".to_owned(),
        ));
    }
    if pointer.card_id != request.card_id {
        return Err(AuthorizationProjectionError::IdentityMismatch(
            "code=authorization_projection.fence_proof_card_scope_mismatch".to_owned(),
        ));
    }

    let expectation = &request.expectation;
    let expectation_mismatch = |dimension: &str, durable: String, evidence: String| {
        AuthorizationProjectionError::CurrentPointerCasConflict(format!(
            "code=authorization_projection.fence_proof_expectation_mismatch;dimension={dimension};durable={durable};evidence={evidence}"
        ))
    };
    if pointer.manifest_id != expectation.manifest_id {
        return Err(expectation_mismatch(
            "manifest_id",
            pointer.manifest_id.to_string(),
            expectation.manifest_id.to_string(),
        ));
    }
    if pointer.current_generation != expectation.generation {
        return Err(expectation_mismatch(
            "generation",
            pointer.current_generation.to_string(),
            expectation.generation.to_string(),
        ));
    }
    if pointer.semantic_hash.as_hex() != expectation.semantic_hash_hex {
        return Err(expectation_mismatch(
            "semantic_hash",
            pointer.semantic_hash.as_hex(),
            expectation.semantic_hash_hex.clone(),
        ));
    }
    if pointer.dependency_hash.as_hex() != expectation.dependency_hash_hex {
        return Err(expectation_mismatch(
            "dependency_hash",
            pointer.dependency_hash.as_hex(),
            expectation.dependency_hash_hex.clone(),
        ));
    }
    if pointer.compiler_version != expectation.compiler_version {
        return Err(expectation_mismatch(
            "compiler_version",
            pointer.compiler_version.clone(),
            expectation.compiler_version.clone(),
        ));
    }
    if pointer.revoke_fence != expectation.revoke_fence {
        return Err(expectation_mismatch(
            "revoke_fence",
            pointer.revoke_fence.to_string(),
            expectation.revoke_fence.to_string(),
        ));
    }
    if pointer.cas_version != expectation.cas_version {
        return Err(expectation_mismatch(
            "cas_version",
            pointer.cas_version.to_string(),
            expectation.cas_version.to_string(),
        ));
    }

    if pointer.revoke_fence_proven {
        return Ok(FenceProofRehearsalDecision::AlreadyProven);
    }
    // Unproven legacy gate: only the provable chain shape may pass. A nonzero
    // numeric fence is migration-era history that cannot be re-derived from
    // durable rows, and a generation above one would require proving a parent
    // lineage the legacy rows cannot supply. Both refuse with stable codes.
    if pointer.revoke_fence != 0 {
        return Err(AuthorizationProjectionError::NotReady(format!(
            "code=authorization_projection.fence_proof_requires_zero_fence;pointer_fence={}",
            pointer.revoke_fence
        )));
    }
    if pointer.current_generation != 1 {
        return Err(AuthorizationProjectionError::NotReady(format!(
            "code=authorization_projection.fence_proof_requires_generation_one_chain;pointer_generation={}",
            pointer.current_generation
        )));
    }
    Ok(FenceProofRehearsalDecision::RehearseLegacyZeroFence)
}

/// Prove the locked target manifest against the locked pointer and request
/// evidence (pure).
///
/// The rehearsal accepts ONLY a `COMMITTED`, parentless, zero-fence
/// generation-one manifest whose identity, card scope, hashes and compiler
/// stamp equal the pointer's. Reference ordinals, segment payloads and the
/// manifest digest seal are re-verified by the transactional caller through
/// the shared strict-read helpers.
fn prove_fence_proof_rehearsal_manifest(
    pointer: &AuthorizationCurrentPointerRecord,
    manifest: &ManifestRawSqlRow,
) -> Result<(), AuthorizationProjectionError> {
    if manifest.decode_identity()? != pointer.identity {
        return Err(AuthorizationProjectionError::IdentityMismatch(
            "code=authorization_projection.fence_proof_manifest_identity_split".to_owned(),
        ));
    }
    if manifest.card_id != pointer.card_id {
        return Err(AuthorizationProjectionError::IdentityMismatch(
            "code=authorization_projection.fence_proof_manifest_card_split".to_owned(),
        ));
    }
    if manifest.decode_generations()?.0 != pointer.current_generation {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.fence_proof_manifest_generation_split".to_owned(),
        ));
    }
    if manifest.status != MANIFEST_STATUS_COMMITTED {
        return Err(AuthorizationProjectionError::NotReady(format!(
            "code=authorization_projection.fence_proof_manifest_not_committed;status={}",
            manifest.status
        )));
    }
    if manifest.decode_parent_manifest_id()?.is_some() {
        return Err(AuthorizationProjectionError::Corrupt(format!(
            "code=authorization_projection.fence_proof_manifest_has_parent;parent={:?}",
            manifest.parent_manifest_id
        )));
    }
    if manifest.decode_revoke_fence()? != 0 {
        return Err(AuthorizationProjectionError::Corrupt(format!(
            "code=authorization_projection.fence_proof_manifest_fence_nonzero;fence={}",
            manifest.decode_revoke_fence()?
        )));
    }
    let (semantic_hash, dependency_hash, _) = manifest.decode_hashes()?;
    if semantic_hash != pointer.semantic_hash
        || dependency_hash != pointer.dependency_hash
        || manifest.compiler_version != pointer.compiler_version
    {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.fence_proof_manifest_hash_chain_break".to_owned(),
        ));
    }
    // The request evidence already equals the pointer (decision gate), so the
    // manifest is proven strictly against the pointer's durable dimensions.
    Ok(())
}

const FENCE_PROOF_AUDIT_INSERT_SQL: &str = "INSERT INTO audit_log \
    (user_id, card_id, action, resource, decision, reason, event_type, request_id, detail) \
    VALUES (?, ?, ?, 'authorization_projection_current', 'ALLOW', ?, 'AUTHZ_FENCE_PROOF_LATCH', ?, ?)";

/// Single guarded latch CAS: sets ONLY the proof latch and increments the CAS
/// counter, pinned to the full identity/card/manifest/generation/cas/fence
/// evidence and the old latch value. A blanket or unpinned latch update is
/// unrepresentable with this statement.
const POINTER_FENCE_PROOF_LATCH_SQL: &str = "UPDATE authorization_projection_current \
    SET revoke_fence_proven = 1, cas_version = cas_version + 1 \
    WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ? AND card_id <=> ? \
      AND manifest_id = ? AND current_generation = ? AND cas_version = ? \
      AND revoke_fence = ? AND revoke_fence_proven = 0";

/// Bounded probe (index `uk_apm_generation`, `LIMIT 1`) refusing any aggregate
/// whose history carries another `COMMITTED`/`SUPERSEDED`/`READY` generation
/// beside the rehearsed generation one: such history cannot be proven complete
/// from durable rows and is rejected instead of backfilled implicitly.
const MANIFEST_OTHER_COMMITTED_GENERATION_PROBE_SQL: &str = "SELECT generation \
    FROM authorization_projection_manifest \
    WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ? \
      AND status IN ('COMMITTED', 'SUPERSEDED', 'READY') AND generation <> ? LIMIT 1";

/// Rehearse and latch the legacy fence-proof state of ONE unproven current
/// pointer, or verify an idempotent no-op replay. See the section header for
/// the full contract; this function never commits, never touches MQ/Redis and
/// performs no external side effect.
///
/// Failure policy: every refusal happens before the CAS, the audit row and the
/// CAS commit atomically in the caller's transaction, and any zero-row CAS or
/// post-latch divergence raises an explicit error so the caller rolls back —
/// the latch can never exist without its durable audit evidence.
pub async fn rehearse_legacy_fence_proof_in_tx(
    tx: &mut Transaction<'_, MySql>,
    request: &AuthorizationFenceProofRehearsalRequest,
) -> Result<AuthorizationFenceProofRehearsalOutcome, AuthorizationProjectionError> {
    validate_fence_proof_rehearsal_request(request)?;

    // Lock the pointer first: it serializes against publishers/staging for the
    // aggregate and is the authority every later step revalidates against.
    let pointer = lock_current_pointer_in_tx(tx, &request.identity)
        .await?
        .ok_or_else(|| {
            AuthorizationProjectionError::NotReady(
                "code=authorization_projection.fence_proof_pointer_missing".to_owned(),
            )
        })?;

    match decide_fence_proof_rehearsal(request, &pointer)? {
        FenceProofRehearsalDecision::AlreadyProven => {
            // Verified no-op: nothing durable to mutate, so nothing is written
            // and no audit row is appended.
            return Ok(AuthorizationFenceProofRehearsalOutcome {
                pointer,
                latched_now: false,
            });
        }
        FenceProofRehearsalDecision::RehearseLegacyZeroFence => {}
    }

    // Reject multi-generation legacy history instead of inferring lineage:
    // generation-one chains are the only shape provable from durable rows.
    let stray_generation: Option<(i64,)> =
        sqlx::query_as(MANIFEST_OTHER_COMMITTED_GENERATION_PROBE_SQL)
            .bind(request.identity.tenant_id)
            .bind(&request.identity.aggregate_type)
            .bind(request.identity.aggregate_id)
            .bind(bind_u64(
                pointer.current_generation,
                "rehearsal.probe_generation",
            )?)
            .fetch_optional(&mut **tx)
            .await?;
    if let Some((generation,)) = stray_generation {
        let generation = read_counter_i64(generation, "manifest.generation")?;
        return Err(AuthorizationProjectionError::Corrupt(format!(
            "code=authorization_projection.fence_proof_multi_generation_history;generation={generation}"
        )));
    }

    // Re-prove the target manifest under lock, then re-verify the whole
    // segment chain and the manifest digest seal with the shared strict-read
    // helpers (ordinal continuity, identity/provenance agreement, payload
    // digests, segment-local seals).
    let manifest = fetch_manifest_for_update(tx, pointer.manifest_id)
        .await?
        .ok_or_else(|| {
            AuthorizationProjectionError::NotReady(
                "code=authorization_projection.fence_proof_target_manifest_missing".to_owned(),
            )
        })?;
    prove_fence_proof_rehearsal_manifest(&pointer, &manifest)?;
    let (references, segments) =
        load_verified_chain_with_references(tx, &pointer.identity, &manifest).await?;
    let (_, _, manifest_digest) = manifest.decode_hashes()?;
    let recomputed = manifest.recomputed_digest(
        segments
            .iter()
            .map(|snapshot| snapshot.content_digest.as_hex())
            .collect(),
    )?;
    if recomputed != manifest_digest {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.fence_proof_digest_seal_broken".to_owned(),
        ));
    }

    // Durable audit correlation row, SAME transaction, BEFORE the CAS: the
    // latch can never exist without its audit evidence and an audit failure
    // aborts the whole mutation. No external side effect is performed here.
    let audit_detail = serde_json::to_string(&serde_json::json!({
        "code": "authorization_projection.fence_proof_latched",
        "rehearsalOperationId": request.operation_id,
        "operatorId": request.operator_id,
        "tenantId": request.identity.tenant_id,
        "aggregateType": request.identity.aggregate_type,
        "aggregateId": request.identity.aggregate_id,
        "cardId": request.card_id,
        "pointerId": pointer.pointer_id,
        "manifestId": pointer.manifest_id,
        "generation": pointer.current_generation,
        "revokeFence": pointer.revoke_fence,
        "expectedCasVersion": request.expectation.cas_version,
        "semanticHashHex": pointer.semantic_hash.as_hex(),
        "dependencyHashHex": pointer.dependency_hash.as_hex(),
        "compilerVersion": pointer.compiler_version,
        "manifestEventId": pointer.event_id,
        "manifestOperationId": pointer.operation_id,
        "referenceCount": references.len(),
        "totalGrantCount": sum_grant_counts(&segments)?,
    }))
    .map_err(|error| {
        mapping_error(format!(
            "code=authorization_projection.fence_proof_audit_detail_unserializable;error={error}"
        ))
    })?;
    sqlx::query(FENCE_PROOF_AUDIT_INSERT_SQL)
        .bind(request.operator_id)
        .bind(request.card_id)
        .bind("REHEARSE_REVOKE_FENCE_PROOF")
        .bind(&request.reason)
        .bind(&request.operation_id)
        .bind(audit_detail)
        .execute(&mut **tx)
        .await?;

    // Single guarded CAS: only the latch moves, everything else is pinned.
    let latch_update = sqlx::query(POINTER_FENCE_PROOF_LATCH_SQL)
        .bind(request.identity.tenant_id)
        .bind(&request.identity.aggregate_type)
        .bind(request.identity.aggregate_id)
        .bind(request.card_id)
        .bind(pointer.manifest_id)
        .bind(bind_u64(
            pointer.current_generation,
            "rehearsal.current_generation",
        )?)
        .bind(pointer.cas_version)
        .bind(bind_u64(pointer.revoke_fence, "rehearsal.revoke_fence")?)
        .execute(&mut **tx)
        .await?;
    if latch_update.rows_affected() != 1 {
        return Err(AuthorizationProjectionError::CurrentPointerCasConflict(format!(
            "code=authorization_projection.fence_proof_latch_cas_zero_rows;expected_manifest={};expected_generation={};expected_cas={}",
            pointer.manifest_id, pointer.current_generation, pointer.cas_version
        )));
    }

    // Read the authoritative post-state back within the same transaction and
    // prove exactly the latch moved.
    let statement = format!("{SELECT_PREFIX}{POINTER_ROW_COLUMNS}{POINTER_BY_IDENTITY_TAIL}");
    let pointer_after: Option<PointerRawSqlRow> = sqlx::query_as(statement.as_str())
        .bind(request.identity.tenant_id)
        .bind(&request.identity.aggregate_type)
        .bind(request.identity.aggregate_id)
        .fetch_optional(&mut **tx)
        .await?;
    let pointer_record = pointer_after
        .ok_or_else(|| {
            AuthorizationProjectionError::Corrupt(
                "code=authorization_projection.fence_proof_post_latch_pointer_missing".to_owned(),
            )
        })?
        .decode()?;
    let expected_cas = pointer.cas_version.checked_add(1).ok_or_else(|| {
        mapping_error("code=authorization_projection.cas_version_overflow".to_owned())
    })?;
    if !pointer_record.revoke_fence_proven
        || pointer_record.cas_version != expected_cas
        || pointer_record.manifest_id != pointer.manifest_id
        || pointer_record.current_generation != pointer.current_generation
        || pointer_record.revoke_fence != pointer.revoke_fence
        || pointer_record.card_id != pointer.card_id
        || pointer_record.semantic_hash != pointer.semantic_hash
        || pointer_record.dependency_hash != pointer.dependency_hash
        || pointer_record.compiler_version != pointer.compiler_version
        || pointer_record.event_id != pointer.event_id
        || pointer_record.operation_id != pointer.operation_id
    {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.fence_proof_post_latch_diverged".to_owned(),
        ));
    }

    Ok(AuthorizationFenceProofRehearsalOutcome {
        pointer: pointer_record,
        latched_now: true,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Strict published card grant evidence reader (read-only slice)
// ─────────────────────────────────────────────────────────────────────────────
//
// This is the formal read-side prerequisite for `PolicyEngine.evaluate()` when
// the repository capability `requires_published_card_evidence()` is true. It
// does not change policy semantics, does not touch the legacy snapshot/read
// path, and does not integrate CACHE or MQ. It reads EXCLUSIVELY the Rust-owned
// manifest/segment tables created by migration `20260825000002` (as extended by
// `20260827000001`); legacy `permission_rule_snapshot` / `rule_set_snapshot`
// rows, the legacy head/outbox path and every cache fallback are invisible to
// this code by construction.
//
// Guarantees provided to the formal caller:
// 1. One deterministic lock order: all matching `authorization_projection_current`
//    rows for `(tenant_id, card_id)` are locked in a single statement ordered by
//    `(aggregate_type, aggregate_id)`; each aggregate's chain is then verified
//    through [`read_published_authorization_state_in_tx`] inside the SAME
//    transaction. Publishers acquire exactly one current-pointer row plus its
//    chain; the fixed sequences stay acyclic (documented lock order of this
//    module). The strict reader re-locks only rows this reader already holds,
//    which cannot reorder anything within one transaction.
// 2. Fail-closed scope algebra: every grant must be ACTIVE + ALLOW, pass
//    validity at ONE unified UTC now captured per read, and agree with the
//    pointer's tenant/card scope structurally — any disagreement aborts the
//    whole read with an explicit error (never a partially authorized set).
//    Expired / not-yet-valid / revoked grants are simply not ALLOWed and stay
//    visible as excluded records with a typed reason.
// 3. Provenance preservation across aggregates: records carry their source
//    `(aggregate_type, aggregate_id)`; duplicates of one `(grant_id, revision)`
//    tuple may collapse ONLY when byte-for-byte fully equal AND from the same
//    origin — anything else is corrupt state that fails closed. This reader
//    never merges provenance silently and NEVER compares aggregate publication
//    generations against per-grant revisions or ledger targets: generation is
//    carried as descriptive provenance of each manifest only.
//
// Real MySQL integration testing remains a separate gate (not executed here);
// unit tests below cover the pure assembly and SQL shapes without a database.

/// Aggregate types the card evidence reader accepts from
/// `authorization_projection_current`. RuleSet / DIRECT (USER_CARD) /
/// APPROVAL / DELEGATION contributions may all legitimately publish under a
/// card scope; ANY other stored type fails closed instead of being skipped.
pub const PUBLISHED_CARD_AGGREGATE_TYPES: [&str; 4] =
    ["USER_CARD", "RULE_SET", "APPROVAL", "DELEGATION"];

/// Single deterministic lock/read of all card-scoped current pointers.
///
/// The tail locks `(tenant_id = ? AND card_id = ?)` rows and orders them by
/// `(aggregate_type ASC, aggregate_id ASC)` so concurrent readers take the same
/// locks in the same sequence and publishers (one pointer per transaction)
/// can never form a cycle with this read.
const POINTER_ROWS_FOR_TENANT_CARD_LOCKED_TAIL: &str = " FROM authorization_projection_current \
    WHERE tenant_id = ? AND card_id = ? \
    ORDER BY aggregate_type ASC, aggregate_id ASC FOR UPDATE";

/// Defensive fan-out cap: how many published aggregates one card read may
/// compose before refusing with an explicit `NotReady`. Purely operational;
/// never used to skip data.
pub const MAX_PUBLISHED_CARD_AGGREGATES_PER_READ: usize = 4_096;

/// Dedicated typed error bridge for the published-card evidence read path.
///
/// It deliberately does NOT reuse "empty result" semantics anywhere: missing
/// durable state maps to [`AuthorizationEvidenceError::NotReady`], inconsistent
/// durable state maps to [`AuthorizationEvidenceError::Corrupt`], and database
/// transport failures map to [`AuthorizationEvidenceError::Query`] — a DB error
/// is NEVER turned into an empty/equivalent authorization set.
#[derive(Debug, thiserror::Error)]
pub enum AuthorizationEvidenceError {
    /// Durable evidence is absent or not yet usable (`PENDING`/`DENY`).
    #[error("published card evidence not ready: {0}")]
    NotReady(String),
    /// Durable state contradicts itself or the contract (`DENY` + 对账).
    #[error("published card evidence corrupt: {0}")]
    Corrupt(String),
    /// Reader input violated the typed scope contract (never a data fault).
    #[error("published card evidence request rejected: {0}")]
    InvalidRequest(String),
    /// Database transport failure (`PENDING`; unknown, never authorize).
    #[error("database query failed: {0}")]
    Query(#[from] sqlx::Error),
}

impl AuthorizationEvidenceError {
    /// Pure classification bridging onto the shared gate vocabulary so a
    /// future PolicyEngine can map non-`Ready` outcomes uniformly to
    /// `PENDING`/`DENY` without importing database internals.
    pub const fn as_gate_status(&self) -> PublishedEvidenceGateStatus {
        match self {
            Self::NotReady(_) | Self::InvalidRequest(_) | Self::Query(_) => {
                PublishedEvidenceGateStatus::Pending
            }
            Self::Corrupt(_) => PublishedEvidenceGateStatus::Corrupt,
        }
    }
}

/// Convert the strict single-aggregate projection error into the evidence
/// vocabulary. Missing/not-committed state stays `NotReady`; integrity
/// breakage becomes `Corrupt`; everything else the loader reports is treated
/// as `Corrupt`-family (it can only describe unexpected durable shape here).
impl From<AuthorizationProjectionError> for AuthorizationEvidenceError {
    fn from(error: AuthorizationProjectionError) -> Self {
        use AuthorizationProjectionError as ProjectionError;
        match error {
            ProjectionError::NotReady(message) => Self::NotReady(message),
            ProjectionError::Corrupt(message) => Self::Corrupt(message),
            ProjectionError::Query(query) => Self::Query(query),
            ProjectionError::Contract(contract) => Self::Corrupt(format!(
                "code=published_card_evidence.grant_contract_violation;detail={contract}"
            )),
            other => Self::Corrupt(format!(
                "code=published_card_evidence.corrupt_projection_state;detail={other}"
            )),
        }
    }
}

fn evidence_corrupt(code_fragment: &str) -> AuthorizationEvidenceError {
    AuthorizationEvidenceError::Corrupt(format!("code=published_card_evidence.{code_fragment}"))
}

/// Classify one validity window against the unified UTC now. Ordering matters:
/// expiry dominates when both bounds would exclude (windows cannot overlap
/// exclusion because contract validation forbids inverted windows).
fn classify_validity_at(
    window: &ValidityWindow,
    now_unix_seconds: i64,
) -> Option<UnacceptedGrantReason> {
    if let Some(expires_at) = window.expires_at {
        if now_unix_seconds >= expires_at {
            return Some(UnacceptedGrantReason::Expired);
        }
    }
    if let Some(not_before) = window.not_before {
        if not_before > now_unix_seconds {
            return Some(UnacceptedGrantReason::NotYetValid);
        }
    }
    None
}

/// Build one provenance-complete record per stored grant. Ordinals come from
/// the verified reference row whose content digest the segment was sealed
/// against; the caller iterates `(reference, segment)` pairs in ordinal order.
#[allow(clippy::too_many_arguments)]
fn build_verified_record(
    pointer: &AuthorizationCurrentPointerRecord,
    manifest_semantic_hash_hex: &str,
    manifest_dependency_hash_hex: &str,
    compiler_version: &str,
    reference_ordinal: u64,
    position_in_segment: usize,
    stored_grant: &CanonicalGrant,
    unaccepted_reason: Option<UnacceptedGrantReason>,
) -> VerifiedPublishedGrantRecord {
    VerifiedPublishedGrantRecord {
        aggregate_type: pointer.identity.aggregate_type.clone(),
        aggregate_id: pointer.identity.aggregate_id,
        publication_generation: pointer.current_generation,
        revoke_fence: pointer.revoke_fence,
        manifest_id: pointer.manifest_id,
        event_id: pointer.event_id.clone(),
        operation_id: pointer.operation_id.clone(),
        semantic_hash_hex: manifest_semantic_hash_hex.to_owned(),
        dependency_hash_hex: manifest_dependency_hash_hex.to_owned(),
        compiler_version: compiler_version.to_owned(),
        segment_ordinal: reference_ordinal,
        position_in_segment: position_in_segment as u64,
        grant: stored_grant.clone(),
        accepted_into_effective_set: unaccepted_reason.is_none(),
        unaccepted_reason,
    }
}

fn grant_card_verdict(
    scope: &PublishedCardEvidenceScope,
    now_unix_seconds: i64,
    stored_grant: &CanonicalGrant,
) -> Result<Option<UnacceptedGrantReason>, AuthorizationEvidenceError> {
    // Structural integrity first: mismatching tenant/card inside a committed
    // payload proves the segment content was minted outside the claimed scope.
    if stored_grant.tenant.tenant_id != scope.tenant_id {
        return Err(evidence_corrupt(
            "grant_tenant_scope_mismatch_inside_committed_payload",
        ));
    }
    if stored_grant.card_id != scope.card_id {
        return Err(evidence_corrupt(
            "grant_card_scope_mismatch_inside_committed_payload",
        ));
    }
    // Revocation/tombstone semantics: only the explicit ACTIVE state may
    // authorize. Pending/Revoked/Removed/Expired/Archived records never
    // authorize but stay visible for audit counts (kept in `records`, excluded
    // from the effect set with one shared typed reason).
    if stored_grant.state != GrantState::Active {
        return Ok(Some(UnacceptedGrantReason::InactiveState));
    }
    // Time is judged against exactly one unified now per read.
    if let Some(reason) = classify_validity_at(&stored_grant.validity, now_unix_seconds) {
        return Ok(Some(reason));
    }
    // Lens narrowing last: user/domain filters shrink the accepted set without
    // implying corruption. `effect` is statically Allow-only in the contract.
    if let Some(user_filter) = scope.user_filter {
        if stored_grant.user_id != user_filter {
            return Ok(Some(UnacceptedGrantReason::OutOfUserFilter));
        }
    }
    if !scope.domain.matches(stored_grant.tenant.domain_id) {
        return Ok(Some(UnacceptedGrantReason::OutOfDomainFilter));
    }
    Ok(None)
}

/// Deterministic total ordering of verified records across the whole card read:
/// origin aggregate, then publication provenance, then segment payload layout,
/// then grant identity. Equal-tuple records from different origins therefore
/// do NOT merge silently — grouping detects cross-origin splits explicitly.
fn compare_verified_records(
    left: &VerifiedPublishedGrantRecord,
    right: &VerifiedPublishedGrantRecord,
) -> std::cmp::Ordering {
    (
        left.aggregate_type.as_str(),
        left.aggregate_id,
        left.publication_generation,
        left.manifest_id,
        left.segment_ordinal,
        left.position_in_segment,
        left.grant.grant_id,
        left.grant.revision.value(),
    )
        .cmp(&(
            right.aggregate_type.as_str(),
            right.aggregate_id,
            right.publication_generation,
            right.manifest_id,
            right.segment_ordinal,
            right.position_in_segment,
            right.grant.grant_id,
            right.grant.revision.value(),
        ))
}

/// Collapse duplicates ONLY for fully identical, same-origin records; split
/// origins (or unequal bytes) over one `(grant_id, revision)` tuple fail the
/// entire read as corrupt provenance. Returns the surviving vector and the
/// number of collapsed duplicates.
fn deduplicate_verified_records(
    records: Vec<VerifiedPublishedGrantRecord>,
) -> Result<(Vec<VerifiedPublishedGrantRecord>, usize), AuthorizationEvidenceError> {
    use std::collections::BTreeMap;

    let mut groups: BTreeMap<(GrantId, u64), Vec<usize>> = BTreeMap::new();
    for (index, record) in records.iter().enumerate() {
        groups
            .entry((record.grant.grant_id, record.grant.revision.value()))
            .or_default()
            .push(index);
    }

    let mut collapsed_count = 0_usize;
    let mut dropped = vec![false; records.len()];
    for ((grant_id, revision), members) in &groups {
        if members.len() <= 1 {
            continue;
        }
        let first_origin = (
            records[members[0]].aggregate_type.as_str(),
            records[members[0]].aggregate_id,
        );
        for member in &members[1..] {
            let candidate = &records[*member];
            let candidate_origin = (candidate.aggregate_type.as_str(), candidate.aggregate_id);
            // Equal-provenance duplicates may only collapse when the whole
            // semantic surface matches (payload bytes, provenance identities,
            // hashes, compiler, acceptance verdict). Segment layout fields are
            // incidental and ignored. Anything else is conflicting provenance.
            let semantically_equal = candidate.grant == records[members[0]].grant
                && candidate.event_id == records[members[0]].event_id
                && candidate.operation_id == records[members[0]].operation_id
                && candidate.semantic_hash_hex == records[members[0]].semantic_hash_hex
                && candidate.dependency_hash_hex == records[members[0]].dependency_hash_hex
                && candidate.compiler_version == records[members[0]].compiler_version
                && candidate.manifest_id == records[members[0]].manifest_id
                && candidate.publication_generation == records[members[0]].publication_generation
                && candidate.revoke_fence == records[members[0]].revoke_fence
                && candidate.accepted_into_effective_set
                    == records[members[0]].accepted_into_effective_set
                && candidate.unaccepted_reason == records[members[0]].unaccepted_reason;
            if candidate_origin != first_origin || !semantically_equal {
                return Err(evidence_corrupt(&format!(
                    "conflicting_grant_provenance;grant_id={grant_id};revision={revision};origin_a={first_origin:?};origin_b={candidate_origin:?}"
                )));
            }
            dropped[*member] = true;
            collapsed_count += 1;
        }
    }

    let mut surviving = Vec::with_capacity(records.len() - collapsed_count);
    for (index, record) in records.into_iter().enumerate() {
        if !dropped[index] {
            surviving.push(record);
        }
    }
    Ok((surviving, collapsed_count))
}

/// Pure multi-aggregate assembly behind the strict readers (no I/O).
///
/// Input states MUST have been produced by
/// [`read_published_authorization_state_in_tx`] inside the caller's transaction
/// and appear in the locked pointer SELECT order; this function adds the
/// card-scope algebra the single-aggregate loader cannot know about (scope
/// equality between pointer/reference/segment/grant across the merged view).
fn assemble_published_card_evidence(
    scope: &PublishedCardEvidenceScope,
    now_unix_seconds: i64,
    states: &[AuthorizationPublishedState],
) -> Result<PublishedCardAuthorization, AuthorizationEvidenceError> {
    scope.validate().map_err(|contract| {
        AuthorizationEvidenceError::InvalidRequest(format!(
            "code=published_card_evidence.invalid_scope;detail={contract}"
        ))
    })?;
    // Parity guard with the tx reader: a genuinely absent projection must stay
    // an explicit NotReady forever, never a silent Ok(empty).
    if states.is_empty() {
        return Err(AuthorizationEvidenceError::NotReady(
            "code=published_card_evidence.current_pointer_missing".to_owned(),
        ));
    }

    let mut manifests: Vec<PublishedAggregateManifestSummary> = Vec::with_capacity(states.len());
    let mut records: Vec<VerifiedPublishedGrantRecord> = Vec::new();

    for state in states {
        let pointer = &state.pointer;
        let identity = &pointer.identity;
        if !PUBLISHED_CARD_AGGREGATE_TYPES.contains(&identity.aggregate_type.as_str()) {
            return Err(evidence_corrupt(&format!(
                "unknown_aggregate_type;value={}",
                identity.aggregate_type
            )));
        }
        if identity.tenant_id != scope.tenant_id {
            return Err(evidence_corrupt("pointer_tenant_scope_split"));
        }
        // Card-scoped aggregates only: AppUser / card_id=None pointers are out
        // of scope for this reader and can never be fabricated into it.
        if pointer.card_id != Some(scope.card_id) {
            return Err(evidence_corrupt("pointer_card_scope_split"));
        }
        // Chain-level card continuity the generic loader cannot check (it has
        // no outer scope to compare against): references and segments must
        // carry the same card stamp as the pointer/manifest they hang from,
        // and the verified chain pairs must stay aligned by ordinal.
        for reference in &state.references {
            if reference.card_id != pointer.card_id {
                return Err(evidence_corrupt("reference_card_scope_split"));
            }
            if reference.generation != state.generation {
                return Err(evidence_corrupt("reference_generation_split"));
            }
        }
        if state.references.len() != state.segments.len() {
            return Err(evidence_corrupt("reference_segment_pairing_split"));
        }
        let manifest_semantic_hash_hex = state.semantic_hash.as_hex();
        let manifest_dependency_hash_hex = state.dependency_hash.as_hex();
        let walked_before_state = records.len();
        for (reference, segment) in state.references.iter().zip(state.segments.iter()) {
            if segment.card_id != pointer.card_id {
                return Err(evidence_corrupt("segment_card_scope_split"));
            }
            for (position, stored_grant) in segment.grants.iter().enumerate() {
                let unaccepted_reason = grant_card_verdict(scope, now_unix_seconds, stored_grant)?;
                records.push(build_verified_record(
                    pointer,
                    &manifest_semantic_hash_hex,
                    &manifest_dependency_hash_hex,
                    &state.compiler_version,
                    reference.ordinal,
                    position,
                    stored_grant,
                    unaccepted_reason,
                ));
            }
        }
        manifests.push(PublishedAggregateManifestSummary {
            tenant_id: identity.tenant_id,
            card_id: scope.card_id,
            aggregate_type: identity.aggregate_type.clone(),
            aggregate_id: identity.aggregate_id,
            manifest_id: state.manifest_id,
            generation: state.generation,
            source_generation: state.source_generation,
            projected_generation: state.projected_generation,
            revoke_fence: state.revoke_fence,
            cas_version: state.pointer.cas_version,
            semantic_hash_hex: manifest_semantic_hash_hex,
            dependency_hash_hex: manifest_dependency_hash_hex,
            manifest_digest_hex: state.manifest_digest.as_hex(),
            compiler_version: state.compiler_version.clone(),
            event_id: state.event_id.clone(),
            operation_id: state.operation_id.clone(),
            parent_manifest_id: state.parent_manifest_id,
            segment_count: state.segments.len() as u64,
            declared_grant_row_count: state.total_grant_count,
        });
        let walked_for_state = (records.len() - walked_before_state) as u64;
        if walked_for_state != state.total_grant_count {
            // Filters and tombstones keep records in the walk, so a shrunken
            // walk can only mean the sealed totals lied about payload size.
            return Err(evidence_corrupt(
                "walked_record_count_below_declared_segment_rows",
            ));
        }
    }

    let mut sorted_records = records;
    sorted_records.sort_by(compare_verified_records);
    let (deduplicated_records, equivalent_duplicate_collapsed_count) =
        deduplicate_verified_records(sorted_records)?;

    let effective_grants: Vec<CanonicalGrant> = deduplicated_records
        .iter()
        .filter(|record| record.accepted_into_effective_set)
        .map(|record| record.grant.clone())
        .collect();
    let not_in_effective_count = deduplicated_records.len() - effective_grants.len();

    // Defensive deterministic summary order; the tx caller feeds pointers in
    // `(aggregate_type, aggregate_id)` SELECT order already, but the pure
    // assembly stays self-contained regardless of caller arrangement.
    manifests.sort_by(|left, right| {
        (left.aggregate_type.as_str(), left.aggregate_id)
            .cmp(&(right.aggregate_type.as_str(), right.aggregate_id))
    });

    Ok(PublishedCardAuthorization {
        tenant_id: scope.tenant_id,
        card_id: scope.card_id,
        read_unix_seconds: now_unix_seconds,
        gate: PublishedCardAuthorizationGate {
            status: PublishedEvidenceGateStatus::Ready,
            aggregate_manifest_count: manifests.len(),
            verified_record_count: deduplicated_records.len(),
            effective_grant_count: effective_grants.len(),
            not_in_effective_count,
            equivalent_duplicate_collapsed_count,
        },
        manifests,
        records: deduplicated_records,
        effective_grants,
    })
}

/// Card-scoped fence-raising-delta probe (source-freshness gate, NON-LOCKING).
///
/// 语义（2026-09-01 修订，三节点 P3 写风暴实测驱动）：`authorization_delta_event`
/// 行与 source mutation 同事务写入、与 pointer CAS 同事务 `SUCCEEDED`。门只拦
/// **撤权类**未发布 delta——`event_type IN ('REMOVE','REVOKE')`（授权移除/
/// 吊销：旧证据继续放行即 stale-ALLOW），或 delta 自身明确标记
/// `invalidates_published_evidence <> 0`，或 `revoke_fence` 超前于本卡已发布
/// 水位（fence-raising 变更未落地）。行级标记来自 source transaction 的
/// authorization-content 判定，避免同卡不同 grant 的后发事件把收窄 UPDATE
/// 折叠进卡级 watermark。未命中的未发布 delta（ADD/UPDATE 等扩
/// 权或中性变更）不阻塞：缺新授权只造成 ms 级"漏授权"窗口，走既有的
/// deny-biased eventual consistency 语义（发布即收敛）。
///
/// 为什么不能"任何未发布 delta 都阻塞"（初版实现，P3 实测否决）：写突发期
/// 间每个 POST 的权限检查都是一次证据读，前一个写的未发布 delta 会把后一个
/// 写的权限检查打成 PENDING → 403 自饥饿（三节点实测 20s 风暴 2 ops /
/// 16,965 errors + 熔断打开）。
///
/// 为什么非锁定：锁定读（FOR UPDATE）会与 projector 发布事务在 delta 行锁上
/// 互饿——发布需要行锁推进 `SUCCEEDED`，读者持锁会拉长未发布窗口形成正反
/// 馈。非锁定一致性读作为严格 reader 事务的**第一条语句**建立读快照（此前
/// 无任何快照读），可见性到探针瞬间为止；残余的探针-返回间窗口由既有双读
/// 纪律 + ALLOW 前复读（新事务重跑整个协议）覆盖，与指针移动的线性化语义
/// 一致。
///
/// 收窄型 UPDATE 的 stale-ALLOW 窗口（2026-09-04 闭合）：可能移除旧授权的
/// UPDATE（before-image 与新 grant 的 authorization-content 字段比较）在写侧
/// 让 CARD 父投影事件改用 REVOKE 语义抬 fence（trustgraph 三条 UPDATE 链路），
/// 其 delta 携带超前于已发布水位的 `revoke_fence` → 本探针的 fence 超前分支
/// 命中 → 发布前一律 PENDING；纯 provenance-only/no-op UPDATE 不抬 fence，
/// 走既有 deny-biased EC 语义，写突发不得自饥饿（P3 风暴实测教训）。
///
/// 作用域覆盖（2026-09-04 修订）：谓词为 `(card_id = ? OR card_id IS NULL)`，
/// 卡作用域与 aggregate-wide（`NULL` card）的撤权类未发布 delta 都拦截本卡
/// 读取——aggregate-wide 的 REMOVE/REVOKE/fence 抬升同样会让旧代已发布证据
/// 变成 stale-ALLOW。已发布水位子查询用 MySQL NULL-safe 等值（`<=>`）关联：
/// `NULL` card 行对 `NULL` card 已发布水位比较，卡作用域行对同卡已发布水位
/// 比较；若用普通 `=`，`NULL = NULL` 恒为 UNKNOWN 会把水位折叠成 0，使已被
/// 已发布水位覆盖的 aggregate-wide delta 误报 PENDING。
///
/// `idx_ade_card (tenant_id, card_id, target_version)` 支撑点查（`OR card_id
/// IS NULL` 展开为两个索引区间）；`LIMIT 1` 命中即短路。
pub(crate) const FRESHNESS_GATE_PROBE_SQL: &str = "SELECT 1 FROM authorization_delta_event \
    WHERE tenant_id = ? AND (card_id = ? OR card_id IS NULL) \
      AND status <> 'SUCCEEDED' \
      AND (invalidates_published_evidence <> 0 \
           OR event_type IN ('REMOVE', 'REVOKE') \
           OR revoke_fence > COALESCE((SELECT MAX(p.revoke_fence) FROM authorization_delta_event p \
                                       WHERE p.tenant_id = authorization_delta_event.tenant_id \
                                         AND p.card_id <=> authorization_delta_event.card_id \
                                         AND p.status = 'SUCCEEDED'), 0)) \
    LIMIT 1";

/// 卡作用域（含 aggregate-wide `NULL` card delta）是否存在撤权类未发布 delta
/// （非锁定一致性读，作为 reader 事务的第一条语句建立读快照）。
///
/// `true` ⟺ source-freshness gate 未通过：正式读链必须 `NotReady → PENDING`，
/// 绝不以旧代已发布证据放行即将被移除/吊销的授权。`QUARANTINED` 的撤权类
/// delta 同样命中（确定性分歧的变更永不发布，受影响作用域在人工对账前持续
/// PENDING——fail-closed 的正确方向）。aggregate-wide（`NULL` card）的撤权类
/// delta 同样命中：其授权移除对全部卡作用域读取都是 stale-ALLOW 方向。
async fn card_has_unsafe_pending_delta_in_tx(
    tx: &mut Transaction<'_, MySql>,
    tenant_id: i64,
    card_id: i64,
) -> Result<bool, AuthorizationEvidenceError> {
    #[cfg(feature = "e1-observability")]
    {
        let stamp = policy_engine::e1_observation::stamp();
        tracing::info!(
            target: "authz_e1",
            event = "authoritative_read_start",
            observation = "strict_pending_probe",
            request_id = stamp.request_id.as_deref().unwrap_or(""),
            process_observation_id = %stamp.process_observation_id,
            event_sequence = stamp.event_sequence,
            wall_unix_ns = %stamp.wall_unix_ns,
            tenant_id,
            card_id,
            outcome = "started",
            "e1 authorization observation"
        );
    }
    let row_result: Result<Option<(i64,)>, sqlx::Error> = sqlx::query_as(FRESHNESS_GATE_PROBE_SQL)
        .bind(tenant_id)
        .bind(card_id)
        .fetch_optional(&mut **tx)
        .await;
    #[cfg(feature = "e1-observability")]
    {
        let stamp = policy_engine::e1_observation::stamp();
        tracing::info!(
            target: "authz_e1",
            event = "authoritative_read_end",
            observation = "strict_pending_probe",
            request_id = stamp.request_id.as_deref().unwrap_or(""),
            process_observation_id = %stamp.process_observation_id,
            event_sequence = stamp.event_sequence,
            wall_unix_ns = %stamp.wall_unix_ns,
            tenant_id,
            card_id,
            outcome = if row_result.is_ok() { "ok" } else { "error" },
            pending = ?row_result.as_ref().ok().map(Option::is_some),
            "e1 authorization observation"
        );
    }
    Ok(row_result?.is_some())
}

/// Transaction-scoped strict reader: compose EVERY card-scoped published
/// aggregate into one verifiable evidence object.
///
/// Scope rules:
/// - matches ONLY `card_id = Some(card)` pointers; aggregate-wide (`None`)
///   projections belong to other future readers and are invisible to the
///   pointer composition below — BUT the source-freshness gate in this reader
///   DOES see aggregate-wide (`card_id IS NULL`) unpublished revoke-class
///   deltas: their removal/fence-raising makes the published card evidence
///   stale-ALLOW just the same, so the probe predicate is
///   `(card_id = ? OR card_id IS NULL)` (2026-09-04 revision);
/// - unknown stored aggregate types fail the WHOLE read (`Corrupt`), never get
///   skipped;
/// - any aggregate reporting `missing pointer/non-COMMITTED/corrupt chain`
///   propagates immediately — errors are never swallowed to continue with
///   sibling aggregates;
/// - missing current rows entirely yields `NotReady` (never `Ok(empty)`).
///
/// Lock discipline: the fence-raising-delta freshness probe (NON-LOCKING
/// consistent read) runs FIRST, then a single deterministic `SELECT ... ORDER
/// BY aggregate_type ASC, aggregate_id ASC FOR UPDATE` covers all pointer
/// rows; each chain is then read under the module's documented order. Nothing
/// here commits, writes, caches or publishes; callers own the transaction.
pub async fn load_published_card_grant_evidence_in_tx(
    tx: &mut Transaction<'_, MySql>,
    scope: &PublishedCardEvidenceScope,
) -> Result<PublishedCardAuthorization, AuthorizationEvidenceError> {
    scope.validate().map_err(|contract| {
        AuthorizationEvidenceError::InvalidRequest(format!(
            "code=published_card_evidence.invalid_scope;detail={contract}"
        ))
    })?;

    // Source-freshness gate（撤权类越权修复）：存在撤权类未发布 delta
    // （REMOVE/REVOKE 或 fence 超前已发布水位）时，current 指针仍指向旧代
    // manifest；该窗口内放行旧代证据即 stale-ALLOW。此处必须
    // `NotReady → PENDING`。ADD/UPDATE 类未发布 delta 不阻塞（缺新授权只是
    // ms 级漏授权窗口，deny-biased EC 语义）。该门只挂正式证据读入口——
    // projector 的 frontier/发布路径（`read_published_authorization_state_in_tx`
    // / `load_published_aggregate_frontier_in_tx` / `project_authorization_delta_in_tx`）
    // 不得经过本探针，否则发布事务会被自己未完成的 delta 自锁（由源码锚定
    // 守卫测试钉住）。
    if card_has_unsafe_pending_delta_in_tx(tx, scope.tenant_id, scope.card_id).await? {
        return Err(AuthorizationEvidenceError::NotReady(format!(
            "code=published_card_evidence.source_freshness_pending;tenant={};card={}",
            scope.tenant_id, scope.card_id
        )));
    }

    let statement =
        format!("{SELECT_PREFIX}{POINTER_ROW_COLUMNS}{POINTER_ROWS_FOR_TENANT_CARD_LOCKED_TAIL}");
    let raw_rows: Vec<PointerRawSqlRow> = sqlx::query_as(statement.as_str())
        .bind(scope.tenant_id)
        .bind(scope.card_id)
        .fetch_all(&mut **tx)
        .await?;
    if raw_rows.is_empty() {
        return Err(AuthorizationEvidenceError::NotReady(format!(
            "code=published_card_evidence.current_pointer_missing;tenant={};card={}",
            scope.tenant_id, scope.card_id
        )));
    }
    if raw_rows.len() > MAX_PUBLISHED_CARD_AGGREGATES_PER_READ {
        return Err(AuthorizationEvidenceError::NotReady(format!(
            "code=published_card_evidence.too_many_current_pointers;count={};cap={MAX_PUBLISHED_CARD_AGGREGATES_PER_READ}",
            raw_rows.len()
        )));
    }

    let mut pointers = Vec::with_capacity(raw_rows.len());
    for raw in raw_rows {
        pointers.push(raw.decode()?);
    }

    // Unified clock for the whole read: all validity judgments share one UTC
    // instant so no grant can straddle a boundary mid-read.
    let now_unix_seconds = OffsetDateTime::now_utc().unix_timestamp();

    let mut states = Vec::with_capacity(pointers.len());
    for pointer in &pointers {
        let state = read_published_authorization_state_in_tx(tx, &pointer.identity)
            .await
            .map_err(AuthorizationEvidenceError::from)?;
        // The strict reader re-locks the same (already-held) pointer row; the
        // returned record must still be the very row we observed, otherwise a
        // mixed-generation read is assumed and refused.
        if state.pointer != *pointer {
            return Err(evidence_corrupt("pointer_moved_under_read"));
        }
        states.push(state);
    }

    assemble_published_card_evidence(scope, now_unix_seconds, &states)
}

/// Pool-level wrapper for [`load_published_card_grant_evidence_in_tx`].
///
/// Runs the whole verification inside ONE SHORT transaction and commits it
/// explicitly while returning, releasing every `FOR UPDATE` row lock promptly
/// (locks are never held past this call). The commit is part of the contract:
/// skipping it would leak locks until pool idle timeout, so the wrapper treats
/// commit failure like any other infrastructure failure (`Query` ⇒ `Pending`,
/// never a successful authorization set).
pub async fn load_published_card_grant_evidence(
    pool: &MySqlPool,
    scope: &PublishedCardEvidenceScope,
) -> Result<PublishedCardAuthorization, AuthorizationEvidenceError> {
    let mut tx = pool.begin().await?;
    let evidence = load_published_card_grant_evidence_in_tx(&mut tx, scope).await?;
    tx.commit().await?;
    Ok(evidence)
}

// ─────────────────────────────────────────────────────────────────────────────
// Bridge from the pure compiler kernel (explicit conversion boundary)
// ─────────────────────────────────────────────────────────────────────────────

/// Build an ordered staging plan of NEW segments from a compiled HotState.
///
/// The resulting vector's positions are the ordinals. HotState's segment map is
/// a persistent HAMT (O(1) structural-sharing clone) whose iteration is unordered,
/// so this bridge explicitly sorts entries by [`ProjectionKey`] (which implements
/// `Ord`) to derive the same deterministic ordinal order as
/// [`policy_engine::HotState::segment_references`]. Reuse decisions belong to the
/// caller: unchanged segments become `ReuseParent` entries only when the caller
/// compares plans across generations. Every grant passes through contractual
/// canonicalization here. The O(S log S) sort is a publish-transaction-only cost.
pub fn stage_plan_new_segments_from_hot_state(
    state: &policy_engine::HotState,
) -> Result<Vec<StagedSegmentContent>, AuthorizationProjectionError> {
    let mut entries: Vec<_> = state.segments.iter().collect();
    entries.sort_by(|left, right| left.0.cmp(right.0));
    let mut plan = Vec::with_capacity(entries.len());
    for (_key, segment) in entries {
        for grant in &segment.grants {
            grant.canonicalized()?;
        }
        plan.push(StagedSegmentContent::New(
            segment.grants.as_slice().to_vec(),
        ));
    }
    Ok(plan)
}

/// Build the pure reuse-view list required by
/// [`validate_staging_plan_against_parent`] from loaded parent records.
pub fn parent_reference_views(
    records: &[AuthorizationSegmentReferenceRecord],
) -> Vec<(u64, ParentReferenceView)> {
    records
        .iter()
        .map(|record| (record.ordinal, record.as_parent_view()))
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Durable impact plans (`authorization_impact_plan` + `_item`)
// ─────────────────────────────────────────────────────────────────────────────

/// Defensive upper bound for one durable impact plan's item count.
pub const MAX_IMPACT_PLAN_ITEMS: usize = 100_000;
/// Character cap for one stable `projection_key` (`VARCHAR(191)` column).
///
/// Keys longer than this cannot be persisted faithfully; callers must pick a
/// compact canonical form ([`ProjectionKey`]-style canonical input) rather
/// than truncate, since truncation would silently merge distinct keys.
pub const MAX_PROJECTION_KEY_LENGTH: usize = 191;

/// Schema default status of a freshly persisted impact-plan root.
pub const IMPACT_PLAN_STATUS_PENDING: &str = "PENDING";
/// Terminal status set once the plan's generation published durably.
pub const IMPACT_PLAN_STATUS_SUCCEEDED: &str = "SUCCEEDED";

/// Typed impact-plan lifecycle state; unknown stored strings fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationImpactPlanStatus {
    Pending,
    Succeeded,
}

impl AuthorizationImpactPlanStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => IMPACT_PLAN_STATUS_PENDING,
            Self::Succeeded => IMPACT_PLAN_STATUS_SUCCEEDED,
        }
    }

    pub fn parse(value: &str) -> Result<Self, AuthorizationProjectionError> {
        match value {
            IMPACT_PLAN_STATUS_PENDING => Ok(Self::Pending),
            IMPACT_PLAN_STATUS_SUCCEEDED => Ok(Self::Succeeded),
            other => Err(mapping_error(format!(
                "code=authorization_projection.unknown_impact_plan_status;value={other}"
            ))),
        }
    }

    /// Allowed durable edge: `PENDING -> SUCCEEDED`. Self-edges and any move
    /// out of `SUCCEEDED` are refused.
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                AuthorizationImpactPlanStatus::Pending,
                AuthorizationImpactPlanStatus::Succeeded
            )
        )
    }
}

impl fmt::Display for AuthorizationImpactPlanStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Item vocabulary mirroring the compiler's segment outcomes. Unknown stored
/// strings fail closed; there is deliberately no passthrough variant.
pub const IMPACT_ITEM_TYPE_SEGMENT_UPSERT: &str = "SEGMENT_UPSERT";
pub const IMPACT_ITEM_TYPE_SEGMENT_REMOVE: &str = "SEGMENT_REMOVE";

/// Typed durable impact item kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationImpactItemType {
    /// The exact-key segment exists after this generation (added or changed).
    SegmentUpsert,
    /// The exact-key segment existed before and was removed by this
    /// generation.
    SegmentRemove,
}

impl AuthorizationImpactItemType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SegmentUpsert => IMPACT_ITEM_TYPE_SEGMENT_UPSERT,
            Self::SegmentRemove => IMPACT_ITEM_TYPE_SEGMENT_REMOVE,
        }
    }

    pub fn parse(value: &str) -> Result<Self, AuthorizationProjectionError> {
        match value {
            IMPACT_ITEM_TYPE_SEGMENT_UPSERT => Ok(Self::SegmentUpsert),
            IMPACT_ITEM_TYPE_SEGMENT_REMOVE => Ok(Self::SegmentRemove),
            other => Err(mapping_error(format!(
                "code=authorization_projection.unknown_impact_item_type;value={other}"
            ))),
        }
    }
}

/// One caller-supplied impact item (pure input form).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationImpactItemInput {
    /// Stable exact-projection identity; duplicates within one plan collapse
    /// only when every field agrees, otherwise they refuse.
    pub projection_key: String,
    pub item_type: AuthorizationImpactItemType,
    pub grant_id: Option<GrantId>,
    /// Lowercase SHA-256 hex of the base content digest (present when the
    /// segment existed before).
    pub before_digest_hex: Option<String>,
    /// Lowercase SHA-256 hex of the candidate content digest.
    pub after_digest_hex: Option<String>,
}

/// Normalized, deduplicated, deterministically ordered item exactly as the
/// writer persists it. Ordering is ascending `projection_key` byte order;
/// ordinal positions are derived from this vector because the schema carries
/// no ordinal column (`uk_aipi_plan_key` makes keys unique per plan).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedImpactItem {
    pub projection_key: String,
    pub item_type: AuthorizationImpactItemType,
    pub grant_id: Option<GrantId>,
    pub before_digest: Option<Sha256Digest>,
    pub after_digest: Option<Sha256Digest>,
}

fn validate_projection_key_text(value: &str) -> Result<(), AuthorizationProjectionError> {
    if value.is_empty()
        || value.chars().count() > MAX_PROJECTION_KEY_LENGTH
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(scope_violation(&format!(
            "authorization_projection.invalid_projection_key;max_length={MAX_PROJECTION_KEY_LENGTH}"
        )));
    }
    Ok(())
}

/// Normalize item inputs: validate texts/digests, enforce digest pairing per
/// item kind, collapse identical duplicate keys and reject divergent ones.
///
/// Pairing rules (mirroring compiler evidence):
/// - [`AuthorizationImpactItemType::SegmentUpsert`] requires an
///   `after_digest`; `before_digest` is optional (absent = fresh segment);
/// - [`AuthorizationImpactItemType::SegmentRemove`] requires a
///   `before_digest` and forbids an `after_digest`.
pub fn normalize_impact_items(
    items: &[AuthorizationImpactItemInput],
) -> Result<Vec<NormalizedImpactItem>, AuthorizationProjectionError> {
    if items.len() > MAX_IMPACT_PLAN_ITEMS {
        return Err(scope_violation(
            "authorization_projection.too_many_impact_items",
        ));
    }
    if items.is_empty() {
        return Err(scope_violation(
            "authorization_projection.empty_impact_plan",
        ));
    }
    let mut normalized: std::collections::BTreeMap<String, NormalizedImpactItem> =
        std::collections::BTreeMap::new();
    for item in items {
        validate_projection_key_text(&item.projection_key)?;
        let before = match &item.before_digest_hex {
            Some(hex) => Some(Sha256Digest::from_hex(hex)?),
            None => None,
        };
        let after = match &item.after_digest_hex {
            Some(hex) => Some(Sha256Digest::from_hex(hex)?),
            None => None,
        };
        let normalized_item = match item.item_type {
            AuthorizationImpactItemType::SegmentUpsert => {
                if after.is_none() {
                    return Err(scope_violation(
                        "authorization_projection.upsert_requires_after_digest",
                    ));
                }
                NormalizedImpactItem {
                    projection_key: item.projection_key.clone(),
                    item_type: item.item_type,
                    grant_id: item.grant_id,
                    before_digest: before,
                    after_digest: after,
                }
            }
            AuthorizationImpactItemType::SegmentRemove => {
                if after.is_some() || before.is_none() {
                    return Err(scope_violation(
                        "authorization_projection.remove_digest_pairing",
                    ));
                }
                NormalizedImpactItem {
                    projection_key: item.projection_key.clone(),
                    item_type: item.item_type,
                    grant_id: item.grant_id,
                    before_digest: before,
                    after_digest: None,
                }
            }
        };
        if let Some(existing) = normalized.get(&item.projection_key) {
            if *existing != normalized_item {
                return Err(scope_violation(
                    "authorization_projection.impact_item_key_conflict",
                ));
            }
            continue;
        }
        normalized.insert(item.projection_key.clone(), normalized_item);
    }
    Ok(normalized.into_values().collect())
}

/// Fully validated append/resume input for one generation's impact plan.
#[derive(Debug, Clone)]
pub struct AuthorizationImpactPlanAppendRequest {
    pub identity: ProjectionAggregateIdentity,
    /// Card scope carried into every written row (`None` = aggregate-wide);
    /// must agree with the pointer/manifest chain being built.
    pub card_id: Option<i64>,
    pub event_id: String,
    pub operation_id: String,
    /// Generation this plan builds upon; the very first publication chains
    /// from 0.
    pub base_generation: u64,
    /// Target generation; MUST be exactly `base_generation + 1`.
    pub target_generation: u64,
    /// Per-grant projection version the processed delta chained from.
    pub base_version: i64,
    /// Per-grant projection version the processed delta advanced to.
    pub target_version: i64,
    pub semantic_hash_hex: String,
    pub dependency_hash_hex: String,
    pub compiler_version: String,
    pub items: Vec<AuthorizationImpactItemInput>,
}

/// Evidence returned by [`ensure_authorization_impact_plan_in_tx`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationImpactPlanOutcome {
    pub plan_id: i64,
    /// True when a prior attempt already committed the same immutable plan
    /// and this call verified (and completed) the item set instead.
    pub resumed_existing_plan: bool,
    /// Number of durable items now attached to the plan.
    pub item_count: u64,
}

const IMPACT_PLAN_ROW_COLUMNS: &str = "plan_id, tenant_id, card_id, aggregate_type, \
    aggregate_id, event_id, operation_id, base_generation, target_generation, base_version, \
    target_version, semantic_hash, dependency_hash, compiler_version, status, attempts, \
    cas_version";

const IMPACT_PLAN_BY_EVENT_TAIL: &str =
    " FROM authorization_impact_plan WHERE event_id = ? FOR UPDATE";

const IMPACT_PLAN_BY_TARGET_GENERATION_TAIL: &str = " FROM authorization_impact_plan \
    WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ? AND target_generation = ? \
    FOR UPDATE";

const IMPACT_PLAN_INSERT_SQL: &str = "INSERT INTO authorization_impact_plan \
    (tenant_id, card_id, aggregate_type, aggregate_id, event_id, operation_id, \
     base_generation, target_generation, base_version, target_version, semantic_hash, \
     dependency_hash, compiler_version, status) \
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING')";

const IMPACT_ITEM_ROW_COLUMNS: &str = "item_id, plan_id, tenant_id, card_id, aggregate_type, \
    aggregate_id, event_id, operation_id, projection_key, item_type, grant_id, base_version, \
    target_version, before_digest, after_digest, dependency_hash, status";

const IMPACT_ITEMS_BY_PLAN_TAIL: &str = " FROM authorization_impact_plan_item \
    WHERE plan_id = ? ORDER BY projection_key ASC FOR UPDATE";

const IMPACT_ITEM_BY_PLAN_KEY_TAIL: &str = " FROM authorization_impact_plan_item \
    WHERE plan_id = ? AND projection_key = ? FOR UPDATE";

const IMPACT_ITEM_INSERT_SQL: &str = "INSERT INTO authorization_impact_plan_item \
    (plan_id, tenant_id, card_id, aggregate_type, aggregate_id, event_id, operation_id, \
     projection_key, item_type, grant_id, base_version, target_version, before_digest, \
     after_digest, dependency_hash, status) \
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING')";

/// Items stay `PENDING` while this slice exposes no item mutation; any other
/// stored value is poisoned storage and fails closed instead of guessing.
const IMPACT_ITEM_STATUS_PENDING: &str = "PENDING";

const IMPACT_ITEM_COUNT_SQL: &str =
    "SELECT COUNT(*) FROM authorization_impact_plan_item WHERE plan_id = ?";

/// Completion stays guarded to the aggregate/event identity and the `PENDING`
/// state so replayed publishes can never rewrite terminal history.
const IMPACT_PLAN_COMPLETE_SQL: &str = "UPDATE authorization_impact_plan \
    SET status = 'SUCCEEDED', last_error = NULL \
    WHERE plan_id = ? AND event_id = ? AND tenant_id = ? AND aggregate_type = ? \
      AND aggregate_id = ? AND status = 'PENDING'";

#[derive(Debug, sqlx::FromRow)]
struct ImpactPlanRawSqlRow {
    plan_id: i64,
    tenant_id: i64,
    card_id: Option<i64>,
    aggregate_type: String,
    aggregate_id: i64,
    event_id: String,
    operation_id: String,
    base_generation: i64,
    target_generation: i64,
    base_version: i64,
    target_version: i64,
    semantic_hash: Vec<u8>,
    dependency_hash: Vec<u8>,
    compiler_version: String,
    status: String,
    attempts: i64,
    cas_version: i64,
}

#[derive(Debug, sqlx::FromRow)]
struct ImpactItemRawSqlRow {
    item_id: i64,
    plan_id: i64,
    tenant_id: i64,
    card_id: Option<i64>,
    aggregate_type: String,
    aggregate_id: i64,
    event_id: String,
    operation_id: String,
    projection_key: String,
    item_type: String,
    grant_id: Option<String>,
    base_version: i64,
    target_version: i64,
    before_digest: Option<Vec<u8>>,
    after_digest: Option<Vec<u8>>,
    dependency_hash: Vec<u8>,
    status: String,
}

/// Strictly decoded durable impact item; ordinals are derived positions in
/// the sorted parent vector (no ordinal column exists).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationImpactItemRecord {
    pub item_id: i64,
    pub projection_key: String,
    pub item_type: AuthorizationImpactItemType,
    pub grant_id: Option<GrantId>,
    pub before_digest: Option<Sha256Digest>,
    pub after_digest: Option<Sha256Digest>,
}

/// Strictly decoded durable impact plan including its complete, order-verified
/// item list. Never produced partially: any inconsistency aborts the read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationImpactPlanRecord {
    pub plan_id: i64,
    pub identity: ProjectionAggregateIdentity,
    pub card_id: Option<i64>,
    pub event_id: String,
    pub operation_id: String,
    pub base_generation: u64,
    pub target_generation: u64,
    pub base_version: i64,
    pub target_version: i64,
    pub semantic_hash: Sha256Digest,
    pub dependency_hash: Sha256Digest,
    pub compiler_version: String,
    pub status: AuthorizationImpactPlanStatus,
    pub attempts: i64,
    pub cas_version: i64,
    pub items: Vec<AuthorizationImpactItemRecord>,
}

impl ImpactItemRawSqlRow {
    fn decode_against(
        &self,
        root: &ImpactRootLink<'_>,
    ) -> Result<AuthorizationImpactItemRecord, AuthorizationProjectionError> {
        if self.plan_id <= 0 || self.item_id <= 0 {
            return Err(mapping_error(
                "code=authorization_projection.negative_impact_item_ids".to_owned(),
            ));
        }
        // Inherited denormalized columns must reproduce the parent root
        // exactly; drift means someone wrote outside this module's contract.
        ProjectionAggregateIdentity::new(
            self.tenant_id,
            self.aggregate_type.clone(),
            self.aggregate_id,
        )
        .and_then(|inherited| {
            if inherited != *root.identity || self.plan_id != root.plan_id {
                Err(AuthorizationProjectionError::IdentityMismatch(
                    "code=authorization_projection.impact_item_identity_mismatch".to_owned(),
                ))
            } else {
                Ok(())
            }
        })?;
        if self.card_id != root.card_id
            || self.event_id != root.event_id
            || self.operation_id != root.operation_id
            || self.base_version != root.base_version
            || self.target_version != root.target_version
        {
            return Err(AuthorizationProjectionError::IdentityMismatch(
                "code=authorization_projection.impact_item_root_link_mismatch".to_owned(),
            ));
        }
        if self.dependency_hash.as_slice() != root.dependency_hash.as_bytes() {
            return Err(AuthorizationProjectionError::Corrupt(
                "code=authorization_projection.impact_item_dependency_mismatch".to_owned(),
            ));
        }
        if self.status != IMPACT_ITEM_STATUS_PENDING {
            return Err(AuthorizationProjectionError::NotReady(format!(
                "code=authorization_projection.impact_item_status_unexpected;status={}",
                self.status
            )));
        }
        validate_projection_key_text(&self.projection_key)?;
        let grant_id = match &self.grant_id {
            None => None,
            // Canonical CHAR(36) enforcement is shared with the grant
            // repository: uppercase/braced/binary spellings are poison.
            Some(text) => Some(crate::grant_repository::decode_grant_id_sql(text)?),
        };
        Ok(AuthorizationImpactItemRecord {
            item_id: self.item_id,
            projection_key: self.projection_key.clone(),
            item_type: AuthorizationImpactItemType::parse(&self.item_type)?,
            grant_id,
            before_digest: Sha256Digest::from_optional_bytes(self.before_digest.as_deref())?,
            after_digest: Sha256Digest::from_optional_bytes(self.after_digest.as_deref())?,
        })
    }
}

impl ImpactPlanRawSqlRow {
    /// Strict common decode of the plan root shared by the writer's resume
    /// proof and the recovery reader. Identity/version gates enforced here.
    #[allow(clippy::type_complexity)]
    fn decode_core(
        &self,
    ) -> Result<
        (
            ProjectionAggregateIdentity,
            (u64, u64, i64, i64, Sha256Digest, Sha256Digest),
        ),
        AuthorizationProjectionError,
    > {
        positive_i64(self.plan_id, "plan_id")?;
        validated_option_card_id(self.card_id)?;
        let identity = ProjectionAggregateIdentity::new(
            self.tenant_id,
            self.aggregate_type.clone(),
            self.aggregate_id,
        )?;
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
        if self.attempts < 0 || self.cas_version < 0 {
            return Err(mapping_error(
                "code=authorization_projection.negative_impact_plan_counters".to_owned(),
            ));
        }
        if self.base_version < 0 || self.target_version < 0 {
            return Err(mapping_error(
                "code=authorization_projection.negative_impact_plan_version".to_owned(),
            ));
        }
        if self.target_version <= self.base_version {
            return Err(mapping_error(
                "code=authorization_projection.non_advancing_impact_plan_version".to_owned(),
            ));
        }
        let base_generation = read_counter_i64(self.base_generation, "plan.base_generation")?;
        let target_generation = read_counter_i64(self.target_generation, "plan.target_generation")?;
        if target_generation == 0 || target_generation.checked_sub(base_generation) != Some(1) {
            return Err(mapping_error(
                "code=authorization_projection.non_adjacent_impact_plan_generations".to_owned(),
            ));
        }
        Ok((
            identity,
            (
                base_generation,
                target_generation,
                self.base_version,
                self.target_version,
                Sha256Digest::from_bytes(self.semantic_hash.clone())?,
                Sha256Digest::from_bytes(self.dependency_hash.clone())?,
            ),
        ))
    }

    fn parse_status(&self) -> Result<AuthorizationImpactPlanStatus, AuthorizationProjectionError> {
        AuthorizationImpactPlanStatus::parse(&self.status)
    }

    /// Verify every immutable field against a replayed request; ANY divergence
    /// (including foreign-event occupation provenance surfacing here) refuses
    /// instead of resuming.
    fn assert_equivalent_replay(
        &self,
        expected: &ImpactReplayExpectation<'_>,
    ) -> Result<(), AuthorizationProjectionError> {
        let (
            identity,
            (
                row_base_gen,
                row_target_gen,
                row_base_ver,
                row_target_ver,
                row_semantic,
                row_dependency,
            ),
        ) = self.decode_core()?;
        let mismatch =
            |code: &str| AuthorizationProjectionError::ImmutableConflict(code.to_owned());
        if identity != *expected.identity {
            return Err(mismatch(
                "code=authorization_projection.impact_plan_replay_identity",
            ));
        }
        if self.card_id != expected.card_id {
            return Err(mismatch(
                "code=authorization_projection.impact_plan_replay_card_scope",
            ));
        }
        if self.event_id != expected.event_id {
            return Err(mismatch(
                "code=authorization_projection.impact_plan_replay_event",
            ));
        }
        if self.operation_id != expected.operation_id {
            return Err(mismatch(
                "code=authorization_projection.impact_plan_replay_operation",
            ));
        }
        if row_base_gen != expected.base_generation || row_target_gen != expected.target_generation
        {
            return Err(mismatch(
                "code=authorization_projection.impact_plan_replay_generation",
            ));
        }
        if row_base_ver != expected.base_version || row_target_ver != expected.target_version {
            return Err(mismatch(
                "code=authorization_projection.impact_plan_replay_version",
            ));
        }
        if row_semantic != *expected.semantic_hash || row_dependency != *expected.dependency_hash {
            return Err(mismatch(
                "code=authorization_projection.impact_plan_replay_hash",
            ));
        }
        if self.compiler_version != expected.compiler_version {
            return Err(mismatch(
                "code=authorization_projection.impact_plan_replay_compiler",
            ));
        }
        Ok(())
    }
}

async fn fetch_impact_plan_by_event(
    tx: &mut Transaction<'_, MySql>,
    event_id: &str,
) -> Result<Option<ImpactPlanRawSqlRow>, AuthorizationProjectionError> {
    let statement = format!("SELECT {IMPACT_PLAN_ROW_COLUMNS}{IMPACT_PLAN_BY_EVENT_TAIL}");
    sqlx::query_as(statement.as_str())
        .bind(event_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AuthorizationProjectionError::from)
}

async fn fetch_impact_plan_by_target_generation(
    tx: &mut Transaction<'_, MySql>,
    identity: &ProjectionAggregateIdentity,
    target_generation: u64,
) -> Result<Option<ImpactPlanRawSqlRow>, AuthorizationProjectionError> {
    let statement =
        format!("SELECT {IMPACT_PLAN_ROW_COLUMNS}{IMPACT_PLAN_BY_TARGET_GENERATION_TAIL}");
    sqlx::query_as(statement.as_str())
        .bind(identity.tenant_id)
        .bind(&identity.aggregate_type)
        .bind(identity.aggregate_id)
        .bind(bind_u64(target_generation, "plan.target_generation")?)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AuthorizationProjectionError::from)
}

/// Every denormalized column an item row inherits from its plan root.
struct ImpactRootLink<'a> {
    plan_id: i64,
    identity: &'a ProjectionAggregateIdentity,
    card_id: Option<i64>,
    event_id: &'a str,
    operation_id: &'a str,
    base_version: i64,
    target_version: i64,
    dependency_hash: &'a Sha256Digest,
}

/// The immutable plan-root fields a replayed request must reproduce exactly.
struct ImpactReplayExpectation<'a> {
    identity: &'a ProjectionAggregateIdentity,
    card_id: Option<i64>,
    event_id: &'a str,
    operation_id: &'a str,
    base_generation: u64,
    target_generation: u64,
    base_version: i64,
    target_version: i64,
    semantic_hash: &'a Sha256Digest,
    dependency_hash: &'a Sha256Digest,
    compiler_version: &'a str,
}

impl<'a> ImpactReplayExpectation<'a> {
    /// Derive the replay expectation from the current append request plus the
    /// already-parsed digest values.
    fn of(
        request: &'a AuthorizationImpactPlanAppendRequest,
        semantic_hash: &'a Sha256Digest,
        dependency_hash: &'a Sha256Digest,
    ) -> Self {
        Self {
            identity: &request.identity,
            card_id: request.card_id,
            event_id: &request.event_id,
            operation_id: &request.operation_id,
            base_generation: request.base_generation,
            target_generation: request.target_generation,
            base_version: request.base_version,
            target_version: request.target_version,
            semantic_hash,
            dependency_hash,
            compiler_version: &request.compiler_version,
        }
    }
}

/// Insert-or-verify one item row under `(plan_id, projection_key)`; a losing
/// unique race must prove byte-for-byte equivalence before it may be treated
/// as an idempotent skip (append-only: items are never rewritten or deleted).
async fn ensure_impact_item_row_in_tx(
    tx: &mut Transaction<'_, MySql>,
    root: &ImpactRootLink<'_>,
    item: &NormalizedImpactItem,
) -> Result<(), AuthorizationProjectionError> {
    let attempted_insert = sqlx::query(IMPACT_ITEM_INSERT_SQL)
        .bind(root.plan_id)
        .bind(root.identity.tenant_id)
        .bind(root.card_id)
        .bind(&root.identity.aggregate_type)
        .bind(root.identity.aggregate_id)
        .bind(root.event_id)
        .bind(root.operation_id)
        .bind(&item.projection_key)
        .bind(item.item_type.as_str())
        .bind(item.grant_id.map(|grant_id| grant_id.as_str().to_owned()))
        .bind(root.base_version)
        .bind(root.target_version)
        .bind(item.before_digest.map(|digest| digest.as_bytes().to_vec()))
        .bind(item.after_digest.map(|digest| digest.as_bytes().to_vec()))
        .bind(root.dependency_hash.as_bytes().to_vec())
        .execute(&mut **tx)
        .await;
    match attempted_insert {
        Ok(result) => {
            if result.rows_affected() != 1 {
                return Err(AuthorizationProjectionError::DuplicateRow(
                    "code=authorization_projection.impact_item_insert_not_applied".to_owned(),
                ));
            }
            Ok(())
        }
        Err(error) => {
            if !unique_violation(&error) {
                return Err(error.into());
            }
            let statement =
                format!("SELECT {IMPACT_ITEM_ROW_COLUMNS}{IMPACT_ITEM_BY_PLAN_KEY_TAIL}");
            let existing: Option<ImpactItemRawSqlRow> = sqlx::query_as(statement.as_str())
                .bind(root.plan_id)
                .bind(&item.projection_key)
                .fetch_optional(&mut **tx)
                .await?;
            let Some(existing) = existing else {
                return Err(AuthorizationProjectionError::DuplicateRow(
                    "code=authorization_projection.impact_item_race_unknown_winner".to_owned(),
                ));
            };
            let winner = existing.decode_against(root)?;
            let equivalent = winner.projection_key == item.projection_key
                && winner.item_type == item.item_type
                && winner.grant_id == item.grant_id
                && winner.before_digest == item.before_digest
                && winner.after_digest == item.after_digest;
            if !equivalent {
                return Err(AuthorizationProjectionError::ImmutableConflict(
                    "code=authorization_projection.impact_item_replay_conflict".to_owned(),
                ));
            }
            Ok(())
        }
    }
}

/// Persist (or idempotently resume) one durable impact plan inside the
/// caller's transaction.
///
/// Rules:
/// - the plan root is immutable once committed; a replay wins only when EVERY
///   immutable field agrees, otherwise
///   [`AuthorizationProjectionError::ImmutableConflict`] is raised (never an
///   `ON DUPLICATE KEY` swallow);
/// - each item row is inserted or proven byte-identical via
///   `uk_aipi_plan_key`;
/// - the final item COUNT must equal the request's item count exactly, so any
///   foreign/extra row under the same plan fails closed;
/// - generations must be adjacent (`target == base + 1`) matching the staged
///   manifest chain, versions follow the delta convention
///   (`0 <= base < target`), and at least one item is required.
///
/// Neither commit nor lock release happens here; callers own the transaction.
pub async fn ensure_authorization_impact_plan_in_tx(
    tx: &mut Transaction<'_, MySql>,
    request: &AuthorizationImpactPlanAppendRequest,
) -> Result<AuthorizationImpactPlanOutcome, AuthorizationProjectionError> {
    request.identity.validate()?;
    validated_option_card_id(request.card_id)?;
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
    if request.base_version < 0 || request.target_version <= request.base_version {
        return Err(scope_violation(
            "authorization_projection.invalid_impact_plan_versions",
        ));
    }
    if request.target_generation == 0
        || bind_u64(request.target_generation, "plan.target_generation").is_err()
    {
        return Err(scope_violation(
            "authorization_projection.invalid_impact_plan_target_generation",
        ));
    }
    if request
        .target_generation
        .saturating_sub(request.base_generation)
        != 1
    {
        return Err(scope_violation(
            "authorization_projection.non_adjacent_impact_plan_generations",
        ));
    }
    let semantic_hash = Sha256Digest::from_hex(&request.semantic_hash_hex)?;
    let dependency_hash = Sha256Digest::from_hex(&request.dependency_hash_hex)?;
    let items = normalize_impact_items(&request.items)?;

    // (1) Resolve the root row through either unique key; the target-
    // generation slot decides whether the generation itself is contested.
    let existing_by_event = fetch_impact_plan_by_event(tx, &request.event_id).await?;
    let existing = match existing_by_event {
        Some(existing) => Some(existing),
        None => {
            fetch_impact_plan_by_target_generation(tx, &request.identity, request.target_generation)
                .await?
        }
    };

    let (plan_id, resumed): (i64, bool) = match existing {
        Some(existing) => {
            existing.assert_equivalent_replay(&ImpactReplayExpectation::of(
                request,
                &semantic_hash,
                &dependency_hash,
            ))?;
            (existing.plan_id, true)
        }
        None => {
            let inserted = sqlx::query(IMPACT_PLAN_INSERT_SQL)
                .bind(request.identity.tenant_id)
                .bind(request.card_id)
                .bind(&request.identity.aggregate_type)
                .bind(request.identity.aggregate_id)
                .bind(&request.event_id)
                .bind(&request.operation_id)
                .bind(bind_u64(request.base_generation, "plan.base_generation")?)
                .bind(bind_u64(
                    request.target_generation,
                    "plan.target_generation",
                )?)
                .bind(request.base_version)
                .bind(request.target_version)
                .bind(semantic_hash.as_bytes().to_vec())
                .bind(dependency_hash.as_bytes().to_vec())
                .bind(&request.compiler_version)
                .execute(&mut **tx)
                .await;
            match inserted {
                Ok(result) => {
                    if result.rows_affected() != 1 {
                        return Err(AuthorizationProjectionError::DuplicateRow(
                            "code=authorization_projection.impact_plan_insert_not_applied"
                                .to_owned(),
                        ));
                    }
                    (
                        i64::try_from(result.last_insert_id()).map_err(|_| {
                            mapping_error(
                                "code=authorization_projection.bigint_overflow;field=plan_id"
                                    .to_owned(),
                            )
                        })?,
                        false,
                    )
                }
                Err(error) => {
                    if !unique_violation(&error) {
                        return Err(error.into());
                    }
                    // A concurrent/replayed winner owns one of the two unique
                    // keys. Re-read under BOTH keys and demand full immutable
                    // equivalence before resuming; anything else is an
                    // explicit conflict.
                    let winner_by_event = fetch_impact_plan_by_event(tx, &request.event_id).await?;
                    if let Some(winner) = winner_by_event {
                        winner.assert_equivalent_replay(&ImpactReplayExpectation::of(
                            request,
                            &semantic_hash,
                            &dependency_hash,
                        ))?;
                        (winner.plan_id, true)
                    } else {
                        let winner_by_generation = fetch_impact_plan_by_target_generation(
                            tx,
                            &request.identity,
                            request.target_generation,
                        )
                        .await?;
                        return Err(match winner_by_generation {
                            Some(foreign) => AuthorizationProjectionError::ImmutableConflict(
                                format!(
                                    "code=authorization_projection.impact_plan_generation_occupied;event={}",
                                    foreign.event_id
                                ),
                            ),
                            None => AuthorizationProjectionError::DuplicateRow(
                                "code=authorization_projection.impact_plan_race_unknown_winner"
                                    .to_owned(),
                            ),
                        });
                    }
                }
            }
        }
    };

    // (2) Write every item; proven-equivalent winners skip (idempotent retry),
    // divergent winners raise ImmutableConflict before anything else changes.
    let root = ImpactRootLink {
        plan_id,
        identity: &request.identity,
        card_id: request.card_id,
        event_id: &request.event_id,
        operation_id: &request.operation_id,
        base_version: request.base_version,
        target_version: request.target_version,
        dependency_hash: &dependency_hash,
    };
    for item in &items {
        ensure_impact_item_row_in_tx(tx, &root, item).await?;
    }

    // (3) Completeness: exactly the requested item set must exist now.
    let (stored_count,): (i64,) = sqlx::query_as(IMPACT_ITEM_COUNT_SQL)
        .bind(plan_id)
        .fetch_one(&mut **tx)
        .await?;
    if stored_count < 0 || stored_count > MAX_IMPACT_PLAN_ITEMS as i64 {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.impact_item_count_overflow".to_owned(),
        ));
    }
    if stored_count as usize != items.len() {
        return Err(AuthorizationProjectionError::ImmutableConflict(format!(
            "code=authorization_projection.impact_item_set_drift;stored={stored_count};requested={}",
            items.len()
        )));
    }

    Ok(AuthorizationImpactPlanOutcome {
        plan_id,
        resumed_existing_plan: resumed,
        item_count: items.len() as u64,
    })
}

/// Load one impact plan with its complete, strictly verified item list.
///
/// Verification covers: identity/generation adjacency, hash decodability,
/// status vocabulary, per-item root linkage (tenant/card/type/id/event/
/// operation/versions/dependency), item ordering by `projection_key`, key
/// uniqueness and total completeness. Partial plans are never returned.
pub async fn load_authorization_impact_plan_by_event_in_tx(
    tx: &mut Transaction<'_, MySql>,
    identity: &ProjectionAggregateIdentity,
    event_id: &str,
) -> Result<Option<AuthorizationImpactPlanRecord>, AuthorizationProjectionError> {
    identity.validate()?;
    validated_text(event_id, MAX_EVENT_ID_LENGTH, "event_id")?;
    let Some(raw) = fetch_impact_plan_by_event(tx, event_id).await? else {
        return Ok(None);
    };
    let (
        decoded_identity,
        (
            base_generation,
            target_generation,
            base_version,
            target_version,
            semantic_hash,
            dependency_hash,
        ),
    ) = raw.decode_core()?;
    if decoded_identity != *identity {
        return Err(AuthorizationProjectionError::IdentityMismatch(
            "code=authorization_projection.impact_plan_identity_mismatch".to_owned(),
        ));
    }
    if raw.event_id != event_id {
        return Err(mapping_error(
            "code=authorization_projection.impact_plan_event_slot_drift".to_owned(),
        ));
    }
    let status = raw.parse_status()?;
    let root_dependency = dependency_hash;
    let root_link = ImpactRootLink {
        plan_id: raw.plan_id,
        identity: &decoded_identity,
        card_id: raw.card_id,
        event_id: &raw.event_id,
        operation_id: &raw.operation_id,
        base_version,
        target_version,
        dependency_hash: &root_dependency,
    };

    let statement = format!("SELECT {IMPACT_ITEM_ROW_COLUMNS}{IMPACT_ITEMS_BY_PLAN_TAIL}");
    let rows: Vec<ImpactItemRawSqlRow> = sqlx::query_as(statement.as_str())
        .bind(raw.plan_id)
        .fetch_all(&mut **tx)
        .await?;
    if rows.len() > MAX_IMPACT_PLAN_ITEMS {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.impact_item_count_overflow".to_owned(),
        ));
    }
    if rows.is_empty() {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.impact_plan_without_items".to_owned(),
        ));
    }

    let mut items: Vec<AuthorizationImpactItemRecord> = Vec::with_capacity(rows.len());
    let mut previous_key: Option<String> = None;
    for row in &rows {
        let record = row.decode_against(&root_link)?;
        if let Some(previous) = &previous_key {
            if *previous == record.projection_key {
                return Err(AuthorizationProjectionError::Corrupt(
                    "code=authorization_projection.duplicate_impact_item_key".to_owned(),
                ));
            }
        }
        previous_key = Some(record.projection_key.clone());
        items.push(record);
    }

    Ok(Some(AuthorizationImpactPlanRecord {
        plan_id: raw.plan_id,
        identity: decoded_identity,
        card_id: raw.card_id,
        event_id: raw.event_id,
        operation_id: raw.operation_id,
        base_generation,
        target_generation,
        base_version,
        target_version,
        semantic_hash,
        dependency_hash,
        compiler_version: raw.compiler_version,
        status,
        attempts: raw.attempts,
        cas_version: raw.cas_version,
        items,
    }))
}

/// Move one fully published plan from `PENDING` to `SUCCEEDED`.
///
/// Guarded by plan/event/aggregate identity; `affected_rows != 1` (already
/// completed, foreign state or unknown plan) fails closed so an anomalous
/// history surfaces instead of silently de-duplicating worker results.
pub async fn complete_authorization_impact_plan_in_tx(
    tx: &mut Transaction<'_, MySql>,
    plan_id: i64,
    identity: &ProjectionAggregateIdentity,
    event_id: &str,
) -> Result<(), AuthorizationProjectionError> {
    positive_i64(plan_id, "plan_id")?;
    identity.validate()?;
    validated_text(event_id, MAX_EVENT_ID_LENGTH, "event_id")?;
    let updated = sqlx::query(IMPACT_PLAN_COMPLETE_SQL)
        .bind(plan_id)
        .bind(event_id)
        .bind(identity.tenant_id)
        .bind(&identity.aggregate_type)
        .bind(identity.aggregate_id)
        .execute(&mut **tx)
        .await?;
    if updated.rows_affected() != 1 {
        return Err(mapping_error(
            "code=authorization_projection.impact_plan_complete_not_applied".to_owned(),
        ));
    }
    Ok(())
}

/// Build an impact-plan append request from the pure compiler output.
///
/// Mapping notes (schema-driven, nothing invented):
/// - unchanged segments (`content_changed == false`) produce NO durable item;
///   the plan-root hashes seal the compile outcome instead;
/// - stable compiler segment-id strings have no schema column; durability and
///   ordering come from `projection_key`, so they are intentionally dropped;
/// - `projection_key` uses the compiler's canonical input form and must fit
///   [`MAX_PROJECTION_KEY_LENGTH`] characters;
/// - before/after content hashes enter through the SHA-256 codec (the
///   compiler emits lowercase hex digests; anything else fails here);
/// - grant ids are absent from [`policy_engine::SegmentImpact`] by contract,
///   so durable items carry NULL `grant_id`.
#[allow(clippy::too_many_arguments)]
pub fn impact_plan_request_from_compiler_plan(
    identity: ProjectionAggregateIdentity,
    card_id: Option<i64>,
    event_id: impl Into<String>,
    operation_id: impl Into<String>,
    base_generation: u64,
    target_generation: u64,
    base_version: i64,
    target_version: i64,
    semantic_hash_hex: impl Into<String>,
    dependency_hash_hex: impl Into<String>,
    compiler_version: impl Into<String>,
    compiler_plan: &policy_engine::ImpactPlan,
) -> Result<AuthorizationImpactPlanAppendRequest, AuthorizationProjectionError> {
    let mut items = Vec::with_capacity(compiler_plan.affected_segments.len());
    for segment in &compiler_plan.affected_segments {
        if !segment.content_changed {
            continue;
        }
        let projection_key = segment.key.canonical_input().map_err(|error| {
            mapping_error(format!(
                "code=authorization_projection.projection_key_canonicalization;error={error}"
            ))
        })?;
        let before = segment.before_content_hash.as_ref();
        let after = segment.after_content_hash.as_ref();
        let (item_type, before_hex, after_hex) = match (before, after) {
            (_, Some(after)) => (
                AuthorizationImpactItemType::SegmentUpsert,
                before.map(|hex| hex.as_str()),
                Some(after.as_str()),
            ),
            (Some(before), None) => (
                AuthorizationImpactItemType::SegmentRemove,
                Some(before.as_str()),
                None,
            ),
            (None, None) => {
                return Err(mapping_error(
                    "code=authorization_projection.impact_item_without_content_evidence".to_owned(),
                ))
            }
        };
        items.push(AuthorizationImpactItemInput {
            projection_key,
            item_type,
            grant_id: None,
            before_digest_hex: before_hex.map(|hex| hex.to_owned()),
            after_digest_hex: after_hex.map(|hex| hex.to_owned()),
        });
    }
    Ok(AuthorizationImpactPlanAppendRequest {
        identity,
        card_id,
        event_id: event_id.into(),
        operation_id: operation_id.into(),
        base_generation,
        target_generation,
        base_version,
        target_version,
        // Hash trio comes from the COMPILE OUTPUT (CompiledProjection /
        // HotState), never from the plan alone: ImpactPlan carries no hashes
        // and inventing them here would break the manifest linkage check.
        semantic_hash_hex: semantic_hash_hex.into(),
        dependency_hash_hex: dependency_hash_hex.into(),
        compiler_version: compiler_version.into(),
        items,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Delta-to-manifest publish linkage (pure DTOs and validators)
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal snapshot of one claimed delta relevant to publish linkage. Built
/// explicitly from a claimed row ([`DeltaEventClaim`] or
/// [`ClaimedDeltaEvent`]) so neither concrete type leaks into staging/publish
/// code paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationDeltaLinkageView {
    pub identity: ProjectionAggregateIdentity,
    pub card_id: Option<i64>,
    pub event_id: String,
    pub operation_id: String,
    pub base_version: i64,
    pub target_version: i64,
    pub source_generation: u64,
    pub revoke_fence: u64,
    pub semantic_hash: Sha256Digest,
    pub dependency_hash: Sha256Digest,
    pub compiler_version: String,
}

impl AuthorizationDeltaLinkageView {
    pub fn from_claim(claim: &DeltaEventClaim) -> Result<Self, AuthorizationProjectionError> {
        Ok(Self {
            identity: ProjectionAggregateIdentity::new(
                claim.tenant_id,
                claim.aggregate_type.clone(),
                claim.aggregate_id,
            )?,
            card_id: claim.card_id,
            event_id: claim.event_id.clone(),
            operation_id: claim.operation_id.clone(),
            base_version: claim.base_version,
            target_version: claim.target_version,
            source_generation: claim.source_generation,
            revoke_fence: claim.revoke_fence,
            semantic_hash: claim.semantic_hash,
            dependency_hash: claim.dependency_hash,
            compiler_version: claim.compiler_version.clone(),
        })
    }

    pub fn from_claimed_row(row: &ClaimedDeltaEvent) -> Result<Self, AuthorizationProjectionError> {
        Ok(Self {
            identity: ProjectionAggregateIdentity::new(
                row.tenant_id,
                row.aggregate_type.clone(),
                row.aggregate_id,
            )?,
            card_id: row.card_id,
            event_id: row.event_id.clone(),
            operation_id: row.operation_id.clone(),
            base_version: row.base_version,
            target_version: row.target_version,
            source_generation: row.source_generation,
            revoke_fence: row.revoke_fence,
            semantic_hash: row.semantic_hash,
            dependency_hash: row.dependency_hash,
            compiler_version: row.compiler_version.clone(),
        })
    }
}

/// Everything the projected publish expects the claimed delta to be. Field
/// values typically equal the freshly compiled candidate output so one check
/// pins the delta, the compile and the manifest chain together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaProjectorExpectation {
    pub identity: ProjectionAggregateIdentity,
    /// Card scope the worker believes it processes (`None` = aggregate-wide);
    /// must equal the claimed row's scope exactly.
    pub card_id: Option<i64>,
    pub event_id: String,
    pub operation_id: String,
    pub base_version: i64,
    pub target_version: i64,
    pub source_generation: u64,
    pub semantic_hash_hex: String,
    pub dependency_hash_hex: String,
    pub compiler_version: String,
}

/// Compile-mode consistency evidence for one publication.
///
/// `FULL_REBUILD` mode demands an explicit fallback reason; incremental or
/// replay modes forbid one. This keeps reason/mode drift observable even
/// though no durable column stores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompileModeEvidence {
    pub compile_mode: ProjectionCompileMode,
    pub full_rebuild_reason: Option<policy_engine::FullRebuildReason>,
}

pub fn validate_compile_mode_evidence(
    mode: &CompileModeEvidence,
) -> Result<(), AuthorizationProjectionError> {
    let has_reason = mode.full_rebuild_reason.is_some();
    match mode.compile_mode {
        ProjectionCompileMode::FullRebuild if has_reason => Ok(()),
        ProjectionCompileMode::FullRebuild => Err(scope_violation(
            "authorization_projection.full_rebuild_requires_reason",
        )),
        _ if has_reason => Err(scope_violation(
            "authorization_projection.reason_without_full_rebuild",
        )),
        _ => Ok(()),
    }
}

/// Cross-validate one claimed delta against the candidate it is about to
/// publish (pure).
///
/// Enforced agreement: tenant/aggregate identity, card scope, event and
/// operation ids, per-grant base/target versions (`0 <= base < target`),
/// source generation, semantic/dependency hashes and compiler version.
/// Revoke-fence evidence is MANDATORY paired data
/// ([`PublishRevokeFenceEvidence`]): monotonicity
/// ([`validate_publish_fence_continuity`]) is enforced and the new fence must
/// never regress below the claimed row's stored fence. Compile-mode/reason
/// consistency is verified last. Any mismatch aborts with a distinct explicit
/// code; nothing is defaulted.
pub fn validate_delta_projector_linkage(
    delta_view: &AuthorizationDeltaLinkageView,
    expectation: &DeltaProjectorExpectation,
    fences: PublishRevokeFenceEvidence,
    mode: &CompileModeEvidence,
) -> Result<(), AuthorizationProjectionError> {
    if delta_view.identity != expectation.identity {
        return Err(AuthorizationProjectionError::IdentityMismatch(
            "code=authorization_projection.linkage_identity_mismatch".to_owned(),
        ));
    }
    if delta_view.card_id != expectation.card_id {
        return Err(AuthorizationProjectionError::IdentityMismatch(
            "code=authorization_projection.linkage_card_scope_mismatch".to_owned(),
        ));
    }
    if delta_view.event_id != expectation.event_id {
        return Err(scope_violation(
            "authorization_projection.linkage_event_mismatch",
        ));
    }
    if delta_view.operation_id != expectation.operation_id {
        return Err(scope_violation(
            "authorization_projection.linkage_operation_mismatch",
        ));
    }
    if delta_view.base_version != expectation.base_version
        || delta_view.target_version != expectation.target_version
    {
        return Err(scope_violation(
            "authorization_projection.linkage_version_mismatch",
        ));
    }
    if expectation.base_version < 0 || expectation.target_version <= expectation.base_version {
        return Err(scope_violation(
            "authorization_projection.linkage_invalid_versions",
        ));
    }
    if delta_view.source_generation != expectation.source_generation {
        return Err(scope_violation(
            "authorization_projection.linkage_source_generation_mismatch",
        ));
    }
    let expected_semantic = Sha256Digest::from_hex(&expectation.semantic_hash_hex)?;
    let expected_dependency = Sha256Digest::from_hex(&expectation.dependency_hash_hex)?;
    if delta_view.semantic_hash != expected_semantic {
        return Err(AuthorizationProjectionError::ManifestPublishConflict(
            "code=authorization_projection.linkage_semantic_mismatch".to_owned(),
        ));
    }
    if delta_view.dependency_hash != expected_dependency {
        return Err(AuthorizationProjectionError::ManifestPublishConflict(
            "code=authorization_projection.linkage_dependency_mismatch".to_owned(),
        ));
    }
    if delta_view.compiler_version != expectation.compiler_version {
        return Err(AuthorizationProjectionError::ManifestPublishConflict(
            "code=authorization_projection.linkage_compiler_mismatch".to_owned(),
        ));
    }
    validate_publish_fence_continuity(fences.previous_revoke_fence, fences.new_revoke_fence)?;
    if fences.new_revoke_fence < delta_view.revoke_fence {
        return Err(AuthorizationProjectionError::ManifestPublishConflict(
            format!(
                "code=authorization_projection.fence_below_claimed_delta;delta={};publish={}",
                delta_view.revoke_fence, fences.new_revoke_fence
            ),
        ));
    }
    validate_compile_mode_evidence(mode)?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Published aggregate frontier planning
// ─────────────────────────────────────────────────────────────────────────────

/// Defensive upper bound for one aggregate's published-frontier depth.
///
/// Planning reads stop fail-closed here instead of issuing an unbounded plan
/// scan; a larger honest history requires raising this constant deliberately.
pub const MAX_PUBLISHED_FRONTIER_GENERATIONS: usize = 100_000;
/// Upper bound for rows scanned while probing the extra-SUCCEEDED conflict.
const MAX_EXTRA_SUCCEEDED_FRONTIER_SCAN: i64 = 32;

/// Summary of one generation's manifest-level proof used by frontier
/// assembly and parent-reference views.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedGenerationSummary {
    pub manifest_id: i64,
    /// Aggregate generation (`G`). NEVER comparable to per-grant delta
    /// versions directly; [`PublishedAggregateFrontier::events`] connects the
    /// two domains.
    pub generation: u64,
    pub source_generation: u64,
    pub projected_generation: u64,
    pub event_id: String,
    pub operation_id: String,
    pub semantic_hash: Sha256Digest,
    pub dependency_hash: Sha256Digest,
    pub compiler_version: String,
    pub manifest_digest: Sha256Digest,
    /// Durable lineage (`None` = first generation).
    pub parent_manifest_id: Option<i64>,
    /// Authoritative revoke fence of this generation (manifest row value,
    /// which the strict read proved equal to the live pointer's fence).
    pub revoke_fence: u64,
    /// Card scope of the manifest row; the strict read proves equality with
    /// the pointer's scope, so this always mirrors the pointer's card here.
    pub card_id: Option<i64>,
}

/// Durable impact-plan slice consumed by pure frontier assembly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontierPlanEvidence {
    pub plan_id: i64,
    pub event_id: String,
    pub operation_id: String,
    pub card_id: Option<i64>,
    pub base_generation: u64,
    pub target_generation: u64,
    /// Per-grant projection version the processed delta chained FROM.
    pub base_version: i64,
    /// Per-grant projection version the processed delta advanced TO.
    pub target_version: i64,
    pub semantic_hash: Sha256Digest,
    pub dependency_hash: Sha256Digest,
    pub compiler_version: String,
    pub status: AuthorizationImpactPlanStatus,
}

/// Durable delta-row slice consumed by pure frontier assembly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontierDeltaEvidence {
    pub delta_event_id: i64,
    pub event_id: String,
    pub operation_id: String,
    pub event_type: DeltaEventType,
    pub card_id: Option<i64>,
    pub tenant_id: i64,
    pub aggregate_type: String,
    pub aggregate_id: i64,
    pub grant_id: GrantId,
    pub base_version: i64,
    pub target_version: i64,
    pub source_generation: u64,
    pub revoke_fence: u64,
    pub semantic_hash: Sha256Digest,
    pub dependency_hash: Sha256Digest,
    pub compiler_version: String,
    /// Raw status string; assembly accepts only [`DELTA_STATUS_SUCCEEDED`].
    pub status_str: String,
}

/// One proven event of the published frontier, connecting an aggregate
/// generation to its single-grant delta (`delta.target_version` = per-grant
/// revision, never the aggregate generation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedFrontierEvent {
    /// Aggregate generation proving this event (1..=G, contiguous).
    pub generation: u64,
    pub plan_id: i64,
    pub event_id: String,
    pub operation_id: String,
    pub grant_id: GrantId,
    pub event_type: DeltaEventType,
    pub delta_base_version: i64,
    pub delta_target_version: i64,
    pub source_generation: u64,
    pub revoke_fence: u64,
    pub semantic_hash: Sha256Digest,
    pub dependency_hash: Sha256Digest,
    pub compiler_version: String,
}

/// The strictly verified continuous published frontier of one aggregate:
/// generations 1..=G exactly, where G is the locked current pointer's
/// generation. Every event survived plan ⇆ delta ⇆ manifest ⇆ pointer
/// agreement checks; nothing behind it may authorize anything else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedAggregateFrontier {
    pub identity: ProjectionAggregateIdentity,
    /// Card scope shared by pointer, manifest chain, plans and deltas.
    pub card_id: Option<i64>,
    pub pointer: AuthorizationCurrentPointerRecord,
    pub manifest: PublishedGenerationSummary,
    /// Ascending by generation, one event per generation, no gaps.
    pub events: Vec<PublishedFrontierEvent>,
}

impl PublishedAggregateFrontier {
    /// Map an event id to its proving generation (`event_id → generation`
    /// mapping needed by ledger reconstruction); linear over ≤G entries.
    pub fn frontier_generation(&self, event_id: &str) -> Option<u64> {
        self.events
            .iter()
            .find(|event| event.event_id == event_id)
            .map(|event| event.generation)
    }
}

/// An out-of-range SUCCEEDED plan that contradicts the current pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraSucceededImpactPlan {
    pub plan_id: i64,
    pub event_id: String,
    pub target_generation: u64,
}

/// Pure assembly + validation of the published frontier from strictly loaded
/// durable slices (no DB, fully unit-testable).
///
/// Enforced authority conditions (fail closed):
/// 1. Pointer/manifest agreement was already proven by the strict read; the
///    summary must still carry `generation == pointer.current_generation` and
///    a positive one, plus matching card scopes.
/// 2. Plans enumerate EXACTLY the target generations 1..=G: no missing
///    generation, no duplicate, none beyond G, each `status == SUCCEEDED`,
///    `base_generation == target - 1`, scope/card equal to the pointer's
///    scope, syntactically valid per-grant versions and decodable hashes.
/// 3. Every plan maps to exactly one delta event through its unique
///    `event_id`; every supplied delta maps back to a plan. Deltas must be
///    `SUCCEEDED`, share the aggregate identity (tenant/type/id AND card),
///    agree with their plan on operation id, per-grant base/target versions
///    and global semantic/dependency hashes + compiler, carry a canonical
///    `grant_id`, positive source generation and satisfy the revoke-fence
///    relation.
/// 4. Generation G additionally ties plan/delta/manifest/pointer together:
///    same event id, operation id, hashes and compiler version; manifest
///    `source_generation == delta.source_generation`; manifest fence never
///    below the claimed delta's fence (raising only narrows authorization);
///    manifest/pointer card scopes equal.
/// 5. Same-grant chaining across generations: a repeated `grant_id` continues
///    exactly at the previous frontier target (`base == previous target`) and
///    `(grant_id, target_version)` pairs stay unique; per-grant aggregate
///    generations ascend as a consequence of unique pairs + loop order.
/// 6. Any extra SUCCEEDED plan beyond G is an immutable-history conflict and
///    aborts with its identifying rows; ignored non-succeeded future work
///    stays legal staging residue (unpublished never enters the frontier).
///
/// Pure validators run WITHOUT any database; the transactional loader feeds
/// freshly FOR UPDATE-loaded slices into this function, and every consumer
/// must re-enter a stage/publish transaction that re-verifies everything
/// again inside its own guarded statements before any durable change.
pub fn assemble_published_aggregate_frontier(
    identity: &ProjectionAggregateIdentity,
    pointer: &AuthorizationCurrentPointerRecord,
    manifest: &PublishedGenerationSummary,
    plan_evidence: &[FrontierPlanEvidence],
    delta_evidence_by_event: &std::collections::BTreeMap<String, FrontierDeltaEvidence>,
    extra_succeeded_beyond_current: &[ExtraSucceededImpactPlan],
) -> Result<PublishedAggregateFrontier, AuthorizationProjectionError> {
    // ── (1) pointer / manifest core agreement ────────────────────────────────
    if pointer.identity != *identity || manifest.generation != pointer.current_generation {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.frontier_pointer_summary_split".to_owned(),
        ));
    }
    if pointer.card_id != manifest.card_id {
        return Err(AuthorizationProjectionError::IdentityMismatch(
            "code=authorization_projection.frontier_manifest_card_split".to_owned(),
        ));
    }

    if !extra_succeeded_beyond_current.is_empty() {
        let rendered = extra_succeeded_beyond_current
            .iter()
            .take(MAX_EXTRA_SUCCEEDED_FRONTIER_SCAN.max(1) as usize)
            .map(|row| format!("{}@{}", row.event_id, row.target_generation))
            .collect::<Vec<_>>()
            .join(",");
        return Err(AuthorizationProjectionError::ImmutableConflict(format!(
            "code=authorization_projection.frontier_extra_succeeded_plan;count={};rows=[{rendered}]",
            extra_succeeded_beyond_current.len()
        )));
    }

    // ── (2) exact contiguous plan coverage 1..=G ────────────────────────────
    let frontier_generation = pointer.current_generation;
    if frontier_generation == 0 {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.frontier_zero_generation".to_owned(),
        ));
    }
    let expected_count = usize::try_from(frontier_generation).map_err(|_| {
        mapping_error("code=authorization_projection.frontier_generation_overflow".to_owned())
    })?;
    if plan_evidence.len() > expected_count {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.frontier_plan_duplicate_rows".to_owned(),
        ));
    }

    let mut assembled: Vec<PublishedFrontierEvent> = Vec::with_capacity(expected_count);
    // grant_id -> (generation, last proven per-grant target version)
    let mut last_event_target_by_grant: std::collections::BTreeMap<GrantId, (u64, i64)> =
        std::collections::BTreeMap::new();
    let mut seen_grant_targets: std::collections::HashSet<(GrantId, i64)> =
        std::collections::HashSet::new();

    for (position, plan) in plan_evidence.iter().enumerate() {
        let expected_generation = position as u64 + 1;
        if plan.status != AuthorizationImpactPlanStatus::Succeeded {
            return Err(AuthorizationProjectionError::NotReady(format!(
                "code=authorization_projection.frontier_plan_not_succeeded;generation={expected_generation};status={}",
                plan.status.as_str()
            )));
        }
        if plan.base_generation != expected_generation.saturating_sub(1)
            || plan.target_generation != expected_generation
        {
            return Err(mapping_error(format!(
                "code=authorization_projection.frontier_generation_gap;expected={expected_generation};base={};target={}",
                plan.base_generation, plan.target_generation
            )));
        }
        if plan.card_id != pointer.card_id {
            return Err(AuthorizationProjectionError::IdentityMismatch(format!(
                "code=authorization_projection.frontier_plan_card_mismatch;generation={expected_generation}"
            )));
        }
        if plan.event_id.is_empty()
            || plan.operation_id.is_empty()
            || plan.compiler_version.is_empty()
        {
            return Err(mapping_error(format!(
                "code=authorization_projection.frontier_plan_identity_invalid;generation={expected_generation}"
            )));
        }
        if plan.base_version < 0 || plan.target_version <= plan.base_version {
            return Err(scope_violation(
                "authorization_projection.frontier_plan_invalid_versions",
            ));
        }
        let delta = matched_evidence_for_plan(delta_evidence_by_event, plan, position)?;

        // ── (3) plan ⇆ delta durable identity ───────────────────────────────
        if delta.tenant_id != identity.tenant_id
            || delta.aggregate_type != identity.aggregate_type
            || delta.aggregate_id != identity.aggregate_id
            || delta.card_id != pointer.card_id
        {
            return Err(AuthorizationProjectionError::IdentityMismatch(format!(
                "code=authorization_projection.frontier_delta_scope_mismatch;event={}",
                delta.event_id
            )));
        }
        if delta.status_str != DELTA_STATUS_SUCCEEDED {
            return Err(AuthorizationProjectionError::NotReady(format!(
                "code=authorization_projection.frontier_delta_not_succeeded;event={};status={}",
                delta.event_id, delta.status_str
            )));
        }
        if delta.operation_id != plan.operation_id
            || delta.base_version != plan.base_version
            || delta.target_version != plan.target_version
            || delta.semantic_hash != plan.semantic_hash
            || delta.dependency_hash != plan.dependency_hash
            || delta.compiler_version != plan.compiler_version
        {
            return Err(AuthorizationProjectionError::ImmutableConflict(format!(
                "code=authorization_projection.frontier_plan_delta_linkage_drift;event={}",
                plan.event_id
            )));
        }
        if !seen_grant_targets.insert((delta.grant_id, delta.target_version)) {
            return Err(AuthorizationProjectionError::Corrupt(format!(
                "code=authorization_projection.frontier_duplicate_grant_version;grant={};target={}",
                delta.grant_id, delta.target_version
            )));
        }
        crate::grant_repository::validate_delta_fence_relation(
            delta.source_generation,
            delta.revoke_fence,
        )
        .map_err(|error| mapping_error(error.to_string()))?;

        // ── (5) same-grant chaining across generations ──────────────────────
        if let Some(&(previous_generation, previous_target)) =
            last_event_target_by_grant.get(&delta.grant_id)
        {
            if delta.base_version != previous_target {
                return Err(AuthorizationProjectionError::Corrupt(format!(
                    "code=authorization_projection.frontier_same_grant_chain_gap;grant={};expected_base={previous_target};actual={}",
                    delta.grant_id, delta.base_version
                )));
            }
            if previous_generation > position as u64 {
                return Err(AuthorizationProjectionError::Corrupt(
                    "code=authorization_projection.frontier_same_grant_generation_regression"
                        .to_owned(),
                ));
            }
        }
        last_event_target_by_grant
            .insert(delta.grant_id, (position as u64 + 1, delta.target_version));

        assembled.push(PublishedFrontierEvent {
            generation: expected_generation,
            plan_id: plan.plan_id,
            event_id: plan.event_id.clone(),
            operation_id: plan.operation_id.clone(),
            grant_id: delta.grant_id,
            event_type: delta.event_type,
            delta_base_version: delta.base_version,
            delta_target_version: delta.target_version,
            source_generation: delta.source_generation,
            revoke_fence: delta.revoke_fence,
            semantic_hash: delta.semantic_hash,
            dependency_hash: delta.dependency_hash,
            compiler_version: delta.compiler_version.clone(),
        });
    }
    if assembled.len() != expected_count {
        return Err(AuthorizationProjectionError::Corrupt(format!(
            "code=authorization_projection.frontier_missing_generation;loaded={};expected={expected_count}",
            assembled.len()
        )));
    }
    // Completeness is bidirectional: one unique delta row per plan already
    // holds, so a surplus/unmatched delta slice proves caller-fed junk and
    // fails closed instead of being ignored.
    if delta_evidence_by_event.len() != plan_evidence.len() {
        return Err(AuthorizationProjectionError::Corrupt(format!(
            "code=authorization_projection.frontier_surplus_delta_evidence;deltas={};plans={}",
            delta_evidence_by_event.len(),
            plan_evidence.len()
        )));
    }

    // ── (4) generation-G plan/delta/manifest/pointer tie ────────────────────
    let latest = assembled.last().expect("non-empty after coverage check");
    if manifest.event_id != latest.event_id
        || pointer.event_id != latest.event_id
        || manifest.operation_id != latest.operation_id
        || pointer.operation_id != latest.operation_id
        || manifest.semantic_hash != latest.semantic_hash
        || pointer.semantic_hash != latest.semantic_hash
        || manifest.dependency_hash != latest.dependency_hash
        || pointer.dependency_hash != latest.dependency_hash
        || manifest.compiler_version != latest.compiler_version
        || pointer.compiler_version != latest.compiler_version
    {
        return Err(AuthorizationProjectionError::ManifestPublishConflict(
            "code=authorization_projection.frontier_latest_pointer_tie_break".to_owned(),
        ));
    }
    if manifest.revoke_fence < latest.revoke_fence {
        return Err(AuthorizationProjectionError::ManifestPublishConflict(
            format!(
            "code=authorization_projection.frontier_fence_below_claimed_delta;manifest={};delta={}",
            manifest.revoke_fence, latest.revoke_fence
        ),
        ));
    }
    if manifest.source_generation != latest.source_generation {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.frontier_source_generation_drift".to_owned(),
        ));
    }

    Ok(PublishedAggregateFrontier {
        identity: identity.clone(),
        card_id: pointer.card_id,
        pointer: pointer.clone(),
        manifest: manifest.clone(),
        events: assembled,
    })
}

/// Locate the single matching delta evidence for one plan so failure codes
/// stay identical between unit tests and the transactional loader.
fn matched_evidence_for_plan<'e>(
    delta_evidence_by_event: &'e std::collections::BTreeMap<String, FrontierDeltaEvidence>,
    plan: &FrontierPlanEvidence,
    position: usize,
) -> Result<&'e FrontierDeltaEvidence, AuthorizationProjectionError> {
    delta_evidence_by_event.get(&plan.event_id).ok_or_else(|| {
        mapping_error(format!(
            "code=authorization_projection.frontier_delta_missing;generation={};event={}",
            position + 1,
            plan.event_id
        ))
    })
}

const FRONTIER_PLAN_COLUMNS: &str = "plan_id, tenant_id, card_id, aggregate_type, \
    aggregate_id, event_id, operation_id, base_generation, target_generation, \
    base_version, target_version, semantic_hash, dependency_hash, compiler_version, status";

/// Locked ordered plan scan for one aggregate scope. Bind contract: the
/// inclusive `target_generation <= ?` upper bound receives exactly `G`, so
/// future (`> G`) PENDING/LEASED/QUARANTINED staging plans stay legal residue
/// outside the frontier slice; the trailing `LIMIT ?` receives `G + 1` purely
/// as a duplicate/overrun defense, so a returned row count above `G` is an
/// explicit overflow, never a silent truncation or future-generation
/// inclusion. Every bind is a `?` parameter; no identifiers are composed.
const FRONTIER_PLANS_BY_SCOPE_TAIL: &str =
    " FROM authorization_impact_plan WHERE tenant_id = ? AND aggregate_type = ? \
     AND aggregate_id = ? AND target_generation <= ? ORDER BY target_generation ASC \
     LIMIT ? FOR UPDATE";

#[derive(Debug, sqlx::FromRow)]
struct FrontierPlanRawRow {
    plan_id: i64,
    tenant_id: i64,
    card_id: Option<i64>,
    aggregate_type: String,
    aggregate_id: i64,
    event_id: String,
    operation_id: String,
    base_generation: i64,
    target_generation: i64,
    base_version: i64,
    target_version: i64,
    semantic_hash: Vec<u8>,
    dependency_hash: Vec<u8>,
    compiler_version: String,
    status: String,
}

impl FrontierPlanRawRow {
    fn decode(
        self,
        identity: &ProjectionAggregateIdentity,
    ) -> Result<FrontierPlanEvidence, AuthorizationProjectionError> {
        if self.plan_id <= 0 {
            return Err(mapping_error(
                "code=authorization_projection.frontier_plan_invalid_ids".to_owned(),
            ));
        }
        positive_i64(self.tenant_id, "frontier.plan.tenant_id")?;
        positive_i64(self.aggregate_id, "frontier.plan.aggregate_id")?;
        if let Some(card_id) = self.card_id {
            positive_i64(card_id, "frontier.plan.card_id")?;
        }
        validated_aggregate_type(&self.aggregate_type)?;
        let inherited = ProjectionAggregateIdentity::new(
            self.tenant_id,
            self.aggregate_type.clone(),
            self.aggregate_id,
        )?;
        if inherited != *identity {
            return Err(AuthorizationProjectionError::IdentityMismatch(
                "code=authorization_projection.frontier_plan_identity_mismatch".to_owned(),
            ));
        }
        validated_text(
            &self.event_id,
            MAX_EVENT_ID_LENGTH,
            "frontier.plan.event_id",
        )?;
        validated_text(
            &self.operation_id,
            MAX_GRANT_OPERATION_ID_LENGTH,
            "frontier.plan.operation_id",
        )?;
        validated_text(
            &self.compiler_version,
            MAX_COMPILER_VERSION_LENGTH,
            "frontier.plan.compiler_version",
        )?;
        Ok(FrontierPlanEvidence {
            plan_id: self.plan_id,
            event_id: self.event_id,
            operation_id: self.operation_id,
            card_id: self.card_id,
            base_generation: read_counter_i64(
                self.base_generation,
                "frontier.plan.base_generation",
            )?,
            target_generation: read_counter_i64(
                self.target_generation,
                "frontier.plan.target_generation",
            )?,
            base_version: self.base_version,
            target_version: self.target_version,
            semantic_hash: Sha256Digest::from_bytes(self.semantic_hash)?,
            dependency_hash: Sha256Digest::from_bytes(self.dependency_hash)?,
            compiler_version: self.compiler_version,
            status: AuthorizationImpactPlanStatus::parse(&self.status)?,
        })
    }
}

const FRONTIER_DELTA_COLUMNS: &str = "delta_event_id, event_id, operation_id, event_type, \
    tenant_id, card_id, aggregate_type, aggregate_id, grant_id, base_version, \
    target_version, source_generation, revoke_fence, semantic_hash, dependency_hash, \
    compiler_version, status";

const FRONTIER_DELTA_BY_EVENT_TAIL: &str = " FROM authorization_delta_event \
    WHERE event_id = ? FOR UPDATE";

#[derive(Debug, sqlx::FromRow)]
struct FrontierDeltaRawRow {
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
    semantic_hash: Vec<u8>,
    dependency_hash: Vec<u8>,
    compiler_version: String,
    status: String,
}

impl FrontierDeltaRawRow {
    fn decode(self) -> Result<FrontierDeltaEvidence, AuthorizationProjectionError> {
        if self.delta_event_id <= 0 {
            return Err(mapping_error(
                "code=authorization_projection.frontier_delta_invalid_ids".to_owned(),
            ));
        }
        positive_i64(self.tenant_id, "frontier.delta.tenant_id")?;
        positive_i64(self.aggregate_id, "frontier.delta.aggregate_id")?;
        if let Some(card_id) = self.card_id {
            positive_i64(card_id, "frontier.delta.card_id")?;
        }
        validated_aggregate_type(&self.aggregate_type)?;
        let identity = ProjectionAggregateIdentity::new(
            self.tenant_id,
            self.aggregate_type.clone(),
            self.aggregate_id,
        )?;
        validated_text(
            &self.event_id,
            MAX_EVENT_ID_LENGTH,
            "frontier.delta.event_id",
        )?;
        validated_text(
            &self.operation_id,
            MAX_GRANT_OPERATION_ID_LENGTH,
            "frontier.delta.operation_id",
        )?;
        validated_text(
            &self.compiler_version,
            MAX_COMPILER_VERSION_LENGTH,
            "frontier.delta.compiler_version",
        )?;
        if self.base_version < 0 || self.target_version <= self.base_version {
            return Err(scope_violation(
                "authorization_projection.frontier_delta_invalid_versions",
            ));
        }
        if self.source_generation <= 0 || self.revoke_fence < 0 {
            return Err(mapping_error(
                "code=authorization_projection.frontier_delta_invalid_generation_columns"
                    .to_owned(),
            ));
        }
        let source_generation = u64::try_from(self.source_generation).map_err(|_| {
            mapping_error("code=authorization_projection.frontier_delta_source_overflow".to_owned())
        })?;
        let revoke_fence = u64::try_from(self.revoke_fence).map_err(|_| {
            mapping_error("code=authorization_projection.frontier_delta_fence_overflow".to_owned())
        })?;
        crate::grant_repository::validate_delta_fence_relation(source_generation, revoke_fence)
            .map_err(|error| scope_violation(&format!("{error}")))?;

        Ok(FrontierDeltaEvidence {
            delta_event_id: self.delta_event_id,
            event_id: self.event_id,
            operation_id: self.operation_id,
            event_type: DeltaEventType::from_sql(&self.event_type)?,
            card_id: self.card_id,
            tenant_id: identity.tenant_id,
            aggregate_type: self.aggregate_type,
            aggregate_id: identity.aggregate_id,
            grant_id: crate::grant_repository::decode_grant_id_sql(&self.grant_id)?,
            base_version: self.base_version,
            target_version: self.target_version,
            source_generation,
            revoke_fence,
            semantic_hash: Sha256Digest::from_bytes(self.semantic_hash)?,
            dependency_hash: Sha256Digest::from_bytes(self.dependency_hash)?,
            compiler_version: self.compiler_version,
            status_str: self.status,
        })
    }
}

const EXTRA_SUCCEEDED_FRONTIER_SCAN_SQL: &str = "SELECT plan_id, event_id, target_generation \
    FROM authorization_impact_plan WHERE tenant_id = ? AND aggregate_type = ? \
    AND aggregate_id = ? AND target_generation > ? AND status = 'SUCCEEDED' \
    ORDER BY target_generation ASC LIMIT ? FOR UPDATE";

/// Pure bind contract of the locked plan scan (step 3 of
/// [`load_published_aggregate_frontier_in_tx`]): the inclusive
/// `target_generation <= ?` upper bound binds exactly `G`, keeping future
/// (`> G`) PENDING/LEASED/QUARANTINED staging plans out of the frontier
/// slice; the trailing `LIMIT ?` binds `G + 1` purely as a duplicate/overrun
/// defense. Kept as a checked pure function so tests can pin both values
/// without a database.
fn frontier_plan_scan_binds(generation: u64) -> Result<(i64, i64), AuthorizationProjectionError> {
    let upper_bound = bind_u64(generation, "frontier.plan_upper_bound")?;
    let limit = bind_u64(generation + 1, "frontier.plan_limit")?;
    Ok((upper_bound, limit))
}

/// Pure bind contract of the extra-SUCCEEDED probe: the exclusive
/// `target_generation > ?` lower bound binds exactly `G`, so a SUCCEEDED plan
/// stranded precisely at `G + 1` (durable history ahead of the pointer) still
/// reaches the fail-closed conflict path instead of escaping undetected.
fn frontier_extra_probe_binds(generation: u64) -> Result<(i64, i64), AuthorizationProjectionError> {
    let lower_bound = bind_u64(generation, "frontier.extra_lower_bound")?;
    let limit = bind_u64(
        u64::try_from(MAX_EXTRA_SUCCEEDED_FRONTIER_SCAN).map_err(|_| {
            mapping_error("code=authorization_projection.extra_scan_overflow".to_owned())
        })?,
        "frontier.extra_scan",
    )?;
    Ok((lower_bound, limit))
}

/// Load the strictly verified published aggregate frontier inside one
/// transaction.
///
/// Lock order mirrors the existing stage/publish/recover paths and then
/// extends it: current pointer → manifest (+ references/segments through the
/// strict read) → impact plans (target ≤ G ascending) → one locked delta row
/// per plan event. Concurrent projectors lock delta rows FIRST inside their
/// own transactions, so engine-level deadlock aborts remain possible across
/// opposite acquisition orders; callers must treat such aborts as retryable
/// transactions (no state is partially visible — MySQL rolls back atomically).
///
/// - Returns `Ok(None)` when no current pointer exists: `frontier = 0` with an
///   empty event list is representable only as absence here.
/// - Every loaded slice re-enters [`assemble_published_aggregate_frontier`];
///   all structural disputes (gaps, duplicates, drift, extra SUCCEEDED plans)
///   fail closed before any value escapes this function.
/// - Legacy head/outbox/snapshot tables are never consulted.
pub async fn load_published_aggregate_frontier_in_tx(
    tx: &mut Transaction<'_, MySql>,
    identity: &ProjectionAggregateIdentity,
) -> Result<Option<PublishedAggregateFrontier>, AuthorizationProjectionError> {
    identity.validate()?;
    // (1) Lock + observe the authoritative generation floor.
    if lock_current_pointer_in_tx(tx, identity).await?.is_none() {
        return Ok(None);
    }
    // (2) Full sealed chain verification already locks manifest/references/
    //     segments exactly like every other strict reader.
    let published = read_published_authorization_state_in_tx(tx, identity).await?;

    let depth = usize::try_from(published.generation).map_err(|_| {
        mapping_error("code=authorization_projection.frontier_generation_overflow".to_owned())
    })?;
    if depth > MAX_PUBLISHED_FRONTIER_GENERATIONS {
        return Err(scope_violation(
            "authorization_projection.frontier_generation_cap_exceeded",
        ));
    }

    // (3) Locked plans covering EXACTLY 1..=G: the inclusive
    //     `target_generation <= ?` bound receives G, so future PENDING/
    //     LEASED/QUARANTINED plans at generations > G stay legal staging
    //     residue outside this slice and can never enter the frontier. The
    //     trailing LIMIT G+1 is duplicate/overrun defense only: within the ≤G
    //     window more than G rows can only mean duplicated plan rows, which
    //     fails closed immediately below.
    let (upper_bound, limit) = frontier_plan_scan_binds(published.generation)?;
    let statement = format!("SELECT {FRONTIER_PLAN_COLUMNS}{FRONTIER_PLANS_BY_SCOPE_TAIL}");
    let raw_plans: Vec<FrontierPlanRawRow> = sqlx::query_as(statement.as_str())
        .bind(identity.tenant_id)
        .bind(&identity.aggregate_type)
        .bind(identity.aggregate_id)
        .bind(upper_bound)
        .bind(limit)
        .fetch_all(&mut **tx)
        .await?;
    if raw_plans.len() > depth {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.frontier_plan_row_cap".to_owned(),
        ));
    }
    let mut plan_evidence = Vec::with_capacity(raw_plans.len());
    for raw in raw_plans {
        plan_evidence.push(raw.decode(identity)?);
    }

    // (4) One locked delta row per unique plan event id (`uk_ade_event`
    //     guarantees at most one durable match per fetch).
    let mut delta_evidence_by_event: std::collections::BTreeMap<String, FrontierDeltaEvidence> =
        std::collections::BTreeMap::new();
    for plan in &plan_evidence {
        if delta_evidence_by_event.contains_key(&plan.event_id) {
            return Err(AuthorizationProjectionError::Corrupt(format!(
                "code=authorization_projection.frontier_duplicate_plan_event;event={}",
                plan.event_id
            )));
        }
        let statement = format!("SELECT {FRONTIER_DELTA_COLUMNS}{FRONTIER_DELTA_BY_EVENT_TAIL}");
        let raw: Option<FrontierDeltaRawRow> = sqlx::query_as(statement.as_str())
            .bind(&plan.event_id)
            .fetch_optional(&mut **tx)
            .await?;
        let Some(raw) = raw else {
            return Err(AuthorizationProjectionError::Corrupt(format!(
                "code=authorization_projection.frontier_delta_row_missing;event={}",
                plan.event_id
            )));
        };
        let evidence = raw.decode()?;
        delta_evidence_by_event.insert(evidence.event_id.clone(), evidence);
    }

    // (5) Extra SUCCEEDED plans beyond G are corrupt terminal history. The
    //     exclusive lower bound binds exactly G, so a SUCCEEDED plan stranded
    //     precisely at G+1 (history ahead of the pointer) is caught too; the
    //     probe deliberately ignores card filters so hidden scope flips cannot
    //     escape unnoticed, and caps the scan defensively. Non-SUCCEEDED
    //     future work stays legal staging residue and is ignored here.
    let (extras_lower_bound, extras_bind) = frontier_extra_probe_binds(published.generation)?;
    let raw_extras: Vec<(i64, String, i64)> = sqlx::query_as(EXTRA_SUCCEEDED_FRONTIER_SCAN_SQL)
        .bind(identity.tenant_id)
        .bind(&identity.aggregate_type)
        .bind(identity.aggregate_id)
        .bind(extras_lower_bound)
        .bind(extras_bind)
        .fetch_all(&mut **tx)
        .await?;
    let mut extra_succeeded_beyond_current = Vec::with_capacity(raw_extras.len());
    for (plan_id, event_id, target_generation) in raw_extras {
        if plan_id <= 0 {
            return Err(mapping_error(
                "code=authorization_projection.frontier_extra_plan_invalid_ids".to_owned(),
            ));
        }
        validated_text(&event_id, MAX_EVENT_ID_LENGTH, "frontier.extra.event_id")?;
        extra_succeeded_beyond_current.push(ExtraSucceededImpactPlan {
            plan_id,
            event_id,
            target_generation: read_counter_i64(
                target_generation,
                "frontier.extra.target_generation",
            )?,
        });
    }

    Ok(Some(assemble_published_aggregate_frontier(
        identity,
        &published.pointer,
        &published_generation_summary_from_state(&published),
        &plan_evidence,
        &delta_evidence_by_event,
        &extra_succeeded_beyond_current,
    )?))
}

/// Project the strictly verified published state into the shared summary used
/// by frontier planning and parent-reference views. The manifest card equals
/// the pointer's card by construction of the strict read, which proved that
/// equality fail-closed before reaching this projection step.
fn published_generation_summary_from_state(
    published: &AuthorizationPublishedState,
) -> PublishedGenerationSummary {
    PublishedGenerationSummary {
        manifest_id: published.manifest_id,
        generation: published.generation,
        source_generation: published.source_generation,
        projected_generation: published.projected_generation,
        event_id: published.event_id.clone(),
        operation_id: published.operation_id.clone(),
        semantic_hash: published.semantic_hash,
        dependency_hash: published.dependency_hash,
        compiler_version: published.compiler_version.clone(),
        manifest_digest: published.manifest_digest,
        parent_manifest_id: published.parent_manifest_id,
        revoke_fence: published.revoke_fence,
        card_id: published.pointer.card_id,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Parent manifest / reference planning views
// ─────────────────────────────────────────────────────────────────────────────

/// Planning-time view over the CURRENT publication's references: the sealed
/// pointer record plus every verified ordinal/content-digest pair behind it.
///
/// HINT ONLY, NOT A PUBLISH PROOF: staging and publish transactions repeat the
/// full verification (locks, seals, digests, lineage bytes) inside their own
/// guarded statements before anything becomes durable; consumers must never
/// treat these views as permission to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedParentReferenceSnapshot {
    /// Thin publish-relevant view derived from [`Self::pointer`].
    pub pointer_view: CurrentPointerView,
    /// The locked full pointer record (event/op/hash provenance included).
    pub pointer: AuthorizationCurrentPointerRecord,
    pub manifest_summary: PublishedGenerationSummary,
    /// Durable lineage of the published manifest (`None` = first
    /// generation). Parent manifest ROWS are not loaded here on purpose;
    /// lineage is compared byte-for-byte again inside stage transactions.
    pub parent_manifest_id: Option<i64>,
    /// Verified `(ordinal, ParentReferenceView)` pairs in ascending ordinal
    /// order; segment payloads, content digests and local seals were proven
    /// consistent while loading (same code path as the strict read).
    pub references: Vec<(u64, ParentReferenceView)>,
}

/// Load parent-reference planning views for the CURRENT publication under the
/// same `tenant/aggregate/card` scope, based on the LOCKED current pointer and
/// the existing strict published-state validation path (COMMITTED manifest,
/// contiguous ordinals, per-reference content digest + local seal agreement).
///
/// Returns `Ok(None)` when no current pointer exists — never a partial list,
/// never a fallback to older snapshots or legacy head/outbox/snapshot data.
pub async fn load_published_parent_reference_views_in_tx(
    tx: &mut Transaction<'_, MySql>,
    identity: &ProjectionAggregateIdentity,
) -> Result<Option<PublishedParentReferenceSnapshot>, AuthorizationProjectionError> {
    identity.validate()?;
    // Fixed lock prefix identical to the strict readers: pointer first.
    if lock_current_pointer_in_tx(tx, identity).await?.is_none() {
        return Ok(None);
    }
    let published = read_published_authorization_state_in_tx(tx, identity).await?;
    let mut references = Vec::with_capacity(published.references.len());
    for record in &published.references {
        references.push((record.ordinal, record.as_parent_view()));
    }

    Ok(Some(PublishedParentReferenceSnapshot {
        pointer_view: published.pointer.as_view(),
        pointer: published.pointer.clone(),
        manifest_summary: published_generation_summary_from_state(&published),
        parent_manifest_id: published.parent_manifest_id,
        references,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Archive-outbox intents (`authorization_archive_outbox`)
// ─────────────────────────────────────────────────────────────────────────────

/// Schema default status: work queued, nothing proven.
pub const ARCHIVE_OUTBOX_STATUS_PENDING: &str = "PENDING";
/// Status while one archive worker holds the live lease.
pub const ARCHIVE_OUTBOX_STATUS_LEASED: &str = "LEASED";
/// Terminal status only after durable archive proof arrived.
pub const ARCHIVE_OUTBOX_STATUS_SUCCEEDED: &str = "SUCCEEDED";
/// Operator quarantine: never processed again without intervention.
pub const ARCHIVE_OUTBOX_STATUS_QUARANTINED: &str = "QUARANTINED";

/// Upper bound for one archive intent lease duration in seconds.
pub const MAX_ARCHIVE_LEASE_SECONDS: i64 = 3_600;
/// Upper bound for one archive failure backoff step in seconds.
pub const MAX_ARCHIVE_BACKOFF_SECONDS: i64 = 3_600;
/// Byte cap mirrored from the `archive_key VARCHAR(512)` column.
pub const MAX_ARCHIVE_KEY_LENGTH: usize = 512;

/// Typed archive-outbox lifecycle state; unknown stored strings fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationArchiveOutboxStatus {
    Pending,
    Leased,
    Succeeded,
    Quarantined,
}

impl AuthorizationArchiveOutboxStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => ARCHIVE_OUTBOX_STATUS_PENDING,
            Self::Leased => ARCHIVE_OUTBOX_STATUS_LEASED,
            Self::Succeeded => ARCHIVE_OUTBOX_STATUS_SUCCEEDED,
            Self::Quarantined => ARCHIVE_OUTBOX_STATUS_QUARANTINED,
        }
    }

    pub fn parse(value: &str) -> Result<Self, AuthorizationProjectionError> {
        match value {
            ARCHIVE_OUTBOX_STATUS_PENDING => Ok(Self::Pending),
            ARCHIVE_OUTBOX_STATUS_LEASED => Ok(Self::Leased),
            ARCHIVE_OUTBOX_STATUS_SUCCEEDED => Ok(Self::Succeeded),
            ARCHIVE_OUTBOX_STATUS_QUARANTINED => Ok(Self::Quarantined),
            other => Err(mapping_error(format!(
                "code=authorization_projection.unknown_archive_outbox_status;value={other}"
            ))),
        }
    }

    /// Documented durable edges; terminal states never transition.
    pub const fn can_transition_to(self, next: Self) -> bool {
        use AuthorizationArchiveOutboxStatus::*;
        matches!(
            (self, next),
            (Pending, Leased)
                | (Leased, Pending)
                | (Leased, Succeeded)
                | (Pending, Quarantined)
                | (Leased, Quarantined)
        )
    }
}

impl fmt::Display for AuthorizationArchiveOutboxStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Deterministic storage key for one archived generation.
///
/// Stable across retries (no randomness, no timestamps); content binding comes
/// from the sibling hash columns, not the key. Aggregate-type charset is
/// already restricted to alphanumerics/underscore by
/// [`ProjectionAggregateIdentity::validate`], keeping the composed key safe.
pub fn derive_archive_key(
    identity: &ProjectionAggregateIdentity,
    generation: u64,
) -> Result<String, AuthorizationProjectionError> {
    identity.validate()?;
    let key = format!(
        "astral-auth-archive/v1/{}/{}/{}/generation-{generation}",
        identity.tenant_id, identity.aggregate_type, identity.aggregate_id
    );
    validated_text(&key, MAX_ARCHIVE_KEY_LENGTH, "archive_key")?;
    Ok(key)
}

/// Pure decision: does publishing the target manifest create archive work?
///
/// Only a real parent (current pointer) yields an archive requirement — the
/// FIRST publication supersedes nothing and must NOT fake a historical
/// version. Everything else is derived from already-verified durable data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveIntentRequirement<'a> {
    /// First-ever publication: no parent manifest exists. No intent is
    /// written and no synthetic "generation 0" evidence may be fabricated.
    NoArchiveRequired,
    /// The parent generation becomes SUPERSEDED after the CAS and must be
    /// archived asynchronously.
    Required {
        parent_pointer: &'a AuthorizationCurrentPointerRecord,
    },
}

pub fn decide_archive_intent(
    base_pointer: Option<&AuthorizationCurrentPointerRecord>,
) -> ArchiveIntentRequirement<'_> {
    match base_pointer {
        None => ArchiveIntentRequirement::NoArchiveRequired,
        Some(parent_pointer) => ArchiveIntentRequirement::Required { parent_pointer },
    }
}

/// Idempotent append input for one archive intent. Every field documents the
/// SUPERSeded PARENT manifest (the artifact being archived), which is where
/// the durable pointer carried the truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationArchiveIntentAppendRequest {
    pub identity: ProjectionAggregateIdentity,
    pub card_id: Option<i64>,
    /// Parent manifest id (about to be superseded by the publication).
    pub archived_manifest_id: i64,
    /// Parent generation.
    pub archived_generation: u64,
    /// Parent manifest's event id; doubles as the stable once-per-generation
    /// archive message identity (`uk_aao_event`).
    pub event_id: String,
    /// Parent manifest's operation id (stable deterministic identity; never
    /// random).
    pub operation_id: String,
    /// Deterministic storage key ([`derive_archive_key`] or an equally
    /// stable caller-chosen value).
    pub archive_key: String,
    pub semantic_hash_hex: String,
    pub dependency_hash_hex: String,
    pub compiler_version: String,
    /// Revoke fence of the superseded parent manifest, copied from the locked
    /// durable evidence (parent manifest row / current pointer). Callers may
    /// never guess it; `0` keeps the documented unproven-history meaning.
    pub archived_revoke_fence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationArchiveIntentOutcome {
    pub archive_outbox_id: i64,
    /// True when a prior attempt already committed the identical intent.
    pub resumed_existing_intent: bool,
}

/// Strictly decoded archive-outbox row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationArchiveOutboxRecord {
    pub archive_outbox_id: i64,
    pub identity: ProjectionAggregateIdentity,
    pub card_id: Option<i64>,
    pub archived_manifest_id: i64,
    pub archived_generation: u64,
    pub event_id: String,
    pub operation_id: String,
    pub archive_key: String,
    pub semantic_hash: Sha256Digest,
    pub dependency_hash: Sha256Digest,
    pub compiler_version: String,
    /// Parent manifest's fence copied at intent time (not caller-supplied).
    pub archived_revoke_fence: u64,
    pub status: AuthorizationArchiveOutboxStatus,
    pub attempts: i64,
    pub cas_version: i64,
    /// Present ONLY on `SUCCEEDED` rows (stamp written with durable proof).
    pub archived_at: Option<PrimitiveDateTime>,
}

const ARCHIVE_OUTBOX_ROW_COLUMNS: &str = "archive_outbox_id, tenant_id, card_id, \
    aggregate_type, aggregate_id, manifest_id, generation, event_id, operation_id, \
    archive_key, semantic_hash, dependency_hash, compiler_version, archived_revoke_fence, \
    status, attempts, cas_version, archived_at";

const ARCHIVE_INTENT_BY_EVENT_TAIL: &str = " FROM authorization_archive_outbox \
    WHERE event_id = ? FOR UPDATE";

const ARCHIVE_INTENT_BY_GENERATION_TAIL: &str = " FROM authorization_archive_outbox \
    WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ? AND generation = ? \
    FOR UPDATE";

const ARCHIVE_INTENT_INSERT_SQL: &str = "INSERT INTO authorization_archive_outbox \
    (tenant_id, card_id, aggregate_type, aggregate_id, manifest_id, generation, event_id, \
     operation_id, archive_key, semantic_hash, dependency_hash, compiler_version, \
     archived_revoke_fence, status) \
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING')";

#[derive(Debug, sqlx::FromRow)]
struct ArchiveOutboxRawSqlRow {
    archive_outbox_id: i64,
    tenant_id: i64,
    card_id: Option<i64>,
    aggregate_type: String,
    aggregate_id: i64,
    manifest_id: i64,
    generation: i64,
    event_id: String,
    operation_id: String,
    archive_key: String,
    semantic_hash: Vec<u8>,
    dependency_hash: Vec<u8>,
    compiler_version: String,
    archived_revoke_fence: i64,
    status: String,
    attempts: i64,
    cas_version: i64,
    archived_at: Option<PrimitiveDateTime>,
}

impl ArchiveOutboxRawSqlRow {
    fn decode(&self) -> Result<AuthorizationArchiveOutboxRecord, AuthorizationProjectionError> {
        positive_i64(self.archive_outbox_id, "archive_outbox_id")?;
        positive_i64(self.manifest_id, "archived_manifest_id")?;
        validated_option_card_id(self.card_id)?;
        let identity = ProjectionAggregateIdentity::new(
            self.tenant_id,
            self.aggregate_type.clone(),
            self.aggregate_id,
        )?;
        validated_text(&self.event_id, MAX_EVENT_ID_LENGTH, "event_id")?;
        validated_text(
            &self.operation_id,
            MAX_GRANT_OPERATION_ID_LENGTH,
            "operation_id",
        )?;
        validated_text(&self.archive_key, MAX_ARCHIVE_KEY_LENGTH, "archive_key")?;
        validated_text(
            &self.compiler_version,
            MAX_COMPILER_VERSION_LENGTH,
            "compiler_version",
        )?;
        if self.attempts < 0 || self.cas_version < 0 {
            return Err(mapping_error(
                "code=authorization_projection.negative_archive_counters".to_owned(),
            ));
        }
        let status = AuthorizationArchiveOutboxStatus::parse(&self.status)?;
        let archived_generation = read_counter_i64(self.generation, "archive.archived_generation")?;
        // Proof stamping discipline: a success timestamp belongs exclusively
        // to succeeded rows; any other status carrying one is corrupt state.
        match status {
            AuthorizationArchiveOutboxStatus::Succeeded => {
                if self.archived_at.is_none() {
                    return Err(AuthorizationProjectionError::Corrupt(
                        "code=authorization_projection.archive_success_without_stamp".to_owned(),
                    ));
                }
            }
            _ => {
                if self.archived_at.is_some() {
                    return Err(AuthorizationProjectionError::Corrupt(format!(
                        "code=authorization_projection.archive_stamp_without_proof;status={status}"
                    )));
                }
            }
        }
        Ok(AuthorizationArchiveOutboxRecord {
            archive_outbox_id: self.archive_outbox_id,
            identity,
            card_id: self.card_id,
            archived_manifest_id: self.manifest_id,
            archived_generation,
            event_id: self.event_id.clone(),
            operation_id: self.operation_id.clone(),
            archive_key: self.archive_key.clone(),
            semantic_hash: Sha256Digest::from_bytes(self.semantic_hash.clone())?,
            dependency_hash: Sha256Digest::from_bytes(self.dependency_hash.clone())?,
            compiler_version: self.compiler_version.clone(),
            archived_revoke_fence: read_counter_i64(
                self.archived_revoke_fence,
                "archive.archived_revoke_fence",
            )?,
            status,
            attempts: self.attempts,
            cas_version: self.cas_version,
            archived_at: self.archived_at,
        })
    }

    /// Verify every immutable field against a replayed request; ANY divergence
    /// raises the explicit immutable-conflict error (never swallowed).
    fn assert_equivalent_replay(
        &self,
        request: &AuthorizationArchiveIntentAppendRequest,
        semantic_hash: &Sha256Digest,
        dependency_hash: &Sha256Digest,
    ) -> Result<(), AuthorizationProjectionError> {
        let decoded = self.decode()?;
        let mismatch =
            |code: &str| AuthorizationProjectionError::ImmutableConflict(code.to_owned());
        if decoded.identity != request.identity {
            return Err(mismatch(
                "code=authorization_projection.archive_replay_identity",
            ));
        }
        if decoded.card_id != request.card_id {
            return Err(mismatch(
                "code=authorization_projection.archive_replay_card_scope",
            ));
        }
        if decoded.archived_manifest_id != request.archived_manifest_id {
            return Err(mismatch(
                "code=authorization_projection.archive_replay_manifest",
            ));
        }
        if decoded.archived_generation != request.archived_generation {
            return Err(mismatch(
                "code=authorization_projection.archive_replay_generation",
            ));
        }
        if decoded.event_id != request.event_id {
            return Err(mismatch(
                "code=authorization_projection.archive_replay_event",
            ));
        }
        if decoded.operation_id != request.operation_id {
            return Err(mismatch(
                "code=authorization_projection.archive_replay_operation",
            ));
        }
        if decoded.archive_key != request.archive_key {
            return Err(mismatch("code=authorization_projection.archive_replay_key"));
        }
        if decoded.semantic_hash != *semantic_hash || decoded.dependency_hash != *dependency_hash {
            return Err(mismatch(
                "code=authorization_projection.archive_replay_hash",
            ));
        }
        if decoded.compiler_version != request.compiler_version {
            return Err(mismatch(
                "code=authorization_projection.archive_replay_compiler",
            ));
        }
        if decoded.archived_revoke_fence != request.archived_revoke_fence {
            return Err(mismatch(
                "code=authorization_projection.archive_replay_revoke_fence",
            ));
        }
        Ok(())
    }
}

async fn fetch_archive_intent_by_event(
    tx: &mut Transaction<'_, MySql>,
    event_id: &str,
) -> Result<Option<ArchiveOutboxRawSqlRow>, AuthorizationProjectionError> {
    let statement = format!("SELECT {ARCHIVE_OUTBOX_ROW_COLUMNS}{ARCHIVE_INTENT_BY_EVENT_TAIL}");
    sqlx::query_as(statement.as_str())
        .bind(event_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AuthorizationProjectionError::from)
}

async fn fetch_archive_intent_by_generation(
    tx: &mut Transaction<'_, MySql>,
    identity: &ProjectionAggregateIdentity,
    generation: u64,
) -> Result<Option<ArchiveOutboxRawSqlRow>, AuthorizationProjectionError> {
    let statement =
        format!("SELECT {ARCHIVE_OUTBOX_ROW_COLUMNS}{ARCHIVE_INTENT_BY_GENERATION_TAIL}");
    sqlx::query_as(statement.as_str())
        .bind(identity.tenant_id)
        .bind(&identity.aggregate_type)
        .bind(identity.aggregate_id)
        .bind(bind_u64(generation, "archive.generation")?)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AuthorizationProjectionError::from)
}

/// Pure fail-closed proof of one archive-intent append request against the
/// LOCKED durable parent manifest row it claims to archive.
///
/// Every immutable dimension the request declares — aggregate identity, card
/// scope, generation, `event_id`/`operation_id` provenance, semantic and
/// dependency hashes, compiler version and the archived revoke fence — must
/// equal the parent row's own durable state; the request may never guess any
/// of them. Any divergence (or a parent row that cannot even be decoded)
/// refuses the append before any outbox row is read or written, so a drifted
/// or fabricated request can never launder a foreign parent into the archive
/// path. Each dimension carries a stable machine code so callers and
/// monitors can dispatch on the exact rejection reason.
fn prove_archive_intent_against_parent_manifest(
    request: &AuthorizationArchiveIntentAppendRequest,
    semantic_hash: &Sha256Digest,
    dependency_hash: &Sha256Digest,
    parent: &ManifestRawSqlRow,
) -> Result<(), AuthorizationProjectionError> {
    if parent.decode_identity()? != request.identity {
        return Err(AuthorizationProjectionError::IdentityMismatch(
            "code=authorization_projection.archive_intent_parent_identity_mismatch".to_owned(),
        ));
    }
    if parent.card_id != request.card_id {
        return Err(AuthorizationProjectionError::IdentityMismatch(
            "code=authorization_projection.archive_intent_parent_card_scope_mismatch".to_owned(),
        ));
    }
    // Lifecycle gate: normal publish appends the intent while the parent is
    // still `COMMITTED` (before the pointer CAS marks it `SUPERSEDED`);
    // recovery appends may arrive after supersession. Everything else
    // (never-published `BUILDING`/`READY`, or quarantined) is not archivable
    // evidence and must not gain an archive intent.
    if parent.status != MANIFEST_STATUS_COMMITTED && parent.status != MANIFEST_STATUS_SUPERSEDED {
        return Err(AuthorizationProjectionError::NotReady(format!(
            "code=authorization_projection.archive_intent_parent_not_archivable;status={}",
            parent.status
        )));
    }
    let mismatch = |dimension: &str| {
        AuthorizationProjectionError::ImmutableConflict(format!(
            "code=authorization_projection.archive_intent_parent_mismatch;dimension={dimension}"
        ))
    };
    if parent.decode_generations()?.0 != request.archived_generation {
        return Err(mismatch("generation"));
    }
    if parent.event_id != request.event_id {
        return Err(mismatch("event_id"));
    }
    if parent.operation_id != request.operation_id {
        return Err(mismatch("operation_id"));
    }
    if parent.semantic_hash.as_slice() != semantic_hash.as_bytes().as_slice() {
        return Err(mismatch("semantic_hash"));
    }
    if parent.dependency_hash.as_slice() != dependency_hash.as_bytes().as_slice() {
        return Err(mismatch("dependency_hash"));
    }
    if parent.compiler_version != request.compiler_version {
        return Err(mismatch("compiler_version"));
    }
    // The fence dimension pairs the request with the parent manifest's OWN
    // durable revoke fence; `0` keeps the documented unproven-history
    // sentinel meaning on both sides.
    if parent.decode_revoke_fence()? != request.archived_revoke_fence {
        return Err(mismatch("archived_revoke_fence"));
    }
    Ok(())
}

/// Pure fail-closed proof of a NEW archive-intent append request against the
/// LOCKED live current pointer.
///
/// `revoke_fence_proven` exists ONLY on the current pointer row, so a numeric
/// fence on the archived manifest row alone can never prove that the parent
/// history is complete: a superseded or legacy parent must not gain a new
/// archive intent on the strength of its stored counter. A new intent is
/// therefore only seeded when the live pointer still targets exactly this
/// parent (identity, card scope, manifest id, generation, provenance, hashes,
/// compiler version and revoke fence all agree) AND carries the durable
/// fence-proof latch (`revoke_fence_proven = true`) — a pointer written by
/// this contract is proven even when its honest fence is zero, so a proven
/// zero never blocks archiving while unproven legacy history always does.
/// Each dimension carries a stable machine code.
fn prove_archive_intent_against_live_pointer(
    request: &AuthorizationArchiveIntentAppendRequest,
    semantic_hash: &Sha256Digest,
    dependency_hash: &Sha256Digest,
    pointer: Option<&AuthorizationCurrentPointerRecord>,
) -> Result<(), AuthorizationProjectionError> {
    let Some(pointer) = pointer else {
        // No live pointer means the parent is not the live target (already
        // superseded, or never published): a NEW intent cannot be proven and
        // must not be fabricated — only an already-committed intent may be
        // replayed after supersession.
        return Err(AuthorizationProjectionError::NotReady(
            "code=authorization_projection.archive_intent_parent_pointer_missing".to_owned(),
        ));
    };
    if pointer.identity != request.identity {
        return Err(AuthorizationProjectionError::IdentityMismatch(
            "code=authorization_projection.archive_intent_pointer_identity_mismatch".to_owned(),
        ));
    }
    if pointer.card_id != request.card_id {
        return Err(AuthorizationProjectionError::IdentityMismatch(
            "code=authorization_projection.archive_intent_pointer_card_scope_mismatch".to_owned(),
        ));
    }
    // The anti-legacy latch: an unproven pointer's numeric fence (including a
    // zero) is migration-era history, not evidence of completeness, and never
    // seeds a new archive intent.
    if !pointer.revoke_fence_proven {
        return Err(AuthorizationProjectionError::NotReady(format!(
            "code=authorization_projection.archive_intent_pointer_fence_unproven;pointer_fence={}",
            pointer.revoke_fence
        )));
    }
    let mismatch = |dimension: &str| {
        AuthorizationProjectionError::ImmutableConflict(format!(
            "code=authorization_projection.archive_intent_pointer_mismatch;dimension={dimension}"
        ))
    };
    if pointer.manifest_id != request.archived_manifest_id {
        return Err(mismatch("archived_manifest_id"));
    }
    if pointer.current_generation != request.archived_generation {
        return Err(mismatch("generation"));
    }
    if pointer.event_id != request.event_id {
        return Err(mismatch("event_id"));
    }
    if pointer.operation_id != request.operation_id {
        return Err(mismatch("operation_id"));
    }
    if pointer.semantic_hash.as_bytes() != semantic_hash.as_bytes() {
        return Err(mismatch("semantic_hash"));
    }
    if pointer.dependency_hash.as_bytes() != dependency_hash.as_bytes() {
        return Err(mismatch("dependency_hash"));
    }
    if pointer.compiler_version != request.compiler_version {
        return Err(mismatch("compiler_version"));
    }
    if pointer.revoke_fence != request.archived_revoke_fence {
        return Err(mismatch("archived_revoke_fence"));
    }
    Ok(())
}

/// Append the archive intent for a superseded parent manifest inside the
/// publish transaction, BEFORE the current-pointer CAS.
///
/// Two strict paths, decided by DURABLE intent presence (never by the caller):
///
/// - EXISTING intent (found by `uk_aao_event`, else `uk_aao_generation`): the
///   request is re-verified against the locked parent manifest row and the
///   durable intent row. Supersession is fine here — recovery may replay an
///   already-committed intent after the pointer moved on, so NO live-pointer
///   alignment is demanded on this path.
/// - NEW intent: the LIVE current pointer is locked and must still target
///   exactly this parent (identity, card scope, manifest id, generation,
///   provenance, hashes, compiler version and revoke fence) AND carry the
///   durable fence-proof latch `revoke_fence_proven = true`
///   ([`prove_archive_intent_against_live_pointer`]). A numeric fence alone —
///   on the manifest row or anywhere else — never seeds a new intent:
///   `revoke_fence_proven` exists only on the current pointer, so superseded
///   or legacy/unproven history (including an honest proven-zero parent's
///   unproven predecessor) is refused instead of archived on trust.
///
/// Behavior:
/// - lock order is live pointer → parent manifest → outbox intent: the
///   parent-manifest→outbox direction is shared with the archive
///   proof-recording and completion paths, so concurrent publication and
///   archive work can never form a parent→outbox vs outbox→parent ABBA
///   cycle; the pointer lock also serializes appends and stays compatible
///   with the publish caller that already holds it;
/// - the parent manifest row is locked `FOR UPDATE` and proven on BOTH paths
///   via [`prove_archive_intent_against_parent_manifest`]; a missing,
///   unreadable, not-yet-archivable or drifted parent fails closed with
///   stable machine codes and nothing touches the outbox;
/// - writing the intent NEVER proves archiving happened; the row stays
///   `PENDING` until a future ArchiveWorker presents durable proof;
/// - replays win only when every immutable field agrees, else
///   [`AuthorizationProjectionError::ImmutableConflict`];
/// - `uk_aao_event` carries the stable message identity and `uk_aao_generation`
///   the one-intent-per-generation invariant; races resolve through both keys
///   with explicit conflicts instead of silent skips;
/// - first publications (`NoArchiveRequired`) must not reach this function
///   with fabricated parent values — [`decide_archive_intent`] gates that.
pub async fn ensure_authorization_archive_intent_in_tx(
    tx: &mut Transaction<'_, MySql>,
    request: &AuthorizationArchiveIntentAppendRequest,
) -> Result<AuthorizationArchiveIntentOutcome, AuthorizationProjectionError> {
    request.identity.validate()?;
    validated_option_card_id(request.card_id)?;
    positive_i64(request.archived_manifest_id, "archived_manifest_id")?;
    if request.archived_generation == 0 {
        return Err(scope_violation(
            "authorization_projection.invalid_archived_generation",
        ));
    }
    bind_u64(request.archived_generation, "archive.archived_generation")?;
    validated_text(&request.event_id, MAX_EVENT_ID_LENGTH, "event_id")?;
    validated_text(
        &request.operation_id,
        MAX_GRANT_OPERATION_ID_LENGTH,
        "operation_id",
    )?;
    validated_text(&request.archive_key, MAX_ARCHIVE_KEY_LENGTH, "archive_key")?;
    validated_text(
        &request.compiler_version,
        MAX_COMPILER_VERSION_LENGTH,
        "compiler_version",
    )?;
    // Fence overflow gate into the signed BIGINT domain before any SQL runs.
    bind_u64(
        request.archived_revoke_fence,
        "archive.archived_revoke_fence",
    )?;
    let semantic_hash = Sha256Digest::from_hex(&request.semantic_hash_hex)?;
    let dependency_hash = Sha256Digest::from_hex(&request.dependency_hash_hex)?;

    // Lock the LIVE current pointer FIRST: the normal publish caller already
    // holds it, a standalone recovery call takes it here, and taking it
    // before the parent manifest keeps one global order (pointer → parent
    // manifest → outbox intent) across every archive transaction. It also
    // serializes concurrent appends for the aggregate. The pointer VALUE is
    // only proven on the new-intent path below — an existing intent may be
    // replayed after supersession without any live-pointer requirement.
    let live_pointer = lock_current_pointer_in_tx(tx, &request.identity).await?;

    // Parent manifest row: locked `FOR UPDATE` BEFORE the outbox (the unified
    // parent-manifest→outbox direction shared with the proof-recording and
    // completion paths) and proven on BOTH paths. A missing, unreadable,
    // not-yet-archivable or drifted parent refuses the append outright —
    // never a silent skip.
    let parent = fetch_manifest_for_update(tx, request.archived_manifest_id).await?;
    let Some(parent) = parent else {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.archive_intent_parent_missing".to_owned(),
        ));
    };
    prove_archive_intent_against_parent_manifest(
        request,
        &semantic_hash,
        &dependency_hash,
        &parent,
    )?;

    // Discover an already-committed intent AFTER the parent lock: its
    // presence decides the path. An existing intent may be verified/replayed
    // after supersession; only a NEW intent has to prove a live pointer.
    let existing_by_event = fetch_archive_intent_by_event(tx, &request.event_id).await?;
    let existing = match existing_by_event {
        Some(existing) => Some(existing),
        None => {
            fetch_archive_intent_by_generation(tx, &request.identity, request.archived_generation)
                .await?
        }
    };

    let (intent_id, resumed): (i64, bool) = match existing {
        Some(existing) => {
            // Replay path: the durable intent was seeded under the strict
            // new-intent proof at creation time, so re-verifying request ↔
            // intent equivalence (plus the manifest gate above) is exact —
            // no live-pointer requirement here, post-supersession recovery
            // stays able to replay.
            existing.assert_equivalent_replay(request, &semantic_hash, &dependency_hash)?;
            (existing.archive_outbox_id, true)
        }
        None => {
            // New-intent path: a superseded/legacy parent must never gain a
            // new intent from its manifest's numeric fence alone — the live
            // pointer (with its exclusive `revoke_fence_proven` latch) is
            // the only acceptable fence authority.
            prove_archive_intent_against_live_pointer(
                request,
                &semantic_hash,
                &dependency_hash,
                live_pointer.as_ref(),
            )?;
            let inserted = sqlx::query(ARCHIVE_INTENT_INSERT_SQL)
                .bind(request.identity.tenant_id)
                .bind(request.card_id)
                .bind(&request.identity.aggregate_type)
                .bind(request.identity.aggregate_id)
                .bind(request.archived_manifest_id)
                .bind(bind_u64(request.archived_generation, "archive.generation")?)
                .bind(&request.event_id)
                .bind(&request.operation_id)
                .bind(&request.archive_key)
                .bind(semantic_hash.as_bytes().to_vec())
                .bind(dependency_hash.as_bytes().to_vec())
                .bind(&request.compiler_version)
                .bind(bind_u64(
                    request.archived_revoke_fence,
                    "archive.archived_revoke_fence",
                )?)
                .execute(&mut **tx)
                .await;
            match inserted {
                Ok(result) => {
                    if result.rows_affected() != 1 {
                        return Err(AuthorizationProjectionError::DuplicateRow(
                            "code=authorization_projection.archive_intent_insert_not_applied"
                                .to_owned(),
                        ));
                    }
                    (
                        i64::try_from(result.last_insert_id()).map_err(|_| {
                            mapping_error(
                            "code=authorization_projection.bigint_overflow;field=archive_outbox_id"
                                .to_owned(),
                        )
                        })?,
                        false,
                    )
                }
                Err(error) => {
                    if !unique_violation(&error) {
                        return Err(error.into());
                    }
                    let winner_by_event =
                        fetch_archive_intent_by_event(tx, &request.event_id).await?;
                    if let Some(winner) = winner_by_event {
                        winner.assert_equivalent_replay(
                            request,
                            &semantic_hash,
                            &dependency_hash,
                        )?;
                        (winner.archive_outbox_id, true)
                    } else {
                        let winner_by_generation = fetch_archive_intent_by_generation(
                            tx,
                            &request.identity,
                            request.archived_generation,
                        )
                        .await?;
                        return Err(match winner_by_generation {
                            Some(foreign) => AuthorizationProjectionError::ImmutableConflict(
                                format!(
                                    "code=authorization_projection.archive_generation_occupied;event={}",
                                    foreign.event_id
                                ),
                            ),
                            None => AuthorizationProjectionError::DuplicateRow(
                                "code=authorization_projection.archive_intent_race_unknown_winner"
                                    .to_owned(),
                            ),
                        });
                    }
                }
            }
        }
    };

    Ok(AuthorizationArchiveIntentOutcome {
        archive_outbox_id: intent_id,
        resumed_existing_intent: resumed,
    })
}

/// Strict verifier readback of one archive intent by its stable event
/// identity; `Ok(None)` when absent, explicit errors when present-but-drifted.
pub async fn load_authorization_archive_intent_in_tx(
    tx: &mut Transaction<'_, MySql>,
    identity: &ProjectionAggregateIdentity,
    event_id: &str,
) -> Result<Option<AuthorizationArchiveOutboxRecord>, AuthorizationProjectionError> {
    identity.validate()?;
    validated_text(event_id, MAX_EVENT_ID_LENGTH, "event_id")?;
    let Some(raw) = fetch_archive_intent_by_event(tx, event_id).await? else {
        return Ok(None);
    };
    let record = raw.decode()?;
    if record.identity != *identity {
        return Err(AuthorizationProjectionError::IdentityMismatch(
            "code=authorization_projection.archive_intent_identity_mismatch".to_owned(),
        ));
    }
    Ok(Some(record))
}

// ── Archive-intent lease primitives (claim / complete / fail / release /
//    quarantine). Basic primitives only: no worker loop lives in this crate. ──

/// Run-scoped secret fencing one archive lease; only the SHA-256 hash is
/// stored, mirroring the delta/manifest token policy.
#[derive(Clone, PartialEq, Eq)]
pub struct ArchiveLeaseToken(String);

impl ArchiveLeaseToken {
    fn new_run_scoped() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(token: &str) -> Self {
        Self(token.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn token_hash(&self) -> Sha256Digest {
        Sha256Digest::from_raw_bytes(sha256_digest_bytes(self.0.as_bytes()))
    }
}

impl fmt::Debug for ArchiveLeaseToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ArchiveLeaseToken(REDACTED)")
    }
}

/// Owner + token proof for one lease-guarded archive mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveLeaseProof {
    pub archive_outbox_id: i64,
    pub event_id: String,
    pub lease_owner: String,
    pub lease_token: ArchiveLeaseToken,
}

fn validate_archive_lease_material(
    lease_owner: &str,
    lease_seconds: i64,
) -> Result<(), AuthorizationProjectionError> {
    validated_text(lease_owner, MAX_GRANT_LEASE_OWNER_LENGTH, "lease_owner")?;
    if !(1..=MAX_ARCHIVE_LEASE_SECONDS).contains(&lease_seconds) {
        return Err(scope_violation(&format!(
            "authorization_projection.invalid_archive_lease_seconds;value={lease_seconds}"
        )));
    }
    Ok(())
}

fn validate_archive_lease_proof(
    proof: &ArchiveLeaseProof,
) -> Result<(), AuthorizationProjectionError> {
    positive_i64(proof.archive_outbox_id, "archive_outbox_id")?;
    validated_text(&proof.event_id, MAX_EVENT_ID_LENGTH, "event_id")?;
    validated_text(
        &proof.lease_owner,
        MAX_GRANT_LEASE_OWNER_LENGTH,
        "lease_owner",
    )?;
    if proof.lease_token.as_str().trim().is_empty() {
        return Err(scope_violation(
            "authorization_projection.empty_archive_lease_token",
        ));
    }
    Ok(())
}

/// Lease granted over one pending/expired archive intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationArchiveIntentClaim {
    pub archive_outbox_id: i64,
    pub identity: ProjectionAggregateIdentity,
    pub card_id: Option<i64>,
    pub archived_manifest_id: i64,
    pub archived_generation: u64,
    pub event_id: String,
    pub operation_id: String,
    pub archive_key: String,
    pub semantic_hash: Sha256Digest,
    pub dependency_hash: Sha256Digest,
    pub compiler_version: String,
    /// Parent manifest's fence copied from the durable intent rows.
    pub archived_revoke_fence: u64,
    pub status_before_claim_str: String,
    pub attempts_after_install: i64,
    pub cas_version_after_claim: i64,
    pub lease_owner: String,
    pub lease_token: ArchiveLeaseToken,
    pub lease_expires_at: PrimitiveDateTime,
}

/// Predicate contract for bounded retry: a future-scheduled PENDING row is
/// NOT claimable until its `next_attempt_at` arrives; expired leases stay
/// reclaimable. The two candidate selectors and the install CAS repeat this
/// exact eligibility arm textually (shape-guarded by tests), so a racing
/// install can never widen eligibility: the claim primitive hands back only
/// rows whose backoff stamp has matured. Attempt budgets stay worker policy.
const ARCHIVE_CLAIM_CANDIDATE_UNSCOPED_SQL: &str = "SELECT archive_outbox_id, event_id, \
    operation_id, tenant_id, card_id, aggregate_type, aggregate_id, manifest_id, generation, \
    archive_key, semantic_hash, dependency_hash, compiler_version, archived_revoke_fence, \
    status, cas_version \
    FROM authorization_archive_outbox \
    WHERE tenant_id = ? \
      AND ((status = 'PENDING' \
            AND (next_attempt_at IS NULL OR next_attempt_at <= UTC_TIMESTAMP())) \
           OR (status = 'LEASED' \
               AND lease_expires_at IS NOT NULL \
               AND lease_expires_at <= UTC_TIMESTAMP())) \
    ORDER BY COALESCE(next_attempt_at, created_at), archive_outbox_id \
    LIMIT 1 FOR UPDATE";

const ARCHIVE_CLAIM_CANDIDATE_CARD_SCOPED_SQL: &str = "SELECT archive_outbox_id, event_id, \
    operation_id, tenant_id, card_id, aggregate_type, aggregate_id, manifest_id, generation, \
    archive_key, semantic_hash, dependency_hash, compiler_version, archived_revoke_fence, \
    status, cas_version \
    FROM authorization_archive_outbox \
    WHERE tenant_id = ? AND card_id = ? \
      AND ((status = 'PENDING' \
            AND (next_attempt_at IS NULL OR next_attempt_at <= UTC_TIMESTAMP())) \
           OR (status = 'LEASED' \
               AND lease_expires_at IS NOT NULL \
               AND lease_expires_at <= UTC_TIMESTAMP())) \
    ORDER BY COALESCE(next_attempt_at, created_at), archive_outbox_id \
    LIMIT 1 FOR UPDATE";

const ARCHIVE_CLAIM_INSTALL_SQL: &str = "UPDATE authorization_archive_outbox \
    SET status = 'LEASED', lease_owner = ?, lease_token_hash = ?, \
        lease_expires_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP()), \
        cas_version = cas_version + 1, attempts = attempts + 1 \
    WHERE archive_outbox_id = ? \
      AND ((status = 'PENDING' \
            AND (next_attempt_at IS NULL OR next_attempt_at <= UTC_TIMESTAMP())) \
           OR (status = 'LEASED' \
               AND lease_expires_at IS NOT NULL \
               AND lease_expires_at <= UTC_TIMESTAMP()))";

const ARCHIVE_CLAIM_EXPIRY_READBACK_SQL: &str =
    "SELECT lease_expires_at, cas_version, attempts FROM authorization_archive_outbox \
     WHERE archive_outbox_id = ?";

#[derive(Debug, sqlx::FromRow)]
struct ArchiveClaimCandidateRow {
    archive_outbox_id: i64,
    event_id: String,
    operation_id: String,
    tenant_id: i64,
    card_id: Option<i64>,
    aggregate_type: String,
    aggregate_id: i64,
    manifest_id: i64,
    generation: i64,
    archive_key: String,
    semantic_hash: Vec<u8>,
    dependency_hash: Vec<u8>,
    compiler_version: String,
    archived_revoke_fence: i64,
    status: String,
    cas_version: i64,
}

/// Claim the next claimable archive intent for the scope inside the caller's
/// transaction. Live leases are never stolen; expired leases behave like
/// unqueued-free rows. Returns `Ok(None)` when nothing is claimable.
pub async fn claim_next_authorization_archive_intent_in_tx(
    tx: &mut Transaction<'_, MySql>,
    tenant_id: i64,
    card_id: Option<i64>,
    lease_owner: &str,
    lease_seconds: i64,
) -> Result<Option<AuthorizationArchiveIntentClaim>, AuthorizationProjectionError> {
    positive_i64(tenant_id, "tenant_id")?;
    if let Some(card_id) = card_id {
        positive_i64(card_id, "card_id")?;
    }
    validate_archive_lease_material(lease_owner, lease_seconds)?;

    let candidate_statement = if card_id.is_some() {
        ARCHIVE_CLAIM_CANDIDATE_CARD_SCOPED_SQL
    } else {
        ARCHIVE_CLAIM_CANDIDATE_UNSCOPED_SQL
    };
    let mut candidate_query =
        sqlx::query_as::<_, ArchiveClaimCandidateRow>(candidate_statement).bind(tenant_id);
    if let Some(card_id) = card_id {
        candidate_query = candidate_query.bind(card_id);
    }
    let candidate: Option<ArchiveClaimCandidateRow> =
        candidate_query.fetch_optional(&mut **tx).await?;
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    if candidate.status != ARCHIVE_OUTBOX_STATUS_PENDING
        && candidate.status != ARCHIVE_OUTBOX_STATUS_LEASED
    {
        return Err(mapping_error(format!(
            "code=authorization_projection.archive_claim_ineligible_status;value={}",
            candidate.status
        )));
    }

    let token = ArchiveLeaseToken::new_run_scoped();
    let install = sqlx::query(ARCHIVE_CLAIM_INSTALL_SQL)
        .bind(lease_owner)
        .bind(token.token_hash().as_bytes().to_vec())
        .bind(lease_seconds)
        .bind(candidate.archive_outbox_id)
        .execute(&mut **tx)
        .await?;
    if install.rows_affected() != 1 {
        return Err(AuthorizationProjectionError::ClaimRace);
    }

    let (lease_expires_at, cas_version_after_claim, attempts_after_install): (
        Option<PrimitiveDateTime>,
        i64,
        i64,
    ) = sqlx::query_as(ARCHIVE_CLAIM_EXPIRY_READBACK_SQL)
        .bind(candidate.archive_outbox_id)
        .fetch_one(&mut **tx)
        .await?;
    let Some(lease_expires_at) = lease_expires_at else {
        return Err(mapping_error(
            "code=authorization_projection.archive_claim_expiry_missing".to_owned(),
        ));
    };
    if attempts_after_install <= 0 {
        // The install statement always bumps `attempts`; anything else means
        // the engine betrayed the install outcome.
        return Err(AuthorizationProjectionError::ClaimRace);
    }

    let decoded = ArchiveOutboxRawSqlRow {
        archive_outbox_id: candidate.archive_outbox_id,
        tenant_id: candidate.tenant_id,
        card_id: candidate.card_id,
        aggregate_type: candidate.aggregate_type.clone(),
        aggregate_id: candidate.aggregate_id,
        manifest_id: candidate.manifest_id,
        generation: candidate.generation,
        event_id: candidate.event_id.clone(),
        operation_id: candidate.operation_id.clone(),
        archive_key: candidate.archive_key.clone(),
        semantic_hash: candidate.semantic_hash.clone(),
        dependency_hash: candidate.dependency_hash.clone(),
        compiler_version: candidate.compiler_version.clone(),
        archived_revoke_fence: candidate.archived_revoke_fence,
        status: candidate.status.clone(),
        attempts: 0,
        cas_version: candidate.cas_version,
        archived_at: None,
    }
    .decode()?;

    Ok(Some(AuthorizationArchiveIntentClaim {
        archive_outbox_id: decoded.archive_outbox_id,
        identity: decoded.identity,
        card_id: decoded.card_id,
        archived_manifest_id: decoded.archived_manifest_id,
        archived_generation: decoded.archived_generation,
        event_id: decoded.event_id,
        operation_id: decoded.operation_id,
        archive_key: decoded.archive_key,
        semantic_hash: decoded.semantic_hash,
        dependency_hash: decoded.dependency_hash,
        compiler_version: decoded.compiler_version,
        archived_revoke_fence: decoded.archived_revoke_fence,
        status_before_claim_str: decoded.status.as_str().to_owned(),
        attempts_after_install,
        cas_version_after_claim,
        lease_owner: lease_owner.to_owned(),
        lease_token: token,
        lease_expires_at,
    }))
}

const ARCHIVE_LEASE_GUARD_SUFFIX: &str = "WHERE archive_outbox_id = ? AND event_id = ? \
    AND lease_owner = ? AND lease_token_hash = ? \
    AND status = 'LEASED' \
    AND lease_expires_at IS NOT NULL \
    AND lease_expires_at > UTC_TIMESTAMP()";

const ARCHIVE_COMPLETE_SQL_BASE: &str = "UPDATE authorization_archive_outbox \
    SET status = 'SUCCEEDED', archived_at = UTC_TIMESTAMP(), lease_owner = NULL, \
        lease_token_hash = NULL, lease_expires_at = NULL, last_error = NULL ";

const ARCHIVE_FAIL_SQL_BASE: &str = "UPDATE authorization_archive_outbox \
    SET status = 'PENDING', lease_owner = NULL, lease_token_hash = NULL, \
        lease_expires_at = NULL, next_attempt_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP()), \
        last_error = ? ";

const ARCHIVE_RELEASE_SQL_BASE: &str = "UPDATE authorization_archive_outbox \
    SET status = 'PENDING', lease_owner = NULL, lease_token_hash = NULL, \
        lease_expires_at = NULL, next_attempt_at = NULL ";

async fn guarded_archive_update<'e, E>(
    executor: E,
    statement_base: &str,
    proof: &ArchiveLeaseProof,
) -> Result<u64, AuthorizationProjectionError>
where
    E: Executor<'e, Database = MySql>,
{
    validate_archive_lease_proof(proof)?;
    let statement: String = format!("{statement_base}{ARCHIVE_LEASE_GUARD_SUFFIX}");
    let result = sqlx::query(&statement)
        .bind(proof.archive_outbox_id)
        .bind(&proof.event_id)
        .bind(&proof.lease_owner)
        .bind(proof.lease_token.token_hash().as_bytes().to_vec())
        .execute(executor)
        .await?;
    Ok(result.rows_affected())
}

/// Mark one claimed archive intent durably succeeded — ONLY through a verified
/// durable archive-manifest proof.
///
/// Lock order inside the caller's transaction: the archived parent manifest
/// is locked BEFORE the outbox intent row (identified by an advisory pre-read
/// of the intent's immutable `manifest_id`), matching ensure/record so no
/// parent→outbox vs outbox→parent ABBA cycle can form.
///
/// Order inside the caller's transaction (no ACK-only success path remains):
/// 1. lock and strictly decode the outbox row addressed by the lease proof
///    (id + event identity); non-`LEASED` state fails closed;
/// 2. load the matching `authorization_archive_manifest` row under `FOR
///    UPDATE`; absence, a non-terminal status, a missing `archived_at` stamp,
///    or a broken internal seal refuses completion;
/// 3. cross-check EVERY shared dimension between the locked intent and the
///    proof (identity, card scope, archived manifest id, generation, event and
///    operation ids, archive key, hash trio, compiler version) — any drift is
///    an explicit conflict, never a silent skip;
/// 4. flip the intent to `SUCCEEDED` with the same live-lease guard as before,
///    so the durable proof always precedes the terminal write.
pub async fn complete_authorization_archive_intent(
    tx: &mut Transaction<'_, MySql>,
    proof_of_lease: &ArchiveLeaseProof,
) -> Result<(), AuthorizationProjectionError> {
    validate_archive_lease_proof(proof_of_lease)?;
    // Advisory pre-read (no lock): the intent's `manifest_id` is immutable, so
    // it safely identifies the archived parent row to lock FIRST. Every
    // decision below is re-made on the authoritative locked re-read, so the
    // pre-read can never weaken completion semantics.
    let pre_read_manifest_id: Option<i64> = sqlx::query_scalar(
        "SELECT manifest_id FROM authorization_archive_outbox \
         WHERE archive_outbox_id = ? AND event_id = ?",
    )
    .bind(proof_of_lease.archive_outbox_id)
    .bind(&proof_of_lease.event_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(pre_read_manifest_id) = pre_read_manifest_id else {
        return Err(AuthorizationProjectionError::LeaseCasFailed(format!(
            "code=authorization_projection.archive_complete_intent_missing;event={}",
            proof_of_lease.event_id
        )));
    };
    positive_i64(pre_read_manifest_id, "archive_complete_manifest_id")?;
    // Unified archive lock order: the archived parent manifest is locked
    // BEFORE the outbox intent row, matching ensure/record so concurrent
    // publication/archive work can never form a parent→outbox vs
    // outbox→parent ABBA cycle.
    fetch_manifest_for_update(tx, pre_read_manifest_id)
        .await?
        .ok_or_else(|| {
            AuthorizationProjectionError::Corrupt(
                "code=authorization_projection.archive_parent_missing".to_owned(),
            )
        })?;
    let statement =
        format!("SELECT {ARCHIVE_OUTBOX_ROW_COLUMNS}{ARCHIVE_OUTBOX_BY_ID_AND_EVENT_LOCKED_TAIL}");
    let raw: Option<ArchiveOutboxRawSqlRow> = sqlx::query_as(statement.as_str())
        .bind(proof_of_lease.archive_outbox_id)
        .bind(&proof_of_lease.event_id)
        .fetch_optional(&mut **tx)
        .await?;
    let Some(raw) = raw else {
        return Err(AuthorizationProjectionError::LeaseCasFailed(format!(
            "code=authorization_projection.archive_complete_intent_missing;event={}",
            proof_of_lease.event_id
        )));
    };
    let intent = raw.decode()?;
    if !matches!(intent.status, AuthorizationArchiveOutboxStatus::Leased) {
        return Err(AuthorizationProjectionError::LeaseCasFailed(format!(
            "code=authorization_projection.archive_complete_not_leased;status={}",
            intent.status
        )));
    }

    // Durable proof FIRST: absent or non-terminal evidence never completes.
    let proof =
        load_authorization_archive_proof_in_tx(tx, &intent.identity, intent.archived_generation)
            .await?
            .ok_or_else(|| {
                AuthorizationProjectionError::NotReady(
                    "code=authorization_projection.archive_complete_without_durable_proof"
                        .to_owned(),
                )
            })?;
    // Full re-derivation against durable rows: terminality, stamp parity, the
    // parent manifest's own sealed chain, every referenced segment's LOCAL
    // seal, and the proof's own archive_digest.
    verify_authorization_archive_proof_in_tx(tx, &proof).await?;
    validate_terminal_archive_proof(&proof)?;
    ensure_archive_proof_matches_intent(&intent, &proof)?;

    // Terminal flip SECOND, keeping the exact live-lease guard semantics.
    if guarded_archive_update(&mut **tx, ARCHIVE_COMPLETE_SQL_BASE, proof_of_lease).await? != 1 {
        return Err(AuthorizationProjectionError::LeaseCasFailed(format!(
            "code=authorization_projection.archive_complete_lost_lease;event={}",
            proof_of_lease.event_id
        )));
    }
    Ok(())
}

const ARCHIVE_OUTBOX_BY_ID_AND_EVENT_LOCKED_TAIL: &str = " FROM authorization_archive_outbox \
    WHERE archive_outbox_id = ? AND event_id = ? FOR UPDATE";

/// Record a processing failure: release the lease, schedule a bounded retry
/// and persist the truncated error. Attempt budgets remain worker policy.
pub async fn fail_authorization_archive_intent<'e, E>(
    executor: E,
    proof: &ArchiveLeaseProof,
    backoff_seconds: i64,
    last_error: &str,
) -> Result<(), AuthorizationProjectionError>
where
    E: Executor<'e, Database = MySql>,
{
    if !(0..=MAX_ARCHIVE_BACKOFF_SECONDS).contains(&backoff_seconds) {
        return Err(scope_violation(&format!(
            "authorization_projection.invalid_archive_backoff_seconds;value={backoff_seconds}"
        )));
    }
    validate_archive_lease_proof(proof)?;
    let statement: String = format!("{ARCHIVE_FAIL_SQL_BASE}{ARCHIVE_LEASE_GUARD_SUFFIX}");
    let result = sqlx::query(&statement)
        .bind(backoff_seconds)
        .bind(truncate_last_error(last_error))
        .bind(proof.archive_outbox_id)
        .bind(&proof.event_id)
        .bind(&proof.lease_owner)
        .bind(proof.lease_token.token_hash().as_bytes().to_vec())
        .execute(executor)
        .await?;
    if result.rows_affected() != 1 {
        return Err(AuthorizationProjectionError::LeaseCasFailed(format!(
            "code=authorization_projection.archive_fail_lost_lease;event={}",
            proof.event_id
        )));
    }
    Ok(())
}

/// Relinquish a claim without recording failure; the intent becomes
/// immediately retryable.
pub async fn release_authorization_archive_intent<'e, E>(
    executor: E,
    proof: &ArchiveLeaseProof,
) -> Result<(), AuthorizationProjectionError>
where
    E: Executor<'e, Database = MySql>,
{
    if guarded_archive_update(executor, ARCHIVE_RELEASE_SQL_BASE, proof).await? != 1 {
        return Err(AuthorizationProjectionError::LeaseCasFailed(format!(
            "code=authorization_projection.archive_release_lost_lease;event={}",
            proof.event_id
        )));
    }
    Ok(())
}

/// Heartbeat (renewal) SQL: extends ONLY the live lease expiry — `status`,
/// `attempts`, `cas_version` and every other column stay untouched, so a
/// renewal can never advance retry accounting or mask concurrent CAS changes.
const ARCHIVE_HEARTBEAT_SQL: &str = "UPDATE authorization_archive_outbox \
    SET lease_expires_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP()) ";

/// Renew a live archive lease (worker heartbeat) for expensive proof/complete
/// preparation: the server-stamped `lease_expires_at` is extended by the
/// bounded caller-provided seconds while the stable lease proof (outbox id,
/// event id, owner, token hash) is CAS-rebound and the row must STILL be
/// `LEASED` with an unexpired lease — an expired lease must be re-claimed,
/// never renewed. No `status`/`attempts`/`cas_version` mutation occurs, so
/// renewal neither advances retry accounting nor masks concurrent CAS
/// changes; zero matched rows means the lease was lost/expired/stolen and
/// fails closed with [`AuthorizationProjectionError::LeaseCasFailed`].
pub async fn heartbeat_authorization_archive_intent_lease<'e, E>(
    executor: E,
    proof: &ArchiveLeaseProof,
    extension_seconds: i64,
) -> Result<(), AuthorizationProjectionError>
where
    E: Executor<'e, Database = MySql>,
{
    validate_archive_lease_proof(proof)?;
    validate_archive_lease_material(&proof.lease_owner, extension_seconds)?;
    let statement: String = format!("{ARCHIVE_HEARTBEAT_SQL}{ARCHIVE_LEASE_GUARD_SUFFIX}");
    let result = sqlx::query(&statement)
        .bind(extension_seconds)
        .bind(proof.archive_outbox_id)
        .bind(&proof.event_id)
        .bind(&proof.lease_owner)
        .bind(proof.lease_token.token_hash().as_bytes().to_vec())
        .execute(executor)
        .await?;
    if result.rows_affected() != 1 {
        return Err(AuthorizationProjectionError::LeaseCasFailed(format!(
            "code=authorization_projection.archive_heartbeat_lost_lease;event={}",
            proof.event_id
        )));
    }
    Ok(())
}

/// Operator quarantine of a live-leased pending/claimed intent; preserves the
/// failure reason (truncated) and clears the lease.
pub async fn mark_authorization_archive_intent_quarantined<'e, E>(
    executor: E,
    proof: &ArchiveLeaseProof,
    reason: &str,
) -> Result<(), AuthorizationProjectionError>
where
    E: Executor<'e, Database = MySql>,
{
    validate_archive_lease_proof(proof)?;
    let statement: String = format!(
        "UPDATE authorization_archive_outbox SET status = 'QUARANTINED', \
         lease_owner = NULL, lease_token_hash = NULL, lease_expires_at = NULL, last_error = ? \
         {ARCHIVE_LEASE_GUARD_SUFFIX}"
    );
    let result = sqlx::query(&statement)
        .bind(truncate_last_error(reason))
        .bind(proof.archive_outbox_id)
        .bind(&proof.event_id)
        .bind(&proof.lease_owner)
        .bind(proof.lease_token.token_hash().as_bytes().to_vec())
        .execute(executor)
        .await?;
    if result.rows_affected() != 1 {
        return Err(AuthorizationProjectionError::LeaseCasFailed(
            "code=authorization_projection.archive_quarantine_lost_lease".to_owned(),
        ));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Durable archive-manifest proofs (`authorization_archive_manifest`)
// ─────────────────────────────────────────────────────────────────────────────

/// Schema-default status of a freshly staged archive evidence row.
pub const ARCHIVE_MANIFEST_STATUS_STAGED: &str = "STAGED";
/// Terminal status stamped together with the exclusive `archived_at` column:
/// the generation's chain was re-read and re-digested under lock INSIDE this
/// database. It never claims an external backup succeeded.
pub const ARCHIVE_MANIFEST_STATUS_ARCHIVED: &str = "ARCHIVED";

/// Typed archive-manifest lifecycle state; unknown stored strings fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationArchiveManifestStatus {
    Staged,
    Archived,
}

impl AuthorizationArchiveManifestStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Staged => ARCHIVE_MANIFEST_STATUS_STAGED,
            Self::Archived => ARCHIVE_MANIFEST_STATUS_ARCHIVED,
        }
    }

    pub fn parse(value: &str) -> Result<Self, AuthorizationProjectionError> {
        match value {
            ARCHIVE_MANIFEST_STATUS_STAGED => Ok(Self::Staged),
            ARCHIVE_MANIFEST_STATUS_ARCHIVED => Ok(Self::Archived),
            other => Err(mapping_error(format!(
                "code=authorization_projection.unknown_archive_manifest_status;value={other}"
            ))),
        }
    }

    /// Allowed durable edge: `STAGED -> ARCHIVED`. Terminal states never move.
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!((self, next), (Self::Staged, Self::Archived))
    }
}

impl fmt::Display for AuthorizationArchiveManifestStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Every immutable dimension sealed by `archive_digest`.
///
/// The schema couples an archive manifest to its outbox intent through the
/// stable composite keys `uk_aam_generation` and
/// `(manifest_id, event_id, operation_id, archive_key)`; the digest makes that
/// coupling content-addressed so any drift on ANY bound field is detectable by
/// re-derivation alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationArchiveDigestInput<'a> {
    pub tenant_id: i64,
    pub aggregate_type: &'a str,
    pub aggregate_id: i64,
    pub card_id: Option<i64>,
    /// The superseded parent projection manifest's id (`manifest_id` column).
    pub archived_manifest_id: i64,
    /// The archived (parent) generation.
    pub archived_generation: u64,
    pub event_id: &'a str,
    pub operation_id: &'a str,
    pub archive_key: &'a str,
    /// Revoke fence of the superseded parent manifest, copied from durable
    /// evidence at intent time (never caller-invented).
    pub archived_revoke_fence: u64,
    pub semantic_hash: &'a Sha256Digest,
    pub dependency_hash: &'a Sha256Digest,
    pub compiler_version: &'a str,
    /// The parent projection manifest's OWN sealed `manifest_digest` — the
    /// manifest/segment-chain digest this archive pins. Recomputed from disk
    /// before it may enter here ([`record_authorization_archive_proof_in_tx`]).
    pub manifest_chain_digest: &'a Sha256Digest,
}

const AUTHORIZATION_ARCHIVE_DIGEST_DOMAIN: &[u8] = b"astral-auth-archive-proof-v2";

/// Compute the deterministic `authorization_archive_manifest.archive_digest`.
///
/// Mirrors [`compute_manifest_digest`]'s encoding discipline; status and
/// timestamps mutate by design and never enter the seal. The Phase 1 schema
/// carries no `source_generation` / `base_version` / outbox-id columns, so
/// they are NOT fabricated here — provenance is bound instead through the
/// recorded identities above plus the pinned parent-chain digest.
pub fn compute_authorization_archive_digest(
    input: &AuthorizationArchiveDigestInput<'_>,
) -> Result<Sha256Digest, AuthorizationProjectionError> {
    positive_i64(input.archived_manifest_id, "archived_manifest_id")?;
    if input.archived_generation == 0 {
        return Err(scope_violation(
            "authorization_projection.invalid_archived_generation",
        ));
    }
    if !input.aggregate_type.is_ascii()
        || !input.compiler_version.is_ascii()
        || !input.event_id.is_ascii()
        || !input.operation_id.is_ascii()
        || !input.archive_key.is_ascii()
    {
        return Err(scope_violation(
            "authorization_projection.non_ascii_archive_digest_field",
        ));
    }
    let mut material = Vec::with_capacity(320);
    material.extend_from_slice(AUTHORIZATION_ARCHIVE_DIGEST_DOMAIN);
    material.extend_from_slice(&input.tenant_id.to_be_bytes());
    material.push(b'\x00');
    material.extend_from_slice(input.aggregate_type.as_bytes());
    material.extend_from_slice(&input.aggregate_id.to_be_bytes());
    match input.card_id {
        None => material.extend_from_slice(&(-1_i64).to_be_bytes()),
        Some(card_id) => material.extend_from_slice(&card_id.to_be_bytes()),
    }
    material.extend_from_slice(&input.archived_manifest_id.to_be_bytes());
    material.extend_from_slice(
        &bind_u64(input.archived_generation, "archive.generation")?.to_be_bytes(),
    );
    material.extend_from_slice(&encode_len_prefixed_text(input.event_id, "event_id"));
    material.extend_from_slice(&encode_len_prefixed_text(
        input.operation_id,
        "operation_id",
    ));
    material.extend_from_slice(&encode_len_prefixed_text(input.archive_key, "archive_key"));
    material.extend_from_slice(
        &bind_u64(input.archived_revoke_fence, "archive.archived_revoke_fence")?.to_be_bytes(),
    );
    material.extend_from_slice(&input.semantic_hash.as_bytes());
    material.extend_from_slice(&input.dependency_hash.as_bytes());
    material.extend_from_slice(&encode_len_prefixed_text(
        input.compiler_version,
        "compiler_version",
    ));
    material.extend_from_slice(&input.manifest_chain_digest.as_bytes());
    Ok(Sha256Digest::from_raw_bytes(sha256_digest_bytes(&material)))
}

/// Decoded durable archive proof for one superseded generation.
///
/// `status`/`archived_at`/`cas_version` are lifecycle metadata outside the
/// seal; every other field is immutably bound by `archive_digest`, which also
/// covers the parent manifest's sealed chain digest (recomputed from durable
/// rows during record/verify — the Phase 1 schema has no dedicated column for
/// it, so the binding is content-addressed rather than stored).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationArchiveManifestProof {
    pub archive_manifest_id: i64,
    pub identity: ProjectionAggregateIdentity,
    pub card_id: Option<i64>,
    pub archived_manifest_id: i64,
    pub archived_generation: u64,
    pub event_id: String,
    pub operation_id: String,
    pub archive_key: String,
    pub semantic_hash: Sha256Digest,
    pub dependency_hash: Sha256Digest,
    pub compiler_version: String,
    /// Parent manifest's fence, sealed inside `archive_digest` and equal to
    /// both the intent's and the parent manifest row's durable value.
    pub archived_revoke_fence: u64,
    pub archive_digest: Sha256Digest,
    pub status: AuthorizationArchiveManifestStatus,
    pub cas_version: i64,
    /// Present ONLY on terminal `ARCHIVED` rows.
    pub archived_at: Option<PrimitiveDateTime>,
}

const ARCHIVE_MANIFEST_ROW_COLUMNS: &str = "archive_manifest_id, tenant_id, card_id, \
    aggregate_type, aggregate_id, manifest_id, generation, event_id, operation_id, \
    archive_key, archive_digest, semantic_hash, dependency_hash, compiler_version, \
    archived_revoke_fence, status, cas_version, archived_at";

const ARCHIVE_MANIFEST_BY_GENERATION_TAIL: &str = " FROM authorization_archive_manifest \
    WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ? AND generation = ? \
    FOR UPDATE";

const ARCHIVE_MANIFEST_BY_DIGEST_TAIL: &str = " FROM authorization_archive_manifest \
    WHERE tenant_id = ? AND archive_digest = ? FOR UPDATE";

const ARCHIVE_MANIFEST_INSERT_SQL: &str = "INSERT INTO authorization_archive_manifest \
    (tenant_id, card_id, aggregate_type, aggregate_id, manifest_id, generation, event_id, \
     operation_id, archive_key, archive_digest, semantic_hash, dependency_hash, \
     compiler_version, archived_revoke_fence, status, archived_at) \
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ARCHIVED', UTC_TIMESTAMP())";

#[derive(Debug, sqlx::FromRow)]
struct ArchiveManifestRawSqlRow {
    archive_manifest_id: i64,
    tenant_id: i64,
    card_id: Option<i64>,
    aggregate_type: String,
    aggregate_id: i64,
    manifest_id: i64,
    generation: i64,
    event_id: String,
    operation_id: String,
    archive_key: String,
    archive_digest: Vec<u8>,
    semantic_hash: Vec<u8>,
    dependency_hash: Vec<u8>,
    compiler_version: String,
    archived_revoke_fence: i64,
    status: String,
    cas_version: i64,
    archived_at: Option<PrimitiveDateTime>,
}

impl ArchiveManifestRawSqlRow {
    fn decode(&self) -> Result<AuthorizationArchiveManifestProof, AuthorizationProjectionError> {
        positive_i64(self.archive_manifest_id, "archive_manifest_id")?;
        positive_i64(self.manifest_id, "archived_manifest_id")?;
        validated_option_card_id(self.card_id)?;
        let identity = ProjectionAggregateIdentity::new(
            self.tenant_id,
            self.aggregate_type.clone(),
            self.aggregate_id,
        )?;
        validated_text(&self.event_id, MAX_EVENT_ID_LENGTH, "event_id")?;
        validated_text(
            &self.operation_id,
            MAX_GRANT_OPERATION_ID_LENGTH,
            "operation_id",
        )?;
        validated_text(&self.archive_key, MAX_ARCHIVE_KEY_LENGTH, "archive_key")?;
        validated_text(
            &self.compiler_version,
            MAX_COMPILER_VERSION_LENGTH,
            "compiler_version",
        )?;
        if self.cas_version < 0 {
            return Err(mapping_error(
                "code=authorization_projection.negative_archive_counters".to_owned(),
            ));
        }
        let archived_generation = read_counter_i64(self.generation, "archive_manifest.generation")?;
        let status = AuthorizationArchiveManifestStatus::parse(&self.status)?;
        // Stamp parity: a timestamp belongs exclusively to terminal rows.
        match status {
            AuthorizationArchiveManifestStatus::Archived if self.archived_at.is_none() => {
                return Err(AuthorizationProjectionError::Corrupt(
                    "code=authorization_projection.archive_terminal_without_stamp".to_owned(),
                ));
            }
            AuthorizationArchiveManifestStatus::Staged if self.archived_at.is_some() => {
                return Err(AuthorizationProjectionError::Corrupt(
                    "code=authorization_projection.archive_stamp_without_terminal_status"
                        .to_owned(),
                ));
            }
            _ => {}
        }
        Ok(AuthorizationArchiveManifestProof {
            archive_manifest_id: self.archive_manifest_id,
            identity,
            card_id: self.card_id,
            archived_manifest_id: self.manifest_id,
            archived_generation,
            event_id: self.event_id.clone(),
            operation_id: self.operation_id.clone(),
            archive_key: self.archive_key.clone(),
            // These two columns mirror the archived PARENT manifest's global
            // hashes (identical values also sit on the paired outbox intent);
            // they are NOT segment-local seals here.
            semantic_hash: Sha256Digest::from_bytes(self.semantic_hash.clone())?,
            dependency_hash: Sha256Digest::from_bytes(self.dependency_hash.clone())?,
            compiler_version: self.compiler_version.clone(),
            archived_revoke_fence: read_counter_i64(
                self.archived_revoke_fence,
                "archive_manifest.archived_revoke_fence",
            )?,
            archive_digest: Sha256Digest::from_bytes(self.archive_digest.clone())?,
            status,
            cas_version: self.cas_version,
            archived_at: self.archived_at,
        })
    }
}

/// Caller-validated claim of one archive proof's immutable dimensions.
///
/// Nothing here is trusted as-is: [`record_authorization_archive_proof_in_tx`]
/// cross-checks every field against the locked outbox intent AND strictly
/// re-reads/re-digests the archived manifest chain under lock before any row
/// is written. An ACK, an intent or a caller assertion alone never proves
/// anything.
#[derive(Debug, Clone)]
pub struct AuthorizationArchiveProofRequest {
    pub identity: ProjectionAggregateIdentity,
    pub card_id: Option<i64>,
    /// Superseded parent projection manifest id (`manifest_id` column).
    pub archived_manifest_id: i64,
    /// Parent generation; the schema's `uk_aam_generation` key makes this the
    /// stable once-per-generation proof identity paired to the outbox intent.
    pub archived_generation: u64,
    /// Parent manifest's event id — doubles as the outbox identity (`uk_aao_event`).
    pub event_id: String,
    pub operation_id: String,
    pub archive_key: String,
    pub semantic_hash_hex: String,
    pub dependency_hash_hex: String,
    pub compiler_version: String,
    /// Expected fence of the superseded parent manifest (copied from the
    /// locked durable intent/parent evidence; cross-checked, never trusted).
    pub archived_revoke_fence: u64,
    /// Expected sealed `manifest_digest` of the archived parent manifest
    /// (lowercase hex). Recomputed from durable rows first and refused on drift.
    pub manifest_chain_digest_hex: String,
}

/// Internal borrow view used to derive the archive seal and prove replays.
struct ArchiveProofMaterial<'a> {
    identity: &'a ProjectionAggregateIdentity,
    card_id: Option<i64>,
    archived_manifest_id: i64,
    archived_generation: u64,
    event_id: &'a str,
    operation_id: &'a str,
    archive_key: &'a str,
    archived_revoke_fence: u64,
    semantic_hash: &'a Sha256Digest,
    dependency_hash: &'a Sha256Digest,
    compiler_version: &'a str,
}

impl ArchiveProofMaterial<'_> {
    fn conflict(code: String) -> AuthorizationProjectionError {
        AuthorizationProjectionError::ImmutableConflict(code)
    }

    fn archive_digest(
        &self,
        manifest_chain_digest: &Sha256Digest,
    ) -> Result<Sha256Digest, AuthorizationProjectionError> {
        compute_authorization_archive_digest(&AuthorizationArchiveDigestInput {
            tenant_id: self.identity.tenant_id,
            aggregate_type: &self.identity.aggregate_type,
            aggregate_id: self.identity.aggregate_id,
            card_id: self.card_id,
            archived_manifest_id: self.archived_manifest_id,
            archived_generation: self.archived_generation,
            event_id: self.event_id,
            operation_id: self.operation_id,
            archive_key: self.archive_key,
            archived_revoke_fence: self.archived_revoke_fence,
            semantic_hash: self.semantic_hash,
            dependency_hash: self.dependency_hash,
            compiler_version: self.compiler_version,
            manifest_chain_digest,
        })
    }

    /// Prove an existing durable winner IS this proof byte-for-byte across
    /// every immutable dimension (including the derived seal itself).
    fn assert_equivalent_replay(
        &self,
        existing: &AuthorizationArchiveManifestProof,
        manifest_chain_digest: &Sha256Digest,
    ) -> Result<(), AuthorizationProjectionError> {
        let mismatch = |code: &str| Self::conflict(format!("code=authorization_projection.{code}"));
        if existing.identity != *self.identity {
            return Err(mismatch("archive_manifest_replay_identity"));
        }
        if existing.card_id != self.card_id {
            return Err(mismatch("archive_manifest_replay_card_scope"));
        }
        if existing.archived_manifest_id != self.archived_manifest_id {
            return Err(mismatch("archive_manifest_replay_manifest"));
        }
        if existing.archived_generation != self.archived_generation {
            return Err(mismatch("archive_manifest_replay_generation"));
        }
        if existing.event_id != self.event_id {
            return Err(mismatch("archive_manifest_replay_event"));
        }
        if existing.operation_id != self.operation_id {
            return Err(mismatch("archive_manifest_replay_operation"));
        }
        if existing.archive_key != self.archive_key {
            return Err(mismatch("archive_manifest_replay_key"));
        }
        if existing.semantic_hash.as_bytes() != self.semantic_hash.as_bytes()
            || existing.dependency_hash.as_bytes() != self.dependency_hash.as_bytes()
        {
            return Err(mismatch("archive_manifest_replay_hash"));
        }
        if existing.compiler_version != self.compiler_version {
            return Err(mismatch("archive_manifest_replay_compiler"));
        }
        if existing.archived_revoke_fence != self.archived_revoke_fence {
            return Err(mismatch("archive_manifest_replay_revoke_fence"));
        }
        let expected_digest = self.archive_digest(manifest_chain_digest)?;
        if existing.archive_digest != expected_digest {
            return Err(mismatch("archive_manifest_replay_digest"));
        }
        Ok(())
    }
}

/// Pure terminality gate for one archive proof: only `ARCHIVED` rows carrying
/// their exclusive success stamp may back an intent completion. STAGED rows
/// are staged evidence, not completed archives.
pub fn validate_terminal_archive_proof(
    proof: &AuthorizationArchiveManifestProof,
) -> Result<(), AuthorizationProjectionError> {
    match proof.status {
        AuthorizationArchiveManifestStatus::Archived => {}
        other => {
            return Err(mapping_error(format!(
                "code=authorization_projection.archive_proof_not_terminal;status={other}"
            )));
        }
    }
    if proof.archived_at.is_none() {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.archive_terminal_without_stamp".to_owned(),
        ));
    }
    Ok(())
}

/// Pure dimension-pairing gate between a locked outbox intent and its proof.
pub fn ensure_archive_proof_matches_intent(
    intent: &AuthorizationArchiveOutboxRecord,
    proof: &AuthorizationArchiveManifestProof,
) -> Result<(), AuthorizationProjectionError> {
    let mismatch = |dimension: &str| {
        AuthorizationProjectionError::ImmutableConflict(format!(
            "code=authorization_projection.archive_complete_dimension_mismatch;dimension={dimension}"
        ))
    };
    if proof.identity != intent.identity {
        return Err(mismatch("identity"));
    }
    if proof.card_id != intent.card_id {
        return Err(mismatch("card_scope"));
    }
    if proof.archived_manifest_id != intent.archived_manifest_id {
        return Err(mismatch("archived_manifest_id"));
    }
    if proof.archived_generation != intent.archived_generation {
        return Err(mismatch("generation"));
    }
    if proof.event_id != intent.event_id {
        return Err(mismatch("event_id"));
    }
    if proof.operation_id != intent.operation_id {
        return Err(mismatch("operation_id"));
    }
    if proof.archive_key != intent.archive_key {
        return Err(mismatch("archive_key"));
    }
    if proof.semantic_hash.as_bytes() != intent.semantic_hash.as_bytes()
        || proof.dependency_hash.as_bytes() != intent.dependency_hash.as_bytes()
    {
        return Err(mismatch("hash_trio"));
    }
    if proof.compiler_version != intent.compiler_version {
        return Err(mismatch("compiler_version"));
    }
    // The fence dimension pairs the proof with both the intent and the
    // superseded parent manifest row it claims to archive.
    if proof.archived_revoke_fence != intent.archived_revoke_fence {
        return Err(mismatch("archived_revoke_fence"));
    }
    Ok(())
}

async fn fetch_archive_manifest_by_generation(
    tx: &mut Transaction<'_, MySql>,
    identity: &ProjectionAggregateIdentity,
    generation: u64,
) -> Result<Option<AuthorizationArchiveManifestProof>, AuthorizationProjectionError> {
    let statement =
        format!("SELECT {ARCHIVE_MANIFEST_ROW_COLUMNS}{ARCHIVE_MANIFEST_BY_GENERATION_TAIL}");
    let row: Option<ArchiveManifestRawSqlRow> = sqlx::query_as(statement.as_str())
        .bind(identity.tenant_id)
        .bind(&identity.aggregate_type)
        .bind(identity.aggregate_id)
        .bind(bind_u64(generation, "archive_manifest.generation")?)
        .fetch_optional(&mut **tx)
        .await?;
    row.map(|raw| raw.decode()).transpose()
}

async fn fetch_archive_manifest_by_digest(
    tx: &mut Transaction<'_, MySql>,
    tenant_id: i64,
    digest: &Sha256Digest,
) -> Result<Option<AuthorizationArchiveManifestProof>, AuthorizationProjectionError> {
    let statement =
        format!("SELECT {ARCHIVE_MANIFEST_ROW_COLUMNS}{ARCHIVE_MANIFEST_BY_DIGEST_TAIL}");
    let row: Option<ArchiveManifestRawSqlRow> = sqlx::query_as(statement.as_str())
        .bind(tenant_id)
        .bind(digest.as_bytes().to_vec())
        .fetch_optional(&mut **tx)
        .await?;
    row.map(|raw| raw.decode()).transpose()
}

/// Consistency read of one archive proof by generation; `Ok(None)` when absent.
pub async fn load_authorization_archive_proof_in_tx(
    tx: &mut Transaction<'_, MySql>,
    identity: &ProjectionAggregateIdentity,
    generation: u64,
) -> Result<Option<AuthorizationArchiveManifestProof>, AuthorizationProjectionError> {
    identity.validate()?;
    bind_u64(generation, "archive_manifest.generation")?;
    fetch_archive_manifest_by_generation(tx, identity, generation).await
}

/// Strictly lock one projection-manifest row by primary key and return its
/// sealed chain digest (`manifest_digest`), ONLY when the row is in an
/// archivable terminal state (`COMMITTED` or `SUPERSEDED`).
///
/// Minimal public readback for the asynchronous archive worker: the worker may
/// never hand-write SQL nor reimplement digest algorithms, and the proof
/// request's `manifest_chain_digest_hex` MUST come from THIS transactional
/// re-read — never from a stale claim payload or an out-of-band value.
///
/// - `Ok(None)`: the manifest row does not exist (dangling intent evidence);
///   callers decide the disposition (the worker treats it as an unexpected
///   contract state instead of fabricating a proof).
/// - Non-archivable status (`BUILDING`/`READY`/quarantined): explicit
///   [`AuthorizationProjectionError::NotReady`]; every other pairing
///   (identity/generation/provenance/card/fence plus the full sealed chain)
///   is re-verified inside [`record_authorization_archive_proof_in_tx`].
pub async fn load_archivable_manifest_chain_digest_in_tx(
    tx: &mut Transaction<'_, MySql>,
    archived_manifest_id: i64,
) -> Result<Option<Sha256Digest>, AuthorizationProjectionError> {
    positive_i64(archived_manifest_id, "archived_manifest_id")?;
    let Some(parent) = fetch_manifest_for_update(tx, archived_manifest_id).await? else {
        return Ok(None);
    };
    if parent.status != MANIFEST_STATUS_COMMITTED && parent.status != MANIFEST_STATUS_SUPERSEDED {
        return Err(AuthorizationProjectionError::NotReady(format!(
            "code=authorization_projection.archive_parent_not_archivable;status={}",
            parent.status
        )));
    }
    Ok(Some(parent.decode_hashes()?.2))
}

/// Full re-derivation of one archive proof against durable data under locks.
///
/// Enforced: parent manifest presence/identity/generation/provenance/card
/// agreement, its OWN sealed digest chain (`manifest_digest` over its ordered
/// reference digests), every referenced segment passing its LOCAL seal, and
/// finally the proof's own `archive_digest` reproducing from every recorded
/// dimension PLUS the recomputed chain digest. Any tampering of identities,
/// keys, hashes, compiler stamps or the chain itself fails closed here.
pub async fn verify_authorization_archive_proof_in_tx(
    tx: &mut Transaction<'_, MySql>,
    proof: &AuthorizationArchiveManifestProof,
) -> Result<(), AuthorizationProjectionError> {
    let parent = fetch_manifest_for_update(tx, proof.archived_manifest_id)
        .await?
        .ok_or_else(|| {
            AuthorizationProjectionError::Corrupt(
                "code=authorization_projection.archive_parent_missing".to_owned(),
            )
        })?;
    if parent.decode_identity()? != proof.identity {
        return Err(AuthorizationProjectionError::IdentityMismatch(
            "code=authorization_projection.archive_parent_identity_mismatch".to_owned(),
        ));
    }
    if parent.decode_generations()?.0 != proof.archived_generation {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.archive_parent_generation_mismatch".to_owned(),
        ));
    }
    if parent.event_id != proof.event_id || parent.operation_id != proof.operation_id {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.archive_parent_provenance_mismatch".to_owned(),
        ));
    }
    if parent.card_id != proof.card_id {
        return Err(AuthorizationProjectionError::IdentityMismatch(
            "code=authorization_projection.archive_parent_card_scope_mismatch".to_owned(),
        ));
    }
    // The archived parent manifest's OWN durable fence must equal the proof's
    // recorded fence; anything else means the proof does not describe this
    // parent and no archive evidence may be accepted from it.
    if parent.decode_revoke_fence()? != proof.archived_revoke_fence {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.archive_parent_fence_mismatch".to_owned(),
        ));
    }

    let references = load_and_verify_references(
        tx,
        proof.archived_manifest_id,
        &proof.identity,
        parent.card_id,
        proof.archived_generation,
        &proof.event_id,
        &proof.operation_id,
    )
    .await?;
    for reference in &references {
        fetch_and_verify_segment_row(tx, reference, &proof.identity).await?;
    }
    // Re-proves the parent manifest's own global hash chain and hands back the
    // pinned chain digest that enters the archive seal.
    verify_parent_manifest_chain(&parent, &references)?;
    let (_, _, chain_digest) = parent.decode_hashes()?;

    let material = ArchiveProofMaterial {
        identity: &proof.identity,
        card_id: proof.card_id,
        archived_manifest_id: proof.archived_manifest_id,
        archived_generation: proof.archived_generation,
        event_id: &proof.event_id,
        operation_id: &proof.operation_id,
        archive_key: &proof.archive_key,
        archived_revoke_fence: proof.archived_revoke_fence,
        semantic_hash: &proof.semantic_hash,
        dependency_hash: &proof.dependency_hash,
        compiler_version: &proof.compiler_version,
    };
    let expected = material.archive_digest(&chain_digest)?;
    if proof.archive_digest != expected {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.archive_proof_digest_seal_broken".to_owned(),
        ));
    }
    Ok(())
}

/// Pure fail-closed re-proof of one archive PROOF request against the LOCKED
/// archived parent manifest row (record path).
///
/// Enforced dimensions: identity, generation, `COMMITTED`/`SUPERSEDED`
/// lifecycle, event/operation provenance, card scope, the parent's own
/// durable revoke fence, and — as explicit defense in depth beyond the sealed
/// `manifest_digest` chain — the parent's semantic hash, dependency hash and
/// compiler version compared directly against the request. Any divergence
/// refuses the proof with a stable machine code before any proof material is
/// derived or written.
fn prove_archive_proof_request_against_parent_manifest(
    request: &AuthorizationArchiveProofRequest,
    semantic_hash: &Sha256Digest,
    dependency_hash: &Sha256Digest,
    parent: &ManifestRawSqlRow,
) -> Result<(), AuthorizationProjectionError> {
    if parent.decode_identity()? != request.identity {
        return Err(AuthorizationProjectionError::IdentityMismatch(
            "code=authorization_projection.archive_parent_identity_mismatch".to_owned(),
        ));
    }
    if parent.decode_generations()?.0 != request.archived_generation {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.archive_parent_generation_mismatch".to_owned(),
        ));
    }
    if parent.status != MANIFEST_STATUS_COMMITTED && parent.status != MANIFEST_STATUS_SUPERSEDED {
        return Err(AuthorizationProjectionError::NotReady(format!(
            "code=authorization_projection.archive_parent_not_archivable;status={}",
            parent.status
        )));
    }
    if parent.event_id != request.event_id || parent.operation_id != request.operation_id {
        return Err(AuthorizationProjectionError::IdentityMismatch(
            "code=authorization_projection.archive_parent_provenance_mismatch".to_owned(),
        ));
    }
    if parent.card_id != request.card_id {
        return Err(AuthorizationProjectionError::IdentityMismatch(
            "code=authorization_projection.archive_parent_card_scope_mismatch".to_owned(),
        ));
    }
    // The recorded fence must equal the superseded parent manifest's OWN
    // durable value: the caller copies it from locked evidence, never guesses.
    if parent.decode_revoke_fence()? != request.archived_revoke_fence {
        return Err(AuthorizationProjectionError::ImmutableConflict(
            "code=authorization_projection.archive_parent_fence_mismatch".to_owned(),
        ));
    }
    // Defense in depth: the chain digest already seals these columns, but the
    // direct comparisons refuse any drifted hash or compiler stamp explicitly
    // and with their own stable machine codes.
    if parent.semantic_hash.as_slice() != semantic_hash.as_bytes().as_slice() {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.archive_parent_semantic_hash_mismatch".to_owned(),
        ));
    }
    if parent.dependency_hash.as_slice() != dependency_hash.as_bytes().as_slice() {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.archive_parent_dependency_hash_mismatch".to_owned(),
        ));
    }
    if parent.compiler_version != request.compiler_version {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.archive_parent_compiler_mismatch".to_owned(),
        ));
    }
    Ok(())
}

/// Record the DB-resident durable archive proof for one superseded generation.
///
/// Preconditions enforced INSIDE the caller's transaction (in order):
/// 1. the archived parent manifest is locked FIRST (the archive family's
///    unified parent-manifest→outbox lock order — proof recording must never
///    take the outbox lock before the parent) and strictly re-proven against
///    the request via
///    [`prove_archive_proof_request_against_parent_manifest`]: `COMMITTED`/
///    `SUPERSEDED` lifecycle, identity/generation/provenance/card/fence
///    agreement PLUS direct semantic-hash, dependency-hash and compiler
///    comparisons as defense in depth;
/// 2. the paired outbox intent exists under `uk_aao_generation`, is not
///    `QUARANTINED`, and agrees with the request on EVERY immutable field;
/// 3. when no proof row exists yet, the intent may not be in a fabricated
///    `SUCCEEDED` state — legacy self-proving successes cannot be laundered;
/// 4. the parent manifest's own sealed `manifest_digest` recomputes over its
///    ordered references AND equals the caller-supplied chain-digest
///    expectation; EVERY referenced segment is re-read and passes its LOCAL
///    seal;
/// 5. only then is the `authorization_archive_manifest` row inserted directly
///    in the terminal `ARCHIVED` state with its exclusive `archived_at`
///    stamp. Unique-key races are resolved by proving byte-for-byte replay
///    equivalence (including the derived seal) or refusing with
///    [`AuthorizationProjectionError::ImmutableConflict`] /
///    [`AuthorizationProjectionError::DuplicateRow`].
pub async fn record_authorization_archive_proof_in_tx(
    tx: &mut Transaction<'_, MySql>,
    request: &AuthorizationArchiveProofRequest,
) -> Result<AuthorizationArchiveManifestProof, AuthorizationProjectionError> {
    request.identity.validate()?;
    validated_option_card_id(request.card_id)?;
    positive_i64(request.archived_manifest_id, "archived_manifest_id")?;
    if request.archived_generation == 0 {
        return Err(scope_violation(
            "authorization_projection.invalid_archived_generation",
        ));
    }
    bind_u64(request.archived_generation, "archive.generation")?;
    validated_text(&request.event_id, MAX_EVENT_ID_LENGTH, "event_id")?;
    validated_text(
        &request.operation_id,
        MAX_GRANT_OPERATION_ID_LENGTH,
        "operation_id",
    )?;
    validated_text(&request.archive_key, MAX_ARCHIVE_KEY_LENGTH, "archive_key")?;
    validated_text(
        &request.compiler_version,
        MAX_COMPILER_VERSION_LENGTH,
        "compiler_version",
    )?;
    bind_u64(
        request.archived_revoke_fence,
        "archive.archived_revoke_fence",
    )?;
    let semantic_hash = Sha256Digest::from_hex(&request.semantic_hash_hex)?;
    let dependency_hash = Sha256Digest::from_hex(&request.dependency_hash_hex)?;
    let claimed_chain_digest = Sha256Digest::from_hex(&request.manifest_chain_digest_hex)?;

    // (1) Lock the archived parent manifest FIRST: the archive family shares
    // one unified parent-manifest→outbox lock order, so a concurrent
    // publish/ensure (parent → outbox) can never AB-BA against proof
    // recording — the outbox intent below is never locked before the parent.
    let parent = fetch_manifest_for_update(tx, request.archived_manifest_id)
        .await?
        .ok_or_else(|| {
            AuthorizationProjectionError::Corrupt(
                "code=authorization_projection.archive_parent_missing".to_owned(),
            )
        })?;

    // (2) Lock the paired outbox intent through the stable generation key.
    let intent_raw =
        fetch_archive_intent_by_generation(tx, &request.identity, request.archived_generation)
            .await?
            .ok_or_else(|| {
                AuthorizationProjectionError::NotReady(
                    "code=authorization_projection.archive_proof_without_intent".to_owned(),
                )
            })?;
    let intent = intent_raw.decode()?;
    if matches!(intent.status, AuthorizationArchiveOutboxStatus::Quarantined) {
        return Err(AuthorizationProjectionError::ImmutableConflict(
            "code=authorization_projection.archive_proof_intent_quarantined".to_owned(),
        ));
    }
    let material = ArchiveProofMaterial {
        identity: &request.identity,
        card_id: request.card_id,
        archived_manifest_id: request.archived_manifest_id,
        archived_generation: request.archived_generation,
        event_id: &request.event_id,
        operation_id: &request.operation_id,
        archive_key: &request.archive_key,
        archived_revoke_fence: request.archived_revoke_fence,
        semantic_hash: &semantic_hash,
        dependency_hash: &dependency_hash,
        compiler_version: &request.compiler_version,
    };

    // Full-dimensional cross-check request ↔ locked intent.
    intent_raw.assert_equivalent_replay(
        // The typed append-request shape differs from the proof request, so
        // build the comparison explicitly field by field.
        &AuthorizationArchiveIntentAppendRequest {
            identity: request.identity.clone(),
            card_id: request.card_id,
            archived_manifest_id: request.archived_manifest_id,
            archived_generation: request.archived_generation,
            event_id: request.event_id.clone(),
            operation_id: request.operation_id.clone(),
            archive_key: request.archive_key.clone(),
            semantic_hash_hex: request.semantic_hash_hex.clone(),
            dependency_hash_hex: request.dependency_hash_hex.clone(),
            compiler_version: request.compiler_version.clone(),
            archived_revoke_fence: request.archived_revoke_fence,
        },
        &semantic_hash,
        &dependency_hash,
    )?;

    // (3) Strictly re-prove the LOCKED archived parent manifest against the
    // request (lifecycle, provenance, fence, plus the direct
    // semantic/dependency/compiler defense dimensions) before its whole chain
    // is re-derived.
    prove_archive_proof_request_against_parent_manifest(
        request,
        &semantic_hash,
        &dependency_hash,
        &parent,
    )?;
    let references = load_and_verify_references(
        tx,
        request.archived_manifest_id,
        &request.identity,
        parent.card_id,
        request.archived_generation,
        &request.event_id,
        &request.operation_id,
    )
    .await?;
    for reference in &references {
        fetch_and_verify_segment_row(tx, reference, &request.identity).await?;
    }
    // Parent chain self-seal plus pinned chain-digest agreement.
    verify_parent_manifest_chain(&parent, &references)?;
    let (_, _, stored_chain_digest) = parent.decode_hashes()?;
    if stored_chain_digest != claimed_chain_digest {
        return Err(AuthorizationProjectionError::ImmutableConflict(
            "code=authorization_projection.archive_chain_digest_mismatch".to_owned(),
        ));
    }
    let archive_digest = material.archive_digest(&stored_chain_digest)?;

    // Existing proof? Then only immutable equality survives replay checks.
    if let Some(existing) =
        fetch_archive_manifest_by_generation(tx, &request.identity, request.archived_generation)
            .await?
    {
        material.assert_equivalent_replay(&existing, &stored_chain_digest)?;
        return Ok(existing);
    }
    // A SUCCEEDED intent WITHOUT a durable proof is corrupt/legacy state and
    // must never be regularized retroactively.
    if matches!(intent.status, AuthorizationArchiveOutboxStatus::Succeeded) {
        return Err(AuthorizationProjectionError::ImmutableConflict(
            "code=authorization_projection.archive_outbox_success_without_durable_proof".to_owned(),
        ));
    }

    // (5) Insert the terminal proof; races prove byte-for-byte equivalence.
    let inserted = sqlx::query(ARCHIVE_MANIFEST_INSERT_SQL)
        .bind(request.identity.tenant_id)
        .bind(request.card_id)
        .bind(&request.identity.aggregate_type)
        .bind(request.identity.aggregate_id)
        .bind(request.archived_manifest_id)
        .bind(bind_u64(request.archived_generation, "archive.generation")?)
        .bind(&request.event_id)
        .bind(&request.operation_id)
        .bind(&request.archive_key)
        .bind(archive_digest.as_bytes().to_vec())
        .bind(semantic_hash.as_bytes().to_vec())
        .bind(dependency_hash.as_bytes().to_vec())
        .bind(&request.compiler_version)
        .bind(bind_u64(
            request.archived_revoke_fence,
            "archive.archived_revoke_fence",
        )?)
        .execute(&mut **tx)
        .await;
    match inserted {
        Ok(result) => {
            if result.rows_affected() != 1 {
                return Err(AuthorizationProjectionError::DuplicateRow(
                    "code=authorization_projection.archive_manifest_insert_not_applied".to_owned(),
                ));
            }
            // Read the authoritative row back so the returned proof carries the
            // real server-stamped `archived_at` and passes full decoding.
            fetch_archive_manifest_by_generation(tx, &request.identity, request.archived_generation)
                .await?
                .ok_or_else(|| {
                    AuthorizationProjectionError::Corrupt(
                        "code=authorization_projection.archive_manifest_readback_missing"
                            .to_owned(),
                    )
                })
        }
        Err(error) => {
            if !unique_violation(&error) {
                return Err(error.into());
            }
            // uk_aam_generation raced first; otherwise disambiguate via
            // uk_aam_archive_digest so the proven winner is always identified.
            let winner = fetch_archive_manifest_by_generation(
                tx,
                &request.identity,
                request.archived_generation,
            )
            .await?
            .or(fetch_archive_manifest_by_digest(
                tx,
                request.identity.tenant_id,
                &archive_digest,
            )
            .await?);
            let Some(winner) = winner else {
                return Err(AuthorizationProjectionError::DuplicateRow(
                    "code=authorization_projection.archive_manifest_race_unknown_winner".to_owned(),
                ));
            };
            material.assert_equivalent_replay(&winner, &stored_chain_digest)?;
            Ok(winner)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Combined single-transaction projector contract
// ─────────────────────────────────────────────────────────────────────────────

/// One fully assembled single-transaction projector command.
///
/// Assembly is pure/manual; execution happens only via
/// [`project_authorization_delta_in_tx`], which runs the fixed step order and
/// verifies each pairing. Workers must not hand-write their own sequence.
#[derive(Debug, Clone)]
pub struct DeltaProjectorPublishCommand {
    /// Live delta lease presented by the claiming transaction. It will be
    /// RE-verified inside this transaction before anything writes.
    pub delta_lease_identity: DeltaLeaseIdentity,
    pub expectation: DeltaProjectorExpectation,
    pub fences: PublishRevokeFenceEvidence,
    pub mode: CompileModeEvidence,
    /// Staging plan for `expectation`'s target generation; cross-checked
    /// against the expectation before use.
    pub stage: AuthorizationStageRequest,
    /// Optional reference-count pin forwarded to finalize.
    pub finalize_expected_reference_count: Option<u64>,
    /// Impact plan for the processed delta; cross-checked (versions/hashes/
    /// identities) against the expectation.
    pub impact_plan: AuthorizationImpactPlanAppendRequest,
    /// Owner string reused for the manifest BUILDING lease.
    pub manifest_lease_owner: String,
    /// Manifest lease duration in seconds (1..=[`MAX_MANIFEST_LEASE_SECONDS`]).
    pub manifest_lease_seconds: i64,
}

/// Evidence of one successful single-transaction projector run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaProjectorPublishOutcome {
    pub impact_plan: AuthorizationImpactPlanOutcome,
    pub stage: AuthorizationStageOutcome,
    /// `None` when the publication had no parent (first ever) and therefore
    /// correctly produced `NoArchiveRequired` instead of an intent.
    pub archive_intent: Option<AuthorizationArchiveIntentOutcome>,
    pub publish: AuthorizationPublishOutcome,
}

/// Pure structural consistency checks over an assembled command (before any
/// SQL runs).
fn validate_projector_command_shape(
    command: &DeltaProjectorPublishCommand,
) -> Result<(), AuthorizationProjectionError> {
    command.expectation.identity.validate()?;
    validated_option_card_id(command.expectation.card_id)?;
    command.stage.identity.validate()?;
    command.impact_plan.identity.validate()?;

    if command.stage.identity != command.expectation.identity
        || command.impact_plan.identity != command.expectation.identity
    {
        return Err(scope_violation(
            "authorization_projection.command_identity_mismatch",
        ));
    }
    if command.stage.card_id != command.expectation.card_id
        || command.impact_plan.card_id != command.expectation.card_id
    {
        return Err(scope_violation(
            "authorization_projection.command_card_scope_mismatch",
        ));
    }
    if command.stage.event_id != command.expectation.event_id
        || command.impact_plan.event_id != command.expectation.event_id
        || command.stage.operation_id != command.expectation.operation_id
        || command.impact_plan.operation_id != command.expectation.operation_id
    {
        return Err(scope_violation(
            "authorization_projection.command_provenance_mismatch",
        ));
    }
    if command.stage.source_generation != command.expectation.source_generation {
        return Err(scope_violation(
            "authorization_projection.command_source_generation_mismatch",
        ));
    }
    if command.stage.semantic_hash_hex != command.expectation.semantic_hash_hex
        || command.stage.dependency_hash_hex != command.expectation.dependency_hash_hex
        || command.impact_plan.semantic_hash_hex != command.expectation.semantic_hash_hex
        || command.impact_plan.dependency_hash_hex != command.expectation.dependency_hash_hex
    {
        return Err(scope_violation(
            "authorization_projection.command_hash_mismatch",
        ));
    }
    if command.stage.compiler_version != command.expectation.compiler_version
        || command.impact_plan.compiler_version != command.expectation.compiler_version
    {
        return Err(scope_violation(
            "authorization_projection.command_compiler_mismatch",
        ));
    }
    // Plan root must speak about the SAME delta version window as the claim.
    if command.impact_plan.base_version != command.expectation.base_version
        || command.impact_plan.target_version != command.expectation.target_version
    {
        return Err(scope_violation(
            "authorization_projection.command_version_window_mismatch",
        ));
    }
    validate_compile_mode_evidence(&command.mode)?;
    // The staged manifest must carry exactly the fence being published;
    // anything else would desynchronize the BUILDING row from the later
    // fence-pinned promotion (which fails closed at SQL level anyway).
    if command.stage.revoke_fence != command.fences.new_revoke_fence {
        return Err(scope_violation(
            "authorization_projection.command_stage_revoke_fence_mismatch",
        ));
    }
    // Structural dry-run of the item normalization keeps malformed plans away
    // from SQL entirely; normalize_impact_items enforces the rest.
    normalize_impact_items(&command.impact_plan.items)?;
    Ok(())
}

/// Execute the documented single-transaction projector sequence:
///
/// 1. re-lock and strictly verify the claimed delta lease (fail-closed on
///    expiry/theft/status drift — a claim ACK alone is never durable proof);
/// 2. cross-validate claimed delta ↔ expectation ↔ fences ↔ compile mode;
/// 3. observe (and lock) the current pointer; verify the impact-plan request
///    speaks about the observed base generation;
/// 4. persist or idempotently resume the impact plan;
/// 5. stage/finalize the target manifest chain (staging locks pointer +
///    parents internally; the BUILDING manifest lease is claimed and consumed
///    by finalize);
/// 6. append the archive intent for the superseding publication when (and
///    only when) a parent exists — strictly BEFORE the pointer CAS, remaining
///    `PENDING` because intent ≠ archive proof;
/// 7. publish the target manifest through the affected-rows-exactly-one
///    pointer CAS (failure rolls the WHOLE transaction back);
/// 8. mark the impact plan `SUCCEEDED` and complete the delta lease.
///
/// Every zero-row CAS outcome, immutable drift or lease loss aborts with an
/// explicit error so the caller can roll back atomically. There is no
/// generalized "AlreadyCurrent converts into success" shortcut: only a full
/// `COMMITTED` manifest at the expected generation behind the moved pointer
/// counts as success. Nothing commits; the caller owns the transaction.
pub async fn project_authorization_delta_in_tx(
    tx: &mut Transaction<'_, MySql>,
    command: &DeltaProjectorPublishCommand,
) -> Result<DeltaProjectorPublishOutcome, AuthorizationProjectionError> {
    validate_projector_command_shape(command)?;

    // (1) Lock + strictly re-verify the claimed delta lease.
    let claimed = crate::grant_repository::load_claimed_delta_event_for_update_in_tx(
        tx,
        &command.delta_lease_identity,
    )
    .await?;

    // (2) Linkage between what was claimed and what is being published.
    let delta_view = AuthorizationDeltaLinkageView::from_claimed_row(&claimed)?;
    validate_delta_projector_linkage(
        &delta_view,
        &command.expectation,
        command.fences,
        &command.mode,
    )?;

    // (3) Observe the (locked) current pointer for base-generation decisions.
    let base_pointer = lock_current_pointer_in_tx(tx, &command.expectation.identity).await?;
    let observed_base_generation = base_pointer
        .as_ref()
        .map(|pointer| pointer.current_generation)
        .unwrap_or(0);
    if command.impact_plan.base_generation != observed_base_generation {
        return Err(scope_violation(
            "authorization_projection.command_base_generation_mismatch",
        ));
    }
    // Mandatory fence provenance: the AUTHORITATIVE previous fence is read
    // from the locked current pointer (`None` ⇒ 0) and the command evidence
    // must state exactly that value — it can no longer be forged, defaulted
    // or reconstructed from retained caller history. A restart therefore
    // reconciles against DB rows alone.
    let authoritative_previous = base_pointer
        .as_ref()
        .map(|pointer| (pointer.revoke_fence, pointer.revoke_fence_proven));
    validate_publish_previous_fence_authority(
        authoritative_previous.map(|(fence, _)| fence),
        command.fences.previous_revoke_fence,
    )?;
    // A live pointer is usable only after its durable fence history has been
    // proven. A proven zero is a valid initial fence and may advance normally;
    // an unproven legacy row remains blocked until explicit rehearsal.
    //
    // The monotonicity check uses the EFFECTIVE publication fence: the delta
    // row's revoke_fence is its creation-time floor, and the worker stamps
    // `new_revoke_fence = max(observed frontier, delta fence)`. A delta whose
    // floor fell behind the pointer because SIBLING deltas published first is
    // publishable at the current frontier; rejecting on the raw row fence
    // would wedge it permanently (fence_regression loop with a stale world).
    // If the pointer moved again AFTER assembly, the effective fence is still
    // behind and the failure maps to a fresh-world retry upstream.
    validate_zero_sentinel_fence_history(
        command.fences.new_revoke_fence.max(delta_view.revoke_fence),
        authoritative_previous,
    )?;
    validate_first_publication_previous_fence(
        base_pointer.is_some(),
        command.fences.previous_revoke_fence,
    )?;

    // (4) Durable impact plan (resume-safe).
    let impact_plan = ensure_authorization_impact_plan_in_tx(tx, &command.impact_plan).await?;

    // (5) Stage the target manifest, claim the BUILDING lease and finalize.
    let stage = stage_authorization_manifest_in_tx(tx, &command.stage).await?;
    let manifest_grant = claim_authorization_manifest_in_tx(
        tx,
        &command.expectation.identity,
        command.stage.target_generation,
        &command.manifest_lease_owner,
        command.manifest_lease_seconds,
    )
    .await?
    .ok_or_else(|| {
        AuthorizationProjectionError::NotReady(
            "code=authorization_projection.projector_manifest_not_claimable".to_owned(),
        )
    })?;
    finalize_authorization_manifest_in_tx(
        tx,
        &AuthorizationFinalizeRequest {
            identity: command.expectation.identity.clone(),
            target_generation: command.stage.target_generation,
            manifest_id: stage.manifest_id,
            lease_owner: manifest_grant.lease_owner.clone(),
            lease_token: manifest_grant.lease_token.clone(),
            expected_cas_version: manifest_grant.cas_version_after_claim,
            expected_reference_count: command.finalize_expected_reference_count,
        },
    )
    .await?;

    // (6) Archive intent for the superseded parent — only when one exists.
    let archive_intent = match decide_archive_intent(stage.base_pointer.as_ref()) {
        ArchiveIntentRequirement::NoArchiveRequired => None,
        ArchiveIntentRequirement::Required { parent_pointer } => {
            let request = AuthorizationArchiveIntentAppendRequest {
                identity: command.expectation.identity.clone(),
                card_id: command.expectation.card_id,
                archived_manifest_id: parent_pointer.manifest_id,
                archived_generation: parent_pointer.current_generation,
                event_id: parent_pointer.event_id.clone(),
                operation_id: parent_pointer.operation_id.clone(),
                archive_key: derive_archive_key(
                    &command.expectation.identity,
                    parent_pointer.current_generation,
                )?,
                semantic_hash_hex: parent_pointer.semantic_hash.as_hex(),
                dependency_hash_hex: parent_pointer.dependency_hash.as_hex(),
                compiler_version: parent_pointer.compiler_version.clone(),
                // Copied from the LOCKED durable pointer evidence; never
                // guessed by the caller.
                archived_revoke_fence: parent_pointer.revoke_fence,
            };
            Some(ensure_authorization_archive_intent_in_tx(tx, &request).await?)
        }
    };

    // (7) Atomic publication through the affected-rows-exactly-one CAS.
    let publish = publish_current_pointer_in_tx(
        tx,
        &AuthorizationPublishRequest {
            identity: command.expectation.identity.clone(),
            card_id: command.expectation.card_id,
            target_manifest_id: stage.manifest_id,
            target_generation: command.stage.target_generation,
            current_pointer: stage.base_pointer.as_ref().map(|pointer| pointer.as_view()),
            expected_target_semantic_hash_hex: command.expectation.semantic_hash_hex.clone(),
            expected_target_dependency_hash_hex: command.expectation.dependency_hash_hex.clone(),
            expected_target_compiler_version: command.expectation.compiler_version.clone(),
            fences: command.fences,
        },
    )
    .await?;

    // (8) Terminal bookkeeping inside the same atomic unit.
    complete_authorization_impact_plan_in_tx(
        tx,
        impact_plan.plan_id,
        &command.expectation.identity,
        &command.expectation.event_id,
    )
    .await?;
    // Final ownership heartbeat: all source/projection/pointer writes above are
    // still inside this transaction, and the claimed delta row remains locked.
    // Renew immediately before terminal completion so a long publication cannot
    // pass the hot-state CAS and then fail only because the original lease window
    // elapsed. A lost lease aborts the transaction and preserves UNKNOWN safety.
    crate::grant_repository::extend_delta_event_lease(
        &mut **tx,
        &command.delta_lease_identity,
        120,
    )
    .await?;
    crate::grant_repository::complete_delta_event(&mut **tx, &command.delta_lease_identity).await?;

    Ok(DeltaProjectorPublishOutcome {
        impact_plan,
        stage,
        archive_intent,
        publish,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant_repository::DELTA_STATUS_QUARANTINED;
    use astral_types::{
        BindingLayer, DomainScopeRequirement, GrantEffect, GrantId, GrantProvenance, GrantRevision,
        GrantSourceKind, GrantState, TenantScope, ValidityWindow,
    };

    /// 维度守卫测试的“字段名 + 篡改函数”用例（type_complexity 别名）。
    type DimensionCase<'a, T> = (&'a str, Box<dyn Fn(&mut T) + 'a>);

    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// 源码锚定守卫：source-freshness 门（撤权类未发布 delta 探针）只允许
    /// 出现在正式证据读入口（`load_published_card_grant_evidence_in_tx`）。
    /// projector 的 frontier/发布路径（`read_published_authorization_state_in_tx`
    /// / `load_published_aggregate_frontier_in_tx` / `project_authorization_delta_in_tx`）
    /// 在发布时自身 delta 尚未 `SUCCEEDED`——若经过探针会被自己自锁，永远
    /// 无法发布。该不变式由本测试钉死，防止未来重构误接线。另钉两个语义：
    /// 探针必须是非锁定读（锁定读会与发布者在 delta 行锁上互饿——P3 风暴
    /// 实测教训），且必须只拦撤权类（REMOVE/REVOKE 或 fence 超前）。
    #[test]
    fn source_freshness_gate_is_reader_only_and_never_on_projector_paths() {
        let source = include_str!("authorization_projection_repository.rs");
        // 只检查生产代码区域：测试模块自身提到探针名是合法的（本守卫测试）。
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production region must exist");

        // 读取器函数体：探针必须存在。
        let reader_body = production
            .split("pub async fn load_published_card_grant_evidence_in_tx")
            .nth(1)
            .and_then(|body| {
                body.split("\npub async fn load_published_card_grant_evidence(")
                    .next()
            })
            .expect("strict evidence reader must exist");
        assert!(
            reader_body.contains("card_has_unsafe_pending_delta_in_tx"),
            "strict evidence reader must gate on unsafe pending deltas"
        );

        // 探针定义体：走钉死的 SQL 常量。
        let probe_body = production
            .split("async fn card_has_unsafe_pending_delta_in_tx")
            .nth(1)
            .and_then(|body| body.split("\nasync fn ").next())
            .expect("freshness probe must exist");
        assert!(
            probe_body.contains("FRESHNESS_GATE_PROBE_SQL"),
            "probe must run through the pinned SQL constant"
        );
        assert!(
            !FRESHNESS_GATE_PROBE_SQL.contains("FOR UPDATE"),
            "probe must be NON-LOCKING: a locking probe starves the publisher \
             on the delta row lock (P3 storm lesson)"
        );
        assert!(
            FRESHNESS_GATE_PROBE_SQL.contains("invalidates_published_evidence <> 0"),
            "probe must use the durable row-level published-evidence invalidation fact"
        );
        assert!(
            FRESHNESS_GATE_PROBE_SQL.contains("status <> 'SUCCEEDED'"),
            "probe must consider PENDING/LEASED/QUARANTINED deltas"
        );
        assert!(
            FRESHNESS_GATE_PROBE_SQL.contains("event_type IN ('REMOVE', 'REVOKE')"),
            "probe must block grant-removing deltas (stale-ALLOW direction)"
        );
        assert!(
            FRESHNESS_GATE_PROBE_SQL.contains("revoke_fence > COALESCE"),
            "probe must block fence-raising deltas beyond the published fence"
        );
        // 2026-09-04 修订：探针必须同时覆盖卡作用域与 aggregate-wide（NULL card）
        // 的撤权类未发布 delta——aggregate-wide 的 REMOVE/REVOKE/fence 抬升对
        // 本卡读取同样是 stale-ALLOW 方向，普通 `card_id = ?` 会漏掉它们。
        assert!(
            FRESHNESS_GATE_PROBE_SQL.contains("(card_id = ? OR card_id IS NULL)"),
            "probe must cover both the card scope and aggregate-wide (NULL card) deltas"
        );
        // 已发布水位子查询必须 NULL-safe（<=>）：NULL card 行对 NULL card 已发布
        // 水位比较；普通 `=` 使 `NULL = NULL` 恒 UNKNOWN → 水位折叠为 0，令已被
        // 已发布水位覆盖的 aggregate-wide delta 误报 PENDING。
        assert!(
            FRESHNESS_GATE_PROBE_SQL.contains("p.card_id <=> authorization_delta_event.card_id"),
            "published-watermark correlation must be NULL-safe (<=>), never plain ="
        );
        assert!(
            !FRESHNESS_GATE_PROBE_SQL.contains("p.card_id = authorization_delta_event"),
            "plain = watermark correlation must not survive the NULL-safe fix"
        );

        // projector 路径：任何函数体都不得引用探针。
        for projector_fn in [
            "pub async fn read_published_authorization_state_in_tx",
            "pub async fn load_published_aggregate_frontier_in_tx",
            "pub async fn project_authorization_delta_in_tx",
            "pub async fn publish_current_pointer_in_tx",
        ] {
            let body = production
                .split(projector_fn)
                .nth(1)
                .and_then(|body| body.split("\npub ").next())
                .unwrap_or_else(|| panic!("{projector_fn} must exist"));
            assert!(
                !body.contains("card_has_unsafe_pending_delta_in_tx"),
                "{projector_fn} must never run the source-freshness gate; \
                 the projector would self-deadlock on its own unpublished delta"
            );
        }
    }

    fn tenant() -> TenantScope {
        TenantScope::new(7, Some(11)).unwrap()
    }

    fn grant(unique_tail: u16) -> CanonicalGrant {
        CanonicalGrant {
            grant_id: GrantId::parse(&format!(
                "550e8400-e29b-41d4-a716-44665544{unique_tail:04x}"
            ))
            .unwrap(),
            revision: GrantRevision::initial(),
            state: GrantState::Active,
            source_kind: GrantSourceKind::RuleSet,
            binding_layer: BindingLayer::Base,
            tenant: tenant(),
            card_id: 17,
            user_id: 42,
            resource: "learn_subject:1".to_owned(),
            action: "read".to_owned(),
            effect: GrantEffect::Allow,
            validity: ValidityWindow::perpetual(),
            provenance: GrantProvenance {
                source_id: "rule-set-entry-9".to_owned(),
                source_entry: None,
                binding_id: Some("binding-3".to_owned()),
                delegation_id: None,
                operation_id: "op-1".to_owned(),
                event_id: Some("event-1".to_owned()),
                actor_user_id: Some(42),
            },
        }
    }

    fn identity() -> ProjectionAggregateIdentity {
        ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap()
    }

    fn digest_input<'a>(digest_hexes: Vec<String>) -> ManifestDigestInput<'a> {
        ManifestDigestInput {
            tenant_id: 7,
            aggregate_type: "CARD",
            aggregate_id: 17,
            card_id: None,
            generation: 3,
            source_generation: 9,
            projected_generation: 9,
            event_id: "event-stage",
            operation_id: "op-stage",
            semantic_hash_hex: HASH_A,
            dependency_hash_hex: HASH_B,
            compiler_version: "phase2-authorization-kernel-v1",
            parent_manifest_id: Some(2),
            revoke_fence: 1,
            segment_content_digests_hex: digest_hexes,
        }
    }

    // ── Status purity ───────────────────────────────────────────────────────

    #[test]
    fn status_parse_is_explicit_and_unknown_values_fail_closed() {
        for (text, expected) in [
            ("BUILDING", AuthorizationManifestStatus::Building),
            ("READY", AuthorizationManifestStatus::Ready),
            ("COMMITTED", AuthorizationManifestStatus::Committed),
            ("SUPERSEDED", AuthorizationManifestStatus::Superseded),
            ("QUARANTINED", AuthorizationManifestStatus::Quarantined),
        ] {
            assert_eq!(AuthorizationManifestStatus::parse(text).unwrap(), expected);
            assert_eq!(expected.as_str(), text);
        }
        assert!(
            AuthorizationManifestStatus::parse("ready").is_err()
                && AuthorizationManifestStatus::parse("").is_err()
                && AuthorizationManifestStatus::parse("ARCHIVED").is_err()
        );
    }

    #[test]
    fn status_transition_table_matches_documented_edges() {
        use AuthorizationManifestStatus::*;
        assert!(Building.can_transition_to(Ready));
        assert!(Building.can_transition_to(Quarantined));
        assert!(Ready.can_transition_to(Committed));
        assert!(Ready.can_transition_to(Quarantined));
        assert!(Committed.can_transition_to(Superseded));
        assert!(Committed.can_transition_to(Quarantined));
        for (from, to) in [
            (Building, Committed),
            (Building, Superseded),
            (Ready, Ready),
            (Ready, Superseded),
            (Building, Building),
            (Committed, Committed),
            (Superseded, Ready),
            (Superseded, Quarantined),
            (Quarantined, Building),
            (Quarantined, Ready),
        ] {
            assert!(
                !from.can_transition_to(to),
                "{from:?} -> {to:?} must be refused"
            );
            assert!(from.validate_transition(to).is_err());
        }
        assert!(Building.validate_transition(Ready).is_ok());
    }

    #[test]
    fn digest_codec_round_trip_rejects_uppercase_wrong_length_and_noncanon_uuids() {
        let encoded = Sha256Digest::from_hex(HASH_A).unwrap();
        assert_eq!(encoded.as_hex(), HASH_A);
        assert_eq!(
            Sha256Digest::from_bytes(encoded.as_bytes().to_vec()).unwrap(),
            encoded
        );

        assert!(Sha256Digest::from_hex(&HASH_A.to_ascii_uppercase()).is_err());
        assert!(Sha256Digest::from_hex(&HASH_A[..63]).is_err());
        assert!(Sha256Digest::from_hex(&format!("{HASH_A}ff")).is_err());
        assert!(Sha256Digest::from_hex(&"g".repeat(64)).is_err());

        // Canonical lowercase spelling survives; uppercase spellings do not.
        let grant_id = GrantId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert_eq!(grant_id.as_str(), "550e8400-e29b-41d4-a716-446655440000");
        assert_ne!(
            grant_id.as_str(),
            "550E8400-E29B-41D4-A716-446655440000",
            "uppercase encodings must never be treated as canonical"
        );
        assert!(GrantId::parse("00000000-0000-0000-0000-000000000000").is_err());
    }

    #[test]
    fn checked_bigint_conversions_fail_closed_on_overflow_and_negatives() {
        assert_eq!(bind_u64(i64::MAX as u64, "probe").unwrap(), i64::MAX);
        assert!(bind_u64((i64::MAX as u64) + 1, "probe").is_err());
        assert_eq!(
            read_counter_i64(i64::MAX, "probe").unwrap(),
            i64::MAX as u64
        );
        assert!(read_counter_i64(-1, "probe").is_err());
        assert!(read_counter_i64(i64::MIN, "probe").is_err());
        assert_eq!(bind_i32(i32::MAX as u64, "probe").unwrap(), i32::MAX);
        assert!(bind_i32((i32::MAX as u64) + 1, "probe").is_err());
        assert!(positive_i64(0, "probe").is_err());
        assert!(positive_i64(-5, "probe").is_err());
        assert!(validated_option_card_id(Some(3)).is_ok());
        assert!(validated_option_card_id(Some(0)).is_err());
        assert!(validated_option_card_id(None).is_ok());
    }

    // ── Payload codec ───────────────────────────────────────────────────────

    #[test]
    fn segment_payload_round_trip_is_byte_exact_and_deterministic() {
        let first = encode_segment_payload(&[grant(1), grant(2)]).unwrap();
        let second = encode_segment_payload(&[grant(1), grant(2)]).unwrap();
        assert_eq!(first, second);
        let decoded = decode_segment_payload(&first).unwrap();
        assert_eq!(decoded.len(), 2);

        // Content addressing binds the exact stored bytes.
        let digest = Sha256Digest::from_raw_bytes(sha256_digest_bytes(&first));
        assert_eq!(digest.as_hex().len(), 64);
        // Distinct payloads must address differently.
        let other = encode_segment_payload(&[grant(1)]).unwrap();
        assert_ne!(first, other);

        // Empty segments stay representable and stable.
        let empty = encode_segment_payload(&[]).unwrap();
        assert_eq!(empty, encode_segment_payload(&[]).unwrap());
        assert!(decode_segment_payload(&empty).unwrap().is_empty());
    }

    #[test]
    fn segment_payload_rejects_tampered_and_structurally_broken_bytes() {
        let canonical = encode_segment_payload(&[grant(3)]).unwrap();

        // Syntactically valid JSON whose bytes deviate from canonical form.
        let tampered = {
            let mut bytes = canonical.clone();
            bytes.insert(1, b' ');
            bytes
        };
        assert!(decode_segment_payload(&tampered).is_err());

        // Structurally invalid JSON fails closed outright.
        assert!(decode_segment_payload(b"{not json").is_err());
        assert!(decode_segment_payload(b"null").is_err());
    }

    // ── Manifest digest seal ────────────────────────────────────────────────

    #[test]
    fn manifest_digest_is_order_sensitive_and_binds_every_field() {
        let base = compute_manifest_digest(&digest_input(vec![HASH_A.to_owned()])).unwrap();
        let same = compute_manifest_digest(&digest_input(vec![HASH_A.to_owned()])).unwrap();
        assert_eq!(base, same);

        let reordered =
            compute_manifest_digest(&digest_input(vec![HASH_B.to_owned(), HASH_A.to_owned()]))
                .unwrap();
        let alternate =
            compute_manifest_digest(&digest_input(vec![HASH_A.to_owned(), HASH_B.to_owned()]))
                .unwrap();
        assert_ne!(
            reordered, alternate,
            "ordinal order participates in the seal"
        );
        assert_ne!(base, reordered);

        let empty_list = compute_manifest_digest(&digest_input(vec![])).unwrap();
        assert_ne!(empty_list, base);

        // Invalid child digest text fails closed.
        let bad_child = ManifestDigestInput {
            segment_content_digests_hex: vec!["zzzz".repeat(32)],
            ..digest_input(vec![])
        };
        assert!(compute_manifest_digest(&bad_child).is_err());

        // Uppercase child digests are refused.
        let uppercase_child = ManifestDigestInput {
            segment_content_digests_hex: vec![HASH_A.to_ascii_uppercase()],
            ..digest_input(vec![])
        };
        assert!(compute_manifest_digest(&uppercase_child).is_err());

        // A different card scope changes the seal.
        let with_card = ManifestDigestInput {
            card_id: Some(17),
            ..digest_input(vec![HASH_A.to_owned()])
        };
        assert_ne!(compute_manifest_digest(&with_card).unwrap(), base);
    }

    // ── Ordinal completeness ────────────────────────────────────────────────

    #[test]
    fn contiguous_ordinals_sum_counts_and_flag_gaps_duplicates() {
        assert_eq!(validate_contiguous_ordinals(&[]).unwrap(), 0);
        assert_eq!(
            validate_contiguous_ordinals(&[(0, 3), (1, 0), (2, 9)]).unwrap(),
            12
        );

        // Gapped sequence refuses.
        let error = validate_contiguous_ordinals(&[(0, 1), (2, 1)]).unwrap_err();
        assert!(
            matches!(error, AuthorizationProjectionError::Mapping(ref message)
            if message.contains("ordinal_gap"))
        );

        // Duplicate ordinal shifts the sequence and therefore refuses too.
        let error = validate_contiguous_ordinals(&[(0, 1), (0, 1)]).unwrap_err();
        assert!(
            matches!(error, AuthorizationProjectionError::Mapping(ref message)
            if message.contains("ordinal_gap"))
        );
    }

    // ── Reuse validation ────────────────────────────────────────────────────

    fn parent_view(
        ordinal: u64,
        identity: &ProjectionAggregateIdentity,
    ) -> (u64, ParentReferenceView) {
        (
            ordinal,
            ParentReferenceView {
                ordinal,
                identity: identity.clone(),
                segment_id: 100 + ordinal as i64,
                content_digest_hex: HASH_A.to_owned(),
            },
        )
    }

    #[test]
    fn reuse_validation_accepts_only_same_aggregate_known_ordinals() {
        let identity = identity();
        let references = vec![parent_view(0, &identity), parent_view(1, &identity)];
        let plan = vec![
            StagedSegmentContent::ReuseParent { parent_ordinal: 0 },
            StagedSegmentContent::New(vec![grant(5)]),
            StagedSegmentContent::ReuseParent { parent_ordinal: 1 },
        ];
        let (new_count, reused_count) =
            validate_staging_plan_against_parent(&identity, &plan, Some(&references)).unwrap();
        assert_eq!((new_count, reused_count), (1, 2));

        // Unknown parent ordinal fails closed.
        let unknown_plan = vec![StagedSegmentContent::ReuseParent { parent_ordinal: 9 }];
        assert!(
            validate_staging_plan_against_parent(&identity, &unknown_plan, Some(&references))
                .is_err()
        );

        // Reuse without a parent (first build) fails closed.
        assert!(validate_staging_plan_against_parent(&identity, &unknown_plan, None).is_err());

        // Cross-aggregate reuse fails closed even with an exact digest hit.
        let foreign = ProjectionAggregateIdentity::new(7, "CARD", 99).unwrap();
        let foreign_references = vec![parent_view(0, &foreign)];
        assert!(validate_staging_plan_against_parent(
            &identity,
            &unknown_plan,
            Some(&foreign_references)
        )
        .is_err());

        // Cross-tenant reuse fails closed.
        let other_tenant = ProjectionAggregateIdentity::new(8, "CARD", 17).unwrap();
        let cross_tenant_references = vec![parent_view(0, &other_tenant)];
        assert!(validate_staging_plan_against_parent(
            &identity,
            &unknown_plan,
            Some(&cross_tenant_references)
        )
        .is_err());
    }

    #[test]
    fn reuse_validation_caps_plan_size() {
        let identity = identity();
        let oversized: Vec<StagedSegmentContent> = (0..MAX_SEGMENTS_PER_MANIFEST + 1)
            .map(|_| StagedSegmentContent::New(vec![]))
            .collect();
        assert!(validate_staging_plan_against_parent(&identity, &oversized, None).is_err());
        let maximal: Vec<StagedSegmentContent> = (0..MAX_SEGMENTS_PER_MANIFEST)
            .map(|_| StagedSegmentContent::New(vec![]))
            .collect();
        assert!(validate_staging_plan_against_parent(&identity, &maximal, None).is_ok());
    }

    #[test]
    fn reuse_validation_refuses_duplicate_parent_ordinals_and_segments() {
        let identity = identity();
        let references = vec![parent_view(0, &identity), parent_view(1, &identity)];

        // The same parent ordinal claimed twice is refused before any write.
        let duplicated_ordinal = vec![
            StagedSegmentContent::ReuseParent { parent_ordinal: 0 },
            StagedSegmentContent::ReuseParent { parent_ordinal: 1 },
            StagedSegmentContent::ReuseParent { parent_ordinal: 0 },
        ];
        let error =
            validate_staging_plan_against_parent(&identity, &duplicated_ordinal, Some(&references))
                .unwrap_err();
        assert!(
            matches!(&error, AuthorizationProjectionError::Mapping(message)
                if message.contains("duplicate_parent_ordinal_reuse")),
            "{error:?}"
        );

        // Two distinct ordinals sharing one parent segment row (corrupt or
        // shadowed parent set) are refused as a duplicate segment claim too.
        let (_, shared_view) = parent_view(0, &identity);
        let shadowing = vec![
            (
                0,
                ParentReferenceView {
                    ordinal: 0,
                    ..shared_view.clone()
                },
            ),
            (
                1,
                ParentReferenceView {
                    ordinal: 1,
                    ..shared_view
                },
            ),
        ];
        let shared_segment_claim = vec![
            StagedSegmentContent::ReuseParent { parent_ordinal: 0 },
            StagedSegmentContent::ReuseParent { parent_ordinal: 1 },
        ];
        let error = validate_staging_plan_against_parent(
            &identity,
            &shared_segment_claim,
            Some(&shadowing),
        )
        .unwrap_err();
        assert!(
            matches!(&error, AuthorizationProjectionError::Mapping(message)
                if message.contains("duplicate_parent_segment_reuse")),
            "{error:?}"
        );

        // A healthy plan touching distinct ordinals still validates.
        let healthy = vec![
            StagedSegmentContent::ReuseParent { parent_ordinal: 0 },
            StagedSegmentContent::ReuseParent { parent_ordinal: 1 },
        ];
        assert!(
            validate_staging_plan_against_parent(&identity, &healthy, Some(&references)).is_ok()
        );
    }

    // ── Publish preconditions ───────────────────────────────────────────────

    fn ready_target(generation: u64, manifest_id: i64) -> TargetManifestView {
        TargetManifestView {
            identity: identity(),
            card_id: Some(17),
            manifest_id,
            parent_manifest_id: (generation > 1).then_some(400),
            generation,
            status_str: MANIFEST_STATUS_READY.to_owned(),
            semantic_hash_hex: HASH_A.to_owned(),
            dependency_hash_hex: HASH_B.to_owned(),
            compiler_version: "phase2-authorization-kernel-v1".to_owned(),
            reference_count: 1,
        }
    }

    #[test]
    fn publish_validation_happy_path_and_first_publication_gate() {
        let target = ready_target(1, 500);
        let expectation = AuthorizationPublishExpectation {
            current_pointer: None,
            expected_target_semantic_hash_hex: HASH_A.to_owned(),
            expected_target_dependency_hash_hex: HASH_B.to_owned(),
            expected_target_compiler_version: "phase2-authorization-kernel-v1".to_owned(),
        };
        assert!(validate_manifest_publish(&expectation, &target).is_ok());

        // First-publication generation errors are checked after the target has
        // supplied the only valid first-publication lineage: no parent.
        let later_target = TargetManifestView {
            parent_manifest_id: None,
            ..ready_target(2, 501)
        };
        let error = validate_manifest_publish(&expectation, &later_target).unwrap_err();
        assert!(
            matches!(error, AuthorizationProjectionError::ManifestPublishConflict(ref message)
            if message.contains("first_publication_requires_generation_one"))
        );

        let continuation_target = ready_target(2, 501);
        let continuing_expectation = AuthorizationPublishExpectation {
            current_pointer: Some(CurrentPointerView {
                identity: identity(),
                card_id: Some(17),
                current_generation: 1,
                manifest_id: 400,
                revoke_fence: 2,
                revoke_fence_proven: true,
                cas_version: 3,
            }),
            ..expectation.clone()
        };
        assert!(validate_manifest_publish(&continuing_expectation, &continuation_target).is_ok());
    }

    #[test]
    fn publish_validation_fails_closed_on_target_deviations() {
        let expectation = AuthorizationPublishExpectation {
            current_pointer: None,
            expected_target_semantic_hash_hex: HASH_A.to_owned(),
            expected_target_dependency_hash_hex: HASH_B.to_owned(),
            expected_target_compiler_version: "phase2-authorization-kernel-v1".to_owned(),
        };

        // Target not READY.
        let building_target = TargetManifestView {
            status_str: MANIFEST_STATUS_BUILDING.to_owned(),
            ..ready_target(1, 500)
        };
        let error = validate_manifest_publish(&expectation, &building_target).unwrap_err();
        assert!(
            matches!(error, AuthorizationProjectionError::NotReady(ref message)
            if message.contains("target_not_ready"))
        );

        // Semantic hash disagreement with the compile output.
        let target = ready_target(1, 500);
        let drifted = AuthorizationPublishExpectation {
            expected_target_semantic_hash_hex: HASH_B.to_owned(),
            ..expectation.clone()
        };
        let error = validate_manifest_publish(&drifted, &target).unwrap_err();
        assert!(
            matches!(error, AuthorizationProjectionError::ManifestPublishConflict(ref message)
            if message.contains("publish_target_semantic_mismatch"))
        );

        // Dependency hash disagreement.
        let drifted = AuthorizationPublishExpectation {
            expected_target_dependency_hash_hex: HASH_A.to_owned(),
            ..expectation.clone()
        };
        let error = validate_manifest_publish(&drifted, &target).unwrap_err();
        assert!(
            matches!(error, AuthorizationProjectionError::ManifestPublishConflict(ref message)
            if message.contains("publish_target_dependency_mismatch"))
        );

        // Compiler version disagreement.
        let drifted = AuthorizationPublishExpectation {
            expected_target_compiler_version: "other-compiler".to_owned(),
            ..expectation
        };
        let error = validate_manifest_publish(&drifted, &target).unwrap_err();
        assert!(
            matches!(error, AuthorizationProjectionError::ManifestPublishConflict(ref message)
            if message.contains("publish_target_compiler_mismatch"))
        );
    }

    #[test]
    fn publish_validation_fails_closed_on_pointer_chain_breaks() {
        let pointer =
            |current_generation: u64, manifest_id: i64, identity: ProjectionAggregateIdentity| {
                CurrentPointerView {
                    identity,
                    card_id: Some(17),
                    current_generation,
                    manifest_id,
                    revoke_fence: 2,
                    revoke_fence_proven: true,
                    cas_version: 9,
                }
            };
        let expectation_for =
            |pointer_view: Option<CurrentPointerView>| AuthorizationPublishExpectation {
                current_pointer: pointer_view,
                expected_target_semantic_hash_hex: HASH_A.to_owned(),
                expected_target_dependency_hash_hex: HASH_B.to_owned(),
                expected_target_compiler_version: "phase2-authorization-kernel-v1".to_owned(),
            };

        // Generation gap between pointer and target.
        let target = ready_target(2, 501);
        let gapped = expectation_for(Some(pointer(5, 400, identity())));
        let error = validate_manifest_publish(&gapped, &target).unwrap_err();
        assert!(
            matches!(error, AuthorizationProjectionError::ManifestPublishConflict(ref message)
            if message.contains("publish_generation_gap"))
        );

        // Identity split between pointer and target.
        let foreign_identity = ProjectionAggregateIdentity::new(7, "CARD", 999).unwrap();
        let split = expectation_for(Some(pointer(1, 400, foreign_identity)));
        let error = validate_manifest_publish(&split, &target).unwrap_err();
        assert!(matches!(
            error,
            AuthorizationProjectionError::IdentityMismatch(_)
        ));

        // Re-publishing the same manifest is refused (sequence stays valid).
        let same = expectation_for(Some(pointer(1, 501, identity())));
        let error = validate_manifest_publish(&same, &target).unwrap_err();
        assert!(
            matches!(error, AuthorizationProjectionError::ManifestPublishConflict(ref message)
            if message.contains("publish_same_manifest"))
        );
    }

    #[test]
    fn publish_validation_rejects_card_scope_splits() {
        // Pointer scope vs stored manifest scope must agree exactly; any
        // Some-vs-None or foreign-card split refuses as identity mismatch.
        let pointer = |card_id: Option<i64>| CurrentPointerView {
            identity: identity(),
            card_id,
            current_generation: 1,
            manifest_id: 400,
            revoke_fence: 2,
            revoke_fence_proven: true,
            cas_version: 9,
        };
        let with_card = |card_id: Option<i64>| TargetManifestView {
            card_id,
            ..ready_target(2, 501)
        };
        let expectation_with =
            |pointer_view: Option<CurrentPointerView>| AuthorizationPublishExpectation {
                current_pointer: pointer_view,
                expected_target_semantic_hash_hex: HASH_A.to_owned(),
                expected_target_dependency_hash_hex: HASH_B.to_owned(),
                expected_target_compiler_version: "phase2-authorization-kernel-v1".to_owned(),
            };

        // Card-scoped pointer reading back against a NULL-scoped target.
        let error =
            validate_manifest_publish(&expectation_with(Some(pointer(Some(17)))), &with_card(None))
                .unwrap_err();
        assert!(
            matches!(&error, AuthorizationProjectionError::IdentityMismatch(message)
                if message.contains("publish_pointer_target_card_scope_mismatch")),
            "{error:?}"
        );

        // Legacy NULL residue on the pointer vs card-scoped target.
        let error =
            validate_manifest_publish(&expectation_with(Some(pointer(None))), &with_card(Some(17)))
                .unwrap_err();
        assert!(
            matches!(&error, AuthorizationProjectionError::IdentityMismatch(message)
                if message.contains("publish_pointer_target_card_scope_mismatch")),
            "{error:?}"
        );

        // Agreement keeps validating.
        assert!(validate_manifest_publish(
            &expectation_with(Some(pointer(Some(17)))),
            &with_card(Some(17))
        )
        .is_ok());
        assert!(validate_manifest_publish(
            &expectation_with(Some(pointer(None))),
            &with_card(None)
        )
        .is_ok());
    }

    #[test]
    fn fence_continuity_enforces_monotonicity_or_paired_evidence() {
        // Mandatory paired evidence: monotonicity is still enforced, but the
        // previous "half-supplied pair" case is now unrepresentable by the
        // typed fields (`u64`, not `Option`) — a deliberate API-level fix for
        // the self-proving `PublishRevokeFenceEvidence(None, None)` hole.
        assert!(validate_publish_fence_continuity(3, 3).is_ok());
        assert!(validate_publish_fence_continuity(3, 4).is_ok());

        let error = validate_publish_fence_continuity(5, 4).unwrap_err();
        assert!(
            matches!(error, AuthorizationProjectionError::ManifestPublishConflict(ref message)
            if message.contains("fence_regression"))
        );

        // First publications must present the zero initial fence; any other
        // value is invented evidence, never defaulted silently.
        assert!(validate_first_publication_previous_fence(false, 0).is_ok());
        assert!(validate_first_publication_previous_fence(true, 3).is_ok());
        let error = validate_first_publication_previous_fence(false, 2).unwrap_err();
        assert!(
            matches!(error, AuthorizationProjectionError::ManifestPublishConflict(ref message)
            if message.contains("first_publication_requires_zero_previous_fence"))
        );
    }

    #[test]
    fn previous_fence_authority_takes_only_the_locked_pointer_row() {
        // Evidence agreeing with the durable pointer state passes.
        assert!(validate_publish_previous_fence_authority(None, 0).is_ok());
        assert!(validate_publish_previous_fence_authority(Some(4), 4).is_ok());

        // Any disagreement between caller evidence and the authoritative
        // locked pointer refuses — forged higher, stale lower, both alike.
        for (durable, evidence) in [(Some(4), 3_u64), (Some(4), 5), (Some(0), 1), (None, 1)] {
            let error = validate_publish_previous_fence_authority(durable, evidence).unwrap_err();
            assert!(
                matches!(
                    error,
                    AuthorizationProjectionError::CurrentPointerCasConflict(ref message)
                        if message.contains("previous_fence_not_authoritative")
                ),
                "durable={durable:?};evidence={evidence}"
            );
            assert!(
                format!("{error}").contains(&format!("durable={}", durable.unwrap_or(0))),
                "the refusal must name the authoritative value"
            );
        }
    }

    #[test]
    fn pointer_proof_latch_distinguishes_legacy_zero_from_proven_zero() {
        assert!(validate_current_pointer_proof(None).is_ok());
        assert!(validate_pointer_proof_state(0, true).is_ok());
        assert!(validate_pointer_proof_state(7, true).is_ok());

        for fence in [0, 7] {
            let error = validate_pointer_proof_state(fence, false).unwrap_err();
            assert!(
                matches!(error, AuthorizationProjectionError::NotReady(ref message)
                if message.contains("backfill_or_rehearsal_required")
                    && message.contains("pointer_proof_unproven"))
            );
        }

        let mut unproven = CurrentPointerView {
            identity: identity(),
            card_id: Some(17),
            current_generation: 1,
            manifest_id: 400,
            revoke_fence: 0,
            revoke_fence_proven: false,
            cas_version: 1,
        };
        assert!(validate_current_pointer_proof(Some(&unproven)).is_err());
        unproven.revoke_fence_proven = true;
        assert!(validate_current_pointer_proof(Some(&unproven)).is_ok());
    }

    #[test]
    fn zero_sentinel_never_proves_history_without_the_latch() {
        for claimed in [0, 2] {
            let error =
                validate_zero_sentinel_fence_history(claimed, Some((0, false))).unwrap_err();
            assert!(
                matches!(error, AuthorizationProjectionError::NotReady(ref message)
                if message.contains("backfill_or_rehearsal_required")
                    && message.contains("pointer_proof_unproven"))
            );
        }

        // A Rust-published zero fence is proven and may advance to a positive
        // fence; only numeric history is never used as proof.
        validate_zero_sentinel_fence_history(0, Some((0, true))).unwrap();
        validate_zero_sentinel_fence_history(3, Some((0, true))).unwrap();
        let error = validate_zero_sentinel_fence_history(2, Some((3, true))).unwrap_err();
        assert!(
            matches!(error, AuthorizationProjectionError::ManifestPublishConflict(ref message)
            if message.contains("fence_regression"))
        );
        validate_zero_sentinel_fence_history(7, None).unwrap();
    }

    #[test]
    fn staging_sql_shape_persists_durable_lineage_columns() {
        // The manifest insert writes BOTH new columns on every build.
        assert!(
            MANIFEST_INSERT_SQL.contains("parent_manifest_id, revoke_fence, status"),
            "{MANIFEST_INSERT_SQL}"
        );
        assert!(MANIFEST_INSERT_SQL.ends_with("'BUILDING')"));
        // Row readers expose the same columns so restart reconciliation and
        // immutable-replay verification can rely on them byte-for-byte.
        assert!(MANIFEST_ROW_COLUMNS.contains("parent_manifest_id"));
        assert!(MANIFEST_ROW_COLUMNS.contains("revoke_fence"));
        assert!(POINTER_ROW_COLUMNS.contains("revoke_fence"));
        assert!(POINTER_ROW_COLUMNS.contains("revoke_fence_proven"));
    }

    #[test]
    fn projector_command_shape_pins_stage_revoke_fence_to_published_evidence() {
        let mut command = shaped_command();
        assert_eq!(command.stage.revoke_fence, command.fences.new_revoke_fence);
        assert!(validate_projector_command_shape(&command).is_ok());

        command.stage.revoke_fence += 1;
        let error = validate_projector_command_shape(&command)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("command_stage_revoke_fence_mismatch"),
            "{error}"
        );
    }

    #[test]
    fn resumed_reference_equivalence_requires_full_field_agreement() {
        let identity = identity();
        let snapshot = AuthorizationSegmentSnapshot {
            segment_id: 42,
            identity: identity.clone(),
            card_id: Some(17),
            content_digest: Sha256Digest::from_hex(HASH_A).unwrap(),
            semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap(),
            dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap(),
            compiler_version: "phase2-authorization-kernel-v1".to_owned(),
            format: SEGMENT_FORMAT_AUTHORIZATION_GRANTS_JSON_V1.to_owned(),
            row_count: 2,
            byte_size: 128,
            grants: vec![grant(1), grant(2)],
        };
        let record = |mutate: &dyn Fn(&mut AuthorizationSegmentReferenceRecord)| {
            let mut base = AuthorizationSegmentReferenceRecord {
                reference_id: 7,
                manifest_id: 500,
                identity: identity.clone(),
                card_id: Some(17),
                generation: 3,
                ordinal: 1,
                segment_id: 42,
                content_digest: Sha256Digest::from_hex(HASH_A).unwrap(),
                event_id: "event-stage".to_owned(),
                operation_id: "op-stage".to_owned(),
            };
            mutate(&mut base);
            base
        };
        let expectation_for =
            |manifest_id: i64, generation: u64, ordinal: u64| ResumedReferenceExpectation {
                identity: &identity,
                card_id: Some(17),
                event_id: "event-stage",
                operation_id: "op-stage",
                manifest_id,
                generation,
                ordinal,
                snapshot: &snapshot,
            };
        let matches = |candidate: &AuthorizationSegmentReferenceRecord| {
            resumed_reference_matches(candidate, &expectation_for(500, 3, 1))
        };

        // Byte-for-byte agreement resumes as an idempotent skip.
        assert!(matches(&record(&|_| {})));

        // Any durable dimension drifting from the plan refuses resume.
        for mutation in [
            "manifest_id",
            "ordinal",
            "generation",
            "identity",
            "card_id",
            "segment_id",
            "content_digest",
            "event_id",
            "operation_id",
        ] {
            let candidate = record(
                &|row: &mut AuthorizationSegmentReferenceRecord| match mutation {
                    "manifest_id" => row.manifest_id = 501,
                    "ordinal" => row.ordinal = 2,
                    "generation" => row.generation = 4,
                    "identity" => row.identity.aggregate_id = 99,
                    "card_id" => row.card_id = None,
                    "segment_id" => row.segment_id = 43,
                    "content_digest" => {
                        row.content_digest = Sha256Digest::from_hex(HASH_B).unwrap()
                    }
                    "event_id" => row.event_id = "other-event".to_owned(),
                    _ => row.operation_id = "other-op".to_owned(),
                },
            );
            assert!(!matches(&candidate), "{mutation} drift must refuse resume");
        }

        // A winner committed at a different slot position is not this plan's
        // row either.
        let shifted = record(&|_| {});
        assert!(!resumed_reference_matches(
            &shifted,
            &expectation_for(500, 3, 2)
        ));
    }

    // ── Identity text gates ─────────────────────────────────────────────────

    #[test]
    fn aggregate_identity_validates_charset_positivity_and_texts() {
        assert!(ProjectionAggregateIdentity::new(7, "CARD", 17).is_ok());
        assert!(ProjectionAggregateIdentity::new(0, "CARD", 17).is_err());
        assert!(ProjectionAggregateIdentity::new(-1, "CARD", 17).is_err());
        assert!(ProjectionAggregateIdentity::new(7, "CARD", 0).is_err());
        assert!(ProjectionAggregateIdentity::new(7, "", 17).is_err());
        assert!(ProjectionAggregateIdentity::new(7, "CA RD", 17).is_err());
        assert!(ProjectionAggregateIdentity::new(7, "A".repeat(33).as_str(), 17).is_err());
        assert!(truncate_last_error("0123456789").len() <= MAX_LAST_ERROR_LENGTH);
        assert!(validated_text("event", MAX_EVENT_ID_LENGTH, "event_id").is_ok());
        assert!(validated_text("", MAX_EVENT_ID_LENGTH, "event_id").is_err());
        assert!(validated_text("a\tb", MAX_EVENT_ID_LENGTH, "event_id").is_err());
    }

    // ── Compiler bridge ─────────────────────────────────────────────────────

    #[test]
    fn hot_state_bridge_preserves_deterministic_segment_order() {
        use astral_types::DependencyVersion;
        use policy_engine::HotState;

        let dependency_vector = astral_types::DependencyVector::new(vec![
            DependencyVersion::new("card", 4, 0).unwrap(),
            DependencyVersion::new("rule-set", 3, 1).unwrap(),
        ])
        .unwrap();
        let state = HotState::from_grants(
            tenant(),
            5,
            vec![grant(0x21), grant(0x22)],
            dependency_vector,
        )
        .unwrap();
        let plan = stage_plan_new_segments_from_hot_state(&state).unwrap();
        let references = state.segment_references();
        assert_eq!(plan.len(), references.len());
        assert_eq!(plan.len(), state.segments.len());
        for entry in &plan {
            match entry {
                StagedSegmentContent::New(grants) => {
                    let encoded = encode_segment_payload(grants).unwrap();
                    let computed = Sha256Digest::from_raw_bytes(sha256_digest_bytes(&encoded));
                    assert_eq!(computed.as_hex().len(), 64);
                }
                StagedSegmentContent::ReuseParent { .. } => panic!("bridge yields fresh segments"),
            }
        }
    }

    // ── SQL shape tests (text/binding shape only; NOT integration) ──────────

    #[test]
    fn pointer_cas_statement_shape_pins_every_fence_column() {
        for fragment in [
            "AND current_generation = ?",
            "AND manifest_id = ?",
            "AND cas_version = ?",
            // Null-safe card-scope guard: a scoped pointer can only advance
            // while the stored card_id still equals the requested scope.
            "AND card_id <=> ?",
            // The durable revoke fence is both moved and pinned by the CAS:
            // the WHERE guard refuses any move off a pointer whose fence no
            // longer equals the authoritative previous value.
            "revoke_fence = ?",
            "AND revoke_fence = ?",
            "cas_version = cas_version + 1",
        ] {
            assert!(
                POINTER_CAS_UPDATE_SQL.contains(fragment),
                "missing {fragment}"
            );
        }
        // The CAS update re-pins the scope in SET as well as guarding it.
        assert!(POINTER_CAS_UPDATE_SQL.contains("SET current_generation = ?, card_id = ?,"));
        assert!(
            POINTER_CAS_UPDATE_SQL.contains("compiler_version = ?, revoke_fence = ?,"),
            "the new fence must move inside the same CAS UPDATE"
        );

        // Promotion is pinned to READY plus the observed CAS counter AND the
        // evidence.new revoke fence.
        assert!(MANIFEST_PROMOTE_SQL.contains("AND status = 'READY'"));
        assert!(MANIFEST_PROMOTE_SQL.contains("AND cas_version = ?"));
        assert!(
            MANIFEST_PROMOTE_SQL.contains("AND revoke_fence = ?"),
            "promotion must pin the manifest's own revoke fence"
        );

        // Superseding touches history only after CAS success and never deletes.
        assert!(MANIFEST_SUPERSEDE_SQL.contains("AND status = 'COMMITTED'"));
        for statement in [
            POINTER_CAS_UPDATE_SQL,
            MANIFEST_PROMOTE_SQL,
            MANIFEST_SUPERSEDE_SQL,
            POINTER_FIRST_INSERT_SQL,
        ] {
            assert!(
                !statement.to_uppercase().contains("DELETE"),
                "no deletes allowed"
            );
        }
        assert!(POINTER_FIRST_INSERT_SQL.ends_with("'READY')"));
    }

    #[test]
    fn pointer_statements_propagate_card_scope_and_promotion_clears_lease() {
        // First publication persists the card scope explicitly so a
        // card-scoped chain never starts with a NULL `card_id`.
        assert!(POINTER_FIRST_INSERT_SQL.contains("tenant_id, card_id, aggregate_type"));
        assert_eq!(POINTER_FIRST_INSERT_SQL.matches('?').count(), 12);

        // CAS updates both re-pin and guard the scope; every value binds,
        // including the moved new fence and its pinned previous guard.
        assert_eq!(POINTER_CAS_UPDATE_SQL.matches('?').count(), 17);
        assert!(!POINTER_CAS_UPDATE_SQL.to_uppercase().contains("DELETE"));

        // Promotion to COMMITTED clears the residual builder lease inside
        // the same guarded update (status/cas/hash guards unchanged).
        assert!(MANIFEST_PROMOTE_SQL.contains("lease_owner = NULL"));
        assert!(MANIFEST_PROMOTE_SQL.contains("lease_token_hash = NULL"));
        assert!(MANIFEST_PROMOTE_SQL.contains("lease_expires_at = NULL"));
        assert!(MANIFEST_PROMOTE_SQL.contains("last_error = NULL"));

        // Resume verification reads one ordinal slot under lock and never
        // deletes or rewrites committed reference rows.
        let resume_read =
            format!("{SELECT_PREFIX}{REFERENCE_ROW_COLUMNS}{REFERENCE_BY_MANIFEST_ORDINAL_TAIL}");
        assert!(resume_read.contains("WHERE manifest_id = ? AND segment_ordinal = ? FOR UPDATE"));
        assert!(!resume_read.to_uppercase().contains("DELETE"));
        assert!(!resume_read.to_uppercase().contains("UPDATE "));
        assert!(REFERENCE_INSERT_SQL.starts_with("INSERT INTO"));
    }

    #[test]
    fn lease_statements_guard_owner_token_liveness_and_status() {
        for (statement, status_fragment) in [
            (MANIFEST_HEARTBEAT_SQL, None),
            (MANIFEST_HEARTBEAT_WITH_CAS_SQL, None),
            (MANIFEST_RELEASE_SQL, Some("AND status = 'BUILDING'")),
            (
                MANIFEST_QUARANTINE_SQL,
                Some("status IN ('BUILDING', 'READY')"),
            ),
        ] {
            assert!(statement.contains("AND lease_owner = ?"), "{statement}");
            assert!(
                statement.contains("AND lease_token_hash = ?"),
                "{statement}"
            );
            assert!(
                statement.contains("lease_expires_at > UTC_TIMESTAMP()"),
                "{statement}"
            );
            if let Some(fragment) = status_fragment {
                assert!(statement.contains(fragment));
            }
        }
        // Only hashed tokens ever travel into statements.
        assert!(!MANIFEST_CLAIM_INSTALL_SQL.contains("lease_token ="));
        assert!(MANIFEST_CLAIM_INSTALL_SQL.contains("lease_token_hash = ?"));
        assert!(MANIFEST_CLAIM_INSTALL_SQL.contains("lease_expires_at <= UTC_TIMESTAMP()"));
        // Live leases are never stolen on claim.
        assert!(!MANIFEST_CLAIM_CANDIDATE_SQL.contains("status = 'LEASED'"));
    }

    #[test]
    fn staged_queries_are_parameterized_without_interpolation_surface() {
        for statement in [
            SEGMENT_SELECT_BY_DIGEST_SQL,
            SEGMENT_INSERT_SQL,
            REFERENCE_INSERT_SQL,
            MANIFEST_INSERT_SQL,
            MANIFEST_CLAIM_CANDIDATE_SQL,
            MANIFEST_FINALIZE_SQL,
        ] {
            assert!(
                !statement.contains('{'),
                "brace interpolation surface in: {statement}"
            );
        }
        assert_eq!(REFERENCE_INSERT_SQL.matches('?').count(), 11);
        assert_eq!(MANIFEST_INSERT_SQL.matches('?').count(), 15);
        assert_eq!(SEGMENT_INSERT_SQL.matches('?').count(), 12);
        assert_eq!(MANIFEST_CLAIM_INSTALL_SQL.matches('?').count(), 4);
        assert_eq!(MANIFEST_FINALIZE_SQL.matches('?').count(), 8);
        // Pointer writes carry the card scope end-to-end: first insert binds
        // tenant/card/type/id/gen/manifest/provenance/hashes/compiler/fence
        // (12), CAS update adds the scope re-pin plus its null-safe guard and
        // the pinned previous fence (17).
        assert_eq!(POINTER_CAS_UPDATE_SQL.matches('?').count(), 17);
        assert_eq!(POINTER_FIRST_INSERT_SQL.matches('?').count(), 12);
        assert_eq!(MANIFEST_PROMOTE_SQL.matches('?').count(), 10);

        // Resume readback statement stays fully parameterized.
        let resume_read =
            format!("{SELECT_PREFIX}{REFERENCE_ROW_COLUMNS}{REFERENCE_BY_MANIFEST_ORDINAL_TAIL}");
        assert_eq!(resume_read.matches('?').count(), 2);
    }

    #[test]
    fn finalize_guard_keeps_building_unpublishable_until_complete() {
        assert!(MANIFEST_FINALIZE_SQL.contains("AND status = 'BUILDING'"));
        assert!(MANIFEST_FINALIZE_SQL.contains("AND cas_version = ?"));
        assert!(MANIFEST_FINALIZE_SQL.contains("AND lease_expires_at > UTC_TIMESTAMP()"));
        assert!(!MANIFEST_FINALIZE_SQL.to_uppercase().contains("DELETE"));
    }

    // ── Impact plans: vocabulary, normalization and bridging ───────────────

    #[test]
    fn impact_plan_vocabulary_is_explicit_and_fail_closed() {
        for (text, expected) in [
            ("PENDING", AuthorizationImpactPlanStatus::Pending),
            ("SUCCEEDED", AuthorizationImpactPlanStatus::Succeeded),
        ] {
            assert_eq!(
                AuthorizationImpactPlanStatus::parse(text).unwrap(),
                expected
            );
            assert_eq!(expected.as_str(), text);
        }
        assert!(AuthorizationImpactPlanStatus::parse("READY").is_err());
        assert!(AuthorizationImpactPlanStatus::parse("").is_err());

        assert!(AuthorizationImpactPlanStatus::Pending
            .can_transition_to(AuthorizationImpactPlanStatus::Succeeded));
        for (from, to) in [
            (
                AuthorizationImpactPlanStatus::Succeeded,
                AuthorizationImpactPlanStatus::Pending,
            ),
            (
                AuthorizationImpactPlanStatus::Succeeded,
                AuthorizationImpactPlanStatus::Succeeded,
            ),
            (
                AuthorizationImpactPlanStatus::Pending,
                AuthorizationImpactPlanStatus::Pending,
            ),
        ] {
            assert!(!from.can_transition_to(to));
        }

        for (text, expected) in [
            ("SEGMENT_UPSERT", AuthorizationImpactItemType::SegmentUpsert),
            ("SEGMENT_REMOVE", AuthorizationImpactItemType::SegmentRemove),
        ] {
            assert_eq!(AuthorizationImpactItemType::parse(text).unwrap(), expected);
            assert_eq!(expected.as_str(), text);
        }
        assert!(AuthorizationImpactItemType::parse("UPSERT").is_err());
        assert!(AuthorizationImpactItemType::parse("").is_err());
    }

    fn impact_item_upsert(key: &str) -> AuthorizationImpactItemInput {
        AuthorizationImpactItemInput {
            projection_key: key.to_owned(),
            item_type: AuthorizationImpactItemType::SegmentUpsert,
            grant_id: None,
            before_digest_hex: None,
            after_digest_hex: Some(HASH_A.to_owned()),
        }
    }

    #[test]
    fn impact_item_normalization_sorts_dedupes_and_enforces_digest_pairing() {
        let items = vec![
            impact_item_upsert("b-key"),
            impact_item_upsert("a-key"),
            // Identical duplicate collapses silently.
            impact_item_upsert("b-key"),
        ];
        let normalized = normalize_impact_items(&items).unwrap();
        let keys: Vec<&str> = normalized
            .iter()
            .map(|item| item.projection_key.as_str())
            .collect();
        assert_eq!(
            keys,
            vec!["a-key", "b-key"],
            "byte-ascending order is required"
        );

        // Divergent duplicate under one key refuses instead of merging.
        let mut divergent = impact_item_upsert("a-key");
        divergent.after_digest_hex = Some(HASH_B.to_owned());
        let conflicting = vec![impact_item_upsert("a-key"), divergent];
        assert!(matches!(
            normalize_impact_items(&conflicting),
            Err(AuthorizationProjectionError::ScopeViolation(ref message))
                if message.contains("impact_item_key_conflict")
        ));

        // UPSERT demands an after digest; REMOVE demands before-only.
        let upsert_missing_after = AuthorizationImpactItemInput {
            projection_key: "k".to_owned(),
            item_type: AuthorizationImpactItemType::SegmentUpsert,
            grant_id: None,
            before_digest_hex: Some(HASH_B.to_owned()),
            after_digest_hex: None,
        };
        assert!(matches!(
            normalize_impact_items(&[upsert_missing_after]),
            Err(AuthorizationProjectionError::ScopeViolation(ref message))
                if message.contains("upsert_requires_after_digest")
        ));
        let remove_ok = AuthorizationImpactItemInput {
            projection_key: "r".to_owned(),
            item_type: AuthorizationImpactItemType::SegmentRemove,
            grant_id: None,
            before_digest_hex: Some(HASH_B.to_owned()),
            after_digest_hex: None,
        };
        let normalized_remove = normalize_impact_items(std::slice::from_ref(&remove_ok)).unwrap();
        assert_eq!(normalized_remove[0].after_digest, None);
        assert_eq!(
            normalized_remove[0].before_digest,
            Some(Sha256Digest::from_hex(HASH_B).unwrap())
        );
        let mut remove_with_after = remove_ok;
        remove_with_after.after_digest_hex = Some(HASH_A.to_owned());
        assert!(matches!(
            normalize_impact_items(&[remove_with_after]),
            Err(AuthorizationProjectionError::ScopeViolation(ref message))
                if message.contains("remove_digest_pairing")
        ));

        // Key hygiene: whitespace/control characters, emptiness, caps and
        // non-hex digest payloads all fail closed.
        for poisoned_key in ["", " spaced\t"] {
            let bad = impact_item_upsert(poisoned_key);
            assert!(normalize_impact_items(&[bad]).is_err(), "{poisoned_key}");
        }
        let oversized = impact_item_upsert(&"k".repeat(MAX_PROJECTION_KEY_LENGTH + 1));
        assert!(normalize_impact_items(&[oversized]).is_err());
        let boundary = impact_item_upsert(&"k".repeat(MAX_PROJECTION_KEY_LENGTH));
        assert!(normalize_impact_items(&[boundary]).is_ok());
        let non_hex = impact_item_upsert("k");
        let mut non_hex = non_hex;
        non_hex.after_digest_hex = Some("zz".repeat(32));
        assert!(normalize_impact_items(&[non_hex]).is_err());

        // Plans must carry at least one item.
        assert!(matches!(
            normalize_impact_items(&[]),
            Err(AuthorizationProjectionError::ScopeViolation(ref message))
                if message.contains("empty_impact_plan")
        ));
    }

    #[test]
    fn impact_plan_sql_shape_pins_identity_guarded_completion_and_no_deletes() {
        assert_eq!(IMPACT_PLAN_INSERT_SQL.matches('?').count(), 13);
        assert_eq!(IMPACT_ITEM_INSERT_SQL.matches('?').count(), 15);
        assert!(IMPACT_PLAN_INSERT_SQL.ends_with("'PENDING')"));
        assert!(IMPACT_ITEM_INSERT_SQL.ends_with("'PENDING')"));
        assert!(IMPACT_ITEMS_BY_PLAN_TAIL.contains("ORDER BY projection_key ASC FOR UPDATE"));
        assert!(IMPACT_PLAN_BY_EVENT_TAIL.contains("WHERE event_id = ? FOR UPDATE"));
        assert!(IMPACT_PLAN_BY_TARGET_GENERATION_TAIL
            .contains("AND aggregate_type = ? AND aggregate_id = ? AND target_generation = ?"));
        // Completion stays guarded by event + aggregate identity and PENDING.
        for fragment in [
            "SET status = 'SUCCEEDED'",
            "WHERE plan_id = ? AND event_id = ?",
            "AND tenant_id = ?",
            "AND aggregate_type = ?",
            "AND aggregate_id = ?",
            "AND status = 'PENDING'",
        ] {
            assert!(IMPACT_PLAN_COMPLETE_SQL.contains(fragment), "{fragment}");
        }
        for statement in [
            IMPACT_PLAN_INSERT_SQL,
            IMPACT_ITEM_INSERT_SQL,
            IMPACT_PLAN_COMPLETE_SQL,
            IMPACT_ITEM_COUNT_SQL,
        ] {
            assert!(!statement.to_uppercase().contains("DELETE"), "{statement}");
            assert!(!statement.contains('{'), "no interpolation surface");
        }
    }

    // ── Item root-link decoding ────────────────────────────────────────────

    fn linked_identity() -> ProjectionAggregateIdentity {
        ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap()
    }

    fn item_raw_row() -> ImpactItemRawSqlRow {
        ImpactItemRawSqlRow {
            item_id: 3,
            plan_id: 9,
            tenant_id: 7,
            card_id: Some(17),
            aggregate_type: "CARD".to_owned(),
            aggregate_id: 17,
            event_id: "evt".to_owned(),
            operation_id: "op".to_owned(),
            projection_key: "{\"action\":\"read\",\"cardId\":17}".to_owned(),
            item_type: "SEGMENT_UPSERT".to_owned(),
            grant_id: None,
            base_version: 0,
            target_version: 1,
            before_digest: None,
            after_digest: Some(vec![1u8; 32]),
            dependency_hash: vec![8u8; 32],
            status: "PENDING".to_owned(),
        }
    }

    #[test]
    fn impact_item_decode_rejects_root_link_drift() {
        let identity = linked_identity();
        let dependency = Sha256Digest::from_bytes(vec![8u8; 32]).unwrap();
        let event_id = "evt".to_owned();
        let operation_id = "op".to_owned();
        let root = ImpactRootLink {
            plan_id: 9,
            identity: &identity,
            card_id: Some(17),
            event_id: &event_id,
            operation_id: &operation_id,
            base_version: 0,
            target_version: 1,
            dependency_hash: &dependency,
        };
        let expect_failure = |mutate: &dyn Fn(&mut ImpactItemRawSqlRow), needle: &str| {
            let mut row = item_raw_row();
            mutate(&mut row);
            let error = row.decode_against(&root).unwrap_err().to_string();
            assert!(error.contains(needle), "expected {needle} inside: {error}");
        };

        let happy = item_raw_row().decode_against(&root).unwrap();
        assert_eq!(happy.item_type, AuthorizationImpactItemType::SegmentUpsert);
        assert_eq!(happy.item_id, 3);

        // A row belonging to a different plan root is foreign even when every
        // denormalized column matches.
        expect_failure(&|row| row.plan_id = 10, "impact_item_identity_mismatch");

        expect_failure(
            &|row| row.aggregate_id = 999,
            "impact_item_identity_mismatch",
        );
        expect_failure(&|row| row.card_id = None, "impact_item_root_link_mismatch");
        expect_failure(
            &|row| row.event_id = "other".to_owned(),
            "impact_item_root_link_mismatch",
        );
        expect_failure(
            &|row| row.operation_id = "other".to_owned(),
            "impact_item_root_link_mismatch",
        );
        expect_failure(
            &|row| row.target_version = 9,
            "impact_item_root_link_mismatch",
        );
        expect_failure(
            &|row| row.dependency_hash = vec![7u8; 32],
            "impact_item_dependency_mismatch",
        );
        expect_failure(
            &|row| row.status = "DONE".to_owned(),
            "impact_item_status_unexpected",
        );
        expect_failure(
            &|row| row.item_type = "MIXED".to_owned(),
            "unknown_impact_item_type",
        );
        expect_failure(
            &|row| row.grant_id = Some("550E8400-E29B-41D4-A716-446655440000".to_owned()),
            "invalid_char36_grant_id",
        );
    }

    // ── Compiler bridge ────────────────────────────────────────────────────

    #[test]
    fn compiler_plan_bridge_maps_changed_segments_only() {
        use policy_engine::{ProjectionKey, SegmentImpact};
        let key_a = ProjectionKey::new(17, 42, "learn_subject:1", "read").unwrap();
        let key_b = ProjectionKey::new(18, 42, "learn_subject:2", "write").unwrap();
        let plan = policy_engine::ImpactPlan {
            affected_keys: vec![key_a.clone(), key_b.clone()],
            affected_segments: vec![
                SegmentImpact {
                    key: key_a.clone(),
                    segment_id: "segment-a".to_owned(),
                    before_content_hash: None,
                    after_content_hash: Some(HASH_A.to_owned()),
                    content_changed: true,
                },
                // Unchanged segments are intentionally NOT persisted.
                SegmentImpact {
                    key: key_b.clone(),
                    segment_id: "segment-b".to_owned(),
                    before_content_hash: Some(HASH_A.to_owned()),
                    after_content_hash: Some(HASH_A.to_owned()),
                    content_changed: false,
                },
                SegmentImpact {
                    key: ProjectionKey::new(19, 42, "learn_subject:3", "read").unwrap(),
                    segment_id: "segment-c".to_owned(),
                    before_content_hash: Some(HASH_B.to_owned()),
                    after_content_hash: None,
                    content_changed: true,
                },
            ],
            full_rebuild: false,
            reason: None,
        };

        let request = impact_plan_request_from_compiler_plan(
            linked_identity(),
            Some(17),
            "evt",
            "op",
            1,
            2,
            0,
            1,
            HASH_A,
            HASH_B,
            "phase2-authorization-kernel-v1",
            &plan,
        )
        .unwrap();

        assert_eq!(request.items.len(), 2, "unchanged segment must drop out");
        let mapped_types: Vec<AuthorizationImpactItemType> =
            request.items.iter().map(|item| item.item_type).collect();
        assert_eq!(
            mapped_types,
            vec![
                AuthorizationImpactItemType::SegmentUpsert,
                AuthorizationImpactItemType::SegmentRemove
            ]
        );
        assert!(request.items.iter().all(|item| item.grant_id.is_none()));
        assert_eq!(request.semantic_hash_hex, HASH_A);
        assert_eq!(request.dependency_hash_hex, HASH_B);

        // A segment carrying no content evidence fails closed.
        let empty_evidence = policy_engine::ImpactPlan {
            affected_keys: vec![],
            affected_segments: vec![SegmentImpact {
                key: key_a,
                segment_id: "segment-d".to_owned(),
                before_content_hash: None,
                after_content_hash: None,
                content_changed: true,
            }],
            full_rebuild: false,
            reason: None,
        };
        assert!(matches!(
            impact_plan_request_from_compiler_plan(
                linked_identity(),
                None,
                "evt",
                "op",
                1,
                2,
                0,
                1,
                HASH_A,
                HASH_B,
                "phase2-authorization-kernel-v1",
                &empty_evidence,
            ),
            Err(AuthorizationProjectionError::Mapping(ref message))
                if message.contains("impact_item_without_content_evidence")
        ));
    }

    // ── Linkage validation ─────────────────────────────────────────────────

    fn build_claimed_event() -> (ClaimedDeltaEvent, DeltaLeaseIdentity) {
        let delta_json = serde_json::to_string(&astral_types::GrantDelta::add(grant(1))).unwrap();
        let claimed = ClaimedDeltaEvent {
            delta_event_id: 21,
            event_id: "event-delta".to_owned(),
            operation_id: "op-delta".to_owned(),
            event_type: crate::grant_repository::DeltaEventType::Add,
            tenant_id: 7,
            card_id: Some(17),
            aggregate_type: "CARD".to_owned(),
            aggregate_id: 17,
            grant_id: GrantId::parse("550e8400-e29b-41d4-a716-446655440001").unwrap(),
            base_version: 0,
            target_version: 1,
            source_generation: 5,
            revoke_fence: 2,
            before_image_json: None,
            before_digest: None,
            delta_json,
            semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap(),
            dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap(),
            compiler_version: "phase2-authorization-kernel-v1".to_owned(),
            attempts: 1,
            cas_version: 4,
            lease_owner: "worker-x".to_owned(),
            lease_expires_at: time::PrimitiveDateTime::new(
                time::Date::from_calendar_date(2031, time::Month::March, 3).unwrap(),
                time::Time::MIDNIGHT,
            ),
        };
        let lease_identity = DeltaLeaseIdentity {
            delta_event_id: 21,
            event_id: "event-delta".to_owned(),
            lease_owner: "worker-x".to_owned(),
            lease_token: crate::grant_repository::DeltaLeaseToken::for_test("token-x"),
        };
        (claimed, lease_identity)
    }

    fn linkage_pair(
        claimed: &ClaimedDeltaEvent,
    ) -> (
        AuthorizationDeltaLinkageView,
        DeltaProjectorExpectation,
        PublishRevokeFenceEvidence,
        CompileModeEvidence,
    ) {
        let view = AuthorizationDeltaLinkageView::from_claimed_row(claimed).unwrap();
        let expectation = DeltaProjectorExpectation {
            identity: view.identity.clone(),
            card_id: view.card_id,
            event_id: view.event_id.clone(),
            operation_id: view.operation_id.clone(),
            base_version: view.base_version,
            target_version: view.target_version,
            source_generation: view.source_generation,
            semantic_hash_hex: view.semantic_hash.as_hex(),
            dependency_hash_hex: view.dependency_hash.as_hex(),
            compiler_version: view.compiler_version.clone(),
        };
        let fences = PublishRevokeFenceEvidence {
            previous_revoke_fence: 2,
            new_revoke_fence: 2,
        };
        let mode = CompileModeEvidence {
            compile_mode: astral_types::ProjectionCompileMode::Incremental,
            full_rebuild_reason: None,
        };
        (view, expectation, fences, mode)
    }

    #[test]
    fn linkage_happy_path_agrees_on_every_dimension() {
        let (claimed, _lease) = build_claimed_event();
        let (view, expectation, fences, mode) = linkage_pair(&claimed);
        assert!(validate_delta_projector_linkage(&view, &expectation, fences, &mode).is_ok());

        // The view builds identically from a client-side claim object.
        let client_view = AuthorizationDeltaLinkageView::from_claim(&DeltaEventClaim {
            delta_event_id: claimed.delta_event_id,
            event_id: claimed.event_id.clone(),
            operation_id: claimed.operation_id.clone(),
            event_type: claimed.event_type,
            tenant_id: claimed.tenant_id,
            card_id: claimed.card_id,
            aggregate_type: claimed.aggregate_type.clone(),
            aggregate_id: claimed.aggregate_id,
            grant_id: claimed.grant_id,
            base_version: claimed.base_version,
            target_version: claimed.target_version,
            source_generation: claimed.source_generation,
            revoke_fence: claimed.revoke_fence,
            before_image_json: claimed.before_image_json.clone(),
            before_digest: claimed.before_digest,
            delta_json: claimed.delta_json.clone(),
            semantic_hash: claimed.semantic_hash,
            dependency_hash: claimed.dependency_hash,
            compiler_version: claimed.compiler_version.clone(),
            attempts: claimed.attempts,
            cas_version: claimed.cas_version,
            lease_owner: claimed.lease_owner.clone(),
            lease_token: crate::grant_repository::DeltaLeaseToken::for_test("t"),
            lease_expires_at: claimed.lease_expires_at,
        })
        .unwrap();
        assert_eq!(client_view, view);
    }

    #[test]
    fn linkage_refuses_each_drift_dimension_with_distinct_codes() {
        let (claimed, _) = build_claimed_event();
        let (view, expectation, fences, mode) = linkage_pair(&claimed);
        let run = |expectation: &DeltaProjectorExpectation,
                   fences: PublishRevokeFenceEvidence,
                   mode: &CompileModeEvidence| {
            validate_delta_projector_linkage(&view, expectation, fences, mode)
                .err()
                .map(|error| error.to_string())
        };

        let expect_code = |result: Option<String>, needle: &str| {
            let text = result.expect("expected refusal");
            assert!(text.contains(needle), "expected {needle} inside: {text}");
        };

        // Identity / scope / provenance mismatches.
        let mut drifted = expectation.clone();
        drifted.identity.aggregate_id = 99;
        expect_code(run(&drifted, fences, &mode), "linkage_identity_mismatch");

        let mut drifted = expectation.clone();
        drifted.card_id = None;
        expect_code(run(&drifted, fences, &mode), "linkage_card_scope_mismatch");

        let mut drifted = expectation.clone();
        drifted.event_id = "other-event".to_owned();
        expect_code(run(&drifted, fences, &mode), "linkage_event_mismatch");

        let mut drifted = expectation.clone();
        drifted.operation_id = "other-op".to_owned();
        expect_code(run(&drifted, fences, &mode), "linkage_operation_mismatch");

        // Version windows.
        let mut drifted = expectation.clone();
        drifted.target_version += 1;
        expect_code(run(&drifted, fences, &mode), "linkage_version_mismatch");

        // Equal-but-invalid windows fail the structural gate even though the
        // equality checks would pass.
        let mut bad_view = view.clone();
        bad_view.base_version = -1;
        bad_view.target_version = -1;
        let mut bad_expectation = expectation.clone();
        bad_expectation.base_version = -1;
        bad_expectation.target_version = -1;
        expect_code(
            validate_delta_projector_linkage(&bad_view, &bad_expectation, fences, &mode)
                .err()
                .map(|error| error.to_string()),
            "linkage_invalid_versions",
        );

        let mut drifted = expectation.clone();
        drifted.source_generation += 1;
        expect_code(
            run(&drifted, fences, &mode),
            "linkage_source_generation_mismatch",
        );

        // Hash trio.
        let mut drifted = expectation.clone();
        drifted.semantic_hash_hex = HASH_B.to_owned();
        expect_code(run(&drifted, fences, &mode), "linkage_semantic_mismatch");

        let mut drifted = expectation.clone();
        drifted.dependency_hash_hex = HASH_A.to_owned();
        expect_code(run(&drifted, fences, &mode), "linkage_dependency_mismatch");

        let mut drifted = expectation.clone();
        drifted.compiler_version = "other-compiler".to_owned();
        expect_code(run(&drifted, fences, &mode), "linkage_compiler_mismatch");

        // Fence evidence: regression and publish fences below the claimed
        // delta's stored fence are refused. Half-supplied pairs cannot even be
        // constructed anymore (mandatory `u64` fields).
        expect_code(
            run(
                &expectation,
                PublishRevokeFenceEvidence {
                    previous_revoke_fence: 5,
                    new_revoke_fence: 4,
                },
                &mode,
            ),
            "fence_regression",
        );
        expect_code(
            run(
                &expectation,
                PublishRevokeFenceEvidence {
                    previous_revoke_fence: 0,
                    new_revoke_fence: 0,
                },
                &mode,
            ),
            "fence_below_claimed_delta",
        );

        // Compile-mode/reason consistency.
        expect_code(
            run(
                &expectation,
                fences,
                &CompileModeEvidence {
                    compile_mode: astral_types::ProjectionCompileMode::FullRebuild,
                    full_rebuild_reason: None,
                },
            ),
            "full_rebuild_requires_reason",
        );
        expect_code(
            run(
                &expectation,
                fences,
                &CompileModeEvidence {
                    compile_mode: astral_types::ProjectionCompileMode::Incremental,
                    full_rebuild_reason: Some(policy_engine::FullRebuildReason::DependencyChanged),
                },
            ),
            "reason_without_full_rebuild",
        );
        assert!(validate_compile_mode_evidence(&CompileModeEvidence {
            compile_mode: astral_types::ProjectionCompileMode::FullRebuild,
            full_rebuild_reason: Some(policy_engine::FullRebuildReason::WildcardImpact),
        })
        .is_ok());
    }

    // ── Archive intents ────────────────────────────────────────────────────

    #[test]
    fn archive_outbox_vocabulary_and_transitions_are_explicit() {
        for (text, expected) in [
            ("PENDING", AuthorizationArchiveOutboxStatus::Pending),
            ("LEASED", AuthorizationArchiveOutboxStatus::Leased),
            ("SUCCEEDED", AuthorizationArchiveOutboxStatus::Succeeded),
            ("QUARANTINED", AuthorizationArchiveOutboxStatus::Quarantined),
        ] {
            assert_eq!(
                AuthorizationArchiveOutboxStatus::parse(text).unwrap(),
                expected
            );
            assert_eq!(expected.as_str(), text);
        }
        assert!(AuthorizationArchiveOutboxStatus::parse("ARCHIVED").is_err());

        use AuthorizationArchiveOutboxStatus::*;
        assert!(Pending.can_transition_to(Leased));
        assert!(Leased.can_transition_to(Pending));
        assert!(Leased.can_transition_to(Succeeded));
        assert!(Pending.can_transition_to(Quarantined));
        assert!(Leased.can_transition_to(Quarantined));
        for (from, to) in [
            (Succeeded, Pending),
            (Quarantined, Leased),
            (Succeeded, Leased),
        ] {
            assert!(!from.can_transition_to(to));
        }
    }

    #[test]
    fn archive_lease_tokens_redact_debug_and_hash_deterministically() {
        let token = ArchiveLeaseToken::for_test("run-token-archive");
        assert_eq!(format!("{token:?}"), "ArchiveLeaseToken(REDACTED)");
        assert_eq!(
            token.token_hash(),
            Sha256Digest::from_raw_bytes(sha256_digest_bytes(b"run-token-archive"))
        );
        assert_ne!(
            token.token_hash(),
            ArchiveLeaseToken::for_test("run-token-other").token_hash()
        );
    }

    /// Shape guard for the bounded-retry predicate: a PENDING row carrying a
    /// future `next_attempt_at` must be non-claimable, while expired leases
    /// stay reclaimable. The candidate selection and the install CAS must
    /// repeat the SAME eligibility arm so a racing install can never widen
    /// eligibility. (Runtime behavior on real MySQL belongs to the explicit
    /// integration suite; this pins the durable contract text itself.)
    #[test]
    fn archive_claim_predicate_respects_future_pending_backoff_in_candidates_and_install() {
        const FUTURE_GUARD: &str =
            "(next_attempt_at IS NULL OR next_attempt_at <= UTC_TIMESTAMP())";
        const EXPIRED_LEASE_GUARD: &str = "(status = 'LEASED' \
           AND lease_expires_at IS NOT NULL \
           AND lease_expires_at <= UTC_TIMESTAMP())";
        for (name, sql) in [
            ("unscoped_candidate", ARCHIVE_CLAIM_CANDIDATE_UNSCOPED_SQL),
            (
                "card_scoped_candidate",
                ARCHIVE_CLAIM_CANDIDATE_CARD_SCOPED_SQL,
            ),
            ("install", ARCHIVE_CLAIM_INSTALL_SQL),
        ] {
            assert!(
                sql.contains(FUTURE_GUARD),
                "{name} must refuse future-scheduled PENDING rows"
            );
            assert!(
                sql.contains(EXPIRED_LEASE_GUARD),
                "{name} must keep reclaiming only expired leases"
            );
            // Exactly one PENDING arm: no legacy unguarded fragment may remain.
            let pending_arms = sql.matches("status = 'PENDING'").count();
            let guarded_arms = sql.matches("status = 'PENDING' AND").count();
            assert_eq!(pending_arms, 1, "{name} must keep a single PENDING arm");
            assert_eq!(
                guarded_arms, 1,
                "{name}'s single PENDING arm must carry the backoff guard"
            );
            assert!(
                !sql.contains("(status = 'PENDING')"),
                "{name} must not retain the unguarded PENDING arm"
            );
        }
    }

    #[test]
    fn archivable_chain_digest_readback_refuses_unarchivable_statuses_without_reading() {
        // Pure status-gate check via the documented vocabulary: only COMMITTED
        // and SUPERSEDED are archivable terminal states.
        assert_eq!(
            AuthorizationManifestStatus::parse(MANIFEST_STATUS_COMMITTED).unwrap(),
            AuthorizationManifestStatus::Committed
        );
        assert_eq!(
            AuthorizationManifestStatus::parse(MANIFEST_STATUS_SUPERSEDED).unwrap(),
            AuthorizationManifestStatus::Superseded
        );
        for refused in [
            MANIFEST_STATUS_BUILDING,
            MANIFEST_STATUS_READY,
            MANIFEST_STATUS_QUARANTINED,
        ] {
            assert_ne!(
                AuthorizationManifestStatus::parse(refused).unwrap(),
                AuthorizationManifestStatus::Committed
            );
            assert_ne!(
                AuthorizationManifestStatus::parse(refused).unwrap(),
                AuthorizationManifestStatus::Superseded
            );
        }
    }

    #[test]
    fn archive_key_derivation_is_deterministic_bounded_and_typed() {
        let identity = linked_identity();
        let first = derive_archive_key(&identity, 4).unwrap();
        let second = derive_archive_key(&linked_identity(), 4).unwrap();
        assert_eq!(first, second);
        assert!(first.starts_with("astral-auth-archive/v1/7/CARD/17/generation-4"));
        assert!(first.len() <= MAX_ARCHIVE_KEY_LENGTH);
        // Different generations/aggregates never collide silently.
        assert_ne!(derive_archive_key(&identity, 5).unwrap(), first);
        let foreign = ProjectionAggregateIdentity::new(8, "RULE_SET", 17).unwrap();
        assert_ne!(derive_archive_key(&foreign, 4).unwrap(), first);
    }

    fn pointer_record(generation: u64, manifest_id: i64) -> AuthorizationCurrentPointerRecord {
        AuthorizationCurrentPointerRecord {
            pointer_id: 5,
            identity: linked_identity(),
            card_id: Some(17),
            current_generation: generation,
            manifest_id,
            event_id: "parent-event".to_owned(),
            operation_id: "parent-op".to_owned(),
            semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap(),
            dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap(),
            compiler_version: "phase2-authorization-kernel-v1".to_owned(),
            revoke_fence: 2,
            revoke_fence_proven: true,
            cas_version: 12,
        }
    }

    #[test]
    fn archive_decision_requires_a_real_parent_and_first_publish_stays_clean() {
        match decide_archive_intent(None) {
            ArchiveIntentRequirement::NoArchiveRequired => {}
            ArchiveIntentRequirement::Required { .. } => panic!("first publish must not archive"),
        }
        match decide_archive_intent(Some(&pointer_record(3, 44))) {
            ArchiveIntentRequirement::NoArchiveRequired => panic!("parent demands an intent"),
            ArchiveIntentRequirement::Required { parent_pointer } => {
                assert_eq!(parent_pointer.manifest_id, 44);
                assert_eq!(parent_pointer.current_generation, 3);
                assert_eq!(parent_pointer.event_id, "parent-event");
            }
        }
    }

    fn archive_raw_row() -> ArchiveOutboxRawSqlRow {
        ArchiveOutboxRawSqlRow {
            archive_outbox_id: 77,
            tenant_id: 7,
            card_id: Some(17),
            aggregate_type: "CARD".to_owned(),
            aggregate_id: 17,
            manifest_id: 44,
            generation: 3,
            event_id: "parent-event".to_owned(),
            operation_id: "parent-op".to_owned(),
            archive_key: "astral-auth-archive/v1/7/CARD/17/generation-3".to_owned(),
            semantic_hash: vec![1u8; 32],
            dependency_hash: vec![2u8; 32],
            compiler_version: "phase2-authorization-kernel-v1".to_owned(),
            archived_revoke_fence: 2,
            status: "PENDING".to_owned(),
            attempts: 0,
            cas_version: 1,
            archived_at: None,
        }
    }

    fn archive_request_from(
        row: &ArchiveOutboxRawSqlRow,
    ) -> AuthorizationArchiveIntentAppendRequest {
        AuthorizationArchiveIntentAppendRequest {
            identity: ProjectionAggregateIdentity::new(
                row.tenant_id,
                row.aggregate_type.clone(),
                row.aggregate_id,
            )
            .unwrap(),
            card_id: row.card_id,
            archived_manifest_id: row.manifest_id,
            archived_generation: row.generation as u64,
            event_id: row.event_id.clone(),
            operation_id: row.operation_id.clone(),
            archive_key: row.archive_key.clone(),
            semantic_hash_hex: hex::encode(&row.semantic_hash),
            dependency_hash_hex: hex::encode(&row.dependency_hash),
            compiler_version: row.compiler_version.clone(),
            archived_revoke_fence: row.archived_revoke_fence as u64,
        }
    }

    #[test]
    fn archive_decode_enforces_status_stamp_discipline_and_replay_equivalence() {
        let row = archive_raw_row();
        let decoded = row.decode().unwrap();
        assert_eq!(decoded.status, AuthorizationArchiveOutboxStatus::Pending);
        assert!(decoded.archived_at.is_none());
        assert_eq!(decoded.archived_manifest_id, 44);

        // Replay equivalence holds byte-for-byte...
        let request = archive_request_from(&row);
        row.assert_equivalent_replay(
            &request,
            &Sha256Digest::from_bytes(vec![1u8; 32]).unwrap(),
            &Sha256Digest::from_bytes(vec![2u8; 32]).unwrap(),
        )
        .unwrap();

        // ...and every immutable dimension surfaces an explicit conflict.
        let expect_conflict = |mutate: &dyn Fn(&mut AuthorizationArchiveIntentAppendRequest),
                               needle: &str| {
            let mut drifted = request.clone();
            mutate(&mut drifted);
            let error = archive_raw_row()
                .assert_equivalent_replay(
                    &drifted,
                    &Sha256Digest::from_bytes(vec![1u8; 32]).unwrap(),
                    &Sha256Digest::from_bytes(vec![2u8; 32]).unwrap(),
                )
                .unwrap_err()
                .to_string();
            assert!(error.contains(needle), "expected {needle} inside: {error}");
        };
        expect_conflict(
            &|request: &mut AuthorizationArchiveIntentAppendRequest| {
                request.identity.aggregate_id = 18
            },
            "archive_replay_identity",
        );
        expect_conflict(
            &|request: &mut AuthorizationArchiveIntentAppendRequest| request.card_id = None,
            "archive_replay_card_scope",
        );
        expect_conflict(
            &|request: &mut AuthorizationArchiveIntentAppendRequest| {
                request.archived_manifest_id = 45
            },
            "archive_replay_manifest",
        );
        expect_conflict(
            &|request: &mut AuthorizationArchiveIntentAppendRequest| {
                request.archived_generation = 4
            },
            "archive_replay_generation",
        );
        expect_conflict(
            &|request: &mut AuthorizationArchiveIntentAppendRequest| {
                request.event_id = "other".to_owned()
            },
            "archive_replay_event",
        );
        expect_conflict(
            &|request: &mut AuthorizationArchiveIntentAppendRequest| {
                request.operation_id = "other".to_owned()
            },
            "archive_replay_operation",
        );
        expect_conflict(
            &|request: &mut AuthorizationArchiveIntentAppendRequest| {
                request.archive_key = "drift".to_owned()
            },
            "archive_replay_key",
        );
        expect_conflict(
            &|request: &mut AuthorizationArchiveIntentAppendRequest| {
                request.compiler_version = "other".to_owned()
            },
            "archive_replay_compiler",
        );
        // The copied parent fence participates in immutable replay too.
        assert_eq!(decoded.archived_revoke_fence, 2);
        expect_conflict(
            &|request: &mut AuthorizationArchiveIntentAppendRequest| {
                request.archived_revoke_fence = 3
            },
            "archive_replay_revoke_fence",
        );
        // Hash drift is detected through the paired digest comparison.
        let error = archive_raw_row()
            .assert_equivalent_replay(
                &request,
                &Sha256Digest::from_bytes(vec![9u8; 32]).unwrap(),
                &Sha256Digest::from_bytes(vec![2u8; 32]).unwrap(),
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("archive_replay_hash"), "{error}");

        // Stamp discipline: success without a timestamp and a timestamp
        // without success are BOTH corrupt state.
        let succeeded_late = ArchiveOutboxRawSqlRow {
            status: "SUCCEEDED".to_owned(),
            ..archive_raw_row()
        };
        assert!(succeeded_late.decode().is_err());
        let stamped_pending = ArchiveOutboxRawSqlRow {
            archived_at: Some(time::PrimitiveDateTime::new(
                time::Date::from_calendar_date(2030, time::Month::May, 5).unwrap(),
                time::Time::MIDNIGHT,
            )),
            ..archive_raw_row()
        };
        assert!(stamped_pending.decode().is_err());
        // Negative counters refuse too.
        let negative_attempts = ArchiveOutboxRawSqlRow {
            attempts: -1,
            ..archive_raw_row()
        };
        assert!(negative_attempts.decode().is_err());
    }

    #[test]
    fn archive_statements_pin_guards_and_never_delete_or_randomize() {
        assert_eq!(ARCHIVE_INTENT_INSERT_SQL.matches('?').count(), 13);
        assert!(ARCHIVE_INTENT_INSERT_SQL.ends_with("'PENDING')"));
        assert!(
            ARCHIVE_MANIFEST_INSERT_SQL.matches('?').count() == 14,
            "{ARCHIVE_MANIFEST_INSERT_SQL}"
        );
        assert!(
            ARCHIVE_INTENT_INSERT_SQL.contains("archived_revoke_fence"),
            "intent insert must persist the copied parent fence"
        );
        assert!(
            ARCHIVE_MANIFEST_INSERT_SQL.contains("archived_revoke_fence"),
            "manifest proof insert must persist the parent fence"
        );
        assert!(ARCHIVE_INTENT_BY_EVENT_TAIL.contains("WHERE event_id = ? FOR UPDATE"));
        assert!(ARCHIVE_INTENT_BY_GENERATION_TAIL
            .contains("AND aggregate_type = ? AND aggregate_id = ? AND generation = ?"));

        // Candidate selection keeps the delta-queue discipline: future-scheduled
        // PENDING rows wait for their backoff stamp, expired leases stay
        // reclaimable, deterministic order, row lock, no live stealing.
        for statement in [
            ARCHIVE_CLAIM_CANDIDATE_UNSCOPED_SQL,
            ARCHIVE_CLAIM_CANDIDATE_CARD_SCOPED_SQL,
            ARCHIVE_CLAIM_INSTALL_SQL,
        ] {
            assert!(
                statement.contains(
                    "status = 'PENDING' \
                     AND (next_attempt_at IS NULL OR next_attempt_at <= UTC_TIMESTAMP())"
                ),
                "{statement}"
            );
            assert!(
                statement.contains("lease_expires_at <= UTC_TIMESTAMP()"),
                "{statement}"
            );
            assert!(
                !statement.contains("(status = 'PENDING')"),
                "the unguarded PENDING arm must never come back: {statement}"
            );
            if statement != ARCHIVE_CLAIM_INSTALL_SQL {
                assert!(statement.contains("FOR UPDATE"));
                assert!(
                    statement.contains("ORDER BY COALESCE(next_attempt_at, created_at)"),
                    "{statement}"
                );
            }
        }
        assert!(
            !ARCHIVE_CLAIM_CANDIDATE_UNSCOPED_SQL.contains("lease_expires_at >= UTC_TIMESTAMP()")
        );

        // Install stores only the token HASH and bumps counters.
        assert!(ARCHIVE_CLAIM_INSTALL_SQL.contains("lease_token_hash = ?"));
        assert!(ARCHIVE_CLAIM_INSTALL_SQL.contains("cas_version = cas_version + 1"));
        assert!(ARCHIVE_CLAIM_INSTALL_SQL.contains("attempts = attempts + 1"));

        // Guard suffix covers ownership, status and liveness for every mutation.
        for fragment in [
            "AND status = 'LEASED'",
            "AND lease_owner = ?",
            "AND lease_token_hash = ?",
            "lease_expires_at IS NOT NULL",
            "lease_expires_at > UTC_TIMESTAMP()",
        ] {
            assert!(ARCHIVE_LEASE_GUARD_SUFFIX.contains(fragment), "{fragment}");
        }
        assert!(ARCHIVE_COMPLETE_SQL_BASE.contains("archived_at = UTC_TIMESTAMP()"));
        assert!(ARCHIVE_FAIL_SQL_BASE.contains("TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP())"));
        assert!(ARCHIVE_RELEASE_SQL_BASE.contains("next_attempt_at = NULL"));

        for statement in [
            ARCHIVE_CLAIM_INSTALL_SQL,
            ARCHIVE_LEASE_GUARD_SUFFIX,
            ARCHIVE_COMPLETE_SQL_BASE,
            ARCHIVE_FAIL_SQL_BASE,
            ARCHIVE_RELEASE_SQL_BASE,
        ] {
            assert!(!statement.to_uppercase().contains("DELETE"));
        }
    }

    // ── Combined projector command shape ───────────────────────────────────

    fn shaped_stage() -> AuthorizationStageRequest {
        AuthorizationStageRequest {
            identity: linked_identity(),
            card_id: Some(17),
            target_generation: 2,
            source_generation: 5,
            projected_generation: 5,
            event_id: "event-delta".to_owned(),
            operation_id: "op-delta".to_owned(),
            semantic_hash_hex: HASH_A.to_owned(),
            dependency_hash_hex: HASH_B.to_owned(),
            compiler_version: "phase2-authorization-kernel-v1".to_owned(),
            revoke_fence: 2,
            segments: vec![StagedSegmentContent::New(vec![grant(1)])],
        }
    }

    fn shaped_plan() -> AuthorizationImpactPlanAppendRequest {
        AuthorizationImpactPlanAppendRequest {
            identity: linked_identity(),
            card_id: Some(17),
            event_id: "event-delta".to_owned(),
            operation_id: "op-delta".to_owned(),
            base_generation: 1,
            target_generation: 2,
            base_version: 0,
            target_version: 1,
            semantic_hash_hex: HASH_A.to_owned(),
            dependency_hash_hex: HASH_B.to_owned(),
            compiler_version: "phase2-authorization-kernel-v1".to_owned(),
            items: vec![impact_item_upsert("{\"action\":\"read\",\"cardId\":17}")],
        }
    }

    fn shaped_command() -> DeltaProjectorPublishCommand {
        let (_, lease_identity) = build_claimed_event();
        DeltaProjectorPublishCommand {
            delta_lease_identity: lease_identity,
            expectation: DeltaProjectorExpectation {
                identity: linked_identity(),
                card_id: Some(17),
                event_id: "event-delta".to_owned(),
                operation_id: "op-delta".to_owned(),
                base_version: 0,
                target_version: 1,
                source_generation: 5,
                semantic_hash_hex: HASH_A.to_owned(),
                dependency_hash_hex: HASH_B.to_owned(),
                compiler_version: "phase2-authorization-kernel-v1".to_owned(),
            },
            fences: PublishRevokeFenceEvidence {
                previous_revoke_fence: 2,
                new_revoke_fence: 2,
            },
            mode: CompileModeEvidence {
                compile_mode: astral_types::ProjectionCompileMode::Incremental,
                full_rebuild_reason: None,
            },
            stage: shaped_stage(),
            finalize_expected_reference_count: Some(1),
            impact_plan: shaped_plan(),
            manifest_lease_owner: "worker-x".to_owned(),
            manifest_lease_seconds: 120,
        }
    }

    #[test]
    fn command_shape_accepts_the_fully_aligned_package() {
        let command = shaped_command();
        assert!(validate_projector_command_shape(&command).is_ok());
    }

    #[test]
    fn command_shape_refuses_cross_component_drift_before_any_sql_runs() {
        let expect_refusal = |mutate: &dyn Fn(&mut DeltaProjectorPublishCommand), needle: &str| {
            let mut command = shaped_command();
            mutate(&mut command);
            let error = validate_projector_command_shape(&command)
                .unwrap_err()
                .to_string();
            assert!(error.contains(needle), "expected {needle} inside: {error}");
        };

        expect_refusal(
            &|command| command.stage.identity.aggregate_id = 18,
            "command_identity_mismatch",
        );
        expect_refusal(
            &|command| command.impact_plan.card_id = None,
            "command_card_scope_mismatch",
        );
        expect_refusal(
            &|command| command.impact_plan.event_id = "other".to_owned(),
            "command_provenance_mismatch",
        );
        expect_refusal(
            &|command| command.stage.operation_id = "other".to_owned(),
            "command_provenance_mismatch",
        );
        expect_refusal(
            &|command| command.stage.source_generation = 6,
            "command_source_generation_mismatch",
        );
        expect_refusal(
            &|command| {
                command.impact_plan.semantic_hash_hex = HASH_B.to_owned();
            },
            "command_hash_mismatch",
        );
        expect_refusal(
            &|command| command.stage.compiler_version = "other".to_owned(),
            "command_compiler_mismatch",
        );
        expect_refusal(
            &|command| {
                command.impact_plan.target_version = 9;
            },
            "command_version_window_mismatch",
        );

        // Mode evidence re-validates through the shape gate.
        expect_refusal(
            &|command| {
                command.mode.compile_mode = astral_types::ProjectionCompileMode::FullRebuild;
                command.mode.full_rebuild_reason = None;
            },
            "full_rebuild_requires_reason",
        );

        // Malformed items stay away from SQL entirely.
        expect_refusal(
            &|command| {
                let mut broken = impact_item_upsert("{\"action\":\"read\"}");
                broken.after_digest_hex = None;
                command.impact_plan.items = vec![broken];
            },
            "upsert_requires_after_digest",
        );

        // An empty item list is refused like any other plan draft.
        expect_refusal(
            &|command| command.impact_plan.items = Vec::new(),
            "empty_impact_plan",
        );
    }

    // ── Segment-local seals (fix A) ─────────────────────────────────────────

    fn sealed_snapshot(
        identity: &ProjectionAggregateIdentity,
        card_id: Option<i64>,
        compiler_version: &str,
        grants: &[CanonicalGrant],
        segment_id: i64,
    ) -> AuthorizationSegmentSnapshot {
        let payload = encode_segment_payload(grants).unwrap();
        let content_digest = Sha256Digest::from_raw_bytes(sha256_digest_bytes(&payload));
        let (semantic, dependency) = segment_local_seal_pair(
            identity,
            card_id,
            compiler_version,
            grants.len() as u64,
            &content_digest,
        )
        .unwrap();
        AuthorizationSegmentSnapshot {
            segment_id,
            identity: identity.clone(),
            card_id,
            content_digest,
            semantic_hash: semantic,
            dependency_hash: dependency,
            compiler_version: compiler_version.to_owned(),
            format: SEGMENT_FORMAT_AUTHORIZATION_GRANTS_JSON_V1.to_owned(),
            row_count: grants.len() as u64,
            byte_size: payload.len() as u64,
            grants: grants.to_vec(),
        }
    }

    #[test]
    fn segment_local_seals_bind_every_immutable_dimension_and_stay_generation_invariant() {
        let identity = identity();
        let snapshot = sealed_snapshot(&identity, Some(17), "compiler-v1", &[grant(1)], 9);

        // Deterministic: recomputation reproduces both seals exactly.
        let recomputed = segment_local_seal_pair(
            &identity,
            Some(17),
            "compiler-v1",
            snapshot.row_count,
            &snapshot.content_digest,
        )
        .unwrap();
        assert_eq!(snapshot.semantic_hash, recomputed.0);
        assert_eq!(snapshot.dependency_hash, recomputed.1);
        // Distinct domain tags never collide.
        assert_ne!(snapshot.semantic_hash, snapshot.dependency_hash);

        // Every bound dimension moves at least one seal when it drifts.
        for mutation in [
            "tenant",
            "aggregate",
            "card",
            "compiler",
            "row_count",
            "content_digest",
        ] {
            let drifted_input = |identity_ref: &ProjectionAggregateIdentity,
                                 card: Option<i64>,
                                 compiler: &str,
                                 row_count: u64,
                                 digest: &Sha256Digest| {
                segment_local_seal_pair(identity_ref, card, compiler, row_count, digest).unwrap()
            };
            let (semantic, dependency) = match mutation {
                "tenant" => drifted_input(
                    &ProjectionAggregateIdentity::new(8, "CARD", 17).unwrap(),
                    Some(17),
                    "compiler-v1",
                    1,
                    &snapshot.content_digest,
                ),
                "aggregate" => drifted_input(
                    &ProjectionAggregateIdentity::new(7, "CARD", 18).unwrap(),
                    Some(17),
                    "compiler-v1",
                    1,
                    &snapshot.content_digest,
                ),
                "card" => {
                    drifted_input(&identity, None, "compiler-v1", 1, &snapshot.content_digest)
                }
                "compiler" => drifted_input(
                    &identity,
                    Some(17),
                    "compiler-v2",
                    1,
                    &snapshot.content_digest,
                ),
                "row_count" => drifted_input(
                    &identity,
                    Some(17),
                    "compiler-v1",
                    2,
                    &snapshot.content_digest,
                ),
                _ => drifted_input(
                    &identity,
                    Some(17),
                    "compiler-v1",
                    1,
                    &Sha256Digest::from_hex(HASH_B).unwrap(),
                ),
            };
            assert_ne!(
                snapshot.semantic_hash, semantic,
                "{mutation} must move the semantic seal"
            );
            assert_ne!(
                snapshot.dependency_hash, dependency,
                "{mutation} must move the dependency seal"
            );
        }
    }

    #[test]
    fn verify_segment_local_seal_refuses_tampered_metadata_fail_closed() {
        let identity = identity();
        let base = sealed_snapshot(&identity, Some(17), "compiler-v1", &[grant(1)], 9);
        verify_segment_local_seal(&base).unwrap();

        // Tampering ANY local dimension without recomputing the seals is
        // corrupt storage. This includes compiler stamps and LOCAL hash
        // columns, which no longer compare against any manifest-global value.
        let mut tampered = base.clone();
        tampered.card_id = None;
        assert!(verify_segment_local_seal(&tampered).is_err());

        let mut tampered = base.clone();
        tampered.compiler_version = "compiler-v2".to_owned();
        assert!(verify_segment_local_seal(&tampered).is_err());

        let mut tampered = base.clone();
        tampered.row_count = 4;
        assert!(verify_segment_local_seal(&tampered).is_err());

        let mut tampered = base.clone();
        tampered.semantic_hash = Sha256Digest::from_hex(HASH_B).unwrap();
        assert!(verify_segment_local_seal(&tampered).is_err());

        let mut tampered = base.clone();
        tampered.dependency_hash = Sha256Digest::from_hex(HASH_A).unwrap();
        assert!(verify_segment_local_seal(&tampered).is_err());

        let mut tampered = base.clone();
        tampered.content_digest = Sha256Digest::from_hex(HASH_B).unwrap();
        assert!(verify_segment_local_seal(&tampered).is_err());
    }

    #[test]
    fn identical_segment_verification_reports_compiler_stamp_divergence_as_its_own_code() {
        let identity = linked_identity();
        let request = shaped_stage();
        let grants = vec![grant(1)];

        // Baseline: the same stamp reproduces a byte-identical admissible row.
        let snapshot = sealed_snapshot(
            &identity,
            Some(17),
            request.compiler_version.as_str(),
            &grants,
            9,
        );
        let (semantic_seal, dependency_seal) = segment_local_seal_pair(
            &request.identity,
            request.card_id,
            request.compiler_version.as_str(),
            snapshot.row_count,
            &snapshot.content_digest,
        )
        .unwrap();
        assert_identical_segment(
            &snapshot,
            &request,
            &snapshot.content_digest,
            &semantic_seal,
            &dependency_seal,
            request.compiler_version.as_str(),
        )
        .unwrap();

        // A future compiler upgrade that legitimately reuses the byte-identical
        // payload hits the one-row-per-digest key with a diverging stamp. The
        // payload is proven intact, so this carries the dedicated machine code
        // and is NEVER labeled `digest_metadata_collision` (corruption family).
        let upgraded_request_compiler = "phase2-authorization-kernel-v2";
        let (upgraded_semantic, upgraded_dependency) = segment_local_seal_pair(
            &request.identity,
            request.card_id,
            upgraded_request_compiler,
            snapshot.row_count,
            &snapshot.content_digest,
        )
        .unwrap();
        let error = assert_identical_segment(
            &snapshot,
            &request,
            &snapshot.content_digest,
            &upgraded_semantic,
            &upgraded_dependency,
            upgraded_request_compiler,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains(SEGMENT_COMPILER_STAMP_DIVERGENCE_CODE),
            "compiler stamp divergence must report its dedicated code: {error}"
        );
        assert!(
            !error.contains("digest_metadata_collision"),
            "proven-intact content must not be labeled corrupt: {error}"
        );

        // The corruption-family codes stay exactly where they were: a seal
        // mismatch under the SAME stamp (tampered columns) and a foreign
        // format stamp.
        let mut corrupted_seals = snapshot.clone();
        corrupted_seals.semantic_hash = Sha256Digest::from_hex(HASH_B).unwrap();
        let error = assert_identical_segment(
            &corrupted_seals,
            &request,
            &snapshot.content_digest,
            &semantic_seal,
            &dependency_seal,
            request.compiler_version.as_str(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("digest_metadata_collision"), "{error}");

        let mut foreign_format = snapshot.clone();
        foreign_format.format = "foreign_format".to_owned();
        let error = assert_identical_segment(
            &foreign_format,
            &request,
            &snapshot.content_digest,
            &semantic_seal,
            &dependency_seal,
            request.compiler_version.as_str(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("digest_metadata_collision"), "{error}");

        // Cross-scope reuse of one digest is still a hard collision.
        let foreign_request = AuthorizationStageRequest {
            identity: ProjectionAggregateIdentity::new(7, "CARD", 18).unwrap(),
            ..shaped_stage()
        };
        let error = assert_identical_segment(
            &snapshot,
            &foreign_request,
            &snapshot.content_digest,
            &semantic_seal,
            &dependency_seal,
            request.compiler_version.as_str(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("cross_aggregate_digest_collision"),
            "{error}"
        );
    }

    /// Generation 1→2 real-delta rehearsal, purely: two unchanged segments
    /// (`A`, `C`) keep their refs while only `B` is rewritten, and the target
    /// manifest's GLOBAL semantic/dependency hashes legitimately move without
    /// breaking any seal check.
    #[test]
    fn generation_delta_reuses_unchanged_segments_and_writes_only_the_changed_one() {
        let identity = identity();
        let compiler = "phase2-authorization-kernel-v1";

        // Generation 1: three NEW segments A / B / C.
        let grants_a = vec![grant(1)];
        let grants_b = vec![grant(2)];
        let grants_c = vec![grant(3)];
        let snap_a = sealed_snapshot(&identity, Some(17), compiler, &grants_a, 101);
        let snap_b = sealed_snapshot(&identity, Some(17), compiler, &grants_b, 102);
        let snap_c = sealed_snapshot(&identity, Some(17), compiler, &grants_c, 103);

        // Parent generation-1 references pointing at those contents.
        let parent_records = vec![
            AuthorizationSegmentReferenceRecord {
                reference_id: 1,
                manifest_id: 500,
                identity: identity.clone(),
                card_id: Some(17),
                generation: 1,
                ordinal: 0,
                segment_id: snap_a.segment_id,
                content_digest: snap_a.content_digest,
                event_id: "event-gen1".to_owned(),
                operation_id: "op-gen1".to_owned(),
            },
            AuthorizationSegmentReferenceRecord {
                reference_id: 2,
                manifest_id: 500,
                identity: identity.clone(),
                card_id: Some(17),
                generation: 1,
                ordinal: 1,
                segment_id: snap_b.segment_id,
                content_digest: snap_b.content_digest,
                event_id: "event-gen1".to_owned(),
                operation_id: "op-gen1".to_owned(),
            },
            AuthorizationSegmentReferenceRecord {
                reference_id: 3,
                manifest_id: 500,
                identity: identity.clone(),
                card_id: Some(17),
                generation: 1,
                ordinal: 2,
                segment_id: snap_c.segment_id,
                content_digest: snap_c.content_digest,
                event_id: "event-gen1".to_owned(),
                operation_id: "op-gen1".to_owned(),
            },
        ];

        // Generation 2 target: real delta moves BOTH global hashes…
        let gen1_semantic = Sha256Digest::from_hex(HASH_A).unwrap();
        let gen1_dependency = Sha256Digest::from_hex(HASH_B).unwrap();
        let gen2_semantic = Sha256Digest::from_hex(HASH_B).unwrap();
        let gen2_dependency = Sha256Digest::from_hex(HASH_A).unwrap();
        assert_ne!(gen1_semantic, gen2_semantic);
        assert_ne!(gen1_dependency, gen2_dependency);

        // …while the unchanged segments' LOCAL seals stay bit-identical (the
        // seal surface excludes generation numbers, provenance and global
        // hashes entirely).
        for (record, snapshot) in [(&parent_records[0], &snap_a), (&parent_records[2], &snap_c)] {
            let recomputed = segment_local_seal_pair(
                &identity,
                Some(17),
                compiler,
                snapshot.row_count,
                &snapshot.content_digest,
            )
            .unwrap();
            assert_eq!(snapshot.semantic_hash, recomputed.0);
            assert_eq!(snapshot.dependency_hash, recomputed.1);
            // The decoupling itself: a seal is NOT the (moved) global hash.
            assert_ne!(snapshot.semantic_hash, gen2_semantic);
            // Reference ↔ content ↔ local-seal pairing survives.
            verify_reference_content_pair(record, snapshot, &identity).unwrap();
        }

        // The generation-2 staging plan: reuse A and C, rewrite B only.
        let grants_b2 = vec![grant(0x22)];
        assert_ne!(
            encode_segment_payload(&grants_b2).unwrap(),
            encode_segment_payload(&grants_b).unwrap(),
            "the B delta must really change segment bytes"
        );
        let snap_b2 = sealed_snapshot(&identity, Some(17), compiler, &grants_b2, -1);
        let plan = vec![
            StagedSegmentContent::ReuseParent { parent_ordinal: 0 },
            StagedSegmentContent::New(grants_b2.clone()),
            StagedSegmentContent::ReuseParent { parent_ordinal: 2 },
        ];
        let counts = validate_staging_plan_against_parent(
            &identity,
            &plan,
            Some(parent_reference_views(&parent_records).as_slice()),
        )
        .unwrap();
        assert_eq!(counts, (1, 2), "only B is written; A and C are true refs");

        // Every dim of the reused rows would satisfy finalize/publish/read:
        // LOCAL seal verification passes per segment, and ONLY the rewritten
        // segment carries a new content address.
        for snapshot in [&snap_a, &snap_c] {
            verify_segment_local_seal(snapshot).unwrap();
        }
        verify_segment_local_seal(&snap_b2).unwrap();
        assert_ne!(snap_b2.content_digest, snap_b.content_digest);
    }

    #[test]
    fn parent_chain_verification_pins_the_parents_own_global_hashes_only() {
        let identity = identity();
        let compiler = "phase2-authorization-kernel-v1";
        let snap_a = sealed_snapshot(&identity, Some(17), compiler, &[grant(1)], 201);
        let snap_b = sealed_snapshot(&identity, Some(17), compiler, &[grant(2)], 202);

        let mut parent_row = ManifestRawSqlRow {
            manifest_id: 700,
            tenant_id: identity.tenant_id,
            card_id: Some(17),
            aggregate_type: identity.aggregate_type.clone(),
            aggregate_id: identity.aggregate_id,
            generation: 1,
            source_generation: 5,
            projected_generation: 5,
            event_id: "event-gen1".to_owned(),
            operation_id: "op-gen1".to_owned(),
            semantic_hash: gen1_hash_vec("semantic"),
            dependency_hash: gen1_hash_vec("dependency"),
            compiler_version: compiler.to_owned(),
            manifest_digest: Vec::new(),
            status: MANIFEST_STATUS_COMMITTED.to_owned(),
            cas_version: 2,
            lease_owner: None,
            lease_token_hash: None,
            lease_expires_at: None,
            parent_manifest_id: None,
            revoke_fence: 0,
        };
        let references = [
            AuthorizationSegmentReferenceRecord {
                reference_id: 11,
                manifest_id: 700,
                identity: identity.clone(),
                card_id: Some(17),
                generation: 1,
                ordinal: 0,
                segment_id: snap_a.segment_id,
                content_digest: snap_a.content_digest,
                event_id: "event-gen1".to_owned(),
                operation_id: "op-gen1".to_owned(),
            },
            AuthorizationSegmentReferenceRecord {
                reference_id: 12,
                manifest_id: 700,
                identity: identity.clone(),
                card_id: Some(17),
                generation: 1,
                ordinal: 1,
                segment_id: snap_b.segment_id,
                content_digest: snap_b.content_digest,
                event_id: "event-gen1".to_owned(),
                operation_id: "op-gen1".to_owned(),
            },
        ];
        // Seal the parent over its OWN hashes plus the ordered digests.
        let semantic_hex = hex::encode(&parent_row.semantic_hash);
        let dependency_hex = hex::encode(&parent_row.dependency_hash);
        let sealed = compute_manifest_digest(&ManifestDigestInput {
            tenant_id: parent_row.tenant_id,
            aggregate_type: &parent_row.aggregate_type,
            aggregate_id: parent_row.aggregate_id,
            card_id: parent_row.card_id,
            generation: 1,
            source_generation: 5,
            projected_generation: 5,
            event_id: &parent_row.event_id,
            operation_id: &parent_row.operation_id,
            semantic_hash_hex: &semantic_hex,
            dependency_hash_hex: &dependency_hex,
            compiler_version: &parent_row.compiler_version,
            parent_manifest_id: parent_row.decode_parent_manifest_id().unwrap(),
            revoke_fence: parent_row.decode_revoke_fence().unwrap(),
            segment_content_digests_hex: vec![
                snap_a.content_digest.as_hex(),
                snap_b.content_digest.as_hex(),
            ],
        })
        .unwrap();
        parent_row.manifest_digest = sealed.as_bytes().to_vec();

        verify_parent_manifest_chain(&parent_row, &references).unwrap();

        // Any internal drift breaks the parent's own seal…
        let mut drifted = parent_row.clone();
        drifted.semantic_hash = gen1_hash_vec("semantic-drift");
        let error = verify_parent_manifest_chain(&drifted, &references).unwrap_err();
        assert!(
            matches!(error, AuthorizationProjectionError::Corrupt(ref message)
            if message.contains("parent_manifest_digest_seal_broken"))
        );

        // …including reordered reference evidence.
        let reordered = [references[1].clone(), references[0].clone()];
        assert!(verify_parent_manifest_chain(&parent_row, &reordered).is_err());

        // Gapped ordinals refuse outright.
        let mut gapped = references.clone();
        gapped[1].ordinal = 3;
        assert!(verify_parent_manifest_chain(&parent_row, &gapped).is_err());
    }

    fn gen1_hash_vec(seed: &str) -> Vec<u8> {
        sha256_digest_bytes(seed.as_bytes()).to_vec()
    }

    // ── Archive durable proofs (fix B) ──────────────────────────────────────

    fn archive_identity() -> ProjectionAggregateIdentity {
        ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap()
    }

    fn archive_digest_input<'a>(
        semantic: &'a Sha256Digest,
        dependency: &'a Sha256Digest,
        chain: &'a Sha256Digest,
    ) -> AuthorizationArchiveDigestInput<'a> {
        AuthorizationArchiveDigestInput {
            tenant_id: 7,
            aggregate_type: "CARD",
            aggregate_id: 17,
            card_id: Some(17),
            archived_manifest_id: 500,
            archived_generation: 3,
            event_id: "event-gen2",
            operation_id: "op-gen2",
            archive_key: "astral-auth-archive/v1/7/CARD/17/generation-3",
            archived_revoke_fence: 2,
            semantic_hash: semantic,
            dependency_hash: dependency,
            compiler_version: "phase2-authorization-kernel-v1",
            manifest_chain_digest: chain,
        }
    }

    #[test]
    fn archive_proof_digest_binds_every_dimension_deterministically() {
        let semantic = Sha256Digest::from_hex(HASH_A).unwrap();
        let dependency = Sha256Digest::from_hex(HASH_B).unwrap();
        let chain = Sha256Digest::from_raw_bytes(sha256_digest_bytes(b"chain"));
        let baseline = compute_authorization_archive_digest(&archive_digest_input(
            &semantic,
            &dependency,
            &chain,
        ))
        .unwrap();
        // Deterministic across independent invocations.
        assert_eq!(
            baseline,
            compute_authorization_archive_digest(&archive_digest_input(
                &semantic,
                &dependency,
                &chain,
            ))
            .unwrap()
        );

        // Each textual/binary dimension participates; statuses/timestamps do
        // not enter the seal by design.
        let alt_chain = Sha256Digest::from_raw_bytes(sha256_digest_bytes(b"other"));
        let base = || archive_digest_input(&semantic, &dependency, &chain);
        let expects = [
            (
                AuthorizationArchiveDigestInput {
                    archived_manifest_id: 501,
                    ..base()
                },
                "archived_manifest_id",
            ),
            (
                AuthorizationArchiveDigestInput {
                    archived_generation: 4,
                    ..base()
                },
                "archived_generation",
            ),
            (
                AuthorizationArchiveDigestInput {
                    event_id: "event-other",
                    ..base()
                },
                "event_id",
            ),
            (
                AuthorizationArchiveDigestInput {
                    operation_id: "op-other",
                    ..base()
                },
                "operation_id",
            ),
            (
                AuthorizationArchiveDigestInput {
                    archive_key: "astral-auth-archive/v1/7/CARD/17/generation-4",
                    ..base()
                },
                "archive_key",
            ),
            (
                AuthorizationArchiveDigestInput {
                    archived_revoke_fence: 3,
                    ..base()
                },
                "archived_revoke_fence",
            ),
            (
                AuthorizationArchiveDigestInput {
                    compiler_version: "other-compiler",
                    ..base()
                },
                "compiler_version",
            ),
            (
                AuthorizationArchiveDigestInput {
                    card_id: None,
                    ..base()
                },
                "card_scope",
            ),
            (
                AuthorizationArchiveDigestInput {
                    semantic_hash: &dependency,
                    ..base()
                },
                "semantic_hash",
            ),
            (
                AuthorizationArchiveDigestInput {
                    dependency_hash: &semantic,
                    ..base()
                },
                "dependency_hash",
            ),
            (
                AuthorizationArchiveDigestInput {
                    manifest_chain_digest: &alt_chain,
                    ..base()
                },
                "manifest_chain_digest",
            ),
        ];
        for (input, dimension) in expects {
            let digest = compute_authorization_archive_digest(&input).unwrap();
            assert_ne!(baseline, digest, "{dimension} must move the seal");
        }
    }

    fn archive_manifest_raw_row(
        status: &str,
        archived_at: Option<time::PrimitiveDateTime>,
    ) -> ArchiveManifestRawSqlRow {
        ArchiveManifestRawSqlRow {
            archive_manifest_id: 900,
            tenant_id: 7,
            card_id: Some(17),
            aggregate_type: "CARD".to_owned(),
            aggregate_id: 17,
            manifest_id: 500,
            generation: 3,
            event_id: "event-gen2".to_owned(),
            operation_id: "op-gen2".to_owned(),
            archive_key: "astral-auth-archive/v1/7/CARD/17/generation-3".to_owned(),
            archive_digest: sha256_digest_bytes(b"archive").to_vec(),
            semantic_hash: sha256_digest_bytes(b"semantic").to_vec(),
            dependency_hash: sha256_digest_bytes(b"dependency").to_vec(),
            compiler_version: "phase2-authorization-kernel-v1".to_owned(),
            archived_revoke_fence: 2,
            status: status.to_owned(),
            cas_version: 1,
            archived_at,
        }
    }

    fn stamp() -> time::PrimitiveDateTime {
        time::PrimitiveDateTime::new(
            time::Date::from_calendar_date(2031, time::Month::March, 3).unwrap(),
            time::Time::MIDNIGHT,
        )
    }

    #[test]
    fn archive_manifest_status_vocabulary_and_stamp_parity_fail_closed() {
        // Status vocabulary mirrors the schema default plus one terminal word.
        assert_eq!("STAGED", ARCHIVE_MANIFEST_STATUS_STAGED);
        assert_eq!("ARCHIVED", ARCHIVE_MANIFEST_STATUS_ARCHIVED);
        assert!(AuthorizationArchiveManifestStatus::parse("PENDING").is_err());
        assert!(AuthorizationArchiveManifestStatus::parse("").is_err());
        assert!(AuthorizationArchiveManifestStatus::Staged
            .can_transition_to(AuthorizationArchiveManifestStatus::Archived));
        assert!(!AuthorizationArchiveManifestStatus::Archived
            .can_transition_to(AuthorizationArchiveManifestStatus::Staged));

        // Terminal-with-stamp and staged-without-stamp decode cleanly.
        assert!(archive_manifest_raw_row("ARCHIVED", Some(stamp()))
            .decode()
            .is_ok());
        assert!(archive_manifest_raw_row("STAGED", None).decode().is_ok());

        // Parity violations are corrupt storage, never normalized away.
        for (status, stamp_value, expected_code) in [
            ("ARCHIVED", None, "archive_terminal_without_stamp"),
            (
                "STAGED",
                Some(stamp()),
                "archive_stamp_without_terminal_status",
            ),
        ] {
            let error = archive_manifest_raw_row(status, stamp_value)
                .decode()
                .unwrap_err();
            assert!(
                matches!(error, AuthorizationProjectionError::Corrupt(ref message)
                if message.contains(expected_code)),
                "expected {expected_code}"
            );
        }
        assert!(archive_manifest_raw_row("SUCCEEDED", Some(stamp()))
            .decode()
            .is_err());
        assert!(archive_manifest_raw_row("", None).decode().is_err());
    }

    fn succeeded_outbox_record() -> AuthorizationArchiveOutboxRecord {
        AuthorizationArchiveOutboxRecord {
            archive_outbox_id: 300,
            identity: archive_identity(),
            card_id: Some(17),
            archived_manifest_id: 500,
            archived_generation: 3,
            event_id: "event-gen2".to_owned(),
            operation_id: "op-gen2".to_owned(),
            archive_key: "astral-auth-archive/v1/7/CARD/17/generation-3".to_owned(),
            semantic_hash: Sha256Digest::from_raw_bytes(sha256_digest_bytes(b"semantic")),
            dependency_hash: Sha256Digest::from_raw_bytes(sha256_digest_bytes(b"dependency")),
            compiler_version: "phase2-authorization-kernel-v1".to_owned(),
            archived_revoke_fence: 2,
            status: AuthorizationArchiveOutboxStatus::Leased,
            attempts: 1,
            cas_version: 4,
            archived_at: None,
        }
    }

    fn archiving_proof_record(
        stamp_value: Option<time::PrimitiveDateTime>,
    ) -> AuthorizationArchiveManifestProof {
        AuthorizationArchiveManifestProof {
            archive_manifest_id: 900,
            identity: archive_identity(),
            card_id: Some(17),
            archived_manifest_id: 500,
            archived_generation: 3,
            event_id: "event-gen2".to_owned(),
            operation_id: "op-gen2".to_owned(),
            archive_key: "astral-auth-archive/v1/7/CARD/17/generation-3".to_owned(),
            semantic_hash: Sha256Digest::from_raw_bytes(sha256_digest_bytes(b"semantic")),
            dependency_hash: Sha256Digest::from_raw_bytes(sha256_digest_bytes(b"dependency")),
            compiler_version: "phase2-authorization-kernel-v1".to_owned(),
            archived_revoke_fence: 2,
            archive_digest: Sha256Digest::from_raw_bytes(sha256_digest_bytes(b"sealed")),
            status: AuthorizationArchiveManifestStatus::Archived,
            cas_version: 0,
            archived_at: stamp_value,
        }
    }

    #[test]
    fn terminal_gate_and_intent_pairing_refuse_every_drift_dimension() {
        // STAGED proofs never complete intents.
        let mut proof = archiving_proof_record(Some(stamp()));
        proof.status = AuthorizationArchiveManifestStatus::Staged;
        let error = validate_terminal_archive_proof(&proof).unwrap_err();
        assert!(
            matches!(error, AuthorizationProjectionError::Mapping(ref message)
            if message.contains("archive_proof_not_terminal"))
        );
        proof.status = AuthorizationArchiveManifestStatus::Archived;

        // Terminal without its exclusive stamp is corrupt.
        let unstamped = archiving_proof_record(None);
        assert!(
            matches!(validate_terminal_archive_proof(&unstamped).unwrap_err(),
                     AuthorizationProjectionError::Corrupt(ref message)
                if message.contains("archive_terminal_without_stamp"))
        );

        // Happy path pairs cleanly.
        let intent = succeeded_outbox_record();
        ensure_archive_proof_matches_intent(&intent, &proof).unwrap();

        // Each shared dimension drifts with a distinct, named refusal.
        let expect_mismatch = |proof: &AuthorizationArchiveManifestProof, dimension: &str| {
            let error = ensure_archive_proof_matches_intent(&intent, proof).unwrap_err();
            assert!(
                matches!(error, AuthorizationProjectionError::ImmutableConflict(ref message)
                if message.contains(dimension)),
                "expected dimension {dimension}"
            );
        };

        let mut drifted = proof.clone();
        drifted.identity.aggregate_id = 99;
        expect_mismatch(&drifted, "identity");

        let mut drifted = proof.clone();
        drifted.card_id = None;
        expect_mismatch(&drifted, "card_scope");

        let mut drifted = proof.clone();
        drifted.archived_manifest_id = 501;
        expect_mismatch(&drifted, "archived_manifest_id");

        let mut drifted = proof.clone();
        drifted.archived_generation = 4;
        expect_mismatch(&drifted, "generation");

        let mut drifted = proof.clone();
        drifted.event_id = "other-event".to_owned();
        expect_mismatch(&drifted, "event_id");

        let mut drifted = proof.clone();
        drifted.operation_id = "other-op".to_owned();
        expect_mismatch(&drifted, "operation_id");

        let mut drifted = proof.clone();
        drifted.archive_key = "astral-auth-archive/v1/7/CARD/17/generation-4".to_owned();
        expect_mismatch(&drifted, "archive_key");

        let mut drifted = proof.clone();
        drifted.semantic_hash = Sha256Digest::from_hex(HASH_A).unwrap();
        expect_mismatch(&drifted, "hash_trio");

        let mut drifted = proof.clone();
        drifted.compiler_version = "other-compiler".to_owned();
        expect_mismatch(&drifted, "compiler_version");

        let mut drifted = proof.clone();
        drifted.archived_revoke_fence += 1;
        expect_mismatch(&drifted, "archived_revoke_fence");
    }

    // ── published aggregate frontier planning (pure assembly) ───────────────

    fn sql_placeholder_count(sql: &str) -> usize {
        sql.bytes().filter(|byte| *byte == b'?').count()
    }

    fn frontier_identity() -> ProjectionAggregateIdentity {
        ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap()
    }

    const FRONTIER_COMPILER: &str = "phase2-authorization-kernel-v1";

    fn frontier_pointer(
        generation: u64,
        event: &str,
        operation: &str,
    ) -> AuthorizationCurrentPointerRecord {
        AuthorizationCurrentPointerRecord {
            pointer_id: 3,
            identity: frontier_identity(),
            card_id: Some(17),
            current_generation: generation,
            manifest_id: 700 + generation as i64,
            event_id: event.to_owned(),
            operation_id: operation.to_owned(),
            semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap(),
            dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap(),
            compiler_version: FRONTIER_COMPILER.to_owned(),
            revoke_fence: 4,
            revoke_fence_proven: true,
            cas_version: 12,
        }
    }

    fn frontier_manifest(
        generation: u64,
        event: &str,
        operation: &str,
        source_generation: u64,
        revoke_fence: u64,
    ) -> PublishedGenerationSummary {
        PublishedGenerationSummary {
            manifest_id: 700 + generation as i64,
            generation,
            source_generation,
            projected_generation: source_generation + generation,
            event_id: event.to_owned(),
            operation_id: operation.to_owned(),
            semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap(),
            dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap(),
            compiler_version: FRONTIER_COMPILER.to_owned(),
            manifest_digest: Sha256Digest::from_raw_bytes(sha256_digest_bytes(b"manifest")),
            parent_manifest_id: Some(699),
            revoke_fence,
            card_id: Some(17),
        }
    }

    fn frontier_plan_evidence(
        generation: u64,
        base_generation: u64,
        event: &str,
        operation: &str,
        base_version: i64,
        target_version: i64,
    ) -> FrontierPlanEvidence {
        FrontierPlanEvidence {
            plan_id: generation as i64,
            event_id: event.to_owned(),
            operation_id: operation.to_owned(),
            card_id: Some(17),
            base_generation,
            target_generation: generation,
            base_version,
            target_version,
            semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap(),
            dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap(),
            compiler_version: FRONTIER_COMPILER.to_owned(),
            status: AuthorizationImpactPlanStatus::Succeeded,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn frontier_delta_evidence(
        event: &str,
        operation: &str,
        grant: GrantId,
        base_version: i64,
        target_version: i64,
        source_generation: u64,
        revoke_fence: u64,
        status: &str,
    ) -> FrontierDeltaEvidence {
        FrontierDeltaEvidence {
            delta_event_id: 1000,
            event_id: event.to_owned(),
            operation_id: operation.to_owned(),
            event_type: DeltaEventType::Update,
            card_id: Some(17),
            tenant_id: 7,
            aggregate_type: "CARD".to_owned(),
            aggregate_id: 17,
            grant_id: grant,
            base_version,
            target_version,
            source_generation,
            revoke_fence,
            semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap(),
            dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap(),
            compiler_version: FRONTIER_COMPILER.to_owned(),
            status_str: status.to_owned(),
        }
    }

    fn frontier_grant(tail: u16) -> GrantId {
        GrantId::parse(&format!("550e8400-e29b-41d4-a716-44665544{tail:04x}")).unwrap()
    }

    /// Three honest generations; grants interleave and one grant returns in
    /// generation 3 continuing exactly at its previous per-grant target.
    fn happy_frontier_inputs() -> (
        ProjectionAggregateIdentity,
        AuthorizationCurrentPointerRecord,
        PublishedGenerationSummary,
        Vec<FrontierPlanEvidence>,
        std::collections::BTreeMap<String, FrontierDeltaEvidence>,
    ) {
        let identity = frontier_identity();
        let pointer = frontier_pointer(3, "e-g3", "op-final");
        let manifest = frontier_manifest(3, "e-g3", "op-final", 30, 4);
        let plans = vec![
            frontier_plan_evidence(1, 0, "e-g1", "op-1", 0, 1),
            frontier_plan_evidence(2, 1, "e-g2", "op-2", 0, 1),
            frontier_plan_evidence(3, 2, "e-g3", "op-final", 1, 2),
        ];
        let deltas = [
            frontier_delta_evidence(
                "e-g1",
                "op-1",
                frontier_grant(1),
                0,
                1,
                10,
                0,
                DELTA_STATUS_SUCCEEDED,
            ),
            frontier_delta_evidence(
                "e-g2",
                "op-2",
                frontier_grant(2),
                0,
                1,
                20,
                0,
                DELTA_STATUS_SUCCEEDED,
            ),
            frontier_delta_evidence(
                "e-g3",
                "op-final",
                frontier_grant(1),
                1,
                2,
                30,
                4,
                DELTA_STATUS_SUCCEEDED,
            ),
        ]
        .into_iter()
        .map(|delta| (delta.event_id.clone(), delta))
        .collect();
        (identity, pointer, manifest, plans, deltas)
    }

    fn assemble_happy() -> PublishedAggregateFrontier {
        let (identity, pointer, manifest, plans, deltas) = happy_frontier_inputs();
        assemble_published_aggregate_frontier(&identity, &pointer, &manifest, &plans, &deltas, &[])
            .expect("honest chain must assemble")
    }

    #[test]
    fn published_frontier_assembles_contiguous_chain_with_event_mapping() {
        let frontier = assemble_happy();
        assert_eq!(frontier.events.len(), 3);
        assert_eq!(frontier.card_id, Some(17));
        assert_eq!(frontier.pointer.current_generation, 3);
        for (position, event) in frontier.events.iter().enumerate() {
            assert_eq!(event.generation as usize, position + 1);
        }
        assert_eq!(frontier.events[2].grant_id, frontier_grant(1));
        assert_eq!(
            (
                frontier.events[2].delta_base_version,
                frontier.events[2].delta_target_version
            ),
            (1, 2)
        );
        assert_eq!(frontier.frontier_generation("e-g2"), Some(2));
        assert_eq!(frontier.frontier_generation("absent"), None);
    }

    #[test]
    fn published_frontier_refuses_gaps_duplicates_and_unfinished_plans() {
        type FrontierMutator<'m> = &'m dyn Fn(
            &mut Vec<FrontierPlanEvidence>,
            &mut std::collections::BTreeMap<String, FrontierDeltaEvidence>,
            &mut PublishedGenerationSummary,
            &mut AuthorizationCurrentPointerRecord,
        );
        let expect_failure = |mutate: FrontierMutator, needle: &str| {
            let (identity, mut pointer, mut manifest, mut plans, mut deltas) =
                happy_frontier_inputs();
            mutate(&mut plans, &mut deltas, &mut manifest, &mut pointer);
            let error = assemble_published_aggregate_frontier(
                &identity,
                &pointer,
                &manifest,
                &plans,
                &deltas,
                &[],
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains(needle), "expected {needle} inside: {error}");
        };

        // A PENDING plan can never prove an aggregate generation.
        expect_failure(
            &|plans, _, _, _| plans[0].status = AuthorizationImpactPlanStatus::Pending,
            "frontier_plan_not_succeeded",
        );
        // Missing a middle plan surfaces the generation gap.
        expect_failure(
            &|plans, deltas, _, _| {
                plans.remove(1);
                deltas.remove("e-g2");
            },
            "frontier_generation_gap",
        );
        // Linkage drift between plan and its delta is immutable-history damage.
        expect_failure(
            &|_, deltas, _, _| deltas.get_mut("e-g3").unwrap().target_version = 99,
            "frontier_plan_delta_linkage_drift",
        );
        // Cross-tenant delta rows never prove this aggregate.
        expect_failure(
            &|_, deltas, _, _| deltas.get_mut("e-g1").unwrap().tenant_id = 999,
            "frontier_delta_scope_mismatch",
        );
        // Card-scope drift inside the plan slice fails too.
        expect_failure(
            &|plans, _, _, _| plans[1].card_id = None,
            "frontier_plan_card_mismatch",
        );
        // Duplicate per-grant (grant, target) pairs abort (plan + delta moved
        // together so pure linkage passes and the real duplicate fires).
        expect_failure(
            &|plans, deltas, _, _| {
                plans[2].base_version = 0;
                plans[2].target_version = 1;
                let delta = deltas.get_mut("e-g3").unwrap();
                delta.base_version = 0;
                delta.target_version = 1;
            },
            "frontier_duplicate_grant_version",
        );
        // Same-grant chaining must continue exactly at the previous target —
        // a restart from version 0 is refused (plan and delta moved together
        // so pure linkage passes first).
        expect_failure(
            &|plans, deltas, _, _| {
                plans[2].base_version = 0;
                deltas.get_mut("e-g3").unwrap().base_version = 0;
            },
            "frontier_same_grant_chain_gap",
        );
        // Surplus delta evidence without a matching plan is junk input.
        expect_failure(
            &|_, deltas, _, _| {
                let surplus = frontier_delta_evidence(
                    "e-surplus",
                    "op-x",
                    frontier_grant(9),
                    0,
                    1,
                    40,
                    0,
                    DELTA_STATUS_SUCCEEDED,
                );
                deltas.insert(surplus.event_id.clone(), surplus);
            },
            "frontier_surplus_delta_evidence",
        );
        // A missing delta row for an existing plan aborts explicitly.
        expect_failure(
            &|_, deltas, _, _| {
                deltas.remove("e-g2");
            },
            "frontier_delta_missing",
        );
        // Latest generation must tie to the pointer event identity.
        expect_failure(
            &|_, _, _, pointer| pointer.event_id = "e-forged".to_owned(),
            "frontier_latest_pointer_tie_break",
        );
        // Manifest/pointer card splits are corrupt before anything else runs.
        expect_failure(
            &|_, _, manifest, _| manifest.card_id = None,
            "frontier_manifest_card_split",
        );
        // Zero generation pointers cannot have plans behind them (both sides
        // moved so the summary-agreement gate does not shadow this rule).
        expect_failure(
            &|_, _, manifest, pointer| {
                pointer.current_generation = 0;
                manifest.generation = 0;
            },
            "frontier_zero_generation",
        );
    }

    #[test]
    fn published_frontier_enforces_latest_fences_source_and_status_rules() {
        // Boundary equality: raising the fence to exactly the claimed delta's
        // level stays valid (raising only narrows authorization).
        {
            let (identity, pointer, mut manifest, plans, deltas) = happy_frontier_inputs();
            manifest.revoke_fence = 4; // == gen-3 delta fence
            assemble_published_aggregate_frontier(
                &identity,
                &pointer,
                &manifest,
                &plans,
                &deltas,
                &[],
            )
            .expect("fence parity is acceptable");
        }
        // Regressing below the claimed delta's fence refuses.
        {
            let (identity, pointer, mut manifest, plans, deltas) = happy_frontier_inputs();
            manifest.revoke_fence = 3;
            let error = assemble_published_aggregate_frontier(
                &identity,
                &pointer,
                &manifest,
                &plans,
                &deltas,
                &[],
            )
            .unwrap_err()
            .to_string();
            assert!(
                error.contains("frontier_fence_below_claimed_delta"),
                "{error}"
            );
        }
        // Source-generation drift between manifest and latest delta aborts.
        {
            let (identity, pointer, mut manifest, plans, deltas) = happy_frontier_inputs();
            manifest.source_generation = 31;
            let error = assemble_published_aggregate_frontier(
                &identity,
                &pointer,
                &manifest,
                &plans,
                &deltas,
                &[],
            )
            .unwrap_err()
            .to_string();
            assert!(
                error.contains("frontier_source_generation_drift"),
                "{error}"
            );
        }
        // Non-SUCCEEDED delta rows can never prove generations.
        {
            let (identity, pointer, manifest, plans, mut deltas) = happy_frontier_inputs();
            deltas.get_mut("e-g2").unwrap().status_str = DELTA_STATUS_QUARANTINED.to_owned();
            let error = assemble_published_aggregate_frontier(
                &identity,
                &pointer,
                &manifest,
                &plans,
                &deltas,
                &[],
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("frontier_delta_not_succeeded"), "{error}");
        }
        // Extra SUCCEEDED plans beyond G are immutable-history conflicts with
        // their rows surfaced for operators.
        {
            let (identity, pointer, manifest, plans, deltas) = happy_frontier_inputs();
            let extras = vec![ExtraSucceededImpactPlan {
                plan_id: 42,
                event_id: "e-hijack".to_owned(),
                target_generation: 7,
            }];
            let error = assemble_published_aggregate_frontier(
                &identity, &pointer, &manifest, &plans, &deltas, &extras,
            )
            .unwrap_err()
            .to_string();
            assert!(
                error.contains("frontier_extra_succeeded_plan") && error.contains("e-hijack"),
                "{error}"
            );
        }
    }

    #[test]
    fn frontier_plan_scan_bind_contract_pins_upper_bound_g_limit_g_plus_one() {
        // Bind contracts are pure, so they hold without any database session.
        assert_eq!(
            frontier_plan_scan_binds(3).expect("G fits BIGINT"),
            (3_i64, 4_i64),
            "inclusive upper bound binds G exactly; LIMIT binds the defensive
             duplicate allowance G+1 only"
        );
        assert_eq!(
            frontier_extra_probe_binds(3).expect("probe binds fit BIGINT"),
            (3_i64, MAX_EXTRA_SUCCEEDED_FRONTIER_SCAN),
            "exclusive probe lower bound binds G so a SUCCEEDED plan stranded
             exactly at G+1 cannot escape detection"
        );
        // The scan tail declares which placeholder owns the inclusive upper
        // bound (`<= ?`) versus the defensive limit (`LIMIT ?`).
        let plan_tail = FRONTIER_PLANS_BY_SCOPE_TAIL;
        assert!(plan_tail.contains("target_generation <= ?"), "{plan_tail}");
        assert!(plan_tail.contains("LIMIT ?"), "{plan_tail}");
        assert!(plan_tail.ends_with("FOR UPDATE"), "{plan_tail}");
    }

    #[test]
    fn frontier_slice_leaves_future_pending_residue_off_the_row_cap() {
        // Pointer sits at G=3 while a generation-4 plan is legally staged as
        // PENDING (never published). With the pinned bind contract that staged
        // generation compares above the inclusive upper bound, so the main
        // scan excludes it: honest loading stays at exactly G rows and the
        // row cap (`> G rows ⇒ corrupt`) can never fire on future residue.
        const CURRENT_GENERATION: u64 = 3;
        let staged_target_generation = CURRENT_GENERATION + 1;
        let (upper_bound, limit) = frontier_plan_scan_binds(CURRENT_GENERATION).unwrap();
        assert!(
            staged_target_generation as i64 > upper_bound,
            "future plan must fall outside target_generation <= G"
        );
        assert!(
            limit == upper_bound + 1,
            "LIMIT is one row of duplicate defense above the honest budget"
        );

        // The corrected loader therefore delivers the complete honest slice
        // 1..=G even while G+1 residue exists in storage; assembly accepts it
        // untouched (no row-cap, no gap, pointer semantics unchanged).
        let (identity, pointer, manifest, plans, deltas) = happy_frontier_inputs();
        assert_eq!(
            plans.len(),
            CURRENT_GENERATION as usize,
            "honest slice covers every generation 1..=G"
        );
        assert_eq!(
            usize::try_from(limit).unwrap(),
            plans.len() + 1,
            "defensive LIMIT admits the honest slice plus one duplicate"
        );
        let frontier = assemble_published_aggregate_frontier(
            &identity,
            &pointer,
            &manifest,
            &plans,
            &deltas,
            &[],
        )
        .expect("complete 1..=G slice plus unseen G+1 PENDING residue assembles");
        assert_eq!(frontier.events.len(), CURRENT_GENERATION as usize);
        assert_eq!(frontier.pointer.current_generation, CURRENT_GENERATION);
    }

    #[test]
    fn frontier_rejects_succeeded_plan_stranded_exactly_at_next_generation() {
        // Probe semantics pin `target_generation > G` (never `> G + 1`): a
        // SUCCEEDED plan sitting precisely at G+1 while the pointer still
        // identifies G contradicts durable history and must abort fail-closed
        // with its identifying rows surfaced for operators.
        let (identity, pointer, manifest, plans, deltas) = happy_frontier_inputs();
        let extras = vec![ExtraSucceededImpactPlan {
            plan_id: 99,
            event_id: "e-stranded".to_owned(),
            target_generation: pointer.current_generation + 1,
        }];
        let error = assemble_published_aggregate_frontier(
            &identity, &pointer, &manifest, &plans, &deltas, &extras,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("frontier_extra_succeeded_plan") && error.contains("e-stranded"),
            "{error}"
        );
    }

    #[test]
    fn frontier_statements_stay_parameterized_locked_and_legacy_free() {
        let statements = [
            ("plan scan", FRONTIER_PLANS_BY_SCOPE_TAIL, 5usize),
            ("delta fetch", FRONTIER_DELTA_BY_EVENT_TAIL, 1),
            (
                "extra succeeded probe",
                EXTRA_SUCCEEDED_FRONTIER_SCAN_SQL,
                5,
            ),
        ];
        let legacy_tokens = [
            "permission_rule_snapshot",
            "rule_set_snapshot",
            "authorization_projection_head",
            "ON DUPLICATE KEY",
        ];
        for (label, statement, placeholders) in statements {
            assert!(statement.contains("FOR UPDATE"), "{label} must lock rows");
            assert_eq!(
                sql_placeholder_count(statement),
                placeholders,
                "{label} bind list drifted"
            );
            for token in legacy_tokens {
                assert!(!statement.contains(token), "{label} references {token}");
            }
        }
        assert!(FRONTIER_PLANS_BY_SCOPE_TAIL.contains("ORDER BY target_generation ASC LIMIT ?"));
        assert!(FRONTIER_PLANS_BY_SCOPE_TAIL.contains("target_generation <= ?"));
        assert!(FRONTIER_DELTA_BY_EVENT_TAIL.contains("WHERE event_id = ? FOR UPDATE"));
        assert!(EXTRA_SUCCEEDED_FRONTIER_SCAN_SQL.contains("target_generation > ?"));
        assert!(EXTRA_SUCCEEDED_FRONTIER_SCAN_SQL.contains("status = 'SUCCEEDED'"));
    }

    // ── Published card grant evidence reader (pure assembly + SQL shape) ────

    const EV_HASH_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn repeated_hex(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    fn evidence_identity(aggregate_type: &str, aggregate_id: i64) -> ProjectionAggregateIdentity {
        ProjectionAggregateIdentity::new(7, aggregate_type, aggregate_id).unwrap()
    }

    fn evidence_pointer(
        aggregate_type: &str,
        aggregate_id: i64,
        manifest_id: i64,
    ) -> AuthorizationCurrentPointerRecord {
        AuthorizationCurrentPointerRecord {
            pointer_id: manifest_id,
            identity: evidence_identity(aggregate_type, aggregate_id),
            card_id: Some(17),
            current_generation: 41,
            manifest_id,
            event_id: format!("event-{aggregate_type}-{manifest_id}"),
            operation_id: format!("op-{aggregate_type}-{manifest_id}"),
            semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap(),
            dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap(),
            compiler_version: "phase2-authorization-kernel-v1".to_owned(),
            revoke_fence: 1,
            revoke_fence_proven: true,
            cas_version: 5,
        }
    }

    fn evidence_grant_for(user_id: i64, tail: u16) -> CanonicalGrant {
        let mut sample = grant(tail);
        sample.user_id = user_id;
        sample
    }

    fn evidence_segment(
        identity: &ProjectionAggregateIdentity,
        segment_id: i64,
        grants: Vec<CanonicalGrant>,
    ) -> AuthorizationSegmentSnapshot {
        AuthorizationSegmentSnapshot {
            segment_id,
            identity: identity.clone(),
            card_id: Some(17),
            content_digest: Sha256Digest::from_hex(&repeated_hex((segment_id as u8) | 1)).unwrap(),
            semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap(),
            dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap(),
            compiler_version: "phase2-authorization-kernel-v1".to_owned(),
            format: SEGMENT_FORMAT_AUTHORIZATION_GRANTS_JSON_V1.to_owned(),
            row_count: grants.len() as u64,
            byte_size: 128,
            grants,
        }
    }

    fn evidence_reference(
        pointer: &AuthorizationCurrentPointerRecord,
        ordinal: u64,
        segment: &AuthorizationSegmentSnapshot,
    ) -> AuthorizationSegmentReferenceRecord {
        AuthorizationSegmentReferenceRecord {
            reference_id: ordinal as i64 + 1,
            manifest_id: pointer.manifest_id,
            identity: pointer.identity.clone(),
            card_id: pointer.card_id,
            generation: pointer.current_generation,
            ordinal,
            segment_id: segment.segment_id,
            content_digest: segment.content_digest,
            event_id: pointer.event_id.clone(),
            operation_id: pointer.operation_id.clone(),
        }
    }

    fn published_card_state(
        pointer: &AuthorizationCurrentPointerRecord,
        segments: Vec<AuthorizationSegmentSnapshot>,
    ) -> AuthorizationPublishedState {
        let references = segments
            .iter()
            .enumerate()
            .map(|(ordinal, segment)| evidence_reference(pointer, ordinal as u64, segment))
            .collect();
        let total_grant_count = segments.iter().map(|s| s.row_count).sum::<u64>();
        AuthorizationPublishedState {
            pointer: pointer.clone(),
            manifest_id: pointer.manifest_id,
            generation: pointer.current_generation,
            source_generation: 42,
            projected_generation: 42,
            event_id: pointer.event_id.clone(),
            operation_id: pointer.operation_id.clone(),
            semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap(),
            dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap(),
            compiler_version: pointer.compiler_version.clone(),
            manifest_digest: Sha256Digest::from_hex(EV_HASH_C).unwrap(),
            parent_manifest_id: None,
            revoke_fence: pointer.revoke_fence,
            segments,
            references,
            total_grant_count,
        }
    }

    fn unconstrained_scope() -> PublishedCardEvidenceScope {
        PublishedCardEvidenceScope {
            tenant_id: 7,
            card_id: 17,
            user_filter: None,
            domain: DomainScopeRequirement::Unconstrained,
        }
    }

    fn expect_corrupt(
        result: Result<PublishedCardAuthorization, AuthorizationEvidenceError>,
    ) -> String {
        match result {
            Err(AuthorizationEvidenceError::Corrupt(message)) => message,
            other => panic!("expected Corrupt error, got {other:?}"),
        }
    }

    #[test]
    fn published_card_aggregate_allowlist_is_the_documented_closed_set() {
        assert_eq!(
            PUBLISHED_CARD_AGGREGATE_TYPES,
            ["USER_CARD", "RULE_SET", "APPROVAL", "DELEGATION"]
        );
        const {
            assert!(MAX_PUBLISHED_CARD_AGGREGATES_PER_READ >= 1);
        }
    }

    #[test]
    fn card_evidence_pointer_select_is_tenant_and_card_bound_deterministically_locked() {
        let statement = format!(
            "{SELECT_PREFIX}{POINTER_ROW_COLUMNS}{POINTER_ROWS_FOR_TENANT_CARD_LOCKED_TAIL}"
        );
        assert!(statement.contains("FROM authorization_projection_current"));
        assert!(statement.contains("WHERE tenant_id = ? AND card_id = ?"));
        assert!(statement.contains("ORDER BY aggregate_type ASC, aggregate_id ASC"));
        assert!(statement.ends_with("FOR UPDATE"), "{statement}");
        // Exactly the two scope bindings; no hidden third placeholder.
        assert_eq!(sql_placeholder_count(&statement), 2);
    }

    #[test]
    fn card_evidence_reader_path_has_no_legacy_snapshot_or_cache_fallback() {
        let forbidden = [
            "permission_rule_snapshot",
            "rule_set_snapshot",
            "authorization_projection_head",
            "cache",
        ];
        for fragment in [
            POINTER_ROWS_FOR_TENANT_CARD_LOCKED_TAIL,
            SELECT_PREFIX,
            POINTER_ROW_COLUMNS,
        ] {
            for token in forbidden {
                assert!(
                    !fragment.to_ascii_lowercase().contains(token),
                    "card evidence reader must not reference {token}"
                );
            }
        }
    }

    #[test]
    fn multi_aggregate_evidence_merges_into_deterministic_order() {
        // Scrambled on purpose; the pure assembly must still order summaries
        // and records by (aggregate_type, aggregate_id).
        let states = vec![
            published_card_state(
                &evidence_pointer("USER_CARD", 17, 104),
                vec![evidence_segment(
                    &evidence_identity("USER_CARD", 17),
                    401,
                    vec![evidence_grant_for(42, 0x0001)],
                )],
            ),
            published_card_state(
                &evidence_pointer("DELEGATION", 90, 102),
                vec![evidence_segment(
                    &evidence_identity("DELEGATION", 90),
                    402,
                    vec![evidence_grant_for(42, 0x0002)],
                )],
            ),
            published_card_state(
                &evidence_pointer("RULE_SET", 55, 103),
                vec![evidence_segment(
                    &evidence_identity("RULE_SET", 55),
                    403,
                    vec![evidence_grant_for(42, 0x0003)],
                )],
            ),
            published_card_state(
                &evidence_pointer("APPROVAL", 30, 101),
                vec![evidence_segment(
                    &evidence_identity("APPROVAL", 30),
                    404,
                    vec![evidence_grant_for(43, 0x0004)],
                )],
            ),
        ];
        let evidence =
            assemble_published_card_evidence(&unconstrained_scope(), 1_000_000, &states).unwrap();
        evidence.validate().unwrap();

        let ordered_types: Vec<&str> = manifests_types(&evidence);
        assert_eq!(
            ordered_types,
            ["APPROVAL", "DELEGATION", "RULE_SET", "USER_CARD"]
        );
        let gate = &evidence.gate;
        assert_eq!(gate.status, PublishedEvidenceGateStatus::Ready);
        assert_eq!(gate.aggregate_manifest_count, 4);
        assert_eq!(gate.verified_record_count, 4);
        assert_eq!(gate.effective_grant_count, 4);
        assert_eq!(gate.not_in_effective_count, 0);
        assert_eq!(gate.equivalent_duplicate_collapsed_count, 0);
        assert_eq!(evidence.effective_grants.len(), 4);
        // Provenance stays per-aggregate; every record keeps its own origin.
        for record in &evidence.records {
            assert_ne!(record.publication_generation, record.grant.revision.value());
            assert!(!record.aggregate_type.is_empty());
        }
    }

    fn manifests_types(evidence: &PublishedCardAuthorization) -> Vec<&str> {
        evidence
            .manifests
            .iter()
            .map(|manifest| manifest.aggregate_type.as_str())
            .collect()
    }

    #[test]
    fn empty_state_set_is_not_ready_instead_of_ok_empty() {
        let error = assemble_published_card_evidence(&unconstrained_scope(), 7, &[]).unwrap_err();
        assert!(matches!(error, AuthorizationEvidenceError::NotReady(_)));
        assert_eq!(error.as_gate_status(), PublishedEvidenceGateStatus::Pending);
    }

    #[test]
    fn unknown_aggregate_type_fails_the_whole_read() {
        let states = vec![published_card_state(
            &{
                let mut pointer = evidence_pointer("USER_CARD", 17, 1);
                pointer.identity.aggregate_type = "MYSTERY".to_owned();
                pointer
            },
            vec![evidence_segment(
                &evidence_identity("USER_CARD", 17),
                400,
                vec![evidence_grant_for(42, 0x0011)],
            )],
        )];
        let message = expect_corrupt(assemble_published_card_evidence(
            &unconstrained_scope(),
            100,
            &states,
        ));
        assert!(message.contains("unknown_aggregate_type"), "{message}");
    }

    #[test]
    fn grant_tenant_or_card_scope_split_inside_committed_payload_is_corrupt() {
        let tenant_split_grant = {
            let mut sample = evidence_grant_for(42, 0x0021);
            sample.tenant.tenant_id = 8;
            sample
        };
        let card_split_grant = {
            let mut sample = evidence_grant_for(42, 0x0022);
            sample.card_id = 99;
            sample
        };
        for (label, broken) in [("tenant", tenant_split_grant), ("card", card_split_grant)] {
            let states = vec![published_card_state(
                &evidence_pointer("USER_CARD", 17, 1),
                vec![evidence_segment(
                    &evidence_identity("USER_CARD", 17),
                    405,
                    vec![broken],
                )],
            )];
            let message = expect_corrupt(assemble_published_card_evidence(
                &unconstrained_scope(),
                100,
                &states,
            ));
            assert!(
                message.starts_with("code=published_card_evidence.grant_"),
                "{label}: {message}"
            );
        }
    }

    #[test]
    fn expired_not_yet_valid_and_inactive_are_excluded_but_provenance_kept() {
        let now = 1_000_000_i64;
        let mut expired = evidence_grant_for(42, 0x0031);
        expired.validity = ValidityWindow::between(now - 10, now);
        let mut not_yet_valid = evidence_grant_for(42, 0x0032);
        not_yet_valid.validity = ValidityWindow::between(now + 5, now + 50);
        let mut revoked = evidence_grant_for(42, 0x0033);
        revoked.state = GrantState::Revoked;
        let mut archived = evidence_grant_for(42, 0x0034);
        archived.state = GrantState::Archived;

        let states = vec![published_card_state(
            &evidence_pointer("USER_CARD", 17, 1),
            vec![evidence_segment(
                &evidence_identity("USER_CARD", 17),
                406,
                vec![expired, not_yet_valid, revoked, archived],
            )],
        )];
        let evidence =
            assemble_published_card_evidence(&unconstrained_scope(), now, &states).unwrap();
        evidence.validate().unwrap();

        assert_eq!(evidence.effective_grants.len(), 0);
        assert_eq!(evidence.gate.verified_record_count, 4);
        assert_eq!(evidence.gate.not_in_effective_count, 4);
        let reasons: Vec<_> = evidence
            .records
            .iter()
            .map(|record| record.unaccepted_reason.unwrap())
            .collect();
        assert_eq!(
            reasons,
            vec![
                UnacceptedGrantReason::Expired,
                UnacceptedGrantReason::NotYetValid,
                UnacceptedGrantReason::InactiveState,
                UnacceptedGrantReason::InactiveState,
            ]
        );
    }

    #[test]
    fn fully_equal_same_origin_duplicate_collapses_but_cross_origin_is_corrupt() {
        // Case A: identical duplicate inside ONE aggregate collapses.
        let twin = evidence_grant_for(42, 0x0041);
        let states = vec![published_card_state(
            &evidence_pointer("USER_CARD", 17, 1),
            vec![
                evidence_segment(&evidence_identity("USER_CARD", 17), 407, vec![twin.clone()]),
                evidence_segment(&evidence_identity("USER_CARD", 17), 408, vec![twin]),
            ],
        )];
        let evidence =
            assemble_published_card_evidence(&unconstrained_scope(), 100, &states).unwrap();
        assert_eq!(evidence.gate.equivalent_duplicate_collapsed_count, 1);
        assert_eq!(evidence.gate.verified_record_count, 1);
        assert_eq!(evidence.effective_grants.len(), 1);

        // Case B: same grant tuple under TWO different origins → corrupt;
        // provenance must never be merged silently across aggregates.
        let shared = evidence_grant_for(42, 0x0042);
        let conflicting_states = vec![
            published_card_state(
                &evidence_pointer("USER_CARD", 17, 1),
                vec![evidence_segment(
                    &evidence_identity("USER_CARD", 17),
                    409,
                    vec![shared.clone()],
                )],
            ),
            published_card_state(
                &evidence_pointer("RULE_SET", 55, 2),
                vec![evidence_segment(
                    &evidence_identity("RULE_SET", 55),
                    410,
                    vec![shared],
                )],
            ),
        ];
        let message = expect_corrupt(assemble_published_card_evidence(
            &unconstrained_scope(),
            100,
            &conflicting_states,
        ));
        assert!(
            message.contains("conflicting_grant_provenance"),
            "{message}"
        );
    }

    #[test]
    fn unequal_same_origin_duplicate_is_also_conflicting_provenance() {
        let original = evidence_grant_for(42, 0x0051);
        let drifted = {
            let mut sample = original.clone();
            sample.resource = "learn_subject:2".to_owned();
            sample
        };
        let states = vec![published_card_state(
            &evidence_pointer("USER_CARD", 17, 1),
            vec![
                evidence_segment(&evidence_identity("USER_CARD", 17), 411, vec![original]),
                evidence_segment(&evidence_identity("USER_CARD", 17), 412, vec![drifted]),
            ],
        )];
        let message = expect_corrupt(assemble_published_card_evidence(
            &unconstrained_scope(),
            100,
            &states,
        ));
        assert!(message.contains("conflicting_grant_provenance"));
    }

    #[test]
    fn user_and_domain_lens_narrow_without_inventing_corruption() {
        let domain_user = evidence_grant_for(42, 0x0061); // tenant Some(11)-domain fixture
        let mut plain_user = evidence_grant_for(43, 0x0062);
        plain_user.tenant.domain_id = None;

        let build_states = || {
            vec![published_card_state(
                &evidence_pointer("USER_CARD", 17, 1),
                vec![evidence_segment(
                    &evidence_identity("USER_CARD", 17),
                    413,
                    vec![domain_user.clone(), plain_user.clone()],
                )],
            )]
        };

        // No lens: both accepted.
        let both =
            assemble_published_card_evidence(&unconstrained_scope(), 100, &build_states()).unwrap();
        assert_eq!(both.gate.effective_grant_count, 2);

        // User lens: only user 43 survives; 42 is excluded explicitly.
        let only_plain = assemble_published_card_evidence(
            &PublishedCardEvidenceScope {
                user_filter: Some(43),
                ..unconstrained_scope()
            },
            100,
            &build_states(),
        )
        .unwrap();
        assert_eq!(only_plain.gate.effective_grant_count, 1);
        assert_eq!(
            only_plain.records[0].unaccepted_reason,
            Some(UnacceptedGrantReason::OutOfUserFilter)
        );

        // Domain lens "must be None": excludes the Some(11)-domain grant.
        let none_domain_only = assemble_published_card_evidence(
            &PublishedCardEvidenceScope {
                domain: DomainScopeRequirement::ExactlyNone,
                ..unconstrained_scope()
            },
            100,
            &build_states(),
        )
        .unwrap();
        assert_eq!(none_domain_only.gate.effective_grant_count, 1);
        assert_eq!(
            none_domain_only.records[0].unaccepted_reason,
            Some(UnacceptedGrantReason::OutOfDomainFilter)
        );

        // Domain lens "exactly 11": flips which record survives.
        let exact_domain = assemble_published_card_evidence(
            &PublishedCardEvidenceScope {
                domain: DomainScopeRequirement::ExactlySome(11),
                ..unconstrained_scope()
            },
            100,
            &build_states(),
        )
        .unwrap();
        assert_eq!(exact_domain.gate.effective_grant_count, 1);
        assert_eq!(
            exact_domain.records[1].unaccepted_reason,
            Some(UnacceptedGrantReason::OutOfDomainFilter)
        );
    }

    #[test]
    fn reader_refuses_card_scope_splits_and_declared_row_drift() {
        // Pointer without card scope can never enter a CARD-scoped read.
        let wide_pointer = {
            let mut pointer = evidence_pointer("USER_CARD", 17, 1);
            pointer.card_id = None;
            pointer
        };
        let message = expect_corrupt(assemble_published_card_evidence(
            &unconstrained_scope(),
            100,
            &[published_card_state(
                &wide_pointer,
                vec![evidence_segment(
                    &evidence_identity("USER_CARD", 17),
                    414,
                    vec![evidence_grant_for(42, 0x0071)],
                )],
            )],
        ));
        assert!(message.contains("pointer_card_scope_split"));

        // Reference stamped with a different card than its pointer.
        let split_pointer = evidence_pointer("USER_CARD", 17, 1);
        let mut state = published_card_state(
            &split_pointer,
            vec![evidence_segment(
                &evidence_identity("USER_CARD", 17),
                415,
                vec![evidence_grant_for(42, 0x0072)],
            )],
        );
        state.references[0].card_id = Some(18);
        let message = expect_corrupt(assemble_published_card_evidence(
            &unconstrained_scope(),
            100,
            &[state],
        ));
        assert!(message.contains("reference_card_scope_split"));

        // Segment stamped with a different card than its manifest chain.
        let split_pointer = evidence_pointer("USER_CARD", 17, 1);
        let mut state = published_card_state(
            &split_pointer,
            vec![evidence_segment(
                &evidence_identity("USER_CARD", 17),
                416,
                vec![evidence_grant_for(42, 0x0073)],
            )],
        );
        state.segments[0].card_id = Some(19);
        let message = expect_corrupt(assemble_published_card_evidence(
            &unconstrained_scope(),
            100,
            &[state],
        ));
        assert!(message.contains("segment_card_scope_split"));

        // Reference whose generation disagrees with its manifest publication.
        let split_pointer = evidence_pointer("USER_CARD", 17, 1);
        let mut state = published_card_state(
            &split_pointer,
            vec![evidence_segment(
                &evidence_identity("USER_CARD", 17),
                417,
                vec![evidence_grant_for(42, 0x0074)],
            )],
        );
        state.references[0].generation = 40;
        let message = expect_corrupt(assemble_published_card_evidence(
            &unconstrained_scope(),
            100,
            &[state],
        ));
        assert!(message.contains("reference_generation_split"));

        // Declared sealed totals disagree with the actually walked payload rows.
        let split_pointer = evidence_pointer("USER_CARD", 17, 1);
        let mut state = published_card_state(
            &split_pointer,
            vec![evidence_segment(
                &evidence_identity("USER_CARD", 17),
                418,
                vec![evidence_grant_for(42, 0x0075)],
            )],
        );
        state.total_grant_count += 1;
        let message = expect_corrupt(assemble_published_card_evidence(
            &unconstrained_scope(),
            100,
            &[state],
        ));
        assert!(message.contains("walked_record_count_below_declared_segment_rows"));

        // Reference/segment pairing drift cannot slip through either.
        let split_pointer = evidence_pointer("USER_CARD", 17, 1);
        let mut state = published_card_state(
            &split_pointer,
            vec![evidence_segment(
                &evidence_identity("USER_CARD", 17),
                419,
                vec![evidence_grant_for(42, 0x0076)],
            )],
        );
        state
            .references
            .push(evidence_reference(&state.pointer, 1, &state.segments[0]));
        let message = expect_corrupt(assemble_published_card_evidence(
            &unconstrained_scope(),
            100,
            &[state],
        ));
        assert!(message.contains("reference_segment_pairing_split"));
    }

    #[test]
    fn classification_tables_stay_fail_closed() {
        // Validity boundaries: upper bound exclusive, lower bound inclusive.
        let window = ValidityWindow::between(10, 20);
        assert_eq!(
            classify_validity_at(&window, 9),
            Some(UnacceptedGrantReason::NotYetValid)
        );
        assert_eq!(classify_validity_at(&window, 10), None);
        assert_eq!(classify_validity_at(&window, 19), None);
        assert_eq!(
            classify_validity_at(&window, 20),
            Some(UnacceptedGrantReason::Expired)
        );
        assert_eq!(classify_validity_at(&ValidityWindow::perpetual(), -5), None);

        // Gate vocabulary mapping of the typed error bridge.
        assert_eq!(
            AuthorizationEvidenceError::NotReady("code=x".to_owned()).as_gate_status(),
            PublishedEvidenceGateStatus::Pending
        );
        assert_eq!(
            AuthorizationEvidenceError::InvalidRequest("code=y".to_owned()).as_gate_status(),
            PublishedEvidenceGateStatus::Pending
        );
        assert_eq!(
            AuthorizationEvidenceError::Corrupt("code=z".to_owned()).as_gate_status(),
            PublishedEvidenceGateStatus::Corrupt
        );
    }

    #[test]
    fn projection_errors_bridge_into_the_evidence_vocabulary_fail_closed() {
        use AuthorizationProjectionError as ProjectionError;
        let bridged: AuthorizationEvidenceError = ProjectionError::NotReady(
            "code=authorization_projection.current_pointer_missing".to_owned(),
        )
        .into();
        assert!(matches!(bridged, AuthorizationEvidenceError::NotReady(_)));

        let bridged: AuthorizationEvidenceError = ProjectionError::Corrupt(
            "code=authorization_projection.pointer_hash_chain_break".to_owned(),
        )
        .into();
        assert_eq!(
            bridged.as_gate_status(),
            PublishedEvidenceGateStatus::Corrupt
        );

        let bridged: AuthorizationEvidenceError =
            ProjectionError::IdentityMismatch("code=x".to_owned()).into();
        assert_eq!(
            bridged.as_gate_status(),
            PublishedEvidenceGateStatus::Corrupt
        );

        let bridged: AuthorizationEvidenceError =
            ProjectionError::Mapping("code=y".to_owned()).into();
        assert_eq!(
            bridged.as_gate_status(),
            PublishedEvidenceGateStatus::Corrupt
        );
    }

    // ── Archive-intent parent proof (pure fail-closed gate, no DB) ──────────

    /// Durable parent manifest row whose every dimension matches
    /// [`archive_intent_request`]; `status` is parameterized so lifecycle
    /// gating can be exercised independently.
    fn archive_parent_row(status: &str) -> ManifestRawSqlRow {
        ManifestRawSqlRow {
            manifest_id: 55,
            tenant_id: 7,
            card_id: Some(31),
            aggregate_type: "CARD".to_owned(),
            aggregate_id: 17,
            generation: 3,
            source_generation: 9,
            projected_generation: 9,
            event_id: "event-stage".to_owned(),
            operation_id: "op-stage".to_owned(),
            semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap().as_bytes().to_vec(),
            dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap().as_bytes().to_vec(),
            compiler_version: "phase2-authorization-kernel-v1".to_owned(),
            manifest_digest: Sha256Digest::from_hex(HASH_A).unwrap().as_bytes().to_vec(),
            status: status.to_owned(),
            cas_version: 4,
            lease_owner: None,
            lease_token_hash: None,
            lease_expires_at: None,
            parent_manifest_id: Some(2),
            revoke_fence: 1,
        }
    }

    fn archive_intent_request() -> AuthorizationArchiveIntentAppendRequest {
        AuthorizationArchiveIntentAppendRequest {
            identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
            card_id: Some(31),
            archived_manifest_id: 55,
            archived_generation: 3,
            event_id: "event-stage".to_owned(),
            operation_id: "op-stage".to_owned(),
            archive_key: "astral-auth-archive/v1/7/CARD/17/generation-3".to_owned(),
            semantic_hash_hex: HASH_A.to_owned(),
            dependency_hash_hex: HASH_B.to_owned(),
            compiler_version: "phase2-authorization-kernel-v1".to_owned(),
            archived_revoke_fence: 1,
        }
    }

    fn prove_request(
        request: &AuthorizationArchiveIntentAppendRequest,
        parent: &ManifestRawSqlRow,
    ) -> Result<(), AuthorizationProjectionError> {
        prove_archive_intent_against_parent_manifest(
            request,
            &Sha256Digest::from_hex(&request.semantic_hash_hex).unwrap(),
            &Sha256Digest::from_hex(&request.dependency_hash_hex).unwrap(),
            parent,
        )
    }

    fn assert_parent_rejection(
        error: AuthorizationProjectionError,
        expected_variant: &str,
        expected_code: &str,
    ) {
        let (variant, code) = match error {
            AuthorizationProjectionError::IdentityMismatch(code) => ("IdentityMismatch", code),
            AuthorizationProjectionError::ImmutableConflict(code) => ("ImmutableConflict", code),
            AuthorizationProjectionError::NotReady(code) => ("NotReady", code),
            AuthorizationProjectionError::Corrupt(code) => ("Corrupt", code),
            AuthorizationProjectionError::Mapping(code) => ("Mapping", code),
            other => panic!("unexpected rejection variant: {other:?}"),
        };
        assert_eq!(
            variant, expected_variant,
            "unexpected variant for {expected_code}"
        );
        assert_eq!(code, expected_code);
    }

    #[test]
    fn archive_intent_parent_proof_accepts_committed_and_superseded_parents() {
        for status in [MANIFEST_STATUS_COMMITTED, MANIFEST_STATUS_SUPERSEDED] {
            let request = archive_intent_request();
            prove_request(&request, &archive_parent_row(status)).unwrap_or_else(|error| {
                panic!("parent status {status} must accept a matching intent: {error}")
            });
        }
    }

    #[test]
    fn archive_intent_parent_proof_rejects_unpublished_and_quarantined_parents() {
        let request = archive_intent_request();
        for status in [
            MANIFEST_STATUS_BUILDING,
            MANIFEST_STATUS_READY,
            MANIFEST_STATUS_QUARANTINED,
        ] {
            assert_parent_rejection(
                prove_request(&request, &archive_parent_row(status)).unwrap_err(),
                "NotReady",
                &format!(
                    "code=authorization_projection.archive_intent_parent_not_archivable;status={status}"
                ),
            );
        }
    }

    #[test]
    fn archive_intent_parent_proof_rejects_every_dimension_mismatch_fail_closed() {
        let parent = archive_parent_row(MANIFEST_STATUS_COMMITTED);

        let mut request = archive_intent_request();
        request.identity = ProjectionAggregateIdentity::new(8, "CARD", 17).unwrap();
        assert_parent_rejection(
            prove_request(&request, &parent).unwrap_err(),
            "IdentityMismatch",
            "code=authorization_projection.archive_intent_parent_identity_mismatch",
        );

        let mut request = archive_intent_request();
        request.card_id = None;
        assert_parent_rejection(
            prove_request(&request, &parent).unwrap_err(),
            "IdentityMismatch",
            "code=authorization_projection.archive_intent_parent_card_scope_mismatch",
        );

        let dimension_cases: [DimensionCase<AuthorizationArchiveIntentAppendRequest>; 7] = [
            ("generation", Box::new(|r| r.archived_generation = 4)),
            (
                "event_id",
                Box::new(|r| r.event_id = "event-drift".to_owned()),
            ),
            (
                "operation_id",
                Box::new(|r| r.operation_id = "op-drift".to_owned()),
            ),
            (
                "semantic_hash",
                Box::new(|r| r.semantic_hash_hex = HASH_B.to_owned()),
            ),
            (
                "dependency_hash",
                Box::new(|r| r.dependency_hash_hex = HASH_A.to_owned()),
            ),
            (
                "compiler_version",
                Box::new(|r| r.compiler_version = "drifted-compiler".to_owned()),
            ),
            (
                "archived_revoke_fence",
                Box::new(|r| r.archived_revoke_fence = 2),
            ),
        ];
        for (dimension, mutate) in dimension_cases {
            let mut request = archive_intent_request();
            mutate(&mut request);
            assert_parent_rejection(
                prove_request(&request, &parent).unwrap_err(),
                "ImmutableConflict",
                &format!(
                    "code=authorization_projection.archive_intent_parent_mismatch;dimension={dimension}"
                ),
            );
        }
    }

    #[test]
    fn archive_intent_parent_proof_fails_closed_on_unreadable_parent_counters() {
        let request = archive_intent_request();

        let mut parent = archive_parent_row(MANIFEST_STATUS_COMMITTED);
        parent.revoke_fence = -1;
        assert_parent_rejection(
            prove_request(&request, &parent).unwrap_err(),
            "Mapping",
            "code=authorization_projection.negative_bigint;field=manifest.revoke_fence;value=-1",
        );

        let mut parent = archive_parent_row(MANIFEST_STATUS_COMMITTED);
        parent.generation = -3;
        assert_parent_rejection(
            prove_request(&request, &parent).unwrap_err(),
            "Mapping",
            "code=authorization_projection.negative_bigint;field=manifest.generation;value=-3",
        );
    }

    // ── Archive-intent live-pointer proof (pure fail-closed gate) ───────────

    /// Live current pointer whose every dimension matches
    /// [`archive_intent_request`], carrying the durable fence-proof latch.
    fn archive_live_pointer() -> AuthorizationCurrentPointerRecord {
        AuthorizationCurrentPointerRecord {
            pointer_id: 900,
            identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
            card_id: Some(31),
            current_generation: 3,
            manifest_id: 55,
            event_id: "event-stage".to_owned(),
            operation_id: "op-stage".to_owned(),
            semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap(),
            dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap(),
            compiler_version: "phase2-authorization-kernel-v1".to_owned(),
            revoke_fence: 1,
            revoke_fence_proven: true,
            cas_version: 6,
        }
    }

    fn prove_request_against_pointer(
        request: &AuthorizationArchiveIntentAppendRequest,
        pointer: Option<&AuthorizationCurrentPointerRecord>,
    ) -> Result<(), AuthorizationProjectionError> {
        prove_archive_intent_against_live_pointer(
            request,
            &Sha256Digest::from_hex(&request.semantic_hash_hex).unwrap(),
            &Sha256Digest::from_hex(&request.dependency_hash_hex).unwrap(),
            pointer,
        )
    }

    #[test]
    fn archive_intent_pointer_proof_accepts_matching_proven_pointer() {
        let request = archive_intent_request();
        prove_request_against_pointer(&request, Some(&archive_live_pointer()))
            .expect("a matching proven live pointer must seed a new archive intent");
    }

    #[test]
    fn archive_intent_pointer_proof_refuses_new_intent_without_live_pointer() {
        let request = archive_intent_request();
        // A superseded (pointer moved past) or never-published parent has no
        // live pointer: a NEW intent is refused instead of being seeded from
        // the manifest row's numeric fence alone. Only an already-committed
        // intent may be replayed after supersession.
        assert_parent_rejection(
            prove_request_against_pointer(&request, None).unwrap_err(),
            "NotReady",
            "code=authorization_projection.archive_intent_parent_pointer_missing",
        );
    }

    #[test]
    fn archive_intent_pointer_proof_refuses_unproven_fence_latch_regardless_of_value() {
        let request = archive_intent_request();
        // Matching fence value but the pointer predates the Rust contract:
        // the latch, never the numeric value, decides.
        let mut unproven = archive_live_pointer();
        unproven.revoke_fence_proven = false;
        assert_parent_rejection(
            prove_request_against_pointer(&request, Some(&unproven)).unwrap_err(),
            "NotReady",
            "code=authorization_projection.archive_intent_pointer_fence_unproven;pointer_fence=1",
        );
        // The honest zero sentinel is equally refused while unproven.
        let mut unproven_zero = archive_live_pointer();
        unproven_zero.revoke_fence = 0;
        unproven_zero.revoke_fence_proven = false;
        assert_parent_rejection(
            prove_request_against_pointer(&request, Some(&unproven_zero)).unwrap_err(),
            "NotReady",
            "code=authorization_projection.archive_intent_pointer_fence_unproven;pointer_fence=0",
        );
    }

    #[test]
    fn archive_intent_pointer_proof_rejects_every_dimension_mismatch_fail_closed() {
        let pointer = archive_live_pointer();

        let mut request = archive_intent_request();
        request.identity = ProjectionAggregateIdentity::new(8, "CARD", 17).unwrap();
        assert_parent_rejection(
            prove_request_against_pointer(&request, Some(&pointer)).unwrap_err(),
            "IdentityMismatch",
            "code=authorization_projection.archive_intent_pointer_identity_mismatch",
        );

        let mut request = archive_intent_request();
        request.card_id = None;
        assert_parent_rejection(
            prove_request_against_pointer(&request, Some(&pointer)).unwrap_err(),
            "IdentityMismatch",
            "code=authorization_projection.archive_intent_pointer_card_scope_mismatch",
        );

        let dimension_cases: [DimensionCase<AuthorizationArchiveIntentAppendRequest>; 8] = [
            (
                "archived_manifest_id",
                Box::new(|r| r.archived_manifest_id = 56),
            ),
            ("generation", Box::new(|r| r.archived_generation = 4)),
            (
                "event_id",
                Box::new(|r| r.event_id = "event-drift".to_owned()),
            ),
            (
                "operation_id",
                Box::new(|r| r.operation_id = "op-drift".to_owned()),
            ),
            (
                "semantic_hash",
                Box::new(|r| r.semantic_hash_hex = HASH_B.to_owned()),
            ),
            (
                "dependency_hash",
                Box::new(|r| r.dependency_hash_hex = HASH_A.to_owned()),
            ),
            (
                "compiler_version",
                Box::new(|r| r.compiler_version = "drifted-compiler".to_owned()),
            ),
            (
                "archived_revoke_fence",
                Box::new(|r| r.archived_revoke_fence = 2),
            ),
        ];
        for (dimension, mutate) in dimension_cases {
            let mut request = archive_intent_request();
            mutate(&mut request);
            assert_parent_rejection(
                prove_request_against_pointer(&request, Some(&pointer)).unwrap_err(),
                "ImmutableConflict",
                &format!(
                    "code=authorization_projection.archive_intent_pointer_mismatch;dimension={dimension}"
                ),
            );
        }
    }

    // ── Manifest v2 digest regressions (pure known answer + sensitivity) ────

    /// Independent known answer over the exact `astral-auth-manifest-v2`
    /// material (domain tag, big-endian i64 counters, `-1` sentinels for
    /// absent card/parent, u32 length-prefixed ASCII, raw 32-byte hashes),
    /// computed outside Rust from the documented encoding. Any change to the
    /// domain, field order, widths or sentinels trips this pin.
    const MANIFEST_V2_KNOWN_ANSWER: &str =
        "fc4c41e842bf940e5831626a40bde563be2dfe678eb1a1533d8f9229b6a286fd";

    fn digest_input_v2(segments: Vec<String>) -> ManifestDigestInput<'static> {
        ManifestDigestInput {
            tenant_id: 7,
            aggregate_type: "CARD",
            aggregate_id: 17,
            card_id: None,
            generation: 3,
            source_generation: 9,
            projected_generation: 9,
            event_id: "event-stage",
            operation_id: "op-stage",
            semantic_hash_hex: HASH_A,
            dependency_hash_hex: HASH_B,
            compiler_version: "phase2-authorization-kernel-v1",
            parent_manifest_id: Some(2),
            revoke_fence: 1,
            segment_content_digests_hex: segments,
        }
    }

    #[test]
    fn manifest_digest_v2_known_answer_pins_domain_encoding() {
        let digest = compute_manifest_digest(&digest_input_v2(vec![HASH_A.to_owned()])).unwrap();
        assert_eq!(digest.as_hex(), MANIFEST_V2_KNOWN_ANSWER);
    }

    #[test]
    fn manifest_digest_changes_when_any_sealed_dimension_changes() {
        let base = compute_manifest_digest(&digest_input_v2(vec![HASH_A.to_owned()])).unwrap();
        let mutations: [DimensionCase<'static, ManifestDigestInput<'static>>; 7] = [
            (
                "parent_manifest_id",
                Box::new(|i| i.parent_manifest_id = Some(3)),
            ),
            (
                "parent_manifest_id_none",
                Box::new(|i| i.parent_manifest_id = None),
            ),
            ("revoke_fence", Box::new(|i| i.revoke_fence = 2)),
            ("event_id", Box::new(|i| i.event_id = "event-drift")),
            ("operation_id", Box::new(|i| i.operation_id = "op-drift")),
            (
                "compiler_version",
                Box::new(|i| i.compiler_version = "drifted-compiler"),
            ),
            (
                "segment_digest_same_length",
                Box::new(|i| i.segment_content_digests_hex = vec![HASH_B.to_owned()]),
            ),
        ];
        for (dimension, mutate) in mutations {
            let mut input = digest_input_v2(vec![HASH_A.to_owned()]);
            mutate(&mut input);
            let digest = compute_manifest_digest(&input).unwrap();
            assert_ne!(digest, base, "{dimension} must change the manifest digest");
        }
    }

    #[test]
    fn manifest_digest_fails_closed_on_non_positive_parent_and_non_ascii_fields() {
        for parent in [0, -1] {
            let mut input = digest_input_v2(vec![HASH_A.to_owned()]);
            input.parent_manifest_id = Some(parent);
            let error = compute_manifest_digest(&input).unwrap_err();
            assert!(
                matches!(error, AuthorizationProjectionError::ScopeViolation(ref message)
                if message.contains("authorization_projection.non_positive_id")
                    && message.contains("field=parent_manifest_id")),
                "parent id {parent} must be refused: {error:?}"
            );
        }

        let mut input = digest_input_v2(vec![HASH_A.to_owned()]);
        input.event_id = "événement";
        let error = compute_manifest_digest(&input).unwrap_err();
        assert!(
            matches!(error, AuthorizationProjectionError::ScopeViolation(ref message)
            if message.contains("non_ascii_provenance_digest_field"))
        );

        let mut input = digest_input_v2(vec![HASH_A.to_owned()]);
        input.compiler_version = "compilateur-vé2";
        let error = compute_manifest_digest(&input).unwrap_err();
        assert!(
            matches!(error, AuthorizationProjectionError::ScopeViolation(ref message)
            if message.contains("non_ascii_manifest_digest_field"))
        );
    }

    #[test]
    fn first_publication_rejects_sealed_parent_lineage_fail_closed() {
        let expectation = AuthorizationPublishExpectation {
            current_pointer: None,
            expected_target_semantic_hash_hex: HASH_A.to_owned(),
            expected_target_dependency_hash_hex: HASH_B.to_owned(),
            expected_target_compiler_version: "phase2-authorization-kernel-v1".to_owned(),
        };
        let mut target = ready_target(1, 500);
        target.parent_manifest_id = Some(400);
        let error = validate_manifest_publish(&expectation, &target).unwrap_err();
        assert!(
            matches!(error, AuthorizationProjectionError::ManifestPublishConflict(ref message)
            if message.contains("first_publication_requires_no_parent"))
        );
    }

    // ── Archive proof parent gate (record path, pure fail-closed) ───────────

    /// Proof request whose every dimension matches [`archive_parent_row`].
    fn archive_proof_request() -> AuthorizationArchiveProofRequest {
        AuthorizationArchiveProofRequest {
            identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
            card_id: Some(31),
            archived_manifest_id: 55,
            archived_generation: 3,
            event_id: "event-stage".to_owned(),
            operation_id: "op-stage".to_owned(),
            archive_key: "astral-auth-archive/v1/7/CARD/17/generation-3".to_owned(),
            semantic_hash_hex: HASH_A.to_owned(),
            dependency_hash_hex: HASH_B.to_owned(),
            compiler_version: "phase2-authorization-kernel-v1".to_owned(),
            archived_revoke_fence: 1,
            manifest_chain_digest_hex: HASH_A.to_owned(),
        }
    }

    fn prove_proof_request(
        request: &AuthorizationArchiveProofRequest,
        parent: &ManifestRawSqlRow,
    ) -> Result<(), AuthorizationProjectionError> {
        prove_archive_proof_request_against_parent_manifest(
            request,
            &Sha256Digest::from_hex(&request.semantic_hash_hex).unwrap(),
            &Sha256Digest::from_hex(&request.dependency_hash_hex).unwrap(),
            parent,
        )
    }

    #[test]
    fn archive_proof_parent_gate_accepts_matching_committed_and_superseded() {
        for status in [MANIFEST_STATUS_COMMITTED, MANIFEST_STATUS_SUPERSEDED] {
            let request = archive_proof_request();
            prove_proof_request(&request, &archive_parent_row(status)).unwrap_or_else(|error| {
                panic!("parent status {status} must accept a matching proof: {error}")
            });
        }
    }

    #[test]
    fn archive_proof_parent_gate_rejects_every_dimension_mismatch_fail_closed() {
        let parent = archive_parent_row(MANIFEST_STATUS_COMMITTED);

        let mut request = archive_proof_request();
        request.identity = ProjectionAggregateIdentity::new(8, "CARD", 17).unwrap();
        assert_parent_rejection(
            prove_proof_request(&request, &parent).unwrap_err(),
            "IdentityMismatch",
            "code=authorization_projection.archive_parent_identity_mismatch",
        );

        let mut request = archive_proof_request();
        request.card_id = None;
        assert_parent_rejection(
            prove_proof_request(&request, &parent).unwrap_err(),
            "IdentityMismatch",
            "code=authorization_projection.archive_parent_card_scope_mismatch",
        );

        let mut request = archive_proof_request();
        request.archived_generation = 4;
        assert_parent_rejection(
            prove_proof_request(&request, &parent).unwrap_err(),
            "Corrupt",
            "code=authorization_projection.archive_parent_generation_mismatch",
        );

        let mut request = archive_proof_request();
        request.event_id = "event-drift".to_owned();
        assert_parent_rejection(
            prove_proof_request(&request, &parent).unwrap_err(),
            "IdentityMismatch",
            "code=authorization_projection.archive_parent_provenance_mismatch",
        );

        let mut request = archive_proof_request();
        request.operation_id = "op-drift".to_owned();
        assert_parent_rejection(
            prove_proof_request(&request, &parent).unwrap_err(),
            "IdentityMismatch",
            "code=authorization_projection.archive_parent_provenance_mismatch",
        );

        let mut request = archive_proof_request();
        request.archived_revoke_fence = 2;
        assert_parent_rejection(
            prove_proof_request(&request, &parent).unwrap_err(),
            "ImmutableConflict",
            "code=authorization_projection.archive_parent_fence_mismatch",
        );

        // Defense in depth beyond the sealed chain: direct hash/compiler dims.
        let mut request = archive_proof_request();
        request.semantic_hash_hex = HASH_B.to_owned();
        assert_parent_rejection(
            prove_proof_request(&request, &parent).unwrap_err(),
            "Corrupt",
            "code=authorization_projection.archive_parent_semantic_hash_mismatch",
        );

        let mut request = archive_proof_request();
        request.dependency_hash_hex = HASH_A.to_owned();
        assert_parent_rejection(
            prove_proof_request(&request, &parent).unwrap_err(),
            "Corrupt",
            "code=authorization_projection.archive_parent_dependency_hash_mismatch",
        );

        let mut request = archive_proof_request();
        request.compiler_version = "drifted-compiler".to_owned();
        assert_parent_rejection(
            prove_proof_request(&request, &parent).unwrap_err(),
            "Corrupt",
            "code=authorization_projection.archive_parent_compiler_mismatch",
        );

        let request = archive_proof_request();
        let quarantined = archive_parent_row(MANIFEST_STATUS_QUARANTINED);
        assert_parent_rejection(
            prove_proof_request(&request, &quarantined).unwrap_err(),
            "NotReady",
            "code=authorization_projection.archive_parent_not_archivable;status=QUARANTINED",
        );
    }

    // ── Archive lease heartbeat (pure bounds + SQL shape) ───────────────────

    #[test]
    fn archive_lease_heartbeat_bounds_fail_closed() {
        for seconds in [0, MAX_ARCHIVE_LEASE_SECONDS + 1, -5] {
            let error = validate_archive_lease_material("itest-owner", seconds).unwrap_err();
            assert!(
                matches!(error, AuthorizationProjectionError::ScopeViolation(ref message)
                if message.contains("authorization_projection.invalid_archive_lease_seconds")),
                "seconds {seconds} must be refused: {error:?}"
            );
        }
        let error = validate_archive_lease_material("   ", 60).unwrap_err();
        assert!(
            matches!(error, AuthorizationProjectionError::ScopeViolation(ref message)
            if message.contains("field=lease_owner"))
        );
    }

    #[test]
    fn archive_heartbeat_sql_renews_only_the_live_lease() {
        // Renewal mutates ONLY the expiry: no attempts, no cas_version, no
        // status write — retry accounting and CAS semantics stay untouched.
        assert!(ARCHIVE_HEARTBEAT_SQL
            .contains("SET lease_expires_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP())"));
        assert!(!ARCHIVE_HEARTBEAT_SQL.contains("attempts"));
        assert!(!ARCHIVE_HEARTBEAT_SQL.contains("cas_version"));
        assert!(!ARCHIVE_HEARTBEAT_SQL.contains("status"));
        // The guard rebinds the full stable lease identity and requires the
        // row to still be LEASED with an unexpired (live) lease.
        let full = format!("{ARCHIVE_HEARTBEAT_SQL}{ARCHIVE_LEASE_GUARD_SUFFIX}");
        for fragment in [
            "WHERE archive_outbox_id = ? AND event_id = ?",
            "lease_owner = ?",
            "lease_token_hash = ?",
            "status = 'LEASED'",
            "lease_expires_at IS NOT NULL",
            "lease_expires_at > UTC_TIMESTAMP()",
        ] {
            assert!(full.contains(fragment), "heartbeat SQL lacks `{fragment}`");
        }
    }

    // ── Legacy fence-proof rehearsal (pure gates + SQL shapes, no DB) ───────

    fn rehearsal_expectation() -> AuthorizationFenceProofRehearsalExpectation {
        AuthorizationFenceProofRehearsalExpectation {
            manifest_id: 55,
            generation: 1,
            semantic_hash_hex: HASH_A.to_owned(),
            dependency_hash_hex: HASH_B.to_owned(),
            compiler_version: "phase2-authorization-kernel-v1".to_owned(),
            revoke_fence: 0,
            cas_version: 4,
        }
    }

    fn rehearsal_request() -> AuthorizationFenceProofRehearsalRequest {
        AuthorizationFenceProofRehearsalRequest {
            identity: identity(),
            card_id: Some(31),
            operator_id: 42,
            operation_id: "op-fence-rehearsal-20260826-0001".to_owned(),
            expectation: rehearsal_expectation(),
            reason: "operator_rehearsal_for_legacy_unproven_pointer".to_owned(),
        }
    }

    /// Durable pointer whose every dimension matches [`rehearsal_request`];
    /// the latch is parameterized so both decision paths stay exercisable.
    fn rehearsal_pointer(revoke_fence_proven: bool) -> AuthorizationCurrentPointerRecord {
        AuthorizationCurrentPointerRecord {
            pointer_id: 900,
            identity: identity(),
            card_id: Some(31),
            current_generation: 1,
            manifest_id: 55,
            event_id: "event-stage".to_owned(),
            operation_id: "op-stage".to_owned(),
            semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap(),
            dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap(),
            compiler_version: "phase2-authorization-kernel-v1".to_owned(),
            revoke_fence: 0,
            revoke_fence_proven,
            cas_version: 4,
        }
    }

    /// Committed generation-one manifest matching the rehearsal pointer;
    /// `status`/lineage/fence are parameterized for the refusal matrix.
    fn rehearsal_manifest_row(status: &str) -> ManifestRawSqlRow {
        ManifestRawSqlRow {
            manifest_id: 55,
            tenant_id: 7,
            card_id: Some(31),
            aggregate_type: "CARD".to_owned(),
            aggregate_id: 17,
            generation: 1,
            source_generation: 9,
            projected_generation: 9,
            event_id: "event-stage".to_owned(),
            operation_id: "op-stage".to_owned(),
            semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap().as_bytes().to_vec(),
            dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap().as_bytes().to_vec(),
            compiler_version: "phase2-authorization-kernel-v1".to_owned(),
            manifest_digest: Sha256Digest::from_hex(HASH_A).unwrap().as_bytes().to_vec(),
            status: status.to_owned(),
            cas_version: 4,
            lease_owner: None,
            lease_token_hash: None,
            lease_expires_at: None,
            parent_manifest_id: None,
            revoke_fence: 0,
        }
    }

    fn prove_rehearsal_manifest(
        pointer: &AuthorizationCurrentPointerRecord,
        manifest: &ManifestRawSqlRow,
    ) -> Result<(), AuthorizationProjectionError> {
        prove_fence_proof_rehearsal_manifest(pointer, manifest)
    }

    /// Variant check plus code-prefix check: rehearsal refusals may append
    /// durable/evidence forensics after the stable machine code.
    fn assert_rehearsal_rejection_prefix(
        error: AuthorizationProjectionError,
        expected_variant: &str,
        expected_code_prefix: &str,
    ) {
        let (variant, code) = match error {
            AuthorizationProjectionError::IdentityMismatch(code) => ("IdentityMismatch", code),
            AuthorizationProjectionError::CurrentPointerCasConflict(code) => {
                ("CurrentPointerCasConflict", code)
            }
            AuthorizationProjectionError::NotReady(code) => ("NotReady", code),
            AuthorizationProjectionError::Corrupt(code) => ("Corrupt", code),
            other => panic!("unexpected rejection variant: {other:?}"),
        };
        assert_eq!(
            variant, expected_variant,
            "unexpected variant for {expected_code_prefix}"
        );
        assert!(
            code.starts_with(expected_code_prefix),
            "code `{code}` lacks prefix `{expected_code_prefix}`"
        );
    }

    #[test]
    fn fence_proof_rehearsal_request_shape_is_validated_fail_closed() {
        let request = rehearsal_request();
        validate_fence_proof_rehearsal_request(&request)
            .expect("a well-formed rehearsal request must validate");

        let mut mutated = rehearsal_request();
        mutated.operator_id = 0;
        assert!(matches!(
            validate_fence_proof_rehearsal_request(&mutated).unwrap_err(),
            AuthorizationProjectionError::ScopeViolation(ref message)
                if message.contains("field=operator_id")
        ));

        let mut mutated = rehearsal_request();
        mutated.operation_id = "  ".to_owned();
        assert!(matches!(
            validate_fence_proof_rehearsal_request(&mutated).unwrap_err(),
            AuthorizationProjectionError::ScopeViolation(ref message)
                if message.contains("field=operation_id")
        ));

        let mut mutated = rehearsal_request();
        mutated.operation_id = "o".repeat(MAX_FENCE_PROOF_REHEARSAL_OPERATION_ID_LENGTH + 1);
        assert!(matches!(
            validate_fence_proof_rehearsal_request(&mutated).unwrap_err(),
            AuthorizationProjectionError::ScopeViolation(ref message)
                if message.contains("field=operation_id")
        ));

        let mut mutated = rehearsal_request();
        mutated.reason = String::new();
        assert!(matches!(
            validate_fence_proof_rehearsal_request(&mutated).unwrap_err(),
            AuthorizationProjectionError::ScopeViolation(ref message)
                if message.contains("field=reason")
        ));

        let mut mutated = rehearsal_request();
        mutated.reason = "r".repeat(MAX_FENCE_PROOF_REHEARSAL_REASON_LENGTH + 1);
        assert!(matches!(
            validate_fence_proof_rehearsal_request(&mutated).unwrap_err(),
            AuthorizationProjectionError::ScopeViolation(ref message)
                if message.contains("field=reason")
        ));

        let mut mutated = rehearsal_request();
        mutated.expectation.generation = 0;
        assert!(matches!(
            validate_fence_proof_rehearsal_request(&mutated).unwrap_err(),
            AuthorizationProjectionError::ScopeViolation(ref message)
                if message.contains("invalid_rehearsal_generation")
        ));

        let mut mutated = rehearsal_request();
        mutated.expectation.semantic_hash_hex = "zz".to_owned();
        assert!(matches!(
            validate_fence_proof_rehearsal_request(&mutated).unwrap_err(),
            AuthorizationProjectionError::ScopeViolation(ref message)
                if message.contains("invalid_rehearsal_semantic_hash")
        ));

        let mut mutated = rehearsal_request();
        mutated.expectation.dependency_hash_hex = HASH_A[..30].to_owned();
        assert!(matches!(
            validate_fence_proof_rehearsal_request(&mutated).unwrap_err(),
            AuthorizationProjectionError::ScopeViolation(ref message)
                if message.contains("invalid_rehearsal_dependency_hash")
        ));

        let mut mutated = rehearsal_request();
        mutated.card_id = Some(0);
        assert!(matches!(
            validate_fence_proof_rehearsal_request(&mutated).unwrap_err(),
            AuthorizationProjectionError::ScopeViolation(ref message)
                if message.contains("field=card_id")
        ));

        let mut mutated = rehearsal_request();
        mutated.expectation.manifest_id = 0;
        assert!(matches!(
            validate_fence_proof_rehearsal_request(&mutated).unwrap_err(),
            AuthorizationProjectionError::ScopeViolation(ref message)
                if message.contains("field=expectation.manifest_id")
        ));

        let mut mutated = rehearsal_request();
        mutated.reason = "r".repeat(MAX_FENCE_PROOF_REHEARSAL_REASON_LENGTH + 1);
        assert!(matches!(
            validate_fence_proof_rehearsal_request(&mutated).unwrap_err(),
            AuthorizationProjectionError::ScopeViolation(ref message)
                if message.contains("field=reason")
        ));

        // Padding is refused outright: the raw values are bound verbatim into
        // the durable audit row, so they must equal their validated form.
        let mut mutated = rehearsal_request();
        mutated.operation_id = "  padded-operation-id  ".to_owned();
        assert!(matches!(
            validate_fence_proof_rehearsal_request(&mutated).unwrap_err(),
            AuthorizationProjectionError::ScopeViolation(ref message)
                if message.contains("invalid_rehearsal_operation_id_padding")
        ));

        let mut mutated = rehearsal_request();
        mutated.reason = "operator_rehearsal_reason ".to_owned();
        assert!(matches!(
            validate_fence_proof_rehearsal_request(&mutated).unwrap_err(),
            AuthorizationProjectionError::ScopeViolation(ref message)
                if message.contains("invalid_rehearsal_reason_padding")
        ));
    }

    #[test]
    fn reference_card_scope_must_match_manifest_scope() {
        verify_reference_card_scope(None, None)
            .expect("aggregate-wide references must match an aggregate-wide manifest");
        verify_reference_card_scope(Some(31), Some(31)).expect("equal card scopes must validate");

        // A reference row claiming a foreign (or NULL/aggregate-wide) card
        // scope against a card-scoped manifest — or the inverse — is
        // cross-scope contamination and must fail closed.
        for (record_card_id, manifest_card_id) in
            [(Some(31), Some(32)), (Some(31), None), (None, Some(31))]
        {
            assert!(
                matches!(
                    verify_reference_card_scope(record_card_id, manifest_card_id).unwrap_err(),
                    AuthorizationProjectionError::IdentityMismatch(ref message)
                        if message.contains("code=authorization_projection.reference_card_scope_mismatch")
                ),
                "reference scope {record_card_id:?} vs manifest scope {manifest_card_id:?} must be refused"
            );
        }
    }

    #[test]
    fn read_side_reference_cap_fails_closed_above_staging_bound() {
        enforce_segment_reference_cap(0).expect("zero references must pass the read cap");
        enforce_segment_reference_cap(MAX_SEGMENTS_PER_MANIFEST)
            .expect("exactly the bound must pass the read cap");
        assert!(matches!(
            enforce_segment_reference_cap(MAX_SEGMENTS_PER_MANIFEST + 1).unwrap_err(),
            AuthorizationProjectionError::ScopeViolation(ref message)
                if message.contains("code=authorization_projection.too_many_segments_per_manifest")
        ));
    }

    /// Minimal publish request whose every compared dimension matches
    /// [`publish_readback_pointer`].
    fn publish_readback_request() -> AuthorizationPublishRequest {
        AuthorizationPublishRequest {
            identity: identity(),
            card_id: Some(31),
            target_manifest_id: 55,
            target_generation: 1,
            current_pointer: None,
            expected_target_semantic_hash_hex: HASH_A.to_owned(),
            expected_target_dependency_hash_hex: HASH_B.to_owned(),
            expected_target_compiler_version: "phase2-authorization-kernel-v1".to_owned(),
            fences: PublishRevokeFenceEvidence {
                previous_revoke_fence: 0,
                new_revoke_fence: 5,
            },
        }
    }

    /// Pointer row as it must read back after the CAS: every dimension equals
    /// the published evidence, with the target provenance passed explicitly.
    fn publish_readback_pointer(
        request: &AuthorizationPublishRequest,
        event_id: &str,
        operation_id: &str,
    ) -> AuthorizationCurrentPointerRecord {
        AuthorizationCurrentPointerRecord {
            pointer_id: 900,
            identity: request.identity.clone(),
            card_id: request.card_id,
            current_generation: request.target_generation,
            manifest_id: request.target_manifest_id,
            event_id: event_id.to_owned(),
            operation_id: operation_id.to_owned(),
            semantic_hash: Sha256Digest::from_hex(&request.expected_target_semantic_hash_hex)
                .unwrap(),
            dependency_hash: Sha256Digest::from_hex(&request.expected_target_dependency_hash_hex)
                .unwrap(),
            compiler_version: request.expected_target_compiler_version.clone(),
            revoke_fence: request.fences.new_revoke_fence,
            revoke_fence_proven: true,
            cas_version: 5,
        }
    }

    #[test]
    fn post_publish_readback_proves_target_provenance() {
        let request = publish_readback_request();
        let target_event_id = "event-publish";
        let target_operation_id = "op-publish";
        let target_semantic = Sha256Digest::from_hex(HASH_A).unwrap();
        let target_dependency = Sha256Digest::from_hex(HASH_B).unwrap();

        let pointer = publish_readback_pointer(&request, target_event_id, target_operation_id);
        assert!(post_publish_pointer_agrees(
            &pointer,
            &request,
            target_event_id,
            target_operation_id,
            &target_semantic,
            &target_dependency,
        ));

        // Stale or forged provenance must fail the readback even when every
        // other dimension matches: the pointer may only carry the target
        // manifest's own event/operation identity.
        for forged_event_id in ["", "event-stage", "event-publish-x"] {
            let pointer = publish_readback_pointer(&request, forged_event_id, target_operation_id);
            assert!(
                !post_publish_pointer_agrees(
                    &pointer,
                    &request,
                    target_event_id,
                    target_operation_id,
                    &target_semantic,
                    &target_dependency,
                ),
                "event_id disagreement must fail the post-publish readback"
            );
        }
        for forged_operation_id in ["", "op-stage", "op-publish-x"] {
            let pointer = publish_readback_pointer(&request, target_event_id, forged_operation_id);
            assert!(
                !post_publish_pointer_agrees(
                    &pointer,
                    &request,
                    target_event_id,
                    target_operation_id,
                    &target_semantic,
                    &target_dependency,
                ),
                "operation_id disagreement must fail the post-publish readback"
            );
        }
    }

    #[test]
    fn fence_proof_rehearsal_decision_accepts_unproven_zero_fence_generation_one() {
        let decision =
            decide_fence_proof_rehearsal(&rehearsal_request(), &rehearsal_pointer(false))
                .expect("an exactly matching unproven zero-fence gen-one pointer must rehearse");
        assert_eq!(
            decision,
            FenceProofRehearsalDecision::RehearseLegacyZeroFence
        );
    }

    #[test]
    fn fence_proof_rehearsal_replay_of_proven_pointer_is_a_verified_no_op() {
        // Exact replay after a successful latch: every dimension (including
        // the advanced CAS counter and the fence) matches => verified no-op.
        let decision = decide_fence_proof_rehearsal(&rehearsal_request(), &rehearsal_pointer(true))
            .expect("an exactly matching proven pointer must be a verified no-op");
        assert_eq!(decision, FenceProofRehearsalDecision::AlreadyProven);

        // A proven NONZERO fence is an equally valid no-op match when the
        // caller re-read the fresh evidence: the latch, never the value.
        let mut proven_positive = rehearsal_pointer(true);
        proven_positive.revoke_fence = 3;
        let mut fresh = rehearsal_request();
        fresh.expectation.revoke_fence = 3;
        assert_eq!(
            decide_fence_proof_rehearsal(&fresh, &proven_positive).unwrap(),
            FenceProofRehearsalDecision::AlreadyProven
        );
    }

    #[test]
    fn fence_proof_rehearsal_refuses_identity_and_card_scope_drift() {
        for proven in [false, true] {
            let pointer = rehearsal_pointer(proven);

            let mut request = rehearsal_request();
            request.identity = ProjectionAggregateIdentity::new(8, "CARD", 17).unwrap();
            assert_parent_rejection(
                decide_fence_proof_rehearsal(&request, &pointer).unwrap_err(),
                "IdentityMismatch",
                "code=authorization_projection.fence_proof_identity_mismatch",
            );

            let mut request = rehearsal_request();
            request.card_id = None;
            assert_parent_rejection(
                decide_fence_proof_rehearsal(&request, &pointer).unwrap_err(),
                "IdentityMismatch",
                "code=authorization_projection.fence_proof_card_scope_mismatch",
            );
        }
    }

    #[test]
    fn fence_proof_rehearsal_refuses_every_stale_expectation_dimension() {
        let dimension_cases: [DimensionCase<AuthorizationFenceProofRehearsalRequest>; 7] = [
            ("manifest_id", Box::new(|r| r.expectation.manifest_id = 56)),
            ("generation", Box::new(|r| r.expectation.generation = 2)),
            (
                "semantic_hash",
                Box::new(|r| r.expectation.semantic_hash_hex = HASH_B.to_owned()),
            ),
            (
                "dependency_hash",
                Box::new(|r| r.expectation.dependency_hash_hex = HASH_A.to_owned()),
            ),
            (
                "compiler_version",
                Box::new(|r| r.expectation.compiler_version = "drifted-compiler".to_owned()),
            ),
            ("revoke_fence", Box::new(|r| r.expectation.revoke_fence = 1)),
            ("cas_version", Box::new(|r| r.expectation.cas_version = 5)),
        ];
        for proven in [false, true] {
            let pointer = rehearsal_pointer(proven);
            for (dimension, mutate) in dimension_cases.iter() {
                let mut request = rehearsal_request();
                mutate(&mut request);
                assert_rehearsal_rejection_prefix(
                    decide_fence_proof_rehearsal(&request, &pointer).unwrap_err(),
                    "CurrentPointerCasConflict",
                    &format!(
                        "code=authorization_projection.fence_proof_expectation_mismatch;dimension={dimension}"
                    ),
                );
            }
        }
    }

    #[test]
    fn fence_proof_rehearsal_refuses_unproven_nonzero_fence_and_multi_generation() {
        // A nonzero numeric fence on an unproven row is unprovable history.
        // The caller's expectation must first match the fresh durable value
        // (stale evidence is refused earlier as an expectation mismatch); the
        // legacy gate then refuses the value itself.
        let mut pointer = rehearsal_pointer(false);
        pointer.revoke_fence = 5;
        let mut fresh = rehearsal_request();
        fresh.expectation.revoke_fence = 5;
        assert_parent_rejection(
            decide_fence_proof_rehearsal(&fresh, &pointer).unwrap_err(),
            "NotReady",
            "code=authorization_projection.fence_proof_requires_zero_fence;pointer_fence=5",
        );
        // Stale evidence naming fence 0 against a durable 5 refuses earlier.
        assert_rehearsal_rejection_prefix(
            decide_fence_proof_rehearsal(&rehearsal_request(), &pointer).unwrap_err(),
            "CurrentPointerCasConflict",
            "code=authorization_projection.fence_proof_expectation_mismatch;dimension=revoke_fence",
        );

        // Generation-one chains only: a multi-generation legacy chain would
        // require proving a parent lineage the legacy rows cannot supply.
        let mut pointer = rehearsal_pointer(false);
        pointer.current_generation = 2;
        let mut fresh = rehearsal_request();
        fresh.expectation.generation = 2;
        assert_parent_rejection(
            decide_fence_proof_rehearsal(&fresh, &pointer).unwrap_err(),
            "NotReady",
            "code=authorization_projection.fence_proof_requires_generation_one_chain;pointer_generation=2",
        );
    }

    #[test]
    fn fence_proof_rehearsal_manifest_proof_accepts_only_committed_generation_one() {
        let pointer = rehearsal_pointer(false);
        prove_rehearsal_manifest(&pointer, &rehearsal_manifest_row(MANIFEST_STATUS_COMMITTED))
            .expect("a committed parentless zero-fence gen-one manifest must prove");

        for status in [
            MANIFEST_STATUS_BUILDING,
            MANIFEST_STATUS_READY,
            MANIFEST_STATUS_SUPERSEDED,
            MANIFEST_STATUS_QUARANTINED,
        ] {
            assert_parent_rejection(
                prove_rehearsal_manifest(&pointer, &rehearsal_manifest_row(status)).unwrap_err(),
                "NotReady",
                &format!(
                    "code=authorization_projection.fence_proof_manifest_not_committed;status={status}"
                ),
            );
        }

        let mut manifest = rehearsal_manifest_row(MANIFEST_STATUS_COMMITTED);
        manifest.parent_manifest_id = Some(2);
        assert_parent_rejection(
            prove_rehearsal_manifest(&pointer, &manifest).unwrap_err(),
            "Corrupt",
            "code=authorization_projection.fence_proof_manifest_has_parent;parent=Some(2)",
        );

        let mut manifest = rehearsal_manifest_row(MANIFEST_STATUS_COMMITTED);
        manifest.revoke_fence = 1;
        assert_parent_rejection(
            prove_rehearsal_manifest(&pointer, &manifest).unwrap_err(),
            "Corrupt",
            "code=authorization_projection.fence_proof_manifest_fence_nonzero;fence=1",
        );

        let mut manifest = rehearsal_manifest_row(MANIFEST_STATUS_COMMITTED);
        manifest.generation = 2;
        assert_parent_rejection(
            prove_rehearsal_manifest(&pointer, &manifest).unwrap_err(),
            "Corrupt",
            "code=authorization_projection.fence_proof_manifest_generation_split",
        );

        let mut manifest = rehearsal_manifest_row(MANIFEST_STATUS_COMMITTED);
        manifest.semantic_hash = Sha256Digest::from_hex(HASH_B).unwrap().as_bytes().to_vec();
        assert_parent_rejection(
            prove_rehearsal_manifest(&pointer, &manifest).unwrap_err(),
            "Corrupt",
            "code=authorization_projection.fence_proof_manifest_hash_chain_break",
        );

        let mut manifest = rehearsal_manifest_row(MANIFEST_STATUS_COMMITTED);
        manifest.dependency_hash = Sha256Digest::from_hex(HASH_A).unwrap().as_bytes().to_vec();
        assert_parent_rejection(
            prove_rehearsal_manifest(&pointer, &manifest).unwrap_err(),
            "Corrupt",
            "code=authorization_projection.fence_proof_manifest_hash_chain_break",
        );

        let mut manifest = rehearsal_manifest_row(MANIFEST_STATUS_COMMITTED);
        manifest.compiler_version = "drifted-compiler".to_owned();
        assert_parent_rejection(
            prove_rehearsal_manifest(&pointer, &manifest).unwrap_err(),
            "Corrupt",
            "code=authorization_projection.fence_proof_manifest_hash_chain_break",
        );

        let mut manifest = rehearsal_manifest_row(MANIFEST_STATUS_COMMITTED);
        manifest.card_id = None;
        assert_parent_rejection(
            prove_rehearsal_manifest(&pointer, &manifest).unwrap_err(),
            "IdentityMismatch",
            "code=authorization_projection.fence_proof_manifest_card_split",
        );

        let mut manifest = rehearsal_manifest_row(MANIFEST_STATUS_COMMITTED);
        manifest.tenant_id = 8;
        assert_parent_rejection(
            prove_rehearsal_manifest(&pointer, &manifest).unwrap_err(),
            "IdentityMismatch",
            "code=authorization_projection.fence_proof_manifest_identity_split",
        );
    }

    #[test]
    fn fence_proof_rehearsal_statements_are_minimal_guards_only() {
        // The latch CAS sets ONLY the latch and the CAS increment: no other
        // column may move inside this statement.
        assert!(
            POINTER_FENCE_PROOF_LATCH_SQL.starts_with(
                "UPDATE authorization_projection_current \
                 SET revoke_fence_proven = 1, cas_version = cas_version + 1 WHERE "
            ),
            "{POINTER_FENCE_PROOF_LATCH_SQL}"
        );
        for fragment in [
            "tenant_id = ?",
            "aggregate_type = ?",
            "aggregate_id = ?",
            // Null-safe card scope pin, mirroring the publish CAS.
            "card_id <=> ?",
            "manifest_id = ?",
            "current_generation = ?",
            "cas_version = ?",
            "revoke_fence = ?",
            // The old latch value is part of the guard: a blanket re-latch or
            // a latch through any other state is unrepresentable.
            "revoke_fence_proven = 0",
        ] {
            assert!(
                POINTER_FENCE_PROOF_LATCH_SQL.contains(fragment),
                "latch CAS lacks `{fragment}`"
            );
        }
        assert_eq!(POINTER_FENCE_PROOF_LATCH_SQL.matches('?').count(), 8);

        // The audit row uses the established 9-column in-transaction shape
        // with fixed literals for resource/decision/event_type.
        assert!(FENCE_PROOF_AUDIT_INSERT_SQL.starts_with("INSERT INTO audit_log"));
        assert!(
            FENCE_PROOF_AUDIT_INSERT_SQL
                .contains("(user_id, card_id, action, resource, decision, reason, event_type, request_id, detail)"),
            "{FENCE_PROOF_AUDIT_INSERT_SQL}"
        );
        assert!(FENCE_PROOF_AUDIT_INSERT_SQL.contains("'authorization_projection_current'"));
        assert!(FENCE_PROOF_AUDIT_INSERT_SQL.contains("'ALLOW'"));
        assert!(FENCE_PROOF_AUDIT_INSERT_SQL.contains("'AUTHZ_FENCE_PROOF_LATCH'"));
        assert_eq!(FENCE_PROOF_AUDIT_INSERT_SQL.matches('?').count(), 6);

        // The multi-generation probe is index-bounded and refuse-only; a stray
        // READY generation is as unprovable as COMMITTED/SUPERSEDED history.
        assert!(MANIFEST_OTHER_COMMITTED_GENERATION_PROBE_SQL
            .contains("status IN ('COMMITTED', 'SUPERSEDED', 'READY')"));
        assert!(!MANIFEST_OTHER_COMMITTED_GENERATION_PROBE_SQL
            .contains("status IN ('COMMITTED', 'SUPERSEDED')"));
        assert!(MANIFEST_OTHER_COMMITTED_GENERATION_PROBE_SQL.contains("generation <> ?"));
        assert!(MANIFEST_OTHER_COMMITTED_GENERATION_PROBE_SQL.contains("LIMIT 1"));
        assert_eq!(
            MANIFEST_OTHER_COMMITTED_GENERATION_PROBE_SQL
                .matches('?')
                .count(),
            4
        );

        for statement in [
            POINTER_FENCE_PROOF_LATCH_SQL,
            FENCE_PROOF_AUDIT_INSERT_SQL,
            MANIFEST_OTHER_COMMITTED_GENERATION_PROBE_SQL,
        ] {
            assert!(
                !statement.contains('{'),
                "brace interpolation surface in: {statement}"
            );
            assert!(
                !statement.to_uppercase().contains("DELETE"),
                "no deletes allowed"
            );
        }
    }
}
