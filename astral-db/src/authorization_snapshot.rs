//! Durable authorization projection snapshot: typed warm hint over the strict
//! published-state chain (Phase 5 seam between the durable projection tables
//! and the in-memory authorization mirror).
//!
//! # What this module is (and is not)
//!
//! - [`capture_projection_snapshot`] walks every current pointer of
//!   `authorization_projection_current` within the capture cap inside ONE
//!   read-only short transaction (same lock-first discipline as the strict
//!   card reader: deterministic SQL-bounded pointer enumeration, then each
//!   aggregate's full manifest chain under
//!   [`read_published_authorization_state_in_tx`]), verifies every
//!   aggregate state strictly, and returns only after the commit proved the
//!   read. It never writes a source row.
//! - [`save_projection_snapshot`] frames the captured typed document through
//!   the frozen [`crate::local_projection_snapshot`] container (canonical JSON
//!   envelope, magic + schema version + SHA-256 trailer, 256 MiB bound,
//!   exclusive temp + atomic rename). The frame digest is transport integrity
//!   ONLY — it is never treated as evidence.
//! - [`load_projection_snapshot_hint`] reads such a file, re-derives every
//!   state through [`validate_published_state_snapshot`] (full payload
//!   re-encoding + the ONE assembly contract), re-reads the SQL-bounded
//!   durable pointer token set and all pending delta rows from the database,
//!   and returns a conservative [`ProjectionSnapshotHint`]: only aggregates
//!   whose exact durable pointer token still matches are offered via
//!   [`ProjectionSnapshotHint::states`]; every divergence is reported, never
//!   silently dropped or forgiven.
//!
//! The hint is a WARM HINT, not an authorization fact and not a freshness
//! proof. Structural validation (this module) proves "these bytes are one
//! internally consistent published state"; it cannot prove "the durable
//! ledger still points here". Consumers must keep the mandated
//! `warm_from_durable` second strict load before any state becomes
//! serviceable; the runtime readiness gate lives outside this module.
//!
//! # Bounds
//!
//! Capture is bounded by [`MAX_CAPTURE_PUBLISHED_STATES`]; the pending-delta
//! read by [`MAX_PENDING_DELTA_ROWS`]; the file by the frame module's 256 MiB
//! envelope cap. Every pointer scan is bounded by the SQL ITSELF (`LIMIT ?` =
//! cap + 1 over-limit probe), so an oversized scope never reaches memory as a
//! whole-table read before the refusal. Every bound fails closed
//! (`TooLarge`), never truncates.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::authorization_projection_repository::{
    assemble_verified_published_state, decode_segment_payload, encode_segment_payload,
    lock_all_current_pointer_records_in_tx_bounded, read_all_current_pointer_records_in_tx_bounded,
    read_published_authorization_state_in_tx, verify_segment_local_seal,
    AuthorizationCurrentPointerRecord, AuthorizationProjectionError, AuthorizationPublishedState,
    ManifestRawSqlRow, ProjectionAggregateIdentity, SEGMENT_FORMAT_AUTHORIZATION_GRANTS_JSON_V1,
};
use crate::grant_repository::Sha256Digest;
use crate::local_projection_snapshot::{
    read_local_snapshot, write_local_snapshot_atomic, LocalSnapshotError, SnapshotEnvelope,
    SnapshotFrontier,
};

// ─────────────────────────────────────────────────────────────────────────────
// Bounds and format version
// ─────────────────────────────────────────────────────────────────────────────

/// Payload schema version of [`ProjectionSnapshotDocument`]; readers refuse
/// any other version instead of guessing forward compatibility.
pub const SNAPSHOT_PAYLOAD_VERSION_V1: u32 = 1;

/// Hard cap on the number of published states one capture may carry
/// (`authorization_projection_current` rows). A larger durable scope fails
/// the capture closed instead of producing a silently partial snapshot.
pub const MAX_CAPTURE_PUBLISHED_STATES: usize = 100_000;

/// Hard cap on pending (`status <> 'SUCCEEDED'`) delta rows one hint load
/// reads. Beyond the cap the load fails closed: an unbounded in-flight delta
/// backlog is exactly the situation where the durable warm path must win.
pub const MAX_PENDING_DELTA_ROWS: usize = 100_000;

/// Maximum age of a snapshot file that may still seed a warm hint. The hint
/// is always followed by the mandatory `warm_from_durable` second strict
/// load, so this bound is a conservative hygiene gate, not a freshness proof.
pub const MAX_PROJECTION_SNAPSHOT_HINT_AGE_SECONDS: i64 = 24 * 3_600;

/// SQL bind value for the bounded whole-scope pointer scans: `cap + 1`, so
/// the statement itself carries exactly one over-limit probe row beyond the
/// cap and the caller can refuse the scope as a whole without ever holding a
/// truncated "frontier" or an unbounded whole-table read. `cap` is a
/// compile-time constant here; a cap that cannot fit `i64` is a programming
/// error and fails loud instead of silently binding a wrapped value.
pub(crate) fn pointer_scan_bind_limit(cap: usize) -> i64 {
    let cap = i64::try_from(cap).expect("pointer scan cap must fit i64");
    cap + 1
}

/// Whole-capture capacity decision behind the bounded pointer read: a scan
/// that returned at most [`MAX_CAPTURE_PUBLISHED_STATES`] rows is in scope;
/// the `cap + 1`-th row (over-limit probe present) fails the WHOLE capture
/// closed — never a partial frontier.
pub(crate) fn enforce_capture_pointer_capacity(
    scanned: usize,
) -> Result<(), ProjectionSnapshotError> {
    if scanned > MAX_CAPTURE_PUBLISHED_STATES {
        return Err(ProjectionSnapshotError::TooLarge(format!(
            "code=authorization_snapshot.too_many_current_pointers;count={scanned};cap={MAX_CAPTURE_PUBLISHED_STATES}"
        )));
    }
    Ok(())
}

/// Durable-scope capacity decision behind the hint load: a durable pointer
/// scope larger than one capture can ever carry cannot be classified as a
/// whole, so the hint fails closed (`TooLarge`) and the durable warm path
/// rebuilds — the mirror is never seeded from a partially comparable scope.
pub(crate) fn enforce_hint_durable_pointer_capacity(
    scanned: usize,
) -> Result<(), ProjectionSnapshotError> {
    if scanned > MAX_CAPTURE_PUBLISHED_STATES {
        return Err(ProjectionSnapshotError::TooLarge(format!(
            "code=authorization_snapshot.too_many_durable_pointers;count={scanned};cap={MAX_CAPTURE_PUBLISHED_STATES}"
        )));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Snapshot capture/save/load failures. Every variant fails closed: a hint in
/// any error state must be treated as absent and the durable warm path must
/// rebuild from the ledger. None of them ever authorizes anything.
#[derive(Debug, thiserror::Error)]
pub enum ProjectionSnapshotError {
    /// The framed container rejected the bytes (missing file, magic, schema
    /// version, framing, integrity digest, canonical JSON, capacity).
    #[error("projection snapshot frame failure: {0}")]
    Frame(#[from] LocalSnapshotError),

    /// A strict projection read or re-validation refused the durable/typed
    /// state.
    #[error("projection snapshot projection failure: {0}")]
    Projection(#[from] AuthorizationProjectionError),

    /// Database transport failure (unknown outcome; never a usable hint).
    #[error("database query failed: {0}")]
    Query(#[from] sqlx::Error),

    /// The typed document, frontier or scope-internal consistency failed;
    /// the payload is refused as a whole.
    #[error("projection snapshot refused: {0}")]
    Invalid(String),

    /// A bounded resource (state count, pending-delta count) exceeded its
    /// hard cap; nothing partial is returned.
    #[error("projection snapshot capture exceeded bounds: {0}")]
    TooLarge(String),

    /// The snapshot file is older than
    /// [`MAX_PROJECTION_SNAPSHOT_HINT_AGE_SECONDS`].
    #[error(
        "projection snapshot expired: age_seconds={age_seconds};max_age_seconds={max_age_seconds}"
    )]
    Expired {
        age_seconds: i64,
        max_age_seconds: i64,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Aggregate identity key (frozen `tenant_id:aggregate_type:aggregate_id` form)
// ─────────────────────────────────────────────────────────────────────────────

/// Deterministic aggregate key used by the snapshot frontiers. Matches the
/// key convention documented by [`crate::local_projection_snapshot`] for the
/// authorization mirror; `aggregate_type` is validated ASCII
/// alphanumeric/underscore, so `:` is unambiguous.
pub fn authorization_aggregate_key(identity: &ProjectionAggregateIdentity) -> String {
    format!(
        "{}:{}:{}",
        identity.tenant_id, identity.aggregate_type, identity.aggregate_id
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Typed payload document
// ─────────────────────────────────────────────────────────────────────────────

/// The typed snapshot payload: every strictly verified published state of the
/// whole `authorization_projection_current` scope at capture time.
///
/// Serde on the embedded types is a WIRE FORM ONLY. There is no constructor
/// path from bytes to trust: a deserialized state carries no proof until it
/// passes [`validate_published_state_snapshot`], and a validated state is
/// still only a hint until the durable frontier agrees.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionSnapshotDocument {
    /// Must equal [`SNAPSHOT_PAYLOAD_VERSION_V1`].
    pub snapshot_version: u32,
    /// Verified published states, in capture order (durable pointer order).
    pub states: Vec<AuthorizationPublishedState>,
}

/// Decode + fully validate the payload region of a parsed snapshot envelope.
///
/// Per state this re-runs [`validate_published_state_snapshot`] — payload
/// re-encoding, digest/row-count/byte-size re-proof, grant canonicalization,
/// reference pairing and the manifest digest seal — so "the frame SHA matched"
/// is never the only integrity argument. Unknown payload fields, wrong
/// versions and over-cap state counts fail closed.
pub fn decode_projection_snapshot_payload(
    payload: &serde_json::Value,
) -> Result<ProjectionSnapshotDocument, ProjectionSnapshotError> {
    let document: ProjectionSnapshotDocument =
        serde_json::from_value(payload.clone()).map_err(|error| {
            ProjectionSnapshotError::Invalid(format!(
                "code=authorization_snapshot.payload_unparsable;detail={error}"
            ))
        })?;
    if document.snapshot_version != SNAPSHOT_PAYLOAD_VERSION_V1 {
        return Err(ProjectionSnapshotError::Invalid(format!(
            "code=authorization_snapshot.unsupported_payload_version;found={}",
            document.snapshot_version
        )));
    }
    if document.states.len() > MAX_CAPTURE_PUBLISHED_STATES {
        return Err(ProjectionSnapshotError::TooLarge(format!(
            "code=authorization_snapshot.too_many_states;count={};cap={MAX_CAPTURE_PUBLISHED_STATES}",
            document.states.len()
        )));
    }
    for state in &document.states {
        validate_published_state_snapshot(state)?;
    }
    Ok(document)
}

// ─────────────────────────────────────────────────────────────────────────────
// Structural validation (payload re-encoding + the ONE assembly contract)
// ─────────────────────────────────────────────────────────────────────────────

/// Prove one deserialized `AuthorizationPublishedState` is byte-faithful to
/// the strict durable read contract.
///
/// Two independent layers, both mandatory:
///
/// 1. **Segment re-encoding proof** — for every segment the canonical payload
///    bytes are re-encoded from the typed grants
///    ([`encode_segment_payload`] re-enforces per-grant canonicalization),
///    and the snapshot must agree on `row_count`, `byte_size`, the SHA-256
///    `content_digest` over those exact bytes, a canonical
///    decode→re-serialize round trip, the pinned
///    [`SEGMENT_FORMAT_AUTHORIZATION_GRANTS_JSON_V1`] format and the
///    segment-local semantic/dependency seals
///    ([`verify_segment_local_seal`]).
/// 2. **The one assembly contract** — the manifest row is rebuilt from the
///    state ([`ManifestRawSqlRow::from_published_state`]) and re-run through
///    the same [`assemble_verified_published_state`] the strict reader and
///    guarded publisher share (pointer proof state, pointer/manifest
///    generation-identity-fence-hash agreement, contiguous reference pairing,
///    manifest digest seal, grant-count sums). The reassembled state must be
///    `==` to the input, so any field the contract does not explicitly
///    recompute still cannot drift.
///
/// This proves STRUCTURE only. It is deliberately NOT a freshness proof: a
/// structurally perfect state can still be a superseded generation, and no
/// caller may treat `Ok(())` here as "the durable ledger still points here".
pub fn validate_published_state_snapshot(
    state: &AuthorizationPublishedState,
) -> Result<(), ProjectionSnapshotError> {
    state.pointer.identity.validate().map_err(|error| {
        ProjectionSnapshotError::Invalid(format!(
            "code=authorization_snapshot.invalid_state_identity;detail={error}"
        ))
    })?;
    for segment in &state.segments {
        if segment.format != SEGMENT_FORMAT_AUTHORIZATION_GRANTS_JSON_V1 {
            return Err(ProjectionSnapshotError::Invalid(format!(
                "code=authorization_snapshot.unknown_segment_format;segment={};value={}",
                segment.segment_id, segment.format
            )));
        }
        if segment.row_count != segment.grants.len() as u64 {
            return Err(ProjectionSnapshotError::Invalid(format!(
                "code=authorization_snapshot.segment_row_count_mismatch;segment={};declared={};actual={}",
                segment.segment_id,
                segment.row_count,
                segment.grants.len()
            )));
        }
        let payload = encode_segment_payload(&segment.grants).map_err(|error| {
            ProjectionSnapshotError::Invalid(format!(
                "code=authorization_snapshot.segment_reencode_failed;segment={};detail={error}",
                segment.segment_id
            ))
        })?;
        let byte_size = u64::try_from(payload.len()).map_err(|_| {
            ProjectionSnapshotError::TooLarge(
                "code=authorization_snapshot.segment_payload_overflow".to_owned(),
            )
        })?;
        if segment.byte_size != byte_size {
            return Err(ProjectionSnapshotError::Invalid(format!(
                "code=authorization_snapshot.segment_byte_size_mismatch;segment={};declared={};actual={}",
                segment.segment_id, segment.byte_size, byte_size
            )));
        }
        let computed = Sha256Digest::from_raw_bytes(Sha256::digest(&payload).into());
        if computed != segment.content_digest {
            return Err(ProjectionSnapshotError::Invalid(format!(
                "code=authorization_snapshot.segment_content_digest_mismatch;segment={}",
                segment.segment_id
            )));
        }
        let decoded = decode_segment_payload(&payload).map_err(|error| {
            ProjectionSnapshotError::Invalid(format!(
                "code=authorization_snapshot.segment_roundtrip_unparsable;segment={};detail={error}",
                segment.segment_id
            ))
        })?;
        if decoded != segment.grants {
            return Err(ProjectionSnapshotError::Invalid(format!(
                "code=authorization_snapshot.segment_payload_noncanonical;segment={}",
                segment.segment_id
            )));
        }
        verify_segment_local_seal(segment).map_err(|error| {
            ProjectionSnapshotError::Invalid(format!(
                "code=authorization_snapshot.segment_local_seal_mismatch;segment={};detail={error}",
                segment.segment_id
            ))
        })?;
    }

    let manifest = ManifestRawSqlRow::from_published_state(state)?;
    let reassembled = assemble_verified_published_state(
        state.pointer.clone(),
        &manifest,
        state.references.clone(),
        state.segments.clone(),
    )?;
    if reassembled != *state {
        return Err(ProjectionSnapshotError::Invalid(
            "code=authorization_snapshot.published_state_roundtrip_mismatch".to_owned(),
        ));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Capture (read-only short transaction, full bounded scope)
// ─────────────────────────────────────────────────────────────────────────────

/// A completed capture: the typed document, its per-aggregate source frontier
/// and the capture instant (sampled after the commit proof).
#[derive(Debug, Clone, PartialEq)]
pub struct ProjectionSnapshotCapture {
    created_at: OffsetDateTime,
    document: ProjectionSnapshotDocument,
    source_frontier: SnapshotFrontier,
}

impl ProjectionSnapshotCapture {
    /// Capture instant (after the read transaction's commit proof).
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// The typed document behind this capture.
    pub fn document(&self) -> &ProjectionSnapshotDocument {
        &self.document
    }

    /// Verified states, in durable pointer order.
    pub fn states(&self) -> &[AuthorizationPublishedState] {
        &self.document.states
    }

    /// Per-aggregate published-generation frontier the payload was taken at
    /// (`tenant_id:aggregate_type:aggregate_id` → generation).
    pub fn source_frontier(&self) -> &SnapshotFrontier {
        &self.source_frontier
    }
}

/// Capture EVERY published projection state in one read-only short
/// transaction.
///
/// Lock discipline mirrors the strict card reader: one deterministic
/// `SELECT ... ORDER BY tenant_id, aggregate_type, aggregate_id LIMIT ? FOR
/// UPDATE` over the pointer rows first (the SQL itself stops at
/// [`MAX_CAPTURE_PUBLISHED_STATES`] + 1 rows, so neither the lock set nor the
/// read set can exceed the bound), then each aggregate's manifest chain in
/// pointer order via [`read_published_authorization_state_in_tx`] (which
/// re-locks the already-held pointer and refuses a moved row). No source row
/// is written; the transaction commits BEFORE the capture is returned, so a
/// returned capture always carries a commit proof. Scope is complete and
/// bounded: the `cap + 1`-th pointer row fails the whole capture closed —
/// nothing partial is ever assembled or returned.
pub async fn capture_projection_snapshot(
    pool: &sqlx::MySqlPool,
) -> Result<ProjectionSnapshotCapture, ProjectionSnapshotError> {
    let mut tx = pool.begin().await?;
    // SQL-level cap: the statement stops at cap + 1 rows, so an oversized
    // scope is refused before it can reach memory as a whole-table read, and
    // the over-limit probe row fails the WHOLE capture closed below.
    let pointers = lock_all_current_pointer_records_in_tx_bounded(
        &mut tx,
        pointer_scan_bind_limit(MAX_CAPTURE_PUBLISHED_STATES),
    )
    .await?;
    enforce_capture_pointer_capacity(pointers.len())?;
    let mut states = Vec::with_capacity(pointers.len());
    for pointer in &pointers {
        let state = read_published_authorization_state_in_tx(&mut tx, &pointer.identity).await?;
        if state.pointer != *pointer {
            return Err(ProjectionSnapshotError::Invalid(
                "code=authorization_snapshot.capture_pointer_moved_under_read".to_owned(),
            ));
        }
        // Defense in depth: what is about to be persisted must itself pass
        // the exact validator any future load will demand.
        validate_published_state_snapshot(&state)?;
        states.push(state);
    }
    tx.commit().await?;

    let mut aggregates = BTreeMap::new();
    for state in &states {
        let key = authorization_aggregate_key(&state.pointer.identity);
        if aggregates
            .insert(key, state.pointer.current_generation)
            .is_some()
        {
            return Err(ProjectionSnapshotError::Invalid(
                "code=authorization_snapshot.capture_duplicate_aggregate".to_owned(),
            ));
        }
    }
    let source_frontier = SnapshotFrontier { aggregates };
    source_frontier.validate().map_err(|detail| {
        ProjectionSnapshotError::Invalid(format!(
            "code=authorization_snapshot.capture_frontier_invalid;detail={detail}"
        ))
    })?;
    Ok(ProjectionSnapshotCapture {
        created_at: OffsetDateTime::now_utc(),
        document: ProjectionSnapshotDocument {
            snapshot_version: SNAPSHOT_PAYLOAD_VERSION_V1,
            states,
        },
        source_frontier,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Save (frozen frame container, atomic exclusive write)
// ─────────────────────────────────────────────────────────────────────────────

/// Capture and atomically persist the typed snapshot at `path`.
///
/// The document is embedded as the opaque payload of the frozen
/// [`SnapshotEnvelope`] container ([`crate::local_projection_snapshot`]): the
/// frame module owns the schema version, canonical JSON, SHA-256 trailer and
/// 256 MiB bound, and the write goes through its exclusive-temp + rename
/// atomic swap. The frontier handed to the container is the per-aggregate
/// generation map, so the frame-level exact-scope decision
/// ([`crate::local_projection_snapshot::decide_snapshot_fallback_per_scope`])
/// stays usable on the same file. Returns the capture for telemetry.
pub async fn save_projection_snapshot(
    path: &Path,
    pool: &sqlx::MySqlPool,
) -> Result<ProjectionSnapshotCapture, ProjectionSnapshotError> {
    let capture = capture_projection_snapshot(pool).await?;
    let payload = serde_json::to_value(&capture.document).map_err(|error| {
        ProjectionSnapshotError::Invalid(format!(
            "code=authorization_snapshot.payload_serialization_failed;detail={error}"
        ))
    })?;
    let envelope =
        SnapshotEnvelope::new(capture.created_at, capture.source_frontier.clone(), payload);
    write_local_snapshot_atomic(path, &envelope)?;
    Ok(capture)
}

// ─────────────────────────────────────────────────────────────────────────────
// Pending delta read (complete, bounded, raw — the hint never interprets)
// ─────────────────────────────────────────────────────────────────────────────

/// One pending (`status <> 'SUCCEEDED'`) `authorization_delta_event` row as
/// observed at hint-load time. Raw stored vocabulary (`event_type`, `status`
/// as strings): the hint records, it never interprets or forgives unknown
/// values — classification belongs to the durable warm path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingDeltaSnapshot {
    pub delta_event_id: i64,
    pub tenant_id: i64,
    pub card_id: Option<i64>,
    pub aggregate_type: String,
    pub aggregate_id: i64,
    pub grant_id: String,
    pub event_id: String,
    pub operation_id: String,
    pub event_type: String,
    pub base_version: i64,
    pub target_version: i64,
    pub source_generation: i64,
    pub revoke_fence: i64,
    pub invalidates_published_evidence: bool,
    pub status: String,
    pub cas_version: i64,
}

#[derive(Debug, sqlx::FromRow)]
struct PendingDeltaRawSqlRow {
    delta_event_id: i64,
    tenant_id: i64,
    card_id: Option<i64>,
    aggregate_type: String,
    aggregate_id: i64,
    grant_id: String,
    event_id: String,
    operation_id: String,
    event_type: String,
    base_version: i64,
    target_version: i64,
    source_generation: i64,
    revoke_fence: i64,
    invalidates_published_evidence: i64,
    status: String,
    cas_version: i64,
}

impl PendingDeltaRawSqlRow {
    fn decode(self) -> Result<PendingDeltaSnapshot, ProjectionSnapshotError> {
        let invalidates_published_evidence = match self.invalidates_published_evidence {
            0 => false,
            1 => true,
            other => {
                return Err(ProjectionSnapshotError::Invalid(format!(
                    "code=authorization_snapshot.pending_delta_invalid_flag_invalid;delta_event_id={};value={other}",
                    self.delta_event_id
                )))
            }
        };
        Ok(PendingDeltaSnapshot {
            delta_event_id: self.delta_event_id,
            tenant_id: self.tenant_id,
            card_id: self.card_id,
            aggregate_type: self.aggregate_type,
            aggregate_id: self.aggregate_id,
            grant_id: self.grant_id,
            event_id: self.event_id,
            operation_id: self.operation_id,
            event_type: self.event_type,
            base_version: self.base_version,
            target_version: self.target_version,
            source_generation: self.source_generation,
            revoke_fence: self.revoke_fence,
            invalidates_published_evidence,
            status: self.status,
            cas_version: self.cas_version,
        })
    }
}

const PENDING_DELTA_ROW_COLUMNS: &str = "delta_event_id, tenant_id, card_id, aggregate_type, \
    aggregate_id, grant_id, event_id, operation_id, event_type, base_version, target_version, \
    source_generation, revoke_fence, invalidates_published_evidence, status, cas_version";

const PENDING_DELTA_ROWS_TAIL: &str = " FROM authorization_delta_event \
    WHERE status <> 'SUCCEEDED' ORDER BY delta_event_id ASC LIMIT ?";

/// Read ALL pending delta rows (bounded by [`MAX_PENDING_DELTA_ROWS` + 1]
/// detection) as one consistent read inside the hint-load transaction.
async fn read_pending_delta_snapshots_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
) -> Result<Vec<PendingDeltaSnapshot>, ProjectionSnapshotError> {
    let statement = format!("SELECT {PENDING_DELTA_ROW_COLUMNS}{PENDING_DELTA_ROWS_TAIL}");
    let raw_rows: Vec<PendingDeltaRawSqlRow> = sqlx::query_as(statement.as_str())
        .bind((MAX_PENDING_DELTA_ROWS as i64) + 1)
        .fetch_all(&mut **tx)
        .await?;
    if raw_rows.len() > MAX_PENDING_DELTA_ROWS {
        return Err(ProjectionSnapshotError::TooLarge(format!(
            "code=authorization_snapshot.too_many_pending_deltas;cap={MAX_PENDING_DELTA_ROWS}"
        )));
    }
    raw_rows
        .into_iter()
        .map(PendingDeltaRawSqlRow::decode)
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Hint classification (exact durable pointer tokens, never generation-only)
// ─────────────────────────────────────────────────────────────────────────────

/// Why one aggregate's snapshot state may not seed the warm mirror.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SnapshotHintDivergenceKind {
    /// The snapshot carries the aggregate but the durable ledger has no
    /// current pointer row for it (stale or foreign identity; never warm).
    MissingFromDurable,
    /// The durable ledger publishes an aggregate the snapshot does not carry;
    /// the mandatory durable warm path must cover it.
    MissingFromSnapshot,
    /// The durable generation is BEHIND the snapshot generation — the ledger
    /// cannot yet account for the snapshot's publication; never warm.
    SnapshotAheadOfDurable,
    /// The durable generation moved past the snapshot generation; the state
    /// is stale.
    SnapshotBehindDurable,
    /// Same generation, but the exact durable pointer token disagrees on at
    /// least one field (manifest id, event/operation ids, semantic or
    /// dependency hash, compiler stamp, fence, fence proof, CAS version,
    /// pointer id, card scope). Only full token equality may warm.
    TokenMismatch,
}

/// One per-aggregate divergence between snapshot and durable state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotAggregateDivergence {
    pub aggregate_key: String,
    pub kind: SnapshotHintDivergenceKind,
}

/// Conservative warm hint produced by [`load_projection_snapshot_hint`].
///
/// `states` contains ONLY aggregates whose exact durable pointer token
/// matched the file state at load time; every other aggregate is listed in
/// `divergences` (deterministic key order). This is a warm-up input for the
/// Warming state only — it never substitutes the mandatory
/// `warm_from_durable` second strict load, and nothing here is a freshness
/// proof.
#[derive(Debug, Clone, PartialEq)]
pub struct ProjectionSnapshotHint {
    created_at: OffsetDateTime,
    source_frontier: SnapshotFrontier,
    states: Vec<AuthorizationPublishedState>,
    divergences: Vec<SnapshotAggregateDivergence>,
    pending_deltas: Vec<PendingDeltaSnapshot>,
}

impl ProjectionSnapshotHint {
    /// Capture instant of the file the hint was loaded from.
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// The file's per-aggregate generation frontier (already cross-checked
    /// against the carried states during classification).
    pub fn source_frontier(&self) -> &SnapshotFrontier {
        &self.source_frontier
    }

    /// Fully validated states whose exact durable pointer token matched at
    /// load time. Safe to install ONLY into a warming (non-serviceable)
    /// mirror state; `warm_from_durable` remains mandatory afterwards.
    pub fn states(&self) -> &[AuthorizationPublishedState] {
        &self.states
    }

    /// Every aggregate the snapshot cannot seed, with the reason.
    pub fn divergences(&self) -> &[SnapshotAggregateDivergence] {
        &self.divergences
    }

    /// All pending (non-`SUCCEEDED`) delta rows observed at load time — the
    /// exact outstanding delta picture, not just a generation watermark.
    pub fn pending_deltas(&self) -> &[PendingDeltaSnapshot] {
        &self.pending_deltas
    }
}

/// Reject a snapshot file whose capture instant is in the future or older
/// than [`MAX_PROJECTION_SNAPSHOT_HINT_AGE_SECONDS`].
pub fn check_projection_snapshot_freshness(
    created_at: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<(), ProjectionSnapshotError> {
    let age_seconds = (now - created_at).whole_seconds();
    if age_seconds < 0 {
        return Err(ProjectionSnapshotError::Invalid(format!(
            "code=authorization_snapshot.created_at_in_future;age_seconds={age_seconds}"
        )));
    }
    if age_seconds > MAX_PROJECTION_SNAPSHOT_HINT_AGE_SECONDS {
        return Err(ProjectionSnapshotError::Expired {
            age_seconds,
            max_age_seconds: MAX_PROJECTION_SNAPSHOT_HINT_AGE_SECONDS,
        });
    }
    Ok(())
}

/// Pure classification core behind [`load_projection_snapshot_hint`].
///
/// Inputs are already frame-validated and per-state structurally validated
/// ([`decode_projection_snapshot_payload`]); this layer adds the file-internal
/// scope consistency proof (duplicate aggregates, frontier/state split in any
/// direction — missing, extra or generation-disagreeing entries) and the
/// exact-token durable comparison, then hands back the conservative hint.
pub(crate) fn classify_projection_snapshot_hint(
    document: ProjectionSnapshotDocument,
    source_frontier: SnapshotFrontier,
    durable_pointers: BTreeMap<String, AuthorizationCurrentPointerRecord>,
    pending_deltas: Vec<PendingDeltaSnapshot>,
    created_at: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<ProjectionSnapshotHint, ProjectionSnapshotError> {
    check_projection_snapshot_freshness(created_at, now)?;

    // File-internal consistency: exact bijection between states and frontier
    // keys, with equal generations per key. Duplicates, partial scope, extra
    // keys and cross-agreement failures all refuse the WHOLE document.
    let mut state_by_key: BTreeMap<String, &AuthorizationPublishedState> = BTreeMap::new();
    for state in &document.states {
        let key = authorization_aggregate_key(&state.pointer.identity);
        if state_by_key.insert(key.clone(), state).is_some() {
            return Err(ProjectionSnapshotError::Invalid(format!(
                "code=authorization_snapshot.duplicate_aggregate_state;aggregate_key={key}"
            )));
        }
    }
    if state_by_key.len() != source_frontier.aggregates.len() {
        return Err(ProjectionSnapshotError::Invalid(format!(
            "code=authorization_snapshot.frontier_state_count_split;states={};frontier={}",
            state_by_key.len(),
            source_frontier.aggregates.len()
        )));
    }
    for (key, state) in &state_by_key {
        let frontier_generation = source_frontier.aggregates.get(key).ok_or_else(|| {
            ProjectionSnapshotError::Invalid(format!(
                "code=authorization_snapshot.frontier_missing_state_scope;aggregate_key={key}"
            ))
        })?;
        if *frontier_generation != state.pointer.current_generation {
            return Err(ProjectionSnapshotError::Invalid(format!(
                "code=authorization_snapshot.frontier_generation_split;aggregate_key={key};frontier={frontier_generation};state={}",
                state.pointer.current_generation
            )));
        }
    }

    // Exact durable token comparison. Only full equality warms; anything else
    // is reported per aggregate and never silently dropped or forgiven.
    let mut states = Vec::new();
    let mut divergences = Vec::new();
    for (key, state) in &state_by_key {
        match durable_pointers.get(key) {
            None => divergences.push(SnapshotAggregateDivergence {
                aggregate_key: key.clone(),
                kind: SnapshotHintDivergenceKind::MissingFromDurable,
            }),
            Some(durable) => {
                if *durable == state.pointer {
                    states.push((*state).clone());
                } else {
                    let kind = match durable
                        .current_generation
                        .cmp(&state.pointer.current_generation)
                    {
                        std::cmp::Ordering::Less => {
                            SnapshotHintDivergenceKind::SnapshotAheadOfDurable
                        }
                        std::cmp::Ordering::Greater => {
                            SnapshotHintDivergenceKind::SnapshotBehindDurable
                        }
                        std::cmp::Ordering::Equal => SnapshotHintDivergenceKind::TokenMismatch,
                    };
                    divergences.push(SnapshotAggregateDivergence {
                        aggregate_key: key.clone(),
                        kind,
                    });
                }
            }
        }
    }
    for key in durable_pointers.keys() {
        if !state_by_key.contains_key(key) {
            divergences.push(SnapshotAggregateDivergence {
                aggregate_key: key.clone(),
                kind: SnapshotHintDivergenceKind::MissingFromSnapshot,
            });
        }
    }
    // BTreeMap iteration already yields deterministic key order for both
    // sides; re-sort the combined report so the exact interleaving is stable.
    divergences.sort_by(|left, right| {
        left.aggregate_key
            .cmp(&right.aggregate_key)
            .then_with(|| left.kind.cmp(&right.kind))
    });

    Ok(ProjectionSnapshotHint {
        created_at,
        source_frontier,
        states,
        divergences,
        pending_deltas,
    })
}

/// Load a saved snapshot as a conservative warm hint.
///
/// Pipeline: bounded framed read ([`read_local_snapshot`]) → age gate →
/// typed payload decode with FULL structural re-validation per state
/// ([`decode_projection_snapshot_payload`]) → one short database transaction
/// reading the durable pointer token set (non-locking, deterministic order,
/// SQL-bounded at [`MAX_CAPTURE_PUBLISHED_STATES`] + 1 rows — an over-cap
/// durable scope fails closed because it can never be classified as a whole)
/// and ALL pending delta rows (bounded) → pure exact-token classification
/// ([`classify_projection_snapshot_hint`]).
///
/// Generation alone is never accepted as the durable comparison: the token
/// covers pointer id, identity, card scope, generation, manifest id,
/// event/operation ids, semantic/dependency hashes, compiler stamp, revoke
/// fence, fence proof and CAS version. A file in any error state yields an
/// error (treat as absent); a diverging aggregate yields a divergence report,
/// never a silently stale state.
pub async fn load_projection_snapshot_hint(
    path: &Path,
    pool: &sqlx::MySqlPool,
) -> Result<ProjectionSnapshotHint, ProjectionSnapshotError> {
    let envelope = read_local_snapshot(path)?;
    let now = OffsetDateTime::now_utc();
    let document = decode_projection_snapshot_payload(&envelope.payload)?;

    let mut tx = pool.begin().await?;
    // Same SQL-level cap as capture: a durable scope beyond one capture's
    // hard cap cannot be compared as a whole and must win nothing — the
    // durable warm path rebuilds instead of a partially comparable hint.
    let pointers = read_all_current_pointer_records_in_tx_bounded(
        &mut tx,
        pointer_scan_bind_limit(MAX_CAPTURE_PUBLISHED_STATES),
    )
    .await?;
    enforce_hint_durable_pointer_capacity(pointers.len())?;
    let pending_deltas = read_pending_delta_snapshots_in_tx(&mut tx).await?;
    tx.commit().await?;

    let durable_pointers: BTreeMap<String, AuthorizationCurrentPointerRecord> = pointers
        .into_iter()
        .map(|pointer| (authorization_aggregate_key(&pointer.identity), pointer))
        .collect();
    classify_projection_snapshot_hint(
        document,
        envelope.source_frontier,
        durable_pointers,
        pending_deltas,
        envelope.created_at,
        now,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure tests (no external database; fixtures carry their own sealed proofs)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization_projection_repository::{
        compute_manifest_digest, compute_segment_dependency_hash, compute_segment_semantic_hash,
        AuthorizationSegmentReferenceRecord, AuthorizationSegmentSnapshot, ManifestDigestInput,
        PublishedCardStateBundle, SegmentLocalSealInput, POINTER_ROWS_ALL_LOCKED_BOUNDED_TAIL,
        POINTER_ROWS_ALL_ORDERED_BOUNDED_TAIL,
    };
    use crate::local_projection_snapshot::write_local_snapshot_atomic;
    use astral_types::{
        BindingLayer, CanonicalGrant, DomainScopeRequirement, GrantEffect, GrantId,
        GrantProvenance, GrantRevision, GrantSourceKind, GrantState, PublishedCardEvidenceScope,
        TenantScope, ValidityWindow,
    };
    use std::fs;

    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const FIXTURE_COMPILER: &str = "phase2-authorization-kernel-v1";
    const FIXTURE_EVENT_ID: &str = "event-snap";
    const FIXTURE_OPERATION_ID: &str = "op-snap";

    fn fixture_grant(unique_tail: u16) -> CanonicalGrant {
        CanonicalGrant {
            grant_id: GrantId::parse(&format!(
                "550e8400-e29b-41d4-a716-44665544{unique_tail:04x}"
            ))
            .unwrap(),
            revision: GrantRevision::initial(),
            state: GrantState::Active,
            source_kind: GrantSourceKind::RuleSet,
            binding_layer: BindingLayer::Base,
            tenant: TenantScope::new(7, Some(11)).unwrap(),
            card_id: 5,
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

    /// One structurally verified published state sealed by the same pure
    /// contracts the DB reader enforces (local segment seals + manifest
    /// digest). Everything a real load proves is provable here without I/O.
    fn verified_state_fixture(generation: u64, aggregate_id: i64) -> AuthorizationPublishedState {
        let identity = ProjectionAggregateIdentity::new(7, "USER_CARD", aggregate_id).unwrap();
        let card_id = 5;
        let grants = vec![fixture_grant(1), fixture_grant(2)];
        let grant_count = grants.len() as u64;
        let payload = encode_segment_payload(&grants).unwrap();
        let content_digest = Sha256Digest::from_raw_bytes(Sha256::digest(&payload).into());
        let seal_input = SegmentLocalSealInput {
            identity: &identity,
            card_id: Some(card_id),
            compiler_version: FIXTURE_COMPILER,
            segment_format: SEGMENT_FORMAT_AUTHORIZATION_GRANTS_JSON_V1,
            row_count: grant_count,
            content_digest: &content_digest,
        };
        let segment = AuthorizationSegmentSnapshot {
            segment_id: 900 + aggregate_id,
            identity: identity.clone(),
            card_id: Some(card_id),
            content_digest,
            semantic_hash: compute_segment_semantic_hash(&seal_input).unwrap(),
            dependency_hash: compute_segment_dependency_hash(&seal_input).unwrap(),
            compiler_version: FIXTURE_COMPILER.to_owned(),
            format: SEGMENT_FORMAT_AUTHORIZATION_GRANTS_JSON_V1.to_owned(),
            row_count: grant_count,
            byte_size: payload.len() as u64,
            grants,
        };
        let reference = AuthorizationSegmentReferenceRecord {
            reference_id: 800 + aggregate_id,
            manifest_id: 700 + aggregate_id,
            identity: identity.clone(),
            card_id: Some(card_id),
            generation,
            ordinal: 0,
            segment_id: segment.segment_id,
            content_digest,
            event_id: FIXTURE_EVENT_ID.to_owned(),
            operation_id: FIXTURE_OPERATION_ID.to_owned(),
        };
        let manifest_digest = compute_manifest_digest(&ManifestDigestInput {
            tenant_id: 7,
            aggregate_type: "USER_CARD",
            aggregate_id,
            card_id: Some(card_id),
            generation,
            source_generation: generation,
            projected_generation: generation,
            event_id: FIXTURE_EVENT_ID,
            operation_id: FIXTURE_OPERATION_ID,
            semantic_hash_hex: HASH_A,
            dependency_hash_hex: HASH_B,
            compiler_version: FIXTURE_COMPILER,
            parent_manifest_id: None,
            revoke_fence: 1,
            segment_content_digests_hex: vec![content_digest.as_hex()],
        })
        .unwrap();
        let pointer = AuthorizationCurrentPointerRecord {
            pointer_id: 600 + aggregate_id,
            identity: identity.clone(),
            card_id: Some(card_id),
            current_generation: generation,
            manifest_id: 700 + aggregate_id,
            event_id: FIXTURE_EVENT_ID.to_owned(),
            operation_id: FIXTURE_OPERATION_ID.to_owned(),
            semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap(),
            dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap(),
            compiler_version: FIXTURE_COMPILER.to_owned(),
            revoke_fence: 1,
            revoke_fence_proven: true,
            cas_version: 4,
        };
        AuthorizationPublishedState {
            pointer,
            manifest_id: 700 + aggregate_id,
            generation,
            source_generation: generation,
            projected_generation: generation,
            event_id: FIXTURE_EVENT_ID.to_owned(),
            operation_id: FIXTURE_OPERATION_ID.to_owned(),
            semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap(),
            dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap(),
            compiler_version: FIXTURE_COMPILER.to_owned(),
            manifest_digest,
            parent_manifest_id: None,
            revoke_fence: 1,
            segments: vec![segment],
            references: vec![reference],
            total_grant_count: grant_count,
        }
    }

    fn fixture_document(states: Vec<AuthorizationPublishedState>) -> ProjectionSnapshotDocument {
        ProjectionSnapshotDocument {
            snapshot_version: SNAPSHOT_PAYLOAD_VERSION_V1,
            states,
        }
    }

    fn frontier_from(states: &[AuthorizationPublishedState]) -> SnapshotFrontier {
        SnapshotFrontier {
            aggregates: states
                .iter()
                .map(|state| {
                    (
                        authorization_aggregate_key(&state.pointer.identity),
                        state.pointer.current_generation,
                    )
                })
                .collect(),
        }
    }

    fn durable_from(
        states: &[AuthorizationPublishedState],
    ) -> BTreeMap<String, AuthorizationCurrentPointerRecord> {
        states
            .iter()
            .map(|state| {
                (
                    authorization_aggregate_key(&state.pointer.identity),
                    state.pointer.clone(),
                )
            })
            .collect()
    }

    // ── Sha256Digest serde (strict lowercase hex) ───────────────────────────

    #[test]
    fn digest_serde_is_strict_lowercase_hex_only() {
        let digest = Sha256Digest::from_hex(HASH_A).unwrap();
        let json = serde_json::to_value(digest).unwrap();
        assert_eq!(json, serde_json::json!(HASH_A));
        let back: Sha256Digest = serde_json::from_value(json).unwrap();
        assert_eq!(back, digest);

        for bad in [
            HASH_A.to_ascii_uppercase(),
            "a".repeat(63),
            format!("{HASH_A}ff"),
            "g".repeat(64),
        ] {
            assert!(
                serde_json::from_value::<Sha256Digest>(serde_json::json!(bad.clone())).is_err(),
                "digest serde must refuse {bad:?}"
            );
        }
    }

    // ── validate_published_state_snapshot ───────────────────────────────────

    #[test]
    fn validated_fixture_passes_full_structural_validation() {
        let state = verified_state_fixture(1, 17);
        validate_published_state_snapshot(&state).unwrap();
    }

    #[test]
    fn validate_refuses_payload_digest_rowcount_bytesize_and_canonicalization_lies() {
        // Payload content changed without resealing (digest + canonicalization
        // must both fail the read).
        let mut state = verified_state_fixture(1, 17);
        state.segments[0].grants[0].action = "write".to_owned();
        assert!(validate_published_state_snapshot(&state).is_err());

        // Content digest flipped: breaks the payload digest, the reference
        // pair and the manifest seal at once — refused either way.
        let mut state = verified_state_fixture(1, 17);
        state.segments[0].content_digest = Sha256Digest::from_hex(HASH_B).unwrap();
        assert!(validate_published_state_snapshot(&state).is_err());

        // Declared row count above the real payload.
        let mut state = verified_state_fixture(1, 17);
        state.segments[0].row_count = 3;
        assert!(validate_published_state_snapshot(&state).is_err());

        // Declared byte size disagreeing with the re-encoded payload.
        let mut state = verified_state_fixture(1, 17);
        state.segments[0].byte_size += 1;
        assert!(validate_published_state_snapshot(&state).is_err());
    }

    #[test]
    fn validate_refuses_manifest_seal_reference_and_local_seal_tampering() {
        // Grant-count sum lie: the assembly recomputes the total and the
        // round-trip equality must refuse it.
        let mut state = verified_state_fixture(1, 17);
        state.total_grant_count += 1;
        assert!(validate_published_state_snapshot(&state).is_err());

        // Manifest digest seal broken.
        let mut state = verified_state_fixture(1, 17);
        state.manifest_digest = Sha256Digest::from_hex(HASH_B).unwrap();
        assert!(validate_published_state_snapshot(&state).is_err());

        // Reference ordinal / pairing drift.
        let mut state = verified_state_fixture(1, 17);
        state.references[0].ordinal = 4;
        assert!(validate_published_state_snapshot(&state).is_err());

        let mut state = verified_state_fixture(1, 17);
        state.references[0].segment_id += 1;
        assert!(validate_published_state_snapshot(&state).is_err());

        // Segment-local seal columns tampered.
        let mut state = verified_state_fixture(1, 17);
        state.segments[0].semantic_hash = Sha256Digest::from_hex(HASH_B).unwrap();
        assert!(validate_published_state_snapshot(&state).is_err());

        // Unproven fence sentinel can never re-enter through the wire form.
        let mut state = verified_state_fixture(1, 17);
        state.pointer.revoke_fence_proven = false;
        assert!(validate_published_state_snapshot(&state).is_err());
    }

    // ── Payload decode (serde is not a trust boundary) ──────────────────────

    #[test]
    fn payload_decode_rejects_unknown_fields_wrong_versions_and_tampered_states() {
        let state = verified_state_fixture(1, 17);
        let document = fixture_document(vec![state.clone()]);
        let payload = serde_json::to_value(&document).unwrap();
        let decoded = decode_projection_snapshot_payload(&payload).unwrap();
        assert_eq!(decoded, document);

        // Unknown top-level fields fail closed.
        let mut extra = payload.clone();
        extra
            .as_object_mut()
            .unwrap()
            .insert("extra".to_owned(), serde_json::json!(1));
        assert!(decode_projection_snapshot_payload(&extra).is_err());

        // Wrong payload version.
        let mut versioned = payload.clone();
        versioned
            .as_object_mut()
            .unwrap()
            .insert("snapshot_version".to_owned(), serde_json::json!(2));
        assert!(decode_projection_snapshot_payload(&versioned).is_err());

        // A tampered state (payload lie) inside a well-framed envelope is
        // refused: the frame digest never substitutes for the contract.
        let mut tampered_state = state;
        tampered_state.segments[0].row_count = 9;
        let tampered_payload =
            serde_json::to_value(fixture_document(vec![tampered_state])).unwrap();
        assert!(decode_projection_snapshot_payload(&tampered_payload).is_err());
    }

    // ── Classification: scope-internal consistency ──────────────────────────

    #[test]
    fn classify_refuses_duplicate_aggregates_and_partial_or_extra_scope() {
        let state = verified_state_fixture(1, 17);
        let key = authorization_aggregate_key(&state.pointer.identity);
        let now = OffsetDateTime::now_utc();

        // Duplicate aggregate state (same id twice).
        let duplicate = fixture_document(vec![state.clone(), state.clone()]);
        assert!(classify_projection_snapshot_hint(
            duplicate,
            frontier_from(std::slice::from_ref(&state)),
            durable_from(std::slice::from_ref(&state)),
            Vec::new(),
            now,
            now,
        )
        .is_err());

        // Partial scope: frontier claims less than the states carry.
        let partial_frontier = SnapshotFrontier {
            aggregates: BTreeMap::new(),
        };
        assert!(classify_projection_snapshot_hint(
            fixture_document(vec![state.clone()]),
            partial_frontier,
            durable_from(std::slice::from_ref(&state)),
            Vec::new(),
            now,
            now,
        )
        .is_err());

        // Extra frontier scope: a cross-scope key with no backing state.
        let extra_frontier = SnapshotFrontier {
            aggregates: BTreeMap::from([(key.clone(), 1), ("9:RULE_SET:88".to_owned(), 2)]),
        };
        assert!(classify_projection_snapshot_hint(
            fixture_document(vec![state.clone()]),
            extra_frontier,
            durable_from(std::slice::from_ref(&state)),
            Vec::new(),
            now,
            now,
        )
        .is_err());

        // Frontier generation disagreeing with the state it names.
        let wrong_generation_frontier = SnapshotFrontier {
            aggregates: BTreeMap::from([(key, 2)]),
        };
        assert!(classify_projection_snapshot_hint(
            fixture_document(vec![state.clone()]),
            wrong_generation_frontier,
            durable_from(&[state]),
            Vec::new(),
            now,
            now,
        )
        .is_err());
    }

    // ── Classification: exact durable token comparison ──────────────────────

    #[test]
    fn classify_keeps_only_exact_token_matches_and_reports_every_divergence() {
        let matching = verified_state_fixture(1, 17);
        let stale = verified_state_fixture(2, 18);
        let now = OffsetDateTime::now_utc();
        let document = fixture_document(vec![matching.clone(), stale.clone()]);
        let frontier = frontier_from(&[matching.clone(), stale.clone()]);

        // Durable moved AHEAD of the stale snapshot aggregate.
        let mut durable = durable_from(&[matching.clone(), stale.clone()]);
        durable
            .get_mut(&authorization_aggregate_key(&stale.pointer.identity))
            .unwrap()
            .current_generation = 3;
        let hint = classify_projection_snapshot_hint(
            document.clone(),
            frontier.clone(),
            durable,
            Vec::new(),
            now,
            now,
        )
        .unwrap();
        assert_eq!(hint.states(), std::slice::from_ref(&matching));
        assert_eq!(hint.divergences().len(), 1);
        assert_eq!(
            hint.divergences()[0].kind,
            SnapshotHintDivergenceKind::SnapshotBehindDurable
        );

        // Same generation but a moved durable token field: never warm.
        let mut durable = durable_from(&[matching.clone(), stale.clone()]);
        durable
            .get_mut(&authorization_aggregate_key(&stale.pointer.identity))
            .unwrap()
            .cas_version += 1;
        let hint = classify_projection_snapshot_hint(
            document.clone(),
            frontier.clone(),
            durable,
            Vec::new(),
            now,
            now,
        )
        .unwrap();
        assert_eq!(hint.states(), std::slice::from_ref(&matching));
        assert_eq!(
            hint.divergences()[0].kind,
            SnapshotHintDivergenceKind::TokenMismatch
        );

        // Snapshot ahead of durable: the ledger cannot account for that
        // publication yet — never warm.
        let mut behind_durable = durable_from(&[matching.clone(), stale.clone()]);
        behind_durable
            .get_mut(&authorization_aggregate_key(&stale.pointer.identity))
            .unwrap()
            .current_generation = 1;
        let hint = classify_projection_snapshot_hint(
            document.clone(),
            frontier.clone(),
            behind_durable,
            Vec::new(),
            now,
            now,
        )
        .unwrap();
        assert_eq!(hint.states(), std::slice::from_ref(&matching));
        assert_eq!(
            hint.divergences()[0].kind,
            SnapshotHintDivergenceKind::SnapshotAheadOfDurable
        );

        // Durable row vanished under the snapshot aggregate.
        let mut durable = durable_from(&[matching.clone(), stale.clone()]);
        durable.remove(&authorization_aggregate_key(&stale.pointer.identity));
        let hint = classify_projection_snapshot_hint(
            document.clone(),
            frontier.clone(),
            durable,
            Vec::new(),
            now,
            now,
        )
        .unwrap();
        assert_eq!(hint.states(), std::slice::from_ref(&matching));
        assert_eq!(
            hint.divergences()[0].kind,
            SnapshotHintDivergenceKind::MissingFromDurable
        );

        // Durable publishes an aggregate the snapshot never carried, while the
        // stale aggregate's durable token also moved: only the exact match
        // stays warm and the report covers both, in deterministic key order.
        let extra_durable = verified_state_fixture(1, 19);
        let extra_key = authorization_aggregate_key(&extra_durable.pointer.identity);
        let mut durable = durable_from(&[matching.clone(), stale.clone(), extra_durable.clone()]);
        durable
            .get_mut(&authorization_aggregate_key(&stale.pointer.identity))
            .unwrap()
            .current_generation = 3;
        durable.remove(&extra_key);
        durable.insert(extra_key, extra_durable.pointer.clone());
        let hint =
            classify_projection_snapshot_hint(document, frontier, durable, Vec::new(), now, now)
                .unwrap();
        assert_eq!(hint.states(), std::slice::from_ref(&matching));
        let kinds: Vec<_> = hint
            .divergences()
            .iter()
            .map(|divergence| (divergence.aggregate_key.clone(), divergence.kind))
            .collect();
        assert_eq!(
            kinds,
            vec![
                (
                    authorization_aggregate_key(&stale.pointer.identity),
                    SnapshotHintDivergenceKind::SnapshotBehindDurable
                ),
                (
                    authorization_aggregate_key(&extra_durable.pointer.identity),
                    SnapshotHintDivergenceKind::MissingFromSnapshot
                ),
            ]
        );
    }

    // ── Age gate ────────────────────────────────────────────────────────────

    #[test]
    fn hint_freshness_rejects_expired_and_future_captures() {
        use time::Duration;
        let now = OffsetDateTime::now_utc();
        check_projection_snapshot_freshness(
            now - Duration::seconds(MAX_PROJECTION_SNAPSHOT_HINT_AGE_SECONDS),
            now,
        )
        .unwrap();
        assert!(matches!(
            check_projection_snapshot_freshness(
                now - Duration::seconds(MAX_PROJECTION_SNAPSHOT_HINT_AGE_SECONDS + 1),
                now,
            ),
            Err(ProjectionSnapshotError::Expired { .. })
        ));
        assert!(
            check_projection_snapshot_freshness(now + Duration::seconds(1), now).is_err(),
            "a capture dated in the future must be refused, never clamped"
        );
    }

    // ── Framed temp-file round trip (pure std I/O, no database) ─────────────

    #[test]
    fn snapshot_document_survives_framed_temp_file_round_trip() {
        let matching = verified_state_fixture(1, 17);
        let extra_durable = verified_state_fixture(2, 18);
        let document = fixture_document(vec![matching.clone(), extra_durable.clone()]);
        let frontier = frontier_from(&[matching.clone(), extra_durable.clone()]);
        let payload = serde_json::to_value(&document).unwrap();
        let created_at = OffsetDateTime::now_utc();
        let envelope = SnapshotEnvelope::new(created_at, frontier, payload);

        let directory =
            std::env::temp_dir().join(format!("astral-snapshot-test-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("projection_snapshot.bin");
        let _guard = TempDirGuard(&directory);
        write_local_snapshot_atomic(&path, &envelope).unwrap();

        // Load through the real framed reader, then classify with one exact
        // and one moved durable token to prove both hint surfaces on a file
        // that actually passed through disk.
        let loaded = read_local_snapshot(&path).unwrap();
        assert_eq!(loaded.created_at, created_at);
        let decoded = decode_projection_snapshot_payload(&loaded.payload).unwrap();
        assert_eq!(decoded, document);

        let mut durable = durable_from(&[matching.clone(), extra_durable.clone()]);
        durable
            .get_mut(&authorization_aggregate_key(
                &extra_durable.pointer.identity,
            ))
            .unwrap()
            .current_generation = 3;
        let hint = classify_projection_snapshot_hint(
            decoded,
            loaded.source_frontier,
            durable,
            Vec::new(),
            created_at,
            OffsetDateTime::now_utc(),
        )
        .unwrap();
        assert_eq!(hint.states(), std::slice::from_ref(&matching));
        assert_eq!(
            hint.divergences(),
            &[SnapshotAggregateDivergence {
                aggregate_key: authorization_aggregate_key(&extra_durable.pointer.identity),
                kind: SnapshotHintDivergenceKind::SnapshotBehindDurable,
            }]
        );
        assert_eq!(hint.source_frontier().aggregates.len(), 2);
    }

    /// Best-effort temp-directory cleanup that never masks a test failure.
    struct TempDirGuard<'a>(&'a Path);
    impl<'a> Drop for TempDirGuard<'a> {
        fn drop(&mut self) {
            let _ignored = fs::remove_dir_all(self.0);
        }
    }

    // ── Shared strict load seam (source-anchored, keeps one reader path) ────

    #[test]
    fn published_card_reader_and_bundle_share_one_strict_load_path() {
        let source = include_str!("authorization_projection_repository.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production region must exist");

        // The legacy evidence reader delegates to the shared bundle loader and
        // no longer duplicates the strict sequence itself. The split anchor is
        // the bundle struct's doc comment: everything between the legacy
        // reader and it is the legacy body alone.
        let reader_body = production
            .split("pub async fn load_published_card_grant_evidence_in_tx")
            .nth(1)
            .and_then(|body| {
                body.split("/// Opaque, commit-proven bundle of EVERY card-scoped")
                    .next()
            })
            .expect("strict evidence reader must exist");
        assert!(
            reader_body.contains("load_published_card_state_bundle_in_tx(tx, scope)"),
            "legacy reader must delegate to the shared bundle loader"
        );
        assert!(
            !reader_body.contains("POINTER_ROWS_FOR_TENANT_CARD_LOCKED_TAIL"),
            "the deterministic locked pointer query is owned by the shared loader only"
        );

        // The shared loader keeps the full strict sequence: freshness probe,
        // deterministic locked pointers, per-aggregate strict chain loads.
        let shared_body = production
            .split("pub(crate) async fn load_published_card_state_bundle_in_tx")
            .nth(1)
            .and_then(|body| body.split("\npub ").next())
            .expect("shared bundle loader must exist");
        assert!(shared_body.contains("card_has_unsafe_pending_delta_in_tx"));
        assert!(shared_body.contains("POINTER_ROWS_FOR_TENANT_CARD_LOCKED_TAIL"));
        assert!(shared_body.contains("read_published_authorization_state_in_tx"));

        // The pool-level bundle loader commits before handing out states.
        let pool_body = production
            .split("pub async fn load_published_card_state_bundle(\n    pool")
            .nth(1)
            .and_then(|body| body.split("\npub ").next())
            .expect("pool-level bundle loader must exist");
        assert!(pool_body.contains("pool.begin().await?;"));
        assert!(pool_body.contains("tx.commit().await?;"));
    }

    // ── Bounded pointer scans (SQL cap + 1, fail closed, source-pinned) ─────

    #[test]
    fn pointer_scan_bind_limit_is_exactly_cap_plus_one() {
        // The binding handed to the SQL LIMIT must be the over-limit probe:
        // one row beyond the cap, never the cap itself (a full cap return
        // would be indistinguishable from "exactly in scope") and never an
        // unbounded read.
        assert_eq!(
            pointer_scan_bind_limit(MAX_CAPTURE_PUBLISHED_STATES),
            100_001
        );
        assert_eq!(pointer_scan_bind_limit(0), 1);
        assert_eq!(pointer_scan_bind_limit(1), 2);
    }

    #[test]
    fn capture_capacity_accepts_cap_and_refuses_the_probe_row() {
        // Exactly the cap is in scope — including zero.
        enforce_capture_pointer_capacity(0).unwrap();
        enforce_capture_pointer_capacity(MAX_CAPTURE_PUBLISHED_STATES).unwrap();

        // The cap + 1-th row (the over-limit probe the bounded SQL may
        // return) fails the WHOLE capture closed with the stable error code.
        let error = enforce_capture_pointer_capacity(MAX_CAPTURE_PUBLISHED_STATES + 1)
            .expect_err("over-cap scan must fail closed");
        assert!(
            matches!(error, ProjectionSnapshotError::TooLarge(_)),
            "unexpected error: {error}"
        );
        assert!(
            error
                .to_string()
                .contains("code=authorization_snapshot.too_many_current_pointers"),
            "error must carry the stable capture over-cap code: {error}"
        );
        assert!(
            error.to_string().contains("cap=100000"),
            "error must carry the cap for operators: {error}"
        );
    }

    #[test]
    fn hint_capacity_refuses_an_over_cap_durable_scope_as_a_whole() {
        enforce_hint_durable_pointer_capacity(0).unwrap();
        enforce_hint_durable_pointer_capacity(MAX_CAPTURE_PUBLISHED_STATES).unwrap();

        let error = enforce_hint_durable_pointer_capacity(MAX_CAPTURE_PUBLISHED_STATES + 1)
            .expect_err("over-cap durable scope must fail closed");
        assert!(
            matches!(error, ProjectionSnapshotError::TooLarge(_)),
            "unexpected error: {error}"
        );
        assert!(
            error
                .to_string()
                .contains("code=authorization_snapshot.too_many_durable_pointers"),
            "error must carry the stable hint over-cap code: {error}"
        );
    }

    #[test]
    fn snapshot_pointer_scans_are_sql_bounded_and_source_pinned() {
        // Own production region: every snapshot pointer scan must go through
        // the SQL-bounded repository pair with the cap + 1 binding and the
        // whole-scope capacity refusals; the unbounded contract variants must
        // have no snapshot caller at all.
        let source = include_str!("authorization_snapshot.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production region must exist");

        assert!(
            production.contains("lock_all_current_pointer_records_in_tx_bounded("),
            "capture must call the SQL-bounded locked pointer scan"
        );
        assert!(
            production.contains("read_all_current_pointer_records_in_tx_bounded("),
            "hint load must call the SQL-bounded non-locking pointer scan"
        );
        // The bounded names END in `_bounded(`, so a bare `_tx(` call can
        // only be the unbounded variant.
        assert!(
            !production.contains("lock_all_current_pointer_records_in_tx("),
            "unbounded locked pointer scan must have no snapshot caller"
        );
        assert!(
            !production.contains("read_all_current_pointer_records_in_tx("),
            "unbounded non-locking pointer scan must have no snapshot caller"
        );
        assert_eq!(
            production
                .matches("pointer_scan_bind_limit(MAX_CAPTURE_PUBLISHED_STATES)")
                .count(),
            2,
            "both pointer scans must bind the same cap + 1 over-limit probe"
        );
        assert!(production.contains("enforce_capture_pointer_capacity(pointers.len())?"));
        assert!(production.contains("enforce_hint_durable_pointer_capacity(pointers.len())?"));

        // Repository production region: the bounded pair exists, decodes
        // through the strict shared path, and actually binds the limit.
        let repo_source = include_str!("authorization_projection_repository.rs");
        let repo_production = repo_source
            .split("#[cfg(test)]")
            .next()
            .expect("repository production region must exist");
        assert!(repo_production.contains("const POINTER_ROWS_ALL_LOCKED_BOUNDED_TAIL"));
        assert!(repo_production.contains("const POINTER_ROWS_ALL_ORDERED_BOUNDED_TAIL"));

        let locked_body = repo_production
            .split("pub(crate) async fn lock_all_current_pointer_records_in_tx_bounded(")
            .nth(1)
            .and_then(|body| body.split("/// Non-locking SQL-bounded counterpart").next())
            .expect("bounded locked pointer scan must exist");
        assert!(
            locked_body.contains("positive_i64(limit"),
            "bounded locked scan must refuse a non-positive limit"
        );
        assert!(
            locked_body.contains("POINTER_ROWS_ALL_LOCKED_BOUNDED_TAIL"),
            "bounded locked scan must use the bounded tail, not an unbounded one"
        );
        assert!(
            locked_body.contains(".bind(limit)"),
            "bounded locked scan must actually bind the SQL LIMIT"
        );

        let ordered_body = repo_production
            .split("pub(crate) async fn read_all_current_pointer_records_in_tx_bounded(")
            .nth(1)
            .and_then(|body| body.split("\nasync fn fetch_manifest_for_update").next())
            .expect("bounded non-locking pointer scan must exist");
        assert!(ordered_body.contains("positive_i64(limit"));
        assert!(ordered_body.contains("POINTER_ROWS_ALL_ORDERED_BOUNDED_TAIL"));
        assert!(ordered_body.contains(".bind(limit)"));

        // The bounded tails cut the SQL at `LIMIT ?` (= cap + 1) and keep the
        // deterministic global order; the locked variant keeps FOR UPDATE
        // after the LIMIT so lock set and read set are the same prefix.
        let locked_tail = format!("SELECT {POINTER_ROWS_ALL_LOCKED_BOUNDED_TAIL}");
        assert!(
            locked_tail.contains("ORDER BY tenant_id ASC, aggregate_type ASC, aggregate_id ASC")
        );
        let limit = locked_tail
            .find("LIMIT ?")
            .expect("bounded locked tail must carry LIMIT ?");
        assert!(
            locked_tail[limit..].contains("FOR UPDATE"),
            "bounded locked tail must keep FOR UPDATE after LIMIT: {locked_tail}"
        );
        assert!(
            !locked_tail[..limit].contains("FOR UPDATE"),
            "no lock clause may precede the LIMIT cut: {locked_tail}"
        );
        let ordered_tail = format!("SELECT {POINTER_ROWS_ALL_ORDERED_BOUNDED_TAIL}");
        assert!(ordered_tail.ends_with("LIMIT ?"));
        assert!(!ordered_tail.contains("FOR UPDATE"));
    }

    // ── Bundle semantics (opaque construction, evidence assembly) ───────────

    #[test]
    fn bundle_evidence_at_matches_the_shared_assembly_contract() {
        use crate::authorization_projection_repository::assemble_published_card_evidence;
        use astral_types::PublishedCardAuthorization;

        let state = verified_state_fixture(1, 17);
        let scope = PublishedCardEvidenceScope {
            tenant_id: 7,
            card_id: 5,
            user_filter: None,
            domain: DomainScopeRequirement::Unconstrained,
        };
        let bundle =
            PublishedCardStateBundle::from_verified_parts(scope.clone(), vec![state.clone()]);
        assert_eq!(bundle.states(), std::slice::from_ref(&state));
        assert_eq!(bundle.scope(), &scope);
        let states = bundle.clone().into_states();
        assert_eq!(states, vec![state.clone()]);

        let now = OffsetDateTime::now_utc().unix_timestamp();
        let evidence: PublishedCardAuthorization = bundle.evidence_at(now).unwrap();
        let expected =
            assemble_published_card_evidence(&scope, now, std::slice::from_ref(&state)).unwrap();
        assert_eq!(evidence, expected);
        evidence.validate().unwrap();
        assert_eq!(evidence.gate.effective_grant_count, 2);
    }

    #[test]
    fn bundle_evidence_at_refuses_an_empty_state_set_as_not_ready() {
        use crate::authorization_projection_repository::AuthorizationEvidenceError;

        let scope = PublishedCardEvidenceScope {
            tenant_id: 7,
            card_id: 5,
            user_filter: None,
            domain: DomainScopeRequirement::Unconstrained,
        };
        let bundle = PublishedCardStateBundle::from_verified_parts(scope, Vec::new());
        let now = OffsetDateTime::now_utc().unix_timestamp();
        assert!(matches!(
            bundle.evidence_at(now),
            Err(AuthorizationEvidenceError::NotReady(_))
        ));
    }
}
