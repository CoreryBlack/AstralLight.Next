//! P5 L1 local persistence snapshot for the in-memory authorization mirror.
//!
//! The single-node runtime opts in with `SINGLE_NODE_SNAPSHOT_PATH` and uses
//! [`crate::authorization_snapshot`] for exact durable pointer validation.
//! Startup still rebuilds against the complete durable state before serving.
//! A snapshot is saved only after bounded service shutdown succeeds.
//!
//! ## Purpose and trust boundary
//!
//! The in-memory projection mirror (`memory_projection_hub`) rebuilds from the
//! durable grant ledger on every start. This module lets a future startup path
//! persist one validated mirror snapshot to local disk and reload it to shorten
//! warm-up. A local file is **never** an authorization authority: the snapshot
//! is a warm-up hint only, and every decision this module produces either says
//! "may pre-warm from these validated bytes" or "ledger rebuild is mandatory".
//! There is no variant that serves authorization directly from a snapshot.
//!
//! ## Fail-closed rules (invariants)
//!
//! - Corrupt, truncated, unsupported-version, oversized, or missing snapshot
//!   files map to [`SnapshotFallbackDecision::RebuildRequired`]; the caller
//!   must rebuild from the durable grant ledger. Serving from such a snapshot
//!   is impossible by construction because the decision type has no such
//!   variant.
//! - Frontier completeness is decided **per aggregate with exact identity**:
//!   the snapshot frontier and the durable published scope must contain the
//!   same aggregate keys with equal generations. A durable aggregate missing
//!   from the snapshot, a snapshot aggregate absent from the durable scope
//!   (stale or foreign identity), a generation behind the durable one, and a
//!   generation ahead of the durable one all map to rebuild/reconciliation.
//!   The global maximum generation never proves coverage (a snapshot with one
//!   aggregate ahead and one behind has a high maximum; see the deprecated
//!   [`decide_snapshot_fallback`] documentation).
//! - Even [`SnapshotFallbackDecision::WarmFromSnapshot`] only permits warming;
//!   readiness refuses to serve until the caller proves catch-up against the
//!   durable frontier ([`SnapshotReadiness::Ready`] is the only serviceable
//!   state).
//!
//! ## File format (binary framing, all integers big-endian)
//!
//! ```text
//! [0..8)      magic: b"ASTRLPS1" (fixed ASCII)
//! [8..12)     framed schema_version: u32 BE (1 = SNAPSHOT_SCHEMA_VERSION_V1)
//! [12..20)    envelope_len: u64 BE (length of the canonical JSON envelope)
//! [20..20+n)  envelope: canonical JSON bytes (n = envelope_len)
//! [20+n..+32) integrity: SHA-256 over bytes[0..20+n) (raw 32 bytes)
//! ```
//!
//! The envelope JSON carries `schema_version` (must mirror the frame header),
//! `created_at` (RFC 3339), the `source_frontier` (per-aggregate published
//! generations covered by the payload), and the opaque `payload` value. On
//! read, every layer is validated in order: total length, magic, schema
//! version, envelope capacity bound, framing length consistency, integrity
//! digest, JSON shape, envelope/frame version agreement, canonical byte
//! equality (re-serialization must reproduce the stored bytes, rejecting
//! reordered keys, whitespace, or extra fields), and frontier sanity. Any
//! failure returns a typed [`LocalSnapshotError`].
//!
//! The whole file is capacity-bounded: reads never buffer more than
//! [`MAX_SNAPSHOT_FILE_BYTES`] plus one overflow byte, and framing/parse
//! refuse envelopes beyond [`MAX_SNAPSHOT_ENVELOPE_BYTES`], so a planted or
//! runaway file cannot exhaust memory.
//!
//! ## Atomic write
//!
//! [`write_local_snapshot_atomic`] uses only `std::fs`: it creates a
//! run-scoped uniquely named temp sibling **exclusively**
//! (`File::create_new`; an occupied name is never clobbered or deleted, the
//! write retries with a fresh token within a bounded budget), syncs the
//! content, then renames over the target (atomic same-volume replace on POSIX
//! and on Windows via `MOVEFILE_REPLACE_EXISTING`). On POSIX the parent
//! directory is additionally fsynced after the rename so the rename itself is
//! durable. Windows has no std directory flush: the swap is atomic there, but
//! its crash durability is not proven by this module and must not be claimed.
//! On any failure the temp file (if this call created it) is removed and the
//! previous snapshot, if any, stays intact.
//!
//! All pure helpers ([`frame_snapshot`], [`parse_snapshot_bytes`],
//! [`decide_snapshot_fallback_per_scope`], [`readiness_from_decision`], the
//! readiness transition machine) are unit-testable without touching the
//! filesystem.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

// ─────────────────────────────────────────────────────────────────────────────
// Format constants
// ─────────────────────────────────────────────────────────────────────────────

/// Fixed file magic; a file not starting with these bytes is rejected before
/// any parsing happens.
pub const SNAPSHOT_MAGIC: [u8; 8] = *b"ASTRLPS1";

/// Framed + envelope schema version understood by this reader/writer.
pub const SNAPSHOT_SCHEMA_VERSION_V1: u32 = 1;

/// `magic(8) + schema_version(4) + envelope_len(8)`.
const HEADER_LEN: usize = 20;

/// Raw SHA-256 trailer length.
const DIGEST_LEN: usize = 32;

/// Hard capacity bound for one snapshot file (framing + envelope + trailer).
/// Reads never buffer more than this bound plus one overflow byte, so a
/// planted or runaway file cannot exhaust memory. Generous enough for a
/// whole-mirror warm-up payload, small enough to bound allocation.
pub const MAX_SNAPSHOT_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// Capacity bound for the canonical JSON envelope region alone (the file
/// bound minus the fixed framing).
pub const MAX_SNAPSHOT_ENVELOPE_BYTES: u64 =
    MAX_SNAPSHOT_FILE_BYTES - (HEADER_LEN + DIGEST_LEN) as u64;

// ─────────────────────────────────────────────────────────────────────────────
// Errors (typed, fail-closed; none of them authorizes anything)
// ─────────────────────────────────────────────────────────────────────────────

/// Snapshot load/write failures. Every variant fails closed: the caller must
/// treat a snapshot in any error state as absent and rebuild from the ledger.
#[derive(Debug, thiserror::Error)]
pub enum LocalSnapshotError {
    /// No file at the expected path (clean first-boot situation).
    #[error("snapshot file missing: {0}")]
    Missing(String),

    /// The file exists but could not be read or written.
    #[error("snapshot io failure: {0}")]
    Io(String),

    /// The file ended before the framing said it should (truncation).
    #[error("snapshot truncated: expected at least {expected_min} bytes, found {actual}")]
    Truncated { expected_min: usize, actual: usize },

    /// Leading bytes are not the fixed magic.
    #[error("snapshot magic mismatch: expected ASTRLPS1, found {0}")]
    BadMagic(String),

    /// The framed schema version is not understood by this build.
    #[error("snapshot schema version {found} is not supported (supported: {SNAPSHOT_SCHEMA_VERSION_V1})")]
    UnsupportedSchemaVersion { found: u32 },

    /// The declared envelope length disagrees with the actual file size.
    #[error("snapshot envelope length {declared} disagrees with file size {actual}")]
    EnvelopeLengthMismatch { declared: u64, actual: usize },

    /// SHA-256 over the framed bytes disagrees with the stored trailer.
    #[error("snapshot integrity digest mismatch: expected {expected}, computed {computed}")]
    DigestMismatch { expected: String, computed: String },

    /// The envelope region is not valid JSON or violates the envelope shape.
    #[error("snapshot envelope is not valid JSON: {0}")]
    MalformedEnvelope(String),

    /// The envelope's inner schema_version disagrees with the frame header.
    #[error("snapshot envelope schema_version {envelope} disagrees with frame version {frame}")]
    EnvelopeSchemaMismatch { frame: u32, envelope: u32 },

    /// Re-serializing the parsed envelope does not reproduce the stored bytes
    /// (reordered keys, added whitespace, unknown or missing fields).
    #[error("snapshot envelope is not canonical JSON")]
    NonCanonicalEnvelope,

    /// A source frontier violates its own invariants (zero generation, empty
    /// aggregate key); applies to snapshot frontiers and to the validated
    /// construction of a [`DurableFrontier`].
    #[error("source frontier is invalid: {0}")]
    InvalidFrontier(String),

    /// The file or envelope exceeds the capacity bound; the read is bounded
    /// and refuses to buffer beyond it.
    #[error("snapshot size {size} bytes exceeds the {max} byte capacity bound")]
    SnapshotTooLarge { size: u64, max: u64 },

    /// Serialization of a new envelope failed (defensive; unreachable for
    /// valid envelopes).
    #[error("snapshot serialization failed: {0}")]
    Serialization(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// Source frontier
// ─────────────────────────────────────────────────────────────────────────────

/// Source frontier covered by a snapshot: per-aggregate published generation
/// the payload was taken at. Aggregate keys are caller-owned strings (for the
/// authorization mirror these are `tenant_id:aggregate_type:aggregate_id`);
/// generations follow the projection convention (start at 1, never 0).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotFrontier {
    /// Aggregate key -> published generation covered by the payload.
    #[serde(default)]
    pub aggregates: BTreeMap<String, u64>,
}

impl SnapshotFrontier {
    /// Highest generation covered by the frontier (`None` when empty, i.e. an
    /// empty-system snapshot). Advisory telemetry only: it never proves
    /// completeness (see [`decide_snapshot_fallback_per_scope`]).
    pub fn max_generation(&self) -> Option<u64> {
        self.aggregates.values().copied().max()
    }

    /// Generation covered for one aggregate (`None` when not covered).
    pub fn generation_for(&self, aggregate_key: &str) -> Option<u64> {
        self.aggregates.get(aggregate_key).copied()
    }

    /// Whether the frontier covers `durable_generation` for one aggregate.
    /// This is a single-aggregate gate for catch-up logic; completeness of a
    /// whole snapshot is only proven by the exact per-aggregate identity
    /// comparison in [`decide_snapshot_fallback_per_scope`].
    pub fn covers(&self, aggregate_key: &str, durable_generation: u64) -> bool {
        matches!(
            self.generation_for(aggregate_key),
            Some(generation) if generation >= durable_generation
        )
    }

    /// Frontier sanity: aggregate keys non-empty, generations >= 1 (zero is
    /// not a valid published generation and would silently weaken staleness
    /// checks).
    pub fn validate(&self) -> Result<(), String> {
        for (key, generation) in &self.aggregates {
            if key.is_empty() {
                return Err("aggregate key is empty".to_owned());
            }
            if *generation == 0 {
                return Err(format!("aggregate '{key}' carries generation 0"));
            }
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Snapshot envelope
// ─────────────────────────────────────────────────────────────────────────────

/// One persisted snapshot: schema version, creation time, source frontier,
/// opaque payload, and (in the file framing) a SHA-256 integrity digest.
///
/// The payload is intentionally opaque (`serde_json::Value`): this module owns
/// the container, integrity, and decision semantics, while the authorization
/// mirror owns the payload shape. `deny_unknown_fields` keeps the envelope
/// surface strict so forward-compatible readers must opt in via a new schema
/// version instead of silently ignoring fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotEnvelope {
    /// Must mirror the framed schema version; disagreement is a typed error.
    pub schema_version: u32,
    /// Wall-clock creation instant, serialized as RFC 3339.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Source frontier the payload was taken at.
    pub source_frontier: SnapshotFrontier,
    /// Opaque authorization payload (canonical JSON value).
    pub payload: serde_json::Value,
}

impl SnapshotEnvelope {
    /// Builds a V1 envelope; the schema version is fixed by this module.
    pub fn new(
        created_at: OffsetDateTime,
        source_frontier: SnapshotFrontier,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            schema_version: SNAPSHOT_SCHEMA_VERSION_V1,
            created_at,
            source_frontier,
            payload,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure framing: build and validate the file bytes
// ─────────────────────────────────────────────────────────────────────────────

/// Serializes the envelope to canonical JSON and frames it with magic, schema
/// version, length prefix, and SHA-256 integrity trailer. Pure; no filesystem.
/// The envelope must fit within [`MAX_SNAPSHOT_ENVELOPE_BYTES`].
pub fn frame_snapshot(envelope: &SnapshotEnvelope) -> Result<Vec<u8>, LocalSnapshotError> {
    frame_snapshot_with_limit(envelope, MAX_SNAPSHOT_ENVELOPE_BYTES)
}

/// [`frame_snapshot`] with an explicit capacity bound (test seam for the
/// real bound used by the public function).
fn frame_snapshot_with_limit(
    envelope: &SnapshotEnvelope,
    max_envelope_bytes: u64,
) -> Result<Vec<u8>, LocalSnapshotError> {
    if envelope.schema_version != SNAPSHOT_SCHEMA_VERSION_V1 {
        return Err(LocalSnapshotError::UnsupportedSchemaVersion {
            found: envelope.schema_version,
        });
    }
    envelope
        .source_frontier
        .validate()
        .map_err(LocalSnapshotError::InvalidFrontier)?;
    let envelope_bytes = serde_json::to_vec(envelope)
        .map_err(|error| LocalSnapshotError::Serialization(error.to_string()))?;
    let envelope_len = envelope_bytes.len() as u64;
    if envelope_len > max_envelope_bytes {
        return Err(LocalSnapshotError::SnapshotTooLarge {
            size: envelope_len,
            max: max_envelope_bytes,
        });
    }
    Ok(framed_bytes(envelope.schema_version, &envelope_bytes))
}

/// Assembles the framed byte layout (magic + version + length + envelope +
/// digest) over already-validated inputs.
fn framed_bytes(schema_version: u32, envelope_bytes: &[u8]) -> Vec<u8> {
    let digest = framed_digest(schema_version, envelope_bytes);
    let mut framed = Vec::with_capacity(HEADER_LEN + envelope_bytes.len() + DIGEST_LEN);
    framed.extend_from_slice(&SNAPSHOT_MAGIC);
    framed.extend_from_slice(&schema_version.to_be_bytes());
    framed.extend_from_slice(&(envelope_bytes.len() as u64).to_be_bytes());
    framed.extend_from_slice(envelope_bytes);
    framed.extend_from_slice(&digest);
    framed
}

/// SHA-256 over magic + version + length prefix + envelope bytes; the length
/// prefix is covered so a truncated envelope can never re-align the trailer.
fn framed_digest(schema_version: u32, envelope_bytes: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(SNAPSHOT_MAGIC);
    hasher.update(schema_version.to_be_bytes());
    hasher.update((envelope_bytes.len() as u64).to_be_bytes());
    hasher.update(envelope_bytes);
    hasher.finalize().into()
}

/// Validates every layer of framed snapshot bytes and returns the envelope.
///
/// Validation order (each failure is a distinct typed error): total length,
/// magic, framed schema version, envelope capacity bound, framing length
/// consistency, integrity digest, JSON shape, envelope/frame version
/// agreement, canonical byte equality, frontier sanity.
pub fn parse_snapshot_bytes(bytes: &[u8]) -> Result<SnapshotEnvelope, LocalSnapshotError> {
    parse_snapshot_bytes_with_limit(bytes, MAX_SNAPSHOT_ENVELOPE_BYTES)
}

/// [`parse_snapshot_bytes`] with an explicit capacity bound (test seam for the
/// real bound used by the public function).
fn parse_snapshot_bytes_with_limit(
    bytes: &[u8],
    max_envelope_bytes: u64,
) -> Result<SnapshotEnvelope, LocalSnapshotError> {
    if bytes.len() < HEADER_LEN + DIGEST_LEN {
        return Err(LocalSnapshotError::Truncated {
            expected_min: HEADER_LEN + DIGEST_LEN,
            actual: bytes.len(),
        });
    }
    let magic = &bytes[..8];
    if magic != SNAPSHOT_MAGIC.as_slice() {
        return Err(LocalSnapshotError::BadMagic(hex::encode(magic)));
    }
    let schema_version = u32::from_be_bytes(bytes[8..12].try_into().expect("fixed 4-byte slice"));
    if schema_version != SNAPSHOT_SCHEMA_VERSION_V1 {
        return Err(LocalSnapshotError::UnsupportedSchemaVersion {
            found: schema_version,
        });
    }
    let declared_envelope_len =
        u64::from_be_bytes(bytes[12..20].try_into().expect("fixed 8-byte slice"));
    // Capacity gate before any length arithmetic or slicing: a planted or
    // runaway header can never drive an unbounded buffer.
    if declared_envelope_len > max_envelope_bytes {
        return Err(LocalSnapshotError::SnapshotTooLarge {
            size: declared_envelope_len,
            max: max_envelope_bytes,
        });
    }
    let expected_total = HEADER_LEN as u64 + declared_envelope_len + DIGEST_LEN as u64;
    let actual_total = bytes.len() as u64;
    if expected_total > actual_total {
        return Err(LocalSnapshotError::Truncated {
            expected_min: usize::try_from(expected_total).unwrap_or(usize::MAX),
            actual: bytes.len(),
        });
    }
    if expected_total < actual_total {
        return Err(LocalSnapshotError::EnvelopeLengthMismatch {
            declared: declared_envelope_len,
            actual: bytes.len(),
        });
    }
    let envelope_len = declared_envelope_len as usize;
    let envelope_bytes = &bytes[HEADER_LEN..HEADER_LEN + envelope_len];
    let expected_digest = hex::encode(&bytes[HEADER_LEN + envelope_len..]);
    let computed_digest = hex::encode(framed_digest(schema_version, envelope_bytes));
    if computed_digest != expected_digest {
        return Err(LocalSnapshotError::DigestMismatch {
            expected: expected_digest,
            computed: computed_digest,
        });
    }
    let envelope: SnapshotEnvelope = serde_json::from_slice(envelope_bytes)
        .map_err(|error| LocalSnapshotError::MalformedEnvelope(error.to_string()))?;
    if envelope.schema_version != schema_version {
        return Err(LocalSnapshotError::EnvelopeSchemaMismatch {
            frame: schema_version,
            envelope: envelope.schema_version,
        });
    }
    let canonical_bytes = serde_json::to_vec(&envelope)
        .map_err(|error| LocalSnapshotError::Serialization(error.to_string()))?;
    if canonical_bytes != envelope_bytes {
        return Err(LocalSnapshotError::NonCanonicalEnvelope);
    }
    envelope
        .source_frontier
        .validate()
        .map_err(LocalSnapshotError::InvalidFrontier)?;
    Ok(envelope)
}

// ─────────────────────────────────────────────────────────────────────────────
// File API (pure std)
// ─────────────────────────────────────────────────────────────────────────────

/// Reads and validates a snapshot file. A non-existing file is
/// [`LocalSnapshotError::Missing`] (clean first boot); every other failure
/// means the file must not be used. The read is capacity-bounded by
/// [`MAX_SNAPSHOT_FILE_BYTES`].
pub fn read_local_snapshot(path: &Path) -> Result<SnapshotEnvelope, LocalSnapshotError> {
    read_local_snapshot_with_limit(path, MAX_SNAPSHOT_FILE_BYTES)
}

/// [`read_local_snapshot`] with an explicit capacity bound (test seam for the
/// real bound used by the public function).
fn read_local_snapshot_with_limit(
    path: &Path,
    max_file_bytes: u64,
) -> Result<SnapshotEnvelope, LocalSnapshotError> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(LocalSnapshotError::Missing(path.display().to_string()));
        }
        Err(error) => {
            return Err(LocalSnapshotError::Io(format!(
                "open {}: {error}",
                path.display()
            )));
        }
    };
    // Bounded read: at most one byte beyond the capacity bound is buffered,
    // so an oversized (or concurrently growing) file cannot exhaust memory.
    let mut bytes = Vec::new();
    file.take(max_file_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| LocalSnapshotError::Io(format!("read {}: {error}", path.display())))?;
    if bytes.len() as u64 > max_file_bytes {
        return Err(LocalSnapshotError::SnapshotTooLarge {
            size: bytes.len() as u64,
            max: max_file_bytes,
        });
    }
    parse_snapshot_bytes(&bytes)
}

/// Run-scoped temp sibling path for the atomic write: same directory (so the
/// rename stays on one volume), dotted name derived from the target, and a
/// caller-provided unique token (a UUID at the call sites) so concurrent
/// writers never collide and crashed writers leave identifiable leftovers.
pub fn atomic_temp_sibling_path(path: &Path, token: &str) -> PathBuf {
    let file_name = path.file_name().map_or_else(
        || "snapshot".to_owned(),
        |name| name.to_string_lossy().into_owned(),
    );
    path.with_file_name(format!(".{file_name}.tmp-{token}"))
}

/// Bounded budget for exclusive temp-name creation: a name collision gets a
/// fresh run-scoped token, at most this many attempts, then the write fails
/// closed (a pre-existing name is never clobbered or removed).
const ATOMIC_WRITE_TEMP_ATTEMPTS: usize = 3;

/// Creates the temp file exclusively, writes and syncs the framed bytes, then
/// atomically swaps them in as `target`.
///
/// - `File::create_new` (`O_CREAT | O_EXCL`): an existing temp path is never
///   clobbered; an `AlreadyExists` error leaves that file untouched (it is
///   not ours, so it is never removed either).
/// - `sync_all` before the rename: the bytes are durable before the swap can
///   make them visible (no rename can publish non-durable content).
/// - After the rename, POSIX syncs the parent directory so the rename itself
///   is durable. Windows has no std directory flush: the swap is atomic there
///   (same-volume `MOVEFILE_REPLACE_EXISTING`) but its crash durability is
///   not proven by this module and must not be claimed.
/// - On any failure after creation, the temp file (ours) is removed; the
///   target was never touched by a failed attempt.
fn write_via_exclusive_temp(framed: &[u8], temp_path: &Path, target: &Path) -> std::io::Result<()> {
    // Exclusive create: an existing temp path is never clobbered; an error
    // here means nothing was created and nothing needs cleanup.
    let file = fs::File::create_new(temp_path)?;
    if let Err(error) = write_sync_rename(file, framed, temp_path, target) {
        let _ignored = fs::remove_file(temp_path);
        return Err(error);
    }
    Ok(())
}

/// Writes and syncs the framed bytes, closes the handle, renames over the
/// target, and (POSIX only) fsyncs the parent directory for rename
/// durability. See [`write_via_exclusive_temp`] for the guarantee boundaries.
fn write_sync_rename(
    mut file: fs::File,
    framed: &[u8],
    temp_path: &Path,
    target: &Path,
) -> std::io::Result<()> {
    file.write_all(framed)?;
    file.sync_all()?;
    drop(file);
    fs::rename(temp_path, target)?;
    #[cfg(unix)]
    if let Some(parent) = target.parent() {
        if let Ok(directory) = fs::File::open(parent) {
            // Best-effort directory fsync: the rename already happened, so a
            // failure here degrades the durability guarantee, not correctness.
            let _ignored = directory.sync_all();
        }
    }
    Ok(())
}

/// Writes the snapshot atomically: exclusive unique temp sibling + content
/// sync + rename (+ POSIX directory fsync).
///
/// A temp-name collision (v4 UUID or a hostile pre-planted name) retries with
/// a fresh run-scoped token within [`ATOMIC_WRITE_TEMP_ATTEMPTS`]; a
/// persistent collision fails closed without touching the occupied file. On
/// any other failure the temp file (if this call created it) is removed and
/// the previous snapshot, if any, stays untouched. Durability boundary: the
/// content is fsynced before the swap everywhere; the swap itself is
/// durably recorded only on POSIX (directory fsync) -- on Windows it is
/// atomic but not fs-proven durable, and this module does not claim it.
pub fn write_local_snapshot_atomic(
    path: &Path,
    envelope: &SnapshotEnvelope,
) -> Result<(), LocalSnapshotError> {
    let framed = frame_snapshot(envelope)?;
    let mut occupied_name: Option<std::io::Error> = None;
    for _attempt in 0..ATOMIC_WRITE_TEMP_ATTEMPTS {
        let temp_path = atomic_temp_sibling_path(path, &uuid::Uuid::new_v4().to_string());
        match write_via_exclusive_temp(&framed, &temp_path, path) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                occupied_name = Some(error);
            }
            Err(error) => {
                return Err(LocalSnapshotError::Io(format!(
                    "atomic write {}: {error}",
                    path.display()
                )));
            }
        }
    }
    Err(LocalSnapshotError::Io(match occupied_name {
        Some(error) => format!(
            "atomic write {}: exclusive temp name unavailable: {error}",
            path.display()
        ),
        None => format!(
            "atomic write {}: no exclusive temp attempt was made",
            path.display()
        ),
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Fallback decision (corrupt/missing/scope-divergent => ledger rebuild, never
// serve)
// ─────────────────────────────────────────────────────────────────────────────

/// Why the durable ledger must be rebuilt instead of using the snapshot.
#[derive(Debug, thiserror::Error)]
pub enum RebuildCause {
    /// No snapshot file existed (clean first boot).
    #[error("no local snapshot exists")]
    Missing,

    /// Snapshot bytes failed validation; the detailed error is preserved for
    /// logging/metrics, never for recovery-by-guessing.
    #[error("snapshot unusable: {0}")]
    Corrupt(#[from] LocalSnapshotError),

    /// The snapshot frontier is older than the durable frontier; warming from
    /// it would risk missing deltas, so rebuild replays the ledger instead.
    ///
    /// Produced only by the deprecated global-maximum decision
    /// ([`decide_snapshot_fallback`]); the per-scope decision reports the
    /// offending aggregate via [`RebuildCause::ScopeDivergence`] instead.
    #[error("snapshot generation {snapshot_generation} is behind durable generation {durable_generation}")]
    StaleGeneration {
        snapshot_generation: u64,
        durable_generation: u64,
    },

    /// The snapshot frontier does not exactly match the durable published
    /// scope at one aggregate. Missing (durable aggregate absent from the
    /// snapshot), extra (snapshot aggregate absent from the durable scope --
    /// stale or foreign identity, a tenant-isolation hazard), stale
    /// (generation behind), and ahead (generation beyond anything the durable
    /// ledger can account for) all rebuild/reconcile; none ever serves.
    #[error("snapshot scope diverges at '{aggregate_key}' ({kind:?}): snapshot generation {snapshot_generation:?} vs durable {durable_generation:?}")]
    ScopeDivergence {
        aggregate_key: String,
        kind: ScopeDivergenceKind,
        snapshot_generation: Option<u64>,
        durable_generation: Option<u64>,
    },
}

/// How one aggregate's snapshot frontier diverges from the durable scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeDivergenceKind {
    /// Durable aggregate absent from the snapshot frontier.
    MissingFromSnapshot,
    /// Snapshot aggregate absent from the durable published scope (stale or
    /// foreign identity; never serve).
    ExtraInSnapshot,
    /// Snapshot generation behind the durable generation.
    Stale,
    /// Snapshot generation beyond the durable generation; the ledger cannot
    /// account for that publication, so reconcile via rebuild.
    Ahead,
}

/// What a startup path must do with the local snapshot.
///
/// Deliberately **no** variant serves authorization from the snapshot alone:
/// [`WarmFromSnapshot`](SnapshotFallbackDecision::WarmFromSnapshot) is a
/// warm-up hint whose readiness still refuses until catch-up is proven, and
/// every failure mode lands in
/// [`RebuildRequired`](SnapshotFallbackDecision::RebuildRequired) (mandatory
/// ledger rebuild, fail-closed).
#[derive(Debug)]
pub enum SnapshotFallbackDecision {
    /// Snapshot bytes validated and its frontier exactly matches the durable
    /// published scope; the payload may pre-warm the in-memory mirror.
    /// Readiness still refuses to serve until the durable frontier is proven
    /// caught up.
    WarmFromSnapshot {
        /// Advisory telemetry only: the highest generation in the snapshot
        /// frontier. Completeness is proven by the exact per-aggregate
        /// identity comparison, never by this maximum (0 for an empty-system
        /// snapshot).
        frontier_generation: u64,
    },
    /// Ledger rebuild is mandatory; never authorize from this snapshot.
    RebuildRequired(RebuildCause),
}

/// Durable published scope: the exact set of aggregate identities currently
/// published in the durable ledger and their current generations, as observed
/// by the caller. Constructed validated (empty keys / zero generations are
/// rejected), so the per-scope decision never reasons about an invalid
/// durable scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableFrontier {
    aggregates: BTreeMap<String, u64>,
}

impl DurableFrontier {
    /// Validates and wraps a durable scope; empty keys and zero generations
    /// are rejected with [`LocalSnapshotError::InvalidFrontier`].
    pub fn new(aggregates: BTreeMap<String, u64>) -> Result<Self, LocalSnapshotError> {
        let frontier = SnapshotFrontier { aggregates };
        frontier
            .validate()
            .map_err(LocalSnapshotError::InvalidFrontier)?;
        Ok(Self {
            aggregates: frontier.aggregates,
        })
    }

    /// The empty durable scope (empty system).
    pub fn empty() -> Self {
        Self {
            aggregates: BTreeMap::new(),
        }
    }

    /// The validated durable scope as key -> generation.
    pub fn aggregates(&self) -> &BTreeMap<String, u64> {
        &self.aggregates
    }

    /// Durable generation for one aggregate (`None` when not published).
    pub fn generation_for(&self, aggregate_key: &str) -> Option<u64> {
        self.aggregates.get(aggregate_key).copied()
    }

    /// Whether the durable scope publishes nothing.
    pub fn is_empty(&self) -> bool {
        self.aggregates.is_empty()
    }
}

/// Pure per-aggregate decision over a snapshot load result versus the durable
/// published scope. Completeness requires **exact identity**: the snapshot
/// frontier and the durable scope must contain the same aggregate keys with
/// equal generations. Missing, extra, stale, and ahead aggregates each
/// rebuild with the offending key preserved for reconciliation; the global
/// maximum generation is never used as a coverage proof.
pub fn decide_snapshot_fallback_per_scope(
    load_result: Result<SnapshotEnvelope, LocalSnapshotError>,
    durable_frontier: &DurableFrontier,
) -> SnapshotFallbackDecision {
    let envelope = match load_result {
        Ok(envelope) => envelope,
        Err(LocalSnapshotError::Missing(_)) => {
            return SnapshotFallbackDecision::RebuildRequired(RebuildCause::Missing);
        }
        Err(error) => {
            return SnapshotFallbackDecision::RebuildRequired(RebuildCause::Corrupt(error));
        }
    };
    if let Some(cause) = find_scope_divergence(&envelope.source_frontier, durable_frontier) {
        return SnapshotFallbackDecision::RebuildRequired(cause);
    }
    SnapshotFallbackDecision::WarmFromSnapshot {
        frontier_generation: envelope.source_frontier.max_generation().unwrap_or(0),
    }
}

/// First divergence between the snapshot frontier and the durable scope in
/// deterministic (lexicographic) key order. `None` means exact identity: same
/// key set, equal generation per key.
fn find_scope_divergence(
    snapshot: &SnapshotFrontier,
    durable: &DurableFrontier,
) -> Option<RebuildCause> {
    let mut snapshot_entries = snapshot.aggregates.iter();
    let mut durable_entries = durable.aggregates().iter();
    let mut next_snapshot = snapshot_entries.next();
    let mut next_durable = durable_entries.next();
    loop {
        match (next_snapshot, next_durable) {
            (
                Some((snapshot_key, snapshot_generation)),
                Some((durable_key, durable_generation)),
            ) => match snapshot_key.cmp(durable_key) {
                Ordering::Equal => {
                    if snapshot_generation < durable_generation {
                        return Some(RebuildCause::ScopeDivergence {
                            aggregate_key: snapshot_key.clone(),
                            kind: ScopeDivergenceKind::Stale,
                            snapshot_generation: Some(*snapshot_generation),
                            durable_generation: Some(*durable_generation),
                        });
                    }
                    if snapshot_generation > durable_generation {
                        return Some(RebuildCause::ScopeDivergence {
                            aggregate_key: snapshot_key.clone(),
                            kind: ScopeDivergenceKind::Ahead,
                            snapshot_generation: Some(*snapshot_generation),
                            durable_generation: Some(*durable_generation),
                        });
                    }
                    next_snapshot = snapshot_entries.next();
                    next_durable = durable_entries.next();
                }
                Ordering::Less => {
                    return Some(RebuildCause::ScopeDivergence {
                        aggregate_key: snapshot_key.clone(),
                        kind: ScopeDivergenceKind::ExtraInSnapshot,
                        snapshot_generation: Some(*snapshot_generation),
                        durable_generation: None,
                    });
                }
                Ordering::Greater => {
                    return Some(RebuildCause::ScopeDivergence {
                        aggregate_key: durable_key.clone(),
                        kind: ScopeDivergenceKind::MissingFromSnapshot,
                        snapshot_generation: None,
                        durable_generation: Some(*durable_generation),
                    });
                }
            },
            (Some((snapshot_key, snapshot_generation)), None) => {
                return Some(RebuildCause::ScopeDivergence {
                    aggregate_key: snapshot_key.clone(),
                    kind: ScopeDivergenceKind::ExtraInSnapshot,
                    snapshot_generation: Some(*snapshot_generation),
                    durable_generation: None,
                });
            }
            (None, Some((durable_key, durable_generation))) => {
                return Some(RebuildCause::ScopeDivergence {
                    aggregate_key: durable_key.clone(),
                    kind: ScopeDivergenceKind::MissingFromSnapshot,
                    snapshot_generation: None,
                    durable_generation: Some(*durable_generation),
                });
            }
            (None, None) => return None,
        }
    }
}

/// Legacy global-maximum decision: compares only the highest generation
/// across aggregates against one durable number.
///
/// **Deprecated because it cannot prove completeness**: a multi-aggregate
/// snapshot with one aggregate ahead and one behind the durable frontier has
/// a high maximum and is (wrongly) accepted here. Retained only for callers
/// that predate the per-scope decision; the runtime authorization path must
/// use [`decide_snapshot_fallback_per_scope`], which requires exact
/// per-aggregate identity and generation equality.
#[deprecated(
    since = "0.1.0",
    note = "global max_generation cannot prove per-aggregate completeness; use decide_snapshot_fallback_per_scope"
)]
pub fn decide_snapshot_fallback(
    load_result: Result<SnapshotEnvelope, LocalSnapshotError>,
    durable_frontier_generation: u64,
) -> SnapshotFallbackDecision {
    let envelope = match load_result {
        Ok(envelope) => envelope,
        Err(LocalSnapshotError::Missing(_)) => {
            return SnapshotFallbackDecision::RebuildRequired(RebuildCause::Missing);
        }
        Err(error) => {
            return SnapshotFallbackDecision::RebuildRequired(RebuildCause::Corrupt(error));
        }
    };
    let snapshot_generation = envelope.source_frontier.max_generation();
    let covers = match snapshot_generation {
        Some(max_generation) => max_generation >= durable_frontier_generation,
        // Empty frontier only covers an empty system (durable generation 0).
        None => durable_frontier_generation == 0,
    };
    if covers {
        SnapshotFallbackDecision::WarmFromSnapshot {
            frontier_generation: snapshot_generation.unwrap_or(0),
        }
    } else {
        SnapshotFallbackDecision::RebuildRequired(RebuildCause::StaleGeneration {
            snapshot_generation: snapshot_generation.unwrap_or(0),
            durable_generation: durable_frontier_generation,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Readiness state machine (snapshot -> warm-up -> ready)
// ─────────────────────────────────────────────────────────────────────────────

/// Readiness of the snapshot warm-up path. Only [`SnapshotReadiness::Ready`]
/// may serve; every other state refuses (fail-closed until catch-up proof).
///
/// Ownership boundary: these types and the tracker below are **pure
/// scaffolding** -- they classify decisions and enforce transition legality,
/// but they verify nothing by themselves. `Ready` must only be declared by
/// the runtime after it has durably proven catch-up against the authoritative
/// ledger (a caller bool or a tracker transition is not proof); the startup
/// path that performs and gates that verification lives outside this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotReadiness {
    /// No snapshot attempt has been made yet.
    Cold,
    /// A snapshot (or a completed rebuild) is being warmed; not serviceable.
    Warming,
    /// Warm-up finished and the durable frontier catch-up is proven.
    Ready,
    /// Snapshot bytes failed validation; rebuild is the only way out.
    Corrupt,
    /// Ledger rebuild is mandatory before any serving.
    RebuildRequired,
}

impl SnapshotReadiness {
    /// Whether this state may serve authorization evidence. Only `Ready`.
    pub const fn is_serviceable(self) -> bool {
        matches!(self, SnapshotReadiness::Ready)
    }

    /// Legal transitions:
    /// - `Cold -> Warming` (snapshot accepted) / `Cold -> Corrupt` (bytes
    ///   invalid) / `Cold -> RebuildRequired` (missing)
    /// - `Corrupt -> RebuildRequired` (decision after validation failure)
    /// - `RebuildRequired -> Warming` (ledger rebuild finished, warm again)
    /// - `Warming -> Ready` (catch-up proven) / `Warming -> RebuildRequired`
    ///   (warm-up verification failed)
    /// - `Ready -> Warming` (new warm-up cycle) / `Ready -> RebuildRequired`
    ///   (runtime divergence from durable state discovered)
    ///
    /// Notably illegal: `Cold -> Ready`, `Corrupt -> Ready`,
    /// `RebuildRequired -> Ready` (a rebuild must re-warm first), and any
    /// transition back to `Cold` (state is monotonic in confidence).
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (SnapshotReadiness::Cold, SnapshotReadiness::Warming)
                | (SnapshotReadiness::Cold, SnapshotReadiness::Corrupt)
                | (SnapshotReadiness::Cold, SnapshotReadiness::RebuildRequired)
                | (
                    SnapshotReadiness::Corrupt,
                    SnapshotReadiness::RebuildRequired
                )
                | (
                    SnapshotReadiness::RebuildRequired,
                    SnapshotReadiness::Warming
                )
                | (SnapshotReadiness::Warming, SnapshotReadiness::Ready)
                | (
                    SnapshotReadiness::Warming,
                    SnapshotReadiness::RebuildRequired
                )
                | (SnapshotReadiness::Ready, SnapshotReadiness::Warming)
                | (SnapshotReadiness::Ready, SnapshotReadiness::RebuildRequired)
        )
    }
}

/// Illegal-transition error carrying both endpoints for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("illegal snapshot readiness transition from {from:?} to {to:?}")]
pub struct IllegalSnapshotReadinessTransition {
    pub from: SnapshotReadiness,
    pub to: SnapshotReadiness,
}

/// Tiny pure tracker that only performs legal transitions. Start state is
/// [`SnapshotReadiness::Cold`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotReadinessTracker {
    state: SnapshotReadiness,
}

impl Default for SnapshotReadinessTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl SnapshotReadinessTracker {
    pub const fn new() -> Self {
        Self {
            state: SnapshotReadiness::Cold,
        }
    }

    pub const fn state(&self) -> SnapshotReadiness {
        self.state
    }

    /// Applies `next` if the transition is legal; otherwise returns the
    /// typed error and keeps the current state unchanged.
    pub fn transition(
        &mut self,
        next: SnapshotReadiness,
    ) -> Result<(), IllegalSnapshotReadinessTransition> {
        if self.state.can_transition_to(next) {
            self.state = next;
            Ok(())
        } else {
            Err(IllegalSnapshotReadinessTransition {
                from: self.state,
                to: next,
            })
        }
    }
}

/// Maps a fallback decision onto the initial readiness state. Corrupt maps to
/// [`SnapshotReadiness::Corrupt`] first (kept for observability); the tracker
/// then moves it to `RebuildRequired`. No mapping ever produces `Ready`.
pub fn readiness_from_decision(decision: &SnapshotFallbackDecision) -> SnapshotReadiness {
    match decision {
        SnapshotFallbackDecision::WarmFromSnapshot { .. } => SnapshotReadiness::Warming,
        SnapshotFallbackDecision::RebuildRequired(RebuildCause::Missing) => {
            SnapshotReadiness::RebuildRequired
        }
        SnapshotFallbackDecision::RebuildRequired(RebuildCause::Corrupt(_)) => {
            SnapshotReadiness::Corrupt
        }
        SnapshotFallbackDecision::RebuildRequired(RebuildCause::StaleGeneration { .. }) => {
            SnapshotReadiness::RebuildRequired
        }
        SnapshotFallbackDecision::RebuildRequired(RebuildCause::ScopeDivergence { .. }) => {
            SnapshotReadiness::RebuildRequired
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests (pure; filesystem tests use std temp dirs only)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixed_time() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("fixed timestamp")
    }

    fn test_envelope(frontier_generation: u64) -> SnapshotEnvelope {
        envelope_with_frontier(frontier(&[("tenant:1:card:2", frontier_generation)]))
    }

    fn frontier(pairs: &[(&str, u64)]) -> SnapshotFrontier {
        SnapshotFrontier {
            aggregates: pairs
                .iter()
                .map(|(key, generation)| ((*key).to_owned(), *generation))
                .collect(),
        }
    }

    fn envelope_with_frontier(source_frontier: SnapshotFrontier) -> SnapshotEnvelope {
        SnapshotEnvelope::new(fixed_time(), source_frontier, json!({"grants": []}))
    }

    fn durable_frontier(pairs: &[(&str, u64)]) -> DurableFrontier {
        DurableFrontier::new(frontier(pairs).aggregates).expect("valid durable frontier")
    }

    fn temp_dir_with_prefix(prefix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    // ── roundtrip / canonical bytes ──────────────────────────────────────────

    #[test]
    fn roundtrip_envelope_preserves_all_fields() {
        let envelope = test_envelope(7);
        let framed = frame_snapshot(&envelope).expect("frame");
        let parsed = parse_snapshot_bytes(&framed).expect("parse");
        assert_eq!(parsed, envelope);
        assert_eq!(parsed.schema_version, SNAPSHOT_SCHEMA_VERSION_V1);
        assert_eq!(
            parsed.source_frontier.generation_for("tenant:1:card:2"),
            Some(7)
        );
    }

    #[test]
    fn framing_is_byte_stable_and_canonical() {
        let envelope = test_envelope(7);
        let first = frame_snapshot(&envelope).expect("frame once");
        let second = frame_snapshot(&envelope).expect("frame twice");
        assert_eq!(first, second);
        // RFC 3339 creation time must round-trip byte-stably too.
        assert!(first
            .windows(SNAPSHOT_MAGIC.len())
            .any(|w| w == SNAPSHOT_MAGIC));
    }

    #[test]
    fn parsed_bytes_reparse_to_same_value() {
        let framed = frame_snapshot(&test_envelope(3)).expect("frame");
        let parsed = parse_snapshot_bytes(&framed).expect("parse");
        let reframed = frame_snapshot(&parsed).expect("reframe");
        assert_eq!(framed, reframed);
    }

    // ── tamper / truncation / magic ──────────────────────────────────────────

    #[test]
    fn tampered_payload_byte_fails_digest() {
        let mut framed = frame_snapshot(&test_envelope(7)).expect("frame");
        let last_envelope_byte = framed.len() - DIGEST_LEN - 1;
        framed[last_envelope_byte] ^= 0x01;
        let error = parse_snapshot_bytes(&framed).expect_err("tampered payload");
        assert!(matches!(error, LocalSnapshotError::DigestMismatch { .. }));
    }

    #[test]
    fn tampered_digest_trailer_fails_digest() {
        let mut framed = frame_snapshot(&test_envelope(7)).expect("frame");
        let last = framed.len() - 1;
        framed[last] ^= 0xFF;
        let error = parse_snapshot_bytes(&framed).expect_err("tampered digest");
        assert!(matches!(error, LocalSnapshotError::DigestMismatch { .. }));
    }

    #[test]
    fn truncated_file_rejected_at_every_cut_point() {
        let framed = frame_snapshot(&test_envelope(7)).expect("frame");
        for cut in [
            0usize,
            1,
            HEADER_LEN - 1,
            HEADER_LEN,
            framed.len() - DIGEST_LEN,
            framed.len() - 1,
        ] {
            let error = parse_snapshot_bytes(&framed[..cut]).expect_err("truncated");
            assert!(
                matches!(
                    error,
                    LocalSnapshotError::Truncated { .. } | LocalSnapshotError::BadMagic(_)
                ),
                "unexpected error at cut {cut}: {error:?}"
            );
        }
    }

    #[test]
    fn trailing_extra_bytes_rejected_as_length_mismatch() {
        let mut framed = frame_snapshot(&test_envelope(7)).expect("frame");
        framed.push(0xAB);
        let error = parse_snapshot_bytes(&framed).expect_err("extra bytes");
        assert!(matches!(
            error,
            LocalSnapshotError::EnvelopeLengthMismatch { .. }
        ));
    }

    #[test]
    fn wrong_magic_rejected() {
        let mut framed = frame_snapshot(&test_envelope(7)).expect("frame");
        framed[0] = b'X';
        let error = parse_snapshot_bytes(&framed).expect_err("bad magic");
        assert!(matches!(error, LocalSnapshotError::BadMagic(_)));
    }

    // ── schema version handling ──────────────────────────────────────────────

    #[test]
    fn unsupported_framed_schema_version_rejected_before_digest() {
        // Hand-build a V2 frame with a V2-consistent digest: the version gate
        // must fire regardless of digest correctness.
        let envelope_bytes = serde_json::to_vec(&test_envelope(7)).expect("serialize");
        let digest = framed_digest(2, &envelope_bytes);
        let mut framed = Vec::new();
        framed.extend_from_slice(&SNAPSHOT_MAGIC);
        framed.extend_from_slice(&2u32.to_be_bytes());
        framed.extend_from_slice(&(envelope_bytes.len() as u64).to_be_bytes());
        framed.extend_from_slice(&envelope_bytes);
        framed.extend_from_slice(&digest);
        let error = parse_snapshot_bytes(&framed).expect_err("v2 frame");
        assert!(matches!(
            error,
            LocalSnapshotError::UnsupportedSchemaVersion { found: 2 }
        ));
    }

    #[test]
    fn stale_digest_on_unknown_version_still_reports_version_first() {
        let mut framed = frame_snapshot(&test_envelope(7)).expect("frame");
        framed[11] = 2; // version bytes 0..0=2, digest now stale
        let error = parse_snapshot_bytes(&framed).expect_err("v2 frame, stale digest");
        assert!(matches!(
            error,
            LocalSnapshotError::UnsupportedSchemaVersion { found: 2 }
        ));
    }

    #[test]
    fn envelope_schema_disagreeing_with_frame_rejected() {
        // Valid digest, but the inner envelope claims a different version.
        let mut tampered = test_envelope(7);
        tampered.schema_version = 2;
        let envelope_bytes = serde_json::to_vec(&tampered).expect("serialize");
        let framed = framed_bytes(SNAPSHOT_SCHEMA_VERSION_V1, &envelope_bytes);
        let error = parse_snapshot_bytes(&framed).expect_err("version disagreement");
        assert!(matches!(
            error,
            LocalSnapshotError::EnvelopeSchemaMismatch {
                frame: SNAPSHOT_SCHEMA_VERSION_V1,
                envelope: 2
            }
        ));
    }

    #[test]
    fn framing_rejects_envelope_with_wrong_version_before_writing() {
        let mut envelope = test_envelope(7);
        envelope.schema_version = 99;
        let error = frame_snapshot(&envelope).expect_err("bad version");
        assert!(matches!(
            error,
            LocalSnapshotError::UnsupportedSchemaVersion { found: 99 }
        ));
    }

    // ── canonical JSON enforcement ───────────────────────────────────────────

    #[test]
    fn non_canonical_whitespace_rejected() {
        // Hand-write pretty-printed envelope JSON, then frame it with a valid
        // digest over those exact bytes: only the canonical check can catch it.
        let envelope = test_envelope(7);
        let pretty = serde_json::to_string_pretty(&envelope).expect("pretty");
        assert_ne!(
            pretty.as_bytes(),
            serde_json::to_vec(&envelope).expect("compact")
        );
        let mut framed = framed_bytes(SNAPSHOT_SCHEMA_VERSION_V1, pretty.as_bytes());
        let trailer_at = HEADER_LEN + pretty.len();
        let digest = framed_digest(SNAPSHOT_SCHEMA_VERSION_V1, pretty.as_bytes());
        framed.truncate(trailer_at);
        framed.extend_from_slice(&digest);
        let error = parse_snapshot_bytes(&framed).expect_err("pretty JSON");
        assert!(matches!(error, LocalSnapshotError::NonCanonicalEnvelope));
    }

    #[test]
    fn malformed_envelope_json_rejected() {
        let envelope_bytes = b"{}" as &[u8];
        let mut framed = framed_bytes(SNAPSHOT_SCHEMA_VERSION_V1, envelope_bytes);
        let trailer_at = HEADER_LEN + envelope_bytes.len();
        let digest = framed_digest(SNAPSHOT_SCHEMA_VERSION_V1, envelope_bytes);
        framed.truncate(trailer_at);
        framed.extend_from_slice(&digest);
        let error = parse_snapshot_bytes(&framed).expect_err("empty object");
        assert!(matches!(error, LocalSnapshotError::MalformedEnvelope(_)));
    }

    #[test]
    fn unknown_envelope_fields_rejected() {
        let mut value = serde_json::to_value(test_envelope(7)).expect("to value");
        value["extra_field"] = json!("surprise");
        let envelope_bytes = serde_json::to_vec(&value).expect("serialize");
        let mut framed = framed_bytes(SNAPSHOT_SCHEMA_VERSION_V1, &envelope_bytes);
        let trailer_at = HEADER_LEN + envelope_bytes.len();
        let digest = framed_digest(SNAPSHOT_SCHEMA_VERSION_V1, &envelope_bytes);
        framed.truncate(trailer_at);
        framed.extend_from_slice(&digest);
        let error = parse_snapshot_bytes(&framed).expect_err("extra field");
        assert!(matches!(error, LocalSnapshotError::MalformedEnvelope(_)));
    }

    #[test]
    fn invalid_frontier_zero_generation_rejected() {
        let envelope = envelope_with_frontier(frontier(&[("tenant:1:card:2", 7), ("x", 0)]));
        let error = frame_snapshot(&envelope).expect_err("zero generation");
        assert!(matches!(error, LocalSnapshotError::InvalidFrontier(_)));
    }

    #[test]
    fn invalid_frontier_empty_key_rejected() {
        let envelope = envelope_with_frontier(frontier(&[("", 4)]));
        let error = frame_snapshot(&envelope).expect_err("empty key");
        assert!(matches!(error, LocalSnapshotError::InvalidFrontier(_)));
    }

    // ── capacity bounds and bounded reads ────────────────────────────────────

    #[test]
    fn oversized_declared_envelope_rejected_before_any_buffering() {
        // 52 bytes total (header + dummy trailer) whose header declares an
        // envelope one byte beyond the capacity bound: the capacity gate must
        // fire before any length arithmetic or slicing.
        let mut framed = Vec::new();
        framed.extend_from_slice(&SNAPSHOT_MAGIC);
        framed.extend_from_slice(&SNAPSHOT_SCHEMA_VERSION_V1.to_be_bytes());
        framed.extend_from_slice(&(MAX_SNAPSHOT_ENVELOPE_BYTES + 1).to_be_bytes());
        framed.extend_from_slice(&[0u8; DIGEST_LEN]);
        let error = parse_snapshot_bytes(&framed).expect_err("oversized declaration");
        assert!(matches!(error, LocalSnapshotError::SnapshotTooLarge { .. }));
    }

    #[test]
    fn frame_respects_envelope_capacity_limit() {
        // The test seam uses a tiny limit; the public function uses the real
        // bound and accepts the same envelope.
        let error = frame_snapshot_with_limit(&test_envelope(7), 16).expect_err("tiny limit");
        assert!(matches!(
            error,
            LocalSnapshotError::SnapshotTooLarge { size: _, max: 16 }
        ));
        assert!(frame_snapshot(&test_envelope(7)).is_ok());
    }

    #[test]
    fn read_is_bounded_by_capacity() {
        let dir = temp_dir_with_prefix("astral-snapshot-bounded");
        let target = dir.join("auth-snapshot.bin");
        write_local_snapshot_atomic(&target, &test_envelope(5)).expect("write snapshot");

        // A tiny bound makes the (legitimately larger) file read as too large.
        let error = read_local_snapshot_with_limit(&target, 8).expect_err("bounded read");
        assert!(matches!(error, LocalSnapshotError::SnapshotTooLarge { .. }));
        // The real bound parses the same file fine.
        assert!(read_local_snapshot(&target).is_ok());
        let _unused = fs::remove_dir_all(&dir);
    }

    // ── atomic path helper ───────────────────────────────────────────────────

    #[test]
    fn atomic_temp_sibling_path_is_same_dir_distinct_name() {
        let target = Path::new("/data/mirror/auth-snapshot.bin");
        let temp = atomic_temp_sibling_path(target, "token-1");
        assert_eq!(temp.parent(), target.parent());
        let temp_name = temp.file_name().expect("file name").to_string_lossy();
        assert!(temp_name.starts_with(".auth-snapshot.bin.tmp-"));
        assert!(temp_name.ends_with("token-1"));
        assert_ne!(temp, target);
    }

    #[test]
    fn atomic_temp_sibling_path_handles_bare_file_name() {
        let temp = atomic_temp_sibling_path(Path::new("snapshot.bin"), "t");
        assert_eq!(temp, PathBuf::from(".snapshot.bin.tmp-t"));
    }

    // ── atomic write on real (std temp) filesystem ───────────────────────────

    #[test]
    fn atomic_write_then_read_roundtrips_and_replaces() {
        let dir = temp_dir_with_prefix("astral-snapshot-roundtrip");
        let target = dir.join("auth-snapshot.bin");
        let path: &Path = &target;

        write_local_snapshot_atomic(path, &test_envelope(5)).expect("first write");
        let loaded = read_local_snapshot(path).expect("first read");
        assert_eq!(loaded, test_envelope(5));

        // Second write replaces the first atomically; no duplicate leftovers.
        write_local_snapshot_atomic(path, &test_envelope(9)).expect("second write");
        let reloaded = read_local_snapshot(path).expect("second read");
        assert_eq!(reloaded, test_envelope(9));

        let entries: Vec<_> = fs::read_dir(&dir)
            .expect("list dir")
            .collect::<Result<_, _>>()
            .expect("dir entries");
        assert_eq!(entries.len(), 1, "no temp leftovers: {entries:?}");
        let _unused = fs::remove_dir_all(&dir);
    }

    #[test]
    fn failed_atomic_write_cleans_temp_and_keeps_previous_snapshot() {
        let dir = temp_dir_with_prefix("astral-snapshot-failure");
        let target = dir.join("auth-snapshot.bin");
        write_local_snapshot_atomic(&target, &test_envelope(5)).expect("seed snapshot");

        // Make the rename fail: the target name is taken by a directory, so
        // the exclusive temp create succeeds, sync succeeds, rename fails,
        // and the cleanup must remove our temp file while the seeded
        // snapshot stays.
        let blocked = dir.join("blocked.d");
        fs::create_dir(&blocked).expect("create blocking dir");
        let error = write_local_snapshot_atomic(&blocked, &test_envelope(9))
            .expect_err("rename onto directory must fail");
        assert!(matches!(error, LocalSnapshotError::Io(_)));

        let entries: Vec<_> = fs::read_dir(&dir)
            .expect("list dir")
            .collect::<Result<_, _>>()
            .expect("dir entries");
        assert_eq!(
            entries.len(),
            2,
            "only snapshot + blocking dir: {entries:?}"
        );
        assert!(target.is_file(), "previous snapshot intact");
        assert!(read_local_snapshot(&target).is_ok(), "snapshot still valid");
        let _unused = fs::remove_dir_all(&dir);
    }

    #[test]
    fn temp_creation_is_exclusive_and_never_clobbers() {
        let dir = temp_dir_with_prefix("astral-snapshot-exclusive");
        // Pre-plant a file exactly where the temp sibling would go.
        let occupied = dir.join(".target.bin.tmp-occupied");
        fs::write(&occupied, b"do-not-clobber").expect("plant file");

        let framed = frame_snapshot(&test_envelope(1)).expect("frame");
        let error = write_via_exclusive_temp(&framed, &occupied, &dir.join("target.bin"))
            .expect_err("occupied temp name must fail exclusively");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        // The planted file is neither clobbered nor deleted, and the target
        // was never created by the failed attempt.
        assert_eq!(
            fs::read(&occupied).expect("read planted"),
            b"do-not-clobber"
        );
        assert!(!dir.join("target.bin").exists(), "target untouched");
        let _unused = fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_missing_file_reports_missing() {
        let dir = temp_dir_with_prefix("astral-snapshot-missing");
        let error = read_local_snapshot(&dir.join("absent.bin")).expect_err("missing");
        assert!(matches!(error, LocalSnapshotError::Missing(_)));
        let _unused = fs::remove_dir_all(&dir);
    }

    // ── fallback decision: per-aggregate exact identity comparison ───────────

    #[test]
    fn corrupt_snapshot_requires_rebuild_never_serve() {
        let mut framed =
            frame_snapshot(&envelope_with_frontier(frontier(&[("a", 7)]))).expect("frame");
        framed[HEADER_LEN] ^= 0x01;
        let decision = decide_snapshot_fallback_per_scope(
            parse_snapshot_bytes(&framed),
            &durable_frontier(&[("a", 7)]),
        );
        match decision {
            SnapshotFallbackDecision::RebuildRequired(RebuildCause::Corrupt(
                LocalSnapshotError::DigestMismatch { .. },
            )) => {}
            other => panic!("expected rebuild-on-corrupt, got {other:?}"),
        }
    }

    #[test]
    fn missing_snapshot_requires_rebuild() {
        let decision = decide_snapshot_fallback_per_scope(
            Err(LocalSnapshotError::Missing("gone".to_owned())),
            &DurableFrontier::empty(),
        );
        match decision {
            SnapshotFallbackDecision::RebuildRequired(RebuildCause::Missing) => {}
            other => panic!("expected rebuild-on-missing, got {other:?}"),
        }
    }

    #[test]
    fn per_scope_exact_match_warms() {
        let decision = decide_snapshot_fallback_per_scope(
            Ok(envelope_with_frontier(frontier(&[("a", 3), ("b", 9)]))),
            &durable_frontier(&[("a", 3), ("b", 9)]),
        );
        match decision {
            SnapshotFallbackDecision::WarmFromSnapshot {
                frontier_generation: 9,
            } => {}
            other => panic!("expected warm on exact scope match, got {other:?}"),
        }
    }

    #[test]
    fn per_scope_missing_aggregate_rebuilds() {
        // Durable aggregate "b" is absent from the snapshot frontier.
        let decision = decide_snapshot_fallback_per_scope(
            Ok(envelope_with_frontier(frontier(&[("a", 1)]))),
            &durable_frontier(&[("a", 1), ("b", 2)]),
        );
        match decision {
            SnapshotFallbackDecision::RebuildRequired(RebuildCause::ScopeDivergence {
                aggregate_key,
                kind: ScopeDivergenceKind::MissingFromSnapshot,
                snapshot_generation: None,
                durable_generation: Some(2),
            }) => assert_eq!(aggregate_key, "b"),
            other => panic!("expected missing-aggregate divergence, got {other:?}"),
        }
    }

    #[test]
    fn per_scope_extra_aggregate_rebuilds() {
        // "ghost" exists in the snapshot but not in the durable scope: stale
        // or foreign identity (tenant-isolation hazard), never serve.
        let decision = decide_snapshot_fallback_per_scope(
            Ok(envelope_with_frontier(frontier(&[("a", 1), ("ghost", 4)]))),
            &durable_frontier(&[("a", 1)]),
        );
        match decision {
            SnapshotFallbackDecision::RebuildRequired(RebuildCause::ScopeDivergence {
                aggregate_key,
                kind: ScopeDivergenceKind::ExtraInSnapshot,
                snapshot_generation: Some(4),
                durable_generation: None,
            }) => assert_eq!(aggregate_key, "ghost"),
            other => panic!("expected extra-aggregate divergence, got {other:?}"),
        }
    }

    #[test]
    fn per_scope_stale_generation_rebuilds() {
        let decision = decide_snapshot_fallback_per_scope(
            Ok(envelope_with_frontier(frontier(&[("a", 5)]))),
            &durable_frontier(&[("a", 9)]),
        );
        match decision {
            SnapshotFallbackDecision::RebuildRequired(RebuildCause::ScopeDivergence {
                aggregate_key,
                kind: ScopeDivergenceKind::Stale,
                snapshot_generation: Some(5),
                durable_generation: Some(9),
            }) => assert_eq!(aggregate_key, "a"),
            other => panic!("expected stale divergence, got {other:?}"),
        }
    }

    #[test]
    fn per_scope_ahead_generation_rebuilds() {
        // The snapshot claims a generation the durable ledger does not have:
        // a divergence the ledger cannot account for -> reconcile via rebuild.
        let decision = decide_snapshot_fallback_per_scope(
            Ok(envelope_with_frontier(frontier(&[("a", 9)]))),
            &durable_frontier(&[("a", 1)]),
        );
        match decision {
            SnapshotFallbackDecision::RebuildRequired(RebuildCause::ScopeDivergence {
                aggregate_key,
                kind: ScopeDivergenceKind::Ahead,
                snapshot_generation: Some(9),
                durable_generation: Some(1),
            }) => assert_eq!(aggregate_key, "a"),
            other => panic!("expected ahead divergence, got {other:?}"),
        }
    }

    #[test]
    fn multi_aggregate_one_high_one_low_cannot_cover_by_max() {
        // Snapshot: "a" ahead at 9, "b" behind at 1; the durable max is 9.
        // A max-based comparison sees 9 >= 9 and would wrongly warm; the
        // per-scope decision must rebuild because "b" is not covered.
        let decision = decide_snapshot_fallback_per_scope(
            Ok(envelope_with_frontier(frontier(&[("a", 9), ("b", 1)]))),
            &durable_frontier(&[("a", 9), ("b", 9)]),
        );
        match decision {
            SnapshotFallbackDecision::RebuildRequired(RebuildCause::ScopeDivergence {
                aggregate_key,
                kind: ScopeDivergenceKind::Stale,
                snapshot_generation: Some(1),
                durable_generation: Some(9),
            }) => assert_eq!(aggregate_key, "b"),
            other => panic!("expected stale divergence on 'b', got {other:?}"),
        }
        // Contrast: the deprecated global-max decision accepts the same
        // snapshot, which is exactly why it must stay off the runtime path.
        #[allow(deprecated)]
        {
            let legacy = decide_snapshot_fallback(
                Ok(envelope_with_frontier(frontier(&[("a", 9), ("b", 1)]))),
                9,
            );
            assert!(matches!(
                legacy,
                SnapshotFallbackDecision::WarmFromSnapshot {
                    frontier_generation: 9
                }
            ));
        }
    }

    #[test]
    fn per_scope_empty_system_rules() {
        // Empty durable scope + empty snapshot: the only warmable empty case.
        match decide_snapshot_fallback_per_scope(
            Ok(envelope_with_frontier(SnapshotFrontier::default())),
            &DurableFrontier::empty(),
        ) {
            SnapshotFallbackDecision::WarmFromSnapshot {
                frontier_generation: 0,
            } => {}
            other => panic!("expected warm of empty system, got {other:?}"),
        }
        // Snapshot aggregates the durable scope lacks: extra identity.
        let extra = decide_snapshot_fallback_per_scope(
            Ok(envelope_with_frontier(frontier(&[("a", 1)]))),
            &DurableFrontier::empty(),
        );
        assert!(matches!(
            extra,
            SnapshotFallbackDecision::RebuildRequired(RebuildCause::ScopeDivergence {
                kind: ScopeDivergenceKind::ExtraInSnapshot,
                ..
            })
        ));
        // Durable aggregates the snapshot lacks: missing identity.
        let missing = decide_snapshot_fallback_per_scope(
            Ok(envelope_with_frontier(SnapshotFrontier::default())),
            &durable_frontier(&[("a", 1)]),
        );
        assert!(matches!(
            missing,
            SnapshotFallbackDecision::RebuildRequired(RebuildCause::ScopeDivergence {
                kind: ScopeDivergenceKind::MissingFromSnapshot,
                ..
            })
        ));
    }

    #[test]
    fn decision_type_has_no_direct_serve_variant() {
        // Exhaustive match documents the type-level invariant: every decision
        // is either a warm-up hint or a mandatory rebuild; none authorizes.
        fn describe(decision: &SnapshotFallbackDecision) -> &'static str {
            match decision {
                SnapshotFallbackDecision::WarmFromSnapshot { .. } => "warm-up hint only",
                SnapshotFallbackDecision::RebuildRequired(_) => "ledger rebuild",
            }
        }
        assert_eq!(
            describe(&decide_snapshot_fallback_per_scope(
                Ok(envelope_with_frontier(frontier(&[("a", 9)]))),
                &durable_frontier(&[("a", 9)])
            )),
            "warm-up hint only"
        );
        assert_eq!(
            describe(&decide_snapshot_fallback_per_scope(
                Err(LocalSnapshotError::Missing("x".to_owned())),
                &DurableFrontier::empty()
            )),
            "ledger rebuild"
        );
    }

    #[test]
    #[allow(deprecated)]
    fn legacy_max_decision_is_deprecated_and_insufficient() {
        // Behavior pin for the deprecated API only: it still reports
        // StaleGeneration on a low max and warms on a matching max, but it
        // cannot detect per-aggregate divergence (see
        // multi_aggregate_one_high_one_low_cannot_cover_by_max). The runtime
        // authorization path must use decide_snapshot_fallback_per_scope.
        let decision = decide_snapshot_fallback(Ok(test_envelope(5)), 9);
        assert!(matches!(
            decision,
            SnapshotFallbackDecision::RebuildRequired(RebuildCause::StaleGeneration { .. })
        ));
        let decision = decide_snapshot_fallback(Ok(test_envelope(9)), 9);
        assert!(matches!(
            decision,
            SnapshotFallbackDecision::WarmFromSnapshot {
                frontier_generation: 9
            }
        ));
    }

    #[test]
    fn durable_frontier_rejects_invalid_entries() {
        let mut zero_generation = BTreeMap::new();
        zero_generation.insert("a".to_owned(), 0u64);
        assert!(matches!(
            DurableFrontier::new(zero_generation),
            Err(LocalSnapshotError::InvalidFrontier(_))
        ));

        let mut empty_key = BTreeMap::new();
        empty_key.insert(String::new(), 1u64);
        assert!(matches!(
            DurableFrontier::new(empty_key),
            Err(LocalSnapshotError::InvalidFrontier(_))
        ));

        let empty = DurableFrontier::empty();
        assert!(empty.is_empty());
        assert_eq!(empty.generation_for("a"), None);
        let frontier = durable_frontier(&[("a", 3)]);
        assert!(!frontier.is_empty());
        assert_eq!(frontier.generation_for("a"), Some(3));
        assert_eq!(frontier.generation_for("b"), None);
    }

    // ── readiness state machine ──────────────────────────────────────────────

    #[test]
    fn readiness_from_decision_never_maps_to_ready() {
        let warm = decide_snapshot_fallback_per_scope(
            Ok(envelope_with_frontier(frontier(&[("a", 9)]))),
            &durable_frontier(&[("a", 9)]),
        );
        assert_eq!(readiness_from_decision(&warm), SnapshotReadiness::Warming);

        let missing = decide_snapshot_fallback_per_scope(
            Err(LocalSnapshotError::Missing("x".to_owned())),
            &DurableFrontier::empty(),
        );
        assert_eq!(
            readiness_from_decision(&missing),
            SnapshotReadiness::RebuildRequired
        );

        let mut framed =
            frame_snapshot(&envelope_with_frontier(frontier(&[("a", 7)]))).expect("frame");
        framed[HEADER_LEN] ^= 0x01;
        let corrupt = decide_snapshot_fallback_per_scope(
            parse_snapshot_bytes(&framed),
            &durable_frontier(&[("a", 7)]),
        );
        assert_eq!(
            readiness_from_decision(&corrupt),
            SnapshotReadiness::Corrupt
        );

        let divergent = decide_snapshot_fallback_per_scope(
            Ok(envelope_with_frontier(frontier(&[("a", 9), ("b", 1)]))),
            &durable_frontier(&[("a", 9), ("b", 9)]),
        );
        assert_eq!(
            readiness_from_decision(&divergent),
            SnapshotReadiness::RebuildRequired
        );
    }

    #[test]
    fn only_ready_state_is_serviceable() {
        assert!(!SnapshotReadiness::Cold.is_serviceable());
        assert!(!SnapshotReadiness::Warming.is_serviceable());
        assert!(SnapshotReadiness::Ready.is_serviceable());
        assert!(!SnapshotReadiness::Corrupt.is_serviceable());
        assert!(!SnapshotReadiness::RebuildRequired.is_serviceable());
    }

    #[test]
    fn happy_path_transitions_cold_to_ready() {
        let mut tracker = SnapshotReadinessTracker::new();
        tracker
            .transition(SnapshotReadiness::Warming)
            .expect("cold -> warming");
        tracker
            .transition(SnapshotReadiness::Ready)
            .expect("warming -> ready");
        assert!(tracker.state().is_serviceable());
    }

    #[test]
    fn corrupt_path_goes_through_rebuild_before_warming() {
        let mut tracker = SnapshotReadinessTracker::new();
        tracker
            .transition(SnapshotReadiness::Corrupt)
            .expect("cold -> corrupt");
        // Corrupt can never jump straight to ready.
        assert!(!SnapshotReadiness::Corrupt.can_transition_to(SnapshotReadiness::Ready));
        tracker
            .transition(SnapshotReadiness::RebuildRequired)
            .expect("corrupt -> rebuild");
        tracker
            .transition(SnapshotReadiness::Warming)
            .expect("rebuild -> warming");
        tracker
            .transition(SnapshotReadiness::Ready)
            .expect("warming -> ready");
    }

    #[test]
    fn illegal_transitions_are_rejected_and_state_unchanged() {
        let illegal_pairs = [
            (SnapshotReadiness::Cold, SnapshotReadiness::Ready),
            (SnapshotReadiness::Cold, SnapshotReadiness::Cold),
            (SnapshotReadiness::Warming, SnapshotReadiness::Cold),
            (SnapshotReadiness::Warming, SnapshotReadiness::Corrupt),
            (SnapshotReadiness::Corrupt, SnapshotReadiness::Warming),
            (SnapshotReadiness::Corrupt, SnapshotReadiness::Ready),
            (SnapshotReadiness::Corrupt, SnapshotReadiness::Corrupt),
            (SnapshotReadiness::RebuildRequired, SnapshotReadiness::Ready),
            (
                SnapshotReadiness::RebuildRequired,
                SnapshotReadiness::Corrupt,
            ),
            (SnapshotReadiness::RebuildRequired, SnapshotReadiness::Cold),
            (SnapshotReadiness::Ready, SnapshotReadiness::Cold),
            (SnapshotReadiness::Ready, SnapshotReadiness::Corrupt),
            (SnapshotReadiness::Ready, SnapshotReadiness::Ready),
        ];
        for (from, to) in illegal_pairs {
            let mut tracker = SnapshotReadinessTracker { state: from };
            let error = tracker.transition(to).expect_err("illegal transition");
            assert_eq!(
                error,
                IllegalSnapshotReadinessTransition { from, to },
                "unexpected error for {from:?} -> {to:?}"
            );
            assert_eq!(tracker.state(), from, "state must stay unchanged");
        }
    }

    #[test]
    fn legal_recovery_and_rewarm_transitions_accepted() {
        let legal_pairs = [
            (SnapshotReadiness::Cold, SnapshotReadiness::Warming),
            (SnapshotReadiness::Cold, SnapshotReadiness::Corrupt),
            (SnapshotReadiness::Cold, SnapshotReadiness::RebuildRequired),
            (
                SnapshotReadiness::Corrupt,
                SnapshotReadiness::RebuildRequired,
            ),
            (
                SnapshotReadiness::RebuildRequired,
                SnapshotReadiness::Warming,
            ),
            (SnapshotReadiness::Warming, SnapshotReadiness::Ready),
            (
                SnapshotReadiness::Warming,
                SnapshotReadiness::RebuildRequired,
            ),
            (SnapshotReadiness::Ready, SnapshotReadiness::Warming),
            (SnapshotReadiness::Ready, SnapshotReadiness::RebuildRequired),
        ];
        for (from, to) in legal_pairs {
            let mut tracker = SnapshotReadinessTracker { state: from };
            tracker.transition(to).expect("legal transition");
            assert_eq!(tracker.state(), to);
        }
    }

    // ── frontier helpers ─────────────────────────────────────────────────────

    #[test]
    fn frontier_max_and_per_aggregate_coverage() {
        let empty = SnapshotFrontier::default();
        assert_eq!(empty.max_generation(), None);
        assert!(!empty.covers("a", 0));
        let populated = frontier(&[("a", 3), ("b", 9)]);
        assert_eq!(populated.max_generation(), Some(9));
        assert!(populated.covers("a", 3));
        assert!(!populated.covers("a", 4));
        assert!(!populated.covers("missing", 1));
        populated.validate().expect("valid frontier");
    }
}
