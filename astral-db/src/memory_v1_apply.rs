//! memory—v1 P0 MySQL apply executor: one journal message → one all-or-nothing
//! MySQL transaction.
//!
//! Contract (§15.10.4, 全新数据库设计 §7 item 7/9/10/11): apply an
//! already-authorized, already-journaled governance mutation by committing, in
//! the same MySQL transaction, the authorization facts, the append-only audit
//! row, the operation receipt, and the consumption progress. The receipt binds
//! the stable operation identity, the message sequence, the content digests,
//! and the ORIGINAL message boot identity (`origin_boot_id`); the consumer's
//! boot/worker identity travels separately in `applied_by_boot_id`/`worker_id`
//! and never replaces the original binding.
//!
//! Fail-closed rules implemented here:
//!
//! - Dedup: a receipt that already exists with identical identity and digests
//!   short-circuits as [`MemoryV1ApplyOutcome::Duplicate`]; nothing is
//!   re-applied. A receipt with the same identity but different content, or an
//!   operation identifier bound to a different stream position, is a DENY
//!   ([`MemoryV1ApplyDenialReason::ReceiptContentMismatch`]) that stops and
//!   requests reconciliation — a conflicting message is never skipped.
//! - Prefix continuity: the apply-progress tail must be the contiguous
//!   predecessor of this frame (sequence, mutation sequence, previous frame
//!   hash, same stream and epoch). The tail must have been explicitly
//!   pre-seeded ([`initialize_memory_v1_apply_progress`]) and bound to the
//!   stream's genesis anchor; a missing row is never a trusted genesis. A
//!   gap, a foreign stream, or an epoch rollover is a DENY, never a guessed
//!   fast-forward.
//! - Worker fence with explicit tokens: [`claim_memory_v1_apply_lease`] only
//!   takes a never-leased or expired fence row and returns an unfakeable
//!   [`MemoryV1ApplyFenceToken`] (owner + monotonic generation). Every apply,
//!   release, and renewal presents that token; the apply transaction verifies
//!   owner + generation + unexpired together under its row lock, and every
//!   claim/renewal rotates the generation — a stale token, even held by the
//!   same boot/worker, can no longer write or release. A missing, foreign,
//!   stale-generation, or expired fence is a DENY.
//! - DENY has a concrete apply: [`apply_memory_v1_deny_message`] commits the
//!   append-only DENY audit row, its receipt (`outcome = 'DENY'`), and the
//!   progress advance in one transaction. A deny frame never advances the
//!   mutation sequence and never writes authorization facts.
//! - Uncovered inputs are explicit DENYs with no durable write: an ungoverned
//!   context load ([`MemoryV1ApplyDenialReason::MutationKindNotCovered`]), a
//!   non-ALLOW audit on the mutation path, a non-DENY audit on the deny path,
//!   a plan that is not complete, or any fact precondition/cardinality
//!   failure.
//! - Unknown commit: when `COMMIT` itself fails, the durable outcome is
//!   unknowable from the failed connection. The executor immediately runs
//!   [`reconcile_memory_v1_unknown_commit`], which reads — under row locks in
//!   one snapshot — the receipts bound to BOTH unique keys (operation id and
//!   stream position) plus the progress tail (epoch, journal sequence,
//!   mutation sequence, frame hash). `NotApplied` is only reported when the
//!   tail sits exactly on this frame's predecessor with the matching previous
//!   hash; a receipt present with a non-behind tail proves Applied; every
//!   other state — divergent prefix, cross-epoch tail, missing progress row,
//!   or a read failure — reports
//!   [`MemoryV1ApplyReconciliation::Unknown`]. The executor never retries
//!   blindly and never claims the commit failed or succeeded without proof.
//!
//! Every SQL statement in this module tree is a static string with `?`
//! placeholders; values only travel as bound parameters. The candidate tables
//! live in `Docs/sql/memory-v1-apply-candidate.sql`; this crate does not
//! execute DDL and does not adopt the schema automatically. Database rows
//! written here are durable facts and audit evidence — never an ALLOW, never
//! an authorization.

use thiserror::Error;

use astral_types::memory_v1::MemoryId;
use astral_types::memory_v1_audit::{MemoryV1AuditDecision, MemoryV1AuditEvent};

use crate::memory_v1_apply_plan::{MemoryV1ApplyPlan, TableOwner};

mod verified_prefix;

pub use crate::memory_v1_apply_facts::{executor_operation_sequence, TAIL_SEQUENCE};
pub use verified_prefix::{
    verify_memory_v1_applied_prefix_batch, MemoryV1ApplyPrefixError, MEMORY_V1_APPLY_PREFIX_BATCH,
};

/// Maximum stable operation-identifier bytes (matches the journal contract).
pub const MEMORY_V1_APPLY_MAX_OPERATION_ID_BYTES: usize = 64;
/// Maximum worker-identifier bytes.
pub const MEMORY_V1_APPLY_MAX_WORKER_ID_BYTES: usize = 128;
/// Lease time-to-live lower bound, in seconds.
pub const MEMORY_V1_APPLY_MIN_LEASE_TTL_SECONDS: u64 = 1;
/// Lease time-to-live upper bound, in seconds.
pub const MEMORY_V1_APPLY_MAX_LEASE_TTL_SECONDS: u64 = 300;

/// Upper bound for a single denial detail string.
pub const MEMORY_V1_APPLY_MAX_DETAIL_BYTES: usize = 512;

// ─────────────────────────────────────────────────────────────────────────────
// Request identity and lease values
// ─────────────────────────────────────────────────────────────────────────────

/// The journal-frame kind carried by one message identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryV1ApplyFrameKind {
    /// A mutation frame; applies governed facts and advances both sequences.
    Mutation,
    /// A deny frame; applies only the deny audit row and advances the journal
    /// sequence.
    Deny,
}

/// The journal-frame identity of one persisted message to apply.
///
/// Every field is copied from the decoded journal frame, the payload decoder,
/// and the originating boot's message binding; nothing is guessed.
/// `origin_boot_id` is the boot identity under which the message was produced
/// (启动标识 of the producing boot) — the receipt binds it, never the
/// consumer's boot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryV1ApplyIdentity {
    /// Journal stream identifier.
    pub stream_id: MemoryId,
    /// Epoch within the stream.
    pub epoch_id: MemoryId,
    /// One-based journal sequence of this frame.
    pub journal_sequence: u64,
    /// Mutation sequence: the new mutation sequence for a mutation frame, or
    /// the observed authorization-state sequence for a deny frame (zero
    /// refers to the external baseline on genesis denies).
    pub mutation_sequence: u64,
    /// Message identifier inside the frame.
    pub message_id: MemoryId,
    /// Stable operation identifier bound to the mutation and its audit.
    pub operation_id: String,
    /// The ORIGINAL message boot identity (not the consumer's boot).
    pub origin_boot_id: MemoryId,
    /// Request fingerprint from the frame.
    pub request_fingerprint: [u8; 32],
    /// Previous frame hash in the journal chain.
    pub prev_frame_hash: [u8; 32],
    /// This frame's verified digest.
    pub frame_digest: [u8; 32],
    /// Payload content digest supplied by the payload decoder.
    pub payload_digest: [u8; 32],
    /// Frame kind: mutation or deny.
    pub frame_kind: MemoryV1ApplyFrameKind,
}

/// Worker lease input: the boot identity binds the lease to one service boot
/// (the CONSUMER boot; the receipt keeps the original message boot separate);
/// the worker identifier names the applying worker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryV1ApplyLease {
    /// Service boot identifier of the consumer (启动标识).
    pub boot_id: MemoryId,
    /// Bounded worker identity.
    pub worker_id: String,
    /// Requested lease time-to-live in seconds.
    pub lease_ttl_seconds: u64,
}

/// One already-authorized, already-journaled mutation plus its reviewed plan,
/// audit event, and fence token.
#[derive(Clone)]
pub struct MemoryV1ApplyRequest<'a> {
    /// Journal-frame identity of the message (kind must be Mutation).
    pub identity: MemoryV1ApplyIdentity,
    /// The reviewed transaction plan; it must be complete.
    pub plan: MemoryV1ApplyPlan<'a>,
    /// The ALLOW change audit event bound to the mutation.
    pub audit: &'a MemoryV1AuditEvent,
    /// The explicitly claimed fence token (owner + generation + expiry are
    /// verified together under the apply transaction's row lock).
    pub fence: MemoryV1ApplyFenceToken,
}

/// One journaled DENY plus its deny audit event and fence token.
#[derive(Clone)]
pub struct MemoryV1ApplyDenyRequest<'a> {
    /// Journal-frame identity of the message (kind must be Deny).
    pub identity: MemoryV1ApplyIdentity,
    /// The DENY audit event (its change payload may be partial).
    pub audit: &'a MemoryV1AuditEvent,
    /// The explicitly claimed fence token.
    pub fence: MemoryV1ApplyFenceToken,
}

/// The startup-recovery deny-observation request. It references the
/// `astral_types::memory_v1_deny_observation::MemoryV1DenyObservation` value
/// directly — no DB-side observation DTO — and shares the deny apply's
/// transaction and SQL exactly: one code path, no second transaction. The DB
/// encodes the wire itself from the same observation and fills the audit
/// columns from the same value, adding the strict in-transaction check of the
/// ACTUAL predecessor governance sequence supplied by the verified caller.
#[derive(Clone)]
pub struct MemoryV1ApplyDenyObservationRequest<'a> {
    /// Verified journal-frame identity (kind must be Deny).
    pub identity: MemoryV1ApplyIdentity,
    /// The original deny observation value.
    pub observation: &'a astral_types::memory_v1_deny_observation::MemoryV1DenyObservation,
    /// Verified fence token.
    pub fence: MemoryV1ApplyFenceToken,
    /// The caller-verified predecessor governance sequence; the transaction
    /// requires the progress tail to match it exactly.
    pub predecessor: MemoryV1ApplyPredecessor,
}

// memory—v1
fn validate_identity(identity: &MemoryV1ApplyIdentity) -> Result<(), &'static str> {
    let operation_bytes = identity.operation_id.as_bytes();
    if operation_bytes.is_empty()
        || operation_bytes.len() > MEMORY_V1_APPLY_MAX_OPERATION_ID_BYTES
        || !operation_bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/".contains(byte))
    {
        return Err("operation_id must be 1..=64 ASCII [A-Za-z0-9-_.:/] bytes");
    }
    if identity.journal_sequence == 0 {
        return Err("journal_sequence must be >= 1");
    }
    match identity.frame_kind {
        MemoryV1ApplyFrameKind::Mutation => {
            if identity.mutation_sequence == 0 {
                return Err("mutation frames require mutation_sequence >= 1");
            }
        }
        MemoryV1ApplyFrameKind::Deny => {}
    }
    if zero_id(&identity.stream_id)
        || zero_id(&identity.epoch_id)
        || zero_id(&identity.message_id)
        || zero_id(&identity.origin_boot_id)
    {
        return Err("stream_id, epoch_id, message_id and origin_boot_id must be nonzero");
    }
    if identity.prev_frame_hash == [0u8; 32]
        || identity.frame_digest == [0u8; 32]
        || identity.payload_digest == [0u8; 32]
    {
        return Err("prev_frame_hash, frame_digest and payload_digest must be nonzero");
    }
    Ok(())
}

// memory—v1
fn validate_lease(lease: &MemoryV1ApplyLease) -> Result<(), &'static str> {
    if zero_id(&lease.boot_id) {
        return Err("lease boot_id must be nonzero");
    }
    let worker_bytes = lease.worker_id.as_bytes();
    if worker_bytes.is_empty()
        || worker_bytes.len() > MEMORY_V1_APPLY_MAX_WORKER_ID_BYTES
        || !worker_bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:@".contains(byte))
    {
        return Err("worker_id must be 1..=128 ASCII [A-Za-z0-9-_.:@] bytes");
    }
    if lease.lease_ttl_seconds < MEMORY_V1_APPLY_MIN_LEASE_TTL_SECONDS
        || lease.lease_ttl_seconds > MEMORY_V1_APPLY_MAX_LEASE_TTL_SECONDS
    {
        return Err("lease_ttl_seconds is outside the bounded range");
    }
    Ok(())
}

// memory—v1
fn validate_fence_token(token: &MemoryV1ApplyFenceToken) -> Result<(), &'static str> {
    if zero_id(&token.boot_id()) || zero_id(&token.stream_id()) {
        return Err("fence token boot_id and stream_id must be nonzero");
    }
    let worker_bytes = token.worker_id().as_bytes();
    if worker_bytes.is_empty()
        || worker_bytes.len() > MEMORY_V1_APPLY_MAX_WORKER_ID_BYTES
        || !worker_bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:@".contains(byte))
    {
        return Err("fence token worker_id must be 1..=128 ASCII [A-Za-z0-9-_.:@] bytes");
    }
    if token.fence_generation == 0 {
        return Err("fence token generation must be >= 1");
    }
    Ok(())
}

// memory—v1
fn zero_id(id: &MemoryId) -> bool {
    id.as_bytes().iter().all(|byte| *byte == 0)
}

// ─────────────────────────────────────────────────────────────────────────────
// Outcomes, denials, errors
// ─────────────────────────────────────────────────────────────────────────────

/// A fail-closed denial reason. Every denial writes nothing and rolls back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryV1ApplyDenialReason {
    /// The mutation is a service-period context load, which has no governed
    /// apply contract.
    MutationKindNotCovered,
    /// The frame kind does not match the entry point used.
    FrameKindMismatch,
    /// The supplied plan is not structurally complete.
    PlanNotComplete,
    /// The executor's operation sequence disagrees with the reviewed plan.
    PlanOperationMismatch,
    /// The mutation-path audit event is not an ALLOW change record.
    AuditNotAllow,
    /// The deny-path audit event is not a DENY record.
    AuditNotDeny,
    /// The audit operation identifier does not match the frame identity.
    AuditOperationMismatch,
    /// The plan's flow anchor does not match the frame identity.
    FlowAnchorMismatch,
    /// The caller does not hold the apply-fence lease.
    FenceNotHeld,
    /// The caller's lease expired before the apply transaction ran.
    FenceExpired,
    /// The presented fence token carries a stale generation: a newer claim or
    /// renewal rotated the fence, and the old token can no longer write.
    FenceGenerationMismatch,
    /// The presented fence token is bound to a different stream.
    FenceStreamMismatch,
    /// The progress tail is not the contiguous predecessor of this frame.
    ProgressDiscontinuity,
    /// An epoch rollover within a stream is not covered by this slice.
    EpochChangeNotCovered,
    /// A stored receipt conflicts with the supplied identity or digests.
    ReceiptContentMismatch,
    /// A fact precondition failed (absent/extra row, tombstone, window).
    PreconditionFailed,
    /// A write touched a different number of rows than required.
    CardinalityMismatch,
    /// A stored row carried an unexpected shape (status/scope bytes).
    RowShapeUnexpected,
    /// A database error occurred inside the transaction; everything rolled
    /// back and no decision was made.
    InfraFailureRolledBack,
}

impl std::fmt::Display for MemoryV1ApplyDenialReason {
    // memory—v1
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

/// A fail-closed denial with a bounded detail. The transaction is rolled
/// back; no durable state was written by this call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryV1ApplyDenial {
    pub reason: MemoryV1ApplyDenialReason,
    pub detail: String,
}

// memory—v1
impl MemoryV1ApplyDenial {
    // memory—v1
    fn new(reason: MemoryV1ApplyDenialReason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: crate::memory_v1_apply_facts::truncate_detail(detail.into()),
        }
    }
}

/// Evidence for one executed fact operation. Images are canonical JSON values
/// read from the database inside the apply transaction.
#[derive(Clone, Debug, PartialEq)]
pub struct MemoryV1AppliedOperation {
    /// Zero-based transaction order across fact operations.
    pub ordinal: usize,
    /// Logical fact owner from the plan model.
    pub owner: TableOwner,
    /// Operation kind from the plan model.
    pub kind: crate::memory_v1_apply_plan::OperationKind,
    /// Bounded target description (`table:hexid` or `verify:table:hexid`).
    pub target: String,
    /// Exact rows affected by this operation.
    pub rows_affected: u64,
    /// Before image; `None` for inserts and verify-only evidence.
    pub before: Option<serde_json::Value>,
    /// After image; `None` when the operation only verifies.
    pub after: Option<serde_json::Value>,
}

/// The durable apply receipt (in-memory view of the `mv1_apply_receipt`
/// row). Per-operation images are returned only for the freshly applied path;
/// they are not durable in this slice — the durable proof is the receipt row
/// itself.
#[derive(Clone, Debug, PartialEq)]
pub struct MemoryV1ApplyReceipt {
    /// The applied frame identity (as stored, including origin boot).
    pub identity: MemoryV1ApplyIdentity,
    /// Consumer boot identity that applied the message.
    pub applied_by_boot_id: MemoryId,
    /// Consumer worker identity that applied the message.
    pub applied_by_worker: String,
    /// Receipt outcome token ('APPLIED' or 'DENY').
    pub outcome: &'static str,
    /// Number of fact operations recorded by the receipt.
    pub fact_operation_count: u16,
    /// Total fact rows affected recorded by the receipt.
    pub fact_rows_affected_total: u64,
    /// Per-operation evidence for the freshly applied path only.
    pub operations: Option<Vec<MemoryV1AppliedOperation>>,
}

/// The result of one apply attempt.
#[derive(Clone, Debug, PartialEq)]
pub enum MemoryV1ApplyOutcome {
    /// The transaction committed; the receipt row proves the message applied.
    Applied(MemoryV1ApplyReceipt),
    /// An identical receipt already existed; nothing was re-applied.
    Duplicate(MemoryV1ApplyReceipt),
    /// Fail-closed refusal; no durable write happened in this attempt.
    Denied(MemoryV1ApplyDenial),
}

/// The caller-verified predecessor tail values for reconciliation.
///
/// For a mutation frame the predecessor governance sequence is arithmetically
/// derivable (`mutation_sequence - 1`, enforced by apply-time continuity);
/// for a deny frame the observed old sequence never proves the predecessor's
/// tail, so the caller must supply the verified value from its own ordered
/// consumption. Without it, a receipt-less deny cannot be proven either way
/// and stays UNKNOWN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryV1ApplyPredecessor {
    /// Verified mutation sequence of the durable tail immediately before
    /// this frame was (or was not) applied.
    pub mutation_sequence: u64,
}

/// The result of reconciling an unknown commit or an inconsistency.
#[derive(Clone, Debug, PartialEq)]
pub enum MemoryV1ApplyReconciliation {
    /// A stored receipt matches the supplied identity: the message was
    /// applied and must not be re-applied.
    ReceiptMatches(Box<MemoryV1ApplyReceipt>),
    /// No receipt exists for this identity; the original message may be
    /// re-submitted by the caller after its own bounded retry policy.
    NotApplied,
    /// A stored receipt or progress row conflicts with the supplied values:
    /// stop and reconcile by hand; never skip past this position.
    Inconsistent {
        reason: MemoryV1ApplyDenialReason,
        detail: String,
    },
    /// The durable state could not be examined (read failure) or does not
    /// match any provable outcome (divergent prefix): the commit outcome
    /// remains unknowable and needs manual reconciliation.
    Unknown { detail: String },
}

/// Errors raised by the apply facade. Infra errors never masquerade as
/// decisions; unknown commits are explicit and need reconciliation.
#[derive(Debug, Error)]
pub enum MemoryV1ApplyError {
    /// The request failed shape validation before any database access.
    #[error("memory-v1 apply request rejected before any database access: {0}")]
    InvalidRequest(&'static str),
    /// Canonical encoding of the audit row failed; nothing was committed.
    #[error("memory-v1 apply canonical encoding failed: {0}")]
    Encoding(String),
    /// A database access failed. If this happened before `COMMIT`, the
    /// transaction rolled back; after a failed `COMMIT`, run
    /// [`reconcile_memory_v1_unknown_commit`] — do not assume either outcome.
    #[error("memory-v1 apply database access failed: {0}")]
    MySql(#[from] sqlx::Error),
    /// `COMMIT` returned an error (or reconciliation could not prove a
    /// receipt), so the durable outcome remains unknowable. Reconcile with
    /// the original message identity under a bounded budget; never treat this
    /// as failure-to-apply or as success.
    #[error("memory-v1 apply commit outcome is unknown and needs reconciliation: {0}")]
    UnknownCommit(&'static str),
}

// memory—v1
fn denial_outcome(
    reason: MemoryV1ApplyDenialReason,
    detail: impl Into<String>,
) -> MemoryV1ApplyOutcome {
    MemoryV1ApplyOutcome::Denied(MemoryV1ApplyDenial::new(reason, detail))
}

// ─────────────────────────────────────────────────────────────────────────────
// Progress and lease views
// ─────────────────────────────────────────────────────────────────────────────

/// The durable per-stream apply progress tail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryV1ApplyProgressRow {
    /// Epoch recorded at the tail.
    pub epoch_id: MemoryId,
    /// Last applied journal sequence.
    pub last_journal_sequence: u64,
    /// Last applied mutation sequence.
    pub last_mutation_sequence: u64,
    /// Verified frame digest of the last applied frame.
    pub last_frame_hash: [u8; 32],
}

/// The result of an explicit genesis pre-seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryV1ApplyProgressInit {
    /// The pre-seeded genesis row was inserted by this call.
    Initialized,
    /// A pre-seeded genesis row already existed and matches this genesis.
    Verified,
}

/// The unfakeable lease token returned by an explicit claim or renewal.
///
/// The fields are private and there is no public constructor: only this
/// module mints tokens (claim/renewal), so a caller can hold and present one
/// but never fabricate or mutate it. Each token is bound to its `stream_id`;
/// apply, renewal, and release refuse a token whose stream differs — even
/// with an identical owner and generation on the other stream's fence row.
/// Every claim/renewal rotates the generation, so a previously issued token —
/// even held by the same boot/worker — can no longer write or release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryV1ApplyFenceToken {
    /// The stream this token is bound to.
    stream_id: MemoryId,
    /// The claiming boot identity.
    boot_id: MemoryId,
    /// The claiming worker identity.
    worker_id: String,
    /// The monotonic fence generation captured at claim/renewal time.
    fence_generation: u64,
}

impl MemoryV1ApplyFenceToken {
    /// Mint a token; module-private by construction of the private fields.
    // memory—v1
    pub(crate) fn mint(
        stream_id: MemoryId,
        boot_id: MemoryId,
        worker_id: String,
        fence_generation: u64,
    ) -> Self {
        Self {
            stream_id,
            boot_id,
            worker_id,
            fence_generation,
        }
    }

    /// The stream this token is bound to.
    // memory—v1
    pub fn stream_id(&self) -> MemoryId {
        self.stream_id
    }

    /// The claiming boot identity.
    // memory—v1
    pub fn boot_id(&self) -> MemoryId {
        self.boot_id
    }

    /// The claiming worker identity.
    // memory—v1
    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    /// The monotonic fence generation captured at claim/renewal time.
    // memory—v1
    pub fn fence_generation(&self) -> u64 {
        self.fence_generation
    }

    /// Refuse a token whose bound stream differs from the operated stream:
    /// the same owner+generation on another stream's fence row never counts.
    // memory—v1
    pub(crate) fn verify_stream(&self, stream_id: &MemoryId) -> Result<(), &'static str> {
        if self.stream_id != *stream_id {
            return Err(
                "fence token is bound to a different stream; cross-stream presentation is refused",
            );
        }
        Ok(())
    }
}

/// Result of a lease claim attempt. Only a never-leased or expired fence row
/// can be claimed; a live lease must be renewed with its exact token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MemoryV1ApplyLeaseClaim {
    /// The fence row was taken (or re-taken after expiry) by this caller.
    Claimed {
        /// The explicit token to present on every subsequent operation.
        token: MemoryV1ApplyFenceToken,
    },
    /// A live lease is held (by this or another owner).
    NotClaimed {
        owner_boot_id: MemoryId,
        owner_worker_id: String,
    },
}

/// Result of a lease renewal attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MemoryV1ApplyLeaseRenew {
    /// The token was still current; the generation rotated and the expiry
    /// extended. Use the returned token from now on.
    Renewed { token: MemoryV1ApplyFenceToken },
    /// The token was stale, foreign, or already expired; re-claim is required.
    NotRenewed,
}

// ─────────────────────────────────────────────────────────────────────────────
// Public facade
// ─────────────────────────────────────────────────────────────────────────────

/// Apply one authorized journal mutation to MySQL in one all-or-nothing
/// transaction (facts + audit row + receipt + progress).
///
/// See the module documentation for the fail-closed rules. This function never
/// executes DDL and never claims authorization.
pub async fn apply_memory_v1_mutation_message(
    pool: &sqlx::MySqlPool,
    request: MemoryV1ApplyRequest<'_>,
) -> Result<MemoryV1ApplyOutcome, MemoryV1ApplyError> {
    validate_identity(&request.identity).map_err(MemoryV1ApplyError::InvalidRequest)?;
    validate_fence_token(&request.fence).map_err(MemoryV1ApplyError::InvalidRequest)?;
    if let Some(denial) = mutation_preflight_denial(&request) {
        return Ok(MemoryV1ApplyOutcome::Denied(denial));
    }

    let mutation_digest = request
        .plan
        .mutation_digest()
        .expect("preflight requires a complete plan with a mutation digest");
    let canonical_payload =
        crate::memory_v1_apply_records::encode_canonical_audit_payload(request.audit)
            .map_err(|error| MemoryV1ApplyError::Encoding(error.to_string()))?;
    let audit_row_digest = crate::memory_v1_apply_records::audit_row_digest(&canonical_payload);
    let expected = ExpectedDigests {
        payload_digest: request.identity.payload_digest,
        mutation_digest,
        audit_row_digest,
    };

    let mut tx = pool.begin().await?;

    // 1) Worker fence verification under row lock.
    match verify_fence_in_tx(&mut tx, &request.identity.stream_id, &request.fence).await? {
        FenceVerification::Held => {}
        FenceVerification::Expired => {
            return Ok(denial_outcome(
                MemoryV1ApplyDenialReason::FenceExpired,
                "apply lease expired before the transaction verified it",
            ));
        }
        FenceVerification::Missing => {
            return Ok(denial_outcome(
                MemoryV1ApplyDenialReason::FenceNotHeld,
                "no apply-fence row for this stream; claim the lease first",
            ));
        }
        FenceVerification::ForeignOwner => {
            return Ok(denial_outcome(
                MemoryV1ApplyDenialReason::FenceNotHeld,
                "apply-fence row is held by another boot/worker",
            ));
        }
        FenceVerification::GenerationMismatch => {
            return Ok(denial_outcome(
                MemoryV1ApplyDenialReason::FenceGenerationMismatch,
                "the presented fence token carries a stale generation; a newer claim or renewal rotated the fence",
            ));
        }
        FenceVerification::StreamMismatch => {
            return Ok(denial_outcome(
                MemoryV1ApplyDenialReason::FenceStreamMismatch,
                "the presented fence token is bound to a different stream",
            ));
        }
    }

    // 2) Receipt dedup before any fact write.
    if let Some(outcome) =
        check_receipt_dedup_in_tx(&mut tx, &request.identity, Some(&expected)).await?
    {
        return Ok(outcome);
    }

    // 3) Progress continuity (prefix gate).
    if let Some(denial) = check_progress_continuity_in_tx(&mut tx, &request.identity, None).await? {
        return Ok(MemoryV1ApplyOutcome::Denied(denial));
    }

    // 4) Facts: precondition reads, writes, images, rows affected.
    let applied =
        match crate::memory_v1_apply_facts::execute_fact_operations(&mut tx, &request.plan).await {
            Ok(applied) => applied,
            Err(failure) => {
                return Ok(MemoryV1ApplyOutcome::Denied(MemoryV1ApplyDenial {
                    reason: failure.reason,
                    detail: failure.detail,
                }));
            }
        };

    // 5) Append-only audit row.
    if let Some(outcome) = insert_audit_row_in_tx(
        &mut tx,
        &request.identity,
        &crate::memory_v1_apply_records::AuditRowContent::Event(request.audit),
        &canonical_payload,
        audit_row_digest,
    )
    .await?
    {
        return Ok(outcome);
    }

    // 6) Operation receipt. `boot_id` binds the ORIGINAL message boot; the
    // consumer boot/worker identity is recorded separately.
    let receipt_values = crate::memory_v1_apply_records::ReceiptInsertValues {
        applied_by_boot_id: request.fence.boot_id,
        worker_id: request.fence.worker_id.clone(),
        mutation_digest,
        audit_row_digest,
        fact_operation_count: u16::try_from(applied.len())
            .map_err(|_| MemoryV1ApplyError::InvalidRequest("fact operation count exceeds u16"))?,
        fact_rows_affected_total: applied.iter().map(|op| op.rows_affected).sum(),
        outcome: crate::memory_v1_apply_records::ReceiptOutcome::Mutation,
    };
    let receipt_rows = crate::memory_v1_apply_records::insert_receipt_row(
        &mut tx,
        &request.identity,
        &receipt_values,
    )
    .await;
    if let Err(error) = receipt_rows {
        return resolve_insert_conflict(
            pool,
            tx,
            &request.identity,
            Some(MemoryV1ApplyVerifiedFrameContent::Event(request.audit)),
            error,
        )
        .await;
    }

    // 7) Progress advance (contiguous CAS or genesis insert).
    let advanced =
        crate::memory_v1_apply_records::advance_progress_mutation_row(&mut tx, &request.identity)
            .await?;
    if advanced != 1 {
        return Ok(denial_outcome(
            MemoryV1ApplyDenialReason::ProgressDiscontinuity,
            "progress advance did not move exactly one tail row",
        ));
    }

    // 8) Commit. A failed commit leaves the durable outcome unknowable from
    // this connection: reconcile on a fresh connection before answering.
    if let Err(commit_error) = tx.commit().await {
        tracing::warn!(
            operation_id = %request.identity.operation_id,
            journal_sequence = request.identity.journal_sequence,
            error = %commit_error,
            "memory-v1 apply commit failed; reconciling on a fresh connection"
        );
        return reconcile_after_commit_failure(
            pool,
            request.identity,
            Some(MemoryV1ApplyVerifiedFrameContent::Event(request.audit)),
        )
        .await;
    }

    Ok(MemoryV1ApplyOutcome::Applied(MemoryV1ApplyReceipt {
        identity: request.identity,
        applied_by_boot_id: request.fence.boot_id,
        applied_by_worker: request.fence.worker_id,
        outcome: "APPLIED",
        fact_operation_count: receipt_values.fact_operation_count,
        fact_rows_affected_total: receipt_values.fact_rows_affected_total,
        operations: Some(applied),
    }))
}

/// Apply one journaled DENY to MySQL in one all-or-nothing transaction
/// (append-only deny audit row + receipt + progress advance; no facts, no
/// mutation-sequence advance).
///
/// The deny path gives every persisted deny frame a concrete database apply
/// (全新数据库设计 §7 item 10): the audit row records the frozen decision
/// token and every observed fact the value carries; unobserved facts stay
/// `null` rather than invented.
pub async fn apply_memory_v1_deny_message(
    pool: &sqlx::MySqlPool,
    request: MemoryV1ApplyDenyRequest<'_>,
) -> Result<MemoryV1ApplyOutcome, MemoryV1ApplyError> {
    validate_identity(&request.identity).map_err(MemoryV1ApplyError::InvalidRequest)?;
    validate_fence_token(&request.fence).map_err(MemoryV1ApplyError::InvalidRequest)?;
    if let Some(denial) = deny_preflight_denial(&request) {
        return Ok(MemoryV1ApplyOutcome::Denied(denial));
    }

    let canonical_payload =
        crate::memory_v1_apply_records::encode_canonical_audit_payload(request.audit)
            .map_err(|error| MemoryV1ApplyError::Encoding(error.to_string()))?;
    deny_apply_transaction(
        pool,
        DenyApplyCore {
            identity: request.identity,
            content: crate::memory_v1_apply_records::AuditRowContent::Event(request.audit),
            canonical_payload,
            fence: request.fence,
            strict_predecessor_mutation: None,
        },
    )
    .await
}

/// Consume one original deny observation for the startup-recovery worker.
///
/// This shares the deny apply's transaction and SQL exactly — one code path,
/// no second transaction implementation. The observation's complete value is
/// preserved in the append-only audit row (actor user and identity card, root
/// observation, frozen deny source, reason code, resource/action, engine
/// trusted time, nullable target, binding confirmations and batch), and its
/// exact canonical wire bytes travel as lowercase hex inside the canonical
/// JSON. The engine-supplied time stays the judgment time; the row's
/// `created_at` is server bookkeeping, never a substitute trusted time.
///
/// The transaction strictly checks the ACTUAL predecessor governance
/// sequence: the progress tail must match `request.predecessor` exactly.
pub async fn apply_memory_v1_deny_observation(
    pool: &sqlx::MySqlPool,
    request: MemoryV1ApplyDenyObservationRequest<'_>,
) -> Result<MemoryV1ApplyOutcome, MemoryV1ApplyError> {
    validate_identity(&request.identity).map_err(MemoryV1ApplyError::InvalidRequest)?;
    validate_fence_token(&request.fence).map_err(MemoryV1ApplyError::InvalidRequest)?;
    if request.identity.frame_kind != MemoryV1ApplyFrameKind::Deny {
        return Ok(denial_outcome(
            MemoryV1ApplyDenialReason::FrameKindMismatch,
            "the deny-observation entry point requires a Deny frame identity",
        ));
    }

    let canonical_payload =
        crate::memory_v1_apply_records::encode_canonical_deny_observation_payload(
            request.observation,
        )
        .map_err(|error| MemoryV1ApplyError::Encoding(error.to_string()))?;
    deny_apply_transaction(
        pool,
        DenyApplyCore {
            identity: request.identity,
            content: crate::memory_v1_apply_records::AuditRowContent::DenyObservation(
                request.observation,
            ),
            canonical_payload,
            fence: request.fence,
            strict_predecessor_mutation: Some(request.predecessor.mutation_sequence),
        },
    )
    .await
}

/// The shared deny-apply transaction core: fence verification, dedup,
/// strict-or-legacy continuity, append-only audit row, deny receipt, progress
/// advance, and unknown-commit reconciliation. Both deny entry points run
/// through this single transaction implementation.
struct DenyApplyCore<'a> {
    identity: MemoryV1ApplyIdentity,
    content: crate::memory_v1_apply_records::AuditRowContent<'a>,
    canonical_payload: Vec<u8>,
    fence: MemoryV1ApplyFenceToken,
    strict_predecessor_mutation: Option<u64>,
}

// memory—v1
async fn deny_apply_transaction(
    pool: &sqlx::MySqlPool,
    core: DenyApplyCore<'_>,
) -> Result<MemoryV1ApplyOutcome, MemoryV1ApplyError> {
    let identity = &core.identity;
    let audit_row_digest =
        crate::memory_v1_apply_records::audit_row_digest(&core.canonical_payload);
    let expected = ExpectedDigests {
        payload_digest: identity.payload_digest,
        // A deny frame carries no governed mutation; the zero digest marks
        // "no mutation content" in the receipt.
        mutation_digest: [0u8; 32],
        audit_row_digest,
    };

    let mut tx = pool.begin().await?;

    match verify_fence_in_tx(&mut tx, &identity.stream_id, &core.fence).await? {
        FenceVerification::Held => {}
        FenceVerification::Expired => {
            return Ok(denial_outcome(
                MemoryV1ApplyDenialReason::FenceExpired,
                "apply lease expired before the transaction verified it",
            ));
        }
        FenceVerification::Missing => {
            return Ok(denial_outcome(
                MemoryV1ApplyDenialReason::FenceNotHeld,
                "no apply-fence row for this stream; claim the lease first",
            ));
        }
        FenceVerification::ForeignOwner => {
            return Ok(denial_outcome(
                MemoryV1ApplyDenialReason::FenceNotHeld,
                "apply-fence row is held by another boot/worker",
            ));
        }
        FenceVerification::GenerationMismatch => {
            return Ok(denial_outcome(
                MemoryV1ApplyDenialReason::FenceGenerationMismatch,
                "the presented fence token carries a stale generation; a newer claim or renewal rotated the fence",
            ));
        }
        FenceVerification::StreamMismatch => {
            return Ok(denial_outcome(
                MemoryV1ApplyDenialReason::FenceStreamMismatch,
                "the presented fence token is bound to a different stream",
            ));
        }
    }

    if let Some(outcome) = check_receipt_dedup_in_tx(&mut tx, identity, Some(&expected)).await? {
        return Ok(outcome);
    }
    if let Some(denial) =
        check_progress_continuity_in_tx(&mut tx, identity, core.strict_predecessor_mutation).await?
    {
        return Ok(MemoryV1ApplyOutcome::Denied(denial));
    }

    if let Some(outcome) = insert_audit_row_in_tx(
        &mut tx,
        identity,
        &core.content,
        &core.canonical_payload,
        audit_row_digest,
    )
    .await?
    {
        return Ok(outcome);
    }

    let receipt_values = crate::memory_v1_apply_records::ReceiptInsertValues {
        applied_by_boot_id: core.fence.boot_id,
        worker_id: core.fence.worker_id.clone(),
        mutation_digest: [0u8; 32],
        audit_row_digest,
        fact_operation_count: 0,
        fact_rows_affected_total: 0,
        outcome: crate::memory_v1_apply_records::ReceiptOutcome::Deny,
    };
    let receipt_rows =
        crate::memory_v1_apply_records::insert_receipt_row(&mut tx, identity, &receipt_values)
            .await;
    if let Err(error) = receipt_rows {
        return resolve_insert_conflict(
            pool,
            tx,
            identity,
            verified_from_content(&core.content),
            error,
        )
        .await;
    }

    let advanced =
        crate::memory_v1_apply_records::advance_progress_deny_row(&mut tx, identity).await?;
    if advanced != 1 {
        return Ok(denial_outcome(
            MemoryV1ApplyDenialReason::ProgressDiscontinuity,
            "deny progress advance did not move exactly one tail row",
        ));
    }

    if let Err(commit_error) = tx.commit().await {
        tracing::warn!(
            operation_id = %identity.operation_id,
            journal_sequence = identity.journal_sequence,
            error = %commit_error,
            "memory-v1 deny apply commit failed; reconciling on a fresh connection"
        );
        return reconcile_after_commit_failure(
            pool,
            identity.clone(),
            verified_from_content(&core.content),
        )
        .await;
    }

    Ok(MemoryV1ApplyOutcome::Applied(MemoryV1ApplyReceipt {
        identity: identity.clone(),
        applied_by_boot_id: core.fence.boot_id,
        applied_by_worker: core.fence.worker_id,
        outcome: "DENY",
        fact_operation_count: 0,
        fact_rows_affected_total: 0,
        operations: None,
    }))
}

/// The caller-verified frame content for exact audit-row verification.
///
/// Per-frame recovery has already decoded the message it replays, so it can
/// supply the exact value whose canonical bytes the apply transaction wrote.
/// The executor re-encodes it, recomputes the audit-row digest, and compares
/// it with the stored audit row — actual content matching, never mere row
/// existence. Without this input an `Applied` answer is not provable and
/// stays UNKNOWN.
#[derive(Clone)]
pub enum MemoryV1ApplyVerifiedFrameContent<'a> {
    /// The structured audit event whose canonical bytes were written.
    Event(&'a MemoryV1AuditEvent),
    /// The original deny observation (`astral_types` value) whose canonical
    /// bytes — including the DB-encoded wire hex — were written.
    DenyObservation(&'a astral_types::memory_v1_deny_observation::MemoryV1DenyObservation),
}

/// The reconciliation input for one message identity.
#[derive(Clone)]
pub struct MemoryV1ApplyReconciliationInput<'a> {
    /// The verified journal-frame identity.
    pub identity: MemoryV1ApplyIdentity,
    /// The caller-verified predecessor governance sequence. Required to
    /// prove `NotApplied` for a deny frame; for a mutation frame it must
    /// equal `mutation_sequence - 1` when supplied.
    pub predecessor: Option<MemoryV1ApplyPredecessor>,
    /// The caller-verified frame content for exact audit-row content
    /// verification. Required to prove `Applied`.
    pub verified_content: Option<MemoryV1ApplyVerifiedFrameContent<'a>>,
}

/// Reconcile an unknown commit result for one message identity.
///
/// Opens a fresh transaction (never reuses the connection whose commit
/// failed) and reads — in ONE merged locked query — the receipt matched by
/// EITHER unique key together with its independent append-only audit row,
/// plus the progress tail (epoch, journal sequence, mutation sequence, frame
/// hash): two locked round trips per frame total. The decision requires:
/// both receipt keys agreeing, the receipt outcome token matching the frame
/// kind, the audit row present with its columns and content digest verified
/// against the verified frame (by re-encoding the supplied
/// [`MemoryV1ApplyVerifiedFrameContent`]), and the tail checks — for a
/// historical deny at the frame position, the EXACT verified predecessor
/// governance sequence. Any state outside the provable matrix — including
/// read failures or missing verified content — returns
/// [`MemoryV1ApplyReconciliation::Unknown`] instead of a guess.
pub async fn reconcile_memory_v1_unknown_commit(
    pool: &sqlx::MySqlPool,
    input: MemoryV1ApplyReconciliationInput<'_>,
) -> Result<MemoryV1ApplyReconciliation, MemoryV1ApplyError> {
    let identity = &input.identity;
    validate_identity(identity).map_err(MemoryV1ApplyError::InvalidRequest)?;
    let mut tx = pool.begin().await?;
    let receipt_rows = match crate::memory_v1_apply_records::read_receipts_with_audit_for_update(
        &mut tx,
        &identity.operation_id,
        &identity.stream_id,
        identity.journal_sequence,
    )
    .await
    {
        Ok(rows) => rows,
        Err(error) => {
            drop(tx);
            return Ok(MemoryV1ApplyReconciliation::Unknown {
                detail: format!("merged receipt/audit lookup failed: {error}"),
            });
        }
    };
    let progress = match crate::memory_v1_apply_records::read_progress_for_update(
        &mut tx,
        &identity.stream_id,
    )
    .await
    {
        Ok(row) => row,
        Err(error) => {
            drop(tx);
            return Ok(MemoryV1ApplyReconciliation::Unknown {
                detail: format!("progress lookup failed: {error}"),
            });
        }
    };
    if let Err(error) = tx.commit().await {
        return Ok(MemoryV1ApplyReconciliation::Unknown {
            detail: format!("reconciliation snapshot could not be finalized: {error}"),
        });
    }
    Ok(reconcile_decision(
        &receipt_rows,
        progress.as_ref(),
        identity,
        input.predecessor.as_ref(),
        input.verified_content.as_ref(),
    ))
}

/// The pure reconciliation decision matrix over one merged locked snapshot.
///
/// - An `Applied` proof requires: exactly one receipt row matched by BOTH
///   unique keys agreeing on the same operation, the receipt outcome token
///   matching the frame kind, the content digests matching the identity, the
///   independent append-only audit row present with its columns and content
///   digest verified against the supplied frame content (re-encoded and
///   compared — never mere row existence), and the progress tail checks. For
///   a historical deny at the frame position the tail must carry the EXACT
///   verified predecessor governance sequence.
/// - A `NotApplied` proof requires no receipt on either key and a tail
///   exactly on the predecessor (same epoch, matching previous hash, and the
///   verified predecessor governance sequence; a deny frame's own observed
///   old sequence never guesses its predecessor).
/// - Everything else reports [`Unknown`] or [`Inconsistent`].
// memory—v1
pub(crate) fn reconcile_decision(
    rows: &[crate::memory_v1_apply_records::ReceiptAuditJoinedRow],
    progress: Option<&crate::memory_v1_apply_records::ProgressTailRow>,
    identity: &MemoryV1ApplyIdentity,
    predecessor: Option<&MemoryV1ApplyPredecessor>,
    verified_content: Option<&MemoryV1ApplyVerifiedFrameContent<'_>>,
) -> MemoryV1ApplyReconciliation {
    let mut by_operation: Option<&crate::memory_v1_apply_records::ReceiptAuditJoinedRow> = None;
    let mut by_position: Option<&crate::memory_v1_apply_records::ReceiptAuditJoinedRow> = None;
    for row in rows {
        if row.matched_by_operation() {
            by_operation = Some(row);
        }
        if row.matched_by_position() {
            by_position = Some(row);
        }
    }

    if let Some(receipt_row) = by_operation {
        let receipt = &receipt_row.receipt;
        if receipt.stream_id != identity.stream_id.as_bytes().to_vec()
            || receipt.journal_sequence != identity.journal_sequence
        {
            return MemoryV1ApplyReconciliation::Inconsistent {
                reason: MemoryV1ApplyDenialReason::ReceiptContentMismatch,
                detail: "stored receipt binds the operation id to a different stream position"
                    .into(),
            };
        }
        // Both unique keys must agree before any applied proof: one receipt
        // row is written with both keys in the same transaction, so a
        // key-visible/other-key-invisible state is a storage anomaly.
        let Some(position_row) = by_position else {
            return MemoryV1ApplyReconciliation::Inconsistent {
                reason: MemoryV1ApplyDenialReason::ReceiptContentMismatch,
                detail: "operation-key receipt exists but the stream-position key finds none"
                    .into(),
            };
        };
        if position_row.receipt.operation_id != receipt.operation_id {
            return MemoryV1ApplyReconciliation::Inconsistent {
                reason: MemoryV1ApplyDenialReason::ReceiptContentMismatch,
                detail: "the two receipt unique keys bind different operations".into(),
            };
        }
        if let Err(detail) = compare_receipt(receipt, identity, None) {
            return MemoryV1ApplyReconciliation::Inconsistent {
                reason: MemoryV1ApplyDenialReason::ReceiptContentMismatch,
                detail: format!("stored receipt conflicts with the message: {detail}"),
            };
        }
        // The receipt outcome token must match the frame kind: the two
        // write paths record 'APPLIED' for mutation frames and 'DENY' for
        // deny frames; a cross-kind receipt is a storage anomaly.
        let expected_outcome = match identity.frame_kind {
            MemoryV1ApplyFrameKind::Mutation => "APPLIED",
            MemoryV1ApplyFrameKind::Deny => "DENY",
        };
        if receipt.outcome != expected_outcome {
            return MemoryV1ApplyReconciliation::Inconsistent {
                reason: MemoryV1ApplyDenialReason::ReceiptContentMismatch,
                detail: format!(
                    "stored receipt outcome {} does not match the frame kind {expected_outcome}",
                    receipt.outcome
                ),
            };
        }

        // The independent append-only audit row must exist and match the
        // verified frame by its columns and its actual content.
        if receipt_row.audit_row_digest_value.is_none()
            || receipt_row.audit_canonical_payload.is_none()
        {
            return MemoryV1ApplyReconciliation::Inconsistent {
                reason: MemoryV1ApplyDenialReason::ReceiptContentMismatch,
                detail:
                    "stored receipt exists but its independent append-only audit row is missing"
                        .into(),
            };
        }
        let Some(audit_decision) = receipt_row.audit_decision.as_ref() else {
            return MemoryV1ApplyReconciliation::Inconsistent {
                reason: MemoryV1ApplyDenialReason::ReceiptContentMismatch,
                detail: "stored receipt exists but its audit row decision is missing".into(),
            };
        };
        let expected_decision = match identity.frame_kind {
            MemoryV1ApplyFrameKind::Mutation => "ALLOW",
            MemoryV1ApplyFrameKind::Deny => "DENY",
        };
        if !audit_decision.starts_with(expected_decision) {
            return MemoryV1ApplyReconciliation::Inconsistent {
                reason: MemoryV1ApplyDenialReason::ReceiptContentMismatch,
                detail: format!(
                    "audit row decision {audit_decision} does not match the frame kind {expected_decision}"
                ),
            };
        }
        let audit_checks: [(&str, bool); 5] = [
            (
                "epoch_id",
                receipt_row.audit_epoch_id.as_ref() == Some(&identity.epoch_id.as_bytes().to_vec()),
            ),
            (
                "journal_sequence",
                receipt_row.audit_journal_sequence == Some(identity.journal_sequence),
            ),
            (
                "mutation_sequence",
                receipt_row.audit_mutation_sequence == Some(identity.mutation_sequence),
            ),
            (
                "message_id",
                receipt_row.audit_message_id.as_ref()
                    == Some(&identity.message_id.as_bytes().to_vec()),
            ),
            (
                "operation_id",
                receipt_row.audit_operation_id.as_deref() == Some(identity.operation_id.as_str()),
            ),
        ];
        for (field, matches) in audit_checks {
            if !matches {
                return MemoryV1ApplyReconciliation::Inconsistent {
                    reason: MemoryV1ApplyDenialReason::ReceiptContentMismatch,
                    detail: format!("audit row {field} does not match the verified frame"),
                };
            }
        }
        // Exact content verification: re-encode the caller-verified frame
        // content and compare its recomputed digest with the stored row, and
        // recompute the digest from the STORED canonical payload bytes so a
        // digest column that stayed constant across corrupted content is
        // still refused.
        let Some(verified_content) = verified_content else {
            return MemoryV1ApplyReconciliation::Unknown {
                detail: "the audit row matches the verified frame identity but no verified frame content was supplied; exact content verification is impossible".into(),
            };
        };
        let expected_audit_digest = match verified_content {
            MemoryV1ApplyVerifiedFrameContent::Event(event) => {
                // An event is a valid content source for BOTH write paths
                // (mutation apply and structured deny apply); the audit row's
                // decision token already pins the kind.
                match crate::memory_v1_apply_records::encode_canonical_audit_payload(event) {
                    Ok(payload) => crate::memory_v1_apply_records::audit_row_digest(&payload),
                    Err(error) => {
                        return MemoryV1ApplyReconciliation::Inconsistent {
                            reason: MemoryV1ApplyDenialReason::ReceiptContentMismatch,
                            detail: format!(
                                "the supplied verified event content cannot be re-encoded: {error}"
                            ),
                        };
                    }
                }
            }
            MemoryV1ApplyVerifiedFrameContent::DenyObservation(observation) => {
                if identity.frame_kind != MemoryV1ApplyFrameKind::Deny {
                    return MemoryV1ApplyReconciliation::Inconsistent {
                        reason: MemoryV1ApplyDenialReason::ReceiptContentMismatch,
                        detail:
                            "supplied observation content contradicts a mutation frame identity"
                                .into(),
                    };
                }
                match crate::memory_v1_apply_records::encode_canonical_deny_observation_payload(
                    observation,
                ) {
                    Ok(payload) => crate::memory_v1_apply_records::audit_row_digest(&payload),
                    Err(error) => {
                        return MemoryV1ApplyReconciliation::Inconsistent {
                            reason: MemoryV1ApplyDenialReason::ReceiptContentMismatch,
                            detail: format!(
                                "the supplied verified observation content cannot be re-encoded: {error}"
                            ),
                        };
                    }
                }
            }
        };
        if let Err(detail) = verify_audit_row_content(receipt_row, Some(&expected_audit_digest)) {
            return MemoryV1ApplyReconciliation::Inconsistent {
                reason: MemoryV1ApplyDenialReason::ReceiptContentMismatch,
                detail,
            };
        }

        let Some(tail) = progress else {
            return MemoryV1ApplyReconciliation::Inconsistent {
                reason: MemoryV1ApplyDenialReason::ReceiptContentMismatch,
                detail: "stored receipt exists but the progress tail is missing".into(),
            };
        };
        if tail.epoch_id != identity.epoch_id.as_bytes().to_vec() {
            return MemoryV1ApplyReconciliation::Inconsistent {
                reason: MemoryV1ApplyDenialReason::ReceiptContentMismatch,
                detail: "progress tail belongs to a different epoch than the receipted frame"
                    .into(),
            };
        }
        if tail.last_journal_sequence < identity.journal_sequence {
            return MemoryV1ApplyReconciliation::Inconsistent {
                reason: MemoryV1ApplyDenialReason::ReceiptContentMismatch,
                detail: format!(
                    "progress tail journal sequence {} is behind the receipted frame {}",
                    tail.last_journal_sequence, identity.journal_sequence
                ),
            };
        }
        if tail.last_journal_sequence == identity.journal_sequence {
            if tail.last_frame_hash != identity.frame_digest.to_vec() {
                return MemoryV1ApplyReconciliation::Inconsistent {
                    reason: MemoryV1ApplyDenialReason::ReceiptContentMismatch,
                    detail: "progress tail frame hash does not match the receipted frame".into(),
                };
            }
            match identity.frame_kind {
                MemoryV1ApplyFrameKind::Mutation => {
                    if tail.last_mutation_sequence != identity.mutation_sequence {
                        return MemoryV1ApplyReconciliation::Inconsistent {
                            reason: MemoryV1ApplyDenialReason::ReceiptContentMismatch,
                            detail:
                                "progress tail mutation sequence does not match the receipted frame"
                                    .into(),
                        };
                    }
                }
                // A historical deny did not advance the governance sequence:
                // with a verified predecessor the tail must carry EXACTLY the
                // predecessor governance position; without one the exact
                // position is unprovable.
                MemoryV1ApplyFrameKind::Deny => {
                    let Some(predecessor) = predecessor else {
                        return MemoryV1ApplyReconciliation::Unknown {
                            detail: "the deny tail sits at the frame position but no verified predecessor governance sequence was supplied; the exact governance position is unprovable".into(),
                        };
                    };
                    if tail.last_mutation_sequence != predecessor.mutation_sequence {
                        return MemoryV1ApplyReconciliation::Inconsistent {
                            reason: MemoryV1ApplyDenialReason::ReceiptContentMismatch,
                            detail: format!(
                                "deny tail governance sequence {} does not match the verified predecessor {}",
                                tail.last_mutation_sequence, predecessor.mutation_sequence
                            ),
                        };
                    }
                }
            }
        }
        // A tail at or beyond the receipted frame with matching content: the
        // receipt row is the transaction-completion proof.
        return MemoryV1ApplyReconciliation::ReceiptMatches(Box::new(receipt_view(receipt, None)));
    }
    if let Some(receipt_row) = by_position {
        return MemoryV1ApplyReconciliation::Inconsistent {
            reason: MemoryV1ApplyDenialReason::ReceiptContentMismatch,
            detail: format!(
                "stream position holds a receipt for a different operation: {}",
                receipt_row.receipt.operation_id
            ),
        };
    }
    // No receipt on either unique key: the frame can only be proven
    // not-applied when the progress tail sits exactly on the predecessor —
    // journal sequence minus one, matching previous hash, AND the verified
    // predecessor governance sequence bound into the reconciliation input.
    let Some(tail) = progress else {
        return MemoryV1ApplyReconciliation::Unknown {
            detail: "no receipt on either unique key and no pre-seeded progress row; the stream state cannot prove the outcome".into(),
        };
    };
    if tail.epoch_id != identity.epoch_id.as_bytes().to_vec() {
        return MemoryV1ApplyReconciliation::Unknown {
            detail: "progress tail belongs to a different epoch; epoch rollover is not covered"
                .into(),
        };
    }
    if tail.last_journal_sequence >= identity.journal_sequence {
        return MemoryV1ApplyReconciliation::Inconsistent {
            reason: MemoryV1ApplyDenialReason::ReceiptContentMismatch,
            detail: format!(
                "no receipt exists but the progress tail journal sequence {} is at or beyond this frame {}",
                tail.last_journal_sequence, identity.journal_sequence
            ),
        };
    }
    let at_predecessor_position = tail.last_journal_sequence == identity.journal_sequence - 1
        && tail.last_frame_hash == identity.prev_frame_hash.to_vec();
    if !at_predecessor_position {
        return MemoryV1ApplyReconciliation::Unknown {
            detail: format!(
                "no receipt exists and the progress tail journal sequence {} does not sit on this frame's predecessor with the matching hash",
                tail.last_journal_sequence
            ),
        };
    }
    // The predecessor governance sequence must be proven, never guessed:
    // mutation frames derive it arithmetically; deny frames observe an old
    // sequence that says nothing about the tail, so only a caller-verified
    // value can complete the NotApplied proof.
    let expected_predecessor_mutation = match identity.frame_kind {
        MemoryV1ApplyFrameKind::Mutation => {
            if let Some(supplied) = predecessor {
                if supplied.mutation_sequence != identity.mutation_sequence - 1 {
                    return MemoryV1ApplyReconciliation::Inconsistent {
                        reason: MemoryV1ApplyDenialReason::ReceiptContentMismatch,
                        detail: "the supplied predecessor governance sequence contradicts the mutation frame's own sequence".into(),
                    };
                }
            }
            Some(identity.mutation_sequence - 1)
        }
        MemoryV1ApplyFrameKind::Deny => predecessor.map(|supplied| supplied.mutation_sequence),
    };
    let Some(expected_predecessor_mutation) = expected_predecessor_mutation else {
        return MemoryV1ApplyReconciliation::Unknown {
            detail: "no receipt exists and no verified predecessor governance sequence was supplied; a deny frame's observed old sequence never proves its predecessor".into(),
        };
    };
    if tail.last_mutation_sequence == expected_predecessor_mutation {
        return MemoryV1ApplyReconciliation::NotApplied;
    }
    MemoryV1ApplyReconciliation::Unknown {
        detail: format!(
            "no receipt exists and the predecessor tail governance sequence {} does not match the verified predecessor {}",
            tail.last_mutation_sequence, expected_predecessor_mutation
        ),
    }
}

/// Read the current durable apply-progress tail for one stream.
///
/// A missing row means no frame of this stream has been applied by this
/// executor; it is not evidence that the stream is empty.
pub async fn read_memory_v1_apply_progress(
    pool: &sqlx::MySqlPool,
    stream_id: MemoryId,
) -> Result<Option<MemoryV1ApplyProgressRow>, MemoryV1ApplyError> {
    let mut connection = pool.acquire().await?;
    crate::memory_v1_apply_records::read_progress_row(&mut *connection, &stream_id)
        .await
        .map_err(Into::into)
}

/// Explicitly pre-seed the per-stream apply progress tail, binding it to the
/// stream's genesis anchor.
///
/// The wiring side derives stream/epoch/genesis from the installation
/// identity at boot and calls this before any frame of the stream is applied.
/// A missing row is never accepted as a trusted genesis during apply: the
/// executor requires this pre-seeded row and verifies the first frame's
/// previous hash against the genesis anchor. Idempotent: re-initializing
/// with the same genesis verifies the existing row and reports
/// [`MemoryV1ApplyProgressInit::Verified`]; a disagreeing row is an error.
pub async fn initialize_memory_v1_apply_progress(
    pool: &sqlx::MySqlPool,
    stream_id: MemoryId,
    epoch_id: MemoryId,
    genesis_hash: [u8; 32],
) -> Result<MemoryV1ApplyProgressInit, MemoryV1ApplyError> {
    if zero_id(&stream_id) || zero_id(&epoch_id) {
        return Err(MemoryV1ApplyError::InvalidRequest(
            "stream_id and epoch_id must be nonzero",
        ));
    }
    if genesis_hash == [0u8; 32] {
        return Err(MemoryV1ApplyError::InvalidRequest(
            "genesis_hash must be nonzero",
        ));
    }
    let mut connection = pool.acquire().await?;
    let inserted = crate::memory_v1_apply_records::preseed_progress_row(
        &mut connection,
        &stream_id,
        &epoch_id,
        genesis_hash,
    )
    .await?;
    Ok(if inserted {
        MemoryV1ApplyProgressInit::Initialized
    } else {
        MemoryV1ApplyProgressInit::Verified
    })
}

/// Claim the per-stream apply-fence lease.
///
/// Only a never-leased or expired fence row can be claimed: the CAS update
/// matches `lease_expires_at IS NULL OR <= UTC_TIMESTAMP(6)` exclusively, so a
/// live lease — even held by the same boot/worker — can never be re-claimed
/// without its current generation token (renew it instead). A successful
/// claim rotates the monotonic generation and returns the explicit token
/// that every subsequent apply/release/renewal must present.
pub async fn claim_memory_v1_apply_lease(
    pool: &sqlx::MySqlPool,
    lease: &MemoryV1ApplyLease,
    stream_id: MemoryId,
) -> Result<MemoryV1ApplyLeaseClaim, MemoryV1ApplyError> {
    validate_lease(lease).map_err(MemoryV1ApplyError::InvalidRequest)?;
    if zero_id(&stream_id) {
        return Err(MemoryV1ApplyError::InvalidRequest(
            "stream_id must be nonzero",
        ));
    }
    let mut connection = pool.acquire().await?;
    crate::memory_v1_apply_records::claim_lease(&mut connection, lease, &stream_id)
        .await
        .map_err(Into::into)
}

/// Renew the per-stream apply-fence lease with the exact current token.
///
/// The CAS update matches owner + generation + unexpired together; success
/// rotates the generation and returns the new token. Every previously issued
/// token for this stream is invalidated immediately, so a stale token — even
/// from the same boot/worker — can no longer apply, release, or renew.
pub async fn renew_memory_v1_apply_lease(
    pool: &sqlx::MySqlPool,
    token: &MemoryV1ApplyFenceToken,
    stream_id: MemoryId,
    lease_ttl_seconds: u64,
) -> Result<MemoryV1ApplyLeaseRenew, MemoryV1ApplyError> {
    validate_fence_token(token).map_err(MemoryV1ApplyError::InvalidRequest)?;
    token
        .verify_stream(&stream_id)
        .map_err(MemoryV1ApplyError::InvalidRequest)?;
    if !(MEMORY_V1_APPLY_MIN_LEASE_TTL_SECONDS..=MEMORY_V1_APPLY_MAX_LEASE_TTL_SECONDS)
        .contains(&lease_ttl_seconds)
    {
        return Err(MemoryV1ApplyError::InvalidRequest(
            "lease_ttl_seconds is outside the bounded range",
        ));
    }
    if zero_id(&stream_id) {
        return Err(MemoryV1ApplyError::InvalidRequest(
            "stream_id must be nonzero",
        ));
    }
    let mut connection = pool.acquire().await?;
    crate::memory_v1_apply_records::renew_lease(
        &mut connection,
        token,
        &stream_id,
        lease_ttl_seconds,
    )
    .await
    .map_err(Into::into)
}

/// Release the per-stream apply-fence lease held by the presented token.
///
/// The CAS update matches owner + generation + unexpired together. Returns
/// the rows affected: `1` only for the exact current live token; `0` for a
/// stale, foreign, or expired token (it can no longer act on the fence).
pub async fn release_memory_v1_apply_lease(
    pool: &sqlx::MySqlPool,
    token: &MemoryV1ApplyFenceToken,
    stream_id: MemoryId,
) -> Result<u64, MemoryV1ApplyError> {
    validate_fence_token(token).map_err(MemoryV1ApplyError::InvalidRequest)?;
    token
        .verify_stream(&stream_id)
        .map_err(MemoryV1ApplyError::InvalidRequest)?;
    if zero_id(&stream_id) {
        return Err(MemoryV1ApplyError::InvalidRequest(
            "stream_id must be nonzero",
        ));
    }
    let mut connection = pool.acquire().await?;
    crate::memory_v1_apply_records::release_lease(&mut connection, token, &stream_id)
        .await
        .map_err(Into::into)
}

// ─────────────────────────────────────────────────────────────────────────────
// Preflight (no database access; fail-closed DENYs)
// ─────────────────────────────────────────────────────────────────────────────

// memory—v1
fn mutation_preflight_denial(request: &MemoryV1ApplyRequest<'_>) -> Option<MemoryV1ApplyDenial> {
    if request.identity.frame_kind != MemoryV1ApplyFrameKind::Mutation {
        return Some(MemoryV1ApplyDenial::new(
            MemoryV1ApplyDenialReason::FrameKindMismatch,
            "the mutation entry point requires a Mutation frame identity",
        ));
    }
    if request.plan.kind().is_none() {
        return Some(MemoryV1ApplyDenial::new(
            MemoryV1ApplyDenialReason::MutationKindNotCovered,
            "context load has no governed apply contract",
        ));
    }
    if request.audit.decision() != MemoryV1AuditDecision::Allow {
        return Some(MemoryV1ApplyDenial::new(
            MemoryV1ApplyDenialReason::AuditNotAllow,
            "only an ALLOW change audit event may drive a fact apply",
        ));
    }
    if !request.plan.is_complete() {
        return Some(MemoryV1ApplyDenial::new(
            MemoryV1ApplyDenialReason::PlanNotComplete,
            "apply requires a structurally complete plan",
        ));
    }
    if !request.plan.has_required_tail() {
        return Some(MemoryV1ApplyDenial::new(
            MemoryV1ApplyDenialReason::PlanNotComplete,
            "apply requires the audit/receipt/progress tail",
        ));
    }
    check_audit_operation_and_flow(request.audit, &request.identity, request.plan.flow())
}

// memory—v1
fn deny_preflight_denial(request: &MemoryV1ApplyDenyRequest<'_>) -> Option<MemoryV1ApplyDenial> {
    if request.identity.frame_kind != MemoryV1ApplyFrameKind::Deny {
        return Some(MemoryV1ApplyDenial::new(
            MemoryV1ApplyDenialReason::FrameKindMismatch,
            "the deny entry point requires a Deny frame identity",
        ));
    }
    if !matches!(request.audit.decision(), MemoryV1AuditDecision::Deny(_)) {
        return Some(MemoryV1ApplyDenial::new(
            MemoryV1ApplyDenialReason::AuditNotDeny,
            "the deny apply path requires a DENY audit event",
        ));
    }
    check_audit_operation_and_flow(request.audit, &request.identity, None)
}

// memory—v1
fn check_audit_operation_and_flow(
    audit: &MemoryV1AuditEvent,
    identity: &MemoryV1ApplyIdentity,
    flow: Option<astral_types::memory_v1_journal::JournalAnchor>,
) -> Option<MemoryV1ApplyDenial> {
    if audit.context().operation().id() != identity.operation_id {
        return Some(MemoryV1ApplyDenial::new(
            MemoryV1ApplyDenialReason::AuditOperationMismatch,
            "audit operation identifier does not match the frame identity",
        ));
    }
    if let Some(flow) = flow {
        if flow.journal_sequence() != identity.journal_sequence
            || flow.mutation_sequence() != identity.mutation_sequence
            || flow.frame_hash() != &identity.frame_digest
        {
            return Some(MemoryV1ApplyDenial::new(
                MemoryV1ApplyDenialReason::FlowAnchorMismatch,
                "plan flow anchor does not match the frame identity",
            ));
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// In-transaction checks
// ─────────────────────────────────────────────────────────────────────────────

// memory—v1
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FenceVerification {
    Held,
    Expired,
    Missing,
    ForeignOwner,
    GenerationMismatch,
    StreamMismatch,
}

/// The fence row as read under the apply transaction's row lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FenceRowSnapshot {
    pub owner_boot_id: Vec<u8>,
    pub owner_worker_id: String,
    pub fence_generation: u64,
    pub lease_valid: bool,
}

/// Pure fence-verification decision: the presented token must match owner,
/// generation, and validity together. A stale generation — even from the same
/// boot/worker that still owns the row — can never pass.
// memory—v1
pub(crate) fn evaluate_fence_verification(
    snapshot: Option<&FenceRowSnapshot>,
    token: &MemoryV1ApplyFenceToken,
    stream_id: &MemoryId,
) -> FenceVerification {
    // A token bound to another stream is refused before any row comparison,
    // even when the other stream's row carries the same owner+generation.
    if token.verify_stream(stream_id).is_err() {
        return FenceVerification::StreamMismatch;
    }
    let Some(snapshot) = snapshot else {
        return FenceVerification::Missing;
    };
    if snapshot.owner_boot_id != token.boot_id.as_bytes().to_vec()
        || snapshot.owner_worker_id != token.worker_id
    {
        return FenceVerification::ForeignOwner;
    }
    if snapshot.fence_generation != token.fence_generation {
        return FenceVerification::GenerationMismatch;
    }
    if !snapshot.lease_valid {
        return FenceVerification::Expired;
    }
    FenceVerification::Held
}

// memory—v1
async fn verify_fence_in_tx(
    tx: &mut crate::memory_v1_apply_facts::ApplyTx<'_>,
    stream_id: &MemoryId,
    token: &MemoryV1ApplyFenceToken,
) -> Result<FenceVerification, MemoryV1ApplyError> {
    let row: Option<(Vec<u8>, String, u64, i64)> =
        sqlx::query_as(crate::memory_v1_apply_records::FENCE_SELECT_FOR_UPDATE_SQL)
            .bind(&stream_id.as_bytes()[..])
            .fetch_optional(&mut **tx)
            .await?;
    let snapshot = row.map(
        |(owner_boot_id, owner_worker_id, fence_generation, lease_valid)| FenceRowSnapshot {
            owner_boot_id,
            owner_worker_id,
            fence_generation,
            lease_valid: lease_valid == 1,
        },
    );
    Ok(evaluate_fence_verification(
        snapshot.as_ref(),
        token,
        stream_id,
    ))
}

/// The digests a caller proved in-process for one message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExpectedDigests {
    pub payload_digest: [u8; 32],
    pub mutation_digest: [u8; 32],
    pub audit_row_digest: [u8; 32],
}

// memory—v1
async fn check_receipt_dedup_in_tx(
    tx: &mut crate::memory_v1_apply_facts::ApplyTx<'_>,
    identity: &MemoryV1ApplyIdentity,
    expected: Option<&ExpectedDigests>,
) -> Result<Option<MemoryV1ApplyOutcome>, MemoryV1ApplyError> {
    let by_operation = crate::memory_v1_apply_records::read_receipt_by_operation(
        &mut **tx,
        &identity.operation_id,
    )
    .await?;
    if let Some(receipt) = by_operation {
        // The same operation id must bind the same stream position.
        if receipt.stream_id != identity.stream_id.as_bytes().to_vec()
            || receipt.journal_sequence != identity.journal_sequence
        {
            return Ok(Some(denial_outcome(
                MemoryV1ApplyDenialReason::ReceiptContentMismatch,
                "stored receipt binds the operation id to a different stream position; stop and reconcile",
            )));
        }
        return Ok(Some(match compare_receipt(&receipt, identity, expected) {
            Ok(()) => MemoryV1ApplyOutcome::Duplicate(receipt_view(&receipt, None)),
            Err(detail) => denial_outcome(
                MemoryV1ApplyDenialReason::ReceiptContentMismatch,
                format!("stored receipt conflicts with the message: {detail}"),
            ),
        }));
    }
    let by_position = crate::memory_v1_apply_records::read_receipt_by_position(
        &mut **tx,
        &identity.stream_id,
        identity.journal_sequence,
    )
    .await?;
    if let Some(receipt) = by_position {
        return Ok(Some(denial_outcome(
            MemoryV1ApplyDenialReason::ReceiptContentMismatch,
            format!(
                "stream position already holds a receipt for a different operation: {}",
                receipt.operation_id
            ),
        )));
    }
    Ok(None)
}

// memory—v1
async fn check_progress_continuity_in_tx(
    tx: &mut crate::memory_v1_apply_facts::ApplyTx<'_>,
    identity: &MemoryV1ApplyIdentity,
    strict_predecessor_mutation: Option<u64>,
) -> Result<Option<MemoryV1ApplyDenial>, MemoryV1ApplyError> {
    let previous =
        crate::memory_v1_apply_records::read_progress_for_update(tx, &identity.stream_id).await?;
    Ok(evaluate_progress_continuity(
        previous.as_ref(),
        identity,
        strict_predecessor_mutation,
    ))
}

/// Pure prefix-continuity decision: the pre-seeded tail must be the exact
/// predecessor of this frame (same epoch, journal sequence minus one,
/// matching previous hash, and mutation-sequence rule per frame kind).
/// A missing tail is never a trusted genesis. A strict predecessor
/// governance sequence (recovery observation path) must match exactly.
// memory—v1
pub(crate) fn evaluate_progress_continuity(
    previous: Option<&crate::memory_v1_apply_records::ProgressTailRow>,
    identity: &MemoryV1ApplyIdentity,
    strict_predecessor_mutation: Option<u64>,
) -> Option<MemoryV1ApplyDenial> {
    let Some(previous) = previous else {
        // A missing progress row is never a trusted genesis: the tail must
        // have been explicitly pre-seeded (bound to the stream's genesis
        // anchor) before any frame is applied.
        return Some(MemoryV1ApplyDenial::new(
            MemoryV1ApplyDenialReason::ProgressDiscontinuity,
            "no pre-seeded progress row for this stream; initialize the progress tail at boot before applying",
        ));
    };
    if previous.epoch_id != identity.epoch_id.as_bytes().to_vec() {
        return Some(MemoryV1ApplyDenial::new(
            MemoryV1ApplyDenialReason::EpochChangeNotCovered,
            "progress tail belongs to a different epoch; epoch rollover is not covered",
        ));
    }
    if previous.last_journal_sequence
        != identity.journal_sequence.checked_sub(1).unwrap_or(u64::MAX)
    {
        return Some(MemoryV1ApplyDenial::new(
            MemoryV1ApplyDenialReason::ProgressDiscontinuity,
            format!(
                "progress tail journal sequence {} is not the immediate predecessor of {}",
                previous.last_journal_sequence, identity.journal_sequence
            ),
        ));
    }
    match identity.frame_kind {
        MemoryV1ApplyFrameKind::Mutation => {
            let expected_mutation = identity
                .mutation_sequence
                .checked_sub(1)
                .unwrap_or(u64::MAX);
            if previous.last_mutation_sequence != expected_mutation {
                return Some(MemoryV1ApplyDenial::new(
                    MemoryV1ApplyDenialReason::ProgressDiscontinuity,
                    format!(
                        "progress tail mutation sequence {} is not the immediate predecessor of {}",
                        previous.last_mutation_sequence, identity.mutation_sequence
                    ),
                ));
            }
        }
        // A deny frame reads authorization state at or before the tail; it
        // must never claim a future mutation sequence.
        MemoryV1ApplyFrameKind::Deny => {
            if identity.mutation_sequence > previous.last_mutation_sequence {
                return Some(MemoryV1ApplyDenial::new(
                    MemoryV1ApplyDenialReason::ProgressDiscontinuity,
                    format!(
                        "deny frame mutation sequence {} exceeds the durable tail {}",
                        identity.mutation_sequence, previous.last_mutation_sequence
                    ),
                ));
            }
            // The recovery observation path binds the ACTUAL predecessor
            // governance sequence: the tail must match it exactly.
            if let Some(strict) = strict_predecessor_mutation {
                if previous.last_mutation_sequence != strict {
                    return Some(MemoryV1ApplyDenial::new(
                        MemoryV1ApplyDenialReason::ProgressDiscontinuity,
                        format!(
                            "progress tail mutation sequence {} does not match the verified predecessor {}",
                            previous.last_mutation_sequence, strict
                        ),
                    ));
                }
            }
        }
    }
    if previous.last_frame_hash != identity.prev_frame_hash.to_vec() {
        return Some(MemoryV1ApplyDenial::new(
            MemoryV1ApplyDenialReason::ProgressDiscontinuity,
            "progress tail frame hash does not match this frame's previous hash",
        ));
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit-row insert with conflict resolution
// ─────────────────────────────────────────────────────────────────────────────

// memory—v1
async fn insert_audit_row_in_tx(
    tx: &mut crate::memory_v1_apply_facts::ApplyTx<'_>,
    identity: &MemoryV1ApplyIdentity,
    content: &crate::memory_v1_apply_records::AuditRowContent<'_>,
    canonical_payload: &[u8],
    audit_row_digest: [u8; 32],
) -> Result<Option<MemoryV1ApplyOutcome>, MemoryV1ApplyError> {
    let payload = std::str::from_utf8(canonical_payload)
        .map_err(|_| MemoryV1ApplyError::Encoding("canonical payload is not UTF-8".into()))?;
    match crate::memory_v1_apply_records::insert_audit_row(
        tx,
        identity,
        content,
        payload,
        audit_row_digest,
    )
    .await
    {
        Ok(rows_affected) => {
            if rows_affected != 1 {
                return Ok(Some(denial_outcome(
                    MemoryV1ApplyDenialReason::CardinalityMismatch,
                    format!("audit row insert affected {rows_affected} rows"),
                )));
            }
            Ok(None)
        }
        Err(error) => {
            if crate::memory_v1_apply_records::is_unique_violation(&error) {
                // A receipt/audit row already exists for this operation or
                // position (a concurrent writer committed between our dedup
                // read and this insert). Roll this attempt back and resolve
                // through the fresh-connection receipt lookup.
                return Ok(Some(denial_outcome(
                    MemoryV1ApplyDenialReason::ReceiptContentMismatch,
                    "audit row insert hit a unique-key conflict; re-run reconciliation with the original identity",
                )));
            }
            Err(error.into())
        }
    }
}

/// Verify one merged audit row by its ACTUAL content: the stored canonical
/// payload must exist, its recomputed domain-separated digest must equal the
/// stored `audit_row_digest` column (a digest that stayed constant across
/// corrupted content is refused), and — when the caller proved the in-run
/// digest — it must equal that too.
// memory—v1
pub(crate) fn verify_audit_row_content(
    joined: &crate::memory_v1_apply_records::ReceiptAuditJoinedRow,
    expected_audit_digest: Option<&[u8; 32]>,
) -> Result<(), String> {
    let Some(payload) = joined.audit_canonical_payload.as_ref() else {
        return Err("audit row canonical payload is missing".into());
    };
    let Some(stored_digest) = joined.audit_row_digest_value.as_ref() else {
        return Err("audit row digest column is missing".into());
    };
    let payload: serde_json::Value = serde_json::from_str(payload)
        .map_err(|_| "stored audit row canonical payload is invalid JSON".to_owned())?;
    let canonical = crate::memory_v1_apply_records::canonical_audit_json(payload)
        .map_err(|_| "stored audit row canonical payload cannot be encoded".to_owned())?;
    let recomputed = crate::memory_v1_apply_records::audit_row_digest(&canonical);
    if recomputed.as_slice() != stored_digest.as_slice() {
        return Err(
            "stored audit row canonical payload does not match its own audit_row_digest column; the content changed without its digest".into(),
        );
    }
    if let Some(expected) = expected_audit_digest {
        if recomputed.as_slice() != expected.as_slice() {
            return Err(
                "stored audit row content does not match the verified frame content".into(),
            );
        }
    }
    Ok(())
}

// memory—v1
fn verified_from_content<'a>(
    content: &'a crate::memory_v1_apply_records::AuditRowContent<'a>,
) -> Option<MemoryV1ApplyVerifiedFrameContent<'a>> {
    match content {
        crate::memory_v1_apply_records::AuditRowContent::Event(event) => {
            Some(MemoryV1ApplyVerifiedFrameContent::Event(event))
        }
        crate::memory_v1_apply_records::AuditRowContent::DenyObservation(observation) => Some(
            MemoryV1ApplyVerifiedFrameContent::DenyObservation(observation),
        ),
    }
}

// memory—v1
async fn resolve_insert_conflict(
    pool: &sqlx::MySqlPool,
    tx: crate::memory_v1_apply_facts::ApplyTx<'_>,
    identity: &MemoryV1ApplyIdentity,
    verified_content: Option<MemoryV1ApplyVerifiedFrameContent<'_>>,
    error: sqlx::Error,
) -> Result<MemoryV1ApplyOutcome, MemoryV1ApplyError> {
    if !crate::memory_v1_apply_records::is_unique_violation(&error) {
        return Err(error.into());
    }
    // Drop this attempt (rollback) and look for the concurrent winner's
    // receipt on a fresh connection.
    drop(tx);
    let predecessor = match identity.frame_kind {
        MemoryV1ApplyFrameKind::Mutation => Some(MemoryV1ApplyPredecessor {
            mutation_sequence: identity.mutation_sequence - 1,
        }),
        MemoryV1ApplyFrameKind::Deny => None,
    };
    let input = MemoryV1ApplyReconciliationInput {
        identity: identity.clone(),
        predecessor,
        verified_content,
    };
    match reconcile_memory_v1_unknown_commit(pool, input).await? {
        MemoryV1ApplyReconciliation::ReceiptMatches(receipt) => {
            Ok(MemoryV1ApplyOutcome::Duplicate(*receipt))
        }
        MemoryV1ApplyReconciliation::NotApplied => Ok(denial_outcome(
            MemoryV1ApplyDenialReason::ReceiptContentMismatch,
            "a concurrent writer inserted the conflicting row but no receipt is visible yet; stop and reconcile",
        )),
        MemoryV1ApplyReconciliation::Inconsistent { reason, detail } => {
            Ok(denial_outcome(reason, detail))
        }
        MemoryV1ApplyReconciliation::Unknown { detail } => {
            Err(MemoryV1ApplyError::UnknownCommit(
                "concurrent-writer reconciliation could not prove the outcome; reconcile manually",
            ))
            .inspect_err(|_| tracing::warn!(detail = %detail, "memory-v1 apply conflict reconciliation unknown"))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Receipt comparison and views
// ─────────────────────────────────────────────────────────────────────────────

// memory—v1
fn compare_receipt(
    receipt: &crate::memory_v1_apply_records::ReceiptRow,
    identity: &MemoryV1ApplyIdentity,
    expected: Option<&ExpectedDigests>,
) -> Result<(), String> {
    if receipt.stream_id != identity.stream_id.as_bytes().to_vec() {
        return Err("stream_id differs".into());
    }
    if receipt.journal_sequence != identity.journal_sequence {
        return Err("journal_sequence differs".into());
    }
    if receipt.epoch_id != identity.epoch_id.as_bytes().to_vec() {
        return Err("epoch_id differs".into());
    }
    if receipt.mutation_sequence != identity.mutation_sequence {
        return Err("mutation_sequence differs".into());
    }
    if receipt.message_id != identity.message_id.as_bytes().to_vec() {
        return Err("message_id differs".into());
    }
    if receipt.operation_id != identity.operation_id {
        return Err("operation_id differs".into());
    }
    if receipt.boot_id != identity.origin_boot_id.as_bytes().to_vec() {
        return Err("original boot_id differs from the stored receipt".into());
    }
    if receipt.request_fingerprint != identity.request_fingerprint.to_vec() {
        return Err("request_fingerprint differs".into());
    }
    if receipt.prev_frame_hash != identity.prev_frame_hash.to_vec() {
        return Err("prev_frame_hash differs".into());
    }
    if receipt.frame_digest != identity.frame_digest.to_vec() {
        return Err("frame_digest differs".into());
    }
    if receipt.payload_digest != identity.payload_digest.to_vec() {
        return Err("payload_digest differs".into());
    }
    // The receipt's boot/worker columns are consumer provenance: they must be
    // present but are NOT compared across boots (a restart changes them).
    if receipt.boot_id.iter().all(|byte| *byte == 0)
        || receipt.worker_id.is_empty()
        || receipt.applied_by_boot_id.iter().all(|byte| *byte == 0)
    {
        return Err("stored receipt lacks its boot/worker provenance".into());
    }
    if receipt.outcome != "APPLIED" && receipt.outcome != "DENY" {
        return Err(format!(
            "stored receipt carries an unknown outcome token: {}",
            receipt.outcome
        ));
    }
    if let Some(expected) = expected {
        if receipt.payload_digest != expected.payload_digest {
            return Err("payload_digest differs from the digest proven this run".into());
        }
        if receipt.mutation_digest != expected.mutation_digest {
            return Err("mutation_digest differs from the digest proven this run".into());
        }
        if receipt.audit_row_digest != expected.audit_row_digest {
            return Err("audit_row_digest differs from the digest proven this run".into());
        }
    }
    Ok(())
}

// memory—v1
fn receipt_view(
    receipt: &crate::memory_v1_apply_records::ReceiptRow,
    operations: Option<Vec<MemoryV1AppliedOperation>>,
) -> MemoryV1ApplyReceipt {
    MemoryV1ApplyReceipt {
        identity: MemoryV1ApplyIdentity {
            stream_id: MemoryId::from_bytes(fixed16(&receipt.stream_id)),
            epoch_id: MemoryId::from_bytes(fixed16(&receipt.epoch_id)),
            journal_sequence: receipt.journal_sequence,
            mutation_sequence: receipt.mutation_sequence,
            message_id: MemoryId::from_bytes(fixed16(&receipt.message_id)),
            operation_id: receipt.operation_id.clone(),
            origin_boot_id: MemoryId::from_bytes(fixed16(&receipt.boot_id)),
            request_fingerprint: fixed32(&receipt.request_fingerprint),
            prev_frame_hash: fixed32(&receipt.prev_frame_hash),
            frame_digest: fixed32(&receipt.frame_digest),
            payload_digest: fixed32(&receipt.payload_digest),
            frame_kind: receipt.frame_kind(),
        },
        applied_by_boot_id: MemoryId::from_bytes(fixed16(&receipt.applied_by_boot_id)),
        applied_by_worker: receipt.worker_id.clone(),
        outcome: receipt.outcome_token(),
        fact_operation_count: receipt.fact_operation_count,
        fact_rows_affected_total: receipt.fact_rows_affected_total,
        operations,
    }
}

// memory—v1
fn fixed16(bytes: &[u8]) -> [u8; 16] {
    bytes.try_into().unwrap_or([0; 16])
}

// memory—v1
fn fixed32(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().unwrap_or([0; 32])
}

// memory—v1
async fn reconcile_after_commit_failure(
    pool: &sqlx::MySqlPool,
    identity: MemoryV1ApplyIdentity,
    verified_content: Option<MemoryV1ApplyVerifiedFrameContent<'_>>,
) -> Result<MemoryV1ApplyOutcome, MemoryV1ApplyError> {
    let predecessor = match identity.frame_kind {
        MemoryV1ApplyFrameKind::Mutation => Some(MemoryV1ApplyPredecessor {
            mutation_sequence: identity.mutation_sequence - 1,
        }),
        MemoryV1ApplyFrameKind::Deny => None,
    };
    let input = MemoryV1ApplyReconciliationInput {
        identity,
        predecessor,
        verified_content,
    };
    match reconcile_memory_v1_unknown_commit(pool, input).await {
        Ok(MemoryV1ApplyReconciliation::ReceiptMatches(receipt)) => {
            Ok(MemoryV1ApplyOutcome::Applied(*receipt))
        }
        Ok(MemoryV1ApplyReconciliation::NotApplied) => Err(MemoryV1ApplyError::UnknownCommit(
            "fresh-connection reconciliation found no receipt; retry with the original message under a bounded budget",
        )),
        Ok(MemoryV1ApplyReconciliation::Inconsistent { reason, detail }) => {
            Ok(denial_outcome(reason, detail))
        }
        Ok(MemoryV1ApplyReconciliation::Unknown { detail }) => {
            tracing::warn!(detail = %detail, "memory-v1 apply commit reconciliation is unknown");
            Err(MemoryV1ApplyError::UnknownCommit(
                "reconciliation could not prove the commit outcome; reconcile manually before any retry",
            ))
        }
        Err(error) => {
            tracing::warn!(error = %error, "memory-v1 apply reconciliation itself failed");
            Err(MemoryV1ApplyError::UnknownCommit(
                "fresh-connection reconciliation failed; reconcile manually before any retry",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_v1_apply_plan::tests_support::{
        memory_id as sample_memory_id, sample_audit_event, sample_audit_event_with_operation,
        sample_user_card_row,
    };
    use crate::memory_v1_apply_plan::{ApplyPlanInput, MemoryV1ApplyPlan};
    use astral_authorization_root::memory_v1_db_rows::UserCardRow;
    use astral_authorization_root::memory_v1_root::ManagementMutationV2;
    use astral_types::memory_v1_audit::{
        MemoryV1AuditAction, MemoryV1AuditActor, MemoryV1AuditContext, MemoryV1AuditDecisionInput,
        MemoryV1AuditDenySource, MemoryV1AuditObject, MemoryV1AuditOperation,
        MemoryV1AuditRootObservation, MemoryV1AuditRootStatus, MemoryV1AuditRootVersion,
        MemoryV1AuditTime,
    };
    use astral_types::memory_v1_journal::JournalAnchor;

    // memory—v1
    fn operation_id() -> &'static str {
        "op-records"
    }

    // memory—v1
    fn mutation_identity() -> MemoryV1ApplyIdentity {
        MemoryV1ApplyIdentity {
            stream_id: sample_memory_id(31),
            epoch_id: sample_memory_id(32),
            journal_sequence: 1,
            mutation_sequence: 1,
            message_id: sample_memory_id(33),
            operation_id: operation_id().to_string(),
            origin_boot_id: sample_memory_id(34),
            request_fingerprint: [5; 32],
            prev_frame_hash: [1; 32],
            frame_digest: [7; 32],
            payload_digest: [8; 32],
            frame_kind: MemoryV1ApplyFrameKind::Mutation,
        }
    }

    // memory—v1
    fn deny_identity() -> MemoryV1ApplyIdentity {
        MemoryV1ApplyIdentity {
            mutation_sequence: 0,
            frame_kind: MemoryV1ApplyFrameKind::Deny,
            ..mutation_identity()
        }
    }

    // memory—v1
    fn lease() -> MemoryV1ApplyLease {
        MemoryV1ApplyLease {
            boot_id: sample_memory_id(35),
            worker_id: "it-worker".to_string(),
            lease_ttl_seconds: 60,
        }
    }

    // memory—v1
    fn fence_token() -> MemoryV1ApplyFenceToken {
        MemoryV1ApplyFenceToken::mint(
            sample_memory_id(31),
            sample_memory_id(35),
            "it-worker".to_string(),
            1,
        )
    }

    // memory—v1
    fn matching_flow(identity: &MemoryV1ApplyIdentity) -> JournalAnchor {
        JournalAnchor::new(
            identity.stream_id,
            identity.journal_sequence,
            identity.mutation_sequence,
            identity.frame_digest,
        )
        .unwrap()
    }

    // memory—v1
    fn user_card_mutation() -> ManagementMutationV2 {
        let row: UserCardRow = sample_user_card_row();
        ManagementMutationV2::UserCardCreate { row }
    }

    // memory—v1
    fn deny_event() -> MemoryV1AuditEvent {
        let operation = MemoryV1AuditOperation::new(operation_id(), [7; 32]).unwrap();
        let context = MemoryV1AuditContext::new(
            MemoryV1AuditActor::new(sample_memory_id(1), sample_memory_id(2)),
            MemoryV1AuditTime::new(40).unwrap(),
            MemoryV1AuditAction::new("memory_v1", "apply").unwrap(),
            "MANAGEMENT_PENDING",
            operation,
            MemoryV1AuditRootObservation::new(
                MemoryV1AuditRootVersion::new(sample_memory_id(8), 1),
                [4; 32],
                MemoryV1AuditRootStatus::Serving,
            ),
        )
        .unwrap();
        MemoryV1AuditEvent::read(
            context,
            MemoryV1AuditDecisionInput::Deny(MemoryV1AuditDenySource::NoMatch),
        )
        .unwrap()
    }

    // memory—v1
    fn mutation_request<'a>(
        identity: MemoryV1ApplyIdentity,
        mutation: &'a ManagementMutationV2,
        audit: &'a MemoryV1AuditEvent,
    ) -> MemoryV1ApplyRequest<'a> {
        let flow = matching_flow(&identity);
        let plan = MemoryV1ApplyPlan::build(ApplyPlanInput {
            mutation,
            audit: Some(audit),
            flow: Some(flow),
        });
        MemoryV1ApplyRequest {
            identity,
            plan,
            audit,
            fence: fence_token(),
        }
    }

    /// Identity shape validation rejects zero identities, bad operation
    /// identifier charset, zero hashes, and invalid sequence starts; a deny
    /// frame may carry the external-baseline mutation sequence zero.
    #[test]
    // memory—v1
    fn identity_shape_validation() {
        assert!(validate_identity(&mutation_identity()).is_ok());
        assert!(validate_identity(&deny_identity()).is_ok());

        let mut zero_stream = mutation_identity();
        zero_stream.stream_id = MemoryId::from_bytes([0; 16]);
        assert!(validate_identity(&zero_stream).is_err());

        let mut zero_origin = mutation_identity();
        zero_origin.origin_boot_id = MemoryId::from_bytes([0; 16]);
        assert!(validate_identity(&zero_origin).is_err());

        let mut bad_operation = mutation_identity();
        bad_operation.operation_id = "bad id!".to_string();
        assert!(validate_identity(&bad_operation).is_err());

        let mut zero_payload = mutation_identity();
        zero_payload.payload_digest = [0; 32];
        assert!(validate_identity(&zero_payload).is_err());

        let mut zero_mutation_sequence = mutation_identity();
        zero_mutation_sequence.mutation_sequence = 0;
        assert!(validate_identity(&zero_mutation_sequence).is_err());
    }

    /// Lease validation bounds the worker identifier charset and TTL.
    #[test]
    // memory—v1
    fn lease_shape_validation() {
        assert!(validate_lease(&lease()).is_ok());
        let mut zero_boot = lease();
        zero_boot.boot_id = MemoryId::from_bytes([0; 16]);
        assert!(validate_lease(&zero_boot).is_err());
        let mut bad_worker = lease();
        bad_worker.worker_id = "worker space".to_string();
        assert!(validate_lease(&bad_worker).is_err());
        let mut ttl_over = lease();
        ttl_over.lease_ttl_seconds = MEMORY_V1_APPLY_MAX_LEASE_TTL_SECONDS + 1;
        assert!(validate_lease(&ttl_over).is_err());
        let mut ttl_under = lease();
        ttl_under.lease_ttl_seconds = 0;
        assert!(validate_lease(&ttl_under).is_err());
    }

    /// The mutation entry point refuses ungoverned context loads, non-ALLOW
    /// audits, deny-frame identities, mismatched flow anchors, and foreign
    /// audit operation ids — all before any database access.
    #[test]
    // memory—v1
    fn mutation_preflight_denials() {
        let identity = mutation_identity();
        let event = sample_audit_event(MemoryV1AuditObject::UserCard(sample_memory_id(20)), false);
        let mutation = user_card_mutation();
        let request = mutation_request(identity.clone(), &mutation, &event);
        assert!(mutation_preflight_denial(&request).is_none());

        let deny_frame_request = mutation_request(deny_identity(), &mutation, &event);
        assert_eq!(
            mutation_preflight_denial(&deny_frame_request).map(|denial| denial.reason),
            Some(MemoryV1ApplyDenialReason::FrameKindMismatch)
        );

        let context_load = ManagementMutationV2::ContextLoad {
            rows: Default::default(),
            selections: Vec::new(),
        };
        let context_request = mutation_request(identity.clone(), &context_load, &event);
        assert_eq!(
            mutation_preflight_denial(&context_request).map(|denial| denial.reason),
            Some(MemoryV1ApplyDenialReason::MutationKindNotCovered)
        );

        let deny_audit = deny_event();
        let deny_audit_request = mutation_request(identity.clone(), &mutation, &deny_audit);
        assert_eq!(
            mutation_preflight_denial(&deny_audit_request).map(|denial| denial.reason),
            Some(MemoryV1ApplyDenialReason::AuditNotAllow)
        );

        let mut wrong_flow_identity = identity.clone();
        wrong_flow_identity.journal_sequence = 9;
        // The plan's flow anchor stays bound to the original position while
        // the identity claims a later journal sequence.
        let wrong_flow_request = MemoryV1ApplyRequest {
            identity: wrong_flow_identity,
            plan: MemoryV1ApplyPlan::build(ApplyPlanInput {
                mutation: &mutation,
                audit: Some(&event),
                flow: Some(matching_flow(&identity)),
            }),
            audit: &event,
            fence: fence_token(),
        };
        assert_eq!(
            mutation_preflight_denial(&wrong_flow_request).map(|denial| denial.reason),
            Some(MemoryV1ApplyDenialReason::FlowAnchorMismatch)
        );

        let mut wrong_op_identity = identity;
        wrong_op_identity.operation_id = "op-other".to_string();
        let wrong_op_request = mutation_request(wrong_op_identity, &mutation, &event);
        assert_eq!(
            mutation_preflight_denial(&wrong_op_request).map(|denial| denial.reason),
            Some(MemoryV1ApplyDenialReason::AuditOperationMismatch)
        );
    }

    /// The deny entry point refuses ALLOW audits and mutation-frame
    /// identities; a true DENY audit passes.
    #[test]
    // memory—v1
    fn deny_preflight_decisions() {
        let request = MemoryV1ApplyDenyRequest {
            identity: deny_identity(),
            audit: &deny_event(),
            fence: fence_token(),
        };
        assert!(deny_preflight_denial(&request).is_none());

        let allow_request = MemoryV1ApplyDenyRequest {
            identity: deny_identity(),
            audit: &sample_audit_event(MemoryV1AuditObject::UserCard(sample_memory_id(20)), false),
            fence: fence_token(),
        };
        assert_eq!(
            deny_preflight_denial(&allow_request).map(|denial| denial.reason),
            Some(MemoryV1ApplyDenialReason::AuditNotDeny)
        );

        let mutation_frame_request = MemoryV1ApplyDenyRequest {
            identity: mutation_identity(),
            audit: &deny_event(),
            fence: fence_token(),
        };
        assert_eq!(
            deny_preflight_denial(&mutation_frame_request).map(|denial| denial.reason),
            Some(MemoryV1ApplyDenialReason::FrameKindMismatch)
        );
    }

    /// Receipt comparison: an identical stored receipt matches; any identity
    /// field, digest, or provenance difference refuses. Digest mismatches are
    /// only detectable when the caller proved the in-run digests.
    #[test]
    // memory—v1
    fn receipt_comparison_matrix() {
        let identity = mutation_identity();
        let receipt = crate::memory_v1_apply_records::ReceiptRow {
            stream_id: identity.stream_id.as_bytes().to_vec(),
            epoch_id: identity.epoch_id.as_bytes().to_vec(),
            journal_sequence: identity.journal_sequence,
            mutation_sequence: identity.mutation_sequence,
            message_id: identity.message_id.as_bytes().to_vec(),
            operation_id: identity.operation_id.clone(),
            boot_id: identity.origin_boot_id.as_bytes().to_vec(),
            applied_by_boot_id: lease().boot_id.as_bytes().to_vec(),
            worker_id: lease().worker_id,
            outcome: "APPLIED".to_string(),
            request_fingerprint: identity.request_fingerprint.to_vec(),
            prev_frame_hash: identity.prev_frame_hash.to_vec(),
            frame_digest: identity.frame_digest.to_vec(),
            payload_digest: identity.payload_digest.to_vec(),
            mutation_digest: [9; 32].to_vec(),
            audit_row_digest: [10; 32].to_vec(),
            fact_operation_count: 1,
            fact_rows_affected_total: 1,
        };

        let digests = ExpectedDigests {
            payload_digest: identity.payload_digest,
            mutation_digest: [9; 32],
            audit_row_digest: [10; 32],
        };
        assert!(compare_receipt(&receipt, &identity, Some(&digests)).is_ok());
        assert!(compare_receipt(&receipt, &identity, None).is_ok());

        let mut wrong_origin = receipt.clone();
        wrong_origin.boot_id = [3; 16].to_vec();
        assert!(compare_receipt(&wrong_origin, &identity, Some(&digests)).is_err());

        let mut wrong_payload = receipt.clone();
        wrong_payload.payload_digest = [11; 32].to_vec();
        assert!(compare_receipt(&wrong_payload, &identity, Some(&digests)).is_err());

        let mut wrong_position = receipt.clone();
        wrong_position.journal_sequence = 7;
        assert!(compare_receipt(&wrong_position, &identity, Some(&digests)).is_err());

        let mut wrong_outcome = receipt.clone();
        wrong_outcome.outcome = "MYSTERY".to_string();
        assert!(compare_receipt(&wrong_outcome, &identity, None).is_err());

        let mut wrong_audit_digest = receipt.clone();
        wrong_audit_digest.audit_row_digest = [12; 32].to_vec();
        assert!(compare_receipt(&wrong_audit_digest, &identity, None).is_ok());
        assert!(compare_receipt(&wrong_audit_digest, &identity, Some(&digests)).is_err());
    }

    /// Denial details never exceed the bounded length.
    #[test]
    // memory—v1
    fn denial_details_stay_bounded() {
        let denial = MemoryV1ApplyDenial::new(
            MemoryV1ApplyDenialReason::PreconditionFailed,
            "y".repeat(4096),
        );
        assert!(denial.detail.len() <= MEMORY_V1_APPLY_MAX_DETAIL_BYTES);
    }

    /// Fence verification matrix: owner, generation, and expiry must match
    /// together. A stale generation — even from the same boot/worker that
    /// still owns the row — can never pass, and token shape validation
    /// rejects a zero generation.
    #[test]
    // memory—v1
    fn fence_verification_matrix_rejects_stale_generation() {
        let token = fence_token();
        assert!(validate_fence_token(&token).is_ok());
        let mut zero_generation = token.clone();
        zero_generation.fence_generation = 0;
        assert!(validate_fence_token(&zero_generation).is_err());

        let held = FenceRowSnapshot {
            owner_boot_id: token.boot_id.as_bytes().to_vec(),
            owner_worker_id: token.worker_id.clone(),
            fence_generation: token.fence_generation,
            lease_valid: true,
        };
        assert_eq!(
            evaluate_fence_verification(Some(&held), &token, &sample_memory_id(31)),
            FenceVerification::Held
        );

        // Missing row: nothing is held.
        assert_eq!(
            evaluate_fence_verification(None, &token, &sample_memory_id(31)),
            FenceVerification::Missing
        );

        // Cross-stream presentation: the same owner+generation on another
        // stream's fence row never counts — the token is stream-bound.
        assert_eq!(
            evaluate_fence_verification(Some(&held), &token, &sample_memory_id(41)),
            FenceVerification::StreamMismatch
        );

        // Foreign owner.
        let foreign = FenceRowSnapshot {
            owner_boot_id: [9; 16].to_vec(),
            owner_worker_id: "other-worker".to_string(),
            fence_generation: token.fence_generation,
            lease_valid: true,
        };
        assert_eq!(
            evaluate_fence_verification(Some(&foreign), &token, &sample_memory_id(31)),
            FenceVerification::ForeignOwner
        );

        // Stale generation held by the SAME boot/worker: the old holder can
        // no longer write or release after a claim/renewal rotated the fence.
        let mut stale_higher = held.clone();
        stale_higher.fence_generation = token.fence_generation + 1;
        assert_eq!(
            evaluate_fence_verification(Some(&stale_higher), &token, &sample_memory_id(31)),
            FenceVerification::GenerationMismatch
        );
        let mut stale_lower = held.clone();
        stale_lower.fence_generation = token.fence_generation - 1;
        assert_eq!(
            evaluate_fence_verification(Some(&stale_lower), &token, &sample_memory_id(31)),
            FenceVerification::GenerationMismatch
        );

        // Same owner and generation but expired.
        let expired = FenceRowSnapshot {
            owner_boot_id: held.owner_boot_id,
            owner_worker_id: held.owner_worker_id,
            fence_generation: held.fence_generation,
            lease_valid: false,
        };
        assert_eq!(
            evaluate_fence_verification(Some(&expired), &token, &sample_memory_id(31)),
            FenceVerification::Expired
        );
    }

    /// Prefix-continuity matrix: a missing pre-seeded row, an epoch change, a
    /// sequence gap, a mutation-sequence mismatch, and a hash mismatch are
    /// all fail-closed; only the exact predecessor passes.
    #[test]
    // memory—v1
    fn progress_continuity_matrix_rejects_mismatched_prefix() {
        let identity = mutation_identity();
        // Genesis pre-seed: 0/0 with the genesis anchor as previous hash.
        let genesis_tail = crate::memory_v1_apply_records::ProgressTailRow {
            epoch_id: identity.epoch_id.as_bytes().to_vec(),
            last_journal_sequence: 0,
            last_mutation_sequence: 0,
            last_frame_hash: identity.prev_frame_hash.to_vec(),
        };
        assert!(evaluate_progress_continuity(Some(&genesis_tail), &identity, None).is_none());

        // A missing row is never a trusted genesis.
        assert!(evaluate_progress_continuity(None, &identity, None).is_some());

        // Epoch change on the same stream.
        let foreign_epoch = crate::memory_v1_apply_records::ProgressTailRow {
            epoch_id: [9; 16].to_vec(),
            ..genesis_tail.clone()
        };
        assert_eq!(
            evaluate_progress_continuity(Some(&foreign_epoch), &identity, None)
                .map(|denial| denial.reason),
            Some(MemoryV1ApplyDenialReason::EpochChangeNotCovered)
        );

        // Sequence gap: the tail is not the immediate predecessor.
        let gap = crate::memory_v1_apply_records::ProgressTailRow {
            last_journal_sequence: 5,
            ..genesis_tail.clone()
        };
        assert_eq!(
            evaluate_progress_continuity(Some(&gap), &identity, None).map(|denial| denial.reason),
            Some(MemoryV1ApplyDenialReason::ProgressDiscontinuity)
        );

        // Mutation-sequence mismatch on a mutation frame.
        let mutation_gap = crate::memory_v1_apply_records::ProgressTailRow {
            last_mutation_sequence: 7,
            ..genesis_tail.clone()
        };
        assert_eq!(
            evaluate_progress_continuity(Some(&mutation_gap), &identity, None)
                .map(|denial| denial.reason),
            Some(MemoryV1ApplyDenialReason::ProgressDiscontinuity)
        );

        // A deny frame must never claim a future mutation sequence.
        let deny_identity = deny_identity();
        let deny_tail = crate::memory_v1_apply_records::ProgressTailRow {
            epoch_id: deny_identity.epoch_id.as_bytes().to_vec(),
            last_journal_sequence: 0,
            last_mutation_sequence: 0,
            last_frame_hash: deny_identity.prev_frame_hash.to_vec(),
        };
        assert!(evaluate_progress_continuity(Some(&deny_tail), &deny_identity, None).is_none());
        let future_deny_identity = MemoryV1ApplyIdentity {
            mutation_sequence: 1,
            ..deny_identity.clone()
        };
        assert_eq!(
            evaluate_progress_continuity(Some(&deny_tail), &future_deny_identity, None)
                .map(|denial| denial.reason),
            Some(MemoryV1ApplyDenialReason::ProgressDiscontinuity)
        );

        // Previous-hash mismatch at the correct position.
        let wrong_hash = crate::memory_v1_apply_records::ProgressTailRow {
            last_frame_hash: [8; 32].to_vec(),
            ..genesis_tail
        };
        assert_eq!(
            evaluate_progress_continuity(Some(&wrong_hash), &identity, None)
                .map(|denial| denial.reason),
            Some(MemoryV1ApplyDenialReason::ProgressDiscontinuity)
        );
    }

    /// Reconciliation matrix over the merged receipt+audit row: applied
    /// proofs require both keys agreeing, outcome matching the frame kind,
    /// the audit row present with matching columns and content digest, and
    /// the tail checks; not-applied proofs require the verified predecessor
    /// governance sequence; single-key rows, cross-kind outcomes, missing
    /// audit rows, wrong content, and unprovable states never pass.
    #[test]
    // memory—v1
    fn reconciliation_decision_matrix() {
        let identity = mutation_identity();
        let predecessor_zero = MemoryV1ApplyPredecessor {
            mutation_sequence: 0,
        };
        let base_receipt = crate::memory_v1_apply_records::ReceiptRow {
            stream_id: identity.stream_id.as_bytes().to_vec(),
            epoch_id: identity.epoch_id.as_bytes().to_vec(),
            journal_sequence: identity.journal_sequence,
            mutation_sequence: identity.mutation_sequence,
            message_id: identity.message_id.as_bytes().to_vec(),
            operation_id: identity.operation_id.clone(),
            boot_id: identity.origin_boot_id.as_bytes().to_vec(),
            applied_by_boot_id: fence_token().boot_id.as_bytes().to_vec(),
            worker_id: fence_token().worker_id,
            outcome: "APPLIED".to_string(),
            request_fingerprint: identity.request_fingerprint.to_vec(),
            prev_frame_hash: identity.prev_frame_hash.to_vec(),
            frame_digest: identity.frame_digest.to_vec(),
            payload_digest: identity.payload_digest.to_vec(),
            mutation_digest: [9; 32].to_vec(),
            audit_row_digest: vec![0; 32],
            fact_operation_count: 1,
            fact_rows_affected_total: 1,
        };
        let event = sample_audit_event(MemoryV1AuditObject::UserCard(sample_memory_id(20)), false);
        let expected_digest = crate::memory_v1_apply_records::audit_row_digest(
            &crate::memory_v1_apply_records::encode_canonical_audit_payload(&event).unwrap(),
        );
        let receipt = crate::memory_v1_apply_records::ReceiptRow {
            audit_row_digest: expected_digest.to_vec(),
            ..base_receipt
        };

        // memory—v1
        type AuditColumns = (
            Option<String>,
            Option<Vec<u8>>,
            Option<u64>,
            Option<u64>,
            Option<Vec<u8>>,
            Option<String>,
        );

        // memory—v1
        fn audit_columns(decision: &str, identity: &MemoryV1ApplyIdentity) -> AuditColumns {
            (
                Some(decision.to_string()),
                Some(identity.epoch_id.as_bytes().to_vec()),
                Some(identity.journal_sequence),
                Some(identity.mutation_sequence),
                Some(identity.message_id.as_bytes().to_vec()),
                Some(identity.operation_id.clone()),
            )
        }

        // memory—v1

        // memory—v1
        fn joined_row(
            receipt: &crate::memory_v1_apply_records::ReceiptRow,
            audit: Option<(
                // The stored canonical payload bytes; the digest column is
                // derived from them unless an explicit (corrupted) pair is
                // given.
                AuditColumns,
                Option<String>,
                Option<Vec<u8>>,
            )>,
            by_operation: bool,
            by_position: bool,
        ) -> crate::memory_v1_apply_records::ReceiptAuditJoinedRow {
            let Some((columns, payload, forced_digest)) = audit else {
                return crate::memory_v1_apply_records::ReceiptAuditJoinedRow {
                    receipt: receipt.clone(),
                    matched_by_operation: i64::from(by_operation),
                    matched_by_position: i64::from(by_position),
                    audit_row_digest_value: None,
                    audit_decision: None,
                    audit_epoch_id: None,
                    audit_journal_sequence: None,
                    audit_mutation_sequence: None,
                    audit_message_id: None,
                    audit_operation_id: None,
                    audit_canonical_payload: None,
                };
            };
            let (
                audit_decision,
                audit_epoch_id,
                audit_journal_sequence,
                audit_mutation_sequence,
                audit_message_id,
                audit_operation_id,
            ) = columns;
            // The stored digest column is recomputed from the payload bytes
            // unless the test forces a corrupted (stale) digest column.
            let digest_column = forced_digest.unwrap_or_else(|| {
                crate::memory_v1_apply_records::audit_row_digest(
                    payload.as_ref().map(|p| p.as_bytes()).unwrap_or(&[]),
                )
                .to_vec()
            });
            crate::memory_v1_apply_records::ReceiptAuditJoinedRow {
                receipt: receipt.clone(),
                matched_by_operation: i64::from(by_operation),
                matched_by_position: i64::from(by_position),
                audit_row_digest_value: Some(digest_column),
                audit_decision,
                audit_epoch_id,
                audit_journal_sequence,
                audit_mutation_sequence,
                audit_message_id,
                audit_operation_id,
                audit_canonical_payload: payload,
            }
        }

        let event_payload = String::from_utf8(
            crate::memory_v1_apply_records::encode_canonical_audit_payload(&event).unwrap(),
        )
        .unwrap();
        let matching_audit = (
            audit_columns("ALLOW", &identity),
            Some(event_payload.clone()),
            None,
        );
        let tail_at_frame = crate::memory_v1_apply_records::ProgressTailRow {
            epoch_id: identity.epoch_id.as_bytes().to_vec(),
            last_journal_sequence: identity.journal_sequence,
            last_mutation_sequence: identity.mutation_sequence,
            last_frame_hash: identity.frame_digest.to_vec(),
        };
        let tail_at_predecessor = crate::memory_v1_apply_records::ProgressTailRow {
            last_journal_sequence: identity.journal_sequence - 1,
            last_mutation_sequence: identity.mutation_sequence - 1,
            last_frame_hash: identity.prev_frame_hash.to_vec(),
            ..tail_at_frame.clone()
        };
        let verified_event = MemoryV1ApplyVerifiedFrameContent::Event(&event);

        let both_keys = [joined_row(
            &receipt,
            Some(matching_audit.clone()),
            true,
            true,
        )];
        // Applied proof: both keys, outcome/kind, audit row, exact content.
        assert!(matches!(
            reconcile_decision(
                &both_keys,
                Some(&tail_at_frame),
                &identity,
                Some(&predecessor_zero),
                Some(&verified_event),
            ),
            MemoryV1ApplyReconciliation::ReceiptMatches(_)
        ));

        // Missing verified content: the audit row matches the frame identity
        // but exact content verification is impossible — UNKNOWN, never a
        // row-existence proof.
        assert!(matches!(
            reconcile_decision(
                &both_keys,
                Some(&tail_at_frame),
                &identity,
                Some(&predecessor_zero),
                None,
            ),
            MemoryV1ApplyReconciliation::Unknown { .. }
        ));

        // Wrong supplied content (a different event): digest mismatch.
        let other_event =
            sample_audit_event(MemoryV1AuditObject::UserCard(sample_memory_id(21)), false);
        assert!(matches!(
            reconcile_decision(
                &both_keys,
                Some(&tail_at_frame),
                &identity,
                Some(&predecessor_zero),
                Some(&MemoryV1ApplyVerifiedFrameContent::Event(&other_event)),
            ),
            MemoryV1ApplyReconciliation::Inconsistent { .. }
        ));

        // A later tail is still a proof with the full content verification.
        let tail_ahead = crate::memory_v1_apply_records::ProgressTailRow {
            last_journal_sequence: identity.journal_sequence + 3,
            ..tail_at_frame.clone()
        };
        assert!(matches!(
            reconcile_decision(
                &both_keys,
                Some(&tail_ahead),
                &identity,
                Some(&predecessor_zero),
                Some(&verified_event),
            ),
            MemoryV1ApplyReconciliation::ReceiptMatches(_)
        ));

        // Single-key receipt (position key finds nothing): never applied.
        let op_key_only = [joined_row(
            &receipt,
            Some(matching_audit.clone()),
            true,
            false,
        )];
        assert!(matches!(
            reconcile_decision(
                &op_key_only,
                Some(&tail_at_frame),
                &identity,
                Some(&predecessor_zero),
                Some(&verified_event),
            ),
            MemoryV1ApplyReconciliation::Inconsistent { .. }
        ));

        // Conflicting receipts: the two unique keys bind different operations.
        let mut foreign_receipt = receipt.clone();
        foreign_receipt.operation_id = "op-other".to_string();
        let conflicting = [
            joined_row(&receipt, Some(matching_audit.clone()), true, false),
            joined_row(&foreign_receipt, None, false, true),
        ];
        assert!(matches!(
            reconcile_decision(
                &conflicting,
                Some(&tail_at_frame),
                &identity,
                Some(&predecessor_zero),
                Some(&verified_event),
            ),
            MemoryV1ApplyReconciliation::Inconsistent { .. }
        ));

        // Receipt outcome token does not match the frame kind.
        let mut deny_outcome_receipt = receipt.clone();
        deny_outcome_receipt.outcome = "DENY".to_string();
        let deny_outcome_rows = [joined_row(
            &deny_outcome_receipt,
            Some(matching_audit.clone()),
            true,
            true,
        )];
        assert!(matches!(
            reconcile_decision(
                &deny_outcome_rows,
                Some(&tail_at_frame),
                &identity,
                Some(&predecessor_zero),
                Some(&verified_event),
            ),
            MemoryV1ApplyReconciliation::Inconsistent { .. }
        ));

        // Audit decision token does not match the frame kind.
        let deny_decision_audit = (
            audit_columns("DENY:no_match", &identity),
            Some(event_payload.clone()),
            None,
        );
        let deny_decision_rows = [joined_row(&receipt, Some(deny_decision_audit), true, true)];
        assert!(matches!(
            reconcile_decision(
                &deny_decision_rows,
                Some(&tail_at_frame),
                &identity,
                Some(&predecessor_zero),
                Some(&verified_event),
            ),
            MemoryV1ApplyReconciliation::Inconsistent { .. }
        ));

        // Receipt exists but the independent append-only audit row is missing.
        let no_audit = [joined_row(&receipt, None, true, true)];
        assert!(matches!(
            reconcile_decision(
                &no_audit,
                Some(&tail_at_frame),
                &identity,
                Some(&predecessor_zero),
                Some(&verified_event),
            ),
            MemoryV1ApplyReconciliation::Inconsistent { .. }
        ));

        // Audit row columns disagree with the verified frame.
        let mut wrong_audit = matching_audit.clone();
        wrong_audit.0 .3 = Some(42);
        let wrong_audit_rows = [joined_row(&receipt, Some(wrong_audit), true, true)];
        assert!(matches!(
            reconcile_decision(
                &wrong_audit_rows,
                Some(&tail_at_frame),
                &identity,
                Some(&predecessor_zero),
                Some(&verified_event),
            ),
            MemoryV1ApplyReconciliation::Inconsistent { .. }
        ));

        // Corrupted payload with a stale digest column: the recomputed
        // digest from the stored bytes refuses it even though the column
        // never changed.
        let corrupted_payload = format!("{}}}", event_payload); // corrupt JSON tail
        let stale_digest_column =
            crate::memory_v1_apply_records::audit_row_digest(event_payload.as_bytes()).to_vec();
        let corrupted_rows = [joined_row(
            &receipt,
            Some((
                audit_columns("ALLOW", &identity),
                Some(corrupted_payload),
                Some(stale_digest_column),
            )),
            true,
            true,
        )];
        assert!(matches!(
            reconcile_decision(
                &corrupted_rows,
                Some(&tail_at_frame),
                &identity,
                Some(&predecessor_zero),
                Some(&verified_event),
            ),
            MemoryV1ApplyReconciliation::Inconsistent { .. }
        ));
        // Self-consistent payload that differs from the verified frame
        // content: refused by the verified-digest comparison.
        let other_payload = String::from_utf8(
            crate::memory_v1_apply_records::encode_canonical_audit_payload(&other_event).unwrap(),
        )
        .unwrap();
        let foreign_content_rows = [joined_row(
            &receipt,
            Some((audit_columns("ALLOW", &identity), Some(other_payload), None)),
            true,
            true,
        )];
        assert!(matches!(
            reconcile_decision(
                &foreign_content_rows,
                Some(&tail_at_frame),
                &identity,
                Some(&predecessor_zero),
                Some(&verified_event),
            ),
            MemoryV1ApplyReconciliation::Inconsistent { .. }
        ));

        // Position holds a receipt for a different operation only.
        let pos_key_only = [joined_row(&foreign_receipt, None, false, true)];
        assert!(matches!(
            reconcile_decision(
                &pos_key_only,
                Some(&tail_at_frame),
                &identity,
                Some(&predecessor_zero),
                Some(&verified_event),
            ),
            MemoryV1ApplyReconciliation::Inconsistent { .. }
        ));

        // No receipt anywhere, tail exactly on the predecessor WITH the
        // verified predecessor governance sequence: proven not-applied.
        assert_eq!(
            reconcile_decision(
                &[],
                Some(&tail_at_predecessor),
                &identity,
                Some(&predecessor_zero),
                None,
            ),
            MemoryV1ApplyReconciliation::NotApplied
        );
        // A supplied value that contradicts the mutation arithmetic: refused.
        assert!(matches!(
            reconcile_decision(
                &[],
                Some(&tail_at_predecessor),
                &identity,
                Some(&MemoryV1ApplyPredecessor {
                    mutation_sequence: 9
                }),
                None,
            ),
            MemoryV1ApplyReconciliation::Inconsistent { .. }
        ));
        // Wrong predecessor governance sequence on the tail: unprovable.
        let tail_predecessor_wrong_governance = crate::memory_v1_apply_records::ProgressTailRow {
            last_mutation_sequence: 6,
            ..tail_at_predecessor.clone()
        };
        assert!(matches!(
            reconcile_decision(
                &[],
                Some(&tail_predecessor_wrong_governance),
                &identity,
                Some(&predecessor_zero),
                None,
            ),
            MemoryV1ApplyReconciliation::Unknown { .. }
        ));
        // No receipt, but the tail sits on this frame: atomicity violation.
        assert!(matches!(
            reconcile_decision(
                &[],
                Some(&tail_at_frame),
                &identity,
                Some(&predecessor_zero),
                None,
            ),
            MemoryV1ApplyReconciliation::Inconsistent { .. }
        ));
        // No receipt, tail skipped ahead: never skip the conflict.
        assert!(matches!(
            reconcile_decision(
                &[],
                Some(&tail_ahead),
                &identity,
                Some(&predecessor_zero),
                None,
            ),
            MemoryV1ApplyReconciliation::Inconsistent { .. }
        ));
        // No receipt, no progress row: unknowable.
        assert!(matches!(
            reconcile_decision(&[], None, &identity, Some(&predecessor_zero), None),
            MemoryV1ApplyReconciliation::Unknown { .. }
        ));
        // No receipt, cross-epoch tail: unknowable.
        let cross_epoch = crate::memory_v1_apply_records::ProgressTailRow {
            epoch_id: [9; 16].to_vec(),
            ..tail_at_predecessor.clone()
        };
        assert!(matches!(
            reconcile_decision(
                &[],
                Some(&cross_epoch),
                &identity,
                Some(&predecessor_zero),
                None
            ),
            MemoryV1ApplyReconciliation::Unknown { .. }
        ));
        // No receipt, divergent predecessor hash: unknowable.
        let divergent = crate::memory_v1_apply_records::ProgressTailRow {
            last_frame_hash: [8; 32].to_vec(),
            ..tail_at_predecessor
        };
        assert!(matches!(
            reconcile_decision(
                &[],
                Some(&divergent),
                &identity,
                Some(&predecessor_zero),
                None
            ),
            MemoryV1ApplyReconciliation::Unknown { .. }
        ));

        // Historical-read deny at the frame position: the tail governance
        // sequence must equal the verified predecessor EXACTLY; the deny's
        // own observed old sequence never guesses its predecessor.
        let mut deny_identity = deny_identity();
        deny_identity.mutation_sequence = 2;
        let deny_receipt = crate::memory_v1_apply_records::ReceiptRow {
            mutation_sequence: 2,
            outcome: "DENY".to_string(),
            mutation_digest: [0; 32].to_vec(),
            request_fingerprint: deny_identity.request_fingerprint.to_vec(),
            prev_frame_hash: deny_identity.prev_frame_hash.to_vec(),
            frame_digest: deny_identity.frame_digest.to_vec(),
            payload_digest: deny_identity.payload_digest.to_vec(),
            ..receipt.clone()
        };
        let deny_event = deny_event();
        let deny_tail_at_frame = crate::memory_v1_apply_records::ProgressTailRow {
            last_journal_sequence: deny_identity.journal_sequence,
            last_mutation_sequence: 3,
            last_frame_hash: deny_identity.frame_digest.to_vec(),
            epoch_id: deny_identity.epoch_id.as_bytes().to_vec(),
        };
        let deny_payload = String::from_utf8(
            crate::memory_v1_apply_records::encode_canonical_audit_payload(&deny_event).unwrap(),
        )
        .unwrap();
        let deny_audit = (
            audit_columns("DENY:no_match", &deny_identity),
            Some(deny_payload),
            None,
        );
        let deny_rows = [joined_row(&deny_receipt, Some(deny_audit), true, true)];
        // Exact governance position with the verified predecessor: applied.
        assert!(matches!(
            reconcile_decision(
                &deny_rows,
                Some(&deny_tail_at_frame),
                &deny_identity,
                Some(&MemoryV1ApplyPredecessor {
                    mutation_sequence: 3
                }),
                Some(&MemoryV1ApplyVerifiedFrameContent::Event(&deny_event)),
            ),
            MemoryV1ApplyReconciliation::ReceiptMatches(_)
        ));
        // Without the verified predecessor the exact governance position of a
        // historical deny is unprovable.
        assert!(matches!(
            reconcile_decision(
                &deny_rows,
                Some(&deny_tail_at_frame),
                &deny_identity,
                None,
                Some(&MemoryV1ApplyVerifiedFrameContent::Event(&deny_event)),
            ),
            MemoryV1ApplyReconciliation::Unknown { .. }
        ));
        // Wrong verified predecessor governance sequence: inconsistent.
        assert!(matches!(
            reconcile_decision(
                &deny_rows,
                Some(&deny_tail_at_frame),
                &deny_identity,
                Some(&MemoryV1ApplyPredecessor {
                    mutation_sequence: 7
                }),
                Some(&MemoryV1ApplyVerifiedFrameContent::Event(&deny_event)),
            ),
            MemoryV1ApplyReconciliation::Inconsistent { .. }
        ));
    }

    // ─────────────────────────────────────────────────────────────────────
    // Explicitly runnable real-dependency use cases.
    //
    // These tests run ONLY against an isolated, operator-prepared MySQL that
    // already has the candidate tables from
    // `Docs/sql/memory-v1-apply-candidate.sql` created. The tests never
    // execute DDL; they insert their own run-scoped rows (parameterized) and
    // are recorded as SKIP when the dependency is absent — never as PASS.
    // Run explicitly:
    //   RUST_INTEGRATION_REQUIRED=1 \
    //   ASTRAL_MEMORY_V1_APPLY_TEST_MYSQL_URL=mysql://... \
    //   cargo test -p astral-db --lib memory_v1_apply -- --ignored
    // ─────────────────────────────────────────────────────────────────────

    // memory—v1
    async fn real_apply_pool() -> Option<sqlx::MySqlPool> {
        let required = std::env::var("RUST_INTEGRATION_REQUIRED").as_deref() == Ok("1");
        let Ok(url) = std::env::var("ASTRAL_MEMORY_V1_APPLY_TEST_MYSQL_URL") else {
            assert!(
                !required,
                "required isolated memory-v1 apply MySQL dependency is missing"
            );
            eprintln!("[SKIP] isolated memory-v1 apply MySQL dependency is missing");
            return None;
        };
        Some(sqlx::MySqlPool::connect(&url).await.unwrap())
    }

    // memory—v1
    fn random_memory_id() -> MemoryId {
        MemoryId::from_bytes(*uuid::Uuid::new_v4().as_bytes())
    }

    // memory—v1
    async fn seed_reference_rows(pool: &sqlx::MySqlPool) -> (MemoryId, MemoryId) {
        let user_id = random_memory_id();
        let identity_card_id = random_memory_id();
        let tenant_id = random_memory_id();
        sqlx::query("INSERT INTO memory_user (user_id) VALUES (?)")
            .bind(&user_id.as_bytes()[..])
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO memory_identity_card (identity_card_id, user_id) VALUES (?, ?)")
            .bind(&identity_card_id.as_bytes()[..])
            .bind(&user_id.as_bytes()[..])
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO memory_tenant (tenant_id) VALUES (?)")
            .bind(&tenant_id.as_bytes()[..])
            .execute(pool)
            .await
            .unwrap();
        (user_id, tenant_id)
    }

    /// Happy path: apply one authorized user-card-create message, observe the
    /// receipt and progress tail, re-apply the identical message (dedup), and
    /// reconcile the identity on a fresh connection.
    #[tokio::test]
    #[ignore = "requires isolated ASTRAL_MEMORY_V1_APPLY_TEST_MYSQL_URL with the memory-v1 apply candidate tables created"]
    async fn real_mysql_apply_mutation_duplicate_and_reconcile() {
        let Some(pool) = real_apply_pool().await else {
            return;
        };
        let (user_id, tenant_id) = seed_reference_rows(&pool).await;
        let stream_id = random_memory_id();
        let lease = MemoryV1ApplyLease {
            boot_id: random_memory_id(),
            worker_id: format!("it-{}", uuid::Uuid::new_v4().simple()),
            lease_ttl_seconds: 60,
        };
        let token = match claim_memory_v1_apply_lease(&pool, &lease, stream_id)
            .await
            .unwrap()
        {
            MemoryV1ApplyLeaseClaim::Claimed { token } => token,
            other => panic!("claim must succeed, got {other:?}"),
        };
        let epoch_id = random_memory_id();
        let init = initialize_memory_v1_apply_progress(&pool, stream_id, epoch_id, [1; 32])
            .await
            .unwrap();
        assert!(matches!(init, MemoryV1ApplyProgressInit::Initialized));

        let card_id = random_memory_id();
        let mutation_row = UserCardRow {
            user_card_id: card_id.into_bytes(),
            user_id: user_id.into_bytes(),
            tenant_id: tenant_id.into_bytes(),
            status: astral_authorization_root::memory_v1_db_rows::UserCardStatus::Active,
        };
        let mutation = ManagementMutationV2::UserCardCreate { row: mutation_row };
        let operation_id = format!("it-{}", uuid::Uuid::new_v4().simple());
        let audit = sample_audit_event_with_operation(
            MemoryV1AuditObject::UserCard(card_id),
            false,
            MemoryV1AuditOperation::new(&operation_id, [5; 32]).unwrap(),
        );
        let flow = JournalAnchor::new(stream_id, 1, 1, [7; 32]).unwrap();
        let plan = MemoryV1ApplyPlan::build(ApplyPlanInput {
            mutation: &mutation,
            audit: Some(&audit),
            flow: Some(flow),
        });
        assert!(plan.is_complete(), "seeded mutation must plan complete");

        let identity = MemoryV1ApplyIdentity {
            stream_id,
            epoch_id,
            journal_sequence: 1,
            mutation_sequence: 1,
            message_id: random_memory_id(),
            operation_id,
            origin_boot_id: random_memory_id(),
            request_fingerprint: [5; 32],
            prev_frame_hash: [1; 32],
            frame_digest: [7; 32],
            payload_digest: [8; 32],
            frame_kind: MemoryV1ApplyFrameKind::Mutation,
        };
        let outcome = apply_memory_v1_mutation_message(
            &pool,
            MemoryV1ApplyRequest {
                identity: identity.clone(),
                plan,
                audit: &audit,
                fence: token.clone(),
            },
        )
        .await
        .unwrap();
        let first_receipt = match outcome {
            MemoryV1ApplyOutcome::Applied(receipt) => receipt,
            other => panic!("first apply must be Applied, got {other:?}"),
        };
        assert_eq!(first_receipt.operations.as_ref().unwrap().len(), 1);
        assert_eq!(
            first_receipt.identity.origin_boot_id, identity.origin_boot_id,
            "the receipt binds the ORIGINAL message boot id"
        );
        assert_ne!(
            first_receipt.applied_by_boot_id, identity.origin_boot_id,
            "consumer provenance is separate from the original binding"
        );

        let progress = read_memory_v1_apply_progress(&pool, stream_id)
            .await
            .unwrap()
            .expect("progress tail must exist after the genesis apply");
        assert_eq!(progress.last_journal_sequence, 1);
        assert_eq!(progress.last_mutation_sequence, 1);
        assert_eq!(progress.last_frame_hash, identity.frame_digest);

        let reapply_plan = MemoryV1ApplyPlan::build(ApplyPlanInput {
            mutation: &mutation,
            audit: Some(&audit),
            flow: Some(flow),
        });
        let duplicate = apply_memory_v1_mutation_message(
            &pool,
            MemoryV1ApplyRequest {
                identity: identity.clone(),
                plan: reapply_plan,
                audit: &audit,
                fence: token.clone(),
            },
        )
        .await
        .unwrap();
        let duplicate_receipt = match duplicate {
            MemoryV1ApplyOutcome::Duplicate(receipt) => receipt,
            other => panic!("re-apply must be Duplicate, got {other:?}"),
        };
        assert!(duplicate_receipt.operations.is_none());

        let reconciliation = reconcile_memory_v1_unknown_commit(
            &pool,
            MemoryV1ApplyReconciliationInput {
                identity: identity.clone(),
                predecessor: Some(MemoryV1ApplyPredecessor {
                    mutation_sequence: identity.mutation_sequence - 1,
                }),
                verified_content: Some(MemoryV1ApplyVerifiedFrameContent::Event(&audit)),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            reconciliation,
            MemoryV1ApplyReconciliation::ReceiptMatches(_)
        ));

        // Renewal rotates the generation: the old token can neither release
        // nor apply, and the renewed token still can.
        let stale_token = token.clone();
        let renewed = renew_memory_v1_apply_lease(&pool, &token, stream_id, 60)
            .await
            .unwrap();
        let new_token = match renewed {
            MemoryV1ApplyLeaseRenew::Renewed { token } => token,
            other => panic!("live-lease renewal must succeed, got {other:?}"),
        };
        assert_ne!(
            new_token.fence_generation, stale_token.fence_generation,
            "every renewal rotates the fence generation"
        );
        let released = release_memory_v1_apply_lease(&pool, &stale_token, stream_id)
            .await
            .unwrap();
        assert_eq!(released, 0, "a stale token cannot release the fence");

        // In-transaction misuse: the stale token's apply is refused by the
        // fence verification (owner + generation + expiry under the row lock)
        // before any dedup or fact write runs.
        let reapply_plan = MemoryV1ApplyPlan::build(ApplyPlanInput {
            mutation: &mutation,
            audit: Some(&audit),
            flow: Some(flow),
        });
        let stale_apply = apply_memory_v1_mutation_message(
            &pool,
            MemoryV1ApplyRequest {
                identity: identity.clone(),
                plan: reapply_plan,
                audit: &audit,
                fence: stale_token,
            },
        )
        .await
        .unwrap();
        match stale_apply {
            MemoryV1ApplyOutcome::Denied(denial) => {
                assert_eq!(
                    denial.reason,
                    MemoryV1ApplyDenialReason::FenceGenerationMismatch,
                    "a stale token cannot drive an apply transaction"
                );
            }
            other => panic!("stale-token apply must be Denied, got {other:?}"),
        }

        release_memory_v1_apply_lease(&pool, &new_token, stream_id)
            .await
            .unwrap();
    }

    /// A deny frame applies its audit row and advances only the journal
    /// sequence; the mutation sequence stays at the external baseline.
    #[tokio::test]
    #[ignore = "requires isolated ASTRAL_MEMORY_V1_APPLY_TEST_MYSQL_URL with the memory-v1 apply candidate tables created"]
    async fn real_mysql_apply_deny_advances_journal_only() {
        let Some(pool) = real_apply_pool().await else {
            return;
        };
        let stream_id = random_memory_id();
        let lease = MemoryV1ApplyLease {
            boot_id: random_memory_id(),
            worker_id: format!("it-{}", uuid::Uuid::new_v4().simple()),
            lease_ttl_seconds: 60,
        };
        let token = match claim_memory_v1_apply_lease(&pool, &lease, stream_id)
            .await
            .unwrap()
        {
            MemoryV1ApplyLeaseClaim::Claimed { token } => token,
            other => panic!("claim must succeed, got {other:?}"),
        };
        let epoch_id = random_memory_id();
        let init = initialize_memory_v1_apply_progress(&pool, stream_id, epoch_id, [2; 32])
            .await
            .unwrap();
        assert!(matches!(init, MemoryV1ApplyProgressInit::Initialized));

        let operation_id = format!("it-deny-{}", uuid::Uuid::new_v4().simple());
        let deny_audit = {
            let operation = MemoryV1AuditOperation::new(&operation_id, [5; 32]).unwrap();
            let context = MemoryV1AuditContext::new(
                MemoryV1AuditActor::new(random_memory_id(), random_memory_id()),
                MemoryV1AuditTime::new(50).unwrap(),
                MemoryV1AuditAction::new("memory_v1", "read").unwrap(),
                "NO_MATCH",
                operation,
                MemoryV1AuditRootObservation::new(
                    MemoryV1AuditRootVersion::new(random_memory_id(), 1),
                    [4; 32],
                    MemoryV1AuditRootStatus::Serving,
                ),
            )
            .unwrap();
            MemoryV1AuditEvent::read(
                context,
                MemoryV1AuditDecisionInput::Deny(MemoryV1AuditDenySource::NoMatch),
            )
            .unwrap()
        };
        let identity = MemoryV1ApplyIdentity {
            stream_id,
            epoch_id,
            journal_sequence: 1,
            mutation_sequence: 0,
            message_id: random_memory_id(),
            operation_id,
            origin_boot_id: random_memory_id(),
            request_fingerprint: [5; 32],
            prev_frame_hash: [2; 32],
            frame_digest: [9; 32],
            payload_digest: [10; 32],
            frame_kind: MemoryV1ApplyFrameKind::Deny,
        };
        let outcome = apply_memory_v1_deny_message(
            &pool,
            MemoryV1ApplyDenyRequest {
                identity: identity.clone(),
                audit: &deny_audit,
                fence: token.clone(),
            },
        )
        .await
        .unwrap();
        let receipt = match outcome {
            MemoryV1ApplyOutcome::Applied(receipt) => receipt,
            other => panic!("deny apply must be Applied, got {other:?}"),
        };
        assert_eq!(receipt.outcome, "DENY");
        assert_eq!(receipt.fact_operation_count, 0);

        let progress = read_memory_v1_apply_progress(&pool, stream_id)
            .await
            .unwrap()
            .expect("progress tail must exist after the deny apply");
        assert_eq!(progress.last_journal_sequence, 1);
        assert_eq!(
            progress.last_mutation_sequence, 0,
            "a deny frame never advances the mutation sequence"
        );
        assert_eq!(progress.last_frame_hash, identity.frame_digest);

        release_memory_v1_apply_lease(&pool, &token, stream_id)
            .await
            .unwrap();
    }

    /// A gap in the durable prefix is a fail-closed DENY: applying frame two
    /// to a stream whose tail is absent must refuse without writing.
    #[tokio::test]
    #[ignore = "requires isolated ASTRAL_MEMORY_V1_APPLY_TEST_MYSQL_URL with the memory-v1 apply candidate tables created"]
    async fn real_mysql_progress_gap_denies_apply() {
        let Some(pool) = real_apply_pool().await else {
            return;
        };
        let (user_id, tenant_id) = seed_reference_rows(&pool).await;
        let stream_id = random_memory_id();
        let lease = MemoryV1ApplyLease {
            boot_id: random_memory_id(),
            worker_id: format!("it-{}", uuid::Uuid::new_v4().simple()),
            lease_ttl_seconds: 60,
        };
        let token = match claim_memory_v1_apply_lease(&pool, &lease, stream_id)
            .await
            .unwrap()
        {
            MemoryV1ApplyLeaseClaim::Claimed { token } => token,
            other => panic!("claim must succeed, got {other:?}"),
        };

        let card_id = random_memory_id();
        let mutation_row = UserCardRow {
            user_card_id: card_id.into_bytes(),
            user_id: user_id.into_bytes(),
            tenant_id: tenant_id.into_bytes(),
            status: astral_authorization_root::memory_v1_db_rows::UserCardStatus::Active,
        };
        let mutation = ManagementMutationV2::UserCardCreate { row: mutation_row };
        let operation_id = format!("it-{}", uuid::Uuid::new_v4().simple());
        let audit = sample_audit_event_with_operation(
            MemoryV1AuditObject::UserCard(card_id),
            false,
            MemoryV1AuditOperation::new(&operation_id, [5; 32]).unwrap(),
        );
        // The plan pretends frame two follows frame one; no pre-seeded
        // progress row exists, so the executor must refuse the gap.
        let flow = JournalAnchor::new(stream_id, 2, 1, [7; 32]).unwrap();
        let plan = MemoryV1ApplyPlan::build(ApplyPlanInput {
            mutation: &mutation,
            audit: Some(&audit),
            flow: Some(flow),
        });
        let identity = MemoryV1ApplyIdentity {
            stream_id,
            epoch_id: random_memory_id(),
            journal_sequence: 2,
            mutation_sequence: 1,
            message_id: random_memory_id(),
            operation_id,
            origin_boot_id: random_memory_id(),
            request_fingerprint: [5; 32],
            prev_frame_hash: [1; 32],
            frame_digest: [7; 32],
            payload_digest: [8; 32],
            frame_kind: MemoryV1ApplyFrameKind::Mutation,
        };
        let outcome = apply_memory_v1_mutation_message(
            &pool,
            MemoryV1ApplyRequest {
                identity: identity.clone(),
                plan,
                audit: &audit,
                fence: token.clone(),
            },
        )
        .await
        .unwrap();
        match outcome {
            MemoryV1ApplyOutcome::Denied(denial) => {
                assert_eq!(
                    denial.reason,
                    MemoryV1ApplyDenialReason::ProgressDiscontinuity,
                    "a progress gap must be a fail-closed discontinuity denial"
                );
            }
            other => panic!("gap apply must be Denied, got {other:?}"),
        }
        assert!(read_memory_v1_apply_progress(&pool, stream_id)
            .await
            .unwrap()
            .is_none());
        let reconciliation = reconcile_memory_v1_unknown_commit(
            &pool,
            MemoryV1ApplyReconciliationInput {
                identity,
                predecessor: None,
                verified_content: None,
            },
        )
        .await
        .unwrap();
        // Without a pre-seeded progress row the state proves nothing: the
        // answer is UNKNOWN, never a guessed NotApplied.
        assert!(matches!(
            reconciliation,
            MemoryV1ApplyReconciliation::Unknown { .. }
        ));

        release_memory_v1_apply_lease(&pool, &token, stream_id)
            .await
            .unwrap();
    }
}
