//! memory—v1 apply durable-tail records: canonical audit encoding, receipt,
//! progress, and worker-fence SQL candidates.
//!
//! This module owns the physical record shapes for the P0 database apply
//! executor (`astral-db/src/memory_v1_apply.rs`): the append-only audit row,
//! the operation receipt, the per-stream apply progress, and the worker lease.
//! Every statement here is a static, parameterized SQL string; no value is
//! ever interpolated into SQL text. The candidate tables are declared in
//! `Docs/sql/memory-v1-apply-candidate.sql` and are NOT auto-executed by this
//! crate; nothing here creates, migrates, or adopts the schema.
//!
//! Per §15.10.4 and 全新数据库设计 §7 item 7/9: facts, the append-only audit
//! row, the operation receipt, and consumption progress are committed in one
//! MySQL transaction; the receipt binds the stable operation identity, the
//! message sequence, and content digests. Nothing written here authorizes:
//! database rows are never an ALLOW, and this module performs no permission
//! decision.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use astral_authorization_root::memory_v1_db_rows::{
    BindingLayer, BindingRow, RuleSetRow, RuleSetStatus, UserCardRow, UserCardStatus,
};
use astral_authorization_root::memory_v1_rules::{MemoryV1OwnerScope, MemoryV1TenantScope};
use astral_types::memory_v1::MemoryId;
use astral_types::memory_v1_audit::{
    MemoryV1AuditAction, MemoryV1AuditBindingState, MemoryV1AuditCardState, MemoryV1AuditChange,
    MemoryV1AuditConfirmationRef, MemoryV1AuditConfirmationState, MemoryV1AuditDecision,
    MemoryV1AuditDenySource, MemoryV1AuditEvent, MemoryV1AuditObject, MemoryV1AuditObjectState,
    MemoryV1AuditOperation, MemoryV1AuditRegistryState, MemoryV1AuditRootObservation,
    MemoryV1AuditRootStatus, MemoryV1AuditRuleSetState, MemoryV1AuditRuleSetStatus,
    MemoryV1AuditSource,
};

use crate::memory_v1_apply::{
    MemoryV1ApplyFenceToken, MemoryV1ApplyIdentity, MemoryV1ApplyLease, MemoryV1ApplyLeaseClaim,
    MemoryV1ApplyLeaseRenew, MemoryV1ApplyProgressRow,
};

/// Domain separator for the audit-row content digest stored in the receipt.
const AUDIT_ROW_DIGEST_DOMAIN: &[u8] = b"astrallight/memory-v1/apply/audit-row/1\0";
/// Domain separator for the deterministic audit-row identifier.
const AUDIT_ROW_ID_DOMAIN: &[u8] = b"astrallight/memory-v1/apply/audit-row-id/1\0";

// ─────────────────────────────────────────────────────────────────────────────
// Static parameterized SQL. Every placeholder is `?`; no value is formatted
// into any statement. Keep every statement registered in ALL_APPLY_RECORD_SQL
// so the offline guard test can prove the placeholder-only invariant.
// ─────────────────────────────────────────────────────────────────────────────

/// Read the apply-fence row with a row lock, evaluating lease validity on the
/// server clock to avoid client/server clock trust.
pub const FENCE_SELECT_FOR_UPDATE_SQL: &str = "SELECT owner_boot_id, CONVERT(owner_worker_id USING utf8mb4), fence_generation, CAST(COALESCE(lease_expires_at > UTC_TIMESTAMP(6), 0) AS SIGNED) AS lease_valid FROM mv1_apply_fence WHERE stream_id = ? FOR UPDATE";

/// CAS lease claim: only a never-leased or expired fence row may be taken.
/// A live lease (even held by the same boot/worker) must be renewed with its
/// exact generation token; this keeps every token explicit and rotating.
pub const FENCE_CLAIM_CAS_UPDATE_SQL: &str = "UPDATE mv1_apply_fence SET owner_boot_id = ?, owner_worker_id = ?, lease_expires_at = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND), fence_generation = fence_generation + 1 WHERE stream_id = ? AND (lease_expires_at IS NULL OR lease_expires_at <= UTC_TIMESTAMP(6))";

/// CAS lease renewal: the presented token must still be the current owner,
/// generation, and unexpired; each renewal rotates the generation, so every
/// previously issued token for this stream is invalidated.
pub const FENCE_RENEW_CAS_UPDATE_SQL: &str = "UPDATE mv1_apply_fence SET lease_expires_at = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND), fence_generation = fence_generation + 1 WHERE stream_id = ? AND owner_boot_id = ? AND owner_worker_id = ? AND fence_generation = ? AND lease_expires_at > UTC_TIMESTAMP(6)";

/// Insert a fence row for a stream that has never been leased.
pub const FENCE_INSERT_SQL: &str = "INSERT INTO mv1_apply_fence (stream_id, owner_boot_id, owner_worker_id, lease_expires_at, fence_generation) VALUES (?, ?, ?, DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND), 1)";

/// Owner-only release: the presented token must still be the current owner,
/// generation, and unexpired. An expired lease cannot be released through
/// this path (it is reclaimable through the CAS claim).
pub const FENCE_RELEASE_UPDATE_SQL: &str = "UPDATE mv1_apply_fence SET lease_expires_at = UTC_TIMESTAMP(6) WHERE stream_id = ? AND owner_boot_id = ? AND owner_worker_id = ? AND fence_generation = ? AND lease_expires_at > UTC_TIMESTAMP(6)";

/// Read the current fence owner without a lock (claim bookkeeping).
pub const FENCE_SELECT_OWNER_SQL: &str = "SELECT owner_boot_id, CONVERT(owner_worker_id USING utf8mb4), fence_generation FROM mv1_apply_fence WHERE stream_id = ?";

/// Read the monotonic fence generation after a successful claim.
pub const FENCE_SELECT_GENERATION_SQL: &str =
    "SELECT fence_generation FROM mv1_apply_fence WHERE stream_id = ?";

/// Receipt lookup by the stable operation identity (dedup path).
pub const RECEIPT_SELECT_BY_OPERATION_SQL: &str = "SELECT stream_id, epoch_id, journal_sequence, mutation_sequence, message_id, CONVERT(operation_id USING utf8mb4) AS operation_id, boot_id, applied_by_boot_id, CONVERT(worker_id USING utf8mb4) AS worker_id, CONVERT(outcome USING utf8mb4) AS outcome, request_fingerprint, prev_frame_hash, frame_digest, payload_digest, mutation_digest, audit_row_digest, fact_operation_count, fact_rows_affected_total FROM mv1_apply_receipt WHERE operation_id = ?";

/// Receipt lookup by stream position.
pub const RECEIPT_SELECT_BY_STREAM_SEQ_SQL: &str = "SELECT stream_id, epoch_id, journal_sequence, mutation_sequence, message_id, CONVERT(operation_id USING utf8mb4) AS operation_id, boot_id, applied_by_boot_id, CONVERT(worker_id USING utf8mb4) AS worker_id, CONVERT(outcome USING utf8mb4) AS outcome, request_fingerprint, prev_frame_hash, frame_digest, payload_digest, mutation_digest, audit_row_digest, fact_operation_count, fact_rows_affected_total FROM mv1_apply_receipt WHERE stream_id = ? AND journal_sequence = ?";

/// Append-only receipt insert. All identity and digest columns are bound
/// values; `applied_at` is server time. `boot_id` is the ORIGINAL message's
/// boot identity; `applied_by_boot_id` is the consumer's boot identity.
pub const RECEIPT_INSERT_SQL: &str = "INSERT INTO mv1_apply_receipt (stream_id, journal_sequence, epoch_id, mutation_sequence, message_id, operation_id, boot_id, applied_by_boot_id, worker_id, request_fingerprint, prev_frame_hash, frame_digest, payload_digest, mutation_digest, audit_row_digest, fact_operation_count, fact_rows_affected_total, outcome) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

// Keep the actual receipt and audit columns identical across the runtime and
// startup readers. The caller supplies only static SQL after the projection.
macro_rules! receipt_audit_query {
    ($select:literal, $keys:literal, $tables:literal) => {
        concat!(
            $select,
            "r.stream_id AS stream_id, r.epoch_id AS epoch_id, \
             r.journal_sequence AS journal_sequence, r.mutation_sequence AS mutation_sequence, \
             r.message_id AS message_id, CONVERT(r.operation_id USING utf8mb4) AS operation_id, \
             r.boot_id AS boot_id, r.applied_by_boot_id AS applied_by_boot_id, \
             CONVERT(r.worker_id USING utf8mb4) AS worker_id, CONVERT(r.outcome USING utf8mb4) AS outcome, \
             r.request_fingerprint AS request_fingerprint, r.prev_frame_hash AS prev_frame_hash, \
             r.frame_digest AS frame_digest, r.payload_digest AS payload_digest, \
             r.mutation_digest AS mutation_digest, r.audit_row_digest AS audit_row_digest, \
             r.fact_operation_count AS fact_operation_count, r.fact_rows_affected_total AS fact_rows_affected_total, \
             a.audit_row_digest AS audit_row_digest_value, CONVERT(a.decision USING utf8mb4) AS audit_decision, \
             a.epoch_id AS audit_epoch_id, a.journal_sequence AS audit_journal_sequence, \
             a.mutation_sequence AS audit_mutation_sequence, a.message_id AS audit_message_id, \
             CONVERT(a.operation_id USING utf8mb4) AS audit_operation_id, ",
            $keys,
            $tables,
            " LEFT JOIN mv1_apply_audit_event a ON a.operation_id = r.operation_id \
             AND a.stream_id = r.stream_id AND a.journal_sequence = r.journal_sequence",
        )
    };
}

/// One merged reconciliation read: the receipt matched by EITHER unique key,
/// joined with its independent append-only audit row (LEFT JOIN on the
/// receipt's stream position and operation id), including the audit row's
/// canonical payload so its digest can be recomputed from the ACTUAL bytes.
/// This keeps per-frame recovery at two locked round trips (this + progress).
pub const RECEIPT_AUDIT_MERGED_FOR_UPDATE_SQL: &str = concat!(
    receipt_audit_query!(
        "SELECT ",
        "CONVERT(a.canonical_payload USING utf8mb4) AS audit_canonical_payload, \
         CAST((r.operation_id = ?) AS SIGNED) AS matched_by_operation, \
         CAST((r.stream_id = ? AND r.journal_sequence = ?) AS SIGNED) AS matched_by_position",
        " FROM mv1_apply_receipt r"
    ),
    " WHERE r.operation_id = ? OR (r.stream_id = ? AND r.journal_sequence = ?) FOR UPDATE",
);

// memory—v1: Resolve BOTH unique receipt keys and the exact progress row in
// the same locking read. A missing key, split match or changed progress omits
// the input ordinal, which the startup verifier refuses. Bound the payload
// projected by the server before sending it to the Rust verifier. Start from
// the bounded key list so acquiring locks never scans the retained stream.
const VERIFIED_PREFIX_BATCH_SQL: &str = concat!(
    receipt_audit_query!(
        "SELECT STRAIGHT_JOIN ",
        "CASE WHEN OCTET_LENGTH(CONVERT(a.canonical_payload USING utf8mb4)) <= ? \
         THEN CONVERT(a.canonical_payload USING utf8mb4) END AS audit_canonical_payload, \
         CAST(1 AS SIGNED) AS matched_by_operation, CAST(1 AS SIGNED) AS matched_by_position, \
         CAST(w.ordinal AS UNSIGNED) AS ordinal",
        " FROM JSON_TABLE(?, '$[*]' COLUMNS(ordinal FOR ORDINALITY, \
         journal_sequence BIGINT UNSIGNED PATH '$[0]' ERROR ON EMPTY ERROR ON ERROR, \
         operation_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin PATH '$[1]' ERROR ON EMPTY ERROR ON ERROR)) w \
         INNER JOIN mv1_apply_receipt op FORCE INDEX (uq_mv1_apply_receipt_operation) ON op.operation_id = w.operation_id \
         INNER JOIN mv1_apply_receipt r FORCE INDEX (PRIMARY) ON r.stream_id = ? AND r.journal_sequence = w.journal_sequence \
         AND r.operation_id = op.operation_id AND op.stream_id = r.stream_id \
         AND op.journal_sequence = r.journal_sequence \
         INNER JOIN mv1_apply_progress p ON p.stream_id = r.stream_id \
         AND p.epoch_id = ? AND p.last_journal_sequence = ? AND p.last_mutation_sequence = ? AND p.last_frame_hash = ?"
    ),
    " FOR SHARE OF op, r, p, a",
);

/// One merged receipt+audit row as read by the reconciliation query. The
/// audit columns are `None` when the receipt exists without its independent
/// audit row (an atomicity anomaly the executor reports as Inconsistent).
#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
pub(crate) struct ReceiptAuditJoinedRow {
    #[sqlx(flatten)]
    pub receipt: ReceiptRow,
    pub matched_by_operation: i64,
    pub matched_by_position: i64,
    pub audit_row_digest_value: Option<Vec<u8>>,
    pub audit_decision: Option<String>,
    pub audit_epoch_id: Option<Vec<u8>>,
    pub audit_journal_sequence: Option<u64>,
    pub audit_mutation_sequence: Option<u64>,
    pub audit_message_id: Option<Vec<u8>>,
    pub audit_operation_id: Option<String>,
    /// The audit row's stored canonical payload (JSON text), read so the
    /// executor can recompute its digest from the ACTUAL bytes — a digest
    /// column that stayed constant across corrupted content is refused.
    pub audit_canonical_payload: Option<String>,
}

// memory—v1
impl ReceiptAuditJoinedRow {
    /// Whether this row was matched by the operation-id unique key.
    // memory—v1
    pub(crate) fn matched_by_operation(&self) -> bool {
        self.matched_by_operation == 1
    }

    /// Whether this row was matched by the stream-position unique key.
    // memory—v1
    pub(crate) fn matched_by_position(&self) -> bool {
        self.matched_by_position == 1
    }
}

/// Read the receipt rows (with their joined audit rows) matched by either
/// unique key, under row locks inside the reconciliation transaction.
// memory—v1
pub(crate) async fn read_receipts_with_audit_for_update(
    tx: &mut crate::memory_v1_apply_facts::ApplyTx<'_>,
    operation_id: &str,
    stream_id: &MemoryId,
    journal_sequence: u64,
) -> Result<Vec<ReceiptAuditJoinedRow>, sqlx::Error> {
    let rows: Vec<ReceiptAuditJoinedRow> = sqlx::query_as(RECEIPT_AUDIT_MERGED_FOR_UPDATE_SQL)
        .bind(operation_id)
        .bind(id_bytes(stream_id))
        .bind(journal_sequence)
        .bind(operation_id)
        .bind(id_bytes(stream_id))
        .bind(journal_sequence)
        .fetch_all(&mut **tx)
        .await?;
    Ok(rows)
}

/// One ordinal is returned only when both receipt indexes and the expected
/// progress matched in the locking statement. The audit can still be missing.
#[derive(sqlx::FromRow)]
pub(super) struct PrefixReceiptRow {
    pub ordinal: u64,
    #[sqlx(flatten)]
    pub joined: ReceiptAuditJoinedRow,
}

// memory—v1: Stream results so the verifier holds only one stored audit value.
pub(super) fn stream_verified_prefix_rows<'a>(
    tx: &'a mut crate::memory_v1_apply_facts::ApplyTx<'_>,
    stream: &MemoryId,
    progress: &MemoryV1ApplyProgressRow,
    keys_json: String,
) -> impl futures_util::Stream<Item = Result<PrefixReceiptRow, sqlx::Error>> + 'a {
    // JSON can expand the bounded journal payload when audit bytes are written
    // as hex. Leave room for the JSON projection around that payload.
    const MAX_STORED_AUDIT_BYTES: u32 =
        2 * astral_types::memory_v1_journal::MAX_PAYLOAD_BYTES as u32 + 64 * 1024;
    sqlx::query_as(VERIFIED_PREFIX_BATCH_SQL)
        .bind(MAX_STORED_AUDIT_BYTES)
        .bind(keys_json)
        .bind(id_bytes(stream).to_vec())
        .bind(id_bytes(&progress.epoch_id).to_vec())
        .bind(progress.last_journal_sequence)
        .bind(progress.last_mutation_sequence)
        .bind(progress.last_frame_hash.to_vec())
        .fetch(&mut **tx)
}

/// Read the per-stream apply progress tail with a row lock.
pub const PROGRESS_SELECT_FOR_UPDATE_SQL: &str = "SELECT epoch_id, last_journal_sequence, last_mutation_sequence, last_frame_hash FROM mv1_apply_progress WHERE stream_id = ? FOR UPDATE";

/// Read the per-stream apply progress tail without a lock (status views).
pub const PROGRESS_SELECT_SQL: &str = "SELECT epoch_id, last_journal_sequence, last_mutation_sequence, last_frame_hash FROM mv1_apply_progress WHERE stream_id = ?";

/// Explicit genesis pre-seed insert: sequence zero on both counters and the
/// externally supplied genesis anchor hash. A missing row is never a trusted
/// genesis; the row must exist before the first frame is applied.
pub const PROGRESS_PRESEED_SQL: &str = "INSERT INTO mv1_apply_progress (stream_id, epoch_id, last_journal_sequence, last_mutation_sequence, last_frame_hash) VALUES (?, ?, ?, ?, ?)";

/// Contiguous CAS advance for a mutation frame: the previous tail must still
/// be the row's tail; both sequences advance.
pub const PROGRESS_ADVANCE_CAS_SQL: &str = "UPDATE mv1_apply_progress SET epoch_id = ?, last_journal_sequence = ?, last_mutation_sequence = ?, last_frame_hash = ? WHERE stream_id = ? AND last_journal_sequence = ?";

/// Contiguous CAS advance for a deny frame: the journal sequence advances but
/// the mutation sequence stays put (a DENY reads authorization state, it does
/// not change it).
pub const PROGRESS_ADVANCE_DENY_SQL: &str = "UPDATE mv1_apply_progress SET last_journal_sequence = ?, last_frame_hash = ? WHERE stream_id = ? AND last_journal_sequence = ?";

/// Append-only audit row insert. The row is written once per message.
/// Time semantics are explicit: `audit_time_unix` is only bound when the
/// value carries an engine trusted time; `read_started_at_unix` is only
/// bound for raw deny observations and is the OBSERVED read-start sample,
/// never a final trusted time. Neither is invented.
pub const AUDIT_INSERT_SQL: &str = "INSERT INTO mv1_apply_audit_event (audit_id, stream_id, epoch_id, journal_sequence, mutation_sequence, message_id, operation_id, decision, reason_code, actor_user_id, actor_identity_card_id, resource, action, audit_time_unix, read_started_at_unix, root_instance_id, root_version, root_content_hash, root_status, target_kind, target_id, change_summary, canonical_payload, audit_row_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

/// Every statement above, for the offline parameterization guard test.
pub const ALL_APPLY_RECORD_SQL: &[&str] = &[
    FENCE_SELECT_FOR_UPDATE_SQL,
    FENCE_CLAIM_CAS_UPDATE_SQL,
    FENCE_RENEW_CAS_UPDATE_SQL,
    FENCE_INSERT_SQL,
    FENCE_RELEASE_UPDATE_SQL,
    FENCE_SELECT_OWNER_SQL,
    FENCE_SELECT_GENERATION_SQL,
    RECEIPT_SELECT_BY_OPERATION_SQL,
    RECEIPT_SELECT_BY_STREAM_SEQ_SQL,
    RECEIPT_AUDIT_MERGED_FOR_UPDATE_SQL,
    VERIFIED_PREFIX_BATCH_SQL,
    RECEIPT_INSERT_SQL,
    PROGRESS_SELECT_FOR_UPDATE_SQL,
    PROGRESS_SELECT_SQL,
    PROGRESS_PRESEED_SQL,
    PROGRESS_ADVANCE_CAS_SQL,
    PROGRESS_ADVANCE_DENY_SQL,
    AUDIT_INSERT_SQL,
];

// memory—v1
fn id_bytes(id: &MemoryId) -> &[u8] {
    id.as_bytes()
}

// ─────────────────────────────────────────────────────────────────────────────
// Canonical audit encoding
// ─────────────────────────────────────────────────────────────────────────────

/// Encode one audit object as a canonical JSON value. Binary values are
/// lowercase hex; identifiers keep the canonical UUID text form.
// memory—v1
pub fn encode_audit_object(object: MemoryV1AuditObject) -> Value {
    let (kind, id) = match object {
        MemoryV1AuditObject::Tenant(id) => ("tenant", id),
        MemoryV1AuditObject::UserCard(id) => ("user_card", id),
        MemoryV1AuditObject::RuleSet(id) => ("rule_set", id),
        MemoryV1AuditObject::Binding(id) => ("binding", id),
        MemoryV1AuditObject::Confirmation(id) => ("confirmation", id),
        MemoryV1AuditObject::User(id) => ("user", id),
    };
    json!({ "kind": kind, "id": id.to_string() })
}

/// Encode one observed before/after object state. `Absent` is an explicit
/// observation, not a missing field.
// memory—v1
pub fn encode_audit_object_state(state: &MemoryV1AuditObjectState) -> Value {
    match state {
        MemoryV1AuditObjectState::Absent => json!({ "kind": "absent" }),
        MemoryV1AuditObjectState::UserCard(state) => match state {
            MemoryV1AuditCardState::Active => json!({ "kind": "user_card", "state": "ACTIVE" }),
            MemoryV1AuditCardState::Disabled => json!({ "kind": "user_card", "state": "DISABLED" }),
        },
        MemoryV1AuditObjectState::Binding(state) => match state {
            MemoryV1AuditBindingState::Active => json!({ "kind": "binding", "state": "ACTIVE" }),
            MemoryV1AuditBindingState::Removed => json!({ "kind": "binding", "state": "REMOVED" }),
        },
        MemoryV1AuditObjectState::Confirmation(state) => match state {
            MemoryV1AuditConfirmationState::Active => {
                json!({ "kind": "confirmation", "state": "ACTIVE" })
            }
            MemoryV1AuditConfirmationState::Revoked => {
                json!({ "kind": "confirmation", "state": "REVOKED" })
            }
        },
        MemoryV1AuditObjectState::Registry(state) => match state {
            MemoryV1AuditRegistryState::Active => json!({ "kind": "registry", "state": "ACTIVE" }),
            MemoryV1AuditRegistryState::RetireRequested => {
                json!({ "kind": "registry", "state": "RETIRE_REQUESTED" })
            }
            MemoryV1AuditRegistryState::Retired => {
                json!({ "kind": "registry", "state": "RETIRED" })
            }
        },
        MemoryV1AuditObjectState::RuleSet(state) => encode_rule_set_state(state),
    }
}

// memory—v1
fn encode_rule_set_state(state: &MemoryV1AuditRuleSetState) -> Value {
    let status = match state.status() {
        Some(MemoryV1AuditRuleSetStatus::Active) => json!("ACTIVE"),
        Some(MemoryV1AuditRuleSetStatus::Retired) => json!("RETIRED"),
        // A legacy version/hash-only record has no lifecycle observation; the
        // encoding preserves "unknown" instead of inventing a status.
        None => Value::Null,
    };
    json!({
        "kind": "rule_set",
        "current_version_hex": hex::encode(state.current_version()),
        "content_hash_hex": hex::encode(state.content_hash()),
        "status": status,
    })
}

/// Encode the decision as a frozen token. A DENY keeps its internal source.
// memory—v1
pub fn encode_decision(decision: MemoryV1AuditDecision) -> &'static str {
    match decision {
        MemoryV1AuditDecision::Allow => "ALLOW",
        MemoryV1AuditDecision::Deny(DenySource::RuleDeny) => "DENY:rule_deny",
        MemoryV1AuditDecision::Deny(DenySource::NoMatch) => "DENY:no_match",
        MemoryV1AuditDecision::Deny(DenySource::ScopeDenied) => "DENY:scope_denied",
        MemoryV1AuditDecision::Deny(DenySource::CardUnbound) => "DENY:card_unbound",
        MemoryV1AuditDecision::Deny(DenySource::IdentityMismatch) => "DENY:identity_mismatch",
        MemoryV1AuditDecision::Deny(DenySource::UnregisteredResource) => {
            "DENY:unregistered_resource"
        }
        MemoryV1AuditDecision::Deny(DenySource::SelfConfirmation) => "DENY:self_confirmation",
        MemoryV1AuditDecision::Deny(DenySource::CardDisabled) => "DENY:card_disabled",
        MemoryV1AuditDecision::Deny(DenySource::OverlayOnlyCreation) => {
            "DENY:overlay_only_creation"
        }
    }
}

// memory—v1
use MemoryV1AuditDenySource as DenySource;

/// Encode one confirmations value without guessing unobserved facts.
// memory—v1
fn encode_confirmations(
    confirmations: &astral_types::memory_v1_audit::MemoryV1AuditConfirmations,
) -> Value {
    use astral_types::memory_v1_audit::MemoryV1AuditConfirmationBatchItem;
    if confirmations.is_not_applicable() {
        return json!({ "kind": "not_applicable" });
    }
    if let Some(references) = confirmations.as_references() {
        let refs: Vec<Value> = references.iter().map(encode_confirmation_ref).collect();
        return json!({ "kind": "references", "refs": refs });
    }
    if let Some(batch) = confirmations.as_batch() {
        let items: Vec<Value> = batch
            .items()
            .iter()
            .map(|item: &MemoryV1AuditConfirmationBatchItem| {
                json!({
                    "sequence": item.sequence(),
                    "confirmation": encode_confirmation_ref(&item.confirmation()),
                })
            })
            .collect();
        return json!({
            "kind": "batch",
            "operation_id": batch.operation().id(),
            "items": items,
        });
    }
    // Unreachable through the public constructors; kept explicit so a future
    // variant cannot silently drop facts.
    Value::Null
}

// memory—v1
fn encode_confirmation_ref(reference: &MemoryV1AuditConfirmationRef) -> Value {
    let kind = match reference {
        MemoryV1AuditConfirmationRef::Binding(_) => "binding",
        MemoryV1AuditConfirmationRef::RuleSetChange(_) => "rule_set_change",
    };
    json!({ "kind": kind, "id": reference.confirmation_id().to_string() })
}

/// Encode one optional special source marker.
// memory—v1
fn encode_source(source: MemoryV1AuditSource) -> Value {
    match source {
        MemoryV1AuditSource::Ordinary => json!("ordinary"),
        MemoryV1AuditSource::OverlayOnlyCreation(overlay) => json!({
            "kind": "overlay_only_creation",
            "creator": overlay.creator().to_string(),
            "beneficiary": overlay.beneficiary().to_string(),
            "rule_set": overlay.rule_set().to_string(),
        }),
    }
}

// memory—v1
fn encode_root_version(version: astral_types::memory_v1_audit::MemoryV1AuditRootVersion) -> Value {
    json!({ "instance": version.instance().to_string(), "version": version.version() })
}

// memory—v1
fn encode_root_observation(observation: &MemoryV1AuditRootObservation) -> Value {
    let status = match observation.status() {
        MemoryV1AuditRootStatus::Candidate => "CANDIDATE",
        MemoryV1AuditRootStatus::Serving => "SERVING",
        MemoryV1AuditRootStatus::Invalid => "INVALID",
        MemoryV1AuditRootStatus::Stopped => "STOPPED",
    };
    json!({
        "instance": observation.version().instance().to_string(),
        "version": observation.version().version(),
        "content_hash_hex": hex::encode(observation.content_hash()),
        "status": status,
    })
}

// memory—v1
fn encode_change(change: &MemoryV1AuditChange) -> Value {
    let summary = change
        .change_summary()
        .map(|summary| Value::String(hex::encode(summary.as_bytes())));
    json!({
        "approver": change.approver().map(|id| id.to_string()),
        "target": change.target().map(encode_audit_object),
        "scope": change.scope().map(encode_audit_object),
        "summary_hex": summary,
        "before": change.before().map(encode_audit_object_state),
        "after": change.after().map(encode_audit_object_state),
        "confirmations": change.confirmations().map(encode_confirmations),
        "root_before": change.root_before().map(encode_root_version),
        "root_after": change.root_after().map(encode_root_version),
        "source": encode_source(change.source()),
    })
}

// memory—v1
fn encode_action(action: &MemoryV1AuditAction) -> Value {
    json!({ "resource": action.resource(), "action": action.action() })
}

/// MySQL JSON can reorder keys and add spaces on readback. Use the same
/// deterministic JSON serialization on both sides of the audit digest.
// memory—v1
pub(crate) fn canonical_audit_json(mut value: Value) -> Result<Vec<u8>, serde_json::Error> {
    value.sort_all_objects();
    serde_json::to_vec(&value)
}

/// Encode the complete audit event into canonical JSON bytes.
///
/// Field presence mirrors the value exactly: an unobserved field stays `null`,
/// never replaced with an invented default. The bytes are the exact input to
/// the audit-row digest, so any later re-encoding must reproduce them.
// memory—v1
pub fn encode_canonical_audit_payload(
    event: &MemoryV1AuditEvent,
) -> Result<Vec<u8>, serde_json::Error> {
    let context = event.context();
    let payload = json!({
        "operation_id": context.operation().id(),
        "operation_fingerprint_hex": hex::encode(context.operation().fingerprint()),
        "decision": encode_decision(event.decision()),
        "reason_code": context.reason_code(),
        "actor": {
            "user": context.actor().user().to_string(),
            "identity_card": context.actor().identity_card().to_string(),
        },
        "time_unix_seconds": context.time().unix_seconds(),
        "action": encode_action(context.action()),
        "root": encode_root_observation(&context.root()),
        "change": event.change_details().map(encode_change),
    });
    canonical_audit_json(payload)
}

/// Encode one original deny observation (`astral_types` value) into canonical
/// JSON bytes for the append-only audit row.
///
/// The DB encodes the wire itself: the observation's own binary codec output
/// travels as lowercase hex in the top-level `observation_wire_hex` field.
/// Every observed field is preserved exactly — the four candidate identities,
/// the root observation, the read-start sample (explicitly the OBSERVED time,
/// never a final trusted time), resource/action, the nullable target, target
/// tenant, and target owner, the affected-binding state (unknown /
/// inapplicable / present with its four identifiers), the raw operation id
/// and fingerprint bytes, the frozen deny source, and the optional batch
/// sequence. Nothing is dropped, defaulted, or re-timestamped.
// memory—v1
pub fn encode_canonical_deny_observation_payload(
    observation: &astral_types::memory_v1_deny_observation::MemoryV1DenyObservation,
) -> Result<Vec<u8>, serde_json::Error> {
    use astral_types::memory_v1_deny_observation::MemoryV1DenyAffectedBindingState;
    let wire = observation.encode().map_err(|_| {
        serde_json::Error::io(std::io::Error::other(
            "deny observation wire encoding failed",
        ))
    })?;
    let root = observation.root();
    let identity = observation.identity();
    let status = match root.status() {
        astral_types::memory_v1_audit::MemoryV1AuditRootStatus::Candidate => "CANDIDATE",
        astral_types::memory_v1_audit::MemoryV1AuditRootStatus::Serving => "SERVING",
        astral_types::memory_v1_audit::MemoryV1AuditRootStatus::Invalid => "INVALID",
        astral_types::memory_v1_audit::MemoryV1AuditRootStatus::Stopped => "STOPPED",
    };
    let budget = root.budget();
    let affected_binding = match observation.affected_binding_state() {
        MemoryV1DenyAffectedBindingState::Unknown => json!({ "state": "unknown" }),
        MemoryV1DenyAffectedBindingState::Inapplicable => json!({ "state": "inapplicable" }),
        MemoryV1DenyAffectedBindingState::Present(binding) => json!({
            "state": "present",
            "binding": binding.binding_id().to_string(),
            "user_card": binding.user_card_id().to_string(),
            "owner": binding.owner_user_id().to_string(),
            "tenant": binding.tenant_id().to_string(),
        }),
    };
    let payload = json!({
        "observation_wire_hex": hex::encode(&wire),
        "root": {
            "instance": root.instance().to_string(),
            "version": root.version(),
            "digest_hex": hex::encode(root.digest()),
            "status": status,
            "budget": {
                "max_table_rows": budget.max_table_rows(),
                "max_bindings_per_read": budget.max_bindings_per_read(),
            },
            "row_count": root.row_count(),
        },
        "candidate_identity": {
            "user_id": identity.user_id.to_string(),
            "identity_card_id": identity.identity_card_id.to_string(),
            "user_card_id": identity.user_card_id.to_string(),
            "tenant_id": identity.tenant_id.to_string(),
        },
        // The OBSERVED read-start sample: persisted with exactly this
        // semantic, never presented as the B-4 final trusted time.
        "read_started_at_unix_seconds": observation.read_started_at_unix_seconds(),
        "resource": observation.resource(),
        "action": observation.action(),
        "target": observation.target().map(hex::encode),
        "target_tenant": observation.target_tenant().map(hex::encode),
        "target_owner": observation.target_owner().map(hex::encode),
        "affected_binding": affected_binding,
        "operation_id_hex": hex::encode(observation.operation_id()),
        "operation_fingerprint_hex": hex::encode(observation.operation_fingerprint()),
        "source": observation.source().as_str(),
        "batch_sequence": observation.batch_sequence(),
    });
    canonical_audit_json(payload)
}

/// The audit-row digest binds the exact canonical bytes written to the
/// append-only audit table; the receipt stores it for reconciliation.
// memory—v1
pub fn audit_row_digest(canonical_payload: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(AUDIT_ROW_DIGEST_DOMAIN);
    hash.update(canonical_payload);
    hash.finalize().into()
}

/// Deterministic audit-row identifier: first 16 bytes of a domain-separated
/// SHA-256 over the stream position. The primary key makes the append-only
/// insert idempotent at the row level.
// memory—v1
pub fn derive_audit_row_id(
    stream_id: [u8; 16],
    journal_sequence: u64,
    message_id: [u8; 16],
) -> [u8; 16] {
    let mut hash = Sha256::new();
    hash.update(AUDIT_ROW_ID_DOMAIN);
    hash.update(stream_id);
    hash.update(journal_sequence.to_be_bytes());
    hash.update(message_id);
    let digest: [u8; 32] = hash.finalize().into();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

// ─────────────────────────────────────────────────────────────────────────────
// Row-image encodings for fact tables (before/after evidence)
// ─────────────────────────────────────────────────────────────────────────────

/// Canonical before/after image of a candidate `memory_user_card` row.
// memory—v1
pub fn encode_user_card_row_image(row: &UserCardRow) -> Value {
    let status = match row.status {
        UserCardStatus::Active => "ACTIVE",
        UserCardStatus::Disabled => "DISABLED",
    };
    json!({
        "table": "memory_user_card",
        "user_card_id": hex::encode(row.user_card_id),
        "user_id": hex::encode(row.user_id),
        "tenant_id": hex::encode(row.tenant_id),
        "status": status,
    })
}

/// Canonical before/after image of a candidate `memory_rule_set` row.
// memory—v1
pub fn encode_rule_set_row_image(row: &RuleSetRow) -> Value {
    let status = match row.status {
        RuleSetStatus::Active => "ACTIVE",
        RuleSetStatus::Retired => "RETIRED",
    };
    json!({
        "table": "memory_rule_set",
        "rule_set_id": hex::encode(row.rule_set_id),
        "owner_tenant_id": hex::encode(row.owner_tenant_id),
        "current_version_bytes_hex": hex::encode(&row.current_version_bytes),
        "status": status,
    })
}

/// Canonical before/after image of a candidate `memory_card_rule_set_binding` row.
// memory—v1
pub fn encode_binding_row_image(row: &BindingRow) -> Value {
    let layer = match row.binding_layer {
        BindingLayer::Base => "BASE",
        BindingLayer::Overlay => "OVERLAY",
    };
    let owner_scope = match row.owner_scope {
        MemoryV1OwnerScope::SelfUser => "self",
        MemoryV1OwnerScope::AllUsers => "all",
    };
    let tenant_scope = match row.tenant_scope {
        MemoryV1TenantScope::SelfTenant => "self",
        MemoryV1TenantScope::SelfAndDescendants => "self+descendants",
    };
    json!({
        "table": "memory_card_rule_set_binding",
        "binding_id": hex::encode(row.binding_id),
        "user_card_id": hex::encode(row.user_card_id),
        "rule_set_id": hex::encode(row.rule_set_id),
        "binding_layer": layer,
        "valid_from": row.valid_from,
        "valid_until": row.valid_until,
        "owner_scope": owner_scope,
        "tenant_scope": tenant_scope,
        "removed_at": row.removed_at,
        "removed_by": row.removed_by.map(hex::encode),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit-row column extraction
// ─────────────────────────────────────────────────────────────────────────────

// memory—v1
fn audit_target_column(event: &MemoryV1AuditEvent) -> (Option<&'static str>, Option<Vec<u8>>) {
    let Some(target) = event.change_details().and_then(|change| change.target()) else {
        return (None, None);
    };
    match target {
        MemoryV1AuditObject::Tenant(id) => (Some("tenant"), Some(id.as_bytes().to_vec())),
        MemoryV1AuditObject::UserCard(id) => (Some("user_card"), Some(id.as_bytes().to_vec())),
        MemoryV1AuditObject::RuleSet(id) => (Some("rule_set"), Some(id.as_bytes().to_vec())),
        MemoryV1AuditObject::Binding(id) => (Some("binding"), Some(id.as_bytes().to_vec())),
        MemoryV1AuditObject::Confirmation(id) => {
            (Some("confirmation"), Some(id.as_bytes().to_vec()))
        }
        MemoryV1AuditObject::User(id) => (Some("user"), Some(id.as_bytes().to_vec())),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Stored receipt row
// ─────────────────────────────────────────────────────────────────────────────

/// The exact stored receipt row (raw byte columns kept as read). Only valid
/// rows are produced: the executor compares it field-by-field before use.
/// The derive maps columns positionally by name; the SELECT lists match.
#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
pub(crate) struct ReceiptRow {
    pub stream_id: Vec<u8>,
    pub epoch_id: Vec<u8>,
    pub journal_sequence: u64,
    pub mutation_sequence: u64,
    pub message_id: Vec<u8>,
    pub operation_id: String,
    /// ORIGINAL message boot identity (never the consumer's boot).
    pub boot_id: Vec<u8>,
    /// Consumer boot identity that applied the message.
    pub applied_by_boot_id: Vec<u8>,
    pub worker_id: String,
    /// Receipt outcome token: 'APPLIED' or 'DENY'.
    pub outcome: String,
    pub request_fingerprint: Vec<u8>,
    pub prev_frame_hash: Vec<u8>,
    pub frame_digest: Vec<u8>,
    pub payload_digest: Vec<u8>,
    pub mutation_digest: Vec<u8>,
    pub audit_row_digest: Vec<u8>,
    pub fact_operation_count: u16,
    pub fact_rows_affected_total: u64,
}

// memory—v1
impl ReceiptRow {
    /// The frame kind this receipt recorded, derived from the outcome token.
    // memory—v1
    pub(crate) fn frame_kind(&self) -> crate::memory_v1_apply::MemoryV1ApplyFrameKind {
        if self.outcome == "DENY" {
            crate::memory_v1_apply::MemoryV1ApplyFrameKind::Deny
        } else {
            crate::memory_v1_apply::MemoryV1ApplyFrameKind::Mutation
        }
    }

    /// The frozen outcome token for the receipt view.
    // memory—v1
    pub(crate) fn outcome_token(&self) -> &'static str {
        match self.outcome.as_str() {
            "DENY" => "DENY",
            _ => "APPLIED",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Receipt, progress, audit, and fence database access
// ─────────────────────────────────────────────────────────────────────────────

/// Read the receipt bound to a stable operation identity (no lock needed for
/// the dedup decision; the receipt insert's unique key remains the arbiter).
// memory—v1
pub(crate) async fn read_receipt_by_operation<'e, E: sqlx::Executor<'e, Database = sqlx::MySql>>(
    executor: E,
    operation_id: &str,
) -> Result<Option<ReceiptRow>, sqlx::Error> {
    let row: Option<ReceiptRow> = sqlx::query_as(RECEIPT_SELECT_BY_OPERATION_SQL)
        .bind(operation_id)
        .fetch_optional(executor)
        .await?;
    Ok(row)
}

/// Read the receipt bound to a stream position.
// memory—v1
pub(crate) async fn read_receipt_by_position<'e, E: sqlx::Executor<'e, Database = sqlx::MySql>>(
    executor: E,
    stream_id: &MemoryId,
    journal_sequence: u64,
) -> Result<Option<ReceiptRow>, sqlx::Error> {
    let row: Option<ReceiptRow> = sqlx::query_as(RECEIPT_SELECT_BY_STREAM_SEQ_SQL)
        .bind(id_bytes(stream_id))
        .bind(journal_sequence)
        .fetch_optional(executor)
        .await?;
    Ok(row)
}

/// Receipt column values written by the executor (digests proven in-process).
/// `boot_id` on the row is the ORIGINAL message boot identity; the consumer's
/// boot and worker identity travel in `applied_by_*`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReceiptInsertValues {
    pub applied_by_boot_id: MemoryId,
    pub worker_id: String,
    pub mutation_digest: [u8; 32],
    pub audit_row_digest: [u8; 32],
    pub fact_operation_count: u16,
    pub fact_rows_affected_total: u64,
    pub outcome: ReceiptOutcome,
}

/// The receipt row outcome: a mutation apply or a deny audit apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReceiptOutcome {
    Mutation,
    Deny,
}

// memory—v1
impl ReceiptOutcome {
    // memory—v1
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ReceiptOutcome::Mutation => "APPLIED",
            ReceiptOutcome::Deny => "DENY",
        }
    }
}

/// Append the operation receipt row.
// memory—v1
pub(crate) async fn insert_receipt_row(
    tx: &mut crate::memory_v1_apply_facts::ApplyTx<'_>,
    identity: &MemoryV1ApplyIdentity,
    values: &ReceiptInsertValues,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(RECEIPT_INSERT_SQL)
        .bind(id_bytes(&identity.stream_id))
        .bind(identity.journal_sequence)
        .bind(id_bytes(&identity.epoch_id))
        .bind(identity.mutation_sequence)
        .bind(id_bytes(&identity.message_id))
        .bind(&identity.operation_id)
        .bind(id_bytes(&identity.origin_boot_id))
        .bind(id_bytes(&values.applied_by_boot_id))
        .bind(&values.worker_id)
        .bind(&identity.request_fingerprint[..])
        .bind(&identity.prev_frame_hash[..])
        .bind(&identity.frame_digest[..])
        .bind(&identity.payload_digest[..])
        .bind(&values.mutation_digest[..])
        .bind(&values.audit_row_digest[..])
        .bind(values.fact_operation_count)
        .bind(values.fact_rows_affected_total)
        .bind(values.outcome.as_str())
        .execute(&mut **tx)
        .await?;
    Ok(result.rows_affected())
}

/// Raw progress tail as read from the database.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProgressTailRow {
    pub epoch_id: Vec<u8>,
    pub last_journal_sequence: u64,
    pub last_mutation_sequence: u64,
    pub last_frame_hash: Vec<u8>,
}

// memory—v1
type ProgressTuple = (Vec<u8>, u64, u64, Vec<u8>);

// memory—v1
fn progress_from_tuple(tuple: ProgressTuple) -> ProgressTailRow {
    ProgressTailRow {
        epoch_id: tuple.0,
        last_journal_sequence: tuple.1,
        last_mutation_sequence: tuple.2,
        last_frame_hash: tuple.3,
    }
}

/// Read the progress tail with a row lock inside the apply transaction.
// memory—v1
pub(crate) async fn read_progress_for_update(
    tx: &mut crate::memory_v1_apply_facts::ApplyTx<'_>,
    stream_id: &MemoryId,
) -> Result<Option<ProgressTailRow>, sqlx::Error> {
    let row: Option<ProgressTuple> = sqlx::query_as(PROGRESS_SELECT_FOR_UPDATE_SQL)
        .bind(id_bytes(stream_id))
        .fetch_optional(&mut **tx)
        .await?;
    Ok(row.map(progress_from_tuple))
}

/// Read the progress tail without a lock (status view).
// memory—v1
pub(crate) async fn read_progress_row<'e, E: sqlx::Executor<'e, Database = sqlx::MySql>>(
    executor: E,
    stream_id: &MemoryId,
) -> Result<Option<MemoryV1ApplyProgressRow>, sqlx::Error> {
    let row: Option<ProgressTuple> = sqlx::query_as(PROGRESS_SELECT_SQL)
        .bind(id_bytes(stream_id))
        .fetch_optional(executor)
        .await?;
    let Some((epoch_id, last_journal_sequence, last_mutation_sequence, last_frame_hash)) = row
    else {
        return Ok(None);
    };
    let epoch_bytes: [u8; 16] =
        epoch_id
            .as_slice()
            .try_into()
            .map_err(|_| sqlx::Error::ColumnDecode {
                index: "epoch_id".into(),
                source: "apply-progress epoch id must be 16 bytes".into(),
            })?;
    let hash_bytes: [u8; 32] =
        last_frame_hash
            .as_slice()
            .try_into()
            .map_err(|_| sqlx::Error::ColumnDecode {
                index: "last_frame_hash".into(),
                source: "apply-progress tail hash must be 32 bytes".into(),
            })?;
    Ok(Some(MemoryV1ApplyProgressRow {
        epoch_id: MemoryId::from_bytes(epoch_bytes),
        last_journal_sequence,
        last_mutation_sequence,
        last_frame_hash: hash_bytes,
    }))
}

/// Explicitly pre-seed the per-stream progress tail bound to the stream's
/// genesis anchor.
///
/// A missing progress row is never treated as a trusted genesis: the row must
/// exist before the first frame is applied, and it must bind the externally
/// supplied genesis hash (derived by the boot/journal side from the
/// installation identity). The insert is idempotent: a row that already
/// matches is verified; a row that disagrees is an inconsistency.
// memory—v1
pub(crate) async fn preseed_progress_row(
    connection: &mut sqlx::MySqlConnection,
    stream_id: &MemoryId,
    epoch_id: &MemoryId,
    genesis_hash: [u8; 32],
) -> Result<bool, sqlx::Error> {
    let inserted = sqlx::query(PROGRESS_PRESEED_SQL)
        .bind(id_bytes(stream_id))
        .bind(id_bytes(epoch_id))
        .bind(0_u64)
        .bind(0_u64)
        .bind(&genesis_hash[..])
        .execute(&mut *connection)
        .await;
    match inserted {
        Ok(result) => Ok(result.rows_affected() == 1),
        Err(error) if is_unique_violation(&error) => {
            // A row already exists: it must bind exactly this genesis and
            // epoch, otherwise the stream state is inconsistent.
            let row: Option<ProgressTuple> = sqlx::query_as(PROGRESS_SELECT_SQL)
                .bind(id_bytes(stream_id))
                .fetch_optional(&mut *connection)
                .await?;
            match row {
                Some((row_epoch, 0, 0, row_hash))
                    if row_epoch == epoch_id.as_bytes().to_vec()
                        && row_hash == genesis_hash.to_vec() =>
                {
                    Ok(false)
                }
                _ => Err(sqlx::Error::ColumnDecode {
                    index: "mv1_apply_progress".into(),
                    source: "existing progress row does not bind the supplied genesis anchor"
                        .into(),
                }),
            }
        }
        Err(error) => Err(error),
    }
}

/// Advance the progress tail for a MUTATION frame: both the journal sequence
/// and the mutation sequence advance. The pre-seeded row must exist.
///
/// Returns the rows affected: `1` on success. A zero-row CAS advance inside
/// the locked transaction is impossible without external interference and is
/// reported to the caller as a discontinuity denial.
// memory—v1
pub(crate) async fn advance_progress_mutation_row(
    tx: &mut crate::memory_v1_apply_facts::ApplyTx<'_>,
    identity: &MemoryV1ApplyIdentity,
) -> Result<u64, sqlx::Error> {
    let previous: Option<ProgressTuple> = sqlx::query_as(PROGRESS_SELECT_FOR_UPDATE_SQL)
        .bind(id_bytes(&identity.stream_id))
        .fetch_optional(&mut **tx)
        .await?;
    let Some((_, last_journal_sequence, _, _)) = previous else {
        // The continuity gate requires a pre-seeded row before any apply, so
        // reaching this branch means the row vanished mid-transaction.
        return Err(sqlx::Error::ColumnDecode {
            index: "mv1_apply_progress".into(),
            source: "progress row vanished inside the apply transaction".into(),
        });
    };
    let result = sqlx::query(PROGRESS_ADVANCE_CAS_SQL)
        .bind(id_bytes(&identity.epoch_id))
        .bind(identity.journal_sequence)
        .bind(identity.mutation_sequence)
        .bind(&identity.frame_digest[..])
        .bind(id_bytes(&identity.stream_id))
        .bind(last_journal_sequence)
        .execute(&mut **tx)
        .await?;
    Ok(result.rows_affected())
}

/// Advance the progress tail for a DENY frame: the journal sequence advances
/// but the mutation sequence stays put (a DENY reads authorization state; it
/// does not change it). The pre-seeded row must exist.
// memory—v1
pub(crate) async fn advance_progress_deny_row(
    tx: &mut crate::memory_v1_apply_facts::ApplyTx<'_>,
    identity: &MemoryV1ApplyIdentity,
) -> Result<u64, sqlx::Error> {
    let previous: Option<ProgressTuple> = sqlx::query_as(PROGRESS_SELECT_FOR_UPDATE_SQL)
        .bind(id_bytes(&identity.stream_id))
        .fetch_optional(&mut **tx)
        .await?;
    let Some((_, last_journal_sequence, _, _)) = previous else {
        return Err(sqlx::Error::ColumnDecode {
            index: "mv1_apply_progress".into(),
            source: "progress row vanished inside the apply transaction".into(),
        });
    };
    let result = sqlx::query(PROGRESS_ADVANCE_DENY_SQL)
        .bind(identity.journal_sequence)
        .bind(&identity.frame_digest[..])
        .bind(id_bytes(&identity.stream_id))
        .bind(last_journal_sequence)
        .execute(&mut **tx)
        .await?;
    Ok(result.rows_affected())
}

/// The audit-row column source: a structured audit event, or a raw deny
/// observation value (`astral_types`). One statement, one transaction path.
#[derive(Clone, Copy)]
pub(crate) enum AuditRowContent<'a> {
    /// A structured audit event (mutation apply / structured deny).
    Event(&'a MemoryV1AuditEvent),
    /// A raw deny observation; columns come from the same observation value.
    DenyObservation(&'a astral_types::memory_v1_deny_observation::MemoryV1DenyObservation),
}

/// Append the audit row. Returns the rows affected (exactly one on success).
/// Column values are filled from the SAME content value encoded into the
/// canonical payload; nothing is invented, and absent times stay NULL.
// memory—v1
pub(crate) async fn insert_audit_row(
    tx: &mut crate::memory_v1_apply_facts::ApplyTx<'_>,
    identity: &MemoryV1ApplyIdentity,
    content: &AuditRowContent<'_>,
    canonical_payload: &str,
    audit_row_digest_value: [u8; 32],
) -> Result<u64, sqlx::Error> {
    let audit_id = derive_audit_row_id(
        *identity.stream_id.as_bytes(),
        identity.journal_sequence,
        *identity.message_id.as_bytes(),
    );
    let result = match content {
        AuditRowContent::Event(audit) => {
            let context = audit.context();
            let (target_kind, target_id) = audit_target_column(audit);
            let change_summary: Option<Vec<u8>> = audit
                .change_details()
                .and_then(|change| change.change_summary())
                .map(|summary| summary.as_bytes().to_vec());
            sqlx::query(AUDIT_INSERT_SQL)
                .bind(&audit_id[..])
                .bind(id_bytes(&identity.stream_id))
                .bind(id_bytes(&identity.epoch_id))
                .bind(identity.journal_sequence)
                .bind(identity.mutation_sequence)
                .bind(id_bytes(&identity.message_id))
                .bind(&identity.operation_id)
                .bind(audit_decision_column(audit))
                .bind(context.reason_code())
                .bind(id_bytes(&context.actor().user()))
                .bind(id_bytes(&context.actor().identity_card()))
                .bind(context.action().resource().as_bytes())
                .bind(context.action().action().as_bytes())
                .bind(context.time().unix_seconds())
                .bind(None::<i64>)
                .bind(id_bytes(&context.root().version().instance()))
                .bind(context.root().version().version())
                .bind(&context.root().content_hash()[..])
                .bind(audit_root_status_column(&context.root()))
                .bind(target_kind)
                .bind(target_id.as_deref())
                .bind(change_summary)
                .bind(canonical_payload)
                .bind(&audit_row_digest_value[..])
                .execute(&mut **tx)
                .await?
        }
        AuditRowContent::DenyObservation(observation) => {
            let root = observation.root();
            let identity_value = observation.identity();
            let affected = observation.affected_binding_state();
            let (target_kind, target_id): (Option<&'static str>, Option<Vec<u8>>) =
                match affected {
                    astral_types::memory_v1_deny_observation::MemoryV1DenyAffectedBindingState::Present(_) => {
                        (Some("raw"), observation.target().map(|bytes| bytes.to_vec()))
                    }
                    _ => (None, observation.target().map(|bytes| bytes.to_vec())),
                };
            sqlx::query(AUDIT_INSERT_SQL)
                .bind(&audit_id[..])
                .bind(id_bytes(&identity.stream_id))
                .bind(id_bytes(&identity.epoch_id))
                .bind(identity.journal_sequence)
                .bind(identity.mutation_sequence)
                .bind(id_bytes(&identity.message_id))
                .bind(&identity.operation_id)
                // The frozen deny source token, from the observation value.
                .bind(format!("DENY:{}", observation.source().as_str()))
                // No reason code exists on a raw observation; it stays NULL
                // instead of being manufactured.
                .bind(None::<String>)
                .bind(id_bytes(&identity_value.user_id))
                .bind(id_bytes(&identity_value.identity_card_id))
                .bind(observation.resource().as_bytes())
                .bind(observation.action().as_bytes())
                // No final trusted time exists on a raw observation: NULL.
                .bind(None::<i64>)
                // The OBSERVED read-start sample, with exactly this semantic.
                .bind(Some(observation.read_started_at_unix_seconds()))
                .bind(id_bytes(&root.instance()))
                .bind(root.version())
                .bind(&root.digest()[..])
                .bind(audit_root_status_column_value(root.status()))
                .bind(target_kind)
                .bind(target_id.as_deref())
                // No change summary exists on a raw observation: NULL.
                .bind(None::<Vec<u8>>)
                .bind(canonical_payload)
                .bind(&audit_row_digest_value[..])
                .execute(&mut **tx)
                .await?
        }
    };
    Ok(result.rows_affected())
}

// memory—v1
fn audit_root_status_column(observation: &MemoryV1AuditRootObservation) -> &'static str {
    audit_root_status_column_value(observation.status())
}

// memory—v1
fn audit_root_status_column_value(
    status: astral_types::memory_v1_audit::MemoryV1AuditRootStatus,
) -> &'static str {
    match status {
        MemoryV1AuditRootStatus::Candidate => "CANDIDATE",
        MemoryV1AuditRootStatus::Serving => "SERVING",
        MemoryV1AuditRootStatus::Invalid => "INVALID",
        MemoryV1AuditRootStatus::Stopped => "STOPPED",
    }
}

/// The persisted-audit decision token for the audit table's `decision` column.
// memory—v1
pub fn audit_decision_column(event: &MemoryV1AuditEvent) -> &'static str {
    encode_decision(event.decision())
}

/// Claim (or renew) the per-stream apply-fence lease.
///
/// CAS update first (only a never-leased or expired fence row); a zero-row
/// result means another owner holds a live lease, or a missing row that this
/// caller then inserts. Every successful claim rotates the generation and
/// returns the explicit token; the insert race resolves to the winner.
// memory—v1
pub(crate) async fn claim_lease(
    connection: &mut sqlx::MySqlConnection,
    lease: &MemoryV1ApplyLease,
    stream_id: &MemoryId,
) -> Result<MemoryV1ApplyLeaseClaim, sqlx::Error> {
    let updated = sqlx::query(FENCE_CLAIM_CAS_UPDATE_SQL)
        .bind(id_bytes(&lease.boot_id))
        .bind(&lease.worker_id)
        .bind(lease.lease_ttl_seconds)
        .bind(id_bytes(stream_id))
        .execute(&mut *connection)
        .await?;
    if updated.rows_affected() == 1 {
        return Ok(MemoryV1ApplyLeaseClaim::Claimed {
            token: read_current_token(connection, stream_id, lease).await?,
        });
    }
    let existing: Option<(Vec<u8>, String)> = sqlx::query_as(FENCE_SELECT_OWNER_SQL)
        .bind(id_bytes(stream_id))
        .fetch_optional(&mut *connection)
        .await?;
    let Some((owner_boot, owner_worker)) = existing else {
        let inserted = sqlx::query(FENCE_INSERT_SQL)
            .bind(id_bytes(stream_id))
            .bind(id_bytes(&lease.boot_id))
            .bind(&lease.worker_id)
            .bind(lease.lease_ttl_seconds)
            .execute(&mut *connection)
            .await;
        match inserted {
            Ok(_) => {
                // No auto-increment column: read the inserted generation back.
                return Ok(MemoryV1ApplyLeaseClaim::Claimed {
                    token: read_current_token(connection, stream_id, lease).await?,
                });
            }
            Err(error) if is_unique_violation(&error) => {
                // Another worker inserted the fence row first.
                let (owner_boot, owner_worker): (Vec<u8>, String) =
                    sqlx::query_as(FENCE_SELECT_OWNER_SQL)
                        .bind(id_bytes(stream_id))
                        .fetch_one(&mut *connection)
                        .await?;
                return Ok(not_claimed(&owner_boot, &owner_worker));
            }
            Err(error) => return Err(error),
        }
    };
    Ok(not_claimed(&owner_boot, &owner_worker))
}

/// Read the fence row back after this caller's successful claim, proving the
/// generation that was written, and wrap it into the explicit token.
// memory—v1
async fn read_current_token(
    connection: &mut sqlx::MySqlConnection,
    stream_id: &MemoryId,
    lease: &MemoryV1ApplyLease,
) -> Result<MemoryV1ApplyFenceToken, sqlx::Error> {
    let (owner_boot, owner_worker, generation): (Vec<u8>, String, u64) =
        sqlx::query_as(FENCE_SELECT_OWNER_SQL)
            .bind(id_bytes(stream_id))
            .fetch_one(&mut *connection)
            .await?;
    if owner_boot != lease.boot_id.as_bytes().to_vec() || owner_worker != lease.worker_id {
        return Err(sqlx::Error::ColumnDecode {
            index: "mv1_apply_fence".into(),
            source: "fence row after claim does not bind the claiming boot/worker".into(),
        });
    }
    Ok(MemoryV1ApplyFenceToken::mint(
        *stream_id,
        lease.boot_id,
        lease.worker_id.clone(),
        generation,
    ))
}

/// CAS lease renewal: the presented token must still be the current owner,
/// generation, and unexpired. Each renewal rotates the generation and returns
/// the new token, so every previously issued token for this stream is
/// invalidated immediately.
// memory—v1
pub(crate) async fn renew_lease(
    connection: &mut sqlx::MySqlConnection,
    token: &MemoryV1ApplyFenceToken,
    stream_id: &MemoryId,
    lease_ttl_seconds: u64,
) -> Result<MemoryV1ApplyLeaseRenew, sqlx::Error> {
    let updated = sqlx::query(FENCE_RENEW_CAS_UPDATE_SQL)
        .bind(lease_ttl_seconds)
        .bind(id_bytes(stream_id))
        .bind(id_bytes(&token.boot_id()))
        .bind(token.worker_id())
        .bind(token.fence_generation())
        .execute(&mut *connection)
        .await?;
    if updated.rows_affected() != 1 {
        return Ok(MemoryV1ApplyLeaseRenew::NotRenewed);
    }
    let (owner_boot, owner_worker, generation): (Vec<u8>, String, u64) =
        sqlx::query_as(FENCE_SELECT_OWNER_SQL)
            .bind(id_bytes(stream_id))
            .fetch_one(&mut *connection)
            .await?;
    if owner_boot != token.boot_id().as_bytes().to_vec()
        || owner_worker != token.worker_id()
        || generation != token.fence_generation() + 1
    {
        return Err(sqlx::Error::ColumnDecode {
            index: "mv1_apply_fence".into(),
            source: "fence row after renewal does not bind the renewed token".into(),
        });
    }
    Ok(MemoryV1ApplyLeaseRenew::Renewed {
        token: MemoryV1ApplyFenceToken::mint(
            *stream_id,
            token.boot_id(),
            token.worker_id().to_string(),
            generation,
        ),
    })
}

// memory—v1
fn not_claimed(owner_boot: &[u8], owner_worker: &str) -> MemoryV1ApplyLeaseClaim {
    MemoryV1ApplyLeaseClaim::NotClaimed {
        owner_boot_id: MemoryId::from_bytes(owner_boot.try_into().unwrap_or([0; 16])),
        owner_worker_id: owner_worker.to_string(),
    }
}

// memory—v1
pub(crate) fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(|database_error| database_error.is_unique_violation())
}

/// Release the apply-fence lease held by the presented token. Returns the
/// rows affected: `1` only when the token is still the current owner,
/// generation, and unexpired; `0` for a stale, foreign, or expired token.
// memory—v1
pub(crate) async fn release_lease(
    connection: &mut sqlx::MySqlConnection,
    token: &MemoryV1ApplyFenceToken,
    stream_id: &MemoryId,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(FENCE_RELEASE_UPDATE_SQL)
        .bind(id_bytes(stream_id))
        .bind(id_bytes(&token.boot_id()))
        .bind(token.worker_id())
        .bind(token.fence_generation())
        .execute(&mut *connection)
        .await?;
    Ok(result.rows_affected())
}

// ─────────────────────────────────────────────────────────────────────────────
// The audit operation accessor used by the facade's correlation checks
// ─────────────────────────────────────────────────────────────────────────────

/// Column projection of one audit operation for receipt correlation.
// memory—v1
pub fn audit_operation(event: &MemoryV1AuditEvent) -> &MemoryV1AuditOperation {
    event.context().operation()
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::memory_v1_audit::{
        MemoryV1AuditActor, MemoryV1AuditChangeSummary, MemoryV1AuditConfirmationRef,
        MemoryV1AuditConfirmations, MemoryV1AuditContext, MemoryV1AuditDecisionInput,
        MemoryV1AuditRootVersion, MemoryV1AuditSource, MemoryV1AuditTime,
    };

    use crate::memory_v1_apply_plan::tests_support::sample_allow_change_event;

    // memory—v1
    fn memory_id(n: u8) -> MemoryId {
        MemoryId::from_bytes([n; 16])
    }

    /// Every registered statement is placeholder-parameterized: no braces that
    /// could indicate interpolated values.
    #[test]
    // memory—v1
    fn all_record_statements_are_placeholder_parameterized() {
        for statement in ALL_APPLY_RECORD_SQL {
            assert!(
                !statement.contains('{') && !statement.contains('}'),
                "record SQL must never interpolate values: {statement}"
            );
            assert!(
                statement.contains('?'),
                "statement must bind values: {statement}"
            );
        }
    }

    /// The canonical encoding is deterministic: two encodings of the same
    /// event are byte-identical, so the stored digest stays reproducible.
    #[test]
    // memory—v1
    fn canonical_audit_encoding_is_deterministic() {
        let event = sample_allow_change_event();
        let first = encode_canonical_audit_payload(&event).unwrap();
        let second = encode_canonical_audit_payload(&event).unwrap();
        assert_eq!(first, second);
        assert!(!first.is_empty());

        let digest = audit_row_digest(&first);
        assert_eq!(digest, audit_row_digest(&second));
        assert_ne!(digest, [0u8; 32]);
    }

    /// Unobserved audit facts stay explicit `null`s; absent and null are
    /// never conflated with invented values.
    #[test]
    // memory—v1
    fn absent_change_facts_remain_null_not_defaulted() {
        let operation = MemoryV1AuditOperation::new("op-records", [7; 32]).unwrap();
        let context = MemoryV1AuditContext::new(
            MemoryV1AuditActor::new(memory_id(1), memory_id(2)),
            MemoryV1AuditTime::new(30).unwrap(),
            MemoryV1AuditAction::new("memory_v1", "read").unwrap(),
            "READ_OBSERVED",
            operation,
            MemoryV1AuditRootObservation::new(
                MemoryV1AuditRootVersion::new(memory_id(8), 1),
                [4; 32],
                MemoryV1AuditRootStatus::Serving,
            ),
        )
        .unwrap();
        let event = MemoryV1AuditEvent::read(context, MemoryV1AuditDecisionInput::Allow).unwrap();
        let bytes = encode_canonical_audit_payload(&event).unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(value["change"].is_null());
        assert_eq!(value["decision"], "ALLOW");
        assert_eq!(value["operation_id"], "op-records");
    }

    /// The candidate DDL file stays present, non-executable (the whole DDL
    /// sits inside one block comment), and covers every table the executor
    /// writes or reads. This is a layout guard, not schema adoption.
    #[test]
    // memory—v1
    fn apply_candidate_ddl_covers_executor_tables() {
        let ddl = include_str!("../../Docs/sql/memory-v1-apply-candidate.sql");
        for table in [
            "mv1_apply_fence",
            "mv1_apply_receipt",
            "mv1_apply_progress",
            "mv1_apply_audit_event",
        ] {
            assert!(
                ddl.contains(&format!("CREATE TABLE {table} (")),
                "candidate DDL must declare {table}"
            );
        }
        assert!(
            ddl.trim_start().starts_with("-- OFFLINE CANDIDATE"),
            "candidate DDL must keep the offline-candidate header"
        );
        assert!(
            ddl.contains("/* OFFLINE CANDIDATE"),
            "DDL must stay commented out"
        );
        assert!(
            ddl.trim_end().ends_with("*/"),
            "DDL must stay commented out"
        );
    }

    /// The audit-row identifier is stable for the same stream position and
    /// differs across positions, so the append-only insert stays idempotent.
    #[test]
    // memory—v1
    fn audit_row_id_is_deterministic_per_stream_position() {
        let first = derive_audit_row_id([1; 16], 7, [2; 16]);
        let again = derive_audit_row_id([1; 16], 7, [2; 16]);
        let other_sequence = derive_audit_row_id([1; 16], 8, [2; 16]);
        let other_message = derive_audit_row_id([1; 16], 7, [3; 16]);
        assert_eq!(first, again);
        assert_ne!(first, other_sequence);
        assert_ne!(first, other_message);
    }

    /// Row images carry the exact candidate fields; binary values are hex so
    /// charset/collation can never re-encode them.
    #[test]
    // memory—v1
    fn row_images_hex_encode_binary_fields() {
        let row = UserCardRow {
            user_card_id: [1; 16],
            user_id: [2; 16],
            tenant_id: [3; 16],
            status: UserCardStatus::Active,
        };
        let image = encode_user_card_row_image(&row);
        assert_eq!(image["user_card_id"], hex::encode([1u8; 16]));
        assert_eq!(image["status"], "ACTIVE");

        let binding = BindingRow {
            binding_id: [4; 16],
            user_card_id: [1; 16],
            rule_set_id: [5; 16],
            binding_layer: BindingLayer::Overlay,
            valid_from: Some(10),
            valid_until: None,
            owner_scope: MemoryV1OwnerScope::AllUsers,
            tenant_scope: MemoryV1TenantScope::SelfAndDescendants,
            removed_at: None,
            removed_by: None,
        };
        let image = encode_binding_row_image(&binding);
        assert_eq!(image["binding_layer"], "OVERLAY");
        assert_eq!(image["owner_scope"], "all");
        assert_eq!(image["tenant_scope"], "self+descendants");
        assert!(image["removed_at"].is_null());
        assert!(image["removed_by"].is_null());

        let rule_set_row = RuleSetRow {
            rule_set_id: [6; 16],
            owner_tenant_id: [4; 16],
            current_version_bytes: vec![7; 8],
            status: RuleSetStatus::Retired,
        };
        let image = encode_rule_set_row_image(&rule_set_row);
        assert_eq!(image["status"], "RETIRED");
        assert_eq!(image["current_version_bytes_hex"], hex::encode([7u8; 8]));
    }

    /// The original deny observation encodes from the astral-types value:
    /// the DB-encoded wire hex is embedded, the four candidate identities,
    /// root observation, observed read-start time, nullable targets, the
    /// affected-binding state, frozen source, and batch sequence are all
    /// preserved, and nothing is invented.
    #[test]
    // memory—v1
    fn deny_observation_encoding_preserves_every_field() {
        use astral_types::memory_v1::CandidateIdentity;
        use astral_types::memory_v1_audit::MemoryV1AuditDenySource;
        use astral_types::memory_v1_deny_observation::{
            MemoryV1DenyAffectedBinding, MemoryV1DenyAffectedBindingState, MemoryV1DenyRootBudget,
            MemoryV1DenyRootObservation, MemoryV1DenySource,
        };

        let observation = astral_types::memory_v1_deny_observation::MemoryV1DenyObservation::new(
            MemoryV1DenyRootObservation::new(
                memory_id(8),
                7,
                [4; 32],
                astral_types::memory_v1_audit::MemoryV1AuditRootStatus::Serving,
                MemoryV1DenyRootBudget::new(500, 32),
                12,
            ),
            CandidateIdentity {
                user_id: memory_id(1),
                identity_card_id: memory_id(2),
                user_card_id: memory_id(3),
                tenant_id: memory_id(4),
            },
            1_790_000_000,
            "memory_v1",
            "read",
            Some(vec![9; 16]),
            None,
            Some(vec![10; 16]),
            MemoryV1DenyAffectedBindingState::Present(MemoryV1DenyAffectedBinding::new(
                memory_id(5),
                memory_id(3),
                memory_id(1),
                memory_id(4),
            )),
            b"it-deny-op".to_vec(),
            [6; 32].to_vec(),
            MemoryV1DenySource::NoMatch,
            Some(3),
        )
        .unwrap();
        let bytes = encode_canonical_deny_observation_payload(&observation).unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();

        let wire = observation.encode().unwrap();
        assert_eq!(value["observation_wire_hex"], hex::encode(&wire));
        assert_eq!(value["root"]["instance"], memory_id(8).to_string());
        assert_eq!(value["root"]["digest_hex"], hex::encode([4u8; 32]));
        assert_eq!(value["root"]["budget"]["max_table_rows"], 500);
        assert_eq!(value["root"]["row_count"], 12);
        assert_eq!(
            value["candidate_identity"]["user_id"],
            memory_id(1).to_string()
        );
        assert_eq!(
            value["candidate_identity"]["identity_card_id"],
            memory_id(2).to_string()
        );
        assert_eq!(value["read_started_at_unix_seconds"], 1_790_000_000);
        assert_eq!(value["resource"], "memory_v1");
        assert_eq!(value["target"], hex::encode([9u8; 16]));
        assert!(value["target_tenant"].is_null(), "absent stays null");
        assert_eq!(value["target_owner"], hex::encode([10u8; 16]));
        assert_eq!(value["affected_binding"]["state"], "present");
        assert_eq!(
            value["affected_binding"]["binding"],
            memory_id(5).to_string()
        );
        assert_eq!(value["operation_id_hex"], hex::encode(b"it-deny-op"));
        assert_eq!(value["source"], MemoryV1AuditDenySource::NoMatch.as_str());
        assert_eq!(value["batch_sequence"], 3);

        // Deterministic re-encoding for the stored digest.
        let again = encode_canonical_deny_observation_payload(&observation).unwrap();
        assert_eq!(bytes, again);
        assert_ne!(audit_row_digest(&bytes), [0u8; 32]);
    }

    /// A change with an explicit absent state encodes `absent`, distinct from
    /// a missing object field.
    #[test]
    // memory—v1
    fn absent_state_is_explicit_in_encoding() {
        let state = MemoryV1AuditObjectState::Absent;
        let value = encode_audit_object_state(&state);
        assert_eq!(value["kind"], "absent");

        let confirmations =
            MemoryV1AuditConfirmations::references(&[MemoryV1AuditConfirmationRef::Binding(
                memory_id(6),
            )])
            .unwrap();
        let encoded = encode_confirmations(&confirmations);
        assert_eq!(encoded["kind"], "references");
        assert_eq!(encoded["refs"][0]["id"], memory_id(6).to_string());

        let summary = MemoryV1AuditChangeSummary::new(&[9, 10]).unwrap();
        let change = MemoryV1AuditChange::new(
            Some(memory_id(1)),
            Some(MemoryV1AuditObject::Binding(memory_id(6))),
            Some(MemoryV1AuditObject::Tenant(memory_id(4))),
            Some(summary),
            Some(MemoryV1AuditObjectState::Absent),
            Some(MemoryV1AuditObjectState::Binding(
                MemoryV1AuditBindingState::Active,
            )),
            Some(confirmations),
            None,
            None,
            MemoryV1AuditSource::Ordinary,
        );
        let encoded = encode_change(&change);
        assert_eq!(encoded["before"]["kind"], "absent");
        assert_eq!(encoded["after"]["kind"], "binding");
        assert_eq!(encoded["summary_hex"], hex::encode([9u8, 10]));
        assert!(encoded["root_before"].is_null());
    }
}
