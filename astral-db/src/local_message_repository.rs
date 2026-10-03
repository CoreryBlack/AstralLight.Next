//! MySQL-backed AL-native message outbox — the durable recovery journal.
//!
//! `al_message_outbox` is NOT the local transport authority. On the composite
//! runtime the normal transport is the direct `LocalBus` envelope path
//! (`publish_and_wait` after the source transaction commits); a notification
//! channel may only reduce recovery latency. This table owns the durable
//! recovery state machine (PENDING / PROCESSING / IN_DOUBT / PROCESSED /
//! QUARANTINED) that the recovery-only relay and the explicit reconciliation
//! interface advance. Nothing here may turn a broker/notification ACK or a
//! watermark into a durable completion proof.
//!
//! Per-scope FIFO: `scope_sequence` is allocated inside the same transaction
//! that appends the row (the scope-counter row is locked until commit), so the
//! sequence order equals the source-transaction commit order for each
//! (queue_name, ordering_key) scope. See
//! `migrations/20261001000005_invalidation_scope_sequence.sql`. Rows without a
//! scope (legacy or no ordering key) keep NULL and the claim guard falls back
//! to the conservative (created_at, message_id) comparison.

use sha2::{Digest, Sha256};
use sqlx::mysql::MySqlPool;
use sqlx::FromRow;
use time::PrimitiveDateTime;
use uuid::Uuid;

const LEASE_SECONDS: i64 = 30;
const MAX_ATTEMPTS: i32 = 5;
const MAX_BACKOFF_SECONDS: i64 = 900;

pub const LOCAL_MESSAGE_LEASE_SECONDS: u64 = LEASE_SECONDS as u64;
pub const LOCAL_MESSAGE_MAX_ATTEMPTS: i32 = MAX_ATTEMPTS;

/// Durable row statuses advanced by this repository.
pub(crate) const PENDING_STATUS: &str = "PENDING";
pub(crate) const IN_DOUBT_STATUS: &str = "IN_DOUBT";
pub(crate) const QUARANTINED_STATUS: &str = "QUARANTINED";

/// Scope-counter key separator (unit separator: never occurs in queue names or
/// invalidation ordering keys, keeping the composite key collision-free).
const SCOPE_KEY_SEPARATOR: char = '\u{1f}';

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalMessageAppend {
    Inserted,
    Existing,
}

#[derive(Debug, thiserror::Error)]
pub enum LocalMessageError {
    #[error("local message validation failed: {0}")]
    Validation(String),
    #[error("local message payload conflicts with an existing message id")]
    PayloadConflict,
    #[error("local message lease lost")]
    LeaseLost,
    #[error("local message database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(Debug, Clone, FromRow)]
pub struct LocalMessageRow {
    pub message_id: String,
    pub operation_id: String,
    pub message_type: String,
    pub queue_name: String,
    pub ordering_key: Option<String>,
    pub tenant_id: Option<i64>,
    pub origin_region: String,
    pub target_region: Option<String>,
    pub schema_version: i32,
    pub payload_json: String,
    pub headers_json: Option<String>,
    pub payload_sha256: String,
    pub status: String,
    pub attempts: i32,
    pub next_attempt_at: Option<PrimitiveDateTime>,
    pub lease_owner: Option<String>,
    pub lease_expires_at: Option<PrimitiveDateTime>,
    pub processed_at: Option<PrimitiveDateTime>,
    pub last_error: Option<String>,
    pub created_at: PrimitiveDateTime,
    pub updated_at: PrimitiveDateTime,
}

#[derive(Debug, Clone)]
pub struct LocalMessageInput<'a> {
    pub message_id: &'a str,
    pub operation_id: &'a str,
    pub message_type: &'a str,
    pub queue_name: &'a str,
    pub ordering_key: Option<&'a str>,
    pub tenant_id: Option<i64>,
    pub origin_region: &'a str,
    pub target_region: Option<&'a str>,
    pub schema_version: i32,
    pub payload_json: &'a str,
    pub headers_json: Option<&'a str>,
    pub payload_sha256: &'a str,
}

#[derive(Clone)]
pub struct LocalMessageRepository {
    pool: MySqlPool,
}

/// Provenance a reconciliation decision must match against the exact durable
/// row before any transition is applied. A mismatch fails closed: the row
/// stays IN_DOUBT and no state is changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InDoubtReconciliation<'a> {
    pub message_id: &'a str,
    pub operation_id: &'a str,
    pub message_type: &'a str,
    pub queue_name: &'a str,
    pub payload_sha256: &'a str,
}

/// Explicit IN_DOUBT settlement decision. There is no time-based path: IN_DOUBT
/// rows are never reset to PENDING by expiry, only by an explicit decision made
/// after the handler's durable effect has been reconciled (or proven absent and
/// safe to re-run).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InDoubtDecision {
    /// Return the row to the normal claimable queue.
    Requeue,
    /// Terminal quarantine (e.g. tampered/malformed envelope proven).
    Quarantine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InDoubtReconcileOutcome {
    Requeued,
    Quarantined,
    NotFound,
    /// The row was not IN_DOUBT (or left IN_DOUBT before the CAS landed); no
    /// transition was applied by this call.
    NotInDoubt,
    ProvenanceConflict,
}

/// Re-entrant scope-counter allocation: first append in a scope seeds 1,
/// later appends increment atomically under the row lock held until the
/// caller's transaction commits.
pub(crate) const SCOPE_COUNTER_ALLOCATE_SQL: &str =
    "INSERT INTO al_message_scope_counter (scope_key, last_sequence) VALUES (?, 1) \
     ON DUPLICATE KEY UPDATE last_sequence = last_sequence + 1";

/// Read the just-locked counter value (same transaction, lock held to commit).
pub(crate) const SCOPE_COUNTER_READ_SQL: &str =
    "SELECT last_sequence FROM al_message_scope_counter WHERE scope_key = ? FOR UPDATE";

/// Attach the allocated sequence to the freshly inserted outbox row.
pub(crate) const SCOPE_SEQUENCE_ATTACH_SQL: &str =
    "UPDATE al_message_outbox SET scope_sequence = ? \
     WHERE message_id = ? AND scope_sequence IS NULL";

/// Claimable candidates: only PENDING rows and PROCESSING rows whose lease has
/// expired are reclaimable. IN_DOUBT rows are intentionally never claimable and
/// never reset by time — they leave the state only through
/// [`LocalMessageRepository::reconcile_in_doubt`]. Per-scope FIFO: a row is
/// blocked while a prior unprocessed row exists in the same
/// (queue_name, ordering_key) scope; the "prior" comparison uses the
/// commit-ordered scope_sequence when both rows carry one and falls back to the
/// legacy (created_at, message_id) comparison whenever either side is NULL.
pub(crate) const CLAIM_CANDIDATES_SQL: &str =
    "SELECT message_id, operation_id, message_type, queue_name, ordering_key, tenant_id, \
            origin_region, target_region, schema_version, payload_json, headers_json, \
            payload_sha256, status, attempts, next_attempt_at, lease_owner, \
            lease_expires_at, processed_at, last_error, created_at, updated_at \
     FROM al_message_outbox AS current_message \
     WHERE current_message.queue_name = ? \
       AND (current_message.status = 'PENDING' OR (current_message.status = 'PROCESSING' AND current_message.lease_expires_at < UTC_TIMESTAMP(6))) \
       AND (current_message.next_attempt_at IS NULL OR current_message.next_attempt_at <= UTC_TIMESTAMP(6)) \
       AND NOT EXISTS ( \
           SELECT 1 FROM al_message_outbox AS prior_message \
           WHERE prior_message.queue_name = current_message.queue_name \
             AND prior_message.ordering_key IS NOT NULL \
             AND current_message.ordering_key IS NOT NULL \
             AND prior_message.ordering_key = current_message.ordering_key \
             AND prior_message.status NOT IN ('PROCESSED', 'QUARANTINED') \
             AND ( \
                   (prior_message.scope_sequence IS NOT NULL \
                    AND current_message.scope_sequence IS NOT NULL \
                    AND prior_message.scope_sequence < current_message.scope_sequence) \
                   OR ((prior_message.scope_sequence IS NULL OR current_message.scope_sequence IS NULL) \
                       AND (prior_message.created_at < current_message.created_at \
                            OR (prior_message.created_at = current_message.created_at \
                                AND prior_message.message_id < current_message.message_id))) \
                 ) \
       ) \
     ORDER BY current_message.created_at ASC, current_message.message_id ASC LIMIT ? FOR UPDATE SKIP LOCKED";

/// Exact IN_DOUBT row load (read-only inspection before a decision).
pub(crate) const IN_DOUBT_LOAD_SQL: &str =
    "SELECT message_id, operation_id, message_type, queue_name, ordering_key, tenant_id, \
            origin_region, target_region, schema_version, payload_json, headers_json, \
            payload_sha256, status, attempts, next_attempt_at, lease_owner, \
            lease_expires_at, processed_at, last_error, created_at, updated_at \
     FROM al_message_outbox WHERE message_id = ? AND status = 'IN_DOUBT'";

/// Provenance-matched CAS settlement: the row leaves IN_DOUBT only when it is
/// still IN_DOUBT at update time (idempotent under concurrent reconcilers).
pub(crate) const IN_DOUBT_SETTLE_SQL: &str =
    "UPDATE al_message_outbox SET status = ?, lease_owner = NULL, lease_expires_at = NULL, \
        next_attempt_at = NULL, updated_at = UTC_TIMESTAMP(6) \
     WHERE message_id = ? AND status = 'IN_DOUBT'";

impl LocalMessageRepository {
    pub fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }

    pub async fn append(
        &self,
        input: &LocalMessageInput<'_>,
    ) -> Result<LocalMessageAppend, LocalMessageError> {
        // The standalone append shares the exact transactional path of
        // append_in_tx so per-scope sequences stay commit-ordered and the
        // counter lock is held to a real commit.
        let mut tx = self.pool.begin().await?;
        let outcome = append_in_tx(&mut tx, input).await?;
        tx.commit().await?;
        Ok(outcome)
    }

    pub async fn claim_batch(
        &self,
        owner: &str,
        queue_name: &str,
        limit: u32,
    ) -> Result<Vec<LocalMessageRow>, LocalMessageError> {
        if owner.trim().is_empty() || queue_name.trim().is_empty() || limit == 0 {
            return Err(LocalMessageError::Validation(
                "owner, queue_name and limit are required".into(),
            ));
        }
        let mut tx = self.pool.begin().await?;
        let candidates = sqlx::query_as::<_, LocalMessageRow>(CLAIM_CANDIDATES_SQL)
            .bind(queue_name)
            .bind(i64::from(limit))
            .fetch_all(&mut *tx)
            .await?;

        let mut claimed = Vec::with_capacity(candidates.len());
        for mut candidate in candidates {
            let lease_owner = format!("{owner}:{}", Uuid::new_v4());
            let result = sqlx::query(
                "UPDATE al_message_outbox SET status = 'PROCESSING', lease_owner = ?, \
                    lease_expires_at = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND), \
                    attempts = attempts + 1, updated_at = UTC_TIMESTAMP(6) \
                 WHERE message_id = ? AND queue_name = ? \
                   AND (status = 'PENDING' OR (status = 'PROCESSING' AND lease_expires_at < UTC_TIMESTAMP(6)))",
            )
            .bind(&lease_owner)
            .bind(LEASE_SECONDS)
            .bind(&candidate.message_id)
            .bind(queue_name)
            .execute(&mut *tx)
            .await?;
            if result.rows_affected() == 1 {
                candidate.lease_owner = Some(lease_owner);
                candidate.attempts = candidate.attempts.saturating_add(1);
                claimed.push(candidate);
            }
        }
        tx.commit().await?;
        Ok(claimed)
    }

    pub async fn heartbeat(
        &self,
        message_id: &str,
        lease_token: &str,
    ) -> Result<(), LocalMessageError> {
        let result = sqlx::query(
            "UPDATE al_message_outbox SET lease_expires_at = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND), \
                updated_at = UTC_TIMESTAMP(6) \
             WHERE message_id = ? AND status = 'PROCESSING' AND lease_owner = ? \
               AND lease_expires_at >= UTC_TIMESTAMP(6)",
        )
        .bind(LEASE_SECONDS)
        .bind(message_id)
        .bind(lease_token)
        .execute(&self.pool)
        .await?;
        require_one(result.rows_affected())
    }

    pub async fn complete(
        &self,
        message_id: &str,
        lease_token: &str,
    ) -> Result<(), LocalMessageError> {
        let result = sqlx::query(
            "UPDATE al_message_outbox SET status = 'PROCESSED', processed_at = UTC_TIMESTAMP(6), \
                lease_owner = NULL, lease_expires_at = NULL, updated_at = UTC_TIMESTAMP(6) \
             WHERE message_id = ? AND status = 'PROCESSING' AND lease_owner = ? \
               AND lease_expires_at >= UTC_TIMESTAMP(6)",
        )
        .bind(message_id)
        .bind(lease_token)
        .execute(&self.pool)
        .await?;
        require_one(result.rows_affected())
    }

    pub async fn schedule_retry(
        &self,
        message_id: &str,
        lease_token: &str,
        error: &str,
    ) -> Result<(), LocalMessageError> {
        let result = sqlx::query(
            "UPDATE al_message_outbox SET status = CASE WHEN attempts >= ? THEN 'QUARANTINED' ELSE 'PENDING' END, \
                next_attempt_at = CASE WHEN attempts >= ? THEN NULL ELSE DATE_ADD(UTC_TIMESTAMP(6), INTERVAL \
                    LEAST(?, CAST(POW(2, GREATEST(attempts - 1, 0)) AS UNSIGNED)) SECOND) END, \
                lease_owner = NULL, lease_expires_at = NULL, last_error = LEFT(?, 512), \
                updated_at = UTC_TIMESTAMP(6) \
             WHERE message_id = ? AND status = 'PROCESSING' AND lease_owner = ? \
               AND lease_expires_at >= UTC_TIMESTAMP(6)",
        )
        .bind(MAX_ATTEMPTS)
        .bind(MAX_ATTEMPTS)
        .bind(MAX_BACKOFF_SECONDS)
        .bind(error)
        .bind(message_id)
        .bind(lease_token)
        .execute(&self.pool)
        .await?;
        require_one(result.rows_affected())
    }

    pub async fn quarantine(
        &self,
        message_id: &str,
        lease_token: &str,
        error: &str,
    ) -> Result<(), LocalMessageError> {
        let result = sqlx::query(
            "UPDATE al_message_outbox SET status = 'QUARANTINED', lease_owner = NULL, \
                lease_expires_at = NULL, last_error = LEFT(?, 512), updated_at = UTC_TIMESTAMP(6) \
             WHERE message_id = ? AND status = 'PROCESSING' AND lease_owner = ? \
               AND lease_expires_at >= UTC_TIMESTAMP(6)",
        )
        .bind(error)
        .bind(message_id)
        .bind(lease_token)
        .execute(&self.pool)
        .await?;
        require_one(result.rows_affected())
    }

    pub async fn mark_in_doubt(
        &self,
        message_id: &str,
        lease_token: &str,
        error: &str,
    ) -> Result<(), LocalMessageError> {
        let result = sqlx::query(
            "UPDATE al_message_outbox SET status = 'IN_DOUBT', lease_owner = NULL, \
                lease_expires_at = NULL, last_error = LEFT(?, 512), updated_at = UTC_TIMESTAMP(6) \
             WHERE message_id = ? AND status = 'PROCESSING' AND lease_owner = ? \
               AND lease_expires_at >= UTC_TIMESTAMP(6)",
        )
        .bind(error)
        .bind(message_id)
        .bind(lease_token)
        .execute(&self.pool)
        .await?;
        require_one(result.rows_affected())
    }

    pub async fn load(
        &self,
        message_id: &str,
    ) -> Result<Option<LocalMessageRow>, LocalMessageError> {
        Ok(sqlx::query_as::<_, LocalMessageRow>(
            "SELECT message_id, operation_id, message_type, queue_name, ordering_key, tenant_id, \
                    origin_region, target_region, schema_version, payload_json, headers_json, \
                    payload_sha256, status, attempts, next_attempt_at, lease_owner, \
                    lease_expires_at, processed_at, last_error, created_at, updated_at \
             FROM al_message_outbox WHERE message_id = ?",
        )
        .bind(message_id)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Independent exact IN_DOUBT row load: returns the durable row only while
    /// it is IN_DOUBT, so a reconciler inspects the precise state it must
    /// settle instead of assuming it.
    pub async fn load_in_doubt(
        &self,
        message_id: &str,
    ) -> Result<Option<LocalMessageRow>, LocalMessageError> {
        Ok(sqlx::query_as::<_, LocalMessageRow>(IN_DOUBT_LOAD_SQL)
            .bind(message_id)
            .fetch_optional(&self.pool)
            .await?)
    }

    /// Explicit IN_DOUBT reconciliation: exact row load under lock, full
    /// provenance match, then a status-guarded CAS. There is no time-based
    /// reset to PENDING; the decision is always caller-supplied and the CAS
    /// keeps concurrent reconcilers idempotent (one settlement wins, the rest
    /// observe `NotInDoubt` without touching state).
    pub async fn reconcile_in_doubt(
        &self,
        reconciliation: &InDoubtReconciliation<'_>,
        decision: InDoubtDecision,
    ) -> Result<InDoubtReconcileOutcome, LocalMessageError> {
        let mut tx = self.pool.begin().await?;
        let exact: Option<(String, String, String, String, String)> = sqlx::query_as(
            "SELECT operation_id, message_type, queue_name, payload_sha256, status \
             FROM al_message_outbox WHERE message_id = ? FOR UPDATE",
        )
        .bind(reconciliation.message_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((operation_id, message_type, queue_name, payload_sha256, status)) = exact else {
            tx.rollback().await?;
            return Ok(InDoubtReconcileOutcome::NotFound);
        };
        if operation_id != reconciliation.operation_id
            || message_type != reconciliation.message_type
            || queue_name != reconciliation.queue_name
            || payload_sha256 != reconciliation.payload_sha256
        {
            tx.rollback().await?;
            return Ok(InDoubtReconcileOutcome::ProvenanceConflict);
        }
        if status != IN_DOUBT_STATUS {
            tx.rollback().await?;
            return Ok(InDoubtReconcileOutcome::NotInDoubt);
        }
        let target_status = match decision {
            InDoubtDecision::Requeue => PENDING_STATUS,
            InDoubtDecision::Quarantine => QUARANTINED_STATUS,
        };
        let result = sqlx::query(IN_DOUBT_SETTLE_SQL)
            .bind(target_status)
            .bind(reconciliation.message_id)
            .execute(&mut *tx)
            .await?;
        if result.rows_affected() != 1 {
            // CAS lost: the row left IN_DOUBT between load and settle. This
            // call transitions nothing.
            tx.rollback().await?;
            return Ok(InDoubtReconcileOutcome::NotInDoubt);
        }
        tx.commit().await?;
        Ok(match decision {
            InDoubtDecision::Requeue => InDoubtReconcileOutcome::Requeued,
            InDoubtDecision::Quarantine => InDoubtReconcileOutcome::Quarantined,
        })
    }
}

pub async fn append_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    input: &LocalMessageInput<'_>,
) -> Result<LocalMessageAppend, LocalMessageError> {
    validate_input(input)?;
    let result = sqlx::query(
        "INSERT INTO al_message_outbox \
         (message_id, operation_id, message_type, queue_name, ordering_key, tenant_id, \
          origin_region, target_region, schema_version, payload_json, headers_json, \
          payload_sha256, status, attempts) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', 0) \
         ON DUPLICATE KEY UPDATE message_id = message_id",
    )
    .bind(input.message_id)
    .bind(input.operation_id)
    .bind(input.message_type)
    .bind(input.queue_name)
    .bind(input.ordering_key)
    .bind(input.tenant_id)
    .bind(input.origin_region)
    .bind(input.target_region)
    .bind(input.schema_version)
    .bind(input.payload_json)
    .bind(input.headers_json)
    .bind(input.payload_sha256)
    .execute(&mut **tx)
    .await?;

    if result.rows_affected() == 1 {
        allocate_scope_sequence(tx, input).await?;
        return Ok(LocalMessageAppend::Inserted);
    }

    let existing = sqlx::query_as::<_, LocalMessageRow>(
        "SELECT message_id, operation_id, message_type, queue_name, ordering_key, tenant_id, \
                origin_region, target_region, schema_version, payload_json, headers_json, \
                payload_sha256, status, attempts, next_attempt_at, lease_owner, \
                lease_expires_at, processed_at, last_error, created_at, updated_at \
         FROM al_message_outbox WHERE message_id = ?",
    )
    .bind(input.message_id)
    .fetch_optional(&mut **tx)
    .await?;
    match existing {
        Some(row)
            if row.payload_sha256 == input.payload_sha256
                && row.operation_id == input.operation_id
                && row.message_type == input.message_type
                && row.queue_name == input.queue_name
                && row.ordering_key.as_deref() == input.ordering_key
                && row.tenant_id == input.tenant_id
                && row.origin_region == input.origin_region
                && row.target_region.as_deref() == input.target_region
                && row.schema_version == input.schema_version
                && row.payload_json == input.payload_json
                && row.headers_json.as_deref() == input.headers_json =>
        {
            // Idempotent re-append: the committed row keeps its original
            // scope_sequence; a duplicate never allocates a new one.
            Ok(LocalMessageAppend::Existing)
        }
        Some(_) => Err(LocalMessageError::PayloadConflict),
        None => Err(LocalMessageError::Database(sqlx::Error::Protocol(
            "duplicate local message disappeared before readback".into(),
        ))),
    }
}

/// Allocate the per-scope commit-order sequence for a freshly inserted row,
/// inside the caller's transaction: the scope-counter row is locked until
/// commit, so `scope_sequence` order equals commit order. Rows without an
/// ordering key (and legacy rows) keep `scope_sequence` NULL.
async fn allocate_scope_sequence(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    input: &LocalMessageInput<'_>,
) -> Result<(), LocalMessageError> {
    let Some(ordering_key) = input.ordering_key else {
        return Ok(());
    };
    let Some(scope_key) = scope_counter_key(input.queue_name, ordering_key) else {
        return Err(LocalMessageError::Validation(
            "ordering scope is empty; a scoped row needs a non-blank ordering_key".into(),
        ));
    };
    sqlx::query(SCOPE_COUNTER_ALLOCATE_SQL)
        .bind(&scope_key)
        .execute(&mut **tx)
        .await?;
    let (allocated,): (i64,) = sqlx::query_as(SCOPE_COUNTER_READ_SQL)
        .bind(&scope_key)
        .fetch_one(&mut **tx)
        .await?;
    sqlx::query(SCOPE_SEQUENCE_ATTACH_SQL)
        .bind(allocated)
        .bind(input.message_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Composite counter key for one (queue_name, ordering_key) scope. Returns
/// `None` for blank halves (no sequence is allocated for unscoped rows).
pub(crate) fn scope_counter_key(queue_name: &str, ordering_key: &str) -> Option<String> {
    if queue_name.trim().is_empty() || ordering_key.trim().is_empty() {
        return None;
    }
    Some(format!("{queue_name}{SCOPE_KEY_SEPARATOR}{ordering_key}"))
}

fn validate_input(input: &LocalMessageInput<'_>) -> Result<(), LocalMessageError> {
    for (name, value) in [
        ("message_id", input.message_id),
        ("operation_id", input.operation_id),
        ("message_type", input.message_type),
        ("queue_name", input.queue_name),
        ("origin_region", input.origin_region),
        ("payload_json", input.payload_json),
        ("payload_sha256", input.payload_sha256),
    ] {
        if value.trim().is_empty() {
            return Err(LocalMessageError::Validation(format!("{name} is required")));
        }
    }
    if let Some(ordering_key) = input.ordering_key {
        if ordering_key.trim().is_empty() {
            return Err(LocalMessageError::Validation(
                "ordering_key must not be blank when present".into(),
            ));
        }
    }
    if input.schema_version <= 0 {
        return Err(LocalMessageError::Validation(
            "schema_version must be positive".into(),
        ));
    }
    if input.message_id.len() > 128
        || input.operation_id.len() > 128
        || input.message_type.len() > 64
        || input.queue_name.len() > 128
        || input.origin_region.len() > 64
        || input.target_region.is_some_and(|v| v.len() > 64)
        || input.ordering_key.is_some_and(|v| v.len() > 256)
    {
        return Err(LocalMessageError::Validation(
            "message metadata is too long".into(),
        ));
    }
    if input.payload_sha256.len() != 64
        || !input.payload_sha256.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(LocalMessageError::Validation(
            "payload_sha256 must be a 64-character hexadecimal digest".into(),
        ));
    }
    let value = serde_json::from_str::<serde_json::Value>(input.payload_json).map_err(|error| {
        LocalMessageError::Validation(format!("payload_json is invalid: {error}"))
    })?;
    let digest_value = value.get("payload").unwrap_or(&value);
    let digest = format!(
        "{:x}",
        Sha256::digest(
            serde_json::to_vec(digest_value)
                .map_err(|error| LocalMessageError::Validation(error.to_string()))?,
        )
    );
    if digest != input.payload_sha256.to_ascii_lowercase() {
        return Err(LocalMessageError::Validation(
            "payload_sha256 does not match payload_json payload".into(),
        ));
    }
    Ok(())
}

fn require_one(rows_affected: u64) -> Result<(), LocalMessageError> {
    if rows_affected == 1 {
        Ok(())
    } else {
        Err(LocalMessageError::LeaseLost)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_contract_rejects_empty_and_bad_digest() {
        let input = LocalMessageInput {
            message_id: "",
            operation_id: "op",
            message_type: "AUDIT_LOG",
            queue_name: "astral.audit.log",
            ordering_key: None,
            tenant_id: None,
            origin_region: "local",
            target_region: None,
            schema_version: 1,
            payload_json: "{}",
            headers_json: None,
            payload_sha256: "bad",
        };
        assert!(matches!(
            validate_input(&input),
            Err(LocalMessageError::Validation(_))
        ));
    }

    #[test]
    fn input_contract_rejects_blank_or_oversized_ordering_key() {
        let payload = serde_json::json!({"value": 1});
        let digest = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&payload).unwrap())
        );
        let payload_json = serde_json::to_string(&payload).unwrap();
        // Free function with explicit borrows only: a closure returning this
        // struct would borrow its own captured environment and fail lifetimes.
        fn base<'a>(
            ordering_key: Option<&'a str>,
            digest: &'a str,
            payload_json: &'a str,
        ) -> LocalMessageInput<'a> {
            LocalMessageInput {
                message_id: "event-1",
                operation_id: "operation-1",
                message_type: "EVIDENCE_INVALIDATED",
                queue_name: "astral.authorization.invalidation",
                ordering_key,
                tenant_id: Some(7),
                origin_region: "local",
                target_region: None,
                schema_version: 1,
                payload_json,
                headers_json: None,
                payload_sha256: digest,
            }
        }
        let long_key = "k".repeat(257);
        assert!(matches!(
            validate_input(&base(Some("   "), &digest, &payload_json)),
            Err(LocalMessageError::Validation(message))
                if message.contains("ordering_key")
        ));
        assert!(matches!(
            validate_input(&base(Some(long_key.as_str()), &digest, &payload_json)),
            Err(LocalMessageError::Validation(message))
                if message.contains("too long")
        ));
        assert!(validate_input(&base(
            Some("authorization:eligibility/card/9"),
            &digest,
            &payload_json
        ))
        .is_ok());
    }

    #[test]
    fn input_contract_accepts_complete_envelope_with_inner_payload_digest() {
        let payload = serde_json::json!({"tenantId": 7, "cardId": 42});
        let payload_sha256 = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&payload).unwrap())
        );
        let envelope = serde_json::json!({
            "messageId": "event-1",
            "operationId": "operation-1",
            "messageType": "EVIDENCE_INVALIDATED",
            "schemaVersion": 1,
            "tenantId": 7,
            "originRegion": "city-a",
            "targetRegion": null,
            "orderingKey": "authorization:evidence:tenant/7/aggregate/USER_CARD/42/card/42",
            "traceId": null,
            "createdAt": "2026-09-30T00:00:00Z",
            "expiresAt": null,
            "payloadSha256": payload_sha256,
            "payload": payload
        });
        let payload_json = serde_json::to_string(&envelope).unwrap();
        let input = LocalMessageInput {
            message_id: "event-1",
            operation_id: "operation-1",
            message_type: "EVIDENCE_INVALIDATED",
            queue_name: "astral.authorization.invalidation",
            ordering_key: Some("authorization:evidence:tenant/7/aggregate/USER_CARD/42/card/42"),
            tenant_id: Some(7),
            origin_region: "city-a",
            target_region: None,
            schema_version: 1,
            payload_json: &payload_json,
            headers_json: None,
            payload_sha256: envelope
                .get("payloadSha256")
                .and_then(serde_json::Value::as_str)
                .unwrap(),
        };
        assert!(validate_input(&input).is_ok());
    }

    #[test]
    fn scope_counter_key_is_deterministic_and_domain_separated() {
        let key = scope_counter_key(
            "astral.authorization.invalidation",
            "identity:session/user/9",
        )
        .expect("non-blank scope halves produce a key");
        assert_eq!(
            key,
            scope_counter_key(
                "astral.authorization.invalidation",
                "identity:session/user/9"
            )
            .expect("deterministic"),
        );
        assert!(key.contains(SCOPE_KEY_SEPARATOR));
        // Different queues and different ordering keys are different scopes.
        assert_ne!(
            key,
            scope_counter_key("astral.audit.log", "identity:session/user/9").unwrap()
        );
        assert_ne!(
            key,
            scope_counter_key(
                "astral.authorization.invalidation",
                "identity:session/user/10"
            )
            .unwrap()
        );
        // Blank halves never allocate a scope (conservative NULL handling).
        assert!(scope_counter_key("", "scope").is_none());
        assert!(scope_counter_key("astral.authorization.invalidation", "  ").is_none());
    }

    /// The scope-sequence migration must stay additive and re-entrant: every
    /// executable statement is existence-guarded and nothing is dropped.
    #[test]
    fn scope_sequence_migration_is_additive_and_re_entrant() {
        let migration =
            include_str!("../migrations/20261001000005_invalidation_scope_sequence.sql");
        assert!(migration.contains("TABLE_NAME = 'al_message_outbox'"));
        assert!(migration.contains("COLUMN_NAME = 'scope_sequence'"));
        assert!(migration.contains("IF(@c1 = 0,"));
        assert!(migration.contains("ADD COLUMN scope_sequence BIGINT DEFAULT NULL"));
        assert!(migration.contains("INDEX_NAME = 'idx_al_message_scope_order'"));
        assert!(migration.contains("CREATE TABLE IF NOT EXISTS al_message_scope_counter"));
        assert!(migration.contains("scope_key     VARCHAR(400) NOT NULL"));
        assert!(migration.contains("last_sequence BIGINT NOT NULL DEFAULT 0"));
        // Executable statements only: no DROP anywhere outside comments.
        for line in migration.lines() {
            let trimmed = line.trim_start();
            if !trimmed.starts_with("--") && !trimmed.is_empty() {
                assert!(
                    !trimmed.to_uppercase().contains("DROP"),
                    "scope-sequence migration must be additive; offending line: {line}"
                );
            }
        }
    }

    /// Claim SQL contract: scope-sequence FIFO with conservative legacy
    /// fallback, IN_DOUBT never claimable, no time-based IN_DOUBT reset.
    #[test]
    fn claim_guard_is_scope_ordered_and_never_claims_in_doubt() {
        assert!(CLAIM_CANDIDATES_SQL.contains(
            "current_message.status = 'PENDING' OR (current_message.status = 'PROCESSING' AND current_message.lease_expires_at < UTC_TIMESTAMP(6))"
        ));
        assert!(!CLAIM_CANDIDATES_SQL.contains("IN_DOUBT"));
        assert!(
            CLAIM_CANDIDATES_SQL
                .contains("prior_message.scope_sequence < current_message.scope_sequence"),
            "commit-ordered scope_sequence must decide per-scope FIFO"
        );
        assert!(
            CLAIM_CANDIDATES_SQL.contains(
                "prior_message.scope_sequence IS NULL OR current_message.scope_sequence IS NULL"
            ),
            "mixed/legacy rows must fall back to the conservative created_at comparison"
        );
        assert!(CLAIM_CANDIDATES_SQL.contains("FOR UPDATE SKIP LOCKED"));
        // Settlement contract: only an explicit provenance-matched CAS moves an
        // IN_DOUBT row; the guard SQL never touches IN_DOUBT by time.
        assert!(IN_DOUBT_SETTLE_SQL.contains("AND status = 'IN_DOUBT'"));
        assert!(IN_DOUBT_LOAD_SQL.contains("status = 'IN_DOUBT'"));
        assert!(SCOPE_SEQUENCE_ATTACH_SQL.contains("AND scope_sequence IS NULL"));
    }
}
