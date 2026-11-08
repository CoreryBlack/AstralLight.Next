//! SQL-backed durable delivery intent store (MySQL).
//!
//! Table `al_delivery_intent` (migration `20261107000003_delivery_intent.sql`):
//! server-side CAS lease/generation semantics mirroring the in-memory
//! reference store. Payload material is never persisted — bodies stay in
//! memory, and EphemeralSecret rows carry `body_sha256 IS NULL`.

use async_trait::async_trait;
use sqlx::MySqlPool;
use time::PrimitiveDateTime;

use crate::delivery::intent::{ChannelKind, PayloadClass};
use crate::delivery::lease::{AttemptLease, WorkerIdentity};
use crate::delivery::state::{DeliveryError, DeliveryState, DeliveryTruth};
use crate::delivery::store::{DeliveryStore, IntentRecord};

/// CAS-lease exactly one attempt. A row whose lease expired dirty (owner
/// still set) after a granted attempt is NEVER reclaimed here: the outcome
/// of that attempt is unknown, so the row must go sticky IN_DOUBT first
/// (see STICKY_IN_DOUBT). Only cleanly-released rows (lease_owner IS NULL,
/// i.e. settled outcomes such as transient refusals) may retry within the
/// attempt budget. A zero-row update falls back to a typed error.
/// The lease expiry is computed by the DATABASE clock (DATE_ADD over
/// UTC_TIMESTAMP(6)) so caller/DB clock skew can never widen a lease; the
/// granted lease's true expiry is read back from the row afterwards.
const ACQUIRE_ATTEMPT: &str = "\
UPDATE al_delivery_intent \
SET attempts = attempts + 1, generation = generation + 1, \
    lease_owner = ?, \
    lease_expires_at = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND), \
    updated_at = UTC_TIMESTAMP(6) \
WHERE message_id = ? \
  AND state IN ('NOT_ATTEMPTED','QUEUED') \
  AND attempts < max_attempts \
  AND lease_owner IS NULL \
  AND (lease_expires_at IS NULL OR lease_expires_at < UTC_TIMESTAMP(6))";

/// Sticky unknown: any row whose lease expired with the owner still set
/// after a granted attempt (dispatch may have happened) becomes IN_DOUBT.
/// Reconciliation is the only exit; there is no automatic reclaim+send.
const STICKY_IN_DOUBT: &str = "\
UPDATE al_delivery_intent \
SET state = 'IN_DOUBT', lease_owner = NULL, lease_expires_at = NULL, \
    last_detail = ?, updated_at = UTC_TIMESTAMP(6) \
WHERE message_id = ? \
  AND attempts > 0 \
  AND lease_owner IS NOT NULL \
  AND lease_expires_at < UTC_TIMESTAMP(6) \
  AND state IN ('NOT_ATTEMPTED','QUEUED','ACCEPTED')";

/// Budget exhaustion without acceptance expires the intent deterministically
/// — but ONLY for cleanly-released rows (lease_owner IS NULL). A row whose
/// final attempt still holds a live lease must stay LeaseConflict until that
/// lease expires, at which point STICKY_IN_DOUBT owns the outcome; a
/// concurrent refusal must never clear an active lease and hide an unknown
/// delivery.
const EXPIRE_BUDGET: &str = "\
UPDATE al_delivery_intent \
SET state = 'EXPIRED', lease_owner = NULL, lease_expires_at = NULL, \
    settled_at = UTC_TIMESTAMP(6), updated_at = UTC_TIMESTAMP(6) \
WHERE message_id = ? \
  AND attempts >= max_attempts \
  AND lease_owner IS NULL \
  AND state IN ('NOT_ATTEMPTED','QUEUED')";

/// Settle with the exact lease generation, live lease, and pre-settle
/// state; first settle wins. A late (already expired) lease cannot settle:
/// its outcome is treated as unknown and the row goes through
/// reconciliation instead.
const RECORD_OUTCOME: &str = "\
UPDATE al_delivery_intent \
SET state = ?, provider_reference = ?, last_detail = ?, \
    lease_owner = NULL, lease_expires_at = NULL, \
    settled_at = IF(? IN ('DELIVERED','FAILED','EXPIRED'), UTC_TIMESTAMP(6), settled_at), \
    updated_at = UTC_TIMESTAMP(6) \
WHERE message_id = ? AND generation = ? AND lease_owner = ? \
  AND lease_expires_at >= UTC_TIMESTAMP(6) \
  AND state IN ('NOT_ATTEMPTED','QUEUED','ACCEPTED')";

/// Force an unsettled row to IN_DOUBT with generation CAS.
const MARK_IN_DOUBT: &str = "\
UPDATE al_delivery_intent \
SET state = 'IN_DOUBT', lease_owner = NULL, lease_expires_at = NULL, \
    last_detail = ?, updated_at = UTC_TIMESTAMP(6) \
WHERE message_id = ? AND generation = ? \
  AND state IN ('NOT_ATTEMPTED','QUEUED','ACCEPTED')";

/// Reconciliation: only from IN_DOUBT to a terminal truth.
const RECONCILE: &str = "\
UPDATE al_delivery_intent \
SET state = ?, provider_reference = ?, \
    last_detail = CONCAT('reconciled by ', ?, ': ', ?), \
    settled_at = UTC_TIMESTAMP(6), updated_at = UTC_TIMESTAMP(6) \
WHERE message_id = ? AND state = 'IN_DOUBT'";

const INSERT_INTENT: &str = "\
INSERT IGNORE INTO al_delivery_intent \
(message_id, operation_id, channel_kind, recipient, subject, body_sha256, \
 payload_class, state, attempts, max_attempts, generation, created_at, updated_at) \
VALUES (?, ?, ?, ?, ?, ?, ?, 'QUEUED', 0, ?, 0, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))";

/// Immutable metadata of an existing intent, for conflict detection when
/// INSERT IGNORE lost the race on message_id.
const SELECT_INTENT_CONTRACT: &str = "\
SELECT operation_id, channel_kind, recipient, subject, body_sha256, payload_class \
FROM al_delivery_intent WHERE message_id = ?";

const SELECT_STATE: &str = "\
SELECT state FROM al_delivery_intent WHERE message_id = ?";

pub struct SqlxDeliveryIntentRepository {
    pool: MySqlPool,
}

impl std::fmt::Debug for SqlxDeliveryIntentRepository {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqlxDeliveryIntentRepository").finish()
    }
}

impl SqlxDeliveryIntentRepository {
    pub fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}

fn digest_hex(digest: Option<[u8; 32]>) -> Option<String> {
    digest.map(hex::encode)
}

fn store_error(error: impl std::fmt::Display) -> DeliveryError {
    DeliveryError::Store(error.to_string())
}

fn map_state(raw: String) -> DeliveryState {
    DeliveryState::parse(&raw).unwrap_or(DeliveryState::InDoubt)
}

/// Bounded lease TTL in microseconds (hard cap: one day), for the DB-side
/// DATE_ADD lease computation.
fn lease_ttl_micros(ttl: std::time::Duration) -> i64 {
    ttl.as_micros().min(86_400 * 1_000_000) as i64
}

/// (state, attempts, max_attempts, lease_expires_at, lease_owner)
type AcquireRefusalRow = (String, i32, i32, Option<PrimitiveDateTime>, Option<String>);

/// (operation_id, channel_kind, recipient, subject, body_sha256, payload_class)
type IntentContractRow = (
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    String,
);

const SELECT_REFUSAL_ROW: &str = "\
SELECT state, attempts, max_attempts, lease_expires_at, lease_owner \
FROM al_delivery_intent WHERE message_id = ?";

#[async_trait]
impl DeliveryStore for SqlxDeliveryIntentRepository {
    async fn record_intent(
        &self,
        record: &IntentRecord,
        _now: PrimitiveDateTime,
    ) -> Result<bool, DeliveryError> {
        if record.max_attempts == 0 || record.max_attempts > 32 {
            return Err(DeliveryError::Bounds("max attempts out of range"));
        }
        let result = sqlx::query(INSERT_INTENT)
            .bind(&record.message_id)
            .bind(&record.operation_id)
            .bind(record.channel.as_str())
            .bind(&record.recipient)
            .bind(record.subject.as_deref())
            .bind(digest_hex(record.body_digest))
            .bind(record.payload_class_marker())
            .bind(i64::from(record.max_attempts))
            .execute(&self.pool)
            .await
            .map_err(store_error)?;
        if result.rows_affected() > 0 {
            return Ok(true);
        }
        // INSERT IGNORE lost the race on message_id: the existing row's
        // immutable metadata must match this record exactly, otherwise the
        // same identity is being reused for different content — refuse.
        self.verify_intent_contract(record).await
    }

    async fn acquire_attempt(
        &self,
        message_id: &str,
        worker: &WorkerIdentity,
        lease_ttl: std::time::Duration,
        _now: PrimitiveDateTime,
    ) -> Result<AttemptLease, DeliveryError> {
        // Bounded TTL in microseconds, evaluated by the DB clock.
        let ttl_micros = lease_ttl_micros(lease_ttl);
        let result = sqlx::query(ACQUIRE_ATTEMPT)
            .bind(&worker.id)
            .bind(ttl_micros)
            .bind(message_id)
            .execute(&self.pool)
            .await
            .map_err(store_error)?;
        if result.rows_affected() == 0 {
            return Err(self.classify_acquire_refusal(message_id).await);
        }
        let row: (i64, i32, Option<PrimitiveDateTime>, Option<String>) = sqlx::query_as(
            "SELECT generation, attempts, lease_expires_at, lease_owner \
             FROM al_delivery_intent WHERE message_id = ? AND lease_owner = ?",
        )
        .bind(message_id)
        .bind(&worker.id)
        .fetch_one(&self.pool)
        .await
        .map_err(store_error)?;
        let lease_expires_at = row.2.ok_or(DeliveryError::Store(
            "acquired attempt lost its lease expiry".into(),
        ))?;
        let attempts = u32::try_from(row.1.max(0)).unwrap_or(0);
        Ok(AttemptLease {
            message_id: message_id.to_owned(),
            generation: row.0,
            lease_owner: row.3.unwrap_or_else(|| worker.id.clone()),
            lease_expires_at,
            attempt_no: attempts,
        })
    }

    async fn record_outcome(
        &self,
        lease: &AttemptLease,
        truth: &DeliveryTruth,
        _now: PrimitiveDateTime,
    ) -> Result<DeliveryState, DeliveryError> {
        let result = sqlx::query(RECORD_OUTCOME)
            .bind(truth.state.as_str())
            .bind(truth.provider_reference.as_deref())
            .bind(&truth.detail)
            .bind(truth.state.as_str())
            .bind(&lease.message_id)
            .bind(lease.generation)
            .bind(&lease.lease_owner)
            .execute(&self.pool)
            .await
            .map_err(store_error)?;
        if result.rows_affected() == 0 {
            return Err(DeliveryError::LeaseExpired);
        }
        Ok(truth.state)
    }

    async fn mark_in_doubt(
        &self,
        message_id: &str,
        generation: i64,
        reason: &str,
        _now: PrimitiveDateTime,
    ) -> Result<DeliveryState, DeliveryError> {
        let result = sqlx::query(MARK_IN_DOUBT)
            .bind(reason)
            .bind(message_id)
            .bind(generation)
            .execute(&self.pool)
            .await
            .map_err(store_error)?;
        if result.rows_affected() == 0 {
            return Err(DeliveryError::LeaseExpired);
        }
        Ok(DeliveryState::InDoubt)
    }

    async fn current_state(
        &self,
        message_id: &str,
    ) -> Result<Option<DeliveryState>, DeliveryError> {
        let row: Option<(String,)> = sqlx::query_as(SELECT_STATE)
            .bind(message_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(store_error)?;
        Ok(row.map(|(state,)| map_state(state)))
    }

    async fn reconcile(
        &self,
        message_id: &str,
        truth: &DeliveryTruth,
        reconciled_by: &str,
        _now: PrimitiveDateTime,
    ) -> Result<DeliveryState, DeliveryError> {
        if !truth.state.is_terminal() {
            return Err(DeliveryError::InvalidConfig(
                "reconciliation must settle a terminal truth",
            ));
        }
        if reconciled_by.trim().is_empty() || reconciled_by.len() > 128 {
            return Err(DeliveryError::InvalidConfig("reconciliation actor"));
        }
        let result = sqlx::query(RECONCILE)
            .bind(truth.state.as_str())
            .bind(truth.provider_reference.as_deref())
            .bind(reconciled_by)
            .bind(&truth.detail)
            .bind(message_id)
            .execute(&self.pool)
            .await
            .map_err(store_error)?;
        if result.rows_affected() == 0 {
            return Err(DeliveryError::ReconciliationRequired);
        }
        Ok(truth.state)
    }
}

impl SqlxDeliveryIntentRepository {
    /// Compare the stored immutable intent metadata against the record.
    async fn verify_intent_contract(&self, record: &IntentRecord) -> Result<bool, DeliveryError> {
        let row: Option<IntentContractRow> = sqlx::query_as(SELECT_INTENT_CONTRACT)
            .bind(&record.message_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(store_error)?;
        let Some(row) = row else {
            return Err(DeliveryError::UnknownIntent(record.message_id.clone()));
        };
        let matches = row.0 == record.operation_id
            && row.1 == record.channel.as_str()
            && row.2 == record.recipient
            && row.3 == record.subject
            && row.4 == digest_hex(record.body_digest)
            && row.5 == record.payload_class_marker();
        if matches {
            Ok(false)
        } else {
            Err(DeliveryError::IntentConflict(record.message_id.clone()))
        }
    }

    /// Produce the typed refusal reason for a zero-row acquire.
    async fn classify_acquire_refusal(&self, message_id: &str) -> DeliveryError {
        // Refusal order matters: a dirty-expired lease (owner still set
        // after a granted attempt) is FIRST forced sticky IN_DOUBT — the
        // attempt's outcome is unknown, so neither reclaim+send nor a typed
        // retry path may run. A budget-exhausted queued row is then
        // deterministically expired.
        let sticky = sqlx::query(STICKY_IN_DOUBT)
            .bind("lease expired after dispatch began; reconciliation required")
            .bind(message_id)
            .execute(&self.pool)
            .await;
        if let Err(error) = sticky {
            return store_error(error);
        }
        let expire = sqlx::query(EXPIRE_BUDGET)
            .bind(message_id)
            .execute(&self.pool)
            .await;
        if let Err(error) = expire {
            return store_error(error);
        }
        let row = match sqlx::query_as::<_, AcquireRefusalRow>(SELECT_REFUSAL_ROW)
            .bind(message_id)
            .fetch_optional(&self.pool)
            .await
        {
            Ok(row) => row,
            Err(error) => return store_error(error),
        };
        let Some(row) = row else {
            return DeliveryError::UnknownIntent(message_id.to_owned());
        };
        let (state, attempts, max_attempts, lease_expires_at, lease_owner) = row;
        // Order matters: after STICKY_IN_DOUBT ran, any remaining leased row
        // has a LIVE lease — a safe in-flight attempt owned by another worker.
        // It must surface as LeaseConflict even when the budget is exhausted;
        // only settled/accepted/doubt states and (then) budget exhaustion are
        // more specific truths.
        match state.as_str() {
            "IN_DOUBT" => DeliveryError::ReconciliationRequired,
            "DELIVERED" | "FAILED" | "EXPIRED" | "ACCEPTED" => {
                DeliveryError::BudgetExhausted(format!("intent already {state}"))
            }
            _ if lease_owner.is_some() && lease_expires_at.is_some() => {
                DeliveryError::LeaseConflict
            }
            _ if attempts >= max_attempts => DeliveryError::BudgetExhausted(message_id.to_owned()),
            other => DeliveryError::Store(format!("attempt refused for state {other}")),
        }
    }
}

impl IntentRecord {
    /// Storage marker for the payload class.
    fn payload_class_marker(&self) -> &'static str {
        match self.payload_class {
            PayloadClass::Standard => "STANDARD",
            PayloadClass::EphemeralSecret => "EPHEMERAL_SECRET",
        }
    }
}

impl PayloadClass {
    #[allow(dead_code)]
    pub fn parse(raw: &str) -> Option<PayloadClass> {
        match raw {
            "STANDARD" => Some(PayloadClass::Standard),
            "EPHEMERAL_SECRET" => Some(PayloadClass::EphemeralSecret),
            _ => None,
        }
    }
}

impl ChannelKind {
    #[allow(dead_code)]
    pub fn from_storage(raw: &str) -> Option<ChannelKind> {
        ChannelKind::parse(raw)
    }
}

#[cfg(test)]
mod sql_contract_tests {
    use super::*;

    /// Real MySQL is unavailable in this environment; these assertions pin
    /// the SQL CAS contract that the integration gate must exercise against
    /// a live database (main's schema/migration gate).
    #[test]
    fn acquire_never_reclaims_a_dirty_expired_lease() {
        assert!(
            ACQUIRE_ATTEMPT.contains("AND lease_owner IS NULL"),
            "acquire must refuse rows whose lease expired with the owner still set: {ACQUIRE_ATTEMPT}"
        );
        assert!(ACQUIRE_ATTEMPT.contains("attempts < max_attempts"));
        assert!(ACQUIRE_ATTEMPT.contains("state IN ('NOT_ATTEMPTED','QUEUED')"));
    }

    #[test]
    fn dirty_expiry_is_forced_sticky_in_doubt() {
        assert!(STICKY_IN_DOUBT.contains("state = 'IN_DOUBT'"));
        assert!(STICKY_IN_DOUBT.contains("attempts > 0"));
        assert!(STICKY_IN_DOUBT.contains("lease_owner IS NOT NULL"));
        assert!(STICKY_IN_DOUBT.contains("lease_expires_at < UTC_TIMESTAMP(6)"));
    }

    #[test]
    fn late_lease_cannot_settle() {
        assert!(RECORD_OUTCOME.contains("lease_expires_at >= UTC_TIMESTAMP(6)"));
        assert!(RECORD_OUTCOME.contains("state IN ('NOT_ATTEMPTED','QUEUED','ACCEPTED')"));
        assert!(RECORD_OUTCOME.contains("generation = ?"));
        assert!(RECORD_OUTCOME.contains("lease_owner = ?"));
    }

    #[test]
    fn insert_uses_server_clock_and_matches_bind_count() {
        // created_at/updated_at come from UTC_TIMESTAMP(6): no placeholder.
        assert_eq!(INSERT_INTENT.matches('?').count(), 8, "{INSERT_INTENT}");
        assert!(INSERT_INTENT.contains("UTC_TIMESTAMP(6), UTC_TIMESTAMP(6)"));
        // Bind order in record_intent: 7 metadata binds + max_attempts.
        assert!(INSERT_INTENT.starts_with("INSERT IGNORE INTO al_delivery_intent"));
    }

    #[test]
    fn reconcile_only_leaves_in_doubt() {
        assert!(RECONCILE.contains("state = 'IN_DOUBT'"));
        assert!(MARK_IN_DOUBT.contains("generation = ?"));
    }

    #[test]
    fn placeholder_counts_match_binds() {
        assert_eq!(ACQUIRE_ATTEMPT.matches('?').count(), 3);
        assert_eq!(RECORD_OUTCOME.matches('?').count(), 7);
        assert_eq!(STICKY_IN_DOUBT.matches('?').count(), 2);
        assert_eq!(EXPIRE_BUDGET.matches('?').count(), 1);
        assert_eq!(MARK_IN_DOUBT.matches('?').count(), 3);
        assert_eq!(RECONCILE.matches('?').count(), 5);
        assert_eq!(SELECT_INTENT_CONTRACT.matches('?').count(), 1);
    }
}
