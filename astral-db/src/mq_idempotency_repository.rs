//! MySQL-backed idempotency claim/lease store for RabbitMQ consumers.
//!
//! Replaces the Redis claim layer (`mq:idempotent:<type>:<id>` + `processing:`
//! markers) with a durable, server-TTL lease table (`mq_consumer_lease`). The
//! table is additive; `mq_idempotent_log` remains the durable business-processed
//! proof owned by the audit/login same-transaction handlers and is only
//! logically associated with rows here (no foreign key: legacy fallback ids may
//! differ from the MQ envelope id).
//!
//! Contract highlights:
//! - `claim` runs in one short transaction (a single locking read plus one
//!   INSERT or UPDATE); no Redis/MQ/network access happens inside it.
//! - Only an exact duplicate is idempotent: when both the stored row and the
//!   new claim carry a payload digest, a digest mismatch is a fail-closed
//!   [`MqLeaseError::Conflict`], never a silent `Completed`.
//! - Every takeover increments the monotonic `lease_generation`; the per-claim
//!   `lease_token` is the CAS fence for renew/complete/release, so a stale
//!   worker can never renew, complete or release a lease it no longer owns.
//! - Lease expiry is always evaluated by the database server
//!   (`UTC_TIMESTAMP(6)`), never by consumer wall clocks.
//! - `COMPLETED` is only written by `complete`/`complete_in_tx`, i.e. strictly
//!   after (or atomically with) a durable handler proof; a `Completed` claim
//!   outcome is therefore inherited from a durable handler, never synthesized
//!   by the lease layer itself.

use sqlx::mysql::MySqlPool;
use uuid::Uuid;

/// Maximum accepted lease TTL seconds (server-computed). Kept well below any
/// meaningful message-retention horizon so an abandoned lease cannot pin a
/// message longer than a bounded reconciliation window.
pub const MQ_LEASE_MAX_TTL_SECONDS: i64 = 86_400;

/// Maximum accepted `message_id` length (envelope ids are ≤ 80 chars today;
/// legacy canonical ids are `legacy-<ns>-v1-<64 hex>`).
pub const MQ_LEASE_MAX_MESSAGE_ID_LEN: usize = 191;

/// Maximum accepted `message_type` length (matches `mq_idempotent_log`).
pub const MQ_LEASE_MAX_MESSAGE_TYPE_LEN: usize = 64;

/// Maximum accepted owner identity length.
pub const MQ_LEASE_MAX_OWNER_LEN: usize = 128;

/// Key identifying one message inside the lease store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MqLeaseKey<'a> {
    pub message_type: &'a str,
    pub message_id: &'a str,
}

/// Input of [`MqConsumerLeaseStore::claim`].
#[derive(Debug, Clone, Copy)]
pub struct MqLeaseClaim<'a> {
    pub message_type: &'a str,
    pub message_id: &'a str,
    /// Public IDEM key (`mq:idempotent:<type>:<id>`); stored for correlation.
    pub idem_key: &'a str,
    /// Lowercase sha256 of the raw delivery body. `None` marks a legacy claim
    /// that cannot participate in exact-duplicate conflict detection.
    pub payload_sha256: Option<&'a str>,
    /// Run-scoped consumer identity (who holds the lease).
    pub owner: &'a str,
    /// Lease TTL in seconds; evaluated by the database server.
    pub lease_seconds: i64,
}

/// Input of [`MqConsumerLeaseStore::renew`].
#[derive(Debug, Clone, Copy)]
pub struct MqLeaseRenew<'a> {
    pub key: MqLeaseKey<'a>,
    pub lease_token: &'a str,
    pub lease_seconds: i64,
}

/// Input of [`MqConsumerLeaseStore::release`].
#[derive(Debug, Clone, Copy)]
pub struct MqLeaseRelease<'a> {
    pub key: MqLeaseKey<'a>,
    pub lease_token: &'a str,
}

/// Input of [`MqConsumerLeaseStore::complete`].
#[derive(Debug, Clone, Copy)]
pub struct MqLeaseComplete<'a> {
    pub key: MqLeaseKey<'a>,
    pub lease_token: &'a str,
}

/// Outcome of a claim attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MqLeaseClaimOutcome {
    /// This caller now owns the lease until `lease_expires_at`.
    Claimed {
        /// Per-claim CAS token required by renew/complete/release.
        lease_token: String,
        /// Monotonic fence for observability and reconciliation.
        lease_generation: i64,
    },
    /// A previous delivery of this exact message already completed durably.
    Completed,
    /// Another live lease holds the message; `remaining_ms` is the
    /// server-computed time left (>= 0).
    InFlight { remaining_ms: i64 },
}

#[derive(Debug, thiserror::Error)]
pub enum MqLeaseError {
    #[error("mq consumer lease validation failed: {0}")]
    Validation(String),
    #[error(
        "mq consumer lease payload conflict (fail-closed, not idempotent): \
         message_type={message_type} message_id={message_id}: {detail}"
    )]
    Conflict {
        message_type: String,
        message_id: String,
        detail: String,
    },
    #[error("mq consumer lease database error: {0}")]
    Database(#[from] sqlx::Error),
}

/// Typed store trait for the consumer lease layer.
///
/// Production implementation: [`SqlxMqConsumerLeaseStore`]. Pure tests
/// (this module and `astral-mq`) implement it in memory so the lease
/// semantics can be exercised without a real database connection.
#[async_trait::async_trait]
pub trait MqConsumerLeaseStore: Send + Sync {
    /// Claim the message for processing. Short transaction; no Redis/MQ inside.
    async fn claim(&self, input: &MqLeaseClaim<'_>) -> Result<MqLeaseClaimOutcome, MqLeaseError>;

    /// Extend an owned, unexpired lease. Returns `false` when the lease was
    /// lost (expired, taken over, completed or released).
    async fn renew(&self, input: &MqLeaseRenew<'_>) -> Result<bool, MqLeaseError>;

    /// Clear an owned processing lease after handler failure so a redelivery
    /// can re-claim immediately. Never touches a `COMPLETED` row; returns
    /// `false` when the caller does not own the lease (an unknown outcome must
    /// not be treated as released-and-successful by callers).
    async fn release(&self, input: &MqLeaseRelease<'_>) -> Result<bool, MqLeaseError>;

    /// Promote an owned, unexpired processing lease to `COMPLETED`. Must be
    /// called only after (or atomically with) the durable handler proof.
    async fn complete(&self, input: &MqLeaseComplete<'_>) -> Result<bool, MqLeaseError>;

    /// Server-computed remaining lease time in milliseconds for an active
    /// (`PROCESSING`, unexpired) lease; `None` when there is no active lease.
    async fn remaining_lease_ms(&self, input: &MqLeaseKey<'_>)
        -> Result<Option<i64>, MqLeaseError>;
}

/// sqlx/MySQL implementation of [`MqConsumerLeaseStore`].
#[derive(Clone)]
pub struct SqlxMqConsumerLeaseStore {
    pool: MySqlPool,
}

impl SqlxMqConsumerLeaseStore {
    pub fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }

    /// Pool accessor for callers that must run a completion write inside the
    /// durable handler's own transaction (see [`complete_lease_in_tx`]).
    pub fn pool(&self) -> &MySqlPool {
        &self.pool
    }
}

#[async_trait::async_trait]
impl MqConsumerLeaseStore for SqlxMqConsumerLeaseStore {
    async fn claim(&self, input: &MqLeaseClaim<'_>) -> Result<MqLeaseClaimOutcome, MqLeaseError> {
        validate_claim(input)?;

        let mut tx = self.pool.begin().await?;
        // Short transaction: one locking read + one write, no Redis/MQ inside.
        let row = sqlx::query_as::<_, (Option<String>, String, Option<String>, i64, Option<i64>)>(
            "SELECT payload_sha256, status, lease_token, lease_generation, \
                    TIMESTAMPDIFF(MICROSECOND, UTC_TIMESTAMP(6), lease_expires_at) \
             FROM mq_consumer_lease \
             WHERE message_type = ? AND message_id = ? \
             FOR UPDATE",
        )
        .bind(input.message_type)
        .bind(input.message_id)
        .fetch_optional(&mut *tx)
        .await?;

        let outcome = match row {
            None => {
                let lease_token = Uuid::new_v4().to_string();
                sqlx::query(
                    "INSERT INTO mq_consumer_lease \
                     (idem_key, message_type, message_id, payload_sha256, status, lease_owner, \
                      lease_token, lease_generation, claim_attempts, lease_expires_at) \
                     VALUES (?, ?, ?, ?, 'PROCESSING', ?, ?, 1, 1, \
                             DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND))",
                )
                .bind(input.idem_key)
                .bind(input.message_type)
                .bind(input.message_id)
                .bind(input.payload_sha256)
                .bind(input.owner)
                .bind(&lease_token)
                .bind(input.lease_seconds)
                .execute(&mut *tx)
                .await?;
                MqLeaseClaimOutcome::Claimed {
                    lease_token,
                    lease_generation: 1,
                }
            }
            Some((row_digest, status, _row_token, row_generation, remaining_us)) => {
                ensure_digest_compatible(input, row_digest.as_deref())?;
                match status.as_str() {
                    "COMPLETED" => MqLeaseClaimOutcome::Completed,
                    "PROCESSING" => {
                        let lease_alive = remaining_us.is_some_and(|micros| micros >= 0);
                        if lease_alive {
                            MqLeaseClaimOutcome::InFlight {
                                remaining_ms: (remaining_us.unwrap_or(0) / 1000).max(0),
                            }
                        } else {
                            // Expired or released lease: fenced takeover. The
                            // generation fence advances so stale workers and
                            // operators can always order claims historically.
                            let lease_token = Uuid::new_v4().to_string();
                            sqlx::query(
                                "UPDATE mq_consumer_lease \
                                 SET status = 'PROCESSING', lease_owner = ?, lease_token = ?, \
                                     lease_generation = lease_generation + 1, \
                                     claim_attempts = claim_attempts + 1, \
                                     lease_expires_at = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND), \
                                     payload_sha256 = COALESCE(payload_sha256, ?), \
                                     updated_at = UTC_TIMESTAMP(6) \
                                 WHERE message_type = ? AND message_id = ?",
                            )
                            .bind(input.owner)
                            .bind(&lease_token)
                            .bind(input.lease_seconds)
                            .bind(input.payload_sha256)
                            .bind(input.message_type)
                            .bind(input.message_id)
                            .execute(&mut *tx)
                            .await?;
                            MqLeaseClaimOutcome::Claimed {
                                lease_token,
                                lease_generation: row_generation + 1,
                            }
                        }
                    }
                    other => {
                        return Err(MqLeaseError::Database(sqlx::Error::Protocol(format!(
                            "mq_consumer_lease has unknown status {other:?} for {}/{}",
                            input.message_type, input.message_id
                        ))))
                    }
                }
            }
        };
        tx.commit().await?;
        Ok(outcome)
    }

    async fn renew(&self, input: &MqLeaseRenew<'_>) -> Result<bool, MqLeaseError> {
        validate_key(input.key)?;
        validate_lease_seconds(input.lease_seconds)?;
        if input.lease_token.trim().is_empty() {
            return Err(MqLeaseError::Validation("lease_token is required".into()));
        }
        let result = sqlx::query(
            "UPDATE mq_consumer_lease \
             SET lease_expires_at = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND), \
                 updated_at = UTC_TIMESTAMP(6) \
             WHERE message_type = ? AND message_id = ? AND status = 'PROCESSING' \
               AND lease_token = ? \
               AND lease_expires_at IS NOT NULL AND lease_expires_at >= UTC_TIMESTAMP(6)",
        )
        .bind(input.lease_seconds)
        .bind(input.key.message_type)
        .bind(input.key.message_id)
        .bind(input.lease_token)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn release(&self, input: &MqLeaseRelease<'_>) -> Result<bool, MqLeaseError> {
        validate_key(input.key)?;
        if input.lease_token.trim().is_empty() {
            return Err(MqLeaseError::Validation("lease_token is required".into()));
        }
        let result = sqlx::query(
            "UPDATE mq_consumer_lease \
             SET lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, \
                 updated_at = UTC_TIMESTAMP(6) \
             WHERE message_type = ? AND message_id = ? AND status = 'PROCESSING' \
               AND lease_token = ?",
        )
        .bind(input.key.message_type)
        .bind(input.key.message_id)
        .bind(input.lease_token)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn complete(&self, input: &MqLeaseComplete<'_>) -> Result<bool, MqLeaseError> {
        validate_key(input.key)?;
        if input.lease_token.trim().is_empty() {
            return Err(MqLeaseError::Validation("lease_token is required".into()));
        }
        let result = sqlx::query(
            "UPDATE mq_consumer_lease \
             SET status = 'COMPLETED', completed_at = UTC_TIMESTAMP(6), \
                 lease_expires_at = NULL, updated_at = UTC_TIMESTAMP(6) \
             WHERE message_type = ? AND message_id = ? AND status = 'PROCESSING' \
               AND lease_token = ? \
               AND lease_expires_at IS NOT NULL AND lease_expires_at >= UTC_TIMESTAMP(6)",
        )
        .bind(input.key.message_type)
        .bind(input.key.message_id)
        .bind(input.lease_token)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn remaining_lease_ms(
        &self,
        input: &MqLeaseKey<'_>,
    ) -> Result<Option<i64>, MqLeaseError> {
        validate_key(*input)?;
        let remaining: Option<Option<i64>> = sqlx::query_scalar(
            "SELECT TIMESTAMPDIFF(MICROSECOND, UTC_TIMESTAMP(6), lease_expires_at) \
             FROM mq_consumer_lease \
             WHERE message_type = ? AND message_id = ? AND status = 'PROCESSING' \
               AND lease_expires_at IS NOT NULL",
        )
        .bind(input.message_type)
        .bind(input.message_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(remaining.flatten().map(|micros| (micros / 1000).max(0)))
    }
}

/// Mark a lease `COMPLETED` inside the durable handler's own transaction so
/// the completion proof is inherited atomically from the business effect
/// (instead of a post-hoc marker write). Returns `false` when the caller does
/// not own an unexpired processing lease.
pub async fn complete_lease_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    input: &MqLeaseComplete<'_>,
) -> Result<bool, MqLeaseError> {
    validate_key(input.key)?;
    if input.lease_token.trim().is_empty() {
        return Err(MqLeaseError::Validation("lease_token is required".into()));
    }
    let result = sqlx::query(
        "UPDATE mq_consumer_lease \
         SET status = 'COMPLETED', completed_at = UTC_TIMESTAMP(6), \
             lease_expires_at = NULL, updated_at = UTC_TIMESTAMP(6) \
         WHERE message_type = ? AND message_id = ? AND status = 'PROCESSING' \
           AND lease_token = ? \
           AND lease_expires_at IS NOT NULL AND lease_expires_at >= UTC_TIMESTAMP(6)",
    )
    .bind(input.key.message_type)
    .bind(input.key.message_id)
    .bind(input.lease_token)
    .execute(&mut **tx)
    .await?;
    Ok(result.rows_affected() == 1)
}

fn validate_key(key: MqLeaseKey<'_>) -> Result<(), MqLeaseError> {
    if key.message_type.trim().is_empty() {
        return Err(MqLeaseError::Validation("message_type is required".into()));
    }
    if key.message_id.trim().is_empty() {
        return Err(MqLeaseError::Validation("message_id is required".into()));
    }
    if key.message_type.len() > MQ_LEASE_MAX_MESSAGE_TYPE_LEN {
        return Err(MqLeaseError::Validation(format!(
            "message_type exceeds {MQ_LEASE_MAX_MESSAGE_TYPE_LEN} bytes"
        )));
    }
    if key.message_id.len() > MQ_LEASE_MAX_MESSAGE_ID_LEN {
        return Err(MqLeaseError::Validation(format!(
            "message_id exceeds {MQ_LEASE_MAX_MESSAGE_ID_LEN} bytes"
        )));
    }
    Ok(())
}

fn validate_lease_seconds(lease_seconds: i64) -> Result<(), MqLeaseError> {
    if lease_seconds <= 0 || lease_seconds > MQ_LEASE_MAX_TTL_SECONDS {
        return Err(MqLeaseError::Validation(format!(
            "lease_seconds must be within 1..={MQ_LEASE_MAX_TTL_SECONDS}"
        )));
    }
    Ok(())
}

fn validate_claim(input: &MqLeaseClaim<'_>) -> Result<(), MqLeaseError> {
    validate_key(MqLeaseKey {
        message_type: input.message_type,
        message_id: input.message_id,
    })?;
    if input.idem_key.trim().is_empty() || input.idem_key.len() > 255 {
        return Err(MqLeaseError::Validation(
            "idem_key must be 1..=255 bytes".into(),
        ));
    }
    if input.owner.trim().is_empty() || input.owner.len() > MQ_LEASE_MAX_OWNER_LEN {
        return Err(MqLeaseError::Validation(
            "owner must be 1..=128 bytes".into(),
        ));
    }
    validate_lease_seconds(input.lease_seconds)?;
    if let Some(digest) = input.payload_sha256 {
        validate_digest(digest)?;
    }
    Ok(())
}

fn validate_digest(digest: &str) -> Result<(), MqLeaseError> {
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(MqLeaseError::Validation(
            "payload_sha256 must be a 64-character hexadecimal digest".into(),
        ));
    }
    Ok(())
}

/// Exact-duplicate enforcement: a conflict is only decidable when both sides
/// carry a digest. `None` (legacy claim without digest) never conflicts, and a
/// digest-less stored row is backfilled on takeover.
fn ensure_digest_compatible(
    input: &MqLeaseClaim<'_>,
    row_digest: Option<&str>,
) -> Result<(), MqLeaseError> {
    match (row_digest, input.payload_sha256) {
        (Some(existing), Some(incoming)) => {
            if !existing.eq_ignore_ascii_case(incoming) {
                return Err(MqLeaseError::Conflict {
                    message_type: input.message_type.to_owned(),
                    message_id: input.message_id.to_owned(),
                    detail: "same message id was completed/claimed with a different payload digest"
                        .into(),
                });
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    /// In-memory clock shared with the fake store so lease expiry can be
    /// exercised without a real database.
    #[derive(Default)]
    struct FakeClock(Mutex<i64>);

    impl FakeClock {
        fn now(&self) -> i64 {
            *self.0.lock().unwrap()
        }
        fn advance(&self, seconds: i64) {
            *self.0.lock().unwrap() += seconds;
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct FakeRow {
        payload_sha256: Option<String>,
        status: String,
        lease_owner: Option<String>,
        lease_token: Option<String>,
        lease_generation: i64,
        claim_attempts: i32,
        lease_expires_at: Option<i64>,
        completed_at: Option<i64>,
        created_at: i64,
        updated_at: i64,
    }

    /// Pure in-memory [`MqConsumerLeaseStore`] mirroring the `mq_consumer_lease`
    /// contract (server clock faked by [`FakeClock`], alive iff
    /// `lease_expires_at >= now`, matching the SQL `>=` comparisons). Used by
    /// the lease contract suite so the semantics stay testable without MySQL.
    struct InMemoryMqConsumerLeaseStore {
        rows: Mutex<BTreeMap<(String, String), FakeRow>>,
        idem_keys: Mutex<BTreeMap<String, (String, String)>>,
        clock: Arc<FakeClock>,
        token_counter: Mutex<u64>,
    }

    impl InMemoryMqConsumerLeaseStore {
        fn new(clock: Arc<FakeClock>) -> Self {
            Self {
                rows: Mutex::new(BTreeMap::new()),
                idem_keys: Mutex::new(BTreeMap::new()),
                clock,
                token_counter: Mutex::new(0),
            }
        }

        fn next_token(&self) -> String {
            let mut counter = self.token_counter.lock().unwrap();
            *counter += 1;
            format!("token-{counter:04}")
        }

        fn row(&self, key: &MqLeaseKey<'_>) -> Option<FakeRow> {
            self.rows
                .lock()
                .unwrap()
                .get(&(key.message_type.to_owned(), key.message_id.to_owned()))
                .cloned()
        }

        fn mutate<F>(&self, key: &MqLeaseKey<'_>, mutate: F) -> Option<FakeRow>
        where
            F: FnOnce(&mut FakeRow) -> bool,
        {
            let mut rows = self.rows.lock().unwrap();
            let row = rows.get_mut(&(key.message_type.to_owned(), key.message_id.to_owned()))?;
            if mutate(row) {
                Some(row.clone())
            } else {
                None
            }
        }
    }

    fn assert_conflict(error: &MqLeaseError) {
        assert!(
            matches!(error, MqLeaseError::Conflict { .. }),
            "expected Conflict, got {error:?}"
        );
    }

    fn claim_input<'a>(
        message_id: &'a str,
        digest: Option<&'a str>,
        owner: &'a str,
        lease_seconds: i64,
    ) -> MqLeaseClaim<'a> {
        MqLeaseClaim {
            message_type: "AUDIT_LOG",
            message_id,
            idem_key: Box::leak(format!("mq:idempotent:AUDIT_LOG:{message_id}").into_boxed_str()),
            payload_sha256: digest,
            owner,
            lease_seconds,
        }
    }

    fn digest_of(seed: &str) -> String {
        use sha2::{Digest, Sha256};
        format!("{:x}", Sha256::digest(seed.as_bytes()))
    }

    fn key(message_id: &str) -> MqLeaseKey<'_> {
        MqLeaseKey {
            message_type: "AUDIT_LOG",
            message_id,
        }
    }

    #[async_trait::async_trait]
    impl MqConsumerLeaseStore for InMemoryMqConsumerLeaseStore {
        async fn claim(
            &self,
            input: &MqLeaseClaim<'_>,
        ) -> Result<MqLeaseClaimOutcome, MqLeaseError> {
            validate_claim(input)?;
            let lease_key = key(input.message_id);
            let row = self.row(&lease_key);
            match row {
                None => {
                    let token = self.next_token();
                    let now = self.clock.now();
                    self.rows.lock().unwrap().insert(
                        (input.message_type.to_owned(), input.message_id.to_owned()),
                        FakeRow {
                            payload_sha256: input.payload_sha256.map(ToOwned::to_owned),
                            status: "PROCESSING".into(),
                            lease_owner: Some(input.owner.to_owned()),
                            lease_token: Some(token.clone()),
                            lease_generation: 1,
                            claim_attempts: 1,
                            lease_expires_at: Some(now + input.lease_seconds),
                            completed_at: None,
                            created_at: now,
                            updated_at: now,
                        },
                    );
                    self.idem_keys.lock().unwrap().insert(
                        input.idem_key.to_owned(),
                        (input.message_type.to_owned(), input.message_id.to_owned()),
                    );
                    Ok(MqLeaseClaimOutcome::Claimed {
                        lease_token: token,
                        lease_generation: 1,
                    })
                }
                Some(row) => {
                    ensure_digest_compatible(input, row.payload_sha256.as_deref())?;
                    if row.status == "COMPLETED" {
                        return Ok(MqLeaseClaimOutcome::Completed);
                    }
                    let now = self.clock.now();
                    let alive = row
                        .lease_expires_at
                        .is_some_and(|expires_at| expires_at >= now);
                    if alive {
                        return Ok(MqLeaseClaimOutcome::InFlight {
                            remaining_ms: (row.lease_expires_at.unwrap_or(now) - now) * 1000,
                        });
                    }
                    let token = self.next_token();
                    let taken_over = self.mutate(&lease_key, |row| {
                        row.status = "PROCESSING".into();
                        row.lease_owner = Some(input.owner.to_owned());
                        row.lease_token = Some(token.clone());
                        row.lease_generation += 1;
                        row.claim_attempts += 1;
                        row.lease_expires_at = Some(now + input.lease_seconds);
                        if row.payload_sha256.is_none() {
                            row.payload_sha256 = input.payload_sha256.map(ToOwned::to_owned);
                        }
                        row.updated_at = now;
                        true
                    });
                    assert!(taken_over.is_some(), "row must exist for takeover");
                    Ok(MqLeaseClaimOutcome::Claimed {
                        lease_token: token,
                        lease_generation: row.lease_generation + 1,
                    })
                }
            }
        }

        async fn renew(&self, input: &MqLeaseRenew<'_>) -> Result<bool, MqLeaseError> {
            validate_key(input.key)?;
            validate_lease_seconds(input.lease_seconds)?;
            let now = self.clock.now();
            Ok(self
                .mutate(&input.key, |row| {
                    if row.status != "PROCESSING"
                        || row.lease_token.as_deref() != Some(input.lease_token)
                        || row
                            .lease_expires_at
                            .is_none_or(|expires_at| expires_at < now)
                    {
                        return false;
                    }
                    row.lease_expires_at = Some(now + input.lease_seconds);
                    row.updated_at = now;
                    true
                })
                .is_some())
        }

        async fn release(&self, input: &MqLeaseRelease<'_>) -> Result<bool, MqLeaseError> {
            validate_key(input.key)?;
            Ok(self
                .mutate(&input.key, |row| {
                    if row.status != "PROCESSING"
                        || row.lease_token.as_deref() != Some(input.lease_token)
                    {
                        return false;
                    }
                    row.lease_owner = None;
                    row.lease_token = None;
                    row.lease_expires_at = None;
                    row.updated_at = self.clock.now();
                    true
                })
                .is_some())
        }

        async fn complete(&self, input: &MqLeaseComplete<'_>) -> Result<bool, MqLeaseError> {
            validate_key(input.key)?;
            let now = self.clock.now();
            Ok(self
                .mutate(&input.key, |row| {
                    if row.status != "PROCESSING"
                        || row.lease_token.as_deref() != Some(input.lease_token)
                        || row
                            .lease_expires_at
                            .is_none_or(|expires_at| expires_at < now)
                    {
                        return false;
                    }
                    row.status = "COMPLETED".into();
                    row.completed_at = Some(now);
                    row.lease_expires_at = None;
                    row.updated_at = now;
                    true
                })
                .is_some())
        }

        async fn remaining_lease_ms(
            &self,
            input: &MqLeaseKey<'_>,
        ) -> Result<Option<i64>, MqLeaseError> {
            validate_key(*input)?;
            let now = self.clock.now();
            Ok(self
                .row(input)
                .filter(|row| row.status == "PROCESSING")
                .and_then(|row| row.lease_expires_at)
                .filter(|expires_at| *expires_at >= now)
                .map(|expires_at| (expires_at - now) * 1000))
        }
    }

    // ===== lease contract suite (pure; no MySQL connection) =====

    async fn contract_claim_complete_is_idempotent(store: &dyn MqConsumerLeaseStore) {
        let digest = digest_of("payload-a");
        let first = store
            .claim(&claim_input("msg-1", Some(&digest), "owner-1", 30))
            .await
            .expect("first claim must succeed");
        let MqLeaseClaimOutcome::Claimed {
            lease_token,
            lease_generation,
        } = first
        else {
            panic!("first claim must be Claimed, got {first:?}");
        };
        assert_eq!(lease_generation, 1);

        let second = store
            .claim(&claim_input("msg-1", Some(&digest), "owner-2", 30))
            .await
            .expect("second claim while active must succeed");
        assert_eq!(
            second,
            MqLeaseClaimOutcome::InFlight {
                remaining_ms: 30_000
            }
        );

        let completed = store
            .complete(&MqLeaseComplete {
                key: key("msg-1"),
                lease_token: &lease_token,
            })
            .await
            .expect("complete must succeed");
        assert!(completed);

        let replay = store
            .claim(&claim_input("msg-1", Some(&digest), "owner-3", 30))
            .await
            .expect("replay claim must succeed");
        assert_eq!(replay, MqLeaseClaimOutcome::Completed);
    }

    async fn contract_digest_conflict_fails_closed(store: &dyn MqConsumerLeaseStore) {
        let digest_a = digest_of("payload-a");
        let digest_b = digest_of("payload-b");
        let first = store
            .claim(&claim_input("msg-2", Some(&digest_a), "owner-1", 30))
            .await
            .expect("claim must succeed");
        let MqLeaseClaimOutcome::Claimed { lease_token, .. } = first else {
            panic!("first claim must be Claimed");
        };
        store
            .complete(&MqLeaseComplete {
                key: key("msg-2"),
                lease_token: &lease_token,
            })
            .await
            .expect("complete must succeed");

        // Same id, different payload: fail-closed, never silently Completed.
        let error = store
            .claim(&claim_input("msg-2", Some(&digest_b), "owner-2", 30))
            .await
            .expect_err("digest conflict must fail closed");
        assert_conflict(&error);
    }

    async fn contract_takeover_increments_generation_fence(
        clock: &FakeClock,
        store: &dyn MqConsumerLeaseStore,
    ) {
        let digest = digest_of("payload-a");
        let first = store
            .claim(&claim_input("msg-3", Some(&digest), "owner-1", 30))
            .await
            .expect("claim must succeed");
        let MqLeaseClaimOutcome::Claimed {
            lease_token: stale_token,
            lease_generation: first_generation,
        } = first
        else {
            panic!("first claim must be Claimed");
        };
        assert_eq!(first_generation, 1);

        clock.advance(31);
        let second = store
            .claim(&claim_input("msg-3", Some(&digest), "owner-2", 30))
            .await
            .expect("takeover after expiry must succeed");
        let MqLeaseClaimOutcome::Claimed {
            lease_token: fresh_token,
            lease_generation: second_generation,
        } = second
        else {
            panic!("takeover must be Claimed, got {second:?}");
        };
        assert_ne!(fresh_token, stale_token);
        assert_eq!(second_generation, 2);

        // Stale worker cannot renew/complete/release the fenced lease.
        assert!(!store
            .renew(&MqLeaseRenew {
                key: key("msg-3"),
                lease_token: &stale_token,
                lease_seconds: 30,
            })
            .await
            .expect("renew must evaluate"));
        assert!(!store
            .complete(&MqLeaseComplete {
                key: key("msg-3"),
                lease_token: &stale_token,
            })
            .await
            .expect("complete must evaluate"));
        assert!(!store
            .release(&MqLeaseRelease {
                key: key("msg-3"),
                lease_token: &stale_token,
            })
            .await
            .expect("release must evaluate"));

        // The fresh owner still completes.
        assert!(store
            .complete(&MqLeaseComplete {
                key: key("msg-3"),
                lease_token: &fresh_token,
            })
            .await
            .expect("complete must succeed"));
    }

    async fn contract_release_allows_immediate_reclaim(store: &dyn MqConsumerLeaseStore) {
        let digest = digest_of("payload-a");
        let first = store
            .claim(&claim_input("msg-4", Some(&digest), "owner-1", 300))
            .await
            .expect("claim must succeed");
        let MqLeaseClaimOutcome::Claimed {
            lease_token,
            lease_generation,
        } = first
        else {
            panic!("first claim must be Claimed");
        };
        assert_eq!(lease_generation, 1);

        assert!(store
            .release(&MqLeaseRelease {
                key: key("msg-4"),
                lease_token: &lease_token,
            })
            .await
            .expect("release must succeed"));

        // No clock advance needed: a released lease is immediately re-claimable
        // and the generation fence still advances.
        let second = store
            .claim(&claim_input("msg-4", Some(&digest), "owner-2", 300))
            .await
            .expect("re-claim after release must succeed");
        let MqLeaseClaimOutcome::Claimed {
            lease_generation: next_generation,
            ..
        } = second
        else {
            panic!("re-claim must be Claimed, got {second:?}");
        };
        assert_eq!(next_generation, 2);
    }

    async fn contract_renew_extends_only_owned_live_lease(
        clock: &FakeClock,
        store: &dyn MqConsumerLeaseStore,
    ) {
        let digest = digest_of("payload-a");
        let claimed = store
            .claim(&claim_input("msg-5", Some(&digest), "owner-1", 30))
            .await
            .expect("claim must succeed");
        let MqLeaseClaimOutcome::Claimed { lease_token, .. } = claimed else {
            panic!("first claim must be Claimed");
        };

        clock.advance(10);
        assert!(store
            .renew(&MqLeaseRenew {
                key: key("msg-5"),
                lease_token: &lease_token,
                lease_seconds: 30,
            })
            .await
            .expect("renew must succeed"));
        // Renewal is server-time based: 10s consumed, 30s re-armed.
        let remaining = store
            .remaining_lease_ms(&key("msg-5"))
            .await
            .expect("remaining ttl must resolve");
        assert_eq!(remaining, Some(30_000));

        clock.advance(60);
        assert!(!store
            .renew(&MqLeaseRenew {
                key: key("msg-5"),
                lease_token: &lease_token,
                lease_seconds: 30,
            })
            .await
            .expect("renew after expiry must evaluate"));
        assert_eq!(
            store
                .remaining_lease_ms(&key("msg-5"))
                .await
                .expect("remaining ttl must resolve"),
            None,
            "expired lease has no active remaining time"
        );
    }

    async fn contract_legacy_digest_backfill_on_takeover(
        clock: &FakeClock,
        store: &dyn MqConsumerLeaseStore,
    ) {
        // Legacy claim without digest.
        let first = store
            .claim(&claim_input("msg-6", None, "owner-1", 30))
            .await
            .expect("legacy claim must succeed");
        assert!(matches!(first, MqLeaseClaimOutcome::Claimed { .. }));

        clock.advance(31);
        // Digest-bearing takeover backfills the digest for future comparisons.
        let digest = digest_of("payload-legacy");
        let second = store
            .claim(&claim_input("msg-6", Some(&digest), "owner-2", 30))
            .await
            .expect("takeover must succeed");
        assert!(matches!(second, MqLeaseClaimOutcome::Claimed { .. }));

        clock.advance(31);
        let third = store
            .claim(&claim_input("msg-6", Some(&digest), "owner-3", 30))
            .await
            .expect("third claim must succeed");
        assert!(matches!(third, MqLeaseClaimOutcome::Claimed { .. }));

        // The backfilled digest now participates in conflict detection.
        let other = digest_of("payload-other");
        let error = store
            .claim(&claim_input("msg-6", Some(&other), "owner-4", 30))
            .await
            .expect_err("conflict must fail closed after backfill");
        assert_conflict(&error);
    }

    #[tokio::test]
    async fn lease_contract_suite_runs_on_in_memory_store() {
        let clock = Arc::new(FakeClock::default());
        let store = InMemoryMqConsumerLeaseStore::new(clock.clone());
        contract_claim_complete_is_idempotent(&store).await;
        contract_digest_conflict_fails_closed(&store).await;
        contract_takeover_increments_generation_fence(&clock, &store).await;
        contract_release_allows_immediate_reclaim(&store).await;
        contract_renew_extends_only_owned_live_lease(&clock, &store).await;
        contract_legacy_digest_backfill_on_takeover(&clock, &store).await;
    }

    // ===== input validation (pure) =====

    #[test]
    fn validation_rejects_empty_key_and_bad_bounds() {
        let error = validate_key(MqLeaseKey {
            message_type: " ",
            message_id: "m",
        })
        .expect_err("blank message_type must be rejected");
        assert!(matches!(error, MqLeaseError::Validation(_)));

        let long_id = "x".repeat(MQ_LEASE_MAX_MESSAGE_ID_LEN + 1);
        let error = validate_key(MqLeaseKey {
            message_type: "AUDIT_LOG",
            message_id: &long_id,
        })
        .expect_err("oversized message_id must be rejected");
        assert!(matches!(error, MqLeaseError::Validation(_)));
    }

    #[test]
    fn validation_rejects_unbounded_lease_seconds() {
        assert!(validate_lease_seconds(0).is_err());
        assert!(validate_lease_seconds(MQ_LEASE_MAX_TTL_SECONDS + 1).is_err());
        assert!(validate_lease_seconds(300).is_ok());
    }

    #[test]
    fn validation_rejects_malformed_digest() {
        let mut input = claim_input("m", Some("not-a-digest"), "owner", 30);
        let error = validate_claim(&input).expect_err("malformed digest must be rejected");
        assert!(matches!(error, MqLeaseError::Validation(_)));
        let valid_digest = digest_of("ok");
        input.payload_sha256 = Some(valid_digest.as_str());
        assert!(validate_claim(&input).is_ok());
    }

    #[test]
    fn digest_comparison_is_exact_duplicate_only() {
        let digest = digest_of("payload");
        let other = digest_of("other");
        let upper = digest.to_uppercase();

        assert!(
            ensure_digest_compatible(&claim_input("m", Some(&digest), "o", 30), Some(&digest))
                .is_ok()
        );
        assert!(ensure_digest_compatible(
            &claim_input("m", Some(upper.as_str()), "o", 30),
            Some(&digest)
        )
        .is_ok());
        assert!(ensure_digest_compatible(&claim_input("m", None, "o", 30), Some(&digest)).is_ok());
        assert!(ensure_digest_compatible(&claim_input("m", Some(&digest), "o", 30), None).is_ok());
        let error =
            ensure_digest_compatible(&claim_input("m", Some(&other), "o", 30), Some(&digest))
                .expect_err("digest mismatch must conflict");
        assert_conflict(&error);
    }

    // ===== production SQL static checks (pure) =====

    /// The production SQL must never promote a row to COMPLETED outside the
    /// completion path, every lease CAS must bind the token, and all TTL
    /// arithmetic must be server-side.
    #[test]
    fn sql_contract_keeps_completion_and_cas_guards() {
        let source = include_str!("mq_idempotency_repository.rs");
        let production = source.split("#[cfg(test)]").next().expect("split");
        // Exactly two COMPLETED writes: complete() and complete_lease_in_tx().
        assert_eq!(production.matches("'COMPLETED'").count(), 2);
        // Token bindings: 4 CAS filters + 1 takeover write.
        assert_eq!(
            production.matches("lease_token = ?").count(),
            5,
            "renew/release/complete(both) must CAS on lease_token; takeover writes a new token"
        );
        // One short locking transaction for claim.
        assert_eq!(production.matches("FOR UPDATE").count(), 1);
        // All TTL arithmetic is server-side; no consumer wall clock.
        assert_eq!(
            production
                .matches("DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND)")
                .count(),
            3,
            "claim insert, takeover and renew must arm the lease on the server"
        );
        assert!(!production.contains("NOW(), INTERVAL"));
    }

    /// Guards the async-trait shape so pure test doubles stay possible.
    #[test]
    fn store_trait_is_object_safe_for_test_fakes() {
        fn assert_object_safe<T: MqConsumerLeaseStore + ?Sized>() {}
        assert_object_safe::<dyn MqConsumerLeaseStore>();
    }
}
