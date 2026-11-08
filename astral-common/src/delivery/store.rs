//! Durable delivery intent store: port + in-memory reference implementation.
//!
//! The store owns message-level coordination:
//! - `record_intent` is idempotent by `message_id` (stable intent identity).
//! - `acquire_attempt` is a CAS lease: exactly one live attempt per message;
//!   generation increments per attempt; expired leases allow takeover.
//! - `record_outcome` settles with the exact lease generation (first settle
//!   wins; a lost settle means the outcome is unknown and must reconcile).
//! - `IN_DOUBT` rows accept only explicit `reconcile` (terminal truth).
//!
//! Payload rule: bodies are never persisted. For
//! [`PayloadClass::EphemeralSecret`] not even `body_digest` is recorded.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use time::{Duration as TimeDuration, OffsetDateTime, PrimitiveDateTime};

use crate::delivery::intent::{ChannelKind, PayloadClass};
use crate::delivery::lease::{AttemptLease, WorkerIdentity};
use crate::delivery::state::{DeliveryError, DeliveryState, DeliveryTruth};

/// Durable intent metadata. Contains no payload material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentRecord {
    pub message_id: String,
    pub operation_id: String,
    pub channel: ChannelKind,
    pub recipient: String,
    pub subject: Option<String>,
    /// SHA-256 of the body for Standard payloads; `None` for
    /// EphemeralSecret (no unsalted digest of raw secrets is ever stored).
    pub body_digest: Option<[u8; 32]>,
    pub payload_class: PayloadClass,
    pub max_attempts: u32,
}

/// Port over the durable intent rows.
#[async_trait]
pub trait DeliveryStore: Send + Sync {
    /// Insert the intent if absent. Returns `true` when newly inserted;
    /// `false` when an intent with the same `message_id` already exists.
    async fn record_intent(
        &self,
        record: &IntentRecord,
        now: PrimitiveDateTime,
    ) -> Result<bool, DeliveryError>;

    /// CAS-lease exactly one attempt. Consumes one attempt from the budget,
    /// bumps the generation, and grants an exclusive lease until expiry.
    async fn acquire_attempt(
        &self,
        message_id: &str,
        worker: &WorkerIdentity,
        lease_ttl: Duration,
        now: PrimitiveDateTime,
    ) -> Result<AttemptLease, DeliveryError>;

    /// Settle the attempt with the exact lease generation. Returns the
    /// durable state after settlement. A lost race returns
    /// [`DeliveryError::LeaseExpired`] — the outcome must be treated as
    /// unknown (another claimant may have taken over after expiry).
    async fn record_outcome(
        &self,
        lease: &AttemptLease,
        truth: &DeliveryTruth,
        now: PrimitiveDateTime,
    ) -> Result<DeliveryState, DeliveryError>;

    /// Force an unsettled, lease-expired row to `IN_DOUBT` (explicit
    /// reconciliation required). CAS on generation.
    async fn mark_in_doubt(
        &self,
        message_id: &str,
        generation: i64,
        reason: &str,
        now: PrimitiveDateTime,
    ) -> Result<DeliveryState, DeliveryError>;

    /// Reconciliation read.
    async fn current_state(&self, message_id: &str)
        -> Result<Option<DeliveryState>, DeliveryError>;

    /// Reconciliation write: only from `IN_DOUBT` to a terminal truth, with
    /// a provenance marker. Never from a live lease.
    async fn reconcile(
        &self,
        message_id: &str,
        truth: &DeliveryTruth,
        reconciled_by: &str,
        now: PrimitiveDateTime,
    ) -> Result<DeliveryState, DeliveryError>;
}

/// `now` helper: UTC wall clock as `PrimitiveDateTime` (the MySQL DATETIME
/// domain). Callers pass it in so stores stay deterministic under test.
pub fn utc_now() -> PrimitiveDateTime {
    let now_utc = OffsetDateTime::now_utc();
    PrimitiveDateTime::new(now_utc.date(), now_utc.time())
}

/// TTL conversion between std and `time` domains (bounded to avoid overflow).
pub fn ttl_duration(ttl: std::time::Duration) -> TimeDuration {
    TimeDuration::seconds(ttl.as_secs().min(86_400) as i64)
}

#[derive(Debug, Clone)]
struct IntentRow {
    record: IntentRecord,
    state: DeliveryState,
    attempts: u32,
    generation: i64,
    lease_owner: Option<String>,
    lease_expires_at: Option<PrimitiveDateTime>,
    provider_reference: Option<String>,
    last_detail: Option<String>,
    settled_at: Option<PrimitiveDateTime>,
    /// Recorded for parity with the SQL row; not read by the reference store.
    #[allow(dead_code)]
    created_at: PrimitiveDateTime,
}

/// In-memory store for tests and isolated fixtures. Not durable; production
/// composition must use the SQL-backed store.
#[derive(Default)]
pub struct InMemoryDeliveryStore {
    rows: Mutex<HashMap<String, IntentRow>>,
}

impl InMemoryDeliveryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Test helper: number of recorded intents.
    pub fn len(&self) -> usize {
        self.rows.lock().unwrap().len()
    }

    /// Test helper: whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn row(&self, message_id: &str) -> Result<IntentRow, DeliveryError> {
        self.rows
            .lock()
            .unwrap()
            .get(message_id)
            .cloned()
            .ok_or_else(|| DeliveryError::UnknownIntent(message_id.to_owned()))
    }
}

fn lease_deadline(now: PrimitiveDateTime, ttl: std::time::Duration) -> PrimitiveDateTime {
    now + ttl_duration(ttl)
}

#[async_trait]
impl DeliveryStore for InMemoryDeliveryStore {
    async fn record_intent(
        &self,
        record: &IntentRecord,
        now: PrimitiveDateTime,
    ) -> Result<bool, DeliveryError> {
        if record.max_attempts == 0 || record.max_attempts > 32 {
            return Err(DeliveryError::Bounds("max attempts out of range"));
        }
        let mut rows = self.rows.lock().unwrap();
        if let Some(existing) = rows.get(&record.message_id) {
            // Same contract as the SQL store: a reused message id must carry
            // identical immutable metadata, otherwise refuse (IntentConflict).
            let same = existing.record.operation_id == record.operation_id
                && existing.record.channel == record.channel
                && existing.record.recipient == record.recipient
                && existing.record.subject == record.subject
                && existing.record.body_digest == record.body_digest
                && existing.record.payload_class == record.payload_class;
            return if same {
                Ok(false)
            } else {
                Err(DeliveryError::IntentConflict(record.message_id.clone()))
            };
        }
        rows.insert(
            record.message_id.clone(),
            IntentRow {
                record: record.clone(),
                state: DeliveryState::Queued,
                attempts: 0,
                generation: 0,
                lease_owner: None,
                lease_expires_at: None,
                provider_reference: None,
                last_detail: None,
                settled_at: None,
                created_at: now,
            },
        );
        Ok(true)
    }

    async fn acquire_attempt(
        &self,
        message_id: &str,
        worker: &WorkerIdentity,
        lease_ttl: Duration,
        now: PrimitiveDateTime,
    ) -> Result<AttemptLease, DeliveryError> {
        let mut rows = self.rows.lock().unwrap();
        let row = rows
            .get_mut(message_id)
            .ok_or_else(|| DeliveryError::UnknownIntent(message_id.to_owned()))?;

        if row.state == DeliveryState::InDoubt {
            return Err(DeliveryError::ReconciliationRequired);
        }
        if row.state.is_terminal() || row.state == DeliveryState::Accepted {
            return Err(DeliveryError::BudgetExhausted(format!(
                "intent already {}",
                row.state.as_str()
            )));
        }
        // Lease discipline (mirrors the SQL contract):
        // - live lease: single winner, no takeover;
        // - dirty expiry (owner still set after a granted attempt): the
        //   attempt outcome is unknown -> sticky IN_DOUBT, never reclaim+send;
        // - clean release (owner cleared by a settled outcome): bounded retry.
        if let Some(expires_at) = row.lease_expires_at {
            if expires_at > now {
                return Err(DeliveryError::LeaseConflict);
            }
            if row.lease_owner.is_some() && row.attempts > 0 {
                row.state = DeliveryState::InDoubt;
                row.lease_owner = None;
                row.lease_expires_at = None;
                row.last_detail =
                    Some("lease expired after dispatch began; reconciliation required".into());
                return Err(DeliveryError::ReconciliationRequired);
            }
        }
        if row.attempts >= row.record.max_attempts {
            row.state = DeliveryState::Expired;
            row.settled_at = Some(now);
            return Err(DeliveryError::BudgetExhausted(message_id.to_owned()));
        }

        row.attempts += 1;
        row.generation += 1;
        row.lease_owner = Some(worker.id.clone());
        let expires_at = lease_deadline(now, lease_ttl);
        row.lease_expires_at = Some(expires_at);
        Ok(AttemptLease {
            message_id: message_id.to_owned(),
            generation: row.generation,
            lease_owner: worker.id.clone(),
            lease_expires_at: expires_at,
            attempt_no: row.attempts,
        })
    }

    async fn record_outcome(
        &self,
        lease: &AttemptLease,
        truth: &DeliveryTruth,
        now: PrimitiveDateTime,
    ) -> Result<DeliveryState, DeliveryError> {
        let mut rows = self.rows.lock().unwrap();
        let row = rows
            .get_mut(&lease.message_id)
            .ok_or_else(|| DeliveryError::UnknownIntent(lease.message_id.clone()))?;

        if row.generation != lease.generation
            || row.lease_owner.as_deref() != Some(&lease.lease_owner)
        {
            return Err(DeliveryError::LeaseExpired);
        }
        // A late lease cannot settle (mirror of the SQL guard): the lease
        // must still be live and the row must be in a pre-settle state.
        let lease_live = matches!(row.lease_expires_at, Some(expires_at) if expires_at > now);
        let pre_settle = matches!(
            row.state,
            DeliveryState::NotAttempted | DeliveryState::Queued | DeliveryState::Accepted
        );
        if !lease_live || !pre_settle {
            return Err(DeliveryError::LeaseExpired);
        }
        row.state = truth.state;
        row.provider_reference = truth.provider_reference.clone();
        row.last_detail = Some(truth.detail.clone());
        row.lease_owner = None;
        row.lease_expires_at = None;
        if truth.state.is_terminal() {
            row.settled_at = Some(now);
        }
        Ok(row.state)
    }

    async fn mark_in_doubt(
        &self,
        message_id: &str,
        generation: i64,
        reason: &str,
        _now: PrimitiveDateTime,
    ) -> Result<DeliveryState, DeliveryError> {
        let mut rows = self.rows.lock().unwrap();
        let row = rows
            .get_mut(message_id)
            .ok_or_else(|| DeliveryError::UnknownIntent(message_id.to_owned()))?;
        if row.generation != generation {
            return Err(DeliveryError::LeaseExpired);
        }
        if matches!(
            row.state,
            DeliveryState::Delivered | DeliveryState::Failed | DeliveryState::Expired
        ) {
            return Ok(row.state);
        }
        row.state = DeliveryState::InDoubt;
        row.lease_owner = None;
        row.lease_expires_at = None;
        row.last_detail = Some(reason.to_owned());
        Ok(row.state)
    }

    async fn current_state(
        &self,
        message_id: &str,
    ) -> Result<Option<DeliveryState>, DeliveryError> {
        Ok(Some(self.row(message_id)?.state))
    }

    async fn reconcile(
        &self,
        message_id: &str,
        truth: &DeliveryTruth,
        reconciled_by: &str,
        now: PrimitiveDateTime,
    ) -> Result<DeliveryState, DeliveryError> {
        if !truth.state.is_terminal() {
            return Err(DeliveryError::InvalidConfig(
                "reconciliation must settle a terminal truth",
            ));
        }
        let mut rows = self.rows.lock().unwrap();
        let row = rows
            .get_mut(message_id)
            .ok_or_else(|| DeliveryError::UnknownIntent(message_id.to_owned()))?;
        if row.state != DeliveryState::InDoubt {
            return Err(DeliveryError::ReconciliationRequired);
        }
        if reconciled_by.trim().is_empty() || reconciled_by.len() > 128 {
            return Err(DeliveryError::InvalidConfig("reconciliation actor"));
        }
        row.state = truth.state;
        row.provider_reference = truth.provider_reference.clone();
        row.last_detail = Some(format!("reconciled by {reconciled_by}: {}", truth.detail));
        row.settled_at = Some(now);
        Ok(row.state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: Duration = Duration::from_secs(60);

    fn t0() -> PrimitiveDateTime {
        datetime!(2026-11-07 0:00)
    }

    fn t(seconds: i64) -> PrimitiveDateTime {
        t0() + TimeDuration::seconds(seconds)
    }

    fn worker(id: &str) -> WorkerIdentity {
        WorkerIdentity { id: id.to_owned() }
    }

    fn record(message_id: &str) -> IntentRecord {
        IntentRecord {
            message_id: message_id.to_owned(),
            operation_id: "op-1".to_owned(),
            channel: ChannelKind::Email,
            recipient: "user@example.com".to_owned(),
            subject: None,
            body_digest: Some([7u8; 32]),
            payload_class: PayloadClass::Standard,
            max_attempts: 3,
        }
    }

    #[tokio::test]
    async fn record_intent_is_idempotent_by_message_id() {
        let store = InMemoryDeliveryStore::new();
        assert!(store.record_intent(&record("m1"), t0()).await.unwrap());
        assert!(!store.record_intent(&record("m1"), t(1)).await.unwrap());
        assert_eq!(store.len(), 1);
    }

    #[tokio::test]
    async fn acquire_is_single_winner_with_live_lease() {
        let store = InMemoryDeliveryStore::new();
        store.record_intent(&record("m1"), t0()).await.unwrap();
        let first = store
            .acquire_attempt("m1", &worker("w1"), T, t(1))
            .await
            .unwrap();
        assert_eq!(first.generation, 1);
        assert_eq!(first.attempt_no, 1);
        let second = store
            .acquire_attempt("m1", &worker("w2"), T, t(2))
            .await
            .unwrap_err();
        assert_eq!(second, DeliveryError::LeaseConflict);
    }

    #[tokio::test]
    async fn dirty_expired_lease_is_sticky_in_doubt_and_never_reclaimed() {
        // Worker acquired, dispatched, and crashed: the lease expired with
        // the owner still set. The attempt outcome is unknown, so the row
        // must go sticky IN_DOUBT — no automatic reclaim+send, ever.
        let store = InMemoryDeliveryStore::new();
        store.record_intent(&record("m1"), t0()).await.unwrap();
        let first = store
            .acquire_attempt("m1", &worker("w1"), T, t(1))
            .await
            .unwrap();
        let refused = store
            .acquire_attempt("m1", &worker("w2"), T, t(1 + 61))
            .await
            .unwrap_err();
        assert_eq!(refused, DeliveryError::ReconciliationRequired);
        assert_eq!(
            store.current_state("m1").await.unwrap(),
            Some(DeliveryState::InDoubt),
            "dirty expiry must be sticky"
        );
        // Even much later: still refused, still IN_DOUBT.
        for at in [t(1 + 120), t(1 + 600)] {
            assert_eq!(
                store
                    .acquire_attempt("m1", &worker("w3"), T, at)
                    .await
                    .unwrap_err(),
                DeliveryError::ReconciliationRequired
            );
        }
        assert_eq!(first.generation, 1);
        // Only explicit reconciliation settles it; no new attempt is granted.
        assert_eq!(
            store
                .reconcile(
                    "m1",
                    &DeliveryTruth::failed("provider confirmed loss"),
                    "ops:console",
                    t(1 + 700)
                )
                .await
                .unwrap(),
            DeliveryState::Failed
        );
    }

    #[tokio::test]
    async fn cleanly_released_transient_row_retries_within_budget() {
        // A settled transient outcome (4xx) releases the lease cleanly:
        // bounded retry is allowed and consumes exactly one more attempt.
        let store = InMemoryDeliveryStore::new();
        store.record_intent(&record("m1"), t0()).await.unwrap();
        let first = store
            .acquire_attempt("m1", &worker("w1"), T, t(1))
            .await
            .unwrap();
        store
            .record_outcome(
                &first,
                &DeliveryTruth::retry_scheduled("451 try later"),
                t(2),
            )
            .await
            .unwrap();
        let second = store
            .acquire_attempt("m1", &worker("w2"), T, t(3))
            .await
            .expect("clean release must allow the bounded retry");
        assert_eq!(second.attempt_no, 2);
        assert_eq!(second.generation, first.generation + 1);
    }

    #[tokio::test]
    async fn late_lease_cannot_settle() {
        // The lease expired before settlement: the outcome must not be
        // recorded — the row goes through reconciliation instead.
        let store = InMemoryDeliveryStore::new();
        store.record_intent(&record("m1"), t0()).await.unwrap();
        let lease = store
            .acquire_attempt("m1", &worker("w1"), T, t(1))
            .await
            .unwrap();
        assert_eq!(
            store
                .record_outcome(
                    &lease,
                    &DeliveryTruth::delivered(Some("p"), "late"),
                    t(1 + 61)
                )
                .await
                .unwrap_err(),
            DeliveryError::LeaseExpired
        );
        assert_eq!(
            store.current_state("m1").await.unwrap(),
            Some(DeliveryState::Queued),
            "no late settlement"
        );
    }

    #[tokio::test]
    async fn record_intent_refuses_metadata_conflicts() {
        let store = InMemoryDeliveryStore::new();
        assert!(store.record_intent(&record("m1"), t0()).await.unwrap());
        // Identical record: idempotent (false = not inserted).
        assert!(!store.record_intent(&record("m1"), t(1)).await.unwrap());
        // Same id, different recipient: conflict.
        let mut conflicting = record("m1");
        conflicting.recipient = "other@example.com".to_owned();
        assert_eq!(
            store.record_intent(&conflicting, t(2)).await.unwrap_err(),
            DeliveryError::IntentConflict("m1".to_owned())
        );
        // Same id, different digest: conflict.
        let mut conflicting = record("m1");
        conflicting.body_digest = Some([9u8; 32]);
        assert!(matches!(
            store.record_intent(&conflicting, t(2)).await,
            Err(DeliveryError::IntentConflict(_))
        ));
        assert_eq!(store.len(), 1);
    }

    #[tokio::test]
    async fn outcome_settles_only_with_exact_generation() {
        let store = InMemoryDeliveryStore::new();
        store.record_intent(&record("m1"), t0()).await.unwrap();
        let lease = store
            .acquire_attempt("m1", &worker("w1"), T, t(1))
            .await
            .unwrap();
        let stale = AttemptLease {
            generation: lease.generation - 1,
            ..lease.clone()
        };
        assert_eq!(
            store
                .record_outcome(&stale, &DeliveryTruth::accepted(None, "late"), t(2))
                .await
                .unwrap_err(),
            DeliveryError::LeaseExpired
        );
        let settled = store
            .record_outcome(&lease, &DeliveryTruth::accepted(None, "mta queued"), t(2))
            .await
            .unwrap();
        assert_eq!(settled, DeliveryState::Accepted);
        assert_eq!(
            store.current_state("m1").await.unwrap(),
            Some(DeliveryState::Accepted)
        );
    }

    #[tokio::test]
    async fn in_doubt_blocks_attempts_until_explicit_reconcile() {
        let store = InMemoryDeliveryStore::new();
        store.record_intent(&record("m1"), t0()).await.unwrap();
        let lease = store
            .acquire_attempt("m1", &worker("w1"), T, t(1))
            .await
            .unwrap();
        store
            .record_outcome(&lease, &DeliveryTruth::in_doubt("connection lost"), t(2))
            .await
            .unwrap();
        assert_eq!(
            store
                .acquire_attempt("m1", &worker("w2"), T, t(3))
                .await
                .unwrap_err(),
            DeliveryError::ReconciliationRequired
        );
        // Non-terminal reconcile is refused.
        assert_eq!(
            store
                .reconcile("m1", &DeliveryTruth::retry_scheduled("no"), "op", t(4))
                .await
                .unwrap_err(),
            DeliveryError::InvalidConfig("reconciliation must settle a terminal truth")
        );
        let settled = store
            .reconcile(
                "m1",
                &DeliveryTruth::failed("provider confirmed loss"),
                "ops:console",
                t(4),
            )
            .await
            .unwrap();
        assert_eq!(settled, DeliveryState::Failed);
        assert_eq!(
            store.current_state("m1").await.unwrap(),
            Some(DeliveryState::Failed)
        );
    }

    #[tokio::test]
    async fn budget_exhaustion_never_expires_an_active_lease() {
        // The final attempt still holds a live lease: a concurrent refusal
        // must observe LeaseConflict, never clear the lease and hide an
        // unknown delivery (mirror of the SQL EXPIRE_BUDGET guard).
        let store = InMemoryDeliveryStore::new();
        let mut record = record("m1");
        record.max_attempts = 1;
        store.record_intent(&record, t0()).await.unwrap();
        let lease = store
            .acquire_attempt("m1", &worker("w1"), T, t(1))
            .await
            .unwrap();
        assert_eq!(
            store
                .acquire_attempt("m1", &worker("w2"), T, t(2))
                .await
                .unwrap_err(),
            DeliveryError::LeaseConflict
        );
        assert_eq!(
            store.current_state("m1").await.unwrap(),
            Some(DeliveryState::Queued),
            "active lease must not be cleared by a refusal"
        );
        let _ = lease;
    }

    #[tokio::test]
    async fn budget_exhaustion_expires_the_intent() {
        let store = InMemoryDeliveryStore::new();
        let mut record = record("m1");
        record.max_attempts = 1;
        store.record_intent(&record, t0()).await.unwrap();
        let lease = store
            .acquire_attempt("m1", &worker("w1"), T, t(1))
            .await
            .unwrap();
        // Transient refusal keeps the row queued but consumes the budget.
        store
            .record_outcome(
                &lease,
                &DeliveryTruth::retry_scheduled("451 try later"),
                t(2),
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .acquire_attempt("m1", &worker("w2"), T, t(3))
                .await
                .unwrap_err(),
            DeliveryError::BudgetExhausted("m1".to_owned())
        );
        assert_eq!(
            store.current_state("m1").await.unwrap(),
            Some(DeliveryState::Expired)
        );
    }

    #[tokio::test]
    async fn mark_in_doubt_is_generation_cas_and_respects_settled_truth() {
        let store = InMemoryDeliveryStore::new();
        store.record_intent(&record("m1"), t0()).await.unwrap();
        assert_eq!(
            store
                .mark_in_doubt("m1", 99, "stale generation", t(1))
                .await
                .unwrap_err(),
            DeliveryError::LeaseExpired
        );
        store
            .mark_in_doubt("m1", 0, "worker restart with live lease", t(1))
            .await
            .unwrap();
        assert_eq!(
            store.current_state("m1").await.unwrap(),
            Some(DeliveryState::InDoubt)
        );
    }

    #[tokio::test]
    async fn unknown_intent_is_typed() {
        let store = InMemoryDeliveryStore::new();
        assert_eq!(
            store.current_state("missing").await.unwrap_err(),
            DeliveryError::UnknownIntent("missing".to_owned())
        );
    }

    use time::macros::datetime;
}
