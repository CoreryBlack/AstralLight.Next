//! TrustGraph-owned audit quarantine replay worker.
//!
//! The worker is deliberately narrower than the normal MQ consumer path.  It
//! claims only operator-requested TrustGraph audit rows, validates the stored
//! envelope and payload before touching RabbitMQ, publishes through the raw
//! replay allowlist, and confirms the durable row only after `Ack(None)`.
//! `REPLAY_CONFIRMED` therefore means broker publish confirmation only; it does
//! not assert that the ordinary audit consumer has processed the message.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use lapin::types::ShortString;
use lapin::BasicProperties;
use serde_json::Value;
use tokio::sync::{Notify, RwLock};
use tokio::task::JoinHandle;

use astral_common::service::AUDIT_DETAIL_MAX_BYTES;
use astral_db::{
    begin_next_expired_replaying_replay, begin_next_requested_replay, confirm_replay_claim,
    fail_replay_claim, list_exhausted_replays, AuditQuarantineReplayClaim, MAX_PAYLOAD_BYTES,
    MAX_REPLAY_ATTEMPTS,
};
use astral_mq::config::{EXCHANGE_DIRECT, MAX_RAW_REPLAY_PAYLOAD_BYTES, QUEUE_AUDIT_LOG};
use astral_mq::producer::{AuditLogPayload, MqMessage, Producer, RawReplayError, RawReplayRequest};

const WORKER_OWNER: &str = "trustgraph-audit-replay-worker";
const MESSAGE_TYPE: &str = "AUDIT_LOG";
const ROUTING_KEY: &str = "audit.log";
const POLL_INTERVAL: Duration = Duration::from_secs(5);
const ERROR_BACKOFF_MIN: Duration = Duration::from_secs(1);
const ERROR_BACKOFF_MAX: Duration = Duration::from_secs(30);
const LEASE_SECONDS: i64 = 60;
const MAX_MESSAGE_ID_BYTES: usize = 255;
const MAX_FAILURE_REASON_BYTES: usize = 255;

/// A small cancellation token kept local to TrustGraph so the worker does not
/// need to expose a broker or database runtime through `AppState`.
#[derive(Clone, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl CancellationToken {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        // notify_one retains a permit when cancellation races with waiter setup.
        self.notify.notify_one();
    }

    async fn cancelled(&self) {
        if self.cancelled.load(Ordering::Acquire) {
            return;
        }
        self.notify.notified().await;
    }
}

/// A safe hand-off point between the MQ connection bootstrap and the worker.
/// The worker starts before RabbitMQ is ready and never receives a detached
/// channel; a later connection can replace the producer atomically.
#[derive(Clone, Default)]
pub struct AuditReplayProducerSlot(Arc<RwLock<Option<Producer>>>);

impl AuditReplayProducerSlot {
    pub fn new() -> Self {
        Self::default()
    }

    /// Install the confirmed producer once. Replacing a live channel would
    /// let a stale bootstrap task race the worker with an invalid producer.
    pub async fn set(&self, producer: Producer) -> bool {
        let mut slot = self.0.write().await;
        if slot.is_some() {
            return false;
        }
        *slot = Some(producer);
        true
    }

    pub async fn clear(&self) {
        *self.0.write().await = None;
    }

    async fn get(&self) -> Option<Producer> {
        self.0.read().await.clone()
    }
}

/// The main task owns this handle and must cancel and join it during shutdown.
pub struct AuditReplayWorkerHandle {
    pub cancellation: CancellationToken,
    pub join: JoinHandle<Result<(), AuditReplayWorkerError>>,
}

#[derive(Debug, thiserror::Error)]
pub enum AuditReplayWorkerError {
    #[error("audit replay database operation failed: {0}")]
    Database(#[from] astral_db::DbError),
    #[error("audit replay validation failed: {0}")]
    Validation(&'static str),
    #[error("audit replay publish failed: {0}")]
    Publish(#[from] RawReplayError),
    #[error("audit replay confirmation was rejected by the lease fence")]
    ConfirmationRejected,
    #[error("audit replay failure transition was rejected by the lease fence")]
    FailureTransitionRejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CycleOutcome {
    NoProducer,
    NoWork,
    Confirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplayClaimSource {
    Requested,
    Expired,
    None,
}

fn choose_replay_claim_source(
    requested_available: bool,
    expired_available: bool,
) -> ReplayClaimSource {
    if requested_available {
        ReplayClaimSource::Requested
    } else if expired_available {
        ReplayClaimSource::Expired
    } else {
        ReplayClaimSource::None
    }
}

/// Start one owned worker task.  There is exactly one claim/publish attempt at
/// a time; the durable SQL CAS remains the cross-node concurrency fence.
pub fn start_worker(
    db: sqlx::MySqlPool,
    producer_slot: AuditReplayProducerSlot,
) -> AuditReplayWorkerHandle {
    let cancellation = CancellationToken::default();
    let worker_cancellation = cancellation.clone();
    let join =
        tokio::spawn(async move { run_worker(db, producer_slot, worker_cancellation).await });
    AuditReplayWorkerHandle { cancellation, join }
}

async fn run_worker(
    db: sqlx::MySqlPool,
    producer_slot: AuditReplayProducerSlot,
    cancellation: CancellationToken,
) -> Result<(), AuditReplayWorkerError> {
    let mut failures = 0u32;
    loop {
        if cancellation.cancelled.load(Ordering::Acquire) {
            tracing::info!(owner = WORKER_OWNER, "audit replay worker stopped");
            return Ok(());
        }

        let cycle = run_cycle(&db, &producer_slot).await;
        match cycle {
            Ok(CycleOutcome::NoProducer) | Ok(CycleOutcome::NoWork) => {
                failures = 0;
                wait_or_cancel(&cancellation, POLL_INTERVAL).await;
            }
            Ok(CycleOutcome::Confirmed) => {
                failures = 0;
                tracing::info!(
                    owner = WORKER_OWNER,
                    "audit replay broker publish confirmed; business consumer status is separate"
                );
                wait_or_cancel(&cancellation, Duration::from_millis(100)).await;
            }
            Err(error) => {
                failures = failures.saturating_add(1);
                tracing::error!(
                    owner = WORKER_OWNER,
                    failures,
                    error = %error,
                    "audit replay cycle failed; row remains unconfirmed"
                );
                let multiplier = 2u64.saturating_pow(failures.saturating_sub(1).min(5));
                let delay = ERROR_BACKOFF_MIN
                    .checked_mul(multiplier as u32)
                    .unwrap_or(ERROR_BACKOFF_MAX)
                    .min(ERROR_BACKOFF_MAX);
                wait_or_cancel(&cancellation, delay).await;
            }
        }
    }
}

async fn wait_or_cancel(cancellation: &CancellationToken, duration: Duration) {
    tokio::select! {
        _ = cancellation.cancelled() => {}
        _ = tokio::time::sleep(duration) => {}
    }
}

async fn run_cycle(
    db: &sqlx::MySqlPool,
    producer_slot: &AuditReplayProducerSlot,
) -> Result<CycleOutcome, AuditReplayWorkerError> {
    let Some(producer) = producer_slot.get().await else {
        return Ok(CycleOutcome::NoProducer);
    };

    let requested_claim = begin_next_requested_replay(
        db,
        WORKER_OWNER,
        QUEUE_AUDIT_LOG,
        EXCHANGE_DIRECT,
        ROUTING_KEY,
        MESSAGE_TYPE,
        LEASE_SECONDS,
    )
    .await?;
    let expired_claim = if requested_claim.is_none() {
        begin_next_expired_replaying_replay(
            db,
            WORKER_OWNER,
            QUEUE_AUDIT_LOG,
            EXCHANGE_DIRECT,
            ROUTING_KEY,
            MESSAGE_TYPE,
            LEASE_SECONDS,
        )
        .await?
    } else {
        None
    };

    match choose_replay_claim_source(requested_claim.is_some(), expired_claim.is_some()) {
        ReplayClaimSource::Requested => {
            return process_claim(
                db,
                producer,
                requested_claim.ok_or(AuditReplayWorkerError::FailureTransitionRejected)?,
            )
            .await;
        }
        ReplayClaimSource::Expired => {
            let claim = expired_claim.ok_or(AuditReplayWorkerError::FailureTransitionRejected)?;
            tracing::info!(
                owner = WORKER_OWNER,
                replay_id = claim.raw_record.metadata.id,
                replay_attempts = claim.raw_record.metadata.replay_attempts,
                "reclaimed expired audit replay lease"
            );
            return process_claim(db, producer, claim).await;
        }
        ReplayClaimSource::None => {}
    }

    let exhausted = list_exhausted_replays(
        db,
        QUEUE_AUDIT_LOG,
        EXCHANGE_DIRECT,
        ROUTING_KEY,
        MESSAGE_TYPE,
        1,
    )
    .await?;
    if let Some(row) = exhausted.first() {
        tracing::warn!(
            owner = WORKER_OWNER,
            replay_id = row.id,
            replay_attempts = row.replay_attempts,
            max_replay_attempts = MAX_REPLAY_ATTEMPTS,
            status = row.status.as_str(),
            failure_reason = %row.failure_reason,
            "audit replay reached maximum attempts and remains unconfirmed"
        );
    }
    Ok(CycleOutcome::NoWork)
}

async fn process_claim(
    db: &sqlx::MySqlPool,
    producer: astral_mq::producer::Producer,
    claim: AuditQuarantineReplayClaim,
) -> Result<CycleOutcome, AuditReplayWorkerError> {
    match validate_claim(&claim) {
        Ok(request) => match producer.publish_raw_replay(request).await {
            Ok(()) => {
                if !confirm_replay_claim(db, &claim).await? {
                    fail_claim(db, &claim, "replay_confirm_rejected").await?;
                    return Err(AuditReplayWorkerError::ConfirmationRejected);
                }
                Ok(CycleOutcome::Confirmed)
            }
            Err(error) => {
                fail_claim(db, &claim, &publish_failure_reason(&error)).await?;
                Err(AuditReplayWorkerError::Publish(error))
            }
        },
        Err(error) => {
            let reason = error_reason(&error);
            fail_claim(db, &claim, reason).await?;
            Err(error)
        }
    }
}

async fn fail_claim(
    db: &sqlx::MySqlPool,
    claim: &AuditQuarantineReplayClaim,
    reason: &str,
) -> Result<(), AuditReplayWorkerError> {
    let bounded_reason = bounded_reason(reason);
    if fail_replay_claim(db, claim, &bounded_reason).await? {
        Ok(())
    } else {
        Err(AuditReplayWorkerError::FailureTransitionRejected)
    }
}

fn validate_claim(
    claim: &AuditQuarantineReplayClaim,
) -> Result<RawReplayRequest, AuditReplayWorkerError> {
    let metadata = &claim.raw_record.metadata;
    if metadata.source_queue != QUEUE_AUDIT_LOG
        || metadata.source_exchange != EXCHANGE_DIRECT
        || metadata.source_routing_key != ROUTING_KEY
        || metadata.message_type != MESSAGE_TYPE
    {
        return Err(AuditReplayWorkerError::Validation("route_not_allowlisted"));
    }
    if metadata.message_id.is_empty() || metadata.message_id.len() > MAX_MESSAGE_ID_BYTES {
        return Err(AuditReplayWorkerError::Validation(
            "metadata_message_id_invalid",
        ));
    }
    if claim.raw_record.raw_payload.is_empty()
        || claim.raw_record.raw_payload.len() > MAX_RAW_REPLAY_PAYLOAD_BYTES
        || claim.raw_record.raw_payload.len() > MAX_PAYLOAD_BYTES
    {
        return Err(AuditReplayWorkerError::Validation("payload_size_invalid"));
    }

    let value: Value = serde_json::from_slice(&claim.raw_record.raw_payload)
        .map_err(|_| AuditReplayWorkerError::Validation("malformed_json"))?;
    let (_envelope_message_id, timestamp) = {
        let object = value
            .as_object()
            .ok_or(AuditReplayWorkerError::Validation("envelope_not_object"))?;
        const ALLOWED_FIELDS: &[&str] = &[
            "messageId",
            "timestamp",
            "userId",
            "cardId",
            "action",
            "resource",
            "decision",
            "reason",
            "eventType",
            "sourceIp",
            "requestId",
            "domainId",
            "tenantId",
            // detail 是 AuditLogPayload 的合同可选字段（serde(default)，旧消息
            // 无此键）。它必须进入 allowlist，否则携带 detail 的隔离消息（例
            // 如 ORG_SCOPE provenance detail）会在此处以
            // envelope_field_not_allowlisted 被拒，永远走不到下方的
            // audit_optional_field_invalid 字节上界校验，永久不可重放。
            "detail",
        ];
        let payload_object = object.get("payload").and_then(Value::as_object);
        let fields = payload_object.unwrap_or(object);
        if object
            .keys()
            .any(|key| !ALLOWED_FIELDS.contains(&key.as_str()) && key != "payload")
            || payload_object.is_some_and(|payload| {
                payload
                    .keys()
                    .any(|key| !ALLOWED_FIELDS.contains(&key.as_str()))
            })
        {
            return Err(AuditReplayWorkerError::Validation(
                "envelope_field_not_allowlisted",
            ));
        }
        let envelope_message_id = object
            .get("messageId")
            .or_else(|| fields.get("messageId"))
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or(AuditReplayWorkerError::Validation("message_id_invalid"))?;
        if envelope_message_id != metadata.message_id {
            return Err(AuditReplayWorkerError::Validation("message_id_mismatch"));
        }
        let timestamp = object
            .get("timestamp")
            .or_else(|| fields.get("timestamp"))
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or(AuditReplayWorkerError::Validation("timestamp_invalid"))?;
        time::OffsetDateTime::parse(timestamp, &time::format_description::well_known::Rfc3339)
            .map_err(|_| AuditReplayWorkerError::Validation("timestamp_not_rfc3339"))?;
        (envelope_message_id.to_owned(), timestamp.to_owned())
    };

    let envelope: MqMessage<AuditLogPayload> = serde_json::from_value(value)
        .map_err(|_| AuditReplayWorkerError::Validation("audit_payload_invalid"))?;
    if envelope.message_id != metadata.message_id || envelope.timestamp != timestamp {
        return Err(AuditReplayWorkerError::Validation(
            "envelope_identity_mismatch",
        ));
    }
    validate_audit_payload(&envelope.payload)?;

    let properties = BasicProperties::default()
        .with_delivery_mode(2)
        .with_content_type(ShortString::from("application/json"));
    Ok(RawReplayRequest::new(
        "trustgraph",
        QUEUE_AUDIT_LOG,
        EXCHANGE_DIRECT,
        ROUTING_KEY,
        claim.raw_record.raw_payload.clone(),
        properties,
        metadata.message_id.clone(),
    ))
}

/// 校验审计 payload：必填字段非空，且所有审计字符串字段不超过共享合同上界
/// `astral_common::service::AUDIT_DETAIL_MAX_BYTES`（合同义务针对可选
/// `detail` 字段，对必填字段是同值纵深防御），防止重放路径写入无界字段。
fn validate_audit_payload(payload: &AuditLogPayload) -> Result<(), AuditReplayWorkerError> {
    for (name, value) in [
        ("action", payload.action.as_str()),
        ("resource", payload.resource.as_str()),
        ("decision", payload.decision.as_str()),
        ("event_type", payload.event_type.as_str()),
    ] {
        if value.trim().is_empty() || value.len() > AUDIT_DETAIL_MAX_BYTES {
            return Err(AuditReplayWorkerError::Validation(match name {
                "action" => "audit_action_invalid",
                "resource" => "audit_resource_invalid",
                "decision" => "audit_decision_invalid",
                _ => "audit_event_type_invalid",
            }));
        }
    }
    for value in [
        payload.reason.as_deref(),
        payload.source_ip.as_deref(),
        payload.request_id.as_deref(),
        // producer detail（例如 ORG_SCOPE provenance JSON）与其他可选字段
        // 同受共享合同上界（`AUDIT_DETAIL_MAX_BYTES`）约束，防止重放路径
        // 写入无界 detail。
        payload.detail.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if value.len() > AUDIT_DETAIL_MAX_BYTES {
            return Err(AuditReplayWorkerError::Validation(
                "audit_optional_field_invalid",
            ));
        }
    }
    Ok(())
}

fn error_reason(error: &AuditReplayWorkerError) -> &'static str {
    match error {
        AuditReplayWorkerError::Validation(reason) => reason,
        AuditReplayWorkerError::ConfirmationRejected => "replay_confirm_rejected",
        AuditReplayWorkerError::FailureTransitionRejected => "replay_failure_transition_rejected",
        AuditReplayWorkerError::Database(_) => "replay_database_error",
        AuditReplayWorkerError::Publish(_) => "replay_publish_error",
    }
}

fn publish_failure_reason(error: &RawReplayError) -> String {
    bounded_reason(&format!("replay_publish_error:{error}"))
}

fn bounded_reason(reason: &str) -> String {
    reason.chars().take(MAX_FAILURE_REASON_BYTES).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_db::{AuditQuarantineMetadata, AuditQuarantineRawRecord, AuditQuarantineStatus};

    fn claim_with(payload: &[u8], message_id: &str) -> AuditQuarantineReplayClaim {
        let timestamp = time::PrimitiveDateTime::new(
            time::Date::from_calendar_date(2026, time::Month::January, 1).unwrap(),
            time::Time::MIDNIGHT,
        );
        AuditQuarantineReplayClaim {
            raw_record: AuditQuarantineRawRecord {
                metadata: AuditQuarantineMetadata {
                    id: 7,
                    identity_key: [0; 32],
                    message_id: message_id.into(),
                    message_type: MESSAGE_TYPE.into(),
                    source_queue: QUEUE_AUDIT_LOG.into(),
                    source_exchange: EXCHANGE_DIRECT.into(),
                    source_routing_key: ROUTING_KEY.into(),
                    retry_count: 3,
                    attempts: 1,
                    replay_attempts: 1,
                    failure_reason: "terminal".into(),
                    status: AuditQuarantineStatus::Replaying,
                    replay_lease_owner: Some(WORKER_OWNER.into()),
                    replay_lease_generation: 1,
                    replay_lease_expires_at: Some(timestamp),
                    replay_requested_by: Some("operator".into()),
                    replay_requested_at: Some(timestamp),
                    first_failed_at: timestamp,
                    last_failed_at: timestamp,
                    quarantined_at: timestamp,
                    replayed_at: None,
                },
                raw_payload: payload.to_vec(),
            },
            lease_owner: WORKER_OWNER.into(),
            lease_generation: 1,
            lease_token: astral_db::ReplayLeaseToken::for_test("token"),
            lease_expires_at: timestamp,
            operation_identity: astral_db::ReplayOperationIdentity::for_test("operation"),
        }
    }

    fn valid_payload(message_id: &str) -> Vec<u8> {
        serde_json::json!({
            "messageId": message_id,
            "timestamp": "2026-01-01T00:00:00Z",
            "userId": 7,
            "action": "read",
            "resource": "audit",
            "decision": "ALLOW",
            "eventType": "PERMISSION_CHECK"
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn validation_accepts_only_exact_audit_envelope() {
        let claim = claim_with(&valid_payload("message-1"), "message-1");
        assert!(validate_claim(&claim).is_ok());
    }

    #[test]
    fn validation_rejects_message_id_timestamp_and_unknown_fields() {
        for payload in [
            br#"{"messageId":"other","timestamp":"2026-01-01T00:00:00Z","action":"read","resource":"audit","decision":"ALLOW","eventType":"X"}"#.to_vec(),
            br#"{"messageId":"message-1","timestamp":"not-time","action":"read","resource":"audit","decision":"ALLOW","eventType":"X"}"#.to_vec(),
            br#"{"messageId":"message-1","timestamp":"2026-01-01T00:00:00Z","action":"read","resource":"audit","decision":"ALLOW","eventType":"X","payload":{"unsafe":true}}"#.to_vec(),
        ] {
            assert!(validate_claim(&claim_with(&payload, "message-1")).is_err());
        }
    }

    #[test]
    fn validation_rejects_non_audit_routes_and_empty_required_fields() {
        let mut claim = claim_with(&valid_payload("message-1"), "message-1");
        claim.raw_record.metadata.source_routing_key = "login.event".into();
        assert!(validate_claim(&claim).is_err());

        let payload = serde_json::json!({
            "messageId": "message-1",
            "timestamp": "2026-01-01T00:00:00Z",
            "action": "",
            "resource": "audit",
            "decision": "ALLOW",
            "eventType": "X"
        });
        assert!(
            validate_claim(&claim_with(&payload.to_string().into_bytes(), "message-1")).is_err()
        );
    }

    #[test]
    fn failure_reasons_are_bounded_without_raw_payload() {
        let raw_payload_marker = "raw-payload-must-not-be-logged";
        let reason = bounded_reason(&format!("{}{}", raw_payload_marker, "x".repeat(1000)));
        assert_eq!(reason.len(), MAX_FAILURE_REASON_BYTES);
        assert!(reason.starts_with(raw_payload_marker));
        assert!(!publish_failure_reason(&RawReplayError::PayloadTooLarge {
            limit: MAX_RAW_REPLAY_PAYLOAD_BYTES,
            actual: MAX_RAW_REPLAY_PAYLOAD_BYTES + 1,
        })
        .contains(raw_payload_marker));
    }

    #[test]
    fn confirmation_and_failure_fence_errors_have_bounded_machine_reasons() {
        assert_eq!(
            error_reason(&AuditReplayWorkerError::ConfirmationRejected),
            "replay_confirm_rejected"
        );
        assert_eq!(
            error_reason(&AuditReplayWorkerError::FailureTransitionRejected),
            "replay_failure_transition_rejected"
        );
        assert_eq!(
            bounded_reason(&"a".repeat(MAX_FAILURE_REASON_BYTES + 10)).len(),
            MAX_FAILURE_REASON_BYTES
        );
    }

    #[test]
    fn claim_source_decision_never_treats_missing_claim_as_confirmed() {
        assert_eq!(
            choose_replay_claim_source(false, false),
            ReplayClaimSource::None
        );
        assert_ne!(CycleOutcome::NoWork, CycleOutcome::Confirmed);
    }

    #[test]
    fn requested_replay_has_priority_over_expired_recovery() {
        assert_eq!(
            choose_replay_claim_source(true, true),
            ReplayClaimSource::Requested
        );
        assert_eq!(
            choose_replay_claim_source(true, false),
            ReplayClaimSource::Requested
        );
    }

    #[test]
    fn expired_replay_is_selected_when_no_request_is_available() {
        assert_eq!(
            choose_replay_claim_source(false, true),
            ReplayClaimSource::Expired
        );
        assert_eq!(
            choose_replay_claim_source(false, false),
            ReplayClaimSource::None
        );
    }

    #[test]
    fn exhausted_attempts_are_not_a_success_outcome() {
        assert_ne!(CycleOutcome::NoWork, CycleOutcome::Confirmed);
        assert_eq!(MAX_REPLAY_ATTEMPTS, 5);
    }

    #[test]
    fn detail_field_matches_the_max_bound_replay_contract() {
        // detail 与 reason/sourceIp/requestId 同受共享合同上界
        // AUDIT_DETAIL_MAX_BYTES（astral_common::service）约束：恰好 1024 字节
        // （producer 侧有界化后的最大合法 detail，例如 ORG provenance 结构化
        // detail）必须可重放；超界 1 字节必须以 audit_optional_field_invalid
        // 拒绝，否则隔离消息将永久不可重放。
        let payload_with_detail = |detail: &str| {
            serde_json::json!({
                "messageId": "message-1",
                "timestamp": "2026-01-01T00:00:00Z",
                "userId": 7,
                "action": "read",
                "resource": "audit",
                "decision": "ALLOW",
                "eventType": "PERMISSION_CHECK",
                "detail": detail,
            })
            .to_string()
            .into_bytes()
        };

        let max_bound = "x".repeat(AUDIT_DETAIL_MAX_BYTES);
        assert!(validate_claim(&claim_with(&payload_with_detail(&max_bound), "message-1")).is_ok());

        let over_bound = "x".repeat(AUDIT_DETAIL_MAX_BYTES + 1);
        let error = validate_claim(&claim_with(&payload_with_detail(&over_bound), "message-1"))
            .expect_err("detail beyond the replay field bound must be rejected");
        assert_eq!(error_reason(&error), "audit_optional_field_invalid");
    }

    #[test]
    #[ignore = "requires MySQL and RabbitMQ services"]
    fn mysql_rabbit_replay_worker_integration_skeleton() {
        // The end-to-end claim -> raw publish -> confirm path is intentionally
        // exercised only when external services are provisioned.
    }
}
