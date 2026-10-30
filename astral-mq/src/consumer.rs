//! 消费者基类
//!
//! 提供带 DLX 重试的消费者框架。处理流程：
//! 1. 反序列化消息
//! 2. 幂等 claim（MySQL `mq_consumer_lease` 租约）
//! 3. 执行业务逻辑
//! 4. ack / nack（根据结果）
//!
//! 幂等要求：`init_idempotency_db(pool)` 必须在启动 consumer 前成功；lease 使用
//! server TTL、generation/token fence，只有 payload digest 完全一致的重复才幂等。
//! store 未初始化或不可用时 claim 一律失败（fail-closed → nack → DLX 预算内重试）。
//!
//! 消费失败时检查 `x-retry-count` 头：
//! - 业务处理或 envelope 解析失败：nack（requeue=false → DLX）
//! - DLQ consumer 按预算重投；达到上限后由 DLQ consumer ACK 并记录终态告警

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

use astral_db::{
    MqConsumerLeaseStore, MqLeaseClaim, MqLeaseClaimOutcome, MqLeaseComplete, MqLeaseKey,
    MqLeaseRelease, MqLeaseRenew, SqlxMqConsumerLeaseStore,
};
use futures_util::StreamExt;
use lapin::message::Delivery;
use lapin::options::{BasicAckOptions, BasicConsumeOptions, BasicNackOptions, BasicQosOptions};
use lapin::types::ShortString;
use lapin::Channel;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::MySqlPool;
use tokio::sync::oneshot;

use crate::config::{HEADER_RETRY_COUNT, MAX_RETRY, QUEUE_LOGIN_EVENT};
use crate::error::MqError;
use crate::producer::MqMessage;

/// Processing lease TTL; enforced using MySQL server time.
const PROCESSING_LEASE_SECONDS: i64 = 300;
/// Heartbeat renews at ~1/3 of the lease TTL so a single missed beat never
/// expires the lease.
const LEASE_HEARTBEAT_INTERVAL_FACTOR: u64 = 3;
/// Bounded heartbeat failure budget: after this many consecutive failed renew
/// calls the heartbeat is cancelled. The lease then expires server-side and any
/// later completion fails the token CAS — an unknown heartbeat outcome can
/// never release or confirm a claim as success.
const LEASE_HEARTBEAT_MAX_CONSECUTIVE_FAILURES: u32 = 3;
/// Upper bound for sleeping when another live lease holds the message.
const IN_FLIGHT_WAIT_CAP_MILLIS: u64 = 2_000;

pub(crate) const DEFAULT_PREFETCH: u16 = 32;
/// Bounded wait for any idempotency-store round trip (MySQL).
pub(crate) const IDEMPOTENCY_OPERATION_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(3);

static IDEMPOTENCY_DB_STORE: OnceLock<Arc<dyn MqConsumerLeaseStore>> = OnceLock::new();

/// Initialize the default durable idempotency backend (MySQL
/// `mq_consumer_lease`). Fails closed at startup when the lease table is
/// missing (migration not applied) or the pool cannot serve a smoke query.
pub async fn init_idempotency_db(pool: MySqlPool) -> Result<(), MqError> {
    if IDEMPOTENCY_DB_STORE.get().is_some() {
        return Ok(());
    }
    let store = SqlxMqConsumerLeaseStore::new(pool);
    let smoke = tokio::time::timeout(IDEMPOTENCY_OPERATION_TIMEOUT, async {
        sqlx::query("SELECT 1 FROM mq_consumer_lease LIMIT 1")
            .fetch_optional(store.pool())
            .await
    })
    .await
    .map_err(|_| MqError::Idempotent("idempotency store smoke check timed out".into()))?
    .map_err(|error| MqError::Idempotent(format!("idempotency store not ready: {error}")))?;
    let _ = smoke;
    match IDEMPOTENCY_DB_STORE.set(Arc::new(store)) {
        Ok(()) => Ok(()),
        Err(_) => {
            // Benign concurrent double-init: one store already won.
            if IDEMPOTENCY_DB_STORE.get().is_some() {
                Ok(())
            } else {
                Err(MqError::Idempotent(
                    "DB idempotency store initialization failed".into(),
                ))
            }
        }
    }
}

pub(crate) fn message_type_for_queue(queue_name: &str) -> &'static str {
    match queue_name {
        "astral.audit.log" => "AUDIT_LOG",
        "astral.auth.session.revocation" => "AUTH_SESSION_REVOCATION",
        QUEUE_LOGIN_EVENT => "LOGIN_EVENT",
        _ => "BUSINESS_MESSAGE",
    }
}

/// Validate the canonical flat producer message before a MySQL lease claim or
/// business handler runs. The caller sends every error through the existing DLX
/// path, so malformed deliveries retain the same finite retry behavior.
pub(crate) fn validate_delivery_envelope(data: &[u8]) -> Result<Value, String> {
    let value: Value =
        serde_json::from_slice(data).map_err(|error| format!("malformed_json: {error}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "missing_envelope_object".to_owned())?;

    match object.get("messageId") {
        Some(Value::String(message_id)) if !message_id.trim().is_empty() => {}
        Some(Value::String(_)) => return Err("message_id_empty".to_owned()),
        Some(_) => return Err("message_id_not_string".to_owned()),
        None => return Err("message_id_missing".to_owned()),
    }

    match object.get("timestamp") {
        Some(Value::String(timestamp)) if !timestamp.trim().is_empty() => {
            time::OffsetDateTime::parse(timestamp, &time::format_description::well_known::Rfc3339)
                .map_err(|_| "timestamp_invalid".to_owned())?;
        }
        Some(Value::String(_)) => return Err("timestamp_empty".to_owned()),
        Some(_) => return Err("timestamp_invalid".to_owned()),
        None => return Err("timestamp_missing".to_owned()),
    }

    if object.contains_key("payload") {
        return Err("nested_payload_not_canonical".to_owned());
    }

    Ok(value)
}

/// Decode a delivery without allowing malformed or legacy data to be upgraded.
pub(crate) fn decode_delivery<T: DeserializeOwned>(
    data: &[u8],
    _queue_name: &str,
) -> Result<MqMessage<T>, String> {
    let value = validate_delivery_envelope(data)?;
    serde_json::from_value(value).map_err(|error| format!("payload_invalid: {error}"))
}

/// Return an identifier for diagnostics only; business and lease identity
/// always comes from a validated canonical JSON envelope. RabbitMQ properties
/// are preferred for malformed deliveries because they survive malformed JSON.
pub(crate) fn delivery_message_id(delivery: &Delivery) -> String {
    delivery_message_id_optional(delivery).unwrap_or_else(|| "<missing>".to_owned())
}

fn canonical_message_id_from_body(body: &[u8]) -> Option<String> {
    let value = serde_json::from_slice::<Value>(body).ok()?;
    let object = value.as_object()?;
    object
        .get("messageId")
        .and_then(Value::as_str)
        .filter(|id| !id.trim().is_empty())
        .map(ToOwned::to_owned)
}

fn delivery_message_id_optional(delivery: &Delivery) -> Option<String> {
    delivery
        .properties
        .message_id()
        .as_ref()
        .map(|id| id.as_str().trim())
        .filter(|id| !id.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| canonical_message_id_from_body(&delivery.data))
}

/// Rabbit's optional message-id property is transport metadata, not a second
/// business identity. If present, it must agree exactly with the validated JSON
/// envelope id; otherwise reject the delivery before claiming its lease.
pub(crate) fn validate_delivery_message_id(
    delivery: &Delivery,
    canonical_message_id: &str,
) -> Result<(), String> {
    let transport_message_id = delivery
        .properties
        .message_id()
        .as_ref()
        .map(|id| id.as_str());
    validate_transport_message_id(transport_message_id, canonical_message_id)
}

fn validate_transport_message_id(
    transport_message_id: Option<&str>,
    canonical_message_id: &str,
) -> Result<(), String> {
    if matches!(transport_message_id, Some(transport_id) if transport_id != canonical_message_id) {
        return Err("amqp_message_id_mismatch".to_owned());
    }
    Ok(())
}

/// Resolve the canonical terminal identity without relying on a textual
/// missing-id sentinel; malformed or missing-id deliveries defer to the
/// quarantine repository's source/type/raw identity derivation.
pub(crate) fn terminal_canonical_message_id(
    delivery: &Delivery,
    _queue_name: &str,
) -> Option<String> {
    canonical_message_id_from_body(&delivery.data)
}

pub(crate) fn retry_count_from_delivery(delivery: &Delivery) -> u32 {
    delivery
        .properties
        .headers()
        .as_ref()
        .and_then(|headers| headers.inner().get(HEADER_RETRY_COUNT))
        .and_then(|value| value.as_long_long_int())
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(0)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum IdempotencyClaim {
    Claimed(LeaseHandle),
    Completed,
    InFlight,
}

/// Claim handle for the full MySQL lease API: carries the per-claim CAS token
/// and monotonic generation required by renew/complete/release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LeaseHandle {
    pub lease_token: String,
    pub lease_generation: i64,
}

/// Outcome of a full MySQL lease claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LeaseClaim {
    Claimed(LeaseHandle),
    Completed,
    InFlight { remaining_ms: i64 },
}

fn idempotency_key(message_id: &str, msg_type: &str) -> String {
    format!("mq:idempotent:{msg_type}:{message_id}")
}

/// Lowercase sha256 of the raw delivery body. DLQ republish preserves the raw
/// body, so an exact-duplicate redelivery always hashes identically while any
/// payload mutation under the same message id is a fail-closed conflict.
pub(crate) fn payload_digest_hex(body: &[u8]) -> String {
    format!("{:x}", Sha256::digest(body))
}

/// Stable machine prefix marking a deterministic (non-retryable) idempotency
/// conflict: same message id, different payload digest.
const IDEMPOTENCY_CONFLICT_PREFIX: &str = "mq_consumer_lease_conflict:";

fn map_lease_error(error: astral_db::MqLeaseError) -> MqError {
    match error {
        astral_db::MqLeaseError::Conflict {
            message_type,
            message_id,
            detail,
        } => MqError::Idempotent(format!(
            "{IDEMPOTENCY_CONFLICT_PREFIX}message_type={message_type} message_id={message_id}: {detail}"
        )),
        other => MqError::Idempotent(other.to_string()),
    }
}

pub(crate) fn is_idempotency_conflict(error: &MqError) -> bool {
    matches!(error, MqError::Idempotent(text) if text.starts_with(IDEMPOTENCY_CONFLICT_PREFIX))
}

/// Full claim with payload digest. The durable MySQL lease store is the only
/// backend; an uninitialized store fails closed.
pub(crate) async fn claim_message_with_digest(
    message_id: &str,
    msg_type: &str,
    payload_digest: Option<&str>,
) -> Result<LeaseClaim, MqError> {
    let store = IDEMPOTENCY_DB_STORE
        .get()
        .ok_or_else(|| MqError::Idempotent("DB idempotency store is not initialized".into()))?;
    let owner = uuid::Uuid::new_v4().to_string();
    let idem_key = idempotency_key(message_id, msg_type);
    let input = MqLeaseClaim {
        message_type: msg_type,
        message_id,
        idem_key: &idem_key,
        payload_sha256: payload_digest,
        owner: &owner,
        lease_seconds: PROCESSING_LEASE_SECONDS,
    };
    let outcome = tokio::time::timeout(IDEMPOTENCY_OPERATION_TIMEOUT, store.claim(&input))
        .await
        .map_err(|_| MqError::Idempotent("idempotency claim timed out".into()))?
        .map_err(map_lease_error)?;
    Ok(match outcome {
        MqLeaseClaimOutcome::Claimed {
            lease_token,
            lease_generation,
        } => LeaseClaim::Claimed(LeaseHandle {
            lease_token,
            lease_generation,
        }),
        MqLeaseClaimOutcome::Completed => LeaseClaim::Completed,
        MqLeaseClaimOutcome::InFlight { remaining_ms } => LeaseClaim::InFlight { remaining_ms },
    })
}

/// Claim entry point used by the batched audit durable handler. The raw delivery
/// digest remains attached to the shared MySQL lease; the returned lease handle
/// preserves its CAS token and generation for completion and release.
pub(crate) async fn claim_message_with_digest_for_batch(
    message_id: &str,
    msg_type: &str,
    payload_digest: &str,
) -> Result<IdempotencyClaim, MqError> {
    Ok(
        match claim_message_with_digest(message_id, msg_type, Some(payload_digest)).await? {
            LeaseClaim::Claimed(handle) => IdempotencyClaim::Claimed(handle),
            LeaseClaim::Completed => IdempotencyClaim::Completed,
            LeaseClaim::InFlight { .. } => IdempotencyClaim::InFlight,
        },
    )
}

/// Mark a processing lease as completed only when this caller still owns it.
/// Must be invoked strictly after the handler succeeded (or, for durable
/// handlers, be replaced by a completion inside the handler's own transaction
/// via `astral_db::complete_lease_in_tx`), so the `COMPLETED` state always
/// follows a durable handler proof.
pub(crate) async fn complete_lease(
    message_id: &str,
    msg_type: &str,
    lease: &LeaseHandle,
) -> Result<bool, MqError> {
    let store = IDEMPOTENCY_DB_STORE
        .get()
        .ok_or_else(|| MqError::Idempotent("DB idempotency store is not initialized".into()))?;
    let input = MqLeaseComplete {
        key: MqLeaseKey {
            message_type: msg_type,
            message_id,
        },
        lease_token: &lease.lease_token,
    };
    tokio::time::timeout(IDEMPOTENCY_OPERATION_TIMEOUT, store.complete(&input))
        .await
        .map_err(|_| MqError::Idempotent("complete message timed out".into()))?
        .map_err(map_lease_error)
}

/// Extend an owned processing lease without allowing a stale worker to renew
/// another delivery's lease. `owner` is the MySQL lease token returned by
/// [`claim_message_with_digest`].
pub(crate) async fn renew_message(
    message_id: &str,
    msg_type: &str,
    owner: &str,
) -> Result<bool, MqError> {
    let store = IDEMPOTENCY_DB_STORE
        .get()
        .ok_or_else(|| MqError::Idempotent("DB idempotency store is not initialized".into()))?;
    let input = MqLeaseRenew {
        key: MqLeaseKey {
            message_type: msg_type,
            message_id,
        },
        lease_token: owner,
        lease_seconds: PROCESSING_LEASE_SECONDS,
    };
    tokio::time::timeout(IDEMPOTENCY_OPERATION_TIMEOUT, store.renew(&input))
        .await
        .map_err(|_| MqError::Idempotent("renew message timed out".into()))?
        .map_err(map_lease_error)
}

/// Heartbeat renewal decision (pure): `true` keeps the loop alive, `false`
/// means the lease was demonstrably lost, and an error consumes the bounded
/// failure budget before the heartbeat is cancelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeartbeatDecision {
    Continue,
    LeaseLost,
    BudgetExhausted,
}

fn heartbeat_decision(
    renew_outcome: &Result<bool, MqError>,
    consecutive_failures: u32,
) -> (HeartbeatDecision, u32) {
    match renew_outcome {
        Ok(true) => (HeartbeatDecision::Continue, 0),
        Ok(false) => (HeartbeatDecision::LeaseLost, consecutive_failures),
        Err(_) => {
            let failures = consecutive_failures + 1;
            if failures >= LEASE_HEARTBEAT_MAX_CONSECUTIVE_FAILURES {
                (HeartbeatDecision::BudgetExhausted, failures)
            } else {
                (HeartbeatDecision::Continue, failures)
            }
        }
    }
}

fn start_lease_heartbeat(
    message_id: String,
    msg_type: &'static str,
    lease_token: String,
    queue_name: String,
) -> (oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    let (stop_tx, mut stop_rx) = oneshot::channel();
    let interval = std::time::Duration::from_secs(
        (PROCESSING_LEASE_SECONDS as u64 / LEASE_HEARTBEAT_INTERVAL_FACTOR).max(1),
    );
    let task = tokio::spawn(async move {
        let mut consecutive_failures: u32 = 0;
        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {
                    let outcome = renew_message(&message_id, msg_type, &lease_token).await;
                    match heartbeat_decision(&outcome, consecutive_failures) {
                        (HeartbeatDecision::Continue, failures) => {
                            consecutive_failures = failures;
                            if failures > 0 {
                                tracing::warn!(
                                    queue = %queue_name,
                                    message_id = %message_id,
                                    consecutive_failures = failures,
                                    "processing lease heartbeat failed; retrying within bounded budget"
                                );
                            }
                        }
                        (HeartbeatDecision::LeaseLost, _) => {
                            tracing::warn!(queue = %queue_name, message_id = %message_id, "processing lease was lost during heartbeat");
                            break;
                        }
                        (HeartbeatDecision::BudgetExhausted, failures) => {
                            tracing::error!(
                                queue = %queue_name,
                                message_id = %message_id,
                                consecutive_failures = failures,
                                "processing lease heartbeat budget exhausted; cancelling heartbeat (lease expires server-side, completion will fail closed)"
                            );
                            break;
                        }
                    }
                }
                _ = &mut stop_rx => break,
            }
        }
    });
    (stop_tx, task)
}

/// Release an owned processing lease after handler failure (full handle form).
/// MySQL only clears a row this caller still owns, never a `COMPLETED`
/// row; the release result is best-effort and an unknown outcome is surfaced
/// to the caller, never treated as success.
pub(crate) async fn release_lease(
    message_id: &str,
    msg_type: &str,
    lease: &LeaseHandle,
) -> Result<(), MqError> {
    let store = IDEMPOTENCY_DB_STORE
        .get()
        .ok_or_else(|| MqError::Idempotent("DB idempotency store is not initialized".into()))?;
    let input = MqLeaseRelease {
        key: MqLeaseKey {
            message_type: msg_type,
            message_id,
        },
        lease_token: &lease.lease_token,
    };
    tokio::time::timeout(IDEMPOTENCY_OPERATION_TIMEOUT, store.release(&input))
        .await
        .map_err(|_| MqError::Idempotent("release message timed out".into()))?
        .map(|_released| ())
        .map_err(map_lease_error)
}

/// 消息处理函数类型（简化：使用 async 闭包 / fn 指针）
///
/// 业务代码实现此类型处理具体消息。返回 Ok(()) → ack，返回 Err → nack。
type MessageHandlerFn<T> = Box<
    dyn for<'a> Fn(
            &'a T,
        ) -> Pin<
            Box<dyn Future<Output = Result<(), Box<dyn std::error::Error + Send>>> + Send>,
        > + Send
        + Sync,
>;

type MessageHandlerWithIdFn<T> = Box<
    dyn for<'a> Fn(
            &'a str,
            &'a T,
        ) -> Pin<
            Box<dyn Future<Output = Result<(), Box<dyn std::error::Error + Send>>> + Send>,
        > + Send
        + Sync,
>;

enum MessageHandler<T> {
    Payload(MessageHandlerFn<T>),
    WithMessageId(MessageHandlerWithIdFn<T>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionPolicy {
    RequireMarker,
    DurableHandler,
}

/// 通用消费者：反序列化 + 调用处理器 + ack/nack/DLX
pub struct Consumer<T: DeserializeOwned + Send + 'static> {
    channel: Channel,
    handler: MessageHandler<T>,
    queue_name: String,
    completion_policy: CompletionPolicy,
}

impl<T: DeserializeOwned + Send + 'static> Consumer<T> {
    /// 创建只需要 payload 的消费者。
    pub fn new<F, Fut>(channel: Channel, handler: F, queue_name: impl Into<String>) -> Self
    where
        F: Fn(&T) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), Box<dyn std::error::Error + Send>>> + Send + 'static,
    {
        Self {
            channel,
            handler: MessageHandler::Payload(Box::new(move |payload| Box::pin(handler(payload)))),
            queue_name: queue_name.into(),
            completion_policy: CompletionPolicy::RequireMarker,
        }
    }

    /// 创建可以同时读取 MQ envelope messageId 的消费者。
    ///
    /// The envelope id is the canonical id used by the durable MySQL lease
    /// claim layer. This constructor lets handlers that persist a durable
    /// idempotency record use that same id without changing payload-only consumers.
    pub fn new_with_message_id<F, Fut>(
        channel: Channel,
        handler: F,
        queue_name: impl Into<String>,
    ) -> Self
    where
        F: Fn(&str, &T) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), Box<dyn std::error::Error + Send>>> + Send + 'static,
    {
        Self {
            channel,
            handler: MessageHandler::WithMessageId(Box::new(move |message_id, payload| {
                Box::pin(handler(message_id, payload))
            })),
            queue_name: queue_name.into(),
            completion_policy: CompletionPolicy::RequireMarker,
        }
    }

    /// Mark this consumer's handler as durable and idempotent. If the business
    /// side effect succeeds but the idempotency completion lease cannot be
    /// confirmed (regardless of backend), the delivery is ACKed because the
    /// handler owns the durable deduplication.
    pub fn with_completion_policy(mut self, policy: CompletionPolicy) -> Self {
        self.completion_policy = policy;
        self
    }

    /// Start consuming messages and report broker registration before processing.
    pub async fn start(&self) -> Result<(), MqError> {
        self.start_with_readiness(None).await
    }

    /// Start consuming messages and resolve `ready` immediately after RabbitMQ
    /// accepts the consumer registration. Registration failures are reported to
    /// the caller instead of being hidden inside a detached task.
    pub async fn start_with_readiness(
        &self,
        ready: Option<oneshot::Sender<Result<(), String>>>,
    ) -> Result<(), MqError> {
        if let Err(error) = self
            .channel
            .basic_qos(DEFAULT_PREFETCH, BasicQosOptions { global: false })
            .await
        {
            if let Some(ready) = ready {
                let _ = ready.send(Err(error.to_string()));
            }
            return Err(error.into());
        }
        let mut consumer = match self
            .channel
            .basic_consume(
                ShortString::from(self.queue_name.as_str()),
                ShortString::from(format!("consumer_{}", self.queue_name)),
                BasicConsumeOptions::default(),
                lapin::types::FieldTable::default(),
            )
            .await
        {
            Ok(consumer) => consumer,
            Err(error) => {
                if let Some(ready) = ready {
                    let _ = ready.send(Err(error.to_string()));
                }
                return Err(error.into());
            }
        };
        if let Some(ready) = ready {
            let _ = ready.send(Ok(()));
        }

        tracing::info!(queue = %self.queue_name, "consumer started");

        while let Some(delivery) = consumer.next().await {
            let delivery = delivery.map_err(|e| MqError::Consume(e.to_string()))?;
            if let Err(e) = self.process_delivery(&delivery).await {
                tracing::error!(queue = %self.queue_name, error = %e, "delivery settlement failed");
                return Err(e);
            }
        }

        Ok(())
    }

    async fn process_delivery(&self, delivery: &Delivery) -> Result<(), MqError> {
        let retry_count = self.retry_count(delivery);

        // Parse before any claim or business handler. Any malformed JSON,
        // missing envelope field, or invalid payload gets a terminal broker
        // disposition (nack/requeue=false) and therefore cannot stay unacked.
        let msg = match decode_delivery::<T>(&delivery.data, &self.queue_name) {
            Ok(msg) => msg,
            Err(failure_reason) => {
                let message_id = delivery_message_id(delivery);
                tracing::error!(
                    queue = %self.queue_name,
                    message_id = %message_id,
                    retry = retry_count,
                    failure_reason = %failure_reason,
                    "malformed delivery sent to DLX"
                );
                return self.dead_letter(delivery).await;
            }
        };
        if let Err(failure_reason) = validate_delivery_message_id(delivery, &msg.message_id) {
            tracing::error!(
                queue = %self.queue_name,
                message_id = %msg.message_id,
                retry = retry_count,
                failure_reason = %failure_reason,
                "delivery transport metadata conflicts with canonical envelope; sending to DLX"
            );
            return self.dead_letter(delivery).await;
        }

        if retry_count >= MAX_RETRY {
            tracing::warn!(
                queue = %self.queue_name,
                message_id = %msg.message_id,
                retry = retry_count,
                failure_reason = "max_retries_exceeded",
                "max retries exceeded; delivery sent to DLX"
            );
            return self.dead_letter(delivery).await;
        }

        let message_type = message_type_for_queue(&self.queue_name);
        // Digest over the raw body: exact-duplicate redeliveries hash
        // identically (DLQ republish preserves the raw body); any payload
        // mutation under the same message id is a fail-closed conflict.
        let payload_digest = payload_digest_hex(&delivery.data);
        let claim =
            match claim_message_with_digest(&msg.message_id, message_type, Some(&payload_digest))
                .await
            {
                Ok(claim) => claim,
                Err(error) if is_idempotency_conflict(&error) => {
                    // Deterministic producer-contract violation: same message id,
                    // different payload. Never retryable — go straight to the
                    // terminal DLQ warning instead of burning the retry budget.
                    tracing::error!(
                        queue = %self.queue_name,
                        message_id = %msg.message_id,
                        error = %error,
                        "payload digest conflict for an existing message id; fail-closed to DLX"
                    );
                    return self.dead_letter(delivery).await;
                }
                Err(error) => {
                    tracing::error!(
                        queue = %self.queue_name,
                        message_id = %msg.message_id,
                        error = %error,
                        "idempotency claim unavailable, retrying message"
                    );
                    return self.nack(delivery).await;
                }
            };

        match claim {
            LeaseClaim::Completed => {
                tracing::debug!(
                    queue = %self.queue_name,
                    message_id = %msg.message_id,
                    "message already completed, acking"
                );
                return self.ack(delivery).await;
            }
            LeaseClaim::InFlight { remaining_ms } => {
                tracing::debug!(
                    queue = %self.queue_name,
                    message_id = %msg.message_id,
                    remaining_ms,
                    "message processing lease is active, waiting before requeue"
                );
                tokio::time::sleep(std::time::Duration::from_millis(
                    remaining_ms.clamp(0, IN_FLIGHT_WAIT_CAP_MILLIS as i64) as u64,
                ))
                .await;
                self.requeue(delivery).await
            }
            LeaseClaim::Claimed(lease) => {
                let (heartbeat_stop, heartbeat) = start_lease_heartbeat(
                    msg.message_id.clone(),
                    message_type,
                    lease.lease_token.clone(),
                    self.queue_name.clone(),
                );
                let result = match &self.handler {
                    MessageHandler::Payload(handler) => handler(&msg.payload).await,
                    MessageHandler::WithMessageId(handler) => {
                        handler(&msg.message_id, &msg.payload).await
                    }
                };
                let _ = heartbeat_stop.send(());
                let _ = heartbeat.await;
                match result {
                    Ok(_) => match complete_lease(&msg.message_id, message_type, &lease).await {
                        Ok(true) => self.ack(delivery).await,
                        Ok(false) | Err(_)
                            if self.completion_policy == CompletionPolicy::DurableHandler =>
                        {
                            tracing::error!(
                                queue = %self.queue_name,
                                message_id = %msg.message_id,
                                "durable handler succeeded but completion lease was not confirmed; the handler owns the durable deduplication proof"
                            );
                            self.ack(delivery).await
                        }
                        Ok(false) => self.nack(delivery).await,
                        Err(error) => {
                            tracing::error!(
                                queue = %self.queue_name,
                                message_id = %msg.message_id,
                                error = %error,
                                "message completion marker failed; sending delivery to DLX (redelivery reconciles against the durable lease row)"
                            );
                            self.nack(delivery).await
                        }
                    },
                    Err(e) => {
                        if let Err(release_error) =
                            release_lease(&msg.message_id, message_type, &lease).await
                        {
                            tracing::error!(
                                queue = %self.queue_name,
                                message_id = %msg.message_id,
                                error = %release_error,
                                "failed to release message processing lease"
                            );
                        }
                        tracing::warn!(
                            queue = %self.queue_name,
                            message_id = %msg.message_id,
                            retry = retry_count,
                            error = %e,
                            "nacking for DLX retry"
                        );
                        self.nack(delivery).await
                    }
                }
            }
        }
    }

    fn retry_count(&self, delivery: &Delivery) -> u32 {
        retry_count_from_delivery(delivery)
    }

    async fn ack(&self, delivery: &Delivery) -> Result<(), MqError> {
        self.channel
            .basic_ack(delivery.delivery_tag, BasicAckOptions::default())
            .await?;
        Ok(())
    }

    async fn requeue(&self, delivery: &Delivery) -> Result<(), MqError> {
        self.channel
            .basic_nack(
                delivery.delivery_tag,
                BasicNackOptions {
                    multiple: false,
                    requeue: true,
                },
            )
            .await?;
        Ok(())
    }

    async fn dead_letter(&self, delivery: &Delivery) -> Result<(), MqError> {
        self.channel
            .basic_nack(
                delivery.delivery_tag,
                BasicNackOptions {
                    multiple: false,
                    requeue: false,
                },
            )
            .await?;
        Ok(())
    }

    async fn nack(&self, delivery: &Delivery) -> Result<(), MqError> {
        // 对齐 Java 消费失败语义：不手动 republish 原业务队列（避免热循环绕过
        // 队列声明的 x-dead-letter-exchange + x-message-ttl 拓扑），
        // 直接 nack(requeue=false) 让消息经 astral.dlx 进入死信队列，
        // 由 DLQ 消费者按 x-retry-count 预算重投或终态告警。
        self.channel
            .basic_nack(
                delivery.delivery_tag,
                BasicNackOptions {
                    multiple: false,
                    requeue: false,
                },
            )
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_json_has_explicit_failure_reason() {
        let failure = validate_delivery_envelope(
            br#"{"messageId":"msg-1","timestamp":"2026-10-28T00:00:00Z""#,
        )
        .unwrap_err();
        assert!(failure.starts_with("malformed_json:"));
    }

    #[test]
    fn transport_message_id_must_match_canonical_envelope_id() {
        assert_eq!(
            validate_transport_message_id(Some("message-1"), "message-1"),
            Ok(())
        );
        assert_eq!(validate_transport_message_id(None, "message-1"), Ok(()));
        assert_eq!(
            validate_transport_message_id(Some("other-message"), "message-1"),
            Err("amqp_message_id_mismatch".to_owned())
        );
    }

    #[test]
    fn terminal_canonical_identity_comes_only_from_json_envelope() {
        let canonical = br#"{"messageId":"body-id","timestamp":"2026-10-28T00:00:00Z"}"#;
        assert_eq!(
            canonical_message_id_from_body(canonical).as_deref(),
            Some("body-id")
        );
        assert_eq!(
            canonical_message_id_from_body(br#"{"message_id":"legacy-id"}"#),
            None
        );
    }

    #[test]
    fn missing_required_envelope_fields_are_rejected() {
        assert_eq!(
            validate_delivery_envelope(br#"{"timestamp":"2026-10-28T00:00:00Z"}"#).unwrap_err(),
            "message_id_missing"
        );
        assert_eq!(
            validate_delivery_envelope(br#"{"messageId":"msg-1"}"#).unwrap_err(),
            "timestamp_missing"
        );
        assert_eq!(
            validate_delivery_envelope(br#"{"messageId":"  ","timestamp":"2026-10-28T00:00:00Z"}"#)
                .unwrap_err(),
            "message_id_empty"
        );
        assert_eq!(
            validate_delivery_envelope(br#"{"messageId":17,"timestamp":"2026-10-28T00:00:00Z"}"#)
                .unwrap_err(),
            "message_id_not_string"
        );
    }

    #[test]
    fn numeric_and_invalid_timestamps_are_rejected() {
        assert_eq!(
            validate_delivery_envelope(br#"{"messageId":"msg-1","timestamp":1798156800}"#)
                .unwrap_err(),
            "timestamp_invalid"
        );
        assert_eq!(
            validate_delivery_envelope(br#"{"messageId":"msg-1","timestamp":"not-a-time"}"#)
                .unwrap_err(),
            "timestamp_invalid"
        );
        assert!(decode_delivery::<serde_json::Value>(
            br#"{"messageId":"msg-1","timestamp":"2026-10-28T00:00:00Z","payload":{"userId":7}}"#,
            QUEUE_LOGIN_EVENT
        )
        .unwrap_err()
        .contains("nested_payload_not_canonical"));
    }

    #[test]
    fn canonical_login_envelope_decodes_without_payload_legacy_normalization() {
        let canonical = br#"{"messageId":"login-1","timestamp":"2026-08-18T10:11:12Z","userId":7,"cardId":null,"loginType":"PASSWORD","ipAddress":"127.0.0.1","userAgent":null,"success":true}"#;
        let decoded =
            decode_delivery::<crate::producer::LoginEventPayload>(canonical, QUEUE_LOGIN_EVENT)
                .expect("canonical login event should decode");
        assert_eq!(decoded.message_id, "login-1");
        assert_eq!(decoded.payload.user_id, 7);

        let nested = br#"{"messageId":"login-2","timestamp":"2026-08-18T10:11:12Z","payload":{"userId":7,"loginType":"PASSWORD","success":true}}"#;
        assert!(
            decode_delivery::<crate::producer::LoginEventPayload>(nested, QUEUE_LOGIN_EVENT)
                .is_err()
        );
        let missing_id = br#"{"timestamp":"2026-08-18T10:11:12Z","userId":7,"loginType":"PASSWORD","success":true}"#;
        assert_eq!(
            validate_delivery_envelope(missing_id).unwrap_err(),
            "message_id_missing"
        );
    }

    #[test]
    fn idempotency_key_matches_java_contract() {
        assert_eq!(
            idempotency_key("message-1", "PERMISSION_REFRESH"),
            "mq:idempotent:PERMISSION_REFRESH:message-1"
        );
    }
    #[test]
    fn message_type_matches_java_contract() {
        // 旧 `astral.permission.refresh` → PERMISSION_REFRESH 映射已随
        // permission.refresh 冗余广播退役（队列已从配置移除）。
        assert_eq!(message_type_for_queue("astral.audit.log"), "AUDIT_LOG");
        assert_eq!(message_type_for_queue(QUEUE_LOGIN_EVENT), "LOGIN_EVENT");
        assert_ne!(
            message_type_for_queue("astral.audit.log"),
            message_type_for_queue(QUEUE_LOGIN_EVENT)
        );
        assert_eq!(
            message_type_for_queue("astral.auth.session.revocation"),
            "AUTH_SESSION_REVOCATION"
        );
        assert_eq!(
            message_type_for_queue("astral.chat.message"),
            "BUSINESS_MESSAGE"
        );
    }

    #[test]
    fn idempotency_claim_states_are_explicit() {
        let lease = LeaseHandle {
            lease_token: "token".into(),
            lease_generation: 3,
        };
        assert_eq!(
            IdempotencyClaim::Claimed(lease.clone()),
            IdempotencyClaim::Claimed(lease)
        );
        assert_ne!(IdempotencyClaim::Completed, IdempotencyClaim::InFlight);
    }

    #[test]
    fn payload_digest_is_deterministic_sha256_hex() {
        let first = payload_digest_hex(br#"{"messageId":"m","payload":{}}"#);
        let second = payload_digest_hex(br#"{"messageId":"m","payload":{}}"#);
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(first, first.to_lowercase());
        assert_ne!(
            first,
            payload_digest_hex(br#"{"messageId":"m","payload":{"x":1}}"#)
        );
    }

    #[test]
    fn idempotency_conflict_errors_are_stably_marked() {
        let conflict = map_lease_error(astral_db::MqLeaseError::Conflict {
            message_type: "AUDIT_LOG".into(),
            message_id: "m-1".into(),
            detail: "digest mismatch".into(),
        });
        assert!(is_idempotency_conflict(&conflict));
        assert!(conflict
            .to_string()
            .contains("mq_consumer_lease_conflict:message_type=AUDIT_LOG message_id=m-1"));

        let transient = MqError::Idempotent("database unavailable".into());
        assert!(!is_idempotency_conflict(&transient));
    }

    #[test]
    fn heartbeat_decision_bounds_failures_and_cancels_on_loss() {
        let ok: Result<bool, MqError> = Ok(true);
        let lost: Result<bool, MqError> = Ok(false);
        let failed: Result<bool, MqError> = Err(MqError::Idempotent("db down".into()));

        assert_eq!(heartbeat_decision(&ok, 2), (HeartbeatDecision::Continue, 0));
        assert_eq!(
            heartbeat_decision(&lost, 1),
            (HeartbeatDecision::LeaseLost, 1)
        );
        assert_eq!(
            heartbeat_decision(&failed, 0),
            (HeartbeatDecision::Continue, 1)
        );
        assert_eq!(
            heartbeat_decision(&failed, 1),
            (HeartbeatDecision::Continue, 2)
        );
        assert_eq!(
            heartbeat_decision(&failed, 2),
            (HeartbeatDecision::BudgetExhausted, 3)
        );
    }
}

// ===== durable DB lease backend (default) — pure tests on an in-memory store =====

#[cfg(test)]
mod db_idempotency_tests {
    use super::*;

    /// Fixed server clock (now = 0); leases with TTL 300 never expire inside
    /// these tests. Expiry/takeover semantics are covered by the lease
    /// contract suite in `astral-db`.
    fn install_in_memory_idempotency_store() {
        // The shared contract store from astral-db (test-support): the exact
        // implementation its lease contract suite pins, so the consumer
        // orchestration below runs on the same semantics instead of a local
        // re-implementation that can drift.
        let store = astral_db::testing::InMemoryMqConsumerLeaseStore::new(Arc::new(
            astral_db::testing::FakeClock::default(),
        ));
        let _ = IDEMPOTENCY_DB_STORE.set(Arc::new(store));
    }

    #[tokio::test]
    async fn db_claim_lifecycle_is_idempotent_for_exact_duplicates_only() {
        install_in_memory_idempotency_store();
        let digest_a = payload_digest_hex(b"body-a");
        let digest_b = payload_digest_hex(b"body-b");

        let first = claim_message_with_digest("db-life-1", "AUDIT_LOG", Some(&digest_a))
            .await
            .expect("first claim must succeed");
        let LeaseClaim::Claimed(lease) = first else {
            panic!("first claim must be Claimed, got {first:?}");
        };
        assert_eq!(lease.lease_generation, 1);

        // Live foreign lease → bounded InFlight wait, never a second claim.
        let second = claim_message_with_digest("db-life-1", "AUDIT_LOG", Some(&digest_a))
            .await
            .expect("concurrent claim must succeed");
        assert!(matches!(second, LeaseClaim::InFlight { remaining_ms } if remaining_ms > 0));

        // Handler success → completion inherits the durable proof via CAS.
        let completed = complete_lease("db-life-1", "AUDIT_LOG", &lease)
            .await
            .expect("complete must evaluate");
        assert!(completed);

        // Exact duplicate replay → Completed (idempotent ack).
        let replay = claim_message_with_digest("db-life-1", "AUDIT_LOG", Some(&digest_a))
            .await
            .expect("replay claim must succeed");
        assert_eq!(replay, LeaseClaim::Completed);

        // Same id, different payload → fail-closed conflict (terminal DLX).
        let conflict = claim_message_with_digest("db-life-1", "AUDIT_LOG", Some(&digest_b))
            .await
            .expect_err("digest conflict must fail closed");
        assert!(is_idempotency_conflict(&conflict), "got {conflict:?}");
    }

    #[tokio::test]
    async fn db_release_after_handler_failure_allows_reclaim_with_new_token() {
        install_in_memory_idempotency_store();
        let digest = payload_digest_hex(b"body-release");

        let claimed = claim_message_with_digest("db-release-1", "LOGIN_EVENT", Some(&digest))
            .await
            .expect("claim must succeed");
        let LeaseClaim::Claimed(lease) = claimed else {
            panic!("claim must be Claimed");
        };

        release_lease("db-release-1", "LOGIN_EVENT", &lease)
            .await
            .expect("release must succeed");

        let reclaimed = claim_message_with_digest("db-release-1", "LOGIN_EVENT", Some(&digest))
            .await
            .expect("re-claim after release must succeed");
        let LeaseClaim::Claimed(next) = reclaimed else {
            panic!("re-claim must be Claimed, got {reclaimed:?}");
        };
        assert_ne!(next.lease_token, lease.lease_token);
        assert_eq!(next.lease_generation, lease.lease_generation + 1);

        // The stale worker can no longer complete the fenced lease.
        let stale_complete = complete_lease("db-release-1", "LOGIN_EVENT", &lease)
            .await
            .expect("stale complete must evaluate");
        assert!(!stale_complete);
    }

    #[tokio::test]
    async fn db_batch_claim_preserves_raw_digest_and_fencing() {
        install_in_memory_idempotency_store();

        let digest = payload_digest_hex(b"batch-body");
        let claimed = claim_message_with_digest_for_batch("batch-message-1", "AUDIT_LOG", &digest)
            .await
            .expect("batch claim must succeed");
        let IdempotencyClaim::Claimed(handle) = claimed else {
            panic!("batch claim must be Claimed");
        };

        let exact_duplicate =
            claim_message_with_digest_for_batch("batch-message-1", "AUDIT_LOG", &digest)
                .await
                .expect("exact duplicate claim must succeed");
        assert_eq!(exact_duplicate, IdempotencyClaim::InFlight);

        let different_digest = payload_digest_hex(b"mutated-body");
        let conflict =
            claim_message_with_digest_for_batch("batch-message-1", "AUDIT_LOG", &different_digest)
                .await
                .expect_err("same message id with a different payload must conflict");
        assert!(is_idempotency_conflict(&conflict));

        assert!(complete_lease("batch-message-1", "AUDIT_LOG", &handle)
            .await
            .expect("completion must evaluate"));
        assert_eq!(
            claim_message_with_digest_for_batch("batch-message-1", "AUDIT_LOG", &digest)
                .await
                .expect("exact replay must succeed"),
            IdempotencyClaim::Completed
        );
    }

    #[tokio::test]
    async fn db_lease_key_matches_public_idem_contract() {
        install_in_memory_idempotency_store();
        let digest = payload_digest_hex(b"idem-key-body");
        let claimed = claim_message_with_digest("db-key-1", "CHAT_MESSAGE", Some(&digest))
            .await
            .expect("claim must succeed");
        let LeaseClaim::Claimed(lease) = claimed else {
            panic!("claim must be Claimed");
        };
        // The public IDEM key surface is unchanged; the store keyed the row by
        // (message_type, message_id) and the idem_key was accepted as-is.
        assert_eq!(
            idempotency_key("db-key-1", "CHAT_MESSAGE"),
            "mq:idempotent:CHAT_MESSAGE:db-key-1"
        );
        assert!(complete_lease("db-key-1", "CHAT_MESSAGE", &lease)
            .await
            .expect("complete must evaluate"));
    }
}
