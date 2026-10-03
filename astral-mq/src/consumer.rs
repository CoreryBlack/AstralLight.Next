//! 消费者基类
//!
//! 提供带 DLX 重试的消费者框架。处理流程：
//! 1. 反序列化消息
//! 2. 幂等 claim（默认 MySQL `mq_consumer_lease` 租约；旧 Redis 为 compat 路径）
//! 3. 执行业务逻辑
//! 4. ack / nack（根据结果）
//!
//! 幂等后端选择：`init_idempotency_db(pool)` 是默认要求（durable、server TTL、
//! lease generation/token fence、payload digest 完全一致重复才幂等）；
//! `init_idempotency_redis` 仅保留为 compat 路径（default-off），两者都未初始化时
//! claim 一律失败（fail-closed → nack → DLX 预算内重试）。
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
#[cfg(feature = "redis-compat")]
use redis::aio::ConnectionManager;
#[cfg(feature = "redis-compat")]
use redis::AsyncCommands;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::MySqlPool;
use tokio::sync::oneshot;

use crate::config::{HEADER_RETRY_COUNT, MAX_RETRY, QUEUE_LOGIN_EVENT};
use crate::error::MqError;
use crate::producer::MqMessage;

/// Completed-marker TTL for the compat Redis path (durable 24h marker).
#[cfg(feature = "redis-compat")]
const IDEMPOTENCY_TTL_SECONDS: i64 = 86_400;
/// Processing lease TTL; armed by the backend (server time for the DB path).
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
/// Bounded wait for any idempotency-store round trip (DB or compat Redis).
pub(crate) const IDEMPOTENCY_OPERATION_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(3);

static IDEMPOTENCY_DB_STORE: OnceLock<Arc<dyn MqConsumerLeaseStore>> = OnceLock::new();
#[cfg(feature = "redis-compat")]
static IDEMPOTENCY_REDIS: OnceLock<ConnectionManager> = OnceLock::new();

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

/// Compat-only Redis backend (default-off). New deployments and runtimes must
/// call [`init_idempotency_db`] instead; this path exists solely so existing
/// runtimes keep compiling and can opt back into the Redis claim layer
/// explicitly during a migration window.
#[cfg(feature = "redis-compat")]
pub async fn init_idempotency_redis(redis_url: &str) -> Result<(), MqError> {
    if IDEMPOTENCY_REDIS.get().is_some() {
        return Ok(());
    }
    let client = redis::Client::open(redis_url)
        .map_err(|error| MqError::Idempotent(format!("open Redis client failed: {error}")))?;
    let config = redis::aio::ConnectionManagerConfig::new()
        .set_connection_timeout(Some(std::time::Duration::from_secs(1)))
        .set_response_timeout(Some(std::time::Duration::from_millis(500)))
        .set_number_of_retries(0);
    let manager = tokio::time::timeout(
        IDEMPOTENCY_OPERATION_TIMEOUT,
        ConnectionManager::new_with_config(client, config),
    )
    .await
    .map_err(|_| MqError::Idempotent("Redis connection timed out".into()))?
    .map_err(|error| MqError::Idempotent(format!("connect to Redis failed: {error}")))?;
    IDEMPOTENCY_REDIS
        .set(manager)
        .map_err(|_| MqError::Idempotent("Redis idempotency manager already initialized".into()))
}

#[cfg(feature = "redis-compat")]
pub(crate) fn idempotency_redis() -> Result<ConnectionManager, MqError> {
    IDEMPOTENCY_REDIS
        .get()
        .cloned()
        .ok_or_else(|| MqError::Idempotent("Redis idempotency manager is not initialized".into()))
}

/// compat 路径句柄（仅 redis-compat feature 编译；feature-off 构建中本 API
/// 不存在——redis 编译层退役的显式 BREAKING 收敛点，登记于架构文档）。
#[cfg(feature = "redis-compat")]
pub fn shared_idempotency_redis() -> Result<ConnectionManager, MqError> {
    idempotency_redis()
}

pub(crate) fn message_type_for_queue(queue_name: &str) -> &'static str {
    match queue_name {
        "astral.audit.log" => "AUDIT_LOG",
        "astral.auth.session.revocation" => "AUTH_SESSION_REVOCATION",
        QUEUE_LOGIN_EVENT => "LOGIN_EVENT",
        "astral.chat.message" => "CHAT_MESSAGE",
        _ => "BUSINESS_MESSAGE",
    }
}

/// Login events from the pre-envelope producer may omit `messageId`. Keep this
/// compatibility path narrow: only a complete legacy payload with a stable
/// timestamp can be identified deterministically. Other queues stay strict.
pub(crate) fn validate_delivery_envelope_for_queue(
    data: &[u8],
    queue_name: &str,
) -> Result<Value, String> {
    let value: Value =
        serde_json::from_slice(data).map_err(|error| format!("malformed_json: {error}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "missing_envelope_object".to_owned())?;
    let message_id = object.get("messageId");
    let has_missing_message_id = message_id.is_none();
    if queue_name != QUEUE_LOGIN_EVENT || !has_missing_message_id {
        return validate_delivery_envelope(data);
    }

    let payload = object
        .get("payload")
        .filter(|payload| !payload.is_null())
        .and_then(Value::as_object);
    let has_stable_timestamp = object
        .get("timestamp")
        .or_else(|| payload.and_then(|payload| payload.get("timestamp")))
        .is_some_and(|timestamp| match timestamp {
            Value::String(value) => !value.trim().is_empty(),
            Value::Number(_) => true,
            _ => false,
        });
    if has_stable_timestamp {
        Ok(value)
    } else {
        Err("message_id_missing_login_legacy_timestamp_invalid".to_owned())
    }
}

/// Validate the envelope before any Redis claim or business handler runs.
///
/// `MqMessage` keeps a compatibility path for older numeric timestamps, but
/// the envelope itself must contain a non-empty message id and a timestamp.
/// The caller sends every error through the existing DLX path, so malformed
/// deliveries consume the same finite retry budget as handler failures.
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
        Some(Value::String(timestamp)) if !timestamp.trim().is_empty() => {}
        Some(Value::Number(_)) => {}
        Some(Value::String(_)) => return Err("timestamp_empty".to_owned()),
        Some(_) => return Err("timestamp_invalid".to_owned()),
        None => return Err("timestamp_missing".to_owned()),
    }

    Ok(value)
}

/// Decode a delivery without allowing malformed data to remain unacked.
pub(crate) fn decode_delivery<T: DeserializeOwned>(
    data: &[u8],
    queue_name: &str,
) -> Result<MqMessage<T>, String> {
    let mut value = validate_delivery_envelope_for_queue(data, queue_name)?;
    if queue_name == QUEUE_LOGIN_EVENT && value.get("messageId").and_then(Value::as_str).is_none() {
        normalize_legacy_login_payload(&mut value)?;
        let message_id = legacy_login_message_id(&value)?;
        value
            .as_object_mut()
            .expect("validated MQ envelope must be an object")
            .insert("messageId".into(), Value::String(message_id));
    }
    serde_json::from_value(value).map_err(|error| format!("payload_invalid: {error}"))
}

fn normalize_legacy_login_payload(value: &mut Value) -> Result<(), String> {
    let has_payload_object = value
        .as_object()
        .and_then(|object| object.get("payload"))
        .is_some_and(Value::is_object);
    let payload = if has_payload_object {
        value
            .as_object_mut()
            .and_then(|object| object.get_mut("payload"))
            .and_then(Value::as_object_mut)
            .ok_or_else(|| "legacy_login_payload_missing_object".to_owned())?
    } else {
        value
            .as_object_mut()
            .ok_or_else(|| "missing_envelope_object".to_owned())?
    };

    if !payload.contains_key("loginType") {
        let login_type = payload
            .get("event")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "legacy_login_type_missing".to_owned())?
            .to_owned();
        payload.insert("loginType".into(), Value::String(login_type));
    }
    if !payload.contains_key("success") {
        let success = payload
            .get("result")
            .and_then(Value::as_str)
            .map(|value| value.eq_ignore_ascii_case("SUCCESS"))
            .or_else(|| {
                payload
                    .get("event")
                    .and_then(Value::as_str)
                    .map(|value| value.ends_with("_SUCCESS"))
            })
            .ok_or_else(|| "legacy_login_success_missing".to_owned())?;
        let has_known_result = payload
            .get("result")
            .and_then(Value::as_str)
            .is_some_and(|value| {
                value.eq_ignore_ascii_case("SUCCESS") || value.eq_ignore_ascii_case("FAILURE")
            });
        let has_known_event = payload
            .get("event")
            .and_then(Value::as_str)
            .is_some_and(|value| value.ends_with("_SUCCESS") || value.ends_with("_FAILURE"));
        if !has_known_result && !has_known_event {
            return Err("legacy_login_success_unknown".to_owned());
        }
        payload.insert("success".into(), Value::Bool(success));
    }
    if !payload.contains_key("ipAddress") {
        if let Some(ip) = payload.get("ip").cloned() {
            payload.insert("ipAddress".into(), ip);
        }
    }
    Ok(())
}

pub(crate) fn legacy_login_message_id(value: &Value) -> Result<String, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "missing_envelope_object".to_owned())?;
    let payload = object
        .get("payload")
        .filter(|value| !value.is_null())
        .unwrap_or(value)
        .as_object()
        .ok_or_else(|| "legacy_login_payload_missing_object".to_owned())?;

    if let Some(message_id) = payload
        .get("messageId")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|message_id| !message_id.is_empty())
    {
        return Ok(message_id.to_owned());
    }

    let timestamp = object
        .get("timestamp")
        .or_else(|| payload.get("timestamp"))
        .and_then(|_| canonical_json_field(object, "timestamp"))
        .or_else(|| canonical_json_field(payload, "timestamp"))
        .ok_or_else(|| "legacy_login_timestamp_missing".to_owned())?;
    let user_id = required_json_field(payload, "userId", "legacy_login_user_id_missing")?;
    let login_type = required_json_field(payload, "loginType", "legacy_login_type_missing")?;
    let success = required_json_field(payload, "success", "legacy_login_success_missing")?;
    let fields = [
        ("timestamp", timestamp),
        ("userId", user_id),
        ("cardId", optional_json_field(payload, "cardId")),
        ("loginType", login_type),
        ("provider", optional_json_field(payload, "provider")),
        ("ipAddress", optional_json_field(payload, "ipAddress")),
        ("userAgent", optional_json_field(payload, "userAgent")),
        ("detail", optional_json_field(payload, "detail")),
        ("success", success),
    ];
    Ok(canonical_legacy_message_id("login", &fields))
}

fn canonical_json_field(object: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    object
        .get(key)
        .filter(|value| match value {
            Value::String(value) => !value.trim().is_empty(),
            Value::Number(_) | Value::Bool(_) => true,
            _ => false,
        })
        .map(|value| value.to_string())
}

fn required_json_field(
    object: &serde_json::Map<String, Value>,
    key: &str,
    failure: &str,
) -> Result<String, String> {
    canonical_json_field(object, key).ok_or_else(|| failure.to_owned())
}

fn optional_json_field(object: &serde_json::Map<String, Value>, key: &str) -> String {
    object
        .get(key)
        .map(ToString::to_string)
        .unwrap_or_else(|| "null".to_owned())
}

/// Build the deterministic id used by legacy consumers. Length framing keeps
/// delimiters and user-controlled values from producing ambiguous identities.
pub(crate) fn canonical_legacy_message_id(namespace: &str, fields: &[(&str, String)]) -> String {
    let canonical = fields
        .iter()
        .map(|(name, value)| format!("{}:{}:{}:{};", name.len(), name, value.len(), value))
        .collect::<String>();
    let mut hash = [
        0xcbf29ce484222325_u64,
        0x84222325cbf29ce4_u64,
        0x9e3779b185ebca87_u64,
        0xd6e8feb86659fd93_u64,
    ];
    for (index, byte) in canonical.bytes().enumerate() {
        let lane = index % hash.len();
        hash[lane] ^= u64::from(byte);
        hash[lane] = hash[lane].wrapping_mul(0x100000001b3);
    }
    let digest = hash
        .iter()
        .map(|value| format!("{value:016x}"))
        .collect::<String>();
    format!("legacy-{namespace}-v1-{digest}")
}

/// Return a trace id for malformed and terminal DLQ records without logging
/// the message body. RabbitMQ properties are preferred because they survive
/// malformed JSON; the JSON envelope is used as a compatibility fallback.
pub(crate) fn delivery_message_id(delivery: &Delivery) -> String {
    delivery_message_id_optional(delivery).unwrap_or_else(|| "<missing>".to_owned())
}

fn delivery_message_id_optional(delivery: &Delivery) -> Option<String> {
    delivery
        .properties
        .message_id()
        .as_ref()
        .map(|id| id.as_str().trim())
        .filter(|id| !id.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            serde_json::from_slice::<Value>(&delivery.data)
                .ok()
                .and_then(|value| {
                    value
                        .get("messageId")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|id| !id.is_empty())
                        .map(ToOwned::to_owned)
                })
        })
}

/// Resolve a stable terminal identity without relying on a textual missing-id sentinel.
/// Login legacy envelopes use their canonical helper; malformed/missing-id payloads use
/// the repository's source/type/raw identity derivation by passing `None` to its API.
pub(crate) fn terminal_canonical_message_id(
    delivery: &Delivery,
    queue_name: &str,
) -> Option<String> {
    delivery_message_id_optional(delivery).or_else(|| {
        if queue_name != QUEUE_LOGIN_EVENT {
            return None;
        }
        serde_json::from_slice::<Value>(&delivery.data)
            .ok()
            .and_then(|value| {
                normalize_legacy_login_for_identity(value)
                    .ok()
                    .and_then(|value| legacy_login_message_id(&value).ok())
            })
    })
}

fn normalize_legacy_login_for_identity(mut value: Value) -> Result<Value, String> {
    if value.get("messageId").is_some() {
        return Ok(value);
    }
    normalize_legacy_login_payload(&mut value)?;
    Ok(value)
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
    Claimed(String),
    Completed,
    InFlight,
}

/// Claim handle for the full lease API: carries the per-claim CAS token (and
/// monotonic generation when the durable DB backend is active) required by
/// renew/complete/release. In Redis compat mode `owner == lease_token` is the
/// processing marker value, mirroring the legacy single-string contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LeaseHandle {
    pub owner: String,
    pub lease_token: String,
    pub lease_generation: i64,
}

/// Outcome of a full lease claim (backend-neutral).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LeaseClaim {
    Claimed(LeaseHandle),
    Completed,
    InFlight { remaining_ms: i64 },
}

fn idempotency_key(message_id: &str, msg_type: &str) -> String {
    format!("mq:idempotent:{msg_type}:{message_id}")
}

#[cfg(feature = "redis-compat")]
fn processing_marker(owner: &str) -> String {
    format!("processing:{owner}")
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

fn is_idempotency_conflict(error: &MqError) -> bool {
    matches!(error, MqError::Idempotent(text) if text.starts_with(IDEMPOTENCY_CONFLICT_PREFIX))
}

/// Full claim with payload digest. Default backend is the durable DB lease
/// store; Redis is only consulted as the compat path when no DB store was
/// initialized.
pub(crate) async fn claim_message_with_digest(
    message_id: &str,
    msg_type: &str,
    payload_digest: Option<&str>,
) -> Result<LeaseClaim, MqError> {
    if let Some(store) = IDEMPOTENCY_DB_STORE.get() {
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
        return Ok(match outcome {
            MqLeaseClaimOutcome::Claimed {
                lease_token,
                lease_generation,
            } => LeaseClaim::Claimed(LeaseHandle {
                owner,
                lease_token,
                lease_generation,
            }),
            MqLeaseClaimOutcome::Completed => LeaseClaim::Completed,
            MqLeaseClaimOutcome::InFlight { remaining_ms } => LeaseClaim::InFlight { remaining_ms },
        });
    }

    // Compat Redis path (default-off): short processing lease via SET NX EX;
    // the durable completed marker is only written after handler success.
    // redis-compat feature 未编译：compat 门为真的配置已被启动期集中校验拒绝，
    // 且 durable DB store 未初始化时 claim 本就 fail-closed 失败（nack → DLX）。
    #[cfg(feature = "redis-compat")]
    {
        claim_message_with_redis(message_id, msg_type).await
    }
    #[cfg(not(feature = "redis-compat"))]
    {
        Err(MqError::Idempotent(
            "redis idempotency compat backend is not compiled (redis-compat feature off); initialize the durable DB idempotency store".into(),
        ))
    }
}

/// compat 路径（仅 redis-compat feature 编译）：Redis SET NX 处理租约 claim，
/// 语义与拆线前逐行一致。
#[cfg(feature = "redis-compat")]
async fn claim_message_with_redis(message_id: &str, msg_type: &str) -> Result<LeaseClaim, MqError> {
    let mut conn = idempotency_redis()?;

    let key = idempotency_key(message_id, msg_type);
    let owner = uuid::Uuid::new_v4().to_string();
    let marker = processing_marker(&owner);
    let result: Option<String> = tokio::time::timeout(
        IDEMPOTENCY_OPERATION_TIMEOUT,
        redis::cmd("SET")
            .arg(&key)
            .arg(&marker)
            .arg("NX")
            .arg("EX")
            .arg(PROCESSING_LEASE_SECONDS)
            .query_async(&mut conn),
    )
    .await
    .map_err(|_| MqError::Idempotent("claim message timed out".into()))?
    .map_err(|e| MqError::Idempotent(format!("claim message failed: {e}")))?;

    if result.is_some() {
        return Ok(LeaseClaim::Claimed(LeaseHandle {
            lease_token: owner.clone(),
            owner,
            lease_generation: 0,
        }));
    }

    let current: Option<String> =
        tokio::time::timeout(IDEMPOTENCY_OPERATION_TIMEOUT, conn.get(&key))
            .await
            .map_err(|_| MqError::Idempotent("read message state timed out".into()))?
            .map_err(|e| MqError::Idempotent(format!("read message state failed: {e}")))?;
    match current.as_deref() {
        Some("1") => Ok(LeaseClaim::Completed),
        // The lease may expire between SET NX and GET, or hold an unknown
        // value; both stay retryable through the bounded InFlight wait.
        _ => {
            let ttl_ms = processing_ttl(message_id, msg_type).await.unwrap_or(0);
            Ok(LeaseClaim::InFlight {
                remaining_ms: if ttl_ms > 0 { ttl_ms } else { 0 },
            })
        }
    }
}

/// Legacy claim entry point (no digest): dedup by (message_type, message_id)
/// only, preserving the exact pre-migration semantics for existing callers.
/// The returned string is the claim handle (DB: lease token; Redis: marker
/// owner) accepted back by [`complete_message`]/[`release_message`].
pub(crate) async fn claim_message(
    message_id: &str,
    msg_type: &str,
) -> Result<IdempotencyClaim, MqError> {
    Ok(
        match claim_message_with_digest(message_id, msg_type, None).await? {
            LeaseClaim::Claimed(handle) => IdempotencyClaim::Claimed(handle.lease_token),
            LeaseClaim::Completed => IdempotencyClaim::Completed,
            LeaseClaim::InFlight { .. } => IdempotencyClaim::InFlight,
        },
    )
}

/// Mark a processing lease as completed only when this caller still owns it.
/// Must be invoked strictly after the handler succeeded (or, for durable
/// handlers, be replaced by a completion inside the handler's own transaction
/// via `astral_db::complete_lease_in_tx`), so the `COMPLETED` state always
/// inherits a durable handler proof.
pub(crate) async fn complete_lease(
    message_id: &str,
    msg_type: &str,
    lease: &LeaseHandle,
) -> Result<bool, MqError> {
    if let Some(store) = IDEMPOTENCY_DB_STORE.get() {
        let input = MqLeaseComplete {
            key: MqLeaseKey {
                message_type: msg_type,
                message_id,
            },
            lease_token: &lease.lease_token,
        };
        return tokio::time::timeout(IDEMPOTENCY_OPERATION_TIMEOUT, store.complete(&input))
            .await
            .map_err(|_| MqError::Idempotent("complete message timed out".into()))?
            .map_err(map_lease_error);
    }

    #[cfg(feature = "redis-compat")]
    {
        complete_lease_with_redis(message_id, msg_type, lease).await
    }
    #[cfg(not(feature = "redis-compat"))]
    {
        Err(MqError::Idempotent(
            "redis idempotency compat backend is not compiled (redis-compat feature off); initialize the durable DB idempotency store".into(),
        ))
    }
}

/// compat 路径（仅 redis-compat feature 编译）：完成 marker 的 CAS Script。
#[cfg(feature = "redis-compat")]
async fn complete_lease_with_redis(
    message_id: &str,
    msg_type: &str,
    lease: &LeaseHandle,
) -> Result<bool, MqError> {
    let mut conn = idempotency_redis()?;
    let key = idempotency_key(message_id, msg_type);
    let marker = processing_marker(&lease.owner);
    let result: i32 = tokio::time::timeout(
        IDEMPOTENCY_OPERATION_TIMEOUT,
        redis::Script::new(
            "if redis.call('get', KEYS[1]) == ARGV[1] then redis.call('set', KEYS[1], '1', 'EX', ARGV[2]); return 1 else return 0 end",
        )
        .key(key)
        .arg(marker)
        .arg(IDEMPOTENCY_TTL_SECONDS)
        .invoke_async(&mut conn),
    )
    .await
    .map_err(|_| MqError::Idempotent("complete message timed out".into()))?
    .map_err(|e| MqError::Idempotent(format!("complete message failed: {e}")))?;
    Ok(result == 1)
}

/// Legacy completion entry point: `owner` is the claim handle string returned
/// by [`claim_message`] (DB: lease token; Redis: marker owner).
pub(crate) async fn complete_message(
    message_id: &str,
    msg_type: &str,
    owner: &str,
) -> Result<bool, MqError> {
    complete_lease(
        message_id,
        msg_type,
        &LeaseHandle {
            owner: owner.to_owned(),
            lease_token: owner.to_owned(),
            lease_generation: 0,
        },
    )
    .await
}

/// Extend an owned processing lease without allowing a stale worker to renew
/// another delivery's lease. `owner` is the claim handle string returned by
/// [`claim_message`] (DB: lease token; Redis: marker owner).
pub(crate) async fn renew_message(
    message_id: &str,
    msg_type: &str,
    owner: &str,
) -> Result<bool, MqError> {
    if let Some(store) = IDEMPOTENCY_DB_STORE.get() {
        let input = MqLeaseRenew {
            key: MqLeaseKey {
                message_type: msg_type,
                message_id,
            },
            lease_token: owner,
            lease_seconds: PROCESSING_LEASE_SECONDS,
        };
        return tokio::time::timeout(IDEMPOTENCY_OPERATION_TIMEOUT, store.renew(&input))
            .await
            .map_err(|_| MqError::Idempotent("renew message timed out".into()))?
            .map_err(map_lease_error);
    }

    #[cfg(feature = "redis-compat")]
    {
        renew_message_with_redis(message_id, msg_type, owner).await
    }
    #[cfg(not(feature = "redis-compat"))]
    {
        Err(MqError::Idempotent(
            "redis idempotency compat backend is not compiled (redis-compat feature off); initialize the durable DB idempotency store".into(),
        ))
    }
}

/// compat 路径（仅 redis-compat feature 编译）：续期租约的 expire CAS Script。
#[cfg(feature = "redis-compat")]
async fn renew_message_with_redis(
    message_id: &str,
    msg_type: &str,
    owner: &str,
) -> Result<bool, MqError> {
    let mut conn = idempotency_redis()?;
    let key = idempotency_key(message_id, msg_type);
    let marker = processing_marker(owner);
    let result: i32 = tokio::time::timeout(
        IDEMPOTENCY_OPERATION_TIMEOUT,
        redis::Script::new(
            "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('expire', KEYS[1], ARGV[2]) else return 0 end",
        )
        .key(key)
        .arg(marker)
        .arg(PROCESSING_LEASE_SECONDS)
        .invoke_async(&mut conn),
    )
    .await
    .map_err(|_| MqError::Idempotent("renew message timed out".into()))?
    .map_err(|e| MqError::Idempotent(format!("renew message failed: {e}")))?;
    Ok(result == 1)
}

/// compat 路径（仅 redis-compat feature 编译；唯一调用方为
/// [`claim_message_with_redis`]）。
#[cfg(feature = "redis-compat")]
async fn processing_ttl(message_id: &str, msg_type: &str) -> Result<i64, MqError> {
    let mut conn = idempotency_redis()?;
    let key = idempotency_key(message_id, msg_type);
    tokio::time::timeout(IDEMPOTENCY_OPERATION_TIMEOUT, conn.pttl(key))
        .await
        .map_err(|_| MqError::Idempotent("read processing lease TTL timed out".into()))?
        .map_err(|e| MqError::Idempotent(format!("read processing lease TTL failed: {e}")))
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
/// The DB path only clears a row this caller still owns, never a `COMPLETED`
/// row; the release result is best-effort and an unknown outcome is surfaced
/// to the caller, never treated as success.
pub(crate) async fn release_lease(
    message_id: &str,
    msg_type: &str,
    lease: &LeaseHandle,
) -> Result<(), MqError> {
    if let Some(store) = IDEMPOTENCY_DB_STORE.get() {
        let input = MqLeaseRelease {
            key: MqLeaseKey {
                message_type: msg_type,
                message_id,
            },
            lease_token: &lease.lease_token,
        };
        return tokio::time::timeout(IDEMPOTENCY_OPERATION_TIMEOUT, store.release(&input))
            .await
            .map_err(|_| MqError::Idempotent("release message timed out".into()))?
            .map(|_released| ())
            .map_err(map_lease_error);
    }

    #[cfg(feature = "redis-compat")]
    {
        release_lease_with_redis(message_id, msg_type, lease).await
    }
    #[cfg(not(feature = "redis-compat"))]
    {
        Err(MqError::Idempotent(
            "redis idempotency compat backend is not compiled (redis-compat feature off); initialize the durable DB idempotency store".into(),
        ))
    }
}

/// compat 路径（仅 redis-compat feature 编译）：释放租约的 del CAS Script。
#[cfg(feature = "redis-compat")]
async fn release_lease_with_redis(
    message_id: &str,
    msg_type: &str,
    lease: &LeaseHandle,
) -> Result<(), MqError> {
    let mut conn = idempotency_redis()?;
    let key = idempotency_key(message_id, msg_type);
    let marker = processing_marker(&lease.owner);
    let _: i32 = tokio::time::timeout(
        IDEMPOTENCY_OPERATION_TIMEOUT,
        redis::Script::new(
            "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end",
        )
        .key(key)
        .arg(marker)
        .invoke_async(&mut conn),
    )
    .await
    .map_err(|_| MqError::Idempotent("release message timed out".into()))?
    .map_err(|e| MqError::Idempotent(format!("release message failed: {e}")))?;
    Ok(())
}

/// Release a processing lease after handler failure. `owner` is the claim
/// handle string returned by [`claim_message`] (DB: lease token; Redis:
/// marker owner).
pub(crate) async fn release_message(
    message_id: &str,
    msg_type: &str,
    owner: &str,
) -> Result<(), MqError> {
    release_lease(
        message_id,
        msg_type,
        &LeaseHandle {
            owner: owner.to_owned(),
            lease_token: owner.to_owned(),
            lease_generation: 0,
        },
    )
    .await
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
    /// The envelope id is the canonical id used by the idempotency claim layer
    /// (durable DB lease by default, compat Redis otherwise). This
    /// constructor lets handlers that persist a durable idempotency record use
    /// that same id without changing the existing payload-only consumers.
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

        // Parse before invoking Redis or business handlers. Any malformed JSON,
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
        let failure =
            validate_delivery_envelope(br#"{"messageId":"msg-1","timestamp":"now""#).unwrap_err();
        assert!(failure.starts_with("malformed_json:"));
    }

    #[test]
    fn missing_required_envelope_fields_are_rejected() {
        assert_eq!(
            validate_delivery_envelope(br#"{"timestamp":"now"}"#).unwrap_err(),
            "message_id_missing"
        );
        assert_eq!(
            validate_delivery_envelope(br#"{"messageId":"msg-1"}"#).unwrap_err(),
            "timestamp_missing"
        );
        assert_eq!(
            validate_delivery_envelope(br#"{"messageId":"  ","timestamp":"now"}"#).unwrap_err(),
            "message_id_empty"
        );
    }

    #[test]
    fn numeric_timestamp_remains_compatible() {
        let value =
            validate_delivery_envelope(br#"{"messageId":"msg-1","timestamp":123,"payload":{}}"#)
                .unwrap();
        assert_eq!(value["messageId"], "msg-1");
        assert_eq!(value["timestamp"], 123);
    }

    #[test]
    fn login_legacy_envelope_gets_stable_message_id() {
        let data = br#"{"timestamp":"2026-08-18T10:11:12Z","payload":{"userId":7,"loginType":"PASSWORD","success":true,"ipAddress":"127.0.0.1"}}"#;
        let first = decode_delivery::<crate::producer::LoginEventPayload>(data, QUEUE_LOGIN_EVENT)
            .expect("complete legacy login event should be accepted");
        let second = decode_delivery::<crate::producer::LoginEventPayload>(data, QUEUE_LOGIN_EVENT)
            .expect("retry of same legacy login event should be accepted");
        assert_eq!(first.message_id, second.message_id);
        assert!(first.message_id.starts_with("legacy-login-v1-"));
        assert_eq!(first.payload.user_id, 7);
    }

    #[test]
    fn legacy_java_login_fields_are_normalized_deterministically() {
        let data = br#"{"timestamp":"2026-08-18T10:11:12Z","userId":7,"event":"LOGIN_SUCCESS","provider":"PASSWORD","ip":"127.0.0.1","result":"SUCCESS","detail":"ok"}"#;
        let first = decode_delivery::<crate::producer::LoginEventPayload>(data, QUEUE_LOGIN_EVENT)
            .expect("legacy Java login event should be normalized");
        let second = decode_delivery::<crate::producer::LoginEventPayload>(data, QUEUE_LOGIN_EVENT)
            .expect("same legacy Java login event should be stable on retry");
        assert_eq!(first.message_id, second.message_id);
        assert_eq!(first.payload.login_type, "LOGIN_SUCCESS");
        assert!(first.payload.success);
        assert_eq!(first.payload.ip_address.as_deref(), Some("127.0.0.1"));
    }

    #[test]
    fn login_legacy_envelope_without_stable_identity_fails_closed() {
        let data = br#"{"payload":{"userId":7,"loginType":"PASSWORD","success":true}}"#;
        assert_eq!(
            decode_delivery::<crate::producer::LoginEventPayload>(data, QUEUE_LOGIN_EVENT)
                .unwrap_err(),
            "message_id_missing_login_legacy_timestamp_invalid"
        );
    }

    #[test]
    fn other_queues_keep_strict_message_id_requirement() {
        let data = br#"{"timestamp":"2026-08-18T10:11:12Z","payload":{"userId":7}}"#;
        assert_eq!(
            validate_delivery_envelope_for_queue(data, "astral.audit.log").unwrap_err(),
            "message_id_missing"
        );
    }

    #[test]
    fn legacy_identifier_is_deterministic_and_namespaced() {
        let fields = [("userId", "7".to_owned()), ("timestamp", "t1".to_owned())];
        let first = canonical_legacy_message_id("audit", &fields);
        let second = canonical_legacy_message_id("audit", &fields);
        assert_eq!(first, second);
        assert!(first.starts_with("legacy-audit-v1-"));
        assert_ne!(first, canonical_legacy_message_id("login", &fields));
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
            "CHAT_MESSAGE"
        );
    }

    #[cfg(feature = "redis-compat")]
    #[test]
    fn processing_marker_is_distinct_from_completed_state() {
        let marker = processing_marker("owner-1");
        assert!(marker.starts_with("processing:"));
        assert_ne!(marker, "1");
    }

    #[test]
    fn idempotency_claim_states_are_explicit() {
        assert_eq!(
            IdempotencyClaim::Claimed("owner".into()),
            IdempotencyClaim::Claimed("owner".into())
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
    use astral_db::{
        MqConsumerLeaseStore, MqLeaseClaim, MqLeaseClaimOutcome, MqLeaseError, MqLeaseRelease,
        MqLeaseRenew,
    };
    use std::collections::BTreeMap;

    /// Fixed server clock (now = 0); leases with TTL 300 never expire inside
    /// these tests. Expiry/takeover semantics are covered by the lease
    /// contract suite in `astral-db`.
    #[derive(Debug, Clone)]
    struct FakeLeaseRow {
        payload_sha256: Option<String>,
        status: String,
        lease_token: Option<String>,
        lease_generation: i64,
        lease_expires_at: Option<i64>,
    }

    #[derive(Default)]
    struct InMemoryLeaseStore {
        rows: std::sync::Mutex<BTreeMap<(String, String), FakeLeaseRow>>,
    }

    const NOW: i64 = 0;

    #[async_trait::async_trait]
    impl MqConsumerLeaseStore for InMemoryLeaseStore {
        async fn claim(
            &self,
            input: &MqLeaseClaim<'_>,
        ) -> Result<MqLeaseClaimOutcome, MqLeaseError> {
            let mut rows = self.rows.lock().unwrap();
            let map_key = (input.message_type.to_owned(), input.message_id.to_owned());
            match rows.get(&map_key) {
                None => {
                    let token = format!("tok-{}", rows.len() + 1);
                    rows.insert(
                        map_key,
                        FakeLeaseRow {
                            payload_sha256: input.payload_sha256.map(ToOwned::to_owned),
                            status: "PROCESSING".into(),
                            lease_token: Some(token.clone()),
                            lease_generation: 1,
                            lease_expires_at: Some(NOW + input.lease_seconds),
                        },
                    );
                    Ok(MqLeaseClaimOutcome::Claimed {
                        lease_token: token,
                        lease_generation: 1,
                    })
                }
                Some(row) => {
                    if let (Some(existing), Some(incoming)) =
                        (row.payload_sha256.as_deref(), input.payload_sha256)
                    {
                        if !existing.eq_ignore_ascii_case(incoming) {
                            return Err(MqLeaseError::Conflict {
                                message_type: input.message_type.to_owned(),
                                message_id: input.message_id.to_owned(),
                                detail: "digest mismatch".into(),
                            });
                        }
                    }
                    if row.status == "COMPLETED" {
                        return Ok(MqLeaseClaimOutcome::Completed);
                    }
                    let alive = row
                        .lease_expires_at
                        .is_some_and(|expires_at| expires_at >= NOW);
                    if alive {
                        return Ok(MqLeaseClaimOutcome::InFlight {
                            remaining_ms: (row.lease_expires_at.unwrap_or(NOW) - NOW) * 1000,
                        });
                    }
                    let token = format!("tok-{}", rows.len() + 1);
                    let row = rows.get_mut(&map_key).expect("row exists");
                    row.lease_token = Some(token.clone());
                    row.lease_generation += 1;
                    row.lease_expires_at = Some(NOW + input.lease_seconds);
                    Ok(MqLeaseClaimOutcome::Claimed {
                        lease_token: token,
                        lease_generation: row.lease_generation,
                    })
                }
            }
        }

        async fn renew(&self, input: &MqLeaseRenew<'_>) -> Result<bool, MqLeaseError> {
            let mut rows = self.rows.lock().unwrap();
            let Some(row) = rows.get_mut(&(
                input.key.message_type.to_owned(),
                input.key.message_id.to_owned(),
            )) else {
                return Ok(false);
            };
            if row.status != "PROCESSING"
                || row.lease_token.as_deref() != Some(input.lease_token)
                || row
                    .lease_expires_at
                    .is_none_or(|expires_at| expires_at < NOW)
            {
                return Ok(false);
            }
            row.lease_expires_at = Some(NOW + input.lease_seconds);
            Ok(true)
        }

        async fn release(&self, input: &MqLeaseRelease<'_>) -> Result<bool, MqLeaseError> {
            let mut rows = self.rows.lock().unwrap();
            let Some(row) = rows.get_mut(&(
                input.key.message_type.to_owned(),
                input.key.message_id.to_owned(),
            )) else {
                return Ok(false);
            };
            if row.status != "PROCESSING" || row.lease_token.as_deref() != Some(input.lease_token) {
                return Ok(false);
            }
            row.lease_token = None;
            row.lease_expires_at = None;
            Ok(true)
        }

        async fn complete(
            &self,
            input: &astral_db::MqLeaseComplete<'_>,
        ) -> Result<bool, MqLeaseError> {
            let mut rows = self.rows.lock().unwrap();
            let Some(row) = rows.get_mut(&(
                input.key.message_type.to_owned(),
                input.key.message_id.to_owned(),
            )) else {
                return Ok(false);
            };
            if row.status != "PROCESSING"
                || row.lease_token.as_deref() != Some(input.lease_token)
                || row
                    .lease_expires_at
                    .is_none_or(|expires_at| expires_at < NOW)
            {
                return Ok(false);
            }
            row.status = "COMPLETED".into();
            row.lease_expires_at = None;
            Ok(true)
        }

        async fn remaining_lease_ms(
            &self,
            input: &MqLeaseKey<'_>,
        ) -> Result<Option<i64>, MqLeaseError> {
            let rows = self.rows.lock().unwrap();
            Ok(rows
                .get(&(input.message_type.to_owned(), input.message_id.to_owned()))
                .filter(|row| row.status == "PROCESSING")
                .and_then(|row| row.lease_expires_at)
                .filter(|expires_at| *expires_at >= NOW)
                .map(|expires_at| (expires_at - NOW) * 1000))
        }
    }

    fn install_in_memory_idempotency_store() {
        let _ = IDEMPOTENCY_DB_STORE.set(Arc::new(InMemoryLeaseStore::default()));
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
    async fn db_legacy_claim_message_roundtrip_keeps_contract() {
        install_in_memory_idempotency_store();

        // Legacy claim without digest (consumers.rs batch path contract).
        let claimed = claim_message("db-legacy-1", "LOGIN_EVENT")
            .await
            .expect("legacy claim must succeed");
        let IdempotencyClaim::Claimed(handle) = claimed else {
            panic!("legacy claim must be Claimed");
        };

        // A digest-bearing claim on the same live id stays InFlight (the
        // digest-less row simply cannot conflict yet).
        let digest = payload_digest_hex(b"legacy-body");
        let concurrent = claim_message_with_digest("db-legacy-1", "LOGIN_EVENT", Some(&digest))
            .await
            .expect("concurrent digest claim must succeed");
        assert!(matches!(concurrent, LeaseClaim::InFlight { .. }));

        let completed = complete_message("db-legacy-1", "LOGIN_EVENT", &handle)
            .await
            .expect("legacy complete must evaluate");
        assert!(completed);

        let replay = claim_message("db-legacy-1", "LOGIN_EVENT")
            .await
            .expect("legacy replay must succeed");
        assert_eq!(replay, IdempotencyClaim::Completed);
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
