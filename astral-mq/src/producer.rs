//! 消息生产者
//!
//! 通用消息发送器 + 类型化 DTO，每消息自动生成 `messageId`（用于幂等去重），
//! 序列化为 JSON 后发送到指定队列。

use lapin::message::BasicReturnMessage;
use lapin::options::{BasicPublishOptions, ConfirmSelectOptions};
use lapin::types::{AMQPValue, FieldTable, ShortString};
use lapin::{BasicProperties, Channel, Confirmation};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;
use uuid::Uuid;

use crate::config::{
    EXCHANGE_DIRECT, HEADER_DEATH, HEADER_DLQ_REPUBLISH_COUNT, HEADER_RETRY_COUNT,
    MAX_RAW_REPLAY_PAYLOAD_BYTES, QUEUE_AUDIT_LOG, QUEUE_LOGIN_EVENT,
};

use crate::error::MqError;

/// The only source-to-destination mappings accepted by raw replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawReplayRoute {
    /// TrustGraph audit records.
    TrustGraphAudit,
    /// Identity login records.
    IdentityLogin,
}

impl RawReplayRoute {
    fn resolve(
        owner: &str,
        source_queue: &str,
        source_exchange: &str,
        source_routing_key: &str,
    ) -> Result<Self, RawReplayError> {
        match (owner, source_queue, source_exchange, source_routing_key) {
            ("trustgraph", QUEUE_AUDIT_LOG, EXCHANGE_DIRECT, "audit.log") => {
                Ok(Self::TrustGraphAudit)
            }
            ("identity", QUEUE_LOGIN_EVENT, EXCHANGE_DIRECT, "login.event") => {
                Ok(Self::IdentityLogin)
            }
            _ => Err(RawReplayError::RouteNotAllowed {
                owner: owner.to_owned(),
                source_queue: source_queue.to_owned(),
                source_exchange: source_exchange.to_owned(),
                source_routing_key: source_routing_key.to_owned(),
            }),
        }
    }

    fn destination(self) -> (&'static str, &'static str) {
        match self {
            Self::TrustGraphAudit => (EXCHANGE_DIRECT, "audit.log"),
            Self::IdentityLogin => (EXCHANGE_DIRECT, "login.event"),
        }
    }
}

/// Typed input for the internal raw replay publisher. The route is checked
/// against [`RawReplayRoute`] before any broker call is made.
#[derive(Debug, Clone)]
pub struct RawReplayRequest {
    pub owner: String,
    pub source_queue: String,
    pub source_exchange: String,
    pub source_routing_key: String,
    pub payload: Vec<u8>,
    pub properties: BasicProperties,
    pub message_id: String,
}

impl RawReplayRequest {
    #[must_use]
    pub fn new(
        owner: impl Into<String>,
        source_queue: impl Into<String>,
        source_exchange: impl Into<String>,
        source_routing_key: impl Into<String>,
        payload: Vec<u8>,
        properties: BasicProperties,
        message_id: impl Into<String>,
    ) -> Self {
        Self {
            owner: owner.into(),
            source_queue: source_queue.into(),
            source_exchange: source_exchange.into(),
            source_routing_key: source_routing_key.into(),
            payload,
            properties,
            message_id: message_id.into(),
        }
    }
}

/// Structured error for a raw replay. Returned payloads are summarized by
/// metadata only; no raw body, headers, or returned properties are exposed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RawReplayError {
    #[error("raw replay route is not allowed: owner={owner}, queue={source_queue}, exchange={source_exchange}, routing_key={source_routing_key}")]
    RouteNotAllowed {
        owner: String,
        source_queue: String,
        source_exchange: String,
        source_routing_key: String,
    },
    #[error("raw replay message id is empty")]
    EmptyMessageId,
    #[error("raw replay payload exceeds {limit} bytes: {actual}")]
    PayloadTooLarge { limit: usize, actual: usize },
    #[error("raw replay publish failed: code={code}, text={text}")]
    Publish {
        code: &'static str,
        text: String,
        returned: Option<Box<ReturnedPayloadSummary>>,
    },
    #[error("raw replay message id exceeds AMQP short-string limit: {actual} bytes")]
    MessageIdTooLong { actual: usize },
}

/// Non-sensitive metadata from an unroutable returned message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnedPayloadSummary {
    pub reply_code: u16,
    pub reply_text: String,
    pub payload_bytes: usize,
    pub payload_sha256: String,
    pub exchange: String,
    pub routing_key: String,
}

impl fmt::Display for ReturnedPayloadSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "reply_code={}, reply_text={}, payload_bytes={}, payload_sha256={}, exchange={}, routing_key={}",
            self.reply_code,
            self.reply_text,
            self.payload_bytes,
            self.payload_sha256,
            self.exchange,
            self.routing_key
        )
    }
}

fn sanitize_replay_properties(properties: &BasicProperties, message_id: &str) -> BasicProperties {
    let headers = properties.headers().as_ref().map(|original| {
        let mut sanitized = FieldTable::default();
        for (key, value) in original {
            if key.as_str() != HEADER_DEATH && key.as_str() != HEADER_DLQ_REPUBLISH_COUNT {
                sanitized.insert(key.clone(), value.clone());
            }
        }
        sanitized.insert(
            ShortString::from(HEADER_RETRY_COUNT),
            AMQPValue::LongLongInt(0),
        );
        sanitized
    });

    let properties = properties
        .clone()
        .with_message_id(ShortString::from(message_id));
    match headers {
        Some(headers) => properties.with_headers(headers),
        None => properties.with_headers({
            let mut headers = FieldTable::default();
            headers.insert(
                ShortString::from(HEADER_RETRY_COUNT),
                AMQPValue::LongLongInt(0),
            );
            headers
        }),
    }
}

fn confirmation_error(code: &'static str, returned: BasicReturnMessage) -> RawReplayError {
    let mut hasher = Sha256::new();
    hasher.update(&returned.data);
    let payload_sha256 = format!("{:x}", hasher.finalize());
    RawReplayError::Publish {
        code,
        text: returned.reply_text.to_string(),
        returned: Some(Box::new(ReturnedPayloadSummary {
            reply_code: returned.reply_code,
            reply_text: returned.reply_text.to_string(),
            payload_bytes: returned.data.len(),
            payload_sha256,
            exchange: returned.exchange.to_string(),
            routing_key: returned.routing_key.to_string(),
        })),
    }
}

// ===== 类型化 DTO =====

/// Java `LocalDateTime` 兼容的消息时间戳。
pub fn now_timestamp() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// 审计日志消息
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditLogPayload {
    pub message_id: Option<String>,
    pub user_id: Option<i64>,
    pub card_id: Option<i64>,
    pub action: String,
    pub resource: String,
    pub decision: String,
    pub reason: Option<String>,
    pub event_type: String,
    pub source_ip: Option<String>,
    pub request_id: Option<String>,
    pub domain_id: Option<i64>,
    pub tenant_id: Option<i64>,
    /// producer 提供的有界审计明细（例如 ORG_SCOPE ALLOW 的结构化 JSON
    /// provenance detail）。`serde(default)` 保证旧 wire 消息（无 `detail` 键）
    /// 仍可反序列化；`skip_serializing_if` 保证未携带 detail 的新消息与旧格式
    /// 字节等价。consumer 侧仅在 producer 提供非空白 detail 时落库该值，
    /// 否则回退既有 messageId 关联文本。旧 consumer 对新消息的未知键按 serde
    /// 默认忽略，不破坏向后兼容。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// 会话撤销命令消息（对齐 Java `AuthSessionRevocationCommandService`）
///
/// 由 TrustGraph GlobalAdmin 生命周期等跨服务撤销场景发布到
/// `astral.auth.session.revocation`，Identity consumer 幂等消费后执行
/// `revokeAllForUser`（DB 撤销 + session outbox + Redis 投影删除）。
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthSessionRevocationPayload {
    pub message_id: Option<String>,
    /// Stable command id used by the consumer's durable outbox idempotency key.
    #[serde(default)]
    pub operation_id: Option<String>,
    pub user_id: i64,
    pub reason: String,
    pub timestamp: String,
}

/// 登录事件消息
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginEventPayload {
    pub message_id: Option<String>,
    pub user_id: i64,
    pub card_id: Option<i64>,
    pub login_type: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub success: bool,
}

/// 聊天消息通知
///
/// `messageId` 属于 `MqMessage` envelope，由 producer 生成并同时写入 Rabbit
/// properties，不能在业务 payload 中重复声明。`id` 是 chat handler 的消息
/// 数据库主键；字段通过 `rename_all = "camelCase"` 生成统一 wire 名称。
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatMessagePayload {
    pub id: i64,
    pub conversation_id: i64,
    pub sender_id: i64,
    pub content: String,
    pub message_type: String,
}

/// 学习进度更新
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LearningProgressPayload {
    pub user_id: i64,
    pub subject_id: i64,
    pub progress: f64,
}

/// 学科删除事件
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubjectDeletePayload {
    pub subject_id: i64,
    pub subject_ids: Option<Vec<i64>>,
    pub operator_id: i64,
    pub cascade_delete: bool,
    pub domain_id: Option<i64>,
    pub tenant_id: Option<i64>,
    pub subject_name: Option<String>,
}

// ===== 通用消息包装 =====

/// 通用消息包装。新消息把业务字段展平到根对象，兼容 Java DTO；读取旧消息时
/// 仍接受历史 `payload` 嵌套结构。
#[derive(Debug, Clone)]
pub struct MqMessage<T> {
    pub message_id: String,
    pub timestamp: String,
    pub payload: T,
}

impl<T: Serialize> Serialize for MqMessage<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let payload = serde_json::to_value(&self.payload).map_err(serde::ser::Error::custom)?;
        let mut object = match payload {
            Value::Object(object) => object,
            _ => {
                return Err(serde::ser::Error::custom(
                    "MQ payload must be a JSON object",
                ))
            }
        };
        object.insert("messageId".into(), Value::String(self.message_id.clone()));
        object.insert("timestamp".into(), Value::String(self.timestamp.clone()));
        object.serialize(serializer)
    }
}

impl<'de, T> serde::Deserialize<'de> for MqMessage<T>
where
    T: serde::de::DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut value = Value::deserialize(deserializer)?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| serde::de::Error::custom("MQ message must be a JSON object"))?;
        let message_id = object
            .remove("messageId")
            .and_then(|value| value.as_str().map(ToOwned::to_owned))
            .ok_or_else(|| serde::de::Error::missing_field("messageId"))?;
        let timestamp = object
            .remove("timestamp")
            .and_then(|value| match value {
                Value::String(value) => Some(value),
                Value::Number(value) => Some(value.to_string()),
                _ => None,
            })
            .unwrap_or_default();
        let payload_value = object
            .remove("payload")
            .unwrap_or_else(|| Value::Object(object.clone()));
        let payload = serde_json::from_value(payload_value).map_err(serde::de::Error::custom)?;
        Ok(Self {
            message_id,
            timestamp,
            payload,
        })
    }
}

impl<T: Serialize> MqMessage<T> {
    pub fn new(payload: T) -> Self {
        Self {
            message_id: Uuid::new_v4().to_string(),
            timestamp: now_timestamp(),
            payload,
        }
    }
}

fn local_message_type(queue_name: &str) -> &'static str {
    match queue_name {
        QUEUE_AUDIT_LOG => "AUDIT_LOG",
        QUEUE_LOGIN_EVENT => "LOGIN_EVENT",
        crate::config::QUEUE_AUTH_SESSION_REVOCATION => "AUTH_SESSION_REVOCATION",
        crate::config::QUEUE_CHAT_MESSAGE => "CHAT_MESSAGE",
        crate::config::QUEUE_LEARNING_PROGRESS => "LEARNING_PROGRESS",
        crate::config::QUEUE_SUBJECT_DELETE => "SUBJECT_DELETE",
        _ => "BUSINESS_MESSAGE",
    }
}

/// Build the transport-neutral envelope shared by both local-bus publish paths
/// (`try_publish` admission and `publish_and_wait` completion tracking).
fn local_bus_envelope<T: Serialize>(
    queue_name: &str,
    message: &MqMessage<T>,
    operation_id: &str,
    origin_region: &str,
) -> Result<crate::envelope::MessageEnvelope, MqError> {
    crate::envelope::MessageEnvelope::new(
        &message.message_id,
        operation_id,
        local_message_type(queue_name),
        1,
        origin_region,
        serde_json::to_value(&message.payload)?,
    )
    .map_err(MqError::Publish)
}

#[derive(Clone)]
enum ProducerTransport {
    Rabbit(Channel),
    Local {
        bus: crate::local_bus::LocalBus,
        origin_region: String,
    },
}

/// 消息生产者。
///
/// Rabbit transport is retained for cross-host/region delivery. Local mode
/// admits the message to a bounded in-process bus and never opens a broker or
/// database connection.
#[derive(Clone)]
pub struct Producer {
    transport: ProducerTransport,
}
impl Producer {
    /// 创建 RabbitMQ Producer（兼容既有调用方）。
    pub fn new(channel: Channel) -> Self {
        Self {
            transport: ProducerTransport::Rabbit(channel),
        }
    }

    pub fn new_local(bus: crate::local_bus::LocalBus, origin_region: impl Into<String>) -> Self {
        Self {
            transport: ProducerTransport::Local {
                bus,
                origin_region: origin_region.into(),
            },
        }
    }

    pub async fn enable_confirms(channel: &Channel) -> Result<(), MqError> {
        channel
            .confirm_select(ConfirmSelectOptions::default())
            .await
            .map_err(|error| MqError::Channel(format!("enable publisher confirms failed: {error}")))
    }

    /// Publish an allowlisted raw delivery without changing its body or
    /// business properties. This foundation is intentionally not called by
    /// consumers, workers, or APIs yet.
    pub async fn publish_raw_replay(
        &self,
        request: RawReplayRequest,
    ) -> Result<(), RawReplayError> {
        if request.message_id.trim().is_empty() {
            return Err(RawReplayError::EmptyMessageId);
        }
        if request.message_id.len() > u8::MAX as usize {
            return Err(RawReplayError::MessageIdTooLong {
                actual: request.message_id.len(),
            });
        }
        if request.payload.len() > MAX_RAW_REPLAY_PAYLOAD_BYTES {
            return Err(RawReplayError::PayloadTooLarge {
                limit: MAX_RAW_REPLAY_PAYLOAD_BYTES,
                actual: request.payload.len(),
            });
        }

        let route = RawReplayRoute::resolve(
            &request.owner,
            &request.source_queue,
            &request.source_exchange,
            &request.source_routing_key,
        )?;
        let (destination_exchange, destination_routing_key) = route.destination();
        let properties = sanitize_replay_properties(&request.properties, &request.message_id);
        let ProducerTransport::Rabbit(channel) = &self.transport else {
            return Err(RawReplayError::Publish {
                code: "local_transport_replay_unsupported",
                text: "raw replay requires the remote Rabbit transport".into(),
                returned: None,
            });
        };
        let confirmation = channel
            .basic_publish(
                ShortString::from(destination_exchange),
                ShortString::from(destination_routing_key),
                BasicPublishOptions {
                    mandatory: true,
                    ..BasicPublishOptions::default()
                },
                &request.payload,
                properties,
            )
            .await
            .map_err(|error| RawReplayError::Publish {
                code: "channel_publish_error",
                text: error.to_string(),
                returned: None,
            })?
            .await
            .map_err(|error| RawReplayError::Publish {
                code: "channel_confirm_error",
                text: error.to_string(),
                returned: None,
            })?;

        match confirmation {
            Confirmation::Ack(None) => {
                tracing::info!(
                    owner = %request.owner,
                    source_queue = %request.source_queue,
                    destination_exchange,
                    destination_routing_key,
                    message_id = %request.message_id,
                    payload_bytes = request.payload.len(),
                    "raw replay published"
                );
                Ok(())
            }
            Confirmation::Ack(Some(returned)) => Err(confirmation_error("ack_returned", returned)),
            Confirmation::Nack(returned) => Err(returned
                .map(|returned| confirmation_error("nack_returned", returned))
                .unwrap_or_else(|| RawReplayError::Publish {
                    code: "nack",
                    text: "publisher negatively acknowledged".to_owned(),
                    returned: None,
                })),
            Confirmation::NotRequested => Err(RawReplayError::Publish {
                code: "confirm_not_requested",
                text: "publisher confirms are not enabled".to_owned(),
                returned: None,
            }),
        }
    }

    /// 发送消息到指定交换机。
    pub async fn publish<T: Serialize>(
        &self,
        exchange_name: &str,
        routing_key: &str,
        message: &MqMessage<T>,
    ) -> Result<(), MqError> {
        let queue_name = crate::config::queue_for_routing_key(routing_key)
            .map(|queue| queue.name)
            .ok_or_else(|| {
                MqError::Publish(format!("routing key is not declared: {routing_key}"))
            })?;
        self.publish_with_queue_name(
            queue_name,
            exchange_name,
            routing_key,
            message,
            &message.message_id,
        )
        .await
    }

    /// 便捷方法：直接发送到队列绑定的交换机
    pub async fn publish_to_queue<T: Serialize>(
        &self,
        queue_name: &str,
        routing_key: &str,
        payload: T,
    ) -> Result<(), MqError> {
        self.publish_to_queue_with_message_id(queue_name, routing_key, None, None, payload)
            .await
    }

    async fn publish_to_queue_with_message_id<T: Serialize>(
        &self,
        queue_name: &str,
        routing_key: &str,
        message_id: Option<String>,
        operation_id: Option<String>,
        payload: T,
    ) -> Result<(), MqError> {
        let msg = MqMessage {
            message_id: message_id
                .filter(|message_id| !message_id.trim().is_empty())
                .unwrap_or_else(|| Uuid::new_v4().to_string()),
            timestamp: now_timestamp(),
            payload,
        };
        let exchange = match queue_name {
            crate::config::QUEUE_NOTIFICATION | crate::config::QUEUE_BUSINESS_CHAT => {
                crate::config::EXCHANGE_TOPIC
            }
            _ => crate::config::EXCHANGE_DIRECT,
        };
        if crate::config::route_for(queue_name, routing_key).is_none() {
            return Err(MqError::Publish(format!(
                "queue/routing key is not declared: {queue_name}/{routing_key}"
            )));
        }
        let operation_id = operation_id
            .filter(|operation_id| !operation_id.trim().is_empty())
            .unwrap_or_else(|| msg.message_id.clone());
        self.publish_with_queue_name(queue_name, exchange, routing_key, &msg, &operation_id)
            .await
    }

    async fn publish_with_queue_name<T: Serialize>(
        &self,
        queue_name: &str,
        exchange_name: &str,
        routing_key: &str,
        message: &MqMessage<T>,
        operation_id: &str,
    ) -> Result<(), MqError> {
        let payload = serde_json::to_vec(message)?;
        if let ProducerTransport::Local { bus, origin_region } = &self.transport {
            let envelope = local_bus_envelope(queue_name, message, operation_id, origin_region)?;
            bus.try_publish(queue_name, routing_key, envelope)
                .map_err(|error| MqError::Publish(error.to_string()))?;
            tracing::debug!(
                queue = %queue_name,
                routing_key = %routing_key,
                message_id = %message.message_id,
                "message admitted to local in-process bus"
            );
            return Ok(());
        }

        let ProducerTransport::Rabbit(channel) = &self.transport else {
            return Err(MqError::Publish("unsupported producer transport".into()));
        };
        let properties = BasicProperties::default()
            .with_delivery_mode(2)
            .with_content_type("application/json".into())
            .with_message_id(message.message_id.as_str().into());
        let confirmation = channel
            .basic_publish(
                ShortString::from(exchange_name),
                ShortString::from(routing_key),
                BasicPublishOptions {
                    mandatory: true,
                    ..BasicPublishOptions::default()
                },
                &payload,
                properties,
            )
            .await?
            .await?;
        match confirmation {
            Confirmation::Ack(None) => {}
            Confirmation::Ack(Some(returned)) => {
                return Err(MqError::Publish(format!(
                    "RabbitMQ returned unroutable message: code={}, text={}",
                    returned.reply_code, returned.reply_text
                )));
            }
            Confirmation::Nack(_) => {
                return Err(MqError::Publish("RabbitMQ publisher NACK".into()));
            }
            Confirmation::NotRequested => {
                return Err(MqError::Publish(
                    "RabbitMQ publisher confirms are not enabled".into(),
                ));
            }
        }
        tracing::debug!(
            exchange = %exchange_name,
            routing_key = %routing_key,
            queue = %queue_name,
            message_id = %message.message_id,
            "message published"
        );
        Ok(())
    }

    // ===== 类型化便捷方法 =====

    /// 发布审计日志消息
    pub async fn publish_audit_log(&self, payload: AuditLogPayload) -> Result<(), MqError> {
        let message_id = payload.message_id.clone();
        self.publish_to_queue_with_message_id(
            crate::config::QUEUE_AUDIT_LOG,
            "audit.log",
            message_id,
            None,
            payload,
        )
        .await
    }

    /// 发布登录事件消息
    pub async fn publish_login_event(&self, payload: LoginEventPayload) -> Result<(), MqError> {
        let message_id = payload.message_id.clone();
        self.publish_to_queue_with_message_id(
            crate::config::QUEUE_LOGIN_EVENT,
            "login.event",
            message_id,
            None,
            payload,
        )
        .await
    }

    /// 发布聊天消息通知。
    ///
    /// ChatMessageConsumer 监听 `astral.chat.message`，该队列绑定
    /// `astral.direct`/`chat.message`；不要将它路由到 business-chat topic 队列。
    pub async fn publish_chat_message(&self, payload: ChatMessagePayload) -> Result<(), MqError> {
        self.publish_to_queue(crate::config::QUEUE_CHAT_MESSAGE, "chat.message", payload)
            .await
    }

    /// Publish with an explicit transport identity. This convenience method
    /// generates a new timestamp; durable retries must use `publish_committed_chat_message`.
    pub async fn publish_chat_message_with_message_id(
        &self,
        payload: ChatMessagePayload,
        message_id: &str,
    ) -> Result<(), MqError> {
        if message_id.is_empty()
            || message_id.len() > u8::MAX as usize
            || message_id.trim() != message_id
            || message_id.chars().any(char::is_control)
        {
            return Err(MqError::Publish("invalid stable Chat message id".into()));
        }
        self.publish_to_queue_with_message_id(
            crate::config::QUEUE_CHAT_MESSAGE,
            "chat.message",
            Some(message_id.to_owned()),
            Some(message_id.to_owned()),
            payload,
        )
        .await
    }

    /// Publish the exact persisted Chat message, including its original timestamp.
    /// Confirmation proves broker admission, not recipient delivery.
    pub async fn publish_committed_chat_message(
        &self,
        message: &MqMessage<ChatMessagePayload>,
    ) -> Result<(), MqError> {
        if message.message_id.is_empty()
            || message.message_id.len() > u8::MAX as usize
            || message.message_id.trim() != message.message_id
            || message.message_id.chars().any(char::is_control)
            || message.timestamp.len() > 64
            || time::OffsetDateTime::parse(
                &message.timestamp,
                &time::format_description::well_known::Rfc3339,
            )
            .is_err()
        {
            return Err(MqError::Publish(
                "invalid committed Chat message identity".into(),
            ));
        }
        self.publish_with_queue_name(
            crate::config::QUEUE_CHAT_MESSAGE,
            crate::config::EXCHANGE_DIRECT,
            "chat.message",
            message,
            &message.message_id,
        )
        .await
    }

    /// 发布学习进度更新
    pub async fn publish_learning_progress(
        &self,
        payload: LearningProgressPayload,
    ) -> Result<(), MqError> {
        self.publish_to_queue("astral.learning.progress", "learning.progress", payload)
            .await
    }

    /// 发布学科删除事件
    pub async fn publish_subject_delete(
        &self,
        payload: SubjectDeletePayload,
    ) -> Result<(), MqError> {
        self.publish_to_queue("astral.subject.delete", "subject.delete", payload)
            .await
    }

    /// Publish a typed authorization invalidation after its source transaction
    /// has committed. The local path only admits the validated envelope to the
    /// bounded LocalBus; it does not prove durable fanout. The Rabbit path
    /// stays rejected here on purpose: cross-node delivery must go through the
    /// durable outbox relay ([`crate::invalidation_fanout_worker`] +
    /// `committed_invalidation_fanout_request`), never a direct publish that
    /// could bypass the canonical committed envelope.
    pub async fn publish_invalidation(
        &self,
        event: crate::invalidation::InvalidationEvent,
        message_id: impl Into<String>,
        operation_id: impl Into<String>,
        origin_region: impl Into<String>,
    ) -> Result<(), MqError> {
        let envelope = event
            .to_envelope(message_id, operation_id, origin_region)
            .map_err(|error| MqError::Publish(error.to_string()))?;
        match &self.transport {
            ProducerTransport::Local { bus, .. } => bus
                .try_publish(
                    crate::config::QUEUE_AUTHORIZATION_INVALIDATION,
                    crate::config::ROUTING_KEY_AUTHORIZATION_INVALIDATION,
                    envelope,
                )
                .map_err(|error| MqError::Publish(error.to_string())),
            ProducerTransport::Rabbit(_) => Err(MqError::Publish(
                "authorization invalidation Rabbit fanout is not implemented; durable append and reconciliation are required"
                    .into(),
            )),
        }
    }

    /// 发布会话撤销命令（对齐 Java AuthSessionRevocationCommandService）
    pub async fn publish_auth_session_revocation(
        &self,
        payload: AuthSessionRevocationPayload,
    ) -> Result<(), MqError> {
        let message_id = payload.message_id.clone();
        self.publish_to_queue_with_message_id(
            crate::config::QUEUE_AUTH_SESSION_REVOCATION,
            "auth.session.revocation",
            message_id,
            payload.operation_id.clone(),
            payload,
        )
        .await
    }

    /// 发布撤销命令并在本地组合进程中等待 handler 完成证明。
    ///
    /// LocalBus 的入队成功只代表 admission；本方法在 local transport 下等待
    /// consumer 返回 durable 业务结果，超时/consumer 消失保持 UnknownOutcome。
    /// Rabbit transport 没有远端业务完成语义，因此只等待 publisher confirm，
    /// 调用方仍必须查询 durable outbox 才能决定 READY/PENDING。
    pub async fn publish_auth_session_revocation_and_wait(
        &self,
        payload: AuthSessionRevocationPayload,
        deadline: std::time::Duration,
    ) -> Result<(), MqError> {
        let message_id = payload
            .message_id
            .clone()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let operation_id = payload
            .operation_id
            .clone()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| message_id.clone());
        let msg = MqMessage {
            message_id,
            timestamp: now_timestamp(),
            payload,
        };
        if let ProducerTransport::Local { bus, origin_region } = &self.transport {
            let envelope = local_bus_envelope(
                crate::config::QUEUE_AUTH_SESSION_REVOCATION,
                &msg,
                &operation_id,
                origin_region,
            )?;
            bus.publish_and_wait(
                crate::config::QUEUE_AUTH_SESSION_REVOCATION,
                "auth.session.revocation",
                envelope,
                deadline,
            )
            .await
            .map_err(|error| MqError::Publish(error.to_string()))?;
            return Ok(());
        }
        // Rabbit publisher confirms establish broker admission only. The remote
        // business handler has no request/response channel here, so preserve the
        // normal confirm semantics and let the durable outbox decide completion.
        self.publish_with_queue_name(
            crate::config::QUEUE_AUTH_SESSION_REVOCATION,
            crate::config::EXCHANGE_DIRECT,
            "auth.session.revocation",
            &msg,
            &operation_id,
        )
        .await
    }
}

// ===== invalidation fanout typed seam =====

/// Typed seam between the durable invalidation outbox and the Rabbit fanout
/// transport: derives the publish request from a **preexisting durable row**
/// (as claimed by the relay worker).
///
/// The returned request keeps the row's `payload_json` as the exact wire
/// bytes — `createdAt` and every envelope identity field are the ones the
/// source transaction committed. Nothing here rebuilds or re-stamps the
/// envelope; rows that no longer parse as a contract-valid invalidation
/// envelope are rejected so the relay can quarantine them instead of
/// publishing divergent bytes.
pub fn committed_invalidation_fanout_request(
    row: &astral_db::LocalMessageRow,
) -> Result<crate::invalidation_fanout::CommittedInvalidationEnvelope, MqError> {
    crate::invalidation_fanout::CommittedInvalidationEnvelope::from_durable_row(row)
        .map_err(|error| MqError::Publish(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lapin::types::LongString;
    use serde_json::json;
    use std::time::Duration;

    use crate::config::EXCHANGE_TOPIC;
    use crate::config::QUEUE_AUTH_SESSION_REVOCATION;
    use crate::local_bus::{LocalBus, LocalBusLimits, LocalOwner, LocalReceiver};

    fn replay_request() -> RawReplayRequest {
        let mut headers = FieldTable::default();
        headers.insert(
            ShortString::from("x-keep"),
            AMQPValue::LongString(LongString::from("safe")),
        );
        headers.insert(
            ShortString::from(HEADER_DEATH),
            AMQPValue::LongString(LongString::from("sensitive-death-history")),
        );
        headers.insert(
            ShortString::from(HEADER_DLQ_REPUBLISH_COUNT),
            AMQPValue::LongLongInt(7),
        );
        headers.insert(
            ShortString::from(HEADER_RETRY_COUNT),
            AMQPValue::LongLongInt(9),
        );
        RawReplayRequest::new(
            "trustgraph",
            QUEUE_AUDIT_LOG,
            EXCHANGE_DIRECT,
            "audit.log",
            b"raw-secret-payload".to_vec(),
            BasicProperties::default()
                .with_content_type(ShortString::from("application/json"))
                .with_delivery_mode(2)
                .with_headers(headers),
            "audit-message-1",
        )
    }

    #[test]
    fn raw_replay_allowlist_is_exact_and_canonical() {
        assert_eq!(
            RawReplayRoute::resolve("trustgraph", QUEUE_AUDIT_LOG, EXCHANGE_DIRECT, "audit.log")
                .unwrap()
                .destination(),
            (EXCHANGE_DIRECT, "audit.log")
        );
        assert_eq!(
            RawReplayRoute::resolve(
                "identity",
                QUEUE_LOGIN_EVENT,
                EXCHANGE_DIRECT,
                "login.event"
            )
            .unwrap()
            .destination(),
            (EXCHANGE_DIRECT, "login.event")
        );

        for route in [
            (
                "trustgraph",
                QUEUE_AUDIT_LOG,
                EXCHANGE_DIRECT,
                "login.event",
            ),
            ("identity", QUEUE_LOGIN_EVENT, EXCHANGE_DIRECT, "audit.log"),
            ("trustgraph", QUEUE_AUDIT_LOG, EXCHANGE_TOPIC, "audit.log"),
            (
                "identity",
                QUEUE_LOGIN_EVENT,
                EXCHANGE_DIRECT,
                "login.event.#",
            ),
            ("learn", QUEUE_AUDIT_LOG, EXCHANGE_DIRECT, "audit.log"),
        ] {
            assert!(RawReplayRoute::resolve(route.0, route.1, route.2, route.3).is_err());
        }
    }

    #[test]
    fn raw_replay_properties_preserve_business_fields_and_reset_retry_headers() {
        let request = replay_request();
        let properties = sanitize_replay_properties(&request.properties, &request.message_id);
        assert_eq!(
            properties.message_id().as_ref().unwrap().as_str(),
            "audit-message-1"
        );
        assert_eq!(
            properties.content_type().as_ref().unwrap().as_str(),
            "application/json"
        );
        assert_eq!(properties.delivery_mode(), &Some(2));
        let headers = properties.headers().as_ref().unwrap();
        assert!(headers.contains_key("x-keep"));
        assert!(!headers.contains_key(HEADER_DEATH));
        assert!(!headers.contains_key(HEADER_DLQ_REPUBLISH_COUNT));
        assert_eq!(
            headers
                .inner()
                .get(HEADER_RETRY_COUNT)
                .unwrap()
                .as_long_long_int(),
            Some(0)
        );
    }

    #[test]
    fn raw_replay_payload_and_return_summary_do_not_expose_body() {
        let request = replay_request();
        assert_eq!(request.payload, b"raw-secret-payload");
        let returned = lapin::message::Delivery::mock(
            1,
            ShortString::from(EXCHANGE_DIRECT),
            ShortString::from("audit.log"),
            false,
            b"raw-secret-payload".to_vec(),
        );
        let returned = BasicReturnMessage {
            delivery: returned,
            reply_code: 312,
            reply_text: ShortString::from("NO_ROUTE"),
        };
        let error = confirmation_error("ack_returned", returned);
        let RawReplayError::Publish {
            returned: Some(summary),
            ..
        } = error
        else {
            panic!("expected structured returned-message error");
        };
        assert_eq!(summary.payload_bytes, request.payload.len());
        assert!(!summary.payload_sha256.contains("raw-secret-payload"));
        assert!(!summary.to_string().contains("raw-secret-payload"));
    }

    #[test]
    fn raw_replay_error_codes_cover_confirmation_variants() {
        let variants = [
            ("nack", "publisher negatively acknowledged"),
            (
                "confirm_not_requested",
                "publisher confirms are not enabled",
            ),
        ];
        for (code, text) in variants {
            let error = RawReplayError::Publish {
                code,
                text: text.to_owned(),
                returned: None,
            };
            assert!(error.to_string().contains(code));
            assert!(error.to_string().contains(text));
        }
    }

    fn chat_payload() -> ChatMessagePayload {
        ChatMessagePayload {
            id: 42,
            conversation_id: 10,
            sender_id: 1,
            content: "hello".into(),
            message_type: "TEXT".into(),
        }
    }

    #[test]
    fn audit_payload_detail_is_optional_and_wire_backward_compatible() {
        // 旧 wire 消息（无 detail 键）必须仍可反序列化，detail 落 None。
        let legacy = json!({
            "messageId": "legacy-message",
            "userId": 7,
            "cardId": 70,
            "action": "read",
            "resource": "card",
            "decision": "ALLOW",
            "reason": "ok",
            "eventType": "PERMISSION_CHECK",
            "sourceIp": "127.0.0.1",
            "requestId": "req-1",
            "domainId": 2,
            "tenantId": 1
        });
        let decoded: AuditLogPayload = serde_json::from_value(legacy).unwrap();
        assert_eq!(decoded.detail, None);

        // 新消息带 detail 时按 camelCase wire 名序列化，并可完整回读。
        let mut payload = sample_json_audit_payload();
        payload.detail = Some("{\"path\":\"/stats\"}".into());
        let value = serde_json::to_value(&payload).unwrap();
        assert_eq!(value["detail"], "{\"path\":\"/stats\"}");
        let decoded: AuditLogPayload = serde_json::from_value(value).unwrap();
        assert_eq!(decoded.detail.as_deref(), Some("{\"path\":\"/stats\"}"));

        // detail 缺省为 None 时不得出现在 wire 上（向后兼容的紧凑消息）。
        let value = serde_json::to_value(sample_json_audit_payload()).unwrap();
        assert!(value.get("detail").is_none());
    }

    fn sample_json_audit_payload() -> AuditLogPayload {
        AuditLogPayload {
            message_id: None,
            user_id: Some(7),
            card_id: Some(70),
            action: "read".into(),
            resource: "card".into(),
            decision: "ALLOW".into(),
            reason: Some("ok".into()),
            event_type: "PERMISSION_CHECK".into(),
            source_ip: Some("127.0.0.1".into()),
            request_id: Some("req-1".into()),
            domain_id: Some(2),
            tenant_id: Some(1),
            detail: None,
        }
    }

    #[test]
    fn chat_payload_uses_canonical_camel_case_wire_fields() {
        let value = serde_json::to_value(chat_payload()).unwrap();
        assert_eq!(
            value,
            json!({
                "id": 42,
                "conversationId": 10,
                "senderId": 1,
                "content": "hello",
                "messageType": "TEXT"
            })
        );
        assert!(!value.as_object().unwrap().contains_key("sessionId"));
        assert!(!value.as_object().unwrap().contains_key("msgType"));
        assert!(!value.as_object().unwrap().contains_key("messageId"));
    }

    #[test]
    fn chat_payload_rejects_legacy_field_names() {
        let legacy = json!({
            "messageId": "legacy-message",
            "sessionId": 10,
            "senderId": 1,
            "content": "hello",
            "msgType": "TEXT"
        });
        assert!(serde_json::from_value::<ChatMessagePayload>(legacy).is_err());
    }

    #[test]
    fn chat_envelope_keeps_global_message_id_for_idempotency() {
        let message = MqMessage {
            message_id: "msg-chat-42".into(),
            timestamp: "2026-08-17T00:00:00Z".into(),
            payload: chat_payload(),
        };
        let value = serde_json::to_value(&message).unwrap();
        assert_eq!(value["messageId"], "msg-chat-42");
        assert_eq!(value["id"], 42);
        assert_eq!(value["conversationId"], 10);
        assert_eq!(value["messageType"], "TEXT");
        assert!(value.get("sessionId").is_none());
        assert!(value.get("msgType").is_none());

        let decoded: MqMessage<ChatMessagePayload> = serde_json::from_value(value).unwrap();
        assert_eq!(decoded.message_id, "msg-chat-42");
        assert_eq!(decoded.payload, chat_payload());
    }

    #[tokio::test]
    async fn stable_chat_message_id_rejects_invalid_ids_before_transport() {
        let bus = LocalBus::new(LocalBusLimits::default()).unwrap();
        let producer = Producer::new_local(bus, "local");
        for message_id in [
            "".to_owned(),
            " ".into(),
            " id".into(),
            "id ".into(),
            "id\n".into(),
            "x".repeat(256),
        ] {
            let error = producer
                .publish_chat_message_with_message_id(chat_payload(), &message_id)
                .await
                .unwrap_err();
            assert!(
                matches!(error, MqError::Publish(reason) if reason == "invalid stable Chat message id")
            );
        }
    }

    #[test]
    fn stable_chat_publisher_preserves_envelope_and_amqp_message_id() {
        let source = include_str!("producer.rs");
        let stable = source
            .split("pub async fn publish_chat_message_with_message_id(")
            .nth(1)
            .unwrap()
            .split("pub async fn publish_learning_progress(")
            .next()
            .unwrap();
        assert!(stable.contains("Some(message_id.to_owned())"));
        assert!(!stable.contains("Uuid::new_v4"));
        assert!(stable.contains("crate::config::QUEUE_CHAT_MESSAGE"));
        assert!(stable.contains("\"chat.message\""));
        let rabbit = source
            .split("let properties = BasicProperties::default()")
            .nth(1)
            .unwrap()
            .split("// ===== 类型化便捷方法 =====")
            .next()
            .unwrap();
        assert!(rabbit.contains(".with_message_id(message.message_id.as_str().into())"));
        assert!(rabbit.contains("Confirmation::Ack(None)"));
        assert!(rabbit.contains("mandatory: true"));
    }

    #[test]
    fn committed_chat_wire_digest_is_stable_across_durable_round_trips() {
        let message = MqMessage {
            message_id: "committed-chat-message".into(),
            timestamp: "2026-10-03T00:00:00Z".into(),
            payload: chat_payload(),
        };
        let bytes = serde_json::to_vec(&message).unwrap();
        let reloaded: MqMessage<ChatMessagePayload> = serde_json::from_slice(&bytes).unwrap();
        let replayed = serde_json::to_vec(&reloaded).unwrap();
        assert_eq!(bytes, replayed);
        assert_eq!(Sha256::digest(&bytes), Sha256::digest(&replayed));
        let source = include_str!("producer.rs");
        let committed = source
            .split("pub async fn publish_committed_chat_message(")
            .nth(1)
            .unwrap()
            .split("pub async fn publish_learning_progress(")
            .next()
            .unwrap();
        assert!(!committed.contains("now_timestamp"));
        assert!(!committed.contains("Uuid::new_v4"));
        assert!(committed.contains("message,"));
        assert!(committed.contains("&message.message_id"));
    }

    #[tokio::test]
    async fn committed_chat_message_refuses_unproven_timestamp_before_transport() {
        let producer =
            Producer::new_local(LocalBus::new(LocalBusLimits::default()).unwrap(), "local");
        for timestamp in ["", "not-a-time"] {
            let message = MqMessage {
                message_id: "committed-chat-message".into(),
                timestamp: timestamp.into(),
                payload: chat_payload(),
            };
            let error = producer
                .publish_committed_chat_message(&message)
                .await
                .unwrap_err();
            assert!(
                matches!(error, MqError::Publish(reason) if reason == "invalid committed Chat message identity")
            );
        }
    }

    #[test]
    fn chat_queue_uses_direct_chat_message_binding() {
        let queue = crate::config::QUEUES
            .iter()
            .find(|queue| queue.name == crate::config::QUEUE_CHAT_MESSAGE)
            .unwrap();
        assert_eq!(queue.exchange_name, crate::config::EXCHANGE_DIRECT);
        assert_eq!(queue.routing_key, "chat.message");
    }

    #[tokio::test]
    async fn typed_invalidation_publish_preserves_stable_identity_and_scope() {
        let bus = LocalBus::new(LocalBusLimits::default()).unwrap();
        let mut receiver = bus
            .register(
                crate::config::QUEUE_AUTHORIZATION_INVALIDATION,
                LocalOwner::AuthorizationInvalidation,
            )
            .unwrap();
        let producer = Producer::new_local(bus, "local");
        let event = crate::invalidation::InvalidationEvent::EvidenceInvalidated(
            crate::invalidation::EvidenceInvalidated {
                tenant_id: 7,
                card_id: Some(42),
                aggregate_type: astral_types::PublishedEvidenceAggregate::UserCard,
                aggregate_id: 42,
                published_generation: 10,
                source_generation: 10,
                revoke_fence: 0,
            },
        );
        producer
            .publish_invalidation(event, "event-1", "operation-1", "city-a")
            .await
            .unwrap();
        let delivery = receiver.recv().await.unwrap();
        assert_eq!(delivery.envelope.message_id, "event-1");
        assert_eq!(delivery.envelope.operation_id, "operation-1");
        assert_eq!(
            delivery.envelope.message_type,
            crate::invalidation::EVIDENCE_INVALIDATED
        );
        assert_eq!(delivery.envelope.tenant_id, Some(7));
        assert_eq!(
            delivery.envelope.ordering_key.as_deref(),
            Some("authorization:evidence:tenant/7/aggregate/USER_CARD/42/card/42")
        );
        delivery.complete(Ok(()));
    }

    #[tokio::test]
    async fn generic_publish_cannot_route_to_local_invalidation_queue() {
        let bus = LocalBus::new(LocalBusLimits::default()).unwrap();
        let mut receiver = bus
            .register(
                crate::config::QUEUE_AUTHORIZATION_INVALIDATION,
                LocalOwner::AuthorizationInvalidation,
            )
            .unwrap();
        let producer = Producer::new_local(bus, "local");
        assert!(producer
            .publish_to_queue(
                crate::config::QUEUE_AUTHORIZATION_INVALIDATION,
                crate::config::ROUTING_KEY_AUTHORIZATION_INVALIDATION,
                json!({"message": "untyped"}),
            )
            .await
            .is_err());
        assert!(
            tokio::time::timeout(Duration::from_millis(1), receiver.recv())
                .await
                .is_err()
        );
    }

    // ===== 本地撤销等待路径（publish_auth_session_revocation_and_wait）=====

    fn revocation_payload(
        message_id: Option<&str>,
        operation_id: Option<&str>,
    ) -> AuthSessionRevocationPayload {
        AuthSessionRevocationPayload {
            message_id: message_id.map(ToOwned::to_owned),
            operation_id: operation_id.map(ToOwned::to_owned),
            user_id: 7,
            reason: "admin-reset".into(),
            timestamp: now_timestamp(),
        }
    }

    /// 本地 transport fixture：默认容量 + 已注册的 Identity owner receiver。
    fn local_revocation_fixture(queue_capacity: usize) -> (Producer, LocalReceiver, LocalBus) {
        let bus = LocalBus::new(LocalBusLimits {
            queue_capacity,
            ..LocalBusLimits::default()
        })
        .unwrap();
        let receiver = bus
            .register(QUEUE_AUTH_SESSION_REVOCATION, LocalOwner::Identity)
            .unwrap();
        (Producer::new_local(bus.clone(), "local"), receiver, bus)
    }

    /// 等待语义：producer 必须阻塞到 handler 调用 `delivery.complete` 并以
    /// 该结果收束 —— handler 失败必须作为错误返回（若 admission 即返回，
    /// 这里会错误地得到 `Ok`）。recv → complete 由任务调度点串行，无 sleep。
    #[tokio::test]
    async fn local_revocation_wait_blocks_until_delivery_complete_and_maps_failure() {
        let (producer, mut receiver, _bus) = local_revocation_fixture(4);
        let waiter = tokio::spawn({
            let producer = producer.clone();
            async move {
                producer
                    .publish_auth_session_revocation_and_wait(
                        revocation_payload(Some("rev-wait"), Some("rev-op")),
                        Duration::from_secs(5),
                    )
                    .await
            }
        });
        let delivery = receiver.recv().await.unwrap();
        delivery.complete(Err("identity revocation failed".into()));
        match waiter.await.unwrap() {
            Err(MqError::Publish(text)) => {
                assert!(text.contains("local handler failed"), "unexpected: {text}");
                assert!(
                    text.contains("identity revocation failed"),
                    "unexpected: {text}"
                );
            }
            other => panic!("expected handler failure error, got {other:?}"),
        }
    }

    /// 成功路径 + 稳定 id：显式 message_id/operation_id 原样进入 envelope 与
    /// 业务 payload（consumer 的 durable outbox 幂等键依赖 operationId）。
    #[tokio::test]
    async fn local_revocation_wait_returns_ok_and_preserves_stable_ids() {
        let (producer, mut receiver, _bus) = local_revocation_fixture(4);
        let waiter = tokio::spawn({
            let producer = producer.clone();
            async move {
                producer
                    .publish_auth_session_revocation_and_wait(
                        revocation_payload(Some("rev-msg-1"), Some("rev-op-1")),
                        Duration::from_secs(5),
                    )
                    .await
            }
        });
        let delivery = receiver.recv().await.unwrap();
        assert_eq!(delivery.envelope.message_id, "rev-msg-1");
        assert_eq!(delivery.envelope.operation_id, "rev-op-1");
        assert_eq!(delivery.envelope.message_type, "AUTH_SESSION_REVOCATION");
        assert_eq!(delivery.envelope.origin_region, "local");
        assert_eq!(delivery.envelope.payload["operationId"], "rev-op-1");
        delivery.complete(Ok(()));
        waiter.await.unwrap().unwrap();
    }

    /// id 回退：operation_id 缺省回退到 message_id 且不写入业务 payload；
    /// message_id 也缺省时生成 UUID 并保持 message_id == operation_id。
    #[tokio::test]
    async fn local_revocation_wait_falls_back_operation_id_to_message_id() {
        let (producer, mut receiver, _bus) = local_revocation_fixture(4);
        let waiter = tokio::spawn({
            let producer = producer.clone();
            async move {
                producer
                    .publish_auth_session_revocation_and_wait(
                        revocation_payload(Some("rev-msg-2"), None),
                        Duration::from_secs(5),
                    )
                    .await
            }
        });
        let delivery = receiver.recv().await.unwrap();
        assert_eq!(delivery.envelope.message_id, "rev-msg-2");
        assert_eq!(delivery.envelope.operation_id, "rev-msg-2");
        assert_eq!(
            delivery.envelope.payload["operationId"],
            serde_json::Value::Null
        );
        delivery.complete(Ok(()));
        waiter.await.unwrap().unwrap();

        let waiter = tokio::spawn({
            let producer = producer.clone();
            async move {
                producer
                    .publish_auth_session_revocation_and_wait(
                        revocation_payload(None, None),
                        Duration::from_secs(5),
                    )
                    .await
            }
        });
        let delivery = receiver.recv().await.unwrap();
        assert!(!delivery.envelope.message_id.is_empty());
        assert_eq!(delivery.envelope.operation_id, delivery.envelope.message_id);
        delivery.complete(Ok(()));
        waiter.await.unwrap().unwrap();
    }

    /// 未知结果必须 fail closed：deadline 到期（delivery 未完成）与 consumer
    /// 消失（delivery 被 drop）都只能得到 UnknownOutcome，携带稳定 message_id
    /// 供对账，绝不返回成功。`Duration::ZERO` 保证超时分支确定性。
    #[tokio::test]
    async fn local_revocation_wait_deadline_and_dropped_consumer_stay_unknown() {
        let (producer, mut receiver, _bus) = local_revocation_fixture(4);

        let waiter = tokio::spawn({
            let producer = producer.clone();
            async move {
                producer
                    .publish_auth_session_revocation_and_wait(
                        revocation_payload(Some("rev-deadline"), None),
                        Duration::ZERO,
                    )
                    .await
            }
        });
        let delivery = receiver.recv().await.unwrap();
        assert_eq!(delivery.envelope.message_id, "rev-deadline");
        match waiter.await.unwrap() {
            Err(MqError::Publish(text)) => {
                assert!(text.contains("unknown"), "unexpected: {text}");
                assert!(text.contains("rev-deadline"), "unexpected: {text}");
            }
            other => panic!("expected unknown outcome, got {other:?}"),
        }
        drop(delivery);

        let waiter = tokio::spawn({
            let producer = producer.clone();
            async move {
                producer
                    .publish_auth_session_revocation_and_wait(
                        revocation_payload(Some("rev-dropped"), None),
                        Duration::from_secs(5),
                    )
                    .await
            }
        });
        let delivery = receiver.recv().await.unwrap();
        drop(delivery);
        match waiter.await.unwrap() {
            Err(MqError::Publish(text)) => {
                assert!(text.contains("unknown"), "unexpected: {text}");
                assert!(text.contains("rev-dropped"), "unexpected: {text}");
            }
            other => panic!("expected unknown outcome, got {other:?}"),
        }
    }

    /// 显式拒绝：owner 未注册（NoOwner）与队列打满（Full）都必须在入队前
    /// 得到显式错误，不产生"看似成功"的 admission。
    #[tokio::test]
    async fn local_revocation_wait_reports_missing_owner_and_full_queue_explicitly() {
        let bus = LocalBus::new(LocalBusLimits::default()).unwrap();
        let producer = Producer::new_local(bus, "local");
        match producer
            .publish_auth_session_revocation_and_wait(
                revocation_payload(Some("rev-no-owner"), None),
                Duration::from_secs(5),
            )
            .await
        {
            Err(MqError::Publish(text)) => {
                assert!(text.contains("no registered owner"), "unexpected: {text}");
                assert!(
                    text.contains(QUEUE_AUTH_SESSION_REVOCATION),
                    "unexpected: {text}"
                );
            }
            other => panic!("expected missing-owner error, got {other:?}"),
        }

        let (producer, mut receiver, bus) = local_revocation_fixture(1);
        let filler = crate::envelope::MessageEnvelope::new(
            "rev-filler",
            "rev-filler",
            "AUTH_SESSION_REVOCATION",
            1,
            "local",
            json!({"filler": true}),
        )
        .unwrap();
        bus.try_publish(
            QUEUE_AUTH_SESSION_REVOCATION,
            "auth.session.revocation",
            filler,
        )
        .unwrap();
        match producer
            .publish_auth_session_revocation_and_wait(
                revocation_payload(Some("rev-full"), None),
                Duration::from_secs(5),
            )
            .await
        {
            Err(MqError::Publish(text)) => {
                assert!(text.contains("full"), "unexpected: {text}");
            }
            other => panic!("expected queue-full error, got {other:?}"),
        }
        let filler = receiver.recv().await.unwrap();
        assert_eq!(filler.envelope.message_id, "rev-filler");
        drop(filler);
    }
}
