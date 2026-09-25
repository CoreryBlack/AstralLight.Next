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

/// 消息生产者
#[derive(Clone)]
pub struct Producer {
    channel: Channel,
}
impl Producer {
    /// 创建 Producer
    pub fn new(channel: Channel) -> Self {
        Self { channel }
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
        let confirmation = self
            .channel
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
        let payload = serde_json::to_vec(message)?;

        let properties = BasicProperties::default()
            .with_delivery_mode(2) // persistent
            .with_content_type("application/json".into())
            .with_message_id(message.message_id.as_str().into());

        let confirmation = self
            .channel
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
            Confirmation::Ack(None) | Confirmation::Ack(Some(_)) => {}
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
            message_id = %message.message_id,
            "message published"
        );

        Ok(())
    }

    /// 便捷方法：直接发送到队列绑定的交换机
    ///
    /// 交换机推导规则（对齐 Java MQConfig / MQConstants）：
    /// - `astral.notification` / `astral.business.chat` → `astral.topic`（主题交换机）
    /// - 其他所有队列 → `astral.direct`（直连交换机）
    pub async fn publish_to_queue<T: Serialize>(
        &self,
        queue_name: &str,
        routing_key: &str,
        payload: T,
    ) -> Result<(), MqError> {
        let msg = MqMessage::new(payload);
        let exchange = match queue_name {
            crate::config::QUEUE_NOTIFICATION | crate::config::QUEUE_BUSINESS_CHAT => {
                crate::config::EXCHANGE_TOPIC
            }
            _ => crate::config::EXCHANGE_DIRECT,
        };

        self.publish(exchange, routing_key, &msg).await
    }

    // ===== 类型化便捷方法 =====

    /// 发布审计日志消息
    pub async fn publish_audit_log(&self, payload: AuditLogPayload) -> Result<(), MqError> {
        self.publish_to_queue("astral.audit.log", "audit.log", payload)
            .await
    }

    /// 发布登录事件消息
    pub async fn publish_login_event(&self, payload: LoginEventPayload) -> Result<(), MqError> {
        self.publish_to_queue("astral.login.event", "login.event", payload)
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

    /// 发布会话撤销命令（对齐 Java AuthSessionRevocationCommandService）
    pub async fn publish_auth_session_revocation(
        &self,
        payload: AuthSessionRevocationPayload,
    ) -> Result<(), MqError> {
        self.publish_to_queue(
            crate::config::QUEUE_AUTH_SESSION_REVOCATION,
            "auth.session.revocation",
            payload,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lapin::types::LongString;
    use serde_json::json;

    use crate::config::EXCHANGE_TOPIC;

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

    #[test]
    fn chat_queue_uses_direct_chat_message_binding() {
        let queue = crate::config::QUEUES
            .iter()
            .find(|queue| queue.name == crate::config::QUEUE_CHAT_MESSAGE)
            .unwrap();
        assert_eq!(queue.exchange_name, crate::config::EXCHANGE_DIRECT);
        assert_eq!(queue.routing_key, "chat.message");
    }
}
