//! RabbitMQ 交换机、队列、绑定声明
//!
//! 与 Java Spring AMQP 配置（MQConfig.java / MQConstants.java）完全对齐。
//!
//! 交换机：3 个共享交换机
//! - `astral.direct` (Direct) — 大部分业务队列绑定
//! - `astral.topic`  (Topic)  — notification、business.chat 绑定
//! - `astral.dlx`    (Direct) — 死信交换机
//!
//! 队列：12 个业务队列 + 12 个死信队列
//! - 业务队列 DLX routing key = `astral.dlx.<suffix>`（每队列独立）
//! - 死信队列名 = DLX routing key，绑定到 `astral.dlx`
//!
//! 注：旧 `astral.permission.refresh` 队列已随 CARD permission.refresh 冗余广播
//! （producer/consumer 对）一并移除，不再声明。

use lapin::options::{ExchangeDeclareOptions, QueueBindOptions, QueueDeclareOptions};
use lapin::types::{FieldTable, LongString, ShortString};
use lapin::{Channel, ExchangeKind};

// ===== 交换机常量（对齐 Java MQConstants） =====

pub const EXCHANGE_DIRECT: &str = "astral.direct";
pub const EXCHANGE_TOPIC: &str = "astral.topic";
pub const EXCHANGE_DLX: &str = "astral.dlx";

// ===== 队列常量（对齐 Java MQConstants） =====

pub const QUEUE_AUDIT_LOG: &str = "astral.audit.log";
pub const QUEUE_NOTIFICATION: &str = "astral.notification";
pub const QUEUE_LEARNING_PROGRESS: &str = "astral.learning.progress";
pub const QUEUE_LOGIN_EVENT: &str = "astral.login.event";
pub const QUEUE_SUBJECT_DELETE: &str = "astral.subject.delete";
pub const QUEUE_AUTH_SESSION_REVOCATION: &str = "astral.auth.session.revocation";
pub const QUEUE_CHAT_MESSAGE: &str = "astral.chat.message";
pub const QUEUE_BUSINESS_CHAT: &str = "astral.business.chat";
pub const QUEUE_DELIVERY_ACK: &str = "astral.delivery.ack";
pub const QUEUE_READ_RECEIPT: &str = "astral.read.receipt";
pub const QUEUE_QUESTION_COMMENT: &str = "astral.question.comment";
pub const QUEUE_QUESTION_SHARE: &str = "astral.question.share";

// ===== 通用常量 =====

/// 消息 TTL（24h）
pub const MESSAGE_TTL_MS: u32 = 86_400_000;

/// 最大重试次数
pub const MAX_RETRY: u32 = 3;

/// 重试消息头：当前重试次数
pub const HEADER_RETRY_COUNT: &str = "x-retry-count";

/// RabbitMQ adds this header when a message is dead-lettered. Raw replay must
/// not carry the broker's previous dead-letter history into a fresh delivery.
pub const HEADER_DEATH: &str = "x-death";

/// DLQ republish attempts are scoped to the old delivery path and must not be
/// carried into a raw replay.
pub const HEADER_DLQ_REPUBLISH_COUNT: &str = "x-dlq-republish-count";

/// Bound raw replay bodies before touching the channel. This is deliberately
/// independent from RabbitMQ's negotiated frame size.
pub const MAX_RAW_REPLAY_PAYLOAD_BYTES: usize = 1024 * 1024;

/// 队列定义（exchange_name 只能是 astral.direct / astral.topic）
pub struct QueueDef {
    pub name: &'static str,
    pub routing_key: &'static str,
    pub exchange_name: &'static str,
}

/// 12 个业务队列定义（对齐 Java MQConfig；`astral.permission.refresh` 已移除）
///
/// - 大部分队列绑定到 `astral.direct`
/// - `astral.notification` 和 `astral.business.chat` 绑定到 `astral.topic`
pub const QUEUES: &[QueueDef] = &[
    QueueDef {
        name: QUEUE_AUDIT_LOG,
        routing_key: "audit.log",
        exchange_name: EXCHANGE_DIRECT,
    },
    QueueDef {
        name: QUEUE_NOTIFICATION,
        routing_key: "notification.send",
        exchange_name: EXCHANGE_TOPIC,
    },
    QueueDef {
        name: QUEUE_LEARNING_PROGRESS,
        routing_key: "learning.progress",
        exchange_name: EXCHANGE_DIRECT,
    },
    QueueDef {
        name: QUEUE_LOGIN_EVENT,
        routing_key: "login.event",
        exchange_name: EXCHANGE_DIRECT,
    },
    QueueDef {
        name: QUEUE_SUBJECT_DELETE,
        routing_key: "subject.delete",
        exchange_name: EXCHANGE_DIRECT,
    },
    QueueDef {
        name: QUEUE_AUTH_SESSION_REVOCATION,
        routing_key: "auth.session.revocation",
        exchange_name: EXCHANGE_DIRECT,
    },
    QueueDef {
        name: QUEUE_CHAT_MESSAGE,
        routing_key: "chat.message",
        exchange_name: EXCHANGE_DIRECT,
    },
    QueueDef {
        name: QUEUE_BUSINESS_CHAT,
        routing_key: "business.chat.#",
        exchange_name: EXCHANGE_TOPIC,
    },
    QueueDef {
        name: QUEUE_DELIVERY_ACK,
        routing_key: "delivery.ack",
        exchange_name: EXCHANGE_DIRECT,
    },
    QueueDef {
        name: QUEUE_READ_RECEIPT,
        routing_key: "read.receipt",
        exchange_name: EXCHANGE_DIRECT,
    },
    QueueDef {
        name: QUEUE_QUESTION_COMMENT,
        routing_key: "question.comment",
        exchange_name: EXCHANGE_DIRECT,
    },
    QueueDef {
        name: QUEUE_QUESTION_SHARE,
        routing_key: "question.share",
        exchange_name: EXCHANGE_DIRECT,
    },
];

/// 推导 DLX routing key：`astral.dlx.<suffix>`
///
/// 例：`astral.audit.log` → `astral.dlx.audit.log`
pub fn dlx_routing_key(queue_name: &str) -> String {
    if let Some(suffix) = queue_name.strip_prefix("astral.") {
        format!("astral.dlx.{}", suffix)
    } else {
        format!("astral.dlx.{}", queue_name)
    }
}

/// 声明所有交换机、队列和绑定
/// 1. 声明 3 个交换机（astral.direct, astral.topic, astral.dlx）
/// 2. 对每个业务队列：
///    a. 声明业务队列（durable, DLX + per-queue routing key + TTL）
///    b. 绑定到对应交换机
///    c. 声明死信队列（durable, 无额外参数）
///    d. 死信队列绑定到 astral.dlx（routing key = 死信队列名）
pub async fn declare_all(channel: &Channel) -> Result<(), Box<dyn std::error::Error>> {
    // 1. 声明 3 个共享交换机
    for (name, kind) in [
        (EXCHANGE_DIRECT, ExchangeKind::Direct),
        (EXCHANGE_TOPIC, ExchangeKind::Topic),
        (EXCHANGE_DLX, ExchangeKind::Direct),
    ] {
        channel
            .exchange_declare(
                ShortString::from(name),
                kind,
                ExchangeDeclareOptions {
                    durable: true,
                    ..ExchangeDeclareOptions::default()
                },
                FieldTable::default(),
            )
            .await?;
        tracing::debug!(exchange = name, "declared exchange");
    }

    // 2. 对每个业务队列声明 + 绑定 + DLQ
    for q in QUEUES {
        let dlx_rk = dlx_routing_key(q.name);

        // 2a. 声明业务队列
        // 注意：FieldTable 字符串值必须使用 LongString（AMQP type tag 'S'），
        // 不能使用 ShortString（type tag 's'），否则 RabbitMQ 会关闭连接
        let mut args = FieldTable::default();
        args.insert(
            "x-dead-letter-exchange".into(),
            LongString::from(EXCHANGE_DLX).into(),
        );
        args.insert(
            "x-dead-letter-routing-key".into(),
            LongString::from(dlx_rk.as_str()).into(),
        );
        args.insert(
            "x-message-ttl".into(),
            lapin::types::LongUInt::from(MESSAGE_TTL_MS).into(),
        );

        channel
            .queue_declare(
                ShortString::from(q.name),
                QueueDeclareOptions {
                    durable: true,
                    ..QueueDeclareOptions::default()
                },
                args,
            )
            .await?;

        // 2b. 绑定到业务交换机
        channel
            .queue_bind(
                ShortString::from(q.name),
                ShortString::from(q.exchange_name),
                ShortString::from(q.routing_key),
                QueueBindOptions::default(),
                FieldTable::default(),
            )
            .await?;

        // 2c. 声明死信队列（名称 = DLX routing key）
        channel
            .queue_declare(
                ShortString::from(dlx_rk.as_str()),
                QueueDeclareOptions {
                    durable: true,
                    ..QueueDeclareOptions::default()
                },
                FieldTable::default(),
            )
            .await?;

        // 2d. 死信队列绑定到 astral.dlx（routing key = 死信队列名自身）
        channel
            .queue_bind(
                ShortString::from(dlx_rk.as_str()),
                ShortString::from(EXCHANGE_DLX),
                ShortString::from(dlx_rk.as_str()),
                QueueBindOptions::default(),
                FieldTable::default(),
            )
            .await?;

        tracing::info!(queue = q.name, dlq = %dlx_rk, "declared queue with DLX");
    }

    Ok(())
}
