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
pub const QUEUE_AUTHORIZATION_INVALIDATION: &str = "astral.authorization.invalidation";
pub const ROUTING_KEY_AUTHORIZATION_INVALIDATION: &str = "authorization.invalidation";
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

/// Return the declared queue definition for an exact or topic-compatible route.
pub fn route_for(queue_name: &str, routing_key: &str) -> Option<&'static QueueDef> {
    QUEUES.iter().find(|queue| {
        queue.name == queue_name
            && (queue.routing_key == routing_key
                || queue
                    .routing_key
                    .strip_suffix(".#")
                    .is_some_and(|prefix| routing_key.starts_with(prefix)))
    })
}

/// Resolve a route that exists only inside the composite-process LocalBus.
///
/// The authorization invalidation stream is intentionally excluded from the
/// Rabbit topology until durable cross-node fanout is implemented. Keeping its
/// route separate prevents a local-only queue from being declared remotely by
/// `declare_all` while still allowing LocalBus admission to validate it.
pub fn local_route_for(queue_name: &str, routing_key: &str) -> bool {
    queue_name == QUEUE_AUTHORIZATION_INVALIDATION
        && routing_key == ROUTING_KEY_AUTHORIZATION_INVALIDATION
}

// ===== 授权失效 fanout 拓扑（durable 跨节点订阅，默认关闭） =====
//
// 本节只声明拓扑接缝：fanout 交换机 + 每节点独立 durable 订阅队列 + 每节点
// 独立 DLX 死信队列。队列从不进入 [`QUEUES`]，也永远不会被 `declare_all`
// 或 `route_for` 发现，因此通用 producer 无法绕过 typed 路径把消息投进
// 本拓扑（保持 local-only 队列既有约束）。是否装配由 runtime 显式调用
// `declare_invalidation_fanout_topology` + invalidation_fanout 模块的
// spawn 入口决定，配置缺省（default-off）时不得触碰。

/// Durable fanout exchange for typed authorization invalidation frames.
pub const EXCHANGE_AUTHORIZATION_INVALIDATION_FANOUT: &str = "astral.auth.invalidation.fanout";

/// Prefix of every per-node durable subscription queue.
pub const INVALIDATION_FANOUT_QUEUE_PREFIX: &str = "astral.authorization.invalidation.node.";

/// Heartbeat frame message type carried on the fanout channel. The payload is
/// scope metadata only (sender identity + sent time), never authorization data.
pub const INVALIDATION_HEARTBEAT_MESSAGE_TYPE: &str = "INVALIDATION_HEARTBEAT";

/// Frozen transport identity of one node, derived from the legal
/// `region_id`/`node_id` pair validated by astral-common's config layer
/// (region <= 64 bytes, node <= 128 bytes). Under those legal bounds the
/// per-node queue (`39 + 64 + 1 + 128 = 232` bytes) and its DLX queue
/// (`43 + 193 = 236` bytes) stay within RabbitMQ's 255-byte queue-name
/// limit, so no extra combined bound is required.
///
/// Identity is immutable once constructed; every derived queue name is
/// deterministic so a restarted node re-subscribes to the same durable queue
/// instead of creating a competing subscription.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeIdentity {
    region: String,
    node: String,
}

impl NodeIdentity {
    /// Build a frozen identity from already-frozen config values.
    pub fn try_from_parts(
        region: impl Into<String>,
        node: impl Into<String>,
    ) -> Result<Self, String> {
        let region = region.into();
        let node = node.into();
        if region.is_empty() || region.len() > 64 {
            return Err("node identity region must be non-empty and at most 64 bytes".into());
        }
        if node.is_empty() || node.len() > 128 {
            return Err("node identity node must be non-empty and at most 128 bytes".into());
        }
        let legal = |value: &str| {
            value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-' || byte == b'_'
            })
        };
        if !legal(&region) {
            return Err("node identity region contains an illegal character".into());
        }
        if !legal(&node) {
            return Err("node identity node contains an illegal character".into());
        }
        Ok(Self { region, node })
    }

    pub fn region(&self) -> &str {
        &self.region
    }

    pub fn node(&self) -> &str {
        &self.node
    }
}

/// The node's own durable subscription queue. One queue per node; no shared
/// competing queue may ever swallow a notification for another node.
pub fn invalidation_fanout_queue_name(identity: &NodeIdentity) -> String {
    format!(
        "{}{}.{}",
        INVALIDATION_FANOUT_QUEUE_PREFIX, identity.region, identity.node
    )
}

/// The node's own dead-letter queue name, following the shared
/// `astral.dlx` convention so DLQ tooling recognizes the suffix.
pub fn invalidation_fanout_dlx_queue_name(identity: &NodeIdentity) -> String {
    dlx_routing_key(&invalidation_fanout_queue_name(identity))
}

/// Declare arguments for a per-node subscription queue: durable + per-queue
/// DLX routing + the standard 24h message TTL. Pure helper so topology tests
/// do not need a broker.
pub fn invalidation_fanout_queue_arguments(identity: &NodeIdentity) -> FieldTable {
    let queue_name = invalidation_fanout_queue_name(identity);
    let dlx_rk = dlx_routing_key(&queue_name);
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
    args
}

/// Declare the invalidation fanout topology for one node:
///
/// 1. the durable fanout exchange (shared, idempotent),
/// 2. this node's durable subscription queue bound to the exchange,
/// 3. this node's dead-letter queue bound to `astral.dlx`.
///
/// Everything is creator-guarded and safe to re-run on every reconnect.
pub async fn declare_invalidation_fanout_topology(
    channel: &Channel,
    identity: &NodeIdentity,
) -> Result<(), Box<dyn std::error::Error>> {
    channel
        .exchange_declare(
            ShortString::from(EXCHANGE_AUTHORIZATION_INVALIDATION_FANOUT),
            ExchangeKind::Fanout,
            ExchangeDeclareOptions {
                durable: true,
                ..ExchangeDeclareOptions::default()
            },
            FieldTable::default(),
        )
        .await?;

    let queue_name = invalidation_fanout_queue_name(identity);
    let args = invalidation_fanout_queue_arguments(identity);
    channel
        .queue_declare(
            ShortString::from(queue_name.as_str()),
            QueueDeclareOptions {
                durable: true,
                ..QueueDeclareOptions::default()
            },
            args,
        )
        .await?;
    channel
        .queue_bind(
            ShortString::from(queue_name.as_str()),
            ShortString::from(EXCHANGE_AUTHORIZATION_INVALIDATION_FANOUT),
            ShortString::from(""),
            QueueBindOptions::default(),
            FieldTable::default(),
        )
        .await?;

    let dlx_rk = dlx_routing_key(&queue_name);
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
    channel
        .queue_bind(
            ShortString::from(dlx_rk.as_str()),
            ShortString::from(EXCHANGE_DLX),
            ShortString::from(dlx_rk.as_str()),
            QueueBindOptions::default(),
            FieldTable::default(),
        )
        .await?;

    tracing::info!(
        exchange = EXCHANGE_AUTHORIZATION_INVALIDATION_FANOUT,
        queue = %queue_name,
        dlq = %dlx_rk,
        region = identity.region(),
        node = identity.node(),
        "declared invalidation fanout topology"
    );
    Ok(())
}

#[cfg(test)]
mod local_route_tests {
    use super::*;

    #[test]
    fn authorization_invalidation_route_is_local_only() {
        assert!(local_route_for(
            QUEUE_AUTHORIZATION_INVALIDATION,
            ROUTING_KEY_AUTHORIZATION_INVALIDATION
        ));
        assert!(!local_route_for(
            QUEUE_AUTHORIZATION_INVALIDATION,
            "audit.log"
        ));
        assert!(route_for(
            QUEUE_AUTHORIZATION_INVALIDATION,
            ROUTING_KEY_AUTHORIZATION_INVALIDATION
        )
        .is_none());
        assert!(queue_for_routing_key(ROUTING_KEY_AUTHORIZATION_INVALIDATION).is_none());
        assert!(!QUEUES
            .iter()
            .any(|queue| queue.name == QUEUE_AUTHORIZATION_INVALIDATION));
    }
}

/// Resolve a routing key to its unique declared queue.
pub fn queue_for_routing_key(routing_key: &str) -> Option<&'static QueueDef> {
    QUEUES.iter().find(|queue| {
        queue.routing_key == routing_key
            || queue
                .routing_key
                .strip_suffix(".#")
                .is_some_and(|prefix| routing_key.starts_with(prefix))
    })
}

#[cfg(test)]
mod invalidation_fanout_topology_tests {
    use super::*;
    use lapin::types::AMQPValue;

    fn identity() -> NodeIdentity {
        NodeIdentity::try_from_parts("city-a", "node-1").unwrap()
    }

    #[test]
    fn node_identity_is_frozen_and_validated() {
        let identity = identity();
        assert_eq!(identity.region(), "city-a");
        assert_eq!(identity.node(), "node-1");

        assert!(NodeIdentity::try_from_parts("", "node-1").is_err());
        assert!(NodeIdentity::try_from_parts("city-a", "").is_err());
        assert!(NodeIdentity::try_from_parts("r".repeat(65), "node-1").is_err());
        assert!(NodeIdentity::try_from_parts("city-a", "n".repeat(129)).is_err());
        assert!(NodeIdentity::try_from_parts("city a", "node-1").is_err());
        assert!(NodeIdentity::try_from_parts("city-a", "节点").is_err());

        let long_region = "r".repeat(64);
        let long_node = "n".repeat(128);
        assert!(NodeIdentity::try_from_parts(long_region, long_node).is_ok());
        let overbound_region = "r".repeat(65);
        let overbound_node = "n".repeat(128);
        assert!(NodeIdentity::try_from_parts(overbound_region, overbound_node).is_err());
    }

    #[test]
    fn per_node_queue_names_are_deterministic_and_distinct() {
        let first = identity();
        let second = NodeIdentity::try_from_parts("city-b", "node-1").unwrap();
        let first_queue = invalidation_fanout_queue_name(&first);
        let second_queue = invalidation_fanout_queue_name(&second);
        assert_eq!(
            first_queue,
            "astral.authorization.invalidation.node.city-a.node-1"
        );
        assert_eq!(
            invalidation_fanout_queue_name(&first),
            first_queue,
            "naming must be deterministic so a restart re-subscribes"
        );
        assert_ne!(first_queue, second_queue);
        assert!(first_queue.len() < 255);
        assert!(invalidation_fanout_dlx_queue_name(&first).len() < 255);
        assert_eq!(
            invalidation_fanout_dlx_queue_name(&first),
            "astral.dlx.authorization.invalidation.node.city-a.node-1"
        );
    }

    #[test]
    fn fanout_topology_stays_outside_generic_routes_and_declare_all() {
        let identity = identity();
        let queue = invalidation_fanout_queue_name(&identity);
        assert!(!QUEUES.iter().any(|def| def.name == queue));
        assert!(route_for(&queue, "").is_none());
        assert!(queue_for_routing_key(&queue).is_none());
        assert!(!local_route_for(&queue, ""));
        // The generic typed producer must not be able to address the fanout
        // queue either: only the fanout exchange routes to it.
        assert_ne!(queue, QUEUE_AUTHORIZATION_INVALIDATION);
    }

    #[test]
    fn queue_arguments_declare_dlx_and_ttl() {
        let args = invalidation_fanout_queue_arguments(&identity());
        let dlx = args
            .inner()
            .get("x-dead-letter-exchange")
            .and_then(AMQPValue::as_long_string)
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned());
        assert_eq!(dlx.as_deref(), Some(EXCHANGE_DLX));
        let dlx_rk = args
            .inner()
            .get("x-dead-letter-routing-key")
            .and_then(AMQPValue::as_long_string)
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned());
        assert_eq!(
            dlx_rk.as_deref(),
            Some(invalidation_fanout_dlx_queue_name(&identity()).as_str())
        );
        let ttl = args
            .inner()
            .get("x-message-ttl")
            .and_then(AMQPValue::as_long_uint);
        assert_eq!(ttl, Some(MESSAGE_TTL_MS));
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
