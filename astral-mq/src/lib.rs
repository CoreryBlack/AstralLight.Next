//! AstralLight 消息队列层
//!
//! 基于 lapin (RabbitMQ) 的消息队列基础设施。覆盖 13 个业务队列，
//! 全部绑定 DLX 死信队列，TTL = 86400000ms（24h）。
//!
//! # 模块
//!
//! - `config` — 交换机/队列/绑定声明（与 Java Spring AMQP 配置对齐）
//! - `producer` — 通用消息发送器
//! - `consumer` — 消费者基类 + DLX 重试逻辑
//! - `invalidation_fanout` / `invalidation_fanout_worker` — 授权失效
//!   跨节点 durable fanout 传输（typed frame、typed publish outcome、
//!   per-node durable inbox proof adapter、bounded relay/inbox worker；
//!   default-off，需显式装配）

pub mod config;
pub mod consumer;
pub mod consumers;
pub mod envelope;
pub mod error;
pub mod invalidation;
pub mod invalidation_fanout;
pub mod invalidation_fanout_worker;
pub mod local_bus;
pub mod producer;

pub use config::*;
pub use consumer::*;
pub use envelope::*;
pub use error::*;
pub use invalidation::*;
pub use invalidation_fanout::{
    classify_confirmation, classify_transport_error, CommittedInvalidationEnvelope, FanoutDelivery,
    FanoutDeliverySettlement, FanoutDeliverySource, FanoutFrame, HeartbeatScope,
    InboxCommitOutcome, InboxMarkApplied, InvalidationApply, InvalidationFanoutContractError,
    InvalidationFanoutListener, InvalidationFanoutPublishOutcome, InvalidationFanoutTransport,
    InvalidationInboxAdapter, InvalidationInboxFailure, InvalidationInboxRecord,
    LapinFanoutPublisher, LapinInboxSession, MySqlInvalidationInbox, NoopListener, ScopeGapReport,
    ScopeWatermarkTracker, WatermarkAdvance, INBOX_STORAGE_ERROR_TAG,
};
pub use invalidation_fanout_worker::{
    spawn_invalidation_fanout_inbox_worker, spawn_invalidation_fanout_relay, Backoff,
    BackoffConfig, InvalidationFanoutRelayHandle, InvalidationFanoutRelaySettings,
    InvalidationFanoutSource, InvalidationInboxWorkerHandle, InvalidationInboxWorkerSettings,
    LocalMessageOutboxSource,
};
pub use local_bus::*;
pub use producer::*;
