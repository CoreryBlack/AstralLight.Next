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

pub mod config;
pub mod consumer;
pub mod consumers;
pub mod error;
pub mod producer;

pub use config::*;
pub use consumer::*;
pub use error::*;
pub use producer::*;
