//! 消息副作用端口 — MessageSideEffects
//!
//! send 管线的非关键副作用（MQ 广播 + WebSocket 推送）经该 trait 注入：
//! 生产实现走 RabbitMQ + ConnectionPool，测试注入 no-op 记录器。
//! 与 TrustGraph `PermissionSideEffects` 同一模式。

use std::sync::Arc;
use std::sync::OnceLock;

use async_trait::async_trait;

use astral_mq::producer::{ChatMessagePayload, Producer};

use crate::scope::ChatScope;
use crate::srv::realtime::ConnectionPool;

/// 消息写路径副作用端口（MQ 广播 + WS 推送）
#[async_trait]
pub trait MessageSideEffects: Send + Sync {
    /// MQ 广播（send 非关键路径：生产实现失败仅告警）
    async fn publish_chat_message(&self, payload: ChatMessagePayload);
    /// WS 推送到同一物理卡作用域的在线连接。
    async fn push_to_scope(&self, scope: &ChatScope, message: &str);
}

/// 生产实现：MQ（OnceLock<Producer>，可能未就绪）+ ConnectionPool
pub struct ChatMessageSideEffects {
    mq_producer: Arc<OnceLock<Producer>>,
    connections: Arc<ConnectionPool>,
}

impl ChatMessageSideEffects {
    pub fn new(mq_producer: Arc<OnceLock<Producer>>, connections: Arc<ConnectionPool>) -> Self {
        Self {
            mq_producer,
            connections,
        }
    }
}

#[async_trait]
impl MessageSideEffects for ChatMessageSideEffects {
    async fn publish_chat_message(&self, payload: ChatMessagePayload) {
        if let Some(producer) = self.mq_producer.get() {
            if let Err(e) = producer.publish_chat_message(payload).await {
                tracing::warn!(error = %e, "MQ broadcast failed (non-critical)");
            }
        }
    }

    async fn push_to_scope(&self, scope: &ChatScope, message: &str) {
        self.connections.send_to_scope(scope, message).await;
    }
}
