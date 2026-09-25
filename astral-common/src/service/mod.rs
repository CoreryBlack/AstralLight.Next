//! Common audit/MQ service contracts.
//!
//! Permission rule writes are owned by TrustGraph's canonical write services;
//! this module only retains the cross-crate audit producer bridge.

use std::sync::Arc;

/// `AuditLogEvent.detail`（含 MQ wire 层 `AuditLogPayload.detail`）允许的最大
/// 序列化字节数（UTF-8 字节）。
///
/// 这是全部 audit detail producer 与重放/消费侧共享的稳定传输合同：producer
/// 必须保证最终序列化后的 `detail` 不超过该上界（例如 TrustGraph ORG
/// provenance 结构化 detail 的有界化 formatter），重放/校验侧（如 TrustGraph
/// `audit_replay_worker`）会把超过该上界的可选审计字段以
/// `audit_optional_field_invalid` 拒绝，超界 detail 的隔离消息将永久不可
/// 重放。producer 与 replayer 必须引用本常量，不得在各自 crate 复制数值，
/// 否则两侧上界一旦漂移，超界 detail 会在重放校验时被永久拒绝。重放校验
/// 通常还把该同值上界统一应用于其余审计字符串字段（必填与可选）作为纵深
/// 防御，但合同义务针对可选 `detail` 字段。
pub const AUDIT_DETAIL_MAX_BYTES: usize = 1024;

/// 审计消息值对象。
///
/// `astral-common` 仅保存跨模块审计字段，具体 MQ producer 负责将它映射为
/// 传输层 DTO，避免 common 层反向依赖 `astral-mq`。
#[derive(Debug, Clone)]
pub struct AuditLogEvent {
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
    /// provenance detail），序列化后不得超过 [`AUDIT_DETAIL_MAX_BYTES`] 字节。
    /// `None` 时 MQ consumer 回退既有 messageId 关联文本，
    /// 保持旧事件 wire/落库行为不变。
    pub detail: Option<String>,
}

/// MQ Producer 抽象 trait（避免 astral-common 直接依赖 astral-mq）
///
/// 实现此 trait 的类型可注册为全局 Producer，供 audit 双写使用。
#[async_trait::async_trait]
pub trait MqProducerRef: Send + Sync {
    /// 发布审计日志消息
    async fn publish_audit_log(&self, event: AuditLogEvent) -> Result<(), String>;
    /// 发布登录事件（对齐 Java loginEventProducer → astral.login.event）
    async fn publish_login_event(
        &self,
        user_id: i64,
        login_type: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        success: bool,
    ) -> Result<(), String>;
}

/// 全局 MQ Producer 存储
static GLOBAL_MQ_PRODUCER: std::sync::OnceLock<Arc<dyn MqProducerRef>> = std::sync::OnceLock::new();

/// 注册全局 MQ Producer
pub fn register_mq_producer(producer: Arc<dyn MqProducerRef>) {
    let _ = GLOBAL_MQ_PRODUCER.set(producer);
}

/// 获取全局 MQ Producer（供 audit.rs 使用）
pub fn global_mq_producer() -> Option<Arc<dyn MqProducerRef>> {
    GLOBAL_MQ_PRODUCER.get().cloned()
}

#[cfg(test)]
mod tests {
    use super::AUDIT_DETAIL_MAX_BYTES;

    #[test]
    fn audit_detail_max_bytes_is_the_frozen_wire_contract() {
        // 冻结的跨 crate 传输合同值：producer 有界化与重放校验必须共享同一
        // 上界；修改本值属于破坏性合同变更，必须同步评估在途隔离消息的
        // 可重放性与旧事件 wire/落库行为。
        assert_eq!(AUDIT_DETAIL_MAX_BYTES, 1024);
    }
}
