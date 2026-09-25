//! 审计双写服务 — MQ 主路径 + DB 降级双写
//!
//! 对齐 Java `AuditService.sendViaMQ()` + `fallbackInsert()` 模式。
//!
//! Java 基线对照：
//! - sendViaMQ(): AstralGeneral/.../service/AuditService.java:124-137
//!   try MQ → 失败降级 DB
//! - fallbackInsert(): AuditService.java:139-158
//!   AuthAuditLogMapper.insert() 直接写入
//! - record(): AuditService.java:35-57
//!   构建 AuditLogMessage + sendViaMQ(message, "permission")
//! - recordLogin(): AuditService.java:59-72
//!   sendViaMQ(message, "identity-login")
//! - recordIdentityEvent(): AuditService.java:74-88
//!   sendViaMQ(message, "identity-event")
//! - recordCardSwitch(): AuditService.java:90-103
//!   sendViaMQ(message, "card-switch")
//! - recordDataScopeDenied(): AuditService.java:105-122
//!   sendViaMQ(message, "data-scope")

use astral_common::audit::{record_audit, AuditCategory, AuditEntry, AuditEventType};
use astral_db;
use astral_mq::producer::{self, Producer};
use sqlx::MySqlPool;

/// 审计双写服务
///
/// 实现 MQ 主路径 + DB 降级的双写模式。
/// MQ 发送成功则返回；MQ 发送失败则降级为 DB 直接写入；
/// 同时始终写入 tracing 结构化日志作为三级兜底。
///
/// # Java 基线对照
/// - `send_via_mq()`: AuditService.java:124-137
/// - `fallback_insert()`: AuditService.java:139-158
pub struct AuditDualWriteService {
    producer: Producer,
    pool: MySqlPool,
}

impl AuditDualWriteService {
    /// 创建审计双写服务
    pub fn new(producer: Producer, pool: MySqlPool) -> Self {
        Self { producer, pool }
    }

    /// 记录权限检查审计（对齐 Java `AuditService.record(PolicyContext, PolicyDecision)`）
    ///
    /// Java 对照：AuditService.java:35-57 — sendViaMQ(message, "permission")
    #[allow(clippy::too_many_arguments)]
    pub async fn record_permission_check(
        &self,
        user_id: Option<i64>,
        card_id: Option<i64>,
        domain_id: Option<i64>,
        resource: &str,
        action: &str,
        allowed: bool,
        reason: Option<&str>,
        source_ip: Option<&str>,
        detail: Option<&str>,
    ) {
        let entry = AuditEntry {
            user_id,
            card_id,
            action: action.to_string(),
            resource: resource.to_string(),
            decision: if allowed {
                "ALLOW".into()
            } else {
                "DENY".into()
            },
            reason: reason.map(|s| s.to_string()),
            event_type: AuditEventType::PermissionCheck,
            category: Some(AuditCategory::Permission),
            source_ip: source_ip.map(|s| s.to_string()),
            request_id: None,
            domain_id,
            tenant_id: None,
            detail: detail.map(|s| s.to_string()),
        };

        self.send_via_mq(entry, AuditCategory::Permission).await;
    }

    /// 记录登录事件（对齐 Java `AuditService.recordLogin()`）
    ///
    /// Java 对照：AuditService.java:59-72 — sendViaMQ(message, "identity-login")
    pub async fn record_login(
        &self,
        user_id: i64,
        success: bool,
        source_ip: Option<&str>,
        detail: Option<&str>,
    ) {
        let event_type = if success {
            AuditEventType::LoginSuccess
        } else {
            AuditEventType::LoginFailure
        };

        let entry = AuditEntry {
            user_id: Some(user_id),
            card_id: None,
            action: "login".into(),
            resource: "identity".into(),
            decision: if success {
                "ALLOW".into()
            } else {
                "DENY".into()
            },
            reason: None,
            event_type,
            category: Some(AuditCategory::IdentityLogin),
            source_ip: source_ip.map(|s| s.to_string()),
            request_id: None,
            domain_id: None,
            tenant_id: None,
            detail: detail.map(|s| s.to_string()),
        };

        self.send_via_mq(entry, AuditCategory::IdentityLogin).await;
    }

    /// 记录身份事件（对齐 Java `AuditService.recordIdentityEvent()`）
    ///
    /// Java 对照：AuditService.java:74-88 — sendViaMQ(message, "identity-event")
    pub async fn record_identity_event(
        &self,
        user_id: i64,
        event_type: AuditEventType,
        source_ip: Option<&str>,
        detail: Option<&str>,
    ) {
        let entry = AuditEntry {
            user_id: Some(user_id),
            card_id: None,
            action: "identity".into(),
            resource: "identity".into(),
            decision: "ALLOW".into(),
            reason: None,
            event_type,
            category: Some(AuditCategory::IdentityEvent),
            source_ip: source_ip.map(|s| s.to_string()),
            request_id: None,
            domain_id: None,
            tenant_id: None,
            detail: detail.map(|s| s.to_string()),
        };

        self.send_via_mq(entry, AuditCategory::IdentityEvent).await;
    }

    /// 记录卡片切换（对齐 Java `AuditService.recordCardSwitch()`）
    ///
    /// Java 对照：AuditService.java:90-103 — sendViaMQ(message, "card-switch")
    pub async fn record_card_switch(
        &self,
        user_id: i64,
        from_card_id: i64,
        to_card_id: i64,
        source_ip: Option<&str>,
    ) {
        let entry = AuditEntry {
            user_id: Some(user_id),
            card_id: Some(to_card_id),
            action: "switch".into(),
            resource: "user_card".into(),
            decision: "ALLOW".into(),
            reason: None,
            event_type: AuditEventType::CardSwitch,
            category: Some(AuditCategory::CardSwitch),
            source_ip: source_ip.map(|s| s.to_string()),
            request_id: None,
            domain_id: None,
            tenant_id: None,
            detail: Some(format!(
                "fromCardId={},toCardId={}",
                from_card_id, to_card_id
            )),
        };

        self.send_via_mq(entry, AuditCategory::CardSwitch).await;
    }

    /// 记录数据范围拒绝（对齐 Java `AuditService.recordDataScopeDenied()`）
    ///
    /// Java 对照：AuditService.java:105-122 — sendViaMQ(message, "data-scope")
    pub async fn record_data_scope_denied(
        &self,
        user_id: Option<i64>,
        card_id: Option<i64>,
        domain_id: Option<i64>,
        table_name: &str,
        column_name: &str,
        scope_type: &str,
    ) {
        let entry = AuditEntry {
            user_id,
            card_id,
            action: "data-scope".into(),
            resource: table_name.to_string(),
            decision: "DENY".into(),
            reason: Some(format!("{}_scope_missing", scope_type)),
            event_type: AuditEventType::DataScopeDeny,
            category: Some(AuditCategory::DataScope),
            source_ip: None,
            request_id: None,
            domain_id,
            tenant_id: None,
            detail: Some(format!("column={},scopeType={}", column_name, scope_type)),
        };

        self.send_via_mq(entry, AuditCategory::DataScope).await;
    }

    /// MQ 主路径 + DB 降级双写（核心方法）
    ///
    /// 对齐 Java `AuditService.sendViaMQ()` (AuditService.java:124-137)：
    /// 1. 尝试 MQ 发送 → 成功则返回
    /// 2. MQ 失败 → 降级为 DB 直接写入 (fallbackInsert: AuditService.java:139-158)
    /// 3. 无论如何都写入 tracing 结构化日志 (record_audit 兜底)
    async fn send_via_mq(&self, entry: AuditEntry, category: AuditCategory) {
        let event_type_str = serde_json::to_value(&entry.event_type)
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();

        // Step 1: MQ 主路径（对齐 Java AuditService.java:127-130）
        // message_id 必须唯一：audit consumer 以它为 mq_idempotent_log 幂等键，
        // 恒 None 会回退到 (user,event,action,resource,request) 派生键——permission
        // 审计的 request_id 恒 None，相同 user+resource+action 的重复判定会被
        // INSERT IGNORE 丢弃，丢失真实审计行。这里生成 UUID 保证每条唯一。
        let payload = producer::AuditLogPayload {
            message_id: Some(uuid::Uuid::new_v4().to_string()),
            user_id: entry.user_id,
            card_id: entry.card_id,
            action: entry.action.clone(),
            resource: entry.resource.clone(),
            decision: entry.decision.clone(),
            reason: entry.reason.clone(),
            event_type: event_type_str.clone(),
            source_ip: entry.source_ip.clone(),
            request_id: entry.request_id.clone(),
            domain_id: entry.domain_id,
            tenant_id: entry.tenant_id,
            // producer detail（例如 data-scope 明细）随消息透传；与 DB fallback
            // 一致保留 entry.detail，consumer 仅在非空白时落库。
            detail: entry.detail.clone(),
        };

        match self.producer.publish_audit_log(payload).await {
            Ok(()) => {
                tracing::debug!(
                    category = ?category,
                    event_type = %event_type_str,
                    "audit log sent via MQ"
                );
                // MQ 成功，仍写入 tracing 作为备份
                record_audit(entry);
                return;
            }
            Err(e) => {
                tracing::warn!(
                    category = ?category,
                    event_type = %event_type_str,
                    error = %e,
                    "MQ send failed, falling back to DB direct insert"
                );
            }
        }

        // Step 2: DB 降级路径（对齐 Java AuditService.java:139-158 fallbackInsert）
        match astral_db::insert_audit_log(&self.pool, &entry).await {
            Ok(()) => {
                tracing::info!(
                    category = ?category,
                    event_type = %event_type_str,
                    "audit log written to DB (fallback path)"
                );
            }
            Err(e) => {
                tracing::error!(
                    category = ?category,
                    event_type = %event_type_str,
                    error = %e,
                    "audit log DB fallback insert failed"
                );
            }
        }

        // Step 3: 无论如何都写入 tracing 结构化日志（三级兜底）
        record_audit(entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_type_serde() {
        // 验证事件类型序列化与 Java 对齐（权限检查 = AUTHZ_CHECK）
        let event = AuditEventType::PermissionCheck;
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json.as_str().unwrap(), "AUTHZ_CHECK");

        let event = AuditEventType::LoginSuccess;
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json.as_str().unwrap(), "LOGIN_SUCCESS");

        let event = AuditEventType::DataScopeDeny;
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json.as_str().unwrap(), "DATA_SCOPE_DENY");

        let event = AuditEventType::IdentityUnbind;
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json.as_str().unwrap(), "IDENTITY_UNBIND");
    }

    #[test]
    fn test_audit_category_serde() {
        let cat = AuditCategory::Permission;
        let json = serde_json::to_value(&cat).unwrap();
        assert_eq!(json.as_str().unwrap(), "permission");

        let cat = AuditCategory::IdentityLogin;
        let json = serde_json::to_value(&cat).unwrap();
        assert_eq!(json.as_str().unwrap(), "identity-login");
    }
}
