//! 消息数据访问 — MessageRepository
//!
//! 对齐 Java `ChatMessageMapper` 边界（chat_message + chat_message_delivery 表）。
//! 会话最后消息更新在 `ConversationRepository::update_last_message`；
//! 投递记录批量写入由 service 编排（非关键路径，逐条容错）。

use async_trait::async_trait;
use sqlx::MySqlPool;

use crate::scope::ChatScope;
use astral_types::AstralError;

/// 消息行（platform_v4: message_id UUID 生成；conversation_id → conversation_id）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MessageRecord {
    pub id: i64,
    pub sender_id: i64,
    pub conversation_id: i64,
    pub content: String,
    pub message_type: String,
    pub created_at: Option<time::PrimitiveDateTime>,
}

#[async_trait]
pub trait MessageRepository: Send + Sync {
    async fn insert_message_scoped(
        &self,
        scope: &ChatScope,
        _conversation_id: i64,
        _sender_id: i64,
        _message_type: &str,
        _content: &str,
    ) -> Result<i64, AstralError> {
        let _ = scope;
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }

    async fn get_message_scoped(
        &self,
        scope: &ChatScope,
        id: i64,
    ) -> Result<Option<MessageRecord>, AstralError> {
        let _ = (scope, id);
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }

    async fn count_by_session_scoped(
        &self,
        scope: &ChatScope,
        conversation_id: i64,
    ) -> Result<i64, AstralError> {
        let _ = (scope, conversation_id);
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }

    async fn list_by_session_scoped(
        &self,
        scope: &ChatScope,
        conversation_id: i64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<MessageRecord>, AstralError> {
        let _ = (scope, conversation_id, limit, offset);
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }

    async fn count_unread_scoped(
        &self,
        scope: &ChatScope,
        conversation_id: i64,
        last_read_message_id: i64,
    ) -> Result<i64, AstralError> {
        let _ = (scope, conversation_id, last_read_message_id);
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }

    /// 插入消息（message_id 由 UUID() 生成），返回自增 id
    async fn insert_message(
        &self,
        _conversation_id: i64,
        _sender_id: i64,
        _message_type: &str,
        _content: &str,
    ) -> Result<i64, AstralError>;
    /// 单条消息
    async fn get_message(&self, id: i64) -> Result<Option<MessageRecord>, AstralError>;
    /// 消息发送者（delete_message 前校验）
    async fn get_sender_id(&self, id: i64) -> Result<Option<i64>, AstralError>;
    /// 会话消息总数
    async fn count_by_session(&self, conversation_id: i64) -> Result<i64, AstralError>;
    /// 会话消息分页（id DESC）
    async fn list_by_session(
        &self,
        conversation_id: i64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<MessageRecord>, AstralError>;
    /// 软撤回消息（仅 SENT 状态可撤回，对齐 recall 语义）
    async fn recall_message(&self, id: i64) -> Result<(), AstralError>;
    /// 在当前物理双卡作用域内软撤回消息。
    async fn recall_message_scoped(&self, scope: &ChatScope, id: i64) -> Result<(), AstralError> {
        let _ = (scope, id);
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }
    /// 未读数（id > last_read）
    async fn count_unread(
        &self,
        conversation_id: i64,
        last_read_message_id: i64,
    ) -> Result<i64, AstralError>;
    /// 创建单条投递记录（send 非关键路径，失败仅告警）
    async fn insert_delivery(&self, message_id: i64, recipient_id: i64) -> Result<(), AstralError>;
}

pub struct SqlxMessageRepository {
    db: MySqlPool,
}

impl SqlxMessageRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

const MESSAGE_SELECT: &str =
    "SELECT msg.id, msg.sender_id, msg.conversation_id AS conversation_id, msg.content, \
     msg.message_type AS message_type, msg.created_at FROM chat_message msg";

#[async_trait]
impl MessageRepository for SqlxMessageRepository {
    async fn insert_message_scoped(
        &self,
        scope: &ChatScope,
        conversation_id: i64,
        sender_id: i64,
        message_type: &str,
        content: &str,
    ) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO chat_message (message_id, conversation_id, sender_id, message_type, content, domain_id) \
             SELECT UUID(), ?, ?, ?, ?, c.domain_id \
             FROM chat_conversation c \
             INNER JOIN platform_user pu ON pu.user_id = ? AND pu.status = 'ACTIVE' AND pu.deleted_at IS NULL \
             INNER JOIN identity_card ic ON ic.user_id = pu.user_id AND ic.card_id = ? AND ic.status = 'ACTIVE' \
               AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()) \
             INNER JOIN user_card uc ON uc.user_id = pu.user_id AND uc.card_id = ? AND uc.card_status = 'ACTIVE' \
               AND uc.tenant_id = ? AND uc.domain_id = c.domain_id \
               AND (uc.valid_from IS NULL OR uc.valid_from <= UTC_TIMESTAMP()) \
               AND (uc.valid_until IS NULL OR uc.valid_until >= UTC_TIMESTAMP()) \
             INNER JOIN tenant t ON t.tenant_id = uc.tenant_id AND t.status = 'ACTIVE' \
             INNER JOIN tenant_domain_map tdm ON tdm.tenant_id = uc.tenant_id AND tdm.domain_id = uc.domain_id AND tdm.status = 'ACTIVE' \
             INNER JOIN chat_conversation_member m ON m.conversation_id = c.id AND m.user_id = pu.user_id AND m.left_at IS NULL \
             WHERE c.id = ? AND c.domain_id = ? AND c.status = 'ACTIVE' AND c.is_deleted = 0",
        )
        .bind(conversation_id)
        .bind(sender_id)
        .bind(message_type)
        .bind(content)
        .bind(sender_id)
        .bind(scope.identity_card_id)
        .bind(scope.user_card_id)
        .bind(scope.user_card_tenant_id)
        .bind(conversation_id)
        .bind(scope.user_card_domain_id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        if result.rows_affected() != 1 {
            return Err(AstralError::Permission(
                "physical chat scope required".into(),
            ));
        }
        Ok(result.last_insert_id() as i64)
    }

    async fn get_message_scoped(
        &self,
        scope: &ChatScope,
        id: i64,
    ) -> Result<Option<MessageRecord>, AstralError> {
        sqlx::query_as::<_, MessageRecord>(&format!(
            "{MESSAGE_SELECT} INNER JOIN chat_conversation c ON c.id = msg.conversation_id \\
                 INNER JOIN chat_conversation_member m ON m.conversation_id = c.id \\
                 WHERE msg.id = ? AND msg.domain_id = ? AND c.domain_id = ? \\
                   AND c.status = 'ACTIVE' AND c.is_deleted = 0 \\
                   AND m.user_id = ? AND m.left_at IS NULL \
                   AND EXISTS (SELECT 1 FROM platform_user pu \
                               INNER JOIN identity_card ic ON ic.user_id = pu.user_id AND ic.card_id = ? \
                               INNER JOIN user_card uc ON uc.user_id = pu.user_id AND uc.card_id = ? \
                               INNER JOIN tenant t ON t.tenant_id = uc.tenant_id AND t.status = 'ACTIVE' \
                               INNER JOIN tenant_domain_map tdm ON tdm.tenant_id = uc.tenant_id \
                                 AND tdm.domain_id = uc.domain_id AND tdm.status = 'ACTIVE' \
                               WHERE pu.user_id = ? AND pu.status = 'ACTIVE' AND pu.deleted_at IS NULL \
                                 AND ic.status = 'ACTIVE' AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()) \
                                 AND uc.card_status = 'ACTIVE' AND uc.tenant_id = ? AND uc.domain_id = c.domain_id \
                                 AND (uc.valid_from IS NULL OR uc.valid_from <= UTC_TIMESTAMP()) \
                                 AND (uc.valid_until IS NULL OR uc.valid_until >= UTC_TIMESTAMP()))"
        ))
        .bind(id)
        .bind(scope.user_card_domain_id)
        .bind(scope.user_card_domain_id)
        .bind(scope.user_id)
        .bind(scope.identity_card_id)
        .bind(scope.user_card_id)
        .bind(scope.user_id)
        .bind(scope.user_card_tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn count_by_session_scoped(
        &self,
        scope: &ChatScope,
        conversation_id: i64,
    ) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM chat_message msg INNER JOIN chat_conversation c ON c.id = msg.conversation_id \\
             WHERE msg.conversation_id = ? AND msg.domain_id = ? AND c.domain_id = ? \\
               AND c.status = 'ACTIVE' AND c.is_deleted = 0 \
               AND EXISTS (SELECT 1 FROM platform_user pu \
                           INNER JOIN identity_card ic ON ic.user_id = pu.user_id AND ic.card_id = ? \
                           INNER JOIN user_card uc ON uc.user_id = pu.user_id AND uc.card_id = ? \
                           INNER JOIN tenant t ON t.tenant_id = uc.tenant_id AND t.status = 'ACTIVE' \
                           INNER JOIN tenant_domain_map tdm ON tdm.tenant_id = uc.tenant_id AND tdm.domain_id = uc.domain_id AND tdm.status = 'ACTIVE' \
                           WHERE pu.user_id = ? AND pu.status = 'ACTIVE' AND pu.deleted_at IS NULL \
                             AND ic.status = 'ACTIVE' AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()) \
                             AND uc.card_status = 'ACTIVE' AND uc.tenant_id = ? AND uc.domain_id = c.domain_id \
                             AND (uc.valid_from IS NULL OR uc.valid_from <= UTC_TIMESTAMP()) \
                             AND (uc.valid_until IS NULL OR uc.valid_until >= UTC_TIMESTAMP()))",
        )
        .bind(conversation_id)
        .bind(scope.user_card_domain_id)
        .bind(scope.user_card_domain_id)
        .bind(scope.identity_card_id)
        .bind(scope.user_card_id)
        .bind(scope.user_id)
        .bind(scope.user_card_tenant_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)
    }

    async fn list_by_session_scoped(
        &self,
        scope: &ChatScope,
        conversation_id: i64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<MessageRecord>, AstralError> {
        sqlx::query_as::<_, MessageRecord>(&format!(
            "{MESSAGE_SELECT} INNER JOIN chat_conversation c ON c.id = msg.conversation_id \\
             WHERE msg.conversation_id = ? AND msg.domain_id = ? AND c.domain_id = ? \\
               AND c.status = 'ACTIVE' AND c.is_deleted = 0 \
               AND EXISTS (SELECT 1 FROM platform_user pu \
                           INNER JOIN identity_card ic ON ic.user_id = pu.user_id AND ic.card_id = ? \
                           INNER JOIN user_card uc ON uc.user_id = pu.user_id AND uc.card_id = ? \
                           INNER JOIN tenant t ON t.tenant_id = uc.tenant_id AND t.status = 'ACTIVE' \
                           INNER JOIN tenant_domain_map tdm ON tdm.tenant_id = uc.tenant_id AND tdm.domain_id = uc.domain_id AND tdm.status = 'ACTIVE' \
                           WHERE pu.user_id = ? AND pu.status = 'ACTIVE' AND pu.deleted_at IS NULL \
                             AND ic.status = 'ACTIVE' AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()) \
                             AND uc.card_status = 'ACTIVE' AND uc.tenant_id = ? AND uc.domain_id = c.domain_id \
                             AND (uc.valid_from IS NULL OR uc.valid_from <= UTC_TIMESTAMP()) \
                             AND (uc.valid_until IS NULL OR uc.valid_until >= UTC_TIMESTAMP()) ) ORDER BY msg.id DESC LIMIT ? OFFSET ?",
        ))
        .bind(conversation_id)
        .bind(scope.user_card_domain_id)
        .bind(scope.user_card_domain_id)
        .bind(scope.identity_card_id)
        .bind(scope.user_card_id)
        .bind(scope.user_id)
        .bind(scope.user_card_tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn count_unread_scoped(
        &self,
        scope: &ChatScope,
        conversation_id: i64,
        last_read_message_id: i64,
    ) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM chat_message msg INNER JOIN chat_conversation c ON c.id = msg.conversation_id \
             WHERE msg.conversation_id = ? AND msg.id > ? AND msg.domain_id = ? AND c.domain_id = ? \
               AND c.status = 'ACTIVE' AND c.is_deleted = 0",
        )
        .bind(conversation_id)
        .bind(last_read_message_id)
        .bind(scope.user_card_domain_id)
        .bind(scope.user_card_domain_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)
    }

    async fn insert_message(
        &self,
        _conversation_id: i64,
        _sender_id: i64,
        _message_type: &str,
        _content: &str,
    ) -> Result<i64, AstralError> {
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }

    async fn get_message(&self, _id: i64) -> Result<Option<MessageRecord>, AstralError> {
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }

    async fn get_sender_id(&self, _id: i64) -> Result<Option<i64>, AstralError> {
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }

    async fn count_by_session(&self, _conversation_id: i64) -> Result<i64, AstralError> {
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }

    async fn list_by_session(
        &self,
        _conversation_id: i64,
        _limit: i64,
        _offset: i64,
    ) -> Result<Vec<MessageRecord>, AstralError> {
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }

    async fn recall_message_scoped(&self, scope: &ChatScope, id: i64) -> Result<(), AstralError> {
        sqlx::query(
            "UPDATE chat_message msg \
             INNER JOIN chat_conversation c ON c.id = msg.conversation_id \
             SET msg.status = 'RECALLED' \
             WHERE msg.id = ? AND msg.status = 'SENT' AND msg.domain_id = ? AND c.domain_id = ? \
               AND c.status = 'ACTIVE' AND c.is_deleted = 0 \
               AND EXISTS (SELECT 1 FROM platform_user pu \
                           INNER JOIN identity_card ic ON ic.user_id = pu.user_id AND ic.card_id = ? \
                           INNER JOIN user_card uc ON uc.user_id = pu.user_id AND uc.card_id = ? \
                           INNER JOIN tenant t ON t.tenant_id = uc.tenant_id AND t.status = 'ACTIVE' \
                           INNER JOIN tenant_domain_map tdm ON tdm.tenant_id = uc.tenant_id AND tdm.domain_id = uc.domain_id AND tdm.status = 'ACTIVE' \
                           WHERE pu.user_id = msg.sender_id AND pu.status = 'ACTIVE' AND pu.deleted_at IS NULL \
                             AND ic.status = 'ACTIVE' AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()) \
                             AND uc.card_status = 'ACTIVE' AND uc.tenant_id = ? AND uc.domain_id = c.domain_id \
                             AND (uc.valid_from IS NULL OR uc.valid_from <= UTC_TIMESTAMP()) \
                             AND (uc.valid_until IS NULL OR uc.valid_until >= UTC_TIMESTAMP()))",
        )
        .bind(id)
        .bind(scope.user_card_domain_id)
        .bind(scope.user_card_domain_id)
        .bind(scope.identity_card_id)
        .bind(scope.user_card_id)
        .bind(scope.user_card_tenant_id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn recall_message(&self, id: i64) -> Result<(), AstralError> {
        sqlx::query("UPDATE chat_message SET status = 'RECALLED' WHERE id = ? AND status = 'SENT'")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn count_unread(
        &self,
        _conversation_id: i64,
        _last_read_message_id: i64,
    ) -> Result<i64, AstralError> {
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }

    async fn insert_delivery(&self, message_id: i64, recipient_id: i64) -> Result<(), AstralError> {
        sqlx::query(
            "INSERT INTO chat_message_delivery (message_id, recipient_id, status) VALUES (?, ?, 'PENDING')",
        )
        .bind(message_id)
        .bind(recipient_id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Message repository query failed: {error}"))
}
