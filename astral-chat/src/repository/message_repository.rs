//! 消息数据访问 — MessageRepository
//!
//! 对齐 Java `ChatMessageMapper` 边界（chat_message + chat_message_delivery 表）。
//! 会话最后消息更新在 `ConversationRepository::update_last_message`；
//! 投递记录批量写入由 service 编排（非关键路径，逐条容错）。

use astral_mq::producer::{ChatMessagePayload, MqMessage};
use async_trait::async_trait;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::MySqlPool;
use std::collections::HashSet;
use uuid::Uuid;

use crate::scope::ChatScope;
use astral_types::AstralError;

/// Maximum raw message body accepted on either transport. Keeping headroom below
/// the WS frame cap leaves room for the JSON envelope and acknowledgements.
pub const MAX_CHAT_MESSAGE_CONTENT_BYTES: usize = 48 * 1024;
pub const MAX_CHAT_MEMBERS_PER_CONVERSATION: i64 = 500;
pub const MAX_SEND_INTENT_CLAIM_BATCH: u32 = 32;
pub const MAX_SEND_INTENT_ATTEMPTS: i32 = 8;
const SEND_INTENT_LEASE_SECONDS: i64 = 30;

/// Persisted message and exact effect state for a retry with the same client id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendIntentEffect {
    Pending,
    Claimed,
    Published,
    InDoubt,
}

#[derive(Debug, Clone)]
pub struct PersistedSendIntent {
    pub message_id: i64,
    pub effect: SendIntentEffect,
    pub created: bool,
    pub created_at: Option<i64>,
    pub message_uuid: String,
    pub payload_json: String,
}

/// Claim of one bounded Chat durable send-intent lease.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SendIntentClaim {
    pub intent_id: String,
    pub message_uuid: String,
    pub message_id: i64,
    pub payload_json: String,
    pub conversation_id: i64,
    pub sender_id: i64,
    pub identity_card_id: i64,
    pub user_card_id: i64,
    pub tenant_id: i64,
    pub domain_id: i64,
    pub client_msg_id: String,
    pub attempts: i32,
    pub lease_owner: String,
    pub lease_generation: i64,
}

/// One bounded recipient snapshot row attached to a committed send intent.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SendIntentRecipient {
    pub recipient_id: i64,
    pub identity_card_id: i64,
    pub user_card_id: i64,
    pub tenant_id: i64,
    pub domain_id: i64,
}

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

    /// Persists the message, idempotency reservation, recipient snapshot,
    /// PENDING delivery rows, conversation watermark, and MQ intent atomically.
    async fn persist_send_intent_scoped(
        &self,
        scope: &ChatScope,
        conversation_id: i64,
        message_type: &str,
        content: &str,
        client_msg_id: &str,
    ) -> Result<PersistedSendIntent, AstralError> {
        let _ = (scope, conversation_id, message_type, content, client_msg_id);
        Err(AstralError::Permission(
            "durable Chat send intent required".into(),
        ))
    }

    async fn claim_send_intents(
        &self,
        _owner: &str,
        _limit: u32,
    ) -> Result<Vec<SendIntentClaim>, AstralError> {
        Err(AstralError::NotImplemented(
            "Chat send intent relay not configured".into(),
        ))
    }

    async fn reconcile_send_intents(&self, _limit: u32) -> Result<u32, AstralError> {
        Err(AstralError::NotImplemented(
            "Chat send intent reconciliation not configured".into(),
        ))
    }

    async fn send_intent_recipients(
        &self,
        _claim: &SendIntentClaim,
    ) -> Result<Vec<SendIntentRecipient>, AstralError> {
        Err(AstralError::NotImplemented(
            "Chat send intent recipient reader not configured".into(),
        ))
    }

    async fn complete_send_intent(&self, _claim: &SendIntentClaim) -> Result<(), AstralError> {
        Err(AstralError::NotImplemented(
            "Chat send intent settlement not configured".into(),
        ))
    }

    /// Release only a publisher outcome proven not admitted without side effects.
    async fn retry_known_not_admitted(
        &self,
        _claim: &SendIntentClaim,
        _error: &str,
    ) -> Result<(), AstralError> {
        Err(AstralError::NotImplemented(
            "Chat send intent settlement not configured".into(),
        ))
    }

    /// Fence an ambiguous publish/settlement outcome as IN_DOUBT; never requeue it.
    async fn mark_send_intent_in_doubt(
        &self,
        _claim: &SendIntentClaim,
        _error: &str,
    ) -> Result<(), AstralError> {
        Err(AstralError::NotImplemented(
            "Chat send intent settlement not configured".into(),
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

const GET_MESSAGE_SCOPED_SQL: &str =
    "SELECT msg.id, msg.sender_id, msg.conversation_id AS conversation_id, msg.content, \
     msg.message_type AS message_type, msg.created_at FROM chat_message msg \
     INNER JOIN chat_conversation c ON c.id = msg.conversation_id \
     INNER JOIN chat_conversation_member m ON m.conversation_id = c.id \
     WHERE msg.id = ? AND msg.domain_id = ? AND c.domain_id = ? \
       AND c.status = 'ACTIVE' AND c.is_deleted = 0 \
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
                     AND (uc.valid_until IS NULL OR uc.valid_until >= UTC_TIMESTAMP()))";

const COUNT_BY_SESSION_SCOPED_SQL: &str =
    "SELECT COUNT(*) FROM chat_message msg INNER JOIN chat_conversation c ON c.id = msg.conversation_id \
     WHERE msg.conversation_id = ? AND msg.domain_id = ? AND c.domain_id = ? \
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
                     AND (uc.valid_until IS NULL OR uc.valid_until >= UTC_TIMESTAMP()))";

const INSERT_MESSAGE_SCOPED_SQL: &str =
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
     WHERE c.id = ? AND c.domain_id = ? AND c.status = 'ACTIVE' AND c.is_deleted = 0";

const LIST_BY_SESSION_SCOPED_SQL: &str =
    "SELECT msg.id, msg.sender_id, msg.conversation_id AS conversation_id, msg.content, \
     msg.message_type AS message_type, msg.created_at FROM chat_message msg \
     INNER JOIN chat_conversation c ON c.id = msg.conversation_id \
     WHERE msg.conversation_id = ? AND msg.domain_id = ? AND c.domain_id = ? \
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
                     AND (uc.valid_until IS NULL OR uc.valid_until >= UTC_TIMESTAMP())) \
     ORDER BY msg.id DESC LIMIT ? OFFSET ?";

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
        if sender_id != scope.user_id {
            return Err(AstralError::Permission(
                "sender does not match authenticated scope".into(),
            ));
        }
        let result = sqlx::query(INSERT_MESSAGE_SCOPED_SQL)
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

    async fn persist_send_intent_scoped(
        &self,
        scope: &ChatScope,
        conversation_id: i64,
        message_type: &str,
        content: &str,
        client_msg_id: &str,
    ) -> Result<PersistedSendIntent, AstralError> {
        validate_client_message_id(client_msg_id)?;
        if conversation_id <= 0
            || message_type.trim().is_empty()
            || message_type.len() > 20
            || content.len() > MAX_CHAT_MESSAGE_CONTENT_BYTES
        {
            return Err(AstralError::Validation(
                "Chat message type/content exceeds limits".into(),
            ));
        }
        if scope.user_id <= 0
            || scope.identity_card_id <= 0
            || scope.user_card_id <= 0
            || scope.user_card_tenant_id <= 0
            || scope.user_card_domain_id <= 0
        {
            return Err(AstralError::Permission(
                "physical chat scope required".into(),
            ));
        }
        let request_digest_payload = json!({
            "conversationId": conversation_id,
            "senderId": scope.user_id,
            "content": content,
            "messageType": message_type,
        });
        let request_sha256 = json_digest(&request_digest_payload)?;
        let scope_key_sha256 = scope_idempotency_digest(scope, conversation_id, client_msg_id);
        let mut tx = self.db.begin().await.map_err(db_error)?;

        let conversation: Option<(String, Option<i64>)> = sqlx::query_as(
            "SELECT c.status, c.max_members FROM chat_conversation c \
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
             WHERE c.id = ? AND c.domain_id = ? AND c.status = 'ACTIVE' AND c.is_deleted = 0 FOR UPDATE",
        )
        .bind(scope.user_id)
        .bind(scope.identity_card_id)
        .bind(scope.user_card_id)
        .bind(scope.user_card_tenant_id)
        .bind(conversation_id)
        .bind(scope.user_card_domain_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
        let Some((_conversation_status, configured_max_members)) = conversation else {
            return Err(AstralError::Permission(
                "physical chat scope required".into(),
            ));
        };
        let configured_max_members =
            configured_max_members.unwrap_or(MAX_CHAT_MEMBERS_PER_CONVERSATION);
        if configured_max_members <= 0 || configured_max_members > MAX_CHAT_MEMBERS_PER_CONVERSATION
        {
            return Err(AstralError::Validation(
                "conversation member limit is outside durable snapshot bounds".into(),
            ));
        }
        let current_member_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM chat_conversation_member WHERE conversation_id = ? AND left_at IS NULL",
        )
        .bind(conversation_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_error)?;
        if current_member_count.0 <= 0 || current_member_count.0 > configured_max_members {
            return Err(AstralError::Validation(
                "conversation member count exceeds configured durable snapshot limit".into(),
            ));
        }
        let intent_id = Uuid::new_v4().to_string();
        let message_uuid = Uuid::new_v4().to_string();

        // Serialize concurrent retries for the same physical scope+conversation
        // with a unique reservation insert. A collision waits for the winning
        // transaction; then read back its committed stable message id/digest.
        sqlx::query(
            "INSERT INTO chat_delivery_intent \
             (intent_id, scope_key_sha256, client_msg_id, request_sha256, message_uuid, conversation_id, sender_id, \
              identity_card_id, user_card_id, tenant_id, domain_id, status) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING') \
             ON DUPLICATE KEY UPDATE intent_id = intent_id",
        )
        .bind(&intent_id)
        .bind(&scope_key_sha256)
        .bind(client_msg_id)
        .bind(&request_sha256)
        .bind(&message_uuid)
        .bind(conversation_id)
        .bind(scope.user_id)
        .bind(scope.identity_card_id)
        .bind(scope.user_card_id)
        .bind(scope.user_card_tenant_id)
        .bind(scope.user_card_domain_id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        // Do not infer a duplicate from rows_affected: MySQL's CLIENT_FOUND_ROWS
        // setting changes no-op update counts. Compare the stable reservation id.
        let existing: (String, String, Option<i64>, String, Option<i64>, String, Option<String>) = sqlx::query_as(
            "SELECT intent_id, request_sha256, message_id, status, CAST(UNIX_TIMESTAMP(created_at) AS SIGNED), message_uuid, payload_json \
             FROM chat_delivery_intent WHERE scope_key_sha256 = ? AND client_msg_id = ? FOR UPDATE",
        )
        .bind(&scope_key_sha256)
        .bind(client_msg_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_error)?;
        if existing.0 != intent_id {
            if existing.1 != request_sha256 {
                return Err(AstralError::Validation(
                    "idempotency conflict: clientMsgId was already used with a different payload"
                        .into(),
                ));
            }
            let message_id = existing.2.ok_or_else(|| {
                AstralError::Database(
                    "committed Chat idempotency reservation has no message id".into(),
                )
            })?;
            let effect = send_effect(&existing.3);
            tx.commit().await.map_err(db_error)?;
            return Ok(PersistedSendIntent {
                message_id,
                effect,
                created: false,
                created_at: existing.4,
                message_uuid: existing.5,
                payload_json: existing.6.ok_or_else(|| {
                    AstralError::Database("committed Chat send intent payload is missing".into())
                })?,
            });
        }

        let message_result = sqlx::query(
            "INSERT INTO chat_message (message_id, conversation_id, sender_id, message_type, content, domain_id) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&message_uuid)
        .bind(conversation_id)
        .bind(scope.user_id)
        .bind(message_type)
        .bind(content)
        .bind(scope.user_card_domain_id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        let message_id = message_result.last_insert_id() as i64;
        let mut transport_message = MqMessage::new(ChatMessagePayload {
            id: message_id,
            conversation_id,
            sender_id: scope.user_id,
            content: content.to_owned(),
            message_type: message_type.to_owned(),
        });
        transport_message.message_id = message_uuid.to_owned();
        let payload_json = serde_json::to_string(&transport_message)
            .map_err(|error| AstralError::Internal(error.to_string()))?;
        let linked = sqlx::query("UPDATE chat_delivery_intent SET message_id = ?, payload_json = ? WHERE intent_id = ? AND message_uuid = ? AND status = 'PENDING'")
            .bind(message_id)
            .bind(&payload_json)
            .bind(&intent_id)
            .bind(&message_uuid)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        if linked.rows_affected() != 1 {
            return Err(AstralError::Database(
                "Chat send intent lost its source transaction reservation".into(),
            ));
        }
        // Pinned is a conversation-list property, not a card eligibility proof.
        // Snapshot all active same-tenant/domain physical card pairs (including
        // pinned members), bound the pair fan-out with cap+1, and deduplicate the
        // recipient delivery row by user id.
        let ambiguous_identity: Option<(i64,)> = sqlx::query_as(
            "SELECT m.user_id FROM chat_conversation_member m \
             INNER JOIN identity_card ic ON ic.user_id = m.user_id AND ic.status = 'ACTIVE' \
               AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()) \
             WHERE m.conversation_id = ? AND m.left_at IS NULL \
             GROUP BY m.user_id HAVING COUNT(DISTINCT ic.card_id) > 1 LIMIT 1",
        )
        .bind(conversation_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
        if ambiguous_identity.is_some() {
            return Err(AstralError::Permission(
                "ambiguous active identity-card pairing in recipient snapshot".into(),
            ));
        }

        let recipient_limit = configured_max_members + 1;
        let recipients: Vec<(i64, i64, i64)> = sqlx::query_as(
            "SELECT m.user_id, ic.card_id, uc.card_id \
             FROM chat_conversation_member m \
             INNER JOIN platform_user pu ON pu.user_id = m.user_id AND pu.status = 'ACTIVE' AND pu.deleted_at IS NULL \
             INNER JOIN identity_card ic ON ic.user_id = pu.user_id AND ic.status = 'ACTIVE' \
               AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()) \
             INNER JOIN user_card uc ON uc.user_id = pu.user_id AND uc.card_status = 'ACTIVE' \
               AND uc.tenant_id = ? AND uc.domain_id = ? \
               AND (uc.valid_from IS NULL OR uc.valid_from <= UTC_TIMESTAMP()) \
               AND (uc.valid_until IS NULL OR uc.valid_until >= UTC_TIMESTAMP()) \
             INNER JOIN tenant t ON t.tenant_id = uc.tenant_id AND t.status = 'ACTIVE' \
             INNER JOIN tenant_domain_map tdm ON tdm.tenant_id = uc.tenant_id AND tdm.domain_id = uc.domain_id AND tdm.status = 'ACTIVE' \
             WHERE m.conversation_id = ? AND m.left_at IS NULL \
             ORDER BY m.user_id, ic.card_id, uc.card_id LIMIT ?",
        )
        .bind(scope.user_card_tenant_id)
        .bind(scope.user_card_domain_id)
        .bind(conversation_id)
        .bind(recipient_limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(db_error)?;
        if recipients.len() > configured_max_members as usize {
            return Err(AstralError::Validation(
                "conversation exceeds configured durable recipient-pair snapshot limit".into(),
            ));
        }
        if recipients.is_empty()
            || !recipients
                .iter()
                .any(|(user_id, identity_id, user_card_id)| {
                    *user_id == scope.user_id
                        && *identity_id == scope.identity_card_id
                        && *user_card_id == scope.user_card_id
                })
        {
            return Err(AstralError::Permission(
                "durable recipient snapshot does not prove sender card pair".into(),
            ));
        }

        let mut delivery_recipients = HashSet::new();
        for (recipient_id, identity_card_id, user_card_id) in recipients {
            sqlx::query(
                "INSERT INTO chat_delivery_intent_recipient \
                 (intent_id, recipient_id, identity_card_id, user_card_id, tenant_id, domain_id) VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(&intent_id)
            .bind(recipient_id)
            .bind(identity_card_id)
            .bind(user_card_id)
            .bind(scope.user_card_tenant_id)
            .bind(scope.user_card_domain_id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
            if recipient_id != scope.user_id && delivery_recipients.insert(recipient_id) {
                sqlx::query(
                    "INSERT INTO chat_message_delivery (message_id, recipient_id, status) VALUES (?, ?, 'PENDING')",
                )
                .bind(message_id)
                .bind(recipient_id)
                .execute(&mut *tx)
                .await
                .map_err(db_error)?;
            }
        }

        let updated = sqlx::query("UPDATE chat_conversation SET last_message_id = ?, last_message_time = NOW() WHERE id = ? AND domain_id = ? AND status = 'ACTIVE' AND is_deleted = 0")
            .bind(message_id)
            .bind(conversation_id)
            .bind(scope.user_card_domain_id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        if updated.rows_affected() != 1 {
            return Err(AstralError::Permission(
                "active scoped conversation required".into(),
            ));
        }
        let created_at: (i64,) = sqlx::query_as(
            "SELECT CAST(UNIX_TIMESTAMP(created_at) AS SIGNED) FROM chat_delivery_intent WHERE intent_id = ?",
        )
        .bind(&intent_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_error)?;
        tx.commit().await.map_err(db_error)?;
        Ok(PersistedSendIntent {
            message_id,
            effect: SendIntentEffect::Pending,
            created: true,
            created_at: Some(created_at.0),
            message_uuid: message_uuid.to_owned(),
            payload_json,
        })
    }

    async fn claim_send_intents(
        &self,
        owner: &str,
        limit: u32,
    ) -> Result<Vec<SendIntentClaim>, AstralError> {
        if owner.trim().is_empty() || owner.len() > 128 {
            return Err(AstralError::Validation(
                "send-intent lease owner must be 1-128 bytes".into(),
            ));
        }
        if limit == 0 {
            return Ok(vec![]);
        }
        let bounded_limit = limit.min(MAX_SEND_INTENT_CLAIM_BATCH) as i64;
        let mut tx = self.db.begin().await.map_err(db_error)?;
        // Expired CLAIMED means broker admission is ambiguous: source row identity
        // cannot prove admission. Fence to IN_DOUBT; never republish automatically.
        let expired: Vec<(String,)> = sqlx::query_as(
            "SELECT intent_id FROM chat_delivery_intent \
             WHERE status = 'CLAIMED' AND lease_expires_at < UTC_TIMESTAMP(6) \
             ORDER BY lease_expires_at, intent_id LIMIT ? FOR UPDATE SKIP LOCKED",
        )
        .bind(bounded_limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(db_error)?;
        for (intent_id,) in expired {
            // A matching source message proves identity only, not broker admission.
            // An expired publisher lease is therefore ambiguous and never replayed.
            sqlx::query(
                "UPDATE chat_delivery_intent SET status = 'IN_DOUBT', lease_owner = NULL, \
                 lease_expires_at = NULL, next_attempt_at = NULL, \
                 last_error = 'expired publisher lease has unknown admission outcome' \
                 WHERE intent_id = ? AND status = 'CLAIMED' AND lease_expires_at < UTC_TIMESTAMP(6)",
            )
            .bind(&intent_id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        }
        let rows: Vec<(String, String, i64, String, i64, i64, i64, i64, i64, i64, String, i32, i64)> = sqlx::query_as(
            "SELECT intent_id, message_uuid, message_id, payload_json, conversation_id, sender_id, identity_card_id, user_card_id, tenant_id, domain_id, client_msg_id, attempts, lease_generation \
             FROM chat_delivery_intent WHERE status = 'PENDING' AND message_id IS NOT NULL AND payload_json IS NOT NULL \
               AND (next_attempt_at IS NULL OR next_attempt_at <= UTC_TIMESTAMP(6)) \
               AND (lease_expires_at IS NULL OR lease_expires_at < UTC_TIMESTAMP(6)) \
               AND attempts < ? \
             ORDER BY created_at, intent_id LIMIT ? FOR UPDATE SKIP LOCKED",
        )
        .bind(MAX_SEND_INTENT_ATTEMPTS)
        .bind(bounded_limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(db_error)?;
        let mut claims = Vec::with_capacity(rows.len());
        for (
            intent_id,
            message_uuid,
            message_id,
            payload_json,
            conversation_id,
            sender_id,
            identity_card_id,
            user_card_id,
            tenant_id,
            domain_id,
            client_msg_id,
            attempts,
            generation,
        ) in rows
        {
            let result = sqlx::query(
                "UPDATE chat_delivery_intent SET status = 'CLAIMED', attempts = attempts + 1, \
                 lease_generation = lease_generation + 1, lease_owner = ?, \
                 lease_expires_at = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND) \
                 WHERE intent_id = ? AND status = 'PENDING' AND lease_generation = ?",
            )
            .bind(owner)
            .bind(SEND_INTENT_LEASE_SECONDS)
            .bind(&intent_id)
            .bind(generation)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
            if result.rows_affected() == 1 {
                claims.push(SendIntentClaim {
                    intent_id,
                    message_uuid,
                    message_id,
                    payload_json,
                    conversation_id,
                    sender_id,
                    identity_card_id,
                    user_card_id,
                    tenant_id,
                    domain_id,
                    client_msg_id,
                    attempts,
                    lease_owner: owner.to_owned(),
                    lease_generation: generation + 1,
                });
            }
        }
        tx.commit().await.map_err(db_error)?;
        Ok(claims)
    }

    async fn send_intent_recipients(
        &self,
        claim: &SendIntentClaim,
    ) -> Result<Vec<SendIntentRecipient>, AstralError> {
        sqlx::query_as::<_, SendIntentRecipient>(
            "SELECT r.recipient_id, r.identity_card_id, r.user_card_id, r.tenant_id, r.domain_id \
             FROM chat_delivery_intent_recipient r \
             INNER JOIN chat_delivery_intent i ON i.intent_id = r.intent_id AND i.message_uuid = ? \
             WHERE r.intent_id = ? AND i.message_id = ? AND i.conversation_id = ? AND i.sender_id = ? \
               AND i.status = 'PUBLISHED' \
             ORDER BY r.recipient_id, r.identity_card_id, r.user_card_id LIMIT ?",
        )
        .bind(&claim.message_uuid)
        .bind(&claim.intent_id)
        .bind(claim.message_id)
        .bind(claim.conversation_id)
        .bind(claim.sender_id)
        .bind(MAX_CHAT_MEMBERS_PER_CONVERSATION + 1)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn complete_send_intent(&self, claim: &SendIntentClaim) -> Result<(), AstralError> {
        let result = sqlx::query(
            "UPDATE chat_delivery_intent SET status = 'PUBLISHED', published_at = UTC_TIMESTAMP(6), \
             lease_owner = NULL, lease_expires_at = NULL, last_error = NULL \
             WHERE intent_id = ? AND status = 'CLAIMED' AND lease_owner = ? AND lease_generation = ? \
               AND lease_expires_at > UTC_TIMESTAMP(6)",
        )
        .bind(&claim.intent_id)
        .bind(&claim.lease_owner)
        .bind(claim.lease_generation)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        if result.rows_affected() != 1 {
            return Err(AstralError::Permission(
                "stale Chat send-intent lease".into(),
            ));
        }
        Ok(())
    }

    async fn retry_known_not_admitted(
        &self,
        claim: &SendIntentClaim,
        error: &str,
    ) -> Result<(), AstralError> {
        // Only an explicit proof of no broker admission can enter finite retry.
        let bounded_error: String = error.chars().take(512).collect();
        let retry_status = if claim.attempts.saturating_add(1) < MAX_SEND_INTENT_ATTEMPTS {
            "PENDING"
        } else {
            "IN_DOUBT"
        };
        let result = sqlx::query(
            "UPDATE chat_delivery_intent SET status = ?, last_error = ?, \
             next_attempt_at = CASE WHEN ? = 'PENDING' THEN DATE_ADD(UTC_TIMESTAMP(6), INTERVAL LEAST(POWER(2, attempts), 30) SECOND) ELSE NULL END, \
             lease_owner = NULL, lease_expires_at = NULL \
             WHERE intent_id = ? AND status = 'CLAIMED' AND lease_owner = ? AND lease_generation = ? \
               AND lease_expires_at > UTC_TIMESTAMP(6)",
        )
        .bind(retry_status)
        .bind(bounded_error)
        .bind(retry_status)
        .bind(&claim.intent_id)
        .bind(&claim.lease_owner)
        .bind(claim.lease_generation)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        if result.rows_affected() != 1 {
            return Err(AstralError::Permission(
                "stale Chat send-intent lease".into(),
            ));
        }
        Ok(())
    }

    async fn mark_send_intent_in_doubt(
        &self,
        claim: &SendIntentClaim,
        error: &str,
    ) -> Result<(), AstralError> {
        let bounded_error: String = error.chars().take(512).collect();
        let result = sqlx::query(
            "UPDATE chat_delivery_intent SET status = 'IN_DOUBT', last_error = ?, next_attempt_at = NULL, \
             lease_owner = NULL, lease_expires_at = NULL \
             WHERE intent_id = ? AND status = 'CLAIMED' AND lease_owner = ? AND lease_generation = ? \
               AND lease_expires_at > UTC_TIMESTAMP(6)",
        )
        .bind(bounded_error)
        .bind(&claim.intent_id)
        .bind(&claim.lease_owner)
        .bind(claim.lease_generation)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        if result.rows_affected() != 1 {
            return Err(AstralError::Permission(
                "stale Chat send-intent lease".into(),
            ));
        }
        Ok(())
    }

    async fn get_message_scoped(
        &self,
        scope: &ChatScope,
        id: i64,
    ) -> Result<Option<MessageRecord>, AstralError> {
        sqlx::query_as::<_, MessageRecord>(GET_MESSAGE_SCOPED_SQL)
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
        sqlx::query_scalar::<_, i64>(COUNT_BY_SESSION_SCOPED_SQL)
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
        sqlx::query_as::<_, MessageRecord>(LIST_BY_SESSION_SCOPED_SQL)
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
        if conversation_id <= 0
            || last_read_message_id < 0
            || scope.user_id <= 0
            || scope.identity_card_id <= 0
            || scope.user_card_id <= 0
            || scope.user_card_tenant_id <= 0
            || scope.user_card_domain_id <= 0
        {
            return Err(AstralError::Permission(
                "physical chat scope required".into(),
            ));
        }
        let count: Option<i64> = sqlx::query_scalar(
            "SELECT COUNT(msg.id) FROM chat_conversation c \
             INNER JOIN chat_conversation_member m ON m.conversation_id = c.id \
               AND m.user_id = ? AND m.left_at IS NULL \
             LEFT JOIN chat_message msg ON msg.conversation_id = c.id \
               AND msg.id > ? AND msg.domain_id = c.domain_id \
             WHERE c.id = ? AND c.domain_id = ? AND c.status = 'ACTIVE' AND c.is_deleted = 0 \
               AND EXISTS (SELECT 1 FROM platform_user pu \
                           INNER JOIN identity_card ic ON ic.user_id = pu.user_id \
                             AND ic.card_id = ? AND ic.status = 'ACTIVE' \
                             AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()) \
                           INNER JOIN user_card uc ON uc.user_id = pu.user_id \
                             AND uc.card_id = ? AND uc.card_status = 'ACTIVE' \
                             AND uc.card_type <> 'LEVEL_TEMPLATE_CARD' \
                             AND uc.tenant_id = ? AND uc.domain_id = c.domain_id \
                             AND (uc.valid_from IS NULL OR uc.valid_from <= UTC_TIMESTAMP()) \
                             AND (uc.valid_until IS NULL OR uc.valid_until >= UTC_TIMESTAMP()) \
                           INNER JOIN tenant t ON t.tenant_id = uc.tenant_id AND t.status = 'ACTIVE' \
                           INNER JOIN tenant_domain_map tdm ON tdm.tenant_id = uc.tenant_id \
                             AND tdm.domain_id = uc.domain_id AND tdm.status = 'ACTIVE' \
                           WHERE pu.user_id = m.user_id AND pu.status = 'ACTIVE' \
                             AND pu.deleted_at IS NULL) \
             GROUP BY c.id, m.user_id",
        )
        .bind(scope.user_id)
        .bind(last_read_message_id)
        .bind(conversation_id)
        .bind(scope.user_card_domain_id)
        .bind(scope.identity_card_id)
        .bind(scope.user_card_id)
        .bind(scope.user_card_tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)?;
        count.ok_or_else(|| {
            AstralError::Permission("active scoped conversation member required".into())
        })
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

pub fn validate_client_message_id(value: &str) -> Result<(), AstralError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(AstralError::Validation(
            "clientMsgId must be 1-64 ASCII letters, digits, '.', '_' or '-'".into(),
        ));
    }
    Ok(())
}

fn json_digest(value: &serde_json::Value) -> Result<String, AstralError> {
    let canonical =
        serde_json::to_vec(value).map_err(|error| AstralError::Internal(error.to_string()))?;
    let digest = Sha256::digest(canonical);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn scope_idempotency_digest(
    scope: &ChatScope,
    conversation_id: i64,
    client_msg_id: &str,
) -> String {
    let mut hasher = Sha256::new();
    for field in [
        scope.user_id.to_be_bytes().as_slice(),
        scope.identity_card_id.to_be_bytes().as_slice(),
        scope.user_card_id.to_be_bytes().as_slice(),
        scope.user_card_tenant_id.to_be_bytes().as_slice(),
        scope.user_card_domain_id.to_be_bytes().as_slice(),
        conversation_id.to_be_bytes().as_slice(),
        client_msg_id.as_bytes(),
    ] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    let digest = hasher.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn send_effect(status: &str) -> SendIntentEffect {
    match status {
        "CLAIMED" => SendIntentEffect::Claimed,
        "PUBLISHED" => SendIntentEffect::Published,
        "IN_DOUBT" => SendIntentEffect::InDoubt,
        "PENDING" => SendIntentEffect::Pending,
        _ => SendIntentEffect::InDoubt,
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Message repository query failed: {error}"))
}
