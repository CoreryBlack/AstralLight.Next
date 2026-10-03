//! 消息编排 — MessageService
//!
//! Chat send is committed as one idempotent durable intent. Transport publication
//! is handled asynchronously and does not prove a client delivery or read receipt.

use std::sync::Arc;

use astral_common::contract::PageResponse;
use astral_types::AstralError;

use crate::repository::conversation_repository::ConversationRepository;
use crate::repository::member_repository::MemberRepository;
use crate::repository::message_repository::{MessageRepository, SendIntentEffect};
use crate::scope::ChatScope;
use crate::service::side_effect::MessageSideEffects;
use crate::srv::messages::Message;

fn send_effect_name(effect: SendIntentEffect) -> &'static str {
    match effect {
        SendIntentEffect::Claimed => "PENDING",
        SendIntentEffect::Published => "PUBLISHED",
        SendIntentEffect::InDoubt => "IN_DOUBT",
        SendIntentEffect::Pending => "PENDING",
    }
}

/// 发送消息请求（来自 handler 解析）
pub struct SendMessageInput {
    pub scope: ChatScope,
    pub conversation_id: i64,
    pub content: String,
    pub message_type: String,
    pub client_msg_id: String,
}

/// MessageService（依赖注入 scoped repository）
pub struct MessageService {
    members: Arc<dyn MemberRepository>,
    messages: Arc<dyn MessageRepository>,
}

impl MessageService {
    /// Compatibility constructor retained for the former repository/side-effect API.
    /// Legacy transports are intentionally not used for durable message acceptance.
    pub fn new(
        _conversations: Arc<dyn ConversationRepository>,
        members: Arc<dyn MemberRepository>,
        messages: Arc<dyn MessageRepository>,
        _side_effects: Arc<dyn MessageSideEffects>,
    ) -> Self {
        Self { members, messages }
    }

    /// Construct the durable-intent service used by the Chat runtime.
    pub fn new_durable(
        members: Arc<dyn MemberRepository>,
        messages: Arc<dyn MessageRepository>,
    ) -> Self {
        Self { members, messages }
    }

    /// Persist the message and its exact recipient/delivery snapshot atomically.
    /// The durable MQ relay runs independently; HTTP success is a stored PENDING
    /// intent, never proof of broker publication or client receipt.
    pub async fn send_message(&self, req: &SendMessageInput) -> Result<Message, AstralError> {
        let user_id = req.scope.user_id;
        crate::repository::message_repository::validate_client_message_id(&req.client_msg_id)?;
        let persisted = self
            .messages
            .persist_send_intent_scoped(
                &req.scope,
                req.conversation_id,
                &req.message_type,
                &req.content,
                &req.client_msg_id,
            )
            .await?;
        tracing::info!(
            message_id = persisted.message_id,
            sender = %user_id,
            conversation_id = req.conversation_id,
            created = persisted.created,
            effect = ?persisted.effect,
            "Chat message durably accepted; client delivery remains unproven"
        );
        Ok(Message {
            id: persisted.message_id,
            sender_id: user_id,
            conversation_id: req.conversation_id,
            content: req.content.clone(),
            message_type: req.message_type.clone(),
            client_msg_id: req.client_msg_id.clone(),
            status: send_effect_name(persisted.effect).to_owned(),
            created_at: persisted.created_at,
        })
    }

    /// 获取单条消息；返回前必须验证请求者仍是该会话成员。
    pub async fn get_message(&self, scope: &ChatScope, id: i64) -> Result<Message, AstralError> {
        let row = self
            .messages
            .get_message_scoped(scope, id)
            .await?
            .ok_or_else(|| AstralError::Validation(format!("Message {id} not found")))?;
        self.require_member(row.conversation_id, scope).await?;
        Ok(Message {
            id: row.id,
            sender_id: row.sender_id,
            conversation_id: row.conversation_id,
            content: row.content,
            message_type: row.message_type,
            client_msg_id: String::new(),
            status: "PERSISTED".into(),
            created_at: row.created_at.map(|dt| dt.assume_utc().unix_timestamp()),
        })
    }

    /// 会话消息分页（成员资格 → Permission）
    pub async fn list_session_messages(
        &self,
        scope: &ChatScope,
        conversation_id: i64,
        page: i64,
        size: i64,
    ) -> Result<PageResponse<Message>, AstralError> {
        self.require_member(conversation_id, scope).await?;
        let offset = (page - 1) * size;
        let total = self
            .messages
            .count_by_session_scoped(scope, conversation_id)
            .await?;
        let rows = self
            .messages
            .list_by_session_scoped(scope, conversation_id, size, offset)
            .await?;
        let items: Vec<Message> = rows
            .into_iter()
            .map(|r| Message {
                id: r.id,
                sender_id: r.sender_id,
                conversation_id: r.conversation_id,
                content: r.content,
                message_type: r.message_type,
                client_msg_id: String::new(),
                status: "PERSISTED".into(),
                created_at: r.created_at.map(|dt| dt.assume_utc().unix_timestamp()),
            })
            .collect();
        Ok(PageResponse::new(items, total, page, size))
    }

    /// 删除消息；既要求发送者匹配，也要求当前请求者属于会话。
    pub async fn delete_message(&self, scope: &ChatScope, id: i64) -> Result<(), AstralError> {
        let row = self
            .messages
            .get_message_scoped(scope, id)
            .await?
            .ok_or_else(|| AstralError::Validation(format!("Message {id} not found")))?;
        self.require_member(row.conversation_id, scope).await?;
        if row.sender_id != scope.user_id {
            return Err(AstralError::Permission("只能删除自己发送的消息".into()));
        }
        self.messages.recall_message_scoped(scope, id).await?;
        tracing::info!(message_id = %id, user_id = %scope.user_id, "message deleted");
        Ok(())
    }

    /// 成员资格校验（对齐 util::require_session_member 语义）
    async fn require_member(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
    ) -> Result<(), AstralError> {
        if !self
            .members
            .is_member_scoped(conversation_id, scope)
            .await?
        {
            tracing::warn!(
                conversation_id,
                user_id = scope.user_id,
                "access denied: not a scoped member"
            );
            return Err(AstralError::Permission("您不是该会话的成员".into()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::member_repository::{GroupMemberRecord, MemberRepository};
    use crate::repository::message_repository::{
        MessageRecord, PersistedSendIntent, SendIntentEffect,
    };
    use crate::scope::{ChatScope, ChatScopeKey};
    use astral_common::token_contract::PrincipalKind;
    use async_trait::async_trait;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::sync::Mutex;

    #[derive(Clone)]
    struct StoredIntent {
        digest: String,
        persisted: PersistedSendIntent,
    }

    struct FakeMessageRepository {
        intents: Mutex<HashMap<(ChatScopeKey, i64, String), StoredIntent>>,
        next_id: AtomicI64,
        persist_calls: AtomicI64,
    }

    impl FakeMessageRepository {
        fn new() -> Self {
            Self {
                intents: Mutex::new(HashMap::new()),
                next_id: AtomicI64::new(41),
                persist_calls: AtomicI64::new(0),
            }
        }

        fn set_effect(&self, key: &(ChatScopeKey, i64, String), effect: SendIntentEffect) {
            self.intents
                .lock()
                .unwrap()
                .get_mut(key)
                .unwrap()
                .persisted
                .effect = effect;
        }

        fn key(req: &SendMessageInput) -> (ChatScopeKey, i64, String) {
            (
                req.scope.key(),
                req.conversation_id,
                req.client_msg_id.clone(),
            )
        }
    }

    #[async_trait]
    impl MessageRepository for FakeMessageRepository {
        async fn persist_send_intent_scoped(
            &self,
            scope: &ChatScope,
            conversation_id: i64,
            message_type: &str,
            content: &str,
            client_msg_id: &str,
        ) -> Result<PersistedSendIntent, AstralError> {
            self.persist_calls.fetch_add(1, Ordering::Relaxed);
            crate::repository::message_repository::validate_client_message_id(client_msg_id)?;
            if scope.user_card_id != 200 {
                return Err(AstralError::Permission(
                    "physical chat scope required".into(),
                ));
            }
            let digest = serde_json::to_string(&json!({
                "conversationId": conversation_id,
                "senderId": scope.user_id,
                "messageType": message_type,
                "content": content,
            }))
            .map_err(|error| AstralError::Internal(error.to_string()))?;
            let key = (scope.key(), conversation_id, client_msg_id.to_owned());
            let mut intents = self.intents.lock().unwrap();
            if let Some(existing) = intents.get(&key) {
                if existing.digest != digest {
                    return Err(AstralError::Validation(
                        "idempotency conflict: clientMsgId was already used with a different payload".into(),
                    ));
                }
                let mut original = existing.persisted.clone();
                original.created = false;
                return Ok(original);
            }
            let persisted = PersistedSendIntent {
                message_id: self.next_id.fetch_add(1, Ordering::Relaxed),
                effect: SendIntentEffect::Pending,
                created: true,
                created_at: Some(1_700_000_000),
                message_uuid: uuid::Uuid::new_v4().to_string(),
                payload_json: String::new(),
            };
            intents.insert(
                key,
                StoredIntent {
                    digest,
                    persisted: persisted.clone(),
                },
            );
            Ok(persisted)
        }

        async fn insert_message(
            &self,
            _conversation_id: i64,
            _sender_id: i64,
            _message_type: &str,
            _content: &str,
        ) -> Result<i64, AstralError> {
            Err(AstralError::NotImplemented(
                "legacy insert must not be used".into(),
            ))
        }

        async fn get_message(&self, _id: i64) -> Result<Option<MessageRecord>, AstralError> {
            Ok(None)
        }

        async fn get_sender_id(&self, _id: i64) -> Result<Option<i64>, AstralError> {
            Ok(None)
        }

        async fn count_by_session(&self, _conversation_id: i64) -> Result<i64, AstralError> {
            Ok(0)
        }

        async fn list_by_session(
            &self,
            _conversation_id: i64,
            _limit: i64,
            _offset: i64,
        ) -> Result<Vec<MessageRecord>, AstralError> {
            Ok(vec![])
        }

        async fn recall_message(&self, _id: i64) -> Result<(), AstralError> {
            Ok(())
        }

        async fn count_unread(
            &self,
            _conversation_id: i64,
            _last_read_message_id: i64,
        ) -> Result<i64, AstralError> {
            Ok(0)
        }

        async fn insert_delivery(
            &self,
            _message_id: i64,
            _recipient_id: i64,
        ) -> Result<(), AstralError> {
            Ok(())
        }
    }

    struct FakeMemberRepository {
        member: bool,
    }

    #[async_trait]
    impl MemberRepository for FakeMemberRepository {
        async fn is_member_scoped(
            &self,
            _conversation_id: i64,
            _scope: &ChatScope,
        ) -> Result<bool, AstralError> {
            Ok(self.member)
        }

        async fn is_member(
            &self,
            _conversation_id: i64,
            _user_id: i64,
        ) -> Result<bool, AstralError> {
            Ok(self.member)
        }

        async fn member_role(
            &self,
            _conversation_id: i64,
            _user_id: i64,
        ) -> Result<Option<String>, AstralError> {
            Ok(None)
        }

        async fn count_members(&self, _conversation_id: i64) -> Result<i64, AstralError> {
            Ok(0)
        }

        async fn list_member_ids(&self, _conversation_id: i64) -> Result<Vec<i64>, AstralError> {
            Ok(vec![])
        }

        async fn list_user_ids(
            &self,
            _conversation_id: i64,
            _limit: i64,
            _offset: i64,
        ) -> Result<Vec<i64>, AstralError> {
            Ok(vec![])
        }

        async fn list_group_members(
            &self,
            _conversation_id: i64,
            _limit: i64,
            _offset: i64,
        ) -> Result<Vec<GroupMemberRecord>, AstralError> {
            Ok(vec![])
        }

        async fn member_count(
            &self,
            _conversation_id: i64,
            _user_id: i64,
        ) -> Result<i64, AstralError> {
            Ok(0)
        }

        async fn add_member(
            &self,
            _conversation_id: i64,
            _user_id: i64,
            _role: &str,
            _invite_by: Option<i64>,
        ) -> Result<(), AstralError> {
            Ok(())
        }

        async fn add_member_ignore(
            &self,
            _conversation_id: i64,
            _user_id: i64,
        ) -> Result<(), AstralError> {
            Ok(())
        }

        async fn remove_member(
            &self,
            _conversation_id: i64,
            _user_id: i64,
        ) -> Result<u64, AstralError> {
            Ok(0)
        }

        async fn last_read_message_id(
            &self,
            _conversation_id: i64,
            _user_id: i64,
        ) -> Result<Option<i64>, AstralError> {
            Ok(None)
        }

        async fn mark_read(
            &self,
            _conversation_id: i64,
            _user_id: i64,
            _last_read_message_id: i64,
        ) -> Result<(), AstralError> {
            Ok(())
        }

        async fn update_last_read(
            &self,
            _conversation_id: i64,
            _user_id: i64,
            _read_message_id: i64,
        ) -> Result<(), AstralError> {
            Ok(())
        }

        async fn transfer_group_owner(
            &self,
            _conversation_id: i64,
            _old_owner_id: i64,
            _new_owner_id: i64,
        ) -> Result<(), AstralError> {
            Ok(())
        }
    }

    fn scope(user_id: i64, user_card_id: i64) -> ChatScope {
        ChatScope {
            user_id,
            identity_card_id: 100,
            user_card_id,
            user_card_tenant_id: 10,
            user_card_domain_id: 20,
            principal_kind: PrincipalKind::PlatformUser,
            token_id: "test-token".into(),
        }
    }

    fn request(scope: ChatScope, content: &str) -> SendMessageInput {
        SendMessageInput {
            scope,
            conversation_id: 17,
            content: content.to_owned(),
            message_type: "TEXT".into(),
            client_msg_id: "client-01".into(),
        }
    }

    fn service(repository: Arc<FakeMessageRepository>) -> MessageService {
        MessageService::new_durable(Arc::new(FakeMemberRepository { member: true }), repository)
    }

    #[tokio::test]
    async fn stable_client_msg_id_returns_original_durable_state() {
        let repository = Arc::new(FakeMessageRepository::new());
        let service = service(repository.clone());
        let req = request(scope(7, 200), "hello");
        let first = service.send_message(&req).await.unwrap();
        assert_eq!(first.status, "PENDING");

        repository.set_effect(
            &FakeMessageRepository::key(&req),
            SendIntentEffect::Published,
        );
        let retry = service.send_message(&req).await.unwrap();
        assert_eq!(retry.id, first.id);
        assert_eq!(retry.status, "PUBLISHED");
        assert_eq!(retry.created_at, first.created_at);
        assert_eq!(repository.persist_calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn same_client_msg_id_with_different_payload_conflicts() {
        let repository = Arc::new(FakeMessageRepository::new());
        let service = service(repository);
        service
            .send_message(&request(scope(7, 200), "first body"))
            .await
            .unwrap();

        let error = service
            .send_message(&request(scope(7, 200), "different body"))
            .await
            .unwrap_err();
        assert!(matches!(error, AstralError::Validation(_)));
    }

    #[tokio::test]
    async fn send_requires_valid_current_card_scope() {
        let service = service(Arc::new(FakeMessageRepository::new()));
        let error = service
            .send_message(&request(scope(7, 201), "hello"))
            .await
            .unwrap_err();
        assert!(matches!(error, AstralError::Permission(_)));
    }

    #[tokio::test]
    async fn client_msg_id_is_required_before_repository_access() {
        let repository = Arc::new(FakeMessageRepository::new());
        let service = service(repository.clone());
        let mut req = request(scope(7, 200), "hello");
        req.client_msg_id.clear();

        let error = service.send_message(&req).await.unwrap_err();
        assert!(matches!(error, AstralError::Validation(_)));
        assert_eq!(repository.persist_calls.load(Ordering::Relaxed), 0);
    }
}
