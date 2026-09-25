//! 消息编排 — MessageService
//!
//! 对齐 Java `ChatMessageServiceImpl.sendMessage` 8 步链路：
//! 成员校验 → 会话存在 → INSERT 消息 → 更新会话 last_message（非关键）→
//! 查询接收者（非关键）→ 批量投递记录（非关键）→ MQ 广播（非关键）→ WS 推送。
//! 非关键路径保持 warn-only 容错；MQ/WS 副作用经注入 `MessageSideEffects` trait。

use std::sync::Arc;

use astral_common::contract::PageResponse;
use astral_types::AstralError;

use crate::repository::conversation_repository::ConversationRepository;
use crate::repository::member_repository::MemberRepository;
use crate::repository::message_repository::MessageRepository;
use crate::scope::ChatScope;
use crate::service::side_effect::MessageSideEffects;
use crate::srv::messages::Message;

/// 发送消息请求（来自 handler 解析）
pub struct SendMessageInput {
    pub scope: ChatScope,
    pub conversation_id: i64,
    pub content: String,
    pub message_type: String,
}

/// MessageService（依赖注入 repository + 副作用执行器）
pub struct MessageService {
    conversations: Arc<dyn ConversationRepository>,
    members: Arc<dyn MemberRepository>,
    messages: Arc<dyn MessageRepository>,
    side_effects: Arc<dyn MessageSideEffects>,
}

impl MessageService {
    pub fn new(
        conversations: Arc<dyn ConversationRepository>,
        members: Arc<dyn MemberRepository>,
        messages: Arc<dyn MessageRepository>,
        side_effects: Arc<dyn MessageSideEffects>,
    ) -> Self {
        Self {
            conversations,
            members,
            messages,
            side_effects,
        }
    }

    /// 发送消息（8 步链路；非关键步骤失败仅告警，主链路不阻断）
    pub async fn send_message(&self, req: &SendMessageInput) -> Result<Message, AstralError> {
        let user_id = req.scope.user_id;
        // Step 1: 验证同一物理卡作用域下的会话成员资格
        self.require_member(req.conversation_id, &req.scope).await?;

        // Step 2: 检查会话存在
        if !self
            .conversations
            .session_exists_scoped(&req.scope, req.conversation_id)
            .await?
        {
            return Err(AstralError::Validation(format!(
                "Session {} not found",
                req.conversation_id
            )));
        }

        // Step 3: INSERT 消息
        let message_id = self
            .messages
            .insert_message_scoped(
                &req.scope,
                req.conversation_id,
                user_id,
                &req.message_type,
                &req.content,
            )
            .await?;
        let now = time::OffsetDateTime::now_utc().unix_timestamp();

        // Step 4: 更新会话 last_message（非关键）
        if let Err(e) = self
            .conversations
            .update_last_message(req.conversation_id, message_id)
            .await
        {
            tracing::warn!(conversation_id = req.conversation_id, error = %e, "update session last_message failed (non-critical)");
        }

        // Step 5: 查询接收者 user_id（非关键）
        let member_scopes = match self
            .members
            .list_member_scopes(req.conversation_id, &req.scope)
            .await
        {
            Ok(scopes) => scopes,
            Err(e) => {
                tracing::warn!(conversation_id = req.conversation_id, error = %e, "query scoped session members failed (non-critical)");
                vec![]
            }
        };

        // Step 6: 批量投递记录（排除发送者自己；非关键，逐条容错）
        for recipient_scope in member_scopes
            .iter()
            .filter(|scope| scope.user_id != user_id)
        {
            if let Err(e) = self
                .messages
                .insert_delivery(message_id, recipient_scope.user_id)
                .await
            {
                tracing::warn!(recipient_id = recipient_scope.user_id, error = %e, "create delivery record failed (non-critical)");
            }
        }

        // Step 7: MQ 广播（非关键）
        self.side_effects
            .publish_chat_message(astral_mq::producer::ChatMessagePayload {
                id: message_id,
                conversation_id: req.conversation_id,
                sender_id: user_id,
                content: req.content.clone(),
                message_type: req.message_type.clone(),
            })
            .await;

        // Step 8: WebSocket 推送（通知所有在线成员）
        let ws_msg = serde_json::json!({
            "message_type": "NEW_MESSAGE",
            "conversation_id": req.conversation_id,
            "sender_id": user_id,
            "message_id": message_id,
            "content": req.content,
        });
        let ws_str = ws_msg.to_string();
        for recipient_scope in &member_scopes {
            self.side_effects
                .push_to_scope(recipient_scope, &ws_str)
                .await;
        }

        tracing::info!(message_id, sender = %user_id, session = %req.conversation_id, "message sent (8-step pipeline)");
        Ok(Message {
            id: message_id,
            sender_id: user_id,
            conversation_id: req.conversation_id,
            content: req.content.clone(),
            message_type: req.message_type.clone(),
            created_at: Some(now),
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
    use crate::repository::conversation_repository::{
        ChatSessionRecord, ConversationRecord, GroupPatch,
    };
    use crate::repository::member_repository::GroupMemberRecord;
    use crate::repository::message_repository::MessageRecord;
    use crate::scope::ChatScope;
    use crate::service::side_effect::MessageSideEffects;
    use astral_common::token_contract::PrincipalKind;
    use astral_mq::producer::ChatMessagePayload;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// 记录副作用的 no-op 执行器（不连 DB、不发 MQ/WS）
    struct RecordingSideEffects {
        publishes: Mutex<Vec<ChatMessagePayload>>,
        pushes: Mutex<Vec<(i64, String)>>,
    }

    impl RecordingSideEffects {
        fn new() -> Self {
            Self {
                publishes: Mutex::new(Vec::new()),
                pushes: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl MessageSideEffects for RecordingSideEffects {
        async fn publish_chat_message(&self, payload: ChatMessagePayload) {
            self.publishes.lock().unwrap().push(payload);
        }

        async fn push_to_scope(&self, scope: &ChatScope, message: &str) {
            self.pushes
                .lock()
                .unwrap()
                .push((scope.user_id, message.to_string()));
        }
    }

    struct FakeConversationRepository {
        exists: bool,
        last_message_fails: bool,
    }

    #[async_trait]
    impl ConversationRepository for FakeConversationRepository {
        async fn session_exists_scoped(
            &self,
            _scope: &ChatScope,
            _id: i64,
        ) -> Result<bool, AstralError> {
            Ok(self.exists)
        }

        async fn create_conversation(
            &self,
            _name: &str,
            _conversation_type: &str,
        ) -> Result<i64, AstralError> {
            Ok(1)
        }

        async fn create_group(
            &self,
            _name: &str,
            _owner_id: i64,
            _avatar: Option<&str>,
            _max_members: i64,
        ) -> Result<i64, AstralError> {
            Ok(9)
        }

        async fn session_exists(&self, _id: i64) -> Result<bool, AstralError> {
            Ok(self.exists)
        }

        async fn get_conversation(
            &self,
            _id: i64,
        ) -> Result<Option<ConversationRecord>, AstralError> {
            Ok(None)
        }

        async fn get_group(&self, _id: i64) -> Result<Option<ConversationRecord>, AstralError> {
            Ok(None)
        }

        async fn count_sessions_for_user(&self, _user_id: i64) -> Result<i64, AstralError> {
            Ok(0)
        }

        async fn list_sessions_for_user(
            &self,
            _user_id: i64,
            _limit: i64,
            _offset: i64,
        ) -> Result<Vec<ChatSessionRecord>, AstralError> {
            Ok(vec![])
        }

        async fn count_groups_for_user(&self, _user_id: i64) -> Result<i64, AstralError> {
            Ok(0)
        }

        async fn list_groups_for_user(
            &self,
            _user_id: i64,
            _limit: i64,
            _offset: i64,
        ) -> Result<Vec<ConversationRecord>, AstralError> {
            Ok(vec![])
        }

        async fn count_members_batch(
            &self,
            _ids: &[i64],
        ) -> Result<HashMap<i64, i64>, AstralError> {
            Ok(HashMap::new())
        }

        async fn count_members(&self, _conversation_id: i64) -> Result<i64, AstralError> {
            Ok(0)
        }

        async fn update_name(&self, _id: i64, _name: &str) -> Result<(), AstralError> {
            Ok(())
        }

        async fn update_group(&self, _id: i64, _patch: &GroupPatch) -> Result<(), AstralError> {
            Ok(())
        }

        async fn disband_group(&self, _id: i64) -> Result<(), AstralError> {
            Ok(())
        }

        async fn update_last_message(&self, _id: i64, _message_id: i64) -> Result<(), AstralError> {
            if self.last_message_fails {
                Err(AstralError::Database("boom".into()))
            } else {
                Ok(())
            }
        }
    }

    struct FakeMemberRepository {
        member: bool,
        member_ids: Vec<i64>,
    }

    #[async_trait]
    impl MemberRepository for FakeMemberRepository {
        async fn is_member_scoped(
            &self,
            _conversation_id: i64,
            scope: &ChatScope,
        ) -> Result<bool, AstralError> {
            Ok(self.member && scope.user_id > 0 && scope.user_card_id == 200)
        }

        async fn list_member_scopes(
            &self,
            _conversation_id: i64,
            scope: &ChatScope,
        ) -> Result<Vec<ChatScope>, AstralError> {
            Ok(self
                .member_ids
                .iter()
                .map(|user_id| ChatScope {
                    user_id: *user_id,
                    ..scope.clone()
                })
                .collect())
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
            Ok(Some("MEMBER".into()))
        }

        async fn count_members(&self, _conversation_id: i64) -> Result<i64, AstralError> {
            Ok(0)
        }

        async fn list_member_ids(&self, _conversation_id: i64) -> Result<Vec<i64>, AstralError> {
            Ok(self.member_ids.clone())
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

    struct FakeMessageRepository {
        deliveries: Mutex<Vec<(i64, i64)>>,
    }

    #[async_trait]
    impl MessageRepository for FakeMessageRepository {
        async fn insert_message_scoped(
            &self,
            _scope: &ChatScope,
            _conversation_id: i64,
            _sender_id: i64,
            _message_type: &str,
            _content: &str,
        ) -> Result<i64, AstralError> {
            Ok(42)
        }

        async fn insert_message(
            &self,
            _conversation_id: i64,
            _sender_id: i64,
            _message_type: &str,
            _content: &str,
        ) -> Result<i64, AstralError> {
            Ok(42)
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

        async fn count_unread_scoped(
            &self,
            _scope: &ChatScope,
            _conversation_id: i64,
            _last_read_message_id: i64,
        ) -> Result<i64, AstralError> {
            Ok(0)
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
            message_id: i64,
            recipient_id: i64,
        ) -> Result<(), AstralError> {
            self.deliveries
                .lock()
                .unwrap()
                .push((message_id, recipient_id));
            Ok(())
        }
    }

    fn request(user_id: i64, conversation_id: i64) -> SendMessageInput {
        SendMessageInput {
            scope: ChatScope {
                user_id,
                identity_card_id: 100,
                user_card_id: 200,
                user_card_tenant_id: 10,
                user_card_domain_id: 20,
                principal_kind: PrincipalKind::PlatformUser,
                token_id: "test-token".into(),
            },
            conversation_id,
            content: "hello".into(),
            message_type: "TEXT".into(),
        }
    }

    #[tokio::test]
    async fn send_rejects_non_member() {
        // 非成员发送 → Permission，且不写消息
        let messages = Arc::new(FakeMessageRepository {
            deliveries: Mutex::new(Vec::new()),
        });
        let svc = MessageService::new(
            Arc::new(FakeConversationRepository {
                exists: true,
                last_message_fails: false,
            }),
            Arc::new(FakeMemberRepository {
                member: false,
                member_ids: vec![],
            }),
            messages.clone(),
            Arc::new(RecordingSideEffects::new()),
        );
        let err = svc.send_message(&request(1, 10)).await.unwrap_err();
        assert!(matches!(err, AstralError::Permission(_)));
        assert!(messages.deliveries.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn send_rejects_same_user_with_different_user_card_scope() {
        let svc = MessageService::new(
            Arc::new(FakeConversationRepository {
                exists: true,
                last_message_fails: false,
            }),
            Arc::new(FakeMemberRepository {
                member: true,
                member_ids: vec![1],
            }),
            Arc::new(FakeMessageRepository {
                deliveries: Mutex::new(Vec::new()),
            }),
            Arc::new(RecordingSideEffects::new()),
        );
        let mut request = request(1, 10);
        request.scope.user_card_id = 201;
        let err = svc.send_message(&request).await.unwrap_err();
        assert!(matches!(err, AstralError::Permission(_)));
    }
    #[tokio::test]
    async fn send_runs_full_pipeline() {
        // 8 步链路：成员 → 会话存在 → INSERT → last_message → 接收者 → 投递 → MQ → WS
        let messages = Arc::new(FakeMessageRepository {
            deliveries: Mutex::new(Vec::new()),
        });
        let se = Arc::new(RecordingSideEffects::new());
        let svc = MessageService::new(
            Arc::new(FakeConversationRepository {
                exists: true,
                last_message_fails: false,
            }),
            // 成员 [1,2,3]，发送者 1 → 投递对象为 2,3
            Arc::new(FakeMemberRepository {
                member: true,
                member_ids: vec![1, 2, 3],
            }),
            messages.clone(),
            se.clone(),
        );

        let msg = svc.send_message(&request(1, 10)).await.unwrap();
        assert_eq!(msg.id, 42);
        assert_eq!(msg.sender_id, 1);
        assert_eq!(msg.conversation_id, 10);

        // 投递记录排除发送者自己
        let mut deliveries = messages.deliveries.lock().unwrap().clone();
        deliveries.sort();
        assert_eq!(deliveries, vec![(42, 2), (42, 3)]);

        // MQ 广播一次，payload 字段正确
        let publishes = se.publishes.lock().unwrap().clone();
        assert_eq!(publishes.len(), 1);
        assert_eq!(publishes[0].id, 42);
        assert_eq!(publishes[0].conversation_id, 10);
        assert_eq!(publishes[0].sender_id, 1);
        assert_eq!(publishes[0].message_type, "TEXT");
        assert_eq!(publishes[0].content, "hello");

        // WS 推送每个在线成员
        let pushes = se.pushes.lock().unwrap().clone();
        let pushed_users: Vec<i64> = pushes.iter().map(|(u, _)| *u).collect();
        assert_eq!(pushed_users, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn send_noncritical_failures_do_not_block() {
        // last_message 更新失败 + 成员查询失败：主链路仍成功（非关键路径容错）
        let messages = Arc::new(FakeMessageRepository {
            deliveries: Mutex::new(Vec::new()),
        });
        let se = Arc::new(RecordingSideEffects::new());
        let svc = MessageService::new(
            Arc::new(FakeConversationRepository {
                exists: true,
                last_message_fails: true,
            }),
            Arc::new(FakeMemberRepository {
                member: true,
                member_ids: vec![],
            }),
            messages.clone(),
            se.clone(),
        );
        let msg = svc.send_message(&request(1, 10)).await.unwrap();
        assert_eq!(msg.id, 42);
        // MQ 仍触发（payload 完整），无投递/WS（成员查询失败 → 空列表）
        assert_eq!(se.publishes.lock().unwrap().len(), 1);
        assert!(messages.deliveries.lock().unwrap().is_empty());
        assert!(se.pushes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn send_missing_session_rejected() {
        // 会话不存在 → Validation
        let svc = MessageService::new(
            Arc::new(FakeConversationRepository {
                exists: false,
                last_message_fails: false,
            }),
            Arc::new(FakeMemberRepository {
                member: true,
                member_ids: vec![1],
            }),
            Arc::new(FakeMessageRepository {
                deliveries: Mutex::new(Vec::new()),
            }),
            Arc::new(RecordingSideEffects::new()),
        );
        let err = svc.send_message(&request(1, 10)).await.unwrap_err();
        assert!(matches!(err, AstralError::Validation(_)));
    }
}
