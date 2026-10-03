//! 会话编排 — SessionService
//!
//! 对齐 Java `ChatConversationServiceImpl`：创建会话（创建者自动加入）、
//! 会话列表（member_count 子查询防 N+1）、成员校验、成员管理。
//! 授权判定（成员资格）保留原有错误语义：列表/详情类为 Permission，
//! update_session 为 Validation（对齐现有 handler 差异）。

use std::sync::Arc;

use astral_common::contract::PageResponse;
use astral_types::AstralError;

use crate::repository::conversation_repository::{ChatSessionRecord, ConversationRepository};
use crate::repository::member_repository::MemberRepository;
use crate::scope::ChatScope;
use crate::srv::sessions::ChatSession;

/// SessionService（依赖注入 repository）
pub struct SessionService {
    conversations: Arc<dyn ConversationRepository>,
    members: Arc<dyn MemberRepository>,
}

impl SessionService {
    pub fn new(
        conversations: Arc<dyn ConversationRepository>,
        members: Arc<dyn MemberRepository>,
    ) -> Self {
        Self {
            conversations,
            members,
        }
    }

    /// 创建会话（创建者自动加入）
    pub async fn create_session(
        &self,
        scope: &ChatScope,
        name: String,
        conversation_type: String,
    ) -> Result<ChatSession, AstralError> {
        let user_id = scope.user_id;
        let conversation_id = self
            .conversations
            .create_conversation_with_creator_scoped(scope, &name, &conversation_type)
            .await?;

        tracing::info!(conversation_id, creator = %user_id, "session created");
        Ok(ChatSession {
            id: conversation_id,
            name,
            conversation_type,
            member_count: 1,
            created_at: Some(time::OffsetDateTime::now_utc().unix_timestamp()),
        })
    }

    /// 列出当前用户参与的会话（分页）
    pub async fn list_sessions(
        &self,
        scope: &ChatScope,
        page: i64,
        size: i64,
    ) -> Result<PageResponse<ChatSession>, AstralError> {
        let offset = (page - 1) * size;
        let total = self.conversations.count_sessions_for_scope(scope).await?;
        let rows = self
            .conversations
            .list_sessions_for_scope(scope, size, offset)
            .await?;
        let items: Vec<ChatSession> = rows.into_iter().map(ChatSession::from).collect();
        Ok(PageResponse::new(items, total, page, size))
    }

    /// 获取会话详情（验证成员资格 → Permission）
    pub async fn get_session(
        &self,
        scope: &ChatScope,
        id: i64,
    ) -> Result<ChatSession, AstralError> {
        self.require_member(id, scope).await?;
        let row = self
            .conversations
            .get_conversation_scoped(scope, id)
            .await?
            .ok_or_else(|| AstralError::Validation(format!("Session {id} not found")))?;
        let count = self.members.count_members_scoped(id, scope).await?;
        Ok(ChatSession {
            id: row.id,
            name: row.name,
            conversation_type: row.conversation_type,
            member_count: count,
            created_at: row.created_at.map(|dt| dt.assume_utc().unix_timestamp()),
        })
    }

    /// 更新会话名称（成员资格校验失败 → Validation，对齐现有 handler）
    pub async fn update_session(
        &self,
        scope: &ChatScope,
        id: i64,
        name: Option<&str>,
    ) -> Result<(), AstralError> {
        if !self.members.is_member_scoped(id, scope).await? {
            return Err(AstralError::Validation(
                "Not a member of this session".into(),
            ));
        }
        if let Some(name) = name {
            self.conversations
                .update_name_scoped(scope, id, name)
                .await?;
        }
        tracing::info!(conversation_id = %id, "session updated");
        Ok(())
    }

    /// 列出会话成员 user_id（分页）
    pub async fn list_members(
        &self,
        scope: &ChatScope,
        id: i64,
        page: i64,
        size: i64,
    ) -> Result<PageResponse<i64>, AstralError> {
        self.require_member(id, scope).await?;
        let offset = (page - 1) * size;
        let total = self.members.count_members_scoped(id, scope).await?;
        let ids = self
            .members
            .list_user_ids_scoped(id, scope, size, offset)
            .await?;
        Ok(PageResponse::new(ids, total, page, size))
    }

    /// 添加成员（INSERT IGNORE 幂等）
    pub async fn add_member(
        &self,
        scope: &ChatScope,
        id: i64,
        new_member_id: Option<i64>,
    ) -> Result<(), AstralError> {
        self.require_member(id, scope).await?;
        if let Some(new_member_id) = new_member_id {
            self.members
                .add_member_ignore_scoped(id, scope, new_member_id)
                .await?;
            tracing::info!(conversation_id = %id, new_member = new_member_id, "member added");
        }
        Ok(())
    }

    /// 成员资格校验（对齐 util::require_session_member 语义）
    async fn require_member(&self, id: i64, scope: &ChatScope) -> Result<(), AstralError> {
        if !self.members.is_member_scoped(id, scope).await? {
            tracing::warn!(
                conversation_id = id,
                user_id = scope.user_id,
                "access denied: not a member"
            );
            return Err(AstralError::Permission("您不是该会话的成员".into()));
        }
        Ok(())
    }
}

impl From<ChatSessionRecord> for ChatSession {
    fn from(r: ChatSessionRecord) -> Self {
        Self {
            id: r.id,
            name: r.name,
            conversation_type: r.conversation_type,
            member_count: r.member_count,
            created_at: r.created_at.map(|dt| dt.assume_utc().unix_timestamp()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::conversation_repository::{ConversationRecord, GroupPatch};
    use crate::repository::member_repository::GroupMemberRecord;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Fake ConversationRepository（记录 create/update 调用）
    struct FakeConversationRepository {
        create_id: Mutex<i64>,
        created: Mutex<Vec<(String, String)>>,
    }

    #[async_trait]
    impl ConversationRepository for FakeConversationRepository {
        async fn create_conversation_with_creator_scoped(
            &self,
            scope: &ChatScope,
            name: &str,
            conversation_type: &str,
        ) -> Result<i64, AstralError> {
            self.create_conversation_scoped(scope, name, conversation_type)
                .await
        }

        async fn create_conversation_scoped(
            &self,
            _scope: &ChatScope,
            name: &str,
            conversation_type: &str,
        ) -> Result<i64, AstralError> {
            let mut id = self.create_id.lock().unwrap();
            *id += 1;
            let new_id = *id;
            self.created
                .lock()
                .unwrap()
                .push((name.to_string(), conversation_type.to_string()));
            Ok(new_id)
        }

        async fn create_conversation(
            &self,
            name: &str,
            conversation_type: &str,
        ) -> Result<i64, AstralError> {
            let mut id = self.create_id.lock().unwrap();
            *id += 1;
            let new_id = *id;
            self.created
                .lock()
                .unwrap()
                .push((name.to_string(), conversation_type.to_string()));
            Ok(new_id)
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
            Ok(true)
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
            Ok(())
        }
    }

    /// Fake MemberRepository（记录 add_member_ignore 调用，验证幂等语义）
    struct FakeMemberRepository {
        member: Mutex<bool>,
        add_ignore_calls: Mutex<Vec<(i64, i64)>>,
    }

    #[async_trait]
    impl MemberRepository for FakeMemberRepository {
        async fn is_member_scoped(
            &self,
            _conversation_id: i64,
            _scope: &ChatScope,
        ) -> Result<bool, AstralError> {
            Ok(*self.member.lock().unwrap())
        }

        async fn add_member_scoped(
            &self,
            _conversation_id: i64,
            _scope: &ChatScope,
            _user_id: i64,
            _role: &str,
            _invite_by: Option<i64>,
        ) -> Result<(), AstralError> {
            Ok(())
        }

        async fn add_member_ignore_scoped(
            &self,
            conversation_id: i64,
            _scope: &ChatScope,
            user_id: i64,
        ) -> Result<(), AstralError> {
            self.add_ignore_calls
                .lock()
                .unwrap()
                .push((conversation_id, user_id));
            Ok(())
        }

        async fn is_member(
            &self,
            _conversation_id: i64,
            _user_id: i64,
        ) -> Result<bool, AstralError> {
            Ok(*self.member.lock().unwrap())
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
            conversation_id: i64,
            user_id: i64,
        ) -> Result<(), AstralError> {
            self.add_ignore_calls
                .lock()
                .unwrap()
                .push((conversation_id, user_id));
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

    fn scope() -> ChatScope {
        ChatScope {
            user_id: 7,
            identity_card_id: 70,
            user_card_id: 700,
            user_card_tenant_id: 10,
            user_card_domain_id: 20,
            principal_kind: astral_common::token_contract::PrincipalKind::PlatformUser,
            token_id: "test-token".into(),
        }
    }

    #[tokio::test]
    async fn create_session_adds_creator_as_member() {
        let conversations = Arc::new(FakeConversationRepository {
            create_id: Mutex::new(0),
            created: Mutex::new(Vec::new()),
        });
        let members = Arc::new(FakeMemberRepository {
            member: Mutex::new(false),
            add_ignore_calls: Mutex::new(Vec::new()),
        });
        let svc = SessionService::new(conversations.clone(), members.clone());

        let scope = scope();
        let session = svc
            .create_session(&scope, "test".into(), "GROUP".into())
            .await
            .unwrap();
        assert_eq!(session.id, 1);
        assert_eq!(session.member_count, 1);
        assert_eq!(
            conversations.created.lock().unwrap().clone(),
            vec![("test".to_string(), "GROUP".to_string())]
        );
    }

    #[tokio::test]
    async fn add_member_requires_operator_membership() {
        // 非成员操作者 → Permission
        let conversations = Arc::new(FakeConversationRepository {
            create_id: Mutex::new(0),
            created: Mutex::new(Vec::new()),
        });
        let members = Arc::new(FakeMemberRepository {
            member: Mutex::new(false),
            add_ignore_calls: Mutex::new(Vec::new()),
        });
        let svc = SessionService::new(conversations, members.clone());

        let scope = scope();
        let err = svc.add_member(&scope, 10, Some(8)).await.unwrap_err();
        assert!(matches!(err, AstralError::Permission(_)));
        assert!(members.add_ignore_calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn add_member_uses_insert_ignore_idempotent() {
        // 合法添加 → INSERT IGNORE 幂等（重复添加不会报错）
        let conversations = Arc::new(FakeConversationRepository {
            create_id: Mutex::new(0),
            created: Mutex::new(Vec::new()),
        });
        let members = Arc::new(FakeMemberRepository {
            member: Mutex::new(true),
            add_ignore_calls: Mutex::new(Vec::new()),
        });
        let svc = SessionService::new(conversations, members.clone());

        let scope = scope();
        svc.add_member(&scope, 10, Some(8)).await.unwrap();
        assert_eq!(
            members.add_ignore_calls.lock().unwrap().clone(),
            vec![(10, 8)]
        );
    }
}
