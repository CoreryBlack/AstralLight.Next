//! 已读回执编排 — ReceiptService
//!
//! 对齐 Java `ChatReadWatermarkService`：标记已读（GREATEST(COALESCE) 单调不回退）、
//! 查询指定用户已读位置 + 未读数。成员资格校验（Permission）集中在此。

use std::sync::Arc;

use astral_types::AstralError;

use crate::repository::member_repository::MemberRepository;
use crate::repository::message_repository::MessageRepository;
use crate::scope::ChatScope;
use crate::srv::receipts::ReadReceipt;

/// ReceiptService（依赖注入 repository）
pub struct ReceiptService {
    members: Arc<dyn MemberRepository>,
    messages: Arc<dyn MessageRepository>,
}

impl ReceiptService {
    pub fn new(members: Arc<dyn MemberRepository>, messages: Arc<dyn MessageRepository>) -> Self {
        Self { members, messages }
    }

    /// 标记已读（UPSERT；GREATEST(COALESCE) 防 NULL 回归与水位回退）
    pub async fn mark_read(
        &self,
        scope: &ChatScope,
        conversation_id: i64,
        last_read_message_id: i64,
    ) -> Result<ReadReceipt, AstralError> {
        self.require_member(conversation_id, scope).await?;
        self.members
            .mark_read(conversation_id, scope.user_id, last_read_message_id)
            .await?;
        let unread = self
            .messages
            .count_unread_scoped(scope, conversation_id, last_read_message_id)
            .await?;
        Ok(ReadReceipt {
            user_id: scope.user_id,
            conversation_id,
            last_read_message_id,
            unread_count: unread,
        })
    }

    /// 获取指定用户的已读回执
    pub async fn get_receipt(
        &self,
        scope: &ChatScope,
        conversation_id: i64,
        target_user_id: i64,
    ) -> Result<ReadReceipt, AstralError> {
        self.require_member(conversation_id, scope).await?;
        let last_read = self
            .members
            .last_read_message_id(conversation_id, target_user_id)
            .await?
            .unwrap_or(0);
        let unread = self
            .messages
            .count_unread_scoped(scope, conversation_id, last_read)
            .await?;
        Ok(ReadReceipt {
            user_id: target_user_id,
            conversation_id,
            last_read_message_id: last_read,
            unread_count: unread,
        })
    }

    /// 成员资格校验（对齐 util::require_session_member 语义）
    async fn require_member(&self, conversation_id: i64, scope: &ChatScope) -> Result<(), AstralError> {
        if !self.members.is_member_scoped(conversation_id, scope).await? {
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
    use crate::repository::member_repository::GroupMemberRecord;
    use crate::repository::message_repository::MessageRecord;
    use async_trait::async_trait;
    use std::sync::Mutex;

    /// Fake MemberRepository：记录 mark_read 参数，验证 COALESCE 语义由 SQL 层负责
    struct FakeMemberRepository {
        member: bool,
        mark_read_args: Mutex<Vec<(i64, i64, i64)>>,
        last_read: Mutex<Option<i64>>,
    }

    impl FakeMemberRepository {
        fn new(member: bool) -> Self {
            Self {
                member,
                mark_read_args: Mutex::new(Vec::new()),
                last_read: Mutex::new(None),
            }
        }
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
            Ok(*self.last_read.lock().unwrap())
        }

        async fn mark_read(
            &self,
            conversation_id: i64,
            user_id: i64,
            last_read_message_id: i64,
        ) -> Result<(), AstralError> {
            self.mark_read_args.lock().unwrap().push((
                conversation_id,
                user_id,
                last_read_message_id,
            ));
            *self.last_read.lock().unwrap() = Some(last_read_message_id);
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

    /// Fake MessageRepository：未读数固定返回
    struct FakeMessageRepository;

    #[async_trait]
    impl MessageRepository for FakeMessageRepository {
        async fn insert_message(
            &self,
            _conversation_id: i64,
            _sender_id: i64,
            _message_type: &str,
            _content: &str,
        ) -> Result<i64, AstralError> {
            Ok(1)
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
            Ok(7)
        }
        async fn count_unread(
            &self,
            _conversation_id: i64,
            _last_read_message_id: i64,
        ) -> Result<i64, AstralError> {
            Ok(7)
        }

        async fn insert_delivery(
            &self,
            _message_id: i64,
            _recipient_id: i64,
        ) -> Result<(), AstralError> {
            Ok(())
        }
    }

    fn scope(user_id: i64) -> ChatScope {
        ChatScope {
            user_id,
            identity_card_id: 100,
            user_card_id: 200,
            user_card_tenant_id: 10,
            user_card_domain_id: 20,
            principal_kind: astral_common::token_contract::PrincipalKind::PlatformUser,
            token_id: "test-token".into(),
        }
    }
    #[tokio::test]
    async fn mark_read_non_member_denied() {
        let members = Arc::new(FakeMemberRepository::new(false));
        let svc = ReceiptService::new(members.clone(), Arc::new(FakeMessageRepository));
        let err = svc.mark_read(&scope(1), 10, 5).await.unwrap_err();
        assert!(matches!(err, AstralError::Permission(_)));
        assert!(members.mark_read_args.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn mark_read_writes_monotonic_watermark() {
        // mark_read 透传 last_read_message_id 到 repository（SQL 层 GREATEST(COALESCE) 保证不回退）
        let members = Arc::new(FakeMemberRepository::new(true));
        let svc = ReceiptService::new(members.clone(), Arc::new(FakeMessageRepository));

        let receipt = svc.mark_read(&scope(1), 10, 100).await.unwrap();
        assert_eq!(receipt.last_read_message_id, 100);
        assert_eq!(receipt.unread_count, 7);
        assert_eq!(receipt.user_id, 1);
        assert_eq!(
            members.mark_read_args.lock().unwrap().clone(),
            vec![(10, 1, 100)]
        );
    }

    #[tokio::test]
    async fn get_receipt_defaults_to_zero_when_no_row() {
        // 无已读记录 → last_read 默认 0，未读数从 0 起算
        let members = Arc::new(FakeMemberRepository::new(true));
        let svc = ReceiptService::new(members.clone(), Arc::new(FakeMessageRepository));

        let receipt = svc.get_receipt(&scope(1), 10, 2).await.unwrap();
        assert_eq!(receipt.user_id, 2);
        assert_eq!(receipt.last_read_message_id, 0);
        assert_eq!(receipt.unread_count, 7);
    }
}
