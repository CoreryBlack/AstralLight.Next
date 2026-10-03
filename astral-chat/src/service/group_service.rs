//! 群组编排 — GroupService
//!
//! 对齐 Java `GroupServiceImpl`：角色体系 OWNER > ADMIN > MEMBER；
//! 权限校验集中在 service（原 handler 的 require_group/require_member_role/
//! require_admin/require_owner 逻辑），repository 只做数据访问。
//! list_groups 的 N+1（逐组 count_members）收敛为 batch count（行为不变）。

use std::sync::Arc;

use astral_common::contract::PageResponse;
use astral_types::AstralError;

use crate::repository::conversation_repository::{
    ConversationRecord, ConversationRepository, GroupPatch,
};
use crate::repository::member_repository::{GroupMemberRecord, MemberRepository};
use crate::scope::ChatScope;
use crate::srv::groups::{GroupMemberResponse, GroupResponse};

/// GroupService（依赖注入 repository）
pub struct GroupService {
    conversations: Arc<dyn ConversationRepository>,
    members: Arc<dyn MemberRepository>,
}

impl GroupService {
    pub fn new(
        conversations: Arc<dyn ConversationRepository>,
        members: Arc<dyn MemberRepository>,
    ) -> Self {
        Self {
            conversations,
            members,
        }
    }

    /// 创建群组（创建者自动加入并设为 OWNER）
    pub async fn create_group(
        &self,
        scope: &ChatScope,
        name: String,
        avatar: Option<String>,
        max_members: i64,
    ) -> Result<GroupResponse, AstralError> {
        let user_id = scope.user_id;
        let conversation_id = self
            .conversations
            .create_group_scoped(scope, &name, user_id, avatar.as_deref(), max_members)
            .await?;

        tracing::info!(group_id = conversation_id, owner = %user_id, "group created");
        Ok(GroupResponse {
            id: conversation_id,
            name,
            conversation_type: "GROUP".into(),
            owner_id: Some(user_id),
            avatar,
            max_members,
            status: "ACTIVE".into(),
            member_count: 1,
            created_at: Some(time::OffsetDateTime::now_utc().unix_timestamp()),
        })
    }

    /// 列出当前用户加入的群组（分页；batch count 修复 N+1）
    pub async fn list_groups(
        &self,
        scope: &ChatScope,
        page: i64,
        size: i64,
    ) -> Result<PageResponse<GroupResponse>, AstralError> {
        let offset = (page - 1) * size;
        let total = self.conversations.count_groups_for_scope(scope).await?;
        let groups = self
            .conversations
            .list_groups_for_scope(scope, size, offset)
            .await?;
        let ids: Vec<i64> = groups.iter().map(|g| g.id).collect();
        let counts = self
            .conversations
            .count_members_batch_scoped(scope, &ids)
            .await?;
        let items: Vec<GroupResponse> = groups
            .into_iter()
            .map(|g| {
                let count = counts.get(&g.id).copied().unwrap_or(0);
                to_group_response(g, count)
            })
            .collect();
        Ok(PageResponse::new(items, total, page, size))
    }

    /// 获取群组详情（成员资格 + 群组存在性）
    pub async fn get_group(
        &self,
        scope: &ChatScope,
        id: i64,
    ) -> Result<GroupResponse, AstralError> {
        self.require_member(id, scope).await?;
        let group = self.require_group(scope, id).await?;
        let count = self.members.count_members_scoped(id, scope).await?;
        Ok(to_group_response(group, count))
    }

    /// 更新群组（OWNER/ADMIN）
    pub async fn update_group(
        &self,
        scope: &ChatScope,
        id: i64,
        patch: GroupPatch,
    ) -> Result<GroupResponse, AstralError> {
        self.members.update_group_scoped(id, scope, &patch).await?;

        tracing::info!(group_id = %id, "group updated");
        let group = self.require_group(scope, id).await?;
        let count = self.members.count_members_scoped(id, scope).await?;
        Ok(to_group_response(group, count))
    }

    /// 解散群组（仅 OWNER；软解散）
    pub async fn disband_group(
        &self,
        scope: &ChatScope,
        id: i64,
    ) -> Result<GroupResponse, AstralError> {
        let group = self.require_group(scope, id).await?;
        self.members.disband_group_scoped(id, scope).await?;

        tracing::info!(group_id = %id, owner = %scope.user_id, "group disbanded");
        let count = self.members.count_members_scoped(id, scope).await?;
        Ok(to_group_response(group, count))
    }

    /// 列出群组成员（分页，角色层级排序在 SQL）
    pub async fn list_members(
        &self,
        scope: &ChatScope,
        id: i64,
        page: i64,
        size: i64,
    ) -> Result<PageResponse<GroupMemberResponse>, AstralError> {
        self.require_member(id, scope).await?;
        self.require_group(scope, id).await?;
        let offset = (page - 1) * size;
        let total = self.members.count_members_scoped(id, scope).await?;
        let rows = self
            .members
            .list_group_members_scoped(id, scope, size, offset)
            .await?;
        let items: Vec<GroupMemberResponse> =
            rows.into_iter().map(GroupMemberResponse::from).collect();
        Ok(PageResponse::new(items, total, page, size))
    }

    /// 添加成员（仅 OWNER/ADMIN；目标已是成员拒绝；达上限拒绝）
    pub async fn add_member(
        &self,
        scope: &ChatScope,
        id: i64,
        new_member_id: i64,
    ) -> Result<GroupMemberResponse, AstralError> {
        self.members
            .add_group_member_scoped(id, scope, new_member_id)
            .await?;
        tracing::info!(group_id = %id, new_member = new_member_id, invited_by = %scope.user_id, "member added");

        Ok(GroupMemberResponse {
            user_id: new_member_id,
            role: "MEMBER".into(),
            nickname: None,
            muted: false,
            pinned: false,
            joined_at: Some(time::OffsetDateTime::now_utc().unix_timestamp()),
        })
    }

    /// 移除成员（自退或管理员踢人；不能移除群主；移除 ADMIN 需 OWNER）
    pub async fn remove_member(
        &self,
        scope: &ChatScope,
        id: i64,
        target_user_id: i64,
    ) -> Result<(), AstralError> {
        self.members
            .remove_group_member_scoped(id, scope, target_user_id)
            .await?;
        tracing::info!(group_id = %id, removed_user = %target_user_id, operator = %scope.user_id, "member removed");
        Ok(())
    }

    /// 转让群主（仅 OWNER；不能转让给自己；新群主须为成员；单事务收敛）
    pub async fn transfer_owner(
        &self,
        scope: &ChatScope,
        id: i64,
        new_owner_id: i64,
    ) -> Result<GroupResponse, AstralError> {
        if new_owner_id == scope.user_id {
            return Err(AstralError::Validation("不能转让给自己".into()));
        }
        // OWNER, current conversation type/status, member scope and target eligibility
        // are rechecked under one repository conversation-row lock.

        // 单事务：owner_id + 旧主降 ADMIN + 新主升 OWNER
        self.members
            .transfer_group_owner_scoped(id, scope, scope.user_id, new_owner_id)
            .await?;
        tracing::info!(group_id = %id, old_owner = %scope.user_id, new_owner = %new_owner_id, "ownership transferred");

        let updated_group = self.require_group(scope, id).await?;
        let count = self.members.count_members_scoped(id, scope).await?;
        Ok(to_group_response(updated_group, count))
    }

    async fn require_group(
        &self,
        scope: &ChatScope,
        id: i64,
    ) -> Result<ConversationRecord, AstralError> {
        self.conversations
            .get_group_scoped(scope, id)
            .await?
            .ok_or_else(|| AstralError::Validation(format!("Group {id} not found or not active")))
    }

    /// 验证用户是会话成员
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

/// 验证角色有 ADMIN 及以上权限
pub fn require_admin(role: &str) -> Result<(), AstralError> {
    if role != "OWNER" && role != "ADMIN" {
        return Err(AstralError::Permission("需要管理员权限".into()));
    }
    Ok(())
}

/// 验证角色是 OWNER
pub fn require_owner(role: &str) -> Result<(), AstralError> {
    if role != "OWNER" {
        return Err(AstralError::Permission("需要群主权限".into()));
    }
    Ok(())
}

impl From<GroupMemberRecord> for GroupMemberResponse {
    fn from(r: GroupMemberRecord) -> Self {
        GroupMemberResponse {
            user_id: r.user_id,
            role: r.role,
            nickname: r.nickname,
            muted: r.muted != 0,
            pinned: r.pinned != 0,
            joined_at: r.joined_at.map(|dt| dt.assume_utc().unix_timestamp()),
        }
    }
}

/// 群组行 + 成员数 → 响应 DTO
fn to_group_response(g: ConversationRecord, member_count: i64) -> GroupResponse {
    GroupResponse {
        id: g.id,
        name: g.name,
        conversation_type: g.conversation_type,
        owner_id: g.owner_id,
        avatar: g.avatar,
        max_members: g.max_members,
        status: g.status,
        member_count,
        created_at: g.created_at.map(|dt| dt.assume_utc().unix_timestamp()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Fake ConversationRepository（get_group/list/batch count 返回配置数据）
    struct FakeConversationRepository {
        group: Mutex<Option<ConversationRecord>>,
        counts: Mutex<HashMap<i64, i64>>,
    }

    impl FakeConversationRepository {
        fn new(group: Option<ConversationRecord>, counts: HashMap<i64, i64>) -> Self {
            Self {
                group: Mutex::new(group),
                counts: Mutex::new(counts),
            }
        }
    }

    #[async_trait]
    impl ConversationRepository for FakeConversationRepository {
        async fn get_group_scoped(
            &self,
            _scope: &ChatScope,
            _id: i64,
        ) -> Result<Option<ConversationRecord>, AstralError> {
            Ok(self.group.lock().unwrap().clone())
        }

        async fn count_members_batch_scoped(
            &self,
            _scope: &ChatScope,
            _ids: &[i64],
        ) -> Result<HashMap<i64, i64>, AstralError> {
            Ok(self.counts.lock().unwrap().clone())
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
            Ok(true)
        }

        async fn get_conversation(
            &self,
            _id: i64,
        ) -> Result<Option<ConversationRecord>, AstralError> {
            Ok(self.group.lock().unwrap().clone())
        }

        async fn get_group(&self, _id: i64) -> Result<Option<ConversationRecord>, AstralError> {
            Ok(self.group.lock().unwrap().clone())
        }

        async fn count_sessions_for_user(&self, _user_id: i64) -> Result<i64, AstralError> {
            Ok(0)
        }

        async fn list_sessions_for_user(
            &self,
            _user_id: i64,
            _limit: i64,
            _offset: i64,
        ) -> Result<Vec<crate::repository::conversation_repository::ChatSessionRecord>, AstralError>
        {
            Ok(vec![])
        }

        async fn count_groups_for_user(&self, _user_id: i64) -> Result<i64, AstralError> {
            Ok(1)
        }

        async fn list_groups_for_user(
            &self,
            _user_id: i64,
            _limit: i64,
            _offset: i64,
        ) -> Result<Vec<ConversationRecord>, AstralError> {
            Ok(self.group.lock().unwrap().clone().into_iter().collect())
        }

        async fn count_members_batch(
            &self,
            _ids: &[i64],
        ) -> Result<HashMap<i64, i64>, AstralError> {
            Ok(self.counts.lock().unwrap().clone())
        }

        async fn count_members(&self, conversation_id: i64) -> Result<i64, AstralError> {
            Ok(self
                .counts
                .lock()
                .unwrap()
                .get(&conversation_id)
                .copied()
                .unwrap_or(0))
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

    /// Fake MemberRepository（角色与成员集可配置，记录转让事务参数）
    struct FakeMemberRepository {
        role: Mutex<Option<String>>,
        members: Mutex<Vec<i64>>,
        transfer_args: Mutex<Option<(i64, i64, i64)>>,
    }

    impl FakeMemberRepository {
        fn new(role: Option<String>, members: Vec<i64>) -> Self {
            Self {
                role: Mutex::new(role),
                members: Mutex::new(members),
                transfer_args: Mutex::new(None),
            }
        }
    }

    #[async_trait]
    impl MemberRepository for FakeMemberRepository {
        async fn is_member_scoped(
            &self,
            _conversation_id: i64,
            scope: &ChatScope,
        ) -> Result<bool, AstralError> {
            Ok(self.members.lock().unwrap().contains(&scope.user_id))
        }

        async fn member_role_scoped(
            &self,
            _conversation_id: i64,
            scope: &ChatScope,
        ) -> Result<Option<String>, AstralError> {
            if self.members.lock().unwrap().contains(&scope.user_id) {
                Ok(self.role.lock().unwrap().clone())
            } else {
                Ok(None)
            }
        }

        async fn is_member_target_scoped(
            &self,
            _conversation_id: i64,
            _scope: &ChatScope,
            user_id: i64,
        ) -> Result<bool, AstralError> {
            Ok(self.members.lock().unwrap().contains(&user_id))
        }

        async fn count_members_scoped(
            &self,
            _conversation_id: i64,
            _scope: &ChatScope,
        ) -> Result<i64, AstralError> {
            Ok(self.members.lock().unwrap().len() as i64)
        }

        async fn member_count_scoped(
            &self,
            _conversation_id: i64,
            _scope: &ChatScope,
            user_id: i64,
        ) -> Result<i64, AstralError> {
            Ok(self
                .members
                .lock()
                .unwrap()
                .iter()
                .filter(|member_id| **member_id == user_id)
                .count() as i64)
        }

        async fn is_member(
            &self,
            _conversation_id: i64,
            user_id: i64,
        ) -> Result<bool, AstralError> {
            Ok(self.members.lock().unwrap().contains(&user_id))
        }

        async fn member_role(
            &self,
            _conversation_id: i64,
            _user_id: i64,
        ) -> Result<Option<String>, AstralError> {
            Ok(self.role.lock().unwrap().clone())
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
            Ok(1)
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

        async fn transfer_group_owner_scoped(
            &self,
            conversation_id: i64,
            scope: &ChatScope,
            old_owner_id: i64,
            new_owner_id: i64,
        ) -> Result<(), AstralError> {
            if self.role.lock().unwrap().as_deref() != Some("OWNER")
                || scope.user_id != old_owner_id
            {
                return Err(AstralError::Permission("group owner required".into()));
            }
            if !self.members.lock().unwrap().contains(&new_owner_id) {
                return Err(AstralError::Permission(
                    "target group member required".into(),
                ));
            }
            *self.transfer_args.lock().unwrap() =
                Some((conversation_id, old_owner_id, new_owner_id));
            Ok(())
        }
        async fn transfer_group_owner(
            &self,
            conversation_id: i64,
            old_owner_id: i64,
            new_owner_id: i64,
        ) -> Result<(), AstralError> {
            *self.transfer_args.lock().unwrap() =
                Some((conversation_id, old_owner_id, new_owner_id));
            Ok(())
        }
    }

    fn group(id: i64, owner: Option<i64>) -> ConversationRecord {
        ConversationRecord {
            id,
            name: "g".into(),
            conversation_type: "GROUP".into(),
            owner_id: owner,
            avatar: None,
            max_members: 500,
            status: "ACTIVE".into(),
            created_at: None,
        }
    }

    fn scope(user_id: i64) -> ChatScope {
        ChatScope {
            user_id,
            identity_card_id: 70,
            user_card_id: 700,
            user_card_tenant_id: 10,
            user_card_domain_id: 20,
            principal_kind: astral_common::token_contract::PrincipalKind::PlatformUser,
            token_id: "test-token".into(),
        }
    }

    #[tokio::test]
    async fn update_group_requires_admin_role() {
        // MEMBER 无权更新群组信息
        let svc = GroupService::new(
            Arc::new(FakeConversationRepository::new(
                Some(group(1, Some(1))),
                HashMap::new(),
            )),
            Arc::new(FakeMemberRepository::new(Some("MEMBER".into()), vec![1, 2])),
        );
        let err = svc
            .update_group(&scope(2), 1, GroupPatch::default())
            .await
            .unwrap_err();
        assert!(matches!(err, AstralError::Permission(_)));
    }

    #[tokio::test]
    async fn transfer_owner_rejects_self() {
        // OWNER 不能转让给自己
        let svc = GroupService::new(
            Arc::new(FakeConversationRepository::new(
                Some(group(1, Some(1))),
                HashMap::new(),
            )),
            Arc::new(FakeMemberRepository::new(Some("OWNER".into()), vec![1])),
        );
        let err = svc.transfer_owner(&scope(1), 1, 1).await.unwrap_err();
        assert!(matches!(err, AstralError::Validation(_)));
    }

    #[tokio::test]
    async fn transfer_owner_rejects_non_member_target() {
        // 新群主必须是群成员（目标 2 非成员 → Permission）
        let svc = GroupService::new(
            Arc::new(FakeConversationRepository::new(
                Some(group(1, Some(1))),
                HashMap::new(),
            )),
            Arc::new(FakeMemberRepository::new(Some("OWNER".into()), vec![1])),
        );
        let err = svc.transfer_owner(&scope(1), 1, 2).await.unwrap_err();
        assert!(matches!(err, AstralError::Permission(_)));
    }

    #[tokio::test]
    async fn transfer_owner_non_owner_denied() {
        // ADMIN 无权转让群主
        let svc = GroupService::new(
            Arc::new(FakeConversationRepository::new(
                Some(group(1, Some(1))),
                HashMap::new(),
            )),
            Arc::new(FakeMemberRepository::new(Some("ADMIN".into()), vec![1, 2])),
        );
        let err = svc.transfer_owner(&scope(2), 1, 3).await.unwrap_err();
        assert!(matches!(err, AstralError::Permission(_)));
    }

    #[tokio::test]
    async fn transfer_owner_calls_repo_with_args() {
        // 合法转让：单事务（conversation_id, old_owner, new_owner）参数透传
        let members = Arc::new(FakeMemberRepository::new(Some("OWNER".into()), vec![1, 2]));
        let svc = GroupService::new(
            Arc::new(FakeConversationRepository::new(
                Some(group(1, Some(1))),
                HashMap::new(),
            )),
            members.clone(),
        );
        let resp = svc.transfer_owner(&scope(1), 1, 2).await.unwrap();
        assert_eq!(resp.id, 1);
        assert_eq!(resp.owner_id, Some(1)); // 返回仍读 DB 行（fake 未更新），只校验调用参数
        let args = *members.transfer_args.lock().unwrap();
        assert_eq!(args, Some((1, 1, 2)));
    }
}
