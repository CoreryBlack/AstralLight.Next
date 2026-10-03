//! 会话成员数据访问 — MemberRepository
//!
//! 对齐 Java `ChatConversationMemberMapper` 边界（chat_conversation_member 表）。
//! 群主转让跨 chat_conversation + chat_conversation_member 的写收敛为单事务
//! 聚合方法（对齐 Java 事务语义；此前 3 条独立 UPDATE 存在崩溃中间态）。
//! 已读水位用 GREATEST(COALESCE(...)) 防 NULL 回归（对齐 realtime READ_RECEIPT 写法）。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::AstralError;

use crate::scope::ChatScope;

const LIST_MEMBER_SCOPES_SQL: &str =
    "SELECT DISTINCT m.user_id, ic.card_id, uc.card_id \
     FROM chat_conversation c \
     INNER JOIN chat_conversation_member m ON m.conversation_id = c.id \
     INNER JOIN platform_user pu ON pu.user_id = m.user_id AND pu.status = 'ACTIVE' AND pu.deleted_at IS NULL \
     INNER JOIN identity_card ic ON ic.user_id = pu.user_id AND ic.status = 'ACTIVE' \
       AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()) \
     INNER JOIN user_card uc ON uc.user_id = pu.user_id AND uc.card_status = 'ACTIVE' \
       AND uc.tenant_id = ? AND uc.domain_id = c.domain_id \
       AND (uc.valid_from IS NULL OR uc.valid_from <= UTC_TIMESTAMP()) \
       AND (uc.valid_until IS NULL OR uc.valid_until >= UTC_TIMESTAMP()) \
     INNER JOIN tenant t ON t.tenant_id = uc.tenant_id AND t.status = 'ACTIVE' \
     INNER JOIN tenant_domain_map tdm ON tdm.tenant_id = uc.tenant_id AND tdm.domain_id = uc.domain_id AND tdm.status = 'ACTIVE' \
     WHERE c.id = ? AND c.domain_id = ? AND c.status = 'ACTIVE' AND c.is_deleted = 0 \
       AND m.left_at IS NULL \
       AND (SELECT COUNT(DISTINCT active_ic.card_id) FROM identity_card active_ic \
            WHERE active_ic.user_id = pu.user_id AND active_ic.status = 'ACTIVE' \
              AND (active_ic.expires_at IS NULL OR active_ic.expires_at >= UTC_TIMESTAMP())) = 1 \
     ORDER BY m.user_id, ic.card_id, uc.card_id";

/// 群组成员行（muted/pinned 为 TINYINT → i64，DTO 转换在 handler 层）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct GroupMemberRecord {
    pub user_id: i64,
    pub role: String,
    pub nickname: Option<String>,
    pub muted: i64,
    pub pinned: i64,
    pub joined_at: Option<time::PrimitiveDateTime>,
}

#[async_trait]
pub trait MemberRepository: Send + Sync {
    /// 用户是否为指定物理卡作用域下的活跃会话成员。
    async fn is_member_scoped(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
    ) -> Result<bool, AstralError> {
        let _ = (conversation_id, scope);
        Ok(false)
    }

    /// 返回会话成员在当前租户/域中的物理卡作用域。
    async fn list_member_scopes(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
    ) -> Result<Vec<ChatScope>, AstralError> {
        let _ = (conversation_id, scope);
        Ok(vec![])
    }

    /// 当前作用域下的成员角色。
    async fn member_role_scoped(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
    ) -> Result<Option<String>, AstralError> {
        let _ = (conversation_id, scope);
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }

    /// 当前作用域下的会话成员数。
    async fn count_members_scoped(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
    ) -> Result<i64, AstralError> {
        let _ = (conversation_id, scope);
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }

    /// 当前作用域下的成员分页。
    async fn list_user_ids_scoped(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<i64>, AstralError> {
        let _ = (conversation_id, scope, limit, offset);
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }

    /// 当前作用域下的群成员分页。
    async fn list_group_members_scoped(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<GroupMemberRecord>, AstralError> {
        let _ = (conversation_id, scope, limit, offset);
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }

    async fn is_user_in_scope(
        &self,
        scope: &ChatScope,
        _user_id: i64,
    ) -> Result<bool, AstralError> {
        let _ = scope;
        Ok(false)
    }

    /// Atomically authorizes and updates group metadata under the conversation row lock.
    async fn update_group_scoped(
        &self,
        _conversation_id: i64,
        _scope: &ChatScope,
        _patch: &crate::repository::conversation_repository::GroupPatch,
    ) -> Result<(), AstralError> {
        Err(AstralError::Permission(
            "scoped group mutation required".into(),
        ))
    }

    /// Atomically authorizes and disbands a group under the conversation row lock.
    async fn disband_group_scoped(
        &self,
        _conversation_id: i64,
        _scope: &ChatScope,
    ) -> Result<(), AstralError> {
        Err(AstralError::Permission(
            "scoped group mutation required".into(),
        ))
    }

    /// Validate the target user is a member in the exact scoped conversation.
    async fn is_member_target_scoped(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
        user_id: i64,
    ) -> Result<bool, AstralError> {
        let _ = (conversation_id, scope, user_id);
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }

    async fn member_count_scoped(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
        user_id: i64,
    ) -> Result<i64, AstralError> {
        let _ = (conversation_id, scope, user_id);
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }

    async fn add_member_scoped(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
        user_id: i64,
        role: &str,
        invite_by: Option<i64>,
    ) -> Result<(), AstralError> {
        let _ = (conversation_id, scope, user_id, role, invite_by);
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }

    /// Atomically verifies OWNER/ADMIN, group type, scope, active target, and
    /// member cap while holding the conversation row lock.
    async fn add_group_member_scoped(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
        user_id: i64,
    ) -> Result<(), AstralError> {
        let _ = (conversation_id, scope, user_id);
        Err(AstralError::Permission(
            "scoped group mutation required".into(),
        ))
    }

    /// Atomically applies leave/kick policy and membership removal.
    async fn remove_group_member_scoped(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
        user_id: i64,
    ) -> Result<u64, AstralError> {
        let _ = (conversation_id, scope, user_id);
        Err(AstralError::Permission(
            "scoped group mutation required".into(),
        ))
    }

    async fn member_role_target_scoped(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
        user_id: i64,
    ) -> Result<Option<String>, AstralError> {
        let _ = (conversation_id, scope, user_id);
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }

    async fn add_member_ignore_scoped(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
        user_id: i64,
    ) -> Result<(), AstralError> {
        let _ = (conversation_id, scope, user_id);
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }

    async fn remove_member_scoped(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
        user_id: i64,
    ) -> Result<u64, AstralError> {
        let _ = (conversation_id, scope, user_id);
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }

    async fn transfer_group_owner_scoped(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
        old_owner_id: i64,
        new_owner_id: i64,
    ) -> Result<(), AstralError> {
        let _ = (conversation_id, scope, old_owner_id, new_owner_id);
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }

    /// 用户是否为会话成员（对齐 util::require_session_member 语义）
    async fn is_member(&self, conversation_id: i64, user_id: i64) -> Result<bool, AstralError>;

    /// 用户角色（非成员返回 None）
    async fn member_role(
        &self,
        conversation_id: i64,
        user_id: i64,
    ) -> Result<Option<String>, AstralError>;
    /// 会话成员总数
    async fn count_members(&self, conversation_id: i64) -> Result<i64, AstralError>;
    /// 会话全部成员 user_id（send 投递 + WS 推送用）
    async fn list_member_ids(&self, conversation_id: i64) -> Result<Vec<i64>, AstralError>;
    /// 会话成员 user_id 分页（sessions.list_members）
    async fn list_user_ids(
        &self,
        conversation_id: i64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<i64>, AstralError>;
    /// 群组成员分页（按角色层级 OWNER > ADMIN > MEMBER 排序）
    async fn list_group_members(
        &self,
        conversation_id: i64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<GroupMemberRecord>, AstralError>;
    /// 目标用户已是成员的行数（groups.add_member 幂等检查）
    async fn member_count(&self, conversation_id: i64, user_id: i64) -> Result<i64, AstralError>;
    /// 添加成员（指定角色；groups.add_member）
    async fn add_member(
        &self,
        conversation_id: i64,
        user_id: i64,
        role: &str,
        invite_by: Option<i64>,
    ) -> Result<(), AstralError>;
    /// 添加成员（INSERT IGNORE；sessions.add_member）
    async fn add_member_ignore(
        &self,
        conversation_id: i64,
        user_id: i64,
    ) -> Result<(), AstralError>;
    /// 移除成员，返回影响行数
    async fn remove_member(&self, conversation_id: i64, user_id: i64) -> Result<u64, AstralError>;
    /// 已读水位（无记录 → None）
    async fn last_read_message_id(
        &self,
        conversation_id: i64,
        user_id: i64,
    ) -> Result<Option<i64>, AstralError>;
    /// Read a watermark only while the requester and target remain eligible members
    /// in the exact active conversation and physical tenant/domain scope.
    async fn last_read_message_id_scoped(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
        target_user_id: i64,
    ) -> Result<i64, AstralError> {
        let _ = (conversation_id, scope, target_user_id);
        Err(AstralError::Permission(
            "scoped receipt read required".into(),
        ))
    }
    /// UPSERT 已读水位（receipts.mark_read；GREATEST(COALESCE) 防 NULL 回归）
    async fn mark_read(
        &self,
        conversation_id: i64,
        user_id: i64,
        last_read_message_id: i64,
    ) -> Result<(), AstralError>;
    /// Scoped monotonic receipt watermark; target membership is revalidated in this transaction.
    async fn mark_read_scoped(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
        last_read_message_id: i64,
    ) -> Result<(), AstralError> {
        let _ = (conversation_id, scope, last_read_message_id);
        Err(AstralError::Permission(
            "scoped receipt write required".into(),
        ))
    }
    /// 更新已读水位（realtime READ_RECEIPT；GREATEST(COALESCE) 单调不回退）
    async fn update_last_read(
        &self,
        conversation_id: i64,
        user_id: i64,
        read_message_id: i64,
    ) -> Result<(), AstralError>;
    /// 群主转让（单事务：conversation.owner_id + 旧主降 ADMIN + 新主升 OWNER）
    async fn transfer_group_owner(
        &self,
        conversation_id: i64,
        old_owner_id: i64,
        new_owner_id: i64,
    ) -> Result<(), AstralError>;
}

pub struct SqlxMemberRepository {
    db: MySqlPool,
}

impl SqlxMemberRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

const MAX_SCOPED_GROUP_MEMBERS: i64 = 500;

async fn verify_scope_pair(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    scope: &ChatScope,
) -> Result<bool, AstralError> {
    let eligible: Vec<(i64,)> = sqlx::query_as(
        "SELECT pu.user_id FROM platform_user pu \
         INNER JOIN identity_card ic ON ic.user_id = pu.user_id AND ic.card_id = ? AND ic.status = 'ACTIVE' \
           AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()) \
         INNER JOIN user_card uc ON uc.user_id = pu.user_id AND uc.card_id = ? AND uc.card_status = 'ACTIVE' \
           AND uc.card_type != 'LEVEL_TEMPLATE_CARD' AND uc.tenant_id = ? AND uc.domain_id = ? \
           AND (uc.valid_from IS NULL OR uc.valid_from <= UTC_TIMESTAMP()) \
           AND (uc.valid_until IS NULL OR uc.valid_until >= UTC_TIMESTAMP()) \
         INNER JOIN tenant t ON t.tenant_id = uc.tenant_id AND t.status = 'ACTIVE' \
         INNER JOIN tenant_domain_map tdm ON tdm.tenant_id = uc.tenant_id AND tdm.domain_id = uc.domain_id AND tdm.status = 'ACTIVE' \
         WHERE pu.user_id = ? AND pu.status = 'ACTIVE' AND pu.deleted_at IS NULL \
         LIMIT 2 FOR UPDATE",
    )
    .bind(scope.identity_card_id)
    .bind(scope.user_card_id)
    .bind(scope.user_card_tenant_id)
    .bind(scope.user_card_domain_id)
    .bind(scope.user_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(db_error)?;
    Ok(eligible.len() == 1)
}

async fn target_has_unique_eligible_pair(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    user_id: i64,
    tenant_id: i64,
    domain_id: i64,
) -> Result<bool, AstralError> {
    let pairs: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT ic.card_id, uc.card_id FROM platform_user pu \
         INNER JOIN identity_card ic ON ic.user_id = pu.user_id AND ic.status = 'ACTIVE' \
           AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()) \
         INNER JOIN user_card uc ON uc.user_id = pu.user_id AND uc.card_status = 'ACTIVE' \
           AND uc.card_type != 'LEVEL_TEMPLATE_CARD' AND uc.tenant_id = ? AND uc.domain_id = ? \
           AND (uc.valid_from IS NULL OR uc.valid_from <= UTC_TIMESTAMP()) \
           AND (uc.valid_until IS NULL OR uc.valid_until >= UTC_TIMESTAMP()) \
         INNER JOIN tenant t ON t.tenant_id = uc.tenant_id AND t.status = 'ACTIVE' \
         INNER JOIN tenant_domain_map tdm ON tdm.tenant_id = uc.tenant_id AND tdm.domain_id = uc.domain_id AND tdm.status = 'ACTIVE' \
         WHERE pu.user_id = ? AND pu.status = 'ACTIVE' AND pu.deleted_at IS NULL \
         LIMIT 2 FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(domain_id)
    .bind(user_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(db_error)?;
    Ok(pairs.len() == 1)
}

const LOCK_ACTIVE_CONVERSATION_SQL: &str = concat!(
    "SELECT conversation_type, owner_id, max_members FROM chat_conversation ",
    "WHERE id = ? AND domain_id = ? AND status = 'ACTIVE' AND is_deleted = 0 FOR UPDATE",
);

async fn locked_active_conversation(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    conversation_id: i64,
    scope: &ChatScope,
) -> Result<Option<(String, Option<i64>, Option<i64>)>, AstralError> {
    sqlx::query_as(LOCK_ACTIVE_CONVERSATION_SQL)
        .bind(conversation_id)
        .bind(scope.user_card_domain_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_error)
}

async fn locked_group_row(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    conversation_id: i64,
    scope: &ChatScope,
) -> Result<Option<(Option<i64>, Option<i64>)>, AstralError> {
    sqlx::query_as(
        "SELECT c.owner_id, c.max_members FROM chat_conversation c \
         WHERE c.id = ? AND c.domain_id = ? AND c.conversation_type = 'GROUP' \
           AND c.status = 'ACTIVE' AND c.is_deleted = 0 FOR UPDATE",
    )
    .bind(conversation_id)
    .bind(scope.user_card_domain_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_error)
}

async fn locked_member_count(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    conversation_id: i64,
) -> Result<i64, AstralError> {
    let rows: Vec<(i64,)> = sqlx::query_as(
        "SELECT user_id FROM chat_conversation_member \
         WHERE conversation_id = ? AND left_at IS NULL ORDER BY user_id \
         LIMIT ? FOR UPDATE",
    )
    .bind(conversation_id)
    .bind(MAX_SCOPED_GROUP_MEMBERS + 1)
    .fetch_all(&mut **tx)
    .await
    .map_err(db_error)?;
    Ok(rows.len() as i64)
}

fn authorize_group_admin(
    owner_id: Option<i64>,
    actor_id: i64,
    role: &str,
) -> Result<(), AstralError> {
    match role {
        "OWNER" if owner_id == Some(actor_id) => Ok(()),
        "OWNER" => Err(AstralError::Permission(
            "group owner/member state mismatch".into(),
        )),
        "ADMIN" if owner_id == Some(actor_id) => Err(AstralError::Permission(
            "group owner/member state mismatch".into(),
        )),
        "ADMIN" => Ok(()),
        _ => Err(AstralError::Permission(
            "group owner or admin required".into(),
        )),
    }
}

async fn locked_member_role(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    conversation_id: i64,
    user_id: i64,
) -> Result<Option<String>, AstralError> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT role FROM chat_conversation_member WHERE conversation_id = ? AND user_id = ? AND left_at IS NULL FOR UPDATE",
    )
    .bind(conversation_id)
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_error)?;
    Ok(row.map(|value| value.0))
}

fn scoped_group_member_limit(configured: i64) -> Result<i64, AstralError> {
    if configured <= 0 || configured > MAX_SCOPED_GROUP_MEMBERS {
        return Err(AstralError::Validation(
            "group member limit is outside Chat bounds".into(),
        ));
    }
    Ok(configured)
}

#[async_trait]
impl MemberRepository for SqlxMemberRepository {
    async fn mark_read_scoped(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
        last_read_message_id: i64,
    ) -> Result<(), AstralError> {
        if last_read_message_id < 0 {
            return Err(AstralError::Validation(
                "read watermark must be non-negative".into(),
            ));
        }
        let mut tx = self.db.begin().await.map_err(db_error)?;
        if !verify_scope_pair(&mut tx, scope).await? {
            return Err(AstralError::Permission(
                "physical chat scope required".into(),
            ));
        }
        let Some((conversation_type, _, _)) =
            locked_active_conversation(&mut tx, conversation_id, scope).await?
        else {
            return Err(AstralError::Permission(
                "active scoped conversation required".into(),
            ));
        };
        if locked_member_role(&mut tx, conversation_id, scope.user_id)
            .await?
            .is_none()
        {
            return Err(AstralError::Permission(
                "scoped conversation member required".into(),
            ));
        }
        if conversation_type == "GROUP"
            && locked_group_row(&mut tx, conversation_id, scope)
                .await?
                .is_none()
        {
            return Err(AstralError::Permission("active group required".into()));
        }
        if last_read_message_id > 0 {
            let message: Option<(i64,)> = sqlx::query_as(
                "SELECT id FROM chat_message WHERE id = ? AND conversation_id = ? AND domain_id = ? FOR UPDATE",
            )
            .bind(last_read_message_id)
            .bind(conversation_id)
            .bind(scope.user_card_domain_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_error)?;
            if message.is_none() {
                return Err(AstralError::Permission(
                    "read watermark message is outside the scoped conversation".into(),
                ));
            }
        }
        // `locked_member_role` above already locked and proved this exact member
        // row. Do not interpret rows_affected == 0 as a missing member: MySQL
        // reports zero for a valid idempotent lower-watermark retry.
        sqlx::query(concat!(
            "UPDATE chat_conversation_member SET last_read_message_id = ",
            "GREATEST(COALESCE(last_read_message_id, 0), ?) ",
            "WHERE conversation_id = ? AND user_id = ? AND left_at IS NULL",
        ))
        .bind(last_read_message_id)
        .bind(conversation_id)
        .bind(scope.user_id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        tx.commit().await.map_err(db_error)
    }

    async fn last_read_message_id_scoped(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
        target_user_id: i64,
    ) -> Result<i64, AstralError> {
        if conversation_id <= 0 || target_user_id <= 0 {
            return Err(AstralError::Permission(
                "scoped receipt target required".into(),
            ));
        }
        let mut tx = self.db.begin().await.map_err(db_error)?;
        if !verify_scope_pair(&mut tx, scope).await? {
            return Err(AstralError::Permission(
                "physical chat scope required".into(),
            ));
        }
        let Some((conversation_type, _, _)) =
            locked_active_conversation(&mut tx, conversation_id, scope).await?
        else {
            return Err(AstralError::Permission(
                "active scoped conversation required".into(),
            ));
        };
        if locked_member_role(&mut tx, conversation_id, scope.user_id)
            .await?
            .is_none()
            || locked_member_role(&mut tx, conversation_id, target_user_id)
                .await?
                .is_none()
        {
            return Err(AstralError::Permission(
                "scoped conversation member required".into(),
            ));
        }
        if conversation_type == "GROUP"
            && locked_group_row(&mut tx, conversation_id, scope)
                .await?
                .is_none()
        {
            return Err(AstralError::Permission("active group required".into()));
        }
        if !target_has_unique_eligible_pair(
            &mut tx,
            target_user_id,
            scope.user_card_tenant_id,
            scope.user_card_domain_id,
        )
        .await?
        {
            return Err(AstralError::Permission(
                "receipt target lacks a unique eligible physical card pair".into(),
            ));
        }
        let watermark: Option<(Option<i64>,)> = sqlx::query_as(concat!(
            "SELECT m.last_read_message_id FROM chat_conversation_member m ",
            "WHERE m.conversation_id = ? AND m.user_id = ? AND m.left_at IS NULL FOR UPDATE",
        ))
        .bind(conversation_id)
        .bind(target_user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
        let Some((watermark,)) = watermark else {
            return Err(AstralError::Permission(
                "scoped conversation member required".into(),
            ));
        };
        tx.commit().await.map_err(db_error)?;
        Ok(watermark.unwrap_or(0))
    }

    async fn update_group_scoped(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
        patch: &crate::repository::conversation_repository::GroupPatch,
    ) -> Result<(), AstralError> {
        if patch
            .max_members
            .is_some_and(|value| value <= 0 || value > MAX_SCOPED_GROUP_MEMBERS)
        {
            return Err(AstralError::Validation(
                "group max_members is outside Chat bounds".into(),
            ));
        }
        let mut tx = self.db.begin().await.map_err(db_error)?;
        if !verify_scope_pair(&mut tx, scope).await? {
            return Err(AstralError::Permission(
                "physical chat scope required".into(),
            ));
        }
        let Some((owner_id, configured_max)) =
            locked_group_row(&mut tx, conversation_id, scope).await?
        else {
            return Err(AstralError::Permission(
                "active scoped group required".into(),
            ));
        };
        let current_count = locked_member_count(&mut tx, conversation_id).await?;
        let role = locked_member_role(&mut tx, conversation_id, scope.user_id)
            .await?
            .ok_or_else(|| AstralError::Permission("group member required".into()))?;
        authorize_group_admin(owner_id, scope.user_id, &role)?;
        let old_limit =
            scoped_group_member_limit(configured_max.unwrap_or(MAX_SCOPED_GROUP_MEMBERS))?;
        if patch.max_members.is_some_and(|new_limit| {
            new_limit < current_count
                || new_limit > old_limit && new_limit > MAX_SCOPED_GROUP_MEMBERS
        }) {
            return Err(AstralError::Validation(
                "max_members cannot be below current membership or exceed Chat bounds".into(),
            ));
        }
        let mut builder = sqlx::QueryBuilder::<sqlx::MySql>::new("UPDATE chat_conversation SET ");
        let mut first = true;
        if let Some(name) = &patch.name {
            builder.push("name = ").push_bind(name.clone());
            first = false;
        }
        if let Some(avatar) = &patch.avatar {
            if !first {
                builder.push(", ");
            }
            builder.push("avatar = ").push_bind(avatar.clone());
            first = false;
        }
        if let Some(limit) = patch.max_members {
            if !first {
                builder.push(", ");
            }
            builder.push("max_members = ").push_bind(limit);
            first = false;
        }
        if !first {
            builder
                .push(" WHERE id = ")
                .push_bind(conversation_id)
                .push(" AND domain_id = ")
                .push_bind(scope.user_card_domain_id)
                .push(" AND conversation_type = 'GROUP' AND status = 'ACTIVE' AND is_deleted = 0");
            let result = builder.build().execute(&mut *tx).await.map_err(db_error)?;
            if result.rows_affected() != 1 {
                return Err(AstralError::Permission(
                    "active scoped group required".into(),
                ));
            }
        }
        tx.commit().await.map_err(db_error)
    }

    async fn disband_group_scoped(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
    ) -> Result<(), AstralError> {
        let mut tx = self.db.begin().await.map_err(db_error)?;
        if !verify_scope_pair(&mut tx, scope).await? {
            return Err(AstralError::Permission(
                "physical chat scope required".into(),
            ));
        }
        let Some((owner_id, _)) = locked_group_row(&mut tx, conversation_id, scope).await? else {
            return Err(AstralError::Permission(
                "active scoped group required".into(),
            ));
        };
        let role = locked_member_role(&mut tx, conversation_id, scope.user_id)
            .await?
            .ok_or_else(|| AstralError::Permission("group member required".into()))?;
        if role != "OWNER" || owner_id != Some(scope.user_id) {
            return Err(AstralError::Permission("group owner required".into()));
        }
        let result = sqlx::query(
            "UPDATE chat_conversation SET status = 'DISBANDED' \
             WHERE id = ? AND domain_id = ? AND conversation_type = 'GROUP' AND status = 'ACTIVE' AND is_deleted = 0",
        )
        .bind(conversation_id).bind(scope.user_card_domain_id).execute(&mut *tx).await.map_err(db_error)?;
        if result.rows_affected() != 1 {
            return Err(AstralError::Permission(
                "active scoped group required".into(),
            ));
        }
        tx.commit().await.map_err(db_error)
    }

    async fn add_group_member_scoped(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
        user_id: i64,
    ) -> Result<(), AstralError> {
        let mut tx = self.db.begin().await.map_err(db_error)?;
        if !verify_scope_pair(&mut tx, scope).await? {
            return Err(AstralError::Permission(
                "physical chat scope required".into(),
            ));
        }
        let Some((owner_id, configured_max)) =
            locked_group_row(&mut tx, conversation_id, scope).await?
        else {
            return Err(AstralError::Permission(
                "active scoped group required".into(),
            ));
        };
        let member_count = locked_member_count(&mut tx, conversation_id).await?;
        let actor_role = locked_member_role(&mut tx, conversation_id, scope.user_id)
            .await?
            .ok_or_else(|| AstralError::Permission("group member required".into()))?;
        authorize_group_admin(owner_id, scope.user_id, &actor_role)?;
        if member_count
            >= scoped_group_member_limit(configured_max.unwrap_or(MAX_SCOPED_GROUP_MEMBERS))?
        {
            return Err(AstralError::Validation("group member limit reached".into()));
        }
        if locked_member_role(&mut tx, conversation_id, user_id)
            .await?
            .is_some()
        {
            return Err(AstralError::Validation(
                "target is already a group member".into(),
            ));
        }
        if !target_has_unique_eligible_pair(
            &mut tx,
            user_id,
            scope.user_card_tenant_id,
            scope.user_card_domain_id,
        )
        .await?
        {
            return Err(AstralError::Permission(
                "target user must have one eligible physical card pair in the same tenant/domain"
                    .into(),
            ));
        }
        sqlx::query("INSERT INTO chat_conversation_member (conversation_id, user_id, role, invite_by) VALUES (?, ?, 'MEMBER', ?)")
            .bind(conversation_id).bind(user_id).bind(scope.user_id).execute(&mut *tx).await.map_err(db_error)?;
        tx.commit().await.map_err(db_error)
    }

    async fn remove_group_member_scoped(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
        user_id: i64,
    ) -> Result<u64, AstralError> {
        let mut tx = self.db.begin().await.map_err(db_error)?;
        if !verify_scope_pair(&mut tx, scope).await? {
            return Err(AstralError::Permission(
                "physical chat scope required".into(),
            ));
        }
        let Some((owner_id, _)) = locked_group_row(&mut tx, conversation_id, scope).await? else {
            return Err(AstralError::Permission(
                "active scoped group required".into(),
            ));
        };
        let actor_role = locked_member_role(&mut tx, conversation_id, scope.user_id)
            .await?
            .ok_or_else(|| AstralError::Permission("group member required".into()))?;
        let target_role = locked_member_role(&mut tx, conversation_id, user_id)
            .await?
            .ok_or_else(|| AstralError::Validation("target is not a group member".into()))?;
        if owner_id == Some(user_id) || target_role == "OWNER" {
            return Err(AstralError::Validation("cannot remove group owner".into()));
        }
        if user_id != scope.user_id {
            authorize_group_admin(owner_id, scope.user_id, &actor_role)?;
            if target_role == "ADMIN" && (actor_role != "OWNER" || owner_id != Some(scope.user_id))
            {
                return Err(AstralError::Permission(
                    "only owner may remove an admin".into(),
                ));
            }
        }
        let result = sqlx::query("UPDATE chat_conversation_member SET left_at = UTC_TIMESTAMP() WHERE conversation_id = ? AND user_id = ? AND left_at IS NULL")
            .bind(conversation_id).bind(user_id).execute(&mut *tx).await.map_err(db_error)?;
        tx.commit().await.map_err(db_error)?;
        Ok(result.rows_affected())
    }

    async fn is_member_scoped(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
    ) -> Result<bool, AstralError> {
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM chat_conversation c \
             INNER JOIN chat_conversation_member m ON m.conversation_id = c.id \
             WHERE c.id = ? AND c.domain_id = ? AND c.status = 'ACTIVE' AND c.is_deleted = 0 \
               AND m.user_id = ? AND m.left_at IS NULL \
               AND EXISTS (SELECT 1 FROM identity_card ic \
                           INNER JOIN user_card uc ON uc.user_id = ic.user_id \
                           INNER JOIN tenant t ON t.tenant_id = uc.tenant_id AND t.status = 'ACTIVE' \
                           INNER JOIN tenant_domain_map tdm ON tdm.tenant_id = uc.tenant_id \
                             AND tdm.domain_id = uc.domain_id AND tdm.status = 'ACTIVE' \
                           WHERE ic.card_id = ? AND ic.user_id = ? AND ic.status = 'ACTIVE' \
                             AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()) \
                             AND uc.card_id = ? AND uc.user_id = ? AND uc.card_status = 'ACTIVE' \
                             AND (uc.valid_from IS NULL OR uc.valid_from <= UTC_TIMESTAMP()) \
                             AND (uc.valid_until IS NULL OR uc.valid_until >= UTC_TIMESTAMP()) \
                             AND uc.tenant_id = ? AND uc.domain_id = c.domain_id)",
        )
        .bind(conversation_id)
        .bind(scope.user_card_domain_id)
        .bind(scope.user_id)
        .bind(scope.identity_card_id)
        .bind(scope.user_id)
        .bind(scope.user_card_id)
        .bind(scope.user_id)
        .bind(scope.user_card_tenant_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)?;
        Ok(count.0 == 1)
    }

    async fn list_member_scopes(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
    ) -> Result<Vec<ChatScope>, AstralError> {
        let rows: Vec<(i64, i64, i64)> = sqlx::query_as(LIST_MEMBER_SCOPES_SQL)
            .bind(conversation_id)
            .bind(scope.user_card_domain_id)
            .bind(scope.user_card_tenant_id)
            .fetch_all(&self.db)
            .await
            .map_err(db_error)?;
        Ok(rows
            .into_iter()
            .map(|(user_id, identity_card_id, user_card_id)| {
                scope.for_recipient(user_id, identity_card_id, user_card_id)
            })
            .collect())
    }

    async fn member_role_scoped(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
    ) -> Result<Option<String>, AstralError> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT m.role FROM chat_conversation_member m \
             INNER JOIN chat_conversation c ON c.id = m.conversation_id \
             WHERE m.conversation_id = ? AND m.user_id = ? AND m.left_at IS NULL \
               AND c.domain_id = ? AND c.status = 'ACTIVE' AND c.is_deleted = 0 \
               AND EXISTS (SELECT 1 FROM identity_card ic INNER JOIN user_card uc ON uc.user_id = ic.user_id \
                           WHERE ic.card_id = ? AND ic.user_id = ? AND ic.status = 'ACTIVE' \
                             AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()) \
                             AND uc.card_id = ? AND uc.user_id = ? AND uc.card_status = 'ACTIVE' \
                             AND (uc.valid_from IS NULL OR uc.valid_from <= UTC_TIMESTAMP()) \
                             AND (uc.valid_until IS NULL OR uc.valid_until >= UTC_TIMESTAMP()) \
                             AND uc.tenant_id = ? AND uc.domain_id = c.domain_id)",
        )
        .bind(conversation_id)
        .bind(scope.user_id)
        .bind(scope.user_card_domain_id)
        .bind(scope.identity_card_id)
        .bind(scope.user_id)
        .bind(scope.user_card_id)
        .bind(scope.user_id)
        .bind(scope.user_card_tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)?;
        Ok(row.map(|value| value.0))
    }

    async fn count_members_scoped(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
    ) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM chat_conversation_member m \
             INNER JOIN chat_conversation c ON c.id = m.conversation_id \
             WHERE m.conversation_id = ? AND m.left_at IS NULL AND c.domain_id = ? \
               AND c.status = 'ACTIVE' AND c.is_deleted = 0",
        )
        .bind(conversation_id)
        .bind(scope.user_card_domain_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)
    }

    async fn list_user_ids_scoped(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<i64>, AstralError> {
        let rows: Vec<(i64,)> = sqlx::query_as(
            "SELECT m.user_id FROM chat_conversation_member m \
             INNER JOIN chat_conversation c ON c.id = m.conversation_id \
             WHERE m.conversation_id = ? AND m.left_at IS NULL AND c.domain_id = ? \
               AND c.status = 'ACTIVE' AND c.is_deleted = 0 LIMIT ? OFFSET ?",
        )
        .bind(conversation_id)
        .bind(scope.user_card_domain_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)?;
        Ok(rows.into_iter().map(|row| row.0).collect())
    }

    async fn list_group_members_scoped(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<GroupMemberRecord>, AstralError> {
        sqlx::query_as::<_, GroupMemberRecord>(
            "SELECT m.user_id, m.role, m.nickname, m.muted, m.pinned, m.joined_at \
             FROM chat_conversation_member m INNER JOIN chat_conversation c ON c.id = m.conversation_id \
             WHERE m.conversation_id = ? AND m.left_at IS NULL AND c.domain_id = ? \
               AND c.status = 'ACTIVE' AND c.is_deleted = 0 \
             ORDER BY CASE m.role WHEN 'OWNER' THEN 0 WHEN 'ADMIN' THEN 1 ELSE 2 END, m.joined_at ASC \
             LIMIT ? OFFSET ?",
        )
        .bind(conversation_id)
        .bind(scope.user_card_domain_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn is_user_in_scope(&self, scope: &ChatScope, user_id: i64) -> Result<bool, AstralError> {
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM platform_user pu \
             INNER JOIN identity_card ic ON ic.user_id = pu.user_id \
             INNER JOIN user_card uc ON uc.user_id = pu.user_id \
             INNER JOIN tenant t ON t.tenant_id = uc.tenant_id AND t.status = 'ACTIVE' \
             INNER JOIN tenant_domain_map tdm ON tdm.tenant_id = uc.tenant_id AND tdm.domain_id = uc.domain_id AND tdm.status = 'ACTIVE' \
             WHERE pu.user_id = ? AND pu.status = 'ACTIVE' AND pu.deleted_at IS NULL \
               AND ic.status = 'ACTIVE' AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()) \
               AND uc.card_status = 'ACTIVE' AND uc.tenant_id = ? AND uc.domain_id = ? \
               AND (uc.valid_from IS NULL OR uc.valid_from <= UTC_TIMESTAMP()) \
               AND (uc.valid_until IS NULL OR uc.valid_until >= UTC_TIMESTAMP())",
        )
        .bind(user_id)
        .bind(scope.user_card_tenant_id)
        .bind(scope.user_card_domain_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)?;
        Ok(count.0 > 0)
    }

    async fn is_member_target_scoped(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
        user_id: i64,
    ) -> Result<bool, AstralError> {
        if scope.user_id <= 0 || scope.identity_card_id <= 0 || scope.user_card_id <= 0 {
            return Ok(false);
        }
        let rows: Vec<(i64,)> = sqlx::query_as(
            "SELECT m.user_id FROM chat_conversation_member m \
             INNER JOIN chat_conversation c ON c.id = m.conversation_id \
             INNER JOIN platform_user pu ON pu.user_id = m.user_id AND pu.status = 'ACTIVE' AND pu.deleted_at IS NULL \
             INNER JOIN identity_card ic ON ic.user_id = pu.user_id AND ic.status = 'ACTIVE' \
               AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()) \
             INNER JOIN user_card uc ON uc.user_id = pu.user_id AND uc.card_status = 'ACTIVE' \
               AND uc.tenant_id = ? AND uc.domain_id = c.domain_id \
               AND (uc.valid_from IS NULL OR uc.valid_from <= UTC_TIMESTAMP()) \
               AND (uc.valid_until IS NULL OR uc.valid_until >= UTC_TIMESTAMP()) \
             INNER JOIN tenant t ON t.tenant_id = uc.tenant_id AND t.status = 'ACTIVE' \
             INNER JOIN tenant_domain_map tdm ON tdm.tenant_id = uc.tenant_id AND tdm.domain_id = uc.domain_id AND tdm.status = 'ACTIVE' \
             WHERE m.conversation_id = ? AND m.user_id = ? AND m.left_at IS NULL \
               AND c.domain_id = ? AND c.status = 'ACTIVE' AND c.is_deleted = 0 \
               AND (SELECT COUNT(DISTINCT active_ic.card_id) FROM identity_card active_ic \
                    WHERE active_ic.user_id = pu.user_id AND active_ic.status = 'ACTIVE' \
                      AND (active_ic.expires_at IS NULL OR active_ic.expires_at >= UTC_TIMESTAMP())) = 1 \
             LIMIT 2",
        )
        .bind(scope.user_card_tenant_id)
        .bind(conversation_id)
        .bind(user_id)
        .bind(scope.user_card_domain_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)?;
        Ok(rows.len() == 1)
    }

    async fn member_count_scoped(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
        user_id: i64,
    ) -> Result<i64, AstralError> {
        Ok(
            if self
                .is_member_target_scoped(conversation_id, scope, user_id)
                .await?
            {
                1
            } else {
                0
            },
        )
    }

    async fn add_member_scoped(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
        user_id: i64,
        role: &str,
        invite_by: Option<i64>,
    ) -> Result<(), AstralError> {
        if !self.is_user_in_scope(scope, user_id).await? {
            return Err(AstralError::Permission(
                "target user is outside card scope".into(),
            ));
        }
        sqlx::query(
            "INSERT IGNORE INTO chat_conversation_member (conversation_id, user_id, role, invite_by) \
             SELECT ?, ?, ?, ? FROM chat_conversation c \
             WHERE c.id = ? AND c.domain_id = ? AND c.status = 'ACTIVE' AND c.is_deleted = 0",
        )
        .bind(conversation_id)
        .bind(user_id)
        .bind(role)
        .bind(invite_by)
        .bind(conversation_id)
        .bind(scope.user_card_domain_id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn add_member_ignore_scoped(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
        user_id: i64,
    ) -> Result<(), AstralError> {
        self.add_member_scoped(conversation_id, scope, user_id, "MEMBER", None)
            .await
    }

    async fn remove_member_scoped(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
        user_id: i64,
    ) -> Result<u64, AstralError> {
        let mut tx = self.db.begin().await.map_err(db_error)?;
        if !verify_scope_pair(&mut tx, scope).await? {
            return Err(AstralError::Permission(
                "physical chat scope required".into(),
            ));
        }
        let eligible_target = target_has_unique_eligible_pair(
            &mut tx,
            user_id,
            scope.user_card_tenant_id,
            scope.user_card_domain_id,
        )
        .await?;
        if !eligible_target
            || locked_member_role(&mut tx, conversation_id, user_id)
                .await?
                .is_none()
        {
            return Err(AstralError::Permission(
                "target is not an eligible member in this scoped conversation".into(),
            ));
        }
        let result = sqlx::query(
            "UPDATE chat_conversation_member m INNER JOIN chat_conversation c ON c.id = m.conversation_id \
             SET m.left_at = UTC_TIMESTAMP() WHERE m.conversation_id = ? AND m.user_id = ? \
               AND m.left_at IS NULL AND c.domain_id = ? AND c.status = 'ACTIVE' \
               AND c.conversation_type <> 'GROUP' AND c.is_deleted = 0",
        )
        .bind(conversation_id)
        .bind(user_id)
        .bind(scope.user_card_domain_id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        tx.commit().await.map_err(db_error)?;
        Ok(result.rows_affected())
    }

    async fn transfer_group_owner_scoped(
        &self,
        conversation_id: i64,
        scope: &ChatScope,
        old_owner_id: i64,
        new_owner_id: i64,
    ) -> Result<(), AstralError> {
        if old_owner_id != scope.user_id || old_owner_id == new_owner_id {
            return Err(AstralError::Permission(
                "invalid group owner transfer".into(),
            ));
        }
        let mut tx = self.db.begin().await.map_err(db_error)?;
        if !verify_scope_pair(&mut tx, scope).await? {
            return Err(AstralError::Permission(
                "physical chat scope required".into(),
            ));
        }
        let Some((owner_id, _)) = locked_group_row(&mut tx, conversation_id, scope).await? else {
            return Err(AstralError::Permission(
                "active scoped group required".into(),
            ));
        };
        if owner_id != Some(old_owner_id)
            || locked_member_role(&mut tx, conversation_id, old_owner_id)
                .await?
                .as_deref()
                != Some("OWNER")
        {
            return Err(AstralError::Permission(
                "current group owner required".into(),
            ));
        }
        if locked_member_role(&mut tx, conversation_id, new_owner_id)
            .await?
            .is_none()
            || !target_has_unique_eligible_pair(
                &mut tx,
                new_owner_id,
                scope.user_card_tenant_id,
                scope.user_card_domain_id,
            )
            .await?
        {
            return Err(AstralError::Permission(
                "new owner must be an eligible member in this tenant/domain".into(),
            ));
        }
        let result = sqlx::query("UPDATE chat_conversation SET owner_id = ? WHERE id = ? AND owner_id = ? AND domain_id = ? AND conversation_type = 'GROUP' AND status = 'ACTIVE' AND is_deleted = 0")
            .bind(new_owner_id).bind(conversation_id).bind(old_owner_id).bind(scope.user_card_domain_id)
            .execute(&mut *tx).await.map_err(db_error)?;
        if result.rows_affected() != 1 {
            return Err(AstralError::Permission(
                "group owner transfer lost conversation fence".into(),
            ));
        }
        let old = sqlx::query("UPDATE chat_conversation_member SET role = 'ADMIN' WHERE conversation_id = ? AND user_id = ? AND role = 'OWNER' AND left_at IS NULL")
            .bind(conversation_id).bind(old_owner_id).execute(&mut *tx).await.map_err(db_error)?;
        let new = sqlx::query("UPDATE chat_conversation_member SET role = 'OWNER' WHERE conversation_id = ? AND user_id = ? AND left_at IS NULL")
            .bind(conversation_id).bind(new_owner_id).execute(&mut *tx).await.map_err(db_error)?;
        if old.rows_affected() != 1 || new.rows_affected() != 1 {
            return Err(AstralError::Database(
                "group ownership transfer member rows changed concurrently".into(),
            ));
        }
        tx.commit().await.map_err(db_error)
    }
    async fn is_member(&self, conversation_id: i64, user_id: i64) -> Result<bool, AstralError> {
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM chat_conversation_member WHERE conversation_id = ? AND user_id = ? AND left_at IS NULL",
        )
        .bind(conversation_id)
        .bind(user_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)?;
        Ok(count.0 > 0)
    }

    async fn member_role(
        &self,
        conversation_id: i64,
        user_id: i64,
    ) -> Result<Option<String>, AstralError> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT role FROM chat_conversation_member WHERE conversation_id = ? AND user_id = ? AND left_at IS NULL",
        )
        .bind(conversation_id)
        .bind(user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)?;
        Ok(row.map(|r| r.0))
    }

    async fn count_members(&self, conversation_id: i64) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM chat_conversation_member WHERE conversation_id = ?",
        )
        .bind(conversation_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)
    }

    async fn list_member_ids(&self, conversation_id: i64) -> Result<Vec<i64>, AstralError> {
        let rows: Vec<(i64,)> = sqlx::query_as(
            "SELECT user_id FROM chat_conversation_member WHERE conversation_id = ? AND left_at IS NULL",
        )
        .bind(conversation_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    async fn list_user_ids(
        &self,
        conversation_id: i64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<i64>, AstralError> {
        let rows: Vec<(i64,)> = sqlx::query_as(
            "SELECT user_id FROM chat_conversation_member WHERE conversation_id = ? LIMIT ? OFFSET ?",
        )
        .bind(conversation_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    async fn list_group_members(
        &self,
        conversation_id: i64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<GroupMemberRecord>, AstralError> {
        sqlx::query_as::<_, GroupMemberRecord>(
            "SELECT user_id, role, nickname, muted, pinned, joined_at \
             FROM chat_conversation_member WHERE conversation_id = ? ORDER BY \
             CASE role WHEN 'OWNER' THEN 0 WHEN 'ADMIN' THEN 1 ELSE 2 END, joined_at ASC \
             LIMIT ? OFFSET ?",
        )
        .bind(conversation_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn member_count(&self, conversation_id: i64, user_id: i64) -> Result<i64, AstralError> {
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM chat_conversation_member WHERE conversation_id = ? AND user_id = ? AND left_at IS NULL",
        )
        .bind(conversation_id)
        .bind(user_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)?;
        Ok(count.0)
    }

    async fn add_member(
        &self,
        conversation_id: i64,
        user_id: i64,
        role: &str,
        invite_by: Option<i64>,
    ) -> Result<(), AstralError> {
        sqlx::query(
            "INSERT INTO chat_conversation_member (conversation_id, user_id, role, invite_by) VALUES (?, ?, ?, ?)",
        )
        .bind(conversation_id)
        .bind(user_id)
        .bind(role)
        .bind(invite_by)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn add_member_ignore(
        &self,
        conversation_id: i64,
        user_id: i64,
    ) -> Result<(), AstralError> {
        sqlx::query(
            "INSERT IGNORE INTO chat_conversation_member (conversation_id, user_id) VALUES (?, ?)",
        )
        .bind(conversation_id)
        .bind(user_id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn remove_member(&self, conversation_id: i64, user_id: i64) -> Result<u64, AstralError> {
        let result = sqlx::query(
            "DELETE FROM chat_conversation_member WHERE conversation_id = ? AND user_id = ?",
        )
        .bind(conversation_id)
        .bind(user_id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected())
    }

    async fn last_read_message_id(
        &self,
        conversation_id: i64,
        user_id: i64,
    ) -> Result<Option<i64>, AstralError> {
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT last_read_message_id FROM chat_conversation_member WHERE conversation_id = ? AND user_id = ?",
        )
        .bind(conversation_id)
        .bind(user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)?;
        Ok(row.map(|r| r.0))
    }

    async fn mark_read(
        &self,
        conversation_id: i64,
        user_id: i64,
        last_read_message_id: i64,
    ) -> Result<(), AstralError> {
        // GREATEST(COALESCE(...))：新建行 last_read_message_id 为 NULL 时
        // GREATEST(NULL, VALUES(x)) 会返回 NULL，必须 COALESCE 兜底（对齐 realtime 写法）
        sqlx::query(
            "INSERT INTO chat_conversation_member (conversation_id, user_id, last_read_message_id) \
             VALUES (?, ?, ?) \
             ON DUPLICATE KEY UPDATE last_read_message_id = GREATEST(COALESCE(last_read_message_id, 0), VALUES(last_read_message_id))",
        )
        .bind(conversation_id)
        .bind(user_id)
        .bind(last_read_message_id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn update_last_read(
        &self,
        conversation_id: i64,
        user_id: i64,
        read_message_id: i64,
    ) -> Result<(), AstralError> {
        sqlx::query(
            "UPDATE chat_conversation_member SET last_read_message_id = GREATEST(COALESCE(last_read_message_id, 0), ?) \
             WHERE conversation_id = ? AND user_id = ?",
        )
        .bind(read_message_id)
        .bind(conversation_id)
        .bind(user_id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn transfer_group_owner(
        &self,
        conversation_id: i64,
        old_owner_id: i64,
        new_owner_id: i64,
    ) -> Result<(), AstralError> {
        // 单事务收敛（对齐 Java transferOwner 事务语义；此前 3 条独立 UPDATE
        // 存在崩溃中间态：owner_id 已换但成员角色未同步）
        let mut tx = self.db.begin().await.map_err(db_error)?;
        sqlx::query("UPDATE chat_conversation SET owner_id = ? WHERE id = ?")
            .bind(new_owner_id)
            .bind(conversation_id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        sqlx::query(
            "UPDATE chat_conversation_member SET role = 'ADMIN' WHERE conversation_id = ? AND user_id = ?",
        )
        .bind(conversation_id)
        .bind(old_owner_id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        sqlx::query(
            "UPDATE chat_conversation_member SET role = 'OWNER' WHERE conversation_id = ? AND user_id = ?",
        )
        .bind(conversation_id)
        .bind(new_owner_id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        tx.commit().await.map_err(db_error)?;
        Ok(())
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Member repository query failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Execute;

    #[test]
    fn conversation_lock_sql_is_parameterized_and_has_no_literal_backslash() {
        let query = sqlx::query::<sqlx::MySql>(LOCK_ACTIVE_CONVERSATION_SQL);
        let emitted = query.sql();
        assert!(!emitted.contains('\\'));
        assert!(emitted.contains("id = ? AND domain_id = ?"));
        assert!(emitted.ends_with("FOR UPDATE"));
    }
}
