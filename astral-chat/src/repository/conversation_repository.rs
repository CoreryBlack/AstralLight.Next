//! 会话/群组数据访问 — ConversationRepository
//!
//! 对齐 Java `ChatConversationMapper` 边界（chat_conversation 表）。
//! 跨 chat_conversation + chat_conversation_member 的读聚合（member_count）与
//! 写事务（群主转让）收敛于此层；角色校验与副作用编排在 service。

use std::collections::HashMap;

use async_trait::async_trait;
use sqlx::{MySqlPool, QueryBuilder};

use astral_types::AstralError;

use crate::scope::ChatScope;

/// 会话行（chat_conversation，含别名映射后的字段名）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ConversationRecord {
    pub id: i64,
    pub name: String,
    pub conversation_type: String,
    pub owner_id: Option<i64>,
    pub avatar: Option<String>,
    pub max_members: i64,
    pub status: String,
    pub created_at: Option<time::PrimitiveDateTime>,
}

/// 会话列表行（带 member_count 子查询，修复 N+1）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ChatSessionRecord {
    pub id: i64,
    pub name: String,
    pub conversation_type: String,
    pub created_at: Option<time::PrimitiveDateTime>,
    pub member_count: i64,
}

/// 群成员数聚合行（batch count）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ConversationCountRow {
    pub id: i64,
    pub member_count: i64,
}

/// 群组信息部分更新补丁（仅更新非 None 字段，对齐现有 handler 逐个字段更新语义）
#[derive(Debug, Default)]
pub struct GroupPatch {
    pub name: Option<String>,
    pub avatar: Option<String>,
    pub max_members: Option<i64>,
}

#[async_trait]
pub trait ConversationRepository: Send + Sync {
    /// Creates a conversation inside the authenticated user-card domain.
    async fn create_conversation_scoped(
        &self,
        scope: &ChatScope,
        name: &str,
        conversation_type: &str,
    ) -> Result<i64, AstralError> {
        let _ = (scope, name, conversation_type);
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }
    /// Atomically creates a conversation and its first member.
    async fn create_conversation_with_creator_scoped(
        &self,
        scope: &ChatScope,
        name: &str,
        conversation_type: &str,
    ) -> Result<i64, AstralError> {
        let _ = (scope, name, conversation_type);
        Err(AstralError::Permission(
            "scoped atomic creation required".into(),
        ))
    }
    /// 创建会话（会话无 owner/avatar/max_members），返回新 id
    async fn create_conversation(
        &self,
        name: &str,
        conversation_type: &str,
    ) -> Result<i64, AstralError>;
    /// 创建群组（GROUP 类型 + owner + avatar + max_members），返回新 id
    async fn create_group(
        &self,
        name: &str,
        owner_id: i64,
        avatar: Option<&str>,
        max_members: i64,
    ) -> Result<i64, AstralError>;
    async fn create_group_scoped(
        &self,
        scope: &ChatScope,
        name: &str,
        owner_id: i64,
        avatar: Option<&str>,
        max_members: i64,
    ) -> Result<i64, AstralError> {
        let _ = (scope, name, owner_id, avatar, max_members);
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }
    /// 会话是否存在（send_message 前置检查）
    async fn session_exists(&self, id: i64) -> Result<bool, AstralError>;
    async fn session_exists_scoped(&self, scope: &ChatScope, id: i64) -> Result<bool, AstralError> {
        let _ = (scope, id);
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }
    /// 查询会话/群组（未过滤状态；group 校验在 service）
    async fn get_conversation(&self, id: i64) -> Result<Option<ConversationRecord>, AstralError>;
    async fn get_conversation_scoped(
        &self,
        scope: &ChatScope,
        id: i64,
    ) -> Result<Option<ConversationRecord>, AstralError> {
        let _ = (scope, id);
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }
    /// 查询群组（conversation_type='GROUP' AND status='ACTIVE'）
    async fn get_group(&self, id: i64) -> Result<Option<ConversationRecord>, AstralError>;
    async fn get_group_scoped(
        &self,
        scope: &ChatScope,
        id: i64,
    ) -> Result<Option<ConversationRecord>, AstralError> {
        let _ = (scope, id);
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }
    /// 当前用户参与的会话总数
    async fn count_sessions_for_user(&self, user_id: i64) -> Result<i64, AstralError>;
    async fn count_sessions_for_scope(&self, scope: &ChatScope) -> Result<i64, AstralError> {
        let _ = scope;
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }
    /// 当前用户参与的会话分页（member_count 子查询，无 N+1）
    async fn list_sessions_for_user(
        &self,
        user_id: i64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ChatSessionRecord>, AstralError>;
    async fn list_sessions_for_scope(
        &self,
        scope: &ChatScope,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ChatSessionRecord>, AstralError> {
        let _ = (scope, limit, offset);
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }
    /// 当前用户加入的活跃群组总数
    async fn count_groups_for_user(&self, user_id: i64) -> Result<i64, AstralError>;
    async fn count_groups_for_scope(&self, scope: &ChatScope) -> Result<i64, AstralError> {
        let _ = scope;
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }
    /// 当前用户加入的活跃群组分页
    async fn list_groups_for_user(
        &self,
        user_id: i64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ConversationRecord>, AstralError>;
    async fn list_groups_for_scope(
        &self,
        scope: &ChatScope,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ConversationRecord>, AstralError> {
        let _ = (scope, limit, offset);
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }
    /// 批量查询群成员数（修复 list_groups N+1）
    async fn count_members_batch(&self, ids: &[i64]) -> Result<HashMap<i64, i64>, AstralError>;
    /// 会话成员总数
    async fn count_members(&self, conversation_id: i64) -> Result<i64, AstralError>;
    async fn count_members_batch_scoped(
        &self,
        scope: &ChatScope,
        ids: &[i64],
    ) -> Result<HashMap<i64, i64>, AstralError> {
        let _ = (scope, ids);
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }
    /// 更新会话名称（update_session）
    async fn update_name(&self, id: i64, name: &str) -> Result<(), AstralError>;
    async fn update_name_scoped(
        &self,
        scope: &ChatScope,
        id: i64,
        name: &str,
    ) -> Result<(), AstralError> {
        let _ = (scope, id, name);
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }
    /// 部分更新群组字段（仅 GROUP 类型行生效）
    async fn update_group(&self, id: i64, patch: &GroupPatch) -> Result<(), AstralError>;
    async fn update_group_scoped(
        &self,
        scope: &ChatScope,
        id: i64,
        patch: &GroupPatch,
    ) -> Result<(), AstralError> {
        let _ = (scope, id, patch);
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }
    /// 软解散群组（status='DISBANDED'）
    async fn disband_group(&self, id: i64) -> Result<(), AstralError>;
    async fn disband_group_scoped(&self, scope: &ChatScope, id: i64) -> Result<(), AstralError> {
        let _ = (scope, id);
        Err(AstralError::Permission(
            "physical chat scope required".into(),
        ))
    }
    /// 更新会话最后一条消息（send 非关键路径，失败仅告警）
    async fn update_last_message(&self, id: i64, message_id: i64) -> Result<(), AstralError>;
}

pub struct SqlxConversationRepository {
    db: MySqlPool,
}

impl SqlxConversationRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

const CONVERSATION_SELECT: &str =
    "SELECT id, name, conversation_type AS conversation_type, owner_id, \
     avatar AS avatar, max_members, status, created_at FROM chat_conversation";

#[async_trait]
impl ConversationRepository for SqlxConversationRepository {
    async fn create_conversation_scoped(
        &self,
        scope: &ChatScope,
        name: &str,
        conversation_type: &str,
    ) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO chat_conversation (name, conversation_type, domain_id) VALUES (?, ?, ?)",
        )
        .bind(name)
        .bind(conversation_type)
        .bind(scope.user_card_domain_id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
    }

    async fn create_conversation_with_creator_scoped(
        &self,
        scope: &ChatScope,
        name: &str,
        conversation_type: &str,
    ) -> Result<i64, AstralError> {
        let mut tx = self.db.begin().await.map_err(db_error)?;
        let result = sqlx::query(
            "INSERT INTO chat_conversation (name, conversation_type, domain_id) VALUES (?, ?, ?)",
        )
        .bind(name)
        .bind(conversation_type)
        .bind(scope.user_card_domain_id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        let conversation_id = result.last_insert_id() as i64;
        sqlx::query(
            "INSERT INTO chat_conversation_member (conversation_id, user_id, role) VALUES (?, ?, 'MEMBER')",
        )
        .bind(conversation_id)
        .bind(scope.user_id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        tx.commit().await.map_err(db_error)?;
        Ok(conversation_id)
    }

    async fn create_group_scoped(
        &self,
        scope: &ChatScope,
        name: &str,
        owner_id: i64,
        avatar: Option<&str>,
        max_members: i64,
    ) -> Result<i64, AstralError> {
        let mut tx = self.db.begin().await.map_err(db_error)?;
        let result = sqlx::query(
            "INSERT INTO chat_conversation (name, conversation_type, owner_id, avatar, max_members, status, domain_id) \
             VALUES (?, 'GROUP', ?, ?, ?, 'ACTIVE', ?)",
        )
        .bind(name)
        .bind(owner_id)
        .bind(avatar)
        .bind(max_members)
        .bind(scope.user_card_domain_id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        let conversation_id = result.last_insert_id() as i64;
        sqlx::query(
            "INSERT INTO chat_conversation_member (conversation_id, user_id, role) VALUES (?, ?, 'OWNER')",
        )
        .bind(conversation_id)
        .bind(owner_id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        tx.commit().await.map_err(db_error)?;
        Ok(conversation_id)
    }

    async fn get_conversation_scoped(
        &self,
        scope: &ChatScope,
        id: i64,
    ) -> Result<Option<ConversationRecord>, AstralError> {
        sqlx::query_as::<_, ConversationRecord>(&format!(
            "{CONVERSATION_SELECT} WHERE id = ? AND domain_id = ? AND is_deleted = 0"
        ))
        .bind(id)
        .bind(scope.user_card_domain_id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn get_group_scoped(
        &self,
        scope: &ChatScope,
        id: i64,
    ) -> Result<Option<ConversationRecord>, AstralError> {
        sqlx::query_as::<_, ConversationRecord>(&format!(
            "{CONVERSATION_SELECT} WHERE id = ? AND domain_id = ? AND conversation_type = 'GROUP' \
             AND status = 'ACTIVE' AND is_deleted = 0"
        ))
        .bind(id)
        .bind(scope.user_card_domain_id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn count_sessions_for_scope(&self, scope: &ChatScope) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM chat_conversation s \
             WHERE s.domain_id = ? AND s.is_deleted = 0 \
               AND EXISTS (SELECT 1 FROM chat_conversation_member m \
                           WHERE m.conversation_id = s.id AND m.user_id = ? AND m.left_at IS NULL)",
        )
        .bind(scope.user_card_domain_id)
        .bind(scope.user_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)
    }

    async fn list_sessions_for_scope(
        &self,
        scope: &ChatScope,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ChatSessionRecord>, AstralError> {
        sqlx::query_as::<_, ChatSessionRecord>(
            "SELECT s.id, s.name, s.conversation_type AS conversation_type, s.created_at, \
             (SELECT COUNT(*) FROM chat_conversation_member m WHERE m.conversation_id = s.id \
              AND m.left_at IS NULL) AS member_count \
             FROM chat_conversation s \
             WHERE s.domain_id = ? AND s.is_deleted = 0 \
               AND EXISTS (SELECT 1 FROM chat_conversation_member m \
                           WHERE m.conversation_id = s.id AND m.user_id = ? AND m.left_at IS NULL) \
             ORDER BY s.id DESC LIMIT ? OFFSET ?",
        )
        .bind(scope.user_card_domain_id)
        .bind(scope.user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn count_groups_for_scope(&self, scope: &ChatScope) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM chat_conversation s \
             WHERE s.domain_id = ? AND s.is_deleted = 0 \
               AND s.conversation_type = 'GROUP' AND s.status = 'ACTIVE' \
               AND EXISTS (SELECT 1 FROM chat_conversation_member m \
                           WHERE m.conversation_id = s.id AND m.user_id = ? AND m.left_at IS NULL)",
        )
        .bind(scope.user_card_domain_id)
        .bind(scope.user_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)
    }

    async fn list_groups_for_scope(
        &self,
        scope: &ChatScope,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ConversationRecord>, AstralError> {
        sqlx::query_as::<_, ConversationRecord>(&format!(
            "{CONVERSATION_SELECT} WHERE domain_id = ? AND is_deleted = 0 \
             AND conversation_type = 'GROUP' AND status = 'ACTIVE' \
             AND EXISTS (SELECT 1 FROM chat_conversation_member m \
                         WHERE m.conversation_id = chat_conversation.id AND m.user_id = ? AND m.left_at IS NULL) \
             ORDER BY id DESC LIMIT ? OFFSET ?"
        ))
        .bind(scope.user_card_domain_id)
        .bind(scope.user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn create_conversation(
        &self,
        name: &str,
        conversation_type: &str,
    ) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO chat_conversation (name, conversation_type, domain_id) VALUES (?, ?, 0)",
        )
        .bind(name)
        .bind(conversation_type)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
    }

    async fn create_group(
        &self,
        name: &str,
        owner_id: i64,
        avatar: Option<&str>,
        max_members: i64,
    ) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO chat_conversation (name, conversation_type, owner_id, avatar, max_members, status, domain_id) \
             VALUES (?, 'GROUP', ?, ?, ?, 'ACTIVE', 0)",
        )
        .bind(name)
        .bind(owner_id)
        .bind(avatar)
        .bind(max_members)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
    }

    async fn session_exists_scoped(&self, scope: &ChatScope, id: i64) -> Result<bool, AstralError> {
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM chat_conversation WHERE id = ? AND domain_id = ? AND status = 'ACTIVE' AND is_deleted = 0",
        )
        .bind(id)
        .bind(scope.user_card_domain_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)?;
        Ok(count.0 == 1)
    }

    async fn session_exists(&self, id: i64) -> Result<bool, AstralError> {
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM chat_conversation WHERE id = ?")
            .bind(id)
            .fetch_one(&self.db)
            .await
            .map_err(db_error)?;
        Ok(count.0 > 0)
    }

    async fn get_conversation(&self, id: i64) -> Result<Option<ConversationRecord>, AstralError> {
        sqlx::query_as::<_, ConversationRecord>(&format!("{CONVERSATION_SELECT} WHERE id = ?"))
            .bind(id)
            .fetch_optional(&self.db)
            .await
            .map_err(db_error)
    }

    async fn get_group(&self, id: i64) -> Result<Option<ConversationRecord>, AstralError> {
        sqlx::query_as::<_, ConversationRecord>(&format!(
            "{CONVERSATION_SELECT} WHERE id = ? AND conversation_type = 'GROUP' AND status = 'ACTIVE'"
        ))
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn count_sessions_for_user(&self, user_id: i64) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM chat_conversation s \
             WHERE s.id IN (SELECT conversation_id FROM chat_conversation_member WHERE user_id = ?)",
        )
        .bind(user_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)
    }

    async fn list_sessions_for_user(
        &self,
        user_id: i64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ChatSessionRecord>, AstralError> {
        // 单查询获取会话+成员数（修复 N+1；platform_v4: conversation_type as conversation_type）
        sqlx::query_as::<_, ChatSessionRecord>(
            "SELECT s.id, s.name, s.conversation_type AS conversation_type, s.created_at, \
             (SELECT COUNT(*) FROM chat_conversation_member m WHERE m.conversation_id = s.id) AS member_count \
             FROM chat_conversation s \
             WHERE s.id IN (SELECT conversation_id FROM chat_conversation_member WHERE user_id = ?) \
             ORDER BY s.id DESC LIMIT ? OFFSET ?",
        )
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn count_groups_for_user(&self, user_id: i64) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM chat_conversation s \
             WHERE s.id IN (SELECT conversation_id FROM chat_conversation_member WHERE user_id = ?) \
               AND s.conversation_type = 'GROUP' AND s.status = 'ACTIVE'",
        )
        .bind(user_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)
    }

    async fn list_groups_for_user(
        &self,
        user_id: i64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ConversationRecord>, AstralError> {
        sqlx::query_as::<_, ConversationRecord>(&format!(
            "{CONVERSATION_SELECT} s \
             WHERE s.id IN (SELECT conversation_id FROM chat_conversation_member WHERE user_id = ?) \
               AND s.conversation_type = 'GROUP' AND s.status = 'ACTIVE' \
             ORDER BY s.id DESC LIMIT ? OFFSET ?"
        ))
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn count_members_batch_scoped(
        &self,
        scope: &ChatScope,
        ids: &[i64],
    ) -> Result<HashMap<i64, i64>, AstralError> {
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        let mut qb = QueryBuilder::<sqlx::MySql>::new(
            "SELECT m.conversation_id AS id, COUNT(*) AS member_count \
             FROM chat_conversation_member m INNER JOIN chat_conversation c ON c.id = m.conversation_id \
             WHERE m.conversation_id IN (",
        );
        let mut sep = qb.separated(", ");
        for id in ids {
            sep.push_bind(*id);
        }
        qb.push(") AND m.left_at IS NULL AND c.domain_id = ")
            .push_bind(scope.user_card_domain_id)
            .push(" AND c.status = 'ACTIVE' AND c.is_deleted = 0 GROUP BY m.conversation_id");
        let rows = qb
            .build_query_as::<ConversationCountRow>()
            .fetch_all(&self.db)
            .await
            .map_err(db_error)?;
        Ok(rows.into_iter().map(|r| (r.id, r.member_count)).collect())
    }

    async fn count_members_batch(&self, ids: &[i64]) -> Result<HashMap<i64, i64>, AstralError> {
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        let mut qb = QueryBuilder::<sqlx::MySql>::new(
            "SELECT conversation_id AS id, COUNT(*) AS member_count \
             FROM chat_conversation_member WHERE conversation_id IN (",
        );
        let mut sep = qb.separated(", ");
        for id in ids {
            sep.push_bind(*id);
        }
        qb.push(") GROUP BY conversation_id");
        let rows = qb
            .build_query_as::<ConversationCountRow>()
            .fetch_all(&self.db)
            .await
            .map_err(db_error)?;
        Ok(rows.into_iter().map(|r| (r.id, r.member_count)).collect())
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

    async fn update_name_scoped(
        &self,
        scope: &ChatScope,
        id: i64,
        name: &str,
    ) -> Result<(), AstralError> {
        sqlx::query(
            "UPDATE chat_conversation SET name = ? WHERE id = ? AND domain_id = ? AND is_deleted = 0",
        )
        .bind(name)
        .bind(id)
        .bind(scope.user_card_domain_id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn update_group_scoped(
        &self,
        scope: &ChatScope,
        id: i64,
        patch: &GroupPatch,
    ) -> Result<(), AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new("UPDATE chat_conversation SET ");
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
        if let Some(max) = patch.max_members {
            if !first {
                builder.push(", ");
            }
            builder.push("max_members = ").push_bind(max);
            first = false;
        }
        if first {
            return Ok(());
        }
        builder
            .push(" WHERE id = ")
            .push_bind(id)
            .push(" AND domain_id = ")
            .push_bind(scope.user_card_domain_id)
            .push(" AND conversation_type = 'GROUP' AND status = 'ACTIVE' AND is_deleted = 0");
        builder.build().execute(&self.db).await.map_err(db_error)?;
        Ok(())
    }

    async fn disband_group_scoped(&self, scope: &ChatScope, id: i64) -> Result<(), AstralError> {
        sqlx::query(
            "UPDATE chat_conversation SET status = 'DISBANDED' \
             WHERE id = ? AND domain_id = ? AND conversation_type = 'GROUP' AND status = 'ACTIVE' AND is_deleted = 0",
        )
        .bind(id)
        .bind(scope.user_card_domain_id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn update_name(&self, id: i64, name: &str) -> Result<(), AstralError> {
        sqlx::query("UPDATE chat_conversation SET name = ? WHERE id = ?")
            .bind(name)
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn update_group(&self, id: i64, patch: &GroupPatch) -> Result<(), AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new("UPDATE chat_conversation SET ");
        let mut first = true;
        if let Some(name) = &patch.name {
            if !first {
                builder.push(", ");
            }
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
        if let Some(max) = patch.max_members {
            if !first {
                builder.push(", ");
            }
            builder.push("max_members = ").push_bind(max);
            first = false;
        }
        if first {
            // 空补丁：无字段更新
            return Ok(());
        }
        builder.push(" WHERE id = ").push_bind(id);
        builder.push(" AND conversation_type = 'GROUP'");
        builder.build().execute(&self.db).await.map_err(db_error)?;
        Ok(())
    }

    async fn disband_group(&self, id: i64) -> Result<(), AstralError> {
        sqlx::query(
            "UPDATE chat_conversation SET status = 'DISBANDED' \
             WHERE id = ? AND conversation_type = 'GROUP'",
        )
        .bind(id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn update_last_message(&self, id: i64, message_id: i64) -> Result<(), AstralError> {
        sqlx::query(
            "UPDATE chat_conversation SET last_message_id = ?, last_message_time = NOW() WHERE id = ?",
        )
        .bind(message_id)
        .bind(id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Conversation repository query failed: {error}"))
}
