//! 用户管理数据访问 — UserRepository
//!
//! 对齐 Java `PlatformUserMapper` + `UserLocalCredentialMapper` 边界。
//! 只返回领域记录，不返回 Axum/HTTP 类型。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_db::{append_eligibility_events_for_cards_in_tx, EligibilityCardSelector};
use astral_types::{AstralError, UserCard};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserListRecord {
    pub user_id: i64,
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub status: String,
}

/// user_card 基础行（对齐 platform_v4.user_card 真实列名）。
#[derive(Debug, Clone, sqlx::FromRow)]
struct UserCardRow {
    card_id: i64,
    user_id: Option<i64>,
    domain_id: Option<i64>,
    card_type: String,
    card_status: String,
    template_id: Option<i64>,
    level_id: Option<i64>,
    priority: Option<i32>,
    is_primary: Option<bool>,
    valid_from: Option<String>,
    valid_until: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
    tenant_id: Option<i64>,
}

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn count_users(&self) -> Result<i64, AstralError>;

    async fn list_users(&self, size: i64, offset: i64) -> Result<Vec<UserListRecord>, AstralError>;

    async fn get_user(&self, user_id: i64) -> Result<Option<UserListRecord>, AstralError>;

    /// 单条 COALESCE 更新，对齐 Java 单实体更新与 profile 更新模式。
    async fn update_user(
        &self,
        user_id: i64,
        display_name: Option<&str>,
        email: Option<&str>,
        phone: Option<&str>,
        status: Option<&str>,
    ) -> Result<(), AstralError>;

    async fn update_user_status(&self, user_id: i64, status: &str) -> Result<(), AstralError>;

    async fn soft_delete_user(&self, user_id: i64) -> Result<(), AstralError>;

    async fn list_user_cards(&self, user_id: i64) -> Result<Vec<UserCard>, AstralError>;
}

pub struct SqlxUserRepository {
    db: MySqlPool,
}

impl SqlxUserRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

async fn lock_existing_user(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    user_id: i64,
) -> Result<Option<String>, AstralError> {
    sqlx::query_as::<_, (String,)>(
        "SELECT status FROM platform_user \
         WHERE user_id = ? AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await
    .map(|row| row.map(|(status,)| status))
    .map_err(|e| AstralError::Database(format!("Lock user failed: {e}")))
}

fn status_change_requires_eligibility_event(
    previous_status: &str,
    requested_status: Option<&str>,
) -> bool {
    requested_status.is_some_and(|status| previous_status != status.trim())
}

fn soft_delete_requires_eligibility_event(previous_status: Option<&str>) -> bool {
    previous_status.is_some()
}

#[async_trait]
impl UserRepository for SqlxUserRepository {
    async fn count_users(&self) -> Result<i64, AstralError> {
        let total: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM platform_user WHERE deleted_at IS NULL")
                .fetch_one(&self.db)
                .await
                .map_err(|e| AstralError::Database(format!("Count users failed: {e}")))?;
        Ok(total.0)
    }

    async fn list_users(&self, size: i64, offset: i64) -> Result<Vec<UserListRecord>, AstralError> {
        sqlx::query_as::<_, UserListRecord>(
            "SELECT u.user_id, c.login_name as username, u.display_name, u.email, u.phone, u.status \
             FROM platform_user u \
             LEFT JOIN user_local_credential c ON c.user_id = u.user_id \
             WHERE u.deleted_at IS NULL \
             ORDER BY u.user_id LIMIT ? OFFSET ?",
        )
        .bind(size)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AstralError::Database(format!("List users failed: {e}")))
    }

    async fn get_user(&self, user_id: i64) -> Result<Option<UserListRecord>, AstralError> {
        sqlx::query_as::<_, UserListRecord>(
            "SELECT u.user_id, c.login_name as username, u.display_name, u.email, u.phone, u.status \
             FROM platform_user u \
             LEFT JOIN user_local_credential c ON c.user_id = u.user_id \
             WHERE u.user_id = ? AND u.deleted_at IS NULL",
        )
        .bind(user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AstralError::Database(format!("Get user failed: {e}")))
    }

    async fn update_user(
        &self,
        user_id: i64,
        display_name: Option<&str>,
        email: Option<&str>,
        phone: Option<&str>,
        status: Option<&str>,
    ) -> Result<(), AstralError> {
        // Profile-only updates do not affect card eligibility. Keep this path
        // free of projection work; the status-bearing path below owns the
        // source mutation and ELIGIBILITY fanout transaction.
        if status.is_none() {
            sqlx::query(
                "UPDATE platform_user SET \
                 display_name = COALESCE(?, display_name), \
                 email = COALESCE(?, email), \
                 phone = COALESCE(?, phone), \
                 updated_at = UTC_TIMESTAMP() \
                 WHERE user_id = ? AND deleted_at IS NULL",
            )
            .bind(display_name.map(str::trim))
            .bind(email.map(str::trim))
            .bind(phone.map(str::trim))
            .bind(user_id)
            .execute(&self.db)
            .await
            .map_err(|e| AstralError::Database(format!("Update user profile failed: {e}")))?;
            return Ok(());
        }

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AstralError::Database(format!("Begin update user tx failed: {e}")))?;
        let previous_status = lock_existing_user(&mut tx, user_id).await?;
        let Some(previous_status) = previous_status else {
            return Ok(());
        };
        let emit_eligibility = status_change_requires_eligibility_event(&previous_status, status);

        sqlx::query(
            "UPDATE platform_user SET \
             display_name = COALESCE(?, display_name), \
             email = COALESCE(?, email), \
             phone = COALESCE(?, phone), \
             status = COALESCE(?, status), \
             updated_at = UTC_TIMESTAMP() \
             WHERE user_id = ? AND deleted_at IS NULL",
        )
        .bind(display_name.map(str::trim))
        .bind(email.map(str::trim))
        .bind(phone.map(str::trim))
        .bind(status.map(str::trim))
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AstralError::Database(format!("Update user failed: {e}")))?;

        if emit_eligibility {
            append_eligibility_events_for_cards_in_tx(
                &mut tx,
                EligibilityCardSelector::ByUserId { user_id },
            )
            .await?;
        }
        tx.commit()
            .await
            .map_err(|e| AstralError::Database(format!("Commit update user tx failed: {e}")))?;
        Ok(())
    }

    async fn update_user_status(&self, user_id: i64, status: &str) -> Result<(), AstralError> {
        let mut tx = self.db.begin().await.map_err(|e| {
            AstralError::Database(format!("Begin update user status tx failed: {e}"))
        })?;
        let previous_status = lock_existing_user(&mut tx, user_id).await?;
        let Some(previous_status) = previous_status else {
            return Ok(());
        };
        let requested_status = status.trim();
        let status_changed = previous_status != requested_status;

        sqlx::query(
            "UPDATE platform_user SET status = ?, updated_at = UTC_TIMESTAMP() \
             WHERE user_id = ? AND deleted_at IS NULL",
        )
        .bind(requested_status)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AstralError::Database(format!("Update user status failed: {e}")))?;
        if status_changed {
            append_eligibility_events_for_cards_in_tx(
                &mut tx,
                EligibilityCardSelector::ByUserId { user_id },
            )
            .await?;
        }
        tx.commit().await.map_err(|e| {
            AstralError::Database(format!("Commit update user status tx failed: {e}"))
        })?;
        Ok(())
    }

    async fn soft_delete_user(&self, user_id: i64) -> Result<(), AstralError> {
        let mut tx =
            self.db.begin().await.map_err(|e| {
                AstralError::Database(format!("Begin soft delete user tx failed: {e}"))
            })?;
        let previous_status = lock_existing_user(&mut tx, user_id).await?;
        if !soft_delete_requires_eligibility_event(previous_status.as_deref()) {
            return Ok(());
        }

        sqlx::query(
            "UPDATE platform_user SET deleted_at = CURRENT_TIMESTAMP \
             WHERE user_id = ? AND deleted_at IS NULL",
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AstralError::Database(format!("Soft delete user failed: {e}")))?;
        append_eligibility_events_for_cards_in_tx(
            &mut tx,
            EligibilityCardSelector::ByUserId { user_id },
        )
        .await?;
        tx.commit().await.map_err(|e| {
            AstralError::Database(format!("Commit soft delete user tx failed: {e}"))
        })?;
        Ok(())
    }

    async fn list_user_cards(&self, user_id: i64) -> Result<Vec<UserCard>, AstralError> {
        let rows = sqlx::query_as::<_, UserCardRow>(
            "SELECT card_id, user_id, domain_id, card_type, card_status, template_id, \
             level_id, priority, is_primary, valid_from, valid_until, created_at, updated_at, tenant_id \
             FROM user_card WHERE user_id = ? ORDER BY card_id",
        )
        .bind(user_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AstralError::Database(format!("List user cards failed: {e}")))?;

        Ok(rows
            .into_iter()
            .map(|r| UserCard {
                card_id: Some(r.card_id),
                user_id: r.user_id,
                domain_id: r.domain_id,
                card_type: r.card_type,
                card_status: r.card_status,
                template_id: r.template_id,
                level_id: r.level_id,
                priority: r.priority,
                is_primary: r.is_primary,
                valid_from: r.valid_from,
                valid_until: r.valid_until,
                created_at: r.created_at,
                updated_at: r.updated_at,
                tenant_id: r.tenant_id,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::{soft_delete_requires_eligibility_event, status_change_requires_eligibility_event};

    #[test]
    fn profile_only_update_does_not_emit_eligibility_event() {
        assert!(!status_change_requires_eligibility_event("ACTIVE", None));
    }

    #[test]
    fn unchanged_status_does_not_emit_eligibility_event() {
        assert!(!status_change_requires_eligibility_event(
            "ACTIVE",
            Some(" ACTIVE ")
        ));
    }

    #[test]
    fn changed_status_emits_eligibility_event() {
        assert!(status_change_requires_eligibility_event(
            "ACTIVE",
            Some("DISABLED")
        ));
    }

    #[test]
    fn soft_delete_emits_for_any_existing_user() {
        assert!(soft_delete_requires_eligibility_event(Some("ACTIVE")));
        assert!(soft_delete_requires_eligibility_event(Some("DISABLED")));
        assert!(!soft_delete_requires_eligibility_event(None));
    }
}
