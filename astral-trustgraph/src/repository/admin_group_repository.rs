//! 管理组数据访问 — AdminGroupRepository
//!
//! 对齐 Java `AdminGroupController` 的持久化边界（admin_group + admin_group_member 表）。
//! 删除组先级联删除成员再删组，收敛为**单事务**聚合方法（此前两条独立 DELETE
//! 存在崩溃中间态：成员已删但组残留或反之）。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::AstralError;

/// 管理组行
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AdminGroupRecord {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub scope: String,
}

/// 管理组行（含成员数，LEFT JOIN + GROUP BY 防 N+1）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AdminGroupCountRecord {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub scope: String,
    pub member_count: i64,
}

#[async_trait]
pub trait AdminGroupRepository: Send + Sync {
    /// 全部管理组（含成员数，防 N+1）
    async fn list_with_counts(&self) -> Result<Vec<AdminGroupCountRecord>, AstralError>;
    /// 新建（scope 默认 GLOBAL 由调用方解析），返回新 id
    async fn create(
        &self,
        name: &str,
        description: Option<&str>,
        scope: &str,
    ) -> Result<i64, AstralError>;
    /// 单条
    async fn get(&self, id: i64) -> Result<Option<AdminGroupRecord>, AstralError>;
    /// 更新
    async fn update(
        &self,
        id: i64,
        name: &str,
        description: Option<&str>,
        scope: &str,
    ) -> Result<(), AstralError>;
    /// 删除（单事务：先级联删成员再删组）
    async fn delete(&self, id: i64) -> Result<(), AstralError>;
    /// 组成员 user_id 列表
    async fn list_member_ids(&self, group_id: i64) -> Result<Vec<i64>, AstralError>;
    /// 添加成员（INSERT IGNORE 幂等）
    async fn add_member(&self, group_id: i64, user_id: i64) -> Result<(), AstralError>;
    /// 移除成员
    async fn remove_member(&self, group_id: i64, user_id: i64) -> Result<(), AstralError>;
}

pub struct SqlxAdminGroupRepository {
    db: MySqlPool,
}

impl SqlxAdminGroupRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

const ADMIN_GROUP_SELECT: &str = "SELECT id, name, description, scope FROM admin_group";

#[async_trait]
impl AdminGroupRepository for SqlxAdminGroupRepository {
    async fn list_with_counts(&self) -> Result<Vec<AdminGroupCountRecord>, AstralError> {
        sqlx::query_as::<_, AdminGroupCountRecord>(
            "SELECT g.id, g.name, g.description, g.scope, COUNT(m.user_id) AS member_count \
             FROM admin_group g LEFT JOIN admin_group_member m ON g.id = m.group_id \
             GROUP BY g.id, g.name, g.description, g.scope \
             ORDER BY g.id",
        )
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn create(
        &self,
        name: &str,
        description: Option<&str>,
        scope: &str,
    ) -> Result<i64, AstralError> {
        let result =
            sqlx::query("INSERT INTO admin_group (name, description, scope) VALUES (?, ?, ?)")
                .bind(name)
                .bind(description)
                .bind(scope)
                .execute(&self.db)
                .await
                .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
    }

    async fn get(&self, id: i64) -> Result<Option<AdminGroupRecord>, AstralError> {
        sqlx::query_as::<_, AdminGroupRecord>(&format!("{ADMIN_GROUP_SELECT} WHERE id = ?"))
            .bind(id)
            .fetch_optional(&self.db)
            .await
            .map_err(db_error)
    }

    async fn update(
        &self,
        id: i64,
        name: &str,
        description: Option<&str>,
        scope: &str,
    ) -> Result<(), AstralError> {
        sqlx::query("UPDATE admin_group SET name = ?, description = ?, scope = ? WHERE id = ?")
            .bind(name)
            .bind(description)
            .bind(scope)
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn delete(&self, id: i64) -> Result<(), AstralError> {
        // 单事务：先级联删除成员再删组（此前两条独立 DELETE 存在崩溃中间态）
        let mut tx = self.db.begin().await.map_err(db_error)?;
        sqlx::query("DELETE FROM admin_group_member WHERE group_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        sqlx::query("DELETE FROM admin_group WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        tx.commit().await.map_err(db_error)?;
        Ok(())
    }

    async fn list_member_ids(&self, group_id: i64) -> Result<Vec<i64>, AstralError> {
        let rows: Vec<(i64,)> =
            sqlx::query_as("SELECT user_id FROM admin_group_member WHERE group_id = ?")
                .bind(group_id)
                .fetch_all(&self.db)
                .await
                .map_err(db_error)?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    async fn add_member(&self, group_id: i64, user_id: i64) -> Result<(), AstralError> {
        sqlx::query("INSERT IGNORE INTO admin_group_member (group_id, user_id) VALUES (?, ?)")
            .bind(group_id)
            .bind(user_id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn remove_member(&self, group_id: i64, user_id: i64) -> Result<(), AstralError> {
        sqlx::query("DELETE FROM admin_group_member WHERE group_id = ? AND user_id = ?")
            .bind(group_id)
            .bind(user_id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Admin group repository query failed: {error}"))
}
