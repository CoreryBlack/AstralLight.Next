//! 权限继承配置数据访问 — InheritanceConfigRepository
//!
//! 对齐 Java `PermissionInheritanceConfigMapper` 边界（permission_inheritance_config 表）。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::AstralError;

/// 继承配置记录
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct InheritanceConfigRecord {
    pub id: i64,
    pub resource_type: String,
    pub inheritance_mode: String,
    pub updated_at: Option<i64>,
}

const INHERIT_SELECT_COLUMNS: &str = "id, resource_type, inheritance_mode, \
     UNIX_TIMESTAMP(updated_at) as updated_at";

#[async_trait]
pub trait InheritanceConfigRepository: Send + Sync {
    async fn count_configs(&self) -> Result<i64, AstralError>;
    /// 分页列表（ORDER BY resource_type）
    async fn list_configs(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<InheritanceConfigRecord>, AstralError>;
    /// 原子 UPSERT（idx_pic_resource_type UNIQUE 约束，无竞态）
    async fn upsert_by_resource_type(
        &self,
        resource_type: &str,
        inheritance_mode: &str,
    ) -> Result<(), AstralError>;
    /// UPSERT 后按 resource_type 查回
    async fn get_by_resource_type(
        &self,
        resource_type: &str,
    ) -> Result<InheritanceConfigRecord, AstralError>;
    /// 按 id 更新，返回是否命中
    async fn update_by_id(&self, id: i64, inheritance_mode: &str) -> Result<bool, AstralError>;
    /// 按 id 删除，返回是否命中（legacy/internal compatibility）
    async fn delete_by_id(&self, id: i64) -> Result<bool, AstralError>;
    /// 按 registered resource type 删除，返回是否命中。
    async fn delete_by_resource_type(&self, resource_type: &str) -> Result<bool, AstralError>;
}

pub struct SqlxInheritanceConfigRepository {
    db: MySqlPool,
}

impl SqlxInheritanceConfigRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

#[async_trait]
impl InheritanceConfigRepository for SqlxInheritanceConfigRepository {
    async fn count_configs(&self) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM permission_inheritance_config")
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_configs(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<InheritanceConfigRecord>, AstralError> {
        sqlx::query_as::<_, InheritanceConfigRecord>(&format!(
            "SELECT {INHERIT_SELECT_COLUMNS} FROM permission_inheritance_config \
             ORDER BY resource_type LIMIT ? OFFSET ?"
        ))
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn upsert_by_resource_type(
        &self,
        resource_type: &str,
        inheritance_mode: &str,
    ) -> Result<(), AstralError> {
        sqlx::query(
            "INSERT INTO permission_inheritance_config (resource_type, inheritance_mode) \
             VALUES (?, ?) \
             ON DUPLICATE KEY UPDATE inheritance_mode = VALUES(inheritance_mode)",
        )
        .bind(resource_type)
        .bind(inheritance_mode)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn get_by_resource_type(
        &self,
        resource_type: &str,
    ) -> Result<InheritanceConfigRecord, AstralError> {
        sqlx::query_as::<_, InheritanceConfigRecord>(&format!(
            "SELECT {INHERIT_SELECT_COLUMNS} FROM permission_inheritance_config WHERE resource_type = ?"
        ))
        .bind(resource_type)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)
    }

    async fn update_by_id(&self, id: i64, inheritance_mode: &str) -> Result<bool, AstralError> {
        let result = sqlx::query(
            "UPDATE permission_inheritance_config SET inheritance_mode = ? WHERE id = ?",
        )
        .bind(inheritance_mode)
        .bind(id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_by_id(&self, id: i64) -> Result<bool, AstralError> {
        let result = sqlx::query("DELETE FROM permission_inheritance_config WHERE id = ?")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_by_resource_type(&self, resource_type: &str) -> Result<bool, AstralError> {
        let result =
            sqlx::query("DELETE FROM permission_inheritance_config WHERE resource_type = ?")
                .bind(resource_type)
                .execute(&self.db)
                .await
                .map_err(db_error)?;
        Ok(result.rows_affected() > 0)
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!(
        "Inheritance config repository query failed: {error}"
    ))
}
