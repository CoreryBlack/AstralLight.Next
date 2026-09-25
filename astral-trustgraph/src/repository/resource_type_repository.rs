//! 资源类型数据访问 — ResourceTypeRepository
//!
//! 对齐 Java `DomainResourceTypeMapper` / `ResourceTypeRegistryMapper` 边界
//! （domain_resource_type + resource_type_registry 表）。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::AstralError;

/// domain_resource_type 行（通过别名映射）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DomainResourceTypeRecord {
    pub id: i64,
    pub domain_id: Option<i64>,
    pub code: String,
    pub name: String,
    pub description: Option<String>,
    pub sensitivity_level: Option<String>,
    pub status: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// resource_type_registry 行
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ResourceTypeRegistryRecord {
    pub id: i64,
    pub resource_type: String,
    pub actions_json: String,
    pub description: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[async_trait]
pub trait ResourceTypeRepository: Send + Sync {
    /// domain_resource_type 总数
    async fn count_domain_resource_types(&self) -> Result<i64, AstralError>;
    /// domain_resource_type 分页列表（ORDER BY resource_type_id）
    async fn list_domain_resource_types(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DomainResourceTypeRecord>, AstralError>;
    /// resource_type_registry 全量列表（ORDER BY resource_type）
    async fn list_registry(&self) -> Result<Vec<ResourceTypeRegistryRecord>, AstralError>;
    /// 注册（INSERT IGNORE 幂等）
    async fn insert_ignore_registry(
        &self,
        resource_type: &str,
        actions_json: &str,
        description: Option<&str>,
    ) -> Result<(), AstralError>;
    /// 更新（actions_json + description），返回是否命中
    async fn update_registry(
        &self,
        resource_type: &str,
        actions_json: &str,
        description: Option<&str>,
    ) -> Result<bool, AstralError>;
    /// 注销（DELETE），返回是否命中
    async fn delete_registry(&self, resource_type: &str) -> Result<bool, AstralError>;
    /// 异步扫描用：INSERT ... ON DUPLICATE KEY UPDATE
    async fn upsert_registry(
        &self,
        resource_type: &str,
        actions_json: &str,
    ) -> Result<(), AstralError>;
}

pub struct SqlxResourceTypeRepository {
    db: MySqlPool,
}

impl SqlxResourceTypeRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

#[async_trait]
impl ResourceTypeRepository for SqlxResourceTypeRepository {
    async fn count_domain_resource_types(&self) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM domain_resource_type")
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_domain_resource_types(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DomainResourceTypeRecord>, AstralError> {
        sqlx::query_as::<_, DomainResourceTypeRecord>(
            "SELECT resource_type_id as id, domain_id, type_code as code, type_name as name, \
             type_description as description, sensitivity_level, status, \
             DATE_FORMAT(created_at, '%Y-%m-%dT%H:%i:%sZ') as created_at, \
             DATE_FORMAT(updated_at, '%Y-%m-%dT%H:%i:%sZ') as updated_at \
             FROM domain_resource_type ORDER BY resource_type_id LIMIT ? OFFSET ?",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn list_registry(&self) -> Result<Vec<ResourceTypeRegistryRecord>, AstralError> {
        sqlx::query_as::<_, ResourceTypeRegistryRecord>(
            "SELECT id, resource_type, actions_json, description, \
             DATE_FORMAT(created_at, '%Y-%m-%dT%H:%i:%sZ') as created_at, \
             DATE_FORMAT(updated_at, '%Y-%m-%dT%H:%i:%sZ') as updated_at \
             FROM resource_type_registry ORDER BY resource_type",
        )
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn insert_ignore_registry(
        &self,
        resource_type: &str,
        actions_json: &str,
        description: Option<&str>,
    ) -> Result<(), AstralError> {
        sqlx::query(
            "INSERT IGNORE INTO resource_type_registry (resource_type, actions_json, description) \
             VALUES (?, ?, ?)",
        )
        .bind(resource_type)
        .bind(actions_json)
        .bind(description)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn update_registry(
        &self,
        resource_type: &str,
        actions_json: &str,
        description: Option<&str>,
    ) -> Result<bool, AstralError> {
        let result = sqlx::query(
            "UPDATE resource_type_registry SET actions_json = ?, description = ? WHERE resource_type = ?",
        )
        .bind(actions_json)
        .bind(description)
        .bind(resource_type)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_registry(&self, resource_type: &str) -> Result<bool, AstralError> {
        let result = sqlx::query("DELETE FROM resource_type_registry WHERE resource_type = ?")
            .bind(resource_type)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn upsert_registry(
        &self,
        resource_type: &str,
        actions_json: &str,
    ) -> Result<(), AstralError> {
        sqlx::query(
            "INSERT INTO resource_type_registry (resource_type, actions_json) VALUES (?, ?) \
             ON DUPLICATE KEY UPDATE actions_json = VALUES(actions_json), updated_at = NOW()",
        )
        .bind(resource_type)
        .bind(actions_json)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Resource type repository query failed: {error}"))
}
