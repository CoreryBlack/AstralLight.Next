//! 权限动作数据访问 — PermissionActionRepository
//!
//! 对齐 Java `PermissionActionMapper` 边界（permission_action 表 + domain_resource_type 只读）。

use async_trait::async_trait;
use sqlx::{MySqlPool, QueryBuilder};

use astral_types::AstralError;

/// 权限动作记录（permission_action，通过别名映射）。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PermissionActionRecord {
    pub id: i64,
    pub domain_id: Option<i64>,
    pub resource_type_id: i64,
    pub code: String,
    pub name: String,
    pub description: Option<String>,
    pub created_at: Option<String>,
}

/// 列表过滤（domain_id / resource_type_ids 可选）
#[derive(Debug, Default)]
pub struct ActionFilter {
    pub domain_id: Option<i64>,
    pub resource_type_ids: Vec<i64>,
}

/// 部分更新补丁（name / description）
#[derive(Debug, Default)]
pub struct ActionPatch {
    pub name: Option<String>,
    pub description: Option<String>,
}

const ACTION_SELECT_COLUMNS: &str = "action_id as id, domain_id, resource_type_id, \
     action_code as code, action_name as name, action_description as description, \
     DATE_FORMAT(created_at, '%Y-%m-%dT%H:%i:%sZ') as created_at";

#[async_trait]
pub trait PermissionActionRepository: Send + Sync {
    /// 列表总数（按过滤条件）
    async fn count_actions(&self, filter: &ActionFilter) -> Result<i64, AstralError>;
    /// 分页列表（ORDER BY action_id）
    async fn list_actions(
        &self,
        filter: &ActionFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<PermissionActionRecord>, AstralError>;
    /// 新建（INSERT IGNORE），返回后按 resource_type_id + code 查回
    async fn create_action(
        &self,
        domain_id: Option<i64>,
        resource_type_id: i64,
        code: &str,
        name: &str,
        description: Option<&str>,
    ) -> Result<PermissionActionRecord, AstralError>;
    /// 部分更新（name/description + updated_at），返回是否命中
    async fn update_action(&self, id: i64, patch: &ActionPatch) -> Result<bool, AstralError>;
    /// 按 id 查回
    async fn get_action(&self, id: i64) -> Result<Option<PermissionActionRecord>, AstralError>;
    /// 删除，返回是否命中
    async fn delete_action(&self, id: i64) -> Result<bool, AstralError>;
    /// 全量列表（scan 后重查）
    async fn list_all(&self) -> Result<Vec<PermissionActionRecord>, AstralError>;
    /// 同步扫描用：按 type_code 查 domain_resource_type_id
    async fn resource_type_id_by_code(&self, type_code: &str) -> Result<Option<i64>, AstralError>;
    /// 同步扫描用：INSERT IGNORE（permission_action）
    async fn insert_ignore_action(
        &self,
        domain_id: Option<i64>,
        resource_type_id: i64,
        code: &str,
        name: &str,
    ) -> Result<(), AstralError>;
    /// 异步扫描用：INSERT ... SELECT（domain_resource_type JOIN）ON DUPLICATE KEY
    async fn upsert_action_from_registry(
        &self,
        code: &str,
        name: &str,
        description: &str,
        resource_type: &str,
    ) -> Result<(), AstralError>;
}

pub struct SqlxPermissionActionRepository {
    db: MySqlPool,
}

impl SqlxPermissionActionRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

/// 追加过滤条件（列表与总数共用）
fn push_action_filter<'args>(
    builder: &mut QueryBuilder<'args, sqlx::MySql>,
    filter: &ActionFilter,
) {
    if let Some(domain_id) = filter.domain_id {
        builder.push(" AND domain_id = ").push_bind(domain_id);
    }
    if !filter.resource_type_ids.is_empty() {
        builder.push(" AND resource_type_id IN (");
        let mut sep = "";
        for id in &filter.resource_type_ids {
            builder.push(sep).push_bind(*id);
            sep = ", ";
        }
        builder.push(")");
    }
}

#[async_trait]
impl PermissionActionRepository for SqlxPermissionActionRepository {
    async fn count_actions(&self, filter: &ActionFilter) -> Result<i64, AstralError> {
        let mut builder =
            QueryBuilder::<sqlx::MySql>::new("SELECT COUNT(*) FROM permission_action WHERE 1=1");
        push_action_filter(&mut builder, filter);
        builder
            .build_query_scalar::<i64>()
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_actions(
        &self,
        filter: &ActionFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<PermissionActionRecord>, AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new(&format!(
            "SELECT {ACTION_SELECT_COLUMNS} FROM permission_action WHERE 1=1"
        ));
        push_action_filter(&mut builder, filter);
        builder
            .push(" ORDER BY action_id LIMIT ")
            .push_bind(limit)
            .push(" OFFSET ")
            .push_bind(offset);
        builder
            .build_query_as::<PermissionActionRecord>()
            .fetch_all(&self.db)
            .await
            .map_err(db_error)
    }

    async fn create_action(
        &self,
        domain_id: Option<i64>,
        resource_type_id: i64,
        code: &str,
        name: &str,
        description: Option<&str>,
    ) -> Result<PermissionActionRecord, AstralError> {
        sqlx::query(
            "INSERT IGNORE INTO permission_action (domain_id, resource_type_id, action_code, action_name, action_description) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(domain_id)
        .bind(resource_type_id)
        .bind(code)
        .bind(name)
        .bind(description)
        .execute(&self.db)
        .await
        .map_err(db_error)?;

        sqlx::query_as::<_, PermissionActionRecord>(&format!(
            "SELECT {ACTION_SELECT_COLUMNS} FROM permission_action WHERE resource_type_id = ? AND action_code = ?"
        ))
        .bind(resource_type_id)
        .bind(code)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)
    }

    async fn update_action(&self, id: i64, patch: &ActionPatch) -> Result<bool, AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new("UPDATE permission_action SET ");
        let mut first = true;
        if let Some(name) = &patch.name {
            if !first {
                builder.push(", ");
            }
            builder.push("action_name = ").push_bind(name.clone());
            first = false;
        }
        if let Some(description) = &patch.description {
            if !first {
                builder.push(", ");
            }
            builder
                .push("action_description = ")
                .push_bind(description.clone());
            first = false;
        }
        if first {
            return Ok(false);
        }
        builder
            .push(", updated_at = NOW() WHERE action_id = ")
            .push_bind(id);
        let result = builder.build().execute(&self.db).await.map_err(db_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn get_action(&self, id: i64) -> Result<Option<PermissionActionRecord>, AstralError> {
        sqlx::query_as::<_, PermissionActionRecord>(&format!(
            "SELECT {ACTION_SELECT_COLUMNS} FROM permission_action WHERE action_id = ?"
        ))
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn delete_action(&self, id: i64) -> Result<bool, AstralError> {
        let result = sqlx::query("DELETE FROM permission_action WHERE action_id = ?")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_all(&self) -> Result<Vec<PermissionActionRecord>, AstralError> {
        sqlx::query_as::<_, PermissionActionRecord>(&format!(
            "SELECT {ACTION_SELECT_COLUMNS} FROM permission_action ORDER BY action_id"
        ))
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn resource_type_id_by_code(&self, type_code: &str) -> Result<Option<i64>, AstralError> {
        sqlx::query_scalar::<_, i64>(
            "SELECT resource_type_id FROM domain_resource_type WHERE type_code = ? LIMIT 1",
        )
        .bind(type_code)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn insert_ignore_action(
        &self,
        domain_id: Option<i64>,
        resource_type_id: i64,
        code: &str,
        name: &str,
    ) -> Result<(), AstralError> {
        sqlx::query(
            "INSERT IGNORE INTO permission_action (domain_id, resource_type_id, action_code, action_name) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(domain_id)
        .bind(resource_type_id)
        .bind(code)
        .bind(name)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn upsert_action_from_registry(
        &self,
        code: &str,
        name: &str,
        description: &str,
        resource_type: &str,
    ) -> Result<(), AstralError> {
        sqlx::query(
            "INSERT INTO permission_action (domain_id, resource_type_id, action_code, action_name, action_description) \
             SELECT NULL, dt.resource_type_id, ?, ?, ? \
             FROM domain_resource_type dt WHERE dt.type_code = ? \
             ON DUPLICATE KEY UPDATE updated_at = NOW()",
        )
        .bind(code)
        .bind(name)
        .bind(description)
        .bind(resource_type)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!(
        "Permission action repository query failed: {error}"
    ))
}
