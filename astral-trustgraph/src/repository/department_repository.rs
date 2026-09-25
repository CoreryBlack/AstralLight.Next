//! 部门数据访问 — DepartmentRepository
//!
//! 对齐 Java `DepartmentMapper` 边界（departments 表）。
//! 动态过滤统一 `QueryBuilder` 参数绑定；删除前校验子部门数。

use async_trait::async_trait;
use sqlx::{MySqlPool, QueryBuilder};

use astral_types::AstralError;

/// 部门记录（departments，通过别名映射）。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DepartmentRecord {
    pub id: i64,
    pub tenant_id: i64,
    pub name: String,
    pub code: Option<String>,
    pub parent_id: Option<i64>,
    pub sort_order: Option<i32>,
    pub status: String,
    pub description: Option<String>,
    pub created_at: Option<i64>,
    pub updated_at: Option<i64>,
}

/// 列表过滤（parent_id / tenant_id 可选）
#[derive(Debug, Default)]
pub struct DepartmentFilter {
    pub parent_id: Option<i64>,
    pub tenant_id: Option<i64>,
}

/// 部分更新补丁
#[derive(Debug, Default)]
pub struct DepartmentPatch {
    pub name: Option<String>,
    pub code: Option<String>,
    pub parent_id: Option<i64>,
    pub sort_order: Option<i32>,
    pub description: Option<String>,
}

const DEPT_SELECT_COLUMNS: &str =
    "dept_id as id, tenant_id, dept_name as name, dept_code as code, \
     parent_dept_id as parent_id, sort_order, status, description, \
     UNIX_TIMESTAMP(created_at) as created_at, \
     UNIX_TIMESTAMP(updated_at) as updated_at";

#[async_trait]
pub trait DepartmentRepository: Send + Sync {
    /// 列表总数（按过滤条件）
    async fn count_departments(&self, filter: &DepartmentFilter) -> Result<i64, AstralError>;
    /// 分页列表（ORDER BY dept_id）
    async fn list_departments(
        &self,
        filter: &DepartmentFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DepartmentRecord>, AstralError>;
    /// 父部门是否存在
    async fn department_exists(&self, dept_id: i64) -> Result<bool, AstralError>;
    /// 新建，返回新 dept_id
    async fn create_department(
        &self,
        tenant_id: i64,
        name: &str,
        code: Option<&str>,
        parent_id: Option<i64>,
        sort_order: i32,
        description: Option<&str>,
    ) -> Result<i64, AstralError>;
    /// 按 id 查回
    async fn get_department(&self, id: i64) -> Result<Option<DepartmentRecord>, AstralError>;
    /// 部分更新（空补丁 no-op）
    async fn update_department(&self, id: i64, patch: &DepartmentPatch) -> Result<(), AstralError>;
    /// 子部门数量（删除前校验）
    async fn count_children(&self, dept_id: i64) -> Result<i64, AstralError>;
    /// 删除，返回是否命中
    async fn delete_department(&self, id: i64) -> Result<bool, AstralError>;
}

pub struct SqlxDepartmentRepository {
    db: MySqlPool,
}

impl SqlxDepartmentRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

/// 追加过滤条件（列表与总数共用）
fn push_filter<'args>(builder: &mut QueryBuilder<'args, sqlx::MySql>, filter: &DepartmentFilter) {
    if let Some(parent_id) = filter.parent_id {
        builder.push(" AND parent_dept_id = ").push_bind(parent_id);
    }
    if let Some(tenant_id) = filter.tenant_id {
        builder.push(" AND tenant_id = ").push_bind(tenant_id);
    }
}

#[async_trait]
impl DepartmentRepository for SqlxDepartmentRepository {
    async fn count_departments(&self, filter: &DepartmentFilter) -> Result<i64, AstralError> {
        let mut builder =
            QueryBuilder::<sqlx::MySql>::new("SELECT COUNT(*) FROM departments WHERE 1=1");
        push_filter(&mut builder, filter);
        builder
            .build_query_scalar::<i64>()
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_departments(
        &self,
        filter: &DepartmentFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DepartmentRecord>, AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new(&format!(
            "SELECT {DEPT_SELECT_COLUMNS} FROM departments WHERE 1=1"
        ));
        push_filter(&mut builder, filter);
        builder
            .push(" ORDER BY dept_id LIMIT ")
            .push_bind(limit)
            .push(" OFFSET ")
            .push_bind(offset);
        builder
            .build_query_as::<DepartmentRecord>()
            .fetch_all(&self.db)
            .await
            .map_err(db_error)
    }

    async fn department_exists(&self, dept_id: i64) -> Result<bool, AstralError> {
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT dept_id FROM departments WHERE dept_id = ?")
                .bind(dept_id)
                .fetch_optional(&self.db)
                .await
                .map_err(db_error)?;
        Ok(row.is_some())
    }

    async fn create_department(
        &self,
        tenant_id: i64,
        name: &str,
        code: Option<&str>,
        parent_id: Option<i64>,
        sort_order: i32,
        description: Option<&str>,
    ) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO departments (tenant_id, dept_name, dept_code, parent_dept_id, sort_order, status, description) \
             VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?)",
        )
        .bind(tenant_id)
        .bind(name)
        .bind(code)
        .bind(parent_id)
        .bind(sort_order)
        .bind(description)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
    }

    async fn get_department(&self, id: i64) -> Result<Option<DepartmentRecord>, AstralError> {
        sqlx::query_as::<_, DepartmentRecord>(&format!(
            "SELECT {DEPT_SELECT_COLUMNS} FROM departments WHERE dept_id = ?"
        ))
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn update_department(&self, id: i64, patch: &DepartmentPatch) -> Result<(), AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new("UPDATE departments SET ");
        let mut first = true;
        if let Some(name) = &patch.name {
            if !first {
                builder.push(", ");
            }
            builder.push("dept_name = ").push_bind(name.clone());
            first = false;
        }
        if let Some(code) = &patch.code {
            if !first {
                builder.push(", ");
            }
            builder.push("dept_code = ").push_bind(code.clone());
            first = false;
        }
        if let Some(parent_id) = patch.parent_id {
            if !first {
                builder.push(", ");
            }
            builder.push("parent_dept_id = ").push_bind(parent_id);
            first = false;
        }
        if let Some(sort_order) = patch.sort_order {
            if !first {
                builder.push(", ");
            }
            builder.push("sort_order = ").push_bind(sort_order);
            first = false;
        }
        if let Some(description) = &patch.description {
            if !first {
                builder.push(", ");
            }
            builder
                .push("description = ")
                .push_bind(description.clone());
            first = false;
        }
        if first {
            return Ok(());
        }
        builder.push(" WHERE dept_id = ").push_bind(id);
        builder.build().execute(&self.db).await.map_err(db_error)?;
        Ok(())
    }

    async fn count_children(&self, dept_id: i64) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM departments WHERE parent_dept_id = ?")
            .bind(dept_id)
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn delete_department(&self, id: i64) -> Result<bool, AstralError> {
        let result = sqlx::query("DELETE FROM departments WHERE dept_id = ?")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected() > 0)
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Department repository query failed: {error}"))
}
