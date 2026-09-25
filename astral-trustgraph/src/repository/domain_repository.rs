//! 域数据访问 — DomainRepository
//!
//! 对齐 Java `DomainControlService` 域 CRUD 边界（platform_domain 表）。
//! 动态过滤统一使用 `QueryBuilder` 参数绑定，禁止裸字符串拼接。

use async_trait::async_trait;
use sqlx::{MySqlPool, QueryBuilder};

use astral_types::AstralError;

/// 域记录（platform_domain）。
///
/// 注意：platform_v4 中 platform_domain 表无 org_id 列，org_id 保留为
/// Option<i64> 用于前端兼容（查询时恒为 NULL）。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DomainRecord {
    pub id: i64,
    pub name: String,
    pub code: Option<String>,
    pub description: Option<String>,
    pub org_id: Option<i64>,
    pub status: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// 列表过滤条件（status 可选）
#[derive(Debug, Default)]
pub struct DomainFilter {
    pub status: Option<String>,
}

/// 部分更新补丁（仅更新非 None 字段，对齐 Java Mapper.updateById 语义）
#[derive(Debug, Default)]
pub struct DomainPatch {
    pub name: Option<String>,
    pub code: Option<String>,
    pub status: Option<String>,
}

/// 默认域同步结果
#[derive(Debug, Clone)]
pub struct DefaultDomainSyncResult {
    pub existing: i64,
    pub created: i64,
}

/// platform_v4 真实列名映射（domain_id → id, domain_name → name 等）
const DOMAIN_SELECT_COLUMNS: &str = "domain_id as id, domain_name as name, domain_code as code, \
     domain_description as description, NULL as org_id, status, \
     DATE_FORMAT(created_at, '%Y-%m-%dT%H:%i:%sZ') as created_at, \
     DATE_FORMAT(updated_at, '%Y-%m-%dT%H:%i:%sZ') as updated_at";

#[async_trait]
pub trait DomainRepository: Send + Sync {
    /// 列表总数（按过滤条件）
    async fn count_domains(&self, filter: &DomainFilter) -> Result<i64, AstralError>;
    /// 分页列表（ORDER BY domain_id）
    async fn list_domains(
        &self,
        filter: &DomainFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DomainRecord>, AstralError>;
    async fn get_domain(&self, id: i64) -> Result<Option<DomainRecord>, AstralError>;
    async fn create_domain(
        &self,
        name: &str,
        code: Option<&str>,
        status: &str,
    ) -> Result<i64, AstralError>;
    /// 部分更新（仅应用非 None 字段；空补丁为 no-op）
    async fn update_domain(&self, id: i64, patch: &DomainPatch) -> Result<(), AstralError>;
    /// 软删除（ACTIVE → INACTIVE），返回是否命中
    async fn soft_delete_domain(&self, id: i64) -> Result<bool, AstralError>;
    /// 幂等同步默认域（无域时插入「默认域」），返回现状与新建数量
    async fn sync_default_domain(&self) -> Result<DefaultDomainSyncResult, AstralError>;
}

pub struct SqlxDomainRepository {
    db: MySqlPool,
}

impl SqlxDomainRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

/// 向 QueryBuilder 追加 status 过滤（列表与总数共用同一条件）
fn push_domain_filter<'args>(
    builder: &mut QueryBuilder<'args, sqlx::MySql>,
    filter: &DomainFilter,
) {
    if let Some(status) = &filter.status {
        builder
            .push(" AND status = ")
            .push_bind(status.to_uppercase());
    }
}

#[async_trait]
impl DomainRepository for SqlxDomainRepository {
    async fn count_domains(&self, filter: &DomainFilter) -> Result<i64, AstralError> {
        let mut builder =
            QueryBuilder::<sqlx::MySql>::new("SELECT COUNT(*) FROM platform_domain WHERE 1=1");
        push_domain_filter(&mut builder, filter);
        builder
            .build_query_scalar::<i64>()
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_domains(
        &self,
        filter: &DomainFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DomainRecord>, AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new(&format!(
            "SELECT {DOMAIN_SELECT_COLUMNS} FROM platform_domain WHERE 1=1"
        ));
        push_domain_filter(&mut builder, filter);
        builder
            .push(" ORDER BY domain_id LIMIT ")
            .push_bind(limit)
            .push(" OFFSET ")
            .push_bind(offset);
        builder
            .build_query_as::<DomainRecord>()
            .fetch_all(&self.db)
            .await
            .map_err(db_error)
    }

    async fn get_domain(&self, id: i64) -> Result<Option<DomainRecord>, AstralError> {
        sqlx::query_as::<_, DomainRecord>(&format!(
            "SELECT {DOMAIN_SELECT_COLUMNS} FROM platform_domain WHERE domain_id = ?"
        ))
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn create_domain(
        &self,
        name: &str,
        code: Option<&str>,
        status: &str,
    ) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO platform_domain (domain_name, domain_code, status) VALUES (?, ?, ?)",
        )
        .bind(name)
        .bind(code)
        .bind(status)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
    }

    async fn update_domain(&self, id: i64, patch: &DomainPatch) -> Result<(), AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new("UPDATE platform_domain SET ");
        let mut first = true;
        if let Some(name) = &patch.name {
            if !first {
                builder.push(", ");
            }
            builder.push("domain_name = ").push_bind(name.clone());
            first = false;
        }
        if let Some(code) = &patch.code {
            if !first {
                builder.push(", ");
            }
            builder.push("domain_code = ").push_bind(code.clone());
            first = false;
        }
        if let Some(status) = &patch.status {
            if !first {
                builder.push(", ");
            }
            builder.push("status = ").push_bind(status.clone());
            first = false;
        }
        if first {
            // 空补丁：无字段更新（对齐现有 handler 语义，直接返回）
            return Ok(());
        }
        builder.push(" WHERE domain_id = ").push_bind(id);
        builder.build().execute(&self.db).await.map_err(db_error)?;
        Ok(())
    }

    async fn soft_delete_domain(&self, id: i64) -> Result<bool, AstralError> {
        let result = sqlx::query(
            "UPDATE platform_domain SET status = 'INACTIVE' WHERE domain_id = ? AND status = 'ACTIVE'",
        )
        .bind(id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn sync_default_domain(&self) -> Result<DefaultDomainSyncResult, AstralError> {
        let existing: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM platform_domain")
            .fetch_one(&self.db)
            .await
            .map_err(db_error)?;

        let mut created = 0i64;
        if existing == 0 {
            // 幂等语义：并发同步时容忍失败（对齐现有 handler，不阻塞主链路）
            match sqlx::query(
                "INSERT INTO platform_domain (domain_name, domain_code, status) \
                 VALUES ('默认域', 'DEFAULT', 'ACTIVE')",
            )
            .execute(&self.db)
            .await
            {
                Ok(_) => created = 1,
                Err(e) => {
                    tracing::warn!(error = %e, "default domain insert failed (idempotent sync)");
                }
            }
        }

        Ok(DefaultDomainSyncResult { existing, created })
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Domain repository query failed: {error}"))
}
