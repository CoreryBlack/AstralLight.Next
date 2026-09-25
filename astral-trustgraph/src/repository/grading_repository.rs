//! 用户分级数据访问 — GradingRepository
//!
//! 对齐 Java `IdentityUserGradingMapper` 边界（identity_user_grading 表）。
//! 创建走 `INSERT ... ON DUPLICATE KEY UPDATE` 幂等（uk_iug_user_domain）。

use async_trait::async_trait;
use sqlx::{MySqlPool, QueryBuilder};

use astral_types::AstralError;

/// 用户分级记录（identity_user_grading）。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct GradingRecord {
    pub id: i64,
    pub user_id: i64,
    pub level_id: i64,
    pub domain_id: i64,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// 列表过滤条件（user_id / domain_id 可选）
#[derive(Debug, Default)]
pub struct GradingFilter {
    pub user_id: Option<i64>,
    pub domain_id: Option<i64>,
}

const GRADING_SELECT_COLUMNS: &str = "id, user_id, level_id, domain_id, \
     DATE_FORMAT(created_at, '%Y-%m-%dT%H:%i:%sZ') as created_at, \
     DATE_FORMAT(updated_at, '%Y-%m-%dT%H:%i:%sZ') as updated_at";

#[async_trait]
pub trait GradingRepository: Send + Sync {
    /// 列表总数（按过滤条件）
    async fn count_gradings(&self, filter: &GradingFilter) -> Result<i64, AstralError>;
    /// 分页列表（ORDER BY user_id, domain_id）
    async fn list_gradings(
        &self,
        filter: &GradingFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<GradingRecord>, AstralError>;
    /// 等级是否存在且 ACTIVE（创建校验，对齐现有 handler 语义）
    async fn level_exists_in_domain(
        &self,
        level_id: i64,
        domain_id: i64,
    ) -> Result<bool, AstralError>;
    /// 幂等 upsert（uk_iug_user_domain，单用户单域唯一）
    async fn upsert_grading(
        &self,
        user_id: i64,
        level_id: i64,
        domain_id: i64,
    ) -> Result<(), AstralError>;
    /// upsert 后查回（用户+域唯一，应存在）
    async fn get_grading(&self, user_id: i64, domain_id: i64)
        -> Result<GradingRecord, AstralError>;
    /// 删除，返回是否命中
    async fn delete_grading(&self, id: i64) -> Result<bool, AstralError>;
}

pub struct SqlxGradingRepository {
    db: MySqlPool,
}

impl SqlxGradingRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

/// 向 QueryBuilder 追加 user_id / domain_id 过滤（列表与总数共用同一条件）
fn push_grading_filter<'args>(
    builder: &mut QueryBuilder<'args, sqlx::MySql>,
    filter: &GradingFilter,
) {
    if let Some(user_id) = filter.user_id {
        builder.push(" AND user_id = ").push_bind(user_id);
    }
    if let Some(domain_id) = filter.domain_id {
        builder.push(" AND domain_id = ").push_bind(domain_id);
    }
}

#[async_trait]
impl GradingRepository for SqlxGradingRepository {
    async fn count_gradings(&self, filter: &GradingFilter) -> Result<i64, AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new(
            "SELECT COUNT(*) FROM identity_user_grading WHERE 1=1",
        );
        push_grading_filter(&mut builder, filter);
        builder
            .build_query_scalar::<i64>()
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_gradings(
        &self,
        filter: &GradingFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<GradingRecord>, AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new(&format!(
            "SELECT {GRADING_SELECT_COLUMNS} FROM identity_user_grading WHERE 1=1"
        ));
        push_grading_filter(&mut builder, filter);
        builder
            .push(" ORDER BY user_id, domain_id LIMIT ")
            .push_bind(limit)
            .push(" OFFSET ")
            .push_bind(offset);
        builder
            .build_query_as::<GradingRecord>()
            .fetch_all(&self.db)
            .await
            .map_err(db_error)
    }

    async fn level_exists_in_domain(
        &self,
        level_id: i64,
        domain_id: i64,
    ) -> Result<bool, AstralError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM user_card_level_definition \
             WHERE level_id = ? AND domain_id = ? AND status = 'ACTIVE'",
        )
        .bind(level_id)
        .bind(domain_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)?;
        Ok(count > 0)
    }

    async fn upsert_grading(
        &self,
        user_id: i64,
        level_id: i64,
        domain_id: i64,
    ) -> Result<(), AstralError> {
        sqlx::query(
            "INSERT INTO identity_user_grading (user_id, level_id, domain_id) \
             VALUES (?, ?, ?) \
             ON DUPLICATE KEY UPDATE level_id = VALUES(level_id)",
        )
        .bind(user_id)
        .bind(level_id)
        .bind(domain_id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn get_grading(
        &self,
        user_id: i64,
        domain_id: i64,
    ) -> Result<GradingRecord, AstralError> {
        sqlx::query_as::<_, GradingRecord>(&format!(
            "SELECT {GRADING_SELECT_COLUMNS} FROM identity_user_grading WHERE user_id = ? AND domain_id = ?"
        ))
        .bind(user_id)
        .bind(domain_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)
    }

    async fn delete_grading(&self, id: i64) -> Result<bool, AstralError> {
        let result = sqlx::query("DELETE FROM identity_user_grading WHERE id = ?")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected() > 0)
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Grading repository query failed: {error}"))
}
