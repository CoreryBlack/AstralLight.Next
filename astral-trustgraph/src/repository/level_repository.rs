//! 用户等级定义数据访问 — LevelRepository
//!
//! 对齐 Java `IdentityUserLevelDefinitionMapper` 边界（user_card_level_definition 表）。

use async_trait::async_trait;
use sqlx::{MySqlPool, QueryBuilder};

use astral_types::AstralError;

/// 等级定义记录（user_card_level_definition）。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LevelRecord {
    pub level_id: i64,
    pub domain_id: i64,
    pub level_no: i32,
    pub level_code: String,
    pub level_name: String,
    pub status: String,
    pub upgrade_strategy_json: Option<String>,
    pub description: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// 列表过滤条件（domain_id / status 可选）
#[derive(Debug, Default)]
pub struct LevelFilter {
    pub domain_id: Option<i64>,
    pub status: Option<String>,
}

/// 部分更新补丁（仅更新非 None 字段，对齐 Java Mapper.updateById 语义）
#[derive(Debug, Default)]
pub struct LevelPatch {
    pub level_name: Option<String>,
    pub level_code: Option<String>,
    pub level_no: Option<i32>,
    pub status: Option<String>,
    pub upgrade_strategy_json: Option<String>,
    pub description: Option<String>,
}

const LEVEL_SELECT_COLUMNS: &str =
    "level_id, domain_id, level_no, level_code, level_name, status, \
     upgrade_strategy_json, description, \
     DATE_FORMAT(created_at, '%Y-%m-%dT%H:%i:%sZ') as created_at, \
     DATE_FORMAT(updated_at, '%Y-%m-%dT%H:%i:%sZ') as updated_at";

#[async_trait]
pub trait LevelRepository: Send + Sync {
    /// 列表总数（按过滤条件）
    async fn count_levels(&self, filter: &LevelFilter) -> Result<i64, AstralError>;
    /// 分页列表（ORDER BY domain_id, level_no）
    async fn list_levels(
        &self,
        filter: &LevelFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<LevelRecord>, AstralError>;
    async fn get_level(&self, id: i64) -> Result<Option<LevelRecord>, AstralError>;
    async fn create_level(
        &self,
        domain_id: i64,
        level_name: &str,
        level_code: &str,
        level_no: i32,
        upgrade_strategy_json: Option<&str>,
        description: Option<&str>,
    ) -> Result<i64, AstralError>;
    /// 部分更新（仅应用非 None 字段；空补丁为 no-op）
    async fn update_level(&self, id: i64, patch: &LevelPatch) -> Result<(), AstralError>;
    /// 删除（FK ON DELETE CASCADE 级联 identity_user_grading），返回是否命中
    async fn delete_level(&self, id: i64) -> Result<bool, AstralError>;
}

pub struct SqlxLevelRepository {
    db: MySqlPool,
}

impl SqlxLevelRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

/// 向 QueryBuilder 追加 domain_id / status 过滤（列表与总数共用同一条件）
fn push_level_filter<'args>(builder: &mut QueryBuilder<'args, sqlx::MySql>, filter: &LevelFilter) {
    if let Some(domain_id) = filter.domain_id {
        builder.push(" AND domain_id = ").push_bind(domain_id);
    }
    if let Some(status) = &filter.status {
        builder
            .push(" AND status = ")
            .push_bind(status.to_uppercase());
    }
}

#[async_trait]
impl LevelRepository for SqlxLevelRepository {
    async fn count_levels(&self, filter: &LevelFilter) -> Result<i64, AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new(
            "SELECT COUNT(*) FROM user_card_level_definition WHERE 1=1",
        );
        push_level_filter(&mut builder, filter);
        builder
            .build_query_scalar::<i64>()
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_levels(
        &self,
        filter: &LevelFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<LevelRecord>, AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new(&format!(
            "SELECT {LEVEL_SELECT_COLUMNS} FROM user_card_level_definition WHERE 1=1"
        ));
        push_level_filter(&mut builder, filter);
        builder
            .push(" ORDER BY domain_id, level_no LIMIT ")
            .push_bind(limit)
            .push(" OFFSET ")
            .push_bind(offset);
        builder
            .build_query_as::<LevelRecord>()
            .fetch_all(&self.db)
            .await
            .map_err(db_error)
    }

    async fn get_level(&self, id: i64) -> Result<Option<LevelRecord>, AstralError> {
        sqlx::query_as::<_, LevelRecord>(&format!(
            "SELECT {LEVEL_SELECT_COLUMNS} FROM user_card_level_definition WHERE level_id = ?"
        ))
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn create_level(
        &self,
        domain_id: i64,
        level_name: &str,
        level_code: &str,
        level_no: i32,
        upgrade_strategy_json: Option<&str>,
        description: Option<&str>,
    ) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO user_card_level_definition \
             (domain_id, level_name, level_code, level_no, status, upgrade_strategy_json, description) \
             VALUES (?, ?, ?, ?, 'ACTIVE', ?, ?)",
        )
        .bind(domain_id)
        .bind(level_name)
        .bind(level_code)
        .bind(level_no)
        .bind(upgrade_strategy_json)
        .bind(description)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
    }

    async fn update_level(&self, id: i64, patch: &LevelPatch) -> Result<(), AstralError> {
        let mut builder =
            QueryBuilder::<sqlx::MySql>::new("UPDATE user_card_level_definition SET ");
        let mut first = true;
        if let Some(status) = &patch.status {
            if !first {
                builder.push(", ");
            }
            builder.push("status = ").push_bind(status.to_uppercase());
            first = false;
        }
        if let Some(name) = &patch.level_name {
            if !first {
                builder.push(", ");
            }
            builder.push("level_name = ").push_bind(name.clone());
            first = false;
        }
        if let Some(code) = &patch.level_code {
            if !first {
                builder.push(", ");
            }
            builder.push("level_code = ").push_bind(code.clone());
            first = false;
        }
        if let Some(level_no) = patch.level_no {
            if !first {
                builder.push(", ");
            }
            builder.push("level_no = ").push_bind(level_no);
            first = false;
        }
        if let Some(json) = &patch.upgrade_strategy_json {
            if !first {
                builder.push(", ");
            }
            builder
                .push("upgrade_strategy_json = ")
                .push_bind(json.clone());
            first = false;
        }
        if let Some(desc) = &patch.description {
            if !first {
                builder.push(", ");
            }
            builder.push("description = ").push_bind(desc.clone());
            first = false;
        }
        if first {
            // 空补丁：无字段更新（对齐现有 handler 语义，直接返回）
            return Ok(());
        }
        builder.push(" WHERE level_id = ").push_bind(id);
        builder.build().execute(&self.db).await.map_err(db_error)?;
        Ok(())
    }

    async fn delete_level(&self, id: i64) -> Result<bool, AstralError> {
        let result = sqlx::query("DELETE FROM user_card_level_definition WHERE level_id = ?")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected() > 0)
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Level repository query failed: {error}"))
}
