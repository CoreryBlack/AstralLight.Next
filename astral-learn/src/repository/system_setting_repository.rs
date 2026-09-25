//! 系统设置数据访问 — SystemSettingRepository
//!
//! 对齐 Java `SystemSettingMapper` 边界（learn_system_setting 表）。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::AstralError;

/// 系统设置行
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SystemSettingRecord {
    pub id: i64,
    pub setting_key: String,
    pub setting_value: Option<String>,
    pub description: Option<String>,
    pub updated_at: Option<time::PrimitiveDateTime>,
}

#[async_trait]
pub trait SystemSettingRepository: Send + Sync {
    /// 总数（分页）
    async fn count_all(&self) -> Result<i64, AstralError>;
    /// 分页列表
    async fn list_all(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SystemSettingRecord>, AstralError>;
    /// 更新设置（按 key），返回是否命中
    async fn update_by_key(&self, key: &str, value: &str) -> Result<bool, AstralError>;
}

pub struct SqlxSystemSettingRepository {
    db: MySqlPool,
}

impl SqlxSystemSettingRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

#[async_trait]
impl SystemSettingRepository for SqlxSystemSettingRepository {
    async fn count_all(&self) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM learn_system_setting")
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_all(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SystemSettingRecord>, AstralError> {
        sqlx::query_as::<_, SystemSettingRecord>(
            "SELECT id, setting_key, setting_value, description, updated_at \
             FROM learn_system_setting ORDER BY id LIMIT ? OFFSET ?",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn update_by_key(&self, key: &str, value: &str) -> Result<bool, AstralError> {
        let result = sqlx::query(
            "UPDATE learn_system_setting SET setting_value = ?, updated_at = NOW() WHERE setting_key = ?",
        )
        .bind(value)
        .bind(key)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() > 0)
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("System setting repository query failed: {error}"))
}
