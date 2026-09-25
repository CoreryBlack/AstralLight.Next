//! 平台套餐数据访问 — PlatformPackageRepository
//!
//! 对齐 Java `PlatformPackageMapper` 边界（platform_package 表）。

use async_trait::async_trait;
use sqlx::{MySqlPool, QueryBuilder};

use astral_types::AstralError;

/// 平台套餐记录（platform_package）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PlatformPackageRecord {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub price: Option<i64>,
    pub billing_cycle: Option<String>,
    pub status: String,
    pub created_at: Option<i64>,
}

/// 部分更新补丁（status 需在白名单校验后传入）
#[derive(Debug, Default)]
pub struct PlatformPackagePatch {
    pub name: Option<String>,
    pub description: Option<String>,
    pub price: Option<i64>,
    pub billing_cycle: Option<String>,
    pub status: Option<String>,
}

const PKG_SELECT_COLUMNS: &str = "id, name, description, price, billing_cycle, status, \
     UNIX_TIMESTAMP(created_at) as created_at";

#[async_trait]
pub trait PlatformPackageRepository: Send + Sync {
    async fn count_packages(&self) -> Result<i64, AstralError>;
    async fn list_packages(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<PlatformPackageRecord>, AstralError>;
    async fn get_package(&self, id: i64) -> Result<Option<PlatformPackageRecord>, AstralError>;
    async fn create_package(
        &self,
        name: &str,
        description: Option<&str>,
        price: Option<i64>,
        billing_cycle: &str,
    ) -> Result<i64, AstralError>;
    /// 部分更新（空补丁 no-op）
    async fn update_package(
        &self,
        id: i64,
        patch: &PlatformPackagePatch,
    ) -> Result<(), AstralError>;
    /// 软删除（status → INACTIVE），返回是否命中
    async fn soft_delete_package(&self, id: i64) -> Result<bool, AstralError>;
}

pub struct SqlxPlatformPackageRepository {
    db: MySqlPool,
}

impl SqlxPlatformPackageRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

#[async_trait]
impl PlatformPackageRepository for SqlxPlatformPackageRepository {
    async fn count_packages(&self) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM platform_package")
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_packages(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<PlatformPackageRecord>, AstralError> {
        sqlx::query_as::<_, PlatformPackageRecord>(&format!(
            "SELECT {PKG_SELECT_COLUMNS} FROM platform_package ORDER BY id LIMIT ? OFFSET ?"
        ))
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn get_package(&self, id: i64) -> Result<Option<PlatformPackageRecord>, AstralError> {
        sqlx::query_as::<_, PlatformPackageRecord>(&format!(
            "SELECT {PKG_SELECT_COLUMNS} FROM platform_package WHERE id = ?"
        ))
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn create_package(
        &self,
        name: &str,
        description: Option<&str>,
        price: Option<i64>,
        billing_cycle: &str,
    ) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO platform_package (name, description, price, billing_cycle, status) \
             VALUES (?, ?, ?, ?, 'ACTIVE')",
        )
        .bind(name)
        .bind(description)
        .bind(price)
        .bind(billing_cycle)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
    }

    async fn update_package(
        &self,
        id: i64,
        patch: &PlatformPackagePatch,
    ) -> Result<(), AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new("UPDATE platform_package SET ");
        let mut first = true;
        if let Some(status) = &patch.status {
            if !first {
                builder.push(", ");
            }
            builder.push("status = ").push_bind(status.clone());
            first = false;
        }
        if let Some(name) = &patch.name {
            if !first {
                builder.push(", ");
            }
            builder.push("name = ").push_bind(name.clone());
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
        if let Some(price) = patch.price {
            if !first {
                builder.push(", ");
            }
            builder.push("price = ").push_bind(price);
            first = false;
        }
        if let Some(cycle) = &patch.billing_cycle {
            if !first {
                builder.push(", ");
            }
            builder.push("billing_cycle = ").push_bind(cycle.clone());
            first = false;
        }
        if first {
            return Ok(());
        }
        builder.push(" WHERE id = ").push_bind(id);
        builder.build().execute(&self.db).await.map_err(db_error)?;
        Ok(())
    }

    async fn soft_delete_package(&self, id: i64) -> Result<bool, AstralError> {
        let result = sqlx::query("UPDATE platform_package SET status = 'INACTIVE' WHERE id = ?")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected() > 0)
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Platform package repository query failed: {error}"))
}
