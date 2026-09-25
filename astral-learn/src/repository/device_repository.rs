//! 设备数据访问 — DeviceRepository
//!
//! 对齐 Java `DeviceMapper` 边界（learn_device 表）。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::AstralError;

/// 设备行
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DeviceRecord {
    pub id: i64,
    pub user_id: i64,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
    pub device_id: Option<String>,
    pub last_login_at: Option<time::PrimitiveDateTime>,
    pub created_at: Option<time::PrimitiveDateTime>,
}

#[async_trait]
pub trait DeviceRepository: Send + Sync {
    /// 总数（分页）
    async fn count_all(&self) -> Result<i64, AstralError>;
    /// 全量分页列表
    async fn list_all(&self, limit: i64, offset: i64) -> Result<Vec<DeviceRecord>, AstralError>;
    /// 用户设备列表（last_login_at DESC，不分页）
    async fn list_by_user(&self, user_id: i64) -> Result<Vec<DeviceRecord>, AstralError>;
    /// 删除设备
    async fn delete(&self, id: i64) -> Result<(), AstralError>;
}

pub struct SqlxDeviceRepository {
    db: MySqlPool,
}

impl SqlxDeviceRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

const DEVICE_SELECT: &str =
    "SELECT id, user_id, device_name, device_type, device_id, last_login_at, created_at \
     FROM learn_device";

#[async_trait]
impl DeviceRepository for SqlxDeviceRepository {
    async fn count_all(&self) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM learn_device")
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_all(&self, limit: i64, offset: i64) -> Result<Vec<DeviceRecord>, AstralError> {
        sqlx::query_as::<_, DeviceRecord>(&format!("{DEVICE_SELECT} ORDER BY id LIMIT ? OFFSET ?"))
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_by_user(&self, user_id: i64) -> Result<Vec<DeviceRecord>, AstralError> {
        sqlx::query_as::<_, DeviceRecord>(&format!(
            "{DEVICE_SELECT} WHERE user_id = ? ORDER BY last_login_at DESC"
        ))
        .bind(user_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn delete(&self, id: i64) -> Result<(), AstralError> {
        sqlx::query("DELETE FROM learn_device WHERE id = ?")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Device repository query failed: {error}"))
}
