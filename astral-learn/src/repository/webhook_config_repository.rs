//! Webhook 配置数据访问 — WebhookConfigRepository
//!
//! 对齐 Java `WebhookConfigMapper` 边界（webhook_config 表）。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::AstralError;

/// Webhook 配置行
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct WebhookConfigRecord {
    pub id: i64,
    pub url: String,
    pub event_type: String,
    pub secret: Option<String>,
    pub is_active: i32,
    pub created_at: Option<time::PrimitiveDateTime>,
}

#[async_trait]
pub trait WebhookConfigRepository: Send + Sync {
    /// 总数（分页）
    async fn count_all(&self) -> Result<i64, AstralError>;
    /// 分页列表
    async fn list_all(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<WebhookConfigRecord>, AstralError>;
    /// 新建（is_active=1），返回新 id
    async fn create(
        &self,
        url: &str,
        event_type: &str,
        secret: Option<&str>,
    ) -> Result<i64, AstralError>;
    /// 删除
    async fn delete(&self, id: i64) -> Result<(), AstralError>;
}

pub struct SqlxWebhookConfigRepository {
    db: MySqlPool,
}

impl SqlxWebhookConfigRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

#[async_trait]
impl WebhookConfigRepository for SqlxWebhookConfigRepository {
    async fn count_all(&self) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM webhook_config")
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_all(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<WebhookConfigRecord>, AstralError> {
        sqlx::query_as::<_, WebhookConfigRecord>(
            "SELECT id, url, event_type, secret, is_active, created_at \
             FROM webhook_config ORDER BY id LIMIT ? OFFSET ?",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn create(
        &self,
        url: &str,
        event_type: &str,
        secret: Option<&str>,
    ) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO webhook_config (url, event_type, secret, is_active, created_at) \
             VALUES (?, ?, ?, 1, NOW())",
        )
        .bind(url)
        .bind(event_type)
        .bind(secret)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
    }

    async fn delete(&self, id: i64) -> Result<(), AstralError> {
        sqlx::query("DELETE FROM webhook_config WHERE id = ?")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Webhook config repository query failed: {error}"))
}
