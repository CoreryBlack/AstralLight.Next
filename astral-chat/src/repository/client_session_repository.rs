//! 客户端会话数据访问 — ClientSessionRepository
//!
//! 对齐 Java `ChatClientSessionMapper` 边界（chat_client_session 表）。
//! WebSocket 上下线记录为 UPSERT（非关键路径，失败仅告警，由调用方容错）。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::AstralError;

#[async_trait]
pub trait ClientSessionRepository: Send + Sync {
    /// UPSERT 客户端在线状态（ONLINE/OFFLINE），失败返回错误（调用方 warn-only）
    async fn upsert(
        &self,
        user_id: i64,
        status: &str,
        device_id: Option<&str>,
    ) -> Result<(), AstralError>;
}

pub struct SqlxClientSessionRepository {
    db: MySqlPool,
}

impl SqlxClientSessionRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

#[async_trait]
impl ClientSessionRepository for SqlxClientSessionRepository {
    async fn upsert(
        &self,
        user_id: i64,
        status: &str,
        device_id: Option<&str>,
    ) -> Result<(), AstralError> {
        let device = device_id.unwrap_or("web-unknown");
        sqlx::query(
            "INSERT INTO chat_client_session (user_id, client_type, device_id, status, last_active_at) \
             VALUES (?, 'WEB', ?, ?, NOW()) \
             ON DUPLICATE KEY UPDATE status = VALUES(status), last_active_at = NOW(), connection_id = UUID()",
        )
        .bind(user_id)
        .bind(device)
        .bind(status)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Client session repository query failed: {error}"))
}
