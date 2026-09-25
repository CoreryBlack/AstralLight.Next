//! App 用户数据访问 — AppUserRepository
//!
//! 对齐 Java `AppUserMapper` 边界（app_user + verification_code 表）。
//! 验证码原子消费（UPDATE ... WHERE 子查询，fail-closed）与用户 find-or-create
//! 在此层；外部 HTTP 会话签发在 `service::app_user_service`。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::AstralError;

/// App 用户行
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AppUserRecord {
    pub id: i64,
    pub phone: Option<String>,
    pub nickname: Option<String>,
    pub avatar_url: Option<String>,
    pub status: String,
}

#[async_trait]
pub trait AppUserRepository: Send + Sync {
    /// 原子消费验证码（compare-and-consume 最新有效码；并发防复用），返回是否恰好消费 1 条
    async fn consume_verification_code(
        &self,
        phone: &str,
        purpose: &str,
        code: &str,
    ) -> Result<bool, AstralError>;
    /// 按手机号查用户
    async fn find_by_phone(&self, phone: &str) -> Result<Option<AppUserRecord>, AstralError>;
    /// 按 id 查用户
    async fn find_by_id(&self, id: i64) -> Result<Option<AppUserRecord>, AstralError>;
    /// 新建用户（nickname 默认由调用方生成），返回新 id
    async fn create(&self, phone: &str, nickname: &str) -> Result<i64, AstralError>;
    /// 补偿删除（仅删除本次新建的用户；失败需人工补偿）
    async fn cleanup_new_user(&self, user_id: i64, phone: &str) -> Result<(), AstralError>;
}

pub struct SqlxAppUserRepository {
    db: MySqlPool,
}

impl SqlxAppUserRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

const APP_USER_SELECT: &str = "SELECT id, phone, nickname, avatar_url, status FROM app_user";

#[async_trait]
impl AppUserRepository for SqlxAppUserRepository {
    async fn consume_verification_code(
        &self,
        phone: &str,
        purpose: &str,
        code: &str,
    ) -> Result<bool, AstralError> {
        // 对齐原 handler：原子 compare-and-consume 最新有效码，fail-closed
        let result = sqlx::query(
            "UPDATE verification_code SET verified_at = NOW() \
             WHERE id = (SELECT id FROM (SELECT id FROM verification_code \
               WHERE target = ? AND purpose = ? AND code = ? AND verified_at IS NULL \
                 AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1) AS valid_code)",
        )
        .bind(phone)
        .bind(purpose)
        .bind(code)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn find_by_phone(&self, phone: &str) -> Result<Option<AppUserRecord>, AstralError> {
        sqlx::query_as::<_, AppUserRecord>(&format!("{APP_USER_SELECT} WHERE phone = ?"))
            .bind(phone)
            .fetch_optional(&self.db)
            .await
            .map_err(db_error)
    }

    async fn find_by_id(&self, id: i64) -> Result<Option<AppUserRecord>, AstralError> {
        sqlx::query_as::<_, AppUserRecord>(&format!("{APP_USER_SELECT} WHERE id = ?"))
            .bind(id)
            .fetch_optional(&self.db)
            .await
            .map_err(db_error)
    }

    async fn create(&self, phone: &str, nickname: &str) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO app_user (phone, nickname, status, created_at) VALUES (?, ?, 'ACTIVE', NOW())",
        )
        .bind(phone)
        .bind(nickname)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
    }

    async fn cleanup_new_user(&self, user_id: i64, phone: &str) -> Result<(), AstralError> {
        sqlx::query("DELETE FROM app_user WHERE id = ? AND phone = ? AND status = 'ACTIVE'")
            .bind(user_id)
            .bind(phone)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("App user repository query failed: {error}"))
}
