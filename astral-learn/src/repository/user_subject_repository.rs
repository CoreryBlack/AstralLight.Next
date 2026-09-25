//! 用户学科数据访问 — UserSubjectRepository
//!
//! 对齐 Java `UserSubjectMapper` 边界（learn_user_subject 表）。
//! platform_v4 列名：selected_at 映射为 enrolled_at。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::AstralError;

/// 用户学科行
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserSubjectRecord {
    pub id: i64,
    pub user_id: i64,
    pub subject_id: i64,
    pub enrolled_at: Option<time::OffsetDateTime>,
}

#[async_trait]
pub trait UserSubjectRepository: Send + Sync {
    /// 总数（分页）
    async fn count(&self, user_id: i64) -> Result<i64, AstralError>;
    /// 分页列表（selected_at AS enrolled_at）
    async fn list(
        &self,
        user_id: i64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<UserSubjectRecord>, AstralError>;
    /// 选课，返回新 id
    async fn enroll(&self, user_id: i64, subject_id: i64) -> Result<i64, AstralError>;
}

pub struct SqlxUserSubjectRepository {
    db: MySqlPool,
}

impl SqlxUserSubjectRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

#[async_trait]
impl UserSubjectRepository for SqlxUserSubjectRepository {
    async fn count(&self, user_id: i64) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM learn_user_subject WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list(
        &self,
        user_id: i64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<UserSubjectRecord>, AstralError> {
        sqlx::query_as::<_, UserSubjectRecord>(
            "SELECT id, user_id, subject_id, selected_at AS enrolled_at \
             FROM learn_user_subject WHERE user_id = ? ORDER BY id LIMIT ? OFFSET ?",
        )
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn enroll(&self, user_id: i64, subject_id: i64) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO learn_user_subject (user_id, subject_id, selected_at) VALUES (?, ?, NOW())",
        )
        .bind(user_id)
        .bind(subject_id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("User subject repository query failed: {error}"))
}
