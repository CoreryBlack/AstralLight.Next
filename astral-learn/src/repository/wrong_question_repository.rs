//! 错题数据访问 — WrongQuestionRepository
//!
//! 对齐 Java `WrongQuestionMapper` 边界（wrong_question 表，无 learn_ 前缀）。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::AstralError;

/// 错题行
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct WrongQuestionRecord {
    pub id: i64,
    pub user_id: i64,
    pub question_id: i64,
    pub subject_id: Option<i64>,
    pub status: String,
    pub reviewed_at: Option<time::PrimitiveDateTime>,
    pub mastered_at: Option<time::PrimitiveDateTime>,
    pub created_at: Option<time::PrimitiveDateTime>,
}

#[async_trait]
pub trait WrongQuestionRepository: Send + Sync {
    /// 总数（可选按 subject 过滤）
    async fn count(&self, user_id: i64, subject_id: Option<i64>) -> Result<i64, AstralError>;
    /// UNREVIEWED 数（可选按 subject 过滤）
    async fn count_unreviewed(
        &self,
        user_id: i64,
        subject_id: Option<i64>,
    ) -> Result<i64, AstralError>;
    /// 分页列表（created_at DESC）
    async fn list(
        &self,
        user_id: i64,
        subject_id: Option<i64>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<WrongQuestionRecord>, AstralError>;
    /// 标记已复习（UNREVIEWED → REVIEWED），返回是否命中
    async fn mark_reviewed(&self, id: i64, user_id: i64) -> Result<bool, AstralError>;
    /// 标记已掌握（→ MASTERED），返回是否命中
    async fn mark_mastered(&self, id: i64, user_id: i64) -> Result<bool, AstralError>;
}

pub struct SqlxWrongQuestionRepository {
    db: MySqlPool,
}

impl SqlxWrongQuestionRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

const WRONG_QUESTION_SELECT: &str =
    "SELECT id, user_id, question_id, subject_id, status, reviewed_at, mastered_at, created_at \
     FROM wrong_question";

#[async_trait]
impl WrongQuestionRepository for SqlxWrongQuestionRepository {
    async fn count(&self, user_id: i64, subject_id: Option<i64>) -> Result<i64, AstralError> {
        match subject_id {
            Some(sid) => sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM wrong_question WHERE user_id = ? AND subject_id = ?",
            )
            .bind(user_id)
            .bind(sid)
            .fetch_one(&self.db)
            .await
            .map_err(db_error),
            None => sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM wrong_question WHERE user_id = ?",
            )
            .bind(user_id)
            .fetch_one(&self.db)
            .await
            .map_err(db_error),
        }
    }

    async fn count_unreviewed(
        &self,
        user_id: i64,
        subject_id: Option<i64>,
    ) -> Result<i64, AstralError> {
        match subject_id {
            Some(sid) => sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM wrong_question WHERE user_id = ? AND subject_id = ? AND status = 'UNREVIEWED'",
            )
            .bind(user_id)
            .bind(sid)
            .fetch_one(&self.db)
            .await
            .map_err(db_error),
            None => sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM wrong_question WHERE user_id = ? AND status = 'UNREVIEWED'",
            )
            .bind(user_id)
            .fetch_one(&self.db)
            .await
            .map_err(db_error),
        }
    }

    async fn list(
        &self,
        user_id: i64,
        subject_id: Option<i64>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<WrongQuestionRecord>, AstralError> {
        match subject_id {
            Some(sid) => sqlx::query_as::<_, WrongQuestionRecord>(&format!(
                "{WRONG_QUESTION_SELECT} WHERE user_id = ? AND subject_id = ? \
                 ORDER BY created_at DESC LIMIT ? OFFSET ?"
            ))
            .bind(user_id)
            .bind(sid)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db)
            .await
            .map_err(db_error),
            None => sqlx::query_as::<_, WrongQuestionRecord>(&format!(
                "{WRONG_QUESTION_SELECT} WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?"
            ))
            .bind(user_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db)
            .await
            .map_err(db_error),
        }
    }

    async fn mark_reviewed(&self, id: i64, user_id: i64) -> Result<bool, AstralError> {
        let result = sqlx::query(
            "UPDATE wrong_question SET status = 'REVIEWED', reviewed_at = NOW() WHERE id = ? AND user_id = ?",
        )
        .bind(id)
        .bind(user_id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn mark_mastered(&self, id: i64, user_id: i64) -> Result<bool, AstralError> {
        let result = sqlx::query(
            "UPDATE wrong_question SET status = 'MASTERED', mastered_at = NOW() WHERE id = ? AND user_id = ?",
        )
        .bind(id)
        .bind(user_id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() > 0)
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Wrong question repository query failed: {error}"))
}
