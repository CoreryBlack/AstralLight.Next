//! 用户作答数据访问 — UserAnswerRepository
//!
//! 对齐 Java `UserAnswerMapper` 边界（user_answer 表）。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::AstralError;

/// 作答行
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserAnswerRecord {
    pub id: i64,
    pub user_id: i64,
    pub question_id: i64,
    pub answer: Option<String>,
    pub is_correct: i32,
    pub created_at: Option<time::PrimitiveDateTime>,
}

#[async_trait]
pub trait UserAnswerRepository: Send + Sync {
    /// 新建，返回新 id
    async fn create(
        &self,
        user_id: i64,
        question_id: i64,
        answer: Option<&str>,
        is_correct: bool,
    ) -> Result<i64, AstralError>;
    /// 总数（分页）
    async fn count(&self, user_id: i64) -> Result<i64, AstralError>;
    /// 分页列表（created_at DESC）
    async fn list(
        &self,
        user_id: i64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<UserAnswerRecord>, AstralError>;
}

pub struct SqlxUserAnswerRepository {
    db: MySqlPool,
}

impl SqlxUserAnswerRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

const USER_ANSWER_SELECT: &str =
    "SELECT id, user_id, question_id, answer, is_correct, created_at FROM user_answer";

#[async_trait]
impl UserAnswerRepository for SqlxUserAnswerRepository {
    async fn create(
        &self,
        user_id: i64,
        question_id: i64,
        answer: Option<&str>,
        is_correct: bool,
    ) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO user_answer (user_id, question_id, answer, is_correct, created_at) \
             VALUES (?, ?, ?, ?, NOW())",
        )
        .bind(user_id)
        .bind(question_id)
        .bind(answer)
        .bind(is_correct as i32)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
    }

    async fn count(&self, user_id: i64) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user_answer WHERE user_id = ?")
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
    ) -> Result<Vec<UserAnswerRecord>, AstralError> {
        sqlx::query_as::<_, UserAnswerRecord>(&format!(
            "{USER_ANSWER_SELECT} WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?"
        ))
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("User answer repository query failed: {error}"))
}
