//! 题目解析数据访问 — SolutionRepository
//!
//! 对齐 Java `SolutionMapper` 边界（learn_question_solution 表）。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::AstralError;

/// 解析行
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SolutionRecord {
    pub id: i64,
    pub question_id: i64,
    pub user_id: i64,
    pub content: String,
    pub like_count: i32,
    pub created_at: Option<time::PrimitiveDateTime>,
}

#[async_trait]
pub trait SolutionRepository: Send + Sync {
    /// 总数（可选按 question 过滤）
    async fn count(&self, question_id: Option<i64>) -> Result<i64, AstralError>;
    /// 分页列表（可选按 question 过滤）
    async fn list(
        &self,
        question_id: Option<i64>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SolutionRecord>, AstralError>;
    /// 新建，返回新 id
    async fn create(
        &self,
        question_id: i64,
        user_id: i64,
        content: &str,
    ) -> Result<i64, AstralError>;
    /// 点赞（like_count + 1），返回是否命中
    async fn like(&self, id: i64) -> Result<bool, AstralError>;
}

pub struct SqlxSolutionRepository {
    db: MySqlPool,
}

impl SqlxSolutionRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

const SOLUTION_SELECT: &str =
    "SELECT id, question_id, user_id, content, like_count, created_at FROM learn_question_solution";

#[async_trait]
impl SolutionRepository for SqlxSolutionRepository {
    async fn count(&self, question_id: Option<i64>) -> Result<i64, AstralError> {
        match question_id {
            Some(qid) => sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM learn_question_solution WHERE question_id = ?",
            )
            .bind(qid)
            .fetch_one(&self.db)
            .await
            .map_err(db_error),
            None => sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM learn_question_solution")
                .fetch_one(&self.db)
                .await
                .map_err(db_error),
        }
    }

    async fn list(
        &self,
        question_id: Option<i64>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SolutionRecord>, AstralError> {
        match question_id {
            Some(qid) => sqlx::query_as::<_, SolutionRecord>(&format!(
                "{SOLUTION_SELECT} WHERE question_id = ? ORDER BY like_count DESC, id LIMIT ? OFFSET ?"
            ))
            .bind(qid)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db)
            .await
            .map_err(db_error),
            None => sqlx::query_as::<_, SolutionRecord>(&format!(
                "{SOLUTION_SELECT} ORDER BY id DESC LIMIT ? OFFSET ?"
            ))
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db)
            .await
            .map_err(db_error),
        }
    }

    async fn create(
        &self,
        question_id: i64,
        user_id: i64,
        content: &str,
    ) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO learn_question_solution (question_id, user_id, content, like_count, created_at) \
             VALUES (?, ?, ?, 0, NOW())",
        )
        .bind(question_id)
        .bind(user_id)
        .bind(content)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
    }

    async fn like(&self, id: i64) -> Result<bool, AstralError> {
        let result = sqlx::query(
            "UPDATE learn_question_solution SET like_count = like_count + 1 WHERE id = ?",
        )
        .bind(id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() > 0)
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Solution repository query failed: {error}"))
}
