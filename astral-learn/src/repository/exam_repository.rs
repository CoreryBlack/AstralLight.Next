//! 考试数据访问 — ExamRepository
//!
//! 对齐 Java `ExamMapper` 边界（exam 表）。列名与 Rust 字段同名，无别名。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::AstralError;

/// 考试行
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ExamRecord {
    pub id: i64,
    pub subject_id: i64,
    pub title: String,
    pub duration_minutes: i32,
    pub total_score: i32,
    pub pass_score: i32,
    pub status: String,
}

/// 考试结果信息（get_exam_result 用）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ExamInfoRecord {
    pub title: String,
    pub total_score: i32,
    pub pass_score: i32,
    pub status: String,
}

/// 新建/更新考试参数（默认值解析在 handler）
#[derive(Debug, Clone)]
pub struct ExamInput {
    pub subject_id: i64,
    pub title: String,
    pub duration_minutes: i32,
    pub total_score: i32,
    pub pass_score: i32,
}

#[async_trait]
pub trait ExamRepository: Send + Sync {
    /// 总数（分页）
    async fn count_all(&self) -> Result<i64, AstralError>;
    /// 分页列表
    async fn list_all(&self, limit: i64, offset: i64) -> Result<Vec<ExamRecord>, AstralError>;
    /// 单条
    async fn get(&self, id: i64) -> Result<Option<ExamRecord>, AstralError>;
    /// 新建（status='DRAFT'），返回新 id
    async fn create(&self, input: &ExamInput) -> Result<i64, AstralError>;
    /// 更新
    async fn update(&self, id: i64, input: &ExamInput) -> Result<(), AstralError>;
    /// 归档（status='ARCHIVED'）
    async fn archive(&self, id: i64) -> Result<(), AstralError>;
    /// 是否存在（submit_exam_app 前置校验）
    async fn exists(&self, id: i64) -> Result<bool, AstralError>;
    /// 标记已提交（status='SUBMITTED'；原 handler 吞错，service 层告警）
    async fn mark_submitted(&self, id: i64) -> Result<(), AstralError>;
    /// 考试结果信息
    async fn get_info(&self, id: i64) -> Result<Option<ExamInfoRecord>, AstralError>;
}

pub struct SqlxExamRepository {
    db: MySqlPool,
}

impl SqlxExamRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

const EXAM_SELECT: &str =
    "SELECT id, subject_id, title, duration_minutes, total_score, pass_score, status FROM exam";

#[async_trait]
impl ExamRepository for SqlxExamRepository {
    async fn count_all(&self) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM exam")
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_all(&self, limit: i64, offset: i64) -> Result<Vec<ExamRecord>, AstralError> {
        sqlx::query_as::<_, ExamRecord>(&format!("{EXAM_SELECT} ORDER BY id LIMIT ? OFFSET ?"))
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db)
            .await
            .map_err(db_error)
    }

    async fn get(&self, id: i64) -> Result<Option<ExamRecord>, AstralError> {
        sqlx::query_as::<_, ExamRecord>(&format!("{EXAM_SELECT} WHERE id = ?"))
            .bind(id)
            .fetch_optional(&self.db)
            .await
            .map_err(db_error)
    }

    async fn create(&self, input: &ExamInput) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO exam (subject_id,title,duration_minutes,total_score,pass_score,status) \
             VALUES (?,?,?,?,?,'DRAFT')",
        )
        .bind(input.subject_id)
        .bind(&input.title)
        .bind(input.duration_minutes)
        .bind(input.total_score)
        .bind(input.pass_score)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
    }

    async fn update(&self, id: i64, input: &ExamInput) -> Result<(), AstralError> {
        sqlx::query(
            "UPDATE exam SET subject_id=?,title=?,duration_minutes=?,total_score=?,pass_score=? WHERE id=?",
        )
        .bind(input.subject_id)
        .bind(&input.title)
        .bind(input.duration_minutes)
        .bind(input.total_score)
        .bind(input.pass_score)
        .bind(id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn archive(&self, id: i64) -> Result<(), AstralError> {
        sqlx::query("UPDATE exam SET status='ARCHIVED' WHERE id=?")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn exists(&self, id: i64) -> Result<bool, AstralError> {
        let exists: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM exam WHERE id = ?")
            .bind(id)
            .fetch_one(&self.db)
            .await
            .map_err(db_error)?;
        Ok(exists.0 > 0)
    }

    async fn mark_submitted(&self, id: i64) -> Result<(), AstralError> {
        sqlx::query("UPDATE exam SET status='SUBMITTED' WHERE id=?")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn get_info(&self, id: i64) -> Result<Option<ExamInfoRecord>, AstralError> {
        sqlx::query_as::<_, ExamInfoRecord>(
            "SELECT title, total_score, pass_score, status FROM exam WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Exam repository query failed: {error}"))
}
