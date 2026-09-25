//! 选课数据访问 — EnrollmentRepository
//!
//! 对齐 Java `EnrollmentMapper` 边界（learn_course_enrollment 表）。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::AstralError;

/// 选课行
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EnrollmentRecord {
    pub id: i64,
    pub user_id: i64,
    pub course_id: i64,
    pub status: String,
    pub progress_pct: f64,
}

#[async_trait]
pub trait EnrollmentRepository: Send + Sync {
    /// 选课（status='ACTIVE', progress=0），返回新 id
    async fn enroll(&self, user_id: i64, course_id: i64) -> Result<i64, AstralError>;
    /// 总数（分页）
    async fn count(&self, user_id: i64) -> Result<i64, AstralError>;
    /// 分页列表
    async fn list(
        &self,
        user_id: i64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<EnrollmentRecord>, AstralError>;
    /// 退课（status='WITHDRAWN'）
    async fn withdraw(&self, id: i64) -> Result<(), AstralError>;
}

pub struct SqlxEnrollmentRepository {
    db: MySqlPool,
}

impl SqlxEnrollmentRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

const ENROLLMENT_SELECT: &str =
    "SELECT id, user_id, course_id, status, progress_pct FROM learn_course_enrollment";

#[async_trait]
impl EnrollmentRepository for SqlxEnrollmentRepository {
    async fn enroll(&self, user_id: i64, course_id: i64) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO learn_course_enrollment (user_id,course_id,status,progress_pct) \
             VALUES (?,?,'ACTIVE',0)",
        )
        .bind(user_id)
        .bind(course_id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
    }

    async fn count(&self, user_id: i64) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM learn_course_enrollment WHERE user_id=?")
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
    ) -> Result<Vec<EnrollmentRecord>, AstralError> {
        sqlx::query_as::<_, EnrollmentRecord>(&format!(
            "{ENROLLMENT_SELECT} WHERE user_id=? ORDER BY id LIMIT ? OFFSET ?"
        ))
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn withdraw(&self, id: i64) -> Result<(), AstralError> {
        sqlx::query("UPDATE learn_course_enrollment SET status='WITHDRAWN' WHERE id=?")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Enrollment repository query failed: {error}"))
}
