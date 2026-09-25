//! 学习进度数据访问 — ProgressRepository
//!
//! 对齐 Java `LearningProgressMapper` 边界（learn_question / learn_question_first_attempt）。
//! platform_v4：COUNT(*) 返回 DECIMAL，统一 CAST(... AS SIGNED)。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::AstralError;

/// 首次作答行（first_attempts.rs）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FirstAttemptRecord {
    pub id: i64,
    pub user_id: i64,
    pub question_id: i64,
    pub subject_id: Option<i64>,
    pub is_correct: i32,
    pub attempted_at: Option<time::PrimitiveDateTime>,
}

#[async_trait]
pub trait ProgressRepository: Send + Sync {
    /// 学科活跃题目数（CAST AS SIGNED）
    async fn count_active_questions(&self, subject_id: i64) -> Result<i32, AstralError>;
    /// 作答统计（completed_questions, correct_count；CAST AS SIGNED）
    async fn attempt_stats(&self, user_id: i64, subject_id: i64)
        -> Result<(i32, i32), AstralError>;
    /// 插入首次作答（INSERT IGNORE 幂等）
    async fn insert_ignore_first_attempt(
        &self,
        user_id: i64,
        question_id: i64,
        subject_id: i64,
        correct: bool,
    ) -> Result<(), AstralError>;
    /// 连续打卡天数（窗口 CTE；platform_v4 需 CAST AS SIGNED）
    async fn compute_streak_days(&self, user_id: i64, subject_id: i64) -> Result<i32, AstralError>;
    /// 首次作答总数（分页）
    async fn count_first_attempts(&self, user_id: i64) -> Result<i64, AstralError>;
    /// 首次作答分页（attempted_at DESC）
    async fn list_first_attempts(
        &self,
        user_id: i64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<FirstAttemptRecord>, AstralError>;
}

pub struct SqlxProgressRepository {
    db: MySqlPool,
}

impl SqlxProgressRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

#[async_trait]
impl ProgressRepository for SqlxProgressRepository {
    async fn count_active_questions(&self, subject_id: i64) -> Result<i32, AstralError> {
        sqlx::query_scalar::<_, i32>(
            "SELECT CAST(COUNT(*) AS SIGNED) FROM learn_question WHERE subject_id = ? AND status = 'ACTIVE'",
        )
        .bind(subject_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)
    }

    async fn attempt_stats(
        &self,
        user_id: i64,
        subject_id: i64,
    ) -> Result<(i32, i32), AstralError> {
        let (total, correct): (i32, i32) = sqlx::query_as(
            "SELECT CAST(COUNT(*) AS SIGNED) as total, \
             COALESCE(CAST(SUM(CASE WHEN first_attempt_is_correct = 1 THEN 1 ELSE 0 END) AS SIGNED), 0) as correct \
             FROM learn_question_first_attempt WHERE user_id = ? AND subject_id = ?",
        )
        .bind(user_id)
        .bind(subject_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)?;
        Ok((total, correct))
    }

    async fn insert_ignore_first_attempt(
        &self,
        user_id: i64,
        question_id: i64,
        subject_id: i64,
        correct: bool,
    ) -> Result<(), AstralError> {
        sqlx::query(
            "INSERT IGNORE INTO learn_question_first_attempt \
             (user_id, question_id, subject_id, first_attempt_is_correct, first_attempt_at) \
             VALUES (?, ?, ?, ?, NOW())",
        )
        .bind(user_id)
        .bind(question_id)
        .bind(subject_id)
        .bind(correct as i32)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn compute_streak_days(&self, user_id: i64, subject_id: i64) -> Result<i32, AstralError> {
        #[derive(sqlx::FromRow)]
        struct StreakCount {
            cnt: i32,
        }
        let row: Option<StreakCount> = sqlx::query_as(
            "WITH dates AS ( \
                 SELECT DISTINCT DATE(first_attempt_at) AS dt \
                 FROM learn_question_first_attempt \
                 WHERE user_id = ? AND subject_id = ? \
                   AND first_attempt_at >= DATE_SUB(NOW(), INTERVAL 365 DAY) \
             ), \
             numbered AS ( \
                 SELECT dt, ROW_NUMBER() OVER (ORDER BY dt DESC) AS rn, \
                        DATEDIFF(DATE(NOW()), dt) AS days_ago \
                 FROM dates \
             ), \
             gaps AS ( \
                 SELECT dt, rn, days_ago, days_ago - rn AS grp FROM numbered \
             ) \
             SELECT CAST(COUNT(*) AS SIGNED) AS cnt FROM gaps WHERE grp = 0",
        )
        .bind(user_id)
        .bind(subject_id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)?;
        Ok(row.map(|r| r.cnt).unwrap_or(0))
    }

    async fn count_first_attempts(&self, user_id: i64) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>(
            "SELECT CAST(COUNT(*) AS SIGNED) FROM learn_question_first_attempt WHERE user_id = ?",
        )
        .bind(user_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)
    }

    async fn list_first_attempts(
        &self,
        user_id: i64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<FirstAttemptRecord>, AstralError> {
        sqlx::query_as::<_, FirstAttemptRecord>(
            "SELECT id, user_id, question_id, subject_id, \
             first_attempt_is_correct AS is_correct, first_attempt_at AS attempted_at \
             FROM learn_question_first_attempt WHERE user_id = ? \
             ORDER BY first_attempt_at DESC LIMIT ? OFFSET ?",
        )
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Progress repository query failed: {error}"))
}
