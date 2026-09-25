//! 课程发布工作流数据访问 — PublishingRepository
//!
//! 对齐 Java `CoursePublishingServiceImpl` 边界（learn_course + course_workflow +
//! 聚合查询）。状态机守卫式 UPDATE（DRAFT→REVIEW→APPROVED→PUBLISHED）与
//! workflow upsert 在此层；状态机编排在 `service::publishing_service`。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::AstralError;

/// 工作流状态（course_workflow 关联行）
#[derive(Debug, Clone, Default)]
pub struct WorkflowRecord {
    pub current_status: String,
    pub reviewer_id: Option<i64>,
    pub review_comment: Option<String>,
    pub published_at: Option<String>,
}

/// 课程统计行（learn_course_enrollment 聚合）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CourseStatsRecord {
    pub total_students: i64,
    pub avg_progress: f64,
    pub completion_rate: f64,
    pub avg_score: f64,
}

#[async_trait]
pub trait PublishingRepository: Send + Sync {
    /// DRAFT 或 APPROVED → PUBLISHED（守卫式），返回是否命中
    async fn publish_course(&self, course_id: i64) -> Result<bool, AstralError>;
    /// 任意状态 → ARCHIVED（无守卫），返回是否命中
    async fn archive_course(&self, course_id: i64) -> Result<bool, AstralError>;
    /// DRAFT → REVIEW（守卫式），返回是否命中
    async fn submit_for_review(&self, course_id: i64) -> Result<bool, AstralError>;
    /// REVIEW → APPROVED（守卫式），返回是否命中
    async fn approve_course(&self, course_id: i64) -> Result<bool, AstralError>;
    /// upsert 发布记录（published_at = NOW()）
    async fn upsert_published_at(&self, course_id: i64) -> Result<(), AstralError>;
    /// upsert 审批记录（reviewer_id=1, review_comment='Ready for publishing'）
    async fn upsert_approval(&self, course_id: i64) -> Result<(), AstralError>;
    /// 查询工作流（无关联行 → None）
    async fn get_workflow(&self, course_id: i64) -> Result<Option<WorkflowRecord>, AstralError>;
    /// 课程统计（4 表聚合）
    async fn course_stats(&self, course_id: i64) -> Result<CourseStatsRecord, AstralError>;
    /// 课程章节数（learn_lesson JOIN learn_chapter by subject_id）
    async fn count_lessons(&self, course_id: i64) -> Result<i32, AstralError>;
    /// 已作答章节数（DISTINCT lesson via first_attempt）
    async fn count_answered_lessons(
        &self,
        course_id: i64,
        user_id: i64,
    ) -> Result<i32, AstralError>;
    /// 选课进度（无行 → None）
    async fn get_enrollment_progress(
        &self,
        course_id: i64,
        user_id: i64,
    ) -> Result<Option<f64>, AstralError>;
}

pub struct SqlxPublishingRepository {
    db: MySqlPool,
}

impl SqlxPublishingRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

#[async_trait]
impl PublishingRepository for SqlxPublishingRepository {
    async fn publish_course(&self, course_id: i64) -> Result<bool, AstralError> {
        let result = sqlx::query(
            "UPDATE learn_course SET status = 'PUBLISHED' WHERE course_id = ? AND status IN ('DRAFT','APPROVED')",
        )
        .bind(course_id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn archive_course(&self, course_id: i64) -> Result<bool, AstralError> {
        let result = sqlx::query("UPDATE learn_course SET status = 'ARCHIVED' WHERE course_id = ?")
            .bind(course_id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn submit_for_review(&self, course_id: i64) -> Result<bool, AstralError> {
        let result = sqlx::query(
            "UPDATE learn_course SET status = 'REVIEW' WHERE course_id = ? AND status = 'DRAFT'",
        )
        .bind(course_id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn approve_course(&self, course_id: i64) -> Result<bool, AstralError> {
        let result = sqlx::query(
            "UPDATE learn_course SET status = 'APPROVED' WHERE course_id = ? AND status = 'REVIEW'",
        )
        .bind(course_id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn upsert_published_at(&self, course_id: i64) -> Result<(), AstralError> {
        sqlx::query(
            "INSERT INTO course_workflow (course_id, published_at) \
             VALUES (?, NOW()) ON DUPLICATE KEY UPDATE published_at = NOW()",
        )
        .bind(course_id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn upsert_approval(&self, course_id: i64) -> Result<(), AstralError> {
        sqlx::query(
            "INSERT INTO course_workflow (course_id, reviewer_id, review_comment) \
             VALUES (?, 1, 'Ready for publishing') \
             ON DUPLICATE KEY UPDATE reviewer_id = 1, review_comment = 'Ready for publishing'",
        )
        .bind(course_id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn get_workflow(&self, course_id: i64) -> Result<Option<WorkflowRecord>, AstralError> {
        let row: Option<(String, Option<i64>, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT c.status, cw.reviewer_id, cw.review_comment, cw.published_at \
             FROM learn_course c LEFT JOIN course_workflow cw ON cw.course_id = c.course_id \
             WHERE c.course_id = ?",
        )
        .bind(course_id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)?;
        Ok(row.map(
            |(current_status, reviewer_id, review_comment, published_at)| WorkflowRecord {
                current_status,
                reviewer_id,
                review_comment,
                published_at,
            },
        ))
    }

    async fn course_stats(&self, course_id: i64) -> Result<CourseStatsRecord, AstralError> {
        let (total_students, avg_progress, completion_rate, avg_score): (i64, f64, f64, f64) =
            sqlx::query_as(
                "SELECT COUNT(*) as total_students, \
                 COALESCE(AVG(progress_pct), 0.0) as avg_progress, \
                 COALESCE(SUM(CASE WHEN progress_pct >= 100.0 THEN 1 ELSE 0 END) / NULLIF(COUNT(*), 0), 0.0) as completion_rate, \
                 COALESCE(AVG(g.score), 0.0) as avg_score \
                 FROM learn_course_enrollment e \
                 LEFT JOIN ( \
                     SELECT s.user_id, a.course_id, s.score \
                     FROM learn_submission s \
                     JOIN learn_assignment a ON a.id = s.assignment_id \
                     WHERE a.course_id = ? \
                 ) g ON g.user_id = e.user_id \
                 WHERE e.course_id = ? AND e.status = 'ACTIVE'",
            )
            .bind(course_id)
            .bind(course_id)
            .fetch_one(&self.db)
            .await
            .map_err(db_error)?;
        Ok(CourseStatsRecord {
            total_students,
            avg_progress,
            completion_rate,
            avg_score,
        })
    }

    async fn count_lessons(&self, course_id: i64) -> Result<i32, AstralError> {
        sqlx::query_scalar::<_, i32>(
            "SELECT COUNT(*) FROM learn_lesson l \
             JOIN learn_chapter ch ON ch.chapter_id = l.chapter_id \
             WHERE ch.subject_id = ?",
        )
        .bind(course_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)
    }

    async fn count_answered_lessons(
        &self,
        course_id: i64,
        user_id: i64,
    ) -> Result<i32, AstralError> {
        sqlx::query_scalar::<_, i32>(
            "SELECT COUNT(DISTINCT l.id) FROM learn_lesson l \
             JOIN learn_chapter ch ON ch.chapter_id = l.chapter_id \
             JOIN learn_question_first_attempt qfa ON qfa.subject_id = ch.subject_id \
             WHERE ch.subject_id = ? AND qfa.user_id = ?",
        )
        .bind(course_id)
        .bind(user_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)
    }

    async fn get_enrollment_progress(
        &self,
        course_id: i64,
        user_id: i64,
    ) -> Result<Option<f64>, AstralError> {
        let row: Option<(f64,)> = sqlx::query_as(
            "SELECT progress_pct FROM learn_course_enrollment \
             WHERE course_id = ? AND user_id = ? AND status = 'ACTIVE'",
        )
        .bind(course_id)
        .bind(user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)?;
        Ok(row.map(|r| r.0))
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Publishing repository query failed: {error}"))
}
