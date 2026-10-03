//! 作业/提交数据访问 — AssignmentRepository
//!
//! 对齐 Java `AssignmentMapper` + `SubmissionMapper` 边界（learn_assignment +
//! learn_submission），供 assignments / submissions / grades 三个模块复用。
//! 列名与 Rust 字段同名，无别名（submissions 的 user_id 映射为 student_id 除外）。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::AstralError;

/// 作业行（assignments.rs Assignment）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AssignmentRecord {
    pub id: i64,
    pub course_id: i64,
    pub title: String,
    pub description: Option<String>,
    pub max_score: f64,
    pub status: String,
}

/// 提交行（assignments.rs Submission）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AssignmentSubmissionRecord {
    pub id: i64,
    pub assignment_id: i64,
    pub user_id: i64,
    pub content: Option<String>,
    pub score: Option<f64>,
    pub graded: i8,
}

/// 提交行（submissions.rs SubmissionRow：user_id → student_id）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SubmissionRowRecord {
    pub id: i64,
    pub assignment_id: i64,
    pub student_id: i64,
    pub content: Option<String>,
    pub file_url: Option<String>,
    pub score: Option<f64>,
    pub feedback: Option<String>,
    pub status: String,
}

/// 成绩行（grades.rs）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct GradeRecord {
    pub id: i64,
    pub user_id: i64,
    pub score: f64,
    pub comment: Option<String>,
}

/// 成绩单行（grades.rs transcript）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TranscriptRow {
    pub course_id: i64,
    pub title: String,
    pub score: f64,
}

/// 新建/更新作业参数
#[derive(Debug, Clone)]
pub struct AssignmentInput {
    pub course_id: i64,
    pub title: String,
    pub description: Option<String>,
    pub max_score: f64,
}

#[async_trait]
pub trait AssignmentRepository: Send + Sync {
    // ===== Assignment CRUD =====
    async fn count_assignments(&self) -> Result<i64, AstralError>;
    async fn list_assignments(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AssignmentRecord>, AstralError>;
    async fn get_assignment(&self, id: i64) -> Result<Option<AssignmentRecord>, AstralError>;
    async fn create_assignment(&self, input: &AssignmentInput) -> Result<i64, AstralError>;
    async fn update_assignment(&self, id: i64, input: &AssignmentInput) -> Result<(), AstralError>;
    async fn archive_assignment(&self, id: i64) -> Result<(), AstralError>;

    // ===== Submissions（assignments 模块）=====
    /// 按作业列出提交
    async fn list_submissions_by_assignment(
        &self,
        assignment_id: i64,
    ) -> Result<Vec<AssignmentSubmissionRecord>, AstralError>;
    /// 提交作业（INSERT ... ON DUPLICATE KEY UPDATE 幂等；返回 last_insert_id，重复提交可能为 0，保留原语义）
    async fn submit_assignment(
        &self,
        assignment_id: i64,
        user_id: i64,
        content: &str,
    ) -> Result<i64, AstralError>;
    /// 批改（assignment_id + user_id 定位）
    async fn grade_submission(
        &self,
        assignment_id: i64,
        user_id: i64,
        score: f64,
    ) -> Result<(), AstralError>;
    /// 课程作业统计（作业总数, 已批改提交数）
    async fn course_stats(&self, course_id: i64) -> Result<(i64, i64), AstralError>;

    // ===== Submissions（submissions 模块）=====
    async fn count_submissions(&self) -> Result<i64, AstralError>;
    async fn list_submissions_page(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SubmissionRowRecord>, AstralError>;
    async fn create_submission(
        &self,
        assignment_id: i64,
        user_id: i64,
        content: Option<&str>,
        file_url: Option<&str>,
    ) -> Result<i64, AstralError>;
    async fn get_submission(&self, id: i64) -> Result<Option<SubmissionRowRecord>, AstralError>;
    /// 更新提交（含 user_id 归属过滤；修复原 handler 缺失 bind 的潜在运行时错误）
    async fn update_submission(
        &self,
        id: i64,
        user_id: i64,
        content: Option<&str>,
        file_url: Option<&str>,
    ) -> Result<u64, AstralError>;
    /// 硬删除提交
    async fn delete_submission(&self, id: i64) -> Result<u64, AstralError>;
    /// 批改（id 定位，status='GRADED'）
    async fn grade_submission_by_id(
        &self,
        id: i64,
        score: f64,
        feedback: Option<&str>,
    ) -> Result<(), AstralError>;

    // ===== Grades（grades 模块）=====
    /// 查找或创建唯一的合成成绩簿作业，返回 assignment_id。
    /// The row is identified only by the schema-owned DEFAULT_GRADE discriminator;
    /// legacy assignments without that marker are never guessed or adopted.
    async fn get_or_create_assignment(&self, course_id: i64) -> Result<i64, AstralError>;
    /// 成绩 upsert（ON DUPLICATE KEY UPDATE 幂等）
    async fn upsert_submission(
        &self,
        assignment_id: i64,
        user_id: i64,
        score: f64,
        comment: Option<&str>,
    ) -> Result<(), AstralError>;
    /// 取提交 id（upsert 后重读）
    async fn get_submission_id(&self, assignment_id: i64, user_id: i64)
        -> Result<i64, AstralError>;
    /// 单个成绩（无行 → None，service 降级为零分）
    async fn get_grade(
        &self,
        course_id: i64,
        user_id: i64,
    ) -> Result<Option<GradeRecord>, AstralError>;
    /// 课程成绩列表
    async fn list_course_grades(&self, course_id: i64) -> Result<Vec<GradeRecord>, AstralError>;
    /// 更新成绩（body 含 score 时才调用）
    async fn update_grade_score(&self, id: i64, score: f64) -> Result<(), AstralError>;
    /// 成绩单（graded=1 的提交）
    async fn transcript(&self, user_id: i64) -> Result<Vec<TranscriptRow>, AstralError>;
}

pub struct SqlxAssignmentRepository {
    db: MySqlPool,
}

impl SqlxAssignmentRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

const ASSIGNMENT_SELECT: &str =
    "SELECT id, course_id, title, description, max_score, status FROM learn_assignment";
const DEFAULT_GRADE_COUNT_SQL: &str = "SELECT COUNT(*) FROM learn_assignment \
     WHERE course_id = ? AND system_role = 'DEFAULT_GRADE'";

#[cfg(test)]
const SQL_CONTINUATION_TESTS: &[(&str, &str)] =
    &[("default grade assignment count", DEFAULT_GRADE_COUNT_SQL)];

#[async_trait]
impl AssignmentRepository for SqlxAssignmentRepository {
    // ===== Assignment CRUD =====
    async fn count_assignments(&self) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM learn_assignment")
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_assignments(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AssignmentRecord>, AstralError> {
        sqlx::query_as::<_, AssignmentRecord>(&format!(
            "{ASSIGNMENT_SELECT} ORDER BY id LIMIT ? OFFSET ?"
        ))
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn get_assignment(&self, id: i64) -> Result<Option<AssignmentRecord>, AstralError> {
        sqlx::query_as::<_, AssignmentRecord>(&format!("{ASSIGNMENT_SELECT} WHERE id = ?"))
            .bind(id)
            .fetch_optional(&self.db)
            .await
            .map_err(db_error)
    }

    async fn create_assignment(&self, input: &AssignmentInput) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO learn_assignment (course_id,title,description,max_score,status) \
             VALUES (?,?,?,?,'DRAFT')",
        )
        .bind(input.course_id)
        .bind(&input.title)
        .bind(&input.description)
        .bind(input.max_score)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
    }

    async fn update_assignment(&self, id: i64, input: &AssignmentInput) -> Result<(), AstralError> {
        sqlx::query(
            "UPDATE learn_assignment SET course_id=?,title=?,description=?,max_score=? WHERE id=?",
        )
        .bind(input.course_id)
        .bind(&input.title)
        .bind(&input.description)
        .bind(input.max_score)
        .bind(id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn archive_assignment(&self, id: i64) -> Result<(), AstralError> {
        sqlx::query("UPDATE learn_assignment SET status='ARCHIVED' WHERE id=?")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    // ===== Submissions（assignments 模块）=====
    async fn list_submissions_by_assignment(
        &self,
        assignment_id: i64,
    ) -> Result<Vec<AssignmentSubmissionRecord>, AstralError> {
        sqlx::query_as::<_, AssignmentSubmissionRecord>(
            "SELECT id, assignment_id, user_id, content, score, graded \
             FROM learn_submission WHERE assignment_id=? ORDER BY id",
        )
        .bind(assignment_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn submit_assignment(
        &self,
        assignment_id: i64,
        user_id: i64,
        content: &str,
    ) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO learn_submission (assignment_id,user_id,content,graded) VALUES (?,?,?,0) \
             ON DUPLICATE KEY UPDATE content=VALUES(content),graded=0",
        )
        .bind(assignment_id)
        .bind(user_id)
        .bind(content)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        // 保留原语义：重复提交（ON DUPLICATE KEY UPDATE）时 last_insert_id() 可能为 0
        Ok(result.last_insert_id() as i64)
    }

    async fn grade_submission(
        &self,
        assignment_id: i64,
        user_id: i64,
        score: f64,
    ) -> Result<(), AstralError> {
        sqlx::query(
            "UPDATE learn_submission SET score=?,graded=1 WHERE assignment_id=? AND user_id=?",
        )
        .bind(score)
        .bind(assignment_id)
        .bind(user_id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn course_stats(&self, course_id: i64) -> Result<(i64, i64), AstralError> {
        let total: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM learn_assignment WHERE course_id=?")
                .bind(course_id)
                .fetch_one(&self.db)
                .await
                .map_err(db_error)?;
        let graded: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM learn_submission s JOIN learn_assignment a ON a.id=s.assignment_id \
             WHERE a.course_id=? AND s.graded=1",
        )
        .bind(course_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)?;
        Ok((total.0, graded.0))
    }

    // ===== Submissions（submissions 模块）=====
    async fn count_submissions(&self) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM learn_submission")
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_submissions_page(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SubmissionRowRecord>, AstralError> {
        sqlx::query_as::<_, SubmissionRowRecord>(
            "SELECT id, assignment_id, user_id as student_id, content, file_url, score, feedback, status \
             FROM learn_submission ORDER BY id LIMIT ? OFFSET ?",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn create_submission(
        &self,
        assignment_id: i64,
        user_id: i64,
        content: Option<&str>,
        file_url: Option<&str>,
    ) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO learn_submission (assignment_id, user_id, content, file_url, status) \
             VALUES (?, ?, ?, ?, 'SUBMITTED')",
        )
        .bind(assignment_id)
        .bind(user_id)
        .bind(content)
        .bind(file_url)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
    }

    async fn get_submission(&self, id: i64) -> Result<Option<SubmissionRowRecord>, AstralError> {
        sqlx::query_as::<_, SubmissionRowRecord>(
            "SELECT id, assignment_id, user_id as student_id, content, file_url, score, feedback, status \
             FROM learn_submission WHERE id=?",
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn update_submission(
        &self,
        id: i64,
        user_id: i64,
        content: Option<&str>,
        file_url: Option<&str>,
    ) -> Result<u64, AstralError> {
        // 修复原 handler 的 bind 缺失：SQL 4 个占位符但只绑定 3 个（缺 user_id），
        // 运行时会报 bind 数量错误。此处补齐 user_id 绑定。
        let result = sqlx::query(
            "UPDATE learn_submission SET content=?, file_url=? WHERE id=? AND user_id=?",
        )
        .bind(content)
        .bind(file_url)
        .bind(id)
        .bind(user_id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected())
    }

    async fn delete_submission(&self, id: i64) -> Result<u64, AstralError> {
        let result = sqlx::query("DELETE FROM learn_submission WHERE id=?")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected())
    }

    async fn grade_submission_by_id(
        &self,
        id: i64,
        score: f64,
        feedback: Option<&str>,
    ) -> Result<(), AstralError> {
        sqlx::query("UPDATE learn_submission SET score=?, feedback=?, status='GRADED' WHERE id=?")
            .bind(score)
            .bind(feedback)
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    // ===== Grades（grades 模块）=====
    async fn get_or_create_assignment(&self, course_id: i64) -> Result<i64, AstralError> {
        let mut tx = self.db.begin().await.map_err(db_error)?;
        let course: Option<(i64,)> =
            sqlx::query_as("SELECT course_id FROM learn_course WHERE course_id = ? FOR UPDATE")
                .bind(course_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_error)?;
        if course.is_none() {
            return Err(AstralError::NotFound(format!(
                "Course {course_id} not found"
            )));
        }

        // The course lock serializes writers for this course. Only the explicit
        // schema-owned marker establishes the synthetic gradebook assignment;
        // title, status, id order, and existing submissions carry no such proof.
        let matching: Vec<(i64,)> = sqlx::query_as(
            "SELECT id FROM learn_assignment \
             WHERE course_id = ? AND system_role = 'DEFAULT_GRADE' FOR UPDATE",
        )
        .bind(course_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(db_error)?;
        match matching.as_slice() {
            [(id,)] => {
                let id = *id;
                let duplicate_count: i64 = sqlx::query_scalar(DEFAULT_GRADE_COUNT_SQL)
                    .bind(course_id)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(db_error)?;
                if duplicate_count != 1 {
                    return Err(AstralError::Database(
                        "DEFAULT_GRADE discriminator uniqueness proof is violated".into(),
                    ));
                }
                tx.commit().await.map_err(db_error)?;
                return Ok(id);
            }
            [] => {}
            _ => {
                return Err(AstralError::Database(
                    "Course has duplicate DEFAULT_GRADE assignments; refusing ambiguous grading"
                        .into(),
                ));
            }
        }

        let result = sqlx::query(
            "INSERT INTO learn_assignment (course_id, title, status, system_role) \
             VALUES (?, ?, 'PUBLISHED', 'DEFAULT_GRADE')",
        )
        .bind(course_id)
        .bind("默认评分")
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        let assignment_id = result.last_insert_id() as i64;
        tx.commit().await.map_err(db_error)?;
        Ok(assignment_id)
    }

    async fn upsert_submission(
        &self,
        assignment_id: i64,
        user_id: i64,
        score: f64,
        comment: Option<&str>,
    ) -> Result<(), AstralError> {
        sqlx::query(
            "INSERT INTO learn_submission (assignment_id, user_id, score, graded, content, status) \
             VALUES (?, ?, ?, 1, ?, 'GRADED') \
             ON DUPLICATE KEY UPDATE score = VALUES(score), graded = 1, content = VALUES(content), status = 'GRADED'",
        )
        .bind(assignment_id)
        .bind(user_id)
        .bind(score)
        .bind(comment)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn get_submission_id(
        &self,
        assignment_id: i64,
        user_id: i64,
    ) -> Result<i64, AstralError> {
        let (id,): (i64,) = sqlx::query_as(
            "SELECT id FROM learn_submission WHERE assignment_id = ? AND user_id = ?",
        )
        .bind(assignment_id)
        .bind(user_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)?;
        Ok(id)
    }

    async fn get_grade(
        &self,
        course_id: i64,
        user_id: i64,
    ) -> Result<Option<GradeRecord>, AstralError> {
        sqlx::query_as::<_, GradeRecord>(
            "SELECT s.id, s.user_id, COALESCE(s.score,0) as score, s.content as comment \
             FROM learn_submission s JOIN learn_assignment a ON a.id=s.assignment_id \
             WHERE a.course_id=? AND a.system_role='DEFAULT_GRADE' AND s.user_id=?",
        )
        .bind(course_id)
        .bind(user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn list_course_grades(&self, course_id: i64) -> Result<Vec<GradeRecord>, AstralError> {
        sqlx::query_as::<_, GradeRecord>(
            "SELECT s.id, s.user_id, COALESCE(s.score,0) as score, s.content as comment \
             FROM learn_submission s JOIN learn_assignment a ON a.id=s.assignment_id \
             WHERE a.course_id=? AND a.system_role='DEFAULT_GRADE' ORDER BY s.user_id",
        )
        .bind(course_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn update_grade_score(&self, id: i64, score: f64) -> Result<(), AstralError> {
        sqlx::query("UPDATE learn_submission SET score=?, graded=1 WHERE id=?")
            .bind(score)
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn transcript(&self, user_id: i64) -> Result<Vec<TranscriptRow>, AstralError> {
        sqlx::query_as::<_, TranscriptRow>(
            "SELECT a.course_id, a.title, COALESCE(s.score,0) as score \
             FROM learn_submission s JOIN learn_assignment a ON a.id=s.assignment_id \
             WHERE s.user_id=? AND s.graded=1",
        )
        .bind(user_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Assignment repository query failed: {error}"))
}

#[cfg(test)]
mod sql_tests {
    use super::*;

    #[test]
    fn important_sql_continuations_emit_single_spaces_without_backslashes() {
        use sqlx::Execute;

        for (name, sql) in SQL_CONTINUATION_TESTS {
            let query = sqlx::query::<sqlx::MySql>(sql);
            let emitted = query.sql();
            assert!(
                !emitted.contains('\\'),
                "{name} SQL contains a literal backslash"
            );
            assert!(
                !emitted.contains('\n'),
                "{name} SQL contains an unintended newline"
            );
            assert!(
                !emitted.contains("  "),
                "{name} SQL contains duplicate spaces"
            );
        }
        assert!(DEFAULT_GRADE_COUNT_SQL.contains("system_role = 'DEFAULT_GRADE'"));
    }
}
