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
const ACTIVE_ENROLLMENT_COUNT_SQL: &str = "SELECT COUNT(*) FROM learn_course_enrollment \
     WHERE course_id = ? AND status IN ('ACTIVE', 'ENROLLED', 'IN_PROGRESS')";
const INCREMENT_ENROLLED_COUNT_SQL: &str =
    "UPDATE learn_course SET enrolled_count = COALESCE(enrolled_count, 0) + 1 \
     WHERE course_id = ?";

#[cfg(test)]
const SQL_CONTINUATION_TESTS: &[(&str, &str)] = &[
    ("active enrollment count", ACTIVE_ENROLLMENT_COUNT_SQL),
    ("increment enrolled count", INCREMENT_ENROLLED_COUNT_SQL),
];

#[async_trait]
impl EnrollmentRepository for SqlxEnrollmentRepository {
    async fn enroll(&self, user_id: i64, course_id: i64) -> Result<i64, AstralError> {
        let mut tx = self.db.begin().await.map_err(db_error)?;
        // Lock course before reading its nullable authoritative tenant. NULL is
        // retained as the legacy/global scope and matches only NULL enrollments.
        let course: Option<(Option<i32>, Option<i64>, Option<i64>)> = sqlx::query_as(
            "SELECT capacity, tenant_id, subject_id FROM learn_course WHERE course_id = ? FOR UPDATE",
        )
        .bind(course_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
        let Some((capacity, course_tenant_id, subject_id)) = course else {
            return Err(AstralError::NotFound(format!(
                "Course {course_id} not found"
            )));
        };
        validate_course_tenant(&mut tx, subject_id, course_tenant_id).await?;

        let existing: Option<(i64, String, Option<i64>)> = sqlx::query_as(
            "SELECT id, COALESCE(status, ''), tenant_id FROM learn_course_enrollment \
             WHERE course_id = ? AND user_id = ? FOR UPDATE",
        )
        .bind(course_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
        if let Some((id, status, enrollment_tenant_id)) = existing {
            if enrollment_tenant_id != course_tenant_id {
                return Err(AstralError::Validation(
                    "Existing enrollment tenant does not match the authoritative course".into(),
                ));
            }
            if !matches!(status.as_str(), "ACTIVE" | "ENROLLED" | "IN_PROGRESS") {
                ensure_capacity_available(&mut tx, course_id, capacity).await?;
                let updated = sqlx::query(
                    "UPDATE learn_course_enrollment SET status = 'ACTIVE', progress_pct = 0, enrolled_at = NOW() \
                     WHERE id = ? AND tenant_id <=> ?",
                )
                .bind(id)
                .bind(course_tenant_id)
                .execute(&mut *tx)
                .await
                .map_err(db_error)?;
                if updated.rows_affected() != 1 {
                    return Err(AstralError::Database(
                        "Enrollment reactivation lost its tenant-guarded row".into(),
                    ));
                }
                increment_enrolled_count(&mut tx, course_id).await?;
            }
            tx.commit().await.map_err(db_error)?;
            return Ok(id);
        }

        ensure_capacity_available(&mut tx, course_id, capacity).await?;
        let result = sqlx::query(
            "INSERT INTO learn_course_enrollment \
             (user_id,course_id,status,progress_pct,enrolled_at,tenant_id) \
             VALUES (?,?,'ACTIVE',0,NOW(),?)",
        )
        .bind(user_id)
        .bind(course_id)
        .bind(course_tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        let id = result.last_insert_id() as i64;
        increment_enrolled_count(&mut tx, course_id).await?;
        tx.commit().await.map_err(db_error)?;
        Ok(id)
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

async fn ensure_capacity_available(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    course_id: i64,
    capacity: Option<i32>,
) -> Result<(), AstralError> {
    // Schema contract: NULL means unlimited. Zero or negative configured
    // capacity is a closed course and cannot admit another active enrollment.
    match capacity {
        None => Ok(()),
        Some(limit) if limit > 0 => {
            let active_count: i64 = sqlx::query_scalar(ACTIVE_ENROLLMENT_COUNT_SQL)
                .bind(course_id)
                .fetch_one(&mut **tx)
                .await
                .map_err(db_error)?;
            match capacity_allows(Some(limit), active_count) {
                Ok(true) => Ok(()),
                Ok(false) => Err(AstralError::Validation("Course capacity reached".into())),
                Err(error) => Err(AstralError::Validation(error.into())),
            }
        }
        Some(_) => Err(AstralError::Validation("Course capacity reached".into())),
    }
}

fn capacity_allows(capacity: Option<i32>, active_count: i64) -> Result<bool, &'static str> {
    match capacity {
        None => Ok(true),
        Some(limit) if limit > 0 => Ok(active_count < i64::from(limit)),
        Some(_) => Err("Course capacity reached"),
    }
}

async fn increment_enrolled_count(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    course_id: i64,
) -> Result<(), AstralError> {
    let result = sqlx::query(INCREMENT_ENROLLED_COUNT_SQL)
        .bind(course_id)
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
    if result.rows_affected() != 1 {
        return Err(AstralError::Database(
            "Course disappeared while the enrollment lock was held".into(),
        ));
    }
    Ok(())
}

fn tenant_matches(course_tenant_id: Option<i64>, subject_tenant_id: Option<i64>) -> bool {
    course_tenant_id == subject_tenant_id
}

async fn validate_course_tenant(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    subject_id: Option<i64>,
    course_tenant_id: Option<i64>,
) -> Result<(), AstralError> {
    let subject_tenant_id = match subject_id {
        Some(subject_id) => sqlx::query_scalar::<_, Option<i64>>(
            "SELECT tenant_id FROM learn_subject WHERE subject_id = ? FOR SHARE",
        )
        .bind(subject_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_error)?
        .ok_or_else(|| {
            AstralError::Validation(
                "Course subject does not match an authoritative Learn subject row".into(),
            )
        })?,
        None => return Ok(()),
    };
    if !tenant_matches(course_tenant_id, subject_tenant_id) {
        return Err(AstralError::Validation(
            "Course tenant does not match its authoritative Learn subject".into(),
        ));
    }
    Ok(())
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Enrollment repository query failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nullable_capacity_is_unlimited_and_nonpositive_is_closed() {
        assert_eq!(capacity_allows(None, 100), Ok(true));
        assert_eq!(capacity_allows(Some(2), 1), Ok(true));
        assert_eq!(capacity_allows(Some(2), 2), Ok(false));
        assert!(
            !capacity_allows(Some(2), 2).unwrap(),
            "at-capacity must reject another enrollment"
        );
        assert_eq!(capacity_allows(Some(0), 0), Err("Course capacity reached"));
        assert_eq!(capacity_allows(Some(-1), 0), Err("Course capacity reached"));
    }

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
        assert!(ACTIVE_ENROLLMENT_COUNT_SQL.contains("WHERE course_id = ?"));
        assert!(INCREMENT_ENROLLED_COUNT_SQL.contains("WHERE course_id = ?"));
    }

    #[test]
    fn course_tenant_equality_is_required_when_a_subject_is_present() {
        assert!(tenant_matches(None, None));
        assert!(tenant_matches(Some(8), Some(8)));
        assert!(!tenant_matches(Some(8), None));
        assert!(!tenant_matches(Some(8), Some(9)));
    }
}
