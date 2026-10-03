//! Learn-local resource ownership proofs for routes whose source-row contracts
//! can be read without trusting request identity metadata.
//!
//! These lookups run in the same short MySQL transaction used by the permission
//! middleware. Each mapped lookup locks the target and declared tenant parent
//! with `FOR SHARE`; middleware retains that transaction across PolicyEngine,
//! SoD, and the final source-writer authority-fence check. This protects row
//! metadata from concurrent Learn transactions that update those rows. Routes
//! without a single authoritative row, or whose row cannot prove a tenant/domain
//! relation, remain unresolved and denied.

use astral_db::ResourceOwnershipResolution;
use sqlx::{MySql, Transaction};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LearnOwnershipQuery {
    Subject(i64),
    Course(i64),
    Question(i64),
    Chapter(i64),
    Level(i64),
    Enrollment(i64),
    Assignment(i64),
    Submission(i64),
    Document(i64),
    Progress { subject_id: i64, user_id: i64 },
    CourseProgress { course_id: i64, user_id: i64 },
}

/// Resolve the first-attempt rows that back a Learn progress view through the
/// authoritative question→subject chain. No subject_progress projection exists
/// in the current runtime progress contract.
pub async fn resolve_progress_read_ownership(
    pool: &sqlx::MySqlPool,
    subject_id: i64,
    user_id: i64,
) -> ResourceOwnershipResolution {
    resolve_read_ownership(
        pool,
        PROGRESS_OWNERSHIP_SQL,
        &[user_id, subject_id],
        subject_id,
        user_id,
    )
    .await
}

pub async fn resolve_course_progress_read_ownership(
    pool: &sqlx::MySqlPool,
    course_id: i64,
    user_id: i64,
) -> ResourceOwnershipResolution {
    resolve_read_ownership(
        pool,
        COURSE_PROGRESS_OWNERSHIP_SQL,
        &[course_id, user_id],
        course_id,
        user_id,
    )
    .await
}

async fn resolve_read_ownership(
    pool: &sqlx::MySqlPool,
    sql: &str,
    ids: &[i64],
    target_id: i64,
    user_id: i64,
) -> ResourceOwnershipResolution {
    let mut query = sqlx::query_as::<_, (Option<i64>, Option<i64>, Option<i64>)>(sql);
    for id in ids {
        query = query.bind(*id);
    }
    let row = match query.fetch_optional(pool).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return ResourceOwnershipResolution::Unresolved {
                code: "learn_ownership.progress_source_or_tenant_missing",
            }
        }
        Err(_) => {
            return ResourceOwnershipResolution::Unavailable {
                code: "learn_ownership.progress_source_lookup_unavailable",
            }
        }
    };
    let (Some(tenant_id), domain_id, owner_id) = row else {
        return ResourceOwnershipResolution::Unresolved {
            code: "learn_ownership.progress_tenant_missing",
        };
    };
    if tenant_id <= 0 || domain_id.is_some_and(|id| id <= 0) || owner_id != Some(user_id) {
        return ResourceOwnershipResolution::Unresolved {
            code: "learn_ownership.progress_source_invalid",
        };
    }
    ResourceOwnershipResolution::TenantScoped {
        target_id: Some(target_id),
        tenant_id,
        domain_id,
        owner_id,
    }
}

/// Resolve one target using only the Learn-owned row and its declared tenant
/// parent. Actor tenant/domain headers are intentionally not used as target facts.
pub async fn resolve_learn_resource_ownership(
    tx: &mut Transaction<'_, MySql>,
    resource: &str,
    path: &str,
    method: &str,
    query_target_id: Option<i64>,
    actor_user_id: Option<i64>,
) -> ResourceOwnershipResolution {
    let Some(query) = learn_ownership_query(resource, path, method, actor_user_id) else {
        return ResourceOwnershipResolution::Unresolved {
            code: "learn_ownership.route_contract_unmapped",
        };
    };

    let target_id = match query {
        LearnOwnershipQuery::Subject(id)
        | LearnOwnershipQuery::Course(id)
        | LearnOwnershipQuery::Question(id)
        | LearnOwnershipQuery::Chapter(id)
        | LearnOwnershipQuery::Level(id)
        | LearnOwnershipQuery::Enrollment(id)
        | LearnOwnershipQuery::Assignment(id)
        | LearnOwnershipQuery::Submission(id)
        | LearnOwnershipQuery::Document(id) => id,
        LearnOwnershipQuery::Progress { subject_id, .. } => subject_id,
        LearnOwnershipQuery::CourseProgress { course_id, .. } => course_id,
    };
    if query_target_id.is_some_and(|query_id| query_id != target_id) {
        return ResourceOwnershipResolution::Unresolved {
            code: "learn_ownership.path_query_target_mismatch",
        };
    }

    let row = match query {
        LearnOwnershipQuery::Subject(id) => {
            sqlx::query_as::<_, (Option<i64>, Option<i64>, Option<i64>)>(SUBJECT_OWNERSHIP_SQL)
                .bind(id)
                .fetch_optional(&mut **tx)
                .await
        }
        LearnOwnershipQuery::Course(id) => {
            sqlx::query_as::<_, (Option<i64>, Option<i64>, Option<i64>)>(COURSE_OWNERSHIP_SQL)
                .bind(id)
                .fetch_optional(&mut **tx)
                .await
        }
        LearnOwnershipQuery::Question(id) => {
            sqlx::query_as::<_, (Option<i64>, Option<i64>, Option<i64>)>(QUESTION_OWNERSHIP_SQL)
                .bind(id)
                .fetch_optional(&mut **tx)
                .await
        }
        LearnOwnershipQuery::Chapter(id) => {
            sqlx::query_as::<_, (Option<i64>, Option<i64>, Option<i64>)>(CHAPTER_OWNERSHIP_SQL)
                .bind(id)
                .fetch_optional(&mut **tx)
                .await
        }
        LearnOwnershipQuery::Level(id) => {
            sqlx::query_as::<_, (Option<i64>, Option<i64>, Option<i64>)>(LEVEL_OWNERSHIP_SQL)
                .bind(id)
                .fetch_optional(&mut **tx)
                .await
        }
        LearnOwnershipQuery::Enrollment(id) => {
            sqlx::query_as::<_, (Option<i64>, Option<i64>, Option<i64>)>(ENROLLMENT_OWNERSHIP_SQL)
                .bind(id)
                .fetch_optional(&mut **tx)
                .await
        }
        LearnOwnershipQuery::Assignment(id) => {
            sqlx::query_as::<_, (Option<i64>, Option<i64>, Option<i64>)>(ASSIGNMENT_OWNERSHIP_SQL)
                .bind(id)
                .fetch_optional(&mut **tx)
                .await
        }
        LearnOwnershipQuery::Submission(id) => {
            sqlx::query_as::<_, (Option<i64>, Option<i64>, Option<i64>)>(SUBMISSION_OWNERSHIP_SQL)
                .bind(id)
                .fetch_optional(&mut **tx)
                .await
        }
        LearnOwnershipQuery::Document(id) => {
            sqlx::query_as::<_, (Option<i64>, Option<i64>, Option<i64>)>(DOCUMENT_OWNERSHIP_SQL)
                .bind(id)
                .fetch_optional(&mut **tx)
                .await
        }
        LearnOwnershipQuery::Progress {
            subject_id,
            user_id,
        } => {
            sqlx::query_as::<_, (Option<i64>, Option<i64>, Option<i64>)>(PROGRESS_OWNERSHIP_SQL)
                .bind(user_id)
                .bind(subject_id)
                .fetch_optional(&mut **tx)
                .await
        }
        LearnOwnershipQuery::CourseProgress { course_id, user_id } => {
            sqlx::query_as::<_, (Option<i64>, Option<i64>, Option<i64>)>(
                COURSE_PROGRESS_OWNERSHIP_SQL,
            )
            .bind(course_id)
            .bind(user_id)
            .fetch_optional(&mut **tx)
            .await
        }
    };

    let row = match row {
        Ok(Some(row)) => row,
        Ok(None) => {
            return ResourceOwnershipResolution::Unresolved {
                code: "learn_ownership.target_or_tenant_relation_missing",
            };
        }
        Err(_) => {
            return ResourceOwnershipResolution::Unavailable {
                code: "learn_ownership.source_lookup_unavailable",
            };
        }
    };
    let (Some(tenant_id), domain_id, owner_id) = row else {
        return ResourceOwnershipResolution::Unresolved {
            code: "learn_ownership.tenant_missing",
        };
    };
    if tenant_id <= 0 || domain_id.is_some_and(|id| id <= 0) || owner_id.is_some_and(|id| id <= 0) {
        return ResourceOwnershipResolution::Unresolved {
            code: "learn_ownership.invalid_source_facts",
        };
    }

    ResourceOwnershipResolution::TenantScoped {
        target_id: Some(target_id),
        tenant_id,
        domain_id,
        owner_id,
    }
}

fn learn_ownership_query(
    resource: &str,
    path: &str,
    method: &str,
    actor_user_id: Option<i64>,
) -> Option<LearnOwnershipQuery> {
    let segments: Vec<&str> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    match (resource, segments.as_slice()) {
        ("learn_subject", ["subjects", id]) if item_method(method) => {
            Some(LearnOwnershipQuery::Subject(positive_id(id)?))
        }
        ("learn_question", ["questions", id]) if item_method(method) => {
            Some(LearnOwnershipQuery::Question(positive_id(id)?))
        }
        ("learn_chapter", ["chapters", id]) if item_method(method) => {
            Some(LearnOwnershipQuery::Chapter(positive_id(id)?))
        }
        ("learn_chapter", ["courses", subject_id, "chapters"]) if method == "GET" => {
            Some(LearnOwnershipQuery::Subject(positive_id(subject_id)?))
        }
        ("learn_chapter", ["chapters", "stats", _subject_id]) => None,
        ("learn_level", ["levels", id]) if item_method(method) => {
            Some(LearnOwnershipQuery::Level(positive_id(id)?))
        }
        ("learn_course", ["courses", id]) if item_method(method) => {
            Some(LearnOwnershipQuery::Course(positive_id(id)?))
        }
        ("learn_course", ["courses", id, action])
            if method == "POST"
                && matches!(*action, "publish" | "archive" | "review" | "approve") =>
        {
            Some(LearnOwnershipQuery::Course(positive_id(id)?))
        }
        ("learn_course", ["courses", id, "stats"]) if method == "GET" => {
            Some(LearnOwnershipQuery::Course(positive_id(id)?))
        }
        ("learn_course", ["courses", id, "students", user_id, "progress"]) if method == "GET" => {
            let user_id = positive_id(user_id)?;
            if actor_user_id != Some(user_id) {
                return None;
            }
            Some(LearnOwnershipQuery::CourseProgress {
                course_id: positive_id(id)?,
                user_id,
            })
        }
        ("learn_course", ["enrollments", id]) if method == "DELETE" => {
            Some(LearnOwnershipQuery::Enrollment(positive_id(id)?))
        }
        ("learn_course", ["assignments", id]) if item_method(method) => {
            Some(LearnOwnershipQuery::Assignment(positive_id(id)?))
        }
        ("learn_course", ["assignments", id, action])
            if matches!(*action, "submissions" | "submit")
                && ((method == "GET" && *action == "submissions")
                    || (method == "POST" && *action == "submit")) =>
        {
            Some(LearnOwnershipQuery::Assignment(positive_id(id)?))
        }
        ("learn_course", ["assignments", id, "grade", _user_id]) if method == "POST" => {
            Some(LearnOwnershipQuery::Assignment(positive_id(id)?))
        }
        ("learn_statistics", ["assignments", "stats", course_id]) if method == "GET" => {
            Some(LearnOwnershipQuery::Course(positive_id(course_id)?))
        }
        ("learn_course", ["submissions", id]) if item_method(method) => {
            Some(LearnOwnershipQuery::Submission(positive_id(id)?))
        }
        ("learn_course", ["submissions", id, "grade"]) if method == "POST" => {
            Some(LearnOwnershipQuery::Submission(positive_id(id)?))
        }
        ("learn_document", ["documents", id]) if method == "DELETE" => {
            Some(LearnOwnershipQuery::Document(positive_id(id)?))
        }
        ("learn_progress", ["progress", user_id, subject_id]) if method == "GET" => {
            let user_id = positive_id(user_id)?;
            if actor_user_id != Some(user_id) {
                return None;
            }
            Some(LearnOwnershipQuery::Progress {
                subject_id: positive_id(subject_id)?,
                user_id,
            })
        }
        // Collection/body-addressed and legacy-owned tables intentionally have
        // no single row-level tenant proof here. They remain unresolved.
        _ => None,
    }
}

fn item_method(method: &str) -> bool {
    matches!(method, "GET" | "PUT" | "PATCH" | "DELETE")
}

fn positive_id(value: &str) -> Option<i64> {
    value.parse::<i64>().ok().filter(|id| *id > 0)
}

const SUBJECT_OWNERSHIP_SQL: &str =
    "SELECT tenant_id, domain_id, created_by_user_id FROM learn_subject WHERE subject_id = ? AND tenant_id IS NOT NULL FOR SHARE";
const COURSE_OWNERSHIP_SQL: &str = "SELECT c.tenant_id, s.domain_id, c.instructor_user_id \
     FROM learn_course c JOIN learn_subject s ON s.subject_id = c.subject_id \
       AND s.tenant_id = c.tenant_id \
     WHERE c.course_id = ? AND c.tenant_id IS NOT NULL FOR SHARE";
const QUESTION_OWNERSHIP_SQL: &str =
    "SELECT q.tenant_id, COALESCE(q.domain_id, s.domain_id), q.created_by_user_id \
     FROM learn_question q JOIN learn_subject s ON s.subject_id = q.subject_id \
     WHERE q.question_id = ? AND q.tenant_id IS NOT NULL \
       AND s.tenant_id = q.tenant_id \
       AND (q.domain_id IS NULL OR q.domain_id = s.domain_id) FOR SHARE";
const CHAPTER_OWNERSHIP_SQL: &str =
    "SELECT ch.tenant_id, COALESCE(ch.domain_id, s.domain_id), ch.created_by_user_id \
     FROM learn_chapter ch JOIN learn_subject s ON s.subject_id = ch.subject_id \
     WHERE ch.chapter_id = ? AND ch.tenant_id IS NOT NULL \
       AND s.tenant_id = ch.tenant_id \
       AND (ch.domain_id IS NULL OR ch.domain_id = s.domain_id) FOR SHARE";
const LEVEL_OWNERSHIP_SQL: &str =
    "SELECT l.tenant_id, COALESCE(l.domain_id, s.domain_id), l.created_by_user_id \
     FROM learn_level l JOIN learn_subject s ON s.subject_id = l.subject_id \
     WHERE l.level_id = ? AND l.tenant_id IS NOT NULL \
       AND s.tenant_id = l.tenant_id \
       AND (l.domain_id IS NULL OR l.domain_id = s.domain_id) FOR SHARE";
const ENROLLMENT_OWNERSHIP_SQL: &str = "SELECT c.tenant_id, s.domain_id, e.user_id \
     FROM learn_course_enrollment e JOIN learn_course c ON c.course_id = e.course_id \
     JOIN learn_subject s ON s.subject_id = c.subject_id AND s.tenant_id = c.tenant_id \
     WHERE e.id = ? AND c.tenant_id IS NOT NULL FOR SHARE";
const ASSIGNMENT_OWNERSHIP_SQL: &str = "SELECT c.tenant_id, s.domain_id, c.instructor_user_id \
     FROM learn_assignment a JOIN learn_course c ON c.course_id = a.course_id \
     JOIN learn_subject s ON s.subject_id = c.subject_id AND s.tenant_id = c.tenant_id \
     WHERE a.id = ? AND c.tenant_id IS NOT NULL FOR SHARE";
const SUBMISSION_OWNERSHIP_SQL: &str = "SELECT c.tenant_id, s.domain_id, sub.user_id \
     FROM learn_submission sub JOIN learn_assignment a ON a.id = sub.assignment_id \
     JOIN learn_course c ON c.course_id = a.course_id \
     JOIN learn_subject s ON s.subject_id = c.subject_id AND s.tenant_id = c.tenant_id \
     WHERE sub.id = ? AND c.tenant_id IS NOT NULL FOR SHARE";
const DOCUMENT_OWNERSHIP_SQL: &str = "SELECT s.tenant_id, s.domain_id, d.created_by \
     FROM documents d JOIN learn_subject s ON s.subject_id = d.subject_id \
     WHERE d.id = ? AND s.tenant_id IS NOT NULL FOR SHARE";
const PROGRESS_OWNERSHIP_SQL: &str =
    "SELECT s.tenant_id, COALESCE(q.domain_id, s.domain_id), a.user_id \
     FROM learn_question_first_attempt a \
     JOIN learn_question q ON q.question_id = a.question_id \
     JOIN learn_subject s ON s.subject_id = q.subject_id \
     WHERE a.user_id = ? AND q.subject_id = ? AND s.tenant_id IS NOT NULL \
       AND a.subject_id = q.subject_id \
       AND (q.domain_id IS NULL OR q.domain_id = s.domain_id) FOR SHARE";
const COURSE_PROGRESS_OWNERSHIP_SQL: &str = "SELECT c.tenant_id, s.domain_id, e.user_id \
     FROM learn_course_enrollment e JOIN learn_course c ON c.course_id = e.course_id \
     JOIN learn_subject s ON s.subject_id = c.subject_id AND s.tenant_id = c.tenant_id \
     WHERE e.course_id = ? AND e.user_id = ? AND e.status = 'ACTIVE' \
       AND c.tenant_id IS NOT NULL FOR SHARE";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_declared_single_row_routes_get_ownership_queries() {
        assert_eq!(
            learn_ownership_query("learn_subject", "/subjects/12", "GET", Some(7)),
            Some(LearnOwnershipQuery::Subject(12))
        );
        assert_eq!(
            learn_ownership_query("learn_course", "/courses/9/publish", "POST", Some(9)),
            Some(LearnOwnershipQuery::Course(9))
        );
        assert_eq!(
            learn_ownership_query("learn_progress", "/progress/7/12", "GET", Some(7)),
            Some(LearnOwnershipQuery::Progress {
                subject_id: 12,
                user_id: 7
            })
        );
        assert_eq!(
            learn_ownership_query("learn_progress", "/progress/8/12", "GET", None),
            None,
            "App and platform actors cannot address another user's progress"
        );
        assert_eq!(
            learn_ownership_query("learn_subject", "/subjects", "GET", None),
            None,
            "unfiltered collections have no single tenant proof"
        );
        assert_eq!(
            learn_ownership_query("learn_course", "/courses/9/chapters", "GET", None),
            None,
            "legacy course/subject path ambiguity stays unresolved"
        );
        assert_eq!(
            learn_ownership_query("learn_question", "/solutions/7/like", "POST", None),
            None,
            "a solution ID must not be interpreted as a question ID"
        );
    }

    #[test]
    fn ids_must_be_positive_and_query_targets_cannot_replace_path_contracts() {
        assert_eq!(positive_id("7"), Some(7));
        assert_eq!(positive_id("0"), None);
        assert_eq!(positive_id("-1"), None);
        assert_eq!(positive_id("nope"), None);
        assert_eq!(
            learn_ownership_query("learn_subject", "/subjects/7", "GET", None),
            Some(LearnOwnershipQuery::Subject(7))
        );
    }

    #[test]
    fn ownership_sql_requires_parent_tenant_equality_where_relations_exist() {
        for sql in [
            COURSE_OWNERSHIP_SQL,
            QUESTION_OWNERSHIP_SQL,
            CHAPTER_OWNERSHIP_SQL,
            LEVEL_OWNERSHIP_SQL,
            ENROLLMENT_OWNERSHIP_SQL,
            ASSIGNMENT_OWNERSHIP_SQL,
            SUBMISSION_OWNERSHIP_SQL,
        ] {
            assert!(sql.contains("tenant_id"));
            assert!(sql.contains("s.tenant_id ="));
        }
        assert!(PROGRESS_OWNERSHIP_SQL.contains("learn_question_first_attempt"));
        assert!(PROGRESS_OWNERSHIP_SQL.contains("a.user_id = ?"));
        assert!(!PROGRESS_OWNERSHIP_SQL.contains("subject_progress"));
        assert!(DOCUMENT_OWNERSHIP_SQL.contains("s.tenant_id IS NOT NULL"));
    }
}
