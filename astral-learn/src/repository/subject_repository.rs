//! 学科数据访问 — SubjectRepository
//!
//! 对齐 Java `SubjectMapper` 边界（learn_subject 表）。
//! 学科级联删除（9 步 DELETE，对齐 Java SubjectDeleteConsumer）收敛为
//! 单事务聚合方法 `cascade_delete_subject`；软删（DISABLED）与硬删分离，
//! MQ 发布由 service 编排。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::AstralError;

/// 学科行（learn_subject，platform_v4 列名 subject_id/parent_subject_id）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SubjectRecord {
    pub id: i64,
    pub name: String,
    pub code: String,
    pub parent_id: Option<i64>,
    pub description: Option<String>,
    pub sort_order: i32,
    pub status: String,
}

/// 新建/更新学科参数
#[derive(Debug, Clone)]
pub struct SubjectInput {
    pub name: String,
    pub code: String,
    pub parent_id: Option<i64>,
    pub description: Option<String>,
    pub sort_order: i32,
}

#[async_trait]
pub trait SubjectRepository: Send + Sync {
    /// 全量总数（分页）
    async fn count_all(&self) -> Result<i64, AstralError>;
    /// 分页列表（sort_order）
    async fn list_all(&self, limit: i64, offset: i64) -> Result<Vec<SubjectRecord>, AstralError>;
    /// 活跃学科（不分页，前端下拉）
    async fn list_active(&self) -> Result<Vec<SubjectRecord>, AstralError>;
    /// 单条
    async fn get(&self, id: i64) -> Result<Option<SubjectRecord>, AstralError>;
    /// 新建，返回新 id
    async fn create(&self, input: &SubjectInput) -> Result<i64, AstralError>;
    /// 更新
    async fn update(&self, id: i64, input: &SubjectInput) -> Result<(), AstralError>;
    /// 事务内写入软删除状态和 durable cascade intent；提交后可异步完成级联
    async fn request_cascade_delete(
        &self,
        subject_id: i64,
        operator_id: i64,
        origin_region: &str,
    ) -> Result<(), AstralError>;
    /// 软删除单个状态（仅供受保护的非 cascade 使用）
    async fn soft_delete(&self, id: i64) -> Result<(), AstralError>;
    /// 状态查询（MQ Consumer 幂等检查；不存在 → None）
    async fn get_status(&self, id: i64) -> Result<Option<String>, AstralError>;
    /// 硬删除（MQ 级联最后一步，无事务版）
    async fn hard_delete(&self, id: i64) -> Result<(), AstralError>;
    /// 级联删除学科及所有关联数据（单事务，9 步；对齐 Java SubjectDeleteConsumer）
    async fn cascade_delete_subject(&self, subject_id: i64) -> Result<(), AstralError>;
}

pub struct SqlxSubjectRepository {
    db: MySqlPool,
}

impl SqlxSubjectRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

const SUBJECT_SELECT: &str =
    "SELECT subject_id as id, name, code, parent_subject_id as parent_id, description, \
     COALESCE(sort_order,0) as sort_order, status FROM learn_subject";
const LOCK_SUBJECT_DELETE_SOURCE_SQL: &str = "SELECT subject_id, status, tenant_id, domain_id \
     FROM learn_subject WHERE subject_id = ? FOR UPDATE";
const FIND_SUBJECT_DELETE_SQL: &str =
    "SELECT message_id, operation_id, message_type, payload_json, payload_sha256, status, \
            tenant_id, origin_region, target_region, schema_version, ordering_key, headers_json \
     FROM al_message_outbox \
     WHERE queue_name = ? \
       AND JSON_UNQUOTE(JSON_EXTRACT(payload_json, '$.payload.subjectId')) = ? \
     ORDER BY created_at, message_id LIMIT 2 FOR UPDATE";
const READ_SUBJECT_DELETE_ANCHOR_SQL: &str =
    "SELECT message_id, operation_id, message_type, payload_json, payload_sha256, status, \
            tenant_id, origin_region, target_region, schema_version, ordering_key, headers_json \
     FROM al_message_outbox \
     WHERE queue_name = ? \
       AND JSON_UNQUOTE(JSON_EXTRACT(payload_json, '$.payload.subjectId')) = ? \
     ORDER BY created_at, message_id LIMIT 2";
const TABLE_EXISTS_SQL: &str = "SELECT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.TABLES \
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?)";
const LOCK_SUBJECT_COURSES_SQL: &str = "SELECT course_id, tenant_id FROM learn_course \
     WHERE subject_id = ? ORDER BY course_id LIMIT 10001 FOR UPDATE";

/// These historical tables use the retired `course.id` namespace. Without a
/// committed crosswalk, any rows in them are ambiguous and must keep cascade
/// settlement fail-closed rather than being deleted by coincident numeric IDs.
const UNMAPPED_LEGACY_DEPENDENTS: &[(&str, &str)] = &[
    (
        "announcement",
        "SELECT EXISTS (SELECT 1 FROM announcement LIMIT 1)",
    ),
    (
        "discussion_post",
        "SELECT EXISTS (SELECT 1 FROM discussion_post LIMIT 1)",
    ),
    ("class", "SELECT EXISTS (SELECT 1 FROM class LIMIT 1)"),
    (
        "course_workflow",
        "SELECT EXISTS (SELECT 1 FROM course_workflow LIMIT 1)",
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SubjectDeleteScope {
    tenant_id: i64,
    domain_id: Option<i64>,
}

#[derive(Debug, sqlx::FromRow)]
struct SubjectDeleteIntentRow {
    message_id: String,
    operation_id: String,
    message_type: String,
    payload_json: String,
    payload_sha256: String,
    status: String,
    tenant_id: Option<i64>,
    origin_region: String,
    target_region: Option<String>,
    schema_version: i32,
    ordering_key: Option<String>,
    headers_json: Option<String>,
}

#[cfg(test)]
const SQL_CONTINUATION_TESTS: &[(&str, &str)] = &[
    ("locked source subject", LOCK_SUBJECT_DELETE_SOURCE_SQL),
    ("subject intent history", FIND_SUBJECT_DELETE_SQL),
    ("locked child courses", LOCK_SUBJECT_COURSES_SQL),
    ("optional table presence", TABLE_EXISTS_SQL),
];

#[async_trait]
impl SubjectRepository for SqlxSubjectRepository {
    async fn count_all(&self) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM learn_subject")
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_all(&self, limit: i64, offset: i64) -> Result<Vec<SubjectRecord>, AstralError> {
        sqlx::query_as::<_, SubjectRecord>(&format!(
            "{SUBJECT_SELECT} ORDER BY sort_order LIMIT ? OFFSET ?"
        ))
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn list_active(&self) -> Result<Vec<SubjectRecord>, AstralError> {
        sqlx::query_as::<_, SubjectRecord>(&format!(
            "{SUBJECT_SELECT} WHERE status = 'ACTIVE' ORDER BY sort_order"
        ))
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn get(&self, id: i64) -> Result<Option<SubjectRecord>, AstralError> {
        sqlx::query_as::<_, SubjectRecord>(&format!("{SUBJECT_SELECT} WHERE subject_id = ?"))
            .bind(id)
            .fetch_optional(&self.db)
            .await
            .map_err(db_error)
    }

    async fn create(&self, input: &SubjectInput) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO learn_subject (name, code, parent_subject_id, description, sort_order, status) \
             VALUES (?, ?, ?, ?, ?, 'ACTIVE')",
        )
        .bind(&input.name)
        .bind(&input.code)
        .bind(input.parent_id)
        .bind(&input.description)
        .bind(input.sort_order)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
    }

    async fn update(&self, id: i64, input: &SubjectInput) -> Result<(), AstralError> {
        sqlx::query(
            "UPDATE learn_subject SET name = ?, code = ?, parent_subject_id = ?, description = ?, sort_order = ? WHERE subject_id = ?",
        )
        .bind(&input.name)
        .bind(&input.code)
        .bind(input.parent_id)
        .bind(&input.description)
        .bind(input.sort_order)
        .bind(id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn request_cascade_delete(
        &self,
        subject_id: i64,
        operator_id: i64,
        origin_region: &str,
    ) -> Result<(), AstralError> {
        let source_guard = astral_db::memory_projection_hub::acquire_source_guard()?;
        let mut tx = self.db.begin().await.map_err(db_error)?;
        let subject: Option<(i64, String, Option<i64>, Option<i64>)> =
            sqlx::query_as(LOCK_SUBJECT_DELETE_SOURCE_SQL)
                .bind(subject_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_error)?;
        let Some((_, status, tenant_id, domain_id)) = subject else {
            return Err(AstralError::NotFound(format!(
                "Subject {subject_id} not found"
            )));
        };
        let requested_scope = checked_delete_scope(tenant_id, domain_id)?;

        let payload = astral_mq::producer::SubjectDeletePayload {
            subject_id,
            subject_ids: None,
            operator_id,
            cascade_delete: true,
            domain_id: requested_scope.domain_id,
            tenant_id: Some(requested_scope.tenant_id),
            subject_name: None,
        };
        let operation_id = uuid::Uuid::new_v4().to_string();
        let mut envelope = astral_mq::envelope::MessageEnvelope::new(
            operation_id.clone(),
            operation_id,
            "SUBJECT_DELETE",
            1,
            origin_region.to_owned(),
            serde_json::to_value(payload)
                .map_err(|error| AstralError::Validation(error.to_string()))?,
        )
        .map_err(AstralError::Validation)?;
        envelope.tenant_id = tenant_id;
        envelope.ordering_key = Some(format!("learn_subject:{subject_id}"));
        envelope.validate().map_err(AstralError::Validation)?;
        let payload_json = envelope.envelope_json().map_err(|error| {
            AstralError::Validation(format!("Delete intent serialization failed: {error}"))
        })?;
        let input = astral_db::LocalMessageInput {
            message_id: &envelope.message_id,
            operation_id: &envelope.operation_id,
            message_type: &envelope.message_type,
            queue_name: astral_mq::config::QUEUE_SUBJECT_DELETE,
            ordering_key: envelope.ordering_key.as_deref(),
            tenant_id: envelope.tenant_id,
            origin_region: &envelope.origin_region,
            target_region: envelope.target_region.as_deref(),
            schema_version: envelope.schema_version,
            payload_json: &payload_json,
            headers_json: None,
            payload_sha256: &envelope.payload_sha256,
        };

        if status != "DISABLED" {
            let disabled = sqlx::query(
                "UPDATE learn_subject SET status = 'DISABLED' WHERE subject_id = ? AND status = ?",
            )
            .bind(subject_id)
            .bind(&status)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
            if disabled.rows_affected() != 1 {
                return Err(AstralError::Database(
                    "Subject changed while its delete intent was being recorded".into(),
                ));
            }
            astral_db::append_in_tx(&mut tx, &input)
                .await
                .map_err(|error| {
                    AstralError::Database(format!(
                        "Failed to append subject cascade intent: {error}"
                    ))
                })?;
        } else {
            // An earlier request may have committed DISABLED before a process
            // interruption. Reuse a proven pending intent instead of silently
            // treating the source flag as durable cascade evidence.
            let prior = sqlx::query_as::<
                _,
                (
                    String,
                    String,
                    String,
                    String,
                    String,
                    String,
                    Option<i64>,
                    String,
                    Option<String>,
                    i32,
                    Option<String>,
                    Option<String>,
                ),
            >(FIND_SUBJECT_DELETE_SQL)
            .bind(astral_mq::config::QUEUE_SUBJECT_DELETE)
            .bind(subject_id.to_string())
            .fetch_all(&mut *tx)
            .await
            .map_err(db_error)?;
            if prior.len() > 1 {
                return Err(AstralError::Database(
                    "Multiple subject delete intents require reconciliation".into(),
                ));
            }
            if let Some((
                message_id,
                operation_id,
                message_type,
                payload_json,
                payload_sha256,
                row_status,
                row_tenant_id,
                origin_region,
                target_region,
                schema_version,
                ordering_key,
                headers_json,
            )) = prior.into_iter().next()
            {
                let prior_envelope: astral_mq::envelope::MessageEnvelope =
                    serde_json::from_str(&payload_json).map_err(|error| {
                        AstralError::Database(format!(
                            "Subject delete intent is malformed: {error}"
                        ))
                    })?;
                prior_envelope.validate().map_err(|error| {
                    AstralError::Database(format!("Subject delete intent is invalid: {error}"))
                })?;
                let canonical_prior_json = prior_envelope.envelope_json().map_err(|error| {
                    AstralError::Database(format!(
                        "Subject delete intent cannot be serialized: {error}"
                    ))
                })?;
                let prior_payload: astral_mq::producer::SubjectDeletePayload =
                    serde_json::from_value(prior_envelope.payload.clone()).map_err(|error| {
                        AstralError::Database(format!(
                            "Subject delete payload is malformed: {error}"
                        ))
                    })?;
                if canonical_prior_json != payload_json
                    || prior_envelope.message_id != message_id
                    || prior_envelope.operation_id != operation_id
                    || prior_envelope.message_type != message_type
                    || prior_envelope.message_type != "SUBJECT_DELETE"
                    || prior_envelope.tenant_id != row_tenant_id
                    || row_tenant_id != tenant_id
                    || prior_envelope.origin_region != origin_region
                    || prior_envelope.target_region != target_region
                    || prior_envelope.schema_version != schema_version
                    || prior_envelope.ordering_key != ordering_key
                    || prior_envelope.payload_sha256 != payload_sha256
                    || headers_json.is_some()
                    || prior_payload.subject_id != subject_id
                    || prior_payload.tenant_id != Some(requested_scope.tenant_id)
                    || prior_payload.domain_id != requested_scope.domain_id
                    || !prior_payload.cascade_delete
                {
                    return Err(AstralError::Database(
                        "Subject delete intent does not match the locked source row".into(),
                    ));
                }
                match row_status.as_str() {
                    "PENDING" | "PROCESSING" | "IN_DOUBT" => {
                        if let Some(guard) = source_guard.as_ref() {
                            guard.mark_commit_started();
                        }
                        let commit_result = tx.commit().await;
                        match &commit_result {
                            Ok(()) => {
                                if let Some(guard) = source_guard.as_ref() {
                                    guard.mark_commit_proven();
                                }
                            }
                            Err(_) => {
                                if let Some(guard) = source_guard.as_ref() {
                                    guard.mark_uncertain();
                                }
                            }
                        }
                        commit_result.map_err(|error| {
                            AstralError::Database(format!(
                                "subject_delete_intent_commit_outcome_unknown: {error}"
                            ))
                        })?;
                        return Ok(());
                    }
                    "PROCESSED" | "QUARANTINED" => {
                        return Err(AstralError::Database(format!(
                            "Subject delete intent is terminal ({row_status}) while source remains DISABLED; reconcile before retry"
                        )));
                    }
                    _ => {
                        return Err(AstralError::Database(format!(
                            "Unknown subject delete intent state {row_status}; reconcile before retry"
                        )));
                    }
                }
            }
            astral_db::append_in_tx(&mut tx, &input)
                .await
                .map_err(|error| {
                    AstralError::Database(format!(
                        "Failed to append subject cascade intent: {error}"
                    ))
                })?;
        }
        if let Some(guard) = source_guard.as_ref() {
            guard.mark_commit_started();
        }
        let commit_result = tx.commit().await;
        match &commit_result {
            Ok(()) => {
                if let Some(guard) = source_guard.as_ref() {
                    guard.mark_commit_proven();
                }
            }
            Err(_) => {
                if let Some(guard) = source_guard.as_ref() {
                    guard.mark_uncertain();
                }
            }
        }
        commit_result.map_err(|error| {
            AstralError::Database(format!(
                "subject_delete_intent_commit_outcome_unknown: {error}"
            ))
        })?;
        Ok(())
    }

    async fn soft_delete(&self, id: i64) -> Result<(), AstralError> {
        sqlx::query("UPDATE learn_subject SET status = 'DISABLED' WHERE subject_id = ?")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn get_status(&self, id: i64) -> Result<Option<String>, AstralError> {
        sqlx::query_scalar::<_, String>("SELECT status FROM learn_subject WHERE subject_id = ?")
            .bind(id)
            .fetch_optional(&self.db)
            .await
            .map_err(db_error)
    }

    async fn hard_delete(&self, id: i64) -> Result<(), AstralError> {
        sqlx::query("DELETE FROM learn_subject WHERE subject_id = ?")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn cascade_delete_subject(&self, subject_id: i64) -> Result<(), AstralError> {
        tracing::info!(subject_id, "cascade delete started");
        let source_guard = astral_db::memory_projection_hub::acquire_source_guard()?;
        let mut tx = self.db.begin().await.map_err(db_error)?;
        let anchor = load_delete_anchor_scope(&mut tx, subject_id).await?;
        let subject: Option<(i64, String, Option<i64>, Option<i64>)> =
            sqlx::query_as(LOCK_SUBJECT_DELETE_SOURCE_SQL)
                .bind(subject_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_error)?;
        if let Some((_, status, tenant_id, domain_id)) = subject {
            if status != "DISABLED" || checked_delete_scope(tenant_id, domain_id)? != anchor {
                return Err(AstralError::Permission(
                    "Subject changed; cascade intent requires reconciliation".into(),
                ));
            }
        }
        validate_cascade_dependents(&mut tx, subject_id, anchor).await?;

        // Only mapped authoritative dependents are deleted after locked scope validation.
        delete_optional_for_subject(
            &mut tx,
            "learn_level_status",
            "DELETE FROM learn_level_status WHERE level_id IN \
             (SELECT level_id FROM learn_level WHERE subject_id = ?)",
            subject_id,
        )
        .await?;
        delete_optional_for_subject(
            &mut tx,
            "learn_level_completion",
            "DELETE FROM learn_level_completion WHERE level_id IN \
             (SELECT level_id FROM learn_level WHERE subject_id = ?)",
            subject_id,
        )
        .await?;
        delete_for_subject(
            &mut tx,
            "DELETE FROM learn_lesson WHERE chapter_id IN \
             (SELECT chapter_id FROM learn_chapter WHERE subject_id = ?)",
            subject_id,
        )
        .await?;
        delete_optional_for_subject(
            &mut tx,
            "chapter_progress",
            "DELETE FROM chapter_progress WHERE chapter_id IN \
             (SELECT chapter_id FROM learn_chapter WHERE subject_id = ?)",
            subject_id,
        )
        .await?;
        delete_for_subject(
            &mut tx,
            "DELETE FROM learn_chapter WHERE subject_id = ?",
            subject_id,
        )
        .await?;
        delete_optional_for_subject(
            &mut tx,
            "learn_level_question",
            "DELETE FROM learn_level_question WHERE level_id IN \
             (SELECT level_id FROM learn_level WHERE subject_id = ?)",
            subject_id,
        )
        .await?;
        delete_optional_for_subject(
            &mut tx,
            "learn_level_questions",
            "DELETE FROM learn_level_questions WHERE level_id IN \
             (SELECT level_id FROM learn_level WHERE subject_id = ?)",
            subject_id,
        )
        .await?;
        delete_for_subject(
            &mut tx,
            "DELETE FROM learn_level WHERE subject_id = ?",
            subject_id,
        )
        .await?;
        delete_optional_for_subject(
            &mut tx,
            "learn_solution_like",
            "DELETE FROM learn_solution_like WHERE solution_id IN \
             (SELECT id FROM learn_question_solution WHERE question_id IN \
              (SELECT question_id FROM learn_question WHERE subject_id = ?))",
            subject_id,
        )
        .await?;
        delete_for_subject(
            &mut tx,
            "DELETE FROM learn_question_solution WHERE question_id IN \
             (SELECT question_id FROM learn_question WHERE subject_id = ?)",
            subject_id,
        )
        .await?;
        delete_for_subject(
            &mut tx,
            "DELETE FROM learn_question_first_attempt WHERE subject_id = ?",
            subject_id,
        )
        .await?;
        delete_optional_for_subject(
            &mut tx,
            "learn_question_summary",
            "DELETE FROM learn_question_summary WHERE subject_id = ?",
            subject_id,
        )
        .await?;
        delete_optional_for_subject(
            &mut tx,
            "subject_progress",
            "DELETE FROM subject_progress WHERE subject_id = ?",
            subject_id,
        )
        .await?;
        delete_optional_for_subject(
            &mut tx,
            "learn_user_answer",
            "DELETE FROM learn_user_answer WHERE question_id IN \
             (SELECT question_id FROM learn_question WHERE subject_id = ?)",
            subject_id,
        )
        .await?;
        delete_optional_for_subject(
            &mut tx,
            "user_answer",
            "DELETE FROM user_answer WHERE question_id IN \
             (SELECT question_id FROM learn_question WHERE subject_id = ?)",
            subject_id,
        )
        .await?;
        delete_optional_for_subject(
            &mut tx,
            "wrong_question",
            "DELETE FROM wrong_question WHERE subject_id = ?",
            subject_id,
        )
        .await?;
        delete_optional_for_subject(
            &mut tx,
            "learn_wrong_question",
            "DELETE FROM learn_wrong_question WHERE subject_id = ?",
            subject_id,
        )
        .await?;
        delete_for_subject(
            &mut tx,
            "DELETE FROM learn_question WHERE subject_id = ?",
            subject_id,
        )
        .await?;
        delete_optional_for_subject(
            &mut tx,
            "chapter_progress",
            "DELETE FROM chapter_progress WHERE chapter_id IN \
             (SELECT chapter_id FROM learn_chapter WHERE subject_id = ?)",
            subject_id,
        )
        .await?;
        delete_for_subject(
            &mut tx,
            "DELETE FROM learn_chapter WHERE subject_id = ?",
            subject_id,
        )
        .await?;
        delete_optional_for_subject(
            &mut tx,
            "subject_progress",
            "DELETE FROM subject_progress WHERE subject_id = ?",
            subject_id,
        )
        .await?;
        delete_for_subject(
            &mut tx,
            "DELETE FROM learn_submission WHERE assignment_id IN \
             (SELECT id FROM learn_assignment WHERE course_id IN \
              (SELECT course_id FROM learn_course WHERE subject_id = ?))",
            subject_id,
        )
        .await?;
        delete_for_subject(
            &mut tx,
            "DELETE FROM learn_assignment WHERE course_id IN \
             (SELECT course_id FROM learn_course WHERE subject_id = ?)",
            subject_id,
        )
        .await?;
        delete_for_subject(
            &mut tx,
            "DELETE FROM learn_course_enrollment WHERE course_id IN \
             (SELECT course_id FROM learn_course WHERE subject_id = ?)",
            subject_id,
        )
        .await?;
        delete_optional_for_subject(
            &mut tx,
            "learn_announcement",
            "DELETE FROM learn_announcement WHERE course_id IN \
             (SELECT course_id FROM learn_course WHERE subject_id = ?)",
            subject_id,
        )
        .await?;
        delete_optional_for_subject(
            &mut tx,
            "learn_discussion_post",
            "DELETE FROM learn_discussion_post WHERE course_id IN \
             (SELECT course_id FROM learn_course WHERE subject_id = ?)",
            subject_id,
        )
        .await?;
        delete_optional_for_subject(
            &mut tx,
            "learn_class_attendance",
            "DELETE FROM learn_class_attendance WHERE course_id IN \
             (SELECT course_id FROM learn_course WHERE subject_id = ?)",
            subject_id,
        )
        .await?;
        delete_for_subject(
            &mut tx,
            "DELETE FROM learn_course WHERE subject_id = ?",
            subject_id,
        )
        .await?;
        delete_optional_for_subject(
            &mut tx,
            "learn_user_subject",
            "DELETE FROM learn_user_subject WHERE subject_id = ?",
            subject_id,
        )
        .await?;
        delete_for_subject(
            &mut tx,
            "DELETE FROM documents WHERE subject_id = ?",
            subject_id,
        )
        .await?;
        delete_for_subject(
            &mut tx,
            "DELETE FROM learn_subject WHERE subject_id = ?",
            subject_id,
        )
        .await?;
        if let Some(guard) = source_guard.as_ref() {
            guard.mark_commit_started();
        }
        let commit_result = tx.commit().await;
        match &commit_result {
            Ok(()) => {
                if let Some(guard) = source_guard.as_ref() {
                    guard.mark_commit_proven();
                }
            }
            Err(_) => {
                if let Some(guard) = source_guard.as_ref() {
                    guard.mark_uncertain();
                }
            }
        }
        commit_result.map_err(|error| {
            AstralError::Database(format!("subject_cascade_commit_outcome_unknown: {error}"))
        })?;
        drop(source_guard);
        tracing::info!(subject_id, "cascade delete completed");
        Ok(())
    }
}

fn checked_delete_scope(
    tenant_id: Option<i64>,
    domain_id: Option<i64>,
) -> Result<SubjectDeleteScope, AstralError> {
    let Some(tenant_id) = tenant_id.filter(|id| *id > 0) else {
        return Err(AstralError::Permission(
            "subject deletion tenant proof is missing".into(),
        ));
    };
    if domain_id.is_some_and(|id| id <= 0) {
        return Err(AstralError::Permission(
            "subject deletion domain proof is invalid".into(),
        ));
    }
    Ok(SubjectDeleteScope {
        tenant_id,
        domain_id,
    })
}

async fn load_delete_anchor_scope(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    subject_id: i64,
) -> Result<SubjectDeleteScope, AstralError> {
    let rows = sqlx::query_as::<_, SubjectDeleteIntentRow>(READ_SUBJECT_DELETE_ANCHOR_SQL)
        .bind(astral_mq::config::QUEUE_SUBJECT_DELETE)
        .bind(subject_id.to_string())
        .fetch_all(&mut **tx)
        .await
        .map_err(db_error)?;
    if rows.len() != 1 {
        return Err(AstralError::Permission(
            "exact committed subject deletion intent required".into(),
        ));
    }
    let row = rows.into_iter().next().unwrap();
    let envelope: astral_mq::envelope::MessageEnvelope = serde_json::from_str(&row.payload_json)
        .map_err(|_| AstralError::Permission("invalid subject deletion envelope".into()))?;
    envelope.validate().map_err(AstralError::Validation)?;
    let payload: astral_mq::producer::SubjectDeletePayload =
        serde_json::from_value(envelope.payload.clone())
            .map_err(|_| AstralError::Permission("invalid subject deletion payload".into()))?;
    if row.status != "PROCESSING"
        || row.message_type != "SUBJECT_DELETE"
        || envelope.message_id != row.message_id
        || envelope.operation_id != row.operation_id
        || envelope.message_type != row.message_type
        || envelope.tenant_id != row.tenant_id
        || envelope.origin_region != row.origin_region
        || envelope.target_region != row.target_region
        || envelope.schema_version != row.schema_version
        || envelope.ordering_key != row.ordering_key
        || envelope.payload_sha256 != row.payload_sha256
        || envelope.envelope_json().map_err(AstralError::Validation)? != row.payload_json
        || row.headers_json.is_some()
        || payload.subject_id != subject_id
        || payload.subject_ids.is_some()
        || payload.operator_id <= 0
        || !payload.cascade_delete
        || payload.tenant_id != row.tenant_id
    {
        return Err(AstralError::Permission(
            "subject deletion intent requires reconciliation".into(),
        ));
    }
    checked_delete_scope(payload.tenant_id, payload.domain_id)
}

async fn validate_cascade_dependents(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    subject_id: i64,
    scope: SubjectDeleteScope,
) -> Result<(), AstralError> {
    let courses: Vec<(i64, Option<i64>)> = sqlx::query_as(LOCK_SUBJECT_COURSES_SQL)
        .bind(subject_id)
        .fetch_all(&mut **tx)
        .await
        .map_err(db_error)?;
    if courses.len() > 10_000
        || courses
            .iter()
            .any(|(_, tenant)| *tenant != Some(scope.tenant_id))
    {
        return Err(AstralError::Permission(
            "subject course tenant proof requires reconciliation".into(),
        ));
    }
    for sql in [
        "SELECT tenant_id, domain_id FROM learn_chapter WHERE subject_id = ? LIMIT 10001 FOR UPDATE",
        "SELECT tenant_id, domain_id FROM learn_question WHERE subject_id = ? LIMIT 10001 FOR UPDATE",
        "SELECT tenant_id, domain_id FROM learn_level WHERE subject_id = ? LIMIT 10001 FOR UPDATE",
    ] {
        let rows: Vec<(Option<i64>, Option<i64>)> = sqlx::query_as(sql)
            .bind(subject_id)
            .fetch_all(&mut **tx)
            .await
            .map_err(db_error)?;
        if rows.len() > 10_000 || rows.iter().any(|(tenant, domain)| {
            *tenant != Some(scope.tenant_id) || domain.is_some() && *domain != scope.domain_id
        }) {
            return Err(AstralError::Permission("subject dependent scope requires reconciliation".into()));
        }
    }
    for (table, query) in UNMAPPED_LEGACY_DEPENDENTS {
        let exists: bool = sqlx::query_scalar(TABLE_EXISTS_SQL)
            .bind(table)
            .fetch_one(&mut **tx)
            .await
            .map_err(db_error)?;
        if exists {
            let populated: bool = sqlx::query_scalar(query)
                .fetch_one(&mut **tx)
                .await
                .map_err(db_error)?;
            if populated {
                return Err(AstralError::Permission(format!(
                    "legacy {table} lacks a course crosswalk; reconcile before cascade"
                )));
            }
        }
    }
    Ok(())
}

async fn delete_for_subject(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    statement: &str,
    subject_id: i64,
) -> Result<(), AstralError> {
    sqlx::query(statement)
        .bind(subject_id)
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
    Ok(())
}

async fn delete_optional_for_subject(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    table_name: &'static str,
    statement: &str,
    subject_id: i64,
) -> Result<(), AstralError> {
    let exists: bool = sqlx::query_scalar(TABLE_EXISTS_SQL)
        .bind(table_name)
        .fetch_one(&mut **tx)
        .await
        .map_err(db_error)?;
    if exists {
        delete_for_subject(tx, statement, subject_id).await?;
    }
    Ok(())
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Subject repository query failed: {error}"))
}

#[cfg(test)]
mod tests {
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
        assert!(LOCK_SUBJECT_DELETE_SOURCE_SQL.contains("FOR UPDATE"));
        assert!(FIND_SUBJECT_DELETE_SQL.contains("FOR UPDATE"));
        assert!(TABLE_EXISTS_SQL.contains("INFORMATION_SCHEMA.TABLES"));
    }

    #[test]
    fn cascade_source_covers_chapter_and_progress_cleanup_before_subject() {
        let source = include_str!("subject_repository.rs")
            .split("impl SubjectRepository for SqlxSubjectRepository {")
            .nth(1)
            .unwrap()
            .split("async fn cascade_delete_subject(")
            .nth(1)
            .unwrap()
            .split("async fn delete_for_subject(")
            .next()
            .unwrap();
        let lesson_cleanup = source
            .find("DELETE FROM learn_lesson WHERE chapter_id IN")
            .expect("lesson cleanup is required before chapter deletion");
        let chapter_cleanup = source
            .find("DELETE FROM learn_chapter WHERE subject_id = ?")
            .expect("chapter cleanup is required before subject deletion");
        let subject_progress_cleanup = source
            .find("DELETE FROM subject_progress WHERE subject_id = ?")
            .expect("legacy progress materialization cleanup is required");
        let subject_delete = source
            .find("DELETE FROM learn_subject WHERE subject_id = ?")
            .expect("source subject must be deleted last");
        assert!(lesson_cleanup < chapter_cleanup);
        assert!(chapter_cleanup < subject_delete);
        assert!(subject_progress_cleanup < subject_delete);
        let course_delete = source
            .find("DELETE FROM learn_course WHERE subject_id = ?")
            .expect("course cleanup must be present");
        assert!(chapter_cleanup < course_delete);
        assert!(source.contains("DELETE FROM learn_question_first_attempt WHERE subject_id = ?"));
    }

    #[test]
    fn cascade_requires_committed_scope_before_deleting_and_never_guesses_legacy_ids() {
        let source = include_str!("subject_repository.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(checked_delete_scope(None, None).is_err());
        assert!(checked_delete_scope(Some(0), None).is_err());
        assert!(checked_delete_scope(Some(1), Some(0)).is_err());
        assert_eq!(
            checked_delete_scope(Some(1), Some(2)).unwrap(),
            SubjectDeleteScope {
                tenant_id: 1,
                domain_id: Some(2)
            }
        );
        let full = include_str!("subject_repository.rs");
        let implementation = full
            .split("impl SubjectRepository for SqlxSubjectRepository {")
            .nth(1)
            .unwrap()
            .split("async fn delete_for_subject(")
            .next()
            .unwrap();
        let cascade = implementation
            .split("async fn cascade_delete_subject(")
            .nth(1)
            .unwrap();
        assert!(
            cascade.find("validate_cascade_dependents(").unwrap()
                < cascade.find("DELETE FROM learn_lesson").unwrap()
        );
        for table in [
            "announcement",
            "discussion_post",
            "class",
            "course_workflow",
        ] {
            assert!(!cascade.contains(&format!("DELETE FROM {table} ")));
        }
        assert!(full.contains("row.status != \"PROCESSING\""));
        assert!(full.contains("*tenant != Some(scope.tenant_id)"));
        assert!(source.contains("LIMIT 10001 FOR UPDATE"));
    }

    #[test]
    fn pending_delete_intent_lookup_rejects_multiple_rows() {
        let source = include_str!("subject_repository.rs");
        assert!(source.contains("if prior.len() > 1"));
        assert!(source.contains("Multiple subject delete intents require reconciliation"));
    }
}
