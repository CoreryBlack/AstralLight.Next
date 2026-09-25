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
    /// 软删除（status='DISABLED'）
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
        let mut tx = self.db.begin().await.map_err(db_error)?;

        // Step 1: lessons + chapters（learn_chapter 直接用 subject_id 关联）
        sqlx::query(
            "DELETE FROM learn_lesson WHERE chapter_id IN (SELECT chapter_id FROM learn_chapter WHERE subject_id = ?)",
        )
        .bind(subject_id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        sqlx::query("DELETE FROM learn_chapter WHERE subject_id = ?")
            .bind(subject_id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;

        // Step 2: levels
        sqlx::query("DELETE FROM learn_level WHERE subject_id = ?")
            .bind(subject_id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;

        // Step 3: questions
        sqlx::query("DELETE FROM learn_question WHERE subject_id = ?")
            .bind(subject_id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;

        // Step 4: courses
        sqlx::query("DELETE FROM learn_course WHERE subject_id = ?")
            .bind(subject_id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;

        // Step 5: user_subjects
        sqlx::query("DELETE FROM learn_user_subject WHERE subject_id = ?")
            .bind(subject_id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;

        // Step 6: question_first_attempts
        sqlx::query("DELETE FROM learn_question_first_attempt WHERE subject_id = ?")
            .bind(subject_id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;

        // Step 7: documents
        sqlx::query("DELETE FROM documents WHERE subject_id = ?")
            .bind(subject_id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;

        // Step 8: subject（主表，最后删除）
        sqlx::query("DELETE FROM learn_subject WHERE subject_id = ?")
            .bind(subject_id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;

        tx.commit().await.map_err(db_error)?;
        tracing::info!(subject_id, "cascade delete completed");
        Ok(())
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Subject repository query failed: {error}"))
}
