//! 关卡数据访问 — LevelRepository
//!
//! 对齐 Java `LevelMapper` 边界（learn_level / learn_level_status / learn_level_questions）。
//! platform_v4 列名：level_id / title(as name) / sort_order(as sequence)。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::AstralError;

/// 关卡行
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LevelRecord {
    pub id: i64,
    pub subject_id: i64,
    pub name: String,
    pub sequence: i32,
    pub level_type: String,
    pub config_json: Option<String>,
    pub status: String,
    pub created_at: Option<time::PrimitiveDateTime>,
}

/// 关卡题目行
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LevelQuestionRecord {
    pub id: i64,
    pub level_id: i64,
    pub question_id: i64,
    pub sequence: i32,
}

/// 新建/更新关卡参数（默认值解析在 handler/service）
#[derive(Debug, Clone)]
pub struct LevelInput {
    pub subject_id: i64,
    pub name: String,
    pub sequence: i32,
    pub level_type: String,
}

#[async_trait]
pub trait LevelRepository: Send + Sync {
    /// 总数（可选按 subject 过滤）
    async fn count(&self, subject_id: Option<i64>) -> Result<i64, AstralError>;
    /// 分页列表（可选按 subject 过滤）
    async fn list(
        &self,
        subject_id: Option<i64>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<LevelRecord>, AstralError>;
    /// 新建，返回新 id（status='ACTIVE'）
    async fn create(&self, input: &LevelInput) -> Result<i64, AstralError>;
    /// 更新
    async fn update(&self, id: i64, input: &LevelInput) -> Result<(), AstralError>;
    /// 软删除（status='DISABLED'）
    async fn soft_delete(&self, id: i64) -> Result<(), AstralError>;
    /// 查询活跃关卡（start_level 前置校验）
    async fn get_active(&self, id: i64) -> Result<Option<LevelRecord>, AstralError>;
    /// 关卡题目列表（按 sequence 排序）
    async fn list_questions(&self, level_id: i64) -> Result<Vec<LevelQuestionRecord>, AstralError>;
    /// 创建关卡进度（is_unlocked=1, is_completed=0, attempt_count=1），返回新 id
    async fn create_level_status(&self, level_id: i64, user_id: i64) -> Result<i64, AstralError>;
    /// 查询关卡进度状态（submit_answer 前置守卫）
    async fn get_status_for_user(
        &self,
        level_status_id: i64,
        user_id: i64,
    ) -> Result<Option<String>, AstralError>;
    /// 完成关卡（IN_PROGRESS → COMPLETED + score + finished_at），返回是否命中
    async fn finish_level(
        &self,
        level_status_id: i64,
        user_id: i64,
        score: i32,
    ) -> Result<bool, AstralError>;
}

pub struct SqlxLevelRepository {
    db: MySqlPool,
}

impl SqlxLevelRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

const LEVEL_SELECT: &str =
    "SELECT level_id as id, subject_id, title as name, COALESCE(sort_order,0) as sequence, \
     level_type, NULL as config_json, status, created_at FROM learn_level";

#[async_trait]
impl LevelRepository for SqlxLevelRepository {
    async fn count(&self, subject_id: Option<i64>) -> Result<i64, AstralError> {
        match subject_id {
            Some(sid) => sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM learn_level WHERE subject_id = ?",
            )
            .bind(sid)
            .fetch_one(&self.db)
            .await
            .map_err(db_error),
            None => sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM learn_level")
                .fetch_one(&self.db)
                .await
                .map_err(db_error),
        }
    }

    async fn list(
        &self,
        subject_id: Option<i64>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<LevelRecord>, AstralError> {
        match subject_id {
            Some(sid) => sqlx::query_as::<_, LevelRecord>(&format!(
                "{LEVEL_SELECT} WHERE subject_id = ? ORDER BY sort_order LIMIT ? OFFSET ?"
            ))
            .bind(sid)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db)
            .await
            .map_err(db_error),
            None => sqlx::query_as::<_, LevelRecord>(&format!(
                "{LEVEL_SELECT} ORDER BY subject_id, sort_order LIMIT ? OFFSET ?"
            ))
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db)
            .await
            .map_err(db_error),
        }
    }

    async fn create(&self, input: &LevelInput) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO learn_level (subject_id, title, sort_order, level_type, status) \
             VALUES (?, ?, ?, ?, 'ACTIVE')",
        )
        .bind(input.subject_id)
        .bind(&input.name)
        .bind(input.sequence)
        .bind(&input.level_type)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
    }

    async fn update(&self, id: i64, input: &LevelInput) -> Result<(), AstralError> {
        sqlx::query(
            "UPDATE learn_level SET subject_id = ?, title = ?, sort_order = ?, level_type = ? WHERE level_id = ?",
        )
        .bind(input.subject_id)
        .bind(&input.name)
        .bind(input.sequence)
        .bind(&input.level_type)
        .bind(id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn soft_delete(&self, id: i64) -> Result<(), AstralError> {
        sqlx::query("UPDATE learn_level SET status = 'DISABLED' WHERE level_id = ?")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn get_active(&self, id: i64) -> Result<Option<LevelRecord>, AstralError> {
        sqlx::query_as::<_, LevelRecord>(&format!(
            "{LEVEL_SELECT} WHERE level_id = ? AND status = 'ACTIVE'"
        ))
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn list_questions(&self, level_id: i64) -> Result<Vec<LevelQuestionRecord>, AstralError> {
        sqlx::query_as::<_, LevelQuestionRecord>(
            "SELECT level_question_id as id, level_id, question_id, COALESCE(sequence,0) as sequence \
             FROM learn_level_questions WHERE level_id = ? ORDER BY sequence",
        )
        .bind(level_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn create_level_status(&self, level_id: i64, user_id: i64) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO learn_level_status (level_id, user_id, is_unlocked, is_completed, attempt_count) \
             VALUES (?, ?, 1, 0, 1)",
        )
        .bind(level_id)
        .bind(user_id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
    }

    async fn get_status_for_user(
        &self,
        level_status_id: i64,
        user_id: i64,
    ) -> Result<Option<String>, AstralError> {
        sqlx::query_scalar::<_, String>(
            "SELECT status FROM learn_level_status WHERE id = ? AND user_id = ?",
        )
        .bind(level_status_id)
        .bind(user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn finish_level(
        &self,
        level_status_id: i64,
        user_id: i64,
        score: i32,
    ) -> Result<bool, AstralError> {
        let result = sqlx::query(
            "UPDATE learn_level_status SET status = 'COMPLETED', score = ?, finished_at = NOW() \
             WHERE id = ? AND user_id = ? AND status = 'IN_PROGRESS'",
        )
        .bind(score)
        .bind(level_status_id)
        .bind(user_id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() > 0)
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Level repository query failed: {error}"))
}
