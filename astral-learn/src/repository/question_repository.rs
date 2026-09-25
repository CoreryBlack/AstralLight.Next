//! 题目数据访问 — QuestionRepository
//!
//! 对齐 Java `QuestionMapper` 边界（learn_question 表）。
//! 批量导入收敛为单事务聚合方法（此前逐条 INSERT 无事务，中途失败留孤儿行）。

use async_trait::async_trait;
use sqlx::{MySqlPool, QueryBuilder};

use astral_types::AstralError;

/// 题目行（platform_v4 列名 question_id/options_json/answer_text）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct QuestionRecord {
    pub id: i64,
    pub subject_id: i64,
    pub title: String,
    pub content: Option<String>,
    pub question_type: String,
    pub difficulty: i32,
    pub options: Option<String>,
    pub answer: Option<String>,
    pub status: String,
}

/// 新建/更新题目参数（默认值解析在 service 完成）
#[derive(Debug, Clone)]
pub struct QuestionInput {
    pub subject_id: i64,
    pub title: String,
    pub content: Option<String>,
    pub question_type: String,
    pub difficulty: i32,
    pub options: Option<String>,
    pub answer: Option<String>,
}

#[async_trait]
pub trait QuestionRepository: Send + Sync {
    /// 总数（分页）
    async fn count_all(&self) -> Result<i64, AstralError>;
    /// 分页列表（question_id）
    async fn list_all(&self, limit: i64, offset: i64) -> Result<Vec<QuestionRecord>, AstralError>;
    /// 单条
    async fn get(&self, id: i64) -> Result<Option<QuestionRecord>, AstralError>;
    /// 新建，返回新 id
    async fn create(&self, input: &QuestionInput) -> Result<i64, AstralError>;
    /// 更新
    async fn update(&self, id: i64, input: &QuestionInput) -> Result<(), AstralError>;
    /// 软删除（status='DISABLED'）
    async fn soft_delete(&self, id: i64) -> Result<(), AstralError>;
    /// 批量导入（单事务；任一条失败整体回滚），返回成功条数
    async fn batch_import(&self, items: &[QuestionInput]) -> Result<i64, AstralError>;
    /// 按 subject_id 硬删（学科级联最后一步）
    async fn delete_by_subject(&self, subject_id: i64) -> Result<u64, AstralError>;
}

pub struct SqlxQuestionRepository {
    db: MySqlPool,
}

impl SqlxQuestionRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

const QUESTION_SELECT: &str =
    "SELECT question_id as id, subject_id, title, content, question_type, \
     CAST(difficulty AS SIGNED) as difficulty, CAST(options_json AS CHAR) as options, \
     answer_text as answer, status FROM learn_question";

#[async_trait]
impl QuestionRepository for SqlxQuestionRepository {
    async fn count_all(&self) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM learn_question")
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_all(&self, limit: i64, offset: i64) -> Result<Vec<QuestionRecord>, AstralError> {
        sqlx::query_as::<_, QuestionRecord>(&format!(
            "{QUESTION_SELECT} ORDER BY question_id LIMIT ? OFFSET ?"
        ))
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn get(&self, id: i64) -> Result<Option<QuestionRecord>, AstralError> {
        sqlx::query_as::<_, QuestionRecord>(&format!("{QUESTION_SELECT} WHERE question_id = ?"))
            .bind(id)
            .fetch_optional(&self.db)
            .await
            .map_err(db_error)
    }

    async fn create(&self, input: &QuestionInput) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO learn_question (subject_id,title,content,question_type,difficulty,options_json,answer_text,status) \
             VALUES (?,?,?,?,?,?,?,'ACTIVE')",
        )
        .bind(input.subject_id)
        .bind(&input.title)
        .bind(&input.content)
        .bind(&input.question_type)
        .bind(input.difficulty)
        .bind(&input.options)
        .bind(&input.answer)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
    }

    async fn update(&self, id: i64, input: &QuestionInput) -> Result<(), AstralError> {
        sqlx::query(
            "UPDATE learn_question SET title=?,content=?,question_type=?,difficulty=?,options_json=?,answer_text=? WHERE question_id=?",
        )
        .bind(&input.title)
        .bind(&input.content)
        .bind(&input.question_type)
        .bind(input.difficulty)
        .bind(&input.options)
        .bind(&input.answer)
        .bind(id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn soft_delete(&self, id: i64) -> Result<(), AstralError> {
        sqlx::query("UPDATE learn_question SET status='DISABLED' WHERE question_id=?")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn batch_import(&self, items: &[QuestionInput]) -> Result<i64, AstralError> {
        if items.is_empty() {
            return Ok(0);
        }
        let mut builder =
            QueryBuilder::<sqlx::MySql>::new("INSERT INTO learn_question (subject_id,title,content,question_type,difficulty,options_json,answer_text,status) VALUES ");
        let mut first = true;
        for input in items {
            if !first {
                builder.push(", ");
            }
            first = false;
            builder
                .push("(")
                .push_bind(input.subject_id)
                .push(", ")
                .push_bind(&input.title)
                .push(", ")
                .push_bind(&input.content)
                .push(", ")
                .push_bind(&input.question_type)
                .push(", ")
                .push_bind(input.difficulty)
                .push(", ")
                .push_bind(&input.options)
                .push(", ")
                .push_bind(&input.answer)
                .push(", 'ACTIVE')");
        }
        // 单事务：任一条失败整体回滚（此前逐条 INSERT 无事务，中途失败留孤儿行）
        let mut tx = self.db.begin().await.map_err(db_error)?;
        builder.build().execute(&mut *tx).await.map_err(db_error)?;
        tx.commit().await.map_err(db_error)?;
        Ok(items.len() as i64)
    }

    async fn delete_by_subject(&self, subject_id: i64) -> Result<u64, AstralError> {
        let result = sqlx::query("DELETE FROM learn_question WHERE subject_id = ?")
            .bind(subject_id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected())
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Question repository query failed: {error}"))
}
