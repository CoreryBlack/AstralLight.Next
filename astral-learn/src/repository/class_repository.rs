//! 班级数据访问 — ClassRepository
//!
//! 对齐 Java `ClassMapper` 边界（class 表）。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::AstralError;

/// 班级行
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ClassRecord {
    pub id: i64,
    pub name: String,
    pub code: Option<String>,
    pub subject_id: Option<i64>,
    pub teacher_id: Option<i64>,
    pub description: Option<String>,
}

/// 新建/更新班级参数
#[derive(Debug, Clone)]
pub struct ClassInput {
    pub name: String,
    pub code: Option<String>,
    pub subject_id: Option<i64>,
    pub teacher_id: Option<i64>,
    pub description: Option<String>,
}

#[async_trait]
pub trait ClassRepository: Send + Sync {
    /// 总数（分页）
    async fn count_all(&self) -> Result<i64, AstralError>;
    /// 分页列表
    async fn list_all(&self, limit: i64, offset: i64) -> Result<Vec<ClassRecord>, AstralError>;
    /// 单条
    async fn get(&self, id: i64) -> Result<Option<ClassRecord>, AstralError>;
    /// 新建，返回新 id
    async fn create(&self, input: &ClassInput) -> Result<i64, AstralError>;
    /// 更新
    async fn update(&self, id: i64, input: &ClassInput) -> Result<(), AstralError>;
    /// 删除
    async fn delete(&self, id: i64) -> Result<(), AstralError>;
}

pub struct SqlxClassRepository {
    db: MySqlPool,
}

impl SqlxClassRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

const CLASS_SELECT: &str = "SELECT id, name, code, subject_id, teacher_id, description FROM class";

#[async_trait]
impl ClassRepository for SqlxClassRepository {
    async fn count_all(&self) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM class")
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_all(&self, limit: i64, offset: i64) -> Result<Vec<ClassRecord>, AstralError> {
        sqlx::query_as::<_, ClassRecord>(&format!("{CLASS_SELECT} ORDER BY id LIMIT ? OFFSET ?"))
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db)
            .await
            .map_err(db_error)
    }

    async fn get(&self, id: i64) -> Result<Option<ClassRecord>, AstralError> {
        sqlx::query_as::<_, ClassRecord>(&format!("{CLASS_SELECT} WHERE id=?"))
            .bind(id)
            .fetch_optional(&self.db)
            .await
            .map_err(db_error)
    }

    async fn create(&self, input: &ClassInput) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO class (name, code, subject_id, teacher_id, description) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&input.name)
        .bind(&input.code)
        .bind(input.subject_id)
        .bind(input.teacher_id)
        .bind(&input.description)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
    }

    async fn update(&self, id: i64, input: &ClassInput) -> Result<(), AstralError> {
        sqlx::query(
            "UPDATE class SET name=?, code=?, subject_id=?, teacher_id=?, description=? WHERE id=?",
        )
        .bind(&input.name)
        .bind(&input.code)
        .bind(input.subject_id)
        .bind(input.teacher_id)
        .bind(&input.description)
        .bind(id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn delete(&self, id: i64) -> Result<(), AstralError> {
        sqlx::query("DELETE FROM class WHERE id=?")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Class repository query failed: {error}"))
}
