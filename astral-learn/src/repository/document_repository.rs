//! 文档数据访问 — DocumentRepository
//!
//! 对齐 Java `DocumentMapper` 边界（documents 表）。
//! platform_v4 列名：storage_url 映射为 file_url。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::AstralError;

/// 文档行
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DocumentRecord {
    pub id: i64,
    pub title: String,
    pub subject_id: Option<i64>,
    pub file_url: Option<String>,
    pub file_type: Option<String>,
    pub created_at: Option<time::OffsetDateTime>,
}

#[async_trait]
pub trait DocumentRepository: Send + Sync {
    /// 总数（可选按 subject 过滤）
    async fn count(&self, subject_id: Option<i64>) -> Result<i64, AstralError>;
    /// 分页列表（可选按 subject 过滤）
    async fn list(
        &self,
        subject_id: Option<i64>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DocumentRecord>, AstralError>;
    /// 新建，返回新 id
    async fn create(
        &self,
        title: &str,
        subject_id: Option<i64>,
        file_url: Option<&str>,
        file_type: Option<&str>,
    ) -> Result<i64, AstralError>;
    /// 删除
    async fn delete(&self, id: i64) -> Result<(), AstralError>;
}

pub struct SqlxDocumentRepository {
    db: MySqlPool,
}

impl SqlxDocumentRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

const DOCUMENT_SELECT: &str =
    "SELECT id, title, subject_id, storage_url AS file_url, file_type, created_at FROM documents";

#[async_trait]
impl DocumentRepository for SqlxDocumentRepository {
    async fn count(&self, subject_id: Option<i64>) -> Result<i64, AstralError> {
        match subject_id {
            Some(sid) => {
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM documents WHERE subject_id = ?")
                    .bind(sid)
                    .fetch_one(&self.db)
                    .await
                    .map_err(db_error)
            }
            None => sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM documents")
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
    ) -> Result<Vec<DocumentRecord>, AstralError> {
        match subject_id {
            Some(sid) => sqlx::query_as::<_, DocumentRecord>(&format!(
                "{DOCUMENT_SELECT} WHERE subject_id = ? ORDER BY id LIMIT ? OFFSET ?"
            ))
            .bind(sid)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db)
            .await
            .map_err(db_error),
            None => sqlx::query_as::<_, DocumentRecord>(&format!(
                "{DOCUMENT_SELECT} ORDER BY id LIMIT ? OFFSET ?"
            ))
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db)
            .await
            .map_err(db_error),
        }
    }

    async fn create(
        &self,
        title: &str,
        subject_id: Option<i64>,
        file_url: Option<&str>,
        file_type: Option<&str>,
    ) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO documents (title, subject_id, storage_url, file_type, created_at) \
             VALUES (?, ?, ?, ?, NOW())",
        )
        .bind(title)
        .bind(subject_id)
        .bind(file_url)
        .bind(file_type)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
    }

    async fn delete(&self, id: i64) -> Result<(), AstralError> {
        sqlx::query("DELETE FROM documents WHERE id = ?")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Document repository query failed: {error}"))
}
