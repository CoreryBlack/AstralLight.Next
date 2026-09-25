//! 讨论区数据访问 — DiscussionRepository
//!
//! 对齐 Java `AnnouncementMapper` + `DiscussionMapper` 边界（learn_announcement +
//! learn_discussion_post 表）。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::AstralError;

/// 公告行
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AnnouncementRecord {
    pub id: i64,
    pub course_id: i64,
    pub title: String,
    pub content: String,
    pub author_id: i64,
    pub pinned: bool,
    pub created_at: Option<String>,
}

/// 讨论帖行
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DiscussionRecord {
    pub id: i64,
    pub course_id: i64,
    pub title: String,
    pub content: String,
    pub author_id: i64,
    pub created_at: Option<String>,
}

#[async_trait]
pub trait DiscussionRepository: Send + Sync {
    /// 公告总数
    async fn count_announcements(&self) -> Result<i64, AstralError>;
    /// 公告列表（pinned DESC, created_at DESC）
    async fn list_announcements(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AnnouncementRecord>, AstralError>;
    /// 新建公告，返回新 id
    async fn create_announcement(
        &self,
        course_id: i64,
        title: &str,
        content: &str,
        author_id: i64,
        pinned: bool,
    ) -> Result<i64, AstralError>;
    /// 单条公告
    async fn get_announcement(&self, id: i64) -> Result<Option<AnnouncementRecord>, AstralError>;
    /// 更新公告
    async fn update_announcement(
        &self,
        id: i64,
        title: &str,
        content: &str,
        pinned: bool,
    ) -> Result<(), AstralError>;
    /// 删除公告
    async fn delete_announcement(&self, id: i64) -> Result<(), AstralError>;
    /// 讨论帖总数
    async fn count_discussions(&self) -> Result<i64, AstralError>;
    /// 讨论帖列表（created_at DESC）
    async fn list_discussions(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DiscussionRecord>, AstralError>;
    /// 新建讨论帖，返回新 id
    async fn create_discussion(
        &self,
        course_id: i64,
        title: &str,
        content: &str,
        author_id: i64,
    ) -> Result<i64, AstralError>;
    /// 单条讨论帖
    async fn get_discussion(&self, id: i64) -> Result<Option<DiscussionRecord>, AstralError>;
    /// 删除讨论帖
    async fn delete_discussion(&self, id: i64) -> Result<(), AstralError>;
}

pub struct SqlxDiscussionRepository {
    db: MySqlPool,
}

impl SqlxDiscussionRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

#[async_trait]
impl DiscussionRepository for SqlxDiscussionRepository {
    async fn count_announcements(&self) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM learn_announcement")
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_announcements(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AnnouncementRecord>, AstralError> {
        sqlx::query_as::<_, AnnouncementRecord>(
            "SELECT id, course_id, title, content, author_id, pinned, created_at \
             FROM learn_announcement ORDER BY pinned DESC, created_at DESC LIMIT ? OFFSET ?",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn create_announcement(
        &self,
        course_id: i64,
        title: &str,
        content: &str,
        author_id: i64,
        pinned: bool,
    ) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO learn_announcement (course_id, title, content, author_id, pinned) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(course_id)
        .bind(title)
        .bind(content)
        .bind(author_id)
        .bind(pinned as i32)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
    }

    async fn get_announcement(&self, id: i64) -> Result<Option<AnnouncementRecord>, AstralError> {
        sqlx::query_as::<_, AnnouncementRecord>(
            "SELECT id, course_id, title, content, author_id, pinned, created_at \
             FROM learn_announcement WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn update_announcement(
        &self,
        id: i64,
        title: &str,
        content: &str,
        pinned: bool,
    ) -> Result<(), AstralError> {
        sqlx::query(
            "UPDATE learn_announcement SET title = ?, content = ?, pinned = ? WHERE id = ?",
        )
        .bind(title)
        .bind(content)
        .bind(pinned as i32)
        .bind(id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn delete_announcement(&self, id: i64) -> Result<(), AstralError> {
        sqlx::query("DELETE FROM learn_announcement WHERE id = ?")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn count_discussions(&self) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM learn_discussion_post")
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_discussions(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DiscussionRecord>, AstralError> {
        sqlx::query_as::<_, DiscussionRecord>(
            "SELECT id, course_id, title, content, author_id, created_at \
             FROM learn_discussion_post ORDER BY created_at DESC LIMIT ? OFFSET ?",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn create_discussion(
        &self,
        course_id: i64,
        title: &str,
        content: &str,
        author_id: i64,
    ) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO learn_discussion_post (course_id, title, content, author_id) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(course_id)
        .bind(title)
        .bind(content)
        .bind(author_id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
    }

    async fn get_discussion(&self, id: i64) -> Result<Option<DiscussionRecord>, AstralError> {
        sqlx::query_as::<_, DiscussionRecord>(
            "SELECT id, course_id, title, content, author_id, created_at \
             FROM learn_discussion_post WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn delete_discussion(&self, id: i64) -> Result<(), AstralError> {
        sqlx::query("DELETE FROM learn_discussion_post WHERE id = ?")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Discussion repository query failed: {error}"))
}
