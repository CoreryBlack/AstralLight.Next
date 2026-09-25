//! 课程/章节/课时数据访问 — CourseRepository
//!
//! 对齐 Java `CourseMapper` 边界（learn_course / learn_chapter / learn_lesson）。
//! 章节删除级联（先删课时再删章节）收敛为单事务聚合方法 `delete_chapter`。
//! platform_v4 特例：learn_chapter 用 subject_id 关联课程（无 course_id 列）。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::AstralError;

/// 课程行
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CourseRecord {
    pub id: i64,
    pub subject_id: i64,
    pub title: String,
    pub description: Option<String>,
    pub teacher_id: Option<i64>,
    pub status: String,
}

/// 章节行（platform_v4: subject_id 映射为 course_id）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ChapterRecord {
    pub id: i64,
    pub course_id: i64,
    pub title: String,
    pub description: Option<String>,
    pub sort_order: i32,
}

/// 课时行
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LessonRecord {
    pub id: i64,
    pub chapter_id: i64,
    pub title: String,
    pub content_type: String,
    pub content_url: Option<String>,
    pub duration_minutes: i32,
    pub sort_order: i32,
}

/// 新建/更新课程参数
#[derive(Debug, Clone)]
pub struct CourseInput {
    pub subject_id: i64,
    pub title: String,
    pub description: Option<String>,
    pub teacher_id: Option<i64>,
}

/// 新建/更新章节参数
#[derive(Debug, Clone)]
pub struct ChapterInput {
    pub title: String,
    pub description: Option<String>,
    pub sort_order: i32,
}

/// 新建/更新课时参数
#[derive(Debug, Clone)]
pub struct LessonInput {
    pub title: String,
    pub content_type: String,
    pub content_url: Option<String>,
    pub duration_minutes: i32,
    pub sort_order: i32,
}

#[async_trait]
pub trait CourseRepository: Send + Sync {
    // ===== Course =====
    /// 总数（分页）
    async fn count_courses(&self) -> Result<i64, AstralError>;
    /// 分页列表
    async fn list_courses(&self, limit: i64, offset: i64)
        -> Result<Vec<CourseRecord>, AstralError>;
    /// 单条
    async fn get_course(&self, id: i64) -> Result<Option<CourseRecord>, AstralError>;
    /// 新建，返回新 id
    async fn create_course(&self, input: &CourseInput) -> Result<i64, AstralError>;
    /// 更新
    async fn update_course(&self, id: i64, input: &CourseInput) -> Result<(), AstralError>;
    /// 归档（status='ARCHIVED'）
    async fn archive_course(&self, id: i64) -> Result<(), AstralError>;
    /// 按 subject_id 硬删（学科级联最后一步）
    async fn delete_courses_by_subject(&self, subject_id: i64) -> Result<u64, AstralError>;

    // ===== Chapter =====
    /// 按 subject_id 列章节
    async fn list_chapters_by_subject(
        &self,
        subject_id: i64,
    ) -> Result<Vec<ChapterRecord>, AstralError>;
    /// 全量章节（独立 /chapters 路由，分页）
    async fn list_chapters_page(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ChapterRecord>, AstralError>;
    /// 章节总数（分页）
    async fn count_chapters(&self) -> Result<i64, AstralError>;
    /// 新建章节（subject_id 即 course_id），返回新 id
    async fn create_chapter(
        &self,
        subject_id: i64,
        input: &ChapterInput,
    ) -> Result<i64, AstralError>;
    /// 单条章节
    async fn get_chapter(&self, id: i64) -> Result<Option<ChapterRecord>, AstralError>;
    /// 更新章节（独立 /chapters 路由：无 subject 归属过滤）
    async fn update_chapter(&self, id: i64, input: &ChapterInput) -> Result<(), AstralError>;
    /// 更新章节（嵌套 /courses/{id}/chapters/{ch_id} 路由：含 subject_id 归属过滤）
    async fn update_chapter_by_subject(
        &self,
        id: i64,
        subject_id: i64,
        input: &ChapterInput,
    ) -> Result<(), AstralError>;
    /// 删除章节（单事务：先删课时再删章节；此前两条独立语句存在崩溃中间态）
    async fn delete_chapter(&self, id: i64) -> Result<(), AstralError>;

    // ===== Lesson =====
    /// 按 chapter_id 列课时
    async fn list_lessons(&self, chapter_id: i64) -> Result<Vec<LessonRecord>, AstralError>;
    /// 新建课时，返回新 id
    async fn create_lesson(&self, chapter_id: i64, input: &LessonInput)
        -> Result<i64, AstralError>;
}

pub struct SqlxCourseRepository {
    db: MySqlPool,
}

impl SqlxCourseRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

const COURSE_SELECT: &str = "SELECT course_id as id, subject_id, name as title, description, \
     instructor_user_id as teacher_id, status FROM learn_course";

#[async_trait]
impl CourseRepository for SqlxCourseRepository {
    // ===== Course =====
    async fn count_courses(&self) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM learn_course")
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_courses(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<CourseRecord>, AstralError> {
        sqlx::query_as::<_, CourseRecord>(&format!(
            "{COURSE_SELECT} ORDER BY course_id LIMIT ? OFFSET ?"
        ))
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn get_course(&self, id: i64) -> Result<Option<CourseRecord>, AstralError> {
        sqlx::query_as::<_, CourseRecord>(&format!("{COURSE_SELECT} WHERE course_id = ?"))
            .bind(id)
            .fetch_optional(&self.db)
            .await
            .map_err(db_error)
    }

    async fn create_course(&self, input: &CourseInput) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO learn_course (subject_id,name,description,instructor_user_id,status) \
             VALUES (?,?,?,?,'DRAFT')",
        )
        .bind(input.subject_id)
        .bind(&input.title)
        .bind(&input.description)
        .bind(input.teacher_id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
    }

    async fn update_course(&self, id: i64, input: &CourseInput) -> Result<(), AstralError> {
        sqlx::query(
            "UPDATE learn_course SET subject_id=?,name=?,description=?,instructor_user_id=? WHERE course_id=?",
        )
        .bind(input.subject_id)
        .bind(&input.title)
        .bind(&input.description)
        .bind(input.teacher_id)
        .bind(id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn archive_course(&self, id: i64) -> Result<(), AstralError> {
        sqlx::query("UPDATE learn_course SET status='ARCHIVED' WHERE course_id=?")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn delete_courses_by_subject(&self, subject_id: i64) -> Result<u64, AstralError> {
        let result = sqlx::query("DELETE FROM learn_course WHERE subject_id = ?")
            .bind(subject_id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected())
    }

    // ===== Chapter =====
    async fn list_chapters_by_subject(
        &self,
        subject_id: i64,
    ) -> Result<Vec<ChapterRecord>, AstralError> {
        sqlx::query_as::<_, ChapterRecord>(
            "SELECT chapter_id as id, subject_id as course_id, title, NULL as description, COALESCE(sort_order,0) as sort_order \
             FROM learn_chapter WHERE subject_id=? ORDER BY sort_order",
        )
        .bind(subject_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn list_chapters_page(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ChapterRecord>, AstralError> {
        sqlx::query_as::<_, ChapterRecord>(
            "SELECT chapter_id as id, subject_id as course_id, title, description, COALESCE(sort_order,0) as sort_order \
             FROM learn_chapter ORDER BY subject_id, sort_order LIMIT ? OFFSET ?",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn count_chapters(&self) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM learn_chapter")
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn create_chapter(
        &self,
        subject_id: i64,
        input: &ChapterInput,
    ) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO learn_chapter (subject_id, title, description, sort_order) VALUES (?, ?, ?, ?)",
        )
        .bind(subject_id)
        .bind(&input.title)
        .bind(&input.description)
        .bind(input.sort_order)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
    }

    async fn get_chapter(&self, id: i64) -> Result<Option<ChapterRecord>, AstralError> {
        sqlx::query_as::<_, ChapterRecord>(
            "SELECT chapter_id as id, subject_id as course_id, title, description, COALESCE(sort_order, 0) as sort_order \
             FROM learn_chapter WHERE chapter_id=?",
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn update_chapter(&self, id: i64, input: &ChapterInput) -> Result<(), AstralError> {
        sqlx::query(
            "UPDATE learn_chapter SET title=?, description=?, sort_order=? WHERE chapter_id=?",
        )
        .bind(&input.title)
        .bind(&input.description)
        .bind(input.sort_order)
        .bind(id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn update_chapter_by_subject(
        &self,
        id: i64,
        subject_id: i64,
        input: &ChapterInput,
    ) -> Result<(), AstralError> {
        sqlx::query(
            "UPDATE learn_chapter SET title=?, description=?, sort_order=? WHERE chapter_id=? AND subject_id=?",
        )
        .bind(&input.title)
        .bind(&input.description)
        .bind(input.sort_order)
        .bind(id)
        .bind(subject_id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn delete_chapter(&self, id: i64) -> Result<(), AstralError> {
        // 单事务：先删课时（级联）再删章节（此前两条独立语句，中途失败留孤儿课时）
        let mut tx = self.db.begin().await.map_err(db_error)?;
        sqlx::query("DELETE FROM learn_lesson WHERE chapter_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        sqlx::query("DELETE FROM learn_chapter WHERE chapter_id=?")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        tx.commit().await.map_err(db_error)?;
        Ok(())
    }

    // ===== Lesson =====
    async fn list_lessons(&self, chapter_id: i64) -> Result<Vec<LessonRecord>, AstralError> {
        sqlx::query_as::<_, LessonRecord>(
            "SELECT id, chapter_id, title, content_type, content_url, duration_minutes, sort_order \
             FROM learn_lesson WHERE chapter_id=? ORDER BY sort_order",
        )
        .bind(chapter_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn create_lesson(
        &self,
        chapter_id: i64,
        input: &LessonInput,
    ) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO learn_lesson (chapter_id,title,content_type,content_url,duration_minutes,sort_order) \
             VALUES (?,?,?,?,?,?)",
        )
        .bind(chapter_id)
        .bind(&input.title)
        .bind(&input.content_type)
        .bind(&input.content_url)
        .bind(input.duration_minutes)
        .bind(input.sort_order)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Course repository query failed: {error}"))
}
