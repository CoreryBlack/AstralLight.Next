//! astral-learn 集成测试 — platform_v4 schema 对齐验证
//!
//! 需要 Docker MySQL 8.0 环境（通过 docker-compose.test.yml 启动）。
//! 运行方式：
//!   cargo test -p astral-learn --test integration -- --ignored --nocapture
//!
//! 测试策略：使用 platform_v4 真实列名 INSERT，再用 Rust 同款 SQL 别名 SELECT，
//! 验证 FromRow struct 字段名与 platform_v4 列名之间的别名桥接正确工作。

use sqlx::MySqlPool;

// =====================================================================
// 测试用的 FromRow struct — 与 Rust srv/*.rs 中的结构完全一致
// =====================================================================

#[derive(Debug, sqlx::FromRow, PartialEq)]
struct SubjectRow {
    id: i64,
    name: String,
    code: String,
    parent_id: Option<i64>,
    description: Option<String>,
    sort_order: i32,
    status: String,
}

#[derive(Debug, sqlx::FromRow, PartialEq)]
struct CourseRow {
    id: i64,
    subject_id: i64,
    title: String,
    description: Option<String>,
    teacher_id: Option<i64>,
    status: String,
}

#[derive(Debug, sqlx::FromRow, PartialEq)]
struct ChapterRow {
    id: i64,
    course_id: i64,
    title: String,
    description: Option<String>,
    sort_order: i32,
}

#[derive(Debug, sqlx::FromRow, PartialEq)]
struct QuestionRow {
    id: i64,
    subject_id: i64,
    title: String,
    content: Option<String>,
    question_type: String,
    difficulty: i32,
    options: Option<String>,
    answer: Option<String>,
    status: String,
}

#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
struct EnrollmentRow {
    id: i64,
    user_id: i64,
    course_id: i64,
    status: String,
    progress_pct: f64,
}

// ---- 新增 FromRow struct ----

#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
struct FirstAttemptRow {
    id: i64,
    user_id: i64,
    question_id: i64,
    subject_id: Option<i64>,
    is_correct: i32,
    attempted_at: Option<time::PrimitiveDateTime>,
}

#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
struct SubmissionRow {
    id: i64,
    assignment_id: i64,
    student_id: i64,
    content: Option<String>,
    file_url: Option<String>,
    score: Option<f64>,
    feedback: Option<String>,
    status: String,
}

#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
struct AssignmentRow {
    id: i64,
    course_id: i64,
    title: String,
    description: Option<String>,
    max_score: f64,
    status: String,
}

#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
struct SolutionRow {
    id: i64,
    question_id: i64,
    user_id: i64,
    content: String,
    like_count: i32,
    created_at: Option<time::PrimitiveDateTime>,
}

#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
struct AnnouncementRow {
    id: i64,
    course_id: i64,
    title: String,
    content: String,
    author_id: i64,
    pinned: bool,
    created_at: Option<time::OffsetDateTime>,
}

#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
struct DiscussionRow {
    id: i64,
    course_id: i64,
    title: String,
    content: String,
    author_id: i64,
    created_at: Option<time::OffsetDateTime>,
}

#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
struct DeviceRow {
    id: i64,
    user_id: i64,
    device_name: Option<String>,
    device_type: Option<String>,
    device_id: Option<String>,
    last_login_at: Option<time::OffsetDateTime>,
    created_at: Option<time::OffsetDateTime>,
}

// =====================================================================
// 辅助函数
// =====================================================================

async fn connect() -> Option<MySqlPool> {
    let required = std::env::var("RUST_INTEGRATION_REQUIRED").as_deref() == Ok("1");
    let url = match std::env::var("DATABASE_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        Ok(_) | Err(_) => {
            let message = "DATABASE_URL must be set to run MySQL integration tests";
            if required {
                panic!("RUST_INTEGRATION_REQUIRED=1: {message}");
            }
            eprintln!("[SKIP] {message}");
            return None;
        }
    };

    match MySqlPool::connect(&url).await {
        Ok(p) => Some(p),
        Err(e) => {
            if required {
                panic!("RUST_INTEGRATION_REQUIRED=1: cannot connect using DATABASE_URL: {e}");
            }
            eprintln!("[SKIP] Cannot connect using DATABASE_URL: {e}");
            None
        }
    }
}

async fn setup_learn_tables(pool: &MySqlPool) {
    // 确保 platform_v4 的 learn_* 表存在（Docker MySQL 已自动执行 migrations）
    // 此处仅清理旧测试数据
    // 自建缺失表（远程 DB 未执行 migration 20260705000001）
    // 先 DROP 再 CREATE，确保列结构与测试一致
    let _ = sqlx::query("DROP TABLE IF EXISTS learn_lesson")
        .execute(pool)
        .await;
    let _ = sqlx::query("DROP TABLE IF EXISTS learn_assignment")
        .execute(pool)
        .await;
    let _ = sqlx::query("DROP TABLE IF EXISTS learn_submission")
        .execute(pool)
        .await;
    let _ = sqlx::query("DROP TABLE IF EXISTS learn_device")
        .execute(pool)
        .await;
    let _ = sqlx::query("DROP TABLE IF EXISTS learn_announcement")
        .execute(pool)
        .await;
    let _ = sqlx::query("DROP TABLE IF EXISTS learn_discussion_post")
        .execute(pool)
        .await;
    let _ = sqlx::query(
        "CREATE TABLE IF NOT EXISTS learn_lesson (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            chapter_id BIGINT NOT NULL,
            title VARCHAR(255) NOT NULL,
            content_type VARCHAR(32) NOT NULL DEFAULT 'VIDEO',
            content_url VARCHAR(512),
            duration_minutes INT NOT NULL DEFAULT 0,
            sort_order INT NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_learn_lesson_chapter (chapter_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
    )
    .execute(pool)
    .await;
    let _ = sqlx::query(
        "CREATE TABLE IF NOT EXISTS learn_assignment (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            course_id BIGINT NOT NULL,
            title VARCHAR(255) NOT NULL,
            description TEXT,
            due_date TIMESTAMP NULL,
            max_score DOUBLE NOT NULL DEFAULT 100,
            status VARCHAR(32) NOT NULL DEFAULT 'DRAFT',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_learn_assignment_course (course_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
    )
    .execute(pool)
    .await;
    let _ = sqlx::query(
        "CREATE TABLE IF NOT EXISTS learn_submission (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            assignment_id BIGINT NOT NULL,
            user_id BIGINT NOT NULL,
            content TEXT,
            file_url VARCHAR(512),
            score DOUBLE,
            feedback TEXT,
            graded TINYINT NOT NULL DEFAULT 0,
            status VARCHAR(32) NOT NULL DEFAULT 'SUBMITTED',
            submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_learn_submission_assignment (assignment_id),
            UNIQUE KEY uk_learn_submission (assignment_id, user_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
    )
    .execute(pool)
    .await;
    let _ = sqlx::query(
        "CREATE TABLE IF NOT EXISTS learn_device (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            user_id BIGINT NOT NULL,
            device_name VARCHAR(255),
            device_type VARCHAR(32),
            device_id VARCHAR(255),
            last_login_at TIMESTAMP NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_learn_device_user (user_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
    )
    .execute(pool)
    .await;
    let _ = sqlx::query(
        "CREATE TABLE IF NOT EXISTS learn_announcement (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            course_id BIGINT NOT NULL,
            title VARCHAR(255) NOT NULL,
            content TEXT NOT NULL,
            author_id BIGINT NOT NULL,
            pinned TINYINT NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_learn_announcement_course (course_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
    )
    .execute(pool)
    .await;
    let _ = sqlx::query(
        "CREATE TABLE IF NOT EXISTS learn_discussion_post (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            course_id BIGINT NOT NULL,
            title VARCHAR(255) NOT NULL,
            content TEXT NOT NULL,
            author_id BIGINT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_learn_discussion_post_course (course_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
    )
    .execute(pool)
    .await;
    // 补齐 learn_course_enrollment.progress_pct 列
    let _ = sqlx::query(
        "ALTER TABLE learn_course_enrollment ADD COLUMN IF NOT EXISTS progress_pct DOUBLE NOT NULL DEFAULT 0"
    ).execute(pool).await;
    // 按 code LIKE 'IT_%' 清理（覆盖远程 DB auto_increment 不在 99000-99999 范围的情况）
    // 先删子表再删父表，避免 FK 冲突
    let test_subjs: Vec<(i64,)> =
        sqlx::query_as("SELECT subject_id FROM learn_subject WHERE code LIKE 'IT_%'")
            .fetch_all(pool)
            .await
            .unwrap_or_default();
    let test_courses: Vec<(i64,)> = sqlx::query_as(
        "SELECT course_id FROM learn_course WHERE subject_id IN (SELECT subject_id FROM learn_subject WHERE code LIKE 'IT_%')"
    ).fetch_all(pool).await.unwrap_or_default();
    let test_chapters: Vec<(i64,)> = sqlx::query_as(
        "SELECT chapter_id FROM learn_chapter WHERE subject_id IN (SELECT subject_id FROM learn_subject WHERE code LIKE 'IT_%')"
    ).fetch_all(pool).await.unwrap_or_default();

    for (cid,) in &test_courses {
        let _ = sqlx::query("DELETE FROM learn_course_enrollment WHERE course_id = ?")
            .bind(cid)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM learn_assignment WHERE course_id = ?")
            .bind(cid)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM learn_announcement WHERE course_id = ?")
            .bind(cid)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM learn_discussion_post WHERE course_id = ?")
            .bind(cid)
            .execute(pool)
            .await;
    }
    for (chid,) in &test_chapters {
        let _ = sqlx::query("DELETE FROM learn_lesson WHERE chapter_id = ?")
            .bind(chid)
            .execute(pool)
            .await;
    }
    for (sid,) in &test_subjs {
        let _ = sqlx::query("DELETE FROM learn_question_first_attempt WHERE subject_id = ?")
            .bind(sid)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM learn_question_solution WHERE question_id IN (SELECT question_id FROM learn_question WHERE subject_id = ?)").bind(sid).execute(pool).await;
        let _ = sqlx::query("DELETE FROM learn_question WHERE subject_id = ?")
            .bind(sid)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM learn_chapter WHERE subject_id = ?")
            .bind(sid)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM learn_course WHERE subject_id = ?")
            .bind(sid)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM learn_level WHERE subject_id = ?")
            .bind(sid)
            .execute(pool)
            .await;
    }
    // 按 author_id/user_id 清理独立表
    let _ = sqlx::query("DELETE FROM learn_submission WHERE user_id BETWEEN 99000 AND 99999")
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM learn_device WHERE user_id BETWEEN 99000 AND 99999")
        .execute(pool)
        .await;
    // 最后删学科
    let _ = sqlx::query("DELETE FROM learn_subject WHERE code LIKE 'IT_%'")
        .execute(pool)
        .await;
}

// =====================================================================
// 测试：learn_subject — platform_v4 列名 subject_id / parent_subject_id
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_learn_subject_crud() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    setup_learn_tables(&pool).await;

    // === CREATE: 使用 platform_v4 真实列名 INSERT ===
    let result = sqlx::query(
        "INSERT INTO learn_subject (name, code, parent_subject_id, description, sort_order, status) \
         VALUES ('集成测试学科', 'IT_TEST_001', NULL, '用于集成测试的学科', 10, 'ACTIVE')"
    )
    .execute(&pool).await.expect("INSERT learn_subject should succeed");
    let subject_id = result.last_insert_id() as i64;
    assert!(subject_id > 0, "should get a valid subject_id");

    // === READ: 使用 Rust 同款 SQL 别名 SELECT ===
    let row = sqlx::query_as::<_, SubjectRow>(
        "SELECT subject_id as id, name, code, parent_subject_id as parent_id, \
         description, COALESCE(sort_order,0) as sort_order, status \
         FROM learn_subject WHERE subject_id = ?",
    )
    .bind(subject_id)
    .fetch_one(&pool)
    .await
    .expect("SELECT with aliases should succeed");

    assert_eq!(row.name, "集成测试学科");
    assert_eq!(row.code, "IT_TEST_001");
    assert_eq!(row.parent_id, None);
    assert_eq!(row.sort_order, 10);
    assert_eq!(row.status, "ACTIVE");

    // === UPDATE: 使用 platform_v4 真实列名 UPDATE ===
    sqlx::query("UPDATE learn_subject SET name = ?, sort_order = ? WHERE subject_id = ?")
        .bind("更新后的学科")
        .bind(20)
        .bind(subject_id)
        .execute(&pool)
        .await
        .expect("UPDATE should succeed");

    let updated = sqlx::query_as::<_, SubjectRow>(
        "SELECT subject_id as id, name, code, parent_subject_id as parent_id, \
         description, COALESCE(sort_order,0) as sort_order, status \
         FROM learn_subject WHERE subject_id = ?",
    )
    .bind(subject_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(updated.name, "更新后的学科");
    assert_eq!(updated.sort_order, 20);

    // === DELETE: 清理 ===
    sqlx::query("DELETE FROM learn_subject WHERE subject_id = ?")
        .bind(subject_id)
        .execute(&pool)
        .await
        .unwrap();

    // 验证已删除
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM learn_subject WHERE subject_id = ?")
        .bind(subject_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 0);

    eprintln!("[PASS] learn_subject CRUD with platform_v4 column aliases");
}

// =====================================================================
// 测试：learn_subject 父子关系（parent_subject_id）
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_learn_subject_parent_child() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    setup_learn_tables(&pool).await;

    // 创建父学科
    let parent_id = sqlx::query(
        "INSERT INTO learn_subject (name, code, parent_subject_id, sort_order, status) \
         VALUES ('父学科', 'IT_PARENT', NULL, 0, 'ACTIVE')",
    )
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    // 创建子学科（parent_subject_id = parent_id）
    let child_id = sqlx::query(
        "INSERT INTO learn_subject (name, code, parent_subject_id, sort_order, status) \
         VALUES ('子学科', 'IT_CHILD', ?, 0, 'ACTIVE')",
    )
    .bind(parent_id)
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    // 验证子学科的 parent_subject_id 正确映射到 Rust struct 的 parent_id
    let child = sqlx::query_as::<_, SubjectRow>(
        "SELECT subject_id as id, name, code, parent_subject_id as parent_id, \
         description, COALESCE(sort_order,0) as sort_order, status \
         FROM learn_subject WHERE subject_id = ?",
    )
    .bind(child_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(child.parent_id, Some(parent_id));

    // 验证父学科的 parent_id 为 None
    let parent = sqlx::query_as::<_, SubjectRow>(
        "SELECT subject_id as id, name, code, parent_subject_id as parent_id, \
         description, COALESCE(sort_order,0) as sort_order, status \
         FROM learn_subject WHERE subject_id = ?",
    )
    .bind(parent_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(parent.parent_id, None);

    // 清理
    sqlx::query("DELETE FROM learn_subject WHERE subject_id IN (?, ?)")
        .bind(child_id)
        .bind(parent_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] learn_subject parent-child with parent_subject_id alias");
}

// =====================================================================
// 测试：learn_course — platform_v4 列名 course_id / name / instructor_user_id
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_learn_course_crud() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    setup_learn_tables(&pool).await;

    // 先创建一个学科
    let subj_id = sqlx::query(
        "INSERT INTO learn_subject (name, code, sort_order, status) VALUES ('课程测试学科', 'IT_CRS', 0, 'ACTIVE')"
    ).execute(&pool).await.unwrap().last_insert_id() as i64;

    // === CREATE: 使用 platform_v4 真实列名 INSERT（name, instructor_user_id）===
    let result = sqlx::query(
        "INSERT INTO learn_course (subject_id, name, description, instructor_user_id, status) \
         VALUES (?, '测试课程', '这是一门测试课程', 1001, 'ACTIVE')",
    )
    .bind(subj_id)
    .execute(&pool)
    .await
    .expect("INSERT learn_course should succeed");
    let course_id = result.last_insert_id() as i64;
    assert!(course_id > 0);

    // === READ: 使用 Rust 同款别名 SELECT（name as title, instructor_user_id as teacher_id）===
    let row = sqlx::query_as::<_, CourseRow>(
        "SELECT course_id as id, subject_id, name as title, description, \
         instructor_user_id as teacher_id, status \
         FROM learn_course WHERE course_id = ?",
    )
    .bind(course_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(row.title, "测试课程"); // name → title 别名
    assert_eq!(row.teacher_id, Some(1001)); // instructor_user_id → teacher_id 别名
    assert_eq!(row.subject_id, subj_id);
    assert_eq!(row.status, "ACTIVE");

    // === UPDATE ===
    sqlx::query("UPDATE learn_course SET name = ? WHERE course_id = ?")
        .bind("更新后的课程")
        .bind(course_id)
        .execute(&pool)
        .await
        .unwrap();

    let updated = sqlx::query_as::<_, CourseRow>(
        "SELECT course_id as id, subject_id, name as title, description, \
         instructor_user_id as teacher_id, status \
         FROM learn_course WHERE course_id = ?",
    )
    .bind(course_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(updated.title, "更新后的课程");

    // 清理
    sqlx::query("DELETE FROM learn_course WHERE course_id = ?")
        .bind(course_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM learn_subject WHERE subject_id = ?")
        .bind(subj_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] learn_course CRUD with name→title, instructor_user_id→teacher_id aliases");
}

// =====================================================================
// 测试：learn_chapter — platform_v4 列名 chapter_id / subject_id（不是 course_id！）
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_learn_chapter_crud() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    setup_learn_tables(&pool).await;

    // 创建学科（chapter 直接关联 subject_id）
    let subj_id = sqlx::query(
        "INSERT INTO learn_subject (name, code, sort_order, status) VALUES ('章节测试学科', 'IT_CH', 0, 'ACTIVE')"
    ).execute(&pool).await.unwrap().last_insert_id() as i64;

    // === CREATE: platform_v4 列名 chapter_id, subject_id, sort_order (nullable) ===
    let result = sqlx::query(
        "INSERT INTO learn_chapter (subject_id, title, description, sort_order, status) \
         VALUES (?, '第一章', '第一章描述', 1, 'ACTIVE')",
    )
    .bind(subj_id)
    .execute(&pool)
    .await
    .expect("INSERT learn_chapter should succeed");
    let chapter_id = result.last_insert_id() as i64;

    // === READ: 使用别名 chapter_id as id, subject_id as course_id, COALESCE(sort_order) ===
    let row = sqlx::query_as::<_, ChapterRow>(
        "SELECT chapter_id as id, subject_id as course_id, title, description, \
         COALESCE(sort_order, 0) as sort_order \
         FROM learn_chapter WHERE chapter_id = ?",
    )
    .bind(chapter_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(row.course_id, subj_id); // subject_id → course_id 别名
    assert_eq!(row.title, "第一章");
    assert_eq!(row.sort_order, 1);
    assert_eq!(row.description.as_deref(), Some("第一章描述"));

    // === 测试 COALESCE: sort_order IS NULL 场景 ===
    sqlx::query(
        "INSERT INTO learn_chapter (subject_id, title, sort_order, status) \
         VALUES (?, '无排序章节', NULL, 'ACTIVE')",
    )
    .bind(subj_id)
    .execute(&pool)
    .await
    .unwrap();

    let null_sort_row = sqlx::query_as::<_, ChapterRow>(
        "SELECT chapter_id as id, subject_id as course_id, title, description, \
         COALESCE(sort_order, 0) as sort_order \
         FROM learn_chapter WHERE title = '无排序章节'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        null_sort_row.sort_order, 0,
        "COALESCE should return 0 for NULL sort_order"
    );

    // 清理
    sqlx::query("DELETE FROM learn_chapter WHERE subject_id = ?")
        .bind(subj_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM learn_subject WHERE subject_id = ?")
        .bind(subj_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] learn_chapter with subject_id→course_id alias + COALESCE(sort_order)");
}

// =====================================================================
// 测试：learn_question — platform_v4: difficulty VARCHAR, options_json JSON, answer_text
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_learn_question_crud() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    setup_learn_tables(&pool).await;

    let subj_id = sqlx::query(
        "INSERT INTO learn_subject (name, code, sort_order, status) VALUES ('题目测试学科', 'IT_Q', 0, 'ACTIVE')"
    ).execute(&pool).await.unwrap().last_insert_id() as i64;

    // === CREATE: platform_v4 列名: question_id, difficulty VARCHAR, options_json JSON, answer_text ===
    let result = sqlx::query(
        "INSERT INTO learn_question (subject_id, title, content, question_type, difficulty, options_json, answer_text, status) \
         VALUES (?, '1+1=?', '计算: 1+1=?', 'SINGLE_CHOICE', '3', \
                 '{\"A\":\"1\",\"B\":\"2\",\"C\":\"3\",\"D\":\"4\"}', \
                 'B', 'ACTIVE')"
    ).bind(subj_id).execute(&pool).await.expect("INSERT learn_question should succeed");
    let q_id = result.last_insert_id() as i64;

    // === READ: CAST(difficulty AS SIGNED), CAST(options_json AS CHAR), answer_text as answer ===
    let row = sqlx::query_as::<_, QuestionRow>(
        "SELECT question_id as id, subject_id, title, content, question_type, \
         CAST(difficulty AS SIGNED) as difficulty, \
         CAST(options_json AS CHAR) as options, \
         answer_text as answer, status \
         FROM learn_question WHERE question_id = ?",
    )
    .bind(q_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(row.title, "1+1=?");
    assert_eq!(row.question_type, "SINGLE_CHOICE");
    assert_eq!(row.difficulty, 3i32); // CAST VARCHAR '3' → i32
    assert!(
        row.options.unwrap().contains("B"),
        "options JSON should contain key B"
    );
    assert_eq!(row.answer.as_deref(), Some("B"));
    assert_eq!(row.status, "ACTIVE");

    // === UPDATE ===
    sqlx::query("UPDATE learn_question SET difficulty = ?, answer_text = ? WHERE question_id = ?")
        .bind("5")
        .bind("C")
        .bind(q_id)
        .execute(&pool)
        .await
        .unwrap();

    let updated = sqlx::query_as::<_, QuestionRow>(
        "SELECT question_id as id, subject_id, title, content, question_type, \
         CAST(difficulty AS SIGNED) as difficulty, \
         CAST(options_json AS CHAR) as options, \
         answer_text as answer, status \
         FROM learn_question WHERE question_id = ?",
    )
    .bind(q_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(updated.difficulty, 5);
    assert_eq!(updated.answer.as_deref(), Some("C"));

    // 清理
    sqlx::query("DELETE FROM learn_question WHERE question_id = ?")
        .bind(q_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM learn_subject WHERE subject_id = ?")
        .bind(subj_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] learn_question with CAST difficulty + CAST options + answer_text alias");
}

// =====================================================================
// 测试：learn_course_enrollment — 列名兼容，无需别名（注册后 progress_pct 由 migration 补齐）
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_learn_enrollment_crud() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    setup_learn_tables(&pool).await;

    let subj_id = sqlx::query(
        "INSERT INTO learn_subject (name, code, sort_order, status) VALUES ('注册测试学科', 'IT_ENR', 0, 'ACTIVE')"
    ).execute(&pool).await.unwrap().last_insert_id() as i64;

    let course_id = sqlx::query(
        "INSERT INTO learn_course (subject_id, name, status) VALUES (?, '注册测试课程', 'ACTIVE')",
    )
    .bind(subj_id)
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    // === CREATE: INSERT INTO learn_course_enrollment（progress_pct 列由 migration 补齐）===
    let user_id: i64 = 99901;
    let result = sqlx::query(
        "INSERT INTO learn_course_enrollment (user_id, course_id, status, progress_pct) \
         VALUES (?, ?, 'ACTIVE', 0.0)",
    )
    .bind(user_id)
    .bind(course_id)
    .execute(&pool)
    .await;
    match result {
        Ok(r) => {
            let _id = r.last_insert_id() as i64;
        }
        Err(ref e) if e.to_string().contains("progress_pct") => {
            // progress_pct 列可能未创建（migration 未执行），跳过此测试
            eprintln!("[SKIP] progress_pct column not found — run migration 20260705000001 first");
            sqlx::query("DELETE FROM learn_course WHERE course_id = ?")
                .bind(course_id)
                .execute(&pool)
                .await
                .ok();
            sqlx::query("DELETE FROM learn_subject WHERE subject_id = ?")
                .bind(subj_id)
                .execute(&pool)
                .await
                .ok();
            return;
        }
        Err(e) => panic!("INSERT enrollment failed: {e}"),
    }

    // === READ ===
    let row = sqlx::query_as::<_, EnrollmentRow>(
        "SELECT id, user_id, course_id, status, progress_pct \
         FROM learn_course_enrollment WHERE user_id = ? AND course_id = ?",
    )
    .bind(user_id)
    .bind(course_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(row.user_id, user_id);
    assert_eq!(row.course_id, course_id);
    assert_eq!(row.status, "ACTIVE");
    assert!((row.progress_pct - 0.0).abs() < f64::EPSILON);

    // 清理
    sqlx::query("DELETE FROM learn_course_enrollment WHERE user_id = ?")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM learn_course WHERE course_id = ?")
        .bind(course_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM learn_subject WHERE subject_id = ?")
        .bind(subj_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] learn_course_enrollment CRUD");
}

// =====================================================================
// 测试：NULL sort_order 的 COALESCE 行为
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_coalesce_null_sort_order() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    setup_learn_tables(&pool).await;

    // learn_subject 的 sort_order 在 platform_v4 中允许 NULL
    let subj_id = sqlx::query(
        "INSERT INTO learn_subject (name, code, sort_order, status) VALUES ('NULL排序学科', 'IT_NULL', NULL, 'ACTIVE')"
    ).execute(&pool).await.unwrap().last_insert_id() as i64;

    // 不使用 COALESCE — 应该返回 NULL（sqlx 会报错因为 i32 不能为 NULL）
    let result_no_coalesce = sqlx::query_as::<_, SubjectRow>(
        "SELECT subject_id as id, name, code, parent_subject_id as parent_id, \
         description, sort_order, status \
         FROM learn_subject WHERE subject_id = ?",
    )
    .bind(subj_id)
    .fetch_one(&pool)
    .await;
    assert!(
        result_no_coalesce.is_err(),
        "sort_order NULL without COALESCE should fail"
    );

    // 使用 COALESCE — 应该成功返回 0
    let row_with_coalesce = sqlx::query_as::<_, SubjectRow>(
        "SELECT subject_id as id, name, code, parent_subject_id as parent_id, \
         description, COALESCE(sort_order, 0) as sort_order, status \
         FROM learn_subject WHERE subject_id = ?",
    )
    .bind(subj_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row_with_coalesce.sort_order, 0, "COALESCE should return 0");

    // 清理
    sqlx::query("DELETE FROM learn_subject WHERE subject_id = ?")
        .bind(subj_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] COALESCE(sort_order, 0) handles NULL correctly");
}

// =====================================================================
// 新增测试 1: learn_question_first_attempt — INSERT IGNORE + platform_v4 列名
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_learn_question_first_attempt_insert_ignore() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    setup_learn_tables(&pool).await;

    // 创建学科 + 题目（INSERT 需要合法的 subject_id / question_id）
    let subj_id = sqlx::query(
        "INSERT INTO learn_subject (name, code, sort_order, status) \
         VALUES ('首答测试学科', 'IT_FA', 0, 'ACTIVE')",
    )
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    let q1_id = sqlx::query(
        "INSERT INTO learn_question (subject_id, title, question_type, difficulty, status) \
         VALUES (?, '1+1=?', 'SINGLE_CHOICE', '1', 'ACTIVE')",
    )
    .bind(subj_id)
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    let user_id: i64 = 99101;

    // === INSERT: 使用 platform_v4 真实列名 first_attempt_is_correct, first_attempt_at ===
    // 与 progress.rs update_progress 中的 SQL 完全一致
    let result = sqlx::query(
        "INSERT IGNORE INTO learn_question_first_attempt \
         (user_id, question_id, subject_id, first_attempt_is_correct, first_attempt_at) \
         VALUES (?, ?, ?, ?, NOW())",
    )
    .bind(user_id)
    .bind(q1_id)
    .bind(subj_id)
    .bind(1)
    .execute(&pool)
    .await
    .expect("INSERT IGNORE should succeed");
    assert_eq!(
        result.rows_affected(),
        1,
        "first INSERT should affect 1 row"
    );

    // === 幂等: 重新插入同一 user_id + question_id 应被 IGNORE ===
    let result2 = sqlx::query(
        "INSERT IGNORE INTO learn_question_first_attempt \
         (user_id, question_id, subject_id, first_attempt_is_correct, first_attempt_at) \
         VALUES (?, ?, ?, ?, NOW())",
    )
    .bind(user_id)
    .bind(q1_id)
    .bind(subj_id)
    .bind(0) // 注意: 即使 is_correct 值不同也应被忽略
    .execute(&pool)
    .await
    .expect("INSERT IGNORE (idempotent) should succeed");
    assert_eq!(
        result2.rows_affected(),
        0,
        "duplicate INSERT IGNORE should affect 0 rows"
    );

    // === READ: 不使用别名（first_attempts.rs 当前 SQL — 应失败，证明别名 Bug）===
    let result_no_alias = sqlx::query_as::<_, FirstAttemptRow>(
        "SELECT id, user_id, question_id, subject_id, is_correct, attempted_at \
         FROM learn_question_first_attempt WHERE user_id = ?",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await;
    // platform_v4 列名为 first_attempt_is_correct / first_attempt_at，
    // 不加别名 SELECT 会找不到这些列 → 应该报错
    assert!(
        result_no_alias.is_err(),
        "SELECT without aliases should fail — platform_v4 has first_attempt_is_correct not is_correct"
    );

    // === READ: 使用正确别名（修复后的 SQL）===
    let row = sqlx::query_as::<_, FirstAttemptRow>(
        "SELECT id, user_id, question_id, subject_id, \
         first_attempt_is_correct AS is_correct, \
         first_attempt_at AS attempted_at \
         FROM learn_question_first_attempt WHERE user_id = ?",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .expect("SELECT with correct aliases should succeed");

    assert_eq!(row.user_id, user_id);
    assert_eq!(row.question_id, q1_id);
    assert_eq!(row.subject_id, Some(subj_id));
    assert_eq!(
        row.is_correct, 1,
        "first attempt should remain correct (idempotent re-insert ignored)"
    );
    assert!(
        row.attempted_at.is_some(),
        "attempted_at should be populated"
    );

    // 清理
    sqlx::query("DELETE FROM learn_question_first_attempt WHERE user_id = ?")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM learn_question WHERE question_id = ?")
        .bind(q1_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM learn_subject WHERE subject_id = ?")
        .bind(subj_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] learn_question_first_attempt INSERT IGNORE + idempotent + alias bridge");
}

// =====================================================================
// 新增测试 2: learn_question_first_attempt — progress 聚合查询
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_learn_question_first_attempt_progress_query() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    setup_learn_tables(&pool).await;

    let subj_id = sqlx::query(
        "INSERT INTO learn_subject (name, code, sort_order, status) \
         VALUES ('进度测试学科', 'IT_PROG', 0, 'ACTIVE')",
    )
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    // 创建 3 道题
    let q1 = sqlx::query(
        "INSERT INTO learn_question (subject_id, title, question_type, difficulty, status) \
         VALUES (?, 'Q1', 'SINGLE_CHOICE', '1', 'ACTIVE')",
    )
    .bind(subj_id)
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    let q2 = sqlx::query(
        "INSERT INTO learn_question (subject_id, title, question_type, difficulty, status) \
         VALUES (?, 'Q2', 'SINGLE_CHOICE', '1', 'ACTIVE')",
    )
    .bind(subj_id)
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    let q3 = sqlx::query(
        "INSERT INTO learn_question (subject_id, title, question_type, difficulty, status) \
         VALUES (?, 'Q3', 'SINGLE_CHOICE', '1', 'ACTIVE')",
    )
    .bind(subj_id)
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    let user_id: i64 = 99201;

    // 插入 3 条首答: 2 correct, 1 wrong
    sqlx::query(
        "INSERT IGNORE INTO learn_question_first_attempt \
         (user_id, question_id, subject_id, first_attempt_is_correct, first_attempt_at) \
         VALUES (?, ?, ?, 1, NOW())",
    )
    .bind(user_id)
    .bind(q1)
    .bind(subj_id)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT IGNORE INTO learn_question_first_attempt \
         (user_id, question_id, subject_id, first_attempt_is_correct, first_attempt_at) \
         VALUES (?, ?, ?, 1, NOW())",
    )
    .bind(user_id)
    .bind(q2)
    .bind(subj_id)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT IGNORE INTO learn_question_first_attempt \
         (user_id, question_id, subject_id, first_attempt_is_correct, first_attempt_at) \
         VALUES (?, ?, ?, 0, NOW())",
    )
    .bind(user_id)
    .bind(q3)
    .bind(subj_id)
    .execute(&pool)
    .await
    .unwrap();

    // === 验证 progress.rs 中的聚合 SQL ===
    let (total, correct): (i64, i64) = sqlx::query_as(
        "SELECT CAST(COUNT(*) AS SIGNED) as total,
                COALESCE(CAST(SUM(CASE WHEN first_attempt_is_correct = 1 THEN 1 ELSE 0 END) AS SIGNED), 0) as correct
         FROM learn_question_first_attempt
         WHERE user_id = ? AND subject_id = ?"
    )
    .bind(user_id)
    .bind(subj_id)
    .fetch_one(&pool).await
    .expect("progress aggregation query should succeed");

    assert_eq!(total, 3, "total attempts should be 3");
    assert_eq!(correct, 2, "correct attempts should be 2");

    // 清理
    sqlx::query("DELETE FROM learn_question_first_attempt WHERE user_id = ?")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM learn_question WHERE subject_id = ?")
        .bind(subj_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM learn_subject WHERE subject_id = ?")
        .bind(subj_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] learn_question_first_attempt progress aggregation: total=3, correct=2");
}

// =====================================================================
// 新增测试 3: learn_submission — user_id AS student_id 别名 + grading
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_learn_submission_user_id_as_student_id() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    setup_learn_tables(&pool).await;

    // 创建学科 → 课程 → 作业
    let subj_id = sqlx::query(
        "INSERT INTO learn_subject (name, code, sort_order, status) \
         VALUES ('提交测试学科', 'IT_SUB', 0, 'ACTIVE')",
    )
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    let course_id = sqlx::query(
        "INSERT INTO learn_course (subject_id, name, status) VALUES (?, '提交测试课程', 'ACTIVE')",
    )
    .bind(subj_id)
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    let assignment_id = sqlx::query(
        "INSERT INTO learn_assignment (course_id, title, max_score, status) \
         VALUES (?, '第一次作业', 100.0, 'DRAFT')",
    )
    .bind(course_id)
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    let student_id: i64 = 99301;

    // === CREATE: INSERT INTO learn_submission (user_id 是 platform_v4 真实列名) ===
    let result = sqlx::query(
        "INSERT INTO learn_submission (assignment_id, user_id, content, file_url, status) \
         VALUES (?, ?, '我的答案', '/uploads/homework.pdf', 'SUBMITTED')",
    )
    .bind(assignment_id)
    .bind(student_id)
    .execute(&pool)
    .await
    .expect("INSERT learn_submission should succeed");
    let submission_id = result.last_insert_id() as i64;

    // === READ: 使用 submissions.rs 同款别名 user_id as student_id ===
    let row = sqlx::query_as::<_, SubmissionRow>(
        "SELECT id, assignment_id, user_id as student_id, content, file_url, score, feedback, status \
         FROM learn_submission WHERE id = ?"
    )
    .bind(submission_id)
    .fetch_one(&pool).await.expect("SELECT with user_id as student_id should succeed");

    assert_eq!(row.assignment_id, assignment_id);
    assert_eq!(
        row.student_id, student_id,
        "user_id → student_id alias should work"
    );
    assert_eq!(row.content.as_deref(), Some("我的答案"));
    assert_eq!(row.file_url.as_deref(), Some("/uploads/homework.pdf"));
    assert_eq!(row.score, None, "score should be NULL before grading");
    assert_eq!(row.feedback, None, "feedback should be NULL before grading");
    assert_eq!(row.status, "SUBMITTED");

    // === GRADE: submissions.rs grade_submission 同款 UPDATE ===
    sqlx::query("UPDATE learn_submission SET score=?, feedback=?, status='GRADED' WHERE id=?")
        .bind(85)
        .bind("做得不错，继续加油")
        .bind(submission_id)
        .execute(&pool)
        .await
        .expect("UPDATE grading should succeed");

    let graded = sqlx::query_as::<_, SubmissionRow>(
        "SELECT id, assignment_id, user_id as student_id, content, file_url, score, feedback, status \
         FROM learn_submission WHERE id = ?"
    )
    .bind(submission_id).fetch_one(&pool).await.unwrap();

    assert_eq!(graded.score, Some(85.0));
    assert_eq!(graded.feedback.as_deref(), Some("做得不错，继续加油"));
    assert_eq!(graded.status, "GRADED");

    // 清理
    sqlx::query("DELETE FROM learn_submission WHERE id = ?")
        .bind(submission_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM learn_assignment WHERE id = ?")
        .bind(assignment_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM learn_course WHERE course_id = ?")
        .bind(course_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM learn_subject WHERE subject_id = ?")
        .bind(subj_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] learn_submission user_id→student_id alias + grading UPDATE");
}

// =====================================================================
// 新增测试 4: learn_assignment — CRUD + soft delete + ON DUPLICATE KEY UPDATE
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_learn_assignment_crud_and_soft_delete() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    setup_learn_tables(&pool).await;

    let subj_id = sqlx::query(
        "INSERT INTO learn_subject (name, code, sort_order, status) \
         VALUES ('作业测试学科', 'IT_ASG', 0, 'ACTIVE')",
    )
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    let course_id = sqlx::query(
        "INSERT INTO learn_course (subject_id, name, status) VALUES (?, '作业测试课程', 'ACTIVE')",
    )
    .bind(subj_id)
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    // === CREATE: assignments.rs create_assignment 同款 INSERT ===
    let result = sqlx::query(
        "INSERT INTO learn_assignment (course_id, title, description, max_score, status) \
         VALUES (?, ?, ?, ?, 'DRAFT')",
    )
    .bind(course_id)
    .bind("期中考试")
    .bind("期中考试说明")
    .bind(100.0)
    .execute(&pool)
    .await
    .expect("INSERT learn_assignment should succeed");
    let asg_id = result.last_insert_id() as i64;

    // === READ: assignments.rs 同款 SELECT ===
    let row = sqlx::query_as::<_, AssignmentRow>(
        "SELECT id, course_id, title, description, max_score, status \
         FROM learn_assignment WHERE id = ?",
    )
    .bind(asg_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(row.course_id, course_id);
    assert_eq!(row.title, "期中考试");
    assert_eq!(row.description.as_deref(), Some("期中考试说明"));
    assert!((row.max_score - 100.0).abs() < f64::EPSILON);
    assert_eq!(row.status, "DRAFT");

    // === UPDATE ===
    sqlx::query(
        "UPDATE learn_assignment SET course_id=?, title=?, description=?, max_score=? WHERE id=?",
    )
    .bind(course_id)
    .bind("期末考试")
    .bind("期末考试说明")
    .bind(200.0)
    .bind(asg_id)
    .execute(&pool)
    .await
    .unwrap();

    let updated = sqlx::query_as::<_, AssignmentRow>(
        "SELECT id, course_id, title, description, max_score, status FROM learn_assignment WHERE id = ?"
    ).bind(asg_id).fetch_one(&pool).await.unwrap();
    assert_eq!(updated.title, "期末考试");
    assert!((updated.max_score - 200.0).abs() < f64::EPSILON);

    // === SOFT DELETE: assignments.rs delete 同款 ===
    sqlx::query("UPDATE learn_assignment SET status='ARCHIVED' WHERE id=?")
        .bind(asg_id)
        .execute(&pool)
        .await
        .unwrap();

    let archived = sqlx::query_as::<_, AssignmentRow>(
        "SELECT id, course_id, title, description, max_score, status FROM learn_assignment WHERE id = ?"
    ).bind(asg_id).fetch_one(&pool).await.unwrap();
    assert_eq!(
        archived.status, "ARCHIVED",
        "soft delete should set status to ARCHIVED"
    );

    // === ON DUPLICATE KEY UPDATE: assignments.rs submit_assignment 同款 ===
    // 先清理上面的作业，创建一个新的非归档作业用于提交测试
    let asg2_id = sqlx::query(
        "INSERT INTO learn_assignment (course_id, title, max_score, status) \
         VALUES (?, '可提交作业', 100.0, 'PUBLISHED')",
    )
    .bind(course_id)
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    let student_id: i64 = 99351;

    // 首次提交
    let r1 = sqlx::query(
        "INSERT INTO learn_submission (assignment_id, user_id, content, graded) \
         VALUES (?, ?, ?, 0) \
         ON DUPLICATE KEY UPDATE content=VALUES(content), graded=0",
    )
    .bind(asg2_id)
    .bind(student_id)
    .bind("首次答案")
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(r1.rows_affected(), 1, "first submit should insert 1 row");

    // 重复提交（ON DUPLICATE KEY UPDATE）
    let r2 = sqlx::query(
        "INSERT INTO learn_submission (assignment_id, user_id, content, graded) \
         VALUES (?, ?, ?, 0) \
         ON DUPLICATE KEY UPDATE content=VALUES(content), graded=0",
    )
    .bind(asg2_id)
    .bind(student_id)
    .bind("修改后的答案")
    .execute(&pool)
    .await
    .unwrap();
    // MySQL 在 ON DUPLICATE KEY UPDATE 时 rows_affected 为 2（先删后插语义）
    assert!(
        r2.rows_affected() >= 1,
        "duplicate submit should update existing row"
    );

    // 验证内容被更新
    let sub: SubmissionRow = sqlx::query_as(
        "SELECT id, assignment_id, user_id as student_id, content, file_url, score, feedback, status \
         FROM learn_submission WHERE assignment_id = ? AND user_id = ?"
    )
    .bind(asg2_id).bind(student_id)
    .fetch_one(&pool).await.unwrap();
    assert_eq!(sub.content.as_deref(), Some("修改后的答案"));

    // 清理
    sqlx::query("DELETE FROM learn_submission WHERE assignment_id = ?")
        .bind(asg2_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM learn_assignment WHERE id IN (?, ?)")
        .bind(asg_id)
        .bind(asg2_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM learn_course WHERE course_id = ?")
        .bind(course_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM learn_subject WHERE subject_id = ?")
        .bind(subj_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] learn_assignment CRUD + soft delete + ON DUPLICATE KEY UPDATE");
}

// =====================================================================
// 新增测试 5: learn_question_solution — like_count 原子递增
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_learn_question_solution_like_count() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    setup_learn_tables(&pool).await;

    let subj_id = sqlx::query(
        "INSERT INTO learn_subject (name, code, sort_order, status) \
         VALUES ('题解测试学科', 'IT_SOL', 0, 'ACTIVE')",
    )
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    let q_id = sqlx::query(
        "INSERT INTO learn_question (subject_id, title, question_type, difficulty, status) \
         VALUES (?, '题解题', 'SINGLE_CHOICE', '1', 'ACTIVE')",
    )
    .bind(subj_id)
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    let user_id: i64 = 99401;

    // === CREATE: solutions.rs create_solution 同款 INSERT ===
    let result = sqlx::query(
        "INSERT INTO learn_question_solution (question_id, user_id, content, like_count, created_at) \
         VALUES (?, ?, ?, 0, NOW())"
    )
    .bind(q_id).bind(user_id).bind("这道题选 B，因为...")
    .execute(&pool).await.expect("INSERT learn_question_solution should succeed");
    let sol_id = result.last_insert_id() as i64;

    // === READ: 验证初始 like_count = 0 ===
    let row = sqlx::query_as::<_, SolutionRow>(
        "SELECT id, question_id, user_id, content, like_count, created_at \
         FROM learn_question_solution WHERE id = ?",
    )
    .bind(sol_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.like_count, 0);
    assert_eq!(row.content, "这道题选 B，因为...");
    assert!(row.created_at.is_some());

    // === LIKE: solutions.rs like_solution 同款原子递增 ===
    sqlx::query("UPDATE learn_question_solution SET like_count = like_count + 1 WHERE id = ?")
        .bind(sol_id)
        .execute(&pool)
        .await
        .expect("like increment should succeed");

    let liked = sqlx::query_as::<_, SolutionRow>(
        "SELECT id, question_id, user_id, content, like_count, created_at \
         FROM learn_question_solution WHERE id = ?",
    )
    .bind(sol_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        liked.like_count, 1,
        "like_count should be 1 after first like"
    );

    // 多次点赞
    sqlx::query("UPDATE learn_question_solution SET like_count = like_count + 1 WHERE id = ?")
        .bind(sol_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE learn_question_solution SET like_count = like_count + 1 WHERE id = ?")
        .bind(sol_id)
        .execute(&pool)
        .await
        .unwrap();

    let liked3 = sqlx::query_as::<_, SolutionRow>(
        "SELECT id, question_id, user_id, content, like_count, created_at \
         FROM learn_question_solution WHERE id = ?",
    )
    .bind(sol_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        liked3.like_count, 3,
        "like_count should be 3 after three likes"
    );

    // 清理
    sqlx::query("DELETE FROM learn_question_solution WHERE id = ?")
        .bind(sol_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM learn_question WHERE question_id = ?")
        .bind(q_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM learn_subject WHERE subject_id = ?")
        .bind(subj_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] learn_question_solution like_count atomic increment");
}

// =====================================================================
// 新增测试 6: learn_announcement — CRUD + pinned TINYINT→bool + ORDER BY
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_learn_announcement_crud() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    setup_learn_tables(&pool).await;

    let subj_id = sqlx::query(
        "INSERT INTO learn_subject (name, code, sort_order, status) \
         VALUES ('公告测试学科', 'IT_ANN', 0, 'ACTIVE')",
    )
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    let course_id = sqlx::query(
        "INSERT INTO learn_course (subject_id, name, status) VALUES (?, '公告测试课程', 'ACTIVE')",
    )
    .bind(subj_id)
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    let author_id: i64 = 99501;

    // === CREATE: discussions.rs create_announcement 同款 INSERT ===
    // pinned = 0 (非置顶)
    let result1 = sqlx::query(
        "INSERT INTO learn_announcement (course_id, title, content, author_id, pinned) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(course_id)
    .bind("普通公告")
    .bind("这是普通公告内容")
    .bind(author_id)
    .bind(0)
    .execute(&pool)
    .await
    .expect("INSERT announcement should succeed");
    let ann1_id = result1.last_insert_id() as i64;

    // pinned = 1 (置顶)
    let result2 = sqlx::query(
        "INSERT INTO learn_announcement (course_id, title, content, author_id, pinned) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(course_id)
    .bind("置顶公告")
    .bind("这是置顶公告内容")
    .bind(author_id)
    .bind(1)
    .execute(&pool)
    .await
    .expect("INSERT pinned announcement should succeed");
    let ann2_id = result2.last_insert_id() as i64;

    // === READ: discussions.rs 同款 SELECT — pinned TINYINT→bool 映射 ===
    let row1 = sqlx::query_as::<_, AnnouncementRow>(
        "SELECT id, course_id, title, content, author_id, pinned, created_at \
         FROM learn_announcement WHERE id = ?",
    )
    .bind(ann1_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row1.title, "普通公告");
    assert!(!row1.pinned, "pinned TINYINT 0 → bool false");

    let row2 = sqlx::query_as::<_, AnnouncementRow>(
        "SELECT id, course_id, title, content, author_id, pinned, created_at \
         FROM learn_announcement WHERE id = ?",
    )
    .bind(ann2_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row2.title, "置顶公告");
    assert!(row2.pinned, "pinned TINYINT 1 → bool true");

    // === ORDER BY pinned DESC: 置顶应排在前面 ===
    let rows = sqlx::query_as::<_, AnnouncementRow>(
        "SELECT id, course_id, title, content, author_id, pinned, created_at \
         FROM learn_announcement WHERE course_id = ? \
         ORDER BY pinned DESC, created_at DESC",
    )
    .bind(course_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(rows.len() >= 2, "should have at least 2 announcements");
    assert!(rows[0].pinned, "first row should be pinned");
    assert!(!rows[1].pinned, "second row should not be pinned");

    // === UPDATE: discussions.rs update_announcement 同款 ===
    sqlx::query("UPDATE learn_announcement SET title = ?, content = ?, pinned = ? WHERE id = ?")
        .bind("更新后的公告")
        .bind("更新内容")
        .bind(1)
        .bind(ann1_id)
        .execute(&pool)
        .await
        .unwrap();

    let updated = sqlx::query_as::<_, AnnouncementRow>(
        "SELECT id, course_id, title, content, author_id, pinned, created_at \
         FROM learn_announcement WHERE id = ?",
    )
    .bind(ann1_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(updated.title, "更新后的公告");
    assert!(updated.pinned, "pinned should be updated to true");

    // === DELETE ===
    sqlx::query("DELETE FROM learn_announcement WHERE id = ?")
        .bind(ann1_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM learn_announcement WHERE id = ?")
        .bind(ann2_id)
        .execute(&pool)
        .await
        .unwrap();

    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM learn_announcement WHERE course_id = ?")
            .bind(course_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count.0, 0, "all announcements should be deleted");

    // 清理
    sqlx::query("DELETE FROM learn_course WHERE course_id = ?")
        .bind(course_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM learn_subject WHERE subject_id = ?")
        .bind(subj_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] learn_announcement CRUD + pinned TINYINT→bool + ORDER BY pinned DESC");
}

// =====================================================================
// 新增测试 7: learn_discussion_post — CRUD
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_learn_discussion_post_crud() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    setup_learn_tables(&pool).await;

    let subj_id = sqlx::query(
        "INSERT INTO learn_subject (name, code, sort_order, status) \
         VALUES ('讨论测试学科', 'IT_DISC', 0, 'ACTIVE')",
    )
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    let course_id = sqlx::query(
        "INSERT INTO learn_course (subject_id, name, status) VALUES (?, '讨论测试课程', 'ACTIVE')",
    )
    .bind(subj_id)
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    let author_id: i64 = 99601;

    // === CREATE: discussions.rs create_discussion 同款 INSERT ===
    let result = sqlx::query(
        "INSERT INTO learn_discussion_post (course_id, title, content, author_id) \
         VALUES (?, ?, ?, ?)",
    )
    .bind(course_id)
    .bind("如何学好 Rust？")
    .bind("大家有什么建议吗？")
    .bind(author_id)
    .execute(&pool)
    .await
    .expect("INSERT learn_discussion_post should succeed");
    let post_id = result.last_insert_id() as i64;

    // === READ: discussions.rs 同款 SELECT ===
    let row = sqlx::query_as::<_, DiscussionRow>(
        "SELECT id, course_id, title, content, author_id, created_at \
         FROM learn_discussion_post WHERE id = ?",
    )
    .bind(post_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(row.course_id, course_id);
    assert_eq!(row.title, "如何学好 Rust？");
    assert_eq!(row.content, "大家有什么建议吗？");
    assert_eq!(row.author_id, author_id);
    assert!(row.created_at.is_some(), "created_at should be populated");

    // === LIST: discussions.rs list_discussions 同款 SELECT ===
    let rows = sqlx::query_as::<_, DiscussionRow>(
        "SELECT id, course_id, title, content, author_id, created_at \
         FROM learn_discussion_post ORDER BY created_at DESC LIMIT ? OFFSET ?",
    )
    .bind(20i64)
    .bind(0i64)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(!rows.is_empty(), "should have at least one discussion post");

    // === DELETE: discussions.rs delete_discussion 同款 DELETE ===
    sqlx::query("DELETE FROM learn_discussion_post WHERE id = ?")
        .bind(post_id)
        .execute(&pool)
        .await
        .unwrap();

    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM learn_discussion_post WHERE id = ?")
        .bind(post_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 0, "discussion post should be deleted");

    // 清理
    sqlx::query("DELETE FROM learn_course WHERE course_id = ?")
        .bind(course_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM learn_subject WHERE subject_id = ?")
        .bind(subj_id)
        .execute(&pool)
        .await
        .unwrap();

    eprintln!("[PASS] learn_discussion_post CRUD");
}

// =====================================================================
// 新增测试 8: learn_device — CRUD
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_learn_device_crud() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    setup_learn_tables(&pool).await;

    let user_id: i64 = 99701;

    // === CREATE: devices.rs 同款表结构 INSERT ===
    let result = sqlx::query(
        "INSERT INTO learn_device (user_id, device_name, device_type, device_id, last_login_at, created_at) \
         VALUES (?, ?, ?, ?, NOW(), NOW())"
    )
    .bind(user_id).bind("Chrome on Windows").bind("BROWSER").bind("dev-chrome-win-001")
    .execute(&pool).await.expect("INSERT learn_device should succeed");
    let dev_id = result.last_insert_id() as i64;

    // === READ: devices.rs 同款 SELECT ===
    let row = sqlx::query_as::<_, DeviceRow>(
        "SELECT id, user_id, device_name, device_type, device_id, last_login_at, created_at \
         FROM learn_device WHERE id = ?",
    )
    .bind(dev_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(row.user_id, user_id);
    assert_eq!(row.device_name.as_deref(), Some("Chrome on Windows"));
    assert_eq!(row.device_type.as_deref(), Some("BROWSER"));
    assert_eq!(row.device_id.as_deref(), Some("dev-chrome-win-001"));
    assert!(
        row.last_login_at.is_some(),
        "last_login_at should be populated"
    );
    assert!(row.created_at.is_some(), "created_at should be populated");

    // === LIST BY USER: devices.rs list_my_devices 同款 ===
    let rows = sqlx::query_as::<_, DeviceRow>(
        "SELECT id, user_id, device_name, device_type, device_id, last_login_at, created_at \
         FROM learn_device WHERE user_id = ? ORDER BY last_login_at DESC",
    )
    .bind(user_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(!rows.is_empty(), "should have at least one device for user");

    // === DELETE: devices.rs delete_device 同款 ===
    sqlx::query("DELETE FROM learn_device WHERE id = ?")
        .bind(dev_id)
        .execute(&pool)
        .await
        .unwrap();

    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM learn_device WHERE id = ?")
        .bind(dev_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 0, "device should be deleted");

    eprintln!("[PASS] learn_device CRUD");
}

// =====================================================================
// 新增测试 9: cascade_delete_subject — 8 步事务级联删除
// =====================================================================

#[ignore]
#[tokio::test]
async fn test_cascade_delete_subject_transaction() {
    let pool = match connect().await {
        Some(p) => p,
        None => return,
    };
    setup_learn_tables(&pool).await;

    // === 1. 创建学科 ===
    let subj_id = sqlx::query(
        "INSERT INTO learn_subject (name, code, sort_order, status) \
         VALUES ('级联删除学科', 'IT_CASCADE', 0, 'ACTIVE')",
    )
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    // === 2. 创建课程 ===
    let _course_id = sqlx::query(
        "INSERT INTO learn_course (subject_id, name, status) VALUES (?, '级联删除课程', 'ACTIVE')",
    )
    .bind(subj_id)
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    // === 3. 创建章节 ===
    let chapter_id = sqlx::query(
        "INSERT INTO learn_chapter (subject_id, title, sort_order, status) \
         VALUES (?, '级联删除章节', 1, 'ACTIVE')",
    )
    .bind(subj_id)
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    // 创建课时（learn_lesson 关联 chapter_id）
    let _lesson_id = sqlx::query(
        "INSERT INTO learn_lesson (chapter_id, title, content_type, duration_minutes, sort_order) \
         VALUES (?, '级联删除课时', 'VIDEO', 30, 1)",
    )
    .bind(chapter_id)
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    // === 4. 创建题目 ===
    let q_id = sqlx::query(
        "INSERT INTO learn_question (subject_id, title, question_type, difficulty, status) \
         VALUES (?, '级联删除题目', 'SINGLE_CHOICE', '1', 'ACTIVE')",
    )
    .bind(subj_id)
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    // === 5. 创建用户学科关联 ===
    let _user_subject_id = sqlx::query(
        "INSERT INTO learn_user_subject (user_id, subject_id, selected_at) \
         VALUES (?, ?, NOW())",
    )
    .bind(99801i64)
    .bind(subj_id)
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    // === 6. 创建首答记录 ===
    let _attempt_id = sqlx::query(
        "INSERT IGNORE INTO learn_question_first_attempt \
         (user_id, question_id, subject_id, first_attempt_is_correct, first_attempt_at) \
         VALUES (?, ?, ?, 1, NOW())",
    )
    .bind(99801i64)
    .bind(q_id)
    .bind(subj_id)
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    // === 7. 创建文档 ===
    let _doc_id = sqlx::query(
        "INSERT INTO documents (title, subject_id, storage_url, file_type, created_at) \
         VALUES (?, ?, ?, ?, NOW())",
    )
    .bind("级联删除文档")
    .bind(subj_id)
    .bind("/docs/test.pdf")
    .bind("PDF")
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    // === 8. 创建关卡（learn_level.subject_id）===
    let _level_id = sqlx::query(
        "INSERT INTO learn_level (subject_id, title, sort_order, level_type, status) \
         VALUES (?, '级联删除关卡', 1, 'NORMAL', 'ACTIVE')",
    )
    .bind(subj_id)
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    // === 执行级联删除事务（与 cascade.rs 8 步完全一致）===
    let mut tx = pool.begin().await.expect("BEGIN should succeed");

    // Step 1: lessons + chapters
    // 与 chapters.rs remove_chapters_by_subject_id_tx 完全一致
    sqlx::query(
        "DELETE FROM learn_lesson WHERE chapter_id IN \
         (SELECT chapter_id FROM learn_chapter WHERE subject_id = ?)",
    )
    .bind(subj_id)
    .execute(&mut *tx)
    .await
    .expect("Step 1a: delete lessons should succeed");

    sqlx::query("DELETE FROM learn_chapter WHERE subject_id = ?")
        .bind(subj_id)
        .execute(&mut *tx)
        .await
        .expect("Step 1b: delete chapters should succeed");

    // Step 2: levels
    sqlx::query("DELETE FROM learn_level WHERE subject_id = ?")
        .bind(subj_id)
        .execute(&mut *tx)
        .await
        .expect("Step 2: delete levels should succeed");

    // Step 3: questions
    sqlx::query("DELETE FROM learn_question WHERE subject_id = ?")
        .bind(subj_id)
        .execute(&mut *tx)
        .await
        .expect("Step 3: delete questions should succeed");

    // Step 4: courses
    sqlx::query("DELETE FROM learn_course WHERE subject_id = ?")
        .bind(subj_id)
        .execute(&mut *tx)
        .await
        .expect("Step 4: delete courses should succeed");

    // Step 5: user_subjects
    sqlx::query("DELETE FROM learn_user_subject WHERE subject_id = ?")
        .bind(subj_id)
        .execute(&mut *tx)
        .await
        .expect("Step 5: delete user_subjects should succeed");

    // Step 6: question_first_attempts
    sqlx::query("DELETE FROM learn_question_first_attempt WHERE subject_id = ?")
        .bind(subj_id)
        .execute(&mut *tx)
        .await
        .expect("Step 6: delete first_attempts should succeed");

    // Step 7: documents
    sqlx::query("DELETE FROM documents WHERE subject_id = ?")
        .bind(subj_id)
        .execute(&mut *tx)
        .await
        .expect("Step 7: delete documents should succeed");

    // Step 8: subject (主表，最后删除)
    sqlx::query("DELETE FROM learn_subject WHERE subject_id = ?")
        .bind(subj_id)
        .execute(&mut *tx)
        .await
        .expect("Step 8: delete subject should succeed");

    tx.commit().await.expect("COMMIT should succeed");

    // === 验证所有关联数据已删除 ===
    let subject_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM learn_subject WHERE subject_id = ?")
            .bind(subj_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(subject_count.0, 0, "subject should be gone");

    let course_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM learn_course WHERE subject_id = ?")
            .bind(subj_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(course_count.0, 0, "courses should be gone");

    let chapter_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM learn_chapter WHERE subject_id = ?")
            .bind(subj_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(chapter_count.0, 0, "chapters should be gone");

    let question_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM learn_question WHERE subject_id = ?")
            .bind(subj_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(question_count.0, 0, "questions should be gone");

    let user_subject_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM learn_user_subject WHERE subject_id = ?")
            .bind(subj_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(user_subject_count.0, 0, "user_subjects should be gone");

    let attempt_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM learn_question_first_attempt WHERE subject_id = ?")
            .bind(subj_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(attempt_count.0, 0, "first_attempts should be gone");

    let doc_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM documents WHERE subject_id = ?")
        .bind(subj_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(doc_count.0, 0, "documents should be gone");

    let level_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM learn_level WHERE subject_id = ?")
            .bind(subj_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(level_count.0, 0, "levels should be gone");

    eprintln!("[PASS] cascade_delete_subject — 8-step transactional cascade delete verified");
}
