-- Rust 后端 Schema 对齐 platform_v4 — 补齐 learn 模块缺失表
--
-- platform_v4 已存在：learn_chapter, learn_course, learn_question, learn_question_solution,
-- learn_question_first_attempt, learn_user_subject, learn_subject, learn_course_enrollment
--
-- 本 migration 创建 Rust 代码引用但 platform_v4 缺失的 6 张表 + 1 列补丁：
-- learn_lesson, learn_assignment, learn_submission, learn_device,
-- learn_announcement, learn_discussion_post
-- 并为 learn_course_enrollment 补齐 progress_pct 列（publishing.rs 引用）

-- 课时表（替代旧 lesson 表）
CREATE TABLE IF NOT EXISTS learn_lesson (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    chapter_id BIGINT NOT NULL,
    title VARCHAR(255) NOT NULL,
    content_type VARCHAR(32) NOT NULL DEFAULT 'VIDEO',
    content_url VARCHAR(512),
    duration_minutes INT NOT NULL DEFAULT 0,
    sort_order INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_learn_lesson_chapter (chapter_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='课时表（Rust 后端）';

-- 作业表（替代旧 assignment 表）
CREATE TABLE IF NOT EXISTS learn_assignment (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    course_id BIGINT NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    due_date TIMESTAMP NULL,
    max_score DOUBLE NOT NULL DEFAULT 100,
    status VARCHAR(32) NOT NULL DEFAULT 'DRAFT',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_learn_assignment_course (course_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='作业表（Rust 后端）';

-- 作业提交表（替代旧 submission 表）
CREATE TABLE IF NOT EXISTS learn_submission (
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='作业提交表（Rust 后端）';

-- 设备表（替代旧 device 表）
CREATE TABLE IF NOT EXISTS learn_device (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    device_name VARCHAR(255),
    device_type VARCHAR(32),
    device_id VARCHAR(255),
    last_login_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_learn_device_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='学习设备表（Rust 后端）';

-- 公告表（替代旧 announcement 表）
CREATE TABLE IF NOT EXISTS learn_announcement (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    course_id BIGINT NOT NULL,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    author_id BIGINT NOT NULL,
    pinned TINYINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_learn_announcement_course (course_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='课程公告表（Rust 后端）';

-- 讨论帖表（替代旧 discussion_post 表）
CREATE TABLE IF NOT EXISTS learn_discussion_post (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    course_id BIGINT NOT NULL,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    author_id BIGINT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_learn_discussion_post_course (course_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='课程讨论帖表（Rust 后端）';

-- 为 learn_course_enrollment 补齐 progress_pct 列（publishing.rs 引用）
-- platform_v4 原表无此列，Rust 后端 publishing.rs 需要它来计算课程进度
SET @col_exists = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'learn_course_enrollment'
    AND COLUMN_NAME = 'progress_pct');
SET @ddl = IF(@col_exists = 0,
    'ALTER TABLE learn_course_enrollment ADD COLUMN progress_pct DOUBLE NOT NULL DEFAULT 0',
    'SELECT 1');
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
