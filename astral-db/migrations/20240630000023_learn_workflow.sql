-- Phase 3b: 学习进度 + 课程发布 + 讨论区表
--
-- 为 progress/publishing/discussions 三个 stub 文件提供真实 DB 表

-- 学习进度表
CREATE TABLE IF NOT EXISTS subject_progress (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    subject_id BIGINT NOT NULL,
    total_questions INT NOT NULL DEFAULT 0,
    completed_questions INT NOT NULL DEFAULT 0,
    accuracy DOUBLE NOT NULL DEFAULT 0.0,
    streak_days INT NOT NULL DEFAULT 0,
    last_activity_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_sp_user (user_id),
    INDEX idx_sp_subject (subject_id),
    UNIQUE KEY uk_user_subject (user_id, subject_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 课程发布工作流（将 course 表的 publish 元信息抽离）
CREATE TABLE IF NOT EXISTS course_workflow (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    course_id BIGINT NOT NULL UNIQUE,
    reviewer_id BIGINT,
    review_comment TEXT,
    published_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_cw_course (course_id),
    INDEX idx_cw_reviewer (reviewer_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 课程公告表
CREATE TABLE IF NOT EXISTS announcement (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    course_id BIGINT NOT NULL,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    author_id BIGINT NOT NULL,
    pinned TINYINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_ann_course (course_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 讨论帖表
CREATE TABLE IF NOT EXISTS discussion_post (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    course_id BIGINT NOT NULL,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    author_id BIGINT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_dp_course (course_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
