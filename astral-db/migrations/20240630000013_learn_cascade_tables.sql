-- 学科级联删除关联表（对齐 Java learn_level, learn_user_subject, learn_question_first_attempt, documents）

-- 关卡表
CREATE TABLE IF NOT EXISTS learn_level (
    level_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    subject_id BIGINT NOT NULL,
    chapter_id BIGINT,
    domain_id BIGINT,
    tenant_id BIGINT,
    code VARCHAR(128),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    level_type VARCHAR(32) DEFAULT 'PRACTICE',
    difficulty VARCHAR(32) DEFAULT 'MEDIUM',
    question_count INT DEFAULT 0,
    time_limit_minutes INT,
    points INT DEFAULT 0,
    is_locked TINYINT DEFAULT 0,
    status VARCHAR(32) DEFAULT 'ACTIVE',
    sort_order INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_level_subject (subject_id),
    INDEX idx_level_chapter (chapter_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 用户学科关联
CREATE TABLE IF NOT EXISTS learn_user_subject (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    subject_id BIGINT NOT NULL,
    domain_id BIGINT,
    tenant_id BIGINT,
    status VARCHAR(32) DEFAULT 'ENROLLED',
    enrolled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_us_subject (subject_id),
    INDEX idx_us_user (user_id),
    UNIQUE KEY uk_user_subject (user_id, subject_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 首答记录
CREATE TABLE IF NOT EXISTS learn_question_first_attempt (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    question_id BIGINT NOT NULL,
    subject_id BIGINT NOT NULL,
    is_correct TINYINT DEFAULT 0,
    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_qfa_subject (subject_id),
    UNIQUE KEY uk_user_question (user_id, question_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 文档资源表
CREATE TABLE IF NOT EXISTS documents (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    subject_id BIGINT NOT NULL,
    title VARCHAR(255) NOT NULL,
    file_url VARCHAR(512),
    file_type VARCHAR(32) DEFAULT 'PDF',
    file_size BIGINT DEFAULT 0,
    status VARCHAR(32) DEFAULT 'ACTIVE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_doc_subject (subject_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
