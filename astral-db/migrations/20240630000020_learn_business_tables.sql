-- Phase 19: Learn 业务扩展表
-- 关卡、学校、签到、文档、题解、错题本、用户答题、设备、系统配置、Webhook、App用户

-- 关卡
CREATE TABLE IF NOT EXISTS learn_level (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    subject_id BIGINT NOT NULL,
    name VARCHAR(255) NOT NULL,
    sequence INT NOT NULL DEFAULT 0,
    level_type VARCHAR(32) NOT NULL DEFAULT 'NORMAL',
    config_json TEXT,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_learn_level_subject (subject_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 关卡状态（用户游戏记录）
CREATE TABLE IF NOT EXISTS learn_level_status (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    level_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'IN_PROGRESS',
    score INT,
    started_at TIMESTAMP NULL,
    finished_at TIMESTAMP NULL,
    INDEX idx_level_status_level (level_id),
    INDEX idx_level_status_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 关卡题目关联
CREATE TABLE IF NOT EXISTS learn_level_questions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    level_id BIGINT NOT NULL,
    question_id BIGINT NOT NULL,
    sequence INT NOT NULL DEFAULT 0,
    INDEX idx_level_questions_level (level_id),
    UNIQUE KEY uk_level_question (level_id, question_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 学校
CREATE TABLE IF NOT EXISTS school (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    code VARCHAR(128),
    address VARCHAR(512),
    contact_phone VARCHAR(32),
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_school_code (code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 学校成员
CREATE TABLE IF NOT EXISTS school_member (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    school_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'STUDENT',
    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_school_member_school (school_id),
    INDEX idx_school_member_user (user_id),
    UNIQUE KEY uk_school_member (school_id, user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 签到
CREATE TABLE IF NOT EXISTS learn_checkin (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    checkin_date DATE NOT NULL,
    reward_points INT NOT NULL DEFAULT 10,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_checkin_user (user_id),
    UNIQUE KEY uk_checkin_user_date (user_id, checkin_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 文档
CREATE TABLE IF NOT EXISTS documents (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    subject_id BIGINT,
    file_url VARCHAR(512),
    file_type VARCHAR(32),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_documents_subject (subject_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 题解
CREATE TABLE IF NOT EXISTS question_solution (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    question_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    content TEXT NOT NULL,
    like_count INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_solution_question (question_id),
    INDEX idx_solution_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 错题本
CREATE TABLE IF NOT EXISTS wrong_question (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    question_id BIGINT NOT NULL,
    subject_id BIGINT,
    status VARCHAR(32) NOT NULL DEFAULT 'UNREVIEWED',
    reviewed_at TIMESTAMP NULL,
    mastered_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_wrong_question_user (user_id),
    INDEX idx_wrong_question_subject (subject_id),
    INDEX idx_wrong_question_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 用户答题记录
CREATE TABLE IF NOT EXISTS user_answer (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    question_id BIGINT NOT NULL,
    answer TEXT,
    is_correct TINYINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_answer_user (user_id),
    INDEX idx_user_answer_question (question_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 设备
CREATE TABLE IF NOT EXISTS device (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    device_name VARCHAR(255),
    device_type VARCHAR(32),
    device_id VARCHAR(255),
    last_login_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_device_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 系统配置
CREATE TABLE IF NOT EXISTS learn_system_setting (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    setting_key VARCHAR(128) NOT NULL,
    setting_value TEXT,
    description VARCHAR(512),
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_setting_key (setting_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Webhook配置
CREATE TABLE IF NOT EXISTS webhook_config (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    url VARCHAR(512) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    secret VARCHAR(255),
    is_active TINYINT NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_webhook_event_type (event_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- App用户（简化版，供 App 端登录使用）
CREATE TABLE IF NOT EXISTS app_user (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    phone VARCHAR(32),
    nickname VARCHAR(128),
    avatar_url VARCHAR(512),
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_app_user_phone (phone)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
