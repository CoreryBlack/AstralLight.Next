-- AstralLight Database Baseline
-- 创建时间: 2026-06-30
-- 对应 Java MySQL schema，使用 sqlx migrate 管理

-- ===== 权限系统核心表 =====

-- 规则集容器（共享，不绑定 card_id）
CREATE TABLE IF NOT EXISTS rule_set (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    ref_type VARCHAR(32) NOT NULL DEFAULT 'BASE',
    description TEXT,
    is_active TINYINT NOT NULL DEFAULT 1,
    version BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_rule_set_ref_type (ref_type),
    INDEX idx_rule_set_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 规则集条目
CREATE TABLE IF NOT EXISTS rule_set_entry (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    rule_set_id BIGINT NOT NULL,
    effect VARCHAR(16) NOT NULL DEFAULT 'ALLOW',
    resource VARCHAR(256),
    action VARCHAR(64),
    condition_json TEXT,
    priority INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (rule_set_id) REFERENCES rule_set(id) ON DELETE CASCADE,
    INDEX idx_rse_rule_set (rule_set_id),
    INDEX idx_rse_priority (rule_set_id, priority)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 规则集快照（替代 permission_rule_snapshot 的主职）
CREATE TABLE IF NOT EXISTS rule_set_snapshot (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    rule_set_id BIGINT NOT NULL,
    is_active TINYINT NOT NULL DEFAULT 1,
    version BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (rule_set_id) REFERENCES rule_set(id) ON DELETE CASCADE,
    INDEX idx_rss_rule_set (rule_set_id),
    INDEX idx_rss_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 卡片→规则集绑定
CREATE TABLE IF NOT EXISTS card_rule_set_ref (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    card_id BIGINT NOT NULL,
    rule_set_id BIGINT NOT NULL,
    ref_type VARCHAR(32) NOT NULL DEFAULT 'BASE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (rule_set_id) REFERENCES rule_set(id) ON DELETE CASCADE,
    INDEX idx_crsr_card (card_id),
    INDEX idx_crsr_rule_set (rule_set_id),
    UNIQUE KEY uk_crsr_card_set (card_id, rule_set_id, ref_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 权限规则（CARD_ONLY 特例 / 旧路径兼容）
CREATE TABLE IF NOT EXISTS permission_rule (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    card_id BIGINT NOT NULL,
    effect VARCHAR(16) NOT NULL DEFAULT 'ALLOW',
    resource VARCHAR(256) NOT NULL,
    action VARCHAR(64) NOT NULL,
    rule_type VARCHAR(32) NOT NULL DEFAULT 'CARD_ONLY',
    condition_json TEXT,
    priority INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_pr_card (card_id),
    INDEX idx_pr_type (rule_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 权限规则快照（编译后的权限规则缓存）
CREATE TABLE IF NOT EXISTS permission_rule_snapshot (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    card_id BIGINT NOT NULL,
    rule_set_id BIGINT,
    effect VARCHAR(16) NOT NULL,
    resource VARCHAR(256),
    action VARCHAR(64),
    condition_json TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_prs_card (card_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 权限规则模板（超管模板 __SUPERADMIN__ 等）
CREATE TABLE IF NOT EXISTS permission_rule_template (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    template_id VARCHAR(64) NOT NULL,
    effect VARCHAR(16) NOT NULL DEFAULT 'ALLOW',
    resource VARCHAR(256) NOT NULL,
    action VARCHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_prt_template (template_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===== 身份与卡片表 =====

-- 身份卡（身份证/账号）— 每人一张
CREATE TABLE IF NOT EXISTS identity_card (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    card_number VARCHAR(128) NOT NULL,
    password_hash VARCHAR(256),
    real_name VARCHAR(128),
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    valid_from TIMESTAMP NULL,
    valid_until TIMESTAMP NULL,
    deleted_at TIMESTAMP NULL COMMENT '软删除时间戳',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_ic_card_number (card_number),
    INDEX idx_ic_user (user_id),
    INDEX idx_ic_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 用户卡（员工证/医疗证）— 每人多张
CREATE TABLE IF NOT EXISTS user_card (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    identity_card_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    template_id BIGINT NOT NULL,
    level_id BIGINT,
    card_name VARCHAR(255),
    card_type VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    domain_id BIGINT,
    tenant_id BIGINT,
    org_id BIGINT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_uc_identity (identity_card_id),
    INDEX idx_uc_user (user_id),
    INDEX idx_uc_template (template_id),
    INDEX idx_uc_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 用户卡模板
CREATE TABLE IF NOT EXISTS user_card_template (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    card_type VARCHAR(64) NOT NULL,
    description TEXT,
    is_default TINYINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===== 组织架构表 =====

-- 组织（学校/机构/企业）
CREATE TABLE IF NOT EXISTS organization (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    code VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_org_code (code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 域
CREATE TABLE IF NOT EXISTS domain (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    org_id BIGINT NOT NULL,
    name VARCHAR(255) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_domain_org (org_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 租户
CREATE TABLE IF NOT EXISTS tenant (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    domain_id BIGINT NOT NULL,
    name VARCHAR(255) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_tenant_domain (domain_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===== MQ 幂等去重（Redis替代，表结构仅用于兜底日志） =====

CREATE TABLE IF NOT EXISTS mq_idempotent_log (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    message_type VARCHAR(64) NOT NULL,
    message_id VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'PROCESSED',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_mq_msg (message_type, message_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
