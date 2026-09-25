-- I-5: SoD/命中统计/委托扩展表（对齐 Java 基线 DDL）
--
-- Java 基线对照:
-- - SodPolicy.java / SodViolation.java: AstralGeneral/entity/platform/
-- - PermissionHitStat.java: AstralGeneral/entity/platform/PermissionHitStat.java
-- - PermissionDelegation.java: AstralGeneral/entity/platform/PermissionDelegation.java
--
-- 注意: sod_policy/sod_violation 已被 astral-trustgraph/src/api/sod.rs 使用，
-- delegation 已在 00002_governance.sql 创建，本迁移仅补充缺失表。

-- SoD 职责分离策略表（对齐 Java sod_policy）
CREATE TABLE IF NOT EXISTS sod_policy (
    policy_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    policy_name VARCHAR(255) NOT NULL,
    description TEXT,
    conflict_type VARCHAR(16) NOT NULL DEFAULT 'STATIC' COMMENT 'STATIC | DYNAMIC',
    resource_type VARCHAR(128),
    action_code VARCHAR(64),
    permission_a VARCHAR(256) COMMENT '冲突权限 A',
    permission_b VARCHAR(256) COMMENT '冲突权限 B',
    condition_script TEXT COMMENT 'DYNAMIC 条件脚本',
    status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE' COMMENT 'ACTIVE | INACTIVE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_sp_conflict_type (conflict_type),
    INDEX idx_sp_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- SoD 违规记录表（对齐 Java sod_violation）
CREATE TABLE IF NOT EXISTS sod_violation (
    violation_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    policy_id BIGINT NOT NULL,
    policy_name VARCHAR(255) NOT NULL,
    card_id BIGINT NOT NULL,
    user_id BIGINT,
    operator_id BIGINT,
    violation_type VARCHAR(16) NOT NULL DEFAULT 'STATIC' COMMENT 'STATIC | DYNAMIC',
    details_json TEXT COMMENT '冲突详情 JSON',
    blocked TINYINT NOT NULL DEFAULT 1 COMMENT '是否已拦截',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (policy_id) REFERENCES sod_policy(policy_id) ON DELETE CASCADE,
    INDEX idx_sv_policy (policy_id),
    INDEX idx_sv_card (card_id),
    INDEX idx_sv_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 权限命中统计表（对齐 Java permission_hit_stat）
CREATE TABLE IF NOT EXISTS permission_hit_stat (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    card_id BIGINT NOT NULL,
    resource_type VARCHAR(128) NOT NULL,
    action_code VARCHAR(64) NOT NULL,
    hit_count BIGINT NOT NULL DEFAULT 1,
    last_hit_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    rule_source VARCHAR(32) COMMENT 'RULE_SET | PERMISSION_RULE | TEMPLATE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_phs_card_res_act (card_id, resource_type, action_code),
    INDEX idx_phs_card (card_id),
    INDEX idx_phs_hit_count (hit_count DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ===== Merged from security_education_tables =====
-- 补齐安全与教育域实体表

-- 密码策略
CREATE TABLE IF NOT EXISTS password_policy (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    min_length INT NOT NULL DEFAULT 8,
    max_length INT,
    require_uppercase TINYINT NOT NULL DEFAULT 1,
    require_lowercase TINYINT NOT NULL DEFAULT 1,
    require_digit TINYINT NOT NULL DEFAULT 1,
    require_special TINYINT NOT NULL DEFAULT 0,
    special_chars VARCHAR(64),
    max_retries INT NOT NULL DEFAULT 5,
    lockout_minutes INT NOT NULL DEFAULT 30,
    password_expiry_days INT,
    history_count INT NOT NULL DEFAULT 3,
    is_default TINYINT NOT NULL DEFAULT 0,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 安全事件
CREATE TABLE IF NOT EXISTS security_event (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT,
    event_type VARCHAR(64) NOT NULL,
    severity VARCHAR(16) NOT NULL DEFAULT 'INFO',
    ip_address VARCHAR(45),
    user_agent VARCHAR(512),
    detail TEXT,
    resolved TINYINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_se_user (user_id),
    INDEX idx_se_type (event_type),
    INDEX idx_se_resolved (resolved),
    INDEX idx_se_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- OAuth 提供商
CREATE TABLE IF NOT EXISTS oauth_provider (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    provider_name VARCHAR(64) NOT NULL,
    client_id VARCHAR(256) NOT NULL,
    client_secret_encrypted VARCHAR(512),
    authorize_url VARCHAR(512),
    token_url VARCHAR(512),
    userinfo_url VARCHAR(512),
    scope VARCHAR(256),
    enabled TINYINT NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_provider_name (provider_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 学校
CREATE TABLE IF NOT EXISTS school (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    code VARCHAR(64),
    province VARCHAR(64),
    city VARCHAR(64),
    district VARCHAR(64),
    address VARCHAR(512),
    school_type VARCHAR(32),
    logo_url VARCHAR(512),
    contact_phone VARCHAR(32),
    contact_email VARCHAR(128),
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_code (code),
    INDEX idx_school_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- permission_request 补充 card_id 列
SET @db = (SELECT DATABASE());
SET @col = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'permission_request' AND COLUMN_NAME = 'card_id');
SET @sql = IF(@col = 0, 'ALTER TABLE permission_request ADD COLUMN card_id BIGINT AFTER reason ', 'SELECT 1 AS col_exists');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
