-- Rust-owned support tables formerly created by the TrustGraph process at startup.
-- Application startup now validates these tables and never executes DDL.

CREATE TABLE IF NOT EXISTS sod_policy (
    policy_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    policy_name VARCHAR(128) NOT NULL,
    description TEXT,
    conflict_type VARCHAR(16) NOT NULL DEFAULT 'STATIC',
    resource_type VARCHAR(64),
    action_code VARCHAR(64),
    permission_a VARCHAR(256),
    permission_b VARCHAR(256),
    condition_script TEXT,
    status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE',
    limit_count INT DEFAULT 0,
    limit_window VARCHAR(32) DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_sod_type (conflict_type),
    INDEX idx_sod_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- The Java validation baseline already has these tables but lacks the active
-- status used by the Rust policy queries. Upgrade it explicitly because
-- CREATE TABLE IF NOT EXISTS does not alter an existing baseline table.
ALTER TABLE sod_policy
    ADD COLUMN IF NOT EXISTS status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE' AFTER condition_script;
UPDATE sod_policy SET status = 'ACTIVE' WHERE status IS NULL OR status = '';

SET @db = DATABASE();
SET @idx = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'sod_policy'
      AND INDEX_NAME = 'idx_sod_status'
);
SET @sql = IF(@idx = 0,
    'ALTER TABLE sod_policy ADD KEY idx_sod_status (status)',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

CREATE TABLE IF NOT EXISTS sod_violation (
    violation_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    policy_id BIGINT NOT NULL,
    policy_name VARCHAR(128) NOT NULL,
    card_id BIGINT NOT NULL,
    user_id BIGINT,
    operator_id BIGINT,
    violation_type VARCHAR(16) NOT NULL DEFAULT 'STATIC',
    details_json TEXT,
    blocked BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_sv_policy (policy_id),
    INDEX idx_sv_card (card_id),
    CONSTRAINT fk_sod_violation_policy
        FOREIGN KEY (policy_id) REFERENCES sod_policy(policy_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS identity_global_admin (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    granted_by BIGINT DEFAULT NULL,
    granted_reason VARCHAR(255) DEFAULT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_identity_global_admin_user_id (user_id),
    KEY idx_identity_global_admin_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='全局管理员';
