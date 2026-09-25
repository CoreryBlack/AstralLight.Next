-- 用户 MFA 配置（对齐 Java UserMfa）
CREATE TABLE IF NOT EXISTS user_mfa (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    mfa_type VARCHAR(32) NOT NULL COMMENT 'TOTP|RECOVERY_CODES',
    secret_enc BLOB COMMENT 'AES-256-GCM 加密的 TOTP Secret',
    phone VARCHAR(32),
    email VARCHAR(128),
    is_enabled TINYINT NOT NULL DEFAULT 0,
    is_primary TINYINT NOT NULL DEFAULT 0,
    backup_codes_hash TEXT COMMENT 'JSON 数组: SHA-256 哈希的恢复码',
    backup_codes_used INT NOT NULL DEFAULT 0,
    verified_at TIMESTAMP NULL,
    last_used_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_um_user (user_id),
    UNIQUE KEY uk_um_user_type (user_id, mfa_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- MFA 尝试日志（对齐 Java MfaAttemptLog）
CREATE TABLE IF NOT EXISTS mfa_attempt_log (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    mfa_type VARCHAR(32) NOT NULL,
    success TINYINT NOT NULL,
    ip VARCHAR(64),
    user_agent VARCHAR(512),
    failure_reason VARCHAR(256),
    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_mal_user (user_id),
    INDEX idx_mal_attempted (attempted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
