-- Phase 2a: Identity crate mock 清零扩展
-- 密码重置令牌 + 验证码表 + 审计日志查询索引

-- 密码重置令牌
CREATE TABLE IF NOT EXISTS password_reset_token (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    card_number VARCHAR(128) NOT NULL COMMENT '发起重置的身份卡号',
    token VARCHAR(64) NOT NULL COMMENT '重置令牌（SHA-256 哈希存储）',
    expires_at TIMESTAMP NOT NULL COMMENT '令牌过期时间（默认 30 分钟）',
    used_at TIMESTAMP NULL COMMENT '使用时间，非空表示已消费',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_prt_user (user_id),
    INDEX idx_prt_token (token),
    INDEX idx_prt_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 验证码（邮箱/手机 — 带 TTL 的 DB 存储替代内存 HashMap）
CREATE TABLE IF NOT EXISTS verification_code (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    target VARCHAR(256) NOT NULL COMMENT '邮箱或手机号',
    purpose VARCHAR(64) NOT NULL COMMENT '注册|重置密码|敏感操作等',
    code VARCHAR(16) NOT NULL COMMENT '6 位数字验证码',
    expires_at TIMESTAMP NOT NULL COMMENT '过期时间（默认 5 分钟）',
    verified_at TIMESTAMP NULL COMMENT '验证时间，非空表示已消费',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_vc_target_purpose (target(128), purpose),
    INDEX idx_vc_expires (expires_at),
    INDEX idx_vc_verified (verified_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 为 audit_log 添加 card_id 索引（admin/stats 统计用）
SET @db = (SELECT DATABASE());
SET @idx = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'audit_log' AND INDEX_NAME = 'idx_al_card');
SET @sql = IF(@idx = 0, 'ALTER TABLE audit_log ADD INDEX idx_al_card (card_id)', 'SELECT 1 AS idx_al_card_exists');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @idx2 = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = (SELECT DATABASE()) AND TABLE_NAME = 'audit_log' AND INDEX_NAME = 'idx_al_decision');
SET @sql2 = IF(@idx2 = 0, 'ALTER TABLE audit_log ADD INDEX idx_al_decision (decision)', 'SELECT 1 AS idx_al_decision_exists');
PREPARE stmt2 FROM @sql2; EXECUTE stmt2; DEALLOCATE PREPARE stmt2;
