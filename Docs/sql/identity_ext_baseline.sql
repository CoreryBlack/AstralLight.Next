-- Compose integration baseline for the adopted Java-era identity tables.
-- This file is NOT a migration. Never place it under astral-db/migrations.
-- astral-migrate records 20240630* migrations as adopted without executing them, but the
-- platform-v4 dump lacks password_reset_token and verification_code, which Rust migration
-- 20261107000008 alters. The two CREATE TABLE statements below are copied from lines 5-16 and
-- 19-30 of 20240630000022_identity_ext.sql. Its audit_log index tail is excluded because
-- audit_log exists only after Rust migration 20260818000001.
-- astral-db tests (migration::tests::compose_baseline) pin this copy and the compose mounts.

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
