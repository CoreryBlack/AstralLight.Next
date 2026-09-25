-- Phase 5: 认证设备会话
--
-- Canonical platform_v4 contract.  auth_token_family is created by the
-- following migration, therefore the family foreign key is added there.
-- Keep session_id as the physical primary-key name: resilience migrations
-- reference this column directly.

CREATE TABLE IF NOT EXISTS auth_device_session (
    session_id BIGINT NOT NULL AUTO_INCREMENT,
    family_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    device_id VARCHAR(255) NOT NULL,
    device_type VARCHAR(64) DEFAULT NULL,
    client_app_id VARCHAR(128) DEFAULT NULL,
    channel_code VARCHAR(64) DEFAULT NULL,
    current_user_card_id BIGINT DEFAULT NULL,
    session_state VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    session_version BIGINT NOT NULL DEFAULT 1,
    session_epoch BIGINT NOT NULL DEFAULT 1,
    refresh_token_hash VARCHAR(255) NOT NULL,
    refresh_expires_at DATETIME DEFAULT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    ip_address VARCHAR(64) DEFAULT NULL,
    user_agent VARCHAR(512) DEFAULT NULL,
    last_seen_at DATETIME DEFAULT NULL,
    revoked_at DATETIME DEFAULT NULL,
    revoked_reason VARCHAR(512) DEFAULT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (session_id),
    UNIQUE KEY uk_ads_refresh_token (refresh_token_hash),
    KEY idx_ads_user_device (user_id, device_id),
    KEY idx_ads_family (family_id),
    KEY idx_ads_card (current_user_card_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
