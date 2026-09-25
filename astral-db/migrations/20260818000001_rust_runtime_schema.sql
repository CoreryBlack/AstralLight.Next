-- Rust-only runtime schema that is not part of the verified Java baseline.
--
-- The verified full_schema_v4 baseline contains auth_audit_log, which is a
-- separate Java identity/audit table. Rust runtime consumers use audit_log,
-- mq_idempotent_log, and pending_compensation; never substitute one for the
-- other. CREATE TABLE IF NOT EXISTS keeps this repair safe for databases that
-- already received the historical 202406 migrations.

-- audit_log: the Rust authorization/audit contract assembled from the
-- historical governance, audit extension, and identity extension migrations.
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    action VARCHAR(64) NOT NULL,
    resource VARCHAR(256) NOT NULL,
    decision VARCHAR(16) NOT NULL,
    reason VARCHAR(256),
    card_id BIGINT,
    detail TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    event_type VARCHAR(32),
    source_ip VARCHAR(64),
    request_id VARCHAR(64),
    domain_id BIGINT,
    tenant_id BIGINT,
    INDEX idx_al_user (user_id),
    INDEX idx_al_action (action),
    INDEX idx_al_created (created_at),
    INDEX idx_al_event_type (event_type),
    INDEX idx_al_tenant (tenant_id),
    INDEX idx_al_card (card_id),
    INDEX idx_al_decision (decision)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- MQ consumer idempotency fallback, copied from the baseline DDL.
CREATE TABLE IF NOT EXISTS mq_idempotent_log (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    message_type VARCHAR(64) NOT NULL,
    message_id VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'PROCESSED',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_mq_msg (message_type, message_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Durable retry records for failed side effects, copied from the historical
-- compensation migration.
CREATE TABLE IF NOT EXISTS pending_compensation (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    entity_id BIGINT NOT NULL COMMENT '关联实体 ID（card_id / rule_set_id）',
    op_type VARCHAR(64) NOT NULL COMMENT '操作类型：REBUILD_SNAPSHOT / EVICT_CACHE / FIND_BOUND_CARDS',
    error_msg TEXT COMMENT '错误信息',
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING' COMMENT 'PENDING / COMPLETED / FAILED',
    retry_count INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_status (status),
    INDEX idx_entity (entity_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
