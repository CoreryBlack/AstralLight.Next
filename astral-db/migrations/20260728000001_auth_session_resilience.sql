-- Durable authentication-session resilience contract shared with Java.
--
-- This migration is Rust-owned and runs after the canonical family/session
-- contract. It mirrors the Java entities used by the durable switch-card and
-- Redis projection paths. No raw credentials or idempotency keys are stored.

ALTER TABLE auth_device_session
    ADD COLUMN IF NOT EXISTS session_state VARCHAR(32) NOT NULL DEFAULT 'ACTIVE'
        AFTER current_user_card_id;
ALTER TABLE auth_device_session
    ADD COLUMN IF NOT EXISTS session_version BIGINT NOT NULL DEFAULT 1
        AFTER session_state;
ALTER TABLE auth_device_session
    ADD COLUMN IF NOT EXISTS session_epoch BIGINT NOT NULL DEFAULT 1
        AFTER session_version;

UPDATE auth_device_session
SET session_state = CASE
        WHEN session_state IS NULL OR session_state = '' THEN COALESCE(NULLIF(status, ''), 'ACTIVE')
        ELSE session_state
    END,
    session_version = CASE
        WHEN session_version IS NULL OR session_version < 1 THEN 1
        ELSE session_version
    END,
    session_epoch = CASE
        WHEN session_epoch IS NULL OR session_epoch < 1 THEN 1
        ELSE session_epoch
    END;

CREATE TABLE IF NOT EXISTS auth_session_operation (
    operation_id          VARCHAR(64) NOT NULL,
    session_id            BIGINT DEFAULT NULL,
    user_id               BIGINT NOT NULL,
    operation_type        VARCHAR(32) NOT NULL,
    idempotency_key_hash  CHAR(64) NOT NULL,
    request_hash          CHAR(64) NOT NULL,
    refresh_token_hash    CHAR(64) NOT NULL,
    target_card_id        BIGINT DEFAULT NULL,
    status                VARCHAR(32) NOT NULL,
    response_ciphertext   MEDIUMTEXT DEFAULT NULL,
    response_expires_at   DATETIME DEFAULT NULL,
    completed_at          DATETIME DEFAULT NULL,
    created_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (operation_id),
    UNIQUE KEY uk_aso_user_type_idempotency (user_id, operation_type, idempotency_key_hash),
    KEY idx_aso_session (session_id),
    KEY idx_aso_expiry (response_expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS auth_session_outbox (
    outbox_id             BIGINT NOT NULL AUTO_INCREMENT,
    operation_id          VARCHAR(64) NOT NULL,
    session_id            BIGINT DEFAULT NULL,
    event_type            VARCHAR(16) NOT NULL,
    sequence_number       INT NOT NULL,
    projection_key        VARCHAR(512) NOT NULL,
    payload_json          MEDIUMTEXT DEFAULT NULL,
    projection_expires_at DATETIME DEFAULT NULL,
    status                VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    attempts              INT NOT NULL DEFAULT 0,
    next_attempt_at       DATETIME DEFAULT NULL,
    lease_owner           VARCHAR(64) DEFAULT NULL,
    lease_expires_at      DATETIME DEFAULT NULL,
    processed_at          DATETIME DEFAULT NULL,
    processed_by          VARCHAR(64) DEFAULT NULL,
    terminal_transitions  INT NOT NULL DEFAULT 0,
    last_error            VARCHAR(128) DEFAULT NULL,
    created_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (outbox_id),
    UNIQUE KEY uk_aso_operation_sequence (operation_id, sequence_number),
    KEY idx_aso_pending (status, next_attempt_at, created_at),
    KEY idx_aso_lease (status, lease_expires_at, outbox_id),
    KEY idx_aso_session (session_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS auth_session_jti_index (
    jti_id        BIGINT NOT NULL AUTO_INCREMENT,
    session_id    BIGINT NOT NULL,
    jti           VARCHAR(128) NOT NULL,
    user_id       BIGINT NOT NULL,
    session_epoch BIGINT NOT NULL,
    status        VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    issued_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at    DATETIME DEFAULT NULL,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (jti_id),
    UNIQUE KEY uk_asji_jti (jti),
    KEY idx_asji_session_epoch (session_id, session_epoch, status),
    KEY idx_asji_status (status, expires_at),
    CONSTRAINT fk_asji_session
        FOREIGN KEY (session_id) REFERENCES auth_device_session (session_id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- CREATE INDEX IF NOT EXISTS is not valid MySQL 8 syntax. Repair indexes
-- explicitly for installations that predate this migration.
SET @db = DATABASE();
SET @idx = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @db
      AND TABLE_NAME = 'auth_session_outbox'
      AND INDEX_NAME = 'idx_aso_lease'
);
SET @sql = IF(
    @idx = 0,
    'ALTER TABLE auth_session_outbox ADD KEY idx_aso_lease (status, lease_expires_at, outbox_id)',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
