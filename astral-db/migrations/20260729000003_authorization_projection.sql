-- Durable authorization projection contract shared with Java.
-- Rust owns this migration; Java validates and consumes the tables but never
-- executes schema DDL at application startup.

CREATE TABLE IF NOT EXISTS authorization_projection_head (
    head_id              BIGINT NOT NULL AUTO_INCREMENT,
    aggregate_type       VARCHAR(32) NOT NULL,
    aggregate_id         BIGINT NOT NULL,
    source_generation    BIGINT NOT NULL DEFAULT 0,
    projected_generation BIGINT NOT NULL DEFAULT 0,
    revoke_fence         BIGINT NOT NULL DEFAULT 0,
    projection_status    VARCHAR(32) NOT NULL DEFAULT 'READY',
    last_event_id        VARCHAR(64) DEFAULT NULL,
    last_error            VARCHAR(255) DEFAULT NULL,
    created_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (head_id),
    UNIQUE KEY uk_aph_aggregate (aggregate_type, aggregate_id),
    KEY idx_aph_status (projection_status, updated_at),
    KEY idx_aph_generation (aggregate_type, source_generation, projected_generation)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS authorization_projection_outbox (
    outbox_id             BIGINT NOT NULL AUTO_INCREMENT,
    event_id              VARCHAR(64) NOT NULL,
    aggregate_type        VARCHAR(32) NOT NULL,
    aggregate_id          BIGINT NOT NULL,
    tenant_id             BIGINT DEFAULT NULL,
    event_type             VARCHAR(32) NOT NULL,
    source_generation      BIGINT NOT NULL,
    sequence_number        BIGINT NOT NULL,
    revoke_fence           BIGINT NOT NULL DEFAULT 0,
    payload_json           MEDIUMTEXT DEFAULT NULL,
    status                 VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    attempts               INT NOT NULL DEFAULT 0,
    next_attempt_at        DATETIME DEFAULT NULL,
    lease_owner            VARCHAR(64) DEFAULT NULL,
    lease_expires_at       DATETIME DEFAULT NULL,
    processed_at           DATETIME DEFAULT NULL,
    processed_by           VARCHAR(64) DEFAULT NULL,
    terminal_transitions   INT NOT NULL DEFAULT 0,
    last_error             VARCHAR(255) DEFAULT NULL,
    created_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (outbox_id),
    UNIQUE KEY uk_apob_event (event_id),
    UNIQUE KEY uk_apob_generation_sequence (aggregate_type, aggregate_id, source_generation, sequence_number),
    KEY idx_apob_pending (status, next_attempt_at, created_at),
    KEY idx_apob_lease (status, lease_expires_at, outbox_id),
    KEY idx_apob_aggregate (aggregate_type, aggregate_id, source_generation)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
