-- ============================================================
-- Authorization projection tables (head/outbox)
-- Missing from full_schema_v4.sql; required by the native
-- benchmark (RQ1-RQ4) and the distributed correctness harness.
-- Source: AstralTrustGraph/src/test/resources/sql/test-schema.sql
-- ============================================================

CREATE TABLE IF NOT EXISTS authorization_projection_head (
    head_id BIGINT NOT NULL AUTO_INCREMENT,
    aggregate_type VARCHAR(32) NOT NULL,
    aggregate_id BIGINT NOT NULL,
    source_generation BIGINT NOT NULL DEFAULT 0,
    projected_generation BIGINT NOT NULL DEFAULT 0,
    revoke_fence BIGINT NOT NULL DEFAULT 0,
    projection_status VARCHAR(32) NOT NULL DEFAULT 'READY',
    last_event_id VARCHAR(128),
    last_error TEXT,
    created_at DATETIME,
    updated_at DATETIME,
    PRIMARY KEY (head_id),
    UNIQUE KEY uk_test_projection_head (aggregate_type, aggregate_id)
);

CREATE TABLE IF NOT EXISTS authorization_projection_outbox (
    outbox_id BIGINT NOT NULL AUTO_INCREMENT,
    event_id VARCHAR(64) NOT NULL,
    aggregate_type VARCHAR(32) NOT NULL,
    aggregate_id BIGINT NOT NULL,
    tenant_id BIGINT,
    event_type VARCHAR(32) NOT NULL,
    source_generation BIGINT NOT NULL,
    sequence_number BIGINT NOT NULL,
    revoke_fence BIGINT NOT NULL DEFAULT 0,
    payload_json MEDIUMTEXT,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    attempts INT NOT NULL DEFAULT 0,
    next_attempt_at DATETIME,
    lease_owner VARCHAR(64),
    lease_expires_at DATETIME,
    processed_at DATETIME,
    processed_by VARCHAR(64),
    terminal_transitions INT NOT NULL DEFAULT 0,
    last_error VARCHAR(255),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (outbox_id),
    UNIQUE KEY uk_test_apob_event (event_id),
    UNIQUE KEY uk_test_apob_generation_sequence (aggregate_type, aggregate_id, source_generation, sequence_number),
    KEY idx_test_apob_pending (status, next_attempt_at, created_at),
    KEY idx_test_apob_lease (status, lease_expires_at, outbox_id),
    KEY idx_test_apob_aggregate (aggregate_type, aggregate_id, source_generation)
);
