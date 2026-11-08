-- Recipient-specific invalidation delivery journal. Additive durable transport
-- routing state; never executed by application startup or by this task.
-- Source transactions stage exact canonical outbox bytes plus their frozen roster.
-- Rabbit publisher confirmation and mTLS receipt acknowledgment are separate
-- from receiver inbox APPLIED and from authorization publication readiness.

CREATE TABLE IF NOT EXISTS authorization_invalidation_delivery_journal (
    message_id VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    operation_id VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    source_database_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    envelope_sha256 BINARY(32) NOT NULL,
    payload_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    envelope_json MEDIUMTEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    message_type VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    schema_version INT NOT NULL,
    origin_region VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    target_region VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    ordering_key VARCHAR(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL,
    tenant_id BIGINT NULL,
    authority_metadata_json MEDIUMTEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL,
    roster_version VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    recipient_roster_json MEDIUMTEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    recipient_roster_sha256 BINARY(32) NOT NULL,
    status VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'READY',
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (message_id),
    KEY idx_aidj_created (created_at, message_id),
    KEY idx_aidj_operation (operation_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS authorization_invalidation_delivery_leg (
    message_id VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    leg_id CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    recipient_region VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    recipient_node VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    recipient_database_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    transport_kind VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    endpoint VARCHAR(2048) CHARACTER SET ascii COLLATE ascii_bin NULL,
    peer_certificate_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    envelope_sha256 BINARY(32) NOT NULL,
    payload_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    status VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'PENDING',
    attempts INT NOT NULL DEFAULT 0,
    generation BIGINT NOT NULL DEFAULT 0,
    lease_owner VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
    lease_token CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
    lease_expires_at DATETIME(6) NULL,
    last_error VARCHAR(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (message_id, leg_id),
    KEY idx_aidl_state_created (status, created_at, message_id),
    KEY idx_aidl_recipient_state (recipient_database_id, recipient_region, recipient_node, status),
    CONSTRAINT fk_aidl_journal FOREIGN KEY (message_id)
        REFERENCES authorization_invalidation_delivery_journal (message_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Receiver receipt is returned over an authenticated route, then persisted by
-- the sender. It records exact target and both hash domains independently.
CREATE TABLE IF NOT EXISTS authorization_invalidation_delivery_receipt (
    message_id VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    leg_id CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    target_database_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    target_region VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    target_node VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    envelope_sha256 BINARY(32) NOT NULL,
    payload_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    operation_id VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    message_type VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    schema_version INT NOT NULL,
    origin_region VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    ordering_key VARCHAR(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL,
    tenant_id BIGINT NULL,
    authority_metadata_json MEDIUMTEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL,
    receipt_status VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    received_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (message_id, leg_id),
    KEY idx_aidr_target (target_database_id, target_region, target_node, receipt_status),
    CONSTRAINT fk_aidr_leg FOREIGN KEY (message_id, leg_id)
        REFERENCES authorization_invalidation_delivery_leg (message_id, leg_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
