-- AL-owned local message outbox for single-node delivery.
--
-- This table is deliberately separate from aggregate-specific outboxes such as
-- auth_session_outbox and authorization_delta_event. It owns only transport
-- messages whose business handlers do not already have a canonical durable
-- event table. RabbitMQ may relay these rows in distributed mode, but a local
-- worker can process them without a broker.

CREATE TABLE IF NOT EXISTS al_message_outbox (
    message_id       VARCHAR(128) NOT NULL,
    operation_id     VARCHAR(128) NOT NULL,
    message_type     VARCHAR(64) NOT NULL,
    queue_name       VARCHAR(128) NOT NULL,
    ordering_key     VARCHAR(256) DEFAULT NULL,
    tenant_id        BIGINT DEFAULT NULL,
    origin_region    VARCHAR(64) NOT NULL,
    target_region    VARCHAR(64) DEFAULT NULL,
    schema_version   INT NOT NULL,
    payload_json     MEDIUMTEXT NOT NULL,
    headers_json     MEDIUMTEXT DEFAULT NULL,
    payload_sha256   CHAR(64) NOT NULL,
    status           VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    attempts         INT NOT NULL DEFAULT 0,
    next_attempt_at  DATETIME(6) DEFAULT NULL,
    lease_owner      VARCHAR(128) DEFAULT NULL,
    lease_expires_at DATETIME(6) DEFAULT NULL,
    processed_at     DATETIME(6) DEFAULT NULL,
    last_error       VARCHAR(512) DEFAULT NULL,
    created_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (message_id),
    UNIQUE KEY uk_al_message_queue_message (queue_name, message_id),
    KEY idx_al_message_pending (status, next_attempt_at, created_at),
    KEY idx_al_message_lease (status, lease_expires_at, message_id),
    KEY idx_al_message_ordering (queue_name, ordering_key, status, created_at),
    KEY idx_al_message_operation (operation_id, message_type),
    KEY idx_al_message_tenant (tenant_id, queue_name, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
