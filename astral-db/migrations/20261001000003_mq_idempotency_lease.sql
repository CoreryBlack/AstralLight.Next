-- MQ consumer processing-lease store: durable idempotency claim surface for
-- RabbitMQ consumers (fully additive; no existing table, column or row is
-- modified).
--
-- Ownership boundaries (must not be violated):
-- - `mq_idempotent_log` remains the durable business-processed proof written by
--   the audit/login handlers in the same transaction as their business effect.
--   This table is only the delivery lease layer and is associated with that
--   proof logically (message_type/message_id); there is intentionally no
--   foreign key because legacy audit/login fallback ids may differ from the
--   MQ envelope message id used by the claim layer.
-- - Rows in state `COMPLETED` are written exclusively by the completion path
--   that inherits a durable handler proof (handler success or a completion in
--   the handler's own transaction); the claim/lease layer never promotes a row
--   to `COMPLETED` on its own.
-- - `lease_expires_at` is always computed by the database server
--   (`DATE_ADD(UTC_TIMESTAMP(6), INTERVAL n SECOND)`); consumers never supply
--   their own wall clock for TTL decisions.
--
-- Rollback: DROP TABLE mq_consumer_lease (after consumers are reverted to the
-- compat Redis claim path); the table holds no source-of-truth business data.

CREATE TABLE IF NOT EXISTS mq_consumer_lease (
    idem_key         VARCHAR(255) NOT NULL COMMENT 'public IDEM key: mq:idempotent:<message_type>:<message_id>',
    message_type     VARCHAR(64) NOT NULL,
    message_id       VARCHAR(191) NOT NULL,
    payload_sha256   CHAR(64) DEFAULT NULL COMMENT 'lowercase sha256 of the raw delivery body; NULL = legacy claim without digest, exact-duplicate enforcement requires both digests',
    status           VARCHAR(32) NOT NULL DEFAULT 'PROCESSING' COMMENT 'PROCESSING / COMPLETED',
    lease_owner      VARCHAR(128) DEFAULT NULL COMMENT 'run-scoped consumer identity that holds (or last held) the lease',
    lease_token      VARCHAR(64) DEFAULT NULL COMMENT 'per-claim CAS token; renew/complete/release must match it exactly',
    lease_generation BIGINT NOT NULL DEFAULT 0 COMMENT 'monotonic per (message_type, message_id); incremented on every takeover',
    claim_attempts   INT NOT NULL DEFAULT 0 COMMENT 'observability only; broker DLX retry budget is bounded elsewhere',
    lease_expires_at DATETIME(6) DEFAULT NULL COMMENT 'server-side lease TTL; NULL = released or completed',
    completed_at     DATETIME(6) DEFAULT NULL,
    created_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (message_type, message_id),
    UNIQUE KEY uk_mq_consumer_lease_idem_key (idem_key),
    KEY idx_mq_consumer_lease_active (status, lease_expires_at),
    KEY idx_mq_consumer_lease_completed (status, completed_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
