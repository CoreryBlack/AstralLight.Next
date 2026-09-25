-- Durable Rust-owned audit quarantine contract.
--
-- This table stores a failed delivery after the broker retry budget is
-- exhausted.  It deliberately has no CHECK constraint or functional index so
-- the DDL remains executable on MySQL 5.7 and 8.0.  The binary identity key is
-- a fixed-size digest, keeping the unique key well below utf8mb4 index limits.

CREATE TABLE IF NOT EXISTS audit_quarantine (
    id                       BIGINT NOT NULL AUTO_INCREMENT,
    identity_key             BINARY(32) NOT NULL,
    message_id               VARCHAR(255) NOT NULL,
    message_type             VARCHAR(64) NOT NULL,
    raw_payload              LONGBLOB NOT NULL,
    source_queue             VARCHAR(128) NOT NULL,
    source_exchange          VARCHAR(128) NOT NULL,
    source_routing_key       VARCHAR(255) NOT NULL,
    retry_count              INT UNSIGNED NOT NULL DEFAULT 0,
    attempts                 INT UNSIGNED NOT NULL DEFAULT 0,
    replay_attempts          INT UNSIGNED NOT NULL DEFAULT 0,
    failure_reason           VARCHAR(255) NOT NULL,
    status                   VARCHAR(32) NOT NULL DEFAULT 'QUARANTINED',
    replay_lease_owner       VARCHAR(128) DEFAULT NULL,
    replay_lease_token       VARCHAR(128) DEFAULT NULL,
    replay_lease_expires_at  DATETIME DEFAULT NULL,
    first_failed_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_failed_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    quarantined_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    replayed_at              DATETIME DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_aq_identity_key (identity_key),
    KEY idx_aq_status (status, quarantined_at, id),
    KEY idx_aq_replay_lease (status, replay_lease_expires_at, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
