-- Durable per-node invalidation inbox (Rabbit invalidation fanout transport).
--
-- Each Rabbit node owns its own durable subscription queue bound to the
-- `astral.auth.invalidation.fanout` exchange. Before any broker delivery is
-- ACKed, this table records the delivery as a durable per-node receipt; only
-- after the node's in-memory invalidation apply succeeds is the receipt
-- marked APPLIED. The receipt proves "this node durably received and applied
-- the invalidation notification" — it never proves that a downstream
-- authorization projection is READY; the read gate stays PENDING/DENY until
-- the authorization projection path itself proves READY.
--
-- Write ownership: this table is owned exclusively by
-- `astral_db::InvalidationInboxRepository` (consumed through the
-- astral-mq invalidation fanout adapter). It deliberately shares no
-- rows, keys, or write paths with `al_message_outbox`
-- (LocalMessageRepository), which remains the sole owner of the sender-side
-- outbox state machine.
--
-- Identity bound: node_region / node_id mirror the frozen AppConfig
-- transport identity (region <= 64, node <= 128 chars) with the astral-mq
-- `NodeIdentity` charset restriction ([A-Za-z0-9._-]); the composite
-- primary key therefore stays far below the InnoDB 3072-byte index limit
-- under utf8mb4.
--
-- Scope ordering: `envelope_created_at` stores the sender envelope's
-- `createdAt` (UTC) so a reader can detect out-of-order gaps inside one
-- ordering-key scope (watermark reconciliation). Message bodies are the
-- canonical envelope JSON whose inner payload digest is `payload_sha256`.
-- State transitions (PENDING -> APPLIED) are enforced by the repository,
-- not by CHECK constraints or triggers.

CREATE TABLE IF NOT EXISTS authorization_invalidation_inbox (
    node_region        VARCHAR(64) NOT NULL,
    node_id            VARCHAR(128) NOT NULL,
    message_id         VARCHAR(128) NOT NULL,
    operation_id       VARCHAR(128) NOT NULL,
    message_type       VARCHAR(64) NOT NULL,
    ordering_key       VARCHAR(256) DEFAULT NULL,
    tenant_id          BIGINT DEFAULT NULL,
    origin_region      VARCHAR(64) NOT NULL,
    schema_version     INT NOT NULL,
    payload_json       MEDIUMTEXT NOT NULL,
    payload_sha256     CHAR(64) NOT NULL,
    envelope_created_at DATETIME(6) NOT NULL,
    status             VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    applied_at         DATETIME(6) DEFAULT NULL,
    created_at         DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at         DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (node_region, node_id, message_id),
    KEY idx_invalidation_inbox_scope_pending
        (node_region, node_id, ordering_key, status, envelope_created_at, message_id),
    KEY idx_invalidation_inbox_pending
        (node_region, node_id, status, envelope_created_at),
    KEY idx_invalidation_inbox_operation
        (node_region, node_id, operation_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
