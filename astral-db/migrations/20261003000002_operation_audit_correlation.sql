-- Durable requester-scoped progress for TrustGraph card-bind batches.
-- This table stores only task metadata and per-card outcomes; it never stores
-- credentials, raw request bodies, or worker lease secrets. Existing active rows
-- are not automatically resumed after restart: a different owner is surfaced as
-- IN_DOUBT and only untouched source work is left for explicit operator review.

CREATE TABLE IF NOT EXISTS async_operation (
    task_id                         VARCHAR(64) NOT NULL,
    task_type                       VARCHAR(32) NOT NULL,
    status                          VARCHAR(16) NOT NULL DEFAULT 'PENDING',
    requester_user_id               BIGINT NOT NULL,
    requester_card_id               BIGINT NOT NULL,
    requester_tenant_id             BIGINT NOT NULL,
    requester_domain_id             BIGINT NOT NULL,
    authorization_target_card_id    BIGINT NOT NULL,
    authorization_target_tenant_id  BIGINT NOT NULL,
    authorization_target_domain_id  BIGINT NOT NULL,
    target_user_id                  BIGINT NOT NULL,
    total_items                     INT UNSIGNED NOT NULL,
    completed_items                 INT UNSIGNED NOT NULL DEFAULT 0,
    owner_instance_id               VARCHAR(64) NOT NULL,
    error_message                   VARCHAR(255) NULL,
    created_at                      BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    updated_at                      BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    PRIMARY KEY (task_id),
    KEY idx_async_operation_owner_status (requester_user_id, status, updated_at),
    KEY idx_async_operation_anchor (authorization_target_card_id, task_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS async_operation_item (
    task_id          VARCHAR(64) NOT NULL,
    card_id          BIGINT NOT NULL,
    tenant_id        BIGINT NOT NULL,
    domain_id        BIGINT NOT NULL,
    operation_id     VARCHAR(64) NOT NULL,
    status           VARCHAR(16) NOT NULL DEFAULT 'PENDING',
    error_message    VARCHAR(255) NULL,
    created_at       BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    updated_at       BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    PRIMARY KEY (task_id, card_id),
    UNIQUE KEY uk_async_operation_item_operation (operation_id),
    KEY idx_async_operation_item_status (task_id, status, card_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
