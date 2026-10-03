-- Chat-owned durable send intent and recipient snapshot.
--
-- This migration is additive and creates independent tables. It does not alter
-- historical Chat tables or assume that a particular baseline DDL is deployed.
-- The outbox proves only a committed Chat send intent. PUBLISHED means a
-- transport publisher confirmation/admission was received; it never means that
-- a client received or read the message. Per-recipient `chat_message_delivery`
-- rows remain PENDING until the existing delivery/receipt owner records proof.
--
-- The idempotency key is keyed by SHA-256 of the full physical scope plus
-- conversation, paired with the caller's bounded client_msg_id. The stored
-- request digest prevents the same key from accepting different content. All
-- intent, message, recipient snapshot, delivery, and conversation watermark
-- writes are made by the Chat repository in one source transaction.

CREATE TABLE IF NOT EXISTS chat_delivery_intent (
    intent_id          CHAR(36) NOT NULL,
    scope_key_sha256   CHAR(64) NOT NULL,
    client_msg_id      VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    request_sha256     CHAR(64) NOT NULL,
    message_uuid       CHAR(36) NOT NULL,
    message_id         BIGINT DEFAULT NULL,
    conversation_id    BIGINT NOT NULL,
    sender_id          BIGINT NOT NULL,
    identity_card_id   BIGINT NOT NULL,
    user_card_id       BIGINT NOT NULL,
    tenant_id          BIGINT NOT NULL,
    domain_id          BIGINT NOT NULL,
    payload_json       MEDIUMTEXT DEFAULT NULL,
    status             VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    attempts           INT NOT NULL DEFAULT 0,
    next_attempt_at    DATETIME(6) DEFAULT NULL,
    lease_owner        VARCHAR(128) DEFAULT NULL,
    lease_generation   BIGINT NOT NULL DEFAULT 0,
    lease_expires_at   DATETIME(6) DEFAULT NULL,
    published_at       DATETIME(6) DEFAULT NULL,
    last_error         VARCHAR(512) DEFAULT NULL,
    created_at         DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at         DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (intent_id),
    UNIQUE KEY uk_chat_delivery_intent_scope_client (scope_key_sha256, client_msg_id),
    UNIQUE KEY uk_chat_delivery_intent_message_uuid (message_uuid),
    UNIQUE KEY uk_chat_delivery_intent_message_id (message_id),
    KEY idx_chat_delivery_intent_claim (status, lease_expires_at, created_at, intent_id),
    KEY idx_chat_delivery_intent_conversation (conversation_id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS chat_delivery_intent_recipient (
    intent_id          CHAR(36) NOT NULL,
    recipient_id       BIGINT NOT NULL,
    identity_card_id   BIGINT NOT NULL,
    user_card_id       BIGINT NOT NULL,
    tenant_id          BIGINT NOT NULL,
    domain_id          BIGINT NOT NULL,
    created_at         DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (intent_id, recipient_id, identity_card_id, user_card_id),
    KEY idx_chat_delivery_intent_recipient_user (recipient_id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
