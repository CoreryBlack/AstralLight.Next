-- Additive durable one-use record for ROOT-signed source bootstrap bridges.
-- This capability is distinct from authorization_admission_use: a source
-- bootstrap capability is never an AuthorizationAdmission and cannot enter F1.
-- The bridge writes the completed row in the same transaction as the source
-- aggregate, audit row, and retained receipt/evidence JSON.
CREATE TABLE IF NOT EXISTS authority_source_bootstrap_use (
    reservation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    operation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    event_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    capability_nonce VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    authority_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    service_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    database_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    authority_term BIGINT UNSIGNED NOT NULL,
    global_fence_sequence BIGINT UNSIGNED NOT NULL,
    key_epoch BIGINT UNSIGNED NOT NULL,
    ticket_digest BINARY(32) NOT NULL,
    capability_digest BINARY(32) NOT NULL,
    source_payload_digest BINARY(32) NOT NULL,
    before_image_digest BINARY(32) NOT NULL,
    source_commit_digest BINARY(32) NOT NULL,
    after_image_digest BINARY(32) NOT NULL,
    source_outcome_digest BINARY(32) NOT NULL,
    staged_evidence_digest BINARY(32) NOT NULL,
    audit_receipt_digest BINARY(32) NOT NULL,
    generated_ids JSON NOT NULL,
    source_receipts JSON NOT NULL,
    outcome_json JSON NOT NULL,
    staged_evidence JSON NOT NULL,
    state VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    committed_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (reservation_id),
    UNIQUE KEY uk_asbu_operation (operation_id),
    UNIQUE KEY uk_asbu_event (event_id),
    UNIQUE KEY uk_asbu_capability_nonce (capability_nonce),
    KEY idx_asbu_ticket_digest (ticket_digest),
    KEY idx_asbu_state (state)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
