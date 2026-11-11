-- Durable, authority-bound completion ledger for CertifiedMemory families.
-- Rows are written by the family source owner after the source outcome,
-- projection/audit receipts, bounded inventory, and authority completion receipt
-- are durably reconciled. A missing or non-terminal row is never a certificate.
CREATE TABLE IF NOT EXISTS authority_certified_memory_completion (
    family VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    scope_key VARCHAR(256) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    tenant_id BIGINT NULL,
    scope_generation BIGINT UNSIGNED NOT NULL,
    revoke_watermark BIGINT UNSIGNED NOT NULL,
    state VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    reconciliation_state VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    reservation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    operation_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    event_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    message_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
    source_commit_digest BINARY(32) NOT NULL,
    source_outcome_digest BINARY(32) NOT NULL,
    before_content_digest BINARY(32) NULL,
    after_content_digest BINARY(32) NULL,
    complete_content_digest BINARY(32) NULL,
    audit_correlation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    inventory_json JSON NOT NULL,
    payload_json JSON NOT NULL,
    dependency_frontier_json JSON NOT NULL,
    authority_completion_receipt_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (family, scope_key, scope_generation),
    KEY idx_acmc_scope_frontier (scope_key, tenant_id, scope_generation, revoke_watermark),
    KEY idx_acmc_state (state, reconciliation_state, updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
