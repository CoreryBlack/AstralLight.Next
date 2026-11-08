-- Additive V7 local history of authority scope publication certificates.
-- Every authority-signed certificate this database observes and verifies is
-- recorded here immutably (insert-only; rows are never updated or deleted by
-- the reconciler). This table is deliberately SEPARATE from the current
-- pointer row in authorization_scope_certificate: recording a historical
-- certificate NEVER advances or rolls back the pointer, and the pointer only
-- advances onto a certificate whose exact parent is the current record with
-- non-decreasing authority term/fence counters. This separation lets the
-- publication reconciler re-observe an already-certified scope after the
-- pointer moved on (lost certify response, lease handover) without weakening
-- the pointer chain and without re-deriving ancestry from term/fence order.
-- No row here grants authority; it is local reconciliation and audit evidence.
CREATE TABLE IF NOT EXISTS authorization_scope_certificate_history (
    certificate_hash BINARY(32) NOT NULL,
    scope_hash BINARY(32) NOT NULL,
    reservation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    operation_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    certificate_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    authority_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    authority_term BIGINT UNSIGNED NOT NULL,
    global_fence_sequence BIGINT UNSIGNED NOT NULL,
    parent_certificate_hash BINARY(32) NULL,
    certificate_json JSON NOT NULL,
    observed_at BIGINT NOT NULL,
    PRIMARY KEY (certificate_hash),
    KEY idx_asch_scope_order (scope_hash, authority_term, global_fence_sequence),
    KEY idx_asch_reservation (reservation_id, operation_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
