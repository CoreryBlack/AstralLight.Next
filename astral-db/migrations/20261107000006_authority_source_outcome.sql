-- Durable source-outcome record for the external authority control plane (V7).
-- Exactly one row is committed in the SAME source transaction as the mutation
-- it describes; it is the only input the outside reconciler reads back, so it
-- must bind the stable reservation/proof/operation identity, the registered
-- service/database owner, the actual source receipt identities, and the real
-- before/after image digests supplied by the writer of those rows. This table
-- never grants authority; it is the source-side evidence of one committed
-- mutation awaiting (or past) its authority commit acknowledgement.
CREATE TABLE IF NOT EXISTS authority_source_outcome (
    reservation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    operation_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    event_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    admission_proof_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    request_binding_digest BINARY(32) NOT NULL,
    mutation_kind VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    service_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    database_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    source_commit_digest BINARY(32) NULL,
    before_image_digest BINARY(32) NULL,
    after_image_digest BINARY(32) NULL,
    source_receipts JSON NULL,
    staged_evidence JSON NULL,
    status VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    attempts INT UNSIGNED NOT NULL DEFAULT 0,
    lease_owner VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
    lease_until BIGINT NULL,
    generation BIGINT UNSIGNED NOT NULL DEFAULT 0,
    authority_disposition VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NULL,
    last_error TEXT NULL,
    outcome_digest BINARY(32) NOT NULL,
    committed_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (reservation_id),
    UNIQUE KEY uk_aso_proof (admission_proof_id),
    KEY idx_aso_status_lease (status, lease_until),
    KEY idx_aso_operation (operation_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
