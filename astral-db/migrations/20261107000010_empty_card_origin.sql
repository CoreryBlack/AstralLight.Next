-- Durable source-proven origin for an empty card that may later receive its first grant.
-- The source owner inserts PENDING in the card creation transaction; only an
-- authority-returned immutable eligibility completion receipt can move it to COMPLETED.
CREATE TABLE IF NOT EXISTS authority_empty_card_origin (
    tenant_id                    BIGINT NOT NULL,
    card_id                      BIGINT NOT NULL,
    create_operation_id          VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    reservation_id               VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    event_id                     VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    admission_proof_id           VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    service_id                   VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    database_id                  VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    request_binding_digest       BINARY(32) NOT NULL,
    source_commit_digest         BINARY(32) NOT NULL,
    before_image_digest          BINARY(32) NOT NULL,
    after_image_digest           BINARY(32) NOT NULL,
    source_outcome_digest        BINARY(32) NOT NULL,
    staged_evidence_digest       BINARY(32) NOT NULL,
    source_receipts              JSON NOT NULL,
    staged_evidence             JSON NOT NULL,
    state                        VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    authority_terminal_receipt   JSON NULL,
    authority_terminal_receipt_digest BINARY(32) NULL,
    created_at                   BIGINT NOT NULL,
    updated_at                   BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, card_id),
    UNIQUE KEY uk_aceo_card_id (card_id),
    UNIQUE KEY uk_aceo_reservation (reservation_id),
    KEY idx_aceo_operation (create_operation_id),
    CONSTRAINT chk_aceo_state CHECK (state IN ('PENDING', 'COMPLETED')),
    CONSTRAINT chk_aceo_terminal_pair CHECK (
        (state = 'PENDING' AND authority_terminal_receipt IS NULL AND authority_terminal_receipt_digest IS NULL)
        OR
        (state = 'COMPLETED' AND authority_terminal_receipt IS NOT NULL AND authority_terminal_receipt_digest IS NOT NULL)
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
