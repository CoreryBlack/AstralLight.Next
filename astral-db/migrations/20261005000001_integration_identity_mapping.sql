-- Default-off SDK identity mapping source and same-transaction operation ledger.
-- This migration is intentionally not added to migration.rs' global required
-- schema preflight. Enabling the feature must explicitly call the read-only
-- validate_integration_mapping_schema(pool) preflight before serving requests.
--
-- Keys are raw UTF-8 bytes carried in VARBINARY columns. No SQL collation,
-- case-folding, trimming, or Unicode normalization participates in uniqueness.
CREATE TABLE integration_identity_mapping (
    mapping_id      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    app_id          VARBINARY(64) NOT NULL,
    issuer          VARBINARY(512) NOT NULL,
    subject         VARBINARY(512) NOT NULL,
    user_id         BIGINT NOT NULL,
    identity_card_id BIGINT NOT NULL,
    status          ENUM('ACTIVE', 'DISABLED', 'REVOKED')
                        CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    revision        BIGINT UNSIGNED NOT NULL DEFAULT 1,
    created_by      BIGINT NOT NULL,
    updated_by      BIGINT NOT NULL,
    operation_id    VARBINARY(64) NOT NULL,
    created_at      TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at      TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                        ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (mapping_id),
    UNIQUE KEY uq_iim_external_identity (app_id, issuer, subject),
    KEY idx_iim_user_id (user_id),
    KEY idx_iim_identity_card_id (identity_card_id),
    CONSTRAINT fk_iim_platform_user FOREIGN KEY (user_id)
        REFERENCES platform_user (user_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_iim_identity_card FOREIGN KEY (identity_card_id)
        REFERENCES identity_card (card_id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- One row per stable operation id. The source row, completed operation result,
-- and corresponding audit_log record commit in one transaction, so a committed
-- PENDING row is treated as an in-doubt contract violation rather than replayed.
CREATE TABLE integration_identity_mapping_operation (
    operation_id    VARBINARY(64) NOT NULL,
    request_digest  BINARY(32) NOT NULL,
    actor_id        BIGINT NOT NULL,
    status          ENUM('PENDING', 'COMPLETED')
                        CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    result_revision BIGINT UNSIGNED NULL,
    claim_token     BINARY(16) NULL,
    created_at      TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (operation_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
