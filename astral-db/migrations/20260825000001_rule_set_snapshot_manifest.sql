-- Rust-owned additive proof for an empty or deleted RuleSet snapshot.
--
-- A marker is written in the same transaction as replacement/deletion of the
-- RuleSet snapshot rows. Readers may use it only when its generation equals the
-- READY projection head generation. No foreign key is intentional: DELETED
-- RuleSets must retain their generation-bound evidence after source deletion.
-- Status is application-constrained to EMPTY or DELETED by the projection
-- writer and read gate; this avoids a MySQL-version-specific CHECK contract.

CREATE TABLE IF NOT EXISTS rule_set_snapshot_manifest (
    rule_set_id          BIGINT NOT NULL,
    projection_generation BIGINT NOT NULL,
    status               VARCHAR(16) NOT NULL,
    tenant_id            BIGINT NULL,
    event_id             VARCHAR(128) NOT NULL,
    operation_id         VARCHAR(128) NOT NULL,
    committed_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (rule_set_id, projection_generation),
    KEY idx_rssm_event (event_id),
    KEY idx_rssm_operation (operation_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Rust-owned generation-bound empty/deleted RuleSet snapshot proof';
