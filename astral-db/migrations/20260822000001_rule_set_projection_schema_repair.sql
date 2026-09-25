-- Rust-owned additive repair for the rule-set projection contract.
--
-- Never edit an applied migration: SQLx checksums are immutable. This migration
-- creates the durable audit-correlation table and repairs the existing
-- rule-set/projection tables. Missing identity columns or primary keys in those
-- existing tables are intentionally rejected by the Rust preflight instead of
-- being guessed here.
--
-- Existing platform-v5/test-export index names are accepted by the Rust schema
-- validator and by the shape checks below. A same-name index with a different
-- shape is not accepted: the attempted ADD then fails closed.
--
-- Data backfill is intentionally kept in migration.rs: it needs UUID payloads,
-- generation arithmetic, and one transaction spanning head/outbox rows. The
-- explicit migration job invokes it while MIGRATION_LOCK_NAME is held.

SET @astral_db = DATABASE();

-- Rust-owned durable audit correlation. It intentionally has no foreign key to
-- rule_set so DELETE history remains queryable after source deletion.
CREATE TABLE IF NOT EXISTS rule_set_projection_audit (
    audit_id BIGINT NOT NULL AUTO_INCREMENT,
    rule_set_id BIGINT NOT NULL,
    entry_id BIGINT NULL,
    changed_by BIGINT NOT NULL,
    change_type VARCHAR(32) NOT NULL,
    old_value_json TEXT NULL,
    new_value_json TEXT NULL,
    changed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    tenant_id BIGINT NULL,
    aggregate_type VARCHAR(32) NOT NULL,
    aggregate_id BIGINT NOT NULL,
    event_id VARCHAR(128) NOT NULL,
    source_generation BIGINT NOT NULL,
    operation_id VARCHAR(128) NOT NULL,
    PRIMARY KEY (audit_id),
    UNIQUE KEY uk_rsp_audit_event_generation (event_id, source_generation, change_type),
    KEY idx_rsp_audit_rule_set_generation (rule_set_id, source_generation),
    KEY idx_rsp_audit_operation (operation_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
 COMMENT='Rust-owned RuleSet source/projection audit correlation';

-- The creator migrations must have produced all six tables before this repair.
SET @astral_missing_tables =
    (SELECT COUNT(*) FROM (
        SELECT 'rule_set' AS table_name
        UNION ALL SELECT 'rule_set_entry'
        UNION ALL SELECT 'rule_set_snapshot'
        UNION ALL SELECT 'card_rule_set_ref'
        UNION ALL SELECT 'authorization_projection_head'
        UNION ALL SELECT 'authorization_projection_outbox'
    ) AS required_tables
    LEFT JOIN information_schema.TABLES t
      ON t.TABLE_SCHEMA = @astral_db
     AND t.TABLE_NAME = required_tables.table_name
     AND t.TABLE_TYPE = 'BASE TABLE'
    WHERE t.TABLE_NAME IS NULL);
SET @astral_sql = IF(@astral_missing_tables = 0,
    'SELECT 1',
    'THIS IS AN INTENTIONAL SCHEMA CONTRACT FAILURE');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

-- Required source/head/outbox columns are not reconstructed by a repair.
-- projection_generation is the sole additive column owned by this migration.
SET @astral_missing_columns =
    (SELECT COUNT(*) FROM (
        SELECT 'rule_set' AS table_name, 'rule_set_id' AS column_name
        UNION ALL SELECT 'rule_set', 'name'
        UNION ALL SELECT 'rule_set', 'code'
        UNION ALL SELECT 'rule_set', 'source_type'
        UNION ALL SELECT 'rule_set', 'source_id'
        UNION ALL SELECT 'rule_set', 'enabled'
        UNION ALL SELECT 'rule_set', 'tenant_id'
        UNION ALL SELECT 'rule_set_entry', 'entry_id'
        UNION ALL SELECT 'rule_set_entry', 'rule_set_id'
        UNION ALL SELECT 'rule_set_entry', 'resource_type'
        UNION ALL SELECT 'rule_set_entry', 'resource_id'
        UNION ALL SELECT 'rule_set_entry', 'action_code'
        UNION ALL SELECT 'rule_set_entry', 'effect'
        UNION ALL SELECT 'rule_set_entry', 'condition_json'
        UNION ALL SELECT 'rule_set_entry', 'priority'
        UNION ALL SELECT 'rule_set_entry', 'enabled'
        UNION ALL SELECT 'rule_set_entry', 'valid_from'
        UNION ALL SELECT 'rule_set_entry', 'valid_to'
        UNION ALL SELECT 'rule_set_entry', 'tenant_id'
        UNION ALL SELECT 'rule_set_snapshot', 'snapshot_id'
        UNION ALL SELECT 'rule_set_snapshot', 'rule_set_id'
        UNION ALL SELECT 'rule_set_snapshot', 'resource_key'
        UNION ALL SELECT 'rule_set_snapshot', 'action_code'
        UNION ALL SELECT 'rule_set_snapshot', 'final_effect'
        UNION ALL SELECT 'rule_set_snapshot', 'entry_id'
        UNION ALL SELECT 'rule_set_snapshot', 'version_no'
        UNION ALL SELECT 'rule_set_snapshot', 'tenant_id'
        UNION ALL SELECT 'card_rule_set_ref', 'id'
        UNION ALL SELECT 'card_rule_set_ref', 'card_id'
        UNION ALL SELECT 'card_rule_set_ref', 'rule_set_id'
        UNION ALL SELECT 'card_rule_set_ref', 'ref_type'
        UNION ALL SELECT 'card_rule_set_ref', 'tenant_id'
        UNION ALL SELECT 'authorization_projection_head', 'head_id'
        UNION ALL SELECT 'authorization_projection_head', 'aggregate_type'
        UNION ALL SELECT 'authorization_projection_head', 'aggregate_id'
        UNION ALL SELECT 'authorization_projection_head', 'source_generation'
        UNION ALL SELECT 'authorization_projection_head', 'projected_generation'
        UNION ALL SELECT 'authorization_projection_head', 'revoke_fence'
        UNION ALL SELECT 'authorization_projection_head', 'projection_status'
        UNION ALL SELECT 'authorization_projection_head', 'last_event_id'
        UNION ALL SELECT 'authorization_projection_head', 'last_error'
        UNION ALL SELECT 'authorization_projection_head', 'created_at'
        UNION ALL SELECT 'authorization_projection_head', 'updated_at'
        UNION ALL SELECT 'authorization_projection_outbox', 'outbox_id'
        UNION ALL SELECT 'authorization_projection_outbox', 'event_id'
        UNION ALL SELECT 'authorization_projection_outbox', 'aggregate_type'
        UNION ALL SELECT 'authorization_projection_outbox', 'aggregate_id'
        UNION ALL SELECT 'authorization_projection_outbox', 'tenant_id'
        UNION ALL SELECT 'authorization_projection_outbox', 'event_type'
        UNION ALL SELECT 'authorization_projection_outbox', 'source_generation'
        UNION ALL SELECT 'authorization_projection_outbox', 'sequence_number'
        UNION ALL SELECT 'authorization_projection_outbox', 'revoke_fence'
        UNION ALL SELECT 'authorization_projection_outbox', 'payload_json'
        UNION ALL SELECT 'authorization_projection_outbox', 'status'
        UNION ALL SELECT 'authorization_projection_outbox', 'attempts'
        UNION ALL SELECT 'authorization_projection_outbox', 'next_attempt_at'
        UNION ALL SELECT 'authorization_projection_outbox', 'lease_owner'
        UNION ALL SELECT 'authorization_projection_outbox', 'lease_expires_at'
        UNION ALL SELECT 'authorization_projection_outbox', 'processed_at'
        UNION ALL SELECT 'authorization_projection_outbox', 'processed_by'
        UNION ALL SELECT 'authorization_projection_outbox', 'terminal_transitions'
        UNION ALL SELECT 'authorization_projection_outbox', 'last_error'
        UNION ALL SELECT 'authorization_projection_outbox', 'created_at'
        UNION ALL SELECT 'authorization_projection_outbox', 'updated_at'
    ) AS required_columns
    LEFT JOIN information_schema.COLUMNS c
      ON c.TABLE_SCHEMA = @astral_db
     AND c.TABLE_NAME = required_columns.table_name
     AND c.COLUMN_NAME = required_columns.column_name
    WHERE c.COLUMN_NAME IS NULL);
SET @astral_sql = IF(@astral_missing_columns = 0,
    'SELECT 1',
    'THIS IS AN INTENTIONAL SCHEMA CONTRACT FAILURE');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

-- Add the generation fence only when it is absent. Existing rows receive the
-- fail-closed sentinel 0; the post-migration Rust backfill then enqueues a
-- RULE_SET rebuild before any old snapshot can be considered proven.
SET @astral_count = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'rule_set_snapshot'
      AND COLUMN_NAME = 'projection_generation');
SET @astral_sql = IF(@astral_count = 0,
    'ALTER TABLE rule_set_snapshot ADD COLUMN projection_generation BIGINT NOT NULL DEFAULT 0',
    'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

-- Index repair is conditional on the exact column order and uniqueness. The
-- accepted aliases preserve platform-v5/test-export adoption without renaming
-- existing baseline indexes.

-- rule_set
SET @astral_index = (SELECT COUNT(*) FROM (
    SELECT INDEX_NAME FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'rule_set'
      AND INDEX_NAME IN ('uk_rule_set_code') AND NON_UNIQUE = 0
    GROUP BY INDEX_NAME
    HAVING COUNT(*) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 1 AND COLUMN_NAME = 'code' THEN 1 ELSE 0 END) = 1
) AS matching_index);
SET @astral_sql = IF(@astral_index = 0,
    'ALTER TABLE rule_set ADD UNIQUE INDEX uk_rule_set_code (code)',
    'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_index = (SELECT COUNT(*) FROM (
    SELECT INDEX_NAME FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'rule_set'
      AND INDEX_NAME IN ('idx_rule_set_source') AND NON_UNIQUE = 1
    GROUP BY INDEX_NAME
    HAVING COUNT(*) = 2
       AND MAX(CASE WHEN SEQ_IN_INDEX = 1 AND COLUMN_NAME = 'source_type' THEN 1 ELSE 0 END) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 2 AND COLUMN_NAME = 'source_id' THEN 1 ELSE 0 END) = 1
) AS matching_index);
SET @astral_sql = IF(@astral_index = 0,
    'ALTER TABLE rule_set ADD INDEX idx_rule_set_source (source_type, source_id)',
    'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

-- rule_set_entry
SET @astral_index = (SELECT COUNT(*) FROM (
    SELECT INDEX_NAME FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'rule_set_entry'
      AND INDEX_NAME IN ('idx_rule_set_entry') AND NON_UNIQUE = 1
    GROUP BY INDEX_NAME
    HAVING COUNT(*) = 3
       AND MAX(CASE WHEN SEQ_IN_INDEX = 1 AND COLUMN_NAME = 'rule_set_id' THEN 1 ELSE 0 END) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 2 AND COLUMN_NAME = 'enabled' THEN 1 ELSE 0 END) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 3 AND COLUMN_NAME = 'priority' THEN 1 ELSE 0 END) = 1
) AS matching_index);
SET @astral_sql = IF(@astral_index = 0,
    'ALTER TABLE rule_set_entry ADD INDEX idx_rule_set_entry (rule_set_id, enabled, priority)',
    'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

-- card_rule_set_ref
SET @astral_index = (SELECT COUNT(*) FROM (
    SELECT INDEX_NAME FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'card_rule_set_ref'
      AND INDEX_NAME IN ('uk_card_rule_set') AND NON_UNIQUE = 0
    GROUP BY INDEX_NAME
    HAVING COUNT(*) = 2
       AND MAX(CASE WHEN SEQ_IN_INDEX = 1 AND COLUMN_NAME = 'card_id' THEN 1 ELSE 0 END) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 2 AND COLUMN_NAME = 'rule_set_id' THEN 1 ELSE 0 END) = 1
) AS matching_index);
SET @astral_sql = IF(@astral_index = 0,
    'ALTER TABLE card_rule_set_ref ADD UNIQUE INDEX uk_card_rule_set (card_id, rule_set_id)',
    'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_index = (SELECT COUNT(*) FROM (
    SELECT INDEX_NAME FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'card_rule_set_ref'
      AND INDEX_NAME IN ('idx_crsr_card') AND NON_UNIQUE = 1
    GROUP BY INDEX_NAME
    HAVING COUNT(*) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 1 AND COLUMN_NAME = 'card_id' THEN 1 ELSE 0 END) = 1
) AS matching_index);
SET @astral_sql = IF(@astral_index = 0,
    'ALTER TABLE card_rule_set_ref ADD INDEX idx_crsr_card (card_id)',
    'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_index = (SELECT COUNT(*) FROM (
    SELECT INDEX_NAME FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'card_rule_set_ref'
      AND INDEX_NAME IN ('idx_crsr_rule_set') AND NON_UNIQUE = 1
    GROUP BY INDEX_NAME
    HAVING COUNT(*) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 1 AND COLUMN_NAME = 'rule_set_id' THEN 1 ELSE 0 END) = 1
) AS matching_index);
SET @astral_sql = IF(@astral_index = 0,
    'ALTER TABLE card_rule_set_ref ADD INDEX idx_crsr_rule_set (rule_set_id)',
    'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

-- rule_set_snapshot; uk_snapshot is the historical platform-v4/test-export alias.
SET @astral_index = (SELECT COUNT(*) FROM (
    SELECT INDEX_NAME FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'rule_set_snapshot'
      AND INDEX_NAME IN ('uk_rule_set_snapshot', 'uk_snapshot') AND NON_UNIQUE = 0
    GROUP BY INDEX_NAME
    HAVING COUNT(*) = 3
       AND MAX(CASE WHEN SEQ_IN_INDEX = 1 AND COLUMN_NAME = 'rule_set_id' THEN 1 ELSE 0 END) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 2 AND COLUMN_NAME = 'resource_key' THEN 1 ELSE 0 END) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 3 AND COLUMN_NAME = 'action_code' THEN 1 ELSE 0 END) = 1
) AS matching_index);
SET @astral_sql = IF(@astral_index = 0,
    'ALTER TABLE rule_set_snapshot ADD UNIQUE INDEX uk_rule_set_snapshot (rule_set_id, resource_key, action_code)',
    'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_index = (SELECT COUNT(*) FROM (
    SELECT INDEX_NAME FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'rule_set_snapshot'
      AND INDEX_NAME IN ('idx_rss_rule_set') AND NON_UNIQUE = 1
    GROUP BY INDEX_NAME
    HAVING COUNT(*) = 2
       AND MAX(CASE WHEN SEQ_IN_INDEX = 1 AND COLUMN_NAME = 'rule_set_id' THEN 1 ELSE 0 END) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 2 AND COLUMN_NAME = 'action_code' THEN 1 ELSE 0 END) = 1
) AS matching_index);
SET @astral_sql = IF(@astral_index = 0,
    'ALTER TABLE rule_set_snapshot ADD INDEX idx_rss_rule_set (rule_set_id, action_code)',
    'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

-- authorization_projection_head; platform-v5 and Rust integration-test aliases
-- are accepted without renaming existing indexes.
SET @astral_index = (SELECT COUNT(*) FROM (
    SELECT INDEX_NAME FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'authorization_projection_head'
      AND INDEX_NAME IN ('uk_aph_aggregate', 'uk_test_projection_head', 'uk_projection_head') AND NON_UNIQUE = 0
    GROUP BY INDEX_NAME
    HAVING COUNT(*) = 2
       AND MAX(CASE WHEN SEQ_IN_INDEX = 1 AND COLUMN_NAME = 'aggregate_type' THEN 1 ELSE 0 END) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 2 AND COLUMN_NAME = 'aggregate_id' THEN 1 ELSE 0 END) = 1
) AS matching_index);
SET @astral_sql = IF(@astral_index = 0,
    'ALTER TABLE authorization_projection_head ADD UNIQUE INDEX uk_aph_aggregate (aggregate_type, aggregate_id)',
    'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_index = (SELECT COUNT(*) FROM (
    SELECT INDEX_NAME FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'authorization_projection_head'
      AND INDEX_NAME IN ('idx_aph_status') AND NON_UNIQUE = 1
    GROUP BY INDEX_NAME
    HAVING COUNT(*) = 2
       AND MAX(CASE WHEN SEQ_IN_INDEX = 1 AND COLUMN_NAME = 'projection_status' THEN 1 ELSE 0 END) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 2 AND COLUMN_NAME = 'updated_at' THEN 1 ELSE 0 END) = 1
) AS matching_index);
SET @astral_sql = IF(@astral_index = 0,
    'ALTER TABLE authorization_projection_head ADD INDEX idx_aph_status (projection_status, updated_at)',
    'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_index = (SELECT COUNT(*) FROM (
    SELECT INDEX_NAME FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'authorization_projection_head'
      AND INDEX_NAME IN ('idx_aph_generation') AND NON_UNIQUE = 1
    GROUP BY INDEX_NAME
    HAVING COUNT(*) = 3
       AND MAX(CASE WHEN SEQ_IN_INDEX = 1 AND COLUMN_NAME = 'aggregate_type' THEN 1 ELSE 0 END) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 2 AND COLUMN_NAME = 'source_generation' THEN 1 ELSE 0 END) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 3 AND COLUMN_NAME = 'projected_generation' THEN 1 ELSE 0 END) = 1
) AS matching_index);
SET @astral_sql = IF(@astral_index = 0,
    'ALTER TABLE authorization_projection_head ADD INDEX idx_aph_generation (aggregate_type, source_generation, projected_generation)',
    'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

-- authorization_projection_outbox; platform-v5/test-export names are accepted aliases.
SET @astral_index = (SELECT COUNT(*) FROM (
    SELECT INDEX_NAME FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'authorization_projection_outbox'
      AND INDEX_NAME IN ('uk_apob_event', 'uk_test_apob_event') AND NON_UNIQUE = 0
    GROUP BY INDEX_NAME
    HAVING COUNT(*) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 1 AND COLUMN_NAME = 'event_id' THEN 1 ELSE 0 END) = 1
) AS matching_index);
SET @astral_sql = IF(@astral_index = 0,
    'ALTER TABLE authorization_projection_outbox ADD UNIQUE INDEX uk_apob_event (event_id)',
    'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_index = (SELECT COUNT(*) FROM (
    SELECT INDEX_NAME FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'authorization_projection_outbox'
      AND INDEX_NAME IN ('uk_apob_generation_sequence', 'uk_test_apob_generation_sequence') AND NON_UNIQUE = 0
    GROUP BY INDEX_NAME
    HAVING COUNT(*) = 4
       AND MAX(CASE WHEN SEQ_IN_INDEX = 1 AND COLUMN_NAME = 'aggregate_type' THEN 1 ELSE 0 END) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 2 AND COLUMN_NAME = 'aggregate_id' THEN 1 ELSE 0 END) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 3 AND COLUMN_NAME = 'source_generation' THEN 1 ELSE 0 END) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 4 AND COLUMN_NAME = 'sequence_number' THEN 1 ELSE 0 END) = 1
) AS matching_index);
SET @astral_sql = IF(@astral_index = 0,
    'ALTER TABLE authorization_projection_outbox ADD UNIQUE INDEX uk_apob_generation_sequence (aggregate_type, aggregate_id, source_generation, sequence_number)',
    'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_index = (SELECT COUNT(*) FROM (
    SELECT INDEX_NAME FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'authorization_projection_outbox'
      AND INDEX_NAME IN ('idx_apob_pending', 'idx_test_apob_pending') AND NON_UNIQUE = 1
    GROUP BY INDEX_NAME
    HAVING COUNT(*) = 3
       AND MAX(CASE WHEN SEQ_IN_INDEX = 1 AND COLUMN_NAME = 'status' THEN 1 ELSE 0 END) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 2 AND COLUMN_NAME = 'next_attempt_at' THEN 1 ELSE 0 END) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 3 AND COLUMN_NAME = 'created_at' THEN 1 ELSE 0 END) = 1
) AS matching_index);
SET @astral_sql = IF(@astral_index = 0,
    'ALTER TABLE authorization_projection_outbox ADD INDEX idx_apob_pending (status, next_attempt_at, created_at)',
    'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_index = (SELECT COUNT(*) FROM (
    SELECT INDEX_NAME FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'authorization_projection_outbox'
      AND INDEX_NAME IN ('idx_apob_lease', 'idx_test_apob_lease') AND NON_UNIQUE = 1
    GROUP BY INDEX_NAME
    HAVING COUNT(*) = 3
       AND MAX(CASE WHEN SEQ_IN_INDEX = 1 AND COLUMN_NAME = 'status' THEN 1 ELSE 0 END) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 2 AND COLUMN_NAME = 'lease_expires_at' THEN 1 ELSE 0 END) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 3 AND COLUMN_NAME = 'outbox_id' THEN 1 ELSE 0 END) = 1
) AS matching_index);
SET @astral_sql = IF(@astral_index = 0,
    'ALTER TABLE authorization_projection_outbox ADD INDEX idx_apob_lease (status, lease_expires_at, outbox_id)',
    'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_index = (SELECT COUNT(*) FROM (
    SELECT INDEX_NAME FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'authorization_projection_outbox'
      AND INDEX_NAME IN ('idx_apob_aggregate', 'idx_test_apob_aggregate') AND NON_UNIQUE = 1
    GROUP BY INDEX_NAME
    HAVING COUNT(*) = 3
       AND MAX(CASE WHEN SEQ_IN_INDEX = 1 AND COLUMN_NAME = 'aggregate_type' THEN 1 ELSE 0 END) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 2 AND COLUMN_NAME = 'aggregate_id' THEN 1 ELSE 0 END) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 3 AND COLUMN_NAME = 'source_generation' THEN 1 ELSE 0 END) = 1
) AS matching_index);
SET @astral_sql = IF(@astral_index = 0,
    'ALTER TABLE authorization_projection_outbox ADD INDEX idx_apob_aggregate (aggregate_type, aggregate_id, source_generation)',
    'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;
