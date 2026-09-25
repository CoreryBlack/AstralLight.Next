-- Decommission the legacy snapshot tables (rule_set_snapshot /
-- permission_rule_snapshot / rule_set_snapshot_manifest) after the versioned
-- authorization projection chain cutover.
--
-- STANDBY SCRIPT. It is embedded and checksum-pinned like every Rust migration,
-- but it must only be executed (explicit isolated migration job or operator
-- runbook) after ALL of the following hold on the target database:
--   1. The Rust-owned canonical chain (authorization_grant_revision /
--      authorization_delta_event / authorization_projection_current) is the
--      only authorization read path; the legacy snapshot readers
--      (permission_query.rs / repository.rs legacy selects, the policy-engine
--      L1 RULE_SET dependency gate, the identity effective-permission
--      fallback) are removed or permanently disabled. As of read-chain switch
--      batch 3.5 the last Rust consumers (repository.rs load_snapshot_winners
--      and the policy-engine dependency gate / ALLOW recheck) are removed.
--   2. The legacy CARD/RULE_SET projection worker no longer writes
--      permission_rule_snapshot / rule_set_snapshot, and the retired
--      write_rule_set_snapshot_manifest_in_tx path no longer writes
--      rule_set_snapshot_manifest (no pending or replayable
--      authorization_projection_outbox event rebuilds them).
--   3. A backup of all three tables exists and the rollback block below has
--      been rehearsed (Docs/迁移 preflight/backup/recovery requirements).
--
-- Dropping these tables while any legacy reader or the legacy worker is still
-- active breaks authorization evaluation. This migration intentionally does
-- NOT touch authorization_projection_head / authorization_projection_outbox
-- (excluded: still written as writer correlation), rule_set_projection_audit,
-- or the incremental archive chain.
--
-- Safety properties:
--   - Guarded: a table is only dropped when it exists in the current schema.
--   - Idempotent: repeated execution converges to the same state (absent);
--     a manually pre-dropped database records a no-op success row.
--   - Rollback: the commented block below recreates all three tables with the
--     deployed shapes (platform-v5 plus the Rust additive columns for the two
--     legacy snapshot tables, and the 20260825000001 shape for the manifest).
--     Row data can only be
--     restored from the pre-DROP backup; unproven rows are rejected by the
--     generation/read gate, so no partial restore can resurrect an ALLOW.

SET @astral_db = DATABASE();

-- Guard + drop: rule_set_snapshot (legacy shared rule-set winner snapshot).
SET @astral_table_count = (
    SELECT COUNT(*) FROM information_schema.TABLES
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'rule_set_snapshot'
      AND TABLE_TYPE = 'BASE TABLE');
SET @astral_sql = IF(@astral_table_count = 1,
    'DROP TABLE rule_set_snapshot',
    'SELECT 1 AS rule_set_snapshot_already_absent');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

-- Guard + drop: permission_rule_snapshot (legacy per-card rule snapshot).
SET @astral_table_count = (
    SELECT COUNT(*) FROM information_schema.TABLES
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'permission_rule_snapshot'
      AND TABLE_TYPE = 'BASE TABLE');
SET @astral_sql = IF(@astral_table_count = 1,
    'DROP TABLE permission_rule_snapshot',
    'SELECT 1 AS permission_rule_snapshot_already_absent');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

-- Guard + drop: rule_set_snapshot_manifest (legacy generation-bound empty/
-- deleted RuleSet snapshot proof; its writer write_rule_set_snapshot_manifest_in_tx
-- was retired together with the legacy snapshot rebuild family).
SET @astral_table_count = (
    SELECT COUNT(*) FROM information_schema.TABLES
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'rule_set_snapshot_manifest'
      AND TABLE_TYPE = 'BASE TABLE');
SET @astral_sql = IF(@astral_table_count = 1,
    'DROP TABLE rule_set_snapshot_manifest',
    'SELECT 1 AS rule_set_snapshot_manifest_already_absent');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

-- ===== ROLLBACK (commented; rehearse statement-by-statement before use) =====
--
-- Recreates the deployed platform-v5 shape plus the Rust additive columns
-- (20260822000001 projection_generation, 20260822000002 validity windows), and
-- rule_set_snapshot_manifest in its exact 20260825000001 creator shape.
-- Requires rule_set to still exist (fk_rss_rule_set target). This restores
-- structure only: rows must come from the pre-DROP backup, and the legacy
-- projection worker (while still wired) or the documented rebuild job must
-- reproject the current generations before any legacy reader is re-enabled;
-- the read gate rejects rows whose projection_generation does not match the
-- READY head, so a stale restore fails closed instead of authorizing.
--
-- CREATE TABLE IF NOT EXISTS rule_set_snapshot (
--     snapshot_id BIGINT NOT NULL AUTO_INCREMENT,
--     rule_set_id BIGINT NOT NULL COMMENT '规则集ID',
--     resource_key VARCHAR(128) NOT NULL COMMENT 'resourceType:resourceId 或 resourceType:*',
--     action_code VARCHAR(64) NOT NULL COMMENT '动作编码',
--     final_effect VARCHAR(16) NOT NULL COMMENT 'ALLOW / DENY',
--     entry_id BIGINT NOT NULL COMMENT '来源条目ID',
--     version_no BIGINT NOT NULL DEFAULT 0 COMMENT '版本号',
--     created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
--     updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
--     tenant_id BIGINT DEFAULT NULL,
--     projection_generation BIGINT NOT NULL DEFAULT 0,
--     valid_from DATETIME NULL,
--     valid_to DATETIME NULL,
--     PRIMARY KEY (snapshot_id),
--     UNIQUE KEY uk_rule_set_snapshot (rule_set_id, resource_key, action_code),
--     KEY idx_rss_rule_set (rule_set_id, action_code),
--     CONSTRAINT fk_rss_rule_set FOREIGN KEY (rule_set_id)
--         REFERENCES rule_set (rule_set_id) ON DELETE CASCADE
-- ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
--   COMMENT='规则集快照（decommission rollback rebuild）';
--
-- CREATE TABLE IF NOT EXISTS permission_rule_snapshot (
--     snapshot_id BIGINT NOT NULL AUTO_INCREMENT,
--     card_id BIGINT NOT NULL,
--     resource_key VARCHAR(128) NOT NULL COMMENT 'resource_type:resource_id',
--     action_code VARCHAR(64) NOT NULL,
--     final_effect VARCHAR(16) NOT NULL COMMENT 'ALLOW / DENY',
--     rule_id BIGINT NOT NULL,
--     version_no BIGINT NOT NULL DEFAULT 0,
--     created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
--     updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
--     tenant_id BIGINT DEFAULT NULL,
--     valid_from DATETIME NULL,
--     valid_to DATETIME NULL,
--     PRIMARY KEY (snapshot_id),
--     UNIQUE KEY uk_permission_rule_snapshot (card_id, resource_key, action_code),
--     KEY idx_permission_rule_snapshot_card (card_id, action_code)
-- ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
--   COMMENT='权限规则快照表（decommission rollback rebuild）';
--
-- CREATE TABLE IF NOT EXISTS rule_set_snapshot_manifest (
--     rule_set_id          BIGINT NOT NULL,
--     projection_generation BIGINT NOT NULL,
--     status               VARCHAR(16) NOT NULL,
--     tenant_id            BIGINT NULL,
--     event_id             VARCHAR(128) NOT NULL,
--     operation_id         VARCHAR(128) NOT NULL,
--     committed_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
--     PRIMARY KEY (rule_set_id, projection_generation),
--     KEY idx_rssm_event (event_id),
--     KEY idx_rssm_operation (operation_id)
-- ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
--   COMMENT='Rust-owned generation-bound empty/deleted RuleSet snapshot proof';
