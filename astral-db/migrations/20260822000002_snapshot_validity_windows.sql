-- Rust-owned additive repair for snapshot validity windows.
--
-- The source tables already carry valid_from/valid_to, but the projection
-- tables historically discarded those windows. Keep the applied migrations
-- immutable and add nullable UTC DATETIME columns to both snapshot tables.
-- Every statement is conditional so a partially repaired schema can converge
-- without dropping or rewriting existing data.

SET @astral_db = DATABASE();

SET @astral_count = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'permission_rule_snapshot'
      AND COLUMN_NAME = 'valid_from'
);
SET @astral_sql = IF(@astral_count = 0,
    'ALTER TABLE permission_rule_snapshot ADD COLUMN valid_from DATETIME NULL',
    'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'permission_rule_snapshot'
      AND COLUMN_NAME = 'valid_to'
);
SET @astral_sql = IF(@astral_count = 0,
    'ALTER TABLE permission_rule_snapshot ADD COLUMN valid_to DATETIME NULL',
    'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'rule_set_snapshot'
      AND COLUMN_NAME = 'valid_from'
);
SET @astral_sql = IF(@astral_count = 0,
    'ALTER TABLE rule_set_snapshot ADD COLUMN valid_from DATETIME NULL',
    'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'rule_set_snapshot'
      AND COLUMN_NAME = 'valid_to'
);
SET @astral_sql = IF(@astral_count = 0,
    'ALTER TABLE rule_set_snapshot ADD COLUMN valid_to DATETIME NULL',
    'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

-- Existing rows are repaired only from their immutable source identity. Rows
-- whose source identity no longer exists are removed rather than being treated
-- as unbounded: formal readers cannot join raw source tables and must never
-- revive an unverifiable ALLOW.
UPDATE permission_rule_snapshot prs
LEFT JOIN permission_rule pr
       ON pr.rule_id = prs.rule_id
      AND pr.card_id = prs.card_id
SET prs.valid_from = pr.valid_from,
    prs.valid_to = pr.valid_to
WHERE pr.rule_id IS NOT NULL;
DELETE prs
FROM permission_rule_snapshot prs
LEFT JOIN permission_rule pr
       ON pr.rule_id = prs.rule_id
      AND pr.card_id = prs.card_id
WHERE pr.rule_id IS NULL;

UPDATE rule_set_snapshot rss
LEFT JOIN rule_set_entry rse
       ON rse.entry_id = rss.entry_id
      AND rse.rule_set_id = rss.rule_set_id
SET rss.valid_from = rse.valid_from,
    rss.valid_to = rse.valid_to
WHERE rse.entry_id IS NOT NULL;
DELETE rss
FROM rule_set_snapshot rss
LEFT JOIN rule_set_entry rse
       ON rse.entry_id = rss.entry_id
      AND rse.rule_set_id = rss.rule_set_id
WHERE rse.entry_id IS NULL;
