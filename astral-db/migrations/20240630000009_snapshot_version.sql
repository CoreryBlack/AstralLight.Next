-- 乐观锁版本号（对齐 Java 快照重建的增量/全量回退策略）
SET @db = (SELECT DATABASE());

SET @col = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'permission_rule_snapshot' AND COLUMN_NAME = 'version_no');
SET @sql = IF(@col = 0, 'ALTER TABLE permission_rule_snapshot ADD COLUMN version_no BIGINT NOT NULL DEFAULT 0', 'SELECT 1 AS version_no_exists');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @idx = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'permission_rule_snapshot' AND INDEX_NAME = 'idx_prs_card_version');
SET @sql2 = IF(@idx = 0, 'CREATE INDEX idx_prs_card_version ON permission_rule_snapshot(card_id, version_no)', 'SELECT 1 AS idx_exists');
PREPARE stmt2 FROM @sql2; EXECUTE stmt2; DEALLOCATE PREPARE stmt2;
