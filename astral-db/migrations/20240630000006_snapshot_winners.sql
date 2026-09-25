-- 为 rule_set_snapshot 添加预计算胜者字段（幂等）
-- 对齐 Java rule_set_snapshot.final_effect 语义

SET @db = (SELECT DATABASE());
SET @col = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'rule_set_snapshot' AND COLUMN_NAME = 'resource_key');
SET @sql = IF(@col = 0,
    'ALTER TABLE rule_set_snapshot ADD COLUMN resource_key VARCHAR(255), ADD COLUMN action_code VARCHAR(64), ADD COLUMN final_effect VARCHAR(8)',
    'SELECT 1 AS resource_key_exists');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @idx = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'rule_set_snapshot' AND INDEX_NAME = 'idx_rss_lookup');
SET @sql2 = IF(@idx = 0, 'CREATE INDEX idx_rss_lookup ON rule_set_snapshot (rule_set_id, resource_key, action_code)', 'SELECT 1 AS idx_rss_lookup_exists');
PREPARE stmt2 FROM @sql2; EXECUTE stmt2; DEALLOCATE PREPARE stmt2;
