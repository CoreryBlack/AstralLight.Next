-- 补齐 permission_rule 和 permission_rule_template 的 enabled/resource_type/action_code 列
-- 对齐 Java PermissionRule.java / PermissionRuleTemplate.java 字段定义

-- permission_rule: 添加 enabled 列（幂等）
SET @db = (SELECT DATABASE());
SET @col = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'permission_rule' AND COLUMN_NAME = 'enabled');
SET @sql = IF(@col = 0, 'ALTER TABLE permission_rule ADD COLUMN enabled TINYINT NOT NULL DEFAULT 1', 'SELECT 1 AS enabled_exists');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- permission_rule_template: resource_type + action_code + priority + enabled
SET @col2 = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'permission_rule_template' AND COLUMN_NAME = 'resource_type');
SET @sql2 = IF(@col2 = 0, 'ALTER TABLE permission_rule_template ADD COLUMN resource_type VARCHAR(128) NULL, ADD COLUMN action_code VARCHAR(64) NULL, ADD COLUMN priority INT NOT NULL DEFAULT 0, ADD COLUMN enabled TINYINT NOT NULL DEFAULT 1', 'SELECT 1 AS resource_type_exists');
PREPARE stmt2 FROM @sql2; EXECUTE stmt2; DEALLOCATE PREPARE stmt2;

-- Indexes (幂等)
SET @idx1 = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'permission_rule' AND INDEX_NAME = 'idx_pr_enabled');
SET @sql3 = IF(@idx1 = 0, 'CREATE INDEX idx_pr_enabled ON permission_rule (enabled)', 'SELECT 1 AS idx_pr_enabled_exists');
PREPARE stmt3 FROM @sql3; EXECUTE stmt3; DEALLOCATE PREPARE stmt3;

SET @idx2 = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'permission_rule_template' AND INDEX_NAME = 'idx_prt_resource_type');
SET @sql4 = IF(@idx2 = 0, 'CREATE INDEX idx_prt_resource_type ON permission_rule_template (resource_type)', 'SELECT 1 AS idx_prt_resource_type_exists');
PREPARE stmt4 FROM @sql4; EXECUTE stmt4; DEALLOCATE PREPARE stmt4;

SET @idx3 = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'permission_rule_template' AND INDEX_NAME = 'idx_prt_enabled');
SET @sql5 = IF(@idx3 = 0, 'CREATE INDEX idx_prt_enabled ON permission_rule_template (enabled)', 'SELECT 1 AS idx_prt_enabled_exists');
PREPARE stmt5 FROM @sql5; EXECUTE stmt5; DEALLOCATE PREPARE stmt5;
