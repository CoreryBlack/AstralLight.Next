-- 为 chat_message 添加 status 字段，支持软删除（status='RECALLED'）
SET @db = (SELECT DATABASE());
SET @col = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'chat_message' AND COLUMN_NAME = 'status');
SET @sql = IF(@col = 0, 'ALTER TABLE chat_message ADD COLUMN status VARCHAR(16) NOT NULL DEFAULT ''ACTIVE''', 'SELECT 1 AS status_exists');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @db = (SELECT DATABASE());
SET @idx = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'chat_message' AND INDEX_NAME = 'idx_cm_status');
SET @sql = IF(@idx = 0, 'CREATE INDEX idx_cm_status ON chat_message (status)', 'SELECT 1 AS idx_cm_status_exists');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- 为 chat_session_member 添加 left_at 字段
SET @db = (SELECT DATABASE());
SET @col = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'chat_session_member' AND COLUMN_NAME = 'left_at');
SET @sql = IF(@col = 0, 'ALTER TABLE chat_session_member ADD COLUMN left_at TIMESTAMP NULL DEFAULT NULL', 'SELECT 1 AS left_at_exists');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
