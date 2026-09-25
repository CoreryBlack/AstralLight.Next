-- 补充各表 deleted_at 列（代码中已引用但 baseline 遗漏）
-- 使用 information_schema 确保幂等

SET @db = (SELECT DATABASE());

-- user_card 表
SET @c1 = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'user_card' AND COLUMN_NAME = 'deleted_at');
SET @s1 = IF(@c1 = 0, 'ALTER TABLE user_card ADD COLUMN deleted_at TIMESTAMP NULL COMMENT ''软删除时间戳''', 'SELECT 1');
PREPARE p1 FROM @s1; EXECUTE p1; DEALLOCATE PREPARE p1;
