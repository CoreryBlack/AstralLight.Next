-- 扩展 audit_log 表（对齐 Java AuditService 完整字段）
-- 新增 event_type/source_ip/request_id/domain_id/tenant_id 列

SET @db = (SELECT DATABASE());

SET @c1 = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'event_type');
SET @s1 = IF(@c1 = 0, 'ALTER TABLE audit_log ADD COLUMN event_type VARCHAR(32) NULL', 'SELECT 1');
PREPARE p1 FROM @s1; EXECUTE p1; DEALLOCATE PREPARE p1;

SET @c2 = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'source_ip');
SET @s2 = IF(@c2 = 0, 'ALTER TABLE audit_log ADD COLUMN source_ip VARCHAR(64) NULL', 'SELECT 1');
PREPARE p2 FROM @s2; EXECUTE p2; DEALLOCATE PREPARE p2;

SET @c3 = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'request_id');
SET @s3 = IF(@c3 = 0, 'ALTER TABLE audit_log ADD COLUMN request_id VARCHAR(64) NULL', 'SELECT 1');
PREPARE p3 FROM @s3; EXECUTE p3; DEALLOCATE PREPARE p3;

SET @c4 = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'domain_id');
SET @s4 = IF(@c4 = 0, 'ALTER TABLE audit_log ADD COLUMN domain_id BIGINT NULL', 'SELECT 1');
PREPARE p4 FROM @s4; EXECUTE p4; DEALLOCATE PREPARE p4;

SET @c5 = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'tenant_id');
SET @s5 = IF(@c5 = 0, 'ALTER TABLE audit_log ADD COLUMN tenant_id BIGINT NULL', 'SELECT 1');
PREPARE p5 FROM @s5; EXECUTE p5; DEALLOCATE PREPARE p5;

SET @idx1 = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'audit_log' AND INDEX_NAME = 'idx_al_event_type');
SET @si1 = IF(@idx1 = 0, 'CREATE INDEX idx_al_event_type ON audit_log (event_type)', 'SELECT 1');
PREPARE pi1 FROM @si1; EXECUTE pi1; DEALLOCATE PREPARE pi1;

SET @idx2 = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'audit_log' AND INDEX_NAME = 'idx_al_tenant');
SET @si2 = IF(@idx2 = 0, 'CREATE INDEX idx_al_tenant ON audit_log (tenant_id)', 'SELECT 1');
PREPARE pi2 FROM @si2; EXECUTE pi2; DEALLOCATE PREPARE pi2;
