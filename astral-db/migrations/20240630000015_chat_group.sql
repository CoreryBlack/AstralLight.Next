-- Group support: 群组专属字段
-- chat_session 增加群组专属字段
SET @db = (SELECT DATABASE());
SET @col = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'chat_session' AND COLUMN_NAME = 'owner_id');
SET @sql = IF(@col = 0, 'ALTER TABLE chat_session ADD COLUMN owner_id BIGINT NULL, ADD COLUMN group_avatar VARCHAR(255) NULL, ADD COLUMN max_members INT NOT NULL DEFAULT 500, ADD COLUMN status VARCHAR(16) NOT NULL DEFAULT ''ACTIVE''', 'SELECT 1 AS owner_id_exists');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @db = (SELECT DATABASE());
SET @idx = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'chat_session' AND INDEX_NAME = 'idx_owner');
SET @sql = IF(@idx = 0, 'ALTER TABLE chat_session ADD INDEX idx_owner (owner_id);', 'SELECT 1 AS idx_owner_exists');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @db = (SELECT DATABASE());
SET @idx = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'chat_session' AND INDEX_NAME = 'idx_status');
SET @sql = IF(@idx = 0, 'ALTER TABLE chat_session ADD INDEX idx_status (status);', 'SELECT 1 AS idx_status_exists');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- chat_session_member 增加角色字段
SET @db = (SELECT DATABASE());
SET @col = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'chat_session_member' AND COLUMN_NAME = 'role');
SET @sql = IF(@col = 0, 'ALTER TABLE chat_session_member ADD COLUMN role VARCHAR(16) NOT NULL DEFAULT ''MEMBER'', ADD COLUMN nickname VARCHAR(50) NULL, ADD COLUMN muted TINYINT NOT NULL DEFAULT 0, ADD COLUMN pinned TINYINT NOT NULL DEFAULT 0, ADD COLUMN joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, ADD COLUMN invite_by BIGINT NULL', 'SELECT 1 AS role_exists');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @db = (SELECT DATABASE());
SET @idx = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'chat_session_member' AND INDEX_NAME = 'idx_role');
SET @sql = IF(@idx = 0, 'ALTER TABLE chat_session_member ADD INDEX idx_role (role);', 'SELECT 1 AS idx_role_exists');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- 客户端会话追踪表（WebSocket 连接追踪）
CREATE TABLE IF NOT EXISTS chat_client_session (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    client_type VARCHAR(32) NOT NULL DEFAULT 'WEB' COMMENT '客户端类型: WEB / MOBILE / DESKTOP',
    device_id VARCHAR(100) NULL COMMENT '设备唯一标识',
    device_name VARCHAR(100) NULL COMMENT '设备名称',
    connection_id VARCHAR(100) NULL COMMENT 'WebSocket连接ID',
    status VARCHAR(16) NOT NULL DEFAULT 'ONLINE' COMMENT '状态: ONLINE / OFFLINE',
    last_active_at TIMESTAMP NULL COMMENT '最后活跃时间',
    push_token VARCHAR(200) NULL COMMENT '推送Token',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_user_client_device (user_id, client_type, device_id),
    INDEX idx_user (user_id),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='客户端会话追踪表';
