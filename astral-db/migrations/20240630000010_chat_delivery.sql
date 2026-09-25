-- 消息投递追踪表（对齐 Java ChatDeliveryService）
CREATE TABLE IF NOT EXISTS chat_delivery (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    message_id BIGINT NOT NULL,
    recipient_id BIGINT NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'PENDING',
    delivered_at TIMESTAMP NULL,
    read_at TIMESTAMP NULL,
    INDEX idx_cd_message (message_id),
    INDEX idx_cd_recipient (recipient_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 会话最后消息追踪（对齐 Java ChatConversation.lastMessageId）
SET @db = (SELECT DATABASE());

SET @col1 = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'chat_session' AND COLUMN_NAME = 'last_message_id');
SET @sql1 = IF(@col1 = 0, 'ALTER TABLE chat_session ADD COLUMN last_message_id BIGINT NULL', 'SELECT 1 AS last_message_id_exists');
PREPARE stmt1 FROM @sql1; EXECUTE stmt1; DEALLOCATE PREPARE stmt1;

SET @col2 = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'chat_session' AND COLUMN_NAME = 'last_message_at');
SET @sql2 = IF(@col2 = 0, 'ALTER TABLE chat_session ADD COLUMN last_message_at TIMESTAMP NULL', 'SELECT 1 AS last_message_at_exists');
PREPARE stmt2 FROM @sql2; EXECUTE stmt2; DEALLOCATE PREPARE stmt2;
