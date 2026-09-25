-- 副作用补偿表（对齐 Java 补偿任务机制）
-- 用于记录快照重建、缓存清除等副作用失败后的补偿信息
CREATE TABLE IF NOT EXISTS pending_compensation (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    entity_id BIGINT NOT NULL COMMENT '关联实体 ID（card_id / rule_set_id）',
    op_type VARCHAR(64) NOT NULL COMMENT '操作类型：REBUILD_SNAPSHOT / EVICT_CACHE / FIND_BOUND_CARDS',
    error_msg TEXT COMMENT '错误信息',
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING' COMMENT 'PENDING / COMPLETED / FAILED',
    retry_count INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_status (status),
    INDEX idx_entity (entity_id)
);
