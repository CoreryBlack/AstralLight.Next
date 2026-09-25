-- Rust-owned monitor schema repair.
--
-- The historical 20240630000004_chat_monitor.sql and
-- 20240630000016_monitor_tables.sql are immutable: Java baseline adoption may
-- record them as applied even when their DDL was never replayed. This additive
-- migration recreates the canonical Rust monitor tables without altering any
-- existing table or introducing the obsolete Java monitor-rule foreign key.
-- CREATE TABLE IF NOT EXISTS makes fresh and repaired environments safe.

CREATE TABLE IF NOT EXISTS alert_rule (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    metric VARCHAR(128) NOT NULL,
    condition_op VARCHAR(16) NOT NULL DEFAULT '>=',
    threshold DOUBLE NOT NULL,
    duration_seconds INT NOT NULL DEFAULT 60,
    severity VARCHAR(32) NOT NULL DEFAULT 'WARNING',
    enabled TINYINT NOT NULL DEFAULT 1,
    created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS notification_channel (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    channel_type VARCHAR(32) NOT NULL DEFAULT 'EMAIL',
    config JSON,
    enabled TINYINT NOT NULL DEFAULT 1,
    created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS monitor_metric_snapshot (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    service_name VARCHAR(128) NOT NULL COMMENT '服务名称',
    metric_type VARCHAR(64) NOT NULL COMMENT '指标类型（latency / reachable / cpu_usage / memory_usage 等）',
    metric_value DOUBLE NOT NULL,
    collected_at TIMESTAMP NOT NULL COMMENT '采集时间',
    created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_mms_service (service_name),
    INDEX idx_mms_type (metric_type),
    INDEX idx_mms_collected (collected_at),
    INDEX idx_mms_service_type (service_name, metric_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS monitor_alert_history (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    rule_id BIGINT NOT NULL COMMENT '关联告警规则ID',
    rule_name VARCHAR(255) COMMENT '告警规则名称（快照）',
    metric_type VARCHAR(64) COMMENT '指标类型',
    actual_value DOUBLE COMMENT '触发时的实际值',
    severity VARCHAR(32) NOT NULL DEFAULT 'WARNING' COMMENT '严重级别',
    status VARCHAR(32) NOT NULL DEFAULT 'triggered' COMMENT 'triggered / acknowledged / resolved',
    triggered_at TIMESTAMP NOT NULL COMMENT '触发时间',
    resolved_at TIMESTAMP NULL COMMENT '确认/解决时间',
    created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_mah_rule (rule_id),
    INDEX idx_mah_status (status),
    INDEX idx_mah_severity (severity),
    INDEX idx_mah_triggered (triggered_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS monitor_activity_log (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    event_type VARCHAR(64) NOT NULL COMMENT '事件类型',
    title VARCHAR(255) COMMENT '事件标题',
    detail TEXT COMMENT '事件详情',
    level VARCHAR(16) NOT NULL DEFAULT 'info' COMMENT '级别（info / warn / error）',
    source_service VARCHAR(128) COMMENT '来源服务',
    occurred_at TIMESTAMP NOT NULL COMMENT '发生时间',
    created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_mal_event_type (event_type),
    INDEX idx_mal_level (level),
    INDEX idx_mal_source (source_service),
    INDEX idx_mal_occurred (occurred_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
