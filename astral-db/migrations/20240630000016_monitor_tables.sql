-- Phase 16: Monitor 补充表
-- Metric 快照、告警历史、活动日志（对应 Java AstralMonitor 的 monitor_metric_snapshot / monitor_alert_history / monitor_activity_log）

CREATE TABLE IF NOT EXISTS monitor_metric_snapshot (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    service_name VARCHAR(128) NOT NULL COMMENT '服务名称',
    metric_type VARCHAR(64) NOT NULL COMMENT '指标类型（latency / reachable / cpu_usage / memory_usage 等）',
    metric_value DOUBLE NOT NULL,
    collected_at TIMESTAMP NOT NULL COMMENT '采集时间',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_mms_service (service_name),
    INDEX idx_mms_type (metric_type),
    INDEX idx_mms_collected (collected_at),
    INDEX idx_mms_service_type (service_name, metric_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_mah_rule (rule_id),
    INDEX idx_mah_status (status),
    INDEX idx_mah_severity (severity),
    INDEX idx_mah_triggered (triggered_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS monitor_activity_log (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    event_type VARCHAR(64) NOT NULL COMMENT '事件类型',
    title VARCHAR(255) COMMENT '事件标题',
    detail TEXT COMMENT '事件详情',
    level VARCHAR(16) NOT NULL DEFAULT 'info' COMMENT '级别（info / warn / error）',
    source_service VARCHAR(128) COMMENT '来源服务',
    occurred_at TIMESTAMP NOT NULL COMMENT '发生时间',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_mal_event_type (event_type),
    INDEX idx_mal_level (level),
    INDEX idx_mal_source (source_service),
    INDEX idx_mal_occurred (occurred_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
