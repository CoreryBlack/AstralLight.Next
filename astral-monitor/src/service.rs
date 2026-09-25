//! Monitor application service facade.
//!
//! Keeps Java `DashboardMonitoringService` / `AlertRuleService` behavior out
//! of HTTP handlers and converts persistence records to API DTOs.

use std::sync::Arc;

use astral_types::AstralError;

use crate::alerts::{
    ActivityLog, ActivityLogFilter, AlertHistory, AlertHistoryFilter, AlertRule, AlertRuleFilter,
    CreateAlertReq,
};
use crate::dashboard::{ActivityItem, AlertItem, MetricSnapshot, MetricsHistoryFilter};
use crate::dispatch::AlertNotification;
use crate::repository::{
    ActivityLogQuery, ActivityLogRecord, AlertHistoryQuery, AlertHistoryRecord, AlertRuleQuery,
    AlertRuleRecord, AlertRuleUpdate, MetricHistoryQuery, MetricSnapshotRecord, MonitorRepository,
    NotificationChannelRecord,
};

pub struct MonitorService {
    repository: Arc<dyn MonitorRepository>,
}

impl MonitorService {
    pub fn new(repository: Arc<dyn MonitorRepository>) -> Self {
        Self { repository }
    }

    pub async fn list_rules(&self, filter: AlertRuleFilter) -> Result<Vec<AlertRule>, AstralError> {
        Ok(self
            .repository
            .list_alert_rules(AlertRuleQuery {
                metric: filter.metric,
                enabled: filter.enabled,
            })
            .await?
            .into_iter()
            .map(AlertRule::from)
            .collect())
    }

    pub async fn create_rule(&self, request: CreateAlertReq) -> Result<AlertRule, AstralError> {
        let condition_op = request.condition_op.unwrap_or_else(|| ">=".into());
        let duration_seconds = request.duration_seconds.unwrap_or(60);
        let severity = request.severity.unwrap_or_else(|| "WARNING".into());
        self.repository
            .create_alert_rule(
                &request.name,
                &request.metric,
                &condition_op,
                request.threshold,
                duration_seconds,
                &severity,
            )
            .await
            .map(AlertRule::from)
    }

    pub async fn get_rule(&self, id: i64) -> Result<AlertRule, AstralError> {
        self.repository
            .get_alert_rule(id)
            .await?
            .map(AlertRule::from)
            .ok_or_else(|| AstralError::Validation("告警规则不存在".into()))
    }

    pub async fn update_rule(&self, id: i64, request: CreateAlertReq) -> Result<(), AstralError> {
        self.repository
            .update_alert_rule(AlertRuleUpdate {
                id,
                name: request.name,
                metric: request.metric,
                condition_op: request.condition_op.unwrap_or_else(|| ">=".into()),
                threshold: request.threshold,
                duration_seconds: request.duration_seconds.unwrap_or(60),
                severity: request.severity.unwrap_or_else(|| "WARNING".into()),
            })
            .await
    }

    pub async fn delete_rule(&self, id: i64) -> Result<(), AstralError> {
        self.repository.delete_alert_rule(id).await
    }

    pub async fn toggle_rule(&self, id: i64) -> Result<AlertRule, AstralError> {
        self.repository.toggle_alert_rule(id).await?;
        self.get_rule(id).await
    }

    pub async fn list_alert_history(
        &self,
        filter: AlertHistoryFilter,
    ) -> Result<Vec<AlertHistory>, AstralError> {
        Ok(self
            .repository
            .list_alert_history(AlertHistoryQuery {
                status: filter.status,
                severity: filter.severity,
                start_time: filter.start_time,
                end_time: filter.end_time,
                limit: filter.limit.unwrap_or(50).clamp(1, 200),
            })
            .await?
            .into_iter()
            .map(AlertHistory::from)
            .collect())
    }

    pub async fn acknowledge_alert(&self, id: i64) -> Result<(), AstralError> {
        self.repository.acknowledge_alert(id).await
    }

    pub async fn list_activity_logs(
        &self,
        filter: ActivityLogFilter,
    ) -> Result<Vec<ActivityLog>, AstralError> {
        Ok(self
            .repository
            .list_activity_logs(ActivityLogQuery {
                event_type: filter.event_type,
                level: filter.level,
                source_service: filter.source_service,
                start_time: filter.start_time,
                end_time: filter.end_time,
                limit: filter.limit.unwrap_or(50).clamp(1, 200),
            })
            .await?
            .into_iter()
            .map(ActivityLog::from)
            .collect())
    }

    pub async fn latest_metric(
        &self,
        service_name: &str,
        metric_type: &str,
    ) -> Result<Option<f64>, AstralError> {
        self.repository
            .latest_metric(service_name, metric_type)
            .await
    }

    pub async fn metric_history(
        &self,
        filter: MetricsHistoryFilter,
    ) -> Result<Vec<MetricSnapshot>, AstralError> {
        Ok(self
            .repository
            .metric_history(MetricHistoryQuery {
                service_name: filter.service_name,
                metric_type: filter.metric_type,
                start_time: filter.start_time,
                end_time: filter.end_time,
                limit: filter.limit.unwrap_or(100).clamp(1, 500),
            })
            .await?
            .into_iter()
            .map(MetricSnapshot::from)
            .collect())
    }

    pub async fn metric_trend(&self) -> Result<Vec<(i64, f64)>, AstralError> {
        self.repository.metric_trend().await
    }

    pub async fn dashboard_alerts(&self) -> Result<Vec<AlertItem>, AstralError> {
        Ok(self
            .repository
            .dashboard_alerts()
            .await?
            .into_iter()
            .map(|record| {
                let mut title = record
                    .rule_name
                    .unwrap_or_else(|| record.metric_type.unwrap_or_default());
                if let Some(value) = record.actual_value {
                    title.push_str(&format!(" ({value:.1})"));
                }
                AlertItem {
                    level: map_severity_to_level(&record.severity),
                    title,
                    time_ago: format_relative_time(record.triggered_at),
                }
            })
            .collect())
    }

    pub async fn dashboard_activities(&self) -> Result<Vec<ActivityItem>, AstralError> {
        Ok(self
            .repository
            .dashboard_activities()
            .await?
            .into_iter()
            .map(|record| ActivityItem {
                time_ago: format_relative_time(record.occurred_at),
                title: record.title.unwrap_or_default(),
                detail: record.detail.unwrap_or_default(),
                level: record.level,
            })
            .collect())
    }

    pub async fn recent_metric_count(&self) -> Result<i64, AstralError> {
        self.repository.recent_metric_count().await
    }

    pub async fn recent_metrics_summary(&self) -> Result<serde_json::Value, AstralError> {
        let (cpu, memory, disk, active_connections) = tokio::try_join!(
            self.repository.recent_metric("system", "cpu_usage"),
            self.repository.recent_metric("system", "memory_usage"),
            self.repository.recent_metric("system", "disk_usage"),
            self.repository
                .recent_metric("system", "active_connections"),
        )?;
        let has_data = cpu.is_some() || memory.is_some() || disk.is_some();
        Ok(serde_json::json!({
            "cpuUsage": cpu,
            "memoryUsage": memory,
            "diskUsage": disk,
            "activeConnections": active_connections.map(|value| value as i64),
            "dataStatus": if has_data { "OK" } else { "NO_DATA" },
        }))
    }

    pub async fn dashboard_summary(&self) -> Result<serde_json::Value, AstralError> {
        let (total, triggered) = self.repository.alert_counts().await?;
        let activities = self.repository.dashboard_activities().await?;
        Ok(serde_json::json!({
            "totalAlerts": total,
            "activeAlerts": triggered,
            "recentActivities": activities.into_iter().map(|activity| serde_json::json!({
                "type": activity.event_type,
                "title": activity.title,
                "detail": activity.detail,
                "level": activity.level,
            })).collect::<Vec<_>>(),
        }))
    }

    pub async fn list_notification_channels(
        &self,
    ) -> Result<Vec<crate::notifications::NotificationChannel>, AstralError> {
        Ok(self
            .repository
            .list_notification_channels()
            .await?
            .into_iter()
            .map(crate::notifications::NotificationChannel::from)
            .collect())
    }

    pub async fn get_notification_channel(
        &self,
        id: i64,
    ) -> Result<crate::notifications::NotificationChannel, AstralError> {
        self.repository
            .get_notification_channel(id)
            .await?
            .map(crate::notifications::NotificationChannel::from)
            .ok_or_else(|| AstralError::Validation("通知渠道不存在".into()))
    }

    pub async fn create_notification_channel(
        &self,
        name: &str,
        channel_type: &str,
        config: Option<&str>,
    ) -> Result<crate::notifications::NotificationChannel, AstralError> {
        self.repository
            .create_notification_channel(name, channel_type, config)
            .await
            .map(crate::notifications::NotificationChannel::from)
    }

    pub async fn update_notification_channel(
        &self,
        id: i64,
        name: &str,
        channel_type: &str,
        config: Option<&str>,
    ) -> Result<(), AstralError> {
        self.repository
            .update_notification_channel(id, name, channel_type, config)
            .await
    }

    pub async fn record_activity(
        &self,
        event_type: &str,
        title: &str,
        detail: &str,
        level: &str,
        source_service: &str,
    ) -> Result<(), AstralError> {
        self.repository
            .record_activity(event_type, title, detail, level, source_service)
            .await
    }

    // ===== 采集器编排（对应 Java MetricCollectService / AlertEvaluationTask） =====

    /// 写入 system 服务的 CPU/内存/磁盘使用率并记录采集活动日志。
    pub async fn collect_system_metrics(
        &self,
        cpu_percent: f64,
        memory_percent: f64,
        disk_percent: f64,
    ) -> Result<(), AstralError> {
        self.repository
            .insert_metric("system", "cpu_usage", cpu_percent.min(100.0))
            .await?;
        self.repository
            .insert_metric("system", "memory_usage", memory_percent.min(100.0))
            .await?;
        self.repository
            .insert_metric("system", "disk_usage", disk_percent.min(100.0))
            .await?;
        let detail =
            format!("CPU {cpu_percent:.0}% · 内存 {memory_percent:.0}% · 磁盘 {disk_percent:.0}%");
        self.repository
            .record_activity(
                "system_collect",
                "系统指标采集",
                &detail,
                "info",
                "astral-monitor",
            )
            .await?;
        Ok(())
    }

    /// 写入单个服务的 latency 与 reachable 指标。
    pub async fn collect_service_metrics(
        &self,
        service_name: &str,
        latency_ms: i64,
        reachable: bool,
    ) -> Result<(), AstralError> {
        self.repository
            .insert_metric(service_name, "latency", latency_ms as f64)
            .await?;
        self.repository
            .insert_metric(service_name, "reachable", if reachable { 1.0 } else { 0.0 })
            .await?;
        Ok(())
    }

    /// 写入 redis 服务的 6 个指标。
    #[allow(clippy::too_many_arguments)]
    pub async fn collect_redis_metrics(
        &self,
        hit_rate: f64,
        connected_clients: i64,
        used_memory_mb: f64,
        max_memory_mb: f64,
        key_count: i64,
    ) -> Result<(), AstralError> {
        self.repository
            .insert_metric("redis", "hit_rate", hit_rate)
            .await?;
        self.repository
            .insert_metric("redis", "connected_clients", connected_clients as f64)
            .await?;
        self.repository
            .insert_metric("redis", "used_memory_mb", used_memory_mb)
            .await?;
        self.repository
            .insert_metric("redis", "max_memory_mb", max_memory_mb)
            .await?;
        let memory_percent = if max_memory_mb > 0.0 {
            used_memory_mb * 100.0 / max_memory_mb
        } else {
            0.0
        };
        self.repository
            .insert_metric("redis", "memory_usage", memory_percent)
            .await?;
        self.repository
            .insert_metric("redis", "key_count", key_count as f64)
            .await?;
        Ok(())
    }

    /// 评估启用规则：近 `window_secs` 最新 metric → 条件判定 → 窗口去重 → 写告警历史。
    ///
    /// 返回本次新触发的告警（已去重、已持久化），由调用方负责通知派发；
    /// 派发不在此处执行，保证通知故障不进入评估路径。
    pub async fn evaluate_alert_rules(
        &self,
        window_secs: i64,
    ) -> Result<Vec<AlertNotification>, AstralError> {
        let rules = self
            .repository
            .list_alert_rules(AlertRuleQuery {
                metric: None,
                enabled: Some(1),
            })
            .await?;
        let mut triggered = Vec::new();
        if rules.is_empty() {
            return Ok(triggered);
        }

        let since = time::OffsetDateTime::now_utc() - time::Duration::seconds(window_secs);
        for rule in rules {
            let Some(value) = self
                .repository
                .find_latest_metric_by_type(&rule.metric, since)
                .await?
            else {
                continue;
            };
            if !evaluate_condition(value, &rule.condition_op, rule.threshold) {
                continue;
            }
            if self
                .repository
                .has_recent_triggered_alert(rule.id, since)
                .await?
            {
                continue;
            }
            self.repository
                .insert_alert_history(rule.id, &rule.name, &rule.metric, value, &rule.severity)
                .await?;
            metrics::counter!("astral_monitor_alerts_triggered_total", "severity" => rule.severity.clone())
                .increment(1);
            triggered.push(AlertNotification {
                rule_id: rule.id,
                rule_name: rule.name.clone(),
                metric: rule.metric.clone(),
                actual_value: value,
                severity: rule.severity.clone(),
                triggered_at: time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
            });
        }
        Ok(triggered)
    }

    /// 每日清理：删除 7 天前指标快照与 30 天前告警历史。
    pub async fn cleanup_old_data(&self) -> Result<(), AstralError> {
        let metrics_deleted = self.repository.delete_metrics_older_than_days(7).await?;
        let alerts_deleted = self
            .repository
            .delete_alert_history_older_than_days(30)
            .await?;
        tracing::info!(metrics_deleted, alerts_deleted, "monitor data cleanup");
        Ok(())
    }
}

/// 条件判定（对齐 Java `AlertEvaluationTask.evaluateCondition`）。
/// 兼容 `>=`/`>`/`<=`/`<`/`==` 与 `gte/gt/lte/lt/eq`；未知 operator 返回 false。
fn evaluate_condition(value: f64, condition_op: &str, threshold: f64) -> bool {
    match condition_op.trim().to_lowercase().as_str() {
        ">=" | "gte" => value >= threshold,
        ">" | "gt" => value > threshold,
        "<=" | "lte" => value <= threshold,
        "<" | "lt" => value < threshold,
        "==" | "eq" => (value - threshold).abs() < 0.001,
        _ => false,
    }
}

impl From<NotificationChannelRecord> for crate::notifications::NotificationChannel {
    fn from(record: NotificationChannelRecord) -> Self {
        Self {
            id: record.id,
            name: record.name,
            channel_type: record.channel_type,
            config: record.config,
            enabled: record.enabled,
        }
    }
}

impl From<AlertRuleRecord> for AlertRule {
    fn from(record: AlertRuleRecord) -> Self {
        Self {
            id: record.id,
            name: record.name,
            metric: record.metric,
            condition_op: record.condition_op,
            threshold: record.threshold,
            duration_seconds: record.duration_seconds,
            severity: record.severity,
            enabled: record.enabled,
        }
    }
}

impl From<AlertHistoryRecord> for AlertHistory {
    fn from(record: AlertHistoryRecord) -> Self {
        Self {
            id: record.id,
            rule_id: record.rule_id,
            rule_name: record.rule_name,
            metric_type: record.metric_type,
            actual_value: record.actual_value,
            severity: record.severity,
            status: record.status,
            triggered_at: record.triggered_at,
            resolved_at: record.resolved_at,
        }
    }
}

impl From<ActivityLogRecord> for ActivityLog {
    fn from(record: ActivityLogRecord) -> Self {
        Self {
            id: record.id,
            event_type: record.event_type,
            title: record.title,
            detail: record.detail,
            level: record.level,
            source_service: record.source_service,
            occurred_at: record.occurred_at,
        }
    }
}

impl From<MetricSnapshotRecord> for MetricSnapshot {
    fn from(record: MetricSnapshotRecord) -> Self {
        Self {
            id: record.id,
            service_name: record.service_name,
            metric_type: record.metric_type,
            metric_value: record.metric_value,
            collected_at: record.collected_at,
        }
    }
}

fn map_severity_to_level(severity: &str) -> String {
    match severity.to_lowercase().as_str() {
        "critical" => "error".into(),
        "warning" => "warn".into(),
        _ => "info".into(),
    }
}

fn format_relative_time(timestamp: time::OffsetDateTime) -> String {
    let seconds = (time::OffsetDateTime::now_utc() - timestamp)
        .whole_seconds()
        .max(0);
    if seconds < 60 {
        format!("{} 秒前", seconds)
    } else if seconds < 3600 {
        format!("{} 分钟前", seconds / 60)
    } else if seconds < 86400 {
        format!("{} 小时前", seconds / 3600)
    } else {
        format!("{} 天前", seconds / 86400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Mutex;

    struct FakeMonitorRepository {
        last_rule_query: Mutex<Option<AlertRuleQuery>>,
        latest_metric: Mutex<Option<f64>>,
        recent_alert: Mutex<bool>,
        inserted_alerts: Mutex<Vec<String>>,
    }

    fn fake_repository() -> FakeMonitorRepository {
        FakeMonitorRepository {
            last_rule_query: Mutex::new(None),
            latest_metric: Mutex::new(None),
            recent_alert: Mutex::new(false),
            inserted_alerts: Mutex::new(Vec::new()),
        }
    }

    fn rule_record() -> AlertRuleRecord {
        AlertRuleRecord {
            id: 7,
            name: "CPU high".into(),
            metric: "cpu_usage".into(),
            condition_op: ">=".into(),
            threshold: 80.0,
            duration_seconds: 60,
            severity: "WARNING".into(),
            enabled: 1,
        }
    }

    #[async_trait]
    impl MonitorRepository for FakeMonitorRepository {
        async fn list_alert_rules(
            &self,
            query: AlertRuleQuery,
        ) -> Result<Vec<AlertRuleRecord>, AstralError> {
            *self.last_rule_query.lock().unwrap() = Some(query);
            Ok(vec![rule_record()])
        }

        async fn create_alert_rule(
            &self,
            _name: &str,
            _metric: &str,
            _condition_op: &str,
            _threshold: f64,
            _duration_seconds: i32,
            _severity: &str,
        ) -> Result<AlertRuleRecord, AstralError> {
            Ok(rule_record())
        }

        async fn get_alert_rule(&self, _id: i64) -> Result<Option<AlertRuleRecord>, AstralError> {
            Ok(Some(rule_record()))
        }

        async fn update_alert_rule(&self, _update: AlertRuleUpdate) -> Result<(), AstralError> {
            Ok(())
        }

        async fn delete_alert_rule(&self, _id: i64) -> Result<(), AstralError> {
            Ok(())
        }

        async fn toggle_alert_rule(&self, _id: i64) -> Result<(), AstralError> {
            Ok(())
        }

        async fn list_alert_history(
            &self,
            _query: AlertHistoryQuery,
        ) -> Result<Vec<AlertHistoryRecord>, AstralError> {
            Ok(vec![])
        }

        async fn acknowledge_alert(&self, _id: i64) -> Result<(), AstralError> {
            Ok(())
        }

        async fn list_activity_logs(
            &self,
            _query: ActivityLogQuery,
        ) -> Result<Vec<ActivityLogRecord>, AstralError> {
            Ok(vec![])
        }

        async fn latest_metric(
            &self,
            _service_name: &str,
            _metric_type: &str,
        ) -> Result<Option<f64>, AstralError> {
            Ok(None)
        }

        async fn recent_metric(
            &self,
            _service_name: &str,
            _metric_type: &str,
        ) -> Result<Option<f64>, AstralError> {
            Ok(None)
        }

        async fn metric_history(
            &self,
            _query: MetricHistoryQuery,
        ) -> Result<Vec<MetricSnapshotRecord>, AstralError> {
            Ok(vec![])
        }

        async fn metric_trend(&self) -> Result<Vec<(i64, f64)>, AstralError> {
            Ok(vec![])
        }

        async fn dashboard_alerts(&self) -> Result<Vec<AlertHistoryRecord>, AstralError> {
            Ok(vec![])
        }

        async fn dashboard_activities(&self) -> Result<Vec<ActivityLogRecord>, AstralError> {
            Ok(vec![])
        }

        async fn recent_metric_count(&self) -> Result<i64, AstralError> {
            Ok(0)
        }

        async fn alert_counts(&self) -> Result<(i64, i64), AstralError> {
            Ok((0, 0))
        }

        async fn list_notification_channels(
            &self,
        ) -> Result<Vec<NotificationChannelRecord>, AstralError> {
            Ok(vec![])
        }

        async fn get_notification_channel(
            &self,
            _id: i64,
        ) -> Result<Option<NotificationChannelRecord>, AstralError> {
            Ok(None)
        }

        async fn create_notification_channel(
            &self,
            _name: &str,
            _channel_type: &str,
            _config: Option<&str>,
        ) -> Result<NotificationChannelRecord, AstralError> {
            Err(AstralError::Validation("not used in test".into()))
        }

        async fn update_notification_channel(
            &self,
            _id: i64,
            _name: &str,
            _channel_type: &str,
            _config: Option<&str>,
        ) -> Result<(), AstralError> {
            Ok(())
        }

        async fn record_activity(
            &self,
            _event_type: &str,
            _title: &str,
            _detail: &str,
            _level: &str,
            _source_service: &str,
        ) -> Result<(), AstralError> {
            Ok(())
        }

        async fn insert_metric(
            &self,
            _service_name: &str,
            _metric_type: &str,
            _value: f64,
        ) -> Result<(), AstralError> {
            Ok(())
        }

        async fn insert_alert_history(
            &self,
            _rule_id: i64,
            rule_name: &str,
            _metric_type: &str,
            _actual_value: f64,
            _severity: &str,
        ) -> Result<(), AstralError> {
            self.inserted_alerts
                .lock()
                .unwrap()
                .push(rule_name.to_string());
            Ok(())
        }

        async fn find_latest_metric_by_type(
            &self,
            _metric_type: &str,
            _since: time::OffsetDateTime,
        ) -> Result<Option<f64>, AstralError> {
            Ok(*self.latest_metric.lock().unwrap())
        }

        async fn has_recent_triggered_alert(
            &self,
            _rule_id: i64,
            _since: time::OffsetDateTime,
        ) -> Result<bool, AstralError> {
            Ok(*self.recent_alert.lock().unwrap())
        }

        async fn delete_metrics_older_than_days(&self, _days: i64) -> Result<u64, AstralError> {
            Ok(0)
        }

        async fn delete_alert_history_older_than_days(
            &self,
            _days: i64,
        ) -> Result<u64, AstralError> {
            Ok(0)
        }
    }

    #[tokio::test]
    async fn list_rules_passes_java_filter_contract_to_repository() {
        let repository = Arc::new(fake_repository());
        let service = MonitorService::new(repository.clone());
        let rules = service
            .list_rules(AlertRuleFilter {
                metric: Some("cpu_usage".into()),
                enabled: Some(1),
            })
            .await
            .unwrap();

        assert_eq!(rules[0].name, "CPU high");
        let query = repository.last_rule_query.lock().unwrap().clone().unwrap();
        assert_eq!(query.metric.as_deref(), Some("cpu_usage"));
        assert_eq!(query.enabled, Some(1));
    }

    #[tokio::test]
    async fn recent_metrics_summary_marks_missing_data_explicitly() {
        let service = MonitorService::new(Arc::new(fake_repository()));
        let summary = service.recent_metrics_summary().await.unwrap();
        assert_eq!(summary["dataStatus"], "NO_DATA");
        assert!(summary["cpuUsage"].is_null());
    }

    #[test]
    fn evaluate_condition_supports_java_and_rust_operators() {
        assert!(evaluate_condition(85.0, ">=", 80.0));
        assert!(!evaluate_condition(75.0, ">=", 80.0));
        assert!(evaluate_condition(85.0, "gte", 80.0));
        assert!(evaluate_condition(85.0, "gt", 80.0));
        assert!(evaluate_condition(80.0, "lte", 80.0));
        assert!(evaluate_condition(80.0, "lt", 81.0));
        assert!(evaluate_condition(1.0002, "eq", 1.0));
        assert!(!evaluate_condition(1.0, "unknown", 1.0));
    }

    #[tokio::test]
    async fn evaluate_alert_rules_returns_newly_triggered_alerts() {
        let repository = Arc::new(fake_repository());
        *repository.latest_metric.lock().unwrap() = Some(90.0);
        let service = MonitorService::new(repository.clone());

        let triggered = service.evaluate_alert_rules(60).await.unwrap();

        assert_eq!(triggered.len(), 1, "cpu_usage=90 >= 80 must trigger once");
        let alert = &triggered[0];
        assert_eq!(alert.rule_id, 7);
        assert_eq!(alert.rule_name, "CPU high");
        assert_eq!(alert.metric, "cpu_usage");
        assert_eq!(alert.actual_value, 90.0);
        assert_eq!(alert.severity, "WARNING");
        assert!(!alert.triggered_at.is_empty());
        assert_eq!(
            repository.inserted_alerts.lock().unwrap().len(),
            1,
            "alert must be persisted exactly once"
        );
    }

    #[tokio::test]
    async fn evaluate_alert_rules_respects_dedup_window() {
        let repository = Arc::new(fake_repository());
        *repository.latest_metric.lock().unwrap() = Some(90.0);
        *repository.recent_alert.lock().unwrap() = true;
        let service = MonitorService::new(repository.clone());

        let triggered = service.evaluate_alert_rules(60).await.unwrap();

        assert!(
            triggered.is_empty(),
            "dedup window must suppress re-trigger"
        );
        assert!(repository.inserted_alerts.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn evaluate_alert_rules_skips_missing_metric() {
        let repository = Arc::new(fake_repository());
        let service = MonitorService::new(repository.clone());

        let triggered = service.evaluate_alert_rules(60).await.unwrap();

        assert!(triggered.is_empty(), "no metric snapshot → no evaluation");
        assert!(repository.inserted_alerts.lock().unwrap().is_empty());
    }
}
