//! Monitor persistence port and SQLx adapter.
//!
//! The repository owns table names, filters and row mapping. HTTP DTOs and
//! Java-compatible defaults remain in `MonitorService`.

use async_trait::async_trait;
use sqlx::{MySqlPool, QueryBuilder};

use astral_types::AstralError;

#[derive(Debug, Clone)]
pub struct NotificationChannelRecord {
    pub id: i64,
    pub name: String,
    pub channel_type: String,
    pub config: Option<String>,
    pub enabled: i8,
}

#[derive(Debug, Clone)]
pub struct AlertRuleRecord {
    pub id: i64,
    pub name: String,
    pub metric: String,
    pub condition_op: String,
    pub threshold: f64,
    pub duration_seconds: i32,
    pub severity: String,
    pub enabled: i8,
}

#[derive(Debug, Clone)]
pub struct AlertHistoryRecord {
    pub id: i64,
    pub rule_id: i64,
    pub rule_name: Option<String>,
    pub metric_type: Option<String>,
    pub actual_value: Option<f64>,
    pub severity: String,
    pub status: String,
    pub triggered_at: time::OffsetDateTime,
    pub resolved_at: Option<time::OffsetDateTime>,
}

#[derive(Debug, Clone)]
pub struct ActivityLogRecord {
    pub id: i64,
    pub event_type: String,
    pub title: Option<String>,
    pub detail: Option<String>,
    pub level: String,
    pub source_service: Option<String>,
    pub occurred_at: time::OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct MetricSnapshotRecord {
    pub id: i64,
    pub service_name: String,
    pub metric_type: String,
    pub metric_value: f64,
    pub collected_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, Default)]
pub struct AlertRuleQuery {
    pub metric: Option<String>,
    pub enabled: Option<i8>,
}

#[derive(Debug, Clone)]
pub struct AlertRuleUpdate {
    pub id: i64,
    pub name: String,
    pub metric: String,
    pub condition_op: String,
    pub threshold: f64,
    pub duration_seconds: i32,
    pub severity: String,
}

#[derive(Debug, Clone, Default)]
pub struct AlertHistoryQuery {
    pub status: Option<String>,
    pub severity: Option<String>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub limit: i64,
}

#[derive(Debug, Clone, Default)]
pub struct ActivityLogQuery {
    pub event_type: Option<String>,
    pub level: Option<String>,
    pub source_service: Option<String>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub limit: i64,
}

#[derive(Debug, Clone, Default)]
pub struct MetricHistoryQuery {
    pub service_name: Option<String>,
    pub metric_type: Option<String>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub limit: i64,
}

#[async_trait]
pub trait MonitorRepository: Send + Sync {
    async fn list_alert_rules(
        &self,
        query: AlertRuleQuery,
    ) -> Result<Vec<AlertRuleRecord>, AstralError>;
    async fn create_alert_rule(
        &self,
        name: &str,
        metric: &str,
        condition_op: &str,
        threshold: f64,
        duration_seconds: i32,
        severity: &str,
    ) -> Result<AlertRuleRecord, AstralError>;
    async fn get_alert_rule(&self, id: i64) -> Result<Option<AlertRuleRecord>, AstralError>;
    async fn update_alert_rule(&self, update: AlertRuleUpdate) -> Result<(), AstralError>;
    async fn delete_alert_rule(&self, id: i64) -> Result<(), AstralError>;
    async fn toggle_alert_rule(&self, id: i64) -> Result<(), AstralError>;

    async fn list_alert_history(
        &self,
        query: AlertHistoryQuery,
    ) -> Result<Vec<AlertHistoryRecord>, AstralError>;
    async fn acknowledge_alert(&self, id: i64) -> Result<(), AstralError>;
    async fn list_activity_logs(
        &self,
        query: ActivityLogQuery,
    ) -> Result<Vec<ActivityLogRecord>, AstralError>;

    async fn latest_metric(
        &self,
        service_name: &str,
        metric_type: &str,
    ) -> Result<Option<f64>, AstralError>;
    async fn recent_metric(
        &self,
        service_name: &str,
        metric_type: &str,
    ) -> Result<Option<f64>, AstralError>;
    async fn metric_history(
        &self,
        query: MetricHistoryQuery,
    ) -> Result<Vec<MetricSnapshotRecord>, AstralError>;
    async fn metric_trend(&self) -> Result<Vec<(i64, f64)>, AstralError>;
    async fn dashboard_alerts(&self) -> Result<Vec<AlertHistoryRecord>, AstralError>;
    async fn dashboard_activities(&self) -> Result<Vec<ActivityLogRecord>, AstralError>;
    async fn recent_metric_count(&self) -> Result<i64, AstralError>;
    async fn alert_counts(&self) -> Result<(i64, i64), AstralError>;
    async fn list_notification_channels(
        &self,
    ) -> Result<Vec<NotificationChannelRecord>, AstralError>;
    async fn get_notification_channel(
        &self,
        id: i64,
    ) -> Result<Option<NotificationChannelRecord>, AstralError>;
    async fn create_notification_channel(
        &self,
        name: &str,
        channel_type: &str,
        config: Option<&str>,
    ) -> Result<NotificationChannelRecord, AstralError>;
    async fn update_notification_channel(
        &self,
        id: i64,
        name: &str,
        channel_type: &str,
        config: Option<&str>,
    ) -> Result<(), AstralError>;
    async fn record_activity(
        &self,
        event_type: &str,
        title: &str,
        detail: &str,
        level: &str,
        source_service: &str,
    ) -> Result<(), AstralError>;

    // ===== 采集器写入路径（对应 Java MetricCollectTask / AlertEvaluationTask） =====

    async fn insert_metric(
        &self,
        service_name: &str,
        metric_type: &str,
        value: f64,
    ) -> Result<(), AstralError>;
    async fn insert_alert_history(
        &self,
        rule_id: i64,
        rule_name: &str,
        metric_type: &str,
        actual_value: f64,
        severity: &str,
    ) -> Result<(), AstralError>;
    /// 按 metric_type 查最近快照（Java 仅按 metric_type 过滤，不按 service_name）。
    async fn find_latest_metric_by_type(
        &self,
        metric_type: &str,
        since: time::OffsetDateTime,
    ) -> Result<Option<f64>, AstralError>;
    /// 60s 窗口内同规则是否已有 triggered 记录（Java 去重窗口）。
    async fn has_recent_triggered_alert(
        &self,
        rule_id: i64,
        since: time::OffsetDateTime,
    ) -> Result<bool, AstralError>;
    async fn delete_metrics_older_than_days(&self, days: i64) -> Result<u64, AstralError>;
    async fn delete_alert_history_older_than_days(&self, days: i64) -> Result<u64, AstralError>;
}

pub struct SqlxMonitorRepository {
    db: MySqlPool,
}

impl SqlxMonitorRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

#[async_trait]
impl MonitorRepository for SqlxMonitorRepository {
    async fn list_alert_rules(
        &self,
        query: AlertRuleQuery,
    ) -> Result<Vec<AlertRuleRecord>, AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new(
            "SELECT id,name,metric,condition_op,threshold,duration_seconds,severity,enabled \
             FROM alert_rule WHERE 1=1",
        );
        if let Some(metric) = query.metric {
            builder.push(" AND metric = ").push_bind(metric);
        }
        if let Some(enabled) = query.enabled {
            builder.push(" AND enabled = ").push_bind(enabled);
        }
        builder.push(" ORDER BY id");
        let rows = builder
            .build_query_as::<AlertRuleRow>()
            .fetch_all(&self.db)
            .await
            .map_err(db_error)?;
        Ok(rows.into_iter().map(AlertRuleRecord::from).collect())
    }

    async fn create_alert_rule(
        &self,
        name: &str,
        metric: &str,
        condition_op: &str,
        threshold: f64,
        duration_seconds: i32,
        severity: &str,
    ) -> Result<AlertRuleRecord, AstralError> {
        let result = sqlx::query(
            "INSERT INTO alert_rule \
             (name,metric,condition_op,threshold,duration_seconds,severity,enabled) \
             VALUES (?,?,?,?,?,?,1)",
        )
        .bind(name)
        .bind(metric)
        .bind(condition_op)
        .bind(threshold)
        .bind(duration_seconds)
        .bind(severity)
        .execute(&self.db)
        .await
        .map_err(db_error)?;

        self.get_alert_rule(result.last_insert_id() as i64)
            .await?
            .ok_or_else(|| AstralError::Database("Created alert rule could not be reloaded".into()))
    }

    async fn get_alert_rule(&self, id: i64) -> Result<Option<AlertRuleRecord>, AstralError> {
        sqlx::query_as::<_, AlertRuleRow>(
            "SELECT id,name,metric,condition_op,threshold,duration_seconds,severity,enabled \
             FROM alert_rule WHERE id=?",
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map(|row| row.map(AlertRuleRecord::from))
        .map_err(db_error)
    }

    async fn update_alert_rule(&self, update: AlertRuleUpdate) -> Result<(), AstralError> {
        sqlx::query(
            "UPDATE alert_rule SET name=?,metric=?,condition_op=?,threshold=?,duration_seconds=?,severity=? WHERE id=?",
        )
        .bind(update.name)
        .bind(update.metric)
        .bind(update.condition_op)
        .bind(update.threshold)
        .bind(update.duration_seconds)
        .bind(update.severity)
        .bind(update.id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn delete_alert_rule(&self, id: i64) -> Result<(), AstralError> {
        sqlx::query("DELETE FROM alert_rule WHERE id=?")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn toggle_alert_rule(&self, id: i64) -> Result<(), AstralError> {
        sqlx::query("UPDATE alert_rule SET enabled = 1 - enabled WHERE id=?")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn list_alert_history(
        &self,
        query: AlertHistoryQuery,
    ) -> Result<Vec<AlertHistoryRecord>, AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new(
            "SELECT id,rule_id,rule_name,metric_type,actual_value,severity,status,triggered_at,resolved_at \
             FROM monitor_alert_history WHERE 1=1",
        );
        if let Some(status) = query.status {
            builder.push(" AND status = ").push_bind(status);
        }
        if let Some(severity) = query.severity {
            builder.push(" AND severity = ").push_bind(severity);
        }
        if let Some(start_time) = query.start_time {
            builder.push(" AND triggered_at >= ").push_bind(start_time);
        }
        if let Some(end_time) = query.end_time {
            builder.push(" AND triggered_at <= ").push_bind(end_time);
        }
        builder
            .push(" ORDER BY triggered_at DESC LIMIT ")
            .push_bind(query.limit.clamp(1, 200));
        let rows = builder
            .build_query_as::<AlertHistoryRow>()
            .fetch_all(&self.db)
            .await
            .map_err(db_error)?;
        Ok(rows.into_iter().map(AlertHistoryRecord::from).collect())
    }

    async fn acknowledge_alert(&self, id: i64) -> Result<(), AstralError> {
        let affected = sqlx::query(
            "UPDATE monitor_alert_history SET status='acknowledged',resolved_at=NOW() \
             WHERE id=? AND status='triggered'",
        )
        .bind(id)
        .execute(&self.db)
        .await
        .map_err(db_error)?
        .rows_affected();
        if affected == 0 {
            return Err(AstralError::Validation("告警记录不存在或已确认".into()));
        }
        Ok(())
    }

    async fn list_activity_logs(
        &self,
        query: ActivityLogQuery,
    ) -> Result<Vec<ActivityLogRecord>, AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new(
            "SELECT id,event_type,title,detail,level,source_service,occurred_at \
             FROM monitor_activity_log WHERE 1=1",
        );
        if let Some(event_type) = query.event_type {
            builder.push(" AND event_type = ").push_bind(event_type);
        }
        if let Some(level) = query.level {
            builder.push(" AND level = ").push_bind(level);
        }
        if let Some(source_service) = query.source_service {
            builder
                .push(" AND source_service = ")
                .push_bind(source_service);
        }
        if let Some(start_time) = query.start_time {
            builder.push(" AND occurred_at >= ").push_bind(start_time);
        }
        if let Some(end_time) = query.end_time {
            builder.push(" AND occurred_at <= ").push_bind(end_time);
        }
        builder
            .push(" ORDER BY occurred_at DESC LIMIT ")
            .push_bind(query.limit.clamp(1, 200));
        let rows = builder
            .build_query_as::<ActivityLogRow>()
            .fetch_all(&self.db)
            .await
            .map_err(db_error)?;
        Ok(rows.into_iter().map(ActivityLogRecord::from).collect())
    }

    async fn latest_metric(
        &self,
        service_name: &str,
        metric_type: &str,
    ) -> Result<Option<f64>, AstralError> {
        sqlx::query_scalar(
            "SELECT metric_value FROM monitor_metric_snapshot \
             WHERE service_name=? AND metric_type=? \
             ORDER BY collected_at DESC LIMIT 1",
        )
        .bind(service_name)
        .bind(metric_type)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn recent_metric(
        &self,
        service_name: &str,
        metric_type: &str,
    ) -> Result<Option<f64>, AstralError> {
        sqlx::query_scalar(
            "SELECT metric_value FROM monitor_metric_snapshot \
             WHERE service_name=? AND metric_type=? \
               AND collected_at >= UTC_TIMESTAMP() - INTERVAL 5 MINUTE \
             ORDER BY collected_at DESC LIMIT 1",
        )
        .bind(service_name)
        .bind(metric_type)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn metric_history(
        &self,
        query: MetricHistoryQuery,
    ) -> Result<Vec<MetricSnapshotRecord>, AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new(
            "SELECT id,service_name,metric_type,metric_value,collected_at \
             FROM monitor_metric_snapshot WHERE 1=1",
        );
        if let Some(service_name) = query.service_name {
            builder.push(" AND service_name = ").push_bind(service_name);
        }
        if let Some(metric_type) = query.metric_type {
            builder.push(" AND metric_type = ").push_bind(metric_type);
        }
        if let Some(start_time) = query.start_time {
            builder.push(" AND collected_at >= ").push_bind(start_time);
        }
        if let Some(end_time) = query.end_time {
            builder.push(" AND collected_at <= ").push_bind(end_time);
        }
        builder
            .push(" ORDER BY collected_at ASC LIMIT ")
            .push_bind(query.limit.clamp(1, 500));
        let rows = builder
            .build_query_as::<MetricSnapshotRow>()
            .fetch_all(&self.db)
            .await
            .map_err(db_error)?;
        Ok(rows.into_iter().map(MetricSnapshotRecord::from).collect())
    }

    async fn metric_trend(&self) -> Result<Vec<(i64, f64)>, AstralError> {
        sqlx::query_as(
            "SELECT FLOOR(HOUR(collected_at) / 3) AS slot, AVG(metric_value) AS avg_latency \
             FROM monitor_metric_snapshot \
             WHERE metric_type='latency' AND collected_at >= NOW() - INTERVAL 24 HOUR \
             GROUP BY FLOOR(HOUR(collected_at) / 3) ORDER BY slot",
        )
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn dashboard_alerts(&self) -> Result<Vec<AlertHistoryRecord>, AstralError> {
        let rows = sqlx::query_as::<_, AlertHistoryRow>(
            "SELECT id,rule_id,rule_name,metric_type,actual_value,severity,status,triggered_at,resolved_at \
             FROM monitor_alert_history WHERE status='triggered' \
               AND triggered_at >= NOW() - INTERVAL 24 HOUR \
             ORDER BY triggered_at DESC LIMIT 10",
        )
        .fetch_all(&self.db)
        .await
        .map_err(db_error)?;
        Ok(rows.into_iter().map(AlertHistoryRecord::from).collect())
    }

    async fn dashboard_activities(&self) -> Result<Vec<ActivityLogRecord>, AstralError> {
        let rows = sqlx::query_as::<_, ActivityLogRow>(
            "SELECT id,event_type,title,detail,level,source_service,occurred_at \
             FROM monitor_activity_log WHERE occurred_at >= NOW() - INTERVAL 24 HOUR \
             ORDER BY occurred_at DESC LIMIT 10",
        )
        .fetch_all(&self.db)
        .await
        .map_err(db_error)?;
        Ok(rows.into_iter().map(ActivityLogRecord::from).collect())
    }

    async fn recent_metric_count(&self) -> Result<i64, AstralError> {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM monitor_metric_snapshot \
             WHERE collected_at >= NOW() - INTERVAL 5 MINUTE",
        )
        .fetch_one(&self.db)
        .await
        .map_err(db_error)
    }

    async fn alert_counts(&self) -> Result<(i64, i64), AstralError> {
        let total = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM monitor_alert_history")
            .fetch_one(&self.db)
            .await
            .map_err(db_error)?;
        let triggered = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM monitor_alert_history WHERE status = 'triggered'",
        )
        .fetch_one(&self.db)
        .await
        .map_err(db_error)?;
        Ok((total, triggered))
    }

    async fn list_notification_channels(
        &self,
    ) -> Result<Vec<NotificationChannelRecord>, AstralError> {
        let rows = sqlx::query_as::<_, NotificationChannelRow>(
            "SELECT id,name,channel_type,CAST(config AS CHAR) as config,enabled \
             FROM notification_channel ORDER BY id",
        )
        .fetch_all(&self.db)
        .await
        .map_err(db_error)?;
        Ok(rows
            .into_iter()
            .map(NotificationChannelRecord::from)
            .collect())
    }

    async fn get_notification_channel(
        &self,
        id: i64,
    ) -> Result<Option<NotificationChannelRecord>, AstralError> {
        sqlx::query_as::<_, NotificationChannelRow>(
            "SELECT id,name,channel_type,CAST(config AS CHAR) as config,enabled \
             FROM notification_channel WHERE id=?",
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map(|row| row.map(NotificationChannelRecord::from))
        .map_err(db_error)
    }

    async fn create_notification_channel(
        &self,
        name: &str,
        channel_type: &str,
        config: Option<&str>,
    ) -> Result<NotificationChannelRecord, AstralError> {
        let result = sqlx::query(
            "INSERT INTO notification_channel (name,channel_type,config,enabled) VALUES (?,?,?,1)",
        )
        .bind(name)
        .bind(channel_type)
        .bind(config)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        self.get_notification_channel(result.last_insert_id() as i64)
            .await?
            .ok_or_else(|| {
                AstralError::Database("Created notification channel could not be reloaded".into())
            })
    }

    async fn update_notification_channel(
        &self,
        id: i64,
        name: &str,
        channel_type: &str,
        config: Option<&str>,
    ) -> Result<(), AstralError> {
        sqlx::query("UPDATE notification_channel SET name=?,channel_type=?,config=? WHERE id=?")
            .bind(name)
            .bind(channel_type)
            .bind(config)
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn record_activity(
        &self,
        event_type: &str,
        title: &str,
        detail: &str,
        level: &str,
        source_service: &str,
    ) -> Result<(), AstralError> {
        sqlx::query(
            "INSERT INTO monitor_activity_log \
             (event_type,title,detail,level,source_service,occurred_at) \
             VALUES (?,?,?,?,?,NOW())",
        )
        .bind(event_type)
        .bind(title)
        .bind(detail)
        .bind(level)
        .bind(source_service)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn insert_metric(
        &self,
        service_name: &str,
        metric_type: &str,
        value: f64,
    ) -> Result<(), AstralError> {
        sqlx::query(
            "INSERT INTO monitor_metric_snapshot \
             (service_name,metric_type,metric_value,collected_at) \
             VALUES (?,?,?,UTC_TIMESTAMP())",
        )
        .bind(service_name)
        .bind(metric_type)
        .bind(value)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn insert_alert_history(
        &self,
        rule_id: i64,
        rule_name: &str,
        metric_type: &str,
        actual_value: f64,
        severity: &str,
    ) -> Result<(), AstralError> {
        sqlx::query(
            "INSERT INTO monitor_alert_history \
             (rule_id,rule_name,metric_type,actual_value,severity,status,triggered_at) \
             VALUES (?,?,?,?,?,'triggered',UTC_TIMESTAMP())",
        )
        .bind(rule_id)
        .bind(rule_name)
        .bind(metric_type)
        .bind(actual_value)
        .bind(severity)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn find_latest_metric_by_type(
        &self,
        metric_type: &str,
        since: time::OffsetDateTime,
    ) -> Result<Option<f64>, AstralError> {
        sqlx::query_scalar(
            "SELECT metric_value FROM monitor_metric_snapshot \
             WHERE metric_type = ? AND collected_at >= ? \
             ORDER BY collected_at DESC LIMIT 1",
        )
        .bind(metric_type)
        .bind(since)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn has_recent_triggered_alert(
        &self,
        rule_id: i64,
        since: time::OffsetDateTime,
    ) -> Result<bool, AstralError> {
        let exists: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM monitor_alert_history \
             WHERE rule_id = ? AND status = 'triggered' AND triggered_at >= ? LIMIT 1",
        )
        .bind(rule_id)
        .bind(since)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)?;
        Ok(exists.is_some())
    }

    async fn delete_metrics_older_than_days(&self, days: i64) -> Result<u64, AstralError> {
        let result = sqlx::query(
            "DELETE FROM monitor_metric_snapshot \
             WHERE collected_at < UTC_TIMESTAMP() - INTERVAL ? DAY",
        )
        .bind(days)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected())
    }

    async fn delete_alert_history_older_than_days(&self, days: i64) -> Result<u64, AstralError> {
        let result = sqlx::query(
            "DELETE FROM monitor_alert_history \
             WHERE triggered_at < UTC_TIMESTAMP() - INTERVAL ? DAY",
        )
        .bind(days)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected())
    }
}

#[derive(Debug, sqlx::FromRow)]
struct NotificationChannelRow {
    id: i64,
    name: String,
    channel_type: String,
    config: Option<String>,
    enabled: i8,
}

impl From<NotificationChannelRow> for NotificationChannelRecord {
    fn from(row: NotificationChannelRow) -> Self {
        Self {
            id: row.id,
            name: row.name,
            channel_type: row.channel_type,
            config: row.config,
            enabled: row.enabled,
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct AlertRuleRow {
    id: i64,
    name: String,
    metric: String,
    condition_op: String,
    threshold: f64,
    duration_seconds: i32,
    severity: String,
    enabled: i8,
}

impl From<AlertRuleRow> for AlertRuleRecord {
    fn from(row: AlertRuleRow) -> Self {
        Self {
            id: row.id,
            name: row.name,
            metric: row.metric,
            condition_op: row.condition_op,
            threshold: row.threshold,
            duration_seconds: row.duration_seconds,
            severity: row.severity,
            enabled: row.enabled,
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct AlertHistoryRow {
    id: i64,
    rule_id: i64,
    rule_name: Option<String>,
    metric_type: Option<String>,
    actual_value: Option<f64>,
    severity: String,
    status: String,
    triggered_at: time::OffsetDateTime,
    resolved_at: Option<time::OffsetDateTime>,
}

impl From<AlertHistoryRow> for AlertHistoryRecord {
    fn from(row: AlertHistoryRow) -> Self {
        Self {
            id: row.id,
            rule_id: row.rule_id,
            rule_name: row.rule_name,
            metric_type: row.metric_type,
            actual_value: row.actual_value,
            severity: row.severity,
            status: row.status,
            triggered_at: row.triggered_at,
            resolved_at: row.resolved_at,
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct ActivityLogRow {
    id: i64,
    event_type: String,
    title: Option<String>,
    detail: Option<String>,
    level: String,
    source_service: Option<String>,
    occurred_at: time::OffsetDateTime,
}

impl From<ActivityLogRow> for ActivityLogRecord {
    fn from(row: ActivityLogRow) -> Self {
        Self {
            id: row.id,
            event_type: row.event_type,
            title: row.title,
            detail: row.detail,
            level: row.level,
            source_service: row.source_service,
            occurred_at: row.occurred_at,
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct MetricSnapshotRow {
    id: i64,
    service_name: String,
    metric_type: String,
    metric_value: f64,
    collected_at: time::OffsetDateTime,
}

impl From<MetricSnapshotRow> for MetricSnapshotRecord {
    fn from(row: MetricSnapshotRow) -> Self {
        Self {
            id: row.id,
            service_name: row.service_name,
            metric_type: row.metric_type,
            metric_value: row.metric_value,
            collected_at: row.collected_at,
        }
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Monitor repository query failed: {error}"))
}
