//! 告警通知派发 — 告警触发后向启用的通知渠道投递。
//!
//! 与 `notifications.rs` 的测试派发（`/test` 端点）互补：本模块是
//! `evaluate_alert_rules` 触发真实告警后的派发路径。所有渠道（WEBHOOK/
//! EMAIL/SMS/DINGTALK/WECHAT）都通过共享的
//! `astral_common::delivery::DeliveryOwner` 真实外发；不再存在模拟分支。
//!
//! 真值语义：服务商 2xx / SMTP 250 最多记为 ACCEPTED；DELIVERED 必须有
//! 显式回执证明（同步 webhook 2xx 或中继回执字段）；IN_DOUBT 表示投递已
//! 开始但结果未知，只能显式对账，绝不自动重试。活动日志只记录 typed
//! truth，不得从日志反推“已成功投递”。
//!
//! 失败语义（事故链）：派发失败只记录日志与指标，绝不向上传播——
//! 告警持久化与采集循环不得因通知通道故障中断。

use std::sync::Arc;

use async_trait::async_trait;

use astral_common::delivery::{
    resolve_channel, ChannelKind, DeliveryMessage, DeliveryOwner, DeliveryState, DeliveryStore,
    DeliveryTruth, PayloadClass,
};
use astral_types::AstralError;

use crate::notifications::NotificationChannel;
use crate::service::MonitorService;

/// 一条待派发的告警（由 `evaluate_alert_rules` 在新触发时产出）。
#[derive(Debug, Clone)]
pub struct AlertNotification {
    pub rule_id: i64,
    pub rule_name: String,
    pub metric: String,
    pub actual_value: f64,
    pub severity: String,
    /// RFC3339 时间戳（触发时刻）。
    pub triggered_at: String,
}

/// 派发依赖的最小端口：查询通知渠道 + 记录活动日志 + 可选的 durable
/// intent store。独立于 `MonitorRepository`，测试用小型 fake 即可。
#[async_trait]
pub trait AlertNotificationSink: Send + Sync {
    async fn notification_channels(&self) -> Result<Vec<NotificationChannel>, AstralError>;
    async fn record_dispatch_activity(
        &self,
        title: &str,
        detail: &str,
        level: &str,
    ) -> Result<(), AstralError>;

    /// Durable delivery intent store. `None` means the runtime has not wired
    /// the store yet: real delivery is refused fail-closed (typed
    /// NOT_ATTEMPTED) — never simulated, never silently dropped.
    async fn delivery_store(&self) -> Option<Arc<dyn DeliveryStore>> {
        None
    }
}

#[async_trait]
impl AlertNotificationSink for MonitorService {
    async fn notification_channels(&self) -> Result<Vec<NotificationChannel>, AstralError> {
        self.list_notification_channels().await
    }

    async fn record_dispatch_activity(
        &self,
        title: &str,
        detail: &str,
        level: &str,
    ) -> Result<(), AstralError> {
        self.record_activity("alert_notification", title, detail, level, "astral-monitor")
            .await
    }

    // delivery_store(): default None. The runtime composition (main) wires
    // the SQL store when the AppState carries it; until then alert delivery
    // is refused with a typed NOT_ATTEMPTED instead of being simulated.
}

/// Ready-made sink for runtime composition: wraps `MonitorService` with the
/// SQL-backed durable intent store built from the shared DB pool.
pub struct DbBackedAlertSink {
    inner: Arc<MonitorService>,
    store: Arc<dyn DeliveryStore>,
}

impl DbBackedAlertSink {
    pub fn new(inner: Arc<MonitorService>, store: Arc<dyn DeliveryStore>) -> Self {
        Self { inner, store }
    }
}

#[async_trait]
impl AlertNotificationSink for DbBackedAlertSink {
    async fn notification_channels(&self) -> Result<Vec<NotificationChannel>, AstralError> {
        self.inner.list_notification_channels().await
    }

    async fn record_dispatch_activity(
        &self,
        title: &str,
        detail: &str,
        level: &str,
    ) -> Result<(), AstralError> {
        self.inner
            .record_activity("alert_notification", title, detail, level, "astral-monitor")
            .await
    }

    async fn delivery_store(&self) -> Option<Arc<dyn DeliveryStore>> {
        Some(self.store.clone())
    }
}

/// 派发单条告警：对启用的渠道逐一真实外发，并写一条活动日志汇总。
///
/// 无任何可识别的启用渠道时不写活动日志（避免每个告警周期产生噪音行）。
pub async fn dispatch_alert<S: AlertNotificationSink + ?Sized>(
    sink: &S,
    alert: &AlertNotification,
) {
    let store = sink.delivery_store().await;
    let owner = DeliveryOwner::builder(store).build();
    dispatch_alert_with_owner(sink, &owner, alert).await;
}

/// Owner-injecting variant (tests inject a fake transport; production uses
/// the shared real transports).
pub async fn dispatch_alert_with_owner<S: AlertNotificationSink + ?Sized>(
    sink: &S,
    owner: &DeliveryOwner,
    alert: &AlertNotification,
) {
    let channels = match sink.notification_channels().await {
        Ok(channels) => channels,
        Err(error) => {
            tracing::warn!(error = %error, "alert notification skipped: channel list unavailable");
            return;
        }
    };

    let enabled: Vec<&NotificationChannel> = channels
        .iter()
        .filter(|channel| {
            channel.enabled == 1 && ChannelKind::parse(&channel.channel_type).is_some()
        })
        .collect();
    let unknown: Vec<&NotificationChannel> = channels
        .iter()
        .filter(|channel| {
            channel.enabled == 1 && ChannelKind::parse(&channel.channel_type).is_none()
        })
        .collect();
    for channel in &unknown {
        tracing::debug!(
            channel = %channel.name,
            channel_type = %channel.channel_type,
            "unknown channel type skipped on real alert"
        );
    }
    if enabled.is_empty() {
        return;
    }

    let mut summary: Vec<String> = Vec::with_capacity(enabled.len());
    let mut delivered = 0usize;
    let mut accepted = 0usize;
    let mut refused = 0usize;
    let mut failed = 0usize;
    let mut in_doubt = 0usize;

    for channel in &enabled {
        let kind = ChannelKind::parse(&channel.channel_type).unwrap_or(ChannelKind::Webhook);
        let truth = deliver_alert_to_channel(owner, channel, kind, alert).await;
        metrics::counter!(
            "astral_delivery_outcome_total",
            "channel" => kind.as_str(),
            "state" => truth.state.as_str()
        )
        .increment(1);
        match truth.state {
            DeliveryState::Delivered => {
                delivered += 1;
                metrics::counter!(
                    "astral_monitor_notifications_sent_total",
                    "channel_type" => kind.as_str()
                )
                .increment(1);
            }
            DeliveryState::Accepted => accepted += 1,
            DeliveryState::InDoubt => in_doubt += 1,
            DeliveryState::Failed | DeliveryState::Expired => failed += 1,
            DeliveryState::NotAttempted | DeliveryState::Queued => refused += 1,
        }
        tracing::info!(
            channel = %channel.name,
            state = %truth.state,
            detail = %truth.detail,
            "alert notification attempt settled"
        );
        summary.push(format!(
            "{}[{}]={}",
            kind.as_str(),
            channel.name,
            truth.state.as_str()
        ));
    }

    let title = format!("告警通知 [{}]", alert.rule_name);
    let mut detail = format!(
        "{} 触发告警 {} = {:.2}（严重级别 {}）；DELIVERED {delivered} / ACCEPTED {accepted} / FAILED {failed} / IN_DOUBT {in_doubt} / NOT_ATTEMPTED {refused}；",
        alert.triggered_at, alert.metric, alert.actual_value, alert.severity
    );
    detail.push_str(&summary.join("; "));
    if detail.len() > 512 {
        detail.truncate(512);
    }
    let level = if failed > 0 || in_doubt > 0 {
        "warn"
    } else {
        "info"
    };
    if let Err(error) = sink.record_dispatch_activity(&title, &detail, level).await {
        tracing::warn!(error = %error, "alert dispatch activity recording failed");
    }
}

/// 通过共享 DeliveryOwner 向单个渠道真实投递一条告警。
async fn deliver_alert_to_channel(
    owner: &DeliveryOwner,
    channel: &NotificationChannel,
    kind: ChannelKind,
    alert: &AlertNotification,
) -> DeliveryTruth {
    let resolved = match resolve_channel(kind, channel.config.as_deref()) {
        Ok(resolved) => resolved,
        Err(error) => return DeliveryTruth::not_attempted(error.to_string()),
    };
    let recipient = match alert_recipient(&resolved, channel) {
        Ok(recipient) => recipient,
        Err(truth) => return truth,
    };
    // Stable operation per firing: re-dispatching the same alert firing is
    // idempotent at the durable-intent layer (same message id).
    let operation = format!(
        "monitor:alert:{}:{}:{}",
        alert.rule_id, alert.metric, alert.triggered_at
    );
    let message = match kind {
        ChannelKind::Webhook => DeliveryMessage::compose(
            kind,
            &operation,
            Some(&DeliveryOwner::message_id_for_operation(&operation)),
            &recipient,
            Some(&alert_subject(alert)),
            &alert_payload(alert).to_string(),
            PayloadClass::Standard,
        ),
        _ => DeliveryMessage::compose(
            kind,
            &operation,
            Some(&DeliveryOwner::message_id_for_operation(&operation)),
            &recipient,
            Some(&alert_subject(alert)),
            &alert_body(alert),
            PayloadClass::Standard,
        ),
    };
    let message = match message {
        Ok(message) => message,
        Err(error) => return DeliveryTruth::not_attempted(error.to_string()),
    };
    owner.deliver(&message, &resolved).await
}

fn alert_subject(alert: &AlertNotification) -> String {
    format!("告警 [{}] {}", alert.severity, alert.rule_name)
}

fn alert_body(alert: &AlertNotification) -> String {
    format!(
        "触发告警: {} = {:.2}（严重级别 {}，时间 {}）",
        alert.metric, alert.actual_value, alert.severity, alert.triggered_at
    )
}

/// 渠道收件人：EMAIL 用配置的 `recipient`（缺失即拒发）；其余渠道用
/// 端点 URL 作为意图记录的收件标识。
fn alert_recipient(
    resolved: &astral_common::delivery::ResolvedChannel,
    channel: &NotificationChannel,
) -> Result<String, DeliveryTruth> {
    match resolved {
        astral_common::delivery::ResolvedChannel::Smtp(_) => {
            let config: serde_json::Value = channel
                .config
                .as_deref()
                .and_then(|value| serde_json::from_str(value).ok())
                .unwrap_or_else(|| serde_json::json!({}));
            let recipient = config
                .get("recipient")
                .and_then(|value| value.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned);
            recipient.ok_or_else(|| {
                DeliveryTruth::not_attempted("email recipient (config recipient) not configured")
            })
        }
        astral_common::delivery::ResolvedChannel::Relay(config)
        | astral_common::delivery::ResolvedChannel::Webhook(config) => Ok(config.url.clone()),
    }
}

/// 构造告警 webhook payload（camelCase 契约）。
fn alert_payload(alert: &AlertNotification) -> serde_json::Value {
    serde_json::json!({
        "event": "alert",
        "ruleId": alert.rule_id,
        "ruleName": alert.rule_name,
        "metric": alert.metric,
        "actualValue": alert.actual_value,
        "severity": alert.severity,
        "triggeredAt": alert.triggered_at,
        "message": format!("告警触发: {} = {:.2}", alert.metric, alert.actual_value),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_common::delivery::InMemoryDeliveryStore;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    fn fake_store() -> Arc<dyn DeliveryStore> {
        Arc::new(InMemoryDeliveryStore::new())
    }

    /// Static-truth transport for owner-level dispatch tests.
    struct StaticTransport {
        calls: AtomicUsize,
        truth: DeliveryTruth,
    }

    impl StaticTransport {
        fn delivered() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                truth: DeliveryTruth::delivered(Some("prov-1"), "receipt"),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl astral_common::delivery::ChannelTransport for StaticTransport {
        async fn dispatch(
            &self,
            _message: &DeliveryMessage,
            _channel: &astral_common::delivery::ResolvedChannel,
        ) -> DeliveryTruth {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.truth.clone()
        }
    }

    fn alert() -> AlertNotification {
        AlertNotification {
            rule_id: 7,
            rule_name: "CPU high".into(),
            metric: "cpu_usage".into(),
            actual_value: 91.5,
            severity: "WARNING".into(),
            triggered_at: "2026-09-02T00:00:00Z".into(),
        }
    }

    fn channel(
        id: i64,
        channel_type: &str,
        enabled: i8,
        config: Option<&str>,
    ) -> NotificationChannel {
        NotificationChannel {
            id,
            name: format!("channel-{id}"),
            channel_type: channel_type.into(),
            config: config.map(str::to_string),
            enabled,
        }
    }

    struct FakeSink {
        channels: Vec<NotificationChannel>,
        activities: Mutex<Vec<String>>,
        channels_error: bool,
        store: Option<Arc<dyn DeliveryStore>>,
    }

    impl FakeSink {
        fn new(channels: Vec<NotificationChannel>) -> Self {
            Self {
                channels,
                activities: Mutex::new(Vec::new()),
                channels_error: false,
                store: None,
            }
        }

        fn with_store(mut self, store: Arc<dyn DeliveryStore>) -> Self {
            self.store = Some(store);
            self
        }

        fn activities(&self) -> Vec<String> {
            self.activities.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl AlertNotificationSink for FakeSink {
        async fn notification_channels(&self) -> Result<Vec<NotificationChannel>, AstralError> {
            if self.channels_error {
                return Err(AstralError::Validation("db unavailable".into()));
            }
            Ok(self.channels.clone())
        }

        async fn record_dispatch_activity(
            &self,
            title: &str,
            detail: &str,
            level: &str,
        ) -> Result<(), AstralError> {
            self.activities
                .lock()
                .unwrap()
                .push(format!("{title}|{detail}|{level}"));
            Ok(())
        }

        async fn delivery_store(&self) -> Option<Arc<dyn DeliveryStore>> {
            self.store.clone()
        }
    }

    #[test]
    fn alert_payload_contains_rule_fields() {
        let payload = alert_payload(&alert());
        assert_eq!(payload["event"], "alert");
        assert_eq!(payload["ruleId"], 7);
        assert_eq!(payload["ruleName"], "CPU high");
        assert_eq!(payload["metric"], "cpu_usage");
        assert_eq!(payload["severity"], "WARNING");
        assert!(payload["message"].as_str().unwrap().contains("91.5"));
    }

    #[tokio::test]
    async fn dispatch_without_enabled_channels_writes_no_activity() {
        let sink = FakeSink::new(vec![
            channel(2, "EMAIL", 0, None),
            channel(3, "WEBHOOK", 0, None),
            channel(4, "FAX", 1, None),
        ]);
        dispatch_alert(&sink, &alert()).await;
        assert!(sink.activities().is_empty());
    }

    #[tokio::test]
    async fn dispatch_channel_list_failure_is_contained() {
        let mut sink = FakeSink::new(vec![]);
        sink.channels_error = true;
        dispatch_alert(&sink, &alert()).await;
        assert!(sink.activities().is_empty());
    }

    #[tokio::test]
    async fn missing_durable_store_refuses_dispatch_fail_closed() {
        // No store wired: delivery is refused with typed truth, never simulated.
        let sink = FakeSink::new(vec![channel(
            4,
            "WEBHOOK",
            1,
            Some(r#"{"url":"https://hooks.example.com/x"}"#),
        )]);
        dispatch_alert(&sink, &alert()).await;
        let activities = sink.activities();
        assert_eq!(activities.len(), 1, "{activities:?}");
        assert!(
            activities[0].contains("WEBHOOK[channel-4]=NOT_ATTEMPTED"),
            "{activities:?}"
        );
        assert!(activities[0].ends_with("|info"), "{activities:?}");
    }

    #[tokio::test]
    async fn real_owner_composition_records_typed_truth_in_activity() {
        // Store wired + fake transport truth via the owner-injecting variant:
        // activity must carry the typed state, never an inferred success.
        let sink = FakeSink::new(vec![channel(
            5,
            "WEBHOOK",
            1,
            Some(r#"{"url":"https://hooks.example.com/x"}"#),
        )])
        .with_store(fake_store());
        let transport = StaticTransport::delivered();
        let owner = DeliveryOwner::builder(Some(fake_store()))
            .transport(Arc::new(transport))
            .build();
        dispatch_alert_with_owner(&sink, &owner, &alert()).await;
        let activities = sink.activities();
        assert_eq!(activities.len(), 1, "{activities:?}");
        assert!(
            activities[0].contains("WEBHOOK[channel-5]=DELIVERED"),
            "{activities:?}"
        );
        assert!(activities[0].ends_with("|info"), "{activities:?}");
    }

    #[tokio::test]
    async fn email_without_recipient_is_not_attempted() {
        let sink = FakeSink::new(vec![channel(
            6,
            "EMAIL",
            1,
            Some(r#"{"host":"smtp.example.com","from":"noreply@example.com"}"#),
        )])
        .with_store(fake_store());
        dispatch_alert(&sink, &alert()).await;
        let activities = sink.activities();
        assert!(
            activities[0].contains("EMAIL[channel-6]=NOT_ATTEMPTED"),
            "{activities:?}"
        );
    }

    #[tokio::test]
    async fn invalid_config_is_contained_per_channel() {
        let sink = FakeSink::new(vec![
            channel(7, "SMS", 1, Some(r#"{"url":"http://169.254.169.254/x"}"#)),
            channel(
                8,
                "WEBHOOK",
                1,
                Some(r#"{"url":"https://hooks.example.com/x"}"#),
            ),
        ])
        .with_store(fake_store());
        let transport = StaticTransport::delivered();
        let owner = DeliveryOwner::builder(Some(fake_store()))
            .transport(Arc::new(transport))
            .build();
        dispatch_alert_with_owner(&sink, &owner, &alert()).await;
        let activities = sink.activities();
        assert!(
            activities[0].contains("SMS[channel-7]=NOT_ATTEMPTED"),
            "{activities:?}"
        );
        assert!(
            activities[0].contains("WEBHOOK[channel-8]=DELIVERED"),
            "{activities:?}"
        );
        assert!(activities[0].ends_with("|info"), "{activities:?}");
    }

    #[tokio::test]
    async fn same_alert_firing_does_not_redispatch_after_terminal_truth() {
        let sink = FakeSink::new(vec![channel(
            9,
            "WEBHOOK",
            1,
            Some(r#"{"url":"https://hooks.example.com/x"}"#),
        )])
        .with_store(fake_store());
        let transport = Arc::new(StaticTransport::delivered());
        let owner = DeliveryOwner::builder(Some(fake_store()))
            .transport(transport.clone())
            .build();
        dispatch_alert_with_owner(&sink, &owner, &alert()).await;
        dispatch_alert_with_owner(&sink, &owner, &alert()).await;
        assert_eq!(
            transport.calls(),
            1,
            "same firing must not re-dispatch after terminal truth"
        );
    }
}
