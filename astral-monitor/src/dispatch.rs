//! 告警通知派发 — 告警触发后向启用的通知渠道投递。
//!
//! 与 `notifications.rs` 的测试派发（`/test` 端点）互补：本模块是
//! `evaluate_alert_rules` 触发真实告警后的派发路径。WEBHOOK 渠道真实
//! 外发 HTTP；EMAIL/SMS/DINGTALK/WECHAT 保持显式模拟（与测试端点一致），
//! 仅计数不投递。
//!
//! 失败语义（事故链）：派发失败只记录日志与指标，绝不向上传播——
//! 告警持久化与采集循环不得因通知通道故障中断。

use async_trait::async_trait;

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

/// 派发依赖的最小端口：查询通知渠道 + 记录活动日志。
/// 独立于 `MonitorRepository`，测试用小型 fake 即可。
#[async_trait]
pub trait AlertNotificationSink: Send + Sync {
    async fn notification_channels(&self) -> Result<Vec<NotificationChannel>, AstralError>;
    async fn record_dispatch_activity(
        &self,
        title: &str,
        detail: &str,
        level: &str,
    ) -> Result<(), AstralError>;
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
}

/// 派发单条告警：对启用的 WEBHOOK 渠道逐一真实外发，并写一条活动日志汇总。
///
/// 无任何 WEBHOOK 渠道时不写活动日志（避免每个告警周期产生噪音行）。
pub async fn dispatch_alert<S: AlertNotificationSink + ?Sized>(
    sink: &S,
    alert: &AlertNotification,
) {
    let channels = match sink.notification_channels().await {
        Ok(channels) => channels,
        Err(error) => {
            tracing::warn!(error = %error, "alert notification skipped: channel list unavailable");
            return;
        }
    };

    let webhooks: Vec<&NotificationChannel> = channels
        .iter()
        .filter(|channel| {
            channel.enabled == 1 && channel.channel_type.eq_ignore_ascii_case("WEBHOOK")
        })
        .collect();
    let simulated = channels
        .iter()
        .filter(|channel| {
            channel.enabled == 1 && !channel.channel_type.eq_ignore_ascii_case("WEBHOOK")
        })
        .count();
    if simulated > 0 {
        tracing::debug!(
            simulated,
            "non-webhook channels are simulated; skipped on real alert"
        );
    }
    if webhooks.is_empty() {
        return;
    }

    let mut sent = 0usize;
    let mut failed = 0usize;
    for channel in &webhooks {
        match send_webhook_alert(channel, alert).await {
            Ok(status) => {
                sent += 1;
                metrics::counter!("astral_monitor_notifications_sent_total", "channel_type" => "WEBHOOK")
                    .increment(1);
                tracing::info!(channel = %channel.name, status = %status, "webhook alert delivered");
            }
            Err(error) => {
                failed += 1;
                metrics::counter!("astral_monitor_notifications_failed_total", "channel_type" => "WEBHOOK")
                    .increment(1);
                tracing::warn!(channel = %channel.name, error = %error, "webhook alert delivery failed");
            }
        }
    }

    let title = format!("告警通知 [{}]", alert.rule_name);
    let detail = format!(
        "{} 触发告警 {} = {:.2}（严重级别 {}）；WEBHOOK 成功 {} / 失败 {}",
        alert.triggered_at, alert.metric, alert.actual_value, alert.severity, sent, failed
    );
    let level = if failed > 0 { "warn" } else { "info" };
    if let Err(error) = sink.record_dispatch_activity(&title, &detail, level).await {
        tracing::warn!(error = %error, "alert dispatch activity recording failed");
    }
}

/// 构造告警 webhook payload（与测试端点 payload 风格一致的 camelCase 契约）。
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

/// 从渠道 config JSON 提取 `url`（缺失/为空返回错误）。
fn webhook_url(channel: &NotificationChannel) -> Result<String, String> {
    let config: serde_json::Value = channel
        .config
        .as_deref()
        .and_then(|value| serde_json::from_str(value).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    let url = config
        .get("url")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if url.is_empty() {
        return Err("Webhook URL 未配置".into());
    }
    Ok(url)
}

/// 真实外发告警 webhook：POST JSON，5s 超时，2xx 视为成功。
async fn send_webhook_alert(
    channel: &NotificationChannel,
    alert: &AlertNotification,
) -> Result<String, String> {
    let url = webhook_url(channel)?;
    let response = reqwest::Client::new()
        .post(&url)
        .json(&alert_payload(alert))
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .map_err(|error| format!("Webhook 发送失败: {error}"))?;
    let status = response.status();
    if status.is_success() {
        Ok(status.to_string())
    } else {
        Err(format!("Webhook 响应状态: {status}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

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
    }

    impl FakeSink {
        fn new(channels: Vec<NotificationChannel>) -> Self {
            Self {
                channels,
                activities: Mutex::new(Vec::new()),
                channels_error: false,
            }
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

    #[test]
    fn webhook_url_requires_configured_url() {
        assert_eq!(
            webhook_url(&channel(1, "WEBHOOK", 1, None)).unwrap_err(),
            "Webhook URL 未配置"
        );
        assert_eq!(
            webhook_url(&channel(1, "WEBHOOK", 1, Some(r#"{"url":"  "#))).unwrap_err(),
            "Webhook URL 未配置"
        );
        assert_eq!(
            webhook_url(&channel(
                1,
                "WEBHOOK",
                1,
                Some(r#"{"url":"http://h/hook"}"#)
            ))
            .unwrap(),
            "http://h/hook"
        );
    }

    #[tokio::test]
    async fn webhook_delivery_posts_alert_payload() {
        let captured: std::sync::Arc<std::sync::Mutex<Vec<String>>> = Default::default();
        let seen = captured.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let app = axum::Router::new().route(
                "/hook",
                axum::routing::post(move |body: axum::body::Bytes| {
                    let seen = seen.clone();
                    async move {
                        seen.lock()
                            .unwrap()
                            .push(String::from_utf8_lossy(&body).to_string());
                        axum::http::StatusCode::OK
                    }
                }),
            );
            axum::serve(listener, app).await.unwrap();
        });
        let target = format!("http://{addr}/hook");
        let result = send_webhook_alert(
            &channel(1, "WEBHOOK", 1, Some(&format!(r#"{{"url":"{target}"}}"#))),
            &alert(),
        )
        .await;
        server.abort();
        assert!(result.is_ok(), "delivery should succeed: {result:?}");
        let bodies = captured.lock().unwrap();
        assert_eq!(bodies.len(), 1, "exactly one delivery");
        let body = &bodies[0];
        assert!(body.contains("\"event\":\"alert\""), "captured: {body}");
        assert!(
            body.contains("\"ruleName\":\"CPU high\""),
            "captured: {body}"
        );
    }

    #[tokio::test]
    async fn webhook_delivery_fails_on_unreachable_url() {
        // 端口 1 上无监听，连接应快速被拒。
        let result = send_webhook_alert(
            &channel(
                1,
                "WEBHOOK",
                1,
                Some(r#"{"url":"http://127.0.0.1:1/hook"}"#),
            ),
            &alert(),
        )
        .await;
        assert!(result.is_err(), "unreachable webhook must fail: {result:?}");
    }

    #[tokio::test]
    async fn dispatch_without_webhook_channels_writes_no_activity() {
        let sink = FakeSink::new(vec![
            channel(2, "EMAIL", 1, None),
            channel(3, "WEBHOOK", 0, None),
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
    async fn dispatch_records_activity_summary_with_failures() {
        let sink = FakeSink::new(vec![channel(
            4,
            "WEBHOOK",
            1,
            Some(r#"{"url":"http://127.0.0.1:1/hook"}"#),
        )]);
        dispatch_alert(&sink, &alert()).await;
        let activities = sink.activities();
        assert_eq!(activities.len(), 1, "one summary activity row");
        assert!(
            activities[0].contains("WEBHOOK 成功 0 / 失败 1"),
            "{activities:?}"
        );
        assert!(activities[0].ends_with("|warn"), "{activities:?}");
    }

    #[tokio::test]
    async fn dispatch_success_activity_is_info_level() {
        let captured: std::sync::Arc<std::sync::Mutex<Vec<String>>> = Default::default();
        let seen = captured.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let app = axum::Router::new().route(
                "/hook",
                axum::routing::post(move |body: axum::body::Bytes| {
                    let seen = seen.clone();
                    async move {
                        seen.lock()
                            .unwrap()
                            .push(String::from_utf8_lossy(&body).to_string());
                        axum::http::StatusCode::OK
                    }
                }),
            );
            axum::serve(listener, app).await.unwrap();
        });
        let sink = FakeSink::new(vec![channel(
            5,
            "WEBHOOK",
            1,
            Some(&format!(r#"{{"url":"http://{addr}/hook"}}"#)),
        )]);
        dispatch_alert(&sink, &alert()).await;
        server.abort();
        assert_eq!(captured.lock().unwrap().len(), 1, "delivery must land");
        let activities = sink.activities();
        assert_eq!(activities.len(), 1, "{activities:?}");
        assert!(
            activities[0].contains("WEBHOOK 成功 1 / 失败 0"),
            "{activities:?}"
        );
        assert!(activities[0].ends_with("|info"), "{activities:?}");
    }
}
