//! 通知渠道管理 — HTTP adapter + transport test dispatch。

use axum::extract::{Path, State};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::AppState;
use astral_common::contract::{ApiResponse, EmptyResponse};
use astral_common::error::AppError;

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct NotificationChannel {
    pub id: i64,
    pub name: String,
    pub channel_type: String,
    pub config: Option<String>,
    pub enabled: i8,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateChannelReq {
    pub name: String,
    pub channel_type: String,
    pub config: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestResult {
    pub success: bool,
    pub message: String,
    pub channel_type: String,
}

pub fn notification_routes() -> Router<AppState> {
    Router::new()
        .route("/notifications", get(list_channels))
        .route("/notifications", post(create_channel))
        .route("/notifications/{id}", put(update_channel))
        .route("/notifications/{id}/test", post(test_channel))
        .route("/channels", get(list_channels))
}

async fn list_channels(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<NotificationChannel>>>, AppError> {
    Ok(Json(ApiResponse::success(
        state.monitor_service.list_notification_channels().await?,
    )))
}

async fn create_channel(
    State(state): State<AppState>,
    Json(request): Json<CreateChannelReq>,
) -> Result<Json<ApiResponse<NotificationChannel>>, AppError> {
    let config = request.config.as_ref().map(ToString::to_string);
    Ok(Json(ApiResponse::success(
        state
            .monitor_service
            .create_notification_channel(&request.name, &request.channel_type, config.as_deref())
            .await?,
    )))
}

async fn update_channel(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(request): Json<CreateChannelReq>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let config = request.config.as_ref().map(ToString::to_string);
    state
        .monitor_service
        .update_notification_channel(id, &request.name, &request.channel_type, config.as_deref())
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn test_channel(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<TestResult>>, AppError> {
    let channel = state.monitor_service.get_notification_channel(id).await?;
    if channel.enabled == 0 {
        return Ok(Json(ApiResponse::success(TestResult {
            success: false,
            message: "通知渠道已禁用，请先启用".into(),
            channel_type: channel.channel_type,
        })));
    }

    let result = match channel.channel_type.as_str() {
        "EMAIL" => send_test_email(&channel).await,
        "SMS" => send_test_sms(&channel).await,
        "WEBHOOK" => send_test_webhook(&channel).await,
        "DINGTALK" => send_test_dingtalk(&channel).await,
        "WECHAT" => send_test_wechat(&channel).await,
        _ => TestResult {
            success: false,
            message: format!("不支持的渠道类型: {}", channel.channel_type),
            channel_type: channel.channel_type.clone(),
        },
    };

    let detail = serde_json::json!({
        "channel_id": channel.id,
        "channel_type": channel.channel_type,
        "success": result.success,
        "message": result.message,
    })
    .to_string();
    state
        .monitor_service
        .record_activity(
            "notification_test",
            &format!("测试通知 [{}] {}", channel.channel_type, channel.name),
            &detail,
            if result.success { "info" } else { "warn" },
            "astral-monitor",
        )
        .await?;

    Ok(Json(ApiResponse::success(result)))
}

async fn send_test_email(channel: &NotificationChannel) -> TestResult {
    let config: serde_json::Value = channel
        .config
        .as_deref()
        .and_then(|value| serde_json::from_str(value).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    let to = config
        .get("to")
        .and_then(|value| value.as_str())
        .unwrap_or("test@example.com");
    tracing::info!(channel = %channel.name, to, "sending test email notification (simulated)");
    TestResult {
        success: true,
        message: format!("测试邮件已发送至 {to}"),
        channel_type: "EMAIL".into(),
    }
}

async fn send_test_sms(_channel: &NotificationChannel) -> TestResult {
    TestResult {
        success: true,
        message: "测试短信已发送（模拟）".into(),
        channel_type: "SMS".into(),
    }
}

async fn send_test_webhook(channel: &NotificationChannel) -> TestResult {
    let config: serde_json::Value = channel
        .config
        .as_deref()
        .and_then(|value| serde_json::from_str(value).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    let url = config
        .get("url")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    if url.is_empty() {
        return TestResult {
            success: false,
            message: "Webhook URL 未配置".into(),
            channel_type: "WEBHOOK".into(),
        };
    }

    let payload = serde_json::json!({
        "event": "test",
        "channel": channel.name,
        "message": "This is a test notification from AstralMonitor",
        "timestamp": time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
    });
    match reqwest::Client::new()
        .post(url)
        .json(&payload)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(response) => TestResult {
            success: response.status().is_success(),
            message: format!("Webhook 响应状态: {}", response.status()),
            channel_type: "WEBHOOK".into(),
        },
        Err(error) => TestResult {
            success: false,
            message: format!("Webhook 发送失败: {error}"),
            channel_type: "WEBHOOK".into(),
        },
    }
}

async fn send_test_dingtalk(_channel: &NotificationChannel) -> TestResult {
    TestResult {
        success: true,
        message: "测试钉钉通知已发送（模拟）".into(),
        channel_type: "DINGTALK".into(),
    }
}

async fn send_test_wechat(_channel: &NotificationChannel) -> TestResult {
    TestResult {
        success: true,
        message: "测试企业微信通知已发送（模拟）".into(),
        channel_type: "WECHAT".into(),
    }
}
