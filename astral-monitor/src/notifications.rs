//! 通知渠道管理 — HTTP adapter + transport test dispatch。

use axum::extract::{Extension, Path, State};
use axum::http::HeaderMap;
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
    /// True only when the transport produced explicit end-delivery proof.
    /// Provider acceptance (2xx without receipt, SMTP 250) is NOT success.
    pub success: bool,
    pub message: String,
    pub channel_type: String,
    /// Typed delivery truth: DELIVERED, ACCEPTED, FAILED, IN_DOUBT,
    /// RETRY_SCHEDULED, NOT_ATTEMPTED, or UNSUPPORTED.
    pub delivery_status: &'static str,
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
    headers: HeaderMap,
    Extension(policy): Extension<astral_types::PolicyContext>,
    Extension(admission): Extension<astral_types::AuthorizationAdmission>,
    Json(request): Json<CreateChannelReq>,
) -> Result<Json<ApiResponse<NotificationChannel>>, AppError> {
    let context =
        crate::mutation::context(&headers, &policy, admission, "notification", "create", None)?;
    let mutation = crate::repository::MonitorMutation::CreateChannel {
        name: request.name,
        channel_type: request.channel_type,
        config: request.config.as_ref().map(ToString::to_string),
    };
    match state
        .monitor_service
        .protected_mutation(&context, mutation)
        .await?
    {
        crate::repository::MonitorMutationResult::Channel(channel) => {
            Ok(Json(ApiResponse::success(channel.into())))
        }
        _ => Err(crate::mutation::unexpected_result()),
    }
}

async fn update_channel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy): Extension<astral_types::PolicyContext>,
    Extension(admission): Extension<astral_types::AuthorizationAdmission>,
    Path(id): Path<i64>,
    Json(request): Json<CreateChannelReq>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let context = crate::mutation::context(
        &headers,
        &policy,
        admission,
        "notification",
        "update",
        Some(id),
    )?;
    state
        .monitor_service
        .protected_mutation(
            &context,
            crate::repository::MonitorMutation::UpdateChannel {
                id,
                name: request.name,
                channel_type: request.channel_type,
                config: request.config.as_ref().map(ToString::to_string),
            },
        )
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn test_channel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy): Extension<astral_types::PolicyContext>,
    Extension(admission): Extension<astral_types::AuthorizationAdmission>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<TestResult>>, AppError> {
    let context = crate::mutation::context(
        &headers,
        &policy,
        admission,
        "notification",
        "test",
        Some(id),
    )?;
    let channel = match state
        .monitor_service
        .protected_mutation(
            &context,
            crate::repository::MonitorMutation::TestChannel(id),
        )
        .await?
    {
        crate::repository::MonitorMutationResult::Channel(channel) => {
            NotificationChannel::from(channel)
        }
        _ => return Err(crate::mutation::unexpected_result()),
    };
    if channel.enabled == 0 {
        return Ok(Json(ApiResponse::success(TestResult {
            success: false,
            message: "通知渠道已禁用，请先启用".into(),
            channel_type: channel.channel_type,
            delivery_status: "NOT_ATTEMPTED",
        })));
    }

    // Unified real-delivery dispatcher: durable intent store from the shared
    // pool; the stable caller operation comes from the protected mutation
    // context, so repeated invocations of the same operation never re-send.
    let store: std::sync::Arc<dyn astral_common::delivery::DeliveryStore> = std::sync::Arc::new(
        astral_common::delivery::SqlxDeliveryIntentRepository::new(state.db.clone()),
    );
    let result = dispatch_test_notification(&channel, store, context.operation_id()).await;

    let detail = serde_json::json!({
        "channel_id": channel.id,
        "channel_type": channel.channel_type,
        "success": result.success,
        "delivery_status": result.delivery_status,
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

/// 统一测试派发入口（替代原 send_test_* 模拟分支）。
///
/// 调用方（`test_channel`）先完成 durable admission/use/audit，然后携带
/// 冻结的渠道行与受保护操作 id 调用本函数；外部投递由此开始：
/// - message id 由稳定 operation id 确定性派生：同一 operation 重复调用
///   不会重复外发，直接返回已终结的 durable truth；
/// - 上一次尝试 IN_DOUBT 时返回 IN_DOUBT（PENDING 对账语义），绝不盲目重发；
/// - 真值：服务商 2xx / SMTP 250 最多 ACCEPTED；DELIVERED 需要显式回执
///   （同步 webhook 2xx 或中继回执字段）。
pub(crate) async fn dispatch_test_notification(
    channel: &NotificationChannel,
    store: std::sync::Arc<dyn astral_common::delivery::DeliveryStore>,
    operation_id: &str,
) -> TestResult {
    let kind = match astral_common::delivery::ChannelKind::parse(&channel.channel_type) {
        Some(kind) => kind,
        None => {
            return TestResult {
                success: false,
                message: format!("不支持的渠道类型: {}", channel.channel_type),
                channel_type: channel.channel_type.clone(),
                delivery_status: "UNSUPPORTED",
            }
        }
    };
    let caller_operation = format!("monitor:notification-test:{operation_id}");
    let truth = astral_common::delivery::dispatch_channel_test(
        store,
        &caller_operation,
        kind,
        &channel.name,
        channel.config.as_deref(),
        "This is a test notification from AstralMonitor",
    )
    .await;
    test_result_from_truth(&channel.channel_type, truth)
}

/// Typed truth → API contract. `success` is true ONLY for DELIVERED.
fn test_result_from_truth(
    channel_type: &str,
    truth: astral_common::delivery::DeliveryTruth,
) -> TestResult {
    use astral_common::delivery::DeliveryState;
    let (success, delivery_status): (bool, &'static str) = match truth.state {
        DeliveryState::Delivered => (true, "DELIVERED"),
        DeliveryState::Accepted => (false, "ACCEPTED"),
        DeliveryState::InDoubt => (false, "IN_DOUBT"),
        DeliveryState::Queued => (false, "RETRY_SCHEDULED"),
        DeliveryState::NotAttempted => (false, "NOT_ATTEMPTED"),
        DeliveryState::Failed | DeliveryState::Expired => (false, "FAILED"),
    };
    TestResult {
        success,
        message: truth.detail,
        channel_type: channel_type.to_owned(),
        delivery_status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn channel(channel_type: &str, config: Option<&str>) -> NotificationChannel {
        NotificationChannel {
            id: 1,
            name: "test-channel".into(),
            channel_type: channel_type.into(),
            config: config.map(str::to_string),
            enabled: 1,
        }
    }

    fn store() -> std::sync::Arc<dyn astral_common::delivery::DeliveryStore> {
        std::sync::Arc::new(astral_common::delivery::InMemoryDeliveryStore::new())
    }

    #[tokio::test]
    async fn unconfigured_channels_are_typed_not_attempted_never_simulated() {
        for channel_type in ["EMAIL", "SMS", "DINGTALK", "WECHAT"] {
            let result =
                dispatch_test_notification(&channel(channel_type, None), store(), "op-1").await;
            assert!(!result.success, "{channel_type} must not claim success");
            assert_eq!(result.delivery_status, "NOT_ATTEMPTED", "{channel_type}");
        }
    }

    #[tokio::test]
    async fn inline_secret_config_is_rejected_before_dispatch() {
        let result = dispatch_test_notification(
            &channel(
                "EMAIL",
                Some(r#"{"host":"smtp.example.com","from":"a@b.c","password":"inline"}"#),
            ),
            store(),
            "op-secret",
        )
        .await;
        assert!(!result.success);
        assert_eq!(result.delivery_status, "NOT_ATTEMPTED");
        assert!(
            result.message.contains("env ref") || result.message.contains("secret"),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn unsupported_channel_kind_is_typed() {
        let result = dispatch_test_notification(&channel("FAX", None), store(), "op-2").await;
        assert!(!result.success);
        assert_eq!(result.delivery_status, "UNSUPPORTED");
    }

    #[tokio::test]
    async fn blocked_endpoint_is_not_attempted() {
        let result = dispatch_test_notification(
            &channel("WEBHOOK", Some(r#"{"url":"http://169.254.169.254/x"}"#)),
            store(),
            "op-3",
        )
        .await;
        assert!(!result.success);
        assert_eq!(result.delivery_status, "NOT_ATTEMPTED");
    }

    #[test]
    fn truth_mapping_caps_acceptance_below_success() {
        use astral_common::delivery::DeliveryTruth;
        let delivered =
            test_result_from_truth("WEBHOOK", DeliveryTruth::delivered(Some("p"), "ok"));
        assert!(delivered.success);
        assert_eq!(delivered.delivery_status, "DELIVERED");

        let accepted = test_result_from_truth("EMAIL", DeliveryTruth::accepted(None, "mta queued"));
        assert!(!accepted.success, "SMTP/relay acceptance is not delivery");
        assert_eq!(accepted.delivery_status, "ACCEPTED");

        let in_doubt = test_result_from_truth("SMS", DeliveryTruth::in_doubt("lost reply"));
        assert!(!in_doubt.success);
        assert_eq!(in_doubt.delivery_status, "IN_DOUBT");

        let retry = test_result_from_truth("SMS", DeliveryTruth::retry_scheduled("451"));
        assert!(!retry.success);
        assert_eq!(retry.delivery_status, "RETRY_SCHEDULED");

        let failed = test_result_from_truth("SMS", DeliveryTruth::failed("550"));
        assert!(!failed.success);
        assert_eq!(failed.delivery_status, "FAILED");

        let refused = test_result_from_truth("SMS", DeliveryTruth::not_attempted("no recipient"));
        assert!(!refused.success);
        assert_eq!(refused.delivery_status, "NOT_ATTEMPTED");
    }
}
