//! 监控端点 — Actuator / 健康检查（Service adapter）
//!
//! `/health` 与 `/health/detailed` 使用带超时的实时 DB/RabbitMQ probe；
//! 历史 metric 仅用于趋势，不再把固定 `UP`/`UNKNOWN` 当作健康事实
//! （对齐 Java `HealthController` + `DashboardMonitoringService`）。

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use astral_common::contract::ApiResponse;
use astral_common::error::AppError;

use crate::AppState;

/// DB probe 超时（秒）
const PROBE_TIMEOUT_SECS: u64 = 2;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthStatus {
    pub service: String,
    pub status: String,
    pub uptime_seconds: u64,
    pub version: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceStatus {
    pub gateway: String,
    pub identity: String,
    pub trustgraph: String,
    pub database: String,
    pub rabbitmq: String,
    pub local_message_store: String,
}

/// Direct health probe exposed by the Monitor service port.
pub fn actuator_health_routes() -> Router<AppState> {
    Router::new().route("/health", get(health_check))
}

/// Actuator routes that remain behind Gateway signature verification.
pub fn monitor_routes() -> Router<AppState> {
    Router::new()
        .route("/health/detailed", get(detailed_health))
        .route("/metrics", get(metrics))
        .route("/status", get(service_status))
}

/// Frontend health routes are direct Monitor service endpoints and are not
/// Gateway proxy routes.
pub fn frontend_health_routes() -> Router<AppState> {
    Router::new()
        .route("/health", get(frontend_health_check))
        .route("/health/metrics", get(frontend_metrics))
}

/// 实时 DB probe：`SELECT 1`（2s 超时）。
async fn check_db_health(state: &AppState) -> String {
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(PROBE_TIMEOUT_SECS),
        sqlx::query_scalar::<_, i64>("SELECT 1").fetch_one(&state.db),
    )
    .await;
    match result {
        Ok(Ok(_)) => "UP".into(),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "db health probe failed");
            "DOWN".into()
        }
        Err(_) => "DOWN".into(),
    }
}

/// The in-process bus is the local transport readiness boundary. A database
/// probe is deliberately not used as a message-queue health signal.
fn local_message_store_status(
    config: &astral_common::config::AppConfig,
    local_bus_ready: bool,
) -> String {
    if !matches!(
        config.message_transport(),
        Ok(astral_common::config::MessageTransport::Local)
    ) {
        return "NOT_CONFIGURED".into();
    }
    if local_bus_ready {
        "UP".into()
    } else {
        "DOWN".into()
    }
}

/// RabbitMQ is a remote dependency only in explicit Rabbit transport mode.
/// Local mode reports NOT_CONFIGURED and never opens a socket.
async fn check_rabbitmq_health(config: &astral_common::config::AppConfig) -> String {
    if !matches!(
        config.message_transport(),
        Ok(astral_common::config::MessageTransport::Rabbit)
    ) {
        return "NOT_CONFIGURED".into();
    }
    if config.rabbitmq_url.is_empty() {
        return "NOT_CONFIGURED".into();
    }
    let Some((host, port)) = rabbitmq_host_port(&config.rabbitmq_url) else {
        tracing::warn!("rabbitmq health probe failed: unparseable url");
        return "UNKNOWN".into();
    };
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(PROBE_TIMEOUT_SECS),
        tokio::net::TcpStream::connect((host.as_str(), port)),
    )
    .await;
    match result {
        Ok(Ok(_)) => "UP".into(),
        Ok(Err(e)) => {
            tracing::warn!(host, port, error = %e, "rabbitmq health probe failed");
            "DOWN".into()
        }
        Err(_) => "DOWN".into(),
    }
}

/// 从 amqp(s)://user:pass@host:port/vhost 解析 host:port（默认 5672）。
/// 不含任何硬编码 IP/凭据。
fn rabbitmq_host_port(url: &str) -> Option<(String, u16)> {
    let rest = url
        .strip_prefix("amqp://")
        .or_else(|| url.strip_prefix("amqps://"))?;
    let authority = rest.split('/').next().unwrap_or("");
    let hostport = match authority.rfind('@') {
        Some(idx) => &authority[idx + 1..],
        None => authority,
    };
    let hostport = hostport.trim();
    if hostport.is_empty() {
        return None;
    }
    match hostport.rfind(':') {
        Some(idx) => {
            let host = &hostport[..idx];
            let port = hostport[idx + 1..].parse::<u16>().ok()?;
            Some((host.to_string(), port))
        }
        None => Some((hostport.to_string(), 5672)),
    }
}

/// Gateway has no registered standalone public health route in the current runtime.
/// Until a signed service-probe contract exists, use only persisted evidence and
/// return UNKNOWN when none is present.
async fn gateway_status(state: &AppState) -> String {
    query_service_status(state, "gateway").await
}

async fn health_check(State(state): State<AppState>) -> (StatusCode, Json<HealthStatus>) {
    let status = check_db_health(&state).await;
    let http_status = health_http_status(&status);
    (
        http_status,
        Json(HealthStatus {
            service: "astral-monitor".into(),
            status,
            uptime_seconds: 0,
            version: env!("CARGO_PKG_VERSION").into(),
        }),
    )
}

fn health_http_status(status: &str) -> StatusCode {
    if status == "UP" {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn query_service_status(state: &AppState, service_name: &str) -> String {
    match state
        .monitor_service
        .latest_metric(service_name, "probe_status_unknown")
        .await
    {
        Ok(Some(value)) if value > 0.0 => return "UNKNOWN".into(),
        Ok(Some(_)) | Ok(None) => {}
        Err(_) => return "UNKNOWN".into(),
    }
    match state
        .monitor_service
        .latest_metric(service_name, "reachable")
        .await
    {
        Ok(Some(value)) if value > 0.0 => "UP".into(),
        Ok(Some(0.0)) => "DOWN".into(),
        Ok(Some(_)) | Ok(None) | Err(_) => "UNKNOWN".into(),
    }
}

async fn detailed_health(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<ServiceStatus>>, AppError> {
    let (db_status, gateway, identity, trustgraph, rabbitmq) = tokio::join!(
        check_db_health(&state),
        gateway_status(&state),
        query_service_status(&state, "identity"),
        query_service_status(&state, "trustgraph"),
        check_rabbitmq_health(&state.config),
    );
    let local_message_store = local_message_store_status(&state.config, false);
    Ok(Json(ApiResponse::success(ServiceStatus {
        gateway,
        identity,
        trustgraph,
        database: db_status,
        rabbitmq,
        local_message_store,
    })))
}

/// 权限检查计数（来自 DB metric；无数据时输出 0，不再硬编码假计数）。
async fn permission_metrics(state: &AppState) -> String {
    let checks = state
        .monitor_service
        .recent_metric_count()
        .await
        .unwrap_or(0);
    format!(
        "# HELP astral_permission_checks_total Total permission checks\n# TYPE astral_permission_checks_total counter\nastral_permission_checks_total {}\n",
        checks
    )
}

async fn metrics(State(state): State<AppState>) -> String {
    permission_metrics(&state).await
}

pub async fn frontend_health_check(
    State(state): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    let db_status = check_db_health(&state).await;
    let healthy = db_status == "UP";
    let http_status = health_http_status(&db_status);
    let response_code = http_status.as_u16();
    let permission_checks = state
        .monitor_service
        .recent_metric_count()
        .await
        .unwrap_or(0);
    let metrics_available = permission_checks > 0;
    (
        http_status,
        Json(serde_json::json!({
            "code": response_code,
            "success": healthy,
            "message": if healthy { "操作成功" } else { "依赖不可用" },
            "data": {
                "application": "astral-monitor",
                "timestamp": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis(),
                "uptimeMs": 0,
                "path": "/api/health",
                "database": {
                    "healthy": healthy,
                    "status": db_status,
                    "driver": "mysql",
                },
                "metrics": {
                    "ordersCreated": 0,
                    "paymentSuccess": 0,
                    "paymentFailure": 0,
                    "permissionDenied": 0,
                    "permissionChecksTotal": permission_checks,
                    "metricsAvailable": metrics_available,
                },
                "status": if healthy { "UP" } else { "DOWN" },
            },
        })),
    )
}

pub async fn frontend_metrics(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, AppError> {
    let permission_checks = state
        .monitor_service
        .recent_metric_count()
        .await
        .unwrap_or(0);
    let metrics_available = permission_checks > 0;
    Ok(Json(serde_json::json!({
        "code": 200,
        "success": true,
        "message": "操作成功",
        "data": {
            "ordersCreated": 0,
            "paymentSuccess": 0,
            "paymentFailure": 0,
            "permissionDenied": 0,
            "permissionChecksTotal": permission_checks,
            "metricsAvailable": metrics_available,
        },
    })))
}

async fn service_status(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<ServiceStatus>>, AppError> {
    let (db_status, gateway, identity, trustgraph, rabbitmq) = tokio::join!(
        check_db_health(&state),
        gateway_status(&state),
        query_service_status(&state, "identity"),
        query_service_status(&state, "trustgraph"),
        check_rabbitmq_health(&state.config),
    );
    let local_message_store = local_message_store_status(&state.config, false);
    Ok(Json(ApiResponse::success(ServiceStatus {
        gateway,
        identity,
        trustgraph,
        database: db_status,
        rabbitmq,
        local_message_store,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_status_maps_only_up_to_success() {
        assert_eq!(health_http_status("UP"), StatusCode::OK);
        for status in ["DOWN", "UNKNOWN", "NOT_CONFIGURED"] {
            assert_eq!(health_http_status(status), StatusCode::SERVICE_UNAVAILABLE);
        }
    }

    #[test]
    fn local_message_store_reports_not_configured_outside_local_mode() {
        let config = astral_common::config::AppConfig::default();
        assert_eq!(
            config.message_transport(),
            Ok(astral_common::config::MessageTransport::Rabbit)
        );
        assert_eq!(local_message_store_status(&config, false), "NOT_CONFIGURED");
        assert_eq!(local_message_store_status(&config, true), "NOT_CONFIGURED");
    }

    #[test]
    fn local_message_store_reports_bus_readiness_in_local_mode() {
        let config = astral_common::config::AppConfig {
            message_transport: "local".into(),
            ..Default::default()
        };
        assert_eq!(local_message_store_status(&config, false), "DOWN");
        assert_eq!(local_message_store_status(&config, true), "UP");
    }
}
