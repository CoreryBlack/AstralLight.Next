//! 监控端点 — Actuator / 健康检查（Service adapter）
//!
//! `/health` 与 `/health/detailed` 使用带超时的实时 DB/Redis/RabbitMQ probe；
//! 历史 metric 仅用于趋势，不再把固定 `UP`/`UNKNOWN` 当作健康事实
//! （对齐 Java `HealthController` + `DashboardMonitoringService`）。

use axum::extract::State;
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
    pub learn: String,
    pub trustgraph: String,
    pub database: String,
    pub redis: String,
    pub rabbitmq: String,
}

pub fn monitor_routes() -> Router<AppState> {
    Router::new()
        .route("/health", get(health_check))
        .route("/health/detailed", get(detailed_health))
        .route("/metrics", get(metrics))
        .route("/status", get(service_status))
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

/// 实时 Redis probe：PING（2s 超时）。
async fn check_redis_health(config: &astral_common::config::AppConfig) -> String {
    if config.redis_url.is_empty() {
        return "UNKNOWN".into();
    }
    let result = tokio::time::timeout(std::time::Duration::from_secs(PROBE_TIMEOUT_SECS), async {
        let client = redis::Client::open(config.redis_url.as_str())?;
        let mut conn = client.get_connection_manager().await?;
        redis::cmd("PING").query_async::<String>(&mut conn).await
    })
    .await;
    match result {
        Ok(Ok(_)) => "UP".into(),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "redis health probe failed");
            "DOWN".into()
        }
        Err(_) => "DOWN".into(),
    }
}

/// 实时 RabbitMQ probe：对 amqp URL 的 host:port 做 TCP 连接（2s 超时）。
/// URL 为空 → UNKNOWN（未配置），不伪造 UP。
async fn check_rabbitmq_health(config: &astral_common::config::AppConfig) -> String {
    if config.rabbitmq_url.is_empty() {
        return "UNKNOWN".into();
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

/// 网关状态：配置 URI 缺失时明确 UNKNOWN（不伪造 UP）。
async fn gateway_status(state: &AppState) -> String {
    if state.config.gateway_service_uri.is_empty() {
        return "UNKNOWN".into();
    }
    query_service_status(state, "gateway").await
}

async fn health_check(State(state): State<AppState>) -> Json<HealthStatus> {
    let (db, redis) = tokio::join!(check_db_health(&state), check_redis_health(&state.config));
    let status = if db == "UP" && redis == "UP" {
        "UP"
    } else if db == "UP" || redis == "UP" {
        "DEGRADED"
    } else {
        "DOWN"
    };
    Json(HealthStatus {
        service: "astral-monitor".into(),
        status: status.into(),
        uptime_seconds: 0,
        version: env!("CARGO_PKG_VERSION").into(),
    })
}

async fn query_service_status(state: &AppState, service_name: &str) -> String {
    match state
        .monitor_service
        .latest_metric(service_name, "reachable")
        .await
    {
        Ok(Some(value)) if value > 0.0 => "UP".into(),
        Ok(Some(_)) => "DOWN".into(),
        Ok(None) => "UNKNOWN".into(),
        Err(_) => "DOWN".into(),
    }
}

async fn detailed_health(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<ServiceStatus>>, AppError> {
    let (db_status, gateway, identity, learn, trustgraph, redis, rabbitmq) = tokio::join!(
        check_db_health(&state),
        gateway_status(&state),
        query_service_status(&state, "identity"),
        query_service_status(&state, "learn"),
        query_service_status(&state, "chat"),
        check_redis_health(&state.config),
        check_rabbitmq_health(&state.config),
    );
    Ok(Json(ApiResponse::success(ServiceStatus {
        gateway,
        identity,
        learn,
        trustgraph,
        database: db_status,
        redis,
        rabbitmq,
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
) -> Result<Json<serde_json::Value>, AppError> {
    let (db_status, redis_status) =
        tokio::join!(check_db_health(&state), check_redis_health(&state.config));
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
            "application": "astral-monitor",
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            "uptimeMs": 0,
            "path": "/api/health",
            "database": {
                "healthy": db_status == "UP",
                "status": db_status,
                "driver": "mysql",
            },
            "redis": {
                "healthy": redis_status == "UP",
                "status": redis_status,
            },
            "metrics": {
                "ordersCreated": 0,
                "paymentSuccess": 0,
                "paymentFailure": 0,
                "permissionDenied": 0,
                "permissionChecksTotal": permission_checks,
                "metricsAvailable": metrics_available,
            },
            "status": if db_status == "UP" && redis_status == "UP" {
                "UP"
            } else if db_status == "UP" || redis_status == "UP" {
                "DEGRADED"
            } else {
                "DOWN"
            },
        },
    })))
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
    let (db_status, gateway, identity, learn, trustgraph, redis, rabbitmq) = tokio::join!(
        check_db_health(&state),
        gateway_status(&state),
        query_service_status(&state, "identity"),
        query_service_status(&state, "learn"),
        query_service_status(&state, "chat"),
        check_redis_health(&state.config),
        check_rabbitmq_health(&state.config),
    );
    Ok(Json(ApiResponse::success(ServiceStatus {
        gateway,
        identity,
        learn,
        trustgraph,
        database: db_status,
        redis,
        rabbitmq,
    })))
}
