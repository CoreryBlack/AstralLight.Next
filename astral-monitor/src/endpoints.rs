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
    pub local_message_store: String,
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
///
/// 状态语义（redis 编译层退役后，redis-layer-retirement-20261002）：
/// - `NOT_CONFIGURED`：**Redis 依赖未启用**——`redis_url` 未配置、compat 旗标
///   未开启、或本二进制未编译 `redis-compat` feature。这是**中性事实**：聚合
///   仅由 DB 决定，绝不因"未启用"而降级健康（默认 Redis-free 部署零 Redis，
///   默认 Redis 绝不成为健康 gate）；
/// - `UP`/`DOWN`：compat 已启用（feature 编译 + 旗标开启 + URL 非空）时的实际
///   PING 结果（DOWN = 确定性失败，保留 compat 模式故障可观测性）；
/// - `UNKNOWN`：**仅保留**"已启用但探测无法确定"（PING 超时）。聚合仍保守
///   降级（不当中性），不得当作健康放行。
async fn check_redis_health(config: &astral_common::config::AppConfig) -> String {
    let compat_demanded =
        config.redis_projection_compat_enabled && !config.redis_url.trim().is_empty();
    #[cfg(feature = "redis-compat")]
    {
        if !compat_demanded {
            return "NOT_CONFIGURED".into();
        }
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(PROBE_TIMEOUT_SECS), async {
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
            // 已启用但探测无法确定（超时）→ 保守 UNKNOWN，聚合按依赖故障降级。
            Err(_) => "UNKNOWN".into(),
        }
    }
    #[cfg(not(feature = "redis-compat"))]
    {
        if compat_demanded {
            // 集中启动校验（astral-common validate_runtime_safety）应已拒绝该
            // 配置；探测面兜底告警，保持不静默。
            tracing::warn!(
                "redis_projection_compat_enabled requires a `redis-compat` feature build; probe reports NOT_CONFIGURED"
            );
        }
        "NOT_CONFIGURED".into()
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

/// 网关状态：配置 URI 缺失时明确 UNKNOWN（不伪造 UP）。
async fn gateway_status(state: &AppState) -> String {
    if state.config.gateway_service_uri.is_empty() {
        return "UNKNOWN".into();
    }
    query_service_status(state, "gateway").await
}

/// 聚合 DB 与 Redis 探针结果（纯函数）。
///
/// 区分三种 Redis 状态：
/// - `NOT_CONFIGURED`：Redis 未配置（Redis-free 部署），属中性事实，
///   不参与降级判定；聚合状态仅由 DB 决定（DB UP → `UP`，否则 `DOWN`）。
/// - `UNKNOWN`：已启用但探测结果无法确定（如 PING 超时），一律保守处理：
///   DB UP → `DEGRADED`，DB DOWN → `DOWN`；不得当作健康放行，避免掩盖已启用
///   依赖的未知故障。（"compat 未启用/未编译"不再是 UNKNOWN——归入
///   `NOT_CONFIGURED` 中性事实，默认部署绝不因 Redis 未启用而降级。）
/// - `UP`/`DOWN`：实际探测结果，沿用原语义：双 `UP` → `UP`，双 `DOWN` → `DOWN`，
///   其余组合 → `DEGRADED`（保留 compat 模式 Redis 故障可观测性）。
fn aggregate_health_status(db: &str, redis: &str) -> String {
    if redis == "NOT_CONFIGURED" {
        return if db == "UP" {
            "UP".into()
        } else {
            "DOWN".into()
        };
    }
    match (db == "UP", redis == "UP") {
        (true, true) => "UP".into(),
        (false, false) => "DOWN".into(),
        // (true, false)：DB UP + Redis DOWN/UNKNOWN → DEGRADED（保守）；
        // (false, true)：DB DOWN + Redis UP → DEGRADED。
        _ => "DEGRADED".into(),
    }
}

async fn health_check(State(state): State<AppState>) -> Json<HealthStatus> {
    let (db, redis) = tokio::join!(check_db_health(&state), check_redis_health(&state.config));
    let status = aggregate_health_status(&db, &redis);
    Json(HealthStatus {
        service: "astral-monitor".into(),
        status,
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
    let local_message_store = local_message_store_status(&state.config, false);
    Ok(Json(ApiResponse::success(ServiceStatus {
        gateway,
        identity,
        learn,
        trustgraph,
        database: db_status,
        redis,
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
            "status": aggregate_health_status(&db_status, &redis_status),
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
    let local_message_store = local_message_store_status(&state.config, false);
    Ok(Json(ApiResponse::success(ServiceStatus {
        gateway,
        identity,
        learn,
        trustgraph,
        database: db_status,
        redis,
        rabbitmq,
        local_message_store,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_is_up_when_db_up_and_redis_not_configured() {
        // Redis-free 部署：仅 NOT_CONFIGURED 中性，DB 健康即整体 UP。
        assert_eq!(aggregate_health_status("UP", "NOT_CONFIGURED"), "UP");
    }

    #[test]
    fn aggregate_follows_db_alone_when_redis_not_configured() {
        assert_eq!(aggregate_health_status("DOWN", "NOT_CONFIGURED"), "DOWN");
    }

    #[test]
    fn configured_unknown_is_conservative_unlike_not_configured() {
        // 已配置但探针 UNKNOWN（如 compat 关闭未探测、未来探针内部未知态）
        // 不得当作健康放行：与未配置（中性）明确区分，DB UP 保守降级为 DEGRADED。
        assert_eq!(aggregate_health_status("UP", "UNKNOWN"), "DEGRADED");
        // DB DOWN 时 UNKNOWN 与 DOWN 同为 DOWN（DB 故障主导，同样不放行）。
        assert_eq!(aggregate_health_status("DOWN", "UNKNOWN"), "DOWN");
    }

    #[test]
    fn configured_redis_fault_keeps_degraded_observability() {
        // compat 模式：Redis 已配置但故障必须可见。
        assert_eq!(aggregate_health_status("UP", "DOWN"), "DEGRADED");
        assert_eq!(aggregate_health_status("DOWN", "UP"), "DEGRADED");
    }

    #[test]
    fn configured_redis_both_up_is_up_and_both_down_is_down() {
        assert_eq!(aggregate_health_status("UP", "UP"), "UP");
        assert_eq!(aggregate_health_status("DOWN", "DOWN"), "DOWN");
    }

    /// 空 redis_url 走未配置早退分支，不打开任何 socket。
    #[tokio::test]
    async fn redis_probe_reports_not_configured_when_url_empty() {
        let config = astral_common::config::AppConfig::default();
        assert!(config.redis_url.is_empty());
        assert_eq!(check_redis_health(&config).await, "NOT_CONFIGURED");
    }

    /// 已配置 redis_url 但 compat 关闭：按契约不连接 Redis，返回 UNKNOWN
    /// （聚合侧保守降级），同样不打开任何 socket。
    #[tokio::test]
    async fn redis_probe_skips_connection_when_compat_disabled() {
        let config = astral_common::config::AppConfig {
            redis_url: "redis://127.0.0.1:1/".into(),
            redis_projection_compat_enabled: false,
            ..Default::default()
        };
        // redis 编译层退役后语义：compat 未启用 = 依赖未启用 = 中性事实
        // NOT_CONFIGURED（不再报告 UNKNOWN，默认部署绝不因 Redis 未启用降级）。
        assert_eq!(check_redis_health(&config).await, "NOT_CONFIGURED");
    }

    /// compat 开启但 URL 无法解析：Client::open 同步解析失败即 DOWN，
    /// 不发起任何连接。（仅 redis-compat feature 编译可探测；feature-off
    /// 构建恒 NOT_CONFIGURED，见 `check_redis_health` 语义注释。）
    #[cfg(feature = "redis-compat")]
    #[tokio::test]
    async fn redis_probe_reports_down_on_unparseable_url() {
        let config = astral_common::config::AppConfig {
            redis_url: "::not a redis url".into(),
            redis_projection_compat_enabled: true,
            ..Default::default()
        };
        assert_eq!(check_redis_health(&config).await, "DOWN");
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
