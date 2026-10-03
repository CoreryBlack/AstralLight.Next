//! AstralMonitor 启动入口

use std::future::IntoFuture;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use policy_engine::{get_consistency_checker, PolicyEngine};

use astral_common::audit::{AuditDbWriter, AuditEntry};
use astral_common::config::AppConfig;
use astral_common::contract::ApiResponse;
use astral_common::error::global_exception_handler;
use astral_common::middleware::gateway_signature::gateway_signature_middleware;
use astral_common::tracing::init_tracing;
use astral_db::connect_and_validate_schema;
use astral_monitor::{
    alerts, collector, dashboard, endpoints, notifications, repository::SqlxMonitorRepository,
    service::MonitorService, AppState,
};

mod middleware;

struct MonitorAuditDbWriter {
    pool: sqlx::MySqlPool,
}

#[async_trait::async_trait]
impl AuditDbWriter for MonitorAuditDbWriter {
    async fn insert_audit(&self, entry: &AuditEntry) -> Result<(), String> {
        astral_db::insert_audit_log(&self.pool, entry)
            .await
            .map_err(|e| e.to_string())
    }
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SystemInfo {
    os: &'static str,
    arch: &'static str,
    version: &'static str,
    uptime_seconds: u64,
}

async fn metrics_summary(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<serde_json::Value>>, astral_common::error::AppError> {
    Ok(Json(ApiResponse::success(
        state.monitor_service.recent_metrics_summary().await?,
    )))
}

async fn system_info() -> Json<ApiResponse<SystemInfo>> {
    Json(ApiResponse::success(SystemInfo {
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        version: env!("CARGO_PKG_VERSION"),
        uptime_seconds: 0,
    }))
}

async fn dashboard_summary(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<serde_json::Value>>, astral_common::error::AppError> {
    Ok(Json(ApiResponse::success(
        state.monitor_service.dashboard_summary().await?,
    )))
}

async fn consistency_summary() -> Json<ApiResponse<serde_json::Value>> {
    let checker = get_consistency_checker();
    Json(ApiResponse::success(serde_json::json!({
        "stats": checker.get_stats(),
        "violations": checker.get_violations(),
    })))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    // Prometheus 指标暴露：默认 loopback 抓取端口；
    // METRICS_LISTEN_ADDR 覆盖，置空显式禁用。观测失败不影响主服务。
    if let Some(metrics_addr) =
        astral_common::metrics_runtime::metrics_listen_addr("127.0.0.1:9101")
    {
        match astral_common::metrics_runtime::install_prometheus_recorder() {
            Ok(handle) => {
                astral_common::metrics_runtime::spawn_metrics_server(metrics_addr, handle);
            }
            Err(error) => {
                tracing::error!(error = %error, "prometheus recorder install failed; /metrics disabled")
            }
        }
    }

    let config = Arc::new(AppConfig::from_files("application")?);
    // Redis 编译层退役收口（redis-layer-retirement-20261002）：宿主能力门 +
    // 已校验旗标一次性冻结。astral-common 的零依赖 marker 会被 workspace
    // feature 统一放大——任何其他 crate 打开 redis-compat 都会让集中校验的
    // cfg 通过，即便本宿主并未编译自己的 compat adapter（历史上只留下 log
    // 静默跳过）。能力断言以**本 crate** 的 cfg! 为准：旗标开启但 Monitor
    // 未编译 redis-compat adapter 时，在任何 DB 连接 / collector / 服务装配
    // 之前显式拒绝启动（fail-closed，非 log-only）；随后把已校验旗标冻结进
    // 进程级共享源（first-wins、同值幂等、异值冲突拒绝）。
    config
        .validate_redis_adapter_support(cfg!(feature = "redis-compat"))
        .map_err(anyhow::Error::msg)?;
    astral_common::config::install_redis_projection_compat(config.redis_projection_compat_enabled)
        .map_err(anyhow::Error::msg)?;
    let db = connect_and_validate_schema(&config.database_url).await?;
    let engine = Arc::new(PolicyEngine::new());
    astral_common::audit::register_audit_db_writer(Arc::new(MonitorAuditDbWriter {
        pool: db.clone(),
    }));
    let monitor_service = Arc::new(MonitorService::new(Arc::new(SqlxMonitorRepository::new(
        db.clone(),
    ))));

    astral_common::middleware::permission_check_shared::validate_path_map(
        middleware::MONITOR_PATH_MAP,
        "monitor",
    );
    let state = AppState {
        config,
        db,
        engine,
        monitor_service,
    };

    // 启动定时采集（系统/服务/Redis 指标、告警评估、每日清理）；持有所有权直到有界停机。
    let mut collector = collector::spawn_collector(state.clone());

    let api_routes = Router::new()
        .merge(alerts::alert_routes())
        .merge(notifications::notification_routes())
        .merge(dashboard::dashboard_routes())
        .route("/metrics", get(metrics_summary))
        .route("/system-info", get(system_info))
        .route("/dashboard", get(dashboard_summary))
        .route("/consistency-check", get(consistency_summary))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::monitor_permission_middleware,
        ));

    let frontend_health_routes = Router::new()
        .route("/health", get(endpoints::frontend_health_check))
        .route("/health/metrics", get(endpoints::frontend_metrics));

    let app = Router::new()
        .nest("/actuator", endpoints::monitor_routes())
        .nest("/api/v1/monitor", api_routes)
        .nest("/api", frontend_health_routes)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            gateway_signature_middleware,
        ))
        .layer(axum::middleware::from_fn(global_exception_handler))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state);

    let addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:9006".into());
    tracing::info!(addr = %addr, "monitor service starting");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let mut serve = std::pin::pin!(axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        })
        .into_future());
    let (serve_result, graceful_shutdown) = tokio::select! {
        result = &mut serve => (
            result.map_err(|error| anyhow::anyhow!("monitor HTTP serve failed: {error}")),
            false,
        ),
        signal = tokio::signal::ctrl_c() => {
            let signal_error = signal.err();
            if let Some(error) = &signal_error {
                tracing::error!(error = %error, "monitor Ctrl-C handler failed; initiating shutdown anyway");
            }
            let _ = shutdown_tx.send(());
            let drain_result = match tokio::time::timeout(Duration::from_secs(30), &mut serve).await {
                Ok(result) => result
                    .map_err(|error| anyhow::anyhow!("monitor HTTP serve failed: {error}")),
                Err(_) => Err(anyhow::anyhow!(
                    "monitor HTTP graceful drain timed out; in-flight request outcomes unknown"
                )),
            };
            let serve_result = match (signal_error, drain_result) {
                (Some(signal_error), Err(drain_error)) => Err(anyhow::anyhow!(
                    "monitor Ctrl-C handler failed ({signal_error}); HTTP drain also failed ({drain_error})"
                )),
                (Some(signal_error), Ok(())) => Err(anyhow::anyhow!(
                    "monitor Ctrl-C handler failed: {signal_error}"
                )),
                (None, drain_result) => drain_result,
            };
            (serve_result, true)
        }
        death = collector.wait_for_death() => {
            let _ = shutdown_tx.send(());
            let failure = match tokio::time::timeout(Duration::from_secs(30), &mut serve).await {
                Ok(Ok(())) => format!("required monitor collector exited: {death}"),
                Ok(Err(error)) => format!(
                    "required monitor collector exited: {death}; HTTP drain failed: {error}"
                ),
                Err(_) => format!(
                    "required monitor collector exited: {death}; HTTP drain timed out; request outcomes unknown"
                ),
            };
            (Err(anyhow::anyhow!(failure)), true)
        }
    };
    if !graceful_shutdown {
        collector.request_shutdown();
    }

    let collector_result = collector.shutdown(Duration::from_secs(10)).await;
    let audit_result = astral_common::audit::drain_owned_audit_tasks(Duration::from_secs(5)).await;
    let mut shutdown_errors = Vec::new();
    if let Err(error) = serve_result {
        tracing::error!(error = %error, "monitor HTTP server stopped with error");
        shutdown_errors.push(format!("HTTP server: {error:#}"));
    }
    if let Err(error) = collector_result {
        tracing::error!(error = %error, "monitor collector shutdown failed");
        shutdown_errors.push(format!("collector shutdown: {error}"));
    }
    if let Err(error) = audit_result {
        tracing::error!(error = %error, "owned audit drain failed");
        shutdown_errors.push(format!("owned audit drain: {error}"));
    }
    if shutdown_errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(shutdown_errors.join("; ")))
    }
}

#[cfg(test)]
mod shutdown_tests {
    #[test]
    fn collector_failure_drains_http_before_owned_audit() {
        let source = include_str!("main.rs");
        let branch = source
            .split("death = collector.wait_for_death() => {")
            .nth(1)
            .expect("collector death must remain observable")
            .split("let collector_result")
            .next()
            .unwrap();
        let stop = branch.find("shutdown_tx.send(())").unwrap();
        let drain = branch
            .find("timeout(Duration::from_secs(30), &mut serve)")
            .unwrap();
        assert!(stop < drain);
        assert!(branch.contains("request outcomes unknown"));
        assert!(branch.contains("Err(anyhow::anyhow!(failure))"));
    }
}
