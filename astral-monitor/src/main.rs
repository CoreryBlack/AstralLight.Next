//! AstralMonitor 启动入口

use std::sync::Arc;

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

    // 启动定时采集（系统/服务/Redis 指标、告警评估、每日清理）
    collector::spawn_collector(state.clone());

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
    axum::serve(listener, app).await?;
    Ok(())
}
