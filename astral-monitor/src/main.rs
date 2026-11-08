//! AstralMonitor 启动入口

use std::future::IntoFuture;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use policy_engine::PolicyEngine;

use astral_common::audit::{AuditDbWriter, AuditEntry};
use astral_common::config::{AppConfig, JwtValidationRole};
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    astral_common::middleware::permission_check_shared::validate_path_map(
        middleware::MONITOR_PATH_MAP,
        "monitor",
    )?;

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

    let config = Arc::new(AppConfig::from_files_for(
        "application",
        JwtValidationRole::Gateway,
    )?);
    let db = connect_and_validate_schema(&config.database_url).await?;
    let authorization_fence_provider = astral_db::authority_provider_from_env(db.clone())
        .await
        .map_err(|error| {
            anyhow::anyhow!("authorization authority trust-root configuration invalid: {error}")
        })?;
    // Authority source outcome reconciliation runtime（V7）：provider 存在时
    // 运行与 TrustGraph/Identity 相同的共享生命周期任务；先于 collector 启动，
    // 因此按严格逆序在关闭尾段（HTTP drain、collector 停止与 owned audit
    // drain 之后）最后停止。provider 缺席时保持既有 fail-closed 行为：不启动、
    // 不产生正向就绪信号。Monitor 不持有 authority 私有材料，也不重复持有
    // provider/quorum 的批次与 allowlist 配置。
    let mut authority_source_outcome_runtime = authorization_fence_provider
        .clone()
        .map(astral_db::authority_source_runtime::spawn_authority_source_outcome_runtime);
    let engine = Arc::new(PolicyEngine::new());
    astral_common::audit::register_audit_db_writer(Arc::new(MonitorAuditDbWriter {
        pool: db.clone(),
    }));
    let monitor_service = Arc::new(MonitorService::new(Arc::new(SqlxMonitorRepository::new(
        db.clone(),
    ))));

    let state = AppState {
        config,
        db,
        engine,
        authorization_fence_provider,
        monitor_service,
    };

    // 启动定时采集（系统/服务指标、告警评估、每日清理）；持有所有权直到有界停机。
    let mut collector = collector::spawn_collector(state.clone());

    let app = build_router(state.clone());

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
        death = async {
            match authority_source_outcome_runtime.as_mut() {
                Some(handle) => handle.wait_for_death().await,
                None => std::future::pending().await,
            }
        } => {
            let _ = shutdown_tx.send(());
            let failure = match tokio::time::timeout(Duration::from_secs(30), &mut serve).await {
                Ok(Ok(())) => format!("required authority source outcome runtime exited: {death}"),
                Ok(Err(error)) => format!(
                    "required authority source outcome runtime exited: {death}; HTTP drain failed: {error}"
                ),
                Err(_) => format!(
                    "required authority source outcome runtime exited: {death}; HTTP drain timed out; request outcomes unknown"
                ),
            };
            (Err(anyhow::anyhow!(failure)), true)
        }
    };
    if !graceful_shutdown {
        collector.request_shutdown();
        if let Some(handle) = authority_source_outcome_runtime.as_ref() {
            handle.request_shutdown();
        }
    }

    let collector_result = collector.shutdown(Duration::from_secs(10)).await;
    let audit_result = astral_common::audit::drain_owned_audit_tasks(Duration::from_secs(5)).await;
    // Authority source outcome runtime：先于 collector 启动 → 严格逆序在
    // collector 停止与 owned audit drain 之后最后停止。在途 cycle 受 <=10s
    // deadline 约束；未知取消只留下 durable lease pending，绝不重放 source。
    // 失败与 panic 转为进程错误，绝不静默。
    let source_outcome_result = match authority_source_outcome_runtime.take() {
        Some(handle) => {
            handle
                .shutdown(astral_db::authority_source_runtime::SOURCE_OUTCOME_SHUTDOWN_JOIN_TIMEOUT)
                .await
        }
        None => Ok(()),
    };
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
    if let Err(error) = source_outcome_result {
        tracing::error!(error = %error, "authority source outcome runtime shutdown failed");
        shutdown_errors.push(format!("authority source outcome runtime: {error}"));
    }
    if shutdown_errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(shutdown_errors.join("; ")))
    }
}

fn build_router(state: AppState) -> Router {
    let api_routes = Router::new()
        .merge(alerts::alert_routes())
        .merge(notifications::notification_routes())
        .merge(dashboard::dashboard_routes())
        .route("/metrics", get(metrics_summary))
        .route("/system-info", get(system_info))
        .route("/dashboard", get(dashboard_summary))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::monitor_permission_middleware,
        ));

    let direct_health_routes = Router::new()
        .nest("/api", endpoints::frontend_health_routes())
        .nest("/actuator", endpoints::actuator_health_routes());

    let protected_monitor_routes = Router::new()
        .nest("/actuator", endpoints::monitor_routes())
        .nest("/api/v1/monitor", api_routes)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            gateway_signature_middleware,
        ));

    direct_health_routes
        .merge(protected_monitor_routes)
        .layer(axum::middleware::from_fn(global_exception_handler))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

#[cfg(test)]
mod router_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn test_state() -> AppState {
        let db = sqlx::MySqlPool::connect_lazy("mysql://localhost:1/astral_test").unwrap();
        AppState {
            config: Arc::new(AppConfig {
                gateway: astral_common::config::GatewayCfg {
                    hmac_secret: "test-gateway-secret-0123456789abcdef".into(),
                    timestamp_tolerance_secs: 30,
                    ..Default::default()
                },
                ..Default::default()
            }),
            db: db.clone(),
            engine: Arc::new(PolicyEngine::new()),
            authorization_fence_provider: None,
            monitor_service: Arc::new(MonitorService::new(Arc::new(SqlxMonitorRepository::new(
                db,
            )))),
        }
    }

    async fn response_for(app: Router, method: &str, path: &str) -> StatusCode {
        app.oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
    }

    #[tokio::test]
    async fn direct_health_routes_bypass_gateway_signature() {
        for path in ["/api/health", "/api/health/metrics", "/actuator/health"] {
            assert_eq!(
                response_for(build_router(test_state()), "OPTIONS", path).await,
                StatusCode::METHOD_NOT_ALLOWED,
                "registered direct health route must bypass gateway signature: {path}"
            );
        }
    }

    #[tokio::test]
    async fn protected_monitor_routes_require_gateway_signature() {
        for path in [
            "/api/v1/monitor/system-info",
            "/actuator/health/detailed",
            "/actuator/metrics",
            "/actuator/status",
        ] {
            assert_eq!(
                response_for(build_router(test_state()), "GET", path).await,
                StatusCode::FORBIDDEN,
                "protected monitor route must require gateway signature: {path}"
            );
        }
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
