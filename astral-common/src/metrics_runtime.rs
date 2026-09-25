//! Prometheus 指标运行时 — 全局 recorder 安装 + 独立 loopback 抓取端口。
//!
//! 设计约束：
//! - 观测失败不得影响主服务：`/metrics` 监听 bind/serve 失败只记录 error；
//!   recorder 安装失败由调用方降级为无指标（metrics 宏自动退化为 no-op）。
//! - `/metrics` 不挂在业务 Router 上，避免触碰认证/签名/权限路径；
//!   默认只绑定 loopback，跨机抓取需显式设置 `METRICS_LISTEN_ADDR`。

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

/// 安装全局 Prometheus recorder（每进程只能安装一次，重复调用返回 Err）。
pub fn install_prometheus_recorder() -> Result<PrometheusHandle, String> {
    PrometheusBuilder::new()
        .install_recorder()
        .map_err(|error| error.to_string())
}

/// 在独立地址暴露 `GET /metrics`（Prometheus 文本格式）。
///
/// 返回的 JoinHandle 仅用于测试等待；生产调用方 drop 即可，任务持续运行。
pub fn spawn_metrics_server(addr: String, handle: PrometheusHandle) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        match tokio::net::TcpListener::bind(&addr).await {
            Ok(listener) => serve_metrics_on(listener, handle).await,
            Err(error) => {
                tracing::error!(addr = %addr, error = %error, "metrics server bind failed; metrics exposure disabled")
            }
        }
    })
}

/// 在已绑定的 listener 上运行 `/metrics` 服务（bind 与 serve 分离，端口 0 可测）。
pub async fn serve_metrics_on(listener: tokio::net::TcpListener, handle: PrometheusHandle) {
    let app = axum::Router::new().route(
        "/metrics",
        axum::routing::get(move || {
            let handle = handle.clone();
            async move {
                (
                    [(
                        axum::http::header::CONTENT_TYPE,
                        "text/plain; version=0.0.4; charset=utf-8",
                    )],
                    handle.render(),
                )
            }
        }),
    );
    let bound = listener
        .local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_default();
    tracing::info!(addr = %bound, "prometheus metrics endpoint listening");
    if let Err(error) = axum::serve(listener, app).await {
        tracing::error!(error = %error, "metrics server terminated");
    }
}

/// 读取 `METRICS_LISTEN_ADDR`（未设置用默认值；设置为空白显式禁用）。
pub fn metrics_listen_addr(default_addr: &str) -> Option<String> {
    resolve_metrics_addr(std::env::var("METRICS_LISTEN_ADDR").ok(), default_addr)
}

/// 纯函数形式的地址解析，便于测试。
fn resolve_metrics_addr(env_value: Option<String>, default_addr: &str) -> Option<String> {
    match env_value {
        Some(value) if value.trim().is_empty() => None,
        Some(value) => Some(value),
        None => Some(default_addr.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Once, OnceLock};

    static INSTALL: Once = Once::new();
    static HANDLE: OnceLock<Option<PrometheusHandle>> = OnceLock::new();

    /// 每个测试二进制只能安装一次全局 recorder；用 Once 固定共享句柄。
    fn shared_handle() -> &'static Option<PrometheusHandle> {
        INSTALL.call_once(|| {
            let _ = HANDLE.set(install_prometheus_recorder().ok());
        });
        HANDLE.get().expect("handle slot initialized by Once")
    }

    #[test]
    fn recorder_renders_recorded_metrics() {
        let handle = shared_handle()
            .as_ref()
            .expect("first install in test process must succeed");
        metrics::counter!("astral_common_metrics_runtime_test_total").increment(3);
        let body = handle.render();
        assert!(
            body.contains("astral_common_metrics_runtime_test_total"),
            "metric name must appear in exposition: {body}"
        );
        assert!(
            body.contains("astral_common_metrics_runtime_test_total 3"),
            "counter value must be rendered: {body}"
        );
    }

    #[test]
    fn second_install_fails() {
        shared_handle();
        assert!(
            install_prometheus_recorder().is_err(),
            "global recorder must reject a second install"
        );
    }

    #[test]
    fn listen_addr_resolution_defaults_overrides_and_disables() {
        assert_eq!(
            resolve_metrics_addr(None, "127.0.0.1:9100"),
            Some("127.0.0.1:9100".to_string())
        );
        assert_eq!(
            resolve_metrics_addr(Some("0.0.0.0:9200".into()), "127.0.0.1:9100"),
            Some("0.0.0.0:9200".to_string())
        );
        assert_eq!(
            resolve_metrics_addr(Some("  ".into()), "127.0.0.1:9100"),
            None
        );
    }

    /// 端到端：`GET /metrics` 返回 Prometheus 文本格式与正确 content-type。
    #[tokio::test]
    async fn metrics_endpoint_serves_prometheus_exposition() {
        let handle = shared_handle()
            .as_ref()
            .expect("first install in test process must succeed")
            .clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_metrics_on(listener, handle));

        let response = reqwest::get(format!("http://{addr}/metrics"))
            .await
            .expect("metrics endpoint reachable");
        assert_eq!(response.status(), 200);
        assert!(
            response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .starts_with("text/plain"),
            "prometheus exposition content-type required"
        );
        let body = response.text().await.unwrap();
        assert!(
            body.contains("astral_common_metrics_runtime_test_total"),
            "exposed metrics must render: {body}"
        );
        server.abort();
    }
}
