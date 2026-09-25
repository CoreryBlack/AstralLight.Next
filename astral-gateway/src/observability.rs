//! Gateway 请求指标中间件 — 请求计数 + 时延直方图（Prometheus）。
//!
//! route 标签取 axum `MatchedPath`（低基数路由模式，如 `/api/v1/auth/users/{id}`）；
//! 未匹配路径（404）记为 `UNMATCHED`。中间件挂在最外层，看到的是最终状态码
//! （含 JWT 401/403、限流 429、CORS 预检），不侵入任何认证/转发逻辑。

use std::time::Instant;

use axum::extract::{MatchedPath, Request};
use axum::middleware::Next;
use axum::response::Response;

pub async fn metrics_middleware(req: Request, next: Next) -> Response {
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_owned())
        .unwrap_or_else(|| "UNMATCHED".to_owned());
    let method = req.method().to_string();

    let start = Instant::now();
    let response = next.run(req).await;
    let elapsed = start.elapsed().as_secs_f64();
    let code = response.status().as_u16().to_string();

    metrics::counter!(
        "astral_gateway_requests_total",
        "method" => method,
        "route" => route.clone(),
        "code" => code
    )
    .increment(1);
    metrics::histogram!("astral_gateway_request_duration_seconds", "route" => route)
        .record(elapsed);

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::routing::get;
    use axum::Router;
    use metrics_exporter_prometheus::PrometheusHandle;
    use std::sync::{Once, OnceLock};
    use tower::ServiceExt;

    static INSTALL: Once = Once::new();
    static HANDLE: OnceLock<Option<PrometheusHandle>> = OnceLock::new();

    /// 每个测试二进制只能安装一次全局 recorder；用 Once 固定共享句柄。
    fn shared_handle() -> PrometheusHandle {
        INSTALL.call_once(|| {
            let _ = HANDLE.set(
                metrics_exporter_prometheus::PrometheusBuilder::new()
                    .install_recorder()
                    .ok(),
            );
        });
        HANDLE
            .get()
            .expect("handle slot initialized")
            .as_ref()
            .expect("first install in test process must succeed")
            .clone()
    }

    fn app() -> Router {
        Router::new()
            .route("/api/v1/auth/me", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(metrics_middleware))
    }

    #[tokio::test]
    async fn records_request_counter_and_duration_for_matched_route() {
        let handle = shared_handle();
        let response = app()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/auth/me")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);

        let body = handle.render();
        assert!(
            body.contains("astral_gateway_requests_total"),
            "counter must be exposed: {body}"
        );
        assert!(
            body.contains("route=\"/api/v1/auth/me\""),
            "matched route label required: {body}"
        );
        assert!(
            body.contains("code=\"200\""),
            "status label required: {body}"
        );
        assert!(
            body.contains("astral_gateway_request_duration_seconds"),
            "latency histogram must be exposed: {body}"
        );
    }

    #[tokio::test]
    async fn unmatched_routes_are_labelled_unmatched() {
        let handle = shared_handle();
        let response = app()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/not/a/route")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 404);

        let body = handle.render();
        assert!(
            body.contains("route=\"UNMATCHED\""),
            "unmatched path must use the UNMATCHED label: {body}"
        );
        assert!(
            body.contains("code=\"404\""),
            "status label required: {body}"
        );
    }
}
