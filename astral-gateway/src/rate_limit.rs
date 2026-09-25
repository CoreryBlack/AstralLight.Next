//! 基于 IP 的速率限制中间件（Gateway 专属运行时）
//!
//! 配置从 `AppConfig.rate_limit` 注入（对齐 Java `RateLimitConfig`）；
//! 客户端 IP 只信任来自配置代理的 `X-Forwarded-For` / `X-Real-IP`，否则回退
//! TCP 对端地址（`ConnectInfo`）。bucket 带最后访问时间，周期清理防内存无限增长。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Instant;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use astral_common::config::{AppConfig, RateLimitCfg};

/// 全局速率限制器实例（跨请求共享；配置来自首个请求，启动期确定）
static RATE_LIMITER: std::sync::OnceLock<RateLimiter> = std::sync::OnceLock::new();

/// bucket 空闲清理阈值：超过该时长未访问的 key 移除（防长运行内存增长）
const BUCKET_TTL: std::time::Duration = std::time::Duration::from_secs(60);

/// 基于 IP 的滑动窗口计数器
struct WindowCounter {
    count: u64,
    window_start: Instant,
    last_seen: Instant,
}

/// 速率限制器
pub struct RateLimiter {
    config: RateLimitCfg,
    buckets: Mutex<HashMap<String, WindowCounter>>,
}

impl RateLimiter {
    pub fn new(config: RateLimitCfg) -> Self {
        Self {
            config,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    fn check(&self, key: &str) -> bool {
        if !self.config.enabled {
            return true;
        }
        let mut buckets = self.buckets.lock().unwrap();
        let now = Instant::now();
        let window = std::time::Duration::from_secs(1);

        // 周期性清理空闲 bucket（仅在达到一定规模时执行，避免每次请求全扫）
        if buckets.len() > 1024 {
            buckets.retain(|_, counter| now.duration_since(counter.last_seen) < BUCKET_TTL);
        }

        let counter = buckets.entry(key.to_string()).or_insert(WindowCounter {
            count: 0,
            window_start: now,
            last_seen: now,
        });
        counter.last_seen = now;
        if now.duration_since(counter.window_start) > window {
            counter.count = 0;
            counter.window_start = now;
        }
        if counter.count >= self.config.requests_per_second as u64 {
            false
        } else {
            counter.count += 1;
            true
        }
    }
}

/// Resolve a trusted proxy setting as an exact address or simple CIDR prefix.
fn trusted_proxy(remote: Option<&SocketAddr>, configured: &[String]) -> bool {
    let Some(remote) = remote else { return false };
    configured.iter().any(|value| {
        let value = value.trim();
        value == remote.ip().to_string()
            || value
                .strip_suffix("/32")
                .or_else(|| value.strip_suffix("/128"))
                .is_some_and(|network| network == remote.ip().to_string())
            || value
                .strip_suffix(".")
                .is_some_and(|prefix| remote.ip().to_string().starts_with(prefix))
    })
}

/// 解析客户端 IP。Forwarded headers are ignored unless the TCP peer is trusted.
fn client_ip(
    headers: &axum::http::HeaderMap,
    connect_info: Option<&SocketAddr>,
    trusted_proxy_ips: &[String],
) -> String {
    if trusted_proxy(connect_info, trusted_proxy_ips) {
        if let Some(first) = headers
            .get("X-Forwarded-For")
            .and_then(|value| value.to_str().ok())
            .and_then(|xff| xff.split(',').next())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return first.to_string();
        }
        if let Some(real) = headers
            .get("X-Real-IP")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return real.to_string();
        }
    }
    connect_info
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn rate_limit_error(req: &Request) -> Response {
    let trace_id = req
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("rate-limit-error");
    let body = serde_json::json!({
        "code": 429,
        "message": "Rate limit exceeded",
        "traceId": trace_id,
        "requestPath": req.uri().path(),
        "requestMethod": req.method().as_str(),
        "errorType": "TOO_MANY_REQUESTS",
        "decision": "RATE_LIMIT_EXCEEDED",
        "reasonCode": "RATE_LIMIT_EXCEEDED",
    });
    let mut response = (StatusCode::TOO_MANY_REQUESTS, axum::Json(body)).into_response();
    response
        .headers_mut()
        .insert("Retry-After", axum::http::HeaderValue::from_static("1"));
    if let Ok(value) = trace_id.parse() {
        response.headers_mut().insert("X-Trace-Id", value);
    }
    response
}

///
/// limiter 必须是跨请求共享的单例：每请求重建会导致 bucket 恒空、限流恒不生效。
/// 配置取自首个请求的 `AppConfig.rate_limit`（启动期确定，不随请求变化）。
pub async fn rate_limit_middleware(
    State(config): State<AppConfig>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let limiter = RATE_LIMITER.get_or_init(|| RateLimiter::new(config.rate_limit.clone()));
    let ip = client_ip(
        req.headers(),
        Some(&addr),
        &config.gateway.trusted_proxy_ips,
    );

    if !limiter.check(&ip) {
        tracing::warn!(ip = %ip, "rate limit exceeded");
        metrics::counter!("astral_gateway_rate_limit_rejected_total").increment(1);
        return rate_limit_error(&req);
    }

    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    fn test_config() -> RateLimitCfg {
        RateLimitCfg {
            enabled: true,
            requests_per_second: 2,
            burst_size: 4,
        }
    }

    #[test]
    fn test_rate_limiter_under_limit() {
        let limiter = RateLimiter::new(test_config());
        assert!(limiter.check("a"));
        assert!(limiter.check("a"));
        assert!(!limiter.check("a")); // 第 3 个超限
    }

    #[test]
    fn test_rate_limiter_disabled() {
        let config = RateLimitCfg {
            enabled: false,
            requests_per_second: 0,
            burst_size: 0,
        };
        let limiter = RateLimiter::new(config);
        for _ in 0..1000 {
            assert!(limiter.check("test"));
        }
    }

    #[test]
    fn test_xff_first_hop_is_used() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("X-Forwarded-For", "1.2.3.4, 5.6.7.8".parse().unwrap());
        let addr: SocketAddr = "9.9.9.9:1234".parse().unwrap();
        assert_eq!(
            client_ip(&headers, Some(&addr), &["9.9.9.9".into()]),
            "1.2.3.4"
        );
    }

    #[test]
    fn untrusted_forwarded_headers_fall_back_to_peer() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("X-Forwarded-For", "1.2.3.4".parse().unwrap());
        headers.insert("X-Real-IP", "8.8.8.8".parse().unwrap());
        let addr: SocketAddr = "9.9.9.9:1234".parse().unwrap();
        assert_eq!(client_ip(&headers, Some(&addr), &[]), "9.9.9.9");
    }

    #[test]
    fn trusted_proxy_accepts_x_real_ip_fallback() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("X-Real-IP", "8.8.8.8".parse().unwrap());
        let addr: SocketAddr = "9.9.9.9:1234".parse().unwrap();
        assert_eq!(
            client_ip(&headers, Some(&addr), &["9.9.9.9".into()]),
            "8.8.8.8"
        );
    }

    #[test]
    fn test_xff_absent_falls_back_to_peer() {
        let headers = axum::http::HeaderMap::new();
        let addr: SocketAddr = "9.9.9.9:1234".parse().unwrap();
        assert_eq!(client_ip(&headers, Some(&addr), &[]), "9.9.9.9");
    }

    #[test]
    fn rate_limit_response_has_retry_after() {
        let request = Request::builder()
            .uri("/api/v1/auth/login")
            .body(Body::empty())
            .unwrap();
        let response = rate_limit_error(&request);
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()["Retry-After"], "1");
    }
}
