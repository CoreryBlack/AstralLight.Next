//! 基于 IP 的速率限制中间件（Gateway 运行时装配）。
//!
//! 计数核心、受信代理匹配与客户端 IP 解析由
//! `astral_common::middleware::ip_rate_limit` 统一提供（与 Identity verification
//! 路由限流同源；taskId `global-authority-20261107-limiter` 抽取），本模块只负责
//! Gateway 侧的配置注入、单例装配、拒绝指标与 429 响应出口。
//!
//! 配置从 `AppConfig.rate_limit` 注入（对齐 Java `RateLimitConfig`）；客户端 IP
//! 只信任来自 `gateway.trusted_proxy_ips` 配置代理的 `X-Forwarded-For` /
//! `X-Real-IP`，否则回退 TCP 对端地址（`ConnectInfo`）。桶带最后访问时间，
//! TTL+GC 与硬容量双边界由共享 limiter 保证（容量耗尽时新 key fail-closed）。
//! 本中间件是**进程内本地限流**：不提供跨副本全局配额，各副本预算独立。

use std::net::SocketAddr;
use std::sync::OnceLock;

use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::Next;
use axum::response::Response;

use astral_common::config::AppConfig;
use astral_common::middleware::ip_rate_limit::{
    rate_limit_response, resolve_client_ip, IpRateLimiter, TrustedProxySet,
};

/// Gateway 侧共享实例（跨请求；配置来自首个请求的启动期冻结 AppConfig，
/// 每请求重建会导致 bucket 恒空、限流恒不生效）。
struct GatewayRateLimit {
    limiter: IpRateLimiter,
    trusted: TrustedProxySet,
}

static GATEWAY_RATE_LIMIT: OnceLock<GatewayRateLimit> = OnceLock::new();

// memory—v1: Internal result of Gateway's trusted-proxy resolution, never an HTTP header.
#[derive(Clone, Copy)]
pub(crate) struct ResolvedClientIp(pub std::net::IpAddr);

pub async fn rate_limit_middleware(
    State(config): State<AppConfig>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut req: Request,
    next: Next,
) -> Response {
    let shared = GATEWAY_RATE_LIMIT.get_or_init(|| {
        let trusted = TrustedProxySet::compile(&config.gateway.trusted_proxy_ips);
        for entry in trusted.invalid_entries() {
            tracing::warn!(
                entry = %entry,
                "invalid gateway.trusted_proxy_ips entry; ignored (fail closed to peer address)"
            );
        }
        GatewayRateLimit {
            limiter: IpRateLimiter::new(config.rate_limit.clone()),
            trusted,
        }
    });
    let client = resolve_client_ip(req.headers(), Some(addr.ip()), &shared.trusted);

    if !shared.limiter.check(client) {
        tracing::warn!(client = ?client, "rate limit exceeded");
        metrics::counter!("astral_gateway_rate_limit_rejected_total").increment(1);
        return rate_limit_response(&req, "rate-limit-error");
    }

    if let Some(client) = client {
        req.extensions_mut().insert(ResolvedClientIp(client));
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    use astral_common::config::RateLimitCfg;

    fn key(value: &str) -> Option<IpAddr> {
        Some(value.parse().unwrap())
    }

    fn compile(entries: &[&str]) -> TrustedProxySet {
        let owned: Vec<String> = entries.iter().map(|entry| (*entry).to_string()).collect();
        TrustedProxySet::compile(&owned)
    }

    #[test]
    fn gateway_limiter_caps_per_key_and_isolates_buckets() {
        let limiter = IpRateLimiter::new(RateLimitCfg {
            enabled: true,
            requests_per_second: 2,
            burst_size: 0,
        });
        assert!(limiter.check(key("10.0.0.1")));
        assert!(limiter.check(key("10.0.0.1")));
        assert!(!limiter.check(key("10.0.0.1")), "第 3 个超限");
        assert!(
            limiter.check(key("10.0.0.2")),
            "budget must be isolated per client"
        );
    }

    #[test]
    fn gateway_limiter_burst_adds_in_window_headroom() {
        // rps=2 + burst=4：单窗口内允许 6 次，第 7 次拒绝。
        let limiter = IpRateLimiter::new(RateLimitCfg {
            enabled: true,
            requests_per_second: 2,
            burst_size: 4,
        });
        for _ in 0..6 {
            assert!(limiter.check(key("10.0.0.1")));
        }
        assert!(!limiter.check(key("10.0.0.1")));
        assert!(limiter.check(key("10.0.0.2")));
    }

    #[test]
    fn gateway_limiter_disabled_admits_all() {
        let limiter = IpRateLimiter::new(RateLimitCfg {
            enabled: false,
            requests_per_second: 0,
            burst_size: 0,
        });
        for _ in 0..1000 {
            assert!(limiter.check(key("10.0.0.1")));
        }
    }

    #[test]
    fn gateway_trusted_proxy_resolution_ignores_untrusted_headers() {
        let trusted = compile(&["9.9.9.9"]);
        let peer: IpAddr = "7.7.7.7".parse().unwrap();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("X-Forwarded-For", "1.2.3.4".parse().unwrap());
        headers.insert("X-Real-IP", "8.8.8.8".parse().unwrap());
        // 非受信对端：伪造转发头不能换桶，回退对端地址。
        assert_eq!(
            resolve_client_ip(&headers, Some(peer), &trusted),
            Some(peer)
        );
    }

    #[test]
    fn gateway_trusted_proxy_resolves_rightmost_untrusted_hop() {
        let trusted = compile(&["9.9.9.9"]);
        let peer: IpAddr = "9.9.9.9".parse().unwrap();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("X-Forwarded-For", "1.2.3.4, 5.6.7.8".parse().unwrap());
        assert_eq!(
            resolve_client_ip(&headers, Some(peer), &trusted),
            key("5.6.7.8"),
            "the proxy-appended rightmost untrusted hop is the client"
        );
    }

    #[test]
    fn gateway_cidr_and_legacy_prefix_compat() {
        // CIDR 按位匹配。
        let cidr = compile(&["10.1.2.0/24"]);
        assert!(cidr.matches_peer(key("10.1.2.77")));
        assert!(!cidr.matches_peer(key("10.1.3.77")));
        // 遗留点分前缀兼容（`10.1.` 继续命中 10.1.2.3）。
        let legacy = compile(&["10.1."]);
        assert!(legacy.matches_peer(key("10.1.2.3")));
        assert!(!legacy.matches_peer(key("10.2.0.1")));
        // 非法条目 fail-closed（回退对端，不静默放宽）。
        let invalid = compile(&["not-an-ip"]);
        assert_eq!(invalid.invalid_entries().len(), 1);
        assert!(!invalid.matches_peer(key("10.0.0.1")));
    }

    #[test]
    fn gateway_rate_limit_response_keeps_contract() {
        let request = Request::builder()
            .uri("/api/v1/auth/login")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = rate_limit_response(&request, "rate-limit-error");
        assert_eq!(response.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()["Retry-After"], "1");
        assert_eq!(response.headers()["X-Trace-Id"], "rate-limit-error");
    }
}
