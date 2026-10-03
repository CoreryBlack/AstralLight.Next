//! AstralLight API Gateway
//!
//! 功能（对应 Java `GatewayApplication`）：
//! 1. 内部身份头清洗（防止客户端伪造）
//! 2. JWT 验证 + 公共路径放行 + 租户状态拦截
//! 3. 路由转发到后端服务 + HMAC 签名注入
//! 4. 全局异常处理 + 请求追踪
//! 5. CORS + 限流
//!
//! 启动：
//! ```bash
//! cargo run -p astral-gateway
//! # 或指定配置
//! LEARN_SERVICE_URI=http://localhost:9002 cargo run -p astral-gateway
//! ```

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{any, post};
use axum::{middleware as axum_middleware, Router};
use tower_http::cors::{AllowOrigin, Any, CorsLayer};

use anyhow::Context;
use astral_common::config::{AppConfig, JwtValidationRole};
use astral_common::error::global_exception_handler;
use std::future::Future;

#[path = "middleware.rs"]
pub mod middleware;
#[path = "observability.rs"]
pub mod observability;
#[path = "proxy.rs"]
pub mod proxy;
#[path = "rate_limit.rs"]
pub mod rate_limit;

use crate::middleware::{
    internal_session_auth_middleware_with_config, jwt_auth_middleware,
    sanitize_internal_auth_headers,
};
use crate::rate_limit::rate_limit_middleware;

/// Identity 用户管理的 canonical 外部路由。
///
/// Identity 已注册同一组 `/api/v1/auth/users` handler；Gateway 必须逐路由暴露，
/// 不能用未约束的 wildcard 把 Identity 未注册的路径一并代理出去。
fn identity_user_routes() -> Router<AppConfig> {
    Router::new()
        .route("/api/v1/auth/users", any(proxy::forward_to_identity_static))
        .route(
            "/api/v1/auth/users/{id}",
            any(proxy::forward_to_identity_static),
        )
        .route(
            "/api/v1/auth/users/{id}/status",
            any(proxy::forward_to_identity_static),
        )
        .route(
            "/api/v1/auth/users/{id}/cards",
            any(proxy::forward_to_identity_static),
        )
        .route(
            "/api/v1/auth/users/{id}/password",
            any(proxy::forward_to_identity_static),
        )
}

/// Identity 当前用户查询的 canonical 外部路由。
///
/// `/me` handler 已在 Identity 注册；Gateway 只暴露同样的固定资源，避免
/// wildcard 将未注册的 Identity 路径误认为可用能力。
fn identity_me_routes() -> Router<AppConfig> {
    Router::new()
        .route("/api/v1/auth/me", any(proxy::forward_to_identity_static))
        .route(
            "/api/v1/auth/me/cards",
            any(proxy::forward_to_identity_static),
        )
        .route(
            "/api/v1/auth/me/identities",
            any(proxy::forward_to_identity_static),
        )
        .route(
            "/api/v1/auth/me/permissions",
            any(proxy::forward_to_identity_static),
        )
        .route(
            "/api/v1/auth/me/menus",
            any(proxy::forward_to_identity_static),
        )
}

/// Identity session handlers exposed by the canonical Rust contract.
///
/// Do not use a wildcard here: `session-operations/*` is not registered by
/// Identity and must remain an explicit unsupported/404 capability.
fn identity_session_routes() -> Router<AppConfig> {
    Router::new()
        .route(
            "/api/v1/auth/sessions",
            post(proxy::forward_to_identity_sessions_root),
        )
        .route(
            "/api/v1/auth/sessions/refresh",
            post(proxy::forward_to_identity_static),
        )
        .route(
            "/api/v1/auth/sessions/revoke",
            post(proxy::forward_to_identity_static),
        )
        .route(
            "/api/v1/auth/sessions/logout",
            post(proxy::forward_to_identity_static),
        )
        .route(
            "/api/v1/auth/sessions/switch-card",
            post(proxy::forward_to_identity_static),
        )
}

/// Reject invalid user IDs before the WebSocket extractor can return a generic
/// handshake error. Extra path segments never reach this route because the
/// route pattern is a single Axum path parameter.
async fn chat_ws_route_boundary_middleware(req: Request, next: Next) -> Response {
    let user_id = req.uri().path().rsplit('/').next().unwrap_or_default();
    if !user_id.parse::<i64>().is_ok_and(|value| value > 0) {
        return StatusCode::NOT_FOUND.into_response();
    }
    next.run(req).await
}

fn chat_ws_routes() -> Router<AppConfig> {
    Router::new()
        .route("/v1/chat/ws/{user_id}", any(proxy::forward_chat_ws))
        .route_layer(axum_middleware::from_fn(chat_ws_route_boundary_middleware))
}

/// Chat HTTP 只暴露 Chat 服务实际注册的 route set。
///
/// 保持 WS 路由与普通 Chat API 分离，避免通用 wildcard 把未知 WS 子路径
/// 转发到 Chat 服务后再由中间件拒绝。
fn chat_http_routes() -> Router<AppConfig> {
    Router::new()
        .route("/v1/chat/messages", any(proxy::forward_to_chat))
        .route("/v1/chat/messages/{id}", any(proxy::forward_to_chat))
        .route(
            "/v1/chat/messages/session/{conversation_id}",
            any(proxy::forward_to_chat),
        )
        .route("/v1/chat/sessions", any(proxy::forward_to_chat))
        .route("/v1/chat/sessions/{id}", any(proxy::forward_to_chat))
        .route(
            "/v1/chat/sessions/{id}/members",
            any(proxy::forward_to_chat),
        )
        .route("/v1/chat/groups", any(proxy::forward_to_chat))
        .route("/v1/chat/groups/{id}", any(proxy::forward_to_chat))
        .route("/v1/chat/groups/{id}/members", any(proxy::forward_to_chat))
        .route(
            "/v1/chat/groups/{id}/members/{user_id}",
            any(proxy::forward_to_chat),
        )
        .route(
            "/v1/chat/groups/{id}/transfer-owner",
            any(proxy::forward_to_chat),
        )
        .route("/v1/chat/receipts", any(proxy::forward_to_chat))
        .route(
            "/v1/chat/receipts/{conversation_id}/{user_id}",
            any(proxy::forward_to_chat),
        )
}

fn chat_routes() -> Router<AppConfig> {
    chat_ws_routes().merge(chat_http_routes())
}

pub async fn run() -> anyhow::Result<()> {
    let addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:9001".to_string());
    run_with_listen_addr(&addr).await
}

pub async fn run_with_listen_addr(addr: &str) -> anyhow::Result<()> {
    let signal_failed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let signal_failed_in_shutdown = signal_failed.clone();
    run_with_listen_addr_and_shutdown(addr, async move {
        if let Err(error) = tokio::signal::ctrl_c().await {
            signal_failed_in_shutdown.store(true, std::sync::atomic::Ordering::Release);
            tracing::error!(error = %error, "gateway ctrl-c handler failed; initiating graceful shutdown");
        }
    })
    .await?;
    anyhow::ensure!(
        !signal_failed.load(std::sync::atomic::Ordering::Acquire),
        "gateway Ctrl-C handler failed during shutdown"
    );
    Ok(())
}

/// Run Gateway with a caller-owned shutdown signal and wait for Axum's HTTP
/// connections to drain before returning. Callers own the shutdown deadline.
pub async fn run_with_listen_addr_and_shutdown<F>(addr: &str, shutdown: F) -> anyhow::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    run_with_listen_addr_and_shutdown_inner(addr, shutdown).await
}

async fn run_with_listen_addr_and_shutdown_inner<F>(addr: &str, shutdown: F) -> anyhow::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    // Prometheus 指标暴露：默认 loopback 抓取端口；
    // METRICS_LISTEN_ADDR 覆盖，置空显式禁用。观测失败不影响主服务。
    if let Some(metrics_addr) =
        astral_common::metrics_runtime::metrics_listen_addr("127.0.0.1:9100")
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

    let config = AppConfig::from_files_for("application", JwtValidationRole::Gateway)?;
    // Redis 编译层退役收口：宿主能力门（本 crate cfg! 为准，marker 会被
    // workspace feature 统一放大）+ 已校验旗标一次性冻结（组合成员一致，
    // 异值冲突拒绝启动）。旗标开启而 adapter 未编译 → DB 连接前显式拒绝。
    config
        .validate_redis_adapter_support(cfg!(feature = "redis-compat"))
        .map_err(anyhow::Error::msg)?;
    astral_common::config::install_redis_projection_compat(config.redis_projection_compat_enabled)
        .map_err(anyhow::Error::msg)?;
    let session_db = astral_db::connect_and_validate_schema(&config.database_url)
        .await
        .map_err(|error| anyhow::Error::msg(error.to_string()))?;
    // 镜像 positive 资格 = 组合进程强条件（观测事实，非 invented bool）：
    // LocalBus owners ready + 同进程已安装 hub 通道健康 + aux marker（装配
    // 资格，非运行期租约存活证明；实时门是 canonical verifier 的 hub 读取
    // 令牌/栅栏）。hub 健康非启动自然保证：组合 main 的 readiness 等待
    // （持租约、要求 hub healthy + projection owner alive）保证 spawn
    // gateway 时条件确定成立；为假只降级 warn + DenyOnly（逐请求
    // strict DB），绝不 fail startup。
    let (mirror, policy) = if config.session_grant_mirror_enabled
        && middleware::composite_positive_ready()
    {
        tracing::info!(
            "session grant mirror enabled (composite single-writer, verified-positive policy)"
        );
        (
            Some(astral_common::session_projection_store::SessionProjectionMirror::default()),
            astral_common::session_projection_store::MirrorPolicy::VerifiedPositive,
        )
    } else {
        if config.session_grant_mirror_enabled {
            tracing::warn!(
                "session grant mirror enabled but composite positive preconditions are absent; refusing mirror install (strict DB per request)"
            );
        }
        (
            None,
            astral_common::session_projection_store::MirrorPolicy::DenyOnly,
        )
    };
    middleware::install_gateway_session_auth(
        session_db,
        mirror,
        policy,
        config.session_grant_mirror_positive_disabled,
    )
    .map_err(anyhow::Error::msg)?;
    // Redis 编译层退役：feature-off 构建无 compat adapter 可装配；compat 旗标
    // 开启 + feature 缺失的配置已被 astral-common 集中校验与上方宿主能力门
    // 双重拒绝（fail-closed），此处 cfg 分支只做装配或说明，不再承担拒绝职责。
    #[cfg(feature = "redis-compat")]
    if config.redis_projection_compat_enabled {
        middleware::init_gateway_redis(&config.redis_url)
            .await
            .map_err(anyhow::Error::msg)?;
    } else {
        tracing::info!(
            transport = "mysql",
            "gateway session auth uses strict MySQL durable facts; redis projection adapter disabled"
        );
    }
    #[cfg(not(feature = "redis-compat"))]
    tracing::info!(
        transport = "mysql",
        "redis projection adapter not compiled (redis-compat feature disabled); strict MySQL durable facts in use"
    );

    tracing::info!("gateway starting");

    // 配置 CORS。AppConfig 已在启动前拒绝 wildcard、缺失和不安全 origin，
    // 这里仅构造显式 allow-list，避免运行时镜像任意请求 Origin。
    let origins: Vec<_> = config
        .cors
        .allowed_origins
        .iter()
        .filter_map(|origin| origin.parse().ok())
        .collect();
    // 显式 origin 分支必须补 allow_methods/allow_headers：
    // tower-http 默认 Const(None)，预检响应不带
    // Access-Control-Allow-Methods/Headers → 浏览器预检必然失败。
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_credentials(config.cors.allow_credentials);

    let internal_config = config.clone();
    let app =
        Router::new()
            .merge(identity_user_routes())
            .merge(identity_me_routes())
            .merge(identity_session_routes())
            .merge(
                Router::new()
                    .route(
                        "/api/v1/auth/internal/sessions",
                        axum::routing::post(proxy::forward_internal_session),
                    )
                    .with_state(config.clone())
                    .layer(axum_middleware::from_fn(move |req, next| {
                        let config = internal_config.clone();
                        async move {
                            internal_session_auth_middleware_with_config(config, req, next).await
                        }
                    })),
            )
            .route(
                "/api/v1/auth/register",
                any(proxy::forward_to_identity_static),
            )
            .route(
                "/api/v1/auth/profile",
                any(proxy::forward_to_identity_static),
            )
            .route(
                "/api/v1/auth/change-password",
                any(proxy::forward_to_identity_static),
            )
            .route(
                "/api/v1/auth/providers",
                any(proxy::forward_to_identity_static),
            )
            .route(
                "/api/v1/auth/password/forgot",
                any(proxy::forward_to_identity_static),
            )
            .route(
                "/api/v1/auth/password/reset/{token}",
                any(proxy::forward_to_identity_password_reset),
            )
            .route(
                "/api/v1/auth/verification/send",
                any(proxy::forward_to_identity_static),
            )
            .route(
                "/api/v1/auth/verification/verify",
                any(proxy::forward_to_identity_static),
            )
            .route(
                "/api/v1/auth/mfa/status",
                any(proxy::forward_to_identity_static),
            )
            .route(
                "/api/v1/auth/mfa/verify",
                any(proxy::forward_to_identity_static),
            )
            .route(
                "/v1/admin/learn/{*path}",
                any(proxy::forward_to_learn_admin),
            )
            .route("/v1/app/learn/{*path}", any(proxy::forward_to_learn_app))
            .route(
                "/v1/app/users/{*path}",
                any(proxy::forward_to_learn_app_users),
            )
            .route("/v1/app/users", any(proxy::forward_to_learn_app_users_root))
            .merge(chat_routes())
            .route("/main/api/v1/{*path}", any(proxy::forward_to_trustgraph))
            .route("/api/v1/monitor/{*path}", any(proxy::forward_to_monitor))
            // JWT 中间件（公共路径放行 + strict MySQL 会话判定（可选已证明镜像/
            // 显式 Redis 兼容 adapter）+ 租户状态严格校验 + 身份头注入）
            .route_layer(axum_middleware::from_fn_with_state(
                config.clone(),
                jwt_auth_middleware,
            ))
            // 内部身份头清洗（JWT 之前执行，剥离伪造头）
            .layer(axum_middleware::from_fn(sanitize_internal_auth_headers))
            .layer(axum_middleware::from_fn_with_state(
                config.clone(),
                rate_limit_middleware,
            ))
            .layer(axum_middleware::from_fn(global_exception_handler))
            .layer(cors)
            .layer(
                tower_http::trace::TraceLayer::new_for_http().make_span_with(
                    |request: &axum::http::Request<axum::body::Body>| {
                        tracing::info_span!(
                            "http_request",
                            method = %request.method(),
                            path = %request.uri().path(),
                        )
                    },
                ),
            )
            // 最外层指标中间件：看到最终状态码（JWT 401/403、限流 429、404）。
            .layer(axum_middleware::from_fn(observability::metrics_middleware))
            .with_state(config);

    tracing::info!(addr = %addr, "gateway listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
    .context("Gateway HTTP server failed before graceful shutdown completed")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use axum::body::{to_bytes, Body};
    use axum::extract::Path;
    use axum::http::Request;
    use axum::Router;
    use tower::ServiceExt;

    use super::axum_middleware;
    use astral_common::config::AppConfig;

    #[test]
    fn os_signal_failure_is_retained_after_runtime_cleanup() {
        let source = include_str!("runtime.rs");
        let wrapper = source
            .split("pub async fn run_with_listen_addr(addr: &str)")
            .nth(1)
            .unwrap()
            .split("pub async fn run_with_listen_addr_and_shutdown<F>")
            .next()
            .unwrap();
        assert!(wrapper.contains("signal_failed_in_shutdown.store(true"));
        let cleanup = wrapper.find(".await?;").unwrap();
        let check = wrapper.find("anyhow::ensure!(").unwrap();
        assert!(cleanup < check);
        assert!(wrapper.contains("gateway Ctrl-C handler failed during shutdown"));
    }

    #[tokio::test]
    async fn canonical_identity_user_routes_are_registered_without_bare_alias() {
        let app = super::identity_user_routes().with_state(AppConfig::default());
        let canonical_paths = [
            "/api/v1/auth/users",
            "/api/v1/auth/users/7",
            "/api/v1/auth/users/7/status",
            "/api/v1/auth/users/7/cards",
            "/api/v1/auth/users/7/password",
        ];

        for path in canonical_paths {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            // The default test config has no Identity upstream, so a matched proxy
            // returns a gateway dependency error; an unregistered route would be 404.
            assert_ne!(
                response.status(),
                404,
                "canonical route must be registered: {path}"
            );
        }

        for path in [
            "/api/v1/users",
            "/api/v1/users/7",
            "/api/v1/auth/users/7/unknown",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                404,
                "unregistered route must remain 404: {path}"
            );
        }
    }

    #[tokio::test]
    async fn canonical_identity_session_routes_exclude_session_operations() {
        let app = super::identity_session_routes().with_state(AppConfig::default());
        for path in [
            "/api/v1/auth/sessions",
            "/api/v1/auth/sessions/refresh",
            "/api/v1/auth/sessions/revoke",
            "/api/v1/auth/sessions/logout",
            "/api/v1/auth/sessions/switch-card",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_ne!(
                response.status(),
                404,
                "canonical session route must be registered: {path}"
            );
        }

        for path in [
            "/api/v1/auth/session-operations/operation/recover",
            "/api/v1/auth/session-operations/recover-by-key",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                404,
                "session operation route must remain unregistered: {path}"
            );
        }
    }

    #[tokio::test]
    async fn canonical_identity_session_routes_reject_non_post_methods() {
        let app = super::identity_session_routes().with_state(AppConfig::default());
        for path in [
            "/api/v1/auth/sessions",
            "/api/v1/auth/sessions/refresh",
            "/api/v1/auth/sessions/revoke",
            "/api/v1/auth/sessions/logout",
            "/api/v1/auth/sessions/switch-card",
        ] {
            for method in ["GET", "PUT", "PATCH", "DELETE"] {
                let response = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .method(method)
                            .uri(path)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    response.status(),
                    axum::http::StatusCode::METHOD_NOT_ALLOWED,
                    "session route must be POST-only: {method} {path}"
                );
            }
        }
    }

    #[tokio::test]
    async fn canonical_identity_me_routes_are_registered_without_unbind_alias() {
        let app = super::identity_me_routes().with_state(AppConfig::default());
        for path in [
            "/api/v1/auth/me",
            "/api/v1/auth/me/cards",
            "/api/v1/auth/me/identities",
            "/api/v1/auth/me/permissions",
            "/api/v1/auth/me/menus",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_ne!(
                response.status(),
                404,
                "canonical me route must be registered: {path}"
            );
        }

        for path in [
            "/api/v1/auth/me/identities/unbind",
            "/api/v1/auth/identities/unbind",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                404,
                "unsupported alias must remain 404: {path}"
            );
        }
    }

    #[tokio::test]
    async fn password_reset_route_accepts_one_token_segment_only() {
        let app = Router::new().route(
            "/api/v1/auth/password/reset/{token}",
            axum::routing::post(|Path(token): Path<String>| async move { token }),
        );

        let one_segment = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/password/reset/token?source=email")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(one_segment.status(), 200);
        assert_eq!(
            to_bytes(one_segment.into_body(), usize::MAX).await.unwrap(),
            "token"
        );

        let extra_segment = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/password/reset/token/extra")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(extra_segment.status(), 404);
    }

    #[tokio::test]
    async fn unknown_path_with_bearer_is_not_authenticated_before_404() {
        let app = Router::new()
            .route("/known", axum::routing::get(|| async { "ok" }))
            .route_layer(axum_middleware::from_fn_with_state(
                AppConfig::default(),
                super::jwt_auth_middleware,
            ))
            .with_state(AppConfig::default());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/unknown")
                    .header("authorization", "Bearer definitely-invalid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 404);
    }

    #[tokio::test]
    async fn chat_ws_route_accepts_one_positive_id_segment_only() {
        let app = super::chat_ws_routes().with_state(AppConfig::default());

        let canonical = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/chat/ws/42")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // The WebSocket extractor rejects a non-upgrade request after the route
        // has matched; 404 would mean the canonical route was not registered.
        assert_ne!(canonical.status(), 404);

        for path in [
            "/v1/chat/ws/42/extra",
            "/v1/chat/ws/42/",
            "/v1/chat/ws/0",
            "/v1/chat/ws/-1",
            "/v1/chat/ws/not-a-user",
            "/v1/chat/wsfoo/42",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                404,
                "invalid Chat WebSocket route must remain 404: {path}"
            );
        }
    }

    #[tokio::test]
    async fn chat_routes_do_not_fall_back_to_unknown_paths() {
        let app = super::chat_routes().with_state(AppConfig::default());
        for path in [
            "/v1/chat/wsfoo/42",
            "/v1/chat/ws/42/extra",
            "/v1/chat/unknown",
        ] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                404,
                "unknown Chat path must remain 404: {path}"
            );
        }
    }
}
