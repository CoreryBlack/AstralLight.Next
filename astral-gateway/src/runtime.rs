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
//! LISTEN_ADDR=0.0.0.0:9001 cargo run -p astral-gateway
//! ```

use axum::routing::{any, post};
use axum::{middleware as axum_middleware, Router};
use tower_http::cors::{AllowOrigin, Any, CorsLayer};

use anyhow::Context;
use astral_common::config::{AppConfig, JwtValidationRole};
use astral_common::error::global_exception_handler;
use std::future::Future;

#[path = "circuit_breaker.rs"]
mod circuit_breaker;
#[path = "middleware.rs"]
pub mod middleware;
#[path = "observability.rs"]
pub mod observability;
#[path = "proxy.rs"]
pub mod proxy;
#[path = "rate_limit.rs"]
pub mod rate_limit;

use crate::middleware::{jwt_auth_middleware, sanitize_internal_auth_headers};
use crate::rate_limit::rate_limit_middleware;
use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionVerifier;

/// Identity 用户管理的 canonical 外部路由。
///
/// Identity 已注册同一组 `/api/v1/auth/users` handler；Gateway 必须逐路由暴露，
/// 不能用未约束的 wildcard 把 Identity 未注册的路径一并代理出去。
fn identity_user_routes() -> Router<AppConfig> {
    Router::new()
        .route(
            "/api/v1/auth/integrations/identity-mappings",
            any(proxy::forward_to_identity_static),
        )
        .route(
            "/api/v1/auth/integrations/identity-mappings/status",
            any(proxy::forward_to_identity_static),
        )
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

fn gateway_routes() -> Router<AppConfig> {
    Router::new()
        .merge(identity_user_routes())
        .merge(identity_me_routes())
        .merge(identity_session_routes())
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
        .route("/main/api/v1/{*path}", any(proxy::forward_to_trustgraph))
        .route("/api/v1/monitor/{*path}", any(proxy::forward_to_monitor))
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
    let config = AppConfig::from_files_for("application", JwtValidationRole::Gateway)?;
    run_with_config_and_listen_addr_and_shutdown(config, addr, shutdown).await
}

pub async fn run_with_config_and_listen_addr_and_shutdown<F>(
    config: AppConfig,
    addr: &str,
    shutdown: F,
) -> anyhow::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    config.validate_listener_for(JwtValidationRole::Gateway)?;
    run_with_listen_addr_and_shutdown_inner(config, addr, shutdown, None).await
}

/// memory—v1: Run the legacy listener while retaining the process-composed
/// verifier capability for the future memory—v1 authentication branch.
///
/// The current listener still authenticates through the legacy JWT/MySQL path;
/// accepting this verifier does not authorize `m1.*` credentials or claim that
/// an external HTTP hop carries a request reader.
pub async fn run_with_memory_v1_session_and_config_and_listen_addr_and_shutdown<F>(
    config: AppConfig,
    addr: &str,
    shutdown: F,
    session_verifier: MemoryV1SessionVerifier,
) -> anyhow::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    config.validate_listener_for(JwtValidationRole::Gateway)?;
    run_with_listen_addr_and_shutdown_inner(config, addr, shutdown, Some(session_verifier)).await
}

async fn run_with_listen_addr_and_shutdown_inner<F>(
    config: AppConfig,
    addr: &str,
    shutdown: F,
    memory_v1_session_verifier: Option<MemoryV1SessionVerifier>,
) -> anyhow::Result<()>
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

    let session_db = astral_db::connect_and_validate_schema(&config.database_url)
        .await
        .map_err(|error| anyhow::Error::msg(error.to_string()))?;
    astral_db::validate_projection_owned_schema(&session_db)
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
    tracing::info!(
        transport = "mysql",
        "gateway session auth uses strict MySQL durable facts"
    );

    tracing::info!("gateway starting");

    let app = build_gateway_router(config);
    let app = match memory_v1_session_verifier {
        Some(session_verifier) => app.layer(axum::Extension(session_verifier)),
        None => app,
    };

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

/// memory—v1: Construct a Gateway router for one supervised in-process composition.
///
/// The caller must validate configuration and retain the unique root owner.
/// This does not open a listener or establish readiness.
pub fn build_in_process_gateway_router(
    config: AppConfig,
    identity: Router,
    trustgraph: Router,
    root: astral_authorization_root::memory_v1_root::RootHandle,
) -> Router {
    build_in_process_gateway_router_with_session_verifier(
        config,
        identity,
        trustgraph,
        root,
        MemoryV1SessionVerifier::deny_all(),
    )
}

/// memory—v1: Build the in-process Gateway with the Identity-owned verifier.
pub fn build_in_process_gateway_router_with_session_verifier(
    config: AppConfig,
    identity: Router,
    trustgraph: Router,
    root: astral_authorization_root::memory_v1_root::RootHandle,
    session_verifier: MemoryV1SessionVerifier,
) -> Router {
    build_in_process_gateway_router_with_session_verifier_and_budget(
        config,
        identity,
        trustgraph,
        root,
        session_verifier,
        astral_authorization_root::memory_v1_request::RequestRootBudget::new(
            proxy::DEFAULT_MAX_ACTIVE_REQUEST_SCOPES,
        ),
    )
}

/// memory—v1: Build the in-process Gateway whose request scopes are admitted
/// through the composition-owned `scope_budget`.
///
/// The composition keeps a clone of the budget to observe live request scopes;
/// exhaustion is rejected per request (503) and never queued.
pub fn build_in_process_gateway_router_with_session_verifier_and_budget(
    config: AppConfig,
    identity: Router,
    trustgraph: Router,
    root: astral_authorization_root::memory_v1_root::RootHandle,
    session_verifier: MemoryV1SessionVerifier,
    scope_budget: astral_authorization_root::memory_v1_request::RequestRootBudget,
) -> Router {
    let (identity_issuer, identity_verifier) =
        astral_common::middleware::gateway_signature::in_process_gateway_source();
    let (trustgraph_issuer, trustgraph_verifier) =
        astral_common::middleware::gateway_signature::in_process_gateway_source();
    let identity = identity.layer(axum_middleware::from_fn_with_state(
        (config.clone(), identity_verifier),
        astral_common::middleware::gateway_signature::in_process_gateway_signature_middleware,
    ));
    let trustgraph = trustgraph.layer(axum_middleware::from_fn_with_state(
        (config.clone(), trustgraph_verifier),
        astral_common::middleware::gateway_signature::in_process_gateway_signature_middleware,
    ));
    build_gateway_router(config).layer(axum::Extension(
        proxy::InProcessTargets::with_session_verifier_and_budget(
            identity,
            trustgraph,
            std::sync::Arc::new(identity_issuer),
            std::sync::Arc::new(trustgraph_issuer),
            root,
            session_verifier,
            scope_budget,
        ),
    ))
}

// memory—v1: Assemble the Gateway middleware independently of listener ownership.
fn build_gateway_router(config: AppConfig) -> Router {
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

    gateway_routes()
        // JWT 中间件（公共路径放行 + strict MySQL 会话判定（可选已证明镜像）+
        // 租户状态严格校验 + 身份头注入）
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
        .with_state(config)
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

    // memory—v1: The real Gateway route carries one request scope through in-process dispatch.
    #[tokio::test]
    async fn in_process_gateway_dispatches_public_route_and_ends_reader_scope() {
        use astral_authorization_root::memory_v1_db_rows::CandidateRows;
        use astral_authorization_root::memory_v1_hamt::CandidateBudget;
        use astral_authorization_root::memory_v1_request::{
            RequestRootAccessError, RequestRootExtension,
        };
        use astral_authorization_root::memory_v1_root::install_process_root;
        use axum::extract::Extension;
        use axum::http::{HeaderMap, StatusCode};
        use axum::routing::post;
        use std::sync::{Arc, Mutex};

        let owner = install_process_root(
            CandidateRows::default(),
            vec![],
            CandidateBudget {
                max_table_rows: 16,
                max_bindings_per_read: 4,
            },
        )
        .unwrap();
        let captured: Arc<Mutex<Option<RequestRootExtension>>> = Arc::new(Mutex::new(None));
        let downstream_captured = Arc::clone(&captured);
        let identity = Router::new().route(
            "/api/v1/auth/sessions",
            post(
                move |Extension(root): Extension<RequestRootExtension>,
                      axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<
                    std::net::SocketAddr,
                >,
                      headers: HeaderMap| {
                    let captured = Arc::clone(&downstream_captured);
                    async move {
                        assert!(!headers.contains_key("x-user-id"));
                        assert!(!headers.contains_key("x-real-ip"));
                        assert_eq!(
                            peer.ip(),
                            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                        );
                        let first = root
                            .with_reader(|reader| (reader.request_id(), reader.metadata()))
                            .unwrap();
                        let second = root
                            .clone()
                            .with_reader(|reader| (reader.request_id(), reader.metadata()))
                            .unwrap();
                        assert_eq!(first, second);
                        *captured.lock().unwrap() = Some(root);
                        StatusCode::NO_CONTENT
                    }
                },
            ),
        );
        let mut config = AppConfig::default();
        config.gateway.hmac_secret = uuid::Uuid::new_v4().to_string();
        let app =
            super::build_in_process_gateway_router(config, identity, Router::new(), owner.handle());
        let unauthorized = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/main/api/v1/permission-rules/registry")
                    .header("x-user-id", "forged")
                    .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                        std::net::Ipv4Addr::LOCALHOST,
                        12345,
                    ))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        assert!(captured.lock().unwrap().is_none());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/sessions")
                    .header("x-user-id", "forged")
                    .header("x-real-ip", "forged")
                    .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                        std::net::Ipv4Addr::LOCALHOST,
                        12345,
                    ))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        assert_eq!(
            status,
            StatusCode::NO_CONTENT,
            "{}",
            String::from_utf8_lossy(&body)
        );
        let extension = captured.lock().unwrap().take().unwrap();
        assert!(matches!(
            extension.with_reader(|_| ()),
            Err(RequestRootAccessError::ScopeEnded)
        ));
        in_process_routes_preserve_encoded_paths_and_query(owner.handle()).await;
    }

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
    async fn gateway_route_contract_excludes_service_direct_health_paths() {
        let app = super::gateway_routes().with_state(AppConfig::default());
        for path in [
            "/api/health",
            "/api/health/metrics",
            "/actuator/health",
            "/actuator/health/detailed",
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
                "service-direct health path must not be proxied by Gateway: {path}"
            );
        }

        for path in ["/api/v1/monitor/system-info", "/api/v1/monitor/metrics"] {
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
                "protected monitor path must remain a Gateway proxy route: {path}"
            );
        }
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
            "/api/v1/auth/integrations/identity-mappings",
            "/api/v1/auth/integrations/identity-mappings/status",
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
            "/integrations/identity-mappings",
            "/api/v1/auth/integrations/identity-mappings/unknown",
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

    // memory—v1: Exercise real Gateway route extraction and both downstream verifier boundaries.
    async fn in_process_routes_preserve_encoded_paths_and_query(
        root: astral_authorization_root::memory_v1_root::RootHandle,
    ) {
        use astral_common::middleware::gateway_signature::{
            in_process_gateway_signature_middleware, in_process_gateway_source,
        };
        use axum::http::StatusCode;
        use axum::routing::any;
        use std::sync::Arc;

        let mut config = AppConfig::default();
        config.gateway.hmac_secret = uuid::Uuid::new_v4().to_string();
        let (identity_issuer, identity_verifier) = in_process_gateway_source();
        let (trustgraph_issuer, trustgraph_verifier) = in_process_gateway_source();
        let identity = Router::new()
            .route(
                "/api/v1/auth/password/reset/{token}",
                any(inspect_in_process_route),
            )
            .route("/api/v1/auth/me", any(inspect_in_process_route))
            .layer(axum_middleware::from_fn_with_state(
                (config.clone(), identity_verifier),
                in_process_gateway_signature_middleware,
            ));
        let trustgraph = Router::new()
            .route("/main/api/v1/{*path}", any(inspect_in_process_route))
            .layer(axum_middleware::from_fn_with_state(
                (config.clone(), trustgraph_verifier),
                in_process_gateway_signature_middleware,
            ));
        let app = super::gateway_routes()
            .with_state(config)
            .layer(axum::Extension(super::proxy::InProcessTargets::new(
                identity,
                trustgraph,
                Arc::new(identity_issuer),
                Arc::new(trustgraph_issuer),
                root,
            )));

        for (method, uri) in [
            ("POST", "/api/v1/auth/password/reset/plain?source=email"),
            (
                "POST",
                "/api/v1/auth/password/reset/a%2Fb%3Fc%25d%23e?source=a%2Fb&empty=",
            ),
            ("GET", "/api/v1/auth/me?view=cards%2Factive"),
            (
                "GET",
                "/main/api/v1/permission-rules/a%2Fb%3Fc%25d%23e?view=a%2Fb&empty=",
            ),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        // Fixture identity stands in for the Gateway authentication layer.
                        .header("x-principal-kind", "APP_USER")
                        .header("x-identity-card-id", "fixture-card")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let body = to_bytes(response.into_body(), 4096).await.unwrap();
            assert_eq!(
                status,
                StatusCode::OK,
                "{uri}: {}",
                String::from_utf8_lossy(&body)
            );
            assert_eq!(body, uri, "{uri}");
        }
    }

    // memory—v1: Assert the handler sees exactly the URI bound by the verifier.
    async fn inspect_in_process_route(req: Request<Body>) -> String {
        assert_eq!(req.headers()["x-original-path"], req.uri().path());
        req.uri().to_string()
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
}
