// AstralLight 身份认证服务
//
// 对应 Java `AstralIdentity` 模块。
// 职责：用户注册、密码验证、JWT 签发。

#[path = "api.rs"]
pub mod api;
#[path = "auth.rs"]
pub mod auth;
#[path = "integration_mappings.rs"]
mod integration_mappings;
#[path = "memory_v1.rs"]
pub mod memory_v1;
#[path = "middleware.rs"]
pub mod middleware;
#[path = "srv/mod.rs"]
pub mod srv;

use std::future::IntoFuture;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::extract::{ConnectInfo, FromRef, Request, State};
use axum::middleware::Next;
use axum::response::Response;
use axum::Router;
use lapin::Connection;
use policy_engine::PolicyEngine;
use sqlx::MySqlPool;

use astral_common::audit::{register_audit_db_writer, AuditDbWriter, AuditEntry};
use astral_common::config::{AppConfig, JwtValidationRole};
use astral_common::error::global_exception_handler;
use astral_common::middleware::gateway_signature::gateway_signature_middleware;
use astral_common::middleware::ip_rate_limit::{
    rate_limit_response, resolve_client_ip, IpRateLimiter, TrustedProxySet,
};
use astral_common::service::{register_mq_producer, AuditLogEvent, MqProducerRef};
use astral_db::connect_and_validate_schema;
use srv::auth_repository::SqlxAuthRepository;
use srv::auth_service::AuthService;
use srv::card_repository::SqlxCardRepository;
use srv::me_repository::SqlxMeRepository;
use srv::me_service::MeService;
use srv::org_repository::SqlxOrgRepository;
use srv::org_service::OrgService;
use srv::user_repository::SqlxUserRepository;
use srv::user_service::UserService;

/// Owns each local consumer until bounded shutdown or runtime cancellation.
struct IdentityRuntimeTaskHandle {
    name: &'static str,
    join: Option<tokio::task::JoinHandle<()>>,
}

/// Required-worker death wait (worker-supervision-20261002): resolves with the
/// stable terminal reason once the supervised recovery loop reached a terminal
/// state, or immediately when the death channel closed (supervisor gone).
async fn wait_required_worker_death(
    death: &mut tokio::sync::watch::Receiver<Option<String>>,
) -> String {
    loop {
        if let Some(reason) = death.borrow().clone() {
            return reason;
        }
        if death.changed().await.is_err() {
            return "session recovery worker death channel closed".to_owned();
        }
    }
}

impl IdentityRuntimeTaskHandle {
    fn spawn(
        name: &'static str,
        task: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Self {
        Self {
            name,
            join: Some(tokio::spawn(task)),
        }
    }

    /// 有界 join：超时则 abort 并等待收敛；`Err` 报告超时/panic，绝不静默。
    async fn shutdown_join(mut self, timeout: std::time::Duration) -> Result<(), String> {
        let name = self.name;
        let Some(join) = self.join.as_mut() else {
            return Ok(());
        };
        match tokio::time::timeout(timeout, &mut *join).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(join_error)) => Err(format!("runtime task {name} join failed: {join_error}")),
            Err(_) => {
                join.abort();
                let _ = tokio::time::timeout(std::time::Duration::from_secs(1), &mut *join).await;
                Err(format!(
                    "runtime task {name} shutdown timed out; final outcome unknown"
                ))
            }
        }
    }
}

impl Drop for IdentityRuntimeTaskHandle {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}

#[async_trait::async_trait]
trait IdentityRabbitConnectionClose: Send + Sync {
    async fn close(&self, reason: &str) -> Result<(), String>;
}

struct LapinIdentityRabbitConnection(Arc<Connection>);

#[async_trait::async_trait]
impl IdentityRabbitConnectionClose for LapinIdentityRabbitConnection {
    async fn close(&self, reason: &str) -> Result<(), String> {
        self.0
            .close(200, reason.to_owned().into())
            .await
            .map_err(|error| error.to_string())
    }
}

/// Owns a successfully bootstrapped Rabbit connection independently of the
/// global producer's channel clones. Drop requests a bounded best-effort close;
/// only `shutdown` can return an explicit close result to its caller.
struct IdentityRabbitConnectionGuard {
    connection: Option<Arc<dyn IdentityRabbitConnectionClose>>,
}

impl IdentityRabbitConnectionGuard {
    fn new(connection: Arc<Connection>) -> Self {
        Self::from_owner(Arc::new(LapinIdentityRabbitConnection(connection)))
    }

    fn from_owner(connection: Arc<dyn IdentityRabbitConnectionClose>) -> Self {
        Self {
            connection: Some(connection),
        }
    }

    async fn shutdown(mut self, reason: &str) -> Result<(), String> {
        let connection = Arc::clone(
            self.connection
                .as_ref()
                .expect("Rabbit connection guard owns the connection until close succeeds"),
        );
        match tokio::time::timeout(Duration::from_secs(5), connection.close(reason)).await {
            Ok(Ok(())) => {
                self.connection.take();
                Ok(())
            }
            Ok(Err(error)) => Err(format!("Identity Rabbit connection close failed: {error}")),
            Err(_) => Err("Identity Rabbit connection close timed out; outcome unknown".to_owned()),
        }
    }
}

impl Drop for IdentityRabbitConnectionGuard {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.take() {
            spawn_identity_connection_close_reaper(
                connection,
                "identity early shutdown".to_owned(),
            );
        }
    }
}

fn spawn_identity_connection_close_reaper(
    connection: Arc<dyn IdentityRabbitConnectionClose>,
    reason: String,
) {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        tracing::error!("Identity Rabbit connection close could not be scheduled; outcome unknown");
        return;
    };
    runtime.spawn(async move {
        match tokio::time::timeout(Duration::from_secs(5), connection.close(&reason)).await {
            Ok(Ok(())) => tracing::debug!("Identity Rabbit connection closed by shutdown reaper"),
            Ok(Err(_)) | Err(_) => {
                tracing::warn!("Identity Rabbit close reaper could not prove connection close")
            }
        }
    });
}

fn finish_after_signal_failure(
    result: anyhow::Result<()>,
    signal_failure: Result<String, tokio::sync::oneshot::error::RecvError>,
) -> anyhow::Result<()> {
    match signal_failure {
        Ok(reason) => match result {
            Ok(()) => Err(anyhow::anyhow!("Identity shutdown signal failed: {reason}")),
            Err(error) => {
                Err(error.context(format!("Identity shutdown signal also failed: {reason}")))
            }
        },
        Err(_) => result,
    }
}

/// Startup-failure cleanup for owners created before HTTP serving begins.
///
/// Startup order is authority runtime -> session recovery worker -> transport
/// owners. Cleanup therefore runs in reverse order. Every owned resource is
/// awaited within its existing bounded shutdown API; failures are accumulated
/// and do not skip later owners, with authority stopped last.
async fn shutdown_startup_owners(
    session_projection_worker: srv::session_projection_worker::SessionProjectionWorkerHandle,
    local_stop_tx: tokio::sync::watch::Sender<bool>,
    local_owner_tasks: Vec<IdentityRuntimeTaskHandle>,
    rabbit_connection: Option<IdentityRabbitConnectionGuard>,
    authority_source_outcome_runtime: Option<
        astral_db::authority_source_runtime::AuthoritySourceOutcomeRuntimeHandle,
    >,
) -> Vec<String> {
    let mut failures = Vec::new();
    let _ = local_stop_tx.send(true);
    for task in local_owner_tasks {
        if let Err(failure) = task.shutdown_join(Duration::from_secs(5)).await {
            failures.push(failure);
        }
    }
    if let Some(connection) = rabbit_connection {
        if let Err(failure) = connection.shutdown("identity startup rollback").await {
            failures.push(failure);
        }
    }
    if let Err(failure) = session_projection_worker.shutdown_join().await {
        failures.push(failure);
    }
    if let Some(handle) = authority_source_outcome_runtime {
        if let Err(failure) = handle
            .shutdown(astral_db::authority_source_runtime::SOURCE_OUTCOME_SHUTDOWN_JOIN_TIMEOUT)
            .await
        {
            failures.push(failure);
        }
    }
    failures
}

fn identity_startup_error(message: impl Into<String>, failures: Vec<String>) -> anyhow::Error {
    let message = message.into();
    if failures.is_empty() {
        anyhow::anyhow!(message)
    } else {
        anyhow::anyhow!(
            "{message}; startup rollback failed: {}",
            failures.join("; ")
        )
    }
}

async fn consume_local_until_stopped(
    mut receiver: astral_mq::local_bus::LocalReceiver,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        if *stop.borrow() {
            receiver.close();
            break;
        }
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    receiver.close();
                    break;
                }
            }
            delivery = receiver.recv() => {
                let Some(delivery) = delivery else { return; };
                let result = astral_mq::consumers::dispatch_local_delivery(&delivery).await;
                delivery.complete(result);
            }
        }
    }
    while let Some(delivery) = receiver.recv().await {
        let result = astral_mq::consumers::dispatch_local_delivery(&delivery).await;
        delivery.complete(result);
    }
}

/// 应用共享状态
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub db: MySqlPool,
    pub engine: Arc<PolicyEngine>,
    pub me_service: Arc<MeService>,
    pub auth_service: Arc<AuthService>,
    pub user_service: Arc<UserService>,
    pub card_repository: Arc<dyn srv::card_repository::CardRepository>,
    pub org_service: Arc<OrgService>,
    /// Password-reset delivery is an explicit Identity-owned port. The runtime
    /// resolves it once at startup via
    /// `srv::password::password_reset_notifier_from_env`: real SMTP delivery
    /// (durable delivery-intent store, secrets only via protected env NAMES)
    /// when configured, otherwise the fail-closed `UnavailablePasswordResetNotifier`
    /// that keeps the unified 503-before-lookup contract. This field never
    /// falls back to returning reset tokens to the caller.
    pub password_reset_notifier: Arc<dyn srv::password::PasswordResetNotifier>,
    /// Fixed trust-root verifier for request-bound authorization fences. A
    /// missing provider is not-ready in Strict mode; DurableOnly is an explicit
    /// compatibility profile.
    pub authorization_fence_provider: Option<Arc<astral_db::SqlxAuthorizationFenceProvider>>,
    /// ORG_SCOPE 部署旗标（default-off）：启动期由共享 AppConfig 经
    /// astral-common 严格解析器一次性解析并冻结（`config.org_scope_enabled`），
    /// 本字段只是同一冻结值的 AppState 侧副本；授权中间件构造正式
    /// `SqlxRuleRepository` 时必须传入，绝不逐请求读 env。
    pub org_scope_enabled: bool,
}

impl FromRef<AppState> for MySqlPool {
    fn from_ref(state: &AppState) -> Self {
        state.db.clone()
    }
}

impl FromRef<AppState> for astral_common::config::AppConfig {
    fn from_ref(state: &AppState) -> Self {
        (*state.config).clone()
    }
}

/// DB adapter for the common audit writer.
struct IdentityAuditDbWriter {
    pool: MySqlPool,
}

#[async_trait::async_trait]
impl AuditDbWriter for IdentityAuditDbWriter {
    async fn insert_audit(&self, entry: &AuditEntry) -> Result<(), String> {
        astral_db::insert_audit_log(&self.pool, entry)
            .await
            .map_err(|e| e.to_string())
    }
}

/// MQ Producer 包装器
///
/// 实现 `MqProducerRef` trait，将 `astral_mq::producer::Producer` 的能力
/// 桥接到 `astral_common::service::MqProducerRef`，供审计双写使用。
struct IdentityMqProducer {
    inner: astral_mq::producer::Producer,
}

#[async_trait::async_trait]
impl MqProducerRef for IdentityMqProducer {
    async fn publish_audit_log(&self, event: AuditLogEvent) -> Result<(), String> {
        let payload = astral_mq::producer::AuditLogPayload {
            user_id: event.user_id,
            card_id: event.card_id,
            action: event.action,
            resource: event.resource,
            decision: event.decision,
            reason: event.reason,
            event_type: event.event_type,
            source_ip: event.source_ip,
            request_id: event.request_id,
            domain_id: event.domain_id,
            tenant_id: event.tenant_id,
            // producer detail 随消息透传；consumer 仅在非空白时落库。
            detail: event.detail,
        };
        self.inner
            .publish_audit_log(payload)
            .await
            .map_err(|e| e.to_string())
    }

    async fn publish_login_event(
        &self,
        user_id: i64,
        login_type: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        success: bool,
    ) -> Result<(), String> {
        let payload = astral_mq::producer::LoginEventPayload {
            user_id,
            card_id: None,
            login_type: login_type.to_string(),
            ip_address: ip_address.map(|s| s.to_string()),
            user_agent: user_agent.map(|s| s.to_string()),
            success,
        };
        self.inner
            .publish_login_event(payload)
            .await
            .map_err(|e| e.to_string())
    }
}

/// `/password/forgot` 的进程内 per-IP 限流（Identity 直连监听器防护）。
///
/// ## 与 verification 限流同源同合同
///
/// 计数核心、受信代理匹配与客户端 IP 解析复用共享
/// `astral_common::middleware::ip_rate_limit`（`IpRateLimiter` /
/// `TrustedProxySet` / `resolve_client_ip` / `rate_limit_response`，与
/// Gateway/verification 同源），沿用同一启动期冻结
/// `RateLimitCfg`（`state.config.rate_limit`）与
/// `gateway.trusted_proxy_ips` 可信代理合同；不重新实现桶计数。限流只做
/// 可用性保护：不产生 `AuthorizationAdmission`、不读取/消费宿主准入栅栏，
/// bootstrap 路由的 admission-free 语义不变。跨副本不预算（与 verification
/// 相同的已知边界）；notifier 侧的 durable 交付预算由 notifier owner 单独
/// 持有，本限流不代表交付预算。
///
/// ## 作用域（刻意收窄）
///
/// `password_reset_routes()` 子路由整体挂 `route_layer`，但仅 `/password/forgot`
/// 消耗预算；`/password/reset/{token}` 直接放行——forgot 触发出站 notifier
/// 交付并暴露账号探测面，reset 只按持有令牌兑换且无出站副作用，同一 IP 的
/// 合法重置不应被 forgot 预算误伤。预算桶与 verification 限流相互独立
/// （独立 `IpRateLimiter` 实例），两侧互不挤占。
struct PasswordForgotRateLimit {
    limiter: IpRateLimiter,
    trusted: TrustedProxySet,
}

static PASSWORD_FORGOT_IP_LIMITER: OnceLock<PasswordForgotRateLimit> = OnceLock::new();

/// Identity 直连监听器上 `/password/forgot` 的 per-IP 限流入口（仅该路径
/// 计预算，见类型文档；对端地址缺失时聚合单桶，绝不 panic 或放行）。
pub(crate) async fn password_forgot_ip_rate_limit(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    // 仅 /password/forgot 计预算；同子路由的 reset/{token} 直通。
    if !req.uri().path().ends_with("/password/forgot") {
        return next.run(req).await;
    }
    // 配置来自首个请求的启动期冻结 AppConfig（对齐 verification/Gateway 注入模式）。
    let shared = PASSWORD_FORGOT_IP_LIMITER.get_or_init(|| {
        let trusted = TrustedProxySet::compile(&state.config.gateway.trusted_proxy_ips);
        for entry in trusted.invalid_entries() {
            tracing::warn!(
                entry = %entry,
                "invalid gateway.trusted_proxy_ips entry; ignored (fail closed to peer address)"
            );
        }
        PasswordForgotRateLimit {
            limiter: IpRateLimiter::new(state.config.rate_limit.clone()),
            trusted,
        }
    });
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|connect_info| connect_info.0.ip());
    let client = resolve_client_ip(req.headers(), peer, &shared.trusted);
    if !shared.limiter.check(client) {
        tracing::warn!(
            client = ?client,
            path = req.uri().path(),
            "password forgot rate limit exceeded"
        );
        return rate_limit_response(&req, "password-forgot-rate-limit-error");
    }
    next.run(req).await
}

fn source_delivery_context(
    config: &AppConfig,
) -> anyhow::Result<Option<Arc<astral_db::invalidation_delivery::InvalidationDeliveryContext>>> {
    let delivery = &config.invalidation_delivery;
    if !delivery.enabled {
        return Ok(None);
    }
    let recipients = serde_json::from_str(&delivery.recipients_json)
        .map_err(|error| anyhow::anyhow!("invalid invalidation delivery recipients: {error}"))?;
    let context = astral_db::invalidation_delivery::InvalidationDeliveryContext::try_new(
        delivery.source_database_id.clone(),
        delivery.roster_version.clone(),
        recipients,
    )
    .map_err(|error| anyhow::anyhow!("invalid invalidation delivery context: {error}"))?;
    Ok(Some(Arc::new(context)))
}

pub async fn run() -> anyhow::Result<()> {
    let addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:9004".to_string());
    run_with_listen_addr(&addr).await
}

pub async fn run_with_listen_addr(addr: &str) -> anyhow::Result<()> {
    let (signal_failure_tx, signal_failure_rx) = tokio::sync::oneshot::channel();
    let result = run_with_listen_addr_and_shutdown(addr, async move {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::warn!(%error, "failed to install Ctrl-C handler");
            let _ = signal_failure_tx.send(error.to_string());
        }
    })
    .await;
    finish_after_signal_failure(result, signal_failure_rx.await)
}

pub async fn run_with_listen_addr_and_shutdown<F>(addr: &str, shutdown: F) -> anyhow::Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    run_with_listen_addr_and_shutdown_and_drain(addr, shutdown, std::future::ready(())).await
}

pub async fn run_with_listen_addr_and_shutdown_and_drain<F, D>(
    addr: &str,
    shutdown: F,
    producers_drained: D,
) -> anyhow::Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
    D: std::future::Future<Output = ()> + Send + 'static,
{
    let config = AppConfig::from_files_for("application", JwtValidationRole::Identity)?;
    run_with_config_and_listen_addr_and_shutdown_and_drain(
        config,
        addr,
        shutdown,
        producers_drained,
    )
    .await
}

/// Run Identity with a caller-owned startup-frozen configuration.
///
/// Composite hosts load `AppConfig` once and pass a clone of that frozen value
/// to each in-process runtime. Standalone callers retain the compatibility
/// wrappers above, which load their own configuration once.
pub async fn run_with_config_and_listen_addr_and_shutdown<F>(
    config: AppConfig,
    addr: &str,
    shutdown: F,
) -> anyhow::Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    run_with_config_and_listen_addr_and_shutdown_and_drain(
        config,
        addr,
        shutdown,
        std::future::ready(()),
    )
    .await
}

/// memory—v1
pub async fn run_with_config_and_listen_addr_and_shutdown_and_drain<F, D>(
    config: AppConfig,
    addr: &str,
    shutdown: F,
    producers_drained: D,
) -> anyhow::Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
    D: std::future::Future<Output = ()> + Send + 'static,
{
    run_with_config_and_listen_addr_and_shutdown_and_drain_inner(
        config,
        addr,
        shutdown,
        producers_drained,
        None,
    )
    .await
}

/// memory—v1: Run Identity with an explicitly injected UUID-native session
/// boundary while retaining the existing startup and shutdown contract.
pub async fn run_with_memory_v1_session_and_config_and_listen_addr_and_shutdown<F>(
    config: AppConfig,
    addr: &str,
    shutdown: F,
    memory_v1_session: Arc<memory_v1::MemoryV1IdentitySession>,
) -> anyhow::Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    run_with_memory_v1_session_and_config_and_listen_addr_and_shutdown_and_drain(
        config,
        addr,
        shutdown,
        std::future::ready(()),
        memory_v1_session,
    )
    .await
}

/// memory—v1: Composite hosts use this entry to inject the Identity-owned
/// session boundary created by the single process authority.
pub async fn run_with_memory_v1_session_and_config_and_listen_addr_and_shutdown_and_drain<F, D>(
    config: AppConfig,
    addr: &str,
    shutdown: F,
    producers_drained: D,
    memory_v1_session: Arc<memory_v1::MemoryV1IdentitySession>,
) -> anyhow::Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
    D: std::future::Future<Output = ()> + Send + 'static,
{
    run_with_config_and_listen_addr_and_shutdown_and_drain_inner(
        config,
        addr,
        shutdown,
        producers_drained,
        Some(memory_v1_session),
    )
    .await
}

/// memory—v1: Internal startup implementation shared by legacy standalone and
/// injected composite entry points. `None` preserves the legacy runtime shape;
/// it never manufactures a memory—v1 authority.
async fn run_with_config_and_listen_addr_and_shutdown_and_drain_inner<F, D>(
    config: AppConfig,
    addr: &str,
    shutdown: F,
    producers_drained: D,
    memory_v1_session: Option<Arc<memory_v1::MemoryV1IdentitySession>>,
) -> anyhow::Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
    D: std::future::Future<Output = ()> + Send + 'static,
{
    config.validate_listener_for(JwtValidationRole::Identity)?;
    let config = Arc::new(config);
    astral_common::middleware::permission_check_shared::validate_path_map(
        middleware::IDENTITY_PATH_MAP,
        "identity",
    )?;

    if let Some(metrics_addr) =
        astral_common::metrics_runtime::metrics_listen_addr("127.0.0.1:9103")
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

    // 进程级 origin region 唯一安装点：配置校验后、DB/worker/router 装配前
    // 安装一次。durable invalidation intent 在未安装时拒绝 append（fail-closed），
    // 因此必须在任何可能触发租户资格变更的路径之前完成。
    srv::org_repository::install_origin_region(config.region_id.clone())
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let identity_mapping_enabled =
        integration_mappings::enabled_from_env().map_err(anyhow::Error::msg)?;
    let db = connect_and_validate_schema(&config.database_url).await?;
    astral_db::validate_projection_owned_schema(&db).await?;
    if identity_mapping_enabled {
        astral_db::validate_integration_mapping_schema(&db).await?;
    }
    // 纯配置门（message transport 解析）先于任何后台 worker/authority 装配：
    // 非法传输值只在零后台任务时拒绝启动。
    let message_transport = config.message_transport().map_err(anyhow::Error::msg)?;
    let invalidation_delivery = source_delivery_context(&config)?;
    if let Some(context) = &invalidation_delivery {
        astral_mq::consumers::set_session_revocation_delivery((**context).clone())
            .map_err(anyhow::Error::msg)?;
    }
    let authorization_fence_provider = astral_db::authority_provider_from_env(db.clone())
        .await
        .map_err(|error| {
            anyhow::anyhow!("authorization authority trust-root configuration invalid: {error}")
        })?;
    let authorization_read_surface = astral_db::ensure_authorization_read_surface(
        config.authorization_read_profile,
        db.clone(),
        config.org_scope_enabled,
        config.authority_runtime_mode.requires_authority(),
        authorization_fence_provider.clone(),
        None,
    )
    .map_err(|error| anyhow::anyhow!("authorization read surface unavailable: {error}"))?;
    let _authorization_read_surface = authorization_read_surface;
    // Authority source outcome reconciliation runtime（V7）：Identity 与
    // TrustGraph/Monitor 运行同一共享生命周期任务。worker 序列中最先启动，
    // 按严格逆序在关闭尾段最后停止——位于 HTTP/request drain、producers
    // drain 与 owned transport 关闭之后。provider 缺席时保持既有 fail-closed
    // 行为：不启动、不产生正向就绪信号。运行 UUID 每进程任务一个、全程稳定；
    // 批次/lease/尝试上限与 allowlist 由 provider/quorum 配置持有，本装配不
    // 引入第二套配置。
    let mut authority_source_outcome_runtime = authorization_fence_provider
        .clone()
        .map(astral_db::authority_source_runtime::spawn_authority_source_outcome_runtime);
    let engine = Arc::new(PolicyEngine::new());
    register_audit_db_writer(Arc::new(IdentityAuditDbWriter { pool: db.clone() }));
    let me_service = Arc::new(MeService::new(Arc::new(SqlxMeRepository::new(db.clone()))));
    let auth_repository = Arc::new(SqlxAuthRepository::new(db.clone()));
    let auth_service = Arc::new(match memory_v1_session {
        Some(memory_v1_session) => {
            AuthService::with_memory_v1_session(auth_repository.clone(), memory_v1_session)
        }
        None => AuthService::new(auth_repository.clone()),
    });
    let user_repository = match &invalidation_delivery {
        Some(context) => SqlxUserRepository::new_with_delivery_context(db.clone(), context.clone()),
        None => SqlxUserRepository::new(db.clone()),
    };
    let user_service = Arc::new(UserService::new(Arc::new(user_repository), auth_repository));
    let card_repository: Arc<dyn srv::card_repository::CardRepository> =
        Arc::new(match &invalidation_delivery {
            Some(context) => {
                SqlxCardRepository::new_with_delivery_context(db.clone(), context.clone())
            }
            None => SqlxCardRepository::new(db.clone()),
        });
    let org_repository = match &invalidation_delivery {
        Some(context) => SqlxOrgRepository::new_with_delivery_context(db.clone(), context.clone()),
        None => SqlxOrgRepository::new(db.clone()),
    };
    let org_service = Arc::new(OrgService::new(Arc::new(org_repository)));
    // ORG_SCOPE 旗标已在配置加载处一次性解析并冻结（非法值启动即失败）；
    // 这里只复制冻结值，不再读取 env。default-off：未配置时保持 false。
    let org_scope_enabled = config.org_scope_enabled;
    let state = AppState {
        config,
        db: db.clone(),
        engine,
        me_service,
        auth_service,
        user_service,
        card_repository,
        org_service,
        password_reset_notifier: srv::password::password_reset_notifier_from_env(db.clone()),
        authorization_fence_provider,
        org_scope_enabled,
    };

    // Every Identity replica runs the same leased recovery loop. MySQL owns
    // coordination and durable authority; the worker reconciles process-local
    // acceleration only after verifying the committed revocation snapshot.
    //
    // worker-supervision-20261002: the required recovery leg runs on the
    // OWNED handle flavor — RAII (Drop aborts the supervisor), bounded
    // shutdown, and an observable death signal. Startup gates above are
    // unchanged.
    let session_projection_worker = srv::session_projection_worker::spawn_owned(state.clone());

    // Inject Identity-owned durable handlers before either transport starts.
    astral_mq::consumers::set_session_revocation_db(db.clone());
    astral_mq::consumers::set_login_event_db(db.clone());
    // worker-supervision-20261002: RAII handles for the local owner consumer
    // loops; declared at function scope so they live until the serve tail and
    // receive a bounded shutdown on every exit path.
    let mut local_owner_tasks: Vec<IdentityRuntimeTaskHandle> = Vec::new();
    let mut rabbit_connection: Option<IdentityRabbitConnectionGuard> = None;
    let (local_stop_tx, local_stop_rx) = tokio::sync::watch::channel(false);
    if matches!(
        message_transport,
        astral_common::config::MessageTransport::Local
    ) {
        let bus = match astral_mq::local_bus::global_local_bus() {
            Some(bus) => bus,
            None => {
                let failures = shutdown_startup_owners(
                    session_projection_worker,
                    local_stop_tx,
                    local_owner_tasks,
                    rabbit_connection,
                    authority_source_outcome_runtime.take(),
                )
                .await;
                return Err(identity_startup_error(
                    "local transport requires a composite runtime-installed LocalBus",
                    failures,
                ));
            }
        };
        // worker-supervision-20261002: the local owner consumer loops are
        // RAII-owned (Drop abort; bounded shutdown at serve end) instead of
        // detached fire-and-forget — identical dispatch/complete semantics.
        let revocation_receiver = match bus.register(
            astral_mq::config::QUEUE_AUTH_SESSION_REVOCATION,
            astral_mq::local_bus::LocalOwner::Identity,
        ) {
            Ok(receiver) => receiver,
            Err(error) => {
                let failures = shutdown_startup_owners(
                    session_projection_worker,
                    local_stop_tx,
                    local_owner_tasks,
                    rabbit_connection,
                    authority_source_outcome_runtime.take(),
                )
                .await;
                return Err(identity_startup_error(error.to_string(), failures));
            }
        };
        let login_receiver = match bus.register(
            astral_mq::config::QUEUE_LOGIN_EVENT,
            astral_mq::local_bus::LocalOwner::Identity,
        ) {
            Ok(receiver) => receiver,
            Err(error) => {
                let failures = shutdown_startup_owners(
                    session_projection_worker,
                    local_stop_tx,
                    local_owner_tasks,
                    rabbit_connection,
                    authority_source_outcome_runtime.take(),
                )
                .await;
                return Err(identity_startup_error(error.to_string(), failures));
            }
        };
        let revocation_consumer = IdentityRuntimeTaskHandle::spawn(
            "identity-local-revocation-consumer",
            consume_local_until_stopped(revocation_receiver, local_stop_rx.clone()),
        );
        let login_consumer = IdentityRuntimeTaskHandle::spawn(
            "identity-local-login-consumer",
            consume_local_until_stopped(login_receiver, local_stop_rx),
        );
        local_owner_tasks.push(revocation_consumer);
        local_owner_tasks.push(login_consumer);
        let producer =
            astral_mq::producer::Producer::new_local(bus, state.config.region_id.clone());
        register_mq_producer(Arc::new(IdentityMqProducer { inner: producer }));
    } else {
        let mq_url = state.config.rabbitmq_url.clone();
        let mut connected = false;
        for attempt in 1..=5_u32 {
            if let Ok((producer, connection)) = init_mq(&mq_url, &db).await {
                // Retain a shutdown owner before registering the global producer:
                // channel clones outlive this function's local bindings.
                rabbit_connection = Some(IdentityRabbitConnectionGuard::new(connection));
                register_mq_producer(Arc::new(producer));
                tracing::info!(
                    service = "identity",
                    transport = "rabbit",
                    "MQ producer registered"
                );
                connected = true;
                break;
            }
            if attempt < 5 {
                let backoff_secs = 2u64.pow(attempt.min(3));
                tracing::warn!(
                    service = "identity",
                    attempt,
                    backoff_secs,
                    "MQ initialization failed, retrying with backoff"
                );
                tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
            }
        }
        if !connected {
            let failures = shutdown_startup_owners(
                session_projection_worker,
                local_stop_tx,
                local_owner_tasks,
                rabbit_connection,
                authority_source_outcome_runtime.take(),
            )
            .await;
            return Err(identity_startup_error(
                "Identity MQ bootstrap exhausted its retry budget",
                failures,
            ));
        }
    }

    // 启动期注册校验已在所有 worker、consumer、metrics 和 router 装配前完成。
    let app = build_router(state, identity_mapping_enabled);

    tracing::info!(addr = %addr, "identity service starting");
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(error) => {
            let failures = shutdown_startup_owners(
                session_projection_worker,
                local_stop_tx,
                local_owner_tasks,
                rabbit_connection,
                authority_source_outcome_runtime.take(),
            )
            .await;
            return Err(identity_startup_error(
                format!("Identity HTTP listener bind failed: {error}"),
                failures,
            ));
        }
    };
    // Required recovery-worker death closes admission before draining HTTP tasks.
    let mut session_death = session_projection_worker.death_signal();
    let (serve_stop_tx, serve_stop_rx) = tokio::sync::oneshot::channel();
    let (drain_started_tx, mut drain_started_rx) = tokio::sync::oneshot::channel();
    // into_make_service_with_connect_info：verification 路由的 per-IP 限流
    // 需要在对端地址缺失时回退 TCP peer（trusted XFF 之外的回退源）；扩展
    // 缺失时限流器聚合 unknown 单桶，不会 panic。
    let mut serve = std::pin::pin!(axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>()
    )
    .with_graceful_shutdown(async move {
        tokio::select! {
            _ = shutdown => {}
            _ = serve_stop_rx => {}
        }
        if let Some(hub) = astral_db::memory_projection_hub() {
            hub.mark_runtime_owner_failed("identity runtime shutting down");
        }
        let _ = drain_started_tx.send(());
    })
    .into_future());
    let serve_result = tokio::select! {
        result = &mut serve => result
            .map_err(|error| anyhow::anyhow!("identity service serve failed: {error}")),
        _ = &mut drain_started_rx => {
            match tokio::time::timeout(std::time::Duration::from_secs(30), &mut serve).await {
                Ok(result) => result.map_err(Into::into),
                Err(_) => Err(anyhow::anyhow!("Identity HTTP drain timed out; handler outcomes unknown")),
            }
        }
        reason = wait_required_worker_death(&mut session_death) => {
            if let Some(hub) = astral_db::memory_projection_hub() {
                hub.mark_runtime_owner_failed(format!(
                    "code=identity.required_worker_death;reason={reason}"
                ));
            }
            let _ = serve_stop_tx.send(());
            let drain = tokio::time::timeout(std::time::Duration::from_secs(30), &mut serve).await;
            Err(anyhow::anyhow!(
                "required session recovery worker died: {reason}; HTTP drain outcome: {drain:?}"
            ))
        }
        death = async {
            match authority_source_outcome_runtime.as_mut() {
                Some(handle) => handle.wait_for_death().await,
                None => std::future::pending().await,
            }
        } => {
            // Required reconciliation runtime death fails readiness closed via
            // the existing hub owner-failure API; no blanket clears, and the
            // hub never returns to serving on this path.
            if let Some(hub) = astral_db::memory_projection_hub() {
                hub.mark_runtime_owner_failed(format!(
                    "code=identity.authority_source_outcome_runtime_death;reason={death}"
                ));
            }
            let _ = serve_stop_tx.send(());
            let drain = tokio::time::timeout(std::time::Duration::from_secs(30), &mut serve).await;
            Err(anyhow::anyhow!(
                "required authority source outcome reconciliation runtime died: {death}; HTTP drain outcome: {drain:?}"
            ))
        }
    };
    let worker_result = session_projection_worker.shutdown_join().await;
    // ORG events may have a frozen deadline of almost one hour on the peer.
    let barrier_result =
        tokio::time::timeout(std::time::Duration::from_secs(4_200), producers_drained).await;
    let mut failures = Vec::new();
    if barrier_result.is_err() {
        failures.push("Identity producer drain barrier timed out; outcome unknown".into());
    }
    let audit_result =
        astral_common::audit::drain_owned_audit_tasks(std::time::Duration::from_secs(5)).await;
    let _ = local_stop_tx.send(true);
    if let Err(failure) = audit_result {
        failures.push(failure);
    }
    for task in local_owner_tasks {
        if let Err(failure) = task.shutdown_join(std::time::Duration::from_secs(5)).await {
            failures.push(failure);
        }
    }
    if let Err(failure) = worker_result {
        failures.push(failure);
    }
    if let Some(connection) = rabbit_connection {
        if let Err(failure) = connection.shutdown("identity runtime shutdown").await {
            failures.push(failure);
        }
    }
    // Authority source outcome reconciliation runtime：worker 序列中最先启动，
    // 按严格逆序最后停止——位于 HTTP/request drain、producers drain、owned
    // audit drain 与本地 consumer/Rabbit 关闭之后。在途 cycle 受 <=10s deadline
    // 约束；未知取消只留下 durable lease pending，绝不重放 source。失败与
    // panic 一律转为进程错误，绝不静默。
    if let Some(handle) = authority_source_outcome_runtime.take() {
        if let Err(failure) = handle
            .shutdown(astral_db::authority_source_runtime::SOURCE_OUTCOME_SHUTDOWN_JOIN_TIMEOUT)
            .await
        {
            failures.push(failure);
        }
    }
    if !failures.is_empty() {
        return Err(anyhow::anyhow!(
            "identity shutdown failed: {}",
            failures.join("; ")
        ));
    }
    serve_result?;
    Ok(())
}

/// memory—v1: Assemble the Identity router with the explicitly injected
/// Identity-owned UUID session boundary. The capability is kept inside
/// `AuthService`; it is never derived from legacy state or client input.
pub fn build_router_with_memory_v1_session(
    mut state: AppState,
    identity_mapping_enabled: bool,
    memory_v1_session: Arc<memory_v1::MemoryV1IdentitySession>,
) -> Router {
    state.auth_service = Arc::new(
        state
            .auth_service
            .with_memory_v1_session_boundary(memory_v1_session),
    );
    build_router(state, identity_mapping_enabled)
}

/// Assemble the same Identity router used by the standalone runtime.
///
/// `identity_mapping_enabled` must be the startup-frozen, validated setting.
/// This does not perform listener, schema, worker, or readiness checks; a host
/// must retain those gates and supply peer `ConnectInfo<SocketAddr>` for rate
/// limiting. Constructing a router does not authorize opening a listener.
///
/// memory—v1
pub fn build_router(state: AppState, identity_mapping_enabled: bool) -> Router {
    let identity_mapping_routes = if identity_mapping_enabled {
        integration_mappings::routes()
    } else {
        Router::new()
    };

    // 将所有 /api/v1/auth 路由合并到子路由，应用权限检查中间件
    let auth_routes = Router::new()
        .merge(identity_mapping_routes)
        .merge(api::auth_routes())
        .merge(srv::users::user_routes())
        .merge(srv::cards::card_routes())
        .merge(srv::session::session_routes())
        .merge(
            // /password/forgot 的进程内 per-IP 限流：route_layer 覆盖整个
            // password 子路由，但中间件内部仅对 forgot 路径计预算
            // （reset/{token} 直通，见 password_forgot_ip_rate_limit 文档）。
            // 可用性保护而已：不产生 AuthorizationAdmission、不消费准入栅栏。
            srv::password::password_reset_routes().route_layer(
                axum::middleware::from_fn_with_state(state.clone(), password_forgot_ip_rate_limit),
            ),
        )
        .merge(srv::admin::admin_routes())
        .merge(
            // Verification 路由的进程内 per-IP 限流（Identity 直连监听器防护；
            // 语义复用共享 RateLimitCfg 合同，跨副本限制刻意保留，见
            // middleware 模块文档）。可用性保护而已：不产生
            // AuthorizationAdmission、不消费准入栅栏，bootstrap 路由的
            // admission-free 语义不变。
            srv::verification::verification_routes().route_layer(
                axum::middleware::from_fn_with_state(
                    state.clone(),
                    middleware::verification_ip_rate_limit,
                ),
            ),
        )
        .merge(srv::mfa::mfa_routes())
        .merge(srv::orgs::org_routes())
        .merge(srv::orgs::domain_routes())
        .merge(srv::orgs::tenant_routes())
        .merge(srv::me::me_routes())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::identity_permission_middleware,
        ));

    let public_routes = Router::new().nest("/api/v1/auth", auth_routes).layer(
        axum::middleware::from_fn_with_state(state.clone(), gateway_signature_middleware),
    );

    Router::new()
        .merge(public_routes)
        .layer(axum::middleware::from_fn(global_exception_handler))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

/// 初始化 MQ：连接 RabbitMQ、声明队列、创建 Producer、启动消费者
///
/// 返回 `IdentityMqProducer` 供全局注册使用。
async fn init_mq(
    rabbitmq_url: &str,
    quarantine_db: &MySqlPool,
) -> Result<(IdentityMqProducer, Arc<Connection>), String> {
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        astral_mq::consumer::init_idempotency_db(quarantine_db.clone()),
    )
    .await
    .map_err(|_| "Identity durable consumer backend timed out".to_owned())?
    .map_err(|_| "Identity durable consumer backend unavailable".to_owned())?;
    let conn = Arc::new(
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            Connection::connect(
                rabbitmq_url,
                lapin::ConnectionProperties::default().enable_auto_recover(),
            ),
        )
        .await
        .map_err(|_| "Identity Rabbit connection timed out".to_owned())?
        .map_err(|_| "Identity Rabbit connection failed".to_owned())?,
    );
    let setup = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let channel = conn
            .create_channel()
            .await
            .map_err(|_| "Identity Rabbit channel failed".to_owned())?;
        astral_mq::producer::Producer::enable_confirms(&channel)
            .await
            .map_err(|_| "Identity publisher confirms unavailable".to_owned())?;
        astral_mq::config::declare_all(&channel)
            .await
            .map_err(|_| "Identity Rabbit topology failed".to_owned())?;
        astral_mq::consumers::start_dlq_consumers(
            &channel,
            astral_mq::consumers::DlqOwner::Identity,
            Some(quarantine_db.clone()),
        )
        .await
        .map_err(|_| "Identity dead-letter consumer unavailable".to_owned())?;
        astral_mq::consumers::start_auth_session_revocation_consumer(&channel)
            .await
            .map_err(|_| "Identity revocation consumer unavailable".to_owned())?;
        astral_mq::consumers::start_login_event_consumer(&channel)
            .await
            .map_err(|_| "Identity login consumer unavailable".to_owned())?;
        tracing::info!(service = "identity", "MQ consumers started");
        Ok::<_, String>(IdentityMqProducer {
            inner: astral_mq::producer::Producer::new(channel),
        })
    })
    .await;
    match setup {
        Ok(Ok(producer)) => Ok((producer, conn)),
        outcome => {
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                conn.close(200, "identity bootstrap rejected".into()),
            )
            .await;
            match outcome {
                Ok(Err(error)) => Err(error),
                _ => Err("Identity Rabbit consumer setup timed out".into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    #[test]
    fn source_delivery_context_is_frozen_and_rejects_cross_database_routes() {
        let mut config = astral_common::config::AppConfig::default();
        assert!(super::source_delivery_context(&config).unwrap().is_none());
        config.invalidation_delivery.enabled = true;
        config.invalidation_delivery.source_database_id = "db-one".into();
        config.invalidation_delivery.roster_version = "roster-one".into();
        config.invalidation_delivery.recipients_json = serde_json::json!([{
            "regionId": "region-two",
            "nodeId": "node-two",
            "databaseId": "db-two",
            "transport": "cross_db_rabbit",
            "endpoint": null,
            "peerCertificateSha256": null
        }])
        .to_string();
        let context = super::source_delivery_context(&config).unwrap().unwrap();
        config.invalidation_delivery.roster_version = "roster-two".into();
        assert_eq!(context.roster_version(), "roster-one");
        assert_eq!(context.source_database_id(), "db-one");
        assert_eq!(context.recipients()[0].database_id, "db-two");
        config.invalidation_delivery.recipients_json = serde_json::json!([{
            "regionId": "region-two",
            "nodeId": "node-two",
            "databaseId": "db-one",
            "transport": "cross_db_rabbit",
            "endpoint": null,
            "peerCertificateSha256": null
        }])
        .to_string();
        assert!(super::source_delivery_context(&config).is_err());
        config.invalidation_delivery.recipients_json = "[]".into();
        assert!(super::source_delivery_context(&config).is_err());
    }

    #[tokio::test]
    async fn dropping_rabbit_guard_schedules_bounded_close_reaper() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct FakeClose(AtomicUsize, tokio::sync::Notify);
        #[async_trait::async_trait]
        impl super::IdentityRabbitConnectionClose for FakeClose {
            async fn close(&self, _reason: &str) -> Result<(), String> {
                self.0.fetch_add(1, Ordering::SeqCst);
                self.1.notify_one();
                Ok(())
            }
        }

        let close = Arc::new(FakeClose(AtomicUsize::new(0), tokio::sync::Notify::new()));
        let guard = super::IdentityRabbitConnectionGuard::from_owner(close.clone());
        drop(guard);
        tokio::time::timeout(std::time::Duration::from_secs(1), close.1.notified())
            .await
            .expect("early-drop close reaper must attempt close");
        assert_eq!(close.0.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn identity_rabbit_guard_reports_explicit_close_result() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct FakeClose(AtomicUsize);
        #[async_trait::async_trait]
        impl super::IdentityRabbitConnectionClose for FakeClose {
            async fn close(&self, _reason: &str) -> Result<(), String> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        let close = Arc::new(FakeClose(AtomicUsize::new(0)));
        super::IdentityRabbitConnectionGuard::from_owner(close.clone())
            .shutdown("test shutdown")
            .await
            .expect("explicit Rabbit close must succeed");
        assert_eq!(close.0.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn identity_signal_failure_cannot_be_reported_as_clean_shutdown() {
        let result =
            super::finish_after_signal_failure(Ok(()), Ok("signal registration failed".into()));
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("signal registration failed"));
    }

    #[test]
    fn identity_rabbit_guard_precedes_global_producer_and_bind_error_paths() {
        let source = include_str!("runtime.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let guard = production
            .find("rabbit_connection = Some(IdentityRabbitConnectionGuard::new(connection))")
            .expect("successful bootstrap must immediately install its close owner");
        let producer = production[guard..]
            .find("register_mq_producer(Arc::new(producer))")
            .map(|offset| guard + offset)
            .expect("global producer registration must remain");
        let bind = production[producer..]
            .find("let listener = match tokio::net::TcpListener::bind(addr).await")
            .map(|offset| producer + offset)
            .expect("HTTP bind error path must remain explicit");
        assert!(guard < producer && producer < bind);
        assert!(production.contains("spawn_identity_connection_close_reaper"));
    }

    #[test]
    fn identity_startup_failures_use_bounded_reverse_owner_cleanup() {
        let source = include_str!("runtime.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let cleanup = production
            .find("async fn shutdown_startup_owners(")
            .expect("startup failures must have one bounded cleanup helper");
        let local_tasks = production[cleanup..]
            .find("for task in local_owner_tasks")
            .map(|offset| cleanup + offset)
            .expect("local tasks must be stopped by startup cleanup");
        let rabbit = production[local_tasks..]
            .find("if let Some(connection) = rabbit_connection")
            .map(|offset| local_tasks + offset)
            .expect("Rabbit connection must be stopped after local tasks");
        let session = production[rabbit..]
            .find("session_projection_worker.shutdown_join()")
            .map(|offset| rabbit + offset)
            .expect("session worker must be stopped after transport owners");
        let authority = production[session..]
            .find(
                ".shutdown(astral_db::authority_source_runtime::SOURCE_OUTCOME_SHUTDOWN_JOIN_TIMEOUT)",
            )
            .map(|offset| session + offset)
            .expect("authority runtime must be stopped last");
        assert!(local_tasks < rabbit && rabbit < session && session < authority);
        let failure_sites = [
            "local transport requires a composite runtime-installed LocalBus",
            "QUEUE_AUTH_SESSION_REVOCATION",
            "QUEUE_LOGIN_EVENT",
            "Identity MQ bootstrap exhausted its retry budget",
            "Identity HTTP listener bind failed",
        ];
        for site in failure_sites {
            assert!(
                production.contains(site),
                "missing startup failure site: {site}"
            );
        }
        assert_eq!(
            production.matches("shutdown_startup_owners(").count(),
            6,
            "one helper definition plus five startup failure cleanup calls must remain"
        );
        assert!(production.contains("failures.join(\"; \")"));
    }

    #[test]
    fn identity_startup_error_preserves_all_cleanup_failures() {
        let error = super::identity_startup_error(
            "startup failed",
            vec!["local consumer failed".into(), "authority failed".into()],
        );
        let text = error.to_string();
        assert!(text.contains("startup failed"));
        assert!(text.contains("local consumer failed"));
        assert!(text.contains("authority failed"));
    }

    #[tokio::test]
    async fn local_consumer_cooperative_shutdown_closes_admission() {
        let bus = astral_mq::local_bus::LocalBus::new(Default::default()).unwrap();
        let receiver = bus
            .register(
                astral_mq::config::QUEUE_LOGIN_EVENT,
                astral_mq::local_bus::LocalOwner::Identity,
            )
            .unwrap();
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let handle = super::IdentityRuntimeTaskHandle::spawn(
            "local-stop-test",
            super::consume_local_until_stopped(receiver, stop_rx),
        );
        stop_tx.send(true).unwrap();
        handle
            .shutdown_join(std::time::Duration::from_secs(1))
            .await
            .expect("closed local receiver must stop cooperatively");
        assert!(!bus.owners_ready());
    }

    #[tokio::test]
    async fn cancelling_consumer_shutdown_keeps_task_ownership() {
        struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);
        impl Drop for DropSignal {
            fn drop(&mut self) {
                if let Some(signal) = self.0.take() {
                    let _ = signal.send(());
                }
            }
        }
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
        let handle = super::IdentityRuntimeTaskHandle::spawn("consumer-drop-test", async move {
            let _drop = DropSignal(Some(dropped_tx));
            let _ = ready_tx.send(());
            std::future::pending::<()>().await;
        });
        ready_rx.await.unwrap();
        {
            let mut shutdown =
                std::pin::pin!(handle.shutdown_join(std::time::Duration::from_secs(5)));
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(20), &mut shutdown)
                    .await
                    .is_err()
            );
        }
        tokio::time::timeout(std::time::Duration::from_secs(1), dropped_rx)
            .await
            .expect("cancelled shutdown must not detach the consumer")
            .expect("consumer Drop must be observed");
    }

    #[test]
    fn mq_bootstrap_tracing_never_formats_credential_sources() {
        let source = include_str!("runtime.rs");
        let bootstrap_start = source
            .find("// Inject Identity-owned durable handlers before either transport starts.")
            .expect("MQ bootstrap block must remain");
        let bootstrap_end = source[bootstrap_start..]
            .find("// 启动期注册校验")
            .map(|offset| bootstrap_start + offset)
            .expect("MQ bootstrap block must have a stable end marker");
        let init_start = source
            .find("async fn init_mq(")
            .expect("MQ initializer must remain");
        let init_end = source[init_start..]
            .find("#[cfg(test)]")
            .map(|offset| init_start + offset)
            .expect("MQ initializer must have a stable end marker");
        let blocks = [
            &source[bootstrap_start..bootstrap_end],
            &source[init_start..init_end],
        ];
        let mut calls = Vec::new();
        for block in blocks {
            let mut offset = 0;
            while let Some(relative_start) = block[offset..].find("tracing::") {
                let call_start = offset + relative_start;
                let call_end = call_start
                    + block[call_start..]
                        .find(';')
                        .expect("tracing invocation must end with a semicolon")
                    + 1;
                calls.push(&block[call_start..call_end]);
                offset = call_end;
            }
        }
        assert_eq!(calls.len(), 3, "review every Identity MQ tracing call");
        for call in calls {
            for forbidden in [
                "rabbitmq_url",
                "mq_url",
                "error =",
                "%error",
                "?error",
                "%e",
                "?e",
                "{error",
                "{e",
                ".to_string()",
                "format!(",
            ] {
                assert!(
                    !call.contains(forbidden),
                    "Identity MQ tracing must not format credential sources: {call}"
                );
            }
        }
        assert!(blocks[0].contains("Producer::new_local"));
        assert!(!blocks[0].contains("init_idempotency_redis"));
    }

    fn forgot_rate_limit_test_state() -> super::AppState {
        use super::{
            AppConfig, AppState, AuthService, MeService, OrgService, PolicyEngine,
            SqlxAuthRepository, SqlxCardRepository, SqlxMeRepository, SqlxOrgRepository,
            SqlxUserRepository, UserService,
        };

        let db = sqlx::MySqlPool::connect_lazy("mysql://localhost:1/astral_test")
            .expect("lazy test pool must construct without connecting");
        AppState {
            config: Arc::new(AppConfig {
                rate_limit: astral_common::config::RateLimitCfg {
                    enabled: true,
                    requests_per_second: 1,
                    burst_size: 0,
                },
                gateway: astral_common::config::GatewayCfg {
                    hmac_secret: "test-forgot-gateway-secret-0123456789abcdef".into(),
                    ..Default::default()
                },
                ..Default::default()
            }),
            db: db.clone(),
            engine: Arc::new(PolicyEngine::new()),
            me_service: Arc::new(MeService::new(Arc::new(SqlxMeRepository::new(db.clone())))),
            auth_service: Arc::new(AuthService::new(Arc::new(SqlxAuthRepository::new(
                db.clone(),
            )))),
            user_service: Arc::new(UserService::new(
                Arc::new(SqlxUserRepository::new(db.clone())),
                Arc::new(SqlxAuthRepository::new(db.clone())),
            )),
            card_repository: Arc::new(SqlxCardRepository::new(db.clone())),
            org_service: Arc::new(OrgService::new(Arc::new(SqlxOrgRepository::new(
                db.clone(),
            )))),
            password_reset_notifier: Arc::new(
                super::srv::password::UnavailablePasswordResetNotifier,
            ),
            authorization_fence_provider: None,
            org_scope_enabled: false,
        }
    }

    /// memory—v1
    #[tokio::test]
    async fn assembled_router_rejects_unverified_gateway_requests() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        for identity_mapping_enabled in [false, true] {
            let app = super::build_router(forgot_rate_limit_test_state(), identity_mapping_enabled);
            for path in [
                "/api/v1/auth/password/forgot",
                "/api/v1/auth/verification/send",
            ] {
                let response = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri(path)
                            .header("x-gateway-auth", "verified")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
            }
        }
    }

    /// memory—v1
    #[test]
    fn standalone_uses_complete_router_before_listener() {
        let source = include_str!("runtime.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let caller = production
            .find("let app = build_router(state, identity_mapping_enabled);")
            .expect("standalone runtime must use the reusable router");
        let listener = production[caller..]
            .find("let listener = match tokio::net::TcpListener::bind(addr).await")
            .expect("listener must remain after router assembly");
        assert!(listener > 0);
        let router = production
            .split("pub fn build_router(")
            .nth(1)
            .expect("router constructor must remain in production source")
            .split("/// 初始化 MQ")
            .next()
            .unwrap();
        let layers = [
            "password_reset_routes().route_layer(",
            "verification_routes().route_layer(",
            "middleware::identity_permission_middleware",
            "gateway_signature_middleware",
            "global_exception_handler",
            "TraceLayer::new_for_http()",
            ".with_state(state)",
        ];
        let mut remaining = router;
        for layer in layers {
            let position = remaining.find(layer).expect(layer);
            remaining = &remaining[position + layer.len()..];
        }
        assert!(router.contains("if identity_mapping_enabled"));
        assert!(router.contains(".merge(identity_mapping_routes)"));
        assert!(router.contains(".nest(\"/api/v1/auth\", auth_routes)"));
    }

    /// 路由层行为测试：/password/forgot 消耗 per-IP 预算（耗尽后 429 共享有界
    /// 形状），/password/reset/{token} 不消耗也不受 forgot 预算影响（直通）。
    /// handler 侧响应（503/422/500）由 DB/notifier 部署决定，断言只钉 429 语义。
    #[tokio::test]
    async fn forgot_route_consumes_per_ip_budget_while_reset_passes_through() {
        use super::{password_forgot_ip_rate_limit, srv, Router};
        use axum::body::Body;
        use axum::extract::ConnectInfo;
        use axum::http::{Request, StatusCode};
        use std::net::SocketAddr;
        use tower::ServiceExt;

        let state = forgot_rate_limit_test_state();
        let app = Router::new()
            .merge(srv::password::password_reset_routes().route_layer(
                axum::middleware::from_fn_with_state(state.clone(), password_forgot_ip_rate_limit),
            ))
            .with_state(state);

        let peer = SocketAddr::from(([10, 0, 0, 1], 40_000));
        let send = |app: Router, path: &'static str| {
            app.oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("content-type", "application/json")
                    .header("x-operation-id", "forgot-test-20261108")
                    .extension(ConnectInfo(peer))
                    .body(Body::from(r#"{"email":"alice@example.com"}"#))
                    .unwrap(),
            )
        };

        // 预算内：穿过限流层到达 handler（未配置投递 → 统一 503 合同），绝不 429。
        let first = send(app.clone(), "/password/forgot").await.unwrap();
        assert_ne!(
            first.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "the first forgot request must pass the per-IP limiter"
        );
        assert_eq!(
            first.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "unconfigured notifier must keep the unified 503 contract before account lookup"
        );
        // 预算耗尽（cap = rps+burst = 1）：同窗口第二笔 forgot 被限流拒绝。
        let second = send(app.clone(), "/password/forgot").await.unwrap();
        assert_eq!(
            second.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "forgot requests beyond the per-IP budget must be rejected with the shared 429 shape"
        );
        // reset/{token} 直通：不消耗 forgot 预算，也不被耗尽的 forgot 预算拒绝。
        let reset = send(app, "/password/reset/some-token").await.unwrap();
        assert_ne!(
            reset.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "reset token route must not ride the forgot per-IP budget"
        );
    }

    /// 装配形状守卫：forgot 限流必须挂 route_layer 在 password 子路由上并先于
    /// 权限中间件 layer；语义必须复用共享 ip_rate_limit 实现（同
    /// verification/Gateway 合同），本文件不得重新实现桶计数；作用域收窄到
    /// forgot 路径；限流 admission-free；直连监听器注入对端地址扩展。
    #[test]
    fn forgot_ip_limit_wiring_contract() {
        let source = include_str!("runtime.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        let wiring = production
            .find("password_reset_routes().route_layer(")
            .expect("the runtime must wire the forgot limiter via route_layer");
        let permission_layer = production[wiring..]
            .find("identity_permission_middleware")
            .map(|offset| wiring + offset)
            .expect("auth routes must keep the permission middleware layer");
        let limiter_ref = production[wiring..]
            .find("password_forgot_ip_rate_limit")
            .map(|offset| wiring + offset)
            .expect("the forgot subrouter must be wired to password_forgot_ip_rate_limit");
        assert!(limiter_ref < permission_layer);
        assert!(
            production.contains("IpRateLimiter::new(state.config.rate_limit.clone())"),
            "the forgot limiter must reuse the frozen shared RateLimitCfg"
        );
        assert!(
            production
                .contains("TrustedProxySet::compile(&state.config.gateway.trusted_proxy_ips)"),
            "the forgot limiter must reuse the trusted proxy contract"
        );
        assert!(
            production.contains("resolve_client_ip(req.headers(), peer, &shared.trusted)"),
            "client resolution must come from the shared implementation"
        );
        assert!(
            production.contains("rate_limit_response(&req, \"password-forgot-rate-limit-error\")"),
            "rejected requests must use the shared bounded 429 shape"
        );
        assert!(
            !production.contains("buckets.lock()"),
            "the runtime must not re-implement bucket counting (shared IpRateLimiter owns it)"
        );
        assert!(
            production.contains("ends_with(\"/password/forgot\")"),
            "only the forgot path may consume the budget; the reset token route passes through"
        );
        let limiter_start = production
            .find("pub(crate) async fn password_forgot_ip_rate_limit(")
            .expect("the forgot limiter entry point must remain");
        let limiter_end = production[limiter_start..]
            .find("pub async fn run()")
            .map(|offset| limiter_start + offset)
            .expect("the limiter must be bounded by the run entry");
        assert!(
            !production[limiter_start..limiter_end].contains("AuthorizationAdmission"),
            "the forgot limiter is availability protection only and must stay admission-free"
        );
        assert!(
            production.contains("into_make_service_with_connect_info::<std::net::SocketAddr>()"),
            "the direct listener must provide ConnectInfo so the limiter can resolve the peer address"
        );
    }
}
