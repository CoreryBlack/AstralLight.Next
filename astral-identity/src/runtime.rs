// AstralLight 身份认证服务
//
// 对应 Java `AstralIdentity` 模块。
// 职责：用户注册、密码验证、JWT 签发。

#[path = "api.rs"]
pub mod api;
#[path = "auth.rs"]
pub mod auth;
#[path = "middleware.rs"]
pub mod middleware;
#[path = "srv/mod.rs"]
pub mod srv;

use std::future::IntoFuture;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::FromRef;
use axum::Router;
use lapin::Connection;
use policy_engine::PolicyEngine;
#[cfg(feature = "redis-compat")]
use redis::aio::ConnectionManager;
use sqlx::MySqlPool;

use astral_common::audit::{register_audit_db_writer, AuditDbWriter, AuditEntry};
use astral_common::config::{AppConfig, JwtValidationRole};
use astral_common::error::global_exception_handler;
use astral_common::middleware::gateway_signature::gateway_signature_middleware;
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
    /// Redis adapter is available only with the explicit compatibility feature.
    #[cfg(feature = "redis-compat")]
    pub redis: Option<ConnectionManager>,
    pub engine: Arc<PolicyEngine>,
    pub me_service: Arc<MeService>,
    pub auth_service: Arc<AuthService>,
    pub user_service: Arc<UserService>,
    pub card_repository: Arc<dyn srv::card_repository::CardRepository>,
    pub org_service: Arc<OrgService>,
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
            // UUID 幂等键：防 audit consumer 派生键重复 → INSERT IGNORE 丢审计行
            message_id: Some(uuid::Uuid::new_v4().to_string()),
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
            // UUID 幂等键：防 login.event consumer 无幂等时 DLX 重投重复审计行
            message_id: Some(uuid::Uuid::new_v4().to_string()),
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
    let config = Arc::new(AppConfig::from_files_for(
        "application",
        JwtValidationRole::Identity,
    )?);
    config.validate_identity_session_grant_compatibility()?;
    // Redis 编译层退役收口（redis-layer-retirement-20261002）：宿主能力门 +
    // 已校验旗标一次性冻结。astral-common 的零依赖 marker 会被 workspace
    // feature 统一放大——任何其他 crate 打开 redis-compat 都会让集中校验的
    // cfg 通过，即便本宿主并未编译自己的 compat adapter。能力断言以**本
    // crate** 的 cfg! 为准：旗标开启但 adapter 未编译时，在任何 DB 连接 /
    // 服务装配之前显式拒绝启动（fail-closed，非 log-only）；随后把已校验
    // 旗标冻结进进程级共享源（first-wins、同值幂等、异值冲突拒绝）。
    // canonical origin 安装点与下方 cfg adapter 装配保持不变。
    config
        .validate_redis_adapter_support(cfg!(feature = "redis-compat"))
        .map_err(anyhow::Error::msg)?;
    astral_common::config::install_redis_projection_compat(config.redis_projection_compat_enabled)
        .map_err(anyhow::Error::msg)?;
    // 进程级 origin region 唯一安装点：配置校验后、DB/worker/router 装配前
    // 安装一次。durable invalidation intent 在未安装时拒绝 append（fail-closed），
    // 因此必须在任何可能触发租户资格变更的路径之前完成。
    srv::org_repository::install_origin_region(config.region_id.clone())
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let db = connect_and_validate_schema(&config.database_url).await?;
    // Redis 兼容 adapter（default-off）：仅当显式开启 compat 旗标时连接
    // （失败即启动失败，显式配置的 adapter 不允许静默降级）；默认 Redis-free
    // 路径完全不连接 Redis，登录/refresh/switch 以 MySQL durable proof 为准。
    // 仅 redis-compat feature 编译；feature-off + 旗标开启由 astral-common
    // 启动期集中校验拒绝（RedisCompatRequiresFeatureBuild，fail-closed）。
    #[cfg(feature = "redis-compat")]
    let redis = match config.redis_projection_compat_enabled {
        true => {
            let redis_client = redis::Client::open(config.redis_url.as_str())?;
            let redis_config = redis::aio::ConnectionManagerConfig::new()
                .set_connection_timeout(Some(std::time::Duration::from_secs(1)))
                .set_response_timeout(Some(std::time::Duration::from_millis(500)))
                .set_number_of_retries(0);
            let connection = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                ConnectionManager::new_with_config(redis_client, redis_config),
            )
            .await
            .map_err(|_| anyhow::anyhow!("Redis connection timed out"))??;
            tracing::info!("redis projection compat adapter enabled");
            Some(connection)
        }
        false => {
            tracing::info!(
                transport = "mysql",
                "redis projection disabled; session auth uses strict MySQL durable facts"
            );
            None
        }
    };
    let engine = Arc::new(PolicyEngine::new());
    register_audit_db_writer(Arc::new(IdentityAuditDbWriter { pool: db.clone() }));
    let me_service = Arc::new(MeService::new(Arc::new(SqlxMeRepository::new(db.clone()))));
    let auth_repository = Arc::new(SqlxAuthRepository::new(db.clone()));
    let auth_service = Arc::new(AuthService::new(auth_repository.clone()));
    let user_service = Arc::new(UserService::new(
        Arc::new(SqlxUserRepository::new(db.clone())),
        auth_repository,
    ));
    let card_repository: Arc<dyn srv::card_repository::CardRepository> =
        Arc::new(SqlxCardRepository::new(db.clone()));
    let org_service = Arc::new(OrgService::new(Arc::new(SqlxOrgRepository::new(
        db.clone(),
    ))));
    // ORG_SCOPE 旗标已在配置加载处一次性解析并冻结（非法值启动即失败）；
    // 这里只复制冻结值，不再读取 env。default-off：未配置时保持 false。
    let org_scope_enabled = config.org_scope_enabled;
    let state = AppState {
        config,
        db: db.clone(),
        #[cfg(feature = "redis-compat")]
        redis: redis.clone(),
        engine,
        me_service,
        auth_service,
        user_service,
        card_repository,
        org_service,
        org_scope_enabled,
    };

    // Every Identity replica runs the same leased recovery loop. MySQL owns
    // coordination and is the authority; Redis (when the compat adapter is
    // explicitly enabled) remains an idempotent projection store.
    //
    // worker-supervision-20261002: the required recovery leg runs on the
    // OWNED handle flavor — RAII (Drop aborts the supervisor), bounded
    // shutdown, and an observable death signal. Startup gates above are
    // unchanged.
    #[cfg(feature = "redis-compat")]
    let session_projection_worker =
        srv::session_projection_worker::spawn_owned(db.clone(), redis.clone());
    #[cfg(not(feature = "redis-compat"))]
    let session_projection_worker =
        srv::session_projection_worker::spawn_without_redis_owned(db.clone());

    // Inject Identity-owned durable handlers before either transport starts.
    astral_mq::consumers::set_session_revocation_db(db.clone());
    #[cfg(feature = "redis-compat")]
    if let Some(redis) = redis.clone() {
        astral_mq::consumers::set_session_revocation_redis(redis);
    }
    astral_mq::consumers::set_login_event_db(db.clone());
    // worker-supervision-20261002: RAII handles for the local owner consumer
    // loops; declared at function scope so they live until the serve tail and
    // receive a bounded shutdown on every exit path.
    let mut local_owner_tasks: Vec<IdentityRuntimeTaskHandle> = Vec::new();
    let mut rabbit_connection: Option<IdentityRabbitConnectionGuard> = None;
    let (local_stop_tx, local_stop_rx) = tokio::sync::watch::channel(false);
    if matches!(
        state
            .config
            .message_transport()
            .map_err(anyhow::Error::msg)?,
        astral_common::config::MessageTransport::Local
    ) {
        let bus = astral_mq::local_bus::global_local_bus().ok_or_else(|| {
            anyhow::anyhow!("local transport requires a composite runtime-installed LocalBus")
        })?;
        // worker-supervision-20261002: the local owner consumer loops are
        // RAII-owned (Drop abort; bounded shutdown at serve end) instead of
        // detached fire-and-forget — identical dispatch/complete semantics.
        let revocation_receiver = bus
            .register(
                astral_mq::config::QUEUE_AUTH_SESSION_REVOCATION,
                astral_mq::local_bus::LocalOwner::Identity,
            )
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let login_receiver = bus
            .register(
                astral_mq::config::QUEUE_LOGIN_EVENT,
                astral_mq::local_bus::LocalOwner::Identity,
            )
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
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
            return Err(anyhow::anyhow!(
                "Identity MQ bootstrap exhausted its retry budget"
            ));
        }
    }

    // 启动期注册校验（对齐 Java @PostConstruct 校验）
    astral_common::middleware::permission_check_shared::validate_path_map(
        middleware::IDENTITY_PATH_MAP,
        "identity",
    );

    let internal_routes = Router::new().merge(srv::internal::internal_routes());

    // 将所有 /api/v1/auth 路由合并到子路由，应用权限检查中间件
    let auth_routes = Router::new()
        .merge(api::auth_routes())
        .merge(srv::users::user_routes())
        .merge(srv::cards::card_routes())
        .merge(srv::session::session_routes())
        .merge(srv::password::password_reset_routes())
        .merge(srv::admin::admin_routes())
        .merge(srv::verification::verification_routes())
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

    let app = Router::new()
        .merge(public_routes)
        .merge(internal_routes)
        .layer(axum::middleware::from_fn(global_exception_handler))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state);

    tracing::info!(addr = %addr, "identity service starting");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    // Required recovery-worker death closes admission before draining HTTP tasks.
    let mut session_death = session_projection_worker.death_signal();
    let (serve_stop_tx, serve_stop_rx) = tokio::sync::oneshot::channel();
    let (drain_started_tx, mut drain_started_rx) = tokio::sync::oneshot::channel();
    let mut serve = std::pin::pin!(axum::serve(listener, app)
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
    };
    let worker_result = session_projection_worker.shutdown_join().await;
    // ORG events may have a frozen deadline of almost one hour on the peer.
    let barrier_result =
        tokio::time::timeout(std::time::Duration::from_secs(4_200), producers_drained).await;
    if barrier_result.is_err() {
        return Err(anyhow::anyhow!(
            "Identity producer drain barrier timed out; outcome unknown"
        ));
    }
    let audit_result =
        astral_common::audit::drain_owned_audit_tasks(std::time::Duration::from_secs(5)).await;
    let _ = local_stop_tx.send(true);
    let mut failures = Vec::new();
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
    if !failures.is_empty() {
        return Err(anyhow::anyhow!(
            "identity shutdown failed: {}",
            failures.join("; ")
        ));
    }
    serve_result?;
    Ok(())
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
        let guard = source
            .find("rabbit_connection = Some(IdentityRabbitConnectionGuard::new(connection))")
            .expect("successful bootstrap must immediately install its close owner");
        let producer = source[guard..]
            .find("register_mq_producer(Arc::new(producer))")
            .map(|offset| guard + offset)
            .expect("global producer registration must remain");
        let bind = source[producer..]
            .find("TcpListener::bind(addr).await?")
            .map(|offset| producer + offset)
            .expect("HTTP bind error path must remain");
        assert!(guard < producer && producer < bind);
        assert!(source.contains("spawn_identity_connection_close_reaper"));
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
}
