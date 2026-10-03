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
    {
        // Death observability: a terminal state of the required recovery leg
        // (panic / unexpected exit / cooperative stop) is surfaced loudly.
        let mut death = session_projection_worker.death_signal();
        tokio::spawn(async move {
            while death.changed().await.is_ok() {
                if let Some(reason) = death.borrow().clone() {
                    tracing::error!(
                        reason = %reason,
                        "auth session recovery worker reached a terminal state \
                         (required recovery leg)"
                    );
                }
            }
        });
    }

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
        let mut revocation_receiver = bus
            .register(
                astral_mq::config::QUEUE_AUTH_SESSION_REVOCATION,
                astral_mq::local_bus::LocalOwner::Identity,
            )
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let mut login_receiver = bus
            .register(
                astral_mq::config::QUEUE_LOGIN_EVENT,
                astral_mq::local_bus::LocalOwner::Identity,
            )
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let revocation_consumer =
            IdentityRuntimeTaskHandle::spawn("identity-local-revocation-consumer", async move {
                while let Some(delivery) = revocation_receiver.recv().await {
                    let result = astral_mq::consumers::dispatch_local_delivery(&delivery).await;
                    delivery.complete(result);
                }
            });
        let login_consumer =
            IdentityRuntimeTaskHandle::spawn("identity-local-login-consumer", async move {
                while let Some(delivery) = login_receiver.recv().await {
                    let result = astral_mq::consumers::dispatch_local_delivery(&delivery).await;
                    delivery.complete(result);
                }
            });
        local_owner_tasks.push(revocation_consumer);
        local_owner_tasks.push(login_consumer);
        let producer =
            astral_mq::producer::Producer::new_local(bus, state.config.region_id.clone());
        register_mq_producer(Arc::new(IdentityMqProducer { inner: producer }));
    } else {
        let mq_url = state.config.rabbitmq_url.clone();
        let dlq_quarantine_db = db.clone();
        tokio::spawn(async move {
            let mut attempt: u32 = 0;
            loop {
                let producer = init_mq(&mq_url, &dlq_quarantine_db).await.ok();
                if let Some(producer) = producer {
                    register_mq_producer(Arc::new(producer));
                    tracing::info!(
                        service = "identity",
                        transport = "rabbit",
                        "MQ producer registered"
                    );
                    break;
                }
                attempt = attempt.saturating_add(1);
                let backoff_secs = 2u64.pow(attempt.min(5));
                tracing::warn!(
                    service = "identity",
                    attempt,
                    backoff_secs,
                    "MQ initialization failed, retrying with backoff"
                );
                tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
            }
        });
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
    // Required recovery-worker death stops serving before owned tasks close.
    let mut session_death = session_projection_worker.death_signal();
    let mut serve = std::pin::pin!(axum::serve(listener, app).into_future());
    let serve_result = tokio::select! {
        result = &mut serve => result
            .map_err(|error| anyhow::anyhow!("identity service serve failed: {error}")),
        reason = wait_required_worker_death(&mut session_death) => {
            tracing::error!(
                reason = %reason,
                "required session recovery worker reached a terminal state; failing the \
                 identity runtime (sticky required-owner failure, no half-served state)"
            );
            if let Some(hub) = astral_db::memory_projection_hub() {
                hub.mark_runtime_owner_failed(format!(
                    "code=identity.required_worker_death;reason={reason}"
                ));
            }
            Err(anyhow::anyhow!(
                "required session recovery worker death stopped the identity runtime: {reason}"
            ))
        }
    };
    for task in local_owner_tasks {
        if let Err(failure) = task.shutdown_join(std::time::Duration::from_secs(5)).await {
            tracing::warn!(failure = %failure, "identity runtime task did not stop cleanly");
        }
    }
    if let Err(failure) = session_projection_worker.shutdown_join().await {
        tracing::warn!(
            failure = %failure,
            "auth session recovery worker did not stop cleanly"
        );
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
) -> Result<IdentityMqProducer, Box<dyn std::error::Error>> {
    // MQ 消费者幂等走 durable MySQL lease（mq_consumer_lease，缺表启动即
    // 失败 fail-closed）；Redis 仅为显式兼容 adapter，不承载幂等。
    astral_mq::consumer::init_idempotency_db(quarantine_db.clone()).await?;
    let conn = Connection::connect(
        rabbitmq_url,
        lapin::ConnectionProperties::default().enable_auto_recover(),
    )
    .await?;
    let channel = conn.create_channel().await?;
    astral_mq::producer::Producer::enable_confirms(&channel).await?;
    astral_mq::config::declare_all(&channel).await?;

    // 创建 Producer
    let producer = astral_mq::producer::Producer::new(channel.clone());

    // 启动消费者：Identity 独占会话撤销与登录事件，不消费 audit.log。
    // DLQ 消费者先于业务消费者启动，保证死信消息可被重投/告警闭环。
    astral_mq::consumers::start_dlq_consumers(
        &channel,
        astral_mq::consumers::DlqOwner::Identity,
        Some(quarantine_db.clone()),
    )
    .await?;
    astral_mq::consumers::start_auth_session_revocation_consumer(&channel).await?;
    astral_mq::consumers::start_login_event_consumer(&channel).await?;
    let started = Vec::<String>::new();
    tracing::info!(service = "identity", "MQ consumers started: {:?}", started);

    // 保持连接存活
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        }
    });

    Ok(IdentityMqProducer { inner: producer })
}

#[cfg(test)]
mod tests {
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
