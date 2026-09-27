//! AstralLight 身份认证服务
//!
//! 对应 Java `AstralIdentity` 模块。
//! 职责：用户注册、密码验证、JWT 签发。

pub mod api;
pub mod auth;
pub mod middleware;
pub mod srv;

use std::sync::Arc;

use axum::extract::FromRef;
use axum::Router;
use lapin::Connection;
use policy_engine::PolicyEngine;
use redis::aio::ConnectionManager;
use sqlx::MySqlPool;

use astral_common::audit::{register_audit_db_writer, AuditDbWriter, AuditEntry};
use astral_common::config::{AppConfig, JwtValidationRole};
use astral_common::error::global_exception_handler;
use astral_common::middleware::gateway_signature::gateway_signature_middleware;
use astral_common::service::{register_mq_producer, AuditLogEvent, MqProducerRef};
use astral_common::tracing::init_tracing;
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

/// 应用共享状态
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub db: MySqlPool,
    pub redis: ConnectionManager,
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let config = Arc::new(AppConfig::from_files_for(
        "application",
        JwtValidationRole::Identity,
    )?);
    config.validate_identity_session_grant_compatibility()?;
    let db = connect_and_validate_schema(&config.database_url).await?;
    let redis_client = redis::Client::open(config.redis_url.as_str())?;
    let redis_config = redis::aio::ConnectionManagerConfig::new()
        .set_connection_timeout(Some(std::time::Duration::from_secs(1)))
        .set_response_timeout(Some(std::time::Duration::from_millis(500)))
        .set_number_of_retries(0);
    let redis = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        ConnectionManager::new_with_config(redis_client, redis_config),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Redis connection timed out"))??;
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
    // coordination; Redis remains an idempotent projection store.
    srv::session_projection_worker::spawn(db.clone(), redis.clone());

    // MQ 初始化：连接 RabbitMQ、注册 Producer、启动消费者（后台退避重试，避免
    // 启动时 RabbitMQ 暂不可用导致 producer 永久缺失；审计双写失败走 DB fallback 兜底）
    let mq_url = state.config.rabbitmq_url.clone();
    let redis_url = state.config.redis_url.clone();
    let dlq_quarantine_db = db.clone();
    // 注入 auth.session.revocation consumer 的 DB pool（TrustGraph GlobalAdmin
    // 生命周期等跨服务撤销命令由 identity 消费执行）
    astral_mq::consumers::set_session_revocation_db(db.clone());
    // 注入 login.event consumer 的 DB pool（登录事件写 audit_log）
    astral_mq::consumers::set_login_event_db(db.clone());
    tokio::spawn(async move {
        let mut attempt: u32 = 0;
        loop {
            let producer = init_mq(&mq_url, &redis_url, &dlq_quarantine_db).await.ok();
            if let Some(producer) = producer {
                register_mq_producer(Arc::new(producer));
                tracing::info!(service = "identity", "MQ producer registered");
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

    // 监听地址支持 env 覆盖（与其余服务一致）；默认 9004。
    let addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:9004".to_string());
    tracing::info!(addr = %addr, "identity service starting");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// 初始化 MQ：连接 RabbitMQ、声明队列、创建 Producer、启动消费者
///
/// 返回 `IdentityMqProducer` 供全局注册使用。
async fn init_mq(
    rabbitmq_url: &str,
    redis_url: &str,
    quarantine_db: &MySqlPool,
) -> Result<IdentityMqProducer, Box<dyn std::error::Error>> {
    astral_mq::consumer::init_idempotency_redis(redis_url).await?;
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
    #[test]
    fn mq_bootstrap_tracing_never_formats_credential_sources() {
        let source = include_str!("main.rs");
        let bootstrap_start = source
            .find("// MQ 初始化：连接 RabbitMQ")
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
        assert!(blocks[0].contains(".await.ok();"));
    }
}
