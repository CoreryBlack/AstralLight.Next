//! AstralChat 启动入口
//! ```bash
//! cargo run -p astral-chat
//! # LISTEN_ADDR=0.0.0.0:9003 cargo run -p astral-chat
//! ```

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::Router;
use lapin::Connection;
use policy_engine::PolicyEngine;

use astral_common::audit::{register_audit_db_writer, AuditDbWriter, AuditEntry};
use astral_common::config::AppConfig;
use astral_common::error::global_exception_handler;
use astral_common::middleware::gateway_signature::gateway_signature_middleware;
use astral_common::service::{register_mq_producer, AuditLogEvent, MqProducerRef};
use astral_common::tracing::init_tracing;
use astral_db::connect_and_validate_schema;
use astral_mq::producer::Producer;

use astral_chat::repository::client_session_repository::SqlxClientSessionRepository;
use astral_chat::repository::conversation_repository::SqlxConversationRepository;
use astral_chat::repository::member_repository::SqlxMemberRepository;
use astral_chat::repository::message_repository::SqlxMessageRepository;
use astral_chat::service::group_service::GroupService;
use astral_chat::service::message_service::MessageService;
use astral_chat::service::receipt_service::ReceiptService;
use astral_chat::service::send_intent_relay;
use astral_chat::service::session_service::SessionService;
use astral_chat::srv;
use astral_chat::srv::realtime::ConnectionPool;
use astral_chat::AppState;

mod middleware;

struct ChatAuditDbWriter {
    pool: sqlx::MySqlPool,
}

#[async_trait::async_trait]
impl AuditDbWriter for ChatAuditDbWriter {
    async fn insert_audit(&self, entry: &AuditEntry) -> Result<(), String> {
        astral_db::insert_audit_log(&self.pool, entry)
            .await
            .map_err(|e| e.to_string())
    }
}

struct ChatMqProducer {
    inner: Producer,
}

#[async_trait::async_trait]
impl MqProducerRef for ChatMqProducer {
    async fn publish_audit_log(&self, event: AuditLogEvent) -> Result<(), String> {
        self.inner
            .publish_audit_log(astral_mq::producer::AuditLogPayload {
                // message_id 必须唯一：audit consumer 以它为 mq_idempotent_log 幂等键，
                // 恒 None 会回退到派生键，permission 审计 request_id 恒 None，
                // 相同 user+resource+action 的重复判定会被 INSERT IGNORE 静默丢弃。
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
            })
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
        self.inner
            .publish_login_event(astral_mq::producer::LoginEventPayload {
                message_id: Some(uuid::Uuid::new_v4().to_string()),
                user_id,
                card_id: None,
                login_type: login_type.to_string(),
                ip_address: ip_address.map(str::to_string),
                user_agent: user_agent.map(str::to_string),
                success,
            })
            .await
            .map_err(|e| e.to_string())
    }
}

const STARTUP_SCHEMA_DEADLINE: Duration = Duration::from_secs(10);
const MQ_INITIALIZATION_DEADLINE: Duration = Duration::from_secs(10);
const HTTP_DRAIN_DEADLINE: Duration = Duration::from_secs(30);
const RELAY_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(10);
const AUDIT_DRAIN_DEADLINE: Duration = Duration::from_secs(3);
const RABBIT_CLOSE_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
struct RabbitConnectionCloseError(&'static str);

#[async_trait::async_trait]
trait RabbitConnectionClose: Send + Sync {
    async fn close(&self, reason: &'static str) -> Result<(), RabbitConnectionCloseError>;
}

struct LapinChatRabbitConnection(Arc<Connection>);

#[async_trait::async_trait]
impl RabbitConnectionClose for LapinChatRabbitConnection {
    async fn close(&self, reason: &'static str) -> Result<(), RabbitConnectionCloseError> {
        self.0
            .close(200, reason.into())
            .await
            .map_err(|_| RabbitConnectionCloseError("RabbitMQ close failed"))
    }
}

/// Retains a Rabbit connection until an explicit close is confirmed.
struct RabbitConnectionOwner {
    connection: Option<Arc<dyn RabbitConnectionClose>>,
}

impl RabbitConnectionOwner {
    fn new(connection: Arc<dyn RabbitConnectionClose>) -> Self {
        Self {
            connection: Some(connection),
        }
    }

    async fn close_with_deadline(
        &mut self,
        reason: &'static str,
        deadline: Duration,
    ) -> Result<(), RabbitConnectionCloseError> {
        let Some(connection) = self.connection.as_ref().cloned() else {
            return Ok(());
        };
        match tokio::time::timeout(deadline, connection.close(reason)).await {
            Ok(Ok(())) => {
                drop(self.connection.take());
                Ok(())
            }
            Ok(Err(error)) => Err(error),
            Err(_) => Err(RabbitConnectionCloseError(
                "RabbitMQ close deadline elapsed",
            )),
        }
    }

    async fn close(&mut self, reason: &'static str) -> Result<(), RabbitConnectionCloseError> {
        self.close_with_deadline(reason, RABBIT_CLOSE_DEADLINE)
            .await
    }
}

impl Drop for RabbitConnectionOwner {
    fn drop(&mut self) {
        let Some(connection) = self.connection.take() else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            tracing::error!(
                "Rabbit connection owner dropped without an active runtime; close outcome unknown"
            );
            return;
        };
        runtime.spawn(async move {
            match tokio::time::timeout(
                RABBIT_CLOSE_DEADLINE,
                connection.close("Chat Rabbit connection owner dropped"),
            )
            .await
            {
                Ok(Ok(())) => tracing::debug!("Chat Rabbit connection reaped after owner drop"),
                Ok(Err(error)) => tracing::error!(
                    reason = error.0,
                    "Chat Rabbit connection drop reaper failed"
                ),
                Err(_) => tracing::error!(
                    "Chat Rabbit connection drop reaper timed out; close outcome unknown"
                ),
            }
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MqInitializationError(&'static str);

async fn close_rabbit_owner(
    owner: &mut Option<RabbitConnectionOwner>,
    reason: &'static str,
) -> Result<(), RabbitConnectionCloseError> {
    let result = match owner.as_mut() {
        Some(connection) => connection.close(reason).await,
        None => Ok(()),
    };
    if result.is_ok() {
        owner.take();
    }
    result
}

fn parse_listen_addr(value: Option<&str>) -> anyhow::Result<SocketAddr> {
    value
        .unwrap_or("0.0.0.0:9003")
        .parse()
        .map_err(|_| anyhow::anyhow!("LISTEN_ADDR must be a valid socket address"))
}

fn listen_addr_from_env() -> anyhow::Result<SocketAddr> {
    match std::env::var("LISTEN_ADDR") {
        Ok(value) => parse_listen_addr(Some(&value)),
        Err(std::env::VarError::NotPresent) => parse_listen_addr(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("LISTEN_ADDR must be valid UTF-8")
        }
    }
}

#[derive(Default)]
struct ServeShutdownReport {
    signal_error: Option<String>,
    serve_error: Option<String>,
    relay_death: Option<String>,
    http_drain_timed_out: bool,
    socket_drain_error: Option<String>,
    server_returned_before_shutdown: bool,
}

async fn serve_until_shutdown(
    listener: tokio::net::TcpListener,
    app: Router,
    mut relay_death: tokio::sync::watch::Receiver<Option<String>>,
    connections: Arc<ConnectionPool>,
) -> ServeShutdownReport {
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let mut server = Box::pin(std::future::IntoFuture::into_future(
        axum::serve(listener, app).with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        }),
    ));
    let initial_relay_death = relay_death.borrow().clone();
    let trigger = if let Some(reason) = initial_relay_death {
        ShutdownTrigger::RelayDeath(reason)
    } else {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => ShutdownTrigger::Signal(signal),
            changed = relay_death.changed() => {
                let reason = relay_death.borrow().clone().unwrap_or_else(|| {
                    if changed.is_err() {
                        "Chat send-intent relay death watch closed without a terminal reason".to_owned()
                    } else {
                        "Chat send-intent relay reported death without a terminal reason".to_owned()
                    }
                });
                ShutdownTrigger::RelayDeath(reason)
            }
            result = &mut server => ShutdownTrigger::ServerExit(result),
        }
    };

    let mut report = ServeShutdownReport::default();
    let drain_http = match trigger {
        ShutdownTrigger::Signal(Ok(())) => true,
        ShutdownTrigger::Signal(Err(error)) => {
            report.signal_error = Some(format!("Ctrl-C signal failed: {error}"));
            true
        }
        ShutdownTrigger::RelayDeath(reason) => {
            report.relay_death = Some(reason);
            true
        }
        ShutdownTrigger::ServerExit(result) => {
            report.serve_error = result.err().map(|error| error.to_string());
            report.server_returned_before_shutdown = report.serve_error.is_none();
            false
        }
    };

    connections.close_all().await;
    if drain_http {
        let _ = shutdown_tx.send(());
        match tokio::time::timeout(HTTP_DRAIN_DEADLINE, &mut server).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => report.serve_error = Some(error.to_string()),
            Err(_) => report.http_drain_timed_out = true,
        }
    }
    report.socket_drain_error = connections
        .drain_sockets(Duration::from_secs(15))
        .await
        .err();
    report
}

enum ShutdownTrigger {
    Signal(std::io::Result<()>),
    RelayDeath(String),
    ServerExit(std::io::Result<()>),
}

async fn schema_gated_pool(database_url: &str) -> anyhow::Result<sqlx::MySqlPool> {
    tokio::time::timeout(STARTUP_SCHEMA_DEADLINE, async {
        let db = connect_and_validate_schema(database_url).await?;
        astral_db::validate_chat_delivery_intent_schema(&db).await?;
        Ok::<_, astral_db::MigrationError>(db)
    })
    .await
    .map_err(|_| anyhow::anyhow!("Chat startup schema gate exceeded its 10-second deadline"))?
    .map_err(anyhow::Error::from)
}

async fn init_mq_producer(
    rabbitmq_url: &str,
    mq_producer: &OnceLock<Producer>,
    rabbit_owner: &mut Option<RabbitConnectionOwner>,
) -> Result<(), MqInitializationError> {
    let connection = Arc::new(
        Connection::connect(
            rabbitmq_url,
            lapin::ConnectionProperties::default().enable_auto_recover(),
        )
        .await
        .map_err(|_| MqInitializationError("RabbitMQ connection failed"))?,
    );
    *rabbit_owner = Some(RabbitConnectionOwner::new(Arc::new(
        LapinChatRabbitConnection(connection.clone()),
    )));

    let channel = connection
        .create_channel()
        .await
        .map_err(|_| MqInitializationError("RabbitMQ channel creation failed"))?;
    if astral_mq::producer::Producer::enable_confirms(&channel)
        .await
        .is_err()
    {
        return Err(MqInitializationError("RabbitMQ confirm setup failed"));
    }
    if astral_mq::config::declare_all(&channel).await.is_err() {
        return Err(MqInitializationError("RabbitMQ queue declaration failed"));
    }
    let producer = Producer::new(channel);
    if mq_producer.set(producer.clone()).is_err() {
        return Err(MqInitializationError(
            "Chat MQ producer already initialized",
        ));
    }
    register_mq_producer(Arc::new(ChatMqProducer { inner: producer }));
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let config = Arc::new(AppConfig::from_files("application")?);
    // Pure address/config validation precedes all external connections.
    let addr = listen_addr_from_env()?;
    config
        .message_transport()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let db = schema_gated_pool(&config.database_url).await?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let engine = Arc::new(PolicyEngine::new());
    register_audit_db_writer(Arc::new(ChatAuditDbWriter { pool: db.clone() }));
    // 启动期注册校验
    astral_common::middleware::permission_check_shared::validate_path_map(
        middleware::CHAT_PATH_MAP,
        "chat",
    );

    let mq_producer = Arc::new(OnceLock::new());
    let mut rabbit_owner = None;
    match tokio::time::timeout(
        MQ_INITIALIZATION_DEADLINE,
        init_mq_producer(&config.rabbitmq_url, &mq_producer, &mut rabbit_owner),
    )
    .await
    {
        Ok(Ok(())) => tracing::info!("chat MQ producer initialized"),
        Ok(Err(error)) => {
            tracing::warn!(reason = error.0, "chat MQ producer deferred");
            if let Err(close_error) =
                close_rabbit_owner(&mut rabbit_owner, "Chat MQ initialization failed").await
            {
                tracing::error!(
                    reason = close_error.0,
                    "Chat Rabbit close failed after MQ initialization error"
                );
            }
        }
        Err(_) => {
            tracing::warn!("chat MQ producer initialization deadline elapsed");
            if let Err(error) =
                close_rabbit_owner(&mut rabbit_owner, "Chat MQ initialization timed out").await
            {
                tracing::error!(
                    reason = error.0,
                    "Chat Rabbit close failed after MQ initialization timeout"
                );
            }
        }
    }

    // 数据访问层（对齐 Java ChatMapper 边界）
    let conversation_repository: Arc<
        dyn astral_chat::repository::conversation_repository::ConversationRepository,
    > = Arc::new(SqlxConversationRepository::new(db.clone()));
    let member_repository: Arc<dyn astral_chat::repository::member_repository::MemberRepository> =
        Arc::new(SqlxMemberRepository::new(db.clone()));
    let message_repository: Arc<
        dyn astral_chat::repository::message_repository::MessageRepository,
    > = Arc::new(SqlxMessageRepository::new(db.clone()));
    let client_session_repository: Arc<
        dyn astral_chat::repository::client_session_repository::ClientSessionRepository,
    > = Arc::new(SqlxClientSessionRepository::new(db.clone()));

    let connections = Arc::new(ConnectionPool::default());
    // 应用服务层（对齐 Java Chat*ServiceImpl 编排边界）
    let session_service = Arc::new(SessionService::new(
        conversation_repository.clone(),
        member_repository.clone(),
    ));
    let group_service = Arc::new(GroupService::new(
        conversation_repository.clone(),
        member_repository.clone(),
    ));
    let message_service = Arc::new(MessageService::new_durable(
        member_repository.clone(),
        message_repository.clone(),
    ));
    let receipt_service = Arc::new(ReceiptService::new(
        member_repository.clone(),
        message_repository.clone(),
    ));

    let relay_repository = message_repository.clone();
    let relay_producer = mq_producer.clone();
    let relay_connections = connections.clone();
    let relay = Arc::new(send_intent_relay::spawn_owned(
        relay_repository,
        relay_producer,
        relay_connections,
    ));
    let state = AppState {
        config,
        db: db.clone(),
        connections: connections.clone(),
        engine,
        mq_producer,
        conversation_repository,
        member_repository,
        message_repository,
        client_session_repository,
        session_service,
        group_service,
        message_service,
        receipt_service,
        send_intent_relay: relay.clone(),
    };

    let api_routes = Router::new()
        .merge(srv::messages::message_routes())
        .merge(srv::sessions::session_routes())
        .merge(srv::groups::group_routes())
        .merge(srv::realtime::ws_routes())
        .merge(srv::receipts::receipt_routes())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::chat_permission_middleware,
        ));

    let app = Router::new()
        .nest("/v1/chat", api_routes)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            gateway_signature_middleware,
        ))
        .layer(axum::middleware::from_fn(global_exception_handler))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state);

    tracing::info!(addr = %addr, "chat service starting");
    let relay_death = relay.death_signal();
    let shutdown_report = serve_until_shutdown(listener, app, relay_death, connections).await;
    if let Some(reason) = shutdown_report.relay_death.as_deref() {
        tracing::error!(
            reason,
            "Chat send-intent relay exited while HTTP service was running"
        );
    }
    if shutdown_report.http_drain_timed_out {
        tracing::error!("Chat HTTP graceful drain exceeded its 30-second deadline");
    }
    if let Some(error) = shutdown_report.serve_error.as_deref() {
        tracing::error!(error, "Chat HTTP server returned an error");
    }

    // HTTP drain precedes all worker shutdown so accepted requests can finish.
    relay.request_stop();
    let relay_shutdown = tokio::time::timeout(RELAY_SHUTDOWN_DEADLINE, relay.shutdown_join()).await;
    let audit_drain = tokio::time::timeout(
        AUDIT_DRAIN_DEADLINE,
        astral_common::audit::drain_owned_audit_tasks(AUDIT_DRAIN_DEADLINE),
    )
    .await;
    let rabbit_close = close_rabbit_owner(&mut rabbit_owner, "Chat service shutdown").await;

    let mut shutdown_errors = Vec::new();
    if let Some(error) = shutdown_report.signal_error {
        shutdown_errors.push(error);
    }
    if let Some(reason) = shutdown_report.relay_death {
        shutdown_errors.push(format!("Chat relay terminated during service: {reason}"));
    }
    if shutdown_report.http_drain_timed_out {
        shutdown_errors.push("Chat HTTP graceful drain exceeded its 30-second deadline".into());
    }
    if let Some(error) = shutdown_report.serve_error {
        shutdown_errors.push(format!("Chat HTTP server failed: {error}"));
    }
    if let Some(error) = shutdown_report.socket_drain_error {
        shutdown_errors.push(error);
    }
    if shutdown_report.server_returned_before_shutdown {
        shutdown_errors.push("Chat HTTP server returned before a shutdown signal".into());
    }
    match relay_shutdown {
        Ok(Ok(())) => {}
        Ok(Err(error)) => shutdown_errors.push(format!("Chat relay shutdown failed: {error}")),
        Err(_) => {
            shutdown_errors.push("Chat relay shutdown exceeded its 10-second deadline".into())
        }
    }
    match audit_drain {
        Ok(Ok(())) => {}
        Ok(Err(error)) => shutdown_errors.push(format!("Chat audit drain failed: {error}")),
        Err(_) => shutdown_errors.push("Chat audit drain exceeded its 3-second deadline".into()),
    }
    if let Err(error) = rabbit_close {
        shutdown_errors.push(format!("Chat Rabbit connection close failed: {}", error.0));
    }
    if !shutdown_errors.is_empty() {
        anyhow::bail!(shutdown_errors.join("; "));
    }
    Ok(())
}

#[cfg(test)]
mod startup_shutdown_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    struct MockRabbitConnectionClose {
        calls: AtomicUsize,
        fail_first: bool,
        delay_first: Duration,
        closed: Notify,
    }

    impl MockRabbitConnectionClose {
        fn new(fail_first: bool, delay_first: Duration) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                fail_first,
                delay_first,
                closed: Notify::new(),
            }
        }
    }

    #[async_trait::async_trait]
    impl RabbitConnectionClose for MockRabbitConnectionClose {
        async fn close(&self, _reason: &'static str) -> Result<(), RabbitConnectionCloseError> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 && !self.delay_first.is_zero() {
                tokio::time::sleep(self.delay_first).await;
            }
            if call == 0 && self.fail_first {
                return Err(RabbitConnectionCloseError("mock close failure"));
            }
            self.closed.notify_one();
            Ok(())
        }
    }

    #[tokio::test]
    async fn rabbit_owner_retains_connection_after_close_error_and_allows_retry() {
        let mock = Arc::new(MockRabbitConnectionClose::new(true, Duration::ZERO));
        let mut owner = RabbitConnectionOwner::new(mock.clone());

        let error = owner
            .close("unit test")
            .await
            .expect_err("first close error must be reported");
        assert_eq!(error, RabbitConnectionCloseError("mock close failure"));
        assert!(
            owner.connection.is_some(),
            "failed close must retain ownership"
        );

        owner
            .close("retry")
            .await
            .expect("subsequent close should succeed");
        assert!(owner.connection.is_none(), "successful close disarms owner");
        assert_eq!(mock.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn rabbit_owner_retains_connection_when_close_deadline_expires() {
        let mock = Arc::new(MockRabbitConnectionClose::new(
            false,
            Duration::from_millis(100),
        ));
        let mut owner = RabbitConnectionOwner::new(mock.clone());

        let error = owner
            .close_with_deadline("deadline test", Duration::from_millis(1))
            .await
            .expect_err("expired close must be reported");
        assert_eq!(
            error,
            RabbitConnectionCloseError("RabbitMQ close deadline elapsed")
        );
        assert!(
            owner.connection.is_some(),
            "expired close must retain ownership"
        );

        owner
            .close("retry")
            .await
            .expect("retry should close the retained connection");
        assert!(owner.connection.is_none());
        assert_eq!(mock.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn rabbit_owner_drop_reaper_attempts_close() {
        let mock = Arc::new(MockRabbitConnectionClose::new(false, Duration::ZERO));
        let reaped = mock.closed.notified();
        let owner = RabbitConnectionOwner::new(mock.clone());
        drop(owner);

        tokio::time::timeout(Duration::from_secs(1), reaped)
            .await
            .expect("drop reaper should attempt close");
        assert_eq!(mock.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn listen_address_validation_is_pure_and_rejects_invalid_values() {
        assert_eq!(
            parse_listen_addr(None).expect("default address is valid"),
            "0.0.0.0:9003".parse::<SocketAddr>().unwrap()
        );
        assert!(parse_listen_addr(Some("not-an-address")).is_err());
        assert!(parse_listen_addr(Some("")).is_err());
    }

    #[test]
    fn startup_gate_and_shutdown_order_are_wired_in_main() {
        let source = include_str!("main.rs");
        let main = source
            .split("#[tokio::main]")
            .nth(1)
            .expect("binary main exists");
        let config = main.find("AppConfig::from_files").unwrap();
        let pure_address = main.find("listen_addr_from_env()").unwrap();
        let schema = main.find("schema_gated_pool(").unwrap();
        let bind = main.find("TcpListener::bind(addr)").unwrap();
        let mq_init = main.find("init_mq_producer(").unwrap();
        let relay_spawn = main.find("send_intent_relay::spawn_owned(").unwrap();
        assert!(config < pure_address && pure_address < schema && schema < bind);
        assert!(bind < mq_init && mq_init < relay_spawn);
        assert!(source.contains("astral_db::validate_chat_delivery_intent_schema(&db).await?;"));
        assert!(!main.contains("mq_initializer"));

        let serve = main
            .find("serve_until_shutdown(listener, app, relay_death, connections)")
            .unwrap();
        let relay_stop = main.find("relay.request_stop()").unwrap();
        let relay_join = main.find("relay.shutdown_join()").unwrap();
        let audit_drain = main
            .find("drain_owned_audit_tasks(AUDIT_DRAIN_DEADLINE)")
            .unwrap();
        let rabbit_close = main
            .find("close_rabbit_owner(&mut rabbit_owner, \"Chat service shutdown\")")
            .unwrap();
        assert!(serve < relay_stop && relay_stop < relay_join);
        assert!(relay_join < audit_drain && audit_drain < rabbit_close);

        let serve_source = source
            .split("async fn serve_until_shutdown")
            .nth(1)
            .and_then(|body| body.split("async fn schema_gated_pool").next())
            .expect("server lifecycle function exists");
        assert!(serve_source.contains("with_graceful_shutdown"));
        assert!(serve_source.contains("HTTP_DRAIN_DEADLINE"));
        assert!(serve_source.contains("relay_death.changed()"));
    }
}
