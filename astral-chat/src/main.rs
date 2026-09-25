//! AstralChat 启动入口
//! ```bash
//! cargo run -p astral-chat
//! # LISTEN_ADDR=0.0.0.0:9003 cargo run -p astral-chat
//! ```

use std::sync::Arc;
use std::sync::OnceLock;

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
use astral_chat::service::session_service::SessionService;
use astral_chat::service::side_effect::ChatMessageSideEffects;
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let config = Arc::new(AppConfig::from_files("application")?);
    let db = connect_and_validate_schema(&config.database_url).await?;
    let engine = Arc::new(PolicyEngine::new());
    register_audit_db_writer(Arc::new(ChatAuditDbWriter { pool: db.clone() }));
    // 启动期注册校验
    astral_common::middleware::permission_check_shared::validate_path_map(
        middleware::CHAT_PATH_MAP,
        "chat",
    );

    let mq_producer = Arc::new(OnceLock::new());

    // 后台初始化 MQ Producer（非阻塞，失败仅记日志）
    {
        let rabbitmq_url = config.rabbitmq_url.clone();
        let mq_producer = mq_producer.clone();
        tokio::spawn(async move {
            match init_mq_producer(&rabbitmq_url, &mq_producer).await {
                Ok(()) => tracing::info!("chat MQ producer initialized"),
                Err(e) => {
                    tracing::warn!(error = %e, "chat MQ producer deferred (network may not be ready)")
                }
            }
        });
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
    // 副作用执行器（MQ + WS；测试注入 no-op）
    let side_effects = Arc::new(ChatMessageSideEffects::new(
        mq_producer.clone(),
        connections.clone(),
    ));

    // 应用服务层（对齐 Java Chat*ServiceImpl 编排边界）
    let session_service = Arc::new(SessionService::new(
        conversation_repository.clone(),
        member_repository.clone(),
    ));
    let group_service = Arc::new(GroupService::new(
        conversation_repository.clone(),
        member_repository.clone(),
    ));
    let message_service = Arc::new(MessageService::new(
        conversation_repository.clone(),
        member_repository.clone(),
        message_repository.clone(),
        side_effects,
    ));
    let receipt_service = Arc::new(ReceiptService::new(
        member_repository.clone(),
        message_repository.clone(),
    ));

    let state = AppState {
        config,
        db,
        connections,
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

    let addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:9003".into());
    tracing::info!(addr = %addr, "chat service starting");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// 初始化 MQ Producer（连接 RabbitMQ、声明队列、创建 Producer）
async fn init_mq_producer(
    rabbitmq_url: &str,
    mq_producer: &OnceLock<Producer>,
) -> Result<(), Box<dyn std::error::Error>> {
    let conn = Connection::connect(
        rabbitmq_url,
        lapin::ConnectionProperties::default().enable_auto_recover(),
    )
    .await?;
    let channel = conn.create_channel().await?;
    astral_mq::producer::Producer::enable_confirms(&channel).await?;
    astral_mq::config::declare_all(&channel).await?;
    let producer = Producer::new(channel);
    register_mq_producer(Arc::new(ChatMqProducer {
        inner: producer.clone(),
    }));
    let _ = mq_producer.set(producer);

    // 保持连接存活
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        }
    });

    Ok(())
}
