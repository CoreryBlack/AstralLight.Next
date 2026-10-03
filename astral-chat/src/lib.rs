//! AstralLight 即时通讯服务
//!
//! 对应 Java `AstralChat` 模块（~3,350 行 / ~49 文件）。

pub mod repository;
pub mod scope;
pub mod service;
pub mod srv;

use astral_common::config::AppConfig;
use astral_mq::producer::Producer;
use axum::extract::FromRef;
use policy_engine::PolicyEngine;
use sqlx::MySqlPool;
use std::sync::Arc;
use std::sync::OnceLock;

use crate::repository::client_session_repository::ClientSessionRepository;
use crate::repository::conversation_repository::ConversationRepository;
use crate::repository::member_repository::MemberRepository;
use crate::repository::message_repository::MessageRepository;
use crate::service::group_service::GroupService;
use crate::service::message_service::MessageService;
use crate::service::receipt_service::ReceiptService;
use crate::service::send_intent_relay::SendIntentRelayHandle;
use crate::service::session_service::SessionService;
use crate::srv::realtime::ConnectionPool;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub db: MySqlPool,
    pub connections: Arc<ConnectionPool>,
    pub engine: Arc<PolicyEngine>,
    pub mq_producer: Arc<OnceLock<Producer>>,
    /// 会话/群组数据访问
    pub conversation_repository: Arc<dyn ConversationRepository>,
    /// 会话成员数据访问
    pub member_repository: Arc<dyn MemberRepository>,
    /// 消息数据访问
    pub message_repository: Arc<dyn MessageRepository>,
    /// 客户端会话（WebSocket 上下线）数据访问
    pub client_session_repository: Arc<dyn ClientSessionRepository>,
    /// 会话编排（创建/列表/成员管理）
    pub session_service: Arc<SessionService>,
    /// 群组编排（角色体系/转让/解散）
    pub group_service: Arc<GroupService>,
    /// 消息编排（send 8 步链路）
    pub message_service: Arc<MessageService>,
    /// 已读回执编排
    pub receipt_service: Arc<ReceiptService>,
    /// Required owned durable send-intent relay worker.
    pub send_intent_relay: Arc<SendIntentRelayHandle>,
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
