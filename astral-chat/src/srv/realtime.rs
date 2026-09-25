//! WebSocket 实时消息
//!
//! 对应 Java `WebSocketHandler` + `ChatWebSocketService`。
//!
//! # 数据流
//! 1. 客户端连接 → JWT 验证 → 注册到 ConnectionPool → 记录 chat_client_session
//! 2. 客户端发送 TEXT 消息 → INSERT chat_message → UPDATE chat_conversation.last_message
//! 3. 服务端推送新消息 → 从 ConnectionPool 找到在线用户 → 发送到 WebSocket

use std::collections::HashMap;

use crate::scope::{ChatScope, ChatScopeKey};
use crate::AppState;
use astral_common::token_contract::{PrincipalKind, CHAT_WS_SUBPROTOCOL};
use astral_db::{check_card_active_cached_with_options, CardActiveContext};
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Path, State, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::sync::RwLock;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WsScope {
    pub user_id: i64,
    pub identity_card_id: i64,
    pub user_card_id: Option<i64>,
    pub user_card_tenant_id: Option<i64>,
    pub user_card_domain_id: Option<i64>,
    pub principal_kind: PrincipalKind,
    pub token_id: String,
}

impl WsScope {
    fn key(&self) -> ChatScopeKey {
        self.chat_scope().key()
    }

    fn chat_scope(&self) -> ChatScope {
        ChatScope {
            user_id: self.user_id,
            identity_card_id: self.identity_card_id,
            user_card_id: self.user_card_id.unwrap_or_default(),
            user_card_tenant_id: self.user_card_tenant_id.unwrap_or_default(),
            user_card_domain_id: self.user_card_domain_id.unwrap_or_default(),
            principal_kind: self.principal_kind,
            token_id: self.token_id.clone(),
        }
    }
}

/// WebSocket 身份认证只接受 Gateway 已验证的物理身份上下文。
async fn authenticate_ws(
    state: &AppState,
    headers: &HeaderMap,
    path_user_id: i64,
) -> Result<WsScope, (StatusCode, &'static str)> {
    let scope =
        ChatScope::from_headers(headers).map_err(|reason| (StatusCode::UNAUTHORIZED, reason))?;
    if scope.user_id != path_user_id {
        return Err((StatusCode::FORBIDDEN, "User ID mismatch"));
    }
    let ws_scope = WsScope {
        user_id: scope.user_id,
        identity_card_id: scope.identity_card_id,
        user_card_id: Some(scope.user_card_id),
        user_card_tenant_id: Some(scope.user_card_tenant_id),
        user_card_domain_id: Some(scope.user_card_domain_id),
        principal_kind: scope.principal_kind,
        token_id: scope.token_id,
    };
    if !revalidate_ws_scope(state, &ws_scope).await {
        return Err((StatusCode::FORBIDDEN, "Physical card context denied"));
    }
    Ok(ws_scope)
}

pub struct ConnectionPool {
    connections: RwLock<HashMap<ChatScopeKey, Vec<tokio::sync::mpsc::UnboundedSender<String>>>>,
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionPool {
    pub fn new() -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
        }
    }

    pub async fn register(&self, scope: &WsScope, tx: tokio::sync::mpsc::UnboundedSender<String>) {
        let mut map = self.connections.write().await;
        map.entry(scope.key()).or_default().push(tx);
    }

    pub async fn unregister(
        &self,
        scope: &WsScope,
        tx: &tokio::sync::mpsc::UnboundedSender<String>,
    ) {
        let key = scope.key();
        let mut map = self.connections.write().await;
        if let Some(senders) = map.get_mut(&key) {
            senders.retain(|s| !s.same_channel(tx));
            if senders.is_empty() {
                map.remove(&key);
            }
        }
    }

    /// 向指定物理卡作用域的所有连接推送消息。
    pub async fn send_to_scope(&self, scope: &ChatScope, message: &str) {
        let map = self.connections.read().await;
        if let Some(senders) = map.get(&scope.key()) {
            for tx in senders {
                let _ = tx.send(message.to_string());
            }
        }
    }

    /// 向会话中指定用户的物理卡连接推送消息。
    pub async fn send_to_member_scopes(&self, scopes: &[ChatScope], message: &str) {
        let map = self.connections.read().await;
        for scope in scopes {
            if let Some(senders) = map.get(&scope.key()) {
                for tx in senders {
                    let _ = tx.send(message.to_string());
                }
            }
        }
    }
}

/// WebSocket 消息协议（客户端 → 服务端）
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WsIncomingMessage {
    pub message_type: String,
    pub conversation_id: i64,
    pub sender_id: i64,
    pub content: Option<String>,
    /// 客户端消息 ID（可选，用于去重）
    #[serde(default)]
    pub client_msg_id: Option<String>,
}

/// WebSocket 消息协议（服务端 → 客户端）
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WsOutgoingMessage {
    pub message_type: String,
    pub conversation_id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_msg_id: Option<String>,
    pub timestamp: i64,
}

pub fn ws_routes() -> Router<AppState> {
    Router::new().route("/ws/{user_id}", get(ws_handler))
}

async fn ws_handler(
    headers: HeaderMap,
    ws: WebSocketUpgrade,
    Path(user_id): Path<i64>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let scope = authenticate_ws(&state, &headers, user_id).await?;

    Ok(ws
        .protocols([CHAT_WS_SUBPROTOCOL])
        .on_upgrade(move |socket| handle_socket(socket, scope, state)))
}

async fn handle_socket(mut socket: WebSocket, scope: WsScope, state: AppState) {
    let user_id = scope.user_id;
    let device_id = scope.chat_scope().connection_device_id(None);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    state.connections.register(&scope, tx.clone()).await;

    // 记录客户端上线（非关键路径，失败仅告警）
    if let Err(e) = state
        .client_session_repository
        .upsert(user_id, "ONLINE", Some(&device_id))
        .await
    {
        tracing::warn!(user_id, error = %e, "upsert client session failed (non-critical)");
    }
    tracing::info!(user_id, "websocket connected");

    loop {
        tokio::select! {
            // 从 channel 接收消息 → 发送到 WebSocket
            msg = rx.recv() => {
                match msg {
                    Some(text) => {
                        if socket.send(Message::Text(text.into())).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            // 从 WebSocket 接收消息 → 持久化 + 广播
            ws_msg = socket.recv() => {
                match ws_msg {
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(parsed) = serde_json::from_str::<WsIncomingMessage>(&text) {
                            if !revalidate_ws_scope(&state, &scope).await {
                                tracing::warn!(user_id, "websocket physical scope revoked; closing connection");
                                let _ = socket.send(Message::Close(None)).await;
                                break;
                            }
                            handle_incoming_message(&state, &tx, &scope, parsed).await;
                        } else {
                            tracing::warn!(user_id, raw = %text, "invalid WS message format");
                        }
                    }
                    Some(Ok(Message::Ping(data))) => {
                        // 响应 Ping → Pong（保持心跳）
                        if socket.send(Message::Pong(data)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) => {
                        tracing::info!(user_id, "websocket client close frame");
                        break;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(e)) => {
                        tracing::warn!(user_id, error = %e, "websocket recv error");
                        break;
                    }
                    None => {
                        tracing::info!(user_id, "websocket stream ended");
                        break;
                    }
                }
            }
        }
    }

    // 清理：取消注册 + 标记离线
    state.connections.unregister(&scope, &tx).await;
    if let Err(e) = state
        .client_session_repository
        .upsert(user_id, "OFFLINE", Some(&device_id))
        .await
    {
        tracing::warn!(user_id, error = %e, "upsert client session failed (non-critical)");
    }
    tracing::info!(user_id, "websocket disconnected");
}

/// 处理 WebSocket 接收到的消息
async fn handle_incoming_message(
    state: &AppState,
    tx: &tokio::sync::mpsc::UnboundedSender<String>,
    scope: &WsScope,
    parsed: WsIncomingMessage,
) {
    let user_id = scope.user_id;
    if !revalidate_ws_scope(state, scope).await {
        let _ = tx.send(
            serde_json::json!({
                "message_type": "ERROR",
                "content": "physical card context is no longer valid",
                "timestamp": OffsetDateTime::now_utc().unix_timestamp(),
            })
            .to_string(),
        );
        return;
    }
    match parsed.message_type.as_str() {
        "PING" => {
            // PING/PONG 心跳响应
            let pong = serde_json::json!({
                "message_type": "PONG",
                "timestamp": OffsetDateTime::now_utc().unix_timestamp(),
            });
            let _ = tx.send(pong.to_string());
        }
        "TEXT" | "IMAGE" | "FILE" | "SYSTEM" => {
            if parsed.sender_id != user_id {
                tracing::warn!(
                    user_id,
                    claimed_sender = parsed.sender_id,
                    "sender_id mismatch in WS message"
                );
                let err_msg = serde_json::json!({
                    "message_type": "ERROR",
                    "content": "sender_id mismatch",
                    "timestamp": OffsetDateTime::now_utc().unix_timestamp(),
                });
                let _ = tx.send(err_msg.to_string());
                return;
            }

            let input = crate::service::message_service::SendMessageInput {
                scope: scope.chat_scope(),
                conversation_id: parsed.conversation_id,
                content: parsed.content.unwrap_or_default(),
                message_type: parsed.message_type,
            };
            if let Err(error) = state.message_service.send_message(&input).await {
                tracing::warn!(
                    user_id,
                    conversation_id = input.conversation_id,
                    error = %error,
                    "WS message rejected"
                );
                let err_msg = serde_json::json!({
                    "message_type": "ERROR",
                    "content": error.to_string(),
                    "timestamp": OffsetDateTime::now_utc().unix_timestamp(),
                });
                let _ = tx.send(err_msg.to_string());
            }
        }
        "TYPING" => {
            if !state
                .member_repository
                .is_member_scoped(parsed.conversation_id, &scope.chat_scope())
                .await
                .unwrap_or(false)
            {
                return;
            }
            let typing_msg = serde_json::json!({
                "message_type": "TYPING",
                "conversation_id": parsed.conversation_id,
                "sender_id": user_id,
                "timestamp": OffsetDateTime::now_utc().unix_timestamp(),
            });
            let typing_str = typing_msg.to_string();
            if let Ok(member_scopes) = state
                .member_repository
                .list_member_scopes(parsed.conversation_id, &scope.chat_scope())
                .await
            {
                state
                    .connections
                    .send_to_member_scopes(&member_scopes, &typing_str)
                    .await;
            }
        }
        "READ_RECEIPT" => {
            if !state
                .member_repository
                .is_member_scoped(parsed.conversation_id, &scope.chat_scope())
                .await
                .unwrap_or(false)
            {
                return;
            }
            if let Some(ref content) = parsed.content {
                if let Ok(read_id) = content.parse::<i64>() {
                    if let Err(e) = state
                        .member_repository
                        .update_last_read(parsed.conversation_id, scope.user_id, read_id)
                        .await
                    {
                        tracing::warn!(session = %parsed.conversation_id, error = %e, "WS read receipt update failed");
                    }
                }
            }
        }
        other => {
            tracing::warn!(message_type = %other, "unknown WS message type");
        }
    }
}

async fn revalidate_ws_scope(state: &AppState, scope: &WsScope) -> bool {
    if scope.principal_kind != PrincipalKind::PlatformUser {
        return false;
    }
    let (Some(user_card_id), Some(tenant_id), Some(domain_id)) = (
        scope.user_card_id,
        scope.user_card_tenant_id,
        scope.user_card_domain_id,
    ) else {
        return false;
    };

    check_card_active_cached_with_options(
        &state.db,
        &CardActiveContext {
            user_id: scope.user_id,
            identity_card_id: scope.identity_card_id,
            user_card_id,
            user_card_tenant_id: tenant_id,
            user_card_domain_id: domain_id,
        },
        30,
        5,
        true,
    )
    .await
    .unwrap_or_else(|error| {
        tracing::warn!(
            user_id = scope.user_id,
            user_card_id,
            error = %error,
            "WebSocket physical card revalidation failed"
        );
        false
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_common::token_contract::PrincipalKind;

    fn scope(user_card_id: i64, domain_id: i64) -> WsScope {
        WsScope {
            user_id: 7,
            identity_card_id: 70,
            user_card_id: Some(user_card_id),
            user_card_tenant_id: Some(10),
            user_card_domain_id: Some(domain_id),
            principal_kind: PrincipalKind::PlatformUser,
            token_id: format!("token-{user_card_id}"),
        }
    }

    #[tokio::test]
    async fn connection_pool_isolates_same_user_across_cards() {
        let pool = ConnectionPool::new();
        let card_a = scope(701, 20);
        let card_b = scope(702, 21);
        let (tx_a, mut rx_a) = tokio::sync::mpsc::unbounded_channel();
        let (tx_b, mut rx_b) = tokio::sync::mpsc::unbounded_channel();
        pool.register(&card_a, tx_a).await;
        pool.register(&card_b, tx_b).await;

        pool.send_to_scope(&card_a.chat_scope(), "card-a").await;

        assert_eq!(rx_a.recv().await.as_deref(), Some("card-a"));
        assert!(rx_b.try_recv().is_err());
    }

    #[tokio::test]
    async fn connection_pool_broadcasts_to_same_physical_scope_only() {
        let pool = ConnectionPool::new();
        let card = scope(701, 20);
        let other = scope(702, 20);
        let (tx_one, mut rx_one) = tokio::sync::mpsc::unbounded_channel();
        let (tx_two, mut rx_two) = tokio::sync::mpsc::unbounded_channel();
        let (tx_other, mut rx_other) = tokio::sync::mpsc::unbounded_channel();
        pool.register(&card, tx_one).await;
        pool.register(&card, tx_two).await;
        pool.register(&other, tx_other).await;

        pool.send_to_scope(&card.chat_scope(), "same-card").await;

        assert_eq!(rx_one.recv().await.as_deref(), Some("same-card"));
        assert_eq!(rx_two.recv().await.as_deref(), Some("same-card"));
        assert!(rx_other.try_recv().is_err());
    }
}
