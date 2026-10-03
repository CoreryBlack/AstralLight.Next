//! WebSocket 实时消息
//!
//! 对应 Java `WebSocketHandler` + `ChatWebSocketService`。
//!
//! # 数据流
//! 1. 客户端连接 → JWT 验证 → 注册到 ConnectionPool → 记录 chat_client_session
//! 2. 客户端发送 TEXT 消息 → INSERT chat_message → UPDATE chat_conversation.last_message
//! 3. 服务端推送新消息 → 从 ConnectionPool 找到在线用户 → 发送到 WebSocket

use std::collections::HashMap;

use crate::repository::message_repository::validate_client_message_id;
use crate::scope::{ChatScope, ChatScopeKey};
use crate::AppState;
use astral_common::token_contract::{PrincipalKind, CHAT_WS_SUBPROTOCOL};
use astral_db::{check_card_active_cached_with_options, CardActiveContext};
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Path, State, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Extension, Router};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::sync::RwLock;

pub const MAX_CHAT_WS_FRAME_BYTES: usize = 64 * 1024;
pub const CHAT_WS_OUTBOUND_CAPACITY: usize = 128;
const CHAT_WS_CONNECTION_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

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

struct PooledConnection {
    sender: tokio::sync::mpsc::Sender<String>,
    cancel: tokio::sync::watch::Sender<bool>,
}

pub struct ConnectionPool {
    connections: RwLock<HashMap<ChatScopeKey, Vec<PooledConnection>>>,
    closing: std::sync::atomic::AtomicBool,
    active_sockets: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    sockets_drained: std::sync::Arc<tokio::sync::Notify>,
    socket_failure: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

struct SocketOwner {
    active: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    drained: std::sync::Arc<tokio::sync::Notify>,
    failed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    completed: bool,
}

impl SocketOwner {
    fn complete(mut self) {
        self.completed = true;
    }
}

impl Drop for SocketOwner {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;
        if !self.completed {
            self.failed.store(true, Ordering::Release);
        }
        if self.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.drained.notify_one();
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOutcome {
    Queued,
    NoConnections,
    Backpressure,
    Closed,
    TooLarge,
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
            closing: std::sync::atomic::AtomicBool::new(false),
            active_sockets: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            sockets_drained: std::sync::Arc::new(tokio::sync::Notify::new()),
            socket_failure: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    async fn admit_socket(&self) -> Option<SocketOwner> {
        let _connections = self.connections.write().await;
        if self.is_closing() {
            return None;
        }
        self.active_sockets
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        Some(SocketOwner {
            active: self.active_sockets.clone(),
            drained: self.sockets_drained.clone(),
            failed: self.socket_failure.clone(),
            completed: false,
        })
    }

    pub async fn drain_sockets(&self, timeout: std::time::Duration) -> Result<(), String> {
        let drain = async {
            loop {
                let notified = self.sockets_drained.notified();
                if self
                    .active_sockets
                    .load(std::sync::atomic::Ordering::Acquire)
                    == 0
                {
                    break;
                }
                notified.await;
            }
        };
        if tokio::time::timeout(timeout, drain).await.is_err() {
            self.socket_failure
                .store(true, std::sync::atomic::Ordering::Release);
            return Err("Chat socket owner drain timed out; shutdown is unproven".into());
        }
        if self
            .socket_failure
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err("Chat socket owner panicked or was cancelled; shutdown is unproven".into());
        }
        Ok(())
    }

    /// Legacy unbounded registrations are rejected; use the bounded owner API.
    pub async fn register(&self, _scope: &WsScope, tx: tokio::sync::mpsc::UnboundedSender<String>) {
        drop(tx);
        tracing::warn!("unbounded Chat registration rejected; use register_bounded");
    }

    pub async fn register_bounded(&self, scope: &WsScope, tx: tokio::sync::mpsc::Sender<String>) {
        let (cancel, _) = tokio::sync::watch::channel(false);
        self.register_with_cancel(scope, tx, cancel).await;
    }

    pub async fn register_with_cancel(
        &self,
        scope: &WsScope,
        tx: tokio::sync::mpsc::Sender<String>,
        cancel: tokio::sync::watch::Sender<bool>,
    ) {
        let key = scope.key();
        let mut connections = self.connections.write().await;
        if self.is_closing() {
            let _ = cancel.send(true);
            return;
        }
        connections
            .entry(key)
            .or_default()
            .push(PooledConnection { sender: tx, cancel });
    }

    pub fn is_closing(&self) -> bool {
        self.closing.load(std::sync::atomic::Ordering::Acquire)
    }

    pub async fn close_all(&self) {
        let mut connections = self.connections.write().await;
        self.closing
            .store(true, std::sync::atomic::Ordering::Release);
        for connection in connections.values().flatten() {
            let _ = connection.cancel.send(true);
        }
        connections.clear();
    }

    pub async fn unregister(
        &self,
        _scope: &WsScope,
        _tx: &tokio::sync::mpsc::UnboundedSender<String>,
    ) {
    }

    pub async fn unregister_bounded(
        &self,
        scope: &WsScope,
        tx: &tokio::sync::mpsc::Sender<String>,
    ) {
        let key = scope.key();
        let mut map = self.connections.write().await;
        if let Some(senders) = map.get_mut(&key) {
            senders.retain(|connection| !connection.sender.same_channel(tx));
            if senders.is_empty() {
                map.remove(&key);
            }
        }
    }

    /// Queues a message to bounded per-connection channels. Full/closed queues
    /// cause the slow connection to be removed; WebSocket queuing is not a
    /// durable delivered receipt.
    pub async fn send_to_scope(&self, scope: &ChatScope, message: &str) {
        let _ = self.try_send_to_scope(scope, message).await;
    }

    pub async fn try_send_to_scope(&self, scope: &ChatScope, message: &str) -> PushOutcome {
        self.send_to_scopes(std::slice::from_ref(scope), message)
            .await
    }

    pub async fn send_to_member_scopes(&self, scopes: &[ChatScope], message: &str) {
        let _ = self.try_send_to_member_scopes(scopes, message).await;
    }

    pub async fn try_send_to_member_scopes(
        &self,
        scopes: &[ChatScope],
        message: &str,
    ) -> PushOutcome {
        self.send_to_scopes(scopes, message).await
    }

    async fn send_to_scopes(&self, scopes: &[ChatScope], message: &str) -> PushOutcome {
        if message.len() > MAX_CHAT_WS_FRAME_BYTES {
            return PushOutcome::TooLarge;
        }
        let mut map = self.connections.write().await;
        if self.is_closing() {
            return PushOutcome::Closed;
        }
        let mut found = false;
        let mut queued = false;
        let mut backpressure = false;
        let mut closed = false;
        for scope in scopes {
            let key = scope.key();
            if let Some(connections) = map.get_mut(&key) {
                found = true;
                connections.retain(|connection| {
                    match connection.sender.try_send(message.to_owned()) {
                        Ok(()) => {
                            queued = true;
                            true
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            backpressure = true;
                            let _ = connection.cancel.send(true);
                            false
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                            closed = true;
                            let _ = connection.cancel.send(true);
                            false
                        }
                    }
                });
            }
            if map.get(&key).is_some_and(Vec::is_empty) {
                map.remove(&key);
            }
        }
        if queued {
            PushOutcome::Queued
        } else if backpressure {
            PushOutcome::Backpressure
        } else if closed || found {
            PushOutcome::Closed
        } else {
            PushOutcome::NoConnections
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
    admission_fence: Option<Extension<astral_db::AuthorityReadFence>>,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let scope = authenticate_ws(&state, &headers, user_id).await?;
    let socket_owner = state.connections.admit_socket().await.ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "WebSocket admission closed",
    ))?;
    if state.connections.is_closing()
        || astral_db::memory_projection_hub().is_some_and(|hub| {
            admission_fence
                .as_ref()
                .is_none_or(|Extension(fence)| !hub.authority_fence_matches(*fence))
        })
    {
        socket_owner.complete();
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "WebSocket admission changed",
        ));
    }

    Ok(ws
        .max_message_size(MAX_CHAT_WS_FRAME_BYTES)
        .max_frame_size(MAX_CHAT_WS_FRAME_BYTES)
        .protocols([CHAT_WS_SUBPROTOCOL])
        .on_upgrade(move |socket| async move {
            handle_socket(socket, scope, state).await;
            socket_owner.complete();
        }))
}

async fn handle_socket(mut socket: WebSocket, scope: WsScope, state: AppState) {
    if !ws_session_admission(&state, &scope).await {
        close_socket_bounded(&mut socket).await;
        return;
    }
    let user_id = scope.user_id;
    let device_id = scope.chat_scope().connection_device_id(None);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(CHAT_WS_OUTBOUND_CAPACITY);
    let (cancel_tx, mut cancel_rx) = tokio::sync::watch::channel(false);
    state
        .connections
        .register_with_cancel(&scope, tx.clone(), cancel_tx)
        .await;

    // 记录客户端上线（非关键路径，失败仅告警）
    let online = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        state
            .client_session_repository
            .upsert(user_id, "ONLINE", Some(&device_id)),
    )
    .await;
    if !matches!(online, Ok(Ok(()))) {
        tracing::warn!(
            user_id,
            "upsert client session failed or timed out (non-critical)"
        );
    }
    tracing::info!(user_id, "websocket connected");

    loop {
        if state.connections.is_closing() || *cancel_rx.borrow() {
            close_socket_bounded(&mut socket).await;
            break;
        }
        tokio::select! {
            cancelled = cancel_rx.changed() => {
                if cancelled.is_err() || *cancel_rx.borrow() {
                    close_socket_bounded(&mut socket).await;
                    break;
                }
            }
            // From the bounded channel into the WebSocket. A stalled socket is
            // closed after a fixed deadline; outbound queue growth is bounded.
            msg = rx.recv() => {
                match msg {
                    Some(text) => {
                        if !authorize_queued_frame(&state, &scope, &text).await {
                            close_socket_bounded(&mut socket).await;
                            break;
                        }
                        match tokio::time::timeout(
                            CHAT_WS_CONNECTION_SEND_TIMEOUT,
                            socket.send(Message::Text(text.into())),
                        ).await {
                            Ok(Ok(())) => {}
                            Ok(Err(_)) | Err(_) => break,
                        }
                    }
                    None => break,
                }
            }
            // 从 WebSocket 接收消息 → 持久化 + 广播
            ws_msg = socket.recv() => {
                match ws_msg {
                    Some(Ok(Message::Text(text))) => {
                        if text.len() > MAX_CHAT_WS_FRAME_BYTES {
                            tracing::warn!(user_id, bytes = text.len(), "oversized WS text frame; closing connection");
                            close_socket_bounded(&mut socket).await;
                            break;
                        }
                        if let Ok(parsed) = serde_json::from_str::<WsIncomingMessage>(&text) {
                            if !revalidate_ws_scope(&state, &scope).await {
                                tracing::warn!(user_id, "websocket physical scope revoked; closing connection");
                                close_socket_bounded(&mut socket).await;
                                break;
                            }
                            match handle_incoming_message(&state, &tx, &scope, parsed).await {
                                IncomingMessageOutcome::Close => {
                                    close_socket_bounded(&mut socket).await;
                                    break;
                                }
                                IncomingMessageOutcome::Continue => {}
                            }
                        } else {
                            tracing::warn!(user_id, "invalid WS message format");
                            if queue_ws_error(&tx, "invalid WS message format").await != PushOutcome::Queued {
                                close_socket_bounded(&mut socket).await;
                                break;
                            }
                        }
                    }
                    Some(Ok(Message::Ping(data))) => {
                        // 响应 Ping → Pong（保持心跳）；所有写均有固定期限。
                        match tokio::time::timeout(
                            CHAT_WS_CONNECTION_SEND_TIMEOUT,
                            socket.send(Message::Pong(data)),
                        ).await {
                            Ok(Ok(())) => {}
                            Ok(Err(_)) | Err(_) => break,
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
    state.connections.unregister_bounded(&scope, &tx).await;
    let offline = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        state
            .client_session_repository
            .upsert(user_id, "OFFLINE", Some(&device_id)),
    )
    .await;
    if !matches!(offline, Ok(Ok(()))) {
        tracing::warn!(
            user_id,
            "upsert client session failed or timed out (non-critical)"
        );
    }
    tracing::info!(user_id, "websocket disconnected");
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueuedFrameAdmission {
    Conversation { id: i64, action: &'static str },
    Session,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct QueuedFrameHeader {
    #[serde(alias = "message_type")]
    message_type: String,
    #[serde(alias = "conversation_id")]
    conversation_id: Option<i64>,
}

fn queued_frame_admission(text: &str) -> Option<QueuedFrameAdmission> {
    let header: QueuedFrameHeader = serde_json::from_str(text).ok()?;
    let action = match header.message_type.as_str() {
        "NEW_MESSAGE" | "TEXT" | "IMAGE" | "FILE" | "SYSTEM" | "TYPING" | "READ_RECEIPT" => "read",
        "MESSAGE_ACCEPTED" => "create",
        "ERROR" | "PONG" => return Some(QueuedFrameAdmission::Session),
        _ => return None,
    };
    Some(QueuedFrameAdmission::Conversation {
        id: header.conversation_id.filter(|id| *id > 0)?,
        action,
    })
}

async fn ws_session_admission(state: &AppState, scope: &WsScope) -> bool {
    let hub = astral_db::memory_projection_hub();
    let fence = if let Some(hub) = hub {
        let Some(fence) = hub.capture_authority_fence() else {
            return false;
        };
        Some(fence)
    } else {
        None
    };
    if !revalidate_ws_scope(state, scope).await {
        return false;
    }
    if let Some((hub, fence)) = hub.zip(fence) {
        if !hub.authority_fence_matches(fence) {
            return false;
        }
    }
    !state.connections.is_closing()
}

async fn authorize_queued_frame(state: &AppState, scope: &WsScope, text: &str) -> bool {
    let check = async {
        match queued_frame_admission(text) {
            Some(QueuedFrameAdmission::Conversation { id, action }) => {
                matches!(
                    fresh_chat_permission(state, scope, id, action).await,
                    Ok(true)
                )
            }
            Some(QueuedFrameAdmission::Session) => ws_session_admission(state, scope).await,
            None => false,
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), check)
        .await
        .unwrap_or(false)
}

async fn close_socket_bounded(socket: &mut WebSocket) {
    let _ = tokio::time::timeout(
        CHAT_WS_CONNECTION_SEND_TIMEOUT,
        socket.send(Message::Close(None)),
    )
    .await;
}

fn canonical_ws_action(message_type: &str) -> Option<&'static str> {
    match message_type {
        "TEXT" | "IMAGE" | "FILE" | "SYSTEM" => Some("create"),
        "PING" | "TYPING" => Some("read"),
        "READ_RECEIPT" => Some("update"),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IncomingMessageOutcome {
    Continue,
    Close,
}

async fn queue_ws_error(tx: &tokio::sync::mpsc::Sender<String>, text: &str) -> PushOutcome {
    let body = serde_json::json!({
        "message_type": "ERROR",
        "content": text,
        "timestamp": OffsetDateTime::now_utc().unix_timestamp(),
    })
    .to_string();
    match tokio::time::timeout(CHAT_WS_CONNECTION_SEND_TIMEOUT, tx.send(body)).await {
        Ok(Ok(())) => PushOutcome::Queued,
        Ok(Err(_)) => PushOutcome::Closed,
        Err(_) => PushOutcome::Backpressure,
    }
}

/// Handle one untrusted client frame; each action is independently authorized.
async fn handle_incoming_message(
    state: &AppState,
    tx: &tokio::sync::mpsc::Sender<String>,
    scope: &WsScope,
    parsed: WsIncomingMessage,
) -> IncomingMessageOutcome {
    let user_id = scope.user_id;
    if !revalidate_ws_scope(state, scope).await {
        return IncomingMessageOutcome::Close;
    }
    let Some(action) = canonical_ws_action(&parsed.message_type) else {
        return IncomingMessageOutcome::Continue;
    };
    match parsed.message_type.as_str() {
        "PING" => {
            if !matches!(
                fresh_chat_permission(state, scope, parsed.conversation_id, action).await,
                Ok(true)
            ) {
                return IncomingMessageOutcome::Close;
            }
            let pong = serde_json::json!({
                "message_type": "PONG",
                "timestamp": OffsetDateTime::now_utc().unix_timestamp(),
            })
            .to_string();
            if queue_ws_frame(tx, pong).await != PushOutcome::Queued {
                return IncomingMessageOutcome::Close;
            }
        }
        "TEXT" | "IMAGE" | "FILE" | "SYSTEM" => {
            if parsed.sender_id != user_id {
                tracing::warn!(
                    user_id,
                    claimed_sender = parsed.sender_id,
                    "sender_id mismatch in WS message"
                );
                if queue_ws_error(tx, "sender_id mismatch").await != PushOutcome::Queued {
                    return IncomingMessageOutcome::Close;
                }
                return IncomingMessageOutcome::Continue;
            }

            let client_msg_id = match parsed.client_msg_id.as_deref() {
                Some(value) if validate_client_message_id(value).is_ok() => value,
                _ => {
                    if queue_ws_error(tx, "clientMsgId is required and must be 1-64 ASCII letters, digits, '.', '_' or '-'").await != PushOutcome::Queued {
                        return IncomingMessageOutcome::Close;
                    }
                    return IncomingMessageOutcome::Continue;
                }
            };
            let input = crate::service::message_service::SendMessageInput {
                scope: scope.chat_scope(),
                conversation_id: parsed.conversation_id,
                content: parsed.content.unwrap_or_default(),
                message_type: parsed.message_type,
                client_msg_id: client_msg_id.to_owned(),
            };
            match fresh_chat_permission(state, scope, input.conversation_id, action).await {
                Ok(true) => {}
                Ok(false) => {
                    let _ = queue_ws_error(tx, "chat_message:create permission denied").await;
                    return IncomingMessageOutcome::Continue;
                }
                Err(error) => {
                    tracing::warn!(user_id, conversation_id = input.conversation_id, error = %error, "fresh WebSocket send authorization unavailable; denying");
                    let _ =
                        queue_ws_error(tx, "chat_message:create authorization unavailable").await;
                    return IncomingMessageOutcome::Continue;
                }
            }
            match state.message_service.send_message(&input).await {
                Ok(message) => {
                    let ack = serde_json::json!({
                        "message_type": "MESSAGE_ACCEPTED",
                        "conversation_id": message.conversation_id,
                        "sender_id": message.sender_id,
                        "message_id": message.id,
                        "client_msg_id": client_msg_id,
                        "status": "PENDING",
                        "timestamp": OffsetDateTime::now_utc().unix_timestamp(),
                    })
                    .to_string();
                    if queue_ws_frame(tx, ack).await != PushOutcome::Queued {
                        return IncomingMessageOutcome::Close;
                    }
                }
                Err(error) => {
                    tracing::warn!(user_id, conversation_id = input.conversation_id, error = %error, "WS message rejected");
                    if queue_ws_error(tx, &error.to_string()).await != PushOutcome::Queued {
                        return IncomingMessageOutcome::Close;
                    }
                }
            }
        }
        "TYPING" => {
            match fresh_chat_permission(state, scope, parsed.conversation_id, action).await {
                Ok(true) => {}
                Ok(false) | Err(_) => return IncomingMessageOutcome::Continue,
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
            match fresh_chat_permission(state, scope, parsed.conversation_id, action).await {
                Ok(true) => {}
                Ok(false) | Err(_) => return IncomingMessageOutcome::Continue,
            }
            if let Some(ref content) = parsed.content {
                if let Ok(read_id) = content.parse::<i64>() {
                    if let Err(e) = state
                        .receipt_service
                        .mark_read(&scope.chat_scope(), parsed.conversation_id, read_id)
                        .await
                    {
                        tracing::warn!(session = %parsed.conversation_id, error = %e, "WS read receipt update failed");
                    }
                }
            }
        }
        other => {
            tracing::warn!(message_type = %other, "unknown WS message type");
            if queue_ws_error(tx, "unknown WS message type").await != PushOutcome::Queued {
                return IncomingMessageOutcome::Close;
            }
        }
    }
    IncomingMessageOutcome::Continue
}

async fn queue_ws_frame(tx: &tokio::sync::mpsc::Sender<String>, text: String) -> PushOutcome {
    if text.len() > MAX_CHAT_WS_FRAME_BYTES {
        return PushOutcome::TooLarge;
    }
    match tokio::time::timeout(CHAT_WS_CONNECTION_SEND_TIMEOUT, tx.send(text)).await {
        Ok(Ok(())) => PushOutcome::Queued,
        Ok(Err(_)) => PushOutcome::Closed,
        Err(_) => PushOutcome::Backpressure,
    }
}

async fn fresh_chat_permission(
    state: &AppState,
    scope: &WsScope,
    conversation_id: i64,
    action: &str,
) -> Result<bool, astral_types::AstralError> {
    let (Some(user_card_id), Some(tenant_id), Some(domain_id)) = (
        scope.user_card_id,
        scope.user_card_tenant_id,
        scope.user_card_domain_id,
    ) else {
        return Ok(false);
    };
    let hub = astral_db::memory_projection_hub();
    let fence = if let Some(hub) = hub {
        Some(hub.capture_authority_fence().ok_or_else(|| {
            astral_types::AstralError::Permission("Chat authority state is changing".into())
        })?)
    } else {
        None
    };
    if !revalidate_ws_scope(state, scope).await || state.connections.is_closing() {
        return Ok(false);
    }
    let ownership = astral_db::resolve_resource_ownership(
        &state.db,
        "chat_message",
        &format!("/messages/session/{conversation_id}"),
        "GET",
        None,
        Some(user_card_id),
        Some(scope.user_id),
    )
    .await;
    let policy_ctx = astral_types::PolicyContext::builder()
        .user_id(Some(scope.user_id))
        .principal_kind(Some(scope.principal_kind.as_str().to_owned()))
        .identity_card_id(Some(scope.identity_card_id))
        .card_id(Some(user_card_id))
        .tenant_id(Some(tenant_id))
        .domain_id(Some(domain_id))
        .resource(Some("chat_message".to_owned()))
        .action(action.to_owned())
        .target_id(Some(conversation_id))
        .build();
    let mut policy_ctx = policy_ctx;
    ownership.apply_to(&mut policy_ctx);
    let repo = astral_db::SqlxRuleRepository::new(state.db.clone())
        .with_org_scope_enabled(state.config.org_scope_enabled);
    let decision = state.engine.evaluate(&policy_ctx, &repo).await;
    astral_common::audit::record_permission_audit(
        Some(scope.user_id),
        Some(user_card_id),
        Some(domain_id),
        Some(tenant_id),
        "chat_message",
        action,
        decision.allowed,
        &decision.reason,
        "/ws/{user_id}",
    )
    .await;
    if !decision.allowed {
        tracing::warn!(
            user_id = scope.user_id,
            identity_card_id = scope.identity_card_id,
            user_card_id,
            conversation_id,
            requested_frame_action = action,
            reason = %decision.reason,
            "fresh WebSocket chat_message authorization denied"
        );
    }
    if !decision.allowed {
        return Ok(false);
    }
    let sod = astral_db::check_sod_conflict_with_context(
        &state.db,
        &policy_ctx,
        policy_ctx.resource_owner_id,
    )
    .await
    .map_err(|error| {
        astral_types::AstralError::Database(format!("WebSocket SoD proof unavailable: {error}"))
    })?;
    if sod.has_conflict {
        return Ok(false);
    }
    if let Some((hub, fence)) = hub.zip(fence) {
        if !hub.authority_fence_matches(fence) {
            return Ok(false);
        }
    }
    Ok(!state.connections.is_closing())
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

    let fact = match tokio::time::timeout(
        std::time::Duration::from_secs(3),
        astral_db::load_active_platform_access_session_fact(
            &state.db,
            &scope.token_id,
            scope.identity_card_id,
        ),
    )
    .await
    {
        Ok(Ok(Some(fact))) => fact,
        _ => return false,
    };
    let Some(expires_at) = fact.jti_expires_at_epoch_second else {
        return false;
    };
    let bind = astral_common::session_projection_store::SessionBindContext {
        user_id: scope.user_id,
        session_id: fact.session_id,
        session_version: fact.session_version,
        session_epoch: fact.session_epoch,
        token_family_id: fact.family_id,
        principal_kind: scope.principal_kind.as_str(),
        identity_card_id: Some(scope.identity_card_id),
        user_card_id: Some(user_card_id),
        user_card_tenant_id: Some(tenant_id),
        user_card_domain_id: Some(domain_id),
        expires_at_epoch_second: expires_at,
    };
    if astral_common::session_projection_store::evaluate_access_fact(&fact, &bind).is_err() {
        return false;
    }
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
    async fn legacy_unbounded_registration_is_retained_but_not_admitted() {
        let pool = ConnectionPool::new();
        let card = scope(701, 20);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        pool.register(&card, tx.clone()).await;
        pool.send_to_scope(&card.chat_scope(), "legacy").await;
        assert!(rx.try_recv().is_err());
        assert!(pool.connections.read().await.is_empty());
        pool.unregister(&card, &tx).await;
    }

    #[tokio::test]
    async fn connection_pool_isolates_same_user_across_cards_with_bounded_queues() {
        let pool = ConnectionPool::new();
        let card_a = scope(701, 20);
        let card_b = scope(702, 21);
        let (tx_a, mut rx_a) = tokio::sync::mpsc::channel(2);
        let (tx_b, mut rx_b) = tokio::sync::mpsc::channel(2);
        pool.register_bounded(&card_a, tx_a).await;
        pool.register_bounded(&card_b, tx_b).await;

        pool.try_send_to_scope(&card_a.chat_scope(), "card-a").await;

        assert_eq!(rx_a.recv().await.as_deref(), Some("card-a"));
        assert!(rx_b.try_recv().is_err());
    }

    #[tokio::test]
    async fn connection_pool_broadcasts_to_same_physical_scope_only() {
        let pool = ConnectionPool::new();
        let card = scope(701, 20);
        let other = scope(702, 20);
        let (tx_one, mut rx_one) = tokio::sync::mpsc::channel(2);
        let (tx_two, mut rx_two) = tokio::sync::mpsc::channel(2);
        let (tx_other, mut rx_other) = tokio::sync::mpsc::channel(2);
        pool.register_bounded(&card, tx_one).await;
        pool.register_bounded(&card, tx_two).await;
        pool.register_bounded(&other, tx_other).await;

        pool.try_send_to_scope(&card.chat_scope(), "same-card")
            .await;

        assert_eq!(rx_one.recv().await.as_deref(), Some("same-card"));
        assert_eq!(rx_two.recv().await.as_deref(), Some("same-card"));
        assert!(rx_other.try_recv().is_err());
    }

    #[tokio::test]
    async fn full_bounded_queue_cancels_the_actual_socket_owner() {
        let pool = ConnectionPool::new();
        let card = scope(701, 20);
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let (cancel_tx, mut cancel_rx) = tokio::sync::watch::channel(false);
        pool.register_with_cancel(&card, tx, cancel_tx).await;
        assert_eq!(
            pool.try_send_to_scope(&card.chat_scope(), "one").await,
            PushOutcome::Queued
        );
        assert_eq!(
            pool.try_send_to_scope(&card.chat_scope(), "two").await,
            PushOutcome::Backpressure
        );
        assert!(cancel_rx.changed().await.is_ok());
        assert!(*cancel_rx.borrow());
    }

    #[tokio::test]
    async fn shutdown_closes_connections_and_rejects_late_registration() {
        let pool = ConnectionPool::new();
        let card = scope(701, 20);
        let (tx, _) = tokio::sync::mpsc::channel(1);
        let (cancel, cancel_rx) = tokio::sync::watch::channel(false);
        pool.register_with_cancel(&card, tx, cancel).await;
        pool.close_all().await;
        assert!(pool.is_closing());
        assert!(*cancel_rx.borrow());
        let (late_tx, _) = tokio::sync::mpsc::channel(1);
        let (late_cancel, late_rx) = tokio::sync::watch::channel(false);
        pool.register_with_cancel(&card, late_tx, late_cancel).await;
        assert!(*late_rx.borrow());
        assert!(pool.connections.read().await.is_empty());
        assert_eq!(
            pool.try_send_to_scope(&card.chat_scope(), "after-close")
                .await,
            PushOutcome::Closed
        );
    }

    #[tokio::test]
    async fn socket_drain_requires_owner_exit_and_preserves_cancellation() {
        let pool = ConnectionPool::new();
        let owner = pool.admit_socket().await.unwrap();
        pool.close_all().await;
        assert!(pool.admit_socket().await.is_none());
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(10),
            pool.drain_sockets(std::time::Duration::from_secs(1)),
        )
        .await
        .is_err());
        owner.complete();
        pool.drain_sockets(std::time::Duration::from_secs(1))
            .await
            .unwrap();

        let pool = ConnectionPool::new();
        let owner = pool.admit_socket().await.unwrap();
        drop(owner);
        pool.close_all().await;
        assert!(pool
            .drain_sockets(std::time::Duration::from_secs(1))
            .await
            .is_err());
    }

    #[test]
    fn queued_frames_require_current_policy_or_session() {
        assert_eq!(
            queued_frame_admission(r#"{"message_type":"NEW_MESSAGE","conversation_id":9}"#),
            Some(QueuedFrameAdmission::Conversation {
                id: 9,
                action: "read"
            })
        );
        assert_eq!(
            queued_frame_admission(r#"{"messageType":"TEXT","conversationId":9}"#),
            Some(QueuedFrameAdmission::Conversation {
                id: 9,
                action: "read"
            })
        );
        assert_eq!(
            queued_frame_admission(r#"{"message_type":"MESSAGE_ACCEPTED","conversation_id":9}"#),
            Some(QueuedFrameAdmission::Conversation {
                id: 9,
                action: "create"
            })
        );
        assert_eq!(
            queued_frame_admission(r#"{"message_type":"ERROR"}"#),
            Some(QueuedFrameAdmission::Session)
        );
        for denied in [
            r#"{"message_type":"NEW_MESSAGE"}"#,
            r#"{"message_type":"NEW_MESSAGE","conversation_id":0}"#,
            r#"{"message_type":"UNKNOWN","conversation_id":9}"#,
            "not-json",
        ] {
            assert!(queued_frame_admission(denied).is_none());
        }
        let source = include_str!("realtime.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let outbound = source
            .split("msg = rx.recv() =>")
            .nth(1)
            .unwrap()
            .split("ws_msg = socket.recv() =>")
            .next()
            .unwrap();
        assert!(
            outbound.find("authorize_queued_frame(").unwrap()
                < outbound.find("socket.send(Message::Text(").unwrap()
        );
        let upgrade = source
            .split("async fn ws_handler(")
            .nth(1)
            .unwrap()
            .split("async fn handle_socket(")
            .next()
            .unwrap();
        assert!(
            upgrade.find("authenticate_ws(").unwrap()
                < upgrade.find("authority_fence_matches(").unwrap()
        );
    }

    #[test]
    fn ws_action_admission_pins_session_sod_and_final_authority_fence() {
        let source = include_str!("realtime.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let action = source
            .split("async fn fresh_chat_permission(")
            .nth(1)
            .unwrap()
            .split("async fn revalidate_ws_scope(")
            .next()
            .unwrap();
        let capture = action.find("capture_authority_fence()").unwrap();
        let session = action.find("revalidate_ws_scope(").unwrap();
        let policy = action.find(".evaluate(").unwrap();
        let sod = action.find("check_sod_conflict_with_context(").unwrap();
        let final_fence = action.find("authority_fence_matches(").unwrap();
        assert!(capture < session && session < policy && policy < sod && sod < final_fence);
        assert!(source.contains("load_active_platform_access_session_fact("));
        assert!(source.contains("evaluate_access_fact("));
        assert!(source.contains(".mark_read(&scope.chat_scope()"));
    }

    #[test]
    fn canonical_ws_policy_actions_are_explicit() {
        assert_eq!(canonical_ws_action("TEXT"), Some("create"));
        assert_eq!(canonical_ws_action("IMAGE"), Some("create"));
        assert_eq!(canonical_ws_action("PING"), Some("read"));
        assert_eq!(canonical_ws_action("TYPING"), Some("read"));
        assert_eq!(canonical_ws_action("READ_RECEIPT"), Some("update"));
        assert_eq!(canonical_ws_action("UNKNOWN"), None);
    }
}
