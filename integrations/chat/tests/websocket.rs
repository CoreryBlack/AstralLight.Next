use astral_chat_sdk_sample::{actor, manifest, ChatStore, Conversation};
use astral_sdk::{AccessToken, ClientConfig, SdkClient};
use astral_sdk_contracts::{AuthorizationRequest, SignedAuthorizationRequest};
use astral_sdk_test_support::{now_millis, TestApplication, TestDecisionServer};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::Response,
    routing::get,
    Router,
};
use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use std::{
    collections::BTreeSet,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

#[derive(Clone)]
struct SocketState {
    store: Arc<Mutex<ChatStore>>,
    client: Arc<SdkClient>,
    app_key: Arc<SigningKey>,
    sequence: Arc<AtomicUsize>,
}
fn request(state: &SocketState, handshake: bool) -> AuthorizationRequest {
    let sequence = state.sequence.fetch_add(1, Ordering::SeqCst);
    let facts = if handshake {
        state.store.lock().unwrap().handshake_facts(1)
    } else {
        state.store.lock().unwrap().facts(1)
    }
    .unwrap();
    AuthorizationRequest {
        app_id: "astral-chat".into(),
        key_id: "test-app".into(),
        manifest_digest: manifest().digest().unwrap(),
        revision: "1".into(),
        request_id: format!("request-{sequence}"),
        nonce: format!("abcdefghijkl12345678{sequence:04}"),
        timestamp: now_millis(),
        session_token_id: "test-session".into(),
        subject: actor("member-a"),
        method: if handshake { "GET" } else { "POST" }.into(),
        path: if handshake {
            "/conversations/1/socket"
        } else {
            "/conversations/1/messages"
        }
        .into(),
        action: if handshake { "read" } else { "create" }.into(),
        operation_id: format!("message-{sequence}"),
        facts,
    }
}
async fn upgrade(State(state): State<SocketState>, upgrade: WebSocketUpgrade) -> Response {
    upgrade
        .max_message_size(4096)
        .on_upgrade(move |socket| frames(state, socket))
}
async fn frames(state: SocketState, mut socket: WebSocket) {
    let signed = SignedAuthorizationRequest::sign(&state.app_key, request(&state, true)).unwrap();
    let proof = state
        .client
        .authorize(&signed, &AccessToken::new("test-bearer").unwrap())
        .await;
    if !proof.is_ok_and(|proof| {
        state
            .store
            .lock()
            .unwrap()
            .handshake(&signed.request, proof)
            .is_ok()
    }) {
        let _ = socket.send(Message::Text("DENIED".into())).await;
        return;
    }
    socket.send(Message::Text("READY".into())).await.unwrap();
    while let Some(Ok(Message::Text(content))) = socket.next().await {
        let signed =
            SignedAuthorizationRequest::sign(&state.app_key, request(&state, false)).unwrap();
        let proof = state
            .client
            .authorize(&signed, &AccessToken::new("test-bearer").unwrap())
            .await;
        let accepted = proof.is_ok_and(|proof| {
            state
                .store
                .lock()
                .unwrap()
                .send(&signed.request, proof, &content)
                .is_ok()
        });
        socket
            .send(Message::Text(
                if accepted { "ACCEPTED" } else { "DENIED" }.into(),
            ))
            .await
            .unwrap();
        if !accepted {
            break;
        }
    }
}
struct Runner(tokio::task::JoinHandle<()>);
impl Drop for Runner {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::test]
async fn websocket_checks_handshake_every_frame_and_reconnect_after_revocation() {
    let server = TestDecisionServer::start(
        TestApplication {
            manifest: manifest(),
            subject: actor("member-a"),
            tenant: "tenant-a".into(),
            domain: "chat".into(),
        },
        SigningKey::from_bytes(&[61; 32]),
        SigningKey::from_bytes(&[62; 32]),
    )
    .await;
    let client = Arc::new(
        SdkClient::new(
            ClientConfig::new(
                server.address.parse().unwrap(),
                Duration::from_secs(2),
                65536,
                &server.decision_key_id,
                server.decision_key.verifying_key(),
            )
            .with_insecure_loopback_http(true),
        )
        .unwrap(),
    );
    let mut store = ChatStore::default();
    store
        .insert(Conversation {
            id: 1,
            tenant: "tenant-a".into(),
            domain: "chat".into(),
            revision: 1,
            members: BTreeSet::from(["member-a".into()]),
        })
        .unwrap();
    let state = SocketState {
        store: Arc::new(Mutex::new(store)),
        client,
        app_key: server.app_key.clone(),
        sequence: Arc::new(AtomicUsize::new(1)),
    };
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let url = format!("ws://{}/socket", listener.local_addr().unwrap());
    let router = Router::new()
        .route("/socket", get(upgrade))
        .with_state(state.clone());
    let runner = Runner(tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    }));
    let exercise = async {
        let (mut socket, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "READY"
        );
        socket
            .send(tokio_tungstenite::tungstenite::Message::Text(
                "hello".into(),
            ))
            .await
            .unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "ACCEPTED"
        );
        state
            .store
            .lock()
            .unwrap()
            .revoke_member(1, "member-a")
            .unwrap();
        socket
            .send(tokio_tungstenite::tungstenite::Message::Text(
                "blocked".into(),
            ))
            .await
            .unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "DENIED"
        );
        let (mut reconnect, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
        assert_eq!(
            reconnect
                .next()
                .await
                .unwrap()
                .unwrap()
                .into_text()
                .unwrap(),
            "DENIED"
        );
        assert_eq!(state.store.lock().unwrap().message_count(), 1);
        assert_eq!(server.request_count(), 4);
    };
    tokio::time::timeout(Duration::from_secs(5), exercise)
        .await
        .unwrap();
    drop(runner);
    server.stop().await;
}
