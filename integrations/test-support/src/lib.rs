//! Isolated protocol runner, not a replacement for platform integration evidence.

use std::collections::BTreeSet;
use std::sync::{
    atomic::{AtomicU8, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use astral_sdk_contracts::{
    sign_decision, verify_request, ApplicationManifest, AuthorizationDecision, DecisionOutcome,
    ExternalSubject, SignedAuthorizationRequest,
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::json;
use tokio::net::TcpListener;

#[derive(Clone)]
pub struct TestApplication {
    pub manifest: ApplicationManifest,
    pub subject: ExternalSubject,
    pub tenant: String,
    pub domain: String,
}

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum Fault {
    None = 0,
    Pending,
    Deny,
    MissingMapping,
    DisabledMapping,
    StaleSession,
    BadSignature,
    BadScope,
    Expired,
    WrongTrace,
    BadEnvelope,
    Oversized,
    Timeout,
    Redirect,
}

pub struct TestDecisionServer {
    pub address: String,
    pub app_key: Arc<SigningKey>,
    pub decision_key: Arc<SigningKey>,
    pub decision_key_id: String,
    mode: Arc<AtomicU8>,
    requests: Arc<AtomicUsize>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

#[derive(Clone)]
struct ServerState {
    app_key: VerifyingKey,
    decision_key: Arc<SigningKey>,
    application: TestApplication,
    mode: Arc<AtomicU8>,
    requests: Arc<AtomicUsize>,
    nonces: Arc<Mutex<BTreeSet<String>>>,
}

impl TestDecisionServer {
    pub async fn start(
        application: TestApplication,
        app_key: SigningKey,
        decision_key: SigningKey,
    ) -> Self {
        application.manifest.validate().unwrap();
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let (tx, rx) = tokio::sync::oneshot::channel();
        let state = ServerState {
            app_key: app_key.verifying_key(),
            decision_key: Arc::new(decision_key),
            application,
            mode: Arc::new(AtomicU8::new(Fault::None as u8)),
            requests: Arc::new(AtomicUsize::new(0)),
            nonces: Arc::new(Mutex::new(BTreeSet::new())),
        };
        let router = Router::new()
            .route(astral_sdk_contracts::AUTHORIZATION_PATH, post(decision))
            .layer(axum::extract::DefaultBodyLimit::max(65536))
            .with_state(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await
                .unwrap();
        });
        Self {
            address,
            app_key: Arc::new(app_key),
            decision_key: state.decision_key,
            decision_key_id: "test-decision".into(),
            mode: state.mode,
            requests: state.requests,
            shutdown: Some(tx),
            task,
        }
    }

    pub fn set_fault(&self, mode: Fault) {
        self.mode.store(mode as u8, Ordering::SeqCst);
    }
    pub fn request_count(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if tokio::time::timeout(Duration::from_secs(2), &mut self.task)
            .await
            .is_err()
        {
            self.task.abort();
        }
    }
}

impl Drop for TestDecisionServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        self.task.abort();
    }
}

pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

async fn decision(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(signed): Json<SignedAuthorizationRequest>,
) -> Response {
    state.requests.fetch_add(1, Ordering::SeqCst);
    let req = &signed.request;
    if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some("Bearer test-bearer")
        || req.session_token_id != "test-session"
        || req.subject != state.application.subject
        || req.app_id != state.application.manifest.app_id
        || req.key_id != "test-app"
        || req.manifest_digest != state.application.manifest.digest().unwrap()
        || req.revision != state.application.manifest.revision
        || !state.application.manifest.permits_request(req)
        || req.facts.external_tenant_id != state.application.tenant
        || req.facts.external_domain_id != state.application.domain
        || req.validate_at(now_millis()).is_err()
        || verify_request(&state.app_key, req, &signed.signature).is_err()
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    {
        let mut nonces = state.nonces.lock().unwrap();
        if nonces.len() >= 1024 || !nonces.insert(req.nonce.clone()) {
            return StatusCode::FORBIDDEN.into_response();
        }
    }
    let mode = state.mode.load(Ordering::SeqCst);
    if [
        Fault::MissingMapping,
        Fault::DisabledMapping,
        Fault::StaleSession,
    ]
    .iter()
    .any(|v| mode == *v as u8)
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    if mode == Fault::Timeout as u8 {
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    if mode == Fault::Redirect as u8 {
        return (
            StatusCode::TEMPORARY_REDIRECT,
            [("location", "/unexpected")],
        )
            .into_response();
    }
    if mode == Fault::Oversized as u8 {
        return "x".repeat(70000).into_response();
    }
    let outcome = if mode == Fault::Pending as u8 {
        DecisionOutcome::Pending
    } else if mode == Fault::Deny as u8 {
        DecisionOutcome::Deny
    } else {
        DecisionOutcome::Allow
    };
    let now = now_millis();
    let mut decision =
        AuthorizationDecision::bound_to(req, "mapping-1", outcome, None, now).unwrap();
    if mode == Fault::Expired as u8 {
        decision.issued_at_ms = now - 6000;
        decision.expires_at_ms = now - 1000;
    }
    if mode == Fault::BadScope as u8 {
        decision.scope.external_tenant_id = "foreign".into();
    }
    let key = if mode == Fault::BadSignature as u8 {
        SigningKey::from_bytes(&[99; 32])
    } else {
        state.decision_key.as_ref().clone()
    };
    let signed_decision = sign_decision("test-decision", &key, decision).unwrap();
    let trace = if mode == Fault::WrongTrace as u8 {
        "wrong-request"
    } else {
        &req.request_id
    };
    Json(
        json!({ "success": mode != Fault::BadEnvelope as u8, "code": 200,
        "message": "test only", "data": signed_decision, "timestamp": (now / 1000) as i64,
        "traceId": trace }),
    )
    .into_response()
}
