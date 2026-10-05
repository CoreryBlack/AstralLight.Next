use astral_learn_sdk_sample::{actor, manifest, Course, CourseScope, LearnStore};
use astral_sdk::{AccessToken, ClientConfig, SdkClient};
use astral_sdk_axum::{
    ActorResolver, ApplicationBinding, AuthenticatedActor, AuthorizationLayer,
    AuthorizedRequestExtension, ResolveError, ResourceFactsResolver, ResourceRequest,
};
use astral_sdk_contracts::{ManifestRoute, ResourceFacts};
use astral_sdk_test_support::{TestApplication, TestDecisionServer};
use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Router,
};
use ed25519_dalek::SigningKey;
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};
use tower::ServiceExt;

struct Actor;
impl ActorResolver for Actor {
    fn resolve<'a>(
        &'a self,
        _headers: &'a HeaderMap,
    ) -> Pin<Box<dyn Future<Output = Result<AuthenticatedActor, ResolveError>> + Send + 'a>> {
        Box::pin(async {
            Ok(AuthenticatedActor {
                subject: actor("teacher-a"),
                session_token_id: "test-session".into(),
                gateway_access_token: AccessToken::new("test-bearer").unwrap(),
            })
        })
    }
}
struct Facts(Arc<Mutex<LearnStore>>);
impl ResourceFactsResolver for Facts {
    fn resolve<'a>(
        &'a self,
        _route: &'a ManifestRoute,
        request: &'a ResourceRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ResourceFacts, ResolveError>> + Send + 'a>> {
        Box::pin(async move {
            let id = request
                .uri
                .path()
                .split('/')
                .nth(2)
                .and_then(|id| id.parse().ok())
                .ok_or(ResolveError::Unauthenticated)?;
            self.0
                .lock()
                .unwrap()
                .facts(id)
                .map_err(|_| ResolveError::Unauthenticated)
        })
    }
}
async fn publish(
    State(store): State<Arc<Mutex<LearnStore>>>,
    extension: AuthorizedRequestExtension,
) -> StatusCode {
    let authorized = extension.take().unwrap();
    assert!(extension.take().is_err(), "proof can be taken only once");
    let (request, proof) = authorized.into_parts();
    match store.lock().unwrap().publish(&request, proof) {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::CONFLICT,
    }
}

#[tokio::test]
async fn central_adapter_consumes_http_proof_and_blocks_undeclared_methods() {
    let server = TestDecisionServer::start(
        TestApplication {
            manifest: manifest(),
            subject: actor("teacher-a"),
            tenant: "school-a".into(),
            domain: "courses".into(),
        },
        SigningKey::from_bytes(&[51; 32]),
        SigningKey::from_bytes(&[52; 32]),
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
    let mut store = LearnStore::default();
    store
        .insert_scope(CourseScope {
            id: 1,
            tenant: "school-a".into(),
            domain: "courses".into(),
            revision: 1,
        })
        .unwrap();
    store
        .insert(Course {
            id: 1,
            scope_id: 1,
            owner: actor("teacher-a"),
            revision: 1,
            published: false,
        })
        .unwrap();
    let store = Arc::new(Mutex::new(store));
    let binding = Arc::new(ApplicationBinding {
        app_id: "astral-learn".into(),
        key_id: "test-app".into(),
        manifest: Arc::new(manifest()),
        signing_key: server.app_key.as_ref().clone(),
    });
    let layer = AuthorizationLayer::new(
        client,
        binding,
        Arc::new(Actor),
        Arc::new(Facts(store.clone())),
    )
    .unwrap()
    .public_route("GET", "/health")
    .unwrap();
    let router = Router::new()
        .route(
            "/courses/{id}/publish",
            post(publish).get(|| async { "must-be-denied" }),
        )
        .route("/health", get(|| async { "ok" }))
        .with_state(store.clone());
    let app = layer.layer(router);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/courses/1/publish")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/courses/1/publish")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(server.request_count(), 0);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/courses/1/publish")
                .header("x-operation-id", "publish-original")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(store.lock().unwrap().course(1).unwrap().published);
    assert_eq!(server.request_count(), 1);
    server.stop().await;
}
