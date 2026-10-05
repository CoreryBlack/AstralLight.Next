use super::*;
use axum::body::Body;
use axum::routing::get;
use std::sync::atomic::{AtomicBool, Ordering};
use tower::ServiceExt;

struct NeverResolve;

impl ActorResolver for NeverResolve {
    fn resolve<'a>(
        &'a self,
        _headers: &'a HeaderMap,
    ) -> Pin<Box<dyn Future<Output = Result<AuthenticatedActor, ResolveError>> + Send + 'a>> {
        Box::pin(async { Err(ResolveError::Unavailable) })
    }
}

struct NeverFacts;

impl ResourceFactsResolver for NeverFacts {
    fn resolve<'a>(
        &'a self,
        _route: &'a ManifestRoute,
        _request: &'a ResourceRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ResourceFacts, ResolveError>> + Send + 'a>> {
        Box::pin(async { Err(ResolveError::Unavailable) })
    }
}

fn client() -> Arc<SdkClient> {
    use ed25519_dalek::SigningKey;
    let public_key = SigningKey::from_bytes(&[6; 32]).verifying_key();
    let config = astral_sdk::ClientConfig::new(
        url::Url::parse("http://127.0.0.1:1").unwrap(),
        std::time::Duration::from_secs(1),
        1024,
        "decision_key",
        public_key,
    )
    .with_insecure_loopback_http(true);
    Arc::new(SdkClient::new(config).unwrap())
}

fn binding() -> Arc<ApplicationBinding> {
    use ed25519_dalek::SigningKey;
    let mut builder = ManifestBuilder::new("chat_app", "manifest-1");
    builder
        .ordinary(
            "GET",
            "/messages/{id}",
            "chat_message",
            None,
            ResourceOperation::ScopedCollection,
            ResourceResolver::ScopedCollection {
                target_id_path: "/{id}".into(),
            },
        )
        .unwrap();
    Arc::new(ApplicationBinding {
        app_id: "chat_app".into(),
        key_id: "client_key".into(),
        manifest: Arc::new(builder.build().unwrap()),
        signing_key: SigningKey::from_bytes(&[7; 32]),
    })
}

#[tokio::test]
async fn undeclared_route_is_denied_before_actor_or_handler() {
    let called = Arc::new(AtomicBool::new(false));
    let called_handler = called.clone();
    let router = axum::Router::new().route(
        "/undeclared",
        get(move || {
            let called = called_handler.clone();
            async move {
                called.store(true, Ordering::SeqCst);
                "should-not-run"
            }
        }),
    );
    let layer = AuthorizationLayer::new(
        client(),
        binding(),
        Arc::new(NeverResolve),
        Arc::new(NeverFacts),
    )
    .unwrap();
    let response = layer
        .layer(router)
        .oneshot(
            http::Request::builder()
                .uri("/undeclared")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(!called.load(Ordering::SeqCst));
}

#[test]
fn manifest_builder_fails_closed_and_requires_explicit_special_actions() {
    let mut missing_special = ManifestBuilder::new("chat_app", "manifest-1");
    assert!(missing_special
        .ordinary(
            "TRACE",
            "/messages/{id}",
            "chat_message",
            None,
            ResourceOperation::Object,
            ResourceResolver::Object {
                target_id_path: "/id".into(),
            },
        )
        .is_err());

    let mut duplicates = ManifestBuilder::new("chat_app", "manifest-1");
    duplicates
        .ordinary(
            "GET",
            "/messages/{id}",
            "chat_message",
            None,
            ResourceOperation::ScopedCollection,
            ResourceResolver::ScopedCollection {
                target_id_path: "/{id}".into(),
            },
        )
        .unwrap();
    assert!(duplicates
        .special(
            "GET",
            "/messages/{id}",
            "chat_message",
            "export",
            ResourceOperation::ScopedCollection,
            ResourceResolver::ScopedCollection {
                target_id_path: "/{id}".into()
            },
        )
        .is_err());
    assert!(ManifestBuilder::new("chat_app", "manifest-1")
        .build()
        .is_err());
}
