//! memory—v1: In-process candidate request-chain integration, not production E2E.
//!
//! Authentication, signing, candidate identity and business work are test fixtures.
//! No listener, database, production JWT/session or source-IP check is exercised.
//! The UUID candidate identity is independent of the legacy policy context;
//! candidate inspection is not authentication or authorization.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex, OnceLock,
};
use std::time::{SystemTime, UNIX_EPOCH};

use astral_authorization_root::memory_v1_db_rows::{
    BinaryId, CandidateRows, IdentityCardRow, TenantRow, UserCardRow, UserRow,
};
use astral_authorization_root::memory_v1_hamt::CandidateBudget;
use astral_authorization_root::memory_v1_request::RequestRootScope;
use astral_authorization_root::memory_v1_root::{
    install_process_root, RequestRootReader, RootHandle, RootStatus,
};
use astral_common::config::{AppConfig, GatewayCfg};
use astral_common::middleware::gateway_signature::{
    compute_hmac_signature_v3, gateway_signature_middleware,
};
use astral_common::middleware::permission_check_shared::physical_policy_context;
use astral_gateway::middleware::sanitize_internal_auth_headers;
use astral_types::memory_v1::{CandidateIdentity, MemoryId};
use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::{routing::get, Router};
use policy_engine::memory_v1_candidate::{inspect_typed_request_candidate, CandidateInspection};
use policy_engine::PolicyEngine;
use tower::ServiceExt;
use uuid::Uuid;

const PATH: &str = "/candidate-request-chain";
const BEARER: &str = "Bearer isolated-fixture";

// These modes are injected into request extensions by the test, not by clients.
#[derive(Clone, Copy)]
enum FixtureMode {
    Normal,
    WrongSignature,
    CrossTenant,
}

#[derive(Default)]
struct Observations {
    sanitized: AtomicUsize,
    handlers: AtomicUsize,
    evaluations: AtomicUsize,
    business_effects: AtomicUsize,
    inspections: Mutex<Vec<CandidateInspection>>,
}

// memory—v1: Supply a synthetic key only for this in-process test.
fn fixture_secret() -> String {
    static SECRET: OnceLock<String> = OnceLock::new();
    SECRET.get_or_init(|| Uuid::new_v4().to_string()).clone()
}

// memory—v1: The verifier receives the same synthetic configuration as the signer.
fn fixture_config() -> AppConfig {
    AppConfig {
        gateway: GatewayCfg {
            hmac_secret: fixture_secret(),
            timestamp_tolerance_secs: 30,
            trusted_proxy_ips: vec![],
        },
        ..Default::default()
    }
}

// memory—v1: Independent candidate values, not derived from the legacy headers.
const USER: BinaryId = [1; 16];
const IDENTITY_CARD: BinaryId = [2; 16];
const TENANT: BinaryId = [3; 16];
const USER_CARD: BinaryId = [4; 16];
const OTHER_TENANT: BinaryId = [7; 16];

// memory—v1: This synthetic identity is not evidence of a verified session.
fn candidate_identity(mode: FixtureMode) -> CandidateIdentity {
    CandidateIdentity {
        user_id: MemoryId::from_bytes(USER),
        identity_card_id: MemoryId::from_bytes(IDENTITY_CARD),
        user_card_id: MemoryId::from_bytes(USER_CARD),
        tenant_id: MemoryId::from_bytes(if matches!(mode, FixtureMode::CrossTenant) {
            OTHER_TENANT
        } else {
            TENANT
        }),
    }
}

// memory—v1: Emulate authentication and signing solely to connect real middleware.
async fn test_authentication_and_signing(mut req: Request, next: Next) -> Response {
    let observations = Arc::clone(req.extensions().get::<Arc<Observations>>().unwrap());
    for name in [
        "x-user-id",
        "x-identity-card-id",
        "x-user-card-id",
        "x-user-card-tenant-id",
        "x-gateway-auth",
        "x-gateway-ts",
        "x-gateway-signature",
        "x-original-path",
        "x-resource-owner-id",
        "x-user-forged-extra",
    ] {
        assert!(
            !req.headers().contains_key(name),
            "sanitizer retained {name}"
        );
    }
    observations.sanitized.fetch_add(1, Ordering::SeqCst);
    if req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        != Some(BEARER)
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let mode = *req.extensions().get::<FixtureMode>().unwrap();
    let tenant = if matches!(mode, FixtureMode::CrossTenant) {
        "47"
    } else {
        "46"
    };
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .to_string();
    let secret = if matches!(mode, FixtureMode::WrongSignature) {
        format!("{}-wrong", fixture_secret())
    } else {
        fixture_secret()
    };
    let signature = compute_hmac_signature_v3(
        &secret,
        req.method().as_str(),
        req.uri().path(),
        "42",
        "PLATFORM_USER",
        "fixture-token",
        "43",
        "44",
        "45",
        tenant,
        "ACCESS",
        "2",
        "read",
        "",
        &timestamp,
    );
    for (name, value) in [
        ("x-gateway-auth", "verified"),
        ("x-gateway-ts", timestamp.as_str()),
        ("x-gateway-signature", signature.as_str()),
        ("x-user-id", "42"),
        ("x-principal-kind", "PLATFORM_USER"),
        ("x-token-id", "fixture-token"),
        ("x-identity-card-id", "43"),
        ("x-user-card-id", "44"),
        ("x-user-card-domain-id", "45"),
        ("x-user-card-tenant-id", tenant),
        ("x-token-use", "ACCESS"),
        ("x-claims-version", "2"),
        ("x-action-codes", "read"),
    ] {
        req.headers_mut().insert(
            axum::http::header::HeaderName::from_static(name),
            value.parse().unwrap(),
        );
    }
    next.run(req).await
}

// memory—v1: A local identity component borrows the request reader.
fn local_identity_component(reader: &RequestRootReader, identity: &CandidateIdentity) -> BinaryId {
    reader
        .read_card(identity.user_card_id.into_bytes(), |view| {
            view.identity.identity_card_id
        })
        .unwrap()
}

// memory—v1: A second local component borrows the very same request reader.
fn local_tenant_component(reader: &RequestRootReader, identity: &CandidateIdentity) -> BinaryId {
    reader
        .read_card(identity.user_card_id.into_bytes(), |view| {
            view.tenant.tenant_id
        })
        .unwrap()
}

// memory—v1: Inspect the fixture identity on the reader also passed to formal evaluation.
async fn candidate_handler(
    headers: HeaderMap,
    mode: FixtureMode,
    handle: RootHandle,
    observations: Arc<Observations>,
) -> StatusCode {
    observations.handlers.fetch_add(1, Ordering::SeqCst);
    let policy_context =
        physical_policy_context(&headers, "fixture_resource", "read", Some(42)).unwrap();
    let identity = candidate_identity(mode);
    let request_id = Uuid::new_v4();
    let scope = RequestRootScope::new(handle, request_id);
    let extension = scope.extension();
    let inspection = extension
        .with_reader(|reader| {
            assert_eq!(reader.request_id(), request_id);
            assert_eq!(reader.metadata().status, RootStatus::Candidate);
            assert_eq!(local_identity_component(reader, &identity), IDENTITY_CARD);
            assert_eq!(local_tenant_component(reader, &identity), TENANT);
            inspect_typed_request_candidate(reader, &identity)
        })
        .unwrap();
    observations.inspections.lock().unwrap().push(inspection);

    observations.evaluations.fetch_add(1, Ordering::SeqCst);
    let decision = PolicyEngine::new()
        .evaluate_with_request_root_and_candidate_identity(&policy_context, extension, identity)
        .await;
    if decision.allowed {
        observations.business_effects.fetch_add(1, Ordering::SeqCst);
        StatusCode::OK
    } else {
        assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
        StatusCode::SERVICE_UNAVAILABLE
    }
}

// memory—v1: Build the real sanitizer and verifier around explicitly synthetic auth.
fn app(handle: RootHandle, observations: Arc<Observations>) -> Router {
    Router::new()
        .route(
            PATH,
            get(
                move |headers: HeaderMap, axum::Extension(mode): axum::Extension<FixtureMode>| {
                    candidate_handler(headers, mode, handle.clone(), Arc::clone(&observations))
                },
            ),
        )
        .layer(middleware::from_fn_with_state(
            fixture_config(),
            gateway_signature_middleware,
        ))
        .layer(middleware::from_fn(test_authentication_and_signing))
        .layer(middleware::from_fn(sanitize_internal_auth_headers))
}

// memory—v1: Submit client-controlled forged headers and out-of-band fixture mode.
fn request(mode: FixtureMode, authenticated: bool, observations: Arc<Observations>) -> Request {
    let mut builder = Request::builder().uri(PATH);
    for name in [
        "x-user-id",
        "x-identity-card-id",
        "x-user-card-id",
        "x-user-card-tenant-id",
        "x-gateway-auth",
        "x-gateway-ts",
        "x-gateway-signature",
        "x-original-path",
        "x-resource-owner-id",
        "x-user-forged-extra",
    ] {
        builder = builder.header(name, "forged");
    }
    if authenticated {
        builder = builder.header("authorization", BEARER);
    }
    let mut request = builder.body(Body::empty()).unwrap();
    request.extensions_mut().insert(mode);
    request.extensions_mut().insert(observations);
    request
}

// memory—v1: One test process installs exactly one candidate root and exercises all paths.
#[tokio::test]
async fn isolated_gateway_to_shared_candidate_reader_stays_pending() {
    let rows = CandidateRows {
        users: vec![UserRow { user_id: USER }],
        identity_cards: vec![IdentityCardRow {
            identity_card_id: IDENTITY_CARD,
            user_id: USER,
        }],
        tenants: vec![
            TenantRow {
                tenant_id: TENANT,
                parent_tenant_id: None,
            },
            TenantRow {
                tenant_id: OTHER_TENANT,
                parent_tenant_id: None,
            },
        ],
        user_cards: vec![UserCardRow {
            user_card_id: USER_CARD,
            user_id: USER,
            tenant_id: TENANT,
            status: astral_authorization_root::memory_v1_db_rows::UserCardStatus::Active,
        }],
        ..CandidateRows::default()
    };
    let owner = install_process_root(
        rows,
        vec![],
        CandidateBudget {
            max_table_rows: 16,
            max_bindings_per_read: 4,
        },
    )
    .unwrap();
    let observations = Arc::new(Observations::default());
    let app = app(owner.handle(), Arc::clone(&observations));

    for (mode, authenticated, expected) in [
        (FixtureMode::Normal, false, StatusCode::UNAUTHORIZED),
        (FixtureMode::WrongSignature, true, StatusCode::FORBIDDEN),
        (FixtureMode::Normal, true, StatusCode::SERVICE_UNAVAILABLE),
        (
            FixtureMode::CrossTenant,
            true,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
    ] {
        let response = app
            .clone()
            .oneshot(request(mode, authenticated, Arc::clone(&observations)))
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    assert_eq!(observations.sanitized.load(Ordering::SeqCst), 4);
    assert_eq!(observations.handlers.load(Ordering::SeqCst), 2);
    assert_eq!(observations.evaluations.load(Ordering::SeqCst), 2);
    assert_eq!(observations.business_effects.load(Ordering::SeqCst), 0);
    assert_eq!(
        *observations.inspections.lock().unwrap(),
        vec![
            CandidateInspection::Unverified,
            CandidateInspection::IdentityMismatch
        ],
    );
}
