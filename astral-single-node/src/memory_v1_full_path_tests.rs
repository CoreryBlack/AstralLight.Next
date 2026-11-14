//! memory—v1: One full-path protected request through the real composition.
//!
//! Path under test: client → Gateway (internal-header sanitization, memory—v1
//! session authentication, budgeted request scope, session binding, signed
//! in-process dispatch) → TrustGraph (source and signature verification, the
//! memory—v1 permission guard) → `PolicyEngine::evaluate_memory_v1` on the
//! request's one reader with its final metadata/time recheck → the real route
//! handler → response → request scope and reader released.
//!
//! The root is a fixture adopted through the test-only `test-support` hook. This
//! proves the request-lifecycle wiring and its fail-closed refusals; it does not
//! prove database provenance, coverage, confirmer authority or production
//! adoption, and it opens no listener (requests are dispatched with `oneshot`).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use astral_authorization_root::memory_v1_db_rows::{
    BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, CurrentSelection,
    IdentityCardRow, RuleSetRow, RuleSetVersionRow, TenantRow, UserCardRow, UserRow,
};
use astral_authorization_root::memory_v1_hamt::CandidateBudget;
use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
use astral_authorization_root::memory_v1_request::{
    RequestRootAccessError, RequestRootExtension, RequestRootScope,
};
use astral_authorization_root::memory_v1_root::{
    install_process_root, RootHandle, RootMetadata, RootStatus,
};
use astral_authorization_root::memory_v1_rules::{
    canonical_version_bytes, MemoryV1OwnerScope, MemoryV1TenantScope,
};
use astral_common::config::AppConfig;
use astral_identity::runtime::memory_v1::{
    MemoryV1CredentialAuthenticator, MemoryV1CredentialRecord, MemoryV1CredentialRepository,
    MemoryV1CredentialRepositoryError, MemoryV1CredentialStatus, MemoryV1LoginError,
    MemoryV1LoginRequest,
};
use astral_identity::MemoryV1IdentitySession;
use astral_trustgraph::{build_memory_v1_offline_app_state, build_router, RouterIntegrationConfig};
use astral_types::memory_v1::MemoryId;
use axum::body::{to_bytes, Body};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::Router;
use policy_engine::PolicyEngine;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use super::MemoryV1Composition;

pub(crate) const REGISTRY: &str = "/main/api/v1/permission-rules/registry";

pub(crate) const ALICE: [u8; 16] = [0x11; 16];
const ALICE_IDENTITY: [u8; 16] = [0x12; 16];
pub(crate) const BOB: [u8; 16] = [0x21; 16];
const BOB_IDENTITY: [u8; 16] = [0x22; 16];
const TENANT: [u8; 16] = [0x13; 16];
pub(crate) const CARD_ALLOW: [u8; 16] = [0x31; 16];
pub(crate) const CARD_OVERLAY_DENY: [u8; 16] = [0x32; 16];
pub(crate) const CARD_UNBOUND: [u8; 16] = [0x33; 16];
pub(crate) const CARD_BOB: [u8; 16] = [0x34; 16];
const RULES_READ: [u8; 16] = [0x41; 16];
const RULES_DENY: [u8; 16] = [0x42; 16];

// memory—v1: Build one hashed version of the closed rule grammar.
fn version_row(rule_set_id: [u8; 16], content: &[u8]) -> RuleSetVersionRow {
    let version = vec![1];
    let timestamp = vec![1];
    let hash_input_bytes = canonical_version_bytes(&version, content, &timestamp);
    let hash_bytes = Sha256::digest(&hash_input_bytes).to_vec();
    RuleSetVersionRow {
        rule_set_id,
        version_bytes: version,
        content_bytes: content.to_vec(),
        timestamp_bytes: timestamp,
        hash_input_bytes,
        hash_bytes,
    }
}

// memory—v1: Two users with dual cards in one tenant; every binding is confirmed.
//
// Alice: CARD_ALLOW (BASE read), CARD_OVERLAY_DENY (BASE read + OVERLAY deny),
// CARD_UNBOUND (no binding). Bob: CARD_BOB (BASE read). The shared rule set
// RULES_READ is bound by three cards without being copied per card.
pub(crate) fn fixture() -> (CandidateRows, Vec<CurrentSelection>) {
    let read = br#"{"rules":[{"ruleId":"R7","resource":"permission_rule","action":"read","effect":"ALLOW"}]}"#;
    let deny = br#"{"rules":[{"ruleId":"R8","resource":"permission_rule","action":"read","effect":"DENY"}]}"#;
    let card = |user_card_id, user_id| UserCardRow {
        user_card_id,
        user_id,
        tenant_id: TENANT,
    };
    let bindings = [
        ([0x51; 16], CARD_ALLOW, RULES_READ, BindingLayer::Base),
        (
            [0x52; 16],
            CARD_OVERLAY_DENY,
            RULES_READ,
            BindingLayer::Base,
        ),
        (
            [0x53; 16],
            CARD_OVERLAY_DENY,
            RULES_DENY,
            BindingLayer::Overlay,
        ),
        ([0x54; 16], CARD_BOB, RULES_READ, BindingLayer::Base),
    ];
    let rows = CandidateRows {
        users: vec![UserRow { user_id: ALICE }, UserRow { user_id: BOB }],
        identity_cards: vec![
            IdentityCardRow {
                identity_card_id: ALICE_IDENTITY,
                user_id: ALICE,
            },
            IdentityCardRow {
                identity_card_id: BOB_IDENTITY,
                user_id: BOB,
            },
        ],
        tenants: vec![TenantRow {
            tenant_id: TENANT,
            parent_tenant_id: None,
        }],
        user_cards: vec![
            card(CARD_ALLOW, ALICE),
            card(CARD_OVERLAY_DENY, ALICE),
            card(CARD_UNBOUND, ALICE),
            card(CARD_BOB, BOB),
        ],
        rule_sets: vec![
            RuleSetRow {
                rule_set_id: RULES_READ,
                owner_tenant_id: TENANT,
            },
            RuleSetRow {
                rule_set_id: RULES_DENY,
                owner_tenant_id: TENANT,
            },
        ],
        rule_set_versions: vec![version_row(RULES_READ, read), version_row(RULES_DENY, deny)],
        bindings: bindings
            .iter()
            .map(
                |&(binding_id, user_card_id, rule_set_id, binding_layer)| BindingRow {
                    binding_id,
                    user_card_id,
                    rule_set_id,
                    binding_layer,
                    valid_from: None,
                    valid_until: None,
                    owner_scope: MemoryV1OwnerScope::default(),
                    tenant_scope: MemoryV1TenantScope::default(),
                },
            )
            .collect(),
        binding_confirmations: bindings
            .iter()
            .map(|&(binding_id, _, rule_set_id, _)| BindingConfirmationRow {
                confirmation_id: [binding_id[0] + 0x10; 16],
                binding_id,
                rule_set_id,
                version_bytes: vec![1],
                confirmer_user_id: ALICE,
                scope_bytes: vec![1],
                operation_id: vec![1],
                confirmed_at_bytes: vec![1],
            })
            .collect(),
        ..CandidateRows::default()
    };
    let selections = [RULES_READ, RULES_DENY]
        .into_iter()
        .map(|rule_set_id| CurrentSelection {
            rule_set_id,
            version_bytes: vec![1],
        })
        .collect();
    (rows, selections)
}

// memory—v1: In-memory UUID-native credentials for the Identity authenticator.
struct FixtureCredentials(Vec<(&'static str, MemoryV1CredentialRecord)>);

#[async_trait::async_trait]
impl MemoryV1CredentialRepository for FixtureCredentials {
    // memory—v1: Return the fixture record for an already normalized identifier.
    async fn find_by_identifier(
        &self,
        normalized_identifier: &str,
    ) -> Result<Option<MemoryV1CredentialRecord>, MemoryV1CredentialRepositoryError> {
        Ok(self
            .0
            .iter()
            .find(|(identifier, _)| *identifier == normalized_identifier)
            .map(|(_, record)| record.clone()))
    }
}

// memory—v1: Real password hashing and verification over fixture credentials.
fn authenticator() -> MemoryV1CredentialAuthenticator {
    let record = |user: [u8; 16], password: &str| {
        MemoryV1CredentialRecord::new(
            MemoryId::from_bytes(user),
            astral_identity::auth::hash_password(password).unwrap(),
            MemoryV1CredentialStatus::Active,
            1,
        )
    };
    MemoryV1CredentialAuthenticator::new(Arc::new(FixtureCredentials(vec![
        ("alice", record(ALICE, "alice-secret")),
        ("bob", record(BOB, "bob-secret")),
    ])))
}

// memory—v1: The trusted UTC clock used for session issuance in the fixture.
fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

// memory—v1: One Identity login lifecycle on its own request-scoped reader.
async fn login(
    session: &MemoryV1IdentitySession,
    authenticator: &MemoryV1CredentialAuthenticator,
    root: &RootHandle,
    identifier: &str,
    password: &str,
    card: [u8; 16],
) -> Result<String, MemoryV1LoginError> {
    let scope = RequestRootScope::new(root.clone(), uuid::Uuid::new_v4());
    let issued = session
        .login(
            authenticator,
            &scope.extension(),
            MemoryV1LoginRequest {
                identifier,
                password,
                user_card_id: MemoryId::from_bytes(card),
                now_unix_seconds: now(),
                lifetime_seconds: 300,
            },
        )
        .await?;
    Ok(issued.credential().to_owned())
}

/// What TrustGraph observed of one downstream request.
struct Observation {
    request_id_at_entry: uuid::Uuid,
    request_id_at_exit: uuid::Uuid,
    metadata: RootMetadata,
    forged_headers_absent: bool,
    bearer_absent: bool,
    root: RequestRootExtension,
}

type Observations = Arc<Mutex<Vec<Observation>>>;

// memory—v1: Observe a downstream request around the complete TrustGraph stack.
async fn observe(State(observations): State<Observations>, req: Request, next: Next) -> Response {
    let root = req
        .extensions()
        .get::<RequestRootExtension>()
        .cloned()
        .expect("in-process dispatch injects the request root scope");
    let (request_id_at_entry, metadata) = root
        .with_reader(|reader| (reader.request_id(), reader.metadata()))
        .expect("the request reader is readable at TrustGraph entry");
    let headers = req.headers();
    let forged_headers_absent = [
        "x-user-id",
        "x-principal-kind",
        "x-user-card-id",
        "x-identity-card-id",
        "x-user-card-tenant-id",
        "x-template-id",
    ]
    .iter()
    .all(|name| headers.get(*name).is_none());
    let bearer_absent = headers.get("authorization").is_none();
    let response = next.run(req).await;
    let request_id_at_exit = root
        .with_reader(|reader| reader.request_id())
        .expect("the scope outlives the downstream response");
    observations.lock().unwrap().push(Observation {
        request_id_at_entry,
        request_id_at_exit,
        metadata,
        forged_headers_absent,
        bearer_absent,
        root,
    });
    response
}

// memory—v1: A client request that also carries forged internal identity headers.
fn client_request(method: &str, path: &str, credential: Option<&str>) -> Request {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("x-user-id", "999")
        .header("x-principal-kind", "PLATFORM_USER")
        .header("x-user-card-id", "999")
        .header("x-identity-card-id", "999")
        .header("x-template-id", "7")
        .header("x-gateway-auth", "verified")
        .extension(ConnectInfo(SocketAddr::from((Ipv4Addr::LOCALHOST, 41000))));
    if let Some(credential) = credential {
        builder = builder.header("authorization", format!("Bearer {credential}"));
    }
    builder.body(Body::empty()).unwrap()
}

// memory—v1: Send one request through the composed Gateway and decode its body.
async fn send_to(
    router: &Router,
    method: &str,
    path: &str,
    credential: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let response = router
        .clone()
        .oneshot(client_request(method, path, credential))
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (
        status,
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
    )
}

// memory—v1: Send the full-path registry read.
async fn send(router: &Router, credential: Option<&str>) -> (StatusCode, serde_json::Value) {
    send_to(router, "GET", REGISTRY, credential).await
}

// memory—v1: Install the one process root in a child process, then run the lifecycle.
#[test]
fn full_path_lifecycle_request_isolated_process() {
    const CHILD: &str = "ASTRAL_MEMORY_V1_FULL_PATH_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "memory_v1_composition::full_path_tests::full_path_lifecycle_request_isolated_process",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .expect("failed to start the isolated test process");
        assert!(
            output.status.success(),
            "stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        return;
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(full_path_lifecycle());
}

// memory—v1: The acceptance scenario for the request-lifecycle reader.
async fn full_path_lifecycle() {
    let (rows, selections) = fixture();
    let owner = install_process_root(
        rows,
        selections,
        CandidateBudget {
            max_table_rows: 64,
            max_bindings_per_read: 8,
        },
    )
    .unwrap();
    let handle = owner.handle();
    let mut config = AppConfig::default();
    config.gateway.hmac_secret = uuid::Uuid::new_v4().to_string();
    let engine = Arc::new(PolicyEngine::new());
    let observations: Observations = Arc::default();
    let trustgraph = build_router(
        build_memory_v1_offline_app_state(config.clone(), Arc::clone(&engine)),
        RouterIntegrationConfig::disabled(),
    )
    .layer(middleware::from_fn_with_state(
        Arc::clone(&observations),
        observe,
    ));
    let identity_slot = Arc::new(OnceLock::new());
    let slot = Arc::clone(&identity_slot);
    let composition = MemoryV1Composition::new(
        owner,
        move |session| {
            slot.set(session).ok();
            Router::new()
        },
        trustgraph,
        config,
    );
    let identity: Arc<MemoryV1IdentitySession> = identity_slot
        .get()
        .cloned()
        .expect("the composition injects the Identity session boundary");
    let router = composition.router();
    let budget = composition.request_scope_budget();
    let credentials = authenticator();

    // 1. A candidate root backs neither a login nor any decision.
    assert_eq!(handle.metadata().unwrap().status, RootStatus::Candidate);
    assert_eq!(
        login(
            &identity,
            &credentials,
            &handle,
            "alice",
            "alice-secret",
            CARD_ALLOW
        )
        .await,
        Err(MemoryV1LoginError::Unavailable)
    );

    // 2. Adopt the fixture (test-only hook over the real verify + CAS publish path).
    let serving = composition
        ._root
        .adopt_serving_for_isolated_tests()
        .unwrap();
    assert_eq!(serving.status, RootStatus::Serving);
    // memory—v1 §4.9: the composition installs the aggregated registry before
    // any formal evaluation; an uninstalled registry refuses deterministically.
    composition
        ._root
        .install_registry(&[RegistryDeclaration {
            resource: "permission_rule".to_owned(),
            actions: vec!["read".to_owned()],
        }])
        .unwrap();

    // 3. Identity checks the credential, then the dual-card relationship, first.
    assert_eq!(
        login(
            &identity,
            &credentials,
            &handle,
            "alice",
            "wrong",
            CARD_ALLOW
        )
        .await,
        Err(MemoryV1LoginError::InvalidCredentials)
    );
    assert_eq!(
        login(
            &identity,
            &credentials,
            &handle,
            "bob",
            "bob-secret",
            CARD_ALLOW
        )
        .await,
        Err(MemoryV1LoginError::CardNotOwned)
    );
    assert_eq!(
        login(
            &identity,
            &credentials,
            &handle,
            "alice",
            "alice-secret",
            [0x99; 16]
        )
        .await,
        Err(MemoryV1LoginError::CardNotOwned)
    );
    let alice = login(
        &identity,
        &credentials,
        &handle,
        "alice",
        "alice-secret",
        CARD_ALLOW,
    )
    .await
    .unwrap();

    // 4. The full-path lifecycle request.
    let (status, body) = send(&router, Some(&alice)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["success"], true, "{body}");
    assert!(
        body["data"].as_array().is_some_and(|entries| entries
            .iter()
            .any(|entry| entry["resourceType"] == "permission_rule")),
        "the real registry handler ran: {body}"
    );
    let stats = engine.get_stats();
    assert_eq!((stats.evaluation_count, stats.allow_count), (1, 1));
    let first = observations
        .lock()
        .unwrap()
        .pop()
        .expect("the request reached TrustGraph");
    assert_eq!(
        first.request_id_at_entry, first.request_id_at_exit,
        "one request-scoped reader spans the whole downstream lifecycle"
    );
    assert_eq!(
        first.metadata, serving,
        "the reader pinned the serving phase"
    );
    assert!(
        first.forged_headers_absent,
        "Gateway stripped forged identity"
    );
    assert!(
        first.bearer_absent,
        "the credential never crossed the dispatch"
    );
    assert!(
        matches!(
            first.root.with_reader(|_| ()),
            Err(RequestRootAccessError::ScopeEnded)
        ),
        "the reader is released once the response is complete"
    );
    assert_eq!(budget.active(), 0, "the request scope returned its slot");

    // 5. Every request gets its own reader.
    let (status, _) = send(&router, Some(&alice)).await;
    assert_eq!(status, StatusCode::OK);
    let second = observations.lock().unwrap().pop().unwrap();
    assert_ne!(second.request_id_at_entry, first.request_id_at_entry);

    // 6. Decisions use only the session's card, despite forged identity headers:
    //    OVERLAY DENY blocks the shared BASE allow; an unbound card is denied; the
    //    same shared rule set still allows another user's bound card.
    let overlay = login(
        &identity,
        &credentials,
        &handle,
        "alice",
        "alice-secret",
        CARD_OVERLAY_DENY,
    )
    .await
    .unwrap();
    let (status, body) = send(&router, Some(&overlay)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["reasonCode"], "AUTHORIZATION_RULE_DENIED");
    let unbound = login(
        &identity,
        &credentials,
        &handle,
        "alice",
        "alice-secret",
        CARD_UNBOUND,
    )
    .await
    .unwrap();
    let (status, body) = send(&router, Some(&unbound)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let bob = login(
        &identity,
        &credentials,
        &handle,
        "bob",
        "bob-secret",
        CARD_BOB,
    )
    .await
    .unwrap();
    let (status, _) = send(&router, Some(&bob)).await;
    assert_eq!(status, StatusCode::OK);
    let stats = engine.get_stats();
    assert_eq!((stats.evaluation_count, stats.allow_count), (5, 3));
    assert_eq!(budget.active(), 0);

    // 6b. Only routes adapted to memory—v1 can be admitted. An unadapted read and
    //     a mutation stay pending even for a card whose rules allow the action;
    //     they are refused before evaluation and no legacy handler runs.
    for (method, path) in [
        ("GET", "/main/api/v1/permission-rules"),
        ("POST", "/main/api/v1/permission-rules"),
    ] {
        let (status, body) = send_to(&router, method, path, Some(&bob)).await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{method} {path}: {body}"
        );
        assert_eq!(
            body["reasonCode"], "AUTHORIZATION_ROUTE_NOT_ADAPTED",
            "{body}"
        );
    }
    assert_eq!(engine.get_stats().evaluation_count, 5);

    // 6c. A legacy-only target never receives a memory—v1 request as identity-
    //     empty: Identity keeps its legacy principal requirement.
    let (status, body) = send_to(&router, "GET", "/api/v1/auth/me", Some(&bob)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["reasonCode"], "PRINCIPAL_KIND_INVALID", "{body}");
    assert_eq!(budget.active(), 0);

    // 7. Authentication failures stop at the Gateway before any evaluation.
    identity.revoke(&alice).unwrap();
    let downstream_before = observations.lock().unwrap().len();
    for credential in [
        Some(alice.as_str()),
        None,
        Some("m1.not-a-session"),
        Some("not.a.jwt"),
    ] {
        let (status, body) = send(&router, credential).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{credential:?}: {body}");
    }
    assert_eq!(observations.lock().unwrap().len(), downstream_before);
    let stats = engine.get_stats();
    assert_eq!((stats.evaluation_count, stats.allow_count), (5, 3));
    assert_eq!(budget.active(), 0);

    // 8. Losing the root owner fails closed for every later request.
    drop(composition);
    let (status, _) = send(&router, Some(&bob)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(engine.get_stats().evaluation_count, 5);
}
