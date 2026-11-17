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

use astral_authorization_root::memory_v1_adoption::{
    AdoptionLimit, ColdLoadFacts, MEMORY_V1_CANDIDATE_SCHEMA_VERSION,
};
use astral_authorization_root::memory_v1_db_rows::UserCardStatus;
use astral_authorization_root::memory_v1_db_rows::{
    BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, CurrentSelection,
    IdentityCardRow, RuleSetChangeConfirmationRow, RuleSetRow, RuleSetVersionRow, TenantRow,
    UserCardRow, UserRow,
};
use astral_authorization_root::memory_v1_hamt::CandidateBudget;
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
const GOVERNANCE_BINDINGS: &str = "/main/api/v1/governance/bindings";
const GOVERNANCE_CONFIRM_BATCH: &str = "/main/api/v1/governance/bindings/confirm/batch";
const GOVERNANCE_RULE_SETS: &str = "/main/api/v1/governance/rule-sets";
const GOVERNANCE_RULE_SET_PUBLISH: &str = "/main/api/v1/governance/rule-sets/publish";
const CARD_OPERATOR: [u8; 16] = [0x35; 16];
const CARD_CREATE_ONLY: [u8; 16] = [0x36; 16];
const CARD_TARGET: [u8; 16] = [0x37; 16];
const RULES_OPERATOR: [u8; 16] = [0x43; 16];
const RULES_CREATE_ONLY: [u8; 16] = [0x44; 16];

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
        status: UserCardStatus::Active,
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
                status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
                rule_set_id: RULES_READ,
                owner_tenant_id: TENANT,
                current_version_bytes: vec![1],
            },
            RuleSetRow {
                status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
                rule_set_id: RULES_DENY,
                owner_tenant_id: TENANT,
                current_version_bytes: vec![1],
            },
        ],
        rule_set_versions: vec![version_row(RULES_READ, read), version_row(RULES_DENY, deny)],
        rule_set_change_confirmations: [RULES_READ, RULES_DENY]
            .into_iter()
            .enumerate()
            .map(|(index, rule_set_id)| RuleSetChangeConfirmationRow {
                confirmation_id: [0x90 + index as u8; 16],
                rule_set_id,
                version_bytes: vec![1],
                confirmer_user_id: BOB,
                affected_scope_bytes: vec![1],
                operation_id: vec![1],
                confirmed_at_bytes: vec![1],
                revoked_at: None,
                revoked_by: None,
            })
            .collect(),
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
                    removed_at: None,
                    removed_by: None,
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
                revoked_at: None,
                revoked_by: None,
            })
            .collect(),
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

// memory—v1: Construct distinct operator cards for compound governance actions.
fn governance_fixture() -> (CandidateRows, Vec<CurrentSelection>) {
    let (mut rows, mut selections) = fixture();
    let compound = br#"{"rules":[{"ruleId":"create","resource":"binding","action":"create","effect":"ALLOW","ownerScope":"all"},{"ruleId":"confirm","resource":"binding","action":"confirm","effect":"ALLOW","ownerScope":"all"},{"ruleId":"create-set","resource":"rule_set","action":"create","effect":"ALLOW","ownerScope":"all"},{"ruleId":"publish-set","resource":"rule_set","action":"version-publish","effect":"ALLOW","ownerScope":"all"},{"ruleId":"confirm-change","resource":"rule_set","action":"confirm-change","effect":"ALLOW","ownerScope":"all"}]}"#;
    let create_only = br#"{"rules":[{"ruleId":"create","resource":"binding","action":"create","effect":"ALLOW","ownerScope":"all"},{"ruleId":"create-set","resource":"rule_set","action":"create","effect":"ALLOW","ownerScope":"all"},{"ruleId":"publish-set","resource":"rule_set","action":"version-publish","effect":"ALLOW","ownerScope":"all"}]}"#;
    for (index, (card_id, rule_set_id, content)) in [
        (CARD_OPERATOR, RULES_OPERATOR, compound.as_slice()),
        (CARD_CREATE_ONLY, RULES_CREATE_ONLY, create_only.as_slice()),
    ]
    .into_iter()
    .enumerate()
    {
        let binding_id = [0xa0 + index as u8; 16];
        rows.user_cards.push(UserCardRow {
            user_card_id: card_id,
            user_id: ALICE,
            tenant_id: TENANT,
            status: UserCardStatus::Active,
        });
        rows.rule_sets.push(RuleSetRow {
            status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
            rule_set_id,
            owner_tenant_id: TENANT,
            current_version_bytes: vec![1],
        });
        rows.rule_set_versions
            .push(version_row(rule_set_id, content));
        rows.rule_set_change_confirmations
            .push(RuleSetChangeConfirmationRow {
                confirmation_id: [0xa4 + index as u8; 16],
                rule_set_id,
                version_bytes: vec![1],
                confirmer_user_id: BOB,
                affected_scope_bytes: vec![1],
                operation_id: vec![1],
                confirmed_at_bytes: vec![1],
                revoked_at: None,
                revoked_by: None,
            });
        rows.bindings.push(BindingRow {
            binding_id,
            user_card_id: card_id,
            rule_set_id,
            binding_layer: BindingLayer::Base,
            valid_from: None,
            valid_until: None,
            owner_scope: MemoryV1OwnerScope::AllUsers,
            tenant_scope: MemoryV1TenantScope::SelfTenant,
            removed_at: None,
            removed_by: None,
        });
        rows.binding_confirmations.push(BindingConfirmationRow {
            confirmation_id: [0xa2 + index as u8; 16],
            binding_id,
            rule_set_id,
            version_bytes: vec![1],
            confirmer_user_id: BOB,
            scope_bytes: vec![1],
            operation_id: vec![1],
            confirmed_at_bytes: vec![1],
            revoked_at: None,
            revoked_by: None,
        });
        selections.push(CurrentSelection {
            rule_set_id,
            version_bytes: vec![1],
        });
    }
    rows.user_cards.push(UserCardRow {
        user_card_id: CARD_TARGET,
        user_id: BOB,
        tenant_id: TENANT,
        status: UserCardStatus::Active,
    });
    // memory—v1: A withdrawn confirmation lets the batch exercise a genuine
    // reconfirmation target without changing the operator's own bindings.
    let withdrawn = rows
        .binding_confirmations
        .iter_mut()
        .find(|confirmation| confirmation.binding_id == [0x54; 16])
        .unwrap();
    withdrawn.revoked_at = Some(1);
    withdrawn.revoked_by = Some(ALICE);
    let unbound_rule_set = [0xc4; 16];
    rows.rule_sets.push(RuleSetRow {
        status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
        rule_set_id: unbound_rule_set,
        owner_tenant_id: TENANT,
        current_version_bytes: vec![1],
    });
    rows.rule_set_versions
        .push(version_row(unbound_rule_set, br#"{"rules":[]}"#));
    rows.rule_set_change_confirmations
        .push(RuleSetChangeConfirmationRow {
            confirmation_id: [0xc6; 16],
            rule_set_id: unbound_rule_set,
            version_bytes: vec![1],
            confirmer_user_id: BOB,
            affected_scope_bytes: vec![1],
            operation_id: vec![1],
            confirmed_at_bytes: vec![1],
            revoked_at: None,
            revoked_by: None,
        });
    selections.push(CurrentSelection {
        rule_set_id: unbound_rule_set,
        version_bytes: vec![1],
    });
    (rows, selections)
}

// memory—v1: Send the exact governance body through the composed Gateway.
async fn send_governance(
    router: &Router,
    path: &str,
    credential: Option<&str>,
    body: &serde_json::Value,
    operation_id: &str,
) -> (StatusCode, serde_json::Value) {
    let (mut parts, _) = client_request("POST", path, credential).into_parts();
    parts
        .headers
        .insert("content-type", "application/json".parse().unwrap());
    parts
        .headers
        .insert("x-request-id", operation_id.parse().unwrap());
    let response = router
        .clone()
        .oneshot(Request::from_parts(parts, Body::from(body.to_string())))
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (
        status,
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
    )
}

// memory—v1: Exercise the real request chain with an acknowledged but
// unverified confirmation authority, without opening a listener or database.
#[test]
fn unproven_confirmation_request_isolated_process() {
    const CHILD: &str = "ASTRAL_MEMORY_V1_UNPROVEN_CONFIRMATION_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "memory_v1_composition::full_path_tests::unproven_confirmation_request_isolated_process",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        return;
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(unproven_confirmation_request());
}

async fn unproven_confirmation_request() {
    let (rows, selections) = governance_fixture();
    let counts = rows.table_counts();
    let owner = install_process_root(
        rows,
        selections,
        CandidateBudget {
            max_table_rows: 128,
            max_bindings_per_read: 16,
        },
    )
    .unwrap();
    owner
        .install_registry(&crate::memory_v1_service::registry_declarations())
        .unwrap();
    let captured_at_unix_seconds = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    owner
        .adopt_experimental(
            &ColdLoadFacts {
                schema_contract_version: MEMORY_V1_CANDIDATE_SCHEMA_VERSION,
                schema_fingerprint: [1; 32],
                snapshot_counts: counts,
                scanned_counts: counts,
                captured_at_unix_seconds,
            },
            &AdoptionLimit::EXPERIMENTAL,
        )
        .unwrap();
    let handle = owner.handle();
    assert!(handle
        .adoption_record()
        .unwrap()
        .unwrap()
        .unverified
        .contains(&AdoptionLimit::ConfirmationAuthority));
    assert!(super::require_serving_root(&handle).is_err());
    let before = handle.metadata().unwrap();
    let mut config = AppConfig::default();
    config.gateway.hmac_secret = uuid::Uuid::new_v4().to_string();
    let engine = Arc::new(PolicyEngine::new());
    let trustgraph = build_router(
        build_memory_v1_offline_app_state(config.clone(), Arc::clone(&engine)),
        RouterIntegrationConfig::disabled(),
    );
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
    )
    .unwrap();
    let identity = identity_slot.get().cloned().unwrap();
    let router = composition.router();
    let credentials = authenticator();
    let reader = login(
        &identity,
        &credentials,
        &handle,
        "alice",
        "alice-secret",
        CARD_ALLOW,
    )
    .await
    .unwrap();
    let operator = login(
        &identity,
        &credentials,
        &handle,
        "alice",
        "alice-secret",
        CARD_OPERATOR,
    )
    .await
    .unwrap();

    let (status, refusal) = send(&router, Some(&reader)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{refusal}");
    assert_eq!(refusal["reasonCode"], "AUTHORIZATION_CONTEXT_INVALID");
    let id = |bytes| MemoryId::from_bytes(bytes).to_string();
    let batch = serde_json::json!({"items": [{
        "sequence": 0,
        "binding_id": id([0x54; 16]),
        "confirmation_id": id([0xd1; 16]),
        "rule_set_id": id(RULES_READ),
        "scope": "tenant",
    }]});
    let (status, refusal) = send_governance(
        &router,
        GOVERNANCE_CONFIRM_BATCH,
        Some(&operator),
        &batch,
        "unproven-confirmation-batch",
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{refusal}");
    assert_eq!(refusal["reasonCode"], "AUTHORIZATION_CONTEXT_INVALID");
    assert_eq!(engine.get_stats().allow_count, 0);
    assert_eq!(handle.metadata().unwrap(), before);
}

// memory—v1: Use real Gateway/session routing while keeping the root process isolated.
#[test]
fn governance_compound_authorization_isolated_process() {
    const CHILD: &str = "ASTRAL_MEMORY_V1_GOVERNANCE_CHAIN_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "memory_v1_composition::full_path_tests::governance_compound_authorization_isolated_process",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .expect("failed to start isolated governance chain test");
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
        .block_on(governance_compound_authorization());
}

// memory—v1: Action checks and root-derived targets precede the durable audit gate.
async fn governance_compound_authorization() {
    let (rows, selections) = governance_fixture();
    let owner = install_process_root(
        rows,
        selections,
        CandidateBudget {
            max_table_rows: 128,
            max_bindings_per_read: 16,
        },
    )
    .unwrap();
    owner
        .install_registry(&crate::memory_v1_service::registry_declarations())
        .unwrap();
    owner.adopt_serving_for_isolated_tests().unwrap();
    let handle = owner.handle();
    let mut config = AppConfig::default();
    config.gateway.hmac_secret = uuid::Uuid::new_v4().to_string();
    let engine = Arc::new(PolicyEngine::new());
    let trustgraph = build_router(
        build_memory_v1_offline_app_state(config.clone(), Arc::clone(&engine)),
        RouterIntegrationConfig::disabled(),
    );
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
    )
    .expect("composition binds the session authority");
    let identity = identity_slot.get().cloned().unwrap();
    let router = composition.router();
    let credentials = authenticator();
    let operator = login(
        &identity,
        &credentials,
        &handle,
        "alice",
        "alice-secret",
        CARD_OPERATOR,
    )
    .await
    .unwrap();
    let create_only = login(
        &identity,
        &credentials,
        &handle,
        "alice",
        "alice-secret",
        CARD_CREATE_ONLY,
    )
    .await
    .unwrap();
    let id = |bytes| MemoryId::from_bytes(bytes).to_string();
    let mut body = serde_json::json!({
        "binding_id": id([0xb1; 16]),
        "user_card_id": id(CARD_BOB),
        "rule_set_id": id(RULES_READ),
        "binding_layer": "BASE",
        "confirmation_id": id([0xb2; 16]),
        "confirmation_scope": "self",
    });
    let before = handle.metadata().unwrap();

    let (status, _) = send_governance(
        &router,
        GOVERNANCE_BINDINGS,
        None,
        &body,
        "governance-unauthenticated",
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(engine.get_stats().evaluation_count, 0);

    let (status, refusal) = send_governance(
        &router,
        GOVERNANCE_BINDINGS,
        Some(&create_only),
        &body,
        "governance-missing-confirm",
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{refusal}");
    assert_eq!(refusal["decision"], "AUTHORIZATION_NO_MATCH");
    assert_eq!(refusal["reasonCode"], "AUTHORIZATION_AUDIT_UNAVAILABLE");
    assert_eq!(engine.get_stats().evaluation_count, 1);

    let (status, refusal) = send_governance(
        &router,
        GOVERNANCE_BINDINGS,
        Some(&operator),
        &body,
        "governance-audit-unavailable",
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{refusal}");
    assert_eq!(refusal["reasonCode"], "AUTHORIZATION_PENDING");
    assert_eq!(engine.get_stats().evaluation_count, 2);
    assert_eq!(handle.metadata().unwrap(), before);

    body["user_card_id"] = id(CARD_OPERATOR).into();
    body["target_owner"] = id(BOB).into();
    body["target_tenant"] = id(TENANT).into();
    let (status, refusal) = send_governance(
        &router,
        GOVERNANCE_BINDINGS,
        Some(&operator),
        &body,
        "governance-forged-owner",
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{refusal}");
    assert_eq!(refusal["decision"], "AUTHORIZATION_NO_MATCH");
    assert_eq!(refusal["reasonCode"], "AUTHORIZATION_AUDIT_UNAVAILABLE");
    assert_eq!(engine.get_stats().evaluation_count, 3);
    assert_eq!(handle.metadata().unwrap(), before);

    body.as_object_mut().unwrap().remove("target_owner");
    body.as_object_mut().unwrap().remove("target_tenant");
    body["user_card_id"] = id(CARD_TARGET).into();
    body["binding_layer"] = "OVERLAY".into();
    let (status, refusal) = send_governance(
        &router,
        GOVERNANCE_BINDINGS,
        Some(&operator),
        &body,
        "governance-overlay-only",
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{refusal}");
    assert_eq!(refusal["decision"], "AUTHORIZATION_NO_MATCH");
    assert_eq!(refusal["reasonCode"], "AUTHORIZATION_AUDIT_UNAVAILABLE");
    assert_eq!(engine.get_stats().evaluation_count, 4);
    assert_eq!(handle.metadata().unwrap(), before);

    let rule_set_body = serde_json::json!({
        "rule_set_id": id([0xc1; 16]),
        "owner_tenant_id": id(TENANT),
        "content": "{\"rules\":[]}",
        "version_bytes": "v1",
        "change_confirmation_id": id([0xc2; 16]),
        "affected_scope": "tenant",
    });
    let (status, refusal) = send_governance(
        &router,
        GOVERNANCE_RULE_SETS,
        Some(&create_only),
        &rule_set_body,
        "governance-rule-set-missing-confirm-change",
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{refusal}");
    assert_eq!(refusal["decision"], "AUTHORIZATION_NO_MATCH");
    assert_eq!(refusal["reasonCode"], "AUTHORIZATION_AUDIT_UNAVAILABLE");
    assert_eq!(engine.get_stats().evaluation_count, 5);
    assert_eq!(handle.metadata().unwrap(), before);

    let (status, refusal) = send_governance(
        &router,
        GOVERNANCE_RULE_SETS,
        Some(&operator),
        &rule_set_body,
        "governance-rule-set-audit-unavailable",
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{refusal}");
    assert_eq!(refusal["reasonCode"], "AUTHORIZATION_PENDING");
    assert_eq!(engine.get_stats().evaluation_count, 6);
    assert_eq!(handle.metadata().unwrap(), before);

    let mut publish_body = serde_json::json!({
        "rule_set_id": id([0xc4; 16]),
        "content": "{\"rules\":[]}",
        "version_bytes": "v2",
        "change_confirmation_id": id([0xc3; 16]),
        "affected_scope": "tenant",
    });
    let (status, refusal) = send_governance(
        &router,
        GOVERNANCE_RULE_SET_PUBLISH,
        Some(&create_only),
        &publish_body,
        "governance-publish-missing-confirm-change",
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{refusal}");
    assert_eq!(refusal["decision"], "AUTHORIZATION_NO_MATCH");
    assert_eq!(refusal["reasonCode"], "AUTHORIZATION_AUDIT_UNAVAILABLE");
    assert_eq!(engine.get_stats().evaluation_count, 7);
    assert_eq!(handle.metadata().unwrap(), before);

    publish_body["rule_set_id"] = id(RULES_CREATE_ONLY).into();
    let (status, refusal) = send_governance(
        &router,
        GOVERNANCE_RULE_SET_PUBLISH,
        Some(&operator),
        &publish_body,
        "governance-publish-self-confirmation",
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{refusal}");
    assert_eq!(refusal["decision"], "AUTHORIZATION_NO_MATCH");
    assert_eq!(refusal["reasonCode"], "AUTHORIZATION_AUDIT_UNAVAILABLE");
    assert_eq!(engine.get_stats().evaluation_count, 8);
    assert_eq!(handle.metadata().unwrap(), before);

    let allows_before_publish = engine.get_stats().allow_count;
    let unbound_publish_body = serde_json::json!({
        "rule_set_id": id([0xc4; 16]),
        "content": "{\"rules\":[]}",
        "version_bytes": "v2",
        "change_confirmation_id": id([0xc5; 16]),
        "affected_scope": "tenant",
    });
    let (status, refusal) = send_governance(
        &router,
        GOVERNANCE_RULE_SET_PUBLISH,
        Some(&operator),
        &unbound_publish_body,
        "governance-publish-audit-unavailable",
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{refusal}");
    assert_eq!(refusal["reasonCode"], "AUTHORIZATION_PENDING");
    assert_eq!(engine.get_stats().evaluation_count, 9);
    assert_eq!(engine.get_stats().allow_count, allows_before_publish + 1);
    assert_eq!(handle.metadata().unwrap(), before);

    let batch_item = |sequence, binding_id, rule_set_id, confirmation_id| {
        serde_json::json!({
            "sequence": sequence,
            "binding_id": id(binding_id),
            "confirmation_id": id(confirmation_id),
            "rule_set_id": id(rule_set_id),
            "scope": "tenant",
        })
    };
    let allowed_item = batch_item(0, [0x54; 16], RULES_READ, [0xd1; 16]);
    let self_item = batch_item(0, [0xa0; 16], RULES_OPERATOR, [0xd2; 16]);
    let unknown_item = batch_item(0, [0xdf; 16], RULES_READ, [0xd3; 16]);
    let request_batch = |items: Vec<serde_json::Value>| serde_json::json!({"items": items});

    let (status, _) = send_governance(
        &router,
        GOVERNANCE_CONFIRM_BATCH,
        None,
        &request_batch(vec![allowed_item.clone()]),
        "batch-unauthenticated",
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(engine.get_stats().evaluation_count, 9);

    let (status, refusal) = send_governance(
        &router,
        GOVERNANCE_CONFIRM_BATCH,
        Some(&operator),
        &request_batch(vec![allowed_item.clone()]),
        "batch-audit-unavailable",
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{refusal}");
    assert_eq!(refusal["reasonCode"], "AUTHORIZATION_PENDING");
    assert_eq!(engine.get_stats().evaluation_count, 10);
    assert_eq!(handle.metadata().unwrap(), before);

    for (index, mut items) in [
        vec![self_item.clone(), unknown_item.clone()],
        vec![unknown_item.clone(), self_item.clone()],
    ]
    .into_iter()
    .enumerate()
    {
        for (sequence, item) in items.iter_mut().enumerate() {
            item["sequence"] = sequence.into();
        }
        let (status, refusal) = send_governance(
            &router,
            GOVERNANCE_CONFIRM_BATCH,
            Some(&operator),
            &request_batch(items),
            &format!("batch-self-unknown-{index}"),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{refusal}");
        assert_eq!(refusal["decision"], "AUTHORIZATION_NO_MATCH");
        assert_eq!(refusal["reasonCode"], "AUTHORIZATION_AUDIT_UNAVAILABLE");
        assert_eq!(handle.metadata().unwrap(), before);
    }
    for (index, mut items) in [
        vec![allowed_item.clone(), unknown_item.clone()],
        vec![unknown_item.clone(), allowed_item.clone()],
    ]
    .into_iter()
    .enumerate()
    {
        for (sequence, item) in items.iter_mut().enumerate() {
            item["sequence"] = sequence.into();
        }
        let (status, refusal) = send_governance(
            &router,
            GOVERNANCE_CONFIRM_BATCH,
            Some(&operator),
            &request_batch(items),
            &format!("batch-valid-unknown-{index}"),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{refusal}");
        assert_eq!(refusal["reasonCode"], "AUTHORIZATION_CONTEXT_INVALID");
        assert_eq!(handle.metadata().unwrap(), before);
    }
    let (status, _) = send_governance(
        &router,
        GOVERNANCE_CONFIRM_BATCH,
        Some(&operator),
        &serde_json::json!({"items": [allowed_item], "unexpected": true}),
        "batch-invalid-body",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(engine.get_stats().evaluation_count, 14);
    assert_eq!(handle.metadata().unwrap(), before);
    assert_eq!(composition.request_scope_budget().active(), 0);
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
    owner
        .install_registry(&crate::memory_v1_service::registry_declarations())
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
    )
    .expect("composition binds the session authority");
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
    assert!(super::require_serving_root(&handle).is_err());

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
    let entries = body["data"].as_array().expect("registry entries");
    let active: std::collections::BTreeMap<_, _> = entries
        .iter()
        .map(|entry| {
            (
                entry["resourceType"].as_str().expect("resourceType"),
                entry["actions"]
                    .as_array()
                    .expect("actions")
                    .iter()
                    .map(|action| action.as_str().expect("action"))
                    .collect::<Vec<_>>(),
            )
        })
        .collect();
    assert_eq!(
        active.len(),
        4,
        "the root route registry is the only catalog"
    );
    assert_eq!(active["permission_rule"], ["read"]);
    assert_eq!(
        active["binding"],
        [
            "confirm",
            "create",
            "create-overlay-only",
            "remove",
            "revoke-confirmation"
        ]
    );
    assert_eq!(
        active["rule_set"],
        ["confirm-change", "create", "retire", "version-publish"]
    );
    assert_eq!(active["user_card"], ["create", "disable", "enable"]);
    assert!(
        !active.contains_key("organization"),
        "legacy global catalog leaked"
    );
    assert!(entries.iter().all(
        |entry| entry["supportedConditions"] == serde_json::json!([])
            && entry["description"].is_null()
    ));
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
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["decision"], "AUTHORIZATION_RULE_DENIED");
    assert_eq!(body["reasonCode"], "AUTHORIZATION_AUDIT_UNAVAILABLE");
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
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["decision"], "AUTHORIZATION_CARD_UNBOUND");
    assert_eq!(body["reasonCode"], "AUTHORIZATION_AUDIT_UNAVAILABLE");
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
