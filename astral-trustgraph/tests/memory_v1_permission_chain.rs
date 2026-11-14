//! memory—v1: Isolated fail-closed slices. Fixture identity and the test issuer
//! do not represent Gateway authentication, a live session, or authorization.

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use astral_authorization_root::{
    memory_v1_db_rows::CandidateRows,
    memory_v1_hamt::CandidateBudget,
    memory_v1_request::{RequestRootAccessError, RequestRootExtension, RequestRootScope},
    memory_v1_root::install_process_root,
};
use astral_common::{
    config::AppConfig,
    middleware::{
        decode_v2_token,
        gateway_signature::{
            compute_hmac_signature_v3, in_process_gateway_signature_middleware,
            in_process_gateway_source,
        },
        JwtClaims,
    },
    token_contract::{ACCESS_TYP, CLAIMS_VERSION},
};
use astral_trustgraph::{
    api::{permission_check::permission_check_middleware, rules::rule_routes},
    repository::{
        admin_group_repository::SqlxAdminGroupRepository,
        audit_log_repository::SqlxAuditLogRepository,
        card_template_repository::SqlxCardTemplateRepository,
        cross_org_grant_repository::SqlxCrossOrgGrantRepository,
        delegation_repository::SqlxDelegationRepository,
        department_repository::SqlxDepartmentRepository, domain_repository::SqlxDomainRepository,
        global_admin_repository::SqlxGlobalAdminRepository,
        grading_repository::SqlxGradingRepository, hit_stat_repository::SqlxHitStatRepository,
        inheritance_config_repository::SqlxInheritanceConfigRepository,
        level_repository::SqlxLevelRepository,
        level_template_repository::SqlxLevelTemplateRepository,
        permission_action_repository::SqlxPermissionActionRepository,
        permission_request_repository::SqlxPermissionRequestRepository,
        platform_package_repository::SqlxPlatformPackageRepository,
        resource_type_repository::SqlxResourceTypeRepository, rule_repository::SqlxRuleRepository,
        rule_set_repository::SqlxRuleSetRepository, sod_repository::SqlxSodRepository,
        template_repository::SqlxTemplateRepository, tenant_repository::SqlxTenantRepository,
        user_card_repository::SqlxUserCardRepository,
    },
    service::{
        approval_service::ApprovalService,
        audit_replay_worker::AuditReplayProducerSlot,
        delegation_service::DelegationWriteService,
        level_template_service::LevelTemplateService,
        personal_permission_service::PersonalPermissionService,
        rule_set_write_service::RuleSetWriteService,
        rule_write_service::{RuleWriteService, SqlxGrantSodValidator},
        template_service::TemplateService,
        tenant_service::TenantService,
        user_card_service::UserCardService,
    },
    AppState,
};
use axum::{
    body::{to_bytes, Body},
    extract::{ConnectInfo, Request},
    http::StatusCode,
    middleware::{self, Next},
    response::Response,
    Router,
};
use policy_engine::PolicyEngine;
use sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions};
use tower::ServiceExt;
use tracing::instrument::WithSubscriber;

const PATH: &str = "/main/api/v1/permission-rules/registry";

// memory—v1: Constructors only retain the lazy pool; it has no network endpoint.
fn fixture_state(config: AppConfig, engine: Arc<PolicyEngine>) -> AppState {
    let pool = MySqlPoolOptions::new().connect_lazy_with(MySqlConnectOptions::new().socket(
        std::env::temp_dir().join(format!(
            "astral-memory-v1-nonexistent-{}",
            uuid::Uuid::new_v4()
        )),
    ));
    let sod = Arc::new(SqlxGrantSodValidator::new(pool.clone()));
    let rules = Arc::new(SqlxRuleRepository::new(pool.clone()));
    let rule_sets = Arc::new(SqlxRuleSetRepository::new(pool.clone()));
    let delegations = Arc::new(SqlxDelegationRepository::new(pool.clone()));
    let requests = Arc::new(SqlxPermissionRequestRepository::new(pool.clone()));
    let templates = Arc::new(SqlxTemplateRepository::new(pool.clone()));
    let level_templates = Arc::new(SqlxLevelTemplateRepository::new(pool.clone()));
    let user_cards = Arc::new(SqlxUserCardRepository::new(pool.clone()));
    let tenants = Arc::new(SqlxTenantRepository::new(pool.clone()));
    AppState {
        config: Arc::new(config),
        db: pool.clone(),
        engine,
        domain_repository: Arc::new(SqlxDomainRepository::new(pool.clone())),
        level_repository: Arc::new(SqlxLevelRepository::new(pool.clone())),
        grading_repository: Arc::new(SqlxGradingRepository::new(pool.clone())),
        card_template_repository: Arc::new(SqlxCardTemplateRepository::new(pool.clone())),
        global_admin_repository: Arc::new(SqlxGlobalAdminRepository::new(pool.clone())),
        cross_org_grant_repository: Arc::new(SqlxCrossOrgGrantRepository::new(pool.clone())),
        rule_repository: rules.clone(),
        rule_set_repository: rule_sets.clone(),
        delegation_repository: delegations.clone(),
        admin_group_repository: Arc::new(SqlxAdminGroupRepository::new(pool.clone())),
        rule_write_service: Arc::new(RuleWriteService::new(rules.clone(), sod.clone())),
        rule_set_write_service: Arc::new(RuleSetWriteService::new(rule_sets)),
        delegation_service: Arc::new(DelegationWriteService::new(delegations)),
        department_repository: Arc::new(SqlxDepartmentRepository::new(pool.clone())),
        platform_package_repository: Arc::new(SqlxPlatformPackageRepository::new(pool.clone())),
        inheritance_config_repository: Arc::new(SqlxInheritanceConfigRepository::new(pool.clone())),
        permission_action_repository: Arc::new(SqlxPermissionActionRepository::new(pool.clone())),
        resource_type_repository: Arc::new(SqlxResourceTypeRepository::new(pool.clone())),
        audit_log_repository: Arc::new(SqlxAuditLogRepository::new(pool.clone())),
        sod_repository: Arc::new(SqlxSodRepository::new(pool.clone())),
        hit_stat_repository: Arc::new(SqlxHitStatRepository::new(pool)),
        permission_request_repository: requests.clone(),
        template_repository: templates.clone(),
        level_template_repository: level_templates.clone(),
        user_card_repository: user_cards.clone(),
        tenant_repository: tenants.clone(),
        tenant_service: Arc::new(TenantService::new(tenants)),
        approval_service: Arc::new(ApprovalService::new(requests)),
        template_service: Arc::new(TemplateService::new(templates)),
        level_template_service: Arc::new(LevelTemplateService::new(level_templates)),
        user_card_service: Arc::new(UserCardService::new(user_cards)),
        personal_permission_service: Arc::new(PersonalPermissionService::new(rules, sod)),
        authorization_fence_provider: None,
        projector_health: Arc::new(OnceLock::new()),
        audit_replay_producer: AuditReplayProducerSlot::new(),
        test_control: None,
        org_scope_enabled: false,
        org_scope_tenant_allowlist: vec![],
    }
}

// memory—v1: Detect entry to the real route handler, including early handler rejection.
async fn count_handler(req: Request, next: Next) -> Response {
    req.extensions()
        .get::<Arc<AtomicUsize>>()
        .unwrap()
        .fetch_add(1, Ordering::SeqCst);
    next.run(req).await
}

// memory—v1: Observe the verified request before it enters the real permission layer.
async fn capture_verified_root(mut req: Request, next: Next) -> Response {
    let captured = req
        .extensions_mut()
        .remove::<Arc<Mutex<Option<RequestRootExtension>>>>()
        .unwrap();
    let root = req
        .extensions()
        .get::<RequestRootExtension>()
        .unwrap()
        .clone();
    *captured.lock().unwrap() = Some(root);
    next.run(req).await
}

// memory—v1: Create signed fixture headers, not a JWT or a proven session.
fn signed_fixture(config: &AppConfig, root: RequestRootExtension) -> Request {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .to_string();
    let signature = compute_hmac_signature_v3(
        &config.gateway.hmac_secret,
        "GET",
        PATH,
        "42",
        "PLATFORM_USER",
        "fixture-token",
        "43",
        "44",
        "45",
        "46",
        "ACCESS",
        "2",
        "",
        "",
        &timestamp,
    );
    Request::builder()
        .uri(PATH)
        .header("x-original-path", PATH)
        .header("x-gateway-auth", "verified")
        .header("x-gateway-ts", timestamp)
        .header("x-gateway-signature", signature)
        .header("x-user-id", "42")
        .header("x-principal-kind", "PLATFORM_USER")
        .header("x-token-id", "fixture-token")
        .header("x-identity-card-id", "43")
        .header("x-user-card-id", "44")
        .header("x-user-card-domain-id", "45")
        .header("x-user-card-tenant-id", "46")
        .header("x-token-use", "ACCESS")
        .header("x-claims-version", "2")
        .extension(root)
        .body(Body::empty())
        .unwrap()
}

// memory—v1: A cryptographically valid test JWT still has no session proof.
fn fixture_jwt(config: &AppConfig) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;
    let claims = JwtClaims {
        claims_version: CLAIMS_VERSION,
        issuer: config.jwt.access.issuer.clone(),
        audience: config.jwt.access.audience.clone(),
        sub: "42".into(),
        jti: uuid::Uuid::new_v4().to_string(),
        roles: vec![],
        token_use: "ACCESS".into(),
        principal_kind: "PLATFORM_USER".into(),
        identity_card_id: Some(43),
        user_card_id: Some(44),
        user_card_tenant_id: Some(46),
        user_card_domain_id: Some(45),
        template_id: None,
        structure_node_id: None,
        tenant_status: None,
        permissions: None,
        sid: Some(1),
        session_version: Some(1),
        sev: Some(1),
        family_id: Some(1),
        exp: now + 300,
        iat: now,
        nbf: now,
    };
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.typ = Some(ACCESS_TYP.into());
    header.kid = Some(config.jwt.access.kid.clone());
    jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(config.jwt.access.secret.as_bytes()),
    )
    .unwrap()
}

// memory—v1: Observe only tracing events emitted by the actual evaluator and middleware.
#[derive(Clone, Default)]
struct Events(Arc<Mutex<Vec<String>>>);
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Events {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        struct Visitor(String);
        impl tracing::field::Visit for Visitor {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                use std::fmt::Write;
                write!(self.0, "{}={value:?} ", field.name()).unwrap();
            }
        }
        let mut visitor = Visitor(String::new());
        event.record(&mut visitor);
        self.0.lock().unwrap().push(visitor.0);
    }
}

// memory—v1: The Gateway session gate and the verified fixture root both refuse before any policy
// evaluation: the root is refused with 503 by the TrustGraph guard, with zero evaluations and no
// handler run.
#[tokio::test]
async fn real_gateway_blocks_without_session_and_verified_fixture_is_refused_before_evaluation() {
    use tracing_subscriber::prelude::*;

    let owner = install_process_root(
        CandidateRows::default(),
        vec![],
        CandidateBudget {
            max_table_rows: 16,
            max_bindings_per_read: 4,
        },
    )
    .unwrap();
    let mut config = AppConfig::default();
    config.gateway.hmac_secret = uuid::Uuid::new_v4().to_string();
    config.jwt.access.secret = uuid::Uuid::new_v4().to_string();
    config.jwt.access.issuer = "isolated-test-issuer".into();
    config.jwt.access.audience = "isolated-test-audience".into();
    config.rate_limit.enabled = false;
    let engine = Arc::new(PolicyEngine::new());
    let state = fixture_state(config.clone(), engine.clone());
    let handlers = Arc::new(AtomicUsize::new(0));
    let verified: Arc<Mutex<Option<RequestRootExtension>>> = Arc::new(Mutex::new(None));
    let (issuer, verifier) = in_process_gateway_source();
    let routes = rule_routes()
        .route_layer(middleware::from_fn(count_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            permission_check_middleware,
        ));
    let base_downstream = Router::new()
        .nest("/main/api/v1", routes)
        .with_state(state)
        .layer(axum::Extension(handlers.clone()));
    let downstream = base_downstream
        .clone()
        .layer(middleware::from_fn(capture_verified_root))
        .layer(middleware::from_fn_with_state(
            (config.clone(), verifier),
            in_process_gateway_signature_middleware,
        ));

    let token = fixture_jwt(&config);
    assert!(decode_v2_token(&token, &config).is_ok());
    let gateway = astral_gateway::runtime::build_in_process_gateway_router(
        config.clone(),
        Router::new(),
        base_downstream,
        owner.handle(),
    );
    let response = gateway
        .oneshot(
            Request::builder()
                .uri(PATH)
                .header("authorization", format!("Bearer {token}"))
                .header("x-user-id", "forged")
                .extension(ConnectInfo(SocketAddr::from((Ipv4Addr::LOCALHOST, 12345))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), 16384).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["reasonCode"], "AUTH_STATE_UNAVAILABLE");
    assert_eq!(engine.get_stats().evaluation_count, 0);
    assert_eq!(handlers.load(Ordering::SeqCst), 0);
    assert!(verified.lock().unwrap().is_none());

    let scope = RequestRootScope::new(owner.handle(), uuid::Uuid::new_v4());
    let extension = scope.extension();
    let before = extension
        .with_reader(|reader| {
            (
                reader.request_id(),
                reader.metadata(),
                std::ptr::from_ref(reader) as usize,
            )
        })
        .unwrap();
    let mut unsigned_source = signed_fixture(&config, extension.clone());
    unsigned_source.extensions_mut().insert(verified.clone());
    let response = downstream.clone().oneshot(unsigned_source).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(engine.get_stats().evaluation_count, 0);
    assert!(verified.lock().unwrap().is_none());

    let mut bad_signature = signed_fixture(&config, extension.clone());
    bad_signature
        .headers_mut()
        .insert("x-gateway-signature", "invalid".parse().unwrap());
    bad_signature.extensions_mut().insert(verified.clone());
    issuer.mark(&mut bad_signature);
    let response = downstream.clone().oneshot(bad_signature).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(engine.get_stats().evaluation_count, 0);
    assert!(verified.lock().unwrap().is_none());

    let events = Events::default();
    let subscriber = tracing_subscriber::registry().with(events.clone());
    let mut request = signed_fixture(&config, extension);
    request.extensions_mut().insert(verified.clone());
    issuer.mark(&mut request);
    let response = downstream
        .oneshot(request)
        .with_subscriber(subscriber)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let stats = engine.get_stats();
    assert_eq!(
        (stats.evaluation_count, stats.allow_count, stats.deny_count),
        (0, 0, 0)
    );
    assert_eq!(handlers.load(Ordering::SeqCst), 0);
    let after = verified.lock().unwrap().take().unwrap();
    assert_eq!(
        before,
        after
            .with_reader(|reader| {
                (
                    reader.request_id(),
                    reader.metadata(),
                    std::ptr::from_ref(reader) as usize,
                )
            })
            .unwrap()
    );
    let events = events.0.lock().unwrap();
    assert!(!events
        .iter()
        .any(|event| event.contains("memory-v1 request root observation")));
    assert!(!events
        .iter()
        .any(|event| event.contains("memory-v1 candidate authorization unavailable")));
    drop(events);
    drop(scope);
    assert!(matches!(
        after.with_reader(|_| ()),
        Err(RequestRootAccessError::ScopeEnded)
    ));
}
