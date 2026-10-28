use std::{
    str::FromStr,
    sync::{Arc, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Context, Result};
use astral_common::{
    config::{AppConfig, GatewayCfg},
    error::global_exception_handler,
    middleware::gateway_signature::{compute_hmac_signature_v3, gateway_signature_middleware},
};
use astral_db::{
    load_owned_delta_completion, validate_projection_owned_schema,
    CachedPublishedEvidenceRuleRepository, DeltaEventAppendRequest, DeltaEventType, Sha256Digest,
    SqlxRuleRepository as SqlxPolicyRepository,
};
use astral_trustgraph::{
    api::{permission_check::permission_check_middleware, rules::rule_routes},
    repository::{
        admin_group_repository::{AdminGroupRepository, SqlxAdminGroupRepository},
        audit_log_repository::{RuleSetMutationContext, SqlxAuditLogRepository},
        card_template_repository::SqlxCardTemplateRepository,
        cross_org_grant_repository::SqlxCrossOrgGrantRepository,
        delegation_repository::SqlxDelegationRepository,
        department_repository::SqlxDepartmentRepository,
        domain_repository::SqlxDomainRepository,
        global_admin_repository::SqlxGlobalAdminRepository,
        grading_repository::SqlxGradingRepository,
        hit_stat_repository::SqlxHitStatRepository,
        inheritance_config_repository::SqlxInheritanceConfigRepository,
        level_repository::SqlxLevelRepository,
        level_template_repository::SqlxLevelTemplateRepository,
        permission_action_repository::SqlxPermissionActionRepository,
        permission_request_repository::SqlxPermissionRequestRepository,
        platform_package_repository::SqlxPlatformPackageRepository,
        resource_type_repository::SqlxResourceTypeRepository,
        rule_repository::SqlxRuleRepository,
        rule_set_repository::SqlxRuleSetRepository,
        sod_repository::SqlxSodRepository,
        template_repository::SqlxTemplateRepository,
        tenant_repository::SqlxTenantRepository,
        user_card_repository::SqlxUserCardRepository,
    },
    service::{
        approval_service::ApprovalService,
        arbiter::ArbiterService,
        audit_replay_worker::AuditReplayProducerSlot,
        delegation_service::DelegationWriteService,
        level_template_service::LevelTemplateService,
        personal_permission_service::PersonalPermissionService,
        rule_set_write_service::{AddEntryRequest, BindCardRequest, RuleSetWriteService},
        rule_write_service::RuleWriteService,
        side_effect::SqlxPermissionSideEffects,
        template_service::TemplateService,
        tenant_service::TenantService,
        user_card_service::UserCardService,
    },
    AppState,
};
use astral_types::{GrantId, PolicyContext};
use axum::{
    body::{to_bytes, Body},
    http::{Method, Request},
    middleware,
    response::Response,
    Router,
};
use policy_engine::PolicyEngine;
use serde_json::Value;
use sqlx::{
    mysql::{MySqlConnectOptions, MySqlPoolOptions},
    MySqlPool, Row,
};
use testsuite::{cleanup_suite_rows, seed_all_tenants, SuiteFixture, SuiteTenant, TenantRole};
use tower::ServiceExt;

pub const DB_TIMEOUT: Duration = Duration::from_secs(8);
pub const TEST_TIMEOUT: Duration = Duration::from_secs(180);
const REQUIRED_DATABASE_PREFIX: &str = "astral_rehearsal_projection_owner_20261015_";
const REQUIRED_MIGRATION_VERSION: i64 = 20261015000001;
const HTTP_BODY_LIMIT: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct OwnedFixture {
    pub suite: SuiteFixture,
    pub tenant_id: i64,
    pub domain_id: i64,
    pub user_id: i64,
    pub identity_card_id: i64,
    pub card_id: i64,
    pub other_tenant_id: i64,
    pub gateway_secret: String,
    pub base: i64,
}

impl OwnedFixture {
    pub fn new(code_prefix: &str) -> Self {
        let suite = SuiteFixture::new(
            code_prefix,
            &[TenantRole::AllowActive, TenantRole::DenyActive],
        );
        let tenant = suite.tenants[0];
        let other = suite.tenants[1];
        Self {
            suite,
            tenant_id: tenant.tenant_id,
            domain_id: tenant.domain_id,
            user_id: tenant.user_id,
            identity_card_id: tenant.identity_card_id,
            card_id: tenant.card_id,
            other_tenant_id: other.tenant_id,
            gateway_secret: format!("projection-owned-http-{}", "s".repeat(40)),
            base: tenant.tenant_id,
        }
    }

    pub fn tenant(&self) -> SuiteTenant {
        self.suite.tenants[0]
    }

    pub fn add_operation(&self, label: &str) -> String {
        format!("http-{label}-{:032x}", self.suite.salt)
    }
}

#[derive(Debug, Clone)]
pub struct HttpIdentity {
    pub user_id: i64,
    pub principal_kind: &'static str,
    pub token_id: String,
    pub identity_card_id: i64,
    pub user_card_id: i64,
    pub user_card_domain_id: i64,
    pub user_card_tenant_id: i64,
    pub token_use: &'static str,
    pub claims_version: &'static str,
    pub action_codes: &'static str,
    pub user_roles: &'static str,
    signing_secret: String,
}

impl HttpIdentity {
    pub fn for_fixture(fixture: &OwnedFixture) -> Self {
        Self {
            user_id: fixture.user_id,
            principal_kind: "PLATFORM_USER",
            token_id: format!("http-token-{:032x}", fixture.suite.salt),
            identity_card_id: fixture.identity_card_id,
            user_card_id: fixture.card_id,
            user_card_domain_id: fixture.domain_id,
            user_card_tenant_id: fixture.tenant_id,
            token_use: "ACCESS",
            claims_version: "3",
            action_codes: "read,create,update,delete",
            user_roles: "USER",
            signing_secret: fixture.gateway_secret.clone(),
        }
    }

    pub fn with_tenant(&self, tenant_id: i64) -> Self {
        let mut clone = self.clone();
        clone.user_card_tenant_id = tenant_id;
        clone
    }
}

#[derive(Debug, Clone)]
pub struct DeltaReceipt {
    pub tenant_id: i64,
    pub event_id: String,
    pub operation_id: String,
    pub event_type: String,
}

pub async fn connect_required() -> MySqlPool {
    assert_eq!(
        std::env::var("RUST_INTEGRATION_REQUIRED").as_deref(),
        Ok("1"),
        "RUST_INTEGRATION_REQUIRED=1 is mandatory; an ignored real integration test must not SKIP"
    );
    assert_eq!(
        std::env::var("TEST_USE_EXISTING").as_deref(),
        Ok("1"),
        "TEST_USE_EXISTING=1 is mandatory for the approved clone"
    );
    assert_eq!(
        std::env::var("ASTRAL_MIGRATION_ENV").as_deref(),
        Ok("isolated"),
        "ASTRAL_MIGRATION_ENV=isolated is mandatory"
    );

    let expected_database = std::env::var("ASTRAL_TEST_DATABASE_NAME")
        .expect("ASTRAL_TEST_DATABASE_NAME must identify the run-owned clone");
    assert!(
        expected_database.starts_with(REQUIRED_DATABASE_PREFIX),
        "database must use the approved projection-owner prefix"
    );
    let suffix = &expected_database[REQUIRED_DATABASE_PREFIX.len()..];
    assert!(!suffix.is_empty() && suffix.len() <= 20);
    assert!(suffix
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'));

    let url = std::env::var("DATABASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .expect("DATABASE_URL is mandatory when RUST_INTEGRATION_REQUIRED=1");
    assert!(!url.contains('?') && !url.contains('#'));
    let options = MySqlConnectOptions::from_str(&url).expect("DATABASE_URL must parse");
    assert!(matches!(
        options.get_host(),
        "localhost" | "127.0.0.1" | "::1"
    ));
    assert_eq!(options.get_port(), 3308);
    assert!(options.get_socket().is_none());
    assert_eq!(options.get_database(), Some(expected_database.as_str()));

    let pool = MySqlPoolOptions::new()
        .max_connections(8)
        .acquire_timeout(DB_TIMEOUT)
        .connect_with(options)
        .await
        .expect("approved loopback MySQL clone must be reachable");
    validate_projection_owned_schema(&pool)
        .await
        .expect("owned projection schema must be migrated and internally consistent");
    let migration: Option<i64> = sqlx::query_scalar(
        "SELECT version FROM _sqlx_migrations WHERE version = ? AND success = TRUE",
    )
    .bind(REQUIRED_MIGRATION_VERSION)
    .fetch_optional(&pool)
    .await
    .expect("migration marker read must succeed");
    assert_eq!(migration, Some(REQUIRED_MIGRATION_VERSION));
    pool
}

fn fixture_message_scope(fixture: &OwnedFixture) -> (String, String) {
    use astral_mq::invalidation::{EvidenceInvalidated, InvalidationEvent, INVALIDATION_QUEUE};

    let ordering_key = InvalidationEvent::EvidenceInvalidated(EvidenceInvalidated {
        tenant_id: fixture.tenant_id,
        card_id: Some(fixture.card_id),
        aggregate_type: astral_types::PublishedEvidenceAggregate::UserCard,
        aggregate_id: fixture.card_id,
        published_generation: 1,
        stamp: astral_types::PublicationStamp::new(
            1,
            "ab".repeat(32),
            astral_types::PublicationSeal::from_unix_seconds(1_700_000_000).unwrap(),
        )
        .unwrap(),
        source_generation: 1,
        revoke_fence: 0,
    })
    .ordering_key();
    let counter_key = format!("{INVALIDATION_QUEUE}\u{1f}{ordering_key}");
    (ordering_key, counter_key)
}

pub async fn seed_governance_fixture(pool: &MySqlPool, fixture: &OwnedFixture) -> Result<String> {
    let (ordering_key, counter_key) = fixture_message_scope(fixture);
    let existing: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM al_message_scope_counter WHERE scope_key = ?) + \
                (SELECT COUNT(*) FROM al_message_outbox WHERE queue_name = ? AND ordering_key = ?)",
    )
    .bind(&counter_key)
    .bind(astral_mq::invalidation::INVALIDATION_QUEUE)
    .bind(&ordering_key)
    .fetch_one(pool)
    .await?;
    if existing != 0 {
        return Err(anyhow!(
            "HTTP fixture message scope must be unused before setup"
        ));
    }
    tokio::time::timeout(DB_TIMEOUT, seed_all_tenants(pool, &fixture.suite))
        .await
        .context("seed suite topology timed out")??;

    let tenant = fixture.tenant();
    let repository = Arc::new(SqlxRuleSetRepository::new(pool.clone()));
    let service = RuleSetWriteService::new(repository);
    let operation_id = fixture.add_operation("ruleset-bootstrap");
    let context = RuleSetMutationContext::user(fixture.user_id, Some(&operation_id))
        .map_err(|error| anyhow!("construct RuleSet bootstrap context: {error}"))?;

    // Remove the suite's default business grant through the production source
    // mutation path before creating management entries and binding the card.
    service
        .delete_entry(tenant.rule_set_id, tenant.entry_id, &context)
        .await
        .map_err(|error| anyhow!("remove seeded business RuleSet entry: {error}"))?;
    for (resource, action, priority) in [
        ("permission_rule", "read", 1),
        ("permission_rule", "create", 2),
        ("permission_rule", "update", 3),
        ("permission_rule", "delete", 4),
    ] {
        service
            .add_entry(
                tenant.rule_set_id,
                &ruleset_entry(resource, action, priority),
                &context,
            )
            .await
            .map_err(|error| anyhow!("bootstrap RuleSet management entry {action}: {error}"))?;
    }
    service
        .bind_card(
            tenant.rule_set_id,
            &BindCardRequest {
                card_id: tenant.card_id,
                ref_type: "BASE".to_owned(),
            },
            &context,
        )
        .await
        .map_err(|error| {
            anyhow!("bootstrap RuleSet card binding through production service: {error}")
        })?;
    Ok(operation_id)
}

fn ruleset_entry(resource: &str, action: &str, priority: i32) -> AddEntryRequest {
    AddEntryRequest {
        effect: "ALLOW".to_owned(),
        resource: Some(resource.to_owned()),
        resource_id: None,
        action: Some(action.to_owned()),
        condition_json: None,
        priority,
    }
}

pub fn build_signed_router(pool: &MySqlPool, gateway_secret: &str) -> Result<Router> {
    let config = AppConfig {
        gateway: GatewayCfg {
            hmac_secret: gateway_secret.to_owned(),
            timestamp_tolerance_secs: 30,
            ..GatewayCfg::default()
        },
        org_scope_enabled: false,
        ..AppConfig::default()
    };
    let state = build_app_state(pool.clone(), config);
    let api_routes = Router::new()
        .merge(rule_routes())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            permission_check_middleware,
        ));
    Ok(Router::new()
        .nest("/main/api/v1", api_routes)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            gateway_signature_middleware,
        ))
        .layer(middleware::from_fn(global_exception_handler))
        .with_state(state))
}

fn build_app_state(pool: MySqlPool, config: AppConfig) -> AppState {
    let config = Arc::new(config);
    let side_effects = Arc::new(SqlxPermissionSideEffects::new(pool.clone()));
    let rule_repository = Arc::new(SqlxRuleRepository::new(pool.clone()));
    let rule_set_repository = Arc::new(SqlxRuleSetRepository::new(pool.clone()));
    let delegation_repository = Arc::new(SqlxDelegationRepository::new(pool.clone()));
    let admin_group_repository: Arc<dyn AdminGroupRepository> =
        Arc::new(SqlxAdminGroupRepository::new(pool.clone()));
    let permission_request_repository =
        Arc::new(SqlxPermissionRequestRepository::new(pool.clone()));
    let template_repository = Arc::new(SqlxTemplateRepository::new(pool.clone()));
    let level_template_repository = Arc::new(SqlxLevelTemplateRepository::new(pool.clone()));
    let user_card_repository = Arc::new(SqlxUserCardRepository::new(pool.clone()));
    let tenant_repository = Arc::new(SqlxTenantRepository::new(pool.clone()));
    AppState {
        config,
        db: pool.clone(),
        engine: Arc::new(PolicyEngine::new()),
        domain_repository: Arc::new(SqlxDomainRepository::new(pool.clone())),
        level_repository: Arc::new(SqlxLevelRepository::new(pool.clone())),
        grading_repository: Arc::new(SqlxGradingRepository::new(pool.clone())),
        card_template_repository: Arc::new(SqlxCardTemplateRepository::new(pool.clone())),
        global_admin_repository: Arc::new(SqlxGlobalAdminRepository::new(pool.clone())),
        cross_org_grant_repository: Arc::new(SqlxCrossOrgGrantRepository::new(pool.clone())),
        rule_repository: rule_repository.clone(),
        rule_set_repository: rule_set_repository.clone(),
        delegation_repository: delegation_repository.clone(),
        admin_group_repository,
        rule_write_service: Arc::new(
            RuleWriteService::new(rule_repository.clone(), side_effects.clone())
                .with_sod_db(pool.clone()),
        ),
        rule_set_write_service: Arc::new(RuleSetWriteService::new(rule_set_repository.clone())),
        delegation_service: Arc::new(DelegationWriteService::new(delegation_repository.clone())),
        department_repository: Arc::new(SqlxDepartmentRepository::new(pool.clone())),
        platform_package_repository: Arc::new(SqlxPlatformPackageRepository::new(pool.clone())),
        inheritance_config_repository: Arc::new(SqlxInheritanceConfigRepository::new(pool.clone())),
        permission_action_repository: Arc::new(SqlxPermissionActionRepository::new(pool.clone())),
        resource_type_repository: Arc::new(SqlxResourceTypeRepository::new(pool.clone())),
        audit_log_repository: Arc::new(SqlxAuditLogRepository::new(pool.clone())),
        sod_repository: Arc::new(SqlxSodRepository::new(pool.clone())),
        hit_stat_repository: Arc::new(SqlxHitStatRepository::new(pool.clone())),
        permission_request_repository: permission_request_repository.clone(),
        template_repository: template_repository.clone(),
        level_template_repository: level_template_repository.clone(),
        user_card_repository: user_card_repository.clone(),
        tenant_repository: tenant_repository.clone(),
        tenant_service: Arc::new(TenantService::new(tenant_repository)),
        approval_service: Arc::new(ApprovalService::new(
            permission_request_repository,
            side_effects.clone(),
        )),
        template_service: Arc::new(TemplateService::new(template_repository)),
        level_template_service: Arc::new(LevelTemplateService::new(
            level_template_repository,
            side_effects.clone(),
        )),
        user_card_service: Arc::new(UserCardService::new(
            user_card_repository,
            side_effects.clone(),
        )),
        personal_permission_service: Arc::new(
            PersonalPermissionService::new(rule_repository, side_effects).with_sod_db(pool),
        ),
        projector_health: Arc::new(OnceLock::new()),
        arbiter_service: Arc::new(ArbiterService::new()),
        audit_replay_producer: AuditReplayProducerSlot::new(),
        test_control: None,
        org_scope_enabled: false,
        org_scope_tenant_allowlist: Vec::new(),
    }
}

pub async fn http_post(
    router: Router,
    identity: &HttpIdentity,
    operation_id: &str,
    body: Value,
    corrupt_signature: bool,
) -> Result<Response> {
    signed_request(
        router,
        Method::POST,
        "/main/api/v1/permission-rules",
        identity,
        operation_id,
        Some(body),
        corrupt_signature,
    )
    .await
}

pub async fn http_put(
    router: Router,
    identity: &HttpIdentity,
    rule_id: i64,
    operation_id: &str,
    body: Value,
    corrupt_signature: bool,
) -> Result<Response> {
    signed_request(
        router,
        Method::PUT,
        &format!("/main/api/v1/permission-rules/{rule_id}"),
        identity,
        operation_id,
        Some(body),
        corrupt_signature,
    )
    .await
}

pub async fn http_delete(
    router: Router,
    identity: &HttpIdentity,
    rule_id: i64,
    operation_id: &str,
) -> Result<Response> {
    signed_request(
        router,
        Method::DELETE,
        &format!("/main/api/v1/permission-rules/{rule_id}"),
        identity,
        operation_id,
        None,
        false,
    )
    .await
}

pub async fn http_delete_card(
    router: Router,
    identity: &HttpIdentity,
    card_id: i64,
    operation_id: &str,
) -> Result<Response> {
    signed_request(
        router,
        Method::DELETE,
        &format!("/main/api/v1/permission-rules/card/{card_id}"),
        identity,
        operation_id,
        None,
        false,
    )
    .await
}

async fn signed_request(
    router: Router,
    method: Method,
    path: &str,
    identity: &HttpIdentity,
    operation_id: &str,
    body: Option<Value>,
    corrupt_signature: bool,
) -> Result<Response> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("clock before Unix epoch")?
        .as_millis()
        .to_string();
    let secret = identity.signing_secret.as_str();
    let signature = compute_hmac_signature_v3(
        secret,
        method.as_str(),
        path,
        &identity.user_id.to_string(),
        identity.principal_kind,
        &identity.token_id,
        &identity.identity_card_id.to_string(),
        &identity.user_card_id.to_string(),
        &identity.user_card_domain_id.to_string(),
        &identity.user_card_tenant_id.to_string(),
        identity.token_use,
        identity.claims_version,
        identity.action_codes,
        identity.user_roles,
        &timestamp,
    );
    let signature = if corrupt_signature {
        format!("{signature}00")
    } else {
        signature
    };
    let body = body
        .map(|value| serde_json::to_vec(&value))
        .transpose()
        .context("serialize HTTP body")?
        .unwrap_or_default();
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("x-gateway-auth", "verified")
        .header("x-gateway-ts", timestamp)
        .header("x-gateway-signature", signature)
        .header("x-original-path", path)
        .header("x-user-id", identity.user_id.to_string())
        .header("x-principal-kind", identity.principal_kind)
        .header("x-token-id", &identity.token_id)
        .header("x-identity-card-id", identity.identity_card_id.to_string())
        .header("x-user-card-id", identity.user_card_id.to_string())
        .header(
            "x-user-card-domain-id",
            identity.user_card_domain_id.to_string(),
        )
        .header(
            "x-user-card-tenant-id",
            identity.user_card_tenant_id.to_string(),
        )
        .header("x-token-use", identity.token_use)
        .header("x-claims-version", identity.claims_version)
        .header("x-action-codes", identity.action_codes)
        .header("x-user-roles", identity.user_roles)
        .header("x-request-id", operation_id)
        .body(Body::from(body))
        .context("build signed HTTP request")?;
    // The secret is supplied by the fixture identity and is the same value used
    // to configure production AppState::config.gateway.hmac_secret.
    router
        .oneshot(request)
        .await
        .map_err(|error| anyhow!("production Router::oneshot failed: {error}"))
}

pub async fn response_rule_id(response: Response) -> Result<i64> {
    let bytes = to_bytes(response.into_body(), HTTP_BODY_LIMIT)
        .await
        .context("read rule response body")?;
    let json: Value = serde_json::from_slice(&bytes).context("decode rule response")?;
    json.pointer("/data/ruleId")
        .and_then(Value::as_i64)
        .ok_or_else(|| anyhow!("production rule response did not contain data.ruleId"))
}

pub async fn require_success(response: Response, label: &str) -> Result<Response> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let body = to_bytes(response.into_body(), HTTP_BODY_LIMIT)
        .await
        .context("read failed rule response body")?;
    let detail: Value = serde_json::from_slice(&body).context("decode failed rule response")?;
    Err(anyhow!("{label} returned HTTP {status}: {detail}"))
}

#[derive(Debug, PartialEq, Eq, sqlx::FromRow)]
pub struct SourceMutationSnapshot {
    rules: i64,
    revisions: i64,
    deltas: i64,
    source_generation: i64,
    revoke_fence: i64,
    source_outbox: i64,
    source_audits: i64,
}

pub async fn source_mutation_snapshot(
    pool: &MySqlPool,
    fixture: &OwnedFixture,
) -> Result<SourceMutationSnapshot> {
    tokio::time::timeout(
        DB_TIMEOUT,
        sqlx::query_as(
            "SELECT \
             (SELECT COUNT(*) FROM permission_rule WHERE card_id = ?) AS rules, \
             (SELECT COUNT(*) FROM authorization_grant_revision WHERE tenant_id = ?) AS revisions, \
             (SELECT COUNT(*) FROM authorization_delta_event WHERE tenant_id = ?) AS deltas, \
             (SELECT COALESCE(MAX(source_generation), 0) FROM authorization_projection_head \
              WHERE aggregate_type = 'CARD' AND aggregate_id = ?) AS source_generation, \
             (SELECT COALESCE(MAX(revoke_fence), 0) FROM authorization_projection_head \
              WHERE aggregate_type = 'CARD' AND aggregate_id = ?) AS revoke_fence, \
             (SELECT COUNT(*) FROM authorization_projection_outbox \
              WHERE tenant_id = ?) AS source_outbox, \
             (SELECT COUNT(*) FROM audit_log WHERE tenant_id = ? \
              AND event_type = 'PERMISSION_RULE_MUTATION') AS source_audits",
        )
        .bind(fixture.card_id)
        .bind(fixture.tenant_id)
        .bind(fixture.tenant_id)
        .bind(fixture.card_id)
        .bind(fixture.card_id)
        .bind(fixture.tenant_id)
        .bind(fixture.tenant_id)
        .fetch_one(pool),
    )
    .await
    .context("source mutation snapshot timed out")?
    .map_err(Into::into)
}

pub async fn wait_for_delta(
    pool: &MySqlPool,
    fixture: &OwnedFixture,
    operation_id: &str,
    event_type: &str,
) -> Result<DeltaReceipt> {
    wait_for("delta event", Duration::from_secs(30), || async {
        let row = tokio::time::timeout(
            DB_TIMEOUT,
            sqlx::query(
                "SELECT event_id, operation_id, event_type \
                 FROM authorization_delta_event \
                 WHERE tenant_id = ? AND operation_id = ? ORDER BY delta_event_id DESC LIMIT 1",
            )
            .bind(fixture.tenant_id)
            .bind(operation_id)
            .fetch_optional(pool),
        )
        .await
        .context("delta event query timed out")??;
        let Some(row) = row else {
            return Ok(None);
        };
        let actual: String = row.try_get("event_type")?;
        if actual != event_type {
            return Err(anyhow!(
                "operation {operation_id} produced {actual}, expected {event_type}"
            ));
        }
        Ok(Some(DeltaReceipt {
            tenant_id: fixture.tenant_id,
            event_id: row.try_get("event_id")?,
            operation_id: row.try_get("operation_id")?,
            event_type: actual,
        }))
    })
    .await
}

pub async fn wait_for_operation_deltas(
    pool: &MySqlPool,
    fixture: &OwnedFixture,
    operation_id: &str,
    expected: usize,
    event_type: &str,
) -> Result<Vec<DeltaReceipt>> {
    wait_for("operation delta batch", Duration::from_secs(30), || async {
        let rows = tokio::time::timeout(
            DB_TIMEOUT,
            sqlx::query(
                "SELECT event_id, operation_id, event_type \
                 FROM authorization_delta_event \
                 WHERE tenant_id = ? AND operation_id = ? AND event_type = ? \
                 ORDER BY delta_event_id ASC",
            )
            .bind(fixture.tenant_id)
            .bind(operation_id)
            .bind(event_type)
            .fetch_all(pool),
        )
        .await
        .context("operation delta batch query timed out")??;
        if rows.len() < expected {
            return Ok(None);
        }
        let mut result = Vec::with_capacity(rows.len());
        for row in rows {
            let actual: String = row.try_get("event_type")?;
            if actual != event_type {
                return Err(anyhow!(
                    "operation {operation_id} produced {actual}, expected {event_type}"
                ));
            }
            result.push(DeltaReceipt {
                tenant_id: fixture.tenant_id,
                event_id: row.try_get("event_id")?,
                operation_id: row.try_get("operation_id")?,
                event_type: actual,
            });
        }
        Ok(Some(result))
    })
    .await
}

pub async fn wait_for_projection(
    pool: &MySqlPool,
    _fixture: &OwnedFixture,
    delta: &DeltaReceipt,
) -> Result<()> {
    wait_for(
        "owned projection completion",
        Duration::from_secs(45),
        || async {
            if has_exact_completion(pool, delta).await? {
                Ok(Some(()))
            } else {
                Ok(None)
            }
        },
    )
    .await
}

pub async fn assert_unclaimed_delta(
    pool: &MySqlPool,
    delta: &DeltaReceipt,
    invalidates: bool,
) -> Result<()> {
    let request = load_completion_request(pool, delta).await?;
    let state: (String, i64, i64, i64) = tokio::time::timeout(
        DB_TIMEOUT,
        sqlx::query_as(
            "SELECT status, attempts, execution_attempts, execution_failures \
             FROM authorization_delta_event \
             WHERE tenant_id = ? AND event_id = ? AND operation_id = ?",
        )
        .bind(delta.tenant_id)
        .bind(&delta.event_id)
        .bind(&delta.operation_id)
        .fetch_one(pool),
    )
    .await
    .context("unclaimed delta state read timed out")??;
    if state != ("PENDING".to_owned(), 0, 0, 0)
        || request.invalidates_published_evidence != invalidates
        || (invalidates && request.revoke_fence == 0)
        || has_exact_completion(pool, delta).await?
    {
        return Err(anyhow!(
            "stopped owner delta has unexpected state or invalidation: {state:?}, invalidates={}, fence={}",
            request.invalidates_published_evidence,
            request.revoke_fence
        ));
    }
    Ok(())
}

pub async fn has_exact_completion(pool: &MySqlPool, delta: &DeltaReceipt) -> Result<bool> {
    let request = load_completion_request(pool, delta).await?;
    let proof = tokio::time::timeout(DB_TIMEOUT, load_owned_delta_completion(pool, &request))
        .await
        .context("exact completion proof timed out")??;
    Ok(proof.is_some())
}

pub async fn assert_exact_receipt(
    pool: &MySqlPool,
    _fixture: &OwnedFixture,
    operation_id: &str,
    delta: &DeltaReceipt,
) -> Result<()> {
    if delta.operation_id != operation_id || delta.event_type.is_empty() {
        return Err(anyhow!(
            "delta identity is not bound to the expected operation"
        ));
    }
    if !has_exact_completion(pool, delta).await? {
        return Err(anyhow!(
            "event {} has no complete historical publication proof",
            delta.event_id
        ));
    }
    Ok(())
}

async fn load_completion_request(
    pool: &MySqlPool,
    delta: &DeltaReceipt,
) -> Result<DeltaEventAppendRequest> {
    let row = tokio::time::timeout(
        DB_TIMEOUT,
        sqlx::query(
            "SELECT tenant_id, card_id, aggregate_type, aggregate_id, grant_id, \
             event_id, operation_id, event_type, base_version, target_version, \
             source_generation, revoke_fence, invalidates_published_evidence, \
             CAST(before_image_json AS CHAR CHARACTER SET utf8mb4) AS before_image_json, \
             before_digest, CAST(delta_json AS CHAR CHARACTER SET utf8mb4) AS delta_json, \
             semantic_hash, dependency_hash, compiler_version FROM authorization_delta_event \
             WHERE tenant_id = ? AND event_id = ? AND operation_id = ?",
        )
        .bind(delta.tenant_id)
        .bind(&delta.event_id)
        .bind(&delta.operation_id)
        .fetch_one(pool),
    )
    .await
    .context("completion request read timed out")??;
    let event_type: String = row.try_get("event_type")?;
    let event_type = match event_type.as_str() {
        "ADD" => DeltaEventType::Add,
        "UPDATE" => DeltaEventType::Update,
        "REMOVE" => DeltaEventType::Remove,
        "REVOKE" => DeltaEventType::Revoke,
        other => return Err(anyhow!("unknown durable event type {other}")),
    };
    let before_digest: Option<Vec<u8>> = row.try_get("before_digest")?;
    let grant_id: String = row.try_get("grant_id")?;
    Ok(DeltaEventAppendRequest {
        tenant_id: row.try_get("tenant_id")?,
        card_id: row.try_get("card_id")?,
        aggregate_type: row.try_get("aggregate_type")?,
        aggregate_id: row.try_get("aggregate_id")?,
        grant_id: GrantId::parse(&grant_id)?,
        event_id: row.try_get("event_id")?,
        operation_id: row.try_get("operation_id")?,
        event_type,
        base_version: row.try_get("base_version")?,
        target_version: row.try_get("target_version")?,
        source_generation: u64::try_from(row.try_get::<i64, _>("source_generation")?)?,
        revoke_fence: u64::try_from(row.try_get::<i64, _>("revoke_fence")?)?,
        invalidates_published_evidence: row.try_get::<i8, _>("invalidates_published_evidence")?
            != 0,
        before_image_json: row.try_get("before_image_json")?,
        before_digest_hex: before_digest
            .map(Sha256Digest::from_bytes)
            .transpose()?
            .map(|digest| digest.as_hex()),
        delta_json: row.try_get("delta_json")?,
        semantic_hash_hex: Sha256Digest::from_bytes(row.try_get("semantic_hash")?)?.as_hex(),
        dependency_hash_hex: Sha256Digest::from_bytes(row.try_get("dependency_hash")?)?.as_hex(),
        compiler_version: row.try_get("compiler_version")?,
        next_attempt_at: None,
    })
}

pub async fn strict_evaluate(
    pool: &MySqlPool,
    fixture: &OwnedFixture,
    expect_allow: bool,
) -> Result<astral_types::PolicyDecision> {
    let tenant = fixture.tenant();
    let ctx = PolicyContext::builder()
        .user_id(Some(tenant.user_id))
        .principal_kind(Some("PLATFORM_USER".to_owned()))
        .identity_card_id(Some(tenant.identity_card_id))
        .card_id(Some(tenant.card_id))
        .tenant_id(Some(tenant.tenant_id))
        .domain_id(Some(tenant.domain_id))
        .resource(Some("learn_subject".to_owned()))
        .action("read".to_owned())
        .build();
    let repo = CachedPublishedEvidenceRuleRepository::new(
        SqlxPolicyRepository::new(pool.clone()),
        pool.clone(),
    );
    let decision = tokio::time::timeout(DB_TIMEOUT, PolicyEngine::new().evaluate(&ctx, &repo))
        .await
        .context("strict PolicyEngine.evaluate timed out")?;
    if decision.allowed != expect_allow {
        return Err(anyhow!("unexpected strict policy decision: {decision:?}"));
    }
    Ok(decision)
}

async fn wait_for<T, F, Fut>(label: &str, deadline: Duration, mut check: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<Option<T>>>,
{
    let start = tokio::time::Instant::now();
    loop {
        if let Some(value) = check().await? {
            return Ok(value);
        }
        if start.elapsed() >= deadline {
            return Err(anyhow!("{label} did not reach its postcondition"));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

pub async fn cleanup_fixture(
    pool: &MySqlPool,
    fixture: &OwnedFixture,
    operation_ids: &[String],
) -> Result<()> {
    let lo = fixture.suite.base;
    let tenant_hi = fixture.suite.base + fixture.suite.tenants.len() as i64;
    let card_hi = fixture.suite.base + 14 * testsuite::CATEGORY_STRIDE + 2_000;
    let mut tx = tokio::time::timeout(DB_TIMEOUT, pool.begin())
        .await
        .context("cleanup transaction begin timed out")??;
    let (ordering_key, counter_key) = fixture_message_scope(fixture);
    let counter: Option<i64> = sqlx::query_scalar(
        "SELECT last_sequence FROM al_message_scope_counter WHERE scope_key = ? \
         AND CAST(scope_key AS BINARY) = CAST(? AS BINARY) FOR UPDATE",
    )
    .bind(&counter_key)
    .bind(&counter_key)
    .fetch_optional(&mut *tx)
    .await?;
    let messages = sqlx::query(
        "SELECT operation_id, tenant_id, origin_region, message_type, status, lease_owner, scope_sequence \
         FROM al_message_outbox WHERE queue_name = ? AND ordering_key = ? FOR UPDATE",
    )
    .bind(astral_mq::invalidation::INVALIDATION_QUEUE)
    .bind(&ordering_key)
    .fetch_all(&mut *tx)
    .await?;
    let expected_origin = format!("owned-http-{:x}", fixture.suite.salt);
    let mut sequences = std::collections::BTreeSet::new();
    for row in &messages {
        let operation_id: String = row.try_get("operation_id")?;
        let tenant_id: Option<i64> = row.try_get("tenant_id")?;
        let origin: String = row.try_get("origin_region")?;
        let message_type: String = row.try_get("message_type")?;
        let status: String = row.try_get("status")?;
        let owner: Option<String> = row.try_get("lease_owner")?;
        let sequence: Option<i64> = row.try_get("scope_sequence")?;
        if !operation_ids.contains(&operation_id)
            || tenant_id != Some(fixture.tenant_id)
            || origin != expected_origin
            || message_type != astral_mq::invalidation::EVIDENCE_INVALIDATED
            || !matches!(status.as_str(), "PENDING" | "PROCESSED")
            || owner.as_deref().is_some_and(|value| !value.is_empty())
            || sequence.is_none_or(|value| value <= 0 || !sequences.insert(value))
        {
            return Err(anyhow!("HTTP fixture message scope ownership is unproven"));
        }
    }
    if counter != sequences.last().copied() {
        return Err(anyhow!(
            "HTTP fixture message counter does not match its owned rows"
        ));
    }
    let pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM authorization_delta_event \
         WHERE tenant_id > ? AND tenant_id <= ? AND status <> 'SUCCEEDED'",
    )
    .bind(lo)
    .bind(tenant_hi)
    .fetch_one(&mut *tx)
    .await?;
    let active: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM authorization_projection_partition_lease \
         WHERE tenant_id > ? AND tenant_id <= ? AND \
           (active_delta_event_id IS NOT NULL OR active_delta_token_hash IS NOT NULL \
            OR lease_owner <> '' OR lease_expires_at > UTC_TIMESTAMP(6))",
    )
    .bind(lo)
    .bind(tenant_hi)
    .fetch_one(&mut *tx)
    .await?;
    if pending != 0 || active != 0 {
        return Err(anyhow!(
            "HTTP fixture cleanup requires all events succeeded and lanes inactive"
        ));
    }
    sqlx::query(
        "DELETE a FROM audit_log a INNER JOIN authorization_delta_event d \
           ON d.tenant_id = a.tenant_id \
          AND CAST(d.event_id AS BINARY) = \
              CAST(JSON_UNQUOTE(JSON_EXTRACT(a.detail, '$.eventId')) AS BINARY) \
         WHERE a.tenant_id > ? AND a.tenant_id <= ? \
           AND a.event_type = 'AUTHZ_OWNED_PROJECTION_LANE' \
           AND a.resource = 'authorization_projection_owned_lane'",
    )
    .bind(lo)
    .bind(tenant_hi)
    .execute(&mut *tx)
    .await
    .context("cleanup exact HTTP fixture lane audit")?;
    for table in [
        "authorization_projection_partition_lease",
        "authorization_projection_manifest_segment",
        "authorization_projection_current",
        "authorization_projection_manifest",
        "authorization_projection_segment",
        "authorization_impact_plan_item",
        "authorization_impact_plan",
        "authorization_archive_manifest",
        "authorization_archive_outbox",
        "authorization_delta_event",
        "authorization_grant_revision",
    ] {
        let sql = format!("DELETE FROM {table} WHERE tenant_id > ? AND tenant_id <= ?");
        sqlx::query(&sql)
            .bind(lo)
            .bind(tenant_hi)
            .execute(&mut *tx)
            .await
            .with_context(|| format!("cleanup {table}"))?;
    }
    for table in [
        "authorization_projection_outbox",
        "authorization_projection_head",
    ] {
        let sql = format!("DELETE FROM {table} WHERE aggregate_id > ? AND aggregate_id <= ?");
        sqlx::query(&sql)
            .bind(lo)
            .bind(card_hi)
            .execute(&mut *tx)
            .await
            .with_context(|| format!("cleanup {table}"))?;
    }
    sqlx::query("DELETE FROM permission_rule WHERE card_id > ? AND card_id <= ?")
        .bind(lo)
        .bind(card_hi)
        .execute(&mut *tx)
        .await
        .context("cleanup permission source rows")?;
    if !operation_ids.is_empty() {
        let placeholders = std::iter::repeat_n("?", operation_ids.len())
            .collect::<Vec<_>>()
            .join(",");
        let message_sql = format!(
            "DELETE FROM al_message_outbox WHERE tenant_id = ? AND origin_region = ? \
             AND operation_id IN ({placeholders})"
        );
        let audit_sql = format!("DELETE FROM audit_log WHERE request_id IN ({placeholders})");
        let ruleset_audit_sql = format!(
            "DELETE FROM rule_set_projection_audit WHERE tenant_id > ? AND tenant_id <= ? \
             AND operation_id IN ({placeholders})"
        );
        let mut message_query = sqlx::query(&message_sql)
            .bind(fixture.tenant_id)
            .bind(&expected_origin);
        let mut audit_query = sqlx::query(&audit_sql);
        let mut ruleset_audit_query = sqlx::query(&ruleset_audit_sql).bind(lo).bind(tenant_hi);
        for operation_id in operation_ids {
            message_query = message_query.bind(operation_id);
            audit_query = audit_query.bind(operation_id);
            ruleset_audit_query = ruleset_audit_query.bind(operation_id);
        }
        message_query
            .execute(&mut *tx)
            .await
            .context("cleanup message outbox")?;
        audit_query
            .execute(&mut *tx)
            .await
            .context("cleanup audit correlation")?;
        ruleset_audit_query
            .execute(&mut *tx)
            .await
            .context("cleanup RuleSet bootstrap audit correlation")?;
    }
    if let Some(last_sequence) = counter {
        let deleted = sqlx::query(
            "DELETE FROM al_message_scope_counter WHERE scope_key = ? \
             AND CAST(scope_key AS BINARY) = CAST(? AS BINARY) AND last_sequence = ? \
             AND NOT EXISTS (SELECT 1 FROM al_message_outbox WHERE queue_name = ? AND ordering_key = ?)",
        )
        .bind(&counter_key)
        .bind(&counter_key)
        .bind(last_sequence)
        .bind(astral_mq::invalidation::INVALIDATION_QUEUE)
        .bind(&ordering_key)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if deleted != 1 {
            return Err(anyhow!(
                "HTTP fixture message counter retirement was not proven"
            ));
        }
    }
    tx.commit().await.context("cleanup transaction commit")?;
    cleanup_suite_rows(pool, &fixture.suite)
        .await
        .context("cleanup suite topology")?;
    let remaining: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM audit_log WHERE tenant_id > ? AND tenant_id <= ? \
                  AND event_type = 'AUTHZ_OWNED_PROJECTION_LANE') + \
                (SELECT COUNT(*) FROM rule_set_projection_audit WHERE tenant_id > ? AND tenant_id <= ?) + \
                (SELECT COUNT(*) FROM al_message_scope_counter WHERE scope_key = ?) + \
                (SELECT COUNT(*) FROM al_message_outbox WHERE queue_name = ? AND ordering_key = ?)",
    )
    .bind(lo)
    .bind(tenant_hi)
    .bind(lo)
    .bind(tenant_hi)
    .bind(&counter_key)
    .bind(astral_mq::invalidation::INVALIDATION_QUEUE)
    .bind(&ordering_key)
    .fetch_one(pool)
    .await?;
    if remaining != 0 {
        return Err(anyhow!(
            "HTTP fixture audit or message scope cleanup is incomplete"
        ));
    }
    Ok(())
}
