//! memory—v1: Governance router and registration parity without external services.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, OnceLock},
};

use astral_common::config::AppConfig;
use astral_trustgraph::{
    api::{governance_routes::governance_routes, permission_check::MEMORY_V1_ROUTE_REGISTRATIONS},
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
    body::Body,
    http::{Method, Request, StatusCode},
    Router,
};
use policy_engine::PolicyEngine;
use sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions};
use tower::ServiceExt;

// memory—v1: The pool is lazy and points to a nonexistent per-run Unix socket;
// governance handlers reject missing admission before any repository access.
fn state() -> AppState {
    let pool = MySqlPoolOptions::new().connect_lazy_with(MySqlConnectOptions::new().socket(
        std::env::temp_dir().join(format!("astral-governance-parity-{}", uuid::Uuid::new_v4())),
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
        config: Arc::new(AppConfig::default()),
        db: pool.clone(),
        engine: Arc::new(PolicyEngine::new()),
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
        memory_v1_governance_commit: Arc::new(
            astral_trustgraph::service::memory_v1_governance_commit::FailClosedMemoryV1GovernanceCommitPort,
        ),
        memory_v1_deny_proof: std::sync::Arc::new(
            astral_trustgraph::service::memory_v1_governance_commit::FailClosedMemoryV1DenyProofPort,
        ),
        authorization_fence_provider: None,
        projector_health: Arc::new(OnceLock::new()),
        audit_replay_producer: AuditReplayProducerSlot::new(),
        test_control: None,
        org_scope_enabled: false,
        org_scope_tenant_allowlist: vec![],
    }
}

// memory—v1: Parse only the production Router expression, rejecting unrecognized
// syntax so a future route construction style cannot silently evade the guard.
fn router_routes() -> BTreeSet<(String, String)> {
    let source = include_str!("../src/api/governance_routes.rs");
    let body = source
        .split_once("pub fn governance_routes() -> Router<AppState> {")
        .expect("governance router signature changed")
        .1
        .split_once("\n}")
        .expect("governance router end missing")
        .0;
    let mut tokens = Vec::new();
    let mut chars = body.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch.is_whitespace() {
            continue;
        }
        if ch == '"' {
            let mut value = String::new();
            loop {
                let next = chars.next().expect("unterminated route string");
                if next == '"' {
                    break;
                }
                assert_ne!(next, '\\', "escaped route literals require parser review");
                value.push(next);
            }
            tokens.push(format!("\"{value}\""));
        } else if ch.is_ascii_alphanumeric() || ch == '_' {
            let mut ident = String::from(ch);
            while chars
                .peek()
                .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_')
            {
                ident.push(chars.next().unwrap());
            }
            tokens.push(ident);
        } else {
            assert!(".:(),".contains(ch), "unrecognized Router syntax: {ch}");
            tokens.push(ch.to_string());
        }
    }
    let mut pos = 0;
    fn take<'a>(tokens: &'a [String], pos: &mut usize) -> &'a str {
        let value = tokens.get(*pos).expect("incomplete Router expression");
        *pos += 1;
        value
    }
    fn expect(tokens: &[String], pos: &mut usize, expected: &str) {
        assert_eq!(
            take(tokens, pos),
            expected,
            "Router expression requires review"
        );
    }
    for token in ["Router", ":", ":", "new", "(", ")"] {
        expect(&tokens, &mut pos, token);
    }
    let mut routes = BTreeSet::new();
    while pos < tokens.len() {
        for token in [".", "route", "("] {
            expect(&tokens, &mut pos, token);
        }
        let literal = take(&tokens, &mut pos);
        let path = literal
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .expect("literal route path required");
        assert!(
            path.starts_with("/governance/") && !path.contains(['{', '}', '*']),
            "route path requires review: {path}"
        );
        expect(&tokens, &mut pos, ",");
        loop {
            let method = take(&tokens, &mut pos);
            assert!(
                ["get", "post", "put", "patch", "delete", "options", "head", "trace"]
                    .contains(&method),
                "unsupported method: {method}"
            );
            expect(&tokens, &mut pos, "(");
            let handler = take(&tokens, &mut pos);
            assert!(
                handler
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "handler syntax requires review"
            );
            expect(&tokens, &mut pos, ")");
            assert!(
                routes.insert((method.to_ascii_uppercase(), path.to_owned())),
                "duplicate route"
            );
            if tokens.get(pos).is_some_and(|t| t == ".") {
                pos += 1;
            } else {
                break;
            }
        }
        if tokens.get(pos).is_some_and(|t| t == ",") {
            pos += 1;
        }
        expect(&tokens, &mut pos, ")");
    }
    assert!(!routes.is_empty(), "no governance routes found");
    routes
}

#[tokio::test]
async fn governance_router_and_registration_match_in_both_directions() {
    let actual = router_routes();
    let mut registered = BTreeSet::new();
    for route in MEMORY_V1_ROUTE_REGISTRATIONS
        .iter()
        .filter(|r| r.path.starts_with("/governance/"))
    {
        assert!(
            registered.insert((route.method.to_owned(), route.path.to_owned())),
            "duplicate governance registration: {} {}",
            route.method,
            route.path
        );
    }
    assert_eq!(
        actual, registered,
        "Router and memory-v1 registrations differ"
    );

    let paths: BTreeSet<_> = actual
        .iter()
        .chain(&registered)
        .map(|(_, path)| path.as_str())
        .collect();
    let app: Router = governance_routes().with_state(state());
    for path in paths {
        for method in [
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
            Method::HEAD,
            Method::TRACE,
            Method::CONNECT,
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method.clone())
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            if actual.contains(&(method.as_str().to_owned(), path.to_owned())) {
                assert_eq!(
                    response.status(),
                    StatusCode::SERVICE_UNAVAILABLE,
                    "registered handler must reject missing admission: {method} {path}"
                );
            } else {
                assert_eq!(
                    response.status(),
                    StatusCode::METHOD_NOT_ALLOWED,
                    "unexpected Router method: {method} {path}"
                );
            }
        }
    }
}

#[test]
fn governance_registration_has_exact_primary_and_compound_actions() {
    // Binding create always confirms; create-overlay-only applies only to the
    // overlay-only branch. Both rule-set changes require confirm-change.
    let expected = BTreeMap::from([
        (
            ("POST", "/governance/bindings"),
            ("binding", "create", &["confirm", "create-overlay-only"][..]),
        ),
        (
            ("DELETE", "/governance/bindings"),
            ("binding", "remove", &[][..]),
        ),
        (
            ("POST", "/governance/bindings/confirm"),
            ("binding", "confirm", &[][..]),
        ),
        (
            ("POST", "/governance/bindings/confirm/batch"),
            ("binding", "confirm", &[][..]),
        ),
        (
            ("POST", "/governance/bindings/revoke-confirmation"),
            ("binding", "revoke-confirmation", &[][..]),
        ),
        (
            ("POST", "/governance/rule-sets"),
            ("rule_set", "create", &["confirm-change"][..]),
        ),
        (
            ("POST", "/governance/rule-sets/publish"),
            ("rule_set", "version-publish", &["confirm-change"][..]),
        ),
        (
            ("POST", "/governance/rule-sets/retire"),
            ("rule_set", "retire", &[][..]),
        ),
        (
            ("POST", "/governance/user-cards"),
            ("user_card", "create", &[][..]),
        ),
        (
            ("POST", "/governance/user-cards/enable"),
            ("user_card", "enable", &[][..]),
        ),
        (
            ("POST", "/governance/user-cards/disable"),
            ("user_card", "disable", &[][..]),
        ),
    ]);
    let mut actual = BTreeMap::new();
    for route in MEMORY_V1_ROUTE_REGISTRATIONS
        .iter()
        .filter(|r| r.path.starts_with("/governance/"))
    {
        assert!(
            actual
                .insert(
                    (route.method, route.path),
                    (route.resource, route.action, route.additional_actions)
                )
                .is_none(),
            "duplicate governance registration"
        );
    }
    assert_eq!(actual, expected, "governance action metadata changed");
}
