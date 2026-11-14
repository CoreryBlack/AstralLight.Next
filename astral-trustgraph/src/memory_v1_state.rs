//! memory—v1: A TrustGraph [`AppState`] with no live database endpoint.
//!
//! The memory—v1 authorization path is entirely in process: the root is loaded
//! once at startup and every decision reads it through the request's own scope.
//! A TrustGraph router built from this state therefore must not reach MySQL, and
//! a handler that wrongly tries to read legacy rows cannot succeed: its pool
//! points at a Unix socket path that does not exist and gives up after a short
//! acquire timeout. Routes that have not been adapted to memory—v1 are refused
//! before any handler runs; this state is the second line of defence behind that.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use astral_common::config::AppConfig;
use policy_engine::PolicyEngine;
use sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions};
use sqlx::MySqlPool;

use crate::repository::{
    admin_group_repository::SqlxAdminGroupRepository, audit_log_repository::SqlxAuditLogRepository,
    card_template_repository::SqlxCardTemplateRepository,
    cross_org_grant_repository::SqlxCrossOrgGrantRepository,
    delegation_repository::SqlxDelegationRepository,
    department_repository::SqlxDepartmentRepository, domain_repository::SqlxDomainRepository,
    global_admin_repository::SqlxGlobalAdminRepository, grading_repository::SqlxGradingRepository,
    hit_stat_repository::SqlxHitStatRepository,
    inheritance_config_repository::SqlxInheritanceConfigRepository,
    level_repository::SqlxLevelRepository, level_template_repository::SqlxLevelTemplateRepository,
    permission_action_repository::SqlxPermissionActionRepository,
    permission_request_repository::SqlxPermissionRequestRepository,
    platform_package_repository::SqlxPlatformPackageRepository,
    resource_type_repository::SqlxResourceTypeRepository, rule_repository::SqlxRuleRepository,
    rule_set_repository::SqlxRuleSetRepository, sod_repository::SqlxSodRepository,
    template_repository::SqlxTemplateRepository, tenant_repository::SqlxTenantRepository,
    user_card_repository::SqlxUserCardRepository,
};
use crate::service::{
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
};
use crate::AppState;

// memory—v1: A pool that can never connect: a Unix socket path nobody listens on.
fn offline_pool() -> MySqlPool {
    MySqlPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(200))
        .connect_lazy_with(
            MySqlConnectOptions::new().socket(std::env::temp_dir().join(format!(
                "astral-memory-v1-no-endpoint-{}",
                uuid::Uuid::new_v4()
            ))),
        )
}

/// memory—v1: Build the TrustGraph application state for the in-process
/// memory—v1 profile.
///
/// Every repository and service shares one pool that cannot connect, so no
/// legacy row can back a decision or a response. `engine` is the shared
/// [`PolicyEngine`]; its decisions come from the request's root scope, never from
/// this state. No background worker, fence provider or audit producer is started.
pub fn build_memory_v1_offline_app_state(config: AppConfig, engine: Arc<PolicyEngine>) -> AppState {
    let pool = offline_pool();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    // memory—v1: The state's pool fails fast instead of reaching any database.
    async fn offline_state_cannot_reach_a_database() {
        let state =
            build_memory_v1_offline_app_state(AppConfig::default(), Arc::new(PolicyEngine::new()));
        let started = std::time::Instant::now();
        let outcome = sqlx::query("SELECT 1").execute(&state.db).await;
        assert!(outcome.is_err(), "the offline pool must never connect");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the offline pool must fail fast"
        );
        assert!(state.authorization_fence_provider.is_none());
        assert!(state.test_control.is_none());
        assert!(!state.org_scope_enabled);
    }

    #[tokio::test]
    // memory—v1: Each state owns its own unreachable endpoint; none is shared.
    async fn offline_endpoints_are_unique_per_state() {
        let first = format!("{:?}", offline_pool().connect_options());
        let second = format!("{:?}", offline_pool().connect_options());
        assert_ne!(first, second);
    }
}
