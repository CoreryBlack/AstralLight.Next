//! AstralTrustGraph — 权限治理中心后端

pub mod api;
pub mod observability;
pub mod repository;
pub mod service;

use astral_common::config::AppConfig;
use axum::extract::FromRef;
use policy_engine::PolicyEngine;
use sqlx::MySqlPool;
use std::sync::Arc;

use repository::admin_group_repository::AdminGroupRepository;
use repository::audit_log_repository::AuditLogRepository;
use repository::card_template_repository::CardTemplateRepository;
use repository::cross_org_grant_repository::CrossOrgGrantRepository;
use repository::delegation_repository::DelegationRepository;
use repository::department_repository::DepartmentRepository;
use repository::domain_repository::DomainRepository;
use repository::global_admin_repository::GlobalAdminRepository;
use repository::grading_repository::GradingRepository;
use repository::hit_stat_repository::HitStatRepository;
use repository::inheritance_config_repository::InheritanceConfigRepository;
use repository::level_repository::LevelRepository;
use repository::level_template_repository::LevelTemplateRepository;
use repository::permission_action_repository::PermissionActionRepository;
use repository::permission_request_repository::PermissionRequestRepository;
use repository::platform_package_repository::PlatformPackageRepository;
use repository::resource_type_repository::ResourceTypeRepository;
use repository::rule_repository::RuleRepository;
use repository::rule_set_repository::RuleSetRepository;
use repository::sod_repository::SodRepository;
use repository::template_repository::TemplateRepository;
use repository::tenant_repository::TenantRepository;
use repository::user_card_repository::UserCardRepository;
use service::approval_service::ApprovalService;
use service::arbiter::ArbiterService;
use service::audit_replay_worker::AuditReplayProducerSlot;
use service::delegation_service::DelegationWriteService;
use service::level_template_service::LevelTemplateService;
use service::personal_permission_service::PersonalPermissionService;
use service::rule_set_write_service::RuleSetWriteService;
use service::rule_write_service::RuleWriteService;
use service::template_service::TemplateService;
use service::tenant_service::TenantService;
use service::user_card_service::UserCardService;

/// 共享应用状态
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub db: MySqlPool,
    /// 共享 PolicyEngine 实例（所有评估复用同一实例，累积命中计数与时序统计）
    pub engine: Arc<PolicyEngine>,
    /// 第一批纯 CRUD 模块的数据访问（对齐 Java Infrastructure Mapper）
    pub domain_repository: Arc<dyn DomainRepository>,
    pub level_repository: Arc<dyn LevelRepository>,
    pub grading_repository: Arc<dyn GradingRepository>,
    pub card_template_repository: Arc<dyn CardTemplateRepository>,
    pub global_admin_repository: Arc<dyn GlobalAdminRepository>,
    pub cross_org_grant_repository: Arc<dyn CrossOrgGrantRepository>,
    /// 第二批：规则/规则集/委托写路径（repository + 副作用链编排 service）
    pub rule_repository: Arc<dyn RuleRepository>,
    pub rule_set_repository: Arc<dyn RuleSetRepository>,
    pub delegation_repository: Arc<dyn DelegationRepository>,
    /// 管理组聚合（admin_group + admin_group_member；删除级联单事务）
    pub admin_group_repository: Arc<dyn AdminGroupRepository>,
    pub rule_write_service: Arc<RuleWriteService>,
    pub rule_set_write_service: Arc<RuleSetWriteService>,
    pub delegation_service: Arc<DelegationWriteService>,
    /// 第四批：剩余纯 CRUD 模块（部门/套餐/继承/动作/资源类型/审计/SoD/命中统计）
    pub department_repository: Arc<dyn DepartmentRepository>,
    pub platform_package_repository: Arc<dyn PlatformPackageRepository>,
    pub inheritance_config_repository: Arc<dyn InheritanceConfigRepository>,
    pub permission_action_repository: Arc<dyn PermissionActionRepository>,
    pub resource_type_repository: Arc<dyn ResourceTypeRepository>,
    pub audit_log_repository: Arc<dyn AuditLogRepository>,
    pub sod_repository: Arc<dyn SodRepository>,
    pub hit_stat_repository: Arc<dyn HitStatRepository>,
    /// 第五批：审批/模板/等级模板/用户卡/个人权限（副作用编排 service）
    pub permission_request_repository: Arc<dyn PermissionRequestRepository>,
    pub template_repository: Arc<dyn TemplateRepository>,
    pub level_template_repository: Arc<dyn LevelTemplateRepository>,
    pub user_card_repository: Arc<dyn UserCardRepository>,
    /// 第六批：租户
    pub tenant_repository: Arc<dyn TenantRepository>,
    pub tenant_service: Arc<TenantService>,
    pub approval_service: Arc<ApprovalService>,
    pub template_service: Arc<TemplateService>,
    pub level_template_service: Arc<LevelTemplateService>,
    pub user_card_service: Arc<UserCardService>,
    pub personal_permission_service: Arc<PersonalPermissionService>,
    /// 投影 worker 监督健康共享态（F5 修复 1d）：main 在启动 projector 后
    /// 写入一次；未启动（配置拒绝）时保持为空，stats 端点如实返回 None。
    pub projector_health:
        Arc<std::sync::OnceLock<Arc<service::authorization_projector::ProjectorHealthShared>>>,
    /// 执剑人运行侧服务（冲突信号统计 + 跨节点证据仲裁）
    pub arbiter_service: Arc<ArbiterService>,
    /// Owned audit replay producer hand-off. The worker JoinHandle is retained
    /// by TrustGraph main rather than placed in cloneable request state.
    pub audit_replay_producer: AuditReplayProducerSlot,
    /// Internal test-control configuration. `None` means the routes are not registered.
    pub test_control: Option<Arc<api::test_control::TestControlConfig>>,
    /// ORG_SCOPE deployment switch parsed once during startup. A managed tenant
    /// is denied rather than falling back to legacy card evidence when false.
    pub org_scope_enabled: bool,
    /// Startup-frozen ORG_SCOPE projector coverage boundary. Every existing or
    /// newly managed tenant must be listed before a governance mutation can
    /// create/alter its durable authority state, otherwise its outbox could not
    /// be consumed by the owned projector. Empty only while ORG_SCOPE is off.
    pub org_scope_tenant_allowlist: Vec<i64>,
}

impl FromRef<AppState> for MySqlPool {
    fn from_ref(state: &AppState) -> Self {
        state.db.clone()
    }
}

impl FromRef<AppState> for astral_common::config::AppConfig {
    fn from_ref(state: &AppState) -> Self {
        (*state.config).clone()
    }
}
