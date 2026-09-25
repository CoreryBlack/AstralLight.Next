//! AstralTrustGraph 启动入口
//!
//! ```bash
//! cargo run -p astral-trustgraph
//! # LISTEN_ADDR=0.0.0.0:9005 cargo run -p astral-trustgraph
//! ```

use std::sync::Arc;

use axum::Router;
use lapin::Connection;
use policy_engine::PolicyEngine;

use astral_common::audit::{register_audit_db_writer, AuditDbWriter, AuditEntry};
use astral_common::config::{AppConfig, JwtValidationRole};
use astral_common::error::global_exception_handler;
use astral_common::middleware::gateway_signature::gateway_signature_middleware;
use astral_common::service::{register_mq_producer, AuditLogEvent, MqProducerRef};
use astral_common::tracing::init_tracing;
use astral_db::connect_and_validate_schema_with_pool_options;
use astral_db::org_scope_repository::{
    list_org_scope_managed_tenant_ids, missing_org_scope_tenant_allowlist_entries,
    validate_org_scope_schema_prerequisites, SqlxOrgScopeRepository,
};
use astral_db::probe_org_scope_gate;
use astral_db::OrgScopeGateState;
use astral_types::ResourceRegistry;

use astral_trustgraph::api;
use astral_trustgraph::repository::admin_group_repository::SqlxAdminGroupRepository;
use astral_trustgraph::repository::audit_log_repository::SqlxAuditLogRepository;
use astral_trustgraph::repository::card_template_repository::SqlxCardTemplateRepository;
use astral_trustgraph::repository::cross_org_grant_repository::SqlxCrossOrgGrantRepository;
use astral_trustgraph::repository::delegation_repository::SqlxDelegationRepository;
use astral_trustgraph::repository::department_repository::SqlxDepartmentRepository;
use astral_trustgraph::repository::domain_repository::SqlxDomainRepository;
use astral_trustgraph::repository::global_admin_repository::SqlxGlobalAdminRepository;
use astral_trustgraph::repository::grading_repository::SqlxGradingRepository;
use astral_trustgraph::repository::hit_stat_repository::SqlxHitStatRepository;
use astral_trustgraph::repository::inheritance_config_repository::SqlxInheritanceConfigRepository;
use astral_trustgraph::repository::level_repository::SqlxLevelRepository;
use astral_trustgraph::repository::level_template_repository::SqlxLevelTemplateRepository;
use astral_trustgraph::repository::permission_action_repository::SqlxPermissionActionRepository;
use astral_trustgraph::repository::permission_request_repository::SqlxPermissionRequestRepository;
use astral_trustgraph::repository::platform_package_repository::SqlxPlatformPackageRepository;
use astral_trustgraph::repository::projection_repository::SqlxProjectionRepository;
use astral_trustgraph::repository::resource_type_repository::SqlxResourceTypeRepository;
use astral_trustgraph::repository::rule_repository::SqlxRuleRepository;
use astral_trustgraph::repository::rule_set_repository::{
    RuleSetRepository, SqlxRuleSetRepository,
};
use astral_trustgraph::repository::sod_repository::SqlxSodRepository;
use astral_trustgraph::repository::template_repository::SqlxTemplateRepository;
use astral_trustgraph::repository::tenant_repository::SqlxTenantRepository;
use astral_trustgraph::repository::user_card_repository::SqlxUserCardRepository;
use astral_trustgraph::service::approval_service::ApprovalService;
use astral_trustgraph::service::audit_replay_worker::{
    start_worker as start_audit_replay_worker, AuditReplayProducerSlot, AuditReplayWorkerHandle,
};
use astral_trustgraph::service::authorization_archive_worker::{
    shutdown_authorization_archive_worker, start_authorization_archive_worker,
    AuthorizationArchiveWorkerHandle, SHUTDOWN_JOIN_TIMEOUT_SECS,
};
use astral_trustgraph::service::authorization_projector::{
    parse_projector_scheduling_mode, parse_projector_tenants, parse_projector_worker_count,
    shutdown_authorization_projector, start_authorization_projector,
    validate_partition_worker_budget, AuthorizationProjectorConfig, AuthorizationProjectorHandle,
    ProjectorHealthShared, ProjectorSchedulingMode,
};
use astral_trustgraph::service::delegation_expiry_worker::{
    parse_delegation_expiry_config, shutdown_delegation_expiry_worker,
    start_delegation_expiry_worker, DelegationExpiryWorkerHandle,
};
use astral_trustgraph::service::delegation_service::DelegationWriteService;
use astral_trustgraph::service::level_template_service::LevelTemplateService;
use astral_trustgraph::service::org_scope_projector::{
    org_scope_projector_shutdown_timeout, parse_org_scope_projector_config,
    shutdown_org_scope_projector, start_org_scope_projector, OrgScopeProjectorEnvRaw,
    OrgScopeProjectorHandle, ENV_BACKOFF_CAP_SECS, ENV_BATCH_PER_TENANT, ENV_EVENT_DEADLINE_MS,
    ENV_LEASE_SECS, ENV_MAX_ATTEMPTS, ENV_POLL_SECS, ENV_PROPAGATE_BATCH_LIMIT, ENV_TENANTS,
};
use astral_trustgraph::service::personal_permission_service::PersonalPermissionService;
use astral_trustgraph::service::projection_worker::{
    shutdown_projection_worker, spawn_worker, ProjectionWorkerHandle,
};
use astral_trustgraph::service::rule_set_write_service::RuleSetWriteService;
use astral_trustgraph::service::rule_write_service::RuleWriteService;
use astral_trustgraph::service::side_effect::SqlxPermissionSideEffects;
use astral_trustgraph::service::template_service::TemplateService;
use astral_trustgraph::service::tenant_service::TenantService;
use astral_trustgraph::service::user_card_service::UserCardService;
use astral_trustgraph::AppState;

struct TrustGraphAuditDbWriter {
    pool: sqlx::MySqlPool,
}

#[async_trait::async_trait]
impl AuditDbWriter for TrustGraphAuditDbWriter {
    async fn insert_audit(&self, entry: &AuditEntry) -> Result<(), String> {
        astral_db::insert_audit_log(&self.pool, entry)
            .await
            .map_err(|e| e.to_string())
    }
}

struct TrustGraphMqProducer {
    inner: astral_mq::producer::Producer,
}

#[async_trait::async_trait]
impl MqProducerRef for TrustGraphMqProducer {
    async fn publish_audit_log(&self, event: AuditLogEvent) -> Result<(), String> {
        self.inner
            .publish_audit_log(astral_mq::producer::AuditLogPayload {
                // message_id 必须唯一：audit consumer 以它为 mq_idempotent_log 幂等键，
                // 恒 None 会回退到 (user,event,action,resource,request) 派生键——permission
                // 审计 request_id 恒 None，相同 user+resource+action 的重复判定会被
                // INSERT IGNORE 丢弃，真实审计行静默丢失。
                message_id: Some(uuid::Uuid::new_v4().to_string()),
                user_id: event.user_id,
                card_id: event.card_id,
                action: event.action,
                resource: event.resource,
                decision: event.decision,
                reason: event.reason,
                event_type: event.event_type,
                source_ip: event.source_ip,
                request_id: event.request_id,
                domain_id: event.domain_id,
                tenant_id: event.tenant_id,
                // producer detail（例如 ORG_SCOPE provenance JSON）随消息透传；
                // consumer 仅在非空白时落库，否则回退 messageId 关联文本。
                detail: event.detail,
            })
            .await
            .map_err(|e| e.to_string())
    }

    async fn publish_login_event(
        &self,
        user_id: i64,
        login_type: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        success: bool,
    ) -> Result<(), String> {
        self.inner
            .publish_login_event(astral_mq::producer::LoginEventPayload {
                // 与审计一致：UUID 幂等键，防 DLX 重投重复登录审计行
                message_id: Some(uuid::Uuid::new_v4().to_string()),
                user_id,
                card_id: None,
                login_type: login_type.to_string(),
                ip_address: ip_address.map(str::to_string),
                user_agent: user_agent.map(str::to_string),
                success,
            })
            .await
            .map_err(|e| e.to_string())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    // Prometheus 指标独立绑定 loopback，避免进入 Gateway 签名与授权 Router。
    // recorder 或监听失败只禁用观测，绝不改变 TrustGraph 的启动或 fail-closed 语义。
    if let Some(metrics_addr) =
        astral_common::metrics_runtime::metrics_listen_addr("127.0.0.1:9102")
    {
        match astral_common::metrics_runtime::install_prometheus_recorder() {
            Ok(handle) => {
                astral_common::metrics_runtime::spawn_metrics_server(metrics_addr, handle);
            }
            Err(error) => {
                tracing::error!(error = %error, "prometheus recorder install failed; /metrics disabled")
            }
        }
    }

    let reg = ResourceRegistry::global();
    tracing::info!(
        "ResourceRegistry initialized: {} resource types",
        reg.count()
    );
    // HMAC 审计缺口修复（2026-09-21）：from_files() 的默认角色是 Learn，
    // 会跳过 gateway.hmac_secret 的强制校验——而本服务恰恰是验签 Gateway
    // 身份头的授权核心。显式声明 Gateway 角色：hmac/internal 密钥缺失、
    // 过短或占位值一律启动失败（fail-closed），绝不以占位密钥上线。
    let config = Arc::new(AppConfig::from_files_for(
        "application",
        JwtValidationRole::Gateway,
    )?);
    // ORG_SCOPE 部署旗标：由 AppConfig 在启动期经 astral-common 共享严格解析器
    // （parse_org_scope_enabled）一次性解析并冻结；非法值已在配置加载处
    // fail-closed 拒绝启动。组织路由门、org 治理元授权与 api/rules 检查端点
    // 共用同一份冻结值，default-off 语义不变。
    let org_scope_enabled = config.org_scope_enabled;
    tracing::info!(
        org_scope_enabled,
        "ORG_SCOPE deployment state frozen at startup"
    );
    // ORG_SCOPE projector 启动配置（Phase 2 default-off）：唯一门禁是上面冻结的
    // 共享 org_scope_enabled 旗标（与组织路由门、org 治理元授权共用同一份冻结值，
    // 绝不引入第二个开关）。旗标开启时，在任何 DB 连接、任何 worker 启动之前，
    // 先对既有 OrgScopeProjectorEnvRaw 的全部字段做一次显式启动 env 快照，再交
    // 既有纯函数解析器 fail-fast 校验——tenant 列表缺失/空白由解析器 validate
    // 阶段拒绝（"list is empty"，绝不静默空转吞积压），任何非法值都在任何 ORG
    // 任务与任何既有 worker 启动之前拒绝进程启动（此处无任何已启动任务，无需
    // 回滚）。旗标关闭时：不读专属 env、不解析、不留下任何 ORG 配置状态。解析
    // 结果在此冻结；实际启动点（委托到期对账 worker 之后）使用这份预校验配置，
    // start 在 spawn 前还会再次 validate（双重 fail-closed）。
    let org_scope_projector_config = if org_scope_enabled {
        let env_raw = OrgScopeProjectorEnvRaw {
            tenants: std::env::var(ENV_TENANTS).ok(),
            poll_interval_secs: std::env::var(ENV_POLL_SECS).ok(),
            claim_lease_seconds: std::env::var(ENV_LEASE_SECS).ok(),
            max_event_attempts: std::env::var(ENV_MAX_ATTEMPTS).ok(),
            backoff_cap_seconds: std::env::var(ENV_BACKOFF_CAP_SECS).ok(),
            events_per_tenant_cycle: std::env::var(ENV_BATCH_PER_TENANT).ok(),
            event_deadline_ms: std::env::var(ENV_EVENT_DEADLINE_MS).ok(),
            propagate_batch_limit: std::env::var(ENV_PROPAGATE_BATCH_LIMIT).ok(),
        };
        match parse_org_scope_projector_config(&env_raw) {
            Ok(config) => Some(config),
            Err(error) => {
                tracing::error!(
                    error = %error,
                    error_code = "ORG_SCOPE_PROJECTOR_CONFIG_INVALID",
                    "invalid org scope projector configuration; refusing startup before \
                     any worker spawned"
                );
                return Err(anyhow::anyhow!(error));
            }
        }
    } else {
        None
    };
    // 读链规模化：连接池扩容（默认 max_connections=80 / acquire 5s 快速失败，
    // env ASTRAL_DB_MAX_CONNECTIONS / ASTRAL_DB_ACQUIRE_TIMEOUT_SECS 可覆盖，
    // 解析规则见 AppConfig::resolved_db_max_connections；非法配置启动失败）。
    // 启动校验契约与 connect_and_validate_schema 完全一致（见 astral-db）。
    let db = connect_and_validate_schema_with_pool_options(
        &config.database_url,
        config
            .resolved_db_max_connections()
            .map_err(anyhow::Error::msg)?,
        config
            .resolved_db_acquire_timeout()
            .map_err(anyhow::Error::msg)?,
    )
    .await?;
    register_audit_db_writer(Arc::new(TrustGraphAuditDbWriter { pool: db.clone() }));

    // ORG_SCOPE enabled 模式的运行期 schema + allowlist coverage 门（只读）：
    // 旗标开启时，在任何 worker/路由装配之前确认 schema 存在，并读取全部当前
    // org_scope_node 租户。frozen ASTRAL_ORG_SCOPE_TENANTS 必须覆盖每一个管理态
    // 单元；遗漏会让其 outbox 永久无人消费，故拒绝启动而不是静默 fail-closed 停滞。
    // 新建/挂靠到尚未列入 frozen allowlist 的租户也由治理 service 拒绝，运维须先
    // 更新 allowlist 并重启。本检查不把单个 tenant probe、空 outbox 或 inactive
    // node 当作覆盖证明。旗标关闭时不探测、不产生任何 ORG 读写。
    if let Some(org_scope_config) = &org_scope_projector_config {
        validate_org_scope_schema_prerequisites(&db)
            .await
            .map_err(|error| {
                tracing::error!(
                    error = %error,
                    error_code = "ORG_SCOPE_SCHEMA_PREREQUISITES_REJECTED",
                    "enabled ORG_SCOPE startup lacks the required source/index contracts"
                );
                anyhow::anyhow!(
                    "enabled ORG_SCOPE startup requires the complete org schema and membership-cap indexes: {error}"
                )
            })?;
        let Some(first_tenant) = org_scope_config.tenants.first().copied() else {
            // 解析器 validate 已保证非空；此处仅作防御性 fail-closed。
            tracing::error!(
                error_code = "ORG_SCOPE_PROJECTOR_CONFIG_INVALID",
                "org scope projector configuration carries no tenants; refusing startup"
            );
            return Err(anyhow::anyhow!(
                "org scope projector configuration carries no tenants"
            ));
        };
        match probe_org_scope_gate(&db, first_tenant).await {
            OrgScopeGateState::TenantUnmanaged | OrgScopeGateState::TenantManaged { .. } => {
                tracing::info!(
                    first_tenant,
                    "org scope schema gate passed for the enabled ORG_SCOPE projector"
                );
            }
            OrgScopeGateState::SchemaUnmanaged | OrgScopeGateState::Pending => {
                tracing::error!(
                    error_code = "ORG_SCOPE_SCHEMA_GATE_REJECTED",
                    first_tenant,
                    "org scope schema gate rejected the enabled ORG_SCOPE projector \
                     (schema unmanaged or probe pending); refusing startup"
                );
                return Err(anyhow::anyhow!(
                    "org scope schema gate rejected enabled ORG_SCOPE startup: \
                     org_scope schema is not confirmed present; apply the explicit \
                     org scope migration before enabling ASTRAL_ORG_SCOPE_ENABLED"
                ));
            }
        }
        let managed_tenants = list_org_scope_managed_tenant_ids(&db)
            .await
            .map_err(|error| {
                tracing::error!(
                    error = %error,
                    error_code = "ORG_SCOPE_ALLOWLIST_COVERAGE_UNAVAILABLE",
                    "cannot prove ORG_SCOPE tenant allowlist coverage; refusing startup"
                );
                anyhow::anyhow!(
                    "cannot prove ORG_SCOPE tenant allowlist coverage before startup: {error}"
                )
            })?;
        let missing_tenants =
            missing_org_scope_tenant_allowlist_entries(&org_scope_config.tenants, &managed_tenants);
        if !missing_tenants.is_empty() {
            tracing::error!(
                error_code = "ORG_SCOPE_ALLOWLIST_INCOMPLETE",
                configured_tenants = ?org_scope_config.tenants,
                missing_tenants = ?missing_tenants,
                "enabled ORG_SCOPE projector allowlist omits managed tenants; refusing startup"
            );
            return Err(anyhow::anyhow!(
                "ASTRAL_ORG_SCOPE_TENANTS omits managed tenant(s) {:?}; update the frozen allowlist and restart before enabling ORG_SCOPE",
                missing_tenants
            ));
        }
        tracing::info!(
            configured_tenants = ?org_scope_config.tenants,
            managed_tenant_count = managed_tenants.len(),
            "ORG_SCOPE schema and tenant allowlist coverage gates passed"
        );
    }

    let org_scope_tenant_allowlist = org_scope_projector_config
        .as_ref()
        .map(|config| config.tenants.clone())
        .unwrap_or_default();

    // Schema DDL is owned by the explicit Rust migration job. This runtime
    // synchronization is DML-only and mirrors Java's super-admin rule refresh.
    if let Err(error) = init_superadmin_template(&db, reg).await {
        tracing::error!(
            error = %error,
            error_code = "SUPERADMIN_INIT_FAILED",
            "superadmin template initialization failed; refusing startup"
        );
        return Err(error);
    }

    // 共享 PolicyEngine 实例
    let engine = Arc::new(PolicyEngine::new());
    tracing::info!("PolicyEngine initialized for hit stats collection");

    // 注册 TrustGraph 数据范围规则（DataScopeRuleProvider）
    astral_trustgraph::api::tenants::register_trustgraph_data_scope_rules();

    let rabbitmq_url = config.rabbitmq_url.clone();

    // 第二批：规则/规则集/委托 repository + service 装配（副作用执行器共享连接池）
    let side_effects = Arc::new(SqlxPermissionSideEffects::new(db.clone()));
    let rule_repository = Arc::new(SqlxRuleRepository::new(db.clone()));
    let rule_set_repository = Arc::new(SqlxRuleSetRepository::new(db.clone()));
    let delegation_repository = Arc::new(SqlxDelegationRepository::new(db.clone()));
    let admin_group_repository: Arc<
        dyn astral_trustgraph::repository::admin_group_repository::AdminGroupRepository,
    > = Arc::new(SqlxAdminGroupRepository::new(db.clone()));
    let rule_write_service = Arc::new(
        RuleWriteService::new(rule_repository.clone(), side_effects.clone())
            .with_sod_db(db.clone()),
    );
    let rule_set_write_service = Arc::new(RuleSetWriteService::new(rule_set_repository.clone()));
    let delegation_service = Arc::new(DelegationWriteService::new(delegation_repository.clone()));

    // 第五批：审批/模板 repository + service 装配
    let permission_request_repository = Arc::new(SqlxPermissionRequestRepository::new(db.clone()));
    let template_repository = Arc::new(SqlxTemplateRepository::new(db.clone()));
    let approval_service = Arc::new(ApprovalService::new(
        permission_request_repository.clone(),
        side_effects.clone(),
    ));
    let template_service = Arc::new(TemplateService::new(template_repository.clone()));
    let level_template_repository = Arc::new(SqlxLevelTemplateRepository::new(db.clone()));
    let user_card_repository = Arc::new(SqlxUserCardRepository::new(db.clone()));
    let level_template_service = Arc::new(LevelTemplateService::new(
        level_template_repository.clone(),
        side_effects.clone(),
    ));
    let user_card_service = Arc::new(UserCardService::new(
        user_card_repository.clone(),
        side_effects.clone(),
    ));
    let personal_permission_service = Arc::new(
        PersonalPermissionService::new(rule_repository.clone(), side_effects.clone())
            .with_sod_db(db.clone()),
    );

    // 第六批：租户 repository + service 装配
    let tenant_repository = Arc::new(SqlxTenantRepository::new(db.clone()));
    let tenant_service = Arc::new(TenantService::new(tenant_repository.clone()));

    // 执剑人运行侧服务（阶段 B：冲突信号统计 + 跨节点证据仲裁）
    let arbiter_service = Arc::new(astral_trustgraph::service::arbiter::ArbiterService::new());
    let audit_replay_producer = AuditReplayProducerSlot::new();

    // 内部测试控制面（S1-S15 分布式授权实验）：默认关闭。仅当
    // ASTRAL_TEST_CONTROL_ENABLED=true 且 ASTRAL_TEST_CONTROL_TOKEN 非空时
    // 返回 Some；配置缺失/无效 fail-closed（路由不注册 → 404）。启用时仍走
    // Gateway 签名 + permission_check 正常链路，token 校验是其上的额外层，
    // 见 api::test_control 安全不变式。探针现状：Java 模式 wait_ready 仅发
    // X-Test-Control-Token，不能通过本链路；Rust 模式经 wait_ready_rust +
    // probe_worker_id.py 携带完整 Gateway v3 签名与 monitor:read 授权可达。
    // Rust 场景协调器仍未实现（就绪后 attempt 即 BLOCKED，不报 PASS）。
    let test_control = api::test_control::TestControlConfig::from_env();

    // 投影 worker 监督健康共享态（F5 修复 1d）：state 构造先于 projector
    // 启动，用 OnceLock 槽位在启动成功后补写；未启动则保持为空。
    let projector_health_slot: Arc<std::sync::OnceLock<Arc<ProjectorHealthShared>>> =
        Arc::new(std::sync::OnceLock::new());

    let state = AppState {
        config,
        db: db.clone(),
        engine,
        projector_health: projector_health_slot.clone(),
        // 第一批纯 CRUD 模块 Repository 装配（对齐 Java Infrastructure Mapper）
        domain_repository: Arc::new(SqlxDomainRepository::new(db.clone())),
        level_repository: Arc::new(SqlxLevelRepository::new(db.clone())),
        grading_repository: Arc::new(SqlxGradingRepository::new(db.clone())),
        card_template_repository: Arc::new(SqlxCardTemplateRepository::new(db.clone())),
        global_admin_repository: Arc::new(SqlxGlobalAdminRepository::new(db.clone())),
        cross_org_grant_repository: Arc::new(SqlxCrossOrgGrantRepository::new(db.clone())),
        rule_repository,
        rule_set_repository,
        delegation_repository,
        admin_group_repository,
        rule_write_service,
        rule_set_write_service,
        delegation_service,
        // 第四批：剩余纯 CRUD 模块 Repository 装配
        department_repository: Arc::new(SqlxDepartmentRepository::new(db.clone())),
        platform_package_repository: Arc::new(SqlxPlatformPackageRepository::new(db.clone())),
        inheritance_config_repository: Arc::new(SqlxInheritanceConfigRepository::new(db.clone())),
        permission_action_repository: Arc::new(SqlxPermissionActionRepository::new(db.clone())),
        resource_type_repository: Arc::new(SqlxResourceTypeRepository::new(db.clone())),
        audit_log_repository: Arc::new(SqlxAuditLogRepository::new(db.clone())),
        sod_repository: Arc::new(SqlxSodRepository::new(db.clone())),
        hit_stat_repository: Arc::new(SqlxHitStatRepository::new(db.clone())),
        permission_request_repository,
        template_repository,
        approval_service,
        template_service,
        level_template_repository,
        user_card_repository,
        level_template_service,
        user_card_service,
        personal_permission_service,
        tenant_repository,
        tenant_service,
        arbiter_service,
        audit_replay_producer: audit_replay_producer.clone(),
        test_control: test_control.clone(),
        org_scope_enabled,
        org_scope_tenant_allowlist,
    };

    // 执剑人哨兵挂接：TrustGraph 进程内的 evaluate() 冲突信号计入 arbiter 统计
    // （阶段 B；仲裁执行由控制面 POST /arbiter/arbitrate 触发，DEFER 必须 fail-closed）。
    state.arbiter_service.register_sink();

    // 启动期注册校验（对齐 Java @PostConstruct 校验）
    astral_common::middleware::permission_check_shared::validate_path_map(
        astral_trustgraph::api::permission_check::TRUSTGRAPH_PATH_RESOURCE_MAP,
        "trustgraph",
    );

    // 权限投影 durable worker（对齐 Java AuthorizationProjectionJob @Scheduled 5s 的
    // claim/lease 形态）。读链切换批次 3 起收敛为 ELIGIBILITY-only：CARD/RULE_SET
    // outbox 事件仅终态 mark_processed（快照重建职责已由下方新链 authorization_projector
    // delta 队列接管），ELIGIBILITY 资格缓存失效为本 worker 存续职责（决策见
    // Rust增量重建与实时授权边界_V1.0.md §3.4）。
    // 启动顺序第一位；关闭序列按严格逆序在最后（新投影 worker 之后）cancel→bounded join。
    let projection_worker: ProjectionWorkerHandle = {
        let projection_repo = Arc::new(SqlxProjectionRepository::new(db.clone()));
        spawn_worker(db.clone(), projection_repo)
    };

    // 新 Rust-owned 版本化授权投影 worker（authorization_delta_event 队列的唯一
    // 消费者；写 20260825000002/20260827000001 新表，不触碰旧 head/outbox 职责）。
    // tenant 范围由部署配置注入：空列表 = 保持空闲并告警（记录在案的 slice-1 缺口）；
    // 混入任何非法 token（空段/非数字/非正数/超范围）一律启动失败，绝不 filter_map
    // 静默丢弃导致"半配置"租户范围；重复 id 由解析器去重。
    let projector_tenants = {
        let raw_tenants = std::env::var("ASTRAL_PROJECTOR_TENANTS").unwrap_or_default();
        match parse_projector_tenants(&raw_tenants) {
            Ok(tenants) => tenants,
            Err(error) => {
                tracing::error!(
                    error = %error,
                    error_code = "PROJECTOR_TENANTS_INVALID",
                    "invalid ASTRAL_PROJECTOR_TENANTS configuration; refusing startup"
                );
                return Err(anyhow::anyhow!(error));
            }
        }
    };
    // 多租户重设计 Phase 1（设计稿 §3）：调度拓扑与并行 worker 数由部署显式
    // 配置；默认 tenant-serial（已验收行为）。非法值启动失败，绝不静默降级。
    let projector_scheduling_mode = {
        let raw = std::env::var("ASTRAL_PROJECTOR_SCHEDULING_MODE").unwrap_or_default();
        match parse_projector_scheduling_mode(&raw) {
            Ok(mode) => mode,
            Err(error) => {
                tracing::error!(
                    error = %error,
                    error_code = "PROJECTOR_SCHEDULING_MODE_INVALID",
                    "invalid ASTRAL_PROJECTOR_SCHEDULING_MODE configuration; refusing startup"
                );
                return Err(anyhow::anyhow!(error));
            }
        }
    };
    let projector_worker_count = {
        let raw = std::env::var("ASTRAL_PROJECTOR_WORKER_COUNT").unwrap_or_default();
        match parse_projector_worker_count(&raw) {
            Ok(count) => count,
            Err(error) => {
                tracing::error!(
                    error = %error,
                    error_code = "PROJECTOR_WORKER_COUNT_INVALID",
                    "invalid ASTRAL_PROJECTOR_WORKER_COUNT configuration; refusing startup"
                );
                return Err(anyhow::anyhow!(error));
            }
        }
    };
    if projector_scheduling_mode == ProjectorSchedulingMode::Partitioned {
        // Q2 启动守卫：worker 数必须落进共享连接池预算（每 worker 2 连接上限）。
        let pool_max_connections = db.options().get_max_connections();
        if let Err(error) =
            validate_partition_worker_budget(projector_worker_count, pool_max_connections)
        {
            tracing::error!(
                error = %error,
                error_code = "PROJECTOR_WORKER_BUDGET_INVALID",
                "partitioned projector configuration exceeds the shared pool budget; refusing startup"
            );
            return Err(anyhow::anyhow!(error));
        }
    }
    let authorization_projector: AuthorizationProjectorHandle = start_authorization_projector(
        db.clone(),
        AuthorizationProjectorConfig {
            tenants: projector_tenants.clone(),
            scheduling_mode: projector_scheduling_mode,
            worker_count: projector_worker_count,
            ..Default::default()
        },
    );
    // F5 修复 1d：监督健康共享态接入 stats 端点（启动成功后补写槽位）。
    let _ = projector_health_slot.set(authorization_projector.health.clone());

    // 归档 worker：与 projector 共享同一份 fail-fast 解析出的 tenant 列表
    // （archive intent 只可能来自这些 tenant 的 publication，绝不引入第二套配置）。
    // 空列表时保持空闲并告警；claim_lease_seconds 等配置非法时构造器在 spawn 前
    // 返回显式配置错误（无任务启动、无持久/外部副作用），进程拒绝启动。启动顺序：
    // 旧 projection worker → 新投影 worker → 归档 worker → 委托到期对账 worker
    // → ORG_SCOPE projector（仅 org_scope_enabled 旗标开启时）→ 审计回放 worker，
    // 关闭严格逆序 cancel→join（旧 projection worker 最早启动，因此在关闭序列
    // 最后 join）。
    let authorization_archive_worker: AuthorizationArchiveWorkerHandle =
        match start_authorization_archive_worker(
            db.clone(),
            astral_trustgraph::service::authorization_archive_worker::AuthorizationArchiveConfig {
                tenants: projector_tenants.clone(),
                ..Default::default()
            },
        ) {
            Ok(handle) => handle,
            Err(error) => {
                tracing::error!(
                    error = %error,
                    error_code = "AUTH_ARCHIVE_WORKER_CONFIG_INVALID",
                    "invalid authorization archive worker configuration; refusing startup"
                );
                // 归档 worker 从未启动：按启动逆序先 cancel→join 已启动的新投影
                // worker，再以显式配置错误拒绝进程启动。
                let projector_report = shutdown_authorization_projector(
                    authorization_projector,
                    std::time::Duration::from_secs(SHUTDOWN_JOIN_TIMEOUT_SECS),
                )
                .await;
                if let Err(failure) = &projector_report.summary {
                    tracing::error!(
                        reason = %failure,
                        "authorization projector did not stop cleanly after \
                         archive worker config rejection"
                    );
                }
                return Err(anyhow::anyhow!(error));
            }
        };

    // 委托到期对账 worker：唯一职责是周期性调用
    // DelegationWriteService::reconcile_expired_delegations（显式有界批次，
    // 单条候选 = 单个 source transaction；不复制 SQL、不新增 source mutation，
    // 事务内无网络/MQ/cache）。候选发现跨租户（permission_delegation 源表暂无
    // tenant_id 列，不改 schema/索引）；每条候选的收敛在各自事务内以锁定端点
    // 卡重新证明 tenant/domain 归属，缺失即 fail-closed。默认 60s 轮询 / 批次
    // 64（硬上限 500）；env 覆盖值非法时在 spawn 前启动失败。
    let delegation_expiry_worker: DelegationExpiryWorkerHandle = {
        let poll_raw = std::env::var("ASTRAL_DELEGATION_EXPIRY_POLL_SECS").ok();
        let batch_raw = std::env::var("ASTRAL_DELEGATION_EXPIRY_BATCH").ok();
        let started = parse_delegation_expiry_config(poll_raw.as_deref(), batch_raw.as_deref())
            .and_then(|config| {
                start_delegation_expiry_worker(state.delegation_service.clone(), config)
            });
        match started {
            Ok(handle) => handle,
            Err(error) => {
                tracing::error!(
                    error = %error,
                    error_code = "DELEGATION_EXPIRY_WORKER_CONFIG_INVALID",
                    "invalid delegation expiry worker configuration; refusing startup"
                );
                // 本 worker 从未启动：按启动逆序先 cancel→join 已启动的归档
                // worker 与新投影 worker，再以显式配置错误拒绝进程启动。
                let archive_report = shutdown_authorization_archive_worker(
                    authorization_archive_worker,
                    std::time::Duration::from_secs(SHUTDOWN_JOIN_TIMEOUT_SECS),
                )
                .await;
                if let Err(failure) = &archive_report.summary {
                    tracing::error!(
                        reason = %failure,
                        "authorization archive worker did not stop cleanly after \
                         delegation expiry worker config rejection"
                    );
                    return Err(anyhow::anyhow!(
                        "authorization archive worker shutdown failed after \
                         delegation expiry worker config rejection: {failure}"
                    ));
                }
                let projector_report = shutdown_authorization_projector(
                    authorization_projector,
                    std::time::Duration::from_secs(SHUTDOWN_JOIN_TIMEOUT_SECS),
                )
                .await;
                if let Err(failure) = &projector_report.summary {
                    tracing::error!(
                        reason = %failure,
                        "authorization projector did not stop cleanly after \
                         delegation expiry worker config rejection"
                    );
                    return Err(anyhow::anyhow!(
                        "authorization projector shutdown failed after \
                         delegation expiry worker config rejection: {failure}"
                    ));
                }
                return Err(anyhow::anyhow!(error));
            }
        }
    };

    // ORG_SCOPE outbox 投影 worker 启动点：配置已在启动最前端（旗标冻结之后、
    // 任何 DB 连接/worker 之前）fail-fast 解析并冻结为 org_scope_projector_config；
    // 此处仅当该配置存在（旗标开启）时以预校验配置启动唯一消费者，旗标关闭时
    // 不 spawn、不注册关闭责任（保持 None）。start 在 spawn 前还会再次 validate
    // （双重 fail-closed）。启动顺序：旧 projection worker → 新投影 worker →
    // 归档 worker → 委托到期对账 worker → ORG_SCOPE projector → 审计回放 worker；
    // 关闭严格逆序 cancel→bounded join。start 失败（仅剩 spawn 前身份校验）发生
    // 在任何 ORG 任务启动之前：按启动逆序回滚已启动 worker 后拒绝启动（见
    // rollback_started_workers_after_org_scope_failure）。
    let org_scope_projector: Option<OrgScopeProjectorHandle> = match org_scope_projector_config {
        Some(config) => {
            match start_org_scope_projector(
                Arc::new(SqlxOrgScopeRepository::new(db.clone())),
                config,
            ) {
                Ok(handle) => Some(handle),
                Err(error) => {
                    tracing::error!(
                        error = %error,
                        error_code = "ORG_SCOPE_PROJECTOR_START_INVALID",
                        "org scope projector failed to start; refusing startup"
                    );
                    if let Some(failure) = rollback_started_workers_after_org_scope_failure(
                        delegation_expiry_worker,
                        authorization_archive_worker,
                        authorization_projector,
                        projection_worker,
                    )
                    .await
                    {
                        return Err(anyhow::anyhow!(failure));
                    }
                    return Err(anyhow::anyhow!(error));
                }
            }
        }
        None => None,
    };

    // The worker is explicitly owned by main. It starts without a producer,
    // waits for MQ bootstrap to install one, and is joined on server shutdown.
    let audit_replay_worker: AuditReplayWorkerHandle =
        start_audit_replay_worker(db.clone(), audit_replay_producer.clone());
    let audit_replay_shutdown = audit_replay_worker.cancellation.clone();

    // 注入 audit.log consumer 的 DB pool。
    astral_mq::consumers::set_audit_log_db(db.clone());

    // MQ 消费者后台启动（非阻塞）。
    // RabbitMQ 暂不可用时按指数退避重试，避免服务启动即永久失去
    // audit.log 消费者（对齐 Java spring-amqp 自动重连）。
    let dlq_quarantine_db = db.clone();
    tokio::spawn(async move {
        let mut attempt: u32 = 0;
        loop {
            // Drop the non-Send transport error before the retry await. The error
            // may contain a credential-bearing endpoint, so it is never formatted.
            let started = init_mq_consumers(
                &rabbitmq_url,
                &dlq_quarantine_db,
                audit_replay_producer.clone(),
            )
            .await
            .ok();
            if let Some(started) = started {
                tracing::info!("MQ consumers started: {:?}", started);
                break;
            }
            attempt = attempt.saturating_add(1);
            let backoff_secs = 2u64.pow(attempt.min(5));
            tracing::warn!(
                attempt,
                backoff_secs,
                "MQ consumers startup failed, retrying with backoff"
            );
            tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
        }
    });

    // 将 /main/api/v1 下的所有路由合并到一个子路由，
    // 并在其上应用权限检查中间件（对齐 Java PermissionAspect.enforce()）
    let api_routes = Router::new()
        .merge(api::rules::rule_routes())
        .merge(api::rule_sets::rule_set_routes())
        .merge(api::audit::audit_routes())
        .merge(api::audit_replay::audit_replay_routes())
        .merge(api::simulation::simulation_routes())
        .merge(api::approval::approval_routes())
        .merge(api::templates::template_routes())
        .merge(api::delegation::delegation_routes())
        .merge(api::stats::stats_routes())
        .merge(api::sod::sod_routes())
        .merge(api::tenants::tenant_routes())
        .merge(api::platform_packages::platform_package_routes())
        .merge(api::departments::department_routes())
        .merge(api::personal_permissions::personal_permission_routes())
        .merge(api::consistency_monitor::consistency_monitor_routes())
        .merge(api::arbiter::arbiter_routes())
        .merge(api::inheritance::inheritance_routes())
        .merge(api::cross_org_grants::cross_org_grant_routes())
        // DomainControl 拆分后的 7 个独立模块
        .merge(api::domains::domain_routes())
        .merge(api::resource_types::resource_type_routes())
        .merge(api::permission_actions::permission_action_routes())
        .merge(api::user_levels::user_level_routes())
        .merge(api::user_gradings::user_grading_routes())
        .merge(api::level_templates::level_template_routes())
        .merge(api::user_cards::user_card_routes())
        .merge(api::card_templates::card_template_routes())
        .merge(api::global_admin::global_admin_routes())
        // 内部测试控制面（默认不注册任何路由；启用后仅只读 worker-id 探针）
        .merge(api::test_control::test_control_routes(
            test_control.as_ref(),
        ));
    let api_routes = if org_scope_enabled {
        api_routes
            .merge(api::org_authorities::org_authority_edge_routes())
            .merge(api::org_authorities::org_unit_card_routes())
            .merge(api::org_authorities::org_membership_routes())
            .merge(api::org_authorities::org_scope_request_routes())
    } else {
        api_routes
    }
    .layer(axum::middleware::from_fn_with_state(
        state.clone(),
        api::permission_check::permission_check_middleware,
    ));

    let app = Router::new()
        .nest("/main/api/v1", api_routes)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            gateway_signature_middleware,
        ))
        .layer(axum::middleware::from_fn(global_exception_handler))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state);

    let addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:9005".into());
    tracing::info!(addr = %addr, "trustgraph service starting");

    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(listener) => listener,
        Err(error) => {
            // bind 失败关闭：与启动严格逆序 cancel→join（审计回放 → ORG_SCOPE
            // projector（仅旗标开启时）→ 委托到期对账 → 归档 → 新投影 → 旧投影
            // worker）；任一 worker 未干净停止都会转为进程错误。
            audit_replay_shutdown.cancel();
            let _ = audit_replay_worker.join.await;
            // ORG_SCOPE projector：启动顺序在委托到期对账 worker 之后、审计回放
            // 之前，按关闭严格逆序在审计回放之后、委托到期对账之前 cancel→
            // bounded join；旗标关闭时从未启动，None 直接跳过。join 超时/panic/
            // Err 转为进程错误，绝不静默吞掉断流状态。
            if let Some(handle) = org_scope_projector {
                let org_scope_shutdown_timeout = org_scope_projector_shutdown_timeout(&handle);
                let org_scope_report =
                    shutdown_org_scope_projector(handle, org_scope_shutdown_timeout).await;
                if let Err(failure) = org_scope_report.summary {
                    tracing::error!(
                        reason = %failure,
                        "org scope projector did not stop cleanly during bind-failure shutdown"
                    );
                    return Err(anyhow::anyhow!(
                        "org scope projector shutdown failed after bind error: {failure}"
                    ));
                }
            }
            let delegation_expiry_report = shutdown_delegation_expiry_worker(
                delegation_expiry_worker,
                std::time::Duration::from_secs(SHUTDOWN_JOIN_TIMEOUT_SECS),
            )
            .await;
            if let Err(failure) = &delegation_expiry_report.summary {
                tracing::error!(
                    reason = %failure,
                    "delegation expiry worker did not stop cleanly during bind-failure shutdown"
                );
                return Err(anyhow::anyhow!(
                    "delegation expiry worker shutdown failed after bind error: {failure}"
                ));
            }
            let archive_report = shutdown_authorization_archive_worker(
                authorization_archive_worker,
                std::time::Duration::from_secs(SHUTDOWN_JOIN_TIMEOUT_SECS),
            )
            .await;
            if let Err(join_failure) = &archive_report.summary {
                tracing::error!(
                    reason = %join_failure,
                    "authorization archive worker did not stop cleanly during bind-failure shutdown"
                );
                return Err(anyhow::anyhow!(
                    "authorization archive worker shutdown failed after bind error: {join_failure}"
                ));
            }
            let projector_report = shutdown_authorization_projector(
                authorization_projector,
                std::time::Duration::from_secs(SHUTDOWN_JOIN_TIMEOUT_SECS),
            )
            .await;
            if let Err(join_failure) = projector_report.summary {
                tracing::error!(
                    reason = %join_failure,
                    "authorization projector did not stop cleanly during bind-failure shutdown"
                );
                return Err(anyhow::anyhow!(
                    "authorization projector shutdown failed after bind error: {join_failure}"
                ));
            }
            // 旧 projection worker：启动顺序第一位，按关闭严格逆序在最后
            // cancel→bounded join；join 超时/panic 与其他 worker 一样转为进程错误。
            let projection_worker_report = shutdown_projection_worker(
                projection_worker,
                std::time::Duration::from_secs(SHUTDOWN_JOIN_TIMEOUT_SECS),
            )
            .await;
            if let Err(join_failure) = projection_worker_report.summary {
                tracing::error!(
                    reason = %join_failure,
                    "legacy projection worker did not stop cleanly during bind-failure shutdown"
                );
                return Err(anyhow::anyhow!(
                    "legacy projection worker shutdown failed after bind error: {join_failure}"
                ));
            }
            return Err(error.into());
        }
    };
    let server_result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await;
    // 正常关闭：启动逆序逐个 cancel→bounded join（审计回放 → ORG_SCOPE
    // projector（仅旗标开启时）→ 委托到期对账 → 归档 → 新投影 → 旧投影 worker）。
    // join 超时/panic/Err 都会让进程退出码显式失败，绝不静默吞掉断流状态；
    // 归档 worker 的运行统计在关闭时打印，供对账观测。
    audit_replay_shutdown.cancel();
    let worker_result = audit_replay_worker.join.await;
    // ORG_SCOPE projector：启动顺序在委托到期对账 worker 之后、审计回放之前，
    // 按关闭严格逆序在审计回放之后、委托到期对账之前 cancel→bounded join；
    // 旗标关闭时从未启动，None 直接跳过（run 统计由 worker 自身关闭时打印，
    // 供对账观测）。
    let org_scope_report = match org_scope_projector {
        Some(handle) => {
            let org_scope_shutdown_timeout = org_scope_projector_shutdown_timeout(&handle);
            Some(shutdown_org_scope_projector(handle, org_scope_shutdown_timeout).await)
        }
        None => None,
    };
    // 委托到期对账 worker：启动逆序第三位（ORG_SCOPE projector 之后、归档之前）。
    let delegation_expiry_report = shutdown_delegation_expiry_worker(
        delegation_expiry_worker,
        std::time::Duration::from_secs(SHUTDOWN_JOIN_TIMEOUT_SECS),
    )
    .await;
    let archive_report = shutdown_authorization_archive_worker(
        authorization_archive_worker,
        std::time::Duration::from_secs(SHUTDOWN_JOIN_TIMEOUT_SECS),
    )
    .await;
    if let Ok(archive_summary) = &archive_report.summary {
        tracing::info!(
            claimed = archive_summary.intents_claimed,
            archived = archive_summary.intents_archived,
            resumed = archive_summary.intents_resumed,
            retried = archive_summary.intents_retried,
            quarantined = archive_summary.intents_quarantined,
            unknown = archive_summary.intents_unknown,
            budget_exhausted = archive_summary.intents_budget_exhausted,
            no_work_cycles = archive_summary.no_work_cycles,
            "authorization archive worker final run summary"
        );
    }
    let projector_report = shutdown_authorization_projector(
        authorization_projector,
        std::time::Duration::from_secs(SHUTDOWN_JOIN_TIMEOUT_SECS),
    )
    .await;
    if let Err(projector_failure) = &projector_report.summary {
        tracing::error!(reason = %projector_failure, "authorization projector failed to stop cleanly");
    }
    // 旧 projection worker：启动顺序第一位（审计回放之前），按关闭严格逆序在
    // 最后 cancel→bounded join；join 超时/panic 与其他 worker 一样转为进程错误。
    let projection_worker_report = shutdown_projection_worker(
        projection_worker,
        std::time::Duration::from_secs(SHUTDOWN_JOIN_TIMEOUT_SECS),
    )
    .await;
    if let Err(error) = worker_result {
        return Err(anyhow::anyhow!("audit replay worker join failed: {error}"));
    }
    if let Some(report) = org_scope_report {
        if let Err(failure) = report.summary {
            return Err(anyhow::anyhow!(
                "org scope projector shutdown failed: {failure}"
            ));
        }
    }
    if let Err(delegation_expiry_failure) = delegation_expiry_report.summary {
        return Err(anyhow::anyhow!(
            "delegation expiry worker shutdown failed: {delegation_expiry_failure}"
        ));
    }
    if let Err(archive_failure) = archive_report.summary {
        return Err(anyhow::anyhow!(
            "authorization archive worker shutdown failed: {archive_failure}"
        ));
    }
    projector_report
        .summary
        .map_err(|failure| anyhow::anyhow!("authorization projector shutdown failed: {failure}"))?;
    if let Err(projection_worker_failure) = projection_worker_report.summary {
        return Err(anyhow::anyhow!(
            "legacy projection worker shutdown failed: {projection_worker_failure}"
        ));
    }
    server_result?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::warn!(%error, "failed to install Ctrl-C handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => tracing::warn!(%error, "failed to install terminate handler"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

/// ORG_SCOPE projector 启动点失败后的已启动 worker 回滚：按启动严格逆序
/// cancel→bounded join（委托到期对账 → 归档 → 新投影 → 旧 projection worker，
/// 均为 ORG_SCOPE projector 启动点之前的任务）。任一 worker 未干净停止
/// （join 超时/panic/Err）都作为首要失败返回并转为进程错误，绝不静默吞掉；
/// 全部干净停止返回 None。与 main 既有失败分支共用同一 SHUTDOWN_JOIN_TIMEOUT_SECS
/// 有界超时。
async fn rollback_started_workers_after_org_scope_failure(
    delegation_expiry_worker: DelegationExpiryWorkerHandle,
    authorization_archive_worker: AuthorizationArchiveWorkerHandle,
    authorization_projector: AuthorizationProjectorHandle,
    projection_worker: ProjectionWorkerHandle,
) -> Option<String> {
    let delegation_expiry_report = shutdown_delegation_expiry_worker(
        delegation_expiry_worker,
        std::time::Duration::from_secs(SHUTDOWN_JOIN_TIMEOUT_SECS),
    )
    .await;
    if let Err(failure) = delegation_expiry_report.summary {
        tracing::error!(
            reason = %failure,
            "delegation expiry worker did not stop cleanly after \
             org scope projector startup failure"
        );
        return Some(format!(
            "delegation expiry worker shutdown failed after org scope projector \
             startup failure: {failure}"
        ));
    }
    let archive_report = shutdown_authorization_archive_worker(
        authorization_archive_worker,
        std::time::Duration::from_secs(SHUTDOWN_JOIN_TIMEOUT_SECS),
    )
    .await;
    if let Err(failure) = archive_report.summary {
        tracing::error!(
            reason = %failure,
            "authorization archive worker did not stop cleanly after \
             org scope projector startup failure"
        );
        return Some(format!(
            "authorization archive worker shutdown failed after org scope \
             projector startup failure: {failure}"
        ));
    }
    let projector_report = shutdown_authorization_projector(
        authorization_projector,
        std::time::Duration::from_secs(SHUTDOWN_JOIN_TIMEOUT_SECS),
    )
    .await;
    if let Err(failure) = projector_report.summary {
        tracing::error!(
            reason = %failure,
            "authorization projector did not stop cleanly after \
             org scope projector startup failure"
        );
        return Some(format!(
            "authorization projector shutdown failed after org scope projector \
             startup failure: {failure}"
        ));
    }
    let projection_worker_report = shutdown_projection_worker(
        projection_worker,
        std::time::Duration::from_secs(SHUTDOWN_JOIN_TIMEOUT_SECS),
    )
    .await;
    if let Err(failure) = projection_worker_report.summary {
        tracing::error!(
            reason = %failure,
            "legacy projection worker did not stop cleanly after \
             org scope projector startup failure"
        );
        return Some(format!(
            "legacy projection worker shutdown failed after org scope projector \
             startup failure: {failure}"
        ));
    }
    None
}

/// 初始化 MQ 消费者（连接到 RabbitMQ、声明队列、启动消费者）
async fn init_mq_consumers(
    rabbitmq_url: &str,
    quarantine_db: &sqlx::MySqlPool,
    audit_replay_producer: AuditReplayProducerSlot,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    // 1. 连接 RabbitMQ
    let conn = Connection::connect(
        rabbitmq_url,
        lapin::ConnectionProperties::default().enable_auto_recover(),
    )
    .await?;
    let channel = conn.create_channel().await?;
    astral_mq::producer::Producer::enable_confirms(&channel).await?;
    tracing::info!("Connected to RabbitMQ");

    // 2. 声明所有交换机、队列和 DLX 绑定
    astral_mq::config::declare_all(&channel).await?;
    tracing::info!("All MQ queues declared");

    // 2.5 初始化全局 MQ producer。审计通过 common 适配器发送，CARD 权限刷新仅由
    // durable projection worker 携带 source_generation/revoke_fence 发布。
    astral_trustgraph::api::side_effects::init_mq_producer(channel.clone());
    // Publisher confirms are enabled on this exact channel above; only publish
    // this producer after all declarations/consumers below complete successfully.
    // The slot is a cloneable lock hand-off, so no OnceLock or borrowed channel
    // escapes this bootstrap task.
    let audit_replay_producer_instance = astral_mq::producer::Producer::new(channel.clone());
    register_mq_producer(Arc::new(TrustGraphMqProducer {
        inner: astral_mq::producer::Producer::new(channel.clone()),
    }));

    // 启动 TrustGraph 独占的 audit.log 消费者。
    // DLQ 消费者先于业务消费者启动，保证死信消息可被重投/告警闭环。
    astral_mq::consumers::start_dlq_consumers(
        &channel,
        astral_mq::consumers::DlqOwner::TrustGraph,
        Some(quarantine_db.clone()),
    )
    .await?;
    let started = Vec::new();
    astral_mq::consumers::start_audit_log_consumer(&channel).await?;
    if !audit_replay_producer
        .set(audit_replay_producer_instance)
        .await
    {
        return Err("audit replay producer slot was already initialized".into());
    }
    tracing::info!("MQ consumers started: {:?}", started);

    // 保持连接存活（后台等待）
    let _ = channel;
    let _ = conn;
    // Keep the connection and channel alive for the consumers and replay slot.
    // The bootstrap task owns these values until it is cancelled with the process.
    tokio::spawn(async move {
        let _connection = conn;
        let _channel = channel;
        std::future::pending::<()>().await;
    });

    Ok(started)
}

/// 初始化超管模板（幂等，对齐 Java SuperAdminTemplateInitializer）
///
/// 对齐 platform_v4：`user_card_template` 真实列名 `template_id`/`template_code`/`template_name`，
/// 无 `description` 列，`domain_id` NOT NULL 必须提供。
async fn init_superadmin_template(
    db: &sqlx::MySqlPool,
    reg: &astral_types::ResourceRegistry,
) -> anyhow::Result<()> {
    let required_columns = [
        "template_id",
        "template_code",
        "template_name",
        "card_type",
        "domain_id",
        "tenant_id",
        "status",
    ];
    for column in required_columns {
        let exists: Option<(String,)> = sqlx::query_as(
            "SELECT COLUMN_NAME FROM information_schema.COLUMNS \
             WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'user_card_template' AND COLUMN_NAME = ?",
        )
        .bind(column)
        .fetch_optional(db)
        .await?;
        if exists.is_none() {
            return Err(anyhow::anyhow!(
                "SUPERADMIN_INIT_FAILED: user_card_template.{column} is not present in the validated schema"
            ));
        }
    }

    let existing: Option<(i64, Option<i64>, Option<i64>)> = sqlx::query_as(
        "SELECT template_id, domain_id, tenant_id FROM user_card_template \
         WHERE template_code = '__SUPERADMIN__' LIMIT 1",
    )
    .fetch_optional(db)
    .await?;

    let template_id = match existing {
        Some((id, Some(domain_id), Some(tenant_id))) => {
            tracing::info!(id, domain_id, tenant_id, "superadmin template exists");
            id
        }
        Some((_, None, _)) => {
            return Err(anyhow::anyhow!(
                "SUPERADMIN_INIT_FAILED: existing __SUPERADMIN__ template has NULL domain_id"
            ));
        }
        Some((_, _, None)) => {
            return Err(anyhow::anyhow!(
                "SUPERADMIN_INIT_FAILED: existing __SUPERADMIN__ template has NULL tenant_id"
            ));
        }
        None => {
            let domain_id: Option<(i64,)> = sqlx::query_as(
                "SELECT domain_id FROM platform_domain WHERE status = 'ACTIVE' ORDER BY domain_id LIMIT 1",
            )
            .fetch_optional(db)
            .await?;
            let Some((domain_id,)) = domain_id else {
                return Err(anyhow::anyhow!(
                    "SUPERADMIN_INIT_FAILED: no ACTIVE platform domain is available"
                ));
            };
            let tenant_id: Option<(i64,)> = sqlx::query_as(
                "SELECT t.tenant_id FROM tenant t \
                 INNER JOIN tenant_domain_map m ON m.tenant_id = t.tenant_id \
                 WHERE m.domain_id = ? AND t.status = 'ACTIVE' AND m.status = 'ACTIVE' \
                 ORDER BY t.tenant_id LIMIT 1",
            )
            .bind(domain_id)
            .fetch_optional(db)
            .await?;
            let Some((tenant_id,)) = tenant_id else {
                return Err(anyhow::anyhow!(
                    "SUPERADMIN_INIT_FAILED: no ACTIVE tenant is mapped to an ACTIVE domain"
                ));
            };
            let result = sqlx::query(
                "INSERT INTO user_card_template (template_name, template_code, card_type, domain_id, tenant_id, status) \
                 VALUES ('超级管理员', '__SUPERADMIN__', 'SUPER_ADMIN', ?, ?, 'ACTIVE')",
            )
            .bind(domain_id)
            .bind(tenant_id)
            .execute(db)
            .await?;
            let id = result.last_insert_id() as i64;
            tracing::info!(id, domain_id, tenant_id, "superadmin template created");
            id
        }
    };

    // Keep the complete template-rule synchronization atomic. Any failed query drops the
    // transaction (rolling back prior inserts), so RuleSet materialization below can only run
    // after every idempotence check and insert has succeeded and the commit is durable.
    let mut tx = db.begin().await?;
    for resource in reg.list_resources() {
        let actions = reg.list_actions(&resource).unwrap_or_default();
        if actions.is_empty() {
            continue;
        }
        for action in &actions {
            // write 别名去重（对齐 Java upsertTemplateRules 别名语义）：
            // 已存在 write 则跳过 create/update/delete（避免冗余 ALLOW 行）
            let is_alias_child = matches!(action.as_str(), "create" | "update" | "delete");
            if is_alias_child {
                let has_write: (i64,) = sqlx::query_as(
                    "SELECT COUNT(*) FROM permission_rule_template \
                     WHERE template_id=? AND resource_type=? AND action_code='write' AND effect='ALLOW'",
                )
                .bind(template_id)
                .bind(&resource)
                .fetch_one(&mut *tx)
                .await?;
                if has_write.0 > 0 {
                    continue;
                }
            }
            // per-action 幂等检查（对齐 Java upsertTemplateRules 的 existingKeys 去重逻辑）
            let has: (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM permission_rule_template \
                 WHERE template_id=? AND resource_type=? AND action_code=? AND effect='ALLOW'",
            )
            .bind(template_id)
            .bind(&resource)
            .bind(action)
            .fetch_one(&mut *tx)
            .await?;
            if has.0 > 0 {
                continue;
            }
            sqlx::query(
                "INSERT INTO permission_rule_template (template_id, resource_type, action_code, effect, priority) \
                 VALUES (?,?,?,'ALLOW',0)"
            ).bind(template_id).bind(&resource).bind(action).execute(&mut *tx).await?;
        }
        tracing::debug!(resource = %resource, count = actions.len(), "synced");
    }
    tx.commit().await?;
    tracing::info!("superadmin template sync done");

    // 第二阶段（对齐 Java ApplicationReadyEvent 完整初始化）：模板 → 投影
    // __SUPERADMIN__ BASE 规则集（createRuleSetFromTemplate 幂等：code 已存在即返回）。
    // 特权经 L1 RuleSet 评估（对齐 Java §2.4），新资源类型重启后自动补齐到规则集快照。
    let rule_set_repo =
        astral_trustgraph::repository::rule_set_repository::SqlxRuleSetRepository::new(db.clone());
    let system_context =
        astral_trustgraph::repository::audit_log_repository::RuleSetMutationContext::system(
            "startup:superadmin-template",
        )?;
    match rule_set_repo
        .create_rule_set_from_template(template_id, "__SUPERADMIN__", &system_context)
        .await
    {
        Ok(rule_set_id) => {
            tracing::info!(rule_set_id, "superadmin BASE rule set ready");
        }
        Err(e) => {
            return Err(anyhow::anyhow!(
                "SUPERADMIN_INIT_FAILED: superadmin rule set projection failed: {e}"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    fn production_source() -> &'static str {
        include_str!("main.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source must precede tests")
    }

    #[test]
    fn all_main_api_routes_are_inside_both_security_layers() {
        let source = production_source();
        let routes_start = source
            .find("let api_routes = Router::new()")
            .expect("main API router must remain explicit");
        let nest = source[routes_start..]
            .find(".nest(\"/main/api/v1\", api_routes)")
            .map(|offset| routes_start + offset)
            .expect("main API router must stay under its canonical prefix");
        let permission_layer = source[routes_start..nest]
            .find("api::permission_check::permission_check_middleware")
            .expect("all merged API routes must cross permission middleware");
        let gateway_layer = source[nest..]
            .find("gateway_signature_middleware")
            .expect("the nested main API router must cross gateway verification");
        assert!(permission_layer > 0);
        assert!(gateway_layer > 0);

        let merge_block = &source[routes_start..nest];
        let expected_merges = [
            "rules::rule_routes",
            "rule_sets::rule_set_routes",
            "audit::audit_routes",
            "audit_replay::audit_replay_routes",
            "simulation::simulation_routes",
            "approval::approval_routes",
            "templates::template_routes",
            "delegation::delegation_routes",
            "stats::stats_routes",
            "sod::sod_routes",
            "tenants::tenant_routes",
            "platform_packages::platform_package_routes",
            "departments::department_routes",
            "personal_permissions::personal_permission_routes",
            "consistency_monitor::consistency_monitor_routes",
            "arbiter::arbiter_routes",
            "inheritance::inheritance_routes",
            "cross_org_grants::cross_org_grant_routes",
            "domains::domain_routes",
            "resource_types::resource_type_routes",
            "permission_actions::permission_action_routes",
            "user_levels::user_level_routes",
            "user_gradings::user_grading_routes",
            "level_templates::level_template_routes",
            "user_cards::user_card_routes",
            "card_templates::card_template_routes",
            "global_admin::global_admin_routes",
            "test_control::test_control_routes",
            "org_authorities::org_authority_edge_routes",
            "org_authorities::org_unit_card_routes",
            "org_authorities::org_membership_routes",
            "org_authorities::org_scope_request_routes",
        ];
        assert_eq!(
            merge_block.matches(".merge(api::").count(),
            expected_merges.len()
        );
        for route_factory in expected_merges {
            assert!(
                merge_block.contains(&format!(".merge(api::{route_factory}")),
                "route factory escaped the protected main API router: {route_factory}"
            );
        }
    }

    #[test]
    fn superadmin_rule_sync_is_atomic_and_commits_before_materialization() {
        let source = production_source();
        let sync_start = source
            .find("let mut tx = db.begin().await?;")
            .expect("superadmin rule sync must begin a transaction");
        let commit = source[sync_start..]
            .find("tx.commit().await?;")
            .map(|offset| sync_start + offset)
            .expect("superadmin rule sync must commit");
        let materialization = source
            .find(".create_rule_set_from_template(")
            .expect("superadmin RuleSet materialization must remain");
        assert!(sync_start < commit);
        assert!(commit < materialization);

        let sync_source = &source[sync_start..commit];
        assert!(sync_source.contains(".fetch_one(&mut *tx)"));
        assert!(sync_source.contains(".execute(&mut *tx)"));
        assert!(!sync_source.contains(".fetch_one(db)"));
        assert!(!sync_source
            .contains(".fetch_one(&mut *tx)\n                .await\n                .unwrap_or"));
        assert!(!sync_source.contains(".execute(db)"));
        assert!(!sync_source.contains("let _ = sqlx::query"));
    }

    #[test]
    fn superadmin_rule_sync_preserves_alias_and_startup_context_contracts() {
        let source = production_source();
        assert!(source.contains("matches!(action.as_str(), \"create\" | \"update\" | \"delete\")"));
        assert!(source.contains("action_code='write' AND effect='ALLOW'"));
        assert!(source.contains("RuleSetMutationContext::system("));
        assert!(source.contains("\"startup:superadmin-template\""));
        assert!(
            source.contains("SUPERADMIN_INIT_FAILED: superadmin rule set projection failed: {e}")
        );
    }

    #[test]
    fn mq_bootstrap_tracing_never_formats_credential_sources() {
        let source = production_source();
        let mq_start = source
            .find("// MQ 消费者后台启动（非阻塞）。")
            .expect("MQ bootstrap block must remain");
        let mq_end = source[mq_start..]
            .find("// 将 /main/api/v1 下的所有路由合并到一个子路由")
            .map(|offset| mq_start + offset)
            .expect("MQ bootstrap block must have a stable end marker");
        let init_start = source
            .find("async fn init_mq_consumers(")
            .expect("MQ initializer must remain");
        let init_end = source[init_start..]
            .find("async fn init_superadmin_template(")
            .map(|offset| init_start + offset)
            .expect("MQ initializer must have a stable end marker");
        let blocks = [&source[mq_start..mq_end], &source[init_start..init_end]];

        let tracing_calls = blocks
            .iter()
            .flat_map(|block| {
                let mut calls = Vec::new();
                let mut offset = 0;
                while let Some(relative_start) = block[offset..].find("tracing::") {
                    let start = offset + relative_start;
                    let relative_end = block[start..]
                        .find(';')
                        .expect("tracing invocation must end with a semicolon");
                    let end = start + relative_end + 1;
                    calls.push(&block[start..end]);
                    offset = end;
                }
                calls
            })
            .collect::<Vec<_>>();

        assert_eq!(tracing_calls.len(), 5, "review every MQ tracing call");
        for call in tracing_calls {
            for forbidden in [
                "rabbitmq_url",
                "mq_url",
                "error =",
                "%error",
                "?error",
                "%e",
                "?e",
                ".to_string()",
            ] {
                assert!(
                    !call.contains(forbidden),
                    "MQ tracing must not format credential sources: {call}"
                );
            }
        }
        assert!(source.contains("tracing::info!(\"Connected to RabbitMQ\")"));
        assert!(!source.contains("Connected to RabbitMQ at"));
        assert!(blocks[0].contains(".await\n            .ok();"));
    }

    #[test]
    fn org_scope_config_gate_and_schema_guard_precede_any_worker_spawn() {
        let source = production_source();
        // 唯一配置门禁：冻结的共享 org_scope_enabled 旗标。env 快照必须在门内
        // 读取，且配置解析必须发生在 DB 连接与任何 worker spawn 之前（非法配置
        // 在零 worker 状态下拒绝启动，无需回滚）。
        let config_gate = source
            .find("let org_scope_projector_config = if org_scope_enabled {")
            .expect("org scope projector config must be gated by the frozen shared flag");
        let db_connect = source
            .find("let db = connect_and_validate_schema_with_pool_options(")
            .expect("DB connect must remain on the startup path");
        let first_worker = source
            .find("let projection_worker: ProjectionWorkerHandle")
            .expect("legacy projection worker startup must remain");
        assert!(config_gate < db_connect && db_connect < first_worker);
        let flag_off = source[config_gate..]
            .find("} else {\n        None\n    };")
            .map(|offset| config_gate + offset)
            .expect("flag-off path must keep ORG config state absent");
        let config_gate_block = &source[config_gate..flag_off];
        assert!(config_gate_block.contains("std::env::var(ENV_TENANTS)"));
        assert!(config_gate_block.contains("parse_org_scope_projector_config(&env_raw)"));
        assert!(
            !source[..config_gate].contains("std::env::var(ENV_"),
            "ORG_SCOPE env snapshot must not be read before the flag gate"
        );
        // enabled 模式 schema 门：DB 连接之后、任何 worker spawn 之前执行；
        // 先验证完整 ORG source/index 合同，再按首个 allowlist tenant 探测管理态。
        let schema_prerequisites = source
            .find("validate_org_scope_schema_prerequisites(&db)")
            .expect("enabled-mode schema prerequisites must remain");
        let schema_guard = source
            .find("probe_org_scope_gate(&db, first_tenant)")
            .expect("enabled-mode schema gate probe must remain");
        assert!(db_connect < schema_prerequisites);
        assert!(schema_prerequisites < schema_guard && schema_guard < first_worker);
        assert!(
            source.contains("ORG_SCOPE_SCHEMA_PREREQUISITES_REJECTED"),
            "incomplete ORG source/index contracts must reject enabled startup"
        );
        assert!(
            source.contains("OrgScopeGateState::SchemaUnmanaged | OrgScopeGateState::Pending => {"),
            "SchemaUnmanaged/Pending must be rejected by the schema gate"
        );
        assert!(
            source.contains(
                "OrgScopeGateState::TenantUnmanaged | OrgScopeGateState::TenantManaged { .. } => {"
            ),
            "TenantUnmanaged/TenantManaged must be admitted by the schema gate"
        );
        // Schema presence alone cannot prove that all managed outbox work has an
        // owner. Before any worker starts, read every node (including inactive
        // nodes), reject an unavailable coverage read, and reject an incomplete
        // frozen allowlist. The same frozen list must be copied into AppState.
        let coverage_gate = source
            .find("let managed_tenants = list_org_scope_managed_tenant_ids(&db)")
            .expect("enabled-mode startup must enumerate every managed tenant");
        let frozen_allowlist = source
            .find("let org_scope_tenant_allowlist = org_scope_projector_config")
            .expect("startup must derive one frozen allowlist for AppState");
        assert!(schema_guard < coverage_gate && coverage_gate < frozen_allowlist);
        assert!(frozen_allowlist < first_worker);
        let coverage_block = &source[coverage_gate..frozen_allowlist];
        assert!(coverage_block.contains("missing_org_scope_tenant_allowlist_entries("));
        assert!(coverage_block.contains("ORG_SCOPE_ALLOWLIST_COVERAGE_UNAVAILABLE"));
        assert!(coverage_block.contains("ORG_SCOPE_ALLOWLIST_INCOMPLETE"));
        assert!(source.contains("org_scope_tenant_allowlist,"));
        // 唯一启动点：消费预校验配置 + 生产 repository 装配，恰好启动一次；
        // 旗标关闭路径保持 None，不产生任何 ORG 状态。
        assert_eq!(
            source.matches("start_org_scope_projector(").count(),
            1,
            "org scope projector must be started exactly once"
        );
        let start_gate = source
            .find("let org_scope_projector: Option<OrgScopeProjectorHandle> = match org_scope_projector_config {")
            .expect("org scope projector start must consume the prevalidated config");
        let start_block_end = source[start_gate..]
            .find("// The worker is explicitly owned by main.")
            .map(|offset| start_gate + offset)
            .expect("audit replay startup comment must follow the org start block");
        let start_block = &source[start_gate..start_block_end];
        assert!(start_block.contains("start_org_scope_projector("));
        assert!(start_block.contains("SqlxOrgScopeRepository::new(db.clone())"));
        assert!(start_block.contains("None => None,"));
    }

    #[test]
    fn org_scope_projector_lifecycle_follows_strict_reverse_startup_order() {
        let source = production_source();
        // 启动顺序：委托到期对账 → ORG_SCOPE projector → 审计回放。
        let delegation_expiry_start = source
            .find("let delegation_expiry_worker: DelegationExpiryWorkerHandle")
            .expect("delegation expiry worker startup must remain");
        let org_start = source
            .find("let org_scope_projector: Option<OrgScopeProjectorHandle>")
            .expect("org scope projector startup must remain");
        let audit_replay_start = source
            .find("let audit_replay_worker: AuditReplayWorkerHandle")
            .expect("audit replay worker startup must remain");
        assert!(delegation_expiry_start < org_start && org_start < audit_replay_start);

        // 正常关闭顺序（严格逆序）：审计回放 → ORG_SCOPE projector → 委托到期
        // 对账 → 归档 → 新投影 → 旧 projection worker，且 ORG 关闭失败必须转为
        // 进程错误。
        let normal_shutdown = source
            .find("let worker_result = audit_replay_worker.join.await;")
            .expect("normal shutdown sequence must remain");
        let org_shutdown = source[normal_shutdown..]
            .find("shutdown_org_scope_projector(")
            .map(|offset| normal_shutdown + offset)
            .expect("org scope projector shutdown must follow audit replay join");
        let delegation_expiry_shutdown = source[org_shutdown..]
            .find("shutdown_delegation_expiry_worker(")
            .map(|offset| org_shutdown + offset)
            .expect("delegation expiry shutdown must follow org scope projector shutdown");
        let archive_shutdown = source[delegation_expiry_shutdown..]
            .find("shutdown_authorization_archive_worker(")
            .map(|offset| delegation_expiry_shutdown + offset)
            .expect("archive shutdown must follow delegation expiry shutdown");
        let projector_shutdown = source[archive_shutdown..]
            .find("shutdown_authorization_projector(")
            .map(|offset| archive_shutdown + offset)
            .expect("authorization projector shutdown must follow archive shutdown");
        assert!(source[projector_shutdown..].contains("shutdown_projection_worker("));
        assert!(
            source[normal_shutdown..].contains("org scope projector shutdown failed: {failure}")
        );

        // bind 失败关闭顺序同样严格逆序：审计回放 → ORG_SCOPE projector → 委托
        // 到期对账；ORG 未干净停止同样转为进程错误。
        let bind_shutdown = source
            .find("let _ = audit_replay_worker.join.await;")
            .expect("bind-failure shutdown sequence must remain");
        let bind_org_shutdown = source[bind_shutdown..]
            .find("shutdown_org_scope_projector(")
            .map(|offset| bind_shutdown + offset)
            .expect("org scope projector must shut down after audit replay on bind failure");
        let bind_delegation_shutdown = source[bind_org_shutdown..]
            .find("shutdown_delegation_expiry_worker(")
            .map(|offset| bind_org_shutdown + offset)
            .expect("delegation expiry shutdown must follow org scope projector shutdown");
        assert!(bind_shutdown < bind_org_shutdown);
        assert!(bind_org_shutdown < bind_delegation_shutdown);
        assert!(source[bind_shutdown..]
            .contains("org scope projector shutdown failed after bind error"));

        // ORG_SCOPE projector 启动点失败回滚：按启动逆序 cancel→join 已启动的
        // 委托到期对账 → 归档 → 新投影 → 旧 projection worker。
        let rollback = source
            .find("async fn rollback_started_workers_after_org_scope_failure(")
            .expect("org scope projector startup-failure rollback helper must remain");
        let rollback_body_end = source[rollback..]
            .find("\n}\n")
            .map(|offset| rollback + offset)
            .expect("rollback helper must have a bounded body");
        let rollback_body = &source[rollback..rollback_body_end];
        let rollback_delegation = rollback_body
            .find("shutdown_delegation_expiry_worker(")
            .expect("rollback must stop the delegation expiry worker first");
        let rollback_archive = rollback_body
            .find("shutdown_authorization_archive_worker(")
            .expect("rollback must stop the archive worker second");
        let rollback_projector = rollback_body
            .find("shutdown_authorization_projector(")
            .expect("rollback must stop the authorization projector third");
        let rollback_projection_worker = rollback_body
            .find("shutdown_projection_worker(")
            .expect("rollback must stop the legacy projection worker last");
        assert!(
            rollback_delegation < rollback_archive
                && rollback_archive < rollback_projector
                && rollback_projector < rollback_projection_worker
        );
    }
}

#[cfg(test)]
mod config_role_tests {
    /// HMAC 审计缺口修复的形状钉子：启动路径必须显式声明 Gateway 角色，
    /// 绝不回退到 from_files() 的 Learn 默认（该默认跳过 gateway.hmac_secret
    /// 强制校验，占位密钥会静默上线）。
    #[test]
    fn startup_loads_config_with_explicit_gateway_role() {
        let source = include_str!("main.rs");
        assert!(
            source.contains("JwtValidationRole::Gateway"),
            "startup must declare the Gateway validation role explicitly"
        );
        assert!(
            source.contains("from_files_for("),
            "startup must use the role-explicit loader"
        );
        assert!(
            !source.contains("AppConfig::from_files(\"application\")"),
            "the role-default Learn loader must not come back on the startup path"
        );
    }
}
