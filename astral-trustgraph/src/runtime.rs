//! AstralTrustGraph 启动入口
//!
//! ```bash
//! cargo run -p astral-trustgraph
//! # LISTEN_ADDR=0.0.0.0:9005 cargo run -p astral-trustgraph
//! ```

use std::future::IntoFuture;
use std::sync::Arc;

use axum::Router;
use lapin::Connection;
use policy_engine::PolicyEngine;

use astral_common::audit::{register_audit_db_writer, AuditDbWriter, AuditEntry};
use astral_common::config::{AppConfig, JwtValidationRole};
use astral_common::error::global_exception_handler;
use astral_common::middleware::gateway_signature::gateway_signature_middleware;
use astral_common::service::{register_mq_producer, AuditLogEvent, MqProducerRef};
use astral_db::connect_and_validate_schema_with_pool_options;
use astral_db::org_scope_repository::{
    list_org_scope_managed_tenant_ids, missing_org_scope_tenant_allowlist_entries,
    validate_org_scope_schema_prerequisites, SqlxOrgScopeRepository,
};
use astral_db::probe_org_scope_gate;
use astral_db::OrgScopeGateState;
use astral_types::ResourceRegistry;

use crate::api;
use crate::repository::admin_group_repository::SqlxAdminGroupRepository;
use crate::repository::audit_log_repository::SqlxAuditLogRepository;
use crate::repository::card_template_repository::SqlxCardTemplateRepository;
use crate::repository::cross_org_grant_repository::SqlxCrossOrgGrantRepository;
use crate::repository::delegation_repository::SqlxDelegationRepository;
use crate::repository::department_repository::SqlxDepartmentRepository;
use crate::repository::domain_repository::SqlxDomainRepository;
use crate::repository::global_admin_repository::SqlxGlobalAdminRepository;
use crate::repository::grading_repository::SqlxGradingRepository;
use crate::repository::hit_stat_repository::SqlxHitStatRepository;
use crate::repository::inheritance_config_repository::SqlxInheritanceConfigRepository;
use crate::repository::level_repository::SqlxLevelRepository;
use crate::repository::level_template_repository::SqlxLevelTemplateRepository;
use crate::repository::permission_action_repository::SqlxPermissionActionRepository;
use crate::repository::permission_request_repository::SqlxPermissionRequestRepository;
use crate::repository::platform_package_repository::SqlxPlatformPackageRepository;
use crate::repository::projection_repository::SqlxProjectionRepository;
use crate::repository::resource_type_repository::{
    load_registry_rows, ResourceTypeRepository, SqlxResourceTypeRepository,
};
use crate::repository::rule_repository::SqlxRuleRepository;
use crate::repository::rule_set_repository::{RuleSetRepository, SqlxRuleSetRepository};
use crate::repository::sod_repository::SqlxSodRepository;
use crate::repository::template_repository::SqlxTemplateRepository;
use crate::repository::tenant_repository::SqlxTenantRepository;
use crate::repository::user_card_repository::SqlxUserCardRepository;
use crate::service::approval_service::ApprovalService;
use crate::service::audit_replay_worker::{
    start_worker as start_audit_replay_worker, AuditReplayProducerSlot, AuditReplayWorkerHandle,
};
use crate::service::authorization_archive_worker::{
    shutdown_authorization_archive_worker, start_authorization_archive_worker,
    AuthorizationArchiveWorkerHandle, SHUTDOWN_JOIN_TIMEOUT_SECS,
};
use crate::service::authorization_projector::{
    parse_projector_scheduling_mode, parse_projector_tenants, parse_projector_worker_count,
    shutdown_authorization_projector, start_authorization_projector,
    validate_partition_worker_budget, AuthorizationProjectorConfig, AuthorizationProjectorHandle,
    ProjectorHealthShared, ProjectorSchedulingMode,
};
use crate::service::cross_city_runtime_wiring::{
    resolve_cross_city_start_from_env, start_cross_city_runtime, CrossCityStartDecision,
};
use crate::service::delegation_expiry_worker::{
    parse_delegation_expiry_config, shutdown_delegation_expiry_worker,
    start_delegation_expiry_worker, DelegationExpiryWorkerHandle,
};
use crate::service::delegation_service::DelegationWriteService;
use crate::service::invalidation_runtime::{
    bootstrap_mq_with_bounded_retry, close_owned_connection, parse_invalidation_fanout_enabled,
    start_invalidation_fanout_runtime, start_local_projection_supervisor, ChannelLiveness,
    FanoutWiring, InvalidationFanoutRuntime, MqConnectionAttempt, RabbitMqRuntime,
    RuntimeTaskHandle, ENV_INVALIDATION_FANOUT_ENABLED, MQ_BOOTSTRAP_BACKOFF_CAP,
    MQ_BOOTSTRAP_MAX_ATTEMPTS,
};
use crate::service::level_template_service::LevelTemplateService;
use crate::service::org_scope_projector::{
    org_scope_projector_shutdown_timeout, parse_org_scope_projector_config,
    shutdown_org_scope_projector, start_org_scope_projector, OrgScopeProjectorEnvRaw,
    OrgScopeProjectorHandle, ENV_BACKOFF_CAP_SECS, ENV_BATCH_PER_TENANT, ENV_EVENT_DEADLINE_MS,
    ENV_LEASE_SECS, ENV_MAX_ATTEMPTS, ENV_POLL_SECS, ENV_PROPAGATE_BATCH_LIMIT, ENV_TENANTS,
};
use crate::service::personal_permission_service::PersonalPermissionService;
use crate::service::projection_worker::{
    shutdown_projection_worker, spawn_worker, ProjectionWorkerHandle,
};
use crate::service::rule_set_write_service::RuleSetWriteService;
use crate::service::rule_write_service::RuleWriteService;
use crate::service::side_effect::SqlxPermissionSideEffects;
use crate::service::template_service::TemplateService;
use crate::service::tenant_service::TenantService;
use crate::service::user_card_service::UserCardService;
use crate::AppState;

#[derive(Default)]
struct RuntimeWorkerOwnership(Vec<tokio::task::AbortHandle>);

impl Drop for RuntimeWorkerOwnership {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

async fn consume_local_until_stopped(
    mut receiver: astral_mq::local_bus::LocalReceiver,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        if *stop.borrow() {
            receiver.close();
            break;
        }
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    receiver.close();
                    break;
                }
            }
            delivery = receiver.recv() => {
                let Some(delivery) = delivery else { return; };
                let result = astral_mq::consumers::dispatch_local_delivery(&delivery).await;
                delivery.complete(result);
            }
        }
    }
    while let Some(delivery) = receiver.recv().await {
        let result = astral_mq::consumers::dispatch_local_delivery(&delivery).await;
        delivery.complete(result);
    }
}

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

pub async fn run() -> anyhow::Result<()> {
    let addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:9005".into());
    run_with_listen_addr(&addr).await
}

pub async fn run_with_listen_addr(addr: &str) -> anyhow::Result<()> {
    let (signal_failure_tx, signal_failure_rx) = tokio::sync::oneshot::channel();
    let result = run_with_listen_addr_and_shutdown(addr, shutdown_signal(signal_failure_tx)).await;
    finish_after_signal_failure(result, signal_failure_rx.await)
}

pub async fn run_with_listen_addr_and_shutdown<F>(addr: &str, shutdown: F) -> anyhow::Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    run_with_listen_addr_and_shutdown_and_drain(addr, shutdown, std::future::ready(())).await
}

pub async fn run_with_listen_addr_and_shutdown_and_drain<F, D>(
    addr: &str,
    shutdown: F,
    producers_drained: D,
) -> anyhow::Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
    D: std::future::Future<Output = ()> + Send + 'static,
{
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
    // Redis 编译层退役收口（redis-layer-retirement-20261002）：宿主能力门 +
    // 已校验旗标一次性冻结。astral-common 的零依赖 marker 会被 workspace
    // feature 统一放大——任何其他 crate 打开 redis-compat 都会让集中校验的
    // cfg 通过，即便本宿主并未编译自己的 compat adapter（历史上只留下 warn
    // log 静默跳过）。能力断言以**本 crate** 的 cfg! 为准（TrustGraph 自身
    // redis-compat 仅覆盖 delete_redis_keys eviction 兼容路径）：旗标开启但
    // 未编译时，在任何 DB 连接 / worker / 服务装配之前显式拒绝启动
    // （fail-closed，非 log-only）；随后把已校验旗标冻结进进程级共享源
    // （first-wins、同值幂等、异值冲突拒绝），同进程读取方统一取值。
    config
        .validate_redis_adapter_support(cfg!(feature = "redis-compat"))
        .map_err(anyhow::Error::msg)?;
    astral_common::config::install_redis_projection_compat(config.redis_projection_compat_enabled)
        .map_err(anyhow::Error::msg)?;
    crate::repository::invalidation_repository::install_origin_region(config.region_id.clone())
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
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
    // 失效 fanout 部署旗标（P3/P4 per-node Rabbit fanout，default-off）：与
    // ORG_SCOPE 旗标同一严格 bool 契约（unset/空白/false → off；精确 true →
    // on；其他任何值 fail-closed 拒绝启动）。旗标在 DB 连接与任何 worker 启动
    // 之前解析冻结，且只门禁 Rabbit 传输分支（Local 传输的 LocalBus-only
    // supervisor 无条件装配，见 local 分支注释——缺装配 hub 永远 Suspect）。
    // NodeIdentity（Rabbit 分支用）由冻结的 region/node 配置派生并在此校验，
    // 非法值在零 worker 状态下拒绝启动（无需回滚）；Local 分支在同一冻结
    // 配置上独立派生并校验自己的 identity。
    let invalidation_fanout_enabled = {
        let raw = std::env::var(ENV_INVALIDATION_FANOUT_ENABLED).ok();
        match parse_invalidation_fanout_enabled(raw.as_deref()) {
            Ok(enabled) => {
                tracing::info!(
                    invalidation_fanout_enabled = enabled,
                    "invalidation fanout deployment state frozen at startup"
                );
                enabled
            }
            Err(error) => {
                tracing::error!(
                    error_code = "INVALIDATION_FANOUT_CONFIG_INVALID",
                    "invalid ASTRAL_INVALIDATION_FANOUT_ENABLED value; refusing startup \
                     before any worker spawn"
                );
                return Err(anyhow::anyhow!(error));
            }
        }
    };
    let invalidation_node_identity = if invalidation_fanout_enabled {
        match astral_mq::NodeIdentity::try_from_parts(
            config.region_id.clone(),
            config.node_id.clone(),
        ) {
            Ok(identity) => Some(identity),
            Err(error) => {
                tracing::error!(
                    error_code = "INVALIDATION_FANOUT_IDENTITY_INVALID",
                    "invalid fanout node identity from frozen region/node config; \
                     refusing startup before any worker spawn"
                );
                return Err(anyhow::anyhow!(
                    "invalid invalidation fanout node identity: {error}"
                ));
            }
        }
    } else {
        None
    };
    // 跨城授权 P4 部署决策（default-off，启动期冻结）：与失效 fanout 同一严格
    // 契约——`ASTRAL_CROSS_CITY_ENABLED` 缺省/false 解析为 Disabled（除本次
    // 纯 env 读取外零 IO）；显式启用但任一必需配置缺失/非法/越界在此
    // fail-closed 拒绝启动（任何 DB 连接、任何 worker 之前）。解析结果冻结一次，
    // 实际启动点（bind 成功后、serve 之前）只消费这份决策，绝不重复读 env。
    let cross_city_start_decision = match resolve_cross_city_start_from_env() {
        Ok(CrossCityStartDecision::Disabled) => {
            tracing::info!(
                "cross-city runtime disabled (default-off); startup stays a dormant no-op \
                 with zero I/O"
            );
            CrossCityStartDecision::Disabled
        }
        Ok(decision @ CrossCityStartDecision::Enabled(_)) => {
            tracing::info!(
                "cross-city runtime enablement resolved; durable startup admission runs \
                 after bind, before serve"
            );
            decision
        }
        Err(error) => {
            tracing::error!(
                error = %error,
                error_code = "CROSS_CITY_CONFIG_REFUSED",
                "invalid cross-city enablement configuration; refusing startup before any \
                 DB connection or worker spawn"
            );
            return Err(anyhow::anyhow!("cross-city configuration refused: {error}"));
        }
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
    let registry_rows = SqlxResourceTypeRepository::new(db.clone())
        .list_registry()
        .await?;
    load_registry_rows(&registry_rows)?;
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
    crate::api::tenants::register_trustgraph_data_scope_rules();

    let message_transport = config.message_transport().map_err(anyhow::Error::msg)?;
    let rabbitmq_url = config.rabbitmq_url.clone();
    let dlq_quarantine_db = db.clone();

    // 第二批：规则/规则集/委托 repository + service 装配（副作用执行器共享连接池）
    let side_effects = Arc::new(SqlxPermissionSideEffects::new(db.clone()));
    let rule_repository = Arc::new(SqlxRuleRepository::new(db.clone()));
    let rule_set_repository = Arc::new(SqlxRuleSetRepository::new(db.clone()));
    let delegation_repository = Arc::new(SqlxDelegationRepository::new(db.clone()));
    let admin_group_repository: Arc<
        dyn crate::repository::admin_group_repository::AdminGroupRepository,
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
    let arbiter_service = Arc::new(crate::service::arbiter::ArbiterService::new());
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
        crate::api::permission_check::TRUSTGRAPH_PATH_RESOURCE_MAP,
        "trustgraph",
    );

    // Pure config gates must run before the first background worker starts, so
    // an invalid tenant/topology/budget value cannot return with work still live.
    // The old eligibility projection worker remains first in startup order after
    // these gates, and therefore last in the reverse shutdown sequence.

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
    let delegation_expiry_worker_config = {
        let poll_raw = std::env::var("ASTRAL_DELEGATION_EXPIRY_POLL_SECS").ok();
        let batch_raw = std::env::var("ASTRAL_DELEGATION_EXPIRY_BATCH").ok();
        match parse_delegation_expiry_config(poll_raw.as_deref(), batch_raw.as_deref()) {
            Ok(config) => config,
            Err(error) => {
                tracing::error!(
                    error = %error,
                    error_code = "DELEGATION_EXPIRY_WORKER_CONFIG_INVALID",
                    "invalid delegation expiry worker configuration; refusing startup before any worker spawn"
                );
                return Err(anyhow::anyhow!(error));
            }
        }
    };
    // 权限投影 durable worker (legacy ELIGIBILITY outbox) starts only after
    // every pure projector configuration gate above has passed. It remains the
    // first worker in this startup sequence and shuts down last.
    let mut worker_ownership = RuntimeWorkerOwnership::default();
    let projection_worker: ProjectionWorkerHandle = {
        let projection_repo = Arc::new(SqlxProjectionRepository::new(db.clone()));
        spawn_worker(db.clone(), projection_repo)
    };
    worker_ownership
        .0
        .push(projection_worker.join.abort_handle());

    let authorization_projector: AuthorizationProjectorHandle = start_authorization_projector(
        db.clone(),
        AuthorizationProjectorConfig {
            tenants: projector_tenants.clone(),
            scheduling_mode: projector_scheduling_mode,
            worker_count: projector_worker_count,
            ..Default::default()
        },
    );
    let _authorization_projector_ownership = authorization_projector.ownership_guard();
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
            crate::service::authorization_archive_worker::AuthorizationArchiveConfig {
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

    worker_ownership
        .0
        .push(authorization_archive_worker.join.abort_handle());
    // 委托到期对账 worker：唯一职责是周期性调用
    // DelegationWriteService::reconcile_expired_delegations（显式有界批次，
    // 单条候选 = 单个 source transaction；不复制 SQL、不新增 source mutation，
    // 事务内无网络/MQ/cache）。候选发现跨租户（permission_delegation 源表暂无
    // tenant_id 列，不改 schema/索引）；每条候选的收敛在各自事务内以锁定端点
    // 卡重新证明 tenant/domain 归属，缺失即 fail-closed。默认 60s 轮询 / 批次
    // 64（硬上限 500）；env 覆盖值非法时在 spawn 前启动失败。
    let delegation_expiry_worker: DelegationExpiryWorkerHandle = start_delegation_expiry_worker(
        state.delegation_service.clone(),
        delegation_expiry_worker_config,
    )
    .map_err(|error| anyhow::anyhow!(error))?;

    worker_ownership
        .0
        .push(delegation_expiry_worker.join.abort_handle());
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

    if let Some(handle) = &org_scope_projector {
        worker_ownership.0.push(handle.join.abort_handle());
    }
    let audit_replay_worker: Option<AuditReplayWorkerHandle> = if matches!(
        message_transport,
        astral_common::config::MessageTransport::Rabbit
    ) {
        Some(start_audit_replay_worker(
            db.clone(),
            audit_replay_producer.clone(),
        ))
    } else {
        None
    };

    if let Some(handle) = &audit_replay_worker {
        worker_ownership.0.push(handle.join.abort_handle());
    }
    // 注入 audit.log consumer 的 DB pool for either local or Rabbit handlers.
    astral_mq::consumers::set_audit_log_db(db.clone());

    // 传输装配（表达式：分支内局部句柄通过元组返回到函数作用域，保证
    // RAII 句柄存活到 bind 失败 / 回滚 / 正常关闭的全部路径）。
    // - Local：audit/invalidation owner 消费循环持有 RuntimeTaskHandle
    //  （Drop abort；进程关闭即静止），不再 fire-and-forget。
    // - Rabbit：MQ bootstrap 从 fire-and-forget（无限重试 + pending 永驻
    //  keepalive 任务）改为有界启动（MQ_BOOTSTRAP_MAX_ATTEMPTS 次 + capped
    //  backoff）；每次尝试持有 owned 连接，失败/放弃必须 close（未知连接结果
    //  绝不留活连接）；成功后连接由 RabbitMqRuntime 持有到本函数作用域结束
    //  （RAII 覆盖 bind 失败/启动失败回滚/正常关闭），keepalive 任务被所有权
    //  取代。幂等后端为 durable DB store（Redis compat 保持 default-off，本
    //  runtime 不选择加入）。Audit/DLQ 消费语义保持不变。
    // - 失效 fanout runtime（旗标开启时）在两个分支各自装配恰好一次；启动
    //  失败按启动逆序回滚已启动 worker 后拒绝启动。
    let (local_stop_tx, local_stop_rx) = tokio::sync::watch::channel(false);
    let (
        rabbit_runtime,
        mut invalidation_fanout_runtime,
        mut local_invalidation_relay,
        local_owner_tasks,
    ): (
        Option<RabbitMqRuntime>,
        Option<InvalidationFanoutRuntime>,
        Option<astral_mq::consumers::LocalInvalidationRelayHandle>,
        Vec<RuntimeTaskHandle>,
    ) = if matches!(
        message_transport,
        astral_common::config::MessageTransport::Local
    ) {
        let bus = astral_mq::local_bus::global_local_bus().ok_or_else(|| {
            anyhow::anyhow!("local transport requires a composite runtime-installed LocalBus")
        })?;
        let audit_receiver = bus
            .register(
                astral_mq::config::QUEUE_AUDIT_LOG,
                astral_mq::local_bus::LocalOwner::TrustGraph,
            )
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let local_audit_consumer = RuntimeTaskHandle::spawn(
            "trustgraph-local-audit-consumer",
            consume_local_until_stopped(audit_receiver, local_stop_rx.clone()),
        );
        let invalidation_receiver = bus
            .register(
                astral_mq::config::QUEUE_AUTHORIZATION_INVALIDATION,
                astral_mq::local_bus::LocalOwner::AuthorizationInvalidation,
            )
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let local_invalidation_consumer = RuntimeTaskHandle::spawn(
            "trustgraph-local-invalidation-consumer",
            consume_local_until_stopped(invalidation_receiver, local_stop_rx),
        );
        // 本地恢复 relay（source commit 直发路径）：句柄持有到函数作用域，
        // 正常关闭 cancel→有界 join；Drop 即信号+abort（agent921 新签名落地）。
        let relay_handle = astral_mq::consumers::spawn_local_invalidation_relay(
            db.clone(),
            bus.clone(),
            format!("trustgraph-invalidation-relay-{}", uuid::Uuid::new_v4()),
        );
        crate::api::side_effects::init_local_mq_producer(
            bus.clone(),
            state.config.region_id.clone(),
        );
        register_mq_producer(Arc::new(TrustGraphMqProducer {
            inner: astral_mq::producer::Producer::new_local(
                bus.clone(),
                state.config.region_id.clone(),
            ),
        }));
        // 失效 fanout（Local 传输，无条件装配 LocalBus-only supervisor）：
        // 单机 Local 传输下 hub 健康监督是默认必需品——warm 后 strict 门只有
        // owners_ready 实际监控 + 周期 durable 对账才能清门，缺装配会让 hub
        // 永远 Suspect、内存 evidence 永不 serve。ASTRAL_INVALIDATION_FANOUT_
        // ENABLED 只门禁 Rabbit 传输分支；Local 分支不启动 relay/inbox（跨节点
        // Rabbit 语义），default-off 关闭的只是跨节点 fanout。NodeIdentity 从
        // 启动期冻结的 region/node 配置派生并在此校验（非法值拒绝启动），不
        // 依赖 fanout 旗标可选 identity。
        let local_fanout = {
            // 二次 warm 证明（composite main 在 spawn services 前已 warm 过一次）：
            // 本装配的 warm 发生在 listener bind 之前（shape test 钉住），此时
            // TrustGraph HTTP 未 serve、不存在本 runtime 的在途写请求；warmup
            // 期间 hub 读面 defer 到 durable（fail-closed），writer lease 由
            // composite 持有，strict 门保持到 reconcile 证明 durable——与 warm
            // 快照竞态的在途写入由首次 reconcile 补齐后才清门，绝不以旧内存
            // evidence serve。standalone Local 模式下本 warm 是唯一一次 warm。
            let identity = astral_mq::NodeIdentity::try_from_parts(
                state.config.region_id.clone(),
                state.config.node_id.clone(),
            )
            .map_err(|error| anyhow::anyhow!("invalid local-bus fanout node identity: {error}"))?;
            match start_local_projection_supervisor(db.clone(), bus.clone(), identity) {
                Ok(runtime) => Some(runtime),
                Err(failure) => {
                    tracing::error!(
                        error_code = "INVALIDATION_FANOUT_START_FAILED",
                        "invalidation fanout runtime failed to start; refusing startup"
                    );
                    if let Some(rollback_failure) =
                        rollback_started_workers_after_mq_bootstrap_failure(
                            audit_replay_worker,
                            org_scope_projector,
                            delegation_expiry_worker,
                            authorization_archive_worker,
                            authorization_projector,
                            projection_worker,
                        )
                        .await
                    {
                        return Err(anyhow::anyhow!(rollback_failure));
                    }
                    return Err(anyhow::anyhow!(
                        "invalidation fanout runtime failed to start: {failure}"
                    ));
                }
            }
        };
        (
            None,
            local_fanout,
            Some(relay_handle),
            vec![local_audit_consumer, local_invalidation_consumer],
        )
    } else {
        let rabbit_liveness = ChannelLiveness::new();
        let rabbit_runtime = match bootstrap_mq_with_bounded_retry(
            RabbitMqBootstrapAttempt {
                rabbitmq_url: rabbitmq_url.clone(),
                quarantine_db: dlq_quarantine_db.clone(),
                audit_replay_producer: audit_replay_producer.clone(),
                liveness: rabbit_liveness,
                owned_connection: None,
            },
            MQ_BOOTSTRAP_MAX_ATTEMPTS,
            MQ_BOOTSTRAP_BACKOFF_CAP,
        )
        .await
        {
            Ok(runtime) => runtime,
            Err(failure) => {
                tracing::error!(
                    error_code = "MQ_BOOTSTRAP_EXHAUSTED",
                    max_attempts = MQ_BOOTSTRAP_MAX_ATTEMPTS,
                    "rabbit mq bootstrap exhausted the bounded retry budget; refusing startup"
                );
                if let Some(rollback_failure) = rollback_started_workers_after_mq_bootstrap_failure(
                    audit_replay_worker,
                    org_scope_projector,
                    delegation_expiry_worker,
                    authorization_archive_worker,
                    authorization_projector,
                    projection_worker,
                )
                .await
                {
                    return Err(anyhow::anyhow!(rollback_failure));
                }
                return Err(anyhow::anyhow!(
                    "rabbit mq bootstrap failed after bounded retries: {failure}"
                ));
            }
        };
        // 失效 fanout（Rabbit 传输）：旗标开启时安装 hub + warm + markSuspect
        // strict 门 + 每节点 topology/relay/inbox + 2s reconcile supervisor；
        // 清门需要「owned 连接实际可用 + 心跳新鲜 + durable 全量对账成功」。
        let rabbit_fanout = if invalidation_fanout_enabled {
            let identity = invalidation_node_identity
                .clone()
                .expect("fanout node identity is validated before any worker starts");
            match start_invalidation_fanout_runtime(
                db.clone(),
                FanoutWiring::Rabbit {
                    connection: rabbit_runtime.connection_handle(),
                    liveness: rabbit_runtime.liveness(),
                },
                identity,
            )
            .await
            {
                Ok(runtime) => Some(runtime),
                Err(failure) => {
                    tracing::error!(
                        error_code = "INVALIDATION_FANOUT_START_FAILED",
                        "invalidation fanout runtime failed to start; refusing startup"
                    );
                    if let Some(rollback_failure) =
                        rollback_started_workers_after_mq_bootstrap_failure(
                            audit_replay_worker,
                            org_scope_projector,
                            delegation_expiry_worker,
                            authorization_archive_worker,
                            authorization_projector,
                            projection_worker,
                        )
                        .await
                    {
                        return Err(anyhow::anyhow!(rollback_failure));
                    }
                    return Err(anyhow::anyhow!(
                        "invalidation fanout runtime failed to start: {failure}"
                    ));
                }
            }
        } else {
            None
        };
        (Some(rabbit_runtime), rabbit_fanout, None, Vec::new())
    };

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

    tracing::info!(addr = %addr, "trustgraph service starting");

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(error) => {
            // bind 失败关闭：与启动严格逆序 cancel→join（审计回放 → ORG_SCOPE
            // projector（仅旗标开启时）→ 委托到期对账 → 归档 → 新投影 → 旧投影
            // worker）；任一 worker 未干净停止都会转为进程错误。
            if let Some(worker) = audit_replay_worker {
                if let Err(failure) = shutdown_audit_replay_worker(worker, "bind-failure").await {
                    return Err(anyhow::anyhow!(failure));
                }
            }
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
    // 跨城 P4 runtime（唯一运行入口，default-off）：bind 成功后、serve 之前恰好
    // 启动一次，RAII 句柄持有到 graceful shutdown。Disabled → dormant 句柄
    // （零 IO、零任务）。Enabled 路径 fail-closed：一次性 durable 启动许可
    // （node key / authoritative scope 注册表缺失即拒绝；本装配绝不注册密钥
    // 或授权）→ 真实 lapin 传输（publisher confirm）→ 有界 outbox relay +
    // inbound worker；broker confirm 只是 outbox 传输语义，绝不充当 activation
    // proof（activation 仅由双城 durable commit receipts 铸造）。启动失败按
    // 启动严格逆序回滚（fanout → 本地 relay → 既有 worker）后拒绝进程启动，
    // 不留半运行状态。
    let mut cross_city_runtime =
        match start_cross_city_runtime(db.clone(), cross_city_start_decision).await {
            Ok(handle) => {
                tracing::info!(
                    active = handle.is_active(),
                    "cross-city runtime start resolved (active=true: enabled workers running; \
                 active=false: default-off dormant with zero I/O)"
                );
                Some(handle)
            }
            Err(failure) => {
                tracing::error!(
                    error = %failure,
                    error_code = "CROSS_CITY_RUNTIME_START_FAILED",
                    "cross-city runtime failed to start; refusing startup"
                );
                // 跨城 start 契约：Err 时必无残留句柄/任务；随后按启动逆序回滚。
                if let Some(fanout) = invalidation_fanout_runtime.take() {
                    if let Err(shutdown_failure) = fanout
                        .shutdown(std::time::Duration::from_secs(SHUTDOWN_JOIN_TIMEOUT_SECS))
                        .await
                    {
                        tracing::error!(
                            reason = %shutdown_failure,
                            "invalidation fanout did not stop cleanly during cross-city rollback"
                        );
                    }
                }
                if let Some(relay) = local_invalidation_relay.take() {
                    relay.cancel();
                    if let Err(join_failure) = relay.join().await {
                        tracing::error!(
                            reason = %join_failure,
                            "local invalidation relay did not stop cleanly during cross-city \
                             rollback"
                        );
                    }
                }
                if let Some(rollback_failure) = rollback_started_workers_after_mq_bootstrap_failure(
                    audit_replay_worker,
                    org_scope_projector,
                    delegation_expiry_worker,
                    authorization_archive_worker,
                    authorization_projector,
                    projection_worker,
                )
                .await
                {
                    return Err(anyhow::anyhow!(
                        "cross-city runtime failed to start and rollback also failed: \
                     {rollback_failure}"
                    ));
                }
                return Err(anyhow::anyhow!(
                    "cross-city runtime failed to start: {failure}"
                ));
            }
        };
    let (serve_stop_tx, serve_stop_rx) = tokio::sync::oneshot::channel();
    let (drain_started_tx, mut drain_started_rx) = tokio::sync::oneshot::channel();
    let server_result = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            tokio::select! {
                _ = shutdown => {}
                _ = serve_stop_rx => {}
            }
            if let Some(hub) = astral_db::memory_projection_hub() {
                hub.mark_runtime_owner_failed("trustgraph runtime shutting down");
            }
            let _ = drain_started_tx.send(());
        })
        .into_future();
    tokio::pin!(server_result);
    let server_result: anyhow::Result<()> = tokio::select! {
        result = &mut server_result => result.map_err(Into::into),
        _ = &mut drain_started_rx => {
            match tokio::time::timeout(std::time::Duration::from_secs(30), &mut server_result).await {
                Ok(result) => result.map_err(Into::into),
                Err(_) => Err(anyhow::anyhow!("TrustGraph HTTP drain timed out; handler outcomes unknown")),
            }
        }
        failure = async {
            match cross_city_runtime.as_mut() {
                Some(handle) => handle.wait_for_failure().await,
                None => std::future::pending().await,
            }
        } => {
            if let Some(hub) = astral_db::memory_projection_hub() {
                hub.mark_runtime_owner_failed("cross-city required worker stopped");
            }
            let _ = serve_stop_tx.send(());
            match tokio::time::timeout(
                std::time::Duration::from_secs(SHUTDOWN_JOIN_TIMEOUT_SECS),
                &mut server_result,
            ).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::error!(%error, "server shutdown after cross-city failure"),
                Err(_) => tracing::error!("server shutdown after cross-city failure timed out"),
            }
            Err(anyhow::anyhow!("cross-city runtime worker failed: {failure}"))
        }
    };
    let batch_shutdown_result = api::async_tracker::tracker()
        .shutdown_tasks(std::time::Duration::from_secs(30))
        .await;
    // 关闭严格逆序：跨城 runtime 最后启动 → 最先关闭（有界 join；worker Err/
    // join 超时与既有 worker 一样转为进程错误，绝不静默吞掉断流状态）。dormant
    // 句柄零任务，报告恒为完成+空。随后才是 fanout、本地 relay 与既有 worker。
    let cross_city_shutdown_report = cross_city_runtime
        .take()
        .map(|handle| handle.shutdown(std::time::Duration::from_secs(SHUTDOWN_JOIN_TIMEOUT_SECS)));
    let server_result = match cross_city_shutdown_report {
        Some(report) => {
            let report = report.await;
            if !report.completed_within_bound {
                tracing::error!(
                    "cross-city runtime workers did not stop within the shutdown bound"
                );
                Err(anyhow::anyhow!(
                    "cross-city runtime shutdown did not complete within the bound"
                ))
            } else if let Some(failure) = report
                .outcomes
                .iter()
                .find_map(|outcome| outcome.as_ref().err())
            {
                tracing::error!(reason = %failure, "cross-city runtime worker failed");
                Err(anyhow::anyhow!(
                    "cross-city runtime worker failed: {failure}"
                ))
            } else {
                server_result
            }
        }
        None => server_result,
    };
    // Fanout and recovery producers drain before Local receivers or Rabbit close.
    // Early-return rollback retains the runtime's abort-on-drop ownership.
    let fanout_shutdown_report = match invalidation_fanout_runtime.take() {
        Some(fanout) => Some(
            fanout
                .shutdown(std::time::Duration::from_secs(SHUTDOWN_JOIN_TIMEOUT_SECS))
                .await,
        ),
        None => None,
    };
    // Local 传输：本地恢复 relay 启动先于 fanout 装配，按严格逆序在 fanout
    // 之后、既有 worker 之前静止：cancel（标记 hub suspect）→ 有界 join；
    // 超时/异常转为进程错误，绝不静默。
    let local_relay_shutdown_report = match local_invalidation_relay.take() {
        Some(relay) => {
            relay.cancel();
            Some(relay.join().await)
        }
        None => None,
    };
    // 正常关闭：启动逆序逐个 cancel→bounded join（审计回放 → ORG_SCOPE
    // projector（仅旗标开启时）→ 委托到期对账 → 归档 → 新投影 → 旧投影 worker）。
    // join 超时/panic/Err 都会让进程退出码显式失败，绝不静默吞掉断流状态；
    // 归档 worker 的运行统计在关闭时打印，供对账观测。
    let worker_result = if let Some(worker) = audit_replay_worker {
        Some(shutdown_audit_replay_worker(worker, "graceful-shutdown").await)
    } else {
        None
    };
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
    tokio::time::timeout(std::time::Duration::from_secs(4_200), producers_drained)
        .await
        .map_err(|_| {
            anyhow::anyhow!("TrustGraph producer drain barrier timed out; outcome unknown")
        })?;
    let audit_result = astral_common::audit::drain_owned_audit_tasks(
        std::time::Duration::from_secs(SHUTDOWN_JOIN_TIMEOUT_SECS),
    )
    .await;
    let _ = local_stop_tx.send(true);
    let mut local_consumer_failures = Vec::new();
    if let Err(failure) = batch_shutdown_result {
        local_consumer_failures.push(failure.to_string());
    }
    if let Err(failure) = audit_result {
        local_consumer_failures.push(failure);
    }
    for task in local_owner_tasks {
        if let Err(failure) = task
            .shutdown_join(std::time::Duration::from_secs(SHUTDOWN_JOIN_TIMEOUT_SECS))
            .await
        {
            local_consumer_failures.push(failure);
        }
    }
    if let Some(runtime) = rabbit_runtime {
        if let Err(failure) = runtime
            .shutdown(std::time::Duration::from_secs(SHUTDOWN_JOIN_TIMEOUT_SECS))
            .await
        {
            local_consumer_failures.push(failure);
        }
    }
    if !local_consumer_failures.is_empty() {
        return Err(anyhow::anyhow!(
            "local consumer drain failed: {}",
            local_consumer_failures.join("; ")
        ));
    }
    // fanout runtime：最后启动 → 关闭失败最先转为进程错误（严格逆序）。
    if let Some(Err(failure)) = &fanout_shutdown_report {
        return Err(anyhow::anyhow!(
            "invalidation fanout runtime shutdown failed: {failure}"
        ));
    }
    if let Some(Err(failure)) = &local_relay_shutdown_report {
        return Err(anyhow::anyhow!(
            "local invalidation relay shutdown failed: {failure}"
        ));
    }
    if let Some(Err(error)) = worker_result {
        return Err(anyhow::anyhow!(error));
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

async fn shutdown_audit_replay_worker(
    worker: AuditReplayWorkerHandle,
    phase: &str,
) -> Result<(), String> {
    worker.cancellation.cancel();
    let mut join = worker.join;
    match tokio::time::timeout(
        std::time::Duration::from_secs(SHUTDOWN_JOIN_TIMEOUT_SECS),
        &mut join,
    )
    .await
    {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(error))) => Err(format!(
            "audit replay worker failed during {phase}: {error}"
        )),
        Ok(Err(error)) => Err(format!(
            "audit replay worker join failed during {phase}: {error}"
        )),
        Err(_) => {
            join.abort();
            let _ = tokio::time::timeout(std::time::Duration::from_secs(1), &mut join).await;
            Err(format!(
                "audit replay worker shutdown timed out during {phase}; durable outcome unknown"
            ))
        }
    }
}

async fn shutdown_signal(signal_failure: tokio::sync::oneshot::Sender<String>) {
    let ctrl_c = async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => Ok(()),
            Err(error) => {
                tracing::warn!(%error, "failed to install Ctrl-C handler");
                Err(error.to_string())
            }
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
                Ok(())
            }
            Err(error) => {
                tracing::warn!(%error, "failed to install terminate handler");
                Err(error.to_string())
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<Result<(), String>>();

    let result = tokio::select! {
        result = ctrl_c => result,
        result = terminate => result,
    };
    if let Err(reason) = result {
        let _ = signal_failure.send(reason);
    }
}

fn finish_after_signal_failure(
    result: anyhow::Result<()>,
    signal_failure: Result<String, tokio::sync::oneshot::error::RecvError>,
) -> anyhow::Result<()> {
    match signal_failure {
        Ok(reason) => match result {
            Ok(()) => Err(anyhow::anyhow!(
                "TrustGraph shutdown signal failed: {reason}"
            )),
            Err(error) => {
                Err(error.context(format!("TrustGraph shutdown signal also failed: {reason}")))
            }
        },
        Err(_) => result,
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

/// MQ bootstrap / 失效 fanout 启动点失败后的已启动 worker 回滚：按启动严格
/// 逆序 cancel→bounded join（审计回放 → ORG_SCOPE projector（仅旗标开启时）
/// → 委托到期对账 → 归档 → 新投影 → 旧 projection worker）。任一 worker 未
/// 干净停止都作为首要失败返回并转为进程错误，绝不静默吞掉；全部干净停止
/// 返回 None。审计回放 worker 仅 Rabbit 传输启动（Local 传输为 None）。
/// 后四名 worker 复用 ORG_SCOPE 回滚 helper 的逆序与有界 join（其内部错误
/// 文案沿用 ORG 上下文，不影响失败语义与逆序契约）。
async fn rollback_started_workers_after_mq_bootstrap_failure(
    audit_replay_worker: Option<AuditReplayWorkerHandle>,
    org_scope_projector: Option<OrgScopeProjectorHandle>,
    delegation_expiry_worker: DelegationExpiryWorkerHandle,
    authorization_archive_worker: AuthorizationArchiveWorkerHandle,
    authorization_projector: AuthorizationProjectorHandle,
    projection_worker: ProjectionWorkerHandle,
) -> Option<String> {
    if let Some(worker) = audit_replay_worker {
        if let Err(failure) = shutdown_audit_replay_worker(worker, "mq-bootstrap-failure").await {
            tracing::error!(
                reason = %failure,
                "audit replay worker did not stop cleanly after \
                 mq bootstrap failure"
            );
            return Some(format!(
                "audit replay worker shutdown failed after mq bootstrap \
                 failure: {failure}"
            ));
        }
    }
    if let Some(handle) = org_scope_projector {
        let org_scope_shutdown_timeout = org_scope_projector_shutdown_timeout(&handle);
        let org_scope_report =
            shutdown_org_scope_projector(handle, org_scope_shutdown_timeout).await;
        if let Err(failure) = org_scope_report.summary {
            tracing::error!(
                reason = %failure,
                "org scope projector did not stop cleanly after \
                 mq bootstrap failure"
            );
            return Some(format!(
                "org scope projector shutdown failed after mq bootstrap \
                 failure: {failure}"
            ));
        }
    }
    rollback_started_workers_after_org_scope_failure(
        delegation_expiry_worker,
        authorization_archive_worker,
        authorization_projector,
        projection_worker,
    )
    .await
}

/// Rabbit MQ bootstrap 的 owned 尝试：每次 open 持有全新连接；open 失败或被
/// 放弃时由 bootstrap 循环调用 close_owned 关闭全部 owned 连接资源（未知/失败
/// 结果绝不留活连接）；每次尝试独立记账，无跨尝试预算残留。成功后连接移交
/// RabbitMqRuntime 持有到函数作用域结束（RAII），keepalive 任务被所有权取代。
struct RabbitMqBootstrapAttempt {
    rabbitmq_url: String,
    quarantine_db: sqlx::MySqlPool,
    audit_replay_producer: AuditReplayProducerSlot,
    liveness: ChannelLiveness,
    owned_connection: Option<Arc<Connection>>,
}

#[async_trait::async_trait]
impl MqConnectionAttempt for RabbitMqBootstrapAttempt {
    type Runtime = RabbitMqRuntime;

    async fn open(&mut self) -> Result<RabbitMqRuntime, String> {
        // 上一次尝试的残留（若有）已由 close_owned 清空；防御性再置空。
        self.owned_connection = None;
        let conn = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            Connection::connect(
                &self.rabbitmq_url,
                lapin::ConnectionProperties::default().enable_auto_recover(),
            ),
        )
        .await
        .map_err(|_| "TrustGraph Rabbit connect timed out".to_owned())?
        .map_err(|_| "TrustGraph Rabbit connect failed".to_owned())?;
        // lapin 4 的 Connection 不可 Clone：Arc 共享（fanout wiring / inbox
        // 重连闭包经由 Arc 克隆使用同一连接），所有权仍归本尝试。
        self.owned_connection = Some(Arc::new(conn));
        let channel = {
            let conn = self
                .owned_connection
                .as_ref()
                .expect("owned connection registered above");
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                init_mq_consumers(
                    conn,
                    &self.quarantine_db,
                    self.audit_replay_producer.clone(),
                ),
            )
            .await
            .map_err(|_| "TrustGraph Rabbit consumer setup timed out".to_owned())?
            .map_err(|_| "TrustGraph Rabbit consumer setup failed".to_owned())?
        };
        let owned = self
            .owned_connection
            .take()
            .expect("owned connection held above");
        self.liveness.mark_alive();
        Ok(RabbitMqRuntime::from_bootstrap(
            owned,
            channel,
            self.liveness.clone(),
        ))
    }

    async fn close_owned(&mut self, reason: &str) {
        if let Some(conn) = self.owned_connection.take() {
            close_owned_connection(conn, reason).await;
        }
        self.liveness.mark_dead();
    }
}

/// 在已连接的 owned 连接上完成 Rabbit 消费面初始化：durable DB 幂等后端
/// （migration preflight：表缺失/池不可用一律启动失败）、声明全部交换机/队列/
/// DLX 绑定、注入 producer、启动 TrustGraph 独占的 audit/DLQ 消费者（旧语义
/// 保持不变）并装配审计回放 producer 槽位。连接所有权留在调用方（bootstrap
/// 尝试），不再 spawn keepalive 任务。
async fn init_mq_consumers(
    conn: &Connection,
    quarantine_db: &sqlx::MySqlPool,
    audit_replay_producer: AuditReplayProducerSlot,
) -> Result<lapin::Channel, Box<dyn std::error::Error>> {
    // 幂等后端切换（Redis-free final review 决议）：durable DB store 是默认且
    // 唯一要求；Redis compat 保持 default-off，本 runtime 不选择加入。
    astral_mq::consumer::init_idempotency_db(quarantine_db.clone()).await?;
    // 1. 声明通道并启用 publisher confirms
    let channel = conn.create_channel().await?;
    astral_mq::producer::Producer::enable_confirms(&channel).await?;
    tracing::info!("Connected to RabbitMQ");

    // 2. 声明所有交换机、队列和 DLX 绑定
    astral_mq::config::declare_all(&channel).await?;
    tracing::info!("All MQ queues declared");

    // 2.5 初始化全局 MQ producer。审计通过 common 适配器发送，CARD 权限刷新仅由
    // durable projection worker 携带 source_generation/revoke_fence 发布。
    crate::api::side_effects::init_mq_producer(channel.clone());
    // Publisher confirms are enabled on this exact channel above; only publish
    // this producer after all declarations/consumers below complete successfully.
    // The slot is a cloneable lock hand-off, so no OnceLock or borrowed channel
    // escapes this bootstrap step.
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
    astral_mq::consumers::start_audit_log_consumer(&channel).await?;
    if !audit_replay_producer
        .set(audit_replay_producer_instance)
        .await
    {
        return Err("audit replay producer slot was already initialized".into());
    }
    Ok(channel)
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
        crate::repository::rule_set_repository::SqlxRuleSetRepository::new(db.clone());
    let system_context = crate::repository::audit_log_repository::RuleSetMutationContext::system(
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
    #[tokio::test]
    async fn local_consumer_cooperative_shutdown_closes_admission() {
        let bus = astral_mq::local_bus::LocalBus::new(Default::default()).unwrap();
        let receiver = bus
            .register(
                astral_mq::config::QUEUE_AUDIT_LOG,
                astral_mq::local_bus::LocalOwner::TrustGraph,
            )
            .unwrap();
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let handle = super::RuntimeTaskHandle::spawn(
            "local-stop-test",
            super::consume_local_until_stopped(receiver, stop_rx),
        );
        stop_tx.send(true).unwrap();
        handle
            .shutdown_join(std::time::Duration::from_secs(1))
            .await
            .expect("closed local receiver must stop cooperatively");
        assert!(!bus.owners_ready());
    }

    #[tokio::test]
    async fn runtime_cancellation_aborts_all_registered_recovery_tasks() {
        struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);
        impl Drop for DropSignal {
            fn drop(&mut self) {
                if let Some(signal) = self.0.take() {
                    let _ = signal.send(());
                }
            }
        }
        let mut owner = super::RuntimeWorkerOwnership::default();
        let mut completions = Vec::new();
        for _ in 0..5 {
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
            let join = tokio::spawn(async move {
                let _drop = DropSignal(Some(dropped_tx));
                let _ = ready_tx.send(());
                std::future::pending::<()>().await;
            });
            owner.0.push(join.abort_handle());
            ready_rx.await.unwrap();
            completions.push(dropped_rx);
        }
        drop(owner);
        for completion in completions {
            tokio::time::timeout(std::time::Duration::from_secs(1), completion)
                .await
                .expect("runtime cancellation must not detach recovery tasks")
                .expect("recovery task Drop must be observed");
        }
    }

    #[test]
    fn every_started_recovery_worker_has_runtime_drop_ownership() {
        let source = production_source();
        for name in [
            "projection_worker",
            "authorization_archive_worker",
            "delegation_expiry_worker",
        ] {
            assert!(source.contains(&format!("{name}.join.abort_handle()")));
        }
        assert!(source.contains("if let Some(handle) = &org_scope_projector"));
        assert!(source.contains("if let Some(handle) = &audit_replay_worker"));
        assert!(source.contains("authorization_projector.ownership_guard()"));
    }

    #[test]
    fn projector_pure_config_gates_precede_first_worker_spawn() {
        let source = production_source();
        let first_worker = source
            .find("let projection_worker: ProjectionWorkerHandle")
            .expect("legacy worker must remain in startup");
        for gate in [
            "let projector_tenants = {",
            "let projector_scheduling_mode = {",
            "let projector_worker_count = {",
            "validate_partition_worker_budget(projector_worker_count, pool_max_connections)",
        ] {
            let position = source
                .find(gate)
                .expect("projector config gate must remain");
            assert!(position < first_worker, "{gate} must precede worker spawn");
        }
        let archive_config_rejection = source
            .find("AUTH_ARCHIVE_WORKER_CONFIG_INVALID")
            .expect("archive config rejection must remain");
        let archive_shutdown = source[archive_config_rejection..]
            .find("shutdown_authorization_projector(")
            .map(|offset| archive_config_rejection + offset)
            .expect("archive rejection must stop the authorization projector");
        assert!(first_worker < archive_config_rejection);
        let projection_shutdown = source[archive_shutdown..]
            .find("shutdown_projection_worker(")
            .map(|offset| archive_shutdown + offset)
            .expect("archive rejection must also stop the legacy worker");
        assert!(archive_shutdown < projection_shutdown);
        assert!(source.contains("rollback_started_workers_after_org_scope_failure"));
    }

    fn production_source() -> &'static str {
        // 守卫测试使用含 \n 的多行锚串；Windows 下 core.autocrlf 检出为
        // CRLF 时 include_str! 会嵌入 \r\n，使所有多行锚串失配（并非真实
        // 源码漂移）。归一化行尾后再截掉测试模块，使断言与检出配置无关。
        static NORMALIZED: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        NORMALIZED.get_or_init(|| {
            include_str!("runtime.rs")
                .replace("\r\n", "\n")
                .split("#[cfg(test)]")
                .next()
                .expect("production source must precede tests")
                .to_string()
        })
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
            .find("let audit_replay_worker: Option<AuditReplayWorkerHandle>")
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
        // fire-and-forget 无限重试已替换为有界 bootstrap：失败不再以 `.ok()`
        // 吞掉后盲目循环，而是 close owned 连接、按 capped backoff 有限重试，
        // 预算耗尽即拒绝启动。
        assert!(
            !blocks[0].contains(".await\n                .ok();"),
            "the fire-and-forget init loop must not come back"
        );
        assert!(blocks[0].contains("MQ_BOOTSTRAP_EXHAUSTED"));
        assert!(blocks[0].contains("rollback_started_workers_after_mq_bootstrap_failure("));
        assert!(blocks[0].contains("MQ_BOOTSTRAP_MAX_ATTEMPTS"));
    }

    #[test]
    fn org_scope_config_gate_and_schema_guard_precede_any_worker_spawn() {
        let source = production_source();
        // 唯一配置门禁：冻结的共享 org_scope_enabled 旗标。env 快照必须在门内
        // 读取，且配置解析必须发生在 DB 连接与 any worker spawn 之前（非法配置
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
            .find("// 注入 audit.log consumer 的 DB pool")
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
            .find("let audit_replay_worker: Option<AuditReplayWorkerHandle>")
            .expect("audit replay worker startup must remain");
        assert!(delegation_expiry_start < org_start && org_start < audit_replay_start);

        // 正常关闭顺序（严格逆序）：审计回放 → ORG_SCOPE projector → 委托到期
        // 对账 → 归档 → 新投影 → 旧 projection worker，且 ORG 关闭失败必须转为
        // 进程错误。
        let normal_shutdown = source
            .find("let worker_result = if let Some(worker) = audit_replay_worker")
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
            .find("if let Some(worker) = audit_replay_worker")
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

    #[test]
    fn signal_registration_failure_is_retained_as_runtime_error() {
        let result =
            super::finish_after_signal_failure(Ok(()), Ok("ctrl-c registration failed".into()));
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("ctrl-c registration failed"));
    }

    #[test]
    fn cross_city_runtime_is_wired_once_with_default_off_gate_and_reverse_order_shutdown() {
        let source = production_source();
        // 启动期冻结：跨城决策解析必须在 DB 连接之前——enabled 但配置非法在
        // 零 IO / 零 worker 状态下拒绝启动；Disabled 保持零 IO dormant。
        let decision = source
            .find("let cross_city_start_decision = match resolve_cross_city_start_from_env()")
            .expect("cross-city start decision must be resolved once from frozen env");
        let db_connect = source
            .find("let db = connect_and_validate_schema_with_pool_options(")
            .expect("DB connect must remain on the startup path");
        assert!(
            decision < db_connect,
            "cross-city decision freezes before any I/O"
        );
        // 唯一启动点：bind 成功后、serve 之前恰好一次（Default-off 走 dormant
        // 句柄；启用路径为 durable 启动许可 + 真实传输）；RAII 句柄持有到关闭。
        assert_eq!(
            source.matches("start_cross_city_runtime(").count(),
            1,
            "cross-city runtime must be started exactly once by the outer runtime"
        );
        let bind = source
            .find("let listener = match tokio::net::TcpListener::bind(addr).await")
            .expect("listener bind must remain the gate before serve");
        let start = source
            .find("start_cross_city_runtime(")
            .expect("cross-city start call must remain");
        let serve = source
            .find("let server_result = axum::serve(listener, app)")
            .expect("axum serve must remain");
        assert!(
            bind < start && start < serve,
            "cross-city starts after bind, before serve"
        );
        // 关闭严格逆序：跨城最后启动 → 最先关闭；worker Err / join 超时转进程错误。
        let cross_city_shutdown = source
            .find("let cross_city_shutdown_report = cross_city_runtime")
            .expect("cross-city shutdown must remain first in the graceful sequence");
        let fanout_shutdown = source
            .find("let fanout_shutdown_report = match invalidation_fanout_runtime.take()")
            .expect("fanout shutdown must remain");
        assert!(
            cross_city_shutdown < fanout_shutdown,
            "cross-city runtime shuts down before the fanout runtime (strict reverse order)"
        );
        assert!(source.contains("cross-city runtime shutdown did not complete within the bound"));
        assert!(source.contains("cross-city runtime worker failed: {failure}"));
        assert!(source.contains("handle.wait_for_failure().await"));
        assert!(source.contains("serve_stop_tx.send(())"));
        // 启动失败：按启动逆序回滚（fanout → 本地 relay → 既有 worker）后拒绝启动。
        let start_failure = source
            .find("CROSS_CITY_RUNTIME_START_FAILED")
            .expect("cross-city start failure must refuse startup");
        assert!(
            source[start_failure..]
                .contains("rollback_started_workers_after_mq_bootstrap_failure("),
            "cross-city start failure must roll back already-started workers"
        );
        assert!(source.contains("cross-city runtime failed to start: {failure}"));
    }

    #[test]
    fn local_transport_supervision_is_unconditional_rabbit_stays_flag_gated() {
        let source = production_source();
        let local_comment = source
            .find("// 失效 fanout（Local 传输，无条件装配 LocalBus-only supervisor）")
            .expect("local transport must unconditionally assemble the LocalBus supervisor");
        let local_start = source
            .find("let local_fanout = {")
            .expect("local transport must unconditionally assemble the LocalBus supervisor");
        let rabbit_gate = source
            .find("let rabbit_fanout = if invalidation_fanout_enabled {")
            .expect("rabbit fanout must stay strictly flag-gated (default-off)");
        let local_block = &source[local_comment..rabbit_gate];
        assert!(local_start < rabbit_gate);
        assert!(
            !local_block.contains("if invalidation_fanout_enabled"),
            "LocalBus supervision must not depend on the fanout flag (hub would stay \
             Suspect forever and in-memory evidence would never serve)"
        );
        assert!(local_block.contains("NodeIdentity::try_from_parts("));
        assert!(
            local_block.contains("state.config.region_id.clone()")
                && local_block.contains("state.config.node_id.clone()"),
            "local identity must derive from the frozen region/node config, not the \
             fanout-optional identity"
        );
        assert!(local_block.contains("start_local_projection_supervisor"));
        assert!(
            !local_block.contains("FanoutWiring::LocalBus"),
            "the already-warmed local branch must use the supervisor-only entry"
        );
        assert!(
            !local_block.contains("FanoutWiring::Rabbit"),
            "the local branch must stay LocalBus-only (no Rabbit relay/inbox)"
        );
        assert_eq!(
            source.matches("start_invalidation_fanout_runtime(").count(),
            1,
            "only the flag-gated Rabbit branch uses the full fanout start"
        );
        // Local supervisor reuses the composite warm; it must not promise a
        // second warm or clear the mirror before durable reconcile.
        let bind = source
            .find("let listener = match tokio::net::TcpListener::bind(addr).await")
            .expect("listener bind must remain the gate before serve");
        assert!(local_start < bind);
        assert!(local_block.contains("start_local_projection_supervisor"));
    }
}

#[cfg(test)]
mod config_role_tests {
    /// HMAC 审计缺口修复的形状钉子：启动路径必须显式声明 Gateway 角色，
    /// 绝不回退到 from_files() 的 Learn 默认（该默认跳过 gateway.hmac_secret
    /// 强制校验，占位密钥会静默上线）。
    #[test]
    fn startup_loads_config_with_explicit_gateway_role() {
        let source = include_str!("runtime.rs");
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
