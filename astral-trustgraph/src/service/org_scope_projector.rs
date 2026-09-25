//! ORG_SCOPE outbox 投影 worker（Phase 2 default-off，独立队列唯一消费者）。
//!
//! 消费 `org_scope_outbox`（`astral_db::org_scope_repository` 专属队列表，与旧
//! `authorization_delta_event` 完全隔离）→ 事务外纯编译 → `complete_publish`
//! 原子发布 sealed publication/segments/dependency pins、current generation CAS
//! 与事件终态。本 worker 只编排既有 API，绝不复制 SQL、绝不新增 source
//! mutation、绝不触碰 MQ/Redis/cache。
//!
//! # 硬边界（对齐 AGENTS §3 与 Exec-L2 预算）
//!
//! - **default-off**：`main` 仅在 `ASTRAL_ORG_SCOPE_ENABLED=true`（严格解析见
//!   [`crate::service::org_authorities::org_authorities_config_from_env`]）时才
//!   调用 [`start_org_scope_projector`]；旗标关闭时本 worker 从未启动，无任务、
//!   无轮询、无副作用。
//! - **worker 身份**：stable run-scoped owner（`org-scope-projector-{run_id}`，
//!   run_id 为 UUIDv4）+ 32 字节随机 lease token（64 位小写 hex，两次 UUIDv4
//!   拼接）；token 只以 SHA-256 摘要落库（由 `astral-db` claim SQL 保证），明文
//!   永不入日志/审计。身份在 spawn 前 fail-fast 校验，与 `astral-db` 的
//!   `validated_lease_owner` / `decode_worker_token` 合同同界。
//! - **事务边界**：claim、`load_compile_input`、`complete_publish` 均为
//!   repository 内部短事务；编译（[`OrgCompiler::compile_full`]，全量 oracle）
//!   是纯内存计算，运行在任何事务之外。source 事务内不含网络/MQ/重试/发布。
//! - **fail-closed**：[`EventOutcome::Published`] 只在 `complete_publish` 返回
//!   `Ok` 后产生——绝不以编译成功、租约持有或"看似成功"代替 durable proof。
//!   失败经 `fail_outbox_event` 登记：可重试失败按 attempt 有界退避
//!   （attempts 达到 `max_event_attempts` 由 repository 落终态 FAILED）；编译器
//!   确定性合同错误（[`OrgError`]，如 `ParentNotDelegable`、结构校验失败）直接
//!   `retryable=false` 落终态 FAILED，等待 operator/新 source 事件介入。租约
//!   丢失（被夺/过期）立即放弃当次事件，零后续写入，绝不重放。同一
//!   `max_event_attempts` 预算也随每条 claim 命令下发（claim 侧预算收敛）：
//!   本 worker 在 claim 之后、失败登记之前崩溃时，过期租约回收达到预算即由
//!   repository 在 claim 事务内直接落终态 FAILED（claim 返回 `Ok(None)`），
//!   认领次数因此有界，绝不无限回收，也绝不静默丢弃 durable 意图。
//! - **有界**：轮询间隔、每租户每轮 claim 数、单事件 deadline（严格小于租约
//!   窗口）、退避上限、重试预算全部有界；取消发生在事件之间，绝不 abort 进行
//!   中的 repository 事务（deadline 中断由事务原子性兜底回滚）。
//! - **失败可见**：`fail_outbox_event` 自身失败 → [`EventOutcome::RecordUnknown`]，
//!   计入 summary 并在关闭时显式上报，要求 operator 对账；绝不静默重试或伪装
//!   成功。
//!
//! # 事件分派（event-kind dispatch）
//!
//! worker 按租约行 `event_kind` 分派，绝不以 payload 解析结果替代 durable 事实：
//!
//! - **发布类**（`NODE_CREATED`、`NODE_TOPOLOGY_CHANGED`、`NODE_MUTATED`、
//!   `GRANT_ISSUED`、`GRANT_REVOKED`、`MASK_APPLIED`、`MASK_REMOVED`）：保持
//!   既有 装载 → 编译 → 发布 主路径；payload 仅作诊断。
//! - **`MEMBERSHIP_CHANGED`**：payload 解析为 typed `OrgMembership` 并
//!   `validate()`、绑定租户（payload tenant 必须等于租约 tenant）后，直接
//!   kind-scoped complete（期望 `MEMBERSHIP_CHANGED`）；绝不 load/compile/
//!   publish。成员资格是独立版本化事实，准入读路径 fresh-check membership，
//!   不需要重编译。解析/校验/租户不一致是确定性合同破坏 → 终态 FAILED。
//! - **`SUBTREE_PROPAGATE`**（锚点扇出模型）：payload 解析为 typed
//!   `OrgSubtreePropagatePayload` 并校验、绑定租户（`child_tenant_id ==
//!   lease.tenant_id`）后，以载荷 child 为**唯一锚点**反复调用租约内扇出传播：
//!   repository 每批只推进锚点的**直接**陈旧子节点至多 `batch_limit` 个，并为
//!   每个被推进子节点原子派生新的 typed child intent（后代由各自事件继续，
//!   不做 worker 内 BFS）。`done=false` 时下一前沿必须精确等于 `[锚点]`
//!   （同一事件重入排空剩余直系兄弟），否则为合同不一致 → 稳定机码
//!   `code=org_scope.propagate_frontier_inconsistent` 有界重试，绝不改道/
//!   重定向、绝不无限循环。`done=true`（锚点直系兄弟排空）或
//!   `superseded=true`（repository 锁内证实意图已被更新的拓扑 source 变更
//!   取代的安全无写放行）才 kind-scoped complete（期望 `SUBTREE_PROPAGATE`）；
//!   绝不发布，也绝不从 payload 本地推断意图新鲜度。
//! - **未知 kind**：按可重试失败登记（稳定机码
//!   `code=org_scope.outbox_event_kind_unknown`），绝不发布/complete；滚动
//!   升级窗口内新 kind 由旧 worker 有界退避，attempt 预算收敛为终态 FAILED。
//!
//! # 编译输入载荷边界（发布类事件）
//!
//! 发布类事件的 outbox `payload_json` 仅作诊断：worker 不解析它，也不从它推导
//! 任何授权事实；编译输入一律由 `load_compile_input` 在租约内从已批准 durable
//! 事实快照装载。子节点只依赖直接父 publication，并携带排序且扁平化的全部祖先
//! dependency pins；决策侧不遍历行政树。深度、依赖缺失或 generation/fence/
//! relationship drift 均由类型合同和 repository reader fail-closed 为 PENDING，
//! 本 worker 只按有界重试/终态 FAILED 合同处理，绝不放宽、绝不绕过。
//!
//! # main 接线契约
//!
//! `service/mod.rs` 将本模块生产可见；`main` 仅在启动期冻结的
//! `org_scope_enabled == true` 时读取 `OrgScopeProjectorEnvRaw`、解析显式 tenant
//! allowlist、完成只读 schema guard，并以预校验配置调用
//! [`start_org_scope_projector`]。关闭时按启动严格逆序调用
//! [`shutdown_org_scope_projector`]（cancel → 有界 join）；超时/panic/Err 必须转为
//! 进程错误，绝不静默吞掉断流状态。

use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use uuid::Uuid;

use astral_db::org_scope_repository::{
    OrgCompileInputCommand, OrgDependencyPropagateCommand, OrgDependencyPropagateOutcome,
    OrgOutboxClaimCommand, OrgOutboxCompleteCommand, OrgOutboxCompleteOutcome, OrgOutboxEventKind,
    OrgOutboxFailCommand, OrgOutboxFailOutcome, OrgOutboxLease, OrgOutboxRenewCommand,
    OrgPublishCommand, OrgPublishOutcome, OrgScopeRepository, OrgSubtreePropagateCommand,
    OrgSubtreePropagateOutcome, SqlxOrgScopeRepository, ORG_MAX_PROPAGATE_BATCH,
};
use astral_types::org_scope::{
    OrgCompileInput, OrgDependencyPropagatePayload, OrgError, OrgMembership, OrgPendingReport,
    OrgPublication, OrgSubtreePropagatePayload,
};
use astral_types::AstralError;
use policy_engine::{OrgCompileOutcome, OrgCompiler};

// ─────────────────────────────────────────────────────────────────────────────
// Worker policy constants (Exec-L2 budgets)
// ─────────────────────────────────────────────────────────────────────────────

/// 空闲轮询间隔（秒）。
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 5;
/// 单条事件租约窗口（秒），claim 侧硬上限 3600（repository 合同）。
pub const DEFAULT_CLAIM_LEASE_SECONDS: i64 = 120;
/// 单事件 attempt 预算（fail_outbox_event 的 max_attempts；attempts 达到该值
/// 后可重试失败由 repository 落终态 FAILED）。
pub const DEFAULT_MAX_EVENT_ATTEMPTS: i64 = 5;
/// 可重试失败退避上限（秒）。
pub const DEFAULT_BACKOFF_CAP_SECONDS: i64 = 900;
/// 每租户每轮 drain 上限。
pub const DEFAULT_EVENTS_PER_TENANT_CYCLE: usize = 8;
/// 单事件处理 deadline（毫秒）；必须严格小于租约窗口（校验强制）。
pub const DEFAULT_EVENT_DEADLINE_MS: u64 = 60_000;
/// Graceful shutdown grants one configured event deadline plus a bounded margin
/// for its best-effort durable failure record. This is intentionally separate
/// from the 30s generic worker join budget: an ORG event may legitimately run
/// for the full configured deadline before cancellation is next observed.
pub const ORG_SCOPE_SHUTDOWN_FAILURE_RECORDING_GRACE_SECS: u64 = 10;
/// 子树传播单批上限默认值：扇出模型下每批只推进锚点的**直接**陈旧子节点，
/// 后代由各自 child intent 事件继续，200 远低于 repository 批上限且分批节奏
/// 平缓（见 [`MAX_PROPAGATE_BATCH_LIMIT`]）。
pub const DEFAULT_PROPAGATE_BATCH_LIMIT: i64 = 200;

pub const MAX_POLL_INTERVAL_SECS: u64 = 3600;
pub const MAX_CLAIM_LEASE_SECONDS: i64 = 3600;
pub const MAX_MAX_EVENT_ATTEMPTS: i64 = 1000;
pub const MAX_BACKOFF_CAP_SECONDS: i64 = 86_400;
pub const MAX_EVENTS_PER_TENANT_CYCLE: usize = 1000;
/// 受治理租户上限（claim 按 tenant 逐个轮询；列表过大会放大每轮无谓探测）。
pub const MAX_ORG_SCOPE_TENANTS: usize = 64;
/// `propagate_batch_limit` 上限：扇出模型下 `done=false` 的下一前沿恒为
/// `[锚点]`（单元素），批行数不再成为前沿宽度，因此只需镜像 repository 自身
/// 的批校验 `1..=ORG_MAX_PROPAGATE_BATCH`，超限会在节点写入前被拒
/// （`code=org_scope.propagate_batch_invalid`）。
pub const MAX_PROPAGATE_BATCH_LIMIT: i64 = ORG_MAX_PROPAGATE_BATCH;

/// 周期级基础设施失败退避上限（claim 连续失败；与事件退避是两个预算）。
const CYCLE_BACKOFF_MAX_SECS: u64 = 30;
/// 租约丢失的稳定机器码（`astral-db` worker 原语合同，不得漂移）。
const LEASE_LOST_MACHINE_CODE: &str = "code=org_scope.outbox_lease_lost";
/// 单事件 deadline 命中时的稳定机器码前缀。
const EVENT_DEADLINE_MACHINE_CODE: &str = "code=org_scope.projector.event_deadline_exceeded";
/// 未知 outbox 事件 kind 的稳定机码（可重试；滚动升级窗口内由 attempt 预算
/// 收敛为终态 FAILED，绝不发布/complete）。
const UNKNOWN_EVENT_KIND_MACHINE_CODE: &str = "code=org_scope.outbox_event_kind_unknown";
/// MEMBERSHIP_CHANGED 载荷解析/校验失败的稳定机码（确定性终态）。
const MEMBERSHIP_PAYLOAD_INVALID_MACHINE_CODE: &str = "code=org_scope.membership_payload_invalid";
/// MEMBERSHIP_CHANGED 载荷租户与租约租户不一致的稳定机码（确定性终态）。
const MEMBERSHIP_TENANT_MISMATCH_MACHINE_CODE: &str = "code=org_scope.membership_tenant_mismatch";
/// SUBTREE_PROPAGATE 载荷解析/校验失败的稳定机码（确定性终态）。
const PROPAGATE_PAYLOAD_INVALID_MACHINE_CODE: &str = "code=org_scope.propagate_payload_invalid";
/// SUBTREE_PROPAGATE 载荷 child 租户与租约租户不一致的稳定机码（确定性终态）。
const PROPAGATE_TENANT_MISMATCH_MACHINE_CODE: &str = "code=org_scope.propagate_tenant_mismatch";
/// propagate 返回非 done 但下一前沿不精确等于 `[锚点]` 的稳定机码（合同不
/// 一致：空前沿、异值或多元素；有界重试，绝不改道重定向，绝不无限循环）。
const PROPAGATE_FRONTIER_INCONSISTENT_MACHINE_CODE: &str =
    "code=org_scope.propagate_frontier_inconsistent";
const DEPENDENCY_PROPAGATE_PAYLOAD_INVALID_MACHINE_CODE: &str =
    "code=org_scope.dependency_propagate_payload_invalid";
const DEPENDENCY_PROPAGATE_TENANT_MISMATCH_MACHINE_CODE: &str =
    "code=org_scope.dependency_propagate_tenant_mismatch";
const DEPENDENCY_PROPAGATE_PROGRESS_INCONSISTENT_MACHINE_CODE: &str =
    "code=org_scope.dependency_propagate_progress_inconsistent";

// 环境变量名（main 读取后以纯函数解析；本模块绝不直接读进程环境）。
pub const ENV_TENANTS: &str = "ASTRAL_ORG_SCOPE_TENANTS";
pub const ENV_POLL_SECS: &str = "ASTRAL_ORG_SCOPE_PROJECTOR_POLL_SECS";
pub const ENV_LEASE_SECS: &str = "ASTRAL_ORG_SCOPE_PROJECTOR_LEASE_SECS";
pub const ENV_MAX_ATTEMPTS: &str = "ASTRAL_ORG_SCOPE_PROJECTOR_MAX_ATTEMPTS";
pub const ENV_BACKOFF_CAP_SECS: &str = "ASTRAL_ORG_SCOPE_PROJECTOR_BACKOFF_CAP_SECS";
pub const ENV_BATCH_PER_TENANT: &str = "ASTRAL_ORG_SCOPE_PROJECTOR_BATCH_PER_TENANT";
pub const ENV_EVENT_DEADLINE_MS: &str = "ASTRAL_ORG_SCOPE_PROJECTOR_EVENT_DEADLINE_MS";
pub const ENV_PROPAGATE_BATCH_LIMIT: &str = "ASTRAL_ORG_SCOPE_PROJECTOR_PROPAGATE_BATCH_LIMIT";

// ─────────────────────────────────────────────────────────────────────────────
// 配置与 fail-fast 解析
// ─────────────────────────────────────────────────────────────────────────────

/// worker 启动配置。spawn 前必须通过 [`OrgScopeProjectorConfig::validate`]，
/// 非法配置一律拒绝，绝不降级为"顺便用默认值"。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgScopeProjectorConfig {
    /// 受治理租户（outbox 行的 tenant_id 域）。由部署显式提供；非空、去重、
    /// 全部为正且 ≤ [`MAX_ORG_SCOPE_TENANTS`]。
    pub tenants: Vec<i64>,
    pub poll_interval_secs: u64,
    pub claim_lease_seconds: i64,
    pub max_event_attempts: i64,
    pub backoff_cap_seconds: i64,
    pub events_per_tenant_cycle: usize,
    /// 单事件处理 deadline（毫秒），严格小于租约窗口（校验强制），保证任何
    /// 挂起步骤都在租约被夺之前变成"计数 + 尽力登记 + 继续循环"。
    pub event_deadline_ms: u64,
    /// 子树传播单批上限（SUBTREE_PROPAGATE 每批推进锚点的**直接**陈旧子节点
    /// 数）。扇出模型下后代由各自 child intent 事件推进，本值不再决定前沿
    /// 宽度；校验镜像 repository 批上限 [`MAX_PROPAGATE_BATCH_LIMIT`]。
    pub propagate_batch_limit: i64,
}

impl Default for OrgScopeProjectorConfig {
    fn default() -> Self {
        Self {
            tenants: Vec::new(),
            poll_interval_secs: DEFAULT_POLL_INTERVAL_SECS,
            claim_lease_seconds: DEFAULT_CLAIM_LEASE_SECONDS,
            max_event_attempts: DEFAULT_MAX_EVENT_ATTEMPTS,
            backoff_cap_seconds: DEFAULT_BACKOFF_CAP_SECONDS,
            events_per_tenant_cycle: DEFAULT_EVENTS_PER_TENANT_CYCLE,
            event_deadline_ms: DEFAULT_EVENT_DEADLINE_MS,
            propagate_batch_limit: DEFAULT_PROPAGATE_BATCH_LIMIT,
        }
    }
}

impl OrgScopeProjectorConfig {
    fn event_deadline(&self) -> Duration {
        Duration::from_millis(self.event_deadline_ms)
    }

    /// spawn 之前的 fail-fast 校验（Exec-L2 启动门禁）。
    pub fn validate(&self) -> Result<(), OrgScopeProjectorConfigError> {
        if self.poll_interval_secs == 0 || self.poll_interval_secs > MAX_POLL_INTERVAL_SECS {
            return Err(OrgScopeProjectorConfigError::PollInterval {
                value: self.poll_interval_secs,
            });
        }
        if self.claim_lease_seconds <= 0 || self.claim_lease_seconds > MAX_CLAIM_LEASE_SECONDS {
            return Err(OrgScopeProjectorConfigError::ClaimLease {
                value: self.claim_lease_seconds,
            });
        }
        if self.max_event_attempts <= 0 || self.max_event_attempts > MAX_MAX_EVENT_ATTEMPTS {
            return Err(OrgScopeProjectorConfigError::MaxAttempts {
                value: self.max_event_attempts,
            });
        }
        if self.backoff_cap_seconds <= 0 || self.backoff_cap_seconds > MAX_BACKOFF_CAP_SECONDS {
            return Err(OrgScopeProjectorConfigError::BackoffCap {
                value: self.backoff_cap_seconds,
            });
        }
        if self.events_per_tenant_cycle == 0
            || self.events_per_tenant_cycle > MAX_EVENTS_PER_TENANT_CYCLE
        {
            return Err(OrgScopeProjectorConfigError::BatchPerTenant {
                value: self.events_per_tenant_cycle,
            });
        }
        if self.propagate_batch_limit <= 0 || self.propagate_batch_limit > MAX_PROPAGATE_BATCH_LIMIT
        {
            return Err(OrgScopeProjectorConfigError::PropagateBatchLimit {
                value: self.propagate_batch_limit,
            });
        }
        // deadline 必须在租约被夺之前给"尽力 durable 登记"留出余量。
        let max_deadline_ms = (self.claim_lease_seconds as u64).saturating_mul(1000);
        if self.event_deadline_ms < 100 || self.event_deadline_ms >= max_deadline_ms {
            return Err(OrgScopeProjectorConfigError::EventDeadline {
                value: self.event_deadline_ms,
                max: max_deadline_ms.saturating_sub(1),
            });
        }
        if self.tenants.is_empty() {
            return Err(OrgScopeProjectorConfigError::Tenants {
                reason: "list is empty; the durable consumer must not idle silently".to_owned(),
            });
        }
        if self.tenants.len() > MAX_ORG_SCOPE_TENANTS {
            return Err(OrgScopeProjectorConfigError::Tenants {
                reason: format!("list exceeds {MAX_ORG_SCOPE_TENANTS} tenants"),
            });
        }
        if let Some(value) = self.tenants.iter().find(|value| **value <= 0) {
            return Err(OrgScopeProjectorConfigError::Tenants {
                reason: format!("non-positive tenant id {value}"),
            });
        }
        let mut seen: Vec<i64> = Vec::with_capacity(self.tenants.len());
        for tenant in &self.tenants {
            if seen.contains(tenant) {
                return Err(OrgScopeProjectorConfigError::Tenants {
                    reason: format!("duplicate tenant id {tenant}"),
                });
            }
            seen.push(*tenant);
        }
        Ok(())
    }
}

/// 启动配置拒绝（spawn 前产生，无任何任务/持久/外部副作用）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OrgScopeProjectorConfigError {
    #[error("org scope projector tenants invalid: {reason}")]
    Tenants {
        /// The rejection reason.
        reason: String,
    },
    #[error(
        "org scope projector poll_interval_secs={value} must be within 1..={MAX_POLL_INTERVAL_SECS}"
    )]
    PollInterval {
        /// The offending configured value.
        value: u64,
    },
    #[error(
        "org scope projector claim_lease_seconds={value} must be within 1..={MAX_CLAIM_LEASE_SECONDS}"
    )]
    ClaimLease {
        /// The offending configured value.
        value: i64,
    },
    #[error(
        "org scope projector max_event_attempts={value} must be within 1..={MAX_MAX_EVENT_ATTEMPTS}"
    )]
    MaxAttempts {
        /// The offending configured value.
        value: i64,
    },
    #[error(
        "org scope projector backoff_cap_seconds={value} must be within 1..={MAX_BACKOFF_CAP_SECONDS}"
    )]
    BackoffCap {
        /// The offending configured value.
        value: i64,
    },
    #[error(
        "org scope projector events_per_tenant_cycle={value} must be within \
         1..={MAX_EVENTS_PER_TENANT_CYCLE}"
    )]
    BatchPerTenant {
        /// The offending configured value.
        value: usize,
    },
    #[error(
        "org scope projector propagate_batch_limit={value} must be within \
         1..={MAX_PROPAGATE_BATCH_LIMIT} (mirrors the repository per-batch validation; \
         the next frontier is always the singleton anchor, so no frontier cap applies)"
    )]
    PropagateBatchLimit {
        /// The offending configured value.
        value: i64,
    },
    #[error(
        "org scope projector event_deadline_ms={value} must be within 100..={max} \
         (strictly below the claim lease window)"
    )]
    EventDeadline {
        /// The offending configured value.
        value: u64,
        /// The inclusive upper bound derived from the claim lease.
        max: u64,
    },
    #[error("org scope projector env {name}={value:?} is not a valid number")]
    Parse {
        /// The offending environment variable name.
        name: &'static str,
        /// The raw offending value.
        value: String,
    },
    #[error(
        "org scope projector generated worker identity is invalid \
         (owner_bytes={owner_bytes}, token_hex_chars={token_hex_chars})"
    )]
    Identity {
        /// Generated owner length in bytes.
        owner_bytes: usize,
        /// Generated token hex length in chars.
        token_hex_chars: usize,
    },
}

/// 部署侧原始 env 快照（main 读取进程环境后传入；解析为纯函数，可单测）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OrgScopeProjectorEnvRaw {
    pub tenants: Option<String>,
    pub poll_interval_secs: Option<String>,
    pub claim_lease_seconds: Option<String>,
    pub max_event_attempts: Option<String>,
    pub backoff_cap_seconds: Option<String>,
    pub events_per_tenant_cycle: Option<String>,
    pub event_deadline_ms: Option<String>,
    pub propagate_batch_limit: Option<String>,
}

fn non_empty(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

/// 严格 tenant 列表解析：任一空白 token、非数字、非正数都是错误；出现任何
/// token 后列表不得为空；重复 id 保序去重。绝不 `filter_map(..ok())` 静默丢弃。
pub fn parse_org_scope_tenant_list(raw: &str) -> Result<Vec<i64>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("tenant list is empty".to_owned());
    }
    let mut tenants: Vec<i64> = Vec::new();
    for token in trimmed.split(',') {
        let token = token.trim();
        if token.is_empty() {
            return Err(format!("blank tenant token in {raw:?}"));
        }
        match token.parse::<i64>() {
            Ok(value) if value > 0 => {
                if !tenants.contains(&value) {
                    tenants.push(value);
                }
            }
            Ok(value) => return Err(format!("non-positive tenant id {value}")),
            Err(_) => return Err(format!("tenant token {token:?} is not a positive i64")),
        }
    }
    if tenants.len() > MAX_ORG_SCOPE_TENANTS {
        return Err(format!(
            "tenant list exceeds {MAX_ORG_SCOPE_TENANTS} tenants"
        ));
    }
    Ok(tenants)
}

/// 纯函数解析 env 快照 → 配置（缺失/空 = 契约默认；非法值一律启动错误）。
pub fn parse_org_scope_projector_config(
    raw: &OrgScopeProjectorEnvRaw,
) -> Result<OrgScopeProjectorConfig, OrgScopeProjectorConfigError> {
    let mut config = OrgScopeProjectorConfig::default();
    if let Some(value) = non_empty(raw.tenants.as_deref()) {
        config.tenants = parse_org_scope_tenant_list(&value)
            .map_err(|reason| OrgScopeProjectorConfigError::Tenants { reason })?;
    }
    if let Some(value) = non_empty(raw.poll_interval_secs.as_deref()) {
        config.poll_interval_secs =
            value
                .parse::<u64>()
                .map_err(|_| OrgScopeProjectorConfigError::Parse {
                    name: ENV_POLL_SECS,
                    value,
                })?;
    }
    if let Some(value) = non_empty(raw.claim_lease_seconds.as_deref()) {
        config.claim_lease_seconds =
            value
                .parse::<i64>()
                .map_err(|_| OrgScopeProjectorConfigError::Parse {
                    name: ENV_LEASE_SECS,
                    value,
                })?;
    }
    if let Some(value) = non_empty(raw.max_event_attempts.as_deref()) {
        config.max_event_attempts =
            value
                .parse::<i64>()
                .map_err(|_| OrgScopeProjectorConfigError::Parse {
                    name: ENV_MAX_ATTEMPTS,
                    value,
                })?;
    }
    if let Some(value) = non_empty(raw.backoff_cap_seconds.as_deref()) {
        config.backoff_cap_seconds =
            value
                .parse::<i64>()
                .map_err(|_| OrgScopeProjectorConfigError::Parse {
                    name: ENV_BACKOFF_CAP_SECS,
                    value,
                })?;
    }
    if let Some(value) = non_empty(raw.events_per_tenant_cycle.as_deref()) {
        config.events_per_tenant_cycle =
            value
                .parse::<usize>()
                .map_err(|_| OrgScopeProjectorConfigError::Parse {
                    name: ENV_BATCH_PER_TENANT,
                    value,
                })?;
    }
    if let Some(value) = non_empty(raw.event_deadline_ms.as_deref()) {
        config.event_deadline_ms =
            value
                .parse::<u64>()
                .map_err(|_| OrgScopeProjectorConfigError::Parse {
                    name: ENV_EVENT_DEADLINE_MS,
                    value,
                })?;
    }
    if let Some(value) = non_empty(raw.propagate_batch_limit.as_deref()) {
        config.propagate_batch_limit =
            value
                .parse::<i64>()
                .map_err(|_| OrgScopeProjectorConfigError::Parse {
                    name: ENV_PROPAGATE_BATCH_LIMIT,
                    value,
                })?;
    }
    config.validate()?;
    Ok(config)
}

// ─────────────────────────────────────────────────────────────────────────────
// worker 身份（stable run-scoped owner + 32 字节随机 lease token）
// ─────────────────────────────────────────────────────────────────────────────

/// 本 worker 一次运行的租约身份；owner 与 token 在整个 run 内稳定。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgScopeWorkerIdentity {
    /// 租约 owner（≤128 字节，`astral-db::validated_lease_owner` 字符集）。
    pub worker_owner: String,
    /// 64 位小写 hex（32 字节熵）；DB 只存 SHA-256 摘要，明文不入日志。
    pub worker_token_hex: String,
}

/// 小写 hex 编码（无外部依赖；结果与 `hex::encode` 逐字节一致）。
fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// `astral_db::validated_lease_owner` 的同界镜像（pub(crate) 不可见，此处只读
/// 复刻合同：1..=128 字节，ASCII 字母数字与 `-_.:/`）。
fn is_valid_lease_owner(value: &str) -> bool {
    !(value.is_empty() || value.len() > 128)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

/// `astral_db::decode_worker_token` 的同界镜像：64 位 hex ⇔ 32 字节熵。
fn is_valid_worker_token_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// 生成 run-scoped 身份：owner 稳定绑定 run_id；token 由两个 UUIDv4（各 16
/// 随机字节）拼成 32 字节熵再 hex 编码。UUIDv4 提供 122 位/枚随机度，合计
/// 244 位，远超租约 token 需求。
fn generate_org_scope_worker_identity(run_id: &str) -> OrgScopeWorkerIdentity {
    let mut token = [0u8; 32];
    let (left, right) = token.split_at_mut(16);
    left.copy_from_slice(&Uuid::new_v4().into_bytes());
    right.copy_from_slice(&Uuid::new_v4().into_bytes());
    OrgScopeWorkerIdentity {
        worker_owner: format!("org-scope-projector-{run_id}"),
        worker_token_hex: bytes_to_hex(&token),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 依赖缝（seam）：store 与 compiler
// ─────────────────────────────────────────────────────────────────────────────

/// 持久缝：worker 只依赖本 trait（claim/renew/load/fail/publish/complete/
/// propagate 七个原语）；生产装配经 blanket impl 绑定 [`OrgScopeRepository`]
/// （含 [`SqlxOrgScopeRepository`]），测试用脚本化 Fake 替换。worker 内没有、
/// 也绝不允许出现任何直接 SQL。
#[async_trait]
pub trait OrgProjectorStore: Send + Sync {
    async fn claim(
        &self,
        cmd: &OrgOutboxClaimCommand,
    ) -> Result<Option<OrgOutboxLease>, AstralError>;
    async fn renew(&self, cmd: &OrgOutboxRenewCommand) -> Result<bool, AstralError>;
    async fn load_input(
        &self,
        cmd: &OrgCompileInputCommand,
    ) -> Result<OrgCompileInput, AstralError>;
    async fn fail(&self, cmd: &OrgOutboxFailCommand) -> Result<OrgOutboxFailOutcome, AstralError>;
    async fn publish(&self, cmd: &OrgPublishCommand) -> Result<OrgPublishOutcome, AstralError>;
    /// kind-scoped 完成：repository 在同一事务内核对期望 kind 与租约后落
    /// durable DONE（非发布类事件的唯一成功形态）。
    async fn complete(
        &self,
        cmd: &OrgOutboxCompleteCommand,
    ) -> Result<OrgOutboxCompleteOutcome, AstralError>;
    /// 租约内按批推进子树传播（repository 保留当前 root 栅栏、意图绑定与
    /// 状态谓词幂等）。
    async fn propagate(
        &self,
        cmd: &OrgSubtreePropagateCommand,
    ) -> Result<OrgSubtreePropagateOutcome, AstralError>;
    /// Lease-bound dependency invalidation. Each batch advances only the generation
    /// of direct dependents and persists their publication trigger and child intent.
    async fn propagate_dependency(
        &self,
        cmd: &OrgDependencyPropagateCommand,
    ) -> Result<OrgDependencyPropagateOutcome, AstralError>;
}

#[async_trait]
impl<T: OrgScopeRepository + ?Sized> OrgProjectorStore for T {
    async fn claim(
        &self,
        cmd: &OrgOutboxClaimCommand,
    ) -> Result<Option<OrgOutboxLease>, AstralError> {
        OrgScopeRepository::claim_outbox_event(self, cmd).await
    }

    async fn renew(&self, cmd: &OrgOutboxRenewCommand) -> Result<bool, AstralError> {
        OrgScopeRepository::renew_outbox_lease(self, cmd).await
    }

    async fn load_input(
        &self,
        cmd: &OrgCompileInputCommand,
    ) -> Result<OrgCompileInput, AstralError> {
        OrgScopeRepository::load_compile_input(self, cmd).await
    }

    async fn fail(&self, cmd: &OrgOutboxFailCommand) -> Result<OrgOutboxFailOutcome, AstralError> {
        OrgScopeRepository::fail_outbox_event(self, cmd).await
    }

    async fn publish(&self, cmd: &OrgPublishCommand) -> Result<OrgPublishOutcome, AstralError> {
        OrgScopeRepository::complete_publish(self, cmd).await
    }

    async fn complete(
        &self,
        cmd: &OrgOutboxCompleteCommand,
    ) -> Result<OrgOutboxCompleteOutcome, AstralError> {
        OrgScopeRepository::complete_outbox_event(self, cmd).await
    }

    async fn propagate(
        &self,
        cmd: &OrgSubtreePropagateCommand,
    ) -> Result<OrgSubtreePropagateOutcome, AstralError> {
        OrgScopeRepository::propagate_subtree_root(self, cmd).await
    }

    async fn propagate_dependency(
        &self,
        cmd: &OrgDependencyPropagateCommand,
    ) -> Result<OrgDependencyPropagateOutcome, AstralError> {
        OrgScopeRepository::propagate_dependency_change(self, cmd).await
    }
}

/// 编译缝：worker 只依赖本 trait；生产装配绑定 [`OrgCompiler`]（全量 oracle；
/// worker 无 HotState，增量路径属后续切片）。测试用脚本化 Fake 替换。
pub trait OrgProjectorCompiler: Send + Sync {
    fn compile_full(&self, input: &OrgCompileInput) -> Result<OrgCompileOutcome, OrgError>;
}

impl OrgProjectorCompiler for OrgCompiler {
    fn compile_full(&self, input: &OrgCompileInput) -> Result<OrgCompileOutcome, OrgError> {
        // 显式限定固有方法，避免误递归进 trait impl 自身。
        OrgCompiler::compile_full(self, input)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 纯分类逻辑（可单测）
// ─────────────────────────────────────────────────────────────────────────────

/// 编译成功后的处置：发布或按未对账报告有界退避重试。
#[derive(Debug, Clone, PartialEq)]
pub enum CompileVerdict {
    /// Applied：渲染完成的待发布 publication（`to_publication` 已含合同校验）。
    Publish(OrgPublication),
    /// Pending：显式未对账集合；状态仅供诊断/落库，绝不进入发布。
    Pending { report: OrgPendingReport },
}

/// 将编译 outcome 分类为发布/退避/确定性错误：
/// - `Applied` → 渲染 publication（渲染失败属确定性合同错误，`Err` 上抛）；
/// - `Pending { report }` → [`CompileVerdict::Pending`]（可重试，预算耗尽落终态）。
fn classify_compile_outcome(outcome: OrgCompileOutcome) -> Result<CompileVerdict, OrgError> {
    match outcome {
        OrgCompileOutcome::Applied(state) => Ok(CompileVerdict::Publish(state.to_publication()?)),
        OrgCompileOutcome::Pending { report, .. } => Ok(CompileVerdict::Pending { report }),
    }
}

/// 失败登记策略：repository 侧错误全部按可重试有界退避（含租约内结构性
/// fail-closed 与发布期新鲜度校验——它们由 attempt 预算收敛为终态 FAILED）；
/// 只有编译器确定性合同错误直接终态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailureKind {
    Retryable,
    Terminal,
}

fn classify_repository_error(_error: &AstralError) -> FailureKind {
    // 策略显式化：repository 侧 Validation/Database/NotFound 一律可重试。
    // 依据：astral-db org_scope_repository 文档——输入结构 fail-closed 与发布
    // 期 stale 校验都要求 worker PENDING 重试；终态由 attempt 预算兜底。
    FailureKind::Retryable
}

/// 事件处理所处阶段（观测/日志/错误定位用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventStage {
    Load,
    Compile,
    Publish,
    Deadline,
    /// 事件 kind 分派（未知 kind 登记阶段）。
    Dispatch,
    /// MEMBERSHIP_CHANGED 非发布完成路径。
    Membership,
    /// SUBTREE_PROPAGATE bounded topology fan-out.
    Propagate,
    /// DEPENDENCY_PROPAGATE bounded generation-only fan-out.
    DependencyPropagate,
}

/// 单事件处理结果（纯数据；durable 终态以 repository 返回为准）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventOutcome {
    /// `complete_publish` 返回 Ok —— 发布类事件的唯一成功形态。
    Published,
    /// 非发布类事件经 kind-scoped complete durable 完成——与发布成功明确区分：
    /// 无 publication、无 generation 推进。
    Completed,
    /// 失败已 durable 登记为 PENDING 退避。
    RetryRecorded(EventStage),
    /// 失败已 durable 登记为终态 FAILED。
    TerminalFailed(EventStage),
    /// 租约丢失（被夺/过期）：放弃当次事件，零后续写入。
    LeaseLost(EventStage),
    /// fail_outbox_event 自身失败：durable 状态未知，必须 operator 对账。
    RecordUnknown(EventStage),
}

/// 截断到 512 字节（char boundary 安全），与 `astral-db` 的 last_error 列宽
/// 镜像一致；截断只是清理，durable 截断仍由 repository 兜底。
fn truncate_error_text(text: &str) -> String {
    const MAX: usize = 512;
    if text.len() <= MAX {
        return text.to_owned();
    }
    let mut cut = MAX;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text[..cut].to_owned()
}

/// Pending 报告 → 紧凑有界诊断文本（稳定机码 + 每码计数 + 首条 detail）。
fn summarize_pending_report(report: &OrgPendingReport) -> String {
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for item in &report.items {
        *counts.entry(item.code.as_machine_code()).or_default() += 1;
    }
    let joined = counts
        .iter()
        .map(|(code, count)| format!("{code}x{count}"))
        .collect::<Vec<_>>()
        .join(",");
    let first = report
        .items
        .first()
        .map(|item| format!("{};{}", item.code.as_machine_code(), item.detail))
        .unwrap_or_default();
    truncate_error_text(&format!(
        "code=org_scope.compile_pending;tenant={};generation={};items={joined};first={first}",
        report.tenant_id, report.generation
    ))
}

/// 租约丢失判定：匹配 `astral-db` worker 原语的稳定机器码。
fn is_lease_lost_error(error: &AstralError) -> bool {
    error.to_string().contains(LEASE_LOST_MACHINE_CODE)
}

/// 事件退避（秒）：按 durable attempt 值有界指数（1,2,4,8,...，封顶 cap）。
fn event_backoff_seconds(attempts: i64, cap_seconds: i64) -> i64 {
    let step = attempts.clamp(1, 32).unsigned_abs() as u32 - 1;
    let exponential = 2u64.saturating_pow(step);
    let cap = cap_seconds.max(1) as u64;
    exponential.min(cap) as i64
}

/// 周期级基础设施失败退避：1s 起步、按连续失败翻倍、硬上限 30s。
fn cycle_backoff_delay(consecutive_failures: u32) -> Duration {
    let multiplier = 2u64.saturating_pow(consecutive_failures.saturating_sub(1).min(5));
    Duration::from_secs(1)
        .saturating_mul(multiplier.min(CYCLE_BACKOFF_MAX_SECS) as u32)
        .min(Duration::from_secs(CYCLE_BACKOFF_MAX_SECS))
}

/// 处理耗时超过租约 1/3（至少 1s）时，在下一步前续租一次。
fn should_renew_lease(elapsed: Duration, claim_lease_seconds: i64) -> bool {
    let threshold = (claim_lease_seconds.max(1) as u64 / 3).max(1);
    elapsed.as_secs() >= threshold
}

/// 每轮租户轮询顺序（游标轮转，避免首租户饱和饿死后续租户）。
fn rotated_tenant_order(tenants: &[i64], cursor: usize) -> (Vec<i64>, usize) {
    if tenants.is_empty() {
        return (Vec::new(), 0);
    }
    let cursor = cursor % tenants.len();
    let ordered = (0..tenants.len())
        .map(|offset| tenants[(cursor + offset) % tenants.len()])
        .collect::<Vec<_>>();
    (ordered, (cursor + 1) % tenants.len())
}

// ─────────────────────────────────────────────────────────────────────────────
// 运行统计 / 取消 / handle / shutdown
// ─────────────────────────────────────────────────────────────────────────────

/// 累计运行统计（关闭时随 handle 一次性返回，供对账观测）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OrgScopeProjectorRunSummary {
    pub cycles: u64,
    pub claimed: u64,
    pub published: u64,
    /// 非发布类事件（MEMBERSHIP_CHANGED/SUBTREE_PROPAGATE）经 kind-scoped
    /// complete durable 完成的计数；与 `published` 严格区分，绝不互相折算。
    pub completed_without_publish: u64,
    pub pending_retries: u64,
    pub terminal_failed: u64,
    pub lease_lost: u64,
    pub record_unknown: u64,
    pub event_timeouts: u64,
    pub claim_errors: u64,
}

impl OrgScopeProjectorRunSummary {
    fn record_outcome(&mut self, outcome: &EventOutcome) {
        match outcome {
            EventOutcome::Published => self.published += 1,
            EventOutcome::Completed => self.completed_without_publish += 1,
            EventOutcome::RetryRecorded(_) => self.pending_retries += 1,
            EventOutcome::TerminalFailed(_) => self.terminal_failed += 1,
            EventOutcome::LeaseLost(_) => self.lease_lost += 1,
            EventOutcome::RecordUnknown(_) => self.record_unknown += 1,
        }
    }

    fn log_final(&self, run_id: &str) {
        tracing::info!(
            run_id = %run_id,
            cycles = self.cycles,
            claimed = self.claimed,
            published = self.published,
            completed_without_publish = self.completed_without_publish,
            pending_retries = self.pending_retries,
            terminal_failed = self.terminal_failed,
            lease_lost = self.lease_lost,
            record_unknown = self.record_unknown,
            event_timeouts = self.event_timeouts,
            claim_errors = self.claim_errors,
            "org scope projector final run summary"
        );
        if self.record_unknown > 0 {
            tracing::error!(
                run_id = %run_id,
                record_unknown = self.record_unknown,
                "org scope projector ended with UNKNOWN failure recordings; \
                 durable outbox state must be reconciled by an operator before retry"
            );
        }
    }
}

/// 本 worker 私有取消令牌（与 delegation expiry / archive worker 同一模式）：
/// `main` 与测试只见 `cancel()`；run 循环用 crate 内私有 wait/check seam。
#[derive(Clone, Debug, Default)]
pub struct OrgScopeProjectorCancellationToken {
    cancelled: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl OrgScopeProjectorCancellationToken {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        // notify_one retains a permit when cancellation races waiter setup.
        self.notify.notify_one();
    }

    async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        self.notify.notified().await;
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

/// Handle held by `main`; graceful shutdown cancels then joins with a bound.
/// Timeout, task panic and worker `Err` all surface explicitly.
#[derive(Debug)]
pub struct OrgScopeProjectorHandle {
    pub cancellation: OrgScopeProjectorCancellationToken,
    pub join: JoinHandle<Result<OrgScopeProjectorRunSummary, tokio::task::JoinError>>,
    /// The configured event deadline bounds an in-flight event during graceful
    /// shutdown; main derives a per-worker join budget from this frozen value.
    pub event_deadline: Duration,
    /// Run-scoped identifier used in logs; never stable across restarts and
    /// never usable as authorization identity.
    pub run_id: String,
}

/// Computes the bounded graceful-shutdown wait for one ORG projector. A healthy
/// worker may already be inside a configured event when cancellation arrives;
/// allow that event deadline plus the one best-effort durable failure-recording
/// margin, then still surface timeout/panic/Err as a process error.
pub fn org_scope_projector_shutdown_timeout(handle: &OrgScopeProjectorHandle) -> Duration {
    handle.event_deadline.saturating_add(Duration::from_secs(
        ORG_SCOPE_SHUTDOWN_FAILURE_RECORDING_GRACE_SECS,
    ))
}

#[derive(Debug)]
pub struct OrgScopeProjectorShutdownReport {
    pub summary: Result<OrgScopeProjectorRunSummary, String>,
    pub join_elapsed: Duration,
}

/// Cancel the worker and await termination within a bounded timeout.
///
/// `Err(summary)` forms cover: worker panic/join failure, propagated worker
/// `Err`, timeout. A dying or stuck worker can never be reported as a clean
/// shutdown — the caller turns non-clean shutdowns into process errors.
pub async fn shutdown_org_scope_projector(
    handle: OrgScopeProjectorHandle,
    timeout: Duration,
) -> OrgScopeProjectorShutdownReport {
    handle.cancellation.cancel();
    let started = Instant::now();
    let summary = match tokio::time::timeout(timeout, handle.join).await {
        Ok(joined) => match joined {
            Ok(Ok(summary)) => Ok(summary),
            Ok(Err(join_error)) => Err(format!("worker task failed: {join_error}")),
            Err(_) => Err("shutdown summary unavailable".to_owned()),
        },
        Err(_) => Err(format!(
            "org scope projector worker did not stop within {timeout:?}; possibly \
             wedged inside a repository transaction"
        )),
    };
    tracing::info!(
        run_id = %handle.run_id,
        join_elapsed_ms = started.elapsed().as_millis() as u64,
        clean = summary.is_ok(),
        "org scope projector worker shutdown completed"
    );
    OrgScopeProjectorShutdownReport {
        summary,
        join_elapsed: started.elapsed(),
    }
}

/// Start one owned ORG_SCOPE outbox projector bound to the production
/// repository. The caller MUST keep the handle and invoke
/// [`shutdown_org_scope_projector`] during shutdown.
///
/// # Errors
/// Returns [`OrgScopeProjectorConfigError`] without spawning any task and
/// without touching the repository when `config` fails validation.
pub fn start_org_scope_projector(
    repository: Arc<SqlxOrgScopeRepository>,
    config: OrgScopeProjectorConfig,
) -> Result<OrgScopeProjectorHandle, OrgScopeProjectorConfigError> {
    let store: Arc<dyn OrgProjectorStore> = repository;
    start_org_scope_projector_with_runtime(store, Arc::new(OrgCompiler::new()), config)
}

/// Start one owned projector on the supplied seams（测试/Fake 入口）。
///
/// # Errors
/// Returns [`OrgScopeProjectorConfigError`] without spawning any task（supplied
/// seams 完全不被触碰）when `config` fails validation.
pub fn start_org_scope_projector_with_runtime(
    store: Arc<dyn OrgProjectorStore>,
    compiler: Arc<dyn OrgProjectorCompiler>,
    config: OrgScopeProjectorConfig,
) -> Result<OrgScopeProjectorHandle, OrgScopeProjectorConfigError> {
    config.validate()?;
    let run_id = Uuid::new_v4().to_string();
    let identity = generate_org_scope_worker_identity(&run_id);
    if !is_valid_lease_owner(&identity.worker_owner)
        || !is_valid_worker_token_hex(&identity.worker_token_hex)
    {
        return Err(OrgScopeProjectorConfigError::Identity {
            owner_bytes: identity.worker_owner.len(),
            token_hex_chars: identity.worker_token_hex.len(),
        });
    }
    let cancellation = OrgScopeProjectorCancellationToken::default();
    let run_cancellation = cancellation.clone();
    let event_deadline = config.event_deadline();
    let join = tokio::spawn(run_worker(
        store,
        compiler,
        config,
        identity,
        run_id.clone(),
        run_cancellation,
    ));
    Ok(OrgScopeProjectorHandle {
        cancellation,
        join,
        event_deadline,
        run_id,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// run loop
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CycleHealth {
    /// 本轮至少处理一条事件：立即开始下一轮（每条事件本身都是真实 DB 工作，
    /// 且每租户每轮有 drain 上限，不会无界放大）。
    Busy,
    /// 全部租户无可 claim 事件：按轮询间隔等待。
    Idle,
    /// claim 基础设施失败：按连续失败有界退避。
    InfraError,
}

fn next_cycle_wait(
    health: CycleHealth,
    consecutive_infra_failures: u32,
    poll_interval: Duration,
) -> Duration {
    match health {
        CycleHealth::Busy => Duration::ZERO,
        CycleHealth::Idle => poll_interval,
        CycleHealth::InfraError => cycle_backoff_delay(consecutive_infra_failures),
    }
}

async fn wait_or_cancel(cancellation: &OrgScopeProjectorCancellationToken, duration: Duration) {
    tokio::select! {
        _ = cancellation.cancelled() => {}
        _ = tokio::time::sleep(duration) => {}
    }
}

async fn run_worker(
    store: Arc<dyn OrgProjectorStore>,
    compiler: Arc<dyn OrgProjectorCompiler>,
    config: OrgScopeProjectorConfig,
    identity: OrgScopeWorkerIdentity,
    run_id: String,
    cancellation: OrgScopeProjectorCancellationToken,
) -> Result<OrgScopeProjectorRunSummary, tokio::task::JoinError> {
    let mut summary = OrgScopeProjectorRunSummary::default();
    let mut consecutive_infra_failures: u32 = 0;
    let mut tenant_cursor: usize = 0;
    let poll_interval = Duration::from_secs(config.poll_interval_secs);
    tracing::info!(
        run_id = %run_id,
        tenants = ?config.tenants,
        poll_interval_secs = config.poll_interval_secs,
        claim_lease_seconds = config.claim_lease_seconds,
        max_event_attempts = config.max_event_attempts,
        backoff_cap_seconds = config.backoff_cap_seconds,
        events_per_tenant_cycle = config.events_per_tenant_cycle,
        event_deadline_ms = config.event_deadline_ms,
        propagate_batch_limit = config.propagate_batch_limit,
        "org scope projector worker loop started; identity owner is run-scoped, \
         lease token is 32 random bytes stored only as a SHA-256 digest"
    );
    loop {
        if cancellation.is_cancelled() {
            tracing::info!(run_id = %run_id, "org scope projector worker stopped");
            break;
        }
        summary.cycles += 1;
        let mut busy = false;
        let mut infra_error = false;
        let (ordered_tenants, next_cursor) = rotated_tenant_order(&config.tenants, tenant_cursor);
        tenant_cursor = next_cursor;
        'tenants: for tenant_id in ordered_tenants {
            for _ in 0..config.events_per_tenant_cycle {
                if cancellation.is_cancelled() {
                    break 'tenants;
                }
                let claim_cmd = OrgOutboxClaimCommand {
                    tenant_id,
                    worker_owner: identity.worker_owner.clone(),
                    worker_token_hex: identity.worker_token_hex.clone(),
                    lease_seconds: config.claim_lease_seconds,
                    // claim 侧预算收敛：与 fail 侧同一预算。worker 在 claim 后
                    // 崩溃时，过期租约回收达到预算即由 repository 在 claim 事务
                    // 内落终态 FAILED（claim 返回 Ok(None)），绝不无限回收。
                    max_attempts: config.max_event_attempts,
                };
                match store.claim(&claim_cmd).await {
                    Ok(None) => break,
                    Ok(Some(lease)) => {
                        busy = true;
                        summary.claimed += 1;
                        let (outcome, timed_out) =
                            process_claimed_event(&*store, &*compiler, &config, &identity, lease)
                                .await;
                        if timed_out {
                            summary.event_timeouts += 1;
                        }
                        summary.record_outcome(&outcome);
                    }
                    Err(error) => {
                        summary.claim_errors += 1;
                        tracing::error!(
                            run_id = %run_id,
                            tenant_id,
                            consecutive_infra_failures = consecutive_infra_failures + 1,
                            error = %error,
                            "org scope projector claim failed against the repository"
                        );
                        infra_error = true;
                        break 'tenants;
                    }
                }
            }
        }
        let health = if infra_error {
            CycleHealth::InfraError
        } else if busy {
            CycleHealth::Busy
        } else {
            CycleHealth::Idle
        };
        if infra_error {
            consecutive_infra_failures = consecutive_infra_failures.saturating_add(1);
        } else {
            consecutive_infra_failures = 0;
        }
        wait_or_cancel(
            &cancellation,
            next_cycle_wait(health, consecutive_infra_failures, poll_interval),
        )
        .await;
    }
    summary.log_final(&run_id);
    Ok(summary)
}

/// 处理一条已认领事件，整体受单事件 deadline 约束：任何一步挂起都必须在
/// deadline 内变成"计数 + 尽力 durable 登记 + 继续循环"。被 drop 的未来若正
/// 处于 repository 短事务内，由事务原子性整体回滚，绝不留下部分状态。
/// 返回 `(outcome, timed_out)`；`timed_out` 仅供 summary 计数。
async fn process_claimed_event(
    store: &dyn OrgProjectorStore,
    compiler: &dyn OrgProjectorCompiler,
    config: &OrgScopeProjectorConfig,
    identity: &OrgScopeWorkerIdentity,
    lease: OrgOutboxLease,
) -> (EventOutcome, bool) {
    let started = Instant::now();
    let deadline = config.event_deadline();
    match tokio::time::timeout(
        deadline,
        process_claimed_event_inner(store, compiler, config, identity, &lease, started),
    )
    .await
    {
        Ok(outcome) => (outcome, false),
        Err(_) => {
            tracing::warn!(
                org_event_id = lease.org_event_id,
                event_id = %lease.event_id,
                operation_id = %lease.operation_id,
                deadline_ms = deadline.as_millis() as u64,
                "org scope projector event processing exceeded its deadline; \
                 recording a durable retry and moving on"
            );
            let outcome = record_failure_and_map(
                store,
                config,
                identity,
                &lease,
                EventStage::Deadline,
                FailureKind::Retryable,
                &format!(
                    "{EVENT_DEADLINE_MACHINE_CODE};deadline_ms={};event_id={}",
                    deadline.as_millis(),
                    lease.event_id
                ),
            )
            .await;
            (outcome, true)
        }
    }
}

async fn process_claimed_event_inner(
    store: &dyn OrgProjectorStore,
    compiler: &dyn OrgProjectorCompiler,
    config: &OrgScopeProjectorConfig,
    identity: &OrgScopeWorkerIdentity,
    lease: &OrgOutboxLease,
    started: Instant,
) -> EventOutcome {
    // 1. 编译/装载耗时可能逼近租约窗口：超过租约 1/3 先续租（失败即失去
    //    所有权，立即放弃，零后续写入）。
    if should_renew_lease(started.elapsed(), config.claim_lease_seconds)
        && !renew_lease(store, identity, lease, config.claim_lease_seconds).await
    {
        return EventOutcome::LeaseLost(EventStage::Load);
    }

    // 2. 事件分派：kind 决定处理路径。未知 kind 按可重试有界退避登记（滚动
    //    升级窗口内新 kind 由 attempt 预算收敛为终态 FAILED），绝不发布、绝不
    //    complete；kind 解析面收敛于 [`parse_outbox_event_kind`]。
    let kind = match parse_outbox_event_kind(&lease.event_kind) {
        Some(kind) => kind,
        None => {
            return record_failure_and_map(
                store,
                config,
                identity,
                lease,
                EventStage::Dispatch,
                FailureKind::Retryable,
                &format!(
                    "{UNKNOWN_EVENT_KIND_MACHINE_CODE};event_kind={}",
                    lease.event_kind
                ),
            )
            .await;
        }
    };
    match kind {
        OrgOutboxEventKind::NodeCreated
        | OrgOutboxEventKind::NodeTopologyChanged
        | OrgOutboxEventKind::NodeMutated
        | OrgOutboxEventKind::GrantIssued
        | OrgOutboxEventKind::GrantRevoked
        | OrgOutboxEventKind::MaskApplied
        | OrgOutboxEventKind::MaskRemoved => {
            process_publication_event(store, compiler, config, identity, lease, started).await
        }
        OrgOutboxEventKind::MembershipChanged => {
            process_membership_event(store, config, identity, lease).await
        }
        OrgOutboxEventKind::SubtreePropagate => {
            process_subtree_propagate_event(store, config, identity, lease, started).await
        }
        OrgOutboxEventKind::DependencyPropagate => {
            process_dependency_propagate_event(store, config, identity, lease, started).await
        }
    }
}

/// outbox `event_kind` 字符串 → typed kind；未知 kind 返回 None。解析调用收敛
/// 于此一处，便于对齐 `astral-db` 公开 API 的具体形态。
fn parse_outbox_event_kind(raw: &str) -> Option<OrgOutboxEventKind> {
    raw.parse::<OrgOutboxEventKind>().ok()
}

/// 发布类事件（NODE_*/GRANT_*/MASK_*）既有主路径：租约内装载 → 纯编译 →
/// 原子发布。outbox payload 仅作诊断，绝不从它推导授权事实。
async fn process_publication_event(
    store: &dyn OrgProjectorStore,
    compiler: &dyn OrgProjectorCompiler,
    config: &OrgScopeProjectorConfig,
    identity: &OrgScopeWorkerIdentity,
    lease: &OrgOutboxLease,
    started: Instant,
) -> EventOutcome {
    // 1. 租约内装载已批准事实快照（repository 内部短事务；租约/过期全检）。
    let input = match store
        .load_input(&OrgCompileInputCommand {
            org_event_id: lease.org_event_id,
            worker_owner: identity.worker_owner.clone(),
            worker_token_hex: identity.worker_token_hex.clone(),
        })
        .await
    {
        Ok(input) => input,
        Err(error) if is_lease_lost_error(&error) => {
            tracing::warn!(
                org_event_id = lease.org_event_id,
                event_id = %lease.event_id,
                "org scope projector lost the lease while loading compile input; \
                 abandoning the event without further writes"
            );
            return EventOutcome::LeaseLost(EventStage::Load);
        }
        Err(error) => {
            return record_failure_and_map(
                store,
                config,
                identity,
                lease,
                EventStage::Load,
                classify_repository_error(&error),
                &error.to_string(),
            )
            .await;
        }
    };

    // 2. 纯编译，运行在任何事务之外（全量 oracle；无 I/O、无副作用）。
    let publication = match compiler.compile_full(&input) {
        Ok(outcome) => match classify_compile_outcome(outcome) {
            Ok(CompileVerdict::Publish(publication)) => publication,
            Ok(CompileVerdict::Pending { report }) => {
                // 显式未对账：绝不发布，按可重试失败有界退避（预算耗尽由
                // repository 落终态 FAILED）。
                return record_failure_and_map(
                    store,
                    config,
                    identity,
                    lease,
                    EventStage::Compile,
                    FailureKind::Retryable,
                    &summarize_pending_report(&report),
                )
                .await;
            }
            Err(error) => {
                // 渲染失败属确定性合同错误：终态 FAILED。
                return record_failure_and_map(
                    store,
                    config,
                    identity,
                    lease,
                    EventStage::Compile,
                    FailureKind::Terminal,
                    &error.to_string(),
                )
                .await;
            }
        },
        Err(error) => {
            // 编译器 Err = 确定性合同破坏（如 ParentNotDelegable / 结构校验）：
            // 相同事实重放只会得到相同错误，直接 durable 终态，等待 operator
            // 或新 source 事件（会入队新事件）介入。
            return record_failure_and_map(
                store,
                config,
                identity,
                lease,
                EventStage::Compile,
                FailureKind::Terminal,
                &error.to_string(),
            )
            .await;
        }
    };

    // 3. 发布前再次续租（编译可能已耗去大半租约窗口）。
    if should_renew_lease(started.elapsed(), config.claim_lease_seconds)
        && !renew_lease(store, identity, lease, config.claim_lease_seconds).await
    {
        return EventOutcome::LeaseLost(EventStage::Publish);
    }

    // 4. 原子发布（repository 内部单事务：sealed publication/segments/dependency
    //    pins + current generation CAS + 事件终态 + 审计；source/dependency
    //    新鲜度与租约在事务内全检）。
    match store
        .publish(&OrgPublishCommand {
            org_event_id: lease.org_event_id,
            worker_owner: identity.worker_owner.clone(),
            worker_token_hex: identity.worker_token_hex.clone(),
            publication,
        })
        .await
    {
        Ok(outcome) => {
            tracing::info!(
                org_event_id = lease.org_event_id,
                event_id = %lease.event_id,
                operation_id = %lease.operation_id,
                publication_id = outcome.publication_id,
                generation = outcome.generation,
                cas_version = outcome.cas_version,
                "org scope projector published a sealed org publication"
            );
            EventOutcome::Published
        }
        Err(error) if is_lease_lost_error(&error) => {
            tracing::warn!(
                org_event_id = lease.org_event_id,
                event_id = %lease.event_id,
                "org scope projector lost the lease before publish could commit; \
                 abandoning the event without further writes"
            );
            EventOutcome::LeaseLost(EventStage::Publish)
        }
        Err(error) => {
            // stale source / generation conflict / DB 故障等：有界退避重试；
            // 下一次 attempt 会以新鲜输入重新编译发布。
            record_failure_and_map(
                store,
                config,
                identity,
                lease,
                EventStage::Publish,
                classify_repository_error(&error),
                &error.to_string(),
            )
            .await
        }
    }
}

/// MEMBERSHIP_CHANGED：成员资格是独立版本化事实，准入读路径 fresh-check
/// membership，不需要重编译/发布；租约内完成 kind-scoped 终态即可。worker 是
/// 纯编排者：解析/校验/租户绑定失败（确定性合同破坏）经既有 fail 路径落终态
/// FAILED；complete 的 repository 侧错误按可重试有界退避；租约丢失零后续写入。
async fn process_membership_event(
    store: &dyn OrgProjectorStore,
    config: &OrgScopeProjectorConfig,
    identity: &OrgScopeWorkerIdentity,
    lease: &OrgOutboxLease,
) -> EventOutcome {
    let membership: OrgMembership = match serde_json::from_str(&lease.payload_json) {
        Ok(membership) => membership,
        Err(error) => {
            return record_failure_and_map(
                store,
                config,
                identity,
                lease,
                EventStage::Membership,
                FailureKind::Terminal,
                &format!("{MEMBERSHIP_PAYLOAD_INVALID_MACHINE_CODE};detail={error}"),
            )
            .await;
        }
    };
    if let Err(error) = membership.validate() {
        return record_failure_and_map(
            store,
            config,
            identity,
            lease,
            EventStage::Membership,
            FailureKind::Terminal,
            &format!("{MEMBERSHIP_PAYLOAD_INVALID_MACHINE_CODE};detail={error}"),
        )
        .await;
    }
    // 租户绑定：payload 声明的成员资格租户必须等于租约租户（outbox 行租户），
    // 否则视为跨租户污染企图，确定性终态，绝不 complete。
    if membership.tenant_id != lease.tenant_id {
        return record_failure_and_map(
            store,
            config,
            identity,
            lease,
            EventStage::Membership,
            FailureKind::Terminal,
            &format!(
                "{MEMBERSHIP_TENANT_MISMATCH_MACHINE_CODE};payload_tenant={};lease_tenant={}",
                membership.tenant_id, lease.tenant_id
            ),
        )
        .await;
    }
    complete_event(
        store,
        config,
        identity,
        lease,
        OrgOutboxEventKind::MembershipChanged,
        EventStage::Membership,
    )
    .await
}

/// SUBTREE_PROPAGATE（锚点扇出）：MOVE/DETACH 后代 root 推进。载荷只声明
/// 意图（child/new_root/relationship revision），本事件只拥有载荷 child 这
/// **一个锚点**；真实推进由 repository 在租约内按批执行——每批只推进锚点的
/// **直接** active 陈旧子节点至多 `batch_limit` 个，并为每个被推进子节点原子
/// 派生新的 typed child intent（后代由各自事件继续，worker 不做 BFS），
/// 并在事务内绑定锁定 outbox 行的 operation/payload/root/revision 栅栏事实。
/// `done=false` 时下一前沿必须精确等于 `[锚点]`（同一事件重入排空剩余直系
/// 兄弟），否则为合同不一致 → 稳定机码有界重试，绝不改道重定向、绝不无限
/// 循环（事件 deadline 与 attempt 预算共同兜底有界性）。`done=true`（锚点
/// 直系兄弟排空）或 `superseded=true`（repository 证实意图已被更新拓扑变更
/// 取代的安全无写放行）才 kind-scoped complete。绝不发布。
async fn process_subtree_propagate_event(
    store: &dyn OrgProjectorStore,
    config: &OrgScopeProjectorConfig,
    identity: &OrgScopeWorkerIdentity,
    lease: &OrgOutboxLease,
    started: Instant,
) -> EventOutcome {
    let payload: OrgSubtreePropagatePayload = match serde_json::from_str(&lease.payload_json) {
        Ok(payload) => payload,
        Err(error) => {
            return record_failure_and_map(
                store,
                config,
                identity,
                lease,
                EventStage::Propagate,
                FailureKind::Terminal,
                &format!("{PROPAGATE_PAYLOAD_INVALID_MACHINE_CODE};detail={error}"),
            )
            .await;
        }
    };
    if let Err(error) = payload.validate() {
        return record_failure_and_map(
            store,
            config,
            identity,
            lease,
            EventStage::Propagate,
            FailureKind::Terminal,
            &format!("{PROPAGATE_PAYLOAD_INVALID_MACHINE_CODE};detail={error}"),
        )
        .await;
    }
    // 租户绑定：意图必须属于租约租户（outbox 行租户）；陈旧/错投的传播意图
    // 绝不能驱动本 worker 推进其他租户的 root。
    if payload.child_tenant_id != lease.tenant_id {
        return record_failure_and_map(
            store,
            config,
            identity,
            lease,
            EventStage::Propagate,
            FailureKind::Terminal,
            &format!(
                "{PROPAGATE_TENANT_MISMATCH_MACHINE_CODE};payload_child={};lease_tenant={}",
                payload.child_tenant_id, lease.tenant_id
            ),
        )
        .await;
    }

    // 锚点扇出：本事件只拥有载荷 child 这一个锚点；每批都以同一锚点重入，
    // 由 repository 在租约内推进其直接陈旧子节点并派生 child intent。
    let anchor = payload.child_tenant_id;
    loop {
        // 每批都是一次独立的 repository 事务：超过租约 1/3 先续租（失败即失去
        // 所有权，立即放弃，零后续写入——包括 complete）。
        if should_renew_lease(started.elapsed(), config.claim_lease_seconds)
            && !renew_lease(store, identity, lease, config.claim_lease_seconds).await
        {
            return EventOutcome::LeaseLost(EventStage::Propagate);
        }
        let command = OrgSubtreePropagateCommand {
            org_event_id: lease.org_event_id,
            worker_owner: identity.worker_owner.clone(),
            worker_token_hex: identity.worker_token_hex.clone(),
            expected_kind: OrgOutboxEventKind::SubtreePropagate,
            operation_id: lease.operation_id.clone(),
            new_root_tenant_id: payload.new_root_tenant_id,
            frontier: vec![anchor],
            batch_limit: config.propagate_batch_limit,
        };
        match store.propagate(&command).await {
            Ok(outcome) => {
                if outcome.superseded {
                    // 意图已被取代：repository 在锁内核实（锚点 relationship
                    // revision 大于载荷 revision）后的安全无写放行。按合同做
                    // kind 限定的无发布完成，绝不以本意图再写后代或重试本批
                    // （更新的意图必然已由该 source 变更入队）；worker 绝不从
                    // payload 本地推断意图新鲜度。
                    tracing::info!(
                        org_event_id = lease.org_event_id,
                        event_id = %lease.event_id,
                        anchor_tenant_id = anchor,
                        "org scope projector observed a repository-proven superseded \
                         subtree propagate intent; completing without publication"
                    );
                    return complete_event(
                        store,
                        config,
                        identity,
                        lease,
                        OrgOutboxEventKind::SubtreePropagate,
                        EventStage::Propagate,
                    )
                    .await;
                }
                if outcome.done {
                    // 传播 durable 完成（锚点直系陈旧子节点已排空；repository
                    // 已在同一事务落 NODE 账/child intent/审计）：此时才允许
                    // kind-scoped 终态。
                    return complete_event(
                        store,
                        config,
                        identity,
                        lease,
                        OrgOutboxEventKind::SubtreePropagate,
                        EventStage::Propagate,
                    )
                    .await;
                }
                // 锚点扇出合同：done=false 时下一前沿必须精确等于 [锚点]
                //（同一事件重入排空剩余直系兄弟）。空前沿、异值或多元素都是
                // 合同不一致：绝不改道/重定向本事件，按稳定机码有界重试
                // （attempt 预算收敛终态），绝不无限循环。
                if outcome.next_frontier.as_slice() != [anchor] {
                    return record_failure_and_map(
                        store,
                        config,
                        identity,
                        lease,
                        EventStage::Propagate,
                        FailureKind::Retryable,
                        &format!(
                            "{PROPAGATE_FRONTIER_INCONSISTENT_MACHINE_CODE};detail=propagate \
                             returned a non-done next frontier other than [anchor];\
                             next_frontier={:?};anchor={}",
                            outcome.next_frontier, anchor
                        ),
                    )
                    .await;
                }
            }
            Err(error) if is_lease_lost_error(&error) => {
                tracing::warn!(
                    org_event_id = lease.org_event_id,
                    event_id = %lease.event_id,
                    "org scope projector lost the lease while propagating the subtree; \
                     abandoning the event without further writes"
                );
                return EventOutcome::LeaseLost(EventStage::Propagate);
            }
            Err(error) => {
                // stale intent / root fence conflict / DB 故障等：worker 只是
                // 编排者，意图新鲜度由 repository 事务内判定；此处按既有有界
                // 重试登记，下一次 attempt 以同一意图重新驱动。
                return record_failure_and_map(
                    store,
                    config,
                    identity,
                    lease,
                    EventStage::Propagate,
                    classify_repository_error(&error),
                    &error.to_string(),
                )
                .await;
            }
        }
    }
}

/// DEPENDENCY_PROPAGATE invalidates direct dependents of a current publication pin.
/// Each repository batch advances only generation, then atomically persists a normal
/// publication event and a child dependency intent. The worker never compiles or
/// publishes from this event; its bounded batches only create durable work.
async fn process_dependency_propagate_event(
    store: &dyn OrgProjectorStore,
    config: &OrgScopeProjectorConfig,
    identity: &OrgScopeWorkerIdentity,
    lease: &OrgOutboxLease,
    started: Instant,
) -> EventOutcome {
    let payload: OrgDependencyPropagatePayload = match serde_json::from_str(&lease.payload_json) {
        Ok(payload) => payload,
        Err(error) => {
            return record_failure_and_map(
                store,
                config,
                identity,
                lease,
                EventStage::DependencyPropagate,
                FailureKind::Terminal,
                &format!("{DEPENDENCY_PROPAGATE_PAYLOAD_INVALID_MACHINE_CODE};detail={error}"),
            )
            .await;
        }
    };
    if let Err(error) = payload.validate() {
        return record_failure_and_map(
            store,
            config,
            identity,
            lease,
            EventStage::DependencyPropagate,
            FailureKind::Terminal,
            &format!("{DEPENDENCY_PROPAGATE_PAYLOAD_INVALID_MACHINE_CODE};detail={error}"),
        )
        .await;
    }
    if payload.anchor_tenant_id != lease.tenant_id {
        return record_failure_and_map(
            store,
            config,
            identity,
            lease,
            EventStage::DependencyPropagate,
            FailureKind::Terminal,
            &format!(
                "{DEPENDENCY_PROPAGATE_TENANT_MISMATCH_MACHINE_CODE};payload_anchor={};lease_tenant={}",
                payload.anchor_tenant_id, lease.tenant_id
            ),
        )
        .await;
    }

    loop {
        if should_renew_lease(started.elapsed(), config.claim_lease_seconds)
            && !renew_lease(store, identity, lease, config.claim_lease_seconds).await
        {
            return EventOutcome::LeaseLost(EventStage::DependencyPropagate);
        }
        let command = OrgDependencyPropagateCommand {
            org_event_id: lease.org_event_id,
            worker_owner: identity.worker_owner.clone(),
            worker_token_hex: identity.worker_token_hex.clone(),
            expected_kind: OrgOutboxEventKind::DependencyPropagate,
            operation_id: lease.operation_id.clone(),
            anchor_tenant_id: payload.anchor_tenant_id,
            batch_limit: config.propagate_batch_limit,
        };
        match store.propagate_dependency(&command).await {
            Ok(outcome) => {
                if outcome.superseded {
                    if !outcome.done || !outcome.updated_tenant_ids.is_empty() {
                        return record_failure_and_map(
                            store,
                            config,
                            identity,
                            lease,
                            EventStage::DependencyPropagate,
                            FailureKind::Retryable,
                            &format!(
                                "{DEPENDENCY_PROPAGATE_PROGRESS_INCONSISTENT_MACHINE_CODE};superseded=true;done={};updated={:?}",
                                outcome.done, outcome.updated_tenant_ids
                            ),
                        )
                        .await;
                    }
                    tracing::info!(
                        org_event_id = lease.org_event_id,
                        event_id = %lease.event_id,
                        anchor_tenant_id = payload.anchor_tenant_id,
                        "org scope projector observed a repository-proven superseded dependency intent"
                    );
                    return complete_event(
                        store,
                        config,
                        identity,
                        lease,
                        OrgOutboxEventKind::DependencyPropagate,
                        EventStage::DependencyPropagate,
                    )
                    .await;
                }

                let updated_count = outcome.updated_tenant_ids.len();
                let has_invalid_ids = outcome
                    .updated_tenant_ids
                    .iter()
                    .any(|tenant_id| *tenant_id <= 0)
                    || outcome
                        .updated_tenant_ids
                        .windows(2)
                        .any(|pair| pair[0] >= pair[1]);
                let progress_valid = !has_invalid_ids
                    && updated_count <= config.propagate_batch_limit as usize
                    && if outcome.done {
                        (updated_count as i64) < config.propagate_batch_limit
                    } else {
                        (updated_count as i64) == config.propagate_batch_limit
                    };
                if !progress_valid {
                    return record_failure_and_map(
                        store,
                        config,
                        identity,
                        lease,
                        EventStage::DependencyPropagate,
                        FailureKind::Retryable,
                        &format!(
                            "{DEPENDENCY_PROPAGATE_PROGRESS_INCONSISTENT_MACHINE_CODE};done={};updated={:?};limit={}",
                            outcome.done, outcome.updated_tenant_ids, config.propagate_batch_limit
                        ),
                    )
                    .await;
                }
                if outcome.done {
                    return complete_event(
                        store,
                        config,
                        identity,
                        lease,
                        OrgOutboxEventKind::DependencyPropagate,
                        EventStage::DependencyPropagate,
                    )
                    .await;
                }
            }
            Err(error) if is_lease_lost_error(&error) => {
                tracing::warn!(
                    org_event_id = lease.org_event_id,
                    event_id = %lease.event_id,
                    "org scope projector lost the lease while propagating dependencies; abandoning without further writes"
                );
                return EventOutcome::LeaseLost(EventStage::DependencyPropagate);
            }
            Err(error) => {
                return record_failure_and_map(
                    store,
                    config,
                    identity,
                    lease,
                    EventStage::DependencyPropagate,
                    classify_repository_error(&error),
                    &error.to_string(),
                )
                .await;
            }
        }
    }
}

async fn complete_event(
    store: &dyn OrgProjectorStore,
    config: &OrgScopeProjectorConfig,
    identity: &OrgScopeWorkerIdentity,
    lease: &OrgOutboxLease,
    expected_kind: OrgOutboxEventKind,
    stage: EventStage,
) -> EventOutcome {
    match store
        .complete(&OrgOutboxCompleteCommand {
            org_event_id: lease.org_event_id,
            worker_owner: identity.worker_owner.clone(),
            worker_token_hex: identity.worker_token_hex.clone(),
            expected_kind,
        })
        .await
    {
        Ok(_) => {
            tracing::info!(
                org_event_id = lease.org_event_id,
                event_id = %lease.event_id,
                operation_id = %lease.operation_id,
                event_kind = ?expected_kind,
                "org scope projector completed an event without publication; no \
                 publication or generation advance was produced"
            );
            EventOutcome::Completed
        }
        Err(error) if is_lease_lost_error(&error) => {
            tracing::warn!(
                org_event_id = lease.org_event_id,
                event_id = %lease.event_id,
                "org scope projector lost the lease before the non-publication complete \
                 could commit; abandoning the event without further writes"
            );
            EventOutcome::LeaseLost(stage)
        }
        Err(error) => {
            // kind 不匹配/租约内校验失败/DB 故障等：按既有有界退避重试；attempt
            // 预算收敛终态。
            record_failure_and_map(
                store,
                config,
                identity,
                lease,
                stage,
                classify_repository_error(&error),
                &error.to_string(),
            )
            .await
        }
    }
}

/// 续租辅助：Ok(false)/Err(lease lost)/其他 Err 统一返回 false——续租失败即
/// 保守认定所有权已失，绝不带着未证明的租约继续发布。
async fn renew_lease(
    store: &dyn OrgProjectorStore,
    identity: &OrgScopeWorkerIdentity,
    lease: &OrgOutboxLease,
    lease_seconds: i64,
) -> bool {
    match store
        .renew(&OrgOutboxRenewCommand {
            org_event_id: lease.org_event_id,
            worker_owner: identity.worker_owner.clone(),
            worker_token_hex: identity.worker_token_hex.clone(),
            lease_seconds,
        })
        .await
    {
        Ok(true) => true,
        Ok(false) => false,
        Err(error) => {
            tracing::warn!(
                org_event_id = lease.org_event_id,
                error = %error,
                "org scope projector lease renewal failed; treating the event as lost"
            );
            false
        }
    }
}

/// durable 失败登记并按 repository 返回的终态归类。**唯一的 durable 写路径**：
/// 失败登记成功前绝不把事件当成功，登记失败即 [`EventOutcome::RecordUnknown`]。
async fn record_failure_and_map(
    store: &dyn OrgProjectorStore,
    config: &OrgScopeProjectorConfig,
    identity: &OrgScopeWorkerIdentity,
    lease: &OrgOutboxLease,
    stage: EventStage,
    kind: FailureKind,
    error_text: &str,
) -> EventOutcome {
    let cmd = OrgOutboxFailCommand {
        org_event_id: lease.org_event_id,
        worker_owner: identity.worker_owner.clone(),
        worker_token_hex: identity.worker_token_hex.clone(),
        error: truncate_error_text(error_text),
        retryable: kind == FailureKind::Retryable,
        backoff_seconds: event_backoff_seconds(lease.attempts, config.backoff_cap_seconds),
        max_attempts: config.max_event_attempts,
    };
    match store.fail(&cmd).await {
        Ok(outcome) if outcome.status == "FAILED" => {
            tracing::error!(
                org_event_id = lease.org_event_id,
                event_id = %lease.event_id,
                operation_id = %lease.operation_id,
                stage = ?stage,
                attempts = outcome.attempts,
                "org scope projector event reached durable terminal FAILED; operator \
                 intervention or a new source mutation is required"
            );
            EventOutcome::TerminalFailed(stage)
        }
        Ok(outcome) => {
            tracing::warn!(
                org_event_id = lease.org_event_id,
                event_id = %lease.event_id,
                operation_id = %lease.operation_id,
                stage = ?stage,
                attempts = outcome.attempts,
                "org scope projector event scheduled for bounded retry"
            );
            EventOutcome::RetryRecorded(stage)
        }
        Err(error) if is_lease_lost_error(&error) => {
            tracing::warn!(
                org_event_id = lease.org_event_id,
                stage = ?stage,
                "org scope projector could not record the failure because the lease \
                 was lost; leaving the event to its new owner"
            );
            EventOutcome::LeaseLost(stage)
        }
        Err(error) => {
            tracing::error!(
                org_event_id = lease.org_event_id,
                event_id = %lease.event_id,
                stage = ?stage,
                error = %error,
                "org scope projector failed to durably record the event failure; \
                 durable outbox state is UNKNOWN and requires operator reconciliation"
            );
            EventOutcome::RecordUnknown(stage)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 测试：纯逻辑 + 脚本化 store/compiler 驱动的循环行为（无 DB）
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::org_scope::{
        OrgErrorCode, OrgGrant, OrgNode, OrgPendingCode, OrgPendingItem, OrgRootActivation,
        OrgScope, OrgSubject,
    };
    use astral_types::ValidityWindow;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    // ───────────────────────────── fixtures ─────────────────────────────

    const GRANT_UUID: &str = "c0ffee00-0000-4000-8000-000000000001";

    fn scope_fixture() -> OrgScope {
        OrgScope {
            resource_tenant_id: 7,
            domain_id: None,
            resource: "doc:1".to_owned(),
            action: "read".to_owned(),
            validity: ValidityWindow::perpetual(),
        }
    }

    fn root_node_fixture() -> OrgNode {
        OrgNode {
            tenant_id: 7,
            root_tenant_id: 7,
            parent_tenant_id: None,
            generation: 1,
            revoke_fence: 0,
            relationship_revision: 1,
            active: true,
            operation_id: "op-root-1".to_owned(),
            root_activation: Some(OrgRootActivation {
                operator_user_id: 1,
                approval_operation_id: "op-approve-1".to_owned(),
            }),
        }
    }

    fn root_grant_fixture() -> OrgGrant {
        OrgGrant {
            grant_id: GRANT_UUID.to_owned(),
            revision: 1,
            receiving_tenant_id: 7,
            origin_tenant_id: 7,
            root_tenant_id: 7,
            scope: scope_fixture(),
            delegable: true,
            parent: None,
            subject: None::<OrgSubject>,
            active: true,
            operation_id: "op-grant-1".to_owned(),
        }
    }

    /// 根单元的合法编译输入（无依赖、无 mask；自源初始授权）。
    fn root_compile_input_fixture() -> OrgCompileInput {
        OrgCompileInput {
            node: root_node_fixture(),
            dependencies: Vec::new(),
            parent_publications: Vec::new(),
            grants: vec![root_grant_fixture()],
            masks: Vec::new(),
            operation_id: "op-compile-1".to_owned(),
        }
    }

    /// 用真实 OrgCompiler 产出 Applied 状态（避免手造 im::HashMap 账本）。
    fn applied_outcome_fixture() -> OrgCompileOutcome {
        OrgCompileOutcome::Applied(
            OrgCompiler::new()
                .rebuild_oracle(&root_compile_input_fixture())
                .expect("root fixture must compile"),
        )
    }

    fn lease_fixture(attempts: i64) -> OrgOutboxLease {
        OrgOutboxLease {
            org_event_id: 42,
            event_id: "org:grant_issued:evt-1".to_owned(),
            tenant_id: 7,
            event_kind: "GRANT_ISSUED".to_owned(),
            operation_id: "op-evt-1".to_owned(),
            payload_json: "{}".to_owned(),
            attempts,
            cas_version: 1,
            lease_expires_at_unix: 0,
        }
    }

    fn pending_report_fixture() -> OrgPendingReport {
        OrgPendingReport {
            tenant_id: 7,
            generation: 3,
            items: vec![OrgPendingItem {
                code: OrgPendingCode::ParentRevisionAdvanced,
                detail: "parent grant advanced to revision 9; reapproval required".to_owned(),
                grant_id: Some(GRANT_UUID.to_owned()),
                mask_id: None,
            }],
        }
    }

    /// 合法成员资格（tenant 与租约租户一致；validate 必须通过）。
    fn membership_fixture(tenant_id: i64) -> OrgMembership {
        OrgMembership {
            membership_id: "c0ffee00-0000-4000-8000-000000000002".to_owned(),
            tenant_id,
            root_tenant_id: tenant_id,
            user_id: 3,
            identity_card_id: 4,
            card_id: 5,
            revision: 1,
            active: true,
            validity: ValidityWindow::perpetual(),
            operation_id: "op-mbr-1".to_owned(),
        }
    }

    /// MEMBERSHIP_CHANGED 租约：payload 与 mutations 写入侧同型（typed
    /// `OrgMembership` 序列化），kind 走非发布完成路径。
    fn membership_lease_fixture(tenant_id: i64) -> OrgOutboxLease {
        let payload =
            serde_json::to_string(&membership_fixture(tenant_id)).expect("membership serializes");
        OrgOutboxLease {
            org_event_id: 77,
            event_id: "org:membership_changed:evt-m1".to_owned(),
            tenant_id,
            event_kind: "MEMBERSHIP_CHANGED".to_owned(),
            operation_id: "op-evt-m1".to_owned(),
            payload_json: payload,
            attempts: 1,
            cas_version: 1,
            lease_expires_at_unix: 0,
        }
    }

    /// SUBTREE_PROPAGATE 租约：payload 与 requests 写入侧同型（serde snake_case
    /// intent：child/new_root/relationship_revision）。
    fn propagate_lease_fixture(tenant_id: i64) -> OrgOutboxLease {
        OrgOutboxLease {
            org_event_id: 88,
            event_id: "org:subtree_propagate:evt-p1".to_owned(),
            tenant_id,
            event_kind: "SUBTREE_PROPAGATE".to_owned(),
            operation_id: "op-evt-p1".to_owned(),
            payload_json: format!(
                r#"{{"child_tenant_id":{tenant_id},"new_root_tenant_id":9,"relationship_revision":1}}"#
            ),
            attempts: 1,
            cas_version: 1,
            lease_expires_at_unix: 0,
        }
    }

    fn dependency_propagate_lease_fixture(tenant_id: i64) -> OrgOutboxLease {
        OrgOutboxLease {
            org_event_id: 89,
            event_id: "org:dependency_propagate:evt-d1".to_owned(),
            tenant_id,
            event_kind: "DEPENDENCY_PROPAGATE".to_owned(),
            operation_id: "op-evt-d1".to_owned(),
            payload_json: format!(
                r#"{{"anchor_tenant_id":{tenant_id},"root_tenant_id":9,"generation":4,"revoke_fence":0,"relationship_revision":1}}"#
            ),
            attempts: 1,
            cas_version: 1,
            lease_expires_at_unix: 0,
        }
    }

    fn dependency_propagate_outcome(
        updated_tenant_ids: &[i64],
        done: bool,
        superseded: bool,
    ) -> OrgDependencyPropagateOutcome {
        OrgDependencyPropagateOutcome {
            updated_tenant_ids: updated_tenant_ids.to_vec(),
            done,
            superseded,
        }
    }

    fn complete_outcome_fixture() -> OrgOutboxCompleteOutcome {
        OrgOutboxCompleteOutcome {
            attempts: 1,
            cas_version: 2,
        }
    }

    /// 锚点扇出结果构造：`done=false` 时下一前沿恒为 `[anchor]`（合同形状）；
    /// `superseded=true` 表示 repository 证实意图已被取代的无写放行。
    fn propagate_outcome(
        anchor: i64,
        updated: &[i64],
        done: bool,
        superseded: bool,
    ) -> OrgSubtreePropagateOutcome {
        OrgSubtreePropagateOutcome {
            updated_tenant_ids: updated.to_vec(),
            next_frontier: if done || superseded {
                Vec::new()
            } else {
                vec![anchor]
            },
            done,
            superseded,
        }
    }

    // ───────────────────── scripted seams（无 DB） ─────────────────────

    /// AstralError 不可 Clone：脚本用可 Clone 的错误描述，命中时再构造。
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum ScriptedErrorKind {
        Validation,
        Database,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ScriptedError {
        kind: ScriptedErrorKind,
        message: String,
    }

    impl ScriptedError {
        fn validation(message: impl Into<String>) -> Self {
            Self {
                kind: ScriptedErrorKind::Validation,
                message: message.into(),
            }
        }

        fn database(message: impl Into<String>) -> Self {
            Self {
                kind: ScriptedErrorKind::Database,
                message: message.into(),
            }
        }

        fn lease_lost() -> Self {
            Self::validation(LEASE_LOST_MACHINE_CODE)
        }

        fn into_astral(self) -> AstralError {
            match self.kind {
                ScriptedErrorKind::Validation => AstralError::Validation(self.message),
                ScriptedErrorKind::Database => AstralError::Database(self.message),
            }
        }
    }

    struct ScriptedStore {
        claims: Mutex<VecDeque<Option<OrgOutboxLease>>>,
        claim_error: Mutex<Option<ScriptedError>>,
        claim_tenants: Mutex<Vec<i64>>,
        claim_commands: Mutex<Vec<OrgOutboxClaimCommand>>,
        input_result: Mutex<Result<OrgCompileInput, ScriptedError>>,
        renew_result: Mutex<Result<bool, ScriptedError>>,
        fail_results: Mutex<VecDeque<Result<OrgOutboxFailOutcome, ScriptedError>>>,
        fail_commands: Mutex<Vec<OrgOutboxFailCommand>>,
        publish_result: Mutex<Result<OrgPublishOutcome, ScriptedError>>,
        publish_commands: Mutex<Vec<OrgPublishCommand>>,
        complete_results: Mutex<VecDeque<Result<OrgOutboxCompleteOutcome, ScriptedError>>>,
        complete_commands: Mutex<Vec<OrgOutboxCompleteCommand>>,
        propagate_results: Mutex<VecDeque<Result<OrgSubtreePropagateOutcome, ScriptedError>>>,
        propagate_commands: Mutex<Vec<OrgSubtreePropagateCommand>>,
        dependency_propagate_results:
            Mutex<VecDeque<Result<OrgDependencyPropagateOutcome, ScriptedError>>>,
        dependency_propagate_commands: Mutex<Vec<OrgDependencyPropagateCommand>>,
    }

    impl Default for ScriptedStore {
        fn default() -> Self {
            Self {
                claims: Mutex::new(VecDeque::new()),
                claim_error: Mutex::new(None),
                claim_tenants: Mutex::new(Vec::new()),
                claim_commands: Mutex::new(Vec::new()),
                input_result: Mutex::new(Err(ScriptedError::validation(
                    "input result not scripted",
                ))),
                renew_result: Mutex::new(Err(ScriptedError::validation(
                    "renew result not scripted",
                ))),
                fail_results: Mutex::new(VecDeque::new()),
                fail_commands: Mutex::new(Vec::new()),
                publish_result: Mutex::new(Err(ScriptedError::validation(
                    "publish result not scripted",
                ))),
                publish_commands: Mutex::new(Vec::new()),
                complete_results: Mutex::new(VecDeque::new()),
                complete_commands: Mutex::new(Vec::new()),
                propagate_results: Mutex::new(VecDeque::new()),
                propagate_commands: Mutex::new(Vec::new()),
                dependency_propagate_results: Mutex::new(VecDeque::new()),
                dependency_propagate_commands: Mutex::new(Vec::new()),
            }
        }
    }

    impl ScriptedStore {
        fn with_claims(claims: Vec<Option<OrgOutboxLease>>) -> Arc<Self> {
            let store = Self::default();
            *store.claims.lock().unwrap() = claims.into();
            Arc::new(store)
        }

        fn with_input_ok(self: &Arc<Self>, input: OrgCompileInput) -> Arc<Self> {
            *self.input_result.lock().unwrap() = Ok(input);
            self.clone()
        }

        fn with_fail_ok(self: &Arc<Self>, statuses: &[&str]) -> Arc<Self> {
            *self.fail_results.lock().unwrap() = statuses
                .iter()
                .map(|status| {
                    Ok(OrgOutboxFailOutcome {
                        status: (*status).to_owned(),
                        attempts: 1,
                    })
                })
                .collect();
            self.clone()
        }

        fn claim_tenants(&self) -> Vec<i64> {
            self.claim_tenants.lock().unwrap().clone()
        }

        fn claim_commands(&self) -> Vec<OrgOutboxClaimCommand> {
            self.claim_commands.lock().unwrap().clone()
        }

        fn fail_commands(&self) -> Vec<OrgOutboxFailCommand> {
            self.fail_commands.lock().unwrap().clone()
        }

        fn publish_commands(&self) -> Vec<OrgPublishCommand> {
            self.publish_commands.lock().unwrap().clone()
        }

        fn complete_commands(&self) -> Vec<OrgOutboxCompleteCommand> {
            self.complete_commands.lock().unwrap().clone()
        }

        fn propagate_commands(&self) -> Vec<OrgSubtreePropagateCommand> {
            self.propagate_commands.lock().unwrap().clone()
        }

        fn dependency_propagate_commands(&self) -> Vec<OrgDependencyPropagateCommand> {
            self.dependency_propagate_commands.lock().unwrap().clone()
        }

        fn with_complete_ok(self: &Arc<Self>, times: usize) -> Arc<Self> {
            *self.complete_results.lock().unwrap() =
                (0..times).map(|_| Ok(complete_outcome_fixture())).collect();
            self.clone()
        }

        fn with_propagate_outcomes(
            self: &Arc<Self>,
            outcomes: Vec<Result<OrgSubtreePropagateOutcome, ScriptedError>>,
        ) -> Arc<Self> {
            *self.propagate_results.lock().unwrap() = outcomes.into();
            self.clone()
        }

        fn with_dependency_propagate_outcomes(
            self: &Arc<Self>,
            outcomes: Vec<Result<OrgDependencyPropagateOutcome, ScriptedError>>,
        ) -> Arc<Self> {
            *self.dependency_propagate_results.lock().unwrap() = outcomes.into();
            self.clone()
        }
    }

    #[async_trait]
    impl OrgProjectorStore for ScriptedStore {
        async fn claim(
            &self,
            cmd: &OrgOutboxClaimCommand,
        ) -> Result<Option<OrgOutboxLease>, AstralError> {
            self.claim_tenants.lock().unwrap().push(cmd.tenant_id);
            self.claim_commands.lock().unwrap().push(cmd.clone());
            if let Some(error) = self.claim_error.lock().unwrap().clone() {
                return Err(error.into_astral());
            }
            Ok(self.claims.lock().unwrap().pop_front().flatten())
        }

        async fn renew(&self, _cmd: &OrgOutboxRenewCommand) -> Result<bool, AstralError> {
            self.renew_result
                .lock()
                .unwrap()
                .clone()
                .map_err(ScriptedError::into_astral)
        }

        async fn load_input(
            &self,
            _cmd: &OrgCompileInputCommand,
        ) -> Result<OrgCompileInput, AstralError> {
            self.input_result
                .lock()
                .unwrap()
                .clone()
                .map_err(ScriptedError::into_astral)
        }

        async fn fail(
            &self,
            cmd: &OrgOutboxFailCommand,
        ) -> Result<OrgOutboxFailOutcome, AstralError> {
            self.fail_commands.lock().unwrap().push(cmd.clone());
            self.fail_results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Err(ScriptedError::validation("fail result not scripted")))
                .map_err(ScriptedError::into_astral)
        }

        async fn publish(&self, cmd: &OrgPublishCommand) -> Result<OrgPublishOutcome, AstralError> {
            self.publish_commands.lock().unwrap().push(cmd.clone());
            self.publish_result
                .lock()
                .unwrap()
                .clone()
                .map_err(ScriptedError::into_astral)
        }

        async fn complete(
            &self,
            cmd: &OrgOutboxCompleteCommand,
        ) -> Result<OrgOutboxCompleteOutcome, AstralError> {
            self.complete_commands.lock().unwrap().push(cmd.clone());
            self.complete_results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Err(ScriptedError::validation("complete result not scripted")))
                .map_err(ScriptedError::into_astral)
        }

        async fn propagate(
            &self,
            cmd: &OrgSubtreePropagateCommand,
        ) -> Result<OrgSubtreePropagateOutcome, AstralError> {
            self.propagate_commands.lock().unwrap().push(cmd.clone());
            self.propagate_results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Err(ScriptedError::validation("propagate result not scripted")))
                .map_err(ScriptedError::into_astral)
        }

        async fn propagate_dependency(
            &self,
            cmd: &OrgDependencyPropagateCommand,
        ) -> Result<OrgDependencyPropagateOutcome, AstralError> {
            self.dependency_propagate_commands
                .lock()
                .unwrap()
                .push(cmd.clone());
            self.dependency_propagate_results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| {
                    Err(ScriptedError::validation(
                        "dependency propagate result not scripted",
                    ))
                })
                .map_err(ScriptedError::into_astral)
        }
    }

    /// 脚本化编译器：按队列返回编译结果；记录全部输入。
    struct ScriptedCompiler {
        results: Mutex<VecDeque<Result<OrgCompileOutcome, OrgError>>>,
        inputs: Mutex<Vec<OrgCompileInput>>,
    }

    impl ScriptedCompiler {
        fn new(results: Vec<Result<OrgCompileOutcome, OrgError>>) -> Arc<Self> {
            Arc::new(Self {
                results: Mutex::new(results.into()),
                inputs: Mutex::new(Vec::new()),
            })
        }

        fn inputs(&self) -> Vec<OrgCompileInput> {
            self.inputs.lock().unwrap().clone()
        }
    }

    impl OrgProjectorCompiler for ScriptedCompiler {
        fn compile_full(&self, input: &OrgCompileInput) -> Result<OrgCompileOutcome, OrgError> {
            self.inputs.lock().unwrap().push(input.clone());
            self.results.lock().unwrap().pop_front().unwrap_or_else(|| {
                Err(OrgError::new(
                    OrgErrorCode::InvalidRequest,
                    "compiler result not scripted",
                ))
            })
        }
    }

    fn small_config(tenants: Vec<i64>) -> OrgScopeProjectorConfig {
        OrgScopeProjectorConfig {
            tenants,
            poll_interval_secs: 3600,
            ..OrgScopeProjectorConfig::default()
        }
    }

    /// 启动 → 等待 worker 到达指定 claim 数（消除"取消先于首轮"的测试竞态）
    /// → 取消 → 有界 join（Idle 轮询间隔 3600s，cancel 会立即唤醒）。
    async fn run_until_claims(
        store: Arc<ScriptedStore>,
        compiler: Arc<ScriptedCompiler>,
        config: OrgScopeProjectorConfig,
        min_claims: usize,
    ) -> OrgScopeProjectorRunSummary {
        let handle = start_org_scope_projector_with_runtime(
            Arc::clone(&store) as Arc<dyn OrgProjectorStore>,
            Arc::clone(&compiler) as Arc<dyn OrgProjectorCompiler>,
            config,
        )
        .expect("test config must spawn");
        let deadline = Instant::now() + Duration::from_secs(5);
        while store.claim_tenants().len() < min_claims && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        handle.cancellation.cancel();
        let report = shutdown_org_scope_projector(handle, Duration::from_secs(5)).await;
        report
            .summary
            .expect("scripted worker must shut down cleanly")
    }

    // ───────────────────── 纯逻辑测试 ─────────────────────

    #[tokio::test]
    async fn shutdown_timeout_tracks_the_frozen_event_deadline() {
        let store = ScriptedStore::with_claims(vec![None]);
        let compiler = ScriptedCompiler::new(vec![]);
        let mut config = small_config(vec![7]);
        config.event_deadline_ms = 1_234;
        let expected = Duration::from_millis(config.event_deadline_ms).saturating_add(
            Duration::from_secs(ORG_SCOPE_SHUTDOWN_FAILURE_RECORDING_GRACE_SECS),
        );
        let handle = start_org_scope_projector_with_runtime(
            store as Arc<dyn OrgProjectorStore>,
            compiler as Arc<dyn OrgProjectorCompiler>,
            config,
        )
        .expect("valid config must spawn");

        assert_eq!(org_scope_projector_shutdown_timeout(&handle), expected);
        let report = shutdown_org_scope_projector(handle, Duration::from_secs(5)).await;
        assert!(report.summary.is_ok());
    }

    #[test]
    fn default_config_matches_the_contract() {
        let config = OrgScopeProjectorConfig::default();
        assert!(config.tenants.is_empty());
        assert_eq!(config.poll_interval_secs, DEFAULT_POLL_INTERVAL_SECS);
        assert_eq!(config.claim_lease_seconds, DEFAULT_CLAIM_LEASE_SECONDS);
        assert_eq!(config.max_event_attempts, DEFAULT_MAX_EVENT_ATTEMPTS);
        assert_eq!(config.backoff_cap_seconds, DEFAULT_BACKOFF_CAP_SECONDS);
        assert_eq!(
            config.events_per_tenant_cycle,
            DEFAULT_EVENTS_PER_TENANT_CYCLE
        );
        assert_eq!(config.event_deadline_ms, DEFAULT_EVENT_DEADLINE_MS);
        assert_eq!(config.propagate_batch_limit, DEFAULT_PROPAGATE_BATCH_LIMIT);
        // 空 tenant 列表必须拒绝启动，绝不静默空转吞积压。
        assert!(matches!(
            config.validate(),
            Err(OrgScopeProjectorConfigError::Tenants { .. })
        ));
    }

    #[test]
    fn config_validation_enforces_bounds_fail_closed() {
        let base = |mutate: &dyn Fn(&mut OrgScopeProjectorConfig)| {
            let mut config = OrgScopeProjectorConfig {
                tenants: vec![7],
                ..OrgScopeProjectorConfig::default()
            };
            mutate(&mut config);
            config.validate()
        };
        assert!(base(&|_| {}).is_ok());
        for bad_poll in [0u64, 3601] {
            assert!(matches!(
                base(&|config| config.poll_interval_secs = bad_poll),
                Err(OrgScopeProjectorConfigError::PollInterval { value }) if value == bad_poll
            ));
        }
        for bad_lease in [0i64, 3601] {
            assert!(matches!(
                base(&|config| config.claim_lease_seconds = bad_lease),
                Err(OrgScopeProjectorConfigError::ClaimLease { value }) if value == bad_lease
            ));
        }
        for bad_attempts in [0i64, 1001] {
            assert!(matches!(
                base(&|config| config.max_event_attempts = bad_attempts),
                Err(OrgScopeProjectorConfigError::MaxAttempts { value }) if value == bad_attempts
            ));
        }
        for bad_cap in [0i64, 86_401] {
            assert!(matches!(
                base(&|config| config.backoff_cap_seconds = bad_cap),
                Err(OrgScopeProjectorConfigError::BackoffCap { value }) if value == bad_cap
            ));
        }
        for bad_batch in [0usize, 1001] {
            assert!(matches!(
                base(&|config| config.events_per_tenant_cycle = bad_batch),
                Err(OrgScopeProjectorConfigError::BatchPerTenant { value }) if value == bad_batch
            ));
        }
        // deadline 必须 ≥100ms 且严格小于租约窗口（120s → max 119_999ms）。
        assert!(matches!(
            base(&|config| config.event_deadline_ms = 99),
            Err(OrgScopeProjectorConfigError::EventDeadline { .. })
        ));
        assert!(matches!(
            base(&|config| config.event_deadline_ms = 120_000),
            Err(OrgScopeProjectorConfigError::EventDeadline { .. })
        ));
        assert!(base(&|config| config.event_deadline_ms = 119_899).is_ok());
        // tenant 列表：非空、正数、无重复、≤64。
        assert!(matches!(
            base(&|config| config.tenants = Vec::new()),
            Err(OrgScopeProjectorConfigError::Tenants { .. })
        ));
        assert!(matches!(
            base(&|config| config.tenants = vec![7, 7]),
            Err(OrgScopeProjectorConfigError::Tenants { .. })
        ));
        assert!(matches!(
            base(&|config| config.tenants = vec![0]),
            Err(OrgScopeProjectorConfigError::Tenants { .. })
        ));
        assert!(matches!(
            base(&|config| config.tenants = vec![-3]),
            Err(OrgScopeProjectorConfigError::Tenants { .. })
        ));
        assert!(matches!(
            base(&|config| config.tenants = (1..=65).collect()),
            Err(OrgScopeProjectorConfigError::Tenants { .. })
        ));
    }

    #[test]
    fn parse_config_uses_defaults_and_strict_overrides() {
        let parsed = parse_org_scope_projector_config(&OrgScopeProjectorEnvRaw {
            tenants: Some("7, 9".to_owned()),
            poll_interval_secs: Some("10".to_owned()),
            claim_lease_seconds: Some("300".to_owned()),
            max_event_attempts: Some("8".to_owned()),
            backoff_cap_seconds: Some("60".to_owned()),
            events_per_tenant_cycle: Some("3".to_owned()),
            event_deadline_ms: Some("120000".to_owned()),
            propagate_batch_limit: Some("150".to_owned()),
        })
        .expect("valid overrides must parse");
        assert_eq!(parsed.tenants, vec![7, 9]);
        assert_eq!(parsed.poll_interval_secs, 10);
        assert_eq!(parsed.claim_lease_seconds, 300);
        assert_eq!(parsed.max_event_attempts, 8);
        assert_eq!(parsed.backoff_cap_seconds, 60);
        assert_eq!(parsed.events_per_tenant_cycle, 3);
        assert_eq!(parsed.event_deadline_ms, 120_000);
        assert_eq!(parsed.propagate_batch_limit, 150);

        assert!(matches!(
            parse_org_scope_projector_config(&OrgScopeProjectorEnvRaw::default()),
            Err(OrgScopeProjectorConfigError::Tenants { .. })
        ));

        for tenants_raw in ["x", "7,,9", "7,0", "-1"] {
            let error = parse_org_scope_projector_config(&OrgScopeProjectorEnvRaw {
                tenants: Some(tenants_raw.to_owned()),
                ..Default::default()
            })
            .expect_err("malformed tenants must fail startup");
            assert!(matches!(
                error,
                OrgScopeProjectorConfigError::Tenants { .. }
            ));
        }
        let error = parse_org_scope_projector_config(&OrgScopeProjectorEnvRaw {
            poll_interval_secs: Some("soon".to_owned()),
            ..Default::default()
        })
        .expect_err("invalid numbers must fail startup");
        assert_eq!(
            error,
            OrgScopeProjectorConfigError::Parse {
                name: ENV_POLL_SECS,
                value: "soon".to_owned()
            }
        );
        // deadline 超过租约窗口必须失败（120s 租约 + 200s deadline）。
        assert!(parse_org_scope_projector_config(&OrgScopeProjectorEnvRaw {
            tenants: Some("7".to_owned()),
            claim_lease_seconds: Some("120".to_owned()),
            event_deadline_ms: Some("200000".to_owned()),
            ..Default::default()
        })
        .is_err());
    }

    #[test]
    fn generated_worker_identity_satisfies_repository_contract() {
        for _ in 0..16 {
            let run_id = Uuid::new_v4().to_string();
            let identity = generate_org_scope_worker_identity(&run_id);
            assert!(identity.worker_owner.starts_with("org-scope-projector-"));
            assert!(identity.worker_owner.contains(&run_id));
            assert!(is_valid_lease_owner(&identity.worker_owner));
            assert!(identity.worker_owner.len() <= 128);
            assert!(is_valid_worker_token_hex(&identity.worker_token_hex));
            assert_eq!(identity.worker_token_hex.len(), 64);
            assert!(identity
                .worker_token_hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
        }
        // 两次生成的身份必须不同（token 32 字节熵，owner 绑定唯一 run）。
        let first = generate_org_scope_worker_identity(&Uuid::new_v4().to_string());
        let second = generate_org_scope_worker_identity(&Uuid::new_v4().to_string());
        assert_ne!(first.worker_token_hex, second.worker_token_hex);
        assert_ne!(first.worker_owner, second.worker_owner);
    }

    #[test]
    fn bytes_to_hex_is_lowercase_and_matches_known_vectors() {
        assert_eq!(bytes_to_hex(&[]), "");
        assert_eq!(bytes_to_hex(&[0x00, 0xff, 0x10]), "00ff10");
        assert_eq!(bytes_to_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn event_backoff_is_exponential_and_capped() {
        assert_eq!(event_backoff_seconds(1, 900), 1);
        assert_eq!(event_backoff_seconds(2, 900), 2);
        assert_eq!(event_backoff_seconds(3, 900), 4);
        assert_eq!(event_backoff_seconds(4, 900), 8);
        assert_eq!(event_backoff_seconds(11, 900), 900);
        assert_eq!(event_backoff_seconds(64, 5), 5);
        assert_eq!(event_backoff_seconds(0, 900), 1);
        assert_eq!(event_backoff_seconds(-3, 900), 1);
        // attempts=33 → clamp 32 → step 31 → 2^31。
        assert_eq!(event_backoff_seconds(33, i64::MAX), 1i64 << 31);
    }

    #[test]
    fn cycle_backoff_is_finite_and_bounded() {
        assert_eq!(cycle_backoff_delay(1), Duration::from_secs(1));
        assert_eq!(cycle_backoff_delay(2), Duration::from_secs(2));
        assert_eq!(cycle_backoff_delay(3), Duration::from_secs(4));
        assert_eq!(cycle_backoff_delay(6), Duration::from_secs(30));
        assert_eq!(cycle_backoff_delay(u32::MAX), Duration::from_secs(30));
    }

    #[test]
    fn next_cycle_wait_maps_health_to_delays() {
        let poll = Duration::from_secs(5);
        assert_eq!(next_cycle_wait(CycleHealth::Busy, 0, poll), Duration::ZERO);
        assert_eq!(next_cycle_wait(CycleHealth::Idle, 0, poll), poll);
        assert_eq!(
            next_cycle_wait(CycleHealth::InfraError, 1, poll),
            Duration::from_secs(1)
        );
        assert_eq!(
            next_cycle_wait(CycleHealth::InfraError, 3, poll),
            Duration::from_secs(4)
        );
    }

    #[test]
    fn should_renew_lease_uses_one_third_of_the_window() {
        assert!(!should_renew_lease(Duration::from_secs(0), 120));
        assert!(!should_renew_lease(Duration::from_secs(39), 120));
        assert!(should_renew_lease(Duration::from_secs(40), 120));
        assert!(should_renew_lease(Duration::from_secs(600), 120));
        assert!(should_renew_lease(Duration::from_secs(1), 1));
        assert!(!should_renew_lease(Duration::from_secs(0), 1));
    }

    #[test]
    fn rotated_tenant_order_rotates_without_duplicates() {
        let tenants = [1, 2, 3];
        let (first, cursor) = rotated_tenant_order(&tenants, 0);
        assert_eq!(first, vec![1, 2, 3]);
        let (second, cursor) = rotated_tenant_order(&tenants, cursor);
        assert_eq!(second, vec![2, 3, 1]);
        let (third, cursor) = rotated_tenant_order(&tenants, cursor);
        assert_eq!(third, vec![3, 1, 2]);
        let (fourth, _) = rotated_tenant_order(&tenants, cursor);
        assert_eq!(fourth, vec![1, 2, 3]);
        // 游标越界安全回绕。
        let (wrapped, _) = rotated_tenant_order(&tenants, 9);
        assert_eq!(wrapped, vec![1, 2, 3]);
        assert_eq!(rotated_tenant_order(&[], 3), (Vec::<i64>::new(), 0));
    }

    #[test]
    fn classify_compile_outcome_renders_publication_for_applied_and_pending_for_report() {
        let verdict =
            classify_compile_outcome(applied_outcome_fixture()).expect("applied must render");
        match verdict {
            CompileVerdict::Publish(publication) => {
                assert_eq!(publication.tenant_id, 7);
                assert_eq!(publication.generation, 1);
                assert_eq!(publication.compiler_version, "org-compiler-v1");
                publication
                    .validate()
                    .expect("rendered publication must satisfy the wire contract");
            }
            other => panic!("expected Publish, got {other:?}"),
        }
        let verdict = classify_compile_outcome(OrgCompileOutcome::Pending {
            state: OrgCompiler::new()
                .rebuild_oracle(&root_compile_input_fixture())
                .expect("fixture state"),
            report: pending_report_fixture(),
        })
        .expect("pending is not an error");
        assert_eq!(
            verdict,
            CompileVerdict::Pending {
                report: pending_report_fixture()
            }
        );
    }

    #[test]
    fn summarize_pending_report_is_bounded_and_counts_by_machine_code() {
        let summary = summarize_pending_report(&pending_report_fixture());
        assert!(summary.starts_with("code=org_scope.compile_pending;"));
        assert!(summary.contains("tenant=7"));
        assert!(summary.contains("generation=3"));
        assert!(summary.contains("org_scope.pending.parent_revision_advancedx1"));
        assert!(summary.contains("reapproval required"));
        assert!(summary.len() <= 512);
        // 大量长 detail：整体必须截断到 512 字节且不破坏 UTF-8 边界。
        let mut report = pending_report_fixture();
        for _ in 0..64 {
            report.items.push(OrgPendingItem {
                code: OrgPendingCode::ScopeNotCovered,
                detail: "范围包含不可证明：".repeat(40),
                grant_id: None,
                mask_id: None,
            });
        }
        let truncated = summarize_pending_report(&report);
        assert!(truncated.len() <= 512);
        assert!(truncated.is_char_boundary(truncated.len()));
    }

    #[test]
    fn truncate_error_text_respects_char_boundaries() {
        let ascii = "a".repeat(600);
        assert_eq!(truncate_error_text(&ascii).len(), 512);
        let multibyte = "组".repeat(400);
        let truncated = truncate_error_text(&multibyte);
        assert!(truncated.len() <= 512);
        assert!(truncated.is_char_boundary(truncated.len()));
        assert_eq!(truncate_error_text("short"), "short");
    }

    #[test]
    fn is_lease_lost_error_matches_the_stable_machine_code() {
        assert!(is_lease_lost_error(&AstralError::Validation(
            LEASE_LOST_MACHINE_CODE.to_owned()
        )));
        assert!(!is_lease_lost_error(&AstralError::Validation(
            "code=org_scope.publish_stale_source;detail=node_head_advanced".to_owned()
        )));
        assert!(!is_lease_lost_error(&AstralError::Database(
            "connection refused".to_owned()
        )));
    }

    #[test]
    fn repository_errors_are_always_retryable_by_policy() {
        // 策略显式化测试：repository 侧任何错误都交由 attempt 预算收敛终态。
        for error in [
            AstralError::Validation("code=org_scope.publish_stale_source".to_owned()),
            AstralError::Validation("code=org_scope.compile_grants_exceeded".to_owned()),
            AstralError::NotFound("code=org_scope.parent_publication_missing".to_owned()),
            AstralError::Database("deadlock".to_owned()),
        ] {
            assert_eq!(classify_repository_error(&error), FailureKind::Retryable);
        }
    }

    // ───────────────────── 循环行为测试（脚本化 seams） ─────────────────────

    #[tokio::test]
    async fn worker_drains_events_and_publishes_only_on_complete_publish_success() {
        let input = root_compile_input_fixture();
        let store = ScriptedStore::with_claims(vec![Some(lease_fixture(1)), None])
            .with_input_ok(input.clone());
        *store.publish_result.lock().unwrap() = Ok(OrgPublishOutcome {
            publication_id: 9001,
            generation: 1,
            cas_version: 2,
        });
        let compiler = ScriptedCompiler::new(vec![Ok(applied_outcome_fixture())]);
        let summary =
            run_until_claims(store.clone(), compiler.clone(), small_config(vec![7]), 2).await;

        assert_eq!(summary.claimed, 1);
        assert_eq!(summary.published, 1);
        assert_eq!(summary.pending_retries, 0);
        assert_eq!(summary.terminal_failed, 0);
        assert_eq!(summary.lease_lost, 0);
        assert_eq!(summary.record_unknown, 0);
        assert!(store.fail_commands().is_empty());
        let publishes = store.publish_commands();
        assert_eq!(publishes.len(), 1);
        assert_eq!(publishes[0].org_event_id, 42);
        assert_eq!(publishes[0].publication.tenant_id, 7);
        assert!(is_valid_lease_owner(&publishes[0].worker_owner));
        assert!(is_valid_worker_token_hex(&publishes[0].worker_token_hex));
        // 编译输入经 seam 原样进入编译器（worker 不解析 payload_json）。
        assert_eq!(compiler.inputs(), vec![input]);
    }

    #[tokio::test]
    async fn pending_outcome_records_retryable_failure_and_never_publishes() {
        let store = ScriptedStore::with_claims(vec![Some(lease_fixture(1)), None])
            .with_input_ok(root_compile_input_fixture())
            .with_fail_ok(&["PENDING"]);
        let compiler = ScriptedCompiler::new(vec![Ok(OrgCompileOutcome::Pending {
            state: OrgCompiler::new()
                .rebuild_oracle(&root_compile_input_fixture())
                .expect("fixture state"),
            report: pending_report_fixture(),
        })]);
        let summary = run_until_claims(store.clone(), compiler, small_config(vec![7]), 2).await;

        assert_eq!(summary.claimed, 1);
        assert_eq!(summary.published, 0);
        assert_eq!(summary.pending_retries, 1);
        assert!(store.publish_commands().is_empty());
        let fails = store.fail_commands();
        assert_eq!(fails.len(), 1);
        assert!(fails[0].retryable);
        assert_eq!(fails[0].max_attempts, DEFAULT_MAX_EVENT_ATTEMPTS);
        assert_eq!(fails[0].backoff_seconds, 1);
        assert!(fails[0]
            .error
            .starts_with("code=org_scope.compile_pending;"));
        assert!(fails[0].error.contains("parent_revision_advanced"));
    }

    #[tokio::test]
    async fn claim_commands_thread_the_configured_attempt_budget() {
        // claim 侧预算收敛：worker 必须把 max_event_attempts 原样带入每条
        // claim 命令（与 fail 侧同一部署预算）。repository 据此在 crash 后的
        // 过期租约回收达到预算时落终态 FAILED，认领次数因此有界。
        let store = ScriptedStore::with_claims(vec![Some(lease_fixture(2)), None])
            .with_input_ok(root_compile_input_fixture())
            .with_fail_ok(&["FAILED"]);
        let compiler = ScriptedCompiler::new(vec![Err(OrgError::new(
            OrgErrorCode::ParentNotDelegable,
            "deterministic contract break",
        ))]);
        let mut config = small_config(vec![7]);
        config.max_event_attempts = 3;
        let summary = run_until_claims(store.clone(), compiler, config, 2).await;

        assert_eq!(summary.claimed, 1);
        assert_eq!(summary.terminal_failed, 1);
        // 取消与轮询存在竞态，claim 次数可能 ≥ 脚本队列长度；但每一条已发出
        // 的 claim 命令都必须携带预算与租约窗口。
        let claims = store.claim_commands();
        assert!(claims.len() >= 2);
        for cmd in &claims {
            assert_eq!(cmd.tenant_id, 7);
            assert_eq!(cmd.max_attempts, 3);
            assert_eq!(cmd.lease_seconds, DEFAULT_CLAIM_LEASE_SECONDS);
            assert!(is_valid_lease_owner(&cmd.worker_owner));
            assert!(is_valid_worker_token_hex(&cmd.worker_token_hex));
        }
    }

    #[tokio::test]
    async fn deterministic_compiler_error_records_terminal_failure() {
        let store = ScriptedStore::with_claims(vec![Some(lease_fixture(1)), None])
            .with_input_ok(root_compile_input_fixture())
            .with_fail_ok(&["FAILED"]);
        let compiler = ScriptedCompiler::new(vec![Err(OrgError::new(
            OrgErrorCode::ParentNotDelegable,
            "parent grant is not delegable; deterministic contract break",
        ))]);
        let summary = run_until_claims(store.clone(), compiler, small_config(vec![7]), 2).await;

        assert_eq!(summary.terminal_failed, 1);
        assert_eq!(summary.published, 0);
        assert!(store.publish_commands().is_empty());
        let fails = store.fail_commands();
        assert_eq!(fails.len(), 1);
        assert!(!fails[0].retryable, "deterministic errors must go terminal");
        assert!(fails[0].error.contains("org_scope.parent_not_delegable"));
    }

    #[tokio::test]
    async fn stale_publish_records_retryable_failure() {
        let store = ScriptedStore::with_claims(vec![Some(lease_fixture(1)), None])
            .with_input_ok(root_compile_input_fixture())
            .with_fail_ok(&["PENDING"]);
        *store.publish_result.lock().unwrap() = Err(ScriptedError::validation(
            "code=org_scope.publish_stale_source;detail=node_head_advanced",
        ));
        let compiler = ScriptedCompiler::new(vec![Ok(applied_outcome_fixture())]);
        let summary = run_until_claims(store.clone(), compiler, small_config(vec![7]), 2).await;

        assert_eq!(summary.published, 0);
        assert_eq!(summary.pending_retries, 1);
        assert_eq!(summary.terminal_failed, 0);
        let fails = store.fail_commands();
        assert_eq!(fails.len(), 1);
        assert!(fails[0].retryable);
        assert!(fails[0].error.contains("publish_stale_source"));
    }

    #[tokio::test]
    async fn lease_lost_during_load_abandons_event_without_failure_recording() {
        let store = ScriptedStore::with_claims(vec![Some(lease_fixture(1)), None]);
        *store.input_result.lock().unwrap() = Err(ScriptedError::lease_lost());
        let compiler = ScriptedCompiler::new(vec![]);
        let summary =
            run_until_claims(store.clone(), compiler.clone(), small_config(vec![7]), 2).await;

        assert_eq!(summary.lease_lost, 1);
        assert_eq!(summary.published, 0);
        assert_eq!(summary.pending_retries, 0);
        assert!(
            store.fail_commands().is_empty(),
            "a lost lease must never be re-recorded"
        );
        assert!(store.publish_commands().is_empty());
        assert!(compiler.inputs().is_empty());
    }

    #[tokio::test]
    async fn fail_outbox_rejection_maps_to_record_unknown() {
        let store = ScriptedStore::with_claims(vec![Some(lease_fixture(1)), None])
            .with_input_ok(root_compile_input_fixture());
        *store.fail_results.lock().unwrap() =
            vec![Err(ScriptedError::database("fail write rejected"))].into();
        let compiler = ScriptedCompiler::new(vec![Err(OrgError::new(
            OrgErrorCode::ParentNotDelegable,
            "deterministic",
        ))]);
        let summary = run_until_claims(store.clone(), compiler, small_config(vec![7]), 2).await;

        assert_eq!(summary.record_unknown, 1);
        assert_eq!(summary.published, 0);
        assert!(store.publish_commands().is_empty());
    }

    #[tokio::test]
    async fn claim_infrastructure_errors_back_off_and_still_shut_down_cleanly() {
        let store = ScriptedStore::with_claims(vec![None, None]);
        *store.claim_error.lock().unwrap() = Some(ScriptedError::database(
            "claim failed against the repository",
        ));
        let compiler = ScriptedCompiler::new(vec![]);
        let handle = {
            let store_dyn: Arc<dyn OrgProjectorStore> = store.clone();
            let compiler_dyn: Arc<dyn OrgProjectorCompiler> = compiler;
            start_org_scope_projector_with_runtime(store_dyn, compiler_dyn, small_config(vec![7]))
                .expect("valid config spawns")
        };
        // 等到至少两轮 claim 尝试（首轮 + 退避后重试），再取消。
        let deadline = Instant::now() + Duration::from_secs(5);
        while store.claim_tenants().len() < 2 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        handle.cancellation.cancel();
        let report = shutdown_org_scope_projector(handle, Duration::from_secs(5)).await;
        assert!(
            report.summary.is_ok(),
            "claim errors must not wedge shutdown"
        );
        let summary = report.summary.expect("clean shutdown");
        assert!(summary.claim_errors >= 1);
        assert_eq!(summary.claimed, 0);
    }

    #[tokio::test]
    async fn shutdown_is_bounded_when_the_store_never_returns() {
        struct HangingStore {
            entered_claim: Arc<AtomicBool>,
        }
        #[async_trait]
        impl OrgProjectorStore for HangingStore {
            async fn claim(
                &self,
                _cmd: &OrgOutboxClaimCommand,
            ) -> Result<Option<OrgOutboxLease>, AstralError> {
                // 先证明 worker 真正进入了 claim 调用，再挂死（消除取消竞态）。
                self.entered_claim.store(true, Ordering::Release);
                std::future::pending::<()>().await;
                unreachable!("pending future never resolves");
            }
            async fn renew(&self, _cmd: &OrgOutboxRenewCommand) -> Result<bool, AstralError> {
                unreachable!("renew must not be reached");
            }
            async fn load_input(
                &self,
                _cmd: &OrgCompileInputCommand,
            ) -> Result<OrgCompileInput, AstralError> {
                unreachable!("load_input must not be reached");
            }
            async fn fail(
                &self,
                _cmd: &OrgOutboxFailCommand,
            ) -> Result<OrgOutboxFailOutcome, AstralError> {
                unreachable!("fail must not be reached");
            }
            async fn publish(
                &self,
                _cmd: &OrgPublishCommand,
            ) -> Result<OrgPublishOutcome, AstralError> {
                unreachable!("publish must not be reached");
            }
            async fn complete(
                &self,
                _cmd: &OrgOutboxCompleteCommand,
            ) -> Result<OrgOutboxCompleteOutcome, AstralError> {
                unreachable!("complete must not be reached");
            }
            async fn propagate(
                &self,
                _cmd: &OrgSubtreePropagateCommand,
            ) -> Result<OrgSubtreePropagateOutcome, AstralError> {
                unreachable!("propagate must not be reached");
            }
            async fn propagate_dependency(
                &self,
                _cmd: &OrgDependencyPropagateCommand,
            ) -> Result<OrgDependencyPropagateOutcome, AstralError> {
                unreachable!("dependency propagation must not be reached");
            }
        }
        let entered_claim = Arc::new(AtomicBool::new(false));
        let store_dyn: Arc<dyn OrgProjectorStore> = Arc::new(HangingStore {
            entered_claim: Arc::clone(&entered_claim),
        });
        let compiler_dyn: Arc<dyn OrgProjectorCompiler> = ScriptedCompiler::new(vec![]);
        let handle =
            start_org_scope_projector_with_runtime(store_dyn, compiler_dyn, small_config(vec![7]))
                .expect("valid config spawns");
        // 等到 worker 真正卡死在 claim 内，再取消并要求有界超时失败。
        let deadline = Instant::now() + Duration::from_secs(5);
        while !entered_claim.load(Ordering::Acquire) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            entered_claim.load(Ordering::Acquire),
            "worker never reached claim"
        );
        let report = shutdown_org_scope_projector(handle, Duration::from_millis(200)).await;
        let failure = report
            .summary
            .expect_err("wedged worker must fail shutdown");
        assert!(failure.contains("did not stop within"));
    }

    #[tokio::test]
    async fn start_rejects_invalid_config_before_spawning_anything() {
        let store = ScriptedStore::with_claims(vec![]);
        let store_dyn: Arc<dyn OrgProjectorStore> = store.clone();
        let compiler_dyn: Arc<dyn OrgProjectorCompiler> = ScriptedCompiler::new(vec![]);
        let error = start_org_scope_projector_with_runtime(
            store_dyn,
            compiler_dyn,
            OrgScopeProjectorConfig::default(), // 空 tenants
        )
        .expect_err("empty tenants must be rejected before spawn");
        assert!(matches!(
            error,
            OrgScopeProjectorConfigError::Tenants { .. }
        ));
        // 校验失败路径绝不触碰 store（无调用、无任务）。
        assert!(store.claim_tenants().is_empty());
    }

    #[tokio::test]
    async fn multi_tenant_claims_rotate_through_the_configured_order() {
        let store = ScriptedStore::with_claims(vec![Some(lease_fixture(1)), None, None])
            .with_input_ok(root_compile_input_fixture());
        *store.publish_result.lock().unwrap() = Ok(OrgPublishOutcome {
            publication_id: 1,
            generation: 1,
            cas_version: 2,
        });
        let compiler = ScriptedCompiler::new(vec![Ok(applied_outcome_fixture())]);
        let summary =
            run_until_claims(store.clone(), compiler, small_config(vec![11, 22]), 3).await;

        assert_eq!(summary.claimed, 1);
        assert_eq!(summary.published, 1);
        let tenants = store.claim_tenants();
        assert!(tenants.contains(&11) && tenants.contains(&22));
        assert_eq!(tenants[0], 11, "first cycle starts at the first tenant");
    }

    // ───────────────────── 事件分派（event-kind dispatch）测试 ─────────────────────

    #[tokio::test]
    async fn membership_event_completes_without_publication() {
        let store = ScriptedStore::with_claims(vec![Some(membership_lease_fixture(7)), None])
            .with_complete_ok(1);
        let compiler = ScriptedCompiler::new(vec![]);
        let summary =
            run_until_claims(store.clone(), compiler.clone(), small_config(vec![7]), 2).await;

        assert_eq!(summary.completed_without_publish, 1);
        assert_eq!(summary.published, 0);
        assert_eq!(summary.pending_retries, 0);
        assert_eq!(summary.terminal_failed, 0);
        assert_eq!(summary.lease_lost, 0);
        // 非发布事件绝不触碰 load_input/compiler/publish/fail/propagate。
        assert!(compiler.inputs().is_empty());
        assert!(store.publish_commands().is_empty());
        assert!(store.fail_commands().is_empty());
        assert!(store.propagate_commands().is_empty());
        let completes = store.complete_commands();
        assert_eq!(completes.len(), 1);
        assert_eq!(completes[0].org_event_id, 77);
        assert_eq!(
            completes[0].expected_kind,
            OrgOutboxEventKind::MembershipChanged
        );
        assert!(is_valid_lease_owner(&completes[0].worker_owner));
        assert!(is_valid_worker_token_hex(&completes[0].worker_token_hex));
    }

    #[tokio::test]
    async fn malformed_membership_payload_is_terminal_and_never_completed() {
        let mut lease = membership_lease_fixture(7);
        lease.payload_json = "{}".to_owned(); // 缺字段：typed 解析失败
        let store = ScriptedStore::with_claims(vec![Some(lease), None]).with_fail_ok(&["FAILED"]);
        let compiler = ScriptedCompiler::new(vec![]);
        let summary =
            run_until_claims(store.clone(), compiler.clone(), small_config(vec![7]), 2).await;

        assert_eq!(summary.terminal_failed, 1);
        assert_eq!(summary.completed_without_publish, 0);
        assert!(compiler.inputs().is_empty());
        assert!(store.publish_commands().is_empty());
        assert!(store.complete_commands().is_empty());
        let fails = store.fail_commands();
        assert_eq!(fails.len(), 1);
        assert!(
            !fails[0].retryable,
            "malformed payload is a deterministic contract break"
        );
        assert!(fails[0]
            .error
            .starts_with("code=org_scope.membership_payload_invalid"));
    }

    #[tokio::test]
    async fn membership_tenant_mismatch_is_terminal_and_never_completed() {
        let mut lease = membership_lease_fixture(7);
        // payload 声明 tenant 8，租约 tenant 7：跨租户污染企图 → 终态。
        lease.payload_json =
            serde_json::to_string(&membership_fixture(8)).expect("membership serializes");
        let store = ScriptedStore::with_claims(vec![Some(lease), None]).with_fail_ok(&["FAILED"]);
        let compiler = ScriptedCompiler::new(vec![]);
        let summary = run_until_claims(store.clone(), compiler, small_config(vec![7]), 2).await;

        assert_eq!(summary.terminal_failed, 1);
        assert!(store.complete_commands().is_empty());
        assert!(store.publish_commands().is_empty());
        let fails = store.fail_commands();
        assert_eq!(fails.len(), 1);
        assert!(!fails[0].retryable);
        assert!(fails[0]
            .error
            .starts_with("code=org_scope.membership_tenant_mismatch"));
        assert!(fails[0].error.contains("payload_tenant=8"));
        assert!(fails[0].error.contains("lease_tenant=7"));
    }

    #[tokio::test]
    async fn unknown_event_kind_is_bounded_retry_and_never_published_or_completed() {
        let mut lease = lease_fixture(1);
        lease.event_kind = "FUTURE_KIND".to_owned(); // 滚动升级：新 kind 由旧 worker 处理
        let store = ScriptedStore::with_claims(vec![Some(lease), None]).with_fail_ok(&["PENDING"]);
        let compiler = ScriptedCompiler::new(vec![]);
        let summary =
            run_until_claims(store.clone(), compiler.clone(), small_config(vec![7]), 2).await;

        assert_eq!(summary.pending_retries, 1);
        assert_eq!(summary.published, 0);
        assert_eq!(summary.completed_without_publish, 0);
        assert!(compiler.inputs().is_empty());
        assert!(store.publish_commands().is_empty());
        assert!(store.complete_commands().is_empty());
        assert!(store.propagate_commands().is_empty());
        let fails = store.fail_commands();
        assert_eq!(fails.len(), 1);
        assert!(
            fails[0].retryable,
            "unknown kind must stay retryable so rolling upgrades converge"
        );
        assert!(fails[0]
            .error
            .starts_with("code=org_scope.outbox_event_kind_unknown"));
        assert!(fails[0].error.contains("FUTURE_KIND"));
    }

    #[tokio::test]
    async fn subtree_propagate_completes_after_multi_batch_and_never_publishes() {
        // 锚点扇出：done=false 时下一前沿恒为 [锚点]，同一事件以同一前沿重入
        // 排空剩余直系兄弟；repository 为每个被推进子节点派生独立 child intent。
        let store = ScriptedStore::with_claims(vec![Some(propagate_lease_fixture(7)), None])
            .with_propagate_outcomes(vec![
                Ok(propagate_outcome(7, &[20, 21], false, false)),
                Ok(propagate_outcome(7, &[30], false, false)),
                Ok(propagate_outcome(7, &[], true, false)),
            ])
            .with_complete_ok(1);
        let compiler = ScriptedCompiler::new(vec![]);
        let summary =
            run_until_claims(store.clone(), compiler.clone(), small_config(vec![7]), 2).await;

        assert_eq!(summary.completed_without_publish, 1);
        assert_eq!(summary.published, 0);
        assert!(compiler.inputs().is_empty());
        assert!(store.publish_commands().is_empty());
        assert!(store.fail_commands().is_empty());
        let propagates = store.propagate_commands();
        assert_eq!(propagates.len(), 3);
        for cmd in &propagates {
            // 每一批都以同一锚点重入：前沿绝不漂移到子节点列表。
            assert_eq!(cmd.frontier, vec![7]);
            assert_eq!(cmd.expected_kind, OrgOutboxEventKind::SubtreePropagate);
            assert_eq!(cmd.new_root_tenant_id, 9);
            assert_eq!(cmd.batch_limit, DEFAULT_PROPAGATE_BATCH_LIMIT);
            assert_eq!(cmd.org_event_id, 88);
            assert_eq!(cmd.operation_id, "op-evt-p1");
            assert!(is_valid_lease_owner(&cmd.worker_owner));
            assert!(is_valid_worker_token_hex(&cmd.worker_token_hex));
        }
        let completes = store.complete_commands();
        assert_eq!(completes.len(), 1);
        assert_eq!(completes[0].org_event_id, 88);
        assert_eq!(
            completes[0].expected_kind,
            OrgOutboxEventKind::SubtreePropagate
        );
    }

    #[tokio::test]
    async fn dependency_propagate_completes_after_bounded_batches_without_publication() {
        let mut config = small_config(vec![7]);
        config.propagate_batch_limit = 2;
        let updated_first = (10..12).collect::<Vec<_>>();
        let store =
            ScriptedStore::with_claims(vec![Some(dependency_propagate_lease_fixture(7)), None])
                .with_dependency_propagate_outcomes(vec![
                    Ok(dependency_propagate_outcome(&updated_first, false, false)),
                    Ok(dependency_propagate_outcome(&[12], true, false)),
                ])
                .with_complete_ok(1);
        let compiler = ScriptedCompiler::new(vec![]);
        let summary = run_until_claims(store.clone(), compiler.clone(), config, 2).await;

        assert_eq!(summary.completed_without_publish, 1);
        assert_eq!(summary.published, 0);
        assert_eq!(summary.pending_retries, 0);
        assert!(compiler.inputs().is_empty());
        assert!(store.publish_commands().is_empty());
        assert!(store.fail_commands().is_empty());
        assert!(store.propagate_commands().is_empty());
        let commands = store.dependency_propagate_commands();
        assert_eq!(commands.len(), 2);
        for cmd in &commands {
            assert_eq!(cmd.expected_kind, OrgOutboxEventKind::DependencyPropagate);
            assert_eq!(cmd.anchor_tenant_id, 7);
            assert_eq!(cmd.batch_limit, 2);
            assert_eq!(cmd.org_event_id, 89);
            assert_eq!(cmd.operation_id, "op-evt-d1");
            assert!(is_valid_lease_owner(&cmd.worker_owner));
            assert!(is_valid_worker_token_hex(&cmd.worker_token_hex));
        }
        assert_eq!(
            store.complete_commands()[0].expected_kind,
            OrgOutboxEventKind::DependencyPropagate
        );
    }

    #[tokio::test]
    async fn dependency_propagate_superseded_completes_without_publication() {
        let store =
            ScriptedStore::with_claims(vec![Some(dependency_propagate_lease_fixture(7)), None])
                .with_dependency_propagate_outcomes(vec![Ok(dependency_propagate_outcome(
                    &[],
                    true,
                    true,
                ))])
                .with_complete_ok(1);
        let compiler = ScriptedCompiler::new(vec![]);
        let summary =
            run_until_claims(store.clone(), compiler.clone(), small_config(vec![7]), 2).await;

        assert_eq!(summary.completed_without_publish, 1);
        assert_eq!(summary.published, 0);
        assert_eq!(summary.pending_retries, 0);
        assert!(compiler.inputs().is_empty());
        assert!(store.publish_commands().is_empty());
        assert!(store.fail_commands().is_empty());
        assert_eq!(store.dependency_propagate_commands().len(), 1);
        assert_eq!(
            store.complete_commands()[0].expected_kind,
            OrgOutboxEventKind::DependencyPropagate
        );
    }

    #[tokio::test]
    async fn dependency_propagate_rejects_malformed_batch_progress() {
        let mut config = small_config(vec![7]);
        config.propagate_batch_limit = 2;
        let store =
            ScriptedStore::with_claims(vec![Some(dependency_propagate_lease_fixture(7)), None])
                .with_dependency_propagate_outcomes(vec![Ok(dependency_propagate_outcome(
                    &[10],
                    false,
                    false,
                ))])
                .with_fail_ok(&["PENDING"]);
        let compiler = ScriptedCompiler::new(vec![]);
        let summary = run_until_claims(store.clone(), compiler, config, 2).await;

        assert_eq!(summary.pending_retries, 1);
        assert_eq!(summary.completed_without_publish, 0);
        assert_eq!(store.dependency_propagate_commands().len(), 1);
        assert!(store.complete_commands().is_empty());
        assert!(store.publish_commands().is_empty());
        let failures = store.fail_commands();
        assert_eq!(failures.len(), 1);
        assert!(failures[0].retryable);
        assert!(failures[0]
            .error
            .starts_with(DEPENDENCY_PROPAGATE_PROGRESS_INCONSISTENT_MACHINE_CODE));
    }

    #[tokio::test]
    async fn malformed_dependency_propagate_payload_is_terminal() {
        let mut lease = dependency_propagate_lease_fixture(7);
        lease.payload_json = "not-json".to_owned();
        let store = ScriptedStore::with_claims(vec![Some(lease), None]).with_fail_ok(&["FAILED"]);
        let compiler = ScriptedCompiler::new(vec![]);
        let summary = run_until_claims(store.clone(), compiler, small_config(vec![7]), 2).await;

        assert_eq!(summary.terminal_failed, 1);
        assert!(store.dependency_propagate_commands().is_empty());
        assert!(store.complete_commands().is_empty());
        assert!(store.publish_commands().is_empty());
        let failures = store.fail_commands();
        assert_eq!(failures.len(), 1);
        assert!(!failures[0].retryable);
        assert!(failures[0]
            .error
            .starts_with(DEPENDENCY_PROPAGATE_PAYLOAD_INVALID_MACHINE_CODE));
    }

    #[tokio::test]
    async fn dependency_propagate_tenant_mismatch_is_terminal() {
        let mut lease = dependency_propagate_lease_fixture(7);
        lease.payload_json = lease
            .payload_json
            .replace("\"anchor_tenant_id\":7", "\"anchor_tenant_id\":8");
        let store = ScriptedStore::with_claims(vec![Some(lease), None]).with_fail_ok(&["FAILED"]);
        let compiler = ScriptedCompiler::new(vec![]);
        let summary = run_until_claims(store.clone(), compiler, small_config(vec![7]), 2).await;

        assert_eq!(summary.terminal_failed, 1);
        assert!(store.dependency_propagate_commands().is_empty());
        assert!(store.complete_commands().is_empty());
        assert!(store.publish_commands().is_empty());
        let failures = store.fail_commands();
        assert_eq!(failures.len(), 1);
        assert!(!failures[0].retryable);
        assert!(failures[0]
            .error
            .starts_with(DEPENDENCY_PROPAGATE_TENANT_MISMATCH_MACHINE_CODE));
    }

    #[tokio::test]
    async fn propagate_superseded_intent_completes_without_publication() {
        // repository 锁内证实意图已被更新拓扑变更取代（安全无写放行）：
        // projector 直接 kind-scoped 完成，绝不重试本批、绝不发布。
        let store = ScriptedStore::with_claims(vec![Some(propagate_lease_fixture(7)), None])
            .with_propagate_outcomes(vec![Ok(propagate_outcome(7, &[], false, true))])
            .with_complete_ok(1);
        let compiler = ScriptedCompiler::new(vec![]);
        let summary =
            run_until_claims(store.clone(), compiler.clone(), small_config(vec![7]), 2).await;

        assert_eq!(summary.completed_without_publish, 1);
        assert_eq!(summary.published, 0);
        assert_eq!(summary.pending_retries, 0);
        assert_eq!(summary.terminal_failed, 0);
        assert!(compiler.inputs().is_empty());
        assert!(store.publish_commands().is_empty());
        assert!(store.fail_commands().is_empty());
        assert_eq!(store.propagate_commands().len(), 1);
        assert_eq!(store.complete_commands().len(), 1);
        assert_eq!(
            store.complete_commands()[0].expected_kind,
            OrgOutboxEventKind::SubtreePropagate
        );
    }

    #[tokio::test]
    async fn lease_lost_during_propagate_abandons_without_further_writes() {
        let store = ScriptedStore::with_claims(vec![Some(propagate_lease_fixture(7)), None])
            .with_propagate_outcomes(vec![Err(ScriptedError::lease_lost())]);
        let compiler = ScriptedCompiler::new(vec![]);
        let summary =
            run_until_claims(store.clone(), compiler.clone(), small_config(vec![7]), 2).await;

        assert_eq!(summary.lease_lost, 1);
        assert_eq!(summary.completed_without_publish, 0);
        assert!(store.fail_commands().is_empty());
        assert!(store.complete_commands().is_empty());
        assert!(store.publish_commands().is_empty());
        assert_eq!(
            store.propagate_commands().len(),
            1,
            "a lost lease must stop every further write, including later batches"
        );
    }

    #[tokio::test]
    async fn propagate_done_false_with_empty_frontier_records_bounded_retry() {
        // 合同不一致（空前沿）：done=false 的下一前沿必须精确等于 [锚点]，
        // 否则按稳定机码有界重试，绝不改道重定向、绝不无限循环。
        let store = ScriptedStore::with_claims(vec![Some(propagate_lease_fixture(7)), None])
            .with_propagate_outcomes(vec![Ok(OrgSubtreePropagateOutcome {
                updated_tenant_ids: Vec::new(),
                next_frontier: Vec::new(),
                done: false,
                superseded: false,
            })])
            .with_fail_ok(&["PENDING"]);
        let compiler = ScriptedCompiler::new(vec![]);
        let summary =
            run_until_claims(store.clone(), compiler.clone(), small_config(vec![7]), 2).await;

        assert_eq!(summary.pending_retries, 1);
        assert_eq!(summary.completed_without_publish, 0);
        assert_eq!(
            store.propagate_commands().len(),
            1,
            "an inconsistent frontier must not loop forever"
        );
        assert!(store.complete_commands().is_empty());
        assert!(store.publish_commands().is_empty());
        let fails = store.fail_commands();
        assert_eq!(fails.len(), 1);
        assert!(fails[0].retryable);
        assert!(fails[0]
            .error
            .starts_with("code=org_scope.propagate_frontier_inconsistent"));
    }

    #[tokio::test]
    async fn propagate_non_done_frontier_other_than_anchor_never_redirects() {
        // 防御性合同检查：非 done 的异值前沿（如子节点列表 [20]）绝不改道本
        // 事件——前沿重定向会让租约内事件驱动无关租户的传播。
        let store = ScriptedStore::with_claims(vec![Some(propagate_lease_fixture(7)), None])
            .with_propagate_outcomes(vec![Ok(OrgSubtreePropagateOutcome {
                updated_tenant_ids: vec![20],
                next_frontier: vec![20],
                done: false,
                superseded: false,
            })])
            .with_fail_ok(&["PENDING"]);
        let compiler = ScriptedCompiler::new(vec![]);
        let summary = run_until_claims(store.clone(), compiler, small_config(vec![7]), 2).await;

        assert_eq!(summary.pending_retries, 1);
        assert_eq!(summary.completed_without_publish, 0);
        assert_eq!(store.propagate_commands().len(), 1);
        // 重入前沿始终是锚点，绝不跟随伪 store 返回的异值前沿。
        assert_eq!(store.propagate_commands()[0].frontier, vec![7]);
        assert!(store.complete_commands().is_empty());
        assert!(store.publish_commands().is_empty());
        let fails = store.fail_commands();
        assert_eq!(fails.len(), 1);
        assert!(fails[0].retryable);
        assert!(fails[0]
            .error
            .starts_with("code=org_scope.propagate_frontier_inconsistent"));
        assert!(fails[0].error.contains("anchor=7"));
    }

    #[tokio::test]
    async fn malformed_propagate_payload_is_terminal_and_never_propagated() {
        let mut lease = propagate_lease_fixture(7);
        lease.payload_json = "not-json".to_owned();
        let store = ScriptedStore::with_claims(vec![Some(lease), None]).with_fail_ok(&["FAILED"]);
        let compiler = ScriptedCompiler::new(vec![]);
        let summary = run_until_claims(store.clone(), compiler, small_config(vec![7]), 2).await;

        assert_eq!(summary.terminal_failed, 1);
        assert!(store.propagate_commands().is_empty());
        assert!(store.complete_commands().is_empty());
        assert!(store.publish_commands().is_empty());
        let fails = store.fail_commands();
        assert_eq!(fails.len(), 1);
        assert!(!fails[0].retryable);
        assert!(fails[0]
            .error
            .starts_with("code=org_scope.propagate_payload_invalid"));
    }

    #[tokio::test]
    async fn propagate_child_tenant_mismatch_is_terminal() {
        let mut lease = propagate_lease_fixture(7);
        // 意图声明 child 8，租约 tenant 7：绝不能驱动跨租户 root 推进。
        lease.payload_json =
            r#"{"child_tenant_id":8,"new_root_tenant_id":9,"relationship_revision":1}"#.to_owned();
        let store = ScriptedStore::with_claims(vec![Some(lease), None]).with_fail_ok(&["FAILED"]);
        let compiler = ScriptedCompiler::new(vec![]);
        let summary = run_until_claims(store.clone(), compiler, small_config(vec![7]), 2).await;

        assert_eq!(summary.terminal_failed, 1);
        assert!(store.propagate_commands().is_empty());
        assert!(store.complete_commands().is_empty());
        let fails = store.fail_commands();
        assert_eq!(fails.len(), 1);
        assert!(!fails[0].retryable);
        assert!(fails[0]
            .error
            .starts_with("code=org_scope.propagate_tenant_mismatch"));
    }

    #[test]
    fn propagate_batch_limit_default_and_bounds_match_repository_caps() {
        let config = OrgScopeProjectorConfig::default();
        assert_eq!(config.propagate_batch_limit, DEFAULT_PROPAGATE_BATCH_LIMIT);
        // 锚点扇出下 done=false 的下一前沿恒为单元素 [锚点]，批行数不再决定
        // 前沿宽度；上限只需镜像 repository 自身的批校验。
        const {
            assert!(DEFAULT_PROPAGATE_BATCH_LIMIT <= MAX_PROPAGATE_BATCH_LIMIT);
        }
        assert_eq!(MAX_PROPAGATE_BATCH_LIMIT, ORG_MAX_PROPAGATE_BATCH);

        let base = |mutate: &dyn Fn(&mut OrgScopeProjectorConfig)| {
            let mut config = OrgScopeProjectorConfig {
                tenants: vec![7],
                ..OrgScopeProjectorConfig::default()
            };
            mutate(&mut config);
            config.validate()
        };
        for bad in [0i64, -5, MAX_PROPAGATE_BATCH_LIMIT + 1] {
            assert!(matches!(
                base(&|config| config.propagate_batch_limit = bad),
                Err(OrgScopeProjectorConfigError::PropagateBatchLimit { value }) if value == bad
            ));
        }
        for good in [1, DEFAULT_PROPAGATE_BATCH_LIMIT, MAX_PROPAGATE_BATCH_LIMIT] {
            assert!(base(&|config| config.propagate_batch_limit = good).is_ok());
        }
    }

    #[test]
    fn parse_config_reads_propagate_batch_limit_override() {
        let parsed = parse_org_scope_projector_config(&OrgScopeProjectorEnvRaw {
            tenants: Some("7".to_owned()),
            propagate_batch_limit: Some("64".to_owned()),
            ..Default::default()
        })
        .expect("valid override must parse");
        assert_eq!(parsed.propagate_batch_limit, 64);

        let error = parse_org_scope_projector_config(&OrgScopeProjectorEnvRaw {
            tenants: Some("7".to_owned()),
            propagate_batch_limit: Some("huge".to_owned()),
            ..Default::default()
        })
        .expect_err("invalid numbers must fail startup");
        assert_eq!(
            error,
            OrgScopeProjectorConfigError::Parse {
                name: ENV_PROPAGATE_BATCH_LIMIT,
                value: "huge".to_owned()
            }
        );
    }
}
