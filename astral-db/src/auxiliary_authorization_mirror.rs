//! 单机辅助授权读面镜像 — org 准入证据与 GlobalAdmin 事实（default-off）。
//!
//! 目标：单机组合进程（`astral-single-node`，hub 已安装且健康）在
//! `PolicyEngine.evaluate()` 正常命中路径上，把两个"同端口两次读取"的辅助
//! 授权端口从逐请求 DB 往返改为进程内镜像命中：
//!
//! - **org 准入证据**：`RuleRepository::load_org_authorization`
//!   （engine.rs 五态门 + `org_admission.rs` ALLOW 前复读，同端口两次）。
//!   事实面 = org_scope gate/node/publication/membership + 物理卡绑定，
//!   全部由既有严格 reader（`probe_org_scope_gate` +
//!   `load_admission_evidence_in_pool`）装配，本模块**不构造**任何事实。
//! - **GlobalAdmin 事实**：`RuleRepository::is_active_global_admin`
//!   （Global 控制面 ownership 门 + ALLOW 前复读，同端口两次）。事实面 =
//!   `identity_global_admin` ACTIVE 行计数，复用 [`crate::is_active_global_admin`]
//!   严格读取；绝不复用 TrustGraph 管理展示缓存。
//!
//! ## 镜像与权威边界（与 memory_projection_hub 同源的不变式）
//!
//! - **只缓存严格 verified evidence**：org 侧缓存 `Ready` 证据、`Disabled`
//!   与 `TenantUnmanaged`（未纳入行政治理的权威 legacy 路由事实）三种可信
//!   值，GA 侧缓存 ACTIVE 布尔事实；`SchemaUnmanaged`（schema 归属由未栅栏
//!   的 migration/DDL 控制，不在 org 纪元语义内）与 `Pending` /
//!   `Unavailable` / 任何基础设施失败**永不缓存**，逐次回源既有 DB 链。
//!   pending/unknown 永不缓存 ALLOW，也永不缓存可能掩盖依赖故障的
//!   Unavailable。因此"进程内零 DB 命中"只适用于 Ready / Disabled /
//!   TenantUnmanaged / GA 条目命中；`SchemaUnmanaged` 端口仍逐次读 DB。
//! - **TenantUnmanaged 缓存的事实边界**：该值 = "org_scope_node 表存在且
//!   该租户无 node 行"，全部来自严格 gate 读取（[`probe_org_scope_gate`]），
//!   本模块零构造。org node 行的生产唯一写点是 org authority 事务
//!   （`begin_authority_tx` → org 纪元在 begin/drop 双向推进），生产路径
//!   不存在 node 行删除，因此 Unmanaged→Managed 转换必然推进纪元并使旧
//!   条目立即失效；TTL 过期只触发同源严格重探，绝不把缓存值当持久结论。
//!   它与 `Ready` 共用同一 token/纪元/TTL/容量/single-flight 协议。
//! - **纪元失效**：条目可信要求"安装纪元 == 当前纪元"。org 纪元由 org
//!   authority 事实写点的 RAII 栅栏（`begin_org_source_transaction`）与 org
//!   镜像整体失效推进；GA 纪元由任何 generic source writer begin/drop 推进
//!   （GA/user_card 写者身份在 hub 侧不可归因，保守全失效）。warm-up、
//!   reconcile、suspect 同步推进双纪元。
//! - **writer-active 直接 fail-closed**：`active_source_writers > 0` 时 org
//!   返回 `Pending{single_node_writer_active}`、GA 返回 `Err(PolicyError)`，
//!   绝不回源旧状态放行，也绝不 serve 镜像条目。
//! - **两读之间 mutation 拒绝**：第一次读取命中镜像（纪元 E）后，任何 source
//!   事务都会推进纪元；第二次读取发现纪元不符时**绝不 serve 旧缓存条目**，
//!   要么 single-flight 严格回填当前真值（与既有 DB 路径逐字节同源），要么
//!   回落既有 DB 链 —— 永不放大既有放行面。
//! - **serve 时重验**：`Ready` 证据在每次命中时刷新 `checked_at_unix = now`
//!   并重跑 `OrgAdmissionEvidence::validate()`（内含 membership 在新时钟下的
//!   有效期判定）；任何重验失败转入严格回填，由 DB 权威裁定（例如
//!   `MembershipExpired` 的确定性业务 pending）。
//! - **多节点禁用**：镜像要求 hub 已安装且通道健康（heartbeat 新鲜）；hub
//!   未安装（Rabbit/多节点部署）时本模块整体 no-op，端口走既有 strict DB
//!   读取，不声称跨节点零 IO。
//! - **容量有界**：entries 上限 + 估算字节上限 + TTL（仅 GC 语义，正确性
//!   完全来自纪元门）；超限时先惰性逐出过期条目，仍超限则拒绝安装（读回
//!   DB = 现状语义，绝不 suspect 整个 hub —— 辅助镜像只是加速层）。
//! - **回填 single-flight**：同键并发只放一个严格回源，其余等结果或命中
//!   已回填条目；对齐 `MemoryProjectionHub::strict_refill` 的等待/容量语义。
//!
//! ## default-off 与激活前提
//!
//! 未调用 [`install_auxiliary_authorization_mirror`] 时全部钩子 no-op
//! （多节点/Rabbit 部署与独立服务进程均不安装）。生产唯一装配方是单机
//! 组合进程（`astral-single-node`）：持有单写者租约、投影镜像 warm-up
//! 完成**之后**才安装本镜像，随后才放行业务服务（装配顺序由 single-node
//! 启动自检钉住：warm-up < 镜像安装 < 服务 spawn）。激活前提（缺一不可，
//! 由装配方保证）：
//! 1. 单写者租约已持有、hub 已安装并完成 warm-up、通道健康；
//! 2. **全部**影响镜像事实面的 source writer 已持 hub 栅栏：org 事实写点
//!    由 `OrgAuthorityTx` 覆盖；TrustGraph source 事务、astral-identity 卡
//!    写路径与 org 写路径均先取 generic writer 栅栏（hub 已装则栅栏必须
//!    可得，取不到即拒绝写入，绝不静默 no-op）；
//! 3. `org_scope_enabled` 冻结值与宿主进程 `SqlxRuleRepository` 相同来源，
//!    避免 Disabled/Ready 判定 split-brain。

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex, OnceLock, RwLock, Weak};
use std::time::{Duration, Instant};

use astral_types::org_scope::{OrgAdmissionEvidence, OrgAdmissionResult};
use astral_types::{PolicyContext, PolicyError};
use policy_engine::org_admission::OrgAuthorityRead;
use sqlx::MySqlPool;

use crate::memory_projection_hub::{AuxiliaryReadGate, AuxiliaryReadToken, MemoryProjectionHub};
use crate::org_scope_repository::{
    load_admission_evidence_in_pool, probe_org_scope_gate, OrgAdmissionQuery, OrgScopeGateState,
};

static GLOBAL_AUXILIARY_MIRROR: OnceLock<AuxiliaryAuthorizationMirror> = OnceLock::new();

/// 安装进程级辅助授权镜像（单机组合进程启动期调用一次；重复安装返回 false）。
///
/// `org_scope_enabled` 必须与宿主进程 `SqlxRuleRepository::with_org_scope_enabled`
/// 同源冻结；镜像据此复现 `Disabled` 五态，绝不越过启动期旗标放行受管租户。
pub fn install_auxiliary_authorization_mirror(pool: MySqlPool, org_scope_enabled: bool) -> bool {
    let mirror = AuxiliaryAuthorizationMirror::new(pool, org_scope_enabled);
    GLOBAL_AUXILIARY_MIRROR.set(mirror).is_ok()
}

/// 进程级辅助镜像句柄；未安装返回 `None`（全部端口回落既有 DB 链）。
pub fn auxiliary_authorization_mirror() -> Option<AuxiliaryAuthorizationMirror> {
    GLOBAL_AUXILIARY_MIRROR.get().cloned()
}

/// 辅助镜像条目 TTL：仅 GC/容量语义。正确性不依赖 TTL —— 纪元门保证任何
/// source mutation 后条目失效；TTL 只约束无写入时的驻留上界。
pub(crate) const AUXILIARY_MIRROR_TTL: Duration = Duration::from_secs(300);

/// org 条目容量上限（全键条数）。
pub(crate) const MAX_ORG_MIRROR_ENTRIES: usize = 4_096;
/// GlobalAdmin 条目容量上限。
pub(crate) const MAX_GLOBAL_ADMIN_MIRROR_ENTRIES: usize = 4_096;
/// 双族共享的条目估算字节总量上限。org 侧按条目序列化体量记账；GA 条目
/// 体量恒定且由条目数上限界定（不进字节账本），32MB 预算实际约束的是
/// org `Ready` 证据载荷。
pub(crate) const MAX_AUXILIARY_MIRROR_BYTES: u64 = 32 * 1024 * 1024;

/// single-flight 回填的并发 scope 上限与等待预算（对齐 hub strict_refill）。
const MAX_REFILL_SCOPES: usize = 1_024;
const REFILL_LOCK_WAIT: Duration = Duration::from_secs(3);
const REFILL_QUERY_DEADLINE: Duration = Duration::from_secs(3);

fn org_pending(reason: &str) -> OrgAuthorityRead {
    OrgAuthorityRead::Pending {
        code: format!("org_scope.pending.{reason}"),
    }
}

fn global_admin_unavailable(reason: &str) -> Result<bool, PolicyError> {
    Err(PolicyError::Repository(format!(
        "global_admin_mirror.{reason}"
    )))
}

/// org 镜像全键：tenant/user/identity_card/card 全量身份，绝不跨键命中。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct OrgMirrorKey {
    pub tenant_id: i64,
    pub user_id: i64,
    pub identity_card_id: Option<i64>,
    pub card_id: i64,
}

/// org 镜像可信值：严格 reader 产物的保守子集。
#[derive(Debug, Clone)]
pub(crate) enum OrgMirrorValue {
    /// 租户受管但启动期冻结旗标关闭 → Disabled。
    Disabled,
    /// 租户未被纳入行政治理（`org_scope_node` 表存在且无 node 行）：权威
    /// legacy 路由事实（引擎按 Unmanaged 走 legacy 评估，绝非 deny）。仅在
    /// 严格 gate 读取成功时缓存；node 行唯一生产写点是受栅栏的 org
    /// authority 事务，Unmanaged→Managed 转换必然推进纪元使本条目失效。
    Unmanaged,
    /// 严格装配的准入证据（serve 时刷新时钟并整体重验）。
    Ready(Arc<OrgAdmissionEvidence>),
}

impl OrgMirrorValue {
    fn to_authority_read(&self) -> OrgAuthorityRead {
        match self {
            OrgMirrorValue::Disabled => OrgAuthorityRead::Disabled,
            OrgMirrorValue::Unmanaged => OrgAuthorityRead::Unmanaged,
            OrgMirrorValue::Ready(evidence) => {
                OrgAuthorityRead::Ready(Box::new(evidence.as_ref().clone()))
            }
        }
    }

    fn estimated_bytes(&self) -> u64 {
        match self {
            // 序列化失败 = 字节不可估计 → u64::MAX 必然超出字节上限，
            // install 判定拒绝安装（读回 DB，绝不误装无法计量的条目）。
            OrgMirrorValue::Ready(evidence) => serde_json::to_vec(evidence.as_ref())
                .map(|bytes| bytes.len() as u64)
                .unwrap_or(u64::MAX)
                .saturating_add(512),
            OrgMirrorValue::Disabled | OrgMirrorValue::Unmanaged => 64,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct OrgMirrorEntry {
    pub installed_at: Instant,
    pub org_epoch: u64,
    pub value: OrgMirrorValue,
}

#[derive(Debug, Clone)]
pub(crate) struct GlobalAdminMirrorEntry {
    pub installed_at: Instant,
    pub global_admin_epoch: u64,
    pub active: bool,
}

#[derive(Default)]
struct MirrorMaps {
    org: HashMap<OrgMirrorKey, OrgMirrorEntry>,
    global_admin: HashMap<i64, GlobalAdminMirrorEntry>,
    org_bytes: u64,
}

impl MirrorMaps {
    fn evict_expired(&mut self, now: Instant) {
        self.org
            .retain(|_, entry| entry_age(entry.installed_at, now) <= AUXILIARY_MIRROR_TTL);
        self.org_bytes = self
            .org
            .values()
            .map(|entry| entry.value.estimated_bytes())
            .fold(0u64, u64::saturating_add);
        self.global_admin
            .retain(|_, entry| entry_age(entry.installed_at, now) <= AUXILIARY_MIRROR_TTL);
    }
}

fn entry_age(installed_at: Instant, now: Instant) -> Duration {
    now.saturating_duration_since(installed_at)
}

fn now_unix_seconds() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// org 条目 serve 判定（纯函数）：命中时刷新读取时钟并整体重验。
pub(crate) enum OrgServeDecision {
    /// 命中 Ready：证据携带刷新后的 `checked_at_unix`（调用方包成 Ready）。
    ServeReady(Box<OrgAdmissionEvidence>),
    /// 命中静态事实（Disabled / Unmanaged）：直接转发权威判定，绝不改写
    /// （Disabled = 受管但旗标关闭；Unmanaged = 未纳入行政治理，由引擎
    /// legacy 路由 —— 两者都不是 deny 偏置）。
    ServeStatic(OrgAuthorityRead),
    /// 纪元变更/TTL 过期/重验失败：绝不 serve 旧条目，转入严格回填。
    Stale,
}

pub(crate) fn org_entry_serve_decision(
    entry: &OrgMirrorEntry,
    current_org_epoch: u64,
    now_unix: i64,
    now: Instant,
) -> OrgServeDecision {
    if entry.org_epoch != current_org_epoch
        || entry_age(entry.installed_at, now) > AUXILIARY_MIRROR_TTL
    {
        return OrgServeDecision::Stale;
    }
    match &entry.value {
        OrgMirrorValue::Disabled => OrgServeDecision::ServeStatic(OrgAuthorityRead::Disabled),
        OrgMirrorValue::Unmanaged => OrgServeDecision::ServeStatic(OrgAuthorityRead::Unmanaged),
        OrgMirrorValue::Ready(evidence) => {
            let mut refreshed = evidence.as_ref().clone();
            refreshed.checked_at_unix = now_unix;
            // validate() 内含 membership 在新时钟下的有效期与 node/publication
            // 栅栏恒等复验；任何失败 → 转严格回填由 DB 权威裁定。
            if refreshed.validate().is_ok() {
                OrgServeDecision::ServeReady(Box::new(refreshed))
            } else {
                OrgServeDecision::Stale
            }
        }
    }
}

/// 回填期间纪元推进时不得返回旧事实，调用方必须保持 Pending/Err。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefillInstallDecision {
    Install,
    Reject,
}

pub(crate) fn refill_install_decision(
    epoch_before: u64,
    epoch_after: u64,
) -> RefillInstallDecision {
    if epoch_before == epoch_after {
        RefillInstallDecision::Install
    } else {
        RefillInstallDecision::Reject
    }
}

/// 容量判定（纯函数；惰性逐出过期后仍超限 → 拒绝安装，读回 DB）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CapacityVerdict {
    Admit,
    Refuse,
}

pub(crate) fn capacity_verdict(
    current_entries: usize,
    max_entries: usize,
    projected_bytes: u64,
    max_bytes: u64,
) -> CapacityVerdict {
    if current_entries >= max_entries || projected_bytes > max_bytes {
        CapacityVerdict::Refuse
    } else {
        CapacityVerdict::Admit
    }
}

/// org 严格回填结果：`Cacheable` = 严格 reader 的可信产物；
/// `Uncacheable` = 确定性业务 Pending（永不缓存，逐次回源）。
enum OrgRefillRead {
    Cacheable(OrgMirrorValue),
    Uncacheable(OrgAuthorityRead),
}

struct MirrorInner {
    pool: MySqlPool,
    org_scope_enabled: bool,
    maps: RwLock<MirrorMaps>,
    org_refills: Mutex<HashMap<OrgMirrorKey, Weak<tokio::sync::Mutex<()>>>>,
    global_admin_refills: Mutex<HashMap<i64, Weak<tokio::sync::Mutex<()>>>>,
}

/// 单机辅助授权镜像。克隆共享同一状态（Arc）。
#[derive(Clone)]
pub struct AuxiliaryAuthorizationMirror {
    inner: Arc<MirrorInner>,
}

impl AuxiliaryAuthorizationMirror {
    pub(crate) fn new(pool: MySqlPool, org_scope_enabled: bool) -> Self {
        Self {
            inner: Arc::new(MirrorInner {
                pool,
                org_scope_enabled,
                maps: RwLock::new(MirrorMaps::default()),
                org_refills: Mutex::new(HashMap::new()),
                global_admin_refills: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// 冻结的 ORG_SCOPE 旗标（诊断用）。
    #[must_use]
    pub fn org_scope_enabled(&self) -> bool {
        self.inner.org_scope_enabled
    }

    fn org_refill_lock(&self, key: &OrgMirrorKey) -> Option<Arc<tokio::sync::Mutex<()>>> {
        let mut scopes = self.inner.org_refills.lock().ok()?;
        scopes.retain(|_, lock| lock.strong_count() != 0);
        if let Some(lock) = scopes.get(key).and_then(Weak::upgrade) {
            return Some(lock);
        }
        if scopes.len() >= MAX_REFILL_SCOPES {
            return None;
        }
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        scopes.insert(*key, Arc::downgrade(&lock));
        Some(lock)
    }

    fn global_admin_refill_lock(&self, user_id: i64) -> Option<Arc<tokio::sync::Mutex<()>>> {
        let mut scopes = self.inner.global_admin_refills.lock().ok()?;
        scopes.retain(|_, lock| lock.strong_count() != 0);
        if let Some(lock) = scopes.get(&user_id).and_then(Weak::upgrade) {
            return Some(lock);
        }
        if scopes.len() >= MAX_REFILL_SCOPES {
            return None;
        }
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        scopes.insert(user_id, Arc::downgrade(&lock));
        Some(lock)
    }

    // ─────────────────────────────────────────────────────────────────────
    // org 准入证据端口
    // ─────────────────────────────────────────────────────────────────────

    /// `load_org_authorization` 镜像入口。
    ///
    /// 返回 `Some(read)` = 已按镜像语义给出结论：全部不确定/竞争/超时/
    /// 容量耗尽一律 fail-closed `Pending`，绝不放大放行面；`None` 仅当
    /// hub 辅助读门为 `StrictRequired`（hub 未安装/未完成 warm-up/通道
    /// 不健康或心跳过期），装饰器必须回落既有 DB 严格链 —— 与现状逐字节
    /// 同语义。
    pub async fn load_org_authorization(
        &self,
        hub: &MemoryProjectionHub,
        ctx: &PolicyContext,
    ) -> Option<OrgAuthorityRead> {
        let (Some(tenant_id), Some(user_id), Some(identity_card_id), Some(card_id)) = (
            ctx.tenant_id,
            ctx.user_id,
            ctx.identity_card_id,
            ctx.card_id,
        ) else {
            // 与 SqlxRuleRepository 同码：身份不完整是确定性业务 pending，
            // 无需任何 IO。
            return Some(OrgAuthorityRead::Pending {
                code: "org_scope.pending.context_missing".to_owned(),
            });
        };
        let token = match hub.auxiliary_read_gate() {
            AuxiliaryReadGate::Ready(token) => token,
            AuxiliaryReadGate::WriterActive => {
                return Some(org_pending("single_node_writer_active"))
            }
            AuxiliaryReadGate::Uncertain => return Some(org_pending("source_outcome_unknown")),
            AuxiliaryReadGate::StrictRequired => return None,
        };
        let key = OrgMirrorKey {
            tenant_id,
            user_id,
            identity_card_id: Some(identity_card_id),
            card_id,
        };
        self.org_authorization_with_strict_refill(hub, key, token, || {
            self.org_strict_read(tenant_id, user_id, identity_card_id, card_id)
        })
        .await
    }

    /// 镜像读协议本体：命中/单飞/超时/纪元栅栏全部在此，严格回源以
    /// `strict_refill` future 工厂注入（生产入口传既有 DB 严格 reader，
    /// 同 crate 测试注入受控 fake —— 仅私有可见，不构成公开替代权威）。
    ///
    /// 契约：工厂至多被调用一次（single-flight 锁持有者）；工厂 future 由
    /// [`REFILL_QUERY_DEADLINE`] 硬 deadline 包裹，超时即 drop（取消回源）
    /// 并 fail-closed Pending，绝不二次查询、绝不回落旧值。
    async fn org_authorization_with_strict_refill<F, Fut>(
        &self,
        hub: &MemoryProjectionHub,
        key: OrgMirrorKey,
        token: AuxiliaryReadToken,
        strict_refill: F,
    ) -> Option<OrgAuthorityRead>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Option<OrgRefillRead>>,
    {
        if let Some(hit) = self.org_cache_serve(&key, token) {
            return Some(if hub.auxiliary_read_matches(token) {
                hit
            } else {
                org_pending("invalidation_raced_read")
            });
        }
        let lock = match self.org_refill_lock(&key) {
            Some(lock) => lock,
            None => return Some(org_pending("refill_capacity_exhausted")),
        };
        let _guard = match tokio::time::timeout(REFILL_LOCK_WAIT, lock.lock()).await {
            Ok(guard) => guard,
            Err(_) => return Some(org_pending("refill_wait_timeout")),
        };
        if !hub.auxiliary_read_matches(token) {
            return Some(org_pending("invalidation_raced_refill"));
        }
        if let Some(hit) = self.org_cache_serve(&key, token) {
            return Some(if hub.auxiliary_read_matches(token) {
                hit
            } else {
                org_pending("invalidation_raced_read")
            });
        }
        let read = match tokio::time::timeout(REFILL_QUERY_DEADLINE, strict_refill()).await {
            Ok(Some(read)) => read,
            Ok(None) => return Some(org_pending("strict_refill_unavailable")),
            Err(_) => return Some(org_pending("strict_refill_timeout")),
        };
        if refill_install_decision(token.org_epoch, hub.auxiliary_org_epoch())
            == RefillInstallDecision::Reject
            || !hub.auxiliary_read_matches(token)
        {
            return Some(org_pending("invalidation_raced_refill"));
        }
        let result = match read {
            OrgRefillRead::Cacheable(value) => {
                self.install_org(&key, value.clone(), token.org_epoch);
                value.to_authority_read()
            }
            OrgRefillRead::Uncacheable(read) => read,
        };
        Some(if hub.auxiliary_read_matches(token) {
            result
        } else {
            org_pending("invalidation_raced_read")
        })
    }

    /// 命中 serve（纯读锁内完成判定；任何失败 → `None` 回填）。
    fn org_cache_serve(
        &self,
        key: &OrgMirrorKey,
        token: AuxiliaryReadToken,
    ) -> Option<OrgAuthorityRead> {
        let maps = self.inner.maps.read().ok()?;
        let entry = maps.org.get(key)?;
        match org_entry_serve_decision(entry, token.org_epoch, now_unix_seconds(), Instant::now()) {
            OrgServeDecision::ServeReady(evidence) => Some(OrgAuthorityRead::Ready(evidence)),
            OrgServeDecision::ServeStatic(read) => Some(read),
            OrgServeDecision::Stale => None,
        }
    }

    /// 严格回填：复用既有 gate probe + 准入证据严格 reader，本模块零事实构造。
    async fn org_strict_read(
        &self,
        tenant_id: i64,
        user_id: i64,
        identity_card_id: i64,
        card_id: i64,
    ) -> Option<OrgRefillRead> {
        match probe_org_scope_gate(&self.inner.pool, tenant_id).await {
            // 严格 gate 读取的权威 legacy 路由事实（表存在且无 node 行，
            // 本模块零构造）：与 Ready 共用同一纪元/容量/single-flight 协议
            // 缓存。node 行的生产唯一写点是受栅栏的 org authority 事务
            // （begin/drop 双向推进纪元），Unmanaged→Managed 转换必然使旧
            // 条目失效；TTL 过期只触发同源重探。
            OrgScopeGateState::TenantUnmanaged => {
                Some(OrgRefillRead::Cacheable(OrgMirrorValue::Unmanaged))
            }
            // schema 归属由 migration/DDL 控制、不在 org 纪元语义内：权威
            // 判定但禁止缓存，逐次回源既有 DB 链重取（缺 schema 绝不落缓存）。
            OrgScopeGateState::SchemaUnmanaged => {
                Some(OrgRefillRead::Uncacheable(OrgAuthorityRead::Unmanaged))
            }
            // gate 基础设施失败：回落既有 DB 链（现状语义），绝不缓存。
            OrgScopeGateState::Pending => None,
            OrgScopeGateState::TenantManaged { .. } if !self.inner.org_scope_enabled => {
                Some(OrgRefillRead::Cacheable(OrgMirrorValue::Disabled))
            }
            OrgScopeGateState::TenantManaged { .. } => {
                let query = OrgAdmissionQuery {
                    tenant_id,
                    user_id,
                    card_id,
                    identity_card_id: Some(identity_card_id),
                    now_unix_seconds: now_unix_seconds(),
                };
                match load_admission_evidence_in_pool(&self.inner.pool, &query).await {
                    Ok(OrgAdmissionResult::Evidence(evidence)) => Some(OrgRefillRead::Cacheable(
                        OrgMirrorValue::Ready(Arc::new(*evidence)),
                    )),
                    Ok(OrgAdmissionResult::Pending { code, .. }) => {
                        Some(OrgRefillRead::Uncacheable(OrgAuthorityRead::Pending {
                            code: code.as_machine_code().to_owned(),
                        }))
                    }
                    Err(_) => None,
                }
            }
        }
    }

    fn install_org(&self, key: &OrgMirrorKey, value: OrgMirrorValue, epoch: u64) {
        let Ok(mut maps) = self.inner.maps.write() else {
            return;
        };
        maps.evict_expired(Instant::now());
        let projected = maps
            .org_bytes
            .saturating_sub(
                maps.org
                    .get(key)
                    .map(|entry| entry.value.estimated_bytes())
                    .unwrap_or(0),
            )
            .saturating_add(value.estimated_bytes());
        if capacity_verdict(
            maps.org.len(),
            MAX_ORG_MIRROR_ENTRIES,
            projected,
            MAX_AUXILIARY_MIRROR_BYTES,
        ) == CapacityVerdict::Refuse
        {
            tracing::debug!(
                tenant_id = key.tenant_id,
                user_id = key.user_id,
                card_id = key.card_id,
                "auxiliary org mirror capacity exhausted; reads stay on the durable path"
            );
            return;
        }
        maps.org_bytes = projected;
        maps.org.insert(
            *key,
            OrgMirrorEntry {
                installed_at: Instant::now(),
                org_epoch: epoch,
                value,
            },
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // GlobalAdmin 事实端口
    // ─────────────────────────────────────────────────────────────────────

    /// `is_active_global_admin` 镜像入口。语义同 org 端口：不确定/竞争/
    /// 超时/容量耗尽一律 `Err(PolicyError)` fail-closed；`None` 仅当 hub
    /// 辅助读门为 `StrictRequired`，装饰器回落既有 DB 严格链。
    pub async fn is_active_global_admin(
        &self,
        hub: &MemoryProjectionHub,
        user_id: i64,
    ) -> Option<Result<bool, PolicyError>> {
        if user_id <= 0 {
            return Some(Ok(false));
        }
        let token = match hub.auxiliary_read_gate() {
            AuxiliaryReadGate::Ready(token) => token,
            AuxiliaryReadGate::WriterActive => {
                return Some(global_admin_unavailable("writer_active"))
            }
            AuxiliaryReadGate::Uncertain => {
                return Some(global_admin_unavailable("source_outcome_unknown"))
            }
            AuxiliaryReadGate::StrictRequired => return None,
        };
        self.global_admin_with_strict_refill(hub, user_id, token, || async {
            // 既有严格 reader 以 sqlx::Error 失败；镜像协议统一按
            // PolicyError 表达（载荷在 strict_refill_unavailable 分支被
            // 丢弃，仅保留类型与可追溯文本，不改变任何可观测语义）。
            crate::is_active_global_admin(&self.inner.pool, user_id)
                .await
                .map_err(|error| {
                    PolicyError::Repository(format!(
                        "global_admin_mirror.strict_read_error: {error}"
                    ))
                })
        })
        .await
    }

    /// GA 镜像读协议本体：契约同 [`Self::org_authorization_with_strict_refill`]
    /// （工厂至多调用一次、严格回源带硬 deadline、纪元/token 栅栏拒绝安装
    /// 与 serve 旧值）。
    async fn global_admin_with_strict_refill<F, Fut>(
        &self,
        hub: &MemoryProjectionHub,
        user_id: i64,
        token: AuxiliaryReadToken,
        strict_refill: F,
    ) -> Option<Result<bool, PolicyError>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<bool, PolicyError>>,
    {
        if let Some(active) = self.global_admin_cache_serve(user_id, token) {
            return Some(if hub.auxiliary_read_matches(token) {
                Ok(active)
            } else {
                global_admin_unavailable("invalidation_raced_read")
            });
        }
        let lock = match self.global_admin_refill_lock(user_id) {
            Some(lock) => lock,
            None => return Some(global_admin_unavailable("refill_capacity_exhausted")),
        };
        let _guard = match tokio::time::timeout(REFILL_LOCK_WAIT, lock.lock()).await {
            Ok(guard) => guard,
            Err(_) => return Some(global_admin_unavailable("refill_wait_timeout")),
        };
        if !hub.auxiliary_read_matches(token) {
            return Some(global_admin_unavailable("invalidation_raced_refill"));
        }
        if let Some(active) = self.global_admin_cache_serve(user_id, token) {
            return Some(if hub.auxiliary_read_matches(token) {
                Ok(active)
            } else {
                global_admin_unavailable("invalidation_raced_read")
            });
        }
        let active = match tokio::time::timeout(REFILL_QUERY_DEADLINE, strict_refill()).await {
            Ok(Ok(active)) => active,
            Ok(Err(_)) => return Some(global_admin_unavailable("strict_refill_unavailable")),
            Err(_) => return Some(global_admin_unavailable("strict_refill_timeout")),
        };
        if refill_install_decision(token.global_admin_epoch, hub.auxiliary_global_admin_epoch())
            == RefillInstallDecision::Reject
            || !hub.auxiliary_read_matches(token)
        {
            return Some(global_admin_unavailable("invalidation_raced_refill"));
        }
        self.install_global_admin(user_id, active, token.global_admin_epoch);
        Some(if hub.auxiliary_read_matches(token) {
            Ok(active)
        } else {
            global_admin_unavailable("invalidation_raced_read")
        })
    }

    fn global_admin_cache_serve(&self, user_id: i64, token: AuxiliaryReadToken) -> Option<bool> {
        let maps = self.inner.maps.read().ok()?;
        let entry = maps.global_admin.get(&user_id)?;
        (entry.global_admin_epoch == token.global_admin_epoch
            && entry_age(entry.installed_at, Instant::now()) <= AUXILIARY_MIRROR_TTL)
            .then_some(entry.active)
    }

    fn install_global_admin(&self, user_id: i64, active: bool, epoch: u64) {
        let Ok(mut maps) = self.inner.maps.write() else {
            return;
        };
        maps.evict_expired(Instant::now());
        // GA 条目体量恒定（常数小条目），由条目数上限单独界定，不进字节
        // 账本；此处 projected 恒为 0，32MB 预算由 org 侧记账守护。
        if capacity_verdict(
            maps.global_admin.len(),
            MAX_GLOBAL_ADMIN_MIRROR_ENTRIES,
            0,
            MAX_AUXILIARY_MIRROR_BYTES,
        ) == CapacityVerdict::Refuse
        {
            tracing::debug!(
                user_id,
                "auxiliary global-admin mirror capacity exhausted; reads stay on the durable path"
            );
            return;
        }
        maps.global_admin.insert(
            user_id,
            GlobalAdminMirrorEntry {
                installed_at: Instant::now(),
                global_admin_epoch: epoch,
                active,
            },
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // 失效
    // ─────────────────────────────────────────────────────────────────────

    /// org authority source transaction **证明 commit 成功**后调用：整体清空
    /// org 条目。纪元推进由 `OrgSourceTransactionGuard` Drop 完成，此处只做
    /// 内存回收 —— 两者叠加保证任何 org mutation 后旧条目立即不可命中。
    pub(crate) fn evict_all_org(&self) {
        if let Ok(mut maps) = self.inner.maps.write() {
            maps.org.clear();
            maps.org_bytes = 0;
        }
    }

    /// 测试/诊断：当前 org 条目数。
    #[cfg(test)]
    pub(crate) fn org_entry_count(&self) -> usize {
        self.inner
            .maps
            .read()
            .map(|maps| maps.org.len())
            .unwrap_or(0)
    }

    /// 测试播种：以指定纪元直接安装 org 条目（同 crate 纯测试用；生产路径
    /// 唯一安装入口是严格回填）。
    #[cfg(test)]
    pub(crate) fn seed_org_entry_for_test(
        &self,
        key: OrgMirrorKey,
        value: OrgMirrorValue,
        epoch: u64,
    ) {
        let mut maps = self.inner.maps.write().expect("mirror maps lock");
        maps.org.insert(
            key,
            OrgMirrorEntry {
                installed_at: Instant::now(),
                org_epoch: epoch,
                value,
            },
        );
    }

    /// 测试播种：以指定纪元直接安装 GA 条目。
    #[cfg(test)]
    pub(crate) fn seed_global_admin_entry_for_test(&self, user_id: i64, active: bool, epoch: u64) {
        let mut maps = self.inner.maps.write().expect("mirror maps lock");
        maps.global_admin.insert(
            user_id,
            GlobalAdminMirrorEntry {
                installed_at: Instant::now(),
                global_admin_epoch: epoch,
                active,
            },
        );
    }

    /// 测试/诊断：当前 GA 条目数。
    #[cfg(test)]
    pub(crate) fn global_admin_entry_count(&self) -> usize {
        self.inner
            .maps
            .read()
            .map(|maps| maps.global_admin.len())
            .unwrap_or(0)
    }
}

#[cfg(test)]
#[allow(clippy::await_holding_lock)]
mod tests {
    // Hub writers clear process-wide eligibility caches, so these tests share their state lock.
    use super::*;
    use astral_types::org_scope::{
        org_build_segment, org_manifest_digest_hex, OrgContribution, OrgGrant, OrgGrantRef,
        OrgManifestDigestMaterial, OrgMembership, OrgNode, OrgProvenance, OrgPublication,
        OrgRootActivation, OrgScope, OrgScopeKey, OrgSegmentContent,
    };
    use astral_types::ValidityWindow;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::oneshot;

    const TENANT: i64 = 100;
    const ROOT: i64 = 100;
    const USER: i64 = 11;
    const IDENTITY_CARD: i64 = 111;
    const CARD: i64 = 222;

    fn uuid(seed: u8) -> String {
        format!("00000000-0000-0000-0000-{seed:012}")
    }

    fn validity() -> ValidityWindow {
        // 覆盖真实 wall clock（2026 年代约 1.8e9），避免睡眠式时间测试。
        ValidityWindow::between(0, 9_999_999_999)
    }

    fn scope_value() -> OrgScope {
        OrgScope {
            resource_tenant_id: TENANT,
            domain_id: None,
            resource: "doc:42".to_owned(),
            action: "read".to_owned(),
            validity: validity(),
        }
    }

    fn grant_value() -> OrgGrant {
        OrgGrant {
            grant_id: uuid(1),
            revision: 1,
            receiving_tenant_id: TENANT,
            origin_tenant_id: TENANT,
            root_tenant_id: ROOT,
            scope: scope_value(),
            delegable: true,
            parent: None,
            subject: None,
            active: true,
            operation_id: "op-grant-1".to_owned(),
        }
    }

    fn contribution_value(grant: &OrgGrant) -> OrgContribution {
        OrgContribution {
            grant_ref: OrgGrantRef {
                tenant_id: grant.receiving_tenant_id,
                grant_id: grant.grant_id.clone(),
                revision: grant.revision,
            },
            scope: grant.scope.clone(),
            delegable: grant.delegable,
            subject: grant.subject,
            provenance: OrgProvenance {
                origin_tenant_id: grant.origin_tenant_id,
                parent_chain: Vec::new(),
                operation_id: grant.operation_id.clone(),
            },
        }
    }

    fn publication_value() -> OrgPublication {
        let grant = grant_value();
        let content = OrgSegmentContent {
            key: OrgScopeKey {
                resource: "doc:42".to_owned(),
                action: "read".to_owned(),
            },
            contributions: vec![contribution_value(&grant)],
        };
        let segment = org_build_segment(0, content).unwrap();
        let publication = OrgPublication {
            tenant_id: TENANT,
            root_tenant_id: ROOT,
            generation: 3,
            relationship_revision: 2,
            revoke_fence: 1,
            dependencies: Vec::new(),
            manifest_digest_hex: String::new(),
            compiler_version: "org-compiler-v1".to_owned(),
            segments: vec![segment],
            operation_id: "op-publish-1".to_owned(),
        };
        let manifest_digest_hex = org_manifest_digest_hex(&OrgManifestDigestMaterial {
            tenant_id: publication.tenant_id,
            root_tenant_id: publication.root_tenant_id,
            generation: publication.generation,
            relationship_revision: publication.relationship_revision,
            revoke_fence: publication.revoke_fence,
            dependencies: &publication.dependencies,
            segments: &publication.segments,
            compiler_version: &publication.compiler_version,
            operation_id: &publication.operation_id,
        })
        .unwrap();
        OrgPublication {
            manifest_digest_hex,
            ..publication
        }
    }

    fn node_value() -> OrgNode {
        OrgNode {
            tenant_id: TENANT,
            root_tenant_id: ROOT,
            parent_tenant_id: None,
            generation: 3,
            revoke_fence: 1,
            relationship_revision: 2,
            active: true,
            operation_id: "op-node-1".to_owned(),
            root_activation: Some(OrgRootActivation {
                operator_user_id: 7,
                approval_operation_id: "op-approve-root".to_owned(),
            }),
        }
    }

    fn membership_value(window: ValidityWindow) -> OrgMembership {
        OrgMembership {
            membership_id: uuid(9),
            tenant_id: TENANT,
            root_tenant_id: ROOT,
            user_id: USER,
            identity_card_id: IDENTITY_CARD,
            card_id: CARD,
            revision: 1,
            active: true,
            validity: window,
            operation_id: "op-member-1".to_owned(),
        }
    }

    fn evidence_value(window: ValidityWindow) -> OrgAdmissionEvidence {
        OrgAdmissionEvidence {
            publication: publication_value(),
            node: node_value(),
            membership: membership_value(window),
            checked_at_unix: 500,
        }
    }

    /// 超限规模证据：单条序列化体量即超出 32MB 双族字节预算（用于字节
    /// 上限拒绝安装的行为验证，不参与 serve）。segment 域内上限 4096
    /// contributions，按多 segment 装配到目标规模。
    fn large_evidence(contribution_count: usize) -> OrgAdmissionEvidence {
        let mut evidence = evidence_value(validity());
        let mut segments = Vec::new();
        let mut remaining = contribution_count;
        let mut index = 0u32;
        let mut grant_index = 1usize;
        while remaining > 0 {
            let count = remaining.min(4_096);
            let mut content = OrgSegmentContent {
                key: OrgScopeKey {
                    resource: "doc:42".to_owned(),
                    action: "read".to_owned(),
                },
                contributions: Vec::with_capacity(count),
            };
            for _ in 0..count {
                let mut grant = grant_value();
                // segment 内 grant 唯一性是域校验：按全局序号生成 grant_id。
                grant.grant_id = format!("00000000-0000-0000-0000-{grant_index:012}");
                content.contributions.push(contribution_value(&grant));
                grant_index += 1;
            }
            segments.push(org_build_segment(index, content).expect("segment build"));
            remaining -= count;
            index += 1;
        }
        evidence.publication.segments = segments;
        evidence
    }

    fn ctx_value(card_id: i64) -> PolicyContext {
        PolicyContext::builder()
            .user_id(Some(USER))
            .identity_card_id(Some(IDENTITY_CARD))
            .card_id(Some(card_id))
            .tenant_id(Some(TENANT))
            .resource_ownership_scope(astral_types::ResourceOwnershipScope::Internal)
            .resource(Some("doc".to_owned()))
            .target_id(Some(42))
            .action("read".to_owned())
            .build()
    }

    fn healthy_hub() -> MemoryProjectionHub {
        let hub = MemoryProjectionHub::default();
        hub.record_channel_heartbeat();
        hub
    }

    fn lazy_pool() -> MySqlPool {
        sqlx::mysql::MySqlPoolOptions::new()
            .acquire_timeout(Duration::from_millis(50))
            .connect_lazy("mysql://user:pass@127.0.0.1:1/none")
            .unwrap()
    }

    fn org_key(card_id: i64) -> OrgMirrorKey {
        OrgMirrorKey {
            tenant_id: TENANT,
            user_id: USER,
            identity_card_id: Some(IDENTITY_CARD),
            card_id,
        }
    }

    fn ready_read(read: Option<OrgAuthorityRead>) -> OrgAdmissionEvidence {
        match read {
            Some(OrgAuthorityRead::Ready(evidence)) => *evidence,
            other => panic!("expected Ready read, got {other:?}"),
        }
    }

    fn assert_pending_code(read: Option<OrgAuthorityRead>, needle: &str) {
        match read {
            Some(OrgAuthorityRead::Pending { code }) => {
                assert!(
                    code.contains(needle),
                    "pending code {code:?} lacks {needle:?}"
                );
            }
            other => panic!("expected Pending({needle}), got {other:?}"),
        }
    }

    fn assert_ga_unavailable(result: Option<Result<bool, PolicyError>>, needle: &str) {
        match result {
            Some(Err(PolicyError::Repository(message))) => {
                assert!(
                    message.contains(needle),
                    "policy error {message:?} lacks {needle:?}"
                );
            }
            other => panic!("expected Err Repository({needle}), got {other:?}"),
        }
    }

    // ── 零 IO 命中与 serve 时重验 ────────────────────────────────────────

    #[tokio::test]
    async fn seeded_ready_evidence_serves_zero_io_with_refreshed_clock() {
        let _state_guard = crate::eligibility::test_global_state_lock();
        let hub = healthy_hub();
        let mirror = AuxiliaryAuthorizationMirror::new(lazy_pool(), true);
        let epoch = hub.auxiliary_org_epoch();
        mirror.seed_org_entry_for_test(
            org_key(CARD),
            OrgMirrorValue::Ready(Arc::new(evidence_value(validity()))),
            epoch,
        );
        let read = mirror.load_org_authorization(&hub, &ctx_value(CARD)).await;
        let evidence = ready_read(read);
        // serve 时刷新读取时钟并整体重验：与"此刻 DB 直读"同语义。
        assert!(evidence.checked_at_unix >= time::OffsetDateTime::now_utc().unix_timestamp());
        assert_eq!(evidence.publication.generation, 3);
        assert!(evidence.validate().is_ok());
        assert_eq!(mirror.org_entry_count(), 1);
    }

    #[tokio::test]
    async fn disabled_static_fact_serves_without_io() {
        let _state_guard = crate::eligibility::test_global_state_lock();
        let hub = healthy_hub();
        let epoch = hub.auxiliary_org_epoch();
        let disabled_mirror = AuxiliaryAuthorizationMirror::new(lazy_pool(), false);
        disabled_mirror.seed_org_entry_for_test(org_key(CARD), OrgMirrorValue::Disabled, epoch);
        assert!(matches!(
            disabled_mirror
                .load_org_authorization(&hub, &ctx_value(CARD))
                .await,
            Some(OrgAuthorityRead::Disabled)
        ));
    }

    #[tokio::test]
    async fn context_missing_is_deterministic_pending_without_any_io() {
        let _state_guard = crate::eligibility::test_global_state_lock();
        let hub = healthy_hub();
        let mirror = AuxiliaryAuthorizationMirror::new(lazy_pool(), true);
        let mut context = ctx_value(CARD);
        context.identity_card_id = None;
        assert_pending_code(
            mirror.load_org_authorization(&hub, &context).await,
            "org_scope.pending.context_missing",
        );
    }

    // ── fail-closed 门：writer-active / suspect / 纪元失效 ───────────────

    #[tokio::test]
    async fn active_source_writer_fails_closed_without_serving_or_refill() {
        let _state_guard = crate::eligibility::test_global_state_lock();
        let hub = healthy_hub();
        let mirror = AuxiliaryAuthorizationMirror::new(lazy_pool(), true);
        let epoch = hub.auxiliary_org_epoch();
        mirror.seed_org_entry_for_test(
            org_key(CARD),
            OrgMirrorValue::Ready(Arc::new(evidence_value(validity()))),
            epoch,
        );
        mirror.seed_global_admin_entry_for_test(USER, true, hub.auxiliary_global_admin_epoch());

        let writer = hub
            .begin_source_transaction()
            .expect("generic writer guard");
        assert_pending_code(
            mirror.load_org_authorization(&hub, &ctx_value(CARD)).await,
            "org_scope.pending.single_node_writer_active",
        );
        assert!(
            matches!(
                mirror.is_active_global_admin(&hub, USER).await,
                Some(Err(_))
            ),
            "writer-active GA read must be PolicyError fail-closed"
        );
        drop(writer);

        // guard 释放推进双纪元：旧条目立即失效，回填走 lazy pool（连接拒绝）
        // 得到 None 回落既有 DB 链；绝不 serve 旧条目。
        assert!(matches!(
            mirror.load_org_authorization(&hub, &ctx_value(CARD)).await,
            Some(OrgAuthorityRead::Pending { .. })
        ));
        assert!(matches!(
            mirror.is_active_global_admin(&hub, USER).await,
            Some(Err(_))
        ));
    }

    #[tokio::test]
    async fn mutation_between_two_reads_never_serves_the_cached_positive() {
        let _state_guard = crate::eligibility::test_global_state_lock();
        let hub = healthy_hub();
        let mirror = AuxiliaryAuthorizationMirror::new(lazy_pool(), true);
        let epoch = hub.auxiliary_org_epoch();
        mirror.seed_org_entry_for_test(
            org_key(CARD),
            OrgMirrorValue::Ready(Arc::new(evidence_value(validity()))),
            epoch,
        );
        // 第一次读取：镜像命中（零 IO）。
        assert!(
            ready_read(mirror.load_org_authorization(&hub, &ctx_value(CARD)).await)
                .validate()
                .is_ok()
        );
        // 两读之间发生 org source mutation：begin（writer-active 直接拒绝）。
        let writer = hub
            .begin_org_source_transaction()
            .expect("org writer guard");
        assert_pending_code(
            mirror.load_org_authorization(&hub, &ctx_value(CARD)).await,
            "org_scope.pending.single_node_writer_active",
        );
        // commit/drop 后：纪元已推进，第二次读取绝不 serve 旧缓存条目。
        drop(writer);
        assert!(matches!(
            mirror.load_org_authorization(&hub, &ctx_value(CARD)).await,
            Some(OrgAuthorityRead::Pending { .. })
        ));
    }

    #[tokio::test]
    async fn org_writer_guard_bumps_only_the_org_epoch() {
        let _state_guard = crate::eligibility::test_global_state_lock();
        let hub = healthy_hub();
        let ga_before = hub.auxiliary_global_admin_epoch();
        let org_before = hub.auxiliary_org_epoch();
        let writer = hub
            .begin_org_source_transaction()
            .expect("org writer guard");
        assert!(hub.has_active_source_writer());
        drop(writer);
        assert!(!hub.has_active_source_writer());
        assert_eq!(hub.auxiliary_org_epoch(), org_before + 2);
        assert_eq!(hub.auxiliary_global_admin_epoch(), ga_before);

        // generic（不可归因）写者保守失效双纪元。
        let generic = hub
            .begin_source_transaction()
            .expect("generic writer guard");
        drop(generic);
        assert_eq!(hub.auxiliary_org_epoch(), org_before + 4);
        assert_eq!(hub.auxiliary_global_admin_epoch(), ga_before + 2);
    }

    #[tokio::test]
    async fn unknown_org_commit_is_sticky_suspect_and_blocks_the_mirror() {
        let _state_guard = crate::eligibility::test_global_state_lock();
        let hub = healthy_hub();
        let mirror = AuxiliaryAuthorizationMirror::new(lazy_pool(), true);
        let writer = hub
            .begin_org_source_transaction()
            .expect("org writer guard");
        writer.mark_uncertain();
        assert!(hub.channel_is_suspect());
        // 心跳不能清除 suspect（sticky）；镜像通道门回落 DB。
        hub.record_channel_heartbeat();
        assert!(hub.channel_is_suspect());
        assert!(matches!(
            mirror.load_org_authorization(&hub, &ctx_value(CARD)).await,
            Some(OrgAuthorityRead::Pending { .. })
        ));
        drop(writer);
    }

    #[tokio::test]
    async fn unhealthy_channel_falls_back_instead_of_serving() {
        let hub = MemoryProjectionHub::default();
        let mirror = AuxiliaryAuthorizationMirror::new(lazy_pool(), true);
        let epoch = hub.auxiliary_org_epoch();
        mirror.seed_org_entry_for_test(
            org_key(CARD),
            OrgMirrorValue::Ready(Arc::new(evidence_value(validity()))),
            epoch,
        );
        assert!(mirror
            .load_org_authorization(&hub, &ctx_value(CARD))
            .await
            .is_none());
    }

    // ── 时间/范围/容量语义 ───────────────────────────────────────────────

    #[tokio::test]
    async fn expired_membership_never_serves_a_stale_positive() {
        let _state_guard = crate::eligibility::test_global_state_lock();
        let hub = healthy_hub();
        let mirror = AuxiliaryAuthorizationMirror::new(lazy_pool(), true);
        let epoch = hub.auxiliary_org_epoch();
        // 会员资格窗口 [0,1000] 早已排除真实 wall clock：serve 刷新时钟后
        // validate 必败，转严格回填（lazy pool 失败得到 None 回落 DB 权威）。
        mirror.seed_org_entry_for_test(
            org_key(CARD),
            OrgMirrorValue::Ready(Arc::new(evidence_value(ValidityWindow::between(0, 1_000)))),
            epoch,
        );
        assert!(matches!(
            mirror.load_org_authorization(&hub, &ctx_value(CARD)).await,
            Some(OrgAuthorityRead::Pending { .. })
        ));
    }

    #[tokio::test]
    async fn partial_scope_keys_never_cross_serve() {
        let _state_guard = crate::eligibility::test_global_state_lock();
        let hub = healthy_hub();
        let mirror = AuxiliaryAuthorizationMirror::new(lazy_pool(), true);
        let epoch = hub.auxiliary_org_epoch();
        mirror.seed_org_entry_for_test(
            org_key(CARD),
            OrgMirrorValue::Ready(Arc::new(evidence_value(validity()))),
            epoch,
        );
        // 同租户同用户、不同 card：全键不匹配得到 miss，严格回填失败后回落。
        assert!(matches!(
            mirror
                .load_org_authorization(&hub, &ctx_value(CARD + 1))
                .await,
            Some(OrgAuthorityRead::Pending { .. })
        ));
    }

    #[tokio::test]
    async fn ga_mirror_hits_zero_io_and_invalidates_on_any_generic_writer() {
        let _state_guard = crate::eligibility::test_global_state_lock();
        let hub = healthy_hub();
        let mirror = AuxiliaryAuthorizationMirror::new(lazy_pool(), true);
        mirror.seed_global_admin_entry_for_test(USER, true, hub.auxiliary_global_admin_epoch());
        assert!(matches!(
            mirror.is_active_global_admin(&hub, USER).await,
            Some(Ok(true))
        ));
        // 非正 user 与既有端口同语义（false，无 IO）。
        assert!(matches!(
            mirror.is_active_global_admin(&hub, 0).await,
            Some(Ok(false))
        ));

        let writer = hub
            .begin_source_transaction()
            .expect("generic writer guard");
        assert!(matches!(
            mirror.is_active_global_admin(&hub, USER).await,
            Some(Err(_))
        ));
        drop(writer);
        assert!(matches!(
            mirror.is_active_global_admin(&hub, USER).await,
            Some(Err(_))
        ));
    }

    #[tokio::test]
    async fn capacity_refusal_keeps_reads_on_the_durable_path() {
        let _state_guard = crate::eligibility::test_global_state_lock();
        let hub = healthy_hub();
        let mirror = AuxiliaryAuthorizationMirror::new(lazy_pool(), true);
        let epoch = hub.auxiliary_org_epoch();
        for card_id in 1..=(MAX_ORG_MIRROR_ENTRIES as i64) {
            mirror.install_org(&org_key(card_id), OrgMirrorValue::Disabled, epoch);
        }
        assert_eq!(mirror.org_entry_count(), MAX_ORG_MIRROR_ENTRIES);
        // 超限，拒绝安装（读回 DB = 现状语义），绝不挤占正确性。
        mirror.install_org(
            &org_key(MAX_ORG_MIRROR_ENTRIES as i64 + 1),
            OrgMirrorValue::Disabled,
            epoch,
        );
        assert_eq!(mirror.org_entry_count(), MAX_ORG_MIRROR_ENTRIES);
    }

    #[tokio::test]
    async fn evict_all_org_clears_every_entry_for_commit_proven_mutations() {
        let _state_guard = crate::eligibility::test_global_state_lock();
        let hub = healthy_hub();
        let mirror = AuxiliaryAuthorizationMirror::new(lazy_pool(), true);
        let epoch = hub.auxiliary_org_epoch();
        mirror.seed_org_entry_for_test(
            org_key(CARD),
            OrgMirrorValue::Ready(Arc::new(evidence_value(validity()))),
            epoch,
        );
        mirror.evict_all_org();
        assert_eq!(mirror.org_entry_count(), 0);
        assert!(matches!(
            mirror.load_org_authorization(&hub, &ctx_value(CARD)).await,
            Some(OrgAuthorityRead::Pending { .. })
        ));
    }

    #[test]
    fn read_token_rejects_writer_health_and_completed_mutation_changes() {
        let _state_guard = crate::eligibility::test_global_state_lock();
        let hub = healthy_hub();
        let AuxiliaryReadGate::Ready(token) = hub.auxiliary_read_gate() else {
            panic!("healthy hub must issue a read token");
        };
        assert!(hub.auxiliary_read_matches(token));
        let writer = hub.begin_source_transaction().unwrap();
        assert_eq!(hub.auxiliary_read_gate(), AuxiliaryReadGate::WriterActive);
        assert!(!hub.auxiliary_read_matches(token));
        drop(writer);
        assert!(!hub.auxiliary_read_matches(token));
        let AuxiliaryReadGate::Ready(after_write) = hub.auxiliary_read_gate() else {
            panic!("completed writer must release the active gate");
        };
        hub.mark_channel_suspect("test channel loss");
        assert!(!hub.auxiliary_read_matches(after_write));
    }

    #[tokio::test]
    async fn singleflight_lock_is_shared_and_held_during_the_owned_scope() {
        let mirror = AuxiliaryAuthorizationMirror::new(lazy_pool(), true);
        let key = org_key(CARD);
        let first = mirror.org_refill_lock(&key).unwrap();
        let second = mirror.org_refill_lock(&key).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        let guard = first.lock().await;
        assert!(second.try_lock().is_err());
        drop(guard);
        assert!(second.try_lock().is_ok());
    }

    #[test]
    fn production_refill_retains_guards_and_bounds_both_queries() {
        let source = include_str!("auxiliary_authorization_mirror.rs").replace("\r\n", "\n");
        let source = source
            .split_once(concat!(
                "#[",
                "cfg(test)]\n#[allow(clippy::await_holding_lock)]\nmod tests"
            ))
            .unwrap()
            .0;
        assert_eq!(
            source
                .matches(
                    "let _guard = match tokio::time::timeout(REFILL_LOCK_WAIT, lock.lock()).await"
                )
                .count(),
            2
        );
        assert_eq!(source.matches("REFILL_QUERY_DEADLINE,").count(), 2);
        assert!(source.contains("OrgRefillRead::Uncacheable(OrgAuthorityRead::Unmanaged)"));
        assert!(!source.contains("ServeFreshUncached"));
    }

    // ── 严格回填 seam 行为（fake-refill future 注入；仅私有可见） ─────────

    #[tokio::test]
    async fn concurrent_same_key_reads_share_one_strict_refill_during_await() {
        let _state_guard = crate::eligibility::test_global_state_lock();
        let hub = healthy_hub();
        let mirror = AuxiliaryAuthorizationMirror::new(lazy_pool(), true);
        let counter = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(tokio::sync::Barrier::new(8));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let mirror = mirror.clone();
            let hub = hub.clone();
            let counter = counter.clone();
            let barrier = barrier.clone();
            handles.push(tokio::spawn(async move {
                let counter = counter.clone();
                let factory = move || async move {
                    // 只有 single-flight 锁持有者会构造并驱动本 future。
                    counter.fetch_add(1, Ordering::SeqCst);
                    // 拉长回填 await 窗口：其余调用者此刻必须排队等锁或命中
                    // 已回填条目，绝不并发发起第二次严格回源。
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    Some(OrgRefillRead::Cacheable(OrgMirrorValue::Ready(Arc::new(
                        evidence_value(validity()),
                    ))))
                };
                barrier.wait().await;
                let AuxiliaryReadGate::Ready(token) = hub.auxiliary_read_gate() else {
                    panic!("healthy hub must issue a read token");
                };
                mirror
                    .org_authorization_with_strict_refill(&hub, org_key(CARD), token, factory)
                    .await
            }));
        }
        let mut served = 0;
        for handle in handles {
            let evidence = ready_read(handle.await.expect("caller task join"));
            assert!(
                evidence.validate().is_ok(),
                "served evidence must revalidate"
            );
            served += 1;
        }
        assert_eq!(served, 8);
        // 8 个并发同键调用者只允许一次严格回源：single-flight 在整个
        // await 期间持有，其余调用方等结果或命中回填条目。
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(mirror.org_entry_count(), 1);
    }

    #[tokio::test]
    async fn concurrent_same_user_global_admin_reads_share_one_strict_refill() {
        let _state_guard = crate::eligibility::test_global_state_lock();
        let hub = healthy_hub();
        let mirror = AuxiliaryAuthorizationMirror::new(lazy_pool(), true);
        let counter = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(tokio::sync::Barrier::new(8));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let mirror = mirror.clone();
            let hub = hub.clone();
            let counter = counter.clone();
            let barrier = barrier.clone();
            handles.push(tokio::spawn(async move {
                let counter = counter.clone();
                let factory = move || async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    Ok(true)
                };
                barrier.wait().await;
                let AuxiliaryReadGate::Ready(token) = hub.auxiliary_read_gate() else {
                    panic!("healthy hub must issue a read token");
                };
                mirror
                    .global_admin_with_strict_refill(&hub, USER, token, factory)
                    .await
            }));
        }
        for handle in handles {
            assert!(matches!(
                handle.await.expect("caller task join"),
                Some(Ok(true))
            ));
        }
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(mirror.global_admin_entry_count(), 1);
    }

    #[tokio::test]
    async fn org_epoch_bump_during_refill_never_installs_or_serves_old_allow() {
        let _state_guard = crate::eligibility::test_global_state_lock();
        let hub = healthy_hub();
        let mirror = AuxiliaryAuthorizationMirror::new(lazy_pool(), true);
        let epoch_before = hub.auxiliary_org_epoch();
        let factory = || async {
            // 正在 await 的严格回填中途发生 org source mutation：begin+drop
            // 推进 org 纪元。回填带回来的仍是"旧纪元"事实。
            let writer = hub
                .begin_org_source_transaction()
                .expect("org writer guard");
            drop(writer);
            Some(OrgRefillRead::Cacheable(OrgMirrorValue::Ready(Arc::new(
                evidence_value(validity()),
            ))))
        };
        let AuxiliaryReadGate::Ready(token) = hub.auxiliary_read_gate() else {
            panic!("healthy hub must issue a read token");
        };
        let read = mirror
            .org_authorization_with_strict_refill(&hub, org_key(CARD), token, factory)
            .await;
        assert_pending_code(read, "invalidation_raced_refill");
        assert_eq!(mirror.org_entry_count(), 0, "raced refill must not install");
        assert!(hub.auxiliary_org_epoch() > epoch_before);
        // 后续新鲜 token 读取也绝不 serve 旧条目（未安装 → 严格回填失败 →
        // Pending 回落权威链）。
        assert!(matches!(
            mirror.load_org_authorization(&hub, &ctx_value(CARD)).await,
            Some(OrgAuthorityRead::Pending { .. })
        ));
    }

    #[tokio::test]
    async fn tenant_unmanaged_strict_fact_is_cacheable_and_reused_zero_io() {
        let _state_guard = crate::eligibility::test_global_state_lock();
        let hub = healthy_hub();
        let mirror = AuxiliaryAuthorizationMirror::new(lazy_pool(), true);
        let counter = Arc::new(AtomicUsize::new(0));
        let factory = {
            let counter = counter.clone();
            move || {
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    // 严格 gate 读取的权威 legacy 路由事实（表存在且无 node
                    // 行）：与 Ready 同协议缓存，供引擎 Unmanaged→legacy。
                    Some(OrgRefillRead::Cacheable(OrgMirrorValue::Unmanaged))
                }
            }
        };
        let AuxiliaryReadGate::Ready(token) = hub.auxiliary_read_gate() else {
            panic!("healthy hub must issue a read token");
        };
        let read = mirror
            .org_authorization_with_strict_refill(&hub, org_key(CARD), token, factory)
            .await;
        assert!(matches!(read, Some(OrgAuthorityRead::Unmanaged)));
        assert_eq!(mirror.org_entry_count(), 1);
        // 第二次读取命中缓存（工厂计数不变）：零 DB 复用同一权威事实。
        let read = mirror.load_org_authorization(&hub, &ctx_value(CARD)).await;
        assert!(matches!(read, Some(OrgAuthorityRead::Unmanaged)));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn unmanaged_refill_across_epoch_bump_never_installs_or_serves() {
        let _state_guard = crate::eligibility::test_global_state_lock();
        let hub = healthy_hub();
        let mirror = AuxiliaryAuthorizationMirror::new(lazy_pool(), true);
        let epoch_before = hub.auxiliary_org_epoch();
        let factory = || async {
            // 回填 await 窗口内发生 org source mutation（node 行写点所属
            // 事务族）：回填带回来的 Unmanaged 属于旧纪元，绝不安装。
            let writer = hub
                .begin_org_source_transaction()
                .expect("org writer guard");
            drop(writer);
            Some(OrgRefillRead::Cacheable(OrgMirrorValue::Unmanaged))
        };
        let AuxiliaryReadGate::Ready(token) = hub.auxiliary_read_gate() else {
            panic!("healthy hub must issue a read token");
        };
        let read = mirror
            .org_authorization_with_strict_refill(&hub, org_key(CARD), token, factory)
            .await;
        assert_pending_code(read, "invalidation_raced_refill");
        assert_eq!(mirror.org_entry_count(), 0);
        assert!(hub.auxiliary_org_epoch() > epoch_before);
        // 新鲜 token 读取也不 serve（未安装）：legacy 路由事实同样受纪元
        // 栅栏约束（Unmanaged→Managed 转换只可能经栅栏事务发生）。
        assert!(matches!(
            mirror.load_org_authorization(&hub, &ctx_value(CARD)).await,
            Some(OrgAuthorityRead::Pending { .. })
        ));
    }

    #[tokio::test]
    async fn writer_active_race_during_refill_fails_closed_without_install() {
        let _state_guard = crate::eligibility::test_global_state_lock();
        let hub = healthy_hub();
        let mirror = AuxiliaryAuthorizationMirror::new(lazy_pool(), true);
        let (guard_tx, guard_rx) = oneshot::channel();
        let factory = || async {
            // 回填 future 中途开始 source 写事务，并把**仍持有**的写者栅栏
            // 交还编排方 —— 助手做安装前复验时 writer 仍 active。
            let guard = hub
                .begin_source_transaction()
                .expect("generic writer guard");
            let _ = guard_tx.send(guard);
            Some(OrgRefillRead::Cacheable(OrgMirrorValue::Ready(Arc::new(
                evidence_value(validity()),
            ))))
        };
        let AuxiliaryReadGate::Ready(token) = hub.auxiliary_read_gate() else {
            panic!("healthy hub must issue a read token");
        };
        let read = mirror
            .org_authorization_with_strict_refill(&hub, org_key(CARD), token, factory)
            .await;
        // 栅栏仍活在 oneshot 中：纪元复验与 token 复验发生在 writer-active
        // 窗口内 → 旧 ALLOW 绝不安装。
        assert!(hub.has_active_source_writer());
        assert_pending_code(read, "invalidation_raced_refill");
        assert_eq!(mirror.org_entry_count(), 0);
        drop(guard_rx);
        assert!(!hub.has_active_source_writer());
    }

    #[tokio::test]
    async fn channel_suspect_race_during_refill_fails_closed_without_install() {
        let _state_guard = crate::eligibility::test_global_state_lock();
        let hub = healthy_hub();
        let mirror = AuxiliaryAuthorizationMirror::new(lazy_pool(), true);
        let factory = || async {
            // 回填 await 窗口内通道失联：sticky suspect 使读 token 失配。
            hub.mark_channel_suspect("orchestrated channel loss during refill");
            Some(OrgRefillRead::Cacheable(OrgMirrorValue::Ready(Arc::new(
                evidence_value(validity()),
            ))))
        };
        let AuxiliaryReadGate::Ready(token) = hub.auxiliary_read_gate() else {
            panic!("healthy hub must issue a read token");
        };
        let read = mirror
            .org_authorization_with_strict_refill(&hub, org_key(CARD), token, factory)
            .await;
        assert!(hub.channel_is_suspect());
        assert_pending_code(read, "invalidation_raced_refill");
        assert_eq!(mirror.org_entry_count(), 0);
    }

    #[tokio::test]
    async fn stale_read_token_cannot_serve_seeded_org_entry_after_epoch_bump() {
        let _state_guard = crate::eligibility::test_global_state_lock();
        let hub = healthy_hub();
        let mirror = AuxiliaryAuthorizationMirror::new(lazy_pool(), true);
        mirror.seed_org_entry_for_test(
            org_key(CARD),
            OrgMirrorValue::Ready(Arc::new(evidence_value(validity()))),
            hub.auxiliary_org_epoch(),
        );
        let AuxiliaryReadGate::Ready(token) = hub.auxiliary_read_gate() else {
            panic!("healthy hub must issue a read token");
        };
        // token 签发后发生并发 org mutation：token 已过期。
        let writer = hub
            .begin_org_source_transaction()
            .expect("org writer guard");
        drop(writer);
        // 条目纪元相对旧 token"新鲜"，但 token 与 hub 现状态失配 → 绝不
        // serve 旧 ALLOW，也绝不发起回填（工厂被调用即 panic）。
        let factory = || async { panic!("raced serve must never reach strict refill") };
        let read = mirror
            .org_authorization_with_strict_refill(&hub, org_key(CARD), token, factory)
            .await;
        assert_pending_code(read, "invalidation_raced_read");
    }

    #[tokio::test]
    async fn global_admin_epoch_bump_during_refill_never_installs_or_serves_old_positive() {
        let _state_guard = crate::eligibility::test_global_state_lock();
        let hub = healthy_hub();
        let mirror = AuxiliaryAuthorizationMirror::new(lazy_pool(), true);
        let epoch_before = hub.auxiliary_global_admin_epoch();
        let factory = || async {
            // 回填 await 窗口内发生 generic source mutation（双纪元推进）。
            let writer = hub
                .begin_source_transaction()
                .expect("generic writer guard");
            drop(writer);
            Ok(true)
        };
        let AuxiliaryReadGate::Ready(token) = hub.auxiliary_read_gate() else {
            panic!("healthy hub must issue a read token");
        };
        let result = mirror
            .global_admin_with_strict_refill(&hub, USER, token, factory)
            .await;
        assert_ga_unavailable(result, "invalidation_raced_refill");
        assert_eq!(mirror.global_admin_entry_count(), 0);
        assert!(hub.auxiliary_global_admin_epoch() > epoch_before);
        // 后续新鲜 token 读取绝不返回缓存旧值（未安装 → 严格回填失败 → Err）。
        assert!(matches!(
            mirror.is_active_global_admin(&hub, USER).await,
            Some(Err(_))
        ));
    }

    #[tokio::test]
    async fn stale_read_token_cannot_serve_seeded_global_admin_after_epoch_bump() {
        let _state_guard = crate::eligibility::test_global_state_lock();
        let hub = healthy_hub();
        let mirror = AuxiliaryAuthorizationMirror::new(lazy_pool(), true);
        mirror.seed_global_admin_entry_for_test(USER, true, hub.auxiliary_global_admin_epoch());
        let AuxiliaryReadGate::Ready(token) = hub.auxiliary_read_gate() else {
            panic!("healthy hub must issue a read token");
        };
        let writer = hub
            .begin_source_transaction()
            .expect("generic writer guard");
        drop(writer);
        let factory = || async { panic!("raced serve must never reach strict refill") };
        let result = mirror
            .global_admin_with_strict_refill(&hub, USER, token, factory)
            .await;
        assert_ga_unavailable(result, "invalidation_raced_read");
    }

    #[tokio::test]
    async fn org_refill_timeout_never_double_queries_or_falls_back() {
        let _state_guard = crate::eligibility::test_global_state_lock();
        let hub = healthy_hub();
        let mirror = AuxiliaryAuthorizationMirror::new(lazy_pool(), true);
        let counter = Arc::new(AtomicUsize::new(0));
        let (started_tx, started_rx) = oneshot::channel();
        let winner = {
            let mirror = mirror.clone();
            let hub = hub.clone();
            let counter = counter.clone();
            tokio::spawn(async move {
                let factory = move || async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let _ = started_tx.send(());
                    // 回填迟迟不返回（远超 3s 查询 deadline；deadline 到期时
                    // 本 future 被整体 drop，sleep 不会跑满）。
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    Some(OrgRefillRead::Cacheable(OrgMirrorValue::Ready(Arc::new(
                        evidence_value(validity()),
                    ))))
                };
                let AuxiliaryReadGate::Ready(token) = hub.auxiliary_read_gate() else {
                    panic!("healthy hub must issue a read token");
                };
                mirror
                    .org_authorization_with_strict_refill(&hub, org_key(CARD), token, factory)
                    .await
            })
        };
        // 等获胜者真正进入 await 的严格回填（已持锁、已发起唯一一次回源），
        // 再放入排队者。
        started_rx.await.expect("refill query started");
        let loser = {
            let mirror = mirror.clone();
            let hub = hub.clone();
            let counter = counter.clone();
            tokio::spawn(async move {
                let factory = move || async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    Some(OrgRefillRead::Cacheable(OrgMirrorValue::Ready(Arc::new(
                        evidence_value(validity()),
                    ))))
                };
                let AuxiliaryReadGate::Ready(token) = hub.auxiliary_read_gate() else {
                    panic!("healthy hub must issue a read token");
                };
                mirror
                    .org_authorization_with_strict_refill(&hub, org_key(CARD), token, factory)
                    .await
            })
        };
        // 获胜者查询仍在飞（3s deadline 未到）：排队者挂在 single-flight 锁上，
        // 绝不并发发起第二次严格回源（无 double-query）。
        tokio::time::sleep(Duration::from_millis(2_500)).await;
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "no second strict query while the first refill is in flight"
        );
        let winner_read = winner.await.expect("winner join");
        let loser_read = loser.await.expect("loser join");
        // 获胜者：查询 deadline 到期 → Pending，回填 future 被丢弃（取消），
        // 绝不二次查询、绝不回落。
        assert_pending_code(winner_read, "strict_refill_timeout");
        // 排队者：锁等待到期；或获胜者释放锁后接棒成为新 leader 并在自身
        // deadline 到期 —— 两条合法路径都一律 fail-closed 超时 Pending，
        // 绝不 Ready、绝不回落任何旧值。
        match loser_read {
            Some(OrgAuthorityRead::Pending { code }) => assert!(
                code.contains("refill_wait_timeout") || code.contains("strict_refill_timeout"),
                "unexpected loser pending code {code:?}"
            ),
            other => panic!("loser must stay fail-closed on timeout, got {other:?}"),
        }
        assert_eq!(mirror.org_entry_count(), 0);
    }

    #[tokio::test]
    async fn global_admin_refill_timeout_never_double_queries_or_falls_back() {
        let _state_guard = crate::eligibility::test_global_state_lock();
        let hub = healthy_hub();
        let mirror = AuxiliaryAuthorizationMirror::new(lazy_pool(), true);
        let counter = Arc::new(AtomicUsize::new(0));
        let (started_tx, started_rx) = oneshot::channel();
        let winner = {
            let mirror = mirror.clone();
            let hub = hub.clone();
            let counter = counter.clone();
            tokio::spawn(async move {
                let factory = move || async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let _ = started_tx.send(());
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    Ok(true)
                };
                let AuxiliaryReadGate::Ready(token) = hub.auxiliary_read_gate() else {
                    panic!("healthy hub must issue a read token");
                };
                mirror
                    .global_admin_with_strict_refill(&hub, USER, token, factory)
                    .await
            })
        };
        started_rx.await.expect("refill query started");
        let loser = {
            let mirror = mirror.clone();
            let hub = hub.clone();
            let counter = counter.clone();
            tokio::spawn(async move {
                let factory = move || async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    Ok(true)
                };
                let AuxiliaryReadGate::Ready(token) = hub.auxiliary_read_gate() else {
                    panic!("healthy hub must issue a read token");
                };
                mirror
                    .global_admin_with_strict_refill(&hub, USER, token, factory)
                    .await
            })
        };
        // 获胜者查询仍在飞：排队者绝不并发发起第二次严格回源。
        tokio::time::sleep(Duration::from_millis(2_500)).await;
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "no second strict query while the first refill is in flight"
        );
        let winner_result = winner.await.expect("winner join");
        let loser_result = loser.await.expect("loser join");
        assert_ga_unavailable(winner_result, "strict_refill_timeout");
        // 排队者：锁等待超时或接棒后自身超时 —— 一律 fail-closed Err。
        match loser_result {
            Some(Err(PolicyError::Repository(message))) => assert!(
                message.contains("refill_wait_timeout")
                    || message.contains("strict_refill_timeout"),
                "unexpected loser policy error {message:?}"
            ),
            other => panic!("loser must stay fail-closed on timeout, got {other:?}"),
        }
        assert_eq!(mirror.global_admin_entry_count(), 0);
    }

    #[tokio::test]
    async fn refill_scope_capacity_exhaustion_fails_closed_without_query() {
        let _state_guard = crate::eligibility::test_global_state_lock();
        let hub = healthy_hub();
        let mirror = AuxiliaryAuthorizationMirror::new(lazy_pool(), true);
        // 占满 1024 个 single-flight scope（保持强引用 = 活跃锁）。
        let mut held = Vec::new();
        for card_id in 0..MAX_REFILL_SCOPES as i64 {
            held.push(
                mirror
                    .org_refill_lock(&org_key(card_id))
                    .expect("scope lock"),
            );
        }
        // 第 1025 个 scope：拿不到回填锁 → fail-closed Pending，绝不发查询。
        let AuxiliaryReadGate::Ready(token) = hub.auxiliary_read_gate() else {
            panic!("healthy hub must issue a read token");
        };
        let factory = || async { panic!("capacity exhausted must never reach strict refill") };
        let read = mirror
            .org_authorization_with_strict_refill(&hub, org_key(999_999), token, factory)
            .await;
        assert_pending_code(read, "refill_capacity_exhausted");
    }

    #[tokio::test]
    async fn org_byte_cap_refuses_oversized_evidence_install() {
        let _state_guard = crate::eligibility::test_global_state_lock();
        let hub = healthy_hub();
        let mirror = AuxiliaryAuthorizationMirror::new(lazy_pool(), true);
        let epoch = hub.auxiliary_org_epoch();
        // 单条证据的真实序列化体量（约 36MB > 32MB 双族预算）→ install
        // 必须拒绝（读回 DB 语义），且不得污染字节账本。
        mirror.install_org(
            &org_key(CARD),
            OrgMirrorValue::Ready(Arc::new(large_evidence(100_000))),
            epoch,
        );
        assert_eq!(mirror.org_entry_count(), 0);
        assert_eq!(
            mirror
                .inner
                .maps
                .read()
                .expect("mirror maps lock")
                .org_bytes,
            0
        );
        // 拒绝后账本健康：小额条目正常准入并 serve（零 DB）。
        mirror.install_org(&org_key(CARD), OrgMirrorValue::Disabled, epoch);
        assert_eq!(mirror.org_entry_count(), 1);
        assert_eq!(
            mirror
                .inner
                .maps
                .read()
                .expect("mirror maps lock")
                .org_bytes,
            64
        );
        // Oversized payload construction may exceed the channel heartbeat window.
        hub.record_channel_heartbeat();
        assert!(matches!(
            mirror.load_org_authorization(&hub, &ctx_value(CARD)).await,
            Some(OrgAuthorityRead::Disabled)
        ));
    }

    #[tokio::test]
    async fn install_evicts_expired_entries_and_recomputes_org_bytes() {
        let _state_guard = crate::eligibility::test_global_state_lock();
        let hub = healthy_hub();
        let mirror = AuxiliaryAuthorizationMirror::new(lazy_pool(), true);
        let epoch = hub.auxiliary_org_epoch();
        mirror.install_org(&org_key(1), OrgMirrorValue::Disabled, epoch);
        mirror.install_org(&org_key(2), OrgMirrorValue::Disabled, epoch);
        assert_eq!(mirror.org_entry_count(), 2);
        // 回拨安装时刻使两条目越过 TTL；下一次 install 的惰性 GC 必须逐出
        // 并按 saturating fold 重算字节账本。
        let ancient = Instant::now()
            .checked_sub(AUXILIARY_MIRROR_TTL + Duration::from_secs(10))
            .expect("monotonic clock must predate the TTL window");
        {
            let mut maps = mirror.inner.maps.write().expect("mirror maps lock");
            for entry in maps.org.values_mut() {
                entry.installed_at = ancient;
            }
        }
        mirror.install_org(&org_key(3), OrgMirrorValue::Disabled, epoch);
        assert_eq!(mirror.org_entry_count(), 1);
        assert_eq!(
            mirror
                .inner
                .maps
                .read()
                .expect("mirror maps lock")
                .org_bytes,
            64
        );
    }

    #[tokio::test]
    async fn global_admin_entry_cap_refuses_beyond_limit() {
        let _state_guard = crate::eligibility::test_global_state_lock();
        let hub = healthy_hub();
        let mirror = AuxiliaryAuthorizationMirror::new(lazy_pool(), true);
        let epoch = hub.auxiliary_global_admin_epoch();
        for user_id in 1..=MAX_GLOBAL_ADMIN_MIRROR_ENTRIES as i64 {
            mirror.install_global_admin(user_id, true, epoch);
        }
        assert_eq!(
            mirror.global_admin_entry_count(),
            MAX_GLOBAL_ADMIN_MIRROR_ENTRIES
        );
        // 超限拒绝安装（读回 DB = 现状语义），绝不挤占正确性。
        mirror.install_global_admin(MAX_GLOBAL_ADMIN_MIRROR_ENTRIES as i64 + 1, true, epoch);
        assert_eq!(
            mirror.global_admin_entry_count(),
            MAX_GLOBAL_ADMIN_MIRROR_ENTRIES
        );
    }

    // ── 纯决策函数 ───────────────────────────────────────────────────────

    #[test]
    fn refill_install_decision_never_installs_across_an_epoch_change() {
        assert_eq!(
            refill_install_decision(7, 7),
            RefillInstallDecision::Install
        );
        assert_eq!(refill_install_decision(7, 8), RefillInstallDecision::Reject);
    }

    #[test]
    fn capacity_verdict_refuses_beyond_entries_or_bytes() {
        assert_eq!(
            capacity_verdict(0, 4_096, 1_024, MAX_AUXILIARY_MIRROR_BYTES),
            CapacityVerdict::Admit
        );
        assert_eq!(
            capacity_verdict(4_096, 4_096, 0, MAX_AUXILIARY_MIRROR_BYTES),
            CapacityVerdict::Refuse
        );
        assert_eq!(
            capacity_verdict(
                0,
                4_096,
                MAX_AUXILIARY_MIRROR_BYTES + 1,
                MAX_AUXILIARY_MIRROR_BYTES
            ),
            CapacityVerdict::Refuse
        );
    }

    #[test]
    fn org_entry_serve_decision_is_epoch_and_ttl_gated() {
        let entry = |value: OrgMirrorValue, installed_at: Instant, epoch: u64| OrgMirrorEntry {
            installed_at,
            org_epoch: epoch,
            value,
        };
        let now = Instant::now();
        // 纪元变更得到 Stale。
        assert!(matches!(
            org_entry_serve_decision(&entry(OrgMirrorValue::Disabled, now, 3), 4, 0, now),
            OrgServeDecision::Stale
        ));
        // TTL 过期得到 Stale（GC/正确性双门中的 TTL 门）。
        let expired_instant = now - (AUXILIARY_MIRROR_TTL + Duration::from_secs(1));
        assert!(matches!(
            org_entry_serve_decision(
                &entry(OrgMirrorValue::Disabled, expired_instant, 3),
                3,
                0,
                now
            ),
            OrgServeDecision::Stale
        ));
        assert!(matches!(
            org_entry_serve_decision(&entry(OrgMirrorValue::Disabled, now, 3), 3, 0, now),
            OrgServeDecision::ServeStatic(OrgAuthorityRead::Disabled)
        ));
    }
}
