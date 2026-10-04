//! 单机内存镜像读面 — MemoryProjectionHub。
//!
//! 组合进程默认安装；独立服务仅在失效通道完整装配时安装。
//! 已提交并严格验证的授权状态以不可变 Arc 保存，读端复用同一证据装配合同。
//! source writer、pending、版本和健康 token 在读取前后复检，缺失或存疑回严格路径。
//! 已开始提交的取消与未知结果持续阻断授权；普通投影对账不能代替该 writer 的结果证明。
//! writer 栅栏同时失效资格和会话正向条目，撤销 marker 保留作为拒绝加速器。
//! 单写者租约必须由组合 runtime 持续监督；咨询锁无法约束非合作的外部写者。

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, RwLock, Weak};
use std::time::{Duration, Instant};
use time::OffsetDateTime;

use astral_types::{
    PublishedCardAuthorization, PublishedCardEvidenceScope, PublishedEvidenceAggregate,
};
use sqlx::MySqlPool;

use crate::authorization_projection_repository::{
    assemble_published_card_evidence, read_published_authorization_state_in_tx,
    AuthorizationPublishedState, DeltaProjectorPublishOutcome, ProjectionAggregateIdentity,
};
use crate::grant_repository::{
    validate_delta_fence_relation, DeltaEventAppendRequest, DeltaEventType,
};

mod assembly_cache;

use assembly_cache::{AssemblyCache, AssemblyStamp};

static GLOBAL_MEMORY_PROJECTION_HUB: OnceLock<MemoryProjectionHub> = OnceLock::new();

/// 安装进程级内存镜像中心（单机组合进程启动期调用一次；重复安装返回 false）。
pub fn install_memory_projection_hub() -> bool {
    let hub = MemoryProjectionHub::default();
    if hub.begin_warmup().is_err() {
        return false;
    }
    GLOBAL_MEMORY_PROJECTION_HUB.set(hub).is_ok()
}

/// 进程级中心句柄；未安装（Rabbit 模式/既有部署）返回 `None`，全部钩子 no-op。
pub fn memory_projection_hub() -> Option<&'static MemoryProjectionHub> {
    GLOBAL_MEMORY_PROJECTION_HUB.get()
}

/// Refuse source writes when an installed hub cannot supply its ownership guard.
pub fn acquire_source_guard() -> Result<Option<SourceTransactionGuard>, astral_types::AstralError> {
    match memory_projection_hub() {
        Some(hub) => hub.begin_source_transaction().map(Some).ok_or_else(|| {
            astral_types::AstralError::Internal("source writer guard unavailable".to_owned())
        }),
        None => Ok(None),
    }
}

/// 装配侧便捷判定：单机入口据此决定是否用 [`MemoryMirroredRuleRepository`]
/// 包裹既有仓储链。
pub fn memory_mirror_is_installed() -> bool {
    memory_projection_hub().is_some()
}

// ─────────────────────────────────────────────────────────────────────────────
// 单机单写者租约（启动门禁）
// ─────────────────────────────────────────────────────────────────────────────

/// 单写者租约语句：MySQL 会话级咨询锁，零超时（拿不到立即失败）。
///
/// 锁随连接存活：进程退出/连接断开自动释放，因此崩溃的写者不会永久阻塞
/// 后续启动；租约连接由调用方持有至进程结束。
pub const SINGLE_NODE_WRITER_LEASE_SQL: &str = "SELECT GET_LOCK('astral_single_node_writer', 0)";

/// 单机单写者门禁：组合进程是唯一授权写者，启动期获取会话级咨询锁并持有
/// 连接直到进程结束。第二个实例拿不到锁即拒绝启动（绝不与在位写者并存，
/// 防止内存镜像与 DB 事实分叉）。返回的连接必须由调用方持有整个进程生命
/// 周期；提前释放即让出写者身份。
pub async fn acquire_single_writer_lease(
    pool: &MySqlPool,
) -> Result<sqlx::pool::PoolConnection<sqlx::MySql>, String> {
    let mut connection = pool.acquire().await.map_err(|error| error.to_string())?;
    let acquired: i64 = sqlx::query_scalar(SINGLE_NODE_WRITER_LEASE_SQL)
        .fetch_one(&mut *connection)
        .await
        .map_err(|error| error.to_string())?;
    if acquired != 1 {
        return Err(
            "another single-node writer instance already holds the writer lease".to_owned(),
        );
    }
    Ok(connection)
}

// ─────────────────────────────────────────────────────────────────────────────
// 启动期重放预热（readiness 门）
// ─────────────────────────────────────────────────────────────────────────────

/// 启动重放清单：全部当前已发布聚合与卡作用域（只读、确定性排序）。
///
/// 容量栅栏：`LIMIT` 是 cap+1 探针（cap = [`MAX_MIRROR_STATES`]，与
/// reconcile 扫描 [`LIST_CURRENT_FRONTIER_SQL`] 共用同一上界）。行数读满
/// cap+1 ⟺ durable frontier 超出镜像容量：warm-up 必须整体失败并拒绝启动，
/// 绝不把 LIMIT 截断的部分 frontier 装进镜像冒充完整读面（判定见
/// [`warm_scan_capacity_verdict`]）。
pub const LIST_CURRENT_IDENTITIES_SQL: &str =
    "SELECT tenant_id, card_id, aggregate_type, aggregate_id \
     FROM authorization_projection_current \
     ORDER BY tenant_id ASC, aggregate_type ASC, aggregate_id ASC \
     LIMIT 131073";

/// 与正式 freshness probe 同域：所有未完成撤权和携带 fence 的意图。
/// 不过滤重试时间或租约有效期，崩溃残留与隔离事件必须继续阻止 stale-ALLOW。
///
/// 容量栅栏：`LIMIT` 是 cap+1 探针（cap = [`MAX_PENDING_ENTRIES`]，与
/// `read_reconciliation` 的 durable pending 容量判定一致）。行数读满 cap+1
/// ⟺ durable pending 超出镜像容量：warm-up 必须整体失败并拒绝启动，同时
/// 保证本进程不会先物化一条无界 Vec（判定见 [`warm_scan_capacity_verdict`]）。
pub const LIST_PENDING_INVALIDATIONS_SQL: &str = "SELECT tenant_id, card_id, aggregate_type, \
    aggregate_id, event_id, operation_id, source_generation, revoke_fence, event_type, \
    invalidates_published_evidence \
    FROM authorization_delta_event WHERE status <> 'SUCCEEDED' \
      AND (invalidates_published_evidence <> 0 OR event_type IN ('REMOVE', 'REVOKE') \
           OR revoke_fence <> 0) \
    ORDER BY tenant_id ASC, delta_event_id ASC \
    LIMIT 100001";

/// A durable current frontier is compared by its complete pointer provenance.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
struct CurrentFrontierRow {
    tenant_id: i64,
    card_id: Option<i64>,
    aggregate_type: String,
    aggregate_id: i64,
    current_generation: i64,
    manifest_id: i64,
    event_id: String,
    operation_id: String,
    semantic_hash: Vec<u8>,
    dependency_hash: Vec<u8>,
    compiler_version: String,
    revoke_fence: i64,
    revoke_fence_proven: bool,
    cas_version: i64,
}

const LIST_CURRENT_FRONTIER_SQL: &str = "SELECT tenant_id, card_id, aggregate_type, aggregate_id, \
    current_generation, manifest_id, event_id, operation_id, semantic_hash, dependency_hash, \
    compiler_version, revoke_fence, revoke_fence_proven, cas_version \
    FROM authorization_projection_current \
    ORDER BY tenant_id, aggregate_type, aggregate_id LIMIT 131073";

impl CurrentFrontierRow {
    fn identity(&self) -> Result<ProjectionAggregateIdentity, String> {
        ProjectionAggregateIdentity::new(self.tenant_id, &self.aggregate_type, self.aggregate_id)
            .map_err(|error| error.to_string())
    }

    fn matches(&self, state: &AuthorizationPublishedState) -> bool {
        let pointer = &state.pointer;
        self.tenant_id == pointer.identity.tenant_id
            && self.aggregate_type == pointer.identity.aggregate_type
            && self.aggregate_id == pointer.identity.aggregate_id
            && self.card_id == pointer.card_id
            && u64::try_from(self.current_generation).ok() == Some(pointer.current_generation)
            && self.manifest_id == pointer.manifest_id
            && self.event_id == pointer.event_id
            && self.operation_id == pointer.operation_id
            && self.semantic_hash.as_slice() == pointer.semantic_hash.as_bytes()
            && self.dependency_hash.as_slice() == pointer.dependency_hash.as_bytes()
            && self.compiler_version == pointer.compiler_version
            && u64::try_from(self.revoke_fence).ok() == Some(pointer.revoke_fence)
            && self.revoke_fence_proven
            && pointer.revoke_fence_proven
            && self.cas_version == pointer.cas_version
    }
}

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
struct PendingInvalidationRow {
    tenant_id: i64,
    card_id: Option<i64>,
    aggregate_type: String,
    aggregate_id: i64,
    event_id: String,
    operation_id: String,
    source_generation: i64,
    revoke_fence: i64,
    event_type: String,
    invalidates_published_evidence: i64,
}

impl PendingInvalidationRow {
    fn decode(self) -> Result<(i64, Option<i64>, PendingDeltaEntry), sqlx::Error> {
        let invalid = || sqlx::Error::Protocol("invalid pending invalidation row".to_owned());
        let aggregate = ProjectionAggregateIdentity::new(
            self.tenant_id,
            self.aggregate_type,
            self.aggregate_id,
        )
        .map_err(|_| invalid())?;
        if self.card_id.is_some_and(|card_id| card_id <= 0)
            || self.event_id.len() > 128
            || self.operation_id.len() > 128
            || self.event_id.trim().is_empty()
            || self.operation_id.trim().is_empty()
        {
            return Err(invalid());
        }
        let source_generation = u64::try_from(self.source_generation).map_err(|_| invalid())?;
        let revoke_fence = u64::try_from(self.revoke_fence).map_err(|_| invalid())?;
        if source_generation == 0 {
            return Err(invalid());
        }
        validate_delta_fence_relation(source_generation, revoke_fence).map_err(|_| invalid())?;
        let event_type = DeltaEventType::from_sql(&self.event_type).map_err(|_| invalid())?;
        let revoke_class = self.invalidates_published_evidence != 0
            || matches!(event_type, DeltaEventType::Remove | DeltaEventType::Revoke);
        Ok((
            self.tenant_id,
            self.card_id,
            PendingDeltaEntry {
                aggregate: Some(aggregate),
                event_id: self.event_id,
                operation_id: self.operation_id,
                source_generation,
                published_generation: None,
                revoke_class,
                revoke_fence,
            },
        ))
    }
}

/// 重放预热报告：清单规模、成功装载、冷态与恢复的 pending 数。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WarmReport {
    pub identities: usize,
    pub installed: usize,
    pub failed: usize,
    pub pending_restored: usize,
}

/// 启动扫描容量判定（纯函数，cap+1 探针语义）。
///
/// 两类启动扫描（frontier 清单 / pending 清单）都按"容量上限 + 1"取行：
/// 行数 ≤ cap 才可能完整；任一维度读满 cap+1 ⟺ durable 世界超出镜像容量
/// ——必须整体失败（fail-closed，拒绝启动），绝不把 LIMIT 截断后的部分
/// frontier/pending 当作完整状态装载。错误文案与 `read_reconciliation` 的
/// 容量错误同族（durable mirror/pending capacity exceeded），保持 reconcile
/// 与 warm-up 同一失败语义。
fn warm_scan_capacity_verdict(frontier_rows: usize, pending_rows: usize) -> Result<(), String> {
    if frontier_rows > MAX_MIRROR_STATES {
        return Err("durable mirror scope capacity exceeded".to_owned());
    }
    if pending_rows > MAX_PENDING_ENTRIES {
        return Err("durable pending capacity exceeded".to_owned());
    }
    Ok(())
}

async fn read_state_short_tx(
    pool: &MySqlPool,
    identity: &ProjectionAggregateIdentity,
) -> Result<AuthorizationPublishedState, String> {
    let mut tx = pool.begin().await.map_err(|error| error.to_string())?;
    let state = read_published_authorization_state_in_tx(&mut tx, identity)
        .await
        .map_err(|error| error.to_string())?;
    tx.commit().await.map_err(|error| error.to_string())?;
    Ok(state)
}

/// 启动期先恢复 durable pending 与完整聚合清单，再装载 committed 发布状态。
///
/// 必须持有单写者租约且尚未启动服务。前次进程崩溃留下的未完成撤权仍然有效；
/// 清单/意图扫描失败时读面保持关闭，调用方必须拒绝启动。单聚合装载失败时，
/// 完整卡索引保留该缺口，该卡整体回退严格 reader，绝不返回部分聚合证据。
/// 未安装中心（Rabbit 模式）不访问数据库。
pub async fn warm_from_durable_with_hint(
    pool: &MySqlPool,
    hint: Option<&crate::ProjectionSnapshotHint>,
) -> Result<WarmReport, sqlx::Error> {
    let Some(hub) = memory_projection_hub() else {
        return Ok(WarmReport::default());
    };
    hub.begin_warmup()?;
    if let Some(hint) = hint {
        let mut maps = hub
            .maps
            .write()
            .map_err(|_| sqlx::Error::Protocol("memory projection hub lock poisoned".to_owned()))?;
        for state in hint.states() {
            maps.install(Arc::new(state.clone()));
        }
    }
    // cap+1 探针扫描：两类清单先各自取满行，再在登记 pending、注册卡索引或
    // 装载任何聚合状态之前做容量判定。任一维度读满 cap+1 即整体失败
    // （fail-closed，拒绝启动）——绝不把 LIMIT 截断的部分 frontier 装进镜像。
    let pending = sqlx::query_as::<_, PendingInvalidationRow>(LIST_PENDING_INVALIDATIONS_SQL)
        .fetch_all(pool)
        .await?;
    let rows = sqlx::query_as::<_, (i64, Option<i64>, String, i64)>(LIST_CURRENT_IDENTITIES_SQL)
        .fetch_all(pool)
        .await?;
    if let Err(reason) = warm_scan_capacity_verdict(rows.len(), pending.len()) {
        hub.mark_channel_suspect(reason.clone());
        return Err(sqlx::Error::Protocol(reason));
    }
    let pending_restored = pending.len();
    for row in pending {
        let (tenant_id, card_id, entry) = row.decode()?;
        hub.record_pending_entry(tenant_id, card_id, entry)?;
    }
    let mut identities = Vec::with_capacity(rows.len());
    for (tenant_id, card_id, aggregate_type, aggregate_id) in rows {
        let identity = ProjectionAggregateIdentity::new(tenant_id, aggregate_type, aggregate_id)
            .map_err(|_| sqlx::Error::Protocol("invalid warm-up aggregate identity".to_owned()))?;
        hub.expect_published_aggregate(&identity, card_id)?;
        identities.push(identity);
    }
    let mut report = WarmReport {
        identities: identities.len(),
        pending_restored,
        ..WarmReport::default()
    };
    for identity in identities {
        match read_state_short_tx(pool, &identity).await {
            Ok(state) => {
                hub.install_published_state(state);
                report.installed += 1;
            }
            Err(error) => {
                report.failed += 1;
                tracing::warn!(
                    aggregate_type = %identity.aggregate_type,
                    aggregate_id = identity.aggregate_id,
                    error = %error,
                    "memory mirror warm-up left an aggregate cold; readers defer to the durable path"
                );
            }
        }
    }
    hub.finish_warmup()?;
    Ok(report)
}

/// Warm the mirror from durable state without a snapshot hint.
pub async fn warm_from_durable(pool: &MySqlPool) -> Result<WarmReport, sqlx::Error> {
    warm_from_durable_with_hint(pool, None).await
}

/// 撤权意图只能由同一事件的 durable 发布完成证明清除，不能跨版本域比较。
#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingDeltaEntry {
    aggregate: Option<ProjectionAggregateIdentity>,
    event_id: String,
    operation_id: String,
    source_generation: u64,
    /// For a post-commit invalidation notification, the published frontier
    /// observed by the sender. This is a same-aggregate publication fence;
    /// it is never compared numerically with `source_generation`.
    published_generation: Option<u64>,
    revoke_class: bool,
    revoke_fence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
enum ChannelHealth {
    #[default]
    Unmonitored,
    Healthy {
        last_heartbeat: Instant,
    },
    Suspect {
        reason: String,
    },
}

pub const CHANNEL_MAX_HEARTBEAT_SILENCE_MS: u64 = 5_000;
const MAX_MIRROR_STATES: usize = 131_072;
const MAX_MIRROR_BYTES: u64 = 256 * 1024 * 1024;
const MIRROR_TTL: Duration = Duration::from_secs(600);
const MAX_PENDING_ENTRIES: usize = 100_000;
const MAX_COMPLETED_RECEIPTS: usize = 65_536;

fn heartbeat_silence_blocks(last: Instant, now: Instant, max_silence: Duration) -> bool {
    now.checked_duration_since(last)
        .is_none_or(|silence| silence > max_silence)
}

fn channel_blocks(channel: &ChannelHealth, now: Instant) -> bool {
    match channel {
        ChannelHealth::Unmonitored => false,
        ChannelHealth::Suspect { .. } => true,
        ChannelHealth::Healthy { last_heartbeat } => heartbeat_silence_blocks(
            *last_heartbeat,
            now,
            Duration::from_millis(CHANNEL_MAX_HEARTBEAT_SILENCE_MS),
        ),
    }
}

/// Compare generations only within one exact aggregate identity.
pub fn watermark_lags(durable_frontier: u64, applied: Option<u64>, max_lag: u64) -> bool {
    durable_frontier.saturating_sub(applied.unwrap_or(0)) > max_lag
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CompletionIdentity {
    aggregate: ProjectionAggregateIdentity,
    event_id: String,
    operation_id: String,
    source_generation: u64,
}

struct CompletionReceipt {
    generation: u64,
    revoke_fence: u64,
    installed_at: Instant,
}

#[derive(Default)]
struct HubMaps {
    warming_up: bool,
    /// Channel health is deliberately unmonitored until a supervisor opts in.
    channel: ChannelHealth,
    last_transport_heartbeat: Option<Instant>,
    notification_watermarks: HashMap<ProjectionAggregateIdentity, u64>,
    completed: HashMap<CompletionIdentity, CompletionReceipt>,
    installed_at: HashMap<ProjectionAggregateIdentity, Instant>,
    mirror_bytes: u64,
    pending_count: usize,
    health_revision: u64,
    tenant_epochs: HashMap<i64, u64>,
    card_epochs: HashMap<(i64, i64), u64>,
    /// 每聚合当前已验证 durable 发布状态镜像（不可变快照，安装即整体替换）。
    states: HashMap<ProjectionAggregateIdentity, Arc<AuthorizationPublishedState>>,
    /// (tenant, card) → 参与该卡的聚合集合（与 `states` 同锁维护）。
    card_index: HashMap<(i64, i64), HashSet<ProjectionAggregateIdentity>>,
    card_index_entries: usize,
    /// pending 撤权类/fence 抬升意图，按租户分桶 + 每卡 O(1) 定位：
    /// `card_id = None` 为 aggregate-wide，拦截该租户全部卡读（对齐 DB probe）。
    /// 读路径的拦截面成本是 O(1) 桶定位 + O(该卡条目数)，绝不随全系统
    /// pending 总量线性增长（极限探针 limit_pending_storm_scan_cost 钉住）。
    /// Runtime-owned source transactions fence online reconciliation.
    active_source_writers: usize,
    uncertain_source: bool,
    runtime_owner_failed: bool,
    mutation_revision: u64,
    source_revision: u64,
    /// 辅助读面（org 准入证据）纪元：org authority writer begin/drop、warm-up、
    /// reconcile、suspect 与 org 镜像整体失效时单调递增。辅助镜像条目仅在
    /// 安装纪元等于当前纪元时可信（"generation/revision 变更使条目失效"）。
    auxiliary_org_epoch: u64,
    /// 辅助读面（GlobalAdmin 事实）纪元：任何 generic source writer
    /// begin/drop（GA/user_card 写不可归因，保守全失效）、warm-up、reconcile、
    /// suspect 时单调递增。
    auxiliary_global_admin_epoch: u64,
    pending: HashMap<i64, TenantPending>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuxiliaryReadToken {
    pub(crate) org_epoch: u64,
    pub(crate) global_admin_epoch: u64,
    mutation_revision: u64,
    health_revision: u64,
}

/// Opaque admission stamp for a host's final source/health recheck.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorityReadFence(AuxiliaryReadToken);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuxiliaryReadGate {
    Ready(AuxiliaryReadToken),
    WriterActive,
    Uncertain,
    StrictRequired,
}

impl HubMaps {
    fn authority_fence_unavailable(&self) -> bool {
        self.runtime_owner_failed
            || [
                self.mutation_revision,
                self.source_revision,
                self.health_revision,
                self.auxiliary_org_epoch,
                self.auxiliary_global_admin_epoch,
            ]
            .contains(&u64::MAX)
    }

    fn auxiliary_read_gate(&self) -> AuxiliaryReadGate {
        if self.authority_fence_unavailable() {
            return AuxiliaryReadGate::Uncertain;
        }
        if self.active_source_writers != 0 {
            return AuxiliaryReadGate::WriterActive;
        }
        if self.uncertain_source {
            return AuxiliaryReadGate::Uncertain;
        }
        if self.warming_up
            || !matches!(self.channel, ChannelHealth::Healthy { .. })
            || channel_blocks(&self.channel, Instant::now())
        {
            return AuxiliaryReadGate::StrictRequired;
        }
        AuxiliaryReadGate::Ready(AuxiliaryReadToken {
            org_epoch: self.auxiliary_org_epoch,
            global_admin_epoch: self.auxiliary_global_admin_epoch,
            mutation_revision: self.mutation_revision,
            health_revision: self.health_revision,
        })
    }

    /// 辅助镜像纪元统一推进点：任何可能改变 org/GlobalAdmin 事实可信范围
    /// 的 hub 生命周期事件都经由此处 bump，保证条目失效语义只有一份。
    fn bump_auxiliary_epochs(&mut self) {
        self.auxiliary_org_epoch = self.auxiliary_org_epoch.saturating_add(1);
        self.auxiliary_global_admin_epoch = self.auxiliary_global_admin_epoch.saturating_add(1);
    }
}

/// Keeps reconciliation from discarding an intent whose source commit is unresolved.
pub struct SourceTransactionGuard {
    hub: MemoryProjectionHub,
    commit_unproven: AtomicBool,
}

fn invalidate_positive_read_caches() {
    crate::eligibility::evict_all_l1_card_active_caches();
    if let Some(store) = astral_common::session_projection_store::global_session_projection_store()
    {
        if let Some(mirror) = store.mirror() {
            mirror.invalidate_all_grants();
        }
    }
}

impl SourceTransactionGuard {
    /// Arm before awaiting COMMIT or an autocommit source statement.
    pub fn mark_commit_started(&self) {
        self.commit_unproven.store(true, Ordering::Release);
    }

    /// Disarm only after the source statement or COMMIT returned proven success.
    pub fn mark_commit_proven(&self) {
        self.commit_unproven.store(false, Ordering::Release);
    }

    /// A failed COMMIT is unknown until an independent durable reconciliation proves it.
    pub fn mark_uncertain(&self) {
        if let Ok(mut maps) = self.hub.maps.write() {
            maps.uncertain_source = true;
            maps.suspect("source commit outcome unknown");
        }
    }
}

impl Drop for SourceTransactionGuard {
    fn drop(&mut self) {
        // Clear before releasing the writer gate; cache locks never acquire the hub lock.
        invalidate_positive_read_caches();
        if let Ok(mut maps) = self.hub.maps.write() {
            if self.commit_unproven.load(Ordering::Acquire) {
                maps.uncertain_source = true;
                maps.suspect("source commit cancelled or outcome unknown");
            }
            maps.active_source_writers = maps.active_source_writers.saturating_sub(1);
            maps.mutation_revision = maps.mutation_revision.saturating_add(1);
            maps.source_revision = maps.source_revision.saturating_add(1);
            maps.bump_auxiliary_epochs();
        }
    }
}

/// Org fact writers share the active writer gate, but only advance the org epoch.
pub struct OrgSourceTransactionGuard {
    hub: MemoryProjectionHub,
    commit_unproven: AtomicBool,
}

impl OrgSourceTransactionGuard {
    /// Arm before awaiting COMMIT.
    pub fn mark_commit_started(&self) {
        self.commit_unproven.store(true, Ordering::Release);
    }

    /// Disarm only after COMMIT returned proven success.
    pub fn mark_commit_proven(&self) {
        self.commit_unproven.store(false, Ordering::Release);
    }

    /// A failed COMMIT is unknown until an independent durable reconciliation proves it.
    pub fn mark_uncertain(&self) {
        if let Ok(mut maps) = self.hub.maps.write() {
            maps.uncertain_source = true;
            maps.suspect("org source commit outcome unknown");
        }
    }
}

impl Drop for OrgSourceTransactionGuard {
    fn drop(&mut self) {
        invalidate_positive_read_caches();
        if let Ok(mut maps) = self.hub.maps.write() {
            if self.commit_unproven.load(Ordering::Acquire) {
                maps.uncertain_source = true;
                maps.suspect("org source commit cancelled or outcome unknown");
            }
            maps.active_source_writers = maps.active_source_writers.saturating_sub(1);
            maps.mutation_revision = maps.mutation_revision.saturating_add(1);
            maps.source_revision = maps.source_revision.saturating_add(1);
            maps.auxiliary_org_epoch = maps.auxiliary_org_epoch.saturating_add(1);
        }
    }
}

/// 单个租户的 pending 分桶。
#[derive(Default)]
struct TenantPending {
    per_card: HashMap<i64, Vec<PendingDeltaEntry>>,
    aggregate_wide: Vec<PendingDeltaEntry>,
}

impl TenantPending {
    fn push(&mut self, card_id: Option<i64>, entry: PendingDeltaEntry) -> bool {
        let entries = match card_id {
            Some(card) => self.per_card.entry(card).or_default(),
            None => &mut self.aggregate_wide,
        };
        if entries.contains(&entry) {
            return false;
        }
        entries.push(entry);
        true
    }

    fn len(&self) -> usize {
        self.aggregate_wide.len() + self.per_card.values().map(Vec::len).sum::<usize>()
    }

    fn complete_publication(&mut self, state: &AuthorizationPublishedState) {
        let completed = |entry: &PendingDeltaEntry| {
            entry.aggregate.as_ref() == Some(&state.pointer.identity)
                && entry.event_id == state.event_id
                && entry.operation_id == state.operation_id
                && entry.source_generation == state.source_generation
                && entry
                    .published_generation
                    .is_none_or(|generation| state.generation > generation)
                && entry.revoke_fence <= state.revoke_fence
        };
        self.aggregate_wide.retain(|entry| !completed(entry));
        if let Some(card_id) = state.pointer.card_id {
            if let Some(entries) = self.per_card.get_mut(&card_id) {
                entries.retain(|entry| !completed(entry));
                if entries.is_empty() {
                    self.per_card.remove(&card_id);
                }
            }
        }
    }

    /// 该卡是否被 pending 拦截（O(1) 定位 + 小集合扫描）。
    fn blocks(
        &self,
        card_id: i64,
        states: &HashMap<ProjectionAggregateIdentity, Arc<AuthorizationPublishedState>>,
    ) -> bool {
        fn entry_blocks(
            entry: &PendingDeltaEntry,
            states: &HashMap<ProjectionAggregateIdentity, Arc<AuthorizationPublishedState>>,
        ) -> bool {
            if entry.revoke_class {
                return true;
            }
            let installed_fence = entry
                .aggregate
                .as_ref()
                .and_then(|aggregate| states.get(aggregate))
                .map(|state| state.revoke_fence)
                .unwrap_or(0);
            entry.revoke_fence > installed_fence
        }
        self.aggregate_wide
            .iter()
            .chain(self.per_card.get(&card_id).into_iter().flatten())
            .any(|entry| entry_blocks(entry, states))
    }
}

#[derive(Debug, Clone)]
pub struct EvidenceInvalidationRequest {
    pub tenant_id: i64,
    pub card_id: Option<i64>,
    pub aggregate_type: PublishedEvidenceAggregate,
    pub aggregate_id: i64,
    pub event_id: String,
    pub operation_id: String,
    pub source_generation: u64,
    pub revoke_fence: u64,
    /// Published frontier observed by the notification producer. This is
    /// provenance only and is compared only with the same aggregate's
    /// installed publication generation.
    pub published_generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReadToken {
    health: u64,
    source: u64,
    tenant: u64,
    card: u64,
}

impl ReadToken {
    fn for_scope(maps: &HubMaps, scope: &PublishedCardEvidenceScope) -> Self {
        Self {
            health: maps.health_revision,
            source: maps.source_revision,
            tenant: maps
                .tenant_epochs
                .get(&scope.tenant_id)
                .copied()
                .unwrap_or(0),
            card: maps
                .card_epochs
                .get(&(scope.tenant_id, scope.card_id))
                .copied()
                .unwrap_or(0),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RefillScope {
    tenant_id: i64,
    card_id: i64,
    user: Option<i64>,
    domain: astral_types::DomainScopeRequirement,
}

impl From<&PublishedCardEvidenceScope> for RefillScope {
    fn from(scope: &PublishedCardEvidenceScope) -> Self {
        Self {
            tenant_id: scope.tenant_id,
            card_id: scope.card_id,
            user: scope.user_filter,
            domain: scope.domain,
        }
    }
}

#[derive(Default)]
struct RefillCoordinator {
    scopes: std::sync::Mutex<HashMap<RefillScope, Weak<tokio::sync::Mutex<()>>>>,
}

impl RefillCoordinator {
    fn lock_for(
        &self,
        scope: &PublishedCardEvidenceScope,
    ) -> Result<Arc<tokio::sync::Mutex<()>>, String> {
        let mut scopes = self
            .scopes
            .lock()
            .map_err(|_| "refill coordinator lock poisoned")?;
        scopes.retain(|_, lock| lock.strong_count() != 0);
        let key = RefillScope::from(scope);
        if let Some(lock) = scopes.get(&key).and_then(Weak::upgrade) {
            return Ok(lock);
        }
        if scopes.len() >= 1_024 {
            return Err("strict refill concurrency capacity exhausted".to_owned());
        }
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        scopes.insert(key, Arc::downgrade(&lock));
        Ok(lock)
    }
}

/// 单机内存镜像中心。克隆共享同一状态（Arc）。
#[derive(Clone, Default)]
pub struct MemoryProjectionHub {
    maps: Arc<RwLock<HubMaps>>,
    refills: Arc<RefillCoordinator>,
    assemblies: Arc<AssemblyCache>,
}

/// 内存读面结果：`Serve` = 与 durable 一致的已验证证据；`DeferToDurable` =
/// 交回权威 DB reader（未预热/pending 命中/装配异常）。
#[derive(Debug)]
pub enum MemoryEvidenceOutcome {
    Serve(PublishedCardAuthorization),
    DeferToDurable,
}

impl HubMaps {
    fn refill_token_matches(&self, token: ReadToken, scope: &PublishedCardEvidenceScope) -> bool {
        token == ReadToken::for_scope(self, scope)
            && self.active_source_writers == 0
            && !self.uncertain_source
            && !self.authority_fence_unavailable()
    }

    fn bump_scope(&mut self, tenant_id: i64, card_id: Option<i64>) {
        if self.card_epochs.len() >= MAX_MIRROR_STATES {
            self.card_epochs.clear();
            self.health_revision = self.health_revision.saturating_add(1);
        }
        if self.tenant_epochs.len() >= MAX_MIRROR_STATES {
            self.tenant_epochs.clear();
            self.health_revision = self.health_revision.saturating_add(1);
        }
        self.mutation_revision = self.mutation_revision.saturating_add(1);
        let epoch = match card_id {
            Some(card_id) => self.card_epochs.entry((tenant_id, card_id)).or_default(),
            None => self.tenant_epochs.entry(tenant_id).or_default(),
        };
        *epoch = self.mutation_revision;
    }

    fn suspect(&mut self, reason: impl Into<String>) {
        self.last_transport_heartbeat = None;
        self.channel = ChannelHealth::Suspect {
            reason: reason.into().chars().take(256).collect(),
        };
        self.health_revision = self.health_revision.saturating_add(1);
        self.mutation_revision = self.mutation_revision.saturating_add(1);
        self.bump_auxiliary_epochs();
    }

    fn state_bytes(state: &AuthorizationPublishedState) -> u64 {
        state.segments.iter().fold(1_024_u64, |sum, segment| {
            sum.saturating_add(segment.byte_size).saturating_add(512)
        })
    }

    fn evict_expired(&mut self, now: Instant) {
        let expired: Vec<_> = self
            .installed_at
            .iter()
            .filter(|(_, at)| now.saturating_duration_since(**at) > MIRROR_TTL)
            .map(|(identity, _)| identity.clone())
            .collect();
        for identity in expired {
            if let Some(state) = self.states.remove(&identity) {
                self.mirror_bytes = self.mirror_bytes.saturating_sub(Self::state_bytes(&state));
                self.bump_scope(identity.tenant_id, state.pointer.card_id);
            }
            self.installed_at.remove(&identity);
        }
        self.completed
            .retain(|_, receipt| now.saturating_duration_since(receipt.installed_at) <= MIRROR_TTL);
    }

    fn index_aggregate(
        &mut self,
        identity: &ProjectionAggregateIdentity,
        card_id: i64,
    ) -> Result<(), String> {
        let key = (identity.tenant_id, card_id);
        if self
            .card_index
            .get(&key)
            .is_some_and(|entries| entries.contains(identity))
        {
            return Ok(());
        }
        if self.card_index_entries >= MAX_MIRROR_STATES {
            self.suspect("memory aggregate index capacity exhausted");
            return Err("memory aggregate index capacity exhausted".to_owned());
        }
        self.card_index
            .entry(key)
            .or_default()
            .insert(identity.clone());
        self.card_index_entries += 1;
        Ok(())
    }

    fn install(&mut self, state: Arc<AuthorizationPublishedState>) {
        let identity = &state.pointer.identity;
        if let Some(existing) = self.states.get(identity) {
            if existing.generation > state.generation {
                return;
            }
            if existing.generation == state.generation {
                if **existing != *state {
                    self.suspect("same-generation publication divergence");
                } else {
                    self.installed_at.insert(identity.clone(), Instant::now());
                }
                return;
            }
        }
        let bytes = Self::state_bytes(&state);
        let mut existing_bytes = self
            .states
            .get(identity)
            .map_or(0, |state| Self::state_bytes(state));
        if !self.states.contains_key(identity) && self.states.len() >= MAX_MIRROR_STATES
            || self
                .mirror_bytes
                .saturating_sub(existing_bytes)
                .saturating_add(bytes)
                > MAX_MIRROR_BYTES
        {
            self.evict_expired(Instant::now());
            existing_bytes = self
                .states
                .get(identity)
                .map_or(0, |state| Self::state_bytes(state));
        }
        if !self.states.contains_key(identity) && self.states.len() >= MAX_MIRROR_STATES
            || self
                .mirror_bytes
                .saturating_sub(existing_bytes)
                .saturating_add(bytes)
                > MAX_MIRROR_BYTES
        {
            self.suspect("memory mirror capacity exhausted");
            return;
        }
        if let Some(card_id) = state.pointer.card_id {
            if self.index_aggregate(identity, card_id).is_err() {
                return;
            }
        }
        self.bump_scope(identity.tenant_id, state.pointer.card_id);
        self.mirror_bytes = self
            .mirror_bytes
            .saturating_sub(existing_bytes)
            .saturating_add(bytes);
        self.installed_at.insert(identity.clone(), Instant::now());
        self.states.insert(identity.clone(), state);
    }

    fn record_pending(
        &mut self,
        tenant_id: i64,
        card_id: Option<i64>,
        entry: PendingDeltaEntry,
    ) -> Result<(), sqlx::Error> {
        let duplicate = self
            .pending
            .get(&tenant_id)
            .is_some_and(|pending| match card_id {
                Some(card_id) => pending
                    .per_card
                    .get(&card_id)
                    .is_some_and(|entries| entries.contains(&entry)),
                None => pending.aggregate_wide.contains(&entry),
            });
        if duplicate {
            return Ok(());
        }
        if self.pending_count >= MAX_PENDING_ENTRIES {
            self.suspect("pending invalidation capacity exhausted");
            return Err(sqlx::Error::Protocol(
                "pending invalidation capacity exhausted".to_owned(),
            ));
        }
        if self
            .pending
            .entry(tenant_id)
            .or_default()
            .push(card_id, entry)
        {
            self.pending_count += 1;
            self.bump_scope(tenant_id, card_id);
        }
        Ok(())
    }
}

impl MemoryProjectionHub {
    /// Acquire before opening the database transaction and hold through commit or rollback.
    ///
    /// Generic（不可归因）source writer：begin/drop 保守失效全部辅助镜像条目
    /// （GA 与 org 物理绑定事实都可能被本写者触碰）。
    pub fn begin_source_transaction(&self) -> Option<SourceTransactionGuard> {
        {
            let mut maps = self.maps.write().ok()?;
            if maps.authority_fence_unavailable() {
                return None;
            }
            maps.active_source_writers = maps.active_source_writers.checked_add(1)?;
            maps.mutation_revision = maps.mutation_revision.saturating_add(1);
            maps.source_revision = maps.source_revision.saturating_add(1);
            maps.bump_auxiliary_epochs();
        }
        invalidate_positive_read_caches();
        Some(SourceTransactionGuard {
            hub: self.clone(),
            commit_unproven: AtomicBool::new(false),
        })
    }

    /// org authority 事实写点专用栅栏：只失效 org 辅助纪元（org 写者不触碰
    /// `identity_global_admin`），`active_source_writers` 语义与 generic 一致。
    pub fn begin_org_source_transaction(&self) -> Option<OrgSourceTransactionGuard> {
        {
            let mut maps = self.maps.write().ok()?;
            if maps.authority_fence_unavailable() {
                return None;
            }
            maps.active_source_writers = maps.active_source_writers.checked_add(1)?;
            maps.mutation_revision = maps.mutation_revision.saturating_add(1);
            maps.source_revision = maps.source_revision.saturating_add(1);
            maps.auxiliary_org_epoch = maps.auxiliary_org_epoch.saturating_add(1);
        }
        invalidate_positive_read_caches();
        Some(OrgSourceTransactionGuard {
            hub: self.clone(),
            commit_unproven: AtomicBool::new(false),
        })
    }

    pub(crate) fn auxiliary_read_gate(&self) -> AuxiliaryReadGate {
        self.maps
            .read()
            .map(|maps| maps.auxiliary_read_gate())
            .unwrap_or(AuxiliaryReadGate::Uncertain)
    }

    pub(crate) fn strict_read_token(&self) -> Option<AuxiliaryReadToken> {
        let maps = self.maps.read().ok()?;
        if maps.active_source_writers != 0
            || maps.uncertain_source
            || maps.authority_fence_unavailable()
        {
            return None;
        }
        Some(AuxiliaryReadToken {
            org_epoch: maps.auxiliary_org_epoch,
            global_admin_epoch: maps.auxiliary_global_admin_epoch,
            mutation_revision: maps.mutation_revision,
            health_revision: maps.health_revision,
        })
    }

    pub fn capture_authority_fence(&self) -> Option<AuthorityReadFence> {
        self.strict_read_token().map(AuthorityReadFence)
    }

    pub fn authority_fence_matches(&self, fence: AuthorityReadFence) -> bool {
        self.strict_read_matches(fence.0)
    }

    pub(crate) fn strict_read_matches(&self, token: AuxiliaryReadToken) -> bool {
        self.strict_read_token() == Some(token)
    }

    pub(crate) fn auxiliary_read_matches(&self, token: AuxiliaryReadToken) -> bool {
        self.auxiliary_read_gate() == AuxiliaryReadGate::Ready(token)
    }

    /// 是否存在未闭合的 source writer（辅助镜像据此直接 fail-closed，
    /// 绝不在 writer-active 期间回源旧状态放行）。
    #[must_use]
    pub fn has_active_source_writer(&self) -> bool {
        self.maps
            .read()
            .map(|maps| maps.active_source_writers != 0)
            .unwrap_or(true)
    }

    /// 辅助镜像 org 条目的当前纪元（条目可信要求安装纪元 == 当前纪元）。
    #[must_use]
    pub fn auxiliary_org_epoch(&self) -> u64 {
        self.maps
            .read()
            .map(|maps| maps.auxiliary_org_epoch)
            .unwrap_or(u64::MAX)
    }

    /// 辅助镜像 GlobalAdmin 条目的当前纪元。
    #[must_use]
    pub fn auxiliary_global_admin_epoch(&self) -> u64 {
        self.maps
            .read()
            .map(|maps| maps.auxiliary_global_admin_epoch)
            .unwrap_or(u64::MAX)
    }

    /// 辅助镜像整体失效 org 条目时由镜像模块调用（条目清空 + 纪元推进）。
    pub fn bump_auxiliary_org_epoch(&self) {
        if let Ok(mut maps) = self.maps.write() {
            maps.auxiliary_org_epoch = maps.auxiliary_org_epoch.saturating_add(1);
        }
    }

    fn begin_warmup(&self) -> Result<(), sqlx::Error> {
        let mut maps = self
            .maps
            .write()
            .map_err(|_| sqlx::Error::Protocol("memory projection hub lock poisoned".to_owned()))?;
        maps.warming_up = true;
        if !matches!(maps.channel, ChannelHealth::Unmonitored) {
            maps.suspect("memory mirror warm-up requires durable reconciliation");
        }
        maps.last_transport_heartbeat = None;
        maps.notification_watermarks.clear();
        maps.completed.clear();
        maps.installed_at.clear();
        maps.mirror_bytes = 0;
        maps.pending_count = 0;
        maps.health_revision = maps.health_revision.saturating_add(1);
        maps.mutation_revision = maps.mutation_revision.saturating_add(1);
        maps.bump_auxiliary_epochs();
        maps.states.clear();
        maps.card_index.clear();
        maps.card_index_entries = 0;
        maps.pending.clear();
        Ok(())
    }

    fn finish_warmup(&self) -> Result<(), sqlx::Error> {
        let mut maps = self
            .maps
            .write()
            .map_err(|_| sqlx::Error::Protocol("memory projection hub lock poisoned".to_owned()))?;
        maps.warming_up = false;
        maps.last_transport_heartbeat = None;
        maps.channel = ChannelHealth::Suspect {
            reason: "memory mirror warm-up completed; transport recovery not proven".to_owned(),
        };
        maps.health_revision = maps.health_revision.saturating_add(1);
        maps.bump_auxiliary_epochs();
        Ok(())
    }

    /// Record liveness using a monotonic clock; a heartbeat cannot clear suspect mode.
    pub fn record_channel_heartbeat(&self) {
        if let Ok(mut maps) = self.maps.write() {
            maps.last_transport_heartbeat = Some(Instant::now());
            if !matches!(maps.channel, ChannelHealth::Suspect { .. }) {
                maps.channel = ChannelHealth::Healthy {
                    last_heartbeat: Instant::now(),
                };
            }
        }
    }

    /// Discard source-derived auxiliary facts when a committed eligibility event arrives.
    pub fn apply_auxiliary_invalidation(&self) -> Result<(), String> {
        {
            let mut maps = self
                .maps
                .write()
                .map_err(|_| "memory projection hub lock poisoned")?;
            maps.mutation_revision = maps.mutation_revision.saturating_add(1);
            maps.source_revision = maps.source_revision.saturating_add(1);
            maps.bump_auxiliary_epochs();
        }
        invalidate_positive_read_caches();
        Ok(())
    }

    /// Enter sticky suspect mode. Only a complete durable reconciliation can clear it.
    pub fn mark_channel_suspect(&self, reason: impl Into<String>) {
        if let Ok(mut maps) = self.maps.write() {
            maps.suspect(reason);
        }
        invalidate_positive_read_caches();
    }

    /// A required owner cannot recover through channel heartbeat or pointer reconciliation.
    pub fn mark_runtime_owner_failed(&self, reason: impl Into<String>) {
        if let Ok(mut maps) = self.maps.write() {
            maps.runtime_owner_failed = true;
            maps.suspect(reason);
        }
        invalidate_positive_read_caches();
    }

    #[must_use]
    pub fn channel_is_suspect(&self) -> bool {
        self.maps
            .read()
            .map(|maps| channel_blocks(&maps.channel, Instant::now()))
            .unwrap_or(true)
    }

    /// A monitored, fresh channel and a completed warm-up are required by auxiliary mirrors.
    #[must_use]
    pub fn channel_is_healthy(&self) -> bool {
        self.maps
            .read()
            .map(|maps| {
                !maps.warming_up
                    && !maps.authority_fence_unavailable()
                    && matches!(maps.channel, ChannelHealth::Healthy { .. })
                    && !channel_blocks(&maps.channel, Instant::now())
            })
            .unwrap_or(false)
    }

    /// Installed immutable state for pure planning; the publication transaction
    /// must still revalidate its pointer, lineage, lease and fence.
    pub fn installed_published_state(
        &self,
        identity: &ProjectionAggregateIdentity,
    ) -> Option<Arc<AuthorizationPublishedState>> {
        let maps = self.maps.read().ok()?;
        if maps.warming_up
            || maps
                .installed_at
                .get(identity)
                .is_none_or(|at| at.elapsed() > MIRROR_TTL)
        {
            return None;
        }
        maps.states.get(identity).cloned()
    }

    /// Highest notification frontier applied for this exact aggregate; not a state proof.
    #[must_use]
    pub fn applied_generation_watermark(
        &self,
        identity: &ProjectionAggregateIdentity,
    ) -> Option<u64> {
        self.maps
            .read()
            .ok()
            .and_then(|maps| maps.notification_watermarks.get(identity).copied())
    }

    /// Generation of the installed state, independent of notification delivery.
    #[must_use]
    pub fn installed_generation(&self, identity: &ProjectionAggregateIdentity) -> Option<u64> {
        self.maps
            .read()
            .ok()
            .and_then(|maps| maps.states.get(identity).map(|state| state.generation))
    }

    fn expect_published_aggregate(
        &self,
        identity: &ProjectionAggregateIdentity,
        card_id: Option<i64>,
    ) -> Result<(), sqlx::Error> {
        if let Some(card_id) = card_id {
            if card_id <= 0 {
                return Err(sqlx::Error::Protocol(
                    "invalid warm-up card scope".to_owned(),
                ));
            }
            let mut maps = self.maps.write().map_err(|_| {
                sqlx::Error::Protocol("memory projection hub lock poisoned".to_owned())
            })?;
            maps.index_aggregate(identity, card_id)
                .map_err(sqlx::Error::Protocol)?;
        }
        Ok(())
    }

    fn record_pending_entry(
        &self,
        tenant_id: i64,
        card_id: Option<i64>,
        entry: PendingDeltaEntry,
    ) -> Result<(), sqlx::Error> {
        let mut maps = self
            .maps
            .write()
            .map_err(|_| sqlx::Error::Protocol("memory projection hub lock poisoned".to_owned()))?;
        maps.record_pending(tenant_id, card_id, entry)
    }

    /// 在 source transaction 提交前登记意图。回滚残留只会持续回退 DB；
    /// 同 source generation 的其他 delta 完成不能解除本事件。
    pub fn record_pending_delta(&self, request: &DeltaEventAppendRequest) {
        let revoke_class = request.invalidates_published_evidence
            || matches!(
                request.event_type,
                DeltaEventType::Remove | DeltaEventType::Revoke
            );
        if !revoke_class && request.revoke_fence == 0 {
            return;
        }
        let aggregate = ProjectionAggregateIdentity::new(
            request.tenant_id,
            request.aggregate_type.clone(),
            request.aggregate_id,
        )
        .ok();
        let entry = PendingDeltaEntry {
            aggregate,
            event_id: request.event_id.clone(),
            operation_id: request.operation_id.clone(),
            source_generation: request.source_generation,
            published_generation: None,
            revoke_class,
            revoke_fence: request.revoke_fence,
        };
        let _ = self.record_pending_entry(request.tenant_id, request.card_id, entry);
    }

    /// Apply a typed post-commit evidence invalidation notification. The
    /// notification is only a freshness fence: it never installs or removes
    /// authorization state. Missing hub or malformed provenance fails closed.
    pub fn apply_evidence_invalidation(
        &self,
        request: EvidenceInvalidationRequest,
    ) -> Result<(), String> {
        if request.tenant_id <= 0
            || request.card_id.is_some_and(|value| value <= 0)
            || request.event_id.len() > 128
            || request.operation_id.len() > 128
            || request.event_id.trim().is_empty()
            || request.operation_id.trim().is_empty()
            || request.source_generation == 0
            || request.published_generation == 0
            || request.revoke_fence > request.source_generation
        {
            return Err("invalid evidence invalidation provenance".to_owned());
        }
        if request.card_id.is_some()
            && request.aggregate_type == PublishedEvidenceAggregate::UserCard
            && Some(request.aggregate_id) != request.card_id
        {
            return Err("published USER_CARD aggregate id does not match card scope".to_owned());
        }
        let aggregate = ProjectionAggregateIdentity::new(
            request.tenant_id,
            request.aggregate_type.as_str(),
            request.aggregate_id,
        )
        .map_err(|error| error.to_string())?;
        let mut maps = self
            .maps
            .write()
            .map_err(|_| "memory projection hub lock poisoned".to_owned())?;
        let completed = maps
            .completed
            .get(&CompletionIdentity {
                aggregate: aggregate.clone(),
                event_id: request.event_id.clone(),
                operation_id: request.operation_id.clone(),
                source_generation: request.source_generation,
            })
            .is_some_and(|receipt| {
                receipt.generation > request.published_generation
                    && receipt.revoke_fence >= request.revoke_fence
                    && receipt.installed_at.elapsed() <= MIRROR_TTL
            });
        if !completed {
            maps.record_pending(
                request.tenant_id,
                request.card_id,
                PendingDeltaEntry {
                    aggregate: Some(aggregate.clone()),
                    event_id: request.event_id,
                    operation_id: request.operation_id,
                    source_generation: request.source_generation,
                    published_generation: Some(request.published_generation),
                    revoke_class: true,
                    revoke_fence: request.revoke_fence,
                },
            )
            .map_err(|error| error.to_string())?;
        }
        maps.notification_watermarks
            .entry(aggregate)
            .and_modify(|generation| *generation = (*generation).max(request.published_generation))
            .or_insert(request.published_generation);
        Ok(())
    }

    /// 安装严格 reader 装载的状态；不把读取成功当作未完成 delta 的终态证明。
    pub fn install_published_state(&self, state: AuthorizationPublishedState) {
        if let Ok(mut maps) = self.maps.write() {
            maps.install(Arc::new(state));
        }
    }

    /// 仅在 projector 事务 commit 成功后调用：安装同一事务已验证的发布状态，
    /// 并解除该事务已完成的单个 delta。未知 commit 不能进入此入口。
    pub fn install_committed_publication(
        &self,
        outcome: &DeltaProjectorPublishOutcome,
    ) -> Result<(), String> {
        let state = &outcome.publish.published_state;
        if state.pointer != outcome.publish.pointer
            || state.pointer.current_generation != state.generation
            || state.pointer.manifest_id != state.manifest_id
            || state.pointer.event_id != state.event_id
            || state.pointer.operation_id != state.operation_id
            || state.pointer.revoke_fence != state.revoke_fence
            || !state.pointer.revoke_fence_proven
            || state.manifest_id != outcome.publish.published_manifest_id
            || state.manifest_id != outcome.stage.manifest_id
            || state.generation != outcome.stage.target_generation
            || state.manifest_digest != outcome.stage.manifest_digest
            || state.total_grant_count != outcome.stage.total_grant_count
        {
            return Err("committed publication state disagrees with its outcome".to_owned());
        }
        let mut maps = self
            .maps
            .write()
            .map_err(|_| "memory projection hub lock poisoned".to_owned())?;
        maps.install(state.clone());
        let installed = maps
            .states
            .get(&state.pointer.identity)
            .is_some_and(|current| {
                current.generation > state.generation
                    || (current.generation == state.generation
                        && current.manifest_id == state.manifest_id
                        && current.manifest_digest == state.manifest_digest)
            });
        if !installed {
            return Err("committed publication could not be installed".to_owned());
        }
        let removed = if let Some(pending) = maps.pending.get_mut(&state.pointer.identity.tenant_id)
        {
            let before = pending.len();
            pending.complete_publication(state);
            before - pending.len()
        } else {
            0
        };
        maps.pending_count = maps.pending_count.saturating_sub(removed);
        if maps
            .pending
            .get(&state.pointer.identity.tenant_id)
            .is_some_and(|pending| pending.len() == 0)
        {
            maps.pending.remove(&state.pointer.identity.tenant_id);
        }
        maps.bump_scope(state.pointer.identity.tenant_id, state.pointer.card_id);
        maps.completed
            .retain(|_, receipt| receipt.installed_at.elapsed() <= MIRROR_TTL);
        if maps.completed.len() >= MAX_COMPLETED_RECEIPTS {
            if let Some(oldest) = maps
                .completed
                .iter()
                .min_by_key(|(_, receipt)| receipt.installed_at)
                .map(|(identity, _)| identity.clone())
            {
                maps.completed.remove(&oldest);
            }
        }
        maps.completed.insert(
            CompletionIdentity {
                aggregate: state.pointer.identity.clone(),
                event_id: state.event_id.clone(),
                operation_id: state.operation_id.clone(),
                source_generation: state.source_generation,
            },
            CompletionReceipt {
                generation: state.generation,
                revoke_fence: state.revoke_fence,
                installed_at: Instant::now(),
            },
        );
        Ok(())
    }

    /// Coalesce one strict refill per complete tenant/card/user/domain scope.
    pub async fn strict_refill(
        &self,
        pool: &MySqlPool,
        scope: &PublishedCardEvidenceScope,
    ) -> Result<PublishedCardAuthorization, astral_types::PolicyError> {
        let repository_error = |reason: String| astral_types::PolicyError::Repository(reason);
        scope
            .validate()
            .map_err(|error| repository_error(error.to_string()))?;
        let lock = self.refills.lock_for(scope).map_err(repository_error)?;
        let _guard = tokio::time::timeout(Duration::from_secs(3), lock.lock())
            .await
            .map_err(|_| repository_error("strict refill wait timed out".to_owned()))?;
        if let MemoryEvidenceOutcome::Serve(evidence) = self.try_memory_evidence(scope) {
            return Ok(evidence);
        }
        let token = {
            let maps = self
                .maps
                .read()
                .map_err(|_| repository_error("memory projection hub lock poisoned".to_owned()))?;
            if maps.active_source_writers != 0
                || maps.uncertain_source
                || maps.authority_fence_unavailable()
            {
                return Err(repository_error(
                    "source writer or unknown commit blocks strict refill".to_owned(),
                ));
            }
            ReadToken::for_scope(&maps, scope)
        };
        let bundle = tokio::time::timeout(
            Duration::from_secs(3),
            crate::load_published_card_state_bundle(pool, scope),
        )
        .await
        .map_err(|_| repository_error("strict refill query timed out".to_owned()))?
        .map_err(|error| repository_error(error.to_string()))?;
        let evidence = bundle
            .evidence_at(OffsetDateTime::now_utc().unix_timestamp())
            .map_err(|error| repository_error(error.to_string()))?;
        let completion_token = self
            .install_strict_refill(token, scope, bundle.states())
            .map_err(repository_error)?;
        {
            let maps = self
                .maps
                .read()
                .map_err(|_| repository_error("memory projection hub lock poisoned".to_owned()))?;
            if !maps.refill_token_matches(completion_token, scope) {
                return Err(repository_error(
                    "invalidation raced strict refill return".to_owned(),
                ));
            }
        }
        Ok(evidence)
    }

    fn install_strict_refill(
        &self,
        token: ReadToken,
        scope: &PublishedCardEvidenceScope,
        states: &[AuthorizationPublishedState],
    ) -> Result<ReadToken, String> {
        let mut maps = self
            .maps
            .write()
            .map_err(|_| "memory projection hub lock poisoned")?;
        if !maps.refill_token_matches(token, scope) {
            return Err("invalidation raced strict refill".to_owned());
        }
        let health = maps.health_revision;
        for state in states {
            maps.install(Arc::new(state.clone()));
        }
        if maps.health_revision != health
            || maps.authority_fence_unavailable()
            || states.iter().any(|state| {
                maps.states
                    .get(&state.pointer.identity)
                    .is_none_or(|installed| installed.as_ref() != state)
            })
        {
            return Err("strict refill mirror installation unproven".to_owned());
        }
        Ok(ReadToken::for_scope(&maps, scope))
    }

    /// Reconcile all current pointers and pending events before clearing suspect mode.
    /// Concurrent source transactions or changed durable frontiers leave the gate closed.
    pub async fn reconcile_from_durable(&self, pool: &MySqlPool) -> Result<WarmReport, String> {
        let (revision, local_pending, uncertain) = {
            let maps = self
                .maps
                .read()
                .map_err(|_| "memory projection hub lock poisoned")?;
            if maps.authority_fence_unavailable() {
                return Err("runtime owner or authority clock unavailable".to_owned());
            }
            if maps.active_source_writers != 0 {
                return Err("source transaction is active; reconciliation deferred".to_owned());
            }
            let pending = maps
                .pending
                .iter()
                .flat_map(|(tenant_id, pending)| {
                    let scoped = pending.per_card.iter().flat_map(move |(card_id, entries)| {
                        entries
                            .iter()
                            .cloned()
                            .map(move |entry| (*tenant_id, Some(*card_id), entry))
                    });
                    scoped.chain(
                        pending
                            .aggregate_wide
                            .iter()
                            .cloned()
                            .map(move |entry| (*tenant_id, None, entry)),
                    )
                })
                .collect::<Vec<_>>();
            (maps.mutation_revision, pending, maps.uncertain_source)
        };
        if uncertain {
            return Err(
                "unknown source commit requires independent writer outcome proof".to_owned(),
            );
        }
        let attempt = self.read_reconciliation(pool, &local_pending).await;
        let (frontier, pending_rows, states) = match attempt {
            Ok(proof) => proof,
            Err(error) => {
                self.mark_channel_suspect("durable reconciliation failed");
                return Err(error);
            }
        };
        invalidate_positive_read_caches();
        let mut maps = self
            .maps
            .write()
            .map_err(|_| "memory projection hub lock poisoned")?;
        if maps.authority_fence_unavailable()
            || maps.active_source_writers != 0
            || maps.mutation_revision != revision
        {
            return Err("memory mutation raced durable reconciliation".to_owned());
        }
        let mut replacement = HashMap::<i64, TenantPending>::new();
        for row in pending_rows {
            let (tenant_id, card_id, entry) = row.decode().map_err(|error| error.to_string())?;
            replacement
                .entry(tenant_id)
                .or_default()
                .push(card_id, entry);
        }
        maps.evict_expired(Instant::now());
        let expected: HashSet<_> = frontier
            .iter()
            .map(CurrentFrontierRow::identity)
            .collect::<Result<_, _>>()?;
        maps.card_index.clear();
        maps.card_index_entries = 0;
        for row in &frontier {
            if let Some(card_id) = row.card_id {
                maps.index_aggregate(&row.identity()?, card_id)?;
            }
        }
        for state in states {
            maps.install(Arc::new(state));
        }
        if frontier.iter().any(|row| {
            row.identity()
                .ok()
                .and_then(|identity| maps.states.get(&identity))
                .is_none_or(|state| !row.matches(state))
        }) {
            maps.suspect("mirror does not cover the reconciled durable frontier");
            return Err("incomplete reconciled memory mirror".to_owned());
        }
        maps.states
            .retain(|identity, _| expected.contains(identity));
        maps.installed_at
            .retain(|identity, _| expected.contains(identity));
        for identity in expected {
            maps.installed_at.insert(identity, Instant::now());
        }
        maps.mirror_bytes = maps
            .states
            .values()
            .map(|state| HubMaps::state_bytes(state))
            .sum();
        maps.pending_count = replacement.values().map(TenantPending::len).sum();
        maps.pending = replacement;
        if maps.last_transport_heartbeat.is_none_or(|last| {
            heartbeat_silence_blocks(
                last,
                Instant::now(),
                Duration::from_millis(CHANNEL_MAX_HEARTBEAT_SILENCE_MS),
            )
        }) {
            maps.suspect("transport recovery heartbeat has not been proven");
            return Err("transport recovery heartbeat has not been proven".to_owned());
        }
        maps.uncertain_source = false;
        maps.warming_up = false;
        maps.channel = ChannelHealth::Healthy {
            last_heartbeat: Instant::now(),
        };
        maps.health_revision = maps.health_revision.saturating_add(1);
        maps.mutation_revision = maps.mutation_revision.saturating_add(1);
        maps.bump_auxiliary_epochs();
        Ok(WarmReport {
            identities: frontier.len(),
            installed: frontier.len(),
            failed: 0,
            pending_restored: maps.pending_count,
        })
    }

    async fn read_reconciliation(
        &self,
        pool: &MySqlPool,
        local_pending: &[(i64, Option<i64>, PendingDeltaEntry)],
    ) -> Result<
        (
            Vec<CurrentFrontierRow>,
            Vec<PendingInvalidationRow>,
            Vec<AuthorizationPublishedState>,
        ),
        String,
    > {
        // Locking an event's unique key waits for an unfinished source transaction;
        // a nonlocking missing-row read cannot prove its rollback.
        for (tenant_id, card_id, entry) in local_pending {
            let mut tx = pool.begin().await.map_err(|error| error.to_string())?;
            let row = sqlx::query_as::<_, (i64, Option<i64>, String, i64, String, i64, i64)>(
                "SELECT tenant_id, card_id, aggregate_type, aggregate_id, operation_id, source_generation, revoke_fence \
                 FROM authorization_delta_event WHERE event_id = ? FOR UPDATE")
                .bind(&entry.event_id).fetch_optional(&mut *tx).await.map_err(|error| error.to_string())?;
            if let Some((tenant, card, aggregate_type, aggregate_id, operation_id, source, fence)) =
                row
            {
                let identity =
                    ProjectionAggregateIdentity::new(tenant, aggregate_type, aggregate_id)
                        .map_err(|error| error.to_string())?;
                if tenant != *tenant_id
                    || card != *card_id
                    || entry.aggregate.as_ref() != Some(&identity)
                    || entry.operation_id != operation_id
                    || u64::try_from(source).ok() != Some(entry.source_generation)
                    || u64::try_from(fence).ok() != Some(entry.revoke_fence)
                {
                    return Err("pending event provenance differs from durable state".to_owned());
                }
            }
            tx.commit().await.map_err(|error| error.to_string())?;
        }
        let frontier = sqlx::query_as::<_, CurrentFrontierRow>(LIST_CURRENT_FRONTIER_SQL)
            .fetch_all(pool)
            .await
            .map_err(|error| error.to_string())?;
        if frontier.len() > MAX_MIRROR_STATES {
            return Err("durable mirror scope capacity exceeded".to_owned());
        }
        let pending = sqlx::query_as::<_, PendingInvalidationRow>(LIST_PENDING_INVALIDATIONS_SQL)
            .fetch_all(pool)
            .await
            .map_err(|error| error.to_string())?;
        if pending.len() > MAX_PENDING_ENTRIES {
            return Err("durable pending capacity exceeded".to_owned());
        }
        let mut states = Vec::new();
        for row in &frontier {
            let identity = row.identity()?;
            let current = self
                .maps
                .read()
                .map_err(|_| "memory projection hub lock poisoned")?
                .states
                .get(&identity)
                .filter(|state| row.matches(state))
                .cloned();
            if current.is_none() {
                states.push(read_state_short_tx(pool, &identity).await?);
            }
        }
        let verify_frontier = sqlx::query_as::<_, CurrentFrontierRow>(LIST_CURRENT_FRONTIER_SQL)
            .fetch_all(pool)
            .await
            .map_err(|error| error.to_string())?;
        let verify_pending =
            sqlx::query_as::<_, PendingInvalidationRow>(LIST_PENDING_INVALIDATIONS_SQL)
                .fetch_all(pool)
                .await
                .map_err(|error| error.to_string())?;
        if frontier != verify_frontier || pending != verify_pending {
            return Err("durable frontier changed during reconciliation".to_owned());
        }
        Ok((frontier, pending, states))
    }

    /// 内存读面入口：pending 拦截面复刻 `FRESHNESS_GATE_PROBE`；命中即回退。
    pub fn try_memory_evidence(&self, scope: &PublishedCardEvidenceScope) -> MemoryEvidenceOutcome {
        self.try_memory_evidence_with_clock(
            scope,
            || OffsetDateTime::now_utc().unix_timestamp(),
            || {},
        )
    }

    fn try_memory_evidence_with_clock(
        &self,
        scope: &PublishedCardEvidenceScope,
        read_clock: impl FnOnce() -> i64,
        before_recheck: impl FnOnce(),
    ) -> MemoryEvidenceOutcome {
        if scope.validate().is_err() {
            return MemoryEvidenceOutcome::DeferToDurable;
        }
        let (token, states) = {
            let Ok(maps) = self.maps.read() else {
                return MemoryEvidenceOutcome::DeferToDurable;
            };
            if maps.warming_up
                || maps.authority_fence_unavailable()
                || maps.active_source_writers != 0
                || maps.uncertain_source
                || channel_blocks(&maps.channel, Instant::now())
            {
                return MemoryEvidenceOutcome::DeferToDurable;
            }
            let Some(identities) = maps.card_index.get(&(scope.tenant_id, scope.card_id)) else {
                return MemoryEvidenceOutcome::DeferToDurable;
            };
            if identities.is_empty()
                || maps
                    .pending
                    .get(&scope.tenant_id)
                    .is_some_and(|pending| pending.blocks(scope.card_id, &maps.states))
            {
                return MemoryEvidenceOutcome::DeferToDurable;
            }
            let now = Instant::now();
            if identities.iter().any(|identity| {
                maps.installed_at
                    .get(identity)
                    .is_none_or(|at| now.saturating_duration_since(*at) > MIRROR_TTL)
            }) {
                return MemoryEvidenceOutcome::DeferToDurable;
            }
            let states: Vec<_> = identities
                .iter()
                .filter_map(|identity| maps.states.get(identity).cloned())
                .collect();
            if states.len() != identities.len() {
                return MemoryEvidenceOutcome::DeferToDurable;
            }
            (ReadToken::for_scope(&maps, scope), states)
        };
        let now_unix_seconds = read_clock();
        let stamp = AssemblyStamp::new(token, now_unix_seconds, &states);
        let cached = self.assemblies.get(scope, &stamp, Instant::now());
        let cache_hit = cached.is_some();
        let evidence = match cached {
            Some(evidence) => (*evidence).clone(),
            None => match assemble_published_card_evidence(scope, now_unix_seconds, &states) {
                Ok(evidence) => evidence,
                Err(_) => return MemoryEvidenceOutcome::DeferToDurable,
            },
        };
        let refill = if !cache_hit && AssemblyCache::can_store(&stamp, &evidence) {
            Some(Arc::new(evidence.clone()))
        } else {
            None
        };
        before_recheck();
        let Ok(maps) = self.maps.read() else {
            return MemoryEvidenceOutcome::DeferToDurable;
        };
        if token != ReadToken::for_scope(&maps, scope)
            || maps.warming_up
            || maps.authority_fence_unavailable()
            || maps.active_source_writers != 0
            || maps.uncertain_source
            || channel_blocks(&maps.channel, Instant::now())
        {
            return MemoryEvidenceOutcome::DeferToDurable;
        }
        drop(maps);
        if let Some(refill) = refill {
            self.assemblies.insert(scope, stamp, refill, Instant::now());
        }
        MemoryEvidenceOutcome::Serve(evidence)
    }
}

/// 发布提交后的镜像刷新：短事务重读当前 durable 发布状态并安装。
///
/// 任何失败只记 warning——对应 pending 不清除，读者持续回退权威 DB 路径。
/// 未安装中心时为 no-op。
pub async fn refresh_from_durable(pool: &MySqlPool, identity: &ProjectionAggregateIdentity) {
    let Some(hub) = memory_projection_hub() else {
        return;
    };
    match read_state_short_tx(pool, identity).await {
        Ok(state) => hub.install_published_state(state),
        Err(error) => tracing::warn!(
            aggregate_type = %identity.aggregate_type,
            aggregate_id = identity.aggregate_id,
            error = %error,
            "memory projection mirror refresh failed; readers keep deferring to the durable path"
        ),
    }
}

/// 内存镜像装饰器：命中 [`MemoryEvidenceOutcome::Serve`] 直接返回与 durable
/// 同源的已验证证据；否则整体回退 `inner`（既有 `CachedPublishedEvidence`
/// /`SqlxRuleRepository` 链）。其余端口全部逐方法转发，语义零改动。
///
/// 辅助授权端口（`load_org_authorization` / `is_active_global_admin`）在
/// hub 健康且辅助镜像已安装（或测试注入）时先问镜像；镜像不适用一律回落
/// `inner`，与既有 DB 链逐字节同语义。default-off：未安装镜像时零行为变化。
pub struct MemoryMirroredRuleRepository<R> {
    inner: R,
    refill_pool: Option<MySqlPool>,
}

impl<R> MemoryMirroredRuleRepository<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            refill_pool: None,
        }
    }

    /// Enable commit-proven strict refills on memory misses.
    pub fn with_durable_refill(mut self, pool: MySqlPool) -> Self {
        self.refill_pool = Some(pool);
        self
    }

    async fn strict_authority_read<T>(
        &self,
        read: impl std::future::Future<Output = Result<T, astral_types::PolicyError>>,
    ) -> Result<T, astral_types::PolicyError> {
        let Some(hub) = memory_projection_hub() else {
            return read.await;
        };
        let token = hub.strict_read_token().ok_or_else(|| {
            astral_types::PolicyError::Repository(
                "source writer or unknown outcome blocks authority read".to_owned(),
            )
        })?;
        let result = tokio::time::timeout(Duration::from_secs(3), read)
            .await
            .map_err(|_| {
                astral_types::PolicyError::Repository("strict authority read timed out".to_owned())
            })?;
        if !hub.strict_read_matches(token) {
            return Err(astral_types::PolicyError::Repository(
                "source mutation raced authority read".to_owned(),
            ));
        }
        result
    }

    fn auxiliary_mirror(
        &self,
    ) -> Option<crate::auxiliary_authorization_mirror::AuxiliaryAuthorizationMirror> {
        crate::auxiliary_authorization_mirror()
    }
}

#[async_trait::async_trait]
impl<R> policy_engine::RuleRepository for MemoryMirroredRuleRepository<R>
where
    R: policy_engine::RuleRepository + Send + Sync,
{
    async fn load_rule_set_snapshots(
        &self,
        card_id: i64,
    ) -> Result<Vec<policy_engine::RuleSetSnapshot>, astral_types::PolicyError> {
        self.inner.load_rule_set_snapshots(card_id).await
    }

    async fn load_permission_rules(
        &self,
        card_id: i64,
    ) -> Result<Vec<policy_engine::PermissionRule>, astral_types::PolicyError> {
        self.inner.load_permission_rules(card_id).await
    }

    async fn load_rule_set_dependency_statuses(
        &self,
        card_id: i64,
    ) -> Result<Option<Vec<policy_engine::RuleSetDependencyStatus>>, astral_types::PolicyError>
    {
        self.inner.load_rule_set_dependency_statuses(card_id).await
    }

    async fn check_card_active(
        &self,
        ctx: &astral_types::PolicyContext,
    ) -> Result<bool, astral_types::PolicyError> {
        self.strict_authority_read(self.inner.check_card_active(ctx))
            .await
    }

    async fn is_active_global_admin(
        &self,
        user_id: i64,
    ) -> Result<bool, astral_types::PolicyError> {
        // 通道可证明时使用镜像；writer/未知与回填竞争均保持 fail-closed。
        if let (Some(hub), Some(mirror)) = (memory_projection_hub(), self.auxiliary_mirror()) {
            if let Some(result) = mirror.is_active_global_admin(hub, user_id).await {
                return result;
            }
        }
        self.strict_authority_read(self.inner.is_active_global_admin(user_id))
            .await
    }

    async fn load_snapshot_winners(
        &self,
        card_id: i64,
    ) -> Result<Vec<policy_engine::SnapshotWinner>, astral_types::PolicyError> {
        self.inner.load_snapshot_winners(card_id).await
    }

    async fn load_rule_set_entries_raw(
        &self,
        card_id: i64,
    ) -> Result<Vec<policy_engine::RuleSetSnapshot>, astral_types::PolicyError> {
        self.inner.load_rule_set_entries_raw(card_id).await
    }

    async fn load_permission_rules_raw(
        &self,
        card_id: i64,
    ) -> Result<Vec<policy_engine::PermissionRule>, astral_types::PolicyError> {
        self.inner.load_permission_rules_raw(card_id).await
    }

    async fn load_delegated_rules(
        &self,
        delegate_id: i64,
        resource: &str,
        action: &str,
    ) -> Result<Vec<policy_engine::PermissionRule>, astral_types::PolicyError> {
        self.inner
            .load_delegated_rules(delegate_id, resource, action)
            .await
    }

    async fn load_projected_delegated_rules(
        &self,
        delegate_id: i64,
        resource: &str,
        action: &str,
    ) -> Result<Vec<policy_engine::PermissionRule>, astral_types::PolicyError> {
        self.inner
            .load_projected_delegated_rules(delegate_id, resource, action)
            .await
    }

    async fn get_projection_gate(
        &self,
        card_id: i64,
    ) -> Result<Option<policy_engine::ProjectionGate>, astral_types::PolicyError> {
        self.inner.get_projection_gate(card_id).await
    }

    fn requires_published_card_evidence(&self) -> bool {
        self.inner.requires_published_card_evidence()
    }

    async fn load_published_card_authorization(
        &self,
        scope: &astral_types::PublishedCardEvidenceScope,
    ) -> Result<Option<PublishedCardAuthorization>, astral_types::PolicyError> {
        if let Some(hub) = memory_projection_hub() {
            if let MemoryEvidenceOutcome::Serve(evidence) = hub.try_memory_evidence(scope) {
                return Ok(Some(evidence));
            }
            if let Some(pool) = &self.refill_pool {
                return hub.strict_refill(pool, scope).await.map(Some);
            }
        }
        self.strict_authority_read(self.inner.load_published_card_authorization(scope))
            .await
    }

    async fn load_org_authorization(
        &self,
        ctx: &astral_types::PolicyContext,
    ) -> Result<policy_engine::org_admission::OrgAuthorityRead, astral_types::PolicyError> {
        // 严格回源同样需要前后源状态 token；不能绕过活动 writer 或未知提交。
        if let (Some(hub), Some(mirror)) = (memory_projection_hub(), self.auxiliary_mirror()) {
            if let Some(read) = mirror.load_org_authorization(hub, ctx).await {
                return Ok(read);
            }
        }
        self.strict_authority_read(self.inner.load_org_authorization(ctx))
            .await
    }
}

#[cfg(test)]
mod tests {
    mod assembly_cache;
    mod performance;

    use super::*;
    use astral_types::{
        BindingLayer, CanonicalGrant, DependencyVector, DependencyVersion, DomainScopeRequirement,
        GrantDelta, GrantEffect, GrantId, GrantProvenance, GrantRevision, GrantSourceKind,
        GrantState, PublishedCardEvidenceScope, TenantScope, ValidityWindow,
    };
    use sha2::{Digest, Sha256};

    use crate::authorization_projection_repository::{
        compute_manifest_digest, encode_segment_payload, stage_plan_new_segments_from_hot_state,
        AuthorizationCurrentPointerRecord, AuthorizationSegmentReferenceRecord,
        AuthorizationSegmentSnapshot, ManifestDigestInput,
    };

    fn sha256_hex(material: &[u8]) -> String {
        hex::encode(Sha256::digest(material))
    }

    fn tenant() -> TenantScope {
        TenantScope::new(7, Some(11)).unwrap()
    }

    fn grant(unique_tail: u16) -> CanonicalGrant {
        CanonicalGrant {
            grant_id: GrantId::parse(&format!(
                "550e8400-e29b-41d4-a716-44665544{unique_tail:04x}"
            ))
            .unwrap(),
            revision: GrantRevision::initial(),
            state: GrantState::Active,
            source_kind: GrantSourceKind::RuleSet,
            binding_layer: BindingLayer::Base,
            tenant: tenant(),
            card_id: 17,
            user_id: 42,
            resource: "learn_subject:1".to_owned(),
            action: "read".to_owned(),
            effect: GrantEffect::Allow,
            validity: ValidityWindow::perpetual(),
            provenance: GrantProvenance {
                source_id: "rule-set-entry-9".to_owned(),
                source_entry: None,
                binding_id: Some("binding-3".to_owned()),
                delegation_id: None,
                operation_id: "op-1".to_owned(),
                event_id: Some("event-1".to_owned()),
                actor_user_id: Some(42),
            },
        }
    }

    fn dependency_vector() -> DependencyVector {
        DependencyVector::new(vec![
            DependencyVersion::new("card", 1, 0).unwrap(),
            DependencyVersion::new("rule-set", 1, 0).unwrap(),
        ])
        .unwrap()
    }

    fn card_identity() -> ProjectionAggregateIdentity {
        ProjectionAggregateIdentity::new(7, "USER_CARD", 17).unwrap()
    }

    fn scope() -> PublishedCardEvidenceScope {
        PublishedCardEvidenceScope {
            tenant_id: 7,
            card_id: 17,
            user_filter: Some(42),
            domain: DomainScopeRequirement::Unconstrained,
        }
    }

    /// 从编译后的 HotState 构造一份"已验证 durable 发布状态"镜像。segment
    /// 顺序、载荷编码、manifest 摘要全部复用 durable 发布管线的同一批纯函数。
    fn seal_state(
        identity: &ProjectionAggregateIdentity,
        card_id: i64,
        generation: u64,
        hot: policy_engine::HotState,
        parent_manifest_id: Option<i64>,
        revoke_fence: u64,
    ) -> AuthorizationPublishedState {
        let card_id = Some(card_id);
        let source_generation = generation.max(revoke_fence);
        let plan = stage_plan_new_segments_from_hot_state(&hot).unwrap();
        let semantic_hash_hex = sha256_hex(format!("semantic:{generation}").as_bytes());
        let dependency_hash_hex = sha256_hex(format!("dependency:{generation}").as_bytes());
        let compiler_version = policy_engine::COMPILER_VERSION.to_owned();
        let event_id = format!("event-{generation}");
        let operation_id = format!("operation-{generation}");
        let mut segments = Vec::new();
        let mut references = Vec::new();
        let mut total_grant_count = 0u64;
        for (ordinal, entry) in plan.iter().enumerate() {
            let crate::authorization_projection_repository::StagedSegmentContent::New(grants) =
                entry
            else {
                panic!("fresh fabrication yields no parent reuse");
            };
            let payload = encode_segment_payload(grants).unwrap();
            let content_digest = crate::grant_repository::Sha256Digest::from_raw_bytes(
                Sha256::digest(&payload).into(),
            );
            total_grant_count += grants.len() as u64;
            segments.push(AuthorizationSegmentSnapshot {
                segment_id: (generation as i64) * 100 + ordinal as i64,
                identity: identity.clone(),
                card_id,
                content_digest,
                semantic_hash: crate::grant_repository::Sha256Digest::from_hex(&semantic_hash_hex)
                    .unwrap(),
                dependency_hash: crate::grant_repository::Sha256Digest::from_hex(
                    &dependency_hash_hex,
                )
                .unwrap(),
                compiler_version: compiler_version.clone(),
                format: "canonical-json-v1".to_owned(),
                row_count: grants.len() as u64,
                byte_size: payload.len() as u64,
                grants: grants.clone(),
            });
            references.push(AuthorizationSegmentReferenceRecord {
                reference_id: (generation as i64) * 100 + ordinal as i64,
                manifest_id: generation as i64,
                identity: identity.clone(),
                card_id,
                generation,
                ordinal: ordinal as u64,
                segment_id: (generation as i64) * 100 + ordinal as i64,
                content_digest,
                event_id: event_id.clone(),
                operation_id: operation_id.clone(),
            });
        }
        let manifest_digest = compute_manifest_digest(&ManifestDigestInput {
            tenant_id: identity.tenant_id,
            aggregate_type: &identity.aggregate_type,
            aggregate_id: identity.aggregate_id,
            card_id,
            generation,
            source_generation,
            projected_generation: source_generation,
            event_id: &event_id,
            operation_id: &operation_id,
            semantic_hash_hex: &semantic_hash_hex,
            dependency_hash_hex: &dependency_hash_hex,
            compiler_version: &compiler_version,
            parent_manifest_id,
            revoke_fence,
            segment_content_digests_hex: segments
                .iter()
                .map(|segment| segment.content_digest.as_hex())
                .collect(),
        })
        .unwrap();
        AuthorizationPublishedState {
            pointer: AuthorizationCurrentPointerRecord {
                pointer_id: generation as i64,
                identity: identity.clone(),
                card_id,
                current_generation: generation,
                manifest_id: generation as i64,
                event_id: event_id.clone(),
                operation_id: operation_id.clone(),
                semantic_hash: crate::grant_repository::Sha256Digest::from_hex(&semantic_hash_hex)
                    .unwrap(),
                dependency_hash: crate::grant_repository::Sha256Digest::from_hex(
                    &dependency_hash_hex,
                )
                .unwrap(),
                compiler_version: compiler_version.clone(),
                revoke_fence,
                revoke_fence_proven: true,
                cas_version: generation as i64,
            },
            manifest_id: generation as i64,
            generation,
            source_generation,
            projected_generation: source_generation,
            event_id,
            operation_id,
            semantic_hash: crate::grant_repository::Sha256Digest::from_hex(&semantic_hash_hex)
                .unwrap(),
            dependency_hash: crate::grant_repository::Sha256Digest::from_hex(&dependency_hash_hex)
                .unwrap(),
            compiler_version,
            manifest_digest,
            parent_manifest_id,
            revoke_fence,
            segments,
            references,
            total_grant_count,
        }
    }

    fn compile_incremental(
        base: &policy_engine::HotState,
        target: u64,
        deltas: Vec<GrantDelta>,
    ) -> policy_engine::HotState {
        match policy_engine::AuthorizationCompiler::new()
            .compile_incremental(base, target, dependency_vector(), deltas)
            .unwrap()
        {
            policy_engine::CompileOutcome::Applied(compiled) => compiled.state,
            other => panic!("expected applied compile, got {other:?}"),
        }
    }

    fn committed_outcome(state: AuthorizationPublishedState) -> DeltaProjectorPublishOutcome {
        DeltaProjectorPublishOutcome {
            impact_plan: crate::AuthorizationImpactPlanOutcome {
                plan_id: 1,
                resumed_existing_plan: false,
                item_count: 1,
            },
            stage: crate::AuthorizationStageOutcome {
                manifest_id: state.manifest_id,
                manifest_digest: state.manifest_digest,
                target_generation: state.generation,
                total_grant_count: state.total_grant_count,
                new_segment_count: state.segments.len() as u64,
                reused_segment_count: 0,
                resumed_existing_manifest: false,
                base_pointer: None,
            },
            archive_intent: None,
            publish: crate::AuthorizationPublishOutcome {
                pointer: state.pointer.clone(),
                published_manifest_id: state.manifest_id,
                previous_superseded_manifest_id: state.parent_manifest_id,
                initialized_first_pointer: state.parent_manifest_id.is_none(),
                published_state: Arc::new(state),
            },
        }
    }

    fn install_committed(hub: &MemoryProjectionHub, state: AuthorizationPublishedState) {
        hub.install_committed_publication(&committed_outcome(state))
            .unwrap();
    }

    fn serve(outcome: MemoryEvidenceOutcome) -> PublishedCardAuthorization {
        match outcome {
            MemoryEvidenceOutcome::Serve(evidence) => evidence,
            MemoryEvidenceOutcome::DeferToDurable => panic!("expected memory evidence"),
        }
    }

    fn defer(outcome: MemoryEvidenceOutcome) {
        assert!(matches!(outcome, MemoryEvidenceOutcome::DeferToDurable));
    }

    #[test]
    fn typed_evidence_notification_marks_only_its_card_pending_and_fails_closed_on_bad_provenance()
    {
        let hub = MemoryProjectionHub::default();
        let identity = card_identity();
        let hot = policy_engine::HotState::from_grants(
            tenant(),
            1,
            vec![grant(0x21)],
            dependency_vector(),
        )
        .unwrap();
        hub.install_published_state(seal_state(&identity, 17, 1, hot, None, 0));
        assert!(hub
            .apply_evidence_invalidation(EvidenceInvalidationRequest {
                tenant_id: 7,
                card_id: Some(17),
                aggregate_type: PublishedEvidenceAggregate::UserCard,
                aggregate_id: 17,
                event_id: "event-2".to_owned(),
                operation_id: "operation-2".to_owned(),
                source_generation: 2,
                published_generation: 1,
                revoke_fence: 0,
            })
            .is_ok());
        defer(hub.try_memory_evidence(&scope()));

        assert!(hub
            .apply_evidence_invalidation(EvidenceInvalidationRequest {
                tenant_id: 7,
                card_id: Some(17),
                aggregate_type: PublishedEvidenceAggregate::UserCard,
                aggregate_id: 17,
                event_id: String::new(),
                operation_id: "operation-3".to_owned(),
                source_generation: 3,
                published_generation: 1,
                revoke_fence: 0,
            })
            .is_err());
        assert!(hub
            .apply_evidence_invalidation(EvidenceInvalidationRequest {
                tenant_id: 7,
                card_id: Some(17),
                aggregate_type: PublishedEvidenceAggregate::UserCard,
                aggregate_id: 17,
                event_id: "event-4".to_owned(),
                operation_id: "operation-4".to_owned(),
                source_generation: 2,
                published_generation: 1,
                revoke_fence: 3,
            })
            .is_err());
    }

    #[test]
    fn typed_evidence_notification_is_tenant_scoped() {
        let hub = MemoryProjectionHub::default();
        assert!(hub
            .apply_evidence_invalidation(EvidenceInvalidationRequest {
                tenant_id: 7,
                card_id: None,
                aggregate_type: PublishedEvidenceAggregate::UserCard,
                aggregate_id: 17,
                event_id: "event-tenant".to_owned(),
                operation_id: "operation-tenant".to_owned(),
                source_generation: 2,
                published_generation: 1,
                revoke_fence: 0,
            })
            .is_ok());
        let maps = hub.maps.read().unwrap();
        assert!(maps.pending.contains_key(&7));
        assert!(!maps.pending.contains_key(&8));
    }
    #[test]
    fn first_publication_is_served_from_memory_with_provenance() {
        let hub = MemoryProjectionHub::default();
        defer(hub.try_memory_evidence(&scope()));
        let identity = card_identity();
        let hot = policy_engine::HotState::from_grants(
            tenant(),
            1,
            vec![grant(0x21)],
            dependency_vector(),
        )
        .unwrap();
        hub.install_published_state(seal_state(&identity, 17, 1, hot, None, 0));
        let evidence = serve(hub.try_memory_evidence(&scope()));
        evidence.validate().unwrap();
        assert_eq!(
            evidence.gate.status,
            astral_types::PublishedEvidenceGateStatus::Ready
        );
        assert_eq!(evidence.gate.effective_grant_count, 1);
        assert_eq!(evidence.manifests.len(), 1);
        assert_eq!(evidence.manifests[0].generation, 1);
        assert_eq!(evidence.effective_grants[0].grant_id, grant(0x21).grant_id);
    }

    #[test]
    fn revoke_advance_removes_effective_grant_and_install_is_monotonic() {
        let hub = MemoryProjectionHub::default();
        let identity = card_identity();
        let hot = policy_engine::HotState::from_grants(
            tenant(),
            1,
            vec![grant(0x21)],
            dependency_vector(),
        )
        .unwrap();
        hub.install_published_state(seal_state(&identity, 17, 1, hot.clone(), None, 0));
        let removed = compile_incremental(
            &hot,
            2,
            vec![GrantDelta::Remove {
                grant_id: grant(0x21).grant_id,
                expected_revision: GrantRevision::initial(),
            }],
        );
        // 乱序安装（旧代后到）必须被拒绝，内存绝不回退。
        let newer = seal_state(&identity, 17, 2, removed, Some(1), 0);
        hub.install_published_state(newer);
        let stale = policy_engine::HotState::from_grants(
            tenant(),
            1,
            vec![grant(0x21)],
            dependency_vector(),
        )
        .unwrap();
        hub.install_published_state(seal_state(&identity, 17, 1, stale, None, 0));
        let evidence = serve(hub.try_memory_evidence(&scope()));
        assert_eq!(evidence.manifests[0].generation, 2);
        assert_eq!(evidence.gate.effective_grant_count, 0);
        assert_eq!(evidence.gate.aggregate_manifest_count, 1);
    }

    #[test]
    fn pending_revoke_delta_defers_reads_until_install_covers_it() {
        let hub = MemoryProjectionHub::default();
        let identity = card_identity();
        let hot = policy_engine::HotState::from_grants(
            tenant(),
            1,
            vec![grant(0x21)],
            dependency_vector(),
        )
        .unwrap();
        hub.install_published_state(seal_state(&identity, 17, 1, hot.clone(), None, 0));
        // source transaction 内（提交前）登记 REMOVE 类 pending：撤权窗口内
        // 旧镜像绝不放行，读者回退权威 DB 路径。
        hub.record_pending_delta(&pending_request(
            Some(17),
            DeltaEventType::Remove,
            2,
            0,
            true,
        ));
        defer(hub.try_memory_evidence(&scope()));
        let removed = compile_incremental(
            &hot,
            2,
            vec![GrantDelta::Remove {
                grant_id: grant(0x21).grant_id,
                expected_revision: GrantRevision::initial(),
            }],
        );
        install_committed(&hub, seal_state(&identity, 17, 2, removed, Some(1), 0));
        let evidence = serve(hub.try_memory_evidence(&scope()));
        assert_eq!(evidence.manifests[0].generation, 2);
        assert_eq!(evidence.gate.effective_grant_count, 0);
    }

    #[test]
    fn fence_raising_delta_defers_until_installed_fence_covers_it() {
        let hub = MemoryProjectionHub::default();
        let identity = card_identity();
        let hot = policy_engine::HotState::from_grants(
            tenant(),
            1,
            vec![grant(0x21)],
            dependency_vector(),
        )
        .unwrap();
        hub.install_published_state(seal_state(&identity, 17, 1, hot.clone(), None, 0));
        // 非 revoke-class 但抬 fence 的 delta：fence 超过已安装水位期间拦截。
        hub.record_pending_delta(&pending_request(
            Some(17),
            DeltaEventType::Update,
            2,
            5,
            false,
        ));
        defer(hub.try_memory_evidence(&scope()));
        let mut updated = grant(0x21);
        updated.revision = GrantRevision::initial().next().unwrap();
        let advanced = compile_incremental(
            &hot,
            2,
            vec![GrantDelta::Update {
                grant: updated,
                expected_revision: GrantRevision::initial(),
            }],
        );
        install_committed(&hub, seal_state(&identity, 17, 2, advanced, Some(1), 5));
        let evidence = serve(hub.try_memory_evidence(&scope()));
        assert_eq!(evidence.manifests[0].revoke_fence, 5);
    }

    #[test]
    fn aggregate_wide_pending_blocks_every_card_in_the_tenant() {
        let hub = MemoryProjectionHub::default();
        let identity = card_identity();
        let hot = policy_engine::HotState::from_grants(
            tenant(),
            1,
            vec![grant(0x21)],
            dependency_vector(),
        )
        .unwrap();
        hub.install_published_state(seal_state(&identity, 17, 1, hot, None, 0));
        hub.record_pending_delta(&pending_request(None, DeltaEventType::Revoke, 2, 0, true));
        defer(hub.try_memory_evidence(&scope()));
        defer(hub.try_memory_evidence(&PublishedCardEvidenceScope {
            tenant_id: 7,
            card_id: 99,
            user_filter: None,
            domain: DomainScopeRequirement::Unconstrained,
        }));
    }

    #[test]
    fn ordinary_state_load_cannot_complete_a_pending_revoke() {
        let hub = MemoryProjectionHub::default();
        let identity = card_identity();
        let hot = policy_engine::HotState::from_grants(
            tenant(),
            100,
            vec![grant(0x21)],
            dependency_vector(),
        )
        .unwrap();
        hub.record_pending_delta(&pending_request(
            Some(17),
            DeltaEventType::Remove,
            2,
            0,
            true,
        ));
        hub.install_published_state(seal_state(&identity, 17, 100, hot, Some(99), 0));
        defer(hub.try_memory_evidence(&scope()));
    }

    #[test]
    fn committed_publication_uses_event_and_source_identity_not_grant_version() {
        let hub = MemoryProjectionHub::default();
        let identity = card_identity();
        let mut request = pending_request(Some(17), DeltaEventType::Remove, 9_000, 0, true);
        request.source_generation = 2;
        request.event_id = "event-2".to_owned();
        request.operation_id = "operation-2".to_owned();
        hub.record_pending_delta(&request);
        let hot =
            policy_engine::HotState::from_grants(tenant(), 2, Vec::new(), dependency_vector())
                .unwrap();
        install_committed(&hub, seal_state(&identity, 17, 2, hot, Some(1), 0));
        assert_eq!(
            serve(hub.try_memory_evidence(&scope()))
                .gate
                .effective_grant_count,
            0
        );
    }

    #[test]
    fn same_source_generation_siblings_need_individual_completion_proof() {
        let hub = MemoryProjectionHub::default();
        let identity = card_identity();
        let first = pending_request(Some(17), DeltaEventType::Remove, 2, 0, true);
        let mut sibling = first.clone();
        sibling.event_id = "event-3".to_owned();
        sibling.operation_id = "operation-3".to_owned();
        sibling.grant_id = grant(0x22).grant_id;
        hub.record_pending_delta(&first);
        hub.record_pending_delta(&sibling);
        let first_hot = policy_engine::HotState::from_grants(
            tenant(),
            2,
            vec![grant(0x22)],
            dependency_vector(),
        )
        .unwrap();
        install_committed(&hub, seal_state(&identity, 17, 2, first_hot, Some(1), 0));
        defer(hub.try_memory_evidence(&scope()));
        let sibling_hot =
            policy_engine::HotState::from_grants(tenant(), 3, Vec::new(), dependency_vector())
                .unwrap();
        let mut state = seal_state(&identity, 17, 3, sibling_hot, Some(2), 0);
        state.source_generation = 2;
        state.projected_generation = 2;
        state.manifest_digest = compute_manifest_digest(&ManifestDigestInput {
            tenant_id: identity.tenant_id,
            aggregate_type: &identity.aggregate_type,
            aggregate_id: identity.aggregate_id,
            card_id: state.pointer.card_id,
            generation: state.generation,
            source_generation: state.source_generation,
            projected_generation: state.projected_generation,
            event_id: &state.event_id,
            operation_id: &state.operation_id,
            semantic_hash_hex: &state.semantic_hash.as_hex(),
            dependency_hash_hex: &state.dependency_hash.as_hex(),
            compiler_version: &state.compiler_version,
            parent_manifest_id: state.parent_manifest_id,
            revoke_fence: state.revoke_fence,
            segment_content_digests_hex: state
                .segments
                .iter()
                .map(|segment| segment.content_digest.as_hex())
                .collect(),
        })
        .unwrap();
        install_committed(&hub, state);
        assert_eq!(
            serve(hub.try_memory_evidence(&scope()))
                .gate
                .effective_grant_count,
            0
        );
    }

    #[test]
    fn mismatched_operation_source_or_aggregate_cannot_clear_pending() {
        for dimension in ["operation", "source", "aggregate", "tenant"] {
            let hub = MemoryProjectionHub::default();
            let identity = card_identity();
            let hot =
                policy_engine::HotState::from_grants(tenant(), 2, Vec::new(), dependency_vector())
                    .unwrap();
            let state = seal_state(&identity, 17, 2, hot, Some(1), 0);
            let mut request = pending_request(Some(17), DeltaEventType::Remove, 2, 0, true);
            match dimension {
                "operation" => request.operation_id.push_str("-other"),
                "source" => request.source_generation = 100,
                "aggregate" => request.aggregate_id = 18,
                "tenant" => request.tenant_id = 8,
                _ => unreachable!(),
            }
            hub.record_pending_delta(&request);
            install_committed(&hub, state);
            let maps = hub.maps.read().unwrap();
            assert!(maps
                .pending
                .get(&request.tenant_id)
                .unwrap()
                .per_card
                .contains_key(&17));
        }
    }

    #[test]
    fn late_committed_install_clears_only_its_event_without_regressing_state() {
        let hub = MemoryProjectionHub::default();
        let identity = card_identity();
        hub.record_pending_delta(&pending_request(
            Some(17),
            DeltaEventType::Remove,
            2,
            0,
            true,
        ));
        let hot =
            policy_engine::HotState::from_grants(tenant(), 3, Vec::new(), dependency_vector())
                .unwrap();
        hub.install_published_state(seal_state(&identity, 17, 3, hot, Some(2), 0));
        defer(hub.try_memory_evidence(&scope()));
        let older =
            policy_engine::HotState::from_grants(tenant(), 2, Vec::new(), dependency_vector())
                .unwrap();
        install_committed(&hub, seal_state(&identity, 17, 2, older, Some(1), 0));
        assert_eq!(
            serve(hub.try_memory_evidence(&scope())).manifests[0].generation,
            3
        );
    }

    #[test]
    fn divergent_outcome_preserves_pending_and_rejects_install() {
        let hub = MemoryProjectionHub::default();
        let identity = card_identity();
        hub.record_pending_delta(&pending_request(
            Some(17),
            DeltaEventType::Remove,
            2,
            0,
            true,
        ));
        let hot =
            policy_engine::HotState::from_grants(tenant(), 2, Vec::new(), dependency_vector())
                .unwrap();
        let mut outcome = committed_outcome(seal_state(&identity, 17, 2, hot, Some(1), 0));
        outcome.stage.manifest_id += 1;
        assert!(hub.install_committed_publication(&outcome).is_err());
        assert!(hub.maps.read().unwrap().states.is_empty());
        defer(hub.try_memory_evidence(&scope()));
    }

    fn pending_row(event_type: &str, invalidates: i64, fence: i64) -> PendingInvalidationRow {
        PendingInvalidationRow {
            tenant_id: 7,
            card_id: Some(17),
            aggregate_type: "USER_CARD".to_owned(),
            aggregate_id: 17,
            event_id: "event-2".to_owned(),
            operation_id: "operation-2".to_owned(),
            source_generation: 2,
            revoke_fence: fence,
            event_type: event_type.to_owned(),
            invalidates_published_evidence: invalidates,
        }
    }

    #[test]
    fn warmup_pending_scan_covers_unfinished_retries_leases_and_quarantine() {
        assert!(LIST_PENDING_INVALIDATIONS_SQL.contains("status <> 'SUCCEEDED'"));
        assert!(LIST_PENDING_INVALIDATIONS_SQL.contains("invalidates_published_evidence <> 0"));
        assert!(LIST_PENDING_INVALIDATIONS_SQL.contains("event_type IN ('REMOVE', 'REVOKE')"));
        assert!(LIST_PENDING_INVALIDATIONS_SQL.contains("revoke_fence <> 0"));
        // LIMIT 仅允许以 cap+1 探针形态出现（超限即 fail-closed 拒绝启动，
        // 见 warm_scan_capacity_verdict）；按时间/租约过滤与锁定读仍然禁止。
        for forbidden in ["next_attempt_at", "lease_expires_at", "FOR UPDATE"] {
            assert!(!LIST_PENDING_INVALIDATIONS_SQL.contains(forbidden));
        }
    }

    #[test]
    fn warm_and_reconcile_share_cap_plus_one_scan_limits() {
        // 启动 warm-up 与 reconcile 对账共用同一容量上界：LIMIT 字面量必须
        // 精确等于 cap+1，行数读满即超限 fail-closed；安全限制（TTL/GC/容量）
        // 是 fail-closed 读面的组成部分，不为零 IO 目标移除。
        assert!(MIRROR_TTL > Duration::ZERO);
        const { assert!(MAX_MIRROR_STATES > 0) };
        const { assert!(MAX_PENDING_ENTRIES > 0) };
        let frontier_limit = format!("LIMIT {}", MAX_MIRROR_STATES + 1);
        assert!(
            LIST_CURRENT_IDENTITIES_SQL.contains(&frontier_limit),
            "warm identity scan must probe cap+1: {LIST_CURRENT_IDENTITIES_SQL}"
        );
        assert!(
            LIST_CURRENT_FRONTIER_SQL.contains(&frontier_limit),
            "reconcile frontier scan must probe the same cap+1: {LIST_CURRENT_FRONTIER_SQL}"
        );
        assert!(
            LIST_PENDING_INVALIDATIONS_SQL.contains(&format!("LIMIT {}", MAX_PENDING_ENTRIES + 1)),
            "pending scan must probe its own cap+1: {LIST_PENDING_INVALIDATIONS_SQL}"
        );
    }

    #[test]
    fn warm_scan_capacity_is_fail_closed_at_cap_plus_one() {
        // cap 行完整、cap+1 行超限：超限必须是 Err 且文案与 reconcile 容量
        // 错误同族；两个维度分别独立判定。
        assert!(warm_scan_capacity_verdict(MAX_MIRROR_STATES, MAX_PENDING_ENTRIES).is_ok());
        assert!(warm_scan_capacity_verdict(0, 0).is_ok());
        let frontier_over = warm_scan_capacity_verdict(MAX_MIRROR_STATES + 1, 0).unwrap_err();
        assert!(
            frontier_over.contains("durable mirror scope capacity exceeded"),
            "{frontier_over}"
        );
        let pending_over =
            warm_scan_capacity_verdict(MAX_MIRROR_STATES, MAX_PENDING_ENTRIES + 1).unwrap_err();
        assert!(
            pending_over.contains("durable pending capacity exceeded"),
            "{pending_over}"
        );
    }

    #[test]
    fn warm_scan_capacity_gates_before_any_mirror_registration() {
        // 形状守卫：warm 主体必须先完成两类 cap+1 探针扫描与容量判定（超限
        // 即 suspect + Err），才允许登记 pending、注册卡索引或装载任何聚合
        // 状态——截断的部分 frontier 绝不进入镜像。
        let source = include_str!("memory_projection_hub.rs");
        let start = source
            .find("pub async fn warm_from_durable_with_hint")
            .expect("warm entry must exist");
        let end = source
            .find("/// Warm the mirror from durable state without a snapshot hint.")
            .expect("warm function must be followed by the hint-free wrapper");
        let body = &source[start..end];
        let anchor = |needle: &str, what: &str| -> usize {
            body.find(needle)
                .unwrap_or_else(|| panic!("{what} must exist inside warm_from_durable_with_hint"))
        };
        let pending_scan = anchor("LIST_PENDING_INVALIDATIONS_SQL", "pending scan");
        let frontier_scan = anchor("LIST_CURRENT_IDENTITIES_SQL", "frontier scan");
        let verdict = anchor(
            "warm_scan_capacity_verdict(rows.len(), pending.len())",
            "capacity verdict",
        );
        let fail_closed = anchor(
            "return Err(sqlx::Error::Protocol(reason))",
            "fail-closed return",
        );
        let suspect = anchor("hub.mark_channel_suspect(reason.clone())", "sticky suspect");
        let pending_register = anchor("hub.record_pending_entry", "pending registration");
        let card_register = anchor("hub.expect_published_aggregate", "card-index registration");
        let state_install = anchor("hub.install_published_state", "state install");
        assert!(
            pending_scan < frontier_scan
                && frontier_scan < verdict
                && verdict < suspect
                && suspect < fail_closed
                && fail_closed < pending_register
                && pending_register < card_register
                && card_register < state_install,
            "capacity verdict must gate every mirror registration and install"
        );
    }

    #[test]
    fn restored_revoke_blocks_old_current_pointer_after_warmup() {
        for (event_type, invalidates) in [("REMOVE", 0), ("REVOKE", 0), ("UPDATE", 1)] {
            let hub = MemoryProjectionHub::default();
            hub.begin_warmup().unwrap();
            let (tenant_id, card_id, entry) =
                pending_row(event_type, invalidates, 0).decode().unwrap();
            hub.record_pending_entry(tenant_id, card_id, entry).unwrap();
            let identity = card_identity();
            hub.expect_published_aggregate(&identity, Some(17)).unwrap();
            let hot = policy_engine::HotState::from_grants(
                tenant(),
                1,
                vec![grant(0x21)],
                dependency_vector(),
            )
            .unwrap();
            hub.install_published_state(seal_state(&identity, 17, 1, hot, None, 0));
            hub.finish_warmup().unwrap();
            defer(hub.try_memory_evidence(&scope()));
        }
    }

    #[test]
    fn restored_aggregate_wide_revoke_is_tenant_scoped() {
        let hub = MemoryProjectionHub::default();
        let mut row = pending_row("REVOKE", 1, 0);
        row.card_id = None;
        let (tenant_id, card_id, entry) = row.decode().unwrap();
        hub.record_pending_entry(tenant_id, card_id, entry).unwrap();
        let maps = hub.maps.read().unwrap();
        assert!(maps.pending.get(&7).unwrap().blocks(99, &maps.states));
        assert!(!maps.pending.contains_key(&8));
    }

    #[test]
    fn pending_restore_rejects_invalid_identity_source_and_fence() {
        let mut rows = Vec::new();
        let mut row = pending_row("REMOVE", 1, 0);
        row.source_generation = 0;
        rows.push(row);
        let mut row = pending_row("REMOVE", 1, 0);
        row.revoke_fence = -1;
        rows.push(row);
        let mut row = pending_row("REMOVE", 1, 3);
        row.source_generation = 2;
        rows.push(row);
        let mut row = pending_row("REMOVE", 1, 0);
        row.tenant_id = 0;
        rows.push(row);
        let mut row = pending_row("REMOVE", 1, 0);
        row.card_id = Some(0);
        rows.push(row);
        let mut row = pending_row("UNKNOWN", 1, 0);
        row.operation_id.clear();
        rows.push(row);
        rows.push(pending_row("UNKNOWN", 1, 0));
        for row in rows {
            assert!(row.decode().is_err());
        }
    }

    #[test]
    fn warmup_blocks_until_complete_and_never_serves_partial_card_aggregates() {
        let hub = MemoryProjectionHub::default();
        hub.begin_warmup().unwrap();
        let identity = card_identity();
        let sibling = ProjectionAggregateIdentity::new(7, "RULE_SET", 19).unwrap();
        hub.expect_published_aggregate(&identity, Some(17)).unwrap();
        hub.expect_published_aggregate(&sibling, Some(17)).unwrap();
        let hot = policy_engine::HotState::from_grants(
            tenant(),
            1,
            vec![grant(0x21)],
            dependency_vector(),
        )
        .unwrap();
        hub.install_published_state(seal_state(&identity, 17, 1, hot, None, 0));
        defer(hub.try_memory_evidence(&scope()));
        hub.finish_warmup().unwrap();
        defer(hub.try_memory_evidence(&scope()));
        hub.record_channel_heartbeat();
        assert!(hub.channel_is_suspect());
        defer(hub.try_memory_evidence(&scope()));
        hub.maps.write().unwrap().channel = ChannelHealth::Healthy {
            last_heartbeat: Instant::now(),
        };
        defer(hub.try_memory_evidence(&scope()));
        let hot = policy_engine::HotState::from_grants(
            tenant(),
            1,
            vec![grant(0x22)],
            dependency_vector(),
        )
        .unwrap();
        hub.install_published_state(seal_state(&sibling, 17, 1, hot, None, 0));
        assert_eq!(serve(hub.try_memory_evidence(&scope())).manifests.len(), 2);
    }

    #[test]
    fn warming_read_gate_stays_closed_after_failed_pending_decode() {
        let hub = MemoryProjectionHub::default();
        hub.begin_warmup().unwrap();
        let identity = card_identity();
        let hot = policy_engine::HotState::from_grants(
            tenant(),
            1,
            vec![grant(0x21)],
            dependency_vector(),
        )
        .unwrap();
        hub.install_published_state(seal_state(&identity, 17, 1, hot, None, 0));
        assert!(pending_row("UNKNOWN", 1, 0).decode().is_err());
        defer(hub.try_memory_evidence(&scope()));
    }

    #[test]
    fn concurrent_install_and_reads_never_expose_torn_evidence() {
        let hub = MemoryProjectionHub::default();
        let identity = card_identity();
        let hot = policy_engine::HotState::from_grants(
            tenant(),
            1,
            vec![grant(0x21)],
            dependency_vector(),
        )
        .unwrap();
        hub.install_published_state(seal_state(&identity, 17, 1, hot, None, 0));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut readers = Vec::new();
        for _ in 0..4 {
            let hub = hub.clone();
            let stop = stop.clone();
            readers.push(std::thread::spawn(move || {
                let mut observations = 0usize;
                while !stop.load(std::sync::atomic::Ordering::Acquire) {
                    match hub.try_memory_evidence(&scope()) {
                        MemoryEvidenceOutcome::Serve(evidence) => {
                            evidence.validate().unwrap();
                            let generation = evidence.manifests[0].generation;
                            assert!((1..=9).contains(&generation));
                            observations += 1;
                        }
                        MemoryEvidenceOutcome::DeferToDurable => {}
                    }
                }
                assert!(observations > 0, "reader must observe installed states");
            }));
        }
        for generation in 2..=9u64 {
            let next = policy_engine::HotState::from_grants(
                tenant(),
                generation,
                vec![grant(0x21)],
                dependency_vector(),
            )
            .unwrap();
            hub.install_published_state(seal_state(
                &identity,
                17,
                generation,
                next,
                Some(generation as i64 - 1),
                0,
            ));
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        stop.store(true, std::sync::atomic::Ordering::Release);
        for reader in readers {
            reader.join().unwrap();
        }
    }

    #[test]
    fn memory_served_evidence_matches_the_pure_db_assembly() {
        // 同一份镜像状态分别喂给内存读面与 DB 严格 reader 的纯装配函数，
        // 语义必须逐字段一致（同一实现、同一 clock）。
        let hub = MemoryProjectionHub::default();
        let identity = card_identity();
        let hot = policy_engine::HotState::from_grants(
            tenant(),
            1,
            vec![grant(0x21), grant(0x22)],
            dependency_vector(),
        )
        .unwrap();
        let state = seal_state(&identity, 17, 1, hot, None, 0);
        hub.install_published_state(state.clone());
        let now = 1_000_000i64;
        let memory = serve(hub.try_memory_evidence(&scope()));
        let direct = assemble_published_card_evidence(&scope(), now, &[state]).unwrap();
        assert_eq!(memory.records.len(), direct.records.len());
        assert_eq!(memory.effective_grants, direct.effective_grants);
        assert_eq!(memory.manifests, direct.manifests);
    }

    #[test]
    fn heartbeat_is_monotonic_and_suspect_survives_heartbeat_and_warmup() {
        let _test_guard = crate::eligibility::test_global_state_lock();
        let now = Instant::now();
        let limit = Duration::from_millis(CHANNEL_MAX_HEARTBEAT_SILENCE_MS);
        assert!(!heartbeat_silence_blocks(now, now + limit, limit));
        assert!(heartbeat_silence_blocks(
            now,
            now + limit + Duration::from_nanos(1),
            limit
        ));
        assert!(heartbeat_silence_blocks(now + limit, now, limit));
        let hub = MemoryProjectionHub::default();
        hub.record_channel_heartbeat();
        assert!(!hub.channel_is_suspect());
        hub.mark_channel_suspect("channel lost");
        hub.record_channel_heartbeat();
        assert!(hub.channel_is_suspect());
        hub.begin_warmup().unwrap();
        hub.finish_warmup().unwrap();
        assert!(hub.channel_is_suspect());
    }

    #[test]
    fn notification_watermark_never_proves_an_installed_state() {
        let hub = MemoryProjectionHub::default();
        let identity = card_identity();
        let hot =
            policy_engine::HotState::from_grants(tenant(), 1, vec![grant(1)], dependency_vector())
                .unwrap();
        hub.install_published_state(seal_state(&identity, 17, 1, hot, None, 0));
        assert_eq!(hub.applied_generation_watermark(&identity), None);
        let request = EvidenceInvalidationRequest {
            tenant_id: 7,
            card_id: Some(17),
            aggregate_type: PublishedEvidenceAggregate::UserCard,
            aggregate_id: 17,
            event_id: "event-2".into(),
            operation_id: "operation-2".into(),
            source_generation: 2,
            revoke_fence: 2,
            published_generation: 1,
        };
        hub.apply_evidence_invalidation(request.clone()).unwrap();
        hub.apply_evidence_invalidation(request).unwrap();
        assert_eq!(hub.applied_generation_watermark(&identity), Some(1));
        assert_eq!(hub.installed_generation(&identity), Some(1));
        assert_eq!(hub.maps.read().unwrap().pending_count, 1);
        defer(hub.try_memory_evidence(&scope()));
        let other_tenant = ProjectionAggregateIdentity::new(8, "USER_CARD", 17).unwrap();
        let other_aggregate = ProjectionAggregateIdentity::new(7, "RULE_SET", 17).unwrap();
        assert_eq!(hub.applied_generation_watermark(&other_tenant), None);
        assert_eq!(hub.applied_generation_watermark(&other_aggregate), None);
    }

    #[test]
    fn late_notification_uses_only_its_exact_committed_completion_receipt() {
        let hub = MemoryProjectionHub::default();
        let hot =
            policy_engine::HotState::from_grants(tenant(), 2, Vec::new(), dependency_vector())
                .unwrap();
        install_committed(&hub, seal_state(&card_identity(), 17, 2, hot, Some(1), 2));
        let mut request = EvidenceInvalidationRequest {
            tenant_id: 7,
            card_id: Some(17),
            aggregate_type: PublishedEvidenceAggregate::UserCard,
            aggregate_id: 17,
            event_id: "event-2".into(),
            operation_id: "operation-2".into(),
            source_generation: 2,
            revoke_fence: 2,
            published_generation: 1,
        };
        hub.apply_evidence_invalidation(request.clone()).unwrap();
        assert_eq!(hub.maps.read().unwrap().pending_count, 0);
        serve(hub.try_memory_evidence(&scope()));
        request.operation_id.push_str("-foreign");
        hub.apply_evidence_invalidation(request).unwrap();
        assert_eq!(hub.maps.read().unwrap().pending_count, 1);
        defer(hub.try_memory_evidence(&scope()));
    }

    #[test]
    fn aggregate_index_capacity_rejects_new_scopes_without_forgetting_existing_scopes() {
        let hub = MemoryProjectionHub::default();
        hub.expect_published_aggregate(&card_identity(), Some(17))
            .unwrap();
        let mut maps = hub.maps.write().unwrap();
        maps.card_index_entries = MAX_MIRROR_STATES;
        assert!(maps.index_aggregate(&card_identity(), 17).is_ok());
        assert!(maps
            .index_aggregate(
                &ProjectionAggregateIdentity::new(7, "USER_CARD", 18).unwrap(),
                18
            )
            .is_err());
        assert!(maps
            .card_index
            .get(&(7, 17))
            .unwrap()
            .contains(&card_identity()));
        assert!(!maps.card_index.contains_key(&(7, 18)));
        assert_eq!(maps.card_index_entries, MAX_MIRROR_STATES);
    }

    #[test]
    fn exhausted_authority_counters_refuse_reads_and_writers() {
        for counter in 0..5 {
            let hub = MemoryProjectionHub::default();
            hub.record_channel_heartbeat();
            {
                let mut maps = hub.maps.write().unwrap();
                match counter {
                    0 => maps.mutation_revision = u64::MAX,
                    1 => maps.source_revision = u64::MAX,
                    2 => maps.health_revision = u64::MAX,
                    3 => maps.auxiliary_org_epoch = u64::MAX,
                    _ => maps.auxiliary_global_admin_epoch = u64::MAX,
                }
            }
            assert_eq!(hub.auxiliary_read_gate(), AuxiliaryReadGate::Uncertain);
            assert!(hub.strict_read_token().is_none());
            assert!(hub.capture_authority_fence().is_none());
            assert!(hub.begin_source_transaction().is_none());
            assert!(hub.begin_org_source_transaction().is_none());
            defer(hub.try_memory_evidence(&scope()));
        }
    }

    #[test]
    fn failed_runtime_owner_cannot_recover_from_heartbeat_or_warmup() {
        let _test_guard = crate::eligibility::test_global_state_lock();
        let hub = MemoryProjectionHub::default();
        hub.record_channel_heartbeat();
        let fence = hub.capture_authority_fence().unwrap();
        hub.mark_runtime_owner_failed("required projection owner exited");
        hub.record_channel_heartbeat();
        hub.begin_warmup().unwrap();
        hub.finish_warmup().unwrap();
        hub.record_channel_heartbeat();
        assert!(!hub.authority_fence_matches(fence));
        assert!(!hub.channel_is_healthy());
        assert!(hub.strict_read_token().is_none());
        assert!(hub.begin_source_transaction().is_none());
        assert_eq!(hub.maps.read().unwrap().active_source_writers, 0);
        assert!(hub.maps.read().unwrap().runtime_owner_failed);
    }

    #[test]
    fn strict_refill_rejects_capacity_failure_and_same_generation_divergence() {
        for capacity_failure in [true, false] {
            let hub = MemoryProjectionHub::default();
            let hot = policy_engine::HotState::from_grants(
                tenant(),
                1,
                vec![grant(1)],
                dependency_vector(),
            )
            .unwrap();
            let state = seal_state(&card_identity(), 17, 1, hot, None, 0);
            if capacity_failure {
                hub.maps.write().unwrap().mirror_bytes = MAX_MIRROR_BYTES;
            } else {
                let other_hot = policy_engine::HotState::from_grants(
                    tenant(),
                    1,
                    Vec::new(),
                    dependency_vector(),
                )
                .unwrap();
                hub.install_published_state(seal_state(
                    &card_identity(),
                    17,
                    1,
                    other_hot,
                    None,
                    0,
                ));
            }
            let token = ReadToken::for_scope(&hub.maps.read().unwrap(), &scope());
            assert!(hub
                .install_strict_refill(token, &scope(), &[state])
                .is_err());
            assert!(hub.channel_is_suspect());
        }
    }

    #[test]
    fn strict_refill_completion_token_rejects_a_later_invalidation() {
        let hub = MemoryProjectionHub::default();
        let hot =
            policy_engine::HotState::from_grants(tenant(), 1, vec![grant(1)], dependency_vector())
                .unwrap();
        let state = seal_state(&card_identity(), 17, 1, hot, None, 0);
        let token = ReadToken::for_scope(&hub.maps.read().unwrap(), &scope());
        let completed = hub
            .install_strict_refill(token, &scope(), &[state])
            .unwrap();
        let mut maps = hub.maps.write().unwrap();
        assert!(maps.refill_token_matches(completed, &scope()));
        maps.bump_scope(scope().tenant_id, Some(scope().card_id));
        assert!(!maps.refill_token_matches(completed, &scope()));
    }

    #[test]
    fn cancelled_commit_keeps_authority_unknown_after_writer_release() {
        let _test_guard = crate::eligibility::test_global_state_lock();
        let hub = MemoryProjectionHub::default();
        hub.record_channel_heartbeat();
        let guard = hub.begin_source_transaction().unwrap();
        guard.mark_commit_started();
        drop(guard);
        hub.record_channel_heartbeat();
        assert_eq!(hub.auxiliary_read_gate(), AuxiliaryReadGate::Uncertain);
        assert!(hub.strict_read_token().is_none());
        assert!(hub.channel_is_suspect());
    }

    #[test]
    fn proven_commit_never_clears_another_writers_unknown_outcome() {
        let _test_guard = crate::eligibility::test_global_state_lock();
        let hub = MemoryProjectionHub::default();
        hub.record_channel_heartbeat();
        let first = hub.begin_source_transaction().unwrap();
        let second = hub.begin_source_transaction().unwrap();
        first.mark_commit_started();
        second.mark_commit_started();
        drop(first);
        second.mark_commit_proven();
        drop(second);
        assert_eq!(hub.auxiliary_read_gate(), AuxiliaryReadGate::Uncertain);
    }

    #[test]
    fn source_guard_token_rejects_completed_writers_and_active_writers() {
        let _test_guard = crate::eligibility::test_global_state_lock();
        let hub = MemoryProjectionHub::default();
        hub.record_channel_heartbeat();
        let initial = hub.strict_read_token().unwrap();
        let guard = hub.begin_source_transaction().unwrap();
        assert!(hub.strict_read_token().is_none());
        guard.mark_commit_started();
        guard.mark_commit_proven();
        drop(guard);
        assert!(!hub.strict_read_matches(initial));
        assert!(matches!(
            hub.auxiliary_read_gate(),
            AuxiliaryReadGate::Ready(_)
        ));
    }

    #[test]
    fn org_cancelled_commit_also_blocks_strict_fallback() {
        let _test_guard = crate::eligibility::test_global_state_lock();
        let hub = MemoryProjectionHub::default();
        hub.record_channel_heartbeat();
        let guard = hub.begin_org_source_transaction().unwrap();
        guard.mark_commit_started();
        drop(guard);
        assert_eq!(hub.auxiliary_read_gate(), AuxiliaryReadGate::Uncertain);
        assert!(hub.strict_read_token().is_none());
    }

    #[test]
    fn unknown_source_commit_stays_suspect_after_its_guard_drops() {
        let _test_guard = crate::eligibility::test_global_state_lock();
        let hub = MemoryProjectionHub::default();
        let guard = hub.begin_source_transaction().unwrap();
        assert_eq!(hub.maps.read().unwrap().active_source_writers, 1);
        guard.mark_uncertain();
        drop(guard);
        hub.record_channel_heartbeat();
        assert!(hub.channel_is_suspect());
        assert!(hub.maps.read().unwrap().uncertain_source);
        assert_eq!(hub.maps.read().unwrap().active_source_writers, 0);
    }

    #[test]
    fn scope_epochs_isolate_cards_and_tenants_and_fence_refill() {
        let mut maps = HubMaps::default();
        let request = scope();
        let initial = ReadToken::for_scope(&maps, &request);
        maps.bump_scope(8, Some(17));
        maps.bump_scope(7, Some(18));
        assert_eq!(initial, ReadToken::for_scope(&maps, &request));
        maps.bump_scope(7, None);
        assert_ne!(initial, ReadToken::for_scope(&maps, &request));
        let updated = ReadToken::for_scope(&maps, &request);
        maps.bump_scope(7, Some(17));
        assert_ne!(updated, ReadToken::for_scope(&maps, &request));
    }

    #[test]
    fn singleflight_key_includes_user_domain_and_releases_cancelled_waiters() {
        let coordinator = RefillCoordinator::default();
        let first = coordinator.lock_for(&scope()).unwrap();
        let second = coordinator.lock_for(&scope()).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        let mut other = scope();
        other.user_filter = Some(43);
        let other_user = coordinator.lock_for(&other).unwrap();
        assert!(!Arc::ptr_eq(&first, &other_user));
        other = scope();
        other.domain = DomainScopeRequirement::ExactlyNone;
        let other_domain = coordinator.lock_for(&other).unwrap();
        assert!(!Arc::ptr_eq(&first, &other_domain));
        drop(first);
        drop(second);
        drop(other_user);
        drop(other_domain);
        coordinator.lock_for(&scope()).unwrap();
        assert_eq!(coordinator.scopes.lock().unwrap().len(), 1);
    }

    #[test]
    fn expired_mirror_state_defers_without_expanding_authority() {
        let hub = MemoryProjectionHub::default();
        let hot =
            policy_engine::HotState::from_grants(tenant(), 1, vec![grant(1)], dependency_vector())
                .unwrap();
        hub.install_published_state(seal_state(&card_identity(), 17, 1, hot, None, 0));
        serve(hub.try_memory_evidence(&scope()));
        hub.maps.write().unwrap().installed_at.insert(
            card_identity(),
            Instant::now() - MIRROR_TTL - Duration::from_secs(1),
        );
        defer(hub.try_memory_evidence(&scope()));
        hub.maps.write().unwrap().evict_expired(Instant::now());
        assert_eq!(hub.installed_generation(&card_identity()), None);
    }

    #[test]
    fn global_install_is_first_wins() {
        let first = install_memory_projection_hub();
        let second = install_memory_projection_hub();
        assert!(first || second);
        assert!(memory_mirror_is_installed());
    }

    #[test]
    fn writer_lease_is_a_zero_timeout_session_advisory_lock() {
        // 会话级锁随连接存活：进程崩溃即释放，绝不永久阻塞后续启动；
        // 零超时保证第二个实例启动期立即失败而不是挂起。
        assert!(
            SINGLE_NODE_WRITER_LEASE_SQL.starts_with("SELECT GET_LOCK('astral_single_node_writer'"),
            "{SINGLE_NODE_WRITER_LEASE_SQL}"
        );
        assert!(
            SINGLE_NODE_WRITER_LEASE_SQL.ends_with(", 0)"),
            "{SINGLE_NODE_WRITER_LEASE_SQL}"
        );
        assert!(!SINGLE_NODE_WRITER_LEASE_SQL
            .to_uppercase()
            .contains("DELETE"));
    }

    #[test]
    fn warm_identity_listing_covers_all_current_pointers_without_locks() {
        // 全量覆盖（无 WHERE 过滤）、确定性排序、只读（无 FOR UPDATE）——
        // 预热不得锁住发布链，也不得遗漏任何已发布聚合。
        assert!(LIST_CURRENT_IDENTITIES_SQL.contains("FROM authorization_projection_current"));
        assert!(!LIST_CURRENT_IDENTITIES_SQL
            .to_uppercase()
            .contains(" WHERE "));
        assert!(LIST_CURRENT_IDENTITIES_SQL
            .contains("ORDER BY tenant_id ASC, aggregate_type ASC, aggregate_id ASC"));
        assert!(!LIST_CURRENT_IDENTITIES_SQL
            .to_uppercase()
            .contains("FOR UPDATE"));
        assert!(!LIST_CURRENT_IDENTITIES_SQL
            .to_uppercase()
            .contains("DELETE"));
    }

    #[test]
    fn warm_and_refresh_reuse_the_strict_published_state_reader() {
        // 预热与刷新只允许经严格 reader（指针/manifest/segment 全链校验）
        // 装载镜像；出现旁路装载入口即契约违规。
        let source = include_str!("memory_projection_hub.rs");
        assert!(source.contains("read_published_authorization_state_in_tx"));
        // 用 concat! 拼接禁用符号，避免 include_str 扫描命中测试自身的字面量。
        let shortcut = concat!("load_published_card_grant_", "evidence");
        assert!(
            !source.contains(shortcut),
            "mirror loaders must consume the aggregate state reader, not the card evidence shortcut"
        );
    }

    fn pending_request(
        card_id: Option<i64>,
        event_type: crate::grant_repository::DeltaEventType,
        target_version: i64,
        revoke_fence: u64,
        invalidates: bool,
    ) -> crate::grant_repository::DeltaEventAppendRequest {
        crate::grant_repository::DeltaEventAppendRequest {
            tenant_id: 7,
            card_id,
            aggregate_type: "USER_CARD".to_owned(),
            aggregate_id: 17,
            grant_id: GrantId::parse("550e8400-e29b-41d4-a716-446655440099").unwrap(),
            event_id: format!("event-{target_version}"),
            operation_id: format!("operation-{target_version}"),
            event_type,
            base_version: target_version - 1,
            target_version,
            source_generation: (target_version as u64).max(revoke_fence),
            revoke_fence,
            invalidates_published_evidence: invalidates,
            before_image_json: None,
            before_digest_hex: None,
            delta_json: "{}".to_owned(),
            semantic_hash_hex: sha256_hex(b"semantic"),
            dependency_hash_hex: sha256_hex(b"dependency"),
            compiler_version: policy_engine::COMPILER_VERSION.to_owned(),
            next_attempt_at: None,
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // 性能基准（std::time 计时，无外部依赖）：多卡/多聚合预热镜像下的
    // 证据读取吞吐与尾延迟。断言只设宽松回归下限（防 CI 抖动），实测数字
    // 以 println 输出并记入变更报告。
    // ─────────────────────────────────────────────────────────────────────

    fn benchmark_grant(card_id: i64, unique_tail: u32) -> CanonicalGrant {
        let mut grant = grant(0);
        grant.grant_id =
            GrantId::parse(&format!("550e8400-e29b-41d4-a716-{unique_tail:012x}")).unwrap();
        grant.card_id = card_id;
        grant
    }

    fn percentile(sorted_nanos: &[u128], fraction: f64) -> u128 {
        let index = ((sorted_nanos.len() as f64 - 1.0) * fraction).round() as usize;
        sorted_nanos[index.min(sorted_nanos.len() - 1)]
    }

    /// 构建预热镜像：`cards` 张卡 × 每卡 2 个聚合（USER_CARD + RULE_SET）×
    /// 每聚合 `grants_per_aggregate` 条 Allow 授权；一次卡读合成两个聚合的
    /// manifest + 全部 verified records（与生产 reader 相同的纯装配路径）。
    fn build_warm_mirror(
        cards: usize,
        grants_per_aggregate: usize,
    ) -> (MemoryProjectionHub, Vec<PublishedCardEvidenceScope>) {
        let hub = MemoryProjectionHub::default();
        let mut scopes = Vec::with_capacity(cards);
        for card_index in 0..cards {
            let card_id = card_index as i64 + 1;
            for (aggregate_slot, (aggregate_type, aggregate_id)) in
                [("USER_CARD", card_id), ("RULE_SET", 10_000 + card_id)]
                    .into_iter()
                    .enumerate()
            {
                let identity =
                    ProjectionAggregateIdentity::new(7, aggregate_type, aggregate_id).unwrap();
                // grant_id 必须跨聚合唯一：同一 grant 出现在两个聚合会触发
                // 装配器的 conflicting_grant_provenance Corrupt 防线（正确行为）。
                let tail_base = (card_index as u32) * 64 + (aggregate_slot as u32) * 32;
                let grants = (0..grants_per_aggregate)
                    .map(|offset| benchmark_grant(card_id, tail_base + (offset as u32) * 2))
                    .collect::<Vec<CanonicalGrant>>();
                let hot =
                    policy_engine::HotState::from_grants(tenant(), 1, grants, dependency_vector())
                        .unwrap();
                hub.install_published_state(seal_state(&identity, card_id, 1, hot, None, 0));
            }
            scopes.push(PublishedCardEvidenceScope {
                tenant_id: 7,
                card_id,
                user_filter: Some(42),
                domain: DomainScopeRequirement::Unconstrained,
            });
        }
        (hub, scopes)
    }

    #[test]
    fn memory_evidence_read_throughput_and_tail_latency_under_warm_multi_card_mirror() {
        const CARDS: usize = 512;
        const GRANTS_PER_AGGREGATE: usize = 4;
        const WARMUP_READS: usize = 2_000;
        const SEQUENTIAL_READS: usize = 20_000;
        const CONCURRENT_THREADS: usize = 4;
        const READS_PER_THREAD: usize = 5_000;
        // 每卡 2 聚合 × 4 授权 = 8 条有效授权。
        const EFFECTIVE_PER_CARD: usize = 2 * GRANTS_PER_AGGREGATE;

        let (hub, scopes) = build_warm_mirror(CARDS, GRANTS_PER_AGGREGATE);
        assert_eq!(scopes.len(), CARDS);

        // 预热 + 正确性抽查（每 100 次做一次完整合同校验）。
        for index in 0..WARMUP_READS {
            let scope = &scopes[index % scopes.len()];
            match hub.try_memory_evidence(scope) {
                MemoryEvidenceOutcome::Serve(evidence) => {
                    assert_eq!(evidence.gate.effective_grant_count, EFFECTIVE_PER_CARD);
                    if index % 100 == 0 {
                        evidence.validate().unwrap();
                    }
                }
                MemoryEvidenceOutcome::DeferToDurable => {
                    panic!("warm scope must be served from memory")
                }
            }
        }

        // 顺序读：吞吐 + 尾延迟。
        let mut sequential_nanos: Vec<u128> = Vec::with_capacity(SEQUENTIAL_READS);
        let sequential_started = std::time::Instant::now();
        for index in 0..SEQUENTIAL_READS {
            let scope = &scopes[index % scopes.len()];
            let read_started = std::time::Instant::now();
            let evidence = match hub.try_memory_evidence(scope) {
                MemoryEvidenceOutcome::Serve(evidence) => evidence,
                MemoryEvidenceOutcome::DeferToDurable => {
                    panic!("warm scope must be served from memory")
                }
            };
            assert_eq!(evidence.gate.effective_grant_count, EFFECTIVE_PER_CARD);
            sequential_nanos.push(read_started.elapsed().as_nanos());
        }
        let sequential_wall = sequential_started.elapsed();
        let sequential_throughput = SEQUENTIAL_READS as f64 / sequential_wall.as_secs_f64();
        sequential_nanos.sort_unstable();
        let seq_p50 = percentile(&sequential_nanos, 0.50);
        let seq_p99 = percentile(&sequential_nanos, 0.99);
        let seq_p999 = percentile(&sequential_nanos, 0.999);
        let seq_max = sequential_nanos[sequential_nanos.len() - 1];

        // 并发读（4 线程 × 5k，读锁共享）：聚合吞吐 + 全局尾延迟。
        let hub = Arc::new(hub);
        let scopes = Arc::new(scopes);
        let mut handles = Vec::with_capacity(CONCURRENT_THREADS);
        let concurrent_started = std::time::Instant::now();
        for _ in 0..CONCURRENT_THREADS {
            let hub = hub.clone();
            let scopes = scopes.clone();
            handles.push(std::thread::spawn(move || {
                let mut samples: Vec<u128> = Vec::with_capacity(READS_PER_THREAD);
                for index in 0..READS_PER_THREAD {
                    let scope = &scopes[index % scopes.len()];
                    let read_started = std::time::Instant::now();
                    match hub.try_memory_evidence(scope) {
                        MemoryEvidenceOutcome::Serve(evidence) => {
                            assert_eq!(evidence.gate.effective_grant_count, EFFECTIVE_PER_CARD);
                        }
                        MemoryEvidenceOutcome::DeferToDurable => {
                            panic!("warm scope must be served from memory")
                        }
                    }
                    samples.push(read_started.elapsed().as_nanos());
                }
                samples
            }));
        }
        let mut concurrent_nanos: Vec<u128> = Vec::new();
        for handle in handles {
            concurrent_nanos.extend(handle.join().unwrap());
        }
        let concurrent_wall = concurrent_started.elapsed();
        let concurrent_reads = CONCURRENT_THREADS * READS_PER_THREAD;
        let concurrent_throughput = concurrent_reads as f64 / concurrent_wall.as_secs_f64();
        concurrent_nanos.sort_unstable();
        let conc_p50 = percentile(&concurrent_nanos, 0.50);
        let conc_p99 = percentile(&concurrent_nanos, 0.99);
        let conc_p999 = percentile(&concurrent_nanos, 0.999);
        let conc_max = concurrent_nanos[concurrent_nanos.len() - 1];

        // 实测数字（写入变更报告；机器相关，仅本机相对比较有效）。
        println!("memory evidence read benchmark ({} cards x 2 aggregates x {GRANTS_PER_AGGREGATE} grants)", CARDS);
        println!(
            "sequential: {} reads, wall {:?}, throughput {:.0} reads/s, p50 {}ns, p99 {}ns, p99.9 {}ns, max {}ns",
            SEQUENTIAL_READS, sequential_wall, sequential_throughput, seq_p50, seq_p99, seq_p999, seq_max
        );
        println!(
            "concurrent({CONCURRENT_THREADS} threads): {} reads, wall {:?}, throughput {:.0} reads/s, p50 {}ns, p99 {}ns, p99.9 {}ns, max {}ns",
            concurrent_reads, concurrent_wall, concurrent_throughput, conc_p50, conc_p99, conc_p999, conc_max
        );

        // 回归下限（刻意宽松，只防数量级退化；不以具体机器数字为准）。
        assert!(
            sequential_throughput >= 20_000.0,
            "sequential throughput {sequential_throughput:.0} reads/s regressed below the sanity floor"
        );
        assert!(
            concurrent_throughput >= 50_000.0,
            "concurrent throughput {concurrent_throughput:.0} reads/s regressed below the sanity floor"
        );
        assert!(
            seq_p99 < 250_000,
            "sequential p99 {seq_p99}ns regressed above the sanity ceiling"
        );
        assert!(
            conc_p99 < 1_000_000,
            "concurrent p99 {conc_p99}ns regressed above the sanity ceiling"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // 极限探针（informational：只测量并输出数字，不断言具体机器值）。
    // 目标是找到内存读面的四个崩溃点：单读记录数扩展、卡数规模扩展、
    // pending 风暴扫描成本、安装风暴下的读尾延迟。
    // ─────────────────────────────────────────────────────────────────────

    /// 规模化镜像构建器：grant_id 全局唯一（u16 尾数上限 0xffff）。
    fn build_mirror_scaled(
        cards: usize,
        grants_per_aggregate: usize,
    ) -> (MemoryProjectionHub, Vec<PublishedCardEvidenceScope>) {
        let hub = MemoryProjectionHub::default();
        let mut scopes = Vec::with_capacity(cards);
        let mut tail: u32 = 0;
        for card_index in 0..cards {
            let card_id = card_index as i64 + 1;
            for (aggregate_type, aggregate_id) in
                [("USER_CARD", card_id), ("RULE_SET", 10_000 + card_id)]
            {
                let identity =
                    ProjectionAggregateIdentity::new(7, aggregate_type, aggregate_id).unwrap();
                let grants = (0..grants_per_aggregate)
                    .map(|_| {
                        let grant = benchmark_grant(card_id, tail);
                        tail += 1;
                        grant
                    })
                    .collect::<Vec<CanonicalGrant>>();
                let hot =
                    policy_engine::HotState::from_grants(tenant(), 1, grants, dependency_vector())
                        .unwrap();
                hub.install_published_state(seal_state(&identity, card_id, 1, hot, None, 0));
            }
            scopes.push(PublishedCardEvidenceScope {
                tenant_id: 7,
                card_id,
                user_filter: Some(42),
                domain: DomainScopeRequirement::Unconstrained,
            });
        }
        (hub, scopes)
    }

    fn timed_reads(
        hub: &MemoryProjectionHub,
        scopes: &[PublishedCardEvidenceScope],
        reads: usize,
        effective_per_card: usize,
    ) -> (f64, Vec<u128>) {
        let mut samples: Vec<u128> = Vec::with_capacity(reads);
        let started = std::time::Instant::now();
        for index in 0..reads {
            let scope = &scopes[index % scopes.len()];
            let read_started = std::time::Instant::now();
            match hub.try_memory_evidence(scope) {
                MemoryEvidenceOutcome::Serve(evidence) => {
                    assert_eq!(evidence.gate.effective_grant_count, effective_per_card);
                }
                MemoryEvidenceOutcome::DeferToDurable => {
                    panic!("warm scope must be served from memory")
                }
            }
            samples.push(read_started.elapsed().as_nanos());
        }
        let throughput = reads as f64 / started.elapsed().as_secs_f64();
        samples.sort_unstable();
        (throughput, samples)
    }

    #[test]
    fn limit_records_per_read_scaling() {
        // 单读记录数扩展：每读 records = 2×grants。排序 + 去重是 O(n log n)，
        // 找到尾延迟超过毫秒级的拐点。
        const CARDS: usize = 64;
        const WARMUP: usize = 500;
        const READS: usize = 5_000;
        println!("-- records-per-read scaling ({} cards) --", CARDS);
        for grants_per_aggregate in [4usize, 64, 256, 1024] {
            let (hub, scopes) = build_mirror_scaled(CARDS, grants_per_aggregate);
            let effective = 2 * grants_per_aggregate;
            for index in 0..WARMUP {
                let _ = hub.try_memory_evidence(&scopes[index % scopes.len()]);
            }
            let (throughput, samples) = timed_reads(&hub, &scopes, READS, effective);
            println!(
                "grants/aggregate={:5}: records/read={:5}, throughput {:9.0} reads/s, p50 {:8.1}us, p99 {:9.1}us, max {:9.1}us",
                grants_per_aggregate,
                effective,
                throughput,
                percentile(&samples, 0.50) as f64 / 1000.0,
                percentile(&samples, 0.99) as f64 / 1000.0,
                samples[samples.len() - 1] as f64 / 1000.0,
            );
        }
    }

    #[test]
    fn limit_card_count_scaling() {
        // 卡数规模扩展：验证卡索引是 O(1)——吞吐应近似与镜像总卡数无关。
        const GRANTS: usize = 4;
        const READS: usize = 10_000;
        println!("-- card-count scaling (2 aggregates, {GRANTS} grants each) --");
        for cards in [512usize, 4096, 16384] {
            let (hub, scopes) = build_mirror_scaled(cards, GRANTS);
            let (throughput, samples) = timed_reads(&hub, &scopes, READS, 2 * GRANTS);
            println!(
                "cards={:6}: throughput {:9.0} reads/s, p50 {:8.1}us, p99 {:9.1}us",
                cards,
                throughput,
                percentile(&samples, 0.50) as f64 / 1000.0,
                percentile(&samples, 0.99) as f64 / 1000.0,
            );
        }
    }

    #[test]
    fn limit_pending_storm_scan_cost() {
        // pending 风暴：K 个未发布撤权意图存在时，非 pending 卡的读仍需支付
        // pending 拦截面扫描成本（当前实现为 O(P) 全表扫描）。量化悬崖位置。
        const CARDS: usize = 512;
        const GRANTS: usize = 4;
        const READS: usize = 5_000;
        println!(
            "-- pending-storm scan cost ({}-card mirror, reads on clean cards) --",
            CARDS
        );
        for pending_entries in [0usize, 100, 1_000, 10_000, 30_000] {
            let (hub, scopes) = build_mirror_scaled(CARDS, GRANTS);
            for entry in 0..pending_entries {
                let card_id = 1_000_000i64 + entry as i64;
                hub.record_pending_delta(&pending_request(
                    Some(card_id),
                    DeltaEventType::Remove,
                    2,
                    0,
                    true,
                ));
            }
            let (throughput, samples) = timed_reads(&hub, &scopes, READS, 2 * GRANTS);
            println!(
                "pending={:6}: clean-card throughput {:9.0} reads/s, p50 {:8.1}us, p99 {:9.1}us",
                pending_entries,
                throughput,
                percentile(&samples, 0.50) as f64 / 1000.0,
                percentile(&samples, 0.99) as f64 / 1000.0,
            );
        }
    }

    #[test]
    fn limit_install_storm_reader_tail() {
        // 安装风暴：写者全速换代期间，读者的读尾延迟退化多少（热交换代价）。
        const CARDS: usize = 512;
        const GRANTS: usize = 4;
        const ROUNDS: usize = 20;
        let (hub, scopes) = build_mirror_scaled(CARDS, GRANTS);
        let (base_throughput, base_samples) = timed_reads(&hub, &scopes, 10_000, 2 * GRANTS);
        let hub = Arc::new(hub);
        let scopes = Arc::new(scopes);
        let mut readers = Vec::new();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let storm_started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        for _ in 0..4 {
            let hub = hub.clone();
            let scopes = scopes.clone();
            let stop = stop.clone();
            let storm_started = storm_started.clone();
            readers.push(std::thread::spawn(move || {
                let mut quiet: Vec<u128> = Vec::new();
                let mut storm: Vec<u128> = Vec::new();
                let mut index = 0usize;
                while !stop.load(std::sync::atomic::Ordering::Acquire) {
                    let scope = &scopes[index % scopes.len()];
                    let started = std::time::Instant::now();
                    match hub.try_memory_evidence(scope) {
                        MemoryEvidenceOutcome::Serve(_) => {}
                        MemoryEvidenceOutcome::DeferToDurable => {}
                    }
                    let sample = started.elapsed().as_nanos();
                    if storm_started.load(std::sync::atomic::Ordering::Acquire) {
                        storm.push(sample);
                    } else {
                        quiet.push(sample);
                    }
                    index += 1;
                }
                (quiet, storm)
            }));
        }
        storm_started.store(true, std::sync::atomic::Ordering::Release);
        let installs_started = std::time::Instant::now();
        let mut installs = 0usize;
        for generation in 2..=(ROUNDS as u64 + 1) {
            for card_index in 0..CARDS {
                let card_id = card_index as i64 + 1;
                let identity = ProjectionAggregateIdentity::new(7, "USER_CARD", card_id).unwrap();
                let hot = policy_engine::HotState::from_grants(
                    tenant(),
                    generation,
                    vec![benchmark_grant(card_id, (card_index * 8) as u32)],
                    dependency_vector(),
                )
                .unwrap();
                hub.install_published_state(seal_state(
                    &identity,
                    card_id,
                    generation,
                    hot,
                    Some(generation as i64 - 1),
                    0,
                ));
                installs += 1;
            }
        }
        let install_throughput = installs as f64 / installs_started.elapsed().as_secs_f64();
        stop.store(true, std::sync::atomic::Ordering::Release);
        let mut quiet_all: Vec<u128> = Vec::new();
        let mut storm_all: Vec<u128> = Vec::new();
        for reader in readers {
            let (quiet, storm) = reader.join().unwrap();
            quiet_all.extend(quiet);
            storm_all.extend(storm);
        }
        quiet_all.sort_unstable();
        storm_all.sort_unstable();
        println!(
            "-- install storm ({} cards, {} installs) --",
            CARDS, installs
        );
        println!("install throughput: {:.0} installs/s", install_throughput);
        println!(
            "reader quiet:  {} samples, throughput {:9.0} reads/s, p99 {:8.1}us",
            quiet_all.len(),
            base_throughput,
            percentile(&base_samples, 0.99) as f64 / 1000.0,
        );
        println!(
            "reader storm:  {} samples, p50 {:8.1}us, p99 {:8.1}us, p99.9 {:9.1}us, max {:9.1}us",
            storm_all.len(),
            percentile(&storm_all, 0.50) as f64 / 1000.0,
            percentile(&storm_all, 0.99) as f64 / 1000.0,
            percentile(&storm_all, 0.999) as f64 / 1000.0,
            storm_all[storm_all.len() - 1] as f64 / 1000.0,
        );
    }

    // ── 辅助授权镜像的 hub 侧合同（双纪元 + org 写者栅栏） ────────────────

    #[test]
    fn org_source_writer_guard_bumps_only_the_org_epoch() {
        let _test_guard = crate::eligibility::test_global_state_lock();
        let hub = MemoryProjectionHub::default();
        hub.record_channel_heartbeat();
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
    }

    #[test]
    fn generic_source_writer_guard_conservatively_bumps_both_auxiliary_epochs() {
        let _test_guard = crate::eligibility::test_global_state_lock();
        let hub = MemoryProjectionHub::default();
        hub.record_channel_heartbeat();
        let ga_before = hub.auxiliary_global_admin_epoch();
        let org_before = hub.auxiliary_org_epoch();
        let writer = hub
            .begin_source_transaction()
            .expect("generic writer guard");
        assert!(hub.has_active_source_writer());
        drop(writer);
        assert_eq!(hub.auxiliary_org_epoch(), org_before + 2);
        assert_eq!(hub.auxiliary_global_admin_epoch(), ga_before + 2);
    }

    #[test]
    fn org_guard_unknown_commit_is_sticky_and_survives_heartbeats() {
        let _test_guard = crate::eligibility::test_global_state_lock();
        let hub = MemoryProjectionHub::default();
        hub.record_channel_heartbeat();
        assert!(!hub.channel_is_suspect());
        let writer = hub
            .begin_org_source_transaction()
            .expect("org writer guard");
        writer.mark_uncertain();
        assert!(hub.channel_is_suspect());
        hub.record_channel_heartbeat();
        assert!(
            hub.channel_is_suspect(),
            "heartbeat must not clear sticky suspect"
        );
        drop(writer);
        assert!(hub.channel_is_suspect());
    }

    /// 辅助镜像端口的装饰器回落：hub 未安装（多节点/Rabbit 模式）时
    /// `MemoryMirroredRuleRepository` 必须把 org/GA 端口原样转发 inner，
    /// 与既有 DB 链逐字节同语义（default-off 合同的一半，另一半由
    /// auxiliary_authorization_mirror 的"镜像不适用返回 None"覆盖）。
    #[tokio::test]
    async fn auxiliary_ports_forward_to_inner_without_hub_or_mirror() {
        use policy_engine::RuleRepository;

        struct ForwardProbe {
            org_called: std::sync::Arc<std::sync::Mutex<bool>>,
            ga_called: std::sync::Arc<std::sync::Mutex<bool>>,
        }

        #[async_trait::async_trait]
        impl policy_engine::RuleRepository for ForwardProbe {
            async fn load_permission_rules(
                &self,
                _card_id: i64,
            ) -> Result<Vec<policy_engine::PermissionRule>, astral_types::PolicyError> {
                Ok(vec![])
            }

            async fn load_org_authorization(
                &self,
                _ctx: &astral_types::PolicyContext,
            ) -> Result<policy_engine::org_admission::OrgAuthorityRead, astral_types::PolicyError>
            {
                *self.org_called.lock().unwrap() = true;
                Ok(policy_engine::org_admission::OrgAuthorityRead::Unmanaged)
            }

            async fn is_active_global_admin(
                &self,
                _user_id: i64,
            ) -> Result<bool, astral_types::PolicyError> {
                *self.ga_called.lock().unwrap() = true;
                Ok(true)
            }
        }

        let org_called = std::sync::Arc::new(std::sync::Mutex::new(false));
        let ga_called = std::sync::Arc::new(std::sync::Mutex::new(false));
        let repo = MemoryMirroredRuleRepository::new(ForwardProbe {
            org_called: org_called.clone(),
            ga_called: ga_called.clone(),
        });
        let context = astral_types::PolicyContext::builder()
            .user_id(Some(11))
            .identity_card_id(Some(111))
            .card_id(Some(222))
            .tenant_id(Some(100))
            .action("read".to_owned())
            .build();
        assert!(matches!(
            repo.load_org_authorization(&context).await,
            Ok(policy_engine::org_admission::OrgAuthorityRead::Unmanaged)
        ));
        assert!(repo.is_active_global_admin(11).await.unwrap());
        assert!(*org_called.lock().unwrap());
        assert!(*ga_called.lock().unwrap());
    }
}
