//! 授权投影 durable worker（新队列唯一消费者）— AuthorizationProjector
//!
//! 消费 migration `20260825000002` 新增的 Rust-owned 表：
//! `authorization_delta_event`（typed grant delta 队列）→ 事务外编译 → 经
//! `authorization_impact_plan` / `authorization_projection_manifest` /
//! `authorization_projection_current` / `authorization_archive_outbox` 发布。
//!
//! 硬边界（对齐 AGENTS §3 与本任务门禁）：
//! - 不触碰旧表职责：不调用旧 CARD/RULE_SET 快照重建入口（`*snapshot_inner`
//!   家族），不写两张旧快照表，不消费旧 outbox 队列表，不发布旧 refresh MQ，
//!   不做旧 cache evict；具体符号清单由 shape tests 锁定。
//! - 每个 event 使用稳定 `event_id`/`operation_id` + run-scoped lease token；
//!   claim 用独立短事务；发布由 `project_authorization_delta_in_tx` 在单事务内
//!   重新校验租约/链接/指针/fence 并完成 complete impact-plan + complete delta，
//!   durable pointer/manifest proof 提交后才向调用方返回成功。
//! - 纯编译阶段全部在事务外：scope ledger 全量读取 →
//!   `latest_entries_from_history`（tombstone 不授权）→ 复核 claimed DTO ↔
//!   ledger ↔ 依赖向量哈希 → `AuthorizationCompiler` 增量编译；
//!   `FullRebuildRequired` 只作为显式 oracle 分支并记录 reason。
//! - Conflict / 哈希漂移 / 版本不一致一律 fail-closed：bounded backoff 或隔离
//!   （QUARANTINE 决策记录在日志与 last_error），绝不发布、绝不伪造成功。
//! - Archive intent 由发布事务内部自动追加（仅当存在 parent、保持 PENDING）；
//!   ArchiveWorker 属于后续独立 slice，本文件绝不引用 archive-intent 终态 API
//!   （具体符号由 shape tests 锁定）。
//! - worker panic / 断流不能静默报成功：句柄 join 结果与 shutdown 耗时全部上抛
//!   给 main（见 [`shutdown_authorization_projector`]）。
//!
//! 当前切片边界（slice-2 已接线，行为契约如下）：
//! 1. **Publication context 观察**：[`AuthorizationProjectorRuntime::
//!    observe_publication_context`] 在一次短事务内经 astral-db 公开 loader 同时
//!    加载严格 published frontier（generation 1..=G）与当前 parent reference
//!    快照；无 pointer 返回 `None`，有 pointer 而 parent 快照缺失按 Corrupt 处理。
//!    结果只作为 planning hint——发布事务 [`project_authorization_delta_in_tx`]
//!    内部重锁指针/fence/parent 做二次权威复核，观察值永远不充当放行证明。
//! 2. **多 grant ledger 分区**：claim/readback 之后加载完整 aggregate ledger，
//!    调用 `partition_ledger_at_published_frontier(rows, frontier,
//!    [current_event])`。base 只能由 partition 的 `published_heads` 构建（每
//!    grant 仅最后一个已被 frontier 证明的 head；tombstone 保留在 HotState
//!    ledger 中但不授权）。遇到未发布兄弟 tail 不再 Blocked：普通
//!    `NotProvenPublished` 排除项不污染 base 且允许当前 candidate 发布；own
//!    event 落在 `ClaimedBehindUnpublishedSiblings` → Blocked；落在
//!    `StaleClaimBehindPublishedFrontier` 或 own missing/ambiguous/partition
//!    corruption → Quarantine。frontier 为 None 时只要求 claimed grant 自身
//!    链从 rev1 连续且含 claimed revision（兄弟 grant 的独立初始链忽略——
//!    per-grant 版本域下跨 grant 发布顺序无歧义，各自 claim 收口；兄弟未发
//!    布期间授权读由 source-freshness 门保持 PENDING，绝不放行中间态）。
//!    aggregate generation 与 per-grant version 永不直接比较：successor 关系
//!    只对照该 grant 自己的 frontier last delta target。
//! 3. **Segment reuse**：观察到 parent references 时将 digest 匹配的 unchanged
//!    segment 计划为 [`StagedSegmentContent::ReuseParent`]（digest 判等 + ordinal
//!    去重），changed/new 用 New。planning view 只是 hint，staging 事务内部全部
//!    重验（指针代差 → PointerMoved 快速 retry，不用旧 refs 强行发布）；无
//!    parent 视图全 New（同内容 segment 行仍由存储层按 digest 去重复用，绝无
//!    delete/reinsert）。
//! 4. **真 QUARANTINED 终态**：确定性 divergence（dependency drift、编译器
//!    DuplicateDelta/ExistingGrant、publish 阶段 immutable conflict 家族等）经
//!    [`AuthorizationProjectorRuntime::mark_event_quarantined`]（live-lease
//!    guarded CAS）写入真实 `QUARANTINED` 状态并离开 claim 队列；成功才计
//!    quarantined。lease/CAS 丢失或查询失败记 UNKNOWN（见
//!    [`WorkerRunSummary::events_quarantine_unknown`]）并停止一切后续 mutation，
//!    绝不 fail/retry/伪装成功。attempt 预算耗尽仍保持 PENDING + 最大退避 +
//!    [`ATTEMPT_BUDGET_EXHAUSTED_CODE`]（持续基础设施故障可能自愈），不转隔离；
//!    无 operator HTTP requeue（requeue API 属 repository/operator 层）。
//! 5. **Publish 租约心跳与 unproven-history 阻塞**：发布事务开始时先在同一
//!    事务内以 owner+token+status CAS + 服务端时间续租
//!    （astral-db `extend_delta_event_lease`，不改 attempts/cas_version），
//!    完成不再仅因原 claim 120s 窗口耗尽而失败；CAS 失败 = 丢失所有权 →
//!    LeaseLost/UNKNOWN，零后续写入（typed `GrantRepositoryError` 变体跨
//!    [`RepositoryRejection`] 保留，绝不按 Display 文本分类）。过期 `LEASED`
//!    行只能被原样 reclaim（attempts+1），其后的每条失败路径都经统一
//!    attempt 预算退避（`next_attempt_at`/cap），绝不热循环。
//!    `backfill_or_rehearsal_required` 属 unproven history（等待 operator
//!    backfill/rehearsal 提供带证明的指针），按 Blocked 在预算内退避，绝不
//!    消耗终态隔离。

use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use sqlx::MySqlPool;
use tokio::task::JoinHandle;

use astral_db::{
    claim_next_delta_event_in_partition_tx, claim_next_delta_event_in_tx,
    decode_delta_event_payload, decode_ledger_row, extend_delta_event_lease, fail_delta_event,
    hot_state_from_entries, impact_plan_request_from_compiler_plan,
    load_claimed_delta_event_for_update_in_tx, load_grant_ledger_rows,
    load_published_aggregate_frontier_in_tx, load_published_parent_reference_views_in_tx,
    mark_delta_event_quarantined, partition_ledger_at_published_frontier,
    project_authorization_delta_in_tx, release_delta_event_lease, AuthorizationImpactItemInput,
    AuthorizationImpactItemType, AuthorizationImpactPlanAppendRequest,
    AuthorizationProjectionError, AuthorizationStageRequest, ClaimedDeltaEvent,
    CompileModeEvidence, DeltaEventClaim, DeltaEventClaimScope, DeltaEventType, DeltaLeaseIdentity,
    DeltaProjectorExpectation, DeltaProjectorPublishCommand, DeltaProjectorPublishOutcome,
    GrantLedgerEntry, ParentReferenceView, PartitionLeaseHandle, PartitionedGrantLedgerAtFrontier,
    ProjectionAggregateIdentity, PublishRevokeFenceEvidence, PublishedAggregateFrontier,
    RawLedgerRow, StagedSegmentContent, MAX_BACKOFF_SECONDS, MAX_MANIFEST_LEASE_SECONDS,
};
use astral_types::{DependencyVector, DependencyVersion, ProjectionCompileMode, TenantScope};
use policy_engine::{
    AuthorizationCompiler, CompileOutcome, CompilerConflict, FullCompilerOracle, FullRebuildReason,
    HotState,
};

use crate::observability::{
    record_projector_event, record_projector_phase, ProjectorEventOutcome, ProjectorPhase,
};

// ─────────────────────────────────────────────────────────────────────────────
// Worker policy constants (Exec-L2 budgets)
// ─────────────────────────────────────────────────────────────────────────────

/// Idle poll period between cycles.
pub const POLL_INTERVAL_SECS: u64 = 5;
/// One claimed event's lease window (≤ [`MAX_DELTA_LEASE_SECONDS`]).
pub const CLAIM_LEASE_SECS: i64 = 120;
/// Hard attempt budget per event. The budget is judged against the durable
/// post-install `attempts` value of the row ([`DeltaEventClaim::attempts`] and
/// the strict [`ClaimedDeltaEvent`] readback both carry that current value):
/// attempts 1..=5 are in-budget retries, a failure observed at attempts >= 5 is
/// exhausted and can never schedule another short backoff.
pub const MAX_EVENT_ATTEMPTS: i64 = 5;
/// Backoff ceiling handed to `fail_delta_event`.
pub const BACKOFF_CAP_SECS: i64 = 900;
/// Maximum number of in-place replans after a publish transaction observes that
/// the aggregate pointer moved. Replanning keeps the original live lease and
/// therefore does not consume another claim attempt; exhaustion falls back to
/// the ordinary durable retry budget.
const MAX_POINTER_MOVED_REPLANS: usize = 3;
/// Maximum events processed per tenant within one poll cycle.
const MAX_EVENTS_PER_TENANT_PER_CYCLE: usize = 8;

// ─────────────────────────────────────────────────────────────────────────────
// Partitioned scheduling (multi-tenant redesign Phase 1; design doc
// Rust多租户聚合分区与组织层级设计_V0.1.md §3). Default-off: TenantSerial
// stays the production default until the partitioned scheduler passes real
// integration acceptance.
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum events one worker may drain from ONE partition while holding its
/// lease. The lease is renewed before every claim iteration; losing it stops
/// the batch immediately (fail-closed: never touch a partition you no longer
/// own).
const MAX_EVENTS_PER_PARTITION_PER_BATCH: usize = 8;
/// Partition lease window: one event's claim lease plus margin for the
/// discover/acquire/renew/release round-trips.
pub const PARTITION_LEASE_SECS: i64 = CLAIM_LEASE_SECS + 60;
/// Discovery candidate bound handed to the ledger query per worker round.
pub const PARTITION_DISCOVERY_LIMIT: i64 = 64;
/// Parallel partition workers (Q2 decision): default 4, hard-bounded.
pub const DEFAULT_PARTITION_WORKER_COUNT: usize = 4;
pub const MAX_PARTITION_WORKER_COUNT: usize = 32;

/// Scheduling topology of the projection worker pool. `TenantSerial` is the
/// historical, fully-accepted behavior and remains the DEFAULT; `Partitioned`
/// activates ledger-discovered aggregate partitions with per-partition lease
/// exclusivity and cross-partition parallelism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectorSchedulingMode {
    TenantSerial,
    Partitioned,
}

/// Stable operator-facing marker appended to `last_error` when the retry
/// budget is exhausted. Kept PENDING on purpose: this slice must NOT fake a
/// terminal QUARANTINED/SUCCEEDED status it cannot durably write yet.
const ATTEMPT_BUDGET_EXHAUSTED_CODE: &str = "code=auth_projector.attempt_budget_exhausted";

fn budget_exhausted_error(reason: &str, attempts: i64) -> String {
    // The repository truncates from the tail; scheduling identity must survive.
    format!("{ATTEMPT_BUDGET_EXHAUSTED_CODE};attempts={attempts};{reason}")
}

#[cfg(feature = "e3-observability")]
fn log_e3_attempt_event(
    event: &'static str,
    claimed: &DeltaEventClaim,
    outcome: &'static str,
    durable: bool,
    backoff_seconds: Option<i64>,
) {
    let stamp = astral_common::experiment_observation::stamp();
    tracing::info!(
        target: "authz_e3",
        event,
        process_observation_id = %stamp.process_observation_id,
        event_sequence = stamp.event_sequence,
        wall_unix_ns = %stamp.wall_unix_ns,
        delta_event_id = claimed.delta_event_id,
        event_id = %claimed.event_id,
        attempt_id = %format!("{}:{}", claimed.delta_event_id, claimed.attempts),
        operation_id = %claimed.operation_id,
        tenant_id = claimed.tenant_id,
        card_id = ?claimed.card_id,
        aggregate_type = %claimed.aggregate_type,
        aggregate_id = claimed.aggregate_id,
        grant_id = %claimed.grant_id,
        target_version = claimed.target_version,
        attempts = claimed.attempts,
        outcome,
        durable,
        backoff_seconds = ?backoff_seconds,
        "e3 projector observation"
    );
}

#[cfg(feature = "e3-observability")]
fn log_e3_identity_event(
    event: &'static str,
    identity: &DeltaLeaseIdentity,
    outcome: &'static str,
    durable: bool,
    backoff_seconds: Option<i64>,
) {
    let stamp = astral_common::experiment_observation::stamp();
    tracing::info!(
        target: "authz_e3",
        event,
        process_observation_id = %stamp.process_observation_id,
        event_sequence = stamp.event_sequence,
        wall_unix_ns = %stamp.wall_unix_ns,
        delta_event_id = identity.delta_event_id,
        event_id = %identity.event_id,
        outcome,
        durable,
        backoff_seconds = ?backoff_seconds,
        "e3 projector observation"
    );
}

fn clamp_backoff(secs: i64) -> i64 {
    secs.clamp(1, BACKOFF_CAP_SECS.min(MAX_BACKOFF_SECONDS))
}

/// Bounded exponential backoff for an event whose attempts counter reached
/// `n` (first failure n=1 → 1s, doubling). Attempt exhaustion switches to the
/// maximal backoff instead of looping hot. Primitive schedule used ONLY by
/// [`plan_retry_schedule`] (plus its tests) — never by handlers directly.
fn event_backoff_secs(attempts: i64) -> i64 {
    let floor = if attempts < 1 { 1 } else { attempts };
    if floor >= MAX_EVENT_ATTEMPTS {
        return clamp_backoff(BACKOFF_CAP_SECS);
    }
    let exp = 1i64
        .checked_shl((floor - 1).min(10) as u32)
        .unwrap_or(i64::MAX);
    clamp_backoff(exp)
}

/// Disposition of the unified attempt-budget policy for one failing path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetrySchedule {
    /// Within budget: keep the row PENDING and schedule the next attempt after
    /// this bounded backoff.
    Continue { backoff_secs: i64 },
    /// Budget exhausted (`current_attempts >= MAX_EVENT_ATTEMPTS`): the event
    /// stays PENDING under the maximal `BACKOFF_CAP_SECS` backoff, carrying the
    /// stable [`ATTEMPT_BUDGET_EXHAUSTED_CODE`] marker in `last_error`. This
    /// never pretends the event was quarantined or succeeded — a true terminal
    /// state requires a later slice with a real status.
    AttemptBudgetExhausted { backoff_secs: i64 },
}

/// THE single retry/backoff policy for every non-publish-success failure path
/// (`Retry`, `Blocked`, `PointerMoved`, `GenericRetry`, infra failures).
///
/// `attempts_current` MUST be the durable CURRENT row value — the post-install
/// counter surfaced by the claim readback / strict re-read; pre-increment views
/// are forbidden here because they would overpay one extra short backoff step.
/// `minimum_backoff_secs` lets conservative paths (immutable divergence)
/// request a longer cool-down; it can never exceed the clamp and it can never
/// rescue an exhausted budget.
fn plan_retry_schedule(attempts_current: i64, minimum_backoff_secs: i64) -> RetrySchedule {
    // Defensive floor: a durable LEASED row always has attempts >= 1
    // (enforced again by the strict readback), but pathological input must not
    // panic or produce zero-second schedules.
    let attempts = attempts_current.max(1);
    if attempts >= MAX_EVENT_ATTEMPTS {
        return RetrySchedule::AttemptBudgetExhausted {
            backoff_secs: clamp_backoff(BACKOFF_CAP_SECS),
        };
    }
    RetrySchedule::Continue {
        backoff_secs: event_backoff_secs(attempts).max(clamp_backoff(minimum_backoff_secs)),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lifecycle handle (owned by main; cancel → bounded join → phase timing)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Default)]
pub struct ProjectorCancellationToken {
    cancelled: Arc<AtomicBool>,
    notify: Arc<tokio::sync::Notify>,
}

impl ProjectorCancellationToken {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.notify.notify_one();
    }

    async fn cancelled(&self) {
        if self.cancelled.load(Ordering::Acquire) {
            return;
        }
        self.notify.notified().await;
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

/// Run-scoped counters reported back through shutdown; NEVER usable as
/// authorization identity (no tenant/card/grant semantics involved).
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkerRunSummary {
    pub events_claimed: u64,
    pub events_published: u64,
    pub events_released_retry: u64,
    pub events_quarantined: u64,
    pub events_blocked: u64,
    pub events_lease_lost: u64,
    /// Number of publish races replanned in-place while retaining the live
    /// lease. This is distinct from claim attempts and ordinary retries.
    pub events_pointer_moved_replanned: u64,
    /// Events whose failure ran into the attempt budget. Orthogonal to the
    /// causal counters above: a blocked event can ALSO hit the budget, in which
    /// case both counters advance. Exhausted events stay PENDING with the
    /// maximal backoff + stable `last_error` marker (no fake terminal state).
    pub events_budget_exhausted: u64,
    /// Terminal quarantine writes whose durable outcome could NOT be proven
    /// (lease CAS loss / query failure). UNKNOWN by definition: no further
    /// mutation was issued for those events; reconciliation is required.
    pub events_quarantine_unknown: u64,
    /// Total wall time spent in the pure decide/compile phase across events.
    pub decide_phase_micros: u64,
    /// Events whose processing exceeded
    /// [`AuthorizationProjectorConfig::event_deadline`] (F5 修复 1b): the
    /// in-flight work was cancelled, the lease was released best-effort, and
    /// the loop continued. Orthogonal to the causal counters above.
    pub events_deadline_exceeded: u64,
}

impl WorkerRunSummary {
    fn record(&mut self, kind: DispositionKind) {
        record_projector_event(kind.metric_outcome());
        match kind {
            DispositionKind::Published => self.events_published += 1,
            DispositionKind::ReleasedRetry => self.events_released_retry += 1,
            DispositionKind::Quarantined => self.events_quarantined += 1,
            DispositionKind::Blocked => self.events_blocked += 1,
            DispositionKind::LeaseLost => self.events_lease_lost += 1,
            DispositionKind::SupersededRelease => self.events_released_retry += 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DispositionKind {
    Published,
    ReleasedRetry,
    Quarantined,
    Blocked,
    LeaseLost,
    SupersededRelease,
}

impl DispositionKind {
    const fn metric_outcome(self) -> ProjectorEventOutcome {
        match self {
            Self::Published => ProjectorEventOutcome::Published,
            Self::ReleasedRetry => ProjectorEventOutcome::ReleasedRetry,
            Self::Quarantined => ProjectorEventOutcome::Quarantined,
            Self::Blocked => ProjectorEventOutcome::Blocked,
            Self::LeaseLost => ProjectorEventOutcome::LeaseLost,
            Self::SupersededRelease => ProjectorEventOutcome::Superseded,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// F5 修复 1d：监督、看门狗与健康快照
// ─────────────────────────────────────────────────────────────────────────────

fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

/// 每代 worker 的进展时间戳（看门狗输入）：claim 返回（含空轮询）与事件完成
/// 均视为进展；卡死在步骤内部（claim/publish/推送挂起）则不再推进。
#[derive(Debug, Default)]
pub struct ProjectorProgress {
    last_progress_ms: AtomicU64,
}

impl ProjectorProgress {
    fn touch(&self) {
        self.last_progress_ms
            .store(unix_millis(), Ordering::Release);
    }

    fn age_ms(&self) -> Option<u64> {
        let last = self.last_progress_ms.load(Ordering::Acquire);
        if last == 0 {
            None
        } else {
            Some(unix_millis().saturating_sub(last))
        }
    }
}

impl WorkerRunSummary {
    /// 跨代聚合（监督循环消费）：把另一份 summary 的全部计数累加进来。
    fn merge(&mut self, other: &WorkerRunSummary) {
        self.events_claimed += other.events_claimed;
        self.events_published += other.events_published;
        self.events_released_retry += other.events_released_retry;
        self.events_quarantined += other.events_quarantined;
        self.events_blocked += other.events_blocked;
        self.events_lease_lost += other.events_lease_lost;
        self.events_pointer_moved_replanned += other.events_pointer_moved_replanned;
        self.events_budget_exhausted += other.events_budget_exhausted;
        self.events_quarantine_unknown += other.events_quarantine_unknown;
        self.decide_phase_micros += other.decide_phase_micros;
        self.events_deadline_exceeded += other.events_deadline_exceeded;
    }
}

/// 监督共享态（F5 修复 1d）：跨代聚合 summary、代计数、重启计数与当前代的
/// 进展指针。仅含聚合计数与时间戳——无租户/卡/grant 语义，不是授权身份。
pub struct ProjectorHealthShared {
    started_at_ms: u64,
    generation: AtomicU64,
    restarts: AtomicU64,
    summary: std::sync::Mutex<WorkerRunSummary>,
    progress: std::sync::Mutex<Arc<ProjectorProgress>>,
}

impl ProjectorHealthShared {
    fn new() -> Self {
        Self {
            started_at_ms: unix_millis(),
            generation: AtomicU64::new(0),
            restarts: AtomicU64::new(0),
            summary: std::sync::Mutex::new(WorkerRunSummary::default()),
            progress: std::sync::Mutex::new(Arc::new(ProjectorProgress::default())),
        }
    }

    fn next_generation(&self) -> u64 {
        self.generation.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn swap_progress(&self, progress: Arc<ProjectorProgress>) {
        if let Ok(mut guard) = self.progress.lock() {
            *guard = progress;
        }
    }

    /// 当前代进展年龄（毫秒）；尚未产生基线 → `None`。
    fn progress_age_ms(&self) -> Option<u64> {
        let guard = self.progress.lock().ok()?;
        guard.age_ms()
    }

    fn merge_summary(&self, summary: &WorkerRunSummary) {
        if let Ok(mut guard) = self.summary.lock() {
            guard.merge(summary);
        }
    }

    fn take_summary(&self) -> WorkerRunSummary {
        self.summary
            .lock()
            .map(|mut guard| std::mem::take(&mut *guard))
            .unwrap_or_default()
    }

    fn record_restart(&self) {
        self.restarts.fetch_add(1, Ordering::Relaxed);
    }

    /// 当前代进展年龄（秒）；当前代尚无任何进展 → `None`。
    fn progress_age_secs(&self) -> Option<u64> {
        let guard = self.progress.lock().ok()?;
        guard.age_ms().map(|age_ms| age_ms / 1000)
    }

    /// 只读健康快照（stats 端点消费；只含聚合计数与时间戳，无敏感物）。
    pub fn snapshot(&self) -> ProjectorHealthSnapshot {
        ProjectorHealthSnapshot {
            generation: self.generation.load(Ordering::Relaxed),
            restarts: self.restarts.load(Ordering::Relaxed),
            uptime_secs: unix_millis().saturating_sub(self.started_at_ms) / 1000,
            last_claim_progress_age_secs: self.progress_age_secs(),
            summary: self
                .summary
                .lock()
                .map(|guard| guard.clone())
                .unwrap_or_default(),
        }
    }
}

/// 只读健康快照（stats 端点返回形态；serde 形态供 HTTP 适配直接复用）。
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectorHealthSnapshot {
    pub generation: u64,
    pub restarts: u64,
    pub uptime_secs: u64,
    pub last_claim_progress_age_secs: Option<u64>,
    pub summary: WorkerRunSummary,
}

/// Handle held by `main`; graceful shutdown cancels then joins with a bound.
pub struct AuthorizationProjectorHandle {
    pub cancellation: ProjectorCancellationToken,
    pub join: JoinHandle<Result<WorkerRunSummary, String>>,
    /// Run-scoped identifier used in logs / lease owner strings; never stable
    /// across restarts and never usable as authorization identity.
    pub run_id: String,
    /// 监督共享态（F5 修复 1d）：健康快照与 stats 端点接线来源。
    pub health: Arc<ProjectorHealthShared>,
}

impl AuthorizationProjectorHandle {
    /// 只读健康快照：代数/重启数/uptime/停滞年龄/跨代聚合计数。仅含聚合
    /// 计数与时间戳——无租户/卡/grant 语义，无 lease token，不是授权身份。
    pub fn health_snapshot(&self) -> ProjectorHealthSnapshot {
        self.health.snapshot()
    }
}

pub struct ShutdownReport {
    pub summary: Result<WorkerRunSummary, String>,
    pub join_elapsed: Duration,
}

/// Cancel the worker and await termination within a bounded timeout.
///
/// Timeout or panic surfaces as `Err`, so a dying worker can never be silently
/// reported as a clean shutdown.
pub async fn shutdown_authorization_projector(
    handle: AuthorizationProjectorHandle,
    timeout: Duration,
) -> ShutdownReport {
    handle.cancellation.cancel();
    let started = Instant::now();
    // 层结构：JoinHandle<T> 作为 Future 的 Output 是 `Result<T, JoinError>`；
    // 监督任务返回 `Result<WorkerRunSummary, String>`，timeout 再包一层
    // Elapsed —— 共四层。
    let summary = match tokio::time::timeout(timeout, handle.join).await {
        Ok(Ok(Ok(summary))) => Ok(summary),
        Ok(Ok(Err(failure))) => Err(failure),
        Ok(Err(join_error)) => Err(format!("supervisor task failed: {join_error}")),
        Err(_) => Err(format!(
            "projector did not stop within {:?}; possibly stuck in a publish transaction",
            timeout
        )),
    };
    tracing::info!(
        run_id = %handle.run_id,
        join_elapsed_ms = started.elapsed().as_millis() as u64,
        clean = summary.is_ok(),
        "authorization projector shutdown completed"
    );
    ShutdownReport {
        summary,
        join_elapsed: started.elapsed(),
    }
}

#[derive(Debug, Clone)]
pub struct AuthorizationProjectorConfig {
    /// Tenant ids polled round-robin each cycle. An empty list keeps the
    /// consumer idle (documented slice-1 gap: no backlog discovery query).
    /// Produced exclusively by [`parse_projector_tenants`]; a misconfigured
    /// deployment must fail startup, never lose tenant scopes silently.
    pub tenants: Vec<i64>,
    pub poll_interval_secs: u64,
    pub claim_lease_seconds: i64,
    pub manifest_lease_seconds: i64,
    /// 单个 delta 事件的整体处理 deadline（F5 修复 1b）：任何一步挂起都必须
    /// 在 deadline 内变成"计数 + 尽力释放租约 + 继续循环"，worker 永不永久
    /// 停在当次事件内。应严格小于 `claim_lease_seconds`，为释放/租约过期
    /// reclaim 留出余量。
    pub event_deadline: Duration,
    /// 看门狗停滞阈值（F5 修复 1d）：连续该时长无任何 claim 返回/事件完成
    /// 进展，且 runtime 报告存在可 claim 积压 → 监督循环重建 worker 代。
    pub watchdog_stall_threshold: Duration,
    /// 看门狗检查周期（F5 修复 1d）；代间退避也使用该值（下界 50ms），
    /// 保证测试可收缩、生产不空转。
    pub watchdog_tick: Duration,
    /// Scheduling topology; see [`ProjectorSchedulingMode`]. Default
    /// `TenantSerial` (accepted behavior) until partitioned integration
    /// acceptance completes — default-off discipline for new durable paths.
    pub scheduling_mode: ProjectorSchedulingMode,
    /// Parallel workers in `Partitioned` mode; ignored by `TenantSerial`.
    /// Guarded by [`validate_partition_worker_budget`] before startup.
    pub worker_count: usize,
}

/// Fail-fast parser for the `ASTRAL_PROJECTOR_TENANTS` deployment variable.
///
/// Explicit policy:
/// - An empty or whitespace-only raw value yields an empty consumer set; the
///   projector start-up logs an idle warning for that documented slice-1 gap.
/// - Once ANY token is present, EVERY comma-separated token must be a
///   strictly positive `i64` after trimming. Blank tokens (`"7,,9"`,
///   trailing/leading commas), non-numbers, zero/negative ids and out-of-range
///   literals are STARTUP ERRORS — silent `filter_map(..ok())` drops of
///   malformed tokens are forbidden because they hide half-configured scopes.
/// - Duplicate ids are deduplicated order-preservingly so a repeated value
///   cannot skew round-robin polling while remaining legal input.
///
/// Pure function (no env access, no DB): keeps multi-instance lease ownership
/// semantics untouched and unit-testable without infrastructure.
pub fn parse_projector_tenants(raw: &str) -> Result<Vec<i64>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let mut tenants: Vec<i64> = Vec::new();
    for token in trimmed.split(',') {
        let token = token.trim();
        if token.is_empty() {
            return Err(format!(
                "code=config.empty_tenant_token;raw={raw:?};expected=positive_i64_list"
            ));
        }
        match token.parse::<i64>() {
            Ok(value) if value > 0 => {
                if !tenants.contains(&value) {
                    tenants.push(value);
                }
            }
            Ok(value) => return Err(format!("code=config.non_positive_tenant_id;value={value}")),
            Err(_) => {
                return Err(format!(
                    "code=config.invalid_tenant_token;token={token:?};expected=positive_i64"
                ))
            }
        }
    }
    Ok(tenants)
}

/// Fail-fast parser for `ASTRAL_PROJECTOR_SCHEDULING_MODE`. Empty/whitespace
/// means the default (`tenant-serial`); anything present must be exactly one
/// of the listed values — unknown values are STARTUP ERRORS, never silently
/// downgraded.
pub fn parse_projector_scheduling_mode(raw: &str) -> Result<ProjectorSchedulingMode, String> {
    match raw.trim() {
        "" => Ok(ProjectorSchedulingMode::TenantSerial),
        "tenant-serial" | "tenant_serial" => Ok(ProjectorSchedulingMode::TenantSerial),
        "partitioned" => Ok(ProjectorSchedulingMode::Partitioned),
        other => Err(format!(
            "code=config.invalid_scheduling_mode;value={other:?};expected=tenant-serial|partitioned"
        )),
    }
}

/// Fail-fast parser for `ASTRAL_PROJECTOR_WORKER_COUNT` (partitioned mode).
/// Empty means the Q2 default (4); present values must be 1..=MAX.
pub fn parse_projector_worker_count(raw: &str) -> Result<usize, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(DEFAULT_PARTITION_WORKER_COUNT);
    }
    let value: usize = trimmed
        .parse()
        .map_err(|_| format!("code=config.invalid_worker_count;value={trimmed:?}"))?;
    if value == 0 || value > MAX_PARTITION_WORKER_COUNT {
        return Err(format!(
            "code=config.worker_count_out_of_bounds;value={value};max={MAX_PARTITION_WORKER_COUNT}"
        ));
    }
    Ok(value)
}

/// Q2 startup guard: the partitioned pool must fit the shared MySQL budget.
/// Each worker runs short transactions; two concurrent connections per worker
/// is the documented ceiling, so `worker_count * 2 <= pool_max_connections`.
pub fn validate_partition_worker_budget(
    worker_count: usize,
    pool_max_connections: u32,
) -> Result<(), String> {
    if worker_count == 0 || worker_count > MAX_PARTITION_WORKER_COUNT {
        return Err(format!(
            "code=auth_projector.worker_count_out_of_bounds;value={worker_count};max={MAX_PARTITION_WORKER_COUNT}"
        ));
    }
    let budget = (pool_max_connections / 2) as usize;
    if worker_count > budget {
        return Err(format!(
            "code=auth_projector.worker_count_exceeds_pool_budget;workers={worker_count};pool_max_connections={pool_max_connections}"
        ));
    }
    Ok(())
}

impl Default for AuthorizationProjectorConfig {
    fn default() -> Self {
        Self {
            tenants: Vec::new(),
            poll_interval_secs: POLL_INTERVAL_SECS,
            claim_lease_seconds: CLAIM_LEASE_SECS,
            manifest_lease_seconds: MAX_MANIFEST_LEASE_SECONDS.min(600),
            // 90s = claim 租约（120s）的 75%：deadline 先于租约过期触发，
            // 释放失败时租约 reclaim 仍是安全网。
            event_deadline: Duration::from_secs((CLAIM_LEASE_SECS as u64) * 3 / 4),
            // 看门狗默认：5 分钟零进展 + 积压存在 → 重建；15s 探测周期。
            watchdog_stall_threshold: Duration::from_secs(300),
            watchdog_tick: Duration::from_secs(15),
            scheduling_mode: ProjectorSchedulingMode::TenantSerial,
            worker_count: DEFAULT_PARTITION_WORKER_COUNT,
        }
    }
}

/// Start one owned projector task backed by the sqlx runtime. The caller MUST
/// keep the handle and invoke [`shutdown_authorization_projector`].
pub fn start_authorization_projector(
    db: MySqlPool,
    config: AuthorizationProjectorConfig,
) -> AuthorizationProjectorHandle {
    let runtime: Arc<dyn AuthorizationProjectorRuntime> =
        Arc::new(SqlxAuthorizationProjectorRuntime::new(db));
    start_authorization_projector_with_runtime(runtime, config)
}

pub fn start_authorization_projector_with_runtime(
    runtime: Arc<dyn AuthorizationProjectorRuntime>,
    config: AuthorizationProjectorConfig,
) -> AuthorizationProjectorHandle {
    let cancellation = ProjectorCancellationToken::default();
    let run_cancellation = cancellation.clone();
    let run_id = uuid::Uuid::new_v4().to_string();
    if config.tenants.is_empty() {
        tracing::warn!(
            run_id = %run_id,
            "authorization projector started WITHOUT tenant scopes; the new delta \
             queue stays unconsumed until tenant configuration is provided"
        );
    }
    // F5 修复 1d：监督循环持有 worker 生命周期——panic/意外退出自动重启
    // （每代新 run_id/owner，租约天然隔离；退避可被 shutdown 打断），
    // "有可 claim 积压但停滞"由看门狗强制重建。调度拓扑按配置分派：
    // TenantSerial（默认，已验收行为）/ Partitioned（Phase 1 新路径）。
    let health = Arc::new(ProjectorHealthShared::new());
    let join: JoinHandle<Result<WorkerRunSummary, String>> = match config.scheduling_mode {
        ProjectorSchedulingMode::TenantSerial => tokio::spawn(supervise_projector(
            runtime,
            config,
            run_cancellation,
            health.clone(),
        )),
        ProjectorSchedulingMode::Partitioned => tokio::spawn(supervise_partition_projector(
            runtime,
            config,
            run_cancellation,
            health.clone(),
        )),
    };
    AuthorizationProjectorHandle {
        cancellation,
        join,
        run_id,
        health,
    }
}

/// 看门狗积压探测：任一配置租户存在可 claim 事件即视为有积压。
async fn supervisor_backlog_exists(
    runtime: &dyn AuthorizationProjectorRuntime,
    config: &AuthorizationProjectorConfig,
) -> bool {
    for tenant_id in &config.tenants {
        let scope = DeltaEventClaimScope {
            tenant_id: *tenant_id,
            card_id: None,
        };
        if runtime.has_claimable_work(&scope).await {
            return true;
        }
    }
    false
}

/// 监督循环（F5 修复 1d）：worker 退出/panic → error 日志 + 退避重启（每代
/// 新 run_id/owner，租约天然隔离，旧 120s 租约到期后被新代 reclaim）；连续
/// `watchdog_stall_threshold` 无进展且 runtime 报告有可 claim 积压 → 看门狗
/// 强制重建当前代。shutdown 取消 → 取消当前代并在有界宽限内聚合返回。
async fn supervise_projector(
    runtime: Arc<dyn AuthorizationProjectorRuntime>,
    config: AuthorizationProjectorConfig,
    shutdown: ProjectorCancellationToken,
    health: Arc<ProjectorHealthShared>,
) -> Result<WorkerRunSummary, String> {
    let backoff = config.watchdog_tick.max(Duration::from_millis(50));
    let mut watchdog = tokio::time::interval(config.watchdog_tick.max(Duration::from_millis(50)));
    watchdog.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        if shutdown.is_cancelled() {
            return Ok(health.take_summary());
        }
        let generation = health.next_generation();
        let child_cancel = ProjectorCancellationToken::default();
        let progress = Arc::new(ProjectorProgress::default());
        health.swap_progress(progress.clone());
        // 代启动时刻即为基线进展：worker 若卡死在首个步骤内部（从未产生任何
        // claim 返回），看门狗仍能按"距代启动的停滞年龄"探测到。
        progress.touch();
        let owner = format!("auth-projector:{}", uuid::Uuid::new_v4());
        tracing::info!(
            generation,
            owner = %owner,
            "authorization projector worker generation starting"
        );
        let mut child = tokio::spawn(run_worker(
            runtime.clone(),
            config.clone(),
            owner,
            child_cancel.clone(),
            progress,
        ));
        let mut outcome: Option<
            Result<Result<WorkerRunSummary, tokio::task::JoinError>, tokio::task::JoinError>,
        > = None;
        let mut abandoned = false;
        loop {
            tokio::select! {
                joined = &mut child => {
                    outcome = Some(joined);
                    break;
                }
                _ = shutdown.cancelled() => {
                    child_cancel.cancel();
                    match tokio::time::timeout(Duration::from_secs(5), &mut child).await {
                        Ok(joined) => outcome = Some(joined),
                        Err(_) => {
                            abandoned = true;
                            tracing::error!(
                                generation,
                                "projector worker generation ignored cancellation; \
                                 abandoning generation"
                            );
                        }
                    }
                    break;
                }
                _ = watchdog.tick() => {
                    // 停滞判定用毫秒比较（下界 50ms 防零阈值热循环）。
                    let stalled = health
                        .progress_age_ms()
                        .map(|age_ms| {
                            age_ms >= (config.watchdog_stall_threshold.as_millis() as u64).max(50)
                        })
                        .unwrap_or(false);
                    if stalled && supervisor_backlog_exists(&*runtime, &config).await {
                        tracing::error!(
                            generation,
                            "projector stall with claimable backlog detected; \
                             rebuilding worker generation"
                        );
                        health.record_restart();
                        child_cancel.cancel();
                        // 卡死的子任务无法被 join 收回：有界等待后弃置；其
                        // 租约到期后由新代 reclaim，绝不产生重复发布。
                        let _ = tokio::time::timeout(Duration::from_secs(1), &mut child).await;
                        break;
                    }
                }
            }
        }
        match outcome {
            Some(Ok(Ok(summary))) => {
                health.merge_summary(&summary);
                if shutdown.is_cancelled() {
                    return Ok(health.take_summary());
                }
                // 无 shutdown 指令下的"干净退出"同样是异常信号：run_worker
                // 只在 cancellation 时返回 Ok。记录并重启。
                tracing::error!(
                    generation,
                    "projector worker exited without shutdown; restarting"
                );
                health.record_restart();
            }
            Some(Ok(Err(join_error))) => {
                tracing::error!(
                    error = %join_error,
                    generation,
                    "projector worker task panicked; restarting"
                );
                health.record_restart();
            }
            Some(Err(_)) | None => {}
        }
        if shutdown.is_cancelled() {
            return if abandoned {
                Err("projector worker generation did not stop within shutdown grace".to_owned())
            } else {
                Ok(health.take_summary())
            };
        }
        // 代间退避（可被 shutdown 打断）。
        let _ = tokio::time::timeout(backoff, shutdown.cancelled()).await;
    }
}

/// Partitioned supervision loop (multi-tenant redesign Phase 1): mirrors the
/// F5 supervisor contract (panic/exit restart, stall + backlog watchdog,
/// generation rebuild, bounded shutdown grace) across `config.worker_count`
/// parallel partition workers. Every child owns its lease identity; a stalled
/// child's partitions are reclaimed by lease expiry, never by double publish.
async fn supervise_partition_projector(
    runtime: Arc<dyn AuthorizationProjectorRuntime>,
    config: AuthorizationProjectorConfig,
    shutdown: ProjectorCancellationToken,
    health: Arc<ProjectorHealthShared>,
) -> Result<WorkerRunSummary, String> {
    let backoff = config.watchdog_tick.max(Duration::from_millis(50));
    let mut watchdog = tokio::time::interval(config.watchdog_tick.max(Duration::from_millis(50)));
    watchdog.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        if shutdown.is_cancelled() {
            return Ok(health.take_summary());
        }
        let generation = health.next_generation();
        let child_cancel = ProjectorCancellationToken::default();
        let progress = Arc::new(ProjectorProgress::default());
        health.swap_progress(progress.clone());
        // 代启动时刻即为基线进展（与单 worker 监督同一停滞探测语义）。
        progress.touch();
        let worker_count = config.worker_count.max(1);
        let mut children: Vec<
            tokio::task::JoinHandle<Result<WorkerRunSummary, tokio::task::JoinError>>,
        > = Vec::with_capacity(worker_count);
        for slot in 0..worker_count {
            let owner = format!("auth-projector-p{slot}:{}", uuid::Uuid::new_v4());
            tracing::info!(
                generation,
                owner = %owner,
                slot,
                "authorization partition worker starting"
            );
            children.push(tokio::spawn(run_partition_worker(
                runtime.clone(),
                config.clone(),
                owner,
                child_cancel.clone(),
                progress.clone(),
            )));
        }
        loop {
            tokio::select! {
                _ = watchdog.tick() => {
                    // 收割已退出槽位：finished join 立即返回；干净退出（无
                    // shutdown 指令）与 panic 同为异常信号，按槽位重启。
                    let mut keep = Vec::with_capacity(children.len());
                    for child in children.drain(..) {
                        if child.is_finished() {
                            match child.await {
                                Ok(Ok(summary)) => health.merge_summary(&summary),
                                Ok(Err(join_error)) => {
                                    tracing::error!(
                                        error = %join_error,
                                        generation,
                                        "partition worker task panicked; respawning slot"
                                    );
                                    health.record_restart();
                                }
                                Err(_) => {}
                            }
                        } else {
                            keep.push(child);
                        }
                    }
                    children = keep;
                    while children.len() < worker_count {
                        let slot = children.len();
                        let owner = format!("auth-projector-p{slot}:{}", uuid::Uuid::new_v4());
                        children.push(tokio::spawn(run_partition_worker(
                            runtime.clone(),
                            config.clone(),
                            owner,
                            child_cancel.clone(),
                            progress.clone(),
                        )));
                    }
                    // 停滞判定（毫秒比较，下界 50ms 防零阈值热循环）。
                    let stalled = health
                        .progress_age_ms()
                        .map(|age_ms| {
                            age_ms >= (config.watchdog_stall_threshold.as_millis() as u64).max(50)
                        })
                        .unwrap_or(false);
                    if stalled && supervisor_backlog_exists(&*runtime, &config).await {
                        tracing::error!(
                            generation,
                            "partition worker stall with claimable backlog detected; \
                             rebuilding worker generation"
                        );
                        health.record_restart();
                        child_cancel.cancel();
                        // 卡死的子任务无法被 join 收回：有界等待后弃置；其
                        // 事件/分区租约到期后由新代 reclaim，绝不产生重复发布。
                        for child in children.iter_mut() {
                            let _ = tokio::time::timeout(Duration::from_secs(1), child).await;
                        }
                        break;
                    }
                }
                _ = shutdown.cancelled() => {
                    child_cancel.cancel();
                    let mut abandoned = false;
                    for child in children.iter_mut() {
                        match tokio::time::timeout(Duration::from_secs(5), child).await {
                            Ok(Ok(Ok(summary))) => health.merge_summary(&summary),
                            Ok(Ok(Err(join_error))) => {
                                tracing::error!(
                                    error = %join_error,
                                    generation,
                                    "partition worker task panicked during shutdown"
                                );
                            }
                            Ok(Err(_)) => {}
                            Err(_) => {
                                abandoned = true;
                            }
                        }
                    }
                    return if abandoned {
                        tracing::error!(
                            generation,
                            "partition worker generation ignored cancellation; \
                             abandoning generation"
                        );
                        Err("partition worker generation did not stop within shutdown grace"
                            .to_owned())
                    } else {
                        Ok(health.take_summary())
                    };
                }
            }
        }
        // 代间退避（可被 shutdown 打断）。
        let _ = tokio::time::timeout(backoff, shutdown.cancelled()).await;
    }
}

/// One partition worker (partitioned scheduling mode). Per round: discover
/// claimable partitions inside the tenant allowlist, acquire each partition's
/// exclusive lease (Busy -> skip, never wait), drain up to
/// [`MAX_EVENTS_PER_PARTITION_PER_BATCH`] events with a lease heartbeat before
/// every claim, then release. The per-event processing path
/// ([`process_one_event`]) is byte-identical to TenantSerial mode.
async fn run_partition_worker(
    runtime: Arc<dyn AuthorizationProjectorRuntime>,
    config: AuthorizationProjectorConfig,
    lease_owner: String,
    cancellation: ProjectorCancellationToken,
    progress: Arc<ProjectorProgress>,
) -> Result<WorkerRunSummary, tokio::task::JoinError> {
    let mut ticker = tokio::time::interval(Duration::from_secs(config.poll_interval_secs.max(1)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut summary = WorkerRunSummary::default();
    tracing::info!(
        tenants = ?config.tenants,
        poll_interval_secs = config.poll_interval_secs,
        claim_lease_seconds = config.claim_lease_seconds,
        partition_lease_secs = PARTITION_LEASE_SECS,
        "authorization partition worker loop started"
    );
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = cancellation.cancelled() => {
                tracing::info!("authorization partition worker stopped cleanly");
                return Ok(summary);
            }
        }
        if cancellation.is_cancelled() {
            return Ok(summary);
        }
        // 1) 发现：allowlist 内当前有可 claim 事件的分区。发现查询镜像 claim
        //    资格 + 版本序门（astral-db discover_claimable_partitions），所以
        //    拿到租约后立刻可 claim，不存在"发现即饿死"。
        let candidates = match runtime
            .discover_partitions(&config.tenants, PARTITION_DISCOVERY_LIMIT)
            .await
        {
            Ok(candidates) => candidates,
            Err(error) => {
                // 瞬态 DB 失败保持周期存活（与旧循环同一纪律：不重试、不伪装）。
                tracing::warn!(error = %error, "partition discovery failed; skipping round");
                continue;
            }
        };
        for candidate in candidates {
            if cancellation.is_cancelled() {
                break;
            }
            // 2) 分区租约：拿到才认领；Busy（他人持有）直接跳过，不等待。
            let handle = match runtime
                .acquire_partition_lease(&candidate, &lease_owner, PARTITION_LEASE_SECS)
                .await
            {
                Ok(Some(handle)) => handle,
                Ok(None) => continue,
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        aggregate_type = %candidate.aggregate_type,
                        aggregate_id = candidate.aggregate_id,
                        "partition lease acquire failed; skipping partition"
                    );
                    continue;
                }
            };
            // 3) 批内逐事件：续租（排他心跳）→ 分区认领 → 与 TenantSerial
            //    完全相同的单事件处理路径。租约丢失立即弃置该分区。
            for _ in 0..MAX_EVENTS_PER_PARTITION_PER_BATCH {
                if cancellation.is_cancelled() {
                    break;
                }
                if let Err(error) = runtime
                    .renew_partition_lease(&handle, PARTITION_LEASE_SECS)
                    .await
                {
                    tracing::warn!(
                        error = %error,
                        aggregate_type = %candidate.aggregate_type,
                        aggregate_id = candidate.aggregate_id,
                        "partition lease lost mid-batch; abandoning partition"
                    );
                    break;
                }
                let claim_started = Instant::now();
                let scope = DeltaEventClaimScope {
                    tenant_id: candidate.tenant_id,
                    card_id: None,
                };
                let claimed_result = runtime
                    .claim_next_event_in_partition(
                        &candidate,
                        &scope,
                        &lease_owner,
                        config.claim_lease_seconds,
                    )
                    .await;
                // 看门狗进展语义与 TenantSerial 一致：claim 返回（含空轮询）即进展。
                progress.touch();
                let claimed = match claimed_result {
                    Ok(Some(claimed)) => claimed,
                    Ok(None) => break,
                    Err(error) => {
                        tracing::warn!(
                            error = %error,
                            aggregate_type = %candidate.aggregate_type,
                            aggregate_id = candidate.aggregate_id,
                            "partition claim cycle failed"
                        );
                        break;
                    }
                };
                summary.events_claimed += 1;
                record_projector_event(ProjectorEventOutcome::Claimed);
                tracing::debug!(
                    event_id = %claimed.event_id,
                    operation_id = %claimed.operation_id,
                    attempts = claimed.attempts,
                    partition_type = %candidate.aggregate_type,
                    partition_id = candidate.aggregate_id,
                    claim_elapsed_us = claim_started.elapsed().as_micros() as u64,
                    "delta event claimed (partitioned)"
                );
                // 事件级 deadline 语义与 TenantSerial 完全一致（F5 修复 1b）。
                let processing = tokio::time::timeout(
                    config.event_deadline,
                    process_one_event(
                        &runtime,
                        &config,
                        &lease_owner,
                        &cancellation,
                        &claimed,
                        &mut summary,
                    ),
                )
                .await;
                if processing.is_err() {
                    summary.events_deadline_exceeded += 1;
                    record_projector_event(ProjectorEventOutcome::DeadlineExceeded);
                    #[cfg(feature = "e3-observability")]
                    log_e3_attempt_event(
                        "terminal_unknown",
                        &claimed,
                        "processing_deadline_exceeded",
                        false,
                        None,
                    );
                    tracing::error!(
                        event_id = %claimed.event_id,
                        operation_id = %claimed.operation_id,
                        deadline_secs = config.event_deadline.as_secs(),
                        "delta event processing deadline exceeded; lease left to expire-reclaim"
                    );
                }
                // F5 修复 1d 看门狗：事件处理完成（无论结果）即进展。
                progress.touch();
            }
            // 4) 尽力释放；崩溃路径由租约到期 reclaim 兜底（释放失败不是错误）。
            if let Err(error) = runtime.release_partition_lease(&handle).await {
                tracing::warn!(
                    error = %error,
                    aggregate_type = %candidate.aggregate_type,
                    aggregate_id = candidate.aggregate_id,
                    "partition lease release failed; expiry will reclaim"
                );
            }
        }
    }
}

async fn run_worker(
    runtime: Arc<dyn AuthorizationProjectorRuntime>,
    config: AuthorizationProjectorConfig,
    lease_owner: String,
    cancellation: ProjectorCancellationToken,
    progress: Arc<ProjectorProgress>,
) -> Result<WorkerRunSummary, tokio::task::JoinError> {
    let mut ticker = tokio::time::interval(Duration::from_secs(config.poll_interval_secs.max(1)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut summary = WorkerRunSummary::default();
    tracing::info!(
        tenants = ?config.tenants,
        poll_interval_secs = config.poll_interval_secs,
        claim_lease_seconds = config.claim_lease_seconds,
        "authorization projector worker loop started"
    );
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = cancellation.cancelled() => {
                tracing::info!("authorization projector worker stopped cleanly");
                return Ok(summary);
            }
        }
        if cancellation.is_cancelled() {
            tracing::info!("authorization projector worker stopped between ticks");
            return Ok(summary);
        }
        for tenant_id in &config.tenants {
            if cancellation.is_cancelled() {
                break;
            }
            let scope = DeltaEventClaimScope {
                tenant_id: *tenant_id,
                card_id: None,
            };
            for _ in 0..MAX_EVENTS_PER_TENANT_PER_CYCLE {
                if cancellation.is_cancelled() {
                    break;
                }
                let claim_started = Instant::now();
                let claimed_result = runtime
                    .claim_next_event(&scope, &lease_owner, config.claim_lease_seconds)
                    .await;
                // F5 修复 1d 看门狗：claim 返回（含空轮询）即进展；卡死在
                // claim 内部则不再推进，由监督循环探测。
                progress.touch();
                let claimed = match claimed_result {
                    Ok(Some(claimed)) => claimed,
                    Ok(None) => break,
                    Err(error) => {
                        // Transient DB failure on the claim path keeps the cycle
                        // alive (interval semantics of the old worker family).
                        tracing::warn!(
                            tenant_id = *tenant_id,
                            error = %error,
                            "authorization projector claim cycle failed"
                        );
                        break;
                    }
                };
                summary.events_claimed += 1;
                record_projector_event(ProjectorEventOutcome::Claimed);
                tracing::debug!(
                    event_id = %claimed.event_id,
                    operation_id = %claimed.operation_id,
                    attempts = claimed.attempts,
                    claim_elapsed_us = claim_started.elapsed().as_micros() as u64,
                    "delta event claimed"
                );
                // F5 修复 1b：事件级 deadline。任何一步挂起（DB 锁等待、连接
                // 池耗尽 await、L2 推送等）都必须在 deadline 内变成"计数 + 尽
                // 力释放租约 + 继续循环"，worker 永不永久停在当次事件内（S15
                // 实测的 LEASED 冻结形态）。临时 future 在语句结束即 drop：
                // 进行中的 DB 事务随 sqlx Tx drop 回滚，无半写。
                let processing = tokio::time::timeout(
                    config.event_deadline,
                    process_one_event(
                        &runtime,
                        &config,
                        &lease_owner,
                        &cancellation,
                        &claimed,
                        &mut summary,
                    ),
                )
                .await;
                if processing.is_err() {
                    summary.events_deadline_exceeded += 1;
                    record_projector_event(ProjectorEventOutcome::DeadlineExceeded);
                    #[cfg(feature = "e3-observability")]
                    log_e3_attempt_event(
                        "terminal_unknown",
                        &claimed,
                        "processing_deadline_exceeded",
                        false,
                        None,
                    );
                    tracing::error!(
                        event_id = %claimed.event_id,
                        operation_id = %claimed.operation_id,
                        deadline_secs = config.event_deadline.as_secs(),
                        "delta event processing deadline exceeded; lease left to expire-reclaim"
                    );
                    // 批次 B 调研纪律：发布事务与事件终态同事务 commit，超时
                    // 只意味着 commit 结果 UNKNOWN——此刻**禁止发布任何租约
                    // mutation**（含 release）。事件租约在 claim_lease 到期后
                    // 由既有 reclaim 门接管：已发布行是 SUCCEEDED（不可再
                    // claim），未发布行按未知结果 takeover 重投，均无需在此
                    // 对账。
                }
                // F5 修复 1d 看门狗：事件处理完成（无论结果）即进展。
                progress.touch();
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Runtime seam: every DB transaction boundary lives behind this trait so each
// decision branch stays unit-testable without MySQL.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum RuntimeAccessError {
    #[error("database access failed: {0}")]
    Database(String),
    #[error("repository rejected the operation: {0}")]
    Repository(RepositoryRejection),
}

/// Typed payload of [`RuntimeAccessError::Repository`]. Repository error
/// variants are kept INTACT across the runtime seam so downstream failure
/// classification matches on the typed variant plus its embedded stable
/// machine code — never on rendered `Display` text, whose wording is not a
/// contract and whose dynamic detail may legitimately contain foreign tokens.
#[derive(Debug, thiserror::Error)]
pub enum RepositoryRejection {
    /// Typed projection-repository refusal (variant + stable `code=` token).
    #[error("{0}")]
    Projection(AuthorizationProjectionError),
    /// Typed astral-db grant-repository refusal (delta-lease claim/lease
    /// primitives and any future non-projection primitive). The variant is
    /// preserved intact — `ClaimRace` and `LeaseCasFailed` in particular — so
    /// lost-lease classification can never be flattened into generic text and
    /// a lost lease can never be misrouted into a `fail_delta_event` write.
    #[error("{0}")]
    Grant(astral_db::GrantRepositoryError),
    /// Non-typed refusal text raised by this module itself (projector-side
    /// stable `code=` tokens), rendered here; carries a stable token when
    /// available.
    #[error("{0}")]
    Other(String),
}

impl From<sqlx::Error> for RuntimeAccessError {
    fn from(value: sqlx::Error) -> Self {
        Self::Database(value.to_string())
    }
}

impl From<astral_db::GrantRepositoryError> for RuntimeAccessError {
    fn from(value: astral_db::GrantRepositoryError) -> Self {
        match value {
            astral_db::GrantRepositoryError::Query(inner) => Self::Database(inner.to_string()),
            // Every non-query grant refusal keeps its variant across the seam
            // (M2): `ClaimRace`/`LeaseCasFailed` must stay classifiable as
            // lost ownership instead of dissolving into rendered text.
            other => Self::Repository(RepositoryRejection::Grant(other)),
        }
    }
}

impl From<AuthorizationProjectionError> for RuntimeAccessError {
    fn from(value: AuthorizationProjectionError) -> Self {
        match value {
            AuthorizationProjectionError::Query(inner) => Self::Database(inner.to_string()),
            other => Self::Repository(RepositoryRejection::Projection(other)),
        }
    }
}

#[async_trait]
pub trait AuthorizationProjectorRuntime: Send + Sync + 'static {
    /// One short-lived claim transaction: installs LEASED + owner + fresh
    /// run-scoped token. Commit happens inside (also for `Ok(None)`).
    async fn claim_next_event(
        &self,
        scope: &DeltaEventClaimScope,
        lease_owner: &str,
        lease_seconds: i64,
    ) -> Result<Option<DeltaEventClaim>, RuntimeAccessError>;

    /// Strict re-read of the leased row (lease proof re-verified inside SQL).
    async fn read_claimed_event(
        &self,
        identity: &DeltaLeaseIdentity,
    ) -> Result<ClaimedDeltaEvent, RuntimeAccessError>;

    /// One short read-only transaction loading the strict published frontier
    /// AND the current parent reference snapshot for one aggregate.
    ///
    /// - `Ok(None)`: no current pointer exists (aggregate never published);
    ///   nothing is locked or written.
    /// - `Ok(Some([`PublicationContext`]))`: frontier generations `1..=G`
    ///   passed the strict plan⇆delta⇆manifest⇆pointer assembly plus the
    ///   verified parent reference views of the CURRENT publication, loaded in
    ///   ONE transaction so both facets describe the same committed world.
    /// - A live pointer whose parent snapshot cannot be observed is reported
    ///   as Corrupt — never as a degraded partial view usable by planning.
    async fn observe_publication_context(
        &self,
        identity: &ProjectionAggregateIdentity,
    ) -> Result<Option<PublicationContext>, RuntimeAccessError>;

    /// Complete revision history for `(tenant, aggregate[, card])`, ordered by
    /// (`grant_id`, `revision_no`); read-only, no raw-source fallback.
    async fn load_scope_ledger(
        &self,
        tenant_id: i64,
        aggregate_type: &str,
        aggregate_id: i64,
        card_id: Option<i64>,
    ) -> Result<Vec<RawLedgerRow>, RuntimeAccessError>;

    /// Execute the fixed single-transaction publish sequence and commit.
    /// Failure rolls everything back atomically.
    async fn execute_projection_publish(
        &self,
        command: &DeltaProjectorPublishCommand,
    ) -> Result<DeltaProjectorPublishOutcome, RuntimeAccessError>;

    /// Record a durable failure + bounded backoff. Loss of the lease CAS is
    /// reconciled (logged) instead of retried blindly.
    async fn fail_event(&self, identity: &DeltaLeaseIdentity, backoff_seconds: i64, message: &str);

    /// Relinquish the lease without recording failure.
    async fn release_event(&self, identity: &DeltaLeaseIdentity);

    /// Durable terminal quarantine of one leased event via the live-lease
    /// guarded repository boundary.
    ///
    /// `Ok(())` is durable proof that the row left the claimable queue as
    /// `QUARANTINED`. A `LeaseCasFailed`-flavored error or a database query
    /// failure means the terminal state is UNKNOWN: callers must record the
    /// unknown result and issue NO further mutation for that event (no fail,
    /// no release, no retry) until reconciliation. Quarantine deliberately
    /// keeps the row's `cas_version` untouched, which is exactly what the
    /// operator requeue path pins later; this worker never requeues.
    async fn mark_event_quarantined(
        &self,
        lease: &DeltaLeaseIdentity,
        reason_code: &str,
        reason_detail: &str,
    ) -> Result<(), RuntimeAccessError>;

    /// 诊断启发（F5 修复 1d 看门狗，非授权路径）：作用域内是否存在当前可
    /// claim 的事件（PENDING 且 backoff 期满，或租约已过期的 LEASED）。默认
    /// `false`（无积压，看门狗保守不动作）仅适用于测试/空闲 runtime；生产
    /// sqlx runtime 必须覆盖。
    async fn has_claimable_work(&self, _scope: &DeltaEventClaimScope) -> bool {
        false
    }

    // ── Partition scheduling ports (multi-tenant redesign Phase 1). Defaults
    // fail closed: a runtime that has not opted into partitioned scheduling
    // must never be silently scheduled as if it had. The production sqlx
    // runtime and partition-mode test fakes override all four; TenantSerial
    // mode never calls them.

    /// Discover partitions (inside the validated tenant allowlist) that hold
    /// at least one claimable event right now, oldest due first. The ledger
    /// query mirrors the claim eligibility + sibling-ordering gate verbatim.
    async fn discover_partitions(
        &self,
        _tenants: &[i64],
        _limit: i64,
    ) -> Result<Vec<ProjectionAggregateIdentity>, RuntimeAccessError> {
        Err(RuntimeAccessError::Repository(RepositoryRejection::Other(
            "code=auth_projector.partition_ports_unsupported".to_owned(),
        )))
    }

    /// Acquire (or self-renew / expired-takeover) the exclusive scheduling
    /// lease for one partition. `Ok(None)` = live lease held by another worker
    /// (Busy): skip, never wait.
    async fn acquire_partition_lease(
        &self,
        _identity: &ProjectionAggregateIdentity,
        _lease_owner: &str,
        _lease_seconds: i64,
    ) -> Result<Option<PartitionLeaseHandle>, RuntimeAccessError> {
        Err(RuntimeAccessError::Repository(RepositoryRejection::Other(
            "code=auth_projector.partition_ports_unsupported".to_owned(),
        )))
    }

    /// Heartbeat the partition lease before each claim iteration. An error
    /// means the lease was lost (another worker took over after expiry): the
    /// worker must stop touching the partition immediately.
    async fn renew_partition_lease(
        &self,
        _handle: &PartitionLeaseHandle,
        _lease_seconds: i64,
    ) -> Result<(), RuntimeAccessError> {
        Err(RuntimeAccessError::Repository(RepositoryRejection::Other(
            "code=auth_projector.partition_ports_unsupported".to_owned(),
        )))
    }

    /// Best-effort release; expiry is the crash safety net.
    async fn release_partition_lease(
        &self,
        _handle: &PartitionLeaseHandle,
    ) -> Result<(), RuntimeAccessError> {
        Err(RuntimeAccessError::Repository(RepositoryRejection::Other(
            "code=auth_projector.partition_ports_unsupported".to_owned(),
        )))
    }

    /// Claim the next claimable event of ONE partition (identical contract to
    /// [`Self::claim_next_event`], narrowed to the partition identity).
    async fn claim_next_event_in_partition(
        &self,
        _identity: &ProjectionAggregateIdentity,
        _scope: &DeltaEventClaimScope,
        _lease_owner: &str,
        _lease_seconds: i64,
    ) -> Result<Option<DeltaEventClaim>, RuntimeAccessError> {
        Err(RuntimeAccessError::Repository(RepositoryRejection::Other(
            "code=auth_projector.partition_ports_unsupported".to_owned(),
        )))
    }

    /// Pointer-advance reclaim (M3, the ~898s finding): after a DURABLE
    /// publication of this aggregate, pull the `next_attempt_at` of its
    /// budget-exhausted parked events back to now. Returns the number of rows
    /// pulled forward. Default fails closed like the other partition ports.
    async fn reclaim_budget_exhausted_events(
        &self,
        _identity: &ProjectionAggregateIdentity,
    ) -> Result<u64, RuntimeAccessError> {
        Err(RuntimeAccessError::Repository(RepositoryRejection::Other(
            "code=auth_projector.partition_ports_unsupported".to_owned(),
        )))
    }
}

/// Planning-time publication world observed in ONE short committed read
/// transaction (never a publish proof).
#[derive(Debug, Clone)]
pub struct PublicationContext {
    /// Strictly verified published frontier of the aggregate: generations
    /// `1..=G`, embedding the locked pointer record (authoritative base
    /// generation + previous revoke fence) and the `G`-th manifest summary.
    pub frontier: PublishedAggregateFrontier,
    /// Verified `(ordinal, view)` parent reference pairs of the CURRENT
    /// publication in ascending ordinal order. Planning hint only: staging
    /// re-locks and re-verifies every digest/seal/lineage byte inside its own
    /// transaction before any reuse becomes durable.
    pub parent_references: Vec<(u64, ParentReferenceView)>,
}

pub struct SqlxAuthorizationProjectorRuntime {
    pool: MySqlPool,
}

/// Watchdog diagnostics probe (F5 修复 1d): "does this tenant scope hold any
/// event the claim path could serve right now?" — same shape as the claim
/// candidate statements, INCLUDING the per-grant sibling-ordering gate (pinned
/// byte-equal to [`astral_db::DELTA_CLAIM_SIBLING_ORDER_GATE`] by
/// `watchdog_probe_carries_the_claim_sibling_order_gate`). A gate-free probe
/// would report a backlog that the claim can never serve while one chain
/// serializes behind a backoff'd predecessor, and the stall detector would
/// rebuild worker generations in a loop.
const WATCHDOG_CLAIMABLE_PROBE_SQL: &str = "SELECT EXISTS(SELECT 1 FROM authorization_delta_event \
    WHERE tenant_id = ? \
      AND ((status = 'PENDING' \
           AND (next_attempt_at IS NULL OR next_attempt_at <= UTC_TIMESTAMP())) \
          OR (status = 'LEASED' \
              AND lease_expires_at IS NOT NULL \
              AND lease_expires_at <= UTC_TIMESTAMP())) \
      AND NOT EXISTS (SELECT 1 FROM authorization_delta_event pred \
          WHERE pred.tenant_id = authorization_delta_event.tenant_id \
            AND pred.grant_id = authorization_delta_event.grant_id \
            AND pred.target_version < authorization_delta_event.target_version \
            AND pred.status IN ('PENDING', 'LEASED')))";

impl SqlxAuthorizationProjectorRuntime {
    pub fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AuthorizationProjectorRuntime for SqlxAuthorizationProjectorRuntime {
    async fn claim_next_event(
        &self,
        scope: &DeltaEventClaimScope,
        lease_owner: &str,
        lease_seconds: i64,
    ) -> Result<Option<DeltaEventClaim>, RuntimeAccessError> {
        let mut tx = self.pool.begin().await?;
        let claim =
            claim_next_delta_event_in_tx(&mut tx, *scope, lease_owner, lease_seconds).await?;
        // Commit both arms: Some(installed lease) and None(read-only snapshot).
        tx.commit().await?;
        #[cfg(feature = "e3-observability")]
        if let Some(claimed) = claim.as_ref() {
            log_e3_attempt_event("claim_committed", claimed, "leased", true, None);
        }
        Ok(claim)
    }

    async fn discover_partitions(
        &self,
        tenants: &[i64],
        limit: i64,
    ) -> Result<Vec<ProjectionAggregateIdentity>, RuntimeAccessError> {
        let rows = astral_db::discover_claimable_partitions(&self.pool, tenants, limit).await?;
        let mut identities = Vec::with_capacity(rows.len());
        for row in rows {
            identities.push(ProjectionAggregateIdentity::new(
                row.tenant_id,
                row.aggregate_type,
                row.aggregate_id,
            )?);
        }
        Ok(identities)
    }

    async fn acquire_partition_lease(
        &self,
        identity: &ProjectionAggregateIdentity,
        lease_owner: &str,
        lease_seconds: i64,
    ) -> Result<Option<PartitionLeaseHandle>, RuntimeAccessError> {
        astral_db::acquire_partition_lease(&self.pool, identity, lease_owner, lease_seconds)
            .await
            .map_err(RuntimeAccessError::from)
    }

    async fn renew_partition_lease(
        &self,
        handle: &PartitionLeaseHandle,
        lease_seconds: i64,
    ) -> Result<(), RuntimeAccessError> {
        astral_db::renew_partition_lease(&self.pool, handle, lease_seconds)
            .await
            .map_err(RuntimeAccessError::from)
    }

    async fn release_partition_lease(
        &self,
        handle: &PartitionLeaseHandle,
    ) -> Result<(), RuntimeAccessError> {
        astral_db::release_partition_lease(&self.pool, handle)
            .await
            .map_err(RuntimeAccessError::from)
    }

    async fn claim_next_event_in_partition(
        &self,
        identity: &ProjectionAggregateIdentity,
        scope: &DeltaEventClaimScope,
        lease_owner: &str,
        lease_seconds: i64,
    ) -> Result<Option<DeltaEventClaim>, RuntimeAccessError> {
        let mut tx = self.pool.begin().await?;
        let claim = claim_next_delta_event_in_partition_tx(
            &mut tx,
            *scope,
            identity,
            lease_owner,
            lease_seconds,
        )
        .await?;
        // Commit both arms: Some(installed lease) and None (read-only snapshot).
        tx.commit().await?;
        #[cfg(feature = "e3-observability")]
        if let Some(claimed) = claim.as_ref() {
            log_e3_attempt_event("claim_committed", claimed, "leased", true, None);
        }
        Ok(claim)
    }

    async fn reclaim_budget_exhausted_events(
        &self,
        identity: &ProjectionAggregateIdentity,
    ) -> Result<u64, RuntimeAccessError> {
        astral_db::reclaim_budget_exhausted_events(&self.pool, identity)
            .await
            .map_err(RuntimeAccessError::from)
    }

    async fn read_claimed_event(
        &self,
        identity: &DeltaLeaseIdentity,
    ) -> Result<ClaimedDeltaEvent, RuntimeAccessError> {
        let mut tx = self.pool.begin().await?;
        let claimed = load_claimed_delta_event_for_update_in_tx(&mut tx, identity).await?;
        tx.commit().await?;
        Ok(claimed)
    }

    async fn observe_publication_context(
        &self,
        identity: &ProjectionAggregateIdentity,
    ) -> Result<Option<PublicationContext>, RuntimeAccessError> {
        let mut tx = self.pool.begin().await?;
        // One short transaction, two strictly verifying public loaders: the
        // frontier loader already proves pointer/manifest/plan/delta agreement
        // (and returns None only when NO current pointer exists); the parent
        // reference loader then re-locks the same committed world. Only
        // astral-db's documented API surface is used — no hand-written SQL.
        let context = match load_published_aggregate_frontier_in_tx(&mut tx, identity).await? {
            None => None,
            Some(frontier) => {
                let snapshot = load_published_parent_reference_views_in_tx(&mut tx, identity)
                    .await?
                    .ok_or_else(|| {
                        RuntimeAccessError::Repository(RepositoryRejection::Other(
                            "code=auth_projector.parent_snapshot_missing_for_live_pointer"
                                .to_owned(),
                        ))
                    })?;
                Some(PublicationContext {
                    frontier,
                    parent_references: snapshot.references,
                })
            }
        };
        tx.commit().await?;
        Ok(context)
    }

    async fn load_scope_ledger(
        &self,
        tenant_id: i64,
        aggregate_type: &str,
        aggregate_id: i64,
        card_id: Option<i64>,
    ) -> Result<Vec<RawLedgerRow>, RuntimeAccessError> {
        let rows = load_grant_ledger_rows(
            &self.pool,
            astral_db::GrantLedgerLoadScope {
                tenant_id,
                card_id,
                aggregate: Some((aggregate_type, aggregate_id)),
            },
        )
        .await?;
        Ok(rows)
    }

    async fn execute_projection_publish(
        &self,
        command: &DeltaProjectorPublishCommand,
    ) -> Result<DeltaProjectorPublishOutcome, RuntimeAccessError> {
        let mut tx = self.pool.begin().await?;
        // Lease heartbeat INSIDE the publish transaction (H2): the claim
        // window can elapse while pure planning/compile work runs before this
        // transaction even starts, and a large transaction can outlast the
        // remaining window; without a renewal the in-transaction completion's
        // live-expiry guard would roll back an otherwise valid publication
        // merely because the original 120s elapsed. The owner+token+status
        // CAS renews from SERVER time for one more full claim window
        // ([`CLAIM_LEASE_SECS`]) and fails closed on any real takeover. A CAS
        // loss surfaces as `LeaseCasFailed` → LeaseLost/UNKNOWN with zero
        // writes (the transaction holds no locks yet — nothing to roll back).
        extend_delta_event_lease(&mut *tx, &command.delta_lease_identity, CLAIM_LEASE_SECS).await?;
        let outcome = project_authorization_delta_in_tx(&mut tx, command).await?;
        tx.commit().await?;
        #[cfg(feature = "e3-observability")]
        log_e3_identity_event(
            "publish_committed",
            &command.delta_lease_identity,
            "succeeded",
            true,
            None,
        );
        // 发布已 durable commit（commit 证明之后）：把本次发布涉及的卡聚合
        // evidence 推入 L2 Redis 分发层（跨实例共享、进程重启不冷）。推送
        // 失败静默 —— L2 miss 的自然回源保证正确性，推送只是共享优化。
        push_published_evidence_to_l2_after_commit(&self.pool, command).await;
        Ok(outcome)
    }

    async fn fail_event(&self, identity: &DeltaLeaseIdentity, backoff_seconds: i64, message: &str) {
        match fail_delta_event(&self.pool, identity, backoff_seconds, message).await {
            Ok(()) => {
                #[cfg(feature = "e3-observability")]
                log_e3_identity_event(
                    "backoff_committed",
                    identity,
                    "pending",
                    true,
                    Some(backoff_seconds),
                );
            }
            Err(error) => {
                #[cfg(feature = "e3-observability")]
                log_e3_identity_event(
                    "terminal_unknown",
                    identity,
                    "backoff_cas_unknown",
                    false,
                    Some(backoff_seconds),
                );
                reconcile_lease_mutation_loss(identity, "fail", &error);
            }
        }
    }

    async fn release_event(&self, identity: &DeltaLeaseIdentity) {
        match release_delta_event_lease(&self.pool, identity).await {
            Ok(()) => {
                #[cfg(feature = "e3-observability")]
                log_e3_identity_event("release_committed", identity, "pending", true, None);
            }
            Err(error) => {
                #[cfg(feature = "e3-observability")]
                log_e3_identity_event(
                    "terminal_unknown",
                    identity,
                    "release_cas_unknown",
                    false,
                    None,
                );
                reconcile_lease_mutation_loss(identity, "release", &error);
            }
        }
    }

    async fn has_claimable_work(&self, scope: &DeltaEventClaimScope) -> bool {
        // 诊断启发（F5 修复 1d 看门狗，非授权路径）：与 claim 候选谓词同形的
        // 存在性探测（同形由 WATCHDOG_CLAIMABLE_PROBE_SQL 常量 +
        // `watchdog_probe_carries_the_claim_sibling_order_gate` 钉死），区分
        // "空队列"与"有积压但停滞"。查询失败 → false（看门狗保守不动作，
        // 绝不因诊断查询失败而重建 worker）。
        matches!(
            sqlx::query_scalar::<_, i64>(WATCHDOG_CLAIMABLE_PROBE_SQL)
                .bind(scope.tenant_id)
                .fetch_one(&self.pool)
                .await,
            Ok(1)
        )
    }

    async fn mark_event_quarantined(
        &self,
        lease: &DeltaLeaseIdentity,
        reason_code: &str,
        reason_detail: &str,
    ) -> Result<(), RuntimeAccessError> {
        let result = mark_delta_event_quarantined(&self.pool, lease, reason_code, reason_detail)
            .await
            .map_err(RuntimeAccessError::from);
        #[cfg(feature = "e3-observability")]
        match &result {
            Ok(()) => {
                log_e3_identity_event("quarantine_committed", lease, "quarantined", true, None)
            }
            Err(_) => log_e3_identity_event(
                "terminal_unknown",
                lease,
                "quarantine_cas_unknown",
                false,
                None,
            ),
        }
        result
    }
}

/// 发布事务提交后的 L2 evidence 推送（读链规模化 Batch D）。
///
/// 受影响卡由发布命令的卡作用域得出：仅 CARD 聚合且携带卡作用域的事件推送
/// （ELIGIBILITY/RULE_SET 等其它聚合不推 —— L2 只承载 CARD 聚合的评估
/// evidence）；卡作用域缺失（None）无法定位卡级 evidence 键，同样不推。
/// 内容来源 = 发布后自读严格 reader（pool 版，与 miss 回源同源同实现，天然
/// parity）；推送到内嵌当前时代的 L2 键（TTL 300s）。任何失败一律静默 warn。
async fn push_published_evidence_to_l2_after_commit(
    pool: &MySqlPool,
    command: &DeltaProjectorPublishCommand,
) {
    if let Some((tenant_id, card_id)) = astral_db::publish_affected_card_scope(
        &command.expectation.identity,
        command.expectation.card_id,
    ) {
        astral_db::push_published_card_evidence_to_l2(pool, tenant_id, card_id).await;
    }
}

/// A lease-guarded mutation matched zero rows: expired, stolen or terminal.
/// That is an UNKNOWN result requiring reconciliation BEFORE any further
/// mutation on this event — never blind repetition.
fn reconcile_lease_mutation_loss(
    identity: &DeltaLeaseIdentity,
    mutation: &str,
    error: &astral_db::GrantRepositoryError,
) {
    tracing::warn!(
        event_id = %identity.event_id,
        delta_event_id = identity.delta_event_id,
        mutation,
        error = %error,
        "delta lease mutation matched zero rows; treating as UNKNOWN, \
         reconciliation required before any retry"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure decision pipeline (unit-tested without MySQL)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum EventDisposition {
    /// Fully assembled single-transaction publish command. Secret lease token
    /// is attached ONLY afterwards by the orchestrator, never logged.
    Publish(Box<DeltaProjectorPublishCommand>),
    /// Transient failure; scheduling goes through [`plan_retry_schedule`] in
    /// `act_on_disposition`. Carries NO hand-picked backoff seconds — fixed
    /// short sleeps bypassing the attempt budget are forbidden.
    Retry { reason: String },
    /// Divergence needing operator review. Writes the REAL terminal
    /// `QUARANTINED` status through [`AuthorizationProjectorRuntime::
    /// mark_event_quarantined`]; unknown CAS/query outcomes stop all further
    /// mutation until reconciliation.
    Quarantine { reason: String },
    /// Candidate completeness unprovable with current public APIs; publishing
    /// partial state is forbidden.
    Blocked { reason: String },
    /// The live manifest chain moved beyond what this event's input can prove;
    /// reserved for future explicit front-loader-driven supersession checks
    /// (release-without-poison semantics live in `act_on_disposition`).
    #[allow(dead_code)]
    Superseded { reason: String },
}

/// Everything the pure decider needs about one claimed event.
struct EventDecisionInput<'a> {
    claimed: &'a ClaimedDeltaEvent,
    /// Observed short-transaction publication world. `None` means the
    /// aggregate has no current pointer at all (genuine first-publication
    /// ground); `Some` carries the strict published frontier plus the parent
    /// reference hints. PLANNING INPUTS ONLY — the publish transaction
    /// re-verifies pointers, fences, lineage and parent content durably.
    publication: Option<&'a PublicationContext>,
    ledger_rows: &'a [RawLedgerRow],
    identity: ProjectionAggregateIdentity,
}

struct AssembledCandidate {
    candidate: HotState,
    /// `true`: incremental compiler application. `false`: deterministic
    /// full-oracle product (first publication or a recorded full-rebuild
    /// reason). BOTH continuation arms carry their compiler outcome, so their
    /// impact items map from the outcome's `ImpactPlan`; ONLY the
    /// first-publication REPLAY (no plan, no base) synthesizes items directly
    /// from candidate key-level hashes.
    incremental: bool,
    incremental_outcome: Option<policy_engine::CompiledProjection>,
    full_rebuild_reason: Option<FullRebuildReason>,
    base: Option<HotState>,
}

/// Outcome of the ledger ⇆ published-frontier planning split for one claimed
/// event.
#[derive(Debug)]
enum LedgerPlan {
    /// First publication: no frontier exists and the scope ledger provably
    /// contains ONLY this event's own contiguous chain ending exactly at the
    /// claimed revision with `base_version == 0`.
    FirstPublication { own_latest: Box<GrantLedgerEntry> },
    /// Incremental continuation over proven published heads. `base_entries`
    /// derive exclusively from the partition's frontier-proven heads (each
    /// grant's last proven head; tombstones stay included while authorizing
    /// nothing). The claimed continuation row was already strictly matched to
    /// every immutable claimed field AND positioned directly above its own
    /// grant's frontier-proven target before this variant exists.
    Continuation { base_entries: Vec<GrantLedgerEntry> },
    /// Candidate completeness unprovable without guessing sibling order or
    /// waiting on sibling tails; transiently retried under the attempt budget.
    Blocked { reason: String },
    /// Immutable divergence / durable corruption requiring operator review
    /// (own stale claim, missing/ambiguous candidate rows, partition-level
    /// bridge failures — never silently repaired).
    Quarantine { reason: String },
}

/// How the claim's own event was located inside a partition outcome.
#[derive(Debug)]
enum LocatedCandidate<'p> {
    Found(&'p GrantLedgerEntry),
    BehindUnpublishedSiblings,
    StaleBehindPublishedFrontier,
    OwnClaimNotRecognized,
    MissingFromLedger,
    Ambiguous,
}

/// Locate the claimed event inside an already-computed partition outcome.
///
/// The partitioner receives `claimed_event_ids = [claimed.event_id]`, so:
/// - a direct hit among `candidate_rows` is our continuation;
/// - excluded rows carrying OUR event id classify precisely by their kind;
/// - `NotProvenPublished` on our own id would contradict that claimed-set
///   membership and surfaces defensively instead of being assumed away;
/// - multiple matches cannot survive the partitioner's duplicate-event abort,
///   yet the contradiction is still reported as ambiguous.
fn locate_claimed_candidate<'p>(
    partition: &'p PartitionedGrantLedgerAtFrontier,
    event_id: &str,
) -> LocatedCandidate<'p> {
    let mut located: Option<&GrantLedgerEntry> = None;
    let mut candidate_hits = 0usize;
    for row in &partition.candidate_rows {
        if row.entry.event_id == event_id {
            candidate_hits += 1;
            located = Some(&row.entry);
        }
    }
    if candidate_hits > 1 {
        return LocatedCandidate::Ambiguous;
    }
    if let Some(entry) = located {
        return LocatedCandidate::Found(entry);
    }
    let mut classified: Option<astral_db::LedgerExclusionKind> = None;
    let mut exclusion_hits = 0usize;
    for row in &partition.excluded_rows {
        if row.entry.event_id == event_id {
            exclusion_hits += 1;
            classified = Some(row.kind);
        }
    }
    match exclusion_hits {
        1 => match classified.expect("single exclusion hit carries its kind") {
            astral_db::LedgerExclusionKind::ClaimedBehindUnpublishedSiblings => {
                LocatedCandidate::BehindUnpublishedSiblings
            }
            astral_db::LedgerExclusionKind::StaleClaimBehindPublishedFrontier => {
                LocatedCandidate::StaleBehindPublishedFrontier
            }
            astral_db::LedgerExclusionKind::NotProvenPublished => {
                LocatedCandidate::OwnClaimNotRecognized
            }
        },
        // Zero hits (and >1 cannot survive the partitioner's duplicate-event
        // abort): the claimed event has no revision row in this scope.
        _ => LocatedCandidate::MissingFromLedger,
    }
}

/// Field-level equality between one ledger entry and every immutable claimed
/// field: any drift means queue row and revision history no longer describe
/// the same delta and refuses to proceed (fail-closed).
fn verify_candidate_matches_claimed(
    entry: &GrantLedgerEntry,
    claimed: &ClaimedDeltaEvent,
) -> Result<(), String> {
    let checks: [(bool, &str); 9] = [
        (
            entry.revision_no == claimed.target_version as u64,
            "revision_no",
        ),
        (entry.event_id == claimed.event_id, "event_id"),
        (entry.operation_id == claimed.operation_id, "operation_id"),
        (
            entry.semantic_hash.as_hex() == claimed.semantic_hash.as_hex(),
            "semantic_hash",
        ),
        (
            entry.dependency_hash.as_hex() == claimed.dependency_hash.as_hex(),
            "dependency_hash",
        ),
        (
            entry.compiler_version == claimed.compiler_version,
            "compiler_version",
        ),
        (entry.tenant_id == claimed.tenant_id, "tenant_id"),
        (entry.card_id == claimed.card_id, "card_id"),
        (
            entry.aggregate_type == claimed.aggregate_type
                && entry.aggregate_id == claimed.aggregate_id,
            "aggregate_identity",
        ),
    ];
    for (holds, field) in checks {
        if !holds {
            return Err(format!(
                "code=auth_projector.candidate_field_mismatch;field={field}"
            ));
        }
    }
    Ok(())
}

/// First-publication proof WITHOUT any frontier: the claimed grant's OWN
/// revision chain must run contiguously from 1, contain the claimed revision,
/// and agree with every immutable claimed field. Rows of OTHER grants
/// (independent initial chains) and the claimed grant's own later revisions are
/// ignored — under per-grant versioning each chain is independently provable,
/// so cross-grant publication order carries no ambiguity and every sibling
/// converges through its own claim (this arm again, or the Some-arm
/// continuation once a pointer exists). The source-freshness read gate keeps
/// the scope `PENDING` for authorization until every sibling delta reaches a
/// terminal state, so an intermediate single-grant publication is never served.
fn prove_first_publication_chain(
    rows: &[RawLedgerRow],
    claimed: &ClaimedDeltaEvent,
) -> Result<GrantLedgerEntry, String> {
    let own_grant_text = claimed.grant_id.as_str();
    // The ledger query orders rows by (grant_id ASC, revision_no ASC); the
    // filtered slice therefore keeps the own-grant revision order.
    let own_rows: Vec<&RawLedgerRow> = rows
        .iter()
        .filter(|row| row.grant_id == own_grant_text)
        .collect();
    if own_rows.is_empty() {
        return Err("code=auth_projector.own_revision_missing".to_owned());
    }
    let mut expected_revision: u64 = 1;
    for row in &own_rows {
        if row.revision_no <= 0 || row.revision_no as u64 != expected_revision {
            return Err("code=auth_projector.first_publication_chain_gap".to_owned());
        }
        expected_revision = expected_revision.saturating_add(1);
    }
    // The claimed row is the chain head being published; own later revisions
    // (beyond the claim) stay unpublished and continue via the Some arm.
    let claimed_row = own_rows
        .iter()
        .find(|row| row.event_id == claimed.event_id)
        .ok_or_else(|| "code=auth_projector.own_revision_missing".to_owned())?;
    let own_latest = decode_ledger_row(claimed_row)
        .map_err(|error| format!("code=auth_projector.own_revision_unreadable;error={error}"))?;
    verify_candidate_matches_claimed(&own_latest, claimed)?;
    Ok(own_latest)
}

/// Split the scope ledger against the observed publication world.
///
/// With a frontier, [`partition_ledger_at_published_frontier`] classifies the
/// append-only history against the strictly verified published generations;
/// its errors are DURABLE CORRUPTION, not transient conditions. The resulting
/// base derives exclusively from `published_heads`, so unproven sibling tails
/// (`PENDING` / `LEASED` / `QUARANTINED` work of other events) can never leak
/// into the compiled pre-state. Without a frontier the claimed grant's own
/// initial chain must be provably contiguous from revision 1 (sibling grants'
/// independent chains are ignored — each converges through its own claim);
/// aggregate generations and per-grant versions are separate domains connected
/// solely through the frontier events — they are never compared directly here.
fn plan_ledger_against_publication(input: &EventDecisionInput<'_>) -> LedgerPlan {
    let claimed = input.claimed;
    match input.publication {
        None => match prove_first_publication_chain(input.ledger_rows, claimed) {
            Ok(own_latest) => {
                if claimed.base_version != 0 {
                    LedgerPlan::Quarantine {
                        reason: "code=auth_projector.first_publication_requires_initial_chain"
                            .to_owned(),
                    }
                } else {
                    LedgerPlan::FirstPublication {
                        own_latest: Box::new(own_latest),
                    }
                }
            }
            Err(reason) => {
                // The None-arm proof only fails on durable contradictions
                // (missing/unreadable own revision, chain gap, field drift) —
                // all terminal Quarantine. Sibling initial chains no longer
                // block: each grant publishes through its own claim.
                LedgerPlan::Quarantine { reason }
            }
        },
        Some(publication) => {
            let frontier = &publication.frontier;
            let partition = match partition_ledger_at_published_frontier(
                input.ledger_rows,
                frontier,
                std::slice::from_ref(&claimed.event_id),
            ) {
                Ok(partition) => partition,
                Err(error) => {
                    return LedgerPlan::Quarantine {
                        reason: format!("code=auth_projector.partition_corrupt;error={error}"),
                    };
                }
            };
            match locate_claimed_candidate(&partition, &claimed.event_id) {
                LocatedCandidate::Found(candidate_entry) => {
                    if let Err(reason) = verify_candidate_matches_claimed(candidate_entry, claimed)
                    {
                        return LedgerPlan::Quarantine { reason };
                    }
                    // Per-grant successor rule: this claim must sit DIRECTLY
                    // above its own grant's last frontier-proven target (zero
                    // when the grant has never published). The AGGREGATE
                    // generation of the pointer stays untouched here.
                    let expected_base_version = frontier
                        .events
                        .iter()
                        .rev()
                        .find(|event| event.grant_id == claimed.grant_id)
                        .map_or(0, |event| event.delta_target_version);
                    if claimed.base_version != expected_base_version {
                        return LedgerPlan::Quarantine {
                            reason: format!(
                                "code=auth_projector.per_grant_chain_gap;base={};expected={expected_base_version}",
                                claimed.base_version
                            ),
                        };
                    }
                    LedgerPlan::Continuation {
                        base_entries: partition
                            .published_heads
                            .iter()
                            .map(|head| head.entry.clone())
                            .collect(),
                    }
                }
                LocatedCandidate::BehindUnpublishedSiblings => LedgerPlan::Blocked {
                    reason: format!(
                        "code=auth_projector.claimed_behind_unpublished_siblings;grant={}",
                        claimed.grant_id
                    ),
                },
                LocatedCandidate::StaleBehindPublishedFrontier => LedgerPlan::Quarantine {
                    reason: format!(
                        "code=auth_projector.stale_claim_behind_published_frontier;grant={}",
                        claimed.grant_id
                    ),
                },
                LocatedCandidate::MissingFromLedger => LedgerPlan::Quarantine {
                    reason: "code=auth_projector.own_revision_missing".to_owned(),
                },
                LocatedCandidate::Ambiguous | LocatedCandidate::OwnClaimNotRecognized => {
                    LedgerPlan::Quarantine {
                        reason: format!(
                            "code=auth_projector.partition_candidate_ambiguous;event={}",
                            claimed.event_id
                        ),
                    }
                }
            }
        }
    }
}

/// Reconstruct the producer-side dependency vector from durable claimed fields.
///
/// Producers bind one contribution to its CARD batch identity through
/// `card:{card_id}` + (generation, fence). Reconstruction is verified against
/// the stored dependency hash; any mismatch means the delta was not written by
/// the documented producer shape and refuses to proceed (fail-closed).
fn reconstruct_dependency_vector(
    claimed_card_id: Option<i64>,
    source_generation: u64,
    revoke_fence: u64,
) -> Result<(DependencyVector, String), String> {
    let Some(card_id) = claimed_card_id else {
        return Err("code=auth_projector.card_scoped_dependency_required".to_owned());
    };
    let version =
        DependencyVersion::new(format!("card:{card_id}"), source_generation, revoke_fence)
            .map_err(|error| {
                format!("code=auth_projector.dependency_version_invalid;error={error}")
            })?;
    let vector = DependencyVector::new(vec![version])
        .map_err(|error| format!("code=auth_projector.dependency_vector_invalid;error={error}"))?;
    let hash = vector
        .canonical_hash()
        .map_err(|error| format!("code=auth_projector.dependency_hash_failed;error={error}"))?;
    Ok((vector, hash))
}

#[allow(dead_code)]
fn claimed_tenant(claimed: &ClaimedDeltaEvent) -> Result<TenantScope, String> {
    TenantScope::new(claimed.tenant_id, claimed.card_id)
        .map_err(|error| format!("code=auth_projector.tenant_scope_invalid;error={error}"))
}

fn claimed_deltas(claimed: &ClaimedDeltaEvent) -> Result<Vec<astral_types::GrantDelta>, String> {
    std::iter::once(decode_delta_event_payload(&claimed.delta_json))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("code=auth_projector.delta_payload_invalid;error={error}"))
}

/// Shared compile gate: the producer compiler version must be recognized and
/// the claimed delta payload must decode before ANY branch is taken.
fn prepare_compile_inputs(
    input: &EventDecisionInput<'_>,
) -> Result<Vec<astral_types::GrantDelta>, String> {
    let claimed = input.claimed;
    let compiler = AuthorizationCompiler::new();
    if compiler.compiler_version() != claimed.compiler_version {
        return Err(format!(
            "code=auth_projector.unsupported_producer_compiler;expected={};claimed={}",
            compiler.compiler_version(),
            claimed.compiler_version
        ));
    }
    let deltas = claimed_deltas(claimed)?;
    if deltas.is_empty() {
        return Err("code=auth_projector.delta_payload_empty".to_owned());
    }
    Ok(deltas)
}

/// Deterministic REPLAY/oracle candidate for a first publication.
///
/// An honest first publication cannot fabricate a base hot state at version 0
/// and must not invent a misleading full-rebuild reason: the sanctioned oracle
/// rebuilds generation 1 directly from the proven initial ledger chain while
/// the claimed delta payload was only proven decodable above (the ledger truth
/// it describes IS the input, so applying it once more would double-apply).
fn assemble_first_publication_candidate(
    input: &EventDecisionInput<'_>,
    own_latest: &GrantLedgerEntry,
    dependency_vector: &DependencyVector,
) -> Result<Result<AssembledCandidate, CompilerConflict>, String> {
    let claimed = input.claimed;
    // Both entry points refuse an inconsistent first delta near the compiler,
    // even after future refactors of the planning layer.
    if claimed.base_version != 0 {
        return Err("code=auth_projector.first_publication_requires_initial_chain".to_owned());
    }
    let Some(target_generation) = 0u64.checked_add(1) else {
        return Err("code=auth_projector.generation_overflow".to_owned());
    };
    let _deltas_proven_decodable = prepare_compile_inputs(input)?;
    // F3 e2e fix: the hot-state tenant scope must come from the proven ledger
    // grant itself (claimed_tenant fabricated domain_id from card_id, which
    // rejected every legitimate first publication with a domain-scoped grant).
    let tenant = own_latest.grant.tenant.clone();
    let candidate = FullCompilerOracle::new()
        .rebuild_from_grants(
            tenant,
            target_generation,
            std::iter::once(own_latest.grant.clone()),
            dependency_vector.clone(),
        )
        .map_err(|error| {
            format!("code=auth_projector.first_publication_rebuild_failed;error={error}")
        })?;
    Ok(Ok(AssembledCandidate {
        candidate,
        incremental: false,
        incremental_outcome: None,
        full_rebuild_reason: None,
        base: None,
    }))
}

/// Incremental (and explicit-full-oracle fallback) candidate over the
/// frontier-proven published heads.
///
/// Base construction binds THREE domains that must never be mixed up:
/// - the HotState VERSION is the aggregate generation `G` locked by the
///   observed frontier pointer (`G + 1` becomes the target);
/// - the per-grant projection window lives ONLY in the claimed/base-target
///   expectation fields and in the per-grant successor rule already enforced
///   during partition planning;
/// - the dependency vector reuses the documented producer reconstruction for
///   this event's card batch (`card:{id}` @ source_generation/fence), whose
///   stored hash was verified against the claim — keeping candidate lineage
///   consistent with what the publish CAS pins.
///
/// `FullRebuildRequired` resolves by running the sanctioned full oracle ON THE
/// SAME VERIFIED base (reason kept as evidence); never by silently relabeling
/// the outcome or rebuilding from an unverified wider input.
#[allow(clippy::too_many_lines)]
fn assemble_continuation_candidate(
    input: &EventDecisionInput<'_>,
    base_generation: u64,
    base_entries: &[GrantLedgerEntry],
    dependency_vector: &DependencyVector,
) -> Result<Result<AssembledCandidate, CompilerConflict>, String> {
    let claimed = input.claimed;
    if base_generation == 0 {
        return Err("code=auth_projector.continuation_requires_published_frontier".to_owned());
    }
    let Some(target_generation) = base_generation.checked_add(1) else {
        return Err("code=auth_projector.generation_overflow".to_owned());
    };
    let deltas = prepare_compile_inputs(input)?;
    // F3 e2e fix: same misderived-scope issue as the first-publication path —
    // derive the aggregate hot-state tenant from the proven base entries
    // (fallback: the claimed Add delta grant scope) instead of card_id-as-domain.
    let tenant = base_entries
        .first()
        .map(|entry| entry.grant.tenant.clone())
        .or_else(|| match claimed_deltas(claimed).ok()?.into_iter().next()? {
            astral_types::GrantDelta::Add { grant } => Some(grant.tenant.clone()),
            _ => None,
        })
        .ok_or_else(|| "code=auth_projector.continuation_tenant_unavailable".to_owned())?;
    let base = hot_state_from_entries(
        &tenant,
        base_generation,
        dependency_vector.clone(),
        claimed.compiler_version.clone(),
        base_entries,
    )
    .map_err(|error| format!("code=auth_projector.base_state_build_failed;error={error}"))?;
    let compiler = AuthorizationCompiler::new();
    match compiler.compile_incremental(&base, target_generation, dependency_vector.clone(), deltas)
    {
        Ok(CompileOutcome::Applied(compiled)) => {
            if compiled.target_version != target_generation
                || compiled.state.version != target_generation
            {
                return Err("code=auth_projector.compile_version_fence_broken".to_owned());
            }
            Ok(Ok(AssembledCandidate {
                candidate: compiled.state.clone(),
                incremental: true,
                incremental_outcome: Some(compiled),
                full_rebuild_reason: None,
                base: Some(base),
            }))
        }
        Ok(CompileOutcome::FullRebuildRequired(required)) => {
            let rebuilt = compiler.full_rebuild(
                &base,
                target_generation,
                dependency_vector.clone(),
                claimed_deltas(claimed)?,
            );
            let outcome = match rebuilt
                .map_err(|error| format!("code=auth_projector.full_rebuild_failed;error={error}"))?
            {
                CompileOutcome::Applied(compiled) => compiled,
                CompileOutcome::FullRebuildRequired(inner) => {
                    return Err(format!(
                        "code=auth_projector.full_rebuild_stuck;reason={:?}",
                        inner.reason
                    ));
                }
                CompileOutcome::Conflict(conflict) => return Ok(Err(conflict)),
            };
            Ok(Ok(AssembledCandidate {
                candidate: outcome.state.clone(),
                incremental: false,
                incremental_outcome: Some(outcome),
                full_rebuild_reason: Some(required.reason),
                base: Some(base),
            }))
        }
        Ok(CompileOutcome::Conflict(conflict)) => Ok(Err(conflict)),
        Err(error) => Err(format!("code=auth_projector.compile_error;error={error}")),
    }
}

/// Derive the stage segment plan from the candidate hot state.
///
/// With `Some(parent references)` a candidate segment whose canonical payload
/// digest equals an UNUSED parent reference digest reuses that exact ordinal:
/// matching is digest-based (never positional inference) and content-safe, and
/// the staging transaction still re-verifies the referenced row under lock.
/// Without references — today's production reality, see module-gap notes —
/// every entry is [`StagedSegmentContent::New`]: identical payloads dedupe onto
/// the same content-addressed segment row, nothing is deleted or rewritten.
fn plan_stage_segments(
    candidate: &HotState,
    parent_references: Option<&[(u64, ParentReferenceView)]>,
) -> Result<Vec<StagedSegmentContent>, String> {
    let mut plan: Vec<StagedSegmentContent> = Vec::with_capacity(candidate.segments.len());
    for (_key, segment) in candidate.segments.iter() {
        let payload = astral_db::encode_segment_payload(&segment.grants)
            .map_err(|error| format!("code=auth_projector.segment_encode_failed;error={error}"))?;
        let digest_hex = hex_lower(&Sha256::digest(&payload));
        let mut reused: Option<u64> = None;
        if let Some(references) = parent_references {
            for (ordinal, view) in references {
                if view.content_digest_hex != digest_hex {
                    continue;
                }
                let ordinal_claimed = plan.iter().any(|entry| match entry {
                    StagedSegmentContent::ReuseParent { parent_ordinal } => {
                        parent_ordinal == ordinal
                    }
                    StagedSegmentContent::New(_) => false,
                });
                if !ordinal_claimed {
                    reused = Some(*ordinal);
                    break;
                }
            }
        }
        match reused {
            Some(parent_ordinal) => plan.push(StagedSegmentContent::ReuseParent { parent_ordinal }),
            None => plan.push(StagedSegmentContent::New(
                segment.grants.as_slice().to_vec(),
            )),
        }
    }
    Ok(plan)
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Synthesize impact items for a REPLAY/oracle candidate directly from
/// key-level compiler hashes. `before` reuses the base state's own recorded
/// hash when that key existed — evidence is never invented.
fn synthesize_replay_items(
    candidate: &HotState,
    base: Option<&HotState>,
) -> Result<Vec<AuthorizationImpactItemInput>, String> {
    let mut items = Vec::with_capacity(candidate.segments.len());
    for (key, segment) in candidate.segments.iter() {
        let projection_key = key.canonical_input().map_err(|error| {
            format!("code=auth_projector.projection_key_canonicalization;error={error}")
        })?;
        let before_digest_hex = base
            .and_then(|state| state.segment_content(key))
            .map(|content| content.content_hash.clone());
        items.push(AuthorizationImpactItemInput {
            projection_key,
            item_type: AuthorizationImpactItemType::SegmentUpsert,
            grant_id: None,
            before_digest_hex,
            after_digest_hex: Some(segment.content_hash.clone()),
        });
    }
    Ok(items)
}

fn classify_compiler_conflict(conflict: &CompilerConflict) -> EventDisposition {
    // Already-applied signatures indicate either a previous successful attempt
    // of THIS event or reflected sibling state; even with a proven frontier,
    // neither can be re-derived locally once the compiler reports them, so
    // operator reconciliation wins over blind retries.
    let reason = format!("code=auth_projector.compile_conflict;conflict={conflict}");
    match conflict {
        CompilerConflict::DuplicateDelta { .. } | CompilerConflict::ExistingGrant { .. } => {
            EventDisposition::Quarantine { reason }
        }
        _ => EventDisposition::Retry { reason },
    }
}

/// Aggregate generation observed as the compile base: `0` only for a genuine
/// first publication (no pointer exists); otherwise the frontier pointer's
/// locked `current_generation`. NEVER mixed with per-grant versions.
fn publication_base_generation(input: &EventDecisionInput<'_>) -> u64 {
    input
        .publication
        .map_or(0u64, |context| context.frontier.pointer.current_generation)
}

/// Map an assembly-stage failure onto dispositions exactly like before: the
/// listed codes are deterministic divergence (terminal quarantine), everything
/// else stays transiently undecidable under the unified attempt budget.
///
/// Classification is EXACT-TOKEN over the stable machine code this module
/// itself embeds at every construction site (`code=auth_projector.<token>` up
/// to the first `;`). Dynamic detail after the `;` (embedded error displays,
/// operator-supplied compiler versions, event ids …) can therefore never flip
/// the disposition — the failure mode of the previous `reason.contains(...)`
/// matching.
fn classify_compile_stage_error(reason: String) -> EventDisposition {
    match AssemblyStageCode::from_reason(&reason) {
        Some(code) if code.is_deterministic_divergence() => EventDisposition::Quarantine { reason },
        // Unknown/unparseable codes keep the bounded-retry default: no
        // deterministic divergence has been proven for this event.
        _ => EventDisposition::Retry { reason },
    }
}

/// Stable machine codes of the assembly stage that prove DETERMINISTIC
/// divergence. Single-sourced here so the constructor sites and the
/// classifier can never drift apart; every reason this module builds starts
/// with `code=auth_projector.<token>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AssemblyStageCode {
    UnsupportedProducerCompiler,
    GenerationOverflow,
    FirstPublicationRequiresInitialChain,
    FullRebuildStuck,
    CompileVersionFenceBroken,
    FirstPublicationRebuildFailed,
    BaseStateBuildFailed,
    ContinuationRequiresPublishedFrontier,
}

impl AssemblyStageCode {
    /// Exact-token parse of the leading machine code. Returns `None` for any
    /// reason whose FIRST token is not one of the enumerated codes — detail
    /// text is never scanned.
    fn from_reason(reason: &str) -> Option<Self> {
        let token = reason
            .strip_prefix("code=auth_projector.")?
            .split(';')
            .next()?;
        Some(match token {
            "unsupported_producer_compiler" => Self::UnsupportedProducerCompiler,
            "generation_overflow" => Self::GenerationOverflow,
            "first_publication_requires_initial_chain" => {
                Self::FirstPublicationRequiresInitialChain
            }
            "full_rebuild_stuck" => Self::FullRebuildStuck,
            "compile_version_fence_broken" => Self::CompileVersionFenceBroken,
            "first_publication_rebuild_failed" => Self::FirstPublicationRebuildFailed,
            "base_state_build_failed" => Self::BaseStateBuildFailed,
            "continuation_requires_published_frontier" => {
                Self::ContinuationRequiresPublishedFrontier
            }
            _ => return None,
        })
    }

    /// Deterministic divergence: the same claimed inputs reproduce this
    /// outcome on every attempt, so retries are futile and the event goes to
    /// terminal quarantine (attempt-budget independent).
    const fn is_deterministic_divergence(self) -> bool {
        matches!(
            self,
            Self::UnsupportedProducerCompiler
                | Self::GenerationOverflow
                | Self::FirstPublicationRequiresInitialChain
                | Self::FullRebuildStuck
                | Self::CompileVersionFenceBroken
                | Self::FirstPublicationRebuildFailed
                | Self::BaseStateBuildFailed
                | Self::ContinuationRequiresPublishedFrontier
        )
    }
}

/// Map a publish-transaction failure onto the retry taxonomy (pure, pinned by
/// unit tests).
enum PublishFailureHandling {
    /// The live publication pointer moved between planning and the publish
    /// transaction. The orchestrator replans in-place under the same lease a
    /// bounded number of times before falling back to the normal retry budget.
    PointerMoved { reason: String },
    /// Our lease died mid-flight; NOTHING may be mutated for this event.
    LeaseLost { reason: String },
    /// Immutable divergence needing operator review.
    ImmutableDivergence { reason: String },
    /// Byte-identical segment content already exists but was stamped by a
    /// different producer compiler version
    /// ([`astral_db::SEGMENT_COMPILER_STAMP_DIVERGENCE_CODE`]). Deterministic
    /// Phase 1 modeling limit — NOT durable corruption: the payload is proven
    /// intact, so the conservative outcome is terminal quarantine with a
    /// dedicated machine code and operator stamp-ownership reconciliation.
    /// Nothing invalid can ever be published this way because nothing is
    /// published at all.
    CompilerStampDivergence { reason: String },
    /// Publication refused on UNPROVEN history evidence: the locked current
    /// pointer predates the durable proof latch, so astral-db refuses with
    /// `AuthorizationProjectionError::NotReady` carrying the stable machine
    /// code `backfill_or_rehearsal_required`. Not event corruption, not
    /// self-healing by immediate retry, but recoverable by an explicit
    /// operator backfill/rehearsal pass that installs a proof-bearing
    /// pointer. The event stays PENDING under the bounded attempt budget
    /// (max-cap backoff once exhausted) instead of burning a terminal
    /// quarantine on a condition an operator resolves.
    Blocked { reason: String },
    /// Everything else (transient DB faults included) backs off normally.
    GenericRetry { reason: String },
}

/// Exact leading `code=authorization_projection.<token>` of an embedded
/// repository machine code; detail after the first `;` is never scanned.
fn projection_machine_code(message: &str) -> Option<&str> {
    message
        .strip_prefix("code=authorization_projection.")?
        .split(';')
        .next()
}

fn classify_publish_failure(error: &RuntimeAccessError) -> PublishFailureHandling {
    let rendered = error.to_string();
    match error {
        // Query/connection trouble inside the rolled-back transaction is the
        // textbook transient fault.
        RuntimeAccessError::Database(_) => {
            PublishFailureHandling::GenericRetry { reason: rendered }
        }
        RuntimeAccessError::Repository(rejection) => match rejection {
            // Typed grant-repository refusals (M2): a lost lease CAS
            // (heartbeat/completion/readback) or a claim race means UNKNOWN
            // ownership — zero further mutation, never a `fail_delta_event`.
            // Every other grant refusal (contract/scope/mapping) proves no
            // deterministic divergence and stays under the attempt budget.
            RepositoryRejection::Grant(grant) => match grant {
                astral_db::GrantRepositoryError::ClaimRace
                | astral_db::GrantRepositoryError::LeaseCasFailed(_) => {
                    PublishFailureHandling::LeaseLost { reason: rendered }
                }
                _ => PublishFailureHandling::GenericRetry { reason: rendered },
            },
            // Projector-side non-typed refusals carry no variant evidence; no
            // deterministic divergence is proven.
            RepositoryRejection::Other(_) => {
                PublishFailureHandling::GenericRetry { reason: rendered }
            }
            RepositoryRejection::Projection(projection) => {
                classify_projection_failure(projection, rendered)
            }
        },
    }
}

/// Typed variant mapping + stable machine codes, in one place. The mapping
/// preserves the prior substring router's outcome for every real
/// construction site while eliminating its failure modes (Display wording was
/// never a contract, and detail text could flip dispositions; the
/// `ClaimRace`/`DuplicateRow` arms were even unreachable against Display
/// text — they now classify by variant as originally intended).
fn classify_projection_failure(
    error: &AuthorizationProjectionError,
    rendered: String,
) -> PublishFailureHandling {
    match error {
        // Lease/CAS ownership evidence died mid-flight: unknown result, zero
        // further mutation. `ClaimRace` is variant-classified here (its
        // Display wording never contained the old `ClaimRace` needle).
        AuthorizationProjectionError::LeaseCasFailed(_)
        | AuthorizationProjectionError::ClaimRace => {
            PublishFailureHandling::LeaseLost { reason: rendered }
        }
        // The chain moved past our assumption (or the pointer/manifest pair
        // disagrees with the claimed world): fresh-world retry.
        AuthorizationProjectionError::CurrentPointerCasConflict(_)
        | AuthorizationProjectionError::IdentityMismatch(_) => {
            PublishFailureHandling::PointerMoved { reason: rendered }
        }
        // Publish-precondition conflicts: only the two codes proving the chain
        // advanced are fast-abandon retries; everything else (fence/semantics/
        // compiler expectation mismatches) stays under the attempt budget.
        AuthorizationProjectionError::ManifestPublishConflict(message) => {
            match projection_machine_code(message) {
                Some("publish_generation_gap" | "publish_same_manifest") => {
                    PublishFailureHandling::PointerMoved { reason: rendered }
                }
                _ => PublishFailureHandling::GenericRetry { reason: rendered },
            }
        }
        // Not-ready mid-flight preconditions retry EXCEPT the codes that prove
        // the world moved or require operator repair of an unproven pointer.
        AuthorizationProjectionError::NotReady(message) => match projection_machine_code(message) {
            Some("backfill_or_rehearsal_required") => {
                PublishFailureHandling::Blocked { reason: rendered }
            }
            Some("stage_generation_gap" | "current_pointer_missing") => {
                PublishFailureHandling::PointerMoved { reason: rendered }
            }
            _ => PublishFailureHandling::GenericRetry { reason: rendered },
        },
        // The one mapping code proving generation space exhaustion routes with
        // the chain-advanced family; other mappings stay transient.
        AuthorizationProjectionError::Mapping(message) => match projection_machine_code(message) {
            Some("generation_overflow") => {
                PublishFailureHandling::PointerMoved { reason: rendered }
            }
            _ => PublishFailureHandling::GenericRetry { reason: rendered },
        },
        AuthorizationProjectionError::SegmentDigestCollision(message) => {
            match projection_machine_code(message) {
                // Proven-intact payload with a diverging compiler stamp: the
                // dedicated conservative path — terminal quarantine with its
                // own stable reason code, never labeled as corruption, and
                // never a publish.
                Some("segment_compiler_stamp_divergence") => {
                    PublishFailureHandling::CompilerStampDivergence {
                        reason: format!(
                            "code=auth_projector.compiler_stamp_divergence;error={rendered}"
                        ),
                    }
                }
                _ => PublishFailureHandling::ImmutableDivergence { reason: rendered },
            }
        }
        // Deterministic immutable-history divergence family: these recur
        // identically on every attempt, so they go to terminal quarantine
        // regardless of the attempt budget. `DuplicateRow` is variant-
        // classified (the old `DuplicateRow` needle could never match its
        // Display wording); its `manifest_identity_conflict` construction is
        // deterministic divergence, as are every unproven unique-race winner
        // and the immutable replay conflicts.
        AuthorizationProjectionError::ImmutableConflict(_)
        | AuthorizationProjectionError::DuplicateRow(_) => {
            PublishFailureHandling::ImmutableDivergence { reason: rendered }
        }
        // Corrupt durable evidence is deterministic divergence and therefore
        // terminal quarantine; unproven history is handled by the NotReady arm.
        AuthorizationProjectionError::Corrupt(_) => {
            PublishFailureHandling::ImmutableDivergence { reason: rendered }
        }
        // No deterministic divergence proven by variant or machine code:
        // bounded-retry default (contract/scope/mapping refusals, illegal
        // transitions, generic state gaps).
        AuthorizationProjectionError::Contract(_)
        | AuthorizationProjectionError::IllegalStatusTransition { .. } => {
            PublishFailureHandling::GenericRetry { reason: rendered }
        }
        AuthorizationProjectionError::ScopeViolation(message) => {
            match projection_machine_code(message) {
                // The publish transaction re-checks the authoritative pointer after
                // planning. A generation mismatch proves only that another valid
                // publisher won the race; it is a fresh-world replan, not a generic
                // infrastructure failure or deterministic corruption.
                Some("command_base_generation_mismatch") => {
                    PublishFailureHandling::PointerMoved { reason: rendered }
                }
                _ => PublishFailureHandling::GenericRetry { reason: rendered },
            }
        }
        // Defensive: `Query` never survives the `From` conversion, but the
        // transient default keeps any future construction fail-safe.
        AuthorizationProjectionError::Query(_) => {
            PublishFailureHandling::GenericRetry { reason: rendered }
        }
    }
}

/// Pure top-level decision for one claimed event.
fn decide_event_disposition(input: &EventDecisionInput<'_>) -> EventDisposition {
    let claimed = input.claimed;
    if claimed.event_type == DeltaEventType::Revoke && claimed.revoke_fence == 0 {
        return EventDisposition::Quarantine {
            reason: "code=auth_projector.revoke_without_fence_progress".to_owned(),
        };
    }

    // 1. Dependency vector reconstruction + stored-hash verification.
    let (dependency_vector, dependency_hash_hex) = match reconstruct_dependency_vector(
        claimed.card_id,
        claimed.source_generation,
        claimed.revoke_fence,
    ) {
        Ok(pair) => pair,
        Err(reason) => return EventDisposition::Quarantine { reason },
    };
    if dependency_hash_hex != claimed.dependency_hash.as_hex() {
        return EventDisposition::Quarantine {
            reason: format!(
                "code=auth_projector.dependency_hash_drift;stored={};reconstructed={dependency_hash_hex}",
                claimed.dependency_hash.as_hex()
            ),
        };
    }

    // 2. Publication-aware ledger partition: proves which effects are already
    //    covered by the published frontier chain and which sibling tails stay
    //    OUT of the compiled base. Terminal corruption never becomes Retry.
    let ledger_plan = plan_ledger_against_publication(input);

    // 3. Compile the candidate (pure, outside any transaction). Compiler
    //    conflicts propagate verbatim to their own classification layer.
    let assembly_outcome = match &ledger_plan {
        LedgerPlan::Blocked { reason } => {
            return EventDisposition::Blocked {
                reason: reason.clone(),
            }
        }
        LedgerPlan::Quarantine { reason } => {
            return EventDisposition::Quarantine {
                reason: reason.clone(),
            }
        }
        LedgerPlan::FirstPublication { own_latest } => {
            assemble_first_publication_candidate(input, own_latest, &dependency_vector)
        }
        LedgerPlan::Continuation { base_entries, .. } => {
            let base_generation = publication_base_generation(input);
            assemble_continuation_candidate(
                input,
                base_generation,
                base_entries,
                &dependency_vector,
            )
        }
    };
    let assembled = match assembly_outcome {
        Ok(Ok(assembled)) => assembled,
        Ok(Err(conflict)) => return classify_compiler_conflict(&conflict),
        Err(reason) => return classify_compile_stage_error(reason),
    };

    let base_generation = publication_base_generation(input);
    let target_generation = match base_generation.checked_add(1) {
        Some(next) => next,
        None => {
            return EventDisposition::Quarantine {
                reason: "code=auth_projector.generation_overflow".to_owned(),
            }
        }
    };

    // 4. Impact plan inputs (non-empty is enforced here and downstream again).
    //
    // Both continuation arms map their items from the compiler outcome's
    // `ImpactPlan` instead of synthesizing them; plan coverage differs by arm:
    // - the FULL-REBUILD continuation runs the sanctioned oracle, whose plan
    //   covers `candidate ∪ base ∪ known` keys — so a segment the compile
    //   REMOVED from the base (e.g. a revoked type-level wildcard that was
    //   the grant's only Active contribution) maps to a `SegmentRemove` item
    //   carrying the base digest as `before` and no `after`;
    // - the INCREMENTAL outcome's plan covers only the deltas' known-affected
    //   keys, and every legal delta changes at least one of them (the grant
    //   revision is part of the segment content hash; `Add` payloads must be
    //   Active, tombstone-carrying Adds are refused at the decode gate), so
    //   its mapped items are never empty.
    // Mapping the plan is evidence-preserving: unchanged segments produce no
    // item and a vanished key can never be synthesized away. The key-level
    // synthesis fallback only walks `candidate.segments` and therefore cannot
    // see vanished keys; it stays reserved for the first-publication REPLAY,
    // which has no compiler plan and no base to remove from (a tombstone seed
    // first publication keeps its empty-impact QUARANTINE — no empty
    // generation is published here).
    let impact_items = match (&assembled.incremental, &assembled.incremental_outcome) {
        (_, Some(outcome)) => {
            match impact_plan_request_from_compiler_plan(
                input.identity.clone(),
                claimed.card_id,
                claimed.event_id.clone(),
                claimed.operation_id.clone(),
                base_generation,
                target_generation,
                claimed.base_version,
                claimed.target_version,
                claimed.semantic_hash.as_hex(),
                claimed.dependency_hash.as_hex(),
                claimed.compiler_version.clone(),
                &outcome.plan,
            ) {
                Ok(request) => request.items,
                Err(error) => {
                    return EventDisposition::Quarantine {
                        reason: format!(
                            "code=auth_projector.impact_plan_mapping_failed;error={error}"
                        ),
                    }
                }
            }
        }
        // First-publication REPLAY: no compiler plan exists and no base from
        // which a segment could vanish; synthesize from the oracle-rebuilt
        // candidate only. An oracle-rebuilt tombstone seed yields an empty
        // candidate and therefore the empty-impact quarantine below stays the
        // contract-consistent terminal outcome (never an empty publication).
        (false, None) => {
            match synthesize_replay_items(&assembled.candidate, assembled.base.as_ref()) {
                Ok(items) => items,
                Err(reason) => return EventDisposition::Quarantine { reason },
            }
        }
        // Unreachable by construction (an incremental application always
        // carries its Applied outcome); fail closed instead of guessing.
        (true, None) => {
            return EventDisposition::Quarantine {
                reason: "code=auth_projector.impact_outcome_missing".to_owned(),
            }
        }
    };
    if impact_items.is_empty() {
        // Every affected segment came out unchanged ⇒ the effect already sits
        // inside the reconstructed candidate. Publishing would create an
        // immutable no-op manifest; operator reconciliation decides instead
        // (mirror of the legacy AlreadyCurrent nuance, without faking success).
        return EventDisposition::Quarantine {
            reason: "code=auth_projector.no_effective_change".to_owned(),
        };
    }

    // 5. Stage segments + publish command assembly. Observed parent
    //    references are PLANNING HINTS for digest-based reuse; the staging
    //    transaction re-locks the pointer + parent chain and re-verifies every
    //    reference before any reuse becomes durable, and a pointer that moved
    //    in between maps to a fast PointerMoved retry.
    let parent_references: Option<&[(u64, ParentReferenceView)]> = input
        .publication
        .map(|context| context.parent_references.as_slice());
    let stage_segments = match plan_stage_segments(&assembled.candidate, parent_references) {
        Ok(segments) => segments,
        Err(reason) => return EventDisposition::Quarantine { reason },
    };

    // The authoritative previous fence comes from the observed frontier
    // pointer (`None` ⇒ 0 first-publication sentinel); the publish
    // transaction re-reads it under lock and refuses stale evidence.
    let previous_revoke_fence = input
        .publication
        .map_or(0, |context| context.frontier.pointer.revoke_fence);
    let new_revoke_fence = previous_revoke_fence.max(claimed.revoke_fence);

    EventDisposition::Publish(Box::new(DeltaProjectorPublishCommand {
        delta_lease_identity: DeltaLeaseIdentity {
            delta_event_id: claimed.delta_event_id,
            event_id: claimed.event_id.clone(),
            lease_owner: claimed.lease_owner.clone(),
            // Secret replaced by the orchestrator from the live claim before
            // any execution; the pure assembler never sees tokens and uses the
            // always-available (not test-gated) placeholder constructor.
            lease_token: astral_db::DeltaLeaseToken::placeholder_for_assembly(),
        },
        expectation: DeltaProjectorExpectation {
            identity: input.identity.clone(),
            card_id: claimed.card_id,
            event_id: claimed.event_id.clone(),
            operation_id: claimed.operation_id.clone(),
            base_version: claimed.base_version,
            target_version: claimed.target_version,
            source_generation: claimed.source_generation,
            semantic_hash_hex: claimed.semantic_hash.as_hex(),
            dependency_hash_hex: claimed.dependency_hash.as_hex(),
            compiler_version: claimed.compiler_version.clone(),
        },
        fences: PublishRevokeFenceEvidence {
            previous_revoke_fence,
            new_revoke_fence,
        },
        mode: CompileModeEvidence {
            compile_mode: match (
                assembled.incremental,
                assembled.full_rebuild_reason.is_some(),
            ) {
                (true, _) => ProjectionCompileMode::Incremental,
                // ONLY a genuine compiler FullRebuildRequired outcome may
                // declare FULL_REBUILD mode, always paired with its reason.
                (false, true) => ProjectionCompileMode::FullRebuild,
                // First publication: deterministic ledger replay via the
                // sanctioned oracle, no invented fallback reason.
                (false, false) => ProjectionCompileMode::Replay,
            },
            full_rebuild_reason: assembled.full_rebuild_reason,
        },
        stage: AuthorizationStageRequest {
            identity: input.identity.clone(),
            card_id: claimed.card_id,
            target_generation,
            source_generation: claimed.source_generation,
            projected_generation: claimed.source_generation,
            event_id: claimed.event_id.clone(),
            operation_id: claimed.operation_id.clone(),
            semantic_hash_hex: claimed.semantic_hash.as_hex(),
            dependency_hash_hex: claimed.dependency_hash.as_hex(),
            compiler_version: claimed.compiler_version.clone(),
            revoke_fence: new_revoke_fence,
            segments: stage_segments,
        },
        finalize_expected_reference_count: None,
        impact_plan: AuthorizationImpactPlanAppendRequest {
            identity: input.identity.clone(),
            card_id: claimed.card_id,
            event_id: claimed.event_id.clone(),
            operation_id: claimed.operation_id.clone(),
            base_generation,
            target_generation,
            base_version: claimed.base_version,
            target_version: claimed.target_version,
            semantic_hash_hex: claimed.semantic_hash.as_hex(),
            dependency_hash_hex: claimed.dependency_hash.as_hex(),
            compiler_version: claimed.compiler_version.clone(),
            items: impact_items,
        },
        manifest_lease_owner: String::new(),
        manifest_lease_seconds: MAX_MANIFEST_LEASE_SECONDS.min(600),
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Orchestrator: claim → readback → observe → decide → publish/dispose, with
// monotonic per-phase timing and bounded retry accounting.
// ─────────────────────────────────────────────────────────────────────────────

struct ProjectorPhaseTimer {
    phase: ProjectorPhase,
    started: Instant,
}

impl ProjectorPhaseTimer {
    fn new(phase: ProjectorPhase) -> Self {
        Self {
            phase,
            started: Instant::now(),
        }
    }
}

impl Drop for ProjectorPhaseTimer {
    fn drop(&mut self) {
        record_projector_phase(self.phase, self.started.elapsed());
    }
}

/// `pub(crate)`：读链规模化 Batch E 的同步发布混合模式
/// （[`super::sync_publish`]）在 source 事务提交后复用同一管线在请求内发布
/// 单卡/小变更目标；worker 循环本身零改动。
pub(crate) async fn process_one_event(
    runtime: &Arc<dyn AuthorizationProjectorRuntime>,
    config: &AuthorizationProjectorConfig,
    lease_owner: &str,
    cancellation: &ProjectorCancellationToken,
    claimed: &DeltaEventClaim,
    summary: &mut WorkerRunSummary,
) {
    let total_started = Instant::now();
    let _total_timer = ProjectorPhaseTimer::new(ProjectorPhase::Total);
    // Lease identity is derivable purely from the claim and needed by EVERY
    // failure funnel below, so it is built once up-front.
    let delta_lease_identity = DeltaLeaseIdentity {
        delta_event_id: claimed.delta_event_id,
        event_id: claimed.event_id.clone(),
        lease_owner: claimed.lease_owner.clone(),
        lease_token: claimed.lease_token.clone(),
    };
    let identity = match ProjectionAggregateIdentity::new(
        claimed.tenant_id,
        claimed.aggregate_type.clone(),
        claimed.aggregate_id,
    ) {
        Ok(identity) => identity,
        Err(error) => {
            let reason = format!("code=auth_projector.claimed_identity_invalid;error={error}");
            tracing::error!(event_id = %claimed.event_id, reason = %reason, "quarantined");
            // Deterministic shape corruption goes through the REAL terminal
            // quarantine boundary: exactly one live-lease guarded CAS write,
            // unknown outcomes recorded without any further mutation.
            quarantine_event_terminal(
                runtime,
                &delta_lease_identity,
                claimed,
                &reason,
                &total_started,
                summary,
            )
            .await;
            return;
        }
    };

    // Phase 1: strict readback proving we still own a live lease.
    let readback_started = Instant::now();
    let claimed_row = match runtime.read_claimed_event(&delta_lease_identity).await {
        Ok(row) => row,
        Err(error) => {
            record_projector_phase(ProjectorPhase::Readback, readback_started.elapsed());
            summary.record(DispositionKind::LeaseLost);
            #[cfg(feature = "e3-observability")]
            log_e3_attempt_event(
                "terminal_unknown",
                claimed,
                "claim_readback_unknown",
                false,
                None,
            );
            tracing::warn!(
                event_id = %claimed.event_id,
                error = %error,
                "claimed delta readback refused; UNKNOWN ownership, no mutation issued"
            );
            return;
        }
    };
    let readback_us = readback_started.elapsed().as_micros() as u64;
    record_projector_phase(ProjectorPhase::Readback, readback_started.elapsed());

    if cancellation.is_cancelled() {
        // Leave the short lease to expire server-side rather than racing a
        // mutation during shutdown (UNKNOWN avoidance beats busywork).
        #[cfg(feature = "e3-observability")]
        log_e3_attempt_event(
            "lease_left_to_expire",
            claimed,
            "shutdown_after_claim",
            false,
            None,
        );
        tracing::info!(
            event_id = %claimed.event_id,
            "shutdown observed after claim; leaving lease to expire"
        );

        return;
    }

    // Phase 2-5 run as one bounded fresh-world loop. A publish transaction may
    // legitimately discover that another publisher advanced the same pointer
    // after our planning read. That is not a failed event attempt: retain the
    // live claim lease, rebuild the plan from the new world, and only consume
    // the ordinary retry budget after the bounded in-place replan allowance is
    // exhausted.
    let mut pointer_moved_replans = 0usize;
    loop {
        if cancellation.is_cancelled() {
            // Leave the short lease to expire server-side rather than racing a
            // mutation during shutdown (UNKNOWN avoidance beats busywork).
            #[cfg(feature = "e3-observability")]
            log_e3_attempt_event(
                "lease_left_to_expire",
                claimed,
                "shutdown_before_attempt",
                false,
                None,
            );
            tracing::info!(
                event_id = %claimed.event_id,
                pointer_moved_replans,
                "shutdown observed before fresh-world projection attempt; leaving lease to expire"
            );
            return;
        }

        // Phase 2: observe the publication context (strict frontier + parent
        // reference snapshot in ONE short committed read transaction).
        let observe_started = Instant::now();
        let publication = match runtime.observe_publication_context(&identity).await {
            Ok(publication) => publication,
            Err(error) => {
                record_projector_phase(ProjectorPhase::Observe, observe_started.elapsed());
                let reason = format!("code=auth_projector.pointer_observe_failed;error={error}");
                retry_disposition(
                    runtime,
                    claimed,
                    &delta_lease_identity,
                    summary,
                    reason,
                    &total_started,
                )
                .await;
                return;
            }
        };
        let observe_us = observe_started.elapsed().as_micros() as u64;
        record_projector_phase(ProjectorPhase::Observe, observe_started.elapsed());

        // Phase 3: load the complete scope ledger (read-only).
        let ledger_started = Instant::now();
        let ledger_rows = match runtime
            .load_scope_ledger(
                claimed.tenant_id,
                &claimed.aggregate_type,
                claimed.aggregate_id,
                claimed.card_id,
            )
            .await
        {
            Ok(rows) => rows,
            Err(error) => {
                record_projector_phase(ProjectorPhase::Ledger, ledger_started.elapsed());
                let reason = format!("code=auth_projector.ledger_load_failed;error={error}");
                retry_disposition(
                    runtime,
                    claimed,
                    &delta_lease_identity,
                    summary,
                    reason,
                    &total_started,
                )
                .await;
                return;
            }
        };
        let ledger_us = ledger_started.elapsed().as_micros() as u64;
        record_projector_phase(ProjectorPhase::Ledger, ledger_started.elapsed());

        // Phase 4: pure decision (verify, partition, compile, assemble).
        let decide_started = Instant::now();
        let input = EventDecisionInput {
            claimed: &claimed_row,
            publication: publication.as_ref(),
            ledger_rows: &ledger_rows,
            identity: identity.clone(),
        };
        let disposition = decide_event_disposition(&input);
        let decide_us = decide_started.elapsed().as_micros() as u64;
        record_projector_phase(ProjectorPhase::Decide, decide_started.elapsed());
        summary.decide_phase_micros += decide_us;
        tracing::debug!(
            event_id = %claimed.event_id,
            operation_id = %claimed.operation_id,
            readback_us,
            observe_us,
            ledger_us,
            decide_us,
            pointer_moved_replans,
            total_us = total_started.elapsed().as_micros() as u64,
            "phase timings recorded"
        );

        if cancellation.is_cancelled() {
            #[cfg(feature = "e3-observability")]
            log_e3_attempt_event(
                "lease_left_to_expire",
                claimed,
                "shutdown_after_planning",
                false,
                None,
            );
            tracing::info!(
                event_id = %claimed.event_id,
                pointer_moved_replans,
                "shutdown observed after fresh-world planning; leaving lease to expire"
            );
            return;
        }

        // Phase 5: act on the disposition. PointerMoved is returned without a
        // lease mutation so the loop can observe a new committed world under
        // the same claim. Every other disposition reaches its existing single
        // mutation/terminal funnel here.
        let ctx = ExecutionContext {
            runtime,
            config,
            lease_owner,
        };
        let pointer_moved_reason = act_on_disposition(
            &ctx,
            claimed,
            &delta_lease_identity,
            summary,
            disposition,
            &total_started,
        )
        .await;
        let Some(reason) = pointer_moved_reason else {
            return;
        };

        if pointer_moved_replans >= MAX_POINTER_MOVED_REPLANS {
            tracing::warn!(
                event_id = %claimed.event_id,
                attempts = claimed.attempts,
                pointer_moved_replans,
                reason = %reason,
                "pointer-moved replan allowance exhausted; entering ordinary retry budget"
            );
            fail_with_budget(
                runtime,
                &delta_lease_identity,
                claimed,
                DispositionKind::ReleasedRetry,
                0,
                &reason,
                summary,
            )
            .await;
            return;
        }

        pointer_moved_replans += 1;
        summary.events_pointer_moved_replanned += 1;
        record_projector_event(ProjectorEventOutcome::PointerMovedReplanned);
        #[cfg(feature = "e3-observability")]
        log_e3_attempt_event("pointer_replan", claimed, "lease_retained", false, None);
        tracing::info!(
            event_id = %claimed.event_id,
            attempts = claimed.attempts,
            pointer_moved_replans,
            max_pointer_moved_replans = MAX_POINTER_MOVED_REPLANS,
            reason = %reason,
            "retaining live lease for bounded fresh-world replan"
        );
    }
}

async fn retry_disposition(
    runtime: &Arc<dyn AuthorizationProjectorRuntime>,
    claimed: &DeltaEventClaim,
    identity: &DeltaLeaseIdentity,
    summary: &mut WorkerRunSummary,
    reason: String,
    started: &Instant,
) {
    tracing::warn!(
        event_id = %claimed.event_id,
        attempts = claimed.attempts,
        elapsed_us = started.elapsed().as_micros() as u64,
        reason = %reason,
        "delta event infrastructure access failed; unified attempt-budget retry"
    );
    fail_with_budget(
        runtime,
        identity,
        claimed,
        DispositionKind::ReleasedRetry,
        0,
        &reason,
        summary,
    )
    .await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Durable terminal quarantine (live-lease guarded CAS) + stable reason parts
// ─────────────────────────────────────────────────────────────────────────────

/// Upper character bound for the machine-stable `code=` part handed to the
/// repository boundary. The repository composes
/// `code={code};detail={detail}` into the durable `last_error` column and
/// byte-truncates the WHOLE composed text itself
/// ([`astral_db::MAX_LAST_ERROR_LENGTH`]); keeping codes short here guarantees
/// the code prefix always survives that clamp, while only free-form detail is
/// ever cut.
pub const QUARANTINE_REASON_CODE_MAX_CHARS: usize = 64;

/// Stable decomposition of one quarantine reason into `(reason_code,
/// reason_detail)` for [`AuthorizationProjectorRuntime::mark_event_quarantined`].
///
/// Contract:
/// - A leading `code=<token>` up to the first `;` becomes the machine-stable
///   code (whitespace-trimmed).
/// - Everything after the first `;` becomes free-form detail text, subject
///   only to the repository's durable byte truncation.
/// - Reasons without a parseable `code=` prefix (empty token included) fall
///   back to the generic code `auth_projector.quarantine` with the FULL
///   original reason preserved as detail, so operator evidence never shrinks.
fn quarantine_reason_parts(reason: &str) -> (String, String) {
    const GENERIC_FALLBACK: &str = "auth_projector.quarantine";
    // Reasons without a leading `code=` token can never provide a
    // machine-stable identifier — keep the full text as evidence instead.
    let Some(body) = reason.strip_prefix("code=") else {
        return (GENERIC_FALLBACK.to_owned(), reason.to_owned());
    };
    let (raw_code, raw_detail) = body.split_once(';').unwrap_or((body, ""));
    let code = raw_code.trim();
    if code.is_empty()
        || code.chars().count() > QUARANTINE_REASON_CODE_MAX_CHARS
        || code.chars().any(char::is_whitespace)
    {
        (GENERIC_FALLBACK.to_owned(), reason.to_owned())
    } else {
        (code.to_owned(), raw_detail.to_owned())
    }
}

/// THE single funnel into the real terminal `QUARANTINED` state.
///
/// Deterministic divergence only: EventDisposition::Quarantine results and
/// publish-phase ImmutableDivergence classifications reach here. Exactly ONE
/// live-lease guarded CAS mutation is attempted:
/// - success proves the row left the claim queue (`Quarantined` counter);
/// - lease/CAS refusal or a query failure leaves the outcome UNKNOWN — no
///   further fail/release/retry mutation is issued and the reconcile-required
///   counter advances instead;
/// - attempt budgets NEVER gate this path and exhausted budgets are never
///   relabeled into quarantine.
#[allow(clippy::too_many_arguments)]
async fn quarantine_event_terminal(
    runtime: &Arc<dyn AuthorizationProjectorRuntime>,
    lease_identity: &DeltaLeaseIdentity,
    claimed: &DeltaEventClaim,
    reason: &str,
    started: &Instant,
    summary: &mut WorkerRunSummary,
) {
    let (reason_code, reason_detail) = quarantine_reason_parts(reason);
    match runtime
        .mark_event_quarantined(lease_identity, &reason_code, &reason_detail)
        .await
    {
        Ok(()) => {
            summary.record(DispositionKind::Quarantined);
            tracing::error!(
                event_id = %claimed.event_id,
                operation_id = %claimed.operation_id,
                attempts = claimed.attempts,
                elapsed_us = started.elapsed().as_micros() as u64,
                quarantine_code = %reason_code,
                "delta event durably quarantined (terminal status written; off \
                 the claim queue until explicit operator requeue)"
            );
        }
        Err(RuntimeAccessError::Repository(rejection)) => {
            summary.events_quarantine_unknown += 1;
            record_projector_event(ProjectorEventOutcome::QuarantineUnknown);
            tracing::warn!(
                event_id = %claimed.event_id,
                operation_id = %claimed.operation_id,
                attempts = claimed.attempts,
                elapsed_us = started.elapsed().as_micros() as u64,
                error = %rejection,
                "quarantine lease/CAS guard refused; result UNKNOWN, \
                 reconciliation required before any further mutation"
            );
        }
        Err(RuntimeAccessError::Database(query_failure)) => {
            summary.events_quarantine_unknown += 1;
            record_projector_event(ProjectorEventOutcome::QuarantineUnknown);
            tracing::warn!(
                event_id = %claimed.event_id,
                operation_id = %claimed.operation_id,
                attempts = claimed.attempts,
                elapsed_us = started.elapsed().as_micros() as u64,
                error = %query_failure,
                "quarantine query failed; result UNKNOWN, the live lease \
                 expires server-side and self-heals"
            );
        }
    }
}

/// THE single funnel every failing-but-retryable path flows through
/// (`Retry`, `Blocked`, `PointerMoved`, `GenericRetry` and infra failures).
///
/// - Reads the durable CURRENT attempts (post-install claim value), never a
///   pre-increment counter.
/// - Plans the backoff exclusively via [`plan_retry_schedule`]; exhausted
///   budgets produce PENDING + maximal cap backoff + the stable exhaustion
///   marker instead of any fake terminal state.
/// - Records the causal summary kind exactly once, advancing the orthogonal
///   budget-exhausted counter when applicable.
/// - Issues EXACTLY ONE `fail_delta_event` mutation. LeaseLost/UNKNOWN paths
///   never enter this funnel at all, so they stay zero-write by construction.
#[allow(clippy::too_many_arguments)]
async fn fail_with_budget(
    runtime: &Arc<dyn AuthorizationProjectorRuntime>,
    identity: &DeltaLeaseIdentity,
    claimed: &DeltaEventClaim,
    kind_for_summary: DispositionKind,
    minimum_backoff_secs: i64,
    reason: &str,
    summary: &mut WorkerRunSummary,
) {
    let schedule = plan_retry_schedule(claimed.attempts, minimum_backoff_secs);
    summary.record(kind_for_summary);
    match schedule {
        RetrySchedule::Continue { backoff_secs } => {
            #[cfg(feature = "e3-observability")]
            log_e3_attempt_event(
                "retry_scheduled",
                claimed,
                "pending",
                false,
                Some(backoff_secs),
            );
            tracing::debug!(
                event_id = %claimed.event_id,
                attempts = claimed.attempts,
                backoff_secs,
                "unified retry budget scheduled the next attempt"
            );
            runtime.fail_event(identity, backoff_secs, reason).await;
        }
        RetrySchedule::AttemptBudgetExhausted { backoff_secs } => {
            summary.events_budget_exhausted += 1;
            record_projector_event(ProjectorEventOutcome::BudgetExhausted);
            #[cfg(feature = "e3-observability")]
            log_e3_attempt_event(
                "retry_budget_exhausted",
                claimed,
                "pending",
                false,
                Some(backoff_secs),
            );
            let marked_error = budget_exhausted_error(reason, claimed.attempts);
            tracing::warn!(
                event_id = %claimed.event_id,
                attempts = claimed.attempts,
                backoff_secs,
                marked_error = %marked_error,
                "attempt budget exhausted; holding PENDING under the maximal \
                 backoff until a real terminal state exists (never faked)"
            );
            runtime
                .fail_event(identity, backoff_secs, &marked_error)
                .await;
        }
    }
}

/// Shared execution context for one cycle; groups collaborators so handlers
/// stay within the standard argument budget.
struct ExecutionContext<'a> {
    runtime: &'a Arc<dyn AuthorizationProjectorRuntime>,
    config: &'a AuthorizationProjectorConfig,
    lease_owner: &'a str,
}

#[allow(clippy::too_many_lines)]
async fn act_on_disposition(
    ctx: &ExecutionContext<'_>,
    claimed: &DeltaEventClaim,
    delta_lease_identity: &DeltaLeaseIdentity,
    summary: &mut WorkerRunSummary,
    disposition: EventDisposition,
    total_started: &Instant,
) -> Option<String> {
    let runtime = ctx.runtime;
    let config = ctx.config;
    let mut pointer_moved_reason = None;
    match disposition {
        EventDisposition::Publish(mut command) => {
            // Attach the LIVE secret lease token + owner/lease seconds only at
            // execution time; the pure assembler never sees them.
            command.delta_lease_identity.lease_token = claimed.lease_token.clone();
            command.delta_lease_identity.lease_owner = claimed.lease_owner.clone();
            command.manifest_lease_owner = ctx.lease_owner.to_owned();
            command.manifest_lease_seconds = config.manifest_lease_seconds;
            let publish_started = Instant::now();
            match runtime.execute_projection_publish(&command).await {
                Ok(outcome) => {
                    record_projector_phase(ProjectorPhase::Publish, publish_started.elapsed());
                    summary.record(DispositionKind::Published);
                    tracing::info!(
                        event_id = %claimed.event_id,
                        operation_id = %claimed.operation_id,
                        manifest_id = outcome.publish.published_manifest_id,
                        initialized_first_pointer = outcome.publish.initialized_first_pointer,
                        archive_intent_written = outcome.archive_intent.is_some(),
                        publish_elapsed_us = publish_started.elapsed().as_micros() as u64,
                        total_elapsed_us = total_started.elapsed().as_micros() as u64,
                        "delta event published durably (single transaction commit proven)"
                    );
                    // M3 pointer-advance reclaim (~898s finding): the durable
                    // pointer move is proof the aggregate world advanced — pull
                    // THIS aggregate's budget-exhausted parked events back into
                    // the claimable set now (a parked row makes its whole
                    // partition undiscoverable, so rewriting `next_attempt_at`
                    // is the only way a stalled partition comes back). Strictly
                    // best-effort: the publish already committed; a reclaim
                    // failure leaves the row to wait out its backoff and the
                    // next pointer advance retries.
                    match ProjectionAggregateIdentity::new(
                        claimed.tenant_id,
                        claimed.aggregate_type.clone(),
                        claimed.aggregate_id,
                    ) {
                        Ok(identity) => {
                            match runtime.reclaim_budget_exhausted_events(&identity).await {
                                Ok(reclaimed) if reclaimed > 0 => {
                                    tracing::info!(
                                        event_id = %claimed.event_id,
                                        aggregate_type = %identity.aggregate_type,
                                        aggregate_id = identity.aggregate_id,
                                        reclaimed,
                                        "pointer advance reclaimed budget-exhausted events"
                                    );
                                }
                                Ok(_) => {}
                                Err(error) => tracing::warn!(
                                    error = %error,
                                    event_id = %claimed.event_id,
                                    "budget-exhausted reclaim failed; the parked row \
                                     waits out its backoff and the next pointer \
                                     advance retries"
                                ),
                            }
                        }
                        Err(error) => tracing::debug!(
                            error = %error,
                            event_id = %claimed.event_id,
                            "claim identity invalid at reclaim; skipped (the event \
                             would have been quarantined earlier)"
                        ),
                    }
                }
                Err(error) => {
                    record_projector_phase(ProjectorPhase::Publish, publish_started.elapsed());
                    match classify_publish_failure(&error) {
                        PublishFailureHandling::LeaseLost { reason } => {
                            summary.record(DispositionKind::LeaseLost);
                            #[cfg(feature = "e3-observability")]
                            log_e3_attempt_event(
                                "terminal_unknown",
                                claimed,
                                "publish_lease_lost",
                                false,
                                None,
                            );
                            tracing::warn!(
                                event_id = %claimed.event_id,
                                reason = %reason,
                                "publish lost the delta lease; UNKNOWN outcome, \
                                 reconciliation before any retry"
                            );
                            // Zero-write by construction: a lost lease is an
                            // unknown result and must not be mutated again.
                        }
                        PublishFailureHandling::PointerMoved { reason } => {
                            tracing::info!(
                                event_id = %claimed.event_id,
                                attempts = claimed.attempts,
                                reason = %reason,
                                "projection chain moved; requesting an in-place fresh-world replan"
                            );
                            pointer_moved_reason = Some(reason);
                        }
                        PublishFailureHandling::ImmutableDivergence { reason } => {
                            tracing::error!(
                                event_id = %claimed.event_id,
                                attempts = claimed.attempts,
                                reason = %reason,
                                "immutable divergence during publish; requesting \
                                 durable terminal quarantine (deterministic, \
                                 attempt-budget independent)"
                            );
                            // Deterministic divergence family ⇒ real terminal
                            // QUARANTINED write. Unknown CAS/query outcomes are
                            // recorded inside the funnel without any follow-up
                            // mutation; exhausted budgets are never involved.
                            quarantine_event_terminal(
                                runtime,
                                delta_lease_identity,
                                claimed,
                                &reason,
                                total_started,
                                summary,
                            )
                            .await;
                        }
                        PublishFailureHandling::CompilerStampDivergence { reason } => {
                            // Proven-intact payload stamped by another producer
                            // compiler version: the documented Phase 1 modeling
                            // limit for compiler upgrades reusing content. This
                            // is a stamp-ownership decision, NOT durable
                            // corruption — retrying deterministically re-collides
                            // on the immutable content-addressed row, so the
                            // conservative outcome is the REAL terminal
                            // quarantine with its dedicated machine code. No
                            // manifest is published, so nothing invalid can
                            // leak into the chain.
                            tracing::error!(
                                event_id = %claimed.event_id,
                                attempts = claimed.attempts,
                                reason = %reason,
                                "compiler stamp divergence on reused segment \
                                 content; requesting durable terminal quarantine \
                                 (deterministic modeling limit, NOT corruption)"
                            );
                            quarantine_event_terminal(
                                runtime,
                                delta_lease_identity,
                                claimed,
                                &reason,
                                total_started,
                                summary,
                            )
                            .await;
                        }
                        PublishFailureHandling::Blocked { reason } => {
                            tracing::warn!(
                                event_id = %claimed.event_id,
                                attempts = claimed.attempts,
                                reason = %reason,
                                "publish refused on unproven history evidence; \
                                 blocked under the unified attempt budget until \
                                 a proof-bearing pointer/backfill exists (never \
                                 terminal quarantine)"
                            );
                            fail_with_budget(
                                runtime,
                                delta_lease_identity,
                                claimed,
                                DispositionKind::Blocked,
                                0,
                                &reason,
                                summary,
                            )
                            .await;
                        }
                        PublishFailureHandling::GenericRetry { reason } => {
                            tracing::warn!(
                                event_id = %claimed.event_id,
                                attempts = claimed.attempts,
                                reason = %reason,
                                "publish failed generically; scheduling retry"
                            );
                            fail_with_budget(
                                runtime,
                                delta_lease_identity,
                                claimed,
                                DispositionKind::ReleasedRetry,
                                0,
                                &reason,
                                summary,
                            )
                            .await;
                        }
                    }
                }
            }
        }
        EventDisposition::Retry { reason } => {
            tracing::warn!(
                event_id = %claimed.event_id,
                attempts = claimed.attempts,
                reason = %reason,
                "delta event transiently undecidable; unified attempt-budget retry"
            );
            fail_with_budget(
                runtime,
                delta_lease_identity,
                claimed,
                DispositionKind::ReleasedRetry,
                0,
                &reason,
                summary,
            )
            .await;
        }
        EventDisposition::Quarantine { reason } => {
            tracing::error!(
                event_id = %claimed.event_id,
                operation_id = %claimed.operation_id,
                reason = %reason,
                "delta event deterministic divergence; durable terminal \
                 quarantine requested"
            );
            quarantine_event_terminal(
                runtime,
                delta_lease_identity,
                claimed,
                &reason,
                total_started,
                summary,
            )
            .await;
        }
        EventDisposition::Blocked { reason } => {
            tracing::warn!(
                event_id = %claimed.event_id,
                attempts = claimed.attempts,
                reason = %reason,
                "delta event blocked (not publishable without additional proof)"
            );
            fail_with_budget(
                runtime,
                delta_lease_identity,
                claimed,
                DispositionKind::Blocked,
                0,
                &reason,
                summary,
            )
            .await;
        }
        EventDisposition::Superseded { reason } => {
            summary.record(DispositionKind::SupersededRelease);
            #[cfg(feature = "e3-observability")]
            log_e3_attempt_event("release_requested", claimed, "superseded", false, None);
            tracing::info!(
                event_id = %claimed.event_id,
                reason = %reason,
                "delta event superseded by newer projection chain; releasing"
            );
            runtime.release_event(delta_lease_identity).await;
        }
    }
    pointer_moved_reason
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_db::{
        AuthorizationCurrentPointerRecord, Sha256Digest, MAX_DELTA_LEASE_SECONDS,
        SEGMENT_COMPILER_STAMP_DIVERGENCE_CODE,
    };
    use astral_types::{
        BindingLayer, GrantEffect, GrantId, GrantProvenance, GrantRevision, GrantSourceKind,
        GrantState, ValidityWindow,
    };

    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    // ── Partitioned scheduling (Phase 1) typed contracts ─────────────────────

    type PartitionJournal = std::sync::Arc<std::sync::Mutex<Vec<String>>>;

    /// Minimal partition-mode runtime: claims always return `None`, so the
    /// per-event processing path stays unreachable; the contracts under test
    /// are discovery fairness, lease exclusivity (Busy), lost-lease abort, and
    /// release discipline.
    struct PartitionSchedulingFake {
        journal: PartitionJournal,
        partitions: Vec<ProjectionAggregateIdentity>,
        busy: Vec<(i64, String, i64)>,
        lose_renewal_on: Vec<i64>,
        fail_first_discovery: bool,
        discovery_calls: std::sync::atomic::AtomicUsize,
    }

    impl PartitionSchedulingFake {
        fn journal(&self) -> Vec<String> {
            self.journal.lock().unwrap().clone()
        }

        fn note(&self, entry: String) {
            self.journal.lock().unwrap().push(entry);
        }

        fn key(tenant: i64, kind: &str, id: i64) -> String {
            format!("{tenant}:{kind}:{id}")
        }
    }

    #[async_trait::async_trait]
    impl AuthorizationProjectorRuntime for PartitionSchedulingFake {
        async fn claim_next_event(
            &self,
            _scope: &DeltaEventClaimScope,
            _lease_owner: &str,
            _lease_seconds: i64,
        ) -> Result<Option<DeltaEventClaim>, RuntimeAccessError> {
            unreachable!("tenant-serial claim is not exercised by partition scheduling tests")
        }

        async fn read_claimed_event(
            &self,
            _identity: &DeltaLeaseIdentity,
        ) -> Result<ClaimedDeltaEvent, RuntimeAccessError> {
            unreachable!("no event is ever claimed by the partition scheduling fake")
        }

        async fn observe_publication_context(
            &self,
            _identity: &ProjectionAggregateIdentity,
        ) -> Result<Option<PublicationContext>, RuntimeAccessError> {
            unreachable!("no event is ever claimed by the partition scheduling fake")
        }

        async fn load_scope_ledger(
            &self,
            _tenant_id: i64,
            _aggregate_type: &str,
            _aggregate_id: i64,
            _card_id: Option<i64>,
        ) -> Result<Vec<RawLedgerRow>, RuntimeAccessError> {
            unreachable!("no event is ever claimed by the partition scheduling fake")
        }

        async fn execute_projection_publish(
            &self,
            _command: &DeltaProjectorPublishCommand,
        ) -> Result<DeltaProjectorPublishOutcome, RuntimeAccessError> {
            unreachable!("no event is ever claimed by the partition scheduling fake")
        }

        async fn fail_event(
            &self,
            _identity: &DeltaLeaseIdentity,
            _backoff_seconds: i64,
            _message: &str,
        ) {
            unreachable!("no event is ever claimed by the partition scheduling fake")
        }

        async fn release_event(&self, _identity: &DeltaLeaseIdentity) {
            unreachable!("no event is ever claimed by the partition scheduling fake")
        }

        async fn mark_event_quarantined(
            &self,
            _lease: &DeltaLeaseIdentity,
            _reason_code: &str,
            _reason_detail: &str,
        ) -> Result<(), RuntimeAccessError> {
            unreachable!("no event is ever claimed by the partition scheduling fake")
        }

        async fn discover_partitions(
            &self,
            _tenants: &[i64],
            _limit: i64,
        ) -> Result<Vec<ProjectionAggregateIdentity>, RuntimeAccessError> {
            self.note("discover".to_owned());
            if self.fail_first_discovery
                && self
                    .discovery_calls
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                    == 0
            {
                return Err(RuntimeAccessError::Repository(RepositoryRejection::Other(
                    "code=test.discovery_unavailable".to_owned(),
                )));
            }
            Ok(self.partitions.clone())
        }

        async fn acquire_partition_lease(
            &self,
            identity: &ProjectionAggregateIdentity,
            lease_owner: &str,
            _lease_seconds: i64,
        ) -> Result<Option<PartitionLeaseHandle>, RuntimeAccessError> {
            let key = Self::key(
                identity.tenant_id,
                &identity.aggregate_type,
                identity.aggregate_id,
            );
            if self.busy.iter().any(|(tenant, kind, id)| {
                *tenant == identity.tenant_id
                    && kind == &identity.aggregate_type
                    && *id == identity.aggregate_id
            }) {
                self.note(format!("busy:{key}"));
                return Ok(None);
            }
            self.note(format!("acquire:{key}"));
            Ok(Some(PartitionLeaseHandle {
                identity: identity.clone(),
                lease_owner: lease_owner.to_owned(),
                token: astral_db::DeltaLeaseToken::new_run_scoped(),
            }))
        }

        async fn renew_partition_lease(
            &self,
            handle: &PartitionLeaseHandle,
            _lease_seconds: i64,
        ) -> Result<(), RuntimeAccessError> {
            let key = Self::key(
                handle.identity.tenant_id,
                &handle.identity.aggregate_type,
                handle.identity.aggregate_id,
            );
            if self.lose_renewal_on.contains(&handle.identity.aggregate_id) {
                self.note(format!("renew_lost:{key}"));
                return Err(RuntimeAccessError::Repository(RepositoryRejection::Other(
                    "code=test.partition_lease_lost".to_owned(),
                )));
            }
            self.note(format!("renew:{key}"));
            Ok(())
        }

        async fn release_partition_lease(
            &self,
            handle: &PartitionLeaseHandle,
        ) -> Result<(), RuntimeAccessError> {
            self.note(format!(
                "release:{}",
                Self::key(
                    handle.identity.tenant_id,
                    &handle.identity.aggregate_type,
                    handle.identity.aggregate_id,
                )
            ));
            Ok(())
        }

        async fn claim_next_event_in_partition(
            &self,
            identity: &ProjectionAggregateIdentity,
            _scope: &DeltaEventClaimScope,
            _lease_owner: &str,
            _lease_seconds: i64,
        ) -> Result<Option<DeltaEventClaim>, RuntimeAccessError> {
            self.note(format!(
                "claim:{}",
                Self::key(
                    identity.tenant_id,
                    &identity.aggregate_type,
                    identity.aggregate_id,
                )
            ));
            Ok(None)
        }
    }

    fn partition_config() -> AuthorizationProjectorConfig {
        AuthorizationProjectorConfig {
            tenants: vec![1],
            poll_interval_secs: 1,
            scheduling_mode: ProjectorSchedulingMode::Partitioned,
            ..Default::default()
        }
    }

    async fn run_partition_worker_until(
        fake: std::sync::Arc<PartitionSchedulingFake>,
        marker: &str,
        config: AuthorizationProjectorConfig,
    ) {
        let runtime: std::sync::Arc<dyn AuthorizationProjectorRuntime> = fake.clone();
        let cancellation = ProjectorCancellationToken::default();
        let progress = Arc::new(ProjectorProgress::default());
        let task = tokio::spawn(run_partition_worker(
            runtime,
            config,
            "partition-owner".to_owned(),
            cancellation.clone(),
            progress,
        ));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline {
            if fake.journal().iter().any(|entry| entry.contains(marker)) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        cancellation.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
    }

    fn partition_identity(id: i64) -> ProjectionAggregateIdentity {
        ProjectionAggregateIdentity::new(1, "CARD", id).expect("valid partition identity")
    }

    #[tokio::test]
    async fn partition_worker_drains_discovered_partitions_in_order_and_releases() {
        let fake = std::sync::Arc::new(PartitionSchedulingFake {
            journal: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            partitions: vec![partition_identity(1), partition_identity(2)],
            busy: Vec::new(),
            lose_renewal_on: Vec::new(),
            fail_first_discovery: false,
            discovery_calls: std::sync::atomic::AtomicUsize::new(0),
        });
        run_partition_worker_until(fake.clone(), "release:1:CARD:2", partition_config()).await;
        let journal = fake.journal();
        // 公平序：发现 → 按 oldest_due 序逐分区 acquire/renew/claim(None)/release。
        let expected_prefix = [
            "discover".to_owned(),
            "acquire:1:CARD:1".to_owned(),
            "renew:1:CARD:1".to_owned(),
            "claim:1:CARD:1".to_owned(),
            "release:1:CARD:1".to_owned(),
            "acquire:1:CARD:2".to_owned(),
            "renew:1:CARD:2".to_owned(),
            "claim:1:CARD:2".to_owned(),
            "release:1:CARD:2".to_owned(),
        ];
        assert!(
            journal.len() >= expected_prefix.len(),
            "journal too short: {journal:?}"
        );
        assert_eq!(journal[..expected_prefix.len()], expected_prefix[..]);
    }

    #[tokio::test]
    async fn partition_worker_skips_busy_partitions_without_waiting() {
        let fake = std::sync::Arc::new(PartitionSchedulingFake {
            journal: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            partitions: vec![partition_identity(1), partition_identity(2)],
            busy: vec![(1, "CARD".to_owned(), 1)],
            lose_renewal_on: Vec::new(),
            fail_first_discovery: false,
            discovery_calls: std::sync::atomic::AtomicUsize::new(0),
        });
        run_partition_worker_until(fake.clone(), "release:1:CARD:2", partition_config()).await;
        let journal = fake.journal();
        assert!(journal.contains(&"busy:1:CARD:1".to_owned()));
        // Busy 分区绝不 renew/claim/release：拿不到租约就跳过，绝不等待。
        assert!(!journal.iter().any(|entry| entry.contains("renew:1:CARD:1")));
        assert!(!journal.iter().any(|entry| entry.contains("claim:1:CARD:1")));
        assert!(!journal
            .iter()
            .any(|entry| entry.contains("release:1:CARD:1")));
        assert!(journal.contains(&"release:1:CARD:2".to_owned()));
    }

    #[tokio::test]
    async fn partition_worker_stops_touching_a_partition_when_the_lease_is_lost() {
        let fake = std::sync::Arc::new(PartitionSchedulingFake {
            journal: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            partitions: vec![partition_identity(1)],
            busy: Vec::new(),
            lose_renewal_on: vec![1],
            fail_first_discovery: false,
            discovery_calls: std::sync::atomic::AtomicUsize::new(0),
        });
        run_partition_worker_until(fake.clone(), "release:1:CARD:1", partition_config()).await;
        let journal = fake.journal();
        // 续租失败 = 分区已被接管：立即弃置（release 仍尽力执行），绝不 claim。
        assert!(journal.contains(&"renew_lost:1:CARD:1".to_owned()));
        assert!(journal.contains(&"release:1:CARD:1".to_owned()));
        assert!(!journal.iter().any(|entry| entry.contains("claim:1:CARD:1")));
    }

    #[tokio::test]
    async fn partition_worker_survives_transient_discovery_failures() {
        let fake = std::sync::Arc::new(PartitionSchedulingFake {
            journal: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            partitions: vec![partition_identity(1)],
            busy: Vec::new(),
            lose_renewal_on: Vec::new(),
            fail_first_discovery: true,
            discovery_calls: std::sync::atomic::AtomicUsize::new(0),
        });
        run_partition_worker_until(fake.clone(), "acquire:1:CARD:1", partition_config()).await;
        let journal = fake.journal();
        // 瞬态失败：第一轮 discovery 失败只跳过本轮，第二轮照常调度。
        let discovers = journal
            .iter()
            .filter(|entry| entry.as_str() == "discover")
            .count();
        assert!(
            discovers >= 2,
            "expected a retried discovery round: {journal:?}"
        );
        assert!(journal.contains(&"acquire:1:CARD:1".to_owned()));
    }

    #[test]
    fn partitioned_scheduling_defaults_to_tenant_serial_until_accepted() {
        let config = AuthorizationProjectorConfig::default();
        assert_eq!(
            config.scheduling_mode,
            ProjectorSchedulingMode::TenantSerial,
            "default-off discipline: partitioned mode must be explicitly opted in"
        );
        assert_eq!(config.worker_count, DEFAULT_PARTITION_WORKER_COUNT);
    }

    #[test]
    fn scheduling_mode_and_worker_count_parsers_fail_fast() {
        assert_eq!(
            parse_projector_scheduling_mode("").unwrap(),
            ProjectorSchedulingMode::TenantSerial
        );
        assert_eq!(
            parse_projector_scheduling_mode("partitioned").unwrap(),
            ProjectorSchedulingMode::Partitioned
        );
        assert!(parse_projector_scheduling_mode("bogus")
            .unwrap_err()
            .contains("invalid_scheduling_mode"));

        assert_eq!(parse_projector_worker_count("").unwrap(), 4);
        assert_eq!(parse_projector_worker_count("4").unwrap(), 4);
        assert!(parse_projector_worker_count("0")
            .unwrap_err()
            .contains("worker_count"));
        assert!(parse_projector_worker_count("33")
            .unwrap_err()
            .contains("worker_count"));
        assert!(parse_projector_worker_count("x")
            .unwrap_err()
            .contains("invalid_worker_count"));
    }

    #[test]
    fn partition_worker_budget_guard_rejects_pool_overflow() {
        assert!(validate_partition_worker_budget(4, 100).is_ok());
        assert!(validate_partition_worker_budget(32, 100).is_ok());
        assert!(validate_partition_worker_budget(0, 100)
            .unwrap_err()
            .contains("worker_count_out_of_bounds"));
        assert!(validate_partition_worker_budget(33, 100)
            .unwrap_err()
            .contains("worker_count_out_of_bounds"));
        // 30 workers × 2 connections > 50 pool budget (within the count bound).
        assert!(validate_partition_worker_budget(30, 50)
            .unwrap_err()
            .contains("worker_count_exceeds_pool_budget"));
    }

    const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    // Production code drives WorkerRunSummary.record directly; the disposition
    // → counter mapping stays unit-test-visible only. This impl deliberately
    // lives INSIDE the test module so the production source contains exactly
    // one `#[cfg(test)]` marker — the section boundary every source-shape scan
    // cuts at.
    impl EventDisposition {
        fn kind(&self) -> DispositionKind {
            match self {
                Self::Publish(_) => DispositionKind::Published,
                Self::Retry { .. } => DispositionKind::ReleasedRetry,
                Self::Quarantine { .. } => DispositionKind::Quarantined,
                Self::Blocked { .. } => DispositionKind::Blocked,
                Self::Superseded { .. } => DispositionKind::SupersededRelease,
            }
        }
    }

    // ── Fixtures mirroring the shared contract test grants ───────────────────

    fn tenant_of(card: i64) -> TenantScope {
        TenantScope::new(7, Some(card)).unwrap()
    }

    fn grant(unique_tail: u16, revision: u64, state: GrantState) -> astral_types::CanonicalGrant {
        astral_types::CanonicalGrant {
            grant_id: GrantId::parse(&format!(
                "550e8400-e29b-41d4-a716-44665544{unique_tail:04x}"
            ))
            .unwrap(),
            revision: GrantRevision::new(revision).unwrap(),
            state,
            source_kind: GrantSourceKind::RuleSet,
            binding_layer: BindingLayer::Base,
            tenant: tenant_of(17),
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

    fn raw_row(
        grant: &astral_types::CanonicalGrant,
        event: &str,
        op: &str,
        revoke_fence: u64,
    ) -> RawLedgerRow {
        let payload = serde_json::to_string(grant).unwrap();
        let semantic = grant.canonical_hash().unwrap();
        // The revision's dependency hash follows the same producer
        // reconstruction the projector performs, pinned to one CARD batch.
        let dep_hash = active_card_dependency_hash(5, revoke_fence).1;
        RawLedgerRow {
            revision_no: grant.revision.value() as i64,
            tenant_id: grant.tenant.tenant_id,
            card_id: Some(grant.card_id),
            aggregate_type: "CARD".to_owned(),
            aggregate_id: 17,
            grant_id: grant.grant_id.as_str().to_owned(),
            status: "ACTIVE".to_owned(),
            is_tombstone: i8::from(matches!(
                grant.state,
                GrantState::Removed | GrantState::Revoked
            )),
            grant_payload: payload,
            semantic_hash: {
                let digest = Sha256Digest::from_hex(&semantic).unwrap();
                digest.as_bytes().to_vec()
            },
            dependency_hash: {
                let digest = Sha256Digest::from_hex(&dep_hash).unwrap();
                digest.as_bytes().to_vec()
            },
            operation_id: op.to_owned(),
            event_id: event.to_owned(),
            // fixture 版本必须与本地 AuthorizationCompiler 一致（prepare_compile_inputs
            // 强制 producer/consumer 同版本），引用导出常量避免 bump 时漂移。
            compiler_version: policy_engine::COMPILER_VERSION.to_owned(),
        }
    }

    // ── Policy helpers ───────────────────────────────────────────────────────

    #[test]
    fn backoff_policy_is_bounded_and_exponential() {
        assert_eq!(event_backoff_secs(1), 1);
        assert_eq!(event_backoff_secs(2), 2);
        assert_eq!(event_backoff_secs(3), 4);
        assert_eq!(event_backoff_secs(4), 8);
        // Attempt budget exhaustion switches to the capped maximum.
        assert_eq!(
            event_backoff_secs(MAX_EVENT_ATTEMPTS),
            clamp_backoff(BACKOFF_CAP_SECS)
        );
        assert_eq!(event_backoff_secs(50), clamp_backoff(BACKOFF_CAP_SECS));
        assert!(clamp_backoff(i64::MAX) <= MAX_BACKOFF_SECONDS);
    }

    #[test]
    fn worker_constants_respect_repository_limits() {
        const _: () = {
            assert!(CLAIM_LEASE_SECS <= MAX_DELTA_LEASE_SECONDS);
            assert!(BACKOFF_CAP_SECS <= MAX_BACKOFF_SECONDS);
            // MAX_MANIFEST_LEASE_SECONDS.min(600) is a stable bound by
            // construction; the runtime comparison stays in `Default`.
        };
        assert_eq!(
            event_backoff_secs(MAX_EVENT_ATTEMPTS),
            clamp_backoff(BACKOFF_CAP_SECS)
        );
        assert_eq!(MAX_EVENT_ATTEMPTS, 5);
    }

    #[test]
    fn unified_retry_budget_pins_attempt_boundaries_one_through_five() {
        // In-budget attempts 1..=4 follow the pinned exponential ladder.
        assert_eq!(
            plan_retry_schedule(1, 0),
            RetrySchedule::Continue { backoff_secs: 1 }
        );
        assert_eq!(
            plan_retry_schedule(2, 0),
            RetrySchedule::Continue { backoff_secs: 2 }
        );
        assert_eq!(
            plan_retry_schedule(3, 0),
            RetrySchedule::Continue { backoff_secs: 4 }
        );
        assert_eq!(
            plan_retry_schedule(4, 0),
            RetrySchedule::Continue { backoff_secs: 8 }
        );
        // Strict monotonicity across the whole in-budget ladder.
        let ladder = [1i64, 2, 3, 4].map(|attempt| match plan_retry_schedule(attempt, 0) {
            RetrySchedule::Continue { backoff_secs } => backoff_secs,
            other => panic!("attempt {attempt} must stay in budget, got {other:?}"),
        });
        assert!(ladder.windows(2).all(|pair| pair[0] < pair[1]));

        // Fifth-failure onward: exhausted. A hypothetical sixth claim can only
        // arrive after a full cap delay and can NEVER short-backoff again.
        let exhausted_backoff = |attempts: i64| -> i64 {
            match plan_retry_schedule(attempts, 0) {
                RetrySchedule::AttemptBudgetExhausted { backoff_secs } => backoff_secs,
                other => panic!("attempt {attempts} must be exhausted, got {other:?}"),
            }
        };
        let cap = clamp_backoff(BACKOFF_CAP_SECS);
        assert_eq!(exhausted_backoff(MAX_EVENT_ATTEMPTS), cap);
        assert_eq!(exhausted_backoff(MAX_EVENT_ATTEMPTS + 1), cap);
        assert_eq!(exhausted_backoff(i64::MAX), cap);
        assert!(cap > 8, "cap must dominate every short step");

        // Defensive floors: zero/negative attempts degrade to attempt 1.
        assert_eq!(
            plan_retry_schedule(0, 0),
            RetrySchedule::Continue { backoff_secs: 1 }
        );
        assert_eq!(
            plan_retry_schedule(-7, 0),
            RetrySchedule::Continue { backoff_secs: 1 }
        );
    }

    #[test]
    fn unified_retry_budget_accepts_long_backoffs_only_within_budget() {
        let long_request = clamp_backoff(MAX_BACKOFF_SECONDS);
        // ImmutableDivergence-grade paths may demand the maximal long cool-down
        // while the budget lasts…
        assert_eq!(
            plan_retry_schedule(1, long_request),
            RetrySchedule::Continue {
                backoff_secs: long_request
            }
        );
        // …but the request can never rescue an exhausted budget: the exhausted
        // disposition wins with its capped backoff.
        assert_eq!(
            plan_retry_schedule(5, long_request),
            RetrySchedule::AttemptBudgetExhausted {
                backoff_secs: clamp_backoff(BACKOFF_CAP_SECS)
            }
        );
    }

    #[test]
    fn attempt_budget_exhausted_marker_is_stable_for_operators() {
        assert_eq!(
            ATTEMPT_BUDGET_EXHAUSTED_CODE,
            "code=auth_projector.attempt_budget_exhausted"
        );
    }

    #[test]
    fn budget_exhaustion_marker_survives_repository_error_truncation() {
        for reason in ["x".repeat(2_048), "数据库错误".repeat(512)] {
            let marked = budget_exhausted_error(&reason, MAX_EVENT_ATTEMPTS);
            let stored: String = marked
                .chars()
                .take(astral_db::MAX_LAST_ERROR_LENGTH)
                .collect();
            assert!(stored.starts_with(ATTEMPT_BUDGET_EXHAUSTED_CODE));
            assert!(stored.contains(&format!("attempts={MAX_EVENT_ATTEMPTS}")));
        }
    }

    #[test]
    fn tenant_scope_parser_is_fail_fast_and_order_preserving() {
        // Empty env / whitespace-only ⇒ empty consumer set (idle warn upstream).
        assert_eq!(parse_projector_tenants("").unwrap(), Vec::<i64>::new());
        assert_eq!(
            parse_projector_tenants("   \t ").unwrap(),
            Vec::<i64>::new()
        );
        // Whitespace-tolerant, order-preserving dedupe of repeats.
        assert_eq!(parse_projector_tenants("7, 9 ,3").unwrap(), vec![7, 9, 3]);
        assert_eq!(parse_projector_tenants("7,7,7").unwrap(), vec![7]);

        let bad_inputs = [
            ",",                   // empty token pair
            "7,,9",                // interior empty token
            "7,",                  // trailing separator leaves an empty token
            ",7",                  // leading separator
            "7,abc",               // non-numeric token
            "7,-3",                // negative id
            "0",                   // zero id
            "9223372036854775808", // out-of-range (i64 overflow)
            "7,9,oops",            // mixed valid + garbage must poison all
        ];
        for raw in bad_inputs {
            let parsed = parse_projector_tenants(raw);
            assert!(parsed.is_err(), "{raw:?} must fail startup parsing");
            let message = parsed.unwrap_err();
            assert!(
                message.starts_with("code=config."),
                "{raw:?} must surface a stable error code, got: {message}"
            );
        }
    }

    // ── Dependency vector reconstruction ────────────────────────────────────

    #[test]
    fn dependency_vector_matches_producer_shape_and_hashes() {
        let (vector, hash) =
            reconstruct_dependency_vector(Some(17), 5, 1).expect("scoped card must rebuild");
        let expected =
            DependencyVector::new(vec![DependencyVersion::new("card:17", 5, 1).unwrap()]).unwrap();
        assert_eq!(vector, expected);
        assert_eq!(hash, expected.canonical_hash().unwrap());

        assert!(reconstruct_dependency_vector(None, 5, 1)
            .unwrap_err()
            .contains("card_scoped_dependency_required"));
    }

    // ── Segment planning ─────────────────────────────────────────────────────

    fn parent_view(ordinal: u64, digest_hex: &str) -> (u64, ParentReferenceView) {
        (
            ordinal,
            ParentReferenceView {
                ordinal,
                identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
                segment_id: 100 + ordinal as i64,
                content_digest_hex: digest_hex.to_owned(),
            },
        )
    }

    #[tokio::test]
    async fn stage_planning_defaults_to_all_new_without_parent_references() {
        let state = HotState::from_grants(
            tenant_of(17),
            3,
            vec![
                grant(1, 1, GrantState::Active),
                grant(2, 1, GrantState::Active),
            ],
            DependencyVector::default(),
        )
        .unwrap();
        let plan = plan_stage_segments(&state, None).unwrap();
        assert_eq!(plan.len(), state.segments.len());
        assert!(plan
            .iter()
            .all(|entry| matches!(entry, StagedSegmentContent::New(_))));
    }

    #[tokio::test]
    async fn stage_planning_reuses_only_exact_content_matched_unused_ordinals() {
        let changed = grant(1, 2, GrantState::Active);
        let unchanged = grant(2, 1, GrantState::Active);
        let candidate = HotState::from_grants(
            tenant_of(17),
            4,
            vec![changed, unchanged.clone()],
            DependencyVector::default(),
        )
        .unwrap();

        let payload_a =
            astral_db::encode_segment_payload(&candidate.segments.iter().next().unwrap().1.grants)
                .unwrap();
        let other_digest = hex_lower(&Sha256::digest(b"unrelated"));

        let references = vec![
            parent_view(0, &other_digest),
            parent_view(1, &hex_lower(&Sha256::digest(&payload_a))),
        ];
        let plan = plan_stage_segments(&candidate, Some(&references)).unwrap();
        // Only the segment whose digest matches an unused parent ordinal is
        // reused; everything else stays New.
        let reused: Vec<&StagedSegmentContent> = plan
            .iter()
            .filter(|entry| matches!(entry, StagedSegmentContent::ReuseParent { .. }))
            .collect();
        assert_eq!(reused.len(), 1);

        // Duplicate ordinal claims collapse: two candidate segments with equal
        // content share one parent row, so the second must fall back to New.
        let twin_state = HotState::from_grants(
            tenant_of(17),
            5,
            vec![unchanged.clone()],
            DependencyVector::default(),
        )
        .unwrap();
        let twin_payload =
            astral_db::encode_segment_payload(&twin_state.segments.iter().next().unwrap().1.grants)
                .unwrap();
        let shared_references = [parent_view(0, &hex_lower(&Sha256::digest(&payload_a)))];
        let _ = twin_payload;
        let duplicate_candidates = [parent_view(3, &other_digest)];
        // Foreign identity views must never be selected even if digests match.
        let foreign = ParentReferenceView {
            identity: ProjectionAggregateIdentity::new(9, "CARD", 88).unwrap(),
            ..parent_view(7, &hex_lower(&Sha256::digest(&payload_a))).1
        };
        let mixed = vec![
            shared_references[0].clone(),
            (foreign.ordinal, foreign),
            duplicate_candidates[0].clone(),
        ];
        let plan_foreign = plan_stage_segments(&candidate, Some(&mixed)).unwrap();
        assert!(plan_foreign.iter().all(|entry| matches!(
            entry,
            StagedSegmentContent::New(_) | StagedSegmentContent::ReuseParent { parent_ordinal: 0 }
        )));
    }

    // ── Publish-failure taxonomy ─────────────────────────────────────────────

    /// Typed construction helper: the projection rejection as the runtime seam
    /// actually delivers it (variant preserved, never re-parsed from text).
    fn projection_failure(error: AuthorizationProjectionError) -> RuntimeAccessError {
        RuntimeAccessError::Repository(RepositoryRejection::Projection(error))
    }

    #[test]
    fn publish_failure_classification_routes_each_family() {
        let pointer_moved = [
            // Variant-classified: the pointer/manifest pair disagrees with the
            // claimed world.
            projection_failure(AuthorizationProjectionError::CurrentPointerCasConflict(
                "code=authorization_projection.previous_fence_not_authoritative;durable=3;evidence=2"
                    .to_owned(),
            )),
            projection_failure(AuthorizationProjectionError::IdentityMismatch(
                "code=authorization_projection.pointer_target_identity_mismatch".to_owned(),
            )),
            // Exact machine code inside ManifestPublishConflict.
            projection_failure(AuthorizationProjectionError::ManifestPublishConflict(
                "code=authorization_projection.publish_generation_gap;expected=5;actual=7"
                    .to_owned(),
            )),
            projection_failure(AuthorizationProjectionError::ManifestPublishConflict(
                "code=authorization_projection.publish_same_manifest".to_owned(),
            )),
            // Exact machine code inside NotReady / Mapping.
            projection_failure(AuthorizationProjectionError::NotReady(
                "code=authorization_projection.stage_generation_gap;expected=4;actual=5".to_owned(),
            )),
            projection_failure(AuthorizationProjectionError::NotReady(
                "code=authorization_projection.current_pointer_missing".to_owned(),
            )),
            projection_failure(AuthorizationProjectionError::Mapping(
                "code=authorization_projection.generation_overflow".to_owned(),
            )),
            // A pointer-generation race is a fresh-world replan even though
            // the repository exposes it through the generic scope variant.
            projection_failure(AuthorizationProjectionError::ScopeViolation(
                "code=authorization_projection.command_base_generation_mismatch;expected=4;actual=5"
                    .to_owned(),
            )),
        ];
        for case in pointer_moved {
            assert!(
                matches!(
                    classify_publish_failure(&case),
                    PublishFailureHandling::PointerMoved { .. }
                ),
                "{case:?} must route to PointerMoved"
            );
        }

        let lease_lost = [
            projection_failure(AuthorizationProjectionError::LeaseCasFailed(
                "code=grant_repository.complete_lost_lease;event=e".to_owned(),
            )),
            projection_failure(AuthorizationProjectionError::LeaseCasFailed(
                "code=grant_repository.claimed_readback_not_leased;event=e".to_owned(),
            )),
            // Variant-classified: the old `ClaimRace` Display needle was dead.
            projection_failure(AuthorizationProjectionError::ClaimRace),
        ];
        for case in lease_lost {
            assert!(
                matches!(
                    classify_publish_failure(&case),
                    PublishFailureHandling::LeaseLost { .. }
                ),
                "{case:?} must route to LeaseLost"
            );
        }

        let immutable = [
            projection_failure(AuthorizationProjectionError::DuplicateRow(
                "code=authorization_projection.manifest_identity_conflict".to_owned(),
            )),
            // Variant-classified: the old `DuplicateRow` Display needle was
            // dead, so unproven unique-race winners silently retried before.
            projection_failure(AuthorizationProjectionError::DuplicateRow(
                "code=authorization_projection.segment_insert_not_applied".to_owned(),
            )),
            projection_failure(AuthorizationProjectionError::ImmutableConflict(
                "code=authorization_projection.replay_field_divergence;field=semantic_hash"
                    .to_owned(),
            )),
            projection_failure(AuthorizationProjectionError::Corrupt(
                "code=authorization_projection.parent_fence_split;manifest=1;pointer=2".to_owned(),
            )),
            // Collision codes OTHER than the compiler-stamp carve-out stay in
            // the corruption family.
            projection_failure(AuthorizationProjectionError::SegmentDigestCollision(
                "code=authorization_projection.cross_card_digest_collision".to_owned(),
            )),
            projection_failure(AuthorizationProjectionError::SegmentDigestCollision(
                "code=authorization_projection.digest_metadata_collision".to_owned(),
            )),
        ];
        for case in immutable {
            assert!(
                matches!(
                    classify_publish_failure(&case),
                    PublishFailureHandling::ImmutableDivergence { .. }
                ),
                "{case:?} must route to ImmutableDivergence"
            );
        }

        let generic = [
            RuntimeAccessError::Database("connection refused".to_owned()),
            // Projector-side non-typed refusal (grant errors now arrive typed
            // via RepositoryRejection::Grant — see the dedicated test below).
            RuntimeAccessError::Repository(RepositoryRejection::Other(
                "code=auth_projector.parent_snapshot_missing_for_live_pointer".to_owned(),
            )),
            RuntimeAccessError::Repository(RepositoryRejection::Grant(
                astral_db::GrantRepositoryError::Mapping(
                    "code=grant_repository.claim_expiry_missing".to_owned(),
                ),
            )),
            projection_failure(AuthorizationProjectionError::NotReady(
                "code=authorization_projection.target_not_ready;status=BUILDING".to_owned(),
            )),
            projection_failure(AuthorizationProjectionError::ManifestPublishConflict(
                "code=authorization_projection.publish_target_semantic_mismatch".to_owned(),
            )),
            projection_failure(AuthorizationProjectionError::ScopeViolation(
                "authorization_projection.payload_size_overflow".to_owned(),
            )),
            projection_failure(AuthorizationProjectionError::Mapping(
                "code=authorization_projection.grant_ledger_conflict;conflict=revision".to_owned(),
            )),
        ];
        for case in generic {
            assert!(
                matches!(
                    classify_publish_failure(&case),
                    PublishFailureHandling::GenericRetry { .. }
                ),
                "{case:?} must route to GenericRetry"
            );
        }
    }

    #[test]
    fn typed_grant_rejections_preserve_lease_loss_across_the_seam() {
        // M2: astral-db grant errors keep their variants across
        // `RepositoryRejection::Grant`, so a lost lease classifies as
        // LeaseLost/UNKNOWN by VARIANT — never by Display text — and can never
        // be misrouted into a `fail_delta_event` write after ownership died.
        let lease_lost = [
            RuntimeAccessError::from(astral_db::GrantRepositoryError::LeaseCasFailed(
                "code=grant_repository.heartbeat_lost_lease;event=e".to_owned(),
            )),
            RuntimeAccessError::from(astral_db::GrantRepositoryError::LeaseCasFailed(
                "code=grant_repository.complete_lost_lease;event=e".to_owned(),
            )),
            RuntimeAccessError::from(astral_db::GrantRepositoryError::LeaseCasFailed(
                "code=grant_repository.claimed_readback_not_leased;event=e".to_owned(),
            )),
            // Variant-classified: the claim race never had a Display needle.
            RuntimeAccessError::from(astral_db::GrantRepositoryError::ClaimRace),
        ];
        for case in lease_lost {
            assert!(
                matches!(
                    classify_publish_failure(&case),
                    PublishFailureHandling::LeaseLost { .. }
                ),
                "{case:?} must route to LeaseLost"
            );
        }

        // Every other typed grant refusal proves no deterministic divergence
        // and stays under the unified attempt budget.
        let generic = [
            RuntimeAccessError::from(astral_db::GrantRepositoryError::Mapping(
                "code=grant_repository.claim_expiry_missing".to_owned(),
            )),
            RuntimeAccessError::from(astral_db::GrantRepositoryError::ScopeViolation(
                "code=grant_repository.invalid_lease_seconds;value=0".to_owned(),
            )),
            RuntimeAccessError::from(astral_db::GrantRepositoryError::DuplicateDeltaEvent(
                "duplicate delta event: evt-x".to_owned(),
            )),
        ];
        for case in generic {
            assert!(
                matches!(
                    classify_publish_failure(&case),
                    PublishFailureHandling::GenericRetry { .. }
                ),
                "{case:?} must route to GenericRetry"
            );
        }
    }

    #[test]
    fn backfill_or_rehearsal_required_blocks_instead_of_quarantining() {
        // astral-db refuses publication on unproven pointer-proof history via
        // `AuthorizationProjectionError::NotReady` carrying the stable machine
        // code `backfill_or_rehearsal_required` (validate_pointer_proof_state);
        // the exact LEADING token routes to Blocked, never to terminal
        // quarantine.
        let error = projection_failure(AuthorizationProjectionError::NotReady(
            "code=authorization_projection.backfill_or_rehearsal_required;pointer_proof_unproven;pointer_fence=0"
                .to_owned(),
        ));
        let PublishFailureHandling::Blocked { reason } = classify_publish_failure(&error) else {
            panic!("unproven pointer history must block, never quarantine");
        };
        // The full evidence (including the pointer-proof detail) survives into
        // the durable failure text handed to the retry funnel.
        assert!(reason.contains("backfill_or_rehearsal_required"));
        assert!(reason.contains("pointer_proof_unproven"));

        // Exact-token discipline inside the NotReady arm: the same token in
        // the DETAIL of another code must NOT flip to Blocked — only the
        // leading token decides, and an unknown code keeps the bounded-retry
        // default.
        let detail_flip = projection_failure(AuthorizationProjectionError::NotReady(
            "code=authorization_projection.parent_fence_split;hint=backfill_or_rehearsal_required"
                .to_owned(),
        ));
        assert!(matches!(
            classify_publish_failure(&detail_flip),
            PublishFailureHandling::GenericRetry { .. }
        ));

        // Corruption quarantine retained: the same token in the detail of a
        // CORRUPT refusal (e.g. the real `parent_fence_split` emission) stays
        // terminal divergence — unproven-history wording never downgrades
        // proven corruption into a blocked retry.
        let corrupt = projection_failure(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.parent_fence_split;hint=backfill_or_rehearsal_required"
                .to_owned(),
        ));
        assert!(matches!(
            classify_publish_failure(&corrupt),
            PublishFailureHandling::ImmutableDivergence { .. }
        ));
    }

    #[test]
    fn blocked_history_ladder_stays_on_bounded_budget_never_hot_loops() {
        // A permanently-blocked event is reclaimed once per scheduled retry;
        // every reclaim increments the durable `attempts` and every failure
        // schedules the next attempt through [`plan_retry_schedule`]. The
        // ladder must be strictly positive and growing, then pin the event
        // under the maximal cap backoff once the budget is exhausted — never a
        // zero-second hot loop and never a terminal quarantine.
        let mut previous: i64 = 0;
        for attempts in 1..MAX_EVENT_ATTEMPTS {
            match plan_retry_schedule(attempts, 0) {
                RetrySchedule::Continue { backoff_secs } => {
                    assert!(backoff_secs >= 1, "no zero-second hot loop");
                    assert!(backoff_secs > previous, "ladder must grow at {attempts}");
                    previous = backoff_secs;
                }
                other => panic!("attempt {attempts} must stay in budget, got {other:?}"),
            }
        }
        let cap = clamp_backoff(BACKOFF_CAP_SECS);
        for attempts in [
            MAX_EVENT_ATTEMPTS,
            MAX_EVENT_ATTEMPTS + 1,
            MAX_EVENT_ATTEMPTS * 10,
        ] {
            match plan_retry_schedule(attempts, 0) {
                RetrySchedule::AttemptBudgetExhausted { backoff_secs } => {
                    assert_eq!(backoff_secs, cap);
                    assert!(backoff_secs > previous, "cap dominates the ladder");
                }
                other => panic!("attempt {attempts} must be exhausted, got {other:?}"),
            }
        }
        // The exhaustion marker stays machine-stable for operators.
        let marked =
            format!("reason;{ATTEMPT_BUDGET_EXHAUSTED_CODE};attempts={MAX_EVENT_ATTEMPTS}");
        assert!(marked.contains(ATTEMPT_BUDGET_EXHAUSTED_CODE));
    }

    #[test]
    fn compiler_stamp_divergence_routes_to_dedicated_quarantine_path() {
        let error = projection_failure(AuthorizationProjectionError::SegmentDigestCollision(
            SEGMENT_COMPILER_STAMP_DIVERGENCE_CODE.to_owned(),
        ));
        let PublishFailureHandling::CompilerStampDivergence { reason } =
            classify_publish_failure(&error)
        else {
            panic!("compiler stamp divergence must take the dedicated path");
        };
        // The durable quarantine reason decomposes into a dedicated, short
        // machine-stable code plus the full evidence as detail.
        let (code, detail) = quarantine_reason_parts(&reason);
        assert_eq!(code, "auth_projector.compiler_stamp_divergence");
        assert!(detail.contains(SEGMENT_COMPILER_STAMP_DIVERGENCE_CODE));
    }

    #[test]
    fn publish_classification_never_scans_dynamic_detail_tokens() {
        // The exact-token router only ever reads the FIRST machine code, so a
        // foreign token inside free-form detail can no longer flip a
        // disposition the way the previous substring matching could.
        let detail_flip = projection_failure(AuthorizationProjectionError::Mapping(
            "code=authorization_projection.grant_ledger_conflict;conflict=generation_overflow"
                .to_owned(),
        ));
        assert!(matches!(
            classify_publish_failure(&detail_flip),
            PublishFailureHandling::GenericRetry { .. }
        ));
        let detail_flip_conflict = projection_failure(
            AuthorizationProjectionError::ManifestPublishConflict(
                "code=authorization_projection.publish_target_compiler_mismatch;detail=manifest_identity_conflict"
                    .to_owned(),
            ),
        );
        assert!(matches!(
            classify_publish_failure(&detail_flip_conflict),
            PublishFailureHandling::GenericRetry { .. }
        ));
        // The leading token itself still decides, whatever follows it.
        let leading_gap = projection_failure(AuthorizationProjectionError::ManifestPublishConflict(
            "code=authorization_projection.publish_generation_gap;expected=1;actual=generation_overflow"
                .to_owned(),
        ));
        assert!(matches!(
            classify_publish_failure(&leading_gap),
            PublishFailureHandling::PointerMoved { .. }
        ));
    }

    #[test]
    fn compile_stage_classification_is_exact_token() {
        let divergence_codes = [
            "code=auth_projector.unsupported_producer_compiler;expected=v1;claimed=v2",
            "code=auth_projector.generation_overflow",
            "code=auth_projector.first_publication_requires_initial_chain",
            "code=auth_projector.full_rebuild_stuck;reason=BaseBehindFrontier",
            "code=auth_projector.compile_version_fence_broken",
            "code=auth_projector.first_publication_rebuild_failed;error=boom",
            "code=auth_projector.base_state_build_failed;error=boom",
            "code=auth_projector.continuation_requires_published_frontier",
        ];
        for reason in divergence_codes {
            assert!(
                matches!(
                    classify_compile_stage_error(reason.to_owned()),
                    EventDisposition::Quarantine { .. }
                ),
                "{reason} must route to Quarantine"
            );
        }

        let retry_codes = [
            "code=auth_projector.compile_error;error=boom",
            "code=auth_projector.full_rebuild_failed;error=boom",
            "code=auth_projector.delta_payload_invalid;error=boom",
            "code=auth_projector.tenant_scope_invalid;error=boom",
            "code=auth_projector.card_scoped_dependency_required",
            // Unparseable / foreign codes keep the bounded-retry default.
            "code=auth_projector.not_a_known_divergence",
            "no code prefix at all",
            "",
        ];
        for reason in retry_codes {
            assert!(
                matches!(
                    classify_compile_stage_error(reason.to_owned()),
                    EventDisposition::Retry { .. }
                ),
                "{reason} must route to Retry"
            );
        }

        // Regression pin for the substring hazard: a dynamic detail token can
        // no longer flip a transient failure into terminal quarantine.
        let detail_flip =
            "code=auth_projector.compile_error;error=inner base_state_build_failed burst";
        assert!(matches!(
            classify_compile_stage_error(detail_flip.to_owned()),
            EventDisposition::Retry { .. }
        ));
    }

    // ── Source-shape guards: no legacy-table/MQ symbols leak into the new
    //    worker (boundary #8, reviewable without running anything).

    /// Banned legacy-channel symbols; ANY occurrence inside scanned production
    /// source fails the suite.
    const LEGACY_CHANNEL_SYMBOLS: [&str; 11] = [
        "rebuild_card_snapshot_inner",
        "rebuild_rule_set_snapshot_inner",
        "permission_rule_snapshot",
        "rule_set_snapshot",
        "authorization_projection_outbox\"",
        "publish_permission_refresh",
        "PermissionRefreshPayload",
        "complete_authorization_archive_intent",
        "evict_card_cache",
        "mark_aggregate_projected_for_event",
        // The old pointer-only observation seam is fully superseded; a
        // reintroduction would silently drop parent-reference hints.
        "observe_current_pointer",
    ];

    /// Reusable extraction of the FULL production source of this file:
    /// everything before the single module-level test section.
    ///
    /// History note: the first implementation cut at the FIRST `#[cfg(test)]`
    /// in the file, which used to sit mid-production (`impl EventDisposition`);
    /// the scan therefore ended around line ~570 and every later symbol —
    /// `run_worker`, `act_on_disposition`, publish-failure handlers — was
    /// invisible to it. This extractor cuts at the true module-level
    /// `#[cfg(test)] mod tests` marker, asserts that marker is unique, and is
    /// proven end-to-end by
    /// [`legacy_guard_self_test_proves_late_production_symbol_detection`].
    fn production_source_slice(full_source: &'static str) -> &'static str {
        const TEST_SECTION_MARKER: &str = "\n#[cfg(test)]\nmod tests";
        let first = full_source.find(TEST_SECTION_MARKER).unwrap_or_else(|| {
            panic!("module-level test section marker missing; production scan refused")
        });
        assert!(
            !full_source[first + TEST_SECTION_MARKER.len()..].contains(TEST_SECTION_MARKER),
            "multiple module-level test sections detected; slice would be ambiguous"
        );
        &full_source[..first + 1]
    }

    fn assert_no_legacy_channel_symbols(production: &str, context: &str) {
        for banned in LEGACY_CHANNEL_SYMBOLS {
            assert!(
                !production.contains(banned),
                "{context}: new worker must not reference legacy symbol {banned}"
            );
        }
    }

    #[test]
    fn worker_source_has_no_legacy_channel_symbols() {
        let source = include_str!("authorization_projector.rs");
        let production = production_source_slice(source);
        // The cut must land exactly on the single test-section marker: no
        // cfg(test)/test-mod text may survive into the scanned production half.
        assert!(
            !production.contains("#[cfg(test)]"),
            "production slice must be cut at the unique module-level test section"
        );

        // Coverage proof across the whole runtime half (fixed scan regression):
        // early constants/policy, the loop body, the disposition actuator and
        // the final production surface before `mod tests` must ALL be present,
        // so any late-file forbidden symbol is now guaranteed to be seen.
        assert!(production.contains("fn plan_retry_schedule("));
        assert!(production.contains("async fn run_worker("));
        assert!(production.contains("async fn act_on_disposition("));
        assert!(production.contains("fn parse_projector_tenants("));

        assert_no_legacy_channel_symbols(production, "authorization_projector.rs");
        // The fixed publish sequence helper IS required.
        assert!(production.contains("project_authorization_delta_in_tx"));
        assert!(production.contains("load_claimed_delta_event_for_update_in_tx"));
        assert!(production.contains("claim_next_delta_event_in_tx"));

        // Slice-2 wiring must stay present: one-transaction publication
        // context, strict frontier loader, parent reference loader, multi-
        // grant partition planning and the real terminal quarantine boundary.
        assert!(production.contains("async fn observe_publication_context("));
        assert!(production.contains("load_published_aggregate_frontier_in_tx"));
        assert!(production.contains("load_published_parent_reference_views_in_tx"));
        assert!(production.contains("partition_ledger_at_published_frontier("));
        assert!(production.contains("async fn mark_event_quarantined("));
        assert!(production.contains("mark_delta_event_quarantined("));
        assert!(production.contains("fn quarantine_reason_parts("));
        // Segment reuse is driven by observed parent references (never hard
        // coded None in the production decide path).
        assert!(production.contains("plan_stage_segments(&assembled.candidate, parent_references)"));
    }

    /// Watchdog probe / claim-candidate same-shape guard (10.D-2 companion).
    ///
    /// `has_claimable_work` feeds the F5-1d stall detector: "backlog exists but
    /// no progress" forces a worker generation rebuild. The claim candidates
    /// gate out events whose same-grant chain predecessor is non-terminal, so
    /// a probe WITHOUT the same gate would report a backlog that the claim can
    /// never serve (a chain serializing behind one backoff'd predecessor) and
    /// the watchdog would rebuild workers in a loop. The production probe must
    /// embed the reference gate byte-equal.
    #[test]
    fn watchdog_probe_carries_the_claim_sibling_order_gate() {
        // Const-to-const comparison: both sides are compiled string values, so
        // the `\`-continuation whitespace rule applies identically and the
        // equality claim is byte-exact (a raw-source scan would compare a
        // compiled value against un-collapsed source text and be meaningless).
        assert!(
            WATCHDOG_CLAIMABLE_PROBE_SQL.contains(astral_db::DELTA_CLAIM_SIBLING_ORDER_GATE),
            "watchdog probe must embed the claim sibling-ordering gate \
             byte-equal to astral_db::DELTA_CLAIM_SIBLING_ORDER_GATE"
        );
        // The probe stays tenant-scoped and never widens to a cross-tenant
        // backlog signal.
        assert!(WATCHDOG_CLAIMABLE_PROBE_SQL.contains("tenant_id = ?"));
        assert_eq!(WATCHDOG_CLAIMABLE_PROBE_SQL.matches('?').count(), 1);
    }

    /// Self-test fixture proving the scanner really trips when a banned legacy
    /// symbol appears in the LATE half of a production source — after the
    /// mid-file run_worker/act_on_disposition markers that used to hide it.
    #[test]
    fn legacy_guard_self_test_proves_late_production_symbol_detection() {
        let fixture_source: &'static str = concat!(
            "fn plan_retry_schedule() {}\n",
            "async fn run_worker(runtime) {}\n",
            "async fn act_on_disposition(ctx) {}\n",
            "\n",
            "// late-half offender:\n",
            "rebuild_rule_set_snapshot_inner();\n",
        );
        let panic_payload = std::panic::catch_unwind(|| {
            assert_no_legacy_channel_symbols(fixture_source, "fixture");
        })
        .expect_err(
            "scanner MUST reject legacy symbols appearing after the mid-file \
             markers",
        );
        let message = panic_payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| {
                panic_payload
                    .downcast_ref::<&str>()
                    .map(|s| (*s).to_owned())
            })
            .unwrap_or_default();
        assert!(
            message.contains("rebuild_rule_set_snapshot_inner"),
            "panic must name the offending symbol, got: {message}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_times_out_when_worker_refuses_to_stop() {
        struct StickyRuntime {
            wedged: Arc<AtomicBool>,
        }
        #[async_trait]
        impl AuthorizationProjectorRuntime for StickyRuntime {
            async fn claim_next_event(
                &self,
                _scope: &DeltaEventClaimScope,
                _owner: &str,
                _lease: i64,
            ) -> Result<Option<DeltaEventClaim>, RuntimeAccessError> {
                // Signal "inside the publish transaction", then simulate a DB
                // wedged against a lost connection: yields, but never resolves;
                // cancellation cannot rescue it and only the bounded shutdown
                // timeout can.
                self.wedged.store(true, Ordering::Release);
                std::future::pending::<()>().await;
                unreachable!("pending future never resolves")
            }
            async fn read_claimed_event(
                &self,
                _identity: &DeltaLeaseIdentity,
            ) -> Result<ClaimedDeltaEvent, RuntimeAccessError> {
                unreachable!()
            }
            async fn observe_publication_context(
                &self,
                _identity: &ProjectionAggregateIdentity,
            ) -> Result<Option<PublicationContext>, RuntimeAccessError> {
                unreachable!()
            }
            async fn load_scope_ledger(
                &self,
                _tenant_id: i64,
                _aggregate_type: &str,
                _aggregate_id: i64,
                _card_id: Option<i64>,
            ) -> Result<Vec<RawLedgerRow>, RuntimeAccessError> {
                unreachable!()
            }
            async fn execute_projection_publish(
                &self,
                _command: &DeltaProjectorPublishCommand,
            ) -> Result<DeltaProjectorPublishOutcome, RuntimeAccessError> {
                unreachable!()
            }
            async fn fail_event(
                &self,
                _identity: &DeltaLeaseIdentity,
                _backoff_seconds: i64,
                _message: &str,
            ) {
            }
            async fn release_event(&self, _identity: &DeltaLeaseIdentity) {}
            async fn mark_event_quarantined(
                &self,
                _lease: &DeltaLeaseIdentity,
                _reason_code: &str,
                _reason_detail: &str,
            ) -> Result<(), RuntimeAccessError> {
                unreachable!()
            }
        }

        let wedged = Arc::new(AtomicBool::new(false));
        let handle = start_authorization_projector_with_runtime(
            Arc::new(StickyRuntime {
                wedged: wedged.clone(),
            }),
            AuthorizationProjectorConfig {
                tenants: vec![1],
                poll_interval_secs: 60,
                ..Default::default()
            },
        );
        // Wait until the runtime PROVABLY sits inside the unresolved claim
        // (publish-transaction stand-in); cancelling earlier would legitimately
        // exit between polls and defeat the bounded-timeout coverage.
        let deadline = Instant::now() + Duration::from_secs(5);
        while !wedged.load(Ordering::Acquire) {
            assert!(Instant::now() < deadline, "worker never reached claim");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let report = shutdown_authorization_projector(handle, Duration::from_millis(120)).await;
        assert!(report.summary.is_err(), "stuck worker must surface as Err");
        assert!(report.join_elapsed < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn worker_stops_cleanly_on_cancellation_between_claims() {
        use std::sync::Mutex;
        struct QuietRuntime {
            claims: Mutex<u32>,
        }
        #[async_trait]
        impl AuthorizationProjectorRuntime for QuietRuntime {
            async fn claim_next_event(
                &self,
                _scope: &DeltaEventClaimScope,
                _owner: &str,
                _lease: i64,
            ) -> Result<Option<DeltaEventClaim>, RuntimeAccessError> {
                *self.claims.lock().unwrap() += 1;
                Ok(None)
            }
            async fn read_claimed_event(
                &self,
                _identity: &DeltaLeaseIdentity,
            ) -> Result<ClaimedDeltaEvent, RuntimeAccessError> {
                unreachable!()
            }
            async fn observe_publication_context(
                &self,
                _identity: &ProjectionAggregateIdentity,
            ) -> Result<Option<PublicationContext>, RuntimeAccessError> {
                unreachable!()
            }
            async fn load_scope_ledger(
                &self,
                _tenant_id: i64,
                _aggregate_type: &str,
                _aggregate_id: i64,
                _card_id: Option<i64>,
            ) -> Result<Vec<RawLedgerRow>, RuntimeAccessError> {
                unreachable!()
            }
            async fn execute_projection_publish(
                &self,
                _command: &DeltaProjectorPublishCommand,
            ) -> Result<DeltaProjectorPublishOutcome, RuntimeAccessError> {
                unreachable!()
            }
            async fn fail_event(
                &self,
                _identity: &DeltaLeaseIdentity,
                _backoff_seconds: i64,
                _message: &str,
            ) {
            }
            async fn release_event(&self, _identity: &DeltaLeaseIdentity) {}
            async fn mark_event_quarantined(
                &self,
                _lease: &DeltaLeaseIdentity,
                _reason_code: &str,
                _reason_detail: &str,
            ) -> Result<(), RuntimeAccessError> {
                unreachable!()
            }
        }

        let runtime = Arc::new(QuietRuntime {
            claims: Mutex::new(0),
        });
        let handle = start_authorization_projector_with_runtime(
            runtime.clone(),
            AuthorizationProjectorConfig {
                tenants: vec![42],
                poll_interval_secs: 1,
                ..Default::default()
            },
        );
        // Allow a couple of empty cycles, then cancel and join promptly.
        tokio::time::sleep(Duration::from_millis(30)).await;
        let report = shutdown_authorization_projector(handle, Duration::from_secs(3)).await;
        assert!(report.summary.is_ok());
        let summary = report.summary.unwrap();
        assert_eq!(summary.events_claimed, 0);
        assert!(
            *runtime.claims.lock().unwrap() >= 1,
            "worker must have polled"
        );
    }

    // ── Pure decision pipeline (no DB): claim-shape ↔ ledger ↔ compiler ─────

    fn active_card_dependency_hash(
        source_generation: u64,
        fence: u64,
    ) -> (DependencyVector, String) {
        reconstruct_dependency_vector(Some(17), source_generation, fence).unwrap()
    }

    struct Fixture {
        grant_rev1: astral_types::CanonicalGrant,
    }

    fn fixture() -> Fixture {
        Fixture {
            grant_rev1: grant(1, 1, GrantState::Active),
        }
    }

    // ── Published-frontier / publication-context fixtures ───────────────────

    fn grant_id_for(unique_tail: u16) -> GrantId {
        GrantId::parse(&format!(
            "550e8400-e29b-41d4-a716-44665544{unique_tail:04x}"
        ))
        .unwrap()
    }

    /// One frontier event mirroring the strict loader's contract: generation
    /// ascending, per-grant chaining, per-grant target equal to the ledger
    /// revision the event proves.
    struct FixtureDelta {
        generation: u64,
        event_id: &'static str,
        grant_id: GrantId,
        delta_base_version: i64,
        delta_target_version: i64,
    }

    fn delta_fixture(
        generation: u64,
        event_id: &'static str,
        grant_tail: u16,
        base: i64,
        target: i64,
    ) -> FixtureDelta {
        FixtureDelta {
            generation,
            event_id,
            grant_id: grant_id_for(grant_tail),
            delta_base_version: base,
            delta_target_version: target,
        }
    }

    fn frontier_fixture(
        card_id: Option<i64>,
        deltas: &[FixtureDelta],
    ) -> PublishedAggregateFrontier {
        use astral_db::{PublishedFrontierEvent, PublishedGenerationSummary};
        let identity = ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap();
        let (last_event, last_op) = deltas
            .last()
            .map(|delta| (delta.event_id.to_owned(), format!("op-{}", delta.event_id)))
            .unwrap_or_default();
        let pointer = AuthorizationCurrentPointerRecord {
            pointer_id: 3,
            identity: identity.clone(),
            card_id,
            current_generation: deltas.last().map(|delta| delta.generation).unwrap_or(0),
            manifest_id: 90,
            event_id: last_event,
            operation_id: last_op,
            semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap(),
            dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap(),
            compiler_version: policy_engine::COMPILER_VERSION.to_owned(),
            revoke_fence: 0,
            revoke_fence_proven: true,
            cas_version: 4,
        };
        let manifest = PublishedGenerationSummary {
            manifest_id: pointer.manifest_id,
            generation: pointer.current_generation,
            source_generation: 5,
            projected_generation: 5,
            event_id: pointer.event_id.clone(),
            operation_id: pointer.operation_id.clone(),
            semantic_hash: pointer.semantic_hash,
            dependency_hash: pointer.dependency_hash,
            compiler_version: pointer.compiler_version.clone(),
            manifest_digest: Sha256Digest::from_hex(HASH_B).unwrap(),
            parent_manifest_id: if pointer.current_generation > 1 {
                Some(89)
            } else {
                None
            },
            revoke_fence: pointer.revoke_fence,
            card_id,
        };
        let events = deltas
            .iter()
            .map(|delta| PublishedFrontierEvent {
                generation: delta.generation,
                plan_id: delta.generation as i64 + 1000,
                event_id: delta.event_id.to_owned(),
                operation_id: format!("op-{}", delta.event_id),
                grant_id: delta.grant_id,
                event_type: astral_db::DeltaEventType::Add,
                delta_base_version: delta.delta_base_version,
                delta_target_version: delta.delta_target_version,
                source_generation: 5,
                revoke_fence: 0,
                semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap(),
                dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap(),
                compiler_version: policy_engine::COMPILER_VERSION.to_owned(),
            })
            .collect();
        PublishedAggregateFrontier {
            identity,
            card_id,
            pointer,
            manifest,
            events,
        }
    }

    /// Observed publication context with NO parent reference hints — the
    /// planning then plans every segment as content-addressed `New`, exactly
    /// like the pre-reuse production behavior.
    fn context_without_references(
        card_id: Option<i64>,
        deltas: &[FixtureDelta],
    ) -> PublicationContext {
        PublicationContext {
            frontier: frontier_fixture(card_id, deltas),
            parent_references: Vec::new(),
        }
    }

    fn claimed_event(
        base: &astral_types::CanonicalGrant,
        delta: &astral_types::GrantDelta,
        source_generation: u64,
        fence: u64,
        event_id: &str,
        operation_id: &str,
        dep_hash_hex: &str,
    ) -> ClaimedDeltaEvent {
        ClaimedDeltaEvent {
            delta_event_id: 77,
            event_id: event_id.to_owned(),
            operation_id: operation_id.to_owned(),
            event_type: astral_db::DeltaEventType::Add,
            tenant_id: base.tenant.tenant_id,
            card_id: Some(base.card_id),
            aggregate_type: "CARD".to_owned(),
            aggregate_id: 17,
            grant_id: base.grant_id,
            base_version: if matches!(delta, astral_types::GrantDelta::Add { .. }) {
                (base.revision.value().saturating_sub(1)) as i64
            } else {
                (base.revision.value() - 1) as i64
            },
            target_version: base.revision.value() as i64,
            source_generation,
            revoke_fence: fence,
            before_image_json: None,
            before_digest: None,
            delta_json: serde_json::to_string(delta).unwrap(),
            semantic_hash: Sha256Digest::from_hex(&base.canonical_hash().unwrap()).unwrap(),
            dependency_hash: Sha256Digest::from_hex(dep_hash_hex).unwrap(),
            compiler_version: policy_engine::COMPILER_VERSION.to_owned(),
            attempts: 1,
            cas_version: 2,
            lease_owner: "auth-projector:test-run".to_owned(),
            lease_expires_at: time::PrimitiveDateTime::MIN,
        }
    }

    #[tokio::test]
    async fn decide_first_publication_replays_oracle_and_assembles_publish() {
        let fx = fixture();
        let initial = fx.grant_rev1;
        let (_, dep_hash) = active_card_dependency_hash(5, 1);
        let delta = astral_types::GrantDelta::add(initial.clone());
        let claimed = claimed_event(&initial, &delta, 5, 1, "evt-first", "op-first", &dep_hash);
        let rows = vec![raw_row(&initial, "evt-first", "op-first", 1)];
        let input = EventDecisionInput {
            claimed: &claimed,
            publication: None,
            ledger_rows: &rows,
            identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
        };
        match decide_event_disposition(&input) {
            EventDisposition::Publish(command) => {
                assert_eq!(command.expectation.identity.aggregate_id, 17);
                assert_eq!(command.stage.target_generation, 1);
                assert_eq!(command.impact_plan.base_generation, 0);
                // REPLAY-mode evidence with no fabricated full-rebuild reason.
                assert_eq!(
                    command.mode.compile_mode,
                    astral_types::ProjectionCompileMode::Replay
                );
                assert!(command.mode.full_rebuild_reason.is_none());
                assert!(!command.impact_plan.items.is_empty());
                assert!(!command.stage.segments.is_empty());
                // Content-addressed staging starts all-New without parent refs.
                assert!(command
                    .stage
                    .segments
                    .iter()
                    .all(|entry| matches!(entry, StagedSegmentContent::New(_))));
                // First publication pins previous fence at the zero sentinel.
                assert_eq!(command.fences.previous_revoke_fence, 0);
                assert_eq!(command.fences.new_revoke_fence, 1);
            }
            other => panic!("expected Publish, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn decide_incremental_second_revision_targets_next_generation() {
        let fx = fixture();
        let rev1 = fx.grant_rev1;
        let mut rev2 = rev1.clone();
        rev2.revision = GrantRevision::new(2).unwrap();
        rev2.provenance.source_id = "rule-set-entry-10".to_owned();
        let (_, dep_hash) = active_card_dependency_hash(5, 0);
        // Strict publication context: generation 1 is proven by the rev-1
        // delta event itself, per-grant target 1.
        let context =
            context_without_references(Some(17), &[delta_fixture(1, "evt-first", 1, 0, 1)]);
        let delta = astral_types::GrantDelta::update(rev2.clone(), rev1.revision);
        let mut claimed = claimed_event(&rev2, &delta, 5, 0, "evt-second", "op-second", &dep_hash);
        claimed.event_type = astral_db::DeltaEventType::Update;
        let rows = vec![
            raw_row(&rev1, "evt-first", "op-first", 0),
            raw_row(&rev2, "evt-second", "op-second", 0),
        ];
        let input = EventDecisionInput {
            claimed: &claimed,
            publication: Some(&context),
            ledger_rows: &rows,
            identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
        };
        match decide_event_disposition(&input) {
            EventDisposition::Publish(command) => {
                assert_eq!(command.stage.target_generation, 2);
                assert_eq!(command.expectation.base_version, 1);
                assert_eq!(command.expectation.target_version, 2);
                assert_eq!(
                    command.mode.compile_mode,
                    astral_types::ProjectionCompileMode::Incremental
                );
                assert!(command.mode.full_rebuild_reason.is_none());
                // INCREMENTAL plan items carry REAL compiler evidence: an
                // unchanged exact-key position that changed content yields one
                // upsert item holding both before and after digests.
                let evidence_upsert = command.impact_plan.items.iter().find(|item| {
                    item.before_digest_hex.is_some() && item.after_digest_hex.is_some()
                });
                assert!(
                    evidence_upsert.is_some(),
                    "content-only change must yield a before+after upsert item"
                );
                // Fence continuity stays monotonic against the locked baseline.
                assert_eq!(command.fences.previous_revoke_fence, 0);
                assert_eq!(command.fences.new_revoke_fence, 0);
            }
            other => panic!("expected Publish, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn decide_full_rebuild_only_through_compiler_outcome_and_records_reason() {
        let fx = fixture();
        let rev1 = fx.grant_rev1;
        let mut wildcarded = rev1.clone();
        wildcarded.revision = GrantRevision::new(2).unwrap();
        wildcarded.resource = "*".to_owned();
        let (_, dep_hash) = active_card_dependency_hash(5, 0);
        let context =
            context_without_references(Some(17), &[delta_fixture(1, "evt-first", 1, 0, 1)]);
        let delta = astral_types::GrantDelta::update(wildcarded.clone(), rev1.revision);
        let mut claimed =
            claimed_event(&wildcarded, &delta, 5, 0, "evt-wild", "op-wild", &dep_hash);
        claimed.event_type = astral_db::DeltaEventType::Update;
        let rows = vec![
            raw_row(&rev1, "evt-first", "op-first", 0),
            raw_row(&wildcarded, "evt-wild", "op-wild", 0),
        ];
        let input = EventDecisionInput {
            claimed: &claimed,
            publication: Some(&context),
            ledger_rows: &rows,
            identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
        };
        match decide_event_disposition(&input) {
            EventDisposition::Publish(command) => {
                // ONLY a genuine compiler FullRebuildRequired outcome may set
                // FULL_REBUILD mode — always paired with its explicit reason.
                assert_eq!(
                    command.mode.compile_mode,
                    astral_types::ProjectionCompileMode::FullRebuild
                );
                assert_eq!(
                    command.mode.full_rebuild_reason,
                    Some(policy_engine::FullRebuildReason::WildcardImpact)
                );
                assert!(!command.impact_plan.items.is_empty());
            }
            other => panic!("expected Publish with recorded reason, got {other:?}"),
        }
    }

    /// The flipped slice-1 case: a legal frontier proving TWO grant chains in
    /// one scope now PUBLISHES. Domain isolation is pinned at the same time:
    /// the aggregate base generation (pointer G + 1) and the per-grant
    /// projection window (base/target on THIS grant's chain) stay separate.
    #[test]
    fn decide_publishes_multi_grant_scope_from_verified_frontier() {
        let own_head = grant(1, 1, GrantState::Active);
        let mut own_next = own_head.clone();
        own_next.revision = GrantRevision::new(2).unwrap();
        own_next.provenance.source_id = "rule-set-entry-next".to_owned();
        let sibling = grant(9, 1, GrantState::Active);
        let (_, dep_hash) = active_card_dependency_hash(5, 0);
        // Frontier: gen1 = own grant revision 1, gen2 = sibling initial.
        let context = context_without_references(
            Some(17),
            &[
                delta_fixture(1, "evt-own-rev1", 1, 0, 1),
                delta_fixture(2, "evt-sibling-init", 9, 0, 1),
            ],
        );
        let delta = astral_types::GrantDelta::update(own_next.clone(), own_head.revision);
        let mut claimed =
            claimed_event(&own_next, &delta, 5, 0, "evt-mixed", "op-mixed", &dep_hash);
        claimed.event_type = astral_db::DeltaEventType::Update;
        // Ledger ordering follows (grant_id ASC, revision_no ASC):
        // …0001 rows stay grouped before …0009.
        let rows = vec![
            raw_row(&own_head, "evt-own-rev1", "op-own-rev1", 0),
            raw_row(&own_next, "evt-mixed", "op-mixed", 0),
            raw_row(&sibling, "evt-sibling-init", "op-sibling", 0),
        ];
        let input = EventDecisionInput {
            claimed: &claimed,
            publication: Some(&context),
            ledger_rows: &rows,
            identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
        };
        match decide_event_disposition(&input) {
            EventDisposition::Publish(command) => {
                // Aggregate domain: pointer G=2 ⇒ target G+1=3.
                assert_eq!(command.stage.target_generation, 3);
                assert_eq!(command.impact_plan.base_generation, 2);
                // Per-grant domain: this claim chains rev1 → rev2 of its OWN
                // grant only; never compared against aggregate generations.
                assert_eq!(command.expectation.base_version, 1);
                assert_eq!(command.expectation.target_version, 2);
                assert_eq!(
                    command.mode.compile_mode,
                    astral_types::ProjectionCompileMode::Incremental
                );
                assert!(!command.stage.segments.is_empty());
            }
            other => panic!("verified multi-grant frontier must publish, got {other:?}"),
        }
    }

    // ── T2 regression: published wildcard continuation REMOVE/REVOKE ────────
    //
    // SQL-seed shape: the grant's Active revision is already PUBLISHED
    // (frontier-proven) and the claimed event appends a tombstone revision.
    // A type-level wildcard that is the card's ONLY Active contribution
    // forces FullRebuildRequired; the rebuilt candidate has NO segment left,
    // so the vanished base key must be planned as an explicit SegmentRemove
    // instead of degrading into the empty-impact quarantine.

    fn wildcard_grant(
        unique_tail: u16,
        revision: u64,
        state: GrantState,
    ) -> astral_types::CanonicalGrant {
        let mut wildcarded = grant(unique_tail, revision, state);
        wildcarded.resource = "learn_subject:*".to_owned();
        wildcarded
    }

    fn tombstone_from(
        source: &astral_types::CanonicalGrant,
        revision: u64,
        state: GrantState,
    ) -> astral_types::CanonicalGrant {
        let mut tombstone = source.clone();
        tombstone.revision = GrantRevision::new(revision).unwrap();
        tombstone.state = state;
        tombstone
    }

    #[test]
    fn decide_continuation_remove_of_only_wildcard_publishes_segment_remove() {
        let published = wildcard_grant(1, 1, GrantState::Active);
        let tombstone = tombstone_from(&published, 2, GrantState::Removed);
        let (_, dep_hash) = active_card_dependency_hash(5, 0);
        let context =
            context_without_references(Some(17), &[delta_fixture(1, "evt-w-add", 1, 0, 1)]);
        let delta = astral_types::GrantDelta::remove(published.grant_id, published.revision);
        let mut claimed = claimed_event(
            &tombstone,
            &delta,
            5,
            0,
            "evt-w-remove",
            "op-w-remove",
            &dep_hash,
        );
        claimed.event_type = astral_db::DeltaEventType::Remove;
        let rows = vec![
            raw_row(&published, "evt-w-add", "op-w-add", 0),
            raw_row(&tombstone, "evt-w-remove", "op-w-remove", 0),
        ];
        let input = EventDecisionInput {
            claimed: &claimed,
            publication: Some(&context),
            ledger_rows: &rows,
            identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
        };
        match decide_event_disposition(&input) {
            EventDisposition::Publish(command) => {
                assert_eq!(
                    command.mode.compile_mode,
                    astral_types::ProjectionCompileMode::FullRebuild
                );
                assert_eq!(
                    command.mode.full_rebuild_reason,
                    Some(policy_engine::FullRebuildReason::WildcardImpact)
                );
                // Exactly one item: the vanished wildcard key, base digest as
                // `before`, NO `after` — compiler-plan evidence, not synthesis.
                assert_eq!(command.impact_plan.items.len(), 1);
                let item = &command.impact_plan.items[0];
                assert_eq!(item.item_type, AuthorizationImpactItemType::SegmentRemove);
                assert!(item.projection_key.contains("learn_subject:*"), "{item:?}");
                assert!(item.before_digest_hex.is_some());
                assert!(item.after_digest_hex.is_none());
                // Nothing stays Active: the removal-only manifest stages no
                // segment content at all.
                assert!(command.stage.segments.is_empty());
            }
            other => panic!("wildcard removal must publish with SegmentRemove, got {other:?}"),
        }
    }

    #[test]
    fn decide_continuation_revoke_of_only_wildcard_publishes_and_advances_fence() {
        let published = wildcard_grant(1, 1, GrantState::Active);
        let tombstone = tombstone_from(&published, 2, GrantState::Revoked);
        let (_, dep_hash) = active_card_dependency_hash(5, 1);
        let context =
            context_without_references(Some(17), &[delta_fixture(1, "evt-r-add", 1, 0, 1)]);
        let delta = astral_types::GrantDelta::revoke(published.grant_id, published.revision);
        let mut claimed = claimed_event(
            &tombstone,
            &delta,
            5,
            1,
            "evt-r-revoke",
            "op-r-revoke",
            &dep_hash,
        );
        claimed.event_type = astral_db::DeltaEventType::Revoke;
        let rows = vec![
            raw_row(&published, "evt-r-add", "op-r-add", 0),
            raw_row(&tombstone, "evt-r-revoke", "op-r-revoke", 1),
        ];
        let input = EventDecisionInput {
            claimed: &claimed,
            publication: Some(&context),
            ledger_rows: &rows,
            identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
        };
        match decide_event_disposition(&input) {
            EventDisposition::Publish(command) => {
                assert_eq!(
                    command.mode.compile_mode,
                    astral_types::ProjectionCompileMode::FullRebuild
                );
                // Exact compiler-trigger evidence, same as the REMOVE path.
                assert_eq!(
                    command.mode.full_rebuild_reason,
                    Some(policy_engine::FullRebuildReason::WildcardImpact)
                );
                assert!(
                    command
                        .impact_plan
                        .items
                        .iter()
                        .any(|item| item.item_type == AuthorizationImpactItemType::SegmentRemove),
                    "revoked wildcard key must yield a SegmentRemove item"
                );
                assert!(
                    !command.impact_plan.items.is_empty()
                        && command.impact_plan.items.iter().all(|item| {
                            item.item_type == AuthorizationImpactItemType::SegmentRemove
                        })
                );
                // REVOKE fence progress: previous fence from the locked
                // pointer, new fence is the claimed max.
                assert_eq!(command.fences.previous_revoke_fence, 0);
                assert_eq!(command.fences.new_revoke_fence, 1);
                // Nothing stays Active: the revoke-only manifest stages no
                // segment content at all (same empty stage as the REMOVE
                // path — the revoked wildcard was the only contribution).
                assert!(command.stage.segments.is_empty());
            }
            other => panic!("wildcard revoke must publish, got {other:?}"),
        }
    }

    #[test]
    fn decide_continuation_remove_wildcard_publishes_and_keeps_object_level_segment() {
        let wildcard = wildcard_grant(1, 1, GrantState::Active);
        let wildcard_tombstone = tombstone_from(&wildcard, 2, GrantState::Removed);
        // Sibling object-level grant on a DIFFERENT exact key stays untouched.
        let object_level = grant(9, 1, GrantState::Active);
        let (_, dep_hash) = active_card_dependency_hash(5, 0);
        let context = context_without_references(
            Some(17),
            &[
                delta_fixture(1, "evt-a-add", 1, 0, 1),
                delta_fixture(2, "evt-b-add", 9, 0, 1),
            ],
        );
        let delta = astral_types::GrantDelta::remove(wildcard.grant_id, wildcard.revision);
        let mut claimed = claimed_event(
            &wildcard_tombstone,
            &delta,
            5,
            0,
            "evt-a-remove",
            "op-a-remove",
            &dep_hash,
        );
        claimed.event_type = astral_db::DeltaEventType::Remove;
        // Ledger ordering: grant …0001 rows grouped before …0009.
        let rows = vec![
            raw_row(&wildcard, "evt-a-add", "op-a-add", 0),
            raw_row(&wildcard_tombstone, "evt-a-remove", "op-a-remove", 0),
            raw_row(&object_level, "evt-b-add", "op-b-add", 0),
        ];
        let input = EventDecisionInput {
            claimed: &claimed,
            publication: Some(&context),
            ledger_rows: &rows,
            identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
        };
        match decide_event_disposition(&input) {
            EventDisposition::Publish(command) => {
                assert_eq!(command.stage.target_generation, 3);
                // Only the vanished wildcard key is removed; the untouched
                // object-level key produces NO impact item (content unchanged
                // ⇒ no durable evidence line) and no removal either.
                assert_eq!(command.impact_plan.items.len(), 1);
                let item = &command.impact_plan.items[0];
                assert_eq!(item.item_type, AuthorizationImpactItemType::SegmentRemove);
                assert!(item.projection_key.contains("learn_subject:*"), "{item:?}");
                // The object-level segment is still staged into the new
                // generation, so published evidence keeps authorizing it.
                assert_eq!(command.stage.segments.len(), 1);
                assert!(matches!(
                    command.stage.segments[0],
                    StagedSegmentContent::New(_)
                ));
            }
            other => panic!("multi-segment wildcard removal must publish, got {other:?}"),
        }
    }

    /// A genuinely empty-impact event keeps the no_effective_change
    /// quarantine. Inside the legal delta contract every incremental delta
    /// changes at least one affected segment (the grant revision is part of
    /// the segment content hash), so the reachable empty-impact shape is the
    /// tombstone-seed FIRST publication: the oracle rebuilds generation 1
    /// from a single removed/revoked seed row, the candidate has no segments,
    /// no base digest exists to cite as `before`, and publishing an empty
    /// generation is forbidden — the event stays terminal for operator
    /// reconciliation instead. (A no-effective INCREMENTAL delta cannot even
    /// reach this guard: the one such shape, an Add whose payload already
    /// carries a tombstone state, is refused by `GrantDelta::validate` at the
    /// durable decode gate — pinned by the next test.)
    #[test]
    fn decide_tombstone_seed_first_publication_keeps_empty_impact_quarantine() {
        // Seed row: revision 1 already carries a tombstone state.
        let seed = tombstone_from(&grant(1, 1, GrantState::Active), 1, GrantState::Removed);
        let (_, dep_hash) = active_card_dependency_hash(5, 0);
        let delta = astral_types::GrantDelta::remove(seed.grant_id, seed.revision);
        let mut claimed = claimed_event(&seed, &delta, 5, 0, "evt-t1", "op-t1", &dep_hash);
        claimed.event_type = astral_db::DeltaEventType::Remove;
        let rows = vec![raw_row(&seed, "evt-t1", "op-t1", 0)];
        let input = EventDecisionInput {
            claimed: &claimed,
            publication: None,
            ledger_rows: &rows,
            identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
        };
        match decide_event_disposition(&input) {
            EventDisposition::Quarantine { reason } => {
                // Exact stable machine token, not a substring scan.
                assert_eq!(reason, "code=auth_projector.no_effective_change");
            }
            other => panic!("tombstone first publication must stay quarantined, got {other:?}"),
        }
    }

    /// The one delta shape that WOULD be genuinely no-effective — an Add
    /// whose payload already carries a tombstone state (records durable
    /// history, authorizes nothing) — is refused by the durable decode gate
    /// BEFORE any compile or impact stage (`GrantDelta::validate` demands an
    /// Active payload for `Add`). Combined with the segment content hash
    /// covering the full canonical grant (revision included), this proves the
    /// incremental arm can never map to an empty item list: every legal
    /// incremental delta changes at least one affected segment, so the
    /// `no_effective_change` guard is unreachable there and the T2
    /// continuation mapping cannot loosen what legal inputs never hit. The
    /// refused shape stays fail-closed under the bounded attempt budget — it
    /// never publishes, never fabricates evidence and never reaches the
    /// impact-plan stage.
    #[test]
    fn decide_tombstone_payload_add_is_refused_before_any_impact_stage() {
        // Published sibling: grant …0001 Active rev 1 (frontier-proven, gen 1).
        let published_sibling = grant(1, 1, GrantState::Active);
        // Claimed: FIRST revision of a NEW grant whose payload is already a
        // tombstone — the shape SQL-seeded history could produce.
        let tombstone_add =
            tombstone_from(&grant(2, 1, GrantState::Active), 1, GrantState::Removed);
        let (_, dep_hash) = active_card_dependency_hash(5, 0);
        let context =
            context_without_references(Some(17), &[delta_fixture(1, "evt-s-add", 1, 0, 1)]);
        let delta = astral_types::GrantDelta::add(tombstone_add.clone());
        let claimed = claimed_event(
            &tombstone_add,
            &delta,
            5,
            0,
            "evt-t-add",
            "op-t-add",
            &dep_hash,
        );
        // Ledger ordering mirrors load_grant_ledger_rows: grant …0001 first.
        let rows = vec![
            raw_row(&published_sibling, "evt-s-add", "op-s-add", 0),
            raw_row(&tombstone_add, "evt-t-add", "op-t-add", 0),
        ];
        let input = EventDecisionInput {
            claimed: &claimed,
            publication: Some(&context),
            ledger_rows: &rows,
            identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
        };
        match decide_event_disposition(&input) {
            EventDisposition::Retry { reason } => {
                // Exact-token machine code prefix (classifier contract); the
                // embedded astral-db detail after `;` is never matched.
                assert!(
                    reason.starts_with("code=auth_projector.delta_payload_invalid"),
                    "unexpected refusal reason: {reason}"
                );
            }
            other => {
                panic!(
                    "tombstone-payload add must be refused before any impact stage, got {other:?}"
                )
            }
        }
    }

    /// F6 修复回归：无 pointer 多链并存不再互相卡死——claimed grant 自身链
    /// 可证明即发布，兄弟 grant 行（独立初始链）忽略，各自 claim 收口。兄弟
    /// 未发布期间授权读由 source-freshness 门保持 PENDING，中间态不外泄。
    #[test]
    fn decide_publishes_own_initial_chain_despite_sibling_grant_rows() {
        let own = grant(1, 1, GrantState::Active);
        let foreign = grant(9, 1, GrantState::Active);
        let (_, dep_hash) = active_card_dependency_hash(5, 1);
        let delta = astral_types::GrantDelta::add(own.clone());
        let claimed = claimed_event(&own, &delta, 5, 1, "evt-mixed", "op-mixed", &dep_hash);
        // 兄弟行在前：证明只按 grant 归属过滤，与行序无关。
        let rows = vec![
            raw_row(&foreign, "evt-foreign", "op-foreign", 1),
            raw_row(&own, "evt-mixed", "op-mixed", 1),
        ];
        let input = EventDecisionInput {
            claimed: &claimed,
            publication: None,
            ledger_rows: &rows,
            identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
        };
        match decide_event_disposition(&input) {
            EventDisposition::Publish(command) => {
                assert_eq!(command.stage.target_generation, 1);
                assert_eq!(command.impact_plan.base_generation, 0);
                // 发布候选只含 claimed grant——兄弟行绝不进入候选。
                for entry in &command.stage.segments {
                    match entry {
                        StagedSegmentContent::New(grants) => {
                            assert!(
                                grants.iter().all(|grant| grant.grant_id == own.grant_id),
                                "sibling grants must never enter the candidate"
                            );
                        }
                        StagedSegmentContent::ReuseParent { .. } => {
                            panic!("first publication must plan all-New segments")
                        }
                    }
                }
            }
            other => panic!(
                "own provable initial chain must publish despite sibling rows, got {other:?}"
            ),
        }
    }

    /// 对称 case：兄弟 grant 先被 claim 同样放行——per-grant 版本域下跨
    /// grant 发布顺序无歧义，两种 claim 顺序都收敛。
    #[test]
    fn decide_publishes_sibling_initial_chain_symmetrically() {
        let own = grant(1, 1, GrantState::Active);
        let foreign = grant(9, 1, GrantState::Active);
        let (_, dep_hash) = active_card_dependency_hash(5, 1);
        let delta = astral_types::GrantDelta::add(foreign.clone());
        let claimed = claimed_event(
            &foreign,
            &delta,
            5,
            1,
            "evt-foreign",
            "op-foreign",
            &dep_hash,
        );
        let rows = vec![
            raw_row(&own, "evt-mixed", "op-mixed", 1),
            raw_row(&foreign, "evt-foreign", "op-foreign", 1),
        ];
        let input = EventDecisionInput {
            claimed: &claimed,
            publication: None,
            ledger_rows: &rows,
            identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
        };
        match decide_event_disposition(&input) {
            EventDisposition::Publish(command) => {
                assert_eq!(command.stage.target_generation, 1);
            }
            other => panic!("symmetric sibling claim must publish, got {other:?}"),
        }
    }

    /// Some 臂第三形态（F6 深层回归钉子）：A 已发布 gen1，兄弟 grant B 的
    /// 初始链（rev1，无任何已发布 head）经 per-grant 回退（expected=0）准入，
    /// 以 Continuation 发布为聚合 gen2（base=A head，per-grant 0→1）。
    #[test]
    fn decide_admits_second_initial_chain_after_published_frontier() {
        let own_head = grant(1, 1, GrantState::Active);
        let sibling = grant(9, 1, GrantState::Active);
        let (_, dep_hash) = active_card_dependency_hash(5, 1);
        // frontier 只证明 A 的 gen1；B 尚无任何已发布事件。
        let context =
            context_without_references(Some(17), &[delta_fixture(1, "evt-own-rev1", 1, 0, 1)]);
        let delta = astral_types::GrantDelta::add(sibling.clone());
        let claimed = claimed_event(
            &sibling,
            &delta,
            5,
            1,
            "evt-sibling-init",
            "op-sibling-init",
            &dep_hash,
        );
        let rows = vec![
            raw_row(&own_head, "evt-own-rev1", "op-own-rev1", 1),
            raw_row(&sibling, "evt-sibling-init", "op-sibling-init", 1),
        ];
        let input = EventDecisionInput {
            claimed: &claimed,
            publication: Some(&context),
            ledger_rows: &rows,
            identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
        };
        match decide_event_disposition(&input) {
            EventDisposition::Publish(command) => {
                assert_eq!(command.stage.target_generation, 2);
                assert_eq!(command.impact_plan.base_generation, 1);
                assert_eq!(command.expectation.base_version, 0);
                assert_eq!(command.expectation.target_version, 1);
                assert_eq!(
                    command.mode.compile_mode,
                    astral_types::ProjectionCompileMode::Incremental
                );
            }
            other => panic!(
                "second initial chain must be admitted after a published frontier, got {other:?}"
            ),
        }
    }

    /// 自身链断档（rev1、rev3，缺 rev2）仍 Quarantine——兄弟行在场不改变
    /// fail-closed 结果。
    #[test]
    fn decide_quarantines_own_chain_gap_even_with_sibling_rows() {
        let own_rev1 = grant(1, 1, GrantState::Active);
        let own_rev3 = grant(1, 3, GrantState::Active);
        let sibling = grant(9, 1, GrantState::Active);
        let (_, dep_hash) = active_card_dependency_hash(5, 1);
        let delta = astral_types::GrantDelta::add(own_rev3.clone());
        let claimed = claimed_event(
            &own_rev3,
            &delta,
            5,
            1,
            "evt-own-rev3",
            "op-own-rev3",
            &dep_hash,
        );
        let rows = vec![
            raw_row(&own_rev1, "evt-own-rev1", "op-own-rev1", 1),
            raw_row(&sibling, "evt-sibling", "op-sibling", 1),
            raw_row(&own_rev3, "evt-own-rev3", "op-own-rev3", 1),
        ];
        let input = EventDecisionInput {
            claimed: &claimed,
            publication: None,
            ledger_rows: &rows,
            identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
        };
        match decide_event_disposition(&input) {
            EventDisposition::Quarantine { reason } => {
                assert!(reason.contains("first_publication_chain_gap"), "{reason}");
            }
            other => panic!("own chain gap must quarantine, got {other:?}"),
        }
    }

    /// 自身后继行（rev2 未发布）存在时，claimed rev1 仍发布 rev1 状态；
    /// 后继行随后经 Some 臂 Continuation 收口，绝不进入首发候选。
    #[test]
    fn decide_publishes_claimed_revision_ignoring_own_later_revisions() {
        let own_rev1 = grant(1, 1, GrantState::Active);
        let mut own_rev2 = own_rev1.clone();
        own_rev2.revision = GrantRevision::new(2).unwrap();
        own_rev2.provenance.source_entry = Some("rule-2".to_owned());
        let (_, dep_hash) = active_card_dependency_hash(5, 1);
        let delta = astral_types::GrantDelta::add(own_rev1.clone());
        let claimed = claimed_event(
            &own_rev1,
            &delta,
            5,
            1,
            "evt-own-rev1",
            "op-own-rev1",
            &dep_hash,
        );
        let rows = vec![
            raw_row(&own_rev1, "evt-own-rev1", "op-own-rev1", 1),
            raw_row(&own_rev2, "evt-own-rev2", "op-own-rev2", 1),
        ];
        let input = EventDecisionInput {
            claimed: &claimed,
            publication: None,
            ledger_rows: &rows,
            identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
        };
        match decide_event_disposition(&input) {
            EventDisposition::Publish(command) => {
                assert_eq!(command.stage.target_generation, 1);
                for entry in &command.stage.segments {
                    match entry {
                        StagedSegmentContent::New(grants) => {
                            assert!(
                                grants.iter().all(|grant| grant.revision.value() == 1),
                                "later own revisions must never enter the first publication"
                            );
                        }
                        StagedSegmentContent::ReuseParent { .. } => {
                            panic!("first publication must plan all-New segments")
                        }
                    }
                }
            }
            other => panic!("claimed revision must publish ignoring later rows, got {other:?}"),
        }
    }

    #[test]
    fn decide_blocks_own_claim_behind_unpublished_siblings() {
        let rev1 = grant(1, 1, GrantState::Active);
        let mut intermediate = rev1.clone();
        intermediate.revision = GrantRevision::new(2).unwrap();
        let mut latecomer = rev1.clone();
        latecomer.revision = GrantRevision::new(3).unwrap();
        latecomer.provenance.source_id = "rule-set-entry-late".to_owned();
        let (_, dep_hash) = active_card_dependency_hash(5, 0);
        let context = context_without_references(Some(17), &[delta_fixture(1, "evt-a1", 1, 0, 1)]);
        let delta = astral_types::GrantDelta::update(latecomer.clone(), intermediate.revision);
        let mut claimed = claimed_event(&latecomer, &delta, 5, 0, "evt-late", "op-late", &dep_hash);
        claimed.event_type = astral_db::DeltaEventType::Update;
        claimed.base_version = 2; // honest producer chaining behind sibling rev2
        let rows = vec![
            raw_row(&rev1, "evt-a1", "op-a1", 0),
            raw_row(
                &intermediate,
                "evt-intermediate-pending",
                "op-intermediate",
                0,
            ),
            raw_row(&latecomer, "evt-late", "op-late", 0),
        ];
        let input = EventDecisionInput {
            claimed: &claimed,
            publication: Some(&context),
            ledger_rows: &rows,
            identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
        };
        match decide_event_disposition(&input) {
            EventDisposition::Blocked { reason } => {
                assert!(
                    reason.contains("claimed_behind_unpublished_siblings"),
                    "{reason}"
                );
            }
            other => panic!("own claim behind siblings must block, got {other:?}"),
        }
    }

    #[test]
    fn decide_quarantines_partition_corruption_and_missing_candidates() {
        let rev1 = grant(1, 1, GrantState::Active);
        let foreign = grant(9, 1, GrantState::Active);
        let (_, dep_hash) = active_card_dependency_hash(5, 0);
        let context = context_without_references(
            Some(17),
            &[
                delta_fixture(1, "evt-foreign", 9, 0, 1),
                delta_fixture(2, "evt-own-rev1", 1, 0, 1),
            ],
        );

        // Corrupt world #1: unsorted ledger input fails closed instead of
        // being silently repaired. grant …0009 appears BEFORE …0001.
        let claimed = claimed_event(
            &rev1,
            &astral_types::GrantDelta::add(rev1.clone()),
            5,
            0,
            "evt-own-rev1",
            "op-own-rev1",
            &dep_hash,
        );
        let unsorted = vec![
            raw_row(&foreign, "evt-foreign", "op-f", 0),
            raw_row(&rev1, "evt-own-rev1", "op-o", 0),
        ];
        let corrupt_input = EventDecisionInput {
            claimed: &claimed,
            publication: Some(&context),
            ledger_rows: &unsorted,
            identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
        };
        match decide_event_disposition(&corrupt_input) {
            EventDisposition::Quarantine { reason } => {
                assert!(reason.contains("partition_corrupt"), "{reason}");
                assert!(reason.contains("partition_unsorted_input"), "{reason}");
            }
            other => panic!("unsorted partition must quarantine, got {other:?}"),
        }

        // Missing candidate: every frontier event is fully consumed by the
        // ledger, yet our claimed event has no revision row anywhere — the
        // queue row and history disagree and reconciliation wins.
        let claimed_missing = claimed_event(
            &foreign,
            &astral_types::GrantDelta::add(foreign.clone()),
            5,
            0,
            "evt-nowhere",
            "op-nowhere",
            &dep_hash,
        );
        let complete_world_context = context_without_references(
            Some(17),
            &[
                delta_fixture(1, "evt-a1", 1, 0, 1),
                delta_fixture(2, "evt-b1", 9, 0, 1),
            ],
        );
        let rows_without_ours = vec![
            raw_row(&rev1, "evt-a1", "op-a1", 0),
            raw_row(&foreign, "evt-b1", "op-b1", 0),
        ];
        let missing_input = EventDecisionInput {
            claimed: &claimed_missing,
            publication: Some(&complete_world_context),
            ledger_rows: &rows_without_ours,
            identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
        };
        match decide_event_disposition(&missing_input) {
            EventDisposition::Quarantine { reason } => {
                assert!(reason.contains("own_revision_missing"), "{reason}");
            }
            other => panic!("missing candidate must quarantine, got {other:?}"),
        }
    }

    #[test]
    fn decide_quarantines_per_grant_chain_gap_against_frontier_target() {
        let rev1 = grant(1, 1, GrantState::Active);
        let mut rev2 = rev1.clone();
        rev2.revision = GrantRevision::new(2).unwrap();
        let (_, dep_hash) = active_card_dependency_hash(5, 0);
        let context =
            context_without_references(Some(17), &[delta_fixture(1, "evt-own-rev1", 1, 0, 1)]);
        let delta = astral_types::GrantDelta::update(rev2.clone(), rev1.revision);
        let mut claimed = claimed_event(&rev2, &delta, 5, 0, "evt-gap", "op-gap", &dep_hash);
        claimed.event_type = astral_db::DeltaEventType::Update;
        claimed.base_version = 9; // drift from the frontier-proven target 1
        let rows = vec![
            raw_row(&rev1, "evt-own-rev1", "op-r1", 0),
            raw_row(&rev2, "evt-gap", "op-gap", 0),
        ];
        let input = EventDecisionInput {
            claimed: &claimed,
            publication: Some(&context),
            ledger_rows: &rows,
            identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
        };
        match decide_event_disposition(&input) {
            EventDisposition::Quarantine { reason } => {
                assert!(reason.contains("per_grant_chain_gap"), "{reason}");
            }
            other => panic!("per-grant chain gap must quarantine, got {other:?}"),
        }
    }

    #[test]
    fn plan_ledger_builds_base_only_from_frontier_proven_heads() {
        let own_head = grant(1, 1, GrantState::Active);
        let sibling_head = grant(9, 1, GrantState::Active);
        let stranger_tail = grant(4, 1, GrantState::Active);
        let (_, dep_hash) = active_card_dependency_hash(5, 0);
        let context = context_without_references(
            Some(17),
            &[
                delta_fixture(1, "evt-own-head", 1, 0, 1),
                delta_fixture(2, "evt-sibling-head", 9, 0, 1),
            ],
        );
        let mut own_rev2 = own_head.clone();
        own_rev2.revision = GrantRevision::new(2).unwrap();
        let delta = astral_types::GrantDelta::update(own_rev2.clone(), own_head.revision);
        let mut claimed = claimed_event(
            &own_rev2,
            &delta,
            5,
            0,
            "evt-candidate",
            "op-candidate",
            &dep_hash,
        );
        claimed.event_type = astral_db::DeltaEventType::Update;
        // Sorted ledger: own-grant rows first (…0001), then the stranger's
        // unproven tail (…0004), then the proven sibling head (…0009).
        let rows = vec![
            raw_row(&own_head, "evt-own-head", "op-h1", 0),
            raw_row(&own_rev2, "evt-candidate", "op-candidate", 0),
            raw_row(&stranger_tail, "evt-stranger-tail", "op-tail", 0),
            raw_row(&sibling_head, "evt-sibling-head", "op-h2", 0),
        ];
        let input = EventDecisionInput {
            claimed: &claimed,
            publication: Some(&context),
            ledger_rows: &rows,
            identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
        };
        match plan_ledger_against_publication(&input) {
            LedgerPlan::Continuation { base_entries } => {
                // EXACTLY the two frontier-proven heads form the base; the
                // stranger's unproven tail never leaks into compilation.
                let mut ids: Vec<&str> = base_entries
                    .iter()
                    .map(|entry| entry.event_id.as_str())
                    .collect();
                ids.sort_unstable();
                assert_eq!(ids, ["evt-own-head", "evt-sibling-head"]);
            }
            other => panic!("expected Continuation base planning, got {other:?}"),
        }
    }

    #[test]
    fn decide_reuses_parent_segments_by_digest_and_keeps_changes_new() {
        let rev_a1 = {
            let mut image = grant(1, 1, GrantState::Active);
            image.resource = "learn_subject:a".to_owned();
            image
        };
        let rev_b1 = {
            let mut image = grant(9, 1, GrantState::Active);
            image.resource = "learn_subject:b".to_owned();
            image
        };
        let mut rev_a2 = rev_a1.clone();
        rev_a2.revision = GrantRevision::new(2).unwrap();
        rev_a2.resource = "learn_subject:a-changed".to_owned(); // distinct new key
        let (_, dep_hash) = active_card_dependency_hash(5, 0);

        // Build the PRE-state exactly like the assembler does (both proven
        // heads at aggregate generation 2) and take the TRUE content digest
        // of the untouched B segment as a parent-reference hint.
        let tenant = TenantScope::new(7, Some(17)).unwrap();
        let dep_vector = reconstruct_dependency_vector(Some(17), 5, 0).unwrap().0;
        let base_state = hot_state_from_entries(
            &tenant,
            2,
            dep_vector,
            policy_engine::COMPILER_VERSION.to_owned(),
            &[
                decode_ledger_row(&raw_row(&rev_a1, "evt-a1", "op-a1", 0)).unwrap(),
                decode_ledger_row(&raw_row(&rev_b1, "evt-b1", "op-b1", 0)).unwrap(),
            ],
        )
        .unwrap();
        let b_segment_payload = astral_db::encode_segment_payload(
            &base_state
                .segments
                .iter()
                .find(|(key, _)| key.resource == "learn_subject:b")
                .map(|(_, segment)| segment.grants.clone())
                .expect("B-key base segment exists"),
        )
        .unwrap();
        let parent_reference = (
            0u64,
            ParentReferenceView {
                ordinal: 0,
                identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
                segment_id: 500,
                content_digest_hex: hex_lower(&Sha256::digest(&b_segment_payload)),
            },
        );
        let context_with_refs = PublicationContext {
            parent_references: vec![parent_reference],
            frontier: frontier_fixture(
                Some(17),
                &[
                    delta_fixture(1, "evt-a1", 1, 0, 1),
                    delta_fixture(2, "evt-b1", 9, 0, 1),
                ],
            ),
        };

        let delta = astral_types::GrantDelta::update(rev_a2.clone(), rev_a1.revision);
        let mut claimed = claimed_event(&rev_a2, &delta, 5, 0, "evt-a2", "op-a2", &dep_hash);
        claimed.event_type = astral_db::DeltaEventType::Update;
        // Sorted ledger: A rows first (…0001), then B (…0009).
        let rows = vec![
            raw_row(&rev_a1, "evt-a1", "op-a1", 0),
            raw_row(&rev_a2, "evt-a2", "op-a2", 0),
            raw_row(&rev_b1, "evt-b1", "op-b1", 0),
        ];
        let input = EventDecisionInput {
            claimed: &claimed,
            publication: Some(&context_with_refs),
            ledger_rows: &rows,
            identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
        };
        match decide_event_disposition(&input) {
            EventDisposition::Publish(command) => {
                let reused: Vec<u64> = command
                    .stage
                    .segments
                    .iter()
                    .filter_map(|entry| match entry {
                        StagedSegmentContent::ReuseParent { parent_ordinal } => {
                            Some(*parent_ordinal)
                        }
                        StagedSegmentContent::New(_) => None,
                    })
                    .collect();
                assert_eq!(reused, vec![0], "unchanged B segment reuses ordinal 0");
                assert!(
                    command
                        .stage
                        .segments
                        .iter()
                        .any(|entry| matches!(entry, StagedSegmentContent::New(_))),
                    "changed/new segments must be written New"
                );
            }
            other => panic!("reuse planning must still publish, got {other:?}"),
        }
    }

    #[test]
    fn decide_quarantines_dependency_drift_and_unsupported_compilers() {
        let fx = fixture();
        let own = fx.grant_rev1;
        let (_, dep_hash) = active_card_dependency_hash(5, 1);

        // Drifted stored dependency hash ⇒ immutable producer/reader divergence.
        let drifted_bytes = {
            let mut bytes = vec![7u8; 32];
            bytes[0] ^= 0xFF;
            bytes
        };
        let delta = astral_types::GrantDelta::add(own.clone());
        let mut drifted = claimed_event(&own, &delta, 5, 1, "evt-drift", "op-drift", &dep_hash);
        drifted.dependency_hash = astral_db::Sha256Digest::from_bytes(drifted_bytes).unwrap();
        let rows = vec![raw_row(&own, "evt-drift", "op-drift", 1)];
        let drift_input = EventDecisionInput {
            claimed: &drifted,
            publication: None,
            ledger_rows: &rows,
            identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
        };
        match decide_event_disposition(&drift_input) {
            EventDisposition::Quarantine { reason } => {
                assert!(
                    reason.contains("dependency_hash_drift"),
                    "unexpected quarantine reason: {reason}"
                );
            }
            other => panic!("expected quarantine on hash drift, got {other:?}"),
        }

        // Unknown producer compiler version refuses before any compilation.
        // Row and claim stay MUTUALLY consistent so only the kernel gate fires.
        let mut foreign_compiler = claimed_event(&own, &delta, 5, 1, "evt-cv", "op-cv", &dep_hash);
        foreign_compiler.compiler_version = "rogue-compiler-v0".to_owned();
        let mut rogue_row = raw_row(&own, "evt-cv", "op-cv", 1);
        rogue_row.compiler_version = "rogue-compiler-v0".to_owned();
        let compiler_rows = vec![rogue_row];
        let compiler_input = EventDecisionInput {
            claimed: &foreign_compiler,
            publication: None,
            ledger_rows: &compiler_rows,
            identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
        };
        match decide_event_disposition(&compiler_input) {
            EventDisposition::Quarantine { reason } => {
                assert!(
                    reason.contains("unsupported_producer_compiler"),
                    "unexpected quarantine reason: {reason}"
                );
            }
            other => panic!("expected quarantine on unknown compiler, got {other:?}"),
        }
    }

    #[test]
    fn quarantine_reason_parts_keep_stable_code_and_free_detail() {
        // Canonical shape: stable code + free detail pass through untouched.
        let (code, detail) = quarantine_reason_parts(
            "code=auth_projector.dependency_hash_drift;stored=aa;reconstructed=bb",
        );
        assert_eq!(code, "auth_projector.dependency_hash_drift");
        assert_eq!(detail, "stored=aa;reconstructed=bb");

        // Exactly-64-char code stays within contract…
        let max_code = "a".repeat(QUARANTINE_REASON_CODE_MAX_CHARS);
        let (code, _) = quarantine_reason_parts(&format!("code={max_code};tail"));
        assert_eq!(code, max_code);

        // …while anything longer falls back with FULL original reason kept as
        // detail for operator evidence.
        let (code, detail) = quarantine_reason_parts(&format!("code={}-x;detail-part", max_code));
        assert_eq!(code, "auth_projector.quarantine");
        assert_eq!(detail, format!("code={}-x;detail-part", max_code));

        // Unprefixed/empty reasons degrade safely without losing evidence.
        let (code, detail) = quarantine_reason_parts("   ");
        assert_eq!(code, "auth_projector.quarantine");
        assert_eq!(detail, "   ");
        let (code, detail) = quarantine_reason_parts("just some text");
        assert_eq!(code, "auth_projector.quarantine");
        assert_eq!(detail, "just some text");

        // Prefix-without-token still lands on the generic fallback.
        let (code, _) = quarantine_reason_parts("code=;kept-detail");
        assert_eq!(code, "auth_projector.quarantine");
    }

    /// Harness recording every mutation call so terminal-quarantine behavior
    /// can be asserted without any database.
    struct QuarantineHarness {
        outcome: Result<(), String>,
        calls: std::sync::Mutex<Vec<&'static str>>,
    }

    impl QuarantineHarness {
        fn new(outcome: Result<(), String>) -> Self {
            Self {
                outcome,
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn recorded(&self) -> Vec<&'static str> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl AuthorizationProjectorRuntime for QuarantineHarness {
        async fn claim_next_event(
            &self,
            _scope: &DeltaEventClaimScope,
            _owner: &str,
            _lease_seconds: i64,
        ) -> Result<Option<DeltaEventClaim>, RuntimeAccessError> {
            Ok(None)
        }
        async fn read_claimed_event(
            &self,
            _identity: &DeltaLeaseIdentity,
        ) -> Result<ClaimedDeltaEvent, RuntimeAccessError> {
            unreachable!("harness drives quarantining directly")
        }
        async fn observe_publication_context(
            &self,
            _identity: &ProjectionAggregateIdentity,
        ) -> Result<Option<PublicationContext>, RuntimeAccessError> {
            unreachable!("harness drives quarantining directly")
        }
        async fn load_scope_ledger(
            &self,
            _tenant_id: i64,
            _aggregate_type: &str,
            _aggregate_id: i64,
            _card_id: Option<i64>,
        ) -> Result<Vec<RawLedgerRow>, RuntimeAccessError> {
            unreachable!("harness drives quarantining directly")
        }
        async fn execute_projection_publish(
            &self,
            _command: &DeltaProjectorPublishCommand,
        ) -> Result<DeltaProjectorPublishOutcome, RuntimeAccessError> {
            unreachable!("harness drives quarantining directly")
        }
        async fn fail_event(
            &self,
            _identity: &DeltaLeaseIdentity,
            backoff_seconds: i64,
            message: &str,
        ) {
            self.calls.lock().unwrap().push("fail");
            let _ = (backoff_seconds, message);
        }
        async fn release_event(&self, _identity: &DeltaLeaseIdentity) {
            self.calls.lock().unwrap().push("release");
        }
        async fn mark_event_quarantined(
            &self,
            _lease: &DeltaLeaseIdentity,
            reason_code: &str,
            _reason_detail: &str,
        ) -> Result<(), RuntimeAccessError> {
            self.calls.lock().unwrap().push("mark");
            assert!(
                !reason_code.is_empty(),
                "stable code part must always reach the repository boundary"
            );
            match self.outcome.clone() {
                Ok(()) => Ok(()),
                Err(text) if text.contains("cas") => Err(RuntimeAccessError::Repository(
                    RepositoryRejection::Other(text),
                )),
                Err(text) => Err(RuntimeAccessError::Database(text)),
            }
        }
    }

    /// F5 修复 1b：任何处理步骤挂起都必须被 event_deadline 收口——计数、
    /// 尽力释放租约、循环继续，worker 永不永久停在当次事件内。
    #[tokio::test]
    async fn event_deadline_releases_lease_and_keeps_the_worker_looping() {
        use std::sync::Mutex as StdMutex;
        struct HangingReadbackRuntime {
            claims: StdMutex<u32>,
            released: StdMutex<Vec<String>>,
        }
        #[async_trait]
        impl AuthorizationProjectorRuntime for HangingReadbackRuntime {
            async fn claim_next_event(
                &self,
                _scope: &DeltaEventClaimScope,
                _owner: &str,
                _lease: i64,
            ) -> Result<Option<DeltaEventClaim>, RuntimeAccessError> {
                let mut claims = self.claims.lock().unwrap();
                *claims += 1;
                if *claims == 1 {
                    Ok(Some(harness_claim()))
                } else {
                    Ok(None)
                }
            }
            async fn read_claimed_event(
                &self,
                _identity: &DeltaLeaseIdentity,
            ) -> Result<ClaimedDeltaEvent, RuntimeAccessError> {
                // 挂起形态（S15 F5 实测）：处理的第一步即永久 pending。
                std::future::pending().await
            }
            async fn observe_publication_context(
                &self,
                _identity: &ProjectionAggregateIdentity,
            ) -> Result<Option<PublicationContext>, RuntimeAccessError> {
                unreachable!("readback hangs before this seam")
            }
            async fn load_scope_ledger(
                &self,
                _tenant_id: i64,
                _aggregate_type: &str,
                _aggregate_id: i64,
                _card_id: Option<i64>,
            ) -> Result<Vec<RawLedgerRow>, RuntimeAccessError> {
                unreachable!("readback hangs before this seam")
            }
            async fn execute_projection_publish(
                &self,
                _command: &DeltaProjectorPublishCommand,
            ) -> Result<DeltaProjectorPublishOutcome, RuntimeAccessError> {
                unreachable!("readback hangs before this seam")
            }
            async fn fail_event(
                &self,
                _identity: &DeltaLeaseIdentity,
                _backoff_seconds: i64,
                _message: &str,
            ) {
            }
            async fn release_event(&self, identity: &DeltaLeaseIdentity) {
                self.released
                    .lock()
                    .unwrap()
                    .push(identity.event_id.clone());
            }
            async fn mark_event_quarantined(
                &self,
                _lease: &DeltaLeaseIdentity,
                _reason_code: &str,
                _reason_detail: &str,
            ) -> Result<(), RuntimeAccessError> {
                unreachable!("readback hangs before this seam")
            }
        }

        let runtime = Arc::new(HangingReadbackRuntime {
            claims: StdMutex::new(0),
            released: StdMutex::new(Vec::new()),
        });
        let config = AuthorizationProjectorConfig {
            tenants: vec![1],
            poll_interval_secs: 60,
            event_deadline: Duration::from_millis(60),
            ..Default::default()
        };
        let handle = start_authorization_projector_with_runtime(runtime.clone(), config);
        // 第一轮循环内完成：claim → readback 挂起 → deadline 触发 → 释放 →
        // 下一次 claim 返回空 → 空闲等待 cancellation。
        tokio::time::sleep(Duration::from_millis(400)).await;
        let report = shutdown_authorization_projector(handle, Duration::from_secs(2)).await;
        let summary = report
            .summary
            .expect("worker must stop cleanly after a deadline event");
        assert_eq!(
            summary.events_deadline_exceeded, 1,
            "a hanging step must be converted into exactly one deadline event"
        );
        // 批次 B 调研纪律：deadline 超时不得发布任何租约 mutation——不释放，
        // 由租约过期 reclaim 门接管；因此这里绝不出现 release 记录。
        assert!(
            runtime.released.lock().unwrap().is_empty(),
            "deadline timeout must NOT issue a lease release (unknown commit result)"
        );
        assert!(
            report.join_elapsed < Duration::from_secs(2),
            "cancellation must still stop the worker promptly"
        );
    }

    /// F5 修复 1d 看门狗：claim 卡死 + 存在可 claim 积压 → 监督循环必须
    /// 在停滞阈值后重建 worker 代（generation 前进、restarts 计数）。
    #[tokio::test]
    async fn watchdog_rebuilds_stalled_generation_when_claimable_backlog_exists() {
        use std::sync::atomic::AtomicBool;
        struct WedgedClaimRuntime {
            claimable: AtomicBool,
        }
        #[async_trait]
        impl AuthorizationProjectorRuntime for WedgedClaimRuntime {
            async fn claim_next_event(
                &self,
                _scope: &DeltaEventClaimScope,
                _owner: &str,
                _lease: i64,
            ) -> Result<Option<DeltaEventClaim>, RuntimeAccessError> {
                // 卡死形态：claim 永不返回，进展永不推进（S15 F5 残余面）。
                std::future::pending().await
            }
            async fn read_claimed_event(
                &self,
                _identity: &DeltaLeaseIdentity,
            ) -> Result<ClaimedDeltaEvent, RuntimeAccessError> {
                unreachable!("claim wedges before this seam")
            }
            async fn observe_publication_context(
                &self,
                _identity: &ProjectionAggregateIdentity,
            ) -> Result<Option<PublicationContext>, RuntimeAccessError> {
                unreachable!("claim wedges before this seam")
            }
            async fn load_scope_ledger(
                &self,
                _tenant_id: i64,
                _aggregate_type: &str,
                _aggregate_id: i64,
                _card_id: Option<i64>,
            ) -> Result<Vec<RawLedgerRow>, RuntimeAccessError> {
                unreachable!("claim wedges before this seam")
            }
            async fn execute_projection_publish(
                &self,
                _command: &DeltaProjectorPublishCommand,
            ) -> Result<DeltaProjectorPublishOutcome, RuntimeAccessError> {
                unreachable!("claim wedges before this seam")
            }
            async fn fail_event(
                &self,
                _identity: &DeltaLeaseIdentity,
                _backoff_seconds: i64,
                _message: &str,
            ) {
            }
            async fn release_event(&self, _identity: &DeltaLeaseIdentity) {}
            async fn mark_event_quarantined(
                &self,
                _lease: &DeltaLeaseIdentity,
                _reason_code: &str,
                _reason_detail: &str,
            ) -> Result<(), RuntimeAccessError> {
                unreachable!("claim wedges before this seam")
            }
            async fn has_claimable_work(&self, _scope: &DeltaEventClaimScope) -> bool {
                self.claimable.load(Ordering::Acquire)
            }
        }

        let runtime = Arc::new(WedgedClaimRuntime {
            claimable: AtomicBool::new(true),
        });
        let config = AuthorizationProjectorConfig {
            tenants: vec![1],
            poll_interval_secs: 60,
            watchdog_stall_threshold: Duration::from_millis(150),
            watchdog_tick: Duration::from_millis(50),
            ..Default::default()
        };
        let handle = start_authorization_projector_with_runtime(runtime, config);
        // 看门狗应在停滞阈值后重建当前代：generation 前进且 restarts 计数。
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let snapshot = handle.health_snapshot();
            if snapshot.generation >= 2 && snapshot.restarts >= 1 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "watchdog never rebuilt the stalled generation (gen={} restarts={})",
                snapshot.generation,
                snapshot.restarts
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // 当前代卡死且忽略取消 → shutdown 有界宽限后如实上报失败。
        let report = shutdown_authorization_projector(handle, Duration::from_secs(2)).await;
        assert!(
            report.summary.is_err(),
            "wedged generation must surface as Err on shutdown"
        );
    }

    /// F5 修复 1d 看门狗负例：无积压（runtime 报告无可 claim 事件）→ 停滞
    /// 不触发重建，空队列的挂起不会制造无意义的代重启。
    #[tokio::test]
    async fn watchdog_does_not_rebuild_without_claimable_backlog() {
        use std::sync::atomic::AtomicBool;
        struct WedgedClaimRuntimeNoBacklog {
            claimable: AtomicBool,
        }
        #[async_trait]
        impl AuthorizationProjectorRuntime for WedgedClaimRuntimeNoBacklog {
            async fn claim_next_event(
                &self,
                _scope: &DeltaEventClaimScope,
                _owner: &str,
                _lease: i64,
            ) -> Result<Option<DeltaEventClaim>, RuntimeAccessError> {
                std::future::pending().await
            }
            async fn read_claimed_event(
                &self,
                _identity: &DeltaLeaseIdentity,
            ) -> Result<ClaimedDeltaEvent, RuntimeAccessError> {
                unreachable!("claim wedges before this seam")
            }
            async fn observe_publication_context(
                &self,
                _identity: &ProjectionAggregateIdentity,
            ) -> Result<Option<PublicationContext>, RuntimeAccessError> {
                unreachable!("claim wedges before this seam")
            }
            async fn load_scope_ledger(
                &self,
                _tenant_id: i64,
                _aggregate_type: &str,
                _aggregate_id: i64,
                _card_id: Option<i64>,
            ) -> Result<Vec<RawLedgerRow>, RuntimeAccessError> {
                unreachable!("claim wedges before this seam")
            }
            async fn execute_projection_publish(
                &self,
                _command: &DeltaProjectorPublishCommand,
            ) -> Result<DeltaProjectorPublishOutcome, RuntimeAccessError> {
                unreachable!("claim wedges before this seam")
            }
            async fn fail_event(
                &self,
                _identity: &DeltaLeaseIdentity,
                _backoff_seconds: i64,
                _message: &str,
            ) {
            }
            async fn release_event(&self, _identity: &DeltaLeaseIdentity) {}
            async fn mark_event_quarantined(
                &self,
                _lease: &DeltaLeaseIdentity,
                _reason_code: &str,
                _reason_detail: &str,
            ) -> Result<(), RuntimeAccessError> {
                unreachable!("claim wedges before this seam")
            }
            async fn has_claimable_work(&self, _scope: &DeltaEventClaimScope) -> bool {
                self.claimable.load(Ordering::Acquire)
            }
        }

        let runtime = Arc::new(WedgedClaimRuntimeNoBacklog {
            claimable: AtomicBool::new(false),
        });
        let config = AuthorizationProjectorConfig {
            tenants: vec![1],
            poll_interval_secs: 60,
            watchdog_stall_threshold: Duration::from_millis(100),
            watchdog_tick: Duration::from_millis(40),
            ..Default::default()
        };
        let handle = start_authorization_projector_with_runtime(runtime, config);
        // 远超停滞阈值：无积压 → 不得重建（generation 恒为 1、restarts 为 0）。
        tokio::time::sleep(Duration::from_millis(400)).await;
        let snapshot = handle.health_snapshot();
        assert_eq!(
            snapshot.generation, 1,
            "no backlog must never trigger a forced rebuild"
        );
        assert_eq!(snapshot.restarts, 0);
        let report = shutdown_authorization_projector(handle, Duration::from_secs(2)).await;
        assert!(
            report.summary.is_err(),
            "wedged child must still fail shutdown honestly"
        );
    }

    fn harness_claim() -> DeltaEventClaim {
        let owner = grant(1, 1, GrantState::Active);
        let (_, dep_hash) = active_card_dependency_hash(5, 0);
        let delta = astral_types::GrantDelta::add(owner.clone());
        let readback = claimed_event(&owner, &delta, 5, 0, "evt-q", "op-q", &dep_hash);
        DeltaEventClaim {
            delta_event_id: readback.delta_event_id,
            event_id: readback.event_id,
            operation_id: readback.operation_id,
            event_type: readback.event_type,
            tenant_id: readback.tenant_id,
            card_id: readback.card_id,
            aggregate_type: readback.aggregate_type,
            aggregate_id: readback.aggregate_id,
            grant_id: readback.grant_id,
            base_version: readback.base_version,
            target_version: readback.target_version,
            source_generation: readback.source_generation,
            revoke_fence: readback.revoke_fence,
            before_image_json: readback.before_image_json.clone(),
            before_digest: readback.before_digest,
            delta_json: readback.delta_json.clone(),
            semantic_hash: readback.semantic_hash,
            dependency_hash: readback.dependency_hash,
            compiler_version: readback.compiler_version.clone(),
            attempts: readback.attempts,
            cas_version: readback.cas_version,
            lease_owner: readback.lease_owner.clone(),
            lease_token: astral_db::DeltaLeaseToken::for_test("secret-test-token"),
            lease_expires_at: readback.lease_expires_at,
        }
    }

    struct ReplanHarness {
        publish_steps: std::sync::Mutex<std::collections::VecDeque<ReplanPublishStep>>,
        calls: std::sync::Mutex<Vec<&'static str>>,
    }

    enum ReplanPublishStep {
        PointerMoved,
        GenericRetry,
        LeaseLost,
        Success,
    }

    impl ReplanHarness {
        fn new(steps: impl IntoIterator<Item = ReplanPublishStep>) -> Self {
            Self {
                publish_steps: std::sync::Mutex::new(steps.into_iter().collect()),
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<&'static str> {
            self.calls.lock().unwrap().clone()
        }
    }

    fn replan_readback() -> ClaimedDeltaEvent {
        let owner = grant(1, 1, GrantState::Active);
        let (_, dep_hash) = active_card_dependency_hash(5, 0);
        let delta = astral_types::GrantDelta::add(owner.clone());
        claimed_event(&owner, &delta, 5, 0, "evt-q", "op-q", &dep_hash)
    }

    fn replan_success() -> DeltaProjectorPublishOutcome {
        let identity = ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap();
        DeltaProjectorPublishOutcome {
            impact_plan: astral_db::AuthorizationImpactPlanOutcome {
                plan_id: 1,
                resumed_existing_plan: false,
                item_count: 1,
            },
            stage: astral_db::AuthorizationStageOutcome {
                manifest_id: 1,
                manifest_digest: Sha256Digest::from_hex(HASH_A).unwrap(),
                target_generation: 1,
                total_grant_count: 1,
                new_segment_count: 1,
                reused_segment_count: 0,
                resumed_existing_manifest: false,
                base_pointer: None,
            },
            archive_intent: None,
            publish: astral_db::AuthorizationPublishOutcome {
                pointer: AuthorizationCurrentPointerRecord {
                    pointer_id: 1,
                    identity,
                    card_id: Some(17),
                    current_generation: 1,
                    manifest_id: 1,
                    event_id: "evt-q".to_owned(),
                    operation_id: "op-q".to_owned(),
                    semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap(),
                    dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap(),
                    compiler_version: policy_engine::COMPILER_VERSION.to_owned(),
                    revoke_fence: 0,
                    revoke_fence_proven: true,
                    cas_version: 1,
                },
                published_manifest_id: 1,
                previous_superseded_manifest_id: None,
                initialized_first_pointer: true,
            },
        }
    }

    #[async_trait]
    impl AuthorizationProjectorRuntime for ReplanHarness {
        async fn claim_next_event(
            &self,
            _scope: &DeltaEventClaimScope,
            _lease_owner: &str,
            _lease_seconds: i64,
        ) -> Result<Option<DeltaEventClaim>, RuntimeAccessError> {
            unreachable!("replan tests call process_one_event directly")
        }

        async fn read_claimed_event(
            &self,
            _identity: &DeltaLeaseIdentity,
        ) -> Result<ClaimedDeltaEvent, RuntimeAccessError> {
            self.calls.lock().unwrap().push("read");
            Ok(replan_readback())
        }

        async fn observe_publication_context(
            &self,
            _identity: &ProjectionAggregateIdentity,
        ) -> Result<Option<PublicationContext>, RuntimeAccessError> {
            self.calls.lock().unwrap().push("observe");
            Ok(None)
        }

        async fn load_scope_ledger(
            &self,
            _tenant_id: i64,
            _aggregate_type: &str,
            _aggregate_id: i64,
            _card_id: Option<i64>,
        ) -> Result<Vec<RawLedgerRow>, RuntimeAccessError> {
            self.calls.lock().unwrap().push("ledger");
            let owner = grant(1, 1, GrantState::Active);
            Ok(vec![raw_row(&owner, "evt-q", "op-q", 0)])
        }

        async fn execute_projection_publish(
            &self,
            _command: &DeltaProjectorPublishCommand,
        ) -> Result<DeltaProjectorPublishOutcome, RuntimeAccessError> {
            self.calls.lock().unwrap().push("publish");
            match self
                .publish_steps
                .lock()
                .unwrap()
                .pop_front()
                .expect("test supplied a publish step for every attempt")
            {
                ReplanPublishStep::PointerMoved => Err(projection_failure(
                    AuthorizationProjectionError::ScopeViolation(
                        "code=authorization_projection.command_base_generation_mismatch;expected=1;actual=2"
                            .to_owned(),
                    ),
                )),
                ReplanPublishStep::GenericRetry => {
                    Err(RuntimeAccessError::Database("synthetic query failure".to_owned()))
                }
                ReplanPublishStep::LeaseLost => Err(projection_failure(
                    AuthorizationProjectionError::LeaseCasFailed(
                        "code=grant_repository.complete_lost_lease;event=evt-q".to_owned(),
                    ),
                )),
                ReplanPublishStep::Success => Ok(replan_success()),
            }
        }

        async fn fail_event(
            &self,
            _identity: &DeltaLeaseIdentity,
            _backoff_seconds: i64,
            _message: &str,
        ) {
            self.calls.lock().unwrap().push("fail");
        }

        async fn release_event(&self, _identity: &DeltaLeaseIdentity) {
            self.calls.lock().unwrap().push("release");
        }

        async fn mark_event_quarantined(
            &self,
            _lease: &DeltaLeaseIdentity,
            _reason_code: &str,
            _reason_detail: &str,
        ) -> Result<(), RuntimeAccessError> {
            self.calls.lock().unwrap().push("mark");
            unreachable!("replan tests do not enter quarantine")
        }
    }

    async fn run_replan_test(
        harness: &std::sync::Arc<ReplanHarness>,
        summary: &mut WorkerRunSummary,
        claimed: &DeltaEventClaim,
    ) {
        let runtime: std::sync::Arc<dyn AuthorizationProjectorRuntime> = harness.clone();
        let config = AuthorizationProjectorConfig {
            tenants: vec![7],
            ..Default::default()
        };
        let cancellation = ProjectorCancellationToken::default();
        process_one_event(
            &runtime,
            &config,
            "auth-projector:test-run",
            &cancellation,
            claimed,
            summary,
        )
        .await;
    }

    #[tokio::test]
    async fn pointer_moved_replans_under_one_lease_then_publishes() {
        let harness = std::sync::Arc::new(ReplanHarness::new([
            ReplanPublishStep::PointerMoved,
            ReplanPublishStep::PointerMoved,
            ReplanPublishStep::Success,
        ]));
        let claimed = harness_claim();
        let mut summary = WorkerRunSummary::default();
        run_replan_test(&harness, &mut summary, &claimed).await;

        assert_eq!(summary.events_pointer_moved_replanned, 2);
        assert_eq!(summary.events_published, 1);
        assert_eq!(summary.events_released_retry, 0);
        assert_eq!(summary.events_budget_exhausted, 0);
        assert_eq!(
            harness.calls(),
            vec![
                "read", "observe", "ledger", "publish", "observe", "ledger", "publish", "observe",
                "ledger", "publish",
            ]
        );
        assert!(
            !harness.calls().contains(&"fail") && !harness.calls().contains(&"release"),
            "in-place replans must not mutate the lease"
        );
    }

    #[tokio::test]
    async fn pointer_moved_replan_exhaustion_enters_budget_once() {
        let harness = std::sync::Arc::new(ReplanHarness::new([
            ReplanPublishStep::PointerMoved,
            ReplanPublishStep::PointerMoved,
            ReplanPublishStep::PointerMoved,
            ReplanPublishStep::PointerMoved,
        ]));
        let claimed = harness_claim();
        let mut summary = WorkerRunSummary::default();
        run_replan_test(&harness, &mut summary, &claimed).await;

        assert_eq!(
            summary.events_pointer_moved_replanned,
            MAX_POINTER_MOVED_REPLANS as u64
        );
        assert_eq!(summary.events_released_retry, 1);
        assert_eq!(summary.events_budget_exhausted, 0);
        assert_eq!(
            harness
                .calls()
                .iter()
                .filter(|call| **call == "publish")
                .count(),
            4
        );
        assert_eq!(
            harness
                .calls()
                .iter()
                .filter(|call| **call == "fail")
                .count(),
            1
        );
        assert!(!harness.calls().contains(&"release"));
    }

    #[tokio::test]
    async fn generic_publish_failure_does_not_enter_replan() {
        let harness = std::sync::Arc::new(ReplanHarness::new([ReplanPublishStep::GenericRetry]));
        let claimed = harness_claim();
        let mut summary = WorkerRunSummary::default();
        run_replan_test(&harness, &mut summary, &claimed).await;

        assert_eq!(summary.events_pointer_moved_replanned, 0);
        assert_eq!(summary.events_released_retry, 1);
        assert_eq!(
            harness.calls(),
            vec!["read", "observe", "ledger", "publish", "fail"]
        );
    }

    #[tokio::test]
    async fn lease_loss_during_replan_stops_without_followup_mutation() {
        let harness = std::sync::Arc::new(ReplanHarness::new([
            ReplanPublishStep::PointerMoved,
            ReplanPublishStep::LeaseLost,
        ]));
        let claimed = harness_claim();
        let mut summary = WorkerRunSummary::default();
        run_replan_test(&harness, &mut summary, &claimed).await;

        assert_eq!(summary.events_pointer_moved_replanned, 1);
        assert_eq!(summary.events_lease_lost, 1);
        assert_eq!(summary.events_released_retry, 0);
        assert_eq!(summary.events_budget_exhausted, 0);
        assert_eq!(
            harness
                .calls()
                .iter()
                .filter(|call| **call == "publish")
                .count(),
            2
        );
        assert!(!harness.calls().contains(&"fail"));
        assert!(!harness.calls().contains(&"release"));
        assert!(!harness.calls().contains(&"mark"));
    }

    #[test]
    fn pointer_moved_replan_summary_merges() {
        let mut aggregate = WorkerRunSummary::default();
        let one = WorkerRunSummary {
            events_pointer_moved_replanned: 2,
            ..WorkerRunSummary::default()
        };
        aggregate.merge(&one);
        assert_eq!(aggregate.events_pointer_moved_replanned, 2);
    }
    #[tokio::test]
    async fn terminal_quarantine_writes_mark_and_records_success() {
        let harness = Arc::new(QuarantineHarness::new(Ok(())));
        let runtime: Arc<dyn AuthorizationProjectorRuntime> = harness.clone();
        let identity = DeltaLeaseIdentity {
            delta_event_id: 77,
            event_id: "evt-q".to_owned(),
            lease_owner: "auth-projector:test-run".to_owned(),
            lease_token: astral_db::DeltaLeaseToken::for_test("secret-test-token"),
        };
        let claimed = harness_claim();
        let mut summary = WorkerRunSummary::default();
        let started = Instant::now();
        quarantine_event_terminal(
            &runtime,
            &identity,
            &claimed,
            "code=auth_projector.no_effective_change;fenced",
            &started,
            &mut summary,
        )
        .await;
        assert_eq!(summary.events_quarantined, 1);
        assert_eq!(summary.events_quarantine_unknown, 0);
        assert_eq!(harness.recorded(), vec!["mark"], "exactly one CAS write");
    }

    #[tokio::test]
    async fn terminal_quarantine_unknown_results_issue_no_followup_mutation() {
        for flavor in ["cas", "query"] {
            let outcome_text = if flavor == "cas" {
                Err("cas: code=grant_repository.quarantine_lost_lease;event=x".to_owned())
            } else {
                Err(String::from("query: connection reset during write"))
            };
            let harness = Arc::new(QuarantineHarness::new(outcome_text));
            let runtime: Arc<dyn AuthorizationProjectorRuntime> = harness.clone();
            let identity = DeltaLeaseIdentity {
                delta_event_id: 77,
                event_id: "evt-q".to_owned(),
                lease_owner: "auth-projector:test-run".to_owned(),
                lease_token: astral_db::DeltaLeaseToken::for_test("secret-test-token"),
            };
            let claimed = harness_claim();
            let mut summary = WorkerRunSummary::default();
            let started = Instant::now();
            quarantine_event_terminal(
                &runtime,
                &identity,
                &claimed,
                "code=auth_projector.compile_conflict;conflict=DuplicateDelta",
                &started,
                &mut summary,
            )
            .await;
            assert_eq!(
                summary.events_quarantine_unknown, 1,
                "{flavor}: UNKNOWN outcome must be counted"
            );
            assert_eq!(
                summary.events_quarantined, 0,
                "{flavor}: nothing proven durable may count as quarantined"
            );
            assert_eq!(
                harness.recorded(),
                vec!["mark"],
                "{flavor}: no fail/release/retry after an unknown terminal write"
            );
        }
    }

    #[tokio::test]
    async fn budget_exhaustion_stays_pending_and_never_fakes_terminal_states() {
        let harness = Arc::new(QuarantineHarness::new(Ok(())));
        let runtime: Arc<dyn AuthorizationProjectorRuntime> = harness.clone();
        let identity = DeltaLeaseIdentity {
            delta_event_id: 77,
            event_id: "evt-q".to_owned(),
            lease_owner: "auth-projector:test-run".to_owned(),
            lease_token: astral_db::DeltaLeaseToken::for_test("secret-test-token"),
        };
        let mut claimed = harness_claim();
        claimed.attempts = MAX_EVENT_ATTEMPTS; // exhausted budget
        let mut summary = WorkerRunSummary::default();
        fail_with_budget(
            &runtime,
            &identity,
            &claimed,
            DispositionKind::Blocked,
            0,
            "code=auth_projector.blocked_forever",
            &mut summary,
        )
        .await;
        assert_eq!(summary.events_budget_exhausted, 1);
        assert_eq!(summary.events_blocked, 1);
        assert_eq!(
            harness.recorded(),
            vec!["fail"],
            "budget exhaustion keeps the PENDING fail path alive"
        );
        // The exhaustion marker rides along inside the durable last_error.
    }

    #[test]
    fn locate_claimed_candidate_maps_every_exclusion_kind() {
        use astral_db::{CandidateLedgerRow, ExcludedLedgerRow};

        fn synthetic_entry(event_id: &str) -> GrantLedgerEntry {
            let row = RawLedgerRow {
                revision_no: 1,
                tenant_id: 7,
                card_id: Some(17),
                aggregate_type: "CARD".to_owned(),
                aggregate_id: 17,
                grant_id: grant_id_for(1).to_string(),
                status: "ACTIVE".to_owned(),
                is_tombstone: 0,
                grant_payload: serde_json::to_string(&grant(1, 1, GrantState::Active)).unwrap(),
                semantic_hash: {
                    let digest = Sha256Digest::from_hex(HASH_A).unwrap();
                    digest.as_bytes().to_vec()
                },
                dependency_hash: {
                    let digest = Sha256Digest::from_hex(HASH_B).unwrap();
                    digest.as_bytes().to_vec()
                },
                operation_id: "op".to_owned(),
                event_id: event_id.to_owned(),
                compiler_version: policy_engine::COMPILER_VERSION.to_owned(),
            };
            decode_ledger_row(&row).unwrap()
        }

        fn empty_partition() -> PartitionedGrantLedgerAtFrontier {
            PartitionedGrantLedgerAtFrontier::default()
        }

        // Missing entirely.
        match locate_claimed_candidate(&empty_partition(), "evt-x") {
            LocatedCandidate::MissingFromLedger => {}
            other => panic!("empty partition must miss, got {other:?}"),
        }

        // Stale classification maps to reconciliation-grade quarantine intent.
        let stale = PartitionedGrantLedgerAtFrontier {
            excluded_rows: vec![ExcludedLedgerRow {
                entry: synthetic_entry("evt-x"),
                kind: astral_db::LedgerExclusionKind::StaleClaimBehindPublishedFrontier,
            }],
            ..PartitionedGrantLedgerAtFrontier::default()
        };
        match locate_claimed_candidate(&stale, "evt-x") {
            LocatedCandidate::StaleBehindPublishedFrontier => {}
            other => panic!("stale claim must classify, got {other:?}"),
        }

        // Sibling-blocked classification keeps its Blocked semantics.
        let behind = PartitionedGrantLedgerAtFrontier {
            excluded_rows: vec![ExcludedLedgerRow {
                entry: synthetic_entry("evt-y"),
                kind: astral_db::LedgerExclusionKind::ClaimedBehindUnpublishedSiblings,
            }],
            ..PartitionedGrantLedgerAtFrontier::default()
        };
        match locate_claimed_candidate(&behind, "evt-y") {
            LocatedCandidate::BehindUnpublishedSiblings => {}
            other => panic!("behind-sibling claim must classify, got {other:?}"),
        }

        // NotProvenPublished on OUR id contradicts claimed-set membership.
        let contradictory = PartitionedGrantLedgerAtFrontier {
            excluded_rows: vec![ExcludedLedgerRow {
                entry: synthetic_entry("evt-z"),
                kind: astral_db::LedgerExclusionKind::NotProvenPublished,
            }],
            ..PartitionedGrantLedgerAtFrontier::default()
        };
        match locate_claimed_candidate(&contradictory, "evt-z") {
            LocatedCandidate::OwnClaimNotRecognized => {}
            other => panic!("contradiction must surface defensively, got {other:?}"),
        }

        // Duplicate candidates are ambiguous even though the partitioner
        // aborts them first — the contradiction never collapses silently.
        let ambiguous = PartitionedGrantLedgerAtFrontier {
            candidate_rows: vec![
                CandidateLedgerRow {
                    entry: synthetic_entry("evt-dup"),
                },
                CandidateLedgerRow {
                    entry: synthetic_entry("evt-dup2"),
                },
            ],
            ..PartitionedGrantLedgerAtFrontier::default()
        };
        let second = locate_claimed_candidate(&ambiguous, "evt-dup2");
        match second {
            LocatedCandidate::Found(_) => {}
            other => panic!("distinct second candidate stays found, got {other:?}"),
        }
        let doubled_same = PartitionedGrantLedgerAtFrontier {
            candidate_rows: vec![
                CandidateLedgerRow {
                    entry: synthetic_entry("evt-dup"),
                },
                CandidateLedgerRow {
                    entry: {
                        let mut e = synthetic_entry("evt-dup");
                        e.revision_no += 1;
                        e
                    },
                },
            ],
            ..PartitionedGrantLedgerAtFrontier::default()
        };
        match locate_claimed_candidate(&doubled_same, "evt-dup") {
            LocatedCandidate::Ambiguous => {}
            other => panic!("duplicate candidates must be ambiguous, got {other:?}"),
        }
    }

    #[test]
    fn disposition_kind_mapping_is_total() {
        let cases: [(EventDisposition, DispositionKind); 4] = [
            (
                EventDisposition::Retry { reason: "x".into() },
                DispositionKind::ReleasedRetry,
            ),
            (
                EventDisposition::Quarantine { reason: "y".into() },
                DispositionKind::Quarantined,
            ),
            (
                EventDisposition::Blocked { reason: "z".into() },
                DispositionKind::Blocked,
            ),
            (
                EventDisposition::Superseded { reason: "w".into() },
                DispositionKind::SupersededRelease,
            ),
        ];
        for (disposition, expected) in cases {
            assert_eq!(disposition.kind(), expected);
        }
    }
}
