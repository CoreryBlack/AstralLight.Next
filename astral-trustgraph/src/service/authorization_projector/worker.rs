//! Projector durable worker：监督循环、租约/重试预算、隔离与关停。

use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use sqlx::MySqlPool;
use tokio::task::JoinHandle;

use astral_db::{
    ClaimedDeltaEvent, DeltaEventClaim, DeltaEventClaimScope, DeltaLeaseIdentity,
    ProjectionAggregateIdentity, MAX_BACKOFF_SECONDS,
};

use crate::observability::{
    record_projector_event, record_projector_phase, ProjectorEventOutcome, ProjectorPhase,
};

use super::*;
/// Stable operator-facing marker appended to `last_error` when the retry
/// budget is exhausted. Kept PENDING on purpose: this slice must NOT fake a
/// terminal QUARANTINED/SUCCEEDED status it cannot durably write yet.
pub(crate) const ATTEMPT_BUDGET_EXHAUSTED_CODE: &str =
    "code=auth_projector.attempt_budget_exhausted";

pub(crate) fn budget_exhausted_error(reason: &str, attempts: i64) -> String {
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

pub(crate) fn clamp_backoff(secs: i64) -> i64 {
    secs.clamp(1, BACKOFF_CAP_SECS.min(MAX_BACKOFF_SECONDS))
}

/// Bounded exponential backoff for an event whose attempts counter reached
/// `n` (first failure n=1 → 1s, doubling). Attempt exhaustion switches to the
/// maximal backoff instead of looping hot. Primitive schedule used ONLY by
/// [`plan_retry_schedule`] (plus its tests) — never by handlers directly.
pub(crate) fn event_backoff_secs(attempts: i64) -> i64 {
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
pub(crate) enum RetrySchedule {
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
pub(crate) fn plan_retry_schedule(
    attempts_current: i64,
    minimum_backoff_secs: i64,
) -> RetrySchedule {
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

    pub(crate) async fn cancelled(&self) {
        if self.cancelled.load(Ordering::Acquire) {
            return;
        }
        self.notify.notified().await;
    }

    pub(crate) fn is_cancelled(&self) -> bool {
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
    /// Commit outcome could not be proven; no ordinary retry is permitted.
    #[serde(default)]
    pub events_publication_unknown: u64,
    /// Commit succeeded, but local reads remain on the strict durable fallback.
    #[serde(default)]
    pub events_committed_mirror_unavailable: u64,
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
pub(crate) enum DispositionKind {
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

pub(crate) fn unix_millis() -> u64 {
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
    pub(crate) fn touch(&self) {
        self.last_progress_ms
            .store(unix_millis(), Ordering::Release);
    }

    pub(crate) fn age_ms(&self) -> Option<u64> {
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
    pub(crate) fn merge(&mut self, other: &WorkerRunSummary) {
        self.events_claimed += other.events_claimed;
        self.events_published += other.events_published;
        self.events_released_retry += other.events_released_retry;
        self.events_quarantined += other.events_quarantined;
        self.events_blocked += other.events_blocked;
        self.events_lease_lost += other.events_lease_lost;
        self.events_publication_unknown += other.events_publication_unknown;
        self.events_committed_mirror_unavailable += other.events_committed_mirror_unavailable;
        self.events_pointer_moved_replanned += other.events_pointer_moved_replanned;
        self.events_budget_exhausted += other.events_budget_exhausted;
        self.events_quarantine_unknown += other.events_quarantine_unknown;
        self.decide_phase_micros += other.decide_phase_micros;
        self.events_deadline_exceeded += other.events_deadline_exceeded;
    }
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
    pub(crate) fn ownership_guard(&self) -> ProjectorOwnershipGuard {
        ProjectorOwnershipGuard {
            cancellation: self.cancellation.clone(),
            task: self.join.abort_handle(),
        }
    }

    /// 只读健康快照：代数/重启数/uptime/停滞年龄/跨代聚合计数。仅含聚合
    /// 计数与时间戳——无租户/卡/grant 语义，无 lease token，不是授权身份。
    pub fn health_snapshot(&self) -> ProjectorHealthSnapshot {
        self.health.snapshot()
    }
}

pub(crate) struct ProjectorOwnershipGuard {
    cancellation: ProjectorCancellationToken,
    task: tokio::task::AbortHandle,
}

impl Drop for ProjectorOwnershipGuard {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.task.abort();
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
    let _ownership = handle.ownership_guard();
    handle.cancellation.cancel();
    let started = Instant::now();
    let mut join = handle.join;
    let summary = match tokio::time::timeout(timeout, &mut join).await {
        Ok(Ok(Ok(summary))) => Ok(summary),
        Ok(Ok(Err(failure))) => Err(failure),
        Ok(Err(join_error)) => Err(format!("supervisor task failed: {join_error}")),
        Err(_) => {
            join.abort();
            let _ = tokio::time::timeout(Duration::from_secs(1), &mut join).await;
            Err(format!(
                "projector did not stop within {timeout:?}; aborted; final durable outcome unknown"
            ))
        }
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

/// Start one owned projector task backed by the sqlx runtime. The caller MUST
/// keep the handle and invoke [`shutdown_authorization_projector`].
///
/// Single-node selection: when the process-global local projection bus AND the
/// memory mirror are installed (single-node composition order), projection is
/// owned EXCLUSIVELY by the in-process worker ([`crate::service::local_projection_worker`])
/// which consumes commit-proven dispatches directly — the 5s DB-poll loop does
/// NOT run on that path (documented single-node discipline: normal local
/// operation never DB-polls). A start failure of the in-process worker is a
/// TERMINAL start failure: the returned handle resolves `Err` immediately and
/// health records it; there is deliberately NO silent fallback to DB polling
/// (a second projector owner racing the composition is strictly worse than a
/// loud, restartable startup failure).
pub fn start_authorization_projector(
    db: MySqlPool,
    config: AuthorizationProjectorConfig,
) -> AuthorizationProjectorHandle {
    if crate::service::local_projection_worker::local_projection_direct_path_ready() {
        return match crate::service::local_projection_worker::start_local_projection_worker(
            db,
            crate::service::local_projection_worker::LocalProjectionWorkerConfig {
                projector: config,
                ..Default::default()
            },
        ) {
            Ok(handle) => {
                tracing::info!(
                    run_id = %handle.run_id,
                    "authorization projector started on the in-process local bus path \
                     (DB-poll loop disabled; low-frequency proven recovery only)"
                );
                handle
            }
            Err(error) => {
                // Terminal: no DB-poll fallback. The join resolves Err at once
                // so the caller's shutdown/join path observes the failure and
                // the process can exit/restart loudly. Additionally record the
                // required-owner failure NOW (global liveness Dead + hub
                // sticky runtime_owner_failed) so a rejected start — e.g. the
                // empty-tenant-scope contract — is a loud composite-level
                // startup failure instead of a process serving strict-DB
                // reads with no projection owner.
                crate::service::local_projection_worker::record_local_worker_start_failure(
                    &error.to_string(),
                );
                tracing::error!(
                    error = %error,
                    "in-process projector start failed terminally; NO DB-poll fallback \
                     (single-node discipline), restart required"
                );
                AuthorizationProjectorHandle {
                    cancellation: ProjectorCancellationToken::default(),
                    join: tokio::spawn(async move {
                        Err(format!(
                            "code=auth_projector.local_start_failed_terminally;error={error}"
                        ))
                    }),
                    run_id: uuid::Uuid::new_v4().to_string(),
                    health: Arc::new(ProjectorHealthShared::new()),
                }
            }
        };
    }
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
pub(crate) async fn run_partition_worker(
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

/// A lease-guarded mutation matched zero rows: expired, stolen or terminal.
/// That is an UNKNOWN result requiring reconciliation BEFORE any further
/// mutation on this event — never blind repetition.
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
/// （[`crate::service::sync_publish`]）在 source 事务提交后复用同一管线在请求内发布
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

    process_verified_claim(
        runtime,
        config,
        lease_owner,
        cancellation,
        claimed,
        &claimed_row,
        identity,
        readback_us,
        summary,
    )
    .await;
}

/// Phases 2-5 of the projector pipeline for a claim whose payload and lease
/// are ALREADY verified in hand.
///
/// `claimed_row` is the strict [`ClaimedDeltaEvent`] for `claimed`: either the
/// queue path's post-claim readback, or the direct-dispatch path's
/// same-transaction claim payload (`claim_delta_event_by_stable_event_in_tx`
/// returns claim + payload from ONE committed transaction, so the direct path
/// never reloads the payload by id). `readback_us` carries the queue path's
/// readback timing (`0` on the direct path) for the phase log.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn process_verified_claim(
    runtime: &Arc<dyn AuthorizationProjectorRuntime>,
    config: &AuthorizationProjectorConfig,
    lease_owner: &str,
    cancellation: &ProjectorCancellationToken,
    claimed: &DeltaEventClaim,
    claimed_row: &ClaimedDeltaEvent,
    identity: ProjectionAggregateIdentity,
    readback_us: u64,
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
            .load_scope_ledger_shared(
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
            claimed: claimed_row,
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
pub(crate) fn quarantine_reason_parts(reason: &str) -> (String, String) {
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
pub(crate) async fn quarantine_event_terminal(
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
        Err(
            RuntimeAccessError::Database(query_failure)
            | RuntimeAccessError::PublicationUnknown(query_failure)
            | RuntimeAccessError::CommittedMirrorUnavailable(query_failure),
        ) => {
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
pub(crate) async fn fail_with_budget(
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
                        PublishFailureHandling::CommittedMirrorUnavailable { reason } => {
                            summary.events_committed_mirror_unavailable += 1;
                            record_projector_event(
                                ProjectorEventOutcome::CommittedMirrorUnavailable,
                            );
                            tracing::error!(
                                event_id = %claimed.event_id,
                                operation_id = %claimed.operation_id,
                                reason = %reason,
                                durable_committed = true,
                                "local mirror unavailable after commit; strict reads continue, restart rebuild required"
                            );
                        }
                        PublishFailureHandling::PublicationUnknown { reason } => {
                            summary.events_publication_unknown += 1;
                            record_projector_event(ProjectorEventOutcome::PublicationUnknown);
                            #[cfg(feature = "e3-observability")]
                            log_e3_attempt_event(
                                "terminal_unknown",
                                claimed,
                                "publication_unknown",
                                false,
                                None,
                            );
                            tracing::warn!(
                                event_id = %claimed.event_id,
                                operation_id = %claimed.operation_id,
                                reason = %reason,
                                "publication requires reconciliation; no retry or lease mutation"
                            );
                        }
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
