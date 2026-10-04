//! Projector 启动配置与共享健康快照。
//!
//! 承载 Exec-L2 预算常量、调度模式、租户/worker 预算解析与
//! [`ProjectorHealthShared`] 聚合健康态；worker 生命周期见主模块与 worker 区块。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{unix_millis, ProjectorProgress, WorkerRunSummary};
use astral_db::MAX_MANIFEST_LEASE_SECONDS;

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
pub(crate) const MAX_POINTER_MOVED_REPLANS: usize = 3;
/// Maximum events processed per tenant within one poll cycle.
pub(crate) const MAX_EVENTS_PER_TENANT_PER_CYCLE: usize = 8;

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
pub(crate) const MAX_EVENTS_PER_PARTITION_PER_BATCH: usize = 8;
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
    pub(crate) fn new() -> Self {
        Self {
            started_at_ms: unix_millis(),
            generation: AtomicU64::new(0),
            restarts: AtomicU64::new(0),
            summary: std::sync::Mutex::new(WorkerRunSummary::default()),
            progress: std::sync::Mutex::new(Arc::new(ProjectorProgress::default())),
        }
    }

    pub(crate) fn next_generation(&self) -> u64 {
        self.generation.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub(crate) fn swap_progress(&self, progress: Arc<ProjectorProgress>) {
        if let Ok(mut guard) = self.progress.lock() {
            *guard = progress;
        }
    }

    /// Mark progress on the current generation's baseline (worker loop use).
    pub(crate) fn note_progress(&self) {
        if let Ok(guard) = self.progress.lock() {
            guard.touch();
        }
    }

    /// 当前代进展年龄（毫秒）；尚未产生基线 → `None`。
    pub(crate) fn progress_age_ms(&self) -> Option<u64> {
        let guard = self.progress.lock().ok()?;
        guard.age_ms()
    }

    pub(crate) fn merge_summary(&self, summary: &WorkerRunSummary) {
        if let Ok(mut guard) = self.summary.lock() {
            guard.merge(summary);
        }
    }

    pub(crate) fn take_summary(&self) -> WorkerRunSummary {
        self.summary
            .lock()
            .map(|mut guard| std::mem::take(&mut *guard))
            .unwrap_or_default()
    }

    pub(crate) fn record_restart(&self) {
        self.restarts.fetch_add(1, Ordering::Relaxed);
    }

    /// 当前代进展年龄（秒）；当前代尚无任何进展 → `None`。
    pub(crate) fn progress_age_secs(&self) -> Option<u64> {
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
