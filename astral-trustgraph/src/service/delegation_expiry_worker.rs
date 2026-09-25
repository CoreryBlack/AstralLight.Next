//! 委托到期对账 worker（Rust-owned，对齐 Java 无等价物 —— 新增运维职责）
//!
//! 唯一职责：周期性调用 [`DelegationWriteService::reconcile_expired_delegations`]
//! （显式有界、幂等的到期对账入口）。worker 不复制 SQL、不发明任何 source
//! mutation，也不做网络/MQ/cache 副作用；每次候选对账的落库收敛都发生在
//! repository 各自的单一 source transaction 内（事务边界语义保持不变）。
//!
//! 候选发现说明：`permission_delegation` 源表暂无 `tenant_id` 列，候选发现
//! 只能跨租户（不改 schema、不加索引）；每条候选的实际收敛在各自 source
//! transaction 内以 `FOR UPDATE` 锁定端点 `user_card` 行，tenant/domain 归属
//! 由锁定卡事实重新证明并在 facts 组装期 fail-closed（缺失即 Validation 错误），
//! grant head 查找同样按 `tenant_id` 收口 —— 跨租户漂移的候选只会收敛失败，
//! source 保持不变。
//!
//! 生命周期对齐同 crate 既有 worker 约定：配置在 spawn 之前 fall-fast 校验
//! （非法即启动失败，无任务、无副作用）；`main` 持有 handle，关闭时 cancel →
//! 有界 join，超时/panic/Err 显式转为进程错误，绝不静默吞掉断流状态。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use astral_types::AstralError;

use crate::repository::delegation_repository::{
    validated_expiry_batch_limit, MAX_EXPIRY_RECONCILIATION_BATCH,
};
use crate::service::delegation_service::{DelegationExpiryBatchReport, DelegationWriteService};

/// 默认轮询间隔（秒）。
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 60;
/// 默认对账批次（每轮候选上限；实际边界由 repository 单一事实源再校验）。
pub const DEFAULT_BATCH_LIMIT: i64 = 64;
/// 轮询间隔显式上限（秒）：防止非法配置把 worker 静默变成"永不轮询"。
pub const MAX_POLL_INTERVAL_SECS: u64 = 3600;
/// 周期失败后的退避下限。
const ERROR_BACKOFF_MIN: Duration = Duration::from_secs(1);
/// 周期失败后的退避上限（有限退避，绝不无界增长/无界循环）。
const ERROR_BACKOFF_MAX: Duration = Duration::from_secs(30);

/// worker 启动配置；默认值即契约默认（60s / 64）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DelegationExpiryWorkerConfig {
    pub poll_interval_secs: u64,
    pub batch_limit: i64,
}

impl Default for DelegationExpiryWorkerConfig {
    fn default() -> Self {
        Self {
            poll_interval_secs: DEFAULT_POLL_INTERVAL_SECS,
            batch_limit: DEFAULT_BATCH_LIMIT,
        }
    }
}

impl DelegationExpiryWorkerConfig {
    /// spawn 之前的 fail-fast 校验（Exec-L2 启动门禁）：
    /// - `poll_interval_secs` 必须在 `1..=MAX_POLL_INTERVAL_SECS`；
    /// - `batch_limit` 复用 repository 的单一事实源
    ///   [`validated_expiry_batch_limit`]（正数且 ≤ MAX_EXPIRY_RECONCILIATION_BATCH=500）。
    ///
    /// 非法配置返回 [`DelegationExpiryConfigError`]，调用方必须拒绝启动，
    /// 绝不降级为"顺便用默认值"。
    pub fn validate(&self) -> Result<(), DelegationExpiryConfigError> {
        if self.poll_interval_secs == 0 || self.poll_interval_secs > MAX_POLL_INTERVAL_SECS {
            return Err(DelegationExpiryConfigError::PollInterval {
                value: self.poll_interval_secs,
            });
        }
        validated_expiry_batch_limit(self.batch_limit)
            .map(|_| ())
            .map_err(|_| DelegationExpiryConfigError::BatchLimit {
                value: self.batch_limit,
            })
    }

    fn poll_interval(&self) -> Duration {
        Duration::from_secs(self.poll_interval_secs)
    }
}

/// 启动配置拒绝（spawn 前产生，无任何任务/持久/外部副作用）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DelegationExpiryConfigError {
    #[error(
        "delegation expiry worker poll_interval_secs={value} must be within \
         1..={MAX_POLL_INTERVAL_SECS}"
    )]
    PollInterval {
        /// The offending configured poll interval.
        value: u64,
    },
    #[error(
        "delegation expiry worker batch_limit={value} must be a positive integer \
         within 1..={MAX_EXPIRY_RECONCILIATION_BATCH}"
    )]
    BatchLimit {
        /// The offending configured batch limit.
        value: i64,
    },
    #[error("delegation expiry worker env {name}={value} is not a valid integer")]
    Parse {
        /// The offending environment variable name.
        name: &'static str,
        /// The raw offending value.
        value: String,
    },
}

/// 纯函数解析 env 覆盖值（None/空串 = 用默认；非法整数或越界一律错误），
/// 不直接读进程环境，保证可单测。
pub fn parse_delegation_expiry_config(
    poll_raw: Option<&str>,
    batch_raw: Option<&str>,
) -> Result<DelegationExpiryWorkerConfig, DelegationExpiryConfigError> {
    let mut config = DelegationExpiryWorkerConfig::default();
    if let Some(raw) = poll_raw.map(str::trim).filter(|raw| !raw.is_empty()) {
        config.poll_interval_secs =
            raw.parse::<u64>()
                .map_err(|_| DelegationExpiryConfigError::Parse {
                    name: "ASTRAL_DELEGATION_EXPIRY_POLL_SECS",
                    value: raw.to_owned(),
                })?;
    }
    if let Some(raw) = batch_raw.map(str::trim).filter(|raw| !raw.is_empty()) {
        config.batch_limit =
            raw.parse::<i64>()
                .map_err(|_| DelegationExpiryConfigError::Parse {
                    name: "ASTRAL_DELEGATION_EXPIRY_BATCH",
                    value: raw.to_owned(),
                })?;
    }
    config.validate()?;
    Ok(config)
}

/// 对账入口 seam：worker 只依赖本 trait，测试用 Fake 替换，
/// 生产装配绑定 [`DelegationWriteService`] 的既有实现（不复制任何 SQL）。
#[async_trait]
pub trait DelegationExpiryReconciler: Send + Sync {
    async fn reconcile_expired_delegations(
        &self,
        batch_limit: i64,
    ) -> Result<DelegationExpiryBatchReport, AstralError>;
}

#[async_trait]
impl DelegationExpiryReconciler for DelegationWriteService {
    async fn reconcile_expired_delegations(
        &self,
        batch_limit: i64,
    ) -> Result<DelegationExpiryBatchReport, AstralError> {
        // 显式限定固有方法，避免误递归进 trait impl 自身。
        DelegationWriteService::reconcile_expired_delegations(self, batch_limit).await
    }
}

/// 本 worker 私有的取消令牌（与 audit replay / archive worker 同一模式）：
/// `main` 与测试只见 `cancel()`；run 循环用 crate 内私有 wait/check seam。
#[derive(Clone, Default)]
pub struct DelegationExpiryCancellationToken {
    cancelled: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl DelegationExpiryCancellationToken {
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

/// 累计运行统计（关闭时随 handle 一次性返回，供对账观测）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DelegationExpiryRunSummary {
    pub cycles: u64,
    pub cycle_errors: u64,
    pub all_failed_cycles: u64,
    pub candidates: u64,
    pub reconciled: u64,
    pub already_terminal: u64,
    pub not_yet_due: u64,
    pub failed_items: u64,
}

impl DelegationExpiryRunSummary {
    fn record_batch(&mut self, report: &DelegationExpiryBatchReport) {
        self.candidates = self.candidates.saturating_add(report.candidates as u64);
        self.reconciled = self.reconciled.saturating_add(report.reconciled as u64);
        self.already_terminal = self
            .already_terminal
            .saturating_add(report.already_terminal as u64);
        self.not_yet_due = self.not_yet_due.saturating_add(report.not_yet_due as u64);
        self.failed_items = self.failed_items.saturating_add(report.failed.len() as u64);
    }

    fn log_final(&self, run_id: &str) {
        tracing::info!(
            run_id = %run_id,
            cycles = self.cycles,
            cycle_errors = self.cycle_errors,
            all_failed_cycles = self.all_failed_cycles,
            candidates = self.candidates,
            reconciled = self.reconciled,
            already_terminal = self.already_terminal,
            not_yet_due = self.not_yet_due,
            failed_items = self.failed_items,
            "delegation expiry worker final run summary"
        );
    }
}

/// Handle held by `main`; graceful shutdown cancels then joins with a bound.
/// Timeout, task panic and worker `Err` all surface explicitly.
pub struct DelegationExpiryWorkerHandle {
    pub cancellation: DelegationExpiryCancellationToken,
    pub join: JoinHandle<Result<DelegationExpiryRunSummary, tokio::task::JoinError>>,
    /// Run-scoped identifier used in logs; never stable across restarts and
    /// never usable as authorization identity.
    pub run_id: String,
}

#[derive(Debug)]
pub struct DelegationExpiryShutdownReport {
    pub summary: Result<DelegationExpiryRunSummary, String>,
    pub join_elapsed: Duration,
}

/// Cancel the worker and await termination within a bounded timeout.
///
/// `Err(summary)` forms cover: worker panic/join failure, propagated worker
/// `Err`, timeout. A dying or stuck worker can never be reported as a clean
/// shutdown — the caller turns non-clean shutdowns into process errors.
pub async fn shutdown_delegation_expiry_worker(
    handle: DelegationExpiryWorkerHandle,
    timeout: Duration,
) -> DelegationExpiryShutdownReport {
    handle.cancellation.cancel();
    let started = Instant::now();
    let summary = match tokio::time::timeout(timeout, handle.join).await {
        Ok(joined) => match joined {
            Ok(Ok(summary)) => Ok(summary),
            Ok(Err(join_error)) => Err(format!("worker task failed: {join_error}")),
            Err(_) => Err("shutdown summary unavailable".to_owned()),
        },
        Err(_) => Err(format!(
            "delegation expiry worker did not stop within {timeout:?}; possibly \
             wedged inside a reconciliation transaction"
        )),
    };
    tracing::info!(
        run_id = %handle.run_id,
        join_elapsed_ms = started.elapsed().as_millis() as u64,
        clean = summary.is_ok(),
        "delegation expiry worker shutdown completed"
    );
    DelegationExpiryShutdownReport {
        summary,
        join_elapsed: started.elapsed(),
    }
}

/// Start one owned expiry worker bound to the production write service. The
/// caller MUST keep the handle and invoke
/// [`shutdown_delegation_expiry_worker`] during shutdown.
///
/// # Errors
/// Returns [`DelegationExpiryConfigError`] without spawning any task and
/// without touching the service when `config` fails validation.
pub fn start_delegation_expiry_worker(
    service: Arc<DelegationWriteService>,
    config: DelegationExpiryWorkerConfig,
) -> Result<DelegationExpiryWorkerHandle, DelegationExpiryConfigError> {
    config.validate()?;
    let reconciler: Arc<dyn DelegationExpiryReconciler> = service;
    start_delegation_expiry_worker_with_reconciler(reconciler, config)
}

/// Start one owned expiry worker on the supplied reconciler seam（测试/Fake 入口）.
///
/// # Errors
/// Returns [`DelegationExpiryConfigError`] without spawning any task（supplied
/// reconciler 完全不被触碰）when `config` fails validation.
pub fn start_delegation_expiry_worker_with_reconciler(
    reconciler: Arc<dyn DelegationExpiryReconciler>,
    config: DelegationExpiryWorkerConfig,
) -> Result<DelegationExpiryWorkerHandle, DelegationExpiryConfigError> {
    config.validate()?;
    let cancellation = DelegationExpiryCancellationToken::default();
    let run_cancellation = cancellation.clone();
    let run_id = uuid::Uuid::new_v4().to_string();
    let join = tokio::spawn(run_worker(
        reconciler,
        config,
        run_id.clone(),
        run_cancellation,
    ));
    Ok(DelegationExpiryWorkerHandle {
        cancellation,
        join,
        run_id,
    })
}

async fn run_worker(
    reconciler: Arc<dyn DelegationExpiryReconciler>,
    config: DelegationExpiryWorkerConfig,
    run_id: String,
    cancellation: DelegationExpiryCancellationToken,
) -> Result<DelegationExpiryRunSummary, tokio::task::JoinError> {
    let mut summary = DelegationExpiryRunSummary::default();
    let mut consecutive_failures: u32 = 0;
    tracing::info!(
        run_id = %run_id,
        poll_interval_secs = config.poll_interval_secs,
        batch_limit = config.batch_limit,
        max_batch_limit = MAX_EXPIRY_RECONCILIATION_BATCH,
        "delegation expiry worker loop started; candidate discovery is \
         cross-tenant because permission_delegation has no tenant_id column, \
         each mutation re-proves tenant/domain scope under locked endpoint \
         cards inside its own source transaction (fail-closed)"
    );
    loop {
        if cancellation.is_cancelled() {
            tracing::info!(run_id = %run_id, "delegation expiry worker stopped");
            break;
        }
        // 一轮 = 一次 service 调用 = 至多 batch_limit 条候选，每条候选各一个
        // 短 source transaction；取消只发生在轮与轮之间，绝不 abort 进行中的
        // 对账事务。
        let cycle_result = reconciler
            .reconcile_expired_delegations(config.batch_limit)
            .await;
        summary.cycles = summary.cycles.saturating_add(1);
        match cycle_result {
            Ok(report) => {
                summary.record_batch(&report);
                let failed_ids: Vec<i64> = report.failed.iter().map(|(id, _)| *id).collect();
                let health = classify_batch_report(&report);
                match health {
                    CycleHealth::Healthy => {
                        consecutive_failures = 0;
                        if report.candidates == 0 {
                            tracing::debug!(
                                run_id = %run_id,
                                "delegation expiry cycle found no candidates"
                            );
                        } else {
                            tracing::info!(
                                run_id = %run_id,
                                candidates = report.candidates,
                                reconciled = report.reconciled,
                                already_terminal = report.already_terminal,
                                not_yet_due = report.not_yet_due,
                                failed = report.failed.len(),
                                "delegation expiry reconciliation cycle completed"
                            );
                        }
                    }
                    CycleHealth::AllFailed => {
                        consecutive_failures = consecutive_failures.saturating_add(1);
                        summary.all_failed_cycles = summary.all_failed_cycles.saturating_add(1);
                        tracing::warn!(
                            run_id = %run_id,
                            candidates = report.candidates,
                            failed_ids = ?failed_ids,
                            consecutive_failures,
                            "every delegation expiry candidate failed; source left unchanged"
                        );
                    }
                }
                let wait =
                    next_wait_after_batch(health, consecutive_failures, config.poll_interval());
                wait_or_cancel(&cancellation, wait).await;
            }
            Err(error) => {
                consecutive_failures = consecutive_failures.saturating_add(1);
                summary.cycle_errors = summary.cycle_errors.saturating_add(1);
                tracing::error!(
                    run_id = %run_id,
                    consecutive_failures,
                    error = %error,
                    "delegation expiry cycle failed against the reconciliation service"
                );
                wait_or_cancel(&cancellation, backoff_delay(consecutive_failures)).await;
            }
        }
    }
    summary.log_final(&run_id);
    Ok(summary)
}

async fn wait_or_cancel(cancellation: &DelegationExpiryCancellationToken, duration: Duration) {
    tokio::select! {
        _ = cancellation.cancelled() => {}
        _ = tokio::time::sleep(duration) => {}
    }
}

/// 单轮批次结果的健康分类（纯函数）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CycleHealth {
    /// 空转、部分收敛或全部收敛：无需退避。
    Healthy,
    /// 有候选但每一条都失败：按连续失败退避。
    AllFailed,
}

fn classify_batch_report(report: &DelegationExpiryBatchReport) -> CycleHealth {
    if report.candidates > 0 && report.failed.len() == report.candidates {
        CycleHealth::AllFailed
    } else {
        CycleHealth::Healthy
    }
}

/// 批次结果之后的等待时长（纯函数）：健康 = 正常轮询间隔；
/// 全失败 = 有限指数退避。
fn next_wait_after_batch(
    health: CycleHealth,
    consecutive_failures: u32,
    poll_interval: Duration,
) -> Duration {
    match health {
        CycleHealth::Healthy => poll_interval,
        CycleHealth::AllFailed => backoff_delay(consecutive_failures),
    }
}

/// 有限指数退避：1s 起步、按连续失败翻倍、硬上限 [`ERROR_BACKOFF_MAX`]，
/// 绝不无界增长（连续失败计数只影响倍率封顶，不产生无界等待）。
fn backoff_delay(consecutive_failures: u32) -> Duration {
    let multiplier = 2u64.saturating_pow(consecutive_failures.saturating_sub(1).min(5));
    ERROR_BACKOFF_MIN
        .checked_mul(multiplier as u32)
        .unwrap_or(ERROR_BACKOFF_MAX)
        .min(ERROR_BACKOFF_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// 可编排返回值并记录调用批次的 Fake（绝不触库）。
    struct ScriptedReconciler {
        calls: Mutex<Vec<i64>>,
        report: Mutex<DelegationExpiryBatchReport>,
        error_message: Mutex<Option<String>>,
    }

    impl ScriptedReconciler {
        fn idle() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                report: Mutex::new(DelegationExpiryBatchReport::default()),
                error_message: Mutex::new(None),
            }
        }

        fn with_report(report: DelegationExpiryBatchReport) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                report: Mutex::new(report),
                error_message: Mutex::new(None),
            }
        }

        fn failing(message: &str) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                report: Mutex::new(DelegationExpiryBatchReport::default()),
                error_message: Mutex::new(Some(message.to_owned())),
            }
        }

        fn calls(&self) -> Vec<i64> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl DelegationExpiryReconciler for ScriptedReconciler {
        async fn reconcile_expired_delegations(
            &self,
            batch_limit: i64,
        ) -> Result<DelegationExpiryBatchReport, AstralError> {
            self.calls.lock().unwrap().push(batch_limit);
            match &*self.error_message.lock().unwrap() {
                Some(message) => Err(AstralError::Internal(message.clone())),
                None => Ok(self.report.lock().unwrap().clone()),
            }
        }
    }

    /// 记录一次调用后永不返回：用于证明有界 join 的超时分支。
    struct HangingReconciler {
        calls: Mutex<Vec<i64>>,
    }

    impl HangingReconciler {
        fn calls(&self) -> Vec<i64> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl DelegationExpiryReconciler for HangingReconciler {
        async fn reconcile_expired_delegations(
            &self,
            batch_limit: i64,
        ) -> Result<DelegationExpiryBatchReport, AstralError> {
            self.calls.lock().unwrap().push(batch_limit);
            std::future::pending::<()>().await;
            unreachable!("pending future never resolves");
        }
    }

    async fn wait_for_calls(reconciler: &ScriptedReconciler, min_calls: usize) {
        wait_for_call_count(|| reconciler.calls().len(), min_calls).await;
    }

    /// 轮询等待 worker 到达指定调用数（真实时间，5s 预算内必须达成），
    /// 消除"取消先于第一轮"的测试竞态。
    async fn wait_for_call_count(call_count: impl Fn() -> usize, min_calls: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if call_count() >= min_calls {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "worker did not reach {min_calls} cycles within the test budget"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn all_failed_report(candidates: usize) -> DelegationExpiryBatchReport {
        DelegationExpiryBatchReport {
            candidates,
            reconciled: 0,
            already_terminal: 0,
            not_yet_due: 0,
            failed: (1..=candidates as i64)
                .map(|id| (id, "drift".to_owned()))
                .collect(),
        }
    }

    #[test]
    fn default_config_matches_the_contract() {
        let config = DelegationExpiryWorkerConfig::default();
        assert_eq!(config.poll_interval_secs, 60);
        assert_eq!(config.batch_limit, 64);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn config_validation_enforces_bounds_fail_closed() {
        // batch：正数且 ≤ 500（与 repository 单一事实源一致）。
        assert!(DelegationExpiryWorkerConfig {
            batch_limit: 1,
            ..Default::default()
        }
        .validate()
        .is_ok());
        assert!(DelegationExpiryWorkerConfig {
            batch_limit: 500,
            ..Default::default()
        }
        .validate()
        .is_ok());
        for bad_batch in [0, -3, 501] {
            let error = DelegationExpiryWorkerConfig {
                batch_limit: bad_batch,
                ..Default::default()
            }
            .validate()
            .unwrap_err();
            assert_eq!(
                error,
                DelegationExpiryConfigError::BatchLimit { value: bad_batch }
            );
        }
        // poll：1..=3600。
        for good_poll in [1, 60, 3600] {
            assert!(DelegationExpiryWorkerConfig {
                poll_interval_secs: good_poll,
                ..Default::default()
            }
            .validate()
            .is_ok());
        }
        for bad_poll in [0u64, 3601, u64::MAX] {
            let error = DelegationExpiryWorkerConfig {
                poll_interval_secs: bad_poll,
                ..Default::default()
            }
            .validate()
            .unwrap_err();
            assert_eq!(
                error,
                DelegationExpiryConfigError::PollInterval { value: bad_poll }
            );
        }
    }

    #[test]
    fn parse_config_uses_defaults_for_missing_and_empty_values() {
        let config = parse_delegation_expiry_config(None, None).unwrap();
        assert_eq!(config, DelegationExpiryWorkerConfig::default());
        let config = parse_delegation_expiry_config(Some("   "), Some("")).unwrap();
        assert_eq!(config, DelegationExpiryWorkerConfig::default());
    }

    #[test]
    fn parse_config_applies_valid_overrides() {
        let config = parse_delegation_expiry_config(Some("5"), Some("7")).unwrap();
        assert_eq!(
            config,
            DelegationExpiryWorkerConfig {
                poll_interval_secs: 5,
                batch_limit: 7,
            }
        );
        // 越界覆盖必须在 spawn 前失败，绝不静默回退默认值。
        assert_eq!(
            parse_delegation_expiry_config(Some("0"), None).unwrap_err(),
            DelegationExpiryConfigError::PollInterval { value: 0 }
        );
        assert_eq!(
            parse_delegation_expiry_config(None, Some("501")).unwrap_err(),
            DelegationExpiryConfigError::BatchLimit { value: 501 }
        );
        assert_eq!(
            parse_delegation_expiry_config(None, Some("-2")).unwrap_err(),
            DelegationExpiryConfigError::BatchLimit { value: -2 }
        );
        assert!(matches!(
            parse_delegation_expiry_config(Some("soon"), None).unwrap_err(),
            DelegationExpiryConfigError::Parse { .. }
        ));
        assert!(matches!(
            parse_delegation_expiry_config(None, Some("64x")).unwrap_err(),
            DelegationExpiryConfigError::Parse { .. }
        ));
    }

    #[test]
    fn batch_bound_is_500_no_matter_what_the_caller_configures() {
        // 硬上限来自 repository 单一事实源；worker 起点校验与 service 内部
        // 校验共享同一判定，双保险但同一边界。
        assert_eq!(MAX_EXPIRY_RECONCILIATION_BATCH, 500);
        for oversized in [501, 1000, i64::MAX] {
            assert!(DelegationExpiryWorkerConfig {
                batch_limit: oversized,
                ..Default::default()
            }
            .validate()
            .is_err());
        }
    }

    #[test]
    fn classify_batch_report_maps_to_backoff_only_when_everything_failed() {
        assert_eq!(
            classify_batch_report(&DelegationExpiryBatchReport::default()),
            CycleHealth::Healthy
        );
        let mixed = DelegationExpiryBatchReport {
            candidates: 3,
            reconciled: 1,
            already_terminal: 1,
            not_yet_due: 0,
            failed: vec![(9, "drift".to_owned())],
        };
        assert_eq!(classify_batch_report(&mixed), CycleHealth::Healthy);
        assert_eq!(
            classify_batch_report(&all_failed_report(2)),
            CycleHealth::AllFailed
        );
    }

    #[test]
    fn backoff_is_finite_and_bounded() {
        assert_eq!(backoff_delay(1), Duration::from_secs(1));
        assert_eq!(backoff_delay(2), Duration::from_secs(2));
        assert_eq!(backoff_delay(3), Duration::from_secs(4));
        assert_eq!(backoff_delay(6), Duration::from_secs(30));
        assert_eq!(backoff_delay(u32::MAX), Duration::from_secs(30));
    }

    #[test]
    fn next_wait_uses_poll_interval_when_healthy_and_backoff_when_all_failed() {
        let poll = Duration::from_secs(60);
        assert_eq!(next_wait_after_batch(CycleHealth::Healthy, 0, poll), poll);
        assert_eq!(
            next_wait_after_batch(CycleHealth::AllFailed, 1, poll),
            Duration::from_secs(1)
        );
        assert_eq!(
            next_wait_after_batch(CycleHealth::AllFailed, 3, poll),
            Duration::from_secs(4)
        );
    }

    #[tokio::test]
    async fn worker_uses_configured_batch_and_shuts_down_cleanly_after_cancel() {
        let reconciler = Arc::new(ScriptedReconciler::idle());
        let handle = start_delegation_expiry_worker_with_reconciler(
            reconciler.clone(),
            DelegationExpiryWorkerConfig {
                poll_interval_secs: 3600,
                batch_limit: 7,
            },
        )
        .unwrap();

        // 第一轮在 spawn 后立即执行且恰好使用配置批次（有界，无内部放大）。
        wait_for_calls(&reconciler, 1).await;
        assert_eq!(reconciler.calls(), vec![7]);
        assert!(!handle.cancellation.is_cancelled());

        // 取消发生在轮间 sleep 中：join 必须立刻完成且带完整统计。
        handle.cancellation.cancel();
        let report = shutdown_delegation_expiry_worker(handle, Duration::from_secs(5)).await;
        let summary = report.summary.expect("clean shutdown must carry a summary");
        assert_eq!(summary.cycles, 1);
        assert_eq!(summary.candidates, 0);
        assert_eq!(summary.cycle_errors, 0);
        assert_eq!(reconciler.calls(), vec![7]);
    }

    #[tokio::test]
    async fn service_errors_do_not_wedge_shutdown_and_are_counted() {
        let reconciler = Arc::new(ScriptedReconciler::failing("reconciliation unavailable"));
        let handle = start_delegation_expiry_worker_with_reconciler(
            reconciler.clone(),
            DelegationExpiryWorkerConfig::default(),
        )
        .unwrap();

        wait_for_calls(&reconciler, 1).await;
        handle.cancellation.cancel();
        let report = shutdown_delegation_expiry_worker(handle, Duration::from_secs(5)).await;
        let summary = report.summary.expect("clean shutdown must carry a summary");
        assert!(summary.cycles >= 1);
        assert!(summary.cycle_errors >= 1);
        assert!(report.join_elapsed < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn all_candidates_failed_cycles_are_counted_as_backoff_cycles() {
        let reconciler = Arc::new(ScriptedReconciler::with_report(all_failed_report(2)));
        let handle = start_delegation_expiry_worker_with_reconciler(
            reconciler.clone(),
            DelegationExpiryWorkerConfig::default(),
        )
        .unwrap();

        wait_for_calls(&reconciler, 1).await;
        handle.cancellation.cancel();
        let report = shutdown_delegation_expiry_worker(handle, Duration::from_secs(5)).await;
        let summary = report.summary.expect("clean shutdown must carry a summary");
        assert!(summary.cycles >= 1);
        assert!(summary.all_failed_cycles >= 1);
        assert_eq!(summary.candidates, 2);
        assert_eq!(summary.failed_items, 2);
        assert_eq!(summary.reconciled, 0);
        assert_eq!(summary.cycle_errors, 0);
    }

    #[tokio::test]
    async fn shutdown_is_bounded_when_the_reconciler_never_returns() {
        let reconciler = Arc::new(HangingReconciler {
            calls: Mutex::new(Vec::new()),
        });
        let handle = start_delegation_expiry_worker_with_reconciler(
            reconciler.clone(),
            DelegationExpiryWorkerConfig::default(),
        )
        .unwrap();

        // 等到 worker 真正进入卡死的对账调用，再取消：证明进行中的调用不会被
        // 报告成干净关闭，join 必须在时限内显式失败。
        wait_for_call_count(|| reconciler.calls().len(), 1).await;
        let report = shutdown_delegation_expiry_worker(handle, Duration::from_millis(100)).await;
        let failure = report
            .summary
            .expect_err("wedged worker must fail shutdown");
        assert!(failure.contains("did not stop within"));
    }

    #[tokio::test]
    async fn start_rejects_invalid_config_before_spawning_anything() {
        let reconciler = Arc::new(ScriptedReconciler::idle());
        for bad in [0, -1, 501] {
            let error = match start_delegation_expiry_worker_with_reconciler(
                reconciler.clone(),
                DelegationExpiryWorkerConfig {
                    batch_limit: bad,
                    ..Default::default()
                },
            ) {
                Err(error) => error,
                Ok(_) => panic!("config batch_limit={bad} must be rejected before spawn"),
            };
            assert_eq!(
                error,
                DelegationExpiryConfigError::BatchLimit { value: bad }
            );
        }
        // 校验失败路径绝不触碰 reconciler（无调用、无任务）。
        assert!(reconciler.calls().is_empty());
    }
}
