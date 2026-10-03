//! 定时采集后台任务 — 对应 Java `MetricCollectTask` + `AlertEvaluationTask`。
//!
//! Service probes only use an explicitly registered endpoint/authentication
//! contract. Existing Learn health is Gateway-signature protected and Chat has no
//! registered `/api/health` route, so neither is fetched with an unsigned request;
//! an unavailable probe contract is recorded as UNKNOWN rather than DOWN.
//!
//! Shutdown is cooperative and bounded. The collector owns its JoinSet of alert
//! dispatches and never detaches one task per alert.

use std::time::{Duration, Instant};

use tokio::sync::watch;
use tokio::task::{JoinError, JoinHandle, JoinSet};
use tokio::time::interval;

use astral_common::config::AppConfig;

use crate::dispatch;
use crate::AppState;

const MAX_ALERT_DISPATCH_CONCURRENCY: usize = 4;
const ALERT_DISPATCH_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const COLLECTOR_SHUTDOWN_JOIN_TIMEOUT: Duration = Duration::from_secs(1);

/// Registered service health endpoint/authentication contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeContract {
    /// A real path exists, but requires Gateway v3 identity signing. The monitor
    /// currently has no service-principal identity and must not synthesize one.
    GatewaySigned { path: &'static str },
    /// No registered endpoint contract exists for this service.
    Unavailable { reason: &'static str },
}

#[derive(Debug, Clone)]
struct ProbeTarget {
    service_name: &'static str,
    contract: ProbeContract,
}

/// Owned collector task and cooperative stop channel.
pub struct CollectorHandle {
    stop: watch::Sender<bool>,
    join: Option<JoinHandle<Result<(), String>>>,
    terminal_result: Option<Result<(), String>>,
}

impl CollectorHandle {
    /// Request cooperative shutdown. The owner must still call `shutdown` to
    /// observe the task's terminal result.
    pub fn request_shutdown(&self) {
        self.stop.send_replace(true);
    }

    /// Wait for the owned collector task to exit unexpectedly, including panic.
    /// The task's completion is cached so `shutdown` does not poll the completed
    /// JoinHandle a second time.
    pub async fn wait_for_death(&mut self) -> String {
        let Some(join) = self.join.as_mut() else {
            return "monitor collector task handle unavailable".into();
        };
        let result = match (&mut *join).await {
            Ok(result) => result,
            Err(error) => Err(format!("monitor collector task failed: {error}")),
        };
        let reason = result
            .as_ref()
            .err()
            .cloned()
            .unwrap_or_else(|| "monitor collector stopped unexpectedly".into());
        self.terminal_result = Some(result);
        self.join.take();
        reason
    }

    /// Stop and join the collector within `deadline`, aborting and observing it
    /// if a cycle or bounded dispatch drain fails to finish in time.
    pub async fn shutdown(mut self, deadline: Duration) -> Result<(), String> {
        self.request_shutdown();
        if let Some(result) = self.terminal_result.take() {
            return result;
        }
        let Some(join) = self.join.as_mut() else {
            return Ok(());
        };
        match tokio::time::timeout(deadline, &mut *join).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => Err(format!("monitor collector task failed: {error}")),
            Err(_) => {
                join.abort();
                match tokio::time::timeout(COLLECTOR_SHUTDOWN_JOIN_TIMEOUT, &mut *join).await {
                    Ok(Err(error)) if error.is_cancelled() => Err(
                        "monitor collector shutdown timed out; pending dispatch outcomes unknown"
                            .into(),
                    ),
                    Ok(Ok(Err(error))) => Err(format!(
                        "monitor collector shutdown timed out; dispatch drain failed: {error}"
                    )),
                    Ok(Ok(Ok(()))) => Err(
                        "monitor collector shutdown timed out before its owned tasks drained"
                            .into(),
                    ),
                    Ok(Err(error)) => Err(format!(
                        "monitor collector shutdown timed out and join failed: {error}"
                    )),
                    Err(_) => {
                        Err("monitor collector abort did not join; task outcome unknown".into())
                    }
                }
            }
        }
    }
}

impl Drop for CollectorHandle {
    fn drop(&mut self) {
        self.request_shutdown();
        if let Some(join) = self.join.take() {
            // Do not let dropping the owner turn its worker into a detached task.
            join.abort();
        }
    }
}

/// Start the collector under an explicit owner. Keep the handle alive and call
/// `shutdown` after HTTP admission closes.
pub fn spawn_collector(state: AppState) -> CollectorHandle {
    let (stop, stop_rx) = watch::channel(false);
    let join = tokio::spawn(async move { run_collector(state, stop_rx).await });
    CollectorHandle {
        stop,
        join: Some(join),
        terminal_result: None,
    }
}

async fn run_collector(state: AppState, mut stop: watch::Receiver<bool>) -> Result<(), String> {
    let mut dispatch_failed = false;
    let mut fast = interval(Duration::from_secs(30));
    let mut slow = interval(Duration::from_secs(60));
    fast.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    slow.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut dispatch_tasks = JoinSet::new();

    loop {
        dispatch_failed |= reap_finished_dispatches(&mut dispatch_tasks);
        tokio::select! {
            _ = wait_for_shutdown(&mut stop) => break,
            _ = fast.tick() => {
                run_probe_and_evaluate(&state, &mut dispatch_tasks, &mut dispatch_failed).await;
            }
            _ = slow.tick() => {
                run_system_and_redis(&state).await;
                maybe_cleanup(&state).await;
            }
        }
    }

    dispatch_failed |= drain_dispatches(&mut dispatch_tasks).await;
    if dispatch_failed {
        Err("one or more owned alert dispatch tasks failed".into())
    } else {
        Ok(())
    }
}

async fn wait_for_shutdown(stop: &mut watch::Receiver<bool>) {
    loop {
        if *stop.borrow_and_update() {
            return;
        }
        if stop.changed().await.is_err() {
            return;
        }
    }
}

fn reap_finished_dispatches(dispatch_tasks: &mut JoinSet<()>) -> bool {
    let mut failed = false;
    while let Some(result) = dispatch_tasks.try_join_next() {
        failed |= log_dispatch_result(result);
    }
    failed
}

fn log_dispatch_result(result: Result<(), JoinError>) -> bool {
    if let Err(error) = result {
        tracing::error!(error = %error, "owned alert dispatch task failed");
        true
    } else {
        false
    }
}

async fn drain_dispatches(dispatch_tasks: &mut JoinSet<()>) -> bool {
    let failed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let failed_in_drain = failed.clone();
    let tasks = &mut *dispatch_tasks;
    let drained = tokio::time::timeout(ALERT_DISPATCH_DRAIN_TIMEOUT, async {
        while let Some(result) = tasks.join_next().await {
            if log_dispatch_result(result) {
                failed_in_drain.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }
    })
    .await
    .is_ok();
    if !drained {
        dispatch_tasks.abort_all();
        let joined_after_abort = tokio::time::timeout(Duration::from_secs(1), async {
            while dispatch_tasks.join_next().await.is_some() {}
        })
        .await
        .is_ok();
        tracing::error!(
            joined_after_abort,
            "owned alert dispatch drain timed out; pending delivery outcomes are unknown"
        );
        return true;
    }
    failed.load(std::sync::atomic::Ordering::Relaxed)
}

async fn run_probe_and_evaluate(
    state: &AppState,
    dispatch_tasks: &mut JoinSet<()>,
    dispatch_failed: &mut bool,
) {
    let cycle_start = Instant::now();
    for target in probe_targets(&state.config) {
        probe_service(state, &target).await;
    }
    metrics::histogram!("astral_monitor_collect_cycle_seconds", "kind" => "probe")
        .record(cycle_start.elapsed().as_secs_f64());

    let eval_start = Instant::now();
    match state.monitor_service.evaluate_alert_rules(60).await {
        Ok(alerts) => {
            for alert in alerts {
                let monitor_service = state.monitor_service.clone();
                spawn_bounded_dispatch(dispatch_tasks, dispatch_failed, async move {
                    dispatch::dispatch_alert(monitor_service.as_ref(), &alert).await;
                })
                .await;
            }
        }
        Err(error) => tracing::warn!(error = %error, "alert rule evaluation failed"),
    }
    metrics::histogram!("astral_monitor_alert_evaluation_seconds")
        .record(eval_start.elapsed().as_secs_f64());
}

async fn spawn_bounded_dispatch<F>(
    dispatch_tasks: &mut JoinSet<()>,
    dispatch_failed: &mut bool,
    future: F,
) where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    if dispatch_tasks.len() >= MAX_ALERT_DISPATCH_CONCURRENCY {
        if let Some(result) = dispatch_tasks.join_next().await {
            *dispatch_failed |= log_dispatch_result(result);
        }
    }
    dispatch_tasks.spawn(future);
}

async fn run_system_and_redis(state: &AppState) {
    let cycle_start = Instant::now();
    collect_system(state).await;
    #[cfg(feature = "redis-compat")]
    collect_redis(state).await;
    metrics::histogram!("astral_monitor_collect_cycle_seconds", "kind" => "system")
        .record(cycle_start.elapsed().as_secs_f64());
}

async fn maybe_cleanup(state: &AppState) {
    let hour = time::OffsetDateTime::now_utc().hour();
    if hour == 3 {
        if let Err(error) = state.monitor_service.cleanup_old_data().await {
            tracing::warn!(error = %error, "monitor data cleanup failed");
        }
    }
}

/// Configured targets retain their service identity even when no safe probe
/// contract exists; each such result is persisted as UNKNOWN, never DOWN.
fn probe_targets(config: &AppConfig) -> Vec<ProbeTarget> {
    [
        ("identity", config.identity_service_uri.as_str()),
        ("learn", config.learn_service_uri.as_str()),
        ("chat", config.chat_service_uri.as_str()),
        ("gateway", config.gateway_service_uri.as_str()),
        ("trustgraph", config.trust_graph_uri.as_str()),
    ]
    .into_iter()
    .filter(|(_, uri)| !uri.trim().is_empty())
    .map(|(service_name, _uri)| ProbeTarget {
        service_name,
        contract: probe_contract(service_name),
    })
    .collect()
}

fn probe_contract(service_name: &str) -> ProbeContract {
    match service_name {
        "learn" => ProbeContract::GatewaySigned {
            path: "/api/health",
        },
        "chat" => ProbeContract::Unavailable {
            reason: "Chat has no registered /api/health route",
        },
        "identity" | "gateway" | "trustgraph" => ProbeContract::Unavailable {
            reason: "service has no registered health route",
        },
        _ => ProbeContract::Unavailable {
            reason: "service has no registered health route",
        },
    }
}

/// No protected/absent health endpoint is contacted without its declared
/// authentication contract. New public probes must add a concrete contract here.
async fn probe_service(state: &AppState, target: &ProbeTarget) {
    let reason = match target.contract {
        ProbeContract::GatewaySigned { path } => format!(
            "health endpoint {path} requires Gateway v3 identity signing; monitor service identity is unavailable"
        ),
        ProbeContract::Unavailable { reason } => reason.to_owned(),
    };
    tracing::debug!(
        service = target.service_name,
        reason,
        "configured health probe unavailable; recording UNKNOWN"
    );
    metrics::gauge!("astral_monitor_service_reachable", "service" => target.service_name).set(-1.0);
    if let Err(error) = state
        .monitor_service
        .collect_unknown_service_probe(target.service_name)
        .await
    {
        tracing::warn!(
            service = target.service_name,
            error = %error,
            "unknown service probe persistence failed"
        );
    }
}

/// 采集系统 CPU/内存/磁盘使用率（sysinfo）。
async fn collect_system(state: &AppState) {
    let mut system = sysinfo::System::new_all();
    system.refresh_cpu_all();
    system.refresh_memory();

    let cpu = system.global_cpu_usage() as f64;

    let total_memory = system.total_memory();
    let used_memory = system.used_memory();
    let memory_percent = if total_memory > 0 {
        used_memory as f64 * 100.0 / total_memory as f64
    } else {
        0.0
    };

    let disks = sysinfo::Disks::new_with_refreshed_list();
    let mut total_space = 0u64;
    let mut available_space = 0u64;
    for disk in &disks {
        total_space += disk.total_space();
        available_space += disk.available_space();
    }
    let disk_percent = if total_space > 0 {
        (total_space - available_space) as f64 * 100.0 / total_space as f64
    } else {
        0.0
    };

    if let Err(error) = state
        .monitor_service
        .collect_system_metrics(cpu, memory_percent, disk_percent)
        .await
    {
        tracing::warn!(error = %error, "system metric collection failed");
    }
}

/// 采集 Redis 指标（INFO memory/stats/clients + DBSIZE；仅 redis-compat feature
/// 编译）。**runtime 门**：feature 已编译但部署未显式启用 compat（旗标关闭或
/// URL 为空）时不做任何 Redis 网络尝试——compat-on build + env off 仍零网络。
#[cfg(feature = "redis-compat")]
async fn collect_redis(state: &AppState) {
    if !state.config.redis_projection_compat_enabled || state.config.redis_url.trim().is_empty() {
        return;
    }
    let redis_url = state.config.redis_url.clone();
    let client = match redis::Client::open(redis_url.as_str()) {
        Ok(client) => client,
        Err(error) => {
            tracing::warn!(error = %error, "redis metric collection skipped: open client failed");
            return;
        }
    };
    let mut conn = match client.get_connection_manager().await {
        Ok(conn) => conn,
        Err(error) => {
            tracing::warn!(error = %error, "redis metric collection skipped: connect failed");
            return;
        }
    };

    let memory_info: Result<String, _> = redis::cmd("INFO")
        .arg("memory")
        .query_async(&mut conn)
        .await;
    let stats_info: Result<String, _> =
        redis::cmd("INFO").arg("stats").query_async(&mut conn).await;
    let clients_info: Result<String, _> = redis::cmd("INFO")
        .arg("clients")
        .query_async(&mut conn)
        .await;
    let db_size: Result<i64, _> = redis::cmd("DBSIZE").query_async(&mut conn).await;

    let memory_info = match memory_info {
        Ok(info) => info,
        Err(error) => {
            tracing::warn!(error = %error, "redis INFO memory failed");
            return;
        }
    };
    let stats_info = match stats_info {
        Ok(info) => info,
        Err(error) => {
            tracing::warn!(error = %error, "redis INFO stats failed");
            return;
        }
    };
    let clients_info = match clients_info {
        Ok(info) => info,
        Err(error) => {
            tracing::warn!(error = %error, "redis INFO clients failed");
            return;
        }
    };
    let key_count = db_size.unwrap_or(0);

    let used_memory = parse_info_field(&memory_info, "used_memory").unwrap_or(0);
    let max_memory = parse_info_field(&memory_info, "maxmemory").unwrap_or(0);
    let hits = parse_info_field(&stats_info, "keyspace_hits").unwrap_or(0);
    let misses = parse_info_field(&stats_info, "keyspace_misses").unwrap_or(0);
    let connected_clients = parse_info_field(&clients_info, "connected_clients").unwrap_or(0);

    let hit_rate = if hits + misses > 0 {
        hits as f64 * 100.0 / (hits + misses) as f64
    } else {
        0.0
    };
    let used_memory_mb = used_memory as f64 / (1024.0 * 1024.0);
    // Java 默认回退 2GB（maxmemory=0 时）。
    let max_memory_effective = if max_memory > 0 {
        max_memory
    } else {
        2_147_483_648
    };
    let max_memory_mb = max_memory_effective as f64 / (1024.0 * 1024.0);

    if let Err(error) = state
        .monitor_service
        .collect_redis_metrics(
            hit_rate,
            connected_clients,
            used_memory_mb,
            max_memory_mb,
            key_count,
        )
        .await
    {
        tracing::warn!(error = %error, "redis metric persistence failed");
    }
}

/// 解析 `INFO` 输出中的 `key:value` 字段（整数值）。
#[cfg(feature = "redis-compat")]
fn parse_info_field(info: &str, key: &str) -> Option<i64> {
    info.lines()
        .find_map(|line| line.strip_prefix(&format!("{key}:")))
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value >= 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn collector_death_result_is_consumed_once_and_preserved_for_shutdown() {
        let (stop, _) = watch::channel(false);
        let mut handle = CollectorHandle {
            stop,
            join: Some(tokio::spawn(async { Err("collector failed".into()) })),
            terminal_result: None,
        };
        assert_eq!(handle.wait_for_death().await, "collector failed");
        assert!(handle.join.is_none());
        assert_eq!(
            handle.shutdown(Duration::from_secs(1)).await,
            Err("collector failed".into())
        );
    }

    #[tokio::test]
    async fn collector_shutdown_timeout_never_reports_success() {
        let (stop, _) = watch::channel(false);
        let handle = CollectorHandle {
            stop,
            join: Some(tokio::spawn(std::future::pending::<Result<(), String>>())),
            terminal_result: None,
        };
        let result = handle.shutdown(Duration::from_millis(1)).await;
        assert!(result.unwrap_err().contains("outcomes unknown"));
    }

    #[tokio::test]
    async fn owned_dispatch_admission_never_exceeds_its_capacity() {
        let mut tasks = JoinSet::new();
        let mut failed = false;
        for _ in 0..(MAX_ALERT_DISPATCH_CONCURRENCY * 3) {
            spawn_bounded_dispatch(&mut tasks, &mut failed, async {
                tokio::task::yield_now().await;
            })
            .await;
            assert!(tasks.len() <= MAX_ALERT_DISPATCH_CONCURRENCY);
        }
        assert!(!drain_dispatches(&mut tasks).await);
        assert!(!failed);
    }
}
