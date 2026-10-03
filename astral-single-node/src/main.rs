use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use astral_common::config::{AppConfig, JwtValidationRole, MessageTransport};
use astral_common::tracing::init_tracing;
use astral_db::{install_local_projection_bus, LocalProjectionBusConfig};
use astral_mq::local_bus::{install_global_local_bus, LocalBus, LocalBusLimits};

mod writer_lease;

const DEFAULT_GATEWAY_ADDR: &str = "0.0.0.0:9001";
const DEFAULT_IDENTITY_ADDR: &str = "0.0.0.0:9004";
const DEFAULT_TRUSTGRAPH_ADDR: &str = "0.0.0.0:9005";

/// Bounded join budget for cancellation cleanup paths.
const SERVICE_SHUTDOWN_JOIN_TIMEOUT: Duration = Duration::from_secs(10);
/// HTTP, producer barrier, worker joins, audit drain, and Local consumer joins all
/// have independent bounds. TrustGraph runs several of these phases sequentially;
/// allow their cumulative budget plus margin instead of cancelling a proven drain
/// while a bounded inner phase is still progressing.
// TrustGraph owns an ORG_SCOPE event deadline configurable up to 3,599s, plus
// sequential bounded workers before the shared producer barrier. Keep an outer
// cap above the maximum legal phase sum; a lower cap would misreport a healthy,
// bounded producer drain as unknown and risk dropping drain proofs.
const GRACEFUL_SERVICE_DRAIN_TIMEOUT: Duration = Duration::from_secs(4_500);
/// Gateway only owns the bounded HTTP drain.
const GRACEFUL_GATEWAY_DRAIN_TIMEOUT: Duration = Duration::from_secs(35);

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

fn snapshot_path(raw: Option<&str>) -> anyhow::Result<Option<PathBuf>> {
    match raw {
        None => Ok(None),
        Some(value) if value.trim().is_empty() => {
            Err(anyhow!("SINGLE_NODE_SNAPSHOT_PATH must not be blank"))
        }
        Some(value) => Ok(Some(PathBuf::from(value))),
    }
}

async fn warm_projection_mirror(
    pool: &sqlx::MySqlPool,
    path: Option<&Path>,
) -> anyhow::Result<astral_db::WarmReport> {
    let hint = match path {
        Some(path) => match tokio::time::timeout(
            Duration::from_secs(30),
            astral_db::load_projection_snapshot_hint(path, pool),
        )
        .await
        {
            Ok(Ok(hint)) if hint.divergences().is_empty() => Some(hint),
            Ok(Ok(hint)) => {
                tracing::warn!(
                    divergences = hint.divergences().len(),
                    "local snapshot frontier differs; rebuilding mirror from durable state"
                );
                None
            }
            Ok(Err(error)) => {
                tracing::warn!(error = %error, "local snapshot unavailable; rebuilding mirror from durable state");
                None
            }
            Err(_) => {
                tracing::warn!("local snapshot load exceeded its startup budget; rebuilding mirror from durable state");
                None
            }
        },
        None => None,
    };
    astral_db::warm_from_durable_with_hint(pool, hint.as_ref())
        .await
        .context("memory mirror warm-up readiness gate")
}

async fn save_shutdown_snapshot(pool: &sqlx::MySqlPool, path: &Path) {
    match tokio::time::timeout(Duration::from_secs(30), astral_db::save_projection_snapshot(path, pool)).await {
        Ok(Ok(_)) => tracing::info!("local projection snapshot saved after service shutdown"),
        Ok(Err(error)) => tracing::warn!(error = %error, "local snapshot save failed; next startup must rebuild from durable state"),
        Err(_) => tracing::warn!("local snapshot save exceeded its shutdown budget; next startup must rebuild from durable state"),
    }
}

fn validate_composite_config(
    config: &AppConfig,
    identity_addr: &str,
    trustgraph_addr: &str,
) -> anyhow::Result<()> {
    // Redis compatibility is refused BEFORE anything else (pure config check,
    // no DB, no I/O): the composite runtime is a strict Redis-free deployment
    // regardless of whether the astral-common build compiled the adapter, and
    // a flagged configuration must fail before the database preflight instead
    // of after a warm-up.
    config
        .validate_redis_adapter_support(false)
        .map_err(|error| anyhow!("composite redis adapter configuration rejected: {error}"))?;
    if config.message_transport()? != MessageTransport::Local {
        return Err(anyhow!(
            "astral-single-node requires ASTRAL_MESSAGE_TRANSPORT=local"
        ));
    }
    if config
        .target_region
        .as_deref()
        .is_some_and(|region| region != config.region_id)
    {
        return Err(anyhow!(
            "local transport target region must match region_id"
        ));
    }
    for (name, configured, expected) in [
        (
            "IDENTITY_SERVICE_URI",
            config.identity_service_uri.as_str(),
            identity_addr,
        ),
        (
            "TRUST_GRAPH_URI",
            config.trust_graph_uri.as_str(),
            trustgraph_addr,
        ),
    ] {
        let expected_uri = format!("http://{expected}");
        if configured.trim_end_matches('/') != expected_uri {
            return Err(anyhow!(
                "{name} must equal {expected_uri} in the single-node runtime"
            ));
        }
    }
    Ok(())
}

use astral_trustgraph::service::local_projection_worker::{
    local_projection_worker_liveness, LocalProjectionWorkerLiveness,
};

/// Required-owner liveness gate (worker-supervision-20261002): the in-process
/// projection worker is the single-node projection owner; a `Dead` liveness is
/// sticky fail-closed (hub `mark_runtime_owner_failed` + global cell) and must
/// stop the composite. Pure helper so readiness and the run loop share one
/// fatal predicate.
fn projection_worker_dead_reason() -> Option<String> {
    match local_projection_worker_liveness() {
        LocalProjectionWorkerLiveness::Dead(reason) => Some(reason),
        _ => None,
    }
}

async fn wait_for_bus_owners(
    bus: &LocalBus,
    identity: &mut tokio::task::JoinHandle<anyhow::Result<()>>,
    trustgraph: &mut tokio::task::JoinHandle<anyhow::Result<()>>,
    joined: &mut HashSet<&'static str>,
) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        // Required-owner readiness conjunction: a Dead projection owner is
        // fatal, and readiness requires ALL of — the LocalBus owner channels
        // registered, the projection worker proven Alive (NotStarted keeps
        // waiting to the bounded deadline), and the memory channel HEALTHY
        // (post-warm-up suspect clears only via the initial durable
        // reconcile, so the gateway installer never starts against a
        // Deny-only memory face).
        let liveness = local_projection_worker_liveness();
        if let LocalProjectionWorkerLiveness::Dead(reason) = liveness {
            return Err(anyhow!(
                "local projection worker died or its start was rejected before composite \
                 readiness: {reason}"
            ));
        }
        let channel_healthy = astral_db::memory_projection_hub::memory_projection_hub()
            .map(|hub| hub.channel_is_healthy())
            .unwrap_or(false);
        if liveness == LocalProjectionWorkerLiveness::Alive && channel_healthy && bus.owners_ready()
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(anyhow!(
                "local bus owners, the projection worker liveness, or the memory channel \
                 health did not become ready within 30 seconds"
            ));
        }
        let retry = tokio::time::sleep(Duration::from_millis(100));
        tokio::pin!(retry);
        tokio::select! {
            result = &mut *identity => {
                joined.insert("identity");
                return task_failed("identity", result);
            },
            result = &mut *trustgraph => {
                joined.insert("trustgraph");
                return task_failed("trustgraph", result);
            },
            _ = &mut retry => {}
        }
    }
}

async fn wait_for_listener_or_task(
    addr: &str,
    service: &'static str,
    task: &mut tokio::task::JoinHandle<anyhow::Result<()>>,
    joined: &mut HashSet<&'static str>,
) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(_) => return Ok(()),
            Err(error) if tokio::time::Instant::now() < deadline => {
                tracing::debug!(addr, service, error = %error, "composite service listener not ready");
                let retry = tokio::time::sleep(Duration::from_millis(100));
                tokio::pin!(retry);
                tokio::select! {
                    result = &mut *task => {
                        joined.insert(service);
                        return task_failed(service, result);
                    },
                    _ = &mut retry => {}
                }
            }
            Err(error) => {
                return Err(anyhow!(
                    "composite service listener {addr} not ready: {error}"
                ));
            }
        }
    }
}

fn task_failed(
    service: &str,
    result: Result<anyhow::Result<()>, tokio::task::JoinError>,
) -> anyhow::Result<()> {
    match result {
        Ok(Ok(())) => Err(anyhow!("{service} stopped before composite readiness")),
        Ok(Err(error)) => Err(error).context(format!("{service} runtime failed")),
        Err(error) => Err(anyhow!(error)).context(format!("{service} task join failed")),
    }
}

async fn abort_task(
    task: &mut tokio::task::JoinHandle<anyhow::Result<()>>,
    service: &str,
) -> (anyhow::Result<()>, bool) {
    abort_task_within(task, service, SERVICE_SHUTDOWN_JOIN_TIMEOUT).await
}

/// Abort then join under a fixed bound. Completed task outcomes are always
/// observed; the boolean records whether this call consumed a terminal JoinHandle
/// result. A timeout is unknown and leaves the handle eligible for one later join.
async fn abort_task_within(
    task: &mut tokio::task::JoinHandle<anyhow::Result<()>>,
    service: &str,
    join_budget: Duration,
) -> (anyhow::Result<()>, bool) {
    if !task.is_finished() {
        task.abort();
    }
    let joined = match tokio::time::timeout(join_budget, &mut *task).await {
        Ok(joined) => joined,
        Err(_) => {
            let reason = format!(
                "{service} did not stop within {join_budget:?}; abort/join outcome unknown"
            );
            tracing::error!(service, budget_ms = join_budget.as_millis() as u64, %reason);
            return (Err(anyhow!(reason)), false);
        }
    };
    let result = match joined {
        Ok(Ok(())) => {
            tracing::info!(service, "composite service stopped cleanly");
            Ok(())
        }
        Ok(Err(error)) => {
            let reason = format!("{service} stopped with service error: {error}");
            tracing::warn!(service, error = %error, "composite service stopped with error");
            Err(anyhow!(reason))
        }
        Err(join_error) if join_error.is_cancelled() => {
            tracing::info!(service, "composite service abort completed");
            Ok(())
        }
        Err(join_error) => {
            let reason = format!("{service} task join failed: {join_error}");
            tracing::warn!(service, error = %join_error, "composite service join failed");
            Err(anyhow!(reason))
        }
    };
    (result, true)
}

async fn abort_if_not_joined(
    joined: &HashSet<&'static str>,
    task: &mut tokio::task::JoinHandle<anyhow::Result<()>>,
    service: &'static str,
) -> (anyhow::Result<()>, bool) {
    if joined.contains(service) {
        (Ok(()), true)
    } else {
        abort_task(task, service).await
    }
}

/// 组合进程全部服务的有界关停：任何退出路径（任务失败、owner 丢失、
/// 租约丢失、信号错误、正常信号）都必须逐一有界 abort，保证没有服务
/// 被遗漏或无限等待。已消费的 JoinHandle 结果由 `joined` 跳过，绝不再次 poll。
async fn abort_all_services(
    joined: &mut HashSet<&'static str>,
    identity: &mut tokio::task::JoinHandle<anyhow::Result<()>>,
    trustgraph: &mut tokio::task::JoinHandle<anyhow::Result<()>>,
    gateway: &mut tokio::task::JoinHandle<anyhow::Result<()>>,
) -> anyhow::Result<()> {
    let (identity_outcome, trustgraph_outcome, gateway_outcome) = tokio::join!(
        abort_if_not_joined(joined, identity, "identity"),
        abort_if_not_joined(joined, trustgraph, "trustgraph"),
        abort_if_not_joined(joined, gateway, "gateway"),
    );
    let outcomes = [
        ("identity", identity_outcome),
        ("trustgraph", trustgraph_outcome),
        ("gateway", gateway_outcome),
    ];
    let mut failures = Vec::new();
    for (service, outcome) in outcomes {
        if let Err(error) = remember_join_result(joined, service, outcome) {
            failures.push(error.to_string());
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(failures.join("; ")))
    }
}

async fn join_service_within(
    task: &mut tokio::task::JoinHandle<anyhow::Result<()>>,
    service: &'static str,
    budget: Duration,
) -> (anyhow::Result<()>, bool) {
    match tokio::time::timeout(budget, &mut *task).await {
        Ok(Ok(Ok(()))) => {
            tracing::info!(service, "composite service drained gracefully");
            (Ok(()), true)
        }
        Ok(Ok(Err(error))) => (
            Err(error).with_context(|| format!("{service} shutdown failed")),
            true,
        ),
        Ok(Err(error)) => (
            Err(anyhow!(error)).with_context(|| format!("{service} join failed")),
            true,
        ),
        Err(_) => {
            task.abort();
            (
                Err(anyhow!(
                    "{service} did not drain within {budget:?}; outcome unknown"
                )),
                false,
            )
        }
    }
}

/// Record a terminal JoinHandle result before returning its success or failure.
/// JoinHandle futures must never be polled again after either terminal outcome.
fn remember_join_result(
    joined: &mut HashSet<&'static str>,
    service: &'static str,
    outcome: (anyhow::Result<()>, bool),
) -> anyhow::Result<()> {
    let (result, completed) = outcome;
    if completed {
        joined.insert(service);
    }
    result
}

/// Graceful stop order: sticky admission closure is performed by the caller;
/// Gateway HTTP drains first, then Identity/TrustGraph HTTP+producer workers
/// reach their shared barrier, close Local receivers and join owned consumers.
async fn graceful_stop_services(
    gateway_shutdown: &mut Option<tokio::sync::oneshot::Sender<()>>,
    identity_shutdown: &mut Option<tokio::sync::oneshot::Sender<()>>,
    trustgraph_shutdown: &mut Option<tokio::sync::oneshot::Sender<()>>,
    joined: &mut HashSet<&'static str>,
    identity: &mut tokio::task::JoinHandle<anyhow::Result<()>>,
    trustgraph: &mut tokio::task::JoinHandle<anyhow::Result<()>>,
    gateway: &mut tokio::task::JoinHandle<anyhow::Result<()>>,
) -> anyhow::Result<()> {
    if let Some(shutdown) = gateway_shutdown.take() {
        let _ = shutdown.send(());
    }
    let mut failures = Vec::new();
    if !joined.contains("gateway") {
        let outcome = join_service_within(gateway, "gateway", GRACEFUL_GATEWAY_DRAIN_TIMEOUT).await;
        if let Err(error) = remember_join_result(joined, "gateway", outcome) {
            failures.push(error.to_string());
        }
    }

    if let Some(shutdown) = identity_shutdown.take() {
        let _ = shutdown.send(());
    }
    if let Some(shutdown) = trustgraph_shutdown.take() {
        let _ = shutdown.send(());
    }
    if joined.contains("identity") || joined.contains("trustgraph") {
        return Err(anyhow!(
            "Identity/TrustGraph exited before the producer barrier; peer drain outcome unknown"
        ));
    }
    let (identity_outcome, trustgraph_outcome) = tokio::join!(
        join_service_within(identity, "identity", GRACEFUL_SERVICE_DRAIN_TIMEOUT),
        join_service_within(trustgraph, "trustgraph", GRACEFUL_SERVICE_DRAIN_TIMEOUT),
    );
    let identity_result = remember_join_result(joined, "identity", identity_outcome);
    let trustgraph_result = remember_join_result(joined, "trustgraph", trustgraph_outcome);
    if let Err(error) = identity_result {
        failures.push(error.to_string());
    }
    if let Err(error) = trustgraph_result {
        failures.push(error.to_string());
    }
    if joined.contains("identity") && joined.contains("trustgraph") && failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(
            "Identity/TrustGraph drain incomplete or unknown: {}",
            failures.join("; ")
        ))
    }
}

/// Startup can fail after Identity and TrustGraph have bound their listeners but
/// before Gateway starts. Close the sticky gate first (caller), then stop both
/// producers so their shared barrier can complete before their tasks are joined.
async fn graceful_stop_producers(
    identity_shutdown: &mut Option<tokio::sync::oneshot::Sender<()>>,
    trustgraph_shutdown: &mut Option<tokio::sync::oneshot::Sender<()>>,
    joined: &mut HashSet<&'static str>,
    identity: &mut tokio::task::JoinHandle<anyhow::Result<()>>,
    trustgraph: &mut tokio::task::JoinHandle<anyhow::Result<()>>,
) -> anyhow::Result<()> {
    if let Some(shutdown) = identity_shutdown.take() {
        let _ = shutdown.send(());
    }
    if let Some(shutdown) = trustgraph_shutdown.take() {
        let _ = shutdown.send(());
    }
    if joined.contains("identity") || joined.contains("trustgraph") {
        return Err(anyhow!(
            "service exited before producer barrier; peer drain outcome unknown"
        ));
    }
    let (identity_outcome, trustgraph_outcome) = tokio::join!(
        join_service_within(identity, "identity", GRACEFUL_SERVICE_DRAIN_TIMEOUT),
        join_service_within(trustgraph, "trustgraph", GRACEFUL_SERVICE_DRAIN_TIMEOUT),
    );
    let identity_result = remember_join_result(joined, "identity", identity_outcome);
    let trustgraph_result = remember_join_result(joined, "trustgraph", trustgraph_outcome);
    match (identity_result, trustgraph_result) {
        (Ok(()), Ok(())) => Ok(()),
        (identity, trustgraph) => {
            let failures = [identity.err(), trustgraph.err()]
                .into_iter()
                .flatten()
                .map(|error| error.to_string())
                .collect::<Vec<_>>();
            Err(anyhow!(
                "producer drain incomplete/unknown: {}",
                failures.join("; ")
            ))
        }
    }
}

/// Run the ordered graceful drain after a known fatal condition. If any drain
/// phase is unproven, make one bounded abort attempt for every owned service and
/// retain both the original failure and the drain failure in the final result.
#[allow(clippy::too_many_arguments)]
async fn graceful_stop_or_abort(
    gateway_shutdown: &mut Option<tokio::sync::oneshot::Sender<()>>,
    identity_shutdown: &mut Option<tokio::sync::oneshot::Sender<()>>,
    trustgraph_shutdown: &mut Option<tokio::sync::oneshot::Sender<()>>,
    joined: &mut HashSet<&'static str>,
    identity: &mut tokio::task::JoinHandle<anyhow::Result<()>>,
    trustgraph: &mut tokio::task::JoinHandle<anyhow::Result<()>>,
    gateway: &mut tokio::task::JoinHandle<anyhow::Result<()>>,
    primary: anyhow::Result<()>,
) -> anyhow::Result<()> {
    let drain = graceful_stop_services(
        gateway_shutdown,
        identity_shutdown,
        trustgraph_shutdown,
        joined,
        identity,
        trustgraph,
        gateway,
    )
    .await;
    if let Err(drain_error) = drain {
        let abort_result = abort_all_services(joined, identity, trustgraph, gateway).await;
        let drain_error = match abort_result {
            Ok(()) => {
                format!("graceful service drain failed: {drain_error}; bounded abort completed")
            }
            Err(abort_error) => format!(
                "graceful service drain failed: {drain_error}; abort outcome: {abort_error}"
            ),
        };
        return match primary {
            Err(primary_error) => Err(primary_error.context(drain_error)),
            Ok(()) => Err(anyhow!(drain_error)),
        };
    }
    if ![
        joined.contains("identity"),
        joined.contains("trustgraph"),
        joined.contains("gateway"),
    ]
    .into_iter()
    .all(|completed| completed)
    {
        return match primary {
            Err(primary_error) => Err(primary_error
                .context("coordinated service drain did not consume every service result")),
            Ok(()) => Err(anyhow!(
                "coordinated service drain did not consume every service result"
            )),
        };
    }
    primary
}

async fn wait_for_source_writers_quiet(timeout: Duration) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let hub = astral_db::memory_projection_hub::memory_projection_hub()
            .ok_or_else(|| anyhow!("memory projection hub unavailable during shutdown"))?;
        if !hub.has_active_source_writer() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(anyhow!(
                "source writers remained active at shutdown; snapshot suppressed"
            ));
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Closes authority admission before the remaining services are aborted.
fn mark_hub_suspect(reason: &str) {
    if let Some(hub) = astral_db::memory_projection_hub::memory_projection_hub() {
        hub.mark_runtime_owner_failed(reason.to_owned());
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let config = AppConfig::from_files_for("application", JwtValidationRole::Gateway)
        .context("load single-node configuration")?;
    let gateway_addr = env_or("SINGLE_NODE_GATEWAY_ADDR", DEFAULT_GATEWAY_ADDR);
    let identity_addr = env_or("SINGLE_NODE_IDENTITY_ADDR", DEFAULT_IDENTITY_ADDR);
    let trustgraph_addr = env_or("SINGLE_NODE_TRUSTGRAPH_ADDR", DEFAULT_TRUSTGRAPH_ADDR);
    let local_snapshot_path =
        snapshot_path(std::env::var("SINGLE_NODE_SNAPSHOT_PATH").ok().as_deref())?;
    validate_composite_config(&config, &identity_addr, &trustgraph_addr)?;
    astral_mq::invalidation::install_origin_region(config.region_id.clone())
        .map_err(|error| anyhow!(error))?;

    let bus = LocalBus::new(LocalBusLimits::default())?;
    install_global_local_bus(bus.clone())?;
    install_local_projection_bus(LocalProjectionBusConfig::default())
        .map_err(|error| anyhow!("install local projection bus: {error}"))?;
    // 单机内存镜像读面（default-off 技术储备落地）：组合进程是唯一写者，
    // 安装后正式授权 evidence 读优先命中与 durable 同源的进程内镜像；
    // pending/未预热/装配异常一律回退权威 DB reader。Rabbit 模式不安装。
    if !astral_db::memory_projection_hub::install_memory_projection_hub() {
        return Err(anyhow!("memory projection hub already installed"));
    }
    // 会话撤销的 deny 加速器与严格 MySQL 会话事实共用进程；未命中不能放行。
    if !astral_common::session_revocation_registry::install_global_session_revocation_registry() {
        return Err(anyhow!("session revocation registry already installed"));
    }

    // 单写者门禁（启动期）：组合进程是唯一授权写者。会话级咨询锁随连接存活，
    // 进程崩溃时连接断开自动释放，绝不永久阻塞后续启动；第二个实例拿不到锁
    // 立即拒绝启动，防止两个写者造成内存镜像与 DB 事实分叉。
    let db = astral_db::connect_and_validate_schema(&config.database_url)
        .await
        .context("single-node database preflight")?;
    let lease_connection = astral_db::memory_projection_hub::acquire_single_writer_lease(&db)
        .await
        .map_err(|error| anyhow!("acquire single-node writer lease: {error}"))?;
    // Lease loss closes the sticky owner gate before shutdown is signalled.
    // The supervisor neither reconnects nor acquires a replacement lease.
    let mut lease_supervisor = writer_lease::start_writer_lease_supervisor(lease_connection)
        .await
        .map_err(|error| anyhow!("start writer lease supervision: {error}"))?;

    // 预热同样处于租约监督之下：租约在预热期间丢失时立即放弃启动，绝不
    // 等预热或 readiness 完成才承认丢失（不误声明 READINESS）。
    let warm = tokio::select! {
        warm = warm_projection_mirror(&db, local_snapshot_path.as_deref()) =>
            warm?,
        loss = lease_supervisor.wait_for_loss() => {
            tracing::error!(reason = %loss, "writer lease lost during warm-up; aborting startup");
            mark_hub_suspect(&loss);
            return Err(anyhow!("single-node writer lease lost during warm-up: {loss}"));
        }
    };
    if !astral_db::install_auxiliary_authorization_mirror(db.clone(), config.org_scope_enabled) {
        return Err(anyhow!("auxiliary authorization mirror already installed"));
    }
    tracing::info!(
        gateway = %gateway_addr,
        identity = %identity_addr,
        trustgraph = %trustgraph_addr,
        "single-node in-process message bus and memory mirrors installed"
    );
    tracing::info!(
        identities = warm.identities,
        installed = warm.installed,
        cold = warm.failed,
        pending_restored = warm.pending_restored,
        "memory mirror warm-up complete; composite readiness gate passed"
    );

    let (identity_shutdown_tx, identity_shutdown_rx) = tokio::sync::oneshot::channel();
    let mut identity_shutdown_tx = Some(identity_shutdown_tx);
    let (trustgraph_shutdown_tx, trustgraph_shutdown_rx) = tokio::sync::oneshot::channel();
    let mut trustgraph_shutdown_tx = Some(trustgraph_shutdown_tx);
    let producer_drain_barrier = Arc::new(tokio::sync::Barrier::new(2));
    let identity_barrier = Arc::clone(&producer_drain_barrier);
    let trustgraph_barrier = Arc::clone(&producer_drain_barrier);
    let identity_task_addr = identity_addr.clone();
    let mut identity = tokio::spawn(async move {
        astral_identity::run_with_listen_addr_and_shutdown_and_drain(
            &identity_task_addr,
            async move {
                let _ = identity_shutdown_rx.await;
            },
            async move {
                identity_barrier.wait().await;
            },
        )
        .await
    });
    let trustgraph_task_addr = trustgraph_addr.clone();
    let mut trustgraph = tokio::spawn(async move {
        astral_trustgraph::run_with_listen_addr_and_shutdown_and_drain(
            &trustgraph_task_addr,
            async move {
                let _ = trustgraph_shutdown_rx.await;
            },
            async move {
                trustgraph_barrier.wait().await;
            },
        )
        .await
    });

    // readiness 期间租约监督持续生效：任一 listener 未就绪时租约丢失同样
    // 立即终止，绝不放任丢失、绝不误声明 READINESS。
    let mut joined = HashSet::new();
    let readiness = tokio::select! {
        result = async {
            wait_for_listener_or_task(
                &identity_addr,
                "identity",
                &mut identity,
                &mut joined,
            )
            .await?;
            wait_for_listener_or_task(
                &trustgraph_addr,
                "trustgraph",
                &mut trustgraph,
                &mut joined,
            )
            .await?;
            wait_for_bus_owners(&bus, &mut identity, &mut trustgraph, &mut joined).await
        } => result,
        loss = lease_supervisor.wait_for_loss() => {
            tracing::error!(reason = %loss, "writer lease lost before composite readiness; aborting startup");
            mark_hub_suspect(&loss);
            Err(anyhow!("single-node writer lease lost before readiness: {loss}"))
        }
    };
    if let Err(error) = readiness {
        // Startup never reached the full composite readiness gate. Close the
        // sticky authority gate before signaling producers, and drain both
        // services through the shared producer barrier; an unknown drain stays
        // an error and can never authorize snapshot persistence.
        mark_hub_suspect("single-node startup readiness failed");
        let producer_stop = graceful_stop_producers(
            &mut identity_shutdown_tx,
            &mut trustgraph_shutdown_tx,
            &mut joined,
            &mut identity,
            &mut trustgraph,
        )
        .await;
        if let Err(drain_error) = producer_stop {
            let aborts = tokio::join!(
                abort_if_not_joined(&joined, &mut identity, "identity"),
                abort_if_not_joined(&joined, &mut trustgraph, "trustgraph"),
            );
            let identity_abort = remember_join_result(&mut joined, "identity", aborts.0);
            let trustgraph_abort = remember_join_result(&mut joined, "trustgraph", aborts.1);
            let abort_report = match (identity_abort, trustgraph_abort) {
                (Ok(()), Ok(())) => "bounded aborts completed".to_owned(),
                (identity, trustgraph) => format!(
                    "bounded abort outcomes identity={identity:?}, trustgraph={trustgraph:?}"
                ),
            };
            return Err(error.context(format!(
                "producer startup drain failed: {drain_error}; {abort_report}"
            )));
        }
        return Err(error);
    }
    tracing::info!("single-node service listeners and message owners ready; starting gateway");
    let (gateway_shutdown_tx, gateway_shutdown_rx) = tokio::sync::oneshot::channel();
    let mut gateway = tokio::spawn(async move {
        astral_gateway::run_with_listen_addr_and_shutdown(&gateway_addr, async move {
            let _ = gateway_shutdown_rx.await;
        })
        .await
    });
    let mut gateway_shutdown_tx = Some(gateway_shutdown_tx);
    let mut owner_watch = tokio::time::interval(Duration::from_millis(250));
    owner_watch.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let runtime_result = 'runtime: loop {
        tokio::select! {
            result = &mut identity => {
                let failure = task_failed("identity", result);
                mark_hub_suspect("required identity service exited");
                let mut joined = HashSet::from(["identity"]);
                let failure = graceful_stop_or_abort(
                    &mut gateway_shutdown_tx,
                    &mut identity_shutdown_tx,
                    &mut trustgraph_shutdown_tx,
                    &mut joined,
                    &mut identity,
                    &mut trustgraph,
                    &mut gateway,
                    failure,
                ).await;
                break 'runtime failure;
            },
            result = &mut trustgraph => {
                let failure = task_failed("trustgraph", result);
                mark_hub_suspect("required trustgraph service exited");
                let mut joined = HashSet::from(["trustgraph"]);
                let failure = graceful_stop_or_abort(
                    &mut gateway_shutdown_tx,
                    &mut identity_shutdown_tx,
                    &mut trustgraph_shutdown_tx,
                    &mut joined,
                    &mut identity,
                    &mut trustgraph,
                    &mut gateway,
                    failure,
                ).await;
                break 'runtime failure;
            },
            result = &mut gateway => {
                let failure = task_failed("gateway", result);
                mark_hub_suspect("required gateway service exited");
                let mut joined = HashSet::from(["gateway"]);
                let failure = graceful_stop_or_abort(
                    &mut gateway_shutdown_tx,
                    &mut identity_shutdown_tx,
                    &mut trustgraph_shutdown_tx,
                    &mut joined,
                    &mut identity,
                    &mut trustgraph,
                    &mut gateway,
                    failure,
                ).await;
                break 'runtime failure;
            },
            _ = owner_watch.tick() => {
                if let Some(reason) = projection_worker_dead_reason() {
                    mark_hub_suspect(&reason);
                    let mut joined = HashSet::new();
                    let failure = graceful_stop_or_abort(
                        &mut gateway_shutdown_tx,
                        &mut identity_shutdown_tx,
                        &mut trustgraph_shutdown_tx,
                        &mut joined,
                        &mut identity,
                        &mut trustgraph,
                        &mut gateway,
                        Err(anyhow!(
                            "local projection worker died after readiness; sticky fail-closed: {reason}"
                        )),
                    ).await;
                    break 'runtime failure;
                }
                if !bus.owners_ready() {
                    mark_hub_suspect("required local bus owner channel closed");
                    let mut joined = HashSet::new();
                    let failure = graceful_stop_or_abort(
                        &mut gateway_shutdown_tx,
                        &mut identity_shutdown_tx,
                        &mut trustgraph_shutdown_tx,
                        &mut joined,
                        &mut identity,
                        &mut trustgraph,
                        &mut gateway,
                        Err(anyhow!("local bus owner channel closed after readiness")),
                    ).await;
                    break 'runtime failure;
                }
            },
            loss = lease_supervisor.wait_for_loss() => {
                tracing::error!(reason = %loss, "writer lease lost after readiness; stopping all composite services");
                mark_hub_suspect(&loss);
                let mut joined = HashSet::new();
                let failure = graceful_stop_or_abort(
                    &mut gateway_shutdown_tx,
                    &mut identity_shutdown_tx,
                    &mut trustgraph_shutdown_tx,
                    &mut joined,
                    &mut identity,
                    &mut trustgraph,
                    &mut gateway,
                    Err(anyhow!("single-node writer lease lost after readiness: {loss}")),
                ).await;
                break 'runtime failure;
            },
            signal = tokio::signal::ctrl_c() => {
                mark_hub_suspect("single-node shutdown admission closed");
                let signal_result = match signal {
                    Ok(()) => {
                        tracing::info!("single-node shutdown requested");
                        Ok(())
                    }
                    Err(error) => {
                        tracing::error!(error = %error, "shutdown signal stream failed; shutting down composite services");
                        Err(anyhow::Error::new(error).context("wait for shutdown signal"))
                    }
                };
                let mut joined = HashSet::new();
                let outcome = graceful_stop_or_abort(
                    &mut gateway_shutdown_tx,
                    &mut identity_shutdown_tx,
                    &mut trustgraph_shutdown_tx,
                    &mut joined,
                    &mut identity,
                    &mut trustgraph,
                    &mut gateway,
                    signal_result,
                ).await;
                break 'runtime outcome;
            }
        }
    };
    if runtime_result.is_ok() {
        match wait_for_source_writers_quiet(SERVICE_SHUTDOWN_JOIN_TIMEOUT).await {
            Ok(()) => {
                if let Some(path) = local_snapshot_path.as_deref() {
                    save_shutdown_snapshot(&db, path).await;
                }
            }
            Err(error) => {
                tracing::error!(error = %error, "source writers were not proven quiet; skipping hint snapshot");
                return Err(error);
            }
        }
    }
    runtime_result
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    #[test]
    fn required_service_or_owner_loss_closes_admission_before_abort() {
        let source = include_str!("main.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let close = source.split("fn mark_hub_suspect").nth(1).unwrap();
        assert!(close
            .split("#[tokio::main]")
            .next()
            .unwrap()
            .contains("mark_runtime_owner_failed"));
        for branch in [
            "result = &mut identity =>",
            "result = &mut trustgraph =>",
            "result = &mut gateway =>",
            "if !bus.owners_ready() {",
        ] {
            let body = source.split(branch).nth(1).unwrap();
            let close = body
                .find("mark_hub_suspect(")
                .expect("loss must close the sticky authority gate");
            let stop = body
                .find("graceful_stop_or_abort(")
                .expect("loss must stop the other services through the owned drain");
            assert!(
                close < stop,
                "authority must close before draining services in {branch}"
            );
        }
    }

    /// 启动门禁顺序锁定（shape）：单写者租约获取 → 运行期租约监督启动 →
    /// 内存镜像预热 → 服务 spawn。监督必须从拿到租约的第一刻起生效，
    /// 保证丢失立即被检测并 fail-closed，绝不误声明 READINESS。
    #[test]
    fn writer_lease_supervision_precedes_warm_up_and_service_spawn() {
        let source = include_str!("main.rs");
        let lease_pos = source
            .find("acquire_single_writer_lease")
            .expect("writer lease gate must exist");
        let supervise_pos = source
            .find("start_writer_lease_supervisor")
            .expect("runtime writer lease supervision must exist");
        let warm_pos = source
            .find("warm_projection_mirror(&db")
            .expect("warm-up readiness gate must exist");
        let spawn_pos = source
            .find("tokio::spawn")
            .expect("service spawn must exist");
        assert!(
            lease_pos < supervise_pos,
            "supervision must start immediately after lease acquisition"
        );
        assert!(
            supervise_pos < warm_pos,
            "lease supervision must be live before warm-up"
        );
        assert!(warm_pos < spawn_pos, "warm-up readiness must precede spawn");
        let region_install = source
            .find("astral_mq::invalidation::install_origin_region")
            .expect("single-node must freeze the canonical origin region");
        let auxiliary_install = source
            .find("install_auxiliary_authorization_mirror")
            .expect("single-node must install auxiliary mirror");
        assert!(
            region_install < warm_pos,
            "origin identity must freeze before warm-up"
        );
        assert!(
            warm_pos < auxiliary_install,
            "auxiliary mirror must install after warm-up"
        );
        assert!(
            auxiliary_install < spawn_pos,
            "auxiliary mirror must install before service spawn"
        );
        assert!(source.contains("memory mirror warm-up readiness gate"));
    }

    /// Required-owner liveness gate wiring (worker-supervision-20261002):
    /// readiness and the run loop must both treat a sticky Dead projection
    /// worker as fatal (stop all services), the probe must read the exported
    /// trustgraph liveness cell — never a LocalBus-only heuristic — and
    /// readiness must require the full conjunction (owners ready AND worker
    /// Alive AND memory channel healthy).
    #[test]
    fn projection_owner_liveness_gate_is_wired_into_readiness_and_run_loop() {
        let source = include_str!("main.rs");
        let helper_pos = source
            .find("fn projection_worker_dead_reason()")
            .expect("the shared fatal predicate must exist");
        let readiness_pos = source
            .find("async fn wait_for_bus_owners")
            .expect("readiness gate must exist");
        let tick_pos = source
            .find("_ = owner_watch.tick() =>")
            .expect("the run-loop tick arm must exist");
        assert!(helper_pos < readiness_pos, "the helper must precede use");
        let readiness_window = &source[readiness_pos..tick_pos];
        assert!(
            readiness_window.contains("LocalProjectionWorkerLiveness::Dead(reason)"),
            "readiness must treat a sticky Dead owner as fatal"
        );
        assert!(
            readiness_window.contains("liveness == LocalProjectionWorkerLiveness::Alive")
                && readiness_window.contains("channel_is_healthy()")
                && readiness_window.contains("bus.owners_ready()"),
            "readiness must require the full conjunction: owners ready + worker Alive + \
             memory channel healthy"
        );
        let run_loop_window = &source[tick_pos..];
        assert!(
            run_loop_window.contains("projection_worker_dead_reason()"),
            "the run loop must observe the required-owner liveness"
        );
        assert!(
            run_loop_window.contains("mark_hub_suspect(&reason)")
                && run_loop_window.contains("graceful_stop_or_abort"),
            "a Dead owner must stop all services fail-closed"
        );
        assert!(
            source.contains("LocalProjectionWorkerLiveness::Dead"),
            "the gate must match the exported sticky Dead state"
        );
    }

    /// Composite Redis compatibility is refused by the FIRST pure config
    /// check (before the DB preflight), with the adapter capability pinned to
    /// `false` for the composite host regardless of the astral-common build.
    #[test]
    fn composite_config_refuses_redis_adapter_before_any_database_work() {
        let source = include_str!("main.rs");
        let fn_start = source
            .find("fn validate_composite_config(")
            .expect("the composite validator must exist");
        let body = &source[fn_start..];
        let redis_check = body
            .find("validate_redis_adapter_support(false)")
            .expect("the composite must pin the adapter capability to false");
        let transport_check = body
            .find("config.message_transport()")
            .expect("the transport check must remain");
        let db_check = source
            .find("connect_and_validate_schema(&config.database_url)")
            .expect("the DB preflight must remain on the startup path");
        assert!(
            redis_check < transport_check,
            "the redis refusal must be the first config check"
        );
        assert!(
            redis_check < db_check,
            "the redis refusal must precede the database preflight"
        );
    }

    /// 租约监督必须同时覆盖 readiness 阶段与运行期主循环；所有退出路径
    /// 都要走有界关停，不允许任何服务逃逸。
    #[test]
    fn lease_loss_is_watched_during_readiness_and_run_loop() {
        let source = include_str!("main.rs");
        let readiness_pos = source
            .find("let readiness = tokio::select!")
            .expect("readiness select must exist");
        let run_loop_pos = source.rfind("loop {").expect("run loop must exist");
        assert!(
            readiness_pos < run_loop_pos,
            "readiness must precede the run loop"
        );
        let readiness_window = &source[readiness_pos..run_loop_pos];
        assert!(
            readiness_window.contains("wait_for_loss"),
            "readiness phase must wait for lease loss"
        );
        let run_loop_window = &source[run_loop_pos..];
        assert!(
            run_loop_window.contains("wait_for_loss"),
            "run loop must wait for lease loss"
        );
        assert!(
            run_loop_window.contains("graceful_stop_or_abort"),
            "run loop exit paths must attempt ordered graceful drain then bounded abort"
        );
    }

    /// A terminal service Err is still a consumed JoinHandle result. The
    /// fallback-abort helper must consult the recorded set rather than polling
    /// that handle a second time.
    #[tokio::test]
    async fn terminal_service_error_is_recorded_and_not_polled_again() {
        let mut task: tokio::task::JoinHandle<anyhow::Result<()>> =
            tokio::spawn(async { Err(anyhow!("service failed")) });
        let outcome = join_service_within(&mut task, "identity", Duration::from_secs(1)).await;
        let mut joined = HashSet::new();
        let drain_result = remember_join_result(&mut joined, "identity", outcome);
        assert!(
            drain_result.is_err(),
            "the terminal service Err stays a failure"
        );
        assert!(
            joined.contains("identity"),
            "the terminal result must be recorded"
        );

        let (abort_result, completed) = abort_if_not_joined(&joined, &mut task, "identity").await;
        assert!(abort_result.is_ok());
        assert!(completed);
    }

    /// 有界关停行为：可取消任务在 abort 后必须立即被限时 join 回收，
    /// 绝不等任务自然完成。
    #[tokio::test]
    async fn abort_task_joins_cancelled_task_within_budget() {
        let mut task: tokio::task::JoinHandle<anyhow::Result<()>> = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(60)).await;
            Ok(())
        });
        let started = Instant::now();
        let (stopped, completed) = abort_task(&mut task, "identity").await;
        assert!(stopped.is_ok());
        assert!(completed);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "abort must reclaim the task immediately instead of waiting for its natural end"
        );
    }

    /// 有界关停行为：任务阻塞在无法立即取消的工作中时，join 必须按预算
    /// 超时脱离（记录后继续关停流程），绝不无限等待，也绝不提前返回。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn abort_task_detaches_task_that_misses_shutdown_budget() {
        // 任务先发出"已开始执行"信号，再进入不可取消的阻塞工作：此时
        // abort 无法立即生效，有界 join 必须按预算超时脱离，而不是等任务
        // 自然结束，也不是在任务尚未启动时立即取消成功。
        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        let mut task: tokio::task::JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
            let _ = started_tx.send(());
            std::thread::sleep(Duration::from_millis(500));
            Ok(())
        });
        let _ = started_rx.await;
        let started = Instant::now();
        let (stopped, completed) =
            abort_task_within(&mut task, "identity", Duration::from_millis(50)).await;
        assert!(stopped.is_err());
        assert!(!completed);
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(50),
            "must honour the full budget"
        );
        assert!(
            elapsed < Duration::from_secs(4),
            "must detach after the budget instead of joining forever"
        );
        // Timed out means the aborted task still runs a synchronous section;
        // test-only blocking work must be allowed to finish before runtime drop.
        let _ = task.await;
    }
}
