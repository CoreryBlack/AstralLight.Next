//! Same-card repository-to-worker projection storm on the native profile.
//!
//! Run only against a migrated, run-scoped MySQL test database. Separate processes
//! select `ASTRAL_PROJECTION_EXECUTION_MODE=legacy-hybrid` or `worker-owned` with
//! identical workload limits. This is not a signed HTTP or cross-node campaign.

use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use astral_db::{
    freeze_projection_execution_mode_from_env, install_local_projection_bus,
    install_memory_projection_hub, load_owned_delta_completion, load_published_card_grant_evidence,
    projection_execution_mode, warm_from_durable, DeltaEventAppendRequest, DeltaEventType,
    LocalProjectionBus, LocalProjectionBusConfig, ProjectionExecutionMode, Sha256Digest,
    LOCAL_PROJECTION_BUS_MAX_PAYLOAD_BYTES, LOCAL_PROJECTION_BUS_MAX_TOTAL_BYTES,
};
use astral_mq::{
    config::{
        QUEUE_AUDIT_LOG, QUEUE_AUTHORIZATION_INVALIDATION, QUEUE_AUTH_SESSION_REVOCATION,
        QUEUE_LOGIN_EVENT,
    },
    consumers::dispatch_invalidation_event,
    invalidation::install_origin_region,
    local_bus::{install_global_local_bus, LocalBus, LocalBusLimits, LocalOwner, LocalReceiver},
    NodeIdentity,
};
use astral_trustgraph::{
    repository::{
        grant_ledger_adapter::DirectRuleMutationContext,
        rule_repository::{NewRule, RuleRepository, SqlxRuleRepository},
    },
    service::{
        authorization_projector::{
            shutdown_authorization_projector, AuthorizationProjectorConfig,
            AuthorizationProjectorHandle, WorkerRunSummary,
        },
        invalidation_runtime::{start_local_projection_supervisor, InvalidationFanoutRuntime},
        local_projection_worker::{start_local_projection_worker, LocalProjectionWorkerConfig},
    },
};
use astral_types::{
    DomainScopeRequirement, PublishedCardEvidenceScope, PublishedEvidenceGateStatus,
};
use sqlx::{MySqlPool, Row};
use testsuite::{cleanup_suite_rows, connect_suite, seed_all_tenants, SuiteFixture, TenantRole};
use tokio::{sync::watch, task::JoinHandle};

const TEST_TIMEOUT: Duration = Duration::from_secs(3_500);
const BURST_WINDOW: Duration = Duration::from_secs(60);
const DRAIN_WINDOW: Duration = Duration::from_secs(960);
const PRODUCERS: usize = 3;
// Three trials stay below AuthorizationSourceTransaction's 1,024 receipt cap,
// including the final one-operation bulk revoke.
const MAX_SUCCESSFUL_MUTATIONS_PER_TRIAL: usize = 256;
const TRIALS: usize = 3;
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const DB_CALL_TIMEOUT: Duration = Duration::from_secs(5);
const RESOURCE_ID_BASE: i64 = 700_000_000;
const ATTEMPT_BUDGET_EXHAUSTED_MARKER: &str = "code=auth_projector.attempt_budget_exhausted";

#[derive(Debug, Clone, Copy)]
struct StormWorkload {
    mutations_per_trial: usize,
    trials: usize,
}

impl StormWorkload {
    fn from_env() -> Result<Self> {
        Ok(Self {
            mutations_per_trial: bounded_workload_value(
                "ASTRAL_STORM_MUTATIONS_PER_TRIAL",
                std::env::var("ASTRAL_STORM_MUTATIONS_PER_TRIAL")
                    .ok()
                    .as_deref(),
                MAX_SUCCESSFUL_MUTATIONS_PER_TRIAL,
            )?,
            trials: bounded_workload_value(
                "ASTRAL_STORM_TRIALS",
                std::env::var("ASTRAL_STORM_TRIALS").ok().as_deref(),
                TRIALS,
            )?,
        })
    }
}

fn bounded_workload_value(name: &str, value: Option<&str>, maximum: usize) -> Result<usize> {
    match value {
        None => Ok(maximum),
        Some(raw) => {
            let value = raw
                .parse::<usize>()
                .with_context(|| format!("{name} must be an integer in 1..={maximum}"))?;
            if !(1..=maximum).contains(&value) {
                return Err(anyhow!("{name} must be in 1..={maximum}"));
            }
            Ok(value)
        }
    }
}

#[test]
fn storm_workload_overrides_cannot_expand_the_resource_budget() {
    assert_eq!(bounded_workload_value("cap", None, 256).unwrap(), 256);
    assert_eq!(bounded_workload_value("cap", Some("16"), 256).unwrap(), 16);
    for invalid in ["", "0", "257", "-1", "true", " 16"] {
        assert!(bounded_workload_value("cap", Some(invalid), 256).is_err());
    }
}

#[derive(Debug, Clone)]
struct MutationRecord {
    operation_id: String,
    rule_id: i64,
    elapsed_ms: u128,
}

#[derive(Debug)]
struct BurstRun {
    records: Vec<MutationRecord>,
    attempted_operation_ids: Vec<String>,
    errors: Vec<String>,
    burst_wall_ms: u128,
    capped: bool,
}

#[derive(Debug, Clone)]
struct DeltaRecord {
    event_id: String,
    operation_id: String,
    grant_id: String,
    event_type: String,
    source_generation: i64,
    status: String,
    attempts: i64,
    last_error: Option<String>,
    revision_no: i64,
    revision_status: String,
    is_tombstone: i64,
    revision_operation_id: String,
    revision_event_id: String,
    source_entry: String,
    provenance_operation_id: String,
    provenance_event_id: String,
}

struct RuntimeOwners {
    projection_bus: LocalProjectionBus,
    supervisor: Option<InvalidationFanoutRuntime>,
    projector: Option<AuthorizationProjectorHandle>,
    invalidation_shutdown: watch::Sender<bool>,
    invalidation_join: Option<JoinHandle<()>>,
    _audit_receiver: LocalReceiver,
    _login_receiver: LocalReceiver,
    _session_receiver: LocalReceiver,
}

impl RuntimeOwners {
    async fn shutdown(mut self) -> Result<WorkerRunSummary> {
        let mut failures = Vec::new();
        let mut summary = WorkerRunSummary::default();

        if let Some(projector) = self.projector.take() {
            match tokio::time::timeout(
                Duration::from_secs(8),
                shutdown_authorization_projector(projector, Duration::from_secs(5)),
            )
            .await
            {
                Ok(report) => match report.summary {
                    Ok(value)
                        if value.events_publication_unknown == 0
                            && value.events_quarantine_unknown == 0 =>
                    {
                        summary = value
                    }
                    Ok(value) => failures.push(format!(
                        "projector shutdown unknowns: publication={}, quarantine={}",
                        value.events_publication_unknown, value.events_quarantine_unknown
                    )),
                    Err(error) => failures.push(format!("projector shutdown: {error}")),
                },
                Err(_) => failures.push("projector shutdown outer bound exceeded".to_owned()),
            }
        }

        if let Some(supervisor) = self.supervisor.take() {
            match tokio::time::timeout(
                Duration::from_secs(8),
                supervisor.shutdown(Duration::from_secs(5)),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => failures.push(format!("invalidation supervisor: {error}")),
                Err(_) => failures.push("invalidation supervisor shutdown timed out".to_owned()),
            }
        }

        let _ = self.invalidation_shutdown.send(true);
        if let Some(mut join) = self.invalidation_join.take() {
            match tokio::time::timeout(Duration::from_secs(3), &mut join).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => failures.push(format!("invalidation consumer: {error}")),
                Err(_) => {
                    join.abort();
                    let _ = tokio::time::timeout(Duration::from_secs(1), &mut join).await;
                    failures.push("invalidation consumer shutdown timed out".to_owned());
                }
            }
        }
        self.projection_bus
            .close("native projection storm shutdown");

        if failures.is_empty() {
            Ok(summary)
        } else {
            Err(anyhow!(failures.join("; ")))
        }
    }
}

impl Drop for RuntimeOwners {
    fn drop(&mut self) {
        let _ = self.invalidation_shutdown.send(true);
        if let Some(join) = self.invalidation_join.as_ref() {
            join.abort();
        }
        if let Some(projector) = self.projector.as_ref() {
            projector.cancellation.cancel();
            projector.join.abort_handle().abort();
        }
        self.projection_bus
            .close("native projection storm owner dropped");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 12)]
#[ignore = "requires migrated run-scoped MySQL and the native single-node projection path"]
async fn native_projection_same_card_write_storm_drains_durably() {
    astral_common::tracing::init_tracing();
    freeze_projection_execution_mode_from_env().expect("projection execution mode must be valid");
    let workload = StormWorkload::from_env().expect("storm workload must stay within its budget");
    let Some(pool) = connect_suite().await else {
        return;
    };
    let mode = projection_execution_mode();
    let fixture = SuiteFixture::new("native-projection-storm", &[TenantRole::DenyActive]);
    let tenant = fixture.tenants[0];
    let operation_prefix = format!("nps{:032x}", fixture.salt);
    let attempted_operations = Arc::new(Mutex::new(Vec::new()));
    let mut storm_records = Vec::new();
    let mut attempted_operation_ids = Vec::new();
    let mut cleanup_operation = None;
    let mut cleanup_event_ids = Vec::new();

    let result = tokio::time::timeout(TEST_TIMEOUT, async {
        setup_fixture(&pool, &fixture).await?;
        let current = read_current_pointer(&pool, tenant.tenant_id, tenant.card_id).await?;
        if current.is_some() {
            return Err(anyhow!("fresh storm card unexpectedly has a USER_CARD current pointer"));
        }

        let owners = install_runtime(&pool, tenant.tenant_id).await?;
        let repo = SqlxRuleRepository::new(pool.clone());
        let mut trials = Vec::with_capacity(workload.trials);

        for trial in 0..workload.trials {
            let burst = run_burst(
                &pool,
                tenant.card_id,
                tenant.user_id,
                &operation_prefix,
                trial,
                workload.mutations_per_trial,
                attempted_operations.clone(),
            )
            .await?;
            attempted_operation_ids.extend(burst.attempted_operation_ids.iter().cloned());
            if !burst.errors.is_empty() {
                reconcile_operations(&pool, tenant.tenant_id, tenant.card_id, &burst.attempted_operation_ids).await?;
                return Err(anyhow!(
                    "trial {} has {} failed or ambiguous source writes: {:?}",
                    trial + 1,
                    burst.errors.len(),
                    burst.errors.iter().take(8).collect::<Vec<_>>()
                ));
            }
            if burst.records.is_empty() {
                return Err(anyhow!("trial {} committed no source mutations", trial + 1));
            }
            storm_records.extend(burst.records.iter().cloned());
            trials.push((burst, trial + 1));
        }

        let drain_started = Instant::now();
        let durable = wait_for_storm_drain(
            &pool,
            tenant.tenant_id,
            tenant.card_id,
            tenant.domain_id,
            &storm_records,
        )
        .await?;
        let storm_drain_ms = drain_started.elapsed().as_millis();
        let storm_attempts_total = durable.iter().map(|delta| delta.attempts as u64).sum::<u64>();
        let storm_max_attempts = durable.iter().map(|delta| delta.attempts).max().unwrap_or_default();
        if mode == ProjectionExecutionMode::WorkerOwned {
            assert_owned_execution_accounting(&pool, tenant.tenant_id, &durable).await?;
        }

        let cleanup_operation_id = format!("npsc{:032x}", fixture.salt);
        cleanup_operation = Some(cleanup_operation_id.clone());
        attempted_operation_ids.push(cleanup_operation_id.clone());
        let context = DirectRuleMutationContext::user(tenant.user_id, Some(&cleanup_operation_id))
            .map_err(|error| anyhow!("cleanup mutation context rejected: {error}"))?;
        if let Err(error) = repo.delete_rules_by_card(tenant.card_id, &context).await {
            reconcile_operations(
                &pool,
                tenant.tenant_id,
                tenant.card_id,
                std::slice::from_ref(&cleanup_operation_id),
            )
            .await?;
            return Err(anyhow!("production delete_rules_by_card returned an unknown outcome: {error}"));
        }

        let cleanup_started = Instant::now();
        let cleanup_deltas = wait_for_cleanup_drain(
            &pool,
            tenant.tenant_id,
            tenant.card_id,
            tenant.domain_id,
            &storm_records,
            &cleanup_operation_id,
        )
        .await?;
        cleanup_event_ids = cleanup_deltas.iter().map(|delta| delta.event_id.clone()).collect();
        let cleanup_drain_ms = cleanup_started.elapsed().as_millis();
        if mode == ProjectionExecutionMode::WorkerOwned {
            assert_owned_execution_accounting(&pool, tenant.tenant_id, &cleanup_deltas).await?;
        }

        // Durable event, manifest and audit assertions are the acceptance proof;
        // worker counters only explain which path performed the work.
        let worker_summary = owners.shutdown().await?;
        report_durable_workload(&pool, tenant.tenant_id, mode, &worker_summary).await?;
        println!(
            "[NATIVE_STORM] execution_mode={mode:?} path=SqlxRuleRepository+local_worker trials={} producers={} burst_window_s={} per_trial_cap={} drain_window_s={} storm_drain_ms={} cleanup_drain_ms={} writes={} attempts_total={} max_attempts={} cleanup_rules={} cleanup_deltas={} worker_published={} worker_claimed={} worker_released_retry={} worker_budget_exhausted={}",
            trials.len(),
            PRODUCERS,
            BURST_WINDOW.as_secs(),
            workload.mutations_per_trial,
            DRAIN_WINDOW.as_secs(),
            storm_drain_ms,
            cleanup_drain_ms,
            storm_records.len(),
            storm_attempts_total,
            storm_max_attempts,
            storm_records.len(),
            cleanup_deltas.len(),
            worker_summary.events_published,
            worker_summary.events_claimed,
            worker_summary.events_released_retry,
            worker_summary.events_budget_exhausted,
        );
        for (burst, trial) in &trials {
            println!(
                "[NATIVE_STORM_TRIAL] trial={} writes={} burst_wall_ms={} capped={} producer_errors={} write_p50_ms={} write_p95_ms={} write_max_ms={}",
                trial,
                burst.records.len(),
                burst.burst_wall_ms,
                burst.capped,
                burst.errors.len(),
                percentile(&burst.records, 0.50),
                percentile(&burst.records, 0.95),
                burst.records.iter().map(|record| record.elapsed_ms).max().unwrap_or_default(),
            );
        }
        Ok(())
    })
    .await
    .map_err(|_| anyhow!("native projection storm exceeded {TEST_TIMEOUT:?}"));

    if !matches!(result, Ok(Ok(()))) {
        if let Ok(recorded) = attempted_operations.lock() {
            attempted_operation_ids.extend(recorded.iter().cloned());
            attempted_operation_ids.sort();
            attempted_operation_ids.dedup();
        }
        eprintln!(
            "[UNKNOWN] native projection storm outcome or durable postcondition unproven; fixture retained: base={} attempted_operations={:?} cleanup_operation={:?} cleanup_event_ids={:?}",
            fixture.base,
            attempted_operation_ids,
            cleanup_operation,
            cleanup_event_ids,
        );
        match result {
            Ok(Err(error)) | Err(error) => panic!("native projection storm failed: {error:#}"),
            Ok(Ok(())) => unreachable!(),
        }
    }

    if let Err(error) = cleanup_storm_fixture(&pool, &fixture, &attempted_operation_ids).await {
        eprintln!(
            "[UNKNOWN] post-drain fixture cleanup outcome unproven; reconcile before retry: base={} attempted_operations={:?} error={error:#}",
            fixture.base,
            attempted_operation_ids,
        );
        panic!("native projection storm fixture cleanup failed: {error:#}");
    }
}

fn percentile(records: &[MutationRecord], fraction: f64) -> u128 {
    let mut samples: Vec<u128> = records.iter().map(|record| record.elapsed_ms).collect();
    if samples.is_empty() {
        return 0;
    }
    samples.sort_unstable();
    let index = ((samples.len() as f64 * fraction).ceil() as usize).saturating_sub(1);
    samples[index.min(samples.len() - 1)]
}

async fn wait_until<T, F, Fut>(label: &str, timeout: Duration, mut check: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<Option<T>>>,
{
    let started = Instant::now();
    loop {
        if let Some(value) = check().await? {
            return Ok(value);
        }
        if started.elapsed() >= timeout {
            return Err(anyhow!("timed out waiting for {label}"));
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

fn fixture_message_scope(fixture: &SuiteFixture) -> (String, String) {
    use astral_mq::invalidation::{EvidenceInvalidated, InvalidationEvent, INVALIDATION_QUEUE};

    let tenant = fixture.tenants[0];
    let ordering_key = InvalidationEvent::EvidenceInvalidated(EvidenceInvalidated {
        tenant_id: tenant.tenant_id,
        card_id: Some(tenant.card_id),
        aggregate_type: astral_types::PublishedEvidenceAggregate::UserCard,
        aggregate_id: tenant.card_id,
        published_generation: 1,
        stamp: astral_types::PublicationStamp::new(
            1,
            "ab".repeat(32),
            astral_types::PublicationSeal::from_unix_seconds(1_700_000_000).unwrap(),
        )
        .unwrap(),
        source_generation: 1,
        revoke_fence: 0,
    })
    .ordering_key();
    let counter_key = format!("{INVALIDATION_QUEUE}\u{1f}{ordering_key}");
    (ordering_key, counter_key)
}

async fn setup_fixture(pool: &MySqlPool, fixture: &SuiteFixture) -> Result<()> {
    let (ordering_key, counter_key) = fixture_message_scope(fixture);
    let existing: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM al_message_scope_counter WHERE scope_key = ?) + \
                (SELECT COUNT(*) FROM al_message_outbox WHERE queue_name = ? AND ordering_key = ?)",
    )
    .bind(&counter_key)
    .bind(QUEUE_AUTHORIZATION_INVALIDATION)
    .bind(&ordering_key)
    .fetch_one(pool)
    .await?;
    if existing != 0 {
        return Err(anyhow!(
            "storm fixture message scope must be unused before setup"
        ));
    }
    tokio::time::timeout(DB_CALL_TIMEOUT, seed_all_tenants(pool, fixture))
        .await
        .map_err(|_| anyhow!("seed_all_tenants timed out"))??;
    install_origin_region(format!("native-storm-{:x}", fixture.salt))
        .map_err(|error| anyhow!("origin region install failed: {error}"))?;
    Ok(())
}

async fn install_runtime(pool: &MySqlPool, tenant_id: i64) -> Result<RuntimeOwners> {
    if !install_memory_projection_hub() {
        return Err(anyhow!("memory projection hub was already installed"));
    }
    let hub = astral_db::memory_projection_hub()
        .cloned()
        .ok_or_else(|| anyhow!("memory projection hub missing after install"))?;
    tokio::time::timeout(Duration::from_secs(90), warm_from_durable(pool))
        .await
        .map_err(|_| anyhow!("memory hub warm-up timed out"))??;

    let projection_bus = install_local_projection_bus(LocalProjectionBusConfig {
        capacity: 4096,
        max_payload_bytes: LOCAL_PROJECTION_BUS_MAX_PAYLOAD_BYTES,
        max_total_bytes: LOCAL_PROJECTION_BUS_MAX_TOTAL_BYTES,
        max_queued_per_aggregate: 1024,
    })
    .map_err(|error| anyhow!("local projection bus install failed: {error}"))?;
    let local_bus = LocalBus::new(LocalBusLimits::default())
        .map_err(|error| anyhow!("LocalBus construction failed: {error}"))?;
    install_global_local_bus(local_bus.clone())
        .map_err(|error| anyhow!("global LocalBus install failed: {error}"))?;
    let audit_receiver = local_bus
        .register(QUEUE_AUDIT_LOG, LocalOwner::TrustGraph)
        .context("register audit owner")?;
    let login_receiver = local_bus
        .register(QUEUE_LOGIN_EVENT, LocalOwner::Identity)
        .context("register login owner")?;
    let session_receiver = local_bus
        .register(QUEUE_AUTH_SESSION_REVOCATION, LocalOwner::Identity)
        .context("register session owner")?;
    let invalidation_receiver = local_bus
        .register(
            QUEUE_AUTHORIZATION_INVALIDATION,
            LocalOwner::AuthorizationInvalidation,
        )
        .context("register invalidation owner")?;
    let (invalidation_shutdown, invalidation_shutdown_rx) = watch::channel(false);
    let identity = NodeIdentity::try_from_parts("native-test", "projection-storm")
        .map_err(|error| anyhow!("node identity construction failed: {error}"))?;
    let supervisor = start_local_projection_supervisor(pool.clone(), local_bus, identity)
        .map_err(|error| anyhow!("invalidation supervisor start failed: {error}"))?;
    let invalidation_join = tokio::spawn(run_invalidation_consumer(
        invalidation_receiver,
        invalidation_shutdown_rx,
    ));
    let mut owners = RuntimeOwners {
        projection_bus,
        supervisor: Some(supervisor),
        projector: None,
        invalidation_shutdown,
        invalidation_join: Some(invalidation_join),
        _audit_receiver: audit_receiver,
        _login_receiver: login_receiver,
        _session_receiver: session_receiver,
    };
    wait_until("memory hub healthy", Duration::from_secs(12), || {
        let hub = hub.clone();
        async move { Ok(hub.channel_is_healthy().then_some(())) }
    })
    .await?;

    let config = AuthorizationProjectorConfig {
        tenants: vec![tenant_id],
        ..AuthorizationProjectorConfig::default()
    };
    owners.projector = Some(
        start_local_projection_worker(
            pool.clone(),
            LocalProjectionWorkerConfig {
                projector: config,
                recovery_poll: Some(Duration::from_secs(1)),
                max_recovery_events_per_pass: 64,
            },
        )
        .map_err(|error| anyhow!("local projector start failed: {error}"))?,
    );
    if astral_trustgraph::service::local_projection_worker::local_projection_worker_liveness()
        != astral_trustgraph::service::local_projection_worker::LocalProjectionWorkerLiveness::Alive
    {
        return Err(anyhow!("local projector did not report Alive"));
    }
    Ok(owners)
}

async fn run_invalidation_consumer(
    mut receiver: LocalReceiver,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
            delivery = receiver.recv() => {
                let Some(delivery) = delivery else { return; };
                let result = dispatch_invalidation_event(&delivery.envelope).await;
                delivery.complete(result);
            }
        }
    }
}

async fn run_burst(
    pool: &MySqlPool,
    card_id: i64,
    actor_id: i64,
    operation_prefix: &str,
    trial: usize,
    mutation_limit: usize,
    attempted_operations: Arc<Mutex<Vec<String>>>,
) -> Result<BurstRun> {
    let start = Instant::now();
    let deadline = start + BURST_WINDOW;
    let next_sequence = Arc::new(AtomicUsize::new(0));
    let mut joins = Vec::with_capacity(PRODUCERS);
    for producer in 0..PRODUCERS {
        let pool = pool.clone();
        let repo = SqlxRuleRepository::new(pool);
        let next_sequence = next_sequence.clone();
        let attempted_operations = attempted_operations.clone();
        let operation_prefix = operation_prefix.to_owned();
        joins.push(tokio::spawn(async move {
            let mut records = Vec::new();
            let mut attempted = Vec::new();
            let mut errors = Vec::new();
            loop {
                if Instant::now() >= deadline {
                    break;
                }
                let sequence = next_sequence.fetch_add(1, Ordering::Relaxed);
                if sequence >= mutation_limit {
                    break;
                }
                let operation_id = format!("{operation_prefix}-t{trial}-p{producer}-n{sequence}");
                attempted.push(operation_id.clone());
                attempted_operations
                    .lock()
                    .map_err(|_| anyhow!("attempted operation recorder poisoned"))?
                    .push(operation_id.clone());
                let context = DirectRuleMutationContext::user(actor_id, Some(&operation_id))
                    .map_err(|error| anyhow!("mutation context rejected: {error}"))?;
                let resource_id = RESOURCE_ID_BASE
                    + (trial * MAX_SUCCESSFUL_MUTATIONS_PER_TRIAL + sequence) as i64;
                let rule = NewRule {
                    card_id,
                    resource_type: "learn_subject".to_owned(),
                    resource_id: Some(resource_id),
                    action_code: "read".to_owned(),
                    effect: "ALLOW".to_owned(),
                    condition_json: None,
                    priority: 1,
                    valid_from: None,
                    valid_to: None,
                    source_type: "MANUAL".to_owned(),
                    enabled: 1,
                };
                let write_started = Instant::now();
                match tokio::time::timeout(
                    Duration::from_secs(25),
                    repo.create_rule(&rule, &context),
                )
                .await
                {
                    Ok(Ok(rule_id)) => records.push(MutationRecord {
                        operation_id,
                        rule_id,
                        elapsed_ms: write_started.elapsed().as_millis(),
                    }),
                    Ok(Err(error)) => errors.push(format!("{operation_id}: {error}")),
                    Err(_) => errors.push(format!("{operation_id}: source call timed out")),
                }
            }
            Ok::<_, anyhow::Error>((records, attempted, errors))
        }));
    }
    let mut records = Vec::new();
    let mut attempted_operation_ids = Vec::new();
    let mut errors = Vec::new();
    for join in joins {
        let (mut completed, mut attempted, mut producer_errors) =
            join.await.context("source producer join failed")??;
        records.append(&mut completed);
        attempted_operation_ids.append(&mut attempted);
        errors.append(&mut producer_errors);
    }
    Ok(BurstRun {
        capped: next_sequence.load(Ordering::Relaxed) >= mutation_limit,
        records,
        attempted_operation_ids,
        errors,
        burst_wall_ms: start.elapsed().as_millis(),
    })
}

async fn wait_for_storm_drain(
    pool: &MySqlPool,
    tenant_id: i64,
    card_id: i64,
    domain_id: i64,
    all_records: &[MutationRecord],
) -> Result<Vec<DeltaRecord>> {
    let started = Instant::now();
    loop {
        let operation_ids: Vec<&str> = all_records
            .iter()
            .map(|record| record.operation_id.as_str())
            .collect();
        let deltas = read_delta_rows(pool, tenant_id, card_id, &operation_ids).await?;
        if deltas.len() != all_records.len() {
            return Err(anyhow!(
                "delta/revision count {} does not equal committed write count {}",
                deltas.len(),
                all_records.len()
            ));
        }
        assert_add_revision_correlation(&deltas, all_records)?;
        if deltas.iter().any(|delta| {
            delta.status == "QUARANTINED"
                || delta
                    .last_error
                    .as_deref()
                    .is_some_and(|error| error.contains(ATTEMPT_BUDGET_EXHAUSTED_MARKER))
        }) {
            return Err(anyhow!(
                "storm event reached quarantine or exhausted attempt budget"
            ));
        }
        if deltas.iter().all(|delta| delta.status == "SUCCEEDED") {
            assert_add_audit_correlation(pool, card_id, &deltas, all_records).await?;
            let latest = deltas
                .iter()
                .max_by_key(|delta| delta.source_generation)
                .ok_or_else(|| anyhow!("no durable storm deltas"))?;
            if deltas.iter().any(|delta| {
                delta.source_generation == latest.source_generation
                    && delta.operation_id != latest.operation_id
            }) {
                return Err(anyhow!(
                    "multiple CARD source events share the storm's latest generation"
                ));
            }
            assert_card_source_frontier(pool, tenant_id, card_id, latest).await?;
            if strict_evidence_matches(pool, tenant_id, card_id, domain_id, &deltas, false).await? {
                return Ok(deltas);
            }
            if let Some((generation, event_id, _, _, source_generation)) =
                read_current_pointer(pool, tenant_id, card_id).await?
            {
                if completed_frontier_regressed(
                    generation,
                    deltas.len(),
                    source_generation,
                    latest.source_generation,
                ) {
                    return Err(anyhow!(
                        "all {} deltas succeeded at publication generation {generation}, but current event {event_id} regressed to source generation {source_generation} below {}; no remaining event can repair the frontier",
                        deltas.len(), latest.source_generation
                    ));
                }
            }
        }
        if started.elapsed() >= DRAIN_WINDOW {
            return Err(anyhow!(
                "post-burst durable drain exceeded {:?}",
                DRAIN_WINDOW
            ));
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

fn completed_frontier_regressed(
    publication_generation: i64,
    event_count: usize,
    current_source_generation: i64,
    latest_source_generation: i64,
) -> bool {
    i64::try_from(event_count).ok() == Some(publication_generation)
        && current_source_generation < latest_source_generation
}

#[test]
fn terminal_source_regression_is_not_a_pending_frontier() {
    assert!(completed_frontier_regressed(64, 64, 7, 64));
    assert!(!completed_frontier_regressed(63, 64, 7, 64));
    assert!(!completed_frontier_regressed(64, 64, 64, 64));
    assert!(!completed_frontier_regressed(64, 64, 65, 64));
}

async fn wait_for_cleanup_drain(
    pool: &MySqlPool,
    tenant_id: i64,
    card_id: i64,
    domain_id: i64,
    storm_records: &[MutationRecord],
    cleanup_operation_id: &str,
) -> Result<Vec<DeltaRecord>> {
    let started = Instant::now();
    loop {
        let cleanup_rows =
            read_delta_rows(pool, tenant_id, card_id, &[cleanup_operation_id]).await?;
        if cleanup_rows.len() > storm_records.len() {
            return Err(anyhow!(
                "cleanup produced more REMOVE deltas than run-owned rules"
            ));
        }
        if cleanup_rows.iter().any(|delta| {
            delta.status == "QUARANTINED"
                || delta
                    .last_error
                    .as_deref()
                    .is_some_and(|error| error.contains(ATTEMPT_BUDGET_EXHAUSTED_MARKER))
        }) {
            return Err(anyhow!(
                "cleanup revoke reached quarantine or exhausted retry budget"
            ));
        }
        if cleanup_rows.len() == storm_records.len()
            && cleanup_rows.iter().all(|delta| delta.status == "SUCCEEDED")
        {
            assert_remove_revision_correlation(
                pool,
                tenant_id,
                card_id,
                &cleanup_rows,
                storm_records,
                cleanup_operation_id,
            )
            .await?;
            let operation_ids: Vec<&str> = storm_records
                .iter()
                .map(|record| record.operation_id.as_str())
                .chain(std::iter::once(cleanup_operation_id))
                .collect();
            let all_deltas = read_delta_rows(pool, tenant_id, card_id, &operation_ids).await?;
            if all_deltas.len() != storm_records.len() + cleanup_rows.len()
                || all_deltas.iter().any(|delta| delta.status != "SUCCEEDED")
            {
                return Err(anyhow!(
                    "cleanup frontier contains missing or nonterminal deltas"
                ));
            }
            assert_card_cleanup_frontier(
                pool,
                tenant_id,
                card_id,
                &cleanup_rows,
                cleanup_operation_id,
            )
            .await?;
            if strict_evidence_matches(pool, tenant_id, card_id, domain_id, &all_deltas, true)
                .await?
            {
                let current = read_current_pointer(pool, tenant_id, card_id)
                    .await?
                    .ok_or_else(|| anyhow!("cleanup strict proof lost current pointer"))?;
                let cleanup_event_ids: HashSet<&str> = cleanup_rows
                    .iter()
                    .map(|delta| delta.event_id.as_str())
                    .collect();
                if current.2 != cleanup_operation_id
                    || !cleanup_event_ids.contains(current.1.as_str())
                    || current.4 != cleanup_rows[0].source_generation
                {
                    return Err(anyhow!(
                        "published current pointer does not identify this cleanup batch"
                    ));
                }
                return Ok(cleanup_rows);
            }
        }
        if started.elapsed() >= DRAIN_WINDOW {
            return Err(anyhow!("cleanup durable drain exceeded {:?}", DRAIN_WINDOW));
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

fn assert_add_revision_correlation(
    deltas: &[DeltaRecord],
    records: &[MutationRecord],
) -> Result<()> {
    let expected: HashMap<&str, i64> = records
        .iter()
        .map(|record| (record.operation_id.as_str(), record.rule_id))
        .collect();
    let mut seen = HashSet::new();
    for delta in deltas {
        let rule_id = expected
            .get(delta.operation_id.as_str())
            .ok_or_else(|| anyhow!("foreign operation in trial rows"))?;
        if !seen.insert(delta.operation_id.as_str())
            || delta.event_type != "ADD"
            || delta.revision_no != 1
            || delta.revision_status != "ACTIVE"
            || delta.is_tombstone != 0
            || delta.revision_operation_id != delta.operation_id
            || delta.revision_event_id != delta.event_id
            || delta.provenance_operation_id != delta.operation_id
            || delta.provenance_event_id != delta.event_id
            || delta.source_entry != rule_id.to_string()
        {
            return Err(anyhow!(
                "delta/revision/provenance identity mismatch for {}",
                delta.operation_id
            ));
        }
    }
    Ok(())
}

async fn assert_add_audit_correlation(
    pool: &MySqlPool,
    card_id: i64,
    deltas: &[DeltaRecord],
    records: &[MutationRecord],
) -> Result<()> {
    let operation_ids: Vec<&str> = records
        .iter()
        .map(|record| record.operation_id.as_str())
        .collect();
    let audits = read_audit_details(pool, &operation_ids).await?;
    for delta in deltas {
        let detail = audits
            .get(&delta.operation_id)
            .ok_or_else(|| anyhow!("missing direct-rule audit row for {}", delta.operation_id))?;
        let parent_event: (String,) = tokio::time::timeout(
            DB_CALL_TIMEOUT,
            sqlx::query_as("SELECT event_id FROM authorization_projection_outbox WHERE aggregate_type = 'CARD' AND aggregate_id = ? AND source_generation = ?")
                .bind(card_id)
                .bind(delta.source_generation)
                .fetch_one(pool),
        ).await.map_err(|_| anyhow!("ADD audit parent projection query timed out"))??;
        let audit_parent = detail.get("eventId").and_then(serde_json::Value::as_str);
        let parent_generation = tokio::time::timeout(
            DB_CALL_TIMEOUT,
            sqlx::query_scalar::<_, i64>("SELECT source_generation FROM authorization_projection_outbox WHERE aggregate_type = 'CARD' AND aggregate_id = ? AND event_id = ?")
                .bind(card_id)
                .bind(&parent_event.0)
                .fetch_one(pool),
        ).await.map_err(|_| anyhow!("ADD audit parent generation query timed out"))??;
        if detail
            .get("operationId")
            .and_then(serde_json::Value::as_str)
            != Some(delta.operation_id.as_str())
            || audit_parent != Some(parent_event.0.as_str())
            || parent_generation != delta.source_generation
            || !json_string_array_contains(detail.get("contributionEventIds"), &delta.event_id)
            || !json_i64_array_contains(detail.get("ruleIds"), delta.source_entry.parse()?)
        {
            return Err(anyhow!(
                "ADD audit correlation mismatch for {}",
                delta.operation_id
            ));
        }
    }
    Ok(())
}

async fn assert_remove_revision_correlation(
    pool: &MySqlPool,
    tenant_id: i64,
    card_id: i64,
    deltas: &[DeltaRecord],
    storm_records: &[MutationRecord],
    cleanup_operation_id: &str,
) -> Result<()> {
    let source_operations: Vec<&str> = storm_records
        .iter()
        .map(|record| record.operation_id.as_str())
        .collect();
    let source_deltas = read_delta_rows(pool, tenant_id, card_id, &source_operations).await?;
    assert_add_revision_correlation(&source_deltas, storm_records)?;
    let grant_by_rule: HashMap<i64, &str> = source_deltas
        .iter()
        .map(|delta| {
            (
                delta.source_entry.parse::<i64>().unwrap_or_default(),
                delta.grant_id.as_str(),
            )
        })
        .collect();
    let expected_rules: HashSet<i64> = storm_records.iter().map(|record| record.rule_id).collect();
    if deltas.len() != expected_rules.len() || grant_by_rule.len() != expected_rules.len() {
        return Err(anyhow!(
            "cleanup tombstone count does not match storm source rule count"
        ));
    }
    let mut seen = HashSet::new();
    for delta in deltas {
        let source_entry: i64 = delta
            .source_entry
            .parse()
            .context("cleanup source entry is not a rule id")?;
        let expected_grant = grant_by_rule
            .get(&source_entry)
            .ok_or_else(|| anyhow!("cleanup tombstone source entry is not a run-owned rule"))?;
        if !seen.insert(source_entry)
            || delta.grant_id != *expected_grant
            || delta.operation_id != cleanup_operation_id
            || delta.event_type != "REMOVE"
            || delta.revision_no != 2
            || delta.revision_status != "ACTIVE"
            || delta.is_tombstone != 1
            || delta.revision_operation_id != cleanup_operation_id
            || delta.revision_event_id != delta.event_id
            || delta.provenance_operation_id != cleanup_operation_id
            || delta.provenance_event_id != delta.event_id
        {
            return Err(anyhow!(
                "cleanup delta/revision correlation mismatch for rule {source_entry}"
            ));
        }
    }

    let audit = read_audit_details(pool, &[cleanup_operation_id]).await?;
    let detail = audit
        .get(cleanup_operation_id)
        .ok_or_else(|| anyhow!("missing batch cleanup audit row"))?;
    let audited_rules = json_i64_array(detail.get("ruleIds"))?;
    let audited_events = json_string_array(detail.get("contributionEventIds"))?;
    let expected_pairs: HashSet<(i64, &str)> = deltas
        .iter()
        .map(|delta| Ok((delta.source_entry.parse::<i64>()?, delta.event_id.as_str())))
        .collect::<Result<_>>()?;
    let actual_pairs: HashSet<(i64, &str)> = audited_rules
        .iter()
        .copied()
        .zip(audited_events.iter().copied())
        .collect();
    if detail
        .get("operationId")
        .and_then(serde_json::Value::as_str)
        != Some(cleanup_operation_id)
        || audited_rules.len() != audited_events.len()
        || actual_pairs != expected_pairs
    {
        return Err(anyhow!(
            "batch cleanup audit does not correlate the exact tombstone events and source rules"
        ));
    }
    let expected_rules: HashSet<i64> = storm_records.iter().map(|record| record.rule_id).collect();
    if audited_rules.iter().copied().collect::<HashSet<_>>() != expected_rules {
        return Err(anyhow!(
            "batch cleanup audit does not list the exact run-owned source rules"
        ));
    }
    Ok(())
}

async fn read_delta_rows(
    pool: &MySqlPool,
    tenant_id: i64,
    card_id: i64,
    operation_ids: &[&str],
) -> Result<Vec<DeltaRecord>> {
    if operation_ids.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = vec!["?"; operation_ids.len()].join(",");
    let sql = format!(
        "SELECT d.event_id, d.operation_id, d.grant_id, d.event_type, d.source_generation, d.status, d.attempts, d.last_error, \
         r.revision_no, r.status, r.is_tombstone, r.operation_id, r.event_id, \
         CAST(JSON_UNQUOTE(JSON_EXTRACT(r.grant_payload, '$.provenance.sourceEntry')) AS CHAR CHARACTER SET utf8mb4), \
         CAST(JSON_UNQUOTE(JSON_EXTRACT(r.grant_payload, '$.provenance.operationId')) AS CHAR CHARACTER SET utf8mb4), \
         CAST(JSON_UNQUOTE(JSON_EXTRACT(r.grant_payload, '$.provenance.eventId')) AS CHAR CHARACTER SET utf8mb4) \
         FROM authorization_delta_event d INNER JOIN authorization_grant_revision r \
           ON r.tenant_id = d.tenant_id AND r.aggregate_type = d.aggregate_type \
          AND r.aggregate_id = d.aggregate_id AND r.grant_id = d.grant_id \
          AND r.operation_id = d.operation_id AND r.event_id = d.event_id \
         WHERE d.tenant_id = ? AND d.card_id = ? AND d.aggregate_type = 'USER_CARD' \
           AND d.aggregate_id = ? AND d.operation_id IN ({placeholders}) ORDER BY d.source_generation, d.delta_event_id"
    );
    let mut query = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            i64,
            String,
            i64,
            Option<String>,
            i64,
            String,
            i64,
            String,
            String,
            String,
            String,
            String,
        ),
    >(&sql)
    .bind(tenant_id)
    .bind(card_id)
    .bind(card_id);
    for operation_id in operation_ids {
        query = query.bind(operation_id);
    }
    let rows = tokio::time::timeout(DB_CALL_TIMEOUT, query.fetch_all(pool))
        .await
        .map_err(|_| anyhow!("delta/revision query timed out"))??;
    Ok(rows
        .into_iter()
        .map(|row| DeltaRecord {
            event_id: row.0,
            operation_id: row.1,
            grant_id: row.2,
            event_type: row.3,
            source_generation: row.4,
            status: row.5,
            attempts: row.6,
            last_error: row.7,
            revision_no: row.8,
            revision_status: row.9,
            is_tombstone: row.10,
            revision_operation_id: row.11,
            revision_event_id: row.12,
            source_entry: row.13,
            provenance_operation_id: row.14,
            provenance_event_id: row.15,
        })
        .collect())
}

async fn assert_owned_execution_accounting(
    pool: &MySqlPool,
    tenant_id: i64,
    deltas: &[DeltaRecord],
) -> Result<()> {
    for delta in deltas {
        let (claims, executions, failures): (i64, i64, i64) = tokio::time::timeout(
            DB_CALL_TIMEOUT,
            sqlx::query_as(
                "SELECT attempts, execution_attempts, execution_failures \
                 FROM authorization_delta_event WHERE tenant_id = ? AND event_id = ?",
            )
            .bind(tenant_id)
            .bind(&delta.event_id)
            .fetch_one(pool),
        )
        .await
        .map_err(|_| anyhow!("owned execution accounting read timed out"))??;
        if (claims, executions, failures) != (1, 1, 0) {
            return Err(anyhow!(
                "healthy owned event {} has claims={claims}, executions={executions}, failures={failures}; expected (1,1,0)",
                delta.event_id,
            ));
        }
        let (proofs,): (i64,) = tokio::time::timeout(
            DB_CALL_TIMEOUT,
            sqlx::query_as(
                "SELECT COUNT(*) FROM authorization_impact_plan p \
                 INNER JOIN authorization_projection_manifest m \
                   ON m.tenant_id = p.tenant_id AND m.aggregate_type = p.aggregate_type \
                  AND m.aggregate_id = p.aggregate_id AND m.generation = p.target_generation \
                 WHERE p.tenant_id = ? AND p.event_id = ? AND p.operation_id = ? \
                   AND m.event_id = p.event_id AND m.operation_id = p.operation_id \
                   AND p.status = 'SUCCEEDED' AND m.status IN ('COMMITTED', 'SUPERSEDED')",
            )
            .bind(tenant_id)
            .bind(&delta.event_id)
            .bind(&delta.operation_id)
            .fetch_one(pool),
        )
        .await
        .map_err(|_| anyhow!("owned event publication proof read timed out"))??;
        if proofs != 1 {
            return Err(anyhow!(
                "owned event {} does not have exactly one matching historical publication",
                delta.event_id,
            ));
        }
        let receipt = load_completion_receipt(pool, tenant_id, delta).await?;
        let completion =
            tokio::time::timeout(DB_CALL_TIMEOUT, load_owned_delta_completion(pool, &receipt))
                .await
                .map_err(|_| anyhow!("owned event full completion proof read timed out"))??;
        if completion.is_none() {
            return Err(anyhow!(
                "owned event {} has no verified historical completion proof",
                delta.event_id,
            ));
        }
    }
    Ok(())
}

async fn load_completion_receipt(
    pool: &MySqlPool,
    tenant_id: i64,
    delta: &DeltaRecord,
) -> Result<DeltaEventAppendRequest> {
    // Reconstructed receipts test historical evidence, not source COMMIT provenance.
    let row = tokio::time::timeout(
        DB_CALL_TIMEOUT,
        sqlx::query(
            "SELECT tenant_id, card_id, aggregate_type, aggregate_id, grant_id, \
             event_id, operation_id, event_type, base_version, target_version, \
             source_generation, revoke_fence, invalidates_published_evidence, \
             CAST(before_image_json AS CHAR CHARACTER SET utf8mb4) AS before_image_json, \
             before_digest, CAST(delta_json AS CHAR CHARACTER SET utf8mb4) AS delta_json, semantic_hash, \
             dependency_hash, compiler_version FROM authorization_delta_event \
             WHERE tenant_id = ? AND event_id = ? AND operation_id = ?",
        )
        .bind(tenant_id)
        .bind(&delta.event_id)
        .bind(&delta.operation_id)
        .fetch_one(pool),
    )
    .await
    .map_err(|_| anyhow!("owned completion receipt read timed out"))??;
    let event_type: String = row.try_get("event_type")?;
    let event_type = match event_type.as_str() {
        "ADD" => DeltaEventType::Add,
        "UPDATE" => DeltaEventType::Update,
        "REMOVE" => DeltaEventType::Remove,
        "REVOKE" => DeltaEventType::Revoke,
        _ => return Err(anyhow!("unknown durable delta event type")),
    };
    let before_digest: Option<Vec<u8>> = row.try_get("before_digest")?;
    let grant_id: String = row.try_get("grant_id")?;
    Ok(DeltaEventAppendRequest {
        tenant_id: row.try_get("tenant_id")?,
        card_id: row.try_get("card_id")?,
        aggregate_type: row.try_get("aggregate_type")?,
        aggregate_id: row.try_get("aggregate_id")?,
        grant_id: astral_types::GrantId::parse(&grant_id)?,
        event_id: row.try_get("event_id")?,
        operation_id: row.try_get("operation_id")?,
        event_type,
        base_version: row.try_get("base_version")?,
        target_version: row.try_get("target_version")?,
        source_generation: u64::try_from(row.try_get::<i64, _>("source_generation")?)?,
        revoke_fence: u64::try_from(row.try_get::<i64, _>("revoke_fence")?)?,
        invalidates_published_evidence: row.try_get::<i8, _>("invalidates_published_evidence")?
            != 0,
        before_image_json: row.try_get("before_image_json")?,
        before_digest_hex: before_digest
            .map(Sha256Digest::from_bytes)
            .transpose()?
            .map(|digest| digest.as_hex()),
        delta_json: row.try_get("delta_json")?,
        semantic_hash_hex: Sha256Digest::from_bytes(row.try_get("semantic_hash")?)?.as_hex(),
        dependency_hash_hex: Sha256Digest::from_bytes(row.try_get("dependency_hash")?)?.as_hex(),
        compiler_version: row.try_get("compiler_version")?,
        next_attempt_at: None,
    })
}

async fn report_durable_workload(
    pool: &MySqlPool,
    tenant_id: i64,
    mode: ProjectionExecutionMode,
    worker: &WorkerRunSummary,
) -> Result<()> {
    let (claims, executions, failures, max_execution_failures): (i64, i64, i64, i64) =
        tokio::time::timeout(
            DB_CALL_TIMEOUT,
            sqlx::query_as(
                "SELECT CAST(COALESCE(SUM(attempts), 0) AS SIGNED), \
                 CAST(COALESCE(SUM(execution_attempts), 0) AS SIGNED), \
                 CAST(COALESCE(SUM(execution_failures), 0) AS SIGNED), \
                 COALESCE(MAX(execution_failures), 0) \
                 FROM authorization_delta_event WHERE tenant_id = ?",
            )
            .bind(tenant_id)
            .fetch_one(pool),
        )
        .await
        .map_err(|_| anyhow!("durable accounting summary timed out"))??;
    let (manifests, reference_rows, segment_rows, segment_bytes): (i64, i64, i64, i64) =
        tokio::time::timeout(
            DB_CALL_TIMEOUT,
            sqlx::query_as(
                "SELECT COUNT(DISTINCT m.manifest_id), COUNT(r.reference_id), \
                 CAST(COALESCE(SUM(s.row_count), 0) AS SIGNED), \
                 CAST(COALESCE(SUM(s.byte_size), 0) AS SIGNED) \
                 FROM authorization_projection_manifest m \
                 LEFT JOIN authorization_projection_manifest_segment r \
                   ON r.manifest_id = m.manifest_id AND r.tenant_id = m.tenant_id \
                 LEFT JOIN authorization_projection_segment s \
                   ON s.segment_id = r.segment_id AND s.tenant_id = r.tenant_id \
                 WHERE m.tenant_id = ? AND m.status IN ('COMMITTED', 'SUPERSEDED')",
            )
            .bind(tenant_id)
            .fetch_one(pool),
        )
        .await
        .map_err(|_| anyhow!("materialization summary timed out"))??;
    let (samples, max_elapsed_seconds): (i64, i64) = tokio::time::timeout(
        DB_CALL_TIMEOUT,
        sqlx::query_as(
            "SELECT COUNT(*), COALESCE(MAX(TIMESTAMPDIFF(SECOND, d.created_at, p.updated_at)), 0) \
             FROM authorization_delta_event d \
             INNER JOIN authorization_impact_plan p ON p.event_id = d.event_id \
               AND p.tenant_id = d.tenant_id AND p.operation_id = d.operation_id \
             WHERE d.tenant_id = ? AND d.status = 'SUCCEEDED' AND p.status = 'SUCCEEDED'",
        )
        .bind(tenant_id)
        .fetch_one(pool),
    )
    .await
    .map_err(|_| anyhow!("durable event timing summary timed out"))??;
    println!(
        "[NATIVE_STORM_COST] execution_mode={mode:?} claims={claims} executions={executions} failures={failures} max_execution_failures={max_execution_failures} historical_manifests={manifests} reference_rows={reference_rows} cumulative_segment_rows={segment_rows} cumulative_segment_bytes={segment_bytes} source_append_to_plan_complete_samples={samples} source_append_to_plan_complete_max_s={max_elapsed_seconds} db_timestamp_resolution_s=1 worker_pointer_replans={} worker_dependency_blocks={} worker_lease_lost={} worker_decide_phase_micros={} execution_counters_authoritative={}",
        worker.events_pointer_moved_replanned,
        worker.events_blocked,
        worker.events_lease_lost,
        worker.decide_phase_micros,
        mode == ProjectionExecutionMode::WorkerOwned,
    );
    Ok(())
}

async fn read_audit_details(
    pool: &MySqlPool,
    operation_ids: &[&str],
) -> Result<HashMap<String, serde_json::Value>> {
    if operation_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let placeholders = vec!["?"; operation_ids.len()].join(",");
    let sql = format!("SELECT request_id, detail FROM audit_log WHERE event_type = 'PERMISSION_RULE_MUTATION' AND request_id IN ({placeholders})");
    let mut query = sqlx::query_as::<_, (String, Option<String>)>(&sql);
    for operation_id in operation_ids {
        query = query.bind(operation_id);
    }
    let rows = tokio::time::timeout(DB_CALL_TIMEOUT, query.fetch_all(pool))
        .await
        .map_err(|_| anyhow!("audit correlation query timed out"))??;
    let mut details = HashMap::new();
    for (request_id, detail) in rows {
        let value: serde_json::Value = serde_json::from_str(detail.as_deref().unwrap_or("null"))
            .with_context(|| format!("invalid direct-rule audit detail for {request_id}"))?;
        if details.insert(request_id.clone(), value).is_some() {
            return Err(anyhow!(
                "duplicate direct-rule audit request id {request_id}"
            ));
        }
    }
    if details.len() != operation_ids.iter().collect::<HashSet<_>>().len() {
        return Err(anyhow!(
            "audit query returned fewer rows than expected operation IDs"
        ));
    }
    Ok(details)
}

fn json_string_array(value: Option<&serde_json::Value>) -> Result<Vec<&str>> {
    value
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow!("audit detail array is missing"))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .ok_or_else(|| anyhow!("audit event id is not a string"))
        })
        .collect()
}

fn json_i64_array(value: Option<&serde_json::Value>) -> Result<Vec<i64>> {
    value
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow!("audit rule-id array is missing"))?
        .iter()
        .map(|entry| {
            entry
                .as_i64()
                .ok_or_else(|| anyhow!("audit rule id is not an integer"))
        })
        .collect()
}

fn json_string_array_contains(value: Option<&serde_json::Value>, needle: &str) -> bool {
    value
        .and_then(serde_json::Value::as_array)
        .is_some_and(|values| values.iter().any(|entry| entry.as_str() == Some(needle)))
}

fn json_i64_array_contains(value: Option<&serde_json::Value>, needle: i64) -> bool {
    value
        .and_then(serde_json::Value::as_array)
        .is_some_and(|values| values.iter().any(|entry| entry.as_i64() == Some(needle)))
}

async fn assert_card_source_frontier(
    pool: &MySqlPool,
    tenant_id: i64,
    card_id: i64,
    latest: &DeltaRecord,
) -> Result<()> {
    assert_card_parent_frontier(
        pool,
        tenant_id,
        card_id,
        latest.source_generation,
        &latest.event_id,
        &latest.operation_id,
        "RULE_CREATED",
    )
    .await
}

async fn assert_card_cleanup_frontier(
    pool: &MySqlPool,
    tenant_id: i64,
    card_id: i64,
    cleanup_rows: &[DeltaRecord],
    cleanup_operation_id: &str,
) -> Result<()> {
    let generation = cleanup_rows
        .iter()
        .map(|delta| delta.source_generation)
        .max()
        .ok_or_else(|| anyhow!("cleanup has no source generation"))?;
    if cleanup_rows
        .iter()
        .any(|delta| delta.source_generation != generation)
    {
        return Err(anyhow!(
            "one card-level batch revoke produced inconsistent source generations"
        ));
    }
    let audit = read_audit_details(pool, &[cleanup_operation_id]).await?;
    let detail = audit
        .get(cleanup_operation_id)
        .ok_or_else(|| anyhow!("missing cleanup audit parent event"))?;
    let parent_event_id = detail
        .get("eventId")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow!("cleanup audit lacks CARD parent event id"))?;
    assert_card_parent_frontier(
        pool,
        tenant_id,
        card_id,
        generation,
        parent_event_id,
        cleanup_operation_id,
        "REVOKE",
    )
    .await
}

async fn assert_card_parent_frontier(
    pool: &MySqlPool,
    tenant_id: i64,
    card_id: i64,
    generation: i64,
    event_id: &str,
    operation_id: &str,
    event_type: &str,
) -> Result<()> {
    let (head_generation, head_event_id): (i64, String) = tokio::time::timeout(
        DB_CALL_TIMEOUT,
        sqlx::query_as("SELECT source_generation, last_event_id FROM authorization_projection_head WHERE aggregate_type = 'CARD' AND aggregate_id = ?")
            .bind(card_id).fetch_one(pool),
    ).await.map_err(|_| anyhow!("CARD head read timed out"))??;
    let (outbox_generation, outbox_event, actual_event_type, outbox_status, payload): (i64, String, String, String, String) = tokio::time::timeout(
        DB_CALL_TIMEOUT,
        sqlx::query_as("SELECT source_generation, event_id, event_type, status, payload_json FROM authorization_projection_outbox WHERE tenant_id = ? AND aggregate_type = 'CARD' AND aggregate_id = ? ORDER BY source_generation DESC, sequence_number DESC LIMIT 1")
            .bind(tenant_id).bind(card_id).fetch_one(pool),
    ).await.map_err(|_| anyhow!("CARD source outbox read timed out"))??;
    let payload: serde_json::Value =
        serde_json::from_str(&payload).context("invalid CARD outbox payload JSON")?;
    if head_generation != generation
        || head_event_id != event_id
        || outbox_generation != generation
        || outbox_event != event_id
        || actual_event_type != event_type
        || !matches!(outbox_status.as_str(), "PENDING" | "PROCESSED")
        || payload
            .get("operationId")
            .and_then(serde_json::Value::as_str)
            != Some(operation_id)
    {
        return Err(anyhow!(
            "CARD head/source outbox does not match the source operation frontier"
        ));
    }
    Ok(())
}

async fn read_current_pointer(
    pool: &MySqlPool,
    tenant_id: i64,
    card_id: i64,
) -> Result<Option<(i64, String, String, String, i64)>> {
    tokio::time::timeout(
        DB_CALL_TIMEOUT,
        sqlx::query_as(
            "SELECT c.current_generation, c.event_id, c.operation_id, c.status, m.source_generation \
             FROM authorization_projection_current c INNER JOIN authorization_projection_manifest m \
               ON m.tenant_id = c.tenant_id AND m.aggregate_type = c.aggregate_type \
              AND m.aggregate_id = c.aggregate_id AND m.manifest_id = c.manifest_id \
             WHERE c.tenant_id = ? AND c.aggregate_type = 'USER_CARD' AND c.aggregate_id = ?",
        ).bind(tenant_id).bind(card_id).fetch_optional(pool),
    )
    .await
    .map_err(|_| anyhow!("USER_CARD current pointer read timed out"))?
    .map_err(Into::into)
}

async fn strict_evidence_matches(
    pool: &MySqlPool,
    tenant_id: i64,
    card_id: i64,
    domain_id: i64,
    deltas: &[DeltaRecord],
    expect_empty: bool,
) -> Result<bool> {
    let Some((generation, event_id, operation_id, status, source_generation)) =
        read_current_pointer(pool, tenant_id, card_id).await?
    else {
        return Ok(false);
    };
    let latest_source_generation = deltas
        .iter()
        .map(|delta| delta.source_generation)
        .max()
        .ok_or_else(|| anyhow!("no deltas supplied to strict frontier check"))?;
    let latest_operation = deltas
        .iter()
        .filter(|delta| delta.source_generation == latest_source_generation)
        .map(|delta| delta.operation_id.as_str())
        .collect::<HashSet<_>>();
    if status != "READY"
        || generation != deltas.len() as i64
        || source_generation != latest_source_generation
        || !deltas.iter().any(|delta| delta.event_id == event_id)
        || !latest_operation.contains(operation_id.as_str())
    {
        return Ok(false);
    }
    let scope = PublishedCardEvidenceScope {
        tenant_id,
        card_id,
        user_filter: None,
        domain: DomainScopeRequirement::ExactlySome(domain_id),
    };
    let evidence = tokio::time::timeout(
        DB_CALL_TIMEOUT,
        load_published_card_grant_evidence(pool, &scope),
    )
    .await
    .map_err(|_| anyhow!("strict evidence read timed out"))??;
    if evidence.gate.status != PublishedEvidenceGateStatus::Ready {
        return Ok(false);
    }
    if expect_empty {
        return Ok(evidence.effective_grants.is_empty() && evidence.gate.effective_grant_count == 0);
    }
    let expected: HashSet<String> = deltas
        .iter()
        .filter(|delta| delta.event_type == "ADD")
        .map(|delta| delta.grant_id.clone())
        .collect();
    let actual: HashSet<String> = evidence
        .effective_grants
        .iter()
        .map(|grant| grant.grant_id.to_string())
        .collect();
    Ok(actual == expected && evidence.gate.effective_grant_count == expected.len())
}

async fn reconcile_operations(
    pool: &MySqlPool,
    tenant_id: i64,
    card_id: i64,
    operation_ids: &[String],
) -> Result<()> {
    if operation_ids.is_empty() {
        return Ok(());
    }
    let borrowed: Vec<&str> = operation_ids.iter().map(String::as_str).collect();
    let rows = read_delta_rows(pool, tenant_id, card_id, &borrowed).await?;
    println!(
        "[NATIVE_STORM_RECONCILE] attempted={} durable_rows={}",
        operation_ids.len(),
        rows.len()
    );
    for row in rows {
        println!(
            "[NATIVE_STORM_RECONCILE] operation_id={} event_id={} state={} attempts={}",
            row.operation_id, row.event_id, row.status, row.attempts
        );
    }
    Ok(())
}

async fn cleanup_storm_fixture(
    pool: &MySqlPool,
    fixture: &SuiteFixture,
    operation_ids: &[String],
) -> Result<()> {
    let lo = fixture.base;
    let tenant_hi = fixture.base + fixture.tenants.len() as i64;
    let card_hi = fixture.base + 14 * testsuite::CATEGORY_STRIDE + 2_000;
    let mut tx = tokio::time::timeout(DB_CALL_TIMEOUT, pool.begin())
        .await
        .map_err(|_| anyhow!("cleanup transaction begin timed out"))??;
    let (ordering_key, counter_key) = fixture_message_scope(fixture);
    let counter: Option<i64> = sqlx::query_scalar(
        "SELECT last_sequence FROM al_message_scope_counter WHERE scope_key = ? \
         AND CAST(scope_key AS BINARY) = CAST(? AS BINARY) FOR UPDATE",
    )
    .bind(&counter_key)
    .bind(&counter_key)
    .fetch_optional(&mut *tx)
    .await?;
    let messages = sqlx::query(
        "SELECT operation_id, tenant_id, origin_region, message_type, status, lease_owner, scope_sequence \
         FROM al_message_outbox WHERE queue_name = ? AND ordering_key = ? FOR UPDATE",
    )
    .bind(QUEUE_AUTHORIZATION_INVALIDATION)
    .bind(&ordering_key)
    .fetch_all(&mut *tx)
    .await?;
    let expected_origin = format!("native-storm-{:x}", fixture.salt);
    let mut sequences = std::collections::BTreeSet::new();
    for row in &messages {
        let operation_id: String = row.try_get("operation_id")?;
        let tenant_id: Option<i64> = row.try_get("tenant_id")?;
        let origin: String = row.try_get("origin_region")?;
        let message_type: String = row.try_get("message_type")?;
        let status: String = row.try_get("status")?;
        let owner: Option<String> = row.try_get("lease_owner")?;
        let sequence: Option<i64> = row.try_get("scope_sequence")?;
        if !operation_ids.contains(&operation_id)
            || tenant_id != Some(fixture.tenants[0].tenant_id)
            || origin != expected_origin
            || message_type != astral_mq::invalidation::EVIDENCE_INVALIDATED
            || !matches!(status.as_str(), "PENDING" | "PROCESSED")
            || owner.as_deref().is_some_and(|value| !value.is_empty())
            || sequence.is_none_or(|value| value <= 0 || !sequences.insert(value))
        {
            return Err(anyhow!("storm fixture message scope ownership is unproven"));
        }
    }
    if counter != sequences.last().copied() {
        return Err(anyhow!(
            "storm fixture message counter does not match its owned rows"
        ));
    }
    let pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM authorization_delta_event \
         WHERE tenant_id > ? AND tenant_id <= ? AND status <> 'SUCCEEDED'",
    )
    .bind(lo)
    .bind(tenant_hi)
    .fetch_one(&mut *tx)
    .await?;
    let active: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM authorization_projection_partition_lease \
         WHERE tenant_id > ? AND tenant_id <= ? AND \
           (active_delta_event_id IS NOT NULL OR active_delta_token_hash IS NOT NULL \
            OR lease_owner <> '' OR lease_expires_at > UTC_TIMESTAMP(6))",
    )
    .bind(lo)
    .bind(tenant_hi)
    .fetch_one(&mut *tx)
    .await?;
    if pending != 0 || active != 0 {
        return Err(anyhow!(
            "fixture cleanup requires all events succeeded and lanes inactive"
        ));
    }
    sqlx::query(
        "DELETE a FROM audit_log a INNER JOIN authorization_delta_event d \
           ON d.tenant_id = a.tenant_id \
          AND CAST(d.event_id AS BINARY) = \
              CAST(JSON_UNQUOTE(JSON_EXTRACT(a.detail, '$.eventId')) AS BINARY) \
         WHERE a.tenant_id > ? AND a.tenant_id <= ? \
           AND a.event_type = 'AUTHZ_OWNED_PROJECTION_LANE' \
           AND a.resource = 'authorization_projection_owned_lane' \
           AND d.aggregate_type = 'USER_CARD' \
           AND d.aggregate_id > ? AND d.aggregate_id <= ?",
    )
    .bind(lo)
    .bind(tenant_hi)
    .bind(lo)
    .bind(card_hi)
    .execute(&mut *tx)
    .await
    .context("cleanup exact fixture lane audit correlation")?;
    for table in [
        "authorization_projection_partition_lease",
        "authorization_projection_manifest_segment",
        "authorization_projection_current",
        "authorization_projection_manifest",
        "authorization_projection_segment",
        "authorization_impact_plan_item",
        "authorization_impact_plan",
        "authorization_archive_manifest",
        "authorization_archive_outbox",
        "authorization_delta_event",
        "authorization_grant_revision",
    ] {
        let sql = format!("DELETE FROM {table} WHERE tenant_id > ? AND tenant_id <= ?");
        sqlx::query(&sql)
            .bind(lo)
            .bind(tenant_hi)
            .execute(&mut *tx)
            .await
            .with_context(|| format!("cleanup {table}"))?;
    }
    for table in [
        "authorization_projection_outbox",
        "authorization_projection_head",
    ] {
        let sql = format!("DELETE FROM {table} WHERE aggregate_id > ? AND aggregate_id <= ?");
        sqlx::query(&sql)
            .bind(lo)
            .bind(card_hi)
            .execute(&mut *tx)
            .await
            .with_context(|| format!("cleanup {table}"))?;
    }
    if !operation_ids.is_empty() {
        let placeholders = vec!["?"; operation_ids.len()].join(",");
        let message_sql = format!(
            "DELETE FROM al_message_outbox WHERE tenant_id = ? AND origin_region = ? \
             AND operation_id IN ({placeholders})"
        );
        let audit_sql = format!("DELETE FROM audit_log WHERE request_id IN ({placeholders})");
        let mut message_query = sqlx::query(&message_sql)
            .bind(fixture.tenants[0].tenant_id)
            .bind(&expected_origin);
        let mut audit_query = sqlx::query(&audit_sql);
        for operation_id in operation_ids {
            message_query = message_query.bind(operation_id);
            audit_query = audit_query.bind(operation_id);
        }
        message_query
            .execute(&mut *tx)
            .await
            .context("cleanup message outbox")?;
        audit_query
            .execute(&mut *tx)
            .await
            .context("cleanup audit correlation")?;
    }
    sqlx::query("DELETE FROM permission_rule WHERE card_id > ? AND card_id <= ?")
        .bind(lo)
        .bind(card_hi)
        .execute(&mut *tx)
        .await
        .context("cleanup storm source rules")?;
    if let Some(last_sequence) = counter {
        let deleted = sqlx::query(
            "DELETE FROM al_message_scope_counter WHERE scope_key = ? \
             AND CAST(scope_key AS BINARY) = CAST(? AS BINARY) AND last_sequence = ? \
             AND NOT EXISTS (SELECT 1 FROM al_message_outbox WHERE queue_name = ? AND ordering_key = ?)",
        )
        .bind(&counter_key)
        .bind(&counter_key)
        .bind(last_sequence)
        .bind(QUEUE_AUTHORIZATION_INVALIDATION)
        .bind(&ordering_key)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if deleted != 1 {
            return Err(anyhow!(
                "storm fixture message counter retirement was not proven"
            ));
        }
    }
    tokio::time::timeout(DB_CALL_TIMEOUT, tx.commit())
        .await
        .map_err(|_| anyhow!("cleanup transaction commit timed out"))??;
    tokio::time::timeout(DB_CALL_TIMEOUT, cleanup_suite_rows(pool, fixture))
        .await
        .map_err(|_| anyhow!("cleanup tenant fixture timed out"))??;
    let remaining_lane_audit: i64 = tokio::time::timeout(
        DB_CALL_TIMEOUT,
        sqlx::query_scalar(
            "SELECT (SELECT COUNT(*) FROM audit_log WHERE tenant_id > ? AND tenant_id <= ? \
                     AND event_type = 'AUTHZ_OWNED_PROJECTION_LANE' \
                     AND resource = 'authorization_projection_owned_lane') + \
                    (SELECT COUNT(*) FROM al_message_scope_counter WHERE scope_key = ?) + \
                    (SELECT COUNT(*) FROM al_message_outbox WHERE queue_name = ? AND ordering_key = ?)",
        )
        .bind(lo)
        .bind(tenant_hi)
        .bind(&counter_key)
        .bind(QUEUE_AUTHORIZATION_INVALIDATION)
        .bind(&ordering_key)
        .fetch_one(pool),
    )
    .await
    .map_err(|_| anyhow!("cleanup lane audit postcondition timed out"))??;
    if remaining_lane_audit != 0 {
        return Err(anyhow!("fixture lane audit cleanup is incomplete"));
    }
    Ok(())
}
