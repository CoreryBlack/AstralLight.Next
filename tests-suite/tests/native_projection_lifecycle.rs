//! Native single-node projection lifecycle integration.
//!
//! This is deliberately one ignored test because the process-global LocalBus,
//! LocalProjectionBus, memory hub, and worker receiver are installed through
//! OnceLock/one-owner contracts. Run with an isolated migrated MySQL database:
//! `RUST_INTEGRATION_REQUIRED=1 cargo test -p testsuite --test native_projection_lifecycle -- --ignored`
//!
//! The source mutations below use the public TrustGraph `SqlxRuleRepository`
//! create/delete API. That API owns `AuthorizationSourceTransaction`, the
//! direct grant ledger, delta/audit correlation, and post-commit dispatch. This
//! test never fabricates a committed delta envelope.

use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use astral_db::{
    install_local_projection_bus, install_memory_projection_hub,
    load_published_card_grant_evidence, warm_from_durable, LocalProjectionBus,
    LocalProjectionBusConfig, MemoryMirroredRuleRepository,
    SqlxRuleRepository as SqlxPolicyRepository, LOCAL_PROJECTION_BUS_MAX_PAYLOAD_BYTES,
    LOCAL_PROJECTION_BUS_MAX_TOTAL_BYTES,
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
            AuthorizationProjectorHandle,
        },
        invalidation_runtime::{start_local_projection_supervisor, InvalidationFanoutRuntime},
        local_projection_worker::{
            start_local_projection_worker, LocalProjectionWorkerConfig,
            LocalProjectionWorkerStartError,
        },
    },
};
use astral_types::{PolicyContext, PublishedEvidenceGateStatus};
use policy_engine::PolicyEngine;
use sqlx::MySqlPool;
use testsuite::{cleanup_suite_rows, connect_suite, seed_all_tenants, SuiteFixture, TenantRole};
use tokio::{sync::watch, task::JoinHandle};

const TEST_TIMEOUT: Duration = Duration::from_secs(180);
const DB_CALL_TIMEOUT: Duration = Duration::from_secs(5);
const WARMUP_TIMEOUT: Duration = Duration::from_secs(90);
const POLL_INTERVAL: Duration = Duration::from_millis(25);

#[derive(Debug, Clone)]
struct MutationIdentity {
    operation_id: String,
    event_id: String,
    grant_id: String,
    revision_no: i64,
    source_generation: i64,
    revoke_fence: i64,
    event_type: String,
    is_tombstone: i64,
}

struct RuntimeOwners {
    projection_bus: LocalProjectionBus,
    supervisor: Option<InvalidationFanoutRuntime>,
    projector: Option<AuthorizationProjectorHandle>,
    invalidation_shutdown: watch::Sender<bool>,
    invalidation_join: Option<JoinHandle<()>>,
    // Keeping these receivers alive is part of LocalBus owner readiness. The
    // invalidation receiver is owned by `invalidation_join` instead.
    _audit_receiver: LocalReceiver,
    _login_receiver: LocalReceiver,
    _session_receiver: LocalReceiver,
}

impl RuntimeOwners {
    async fn shutdown(mut self) -> Result<()> {
        let mut failures = Vec::new();

        if let Some(projector) = self.projector.take() {
            match tokio::time::timeout(
                Duration::from_secs(8),
                shutdown_authorization_projector(projector, Duration::from_secs(5)),
            )
            .await
            {
                Ok(report) => match report.summary {
                    Ok(summary)
                        if summary.events_publication_unknown == 0
                            && summary.events_quarantine_unknown == 0 => {}
                    Ok(_) => failures.push(
                        "projection worker has an unknown durable outcome; reconciliation required"
                            .to_owned(),
                    ),
                    Err(error) => failures.push(format!("projection worker shutdown: {error}")),
                },
                Err(_) => {
                    failures.push("projection worker shutdown outer bound exceeded".to_owned())
                }
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
                Ok(Err(error)) => {
                    failures.push(format!("invalidation supervisor shutdown: {error}"))
                }
                Err(_) => failures
                    .push("invalidation supervisor shutdown outer bound exceeded".to_owned()),
            }
        }

        let _ = self.invalidation_shutdown.send(true);
        if let Some(mut join) = self.invalidation_join.take() {
            match tokio::time::timeout(Duration::from_secs(3), &mut join).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => failures.push(format!("local invalidation consumer: {error}")),
                Err(_) => {
                    join.abort();
                    let _ = tokio::time::timeout(Duration::from_secs(1), &mut join).await;
                    failures.push("local invalidation consumer shutdown timed out".to_owned());
                }
            }
        }

        self.projection_bus.close("native lifecycle test shutdown");

        if failures.is_empty() {
            Ok(())
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
            .close("native lifecycle test owner dropped");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires migrated isolated MySQL and the native single-node projection path"]
async fn native_projection_lifecycle_add_revoke_is_fail_closed_and_owned() {
    let Some(pool) = connect_suite().await else {
        return;
    };
    let fixture = SuiteFixture::new("native-projection-lifecycle", &[TenantRole::AllowActive]);
    let tenant = fixture.tenants[0];
    let add_one_operation = format!("native-projection-add-one-{:032x}", fixture.salt);
    let add_two_operation = format!("native-projection-add-two-{:032x}", fixture.salt);
    let remove_one_operation = format!("native-projection-remove-one-{:032x}", fixture.salt);
    let remove_two_operation = format!("native-projection-remove-two-{:032x}", fixture.salt);
    let operation_ids = vec![
        add_one_operation.clone(),
        add_two_operation.clone(),
        remove_one_operation.clone(),
        remove_two_operation.clone(),
    ];

    let result = tokio::time::timeout(TEST_TIMEOUT, async {
        setup_fixture(&pool, &fixture).await?;
        let mut owners = install_runtime(&pool).await?;
        let lifecycle = exercise_lifecycle(
            &pool,
            &fixture,
            &tenant,
            &mut owners,
            &add_one_operation,
            &add_two_operation,
            &remove_one_operation,
            &remove_two_operation,
        )
        .await;
        let shutdown = owners.shutdown().await;
        lifecycle.and(shutdown)
    })
    .await
    .map_err(|_| anyhow!("native projection lifecycle exceeded {TEST_TIMEOUT:?}"));

    // Failure or cancellation may leave a source commit or worker lease unknown.
    // Preserve run-owned rows until explicit reconciliation, even after an abort.
    if !cleanup_is_proven(&result) {
        eprintln!(
            "[UNKNOWN] native lifecycle outcome unproven; fixtures retained: base={} operations={operation_ids:?}",
            fixture.base
        );
        match result {
            Ok(Err(error)) | Err(error) => panic!("native projection lifecycle failed: {error:#}"),
            Ok(Ok(())) => unreachable!(),
        }
    }
    if let Err(error) = cleanup_native_fixture(&pool, &fixture, &operation_ids).await {
        eprintln!(
            "[UNKNOWN] native lifecycle cleanup outcome unproven; reconcile fixtures before retry"
        );
        panic!("native lifecycle cleanup failed: {error:#}");
    }
}

fn cleanup_is_proven(result: &Result<Result<()>>) -> bool {
    matches!(result, Ok(Ok(())))
}

#[test]
fn cleanup_requires_successful_lifecycle_and_joined_owners() {
    assert!(cleanup_is_proven(&Ok(Ok(()))));
    assert!(!cleanup_is_proven(&Ok(Err(anyhow!(
        "worker outcome unknown"
    )))));
    assert!(!cleanup_is_proven(&Err(anyhow!(
        "lifecycle deadline exceeded"
    ))));
}

#[tokio::test]
async fn projection_bus_drain_wait_requires_empty_occupancy() {
    assert!(drained_bus_observation((0, 0)).is_some());
    for occupancy in [(1, 64), (0, 64), (1, 0)] {
        assert!(drained_bus_observation(occupancy).is_none());
        assert!(wait_for("occupied bus", Duration::ZERO, || {
            std::future::ready(Ok(drained_bus_observation(occupancy)))
        })
        .await
        .is_err());
    }

    let observations = [(1, 64), (0, 64), (0, 0)];
    let mut checks = 0;
    wait_for("bus drain", Duration::from_secs(1), || {
        let observation = drained_bus_observation(observations[checks]);
        checks += 1;
        std::future::ready(Ok(observation))
    })
    .await
    .expect("wait must continue until the count and byte budget are both empty");
    assert_eq!(checks, observations.len());
}

fn drained_bus_observation(occupancy: (usize, usize)) -> Option<()> {
    (occupancy == (0, 0)).then_some(())
}

async fn setup_fixture(pool: &MySqlPool, fixture: &SuiteFixture) -> Result<()> {
    tokio::time::timeout(DB_CALL_TIMEOUT, seed_all_tenants(pool, fixture))
        .await
        .map_err(|_| anyhow!("seed_all_tenants timed out"))??;

    install_origin_region(format!("native-test-{:x}", fixture.salt))
        .map_err(|error| anyhow!("origin region install failed: {error}"))?;
    Ok(())
}

async fn install_runtime(pool: &MySqlPool) -> Result<RuntimeOwners> {
    if !install_memory_projection_hub() {
        return Err(anyhow!("memory projection hub was already installed"));
    }
    let hub = astral_db::memory_projection_hub()
        .cloned()
        .ok_or_else(|| anyhow!("memory projection hub install returned no global hub"))?;
    // Startup restores every durable aggregate, not one SQL call; the outer
    // lifecycle deadline must also retain time for mutation and owner drain.
    tokio::time::timeout(WARMUP_TIMEOUT, warm_from_durable(pool))
        .await
        .map_err(|_| anyhow!("memory projection hub warm-up timed out"))??;

    // A capacity-one bus makes a real second source mutation exercise bounded
    // admission/omission. Durable status is checked separately; queue presence
    // is never treated as a publication proof.
    let projection_bus = install_local_projection_bus(LocalProjectionBusConfig {
        capacity: 1,
        max_payload_bytes: LOCAL_PROJECTION_BUS_MAX_PAYLOAD_BYTES,
        max_total_bytes: LOCAL_PROJECTION_BUS_MAX_TOTAL_BYTES,
        max_queued_per_aggregate: 1,
    })
    .map_err(|error| anyhow!("local projection bus install failed: {error}"))?;

    let local_bus = LocalBus::new(LocalBusLimits::default())
        .map_err(|error| anyhow!("local bus construction failed: {error}"))?;
    install_global_local_bus(local_bus.clone())
        .map_err(|error| anyhow!("global local bus install failed: {error}"))?;
    let audit_receiver = local_bus
        .register(QUEUE_AUDIT_LOG, LocalOwner::TrustGraph)
        .context("register audit LocalBus owner")?;
    let login_receiver = local_bus
        .register(QUEUE_LOGIN_EVENT, LocalOwner::Identity)
        .context("register login LocalBus owner")?;
    let session_receiver = local_bus
        .register(QUEUE_AUTH_SESSION_REVOCATION, LocalOwner::Identity)
        .context("register session LocalBus owner")?;
    let invalidation_receiver = local_bus
        .register(
            QUEUE_AUTHORIZATION_INVALIDATION,
            LocalOwner::AuthorizationInvalidation,
        )
        .context("register invalidation LocalBus owner")?;
    let (invalidation_shutdown, invalidation_shutdown_rx) = watch::channel(false);
    let identity = NodeIdentity::try_from_parts("native-test", "native-lifecycle")
        .map_err(|error| anyhow!("node identity construction failed: {error}"))?;
    let supervisor = start_local_projection_supervisor(pool.clone(), local_bus, identity)
        .map_err(|error| anyhow!("local projection supervisor start failed: {error}"))?;
    let invalidation_join = tokio::spawn(run_invalidation_consumer(
        invalidation_receiver,
        invalidation_shutdown_rx,
    ));
    let owners = RuntimeOwners {
        projection_bus,
        supervisor: Some(supervisor),
        projector: None,
        invalidation_shutdown,
        invalidation_join: Some(invalidation_join),
        _audit_receiver: audit_receiver,
        _login_receiver: login_receiver,
        _session_receiver: session_receiver,
    };
    if let Err(error) = wait_for("memory hub healthy", Duration::from_secs(12), || {
        let hub = hub.clone();
        async move {
            Ok(if hub.channel_is_healthy() {
                Some(())
            } else {
                None
            })
        }
    })
    .await
    {
        return match owners.shutdown().await {
            Ok(()) => Err(error),
            Err(shutdown) => Err(anyhow!(
                "memory hub health wait failed: {error:#}; shutdown: {shutdown:#}"
            )),
        };
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

async fn exercise_lifecycle(
    pool: &MySqlPool,
    _fixture: &SuiteFixture,
    tenant: &testsuite::SuiteTenant,
    owners: &mut RuntimeOwners,
    add_one_operation: &str,
    add_two_operation: &str,
    remove_one_operation: &str,
    remove_two_operation: &str,
) -> Result<()> {
    let repo = SqlxRuleRepository::new(pool.clone());
    let first_rule_id = create_direct_rule(
        &repo,
        tenant.card_id,
        tenant.user_id,
        add_one_operation,
        "learn_subject",
    )
    .await?;
    let first = wait_for_mutation(pool, tenant.tenant_id, add_one_operation, false).await?;
    assert_mutation_shape(&first, tenant, first_rule_id, false, "ADD")?;

    let second_rule_id = create_direct_rule(
        &repo,
        tenant.card_id,
        tenant.user_id,
        add_two_operation,
        "learn_subject",
    )
    .await?;
    let second = wait_for_mutation(pool, tenant.tenant_id, add_two_operation, false).await?;
    assert_mutation_shape(&second, tenant, second_rule_id, false, "ADD")?;
    assert_ne!(first.grant_id, second.grant_id);
    assert!(owners.projection_bus.occupancy().0 >= 1);
    assert_projection_correlation(pool, tenant.card_id, &second).await?;

    // The two source calls are public production calls. The current code also
    // has a bounded post-commit synchronous publisher, so SUCCEEDED here may be
    // attributable to that path rather than the not-yet-started local worker.
    // The admitted envelope remains queued and is never used as a READY proof.
    assert!(matches!(
        first_status(pool, tenant.tenant_id, &first.event_id)
            .await?
            .as_str(),
        "PENDING" | "SUCCEEDED"
    ));
    let allow_before_revoke = evaluate(pool, tenant, true).await?;
    if !allow_before_revoke.allowed {
        return Err(anyhow!(
            "published direct ALLOW was not evaluable after durable source add: {:?}",
            allow_before_revoke
        ));
    }

    let removed_one =
        delete_direct_rule(&repo, first_rule_id, tenant.user_id, remove_one_operation).await?;
    let remove_one = wait_for_mutation(pool, tenant.tenant_id, remove_one_operation, true).await?;
    assert_eq!(removed_one, true);
    assert_mutation_shape(&remove_one, tenant, first_rule_id, true, "REMOVE")?;
    assert_eq!(remove_one.grant_id, first.grant_id);
    let allow_after_first_revoke = evaluate(pool, tenant, true).await?;
    if !allow_after_first_revoke.allowed {
        return Err(anyhow!(
            "remaining second direct ALLOW was denied after first revoke: {:?}",
            allow_after_first_revoke
        ));
    }

    let removed_two =
        delete_direct_rule(&repo, second_rule_id, tenant.user_id, remove_two_operation).await?;
    let remove_two = wait_for_mutation(pool, tenant.tenant_id, remove_two_operation, true).await?;
    assert_eq!(removed_two, true);
    assert_mutation_shape(&remove_two, tenant, second_rule_id, true, "REMOVE")?;
    assert_eq!(remove_two.grant_id, second.grant_id);
    assert!(remove_two.revoke_fence > 0);
    assert_projection_correlation(pool, tenant.card_id, &remove_two).await?;

    // This assertion is intentionally before the local projection worker starts:
    // the source revoke and canonical synchronous publication must close the
    // unsafe ALLOW. A DB/read error is an integration failure, never a DENY.
    let deny_before_worker = evaluate(pool, tenant, false).await?;
    if deny_before_worker.allowed || deny_before_worker.reason != "DEFAULT_DENY" {
        return Err(anyhow!(
            "revoked direct grant was not closed before worker drain: {:?}",
            deny_before_worker
        ));
    }
    let final_current = wait_for_current(pool, tenant.tenant_id, tenant.card_id, 4).await?;
    assert_eq!(
        final_current.1, 2,
        "two REMOVE events must advance revoke fence"
    );
    assert_eq!(final_current.4, "READY");
    assert!(
        final_current.5 > 0,
        "current pointer must carry revoke-fence proof"
    );
    let final_evidence = tokio::time::timeout(
        DB_CALL_TIMEOUT,
        load_published_card_grant_evidence(pool, &tenant.card_scope()),
    )
    .await
    .map_err(|_| anyhow!("final strict evidence read timed out"))??;
    assert_eq!(
        final_evidence.gate.status,
        PublishedEvidenceGateStatus::Ready
    );
    assert_eq!(final_evidence.gate.effective_grant_count, 0);

    // Install the real one-owner production worker only after source/revoke
    // assertions. A second start must be rejected without spawning a task.
    let mut config = AuthorizationProjectorConfig::default();
    config.tenants = vec![tenant.tenant_id];
    let worker = start_local_projection_worker(
        pool.clone(),
        LocalProjectionWorkerConfig {
            projector: config.clone(),
            recovery_poll: Some(Duration::from_secs(1)),
            max_recovery_events_per_pass: 8,
        },
    )
    .map_err(|error| anyhow!("production local projection worker start failed: {error}"))?;
    owners.projector = Some(worker);
    match start_local_projection_worker(
        pool.clone(),
        LocalProjectionWorkerConfig {
            projector: config,
            recovery_poll: Some(Duration::from_secs(1)),
            max_recovery_events_per_pass: 8,
        },
    ) {
        Err(LocalProjectionWorkerStartError::ReceiverTaken) => {}
        Err(other) => return Err(anyhow!("second worker rejected for wrong reason: {other}")),
        Ok(_) => {
            return Err(anyhow!(
                "second local projection worker unexpectedly started"
            ))
        }
    }
    wait_for(
        "local projection bus drain",
        Duration::from_secs(15),
        || {
            let bus = owners.projection_bus.clone();
            async move { Ok(drained_bus_observation(bus.occupancy())) }
        },
    )
    .await?;
    let deny_after_worker = evaluate(pool, tenant, false).await?;
    assert!(!deny_after_worker.allowed);
    assert_eq!(deny_after_worker.reason, "DEFAULT_DENY");
    Ok(())
}

async fn create_direct_rule(
    repo: &SqlxRuleRepository,
    card_id: i64,
    actor_id: i64,
    operation_id: &str,
    resource_type: &str,
) -> Result<i64> {
    let context = DirectRuleMutationContext::user(actor_id, Some(operation_id))
        .map_err(|error| anyhow!("mutation context rejected: {error}"))?;
    let new = NewRule {
        card_id,
        resource_type: resource_type.to_owned(),
        resource_id: None,
        action_code: "read".to_owned(),
        effect: "ALLOW".to_owned(),
        condition_json: None,
        priority: 1,
        valid_from: None,
        valid_to: None,
        source_type: "MANUAL".to_owned(),
        enabled: 1,
    };
    tokio::time::timeout(
        DB_CALL_TIMEOUT + Duration::from_secs(15),
        repo.create_rule(&new, &context),
    )
    .await
    .map_err(|_| anyhow!("direct create_rule timed out for {operation_id}"))?
    .map_err(|error| anyhow!("direct create_rule failed: {error}"))
}

async fn delete_direct_rule(
    repo: &SqlxRuleRepository,
    rule_id: i64,
    actor_id: i64,
    operation_id: &str,
) -> Result<bool> {
    let context = DirectRuleMutationContext::user(actor_id, Some(operation_id))
        .map_err(|error| anyhow!("mutation context rejected: {error}"))?;
    tokio::time::timeout(
        DB_CALL_TIMEOUT + Duration::from_secs(20),
        repo.delete_rule(rule_id, &context),
    )
    .await
    .map_err(|_| anyhow!("direct delete_rule timed out for {operation_id}"))?
    .map_err(|error| anyhow!("direct delete_rule failed: {error}"))
}

async fn wait_for_mutation(
    pool: &MySqlPool,
    tenant_id: i64,
    operation_id: &str,
    tombstone: bool,
) -> Result<MutationIdentity> {
    wait_for(
        "canonical delta terminal status",
        Duration::from_secs(20),
        || {
            let operation_id = operation_id.to_owned();
            async move {
                let row: Option<(
                    String,
                    String,
                    i64,
                    String,
                    String,
                    i64,
                    String,
                    i64,
                    i64,
                    String,
                    i64,
                    i64,
                )> =
                    tokio::time::timeout(
                        DB_CALL_TIMEOUT,
                        sqlx::query_as(
                    "SELECT d.event_id, d.grant_id, r.revision_no, r.operation_id, r.event_id, \
                         r.is_tombstone, d.event_type, d.source_generation, d.revoke_fence, \
                         d.status, d.base_version, d.target_version \
                         FROM authorization_delta_event d \
                         INNER JOIN authorization_grant_revision r \
                           ON r.tenant_id = d.tenant_id AND r.event_id = d.event_id \
                          AND r.operation_id = d.operation_id \
                         WHERE d.tenant_id = ? AND d.operation_id = ? \
                         ORDER BY d.delta_event_id DESC LIMIT 1",
                        )
                        .bind(tenant_id)
                        .bind(&operation_id)
                        .fetch_optional(pool),
                    )
                    .await
                    .map_err(|_| anyhow!("delta identity query timed out"))??;
                let Some((
                    event_id,
                    grant_id,
                    revision_no,
                    revision_operation_id,
                    revision_event_id,
                    is_tombstone,
                    event_type,
                    source_generation,
                    revoke_fence,
                    status,
                    base_version,
                    target_version,
                )) = row
                else {
                    return Ok(None);
                };
                if status != "SUCCEEDED" {
                    return Ok(None);
                }
                if tombstone && event_type != "REMOVE" || !tombstone && event_type != "ADD" {
                    return Err(anyhow!(
                        "unexpected delta event type {event_type} for {operation_id}"
                    ));
                }
                if (is_tombstone != 0) != tombstone {
                    return Err(anyhow!("unexpected tombstone flag for {operation_id}"));
                }
                if revision_operation_id != operation_id || revision_event_id != event_id {
                    return Err(anyhow!(
                        "revision correlation drift for {operation_id}: revision_event={revision_event_id}"
                    ));
                }
                if target_version <= base_version || source_generation <= 0 {
                    return Err(anyhow!("non-advancing canonical delta for {operation_id}"));
                }
                Ok(Some(MutationIdentity {
                    operation_id,
                    event_id,
                    grant_id,
                    revision_no,
                    source_generation,
                    revoke_fence,
                    event_type,
                    is_tombstone,
                }))
            }
        },
    )
    .await
    .and_then(|value| Ok(value))
}

async fn first_status(pool: &MySqlPool, tenant_id: i64, event_id: &str) -> Result<String> {
    let row: Option<(String,)> = tokio::time::timeout(
        DB_CALL_TIMEOUT,
        sqlx::query_as(
            "SELECT status FROM authorization_delta_event WHERE tenant_id = ? AND event_id = ?",
        )
        .bind(tenant_id)
        .bind(event_id)
        .fetch_optional(pool),
    )
    .await
    .map_err(|_| anyhow!("delta status query timed out"))??;
    row.map(|(status,)| status)
        .ok_or_else(|| anyhow!("missing delta event {event_id}"))
}

fn assert_mutation_shape(
    mutation: &MutationIdentity,
    tenant: &testsuite::SuiteTenant,
    rule_id: i64,
    tombstone: bool,
    event_type: &str,
) -> Result<()> {
    if mutation.operation_id.trim().is_empty()
        || mutation.event_id.trim().is_empty()
        || mutation.grant_id.trim().is_empty()
        || mutation.source_generation <= 0
        || mutation.event_type != event_type
        || mutation.is_tombstone != i64::from(tombstone)
    {
        return Err(anyhow!("invalid mutation identity: {mutation:?}"));
    }
    if tombstone {
        if mutation.revision_no != 2 || mutation.revoke_fence <= 0 {
            return Err(anyhow!(
                "REMOVE must append revision 2 and fence: {mutation:?}"
            ));
        }
    } else if mutation.revision_no != 1 || mutation.revoke_fence != 0 {
        return Err(anyhow!(
            "ADD must append revision 1 and fence 0: {mutation:?}"
        ));
    }
    let _ = (tenant, rule_id);
    Ok(())
}

async fn assert_projection_correlation(
    pool: &MySqlPool,
    card_id: i64,
    mutation: &MutationIdentity,
) -> Result<()> {
    let head: (i64, i64, String) = tokio::time::timeout(
        DB_CALL_TIMEOUT,
        sqlx::query_as(
            "SELECT source_generation, revoke_fence, last_event_id \
             FROM authorization_projection_head WHERE aggregate_type = 'CARD' AND aggregate_id = ?",
        )
        .bind(card_id)
        .fetch_one(pool),
    )
    .await
    .map_err(|_| anyhow!("projection head query timed out"))??;
    assert_eq!(head.0, mutation.source_generation);
    assert_eq!(head.1, mutation.revoke_fence);
    assert_eq!(head.2, mutation.event_id);

    let outbox: (String, String, i64, i64, String, String) = tokio::time::timeout(
        DB_CALL_TIMEOUT,
        sqlx::query_as(
            "SELECT event_id, event_type, source_generation, revoke_fence, status, payload_json \
             FROM authorization_projection_outbox WHERE aggregate_type = 'CARD' AND aggregate_id = ? \
             ORDER BY source_generation DESC LIMIT 1",
        )
        .bind(card_id)
        .fetch_one(pool),
    )
    .await
    .map_err(|_| anyhow!("projection outbox query timed out"))??;
    assert_eq!(outbox.0, mutation.event_id);
    assert_eq!(
        outbox.1,
        if mutation.is_tombstone != 0 {
            "REVOKE"
        } else {
            "RULE_CREATED"
        }
    );
    assert_eq!(outbox.2, mutation.source_generation);
    assert_eq!(outbox.3, mutation.revoke_fence);
    assert!(outbox.4 == "PENDING" || outbox.4 == "PROCESSED");
    assert!(outbox.5.contains(&mutation.operation_id));

    let audit: Option<(String, Option<String>)> = tokio::time::timeout(
        DB_CALL_TIMEOUT,
        sqlx::query_as(
            "SELECT request_id, detail FROM audit_log WHERE request_id = ? \
             ORDER BY id DESC LIMIT 1",
        )
        .bind(&mutation.operation_id)
        .fetch_optional(pool),
    )
    .await
    .map_err(|_| anyhow!("audit correlation query timed out"))??;
    let Some((request_id, detail)) = audit else {
        return Err(anyhow!(
            "missing audit correlation for {}",
            mutation.operation_id
        ));
    };
    assert_eq!(request_id, mutation.operation_id);
    assert!(detail.unwrap_or_default().contains(&mutation.event_id));
    Ok(())
}

async fn wait_for_current(
    pool: &MySqlPool,
    tenant_id: i64,
    card_id: i64,
    generation: i64,
) -> Result<(i64, i64, String, String, String, i64)> {
    wait_for(
        "canonical current pointer",
        Duration::from_secs(20),
        || async {
            let row: Option<(i64, i64, String, String, String, i64)> = tokio::time::timeout(
                DB_CALL_TIMEOUT,
                sqlx::query_as(
                    "SELECT current_generation, revoke_fence, event_id, operation_id, status, \
                 revoke_fence_proven FROM authorization_projection_current \
                 WHERE tenant_id = ? AND aggregate_type = 'USER_CARD' AND aggregate_id = ?",
                )
                .bind(tenant_id)
                .bind(card_id)
                .fetch_optional(pool),
            )
            .await
            .map_err(|_| anyhow!("current pointer query timed out"))??;
            match row {
                Some(pointer) if pointer.0 == generation && pointer.4 == "READY" => {
                    Ok(Some(pointer))
                }
                _ => Ok(None),
            }
        },
    )
    .await
    .and_then(|value| Ok(value))
}

async fn evaluate(
    pool: &MySqlPool,
    tenant: &testsuite::SuiteTenant,
    expect_allow: bool,
) -> Result<astral_types::PolicyDecision> {
    let ctx = PolicyContext::builder()
        .user_id(Some(tenant.user_id))
        .identity_card_id(Some(tenant.identity_card_id))
        .card_id(Some(tenant.card_id))
        .tenant_id(Some(tenant.tenant_id))
        .domain_id(Some(tenant.domain_id))
        .resource(Some("learn_subject".to_owned()))
        .action("read".to_owned())
        .build();
    let repo = MemoryMirroredRuleRepository::new(SqlxPolicyRepository::new(pool.clone()))
        .with_durable_refill(pool.clone());
    let decision = tokio::time::timeout(DB_CALL_TIMEOUT, PolicyEngine::new().evaluate(&ctx, &repo))
        .await
        .map_err(|_| anyhow!("PolicyEngine.evaluate timed out"))?;
    if decision.allowed != expect_allow {
        return Err(anyhow!("unexpected policy decision: {decision:?}"));
    }
    Ok(decision)
}

async fn wait_for<T, F, Fut>(label: &str, deadline: Duration, mut check: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<Option<T>>>,
{
    let started = Instant::now();
    loop {
        if let Some(value) = check().await? {
            return Ok(value);
        }
        if started.elapsed() >= deadline {
            return Err(anyhow!(
                "{label} did not reach its postcondition within {deadline:?}"
            ));
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

async fn cleanup_native_fixture(
    pool: &MySqlPool,
    fixture: &SuiteFixture,
    operation_ids: &[String],
) -> Result<()> {
    let lo = fixture.base;
    let tenant_hi = fixture.base + fixture.tenants.len() as i64;
    let card_lo = fixture.base;
    let card_hi = fixture.base + 14 * testsuite::CATEGORY_STRIDE + 2_000;
    let mut tx = tokio::time::timeout(DB_CALL_TIMEOUT, pool.begin())
        .await
        .map_err(|_| anyhow!("cleanup transaction begin timed out"))??;

    for table in [
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
            .bind(card_lo)
            .bind(card_hi)
            .execute(&mut *tx)
            .await
            .with_context(|| format!("cleanup {table}"))?;
    }

    if !operation_ids.is_empty() {
        let placeholders = std::iter::repeat_n("?", operation_ids.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!("DELETE FROM al_message_outbox WHERE operation_id IN ({placeholders})");
        let mut query = sqlx::query(&sql);
        for operation_id in operation_ids {
            query = query.bind(operation_id);
        }
        query
            .execute(&mut *tx)
            .await
            .context("cleanup local message outbox")?;

        let sql = format!("DELETE FROM audit_log WHERE request_id IN ({placeholders})");
        let mut query = sqlx::query(&sql);
        for operation_id in operation_ids {
            query = query.bind(operation_id);
        }
        query
            .execute(&mut *tx)
            .await
            .context("cleanup audit correlation")?;
    }
    sqlx::query("DELETE FROM permission_rule WHERE card_id > ? AND card_id <= ?")
        .bind(card_lo)
        .bind(card_hi)
        .execute(&mut *tx)
        .await
        .context("cleanup direct source rules")?;
    tokio::time::timeout(DB_CALL_TIMEOUT, tx.commit())
        .await
        .map_err(|_| anyhow!("cleanup transaction commit timed out"))??;

    tokio::time::timeout(DB_CALL_TIMEOUT, cleanup_suite_rows(pool, fixture))
        .await
        .map_err(|_| anyhow!("suite fixture cleanup timed out"))??;
    Ok(())
}
