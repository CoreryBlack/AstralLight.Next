//! Source-backed real-MySQL contract tests for WorkerOwned projection execution.
//!
//! This ignored target accepts only the approved run-scoped loopback:3308 clone.
//! RuleSet source writers create every delta receipt; claims and completion proofs
//! are always bound to the exact immutable rows those writers committed. A failure
//! or uncertain result leaves the fixture for reconciliation.
//!
//! Required environment: `RUST_INTEGRATION_REQUIRED=1`, `TEST_USE_EXISTING=1`,
//! `ASTRAL_MIGRATION_ENV=isolated`, `ASTRAL_TEST_DATABASE_NAME`, and `DATABASE_URL`.

use std::{
    env,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use astral_db::{
    begin_owned_delta_execution, claim_next_owned_delta_event,
    claim_owned_delta_event_by_stable_event, fail_owned_delta_event, load_owned_delta_completion,
    load_published_card_grant_evidence, release_owned_delta_event,
    validate_projection_owned_schema, AuthorizationEvidenceError, DeltaEventAppendRequest,
    DeltaEventClaimScope, DeltaEventType, OwnedCompletionIdentity, OwnedDeltaClaim,
    OwnedStableEventOutcome, Sha256Digest,
};
use astral_mq::invalidation::install_origin_region;
use astral_trustgraph::{
    repository::{
        audit_log_repository::RuleSetMutationContext, rule_set_repository::SqlxRuleSetRepository,
    },
    service::{
        authorization_projector::{
            shutdown_authorization_projector, start_authorization_projector_with_runtime,
            AuthorizationProjectorConfig,
        },
        rule_set_write_service::{AddEntryRequest, RuleSetWriteService, UpdateEntryRequest},
    },
};
use astral_types::PublishedEvidenceGateStatus;
use sqlx::{
    mysql::{MySqlConnectOptions, MySqlPoolOptions},
    FromRow, MySqlPool, Row,
};
use testsuite::{
    cleanup_suite_rows, publish_card_manifest, seed_all_tenants, SuiteFixture, SuiteTenant,
    TenantRole,
};
use time::PrimitiveDateTime;
use tokio::sync::Barrier;

const REQUIRED_MIGRATION_VERSION: i64 = 20261015000001;
const REQUIRED_DATABASE_PREFIX: &str = "astral_rehearsal_";
const TEST_DEADLINE: Duration = Duration::from_secs(180);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const CLAIM_LEASE_SECONDS: i64 = 90;
const COMPLETION_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
struct EventState {
    attempts: i64,
    execution_attempts: i64,
    execution_failures: i64,
    execution_accounting_version: i32,
    status: String,
    lease_owner: Option<String>,
    lease_token_hash: Option<Vec<u8>>,
    lease_expires_at: Option<PrimitiveDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
struct LaneState {
    execution_epoch: i64,
    lease_owner: String,
    lease_token_hash: Vec<u8>,
    lease_expires_at: PrimitiveDateTime,
    active_delta_event_id: Option<i64>,
    active_delta_token_hash: Option<Vec<u8>>,
}

async fn required_pool() -> MySqlPool {
    assert_eq!(
        env::var("RUST_INTEGRATION_REQUIRED").as_deref(),
        Ok("1"),
        "RUST_INTEGRATION_REQUIRED=1 is mandatory; this test never silently skips"
    );
    assert_eq!(
        env::var("TEST_USE_EXISTING").as_deref(),
        Ok("1"),
        "the caller must supply the already-created run-owned database"
    );
    assert_eq!(
        env::var("ASTRAL_MIGRATION_ENV").as_deref(),
        Ok("isolated"),
        "the caller must identify the isolated test environment"
    );

    let expected_database = env::var("ASTRAL_TEST_DATABASE_NAME")
        .expect("ASTRAL_TEST_DATABASE_NAME must name the approved clone");
    let suffix = expected_database
        .strip_prefix(REQUIRED_DATABASE_PREFIX)
        .expect("database must use the projection-owner run-scoped prefix");
    assert!(
        !suffix.is_empty()
            && suffix.len() <= 47
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'),
        "database name must have a bounded lowercase run suffix"
    );

    let url = env::var("DATABASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .expect("DATABASE_URL is mandatory when RUST_INTEGRATION_REQUIRED=1");
    assert!(
        !url.contains('?') && !url.contains('#'),
        "database URL query parameters and fragments are not allowed"
    );
    let options = MySqlConnectOptions::from_str(&url).expect("DATABASE_URL must parse");
    assert!(
        matches!(options.get_host(), "localhost" | "127.0.0.1" | "::1"),
        "owned contract tests may only use loopback MySQL"
    );
    assert_eq!(
        options.get_port(),
        3308,
        "expected isolated MySQL port 3308"
    );
    assert!(
        options.get_socket().is_none(),
        "socket URLs are not accepted"
    );
    assert_eq!(
        options.get_database(),
        Some(expected_database.as_str()),
        "DATABASE_URL must select exactly ASTRAL_TEST_DATABASE_NAME"
    );

    let pool = MySqlPoolOptions::new()
        .max_connections(8)
        .acquire_timeout(CONNECT_TIMEOUT)
        .connect_with(options)
        .await
        .expect("required isolated MySQL connection must succeed");
    validate_projection_owned_schema(&pool)
        .await
        .expect("owned execution schema and existing rows must validate read-only");
    let migration: Option<i64> = sqlx::query_scalar(
        "SELECT version FROM _sqlx_migrations WHERE version = ? AND success = TRUE",
    )
    .bind(REQUIRED_MIGRATION_VERSION)
    .fetch_optional(&pool)
    .await
    .expect("read the already-applied owned execution migration marker");
    assert_eq!(
        migration,
        Some(REQUIRED_MIGRATION_VERSION),
        "the owned execution migration must already be applied"
    );
    pool
}

fn operation_id(salt: u128, tag: &str) -> String {
    format!("po-{salt:032x}-{tag}")
}

fn owner_id(salt: u128, tag: &str) -> String {
    format!("worker-po-{salt:032x}-{tag}")
}

fn source_entry(action: &str, priority: i32) -> AddEntryRequest {
    AddEntryRequest {
        effect: "ALLOW".to_owned(),
        resource_type: Some("learn_subject".to_owned()),
        resource_id: None,
        action_code: Some(action.to_owned()),
        condition_json: None,
        priority,
    }
}

fn source_entry_update(action: &str, priority: i32) -> UpdateEntryRequest {
    UpdateEntryRequest {
        effect: "ALLOW".to_owned(),
        resource_type: Some("learn_subject".to_owned()),
        resource_id: None,
        action_code: Some(action.to_owned()),
        condition_json: None,
        priority,
    }
}

async fn source_update(
    service: &RuleSetWriteService,
    suite: &SuiteFixture,
    tenant: SuiteTenant,
    entry_id: i64,
    tag: &str,
    action: &str,
) -> String {
    let operation_id = operation_id(suite.salt, tag);
    let context = RuleSetMutationContext::user(tenant.user_id, Some(&operation_id))
        .expect("source mutation has a verified fixture actor and stable operation id");
    service
        .update_entry(
            tenant.rule_set_id,
            entry_id,
            &source_entry_update(action, 100),
            &context,
        )
        .await
        .expect("RuleSet source mutation must commit through the production writer");
    operation_id
}

/// Read the exact immutable receipt columns written by the source transaction.
async fn load_source_receipts(
    pool: &MySqlPool,
    tenant_id: i64,
    operation_id: &str,
) -> Result<Vec<DeltaEventAppendRequest>> {
    let rows = sqlx::query(
        "SELECT tenant_id, card_id, aggregate_type, aggregate_id, grant_id, event_id, operation_id, \
         event_type, base_version, target_version, source_generation, revoke_fence, \
         invalidates_published_evidence, \
         CAST(before_image_json AS CHAR CHARACTER SET utf8mb4) AS before_image_json, \
         before_digest, CAST(delta_json AS CHAR CHARACTER SET utf8mb4) AS delta_json, \
         semantic_hash, dependency_hash, compiler_version, next_attempt_at \
         FROM authorization_delta_event WHERE tenant_id = ? AND operation_id = ? \
         ORDER BY delta_event_id LIMIT 1025",
    )
    .bind(tenant_id)
    .bind(operation_id)
    .fetch_all(pool)
    .await
    .context("read source-committed delta receipts")?;
    if rows.len() > 1024 {
        return Err(anyhow!(
            "source receipt batch exceeds the bounded test capacity"
        ));
    }

    rows.into_iter()
        .map(|row| {
            let event_type: String = row.try_get("event_type")?;
            let event_type = match event_type.as_str() {
                "ADD" => DeltaEventType::Add,
                "UPDATE" => DeltaEventType::Update,
                "REMOVE" => DeltaEventType::Remove,
                "REVOKE" => DeltaEventType::Revoke,
                other => return Err(anyhow!("unknown durable event type {other}")),
            };
            let before_digest: Option<Vec<u8>> = row.try_get("before_digest")?;
            let semantic_hash: Vec<u8> = row.try_get("semantic_hash")?;
            let dependency_hash: Vec<u8> = row.try_get("dependency_hash")?;
            let request = DeltaEventAppendRequest {
                tenant_id: row.try_get("tenant_id")?,
                card_id: row.try_get("card_id")?,
                aggregate_type: row.try_get("aggregate_type")?,
                aggregate_id: row.try_get("aggregate_id")?,
                grant_id: astral_db::decode_grant_id_sql(row.try_get::<&str, _>("grant_id")?)?,
                event_id: row.try_get("event_id")?,
                operation_id: row.try_get("operation_id")?,
                event_type,
                base_version: row.try_get("base_version")?,
                target_version: row.try_get("target_version")?,
                source_generation: u64::try_from(row.try_get::<i64, _>("source_generation")?)?,
                revoke_fence: u64::try_from(row.try_get::<i64, _>("revoke_fence")?)?,
                invalidates_published_evidence: row
                    .try_get::<i8, _>("invalidates_published_evidence")?
                    != 0,
                before_image_json: row.try_get("before_image_json")?,
                before_digest_hex: before_digest
                    .map(Sha256Digest::from_bytes)
                    .transpose()?
                    .map(|digest| digest.as_hex()),
                delta_json: row.try_get("delta_json")?,
                semantic_hash_hex: Sha256Digest::from_bytes(semantic_hash)?.as_hex(),
                dependency_hash_hex: Sha256Digest::from_bytes(dependency_hash)?.as_hex(),
                compiler_version: row.try_get("compiler_version")?,
                next_attempt_at: row.try_get("next_attempt_at")?,
            };
            if request.tenant_id != tenant_id || request.operation_id != operation_id {
                return Err(anyhow!(
                    "source receipt escaped its requested operation scope"
                ));
            }
            if request.compiler_version != astral_types::AUTHORIZATION_COMPILER_VERSION {
                return Err(anyhow!(
                    "source receipt does not use the current compiler stamp"
                ));
            }
            OwnedCompletionIdentity::from_request(&request)
                .context("validate the complete source-owned receipt")?;
            Ok(request)
        })
        .collect()
}

async fn event_state(pool: &MySqlPool, request: &DeltaEventAppendRequest) -> EventState {
    sqlx::query_as(
        "SELECT attempts, execution_attempts, execution_failures, execution_accounting_version, \
         status, lease_owner, lease_token_hash, lease_expires_at \
         FROM authorization_delta_event WHERE tenant_id = ? AND aggregate_type = ? \
           AND aggregate_id = ? AND event_id = ?",
    )
    .bind(request.tenant_id)
    .bind(&request.aggregate_type)
    .bind(request.aggregate_id)
    .bind(&request.event_id)
    .fetch_one(pool)
    .await
    .expect("read exact source-owned delta state")
}

async fn lane_state(pool: &MySqlPool, request: &DeltaEventAppendRequest) -> Option<LaneState> {
    sqlx::query_as(
        "SELECT execution_epoch, lease_owner, lease_token_hash, lease_expires_at, \
         active_delta_event_id, active_delta_token_hash \
         FROM authorization_projection_partition_lease \
         WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ?",
    )
    .bind(request.tenant_id)
    .bind(&request.aggregate_type)
    .bind(request.aggregate_id)
    .fetch_optional(pool)
    .await
    .expect("read exact source aggregate's owned lane")
}

async fn assert_lane_inactive(pool: &MySqlPool, request: &DeltaEventAppendRequest, epoch: i64) {
    let lane = lane_state(pool, request)
        .await
        .expect("released lane row must be preserved, not deleted");
    assert_eq!(
        lane.execution_epoch, epoch,
        "release preserves the owner epoch"
    );
    assert_eq!(lane.lease_owner, "");
    assert_eq!(lane.lease_token_hash, vec![0_u8; 32]);
    assert!(lane.active_delta_event_id.is_none());
    assert!(lane.active_delta_token_hash.is_none());
    let expired: i64 = sqlx::query_scalar(
        "SELECT CAST(lease_expires_at <= UTC_TIMESTAMP(6) AS SIGNED) \
         FROM authorization_projection_partition_lease \
         WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ?",
    )
    .bind(request.tenant_id)
    .bind(&request.aggregate_type)
    .bind(request.aggregate_id)
    .fetch_one(pool)
    .await
    .expect("check the inactive lane's durable lease expiry");
    assert_eq!(expired, 1, "released lane expiry must be in the past");
}

fn expect_claimed(outcome: OwnedStableEventOutcome, message: &str) -> OwnedDeltaClaim {
    match outcome {
        OwnedStableEventOutcome::Claimed(claimed) => *claimed,
        other => panic!("{message}; got {other:?}"),
    }
}

async fn assert_same_receipt_claim_race(
    pool: &MySqlPool,
    suite: &SuiteFixture,
    request: &DeltaEventAppendRequest,
) {
    let barrier = Arc::new(Barrier::new(3));
    let left_barrier = barrier.clone();
    let right_barrier = barrier.clone();
    let left_pool = pool.clone();
    let right_pool = pool.clone();
    let left_request = request.clone();
    let right_request = request.clone();
    let left_owner = owner_id(suite.salt, "same-receipt-left");
    let right_owner = owner_id(suite.salt, "same-receipt-right");
    let left = tokio::spawn(async move {
        left_barrier.wait().await;
        claim_owned_delta_event_by_stable_event(
            &left_pool,
            &left_request,
            &left_owner,
            CLAIM_LEASE_SECONDS,
        )
        .await
    });
    let right = tokio::spawn(async move {
        right_barrier.wait().await;
        claim_owned_delta_event_by_stable_event(
            &right_pool,
            &right_request,
            &right_owner,
            CLAIM_LEASE_SECONDS,
        )
        .await
    });
    barrier.wait().await;
    let (left, right) = tokio::join!(left, right);
    let mut winner = None;
    let mut busy = 0;
    for outcome in [
        left.expect("left exact-claim task must not panic")
            .expect("left exact claim must return a protocol outcome"),
        right
            .expect("right exact-claim task must not panic")
            .expect("right exact claim must return a protocol outcome"),
    ] {
        match outcome {
            OwnedStableEventOutcome::Claimed(claimed) => {
                assert!(
                    winner.is_none(),
                    "one source receipt acquired two live capabilities"
                );
                winner = Some(*claimed);
            }
            OwnedStableEventOutcome::Busy { event_id } => {
                assert_eq!(event_id, request.event_id);
                busy += 1;
            }
            other => panic!("exact source receipt race must be Claimed/Busy, got {other:?}"),
        }
    }
    assert_eq!(busy, 1, "exactly one contender must observe the live lane");
    let winner = winner.expect("one contender must own the source receipt");
    assert_eq!(winner.claim.event_id, request.event_id);
    assert_eq!(event_state(pool, request).await.attempts, 1);
    assert!(release_owned_delta_event(pool, &winner.lease)
        .await
        .expect("winner must release its exact owned capability"));
    assert_lane_inactive(pool, request, winner.lease.ownership_epoch()).await;
}

async fn assert_independent_aggregate_claims(
    pool: &MySqlPool,
    suite: &SuiteFixture,
    left: &DeltaEventAppendRequest,
    right: &DeltaEventAppendRequest,
) {
    assert_ne!(
        (
            left.tenant_id,
            left.aggregate_type.as_str(),
            left.aggregate_id
        ),
        (
            right.tenant_id,
            right.aggregate_type.as_str(),
            right.aggregate_id
        ),
        "independent claims must come from distinct source aggregates"
    );
    let barrier = Arc::new(Barrier::new(3));
    let left_barrier = barrier.clone();
    let right_barrier = barrier.clone();
    let left_pool = pool.clone();
    let right_pool = pool.clone();
    let left_request = left;
    let right_request = right;
    let left_task_request = left.clone();
    let right_task_request = right.clone();
    let left_owner = owner_id(suite.salt, "independent-left");
    let right_owner = owner_id(suite.salt, "independent-right");
    let left_task = tokio::spawn(async move {
        left_barrier.wait().await;
        claim_owned_delta_event_by_stable_event(
            &left_pool,
            &left_task_request,
            &left_owner,
            CLAIM_LEASE_SECONDS,
        )
        .await
    });
    let right_task = tokio::spawn(async move {
        right_barrier.wait().await;
        claim_owned_delta_event_by_stable_event(
            &right_pool,
            &right_task_request,
            &right_owner,
            CLAIM_LEASE_SECONDS,
        )
        .await
    });
    barrier.wait().await;
    let (left, right) = tokio::join!(left_task, right_task);
    let left = expect_claimed(
        left.expect("independent left task must not panic")
            .expect("independent left claim must succeed"),
        "independent left source aggregate must claim",
    );
    let right = expect_claimed(
        right
            .expect("independent right task must not panic")
            .expect("independent right claim must succeed"),
        "independent right source aggregate must claim",
    );
    assert_eq!(left.claim.event_id, left_request.event_id);
    assert_eq!(right.claim.event_id, right_request.event_id);
    assert!(release_owned_delta_event(pool, &left.lease)
        .await
        .expect("left source capability releases exactly"));
    assert!(release_owned_delta_event(pool, &right.lease)
        .await
        .expect("right source capability releases exactly"));
    assert_lane_inactive(pool, left_request, left.lease.ownership_epoch()).await;
    assert_lane_inactive(pool, right_request, right.lease.ownership_epoch()).await;
}

async fn wait_until_due(pool: &MySqlPool, request: &DeltaEventAppendRequest) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let due: i64 = sqlx::query_scalar(
                "SELECT CAST(next_attempt_at IS NULL OR next_attempt_at <= UTC_TIMESTAMP(6) AS SIGNED) \
                 FROM authorization_delta_event WHERE tenant_id = ? AND aggregate_type = ? \
                   AND aggregate_id = ? AND event_id = ?",
            )
            .bind(request.tenant_id)
            .bind(&request.aggregate_type)
            .bind(request.aggregate_id)
            .bind(&request.event_id)
            .fetch_one(pool)
            .await
            .expect("read the exact source event's retry deadline");
            if due == 1 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("zero-backoff source event must become due within the stored precision");
}

async fn wait_for_exact_completion(
    pool: &MySqlPool,
    requests: &[DeltaEventAppendRequest],
) -> Result<()> {
    let started = Instant::now();
    let mut complete = vec![false; requests.len()];
    while complete.iter().any(|is_complete| !*is_complete) {
        if started.elapsed() >= COMPLETION_TIMEOUT {
            let pending = requests
                .iter()
                .zip(&complete)
                .filter_map(|(request, complete)| (!complete).then_some(&request.event_id))
                .collect::<Vec<_>>();
            return Err(anyhow!(
                "exact owned completion deadline; unresolved events={pending:?}"
            ));
        }
        for (index, request) in requests.iter().enumerate() {
            if !complete[index] {
                complete[index] = load_owned_delta_completion(pool, request)
                    .await
                    .with_context(|| format!("read exact completion for {}", request.event_id))?
                    .is_some();
            }
        }
        if complete.iter().any(|is_complete| !*is_complete) {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
    Ok(())
}

async fn run_contract() -> Result<()> {
    let pool = required_pool().await;
    let suite = SuiteFixture::new(
        "projection-owned-source-contract",
        &[TenantRole::AllowActive, TenantRole::AllowActive],
    );
    install_origin_region(format!("projection-owned-{:x}", suite.salt))
        .expect("fixture source invalidation origin must be installed before source writes");
    seed_all_tenants(&pool, &suite)
        .await
        .context("seed source-owned tenant and RuleSet rows")?;

    let main = suite.tenants[0];
    let independent = suite.tenants[1];
    publish_card_manifest(
        &pool,
        main.tenant_id,
        main.card_id,
        main.rule_set_id,
        main.user_id,
        vec![source_entry("read", 100)],
        ("projection-owned-main-baseline", suite.salt),
    )
    .await;
    publish_card_manifest(
        &pool,
        independent.tenant_id,
        independent.card_id,
        independent.rule_set_id,
        independent.user_id,
        vec![source_entry("read", 100)],
        ("projection-owned-independent-baseline", suite.salt),
    )
    .await;
    for tenant in [main, independent] {
        let evidence = load_published_card_grant_evidence(&pool, &tenant.card_scope())
            .await
            .expect("real source publication must satisfy the strict card reader");
        assert_eq!(evidence.gate.status, PublishedEvidenceGateStatus::Ready);
    }

    let service = RuleSetWriteService::new(Arc::new(SqlxRuleSetRepository::new(pool.clone())));
    let main_entry_id: i64 = sqlx::query_scalar(
        "SELECT entry_id FROM rule_set_entry WHERE rule_set_id = ? AND enabled = 1 \
         ORDER BY entry_id DESC LIMIT 1",
    )
    .bind(main.rule_set_id)
    .fetch_one(&pool)
    .await
    .context("read the actual enabled source entry id")?;
    let independent_entry_id: i64 = sqlx::query_scalar(
        "SELECT entry_id FROM rule_set_entry WHERE rule_set_id = ? AND enabled = 1 \
         ORDER BY entry_id DESC LIMIT 1",
    )
    .bind(independent.rule_set_id)
    .fetch_one(&pool)
    .await
    .context("read the independent actual source entry id")?;

    // Three committed source mutations produce two ordered receipts on one grant
    // chain and one independent receipt on another real RuleSet aggregate.
    let main_first_operation = source_update(
        &service,
        &suite,
        main,
        main_entry_id,
        "main-update-create",
        "create",
    )
    .await;
    let main_second_operation = source_update(
        &service,
        &suite,
        main,
        main_entry_id,
        "main-update-update",
        "update",
    )
    .await;
    let independent_operation = source_update(
        &service,
        &suite,
        independent,
        independent_entry_id,
        "independent-update-create",
        "create",
    )
    .await;

    let main_first = load_source_receipts(&pool, main.tenant_id, &main_first_operation)
        .await?
        .into_iter()
        .collect::<Vec<_>>();
    let main_second = load_source_receipts(&pool, main.tenant_id, &main_second_operation)
        .await?
        .into_iter()
        .collect::<Vec<_>>();
    let independent_receipts =
        load_source_receipts(&pool, independent.tenant_id, &independent_operation).await?;
    assert_eq!(
        main_first.len(),
        1,
        "one bound source entry yields one delta receipt"
    );
    assert_eq!(
        main_second.len(),
        1,
        "one bound source entry yields one successor receipt"
    );
    assert_eq!(
        independent_receipts.len(),
        1,
        "independent source write yields one receipt"
    );
    let first = &main_first[0];
    let second = &main_second[0];
    let independent_request = &independent_receipts[0];
    for request in [first, second, independent_request] {
        assert_eq!(request.event_type, DeltaEventType::Update);
        assert_eq!(
            request.card_id,
            Some(if request.tenant_id == main.tenant_id {
                main.card_id
            } else {
                independent.card_id
            })
        );
        assert_eq!(request.aggregate_type, "RULE_SET");
        assert!(request.invalidates_published_evidence);
        assert!(request.source_generation > 0);
        assert!(request.compiler_version == astral_types::AUTHORIZATION_COMPILER_VERSION);
        assert!(load_owned_delta_completion(&pool, request)
            .await
            .context("read pre-publication completion proof")?
            .is_none());
    }
    assert_eq!(
        first.grant_id, second.grant_id,
        "UPDATE receipts retain source grant identity"
    );
    assert_eq!(first.target_version, second.base_version);
    assert!(first.source_generation < second.source_generation);

    // Source freshness is fail-closed until every invalidating source receipt has
    // a historical exact completion proof; old Ready evidence is not a fallback.
    let pending = load_published_card_grant_evidence(&pool, &main.card_scope())
        .await
        .expect_err("unpublished source UPDATE must gate old card evidence");
    assert!(matches!(
        pending,
        AuthorizationEvidenceError::NotReady(ref message)
            if message.contains("source_freshness_pending")
    ));
    assert_eq!(
        pending.as_gate_status(),
        PublishedEvidenceGateStatus::Pending
    );

    // A forged operation binding is rejected before claim counters or lane state move.
    let first_before_mismatch = event_state(&pool, first).await;
    let first_lane_before_mismatch = lane_state(&pool, first).await;
    let mut forged = first.clone();
    forged.operation_id.push_str("-forged");
    let mismatch = claim_owned_delta_event_by_stable_event(
        &pool,
        &forged,
        &owner_id(suite.salt, "receipt-mismatch"),
        CLAIM_LEASE_SECONDS,
    )
    .await
    .expect_err("receipt identity drift must fail closed");
    assert!(mismatch
        .to_string()
        .contains("grant_repository.owned_event_payload_mismatch"));
    assert_eq!(event_state(&pool, first).await, first_before_mismatch);
    assert_eq!(lane_state(&pool, first).await, first_lane_before_mismatch);

    // Exact same-event contenders cannot install two owned capabilities.
    assert_same_receipt_claim_race(&pool, &suite, first).await;

    // Distinct source aggregates can hold independent capabilities concurrently.
    assert_independent_aggregate_claims(&pool, &suite, first, independent_request).await;

    // A real successor from the same source grant stays Busy until its predecessor
    // is terminal; this refusal consumes no claim attempt and does not alter the lane.
    let second_before = event_state(&pool, second).await;
    let second_lane_before = lane_state(&pool, second).await;
    let successor_busy = claim_owned_delta_event_by_stable_event(
        &pool,
        second,
        &owner_id(suite.salt, "successor-before-predecessor"),
        CLAIM_LEASE_SECONDS,
    )
    .await
    .context("successor claim must return an explicit protocol outcome")?;
    assert!(matches!(
        successor_busy,
        OwnedStableEventOutcome::Busy { .. }
    ));
    assert_eq!(event_state(&pool, second).await, second_before);
    assert_eq!(lane_state(&pool, second).await, second_lane_before);

    // The database recovery scan must select the real earliest pending receipt.
    let queue_claim = claim_next_owned_delta_event(
        &pool,
        DeltaEventClaimScope {
            tenant_id: main.tenant_id,
            card_id: Some(main.card_id),
        },
        &owner_id(suite.salt, "queue-claim"),
        CLAIM_LEASE_SECONDS,
    )
    .await
    .context("owned queue claim must reach its durable scan")?
    .expect("the source-written predecessor must be available to the worker");
    assert_eq!(queue_claim.claim.event_id, first.event_id);
    assert!(release_owned_delta_event(&pool, &queue_claim.lease)
        .await
        .context("release queue-scan capability")?);

    // Exercise idempotent begin/release and one charged failure on the source
    // receipt before allowing its exact worker-owned retry.
    let first_claim = expect_claimed(
        claim_owned_delta_event_by_stable_event(
            &pool,
            first,
            &owner_id(suite.salt, "begin-and-release"),
            CLAIM_LEASE_SECONDS,
        )
        .await
        .context("claim exact source predecessor")?,
        "source predecessor must claim",
    );
    assert_eq!(
        begin_owned_delta_execution(&pool, &first_claim.lease).await?,
        0
    );
    assert_eq!(
        begin_owned_delta_execution(&pool, &first_claim.lease).await?,
        0
    );
    assert!(release_owned_delta_event(&pool, &first_claim.lease).await?);
    assert!(!release_owned_delta_event(&pool, &first_claim.lease).await?);
    assert_lane_inactive(&pool, first, first_claim.lease.ownership_epoch()).await;

    let failed_claim = expect_claimed(
        claim_owned_delta_event_by_stable_event(
            &pool,
            first,
            &owner_id(suite.salt, "charged-failure"),
            CLAIM_LEASE_SECONDS,
        )
        .await
        .context("reclaim exact source predecessor")?,
        "released source predecessor must be reclaimable",
    );
    assert_eq!(
        begin_owned_delta_execution(&pool, &failed_claim.lease).await?,
        0
    );
    assert!(
        fail_owned_delta_event(
            &pool,
            &failed_claim.lease,
            "owned.source_fixture.transient_failure",
            0,
            true,
        )
        .await?
    );
    assert!(
        !fail_owned_delta_event(
            &pool,
            &failed_claim.lease,
            "owned.source_fixture.stale_failure",
            0,
            true,
        )
        .await?
    );
    let failed_state = event_state(&pool, first).await;
    assert_eq!(failed_state.status, "PENDING");
    assert_eq!(failed_state.execution_failures, 1);
    assert_eq!(failed_state.execution_attempts, 2);
    assert_lane_inactive(&pool, first, failed_claim.lease.ownership_epoch()).await;

    wait_until_due(&pool, first).await;
    let retry_claim = expect_claimed(
        claim_owned_delta_event_by_stable_event(
            &pool,
            first,
            &owner_id(suite.salt, "retry-after-proven-failure"),
            CLAIM_LEASE_SECONDS,
        )
        .await
        .context("claim source receipt after its recorded failure backoff is due")?,
        "source receipt with a proven failure must remain retryable",
    );
    assert_eq!(retry_claim.lease.execution_failures(), 1);
    assert_eq!(
        begin_owned_delta_execution(&pool, &retry_claim.lease).await?,
        1
    );
    assert_eq!(
        begin_owned_delta_execution(&pool, &retry_claim.lease).await?,
        1
    );
    assert!(release_owned_delta_event(&pool, &retry_claim.lease).await?);
    assert_lane_inactive(&pool, first, retry_claim.lease.ownership_epoch()).await;

    // Only the production WorkerOwned projector may finish the real source rows.
    let projector = start_authorization_projector_with_runtime(
        Arc::new(astral_trustgraph::service::authorization_projector::SqlxAuthorizationProjectorRuntime::new(
            pool.clone(),
        )),
        AuthorizationProjectorConfig {
            tenants: vec![main.tenant_id, independent.tenant_id],
            poll_interval_secs: 1,
            ..AuthorizationProjectorConfig::default()
        },
    );
    wait_for_exact_completion(
        &pool,
        &[first.clone(), second.clone(), independent_request.clone()],
    )
    .await?;
    let shutdown = tokio::time::timeout(
        Duration::from_secs(12),
        shutdown_authorization_projector(projector, Duration::from_secs(10)),
    )
    .await
    .context("owned projector shutdown outer timeout")?;
    let summary = shutdown
        .summary
        .map_err(|error| anyhow!("owned projector shutdown failed: {error}"))?;
    assert_eq!(summary.events_publication_unknown, 0);
    assert_eq!(summary.events_quarantine_unknown, 0);
    assert_eq!(summary.events_lease_lost, 0);

    for request in [first, second, independent_request] {
        assert!(load_owned_delta_completion(&pool, request)
            .await
            .context("verify historical exact source completion")?
            .is_some());
        let state = event_state(&pool, request).await;
        assert_eq!(state.status, "SUCCEEDED");
        assert!(state.lease_owner.is_none());
        assert!(state.lease_token_hash.is_none());
        assert!(state.lease_expires_at.is_none());
        if let Some(lane) = lane_state(&pool, request).await {
            assert_lane_inactive(&pool, request, lane.execution_epoch).await;
        }
    }
    let main_evidence = load_published_card_grant_evidence(&pool, &main.card_scope())
        .await
        .expect("both ordered source updates must restore strict card evidence");
    assert_eq!(
        main_evidence.gate.status,
        PublishedEvidenceGateStatus::Ready
    );
    assert_eq!(main_evidence.effective_grants.len(), 1);
    assert!(main_evidence
        .effective_grants
        .iter()
        .any(|grant| grant.action == "update"));
    assert!(!main_evidence
        .effective_grants
        .iter()
        .any(|grant| grant.action == "create"));
    let independent_evidence = load_published_card_grant_evidence(&pool, &independent.card_scope())
        .await
        .expect("independent source update must also pass strict evidence reading");
    assert_eq!(
        independent_evidence.gate.status,
        PublishedEvidenceGateStatus::Ready
    );

    cleanup_suite_rows(&pool, &suite)
        .await
        .context("cleanup after exact source completion proofs and owner shutdown")?;
    pool.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real MySQL; run-owned loopback:3308 clone required; RUST_INTEGRATION_REQUIRED=1"]
async fn worker_owned_projection_sql_contract() {
    tokio::time::timeout(TEST_DEADLINE, run_contract())
        .await
        .expect("projection-owned SQL contract exceeded its 180-second deadline")
        .expect("source-backed WorkerOwned contract must complete with durable proof");
}
