//! Source-backed real-MySQL integration tests for V6 authorization publication.
//!
//! Every durable grant/delta in these ignored tests is created by the production
//! RuleSet writer and completed by its WorkerOwned projector. Test code never
//! stages/finalizes/publishes manifests or synthesizes grants, receipts, plans,
//! lease capabilities, or terminal queue states.
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
    claim_owned_delta_event_by_stable_event, load_authorization_archive_proof_in_tx,
    load_owned_delta_completion, load_published_card_grant_evidence,
    validate_projection_owned_schema, verify_authorization_archive_proof_in_tx,
    AuthorizationEvidenceError, DeltaEventAppendRequest, DeltaEventType, OwnedCompletionIdentity,
    OwnedStableEventOutcome, Sha256Digest,
};
use astral_mq::invalidation::install_origin_region;
use astral_trustgraph::{
    repository::{
        audit_log_repository::RuleSetMutationContext, rule_set_repository::SqlxRuleSetRepository,
    },
    service::{
        authorization_archive_worker::{
            shutdown_authorization_archive_worker, start_authorization_archive_worker,
            AuthorizationArchiveConfig,
        },
        authorization_projector::{
            shutdown_authorization_projector, start_authorization_projector_with_runtime,
            AuthorizationProjectorConfig, SqlxAuthorizationProjectorRuntime,
        },
        rule_set_write_service::{AddEntryRequest, RuleSetWriteService, UpdateEntryRequest},
    },
};
use astral_types::PublishedEvidenceGateStatus;
use sqlx::{
    mysql::{MySqlConnectOptions, MySqlPoolOptions},
    MySqlPool, Row,
};
use testsuite::{
    cleanup_suite_rows, publish_card_manifest, seed_all_tenants, SuiteFixture, SuiteTenant,
    TenantRole,
};
use time::PrimitiveDateTime;

const REQUIRED_MIGRATION_VERSION: i64 = 20261015000001;
const REQUIRED_DATABASE_PREFIX: &str = "astral_rehearsal_";
const ORIGIN_REGION: &str = "rq3-authorization-projection-native";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const CLAIM_LEASE_SECONDS: i64 = 90;
const COMPLETION_TIMEOUT: Duration = Duration::from_secs(120);
const ARCHIVE_TIMEOUT: Duration = Duration::from_secs(45);

#[derive(Debug, PartialEq, Eq, sqlx::FromRow)]
struct OwnedLaneState {
    execution_epoch: i64,
    lease_owner: String,
    lease_token_hash: Vec<u8>,
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
        .expect("database must use the isolated rehearsal prefix");
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
        "source-backed contract tests may only use loopback MySQL"
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
    assert_eq!(migration, Some(REQUIRED_MIGRATION_VERSION));
    pool
}

async fn fixture(pool: &MySqlPool, label: &str) -> SuiteFixture {
    let suite = SuiteFixture::new(label, &[TenantRole::AllowActive]);
    install_origin_region(ORIGIN_REGION)
        .expect("all source-backed RQ3 cases use the same frozen process origin");
    seed_all_tenants(pool, &suite)
        .await
        .expect("seed run-scoped tenant and RuleSet source rows");
    suite
}

fn tenant(suite: &SuiteFixture) -> SuiteTenant {
    suite.tenants[0]
}

fn operation_id(suite: &SuiteFixture, tag: &str) -> String {
    format!("rq3-{:032x}-{tag}", suite.salt)
}

fn add_entry(action: &str) -> AddEntryRequest {
    AddEntryRequest {
        effect: "ALLOW".to_owned(),
        resource_type: Some("learn_subject".to_owned()),
        resource_id: None,
        action_code: Some(action.to_owned()),
        condition_json: None,
        priority: 100,
    }
}

fn update_entry(action: &str) -> UpdateEntryRequest {
    UpdateEntryRequest {
        effect: "ALLOW".to_owned(),
        resource_type: Some("learn_subject".to_owned()),
        resource_id: None,
        action_code: Some(action.to_owned()),
        condition_json: None,
        priority: 100,
    }
}

async fn published_baseline(
    pool: &MySqlPool,
    suite: &SuiteFixture,
    tenant: SuiteTenant,
) -> testsuite::PublishedCardFixture {
    publish_card_manifest(
        pool,
        tenant.tenant_id,
        tenant.card_id,
        tenant.rule_set_id,
        tenant.user_id,
        vec![add_entry("read")],
        ("rq3-native-baseline", suite.salt),
    )
    .await
}

async fn mutate_entry(
    pool: &MySqlPool,
    suite: &SuiteFixture,
    tenant: SuiteTenant,
    entry_id: i64,
    tag: &str,
    action: &str,
) -> Result<String> {
    let operation_id = operation_id(suite, tag);
    let context = RuleSetMutationContext::user(tenant.user_id, Some(operation_id.as_str()))
        .context("construct stable RuleSet source mutation context")?;
    let service = RuleSetWriteService::new(Arc::new(SqlxRuleSetRepository::new(pool.clone())));
    service
        .update_entry(
            tenant.rule_set_id,
            entry_id,
            &update_entry(action),
            &context,
        )
        .await
        .context("commit source change through production RuleSetWriteService")?;
    Ok(operation_id)
}

async fn source_entry_id(pool: &MySqlPool, tenant: SuiteTenant) -> Result<i64> {
    sqlx::query_scalar(
        "SELECT entry_id FROM rule_set_entry WHERE rule_set_id = ? AND enabled = 1 \
         ORDER BY entry_id DESC LIMIT 1",
    )
    .bind(tenant.rule_set_id)
    .fetch_one(pool)
    .await
    .context("read the enabled entry created by the real baseline source writer")
}

/// Decode the complete immutable receipt emitted by the source transaction.
async fn source_receipts(
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
    .context("read immutable source-written receipts")?;
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
                other => return Err(anyhow!("unknown durable source event type {other}")),
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
                    "receipt escaped the requested source operation scope"
                ));
            }
            if request.compiler_version != astral_types::AUTHORIZATION_COMPILER_VERSION {
                return Err(anyhow!(
                    "source receipt does not use the current V6 compiler stamp"
                ));
            }
            OwnedCompletionIdentity::from_request(&request)
                .context("validate complete source-owned receipt identity")?;
            Ok(request)
        })
        .collect()
}

fn claimed(outcome: OwnedStableEventOutcome, reason: &str) -> astral_db::OwnedDeltaClaim {
    match outcome {
        OwnedStableEventOutcome::Claimed(claimed) => *claimed,
        other => panic!("{reason}; got {other:?}"),
    }
}

fn start_projector(
    pool: &MySqlPool,
    tenant_id: i64,
) -> astral_trustgraph::service::authorization_projector::AuthorizationProjectorHandle {
    let runtime = Arc::new(SqlxAuthorizationProjectorRuntime::new(pool.clone()));
    start_authorization_projector_with_runtime(
        runtime,
        AuthorizationProjectorConfig {
            tenants: vec![tenant_id],
            poll_interval_secs: 1,
            ..AuthorizationProjectorConfig::default()
        },
    )
}

async fn wait_for_exact_completion(
    pool: &MySqlPool,
    requests: &[DeltaEventAppendRequest],
) -> Result<()> {
    let started = Instant::now();
    let mut complete = vec![false; requests.len()];
    while complete.iter().any(|done| !*done) {
        if started.elapsed() >= COMPLETION_TIMEOUT {
            let unresolved = requests
                .iter()
                .zip(&complete)
                .filter_map(|(request, done)| (!done).then_some(&request.event_id))
                .collect::<Vec<_>>();
            return Err(anyhow!(
                "exact owned completion deadline; unresolved={unresolved:?}"
            ));
        }
        for (index, request) in requests.iter().enumerate() {
            if !complete[index] {
                complete[index] = load_owned_delta_completion(pool, request)
                    .await
                    .with_context(|| format!("load exact proof for {}", request.event_id))?
                    .is_some();
            }
        }
        if complete.iter().any(|done| !*done) {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
    Ok(())
}

async fn finish_projector(
    handle: astral_trustgraph::service::authorization_projector::AuthorizationProjectorHandle,
) -> Result<()> {
    let shutdown = tokio::time::timeout(
        Duration::from_secs(12),
        shutdown_authorization_projector(handle, Duration::from_secs(10)),
    )
    .await
    .context("projector shutdown outer timeout")?;
    let summary = shutdown
        .summary
        .map_err(|error| anyhow!("projector shutdown failed: {error}"))?;
    if summary.events_publication_unknown != 0
        || summary.events_quarantine_unknown != 0
        || summary.events_lease_lost != 0
    {
        return Err(anyhow!(
            "projector shutdown contains unresolved outcomes: {summary:?}"
        ));
    }
    Ok(())
}

async fn wait_for_archive_proof(
    pool: &MySqlPool,
    identity: &astral_db::ProjectionAggregateIdentity,
    generation: u64,
) -> Result<astral_db::AuthorizationArchiveManifestProof> {
    let started = Instant::now();
    loop {
        let mut tx = pool.begin().await.context("begin archive proof read")?;
        let proof = load_authorization_archive_proof_in_tx(&mut tx, identity, generation)
            .await
            .context("read archived generation proof")?;
        tx.rollback().await.context("finish archive proof read")?;
        if let Some(proof) = proof {
            astral_db::validate_terminal_archive_proof(&proof)
                .context("archive proof must be terminal with its durable timestamp")?;
            let mut tx = pool
                .begin()
                .await
                .context("begin archive chain verification")?;
            verify_authorization_archive_proof_in_tx(&mut tx, &proof)
                .await
                .context("re-verify the full archived parent chain")?;
            tx.rollback()
                .await
                .context("finish archive chain verification")?;
            return Ok(proof);
        }
        if started.elapsed() >= ARCHIVE_TIMEOUT {
            return Err(anyhow!(
                "archive worker did not produce the exact proof in time"
            ));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn cleanup(pool: &MySqlPool, suite: &SuiteFixture) {
    cleanup_suite_rows(pool, suite)
        .await
        .expect("remove fixture rows after proven worker shutdown and durable evidence checks");
}

/// Strict V6 evidence must stay PENDING when the scoped card has no current pointer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real MySQL; run-owned loopback:3308 clone required; RUST_INTEGRATION_REQUIRED=1"]
async fn published_evidence_reader_fails_closed_without_current_pointer() {
    let pool = required_pool().await;
    let suite = fixture(&pool, "rq3-no-current-pointer").await;
    let card = tenant(&suite);
    let error = load_published_card_grant_evidence(&pool, &card.card_scope())
        .await
        .expect_err("missing durable pointer must never manufacture an empty Ready set");
    assert!(matches!(
        &error,
        AuthorizationEvidenceError::NotReady(message)
            if message.contains("current_pointer_missing")
    ));
    assert_eq!(error.as_gate_status(), PublishedEvidenceGateStatus::Pending);
    cleanup(&pool, &suite).await;
    pool.close().await;
}

/// The supported helper publishes real RuleSet source, and a later source UPDATE
/// becomes a second V6 generation with strict evidence and exact completion proof.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real MySQL; run-owned loopback:3308 clone required; RUST_INTEGRATION_REQUIRED=1"]
async fn source_publication_and_owned_completion_yield_strict_card_evidence() {
    let pool = required_pool().await;
    let suite = fixture(&pool, "rq3-source-publication").await;
    let card = tenant(&suite);
    let first = published_baseline(&pool, &suite, card).await;
    assert_eq!(
        first.pointer.compiler_version,
        astral_types::AUTHORIZATION_COMPILER_VERSION
    );
    let baseline = load_published_card_grant_evidence(&pool, &card.card_scope())
        .await
        .expect("real baseline source publication must be strictly readable");
    assert_eq!(baseline.gate.status, PublishedEvidenceGateStatus::Ready);
    assert_eq!(baseline.effective_grants.len(), 1);
    assert_eq!(baseline.effective_grants[0].action, "read");

    let entry_id = source_entry_id(&pool, card).await.expect("real entry id");
    let operation = mutate_entry(&pool, &suite, card, entry_id, "generation-two", "create")
        .await
        .expect("content change must commit through the RuleSet writer");
    let receipts = source_receipts(&pool, card.tenant_id, &operation)
        .await
        .expect("read exact committed source receipt");
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].event_type, DeltaEventType::Update);
    assert_eq!(receipts[0].card_id, Some(card.card_id));
    assert_eq!(receipts[0].aggregate_type, "RULE_SET");
    assert!(receipts[0].invalidates_published_evidence);
    assert!(load_owned_delta_completion(&pool, &receipts[0])
        .await
        .expect("pre-publication exact completion read")
        .is_none());

    let owner = start_projector(&pool, card.tenant_id);
    wait_for_exact_completion(&pool, &receipts)
        .await
        .expect("WorkerOwned publication must close the exact source receipt");
    finish_projector(owner)
        .await
        .expect("owned projector must finish with a proved clean shutdown");
    assert!(load_owned_delta_completion(&pool, &receipts[0])
        .await
        .expect("post-publication exact completion read")
        .is_some());

    let current = load_published_card_grant_evidence(&pool, &card.card_scope())
        .await
        .expect("strict reader must accept the completed second generation");
    assert_eq!(current.gate.status, PublishedEvidenceGateStatus::Ready);
    assert_eq!(current.effective_grants.len(), 1);
    assert_eq!(current.effective_grants[0].action, "create");
    let ruleset = current
        .manifests
        .iter()
        .find(|manifest| manifest.aggregate_type == "RULE_SET")
        .expect("source publication must include its RuleSet aggregate");
    assert_eq!(ruleset.parent_manifest_id, Some(first.pointer.manifest_id));
    assert!(ruleset.generation > first.pointer.current_generation);
    cleanup(&pool, &suite).await;
    pool.close().await;
}

/// A real authorization-content UPDATE gates old evidence while its durable
/// receipt is pending, then exact WorkerOwned completion restores strict Ready.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real MySQL; run-owned loopback:3308 clone required; RUST_INTEGRATION_REQUIRED=1"]
async fn content_change_update_via_real_writers_gates_until_owned_completion() {
    let pool = required_pool().await;
    let suite = fixture(&pool, "rq3-source-freshness").await;
    let card = tenant(&suite);
    published_baseline(&pool, &suite, card).await;
    let entry_id = source_entry_id(&pool, card).await.expect("real entry id");
    let operation = mutate_entry(&pool, &suite, card, entry_id, "freshness-narrow", "create")
        .await
        .expect("real content update must commit");
    let receipts = source_receipts(&pool, card.tenant_id, &operation)
        .await
        .expect("read committed source receipt");
    assert_eq!(receipts.len(), 1);
    let request = &receipts[0];
    assert!(request.invalidates_published_evidence);
    assert!(request.revoke_fence > 0);
    assert!(load_owned_delta_completion(&pool, request)
        .await
        .expect("pending exact proof read")
        .is_none());

    let pending = load_published_card_grant_evidence(&pool, &card.card_scope())
        .await
        .expect_err("old evidence must not fallback across an unpublished narrowing UPDATE");
    assert!(matches!(
        &pending,
        AuthorizationEvidenceError::NotReady(message)
            if message.contains("source_freshness_pending")
    ));
    assert_eq!(
        pending.as_gate_status(),
        PublishedEvidenceGateStatus::Pending
    );
    let pending_snapshot =
        astral_db::load_card_scope_fence_snapshot(&pool, card.tenant_id, card.card_id)
            .await
            .expect("source pending flag must be visible to the card fence reader");
    assert!(pending_snapshot.card_source_pending);

    let owner = start_projector(&pool, card.tenant_id);
    wait_for_exact_completion(&pool, &receipts)
        .await
        .expect("owned worker must publish the exact narrowing source receipt");
    finish_projector(owner)
        .await
        .expect("projector shutdown must be clean and bounded");
    let ready = load_published_card_grant_evidence(&pool, &card.card_scope())
        .await
        .expect("strict V6 evidence must recover only after exact completion");
    assert_eq!(ready.gate.status, PublishedEvidenceGateStatus::Ready);
    assert_eq!(ready.effective_grants[0].action, "create");
    let recovered_snapshot =
        astral_db::load_card_scope_fence_snapshot(&pool, card.tenant_id, card.card_id)
            .await
            .expect("read recovered card fence");
    assert!(!recovered_snapshot.card_source_pending);
    cleanup(&pool, &suite).await;
    pool.close().await;
}

/// Two real updates create a same-grant predecessor chain. Exact WorkerOwned
/// claim refuses the successor without charging it; the production owner later
/// publishes both receipts in source order.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real MySQL; run-owned loopback:3308 clone required; RUST_INTEGRATION_REQUIRED=1"]
async fn claim_gate_defers_behind_unpublished_same_grant_source_sibling() {
    let pool = required_pool().await;
    let suite = fixture(&pool, "rq3-source-predecessor").await;
    let card = tenant(&suite);
    published_baseline(&pool, &suite, card).await;
    let entry_id = source_entry_id(&pool, card).await.expect("real entry id");
    let first_operation = mutate_entry(&pool, &suite, card, entry_id, "predecessor-one", "create")
        .await
        .expect("first RuleSet source update must commit");
    let second_operation = mutate_entry(&pool, &suite, card, entry_id, "predecessor-two", "update")
        .await
        .expect("successor RuleSet source update must commit");
    let first_batch = source_receipts(&pool, card.tenant_id, &first_operation)
        .await
        .expect("read predecessor receipt");
    let second_batch = source_receipts(&pool, card.tenant_id, &second_operation)
        .await
        .expect("read successor receipt");
    assert_eq!(first_batch.len(), 1);
    assert_eq!(second_batch.len(), 1);
    let predecessor = &first_batch[0];
    let successor = &second_batch[0];
    assert_eq!(predecessor.grant_id, successor.grant_id);
    assert_eq!(predecessor.target_version, successor.base_version);
    assert!(predecessor.source_generation < successor.source_generation);

    let state_before = sqlx::query_as::<
        _,
        (
            String,
            Option<String>,
            Option<Vec<u8>>,
            Option<PrimitiveDateTime>,
        ),
    >(
        "SELECT status, lease_owner, lease_token_hash, lease_expires_at \
         FROM authorization_delta_event WHERE tenant_id = ? AND aggregate_type = ? \
           AND aggregate_id = ? AND event_id = ?",
    )
    .bind(successor.tenant_id)
    .bind(&successor.aggregate_type)
    .bind(successor.aggregate_id)
    .bind(&successor.event_id)
    .fetch_one(&pool)
    .await
    .expect("read exact source successor state before its refused claim");
    let attempts_before: i64 = sqlx::query_scalar(
        "SELECT attempts FROM authorization_delta_event WHERE tenant_id = ? \
         AND aggregate_type = ? AND aggregate_id = ? AND event_id = ?",
    )
    .bind(successor.tenant_id)
    .bind(&successor.aggregate_type)
    .bind(successor.aggregate_id)
    .bind(&successor.event_id)
    .fetch_one(&pool)
    .await
    .expect("read the source successor's queue-attempt count");
    let lane_before = sqlx::query_as::<_, OwnedLaneState>(
        "SELECT execution_epoch, lease_owner, lease_token_hash, active_delta_event_id, \
             active_delta_token_hash FROM authorization_projection_partition_lease \
             WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ?",
    )
    .bind(successor.tenant_id)
    .bind(&successor.aggregate_type)
    .bind(successor.aggregate_id)
    .fetch_optional(&pool)
    .await
    .expect("read the durable RuleSet lane before probing the blocked successor");
    let refused = claim_owned_delta_event_by_stable_event(
        &pool,
        successor,
        &operation_id(&suite, "successor-probe"),
        CLAIM_LEASE_SECONDS,
    )
    .await
    .expect("exact successor probe must return its protocol outcome");
    assert!(matches!(refused, OwnedStableEventOutcome::Busy { .. }));
    let state_after = sqlx::query_as::<
        _,
        (
            String,
            Option<String>,
            Option<Vec<u8>>,
            Option<PrimitiveDateTime>,
        ),
    >(
        "SELECT status, lease_owner, lease_token_hash, lease_expires_at \
         FROM authorization_delta_event WHERE tenant_id = ? AND aggregate_type = ? \
           AND aggregate_id = ? AND event_id = ?",
    )
    .bind(successor.tenant_id)
    .bind(&successor.aggregate_type)
    .bind(successor.aggregate_id)
    .bind(&successor.event_id)
    .fetch_one(&pool)
    .await
    .expect("read the exact source successor after its blocked claim");
    assert_eq!(state_after, state_before);
    let attempts_after: i64 = sqlx::query_scalar(
        "SELECT attempts FROM authorization_delta_event WHERE tenant_id = ? \
         AND aggregate_type = ? AND aggregate_id = ? AND event_id = ?",
    )
    .bind(successor.tenant_id)
    .bind(&successor.aggregate_type)
    .bind(successor.aggregate_id)
    .bind(&successor.event_id)
    .fetch_one(&pool)
    .await
    .expect("read source successor queue-attempt count after probe");
    assert_eq!(
        attempts_after, attempts_before,
        "refusal must not consume an attempt"
    );
    let lane_after = sqlx::query_as::<_, OwnedLaneState>(
        "SELECT execution_epoch, lease_owner, lease_token_hash, active_delta_event_id, \
             active_delta_token_hash FROM authorization_projection_partition_lease \
             WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ?",
    )
    .bind(successor.tenant_id)
    .bind(&successor.aggregate_type)
    .bind(successor.aggregate_id)
    .fetch_optional(&pool)
    .await
    .expect("read the durable RuleSet lane after probing the blocked successor");
    assert_eq!(lane_after, lane_before);

    let claimed_predecessor = claimed(
        claim_owned_delta_event_by_stable_event(
            &pool,
            predecessor,
            &operation_id(&suite, "predecessor-probe"),
            CLAIM_LEASE_SECONDS,
        )
        .await
        .expect("exact source predecessor claim"),
        "real source predecessor must claim ahead of its successor",
    );
    assert_eq!(claimed_predecessor.claim.event_id, predecessor.event_id);
    assert!(
        astral_db::release_owned_delta_event(&pool, &claimed_predecessor.lease)
            .await
            .expect("release the exact source-owned capability")
    );
    let still_refused = claim_owned_delta_event_by_stable_event(
        &pool,
        successor,
        &operation_id(&suite, "successor-reprobe"),
        CLAIM_LEASE_SECONDS,
    )
    .await
    .expect("successor must remain gated while predecessor is nonterminal");
    assert!(matches!(
        still_refused,
        OwnedStableEventOutcome::Busy { .. }
    ));
    let attempts_after_second_probe: i64 = sqlx::query_scalar(
        "SELECT attempts FROM authorization_delta_event WHERE tenant_id = ? \
         AND aggregate_type = ? AND aggregate_id = ? AND event_id = ?",
    )
    .bind(successor.tenant_id)
    .bind(&successor.aggregate_type)
    .bind(successor.aggregate_id)
    .bind(&successor.event_id)
    .fetch_one(&pool)
    .await
    .expect("read source successor attempts after the second refused claim");
    assert_eq!(attempts_after_second_probe, attempts_before);

    let owner = start_projector(&pool, card.tenant_id);
    wait_for_exact_completion(&pool, &[predecessor.clone(), successor.clone()])
        .await
        .expect("production WorkerOwned projector must complete the source chain");
    finish_projector(owner)
        .await
        .expect("projector shutdown must have no unknown/lease-lost outcome");
    for request in [predecessor, successor] {
        assert!(load_owned_delta_completion(&pool, request)
            .await
            .expect("read exact predecessor/successor proof")
            .is_some());
        let status: String = sqlx::query_scalar(
            "SELECT status FROM authorization_delta_event WHERE tenant_id = ? \
             AND aggregate_type = ? AND aggregate_id = ? AND event_id = ?",
        )
        .bind(request.tenant_id)
        .bind(&request.aggregate_type)
        .bind(request.aggregate_id)
        .bind(&request.event_id)
        .fetch_one(&pool)
        .await
        .expect("read terminal status of the exact source event");
        assert_eq!(status, "SUCCEEDED");
    }
    let evidence = load_published_card_grant_evidence(&pool, &card.card_scope())
        .await
        .expect("published end state must pass the strict V6 reader");
    assert_eq!(evidence.gate.status, PublishedEvidenceGateStatus::Ready);
    assert_eq!(evidence.effective_grants[0].action, "update");
    cleanup(&pool, &suite).await;
    pool.close().await;
}

/// Publishing a second real source generation creates archive work. The archive
/// worker—not a test-built intent/proof—must verify and persist the sealed parent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real MySQL; run-owned loopback:3308 clone required; RUST_INTEGRATION_REQUIRED=1"]
async fn source_publication_archive_worker_records_parent_proof() {
    let pool = required_pool().await;
    let suite = fixture(&pool, "rq3-native-archive").await;
    let card = tenant(&suite);
    let first = published_baseline(&pool, &suite, card).await;
    let entry_id = source_entry_id(&pool, card).await.expect("real entry id");
    let operation = mutate_entry(&pool, &suite, card, entry_id, "archive-successor", "create")
        .await
        .expect("second source generation must commit");
    let receipts = source_receipts(&pool, card.tenant_id, &operation)
        .await
        .expect("read source contribution receipt");
    assert_eq!(receipts.len(), 1);
    let owner = start_projector(&pool, card.tenant_id);
    wait_for_exact_completion(&pool, &receipts)
        .await
        .expect("owned projector must publish second source generation");
    finish_projector(owner)
        .await
        .expect("owned projector must stop cleanly before archive worker starts");

    let archive = start_authorization_archive_worker(
        pool.clone(),
        AuthorizationArchiveConfig {
            tenants: vec![card.tenant_id],
            poll_interval_secs: 1,
            claim_lease_seconds: 90,
        },
    )
    .expect("valid bounded archive worker config");
    let proof = wait_for_archive_proof(
        &pool,
        &first.pointer.identity,
        first.pointer.current_generation,
    )
    .await
    .expect("archive worker must persist and verify the exact parent chain");
    assert_eq!(proof.identity, first.pointer.identity);
    assert_eq!(proof.archived_manifest_id, first.pointer.manifest_id);
    assert_eq!(proof.archived_generation, first.pointer.current_generation);
    assert_eq!(proof.event_id, first.pointer.event_id);
    assert_eq!(proof.operation_id, first.pointer.operation_id);

    let shutdown = tokio::time::timeout(
        Duration::from_secs(12),
        shutdown_authorization_archive_worker(archive, Duration::from_secs(10)),
    )
    .await
    .expect("[UNKNOWN] archive worker shutdown outer timeout; reconcile before cleanup");
    let summary = shutdown
        .summary
        .expect("[UNKNOWN] archive worker shutdown failed; reconcile before cleanup");
    assert!(summary.intents_claimed >= 1);
    assert!(summary.intents_archived + summary.intents_resumed >= 1);
    assert_eq!(summary.intents_unknown, 0);

    let outbox: (String, Option<PrimitiveDateTime>) = sqlx::query_as(
        "SELECT status, archived_at FROM authorization_archive_outbox \
         WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ? AND generation = ? \
           AND event_id = ?",
    )
    .bind(card.tenant_id)
    .bind(&first.pointer.identity.aggregate_type)
    .bind(first.pointer.identity.aggregate_id)
    .bind(i64::try_from(first.pointer.current_generation).expect("generation fits SQL bigint"))
    .bind(&first.pointer.event_id)
    .fetch_one(&pool)
    .await
    .expect("read worker-owned archive outbox completion after clean shutdown");
    assert_eq!(outbox.0, "SUCCEEDED");
    assert!(outbox.1.is_some());
    cleanup(&pool, &suite).await;
    pool.close().await;
}
