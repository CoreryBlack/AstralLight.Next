#![cfg(test)]
//! Source-backed real-MySQL tests for partition scheduling and WorkerOwned claims.
//!
//! These ignored tests require an already-migrated, run-owned isolated MySQL
//! database. Baseline publication uses a bounded fixture-owned projector that
//! is joined before each claim exercise. Tests do not run migrations. Delta
//! receipts are created only through the MANUAL RuleSet source writer; the
//! `OwnedCompletionIdentity` is checked before a partition claim.
//!
//! Required environment: `RUST_INTEGRATION_REQUIRED=1`, `TEST_USE_EXISTING=1`,
//! `ASTRAL_MIGRATION_ENV=isolated`, `ASTRAL_TEST_DATABASE_NAME`, and `DATABASE_URL`.

use std::{collections::HashSet, env, str::FromStr, sync::Arc, time::Duration};

use astral_db::{
    acquire_partition_lease, begin_owned_delta_execution,
    claim_next_owned_delta_event_in_partition, discover_claimable_partitions,
    fail_owned_delta_event, release_owned_delta_event, release_partition_lease,
    renew_partition_lease, validate_projection_owned_schema, DeltaEventAppendRequest,
    DeltaEventClaimScope, DeltaEventType, OwnedCompletionIdentity, OwnedDeltaClaim,
    PartitionLeaseHandle, ProjectionAggregateIdentity, Sha256Digest,
};
use astral_trustgraph::{
    repository::{
        audit_log_repository::RuleSetMutationContext, rule_set_repository::SqlxRuleSetRepository,
    },
    service::{
        authorization_projector::{BACKOFF_CAP_SECS, MAX_EVENT_ATTEMPTS},
        rule_set_write_service::{AddEntryRequest, RuleSetWriteService, UpdateEntryRequest},
    },
};
use astral_types::SYSTEM_ACTOR_ID;
use sqlx::{mysql::MySqlConnectOptions, FromRow, MySqlPool, Row};
use testsuite::{
    cleanup_suite_rows, publish_card_manifest, seed_all_tenants, SuiteFixture, SuiteTenant,
    TenantRole,
};
use time::PrimitiveDateTime;
use tokio::sync::Barrier;

const REQUIRED_DATABASE_PREFIX: &str = "astral_rehearsal_";
const REQUIRED_MIGRATIONS: &[i64] = &[20260921000001, 20261015000001];
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const CLAIM_LEASE_SECONDS: i64 = 120;
const ATTEMPT_BUDGET_EXHAUSTED_MARKER: &str = "code=auth_projector.attempt_budget_exhausted";

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
        "ASTRAL_MIGRATION_ENV=isolated is mandatory"
    );

    let expected_database = env::var("ASTRAL_TEST_DATABASE_NAME")
        .expect("ASTRAL_TEST_DATABASE_NAME must name the approved clone");
    let suffix = expected_database
        .strip_prefix(REQUIRED_DATABASE_PREFIX)
        .expect("database must use the run-scoped astral_rehearsal_ prefix");
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
        "DATABASE_URL query parameters and fragments are not allowed"
    );
    let options = MySqlConnectOptions::from_str(&url).expect("DATABASE_URL must parse");
    assert!(
        matches!(options.get_host(), "localhost" | "127.0.0.1" | "::1"),
        "partition integration tests may only use loopback MySQL"
    );
    assert_eq!(
        options.get_port(),
        3308,
        "expected isolated MySQL port 3308"
    );
    assert!(
        options.get_socket().is_none(),
        "Unix socket URLs are not accepted"
    );
    assert_eq!(
        options.get_database(),
        Some(expected_database.as_str()),
        "DATABASE_URL must select exactly ASTRAL_TEST_DATABASE_NAME"
    );

    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .max_connections(8)
        .acquire_timeout(CONNECT_TIMEOUT)
        .connect_with(options)
        .await
        .expect("required isolated MySQL connection must succeed");
    validate_projection_owned_schema(&pool)
        .await
        .expect("owned execution schema and existing rows must validate read-only");
    let applied: Vec<i64> = sqlx::query_scalar(
        "SELECT version FROM _sqlx_migrations WHERE success = TRUE ORDER BY version",
    )
    .fetch_all(&pool)
    .await
    .expect("read already-applied migration markers");
    for required in REQUIRED_MIGRATIONS {
        assert!(
            applied.contains(required),
            "required migration {required} must already be applied; tests never migrate"
        );
    }
    pool
}

fn identity(tenant: i64, kind: &str, id: i64) -> ProjectionAggregateIdentity {
    ProjectionAggregateIdentity::new(tenant, kind, id).expect("valid partition identity")
}

fn worker_id(salt: u128, tag: &str) -> String {
    format!("rq4-worker-{salt:032x}-{tag}")
}

fn operation_id(suite: &SuiteFixture, tag: &str) -> String {
    format!("rq4-{:032x}-{tag}", suite.salt)
}

async fn lease_test_partition(
    pool: &MySqlPool,
    label: &str,
) -> (SuiteFixture, ProjectionAggregateIdentity) {
    let suite = SuiteFixture::new(label, &[TenantRole::AllowActive]);
    seed_all_tenants(pool, &suite)
        .await
        .expect("seed run-scoped source ownership for the lease-only partition");
    let tenant = suite.tenants[0];
    (suite, identity(tenant.tenant_id, "CARD", tenant.card_id))
}

async fn assert_partition_identity_unused(
    pool: &MySqlPool,
    partition: &ProjectionAggregateIdentity,
) {
    let lease_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM authorization_projection_partition_lease \
         WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ?",
    )
    .bind(partition.tenant_id)
    .bind(&partition.aggregate_type)
    .bind(partition.aggregate_id)
    .fetch_one(pool)
    .await
    .expect("preflight partition lease identity");
    let event_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM authorization_delta_event \
         WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ?",
    )
    .bind(partition.tenant_id)
    .bind(&partition.aggregate_type)
    .bind(partition.aggregate_id)
    .fetch_one(pool)
    .await
    .expect("preflight partition delta identity");
    let audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log \
         WHERE event_type = 'AUTHZ_PARTITION_LEASE' AND tenant_id = ? \
           AND resource = 'authorization_projection_partition_lease' \
           AND JSON_UNQUOTE(JSON_EXTRACT(detail, '$.aggregateType')) = ? \
           AND CAST(JSON_UNQUOTE(JSON_EXTRACT(detail, '$.aggregateId')) AS SIGNED) = ?",
    )
    .bind(partition.tenant_id)
    .bind(&partition.aggregate_type)
    .bind(partition.aggregate_id)
    .fetch_one(pool)
    .await
    .expect("preflight partition lease audit identity");
    assert_eq!(lease_count, 0, "run-scoped lease identity already exists");
    assert_eq!(event_count, 0, "run-scoped delta identity already exists");
    assert_eq!(
        audit_count, 0,
        "run-scoped lease audit identity already exists"
    );
}

async fn cleanup_partition_identity(pool: &MySqlPool, partition: &ProjectionAggregateIdentity) {
    sqlx::query(
        "DELETE FROM authorization_projection_partition_lease \
         WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ?",
    )
    .bind(partition.tenant_id)
    .bind(&partition.aggregate_type)
    .bind(partition.aggregate_id)
    .execute(pool)
    .await
    .expect("cleanup this run-owned partition lease");
    sqlx::query(
        "DELETE FROM audit_log \
         WHERE event_type = 'AUTHZ_PARTITION_LEASE' AND tenant_id = ? \
           AND resource = 'authorization_projection_partition_lease' \
           AND JSON_UNQUOTE(JSON_EXTRACT(detail, '$.aggregateType')) = ? \
           AND CAST(JSON_UNQUOTE(JSON_EXTRACT(detail, '$.aggregateId')) AS SIGNED) = ?",
    )
    .bind(partition.tenant_id)
    .bind(&partition.aggregate_type)
    .bind(partition.aggregate_id)
    .execute(pool)
    .await
    .expect("cleanup only this run-owned partition lease audit");
}

async fn partition_lease_audit_actions(
    pool: &MySqlPool,
    partition: &ProjectionAggregateIdentity,
) -> Vec<String> {
    sqlx::query(
        "SELECT action FROM audit_log \
         WHERE event_type = 'AUTHZ_PARTITION_LEASE' \
           AND tenant_id = ? \
           AND resource = 'authorization_projection_partition_lease' \
           AND JSON_UNQUOTE(JSON_EXTRACT(detail, '$.aggregateType')) = ? \
           AND CAST(JSON_UNQUOTE(JSON_EXTRACT(detail, '$.aggregateId')) AS SIGNED) = ? \
         ORDER BY id",
    )
    .bind(partition.tenant_id)
    .bind(&partition.aggregate_type)
    .bind(partition.aggregate_id)
    .fetch_all(pool)
    .await
    .expect("read partition lease audit")
    .into_iter()
    .map(|row| row.get("action"))
    .collect()
}

async fn partition_lease_audit_rows(
    pool: &MySqlPool,
    partition: &ProjectionAggregateIdentity,
) -> Vec<(i64, String, String, String)> {
    sqlx::query(
        "SELECT user_id, decision, request_id, detail FROM audit_log \
         WHERE event_type = 'AUTHZ_PARTITION_LEASE' \
           AND tenant_id = ? \
           AND resource = 'authorization_projection_partition_lease' \
           AND JSON_UNQUOTE(JSON_EXTRACT(detail, '$.aggregateType')) = ? \
           AND CAST(JSON_UNQUOTE(JSON_EXTRACT(detail, '$.aggregateId')) AS SIGNED) = ? \
         ORDER BY id",
    )
    .bind(partition.tenant_id)
    .bind(&partition.aggregate_type)
    .bind(partition.aggregate_id)
    .fetch_all(pool)
    .await
    .expect("read partition lease audit rows")
    .into_iter()
    .map(|row| {
        (
            row.get("user_id"),
            row.get("decision"),
            row.get("request_id"),
            row.get("detail"),
        )
    })
    .collect()
}

fn audit_detail(row: &(i64, String, String, String)) -> serde_json::Value {
    serde_json::from_str(&row.3).expect("partition lease audit detail JSON")
}

fn lease_correlation_id(detail: &serde_json::Value) -> &str {
    detail["leaseCorrelationId"]
        .as_str()
        .expect("non-secret lease correlation id")
}

async fn lease_row(
    pool: &MySqlPool,
    partition: &ProjectionAggregateIdentity,
) -> Option<(String, i64, i64)> {
    let row = sqlx::query(
        "SELECT lease_owner, generation, cas_version \
         FROM authorization_projection_partition_lease \
         WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ?",
    )
    .bind(partition.tenant_id)
    .bind(&partition.aggregate_type)
    .bind(partition.aggregate_id)
    .fetch_optional(pool)
    .await
    .expect("read partition lease row");
    row.map(|row| {
        (
            row.get::<String, _>("lease_owner"),
            row.get::<i64, _>("generation"),
            row.get::<i64, _>("cas_version"),
        )
    })
}

#[derive(Debug, FromRow)]
struct DeltaQueueState {
    status: String,
    attempts: i64,
    execution_attempts: i64,
    execution_failures: i64,
    retry_is_future: i64,
    last_error: Option<String>,
    lease_owner: Option<String>,
    lease_token_hash: Option<Vec<u8>>,
}

#[derive(Debug, PartialEq, Eq, FromRow)]
struct OwnedLaneState {
    execution_epoch: i64,
    lease_owner: String,
    lease_token_hash: Vec<u8>,
    lease_expires_at: PrimitiveDateTime,
    active_delta_event_id: Option<i64>,
    active_delta_token_hash: Option<Vec<u8>>,
    lease_is_expired: i64,
}

async fn delta_queue_state(pool: &MySqlPool, request: &DeltaEventAppendRequest) -> DeltaQueueState {
    sqlx::query_as(
        "SELECT status, attempts, execution_attempts, execution_failures, \
         CAST(COALESCE(next_attempt_at > UTC_TIMESTAMP(6), 0) AS SIGNED) AS retry_is_future, \
         last_error, lease_owner, lease_token_hash \
         FROM authorization_delta_event \
         WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ? AND event_id = ?",
    )
    .bind(request.tenant_id)
    .bind(&request.aggregate_type)
    .bind(request.aggregate_id)
    .bind(&request.event_id)
    .fetch_one(pool)
    .await
    .expect("read exact source-owned delta queue state")
}

async fn owned_lane_state(
    pool: &MySqlPool,
    partition: &ProjectionAggregateIdentity,
) -> OwnedLaneState {
    sqlx::query_as(
        "SELECT execution_epoch, lease_owner, lease_token_hash, lease_expires_at, \
         active_delta_event_id, active_delta_token_hash, \
         CAST(lease_expires_at <= UTC_TIMESTAMP(6) AS SIGNED) AS lease_is_expired \
         FROM authorization_projection_partition_lease \
         WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ?",
    )
    .bind(partition.tenant_id)
    .bind(&partition.aggregate_type)
    .bind(partition.aggregate_id)
    .fetch_one(pool)
    .await
    .expect("owned execution must preserve its aggregate lane history")
}

fn assert_inactive_lane(lane: &OwnedLaneState) {
    assert!(lane.execution_epoch > 0);
    assert_eq!(lane.lease_owner, "");
    assert_eq!(lane.lease_token_hash, vec![0_u8; 32]);
    assert!(lane.active_delta_event_id.is_none());
    assert!(lane.active_delta_token_hash.is_none());
    assert_eq!(lane.lease_is_expired, 1);
}

async fn assert_owned_lane_inactive(pool: &MySqlPool, request: &DeltaEventAppendRequest) {
    let partition = identity(
        request.tenant_id,
        &request.aggregate_type,
        request.aggregate_id,
    );
    assert_inactive_lane(&owned_lane_state(pool, &partition).await);
}

fn source_entry(action: &str) -> AddEntryRequest {
    AddEntryRequest {
        effect: "ALLOW".to_owned(),
        resource_type: Some("learn_subject".to_owned()),
        resource_id: None,
        action_code: Some(action.to_owned()),
        condition_json: None,
        priority: 100,
    }
}

fn source_entry_update(action: &str) -> UpdateEntryRequest {
    UpdateEntryRequest {
        effect: "ALLOW".to_owned(),
        resource_type: Some("learn_subject".to_owned()),
        resource_id: None,
        action_code: Some(action.to_owned()),
        condition_json: None,
        priority: 100,
    }
}

async fn seed_source_fixture(pool: &MySqlPool, label: &str, tenant_count: usize) -> SuiteFixture {
    assert!(tenant_count > 0 && tenant_count <= 3);
    let suite = SuiteFixture::new(label, &vec![TenantRole::AllowActive; tenant_count]);
    seed_all_tenants(pool, &suite)
        .await
        .expect("seed run-scoped tenant and MANUAL RuleSet rows");
    for tenant in &suite.tenants {
        publish_card_manifest(
            pool,
            tenant.tenant_id,
            tenant.card_id,
            tenant.rule_set_id,
            tenant.user_id,
            vec![source_entry("read")],
            ("rq4-partition-baseline", suite.salt),
        )
        .await;
    }
    suite
}

async fn load_source_receipts(
    pool: &MySqlPool,
    tenant_id: i64,
    operation_id: &str,
) -> Vec<DeltaEventAppendRequest> {
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
    .expect("read immutable source-committed delta receipts");
    assert!(
        rows.len() <= 1024,
        "source receipt batch exceeds test bound"
    );

    rows.into_iter()
        .map(|row| {
            let event_type: String = row.get("event_type");
            let event_type = match event_type.as_str() {
                "ADD" => DeltaEventType::Add,
                "UPDATE" => DeltaEventType::Update,
                "REMOVE" => DeltaEventType::Remove,
                "REVOKE" => DeltaEventType::Revoke,
                other => panic!("unknown source-owned event type {other}"),
            };
            let before_digest: Option<Vec<u8>> = row.get("before_digest");
            let semantic_hash: Vec<u8> = row.get("semantic_hash");
            let dependency_hash: Vec<u8> = row.get("dependency_hash");
            let request = DeltaEventAppendRequest {
                tenant_id: row.get("tenant_id"),
                card_id: row.get("card_id"),
                aggregate_type: row.get("aggregate_type"),
                aggregate_id: row.get("aggregate_id"),
                grant_id: astral_db::decode_grant_id_sql(row.get::<&str, _>("grant_id"))
                    .expect("decode source-owned grant id"),
                event_id: row.get("event_id"),
                operation_id: row.get("operation_id"),
                event_type,
                base_version: row.get("base_version"),
                target_version: row.get("target_version"),
                source_generation: u64::try_from(row.get::<i64, _>("source_generation"))
                    .expect("source generation is positive"),
                revoke_fence: u64::try_from(row.get::<i64, _>("revoke_fence"))
                    .expect("revoke fence is nonnegative"),
                invalidates_published_evidence: row.get::<i8, _>("invalidates_published_evidence")
                    != 0,
                before_image_json: row.get("before_image_json"),
                before_digest_hex: before_digest.map(|bytes| {
                    Sha256Digest::from_bytes(bytes)
                        .expect("decode source-owned before-image digest")
                        .as_hex()
                }),
                delta_json: row.get("delta_json"),
                semantic_hash_hex: Sha256Digest::from_bytes(semantic_hash)
                    .expect("decode source-owned semantic hash")
                    .as_hex(),
                dependency_hash_hex: Sha256Digest::from_bytes(dependency_hash)
                    .expect("decode source-owned dependency hash")
                    .as_hex(),
                compiler_version: row.get("compiler_version"),
                next_attempt_at: row.get("next_attempt_at"),
            };
            assert_eq!(request.tenant_id, tenant_id);
            assert_eq!(request.operation_id, operation_id);
            assert_eq!(
                request.compiler_version,
                astral_types::AUTHORIZATION_COMPILER_VERSION,
                "source receipt must use the current compiler stamp"
            );
            OwnedCompletionIdentity::from_request(&request)
                .expect("complete immutable source receipt must validate");
            request
        })
        .collect()
}

async fn update_source_entry(
    pool: &MySqlPool,
    suite: &SuiteFixture,
    tenant: SuiteTenant,
    tag: &str,
    action: &str,
) -> DeltaEventAppendRequest {
    let operation_id = operation_id(suite, tag);
    let context = RuleSetMutationContext::user(tenant.user_id, Some(&operation_id))
        .expect("source mutation has a verified fixture actor and stable operation id");
    let entry_id: i64 = sqlx::query_scalar(
        "SELECT entry_id FROM rule_set_entry WHERE rule_set_id = ? AND enabled = 1 \
         ORDER BY entry_id DESC LIMIT 1",
    )
    .bind(tenant.rule_set_id)
    .fetch_one(pool)
    .await
    .expect("read actual enabled MANUAL RuleSet entry id");
    let service = RuleSetWriteService::new(Arc::new(SqlxRuleSetRepository::new(pool.clone())));
    service
        .update_entry(
            tenant.rule_set_id,
            entry_id,
            &source_entry_update(action),
            &context,
        )
        .await
        .expect("RuleSet source mutation must commit through the production writer");

    let receipts = load_source_receipts(pool, tenant.tenant_id, &operation_id).await;
    assert_eq!(
        receipts.len(),
        1,
        "one bound source entry update must produce one immutable contribution receipt"
    );
    let request = receipts.into_iter().next().expect("one source receipt");
    assert_eq!(request.card_id, Some(tenant.card_id));
    assert_eq!(request.aggregate_type, "RULE_SET");
    assert_eq!(request.aggregate_id, tenant.rule_set_id);
    assert_eq!(request.event_type, DeltaEventType::Update);
    assert!(request.invalidates_published_evidence);
    assert!(request.source_generation > 0);
    assert!(request.revoke_fence <= request.source_generation);
    request
}

fn assert_claim_matches_receipt(request: &DeltaEventAppendRequest, claim: &OwnedDeltaClaim) {
    let persisted = &claim.claim;
    let readback = &claim.event;
    assert_eq!(persisted.event_id, request.event_id);
    assert_eq!(persisted.operation_id, request.operation_id);
    assert_eq!(persisted.event_type, request.event_type);
    assert_eq!(persisted.tenant_id, request.tenant_id);
    assert_eq!(persisted.card_id, request.card_id);
    assert_eq!(persisted.aggregate_type, request.aggregate_type);
    assert_eq!(persisted.aggregate_id, request.aggregate_id);
    assert_eq!(persisted.grant_id, request.grant_id);
    assert_eq!(persisted.base_version, request.base_version);
    assert_eq!(persisted.target_version, request.target_version);
    assert_eq!(persisted.source_generation, request.source_generation);
    assert_eq!(persisted.revoke_fence, request.revoke_fence);
    assert_eq!(persisted.before_image_json, request.before_image_json);
    assert_eq!(
        persisted
            .before_digest
            .as_ref()
            .map(Sha256Digest::as_hex)
            .as_deref(),
        request.before_digest_hex.as_deref()
    );
    assert_eq!(persisted.delta_json, request.delta_json);
    assert_eq!(persisted.semantic_hash.as_hex(), request.semantic_hash_hex);
    assert_eq!(
        persisted.dependency_hash.as_hex(),
        request.dependency_hash_hex
    );
    assert_eq!(persisted.compiler_version, request.compiler_version);
    assert_eq!(readback.event_id, request.event_id);
    assert_eq!(readback.operation_id, request.operation_id);
    assert_eq!(readback.event_type, request.event_type);
    assert_eq!(readback.tenant_id, request.tenant_id);
    assert_eq!(readback.card_id, request.card_id);
    assert_eq!(readback.aggregate_type, request.aggregate_type);
    assert_eq!(readback.aggregate_id, request.aggregate_id);
    assert_eq!(readback.grant_id, request.grant_id);
    assert_eq!(readback.base_version, request.base_version);
    assert_eq!(readback.target_version, request.target_version);
    assert_eq!(readback.source_generation, request.source_generation);
    assert_eq!(readback.revoke_fence, request.revoke_fence);
    assert_eq!(
        readback.before_image_json.as_deref(),
        request.before_image_json.as_deref()
    );
    assert_eq!(
        readback
            .before_digest
            .as_ref()
            .map(Sha256Digest::as_hex)
            .as_deref(),
        request.before_digest_hex.as_deref()
    );
    assert_eq!(readback.delta_json, request.delta_json);
    assert_eq!(readback.semantic_hash.as_hex(), request.semantic_hash_hex);
    assert_eq!(
        readback.dependency_hash.as_hex(),
        request.dependency_hash_hex
    );
    assert_eq!(readback.compiler_version, request.compiler_version);
    assert_eq!(persisted.attempts, readback.attempts);
    assert_eq!(persisted.lease_owner, readback.lease_owner);
    assert_eq!(
        claim.lease.aggregate_identity(),
        &identity(
            request.tenant_id,
            &request.aggregate_type,
            request.aggregate_id
        )
    );
}

async fn claim_source_partition(
    pool: &MySqlPool,
    request: &DeltaEventAppendRequest,
    owner: &str,
) -> OwnedDeltaClaim {
    OwnedCompletionIdentity::from_request(request)
        .expect("validate full immutable source receipt before partition claim");
    let aggregate = identity(
        request.tenant_id,
        &request.aggregate_type,
        request.aggregate_id,
    );
    let claim = claim_next_owned_delta_event_in_partition(
        pool,
        DeltaEventClaimScope {
            tenant_id: request.tenant_id,
            card_id: request.card_id,
        },
        &aggregate,
        owner,
        CLAIM_LEASE_SECONDS,
    )
    .await
    .expect("WorkerOwned partition claim must complete durably")
    .expect("source-owned receipt must be claimable in its exact partition");
    assert_claim_matches_receipt(request, &claim);
    claim
}

async fn claim_empty_partition(
    pool: &MySqlPool,
    tenant: SuiteTenant,
    owner: &str,
) -> Option<OwnedDeltaClaim> {
    let aggregate = identity(tenant.tenant_id, "RULE_SET", tenant.rule_set_id);
    claim_next_owned_delta_event_in_partition(
        pool,
        DeltaEventClaimScope {
            tenant_id: tenant.tenant_id,
            card_id: Some(tenant.card_id),
        },
        &aggregate,
        owner,
        CLAIM_LEASE_SECONDS,
    )
    .await
    .expect("empty WorkerOwned partition claim must complete without error")
}

async fn release_source_claim(pool: &MySqlPool, claim: &OwnedDeltaClaim) {
    assert!(
        release_owned_delta_event(pool, &claim.lease)
            .await
            .expect("release exact opaque owned capability"),
        "the current opaque capability must release its own claim"
    );
}

#[tokio::test]
#[ignore = "run-owned isolated MySQL integration; requires RUST_INTEGRATION_REQUIRED=1"]
async fn partition_lease_roundtrip_acquire_renew_release() {
    let pool = required_pool().await;
    let (suite, partition) = lease_test_partition(&pool, "rq4-partition-roundtrip").await;
    assert_partition_identity_unused(&pool, &partition).await;

    let owner = worker_id(suite.salt, "roundtrip");
    let handle: PartitionLeaseHandle = acquire_partition_lease(&pool, &partition, &owner, 300)
        .await
        .expect("acquire on fresh partition")
        .expect("fresh partition must not be Busy");
    assert_eq!(handle.lease_owner, owner);

    let (_, generation_before, cas_before) = lease_row(&pool, &partition)
        .await
        .expect("lease row before self renew");
    renew_partition_lease(&pool, &handle, 300)
        .await
        .expect("self renew");
    let (actual_owner, generation, cas) = lease_row(&pool, &partition)
        .await
        .expect("lease row exists");
    assert_eq!(actual_owner, handle.lease_owner);
    assert_eq!(
        generation, generation_before,
        "heartbeat must not manufacture a new ownership generation"
    );
    assert!(cas > cas_before, "self renew must advance the CAS version");

    release_partition_lease(&pool, &handle)
        .await
        .expect("release");
    assert!(lease_row(&pool, &partition).await.is_none());
    assert_eq!(
        partition_lease_audit_actions(&pool, &partition).await,
        vec!["partition_lease_acquire", "partition_lease_release"],
        "renew success must not emit an audit row"
    );
    let audit_rows = partition_lease_audit_rows(&pool, &partition).await;
    assert_eq!(audit_rows.len(), 2);
    let acquire_detail = audit_detail(&audit_rows[0]);
    let release_detail = audit_detail(&audit_rows[1]);
    for (row, detail) in audit_rows.iter().zip([&acquire_detail, &release_detail]) {
        assert_eq!(row.0, SYSTEM_ACTOR_ID);
        assert_eq!(row.1, "INTERNAL");
        assert_eq!(detail["requestId"], row.2);
        assert_eq!(detail["tenantId"], partition.tenant_id);
        assert_eq!(detail["aggregateType"], partition.aggregate_type);
        assert_eq!(detail["aggregateId"], partition.aggregate_id);
    }
    assert_eq!(
        lease_correlation_id(&acquire_detail),
        lease_correlation_id(&release_detail),
        "acquire and release must share one ownership episode"
    );
    assert_ne!(
        audit_rows[0].2, audit_rows[1].2,
        "each lifecycle transition needs its own request id"
    );
    assert_eq!(acquire_detail["outcome"], "ACQUIRE");
    assert_eq!(release_detail["outcome"], "RELEASE");
    cleanup_partition_identity(&pool, &partition).await;
    cleanup_suite_rows(&pool, &suite)
        .await
        .expect("cleanup only the run-owned lease lifecycle fixture");
}

#[tokio::test]
#[ignore = "run-owned isolated MySQL integration; requires RUST_INTEGRATION_REQUIRED=1"]
async fn partition_lease_second_owner_is_busy_while_first_is_live() {
    let pool = required_pool().await;
    let (suite, partition) = lease_test_partition(&pool, "rq4-partition-busy").await;
    assert_partition_identity_unused(&pool, &partition).await;
    let first_owner = worker_id(suite.salt, "first");
    let second_owner = worker_id(suite.salt, "second");

    let first = acquire_partition_lease(&pool, &partition, &first_owner, 300)
        .await
        .expect("acquire")
        .expect("first owner acquires");
    let second = acquire_partition_lease(&pool, &partition, &second_owner, 300)
        .await
        .expect("acquire probe must not error");
    assert!(second.is_none(), "live foreign lease must be Busy");
    let (owner, _, _) = lease_row(&pool, &partition)
        .await
        .expect("lease row still first owner's");
    assert_eq!(owner, first_owner);

    release_partition_lease(&pool, &first)
        .await
        .expect("release first owner");
    let reclaimed = acquire_partition_lease(&pool, &partition, &second_owner, 300)
        .await
        .expect("acquire after release")
        .expect("released partition must be acquirable");
    assert_eq!(reclaimed.lease_owner, second_owner);
    release_partition_lease(&pool, &reclaimed)
        .await
        .expect("release second owner");
    let repeated_owner = acquire_partition_lease(&pool, &partition, &first_owner, 300)
        .await
        .expect("acquire same owner after a completed episode")
        .expect("released partition must be acquirable");
    release_partition_lease(&pool, &repeated_owner)
        .await
        .expect("release repeated owner");

    let audit_rows = partition_lease_audit_rows(&pool, &partition).await;
    assert_eq!(
        partition_lease_audit_actions(&pool, &partition).await,
        vec![
            "partition_lease_acquire",
            "partition_lease_release",
            "partition_lease_acquire",
            "partition_lease_release",
            "partition_lease_acquire",
            "partition_lease_release",
        ],
        "busy probe must not create a lifecycle audit row"
    );
    let details: Vec<_> = audit_rows.iter().map(audit_detail).collect();
    for (row, detail) in audit_rows.iter().zip(&details) {
        assert_eq!(detail["requestId"], row.2);
    }
    let request_ids: HashSet<_> = audit_rows.iter().map(|row| row.2.as_str()).collect();
    assert_eq!(
        request_ids.len(),
        audit_rows.len(),
        "every durable lifecycle transition needs a distinct request id"
    );
    assert_eq!(
        lease_correlation_id(&details[0]),
        lease_correlation_id(&details[1])
    );
    assert_eq!(
        lease_correlation_id(&details[2]),
        lease_correlation_id(&details[3])
    );
    assert_eq!(
        lease_correlation_id(&details[4]),
        lease_correlation_id(&details[5])
    );
    assert_ne!(
        lease_correlation_id(&details[0]),
        lease_correlation_id(&details[4]),
        "the same worker identity must start a new audit episode after release"
    );
    cleanup_partition_identity(&pool, &partition).await;
    cleanup_suite_rows(&pool, &suite)
        .await
        .expect("cleanup only the run-owned lease lifecycle fixture");
}

#[tokio::test]
#[ignore = "run-owned isolated MySQL integration; requires RUST_INTEGRATION_REQUIRED=1"]
async fn partition_lease_expired_lease_is_taken_over_with_generation_bump() {
    let pool = required_pool().await;
    let (suite, partition) = lease_test_partition(&pool, "rq4-partition-expiry").await;
    assert_partition_identity_unused(&pool, &partition).await;
    let abandoned_owner = worker_id(suite.salt, "abandoned");
    let takeover_owner = worker_id(suite.salt, "takeover");

    let abandoned = acquire_partition_lease(&pool, &partition, &abandoned_owner, 1)
        .await
        .expect("acquire")
        .expect("first acquire");
    let (_, generation_before, _) = lease_row(&pool, &partition)
        .await
        .expect("lease row after first acquire");

    tokio::time::sleep(Duration::from_millis(1300)).await;
    let takeover = acquire_partition_lease(&pool, &partition, &takeover_owner, 300)
        .await
        .expect("acquire after expiry")
        .expect("expired lease must be reclaimable");
    assert_eq!(takeover.lease_owner, takeover_owner);
    let (_, generation_after, _) = lease_row(&pool, &partition)
        .await
        .expect("lease row after takeover");
    assert!(
        generation_after > generation_before,
        "takeover must bump generation: {generation_before} -> {generation_after}"
    );
    assert!(
        renew_partition_lease(&pool, &abandoned, 300).await.is_err(),
        "stale owner must observe lease loss"
    );
    assert!(
        renew_partition_lease(&pool, &takeover, 300).await.is_ok(),
        "current owner renews fine"
    );
    release_partition_lease(&pool, &takeover)
        .await
        .expect("release takeover lease");
    let audit_actions_before_stale_release = partition_lease_audit_actions(&pool, &partition).await;
    assert_eq!(
        audit_actions_before_stale_release,
        vec![
            "partition_lease_acquire",
            "partition_lease_reclaim",
            "partition_lease_renew_lost",
            "partition_lease_release",
        ]
    );
    release_partition_lease(&pool, &abandoned)
        .await
        .expect("stale release remains a best-effort no-op");
    assert_eq!(
        partition_lease_audit_actions(&pool, &partition).await,
        audit_actions_before_stale_release,
        "stale release must not create an audit row"
    );
    let audit_rows = partition_lease_audit_rows(&pool, &partition).await;
    let reclaim_detail: serde_json::Value =
        serde_json::from_str(&audit_rows[1].3).expect("reclaim audit detail JSON");
    assert_eq!(audit_rows[1].0, SYSTEM_ACTOR_ID);
    assert_eq!(audit_rows[1].1, "INTERNAL");
    assert_eq!(reclaim_detail["requestId"], audit_rows[1].2);
    assert_eq!(reclaim_detail["outcome"], "RECLAIM");
    let acquire_detail = audit_detail(&audit_rows[0]);
    let renew_lost_detail = audit_detail(&audit_rows[2]);
    let release_detail = audit_detail(&audit_rows[3]);
    assert_eq!(
        lease_correlation_id(&reclaim_detail),
        lease_correlation_id(&release_detail),
        "reclaim and successor release must share one ownership episode"
    );
    assert_ne!(
        lease_correlation_id(&acquire_detail),
        lease_correlation_id(&reclaim_detail),
        "takeover must open a new ownership episode"
    );
    assert_eq!(
        lease_correlation_id(&acquire_detail),
        lease_correlation_id(&renew_lost_detail),
        "stale renew loss belongs to the abandoned episode"
    );
    assert_ne!(audit_rows[0].2, audit_rows[2].2);
    assert_ne!(audit_rows[1].2, audit_rows[3].2);
    assert_eq!(reclaim_detail["generation"], generation_after);
    assert!(
        reclaim_detail["casVersion"]
            .as_i64()
            .is_some_and(|value| value >= 1),
        "reclaim audit must report a durable CAS version"
    );
    cleanup_partition_identity(&pool, &partition).await;
    cleanup_suite_rows(&pool, &suite)
        .await
        .expect("cleanup only the run-owned lease lifecycle fixture");
}

#[tokio::test]
#[ignore = "run-owned isolated MySQL integration; requires RUST_INTEGRATION_REQUIRED=1"]
async fn concurrent_expired_reclaim_has_one_winner_without_duplicate_key_deadlock() {
    let pool = required_pool().await;
    let (suite, partition) = lease_test_partition(&pool, "rq4-partition-reclaim-race").await;
    assert_partition_identity_unused(&pool, &partition).await;
    let abandoned =
        acquire_partition_lease(&pool, &partition, &worker_id(suite.salt, "race-seed"), 1)
            .await
            .expect("seed acquire")
            .expect("seed owner acquires");
    tokio::time::sleep(Duration::from_millis(1300)).await;

    let barrier = Arc::new(Barrier::new(3));
    let first_pool = pool.clone();
    let first_identity = partition.clone();
    let first_barrier = barrier.clone();
    let first_owner = worker_id(suite.salt, "race-a");
    let first_owner_for_task = first_owner.clone();
    let first = tokio::spawn(async move {
        first_barrier.wait().await;
        acquire_partition_lease(&first_pool, &first_identity, &first_owner_for_task, 300).await
    });
    let second_pool = pool.clone();
    let second_identity = partition.clone();
    let second_barrier = barrier.clone();
    let second_owner = worker_id(suite.salt, "race-b");
    let second_owner_for_task = second_owner.clone();
    let second = tokio::spawn(async move {
        second_barrier.wait().await;
        acquire_partition_lease(&second_pool, &second_identity, &second_owner_for_task, 300).await
    });
    barrier.wait().await;

    let first = first
        .await
        .expect("first task join")
        .expect("first acquire result");
    let second = second
        .await
        .expect("second task join")
        .expect("second acquire result");
    let winner = match (first, second) {
        (Some(winner), None) | (None, Some(winner)) => winner,
        other => panic!("exactly one expired reclaim must win without a DB error: {other:?}"),
    };
    release_partition_lease(&pool, &winner)
        .await
        .expect("release winner");
    assert_eq!(
        partition_lease_audit_actions(&pool, &partition).await,
        vec![
            "partition_lease_acquire",
            "partition_lease_reclaim",
            "partition_lease_release",
        ],
        "the losing contender is Busy, not a second reclaim or deadlock witness"
    );
    release_partition_lease(&pool, &abandoned)
        .await
        .expect("stale seed release remains best effort");
    cleanup_partition_identity(&pool, &partition).await;
    cleanup_suite_rows(&pool, &suite)
        .await
        .expect("cleanup only the run-owned lease lifecycle fixture");
}

#[tokio::test]
#[ignore = "run-owned isolated MySQL integration; requires RUST_INTEGRATION_REQUIRED=1"]
async fn partition_discovery_returns_only_claimable_source_partitions() {
    let pool = required_pool().await;
    let suite = seed_source_fixture(&pool, "rq4-partition-discovery", 2).await;
    let due_tenant = suite.tenants[0];
    let parked_tenant = suite.tenants[1];
    let due = update_source_entry(&pool, &suite, due_tenant, "due", "create").await;
    let parked = update_source_entry(&pool, &suite, parked_tenant, "parked", "update").await;

    // A real owned execution failure moves the second source receipt into a
    // future retry window; discovery must omit that parked partition.
    let parked_claim =
        claim_source_partition(&pool, &parked, &worker_id(suite.salt, "parked-failure")).await;
    assert_eq!(
        begin_owned_delta_execution(&pool, &parked_claim.lease)
            .await
            .expect("begin real owned failure episode"),
        0
    );
    assert!(
        fail_owned_delta_event(
            &pool,
            &parked_claim.lease,
            "code=rq4.partition_discovery_backoff",
            BACKOFF_CAP_SECS,
            true,
        )
        .await
        .expect("record the real source-owned retry transition"),
        "the live failure capability must persist its backoff"
    );
    let parked_state = delta_queue_state(&pool, &parked).await;
    assert_eq!(parked_state.status, "PENDING");
    assert_eq!(parked_state.attempts, 1);
    assert_eq!(parked_state.execution_attempts, 1);
    assert_eq!(parked_state.execution_failures, 1);
    assert_eq!(parked_state.retry_is_future, 1);
    assert!(parked_state.lease_owner.is_none());
    assert!(parked_state.lease_token_hash.is_none());
    assert_owned_lane_inactive(&pool, &parked).await;

    let rows =
        discover_claimable_partitions(&pool, &[due_tenant.tenant_id, parked_tenant.tenant_id], 64)
            .await
            .expect("discover claimable source partitions");
    let found: Vec<_> = rows
        .iter()
        .map(|row| (row.tenant_id, row.aggregate_type.as_str(), row.aggregate_id))
        .collect();
    assert!(
        found.contains(&(due.tenant_id, "RULE_SET", due.aggregate_id)),
        "due source partition must be discoverable: {found:?}"
    );
    assert!(
        !found.contains(&(parked.tenant_id, "RULE_SET", parked.aggregate_id)),
        "backoff-parked source partition must not be discoverable: {found:?}"
    );

    let due_claim = claim_source_partition(&pool, &due, &worker_id(suite.salt, "due-claim")).await;
    release_source_claim(&pool, &due_claim).await;
    let due_state = delta_queue_state(&pool, &due).await;
    assert_eq!(due_state.status, "PENDING");
    assert_eq!(due_state.attempts, 1);
    assert!(due_state.lease_owner.is_none());
    assert_owned_lane_inactive(&pool, &due).await;

    cleanup_suite_rows(&pool, &suite)
        .await
        .expect("cleanup only the source-owned fixture after lanes are inactive");
}

#[tokio::test]
#[ignore = "run-owned isolated MySQL integration; requires RUST_INTEGRATION_REQUIRED=1"]
async fn partition_claim_respects_exact_boundary_foreign_row_and_empty_partition() {
    let pool = required_pool().await;
    let suite = seed_source_fixture(&pool, "rq4-partition-boundary", 3).await;
    let target_tenant = suite.tenants[0];
    let foreign_tenant = suite.tenants[1];
    let empty_tenant = suite.tenants[2];
    let target = update_source_entry(&pool, &suite, target_tenant, "target", "create").await;
    let foreign = update_source_entry(&pool, &suite, foreign_tenant, "foreign", "update").await;

    let claim =
        claim_source_partition(&pool, &target, &worker_id(suite.salt, "target-claim")).await;
    assert_eq!(claim.claim.tenant_id, target_tenant.tenant_id);
    assert_eq!(claim.claim.aggregate_type, "RULE_SET");
    assert_eq!(claim.claim.aggregate_id, target_tenant.rule_set_id);

    let foreign_before_release = delta_queue_state(&pool, &foreign).await;
    assert_eq!(foreign_before_release.status, "PENDING");
    assert_eq!(foreign_before_release.attempts, 0);
    assert_eq!(foreign_before_release.execution_attempts, 0);
    assert_eq!(foreign_before_release.execution_failures, 0);
    assert!(foreign_before_release.lease_owner.is_none());
    assert!(foreign_before_release.lease_token_hash.is_none());

    let empty_partition = identity(empty_tenant.tenant_id, "RULE_SET", empty_tenant.rule_set_id);
    let empty_before = owned_lane_state(&pool, &empty_partition).await;
    assert_inactive_lane(&empty_before);
    assert!(
        claim_empty_partition(&pool, empty_tenant, &worker_id(suite.salt, "empty-probe"))
            .await
            .is_none(),
        "real baseline-only RuleSet aggregate must claim None"
    );
    let empty_after = owned_lane_state(&pool, &empty_partition).await;
    assert_inactive_lane(&empty_after);
    assert_eq!(
        empty_before, empty_after,
        "empty queue observation must preserve the baseline publication's retired lane"
    );

    release_source_claim(&pool, &claim).await;
    let target_after_release = delta_queue_state(&pool, &target).await;
    assert_eq!(target_after_release.status, "PENDING");
    assert_eq!(target_after_release.attempts, 1);
    assert!(target_after_release.lease_owner.is_none());
    assert!(target_after_release.lease_token_hash.is_none());
    assert_owned_lane_inactive(&pool, &target).await;
    let foreign_after_release = delta_queue_state(&pool, &foreign).await;
    assert_eq!(foreign_after_release.status, "PENDING");
    assert_eq!(foreign_after_release.attempts, 0);
    assert_eq!(foreign_after_release.execution_attempts, 0);
    assert_eq!(foreign_after_release.execution_failures, 0);
    assert!(foreign_after_release.lease_owner.is_none());
    assert!(foreign_after_release.lease_token_hash.is_none());

    cleanup_suite_rows(&pool, &suite)
        .await
        .expect("cleanup only source-owned fixture after exact claim release");
}

#[tokio::test]
#[ignore = "run-owned isolated MySQL integration; requires RUST_INTEGRATION_REQUIRED=1"]
async fn attempt_budget_exhaustion_parks_real_source_receipt() {
    let pool = required_pool().await;
    let suite = seed_source_fixture(&pool, "rq4-attempt-budget", 1).await;
    let tenant = suite.tenants[0];
    let request = update_source_entry(&pool, &suite, tenant, "budget", "create").await;
    OwnedCompletionIdentity::from_request(&request)
        .expect("attempt-budget exercise starts from a valid full source receipt");

    for expected_failure in 1..=MAX_EVENT_ATTEMPTS {
        let claim = claim_source_partition(
            &pool,
            &request,
            &worker_id(suite.salt, &format!("budget-{expected_failure}")),
        )
        .await;
        assert_eq!(claim.claim.attempts, expected_failure);
        assert_eq!(
            claim.lease.execution_failures(),
            (expected_failure - 1) as u32
        );
        assert_eq!(
            begin_owned_delta_execution(&pool, &claim.lease)
                .await
                .expect("begin actual owned retry episode"),
            (expected_failure - 1) as u32
        );

        let exhausted = expected_failure == MAX_EVENT_ATTEMPTS;
        let reason = if exhausted {
            format!(
                "{ATTEMPT_BUDGET_EXHAUSTED_MARKER};attempts={MAX_EVENT_ATTEMPTS};rq4-owned-transition"
            )
        } else {
            "code=rq4.attempt_budget_failure_probe".to_owned()
        };
        let backoff = if exhausted { BACKOFF_CAP_SECS } else { 0 };
        assert!(
            fail_owned_delta_event(&pool, &claim.lease, &reason, backoff, true)
                .await
                .expect("persist failure through the production owned transition"),
            "each live capability must persist one real failure transition"
        );

        let state = delta_queue_state(&pool, &request).await;
        assert_eq!(state.status, "PENDING", "failure is not a terminal status");
        assert_eq!(state.attempts, expected_failure);
        assert_eq!(state.execution_attempts, expected_failure);
        assert_eq!(state.execution_failures, expected_failure);
        assert!(state.lease_owner.is_none());
        assert!(state.lease_token_hash.is_none());
        if exhausted {
            assert_eq!(state.retry_is_future, 1);
            assert!(state
                .last_error
                .as_deref()
                .is_some_and(|value| value.starts_with(ATTEMPT_BUDGET_EXHAUSTED_MARKER)));
        } else {
            assert_eq!(state.retry_is_future, 0);
            assert!(state
                .last_error
                .as_deref()
                .is_some_and(|value| value.contains("rq4.attempt_budget_failure_probe")));
        }
        assert_owned_lane_inactive(&pool, &request).await;
    }

    let discovered = discover_claimable_partitions(&pool, &[tenant.tenant_id], 64)
        .await
        .expect("discovery after real exhausted failure transitions");
    assert!(
        !discovered.iter().any(|row| {
            row.tenant_id == request.tenant_id
                && row.aggregate_type == request.aggregate_type
                && row.aggregate_id == request.aggregate_id
        }),
        "the exhausted source receipt remains parked and its partition is not claimable"
    );

    // This bounded integration target does not claim pointer-advance recovery:
    // invoking reclaim_budget_exhausted_events directly would not prove that a
    // real WorkerOwned publication advanced this aggregate's current pointer.
    cleanup_suite_rows(&pool, &suite)
        .await
        .expect("cleanup only source-owned fixture after owned failure transitions");
}
