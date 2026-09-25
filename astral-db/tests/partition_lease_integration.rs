#![cfg(test)]
//! Real-MySQL integration acceptance for the partition scheduling primitives
//! (multi-tenant redesign Phase 1; design doc
//! Rust多租户聚合分区与组织层级设计_V0.1.md §3.3).
//!
//! Execution class: real MySQL via `DATABASE_URL`; run with
//!
//! ```text
//! RUST_INTEGRATION_REQUIRED=1 DATABASE_URL=mysql://.../astral_test_e5m1_20260921 \
//!   cargo test -p astral-db --test partition_lease_integration -- --ignored --test-threads=1
//! ```
//!
//! Without `DATABASE_URL` every test is an explicit `[SKIP]`; with
//! `RUST_INTEGRATION_REQUIRED=1` a missing URL or unreachable database is a
//! hard failure (never a silent green). The database name must contain
//! `test` (migration gate) and is expected to have the embedded migrator
//! applied (`authorization_projection_partition_lease` +
//! `authorization_delta_event` exist).
//!
//! Seeded delta rows use distinct partition identities per test and are
//! removed in each test's cleanup; single-threaded execution keeps the lease
//! windows deterministic.

use astral_db::{
    acquire_partition_lease, claim_next_delta_event_in_partition_tx, discover_claimable_partitions,
    release_partition_lease, renew_partition_lease, PartitionLeaseHandle,
    ProjectionAggregateIdentity,
};
use std::collections::HashSet;
use std::sync::Arc;

use astral_types::SYSTEM_ACTOR_ID;
use sqlx::{pool::PoolOptions, MySql, MySqlPool, Row};
use tokio::sync::Barrier;

fn required_mode() -> bool {
    std::env::var("RUST_INTEGRATION_REQUIRED").as_deref() == Ok("1")
}

async fn test_pool() -> Option<MySqlPool> {
    let url = match std::env::var("DATABASE_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        _ => {
            if required_mode() {
                panic!("RUST_INTEGRATION_REQUIRED=1: DATABASE_URL must be set");
            }
            eprintln!("[SKIP] partition_lease_integration: DATABASE_URL not set");
            return None;
        }
    };
    let pool = PoolOptions::<MySql>::new()
        .max_connections(4)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .connect_lazy(&url)
        .expect("lazy pool construction");
    // Fail fast (and loudly) when the database is unreachable.
    match sqlx::query("SELECT 1").fetch_one(&pool).await {
        Ok(_) => Some(pool),
        Err(error) => {
            if required_mode() {
                panic!("RUST_INTEGRATION_REQUIRED=1: database unreachable: {error}");
            }
            eprintln!("[SKIP] partition_lease_integration: database unreachable: {error}");
            None
        }
    }
}

fn identity(tenant: i64, kind: &str, id: i64) -> ProjectionAggregateIdentity {
    ProjectionAggregateIdentity::new(tenant, kind, id).expect("valid partition identity")
}

/// Seed one PENDING delta event into `authorization_delta_event`. Columns
/// satisfy the creator DDL; `revoke_fence` keeps the documented
/// `revoke_fence <= source_generation` relation.
async fn seed_pending_event(
    pool: &MySqlPool,
    tenant: i64,
    aggregate_type: &str,
    aggregate_id: i64,
    grant_id: &str,
    event_id: &str,
) {
    sqlx::query(
        "INSERT INTO authorization_delta_event \
         (tenant_id, card_id, aggregate_type, aggregate_id, grant_id, event_id, operation_id, \
          event_type, base_version, target_version, source_generation, revoke_fence, \
          delta_json, semantic_hash, dependency_hash, compiler_version, status) \
         VALUES (?, NULL, ?, ?, ?, ?, ?, 'ADD', 0, 1, 1, 0, \
                 JSON_OBJECT('op', 'add'), UNHEX(REPEAT('a', 64)), \
                 UNHEX(REPEAT('b', 64)), 'integration-test', 'PENDING')",
    )
    .bind(tenant)
    .bind(aggregate_type)
    .bind(aggregate_id)
    .bind(grant_id)
    .bind(event_id)
    .bind(format!("op-{event_id}"))
    .execute(pool)
    .await
    .expect("seed delta event");
}

async fn cleanup_partition(pool: &MySqlPool, tenant: i64, aggregate_id: i64) {
    sqlx::query("DELETE FROM authorization_delta_event WHERE tenant_id = ? AND aggregate_id = ?")
        .bind(tenant)
        .bind(aggregate_id)
        .execute(pool)
        .await
        .expect("cleanup delta events");
    sqlx::query(
        "DELETE FROM authorization_projection_partition_lease WHERE tenant_id = ? AND aggregate_id = ?",
    )
    .bind(tenant)
    .bind(aggregate_id)
    .execute(pool)
    .await
    .expect("cleanup partition lease");
    sqlx::query(
        "DELETE FROM audit_log WHERE event_type = 'AUTHZ_PARTITION_LEASE' \
         AND tenant_id = ? AND resource = 'authorization_projection_partition_lease' \
         AND JSON_UNQUOTE(JSON_EXTRACT(detail, '$.aggregateType')) = 'CARD' \
         AND CAST(JSON_UNQUOTE(JSON_EXTRACT(detail, '$.aggregateId')) AS SIGNED) = ?",
    )
    .bind(tenant)
    .bind(aggregate_id)
    .execute(pool)
    .await
    .expect("cleanup partition lease audit");
}

async fn partition_lease_audit_actions(
    pool: &MySqlPool,
    tenant: i64,
    aggregate_id: i64,
) -> Vec<String> {
    sqlx::query(
        "SELECT action FROM audit_log \
         WHERE event_type = 'AUTHZ_PARTITION_LEASE' \
           AND tenant_id = ? \
           AND resource = 'authorization_projection_partition_lease' \
           AND JSON_UNQUOTE(JSON_EXTRACT(detail, '$.aggregateType')) = 'CARD' \
           AND CAST(JSON_UNQUOTE(JSON_EXTRACT(detail, '$.aggregateId')) AS SIGNED) = ? \
         ORDER BY id",
    )
    .bind(tenant)
    .bind(aggregate_id)
    .fetch_all(pool)
    .await
    .expect("read partition lease audit")
    .into_iter()
    .map(|row| row.get("action"))
    .collect()
}

async fn partition_lease_audit_rows(
    pool: &MySqlPool,
    tenant: i64,
    aggregate_id: i64,
) -> Vec<(i64, String, String, String)> {
    sqlx::query(
        "SELECT user_id, decision, request_id, detail FROM audit_log \
         WHERE event_type = 'AUTHZ_PARTITION_LEASE' \
           AND tenant_id = ? \
           AND resource = 'authorization_projection_partition_lease' \
           AND JSON_UNQUOTE(JSON_EXTRACT(detail, '$.aggregateType')) = 'CARD' \
           AND CAST(JSON_UNQUOTE(JSON_EXTRACT(detail, '$.aggregateId')) AS SIGNED) = ? \
         ORDER BY id",
    )
    .bind(tenant)
    .bind(aggregate_id)
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

async fn lease_row(pool: &MySqlPool, tenant: i64, aggregate_id: i64) -> Option<(String, i64, i64)> {
    let row = sqlx::query(
        "SELECT lease_owner, generation, cas_version \
         FROM authorization_projection_partition_lease \
         WHERE tenant_id = ? AND aggregate_id = ?",
    )
    .bind(tenant)
    .bind(aggregate_id)
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

const TENANT: i64 = 990_001;

#[tokio::test]
#[ignore = "real MySQL integration; RUST_INTEGRATION_REQUIRED=1 DATABASE_URL=..."]
async fn partition_lease_roundtrip_acquire_renew_release() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let ident = identity(TENANT, "CARD", 1001);
    cleanup_partition(&pool, TENANT, 1001).await;

    let handle: PartitionLeaseHandle = acquire_partition_lease(&pool, &ident, "worker-a", 300)
        .await
        .expect("acquire on fresh partition")
        .expect("fresh partition must not be Busy");
    assert_eq!(handle.lease_owner, "worker-a");

    let (_, generation_before, cas_before) = lease_row(&pool, TENANT, 1001)
        .await
        .expect("lease row before self renew");
    // Self-renew keeps the ownership epoch stable and advances only the
    // liveness/CAS version.
    renew_partition_lease(&pool, &handle, 300)
        .await
        .expect("self renew");
    let (owner, generation, cas) = lease_row(&pool, TENANT, 1001)
        .await
        .expect("lease row exists");
    assert_eq!(owner, "worker-a");
    assert_eq!(
        generation, generation_before,
        "heartbeat must not manufacture a new ownership generation"
    );
    assert!(cas > cas_before, "self renew must advance the CAS version");

    // Best-effort release removes the row entirely. Successful heartbeats are
    // represented by the lease row, not audit spam; only acquire and release
    // create durable lifecycle audit rows.
    release_partition_lease(&pool, &handle)
        .await
        .expect("release");
    assert!(lease_row(&pool, TENANT, 1001).await.is_none());
    assert_eq!(
        partition_lease_audit_actions(&pool, TENANT, 1001).await,
        vec!["partition_lease_acquire", "partition_lease_release"],
        "renew success must not emit an audit row"
    );
    let audit_rows = partition_lease_audit_rows(&pool, TENANT, 1001).await;
    assert_eq!(audit_rows.len(), 2);
    let acquire_detail = audit_detail(&audit_rows[0]);
    let release_detail = audit_detail(&audit_rows[1]);
    for (row, detail) in audit_rows.iter().zip([&acquire_detail, &release_detail]) {
        assert_eq!(row.0, SYSTEM_ACTOR_ID);
        assert_eq!(row.1, "INTERNAL");
        assert_eq!(detail["requestId"], row.2);
        assert_eq!(detail["tenantId"], TENANT);
        assert_eq!(detail["aggregateType"], "CARD");
        assert_eq!(detail["aggregateId"], 1001);
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
    cleanup_partition(&pool, TENANT, 1001).await;
}

#[tokio::test]
#[ignore = "real MySQL integration; RUST_INTEGRATION_REQUIRED=1 DATABASE_URL=..."]
async fn partition_lease_second_owner_is_busy_while_first_is_live() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let ident = identity(TENANT, "CARD", 1002);
    cleanup_partition(&pool, TENANT, 1002).await;

    let first = acquire_partition_lease(&pool, &ident, "worker-a", 300)
        .await
        .expect("acquire")
        .expect("first owner acquires");
    // A live lease held by another owner is BUSY: skip, never wait, never steal.
    let second = acquire_partition_lease(&pool, &ident, "worker-b", 300)
        .await
        .expect("acquire probe must not error");
    assert!(second.is_none(), "live foreign lease must be Busy");
    let (owner, _, _) = lease_row(&pool, TENANT, 1002)
        .await
        .expect("lease row still first owner's");
    assert_eq!(owner, "worker-a");

    release_partition_lease(&pool, &first)
        .await
        .expect("release");
    // After release the partition is free again.
    let reclaimed = acquire_partition_lease(&pool, &ident, "worker-b", 300)
        .await
        .expect("acquire after release")
        .expect("released partition must be acquirable");
    assert_eq!(reclaimed.lease_owner, "worker-b");
    release_partition_lease(&pool, &reclaimed)
        .await
        .expect("release second owner");
    let repeated_owner = acquire_partition_lease(&pool, &ident, "worker-a", 300)
        .await
        .expect("acquire same owner after a completed episode")
        .expect("released partition must be acquirable");
    release_partition_lease(&pool, &repeated_owner)
        .await
        .expect("release repeated owner");
    let audit_rows = partition_lease_audit_rows(&pool, TENANT, 1002).await;
    assert_eq!(
        partition_lease_audit_actions(&pool, TENANT, 1002).await,
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
    cleanup_partition(&pool, TENANT, 1002).await;
}

#[tokio::test]
#[ignore = "real MySQL integration; RUST_INTEGRATION_REQUIRED=1 DATABASE_URL=..."]
async fn partition_lease_expired_lease_is_taken_over_with_generation_bump() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let ident = identity(TENANT, "CARD", 1003);
    cleanup_partition(&pool, TENANT, 1003).await;

    // One-second lease: the original owner abandons the partition (crash
    // simulation) without releasing.
    let abandoned = acquire_partition_lease(&pool, &ident, "worker-a", 1)
        .await
        .expect("acquire")
        .expect("first acquire");
    let (_, generation_before, _) = lease_row(&pool, TENANT, 1003)
        .await
        .expect("lease row after first acquire");
    // Keep the stale handle so the post-takeover CAS and best-effort release
    // paths can prove that a previous owner cannot affect the new holder.

    // Wait out the one-second window, then another worker must be able to
    // take the partition over (never blocked by a dead owner).
    tokio::time::sleep(std::time::Duration::from_millis(1300)).await;
    let takeover = acquire_partition_lease(&pool, &ident, "worker-b", 300)
        .await
        .expect("acquire after expiry")
        .expect("expired lease must be reclaimable");
    assert_eq!(takeover.lease_owner, "worker-b");
    let (_, generation_after, _) = lease_row(&pool, TENANT, 1003)
        .await
        .expect("lease row after takeover");
    assert!(
        generation_after > generation_before,
        "takeover must bump generation: {generation_before} -> {generation_after}"
    );
    // The abandoned owner's stale handle cannot renew after takeover; the
    // failed CAS becomes a durable RENEW_LOST observation while the current
    // owner's successful heartbeat stays audit-free.
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
    let audit_actions_before_stale_release =
        partition_lease_audit_actions(&pool, TENANT, 1003).await;
    assert_eq!(
        audit_actions_before_stale_release,
        vec![
            "partition_lease_acquire",
            "partition_lease_reclaim",
            "partition_lease_renew_lost",
            "partition_lease_release",
        ]
    );
    // A stale owner cannot delete the successor's row. Its best-effort no-op
    // must not manufacture a second release observation; `RENEW_LOST` and
    // `RECLAIM` already record the meaningful fencing transition.
    release_partition_lease(&pool, &abandoned)
        .await
        .expect("stale release remains a best-effort no-op");
    assert_eq!(
        partition_lease_audit_actions(&pool, TENANT, 1003).await,
        audit_actions_before_stale_release,
        "stale release must not create an audit row"
    );
    let audit_rows = partition_lease_audit_rows(&pool, TENANT, 1003).await;
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
    assert_eq!(
        reclaim_detail["generation"], generation_after,
        "reclaim audit must report the durable post-takeover fence"
    );
    assert!(
        reclaim_detail["casVersion"]
            .as_i64()
            .is_some_and(|value| value >= 1),
        "reclaim audit must report a durable CAS version"
    );
    cleanup_partition(&pool, TENANT, 1003).await;
}

#[tokio::test]
#[ignore = "real MySQL integration; RUST_INTEGRATION_REQUIRED=1 DATABASE_URL=..."]
async fn concurrent_expired_reclaim_has_one_winner_without_duplicate_key_deadlock() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let ident = identity(TENANT, "CARD", 1004);
    cleanup_partition(&pool, TENANT, 1004).await;

    let abandoned = acquire_partition_lease(&pool, &ident, "worker-seed", 1)
        .await
        .expect("seed acquire")
        .expect("seed owner acquires");
    tokio::time::sleep(std::time::Duration::from_millis(1300)).await;

    let barrier = Arc::new(Barrier::new(3));
    let first_pool = pool.clone();
    let first_identity = ident.clone();
    let first_barrier = barrier.clone();
    let first = tokio::spawn(async move {
        first_barrier.wait().await;
        acquire_partition_lease(&first_pool, &first_identity, "worker-race-a", 300).await
    });
    let second_pool = pool.clone();
    let second_identity = ident.clone();
    let second_barrier = barrier.clone();
    let second = tokio::spawn(async move {
        second_barrier.wait().await;
        acquire_partition_lease(&second_pool, &second_identity, "worker-race-b", 300).await
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
        partition_lease_audit_actions(&pool, TENANT, 1004).await,
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
    cleanup_partition(&pool, TENANT, 1004).await;
}

#[tokio::test]
#[ignore = "real MySQL integration; RUST_INTEGRATION_REQUIRED=1 DATABASE_URL=..."]
async fn partition_discovery_returns_only_claimable_partitions() {
    let Some(pool) = test_pool().await else {
        return;
    };
    // Partition 2001: one due PENDING event -> discoverable.
    // Partition 2002: its ONLY event is parked in a backoff window
    // (`next_attempt_at` in the future) -> NOT discoverable: the eligibility
    // predicate mirrors the claim candidate, so a partition whose every event
    // is scheduled for later (e.g. the 898s budget-exhausted backoff) never
    // produces a discover-then-starve round. Note a same-grant blocked
    // successor cannot make a partition undiscoverable: the blocked row's
    // chain head is itself claimable, so the partition stays schedulable.
    cleanup_partition(&pool, TENANT, 2001).await;
    cleanup_partition(&pool, TENANT, 2002).await;
    seed_pending_event(
        &pool,
        TENANT,
        "CARD",
        2001,
        "aaaaaaaa-1111-4111-8111-cccccccccccc",
        "evt-disc-2001",
    )
    .await;
    seed_pending_event(
        &pool,
        TENANT,
        "CARD",
        2002,
        "bbbbbbbb-1111-4111-8111-cccccccccccc",
        "evt-disc-2002-backoff",
    )
    .await;
    sqlx::query(
        "UPDATE authorization_delta_event          SET next_attempt_at = TIMESTAMPADD(SECOND, 3600, UTC_TIMESTAMP())          WHERE event_id = 'evt-disc-2002-backoff'",
    )
    .execute(&pool)
    .await
    .expect("park event in a backoff window");

    let rows = discover_claimable_partitions(&pool, &[TENANT], 64)
        .await
        .expect("discovery query");
    let found: Vec<i64> = rows
        .iter()
        .filter(|row| row.tenant_id == TENANT)
        .map(|row| row.aggregate_id)
        .collect();
    assert!(
        found.contains(&2001),
        "claimable partition must be discovered: {found:?}"
    );
    assert!(
        !found.contains(&2002),
        "backoff-parked partition must NOT be discovered: {found:?}"
    );

    cleanup_partition(&pool, TENANT, 2001).await;
    cleanup_partition(&pool, TENANT, 2002).await;
}

#[tokio::test]
#[ignore = "real MySQL integration; RUST_INTEGRATION_REQUIRED=1 DATABASE_URL=..."]
async fn partition_claim_installs_lease_and_respects_partition_boundary() {
    let Some(pool) = test_pool().await else {
        return;
    };
    seed_pending_event(
        &pool,
        TENANT,
        "CARD",
        3001,
        "cccccccc-1111-4111-8111-cccccccccccc",
        "evt-claim-3001",
    )
    .await;
    seed_pending_event(
        &pool,
        TENANT,
        "CARD",
        3002,
        "dddddddd-1111-4111-8111-cccccccccccc",
        "evt-claim-3002",
    )
    .await;

    // Holding partition 3001's lease, claim inside it: returns 3001's event
    // with an installed lease (LEASED, attempts bumped to the durable value 1).
    let handle = acquire_partition_lease(&pool, &identity(TENANT, "CARD", 3001), "worker-a", 300)
        .await
        .expect("acquire")
        .expect("claim partition must be free");
    let mut tx = pool.begin().await.expect("claim tx");
    let claim = claim_next_delta_event_in_partition_tx(
        &mut tx,
        astral_db::DeltaEventClaimScope {
            tenant_id: TENANT,
            card_id: None,
        },
        &identity(TENANT, "CARD", 3001),
        "worker-a",
        120,
    )
    .await
    .expect("partition claim")
    .expect("seeded event must be claimed");
    tx.commit().await.expect("claim commit");
    assert_eq!(claim.event_id, "evt-claim-3001");
    assert_eq!(claim.aggregate_id, 3001);
    assert_eq!(
        claim.attempts, 1,
        "install bumps the durable attempt counter"
    );
    assert_eq!(claim.lease_owner, "worker-a");

    // The other partition's row is untouched by the 3001 claim...
    let untouched: i64 =
        sqlx::query("SELECT COUNT(*) AS c FROM authorization_delta_event WHERE event_id = 'evt-claim-3002' AND status = 'PENDING'")
            .fetch_one(&pool)
            .await
            .expect("count query")
            .get("c");
    assert_eq!(untouched, 1, "foreign partition must stay PENDING");

    // ...and an EMPTY partition claims None without error.
    let mut tx = pool.begin().await.expect("empty-claim tx");
    let none = claim_next_delta_event_in_partition_tx(
        &mut tx,
        astral_db::DeltaEventClaimScope {
            tenant_id: TENANT,
            card_id: None,
        },
        &identity(TENANT, "CARD", 3999),
        "worker-a",
        120,
    )
    .await
    .expect("empty partition claim");
    tx.commit().await.expect("empty-claim commit");
    assert!(none.is_none(), "empty partition must claim None");

    release_partition_lease(&pool, &handle)
        .await
        .expect("release");
    cleanup_partition(&pool, TENANT, 3001).await;
    cleanup_partition(&pool, TENANT, 3002).await;
}

#[tokio::test]
#[ignore = "real MySQL integration; RUST_INTEGRATION_REQUIRED=1 DATABASE_URL=..."]
async fn pointer_advance_reclaims_parked_budget_exhausted_event() {
    let Some(pool) = test_pool().await else {
        return;
    };
    // The ~898s stall shape: a budget-exhausted loser parks ~15 minutes out
    // with the stable exhaustion marker. The E5 finding: while parked, the
    // partition is INVISIBLE to the scheduler (discovery mirrors claim
    // eligibility), so only rewriting the row itself can bring it back.
    cleanup_partition(&pool, TENANT, 4001).await;
    cleanup_partition(&pool, TENANT, 4002).await;
    seed_pending_event(
        &pool,
        TENANT,
        "CARD",
        4001,
        "eeeeeeee-1111-4111-8111-cccccccccccc",
        "evt-reclaim-4001",
    )
    .await;
    sqlx::query(
        "UPDATE authorization_delta_event          SET attempts = 6,              next_attempt_at = TIMESTAMPADD(SECOND, 900, UTC_TIMESTAMP()),              last_error = CONCAT('contention loser;', 'code=auth_projector.attempt_budget_exhausted', ';attempts=6')          WHERE event_id = 'evt-reclaim-4001'",
    )
    .execute(&pool)
    .await
    .expect("park the exhausted row");
    // Negative control: a plain parked row WITHOUT the exhaustion marker in a
    // sibling partition must never be touched by the reclaim.
    seed_pending_event(
        &pool,
        TENANT,
        "CARD",
        4002,
        "ffffffff-1111-4111-8111-cccccccccccc",
        "evt-reclaim-4002",
    )
    .await;
    sqlx::query(
        "UPDATE authorization_delta_event          SET next_attempt_at = TIMESTAMPADD(SECOND, 900, UTC_TIMESTAMP())          WHERE event_id = 'evt-reclaim-4002'",
    )
    .execute(&pool)
    .await
    .expect("park the plain row");

    // Before the pointer advance: both partitions are undiscoverable.
    let rows = discover_claimable_partitions(&pool, &[TENANT], 64)
        .await
        .expect("discovery before reclaim");
    assert!(
        !rows
            .iter()
            .any(|row| row.tenant_id == TENANT && row.aggregate_id == 4001),
        "parked exhausted partition must be undiscoverable before the pointer advance: {:?}",
        rows.iter().map(|row| row.aggregate_id).collect::<Vec<_>>()
    );

    // The pointer ADVANCES (durable publication) -> reclaim this partition.
    let reclaimed =
        astral_db::reclaim_budget_exhausted_events(&pool, &identity(TENANT, "CARD", 4001))
            .await
            .expect("reclaim");
    assert_eq!(
        reclaimed, 1,
        "exactly the marked parked row is pulled forward"
    );

    // After the reclaim the partition is discoverable and claimable again;
    // `attempts` stays authoritative (6 -> 7 on the next install).
    let rows = discover_claimable_partitions(&pool, &[TENANT], 64)
        .await
        .expect("discovery after reclaim");
    assert!(
        rows.iter()
            .any(|row| row.tenant_id == TENANT && row.aggregate_id == 4001),
        "reclaimed partition must be discoverable"
    );
    let mut tx = pool.begin().await.expect("claim tx");
    let claim = claim_next_delta_event_in_partition_tx(
        &mut tx,
        astral_db::DeltaEventClaimScope {
            tenant_id: TENANT,
            card_id: None,
        },
        &identity(TENANT, "CARD", 4001),
        "worker-a",
        120,
    )
    .await
    .expect("claim after reclaim")
    .expect("reclaimed event must be claimable");
    tx.commit().await.expect("claim commit");
    assert_eq!(claim.event_id, "evt-reclaim-4001");
    assert_eq!(
        claim.attempts, 7,
        "install bumps the durable attempt counter"
    );

    // The sibling WITHOUT the marker is untouched: reclaim on its partition
    // pulls zero rows and the row stays parked in the future window.
    let untouched =
        astral_db::reclaim_budget_exhausted_events(&pool, &identity(TENANT, "CARD", 4002))
            .await
            .expect("reclaim on non-exhausted partition");
    assert_eq!(
        untouched, 0,
        "rows without the exhaustion marker match nothing"
    );
    let still_parked: i64 = sqlx::query(
        "SELECT COUNT(*) AS c FROM authorization_delta_event          WHERE event_id = 'evt-reclaim-4002'            AND next_attempt_at > UTC_TIMESTAMP()",
    )
    .fetch_one(&pool)
    .await
    .expect("parked count")
    .get("c");
    assert_eq!(still_parked, 1, "the non-exhausted row keeps its backoff");

    cleanup_partition(&pool, TENANT, 4001).await;
    cleanup_partition(&pool, TENANT, 4002).await;
}
