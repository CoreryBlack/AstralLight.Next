//! Bounded real-MySQL load tests for local message append and claim ordering.
//!
//! Requires an already-migrated isolated MySQL database. These tests never
//! create schema and are selected explicitly by the campaign manifest.

use astral_db::{
    connect_and_validate_schema_with_pool_options, LocalMessageAppend, LocalMessageError,
    LocalMessageExactClaim, LocalMessageInput, LocalMessageRepository,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{mysql::MySqlConnectOptions, MySqlPool};
use std::{
    collections::HashMap,
    env,
    str::FromStr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::sync::Barrier;
use uuid::Uuid;

const QUEUE: &str = "astral.authorization.invalidation";
const PRODUCERS: usize = 24;
const MESSAGES_PER_PRODUCER: usize = 12;
const CLAIM_DEADLINE: Duration = Duration::from_secs(45);
const REQUIRED_MIGRATIONS: &[&str] = &["20260929000001", "20261001000005"];

async fn connect() -> MySqlPool {
    assert_eq!(
        env::var("TEST_USE_EXISTING").as_deref(),
        Ok("1"),
        "the campaign must use an approved existing isolated database"
    );
    assert_eq!(
        env::var("ASTRAL_MIGRATION_ENV").as_deref(),
        Ok("isolated"),
        "ASTRAL_MIGRATION_ENV=isolated is required"
    );
    assert_eq!(
        env::var("RUST_INTEGRATION_REQUIRED").as_deref(),
        Ok("1"),
        "RUST_INTEGRATION_REQUIRED=1 is required"
    );
    let url = env::var("DATABASE_URL").expect("DATABASE_URL is required");
    assert!(
        !url.contains('?') && !url.contains('#'),
        "DATABASE_URL query parameters and fragments are not allowed"
    );
    let expected_database = env::var("ASTRAL_TEST_DATABASE_NAME")
        .expect("ASTRAL_TEST_DATABASE_NAME must be explicitly configured");
    let run_suffix = expected_database
        .strip_prefix("astral_rehearsal_")
        .expect("test database must use the astral_rehearsal_ prefix");
    assert!(
        !run_suffix.is_empty()
            && run_suffix.len() <= 47
            && run_suffix
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'),
        "test database must have a valid run-scoped suffix"
    );
    let options = MySqlConnectOptions::from_str(&url).expect("DATABASE_URL must parse");
    assert!(
        matches!(options.get_host(), "localhost" | "127.0.0.1"),
        "stress tests may only connect to loopback MySQL"
    );
    assert_eq!(options.get_port(), 3308, "unexpected MySQL port");
    assert!(
        options.get_socket().is_none(),
        "Unix socket URLs are not allowed"
    );
    assert_eq!(
        options.get_database(),
        Some(expected_database.as_str()),
        "DATABASE_URL must select the explicitly approved test database"
    );

    let pool = connect_and_validate_schema_with_pool_options(&url, 40, Duration::from_secs(10))
        .await
        .expect("isolated MySQL schema validation must succeed");
    let migrations: Vec<String> = sqlx::query_scalar(
        "SELECT CAST(version AS CHAR) FROM _sqlx_migrations WHERE success = TRUE ORDER BY version",
    )
    .fetch_all(&pool)
    .await
    .expect("read applied Rust migrations");
    for required in REQUIRED_MIGRATIONS {
        assert!(
            migrations
                .iter()
                .any(|version| version.starts_with(required)),
            "required migration {required} must already be applied"
        );
    }
    for table in ["al_message_outbox", "al_message_scope_counter"] {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM information_schema.TABLES \
             WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?",
        )
        .bind(table)
        .fetch_one(&pool)
        .await
        .expect("check required outbox tables");
        assert_eq!(count, 1, "required table {table} must exist");
    }
    pool
}

struct TestMessage {
    message_id: String,
    operation_id: String,
    ordering_key: String,
    envelope_json: String,
    payload_sha256: String,
}

impl TestMessage {
    fn new(message_id: String, operation_id: String, ordering_key: String, payload: Value) -> Self {
        let payload_sha256 = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&payload).unwrap())
        );
        let envelope_json = serde_json::to_string(&json!({
            "messageId": message_id,
            "operationId": operation_id,
            "messageType": "LOCAL_OUTBOX_STRESS",
            "schemaVersion": 1,
            "tenantId": null,
            "originRegion": "integration",
            "targetRegion": null,
            "orderingKey": ordering_key,
            "traceId": null,
            "createdAt": "2026-10-12T00:00:00Z",
            "expiresAt": null,
            "payloadSha256": payload_sha256,
            "payload": payload,
        }))
        .unwrap();
        Self {
            message_id,
            operation_id,
            ordering_key,
            envelope_json,
            payload_sha256,
        }
    }

    fn input(&self) -> LocalMessageInput<'_> {
        LocalMessageInput {
            message_id: &self.message_id,
            operation_id: &self.operation_id,
            message_type: "LOCAL_OUTBOX_STRESS",
            queue_name: QUEUE,
            ordering_key: Some(&self.ordering_key),
            tenant_id: None,
            origin_region: "integration",
            target_region: None,
            schema_version: 1,
            payload_json: &self.envelope_json,
            headers_json: None,
            payload_sha256: &self.payload_sha256,
        }
    }
}

async fn cleanup(pool: &MySqlPool, message_ids: &[String]) -> Result<(), sqlx::Error> {
    if message_ids.is_empty() {
        return Ok(());
    }
    let placeholders = std::iter::repeat_n("?", message_ids.len())
        .collect::<Vec<_>>()
        .join(",");
    let statement = format!("DELETE FROM al_message_outbox WHERE message_id IN ({placeholders})");
    let mut query = sqlx::query(&statement);
    for message_id in message_ids {
        query = query.bind(message_id);
    }
    let result = query.execute(pool).await?;
    assert_eq!(
        result.rows_affected(),
        message_ids.len() as u64,
        "cleanup must remove exactly this run's outbox rows"
    );
    Ok(())
}

fn percentile(samples: &mut [u128], percentile: usize) -> u128 {
    samples.sort_unstable();
    let index = samples.len().saturating_sub(1) * percentile / 100;
    samples[index]
}

#[ignore = "requires isolated migrated MySQL and the local outbox/scope-sequence tables"]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn duplicate_append_is_idempotent_under_concurrency() {
    let pool = connect().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let message = Arc::new(TestMessage::new(
        format!("stress-duplicate-{suffix}"),
        format!("op-duplicate-{suffix}"),
        format!("integration:duplicate-append:{suffix}"),
        json!({"event": "duplicate-append", "run": suffix}),
    ));
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let pool = pool.clone();
        let barrier = barrier.clone();
        let message = message.clone();
        tasks.push(tokio::spawn(async move {
            let repository = LocalMessageRepository::new(pool);
            barrier.wait().await;
            repository.append(&message.input()).await
        }));
    }
    let mut inserted = 0;
    let mut existing = 0;
    for task in tasks {
        match task.await.expect("append task") {
            Ok(LocalMessageAppend::Inserted) => inserted += 1,
            Ok(LocalMessageAppend::Existing) => existing += 1,
            Err(error) => panic!("identical concurrent append failed: {error}"),
        }
    }
    assert_eq!(inserted, 1);
    assert_eq!(existing, 15);

    let row: (String, String, Option<i64>) = sqlx::query_as(
        "SELECT message_id, status, scope_sequence FROM al_message_outbox WHERE message_id = ?",
    )
    .bind(&message.message_id)
    .fetch_one(&pool)
    .await
    .expect("load idempotent row");
    let scope_key = format!("{QUEUE}\u{1f}{}", message.ordering_key);
    let before: i64 = sqlx::query_scalar(
        "SELECT last_sequence FROM al_message_scope_counter WHERE scope_key = ?",
    )
    .bind(&scope_key)
    .fetch_one(&pool)
    .await
    .expect("read scope high watermark");
    assert_eq!(row.2, Some(1));
    assert_eq!(before, 1, "identical retries must allocate one sequence");

    let conflict = TestMessage::new(
        message.message_id.clone(),
        message.operation_id.clone(),
        message.ordering_key.clone(),
        json!({"event": "different", "run": suffix}),
    );
    assert!(matches!(
        LocalMessageRepository::new(pool.clone())
            .append(&conflict.input())
            .await,
        Err(LocalMessageError::PayloadConflict)
    ));
    let metadata_conflict = TestMessage::new(
        message.message_id.clone(),
        format!("{}-different", message.operation_id),
        message.ordering_key.clone(),
        json!({"event": "duplicate-append", "run": suffix}),
    );
    assert!(matches!(
        LocalMessageRepository::new(pool.clone())
            .append(&metadata_conflict.input())
            .await,
        Err(LocalMessageError::PayloadConflict)
    ));
    let after: i64 = sqlx::query_scalar(
        "SELECT last_sequence FROM al_message_scope_counter WHERE scope_key = ?",
    )
    .bind(&scope_key)
    .fetch_one(&pool)
    .await
    .expect("read unchanged scope high watermark");
    assert_eq!(after, before);
    let preserved: (String, String, Option<i64>) = sqlx::query_as(
        "SELECT operation_id,payload_sha256,scope_sequence FROM al_message_outbox WHERE message_id = ?",
    )
    .bind(&message.message_id)
    .fetch_one(&pool)
    .await
    .expect("verify conflicting retries did not alter original row");
    assert_eq!(preserved.0, message.operation_id);
    assert_eq!(preserved.1, message.payload_sha256);
    assert_eq!(preserved.2, Some(1));
    cleanup(&pool, std::slice::from_ref(&message.message_id))
        .await
        .expect("clean run-owned row");
    let remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM al_message_outbox WHERE message_id = ?")
            .bind(&message.message_id)
            .fetch_one(&pool)
            .await
            .expect("prove duplicate test row cleanup");
    assert_eq!(remaining, 0);
    let retained: i64 = sqlx::query_scalar(
        "SELECT last_sequence FROM al_message_scope_counter WHERE scope_key = ?",
    )
    .bind(&scope_key)
    .fetch_one(&pool)
    .await
    .expect("verify high watermark remains after cleanup");
    assert_eq!(retained, before);
}

#[ignore = "requires isolated migrated MySQL; bounded append and claim load only"]
#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
async fn scoped_append_and_claim_load_preserves_sequence_and_fifo() {
    let pool = connect().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let scope_count = 4usize;
    let total = PRODUCERS * MESSAGES_PER_PRODUCER;
    let ordering_keys = (0..scope_count)
        .map(|scope| format!("integration:append-stress:{suffix}:{scope}"))
        .collect::<Vec<_>>();
    let rows = Arc::new(
        (0..total)
            .map(|index| {
                let producer = index / MESSAGES_PER_PRODUCER;
                let scope = if producer < PRODUCERS / 2 {
                    0
                } else {
                    1 + (producer - PRODUCERS / 2) % (scope_count - 1)
                };
                Arc::new(TestMessage::new(
                    format!("stress-{suffix}-{index:04}"),
                    format!("op-stress-{suffix}-{index:04}"),
                    ordering_keys[scope].clone(),
                    json!({
                        "event": "append-stress",
                        "run": suffix,
                        "index": index,
                        "producer": producer
                    }),
                ))
            })
            .collect::<Vec<_>>(),
    );
    let ids = rows
        .iter()
        .map(|row| row.message_id.clone())
        .collect::<Vec<_>>();
    let barrier = Arc::new(Barrier::new(PRODUCERS));
    let append_started = Instant::now();
    let mut tasks = Vec::new();
    for producer in 0..PRODUCERS {
        let pool = pool.clone();
        let rows = rows.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            let repository = LocalMessageRepository::new(pool);
            let mut durations = Vec::new();
            barrier.wait().await;
            for offset in 0..MESSAGES_PER_PRODUCER {
                let index = producer * MESSAGES_PER_PRODUCER + offset;
                let started = Instant::now();
                let outcome = repository.append(&rows[index].input()).await;
                durations.push(started.elapsed().as_micros());
                assert_eq!(
                    outcome.expect("append stress row"),
                    LocalMessageAppend::Inserted
                );
            }
            durations
        }));
    }
    let mut append_latencies = Vec::with_capacity(total);
    for task in tasks {
        append_latencies.extend(task.await.expect("append producer"));
    }
    let append_elapsed = append_started.elapsed();

    let mut expected_by_scope = HashMap::<String, usize>::new();
    for message in rows.iter() {
        *expected_by_scope
            .entry(message.ordering_key.clone())
            .or_default() += 1;
    }
    let mut sequences_by_scope = HashMap::<String, Vec<i64>>::new();
    let sequence_rows: Vec<(String, String, Option<i64>)> = sqlx::query_as(
        "SELECT message_id, ordering_key, scope_sequence FROM al_message_outbox WHERE message_id LIKE ?",
    )
    .bind(format!("stress-{suffix}-%"))
    .fetch_all(&pool)
    .await
    .expect("read allocated scope sequences");
    assert_eq!(sequence_rows.len(), total);
    for (message_id, ordering_key, sequence) in sequence_rows {
        let index: usize = message_id
            .rsplit('-')
            .next()
            .expect("message index")
            .parse()
            .expect("numeric message index");
        assert_eq!(ordering_key, rows[index].ordering_key);
        sequences_by_scope
            .entry(ordering_key)
            .or_default()
            .push(sequence.expect("scoped append sequence"));
    }
    assert_eq!(
        sequences_by_scope
            .iter()
            .map(|(scope, rows)| (scope.clone(), rows.len()))
            .collect::<HashMap<_, _>>(),
        expected_by_scope
            .iter()
            .map(|(scope, count)| (scope.clone(), *count))
            .collect::<HashMap<_, _>>()
    );
    assert_eq!(expected_by_scope[&ordering_keys[0]], total / 2);
    for (scope, sequences) in &mut sequences_by_scope {
        sequences.sort_unstable();
        let expected = expected_by_scope[scope];
        assert_eq!(sequences.len(), expected);
        assert_eq!(sequences, &(1..=expected as i64).collect::<Vec<_>>());
    }

    let completed = Arc::new(AtomicUsize::new(0));
    let claim_started = Instant::now();
    let mut claim_tasks = Vec::new();
    for (scope, ordering_key) in ordering_keys.iter().cloned().enumerate() {
        let pool = pool.clone();
        let rows = rows.clone();
        let completed = completed.clone();
        claim_tasks.push(tokio::spawn(async move {
            let repository = LocalMessageRepository::new(pool.clone());
            let owner = format!("stress-claim-{scope}");
            let mut claimed = Vec::new();
            let mut durations = Vec::new();
            let mut last_sequence = 0;
            let deadline = Instant::now() + CLAIM_DEADLINE;
        let scope_ids = rows
            .iter()
            .filter(|message| message.ordering_key == ordering_key)
            .map(|message| message.message_id.clone())
            .collect::<Vec<_>>();

            let placeholders = std::iter::repeat_n("?", scope_ids.len())
                .collect::<Vec<_>>()
                .join(",");
            let statement = format!(
                "SELECT message_id,scope_sequence FROM al_message_outbox WHERE message_id IN ({placeholders}) ORDER BY scope_sequence"
            );
            let mut query = sqlx::query_as::<_, (String, i64)>(&statement);
            for id in &scope_ids {
                query = query.bind(id);
            }
            let ordered_ids = query
                .fetch_all(&pool)
                .await
                .expect("load exact scope claim order");
            assert_eq!(ordered_ids.len(), scope_ids.len());
            let tail_id = &ordered_ids.last().expect("scope has messages").0;
            let tail = repository
                .claim_exact(&owner, QUEUE, tail_id)
                .await
                .expect("probe out-of-order exact claim");
            assert!(matches!(
                tail,
                LocalMessageExactClaim::NotClaimable { ref reason, .. }
                    if reason.contains("FIFO blocked")
            ));
            for (message_id, expected_sequence) in ordered_ids {
                assert!(Instant::now() < deadline, "claim drain exceeded bounded deadline");
                assert_eq!(expected_sequence, last_sequence + 1);
                let competitor = repository.clone();
                let racer = format!("{owner}-racer");
                let started = Instant::now();
                let (first, second) = tokio::join!(
                    repository.claim_exact(&owner, QUEUE, &message_id),
                    competitor.claim_exact(&racer, QUEUE, &message_id),
                );
                durations.push(started.elapsed().as_micros());
                let (claimed_row, losing_result) = match (first, second) {
                    (Ok(LocalMessageExactClaim::Claimed(row)), Ok(other))
                    | (Ok(other), Ok(LocalMessageExactClaim::Claimed(row))) => (row, other),
                    pair => panic!("one exact claimant must own the row: {pair:?}"),
                };
                assert!(matches!(
                    losing_result,
                    LocalMessageExactClaim::NotClaimable { .. }
                ));
                let token = claimed_row.lease_owner.clone().expect("claim token");
                claimed.push((
                    claimed_row.message_id.clone(),
                    ordering_key.clone(),
                    expected_sequence,
                    claimed.len(),
                ));
                repository
                    .complete(&claimed_row.message_id, &token)
                    .await
                    .expect("complete claimed row");
                last_sequence = expected_sequence;
                completed.fetch_add(1, Ordering::AcqRel);
            }
            (claimed, durations)
        }));
    }
    let mut claims = Vec::with_capacity(total);
    let mut claim_latencies = Vec::new();
    for task in claim_tasks {
        let (worker_claims, durations) = task.await.expect("scope claim worker");
        claims.extend(worker_claims);
        claim_latencies.extend(durations);
    }
    let claim_elapsed = claim_started.elapsed();
    assert_eq!(completed.load(Ordering::Acquire), total);
    assert_eq!(claims.len(), total);
    let mut claimed_ids = claims
        .iter()
        .map(|claim| claim.0.clone())
        .collect::<Vec<_>>();
    claimed_ids.sort();
    let mut expected_ids = ids.clone();
    expected_ids.sort();
    assert_eq!(
        claimed_ids, expected_ids,
        "each run-owned message must have one successful claimant"
    );

    let mut claim_sequences = HashMap::<String, Vec<(usize, i64)>>::new();
    for (_, ordering_key, sequence, order) in &claims {
        claim_sequences
            .entry(ordering_key.clone())
            .or_default()
            .push((*order, *sequence));
    }
    for scope_claims in claim_sequences.values_mut() {
        scope_claims.sort_unstable_by_key(|(order, _)| *order);
        assert!(scope_claims.windows(2).all(|pair| pair[0].1 < pair[1].1));
    }

    let placeholders = std::iter::repeat_n("?", ids.len())
        .collect::<Vec<_>>()
        .join(",");
    let statement = format!(
        "SELECT message_id,status FROM al_message_outbox WHERE message_id IN ({placeholders})"
    );
    let mut query = sqlx::query_as::<_, (String, String)>(&statement);
    for id in &ids {
        query = query.bind(id);
    }
    let statuses = query
        .fetch_all(&pool)
        .await
        .expect("read terminal stress rows");
    assert_eq!(statuses.len(), total);
    assert!(statuses.iter().all(|(_, status)| status == "PROCESSED"));

    println!(
        "local-message load: messages={total} scopes={scope_count} producers={PRODUCERS} claimers={scope_count} competing_claimers_per_message=2 append_msg_s={:.1} claim_msg_s={:.1} append_us_p50={} append_us_p95={} append_us_p99={} claim_us_p50={} claim_us_p95={} claim_us_p99={}",
        total as f64 / append_elapsed.as_secs_f64(),
        total as f64 / claim_elapsed.as_secs_f64(),
        percentile(&mut append_latencies, 50),
        percentile(&mut append_latencies, 95),
        percentile(&mut append_latencies, 99),
        percentile(&mut claim_latencies, 50),
        percentile(&mut claim_latencies, 95),
        percentile(&mut claim_latencies, 99),
    );
    cleanup(&pool, &ids)
        .await
        .expect("clean run-owned outbox rows");
    let placeholders = std::iter::repeat_n("?", ids.len())
        .collect::<Vec<_>>()
        .join(",");
    let statement =
        format!("SELECT COUNT(*) FROM al_message_outbox WHERE message_id IN ({placeholders})");
    let mut query = sqlx::query_scalar::<_, i64>(&statement);
    for id in &ids {
        query = query.bind(id);
    }
    let remaining = query
        .fetch_one(&pool)
        .await
        .expect("prove all load rows were cleaned");
    assert_eq!(remaining, 0);
    for (scope, expected) in &expected_by_scope {
        let scope_key = format!("{QUEUE}\u{1f}{scope}");
        let retained: i64 = sqlx::query_scalar(
            "SELECT last_sequence FROM al_message_scope_counter WHERE scope_key = ?",
        )
        .bind(scope_key)
        .fetch_one(&pool)
        .await
        .expect("verify per-scope high watermark remains after cleanup");
        assert_eq!(retained, *expected as i64);
    }
}
