//! Real MySQL + RabbitMQ audit replay integration coverage.
//!
//! The test is intentionally ignored. With `RUST_INTEGRATION_REQUIRED=1`, missing
//! services or an unmigrated schema fail the test instead of being reported as a
//! pass. The database URL is validated against the already-migrated schema; this
//! test never reads application.yml or executes DDL.
//!
//! Run after the explicit migration job has completed:
//!
//! ```text
//! cargo run -p astral-db --bin astral-migrate
//! RUST_INTEGRATION_REQUIRED=1 DATABASE_URL=... RABBITMQ_URL=... \
//!   cargo test -p astral-trustgraph --test audit_replay_integration -- --ignored --nocapture
//! ```

use std::time::{Duration, Instant};

use astral_db::{
    begin_next_expired_replaying_replay, begin_replay, connect_and_validate_schema,
    fail_replay_claim, get_quarantine_metadata_by_id, insert_or_increment_terminal, request_replay,
    AuditQuarantineInput, AuditQuarantineMetadata, AuditQuarantineStatus,
};
use astral_mq::config::{
    declare_all, EXCHANGE_DIRECT, HEADER_DEATH, HEADER_DLQ_REPUBLISH_COUNT, HEADER_RETRY_COUNT,
    QUEUE_AUDIT_LOG,
};
use astral_mq::producer::{AuditLogPayload, MqMessage, Producer, RawReplayError, RawReplayRequest};
use astral_trustgraph::service::audit_replay_worker::{start_worker, AuditReplayProducerSlot};
use futures_util::StreamExt;
use lapin::options::{BasicAckOptions, BasicConsumeOptions, QueueBindOptions, QueueDeclareOptions};
use lapin::types::{FieldTable, ShortString};
use lapin::{BasicProperties, Connection, ConnectionProperties};
use sqlx::MySqlPool;
use tokio::time::timeout;
use uuid::Uuid;

const ROUTING_KEY: &str = "audit.log";
const MESSAGE_TYPE: &str = "AUDIT_LOG";
const REPLAY_ACTOR_ID: &str = "7901";
const TEST_TIMEOUT: Duration = Duration::from_secs(20);

fn required() -> bool {
    std::env::var("RUST_INTEGRATION_REQUIRED").as_deref() == Ok("1")
}

fn required_env(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => Some(value),
        Ok(_) | Err(_) => {
            let message = format!("{name} must be set for replay integration tests");
            if required() {
                panic!("RUST_INTEGRATION_REQUIRED=1: {message}");
            }
            eprintln!("[SKIP] {message}");
            None
        }
    }
}

struct RabbitHarness {
    connection: Connection,
    channel: lapin::Channel,
    consumer_connection: Connection,
    consumer_channel: lapin::Channel,
    capture_consumer: lapin::Consumer,
}

async fn connect_harness(pool: &MySqlPool) -> Option<RabbitHarness> {
    let _database_url = required_env("DATABASE_URL")?;
    let rabbitmq_url = required_env("RABBITMQ_URL")?;
    if let Err(error) = astral_mq::consumer::init_idempotency_db(pool.clone()).await {
        if required() {
            panic!("RUST_INTEGRATION_REQUIRED=1: durable DB lease setup failed: {error}");
        }
        eprintln!("[SKIP] durable DB lease setup failed: {error}");
        return None;
    }

    // The caller validates this already-migrated schema before creating the
    // RabbitMQ harness; this helper never executes DDL.
    let connection = match Connection::connect(&rabbitmq_url, ConnectionProperties::default()).await
    {
        Ok(connection) => connection,
        Err(error) => {
            if required() {
                panic!("RUST_INTEGRATION_REQUIRED=1: RabbitMQ connection failed: {error}");
            }
            eprintln!("[SKIP] RabbitMQ connection failed: {error}");
            return None;
        }
    };
    let channel = match connection.create_channel().await {
        Ok(channel) => channel,
        Err(error) => {
            if required() {
                panic!("RUST_INTEGRATION_REQUIRED=1: RabbitMQ channel failed: {error}");
            }
            eprintln!("[SKIP] RabbitMQ channel failed: {error}");
            return None;
        }
    };
    if let Err(error) = Producer::enable_confirms(&channel).await {
        if required() {
            panic!("RUST_INTEGRATION_REQUIRED=1: publisher confirms failed: {error}");
        }
        eprintln!("[SKIP] publisher confirms failed: {error}");
        return None;
    }
    if let Err(error) = declare_all(&channel).await {
        if required() {
            panic!("RUST_INTEGRATION_REQUIRED=1: canonical topology declaration failed: {error}");
        }
        eprintln!("[SKIP] canonical topology declaration failed: {error}");
        return None;
    }

    // A private queue receives a copy of the canonical audit route. The actual
    // TrustGraph audit consumer continues to consume astral.audit.log below.
    let capture_queue = match channel
        .queue_declare(
            "".into(),
            QueueDeclareOptions {
                exclusive: true,
                auto_delete: true,
                ..QueueDeclareOptions::default()
            },
            FieldTable::default(),
        )
        .await
    {
        Ok(queue) => queue.name().to_string(),
        Err(error) => {
            if required() {
                panic!("RUST_INTEGRATION_REQUIRED=1: test queue declaration failed: {error}");
            }
            eprintln!("[SKIP] test queue declaration failed: {error}");
            return None;
        }
    };
    if let Err(error) = channel
        .queue_bind(
            ShortString::from(capture_queue.as_str()),
            ShortString::from(EXCHANGE_DIRECT),
            ShortString::from(ROUTING_KEY),
            QueueBindOptions::default(),
            FieldTable::default(),
        )
        .await
    {
        if required() {
            panic!("RUST_INTEGRATION_REQUIRED=1: test queue binding failed: {error}");
        }
        eprintln!("[SKIP] test queue binding failed: {error}");
        return None;
    }
    let capture_consumer = match channel
        .basic_consume(
            ShortString::from(capture_queue.as_str()),
            ShortString::from(format!("replay_capture_{}", Uuid::new_v4().simple())),
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await
    {
        Ok(consumer) => consumer,
        Err(error) => {
            if required() {
                panic!("RUST_INTEGRATION_REQUIRED=1: test consumer startup failed: {error}");
            }
            eprintln!("[SKIP] test consumer startup failed: {error}");
            return None;
        }
    };

    // The audit consumer proves business completion in mq_idempotent_log and
    // audit_log; its processing lease is held in MySQL mq_consumer_lease.
    let consumer_connection =
        match Connection::connect(&rabbitmq_url, ConnectionProperties::default()).await {
            Ok(connection) => connection,
            Err(error) => {
                if required() {
                    panic!(
                        "RUST_INTEGRATION_REQUIRED=1: audit consumer connection failed: {error}"
                    );
                }
                eprintln!("[SKIP] audit consumer connection failed: {error}");
                return None;
            }
        };
    let consumer_channel = match consumer_connection.create_channel().await {
        Ok(channel) => channel,
        Err(error) => {
            if required() {
                panic!("RUST_INTEGRATION_REQUIRED=1: audit consumer channel failed: {error}");
            }
            eprintln!("[SKIP] audit consumer channel failed: {error}");
            return None;
        }
    };
    astral_mq::consumers::set_audit_log_db(pool.clone());
    if let Err(error) = astral_mq::consumers::start_audit_log_consumer(&consumer_channel).await {
        if required() {
            panic!("RUST_INTEGRATION_REQUIRED=1: audit consumer startup failed: {error}");
        }
        eprintln!("[SKIP] audit consumer startup failed: {error}");
        return None;
    }

    Some(RabbitHarness {
        connection,
        channel,
        consumer_connection,
        consumer_channel,
        capture_consumer,
    })
}

fn unique_message_id(label: &str) -> String {
    format!("replay-integration-{label}-{}", Uuid::new_v4().simple())
}

fn request_id_for(message_id: &str) -> String {
    // audit_log.request_id is VARCHAR(64); preserve the stable message-id
    // suffix while keeping the correlation id within that existing contract.
    const PREFIX: &str = "replay-";
    const MAX_BYTES: usize = 64;
    let suffix_len = MAX_BYTES - PREFIX.len();
    let suffix_start = message_id.len().saturating_sub(suffix_len);
    let suffix_start = message_id
        .char_indices()
        .find_map(|(index, _)| (index >= suffix_start).then_some(index))
        .unwrap_or(0);
    format!("{PREFIX}{}", &message_id[suffix_start..])
}

fn audit_envelope(message_id: &str, request_id: &str) -> Vec<u8> {
    let payload = AuditLogPayload {
        message_id: Some(message_id.to_owned()),
        user_id: Some(7_901),
        card_id: Some(7_902),
        action: "replay-read".to_owned(),
        resource: "audit_log".to_owned(),
        decision: "ALLOW".to_owned(),
        reason: Some("replay integration test".to_owned()),
        event_type: "PERMISSION_CHECK".to_owned(),
        source_ip: Some("127.0.0.1".to_owned()),
        request_id: Some(request_id.to_owned()),
        domain_id: Some(7_903),
        tenant_id: Some(7_904),
        detail: None,
    };
    let envelope = MqMessage {
        message_id: message_id.to_owned(),
        timestamp: "2026-01-01T00:00:00Z".to_owned(),
        payload,
    };
    serde_json::to_vec(&envelope).expect("audit envelope must serialize")
}

fn quarantine_input(
    message_id: &str,
    raw_payload: Vec<u8>,
    source_routing_key: &str,
) -> AuditQuarantineInput {
    AuditQuarantineInput {
        source_queue: QUEUE_AUDIT_LOG.to_owned(),
        message_type: MESSAGE_TYPE.to_owned(),
        canonical_message_id: Some(message_id.to_owned()),
        raw_payload,
        source_exchange: EXCHANGE_DIRECT.to_owned(),
        source_routing_key: source_routing_key.to_owned(),
        retry_count: 3,
        failure_reason: "integration-terminal-failure".to_owned(),
    }
}

async fn wait_for_status(
    pool: &MySqlPool,
    id: i64,
    expected: AuditQuarantineStatus,
) -> AuditQuarantineMetadata {
    wait_for_row(pool, id, |row| row.status == expected).await
}

async fn wait_for_failed_replay(
    pool: &MySqlPool,
    id: i64,
    expected_reason: &str,
) -> AuditQuarantineMetadata {
    wait_for_row(pool, id, |row| {
        row.status == AuditQuarantineStatus::Quarantined
            && row.replay_attempts > 0
            && row.failure_reason == expected_reason
    })
    .await
}

async fn wait_for_row<F>(pool: &MySqlPool, id: i64, ready: F) -> AuditQuarantineMetadata
where
    F: Fn(&AuditQuarantineMetadata) -> bool,
{
    let deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        let row = get_quarantine_metadata_by_id(pool, id)
            .await
            .expect("quarantine metadata query must succeed")
            .expect("quarantine row must remain present");
        if ready(&row) {
            return row;
        }
        assert!(
            Instant::now() < deadline,
            "quarantine row {id} did not reach the expected state (last status={}, replay_attempts={}, failure_reason={})",
            row.status.as_str(),
            row.replay_attempts,
            row.failure_reason
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_audit_evidence(pool: &MySqlPool, message_id: &str, request_id: &str) {
    let deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        let idempotency: Option<(String,)> = sqlx::query_as(
            "SELECT status FROM mq_idempotent_log \
             WHERE message_type = ? AND message_id = ?",
        )
        .bind(MESSAGE_TYPE)
        .bind(message_id)
        .fetch_optional(pool)
        .await
        .expect("idempotency evidence query must succeed");
        let lease_status: Option<String> = sqlx::query_scalar(
            "SELECT status FROM mq_consumer_lease WHERE message_type = ? AND message_id = ?",
        )
        .bind(MESSAGE_TYPE)
        .bind(message_id)
        .fetch_optional(pool)
        .await
        .expect("durable processing lease query must succeed");
        let audit_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log \
             WHERE request_id = ? AND event_type = 'PERMISSION_CHECK'",
        )
        .bind(request_id)
        .fetch_one(pool)
        .await
        .expect("audit evidence query must succeed");
        if idempotency
            .as_ref()
            .is_some_and(|(status,)| status == "PROCESSED")
            && audit_count == 1
            && lease_status.as_deref() == Some("COMPLETED")
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "audit consumer evidence missing for message_id={message_id}: \
             idempotency={idempotency:?}, audit_count={audit_count}, lease={lease_status:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn delete_test_rows(pool: &MySqlPool, quarantine_ids: &[i64], message_ids: &[&str]) {
    for id in quarantine_ids {
        sqlx::query("DELETE FROM audit_quarantine WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await
            .expect("quarantine cleanup must succeed");
    }
    for message_id in message_ids {
        sqlx::query(
            "DELETE FROM audit_log WHERE request_id = ? OR (event_type = 'AUDIT_REPLAY_REQUEST' AND request_id = ?)",
        )
        .bind(request_id_for(message_id))
        .bind(format!("op-{message_id}"))
        .execute(pool)
        .await
        .expect("audit cleanup must succeed");
        sqlx::query("DELETE FROM mq_idempotent_log WHERE message_type = ? AND message_id = ?")
            .bind(MESSAGE_TYPE)
            .bind(message_id)
            .execute(pool)
            .await
            .expect("idempotency cleanup must succeed");
        sqlx::query("DELETE FROM mq_consumer_lease WHERE message_type = ? AND message_id = ?")
            .bind(MESSAGE_TYPE)
            .bind(message_id)
            .execute(pool)
            .await
            .expect("test processing lease cleanup must succeed");
    }
}

async fn run_worker_once(
    pool: &MySqlPool,
    channel: &lapin::Channel,
    id: i64,
) -> AuditQuarantineMetadata {
    let producer = Producer::new(channel.clone());
    let slot = AuditReplayProducerSlot::new();
    assert!(
        slot.set(producer).await,
        "test producer slot must initialize once"
    );
    let worker = start_worker(pool.clone(), slot);
    let result = wait_for_status(pool, id, AuditQuarantineStatus::ReplayConfirmed).await;
    worker.cancellation.cancel();
    timeout(Duration::from_secs(3), worker.join)
        .await
        .expect("replay worker must stop after cancellation")
        .expect("replay worker task must join")
        .expect("replay worker must stop cleanly");
    result
}

#[tokio::test]
#[ignore = "requires migrated MySQL and RabbitMQ durable audit replay"]
async fn mysql_rabbit_audit_replay_real_integration() {
    let database_url = match required_env("DATABASE_URL") {
        Some(value) => value,
        None => return,
    };
    let pool = match connect_and_validate_schema(&database_url).await {
        Ok(pool) => pool,
        Err(error) => {
            if required() {
                panic!("RUST_INTEGRATION_REQUIRED=1: migrated schema validation failed: {error}");
            }
            eprintln!("[SKIP] migrated schema validation failed: {error}");
            return;
        }
    };
    let Some(mut harness) = timeout(TEST_TIMEOUT, connect_harness(&pool))
        .await
        .expect("Rabbit connection/topology setup exceeded its deadline")
    else {
        return;
    };

    let mut quarantine_ids = Vec::new();
    let mut message_ids = Vec::new();

    // Happy path: request_replay persists REPLAY_REQUESTED; the existing worker
    // claims REPLAYING and its publish_raw_replay returns Ok only for
    // Confirmation::Ack(None), after which the worker persists REPLAY_CONFIRMED.
    let happy_message_id = unique_message_id("happy");
    let happy_request_id = request_id_for(&happy_message_id);
    let happy_operation_id = format!("op-{happy_message_id}");
    let happy_payload = audit_envelope(&happy_message_id, &happy_request_id);
    let happy_row = insert_or_increment_terminal(
        &pool,
        &quarantine_input(&happy_message_id, happy_payload.clone(), ROUTING_KEY),
    )
    .await
    .expect("happy-path quarantine insert must succeed");
    quarantine_ids.push(happy_row.id);
    message_ids.push(happy_message_id.as_str());
    assert_eq!(happy_row.status, AuditQuarantineStatus::Quarantined);
    assert!(
        request_replay(&pool, happy_row.id, &happy_operation_id, REPLAY_ACTOR_ID)
            .await
            .expect("happy-path request_replay must succeed")
    );
    assert_eq!(
        get_quarantine_metadata_by_id(&pool, happy_row.id)
            .await
            .expect("requested-state query must succeed")
            .expect("happy row must exist")
            .status,
        AuditQuarantineStatus::ReplayRequested
    );

    let confirmed = run_worker_once(&pool, &harness.channel, happy_row.id).await;
    assert_eq!(confirmed.status, AuditQuarantineStatus::ReplayConfirmed);
    assert_eq!(
        confirmed.replay_attempts, 1,
        "REPLAY_CONFIRMED must be backed by a REPLAYING claim"
    );

    let delivery = timeout(TEST_TIMEOUT, async {
        loop {
            match harness.capture_consumer.next().await {
                Some(Ok(delivery)) if delivery.data == happy_payload => break delivery,
                Some(Ok(delivery)) => {
                    delivery
                        .ack(BasicAckOptions::default())
                        .await
                        .expect("unexpected test delivery ack must succeed");
                }
                Some(Err(error)) => panic!("test Rabbit consumer failed: {error}"),
                None => panic!("test Rabbit consumer ended before replay delivery"),
            }
        }
    })
    .await
    .expect("test Rabbit consumer must receive the raw replay payload");
    assert_eq!(delivery.exchange.as_str(), EXCHANGE_DIRECT);
    assert_eq!(delivery.routing_key.as_str(), ROUTING_KEY);
    assert_eq!(
        delivery
            .properties
            .message_id()
            .as_ref()
            .map(ShortString::as_str),
        Some(happy_message_id.as_str()),
        "raw replay must preserve the original message_id"
    );
    let headers = delivery
        .properties
        .headers()
        .as_ref()
        .expect("replayed delivery must carry sanitized retry headers");
    assert_eq!(
        headers
            .inner()
            .get(HEADER_RETRY_COUNT)
            .and_then(|value| value.as_long_long_int()),
        Some(0),
        "raw replay must reset x-retry-count"
    );
    assert!(!headers.contains_key(HEADER_DEATH));
    assert!(!headers.contains_key(HEADER_DLQ_REPUBLISH_COUNT));
    delivery
        .ack(BasicAckOptions::default())
        .await
        .expect("test Rabbit consumer ack must succeed");

    // This is deliberately a separate assertion from REPLAY_CONFIRMED above:
    // broker publisher confirmation is not a claim that the business audit
    // consumer committed audit_log. The second assertion waits for both durable
    // consumer/idempotency records and verifies their persisted values.
    wait_for_audit_evidence(&pool, &happy_message_id, &happy_request_id).await;
    let idempotency_status: (String,) = sqlx::query_as(
        "SELECT status FROM mq_idempotent_log WHERE message_type = ? AND message_id = ?",
    )
    .bind(MESSAGE_TYPE)
    .bind(&happy_message_id)
    .fetch_one(&pool)
    .await
    .expect("idempotency evidence must be queryable");
    assert_eq!(idempotency_status.0, "PROCESSED");
    let audit_row: (i64, String, String) =
        sqlx::query_as("SELECT user_id, decision, event_type FROM audit_log WHERE request_id = ?")
            .bind(&happy_request_id)
            .fetch_one(&pool)
            .await
            .expect("audit_log evidence must be queryable");
    assert_eq!(
        audit_row,
        (7_901, "ALLOW".to_owned(), "PERMISSION_CHECK".to_owned())
    );

    // Validation failure: the worker claims the row but must return it to
    // QUARANTINED. No broker delivery and no REPLAY_CONFIRMED state are allowed.
    let malformed_message_id = unique_message_id("malformed");
    let malformed_operation_id = format!("op-{malformed_message_id}");
    let malformed_row = insert_or_increment_terminal(
        &pool,
        &quarantine_input(&malformed_message_id, b"{not-json".to_vec(), ROUTING_KEY),
    )
    .await
    .expect("malformed quarantine insert must succeed");
    quarantine_ids.push(malformed_row.id);
    message_ids.push(malformed_message_id.as_str());
    assert!(request_replay(
        &pool,
        malformed_row.id,
        &malformed_operation_id,
        REPLAY_ACTOR_ID,
    )
    .await
    .expect("malformed request_replay must succeed"));
    let malformed_worker = {
        let slot = AuditReplayProducerSlot::new();
        assert!(slot.set(Producer::new(harness.channel.clone())).await);
        start_worker(pool.clone(), slot)
    };
    let malformed_result = wait_for_failed_replay(&pool, malformed_row.id, "malformed_json").await;
    malformed_worker.cancellation.cancel();
    timeout(Duration::from_secs(3), malformed_worker.join)
        .await
        .expect("malformed replay worker must stop")
        .expect("malformed replay worker task must join")
        .expect("malformed replay worker must stop cleanly");
    assert_eq!(malformed_result.failure_reason, "malformed_json");
    let malformed_confirmed: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_quarantine WHERE id = ? AND status = 'REPLAY_CONFIRMED'",
    )
    .bind(malformed_row.id)
    .fetch_one(&pool)
    .await
    .expect("malformed confirmation query must succeed");
    assert_eq!(malformed_confirmed, 0);

    // Route failure: request_replay creates the durable request, then the raw
    // replay allowlist rejects the wrong route before any broker call. The
    // active claim is fenced back to QUARANTINED and can never be confirmed.
    let route_message_id = unique_message_id("route");
    let route_operation_id = format!("op-{route_message_id}");
    let route_payload = audit_envelope(&route_message_id, &request_id_for(&route_message_id));
    let route_row = insert_or_increment_terminal(
        &pool,
        &quarantine_input(&route_message_id, route_payload.clone(), "wrong.route"),
    )
    .await
    .expect("wrong-route quarantine insert must succeed");
    quarantine_ids.push(route_row.id);
    message_ids.push(route_message_id.as_str());
    assert!(
        request_replay(&pool, route_row.id, &route_operation_id, REPLAY_ACTOR_ID)
            .await
            .expect("wrong-route request_replay must succeed")
    );
    let route_claim = begin_replay(
        &pool,
        route_row.id,
        "integration-route-worker",
        &route_operation_id,
        60,
    )
    .await
    .expect("wrong-route claim must succeed")
    .expect("wrong-route row must be claimable");
    let route_error = Producer::new(harness.channel.clone())
        .publish_raw_replay(RawReplayRequest::new(
            "trustgraph",
            QUEUE_AUDIT_LOG,
            EXCHANGE_DIRECT,
            "wrong.route",
            route_payload,
            BasicProperties::default(),
            route_message_id.clone(),
        ))
        .await
        .expect_err("wrong route must be rejected before publish");
    assert!(matches!(
        route_error,
        RawReplayError::RouteNotAllowed { .. }
    ));
    assert!(
        fail_replay_claim(&pool, &route_claim, "route_not_allowlisted")
            .await
            .expect("wrong-route failure fence must succeed")
    );
    let route_result = wait_for_failed_replay(&pool, route_row.id, "route_not_allowlisted").await;
    assert_eq!(route_result.failure_reason, "route_not_allowlisted");
    assert_eq!(route_result.replayed_at, None);

    // Lease recovery and token fencing: reclaim an expired REPLAYING claim, then
    // prove the old owner/token cannot confirm or fail the newly fenced claim.
    let expired_message_id = unique_message_id("expired");
    let expired_operation_id = format!("op-{expired_message_id}");
    let expired_row = insert_or_increment_terminal(
        &pool,
        &quarantine_input(
            &expired_message_id,
            audit_envelope(&expired_message_id, &request_id_for(&expired_message_id)),
            ROUTING_KEY,
        ),
    )
    .await
    .expect("expired quarantine insert must succeed");
    quarantine_ids.push(expired_row.id);
    message_ids.push(expired_message_id.as_str());
    assert!(request_replay(
        &pool,
        expired_row.id,
        &expired_operation_id,
        REPLAY_ACTOR_ID
    )
    .await
    .expect("expired request_replay must succeed"));
    let old_claim = begin_replay(
        &pool,
        expired_row.id,
        "integration-old-worker",
        &expired_operation_id,
        1,
    )
    .await
    .expect("old lease claim must succeed")
    .expect("expired row must be claimable");
    tokio::time::sleep(Duration::from_secs(2)).await;
    let reclaimed_claim = begin_next_expired_replaying_replay(
        &pool,
        "integration-new-worker",
        QUEUE_AUDIT_LOG,
        EXCHANGE_DIRECT,
        ROUTING_KEY,
        MESSAGE_TYPE,
        60,
    )
    .await
    .expect("expired lease reclaim query must succeed")
    .expect("expired lease must be reclaimed");
    assert!(reclaimed_claim.lease_generation > old_claim.lease_generation);
    assert_ne!(
        reclaimed_claim.lease_token.as_str(),
        old_claim.lease_token.as_str(),
        "reclaim must issue a fresh fencing token"
    );
    assert!(!astral_db::confirm_replay_claim(&pool, &old_claim)
        .await
        .expect("old-token confirmation query must succeed"));
    assert!(!fail_replay_claim(&pool, &old_claim, "stale_old_token")
        .await
        .expect("old-token failure query must succeed"));
    assert!(
        fail_replay_claim(&pool, &reclaimed_claim, "integration_cleanup")
            .await
            .expect("reclaimed claim cleanup must succeed")
    );
    assert_eq!(
        wait_for_status(&pool, expired_row.id, AuditQuarantineStatus::Quarantined)
            .await
            .failure_reason,
        "integration_cleanup"
    );

    delete_test_rows(&pool, &quarantine_ids, &message_ids).await;
    harness
        .consumer_channel
        .close(0, "replay integration complete".into())
        .await
        .expect("audit consumer channel close must succeed");
    harness
        .consumer_connection
        .close(0, "replay integration complete".into())
        .await
        .expect("audit consumer connection close must succeed");
    harness
        .channel
        .close(0, "replay integration complete".into())
        .await
        .expect("capture channel close must succeed");
    harness
        .connection
        .close(0, "replay integration complete".into())
        .await
        .expect("capture connection close must succeed");
}

#[cfg(test)]
mod tests {
    use super::request_id_for;

    #[test]
    fn request_id_preserves_current_ascii_correlation() {
        let message_id = "replay-integration-happy-0123456789abcdef0123456789abcdef";

        assert_eq!(request_id_for(message_id), format!("replay-{message_id}"));
        assert_eq!(request_id_for(message_id).len(), 64);
    }

    #[test]
    fn request_id_truncates_long_ascii_ids_to_64_bytes() {
        let message_id = "a".repeat(100);
        let request_id = request_id_for(&message_id);

        assert_eq!(request_id, format!("replay-{}", "a".repeat(57)));
        assert_eq!(request_id.len(), 64);
    }

    #[test]
    fn request_id_does_not_split_multibyte_suffix() {
        let message_id = "😀".repeat(64);
        let request_id = request_id_for(&message_id);

        assert!(request_id.len() <= 64);
        assert!(std::str::from_utf8(request_id.as_bytes()).is_ok());
        assert!(request_id.ends_with(&"😀".repeat(14)));
    }
}
