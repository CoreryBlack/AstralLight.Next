//! MySQL integration tests for the durable audit quarantine repository.
//!
//! Run explicitly after applying the Rust migrations:
//! `cargo test -p astral-db --test quarantine_integration -- --ignored`.
//! The tests are ignored by default because they require an external MySQL
//! instance selected by `DATABASE_URL`.

use astral_db::{
    begin_next_expired_replaying_replay, begin_next_requested_replay, begin_replay, confirm_replay,
    confirm_replay_claim, fail_replay, fail_replay_claim, get_quarantine_by_id,
    insert_or_increment_terminal, list_exhausted_replays, list_quarantine_by_status,
    request_replay, AuditQuarantineInput, AuditQuarantineStatus, MAX_LIST_LIMIT,
    MAX_REPLAY_ATTEMPTS,
};
use sqlx::MySqlPool;
use tokio::time::{sleep, Duration};

async fn connect() -> Option<MySqlPool> {
    let required = std::env::var("RUST_INTEGRATION_REQUIRED").as_deref() == Ok("1");
    let url = match std::env::var("DATABASE_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        Ok(_) | Err(_) => {
            let message = "DATABASE_URL must be set to run MySQL integration tests";
            if required {
                panic!("RUST_INTEGRATION_REQUIRED=1: {message}");
            }
            eprintln!("[SKIP] {message}");
            return None;
        }
    };

    match MySqlPool::connect(&url).await {
        Ok(pool) => Some(pool),
        Err(error) => {
            if required {
                panic!("RUST_INTEGRATION_REQUIRED=1: cannot connect using DATABASE_URL: {error}");
            }
            eprintln!("[SKIP] Cannot connect using DATABASE_URL: {error}");
            None
        }
    }
}

fn input(id: &str) -> AuditQuarantineInput {
    input_with_route(
        id,
        "quarantine-integration-test",
        "astral.test",
        "audit.test",
        "audit.test",
    )
}

fn input_with_route(
    id: &str,
    source_queue: &str,
    source_exchange: &str,
    source_routing_key: &str,
    message_type: &str,
) -> AuditQuarantineInput {
    AuditQuarantineInput {
        source_queue: source_queue.to_owned(),
        message_type: message_type.to_owned(),
        canonical_message_id: Some(id.to_owned()),
        raw_payload: br#"{"event":"test"}"#.to_vec(),
        source_exchange: source_exchange.to_owned(),
        source_routing_key: source_routing_key.to_owned(),
        retry_count: 3,
        failure_reason: "integration-test".to_owned(),
    }
}

/// Covers the repository lifecycle against the migration-owned table. This
/// intentionally does not publish or consume any MQ message.
#[ignore]
#[tokio::test]
async fn test_audit_quarantine_repository_lifecycle() {
    let Some(pool) = connect().await else {
        return;
    };

    let input = input("repository-lifecycle");
    let first = insert_or_increment_terminal(&pool, &input)
        .await
        .expect("audit_quarantine migration must be applied");
    assert_eq!(first.status, AuditQuarantineStatus::Quarantined);

    let second = insert_or_increment_terminal(&pool, &input)
        .await
        .expect("duplicate identity must upsert");
    assert_eq!(second.id, first.id);
    assert_eq!(second.attempts, first.attempts + 1);
    assert_eq!(second.retry_count, input.retry_count);

    assert!(request_replay(&pool, first.id, "operation-1", "1")
        .await
        .expect("replay request must succeed"));
    assert!(!request_replay(&pool, first.id, "operation-2", "1")
        .await
        .expect("second operation cannot replace request"));

    let claimed = begin_replay(&pool, first.id, "worker-1", "operation-1", 60)
        .await
        .expect("begin_replay query must succeed")
        .expect("requested row must be claimable");
    assert_eq!(
        claimed.raw_record.metadata.status,
        AuditQuarantineStatus::Replaying
    );
    assert!(!claimed.lease_token.as_str().is_empty());
    assert_eq!(
        claimed.raw_record.raw_payload,
        br#"{"event":"test"}"#.to_vec()
    );

    let metadata = get_quarantine_by_id(&pool, first.id)
        .await
        .expect("metadata query must succeed")
        .expect("row must remain durable");
    assert_eq!(metadata.status, AuditQuarantineStatus::Replaying);

    assert!(!confirm_replay(
        &pool,
        first.id,
        "worker-1",
        "operation-1",
        claimed.lease_generation,
        "wrong-token",
    )
    .await
    .expect("wrong token must be rejected"));
    assert!(confirm_replay(
        &pool,
        first.id,
        "worker-1",
        "operation-1",
        claimed.lease_generation,
        claimed.lease_token.as_str(),
    )
    .await
    .expect("confirm_replay query must succeed"));
    assert!(confirm_replay(
        &pool,
        first.id,
        "worker-1",
        "operation-1",
        claimed.lease_generation,
        claimed.lease_token.as_str(),
    )
    .await
    .expect("repeated confirmation must be idempotent"));
    assert_eq!(
        get_quarantine_by_id(&pool, first.id)
            .await
            .expect("get by id must succeed")
            .expect("row must remain durable")
            .status,
        AuditQuarantineStatus::ReplayConfirmed
    );

    // A new terminal failure for the same identity re-quarantines the row and
    // clears any stale replay lease before a future replay request.
    let third = insert_or_increment_terminal(&pool, &input)
        .await
        .expect("terminal retry after confirmation must upsert");
    assert_eq!(third.status, AuditQuarantineStatus::Quarantined);

    assert!(request_replay(&pool, third.id, "operation-2", "2")
        .await
        .expect("second replay request must succeed"));
    let reclaimed = begin_replay(&pool, third.id, "worker-2", "operation-2", 1)
        .await
        .expect("second begin_replay query must succeed")
        .expect("re-requested row must be claimable");
    assert_eq!(
        reclaimed.raw_record.metadata.replay_attempts,
        third.replay_attempts + 1
    );
    assert!(fail_replay(
        &pool,
        third.id,
        "worker-2",
        "operation-2",
        reclaimed.lease_generation,
        reclaimed.lease_token.as_str(),
        "replay-failed",
    )
    .await
    .expect("fail_replay query must succeed"));

    let failed = get_quarantine_by_id(&pool, third.id)
        .await
        .expect("get after replay failure must succeed")
        .expect("row must remain durable");
    assert_eq!(failed.status, AuditQuarantineStatus::Quarantined);
    assert_eq!(failed.failure_reason, "replay-failed");

    let listed = list_quarantine_by_status(&pool, AuditQuarantineStatus::Quarantined, 100, 0)
        .await
        .expect("list by status must succeed");
    assert!(listed.iter().any(|row| row.id == third.id));
    assert!(list_quarantine_by_status(&pool, "UNKNOWN", 1, 0)
        .await
        .is_err());
    assert!(list_quarantine_by_status(
        &pool,
        AuditQuarantineStatus::Quarantined,
        MAX_LIST_LIMIT + 1,
        0
    )
    .await
    .is_err());

    sqlx::query("DELETE FROM audit_quarantine WHERE id = ?")
        .bind(third.id)
        .execute(&pool)
        .await
        .expect("integration cleanup must succeed");
}

/// Two concurrent operator-approved claims must not share a fresh lease. The
/// second claim becomes possible only after the first lease expires, and the
/// old token is fenced by the generation/hash guard.
#[ignore]
#[tokio::test]
async fn test_concurrent_claim_fencing_and_expired_reclaim() {
    let Some(pool) = connect().await else {
        return;
    };

    let row = insert_or_increment_terminal(&pool, &input("concurrent-claim"))
        .await
        .expect("insert must succeed");
    assert!(request_replay(&pool, row.id, "operation-concurrent", "1")
        .await
        .expect("request must succeed"));

    let pool_a = pool.clone();
    let first_task = tokio::spawn(async move {
        begin_replay(&pool_a, row.id, "worker-a", "operation-concurrent", 1)
            .await
            .expect("first claim query must succeed")
    });
    let pool_b = pool.clone();
    let second_task = tokio::spawn(async move {
        begin_replay(&pool_b, row.id, "worker-b", "operation-concurrent", 1)
            .await
            .expect("second claim query must succeed")
    });
    let first = first_task.await.expect("first claim task must finish");
    let second = second_task.await.expect("second claim task must finish");
    assert!(first.is_some() ^ second.is_some());

    let claim = first.or(second).expect("one claim must win");
    sleep(Duration::from_secs(2)).await;
    let pool_a = pool.clone();
    let reclaim_a = tokio::spawn(async move {
        begin_next_expired_replaying_replay(
            &pool_a,
            "worker-reclaimed-a",
            "quarantine-integration-test",
            "astral.test",
            "audit.test",
            "audit.test",
            60,
        )
        .await
        .expect("expired reclaim query must succeed")
    });
    let pool_b = pool.clone();
    let reclaim_b = tokio::spawn(async move {
        begin_next_expired_replaying_replay(
            &pool_b,
            "worker-reclaimed-b",
            "quarantine-integration-test",
            "astral.test",
            "audit.test",
            "audit.test",
            60,
        )
        .await
        .expect("expired reclaim query must succeed")
    });
    let reclaimed_a = reclaim_a.await.expect("reclaim task must finish");
    let reclaimed_b = reclaim_b.await.expect("reclaim task must finish");
    assert!(reclaimed_a.is_some() ^ reclaimed_b.is_some());
    let reclaimed = reclaimed_a
        .or(reclaimed_b)
        .expect("one expired reclaim must win");
    assert!(reclaimed.lease_generation > claim.lease_generation);
    assert!(!confirm_replay(
        &pool,
        row.id,
        &claim.lease_owner,
        "operation-concurrent",
        claim.lease_generation,
        claim.lease_token.as_str(),
    )
    .await
    .expect("old confirmation query must succeed"));
    assert!(fail_replay(
        &pool,
        row.id,
        &reclaimed.lease_owner,
        "operation-concurrent",
        reclaimed.lease_generation,
        reclaimed.lease_token.as_str(),
        "cleanup",
    )
    .await
    .expect("cleanup fail must succeed"));
    sqlx::query("DELETE FROM audit_quarantine WHERE id = ?")
        .bind(row.id)
        .execute(&pool)
        .await
        .expect("integration cleanup must succeed");
}

/// A fresh operator request must be drained before an expired lease, while an
/// expired row remains recoverable through the atomic recovery claim.
#[ignore]
#[tokio::test]
async fn test_requested_replay_precedes_expired_recovery() {
    let Some(pool) = connect().await else {
        return;
    };

    let expired = insert_or_increment_terminal(&pool, &input("ordering-expired"))
        .await
        .expect("expired row insert must succeed");
    assert!(
        request_replay(&pool, expired.id, "ordering-expired-operation", "1",)
            .await
            .expect("expired replay request must succeed")
    );
    let old_claim = begin_replay(
        &pool,
        expired.id,
        "ordering-old-worker",
        "ordering-expired-operation",
        1,
    )
    .await
    .expect("expired setup claim must succeed")
    .expect("expired setup claim must exist");
    sleep(Duration::from_secs(2)).await;

    let requested = insert_or_increment_terminal(&pool, &input("ordering-requested"))
        .await
        .expect("requested row insert must succeed");
    assert!(
        request_replay(&pool, requested.id, "ordering-requested-operation", "1",)
            .await
            .expect("requested replay request must succeed")
    );

    let selected = begin_next_requested_replay(
        &pool,
        "ordering-worker",
        "quarantine-integration-test",
        "astral.test",
        "audit.test",
        "audit.test",
        60,
    )
    .await
    .expect("requested selection must succeed")
    .expect("requested row must be selected before expired row");
    assert_eq!(selected.raw_record.metadata.id, requested.id);

    let recovered = begin_next_expired_replaying_replay(
        &pool,
        "ordering-recovery-worker",
        "quarantine-integration-test",
        "astral.test",
        "audit.test",
        "audit.test",
        60,
    )
    .await
    .expect("expired selection must succeed")
    .expect("expired row must remain recoverable");
    assert_eq!(recovered.raw_record.metadata.id, expired.id);
    assert!(recovered.lease_generation > old_claim.lease_generation);

    assert!(fail_replay(
        &pool,
        selected.raw_record.metadata.id,
        &selected.lease_owner,
        "ordering-requested-operation",
        selected.lease_generation,
        selected.lease_token.as_str(),
        "cleanup",
    )
    .await
    .expect("requested cleanup must succeed"));
    assert!(fail_replay(
        &pool,
        recovered.raw_record.metadata.id,
        &recovered.lease_owner,
        "ordering-expired-operation",
        recovered.lease_generation,
        recovered.lease_token.as_str(),
        "cleanup",
    )
    .await
    .expect("expired cleanup must succeed"));
    sqlx::query("DELETE FROM audit_quarantine WHERE id IN (?, ?)")
        .bind(expired.id)
        .bind(requested.id)
        .execute(&pool)
        .await
        .expect("integration cleanup must succeed");
}

/// Rows at the replay ceiling are observable and remain unconfirmed. The
/// worker must not silently treat an exhausted row as absent.
#[ignore]
#[tokio::test]
async fn test_max_replay_attempts_are_observable_without_confirmation() {
    let Some(pool) = connect().await else {
        return;
    };

    let row = insert_or_increment_terminal(&pool, &input("max-attempts-observable"))
        .await
        .expect("max-attempts row insert must succeed");
    assert!(
        request_replay(&pool, row.id, "max-attempts-operation", "1",)
            .await
            .expect("replay request must succeed")
    );
    let claim = begin_replay(
        &pool,
        row.id,
        "max-attempts-worker",
        "max-attempts-operation",
        1,
    )
    .await
    .expect("setup claim must succeed")
    .expect("setup claim must exist");
    sqlx::query(
        "UPDATE audit_quarantine SET replay_attempts = ?, replay_lease_expires_at = DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 SECOND) WHERE id = ?",
    )
    .bind(MAX_REPLAY_ATTEMPTS)
    .bind(row.id)
    .execute(&pool)
    .await
    .expect("max-attempts setup must succeed");

    assert!(begin_next_expired_replaying_replay(
        &pool,
        "max-attempts-recovery-worker",
        "quarantine-integration-test",
        "astral.test",
        "audit.test",
        "audit.test",
        60,
    )
    .await
    .expect("exhausted recovery query must succeed")
    .is_none());
    let exhausted = list_exhausted_replays(
        &pool,
        "quarantine-integration-test",
        "astral.test",
        "audit.test",
        "audit.test",
        10,
    )
    .await
    .expect("exhausted metadata query must succeed");
    let observed = exhausted
        .iter()
        .find(|metadata| metadata.id == row.id)
        .expect("exhausted row must be observable");
    assert_eq!(observed.replay_attempts, MAX_REPLAY_ATTEMPTS);
    assert_eq!(observed.status, AuditQuarantineStatus::Replaying);
    assert_ne!(observed.status, AuditQuarantineStatus::ReplayConfirmed);

    // The old lease is no longer valid and the row is removed only as test
    // cleanup; no confirmation path is exercised for an exhausted row.
    assert!(!confirm_replay(
        &pool,
        row.id,
        &claim.lease_owner,
        "max-attempts-operation",
        claim.lease_generation,
        claim.lease_token.as_str(),
    )
    .await
    .expect("old confirmation query must succeed"));
    sqlx::query("DELETE FROM audit_quarantine WHERE id = ?")
        .bind(row.id)
        .execute(&pool)
        .await
        .expect("integration cleanup must succeed");
}

/// Requested claims must match every route component and must never consume a
/// plain quarantine row or a row that has reached the replay ceiling.
#[ignore]
#[tokio::test]
async fn test_requested_claim_requires_exact_route_status_and_attempt_ceiling() {
    let Some(pool) = connect().await else {
        return;
    };

    let ids = [
        "requested-exact-selection",
        "requested-quarantined",
        "requested-wrong-queue",
        "requested-wrong-exchange",
        "requested-wrong-routing-key",
        "requested-wrong-message-type",
        "requested-max-attempts",
    ];
    for id in ids {
        sqlx::query("DELETE FROM audit_quarantine WHERE message_id = ?")
            .bind(id)
            .execute(&pool)
            .await
            .expect("test isolation cleanup must succeed");
    }

    let quarantined = insert_or_increment_terminal(&pool, &input("requested-quarantined"))
        .await
        .expect("quarantined row insert must succeed");
    let wrong_inputs = [
        input_with_route(
            "requested-wrong-queue",
            "other.queue",
            "astral.test",
            "audit.test",
            "audit.test",
        ),
        input_with_route(
            "requested-wrong-exchange",
            "quarantine-integration-test",
            "other.exchange",
            "audit.test",
            "audit.test",
        ),
        input_with_route(
            "requested-wrong-routing-key",
            "quarantine-integration-test",
            "astral.test",
            "other.route",
            "audit.test",
        ),
        input_with_route(
            "requested-wrong-message-type",
            "quarantine-integration-test",
            "astral.test",
            "audit.test",
            "other.type",
        ),
    ];
    let mut wrong_rows = Vec::with_capacity(wrong_inputs.len());
    for wrong_input in wrong_inputs {
        let operation_id = wrong_input
            .canonical_message_id
            .as_deref()
            .expect("test input must have an operation id");
        let row = insert_or_increment_terminal(&pool, &wrong_input)
            .await
            .expect("wrong-route row insert must succeed");
        assert!(request_replay(&pool, row.id, operation_id, "1")
            .await
            .expect("wrong-route replay request must succeed"));
        wrong_rows.push(row);
    }

    let exhausted = insert_or_increment_terminal(&pool, &input("requested-max-attempts"))
        .await
        .expect("max-attempts row insert must succeed");
    assert!(
        request_replay(&pool, exhausted.id, "requested-max-operation", "1",)
            .await
            .expect("max-attempts replay request must succeed")
    );
    sqlx::query(
        "UPDATE audit_quarantine SET replay_attempts = ?, status = 'REPLAY_REQUESTED', replay_lease_owner = NULL, replay_lease_token_hash = NULL, replay_lease_expires_at = NULL WHERE id = ?",
    )
    .bind(MAX_REPLAY_ATTEMPTS)
    .bind(exhausted.id)
    .execute(&pool)
    .await
    .expect("max-attempts setup must succeed");

    let requested = insert_or_increment_terminal(&pool, &input("requested-exact-selection"))
        .await
        .expect("exact-route row insert must succeed");
    assert!(
        request_replay(&pool, requested.id, "requested-exact-operation", "1",)
            .await
            .expect("exact-route replay request must succeed")
    );

    let claim = begin_next_requested_replay(
        &pool,
        "requested-selection-worker",
        "quarantine-integration-test",
        "astral.test",
        "audit.test",
        "audit.test",
        60,
    )
    .await
    .expect("exact-route selection must succeed")
    .expect("exact-route request must be claimable");
    assert_eq!(claim.raw_record.metadata.id, requested.id);
    assert_eq!(
        claim.raw_record.metadata.status,
        AuditQuarantineStatus::Replaying
    );
    assert!(begin_next_requested_replay(
        &pool,
        "requested-selection-worker-2",
        "quarantine-integration-test",
        "astral.test",
        "audit.test",
        "audit.test",
        60,
    )
    .await
    .expect("second exact-route selection must succeed")
    .is_none());

    assert_eq!(
        get_quarantine_by_id(&pool, quarantined.id)
            .await
            .expect("quarantined metadata query must succeed")
            .expect("quarantined row must remain durable")
            .status,
        AuditQuarantineStatus::Quarantined
    );
    for wrong in wrong_rows {
        assert_eq!(
            get_quarantine_by_id(&pool, wrong.id)
                .await
                .expect("wrong-route metadata query must succeed")
                .expect("wrong-route row must remain durable")
                .status,
            AuditQuarantineStatus::ReplayRequested
        );
    }
    assert_eq!(
        get_quarantine_by_id(&pool, exhausted.id)
            .await
            .expect("exhausted metadata query must succeed")
            .expect("exhausted row must remain durable")
            .replay_attempts,
        MAX_REPLAY_ATTEMPTS
    );

    sqlx::query("DELETE FROM audit_quarantine WHERE message_id IN (?, ?, ?, ?, ?, ?, ?)")
        .bind(ids[0])
        .bind(ids[1])
        .bind(ids[2])
        .bind(ids[3])
        .bind(ids[4])
        .bind(ids[5])
        .bind(ids[6])
        .execute(&pool)
        .await
        .expect("integration cleanup must succeed");
}

/// Typed claim transitions require owner, token, generation and operation
/// identity to match. Confirmation is idempotent only for the same claim.
#[ignore]
#[tokio::test]
async fn test_typed_claim_confirm_and_fail_fencing() {
    let Some(pool) = connect().await else {
        return;
    };

    for id in ["typed-confirm-fence", "typed-fail-fence"] {
        sqlx::query("DELETE FROM audit_quarantine WHERE message_id = ?")
            .bind(id)
            .execute(&pool)
            .await
            .expect("test isolation cleanup must succeed");
    }

    let confirm_row = insert_or_increment_terminal(&pool, &input("typed-confirm-fence"))
        .await
        .expect("confirm row insert must succeed");
    assert!(
        request_replay(&pool, confirm_row.id, "typed-confirm-operation", "1",)
            .await
            .expect("confirm request must succeed")
    );
    let confirm_claim = begin_replay(
        &pool,
        confirm_row.id,
        "typed-confirm-worker",
        "typed-confirm-operation",
        60,
    )
    .await
    .expect("confirm claim query must succeed")
    .expect("confirm claim must exist");
    assert!(confirm_replay_claim(&pool, &confirm_claim)
        .await
        .expect("typed confirmation query must succeed"));
    assert!(confirm_replay_claim(&pool, &confirm_claim)
        .await
        .expect("repeated typed confirmation query must succeed"));
    assert_eq!(
        get_quarantine_by_id(&pool, confirm_row.id)
            .await
            .expect("confirmed metadata query must succeed")
            .expect("confirmed row must remain durable")
            .status,
        AuditQuarantineStatus::ReplayConfirmed
    );

    let fail_row = insert_or_increment_terminal(&pool, &input("typed-fail-fence"))
        .await
        .expect("fail row insert must succeed");
    assert!(
        request_replay(&pool, fail_row.id, "typed-fail-operation", "1",)
            .await
            .expect("fail request must succeed")
    );
    let fail_claim = begin_replay(
        &pool,
        fail_row.id,
        "typed-fail-worker",
        "typed-fail-operation",
        60,
    )
    .await
    .expect("fail claim query must succeed")
    .expect("fail claim must exist");

    let mut owner_mismatch = fail_claim.clone();
    owner_mismatch.lease_owner = "different-owner".into();
    assert!(!confirm_replay_claim(&pool, &owner_mismatch)
        .await
        .expect("owner fence query must succeed"));
    assert!(!fail_replay_claim(&pool, &owner_mismatch, "owner-mismatch")
        .await
        .expect("owner failure fence query must succeed"));

    let mut token_mismatch = fail_claim.clone();
    token_mismatch.lease_token = confirm_claim.lease_token.clone();
    assert!(!confirm_replay_claim(&pool, &token_mismatch)
        .await
        .expect("token fence query must succeed"));
    assert!(!fail_replay_claim(&pool, &token_mismatch, "token-mismatch")
        .await
        .expect("token failure fence query must succeed"));

    let mut generation_mismatch = fail_claim.clone();
    generation_mismatch.lease_generation += 1;
    assert!(!confirm_replay_claim(&pool, &generation_mismatch)
        .await
        .expect("generation fence query must succeed"));
    assert!(
        !fail_replay_claim(&pool, &generation_mismatch, "generation-mismatch")
            .await
            .expect("generation failure fence query must succeed")
    );

    let mut operation_mismatch = fail_claim.clone();
    // Reuse another claim's opaque identity so the integration test does not
    // require a production-facing token/operation-id constructor.
    operation_mismatch.operation_identity = confirm_claim.operation_identity.clone();
    assert!(!confirm_replay_claim(&pool, &operation_mismatch)
        .await
        .expect("operation fence query must succeed"));
    assert!(
        !fail_replay_claim(&pool, &operation_mismatch, "operation-mismatch")
            .await
            .expect("operation failure fence query must succeed")
    );

    assert!(fail_replay_claim(&pool, &fail_claim, "typed-failure")
        .await
        .expect("typed failure transition must succeed"));
    assert_eq!(
        get_quarantine_by_id(&pool, fail_row.id)
            .await
            .expect("failed metadata query must succeed")
            .expect("failed row must remain durable")
            .status,
        AuditQuarantineStatus::Quarantined
    );

    sqlx::query("DELETE FROM audit_quarantine WHERE message_id IN (?, ?)")
        .bind("typed-confirm-fence")
        .bind("typed-fail-fence")
        .execute(&pool)
        .await
        .expect("integration cleanup must succeed");
}

/// A stale typed claim cannot confirm or fail after an expired lease is fenced
/// by a new claim, even when the replay operation is unchanged.
#[ignore]
#[tokio::test]
async fn test_expired_reclaim_fences_old_typed_claim() {
    let Some(pool) = connect().await else {
        return;
    };

    let row = insert_or_increment_terminal(&pool, &input("typed-expired-reclaim"))
        .await
        .expect("expired reclaim row insert must succeed");
    assert!(
        request_replay(&pool, row.id, "typed-expired-operation", "1",)
            .await
            .expect("expired reclaim request must succeed")
    );
    let old_claim = begin_replay(
        &pool,
        row.id,
        "typed-expired-old-worker",
        "typed-expired-operation",
        1,
    )
    .await
    .expect("old claim query must succeed")
    .expect("old claim must exist");
    sleep(Duration::from_secs(2)).await;

    let reclaimed = begin_next_expired_replaying_replay(
        &pool,
        "typed-expired-new-worker",
        "quarantine-integration-test",
        "astral.test",
        "audit.test",
        "audit.test",
        60,
    )
    .await
    .expect("expired reclaim query must succeed")
    .expect("expired claim must be recoverable");
    assert!(reclaimed.lease_generation > old_claim.lease_generation);
    assert!(!confirm_replay_claim(&pool, &old_claim)
        .await
        .expect("stale confirmation query must succeed"));
    assert!(!fail_replay_claim(&pool, &old_claim, "stale-claim")
        .await
        .expect("stale failure query must succeed"));
    assert!(confirm_replay_claim(&pool, &reclaimed)
        .await
        .expect("reclaimed confirmation query must succeed"));

    sqlx::query("DELETE FROM audit_quarantine WHERE message_id = ?")
        .bind("typed-expired-reclaim")
        .execute(&pool)
        .await
        .expect("integration cleanup must succeed");
}
