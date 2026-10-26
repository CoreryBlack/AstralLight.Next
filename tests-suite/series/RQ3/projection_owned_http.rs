//! Signed in-process HTTP -> durable source -> owned projection integration.
//!
//! This ignored test uses the production TrustGraph rule router, permission
//! middleware, and Gateway v3 signature middleware over `Router::oneshot`.
//! It must run only against the approved run-owned loopback MySQL clone.

#[path = "projection_owned_http_support/mod.rs"]
mod support;

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use astral_db::{freeze_projection_execution_mode, ProjectionExecutionMode};
use astral_trustgraph::service::authorization_projector::{
    shutdown_authorization_projector, start_authorization_projector, AuthorizationProjectorConfig,
    AuthorizationProjectorHandle,
};
use support::{
    build_signed_router, cleanup_fixture, connect_required, http_delete, http_delete_card,
    http_post, http_put, seed_governance_fixture, strict_evaluate, wait_for_delta,
    wait_for_projection, HttpIdentity, OwnedFixture, DB_TIMEOUT, TEST_TIMEOUT,
};

const RESOURCE: &str = "learn_subject";
const ACTION: &str = "read";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires approved isolated MySQL and the production owned projector"]
async fn projection_owned_signed_http_mutation_source_receipt_worker_strict_evaluate() {
    freeze_projection_execution_mode(ProjectionExecutionMode::WorkerOwned)
        .expect("WorkerOwned must be frozen before any source mutation");

    let pool = connect_required().await;
    let fixture = OwnedFixture::new("projection-owned-http");
    astral_mq::invalidation::install_origin_region(format!("owned-http-{:x}", fixture.suite.salt))
        .expect("source invalidation origin must be installed before writes");
    println!(
        "[OWNED_HTTP_SETUP] fixture_base={} salt={:032x}",
        fixture.base, fixture.suite.salt
    );
    let mut owner: Option<AuthorizationProjectorHandle> = None;
    let mut committed_operations = Vec::new();

    let result = tokio::time::timeout(TEST_TIMEOUT, async {
        let bootstrap_operation = seed_governance_fixture(&pool, &fixture).await?;
        committed_operations.push(bootstrap_operation.clone());
        owner = Some(start_owner(&pool, &fixture));
        let bootstrap_deltas = support::wait_for_operation_deltas(
            &pool,
            &fixture,
            &bootstrap_operation,
            4,
            "ADD",
        )
        .await?;
        for delta in &bootstrap_deltas {
            wait_for_projection(&pool, &fixture, delta).await?;
            support::assert_exact_receipt(&pool, &fixture, &bootstrap_operation, delta).await?;
        }
        strict_evaluate(&pool, &fixture, false).await?;
        let identity = HttpIdentity::for_fixture(&fixture);
        let router = build_signed_router(&pool, &fixture.gateway_secret)?;
        let invalid_before = support::source_mutation_snapshot(&pool, &fixture).await?;
        let invalid = http_post(
            router.clone(),
            &identity,
            &fixture.add_operation("invalid-signature"),
            rule_body(fixture.card_id, 1),
            true,
        )
        .await?;
        if invalid.status() != axum::http::StatusCode::FORBIDDEN {
            return Err(anyhow!(
                "invalid Gateway signature returned {}, expected 403",
                invalid.status()
            ));
        }
        let invalid_after = support::source_mutation_snapshot(&pool, &fixture).await?;
        if invalid_before != invalid_after {
            return Err(anyhow!(
                "invalid signature changed source state: before={invalid_before:?} after={invalid_after:?}"
            ));
        }

        // A validly signed foreign tenant context must fail card scope before source write.
        let cross_before = support::source_mutation_snapshot(&pool, &fixture).await?;
        let cross = http_post(
            router.clone(),
            &identity.with_tenant(fixture.other_tenant_id),
            &fixture.add_operation("cross-tenant"),
            rule_body(fixture.card_id, 1),
            false,
        )
        .await?;
        if cross.status() != axum::http::StatusCode::FORBIDDEN {
            return Err(anyhow!(
                "cross-tenant signed mutation returned {}, expected 403",
                cross.status()
            ));
        }
        let cross_after = support::source_mutation_snapshot(&pool, &fixture).await?;
        if cross_before != cross_after {
            return Err(anyhow!(
                "cross-tenant request changed source state: before={cross_before:?} after={cross_after:?}"
            ));
        }

        // The bootstrap owner is already running; all subsequent source events
        // must be processed by this single WorkerOwned projector.
        let add_operation = fixture.add_operation("add");
        let add = http_post(
            router.clone(),
            &identity,
            &add_operation,
            rule_body(fixture.card_id, 10),
            false,
        )
        .await?;
        let add = support::require_success(add, "signed ADD").await?;
        let add_rule_id = support::response_rule_id(add)
            .await
            .context("signed ADD rule id")?;
        committed_operations.push(add_operation.clone());
        let add_delta = wait_for_delta(&pool, &fixture, &add_operation, "ADD").await?;
        wait_for_projection(&pool, &fixture, &add_delta).await?;
        support::assert_exact_receipt(&pool, &fixture, &add_operation, &add_delta).await?;
        strict_evaluate(&pool, &fixture, true).await?;

        stop_owner(&mut owner).await?;
        let update_operation = fixture.add_operation("update-while-stopped");
        let update = http_put(
            router.clone(),
            &identity,
            add_rule_id,
            &update_operation,
            rule_body(fixture.card_id, 20),
            false,
        )
        .await?;
        support::require_success(update, "signed UPDATE").await?;
        committed_operations.push(update_operation.clone());
        let update_delta = wait_for_delta(&pool, &fixture, &update_operation, "UPDATE").await?;
        support::assert_unclaimed_delta(&pool, &update_delta, false).await?;
        strict_evaluate(&pool, &fixture, true).await?;
        owner = Some(start_owner(&pool, &fixture));
        wait_for_projection(&pool, &fixture, &update_delta).await?;
        support::assert_exact_receipt(&pool, &fixture, &update_operation, &update_delta).await?;
        strict_evaluate(&pool, &fixture, true).await?;

        // A finite validity window narrows the perpetual grant; priority alone does not.
        stop_owner(&mut owner).await?;
        let valid_to: String = tokio::time::timeout(
            DB_TIMEOUT,
            sqlx::query_scalar(
                "SELECT DATE_FORMAT(UTC_TIMESTAMP() + INTERVAL 1 DAY, '%Y-%m-%d %H:%i:%s')",
            )
            .fetch_one(&pool),
        )
        .await
        .context("narrowing UPDATE validity query timed out")??;
        let mut narrowing_body = rule_body(fixture.card_id, 20);
        narrowing_body["validTo"] = valid_to.into();
        let narrowing_operation = fixture.add_operation("narrow-update");
        let narrowing_update = http_put(
            router.clone(),
            &identity,
            add_rule_id,
            &narrowing_operation,
            narrowing_body,
            false,
        )
        .await?;
        support::require_success(narrowing_update, "signed narrowing UPDATE").await?;
        committed_operations.push(narrowing_operation.clone());
        let narrowing_delta =
            wait_for_delta(&pool, &fixture, &narrowing_operation, "UPDATE").await?;
        support::assert_unclaimed_delta(&pool, &narrowing_delta, true).await?;
        let narrowing_decision = strict_evaluate(&pool, &fixture, false).await?;
        if !matches!(
            narrowing_decision.reason.as_str(),
            "AUTHORIZATION_PENDING" | "DEFAULT_DENY"
        ) {
            return Err(anyhow!(
                "strict reader did not fail closed for narrowing UPDATE: {narrowing_decision:?}"
            ));
        }
        owner = Some(start_owner(&pool, &fixture));
        wait_for_projection(&pool, &fixture, &narrowing_delta).await?;
        support::assert_exact_receipt(&pool, &fixture, &narrowing_operation, &narrowing_delta).await?;
        strict_evaluate(&pool, &fixture, true).await?;
        stop_owner(&mut owner).await?;

        let remove_operation = fixture.add_operation("remove-while-stopped");
        let remove = http_delete(router.clone(), &identity, add_rule_id, &remove_operation).await?;
        support::require_success(remove, "signed REMOVE").await?;
        committed_operations.push(remove_operation.clone());
        let remove_delta = wait_for_delta(&pool, &fixture, &remove_operation, "REMOVE").await?;
        support::assert_unclaimed_delta(&pool, &remove_delta, true).await?;
        let narrowed = strict_evaluate(&pool, &fixture, false).await?;
        if narrowed.allowed || !matches!(narrowed.reason.as_str(), "AUTHORIZATION_PENDING" | "DEFAULT_DENY") {
            return Err(anyhow!(
                "strict reader did not fail closed while owner was stopped: {narrowed:?}"
            ));
        }

        // Restart the same production owner and prove every historical receipt.
        owner = Some(start_owner(&pool, &fixture));
        wait_for_projection(&pool, &fixture, &update_delta).await?;
        wait_for_projection(&pool, &fixture, &remove_delta).await?;
        support::assert_exact_receipt(&pool, &fixture, &update_operation, &update_delta).await?;
        support::assert_exact_receipt(&pool, &fixture, &remove_operation, &remove_delta).await?;
        strict_evaluate(&pool, &fixture, false).await?;

        // Add two independent contributions, then use the real production
        // card-bulk endpoint. One request-id must produce multiple REMOVE rows
        // sharing one operation id, each with its own exact completion proof.
        let first_bulk_add_operation = fixture.add_operation("bulk-add-one");
        let first_bulk_add = http_post(
            router.clone(),
            &identity,
            &first_bulk_add_operation,
            rule_body(fixture.card_id, 30),
            false,
        )
        .await?;
        let first_bulk_add = support::require_success(first_bulk_add, "signed bulk ADD one").await?;
        committed_operations.push(first_bulk_add_operation.clone());
        let first_bulk_rule = support::response_rule_id(first_bulk_add).await?;
        let first_bulk_delta =
            wait_for_delta(&pool, &fixture, &first_bulk_add_operation, "ADD").await?;
        wait_for_projection(&pool, &fixture, &first_bulk_delta).await?;

        let second_bulk_add_operation = fixture.add_operation("bulk-add-two");
        let second_bulk_add = http_post(
            router.clone(),
            &identity,
            &second_bulk_add_operation,
            rule_body(fixture.card_id, 40),
            false,
        )
        .await?;
        let second_bulk_add = support::require_success(second_bulk_add, "signed bulk ADD two").await?;
        committed_operations.push(second_bulk_add_operation.clone());
        let second_bulk_rule = support::response_rule_id(second_bulk_add).await?;
        if first_bulk_rule == second_bulk_rule {
            return Err(anyhow!("bulk seed contributions reused one rule id"));
        }
        let second_bulk_delta =
            wait_for_delta(&pool, &fixture, &second_bulk_add_operation, "ADD").await?;
        wait_for_projection(&pool, &fixture, &second_bulk_delta).await?;

        let bulk_operation = fixture.add_operation("bulk-remove");
        let bulk = http_delete_card(router, &identity, fixture.card_id, &bulk_operation).await?;
        support::require_success(bulk, "signed bulk REMOVE").await?;
        committed_operations.push(bulk_operation.clone());
        let bulk_deltas = support::wait_for_operation_deltas(
            &pool,
            &fixture,
            &bulk_operation,
            2,
            "REMOVE",
        )
        .await?;
        if bulk_deltas.len() < 2
            || bulk_deltas.iter().any(|delta| delta.operation_id != bulk_operation)
        {
            return Err(anyhow!("bulk endpoint did not create one shared operation"));
        }
        for delta in &bulk_deltas {
            wait_for_projection(&pool, &fixture, delta).await?;
            support::assert_exact_receipt(&pool, &fixture, &bulk_operation, delta).await?;
        }
        strict_evaluate(&pool, &fixture, false).await?;
        Ok::<(), anyhow::Error>(())
    })
    .await
    .map_err(|_| anyhow!("HTTP projection scenario exceeded {TEST_TIMEOUT:?}"))
    .and_then(|value| value);

    if let Err(error) = stop_owner(&mut owner).await {
        report_unknown_and_fail(&fixture, &committed_operations, result, error);
    }
    if let Err(error) = result {
        report_unknown_and_fail(
            &fixture,
            &committed_operations,
            Err(error),
            anyhow!("scenario failed"),
        );
    }
    tokio::time::timeout(
        DB_TIMEOUT,
        cleanup_fixture(&pool, &fixture, &committed_operations),
    )
    .await
    .expect("cleanup timed out")
    .expect("cleanup requires a proven owner shutdown and durable postconditions");
    println!(
        "[OWNED_HTTP] fixture_base={} operations={} signatures=verified negative_requests=403_without_source_mutation neutral_update=allow narrowing_update=pending remove=pending bulk_remove=complete cleanup=complete",
        fixture.base,
        committed_operations.len()
    );
}

fn rule_body(card_id: i64, priority: i32) -> serde_json::Value {
    serde_json::json!({
        "cardId": card_id,
        "effect": "ALLOW",
        "resourceType": RESOURCE,
        "actionCode": ACTION,
        "sourceType": "MANUAL",
        "priority": priority,
    })
}

fn start_owner(pool: &sqlx::MySqlPool, fixture: &OwnedFixture) -> AuthorizationProjectorHandle {
    let config = AuthorizationProjectorConfig {
        tenants: vec![fixture.tenant_id],
        poll_interval_secs: 1,
        watchdog_tick: Duration::from_millis(100),
        watchdog_stall_threshold: Duration::from_secs(10),
        ..AuthorizationProjectorConfig::default()
    };
    start_authorization_projector(pool.clone(), config)
}

async fn stop_owner(owner: &mut Option<AuthorizationProjectorHandle>) -> Result<()> {
    let Some(handle) = owner.take() else {
        return Ok(());
    };
    let report = tokio::time::timeout(
        Duration::from_secs(12),
        shutdown_authorization_projector(handle, Duration::from_secs(10)),
    )
    .await
    .context("owner shutdown outer timeout")?;
    report
        .summary
        .and_then(|summary| {
            if summary.events_publication_unknown == 0 && summary.events_quarantine_unknown == 0 {
                Ok(())
            } else {
                Err(format!(
                    "owned projector shutdown has unknown outcomes: publication={}, quarantine={}",
                    summary.events_publication_unknown, summary.events_quarantine_unknown
                ))
            }
        })
        .map_err(|error| anyhow!("owned projector shutdown failed: {error}"))
}

fn report_unknown_and_fail(
    fixture: &OwnedFixture,
    operations: &[String],
    result: Result<()>,
    shutdown_error: anyhow::Error,
) -> ! {
    eprintln!(
        "[UNKNOWN] retain fixture base={} operations={operations:?}; shutdown={shutdown_error:#}",
        fixture.base
    );
    match result {
        Ok(()) => panic!("owner shutdown failed; fixture retained"),
        Err(error) => panic!("scenario failed; fixture retained: {error:#}"),
    }
}

#[tokio::test]
async fn stopped_owner_shutdown_is_idempotent() {
    let mut owner = None;
    stop_owner(&mut owner)
        .await
        .expect("absent owner is already stopped");
    stop_owner(&mut owner)
        .await
        .expect("repeated shutdown stays stopped");
}

#[test]
fn target_contract_is_worker_owned_and_bounded() {
    assert_eq!(RESOURCE, "learn_subject");
    assert_eq!(ACTION, "read");
    assert!(TEST_TIMEOUT <= Duration::from_secs(180));
    assert!(DB_TIMEOUT <= Duration::from_secs(10));
    let fixture = OwnedFixture::new("projection-owned-http-contract");
    for label in [
        "ruleset-bootstrap",
        "invalid-signature",
        "cross-tenant",
        "add",
        "update-while-stopped",
        "narrow-update",
        "remove-while-stopped",
        "bulk-add-one",
        "bulk-add-two",
        "bulk-remove",
    ] {
        assert!(fixture.add_operation(label).len() <= 64);
    }
}
