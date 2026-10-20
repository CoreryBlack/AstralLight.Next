//! Real ORG_SCOPE projector runtime integration.
//!
//! This suite is intentionally ignored: it requires an already migrated, isolated
//! MySQL schema. It starts the production projector with the production SQLx
//! repository and compiler; the test never substitutes the hand-driven
//! `converge_unit` harness used by the DB-owner tests.

use std::sync::Arc;
use std::time::Duration;

use astral_db::connect_and_validate_schema;
use astral_db::org_scope_repository::{
    validate_org_scope_schema_prerequisites, OrgApproveCommand, OrgCreateRequestCommand,
    OrgGovernanceProof, OrgScopeRepository, SqlxOrgScopeRepository,
};
use astral_trustgraph::service::org_scope_projector::{
    org_scope_projector_shutdown_timeout, shutdown_org_scope_projector, start_org_scope_projector,
    OrgScopeProjectorConfig,
};
use astral_types::org_scope::{OrgRequestPayload, OrgScope};
use astral_types::ValidityWindow;
use sqlx::mysql::MySqlPool;
use sqlx::Row;

const PROJECTOR_TENANT: i64 = 920_000_731;
const PROJECTOR_POLL_SECS: u64 = 1;
const PROJECTOR_LEASE_SECS: i64 = 10;
const PROJECTOR_MAX_ATTEMPTS: i64 = 3;
const PROJECTOR_BACKOFF_CAP_SECS: i64 = 1;
const PROJECTOR_EVENTS_PER_CYCLE: usize = 2;
const PROJECTOR_DEADLINE_MS: u64 = 5_000;
const PROJECTOR_PROPAGATE_BATCH: i64 = 10;

async fn connect() -> Option<MySqlPool> {
    let required = std::env::var("RUST_INTEGRATION_REQUIRED").as_deref() == Ok("1");
    let url = match std::env::var("DATABASE_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        Ok(_) | Err(_) => {
            if required {
                panic!("RUST_INTEGRATION_REQUIRED=1: DATABASE_URL must be set");
            }
            eprintln!("[SKIP] DATABASE_URL must be set for projector integration");
            return None;
        }
    };
    match connect_and_validate_schema(&url).await {
        Ok(pool) => Some(pool),
        Err(error) => {
            if required {
                panic!("RUST_INTEGRATION_REQUIRED=1: migrated schema validation failed: {error}");
            }
            eprintln!("[SKIP] Cannot validate DATABASE_URL schema: {error}");
            None
        }
    }
}

async fn cleanup(pool: &MySqlPool) {
    sqlx::query(
        "DELETE FROM org_scope_dependency \
         WHERE dependent_tenant_id = ? OR depends_on_tenant_id = ?",
    )
    .bind(PROJECTOR_TENANT)
    .bind(PROJECTOR_TENANT)
    .execute(pool)
    .await
    .expect("cleanup dependency pins");
    sqlx::query(
        "DELETE s FROM org_scope_segment s \
         INNER JOIN org_scope_publication p ON p.publication_id = s.publication_id \
         WHERE p.tenant_id = ?",
    )
    .bind(PROJECTOR_TENANT)
    .execute(pool)
    .await
    .expect("cleanup publication segments");
    for statement in [
        "DELETE FROM org_scope_current WHERE tenant_id = ?",
        "DELETE FROM org_scope_publication WHERE tenant_id = ?",
        "DELETE FROM org_scope_outbox WHERE tenant_id = ?",
        "DELETE FROM org_scope_revision WHERE tenant_id = ?",
        "DELETE FROM org_scope_grant WHERE receiving_tenant_id = ? OR origin_tenant_id = ?",
        "DELETE FROM org_scope_request WHERE requester_tenant_id = ? OR target_tenant_id = ? OR parent_tenant_id = ?",
        "DELETE FROM org_scope_audit WHERE tenant_id = ?",
        "DELETE FROM org_scope_operation WHERE tenant_id = ?",
        "DELETE FROM org_scope_node WHERE tenant_id = ?",
    ] {
        let mut query = sqlx::query(statement).bind(PROJECTOR_TENANT);
        let placeholders = statement.matches('?').count();
        for _ in 1..placeholders {
            query = query.bind(PROJECTOR_TENANT);
        }
        query.execute(pool).await.expect("cleanup projector fixture");
    }
}

fn operation_id(seed: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    format!("projector-{}-{nanos}-{seed}", std::process::id())
}

fn governance_proof() -> OrgGovernanceProof {
    OrgGovernanceProof {
        permission_resource: "org_authority_edge".into(),
        permission_action: "bootstrap".into(),
        admission_operation_id: operation_id("admission"),
        approved_capabilities: vec![OrgScope {
            resource_tenant_id: PROJECTOR_TENANT,
            domain_id: None,
            resource: "*".into(),
            action: "*".into(),
            validity: ValidityWindow::perpetual(),
        }],
    }
}

async fn seed_root_event(repo: &SqlxOrgScopeRepository) -> String {
    let request = repo
        .create_request(&OrgCreateRequestCommand {
            operation_id: operation_id("root-request"),
            actor_user_id: 1,
            actor_tenant_id: Some(PROJECTOR_TENANT),
            payload: OrgRequestPayload::RootInit {
                root_tenant_id: PROJECTOR_TENANT,
                initial_grants: Vec::new(),
            },
        })
        .await
        .expect("create root-init request");
    let outcome = repo
        .approve_request(&OrgApproveCommand {
            request_id: request.request_id,
            expected_revision: 1,
            approver_user_id: 1,
            approver_tenant_id: None,
            operation_id: operation_id("root-approval"),
            note: None,
            governance_proof: Some(governance_proof()),
        })
        .await
        .expect("approve root-init request");
    assert!(outcome
        .records
        .iter()
        .any(|record| record.record_kind == "NODE_CREATED"));
    outcome.operation_id
}

async fn wait_for_durable_publish(pool: &MySqlPool, operation_id: &str) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let row = sqlx::query(
            "SELECT status, last_error FROM org_scope_outbox \
             WHERE tenant_id = ? AND operation_id = ?",
        )
        .bind(PROJECTOR_TENANT)
        .bind(operation_id)
        .fetch_optional(pool)
        .await
        .map_err(|error| format!("read projector outbox postcondition: {error}"))?;
        if let Some(row) = row {
            let status: String = row
                .try_get("status")
                .map_err(|error| format!("read outbox status: {error}"))?;
            let last_error: Option<String> = row
                .try_get("last_error")
                .map_err(|error| format!("read outbox last_error: {error}"))?;
            if status == "FAILED" {
                return Err(format!(
                    "projector terminally failed root event: {last_error:?}"
                ));
            }
            if status == "DONE" {
                let publications: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM org_scope_publication \
                     WHERE tenant_id = ? AND operation_id = ?",
                )
                .bind(PROJECTOR_TENANT)
                .bind(operation_id)
                .fetch_one(pool)
                .await
                .map_err(|error| format!("read publication postcondition: {error}"))?;
                let current: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM org_scope_current WHERE tenant_id = ?",
                )
                .bind(PROJECTOR_TENANT)
                .fetch_one(pool)
                .await
                .map_err(|error| format!("read current pointer postcondition: {error}"))?;
                if publications == 1 && current == 1 {
                    return Ok(());
                }
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(
                "projector did not reach DONE + publication + current postcondition".into(),
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
#[ignore]
async fn production_org_scope_projector_publishes_and_two_workers_do_not_duplicate() {
    let Some(pool) = connect().await else {
        return;
    };
    validate_org_scope_schema_prerequisites(&pool)
        .await
        .expect("ORG_SCOPE schema prerequisites");
    cleanup(&pool).await;
    let repo = Arc::new(SqlxOrgScopeRepository::new(pool.clone()));
    let operation_id = seed_root_event(&repo).await;
    let config = OrgScopeProjectorConfig {
        tenants: vec![PROJECTOR_TENANT],
        poll_interval_secs: PROJECTOR_POLL_SECS,
        claim_lease_seconds: PROJECTOR_LEASE_SECS,
        max_event_attempts: PROJECTOR_MAX_ATTEMPTS,
        backoff_cap_seconds: PROJECTOR_BACKOFF_CAP_SECS,
        events_per_tenant_cycle: PROJECTOR_EVENTS_PER_CYCLE,
        event_deadline_ms: PROJECTOR_DEADLINE_MS,
        propagate_batch_limit: PROJECTOR_PROPAGATE_BATCH,
    };
    let first = start_org_scope_projector(repo.clone(), config.clone())
        .expect("start first production projector");
    let second =
        start_org_scope_projector(repo, config).expect("start second production projector");
    let publish_result = wait_for_durable_publish(&pool, &operation_id).await;

    let first_timeout = org_scope_projector_shutdown_timeout(&first);
    let second_timeout = org_scope_projector_shutdown_timeout(&second);
    let first_report = shutdown_org_scope_projector(first, first_timeout).await;
    let second_report = shutdown_org_scope_projector(second, second_timeout).await;
    let first_summary = first_report.summary;
    let second_summary = second_report.summary;
    let final_state = sqlx::query(
        "SELECT o.status, o.attempts, c.generation, c.publication_id \
         FROM org_scope_outbox o \
         LEFT JOIN org_scope_current c ON c.tenant_id = o.tenant_id \
         WHERE o.tenant_id = ? AND o.operation_id = ?",
    )
    .bind(PROJECTOR_TENANT)
    .bind(&operation_id)
    .fetch_optional(&pool)
    .await
    .map_err(|error| format!("final projector durable state query: {error}"));
    cleanup(&pool).await;

    publish_result.expect("projector durable publish");
    let first_summary = first_summary.expect("first worker clean shutdown");
    let second_summary = second_summary.expect("second worker clean shutdown");
    assert_eq!(
        first_summary.record_unknown + second_summary.record_unknown,
        0
    );
    assert_eq!(
        first_summary.terminal_failed + second_summary.terminal_failed,
        0
    );
    assert_eq!(first_summary.claimed + second_summary.claimed, 1);
    assert_eq!(first_summary.published + second_summary.published, 1);
    let row = final_state
        .expect("final projector durable state query")
        .expect("final projector durable state row");
    let status: String = row.try_get("status").expect("final status");
    let attempts: i64 = row.try_get("attempts").expect("final attempts");
    let generation: i64 = row.try_get("generation").expect("current generation");
    let publication_id: i64 = row.try_get("publication_id").expect("current publication");
    assert_eq!(status, "DONE");
    assert_eq!(attempts, 1);
    assert_eq!(generation, 1);
    assert!(publication_id > 0);
}
