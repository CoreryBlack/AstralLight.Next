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
use astral_types::AuthorizationAdmission;
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

// ── proof-bound admission fixture（有效授权 mutation 的 commit 门）──────────
//
// 审批在 astral-db commit 前同事务对牌 durable `authorization_authority_frontier`
// （SERVING）与 `authorization_authority_proof`（ACTIVE）并一次性消费 admission
// （见 `consume_org_authority_admission`）。本 fixture 每次调用铸造一个结构
// 合法的新 proof（唯一 proof_id/request_nonce）并 seed 其 durable 行；生产
// 签名对牌在 F1 读取时完成，commit 门只做 durable 行等值对牌。frontier 行是
// 全局单例：各套件以相同内容 upsert 收敛；proof 行过期后不可再被消费。
const ORG_TEST_FRONTIER_ID: i64 = 1;
const ORG_TEST_AUTHORITY_ID: &str = "testsuite-org-authority";
const ORG_TEST_KEY_ID: &str = "testsuite-key-1";
const ORG_TEST_SNAPSHOT_HASH_HEX: &str = "ab";

async fn org_authority_admission(pool: &MySqlPool) -> AuthorizationAdmission {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let token = uuid::Uuid::new_v4().simple().to_string();
    let proof_id = format!("org-proof-{token}");
    let request_nonce = format!("org-nonce-{token}");
    let snapshot_hash = ORG_TEST_SNAPSHOT_HASH_HEX.repeat(32);
    let proof = astral_types::AuthorizationFenceProof {
        authorization_edition: astral_types::AUTHORIZATION_EDITION,
        authority_id: ORG_TEST_AUTHORITY_ID.to_owned(),
        authority_term: 1,
        global_fence_sequence: 1,
        scope: astral_types::AuthorizationAuthorityScope {
            tenant_id: 1,
            card_id: 1,
            user_id: Some(1),
            domain: astral_types::AuthorizationDomainScope::Any,
        },
        scope_generation: 1,
        revoke_watermark: 1,
        snapshot_hash: snapshot_hash.clone(),
        parent_hash: None,
        operation_id: format!("org-op-{token}"),
        event_id: format!("org-event-{token}"),
        key_id: ORG_TEST_KEY_ID.to_owned(),
        key_epoch: 1,
        issued_at: now,
        not_before: now - 60,
        expires_at: now + 3_600,
        request_nonce: request_nonce.clone(),
        request_binding_digest: None,
        scope_certificate_hash: None,
        proof_id: proof_id.clone(),
        signature: "00".repeat(64),
    };
    sqlx::query(
        "INSERT INTO authorization_authority_frontier \
         (frontier_id, authority_id, authority_term, global_fence_sequence, key_id, key_epoch, \
          status, snapshot_hash) \
         VALUES (?, ?, 1, 1, ?, 1, 'SERVING', UNHEX(REPEAT(?, 32))) \
         ON DUPLICATE KEY UPDATE authority_id = VALUES(authority_id), \
             authority_term = VALUES(authority_term), \
             global_fence_sequence = VALUES(global_fence_sequence), \
             key_id = VALUES(key_id), key_epoch = VALUES(key_epoch), \
             status = VALUES(status), snapshot_hash = VALUES(snapshot_hash)",
    )
    .bind(ORG_TEST_FRONTIER_ID)
    .bind(ORG_TEST_AUTHORITY_ID)
    .bind(ORG_TEST_KEY_ID)
    .bind(ORG_TEST_SNAPSHOT_HASH_HEX)
    .execute(pool)
    .await
    .expect("seed serving authority frontier fixture");
    sqlx::query(
        "INSERT INTO authorization_authority_proof \
         (proof_id, request_nonce, authorization_edition, authority_id, authority_term, \
          global_fence_sequence, tenant_id, card_id, scope_user_id, scope_domain_kind, \
          scope_domain_id, scope_generation, revoke_watermark, snapshot_hash, parent_hash, \
          operation_id, event_id, key_id, key_epoch, issued_at, not_before, expires_at, \
          signature, status) \
         VALUES (?, ?, ?, ?, 1, 1, 1, 1, 1, 'ANY', NULL, 1, 1, UNHEX(REPEAT(?, 32)), NULL, \
                 ?, ?, ?, 1, ?, ?, ?, UNHEX(REPEAT('00', 64)), 'ACTIVE')",
    )
    .bind(&proof_id)
    .bind(&request_nonce)
    .bind(astral_types::AUTHORIZATION_EDITION)
    .bind(ORG_TEST_AUTHORITY_ID)
    .bind(ORG_TEST_SNAPSHOT_HASH_HEX)
    .bind(&proof.operation_id)
    .bind(&proof.event_id)
    .bind(ORG_TEST_KEY_ID)
    .bind(proof.issued_at)
    .bind(proof.not_before)
    .bind(proof.expires_at)
    .execute(pool)
    .await
    .expect("seed active authority proof fixture");
    AuthorizationAdmission::from_verified_proof(proof)
        .expect("fixture proof must be structurally valid")
}

async fn seed_root_event(repo: &SqlxOrgScopeRepository, pool: &MySqlPool) -> String {
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
            // 审批是有效授权写点：commit 门要求 proof-bound admission。
            admission: org_authority_admission(pool).await,
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
    let operation_id = seed_root_event(&repo, &pool).await;
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
