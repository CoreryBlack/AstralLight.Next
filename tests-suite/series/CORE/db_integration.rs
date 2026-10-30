//! CURRENT V6 database integration tests.
//!
//! Requires an isolated MySQL 8.0 database with the v5 baseline and Rust-owned
//! projection migrations applied. Run explicitly with
//! `cargo test -p testsuite --test db_integration -- --ignored`. Missing
//! `DATABASE_URL` or schema/connection prerequisites produce `[SKIP]` unless
//! `RUST_INTEGRATION_REQUIRED=1` is set.
//!
//! The RuleSet authorization fixture uses the shared
//! `testsuite::publish_card_manifest` source-writer/WorkerOwned protocol and
//! strict published-evidence reader. Fixture code does not construct grants,
//! manifests, leases, or ledger rows. A retained MANUAL `permission_rule` row
//! remains baseline source data and is never an authorization fallback.

use astral_db::{connect_and_validate_schema, SqlxRuleRepository};
use astral_trustgraph::service::rule_set_write_service::AddEntryRequest;
use astral_types::{
    DomainScopeRequirement, GrantEffect, PolicyError, PublishedCardEvidenceScope,
    PublishedEvidenceGateStatus,
};
use policy_engine::RuleRepository;
use sha2::{Digest, Sha256};
use sqlx::MySqlPool;
use testsuite::{publish_card_manifest, PROJECTION_TABLES};
#[path = "../MT-E1/support/source_identity.rs"]
mod source_identity;
use uuid::Uuid;

const DURABLE_TABLES: &[&str] = &[
    "authorization_projection_partition_lease",
    "authorization_projection_outbox",
    "authorization_archive_outbox",
    "authorization_archive_manifest",
    "authorization_impact_plan_item",
    "authorization_impact_plan",
    "authorization_projection_manifest_segment",
    "authorization_projection_current",
    "authorization_projection_manifest",
    "authorization_projection_segment",
    "authorization_delta_event",
    "authorization_grant_revision",
    "rule_set_projection_audit",
    "al_message_outbox",
];

/// 独立随机测试命名空间：uuid 派生的大整数，降低跨运行碰撞概率。
struct TestNamespace {
    salt: u128,
    tenant_id: i64,
    domain_id: i64,
    user_id: i64,
    identity_card_id: i64,
    card_id: i64,
    rule_set_id: i64,
    placeholder_entry_id: i64,
    permission_rule_id: i64,
    tenant_domain_map_id: i64,
}

impl TestNamespace {
    fn new() -> Self {
        let salt = Uuid::new_v4().as_u128();
        // 1e12 起步、步长 1e4 的稀疏大整数区间，远离真实业务 id。
        let base = 1_000_000_000_000_i64 + ((salt % 800_000_000_000) as i64) * 10_000;
        Self {
            salt,
            tenant_id: base,
            domain_id: base + 1,
            user_id: base + 2,
            identity_card_id: base + 9,
            card_id: base + 3,
            rule_set_id: base + 4,
            placeholder_entry_id: base + 5,
            permission_rule_id: base + 7,
            tenant_domain_map_id: base + 8,
        }
    }

    fn evidence_scope(&self) -> PublishedCardEvidenceScope {
        PublishedCardEvidenceScope {
            tenant_id: self.tenant_id,
            card_id: self.card_id,
            user_filter: None,
            domain: DomainScopeRequirement::ExactlySome(self.domain_id),
        }
    }

    /// From a card that has never been seeded: verify fail-closed evidence reads.
    fn unpublished_card_scope(&self) -> PublishedCardEvidenceScope {
        PublishedCardEvidenceScope {
            tenant_id: self.tenant_id,
            card_id: self.card_id + 900_000,
            user_filter: None,
            domain: DomainScopeRequirement::ExactlySome(self.domain_id),
        }
    }
}

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

    let pool = match connect_and_validate_schema(&url).await {
        Ok(pool) => pool,
        Err(error) => {
            if required {
                panic!(
                    "RUST_INTEGRATION_REQUIRED=1: MySQL connection/schema validation failed: {error}"
                );
            }
            eprintln!("[SKIP] MySQL connection/schema validation failed: {error}");
            return None;
        }
    };

    // 显式要求 Rust-owned 投影链表存在；本测试不执行任何临时 DDL。
    let mut missing = Vec::new();
    for table in PROJECTION_TABLES {
        let present: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM information_schema.TABLES \
             WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?",
        )
        .bind(table)
        .fetch_one(&pool)
        .await
        .unwrap();
        if present.0 == 0 {
            missing.push((*table).to_owned());
        }
    }
    if !missing.is_empty() {
        let message = format!(
            "Rust-owned authorization projection tables are missing \
             (migrations 20260825000002/20260827000001 not applied): {missing:?}"
        );
        if required {
            panic!("RUST_INTEGRATION_REQUIRED=1: {message}");
        }
        eprintln!("[SKIP] {message}");
        return None;
    }

    Some(pool)
}

/// Remove only this randomized fixture's V6 and source rows, children before parents.
async fn cleanup_namespace(pool: &MySqlPool, namespace: &TestNamespace) {
    // Scope tenant-owned durable rows by this fixture's unique numeric tenant id.
    // The retained head has no tenant column, so resolve ownership through source rows.
    for table in DURABLE_TABLES {
        sqlx::query(&format!("DELETE FROM {table} WHERE tenant_id = ?"))
            .bind(namespace.tenant_id)
            .execute(pool)
            .await
            .unwrap();
    }
    for (aggregate, source_table, source_alias, source_id, source_tenant) in [
        ("CARD", "user_card", "uc", "card_id", "tenant_id"),
        ("ELIGIBILITY", "user_card", "uc", "card_id", "tenant_id"),
        ("RULE_SET", "rule_set", "rs", "rule_set_id", "tenant_id"),
    ] {
        sqlx::query(&format!(
            "DELETE h FROM authorization_projection_head h \
             INNER JOIN {source_table} {source_alias} \
               ON {source_alias}.{source_id} = h.aggregate_id \
             WHERE h.aggregate_type = ? AND {source_alias}.{source_tenant} = ?"
        ))
        .bind(aggregate)
        .bind(namespace.tenant_id)
        .execute(pool)
        .await
        .unwrap();
    }

    sqlx::query("DELETE FROM audit_log WHERE tenant_id = ? AND user_id = ?")
        .bind(namespace.tenant_id)
        .bind(namespace.user_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM permission_rule WHERE tenant_id = ? AND card_id = ?")
        .bind(namespace.tenant_id)
        .bind(namespace.card_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM rule_set_entry WHERE rule_set_id = ?")
        .bind(namespace.rule_set_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM card_rule_set_ref WHERE rule_set_id = ?")
        .bind(namespace.rule_set_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM rule_set WHERE rule_set_id = ? AND tenant_id = ?")
        .bind(namespace.rule_set_id)
        .bind(namespace.tenant_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM user_card WHERE card_id = ? AND tenant_id = ?")
        .bind(namespace.card_id)
        .bind(namespace.tenant_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM identity_card WHERE card_id = ? AND user_id = ?")
        .bind(namespace.identity_card_id)
        .bind(namespace.user_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM tenant_domain_map WHERE id = ? AND tenant_id = ?")
        .bind(namespace.tenant_domain_map_id)
        .bind(namespace.tenant_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM tenant WHERE tenant_id = ?")
        .bind(namespace.tenant_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM platform_domain WHERE domain_id = ?")
        .bind(namespace.domain_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM platform_user WHERE user_id = ?")
        .bind(namespace.user_id)
        .execute(pool)
        .await
        .unwrap();
}

/// Seed a tenant/domain/user/card, a MANUAL RuleSet placeholder and an
/// independent MANUAL permission_rule baseline fact.
async fn seed_namespace(pool: &MySqlPool, namespace: &TestNamespace) -> Result<(), sqlx::Error> {
    cleanup_namespace(pool, namespace).await;

    sqlx::query(
        "INSERT INTO platform_domain (domain_id, domain_code, domain_name, status) \
         VALUES (?, ?, ?, 'ACTIVE')",
    )
    .bind(namespace.domain_id)
    .bind(format!("e2e_domain_{}", namespace.domain_id))
    .bind("E2E domain")
    .execute(pool)
    .await?;

    sqlx::query(
        "INSERT INTO tenant \
         (tenant_id, tenant_code, tenant_name, tenant_type, status, path, depth) \
         VALUES (?, ?, ?, 'ORGANIZATION', 'ACTIVE', ?, 0)",
    )
    .bind(namespace.tenant_id)
    .bind(format!("e2e_tenant_{}", namespace.tenant_id))
    .bind("E2E tenant")
    .bind(format!("/{}", namespace.tenant_id))
    .execute(pool)
    .await?;

    sqlx::query(
        "INSERT INTO tenant_domain_map (id, tenant_id, domain_id, status) \
         VALUES (?, ?, ?, 'ACTIVE')",
    )
    .bind(namespace.tenant_domain_map_id)
    .bind(namespace.tenant_id)
    .bind(namespace.domain_id)
    .execute(pool)
    .await?;

    sqlx::query(
        "INSERT INTO platform_user \
         (user_id, user_no, display_name, source_type, status) \
         VALUES (?, ?, ?, 'LOCAL', 'ACTIVE')",
    )
    .bind(namespace.user_id)
    .bind(format!("e2e_user_{}", namespace.user_id))
    .bind("E2E user")
    .execute(pool)
    .await?;

    sqlx::query(
        "INSERT INTO identity_card (card_id, user_id, status, token_version) \
         VALUES (?, ?, 'ACTIVE', 1)",
    )
    .bind(namespace.identity_card_id)
    .bind(namespace.user_id)
    .execute(pool)
    .await?;

    sqlx::query(
        "INSERT INTO user_card \
         (card_id, user_id, domain_id, card_type, card_status, template_id, tenant_id) \
         VALUES (?, ?, ?, 'ORG_CARD', 'ACTIVE', NULL, ?)",
    )
    .bind(namespace.card_id)
    .bind(namespace.user_id)
    .bind(namespace.domain_id)
    .bind(namespace.tenant_id)
    .execute(pool)
    .await?;

    sqlx::query(
        "INSERT INTO rule_set \
         (rule_set_id, name, code, description, source_type, enabled, tenant_id) \
         VALUES (?, ?, ?, ?, 'MANUAL', 1, ?)",
    )
    .bind(namespace.rule_set_id)
    .bind("E2E rule set")
    .bind(format!("e2e_rule_set_{}", namespace.rule_set_id))
    .bind("E2E fixture rule set")
    .bind(namespace.tenant_id)
    .execute(pool)
    .await?;

    // This disabled ALLOW placeholder makes the MANUAL RuleSet eligible for the
    // production writer without pre-seeding a grant or a card binding.
    sqlx::query(
        "INSERT INTO rule_set_entry \
         (entry_id, rule_set_id, resource_type, action_code, effect, priority, enabled, tenant_id) \
         VALUES (?, ?, 'learn_subject', 'read', 'ALLOW', 1, 0, ?)",
    )
    .bind(namespace.placeholder_entry_id)
    .bind(namespace.rule_set_id)
    .bind(namespace.tenant_id)
    .execute(pool)
    .await?;

    // This MANUAL baseline remains independent of the published RuleSet grants.
    sqlx::query(
        "INSERT INTO permission_rule \
         (rule_id, card_id, resource_type, resource_id, action_code, effect, priority, source_type, enabled, tenant_id) \
         VALUES (?, ?, 'audit', NULL, 'delete', 'DENY', 1, 'MANUAL', 1, ?)",
    )
    .bind(namespace.permission_rule_id)
    .bind(namespace.card_id)
    .bind(namespace.tenant_id)
    .execute(pool)
    .await?;

    Ok(())
}

fn allow_entry() -> AddEntryRequest {
    AddEntryRequest {
        effect: "ALLOW".to_owned(),
        resource_type: Some("learn_subject".to_owned()),
        resource_id: None,
        action_code: Some("read".to_owned()),
        condition_json: None,
        priority: 2,
    }
}

/// Write real RuleSet source facts and let the shared helper prove WorkerOwned publication.
async fn publish_fixture(
    pool: &MySqlPool,
    namespace: &TestNamespace,
) -> testsuite::PublishedCardFixture {
    let published = publish_card_manifest(
        pool,
        namespace.tenant_id,
        namespace.card_id,
        namespace.rule_set_id,
        namespace.user_id,
        vec![allow_entry()],
        ("core-db-integration", namespace.salt),
    )
    .await;
    published
}

/// Real-MySQL concurrency test for exact Local outbox claims, the completion
/// token CAS, and per-scope FIFO. Requires the outbox plus scope-sequence
/// migrations; never creates schema or runs a migration itself.
#[ignore]
#[tokio::test]
async fn local_message_exact_claim_is_concurrent_fifo_and_token_fenced() {
    let Some(pool) = connect().await else {
        return;
    };
    let suffix = Uuid::new_v4().to_string();
    let queue_name = "astral.authorization.invalidation";
    let ordering_key = format!("integration:local-claim:{suffix}");
    let message_ids = [
        format!("local-claim-a-{suffix}"),
        format!("local-claim-b-{suffix}"),
    ];
    let payload = serde_json::json!({"event": "claim-test", "key": suffix});
    let payload_sha256 = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&payload).unwrap())
    );
    let envelope_json = |message_id: &str, operation_id: &str| {
        serde_json::to_string(&serde_json::json!({
            "messageId": message_id,
            "operationId": operation_id,
            "messageType": "LOCAL_OUTBOX_TEST",
            "schemaVersion": 1,
            "tenantId": null,
            "originRegion": "integration",
            "targetRegion": null,
            "orderingKey": ordering_key,
            "traceId": null,
            "createdAt": "2026-10-03T00:00:00Z",
            "expiresAt": null,
            "payloadSha256": payload_sha256,
            "payload": payload,
        }))
        .unwrap()
    };
    let operation_ids = [format!("op-{suffix}"), format!("op-{suffix}-2")];
    let payload_jsons = [
        envelope_json(&message_ids[0], &operation_ids[0]),
        envelope_json(&message_ids[1], &operation_ids[1]),
    ];
    let repo = astral_db::LocalMessageRepository::new(pool.clone());
    let input_for = |index: usize| astral_db::LocalMessageInput {
        message_id: &message_ids[index],
        operation_id: &operation_ids[index],
        message_type: "LOCAL_OUTBOX_TEST",
        queue_name,
        ordering_key: Some(&ordering_key),
        tenant_id: None,
        origin_region: "integration",
        target_region: None,
        schema_version: 1,
        payload_json: &payload_jsons[index],
        headers_json: None,
        payload_sha256: &payload_sha256,
    };
    for index in 0..message_ids.len() {
        repo.append(&input_for(index))
            .await
            .expect("append exact-claim test row");
    }

    let first_id = &message_ids[0];
    let second_id = &message_ids[1];
    let first_claims = tokio::join!(
        repo.claim_exact("integration-claim-a", queue_name, first_id),
        repo.claim_exact("integration-claim-b", queue_name, first_id),
    );
    let (row, stale_token) = match first_claims {
        (Ok(astral_db::LocalMessageExactClaim::Claimed(row)), Ok(other))
        | (Ok(other), Ok(astral_db::LocalMessageExactClaim::Claimed(row))) => {
            assert!(matches!(
                other,
                astral_db::LocalMessageExactClaim::NotClaimable { .. }
            ));
            let token = row.lease_owner.clone().unwrap();
            (row, token)
        }
        pair => panic!("exact row must have one CAS owner only: {pair:?}"),
    };
    assert_eq!(row.message_id, *first_id);

    let later = repo
        .claim_exact("integration-claim-later", queue_name, second_id)
        .await
        .expect("second row FIFO check");
    assert!(
        matches!(&later, astral_db::LocalMessageExactClaim::NotClaimable { reason, .. } if reason.contains("FIFO blocked")),
        "later row must stay behind the first unprocessed row: {later:?}"
    );

    // The first row's lease owner is token-fenced. A stale token cannot complete.
    let stale = repo.complete(first_id, "not-the-claim-token").await;
    assert!(matches!(
        stale,
        Err(astral_db::LocalMessageError::LeaseLost)
    ));
    repo.complete(first_id, &stale_token)
        .await
        .expect("owned completion CAS");
    let later = repo
        .claim_exact("integration-claim-later", queue_name, second_id)
        .await
        .expect("second row after FIFO head completed");
    let later_row = match later {
        astral_db::LocalMessageExactClaim::Claimed(row) => row,
        other => panic!("second row should become claimable after FIFO head: {other:?}"),
    };
    let later_token = later_row.lease_owner.unwrap();
    repo.complete(second_id, &later_token)
        .await
        .expect("complete FIFO successor");
    let claimed = repo
        .claim_exact("integration-claim-complete", queue_name, first_id)
        .await
        .expect("completed exact row lookup");
    assert!(matches!(
        claimed,
        astral_db::LocalMessageExactClaim::AlreadyProcessed(_)
    ));

    sqlx::query("DELETE FROM al_message_outbox WHERE queue_name = ? AND ordering_key = ?")
        .bind(queue_name)
        .bind(&ordering_key)
        .execute(&pool)
        .await
        .expect("cleanup local claim rows");
}

/// 需要 MySQL，标记为 ignored 默认不执行。
#[ignore]
#[tokio::test]
async fn test_sqlx_repository_e2e() {
    let Some(pool) = connect().await else {
        return;
    };

    let namespace = TestNamespace::new();
    seed_namespace(&pool, &namespace).await.unwrap();
    let published = publish_fixture(&pool, &namespace).await;

    let repo = SqlxRuleRepository::new(pool.clone());
    let context = astral_types::PolicyContext::builder()
        .user_id(Some(namespace.user_id))
        .identity_card_id(Some(namespace.identity_card_id))
        .card_id(Some(namespace.card_id))
        .tenant_id(Some(namespace.tenant_id))
        .domain_id(Some(namespace.domain_id))
        .action("read".to_owned())
        .build();
    assert!(
        repo.check_card_active(&context)
            .await
            .expect("the seeded identity/user card pair must be readable"),
        "identity_card and user_card must resolve to the same actual fixture user"
    );

    // The source writer must persist user actor audit correlation for both BASE
    // binding and entry replacement, independently of the published grant proof.
    let audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM rule_set_projection_audit \
         WHERE rule_set_id = ? AND tenant_id = ? AND changed_by = ? \
           AND aggregate_type = 'RULE_SET' AND aggregate_id = ? \
           AND change_type IN ('BIND_CARD', 'BATCH_REPLACE_ENTRIES')",
    )
    .bind(namespace.rule_set_id)
    .bind(namespace.tenant_id)
    .bind(namespace.user_id)
    .bind(namespace.rule_set_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        audit_count, 2,
        "real source operations must retain actor audit facts"
    );
    assert_eq!(published.pointer.identity.tenant_id, namespace.tenant_id);
    assert_eq!(
        published.pointer.identity.aggregate_id,
        namespace.rule_set_id
    );
    assert_eq!(published.pointer.card_id, Some(namespace.card_id));

    // Formal CURRENT V6 read: only the genuine published RuleSet ALLOW is effective.
    let evidence = repo
        .load_published_card_authorization(&namespace.evidence_scope())
        .await
        .expect("published card evidence read must not fail after a clean publication")
        .expect("a cleanly published card must yield Ready evidence (never Ok(None))");
    assert_eq!(evidence.gate.status, PublishedEvidenceGateStatus::Ready);
    assert_eq!(evidence.gate.effective_grant_count, 1);
    assert_eq!(evidence.effective_grants.len(), 1);
    let grant = &evidence.effective_grants[0];
    assert_eq!(grant.resource, "learn_subject:*");
    assert_eq!(grant.action, "read");
    assert_eq!(grant.effect, GrantEffect::Allow);
    assert_eq!(grant.tenant.tenant_id, namespace.tenant_id);
    assert_eq!(grant.card_id, namespace.card_id);
    assert_eq!(grant.user_id, namespace.user_id);
    assert_eq!(grant.provenance.actor_user_id, Some(namespace.user_id));
    assert_eq!(
        grant.provenance.source_id,
        namespace.rule_set_id.to_string()
    );
    assert_eq!(
        evidence.records[0].aggregate_type, "RULE_SET",
        "published evidence must identify its actual source aggregate"
    );
    assert_eq!(evidence.records[0].aggregate_id, namespace.rule_set_id);
    source_identity::assert_ruleset_source_binding(
        &pool,
        grant,
        namespace.tenant_id,
        namespace.card_id,
        namespace.rule_set_id,
    )
    .await;

    // The retained manual DENY is a source baseline only: it is not projected
    // into canonical grants and cannot override or extend CURRENT V6 evidence.
    let baseline: (String, String, String, String, i8, Option<i64>) = sqlx::query_as(
        "SELECT source_type, resource_type, action_code, effect, enabled, tenant_id \
         FROM permission_rule WHERE rule_id = ? AND card_id = ?",
    )
    .bind(namespace.permission_rule_id)
    .bind(namespace.card_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        baseline,
        (
            "MANUAL".to_owned(),
            "audit".to_owned(),
            "delete".to_owned(),
            "DENY".to_owned(),
            1,
            Some(namespace.tenant_id),
        )
    );
    assert!(evidence
        .effective_grants
        .iter()
        .all(|grant| grant.resource != "audit:*" && grant.action != "delete"));

    // No published pointer is PENDING, not an empty authorization success.
    let missing = repo
        .load_published_card_authorization(&namespace.unpublished_card_scope())
        .await
        .expect_err("a card without published evidence must fail closed");
    match missing {
        PolicyError::Repository(message) => {
            assert!(
                message.contains("published_card_evidence_not_ready"),
                "unexpected policy error family: {message}"
            );
        }
        other => panic!("missing evidence must map to Repository (PENDING), got: {other:?}"),
    }

    cleanup_namespace(&pool, &namespace).await;
}
