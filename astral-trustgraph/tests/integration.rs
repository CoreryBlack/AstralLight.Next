//! Integration tests for astral-trustgraph SQL against platform_v4 database schema.
//!
//! All tests are `#[ignore]` because they require a running MySQL instance.
//! Run with: `cargo test -p astral-trustgraph -- --ignored`
//!
//! Test strategy: INSERT using platform_v4 real column names, then SELECT using the
//! SAME SQL aliases as the Rust source code, to verify the `FromRow` bridge works.

use astral_trustgraph::repository::audit_log_repository::{
    insert_approval_audit_in_tx, ApprovalAuditContext, ApprovalAuditEntry,
};
use sqlx::MySqlPool;
use time::OffsetDateTime;

// ===== Helper =====

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
        Ok(p) => Some(p),
        Err(e) => {
            if required {
                panic!("RUST_INTEGRATION_REQUIRED=1: cannot connect using DATABASE_URL: {e}");
            }
            eprintln!("[SKIP] Cannot connect using DATABASE_URL: {e}");
            None
        }
    }
}

// ===== Test 1: permission_rule CRUD =====

#[derive(Debug, sqlx::FromRow)]
struct RuleRow {
    card_id: i64,
    effect: String,
    resource_type: String,
    action_code: String,
    source_type: String,
    priority: i32,
    condition_json: Option<String>,
}

#[tokio::test]
#[ignore]
async fn test_permission_rule_crud() {
    let Some(pool) = connect().await else { return };

    let mut tx = pool.begin().await.expect("begin tx");

    // Disable FK checks for test isolation (permission_rule.card_id → user_card.card_id)
    sqlx::query("SET FOREIGN_KEY_CHECKS = 0")
        .execute(&mut *tx)
        .await
        .expect("disable FK checks");

    // INSERT — aligns with platform_v4 permission_rule columns
    sqlx::query(
        "INSERT INTO permission_rule (card_id, effect, resource_type, action_code, source_type, priority, condition_json, enabled) \
         VALUES (9991, 'ALLOW', 'user', 'read', 'MANUAL', 10, NULL, 1)",
    )
    .execute(&mut *tx)
    .await
    .expect("insert permission_rule");

    // SELECT — same column list as rules.rs RULE_SELECT_COLUMNS (no aliases)
    let row: RuleRow = sqlx::query_as(
        "SELECT card_id, effect, resource_type, action_code, source_type, priority, condition_json \
         FROM permission_rule WHERE card_id = 9991 AND source_type = 'MANUAL'",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("select permission_rule");

    assert_eq!(row.card_id, 9991);
    assert_eq!(row.effect, "ALLOW");
    assert_eq!(row.resource_type, "user");
    assert_eq!(row.action_code, "read");
    assert_eq!(row.source_type, "MANUAL");
    assert_eq!(row.priority, 10);
    assert!(row.condition_json.is_none());

    // UPDATE
    sqlx::query("UPDATE permission_rule SET effect = 'DENY', priority = 20 WHERE card_id = 9991 AND source_type = 'MANUAL'")
        .execute(&mut *tx)
        .await
        .expect("update permission_rule");

    let updated: RuleRow = sqlx::query_as(
        "SELECT card_id, effect, resource_type, action_code, source_type, priority, condition_json \
         FROM permission_rule WHERE card_id = 9991 AND source_type = 'MANUAL'",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("select after update");

    assert_eq!(updated.effect, "DENY");
    assert_eq!(updated.priority, 20);

    // DELETE
    sqlx::query("DELETE FROM permission_rule WHERE card_id = 9991 AND source_type = 'MANUAL'")
        .execute(&mut *tx)
        .await
        .expect("delete permission_rule");

    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM permission_rule WHERE card_id = 9991 AND source_type = 'MANUAL'",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("count after delete");

    assert_eq!(count.0, 0);

    sqlx::query("SET FOREIGN_KEY_CHECKS = 1")
        .execute(&mut *tx)
        .await
        .ok();
    tx.rollback().await.expect("rollback");
}

// ===== Test 2: rule_set with aliases =====

#[derive(Debug, sqlx::FromRow)]
struct RuleSetRow {
    name: String,
    ref_type: String,
    description: Option<String>,
}

#[tokio::test]
#[ignore]
async fn test_rule_set_id_and_source_type_aliases() {
    let Some(pool) = connect().await else { return };

    let mut tx = pool.begin().await.expect("begin tx");

    // INSERT — platform_v4 rule_set columns: rule_set_id (AI), name, code (UNIQUE), source_type, description, enabled
    sqlx::query(
        "INSERT INTO rule_set (name, code, source_type, description, enabled) \
         VALUES ('test-ruleset', 'test-ruleset', 'TEMPLATE', 'integration test', 1)",
    )
    .execute(&mut *tx)
    .await
    .expect("insert rule_set");

    // SELECT — same aliases as rule_sets.rs RULE_SET_SELECT
    let row: RuleSetRow = sqlx::query_as(
        "SELECT name, source_type as ref_type, description FROM rule_set \
         WHERE code = 'test-ruleset'",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("select rule_set with aliases");

    assert_eq!(row.name, "test-ruleset");
    assert_eq!(row.ref_type, "TEMPLATE");
    assert_eq!(row.description.as_deref(), Some("integration test"));

    tx.rollback().await.expect("rollback");
}

// ===== Test 3: rule_set_entry + card_rule_set_ref =====

#[tokio::test]
#[ignore]
async fn test_rule_set_entry_and_card_ref() {
    let Some(pool) = connect().await else { return };

    let mut tx = pool.begin().await.expect("begin tx");

    // Disable FK checks for test isolation (card_rule_set_ref.card_id → user_card.card_id)
    sqlx::query("SET FOREIGN_KEY_CHECKS = 0")
        .execute(&mut *tx)
        .await
        .expect("disable FK checks");

    // Create a rule_set
    sqlx::query(
        "INSERT INTO rule_set (name, code, source_type, description, enabled) \
         VALUES ('entry-test-rs', 'entry-test-rs', 'BASE', 'entry test', 1)",
    )
    .execute(&mut *tx)
    .await
    .expect("insert rule_set");

    let (rule_set_id,): (i64,) =
        sqlx::query_as("SELECT rule_set_id FROM rule_set WHERE code = 'entry-test-rs'")
            .fetch_one(&mut *tx)
            .await
            .expect("get rule_set_id");

    // Insert rule_set_entry
    sqlx::query(
        "INSERT INTO rule_set_entry (rule_set_id, effect, resource_type, action_code, condition_json, priority, enabled) \
         VALUES (?, 'ALLOW', 'user', 'read', NULL, 10, 1)",
    )
    .bind(rule_set_id)
    .execute(&mut *tx)
    .await
    .expect("insert rule_set_entry");

    // Insert card_rule_set_ref with BASE
    sqlx::query(
        "INSERT INTO card_rule_set_ref (card_id, rule_set_id, ref_type) \
         VALUES (8881, ?, 'BASE')",
    )
    .bind(rule_set_id)
    .execute(&mut *tx)
    .await
    .expect("insert card_rule_set_ref BASE");

    // Insert card_rule_set_ref with OVERLAY for a different card
    sqlx::query(
        "INSERT INTO card_rule_set_ref (card_id, rule_set_id, ref_type) \
         VALUES (8882, ?, 'OVERLAY')",
    )
    .bind(rule_set_id)
    .execute(&mut *tx)
    .await
    .expect("insert card_rule_set_ref OVERLAY");

    // Verify COUNT(DISTINCT card_id) — same query pattern as rule_sets.rs
    let (bound_count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(DISTINCT card_id) FROM card_rule_set_ref WHERE rule_set_id = ?",
    )
    .bind(rule_set_id)
    .fetch_one(&mut *tx)
    .await
    .expect("count distinct card_id");

    assert_eq!(bound_count, 2);

    // Verify entry count
    let (entry_count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM rule_set_entry WHERE rule_set_id = ?")
            .bind(rule_set_id)
            .fetch_one(&mut *tx)
            .await
            .expect("count entries");

    assert_eq!(entry_count, 1);

    // Verify ref_type values
    let base_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM card_rule_set_ref WHERE rule_set_id = ? AND ref_type = 'BASE'",
    )
    .bind(rule_set_id)
    .fetch_one(&mut *tx)
    .await
    .expect("count BASE refs");

    let overlay_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM card_rule_set_ref WHERE rule_set_id = ? AND ref_type = 'OVERLAY'",
    )
    .bind(rule_set_id)
    .fetch_one(&mut *tx)
    .await
    .expect("count OVERLAY refs");

    assert_eq!(base_count.0, 1);
    assert_eq!(overlay_count.0, 1);

    sqlx::query("SET FOREIGN_KEY_CHECKS = 1")
        .execute(&mut *tx)
        .await
        .ok();
    tx.rollback().await.expect("rollback");
}

// ===== Test 4: user_card with DATE_FORMAT aliases =====

#[derive(Debug, sqlx::FromRow)]
struct UserCardRow {
    card_id: i64,
    user_id: Option<i64>,
    domain_id: Option<i64>,
    card_type: String,
    card_status: String,
    template_id: Option<i64>,
    level_id: Option<i64>,
    priority: Option<i32>,
    is_primary: Option<bool>,
    created_at: Option<String>,
    tenant_id: Option<i64>,
}

#[tokio::test]
#[ignore]
async fn test_user_card_date_format_aliases() {
    let Some(pool) = connect().await else { return };

    let mut tx = pool.begin().await.expect("begin tx");

    // Disable FK checks for test isolation (user_card has FK to platform_user, platform_domain, etc.)
    sqlx::query("SET FOREIGN_KEY_CHECKS = 0")
        .execute(&mut *tx)
        .await
        .expect("disable FK checks");

    // INSERT — platform_v4 user_card columns
    sqlx::query(
        "INSERT INTO user_card (user_id, domain_id, card_type, card_status, template_id, level_id, priority, is_primary, tenant_id) \
         VALUES (1001, 2001, 'STANDARD', 'ACTIVE', 3001, 4001, 50, 1, 5001)",
    )
    .execute(&mut *tx)
    .await
    .expect("insert user_card");

    let (card_id,): (i64,) = sqlx::query_as(
        "SELECT card_id FROM user_card WHERE user_id = 1001 AND card_type = 'STANDARD'",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("get card_id");

    // SELECT — same column list + DATE_FORMAT aliases as user_cards.rs USER_CARD_SELECT_COLUMNS
    let row: UserCardRow = sqlx::query_as(
        "SELECT card_id, user_id, domain_id, card_type, card_status, template_id, level_id, priority, is_primary, \
         DATE_FORMAT(created_at, '%Y-%m-%dT%H:%i:%sZ') as created_at, \
         tenant_id FROM user_card WHERE card_id = ?",
    )
    .bind(card_id)
    .fetch_one(&mut *tx)
    .await
    .expect("select user_card with date format aliases");

    assert_eq!(row.card_id, card_id);
    assert_eq!(row.user_id, Some(1001));
    assert_eq!(row.domain_id, Some(2001));
    assert_eq!(row.card_type, "STANDARD");
    assert_eq!(row.card_status, "ACTIVE");
    assert_eq!(row.template_id, Some(3001));
    assert_eq!(row.level_id, Some(4001));
    assert_eq!(row.priority, Some(50));
    assert_eq!(row.is_primary, Some(true));
    assert_eq!(row.tenant_id, Some(5001));
    // DATE_FORMAT returns String; created_at should be set by DB default
    assert!(row.created_at.is_some());
    // valid_from/valid_until may be NULL if not set
    // updated_at may be NULL depending on schema

    sqlx::query("SET FOREIGN_KEY_CHECKS = 1")
        .execute(&mut *tx)
        .await
        .ok();
    tx.rollback().await.expect("rollback");
}

// ===== Test 5: user_card soft-delete cascade =====

#[tokio::test]
#[ignore]
async fn test_user_card_soft_delete_cascade() {
    let Some(pool) = connect().await else { return };

    let mut tx = pool.begin().await.expect("begin tx");

    // Disable FK checks for test isolation (user_card has FK to platform_user, platform_domain, etc.)
    sqlx::query("SET FOREIGN_KEY_CHECKS = 0")
        .execute(&mut *tx)
        .await
        .expect("disable FK checks");

    // 1. Create a user_card
    sqlx::query(
        "INSERT INTO user_card (user_id, domain_id, card_type, card_status, template_id, level_id, priority, is_primary, tenant_id) \
         VALUES (7771, 7772, 'STANDARD', 'ACTIVE', 7773, 7774, 10, 0, 7775)",
    )
    .execute(&mut *tx)
    .await
    .expect("insert user_card");

    let (card_id,): (i64,) = sqlx::query_as(
        "SELECT card_id FROM user_card WHERE user_id = 7771 AND card_type = 'STANDARD'",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("get card_id");

    // 2. Create related permission_rule
    sqlx::query(
        "INSERT INTO permission_rule (card_id, effect, resource_type, action_code, source_type, priority, enabled) \
         VALUES (?, 'ALLOW', 'learn_subject', 'read', 'TEMPLATE', 10, 1)",
    )
    .bind(card_id)
    .execute(&mut *tx)
    .await
    .expect("insert permission_rule");

    // 3. Create rule_set and card_rule_set_ref
    // （旧夹具还插入 permission_rule_snapshot；该表已随迁移 20260827000002
    // 删除，快照维度整体退役，级联清理不再触碰。）
    sqlx::query(
        "INSERT INTO rule_set (name, code, source_type, description, enabled) \
         VALUES ('cascade-test-rs', 'cascade-test-rs', 'BASE', 'cascade test', 1)",
    )
    .execute(&mut *tx)
    .await
    .expect("insert rule_set for cascade");

    let (rule_set_id,): (i64,) =
        sqlx::query_as("SELECT rule_set_id FROM rule_set WHERE code = 'cascade-test-rs'")
            .fetch_one(&mut *tx)
            .await
            .expect("get rule_set_id");

    sqlx::query(
        "INSERT INTO card_rule_set_ref (card_id, rule_set_id, ref_type) VALUES (?, ?, 'BASE')",
    )
    .bind(card_id)
    .bind(rule_set_id)
    .execute(&mut *tx)
    .await
    .expect("insert card_rule_set_ref");

    // Verify related data exists before cascade
    let pr_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM permission_rule WHERE card_id = ?")
        .bind(card_id)
        .fetch_one(&mut *tx)
        .await
        .expect("count rules before");
    assert_eq!(pr_count.0, 1);

    let crsr_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM card_rule_set_ref WHERE card_id = ?")
            .bind(card_id)
            .fetch_one(&mut *tx)
            .await
            .expect("count refs before");
    assert_eq!(crsr_count.0, 1);

    // 4. Cascade delete — same order as user_cards.rs delete_user_card
    // Delete permission_rule
    let pr_deleted = sqlx::query("DELETE FROM permission_rule WHERE card_id = ?")
        .bind(card_id)
        .execute(&mut *tx)
        .await
        .expect("delete permission_rule")
        .rows_affected();
    assert_eq!(pr_deleted, 1);

    // Delete card_rule_set_ref
    let crsr_deleted = sqlx::query("DELETE FROM card_rule_set_ref WHERE card_id = ?")
        .bind(card_id)
        .execute(&mut *tx)
        .await
        .expect("delete card_rule_set_ref")
        .rows_affected();
    assert_eq!(crsr_deleted, 1);

    // Soft-delete user_card
    sqlx::query("UPDATE user_card SET card_status = 'DELETED' WHERE card_id = ?")
        .bind(card_id)
        .execute(&mut *tx)
        .await
        .expect("soft delete user_card");

    // 5. Verify all related data cleaned up
    let pr_after: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM permission_rule WHERE card_id = ?")
        .bind(card_id)
        .fetch_one(&mut *tx)
        .await
        .expect("count rules after");
    assert_eq!(pr_after.0, 0);

    let crsr_after: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM card_rule_set_ref WHERE card_id = ?")
            .bind(card_id)
            .fetch_one(&mut *tx)
            .await
            .expect("count refs after");
    assert_eq!(crsr_after.0, 0);

    // Verify user_card is soft-deleted (status = DELETED, not physically removed)
    let status: (String,) = sqlx::query_as("SELECT card_status FROM user_card WHERE card_id = ?")
        .bind(card_id)
        .fetch_one(&mut *tx)
        .await
        .expect("get card_status after soft delete");
    assert_eq!(status.0, "DELETED");

    sqlx::query("SET FOREIGN_KEY_CHECKS = 1")
        .execute(&mut *tx)
        .await
        .ok();
    tx.rollback().await.expect("rollback");
}

// ===== Test 6: audit_log CRUD =====

#[derive(Debug, sqlx::FromRow)]
struct AuditEntry {
    user_id: i64,
    action: String,
    resource: String,
    decision: String,
    reason: Option<String>,
    card_id: Option<i64>,
}

#[tokio::test]
#[ignore]
async fn test_audit_log_crud() {
    let Some(pool) = connect().await else { return };

    let mut tx = pool.begin().await.expect("begin tx");

    // INSERT — aligns with platform_v4 audit_log columns
    sqlx::query(
        "INSERT INTO audit_log (user_id, action, resource, decision, reason, card_id) \
         VALUES (6001, 'read', 'user', 'ALLOW', 'policy match', 6002)",
    )
    .execute(&mut *tx)
    .await
    .expect("insert audit_log ALLOW");

    sqlx::query(
        "INSERT INTO audit_log (user_id, action, resource, decision, reason, card_id) \
         VALUES (6003, 'delete', 'learn_subject', 'DENY', 'no matching rule', NULL)",
    )
    .execute(&mut *tx)
    .await
    .expect("insert audit_log DENY");

    // SELECT — same columns as audit.rs AuditEntry with DATE_FORMAT for created_at
    let rows: Vec<AuditEntry> = sqlx::query_as(
        "SELECT user_id, action, resource, decision, reason, card_id \
         FROM audit_log WHERE user_id IN (6001, 6003) ORDER BY id",
    )
    .fetch_all(&mut *tx)
    .await
    .expect("select audit_log");

    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].user_id, 6001);
    assert_eq!(rows[0].action, "read");
    assert_eq!(rows[0].resource, "user");
    assert_eq!(rows[0].decision, "ALLOW");
    assert_eq!(rows[0].reason.as_deref(), Some("policy match"));
    assert_eq!(rows[0].card_id, Some(6002));

    assert_eq!(rows[1].user_id, 6003);
    assert_eq!(rows[1].decision, "DENY");
    assert!(rows[1].card_id.is_none());

    // Aggregate stats — same pattern as audit.rs audit_stats
    let allowed: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit_log WHERE decision = 'ALLOW' AND user_id IN (6001, 6003)",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("count ALLOW");

    let denied: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit_log WHERE decision = 'DENY' AND user_id IN (6001, 6003)",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("count DENY");

    assert_eq!(allowed.0, 1);
    assert_eq!(denied.0, 1);

    tx.rollback().await.expect("rollback");
}

// ===== Test 7: permission_request with DATE_FORMAT alias =====

#[derive(Debug, sqlx::FromRow)]
struct PermissionRequestRow {
    user_id: i64,
    request_type: String,
    request_content: Option<String>,
    reason: Option<String>,
    status: String,
    approver_id: Option<i64>,
    approve_comment: Option<String>,
    created_at: Option<String>,
}

#[tokio::test]
#[ignore]
async fn test_permission_request_date_format_alias() {
    let Some(pool) = connect().await else { return };

    let mut tx = pool.begin().await.expect("begin tx");

    // INSERT — aligns with platform_v4 permission_request columns
    // request_content stores canonical JSON with resourceType/actionCode/cardId per approval.rs
    let content = r#"{"resourceType":"learn_subject","actionCode":"create","cardId":7001}"#;

    sqlx::query(
        "INSERT INTO permission_request (user_id, request_type, request_content, reason, status) \
         VALUES (7002, 'RULE', ?, 'need subject create access', 'PENDING')",
    )
    .bind(content)
    .execute(&mut *tx)
    .await
    .expect("insert permission_request");

    // SELECT — same column list + DATE_FORMAT alias as approval.rs PR_SELECT
    let row: PermissionRequestRow = sqlx::query_as(
        "SELECT user_id, request_type, request_content, reason, status, approver_id, approve_comment, \
         DATE_FORMAT(created_at, '%Y-%m-%dT%H:%i:%sZ') as created_at \
         FROM permission_request WHERE user_id = 7002 AND request_type = 'RULE'",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("select permission_request");

    assert_eq!(row.user_id, 7002);
    assert_eq!(row.request_type, "RULE");
    assert_eq!(row.status, "PENDING");
    assert_eq!(row.reason.as_deref(), Some("need subject create access"));
    assert!(row.approver_id.is_none());
    assert!(row.approve_comment.is_none());
    assert!(row.created_at.is_some());

    // Verify request_content JSON round-trips
    assert!(row.request_content.is_some());
    let parsed: serde_json::Value = serde_json::from_str(row.request_content.as_deref().unwrap())
        .expect("parse request_content JSON");
    assert_eq!(parsed["resourceType"], "learn_subject");
    assert_eq!(parsed["actionCode"], "create");
    assert_eq!(parsed["cardId"], 7001);

    tx.rollback().await.expect("rollback");
}

// ===== Test 8: permission_request approval transaction =====

#[tokio::test]
#[ignore]
async fn test_permission_request_approve_transaction() {
    let Some(pool) = connect().await else { return };

    let mut tx = pool.begin().await.expect("begin tx");

    // Disable FK checks for test isolation (permission_rule.card_id → user_card.card_id)
    sqlx::query("SET FOREIGN_KEY_CHECKS = 0")
        .execute(&mut *tx)
        .await
        .expect("disable FK checks");

    // 1. INSERT permission_request with status='PENDING'
    let content = r#"{"resourceType":"learn_question","actionCode":"delete","cardId":8001}"#;

    sqlx::query(
        "INSERT INTO permission_request (user_id, request_type, request_content, reason, status) \
         VALUES (8002, 'RULE', ?, 'need question delete', 'PENDING')",
    )
    .bind(content)
    .execute(&mut *tx)
    .await
    .expect("insert pending permission_request");

    let (request_id,): (i64,) = sqlx::query_as(
        "SELECT request_id FROM permission_request WHERE user_id = 8002 AND status = 'PENDING'",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("get request_id");

    // Verify initial state is PENDING
    let initial_status: (String,) =
        sqlx::query_as("SELECT status FROM permission_request WHERE request_id = ?")
            .bind(request_id)
            .fetch_one(&mut *tx)
            .await
            .expect("check initial status");
    assert_eq!(initial_status.0, "PENDING");

    // 2. In transaction: UPDATE permission_request + INSERT permission_rule
    //    Same pattern as approval.rs approve_request
    sqlx::query(
        "UPDATE permission_request SET status = 'APPROVED', approver_id = 9001, approved_at = NOW(), approve_comment = 'approved in test' \
         WHERE request_id = ?",
    )
    .bind(request_id)
    .execute(&mut *tx)
    .await
    .expect("update permission_request to APPROVED");

    sqlx::query(
        "INSERT INTO permission_rule (card_id, effect, resource_type, action_code, source_type, enabled) \
         VALUES (8001, 'ALLOW', 'learn_question', 'delete', 'MANUAL', 1)",
    )
    .execute(&mut *tx)
    .await
    .expect("insert permission_rule on approval");

    // 3. Verify both changes committed atomically
    let approved_status: (String,) =
        sqlx::query_as("SELECT status FROM permission_request WHERE request_id = ?")
            .bind(request_id)
            .fetch_one(&mut *tx)
            .await
            .expect("check approved status");
    assert_eq!(approved_status.0, "APPROVED");

    let rule_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM permission_rule WHERE card_id = 8001 AND resource_type = 'learn_question' AND action_code = 'delete'",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("count inserted rule");
    assert_eq!(rule_count.0, 1);

    sqlx::query("SET FOREIGN_KEY_CHECKS = 1")
        .execute(&mut *tx)
        .await
        .ok();
    tx.rollback().await.expect("rollback");
}

// ===== Test 8b: approval audit failure rolls back the sensitive status =====

#[tokio::test]
#[ignore]
async fn test_approval_audit_failure_rolls_back_status() {
    let Some(pool) = connect().await else { return };

    let mode: (String,) = sqlx::query_as("SELECT @@SESSION.sql_mode")
        .fetch_one(&pool)
        .await
        .expect("read MySQL SQL mode");
    if !mode
        .0
        .split(',')
        .any(|value| value.trim() == "STRICT_TRANS_TABLES")
        && !mode
            .0
            .split(',')
            .any(|value| value.trim() == "STRICT_ALL_TABLES")
    {
        eprintln!("[SKIP] approval audit rollback test requires strict MySQL SQL mode");
        return;
    }

    let request_content =
        r#"{"resourceType":"learn_question","actionCode":"delete","cardId":8101}"#;
    let inserted = sqlx::query(
        "INSERT INTO permission_request (user_id, request_type, request_content, reason, status) \
         VALUES (8102, 'RULE', ?, 'audit rollback test', 'PENDING')",
    )
    .bind(request_content)
    .execute(&pool)
    .await
    .expect("insert pending permission request");
    let request_id = inserted.last_insert_id() as i64;

    let mut tx = pool.begin().await.expect("begin approval transaction");
    sqlx::query(
        "UPDATE permission_request SET status='APPROVED', approver_id=? \
         WHERE request_id=? AND status='PENDING'",
    )
    .bind(8103_i64)
    .bind(request_id)
    .execute(&mut *tx)
    .await
    .expect("update pending status before audit");

    // audit_log.action is VARCHAR(64); strict mode makes this insert fail,
    // proving the caller must roll back the already-applied sensitive update.
    let invalid_action = "x".repeat(65);
    let context = ApprovalAuditContext::new(Some("audit-rollback-request"), request_id);
    let audit_result = insert_approval_audit_in_tx(
        &mut tx,
        &ApprovalAuditEntry {
            actor_id: 8103,
            reviewer_id: Some(8103),
            target_user_id: 8102,
            target_card_id: Some(8101),
            action: &invalid_action,
            decision: "APPROVED",
            request_reason: Some("audit rollback test"),
            reviewer_comment: Some("must roll back"),
            context: &context,
        },
    )
    .await;
    assert!(
        audit_result.is_err(),
        "oversized action must fail audit insert"
    );
    tx.rollback().await.expect("rollback after audit failure");

    let status: (String,) =
        sqlx::query_as("SELECT status FROM permission_request WHERE request_id=?")
            .bind(request_id)
            .fetch_one(&pool)
            .await
            .expect("read status after rollback");
    assert_eq!(status.0, "PENDING");
    sqlx::query("DELETE FROM permission_request WHERE request_id=?")
        .bind(request_id)
        .execute(&pool)
        .await
        .expect("cleanup rollback test request");
}

// ===== Test 9: sod_policy and sod_violation =====

#[derive(Debug, sqlx::FromRow)]
struct SodPolicy {
    policy_id: Option<i64>,
    policy_name: String,
    conflict_type: String,
    permission_a: Option<String>,
    permission_b: Option<String>,
    status: String,
    created_at: Option<OffsetDateTime>,
}

#[derive(Debug, sqlx::FromRow)]
struct SodViolation {
    violation_id: Option<i64>,
    policy_id: i64,
    policy_name: String,
    card_id: i64,
    user_id: Option<i64>,
    operator_id: Option<i64>,
    violation_type: String,
    details_json: Option<String>,
    blocked: bool,
    created_at: Option<OffsetDateTime>,
}

#[tokio::test]
#[ignore]
async fn test_sod_policy_and_violation() {
    let Some(pool) = connect().await else { return };

    let mut tx = pool.begin().await.expect("begin tx");

    // INSERT sod_policy — aligns with platform_v4 columns
    sqlx::query(
        "INSERT INTO sod_policy (policy_name, description, conflict_type, resource_type, action_code, \
         permission_a, permission_b, condition_script, status, created_at, updated_at) \
         VALUES ('test-sod-policy', 'test conflict', 'STATIC', 'user', 'read', \
         'user:read', 'user:delete', NULL, 'ACTIVE', NOW(), NOW())",
    )
    .execute(&mut *tx)
    .await
    .expect("insert sod_policy");

    // SELECT — same columns as sod.rs SodPolicy
    let policy: SodPolicy = sqlx::query_as(
        "SELECT policy_id, policy_name, conflict_type, permission_a, permission_b, status, created_at \
         FROM sod_policy WHERE policy_name = 'test-sod-policy'",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("select sod_policy");

    assert!(policy.policy_id.is_some());
    assert_eq!(policy.policy_name, "test-sod-policy");
    assert_eq!(policy.conflict_type, "STATIC");
    assert_eq!(policy.permission_a.as_deref(), Some("user:read"));
    assert_eq!(policy.permission_b.as_deref(), Some("user:delete"));
    assert_eq!(policy.status, "ACTIVE");
    assert!(policy.created_at.is_some());

    let policy_id = policy.policy_id.unwrap();

    // INSERT sod_violation — aligns with platform_v4 columns
    sqlx::query(
        "INSERT INTO sod_violation (policy_id, policy_name, card_id, user_id, operator_id, violation_type, details_json, blocked, created_at) \
         VALUES (?, 'test-sod-policy', 5551, 5552, 5553, 'STATIC', ?, true, NOW())",
    )
    .bind(policy_id)
    .bind(r#"{"permission_a":"user:read","permission_b":"user:delete","card_id":5551}"#)
    .execute(&mut *tx)
    .await
    .expect("insert sod_violation");

    // SELECT — same columns as sod.rs SodViolation
    let violation: SodViolation = sqlx::query_as(
        "SELECT violation_id, policy_id, policy_name, card_id, user_id, operator_id, \
         violation_type, CAST(details_json AS CHAR) as details_json, blocked, created_at \
         FROM sod_violation WHERE policy_id = ? AND card_id = 5551",
    )
    .bind(policy_id)
    .fetch_one(&mut *tx)
    .await
    .expect("select sod_violation");

    assert!(violation.violation_id.is_some());
    assert_eq!(violation.policy_id, policy_id);
    assert_eq!(violation.policy_name, "test-sod-policy");
    assert_eq!(violation.card_id, 5551);
    assert_eq!(violation.user_id, Some(5552));
    assert_eq!(violation.operator_id, Some(5553));
    assert_eq!(violation.violation_type, "STATIC");
    assert!(violation.blocked);
    assert!(violation.details_json.is_some());
    assert!(violation.created_at.is_some());

    tx.rollback().await.expect("rollback");
}

// ===== Test 11: delete_with_cascade call-through（空卡主路径 + 幂等短路） =====
//
// 旧 Test 10（SoD UNION 镜像）已退役。镜像型集成测试无法暴露生产 SQL 对
// 已删表的损坏（permission_rule_snapshot 残留 DELETE 曾让已迁移库上删卡
// 1146→500，而镜像测试先死在自己的夹具上），因此本测试**真实调用生产仓库
// 方法** delete_with_cascade：夹具只负责前置状态（user_card 行），被测行为
// 全部走生产函数。

#[tokio::test]
#[ignore]
async fn test_delete_with_cascade_call_through_empty_card() {
    use astral_trustgraph::repository::user_card_repository::{
        SqlxUserCardRepository, UserCardRepository,
    };

    let Some(pool) = connect().await else { return };
    let repo = SqlxUserCardRepository::new(pool.clone());

    // 前置状态（独立事务并提交：被测函数自管事务，必须能看到夹具行）。
    let mut setup = pool.begin().await.expect("begin setup tx");
    sqlx::query("SET FOREIGN_KEY_CHECKS = 0")
        .execute(&mut *setup)
        .await
        .expect("disable FK checks");
    sqlx::query(
        "INSERT INTO user_card (user_id, domain_id, card_type, card_status, template_id, level_id, priority, is_primary, tenant_id)          VALUES (91881, 91882, 'STANDARD', 'ACTIVE', 91883, 91884, 10, 0, 91885)",
    )
    .execute(&mut *setup)
    .await
    .expect("insert user_card fixture");
    let (card_id,): (i64,) = sqlx::query_as(
        "SELECT card_id FROM user_card WHERE user_id = 91881 AND card_type = 'STANDARD'",
    )
    .fetch_one(&mut *setup)
    .await
    .expect("get fixture card_id");
    sqlx::query("SET FOREIGN_KEY_CHECKS = 1")
        .execute(&mut *setup)
        .await
        .ok();
    setup.commit().await.expect("commit fixture");

    // 主路径：ACTIVE 空卡（无规则/委托/绑定）首次删除 —— 走完整生产级联：
    // 父 CARD REVOKE 事件（head correlation）+ ELIGIBILITY 事件 + 软禁用。
    let result = repo
        .delete_with_cascade(card_id)
        .await
        .expect("cascade delete must succeed on a decommissioned-schema database");
    assert!(result.exists);
    assert_eq!(result.permission_rule_deleted, 0);
    assert_eq!(result.snapshot_deleted, 0);
    assert_eq!(result.rule_set_ref_deleted, 0);

    let (status,): (String,) =
        sqlx::query_as("SELECT card_status FROM user_card WHERE card_id = ?")
            .bind(card_id)
            .fetch_one(&pool)
            .await
            .expect("get card status after cascade");
    assert_eq!(status, "DISABLED");

    let (card_head_gen,): (i64,) = sqlx::query_as(
        "SELECT source_generation FROM authorization_projection_head          WHERE aggregate_type = 'CARD' AND aggregate_id = ?",
    )
    .bind(card_id)
    .fetch_one(&pool)
    .await
    .expect("CARD head correlation must exist after cascade");
    // 空卡删除的 CARD 流：仅 Phase 3 父 REVOKE（gen 1）。旧 Phase 6 二次
    // CARD REVOKE 已退役——CARD outbox 事件已无任何重建/刷新消费者。
    assert_eq!(card_head_gen, 1);

    let (eligibility_head_gen,): (i64,) = sqlx::query_as(
        "SELECT source_generation FROM authorization_projection_head          WHERE aggregate_type = 'ELIGIBILITY' AND aggregate_id = ?",
    )
    .bind(card_id)
    .fetch_one(&pool)
    .await
    .expect("ELIGIBILITY head correlation must exist after cascade");
    assert_eq!(eligibility_head_gen, 1);

    // 幂等短路：重复删除直接返回既有结果，不追加任何新事件（head 代次不推进）。
    let again = repo
        .delete_with_cascade(card_id)
        .await
        .expect("repeat cascade delete must short-circuit");
    assert!(again.exists);
    assert_eq!(again.permission_rule_deleted, 0);
    assert_eq!(again.rule_set_ref_deleted, 0);
    let (card_head_gen_after_replay,): (i64,) = sqlx::query_as(
        "SELECT source_generation FROM authorization_projection_head          WHERE aggregate_type = 'CARD' AND aggregate_id = ?",
    )
    .bind(card_id)
    .fetch_one(&pool)
    .await
    .expect("CARD head after replay");
    assert_eq!(
        card_head_gen_after_replay, card_head_gen,
        "repeat delete must not append any new projection event"
    );

    // 清理（被测函数内部 commit，无法回滚；单连接自清理本命名空间）。
    let mut cleanup = pool.acquire().await.expect("acquire cleanup connection");
    sqlx::query("SET FOREIGN_KEY_CHECKS = 0")
        .execute(&mut *cleanup)
        .await
        .ok();
    sqlx::query(
        "DELETE FROM authorization_projection_outbox          WHERE aggregate_type IN ('CARD', 'ELIGIBILITY') AND aggregate_id = ?",
    )
    .bind(card_id)
    .execute(&mut *cleanup)
    .await
    .ok();
    sqlx::query(
        "DELETE FROM authorization_projection_head          WHERE aggregate_type IN ('CARD', 'ELIGIBILITY') AND aggregate_id = ?",
    )
    .bind(card_id)
    .execute(&mut *cleanup)
    .await
    .ok();
    sqlx::query("DELETE FROM audit_log WHERE card_id = ? AND action = 'cascade_delete'")
        .bind(card_id)
        .execute(&mut *cleanup)
        .await
        .ok();
    sqlx::query("DELETE FROM user_card WHERE card_id = ?")
        .bind(card_id)
        .execute(&mut *cleanup)
        .await
        .ok();
    sqlx::query("SET FOREIGN_KEY_CHECKS = 1")
        .execute(&mut *cleanup)
        .await
        .ok();
}
