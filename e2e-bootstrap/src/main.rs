//! e2e 一次性引导 v2：为 e2e 卡产生 gen-1 已发布证据——通过**真实账本路径**。
//!
//! v1（已废弃）以裸 publish 原语（stage → claim → finalize → publish）直接
//! 发布 gen-1，但不产生 impact plan/delta event/grant revision——与 frontier
//! 契约（plans 1..=G 连续、每代映射 delta、每 delta 映射 ledger revision）
//! 不兼容：该聚合上任何后续 delta 都会 `frontier_missing_generation` 确定性
//! 无法发布（三节点 CS 战役实测）。
//!
//! v2 只做 **source 侧写入**：permission_rule source 行 + CARD 投影事件
//! （head 推进 → generation/fence 身份）+ grant revision + delta event
//! （PENDING），然后由运行中的 projector 以标准发布事务推进——impact plan、
//! delta SUCCEEDED、manifest、pointer 全链一致，frontier 契约由构造满足。
//!
//! 幂等：source 规则行已存在的卡跳过。投影为异步（projector 5s 轮询），
//! 调用方（部署脚本就绪探针）自带收敛等待。

use astral_db::grant_ledger::{build_direct_add_draft, DirectRuleLedgerFacts};
use astral_db::{
    append_delta_event, append_grant_revision_in_tx, append_projection_event_with_metadata_in_tx,
    connect_and_validate_schema, next_delta_version, ProjectionEventMetadata,
};
use astral_types::ProjectionAggregate;
use sqlx::mysql::MySqlConnectOptions;
use std::env;
use std::net::IpAddr;
use std::str::FromStr;
use uuid::Uuid;

const ALLOWED_DATABASES: [&str; 2] = ["astral_test", "astral_rehearsal"];
const BOOTSTRAP_ACTIONS: [&str; 1] = ["read"];
const FIXTURE_CARDS: [(i64, i64, i64, i64); 2] =
    [(9001, 9011, 9061, 9031), (9002, 9012, 9062, 9032)];

fn validate_isolated_database_url(raw_url: &str) -> Result<(), &'static str> {
    let options = MySqlConnectOptions::from_str(raw_url).map_err(|_| "invalid_database_url")?;
    let host = options.get_host();
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| {
            ip == IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                || ip == IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        });
    if !loopback {
        return Err("database_host_not_loopback");
    }
    let database = options.get_database().unwrap_or_default();
    if !ALLOWED_DATABASES.contains(&database) {
        return Err("database_name_not_allowlisted");
    }
    if options.get_socket().is_some() {
        return Err("database_socket_not_allowed");
    }
    Ok(())
}

fn validate_isolation_environment() -> Result<(String, String), &'static str> {
    if env::var("ASTRAL_MIGRATION_ENV").as_deref() != Ok("isolated") {
        return Err("migration_environment_must_be_isolated");
    }
    let run_id = env::var("RUN_ID").map_err(|_| "run_id_missing")?;
    if run_id.len() < 8
        || run_id.len() > 96
        || !run_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err("run_id_invalid");
    }
    let url = env::var("DATABASE_URL").map_err(|_| "database_url_missing")?;
    validate_isolated_database_url(&url)?;
    Ok((url, run_id))
}

#[cfg(test)]
mod isolation_tests {
    use super::*;

    #[test]
    fn only_loopback_and_allowlisted_database_names_are_accepted() {
        for url in [
            "mysql://user:secret@localhost:3308/astral_test",
            "mysql://user:secret@[::1]:3308/astral_rehearsal",
            "mysql://user:secret@127.0.0.1:3308/astral_test",
        ] {
            assert_eq!(validate_isolated_database_url(url), Ok(()));
        }
        for url in [
            "mysql://user:secret@example.com:3308/astral_test",
            "mysql://user:secret@[2001:db8::1]:3308/astral_test",
            "mysql://user:secret@127.0.0.2:3308/astral_test",
            "mysql://user:secret@localhost:3308/astral_test?socket=%2Ftmp%2Fmysql.sock",
            "mysql://user:secret@localhost:3308/astral_f4rust_dist_test_1",
            "mysql://user:secret@localhost:3308/astral_f4rust_dist_test_run-20261003",
            "mysql://user:secret@localhost:3308/astral_f4rust_dist_test_other",
            "mysql://user:secret@localhost:3308/production",
            "mysql://user:secret@localhost:3308/astral_prod",
        ] {
            assert!(validate_isolated_database_url(url).is_err());
        }
    }
}

fn bootstrap_operation_id(run_id: &str, card_id: i64, action: &str) -> String {
    let digest = Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("astral-e2e-bootstrap:{run_id}:{card_id}:{action}").as_bytes(),
    );
    format!("e2e-f3-bootstrap-{}", digest.simple())
}

fn bootstrap_action(card_id: i64) -> &'static str {
    BOOTSTRAP_ACTIONS[(card_id as usize) % BOOTSTRAP_ACTIONS.len()]
}

fn complete_bootstrap_set(existing_actions: &[String]) -> bool {
    let existing: std::collections::HashSet<&str> =
        existing_actions.iter().map(String::as_str).collect();
    existing.len() == existing_actions.len()
        && existing.len() == BOOTSTRAP_ACTIONS.len()
        && BOOTSTRAP_ACTIONS
            .iter()
            .all(|action| existing.contains(action))
}

fn bootstrap_set_matches(
    expected_tenant: i64,
    expected_domain: i64,
    expected_user: i64,
    actual: Option<(Option<i64>, Option<i64>, Option<i64>)>,
    existing_actions: &[String],
) -> bool {
    matches!(actual, Some((Some(tenant), Some(domain), Some(user)))
        if tenant == expected_tenant && domain == expected_domain && user == expected_user)
        && complete_bootstrap_set(existing_actions)
}

#[cfg(test)]
mod fixture_tests {
    use super::*;

    #[test]
    fn only_exact_bootstrap_action_set_and_owner_match_can_skip() {
        assert!(complete_bootstrap_set(&["read".to_owned()]));
        assert!(!complete_bootstrap_set(&[
            "read".to_owned(),
            "create".to_owned()
        ]));
        assert!(!complete_bootstrap_set(&[
            "read".to_owned(),
            "read".to_owned()
        ]));
        assert!(!complete_bootstrap_set(&[]));
        assert!(bootstrap_set_matches(
            9001,
            9011,
            9031,
            Some((Some(9001), Some(9011), Some(9031))),
            &["read".to_owned()],
        ));
        assert!(!bootstrap_set_matches(
            9001,
            9011,
            9031,
            Some((Some(9001), Some(9011), Some(9999))),
            &["read".to_owned()],
        ));
        let short_run = "run-20261003";
        let long_run = "z".repeat(96);
        assert!(bootstrap_operation_id(&long_run, 9061, "read").len() <= 64);
        assert_ne!(
            bootstrap_operation_id(short_run, 9061, "read"),
            bootstrap_operation_id(short_run, 9062, "read")
        );
    }

    #[test]
    fn bootstrap_operation_identity_is_stable_bounded_and_action_scoped() {
        let first = bootstrap_operation_id("run-20261003", 9061, "read");
        assert_eq!(first, bootstrap_operation_id("run-20261003", 9061, "read"));
        assert_ne!(
            first,
            bootstrap_operation_id("run-20261003", 9061, "create")
        );
        assert!(first.len() <= 64);
        assert!(first.starts_with("e2e-f3-bootstrap-"));
    }
}

async fn bootstrap_card(
    pool: &sqlx::MySqlPool,
    run_id: &str,
    tenant_id: i64,
    domain_id: i64,
    card_id: i64,
    user_id: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    // 对固定 fixture card/user/source identity 做作用域校验，错配时拒绝写入。
    let actual: Option<(Option<i64>, Option<i64>, Option<i64>)> =
        sqlx::query_as("SELECT tenant_id, domain_id, user_id FROM user_card WHERE card_id = ?")
            .bind(card_id)
            .fetch_optional(pool)
            .await?;
    if !matches!(actual, Some((Some(t), Some(d), Some(u))) if t == tenant_id && d == domain_id && u == user_id)
    {
        return Err("fixture_card_owner_or_scope_mismatch".into());
    }
    let existing_actions: Vec<String> = sqlx::query_scalar(
        "SELECT action_code FROM permission_rule WHERE card_id = ? \\
         AND resource_type = 'permission_rule' ORDER BY rule_id",
    )
    .bind(card_id)
    .fetch_all(pool)
    .await?;
    if bootstrap_set_matches(tenant_id, domain_id, user_id, actual, &existing_actions) {
        let matching_revisions: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM authorization_grant_revision \
             WHERE tenant_id = ? AND aggregate_type = 'USER_CARD' AND aggregate_id = ? \
             AND JSON_UNQUOTE(JSON_EXTRACT(grant_payload, '$.action')) = ? \
             AND JSON_UNQUOTE(JSON_EXTRACT(grant_payload, '$.provenance.sourceEntry')) = \
                 CAST((SELECT rule_id FROM permission_rule WHERE card_id = ? \
                       AND resource_type = 'permission_rule' AND action_code = ? \
                       AND effect = 'ALLOW' AND enabled = 1 AND resource_id IS NULL \
                       AND condition_json IS NULL LIMIT 1) AS CHAR)",
        )
        .bind(tenant_id)
        .bind(card_id)
        .bind(BOOTSTRAP_ACTIONS[0])
        .bind(card_id)
        .bind(BOOTSTRAP_ACTIONS[0])
        .fetch_one(pool)
        .await?;
        let total_revisions: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM authorization_grant_revision \
             WHERE tenant_id = ? AND aggregate_type = 'USER_CARD' AND aggregate_id = ?",
        )
        .bind(tenant_id)
        .bind(card_id)
        .fetch_one(pool)
        .await?;
        if matching_revisions.0 != 1 || total_revisions.0 != 1 {
            return Err("fixture_card_bootstrap_ledger_set_incomplete_or_ambiguous".into());
        }
        println!("card {card_id}: exact bootstrap grant and ledger entry already present, skip");
        return Ok(());
    }
    if !existing_actions.is_empty() {
        return Err("fixture_card_has_partial_bootstrap_action_set".into());
    }
    let existing_outbox: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM authorization_projection_outbox WHERE aggregate_type = 'CARD' AND aggregate_id = ?",
    )
    .bind(card_id)
    .fetch_one(pool)
    .await?;
    if existing_outbox.0 > 0 {
        return Err("fixture_card_has_preexisting_projection_events".into());
    }

    // Existing card-scoped grants on the canonical ledger also mean this is not
    // a fresh bootstrap target; do not issue a duplicate ledger identity.
    let existing_revision: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM authorization_grant_revision \
         WHERE tenant_id = ? AND aggregate_type = 'USER_CARD' AND aggregate_id = ?",
    )
    .bind(tenant_id)
    .bind(card_id)
    .fetch_one(pool)
    .await?;
    if existing_revision.0 > 0 {
        return Err("fixture_card_has_preexisting_grant_revision".into());
    }

    let mut tx = pool.begin().await?;

    // 1) Source fact row for the one explicitly requested bootstrap action.
    // rule_id 用 INSERT 的 last_insert_id（与 create_rule 同一模式）。
    let action = bootstrap_action(card_id);
    let rule_id = i64::try_from(
        sqlx::query(
            "INSERT INTO permission_rule (card_id, tenant_id, resource_type, action_code, effect, \
             priority, enabled) VALUES (?, ?, 'permission_rule', ?, 'ALLOW', 100, 1)",
        )
        .bind(card_id)
        .bind(tenant_id)
        .bind(action)
        .execute(&mut *tx)
        .await?
        .last_insert_id(),
    )
    .map_err(|_| "permission_rule insert returned an unusable rule id")?;

    // 2) CARD 投影事件：head 推进（source_generation/revoke_fence 身份来源）。
    let operation_id = bootstrap_operation_id(run_id, card_id, action);
    let projection = append_projection_event_with_metadata_in_tx(
        &mut tx,
        ProjectionAggregate::Card,
        card_id,
        "RULE_CREATED",
        Some(ProjectionEventMetadata {
            actor_id: user_id,
            operation_id: &operation_id,
        }),
    )
    .await?;

    // 3) 账本组装（canonical grant + evidence 校验）+ revision + delta。
    let facts = DirectRuleLedgerFacts {
        tenant_id: Some(tenant_id),
        domain_id: Some(domain_id),
        card_id,
        user_id,
        rule_id,
        resource: "permission_rule",
        resource_id: None,
        action,
        condition_json: None,
        valid_from: None,
        valid_to: None,
    };
    let draft = build_direct_add_draft(&facts, &operation_id, user_id, &projection)?;
    let (base_version, target_version) = next_delta_version(None)?;
    append_grant_revision_in_tx(&mut tx, &draft.revision_request())
        .await
        .map_err(|e| Box::<dyn std::error::Error>::from(format!("revision append: {e}")))?;
    append_delta_event(
        &mut *tx,
        &draft.delta_event_request(base_version, target_version)?,
    )
    .await
    .map_err(|e| Box::<dyn std::error::Error>::from(format!("delta append: {e}")))?;

    tx.commit().await?;
    println!(
        "card {card_id}: source rule {rule_id} + revision + delta committed \
         (gen {} fence {}); projector owns publication",
        projection.source_generation, projection.revoke_fence
    );
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Validate every environment and URL boundary before connect, schema reads, or writes.
    let (url, run_id) = validate_isolation_environment().inspect_err(|label| {
        eprintln!("e2e bootstrap BLOCKED: {label}");
    })?;
    let pool = connect_and_validate_schema(&url).await.map_err(|_| {
        eprintln!("e2e bootstrap BLOCKED: isolated database connection/schema validation failed");
        "database_connection_or_schema_validation_failed"
    })?;
    for (tenant_id, domain_id, card_id, user_id) in FIXTURE_CARDS {
        bootstrap_card(&pool, &run_id, tenant_id, domain_id, card_id, user_id)
            .await
            .map_err(|_| {
                eprintln!("e2e bootstrap FAIL: bootstrap transaction failed");
                "bootstrap_transaction_failed"
            })?;
    }
    println!("e2e bootstrap done");
    Ok(())
}
