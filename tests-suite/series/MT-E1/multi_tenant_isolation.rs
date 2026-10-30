//! 多租户隔离集成测试（新链语义）
//!
//! 需要可访问的 MySQL 8.0 测试数据库，且数据库已加载 v5 baseline 并应用
//! Rust migrations（含 20260825000002 / 20260827000001 建立的 Rust-owned
//! 授权投影链表）。运行方式：
//! `cargo test -p testsuite --test multi_tenant_isolation -- --ignored`。
//! 未设置 `DATABASE_URL` 或连接/schema 校验失败时默认跳过；设置
//! `RUST_INTEGRATION_REQUIRED=1` 仅将这些前置条件失败转换为 panic，不会解除
//! `#[ignore]`，因此仍须显式传入 `--ignored`。
//!
//! # 新链语义（旧链零写入）
//!
//! - 不读取旧 snapshot/cache 作为授权证据；生产 source writes 仍会写入保留的
//!   `authorization_projection_head` / outbox，清理按租户 source owner 隔离这些 correlation rows。
//! - 数据层 seed 走 v5 表；RuleSet 为 MANUAL + disabled ALLOW placeholder，
//!   BASE binding 与有效 source entries 仅由生产 helper 创建。
//! - 已发布 evidence 通过 testsuite 共享 helper 构造：真实 RuleSet source mutation
//!   → WorkerOwned projector → immutable delta receipt/exact completion proof →
//!   strict published-state bundle。测试不手工构造 manifest、lease 或 ledger。
//! - 隔离判定使用 V6 卡级 evidence reader；Ready 空集只由真实 ADD 后 REMOVE 得到。
//!   新链 grant 合同是 ALLOW-only（`GrantEffect` 只有 `Allow`），"DENY 规则"
//!   的语义是"该卡已发布 evidence 中零有效 ALLOW grant"（Ready + 空有效集）。
//!
//! # 覆盖（对照 Java 基线场景）
//!
//! 1. 多租户隔离: 租户 A 的卡发布 ALLOW 授权、租户 B 的卡（DENY 规则）发布
//!    零有效授权，卡级 evidence 互不可见（Java: PE 前置拒绝 + 多租户隔离专项）。
//! 2. 跨租户绑定拒绝: 生产资格门禁按租户上下文拒绝 + card-rule-set 绑定的
//!    租户一致性 SQL 不变式 + 跨租户 scope 的 evidence 读取 fail-closed 为
//!    NotReady/PENDING（Java: SecurityBoundary 跨租户 overlay 拒绝 +
//!    CardManagementScope 跨租户拒绝）。
//! 3. 同租户不同卡的 evidence 隔离（卡级 lens，Java 未覆盖的加深场景）。
//! 4. 已发布 segment payload 的租户字段被修改时，原 digest 不再匹配；
//!    严格读取器必须整读返回显式 `Corrupt`（映射 DENY），
//!    绝不产生空/等价授权集合。
//! 5. 租户级审计日志读写 + tenant_id 过滤不变式（Java: AuditLogConsumer
//!    幂等 + audit tenant 过滤）。
//! 6. TenantScopedQuery 参数化 SQL 与真实 DB 配合。
//!
//! （跨租户 SQL 隔离的 SQL 级不变式已在 astral-common 单测覆盖，此处不重复。）
//!
//! # 隔离与幂等
//!
//! 每个测试用独立的随机数值命名空间（uuid 派生大整数）和测试专属字符串前缀。
//! 清理使用当前 fixture 的确切 tenant/source/audit IDs，不按场景前缀删除，避免
//! 并行测试相互影响；同一 fixture 可在 seed 前和测试结束后安全清理。

use astral_db::{
    check_card_active_cached_with_options, connect_and_validate_schema,
    load_published_card_grant_evidence, load_published_card_state_bundle,
    AuthorizationEvidenceError, CardActiveContext, SqlxRuleRepository,
};
use astral_trustgraph::service::rule_set_write_service::AddEntryRequest;
use astral_types::{
    DomainScopeRequirement, GrantEffect, PolicyError, PublishedCardEvidenceScope,
    PublishedEvidenceGateStatus,
};
use policy_engine::RuleRepository;
use sqlx::MySqlPool;
use std::collections::BTreeSet;
use testsuite::{publish_card_manifest, PROJECTION_TABLES};
#[path = "support/source_identity.rs"]
mod source_identity;
use uuid::Uuid;

const FIXTURE_BASE_MIN: i64 = 1_000_000_000_000;
const FIXTURE_BASE_STRIDE: i64 = 10_000;
const FIXTURE_RANDOM_RANGE: u128 = 800_000_000_000;
const FIXTURE_AUDIT_SOURCE: &str = "fixture-audit";
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

#[derive(Clone, Copy)]
struct TenantFixture {
    label: &'static str,
    tenant_status: &'static str,
    audit_decision: &'static str,
    baseline_permission_effect: &'static str,
    baseline_permission_action: &'static str,
    tenant_id: i64,
    domain_id: i64,
    user_id: i64,
    identity_card_id: i64,
    template_id: i64,
    card_id: i64,
    rule_set_id: i64,
    entry_id: i64,
    permission_rule_id: i64,
    tenant_domain_map_id: i64,
    audit_seed_id: i64,
    audit_test_base: i64,
}

impl TenantFixture {
    /// 命名空间由 uuid salt 派生的 base 决定；label 保持租户 c 为 SUSPENDED。
    fn new(base: i64, ordinal: i64, label: &'static str) -> Self {
        Self {
            label,
            tenant_status: if label == "c" { "SUSPENDED" } else { "ACTIVE" },
            audit_decision: if label == "a" { "ALLOW" } else { "DENY" },
            baseline_permission_effect: if label == "a" { "ALLOW" } else { "DENY" },
            baseline_permission_action: if label == "b" { "delete" } else { "read" },
            tenant_id: base + ordinal,
            domain_id: base + 10 + ordinal,
            user_id: base + 20 + ordinal,
            identity_card_id: base + 30 + ordinal,
            template_id: base + 40 + ordinal,
            card_id: base + 50 + ordinal,
            rule_set_id: base + 60 + ordinal,
            entry_id: base + 70 + ordinal,
            permission_rule_id: base + 100 + ordinal,
            tenant_domain_map_id: base + 120 + ordinal,
            audit_seed_id: base + 140 + ordinal,
            audit_test_base: base + 200 + ordinal * 10,
        }
    }

    fn audit_test_id(self, offset: i64) -> i64 {
        self.audit_test_base + offset
    }
}

#[derive(Clone, Copy)]
struct MultiTenantFixture {
    code_prefix: &'static str,
    /// uuid salt：隔离本次 fixture 的共享 source operation identities 与随机 ID 区间。
    salt: u128,
    tenants: [TenantFixture; 3],
    /// 租户 A 的第二张卡（同租户同用户不同卡）：卡级 lens 隔离场景。
    second_card_id: i64,
    second_rule_set_id: i64,
    second_entry_id: i64,
    /// 从未 seed 的卡 id：验证"未发布 evidence"的 fail-closed 语义。
    unpublished_card_id: i64,
}

impl MultiTenantFixture {
    fn new(code_prefix: &'static str) -> Self {
        let salt = Uuid::new_v4().as_u128();
        let base = FIXTURE_BASE_MIN + ((salt % FIXTURE_RANDOM_RANGE) as i64) * FIXTURE_BASE_STRIDE;
        Self {
            code_prefix,
            salt,
            tenants: [
                TenantFixture::new(base, 1, "a"),
                TenantFixture::new(base, 2, "b"),
                TenantFixture::new(base, 3, "c"),
            ],
            second_card_id: base + 310,
            second_rule_set_id: base + 320,
            second_entry_id: base + 330,
            unpublished_card_id: base + 998,
        }
    }

    fn test_audit_ids(&self) -> Vec<i64> {
        let mut ids = Vec::with_capacity(15);
        for tenant in self.tenants {
            for offset in 0..5 {
                ids.push(tenant.audit_test_id(offset));
            }
        }
        ids
    }

    fn audit_resource(&self, scope: &str) -> String {
        format!(
            "fixture:{scope}:{}:{}",
            self.code_prefix, self.tenants[0].tenant_id
        )
    }

    fn card_scope(&self, tenant: TenantFixture, card_id: i64) -> PublishedCardEvidenceScope {
        PublishedCardEvidenceScope {
            tenant_id: tenant.tenant_id,
            card_id,
            user_filter: None,
            domain: DomainScopeRequirement::ExactlySome(tenant.domain_id),
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

    // 显式要求 Rust-owned 投影链表存在（migrations 20260825000002 +
    // 20260827000001 已应用）；本测试不执行任何临时 DDL。
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

// ─────────────────────────────────────────────────────────────────────────────
// 清理（随机 namespace 精确 ID → 幂等可重跑）
// ─────────────────────────────────────────────────────────────────────────────

/// 精确清理当前随机命名空间。V6 投影行按实际 tenant ID，保留的 source head
/// 按其真实 aggregate owner，其他 source/audit 行按 fixture 数值主键删除。
async fn cleanup_multi_tenant_data(
    pool: &MySqlPool,
    fixture: &MultiTenantFixture,
) -> Result<(), sqlx::Error> {
    let tenant_ids: Vec<i64> = fixture
        .tenants
        .iter()
        .map(|tenant| tenant.tenant_id)
        .collect();
    let card_owners: Vec<(i64, i64)> = fixture
        .tenants
        .iter()
        .map(|tenant| (tenant.card_id, tenant.tenant_id))
        .chain(std::iter::once((
            fixture.second_card_id,
            fixture.tenants[0].tenant_id,
        )))
        .collect();
    let rule_set_owners: Vec<(i64, i64)> = fixture
        .tenants
        .iter()
        .map(|tenant| (tenant.rule_set_id, tenant.tenant_id))
        .chain(std::iter::once((
            fixture.second_rule_set_id,
            fixture.tenants[0].tenant_id,
        )))
        .collect();

    // Durable projection rows carry tenant_id; use each run's exact numeric IDs.
    for tenant_id in &tenant_ids {
        for table in DURABLE_TABLES {
            sqlx::query(&format!("DELETE FROM {table} WHERE tenant_id = ?"))
                .bind(tenant_id)
                .execute(pool)
                .await?;
        }
    }

    // authorization_projection_head has no tenant column. Resolve each head
    // through its actual source aggregate before deleting any source rows.
    for (card_id, tenant_id) in &card_owners {
        for aggregate_type in ["CARD", "ELIGIBILITY"] {
            sqlx::query(
                "DELETE h FROM authorization_projection_head h \
                 INNER JOIN user_card uc ON uc.card_id = h.aggregate_id \
                 WHERE h.aggregate_type = ? AND h.aggregate_id = ? \
                   AND uc.card_id = ? AND uc.tenant_id = ?",
            )
            .bind(aggregate_type)
            .bind(card_id)
            .bind(card_id)
            .bind(tenant_id)
            .execute(pool)
            .await?;
        }
    }
    for (rule_set_id, tenant_id) in &rule_set_owners {
        sqlx::query(
            "DELETE h FROM authorization_projection_head h \
             INNER JOIN rule_set rs ON rs.rule_set_id = h.aggregate_id \
             WHERE h.aggregate_type = 'RULE_SET' AND h.aggregate_id = ? \
               AND rs.rule_set_id = ? AND rs.tenant_id = ?",
        )
        .bind(rule_set_id)
        .bind(rule_set_id)
        .bind(tenant_id)
        .execute(pool)
        .await?;
    }

    let mut audit_ids = fixture.test_audit_ids();
    audit_ids.extend(fixture.tenants.iter().map(|tenant| tenant.audit_seed_id));
    delete_ids(pool, "audit_log", "id", &audit_ids).await?;
    let mut permission_rule_ids: Vec<i64> = fixture
        .tenants
        .iter()
        .map(|tenant| tenant.permission_rule_id)
        .collect();
    permission_rule_ids.sort_unstable();
    permission_rule_ids.dedup();
    delete_ids(pool, "permission_rule", "rule_id", &permission_rule_ids).await?;

    let rule_set_ids: Vec<i64> = rule_set_owners.iter().map(|(id, _)| *id).collect();
    delete_ids(pool, "rule_set_entry", "rule_set_id", &rule_set_ids).await?;
    delete_ids(pool, "card_rule_set_ref", "rule_set_id", &rule_set_ids).await?;
    delete_ids(pool, "rule_set", "rule_set_id", &rule_set_ids).await?;

    let card_ids: Vec<i64> = card_owners.iter().map(|(id, _)| *id).collect();
    delete_ids(pool, "user_card", "card_id", &card_ids).await?;
    delete_ids(
        pool,
        "identity_card",
        "card_id",
        &fixture
            .tenants
            .iter()
            .map(|tenant| tenant.identity_card_id)
            .collect::<Vec<_>>(),
    )
    .await?;
    delete_ids(
        pool,
        "user_card_template",
        "template_id",
        &fixture
            .tenants
            .iter()
            .map(|tenant| tenant.template_id)
            .collect::<Vec<_>>(),
    )
    .await?;
    delete_ids(
        pool,
        "tenant_domain_map",
        "id",
        &fixture
            .tenants
            .iter()
            .map(|tenant| tenant.tenant_domain_map_id)
            .collect::<Vec<_>>(),
    )
    .await?;
    delete_ids(pool, "tenant", "tenant_id", &tenant_ids).await?;
    delete_ids(
        pool,
        "platform_domain",
        "domain_id",
        &fixture
            .tenants
            .iter()
            .map(|tenant| tenant.domain_id)
            .collect::<Vec<_>>(),
    )
    .await?;
    delete_ids(
        pool,
        "platform_user",
        "user_id",
        &fixture
            .tenants
            .iter()
            .map(|tenant| tenant.user_id)
            .collect::<Vec<_>>(),
    )
    .await?;

    Ok(())
}

async fn delete_ids(
    pool: &MySqlPool,
    table: &str,
    column: &str,
    ids: &[i64],
) -> Result<(), sqlx::Error> {
    if ids.is_empty() {
        return Ok(());
    }
    let placeholders = vec!["?"; ids.len()].join(", ");
    let statement = format!("DELETE FROM {table} WHERE {column} IN ({placeholders})");
    let mut query = sqlx::query(&statement);
    for id in ids {
        query = query.bind(id);
    }
    query.execute(pool).await?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// seed（v5 表 + 新链已发布 evidence）
// ─────────────────────────────────────────────────────────────────────────────

fn allow_entry(resource: &str, priority: i32) -> AddEntryRequest {
    AddEntryRequest {
        effect: "ALLOW".to_owned(),
        resource_type: Some(resource.to_owned()),
        resource_id: None,
        action_code: Some("read".to_owned()),
        condition_json: None,
        priority,
    }
}

async fn publish_fixture_entries(
    pool: &MySqlPool,
    fixture: &MultiTenantFixture,
    tenant: TenantFixture,
    card_id: i64,
    rule_set_id: i64,
    tag: &str,
    entries: Vec<AddEntryRequest>,
) -> testsuite::PublishedCardFixture {
    publish_card_manifest(
        pool,
        tenant.tenant_id,
        card_id,
        rule_set_id,
        tenant.user_id,
        entries,
        (tag, fixture.salt),
    )
    .await
}

/// seed 单个租户的身份、MANUAL source baseline 与审计行；RuleSet 授权 entry 仅作 disabled placeholder。
async fn seed_tenant_v5_rows(
    pool: &MySqlPool,
    fixture: &MultiTenantFixture,
    tenant: TenantFixture,
) -> Result<(), sqlx::Error> {
    let domain_code = format!(
        "mt_{}_domain_{}_{}",
        fixture.code_prefix, tenant.label, tenant.domain_id
    );
    sqlx::query(
        "INSERT INTO platform_domain (domain_id, domain_code, domain_name, status) \
         VALUES (?, ?, ?, 'ACTIVE')",
    )
    .bind(tenant.domain_id)
    .bind(&domain_code)
    .bind(format!("MT {} domain", tenant.label))
    .execute(pool)
    .await?;

    let tenant_code = format!(
        "mt_{}_tenant_{}_{}",
        fixture.code_prefix, tenant.label, tenant.tenant_id
    );
    sqlx::query(
        "INSERT INTO tenant \
         (tenant_id, tenant_code, tenant_name, tenant_type, status, path, depth) \
         VALUES (?, ?, ?, 'ORGANIZATION', ?, ?, 0)",
    )
    .bind(tenant.tenant_id)
    .bind(&tenant_code)
    .bind(format!("MT tenant {}", tenant.label))
    .bind(tenant.tenant_status)
    .bind(format!("/{}", tenant.tenant_id))
    .execute(pool)
    .await?;

    sqlx::query(
        "INSERT INTO tenant_domain_map (id, tenant_id, domain_id, status) \
         VALUES (?, ?, ?, 'ACTIVE')",
    )
    .bind(tenant.tenant_domain_map_id)
    .bind(tenant.tenant_id)
    .bind(tenant.domain_id)
    .execute(pool)
    .await?;

    sqlx::query(
        "INSERT INTO platform_user \
         (user_id, user_no, display_name, source_type, status) \
         VALUES (?, ?, ?, 'LOCAL', 'ACTIVE')",
    )
    .bind(tenant.user_id)
    .bind(format!(
        "mt_{}_user_{}_{}",
        fixture.code_prefix, tenant.label, tenant.user_id
    ))
    .bind(format!("MT user {}", tenant.label))
    .execute(pool)
    .await?;

    sqlx::query(
        "INSERT INTO identity_card (card_id, user_id, status, token_version) \
         VALUES (?, ?, 'ACTIVE', 1)",
    )
    .bind(tenant.identity_card_id)
    .bind(tenant.user_id)
    .execute(pool)
    .await?;

    sqlx::query(
        "INSERT INTO user_card_template \
         (template_id, domain_id, tenant_id, template_code, template_name, card_type, \
          template_scope, version_no, default_priority, status) \
         VALUES (?, ?, ?, ?, ?, 'ORG_CARD', 'DOMAIN', 1, 100, 'ACTIVE')",
    )
    .bind(tenant.template_id)
    .bind(tenant.domain_id)
    .bind(tenant.tenant_id)
    .bind(format!(
        "mt_{}_template_{}_{}",
        fixture.code_prefix, tenant.label, tenant.template_id
    ))
    .bind(format!("MT template {}", tenant.label))
    .execute(pool)
    .await?;

    sqlx::query(
        "INSERT INTO user_card \
         (card_id, user_id, domain_id, card_type, card_status, template_id, tenant_id) \
         VALUES (?, ?, ?, 'ORG_CARD', 'ACTIVE', ?, ?)",
    )
    .bind(tenant.card_id)
    .bind(tenant.user_id)
    .bind(tenant.domain_id)
    .bind(tenant.template_id)
    .bind(tenant.tenant_id)
    .execute(pool)
    .await?;

    sqlx::query(
        "INSERT INTO rule_set \
         (rule_set_id, name, code, description, source_type, enabled, tenant_id) \
         VALUES (?, ?, ?, ?, 'MANUAL', 1, ?)",
    )
    .bind(tenant.rule_set_id)
    .bind(format!("MT rule set {}", tenant.label))
    .bind(format!(
        "mt_{}_rule_set_{}_{}",
        fixture.code_prefix, tenant.label, tenant.rule_set_id
    ))
    .bind(format!("Multi-tenant fixture rule set {}", tenant.label))
    .bind(tenant.tenant_id)
    .execute(pool)
    .await?;

    sqlx::query(
        "INSERT INTO rule_set_entry \
         (entry_id, rule_set_id, resource_type, action_code, effect, priority, enabled, tenant_id) \
         VALUES (?, ?, 'learn_subject', 'read', 'ALLOW', 1, 0, ?)",
    )
    .bind(tenant.entry_id)
    .bind(tenant.rule_set_id)
    .bind(tenant.tenant_id)
    .execute(pool)
    .await?;

    // Retain the MANUAL baseline source independently from published RuleSet grants.
    sqlx::query(
        "INSERT INTO permission_rule \
         (rule_id, card_id, resource_type, resource_id, action_code, effect, priority, source_type, enabled, tenant_id) \
         VALUES (?, ?, 'profile', NULL, ?, ?, 1, 'MANUAL', 1, ?)",
    )
    .bind(tenant.permission_rule_id)
    .bind(tenant.card_id)
    .bind(tenant.baseline_permission_action)
    .bind(tenant.baseline_permission_effect)
    .bind(tenant.tenant_id)
    .execute(pool)
    .await?;

    sqlx::query(
        "INSERT INTO audit_log \
         (id, user_id, card_id, action, resource, decision, reason, event_type, source_ip, \
          domain_id, tenant_id) \
         VALUES (?, ?, ?, 'read', ?, ?, 'FIXTURE_SEED', 'FIXTURE_SEED', ?, ?, ?)",
    )
    .bind(tenant.audit_seed_id)
    .bind(tenant.user_id)
    .bind(tenant.card_id)
    .bind(fixture.audit_resource("seed"))
    .bind(tenant.audit_decision)
    .bind(FIXTURE_AUDIT_SOURCE)
    .bind(tenant.domain_id)
    .bind(tenant.tenant_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// 租户 A 的第二张卡（同租户同用户不同卡）的 v5 行。
async fn seed_second_card_v5_rows(
    pool: &MySqlPool,
    fixture: &MultiTenantFixture,
) -> Result<(), sqlx::Error> {
    let tenant_a = fixture.tenants[0];

    sqlx::query(
        "INSERT INTO user_card \
         (card_id, user_id, domain_id, card_type, card_status, template_id, tenant_id) \
         VALUES (?, ?, ?, 'ORG_CARD', 'ACTIVE', ?, ?)",
    )
    .bind(fixture.second_card_id)
    .bind(tenant_a.user_id)
    .bind(tenant_a.domain_id)
    .bind(tenant_a.template_id)
    .bind(tenant_a.tenant_id)
    .execute(pool)
    .await?;

    sqlx::query(
        "INSERT INTO rule_set \
         (rule_set_id, name, code, description, source_type, enabled, tenant_id) \
         VALUES (?, ?, ?, ?, 'MANUAL', 1, ?)",
    )
    .bind(fixture.second_rule_set_id)
    .bind("MT rule set a2")
    .bind(format!(
        "mt_{}_rule_set_a2_{}",
        fixture.code_prefix, fixture.second_rule_set_id
    ))
    .bind("Multi-tenant fixture second-card rule set")
    .bind(tenant_a.tenant_id)
    .execute(pool)
    .await?;

    sqlx::query(
        "INSERT INTO rule_set_entry \
         (entry_id, rule_set_id, resource_type, action_code, effect, priority, enabled, tenant_id) \
         VALUES (?, ?, 'profile', 'read', 'ALLOW', 1, 0, ?)",
    )
    .bind(fixture.second_entry_id)
    .bind(fixture.second_rule_set_id)
    .bind(tenant_a.tenant_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// seed v5 source 与身份行，再用生产写入和 WorkerOwned helper 发布卡级 evidence：
/// 租户 A 两张卡各有一项 ALLOW，租户 B/C 在真实 ADD→REMOVE 后为 Ready 空集。
async fn seed_multi_tenant_data(
    pool: &MySqlPool,
    fixture: &MultiTenantFixture,
) -> Result<(), sqlx::Error> {
    // Each ignored test gets a run-unique namespace. Cleanup is repeated here
    // so a failed previous run cannot poison the next run.
    cleanup_multi_tenant_data(pool, fixture).await?;

    for tenant in fixture.tenants {
        seed_tenant_v5_rows(pool, fixture, tenant).await?;
    }
    seed_second_card_v5_rows(pool, fixture).await?;

    let [tenant_a, tenant_b, tenant_c] = fixture.tenants;

    // 租户 A 卡 1：真实 ADD 发布 ALLOW（learn_subject:read）。
    let published_a1 = publish_fixture_entries(
        pool,
        fixture,
        tenant_a,
        tenant_a.card_id,
        tenant_a.rule_set_id,
        "a1-card",
        vec![allow_entry("learn_subject", 2)],
    )
    .await;
    assert_eq!(published_a1.published_state.total_grant_count, 1);

    // 租户 A 卡 2：同租户不同卡的真实 ADD（profile:read）。
    let published_a2 = publish_fixture_entries(
        pool,
        fixture,
        tenant_a,
        fixture.second_card_id,
        fixture.second_rule_set_id,
        "a2-card",
        vec![allow_entry("profile", 2)],
    )
    .await;
    assert_eq!(published_a2.published_state.total_grant_count, 1);

    // 租户 B/C：DENY 仍表示 Ready 零授权，但必须由真实 ADD → REMOVE 得到，
    // 不能用首次 empty publication 制造完成态。SUSPENDED 租户 C 保留原事实。
    for (tenant, tag) in [(tenant_b, "b-card"), (tenant_c, "c-card")] {
        let add = publish_fixture_entries(
            pool,
            fixture,
            tenant,
            tenant.card_id,
            tenant.rule_set_id,
            &format!("{tag}-add"),
            vec![allow_entry("learn_subject", 2)],
        )
        .await;
        assert_eq!(add.published_state.total_grant_count, 1);
        let remove = publish_fixture_entries(
            pool,
            fixture,
            tenant,
            tenant.card_id,
            tenant.rule_set_id,
            &format!("{tag}-remove"),
            Vec::new(),
        )
        .await;
        assert_eq!(remove.published_state.total_grant_count, 0);
    }

    Ok(())
}

// ===== 测试用例 =====

/// 多租户规则集隔离（Java 基线①）：租户 A 的卡加载 ALLOW 授权，租户 B 的卡
/// （DENY 规则）零有效授权；卡级 lens 下互不可见。
#[ignore]
#[tokio::test]
async fn test_multi_tenant_rule_set_isolation() {
    let Some(pool) = connect().await else {
        return;
    };

    let fixture = MultiTenantFixture::new("rule_isolation");
    seed_multi_tenant_data(&pool, &fixture).await.unwrap();
    let tenant_a = fixture.tenants[0];
    let tenant_b = fixture.tenants[1];

    // 租户 A 的卡 → Ready evidence，恰一条 ALLOW 授权，provenance 指回 A 的
    // card_rule_set_ref / rule_set_entry。
    let evidence_a =
        load_published_card_grant_evidence(&pool, &fixture.card_scope(tenant_a, tenant_a.card_id))
            .await
            .expect("租户 A 的卡必须返回 Ready evidence");
    assert_eq!(evidence_a.tenant_id, tenant_a.tenant_id);
    assert_eq!(evidence_a.card_id, tenant_a.card_id);
    assert_eq!(evidence_a.gate.status, PublishedEvidenceGateStatus::Ready);
    assert_eq!(evidence_a.gate.aggregate_manifest_count, 1);
    assert_eq!(evidence_a.gate.effective_grant_count, 1);
    assert_eq!(evidence_a.gate.not_in_effective_count, 0);
    assert_eq!(evidence_a.effective_grants.len(), 1);
    let grant_a = &evidence_a.effective_grants[0];
    assert_eq!(grant_a.resource, "learn_subject:*");
    assert_eq!(grant_a.action, "read");
    assert_eq!(grant_a.effect, GrantEffect::Allow);
    assert_eq!(grant_a.tenant.tenant_id, tenant_a.tenant_id);
    assert_eq!(grant_a.card_id, tenant_a.card_id);
    assert_eq!(grant_a.user_id, tenant_a.user_id);
    assert_eq!(grant_a.provenance.actor_user_id, Some(tenant_a.user_id));
    assert_eq!(evidence_a.records[0].aggregate_id, tenant_a.rule_set_id);
    source_identity::assert_ruleset_source_binding(
        &pool,
        grant_a,
        tenant_a.tenant_id,
        tenant_a.card_id,
        tenant_a.rule_set_id,
    )
    .await;

    // 租户 B 的卡 → Ready evidence，零有效授权（DENY 规则的新链表达）。
    let evidence_b =
        load_published_card_grant_evidence(&pool, &fixture.card_scope(tenant_b, tenant_b.card_id))
            .await
            .expect("租户 B 的卡必须返回 Ready evidence");
    assert_eq!(evidence_b.tenant_id, tenant_b.tenant_id);
    assert_eq!(evidence_b.gate.status, PublishedEvidenceGateStatus::Ready);
    assert_eq!(evidence_b.gate.effective_grant_count, 0);
    assert_eq!(evidence_b.gate.verified_record_count, 0);
    assert!(evidence_b.effective_grants.is_empty());

    // 互不可见：A 的 evidence 中不含任何指向 B 命名空间的 provenance。
    assert!(evidence_a.effective_grants.iter().all(|grant| {
        grant.provenance.source_id != tenant_b.rule_set_id.to_string()
            && grant.tenant.tenant_id == tenant_a.tenant_id
    }));

    cleanup_multi_tenant_data(&pool, &fixture).await.unwrap();
}

/// 跨租户绑定拒绝与已存在绑定的一致性验证（Java 基线②）。
///
/// `astral-db` 没有跨租户绑定 mutation API，因此这里不伪造一个写入拒绝
/// 入口；负向 mutation 覆盖范围由上层写入服务测试负责。本测试覆盖：
/// 生产资格门禁的租户上下文拒绝、绑定租户一致性 SQL 不变式、以及跨租户
/// scope 的 evidence 读取 fail-closed（PENDING 语义，绝不返回他卡证据）。
#[ignore]
#[tokio::test]
async fn test_cross_tenant_binding_rejection() {
    let Some(pool) = connect().await else {
        return;
    };

    let fixture = MultiTenantFixture::new("cross_binding");
    seed_multi_tenant_data(&pool, &fixture).await.unwrap();
    let tenant_a = fixture.tenants[0];
    let tenant_b = fixture.tenants[1];

    // The production eligibility gate is the canonical tenant-binding check.
    // It compares the request tenant/domain to the authoritative user_card row;
    // the schema intentionally has no cross-table tenant foreign key to assert.
    let valid_context = CardActiveContext {
        user_id: tenant_a.user_id,
        identity_card_id: tenant_a.identity_card_id,
        user_card_id: tenant_a.card_id,
        user_card_tenant_id: tenant_a.tenant_id,
        user_card_domain_id: tenant_a.domain_id,
    };
    assert!(
        check_card_active_cached_with_options(&pool, &valid_context, 1, 0, false)
            .await
            .unwrap(),
        "the seeded card pair must pass the production eligibility gate"
    );

    let cross_tenant_context = CardActiveContext {
        user_card_tenant_id: tenant_b.tenant_id,
        user_card_domain_id: tenant_b.domain_id,
        ..valid_context
    };
    assert!(
        !check_card_active_cached_with_options(&pool, &cross_tenant_context, 1, 0, false)
            .await
            .unwrap(),
        "a tenant-B context must be rejected for tenant-A's card"
    );

    // card_rule_set_ref has no FK that compares tenant_id across tables. Keep
    // the invariant explicit in SQL and never turn this into a false FK test.
    let invalid_binding_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM card_rule_set_ref crs \
         INNER JOIN user_card uc ON uc.card_id = crs.card_id \
         INNER JOIN rule_set rs ON rs.rule_set_id = crs.rule_set_id \
         WHERE crs.card_id = ? \
           AND (crs.tenant_id IS NULL OR uc.tenant_id IS NULL OR rs.tenant_id IS NULL \
                OR crs.tenant_id <> uc.tenant_id OR crs.tenant_id <> rs.tenant_id)",
    )
    .bind(tenant_a.card_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        invalid_binding_count, 0,
        "seeded card-rule bindings must satisfy the SQL tenant invariant"
    );

    // 跨租户 scope 的 evidence 读取必须 fail-closed：租户 A 的 lens 读不到
    // 租户 B 的卡（指针行按 (tenant_id, card_id) 锁定），缺失 evidence 映射
    // PENDING（PENDING/DENY 词表），绝不返回空/等价授权集合。
    for scope in [
        fixture.card_scope(tenant_a, tenant_b.card_id),
        fixture.card_scope(tenant_b, tenant_a.card_id),
    ] {
        let error = load_published_card_grant_evidence(&pool, &scope)
            .await
            .unwrap_err();
        match &error {
            AuthorizationEvidenceError::NotReady(message) => {
                assert!(
                    message.contains("current_pointer_missing"),
                    "unexpected NotReady code: {message}"
                );
            }
            other => {
                panic!("cross-tenant scope read must be NotReady (PENDING/DENY), got: {other:?}")
            }
        }
        assert_eq!(
            error.as_gate_status(),
            PublishedEvidenceGateStatus::Pending,
            "missing cross-tenant evidence must map to the PENDING vocabulary"
        );
    }

    // 从未 seed 的卡：同样 NotReady（替代旧链的"空规则集"断言）。
    let error = load_published_card_grant_evidence(
        &pool,
        &fixture.card_scope(tenant_a, fixture.unpublished_card_id),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        error,
        AuthorizationEvidenceError::NotReady(ref message) if message.contains("current_pointer_missing")
    ));

    cleanup_multi_tenant_data(&pool, &fixture).await.unwrap();
}

/// 同租户不同卡的 evidence 隔离（Java 未覆盖的加深场景）。
///
/// 同一租户、同一用户的两张卡各自持有独立 RULE_SET 绑定与已发布投影；
/// 卡级 lens 必须只合成 scope 指定卡自己的聚合，绝不串卡。
#[ignore]
#[tokio::test]
async fn test_same_tenant_card_evidence_isolation() {
    let Some(pool) = connect().await else {
        return;
    };

    let fixture = MultiTenantFixture::new("card_lens");
    seed_multi_tenant_data(&pool, &fixture).await.unwrap();
    let tenant_a = fixture.tenants[0];

    let evidence_card1 =
        load_published_card_grant_evidence(&pool, &fixture.card_scope(tenant_a, tenant_a.card_id))
            .await
            .expect("card1 evidence must be Ready");
    let evidence_card2 = load_published_card_grant_evidence(
        &pool,
        &fixture.card_scope(tenant_a, fixture.second_card_id),
    )
    .await
    .expect("card2 evidence must be Ready");

    for (evidence, expected_card_id, expected_rule_set_id, expected_resource) in [
        (
            &evidence_card1,
            tenant_a.card_id,
            tenant_a.rule_set_id,
            "learn_subject:*",
        ),
        (
            &evidence_card2,
            fixture.second_card_id,
            fixture.second_rule_set_id,
            "profile:*",
        ),
    ] {
        assert_eq!(evidence.gate.status, PublishedEvidenceGateStatus::Ready);
        assert_eq!(evidence.tenant_id, tenant_a.tenant_id);
        assert_eq!(evidence.card_id, expected_card_id);
        assert_eq!(evidence.gate.effective_grant_count, 1);
        assert_eq!(evidence.effective_grants.len(), 1);
        let grant = &evidence.effective_grants[0];
        assert_eq!(grant.resource, expected_resource);
        assert_eq!(grant.provenance.source_id, expected_rule_set_id.to_string());
        let binding_id = grant
            .provenance
            .binding_id
            .as_deref()
            .expect("RuleSet grants carry a real binding id")
            .parse::<i64>()
            .expect("production binding id is numeric");
        let entry_id = grant
            .provenance
            .source_entry
            .as_deref()
            .expect("RuleSet grants carry a real entry id")
            .parse::<i64>()
            .expect("production entry id is numeric");
        let source_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM rule_set_entry e \
             INNER JOIN rule_set rs ON rs.rule_set_id = e.rule_set_id \
             INNER JOIN card_rule_set_ref b ON b.id = ? AND b.rule_set_id = e.rule_set_id \
             WHERE e.entry_id = ? AND rs.rule_set_id = ? AND rs.tenant_id = ? \
               AND e.effect = 'ALLOW' AND e.enabled = 1 \
               AND b.card_id = ? AND b.ref_type = 'BASE' AND b.tenant_id = ?",
        )
        .bind(binding_id)
        .bind(entry_id)
        .bind(expected_rule_set_id)
        .bind(tenant_a.tenant_id)
        .bind(expected_card_id)
        .bind(tenant_a.tenant_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            source_count, 1,
            "grant provenance must resolve to real source rows"
        );
        if expected_resource == "learn_subject:*" {
            source_identity::assert_ruleset_source_binding(
                &pool,
                grant,
                tenant_a.tenant_id,
                expected_card_id,
                expected_rule_set_id,
            )
            .await;
        }
        // Every card lens carries a RULE_SET aggregate, never a CARD/user_card id.
        assert_eq!(evidence.manifests.len(), 1);
        assert_eq!(evidence.manifests[0].aggregate_id, expected_rule_set_id);
    }

    // 互不串卡：card1 的有效授权里没有 profile，card2 里没有 learn_subject。
    assert!(evidence_card1
        .effective_grants
        .iter()
        .all(|grant| grant.resource != "profile:*"));
    assert!(evidence_card2
        .effective_grants
        .iter()
        .all(|grant| grant.resource != "learn_subject:*"));
    assert_ne!(
        evidence_card1.effective_grants[0].grant_id,
        evidence_card2.effective_grants[0].grant_id
    );

    cleanup_multi_tenant_data(&pool, &fixture).await.unwrap();
}

/// 已发布 segment payload 完整性失配必须整读 fail-closed。
///
/// 已发布 payload 被篡改后，严格读取器必须整读失败为显式 `Corrupt`。Fixture
/// 先完成真实生产 ADD + WorkerOwned 发布，再只改写隔离 segment 的 payload 字节；
/// 保留原 digest、local seals、reference 与 manifest，使 strict reader 拒绝不一致。
#[ignore]
#[tokio::test]
async fn test_published_segment_payload_tampering_is_corrupt_fail_closed() {
    let Some(pool) = connect().await else {
        return;
    };

    let fixture = MultiTenantFixture::new("payload_digest");
    seed_multi_tenant_data(&pool, &fixture).await.unwrap();
    let tenant_a = fixture.tenants[0];
    let bundle =
        load_published_card_state_bundle(&pool, &fixture.card_scope(tenant_a, tenant_a.card_id))
            .await
            .expect("genuine seed publication must pass the strict bundle reader");
    let state = bundle
        .states()
        .iter()
        .find(|state| {
            state.pointer.identity.aggregate_type == "RULE_SET"
                && state.pointer.identity.aggregate_id == tenant_a.rule_set_id
        })
        .expect("strict bundle must contain the owned RuleSet publication");
    assert_eq!(state.total_grant_count, 1);
    assert_eq!(state.segments.len(), 1);
    assert_eq!(state.segments[0].grants.len(), 1);
    let segment = &state.segments[0];
    assert_eq!(segment.grants[0].tenant.tenant_id, tenant_a.tenant_id);
    let original_payload = serde_json::to_vec(&segment.grants).unwrap();
    let original = tenant_a.tenant_id.to_string();
    let replacement = (tenant_a.tenant_id + 1).to_string();
    let position = original_payload
        .windows(original.len())
        .position(|window| window == original.as_bytes())
        .expect("serialized grants contain the real fixture tenant id");
    let mut payload = original_payload;
    payload.splice(position..position + original.len(), replacement.bytes());
    let mut tx = pool.begin().await.unwrap();
    let changed = sqlx::query(
        "UPDATE authorization_projection_segment \
         SET segment_payload = ? \
         WHERE tenant_id = ? AND segment_id = ? AND content_digest = ?",
    )
    .bind(&payload)
    .bind(tenant_a.tenant_id)
    .bind(segment.segment_id)
    .bind(segment.content_digest.as_bytes().to_vec())
    .execute(&mut *tx)
    .await
    .unwrap();
    assert_eq!(
        changed.rows_affected(),
        1,
        "corruption must target one published owned segment"
    );
    tx.commit().await.unwrap();

    // The unchanged digest must reject the modified payload before grant matching.
    let error =
        load_published_card_grant_evidence(&pool, &fixture.card_scope(tenant_a, tenant_a.card_id))
            .await
            .unwrap_err();
    match &error {
        AuthorizationEvidenceError::Corrupt(message) => {
            assert!(
                message.contains("segment_digest_mismatch"),
                "payload tampering must be rejected by the strict segment digest: {message}"
            );
        }
        other => {
            panic!("modified segment payload must fail the whole read as Corrupt, got: {other:?}")
        }
    }
    assert_eq!(
        error.as_gate_status(),
        PublishedEvidenceGateStatus::Corrupt,
        "payload integrity failure must map to Corrupt (deny + manual reconciliation)"
    );

    // Production repository maps the integrity failure to PolicyError::Repository.
    let repo = SqlxRuleRepository::new(pool.clone());
    let policy_error = repo
        .load_published_card_authorization(&fixture.card_scope(tenant_a, tenant_a.card_id))
        .await
        .unwrap_err();
    match policy_error {
        PolicyError::Repository(message) => {
            assert!(
                message.contains("published_card_evidence_corrupt"),
                "unexpected policy error family: {message}"
            );
        }
        other => panic!("repository port must surface the corrupt family, got: {other:?}"),
    }

    cleanup_multi_tenant_data(&pool, &fixture).await.unwrap();
}

/// 租户级审计日志读写验证（Java 基线③，audit_log 为 v5 表带 tenant_id）
#[ignore]
#[tokio::test]
async fn test_tenant_audit_log_read_write() {
    let Some(pool) = connect().await else {
        return;
    };

    let fixture = MultiTenantFixture::new("audit_write");
    seed_multi_tenant_data(&pool, &fixture).await.unwrap();
    let tenant_a = fixture.tenants[0];
    let tenant_b = fixture.tenants[1];

    sqlx::query(
        r#"INSERT INTO audit_log
           (id, user_id, card_id, action, resource, decision, reason, event_type, source_ip, domain_id, tenant_id)
           VALUES (?, ?, ?, 'read', ?, 'ALLOW', 'RULE_SET_ALLOW', 'AUTHZ_CHECK', ?, ?, ?)"#,
    )
    .bind(tenant_a.audit_test_id(0))
    .bind(tenant_a.user_id)
    .bind(tenant_a.card_id)
    .bind(fixture.audit_resource("authz"))
    .bind(FIXTURE_AUDIT_SOURCE)
    .bind(tenant_a.domain_id)
    .bind(tenant_a.tenant_id)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"INSERT INTO audit_log
           (id, user_id, card_id, action, resource, decision, reason, event_type, source_ip, domain_id, tenant_id)
           VALUES (?, ?, ?, 'read', ?, 'DENY', 'RULE_SET_DENY', 'AUTHZ_CHECK', ?, ?, ?)"#,
    )
    .bind(tenant_b.audit_test_id(0))
    .bind(tenant_b.user_id)
    .bind(tenant_b.card_id)
    .bind(fixture.audit_resource("authz"))
    .bind(FIXTURE_AUDIT_SOURCE)
    .bind(tenant_b.domain_id)
    .bind(tenant_b.tenant_id)
    .execute(&pool)
    .await
    .unwrap();

    let candidate_ids = [tenant_a.audit_test_id(0), tenant_b.audit_test_id(0)];
    let candidate_placeholders = (0..candidate_ids.len())
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(", ");
    let candidate_sql = format!(
        "SELECT id, tenant_id, decision, resource FROM audit_log \
         WHERE event_type = 'AUTHZ_CHECK' AND id IN ({candidate_placeholders}) \
           AND tenant_id = ? ORDER BY id"
    );

    let mut tenant_a_query = sqlx::query_as::<_, (i64, i64, String, String)>(&candidate_sql);
    for id in candidate_ids {
        tenant_a_query = tenant_a_query.bind(id);
    }
    let tenant_a_logs = tenant_a_query
        .bind(tenant_a.tenant_id)
        .fetch_all(&pool)
        .await
        .unwrap();

    assert_eq!(tenant_a_logs.len(), 1, "租户 A 应只看到自己的 AUTHZ 日志");
    assert_eq!(
        tenant_a_logs[0],
        (
            tenant_a.audit_test_id(0),
            tenant_a.tenant_id,
            "ALLOW".to_string(),
            fixture.audit_resource("authz")
        )
    );

    let mut tenant_b_query = sqlx::query_as::<_, (i64, i64, String, String)>(&candidate_sql);
    for id in candidate_ids {
        tenant_b_query = tenant_b_query.bind(id);
    }
    let tenant_b_logs = tenant_b_query
        .bind(tenant_b.tenant_id)
        .fetch_all(&pool)
        .await
        .unwrap();

    assert_eq!(tenant_b_logs.len(), 1, "租户 B 应只看到自己的 AUTHZ 日志");
    assert_eq!(
        tenant_b_logs[0],
        (
            tenant_b.audit_test_id(0),
            tenant_b.tenant_id,
            "DENY".to_string(),
            fixture.audit_resource("authz")
        )
    );

    assert_ne!(tenant_a_logs[0].1, tenant_b_logs[0].1);

    cleanup_multi_tenant_data(&pool, &fixture).await.unwrap();
}

/// 租户级审计日志按 tenant_id 过滤不变式（Java 基线③）
#[ignore]
#[tokio::test]
async fn test_audit_log_tenant_filter_invariant() {
    let Some(pool) = connect().await else {
        return;
    };

    let fixture = MultiTenantFixture::new("audit_filter");
    seed_multi_tenant_data(&pool, &fixture).await.unwrap();

    let audit_resource = fixture.audit_resource("tenant-filter");
    let mut tenant_filter_audit_ids = BTreeSet::new();
    for tenant in fixture.tenants {
        for offset in 0..5 {
            let audit_id = tenant.audit_test_id(offset);
            tenant_filter_audit_ids.insert(audit_id);
            sqlx::query(
                r#"INSERT INTO audit_log
                   (id, user_id, card_id, action, resource, decision, event_type, source_ip, domain_id, tenant_id)
                   VALUES (?, ?, ?, 'read', ?, 'ALLOW', 'TENANT_FILTER', ?, ?, ?)"#,
            )
            .bind(audit_id)
            .bind(tenant.user_id)
            .bind(tenant.card_id)
            .bind(&audit_resource)
            .bind(FIXTURE_AUDIT_SOURCE)
            .bind(tenant.domain_id)
            .bind(tenant.tenant_id)
            .execute(&pool)
            .await
            .unwrap();
        }
    }

    let audit_ids = tenant_filter_audit_ids.into_iter().collect::<Vec<_>>();
    let audit_placeholders = (0..audit_ids.len())
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(", ");
    let scoped_sql = format!(
        "SELECT id, tenant_id FROM audit_log \
         WHERE event_type = 'TENANT_FILTER' AND resource = ? \
           AND id IN ({audit_placeholders}) AND tenant_id = ? ORDER BY id"
    );

    for tenant in fixture.tenants {
        let mut query = sqlx::query_as::<_, (i64, i64)>(&scoped_sql);
        query = query.bind(&audit_resource);
        for id in &audit_ids {
            query = query.bind(*id);
        }
        let rows = query.bind(tenant.tenant_id).fetch_all(&pool).await.unwrap();

        assert_eq!(
            rows.len(),
            5,
            "租户 {} 应只有 5 条审计日志，实际 {}",
            tenant.tenant_id,
            rows.len()
        );
        assert!(rows
            .iter()
            .all(|(_, tenant_id)| *tenant_id == tenant.tenant_id));
        assert_eq!(
            rows.iter().map(|(id, _)| *id).collect::<BTreeSet<_>>(),
            (0..5)
                .map(|offset| tenant.audit_test_id(offset))
                .collect::<BTreeSet<_>>()
        );
    }

    let test_audit_ids = fixture.test_audit_ids();
    let audit_placeholders = (0..test_audit_ids.len())
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(", ");
    let total_sql = format!(
        "SELECT COUNT(*) FROM audit_log \
         WHERE event_type = 'TENANT_FILTER' AND resource = ? \
           AND id IN ({audit_placeholders})"
    );
    let mut total_query = sqlx::query_scalar::<_, i64>(&total_sql).bind(&audit_resource);
    for id in &test_audit_ids {
        total_query = total_query.bind(*id);
    }
    let total = total_query.fetch_one(&pool).await.unwrap();
    assert_eq!(total, 15, "总审计日志数应为 15");

    cleanup_multi_tenant_data(&pool, &fixture).await.unwrap();
}

/// TenantScopedQuery 与实际 SQL 参数化查询配合验证（Java 基线④）。
///
/// 以 seed 审计行的主键为锚点：租户过滤正确时恰好返回本租户那一行；
/// 换成他租户的过滤 id 必须返回空集（参数化租户过滤不得放大范围）。
#[ignore]
#[tokio::test]
async fn test_tenant_scoped_query_with_real_db() {
    use astral_common::middleware::tenant_filter::TenantScopedQuery;

    let Some(pool) = connect().await else {
        return;
    };

    let fixture = MultiTenantFixture::new("scoped_query");
    seed_multi_tenant_data(&pool, &fixture).await.unwrap();
    let tenant_a = fixture.tenants[0];
    let tenant_b = fixture.tenants[1];

    let scoped = TenantScopedQuery::new(format!(
        "SELECT tenant_id, decision FROM audit_log WHERE id = {}",
        tenant_a.audit_seed_id
    ))
    .with_tenant(tenant_a.tenant_id);

    let (sql, params) = scoped.try_build().expect("restricted scoped SELECT");
    assert!(sql.contains("AND audit_log.tenant_id = ?"));
    assert_eq!(params, vec![tenant_a.tenant_id.to_string()]);

    let mut query = sqlx::query_as::<_, (i64, String)>(&sql);
    for param in &params {
        query = query.bind(param);
    }
    let rows = query.fetch_all(&pool).await.unwrap();

    assert_eq!(
        rows.len(),
        1,
        "租户作用域查询应恰好返回租户 A 自己的 seed 审计行"
    );
    assert_eq!(rows[0].0, tenant_a.tenant_id, "结果行必须属于租户 A");
    assert_eq!(rows[0].1, "ALLOW");

    // 参数化租户过滤不放大：换成租户 B 的作用域读同一主键必须返回空集。
    let wrong_scope = TenantScopedQuery::new(format!(
        "SELECT tenant_id, decision FROM audit_log WHERE id = {}",
        tenant_a.audit_seed_id
    ))
    .with_tenant(tenant_b.tenant_id);
    let (wrong_sql, wrong_params) = wrong_scope.try_build().expect("restricted scoped SELECT");
    let mut wrong_query = sqlx::query_as::<_, (i64, String)>(&wrong_sql);
    for param in &wrong_params {
        wrong_query = wrong_query.bind(param);
    }
    let wrong_rows = wrong_query.fetch_all(&pool).await.unwrap();
    assert!(
        wrong_rows.is_empty(),
        "租户 B 的作用域查询不得读到租户 A 的审计行"
    );

    cleanup_multi_tenant_data(&pool, &fixture).await.unwrap();
}
