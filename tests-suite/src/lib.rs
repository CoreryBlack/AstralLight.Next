//! testsuite 共享夹具库。
//!
//! 分类集成测试共用隔离租户拓扑、真实 RuleSet source mutation、worker-owned
//! 发布及 exact receipt completion 验证。测试不构造 manifest、lease 或 impact plan。
//!
//! ID 段从 `SUITE_BASE_MIN` 起，与既有集成测试和分布式 e2e fixture 隔离。

use astral_db::connect_and_validate_schema;
use astral_types::{DomainScopeRequirement, PublishedCardEvidenceScope};
use sha2::{Digest, Sha256};
use sqlx::MySqlPool;
use uuid::Uuid;

/// testsuite 专属随机段起点(2e16),与既有 fixture 段隔离。
pub const SUITE_BASE_MIN: i64 = 20_000_000_000_000_000;
/// 相邻运行 base 的最小间隔(远大于单次运行的类内展开跨度)。
pub const SUITE_BASE_STRIDE: i64 = 10_000_000;
pub const SUITE_RANDOM_RANGE: u128 = 2_000_000_000;
/// 单类 ID 的类内间隔:租户数 ≤ 2000 时类间不重叠。
pub const CATEGORY_STRIDE: i64 = 10_000;
/// 投影链表存在性检查(migrations 20260825000002 + 20260827000001)。
pub const PROJECTION_TABLES: &[&str] = &[
    "authorization_projection_manifest",
    "authorization_projection_segment",
    "authorization_projection_manifest_segment",
    "authorization_projection_current",
];

/// 租户角色:决定播种时的租户状态与规则效果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantRole {
    /// ACTIVE 租户 + ALLOW 规则(可授权)。
    AllowActive,
    /// ACTIVE 租户 + 零有效授权(Ready 空集,DENY 语义)。
    DenyActive,
    /// SUSPENDED 租户 + 零有效授权(租户级 fail-closed)。
    DenySuspended,
}

impl TenantRole {
    pub fn tenant_status(self) -> &'static str {
        match self {
            TenantRole::AllowActive | TenantRole::DenyActive => "ACTIVE",
            TenantRole::DenySuspended => "SUSPENDED",
        }
    }

    /// 新链 grant 合同是 ALLOW-only;"DENY 规则"的语义是已发布 evidence
    /// 中零有效 ALLOW grant(Ready + 空有效集)。
    pub fn has_allow_rule(self) -> bool {
        matches!(self, TenantRole::AllowActive)
    }
}

/// 单个租户的确定性 ID 集:全部由 `base + slot * CATEGORY_STRIDE + ordinal` 派生。
#[derive(Debug, Clone, Copy)]
pub struct SuiteTenant {
    pub ordinal: i64,
    pub role: TenantRole,
    pub tenant_id: i64,
    pub domain_id: i64,
    pub user_id: i64,
    pub identity_card_id: i64,
    pub template_id: i64,
    pub card_id: i64,
    pub rule_set_id: i64,
    pub entry_id: i64,
    pub card_rule_set_ref_id: i64,
    pub permission_rule_id: i64,
    pub tenant_domain_map_id: i64,
    pub audit_seed_id: i64,
    pub audit_test_base: i64,
}

impl SuiteTenant {
    fn new(base: i64, ordinal: i64, role: TenantRole) -> Self {
        let slot = |k: i64| base + k * CATEGORY_STRIDE + ordinal;
        Self {
            ordinal,
            role,
            tenant_id: slot(0),
            domain_id: slot(1),
            user_id: slot(2),
            identity_card_id: slot(3),
            template_id: slot(4),
            card_id: slot(5),
            rule_set_id: slot(6),
            entry_id: slot(7),
            card_rule_set_ref_id: slot(8),
            permission_rule_id: slot(9),
            tenant_domain_map_id: slot(10),
            audit_seed_id: slot(11),
            audit_test_base: slot(12),
        }
    }

    pub fn audit_test_id(&self, offset: i64) -> i64 {
        self.audit_test_base + offset * 100
    }

    pub fn card_scope(&self) -> PublishedCardEvidenceScope {
        PublishedCardEvidenceScope {
            tenant_id: self.tenant_id,
            card_id: self.card_id,
            user_filter: None,
            domain: DomainScopeRequirement::ExactlySome(self.domain_id),
        }
    }
}

/// 一次套件运行的完整租户拓扑:N 租户 + 每租户第二卡(可选场景)。
#[derive(Debug, Clone)]
pub struct SuiteFixture {
    pub code_prefix: String,
    /// GrantId 熵与随机 id 区间的共同来源(每次运行唯一)。
    pub salt: u128,
    pub base: i64,
    pub tenants: Vec<SuiteTenant>,
}

impl SuiteFixture {
    /// `roles[i]` 决定第 i 个租户的角色;`code_prefix` 参与清理与命名。
    pub fn new(code_prefix: &str, roles: &[TenantRole]) -> Self {
        assert!(
            !roles.is_empty() && roles.len() <= 2000,
            "suite supports 1..=2000 tenants per run"
        );
        let salt = Uuid::new_v4().as_u128();
        let base = SUITE_BASE_MIN + ((salt % SUITE_RANDOM_RANGE) as i64) * SUITE_BASE_STRIDE;
        Self {
            code_prefix: code_prefix.to_owned(),
            salt,
            base,
            tenants: roles
                .iter()
                .enumerate()
                .map(|(i, role)| SuiteTenant::new(base, i as i64 + 1, *role))
                .collect(),
        }
    }

    /// 第二卡 ID(同租户同用户不同卡的卡级 lens 隔离场景);类内独立 slot。
    pub fn second_card_id(&self) -> i64 {
        self.base + 13 * CATEGORY_STRIDE
    }

    pub fn second_rule_set_id(&self) -> i64 {
        self.base + 13 * CATEGORY_STRIDE + 1
    }

    pub fn second_entry_id(&self) -> i64 {
        self.base + 13 * CATEGORY_STRIDE + 2
    }

    pub fn second_card_rule_set_ref_id(&self) -> i64 {
        self.base + 13 * CATEGORY_STRIDE + 3
    }

    /// 从未 seed 的卡 id:验证"未发布 evidence"的 fail-closed 语义。
    pub fn unpublished_card_id(&self) -> i64 {
        self.base + 13 * CATEGORY_STRIDE + 998
    }
}

/// 与既有集成测试一致的连接门控:未配置前置时默认 `[SKIP]`;
/// `RUST_INTEGRATION_REQUIRED=1` 将前置缺失转换为 panic(不得由 exit 0 折算 PASS)。
pub async fn connect_suite() -> Option<MySqlPool> {
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

/// Seed isolated topology and a disabled source entry; authorization is created by the writer.
pub async fn seed_tenant_rows(
    pool: &MySqlPool,
    fixture: &SuiteFixture,
    tenant: &SuiteTenant,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO platform_domain (domain_id, domain_code, domain_name, status) \
         VALUES (?, ?, ?, 'ACTIVE')",
    )
    .bind(tenant.domain_id)
    .bind(format!(
        "ts_{}_domain_{}",
        fixture.code_prefix, tenant.domain_id
    ))
    .bind(format!("TS domain {}", tenant.ordinal))
    .execute(pool)
    .await?;

    sqlx::query(
        "INSERT INTO tenant \
         (tenant_id, tenant_code, tenant_name, tenant_type, status, path, depth) \
         VALUES (?, ?, ?, 'ORGANIZATION', ?, ?, 0)",
    )
    .bind(tenant.tenant_id)
    .bind(format!(
        "ts_{}_tenant_{}",
        fixture.code_prefix, tenant.tenant_id
    ))
    .bind(format!("TS tenant {}", tenant.ordinal))
    .bind(tenant.role.tenant_status())
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
        "ts_{}_user_{}",
        fixture.code_prefix, tenant.user_id
    ))
    .bind(format!("TS user {}", tenant.ordinal))
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
        "ts_{}_template_{}",
        fixture.code_prefix, tenant.template_id
    ))
    .bind(format!("TS template {}", tenant.ordinal))
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
    .bind(format!("TS rule set {}", tenant.ordinal))
    .bind(format!(
        "ts_{}_rule_set_{}",
        fixture.code_prefix, tenant.rule_set_id
    ))
    .bind(format!("Suite fixture rule set {}", tenant.ordinal))
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

    Ok(())
}

/// Publish through the source writer and owned projector, retaining exact proof.
mod publication;
pub use publication::{publish_card_manifest, PublishedCardFixture};

pub fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// 播种全部租户。
pub async fn seed_all_tenants(pool: &MySqlPool, fixture: &SuiteFixture) -> Result<(), sqlx::Error> {
    for tenant in &fixture.tenants {
        seed_tenant_rows(pool, fixture, tenant).await?;
    }
    Ok(())
}

/// Remove this fixture's source and published state in one short transaction.
pub async fn cleanup_suite_rows(
    pool: &MySqlPool,
    fixture: &SuiteFixture,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    for tenant in &fixture.tenants {
        let code: Option<String> =
            sqlx::query_scalar("SELECT tenant_code FROM tenant WHERE tenant_id = ? FOR UPDATE")
                .bind(tenant.tenant_id)
                .fetch_optional(&mut *tx)
                .await?;
        let expected_code = format!("ts_{}_tenant_{}", fixture.code_prefix, tenant.tenant_id);
        if code.as_deref() != Some(expected_code.as_str()) {
            return Err(sqlx::Error::Protocol(
                "fixture cleanup cannot prove tenant ownership".into(),
            ));
        }
        let active: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM authorization_projection_partition_lease \
             WHERE tenant_id = ? AND (active_delta_event_id IS NOT NULL \
               OR lease_expires_at > UTC_TIMESTAMP(6))",
        )
        .bind(tenant.tenant_id)
        .fetch_one(&mut *tx)
        .await?;
        if active != 0 {
            return Err(sqlx::Error::Protocol(
                "fixture cleanup requires worker shutdown and owned-lease reconciliation".into(),
            ));
        }
        // The head has no tenant column. Prove ownership while source/outbox
        // rows still exist; an unrelated numeric aggregate id is never enough.
        for aggregate in ["CARD", "ELIGIBILITY"] {
            sqlx::query(
                "DELETE h FROM authorization_projection_head h \
                 INNER JOIN user_card uc ON uc.card_id = h.aggregate_id \
                 WHERE h.aggregate_type = ? AND uc.tenant_id = ?",
            )
            .bind(aggregate)
            .bind(tenant.tenant_id)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query(
            "DELETE h FROM authorization_projection_head h \
             INNER JOIN rule_set rs ON rs.rule_set_id = h.aggregate_id \
             WHERE h.aggregate_type = 'RULE_SET' AND rs.tenant_id = ?",
        )
        .bind(tenant.tenant_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "DELETE h FROM authorization_projection_head h \
             INNER JOIN authorization_projection_outbox o \
               ON o.aggregate_type = h.aggregate_type AND o.aggregate_id = h.aggregate_id \
                 AND o.event_id = h.last_event_id AND o.source_generation = h.source_generation \
             WHERE o.tenant_id = ?",
        )
        .bind(tenant.tenant_id)
        .execute(&mut *tx)
        .await?;
        for table in [
            "authorization_projection_partition_lease",
            "authorization_archive_manifest",
            "authorization_archive_outbox",
            "authorization_impact_plan_item",
            "authorization_impact_plan",
            "authorization_projection_manifest_segment",
            "authorization_projection_current",
            "authorization_projection_manifest",
            "authorization_projection_segment",
            "authorization_delta_event",
            "authorization_grant_revision",
            "rule_set_projection_audit",
            "authorization_projection_outbox",
            "al_message_outbox",
            "audit_log",
        ] {
            let sql = format!("DELETE FROM {table} WHERE tenant_id = ?");
            sqlx::query(&sql)
                .bind(tenant.tenant_id)
                .execute(&mut *tx)
                .await?;
        }
        for statement in [
            "DELETE pr FROM permission_rule pr INNER JOIN user_card uc ON uc.card_id = pr.card_id WHERE uc.tenant_id = ?",
            "DELETE b FROM card_rule_set_ref b INNER JOIN user_card uc ON uc.card_id = b.card_id WHERE uc.tenant_id = ?",
            "DELETE e FROM rule_set_entry e INNER JOIN rule_set rs ON rs.rule_set_id = e.rule_set_id WHERE rs.tenant_id = ?",
            "DELETE FROM rule_set WHERE tenant_id = ?",
            "DELETE FROM user_card WHERE tenant_id = ?",
            "DELETE FROM user_card_template WHERE tenant_id = ?",
            "DELETE FROM tenant_domain_map WHERE tenant_id = ?",
        ] {
            sqlx::query(statement)
                .bind(tenant.tenant_id)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("DELETE FROM identity_card WHERE card_id = ? AND user_id = ?")
            .bind(tenant.identity_card_id)
            .bind(tenant.user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM platform_user WHERE user_id = ? AND user_no = ?")
            .bind(tenant.user_id)
            .bind(format!(
                "ts_{}_user_{}",
                fixture.code_prefix, tenant.user_id
            ))
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM tenant WHERE tenant_id = ? AND tenant_code = ?")
            .bind(tenant.tenant_id)
            .bind(expected_code)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM platform_domain WHERE domain_id = ? AND domain_code = ?")
            .bind(tenant.domain_id)
            .bind(format!(
                "ts_{}_domain_{}",
                fixture.code_prefix, tenant.domain_id
            ))
            .execute(&mut *tx)
            .await?;
        let remaining: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM authorization_projection_current WHERE tenant_id = ?",
        )
        .bind(tenant.tenant_id)
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(
            remaining, 0,
            "fixture cleanup must remove all published pointers"
        );
    }
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod edition_contract {
    #[test]
    fn authorization_publication_and_delivery_use_one_release_edition() {
        let edition = astral_types::AUTHORIZATION_EDITION;
        assert_eq!(astral_types::PublicationSeal::DIGEST_VERSION, edition);
        assert_eq!(astral_mq::INVALIDATION_SCHEMA_VERSION, i32::from(edition));
        assert_eq!(
            astral_mq::EVIDENCE_INVALIDATION_SCHEMA_VERSION,
            i32::from(edition)
        );
        assert_eq!(astral_db::SNAPSHOT_SCHEMA_VERSION, u32::from(edition));
        assert_eq!(astral_db::SNAPSHOT_PAYLOAD_VERSION, u32::from(edition));
        assert_eq!(
            policy_engine::COMPILER_VERSION,
            astral_types::AUTHORIZATION_COMPILER_VERSION
        );
        assert_eq!(
            policy_engine::ORG_COMPILER_VERSION,
            astral_types::AUTHORIZATION_ORG_COMPILER_VERSION
        );
        assert_eq!(
            astral_db::SEGMENT_FORMAT_AUTHORIZATION_GRANTS_JSON,
            astral_types::AUTHORIZATION_SEGMENT_FORMAT
        );
        assert_eq!(
            astral_db::SEGMENT_SEAL_DOMAIN_SEMANTIC,
            astral_types::AUTHORIZATION_SEGMENT_SEMANTIC_DOMAIN
        );
        assert_eq!(
            astral_db::SEGMENT_SEAL_DOMAIN_DEPENDENCY,
            astral_types::AUTHORIZATION_SEGMENT_DEPENDENCY_DOMAIN
        );
    }
}
