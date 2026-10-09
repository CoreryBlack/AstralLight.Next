//! testsuite 共享夹具库。
//!
//! 为 tests-suite 下新增的分类测试套件(多租户混合极限、安全前提扩展)提供:
//! 连接门控、参数化租户拓扑构建、v5 行播种、授权发布路径(stage → claim →
//! finalize → publish,与生产 worker 分步一致)以及确定性清理。
//!
//! 刻意保留的重复:各 crate 既有测试文件内的同名 helper(如
//! `astral-db/tests/multi_tenant_isolation.rs` 的 `TenantFixture`)是**独立副本**,
//! 本库不改动它们(测试深度与行为零变化);本库只服务 testsuite 新增套件。
//!
//! ID 段隔离:testsuite 使用 `SUITE_BASE_MIN`(2e16)起的专属随机段,与既有
//! 测试段(1e12 起,上限 ~8e15)和分布式 e2e 段(9e12 附近)互不重叠。

use astral_db::{
    claim_authorization_manifest_in_tx, connect_and_validate_schema,
    finalize_authorization_manifest_in_tx, publish_current_pointer_in_tx,
    stage_authorization_manifest_in_tx, AuthorizationFinalizeRequest, AuthorizationPublishOutcome,
    AuthorizationPublishRequest, AuthorizationStageRequest, CurrentPointerView,
    ProjectionAggregateIdentity, PublishRevokeFenceEvidence, StagedSegmentContent,
};
use astral_types::{
    BindingLayer, CanonicalGrant, DomainScopeRequirement, GrantEffect, GrantId, GrantProvenance,
    GrantRevision, GrantSourceKind, GrantState, PublishedCardEvidenceScope, TenantScope,
    ValidityWindow,
};
use sha2::{Digest, Sha256};
use sqlx::MySqlPool;
use uuid::Uuid;

/// 卡级聚合类型:合法标识符,且属于卡级证据读取器接受的类型集。
pub const AGGREGATE_TYPE: &str = "USER_CARD";
pub const MANIFEST_LEASE_SECONDS: i64 = 600;

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

/// seed 单个租户的全部 v5 行(不含任何旧链表写入)。
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
         VALUES (?, ?, ?, ?, 'TEMPLATE', 1, ?)",
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
         VALUES (?, ?, 'learn_subject', 'read', ?, 1, 1, ?)",
    )
    .bind(tenant.entry_id)
    .bind(tenant.rule_set_id)
    .bind(if tenant.role.has_allow_rule() {
        "ALLOW"
    } else {
        "DENY"
    })
    .bind(tenant.tenant_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// 构造一条 fixture ALLOW grant(provenance 与 manifest 事件身份在
/// [`publish_card_manifest`] 内对齐)。
#[allow(clippy::too_many_arguments)]
pub fn allow_rule_set_grant(
    salt: u128,
    tenant_id: i64,
    domain_id: i64,
    card_id: i64,
    user_id: i64,
    resource: &str,
    entry_id: i64,
    binding_ref_id: i64,
    unique_tail: u16,
) -> CanonicalGrant {
    assert!(
        unique_tail <= 0x0FFF,
        "tail must fit the 12 hex digit field"
    );
    let entropy = (salt & 0xFFFF_FFFF_F000) | u128::from(unique_tail);
    CanonicalGrant {
        grant_id: GrantId::parse(&format!("550e8400-e29b-41d4-a716-{entropy:012x}"))
            .expect("fixture grant id must be a valid UUID"),
        revision: GrantRevision::initial(),
        state: GrantState::Active,
        source_kind: GrantSourceKind::RuleSet,
        binding_layer: BindingLayer::Base,
        tenant: TenantScope::new(tenant_id, Some(domain_id))
            .expect("fixture tenant scope must be valid"),
        card_id,
        user_id,
        resource: resource.to_owned(),
        action: "read".to_owned(),
        effect: GrantEffect::Allow,
        validity: ValidityWindow::perpetual(),
        provenance: GrantProvenance {
            source_id: format!("rule-set-entry:{entry_id}"),
            source_entry: None,
            binding_id: Some(format!("card-rule-set-ref:{binding_ref_id}")),
            delegation_id: None,
            operation_id: "fixture-op-placeholder".to_owned(),
            event_id: None,
            actor_user_id: Some(user_id),
        },
    }
}

pub fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// 以最小正确方式构造一张卡的已发布 evidence:走公共
/// stage → claim lease → finalize → publish API(各自独立短事务,与生产
/// worker 分步一致)。空 `grants` 表示"投影已完成、零有效授权"(DENY 语义)。
/// `generation == 1` 为首次发布;更高代为增量发布(必须携带锁定到的当前
/// 指针视图)。
#[allow(clippy::too_many_arguments)]
pub async fn publish_card_manifest(
    pool: &MySqlPool,
    tenant_id: i64,
    card_id: i64,
    grants: Vec<CanonicalGrant>,
    tag: &str,
    salt: u128,
    generation: u64,
    current_pointer: Option<CurrentPointerView>,
) -> AuthorizationPublishOutcome {
    let identity = ProjectionAggregateIdentity::new(tenant_id, AGGREGATE_TYPE, card_id)
        .expect("fixture card aggregate identity must be valid");
    let event_id = format!("ev-ts-{salt:032x}-{tag}");
    let operation_id = format!("op-ts-{salt:032x}-{tag}");
    let semantic_hash_hex = sha256_hex(&format!("ts/{tenant_id}/semantic/{tag}"));
    let dependency_hash_hex = sha256_hex(&format!("ts/{tenant_id}/dependency/{tag}"));
    let compiler_version = "testsuite-v1".to_owned();

    let mut payload_grants = grants;
    for grant in &mut payload_grants {
        grant.provenance.operation_id = operation_id.clone();
        grant.provenance.event_id = Some(event_id.clone());
    }

    let stage_request = AuthorizationStageRequest {
        identity: identity.clone(),
        card_id: Some(card_id),
        target_generation: generation,
        source_generation: generation,
        projected_generation: generation,
        event_id: event_id.clone(),
        operation_id: operation_id.clone(),
        semantic_hash_hex: semantic_hash_hex.clone(),
        dependency_hash_hex: dependency_hash_hex.clone(),
        compiler_version: compiler_version.clone(),
        revoke_fence: 0,
        segments: vec![StagedSegmentContent::New(payload_grants)],
    };

    let mut tx = pool.begin().await.unwrap();
    let stage_outcome = stage_authorization_manifest_in_tx(&mut tx, &stage_request)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(
        !stage_outcome.resumed_existing_manifest,
        "a fresh suite namespace must never resume an existing manifest"
    );
    if generation == 1 {
        assert!(
            stage_outcome.base_pointer.is_none(),
            "first generation must observe no current pointer"
        );
    }

    assert_eq!(
        current_pointer,
        stage_outcome
            .base_pointer
            .as_ref()
            .map(|pointer| pointer.as_view()),
        "publication fixture must carry the pointer observed during staging"
    );
    let lease_owner = format!("ts-worker-{tag}");
    let mut tx = pool.begin().await.unwrap();
    let lease = claim_authorization_manifest_in_tx(
        &mut tx,
        &identity,
        generation,
        &lease_owner,
        MANIFEST_LEASE_SECONDS,
    )
    .await
    .unwrap()
    .expect("the staged BUILDING manifest must be claimable right after staging");
    tx.commit().await.unwrap();
    assert_eq!(lease.manifest_id, stage_outcome.manifest_id);
    assert_eq!(lease.generation as u64, generation);

    let finalize_request = AuthorizationFinalizeRequest {
        identity: identity.clone(),
        target_generation: generation,
        manifest_id: stage_outcome.manifest_id,
        lease_owner: lease.lease_owner.clone(),
        lease_token: lease.lease_token,
        expected_cas_version: lease.cas_version_after_claim,
        expected_reference_count: Some(1),
    };
    let mut tx = pool.begin().await.unwrap();
    finalize_authorization_manifest_in_tx(&mut tx, &finalize_request)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let publish_request = AuthorizationPublishRequest {
        identity,
        card_id: Some(card_id),
        target_manifest_id: stage_outcome.manifest_id,
        target_generation: generation,
        current_pointer,
        expected_target_semantic_hash_hex: semantic_hash_hex,
        expected_target_dependency_hash_hex: dependency_hash_hex,
        expected_target_compiler_version: compiler_version,
        fences: PublishRevokeFenceEvidence {
            previous_revoke_fence: 0,
            new_revoke_fence: 0,
        },
    };
    let mut tx = pool.begin().await.unwrap();
    let outcome = publish_current_pointer_in_tx(&mut tx, &publish_request)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(outcome.pointer.current_generation as u64, generation);
    assert_eq!(outcome.pointer.manifest_id, stage_outcome.manifest_id);
    outcome
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
    let lo = fixture.base;
    let hi = fixture.base + 14 * CATEGORY_STRIDE + 2_000;
    let tenant_hi = fixture.base + fixture.tenants.len() as i64;
    let mut tx = pool.begin().await?;
    for table in [
        "authorization_projection_manifest_segment",
        "authorization_projection_current",
        "authorization_projection_manifest",
        "authorization_projection_segment",
    ] {
        let sql = format!("DELETE FROM {table} WHERE tenant_id > ? AND tenant_id <= ?");
        sqlx::query(&sql)
            .bind(lo)
            .bind(tenant_hi)
            .execute(&mut *tx)
            .await?;
    }
    let statements: [(&str, &str); 11] = [
        ("permission_rule", "card_id"),
        ("card_rule_set_ref", "id"),
        ("rule_set_entry", "entry_id"),
        ("rule_set", "rule_set_id"),
        ("user_card", "card_id"),
        ("user_card_template", "template_id"),
        ("identity_card", "card_id"),
        ("platform_user", "user_id"),
        ("tenant_domain_map", "id"),
        ("tenant", "tenant_id"),
        ("platform_domain", "domain_id"),
    ];
    for (table, column) in statements {
        let sql = format!("DELETE FROM {table} WHERE {column} >= ? AND {column} <= ?");
        sqlx::query(&sql)
            .bind(lo)
            .bind(hi)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("DELETE FROM audit_log WHERE id >= ? AND id <= ?")
        .bind(lo)
        .bind(hi)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let remaining: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM authorization_projection_current WHERE tenant_id > ? AND tenant_id <= ?",
    )
    .bind(lo)
    .bind(tenant_hi)
    .fetch_one(pool)
    .await?;
    assert_eq!(
        remaining, 0,
        "fixture cleanup must remove all published pointers"
    );
    Ok(())
}
