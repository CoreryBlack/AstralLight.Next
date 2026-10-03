//! 多租户隔离集成测试（新链语义）
//!
//! 需要可访问的 MySQL 8.0 测试数据库，且数据库已加载 v5 baseline 并应用
//! Rust migrations（含 20260825000002 / 20260827000001 建立的 Rust-owned
//! 授权投影链表）。运行方式：
//! `cargo test --test multi_tenant_isolation -- --ignored`。
//! 未设置 `DATABASE_URL` 或连接/schema 校验失败时默认跳过；设置
//! `RUST_INTEGRATION_REQUIRED=1` 仅将这些前置条件失败转换为 panic，不会解除
//! `#[ignore]`，因此仍须显式传入 `--ignored`。
//!
//! # 新链语义（旧链零写入）
//!
//! - 旧链表（`rule_set_snapshot` / `permission_rule_snapshot` /
//!   `authorization_projection_head`）已被迁移 20260827000002 标记退役；
//!   本文件绝不向它们写入，也绝不从它们读取。
//! - 数据层 seed 走 v5 表（`platform_user` / `identity_card` /
//!   `user_card`（带 tenant_id）/ `rule_set` / `rule_set_entry` /
//!   `card_rule_set_ref` / `permission_rule`，均带 tenant_id）。
//! - 已发布 evidence 通过公共 API 以最小正确方式构造：
//!   `stage_authorization_manifest_in_tx` → `claim_authorization_manifest_in_tx`
//!   → `finalize_authorization_manifest_in_tx` → `publish_current_pointer_in_tx`
//!   （与生产 worker 分步一致；manifest digest / CAS / lineage 全部由实现自洽
//!   生成，测试不手工拼 ledger 行，也不触碰 `authorization_grant_revision` /
//!   `authorization_delta_event` —— 那两张表属于 trustgraph 侧 source
//!   mutation 契约，测试不得伪造）。
//! - 隔离判定改用卡级 lens：`load_published_card_grant_evidence`。
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
//! 4. 跨租户 scope 分裂 = corrupt fail-closed（Java 未覆盖的加深场景）：
//!    已发布 payload 内出现与聚合租户矛盾的 grant 时，严格读取器必须返回
//!    显式 `Corrupt`（映射 DENY），绝不产生空/等价授权集合。
//! 5. 租户级审计日志读写 + tenant_id 过滤不变式（Java: AuditLogConsumer
//!    幂等 + audit tenant 过滤）。
//! 6. TenantScopedQuery 参数化 SQL 与真实 DB 配合。
//!
//! （跨租户 SQL 隔离的 SQL 级不变式已在 astral-common 单测覆盖，此处不重复。）
//!
//! # 隔离与幂等
//!
//! 每个测试用独立的随机数值命名空间（uuid 派生大整数）+ 测试专属字符串前缀。
//! 清理按前缀匹配（而非本轮随机 id），因此上一轮失败残留的行会在下一轮 seed
//! 前被清除；每轮结束再清一次。测试可对同一数据库反复重跑（幂等），不假设
//! 全新库。

use astral_db::{
    check_card_active_cached_with_options, claim_authorization_manifest_in_tx,
    connect_and_validate_schema, finalize_authorization_manifest_in_tx,
    load_published_card_grant_evidence, publish_current_pointer_in_tx,
    read_published_authorization_state_in_tx, stage_authorization_manifest_in_tx,
    AuthorizationEvidenceError, AuthorizationFinalizeRequest, AuthorizationPublishOutcome,
    AuthorizationPublishRequest, AuthorizationStageRequest, CardActiveContext, CurrentPointerView,
    ProjectionAggregateIdentity, PublishRevokeFenceEvidence, SqlxRuleRepository,
    StagedSegmentContent,
};
use astral_types::{
    BindingLayer, CanonicalGrant, DomainScopeRequirement, GrantEffect, GrantId, GrantProvenance,
    GrantRevision, GrantSourceKind, GrantState, PolicyError, PublishedCardEvidenceScope,
    PublishedEvidenceGateStatus, TenantScope, ValidityWindow,
};
use policy_engine::RuleRepository;
use sha2::{Digest, Sha256};
use sqlx::MySqlPool;
use std::collections::BTreeSet;
use uuid::Uuid;

/// 卡级聚合类型：既是合法标识符，也属于卡级证据读取器接受的类型集。
const AGGREGATE_TYPE: &str = "USER_CARD";
const MANIFEST_LEASE_SECONDS: i64 = 600;
const FIXTURE_BASE_MIN: i64 = 1_000_000_000_000;
const FIXTURE_BASE_STRIDE: i64 = 10_000;
const FIXTURE_RANDOM_RANGE: u128 = 800_000_000_000;
const FIXTURE_AUDIT_SOURCE: &str = "fixture-audit";
const PROJECTION_TABLES: &[&str] = &[
    "authorization_projection_manifest",
    "authorization_projection_segment",
    "authorization_projection_manifest_segment",
    "authorization_projection_current",
];

fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

#[derive(Clone, Copy)]
struct TenantFixture {
    label: &'static str,
    tenant_status: &'static str,
    rule_effect: &'static str,
    tenant_id: i64,
    domain_id: i64,
    user_id: i64,
    identity_card_id: i64,
    template_id: i64,
    card_id: i64,
    rule_set_id: i64,
    entry_id: i64,
    card_rule_set_ref_id: i64,
    permission_rule_id: i64,
    tenant_domain_map_id: i64,
    audit_seed_id: i64,
    audit_test_base: i64,
}

impl TenantFixture {
    /// 命名空间由 uuid salt 派生的 base 决定；label 决定租户在 fixture 内的
    /// 角色约定：租户 a = ACTIVE/ALLOW，租户 b = ACTIVE/DENY，
    /// 租户 c = SUSPENDED/DENY。
    fn new(base: i64, ordinal: i64, label: &'static str) -> Self {
        let rule_effect = if label == "a" { "ALLOW" } else { "DENY" };
        Self {
            label,
            tenant_status: if label == "c" { "SUSPENDED" } else { "ACTIVE" },
            rule_effect,
            tenant_id: base + ordinal,
            domain_id: base + 10 + ordinal,
            user_id: base + 20 + ordinal,
            identity_card_id: base + 30 + ordinal,
            template_id: base + 40 + ordinal,
            card_id: base + 50 + ordinal,
            rule_set_id: base + 60 + ordinal,
            entry_id: base + 70 + ordinal,
            card_rule_set_ref_id: base + 90 + ordinal,
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
    /// uuid salt：GrantId 熵与随机 id 区间的共同来源（每次运行唯一）。
    salt: u128,
    tenants: [TenantFixture; 3],
    /// 租户 A 的第二张卡（同租户同用户不同卡）：卡级 lens 隔离场景。
    second_card_id: i64,
    second_rule_set_id: i64,
    second_entry_id: i64,
    second_card_rule_set_ref_id: i64,
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
            second_card_rule_set_ref_id: base + 340,
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
// 清理（前缀匹配 → 幂等可重跑）
// ─────────────────────────────────────────────────────────────────────────────

/// 按测试专属前缀清理本命名空间全部数据。新链投影表通过 `tenant_code` 前缀
/// 定位（此时 tenant 行尚未删除）；随后按子先父后的防御顺序清理 v5 表。
/// 旧链表（rule_set_snapshot / permission_rule_snapshot /
/// authorization_projection_head）零写入，因此也无需清理。
async fn cleanup_multi_tenant_data(
    pool: &MySqlPool,
    fixture: &MultiTenantFixture,
) -> Result<(), sqlx::Error> {
    let domain_code_prefix = format!("mt_{}_domain_", fixture.code_prefix);
    let tenant_code_prefix = format!("mt_{}_tenant_", fixture.code_prefix);
    let user_no_prefix = format!("mt_{}_user_", fixture.code_prefix);
    let template_code_prefix = format!("mt_{}_template_", fixture.code_prefix);
    let rule_set_code_prefix = format!("mt_{}_rule_set_", fixture.code_prefix);

    // 1) 新链投影表（子先父后；segment 是内容寻址，最后删）。
    for table in PROJECTION_TABLES {
        sqlx::query(&format!(
            "DELETE row_to_delete FROM {table} AS row_to_delete \
             INNER JOIN tenant t ON t.tenant_id = row_to_delete.tenant_id \
             WHERE LEFT(t.tenant_code, CHAR_LENGTH(?)) = ?"
        ))
        .bind(&tenant_code_prefix)
        .bind(&tenant_code_prefix)
        .execute(pool)
        .await?;
    }

    // 2) 审计日志（按 fixture 用户定位）。
    sqlx::query(
        "DELETE al FROM audit_log al \
         INNER JOIN platform_user pu ON pu.user_id = al.user_id \
         WHERE LEFT(pu.user_no, CHAR_LENGTH(?)) = ?",
    )
    .bind(&user_no_prefix)
    .bind(&user_no_prefix)
    .execute(pool)
    .await?;

    // 3) v5 source/绑定数据（子先父后的防御顺序；无外键级联依赖）。
    sqlx::query(
        "DELETE pr FROM permission_rule pr \
         INNER JOIN user_card uc ON uc.card_id = pr.card_id \
         INNER JOIN platform_user pu ON pu.user_id = uc.user_id \
         WHERE LEFT(pu.user_no, CHAR_LENGTH(?)) = ?",
    )
    .bind(&user_no_prefix)
    .bind(&user_no_prefix)
    .execute(pool)
    .await?;
    sqlx::query(
        "DELETE rse FROM rule_set_entry rse \
         INNER JOIN rule_set rs ON rs.rule_set_id = rse.rule_set_id \
         WHERE LEFT(rs.code, CHAR_LENGTH(?)) = ?",
    )
    .bind(&rule_set_code_prefix)
    .bind(&rule_set_code_prefix)
    .execute(pool)
    .await?;
    sqlx::query(
        "DELETE crs FROM card_rule_set_ref crs \
         INNER JOIN rule_set rs ON rs.rule_set_id = crs.rule_set_id \
         WHERE LEFT(rs.code, CHAR_LENGTH(?)) = ?",
    )
    .bind(&rule_set_code_prefix)
    .bind(&rule_set_code_prefix)
    .execute(pool)
    .await?;
    sqlx::query("DELETE FROM rule_set WHERE LEFT(code, CHAR_LENGTH(?)) = ?")
        .bind(&rule_set_code_prefix)
        .bind(&rule_set_code_prefix)
        .execute(pool)
        .await?;
    sqlx::query(
        "DELETE uc FROM user_card uc \
         INNER JOIN platform_user pu ON pu.user_id = uc.user_id \
         WHERE LEFT(pu.user_no, CHAR_LENGTH(?)) = ?",
    )
    .bind(&user_no_prefix)
    .bind(&user_no_prefix)
    .execute(pool)
    .await?;
    sqlx::query(
        "DELETE ic FROM identity_card ic \
         INNER JOIN platform_user pu ON pu.user_id = ic.user_id \
         WHERE LEFT(pu.user_no, CHAR_LENGTH(?)) = ?",
    )
    .bind(&user_no_prefix)
    .bind(&user_no_prefix)
    .execute(pool)
    .await?;
    sqlx::query(
        "DELETE FROM user_card_template \
         WHERE LEFT(template_code, CHAR_LENGTH(?)) = ?",
    )
    .bind(&template_code_prefix)
    .bind(&template_code_prefix)
    .execute(pool)
    .await?;
    sqlx::query(
        "DELETE tdm FROM tenant_domain_map tdm \
         INNER JOIN tenant t ON t.tenant_id = tdm.tenant_id \
         WHERE LEFT(t.tenant_code, CHAR_LENGTH(?)) = ?",
    )
    .bind(&tenant_code_prefix)
    .bind(&tenant_code_prefix)
    .execute(pool)
    .await?;
    sqlx::query("DELETE FROM tenant WHERE LEFT(tenant_code, CHAR_LENGTH(?)) = ?")
        .bind(&tenant_code_prefix)
        .bind(&tenant_code_prefix)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM platform_domain WHERE LEFT(domain_code, CHAR_LENGTH(?)) = ?")
        .bind(&domain_code_prefix)
        .bind(&domain_code_prefix)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM platform_user WHERE LEFT(user_no, CHAR_LENGTH(?)) = ?")
        .bind(&user_no_prefix)
        .bind(&user_no_prefix)
        .execute(pool)
        .await?;

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// seed（v5 表 + 新链已发布 evidence）
// ─────────────────────────────────────────────────────────────────────────────

/// 构造一条 RULE_SET 来源的 ALLOW canonical grant（provenance 指向 v5 source
/// 行；operation/event 由 publish 助手与 manifest 对齐后填入）。
#[allow(clippy::too_many_arguments)]
fn allow_rule_set_grant(
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

/// 以最小正确方式构造一张卡的已发布 evidence：走公共
/// stage → claim lease → finalize → publish API（各自独立短事务，与生产
/// worker 分步一致）。空 `grants` 表示"投影已完成、零有效授权"（DENY 语义）。
/// `generation == 1` 为首次发布（`current_pointer` 必须为 None）；更高代为
/// 增量发布（必须携带锁定到的当前指针视图）。
#[allow(clippy::too_many_arguments)]
async fn publish_card_manifest(
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
    let event_id = format!("ev-mt-{salt:032x}-{tag}");
    let operation_id = format!("op-mt-{salt:032x}-{tag}");
    let semantic_hash_hex = sha256_hex(&format!("mt/{tenant_id}/semantic/{tag}"));
    let dependency_hash_hex = sha256_hex(&format!("mt/{tenant_id}/dependency/{tag}"));
    let compiler_version = "multi-tenant-itest-v1".to_owned();

    // grant 的 provenance 与 manifest 事件身份对齐。
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
        "a fresh test namespace must never resume an existing manifest"
    );
    if generation == 1 {
        assert!(
            stage_outcome.base_pointer.is_none(),
            "first generation must observe no current pointer"
        );
    } else {
        let base_pointer = stage_outcome
            .base_pointer
            .as_ref()
            .expect("later generations must observe the current pointer");
        assert_eq!(base_pointer.current_generation as u64, generation - 1);
    }

    let lease_owner = format!("mt-itest-worker-{tag}");
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
    if generation == 1 {
        assert!(outcome.initialized_first_pointer);
    } else {
        assert!(!outcome.initialized_first_pointer);
    }
    outcome
}

/// seed 单个租户的全部 v5 行（不含任何旧链表写入）。
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
         VALUES (?, ?, ?, ?, 'TEMPLATE', 1, ?)",
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
         VALUES (?, ?, 'learn_subject', 'read', ?, 1, 1, ?)",
    )
    .bind(tenant.entry_id)
    .bind(tenant.rule_set_id)
    .bind(tenant.rule_effect)
    .bind(tenant.tenant_id)
    .execute(pool)
    .await?;

    sqlx::query(
        "INSERT INTO card_rule_set_ref (id, card_id, rule_set_id, ref_type, tenant_id) \
         VALUES (?, ?, ?, 'BASE', ?)",
    )
    .bind(tenant.card_rule_set_ref_id)
    .bind(tenant.card_id)
    .bind(tenant.rule_set_id)
    .bind(tenant.tenant_id)
    .execute(pool)
    .await?;

    let permission_action = if tenant.label == "b" {
        "delete"
    } else {
        "read"
    };
    sqlx::query(
        "INSERT INTO permission_rule \
         (rule_id, card_id, resource_type, action_code, effect, priority, source_type, enabled, tenant_id) \
         VALUES (?, ?, 'profile', ?, ?, 1, 'MANUAL', 1, ?)",
    )
    .bind(tenant.permission_rule_id)
    .bind(tenant.card_id)
    .bind(permission_action)
    .bind(tenant.rule_effect)
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
    .bind(tenant.rule_effect)
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
         VALUES (?, ?, ?, ?, 'TEMPLATE', 1, ?)",
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
         VALUES (?, ?, 'profile', 'read', 'ALLOW', 1, 1, ?)",
    )
    .bind(fixture.second_entry_id)
    .bind(fixture.second_rule_set_id)
    .bind(tenant_a.tenant_id)
    .execute(pool)
    .await?;

    sqlx::query(
        "INSERT INTO card_rule_set_ref (id, card_id, rule_set_id, ref_type, tenant_id) \
         VALUES (?, ?, ?, 'BASE', ?)",
    )
    .bind(fixture.second_card_rule_set_ref_id)
    .bind(fixture.second_card_id)
    .bind(fixture.second_rule_set_id)
    .bind(tenant_a.tenant_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// seed 全部 v5 行并按各租户 rule_effect 发布卡级 evidence：
/// 租户 A 的两张卡发布 ALLOW 授权（learn_subject / profile），租户 B/C
/// （DENY 规则）发布零有效授权的已完成投影。
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

    // 租户 A 卡 1：ALLOW（learn_subject:read）。
    let grant_a1 = allow_rule_set_grant(
        fixture.salt,
        tenant_a.tenant_id,
        tenant_a.domain_id,
        tenant_a.card_id,
        tenant_a.user_id,
        "learn_subject:*",
        tenant_a.entry_id,
        tenant_a.card_rule_set_ref_id,
        0x001,
    );
    publish_card_manifest(
        pool,
        tenant_a.tenant_id,
        tenant_a.card_id,
        vec![grant_a1],
        "a1-card",
        fixture.salt,
        1,
        None,
    )
    .await;

    // 租户 A 卡 2：ALLOW（profile:read）——同租户不同卡。
    let grant_a2 = allow_rule_set_grant(
        fixture.salt,
        tenant_a.tenant_id,
        tenant_a.domain_id,
        fixture.second_card_id,
        tenant_a.user_id,
        "profile:*",
        fixture.second_entry_id,
        fixture.second_card_rule_set_ref_id,
        0x002,
    );
    publish_card_manifest(
        pool,
        tenant_a.tenant_id,
        fixture.second_card_id,
        vec![grant_a2],
        "a2-card",
        fixture.salt,
        1,
        None,
    )
    .await;

    // 租户 B/C：DENY 规则 → 已完成的零有效授权投影。
    publish_card_manifest(
        pool,
        tenant_b.tenant_id,
        tenant_b.card_id,
        vec![],
        "b-card",
        fixture.salt,
        1,
        None,
    )
    .await;
    publish_card_manifest(
        pool,
        tenant_c.tenant_id,
        tenant_c.card_id,
        vec![],
        "c-card",
        fixture.salt,
        1,
        None,
    )
    .await;

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
    assert_eq!(
        grant_a.provenance.binding_id,
        Some(format!(
            "card-rule-set-ref:{}",
            tenant_a.card_rule_set_ref_id
        ))
    );
    assert_eq!(
        grant_a.provenance.source_id,
        format!("rule-set-entry:{}", tenant_a.entry_id)
    );

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
        grant.provenance.binding_id
            != Some(format!(
                "card-rule-set-ref:{}",
                tenant_b.card_rule_set_ref_id
            ))
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

    for (evidence, expected_card_id, expected_resource, expected_ref_id) in [
        (
            &evidence_card1,
            tenant_a.card_id,
            "learn_subject:*",
            tenant_a.card_rule_set_ref_id,
        ),
        (
            &evidence_card2,
            fixture.second_card_id,
            "profile:*",
            fixture.second_card_rule_set_ref_id,
        ),
    ] {
        assert_eq!(evidence.gate.status, PublishedEvidenceGateStatus::Ready);
        assert_eq!(evidence.tenant_id, tenant_a.tenant_id);
        assert_eq!(evidence.card_id, expected_card_id);
        assert_eq!(evidence.gate.effective_grant_count, 1);
        assert_eq!(evidence.effective_grants.len(), 1);
        let grant = &evidence.effective_grants[0];
        assert_eq!(grant.resource, expected_resource);
        assert_eq!(
            grant.provenance.binding_id,
            Some(format!("card-rule-set-ref:{expected_ref_id}"))
        );
        // 只合成自己的聚合：manifest 聚合 id 必须等于本卡的 user_card id。
        assert_eq!(evidence.manifests.len(), 1);
        assert_eq!(evidence.manifests[0].aggregate_id, expected_card_id);
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

/// 跨租户 scope 分裂 = corrupt fail-closed（Java 未覆盖的加深场景）。
///
/// 已发布 payload 内出现与聚合租户矛盾的 grant（租户 B 的授权被塞进租户 A
/// 卡的已发布 evidence）时，严格读取器必须整读失败为显式 `Corrupt`
/// （映射 DENY，需要人工对账），绝不静默丢弃或降级为空授权集合。
/// 分裂状态完全通过公共 stage/publish API 构造，不手工改持久化行。
#[ignore]
#[tokio::test]
async fn test_cross_tenant_scope_split_is_corrupt_fail_closed() {
    let Some(pool) = connect().await else {
        return;
    };

    let fixture = MultiTenantFixture::new("scope_split");
    seed_multi_tenant_data(&pool, &fixture).await.unwrap();
    let tenant_a = fixture.tenants[0];
    let tenant_b = fixture.tenants[1];

    // 构造分裂：以租户 A 的卡聚合身份发布一条租户 B scope 的 grant。
    // seed 已为该卡发布 gen1（合法 ALLOW），分裂状态作为 gen2 增量发布，
    // 与生产 worker 的代数推进方式一致。
    let forged_grant = allow_rule_set_grant(
        fixture.salt,
        tenant_b.tenant_id,
        tenant_b.domain_id,
        tenant_b.card_id,
        tenant_b.user_id,
        "learn_subject:*",
        tenant_b.entry_id,
        tenant_b.card_rule_set_ref_id,
        0x003,
    );
    let current_pointer = {
        let identity =
            ProjectionAggregateIdentity::new(tenant_a.tenant_id, AGGREGATE_TYPE, tenant_a.card_id)
                .expect("fixture card aggregate identity must be valid");
        let mut tx = pool.begin().await.unwrap();
        let state = read_published_authorization_state_in_tx(&mut tx, &identity)
            .await
            .expect("seeded gen1 evidence must be readable");
        tx.rollback().await.unwrap();
        state.pointer.as_view()
    };
    publish_card_manifest(
        &pool,
        tenant_a.tenant_id,
        tenant_a.card_id,
        vec![forged_grant],
        "split",
        fixture.salt,
        2,
        Some(current_pointer),
    )
    .await;

    // 卡级严格读取器：payload 内 grant 租户与 scope 矛盾 → 整读 Corrupt。
    let error =
        load_published_card_grant_evidence(&pool, &fixture.card_scope(tenant_a, tenant_a.card_id))
            .await
            .unwrap_err();
    match &error {
        AuthorizationEvidenceError::Corrupt(message) => {
            assert!(
                message.contains("grant_tenant_scope_mismatch_inside_committed_payload"),
                "unexpected Corrupt code: {message}"
            );
        }
        other => {
            panic!("cross-tenant payload split must fail the whole read as Corrupt, got: {other:?}")
        }
    }
    assert_eq!(
        error.as_gate_status(),
        PublishedEvidenceGateStatus::Corrupt,
        "scope split must map to the Corrupt gate status (deny + manual reconciliation)"
    );

    // 生产 repository 端口把 Corrupt 映射为 PolicyError::Repository，稳定
    // code 前缀 published_card_evidence_corrupt 保留供审计关联。
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
