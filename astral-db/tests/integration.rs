//! astral-db 集成测试（新链语义）
//!
//! 需要可访问的 MySQL 8.0 测试数据库，且数据库已加载 v5 baseline 并应用
//! Rust migrations（含 20260825000002 / 20260827000001 建立的 Rust-owned
//! 授权投影链表）。运行方式：`cargo test --test integration -- --ignored`。
//! 未设置 `DATABASE_URL` 或连接失败时默认跳过；设置
//! `RUST_INTEGRATION_REQUIRED=1` 仅将这些前置条件失败转换为 panic。
//!
//! # 新链语义（旧链零写入）
//!
//! 旧版本测试曾直接 INSERT `rule_set_snapshot` /
//! `authorization_projection_head` 等旧链表并以固定主键（card_id=1）假设
//! 全新库——在已有数据的验收库上会因 `Duplicate entry` /
//! `Unknown column 'tenant_id'` 失败，且违反旧链退役后的零写入原则。
//! 现版本：
//! - 使用 uuid 派生的随机命名空间 + 测试专属前缀清理（幂等可重跑，不假设
//!   全新库，也不依赖固定主键）；
//! - 正式 L1 读取走 `load_published_card_authorization`（Rust-owned
//!   published card evidence strict gate，公共
//!   stage → claim lease → finalize → publish API 构造 evidence）；
//! - 不向 `rule_set_snapshot` / `permission_rule_snapshot` /
//!   `authorization_projection_head` 写入任何行，也不执行临时 DDL。
//!
//! # 覆盖
//!
//! 1. repository 正式端口读取已发布卡级 evidence（Ready + 期望授权集）。
//! 2. 无 evidence 的卡读取 fail-closed 为
//!    `published_card_evidence_not_ready`（PENDING 词表，绝无 empty-ALLOW）。
//! 3. 正式 L2 `load_permission_rules` 在 head 缺失时保持空集，绝不回读
//!    source `permission_rule`（保留原测试的 no-source-fallback 断言）。
//! 4. 投影 gate 缺失时显式 ready=false（上游 AUTHORIZATION_PENDING）。
//! 5. raw oracle 读取器（`load_permission_rules_raw` /
//!    `load_rule_set_entries_raw`）仍能看到 source 行，供一致性巡检使用。

use astral_db::{
    claim_authorization_manifest_in_tx, connect_and_validate_schema,
    finalize_authorization_manifest_in_tx, publish_current_pointer_in_tx,
    stage_authorization_manifest_in_tx, AuthorizationFinalizeRequest, AuthorizationPublishRequest,
    AuthorizationStageRequest, ProjectionAggregateIdentity, PublishRevokeFenceEvidence,
    SqlxRuleRepository, StagedSegmentContent,
};
use astral_types::{
    BindingLayer, CanonicalGrant, DomainScopeRequirement, Effect, GrantEffect, GrantId,
    GrantProvenance, GrantRevision, GrantSourceKind, GrantState, PolicyError,
    PublishedCardEvidenceScope, PublishedEvidenceGateStatus, TenantScope, ValidityWindow,
};
use policy_engine::RuleRepository;
use sha2::{Digest, Sha256};
use sqlx::MySqlPool;
use uuid::Uuid;

/// 卡级聚合类型（与生产 USER_CARD 聚合一致，且属于卡级证据读取器接受的类型集）。
const AGGREGATE_TYPE: &str = "USER_CARD";
const MANIFEST_LEASE_SECONDS: i64 = 600;
const PROJECTION_TABLES: &[&str] = &[
    "authorization_projection_manifest",
    "authorization_projection_segment",
    "authorization_projection_manifest_segment",
    "authorization_projection_current",
];

/// 独立随机测试命名空间：uuid 派生的大整数，保证跨运行互不冲突。
struct TestNamespace {
    salt: u128,
    tenant_id: i64,
    domain_id: i64,
    user_id: i64,
    card_id: i64,
    rule_set_id: i64,
    entry_id: i64,
    card_rule_set_ref_id: i64,
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
            card_id: base + 3,
            rule_set_id: base + 4,
            entry_id: base + 5,
            card_rule_set_ref_id: base + 6,
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

    /// 从未 seed 的卡 scope：验证未发布 evidence 的 fail-closed 语义。
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

/// 只删除本命名空间的行（测试专属前缀定位；先子后父的防御顺序）。
/// 旧链表（rule_set_snapshot / permission_rule_snapshot /
/// authorization_projection_head）零写入，因此无需清理。
async fn cleanup_namespace(pool: &MySqlPool) {
    // 每个语句与其定位前缀成对绑定；投影表通过 tenant_code 前缀定位
    // （此时 tenant 行仍在）。
    let statements: [(&str, &str); 13] = [
        (
            "DELETE row_to_delete FROM authorization_projection_manifest_segment AS row_to_delete \
             INNER JOIN tenant t ON t.tenant_id = row_to_delete.tenant_id \
             WHERE LEFT(t.tenant_code, CHAR_LENGTH(?)) = ?",
            "e2e_tenant_",
        ),
        (
            "DELETE row_to_delete FROM authorization_projection_current AS row_to_delete \
             INNER JOIN tenant t ON t.tenant_id = row_to_delete.tenant_id \
             WHERE LEFT(t.tenant_code, CHAR_LENGTH(?)) = ?",
            "e2e_tenant_",
        ),
        (
            "DELETE row_to_delete FROM authorization_projection_manifest AS row_to_delete \
             INNER JOIN tenant t ON t.tenant_id = row_to_delete.tenant_id \
             WHERE LEFT(t.tenant_code, CHAR_LENGTH(?)) = ?",
            "e2e_tenant_",
        ),
        (
            "DELETE row_to_delete FROM authorization_projection_segment AS row_to_delete \
             INNER JOIN tenant t ON t.tenant_id = row_to_delete.tenant_id \
             WHERE LEFT(t.tenant_code, CHAR_LENGTH(?)) = ?",
            "e2e_tenant_",
        ),
        (
            "DELETE pr FROM permission_rule pr \
             INNER JOIN user_card uc ON uc.card_id = pr.card_id \
             INNER JOIN platform_user pu ON pu.user_id = uc.user_id \
             WHERE LEFT(pu.user_no, CHAR_LENGTH(?)) = ?",
            "e2e_user_",
        ),
        (
            "DELETE rse FROM rule_set_entry rse \
             INNER JOIN rule_set rs ON rs.rule_set_id = rse.rule_set_id \
             WHERE LEFT(rs.code, CHAR_LENGTH(?)) = ?",
            "e2e_rule_set_",
        ),
        (
            "DELETE crs FROM card_rule_set_ref crs \
             INNER JOIN rule_set rs ON rs.rule_set_id = crs.rule_set_id \
             WHERE LEFT(rs.code, CHAR_LENGTH(?)) = ?",
            "e2e_rule_set_",
        ),
        (
            "DELETE FROM rule_set WHERE LEFT(code, CHAR_LENGTH(?)) = ?",
            "e2e_rule_set_",
        ),
        (
            "DELETE uc FROM user_card uc \
             INNER JOIN platform_user pu ON pu.user_id = uc.user_id \
             WHERE LEFT(pu.user_no, CHAR_LENGTH(?)) = ?",
            "e2e_user_",
        ),
        (
            "DELETE tdm FROM tenant_domain_map tdm \
             INNER JOIN tenant t ON t.tenant_id = tdm.tenant_id \
             WHERE LEFT(t.tenant_code, CHAR_LENGTH(?)) = ?",
            "e2e_tenant_",
        ),
        (
            "DELETE FROM tenant WHERE LEFT(tenant_code, CHAR_LENGTH(?)) = ?",
            "e2e_tenant_",
        ),
        (
            "DELETE FROM platform_domain WHERE LEFT(domain_code, CHAR_LENGTH(?)) = ?",
            "e2e_domain_",
        ),
        (
            "DELETE FROM platform_user WHERE LEFT(user_no, CHAR_LENGTH(?)) = ?",
            "e2e_user_",
        ),
    ];

    for (statement, prefix) in statements {
        sqlx::query(statement)
            .bind(prefix)
            .bind(prefix)
            .execute(pool)
            .await
            .unwrap();
    }
}

/// seed 最小 v5 命名空间：租户/域/用户/卡 + 规则集/条目/绑定 + 一条
/// MANUAL source permission_rule（正式读取必须忽略它）。
async fn seed_namespace(pool: &MySqlPool, namespace: &TestNamespace) -> Result<(), sqlx::Error> {
    cleanup_namespace(pool).await;

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
         VALUES (?, ?, ?, ?, 'TEMPLATE', 1, ?)",
    )
    .bind(namespace.rule_set_id)
    .bind("E2E rule set")
    .bind(format!("e2e_rule_set_{}", namespace.rule_set_id))
    .bind("E2E fixture rule set")
    .bind(namespace.tenant_id)
    .execute(pool)
    .await?;

    sqlx::query(
        "INSERT INTO rule_set_entry \
         (entry_id, rule_set_id, resource_type, action_code, effect, priority, enabled, tenant_id) \
         VALUES (?, ?, 'learn_subject', 'read', 'ALLOW', 1, 1, ?)",
    )
    .bind(namespace.entry_id)
    .bind(namespace.rule_set_id)
    .bind(namespace.tenant_id)
    .execute(pool)
    .await?;

    sqlx::query(
        "INSERT INTO card_rule_set_ref (id, card_id, rule_set_id, ref_type, tenant_id) \
         VALUES (?, ?, ?, 'BASE', ?)",
    )
    .bind(namespace.card_rule_set_ref_id)
    .bind(namespace.card_id)
    .bind(namespace.rule_set_id)
    .bind(namespace.tenant_id)
    .execute(pool)
    .await?;

    // CARD_ONLY source 行：正式 loader 必须忽略它（保留原测试意图）。
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

fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// 构造与 v5 rule_set_entry 对齐的 ALLOW canonical grant。
fn allow_rule_set_grant(namespace: &TestNamespace) -> CanonicalGrant {
    let entropy = namespace.salt & 0xFFFF_FFFF_F000 | 0x001;
    CanonicalGrant {
        grant_id: GrantId::parse(&format!("550e8400-e29b-41d4-a716-{entropy:012x}"))
            .expect("fixture grant id must be a valid UUID"),
        revision: GrantRevision::initial(),
        state: GrantState::Active,
        source_kind: GrantSourceKind::RuleSet,
        binding_layer: BindingLayer::Base,
        tenant: TenantScope::new(namespace.tenant_id, Some(namespace.domain_id))
            .expect("fixture tenant scope must be valid"),
        card_id: namespace.card_id,
        user_id: namespace.user_id,
        resource: "learn_subject:*".to_owned(),
        action: "read".to_owned(),
        effect: GrantEffect::Allow,
        validity: ValidityWindow::perpetual(),
        provenance: GrantProvenance {
            source_id: format!("rule-set-entry:{}", namespace.entry_id),
            source_entry: None,
            binding_id: Some(format!(
                "card-rule-set-ref:{}",
                namespace.card_rule_set_ref_id
            )),
            delegation_id: None,
            operation_id: "e2e-op-placeholder".to_owned(),
            event_id: None,
            actor_user_id: Some(namespace.user_id),
        },
    }
}

/// 以最小正确方式构造该卡已发布的 evidence：公共
/// stage → claim lease → finalize → publish API，各自独立短事务。
async fn publish_card_manifest(pool: &MySqlPool, namespace: &TestNamespace) {
    let identity =
        ProjectionAggregateIdentity::new(namespace.tenant_id, AGGREGATE_TYPE, namespace.card_id)
            .expect("fixture card aggregate identity must be valid");
    let event_id = format!("ev-e2e-{salt:032x}-gen1", salt = namespace.salt);
    let operation_id = format!("op-e2e-{salt:032x}-gen1", salt = namespace.salt);
    let semantic_hash_hex = sha256_hex(&format!("e2e/{}/semantic", namespace.tenant_id));
    let dependency_hash_hex = sha256_hex(&format!("e2e/{}/dependency", namespace.tenant_id));
    let compiler_version = "e2e-itest-v1".to_owned();

    let mut payload_grants = vec![allow_rule_set_grant(namespace)];
    for grant in &mut payload_grants {
        grant.provenance.operation_id = operation_id.clone();
        grant.provenance.event_id = Some(event_id.clone());
    }

    let stage_request = AuthorizationStageRequest {
        identity: identity.clone(),
        card_id: Some(namespace.card_id),
        target_generation: 1,
        source_generation: 1,
        projected_generation: 1,
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

    let mut tx = pool.begin().await.unwrap();
    let lease = claim_authorization_manifest_in_tx(
        &mut tx,
        &identity,
        1,
        "e2e-itest-worker",
        MANIFEST_LEASE_SECONDS,
    )
    .await
    .unwrap()
    .expect("the staged BUILDING manifest must be claimable right after staging");
    tx.commit().await.unwrap();
    assert_eq!(lease.manifest_id, stage_outcome.manifest_id);

    let finalize_request = AuthorizationFinalizeRequest {
        identity: identity.clone(),
        target_generation: 1,
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
        card_id: Some(namespace.card_id),
        target_manifest_id: stage_outcome.manifest_id,
        target_generation: 1,
        current_pointer: None,
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
    assert!(outcome.initialized_first_pointer);
    assert_eq!(outcome.pointer.current_generation, 1);
    assert_eq!(outcome.pointer.manifest_id, stage_outcome.manifest_id);
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
    publish_card_manifest(&pool, &namespace).await;

    let repo = SqlxRuleRepository::new(pool.clone());
    assert!(
        repo.requires_published_card_evidence(),
        "production repository must declare the strict published-evidence gate"
    );

    // ── 正式 L1：published-card evidence strict gate（旧 load_snapshot_winners
    //    已退役，本端口是其正式继任者）。Ready + 期望授权集。──
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
    assert_eq!(
        grant.provenance.binding_id,
        Some(format!(
            "card-rule-set-ref:{}",
            namespace.card_rule_set_ref_id
        ))
    );

    // ── 无 evidence 的卡：fail-closed 为 NotReady → PENDING 词表，绝不产生
    //    empty-ALLOW。──
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

    // ── 正式 L2：无 CARD head（旧 authorization_projection_head 零写入）时
    //    gate 不可读，保持空集；绝不回读上面的 MANUAL source permission_rule。──
    let rules = repo.load_permission_rules(namespace.card_id).await.unwrap();
    assert!(
        rules.is_empty(),
        "formal permission loader must not fall back to permission_rule"
    );

    let gate = repo
        .get_projection_gate(namespace.card_id)
        .await
        .unwrap()
        .expect("gate reader must return an explicit state, not None");
    assert!(
        !gate.ready,
        "a card without a projection head must be explicitly not ready (AUTHORIZATION_PENDING)"
    );
    assert_eq!(gate.source_generation, 0);

    // ── raw oracle 读取器（一致性巡检专用）仍能看到 source 行。──
    let raw_rules = repo
        .load_permission_rules_raw(namespace.card_id)
        .await
        .unwrap();
    assert_eq!(
        raw_rules.len(),
        1,
        "raw oracle must see the MANUAL source row"
    );
    assert_eq!(raw_rules[0].effect, Effect::Deny);
    assert_eq!(raw_rules[0].resource, "audit");
    assert_eq!(raw_rules[0].action, "delete");

    let raw_entries = repo
        .load_rule_set_entries_raw(namespace.card_id)
        .await
        .unwrap();
    assert_eq!(
        raw_entries.len(),
        1,
        "raw oracle must see the rule set entry"
    );
    assert_eq!(raw_entries[0].rule_set_id, namespace.rule_set_id);
    assert_eq!(raw_entries[0].ref_type, "BASE");
    assert_eq!(raw_entries[0].entries.len(), 1);
    assert_eq!(raw_entries[0].entries[0].effect, Effect::Allow);
    assert_eq!(
        raw_entries[0].entries[0].resource.as_deref(),
        Some("learn_subject:*")
    );
    assert_eq!(raw_entries[0].entries[0].action.as_deref(), Some("read"));

    cleanup_namespace(&pool).await;
}
