//! Rust 自有授权投影链（`astral_db::authorization_projection_repository`）的
//! MySQL 集成测试。
//!
//! # 前置条件（只读校验，绝不执行临时 DDL）
//!
//! - 需要可访问的 MySQL 8.0 测试数据库，且 Rust 自有迁移已经应用：
//!   `20260825000002_incremental_projection_archive.sql` 与
//!   `20260827000001_authorization_projection_lineage_fence.sql` 建立的
//!   `authorization_projection_*` / `authorization_archive_*` 表及
//!   lineage/revoke-fence 列。
//! - 连接与 schema 契约通过 `astral_db::connect_and_validate_schema` 做只读
//!   预检（不执行任何 DDL）；本文件再显式检查六张投影表存在。表缺失时按
//!   迁移未应用处理：默认显式 `[SKIP]`；`RUST_INTEGRATION_REQUIRED=1` 时
//!   panic（`[SKIP]` 不算 PASS）。
//!
//! # 运行方式
//!
//! `cargo test --test authorization_projection_integration -- --ignored`
//!
//! # 隔离与清理
//!
//! 每个测试用独立的随机 tenant/card/aggregate 命名空间（uuid 派生的大整数），
//! 清理只删除本命名空间 `tenant_id` 下的行；`event_id`/`operation_id` 携带
//! uuid salt，保证跨运行、跨测试的全局唯一键（如 `uk_aao_event`）不冲突。
//! 测试不触碰 delta/impact-plan/revision 表，因此无需清理它们。
//!
//! # 覆盖范围
//!
//! 1. 严格发布证据读取器在无 current 指针时 fail-closed 为 `NotReady`
//!    （聚合级 + 卡级），并映射为 `Pending` gate（PENDING/DENY），绝不产生
//!    空/等价授权集合。
//! 2. stage → claim lease → finalize → publish 的 happy path（两代增量），
//!    含 lineage `parent_manifest_id`、严格链回读与卡级证据 `Ready` 读取。
//! 3. 两个并发竞争发布恰好一个 CAS 赢家；败者得到显式冲突
//!    （`publish_promotion_race` / `first_pointer_race` /
//!    `publish_expected_first_but_pointer_exists`）或引擎判定的死锁
//!    （模块文档规定的可整事务重试中止）；另含三个确定性 CAS 败者场景。
//! 4. 归档链路：gen2 发布事务在指针 CAS 之前为仍被 live proof-bearing pointer
//!    指向的 gen1 追加 archive intent（新契约：NEW intent 只能在指针 CAS 前、
//!    live pointer 仍指向父代时创建；与生产编排
//!    `project_authorization_delta_in_tx` 的 (6)→(7) 步同构）→ CAS 后仅允许
//!    同值重放 resume 同一行 → lease claim（活租约不可抢占）→ heartbeat 只
//!    延长租期、绝不触碰 status/attempts/cas_version → 错误 chain digest
//!    拒绝 → durable proof 落库 → 错误租约身份拒绝 → 凭租约完成 `SUCCEEDED`
//!    （先 durable proof 后终态写）。
//! 5. archive intent 父/指针证明（parent/pointer proof）：NEW intent 只能证
//!    明于 live pointer——`archived_revoke_fence` / `event_id` / semantic
//!    hash 与父 manifest 任一不匹配都以
//!    `archive_intent_parent_mismatch;dimension=<dimension>` 在同一事务内
//!    显式拒绝；live pointer 已指向新一代时，为已取代且从无 intent 的父代
//!    补建 NEW intent 以
//!    `archive_intent_pointer_mismatch;dimension=archived_manifest_id` 拒绝；
//!    两者都发生在任何 outbox 写入之前（同事务内 outbox 行数不变）。随后
//!    同一命名空间的合法请求仍走既有幂等写入流（CAS 前 insert → 同值重放
//!    resume 同一行）。
//! 6. source-freshness 门（发布完成前越权修复）：卡作用域存在非 `SUCCEEDED`
//!    delta（注入合成 PENDING 行）→ 严格证据读 `NotReady`（PENDING 语义，
//!    机器码 `source_freshness_pending`）；SUCCEEDED 后恢复 Ready；
//!    QUARANTINED 持续拦截（fail-closed，人工对账前不放行旧代）。
//! 7. source-freshness 门的 aggregate-wide 覆盖（2026-09-04 探针修订）：
//!    `card_id IS NULL` 的未发布撤权类 delta（REMOVE/REVOKE 或 fence 超前
//!    NULL-card 已发布水位）同样拦截任一卡的严格证据读；已被 NULL-card
//!    已发布水位覆盖的 PENDING UPDATE delta 不误报（NULL-safe `<=>` 水位
//!    关联，普通 `=` 会把 NULL 水位折叠成 0 造成误报）。
//! 8. 收窄 UPDATE 的 stale-ALLOW 闭合（2026-09-04，astral-db owner 侧机制）：
//!    经真实仓储写入器（`append_projection_event_with_metadata_and_tenant_in_tx`
//!    的 REVOKE kind → `authorization_projection_head.revoke_fence` 递增 +
//!    `append_delta_event` 的 UPDATE delta 绑定抬升后 fence）在未发布窗口
//!    触发 `source_freshness_pending`，delta SUCCEEDED 后恢复 Ready；同时
//!    证明中性 UPDATE delta（fence 未抬升）不触发该门。
//!
//! # 已知未覆盖（blocked，不伪造）
//!
//! - `project_authorization_delta_in_tx` 组合编排：需要先经
//!   `grant_repository` 写入合法 delta event / impact plan（head/outbox
//!   契约属于另一 owner 的聚合契约），公共 API 上无法在不伪造 source
//!   mutation 的情况下安全组装；由其 owner 模块测试负责。
//! - 外部对象存储/GC：本模块明确只落 DB 内 rehearsal proof，不实现外部
//!   备份，因此不存在也不应伪造外部成功断言。
//! - "authorization-content 变化 → REVOKE kind" 的判定本身位于
//!   astral-trustgraph 三条 UPDATE 链路（direct rule / rule-set entry /
//!   delegation，跨 crate）：astral-db 集成测试只证明 owner 侧机制链
//!   （fence 抬升 → delta → 门 → 恢复），判定逻辑由 trustgraph 侧
//!   结构守卫与纯单测覆盖。

use astral_db::{
    append_delta_event, append_projection_event_with_metadata_and_tenant_in_tx,
    claim_authorization_manifest_in_tx, claim_next_authorization_archive_intent_in_tx,
    claim_next_delta_event_in_tx, complete_authorization_archive_intent,
    connect_and_validate_schema, derive_archive_key, ensure_authorization_archive_intent_in_tx,
    fail_delta_event, finalize_authorization_manifest_in_tx,
    heartbeat_authorization_archive_intent_lease, load_authorization_archive_intent_in_tx,
    load_authorization_recovery_state_in_tx, load_card_scope_fence_snapshot,
    load_published_card_grant_evidence, load_published_card_grant_evidence_in_tx,
    publish_current_pointer_in_tx, read_published_authorization_state_in_tx,
    record_authorization_archive_proof_in_tx, stage_authorization_manifest_in_tx,
    ArchiveLeaseProof, AuthorizationArchiveIntentAppendRequest, AuthorizationArchiveIntentOutcome,
    AuthorizationArchiveManifestStatus, AuthorizationArchiveOutboxStatus,
    AuthorizationArchiveProofRequest, AuthorizationEvidenceError, AuthorizationFinalizeRequest,
    AuthorizationProjectionError, AuthorizationPublishOutcome, AuthorizationPublishRequest,
    AuthorizationStageRequest, CurrentPointerView, DeltaEventAppendRequest, DeltaEventClaimScope,
    DeltaEventType, DeltaLeaseIdentity, ProjectionAggregateIdentity, ProjectionEventMetadata,
    PublishRevokeFenceEvidence, Sha256Digest, StagedSegmentContent,
};
use astral_types::{
    BindingLayer, CanonicalGrant, DomainScopeRequirement, GrantDelta, GrantEffect, GrantId,
    GrantProvenance, GrantRevision, GrantSourceKind, GrantState, ProjectionAggregate,
    PublishedCardEvidenceScope, PublishedEvidenceGateStatus, TenantScope, ValidityWindow,
    EVENT_TYPE_REVOKE,
};
use sha2::{Digest, Sha256};
use sqlx::{MySql, MySqlPool, Transaction};
use time::PrimitiveDateTime;
use uuid::Uuid;

/// Rust 自有投影/归档表；六张表全部存在才允许执行，否则视为迁移未应用。
const REQUIRED_PROJECTION_TABLES: &[&str] = &[
    "authorization_projection_manifest",
    "authorization_projection_segment",
    "authorization_projection_manifest_segment",
    "authorization_projection_current",
    "authorization_archive_outbox",
    "authorization_archive_manifest",
];

/// 本测试使用的聚合类型：既是合法标识符，也属于卡级证据读取器接受的类型集。
const AGGREGATE_TYPE: &str = "USER_CARD";

const MANIFEST_LEASE_SECONDS: i64 = 600;
const ARCHIVE_LEASE_SECONDS: i64 = 600;

// ─────────────────────────────────────────────────────────────────────────────
// 环境门禁与命名空间
// ─────────────────────────────────────────────────────────────────────────────

/// 连接数据库并完成只读 schema 预检。未设置 `DATABASE_URL`、连接/schema
/// 校验失败或投影表缺失时默认显式 `[SKIP]`；`RUST_INTEGRATION_REQUIRED=1`
/// 仅将这些前置失败转换为 panic，不会解除 `#[ignore]`。
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

    // 显式要求 Rust 自有投影/归档迁移（20260825000002 + 20260827000001）
    // 已经应用；本测试不执行任何临时 DDL，表缺失只能跳过或 panic。
    let mut missing = Vec::new();
    for table in REQUIRED_PROJECTION_TABLES {
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
            "Rust-owned authorization projection tables are missing (migrations \
             20260825000002/20260827000001 not applied): {missing:?}"
        );
        if required {
            panic!("RUST_INTEGRATION_REQUIRED=1: {message}");
        }
        eprintln!("[SKIP] {message}");
        return None;
    }

    Some(pool)
}

/// 独立随机测试命名空间：uuid 派生的大整数，保证跨运行/跨测试互不冲突。
struct TestNamespace {
    label: &'static str,
    salt: u128,
    tenant_id: i64,
    card_id: i64,
    aggregate_id: i64,
    user_id: i64,
    domain_id: i64,
}

impl TestNamespace {
    fn new(label: &'static str) -> Self {
        let salt = Uuid::new_v4().as_u128();
        // 8e12 起步、步长 1e5 的稀疏大整数区间，远离真实业务 id。
        let base = 8_000_000_000_000_i64 + ((salt % 1_000_000_000) as i64) * 100_000;
        Self {
            label,
            salt,
            tenant_id: base,
            card_id: base + 1,
            aggregate_id: base + 2,
            user_id: base + 3,
            domain_id: base + 4,
        }
    }

    fn identity(&self) -> ProjectionAggregateIdentity {
        ProjectionAggregateIdentity::new(self.tenant_id, AGGREGATE_TYPE, self.aggregate_id)
            .expect("test namespace identity must be valid")
    }

    fn evidence_scope(&self) -> PublishedCardEvidenceScope {
        PublishedCardEvidenceScope {
            tenant_id: self.tenant_id,
            card_id: self.card_id,
            user_filter: None,
            domain: DomainScopeRequirement::ExactlySome(self.domain_id),
        }
    }

    /// 全局唯一的事件/操作标识（`uk_aao_event` 等全局唯一键的安全来源）。
    fn event_id(&self, tag: &str) -> String {
        format!("ev-{}-{salt:032x}-{tag}", self.label, salt = self.salt)
    }

    fn operation_id(&self, tag: &str) -> String {
        format!("op-{}-{salt:032x}-{tag}", self.label, salt = self.salt)
    }
}

/// 只删除本命名空间 `tenant_id` 下的行；先子后父（无外键，纯防御顺序）。
/// `authorization_delta_event` 行由 source mutation owner 写入；本文件的
/// source-freshness 门测试会注入合成 delta，清理列表一并覆盖（按 tenant
/// 命名空间删除对其它测试的合成行同样安全）。source-freshness/收窄 UPDATE
/// 测试还会经真实仓储写入器落 `authorization_projection_outbox`（tenant
/// 可覆盖捕获）与 `authorization_projection_head`（无 tenant 列，按本命名
/// 空间使用过的 aggregate id 清理）；head/outbox 行清理不影响其它测试
/// （aggregate id 属于本命名空间独占区间）。
async fn cleanup_namespace(pool: &MySqlPool, namespace: &TestNamespace) {
    for statement in [
        "DELETE FROM authorization_archive_manifest WHERE tenant_id = ?",
        "DELETE FROM authorization_archive_outbox WHERE tenant_id = ?",
        "DELETE FROM authorization_projection_current WHERE tenant_id = ?",
        "DELETE FROM authorization_projection_manifest_segment WHERE tenant_id = ?",
        "DELETE FROM authorization_projection_segment WHERE tenant_id = ?",
        "DELETE FROM authorization_projection_manifest WHERE tenant_id = ?",
        "DELETE FROM authorization_delta_event WHERE tenant_id = ?",
        "DELETE FROM authorization_projection_outbox WHERE tenant_id = ?",
    ] {
        sqlx::query(statement)
            .bind(namespace.tenant_id)
            .execute(pool)
            .await
            .unwrap();
    }
    // head 表没有 tenant 列：按本命名空间使用过的 aggregate id（CARD 承载卡
    // 与卡级聚合）清理，避免残留行跨运行累积。
    for aggregate_id in [namespace.card_id, namespace.aggregate_id] {
        sqlx::query(
            "DELETE FROM authorization_projection_head \
             WHERE aggregate_type = ? AND aggregate_id = ?",
        )
        .bind("CARD")
        .bind(aggregate_id)
        .execute(pool)
        .await
        .unwrap();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 构造辅助
// ─────────────────────────────────────────────────────────────────────────────

fn sha256_hex(label: &str) -> String {
    hex::encode(Sha256::digest(label.as_bytes()))
}

/// 构造一条处于规范形（canonical）的 ALLOW/ACTIVE 永久授权。
/// `unique_tail` 只能使用低 12 位，与命名空间 salt 共同派生全局唯一 GrantId。
/// provenance 的 operation/event 由 [`stage_and_finalize_manifest`] 对齐后填入。
fn test_grant(namespace: &TestNamespace, unique_tail: u16) -> CanonicalGrant {
    assert!(
        unique_tail <= 0x0FFF,
        "tail must fit the 12 hex digit field"
    );
    let entropy = (namespace.salt & 0xFFFF_FFFF_F000) | u128::from(unique_tail);
    CanonicalGrant {
        grant_id: GrantId::parse(&format!("550e8400-e29b-41d4-a716-{entropy:012x}"))
            .expect("test grant id must be a valid UUID"),
        revision: GrantRevision::initial(),
        state: GrantState::Active,
        source_kind: GrantSourceKind::RuleSet,
        binding_layer: BindingLayer::Base,
        tenant: TenantScope::new(namespace.tenant_id, Some(namespace.domain_id))
            .expect("test tenant scope must be valid"),
        card_id: namespace.card_id,
        user_id: namespace.user_id,
        resource: format!("itest_resource:{}", namespace.aggregate_id),
        action: "read".to_owned(),
        effect: GrantEffect::Allow,
        validity: ValidityWindow::perpetual(),
        provenance: GrantProvenance {
            source_id: format!("itest-rule-set-entry-{unique_tail}"),
            source_entry: None,
            binding_id: Some(format!("itest-binding-{}", namespace.card_id)),
            delegation_id: None,
            operation_id: "itest-op-placeholder".to_owned(),
            event_id: None,
            actor_user_id: Some(namespace.user_id),
        },
    }
}

/// 一个已完成 stage（BUILDING）→ claim lease → finalize（READY）的 manifest，
/// 及其发布所需的调用方证据（编译哈希）与实际入段载荷。
struct ReadyManifest {
    manifest_id: i64,
    manifest_digest: Sha256Digest,
    semantic_hash_hex: String,
    dependency_hash_hex: String,
    compiler_version: String,
    event_id: String,
    operation_id: String,
    /// 实际写入 segment 的载荷（provenance 与 manifest 对齐后的 grant）。
    payload_grants: Vec<CanonicalGrant>,
}

/// stage + claim + finalize，各自独立短事务并提交，对应真实 worker 的分步。
/// 编译侧全局哈希由测试以确定性 SHA-256 派生（真实编译输出由上层负责）。
async fn stage_and_finalize_manifest(
    pool: &MySqlPool,
    namespace: &TestNamespace,
    generation: u64,
    grants: &[CanonicalGrant],
    tag: &str,
) -> ReadyManifest {
    let identity = namespace.identity();
    let event_id = namespace.event_id(tag);
    let operation_id = namespace.operation_id(tag);
    let semantic_hash_hex = sha256_hex(&format!("itest/{}/semantic/{tag}", namespace.tenant_id));
    let dependency_hash_hex =
        sha256_hex(&format!("itest/{}/dependency/{tag}", namespace.tenant_id));
    let compiler_version = "itest-compiler-v1".to_owned();

    // 与载荷 provenance 保持一致：grant 的 operation/event 与 manifest 对齐。
    let mut payload_grants = grants.to_vec();
    for grant in &mut payload_grants {
        grant.provenance.operation_id = operation_id.clone();
        grant.provenance.event_id = Some(event_id.clone());
    }

    let stage_request = AuthorizationStageRequest {
        identity: identity.clone(),
        card_id: Some(namespace.card_id),
        target_generation: generation,
        source_generation: generation,
        projected_generation: generation,
        event_id: event_id.clone(),
        operation_id: operation_id.clone(),
        semantic_hash_hex: semantic_hash_hex.clone(),
        dependency_hash_hex: dependency_hash_hex.clone(),
        compiler_version: compiler_version.clone(),
        revoke_fence: 0,
        segments: vec![StagedSegmentContent::New(payload_grants.clone())],
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
    assert_eq!(stage_outcome.new_segment_count, 1);
    assert_eq!(stage_outcome.reused_segment_count, 0);
    assert_eq!(stage_outcome.total_grant_count, grants.len() as u64);
    assert_eq!(stage_outcome.target_generation, generation);
    if generation == 1 {
        assert!(
            stage_outcome.base_pointer.is_none(),
            "first generation must observe no current pointer"
        );
    } else {
        let pointer = stage_outcome
            .base_pointer
            .expect("later generations must observe the current pointer");
        assert_eq!(pointer.current_generation, generation - 1);
    }

    let lease_owner = format!("itest-manifest-owner-{tag}");
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
    assert_eq!(lease.manifest_id, stage_outcome.manifest_id);
    assert_eq!(lease.generation, generation);
    assert_eq!(lease.identity, identity);

    let finalize_request = AuthorizationFinalizeRequest {
        identity: identity.clone(),
        target_generation: generation,
        manifest_id: stage_outcome.manifest_id,
        lease_owner: lease.lease_owner.clone(),
        lease_token: lease.lease_token,
        expected_cas_version: lease.cas_version_after_claim,
        expected_reference_count: Some(1),
    };
    finalize_authorization_manifest_in_tx(&mut tx, &finalize_request)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    ReadyManifest {
        manifest_id: stage_outcome.manifest_id,
        manifest_digest: stage_outcome.manifest_digest,
        semantic_hash_hex,
        dependency_hash_hex,
        compiler_version,
        event_id,
        operation_id,
        payload_grants,
    }
}

/// 在独立事务中执行一次已构造好的发布请求；成功提交、失败回滚。
async fn run_publish_request(
    pool: &MySqlPool,
    request: &AuthorizationPublishRequest,
) -> Result<AuthorizationPublishOutcome, AuthorizationProjectionError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(AuthorizationProjectionError::from)?;
    match publish_current_pointer_in_tx(&mut tx, request).await {
        Ok(outcome) => {
            tx.commit()
                .await
                .map_err(AuthorizationProjectionError::from)?;
            Ok(outcome)
        }
        Err(error) => {
            let _ = tx.rollback().await;
            Err(error)
        }
    }
}

/// 组装一次标准 fence 0→0 的发布请求（不执行）；供顺序场景与
/// “CAS 前追加 intent + 发布”组合事务共用。
fn publish_request_for(
    namespace: &TestNamespace,
    manifest: &ReadyManifest,
    generation: u64,
    current_pointer: Option<CurrentPointerView>,
) -> AuthorizationPublishRequest {
    AuthorizationPublishRequest {
        identity: namespace.identity(),
        card_id: Some(namespace.card_id),
        target_manifest_id: manifest.manifest_id,
        target_generation: generation,
        current_pointer,
        expected_target_semantic_hash_hex: manifest.semantic_hash_hex.clone(),
        expected_target_dependency_hash_hex: manifest.dependency_hash_hex.clone(),
        expected_target_compiler_version: manifest.compiler_version.clone(),
        // 所有测试代均发布 fence 0→0（无 revoke 观察），与指针权威一致。
        fences: PublishRevokeFenceEvidence {
            previous_revoke_fence: 0,
            new_revoke_fence: 0,
        },
    }
}

/// 组装一次标准 fence 0→0 的发布请求并执行；供顺序场景使用。
async fn publish_ready_manifest(
    pool: &MySqlPool,
    namespace: &TestNamespace,
    manifest: &ReadyManifest,
    generation: u64,
    current_pointer: Option<CurrentPointerView>,
) -> Result<AuthorizationPublishOutcome, AuthorizationProjectionError> {
    run_publish_request(
        pool,
        &publish_request_for(namespace, manifest, generation, current_pointer),
    )
    .await
}

/// 单事务组合：先为仍被 live proof-bearing pointer 指向的父代追加 archive
/// intent（新契约：NEW intent 只能在指针 CAS 之前、live pointer 仍指向父代时
/// 创建），再在同一事务内执行新一代发布的指针 CAS；与生产编排
/// `project_authorization_delta_in_tx` 的 (6)→(7) 步同构。任一步失败即回滚
/// 整个事务（intent 与指针原子同折）。
async fn append_archive_intent_then_publish_in_tx(
    pool: &MySqlPool,
    intent_request: &AuthorizationArchiveIntentAppendRequest,
    publish_request: &AuthorizationPublishRequest,
) -> Result<
    (
        AuthorizationArchiveIntentOutcome,
        AuthorizationPublishOutcome,
    ),
    AuthorizationProjectionError,
> {
    let mut tx = pool
        .begin()
        .await
        .map_err(AuthorizationProjectionError::from)?;
    let intent = match ensure_authorization_archive_intent_in_tx(&mut tx, intent_request).await {
        Ok(outcome) => outcome,
        Err(error) => {
            let _ = tx.rollback().await;
            return Err(error);
        }
    };
    let publish = match publish_current_pointer_in_tx(&mut tx, publish_request).await {
        Ok(outcome) => outcome,
        Err(error) => {
            let _ = tx.rollback().await;
            return Err(error);
        }
    };
    tx.commit()
        .await
        .map_err(AuthorizationProjectionError::from)?;
    Ok((intent, publish))
}

/// 本命名空间在 `authorization_archive_outbox` 中的行数（调用方事务内可见）。
async fn outbox_row_count(tx: &mut Transaction<'_, MySql>, namespace: &TestNamespace) -> i64 {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM authorization_archive_outbox \
         WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ?",
    )
    .bind(namespace.tenant_id)
    .bind(AGGREGATE_TYPE)
    .bind(namespace.aggregate_id)
    .fetch_one(&mut **tx)
    .await
    .unwrap();
    count
}

/// 并发竞争的合法败者结果集合：显式 CAS/发布冲突，或引擎判定的死锁
/// （模块文档规定的“调用方按整事务可重试失败处理”路径）。其余一律失败。
fn assert_loser_is_explicit_conflict(error: &AuthorizationProjectionError) {
    match error {
        AuthorizationProjectionError::CurrentPointerCasConflict(message) => {
            assert!(
                message.contains("first_pointer_race")
                    || message.contains("publish_expected_pointer_but_missing"),
                "unexpected current-pointer CAS conflict code: {message}"
            );
        }
        AuthorizationProjectionError::ManifestPublishConflict(message) => {
            assert!(
                message.contains("publish_expected_first_but_pointer_exists")
                    || message.contains("publish_promotion_race"),
                "unexpected manifest publish conflict code: {message}"
            );
        }
        AuthorizationProjectionError::Query(sqlx::Error::Database(database)) => {
            let code = database.code().unwrap_or_default();
            let deadlock = code == "1213" || code == "40001" || database.message().contains("Deadlock");
            assert!(
                deadlock,
                "racing publisher hit an unexpected database error: {database}"
            );
        }
        other => panic!(
            "racing publisher failed with an unexpected error (must be an explicit CAS/conflict): {other:?}"
        ),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// (1) 无 current 指针时严格读取器 fail-closed
// ─────────────────────────────────────────────────────────────────────────────

/// 严格发布证据读取器在没有任何 current 指针时必须返回显式 `NotReady`，
/// 绝不产生空/等价的授权集合；卡级读取器映射到 `Pending` gate（PENDING/DENY）。
#[ignore]
#[tokio::test]
async fn published_evidence_reader_fails_closed_without_current_pointer() {
    let Some(pool) = connect().await else {
        return;
    };
    let namespace = TestNamespace::new("no_pointer");
    cleanup_namespace(&pool, &namespace).await;

    let identity = namespace.identity();

    // 聚合级严格读取器：指针缺失 → NotReady（稳定代码 current_pointer_missing）。
    {
        let mut tx = pool.begin().await.unwrap();
        let error = read_published_authorization_state_in_tx(&mut tx, &identity)
            .await
            .unwrap_err();
        tx.rollback().await.unwrap();
        match error {
            AuthorizationProjectionError::NotReady(message) => {
                assert!(
                    message.contains("current_pointer_missing"),
                    "unexpected NotReady code: {message}"
                );
            }
            other => {
                panic!("aggregate strict reader must be NotReady without a pointer, got: {other:?}")
            }
        }
    }

    // 卡级严格读取器：范围内没有任何指针行 → NotReady，且映射 Pending。
    {
        let scope = namespace.evidence_scope();
        let mut tx = pool.begin().await.unwrap();
        let error = load_published_card_grant_evidence_in_tx(&mut tx, &scope)
            .await
            .unwrap_err();
        tx.rollback().await.unwrap();
        match &error {
            AuthorizationEvidenceError::NotReady(message) => {
                assert!(
                    message.contains("current_pointer_missing"),
                    "unexpected NotReady code: {message}"
                );
            }
            other => panic!("card strict reader must be NotReady without pointers, got: {other:?}"),
        }
        assert_eq!(
            error.as_gate_status(),
            PublishedEvidenceGateStatus::Pending,
            "missing durable evidence must map to the PENDING/DENY vocabulary"
        );
    }

    // pool 级包装（自带短事务提交）同样必须 NotReady。
    {
        let error = load_published_card_grant_evidence(&pool, &namespace.evidence_scope())
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            AuthorizationEvidenceError::NotReady(ref message) if message.contains("current_pointer_missing")
        ));
    }

    // 恢复读取器：该代完全不存在是诊断性 Ok(None)，不是 corrupt。
    {
        let mut tx = pool.begin().await.unwrap();
        let recovery = load_authorization_recovery_state_in_tx(&mut tx, &identity, 1)
            .await
            .unwrap();
        tx.rollback().await.unwrap();
        assert!(recovery.is_none());
    }

    cleanup_namespace(&pool, &namespace).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// (2) stage → claim → finalize → publish happy path（两代 + 严格回读）
// ─────────────────────────────────────────────────────────────────────────────

/// 第一代首次发布（初始化指针）与第二代增量发布（lineage 指回第一代）的
/// 完整 happy path；随后严格单聚合回读与卡级证据读取全部 `Ready`。
#[ignore]
#[tokio::test]
async fn stage_finalize_publish_round_trip_yields_strict_card_evidence() {
    let Some(pool) = connect().await else {
        return;
    };
    let namespace = TestNamespace::new("happy_path");
    cleanup_namespace(&pool, &namespace).await;

    let identity = namespace.identity();

    // ── 第一代：一个新 segment，两条 grant ──
    let gen1 = stage_and_finalize_manifest(
        &pool,
        &namespace,
        1,
        &[test_grant(&namespace, 1), test_grant(&namespace, 2)],
        "gen1",
    )
    .await;

    let outcome1 = publish_ready_manifest(&pool, &namespace, &gen1, 1, None)
        .await
        .expect("first publication with a READY manifest and no pointer must succeed");
    assert!(outcome1.initialized_first_pointer);
    assert_eq!(outcome1.previous_superseded_manifest_id, None);
    assert_eq!(outcome1.published_manifest_id, gen1.manifest_id);
    assert_eq!(outcome1.pointer.manifest_id, gen1.manifest_id);
    assert_eq!(outcome1.pointer.current_generation, 1);
    assert_eq!(outcome1.pointer.card_id, Some(namespace.card_id));
    assert_eq!(outcome1.pointer.revoke_fence, 0);

    // 严格单聚合回读：指针/manifest/引用/segment 全链在事务内验证。
    {
        let mut tx = pool.begin().await.unwrap();
        let state = read_published_authorization_state_in_tx(&mut tx, &identity)
            .await
            .unwrap();
        tx.rollback().await.unwrap();
        assert_eq!(state.pointer, outcome1.pointer);
        assert_eq!(state.generation, 1);
        assert_eq!(state.parent_manifest_id, None);
        assert_eq!(state.revoke_fence, 0);
        assert_eq!(state.references.len(), 1);
        assert_eq!(state.references[0].generation, 1);
        assert_eq!(state.segments.len(), 1);
        assert_eq!(state.segments[0].grants, gen1.payload_grants);
        assert_eq!(state.total_grant_count, 2);
    }

    // ── 第二代：真实增量（新内容），lineage 必须指向第一代 ──
    let gen2 =
        stage_and_finalize_manifest(&pool, &namespace, 2, &[test_grant(&namespace, 3)], "gen2")
            .await;

    let outcome2 = publish_ready_manifest(
        &pool,
        &namespace,
        &gen2,
        2,
        Some(outcome1.pointer.as_view()),
    )
    .await
    .expect("second publication with the locked pointer view must succeed");
    assert!(!outcome2.initialized_first_pointer);
    assert_eq!(
        outcome2.previous_superseded_manifest_id,
        Some(gen1.manifest_id)
    );
    assert_eq!(outcome2.pointer.current_generation, 2);
    assert_eq!(outcome2.pointer.manifest_id, gen2.manifest_id);
    assert_eq!(outcome2.pointer.revoke_fence, 0);

    {
        let mut tx = pool.begin().await.unwrap();
        let state = read_published_authorization_state_in_tx(&mut tx, &identity)
            .await
            .unwrap();
        tx.rollback().await.unwrap();
        assert_eq!(state.pointer, outcome2.pointer);
        assert_eq!(state.generation, 2);
        assert_eq!(state.parent_manifest_id, Some(gen1.manifest_id));
        assert_eq!(state.segments[0].grants, gen2.payload_grants);
        assert_eq!(state.total_grant_count, 1);
    }

    // ── 卡级严格证据：Ready，生效集合只有第二代的 grant ──
    let evidence = load_published_card_grant_evidence(&pool, &namespace.evidence_scope())
        .await
        .expect("published card evidence must be Ready after a clean publication chain");
    assert_eq!(evidence.tenant_id, namespace.tenant_id);
    assert_eq!(evidence.card_id, namespace.card_id);
    assert_eq!(evidence.gate.status, PublishedEvidenceGateStatus::Ready);
    assert_eq!(evidence.gate.aggregate_manifest_count, 1);
    assert_eq!(evidence.gate.verified_record_count, 1);
    assert_eq!(evidence.gate.effective_grant_count, 1);
    assert_eq!(evidence.gate.not_in_effective_count, 0);
    assert_eq!(evidence.gate.equivalent_duplicate_collapsed_count, 0);
    assert_eq!(evidence.manifests.len(), 1);
    assert_eq!(evidence.manifests[0].generation, 2);
    assert_eq!(evidence.manifests[0].manifest_id, gen2.manifest_id);
    assert_eq!(
        evidence.manifests[0].parent_manifest_id,
        Some(gen1.manifest_id)
    );
    assert_eq!(evidence.manifests[0].declared_grant_row_count, 1);
    assert_eq!(evidence.effective_grants, gen2.payload_grants);
    assert_eq!(evidence.records.len(), 1);
    assert!(evidence.records[0].accepted_into_effective_set);

    cleanup_namespace(&pool, &namespace).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// (3) 并发竞争发布：恰好一个 CAS 赢家 + 确定性败者
// ─────────────────────────────────────────────────────────────────────────────

/// 两个 worker 并发执行同一 READY manifest 的首次发布：恰好一个赢家持有
/// durable 指针；败者得到显式 CAS/发布冲突或引擎死锁（可整事务重试）。
/// 随后补三个确定性败者：陈旧指针视图、首发布重放、已 COMMITTED 目标。
#[ignore]
#[tokio::test]
async fn competing_publications_admit_exactly_one_cas_winner() {
    let Some(pool) = connect().await else {
        return;
    };
    let namespace = TestNamespace::new("publish_race");
    cleanup_namespace(&pool, &namespace).await;

    let identity = namespace.identity();
    let manifest = stage_and_finalize_manifest(
        &pool,
        &namespace,
        1,
        &[test_grant(&namespace, 11), test_grant(&namespace, 12)],
        "race",
    )
    .await;

    // ── 并发阶段：同一请求、两个独立连接/事务 ──
    let request_a = AuthorizationPublishRequest {
        identity: identity.clone(),
        card_id: Some(namespace.card_id),
        target_manifest_id: manifest.manifest_id,
        target_generation: 1,
        current_pointer: None,
        expected_target_semantic_hash_hex: manifest.semantic_hash_hex.clone(),
        expected_target_dependency_hash_hex: manifest.dependency_hash_hex.clone(),
        expected_target_compiler_version: manifest.compiler_version.clone(),
        fences: PublishRevokeFenceEvidence {
            previous_revoke_fence: 0,
            new_revoke_fence: 0,
        },
    };
    let request_b = request_a.clone();
    let pool_a = pool.clone();
    let pool_b = pool.clone();
    let (first, second) = tokio::join!(
        async move { run_publish_request(&pool_a, &request_a).await },
        async move { run_publish_request(&pool_b, &request_b).await },
    );

    let (winner, loser) = match (first, second) {
        (Ok(winner), Err(loser)) | (Err(loser), Ok(winner)) => (winner, loser),
        (Ok(_), Ok(_)) => panic!(
            "two concurrent first publications both succeeded; exactly-one-winner invariant broken"
        ),
        (Err(a), Err(b)) => panic!("both concurrent publications failed: {a:?} / {b:?}"),
    };
    assert_loser_is_explicit_conflict(&loser);
    assert!(winner.initialized_first_pointer);
    assert_eq!(winner.published_manifest_id, manifest.manifest_id);
    assert_eq!(winner.previous_superseded_manifest_id, None);

    // 恰好一个指针行，且指向被竞争的 manifest。
    let pointer_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM authorization_projection_current \
         WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ?",
    )
    .bind(namespace.tenant_id)
    .bind(AGGREGATE_TYPE)
    .bind(namespace.aggregate_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(pointer_count.0, 1);

    {
        let mut tx = pool.begin().await.unwrap();
        let state = read_published_authorization_state_in_tx(&mut tx, &identity)
            .await
            .unwrap();
        tx.rollback().await.unwrap();
        assert_eq!(state.pointer, winner.pointer);
        assert_eq!(state.generation, 1);
    }

    // ── 确定性败者 1：陈旧指针视图在执行任何语句前被拒 ──
    {
        let mut stale = winner.pointer.as_view();
        stale.cas_version += 1;
        let error = publish_ready_manifest(&pool, &namespace, &manifest, 1, Some(stale))
            .await
            .unwrap_err();
        match error {
            AuthorizationProjectionError::CurrentPointerCasConflict(message) => {
                assert!(
                    message.contains("publish_stale_pointer_view"),
                    "unexpected conflict code: {message}"
                );
            }
            other => panic!("stale pointer view must be a CAS conflict, got: {other:?}"),
        }
    }

    // ── 确定性败者 2：指针已存在时重放“首次发布”期望被拒 ──
    {
        let error = publish_ready_manifest(&pool, &namespace, &manifest, 1, None)
            .await
            .unwrap_err();
        match error {
            AuthorizationProjectionError::ManifestPublishConflict(message) => {
                assert!(
                    message.contains("publish_expected_first_but_pointer_exists"),
                    "unexpected conflict code: {message}"
                );
            }
            other => panic!("first-publication replay must conflict, got: {other:?}"),
        }
    }

    // ── 确定性败者 3：COMMITTED 目标不再是合法发布对象 ──
    {
        let error = publish_ready_manifest(
            &pool,
            &namespace,
            &manifest,
            1,
            Some(winner.pointer.as_view()),
        )
        .await
        .unwrap_err();
        match error {
            AuthorizationProjectionError::NotReady(message) => {
                assert!(
                    message.contains("target_not_ready"),
                    "unexpected NotReady code: {message}"
                );
            }
            other => panic!("committed target must refuse republish, got: {other:?}"),
        }
    }

    cleanup_namespace(&pool, &namespace).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// (4) 归档：CAS 前 intent 与发布同事务 → 重放 / claim / heartbeat → proof → 完成
// ─────────────────────────────────────────────────────────────────────────────

/// 完整两代链之后：gen2 发布事务在指针 CAS 之前为仍被 live proof-bearing
/// pointer 指向的第一代追加归档 intent（新契约：NEW intent 只能在指针 CAS 前
/// 创建；与生产编排 `project_authorization_delta_in_tx` 的 (6)→(7) 步同构），
/// CAS 后仅允许同值重放 resume 同一行；随后 claim 租约（活租约不可抢占），
/// heartbeat 只延长租期、绝不触碰 status/attempts/cas_version，错误 chain
/// digest / 错误租约身份被拒，durable proof 落库后凭活租约把 intent 置为
/// SUCCEEDED（先 proof 后终态）。
#[ignore]
#[tokio::test]
async fn archive_intent_lease_and_durable_proof_flow() {
    let Some(pool) = connect().await else {
        return;
    };
    let namespace = TestNamespace::new("archive");
    cleanup_namespace(&pool, &namespace).await;

    let identity = namespace.identity();

    // 建立两代链：第二代发布后第一代成为 SUPERSEDED（可归档证据）。
    let gen1 = stage_and_finalize_manifest(
        &pool,
        &namespace,
        1,
        &[test_grant(&namespace, 21), test_grant(&namespace, 22)],
        "arch-gen1",
    )
    .await;
    let outcome1 = publish_ready_manifest(&pool, &namespace, &gen1, 1, None)
        .await
        .unwrap();

    let gen2 = stage_and_finalize_manifest(
        &pool,
        &namespace,
        2,
        &[test_grant(&namespace, 23)],
        "arch-gen2",
    )
    .await;

    // ── gen2 发布事务：在指针 CAS 之前为仍被 live proof-bearing pointer 指向
    //    的 gen1 追加归档 intent（新契约：NEW intent 只能在 CAS 前创建），
    //    再执行指针 CAS；与生产编排 (6)→(7) 步同构 ──
    let intent_request = AuthorizationArchiveIntentAppendRequest {
        identity: identity.clone(),
        card_id: Some(namespace.card_id),
        archived_manifest_id: gen1.manifest_id,
        archived_generation: 1,
        event_id: gen1.event_id.clone(),
        operation_id: gen1.operation_id.clone(),
        archive_key: derive_archive_key(&identity, 1).unwrap(),
        semantic_hash_hex: gen1.semantic_hash_hex.clone(),
        dependency_hash_hex: gen1.dependency_hash_hex.clone(),
        compiler_version: gen1.compiler_version.clone(),
        archived_revoke_fence: 0,
    };
    let (intent, outcome2) = append_archive_intent_then_publish_in_tx(
        &pool,
        &intent_request,
        &publish_request_for(&namespace, &gen2, 2, Some(outcome1.pointer.as_view())),
    )
    .await
    .expect("pre-CAS archive intent append plus publication must commit atomically");
    assert!(!intent.resumed_existing_intent);
    assert!(intent.archive_outbox_id > 0);
    assert!(!outcome2.initialized_first_pointer);
    assert_eq!(
        outcome2.previous_superseded_manifest_id,
        Some(gen1.manifest_id)
    );
    assert_eq!(outcome2.pointer.current_generation, 2);
    assert_eq!(outcome2.pointer.manifest_id, gen2.manifest_id);

    // ── CAS 之后：仅允许同值重放（resume 同一行），绝不重复写入 ──
    {
        let mut tx = pool.begin().await.unwrap();
        let replay = ensure_authorization_archive_intent_in_tx(&mut tx, &intent_request)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert!(
            replay.resumed_existing_intent,
            "post-supersession calls may only replay the already-existing intent"
        );
        assert_eq!(replay.archive_outbox_id, intent.archive_outbox_id);
    }

    // ── claim：PENDING → LEASED；活租约不可被第二次 claim 抢占 ──
    let claim = {
        let mut tx = pool.begin().await.unwrap();
        let claimed = claim_next_authorization_archive_intent_in_tx(
            &mut tx,
            namespace.tenant_id,
            Some(namespace.card_id),
            "itest-archive-owner",
            ARCHIVE_LEASE_SECONDS,
        )
        .await
        .unwrap()
        .expect("the fresh PENDING intent must be claimable");
        tx.commit().await.unwrap();
        claimed
    };
    assert_eq!(claim.archive_outbox_id, intent.archive_outbox_id);
    assert_eq!(claim.archived_manifest_id, gen1.manifest_id);
    assert_eq!(claim.archived_generation, 1);
    assert_eq!(claim.event_id, gen1.event_id);
    assert_eq!(claim.status_before_claim_str, "PENDING");
    assert_eq!(claim.card_id, Some(namespace.card_id));

    {
        let mut tx = pool.begin().await.unwrap();
        let none_left = claim_next_authorization_archive_intent_in_tx(
            &mut tx,
            namespace.tenant_id,
            Some(namespace.card_id),
            "itest-archive-owner-2",
            ARCHIVE_LEASE_SECONDS,
        )
        .await
        .unwrap();
        tx.rollback().await.unwrap();
        assert!(
            none_left.is_none(),
            "a live lease must never be stolen by a second claim"
        );
    }

    // ── heartbeat（proof/complete 之前）：续期只延长租期，绝不触碰
    //    status/attempts/cas_version，也绝不推进重试记账 ──
    let lease_proof = ArchiveLeaseProof {
        archive_outbox_id: claim.archive_outbox_id,
        event_id: claim.event_id.clone(),
        lease_owner: claim.lease_owner.clone(),
        lease_token: claim.lease_token.clone(),
    };
    {
        // 被篡改的租约身份必须被租约 CAS 拒绝，且行不发生任何变化。
        let mut tampered = lease_proof.clone();
        tampered.lease_owner = "itest-attacker".to_owned();
        let error =
            heartbeat_authorization_archive_intent_lease(&pool, &tampered, ARCHIVE_LEASE_SECONDS)
                .await
                .unwrap_err();
        assert!(
            matches!(
                error,
                AuthorizationProjectionError::LeaseCasFailed(ref message)
                    if message.contains("archive_heartbeat_lost_lease")
            ),
            "tampered lease identity must fail the heartbeat CAS, got: {error:?}"
        );
    }
    {
        let (expiry_before,): (PrimitiveDateTime,) = sqlx::query_as(
            "SELECT lease_expires_at FROM authorization_archive_outbox \
             WHERE archive_outbox_id = ?",
        )
        .bind(claim.archive_outbox_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        // 续期 3600s ≫ claim 的 600s，使严格递增断言与墙钟同秒抖动无关。
        heartbeat_authorization_archive_intent_lease(&pool, &lease_proof, 3_600)
            .await
            .expect("a live lease must be renewable before proof/complete");
        let (expiry_after,): (PrimitiveDateTime,) = sqlx::query_as(
            "SELECT lease_expires_at FROM authorization_archive_outbox \
             WHERE archive_outbox_id = ?",
        )
        .bind(claim.archive_outbox_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            expiry_after > expiry_before,
            "heartbeat must extend the durable lease expiry"
        );
        // status / attempts / cas_version 全部不变（续期不推进重试记账）。
        let mut tx = pool.begin().await.unwrap();
        let record = load_authorization_archive_intent_in_tx(&mut tx, &identity, &claim.event_id)
            .await
            .unwrap()
            .expect("intent must remain readable after heartbeat");
        tx.rollback().await.unwrap();
        assert_eq!(record.status, AuthorizationArchiveOutboxStatus::Leased);
        assert_eq!(record.attempts, claim.attempts_after_install);
        assert_eq!(record.cas_version, claim.cas_version_after_claim);
    }

    // ── durable proof：错误 chain digest 必须先被拒（无任何写入） ──
    let mut proof_request = AuthorizationArchiveProofRequest {
        identity: identity.clone(),
        card_id: Some(namespace.card_id),
        archived_manifest_id: gen1.manifest_id,
        archived_generation: 1,
        event_id: gen1.event_id.clone(),
        operation_id: gen1.operation_id.clone(),
        archive_key: intent_request.archive_key.clone(),
        semantic_hash_hex: gen1.semantic_hash_hex.clone(),
        dependency_hash_hex: gen1.dependency_hash_hex.clone(),
        compiler_version: gen1.compiler_version.clone(),
        archived_revoke_fence: 0,
        manifest_chain_digest_hex: sha256_hex("itest/wrong/chain-digest"),
    };
    {
        let mut tx = pool.begin().await.unwrap();
        let error = record_authorization_archive_proof_in_tx(&mut tx, &proof_request)
            .await
            .unwrap_err();
        tx.rollback().await.unwrap();
        match error {
            AuthorizationProjectionError::ImmutableConflict(message) => {
                assert!(
                    message.contains("archive_chain_digest_mismatch"),
                    "unexpected conflict code: {message}"
                );
            }
            other => panic!("wrong chain digest must be an immutable conflict, got: {other:?}"),
        }
    }

    // 正确的 chain digest = 第一代 manifest 自身封存的 manifest_digest。
    proof_request.manifest_chain_digest_hex = gen1.manifest_digest.as_hex();
    let proof = {
        let mut tx = pool.begin().await.unwrap();
        let recorded = record_authorization_archive_proof_in_tx(&mut tx, &proof_request)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        recorded
    };
    assert_eq!(proof.status, AuthorizationArchiveManifestStatus::Archived);
    assert!(
        proof.archived_at.is_some(),
        "terminal proof must be stamped"
    );
    assert_eq!(proof.archived_manifest_id, gen1.manifest_id);
    assert_eq!(proof.archived_generation, 1);

    // ── 凭租约完成：先拒绝被篡改的租约身份，再以真实租约置终态 ──
    {
        // 租约 owner 被替换 → 守护更新 0 行 → LeaseCasFailed，行仍为 LEASED。
        let mut tampered = lease_proof.clone();
        tampered.lease_owner = "itest-attacker".to_owned();
        let mut tx = pool.begin().await.unwrap();
        let error = complete_authorization_archive_intent(&mut tx, &tampered)
            .await
            .unwrap_err();
        tx.rollback().await.unwrap();
        assert!(
            matches!(error, AuthorizationProjectionError::LeaseCasFailed(ref message) if message.contains("archive_complete_lost_lease")),
            "tampered lease identity must fail the lease CAS, got: {error:?}"
        );

        let mut tx = pool.begin().await.unwrap();
        let still_leased =
            load_authorization_archive_intent_in_tx(&mut tx, &identity, &claim.event_id)
                .await
                .unwrap()
                .expect("intent must still exist");
        tx.rollback().await.unwrap();
        assert_eq!(
            still_leased.status,
            AuthorizationArchiveOutboxStatus::Leased,
            "a failed lease CAS must not change durable state"
        );
    }
    {
        let mut tx = pool.begin().await.unwrap();
        complete_authorization_archive_intent(&mut tx, &lease_proof)
            .await
            .expect("the durable proof plus live lease must complete the intent");
        tx.commit().await.unwrap();
    }

    // 终态校验：SUCCEEDED 携带 archived_at；SUCCEEDED 行不再可 claim。
    {
        let mut tx = pool.begin().await.unwrap();
        let record = load_authorization_archive_intent_in_tx(&mut tx, &identity, &claim.event_id)
            .await
            .unwrap()
            .expect("the completed intent must remain readable");
        let none_left = claim_next_authorization_archive_intent_in_tx(
            &mut tx,
            namespace.tenant_id,
            Some(namespace.card_id),
            "itest-archive-owner",
            ARCHIVE_LEASE_SECONDS,
        )
        .await
        .unwrap();
        tx.rollback().await.unwrap();
        assert_eq!(record.status, AuthorizationArchiveOutboxStatus::Succeeded);
        assert!(record.archived_at.is_some());
        assert_eq!(record.attempts, 1);
        assert!(none_left.is_none());
    }

    cleanup_namespace(&pool, &namespace).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// (5) archive intent 父/指针证明：维度不匹配先于 outbox 写拒绝（含 CAS 后补建负例）
// ─────────────────────────────────────────────────────────────────────────────

/// 在同一（未提交）事务内执行一次应被拒绝的 archive intent 请求：断言其以
/// `ImmutableConflict`（携带 `expected_fragment` 稳定机器码）失败，且事务内
/// `authorization_archive_outbox` 行数仍为 `expected_outbox_rows`（拒绝先于
/// 任何 outbox 写入；若实现先写后拒，本事务内的行数断言会暴露它）。
async fn assert_intent_append_rejected_before_outbox_write(
    pool: &MySqlPool,
    namespace: &TestNamespace,
    request: &AuthorizationArchiveIntentAppendRequest,
    expected_fragment: &str,
    expected_outbox_rows: i64,
) {
    let mut tx = pool.begin().await.unwrap();
    let error = ensure_authorization_archive_intent_in_tx(&mut tx, request)
        .await
        .unwrap_err();
    let outbox_rows = outbox_row_count(&mut tx, namespace).await;
    tx.rollback().await.unwrap();

    match &error {
        AuthorizationProjectionError::ImmutableConflict(message) => {
            assert!(
                message.contains(expected_fragment),
                "unexpected archive-intent conflict code (expected {expected_fragment}): {message}"
            );
        }
        other => panic!(
            "the rejected archive intent must be an immutable conflict before any outbox write, got: {other:?}"
        ),
    }
    assert_eq!(
        outbox_rows, expected_outbox_rows,
        "the rejection must leave the outbox untouched inside the same transaction"
    );
}

/// `ensure_authorization_archive_intent_in_tx` 的父/指针证明（parent/pointer
/// proof）门禁：NEW intent 只能证明于 live proof-bearing pointer——已发布的
/// 父 manifest（COMMITTED，与正常发布流在指针 CAS 前追加 intent 时的父状态
/// 一致）锁定后，`archived_revoke_fence`、`event_id` 与 semantic hash 任一
/// 不匹配都在触碰 outbox 之前被
/// `archive_intent_parent_mismatch;dimension=<dimension>` 拒绝；随后同一
/// 命名空间的合法请求（此时 live pointer 仍指向父代，符合新契约的
/// NEW-intent 前提）仍走既有幂等写入流（CAS 前 insert → 同值重放 resume）。
/// 之后 gen2/gen3 普通发布制造“父代已被取代但从无 intent”的恢复形态：
/// live pointer 已指向新一代时，为该父代补建 NEW intent 以
/// `archive_intent_pointer_mismatch;dimension=archived_manifest_id` 在触碰
/// outbox 之前被拒。
#[ignore]
#[tokio::test]
async fn archive_intent_parent_proof_rejects_mismatch_before_outbox_write() {
    let Some(pool) = connect().await else {
        return;
    };
    let namespace = TestNamespace::new("archive_parent_proof");
    cleanup_namespace(&pool, &namespace).await;

    // 单代链即可：gen1 发布后处于 COMMITTED 且仍被 live pointer 指向。
    let gen1 = stage_and_finalize_manifest(
        &pool,
        &namespace,
        1,
        &[test_grant(&namespace, 31), test_grant(&namespace, 32)],
        "parent-proof-gen1",
    )
    .await;
    let outcome1 = publish_ready_manifest(&pool, &namespace, &gen1, 1, None)
        .await
        .expect("the parent generation must publish cleanly before parent-proof checks");

    let identity = namespace.identity();
    let valid_request = AuthorizationArchiveIntentAppendRequest {
        identity: identity.clone(),
        card_id: Some(namespace.card_id),
        archived_manifest_id: gen1.manifest_id,
        archived_generation: 1,
        event_id: gen1.event_id.clone(),
        operation_id: gen1.operation_id.clone(),
        archive_key: derive_archive_key(&identity, 1).unwrap(),
        semantic_hash_hex: gen1.semantic_hash_hex.clone(),
        dependency_hash_hex: gen1.dependency_hash_hex.clone(),
        compiler_version: gen1.compiler_version.clone(),
        archived_revoke_fence: 0,
    };

    // ── 维度 1：archived_revoke_fence 不匹配（父为 0，请求伪造 1）──
    let mut forged_fence = valid_request.clone();
    forged_fence.archived_revoke_fence = 1;
    assert_intent_append_rejected_before_outbox_write(
        &pool,
        &namespace,
        &forged_fence,
        "code=authorization_projection.archive_intent_parent_mismatch;dimension=archived_revoke_fence",
        0,
    )
    .await;

    // ── 维度 2：event_id 不匹配（父 provenance 不可伪造）──
    let mut forged_event = valid_request.clone();
    forged_event.event_id = namespace.event_id("forged-event");
    assert_intent_append_rejected_before_outbox_write(
        &pool,
        &namespace,
        &forged_event,
        "code=authorization_projection.archive_intent_parent_mismatch;dimension=event_id",
        0,
    )
    .await;

    // ── 维度 3：semantic_hash 不匹配（父 manifest 封存哈希不可伪造）──
    let mut forged_hash = valid_request.clone();
    forged_hash.semantic_hash_hex = sha256_hex("itest/forged/semantic-hash");
    assert_intent_append_rejected_before_outbox_write(
        &pool,
        &namespace,
        &forged_hash,
        "code=authorization_projection.archive_intent_parent_mismatch;dimension=semantic_hash",
        0,
    )
    .await;

    // ── 合法请求保留既有流：CAS 前 insert（非 resume）→ 同值重放 resume ──
    let intent = {
        let mut tx = pool.begin().await.unwrap();
        let outcome = ensure_authorization_archive_intent_in_tx(&mut tx, &valid_request)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        outcome
    };
    assert!(!intent.resumed_existing_intent);
    assert!(intent.archive_outbox_id > 0);

    let replay = {
        let mut tx = pool.begin().await.unwrap();
        let outcome = ensure_authorization_archive_intent_in_tx(&mut tx, &valid_request)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        outcome
    };
    assert!(replay.resumed_existing_intent);
    assert_eq!(replay.archive_outbox_id, intent.archive_outbox_id);

    // ── 制造“父代已被取代但从无 intent”的恢复形态：gen2/gen3 普通发布
    //    （不在 CAS 前追加任何 intent）──
    let gen2 = stage_and_finalize_manifest(
        &pool,
        &namespace,
        2,
        &[test_grant(&namespace, 33)],
        "parent-proof-gen2",
    )
    .await;
    let outcome2 = publish_ready_manifest(
        &pool,
        &namespace,
        &gen2,
        2,
        Some(outcome1.pointer.as_view()),
    )
    .await
    .expect("gen2 must publish cleanly without a pre-CAS archive intent");
    let gen3 = stage_and_finalize_manifest(
        &pool,
        &namespace,
        3,
        &[test_grant(&namespace, 34)],
        "parent-proof-gen3",
    )
    .await;
    publish_ready_manifest(
        &pool,
        &namespace,
        &gen3,
        3,
        Some(outcome2.pointer.as_view()),
    )
    .await
    .expect("gen3 must publish cleanly, superseding intent-less gen2");

    // ── 新契约负例：live pointer 已指向新一代时，为已取代且从无 intent 的
    //    gen2 补建 NEW intent 必须在触碰 outbox 之前被拒（outbox 仍只有
    //    gen1 的那一行）──
    let mint_request = AuthorizationArchiveIntentAppendRequest {
        identity: identity.clone(),
        card_id: Some(namespace.card_id),
        archived_manifest_id: gen2.manifest_id,
        archived_generation: 2,
        event_id: gen2.event_id.clone(),
        operation_id: gen2.operation_id.clone(),
        archive_key: derive_archive_key(&identity, 2).unwrap(),
        semantic_hash_hex: gen2.semantic_hash_hex.clone(),
        dependency_hash_hex: gen2.dependency_hash_hex.clone(),
        compiler_version: gen2.compiler_version.clone(),
        archived_revoke_fence: 0,
    };
    assert_intent_append_rejected_before_outbox_write(
        &pool,
        &namespace,
        &mint_request,
        "code=authorization_projection.archive_intent_pointer_mismatch;dimension=archived_manifest_id",
        1,
    )
    .await;

    // ── 所有拒绝均未触碰既有 durable 状态：gen1 的 CAS 前 intent 仍是
    //    PENDING 且 attempts 未推进 ──
    {
        let mut tx = pool.begin().await.unwrap();
        let record = load_authorization_archive_intent_in_tx(&mut tx, &identity, &gen1.event_id)
            .await
            .unwrap()
            .expect("the pre-CAS intent must remain readable");
        tx.rollback().await.unwrap();
        assert_eq!(record.status, AuthorizationArchiveOutboxStatus::Pending);
        assert_eq!(
            record.attempts, 0,
            "rejections must never advance retry accounting"
        );
    }

    cleanup_namespace(&pool, &namespace).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// (6) source-freshness 门：发布完成前越权修复
// ─────────────────────────────────────────────────────────────────────────────

/// 卡作用域存在会使旧 published evidence 失效的非 `SUCCEEDED` delta
/// （`invalidates_published_evidence=1`，包括 PENDING/LEASED/QUARANTINED）
/// ⟺ source 已提交而发布未完成/未成功——严格 reader 必须 `NotReady`（机器码
/// `source_freshness_pending`，gate 归类 PENDING），绝不以旧代已发布证据放行；
/// 同卡另一个 grant 的 SUCCEEDED sibling 不能折叠该行；该行自身 SUCCEEDED 后
/// 才恢复 Ready。ADD 与 provenance-only/no-op UPDATE（flag=0）仍保持 deny-biased
/// eventual consistency，不因卡级 watermark 被误阻断。
#[ignore]
#[tokio::test]
async fn unpublished_delta_gates_published_card_evidence_to_pending() {
    let Some(pool) = connect().await else {
        return;
    };
    let namespace = TestNamespace::new("freshness_gate");
    cleanup_namespace(&pool, &namespace).await;
    let scope = namespace.evidence_scope();

    // ── 干净发布一代：无任何 delta 行 → 门禁通过，证据 Ready ──
    let gen1 =
        stage_and_finalize_manifest(&pool, &namespace, 1, &[test_grant(&namespace, 1)], "gen1")
            .await;
    publish_ready_manifest(&pool, &namespace, &gen1, 1, None)
        .await
        .expect("first publication must succeed");
    let before = load_published_card_grant_evidence(&pool, &scope)
        .await
        .expect("evidence must be Ready when no unpublished delta exists");
    assert_eq!(before.gate.status, PublishedEvidenceGateStatus::Ready);

    // ── 注入同卡跨 grant 的收窄 UPDATE：G1 未发布，G2 先成功 ──
    // 两个 sibling 共享同一个 CARD revoke fence；G2 成功只能抬高卡级水位，
    // 不能折叠 G1 的行级 invalidation 标记。
    let narrow_grant = test_grant(&namespace, 301).grant_id;
    let sibling_grant = test_grant(&namespace, 302).grant_id;
    insert_synthetic_delta(
        &pool,
        &namespace,
        "narrow_update",
        Some(namespace.card_id),
        narrow_grant,
        "UPDATE",
        true,
        1,
        2,
        2,
        1,
        "PENDING",
    )
    .await;
    insert_synthetic_delta(
        &pool,
        &namespace,
        "sibling_update",
        Some(namespace.card_id),
        sibling_grant,
        "UPDATE",
        false,
        1,
        2,
        2,
        1,
        "SUCCEEDED",
    )
    .await;

    // 门禁生效：严格证据读 → NotReady（PENDING 语义），绝不放行旧代证据。
    let gated = load_published_card_grant_evidence(&pool, &scope)
        .await
        .expect_err("unpublished delta must gate the published evidence read");
    match &gated {
        AuthorizationEvidenceError::NotReady(message) => {
            assert!(
                message.contains("source_freshness_pending"),
                "unexpected NotReady code: {message}"
            );
        }
        other => panic!("expected NotReady (PENDING), got: {other:?}"),
    }
    assert_eq!(
        gated.as_gate_status(),
        PublishedEvidenceGateStatus::Pending,
        "the gate must classify as PENDING, never Corrupt"
    );

    let pending_snapshot =
        load_card_scope_fence_snapshot(&pool, namespace.tenant_id, namespace.card_id)
            .await
            .expect("pending fence snapshot must load");
    assert!(
        pending_snapshot.card_source_pending,
        "a pending flag=1 sibling must poison the cache fence snapshot"
    );

    // 事务内版本同样被门禁拦截（与 pool 版同一入口）。
    {
        let mut tx = pool.begin().await.unwrap();
        let gated_in_tx = load_published_card_grant_evidence_in_tx(&mut tx, &scope).await;
        assert!(matches!(
            gated_in_tx,
            Err(AuthorizationEvidenceError::NotReady(_))
        ));
        tx.rollback().await.unwrap();
    }

    let narrow_flag: (i64,) = sqlx::query_as(
        "SELECT invalidates_published_evidence FROM authorization_delta_event \
         WHERE event_id = ?",
    )
    .bind(namespace.event_id("narrow_update"))
    .fetch_one(&pool)
    .await
    .expect("narrowing delta row must expose its invalidation flag");
    let sibling_flag: (i64,) = sqlx::query_as(
        "SELECT invalidates_published_evidence FROM authorization_delta_event \
         WHERE event_id = ?",
    )
    .bind(namespace.event_id("sibling_update"))
    .fetch_one(&pool)
    .await
    .expect("sibling delta row must expose its invalidation flag");
    assert_eq!(narrow_flag.0, 1, "narrowing UPDATE must persist flag=1");
    assert_eq!(
        sibling_flag.0, 0,
        "neutral sibling UPDATE must persist flag=0"
    );

    // G1 进入 QUARANTINED 后仍持续阻断；人工对账前不能回退到旧证据。
    sqlx::query(
        "UPDATE authorization_delta_event SET status = 'QUARANTINED' \
         WHERE event_id = ?",
    )
    .bind(namespace.event_id("narrow_update"))
    .execute(&pool)
    .await
    .unwrap();
    let quarantined = load_published_card_grant_evidence(&pool, &scope).await;
    assert!(
        matches!(quarantined, Err(AuthorizationEvidenceError::NotReady(ref message))
            if message.contains("source_freshness_pending")),
        "QUARANTINED flag=1 G1 must keep the card PENDING, got: {quarantined:?}"
    );

    // G1 自身成功发布后才恢复 Ready；另一个 grant 的 SUCCEEDED 不能替代它。
    sqlx::query(
        "UPDATE authorization_delta_event SET status = 'SUCCEEDED' \
         WHERE event_id = ?",
    )
    .bind(namespace.event_id("narrow_update"))
    .execute(&pool)
    .await
    .unwrap();
    let after = load_published_card_grant_evidence(&pool, &scope)
        .await
        .expect("evidence must recover once G1 itself is SUCCEEDED");
    assert_eq!(after.gate.status, PublishedEvidenceGateStatus::Ready);
    let recovered_snapshot =
        load_card_scope_fence_snapshot(&pool, namespace.tenant_id, namespace.card_id)
            .await
            .expect("recovered fence snapshot must load");
    assert!(
        !recovered_snapshot.card_source_pending,
        "the cache fence pending bit must clear only after G1 succeeds"
    );

    // With the card watermark already at fence=1, safe ADD and provenance-only
    // UPDATE rows with flag=0 remain non-blocking even while PENDING.
    insert_synthetic_delta(
        &pool,
        &namespace,
        "neutral_add",
        Some(namespace.card_id),
        test_grant(&namespace, 303).grant_id,
        "ADD",
        false,
        0,
        1,
        2,
        1,
        "PENDING",
    )
    .await;
    insert_synthetic_delta(
        &pool,
        &namespace,
        "neutral_update",
        Some(namespace.card_id),
        test_grant(&namespace, 304).grant_id,
        "UPDATE",
        false,
        1,
        2,
        2,
        1,
        "PENDING",
    )
    .await;
    let neutral = load_published_card_grant_evidence(&pool, &scope)
        .await
        .expect("flag=0 ADD/provenance-only UPDATE must not gate the card");
    assert_eq!(neutral.gate.status, PublishedEvidenceGateStatus::Ready);
    let neutral_snapshot =
        load_card_scope_fence_snapshot(&pool, namespace.tenant_id, namespace.card_id)
            .await
            .expect("neutral fence snapshot must load");
    assert!(
        !neutral_snapshot.card_source_pending,
        "safe flag=0 deltas must not poison the cache fence"
    );

    for event_id in [
        namespace.event_id("neutral_add"),
        namespace.event_id("neutral_update"),
    ] {
        sqlx::query("UPDATE authorization_delta_event SET status = 'SUCCEEDED' WHERE event_id = ?")
            .bind(event_id)
            .execute(&pool)
            .await
            .unwrap();
    }

    cleanup_namespace(&pool, &namespace).await;
}

/// 认领侧兄弟排序门（战役发现 10.D-2）：同 grant 链前驱未终态时，后继事件
/// 不得被认领（认领会白烧 attempts 预算，分区器必然回答
/// `claimed_behind_unpublished_siblings`）。断言四件事：
/// 1. 无前驱的链头（rev1）正常认领（FIFO 链头优先）；
/// 2. rev1 带退避滞留时，rev2 认领返回 None（门生效，预算零消耗）；
/// 3. rev1 退避期满后重新可认领的是 rev1（严格链序，绝不跳前）；
/// 4. rev1 SUCCEEDED 后 rev2 立即可认领；QUARANTINED 前驱不拦认领
///    （不可排序链保持可观测，走决策 Blocked 路径暴露）。
#[tokio::test]
#[ignore]
async fn claim_gate_defers_behind_unpublished_same_grant_siblings() {
    let Some(pool) = connect().await else {
        return;
    };
    let namespace = TestNamespace::new("claim_sibling_gate");
    cleanup_namespace(&pool, &namespace).await;
    // 认领路径的 grant_id 解码要求 canonical 小写连字符 36 位 UUID。
    let grant_id = Uuid::new_v4().to_string();

    async fn insert_delta(
        pool: &MySqlPool,
        namespace: &TestNamespace,
        grant_id: &str,
        tag: &'static str,
        base: i64,
        target: i64,
    ) {
        sqlx::query(
            "INSERT INTO authorization_delta_event              (tenant_id, card_id, aggregate_type, aggregate_id, grant_id, event_id,               operation_id, event_type, base_version, target_version, source_generation,               revoke_fence, invalidates_published_evidence, delta_json, semantic_hash, dependency_hash, compiler_version,               status)              VALUES (?, ?, ?, ?, ?, ?, ?, 'ADD', ?, ?, 1, 0, 0, '{}', ?, ?, 'test', 'PENDING')",
        )
        .bind(namespace.tenant_id)
        .bind(namespace.card_id)
        .bind(AGGREGATE_TYPE)
        .bind(namespace.aggregate_id)
        .bind(grant_id)
        .bind(namespace.event_id(tag))
        .bind(namespace.operation_id(tag))
        .bind(base)
        .bind(target)
        .bind(Sha256::digest(b"claim-gate-semantic").to_vec())
        .bind(Sha256::digest(b"claim-gate-dependency").to_vec())
        .execute(pool)
        .await
        .expect("synthetic sibling delta must insert");
    }

    // `keep_lease=true` 的认领提交事务（租约安装随之持久化，供后续
    // fail_delta_event 的 CAS 使用）；探针式认领一律回滚，不留下租约。
    let claim = |keep_lease: bool| {
        let pool = pool.clone();
        async move {
            let mut tx = pool.begin().await.expect("claim tx must begin");
            let claimed = claim_next_delta_event_in_tx(
                &mut tx,
                DeltaEventClaimScope {
                    tenant_id: namespace.tenant_id,
                    card_id: None,
                },
                "claim-gate-worker",
                60,
            )
            .await
            .expect("claim must not error");
            if keep_lease {
                tx.commit().await.expect("claim lease must persist");
            } else {
                tx.rollback().await.expect("claim probe must roll back");
            }
            claimed
        }
    };

    // 链头 rev1 + 后继 rev2，同 grant，均 PENDING（退避未设）。
    insert_delta(&pool, &namespace, &grant_id, "gate_rev1", 0, 1).await;
    insert_delta(&pool, &namespace, &grant_id, "gate_rev2", 1, 2).await;

    // 1. 无前驱的链头可认领（FIFO）。本笔保留租约供后续 fail 使用。
    let first = claim(true).await.expect("rev1 must be claimable");
    assert_eq!(first.target_version, 1, "claim must pick the chain head");

    // rev1 失败并进入长退避（模拟发布事务 1213 死锁后的重试调度）。
    let identity = DeltaLeaseIdentity {
        delta_event_id: first.delta_event_id,
        event_id: first.event_id.clone(),
        lease_owner: first.lease_owner.clone(),
        lease_token: first.lease_token.clone(),
    };
    fail_delta_event(&pool, &identity, 900, "code=test.deadlock_retry")
        .await
        .expect("fail must schedule the retry");

    // 2. rev2 被兄弟门拦下：认领返回 None，预算零消耗。
    let gated = claim(false).await;
    assert!(
        gated.is_none(),
        "rev2 must NOT be claimed while rev1 is non-terminal (10.D-2 gate)"
    );

    // 3. rev1 退避期满 → 重新可认领的是 rev1（严格链序），绝不是 rev2。
    sqlx::query("UPDATE authorization_delta_event SET next_attempt_at = NULL WHERE event_id = ?")
        .bind(first.event_id.clone())
        .execute(&pool)
        .await
        .unwrap();
    let retried = claim(false).await.expect("due rev1 must be reclaimable");
    assert_eq!(retried.target_version, 1, "chain order is strict FIFO");
    assert_eq!(
        retried.attempts, 2,
        "only real claims consume the attempt budget"
    );

    // 4a. rev1 SUCCEEDED → rev2 立即可认领（排水不再依赖 900s 退避周期）。
    sqlx::query("UPDATE authorization_delta_event SET status = 'SUCCEEDED' WHERE event_id = ?")
        .bind(first.event_id)
        .execute(&pool)
        .await
        .unwrap();
    let second = claim(false)
        .await
        .expect("rev2 must be claimable once rev1 published");
    assert_eq!(second.target_version, 2);

    // 4b. QUARANTINED 前驱不拦认领：不可排序链保持可观测（决策路径 Blocked）。
    sqlx::query("UPDATE authorization_delta_event SET status = 'QUARANTINED' WHERE event_id = ?")
        .bind(second.event_id)
        .execute(&pool)
        .await
        .unwrap();
    insert_delta(&pool, &namespace, &grant_id, "gate_rev3", 2, 3).await;
    let third = claim(false)
        .await
        .expect("QUARANTINED predecessor must not gate the claim (observable stuck state)");
    assert_eq!(third.target_version, 3);

    cleanup_namespace(&pool, &namespace).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 2026-09-04 探针修订：aggregate-wide（card_id IS NULL）覆盖 + 收窄 UPDATE
// 的 stale-ALLOW 闭合（astral-db owner 侧机制链）
// ─────────────────────────────────────────────────────────────────────────────

/// 注入一条合成 delta 行（`card_id` 可为 NULL = aggregate-wide）。
/// 仅用于 freshness 门谓词验证：门只读 `authorization_delta_event` 的
/// `(tenant_id, card_id, status, event_type, invalidates_published_evidence, revoke_fence)` predicate面。
#[allow(clippy::too_many_arguments)]
async fn insert_synthetic_delta(
    pool: &MySqlPool,
    namespace: &TestNamespace,
    tag: &'static str,
    card_id: Option<i64>,
    grant_id: GrantId,
    event_type: &str,
    invalidates_published_evidence: bool,
    base_version: i64,
    target_version: i64,
    source_generation: i64,
    revoke_fence: i64,
    status: &str,
) {
    sqlx::query(
        "INSERT INTO authorization_delta_event \
         (tenant_id, card_id, aggregate_type, aggregate_id, grant_id, event_id, operation_id, \
          event_type, base_version, target_version, source_generation, revoke_fence, \
          invalidates_published_evidence, delta_json, semantic_hash, dependency_hash, \
          compiler_version, status) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', ?, ?, 'test', ?)",
    )
    .bind(namespace.tenant_id)
    .bind(card_id)
    .bind(AGGREGATE_TYPE)
    .bind(namespace.aggregate_id)
    .bind(grant_id.to_string())
    .bind(namespace.event_id(tag))
    .bind(namespace.operation_id(tag))
    .bind(event_type)
    .bind(base_version)
    .bind(target_version)
    .bind(source_generation)
    .bind(revoke_fence)
    .bind(invalidates_published_evidence)
    .bind(Sha256::digest(tag.as_bytes()).to_vec())
    .bind(Sha256::digest(format!("{tag}-dependency").as_bytes()).to_vec())
    .bind(status)
    .execute(pool)
    .await
    .expect("synthetic delta must insert");
}

/// 真实仓储写入器：单事务内 REVOKE kind 的 CARD 父投影事件（head fence 递增）
/// + 绑定抬升后 fence 的 UPDATE delta。
///
/// 与 astral-trustgraph 三条 UPDATE 链路（direct rule / rule-set entry /
/// delegation）在收窄场景调用 astral-db owner 原语的顺序与形状完全一致。
/// 返回 (投影事件身份, 卡 head 的 fence)。
async fn append_revoke_class_card_parent_and_update_delta(
    pool: &MySqlPool,
    namespace: &TestNamespace,
    tag: &'static str,
) -> (astral_db::ProjectionEventIdentity, i64, i64) {
    let mut grant = test_grant(namespace, 7);
    let expected_revision = GrantRevision::initial();
    grant.revision = expected_revision
        .next()
        .expect("revision successor must exist");
    let delta = GrantDelta::Update {
        grant: grant.clone(),
        expected_revision,
    };
    let mut tx = pool.begin().await.expect("update tx must begin");
    // CARD 父投影事件：REVOKE kind → authorization_projection_head.revoke_fence
    // 递增（tenant 用捕获值：本测试命名空间不落 user_card source 行）。
    let projection = append_projection_event_with_metadata_and_tenant_in_tx(
        &mut tx,
        ProjectionAggregate::Card,
        namespace.card_id,
        EVENT_TYPE_REVOKE,
        Some(ProjectionEventMetadata {
            actor_id: namespace.user_id,
            operation_id: &namespace.operation_id(tag),
        }),
        Some(namespace.tenant_id),
    )
    .await
    .expect("REVOKE-class CARD parent event must append");
    // UPDATE delta 绑定抬升后的 fence（content 变化 → revoke-class 语义的
    // 落库形状；event_type 仍为 UPDATE，payload 类型/schema 不变）。
    // ProjectionEventIdentity 走有符号列域（i64），delta 请求走无符号合同域（u64）。
    let fence = projection.revoke_fence;
    let generation = projection.source_generation;
    append_delta_event(
        &mut *tx,
        &DeltaEventAppendRequest {
            tenant_id: namespace.tenant_id,
            card_id: Some(namespace.card_id),
            aggregate_type: AGGREGATE_TYPE.to_owned(),
            aggregate_id: namespace.aggregate_id,
            grant_id: grant.grant_id,
            event_id: namespace.event_id(tag),
            operation_id: namespace.operation_id(tag),
            event_type: DeltaEventType::Update,
            // v2 已被前置的中性 fence-0 控制组消费；真实链路必须延续到 v3，
            // 否则 uk_ade_target_version 唯一键（世代栅栏）会拒绝本 delta。
            base_version: 2,
            target_version: 3,
            source_generation: u64::try_from(generation).expect("generation must be positive"),
            revoke_fence: u64::try_from(fence).expect("fence must be non-negative"),
            invalidates_published_evidence: true,
            before_image_json: None,
            before_digest_hex: None,
            delta_json: serde_json::to_string(&delta).expect("UPDATE delta must serialize"),
            semantic_hash_hex: sha256_hex(&format!("update-fence/{tag}/semantic")),
            dependency_hash_hex: sha256_hex(&format!("update-fence/{tag}/dependency")),
            compiler_version: "itest-compiler-v1".to_owned(),
            next_attempt_at: None,
        },
    )
    .await
    .expect("UPDATE delta with the raised fence must append");
    tx.commit().await.expect("source mutation must commit");
    (projection, generation, fence)
}

/// aggregate-wide（`card_id IS NULL`）未发布撤权类 delta 必须拦截**任一卡**
/// 的严格证据读（2026-09-04 探针修订前普通 `card_id = ?` 会漏掉它们）：
/// 1. NULL-card REVOKE delta（event_type 臂）→ 严格读 `source_freshness_pending`；
/// 2. NULL-card fence 抬升 UPDATE delta（fence 臂）→ 同样拦截；
/// 3. 两者 SUCCEEDED 后恢复 Ready（水位追平， deny-biased EC 收敛）。
#[ignore]
#[tokio::test]
async fn aggregate_wide_null_card_revoke_delta_gates_any_card_evidence() {
    let Some(pool) = connect().await else {
        return;
    };
    let namespace = TestNamespace::new("null_card_gate");
    cleanup_namespace(&pool, &namespace).await;
    let scope = namespace.evidence_scope();

    // 干净发布一代：无任何 delta → Ready。
    let gen1 =
        stage_and_finalize_manifest(&pool, &namespace, 1, &[test_grant(&namespace, 1)], "gen1")
            .await;
    publish_ready_manifest(&pool, &namespace, &gen1, 1, None)
        .await
        .expect("first publication must succeed");
    let before = load_published_card_grant_evidence(&pool, &scope)
        .await
        .expect("evidence must be Ready when no unpublished delta exists");
    assert_eq!(before.gate.status, PublishedEvidenceGateStatus::Ready);

    // 1. NULL-card REVOKE（aggregate-wide 撤权）：任一卡作用域读取都必须 PENDING。
    insert_synthetic_delta(
        &pool,
        &namespace,
        "null_revoke",
        None,
        test_grant(&namespace, 201).grant_id,
        "REVOKE",
        true,
        1,
        2,
        2,
        1,
        "PENDING",
    )
    .await;
    let gated = load_published_card_grant_evidence(&pool, &scope)
        .await
        .expect_err("aggregate-wide revoke must gate the card read");
    match &gated {
        AuthorizationEvidenceError::NotReady(message) => assert!(
            message.contains("source_freshness_pending"),
            "unexpected NotReady code: {message}"
        ),
        other => panic!("expected NotReady (PENDING), got: {other:?}"),
    }
    assert_eq!(
        gated.as_gate_status(),
        PublishedEvidenceGateStatus::Pending,
        "the gate must classify as PENDING, never Corrupt"
    );
    // 事务内版本同样被拦截（同一探针谓词）。
    {
        let mut tx = pool.begin().await.unwrap();
        assert!(matches!(
            load_published_card_grant_evidence_in_tx(&mut tx, &scope).await,
            Err(AuthorizationEvidenceError::NotReady(_))
        ));
        tx.rollback().await.unwrap();
    }
    sqlx::query("UPDATE authorization_delta_event SET status = 'SUCCEEDED' WHERE event_id = ?")
        .bind(namespace.event_id("null_revoke"))
        .execute(&pool)
        .await
        .unwrap();
    let recovered = load_published_card_grant_evidence(&pool, &scope)
        .await
        .expect("evidence must recover once the NULL-card delta is SUCCEEDED");
    assert_eq!(recovered.gate.status, PublishedEvidenceGateStatus::Ready);

    // 2. NULL-card fence 抬升 UPDATE（fence 臂：2 > NULL-card 水位 1）同样拦截。
    insert_synthetic_delta(
        &pool,
        &namespace,
        "null_fence_update",
        None,
        test_grant(&namespace, 202).grant_id,
        "UPDATE",
        false,
        1,
        2,
        3,
        2,
        "PENDING",
    )
    .await;
    let fence_gated = load_published_card_grant_evidence(&pool, &scope).await;
    assert!(
        matches!(
            fence_gated,
            Err(AuthorizationEvidenceError::NotReady(ref message))
                if message.contains("source_freshness_pending")
        ),
        "fence-raising aggregate-wide UPDATE must gate the card read, got: {fence_gated:?}"
    );
    sqlx::query("UPDATE authorization_delta_event SET status = 'SUCCEEDED' WHERE event_id = ?")
        .bind(namespace.event_id("null_fence_update"))
        .execute(&pool)
        .await
        .unwrap();
    let settled = load_published_card_grant_evidence(&pool, &scope)
        .await
        .expect("evidence must recover once every NULL-card delta published");
    assert_eq!(settled.gate.status, PublishedEvidenceGateStatus::Ready);

    cleanup_namespace(&pool, &namespace).await;
}

/// NULL-card PENDING UPDATE delta 已被 NULL-card 已发布水位覆盖时**不得**误报
/// （NULL-safe `<=>` 水位关联的正面断言）：水位 5 覆盖 fence 5 的未发布
/// UPDATE；普通 `=` 关联下 `NULL = NULL` 恒 UNKNOWN → 水位折叠为 0，会把该
/// 行误报为 PENDING。未覆盖的 fence 6 仍然拦截（fence 臂不受影响）。
#[ignore]
#[tokio::test]
async fn null_card_pending_delta_covered_by_published_watermark_does_not_gate() {
    let Some(pool) = connect().await else {
        return;
    };
    let namespace = TestNamespace::new("null_card_watermark");
    cleanup_namespace(&pool, &namespace).await;
    let scope = namespace.evidence_scope();

    let gen1 =
        stage_and_finalize_manifest(&pool, &namespace, 1, &[test_grant(&namespace, 1)], "gen1")
            .await;
    publish_ready_manifest(&pool, &namespace, &gen1, 1, None)
        .await
        .expect("first publication must succeed");

    // 建立 NULL-card 已发布水位 = 5（SUCCEEDED 的 aggregate-wide fence 抬升行）。
    insert_synthetic_delta(
        &pool,
        &namespace,
        "null_watermark",
        None,
        test_grant(&namespace, 203).grant_id,
        "UPDATE",
        false,
        1,
        2,
        6,
        5,
        "SUCCEEDED",
    )
    .await;

    // 被水位覆盖的 NULL-card PENDING UPDATE（fence 5 ≤ 5）：不得拦截。
    insert_synthetic_delta(
        &pool,
        &namespace,
        "null_covered",
        None,
        test_grant(&namespace, 204).grant_id,
        "UPDATE",
        false,
        1,
        2,
        6,
        5,
        "PENDING",
    )
    .await;
    let covered = load_published_card_grant_evidence(&pool, &scope)
        .await
        .expect("watermark-covered NULL-card delta must NOT gate the read");
    assert_eq!(
        covered.gate.status,
        PublishedEvidenceGateStatus::Ready,
        "NULL-safe watermark correlation must admit a covered pending delta"
    );

    // 未覆盖的 NULL-card PENDING UPDATE（fence 6 > 5）：仍然拦截（fail-closed）。
    insert_synthetic_delta(
        &pool,
        &namespace,
        "null_uncovered",
        None,
        test_grant(&namespace, 205).grant_id,
        "UPDATE",
        false,
        1,
        2,
        7,
        6,
        "PENDING",
    )
    .await;
    let uncovered = load_published_card_grant_evidence(&pool, &scope).await;
    assert!(
        matches!(
            uncovered,
            Err(AuthorizationEvidenceError::NotReady(ref message))
                if message.contains("source_freshness_pending")
        ),
        "fence beyond the published NULL-card watermark must gate, got: {uncovered:?}"
    );
    sqlx::query("UPDATE authorization_delta_event SET status = 'SUCCEEDED' WHERE event_id = ?")
        .bind(namespace.event_id("null_uncovered"))
        .execute(&pool)
        .await
        .unwrap();
    let settled = load_published_card_grant_evidence(&pool, &scope)
        .await
        .expect("evidence must recover once the fence-raising delta published");
    assert_eq!(settled.gate.status, PublishedEvidenceGateStatus::Ready);

    cleanup_namespace(&pool, &namespace).await;
}

/// 收窄 UPDATE 的 stale-ALLOW 闭合（astral-db owner 侧机制链，真实仓储写入器）：
/// 1. 中性控制组：fence 未抬升的 UPDATE delta（no-op/provenance-only 更新的
///    落库形状）不触发 freshness 门（写突发不得自饥饿）；
/// 2. REVOKE kind 的 CARD 父投影事件经真实写入器把
///    `authorization_projection_head.revoke_fence` 抬到 1，UPDATE delta 绑定
///    该 fence → 未发布窗口内严格读 `source_freshness_pending`（门命中靠
///    fence 臂，event_type 仍为 UPDATE）；
/// 3. delta SUCCEEDED 后水位追平 → 恢复 Ready。
///
/// 剩余边界：authorization-content 变化 → REVOKE kind 的判定本身在
/// astral-trustgraph 三条 UPDATE 链路（跨 crate），由该 crate 的结构守卫与
/// 纯单测覆盖；本测试证明 astral-db owner 原语链（fence 抬升 → delta →
/// 门 → 恢复）在真实 MySQL 上成立。
#[ignore]
#[tokio::test]
async fn content_change_update_via_real_writers_raises_card_fence_and_gates_evidence() {
    let Some(pool) = connect().await else {
        return;
    };
    let namespace = TestNamespace::new("update_fence_gate");
    cleanup_namespace(&pool, &namespace).await;
    let scope = namespace.evidence_scope();

    let gen1 =
        stage_and_finalize_manifest(&pool, &namespace, 1, &[test_grant(&namespace, 1)], "gen1")
            .await;
    publish_ready_manifest(&pool, &namespace, &gen1, 1, None)
        .await
        .expect("first publication must succeed");
    let before = load_published_card_grant_evidence(&pool, &scope)
        .await
        .expect("clean publication must read Ready");
    assert_eq!(before.gate.status, PublishedEvidenceGateStatus::Ready);

    // ── 中性控制组：fence 未抬升的 UPDATE delta 不触发门 ──
    {
        let mut grant = test_grant(&namespace, 7);
        let expected_revision = GrantRevision::initial();
        grant.revision = expected_revision
            .next()
            .expect("revision successor must exist");
        let delta = GrantDelta::Update {
            grant: grant.clone(),
            expected_revision,
        };
        append_delta_event(
            &pool,
            &DeltaEventAppendRequest {
                tenant_id: namespace.tenant_id,
                card_id: Some(namespace.card_id),
                aggregate_type: AGGREGATE_TYPE.to_owned(),
                aggregate_id: namespace.aggregate_id,
                grant_id: grant.grant_id,
                event_id: namespace.event_id("neutral_update"),
                operation_id: namespace.operation_id("neutral_update"),
                event_type: DeltaEventType::Update,
                base_version: 1,
                target_version: 2,
                source_generation: 1,
                revoke_fence: 0,
                invalidates_published_evidence: false,
                before_image_json: None,
                before_digest_hex: None,
                delta_json: serde_json::to_string(&delta).expect("delta must serialize"),
                semantic_hash_hex: sha256_hex("neutral-update/semantic"),
                dependency_hash_hex: sha256_hex("neutral-update/dependency"),
                compiler_version: "itest-compiler-v1".to_owned(),
                next_attempt_at: None,
            },
        )
        .await
        .expect("neutral UPDATE delta must append");
        let neutral = load_published_card_grant_evidence(&pool, &scope)
            .await
            .expect("a fence-neutral UPDATE delta must NOT gate the read");
        assert_eq!(
            neutral.gate.status,
            PublishedEvidenceGateStatus::Ready,
            "provenance-only/no-op UPDATE updates must not PENDING the card"
        );
        sqlx::query("UPDATE authorization_delta_event SET status = 'SUCCEEDED' WHERE event_id = ?")
            .bind(namespace.event_id("neutral_update"))
            .execute(&pool)
            .await
            .unwrap();
    }

    // ── REVOKE-class CARD 父事件 + 绑定抬升 fence 的 UPDATE delta（真实写入器）──
    let (projection, generation, fence) =
        append_revoke_class_card_parent_and_update_delta(&pool, &namespace, "narrow_update").await;
    assert_eq!(
        (generation, fence),
        (1, 1),
        "first CARD event on a fresh head: REVOKE must raise the fence to 1"
    );

    // 真实 fence 抬升落库证明：head 行与 outbox 行（REVOKE kind）均可回读。
    let head: (i64, i64) = sqlx::query_as(
        "SELECT source_generation, revoke_fence FROM authorization_projection_head \
         WHERE aggregate_type = 'CARD' AND aggregate_id = ?",
    )
    .bind(namespace.card_id)
    .fetch_one(&pool)
    .await
    .expect("CARD head row must exist after the REVOKE-class append");
    assert_eq!(head, (1, 1), "head fence must record the REVOKE raise");
    let outbox_kind: (String,) =
        sqlx::query_as("SELECT event_type FROM authorization_projection_outbox WHERE event_id = ?")
            .bind(&projection.event_id)
            .fetch_one(&pool)
            .await
            .expect("parent outbox row must exist");
    assert_eq!(outbox_kind.0, "REVOKE", "parent event kind must be REVOKE");

    // 未发布窗口：fence 1 > 卡作用域已发布水位 0 → 严格读 PENDING。
    // 门命中靠 fence 臂（delta 行 event_type 仍为 UPDATE）。
    let gated = load_published_card_grant_evidence(&pool, &scope)
        .await
        .expect_err("the raised-fence unpublished delta must gate the read");
    match &gated {
        AuthorizationEvidenceError::NotReady(message) => assert!(
            message.contains("source_freshness_pending"),
            "unexpected NotReady code: {message}"
        ),
        other => panic!("expected NotReady (PENDING), got: {other:?}"),
    }
    assert_eq!(
        gated.as_gate_status(),
        PublishedEvidenceGateStatus::Pending,
        "the gate must classify as PENDING, never Corrupt"
    );
    {
        let mut tx = pool.begin().await.unwrap();
        assert!(matches!(
            load_published_card_grant_evidence_in_tx(&mut tx, &scope).await,
            Err(AuthorizationEvidenceError::NotReady(_))
        ));
        tx.rollback().await.unwrap();
    }
    let delta_kind: (String,) =
        sqlx::query_as("SELECT event_type FROM authorization_delta_event WHERE event_id = ?")
            .bind(namespace.event_id("narrow_update"))
            .fetch_one(&pool)
            .await
            .expect("narrowing UPDATE delta row must exist");
    assert_eq!(
        delta_kind.0, "UPDATE",
        "delta row keeps the UPDATE event type; the gate trips on the fence arm"
    );

    // 发布完成：水位追平（NULL-safe 关联下卡作用域水位 = 1）→ 恢复 Ready。
    sqlx::query("UPDATE authorization_delta_event SET status = 'SUCCEEDED' WHERE event_id = ?")
        .bind(namespace.event_id("narrow_update"))
        .execute(&pool)
        .await
        .unwrap();
    let after = load_published_card_grant_evidence(&pool, &scope)
        .await
        .expect("evidence must recover once the raised-fence delta published");
    assert_eq!(after.gate.status, PublishedEvidenceGateStatus::Ready);

    cleanup_namespace(&pool, &namespace).await;
}
