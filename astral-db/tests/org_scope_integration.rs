//! ORG_SCOPE 行政授权链真实 MySQL 集成测试（DB owner 切片）。
//!
//! 门禁（与既有 integration 套件同型）：
//! - 全部 `#[ignore]`：设置 `DATABASE_URL` 并显式 `--ignored` 才运行；
//! - 未设置 `DATABASE_URL` 或连接/迁移失败时默认 `[SKIP]`；
//! - `RUST_INTEGRATION_REQUIRED=1` 时依赖缺失直接 panic，绝不静默计 PASS。
//!
//! 覆盖：root init（治理证明 `org_authority_edge`/`bootstrap` + 能力范围绑定）→
//! attach → 逐级 grant（root→child→grandchild；精确 revision/delegable/covers，
//! scope 的 source resource tenant 全链保持不变）→ membership（物理卡绑定证明）→
//! claim/load_compile_input（flatten 全祖先依赖向量 + 恰好 1 个直接父
//! publication）/complete_publish（原子发布 + current CAS）→ reader Evidence →
//! grant 撤销/祖先撤销的即时 PENDING → 本级精确来源 mask → membership 撤销 →
//! 操作幂等重放。
//!
//! 运行前置（无法在 compile-only 层伪造，缺一即运行期失败）：
//! - full_schema_v4 基线 + org_scope 迁移已应用的 MySQL 8 实例
//!   （`connect_and_validate_schema` 只校验不执行 DDL）；
//! - membership 依赖真实物理卡绑定 join（`user_card` × `identity_card` ×
//!   `platform_user` × `tenant` × `tenant_domain_map`）：v4 基线库不含任何种子
//!   行，fixture 由本测试**自种自清**（保留段 920_000_2xx 常量：CHILD 租户行 +
//!   domain/user/identity_card/user_card），运行前逆序清理、结束精确回收，
//!   不要求也不触碰任何外部预置数据。
//!
//! 环境无 Docker/MySQL 时整体 SKIP；cleanup 只删本测试租户范围与自有 fixture
//! 常量 id 的行（org_scope_* 表之间无外键约束；fixture 表按逆 FK 序精确删除）。
//!
//! 新增覆盖（同一门禁与自种自清纪律）：新 outbox worker 合同的 durable 状态——
//! kind 限定"无发布完成"`complete_outbox_event`（MEMBERSHIP_CHANGED 载荷同源
//! 绑定通过；category-1 kind / 行内 kind 错配 / 畸形 / 跨租户 / 操作漂移载荷
//! 确定性拒绝且事件保持 LEASED；DONE + CAS 单调 + 租约清除 + 无 publication/
//! 新审计写 + 重复完成租约丢失）与 `propagate_subtree_root` 扇出排空（低批限
//! 下 `done=false` + 同锚点前沿重入排空宽兄弟、被推进子节点 root 置目标 +
//! 三计数同步 +1 + durable NODE 账标记 + child intent 派生、排空前完成拒绝/
//! 排空后完成成功、superseded 意图免写安全完成、同根 MOVE 后代仍失效一次）。
//! 每个 `#[tokio::test]` 使用互不重叠的保留段租户/fixture id，可并行运行。
//!
//! DEPENDENCY_PROPAGATE 波次覆盖（保留段 920_000_6xx，无 membership fixture）：
//! 根 grant source-head 变更只失效直接子单元、孙单元等每个锚点各自重新发布后
//! 才由派生 child intent 失效（锚点 publication 未跟上时 propagate/complete 双门
//! `anchor_publication_stale` 拒绝；旧意图被更新头取代时 superseded 免写安全
//! 完成）；mask apply/remove/revoke 波次在锚点单次重发布内合并失效且
//! generation-only（revoke_fence/relationship_revision 不变）、有界批
//! （selected == batch_limit 绝不 done）与 outbox-marker 幂等重入；MOVE 改挂时
//! 新父 intent 需新父当前 publication、被移动单元在重发布前无新父钉而不被选中。

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use sqlx::mysql::MySqlPoolOptions;
use sqlx::Row;
use tokio::sync::Barrier;

use astral_db::org_scope_repository::{
    validate_org_scope_schema_prerequisites, OrgApproveCommand, OrgApproveOutcome,
    OrgCompileInputCommand, OrgCreateRequestCommand, OrgDependencyPropagateCommand,
    OrgDependencyPropagateOutcome, OrgGovernanceProof, OrgGrantRevokeCommand, OrgMaskApplyCommand,
    OrgMaskRemoveCommand, OrgMembershipCreateCommand, OrgMembershipRevokeCommand,
    OrgMutationOutcome, OrgOutboxClaimCommand, OrgOutboxCompleteCommand, OrgOutboxEventKind,
    OrgOutboxFailCommand, OrgOutboxLease, OrgOutboxRenewCommand, OrgPublishCommand,
    OrgScopeGateState, OrgScopeRepository, OrgSubtreePropagateCommand, SqlxOrgScopeRepository,
    ORG_MAX_ACTIVE_MEMBERSHIPS_PER_USER, ORG_MAX_PROPAGATE_BATCH,
};
use astral_db::probe_org_scope_gate;
use astral_types::org_scope::{
    org_build_segment, org_manifest_digest_hex, OrgContribution, OrgDependencyPropagatePayload,
    OrgGrantRef, OrgGrantSeed, OrgManifestDigestMaterial, OrgMembership, OrgProvenance,
    OrgPublication, OrgReadRequest, OrgRequestPayload, OrgScope, OrgScopeKey, OrgSegmentContent,
    OrgSubtreePropagatePayload,
};
use astral_types::ValidityWindow;

const OWNER: &str = "org-e2e-worker-1";
const TOKEN_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const COMPILER_VERSION: &str = "org-e2e-compiler-v1";

const ROOT_TENANT: i64 = 920_000_101;
const CHILD_TENANT: i64 = 920_000_102;
const GRANDCHILD_TENANT: i64 = 920_000_103;

// ── membership 物理卡绑定 fixture 常量（保留段，避开长生命周期开发数据）────
// CI full_schema_v4 无种子行；membership 的物理绑定 join 需要下列 v4 行，
// 由本测试自种自清（见 `seed_membership_fixture` / `cleanup_membership_fixture`）。
/// platform_domain.domain_id：fixture 域（tenant_domain_map / user_card 外键）。
const FIXTURE_DOMAIN_ID: i64 = 920_000_201;
/// platform_user.user_id：fixture 用户（identity_card / user_card 外键）。
const FIXTURE_USER_ID: i64 = 920_000_202;
/// identity_card.card_id：fixture 身份卡（membership.identity_card_id）。
const FIXTURE_IDENTITY_CARD_ID: i64 = 920_000_203;
/// user_card.card_id：fixture 用户卡（membership.card_id）。
const FIXTURE_CARD_ID: i64 = 920_000_204;

/// 决策请求行初始 revision（org_scope_request.revision DDL DEFAULT 1；首次决策
/// 前无人推进）。审批命令的乐观栅栏必须携带调用方已读值。
const FRESH_REQUEST_REVISION: u64 = 1;

/// claim 侧 attempt 预算：与 fail 侧 `OrgOutboxFailCommand::max_attempts` 携带
/// 同一部署配置（≥ 1；事件最多被认领该值次，过期租约回收有界收敛）。取值与
/// service 层 `DEFAULT_MAX_EVENT_ATTEMPTS`（astral-trustgraph org_scope_projector
/// 默认 5）保持一致。
const CLAIM_MAX_ATTEMPTS: i64 = 5;

// ── 新 outbox worker 合同测试保留段（920_000_3xx）────────────────────────
// 与既有 e2e 的 101-103 租户及其 920_000_2xx 卡绑定 fixture 完全隔离：每个
// `#[tokio::test]` 一组互不重叠的 id，并行运行互不触碰对方行。
/// `complete_outbox_event` 合同测试：root + child。
const COMPLETE_ROOT_TENANT: i64 = 920_000_311;
const COMPLETE_CHILD_TENANT: i64 = 920_000_312;
const COMPLETE_TENANTS: [i64; 2] = [COMPLETE_ROOT_TENANT, COMPLETE_CHILD_TENANT];
/// 该测试专属物理卡绑定 fixture（独立于既有 e2e 的 920_000_2xx 段）。
const COMPLETE_FIXTURE: MembershipFixtureIds = MembershipFixtureIds {
    tenant_id: COMPLETE_CHILD_TENANT,
    domain_id: 920_000_211,
    user_id: 920_000_212,
    identity_card_id: 920_000_213,
    card_id: 920_000_214,
};

/// Membership-cap contract: two independent administrative roots, one user, and
/// a bounded set of physical user cards. The cap is global per user, never a
/// per-root quota; fixture ids stay in the isolated 920_000_4xx range.
const MEMBERSHIP_CAP_ROOT_A: i64 = 920_000_401;
const MEMBERSHIP_CAP_ROOT_B: i64 = 920_000_402;
const MEMBERSHIP_CAP_DOMAIN_ID: i64 = 920_000_421;
const MEMBERSHIP_CAP_USER_ID: i64 = 920_000_422;
const MEMBERSHIP_CAP_IDENTITY_CARD_ID: i64 = 920_000_423;
const MEMBERSHIP_CAP_CARD_BASE: i64 = 920_000_430;
const MEMBERSHIP_CAP_TENANTS: [i64; 2] = [MEMBERSHIP_CAP_ROOT_A, MEMBERSHIP_CAP_ROOT_B];

/// Concurrent membership-cap race fixture. It deliberately does not share any
/// tenant, user, card, or domain ID with the sequential cap fixture above.
const MEMBERSHIP_CAP_RACE_ROOT_A: i64 = 920_000_451;
const MEMBERSHIP_CAP_RACE_ROOT_B: i64 = 920_000_452;
const MEMBERSHIP_CAP_RACE_DOMAIN_ID: i64 = 920_000_471;
const MEMBERSHIP_CAP_RACE_USER_ID: i64 = 920_000_472;
const MEMBERSHIP_CAP_RACE_IDENTITY_CARD_ID: i64 = 920_000_473;
const MEMBERSHIP_CAP_RACE_CARD_BASE: i64 = 920_000_480;
const MEMBERSHIP_CAP_RACE_TENANTS: [i64; 2] =
    [MEMBERSHIP_CAP_RACE_ROOT_A, MEMBERSHIP_CAP_RACE_ROOT_B];

/// READ COMMITTED membership-cap race fixture. It begins with zero active
/// memberships, the range-only case that must be protected by the explicit
/// identity-card serialization anchor rather than InnoDB gap-lock behavior.
const MEMBERSHIP_CAP_RC_ROOT_A: i64 = 920_000_501;
const MEMBERSHIP_CAP_RC_ROOT_B: i64 = 920_000_502;
const MEMBERSHIP_CAP_RC_DOMAIN_ID: i64 = 920_000_521;
const MEMBERSHIP_CAP_RC_USER_ID: i64 = 920_000_522;
const MEMBERSHIP_CAP_RC_IDENTITY_CARD_ID: i64 = 920_000_523;
const MEMBERSHIP_CAP_RC_CARD_BASE: i64 = 920_000_530;
const MEMBERSHIP_CAP_RC_TENANTS: [i64; 2] = [MEMBERSHIP_CAP_RC_ROOT_A, MEMBERSHIP_CAP_RC_ROOT_B];

/// 传播排空测试拓扑：R → M → {A, B, C}；MOVE M 到第二根 Q（跨根）。
const DRAIN_ROOT_TENANT: i64 = 920_000_321;
const DRAIN_ANCHOR_TENANT: i64 = 920_000_322;
const DRAIN_SIBLING_A: i64 = 920_000_323;
const DRAIN_SIBLING_B: i64 = 920_000_324;
const DRAIN_SIBLING_C: i64 = 920_000_325;
const DRAIN_NEW_ROOT_TENANT: i64 = 920_000_326;
const DRAIN_TENANTS: [i64; 6] = [
    DRAIN_ROOT_TENANT,
    DRAIN_ANCHOR_TENANT,
    DRAIN_SIBLING_A,
    DRAIN_SIBLING_B,
    DRAIN_SIBLING_C,
    DRAIN_NEW_ROOT_TENANT,
];

/// superseded / 同根失效测试拓扑：R → {P1, P2}；M 挂 P1，X 挂 M；MOVE M 到
/// P2（同根 R，M.root 不变）。
const SUPER_ROOT_TENANT: i64 = 920_000_331;
const SUPER_PARENT_OLD: i64 = 920_000_332;
const SUPER_PARENT_NEW: i64 = 920_000_333;
const SUPER_ANCHOR_TENANT: i64 = 920_000_334;
const SUPER_LEAF_TENANT: i64 = 920_000_335;
const SUPER_TENANTS: [i64; 5] = [
    SUPER_ROOT_TENANT,
    SUPER_PARENT_OLD,
    SUPER_PARENT_NEW,
    SUPER_ANCHOR_TENANT,
    SUPER_LEAF_TENANT,
];

// ── outbox lease/fence contract fixtures (920_000_7xx) ──────────────────────
// These tests intentionally use a root-init event as the durable source of an
// outbox row. They exercise only the worker state machine after the source
// transaction has committed, and do not hand-insert an event that could bypass
// the source/outbox contract.
const OUTBOX_LEASE_TENANT: i64 = 920_000_701;
const OUTBOX_RETRY_TENANT: i64 = 920_000_702;
const OUTBOX_RACE_TENANT: i64 = 920_000_703;
const OUTBOX_LEASE_TENANTS: [i64; 1] = [OUTBOX_LEASE_TENANT];
const OUTBOX_RETRY_TENANTS: [i64; 1] = [OUTBOX_RETRY_TENANT];
const OUTBOX_RACE_TENANTS: [i64; 1] = [OUTBOX_RACE_TENANT];
const SECOND_OWNER: &str = "org-e2e-worker-2";
const SECOND_TOKEN_HEX: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

// ── read-gate and governance boundary fixtures (920_000_72x) ───────────────
const GATE_ATTACH_PARENT_TENANT: i64 = 920_000_721;
const GATE_UNAUTHORIZED_ROOT: i64 = 920_000_722;
const GATE_CHILD_TENANT: i64 = 920_000_723;
const GATE_FLAG_OFF_TENANT: i64 = 920_000_724;
const GATE_ATTACH_TEST_TENANTS: [i64; 3] = [
    GATE_ATTACH_PARENT_TENANT,
    GATE_UNAUTHORIZED_ROOT,
    GATE_CHILD_TENANT,
];

/// 治理准入证明：root-init 专用**注册** meta-permission 对
/// `org_authority_edge` + `bootstrap`（DB 层精确复核，非注册取值 fail-closed）
/// 与本次 PolicyEngine 评估通过的逐项能力范围（每项待发 scope 必须被至少一项
/// 独立覆盖，不得伪造单个宽泛 scope）。
fn root_governance_proof(root_tenant_id: i64, seed: &str) -> OrgGovernanceProof {
    OrgGovernanceProof {
        permission_resource: "org_authority_edge".into(),
        permission_action: "bootstrap".into(),
        admission_operation_id: unique_operation(&format!("adm-{seed}")),
        approved_capabilities: vec![capability_scope(root_tenant_id)],
    }
}

async fn connect() -> Option<sqlx::MySqlPool> {
    let required = std::env::var("RUST_INTEGRATION_REQUIRED").as_deref() == Ok("1");
    let url = match std::env::var("DATABASE_URL") {
        Ok(url) => url,
        Err(_) => {
            if required {
                panic!("RUST_INTEGRATION_REQUIRED=1: DATABASE_URL must be set");
            }
            eprintln!("[SKIP] DATABASE_URL must be set to run MySQL integration tests");
            return None;
        }
    };
    match astral_db::connect_and_validate_schema(&url).await {
        Ok(pool) => Some(pool),
        Err(error) => {
            if required {
                panic!("RUST_INTEGRATION_REQUIRED=1: cannot connect using DATABASE_URL: {error}");
            }
            eprintln!("[SKIP] Cannot connect using DATABASE_URL: {error}");
            None
        }
    }
}

async fn connect_read_committed() -> Option<sqlx::MySqlPool> {
    let required = std::env::var("RUST_INTEGRATION_REQUIRED").as_deref() == Ok("1");
    let url = match std::env::var("DATABASE_URL") {
        Ok(url) => url,
        Err(_) => {
            if required {
                panic!("RUST_INTEGRATION_REQUIRED=1: DATABASE_URL must be set");
            }
            eprintln!("[SKIP] DATABASE_URL must be set to run MySQL integration tests");
            return None;
        }
    };
    let validation_pool = match astral_db::connect_and_validate_schema(&url).await {
        Ok(pool) => pool,
        Err(error) => {
            if required {
                panic!("RUST_INTEGRATION_REQUIRED=1: cannot validate DATABASE_URL schema: {error}");
            }
            eprintln!("[SKIP] Cannot validate DATABASE_URL schema: {error}");
            return None;
        }
    };
    drop(validation_pool);
    // 慢 VM 上 min_connections 预热偶发超时：池创建失败后有界重试一次，仍失败
    // 才按 RUST_INTEGRATION_REQUIRED 语义判定（绝不静默计 PASS）。
    let mut pool_warmup_retried = false;
    let pool = loop {
        match MySqlPoolOptions::new()
            .max_connections(2)
            .min_connections(2)
            .acquire_timeout(Duration::from_secs(30))
            .after_connect(|connection, _| {
                Box::pin(async move {
                    // MySQL 时区偏移必须带分钟（'+00:00'）：'+00' 报
                    // ERROR 1298 Unknown or incorrect time zone，after_connect
                    // 失败会使 min_connections 预热永远无法满足。
                    sqlx::query("SET time_zone = '+00:00'")
                        .execute(&mut *connection)
                        .await?;
                    sqlx::query("SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED")
                        .execute(&mut *connection)
                        .await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
        {
            Ok(pool) => break pool,
            Err(error) => {
                if pool_warmup_retried {
                    if required {
                        panic!(
                            "RUST_INTEGRATION_REQUIRED=1: cannot connect using DATABASE_URL: {error}"
                        );
                    }
                    eprintln!("[SKIP] Cannot connect using DATABASE_URL: {error}");
                    return None;
                }
                pool_warmup_retried = true;
                // 慢 VM/前序测试清理风暴后偶发的连接预热停顿：backoff 后重试。
                tokio::time::sleep(Duration::from_secs(5)).await;
                eprintln!("[RETRY] RC pool warmup failed once; retrying: {error}");
            }
        }
    };
    let first = pool.acquire().await.expect("acquire first RC connection");
    let second = pool.acquire().await.expect("acquire second RC connection");
    for mut connection in [first, second] {
        let isolation: String = sqlx::query_scalar("SELECT @@session.transaction_isolation")
            .fetch_one(&mut *connection)
            .await
            .expect("read back MySQL session isolation");
        assert_eq!(
            isolation.to_ascii_uppercase(),
            "READ-COMMITTED",
            "membership-cap RC test must configure every connection as READ COMMITTED"
        );
    }
    Some(pool)
}

/// ORG_SCOPE 迁移前置门（cleanup 之前必须通过）：本套件只校验不执行 DDL，
/// `org_scope_*` 表必须已由迁移
/// `20260922000001_org_scope_authority.sql` 应用。缺表时立即 panic（给出迁移
/// 文件名与缺失清单），绝不落入 opaque 的 cleanup DELETE 失败。
async fn require_org_scope_schema(pool: &sqlx::MySqlPool) {
    validate_org_scope_schema_prerequisites(pool).await.expect(
        "ORG_SCOPE integration suite requires all 13 source tables and exact membership-cap \
             indexes from 20260922000001_org_scope_authority.sql before running with --ignored",
    );
}

fn unique_operation(seed: &str) -> String {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.subsec_nanos())
        .unwrap_or(0);
    format!("e2e-{pid}-{nanos}-{seed}")
}

fn scope_for(resource_tenant_id: i64, resource: &str, action: &str) -> OrgScope {
    OrgScope {
        resource_tenant_id,
        domain_id: None,
        resource: resource.to_owned(),
        action: action.to_owned(),
        validity: ValidityWindow::perpetual(),
    }
}

fn capability_scope(resource_tenant_id: i64) -> OrgScope {
    scope_for(resource_tenant_id, "*", "*")
}

/// 生成 n 个 `?` 占位符的 `IN (...)` 列表。
fn placeholders(count: usize) -> String {
    vec!["?"; count].join(", ")
}

/// `DELETE` 辅助：把给定租户 id 序列按 `group_count` 组重复绑定（语句含
/// `group_count` 组 `IN (...)` 谓词），固定 SQL、参数化绑定。
async fn delete_tenant_groups(
    pool: &sqlx::MySqlPool,
    sql: &str,
    group_count: usize,
    tenants: &[i64],
) {
    let mut delete = sqlx::query(sql);
    for _ in 0..group_count {
        for tenant_id in tenants {
            delete = delete.bind(*tenant_id);
        }
    }
    delete.execute(pool).await.expect("cleanup delete");
}

/// org_scope_* 清理（租户集参数化；表序与归属列语义与既有 `cleanup` 一致）：
/// 按每张表**实际的**归属列精确删除。org_scope_* 表之间无物理外键，顺序仅为
/// 依赖可读性（segment 经 join publication 的 tenant_id 定位，先于 publication
/// 删除）。注意 segment/dependency/grant/request 没有 `tenant_id` 列，绝不可
/// 用通用 `WHERE tenant_id` 模板。
async fn cleanup_tenant_set(pool: &sqlx::MySqlPool, tenants: &[i64]) {
    if tenants.is_empty() {
        return;
    }
    let id_list = placeholders(tenants.len());
    // 依赖钉：dependent / depends_on 两个租户列都要覆盖。
    delete_tenant_groups(
        pool,
        &format!(
            "DELETE FROM org_scope_dependency \
             WHERE dependent_tenant_id IN ({id_list}) OR depends_on_tenant_id IN ({id_list})"
        ),
        2,
        tenants,
    )
    .await;
    // 段无租户列：经 publication join 定位本租户封存的段。
    delete_tenant_groups(
        pool,
        &format!(
            "DELETE s FROM org_scope_segment s \
             INNER JOIN org_scope_publication p ON p.publication_id = s.publication_id \
             WHERE p.tenant_id IN ({id_list})"
        ),
        1,
        tenants,
    )
    .await;
    delete_tenant_groups(
        pool,
        &format!("DELETE FROM org_scope_current WHERE tenant_id IN ({id_list})"),
        1,
        tenants,
    )
    .await;
    delete_tenant_groups(
        pool,
        &format!("DELETE FROM org_scope_publication WHERE tenant_id IN ({id_list})"),
        1,
        tenants,
    )
    .await;
    delete_tenant_groups(
        pool,
        &format!("DELETE FROM org_scope_outbox WHERE tenant_id IN ({id_list})"),
        1,
        tenants,
    )
    .await;
    delete_tenant_groups(
        pool,
        &format!("DELETE FROM org_scope_revision WHERE tenant_id IN ({id_list})"),
        1,
        tenants,
    )
    .await;
    delete_tenant_groups(
        pool,
        &format!("DELETE FROM org_scope_mask WHERE tenant_id IN ({id_list})"),
        1,
        tenants,
    )
    .await;
    delete_tenant_groups(
        pool,
        &format!("DELETE FROM org_scope_membership WHERE tenant_id IN ({id_list})"),
        1,
        tenants,
    )
    .await;
    // 授权无 tenant_id 列：receiving / origin 两侧覆盖。
    delete_tenant_groups(
        pool,
        &format!(
            "DELETE FROM org_scope_grant \
             WHERE receiving_tenant_id IN ({id_list}) OR origin_tenant_id IN ({id_list})"
        ),
        2,
        tenants,
    )
    .await;
    // 请求无 tenant_id 列：requester / target / parent 三侧覆盖。
    delete_tenant_groups(
        pool,
        &format!(
            "DELETE FROM org_scope_request \
             WHERE requester_tenant_id IN ({id_list}) OR target_tenant_id IN ({id_list}) \
             OR parent_tenant_id IN ({id_list})"
        ),
        3,
        tenants,
    )
    .await;
    delete_tenant_groups(
        pool,
        &format!("DELETE FROM org_scope_audit WHERE tenant_id IN ({id_list})"),
        1,
        tenants,
    )
    .await;
    delete_tenant_groups(
        pool,
        &format!("DELETE FROM org_scope_operation WHERE tenant_id IN ({id_list})"),
        1,
        tenants,
    )
    .await;
    delete_tenant_groups(
        pool,
        &format!("DELETE FROM org_scope_node WHERE tenant_id IN ({id_list})"),
        1,
        tenants,
    )
    .await;
}

/// 既有 e2e 的 org_scope_* 清理（保持原三租户行为不变）。
async fn cleanup(pool: &sqlx::MySqlPool) {
    cleanup_tenant_set(pool, &[ROOT_TENANT, CHILD_TENANT, GRANDCHILD_TENANT]).await;
}

/// 物理卡绑定 fixture 的保留段 id 集（每个测试独立一组，允许并行运行）。
#[derive(Debug, Clone, Copy)]
struct MembershipFixtureIds {
    /// membership 租户（tenant 行同步自种，物理 join 需要）。
    tenant_id: i64,
    domain_id: i64,
    user_id: i64,
    identity_card_id: i64,
    card_id: i64,
}

/// 既有 e2e 的 fixture id 集（沿用原常量，行为不变）。
const E2E_MEMBERSHIP_FIXTURE: MembershipFixtureIds = MembershipFixtureIds {
    tenant_id: CHILD_TENANT,
    domain_id: FIXTURE_DOMAIN_ID,
    user_id: FIXTURE_USER_ID,
    identity_card_id: FIXTURE_IDENTITY_CARD_ID,
    card_id: FIXTURE_CARD_ID,
};

/// 逆 FK 序精确删除给定 fixture id 集的物理卡绑定行（仅保留段常量 id，不
/// 触碰任何其他数据）：user_card → identity_card → platform_user →
/// tenant_domain_map → tenant → platform_domain。
async fn cleanup_membership_fixture_for(pool: &sqlx::MySqlPool, ids: &MembershipFixtureIds) {
    sqlx::query("DELETE FROM user_card WHERE card_id = ?")
        .bind(ids.card_id)
        .execute(pool)
        .await
        .expect("cleanup fixture user_card");
    sqlx::query("DELETE FROM identity_card WHERE card_id = ?")
        .bind(ids.identity_card_id)
        .execute(pool)
        .await
        .expect("cleanup fixture identity_card");
    sqlx::query("DELETE FROM platform_user WHERE user_id = ?")
        .bind(ids.user_id)
        .execute(pool)
        .await
        .expect("cleanup fixture platform_user");
    sqlx::query("DELETE FROM tenant_domain_map WHERE tenant_id = ? AND domain_id = ?")
        .bind(ids.tenant_id)
        .bind(ids.domain_id)
        .execute(pool)
        .await
        .expect("cleanup fixture tenant_domain_map");
    sqlx::query("DELETE FROM tenant WHERE tenant_id = ?")
        .bind(ids.tenant_id)
        .execute(pool)
        .await
        .expect("cleanup fixture tenant");
    sqlx::query("DELETE FROM platform_domain WHERE domain_id = ?")
        .bind(ids.domain_id)
        .execute(pool)
        .await
        .expect("cleanup fixture platform_domain");
}

/// 按 FK 序种入给定 fixture id 集的物理卡绑定 join 所需 v4 行（CI
/// full_schema_v4 无种子行）：platform_domain → tenant（仅 membership 租户）→
/// tenant_domain_map → platform_user → identity_card → user_card。全部使用
/// 保留段常量 id 与 ACTIVE 状态；code/path 由 id 派生保证唯一；卡有效期窗口
/// 留空（join 侧 NULL 恒通过）。
async fn seed_membership_fixture_for(pool: &sqlx::MySqlPool, ids: &MembershipFixtureIds) {
    sqlx::query(
        "INSERT INTO platform_domain (domain_id, domain_code, domain_name, status) \
         VALUES (?, ?, ?, 'ACTIVE')",
    )
    .bind(ids.domain_id)
    .bind(format!("org_e2e_domain_{}", ids.domain_id))
    .bind("ORG E2E fixture domain")
    .execute(pool)
    .await
    .expect("seed fixture platform_domain");
    sqlx::query(
        "INSERT INTO tenant \
         (tenant_id, tenant_code, tenant_name, tenant_type, status, path, depth) \
         VALUES (?, ?, ?, 'ORGANIZATION', 'ACTIVE', ?, 0)",
    )
    .bind(ids.tenant_id)
    .bind(format!("org_e2e_tenant_{}", ids.tenant_id))
    .bind("ORG E2E fixture child tenant")
    .bind(format!("/{}", ids.tenant_id))
    .execute(pool)
    .await
    .expect("seed fixture tenant");
    sqlx::query(
        "INSERT INTO tenant_domain_map (tenant_id, domain_id, status) \
         VALUES (?, ?, 'ACTIVE')",
    )
    .bind(ids.tenant_id)
    .bind(ids.domain_id)
    .execute(pool)
    .await
    .expect("seed fixture tenant_domain_map");
    sqlx::query(
        "INSERT INTO platform_user \
         (user_id, user_no, display_name, source_type, status) \
         VALUES (?, ?, ?, 'LOCAL', 'ACTIVE')",
    )
    .bind(ids.user_id)
    .bind(format!("org_e2e_user_{}", ids.user_id))
    .bind("ORG E2E fixture user")
    .execute(pool)
    .await
    .expect("seed fixture platform_user");
    sqlx::query(
        "INSERT INTO identity_card (card_id, user_id, status, token_version) \
         VALUES (?, ?, 'ACTIVE', 1)",
    )
    .bind(ids.identity_card_id)
    .bind(ids.user_id)
    .execute(pool)
    .await
    .expect("seed fixture identity_card");
    sqlx::query(
        "INSERT INTO user_card \
         (card_id, user_id, domain_id, card_type, card_status, tenant_id) \
         VALUES (?, ?, ?, 'ORG_CARD', 'ACTIVE', ?)",
    )
    .bind(ids.card_id)
    .bind(ids.user_id)
    .bind(ids.domain_id)
    .bind(ids.tenant_id)
    .execute(pool)
    .await
    .expect("seed fixture user_card");
}

/// Membership-cap fixture cleanup: card rows first, then the one identity/user
/// pair and shared domain. Each root tenant is an isolated test-owned row.
async fn cleanup_membership_cap_fixture(
    pool: &sqlx::MySqlPool,
    tenants: [i64; 2],
    domain_id: i64,
    user_id: i64,
    identity_card_id: i64,
    card_base: i64,
) {
    let card_count = i64::try_from(ORG_MAX_ACTIVE_MEMBERSHIPS_PER_USER + 1)
        .expect("membership cap fixture card count fits i64");
    sqlx::query("DELETE FROM user_card WHERE card_id >= ? AND card_id < ?")
        .bind(card_base)
        .bind(card_base + card_count)
        .execute(pool)
        .await
        .expect("cleanup membership cap fixture cards");
    sqlx::query("DELETE FROM identity_card WHERE card_id = ?")
        .bind(identity_card_id)
        .execute(pool)
        .await
        .expect("cleanup membership cap fixture identity card");
    sqlx::query("DELETE FROM platform_user WHERE user_id = ?")
        .bind(user_id)
        .execute(pool)
        .await
        .expect("cleanup membership cap fixture user");
    sqlx::query("DELETE FROM tenant_domain_map WHERE domain_id = ?")
        .bind(domain_id)
        .execute(pool)
        .await
        .expect("cleanup membership cap fixture tenant domains");
    for tenant_id in tenants {
        sqlx::query("DELETE FROM tenant WHERE tenant_id = ?")
            .bind(tenant_id)
            .execute(pool)
            .await
            .expect("cleanup membership cap fixture tenant");
    }
    sqlx::query("DELETE FROM platform_domain WHERE domain_id = ?")
        .bind(domain_id)
        .execute(pool)
        .await
        .expect("cleanup membership cap fixture domain");
}

/// Seed an isolated membership-cap fixture. The caller supplies a disjoint
/// reserved ID range so ignored tests can run in parallel without cross-cleanup.
async fn seed_membership_cap_fixture(
    pool: &sqlx::MySqlPool,
    tenants: [i64; 2],
    domain_id: i64,
    user_id: i64,
    identity_card_id: i64,
    card_base: i64,
) {
    sqlx::query(
        "INSERT INTO platform_domain (domain_id, domain_code, domain_name, status) \
         VALUES (?, ?, ?, 'ACTIVE')",
    )
    .bind(domain_id)
    .bind(format!("org_e2e_domain_{domain_id}"))
    .bind("ORG E2E membership cap domain")
    .execute(pool)
    .await
    .expect("seed membership cap domain");
    for tenant_id in tenants {
        sqlx::query(
            "INSERT INTO tenant \
             (tenant_id, tenant_code, tenant_name, tenant_type, status, path, depth) \
             VALUES (?, ?, ?, 'ORGANIZATION', 'ACTIVE', ?, 0)",
        )
        .bind(tenant_id)
        .bind(format!("org_e2e_tenant_{tenant_id}"))
        .bind("ORG E2E membership cap root")
        .bind(format!("/{tenant_id}"))
        .execute(pool)
        .await
        .expect("seed membership cap tenant");
        sqlx::query(
            "INSERT INTO tenant_domain_map (tenant_id, domain_id, status) \
             VALUES (?, ?, 'ACTIVE')",
        )
        .bind(tenant_id)
        .bind(domain_id)
        .execute(pool)
        .await
        .expect("seed membership cap tenant domain");
    }
    sqlx::query(
        "INSERT INTO platform_user \
         (user_id, user_no, display_name, source_type, status) \
         VALUES (?, ?, ?, 'LOCAL', 'ACTIVE')",
    )
    .bind(user_id)
    .bind(format!("org_e2e_user_{user_id}"))
    .bind("ORG E2E membership cap user")
    .execute(pool)
    .await
    .expect("seed membership cap user");
    sqlx::query(
        "INSERT INTO identity_card (card_id, user_id, status, token_version) \
         VALUES (?, ?, 'ACTIVE', 1)",
    )
    .bind(identity_card_id)
    .bind(user_id)
    .execute(pool)
    .await
    .expect("seed membership cap identity card");
    for offset in 0..=ORG_MAX_ACTIVE_MEMBERSHIPS_PER_USER {
        let tenant_id = tenants[offset % tenants.len()];
        let card_id = card_base + i64::try_from(offset).expect("offset fits i64");
        sqlx::query(
            "INSERT INTO user_card \
             (card_id, user_id, domain_id, card_type, card_status, tenant_id) \
             VALUES (?, ?, ?, 'ORG_CARD', 'ACTIVE', ?)",
        )
        .bind(card_id)
        .bind(user_id)
        .bind(domain_id)
        .bind(tenant_id)
        .execute(pool)
        .await
        .expect("seed membership cap user card");
    }
}

/// 既有 e2e 的 fixture 清理（保持原行为不变）。
async fn cleanup_membership_fixture(pool: &sqlx::MySqlPool) {
    cleanup_membership_fixture_for(pool, &E2E_MEMBERSHIP_FIXTURE).await;
}

/// 既有 e2e 的 fixture 种入（保持原行为不变）。
async fn seed_membership_fixture(pool: &sqlx::MySqlPool) {
    seed_membership_fixture_for(pool, &E2E_MEMBERSHIP_FIXTURE).await;
}

fn contribution_from_grant(grant: &astral_types::org_scope::OrgGrant) -> OrgContribution {
    OrgContribution {
        grant_ref: OrgGrantRef {
            tenant_id: grant.receiving_tenant_id,
            grant_id: grant.grant_id.clone(),
            revision: grant.revision,
        },
        scope: grant.scope.clone(),
        delegable: grant.delegable,
        subject: grant.subject,
        provenance: OrgProvenance {
            origin_tenant_id: grant.origin_tenant_id,
            parent_chain: grant.parent.clone().into_iter().collect(),
            operation_id: grant.operation_id.clone(),
        },
    }
}

/// 读取单元 node 当前 generation（mask 的 `expected_unit_generation` 乐观栅栏
/// 输入；测试自身租户行，属本测试可控事实）。
async fn node_generation_of(pool: &sqlx::MySqlPool, tenant_id: i64) -> u64 {
    let generation: i64 =
        sqlx::query_scalar::<_, i64>("SELECT generation FROM org_scope_node WHERE tenant_id = ?")
            .bind(tenant_id)
            .fetch_one(pool)
            .await
            .expect("node row for generation read");
    u64::try_from(generation).expect("node generation is non-negative")
}

/// 认领租户队列首个到期事件 → load_compile_input（校验 flatten 依赖合同）→
/// 极简确定性编译 → complete_publish；返回本单元封存的 publication 供依赖
/// 向量断言。仅应在队列已被收敛循环清洗、首个事件即 category-1 投影触发时
/// 调用（播种期请使用 `converge_unit`）。
async fn claim_and_publish_unit(repo: &SqlxOrgScopeRepository, tenant_id: i64) -> OrgPublication {
    let claim = repo
        .claim_outbox_event(&OrgOutboxClaimCommand {
            tenant_id,
            worker_owner: OWNER.into(),
            worker_token_hex: TOKEN_HEX.into(),
            lease_seconds: 300,
            max_attempts: CLAIM_MAX_ATTEMPTS,
        })
        .await
        .expect("claim outbox event")
        .expect("a due outbox event must exist");
    publish_leased_unit(repo, &claim).await
}

/// 按真实 projector 的 category-1 路径消费一条已认领投影触发：
/// load_compile_input → 断言 flatten 依赖合同 → 极简确定性编译 → complete_publish。
async fn publish_leased_unit(
    repo: &SqlxOrgScopeRepository,
    claim: &OrgOutboxLease,
) -> OrgPublication {
    let input = repo
        .load_compile_input(&OrgCompileInputCommand {
            org_event_id: claim.org_event_id,
            worker_owner: OWNER.into(),
            worker_token_hex: TOKEN_HEX.into(),
        })
        .await
        .expect("compile input must load under the lease");

    // flatten 依赖合同（协调结论）：根单元零依赖、零父 publication；子单元恰好
    // 1 个直接父 publication，依赖向量钉住直接父并按 tenant 严格升序。
    if input.node.is_root() {
        assert!(
            input.dependencies.is_empty(),
            "administrative roots carry no ancestor dependency vector"
        );
        assert!(
            input.parent_publications.is_empty(),
            "root units carry zero parent publications"
        );
    } else {
        let parent_tenant_id = input
            .node
            .parent_tenant_id
            .expect("child node has an immediate administrative parent");
        assert_eq!(
            input.parent_publications.len(),
            1,
            "child units carry exactly one direct-parent publication"
        );
        assert_eq!(
            input.parent_publications[0].tenant_id, parent_tenant_id,
            "the single parent publication must be the direct administrative parent"
        );
        assert!(
            input
                .dependencies
                .iter()
                .any(|dependency| dependency.tenant_id == parent_tenant_id),
            "flattened dependency vector must pin the direct administrative parent"
        );
        for pair in input.dependencies.windows(2) {
            assert!(
                pair[0].tenant_id < pair[1].tenant_id,
                "flattened dependency vector must be strictly tenant-sorted"
            );
        }
    }

    let mut buckets: BTreeMap<(String, String), Vec<OrgContribution>> = BTreeMap::new();
    for grant in &input.grants {
        buckets
            .entry((grant.scope.resource.clone(), grant.scope.action.clone()))
            .or_default()
            .push(contribution_from_grant(grant));
    }
    let mut segments = Vec::new();
    for (index, ((resource, action), contributions)) in buckets.into_iter().enumerate() {
        let content = OrgSegmentContent {
            key: OrgScopeKey { resource, action },
            contributions,
        };
        segments.push(org_build_segment(index as u32, content).expect("segment build"));
    }
    let manifest_digest_hex = org_manifest_digest_hex(&OrgManifestDigestMaterial {
        tenant_id: input.node.tenant_id,
        root_tenant_id: input.node.root_tenant_id,
        generation: input.node.generation,
        relationship_revision: input.node.relationship_revision,
        revoke_fence: input.node.revoke_fence,
        dependencies: &input.dependencies,
        segments: &segments,
        compiler_version: COMPILER_VERSION,
        operation_id: &input.operation_id,
    })
    .expect("manifest digest");
    let publication = OrgPublication {
        tenant_id: input.node.tenant_id,
        root_tenant_id: input.node.root_tenant_id,
        generation: input.node.generation,
        relationship_revision: input.node.relationship_revision,
        revoke_fence: input.node.revoke_fence,
        dependencies: input.dependencies.clone(),
        manifest_digest_hex,
        compiler_version: COMPILER_VERSION.into(),
        segments,
        operation_id: input.operation_id.clone(),
    };
    // publish 幂等合同：同 (tenant, generation) 仅当 manifest 字节一致才幂等
    // 成功；manifest 绑定 event 的 operation_id（provenance），同代多触发
    // （projector 滞后/播种收敛时的常态）的第二次发布必然 manifest_conflict。
    // 与生产 worker 的最终语义一致：该触发按终态失败处理，单元证据以先到者
    // 封存的同代 publication 为准（内容逐字段相同，仅 provenance 不同）。
    if let Err(error) = repo
        .complete_publish(&OrgPublishCommand {
            org_event_id: claim.org_event_id,
            worker_owner: OWNER.into(),
            worker_token_hex: TOKEN_HEX.into(),
            publication: publication.clone(),
        })
        .await
    {
        if !error.to_string().contains("publish_manifest_conflict") {
            panic!("atomic publish must succeed: {error}");
        }
        repo.fail_outbox_event(&OrgOutboxFailCommand {
            org_event_id: claim.org_event_id,
            worker_owner: OWNER.into(),
            worker_token_hex: TOKEN_HEX.into(),
            error: "e2e convergence: superseded same-generation trigger".into(),
            retryable: false,
            backoff_seconds: 0,
            max_attempts: CLAIM_MAX_ATTEMPTS,
        })
        .await
        .expect("terminal-fail superseded same-generation trigger");
    }
    publication
}

/// 收敛记录：镜像真实 projector 的按 kind 派发，把一个租户队列消费到排空。
struct UnitConvergence {
    publications: Vec<OrgPublication>,
    dependency_outcomes: Vec<(String, OrgDependencyPropagateOutcome)>,
}

/// 播种期收敛循环。category-1 投影触发（NODE_CREATED / NODE_TOPOLOGY_CHANGED /
/// NODE_MUTATED）装载编译输入并封存 publication；DEPENDENCY_PROPAGATE /
/// SUBTREE_PROPAGATE 以租约内 typed 载荷驱动波次后 kind 限定完成（波次可能为
/// 已收敛空批，也可能被后续 source 变更 superseded——语义与生产 worker 一致）；
/// 其余种类确定性终态化。调用方按拓扑序（父先于子）收敛各单元。
async fn converge_unit(repo: &SqlxOrgScopeRepository, tenant_id: i64) -> UnitConvergence {
    let mut converged = UnitConvergence {
        publications: Vec::new(),
        dependency_outcomes: Vec::new(),
    };
    loop {
        let lease = repo
            .claim_outbox_event(&OrgOutboxClaimCommand {
                tenant_id,
                worker_owner: OWNER.into(),
                worker_token_hex: TOKEN_HEX.into(),
                lease_seconds: 300,
                max_attempts: CLAIM_MAX_ATTEMPTS,
            })
            .await
            .expect("claim outbox event during convergence");
        let Some(lease) = lease else {
            break;
        };
        let row_kind: OrgOutboxEventKind = lease.event_kind.parse().expect("known event kind");
        match row_kind {
            // 其余 7 类全部是 category-1 投影触发（NODE_* / GRANT_ISSUED /
            // GRANT_REVOKED / MASK_APPLIED / MASK_REMOVED）：装载编译输入并封存；
            // 同 (tenant, generation) + 同 manifest 的重复触发走 publish 幂等路径。
            OrgOutboxEventKind::DependencyPropagate => {
                let outcome = repo
                    .propagate_dependency_change(&dependency_propagate_command(
                        &lease,
                        ORG_MAX_PROPAGATE_BATCH,
                    ))
                    .await
                    .expect("dependency wave must succeed under a matched lease");
                repo.complete_outbox_event(&complete_command(
                    lease.org_event_id,
                    OrgOutboxEventKind::DependencyPropagate,
                ))
                .await
                .expect("dependency wave completion during convergence");
                converged
                    .dependency_outcomes
                    .push((lease.operation_id.clone(), outcome));
            }
            OrgOutboxEventKind::SubtreePropagate => {
                propagate_batch(repo, &lease, ORG_MAX_PROPAGATE_BATCH).await;
                repo.complete_outbox_event(&complete_command(
                    lease.org_event_id,
                    OrgOutboxEventKind::SubtreePropagate,
                ))
                .await
                .expect("subtree wave completion during convergence");
            }
            OrgOutboxEventKind::MembershipChanged => {
                // publication-free 合同类：kind 限定完成，绝不发布。
                repo.complete_outbox_event(&complete_command(
                    lease.org_event_id,
                    OrgOutboxEventKind::MembershipChanged,
                ))
                .await
                .expect("membership completion during convergence");
            }
            _ => {
                converged
                    .publications
                    .push(publish_leased_unit(repo, &lease).await);
            }
        }
    }
    converged
}

/// 在收敛记录中查找指定 operation 的依赖波次结果。
fn dependency_outcome_of<'a>(
    converged: &'a UnitConvergence,
    operation_id: &str,
) -> &'a OrgDependencyPropagateOutcome {
    &converged
        .dependency_outcomes
        .iter()
        .find(|(op, _)| op == operation_id)
        .unwrap_or_else(|| panic!("dependency intent for {operation_id} must be recorded"))
        .1
}

/// 1213 死锁是 InnoDB 并发插入的正常瞬态（两个 operation-ledger 插入竞争同一
/// PK 间隙）；生产 worker 与调用方都按有界重试处理。race fixture 每次竞态
/// 尝试至多重试 3 次——重试后输家拿到稳定的 cap 拒绝码，而非瞬态死锁。
async fn create_membership_retrying_deadlock(
    repo: &SqlxOrgScopeRepository,
    cmd: &OrgMembershipCreateCommand,
) -> Result<OrgMutationOutcome, astral_types::AstralError> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        match repo.create_membership(cmd).await {
            Ok(outcome) => return Ok(outcome),
            Err(error) if attempt < 3 && error.to_string().contains("1213") => continue,
            Err(error) => return Err(error),
        }
    }
}

/// Two claimers may transiently deadlock while both lock the same due candidate.
/// The transaction is rolled back by SQLx on 1213, so a bounded retry is safe;
/// any other repository result remains part of the test assertion.
async fn claim_outbox_retrying_deadlock(
    repo: &SqlxOrgScopeRepository,
    cmd: &OrgOutboxClaimCommand,
) -> Result<Option<OrgOutboxLease>, astral_types::AstralError> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        match repo.claim_outbox_event(cmd).await {
            Ok(outcome) => return Ok(outcome),
            Err(error) if attempt < 3 && error.to_string().contains("1213") => continue,
            Err(error) => return Err(error),
        }
    }
}

async fn parent_grant_of(pool: &sqlx::MySqlPool, receiving_tenant_id: i64) -> (String, u64) {
    let row = sqlx::query(
        "SELECT grant_id, revision FROM org_scope_grant \
         WHERE receiving_tenant_id = ? AND active = 1 ORDER BY grant_id LIMIT 1",
    )
    .bind(receiving_tenant_id)
    .fetch_one(pool)
    .await
    .expect("parent grant row");
    let revision: i64 = row.try_get("revision").expect("revision");
    (row.try_get("grant_id").expect("grant_id"), revision as u64)
}

#[tokio::test]
#[ignore]
async fn org_scope_authority_end_to_end() {
    let Some(pool) = connect().await else {
        return;
    };
    require_org_scope_schema(&pool).await;
    cleanup(&pool).await;
    cleanup_membership_fixture(&pool).await;
    seed_membership_fixture(&pool).await;
    let repo = SqlxOrgScopeRepository::new(pool.clone());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // gate：迁移已应用但租户未纳入 → TenantUnmanaged。
    assert_eq!(
        probe_org_scope_gate(&pool, ROOT_TENANT).await,
        OrgScopeGateState::TenantUnmanaged
    );

    // ── ROOT_INIT（治理证明 + 能力范围绑定）───────────────────────────────
    let init_request = repo
        .create_request(&OrgCreateRequestCommand {
            operation_id: unique_operation("req-root-init"),
            actor_user_id: 1,
            actor_tenant_id: Some(ROOT_TENANT),
            payload: OrgRequestPayload::RootInit {
                root_tenant_id: ROOT_TENANT,
                initial_grants: vec![OrgGrantSeed {
                    scope: scope_for(ROOT_TENANT, "learn_subject", "read"),
                    delegable: true,
                }],
            },
        })
        .await
        .expect("root init request");
    repo.approve_request(&OrgApproveCommand {
        request_id: init_request.request_id,
        expected_revision: FRESH_REQUEST_REVISION,
        approver_user_id: 1,
        approver_tenant_id: Some(ROOT_TENANT),
        operation_id: unique_operation("apr-root-init"),
        note: None,
        governance_proof: Some(root_governance_proof(ROOT_TENANT, "root-init")),
    })
    .await
    .expect("root init approval");

    // 幂等重放：同 operation_id 同 digest → replayed=true。
    let replay = repo
        .create_request(&OrgCreateRequestCommand {
            operation_id: init_request.operation_id.clone(),
            actor_user_id: 1,
            actor_tenant_id: Some(ROOT_TENANT),
            payload: OrgRequestPayload::RootInit {
                root_tenant_id: ROOT_TENANT,
                initial_grants: vec![OrgGrantSeed {
                    scope: scope_for(ROOT_TENANT, "learn_subject", "read"),
                    delegable: true,
                }],
            },
        })
        .await
        .expect("idempotent replay");
    assert!(replay.replayed);

    // 无治理证明的 ROOT_GRANT 必须 fail-closed。
    let root_grant_request = repo
        .create_request(&OrgCreateRequestCommand {
            operation_id: unique_operation("req-root-grant"),
            actor_user_id: 1,
            actor_tenant_id: Some(ROOT_TENANT),
            payload: OrgRequestPayload::RootGrant {
                root_tenant_id: ROOT_TENANT,
                scope: scope_for(ROOT_TENANT, "learn_subject", "write"),
                delegable: false,
            },
        })
        .await
        .expect("root grant request");
    let denied = repo
        .approve_request(&OrgApproveCommand {
            request_id: root_grant_request.request_id,
            expected_revision: FRESH_REQUEST_REVISION,
            approver_user_id: 1,
            approver_tenant_id: Some(ROOT_TENANT),
            operation_id: unique_operation("apr-root-grant-no-proof"),
            note: None,
            governance_proof: None,
        })
        .await
        .expect_err("root grant without governance proof must fail closed");
    assert!(denied.to_string().contains("governance_proof_required"));

    // ── ATTACH child ──────────────────────────────────────────────────────
    let attach_request = repo
        .create_request(&OrgCreateRequestCommand {
            operation_id: unique_operation("req-attach"),
            actor_user_id: 1,
            actor_tenant_id: Some(CHILD_TENANT),
            payload: OrgRequestPayload::Attach {
                child_tenant_id: CHILD_TENANT,
                parent_tenant_id: ROOT_TENANT,
            },
        })
        .await
        .expect("attach request");
    repo.approve_request(&OrgApproveCommand {
        request_id: attach_request.request_id,
        expected_revision: FRESH_REQUEST_REVISION,
        approver_user_id: 1,
        approver_tenant_id: Some(ROOT_TENANT),
        operation_id: unique_operation("apr-attach"),
        note: None,
        governance_proof: None,
    })
    .await
    .expect("attach approval");

    // ── GRANT：child ← root 持有 grant（精确 revision/delegable/covers）───
    // V1 资源租户恒等：child 收到的 scope 必须保留 source resource tenant
    // （ROOT），不得替换为 receiving tenant；delegable=true 供下一级转发。
    let (root_grant_id, root_grant_revision) = parent_grant_of(&pool, ROOT_TENANT).await;
    let grant_request = repo
        .create_request(&OrgCreateRequestCommand {
            operation_id: unique_operation("req-grant"),
            actor_user_id: 1,
            actor_tenant_id: Some(CHILD_TENANT),
            payload: OrgRequestPayload::Grant {
                receiving_tenant_id: CHILD_TENANT,
                parent_grant: OrgGrantRef {
                    tenant_id: ROOT_TENANT,
                    grant_id: root_grant_id.clone(),
                    revision: root_grant_revision,
                },
                scope: scope_for(ROOT_TENANT, "learn_subject", "read"),
                delegable: true,
                subject: None,
            },
        })
        .await
        .expect("grant request");
    repo.approve_request(&OrgApproveCommand {
        request_id: grant_request.request_id,
        expected_revision: FRESH_REQUEST_REVISION,
        approver_user_id: 1,
        approver_tenant_id: Some(ROOT_TENANT),
        operation_id: unique_operation("apr-grant"),
        note: None,
        governance_proof: None,
    })
    .await
    .expect("grant approval");

    // ── ATTACH grandchild + GRANT：grandchild ← child（深度 2 链路，供
    //    flatten 全祖先依赖向量与恰好 1 个直接父 publication 的编译输入断言）。
    let attach_grandchild_request = repo
        .create_request(&OrgCreateRequestCommand {
            operation_id: unique_operation("req-attach-grandchild"),
            actor_user_id: 1,
            actor_tenant_id: Some(GRANDCHILD_TENANT),
            payload: OrgRequestPayload::Attach {
                child_tenant_id: GRANDCHILD_TENANT,
                parent_tenant_id: CHILD_TENANT,
            },
        })
        .await
        .expect("grandchild attach request");
    repo.approve_request(&OrgApproveCommand {
        request_id: attach_grandchild_request.request_id,
        expected_revision: FRESH_REQUEST_REVISION,
        approver_user_id: 1,
        approver_tenant_id: Some(CHILD_TENANT),
        operation_id: unique_operation("apr-attach-grandchild"),
        note: None,
        governance_proof: None,
    })
    .await
    .expect("grandchild attach approval");
    let (child_grant_id, child_grant_revision) = parent_grant_of(&pool, CHILD_TENANT).await;
    let grandchild_grant_request = repo
        .create_request(&OrgCreateRequestCommand {
            operation_id: unique_operation("req-grant-grandchild"),
            actor_user_id: 1,
            actor_tenant_id: Some(GRANDCHILD_TENANT),
            payload: OrgRequestPayload::Grant {
                receiving_tenant_id: GRANDCHILD_TENANT,
                parent_grant: OrgGrantRef {
                    tenant_id: CHILD_TENANT,
                    grant_id: child_grant_id.clone(),
                    revision: child_grant_revision,
                },
                scope: scope_for(ROOT_TENANT, "learn_subject", "read"),
                delegable: false,
                subject: None,
            },
        })
        .await
        .expect("grandchild grant request");
    repo.approve_request(&OrgApproveCommand {
        request_id: grandchild_grant_request.request_id,
        expected_revision: FRESH_REQUEST_REVISION,
        approver_user_id: 1,
        approver_tenant_id: Some(CHILD_TENANT),
        operation_id: unique_operation("apr-grant-grandchild"),
        note: None,
        governance_proof: None,
    })
    .await
    .expect("grandchild grant approval");

    // ── membership（自种物理卡绑定 fixture：join 见文件头说明）────────────
    repo.create_membership(&OrgMembershipCreateCommand {
        operation_id: unique_operation("mem-add"),
        actor_user_id: 1,
        actor_tenant_id: Some(CHILD_TENANT),
        tenant_id: CHILD_TENANT,
        user_id: FIXTURE_USER_ID,
        identity_card_id: FIXTURE_IDENTITY_CARD_ID,
        card_id: FIXTURE_CARD_ID,
        validity: ValidityWindow::perpetual(),
    })
    .await
    .expect("membership create");

    // ── 发布 root → child → grandchild；reader 得 Evidence ───────────────
    // 播种期队列混有 attach 的 subtree/dependency 意图，必须走收敛循环。
    converge_unit(&repo, ROOT_TENANT).await;
    converge_unit(&repo, CHILD_TENANT).await;
    let grandchild_convergence = converge_unit(&repo, GRANDCHILD_TENANT).await;
    let grandchild_publication = grandchild_convergence
        .publications
        .last()
        .cloned()
        .expect("grandchild publication during convergence");
    // 深度 2 的 publication 必须钉住完整 flatten 祖先向量（root + 直接父），
    // 按 tenant 升序——不是只有直接父。
    assert_eq!(
        grandchild_publication
            .dependencies
            .iter()
            .map(|dependency| dependency.tenant_id)
            .collect::<Vec<_>>(),
        vec![ROOT_TENANT, CHILD_TENANT],
        "depth-2 publication must pin the full flattened ancestor vector"
    );
    let evidence = repo
        .load_admission_evidence(&astral_db::org_scope_repository::OrgAdmissionQuery {
            tenant_id: CHILD_TENANT,
            user_id: FIXTURE_USER_ID,
            card_id: FIXTURE_CARD_ID,
            identity_card_id: Some(FIXTURE_IDENTITY_CARD_ID),
            now_unix_seconds: now,
        })
        .await
        .expect("reader must not err on healthy state");
    let astral_types::org_scope::OrgAdmissionResult::Evidence(evidence) = evidence else {
        panic!("expected admission evidence, got {evidence:?}");
    };
    assert_eq!(evidence.node.tenant_id, CHILD_TENANT);
    assert_eq!(evidence.membership.user_id, FIXTURE_USER_ID);
    assert_eq!(evidence.publication.tenant_id, CHILD_TENANT);

    // 请求级匹配（OrgReadRequest × publication 贡献）口径自检：资源租户保持
    // source（ROOT）不变，请求按同一资源租户提出。
    let read = OrgReadRequest {
        resource: "learn_subject".into(),
        action: "read".into(),
        resource_tenant_id: ROOT_TENANT,
        domain_id: None,
        now_unix_seconds: now,
    };
    let matched = evidence
        .publication
        .segments
        .iter()
        .filter_map(|segment| astral_types::org_scope::org_decode_segment_content(segment).ok())
        .flat_map(|content| content.contributions)
        .any(|contribution| {
            astral_types::org_scope::org_contribution_matches_request(
                &contribution,
                &read,
                astral_types::org_scope::OrgSubjectFilter::SharedOnly,
            )
        });
    assert!(
        matched,
        "child publication must admit the shared read branch"
    );

    // ── membership 撤销 → 即时 MembershipMissing（不需重编译）────────────
    let membership_row = sqlx::query(
        "SELECT membership_id, revision FROM org_scope_membership \
         WHERE tenant_id = ? AND user_id = ? AND active = 1 LIMIT 1",
    )
    .bind(CHILD_TENANT)
    .bind(FIXTURE_USER_ID)
    .fetch_one(&pool)
    .await
    .expect("membership row");
    let membership_id: String = membership_row
        .try_get("membership_id")
        .expect("membership_id");
    let membership_revision: i64 = membership_row.try_get("revision").expect("revision");
    repo.revoke_membership(&OrgMembershipRevokeCommand {
        operation_id: unique_operation("mem-revoke"),
        actor_user_id: 1,
        actor_tenant_id: Some(CHILD_TENANT),
        tenant_id: CHILD_TENANT,
        membership_id: membership_id.clone(),
        expected_revision: membership_revision as u64,
    })
    .await
    .expect("membership revoke");
    let pending = repo
        .load_admission_evidence(&astral_db::org_scope_repository::OrgAdmissionQuery {
            tenant_id: CHILD_TENANT,
            user_id: FIXTURE_USER_ID,
            card_id: FIXTURE_CARD_ID,
            identity_card_id: None,
            now_unix_seconds: now,
        })
        .await
        .expect("reader must not err");
    assert!(matches!(
        pending,
        astral_types::org_scope::OrgAdmissionResult::Pending {
            code: astral_types::org_scope::OrgPendingCode::MembershipMissing,
            ..
        }
    ));
    // 恢复成员资格以便后续步骤。
    repo.create_membership(&OrgMembershipCreateCommand {
        operation_id: unique_operation("mem-readd"),
        actor_user_id: 1,
        actor_tenant_id: Some(CHILD_TENANT),
        tenant_id: CHILD_TENANT,
        user_id: FIXTURE_USER_ID,
        identity_card_id: FIXTURE_IDENTITY_CARD_ID,
        card_id: FIXTURE_CARD_ID,
        validity: ValidityWindow::perpetual(),
    })
    .await
    .expect("membership re-create");

    // ── 本级 mask（精确祖先来源剪裁）→ generation 推进 → child publication 过期
    // mask 只允许指向本单元已接收贡献 provenance 链上的**祖先** exact ref
    // （本级 grant 属 grant ledger 管辖，mask_target_self 拒绝）；这里钉住 child
    // 所收贡献的直接来源：root 的初始 grant（精确 revision）。
    let child_unit_generation = node_generation_of(&pool, CHILD_TENANT).await;
    repo.apply_mask(&OrgMaskApplyCommand {
        operation_id: unique_operation("mask-apply"),
        actor_user_id: 1,
        actor_tenant_id: Some(CHILD_TENANT),
        tenant_id: CHILD_TENANT,
        target: OrgGrantRef {
            tenant_id: ROOT_TENANT,
            grant_id: root_grant_id.clone(),
            revision: root_grant_revision,
        },
        expected_unit_generation: child_unit_generation,
        reason: Some("e2e exact-source mask".into()),
    })
    .await
    .expect("mask apply");
    let pending = repo
        .load_admission_evidence(&astral_db::org_scope_repository::OrgAdmissionQuery {
            tenant_id: CHILD_TENANT,
            user_id: FIXTURE_USER_ID,
            card_id: FIXTURE_CARD_ID,
            identity_card_id: None,
            now_unix_seconds: now,
        })
        .await
        .expect("reader must not err");
    assert!(matches!(
        pending,
        astral_types::org_scope::OrgAdmissionResult::Pending {
            code: astral_types::org_scope::OrgPendingCode::SourceGenerationAdvanced,
            ..
        }
    ));

    // mask 推进本单元 head 后 reader 先报 SourceGenerationAdvanced；重发布使
    // child 重新对齐当前 head，后续祖先撤销的 DependencyStale 才可被单独观察。
    converge_unit(&repo, CHILD_TENANT).await;

    // ── 祖先撤销即时可见：撤 root 初始 grant → child/grandchild 依赖钉失配 →
    //    DependencyStale（flatten 依赖使任意层级祖先失效不需等待父重发布）。
    repo.revoke_grant(&OrgGrantRevokeCommand {
        operation_id: unique_operation("grant-revoke-root"),
        actor_user_id: 1,
        actor_tenant_id: Some(ROOT_TENANT),
        receiving_tenant_id: ROOT_TENANT,
        grant_id: root_grant_id.clone(),
        expected_revision: root_grant_revision,
        reason: Some("e2e revocation".into()),
    })
    .await
    .expect("root grant revoke");
    let pending = repo
        .load_admission_evidence(&astral_db::org_scope_repository::OrgAdmissionQuery {
            tenant_id: CHILD_TENANT,
            user_id: FIXTURE_USER_ID,
            card_id: FIXTURE_CARD_ID,
            identity_card_id: None,
            now_unix_seconds: now,
        })
        .await
        .expect("reader must not err");
    assert!(matches!(
        pending,
        astral_types::org_scope::OrgAdmissionResult::Pending {
            code: astral_types::org_scope::OrgPendingCode::DependencyStale,
            ..
        }
    ));

    // ── DETACH child：旧链 grants 撤销 + root 改为自身 ────────────────────
    let detach_request = repo
        .create_request(&OrgCreateRequestCommand {
            operation_id: unique_operation("req-detach"),
            actor_user_id: 1,
            actor_tenant_id: Some(CHILD_TENANT),
            payload: OrgRequestPayload::Detach {
                child_tenant_id: CHILD_TENANT,
            },
        })
        .await
        .expect("detach request");
    let outcome = repo
        .approve_request(&OrgApproveCommand {
            request_id: detach_request.request_id,
            expected_revision: FRESH_REQUEST_REVISION,
            approver_user_id: 1,
            approver_tenant_id: Some(ROOT_TENANT),
            operation_id: unique_operation("apr-detach"),
            note: None,
            governance_proof: None,
        })
        .await
        .expect("detach approval");
    assert!(outcome
        .records
        .iter()
        .any(|record| record.record_kind == "NODE_DETACHED"));
    cleanup_membership_fixture(&pool).await;
    cleanup(&pool).await;
}

#[tokio::test]
#[ignore]
async fn org_scope_membership_cap_is_global_fail_closed_and_revoke_frees_capacity() {
    let Some(pool) = connect().await else {
        return;
    };
    require_org_scope_schema(&pool).await;
    cleanup_tenant_set(&pool, &MEMBERSHIP_CAP_TENANTS).await;
    cleanup_membership_cap_fixture(
        &pool,
        MEMBERSHIP_CAP_TENANTS,
        MEMBERSHIP_CAP_DOMAIN_ID,
        MEMBERSHIP_CAP_USER_ID,
        MEMBERSHIP_CAP_IDENTITY_CARD_ID,
        MEMBERSHIP_CAP_CARD_BASE,
    )
    .await;
    seed_membership_cap_fixture(
        &pool,
        MEMBERSHIP_CAP_TENANTS,
        MEMBERSHIP_CAP_DOMAIN_ID,
        MEMBERSHIP_CAP_USER_ID,
        MEMBERSHIP_CAP_IDENTITY_CARD_ID,
        MEMBERSHIP_CAP_CARD_BASE,
    )
    .await;
    let repo = SqlxOrgScopeRepository::new(pool.clone());

    for (index, tenant_id) in MEMBERSHIP_CAP_TENANTS.into_iter().enumerate() {
        submit_and_approve(
            &repo,
            OrgRequestPayload::RootInit {
                root_tenant_id: tenant_id,
                initial_grants: Vec::new(),
            },
            tenant_id,
            None,
            if index == 0 {
                "membership-cap-root-a"
            } else {
                "membership-cap-root-b"
            },
            Some(root_governance_proof(tenant_id, "membership-cap-root")),
        )
        .await;
    }

    let expired = ValidityWindow::between(1, 2);
    let mut revoked_membership_id = None;
    for offset in 0..ORG_MAX_ACTIVE_MEMBERSHIPS_PER_USER {
        let tenant_id = MEMBERSHIP_CAP_TENANTS[offset % MEMBERSHIP_CAP_TENANTS.len()];
        let card_id = MEMBERSHIP_CAP_CARD_BASE + i64::try_from(offset).expect("offset fits i64");
        let outcome = repo
            .create_membership(&OrgMembershipCreateCommand {
                operation_id: unique_operation(&format!("membership-cap-fill-{offset}")),
                actor_user_id: 1,
                actor_tenant_id: Some(tenant_id),
                tenant_id,
                user_id: MEMBERSHIP_CAP_USER_ID,
                identity_card_id: MEMBERSHIP_CAP_IDENTITY_CARD_ID,
                card_id,
                validity: if offset == 0 {
                    expired
                } else {
                    ValidityWindow::perpetual()
                },
            })
            .await
            .expect("membership below cap must be created");
        if offset == 0 {
            revoked_membership_id = Some(outcome.records[0].subject_id.clone());
        }
    }
    let active_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM org_scope_membership WHERE user_id = ? AND active = 1",
    )
    .bind(MEMBERSHIP_CAP_USER_ID)
    .fetch_one(&pool)
    .await
    .expect("count active capped memberships");
    assert_eq!(
        active_count,
        i64::try_from(ORG_MAX_ACTIVE_MEMBERSHIPS_PER_USER).expect("cap fits i64")
    );

    let rejected_operation = unique_operation("membership-cap-reject");
    let rejected_card_id = MEMBERSHIP_CAP_CARD_BASE
        + i64::try_from(ORG_MAX_ACTIVE_MEMBERSHIPS_PER_USER).expect("cap fits i64");
    let rejected = repo
        .create_membership(&OrgMembershipCreateCommand {
            operation_id: rejected_operation.clone(),
            actor_user_id: 1,
            actor_tenant_id: Some(MEMBERSHIP_CAP_ROOT_A),
            tenant_id: MEMBERSHIP_CAP_ROOT_A,
            user_id: MEMBERSHIP_CAP_USER_ID,
            identity_card_id: MEMBERSHIP_CAP_IDENTITY_CARD_ID,
            card_id: rejected_card_id,
            validity: ValidityWindow::perpetual(),
        })
        .await
        .expect_err("global membership cap must reject another root/card");
    assert!(
        rejected
            .to_string()
            .contains("code=org_scope.membership_user_cap_exceeded;cap="),
        "unexpected membership-cap error: {rejected}"
    );
    for (table, column) in [
        ("org_scope_operation", "operation_id"),
        ("org_scope_audit", "operation_id"),
        ("org_scope_outbox", "operation_id"),
    ] {
        let sql = format!("SELECT COUNT(*) FROM {table} WHERE {column} = ?");
        let count: i64 = sqlx::query_scalar(&sql)
            .bind(&rejected_operation)
            .fetch_one(&pool)
            .await
            .expect("rejected membership leaves no durable artifacts");
        assert_eq!(count, 0, "rejected membership leaked into {table}");
    }

    let revoked_membership_id = revoked_membership_id.expect("first membership id");
    let revision: i64 = sqlx::query_scalar(
        "SELECT revision FROM org_scope_membership WHERE membership_id = ? AND active = 1",
    )
    .bind(&revoked_membership_id)
    .fetch_one(&pool)
    .await
    .expect("expired active membership must remain revocable");
    repo.revoke_membership(&OrgMembershipRevokeCommand {
        operation_id: unique_operation("membership-cap-revoke-expired"),
        actor_user_id: 1,
        actor_tenant_id: Some(MEMBERSHIP_CAP_ROOT_A),
        tenant_id: MEMBERSHIP_CAP_ROOT_A,
        membership_id: revoked_membership_id,
        expected_revision: u64::try_from(revision).expect("membership revision is non-negative"),
    })
    .await
    .expect("revoke before replacement frees capacity");

    repo.create_membership(&OrgMembershipCreateCommand {
        operation_id: unique_operation("membership-cap-replacement"),
        actor_user_id: 1,
        actor_tenant_id: Some(MEMBERSHIP_CAP_ROOT_A),
        tenant_id: MEMBERSHIP_CAP_ROOT_A,
        user_id: MEMBERSHIP_CAP_USER_ID,
        identity_card_id: MEMBERSHIP_CAP_IDENTITY_CARD_ID,
        card_id: rejected_card_id,
        validity: ValidityWindow::perpetual(),
    })
    .await
    .expect("revoke-then-create must restore exactly one available slot");
    let final_active_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM org_scope_membership WHERE user_id = ? AND active = 1",
    )
    .bind(MEMBERSHIP_CAP_USER_ID)
    .fetch_one(&pool)
    .await
    .expect("count active memberships after replacement");
    assert_eq!(
        final_active_count,
        i64::try_from(ORG_MAX_ACTIVE_MEMBERSHIPS_PER_USER).expect("cap fits i64")
    );

    cleanup_membership_cap_fixture(
        &pool,
        MEMBERSHIP_CAP_TENANTS,
        MEMBERSHIP_CAP_DOMAIN_ID,
        MEMBERSHIP_CAP_USER_ID,
        MEMBERSHIP_CAP_IDENTITY_CARD_ID,
        MEMBERSHIP_CAP_CARD_BASE,
    )
    .await;
    cleanup_tenant_set(&pool, &MEMBERSHIP_CAP_TENANTS).await;
}

#[tokio::test]
#[ignore]
async fn org_scope_membership_cap_serializes_concurrent_distinct_cards() {
    let Some(pool) = connect().await else {
        return;
    };
    require_org_scope_schema(&pool).await;
    cleanup_tenant_set(&pool, &MEMBERSHIP_CAP_RACE_TENANTS).await;
    cleanup_membership_cap_fixture(
        &pool,
        MEMBERSHIP_CAP_RACE_TENANTS,
        MEMBERSHIP_CAP_RACE_DOMAIN_ID,
        MEMBERSHIP_CAP_RACE_USER_ID,
        MEMBERSHIP_CAP_RACE_IDENTITY_CARD_ID,
        MEMBERSHIP_CAP_RACE_CARD_BASE,
    )
    .await;
    seed_membership_cap_fixture(
        &pool,
        MEMBERSHIP_CAP_RACE_TENANTS,
        MEMBERSHIP_CAP_RACE_DOMAIN_ID,
        MEMBERSHIP_CAP_RACE_USER_ID,
        MEMBERSHIP_CAP_RACE_IDENTITY_CARD_ID,
        MEMBERSHIP_CAP_RACE_CARD_BASE,
    )
    .await;
    let setup_repo = SqlxOrgScopeRepository::new(pool.clone());

    for (index, tenant_id) in MEMBERSHIP_CAP_RACE_TENANTS.into_iter().enumerate() {
        submit_and_approve(
            &setup_repo,
            OrgRequestPayload::RootInit {
                root_tenant_id: tenant_id,
                initial_grants: Vec::new(),
            },
            tenant_id,
            None,
            if index == 0 {
                "membership-cap-race-root-a"
            } else {
                "membership-cap-race-root-b"
            },
            Some(root_governance_proof(tenant_id, "membership-cap-race-root")),
        )
        .await;
    }

    for offset in 0..(ORG_MAX_ACTIVE_MEMBERSHIPS_PER_USER - 1) {
        let tenant_id = MEMBERSHIP_CAP_RACE_TENANTS[offset % MEMBERSHIP_CAP_RACE_TENANTS.len()];
        setup_repo
            .create_membership(&OrgMembershipCreateCommand {
                operation_id: unique_operation(&format!("membership-cap-race-fill-{offset}")),
                actor_user_id: 1,
                actor_tenant_id: Some(tenant_id),
                tenant_id,
                user_id: MEMBERSHIP_CAP_RACE_USER_ID,
                identity_card_id: MEMBERSHIP_CAP_RACE_IDENTITY_CARD_ID,
                card_id: MEMBERSHIP_CAP_RACE_CARD_BASE
                    + i64::try_from(offset).expect("offset fits i64"),
                validity: ValidityWindow::perpetual(),
            })
            .await
            .expect("pre-cap membership must be created");
    }

    let barrier = Arc::new(Barrier::new(3));
    let first_pool = pool.clone();
    let first_barrier = barrier.clone();
    let first = tokio::spawn(async move {
        first_barrier.wait().await;
        let repo = SqlxOrgScopeRepository::new(first_pool);
        let cmd = OrgMembershipCreateCommand {
            operation_id: unique_operation("membership-cap-race-a"),
            actor_user_id: 1,
            actor_tenant_id: Some(MEMBERSHIP_CAP_RACE_ROOT_A),
            tenant_id: MEMBERSHIP_CAP_RACE_ROOT_A,
            user_id: MEMBERSHIP_CAP_RACE_USER_ID,
            identity_card_id: MEMBERSHIP_CAP_RACE_IDENTITY_CARD_ID,
            // 卡片播种按 offset%2 轮换租户（CAP=8 为偶）：base+CAP 属 ROOT_A、
            // base+CAP-1 属 ROOT_B——竞态卡必须与请求租户精确绑定，错位即
            // membership_physical_card_binding_invalid。
            card_id: MEMBERSHIP_CAP_RACE_CARD_BASE
                + i64::try_from(ORG_MAX_ACTIVE_MEMBERSHIPS_PER_USER).expect("cap fits i64"),
            validity: ValidityWindow::perpetual(),
        };
        create_membership_retrying_deadlock(&repo, &cmd).await
    });
    let second_pool = pool.clone();
    let second_barrier = barrier.clone();
    let second = tokio::spawn(async move {
        second_barrier.wait().await;
        let repo = SqlxOrgScopeRepository::new(second_pool);
        let cmd = OrgMembershipCreateCommand {
            operation_id: unique_operation("membership-cap-race-b"),
            actor_user_id: 1,
            actor_tenant_id: Some(MEMBERSHIP_CAP_RACE_ROOT_B),
            tenant_id: MEMBERSHIP_CAP_RACE_ROOT_B,
            user_id: MEMBERSHIP_CAP_RACE_USER_ID,
            identity_card_id: MEMBERSHIP_CAP_RACE_IDENTITY_CARD_ID,
            // 见 race-a：base+CAP-1 属 ROOT_B。
            card_id: MEMBERSHIP_CAP_RACE_CARD_BASE
                + i64::try_from(ORG_MAX_ACTIVE_MEMBERSHIPS_PER_USER - 1).expect("cap fits i64"),
            validity: ValidityWindow::perpetual(),
        };
        create_membership_retrying_deadlock(&repo, &cmd).await
    });
    barrier.wait().await;
    let first = first.await.expect("first membership-cap task join");
    let second = second.await.expect("second membership-cap task join");
    let outcomes = [first, second];
    let outcome_debug = format!("{outcomes:?}");
    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.is_ok()).count(),
        1,
        "exactly one boundary membership may commit; outcomes: {outcome_debug}"
    );
    for error in outcomes.iter().filter_map(|outcome| outcome.as_ref().err()) {
        assert!(
            error
                .to_string()
                .contains("code=org_scope.membership_user_cap_exceeded;cap="),
            "concurrent loser must fail with the stable cap code, got {error}"
        );
    }
    let active_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM org_scope_membership WHERE user_id = ? AND active = 1",
    )
    .bind(MEMBERSHIP_CAP_RACE_USER_ID)
    .fetch_one(&pool)
    .await
    .expect("count memberships after concurrent boundary race");
    assert_eq!(
        active_count,
        i64::try_from(ORG_MAX_ACTIVE_MEMBERSHIPS_PER_USER).expect("cap fits i64")
    );

    cleanup_membership_cap_fixture(
        &pool,
        MEMBERSHIP_CAP_RACE_TENANTS,
        MEMBERSHIP_CAP_RACE_DOMAIN_ID,
        MEMBERSHIP_CAP_RACE_USER_ID,
        MEMBERSHIP_CAP_RACE_IDENTITY_CARD_ID,
        MEMBERSHIP_CAP_RACE_CARD_BASE,
    )
    .await;
    cleanup_tenant_set(&pool, &MEMBERSHIP_CAP_RACE_TENANTS).await;
}

#[tokio::test]
#[ignore]
async fn org_scope_membership_cap_serializes_boundary_race_at_read_committed() {
    let Some(pool) = connect_read_committed().await else {
        return;
    };
    require_org_scope_schema(&pool).await;
    cleanup_tenant_set(&pool, &MEMBERSHIP_CAP_RC_TENANTS).await;
    cleanup_membership_cap_fixture(
        &pool,
        MEMBERSHIP_CAP_RC_TENANTS,
        MEMBERSHIP_CAP_RC_DOMAIN_ID,
        MEMBERSHIP_CAP_RC_USER_ID,
        MEMBERSHIP_CAP_RC_IDENTITY_CARD_ID,
        MEMBERSHIP_CAP_RC_CARD_BASE,
    )
    .await;
    seed_membership_cap_fixture(
        &pool,
        MEMBERSHIP_CAP_RC_TENANTS,
        MEMBERSHIP_CAP_RC_DOMAIN_ID,
        MEMBERSHIP_CAP_RC_USER_ID,
        MEMBERSHIP_CAP_RC_IDENTITY_CARD_ID,
        MEMBERSHIP_CAP_RC_CARD_BASE,
    )
    .await;
    let setup_repo = SqlxOrgScopeRepository::new(pool.clone());
    for (index, tenant_id) in MEMBERSHIP_CAP_RC_TENANTS.into_iter().enumerate() {
        submit_and_approve(
            &setup_repo,
            OrgRequestPayload::RootInit {
                root_tenant_id: tenant_id,
                initial_grants: Vec::new(),
            },
            tenant_id,
            None,
            if index == 0 {
                "membership-cap-rc-root-a"
            } else {
                "membership-cap-rc-root-b"
            },
            Some(root_governance_proof(tenant_id, "membership-cap-rc-root")),
        )
        .await;
    }
    for offset in 0..(ORG_MAX_ACTIVE_MEMBERSHIPS_PER_USER - 1) {
        let tenant_id = MEMBERSHIP_CAP_RC_TENANTS[offset % MEMBERSHIP_CAP_RC_TENANTS.len()];
        setup_repo
            .create_membership(&OrgMembershipCreateCommand {
                operation_id: unique_operation(&format!("membership-cap-rc-fill-{offset}")),
                actor_user_id: 1,
                actor_tenant_id: Some(tenant_id),
                tenant_id,
                user_id: MEMBERSHIP_CAP_RC_USER_ID,
                identity_card_id: MEMBERSHIP_CAP_RC_IDENTITY_CARD_ID,
                card_id: MEMBERSHIP_CAP_RC_CARD_BASE
                    + i64::try_from(offset).expect("offset fits i64"),
                validity: ValidityWindow::perpetual(),
            })
            .await
            .expect("READ COMMITTED pre-cap membership must be created");
    }

    let barrier = Arc::new(Barrier::new(3));
    let first_pool = pool.clone();
    let first_barrier = barrier.clone();
    let first = tokio::spawn(async move {
        first_barrier.wait().await;
        let repo = SqlxOrgScopeRepository::new(first_pool);
        let cmd = OrgMembershipCreateCommand {
            operation_id: unique_operation("membership-cap-rc-a"),
            actor_user_id: 1,
            actor_tenant_id: Some(MEMBERSHIP_CAP_RC_ROOT_A),
            tenant_id: MEMBERSHIP_CAP_RC_ROOT_A,
            user_id: MEMBERSHIP_CAP_RC_USER_ID,
            identity_card_id: MEMBERSHIP_CAP_RC_IDENTITY_CARD_ID,
            // 见 boundary race：base+CAP 属 ROOT_A（偶数 CAP 轮换）。
            card_id: MEMBERSHIP_CAP_RC_CARD_BASE
                + i64::try_from(ORG_MAX_ACTIVE_MEMBERSHIPS_PER_USER).expect("cap fits i64"),
            validity: ValidityWindow::perpetual(),
        };
        create_membership_retrying_deadlock(&repo, &cmd).await
    });
    let second_pool = pool.clone();
    let second_barrier = barrier.clone();
    let second = tokio::spawn(async move {
        second_barrier.wait().await;
        let repo = SqlxOrgScopeRepository::new(second_pool);
        let cmd = OrgMembershipCreateCommand {
            operation_id: unique_operation("membership-cap-rc-b"),
            actor_user_id: 1,
            actor_tenant_id: Some(MEMBERSHIP_CAP_RC_ROOT_B),
            tenant_id: MEMBERSHIP_CAP_RC_ROOT_B,
            user_id: MEMBERSHIP_CAP_RC_USER_ID,
            identity_card_id: MEMBERSHIP_CAP_RC_IDENTITY_CARD_ID,
            // 见 boundary race：base+CAP-1 属 ROOT_B。
            card_id: MEMBERSHIP_CAP_RC_CARD_BASE
                + i64::try_from(ORG_MAX_ACTIVE_MEMBERSHIPS_PER_USER - 1).expect("cap fits i64"),
            validity: ValidityWindow::perpetual(),
        };
        create_membership_retrying_deadlock(&repo, &cmd).await
    });
    barrier.wait().await;
    let first = first.await.expect("first RC membership task join");
    let second = second.await.expect("second RC membership task join");
    let outcomes = [first, second];
    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.is_ok()).count(),
        1,
        "the identity-card anchor must serialize the READ COMMITTED cap boundary"
    );
    for error in outcomes.iter().filter_map(|outcome| outcome.as_ref().err()) {
        assert!(
            error
                .to_string()
                .contains("code=org_scope.membership_user_cap_exceeded;cap="),
            "READ COMMITTED loser must fail with the stable cap code, got {error}"
        );
    }
    let active_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM org_scope_membership WHERE user_id = ? AND active = 1",
    )
    .bind(MEMBERSHIP_CAP_RC_USER_ID)
    .fetch_one(&pool)
    .await
    .expect("count memberships after READ COMMITTED boundary race");
    assert_eq!(
        active_count,
        i64::try_from(ORG_MAX_ACTIVE_MEMBERSHIPS_PER_USER).expect("cap fits i64"),
        "READ COMMITTED race must never overfill the global membership cap"
    );

    cleanup_membership_cap_fixture(
        &pool,
        MEMBERSHIP_CAP_RC_TENANTS,
        MEMBERSHIP_CAP_RC_DOMAIN_ID,
        MEMBERSHIP_CAP_RC_USER_ID,
        MEMBERSHIP_CAP_RC_IDENTITY_CARD_ID,
        MEMBERSHIP_CAP_RC_CARD_BASE,
    )
    .await;
    cleanup_tenant_set(&pool, &MEMBERSHIP_CAP_RC_TENANTS).await;
}

// ══════════════════════ 新 outbox worker 合同（kind 限定完成 + 子树传播）═════════════════════

/// create + approve 组合（请求方 actor 租户 = payload requester；approver 租户
/// 与治理证明由调用方显式给定：ROOT_* 需治理证明，ATTACH/MOVE 属载荷对侧父）。
/// 返回审批 outcome——其 operation_id 即该 source mutation 写入 outbox 的事件/
/// 意图关联 id（意图绑定的权威关联键）。
async fn submit_and_approve(
    repo: &SqlxOrgScopeRepository,
    payload: OrgRequestPayload,
    actor_tenant_id: i64,
    approver_tenant_id: Option<i64>,
    seed: &str,
    governance_proof: Option<OrgGovernanceProof>,
) -> OrgApproveOutcome {
    let request = repo
        .create_request(&OrgCreateRequestCommand {
            operation_id: unique_operation(&format!("req-{seed}")),
            actor_user_id: 1,
            actor_tenant_id: Some(actor_tenant_id),
            payload,
        })
        .await
        .expect("request create");
    repo.approve_request(&OrgApproveCommand {
        request_id: request.request_id,
        expected_revision: FRESH_REQUEST_REVISION,
        approver_user_id: 1,
        approver_tenant_id,
        operation_id: unique_operation(&format!("apr-{seed}")),
        note: None,
        governance_proof,
    })
    .await
    .expect("request approval")
}

/// 认领指定租户下 (event_kind, operation_id) 精确匹配的到期事件；claim 按
/// created_at/org_event_id 先进先出，途中遇到的非目标事件终态化（FAILED）退出
/// 队列，循环有界确定（fixture 每租户事件数有限）。
async fn claim_lease_of_kind(
    repo: &SqlxOrgScopeRepository,
    tenant_id: i64,
    kind: OrgOutboxEventKind,
    operation_id: &str,
) -> OrgOutboxLease {
    for _ in 0..32 {
        let lease = repo
            .claim_outbox_event(&OrgOutboxClaimCommand {
                tenant_id,
                worker_owner: OWNER.into(),
                worker_token_hex: TOKEN_HEX.into(),
                lease_seconds: 300,
                max_attempts: CLAIM_MAX_ATTEMPTS,
            })
            .await
            .expect("claim outbox event")
            .unwrap_or_else(|| {
                panic!("expected a due {kind:?} event for tenant {tenant_id} (op {operation_id})")
            });
        let row_kind: OrgOutboxEventKind = lease.event_kind.parse().expect("known event kind");
        if row_kind == kind && lease.operation_id == operation_id {
            return lease;
        }
        repo.fail_outbox_event(&OrgOutboxFailCommand {
            org_event_id: lease.org_event_id,
            worker_owner: OWNER.into(),
            worker_token_hex: TOKEN_HEX.into(),
            error: "e2e fixture: not the target event".into(),
            retryable: false,
            backoff_seconds: 0,
            max_attempts: CLAIM_MAX_ATTEMPTS,
        })
        .await
        .expect("fail non-target event");
    }
    panic!("target {kind:?} event not claimed within the fixture budget");
}

/// 以租约内 typed 意图载荷构造传播批命令（frontier 恰为 durable 锚点重入；
/// new_root 取自载荷，命令与事件行逐项绑定）。
async fn propagate_batch(
    repo: &SqlxOrgScopeRepository,
    lease: &OrgOutboxLease,
    batch_limit: i64,
) -> astral_db::org_scope_repository::OrgSubtreePropagateOutcome {
    let payload: OrgSubtreePropagatePayload =
        serde_json::from_str(&lease.payload_json).expect("typed subtree intent payload");
    repo.propagate_subtree_root(&OrgSubtreePropagateCommand {
        org_event_id: lease.org_event_id,
        worker_owner: OWNER.into(),
        worker_token_hex: TOKEN_HEX.into(),
        expected_kind: OrgOutboxEventKind::SubtreePropagate,
        operation_id: lease.operation_id.clone(),
        new_root_tenant_id: payload.new_root_tenant_id,
        frontier: vec![payload.child_tenant_id],
        batch_limit,
    })
    .await
    .expect("propagate batch")
}

/// kind 限定完成命令（统一 worker 身份）。
fn complete_command(org_event_id: i64, kind: OrgOutboxEventKind) -> OrgOutboxCompleteCommand {
    OrgOutboxCompleteCommand {
        org_event_id,
        worker_owner: OWNER.into(),
        worker_token_hex: TOKEN_HEX.into(),
        expected_kind: kind,
    }
}

/// node 行头快照（传播批前后对比根/归属/三计数/last_op）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct NodeHead {
    root_tenant_id: i64,
    parent_tenant_id: Option<i64>,
    generation: i64,
    revoke_fence: i64,
    relationship_revision: i64,
    last_operation_id: String,
}

async fn node_head_of(pool: &sqlx::MySqlPool, tenant_id: i64) -> NodeHead {
    let row = sqlx::query(
        "SELECT root_tenant_id, parent_tenant_id, generation, revoke_fence, \
         relationship_revision, last_operation_id FROM org_scope_node WHERE tenant_id = ?",
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .expect("node row");
    NodeHead {
        root_tenant_id: row.try_get("root_tenant_id").expect("root_tenant_id"),
        parent_tenant_id: row.try_get("parent_tenant_id").expect("parent_tenant_id"),
        generation: row.try_get("generation").expect("generation"),
        revoke_fence: row.try_get("revoke_fence").expect("revoke_fence"),
        relationship_revision: row
            .try_get("relationship_revision")
            .expect("relationship_revision"),
        last_operation_id: row.try_get("last_operation_id").expect("last_operation_id"),
    }
}

/// outbox 行状态快照（DONE/CAS 单调/租约清除证据）。cas_version 以 u64 对齐
/// 仓储语义（`OrgOutboxLease.cas_version`/`OrgOutboxCompleteOutcome.cas_version`）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct OutboxRowState {
    status: String,
    attempts: i64,
    cas_version: u64,
    lease_owner: Option<String>,
    lease_expires_at_unix: Option<i64>,
    next_attempt_at_unix: Option<i64>,
    last_error: Option<String>,
}

async fn outbox_state_of(pool: &sqlx::MySqlPool, org_event_id: i64) -> OutboxRowState {
    let row = sqlx::query(
        "SELECT status, attempts, cas_version, lease_owner, \
         CAST(UNIX_TIMESTAMP(lease_expires_at) AS SIGNED) AS lease_expires_at_unix, \
         CAST(UNIX_TIMESTAMP(next_attempt_at) AS SIGNED) AS next_attempt_at_unix, last_error \
         FROM org_scope_outbox WHERE org_event_id = ?",
    )
    .bind(org_event_id)
    .fetch_one(pool)
    .await
    .expect("outbox row");
    OutboxRowState {
        status: row.try_get("status").expect("status"),
        attempts: row.try_get("attempts").expect("attempts"),
        cas_version: u64::try_from(row.try_get::<i64, _>("cas_version").expect("cas_version"))
            .expect("cas_version is non-negative"),
        lease_owner: row.try_get("lease_owner").expect("lease_owner"),
        lease_expires_at_unix: row
            .try_get("lease_expires_at_unix")
            .expect("lease_expires_at_unix"),
        next_attempt_at_unix: row
            .try_get("next_attempt_at_unix")
            .expect("next_attempt_at_unix"),
        last_error: row.try_get("last_error").expect("last_error"),
    }
}

async fn outbox_last_error(pool: &sqlx::MySqlPool, org_event_id: i64) -> Option<String> {
    sqlx::query_scalar("SELECT last_error FROM org_scope_outbox WHERE org_event_id = ?")
        .bind(org_event_id)
        .fetch_one(pool)
        .await
        .expect("outbox last_error")
}

/// Create and approve ROOT_INIT, returning its operation id without claiming the
/// resulting event. The event therefore remains available for race tests.
async fn create_root_event(
    pool: &sqlx::MySqlPool,
    tenant_id: i64,
    seed: &str,
) -> (SqlxOrgScopeRepository, String) {
    cleanup_tenant_set(pool, &[tenant_id]).await;
    let repo = SqlxOrgScopeRepository::new(pool.clone());
    let outcome = submit_and_approve(
        &repo,
        OrgRequestPayload::RootInit {
            root_tenant_id: tenant_id,
            initial_grants: Vec::new(),
        },
        tenant_id,
        None,
        seed,
        Some(root_governance_proof(tenant_id, seed)),
    )
    .await;
    assert!(outcome
        .records
        .iter()
        .any(|record| record.record_kind == "NODE_CREATED"));
    (repo, outcome.operation_id)
}

/// Create a root-init source mutation and return its single NODE_CREATED outbox
/// lease. The source transaction is deliberately exercised through the public
/// repository API so the lease tests cannot pass with a malformed hand-seeded row.
async fn seed_root_event(
    pool: &sqlx::MySqlPool,
    tenant_id: i64,
    seed: &str,
) -> (SqlxOrgScopeRepository, OrgOutboxLease) {
    let (repo, operation_id) = create_root_event(pool, tenant_id, seed).await;
    let lease = claim_lease_of_kind(
        &repo,
        tenant_id,
        OrgOutboxEventKind::NodeCreated,
        &operation_id,
    )
    .await;
    (repo, lease)
}

async fn empty_root_publication(
    repo: &SqlxOrgScopeRepository,
    lease: &OrgOutboxLease,
    worker_owner: &str,
    worker_token_hex: &str,
) -> OrgPublication {
    let input = repo
        .load_compile_input(&OrgCompileInputCommand {
            org_event_id: lease.org_event_id,
            worker_owner: worker_owner.into(),
            worker_token_hex: worker_token_hex.into(),
        })
        .await
        .expect("root compile input under current lease");
    assert!(input.node.is_root());
    assert!(input.grants.is_empty());
    assert!(input.dependencies.is_empty());
    assert!(input.parent_publications.is_empty());
    let segments = Vec::new();
    let manifest_digest_hex = org_manifest_digest_hex(&OrgManifestDigestMaterial {
        tenant_id: input.node.tenant_id,
        root_tenant_id: input.node.root_tenant_id,
        generation: input.node.generation,
        relationship_revision: input.node.relationship_revision,
        revoke_fence: input.node.revoke_fence,
        dependencies: &input.dependencies,
        segments: &segments,
        compiler_version: COMPILER_VERSION,
        operation_id: &input.operation_id,
    })
    .expect("root manifest digest");
    OrgPublication {
        tenant_id: input.node.tenant_id,
        root_tenant_id: input.node.root_tenant_id,
        generation: input.node.generation,
        relationship_revision: input.node.relationship_revision,
        revoke_fence: input.node.revoke_fence,
        dependencies: input.dependencies,
        manifest_digest_hex,
        compiler_version: COMPILER_VERSION.into(),
        segments,
        operation_id: input.operation_id,
    }
}

/// 测试夹具直改**本测试自有**租约行载荷（畸形/跨租户/漂移意图注入；完成门在
/// DONE 之前复核载荷，注入绝不影响其他数据）。
async fn tamper_outbox_payload(pool: &sqlx::MySqlPool, org_event_id: i64, payload_json: &str) {
    sqlx::query("UPDATE org_scope_outbox SET payload_json = ? WHERE org_event_id = ?")
        .bind(payload_json)
        .bind(org_event_id)
        .execute(pool)
        .await
        .expect("tamper outbox payload");
}

/// 传播 durable 幂等标记：NODE revision 账中以指定 operation_id 落账的行数。
async fn node_revision_mark_count(
    pool: &sqlx::MySqlPool,
    tenant_id: i64,
    operation_id: &str,
) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM org_scope_revision \
         WHERE subject_kind = 'NODE' AND tenant_id = ? AND operation_id = ?",
    )
    .bind(tenant_id)
    .bind(operation_id)
    .fetch_one(pool)
    .await
    .expect("node revision mark count")
}

/// 指定租户/操作派生的 SUBTREE_PROPAGATE child intent 数。
async fn subtree_intent_count(pool: &sqlx::MySqlPool, tenant_id: i64, operation_id: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM org_scope_outbox \
         WHERE tenant_id = ? AND event_kind = 'SUBTREE_PROPAGATE' AND operation_id = ?",
    )
    .bind(tenant_id)
    .bind(operation_id)
    .fetch_one(pool)
    .await
    .expect("subtree intent count")
}

async fn publication_count(pool: &sqlx::MySqlPool, tenant_id: i64) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM org_scope_publication WHERE tenant_id = ?")
        .bind(tenant_id)
        .fetch_one(pool)
        .await
        .expect("publication count")
}

async fn audit_count_for_operation(pool: &sqlx::MySqlPool, operation_id: &str) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM org_scope_audit WHERE operation_id = ?")
        .bind(operation_id)
        .fetch_one(pool)
        .await
        .expect("audit count")
}

/// kind 限定"无发布完成"合同（MEMBERSHIP_CHANGED 路径）：载荷同源绑定通过；
/// category-1 kind / 行内 kind 错配 / 畸形 / 跨租户 / 操作漂移载荷全部确定性
/// 拒绝且事件保持 LEASED；恢复原载荷后完成（DONE + CAS 单调 + 租约清除 + 无
/// publication/新审计写）；重复完成租约丢失。
#[tokio::test]
#[ignore]
async fn org_scope_complete_outbox_event_kind_scoped_membership_contract() {
    let Some(pool) = connect().await else {
        return;
    };
    require_org_scope_schema(&pool).await;
    cleanup_tenant_set(&pool, &COMPLETE_TENANTS).await;
    cleanup_membership_fixture_for(&pool, &COMPLETE_FIXTURE).await;
    seed_membership_fixture_for(&pool, &COMPLETE_FIXTURE).await;
    let repo = SqlxOrgScopeRepository::new(pool.clone());

    // 拓扑：root-init R（无种子 grant）→ attach CHILD。
    submit_and_approve(
        &repo,
        OrgRequestPayload::RootInit {
            root_tenant_id: COMPLETE_ROOT_TENANT,
            initial_grants: Vec::new(),
        },
        COMPLETE_ROOT_TENANT,
        None,
        "complete-root-init",
        Some(root_governance_proof(COMPLETE_ROOT_TENANT, "complete-root")),
    )
    .await;
    submit_and_approve(
        &repo,
        OrgRequestPayload::Attach {
            child_tenant_id: COMPLETE_CHILD_TENANT,
            parent_tenant_id: COMPLETE_ROOT_TENANT,
        },
        COMPLETE_CHILD_TENANT,
        Some(COMPLETE_ROOT_TENANT),
        "complete-attach",
        None,
    )
    .await;

    // membership source mutation → MEMBERSHIP_CHANGED 事件（typed 载荷）。
    let membership_op = unique_operation("complete-mem");
    repo.create_membership(&OrgMembershipCreateCommand {
        operation_id: membership_op.clone(),
        actor_user_id: 1,
        actor_tenant_id: Some(COMPLETE_CHILD_TENANT),
        tenant_id: COMPLETE_CHILD_TENANT,
        user_id: COMPLETE_FIXTURE.user_id,
        identity_card_id: COMPLETE_FIXTURE.identity_card_id,
        card_id: COMPLETE_FIXTURE.card_id,
        validity: ValidityWindow::perpetual(),
    })
    .await
    .expect("membership create");

    let lease = claim_lease_of_kind(
        &repo,
        COMPLETE_CHILD_TENANT,
        OrgOutboxEventKind::MembershipChanged,
        &membership_op,
    )
    .await;
    // 行内载荷即 typed OrgMembership，与事件行同源（同租户 + 同 operation_id）。
    let membership: OrgMembership =
        serde_json::from_str(&lease.payload_json).expect("typed membership payload");
    assert_eq!(membership.tenant_id, COMPLETE_CHILD_TENANT);
    assert_eq!(membership.root_tenant_id, COMPLETE_ROOT_TENANT);
    assert_eq!(membership.operation_id, membership_op);
    let original_payload = lease.payload_json.clone();
    let leased_state = outbox_state_of(&pool, lease.org_event_id).await;
    assert_eq!(leased_state.status, "LEASED");

    // 1) category-1 kind：白名单在任何 DB 写之前拒绝。
    let error = repo
        .complete_outbox_event(&complete_command(
            lease.org_event_id,
            OrgOutboxEventKind::GrantIssued,
        ))
        .await
        .expect_err("category-1 kind must be refused");
    assert!(error
        .to_string()
        .contains("org_scope.outbox_complete_kind_forbidden"));
    let state = outbox_state_of(&pool, lease.org_event_id).await;
    assert_eq!(state.status, "LEASED");
    assert_eq!(state.cas_version, leased_state.cas_version);

    // 2) 行内 event_kind 与 expected_kind 不一致：拒绝，绝不静默消费错种类。
    let error = repo
        .complete_outbox_event(&complete_command(
            lease.org_event_id,
            OrgOutboxEventKind::SubtreePropagate,
        ))
        .await
        .expect_err("row kind mismatch must be refused");
    assert!(error
        .to_string()
        .contains("org_scope.outbox_complete_kind_mismatch"));
    assert_eq!(
        outbox_state_of(&pool, lease.org_event_id).await.status,
        "LEASED"
    );

    // 3) 畸形载荷（JSON 合法但与 typed 合同不同构）：确定性不可读拒绝。
    tamper_outbox_payload(&pool, lease.org_event_id, "{\"unexpected\":1}").await;
    let error = repo
        .complete_outbox_event(&complete_command(
            lease.org_event_id,
            OrgOutboxEventKind::MembershipChanged,
        ))
        .await
        .expect_err("malformed payload must be refused");
    assert!(error
        .to_string()
        .contains("org_scope.complete_payload_unreadable"));
    assert_eq!(
        outbox_state_of(&pool, lease.org_event_id).await.status,
        "LEASED"
    );

    // 4) 跨租户载荷：事件租户绑定拒绝。
    let cross_tenant = OrgMembership {
        tenant_id: COMPLETE_ROOT_TENANT,
        root_tenant_id: COMPLETE_ROOT_TENANT,
        ..membership.clone()
    };
    tamper_outbox_payload(
        &pool,
        lease.org_event_id,
        &serde_json::to_string(&cross_tenant).expect("serialize cross-tenant membership"),
    )
    .await;
    let error = repo
        .complete_outbox_event(&complete_command(
            lease.org_event_id,
            OrgOutboxEventKind::MembershipChanged,
        ))
        .await
        .expect_err("cross-tenant payload must be refused");
    assert!(error
        .to_string()
        .contains("org_scope.complete_payload_tenant_mismatch"));
    assert_eq!(
        outbox_state_of(&pool, lease.org_event_id).await.status,
        "LEASED"
    );

    // 5) 载荷 operation_id 与事件行漂移：durable 溯源绑定拒绝。
    let drifted = OrgMembership {
        operation_id: "e2e-drifted-op".into(),
        ..membership.clone()
    };
    tamper_outbox_payload(
        &pool,
        lease.org_event_id,
        &serde_json::to_string(&drifted).expect("serialize drifted membership"),
    )
    .await;
    let error = repo
        .complete_outbox_event(&complete_command(
            lease.org_event_id,
            OrgOutboxEventKind::MembershipChanged,
        ))
        .await
        .expect_err("drifted payload operation must be refused");
    assert!(error
        .to_string()
        .contains("org_scope.complete_payload_operation_mismatch"));
    assert_eq!(
        outbox_state_of(&pool, lease.org_event_id).await.status,
        "LEASED"
    );

    // 6) 恢复原载荷 → 完成：CAS 单调 + 租约清除 + DONE。
    tamper_outbox_payload(&pool, lease.org_event_id, &original_payload).await;
    let audits_before = audit_count_for_operation(&pool, &membership_op).await;
    let outcome = repo
        .complete_outbox_event(&complete_command(
            lease.org_event_id,
            OrgOutboxEventKind::MembershipChanged,
        ))
        .await
        .expect("kind-scoped completion");
    assert_eq!(outcome.attempts, lease.attempts);
    assert_eq!(outcome.cas_version, lease.cas_version + 1);
    let state = outbox_state_of(&pool, lease.org_event_id).await;
    assert_eq!(state.status, "DONE");
    assert!(state.lease_owner.is_none());
    assert_eq!(state.cas_version, lease.cas_version + 1);
    // 无 publication 副产物、无新审计写（消费完成以行状态为可追溯证据）。
    assert_eq!(publication_count(&pool, COMPLETE_CHILD_TENANT).await, 0);
    assert_eq!(
        audit_count_for_operation(&pool, &membership_op).await,
        audits_before
    );

    // 7) 重复完成：DONE 行不再满足租约谓词。
    let error = repo
        .complete_outbox_event(&complete_command(
            lease.org_event_id,
            OrgOutboxEventKind::MembershipChanged,
        ))
        .await
        .expect_err("re-completion must fail");
    assert!(error.to_string().contains("org_scope.outbox_lease_lost"));

    cleanup_membership_fixture_for(&pool, &COMPLETE_FIXTURE).await;
    cleanup_tenant_set(&pool, &COMPLETE_TENANTS).await;
}

/// 子树传播扇出排空合同：MOVE 锚点 3 个直接兄弟、batch_limit=2 → 首批推进
/// 升序前 2 个（done=false + next_frontier=[锚点]）；排空前完成拒绝（
/// complete_propagation_incomplete）、事件保持 LEASED/CAS 不动；重入排空第 3
/// 个后才 done；被推进子节点 root 跨根置目标 + 三计数同步 +1 + durable NODE
/// 账标记 + child intent 派生；排空后完成 DONE + CAS 单调，重复完成租约丢失。
#[tokio::test]
#[ignore]
async fn org_scope_propagate_subtree_drains_wide_siblings_before_completion() {
    let Some(pool) = connect().await else {
        return;
    };
    require_org_scope_schema(&pool).await;
    cleanup_tenant_set(&pool, &DRAIN_TENANTS).await;
    let repo = SqlxOrgScopeRepository::new(pool.clone());

    // 拓扑：R、Q 两根；M 挂 R；A/B/C 挂 M；MOVE M → Q（M 的直接兄弟 root 需由
    // 传播意图推进，兄弟各自 attach 的 op 与 MOVE op 不同 ⇒ 全部未被标记）。
    submit_and_approve(
        &repo,
        OrgRequestPayload::RootInit {
            root_tenant_id: DRAIN_ROOT_TENANT,
            initial_grants: Vec::new(),
        },
        DRAIN_ROOT_TENANT,
        None,
        "drain-root-init",
        Some(root_governance_proof(DRAIN_ROOT_TENANT, "drain-root-r")),
    )
    .await;
    submit_and_approve(
        &repo,
        OrgRequestPayload::RootInit {
            root_tenant_id: DRAIN_NEW_ROOT_TENANT,
            initial_grants: Vec::new(),
        },
        DRAIN_NEW_ROOT_TENANT,
        None,
        "drain-root-init-q",
        Some(root_governance_proof(DRAIN_NEW_ROOT_TENANT, "drain-root-q")),
    )
    .await;
    submit_and_approve(
        &repo,
        OrgRequestPayload::Attach {
            child_tenant_id: DRAIN_ANCHOR_TENANT,
            parent_tenant_id: DRAIN_ROOT_TENANT,
        },
        DRAIN_ANCHOR_TENANT,
        Some(DRAIN_ROOT_TENANT),
        "drain-attach-anchor",
        None,
    )
    .await;
    for (sibling, seed) in [
        (DRAIN_SIBLING_A, "a"),
        (DRAIN_SIBLING_B, "b"),
        (DRAIN_SIBLING_C, "c"),
    ] {
        submit_and_approve(
            &repo,
            OrgRequestPayload::Attach {
                child_tenant_id: sibling,
                parent_tenant_id: DRAIN_ANCHOR_TENANT,
            },
            sibling,
            Some(DRAIN_ANCHOR_TENANT),
            &format!("drain-attach-{seed}"),
            None,
        )
        .await;
    }
    let move_outcome = submit_and_approve(
        &repo,
        OrgRequestPayload::Move {
            child_tenant_id: DRAIN_ANCHOR_TENANT,
            new_parent_tenant_id: DRAIN_NEW_ROOT_TENANT,
        },
        DRAIN_ANCHOR_TENANT,
        Some(DRAIN_NEW_ROOT_TENANT),
        "drain-move",
        None,
    )
    .await;
    let move_op = move_outcome.operation_id;

    // 批前快照：兄弟全部还挂在锚点下、root=R。
    let heads_before = [
        node_head_of(&pool, DRAIN_SIBLING_A).await,
        node_head_of(&pool, DRAIN_SIBLING_B).await,
        node_head_of(&pool, DRAIN_SIBLING_C).await,
    ];
    for head in &heads_before {
        assert_eq!(head.root_tenant_id, DRAIN_ROOT_TENANT);
        assert_eq!(head.parent_tenant_id, Some(DRAIN_ANCHOR_TENANT));
    }

    let lease = claim_lease_of_kind(
        &repo,
        DRAIN_ANCHOR_TENANT,
        OrgOutboxEventKind::SubtreePropagate,
        &move_op,
    )
    .await;
    let intent: OrgSubtreePropagatePayload =
        serde_json::from_str(&lease.payload_json).expect("typed subtree intent");
    assert_eq!(intent.child_tenant_id, DRAIN_ANCHOR_TENANT);
    assert_eq!(intent.new_root_tenant_id, DRAIN_NEW_ROOT_TENANT);

    // 批 1（batch_limit=2）：升序推进前 2 个兄弟；选中数 == batch_limit ⇒ 绝不定 done。
    let batch1 = propagate_batch(&repo, &lease, 2).await;
    assert_eq!(
        batch1.updated_tenant_ids,
        vec![DRAIN_SIBLING_A, DRAIN_SIBLING_B]
    );
    assert_eq!(batch1.next_frontier, vec![DRAIN_ANCHOR_TENANT]);
    assert!(!batch1.done);
    assert!(!batch1.superseded);

    // 被推进者：root 跨根置目标 + 三计数同步 +1 + last_op=move op。
    for (tenant_id, before) in [
        (DRAIN_SIBLING_A, heads_before[0].clone()),
        (DRAIN_SIBLING_B, heads_before[1].clone()),
    ] {
        let after = node_head_of(&pool, tenant_id).await;
        assert_eq!(after.root_tenant_id, DRAIN_NEW_ROOT_TENANT);
        assert_eq!(after.parent_tenant_id, Some(DRAIN_ANCHOR_TENANT));
        assert_eq!(after.generation, before.generation + 1);
        assert_eq!(after.revoke_fence, before.revoke_fence + 1);
        assert_eq!(
            after.relationship_revision,
            before.relationship_revision + 1
        );
        assert_eq!(after.last_operation_id, move_op);
    }
    // 未选中兄弟完全原样。
    assert_eq!(node_head_of(&pool, DRAIN_SIBLING_C).await, heads_before[2]);
    // durable 幂等标记 + 派生 child intent（宽兄弟扇出证据）。
    assert_eq!(
        node_revision_mark_count(&pool, DRAIN_SIBLING_A, &move_op).await,
        1
    );
    assert_eq!(
        node_revision_mark_count(&pool, DRAIN_SIBLING_B, &move_op).await,
        1
    );
    assert_eq!(
        node_revision_mark_count(&pool, DRAIN_SIBLING_C, &move_op).await,
        0
    );
    assert_eq!(
        subtree_intent_count(&pool, DRAIN_SIBLING_A, &move_op).await,
        1
    );
    assert_eq!(
        subtree_intent_count(&pool, DRAIN_SIBLING_B, &move_op).await,
        1
    );

    // 排空前完成：存在未以本操作 id 标记的直接 active 子节点 ⇒ 拒绝，事件保持
    // LEASED、CAS 不动（回滚证据）。
    let state_before_refusal = outbox_state_of(&pool, lease.org_event_id).await;
    let error = repo
        .complete_outbox_event(&complete_command(
            lease.org_event_id,
            OrgOutboxEventKind::SubtreePropagate,
        ))
        .await
        .expect_err("completion before drain must be refused");
    assert!(error
        .to_string()
        .contains("org_scope.complete_propagation_incomplete"));
    let state_after_refusal = outbox_state_of(&pool, lease.org_event_id).await;
    assert_eq!(state_after_refusal.status, "LEASED");
    assert_eq!(
        state_after_refusal.cas_version,
        state_before_refusal.cas_version
    );

    // 重入（同一事件 + 同一锚点前沿）：排空剩余兄弟后才 done。
    let batch2 = propagate_batch(&repo, &lease, 2).await;
    assert_eq!(batch2.updated_tenant_ids, vec![DRAIN_SIBLING_C]);
    assert!(batch2.done);
    assert!(batch2.next_frontier.is_empty());
    assert!(!batch2.superseded);
    let after_c = node_head_of(&pool, DRAIN_SIBLING_C).await;
    assert_eq!(after_c.root_tenant_id, DRAIN_NEW_ROOT_TENANT);
    assert_eq!(after_c.generation, heads_before[2].generation + 1);
    assert_eq!(after_c.revoke_fence, heads_before[2].revoke_fence + 1);
    assert_eq!(
        after_c.relationship_revision,
        heads_before[2].relationship_revision + 1
    );
    assert_eq!(after_c.last_operation_id, move_op);
    assert_eq!(
        node_revision_mark_count(&pool, DRAIN_SIBLING_C, &move_op).await,
        1
    );
    assert_eq!(
        subtree_intent_count(&pool, DRAIN_SIBLING_C, &move_op).await,
        1
    );

    // 排空后完成：CAS 单调 + 租约清除 + DONE；重复完成租约丢失。
    let outcome = repo
        .complete_outbox_event(&complete_command(
            lease.org_event_id,
            OrgOutboxEventKind::SubtreePropagate,
        ))
        .await
        .expect("completion after drain");
    assert_eq!(outcome.attempts, lease.attempts);
    assert_eq!(outcome.cas_version, lease.cas_version + 1);
    let final_state = outbox_state_of(&pool, lease.org_event_id).await;
    assert_eq!(final_state.status, "DONE");
    assert!(final_state.lease_owner.is_none());
    let error = repo
        .complete_outbox_event(&complete_command(
            lease.org_event_id,
            OrgOutboxEventKind::SubtreePropagate,
        ))
        .await
        .expect_err("re-completion must fail");
    assert!(error.to_string().contains("org_scope.outbox_lease_lost"));

    cleanup_tenant_set(&pool, &DRAIN_TENANTS).await;
}

/// superseded 意图 + 同根失效：M 的 attach 意图（I1）在同根 MOVE 推进锚点
/// relationship_revision 后被取代——传播无写安全放行（superseded=true、叶子零
/// 变更、无 NODE 账/child intent）并免收敛证明安全完成；随后处理 MOVE 意图
/// （I2，Current）：同根（叶子 root 已等于目标）仍被选中失效一次（三计数同步
/// +1、root 不变、NODE 账 + child intent），排空后完成。
#[tokio::test]
#[ignore]
async fn org_scope_propagate_superseded_intent_and_same_root_invalidation() {
    let Some(pool) = connect().await else {
        return;
    };
    require_org_scope_schema(&pool).await;
    cleanup_tenant_set(&pool, &SUPER_TENANTS).await;
    let repo = SqlxOrgScopeRepository::new(pool.clone());

    // 拓扑：R ← {P1, P2}；M 挂 P1；X 挂 M。
    submit_and_approve(
        &repo,
        OrgRequestPayload::RootInit {
            root_tenant_id: SUPER_ROOT_TENANT,
            initial_grants: Vec::new(),
        },
        SUPER_ROOT_TENANT,
        None,
        "super-root-init",
        Some(root_governance_proof(SUPER_ROOT_TENANT, "super-root")),
    )
    .await;
    submit_and_approve(
        &repo,
        OrgRequestPayload::Attach {
            child_tenant_id: SUPER_PARENT_OLD,
            parent_tenant_id: SUPER_ROOT_TENANT,
        },
        SUPER_PARENT_OLD,
        Some(SUPER_ROOT_TENANT),
        "super-attach-p1",
        None,
    )
    .await;
    submit_and_approve(
        &repo,
        OrgRequestPayload::Attach {
            child_tenant_id: SUPER_PARENT_NEW,
            parent_tenant_id: SUPER_ROOT_TENANT,
        },
        SUPER_PARENT_NEW,
        Some(SUPER_ROOT_TENANT),
        "super-attach-p2",
        None,
    )
    .await;
    let attach_anchor = submit_and_approve(
        &repo,
        OrgRequestPayload::Attach {
            child_tenant_id: SUPER_ANCHOR_TENANT,
            parent_tenant_id: SUPER_PARENT_OLD,
        },
        SUPER_ANCHOR_TENANT,
        Some(SUPER_PARENT_OLD),
        "super-attach-anchor",
        None,
    )
    .await;
    submit_and_approve(
        &repo,
        OrgRequestPayload::Attach {
            child_tenant_id: SUPER_LEAF_TENANT,
            parent_tenant_id: SUPER_ANCHOR_TENANT,
        },
        SUPER_LEAF_TENANT,
        Some(SUPER_ANCHOR_TENANT),
        "super-attach-leaf",
        None,
    )
    .await;

    let leaf_before = node_head_of(&pool, SUPER_LEAF_TENANT).await;
    assert_eq!(leaf_before.root_tenant_id, SUPER_ROOT_TENANT);

    // 同根 MOVE：M 从 P1 到 P2（同根 R），锚点 relationship_revision 推进而
    // root 不变；其 attach 意图 I1 由此被取代。
    let move_outcome = submit_and_approve(
        &repo,
        OrgRequestPayload::Move {
            child_tenant_id: SUPER_ANCHOR_TENANT,
            new_parent_tenant_id: SUPER_PARENT_NEW,
        },
        SUPER_ANCHOR_TENANT,
        Some(SUPER_PARENT_NEW),
        "super-move",
        None,
    )
    .await;
    let move_op = move_outcome.operation_id;
    let anchor_after_move = node_head_of(&pool, SUPER_ANCHOR_TENANT).await;
    assert_eq!(anchor_after_move.root_tenant_id, SUPER_ROOT_TENANT);

    // claim 先进先出：先处理旧 attach 意图 I1（op=attach-anchor op）。
    let stale_lease = claim_lease_of_kind(
        &repo,
        SUPER_ANCHOR_TENANT,
        OrgOutboxEventKind::SubtreePropagate,
        &attach_anchor.operation_id,
    )
    .await;
    let stale_intent: OrgSubtreePropagatePayload =
        serde_json::from_str(&stale_lease.payload_json).expect("typed stale intent");
    assert_eq!(stale_intent.child_tenant_id, SUPER_ANCHOR_TENANT);
    assert_eq!(stale_intent.new_root_tenant_id, SUPER_ROOT_TENANT);
    assert_eq!(
        stale_intent.relationship_revision as i64,
        anchor_after_move.relationship_revision - 1,
        "stale intent must pin the pre-move anchor revision"
    );

    // superseded：锚点 revision 已被更新的拓扑 source 变更推进 ⇒ 无写安全放行。
    let outcome = propagate_batch(&repo, &stale_lease, 2).await;
    assert!(outcome.superseded);
    assert!(outcome.done);
    assert!(outcome.updated_tenant_ids.is_empty());
    assert!(outcome.next_frontier.is_empty());
    // 叶子零变更：无节点写入、无 NODE 账标记、无 child intent。
    assert_eq!(node_head_of(&pool, SUPER_LEAF_TENANT).await, leaf_before);
    assert_eq!(
        node_revision_mark_count(&pool, SUPER_LEAF_TENANT, &attach_anchor.operation_id).await,
        0
    );
    assert_eq!(
        subtree_intent_count(&pool, SUPER_LEAF_TENANT, &attach_anchor.operation_id).await,
        0
    );

    // Superseded 意图免收敛证明安全完成（更新的意图必然已由该 source 变更入队）。
    repo.complete_outbox_event(&complete_command(
        stale_lease.org_event_id,
        OrgOutboxEventKind::SubtreePropagate,
    ))
    .await
    .expect("superseded intent completes without drain proof");
    assert_eq!(
        outbox_state_of(&pool, stale_lease.org_event_id)
            .await
            .status,
        "DONE"
    );

    // MOVE 意图 I2（Current）：同根失效——X.root 已等于目标仍被选中一次。
    let move_lease = claim_lease_of_kind(
        &repo,
        SUPER_ANCHOR_TENANT,
        OrgOutboxEventKind::SubtreePropagate,
        &move_op,
    )
    .await;
    let move_intent: OrgSubtreePropagatePayload =
        serde_json::from_str(&move_lease.payload_json).expect("typed move intent");
    assert_eq!(move_intent.child_tenant_id, SUPER_ANCHOR_TENANT);
    assert_eq!(move_intent.new_root_tenant_id, SUPER_ROOT_TENANT);
    assert_eq!(
        move_intent.relationship_revision as i64,
        anchor_after_move.relationship_revision
    );

    let batch = propagate_batch(&repo, &move_lease, 2).await;
    assert_eq!(batch.updated_tenant_ids, vec![SUPER_LEAF_TENANT]);
    assert!(batch.done);
    assert!(!batch.superseded);
    let leaf_after = node_head_of(&pool, SUPER_LEAF_TENANT).await;
    // 同根：root 值不变，但三计数同步 +1（失效语义不依赖 root 不等）。
    assert_eq!(leaf_after.root_tenant_id, leaf_before.root_tenant_id);
    assert_eq!(leaf_after.parent_tenant_id, Some(SUPER_ANCHOR_TENANT));
    assert_eq!(leaf_after.generation, leaf_before.generation + 1);
    assert_eq!(leaf_after.revoke_fence, leaf_before.revoke_fence + 1);
    assert_eq!(
        leaf_after.relationship_revision,
        leaf_before.relationship_revision + 1
    );
    assert_eq!(leaf_after.last_operation_id, move_op);
    assert_eq!(
        node_revision_mark_count(&pool, SUPER_LEAF_TENANT, &move_op).await,
        1
    );
    assert_eq!(
        subtree_intent_count(&pool, SUPER_LEAF_TENANT, &move_op).await,
        1
    );

    // 排空后完成。
    repo.complete_outbox_event(&complete_command(
        move_lease.org_event_id,
        OrgOutboxEventKind::SubtreePropagate,
    ))
    .await
    .expect("completion after same-root drain");
    assert_eq!(
        outbox_state_of(&pool, move_lease.org_event_id).await.status,
        "DONE"
    );

    cleanup_tenant_set(&pool, &SUPER_TENANTS).await;
}

// ══════════════════════ DEPENDENCY_PROPAGATE 波次合同（真实 MySQL）═════════════════════
//
// 覆盖 `propagate_dependency_change` 的 durable 合同：source-head 变更（根 grant /
// mask apply / mask remove / grant revoke）在锚点单元落 DEPENDENCY_PROPAGATE
// intent；传播必须等锚点**当前 publication** 跟上载荷头（否则
// `anchor_publication_stale`），只选中锚点的直接 active 子节点中当前 publication
// 依赖钉与载荷头失配者，generation-only 推进（revoke_fence /
// relationship_revision 不动），幂等凭 outbox marker（同 op 的
// DEPENDENCY_PROPAGATE/SUBTREE_PROPAGATE 行），并为每个被推进子节点派生
// NODE_MUTATED 触发事件 + typed dependency child intent（孙单元等子锚点重新
// 发布后才失效）。

/// 根 grant 波次拓扑：R → C → G（无授权链；publication 允许零 segment）。
const DEP_ROOT_TENANT: i64 = 920_000_601;
const DEP_CHILD_TENANT: i64 = 920_000_602;
const DEP_GRANDCHILD_TENANT: i64 = 920_000_603;
const DEP_WAVE_TENANTS: [i64; 3] = [DEP_ROOT_TENANT, DEP_CHILD_TENANT, DEP_GRANDCHILD_TENANT];

/// mask apply/remove/revoke 波次拓扑：R → C → G（真实授权链供 mask 祖先 exact
/// ref 与孙单元派生贡献）。
const DEP_MASK_ROOT_TENANT: i64 = 920_000_611;
const DEP_MASK_CHILD_TENANT: i64 = 920_000_612;
const DEP_MASK_GRANDCHILD_TENANT: i64 = 920_000_613;
const DEP_MASK_TENANTS: [i64; 3] = [
    DEP_MASK_ROOT_TENANT,
    DEP_MASK_CHILD_TENANT,
    DEP_MASK_GRANDCHILD_TENANT,
];

/// reparenting 拓扑：R ← {P1, P2}；M、L 挂 P1；K 挂 P2；K2 后置挂 P2。升序
/// 批次断言依赖 M(624) < K(626)。
const DEP_MV_ROOT_TENANT: i64 = 920_000_621;
const DEP_MV_PARENT_OLD: i64 = 920_000_622;
const DEP_MV_PARENT_NEW: i64 = 920_000_623;
const DEP_MV_MOVED: i64 = 920_000_624;
const DEP_MV_OLD_SIBLING: i64 = 920_000_625;
const DEP_MV_NEW_CHILD: i64 = 920_000_626;
const DEP_MV_LATE_CHILD: i64 = 920_000_627;
const DEP_MV_TENANTS: [i64; 7] = [
    DEP_MV_ROOT_TENANT,
    DEP_MV_PARENT_OLD,
    DEP_MV_PARENT_NEW,
    DEP_MV_MOVED,
    DEP_MV_OLD_SIBLING,
    DEP_MV_NEW_CHILD,
    DEP_MV_LATE_CHILD,
];

/// 从租约 typed 载荷构造依赖传播批命令（anchor 取自 durable 载荷，命令与事件
/// 行逐项绑定；与 `propagate_batch` 同型）。
fn dependency_propagate_command(
    lease: &OrgOutboxLease,
    batch_limit: i64,
) -> OrgDependencyPropagateCommand {
    let payload: OrgDependencyPropagatePayload =
        serde_json::from_str(&lease.payload_json).expect("typed dependency intent payload");
    OrgDependencyPropagateCommand {
        org_event_id: lease.org_event_id,
        worker_owner: OWNER.into(),
        worker_token_hex: TOKEN_HEX.into(),
        expected_kind: OrgOutboxEventKind::DependencyPropagate,
        operation_id: lease.operation_id.clone(),
        anchor_tenant_id: payload.anchor_tenant_id,
        batch_limit,
    }
}

/// 认领并处理指定 (tenant, operation) 的 DEPENDENCY_PROPAGATE intent：
/// 满批传播并完成，返回传播结果供调用方断言。途中非目标到期事件由
/// `claim_lease_of_kind` 终态化（既有 helper 行为）。
async fn run_dependency_intent(
    repo: &SqlxOrgScopeRepository,
    tenant_id: i64,
    operation_id: &str,
) -> OrgDependencyPropagateOutcome {
    let lease = claim_lease_of_kind(
        repo,
        tenant_id,
        OrgOutboxEventKind::DependencyPropagate,
        operation_id,
    )
    .await;
    let outcome = repo
        .propagate_dependency_change(&dependency_propagate_command(
            &lease,
            ORG_MAX_PROPAGATE_BATCH,
        ))
        .await
        .expect("dependency wave must succeed under a matched lease");
    repo.complete_outbox_event(&complete_command(
        lease.org_event_id,
        OrgOutboxEventKind::DependencyPropagate,
    ))
    .await
    .expect("dependency wave completion");
    outcome
}

/// DEPENDENCY_PROPAGATE 意图行数（传播幂等的 outbox marker 证据；依赖路径不写
/// NODE revision 账，幂等标记就是本行）。
async fn dependency_intent_count(
    pool: &sqlx::MySqlPool,
    tenant_id: i64,
    operation_id: &str,
) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM org_scope_outbox \
         WHERE tenant_id = ? AND event_kind = 'DEPENDENCY_PROPAGATE' AND operation_id = ?",
    )
    .bind(tenant_id)
    .bind(operation_id)
    .fetch_one(pool)
    .await
    .expect("dependency intent count")
}

/// 指定租户/种类/操作的 outbox 行数（被推进子节点的 NODE_MUTATED 派生触发
/// 事件证据）。
async fn outbox_kind_operation_count(
    pool: &sqlx::MySqlPool,
    tenant_id: i64,
    event_kind: &str,
    operation_id: &str,
) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM org_scope_outbox \
         WHERE tenant_id = ? AND event_kind = ? AND operation_id = ?",
    )
    .bind(tenant_id)
    .bind(event_kind)
    .bind(operation_id)
    .fetch_one(pool)
    .await
    .expect("outbox kind/operation count")
}

/// 指定操作 + action 的审计行数（DEPENDENCY_PROPAGATED 波次审计精确证据）。
async fn audit_count_for_operation_action(
    pool: &sqlx::MySqlPool,
    operation_id: &str,
    action: &str,
) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM org_scope_audit WHERE operation_id = ? AND action = ?",
    )
    .bind(operation_id)
    .bind(action)
    .fetch_one(pool)
    .await
    .expect("audit count for operation/action")
}

/// 单元当前 publication 的依赖钉（(depends_on, pinned_generation,
/// pinned_revoke_fence, pinned_relationship_revision)，按 depends_on 升序）。
/// 历史钉绑定旧 publication_id，天然被 current join 排除。
async fn current_dependency_pins(
    pool: &sqlx::MySqlPool,
    tenant_id: i64,
) -> Vec<(i64, i64, i64, i64)> {
    let rows = sqlx::query(
        "SELECT d.depends_on_tenant_id, d.pinned_generation, d.pinned_revoke_fence, \
         d.pinned_relationship_revision FROM org_scope_dependency d \
         JOIN org_scope_current c ON c.tenant_id = ? AND c.publication_id = d.publication_id \
         WHERE d.dependent_tenant_id = ? ORDER BY d.depends_on_tenant_id",
    )
    .bind(tenant_id)
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    .expect("current dependency pins");
    rows.iter()
        .map(|row| {
            (
                row.try_get("depends_on_tenant_id").expect("depends_on"),
                row.try_get("pinned_generation").expect("pinned_generation"),
                row.try_get("pinned_revoke_fence")
                    .expect("pinned_revoke_fence"),
                row.try_get("pinned_relationship_revision")
                    .expect("pinned_relationship_revision"),
            )
        })
        .collect()
}

/// 根 grant source-head 变更波次：直接子单元先失效、孙单元只在**每个锚点各自
/// 重新发布后**由派生 child intent 失效。锚点 publication 未跟上时 propagate 与
/// complete 双门都以 `anchor_publication_stale` 拒绝；二次 source 变更使旧意图
/// superseded 免写安全完成；新意图有界批（selected == batch_limit 绝不 done）+
/// 同事件重入幂等（outbox marker 排除、无 NODE revision 账）+ generation-only
/// 推进（revoke_fence / relationship_revision 全程不变）；子单元重发布后其
/// intent 才推进孙单元；孙单元重发布后依赖钉刷新为当前祖先头。
#[tokio::test]
#[ignore]
async fn org_scope_dependency_propagate_root_grant_wave_child_then_grandchild_after_republication()
{
    let Some(pool) = connect().await else {
        return;
    };
    require_org_scope_schema(&pool).await;
    cleanup_tenant_set(&pool, &DEP_WAVE_TENANTS).await;
    let repo = SqlxOrgScopeRepository::new(pool.clone());

    // 拓扑：R → C → G（grant-less；publication 零 segment 合法）。
    submit_and_approve(
        &repo,
        OrgRequestPayload::RootInit {
            root_tenant_id: DEP_ROOT_TENANT,
            initial_grants: Vec::new(),
        },
        DEP_ROOT_TENANT,
        None,
        "dep-root-init",
        Some(root_governance_proof(DEP_ROOT_TENANT, "dep-root")),
    )
    .await;
    let attach_child = submit_and_approve(
        &repo,
        OrgRequestPayload::Attach {
            child_tenant_id: DEP_CHILD_TENANT,
            parent_tenant_id: DEP_ROOT_TENANT,
        },
        DEP_CHILD_TENANT,
        Some(DEP_ROOT_TENANT),
        "dep-attach-child",
        None,
    )
    .await;
    let attach_grandchild = submit_and_approve(
        &repo,
        OrgRequestPayload::Attach {
            child_tenant_id: DEP_GRANDCHILD_TENANT,
            parent_tenant_id: DEP_CHILD_TENANT,
        },
        DEP_GRANDCHILD_TENANT,
        Some(DEP_CHILD_TENANT),
        "dep-attach-grandchild",
        None,
    )
    .await;
    let root_convergence = converge_unit(&repo, DEP_ROOT_TENANT).await;
    let child_convergence = converge_unit(&repo, DEP_CHILD_TENANT).await;
    converge_unit(&repo, DEP_GRANDCHILD_TENANT).await;
    let root_head = node_head_of(&pool, DEP_ROOT_TENANT).await;
    let child_head = node_head_of(&pool, DEP_CHILD_TENANT).await;
    let grand_head = node_head_of(&pool, DEP_GRANDCHILD_TENANT).await;

    // 设置期依赖意图（attach 推进父头时落）已在收敛中驱动：依赖钉已与当前头
    // 一致 → 空批（已收敛依赖绝不重复失效）、done、未被取代；完成后事件队列
    // 对波次干净。
    let settled = dependency_outcome_of(&root_convergence, &attach_child.operation_id);
    assert!(settled.updated_tenant_ids.is_empty());
    assert!(settled.done);
    assert!(!settled.superseded);
    let settled = dependency_outcome_of(&child_convergence, &attach_grandchild.operation_id);
    assert!(settled.updated_tenant_ids.is_empty());
    assert!(settled.done);
    assert!(!settled.superseded);

    // ── 根 grant X：R head +1，落 GRANT_ISSUED(X) + DEPENDENCY_PROPAGATE(X)──
    let grant_x = submit_and_approve(
        &repo,
        OrgRequestPayload::RootGrant {
            root_tenant_id: DEP_ROOT_TENANT,
            scope: scope_for(DEP_ROOT_TENANT, "learn_subject", "write"),
            delegable: false,
        },
        DEP_ROOT_TENANT,
        Some(DEP_ROOT_TENANT),
        "dep-root-grant-x",
        Some(root_governance_proof(DEP_ROOT_TENANT, "dep-grant-x")),
    )
    .await;
    let op_x = grant_x.operation_id;
    let root_after_x = node_head_of(&pool, DEP_ROOT_TENANT).await;
    assert_eq!(root_after_x.generation, root_head.generation + 1);
    assert_eq!(root_after_x.revoke_fence, root_head.revoke_fence);
    assert_eq!(
        root_after_x.relationship_revision,
        root_head.relationship_revision
    );

    // 认领 X 意图（途中的 GRANT_ISSUED(X) 及设置期残留事件由 helper 终态化；
    // R 的当前 publication 因此停在旧头 —— 正是待测的 stale 窗口）。载荷必须
    // 精确钉住变更后锚点头。
    let lease_x = claim_lease_of_kind(
        &repo,
        DEP_ROOT_TENANT,
        OrgOutboxEventKind::DependencyPropagate,
        &op_x,
    )
    .await;
    let intent_x: OrgDependencyPropagatePayload =
        serde_json::from_str(&lease_x.payload_json).expect("typed X intent");
    assert_eq!(intent_x.anchor_tenant_id, DEP_ROOT_TENANT);
    assert_eq!(intent_x.root_tenant_id, DEP_ROOT_TENANT);
    assert_eq!(
        u64::try_from(root_after_x.generation).expect("generation fits u64"),
        intent_x.generation
    );
    assert_eq!(
        u64::try_from(root_after_x.revoke_fence).expect("fence fits u64"),
        intent_x.revoke_fence
    );
    assert_eq!(
        u64::try_from(root_after_x.relationship_revision).expect("revision fits u64"),
        intent_x.relationship_revision
    );
    let leased_x = outbox_state_of(&pool, lease_x.org_event_id).await;
    assert_eq!(leased_x.status, "LEASED");

    // 锚点未重发布 → 传播拒绝（publication 栅栏），事件保持 LEASED/CAS 不动。
    let error = repo
        .propagate_dependency_change(&dependency_propagate_command(
            &lease_x,
            ORG_MAX_PROPAGATE_BATCH,
        ))
        .await
        .expect_err("propagation before anchor re-publication must be refused");
    assert!(error
        .to_string()
        .contains("org_scope.dependency_propagate_anchor_publication_stale"));
    let state_x = outbox_state_of(&pool, lease_x.org_event_id).await;
    assert_eq!(state_x.status, "LEASED");
    assert_eq!(state_x.cas_version, leased_x.cas_version);

    // 完成门同栅栏：未重发布前完成同样拒绝。
    let error = repo
        .complete_outbox_event(&complete_command(
            lease_x.org_event_id,
            OrgOutboxEventKind::DependencyPropagate,
        ))
        .await
        .expect_err("completion before anchor re-publication must be refused");
    assert!(error
        .to_string()
        .contains("org_scope.dependency_propagate_anchor_publication_stale"));
    assert_eq!(
        outbox_state_of(&pool, lease_x.org_event_id).await.status,
        "LEASED"
    );

    // ── 二次根 grant Y：R head 再 +1；重发布后 X 意图被取代（免写安全完成）──
    let grant_y = submit_and_approve(
        &repo,
        OrgRequestPayload::RootGrant {
            root_tenant_id: DEP_ROOT_TENANT,
            scope: scope_for(DEP_ROOT_TENANT, "learn_subject", "delete"),
            delegable: false,
        },
        DEP_ROOT_TENANT,
        Some(DEP_ROOT_TENANT),
        "dep-root-grant-y",
        Some(root_governance_proof(DEP_ROOT_TENANT, "dep-grant-y")),
    )
    .await;
    let op_y = grant_y.operation_id;
    claim_and_publish_unit(&repo, DEP_ROOT_TENANT).await;
    let root_republished = node_head_of(&pool, DEP_ROOT_TENANT).await;
    assert_eq!(root_republished.generation, root_head.generation + 2);

    let superseded = repo
        .propagate_dependency_change(&dependency_propagate_command(
            &lease_x,
            ORG_MAX_PROPAGATE_BATCH,
        ))
        .await
        .expect("superseded intent must be safely released");
    assert!(superseded.superseded);
    assert!(superseded.done);
    assert!(superseded.updated_tenant_ids.is_empty());
    // 取代传播零写入：子/孙头原样，C 无 X 派生工件。
    assert_eq!(node_head_of(&pool, DEP_CHILD_TENANT).await, child_head);
    assert_eq!(node_head_of(&pool, DEP_GRANDCHILD_TENANT).await, grand_head);
    assert_eq!(
        dependency_intent_count(&pool, DEP_CHILD_TENANT, &op_x).await,
        0
    );
    assert_eq!(
        outbox_kind_operation_count(&pool, DEP_CHILD_TENANT, "NODE_MUTATED", &op_x).await,
        0
    );
    repo.complete_outbox_event(&complete_command(
        lease_x.org_event_id,
        OrgOutboxEventKind::DependencyPropagate,
    ))
    .await
    .expect("superseded intent completes without drain proof");
    assert_eq!(
        outbox_state_of(&pool, lease_x.org_event_id).await.status,
        "DONE"
    );

    // ── Y 波：有界批（selected == batch_limit ⇒ 绝不 done）+ 重入幂等 ──────
    let lease_y = claim_lease_of_kind(
        &repo,
        DEP_ROOT_TENANT,
        OrgOutboxEventKind::DependencyPropagate,
        &op_y,
    )
    .await;
    let error = repo
        .propagate_dependency_change(&dependency_propagate_command(&lease_y, 0))
        .await
        .expect_err("batch_limit=0 must be refused before any write");
    assert!(error
        .to_string()
        .contains("org_scope.propagate_batch_invalid"));

    let batch1 = repo
        .propagate_dependency_change(&dependency_propagate_command(&lease_y, 1))
        .await
        .expect("bounded batch");
    assert_eq!(batch1.updated_tenant_ids, vec![DEP_CHILD_TENANT]);
    assert!(
        !batch1.done,
        "selected == batch_limit must never report done"
    );
    assert!(!batch1.superseded);
    // 同事件重入：marker 排除已推进子节点 → 空批 + done；C 恰好推进一次。
    let batch2 = repo
        .propagate_dependency_change(&dependency_propagate_command(
            &lease_y,
            ORG_MAX_PROPAGATE_BATCH,
        ))
        .await
        .expect("idempotent re-entry");
    assert!(batch2.updated_tenant_ids.is_empty());
    assert!(batch2.done);
    assert!(!batch2.superseded);

    let child_after_wave = node_head_of(&pool, DEP_CHILD_TENANT).await;
    assert_eq!(child_after_wave.generation, child_head.generation + 1);
    assert_eq!(
        child_after_wave.revoke_fence, child_head.revoke_fence,
        "dependency propagation must never advance revoke_fence"
    );
    assert_eq!(
        child_after_wave.relationship_revision, child_head.relationship_revision,
        "dependency propagation must never advance relationship_revision"
    );
    assert_eq!(child_after_wave.last_operation_id, op_y);
    // 锚点自身与孙单元都不被根波触碰。
    assert_eq!(node_head_of(&pool, DEP_ROOT_TENANT).await, root_republished);
    assert_eq!(node_head_of(&pool, DEP_GRANDCHILD_TENANT).await, grand_head);
    // 派生工件：C 的 NODE_MUTATED + typed child intent；幂等标记是 outbox 行
    // 而非 NODE revision 账。
    assert_eq!(
        dependency_intent_count(&pool, DEP_CHILD_TENANT, &op_y).await,
        1
    );
    assert_eq!(
        outbox_kind_operation_count(&pool, DEP_CHILD_TENANT, "NODE_MUTATED", &op_y).await,
        1
    );
    assert_eq!(
        node_revision_mark_count(&pool, DEP_CHILD_TENANT, &op_y).await,
        0
    );
    // 波次审计只在锚点落一条 DEPENDENCY_PROPAGATED（X 被取代 → 零审计）。
    assert_eq!(
        audit_count_for_operation_action(&pool, &op_y, "DEPENDENCY_PROPAGATED").await,
        1
    );
    assert_eq!(
        audit_count_for_operation_action(&pool, &op_x, "DEPENDENCY_PROPAGATED").await,
        0
    );

    // 排空后完成（C 的 marker 即收敛证明）+ 重放拒绝。
    repo.complete_outbox_event(&complete_command(
        lease_y.org_event_id,
        OrgOutboxEventKind::DependencyPropagate,
    ))
    .await
    .expect("completion after drain");
    let state_y = outbox_state_of(&pool, lease_y.org_event_id).await;
    assert_eq!(state_y.status, "DONE");
    assert!(state_y.lease_owner.is_none());
    let error = repo
        .complete_outbox_event(&complete_command(
            lease_y.org_event_id,
            OrgOutboxEventKind::DependencyPropagate,
        ))
        .await
        .expect_err("re-completion must fail");
    assert!(error.to_string().contains("org_scope.outbox_lease_lost"));

    // ── C 波：孙单元只在子锚点重新发布后失效 ─────────────────────────────
    claim_and_publish_unit(&repo, DEP_CHILD_TENANT).await;
    let lease_c = claim_lease_of_kind(
        &repo,
        DEP_CHILD_TENANT,
        OrgOutboxEventKind::DependencyPropagate,
        &op_y,
    )
    .await;
    let out_c = repo
        .propagate_dependency_change(&dependency_propagate_command(
            &lease_c,
            ORG_MAX_PROPAGATE_BATCH,
        ))
        .await
        .expect("child wave");
    assert_eq!(out_c.updated_tenant_ids, vec![DEP_GRANDCHILD_TENANT]);
    assert!(out_c.done);
    let grand_after = node_head_of(&pool, DEP_GRANDCHILD_TENANT).await;
    assert_eq!(grand_after.generation, grand_head.generation + 1);
    assert_eq!(grand_after.revoke_fence, grand_head.revoke_fence);
    assert_eq!(
        grand_after.relationship_revision,
        grand_head.relationship_revision
    );
    assert_eq!(grand_after.last_operation_id, op_y);
    assert_eq!(
        node_head_of(&pool, DEP_CHILD_TENANT).await,
        child_after_wave
    );
    repo.complete_outbox_event(&complete_command(
        lease_c.org_event_id,
        OrgOutboxEventKind::DependencyPropagate,
    ))
    .await
    .expect("child wave completion");

    // 孙单元重发布：依赖钉刷新为当前祖先头（root 新头 + child 新头）。
    claim_and_publish_unit(&repo, DEP_GRANDCHILD_TENANT).await;
    let lease_g = claim_lease_of_kind(
        &repo,
        DEP_GRANDCHILD_TENANT,
        OrgOutboxEventKind::DependencyPropagate,
        &op_y,
    )
    .await;
    let out_g = repo
        .propagate_dependency_change(&dependency_propagate_command(
            &lease_g,
            ORG_MAX_PROPAGATE_BATCH,
        ))
        .await
        .expect("leaf wave");
    assert!(out_g.updated_tenant_ids.is_empty());
    assert!(out_g.done);
    repo.complete_outbox_event(&complete_command(
        lease_g.org_event_id,
        OrgOutboxEventKind::DependencyPropagate,
    ))
    .await
    .expect("leaf wave completion");
    assert_eq!(
        current_dependency_pins(&pool, DEP_GRANDCHILD_TENANT).await,
        vec![
            (
                DEP_ROOT_TENANT,
                root_republished.generation,
                root_republished.revoke_fence,
                root_republished.relationship_revision
            ),
            (
                DEP_CHILD_TENANT,
                child_after_wave.generation,
                child_after_wave.revoke_fence,
                child_after_wave.relationship_revision
            ),
        ],
        "grandchild republication must pin the refreshed ancestor heads"
    );

    cleanup_tenant_set(&pool, &DEP_WAVE_TENANTS).await;
}

/// mask apply/remove/revoke 变更波次：锚点（C）连续两次 source-head 变更
/// （mask apply → mask remove）在其单次重发布内**合并为一次**失效 —— 旧意图被
/// 更新头取代（superseded 免写安全完成，G 零变更），新意图传播后 G 恰好 +1；
/// 随后 grant revoke 波再 +1；全部波次 generation-only（G 的 revoke_fence /
/// relationship_revision 全程不变），R 头全程不动。
#[tokio::test]
#[ignore]
async fn org_scope_dependency_propagate_mask_remove_revoke_waves_coalesce_and_advance_generation_only(
) {
    let Some(pool) = connect().await else {
        return;
    };
    require_org_scope_schema(&pool).await;
    cleanup_tenant_set(&pool, &DEP_MASK_TENANTS).await;
    let repo = SqlxOrgScopeRepository::new(pool.clone());

    // 授权链：root-init(seed grant, delegable) → grant C ← R → attach G →
    // grant G ← C；发布 R → C → G。
    submit_and_approve(
        &repo,
        OrgRequestPayload::RootInit {
            root_tenant_id: DEP_MASK_ROOT_TENANT,
            initial_grants: vec![OrgGrantSeed {
                scope: scope_for(DEP_MASK_ROOT_TENANT, "learn_subject", "read"),
                delegable: true,
            }],
        },
        DEP_MASK_ROOT_TENANT,
        None,
        "dep-mask-root-init",
        Some(root_governance_proof(DEP_MASK_ROOT_TENANT, "dep-mask-root")),
    )
    .await;
    submit_and_approve(
        &repo,
        OrgRequestPayload::Attach {
            child_tenant_id: DEP_MASK_CHILD_TENANT,
            parent_tenant_id: DEP_MASK_ROOT_TENANT,
        },
        DEP_MASK_CHILD_TENANT,
        Some(DEP_MASK_ROOT_TENANT),
        "dep-mask-attach-child",
        None,
    )
    .await;
    let (root_grant_id, root_grant_revision) = parent_grant_of(&pool, DEP_MASK_ROOT_TENANT).await;
    let grant_child = submit_and_approve(
        &repo,
        OrgRequestPayload::Grant {
            receiving_tenant_id: DEP_MASK_CHILD_TENANT,
            parent_grant: OrgGrantRef {
                tenant_id: DEP_MASK_ROOT_TENANT,
                grant_id: root_grant_id.clone(),
                revision: root_grant_revision,
            },
            scope: scope_for(DEP_MASK_ROOT_TENANT, "learn_subject", "read"),
            delegable: true,
            subject: None,
        },
        DEP_MASK_CHILD_TENANT,
        Some(DEP_MASK_ROOT_TENANT),
        "dep-mask-grant-child",
        None,
    )
    .await;
    let attach_grandchild = submit_and_approve(
        &repo,
        OrgRequestPayload::Attach {
            child_tenant_id: DEP_MASK_GRANDCHILD_TENANT,
            parent_tenant_id: DEP_MASK_CHILD_TENANT,
        },
        DEP_MASK_GRANDCHILD_TENANT,
        Some(DEP_MASK_CHILD_TENANT),
        "dep-mask-attach-grandchild",
        None,
    )
    .await;
    let (child_grant_id, child_grant_revision) =
        parent_grant_of(&pool, DEP_MASK_CHILD_TENANT).await;
    let grant_grandchild = submit_and_approve(
        &repo,
        OrgRequestPayload::Grant {
            receiving_tenant_id: DEP_MASK_GRANDCHILD_TENANT,
            parent_grant: OrgGrantRef {
                tenant_id: DEP_MASK_CHILD_TENANT,
                grant_id: child_grant_id.clone(),
                revision: child_grant_revision,
            },
            scope: scope_for(DEP_MASK_ROOT_TENANT, "learn_subject", "read"),
            delegable: false,
            subject: None,
        },
        DEP_MASK_GRANDCHILD_TENANT,
        Some(DEP_MASK_CHILD_TENANT),
        "dep-mask-grant-grandchild",
        None,
    )
    .await;
    let _root_convergence = converge_unit(&repo, DEP_MASK_ROOT_TENANT).await;
    let child_convergence = converge_unit(&repo, DEP_MASK_CHILD_TENANT).await;
    let grand_convergence = converge_unit(&repo, DEP_MASK_GRANDCHILD_TENANT).await;
    let root_head = node_head_of(&pool, DEP_MASK_ROOT_TENANT).await;
    let child_head = node_head_of(&pool, DEP_MASK_CHILD_TENANT).await;
    let grand_head = node_head_of(&pool, DEP_MASK_GRANDCHILD_TENANT).await;

    // 设置期 intent 排空（收敛中驱动）：grant-C 意图（payload 钉中间头）被
    // attach-G 推进的更新头取代 → superseded 免写安全完成；其余 intent 的
    // 依赖钉已与当前头一致 → 空批。
    let superseded_setup = dependency_outcome_of(&child_convergence, &grant_child.operation_id);
    assert!(superseded_setup.superseded);
    assert!(superseded_setup.done);
    assert!(superseded_setup.updated_tenant_ids.is_empty());
    let settled = dependency_outcome_of(&child_convergence, &attach_grandchild.operation_id);
    assert!(settled.updated_tenant_ids.is_empty());
    assert!(!settled.superseded);
    let settled = dependency_outcome_of(&grand_convergence, &grant_grandchild.operation_id);
    assert!(settled.updated_tenant_ids.is_empty());

    // ── W1 mask apply（C head +1）→ W2 mask remove（C head 再 +1），期间不
    //    重发布：两次 source 变更尚未被任何 publication 吸收 ─────────────────
    let mask_generation = node_generation_of(&pool, DEP_MASK_CHILD_TENANT).await;
    let mask_outcome = repo
        .apply_mask(&OrgMaskApplyCommand {
            operation_id: unique_operation("dep-mask-apply"),
            actor_user_id: 1,
            actor_tenant_id: Some(DEP_MASK_CHILD_TENANT),
            tenant_id: DEP_MASK_CHILD_TENANT,
            target: OrgGrantRef {
                tenant_id: DEP_MASK_ROOT_TENANT,
                grant_id: root_grant_id.clone(),
                revision: root_grant_revision,
            },
            expected_unit_generation: mask_generation,
            reason: Some("e2e dependency wave mask".into()),
        })
        .await
        .expect("mask apply");
    let op_w1 = mask_outcome.operation_id;
    let mask_id = mask_outcome
        .records
        .iter()
        .find(|record| record.record_kind == "MASK_APPLIED")
        .expect("mask apply record")
        .subject_id
        .clone();
    let remove_outcome = repo
        .remove_mask(&OrgMaskRemoveCommand {
            operation_id: unique_operation("dep-mask-remove"),
            actor_user_id: 1,
            actor_tenant_id: Some(DEP_MASK_CHILD_TENANT),
            tenant_id: DEP_MASK_CHILD_TENANT,
            mask_id,
            expected_revision: 1,
        })
        .await
        .expect("mask remove");
    let op_w2 = remove_outcome.operation_id;

    // 认领 W1 意图（MASK_APPLIED(W1) 由 helper 终态化 —— 其 publication 事件
    // 不再需要，头已在 W2 事务内推进）。锚点头（W2 后）高于 W1 载荷头 →
    // superseded：零写入、免收敛证明安全完成。
    let lease_w1 = claim_lease_of_kind(
        &repo,
        DEP_MASK_CHILD_TENANT,
        OrgOutboxEventKind::DependencyPropagate,
        &op_w1,
    )
    .await;
    let superseded_w1 = repo
        .propagate_dependency_change(&dependency_propagate_command(
            &lease_w1,
            ORG_MAX_PROPAGATE_BATCH,
        ))
        .await
        .expect("superseded mask intent must be safely released");
    assert!(superseded_w1.superseded);
    assert!(superseded_w1.done);
    assert!(superseded_w1.updated_tenant_ids.is_empty());
    assert_eq!(
        node_head_of(&pool, DEP_MASK_GRANDCHILD_TENANT).await,
        grand_head
    );
    assert_eq!(
        dependency_intent_count(&pool, DEP_MASK_GRANDCHILD_TENANT, &op_w1).await,
        0
    );
    assert_eq!(
        outbox_kind_operation_count(&pool, DEP_MASK_GRANDCHILD_TENANT, "NODE_MUTATED", &op_w1)
            .await,
        0
    );
    assert_eq!(
        audit_count_for_operation_action(&pool, &op_w1, "DEPENDENCY_PROPAGATED").await,
        0
    );
    repo.complete_outbox_event(&complete_command(
        lease_w1.org_event_id,
        OrgOutboxEventKind::DependencyPropagate,
    ))
    .await
    .expect("superseded intent completes without drain proof");
    assert_eq!(
        outbox_state_of(&pool, lease_w1.org_event_id).await.status,
        "DONE"
    );

    // 锚点单次重发布（consume MASK_REMOVED(W2)）→ 两次变更合并吸收到同一头。
    claim_and_publish_unit(&repo, DEP_MASK_CHILD_TENANT).await;
    let child_coalesced = node_head_of(&pool, DEP_MASK_CHILD_TENANT).await;
    assert_eq!(child_coalesced.generation, child_head.generation + 2);

    // W2 波：G 恰好 +1（两次变更合并为一次失效），generation-only。
    let lease_w2 = claim_lease_of_kind(
        &repo,
        DEP_MASK_CHILD_TENANT,
        OrgOutboxEventKind::DependencyPropagate,
        &op_w2,
    )
    .await;
    let out_w2 = repo
        .propagate_dependency_change(&dependency_propagate_command(
            &lease_w2,
            ORG_MAX_PROPAGATE_BATCH,
        ))
        .await
        .expect("mask wave");
    assert_eq!(out_w2.updated_tenant_ids, vec![DEP_MASK_GRANDCHILD_TENANT]);
    assert!(out_w2.done);
    let grand_after_w2 = node_head_of(&pool, DEP_MASK_GRANDCHILD_TENANT).await;
    assert_eq!(grand_after_w2.generation, grand_head.generation + 1);
    assert_eq!(grand_after_w2.revoke_fence, grand_head.revoke_fence);
    assert_eq!(
        grand_after_w2.relationship_revision,
        grand_head.relationship_revision
    );
    assert_eq!(grand_after_w2.last_operation_id, op_w2);
    assert_eq!(
        node_head_of(&pool, DEP_MASK_CHILD_TENANT).await,
        child_coalesced
    );
    assert_eq!(
        audit_count_for_operation_action(&pool, &op_w2, "DEPENDENCY_PROPAGATED").await,
        1
    );
    repo.complete_outbox_event(&complete_command(
        lease_w2.org_event_id,
        OrgOutboxEventKind::DependencyPropagate,
    ))
    .await
    .expect("mask wave completion");

    // 孙单元重发布：钉刷新为 R 与合并后的 C 当前头。
    claim_and_publish_unit(&repo, DEP_MASK_GRANDCHILD_TENANT).await;
    assert_eq!(
        current_dependency_pins(&pool, DEP_MASK_GRANDCHILD_TENANT).await,
        vec![
            (
                DEP_MASK_ROOT_TENANT,
                root_head.generation,
                root_head.revoke_fence,
                root_head.relationship_revision
            ),
            (
                DEP_MASK_CHILD_TENANT,
                child_coalesced.generation,
                child_coalesced.revoke_fence,
                child_coalesced.relationship_revision
            ),
        ],
        "grandchild republication must pin the coalesced child head"
    );

    // ── W3 grant revoke 波：撤销 C 收到的 grant（narrowing）→ C head 再 +1 →
    //    重发布 → 传播 → G 再 +1；fence/relationship 仍全程不变 ─────────────
    let revoke_outcome = repo
        .revoke_grant(&OrgGrantRevokeCommand {
            operation_id: unique_operation("dep-mask-revoke"),
            actor_user_id: 1,
            actor_tenant_id: Some(DEP_MASK_CHILD_TENANT),
            receiving_tenant_id: DEP_MASK_CHILD_TENANT,
            grant_id: child_grant_id.clone(),
            expected_revision: child_grant_revision,
            reason: Some("e2e dependency wave revoke".into()),
        })
        .await
        .expect("grant revoke");
    let op_w3 = revoke_outcome.operation_id;
    claim_and_publish_unit(&repo, DEP_MASK_CHILD_TENANT).await;
    let child_after_revoke = node_head_of(&pool, DEP_MASK_CHILD_TENANT).await;
    assert_eq!(child_after_revoke.generation, child_head.generation + 3);
    let out_w3 = run_dependency_intent(&repo, DEP_MASK_CHILD_TENANT, &op_w3).await;
    assert_eq!(out_w3.updated_tenant_ids, vec![DEP_MASK_GRANDCHILD_TENANT]);
    assert!(out_w3.done);
    assert!(!out_w3.superseded);
    let grand_after_w3 = node_head_of(&pool, DEP_MASK_GRANDCHILD_TENANT).await;
    assert_eq!(grand_after_w3.generation, grand_head.generation + 2);
    assert_eq!(grand_after_w3.revoke_fence, grand_head.revoke_fence);
    assert_eq!(
        grand_after_w3.relationship_revision,
        grand_head.relationship_revision
    );
    // 全部波次中根头不动（依赖传播只作用于直接依赖者）。
    assert_eq!(node_head_of(&pool, DEP_MASK_ROOT_TENANT).await, root_head);

    cleanup_tenant_set(&pool, &DEP_MASK_TENANTS).await;
}

/// MOVE 改挂波次：MOVE 事务内被移动单元三计数同步 +1，新旧父头各 +1 并各落
/// DEPENDENCY_PROPAGATE intent；新父 intent 必须等**新父当前 publication** 跟上
/// （重发布后传播才放行）；被移动单元在重发布前对新父**无依赖钉** → 不被新父
/// 波选中（其失效已在 MOVE 事务内完成），旧父波也因父子边消失而不再选中它；
/// 各自父下的既有子单元（旧钉失配）被 generation-only 推进；被移动单元重发布
/// 后新父钉建立（flatten 依赖只含 [R, 新父]）；此后新父的后续 source 变更与
/// 既有子单元一起以有界批失效它（完成前排空门拒绝）。
#[tokio::test]
#[ignore]
async fn org_scope_dependency_propagate_reparenting_old_and_new_parent_waves() {
    let Some(pool) = connect().await else {
        return;
    };
    require_org_scope_schema(&pool).await;
    cleanup_tenant_set(&pool, &DEP_MV_TENANTS).await;
    let repo = SqlxOrgScopeRepository::new(pool.clone());

    // 拓扑：R ← {P1, P2}；M、L 挂 P1；K 挂 P2（grant-less；零 segment 合法）。
    submit_and_approve(
        &repo,
        OrgRequestPayload::RootInit {
            root_tenant_id: DEP_MV_ROOT_TENANT,
            initial_grants: Vec::new(),
        },
        DEP_MV_ROOT_TENANT,
        None,
        "dep-mv-root-init",
        Some(root_governance_proof(DEP_MV_ROOT_TENANT, "dep-mv-root")),
    )
    .await;
    let attach_p1 = submit_and_approve(
        &repo,
        OrgRequestPayload::Attach {
            child_tenant_id: DEP_MV_PARENT_OLD,
            parent_tenant_id: DEP_MV_ROOT_TENANT,
        },
        DEP_MV_PARENT_OLD,
        Some(DEP_MV_ROOT_TENANT),
        "dep-mv-attach-p1",
        None,
    )
    .await;
    let attach_p2 = submit_and_approve(
        &repo,
        OrgRequestPayload::Attach {
            child_tenant_id: DEP_MV_PARENT_NEW,
            parent_tenant_id: DEP_MV_ROOT_TENANT,
        },
        DEP_MV_PARENT_NEW,
        Some(DEP_MV_ROOT_TENANT),
        "dep-mv-attach-p2",
        None,
    )
    .await;
    let attach_m = submit_and_approve(
        &repo,
        OrgRequestPayload::Attach {
            child_tenant_id: DEP_MV_MOVED,
            parent_tenant_id: DEP_MV_PARENT_OLD,
        },
        DEP_MV_MOVED,
        Some(DEP_MV_PARENT_OLD),
        "dep-mv-attach-m",
        None,
    )
    .await;
    let attach_l = submit_and_approve(
        &repo,
        OrgRequestPayload::Attach {
            child_tenant_id: DEP_MV_OLD_SIBLING,
            parent_tenant_id: DEP_MV_PARENT_OLD,
        },
        DEP_MV_OLD_SIBLING,
        Some(DEP_MV_PARENT_OLD),
        "dep-mv-attach-l",
        None,
    )
    .await;
    let attach_k = submit_and_approve(
        &repo,
        OrgRequestPayload::Attach {
            child_tenant_id: DEP_MV_NEW_CHILD,
            parent_tenant_id: DEP_MV_PARENT_NEW,
        },
        DEP_MV_NEW_CHILD,
        Some(DEP_MV_PARENT_NEW),
        "dep-mv-attach-k",
        None,
    )
    .await;
    let root_convergence = converge_unit(&repo, DEP_MV_ROOT_TENANT).await;
    let old_parent_convergence = converge_unit(&repo, DEP_MV_PARENT_OLD).await;
    let new_parent_convergence = converge_unit(&repo, DEP_MV_PARENT_NEW).await;
    converge_unit(&repo, DEP_MV_MOVED).await;
    converge_unit(&repo, DEP_MV_OLD_SIBLING).await;
    converge_unit(&repo, DEP_MV_NEW_CHILD).await;
    let root_head = node_head_of(&pool, DEP_MV_ROOT_TENANT).await;
    let old_parent_head = node_head_of(&pool, DEP_MV_PARENT_OLD).await;
    let new_parent_head = node_head_of(&pool, DEP_MV_PARENT_NEW).await;
    let moved_head = node_head_of(&pool, DEP_MV_MOVED).await;
    let old_sibling_head = node_head_of(&pool, DEP_MV_OLD_SIBLING).await;
    let new_child_head = node_head_of(&pool, DEP_MV_NEW_CHILD).await;

    // 设置期 intent 排空（收敛中驱动）：两个父挂载的旧意图被后续挂载推进的
    // 头取代（superseded），其余为已收敛空批。
    let superseded = dependency_outcome_of(&root_convergence, &attach_p1.operation_id);
    assert!(superseded.superseded);
    assert!(superseded.updated_tenant_ids.is_empty());
    let settled = dependency_outcome_of(&root_convergence, &attach_p2.operation_id);
    assert!(settled.updated_tenant_ids.is_empty());
    assert!(!settled.superseded);
    let superseded = dependency_outcome_of(&old_parent_convergence, &attach_m.operation_id);
    assert!(superseded.superseded);
    let settled = dependency_outcome_of(&old_parent_convergence, &attach_l.operation_id);
    assert!(settled.updated_tenant_ids.is_empty());
    let settled = dependency_outcome_of(&new_parent_convergence, &attach_k.operation_id);
    assert!(settled.updated_tenant_ids.is_empty());

    // ── MOVE M：P1 → P2（同根）。M 三计数同步 +1；两父头各 +1 并各落 intent。
    let move_outcome = submit_and_approve(
        &repo,
        OrgRequestPayload::Move {
            child_tenant_id: DEP_MV_MOVED,
            new_parent_tenant_id: DEP_MV_PARENT_NEW,
        },
        DEP_MV_MOVED,
        Some(DEP_MV_PARENT_NEW),
        "dep-mv-move",
        None,
    )
    .await;
    let op_mv = move_outcome.operation_id;
    let moved_after_move = node_head_of(&pool, DEP_MV_MOVED).await;
    assert_eq!(moved_after_move.generation, moved_head.generation + 1);
    assert_eq!(moved_after_move.revoke_fence, moved_head.revoke_fence + 1);
    assert_eq!(
        moved_after_move.relationship_revision,
        moved_head.relationship_revision + 1
    );
    assert_eq!(moved_after_move.parent_tenant_id, Some(DEP_MV_PARENT_NEW));
    let old_parent_after_move = node_head_of(&pool, DEP_MV_PARENT_OLD).await;
    assert_eq!(
        old_parent_after_move.generation,
        old_parent_head.generation + 1
    );
    let new_parent_after_move = node_head_of(&pool, DEP_MV_PARENT_NEW).await;
    assert_eq!(
        new_parent_after_move.generation,
        new_parent_head.generation + 1
    );

    // 双锚点各自重发布（MOVE 的 NODE_TOPOLOGY_CHANGED 事件）。
    claim_and_publish_unit(&repo, DEP_MV_PARENT_OLD).await;
    claim_and_publish_unit(&repo, DEP_MV_PARENT_NEW).await;

    // 新父波：M 的当前 publication 发布于改挂前，对 P2 无依赖钉 → 不被选中；
    // K 的 P2 钉失配 → generation-only +1。
    let lease_p2 = claim_lease_of_kind(
        &repo,
        DEP_MV_PARENT_NEW,
        OrgOutboxEventKind::DependencyPropagate,
        &op_mv,
    )
    .await;
    let intent_p2: OrgDependencyPropagatePayload =
        serde_json::from_str(&lease_p2.payload_json).expect("typed move intent");
    assert_eq!(intent_p2.anchor_tenant_id, DEP_MV_PARENT_NEW);
    assert_eq!(intent_p2.root_tenant_id, DEP_MV_ROOT_TENANT);
    assert_eq!(
        u64::try_from(new_parent_after_move.generation).expect("generation fits u64"),
        intent_p2.generation
    );
    let out_p2 = repo
        .propagate_dependency_change(&dependency_propagate_command(
            &lease_p2,
            ORG_MAX_PROPAGATE_BATCH,
        ))
        .await
        .expect("new-parent wave");
    assert_eq!(out_p2.updated_tenant_ids, vec![DEP_MV_NEW_CHILD]);
    assert!(out_p2.done);
    let new_child_after = node_head_of(&pool, DEP_MV_NEW_CHILD).await;
    assert_eq!(new_child_after.generation, new_child_head.generation + 1);
    assert_eq!(new_child_after.revoke_fence, new_child_head.revoke_fence);
    assert_eq!(
        new_child_after.relationship_revision,
        new_child_head.relationship_revision
    );
    assert_eq!(node_head_of(&pool, DEP_MV_MOVED).await, moved_after_move);
    repo.complete_outbox_event(&complete_command(
        lease_p2.org_event_id,
        OrgOutboxEventKind::DependencyPropagate,
    ))
    .await
    .expect("new-parent wave completion");

    // 旧父波：L（P1 钉失配）被选中；M 的父子边已消失 → 不被旧父波选中。
    let out_p1 = run_dependency_intent(&repo, DEP_MV_PARENT_OLD, &op_mv).await;
    assert_eq!(out_p1.updated_tenant_ids, vec![DEP_MV_OLD_SIBLING]);
    assert!(out_p1.done);
    let old_sibling_after = node_head_of(&pool, DEP_MV_OLD_SIBLING).await;
    assert_eq!(
        old_sibling_after.generation,
        old_sibling_head.generation + 1
    );
    assert_eq!(
        old_sibling_after.revoke_fence,
        old_sibling_head.revoke_fence
    );
    assert_eq!(
        old_sibling_after.relationship_revision,
        old_sibling_head.relationship_revision
    );
    assert_eq!(node_head_of(&pool, DEP_MV_MOVED).await, moved_after_move);

    // M 重发布：新父钉建立（钉 P2 当前 publication），flatten 依赖只含
    // [R, P2]；旧父钉随旧 publication 成为历史行。
    let moved_publication = claim_and_publish_unit(&repo, DEP_MV_MOVED).await;
    assert_eq!(
        moved_publication
            .dependencies
            .iter()
            .map(|dependency| dependency.tenant_id)
            .collect::<Vec<_>>(),
        vec![DEP_MV_ROOT_TENANT, DEP_MV_PARENT_NEW],
        "republished moved unit must pin the new administrative chain only"
    );
    assert_eq!(
        current_dependency_pins(&pool, DEP_MV_MOVED).await,
        vec![
            (
                DEP_MV_ROOT_TENANT,
                root_head.generation,
                root_head.revoke_fence,
                root_head.relationship_revision
            ),
            (
                DEP_MV_PARENT_NEW,
                new_parent_after_move.generation,
                new_parent_after_move.revoke_fence,
                new_parent_after_move.relationship_revision
            ),
        ],
        "moved unit's current publication must carry a new-parent pin"
    );
    // M 无后代：MOVE 派生的 SUBTREE intent 在此无扇出对象，终态化让位
    // （子树排空合同由专门测试覆盖）。
    let subtree_lease = claim_lease_of_kind(
        &repo,
        DEP_MV_MOVED,
        OrgOutboxEventKind::SubtreePropagate,
        &op_mv,
    )
    .await;
    repo.fail_outbox_event(&OrgOutboxFailCommand {
        org_event_id: subtree_lease.org_event_id,
        worker_owner: OWNER.into(),
        worker_token_hex: TOKEN_HEX.into(),
        error: "e2e fixture: moved unit has no descendants".into(),
        retryable: false,
        backoff_seconds: 0,
        max_attempts: CLAIM_MAX_ATTEMPTS,
    })
    .await
    .expect("fail leaf subtree intent");

    // ── 新父的后续 source 变更（attach K2 → P2 head +1）：M 的新父钉（旧头）
    //    与 K 的钉一同失配 → 有界批推进；完成门前先被排空门拒绝 ─────────────
    let attach_k2 = submit_and_approve(
        &repo,
        OrgRequestPayload::Attach {
            child_tenant_id: DEP_MV_LATE_CHILD,
            parent_tenant_id: DEP_MV_PARENT_NEW,
        },
        DEP_MV_LATE_CHILD,
        Some(DEP_MV_PARENT_NEW),
        "dep-mv-attach-k2",
        None,
    )
    .await;
    claim_and_publish_unit(&repo, DEP_MV_PARENT_NEW).await;
    let new_parent_final = node_head_of(&pool, DEP_MV_PARENT_NEW).await;
    assert_eq!(
        new_parent_final.generation,
        new_parent_after_move.generation + 1
    );
    let lease_a2 = claim_lease_of_kind(
        &repo,
        DEP_MV_PARENT_NEW,
        OrgOutboxEventKind::DependencyPropagate,
        &attach_k2.operation_id,
    )
    .await;
    // 完成门：存在钉失配且未以本操作 id 标记的直接子节点 → 拒绝并保持 LEASED。
    let error = repo
        .complete_outbox_event(&complete_command(
            lease_a2.org_event_id,
            OrgOutboxEventKind::DependencyPropagate,
        ))
        .await
        .expect_err("completion before drain must be refused");
    assert!(error
        .to_string()
        .contains("org_scope.dependency_propagate_incomplete"));
    assert_eq!(
        outbox_state_of(&pool, lease_a2.org_event_id).await.status,
        "LEASED"
    );

    // 有界批：M(624) < K(626) 升序 → 首批恰一个、done=false；重入排空其余。
    let batch1 = repo
        .propagate_dependency_change(&dependency_propagate_command(&lease_a2, 1))
        .await
        .expect("bounded reparent wave batch");
    assert_eq!(batch1.updated_tenant_ids, vec![DEP_MV_MOVED]);
    assert!(!batch1.done);
    let moved_after_wave = node_head_of(&pool, DEP_MV_MOVED).await;
    assert_eq!(moved_after_wave.generation, moved_after_move.generation + 1);
    assert_eq!(moved_after_wave.revoke_fence, moved_after_move.revoke_fence);
    assert_eq!(
        moved_after_wave.relationship_revision,
        moved_after_move.relationship_revision
    );
    assert_eq!(moved_after_wave.last_operation_id, lease_a2.operation_id);
    let batch2 = repo
        .propagate_dependency_change(&dependency_propagate_command(
            &lease_a2,
            ORG_MAX_PROPAGATE_BATCH,
        ))
        .await
        .expect("reparent wave re-entry");
    assert_eq!(batch2.updated_tenant_ids, vec![DEP_MV_NEW_CHILD]);
    assert!(batch2.done);
    let new_child_final = node_head_of(&pool, DEP_MV_NEW_CHILD).await;
    assert_eq!(new_child_final.generation, new_child_after.generation + 1);
    assert_eq!(new_child_final.revoke_fence, new_child_after.revoke_fence);
    assert_eq!(
        new_child_final.relationship_revision,
        new_child_after.relationship_revision
    );
    // K2 无 publication（未发布单元不在依赖钉 join 内）→ 永不被选中。
    assert!(!batch1.updated_tenant_ids.contains(&DEP_MV_LATE_CHILD));
    assert!(!batch2.updated_tenant_ids.contains(&DEP_MV_LATE_CHILD));
    repo.complete_outbox_event(&complete_command(
        lease_a2.org_event_id,
        OrgOutboxEventKind::DependencyPropagate,
    ))
    .await
    .expect("completion after reparent wave drain");

    cleanup_tenant_set(&pool, &DEP_MV_TENANTS).await;
}

// ═════════════════════════ ORG_SCOPE outbox lease/fence ═════════════════════

#[tokio::test]
#[ignore]
async fn org_scope_outbox_renew_reclaim_and_stale_worker_fencing() {
    let Some(pool) = connect().await else {
        return;
    };
    require_org_scope_schema(&pool).await;
    let (repo, lease) = seed_root_event(&pool, OUTBOX_LEASE_TENANT, "outbox-lease").await;
    let initial = outbox_state_of(&pool, lease.org_event_id).await;
    assert_eq!(initial.status, "LEASED");
    assert_eq!(initial.attempts, 1);
    assert_eq!(initial.cas_version, lease.cas_version);

    let renewed = repo
        .renew_outbox_lease(&OrgOutboxRenewCommand {
            org_event_id: lease.org_event_id,
            worker_owner: OWNER.into(),
            worker_token_hex: TOKEN_HEX.into(),
            lease_seconds: 300,
        })
        .await
        .expect("renew active lease");
    assert!(renewed);
    let after_renew = outbox_state_of(&pool, lease.org_event_id).await;
    assert_eq!(after_renew.cas_version, initial.cas_version + 1);
    assert!(after_renew.lease_expires_at_unix.unwrap() >= lease.lease_expires_at_unix);

    // A different owner/token cannot renew the live lease.
    assert!(!repo
        .renew_outbox_lease(&OrgOutboxRenewCommand {
            org_event_id: lease.org_event_id,
            worker_owner: SECOND_OWNER.into(),
            worker_token_hex: SECOND_TOKEN_HEX.into(),
            lease_seconds: 300,
        })
        .await
        .expect("wrong owner renew is a fence miss"));
    assert!(!repo
        .renew_outbox_lease(&OrgOutboxRenewCommand {
            org_event_id: lease.org_event_id,
            worker_owner: OWNER.into(),
            worker_token_hex: SECOND_TOKEN_HEX.into(),
            lease_seconds: 300,
        })
        .await
        .expect("wrong token renew is a fence miss"));
    let after_wrong_identity = outbox_state_of(&pool, lease.org_event_id).await;
    assert_eq!(after_wrong_identity.cas_version, after_renew.cas_version);

    // Expiry is changed only on this test-owned outbox row; all state transitions
    // under test still go through the repository's SQL lease predicates.
    sqlx::query(
        "UPDATE org_scope_outbox SET lease_expires_at = TIMESTAMPADD(SECOND, -1, UTC_TIMESTAMP(6)) \
         WHERE org_event_id = ?",
    )
    .bind(lease.org_event_id)
    .execute(&pool)
    .await
    .expect("expire fixture lease");
    assert!(!repo
        .renew_outbox_lease(&OrgOutboxRenewCommand {
            org_event_id: lease.org_event_id,
            worker_owner: OWNER.into(),
            worker_token_hex: TOKEN_HEX.into(),
            lease_seconds: 300,
        })
        .await
        .expect("expired lease renew is a fence miss"));

    let successor = repo
        .claim_outbox_event(&OrgOutboxClaimCommand {
            tenant_id: OUTBOX_LEASE_TENANT,
            worker_owner: SECOND_OWNER.into(),
            worker_token_hex: SECOND_TOKEN_HEX.into(),
            lease_seconds: 300,
            max_attempts: CLAIM_MAX_ATTEMPTS,
        })
        .await
        .expect("successor claim")
        .expect("expired lease is reclaimable");
    assert_eq!(successor.org_event_id, lease.org_event_id);
    assert_eq!(successor.attempts, lease.attempts + 1);
    assert!(successor.cas_version > after_renew.cas_version);
    let takeover = outbox_state_of(&pool, lease.org_event_id).await;
    assert_eq!(takeover.lease_owner.as_deref(), Some(SECOND_OWNER));

    assert!(!repo
        .renew_outbox_lease(&OrgOutboxRenewCommand {
            org_event_id: lease.org_event_id,
            worker_owner: OWNER.into(),
            worker_token_hex: TOKEN_HEX.into(),
            lease_seconds: 300,
        })
        .await
        .expect("stale owner renew is a fence miss"));
    let stale_fail = repo
        .fail_outbox_event(&OrgOutboxFailCommand {
            org_event_id: lease.org_event_id,
            worker_owner: OWNER.into(),
            worker_token_hex: TOKEN_HEX.into(),
            error: "stale owner must not mutate the successor lease".into(),
            retryable: false,
            backoff_seconds: 0,
            max_attempts: CLAIM_MAX_ATTEMPTS,
        })
        .await
        .expect_err("stale owner fail must be rejected");
    assert!(stale_fail
        .to_string()
        .contains("org_scope.outbox_lease_lost"));
    let stale_publication =
        empty_root_publication(&repo, &successor, SECOND_OWNER, SECOND_TOKEN_HEX).await;
    let stale_publish = repo
        .complete_publish(&OrgPublishCommand {
            org_event_id: lease.org_event_id,
            worker_owner: OWNER.into(),
            worker_token_hex: TOKEN_HEX.into(),
            publication: stale_publication,
        })
        .await
        .expect_err("stale owner publish must be rejected");
    assert!(stale_publish
        .to_string()
        .contains("org_scope.outbox_lease_lost"));
    let still_owned = outbox_state_of(&pool, lease.org_event_id).await;
    assert_eq!(still_owned.status, "LEASED");
    assert_eq!(still_owned.lease_owner.as_deref(), Some(SECOND_OWNER));
    assert_eq!(still_owned.cas_version, successor.cas_version);

    let publication =
        empty_root_publication(&repo, &successor, SECOND_OWNER, SECOND_TOKEN_HEX).await;
    repo.complete_publish(&OrgPublishCommand {
        org_event_id: successor.org_event_id,
        worker_owner: SECOND_OWNER.into(),
        worker_token_hex: SECOND_TOKEN_HEX.into(),
        publication,
    })
    .await
    .expect("successor publishes under the current lease");
    let done = outbox_state_of(&pool, lease.org_event_id).await;
    assert_eq!(done.status, "DONE");
    assert!(done.lease_owner.is_none());
    assert!(done.cas_version > successor.cas_version);
    cleanup_tenant_set(&pool, &OUTBOX_LEASE_TENANTS).await;
}

#[tokio::test]
#[ignore]
async fn org_scope_outbox_retry_backoff_and_claim_budget_are_durable() {
    let Some(pool) = connect().await else {
        return;
    };
    require_org_scope_schema(&pool).await;
    let (repo, lease) = seed_root_event(&pool, OUTBOX_RETRY_TENANT, "outbox-retry").await;

    let negative_backoff = repo
        .fail_outbox_event(&OrgOutboxFailCommand {
            org_event_id: lease.org_event_id,
            worker_owner: OWNER.into(),
            worker_token_hex: TOKEN_HEX.into(),
            error: "negative backoff must not persist".into(),
            retryable: true,
            backoff_seconds: -1,
            max_attempts: CLAIM_MAX_ATTEMPTS,
        })
        .await
        .expect_err("negative backoff must fail closed");
    assert!(negative_backoff
        .to_string()
        .contains("org_scope.invalid_backoff_seconds"));
    let unchanged = outbox_state_of(&pool, lease.org_event_id).await;
    assert_eq!(unchanged.status, "LEASED");
    assert_eq!(unchanged.cas_version, lease.cas_version);

    let retry = repo
        .fail_outbox_event(&OrgOutboxFailCommand {
            org_event_id: lease.org_event_id,
            worker_owner: OWNER.into(),
            worker_token_hex: TOKEN_HEX.into(),
            error: "transient test failure".into(),
            retryable: true,
            backoff_seconds: 60,
            max_attempts: 3,
        })
        .await
        .expect("record retryable failure");
    assert_eq!(retry.status, "PENDING");
    assert_eq!(retry.attempts, 1);
    let parked = outbox_state_of(&pool, lease.org_event_id).await;
    assert_eq!(parked.status, "PENDING");
    assert_eq!(parked.attempts, 1);
    let now_unix: i64 =
        sqlx::query_scalar("SELECT CAST(UNIX_TIMESTAMP(UTC_TIMESTAMP(6)) AS SIGNED)")
            .fetch_one(&pool)
            .await
            .expect("current UTC timestamp");
    assert!(parked.next_attempt_at_unix.unwrap() > now_unix);
    assert!(parked.lease_owner.is_none());
    assert_eq!(parked.last_error.as_deref(), Some("transient test failure"));
    let not_due = repo
        .claim_outbox_event(&OrgOutboxClaimCommand {
            tenant_id: OUTBOX_RETRY_TENANT,
            worker_owner: OWNER.into(),
            worker_token_hex: TOKEN_HEX.into(),
            lease_seconds: 300,
            max_attempts: 3,
        })
        .await
        .expect("backoff window claim probe");
    assert!(not_due.is_none(), "future retry must remain parked");

    // Make the retry due, reclaim it, then consume the final permitted attempt.
    sqlx::query(
        "UPDATE org_scope_outbox SET next_attempt_at = TIMESTAMPADD(SECOND, -1, UTC_TIMESTAMP(6)) \
         WHERE org_event_id = ?",
    )
    .bind(lease.org_event_id)
    .execute(&pool)
    .await
    .expect("make retry due");
    let second = repo
        .claim_outbox_event(&OrgOutboxClaimCommand {
            tenant_id: OUTBOX_RETRY_TENANT,
            worker_owner: OWNER.into(),
            worker_token_hex: TOKEN_HEX.into(),
            lease_seconds: 300,
            max_attempts: 2,
        })
        .await
        .expect("second attempt claim")
        .expect("retry is due");
    assert_eq!(second.attempts, 2);
    let terminal = repo
        .fail_outbox_event(&OrgOutboxFailCommand {
            org_event_id: second.org_event_id,
            worker_owner: OWNER.into(),
            worker_token_hex: TOKEN_HEX.into(),
            error: "attempt budget reached".into(),
            retryable: true,
            backoff_seconds: 60,
            max_attempts: 2,
        })
        .await
        .expect("retryable error at max attempts is terminal");
    assert_eq!(terminal.status, "FAILED");
    let failed = outbox_state_of(&pool, lease.org_event_id).await;
    assert_eq!(failed.status, "FAILED");
    assert_eq!(failed.attempts, 2);
    assert!(failed.next_attempt_at_unix.is_none());
    assert!(failed.lease_owner.is_none());

    // A new source event exercises claim-side budget exhaustion after a worker
    // repeatedly crashed with an expired lease before failure could be recorded.
    let (_, claim_budget_lease) =
        seed_root_event(&pool, OUTBOX_RETRY_TENANT, "outbox-claim-budget").await;
    sqlx::query(
        "UPDATE org_scope_outbox SET attempts = 2, \
         lease_expires_at = TIMESTAMPADD(SECOND, -1, UTC_TIMESTAMP(6)) \
         WHERE org_event_id = ?",
    )
    .bind(claim_budget_lease.org_event_id)
    .execute(&pool)
    .await
    .expect("simulate expired final claim on test-owned event");
    let exhausted = repo
        .claim_outbox_event(&OrgOutboxClaimCommand {
            tenant_id: OUTBOX_RETRY_TENANT,
            worker_owner: SECOND_OWNER.into(),
            worker_token_hex: SECOND_TOKEN_HEX.into(),
            lease_seconds: 300,
            max_attempts: 2,
        })
        .await
        .expect("claim-side budget exhaustion is a durable terminal result");
    assert!(exhausted.is_none());
    let exhausted_state = outbox_state_of(&pool, claim_budget_lease.org_event_id).await;
    assert_eq!(exhausted_state.status, "FAILED");
    assert_eq!(exhausted_state.attempts, 2);
    assert!(exhausted_state.lease_owner.is_none());
    assert!(outbox_last_error(&pool, claim_budget_lease.org_event_id)
        .await
        .as_deref()
        .is_some_and(|error| error.contains("org_scope.outbox_claim_budget_exhausted")));
    cleanup_tenant_set(&pool, &OUTBOX_RETRY_TENANTS).await;
}

#[tokio::test]
#[ignore]
async fn org_scope_outbox_concurrent_claim_has_one_winner() {
    let Some(pool) = connect().await else {
        return;
    };
    require_org_scope_schema(&pool).await;
    let (repo, operation_id) = create_root_event(&pool, OUTBOX_RACE_TENANT, "outbox-race").await;
    let barrier = Arc::new(Barrier::new(3));
    let first_pool = pool.clone();
    let first_barrier = barrier.clone();
    let first = tokio::spawn(async move {
        let repo = SqlxOrgScopeRepository::new(first_pool);
        first_barrier.wait().await;
        claim_outbox_retrying_deadlock(
            &repo,
            &OrgOutboxClaimCommand {
                tenant_id: OUTBOX_RACE_TENANT,
                worker_owner: OWNER.into(),
                worker_token_hex: TOKEN_HEX.into(),
                lease_seconds: 300,
                max_attempts: CLAIM_MAX_ATTEMPTS,
            },
        )
        .await
    });
    let second_pool = pool.clone();
    let second_barrier = barrier.clone();
    let second = tokio::spawn(async move {
        let repo = SqlxOrgScopeRepository::new(second_pool);
        second_barrier.wait().await;
        claim_outbox_retrying_deadlock(
            &repo,
            &OrgOutboxClaimCommand {
                tenant_id: OUTBOX_RACE_TENANT,
                worker_owner: SECOND_OWNER.into(),
                worker_token_hex: SECOND_TOKEN_HEX.into(),
                lease_seconds: 300,
                max_attempts: CLAIM_MAX_ATTEMPTS,
            },
        )
        .await
    });
    barrier.wait().await;
    let first = first
        .await
        .expect("first claimant task")
        .expect("first claim result");
    let second = second
        .await
        .expect("second claimant task")
        .expect("second claim result");
    let winner = match (first, second) {
        (Some(winner), None) | (None, Some(winner)) => winner,
        other => panic!("one outbox event has exactly one claim winner: {other:?}"),
    };
    assert_eq!(winner.operation_id, operation_id);
    let state = outbox_state_of(&pool, winner.org_event_id).await;
    assert_eq!(state.status, "LEASED");
    assert_eq!(state.attempts, 1);
    let winner_owner = state
        .lease_owner
        .clone()
        .expect("claim winner owns the leased row");
    assert!(winner_owner == OWNER || winner_owner == SECOND_OWNER);
    let winner_token = if winner_owner == OWNER {
        TOKEN_HEX
    } else {
        SECOND_TOKEN_HEX
    };
    repo.fail_outbox_event(&OrgOutboxFailCommand {
        org_event_id: winner.org_event_id,
        worker_owner: winner_owner,
        worker_token_hex: winner_token.into(),
        error: "concurrent claim test cleanup".into(),
        retryable: false,
        backoff_seconds: 0,
        max_attempts: CLAIM_MAX_ATTEMPTS,
    })
    .await
    .expect("terminally release winning lease");
    cleanup_tenant_set(&pool, &OUTBOX_RACE_TENANTS).await;
}

// ═══════════════════════ read-gate / governance boundaries ═══════════════════

#[tokio::test]
#[ignore]
async fn org_scope_managed_tenant_flag_off_never_falls_back_to_legacy() {
    let Some(pool) = connect().await else {
        return;
    };
    require_org_scope_schema(&pool).await;
    let (repo, _) = create_root_event(&pool, GATE_FLAG_OFF_TENANT, "managed-flag-off").await;
    assert!(matches!(
        probe_org_scope_gate(&pool, GATE_FLAG_OFF_TENANT).await,
        OrgScopeGateState::TenantManaged { .. }
    ));

    let ctx = astral_types::PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .identity_card_id(Some(1))
        .tenant_id(Some(GATE_FLAG_OFF_TENANT))
        .action("read".into())
        .build();
    let disabled = policy_engine::RuleRepository::load_org_authorization(
        &astral_db::SqlxRuleRepository::new(pool.clone()),
        &ctx,
    )
    .await
    .expect("flag-off gate read");
    assert!(matches!(
        disabled,
        policy_engine::OrgAuthorityRead::Disabled
    ));

    let enabled = policy_engine::RuleRepository::load_org_authorization(
        &astral_db::SqlxRuleRepository::new(pool.clone()).with_org_scope_enabled(true),
        &ctx,
    )
    .await
    .expect("flag-on gate read");
    assert!(matches!(
        enabled,
        policy_engine::OrgAuthorityRead::Pending { .. }
    ));
    cleanup_tenant_set(&pool, &[GATE_FLAG_OFF_TENANT]).await;
    drop(repo);
}

#[tokio::test]
#[ignore]
async fn org_scope_attach_approval_rejects_non_parent_counterparty() {
    let Some(pool) = connect().await else {
        return;
    };
    require_org_scope_schema(&pool).await;
    cleanup_tenant_set(&pool, &GATE_ATTACH_TEST_TENANTS).await;
    let repo = SqlxOrgScopeRepository::new(pool.clone());
    submit_and_approve(
        &repo,
        OrgRequestPayload::RootInit {
            root_tenant_id: GATE_ATTACH_PARENT_TENANT,
            initial_grants: Vec::new(),
        },
        GATE_ATTACH_PARENT_TENANT,
        None,
        "boundary-root-init",
        Some(root_governance_proof(
            GATE_ATTACH_PARENT_TENANT,
            "boundary-root",
        )),
    )
    .await;
    let request = repo
        .create_request(&OrgCreateRequestCommand {
            operation_id: unique_operation("boundary-attach"),
            actor_user_id: 1,
            actor_tenant_id: Some(GATE_CHILD_TENANT),
            payload: OrgRequestPayload::Attach {
                child_tenant_id: GATE_CHILD_TENANT,
                parent_tenant_id: GATE_ATTACH_PARENT_TENANT,
            },
        })
        .await
        .expect("boundary attach request");
    let error = repo
        .approve_request(&OrgApproveCommand {
            request_id: request.request_id,
            expected_revision: FRESH_REQUEST_REVISION,
            approver_user_id: 1,
            approver_tenant_id: Some(GATE_UNAUTHORIZED_ROOT),
            operation_id: unique_operation("boundary-attach-unauthorized"),
            note: None,
            governance_proof: None,
        })
        .await
        .expect_err("non-parent counterparty must not approve attach");
    assert!(error
        .to_string()
        .contains("org_scope.decide_not_counterparty_parent"));
    let view = repo
        .get_request(request.request_id)
        .await
        .expect("request remains queryable")
        .expect("request row exists");
    assert_eq!(view.status, "PENDING");
    assert!(sqlx::query_scalar::<_, Option<i64>>(
        "SELECT tenant_id FROM org_scope_node WHERE tenant_id = ?",
    )
    .bind(GATE_CHILD_TENANT)
    .fetch_optional(&pool)
    .await
    .expect("child node probe")
    .is_none());
    cleanup_tenant_set(&pool, &GATE_ATTACH_TEST_TENANTS).await;
}
