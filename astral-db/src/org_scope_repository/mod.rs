//! ORG_SCOPE 行政授权链 Sqlx 仓储（多租户改造 Phase 2，DB owner 切片）。
//!
//! 设计依据：`Docs/架构/Rust架构设计/Rust多租户聚合分区与组织层级设计_V0.1.md` §4/§7、
//! MT 运行共享实施合同与 `astral-types/src/org_scope.rs` 冻结类型（以实际文件为准）。
//!
//! # 职责边界
//!
//! - 本模块只负责 ORG_SCOPE **独立** durable 面：行政树 node、审批 request、
//!   grant/mask/membership、通用 revision 账、org 专属 outbox、不可变 sealed
//!   publication/segment/current、依赖 pin、操作幂等账与 org 审计。
//! - **绝不写旧 `authorization_delta_event` / `authorization_grant_revision`**：
//!   旧 worker 认领并用 `CanonicalGrant`（user_id 绑定）解码，org 载荷混入会被
//!   旧链误读。org 事件走 `org_scope_outbox`，新 worker 由 main owner 接线。
//! - 编译（HAMT/OrgCompiledState）外置给 policy-engine org compiler；本模块提供
//!   `load_compile_input`（租约校验 + 已批准事实快照，含 flatten 祖先依赖）与
//!   `complete_publish`（sealed publication + segment + dependency + current
//!   generation CAS + outbox 终态，单事务原子）。
//! - actor 的治理权限（meta-permission、上级审批人身份）由 API/PolicyEngine 验证；
//!   本仓储在事务内复验**结构性**资格（边激活、parent grant active/delegable/
//!   精确 revision/同 root/作用域包含、环检查、CAS 代次、治理证明存在性与
//!   能力范围绑定）。
//! - worker 派发合同（[`OrgOutboxEventKind`]）：10 个 event_kind 字面量在
//!   DB 内封闭成分类（仅精确大写解析），公开常量由分类 const 派生防漂移。
//!   `MEMBERSHIP_CHANGED` / `SUBTREE_PROPAGATE` / `DEPENDENCY_PROPAGATE` 允许租约内
//!   **无发布完成**（`complete_outbox_event`：清租约 + CAS 单调 + DONE，绝不产生
//!   publication/source mutation/新审计写）；category-1 其余 7 类只能经
//!   `complete_publish` 消费。`SUBTREE_PROPAGATE` 为**扇出**语义：每批只推进
//!   锚点（载荷 child）的直接 active 子节点中尚未以本操作 id 落过 NODE
//!   revision 账的（durable 幂等标记；同 root 后代同样选中失效），并为每个被
//!   推进子节点原子派生新的
//!   typed child intent——宽兄弟分支与任意深度后代不可能因批间状态丢失；
//!   租约 + 意图绑定（tenant/operation/root/frontier/revision 栅栏）先于任何
//!   节点写入。
//!
//! # default-off 语义
//!
//! - 部署旗标 `ASTRAL_ORG_SCOPE_ENABLED`（严格 bool，默认 false）由 main 配置层
//!   解析；[`probe_org_scope_gate`] 供其组合：
//!   - `SchemaUnmanaged`：确知 `org_scope_node` 表不存在 → 特性从未激活，legacy；
//!   - `Pending`：任何其他 DB 失败（fail-closed，不得当 Unmanaged）；
//!   - `TenantUnmanaged`：表存在但该租户无 node 行 → legacy；
//!   - `TenantManaged`：存在 node 行 → 受 org 治理；**旗标关闭时 main 必须 deny
//!     受治理分支（Disabled），不得回退 legacy**。
//! - main 的 RuleRepository hook `load_org_authorization(ctx)` 组合 gate 与
//!   [`OrgScopeRepository::load_admission_evidence`]：gate/evidence reader 的基础设施
//!   不可用映射为 `Unavailable`，已确认的业务证据不完整映射为 `Pending`；两者都
//!   fail-closed，且绝不当作 Unmanaged。
//! - 迁移文件只入库不自动应用；应用与否属 Exec-L3 运维动作。
//!
//! # 幂等与 CAS
//!
//! 每个 authority mutation 携带稳定 `operation_id`（**≤64 字节**，与类型合同
//! `MAX_ORG_ID_TEXT_LEN` 对齐）；`org_scope_operation` 以 operation_id 为主键、
//! `input_digest` 绑定规范输入字节：同 id 同 digest 重放返回已记录 outcome
//! （`replayed=true`），同 id 异 digest 一律 Validation 冲突。关系变更在锁定读下
//! 按 `relationship_revision` CAS 推进；发布按 generation 单调 CAS 推进 current。
//!
//! # flatten 依赖合同（协调结论）
//!
//! 祖先撤销必须对本单元**立即可见**：compile input 的 `dependencies` 按**全部
//! 行政祖先 source head** flatten（每祖先一项），reader 对每一项校验
//! active + root + generation + revoke_fence + relationship_revision。冻结的
//! `OrgCompileInput::validate` 要求根节点携带零项依赖、子节点携带"直接父 +
//! 父 publication 的全部传递祖先"这一完整向量；任何缺失、重复、排序或栅栏
//! 漂移都 fail-closed。

use astral_types::org_scope::{
    OrgAdmissionResult, OrgError, OrgGrantRef, OrgNode, OrgPendingCode, OrgRootActivation,
    OrgScope, OrgSubject, MAX_ORG_ID_TEXT_LEN,
};
use astral_types::AstralError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{MySql, MySqlPool, Row, Transaction};
use uuid::Uuid;

pub use astral_types::org_scope::{
    MAX_ORG_ACTIVE_MEMBERSHIPS_PER_USER as ORG_MAX_ACTIVE_MEMBERSHIPS_PER_USER,
    MAX_ORG_ROOT_INIT_GRANTS as ORG_MAX_ROOT_INIT_GRANTS, ORG_SCOPE_AGGREGATE_TYPE,
};

use astral_types::ValidityWindow;

mod mutations;
mod reader;
mod requests;
mod worker;

pub use mutations::{
    OrgGrantRevokeCommand, OrgMaskApplyCommand, OrgMaskRemoveCommand, OrgMembershipCreateCommand,
    OrgMembershipRevokeCommand,
};
pub use requests::{
    OrgApproveCommand, OrgCancelCommand, OrgCreateRequestCommand, OrgGovernanceProof,
    OrgRejectCommand, OrgRequestOutcome, OrgRequestView,
};
pub use worker::{
    OrgCompileInputCommand, OrgDependencyPropagateCommand, OrgDependencyPropagateOutcome,
    OrgOutboxClaimCommand, OrgOutboxCompleteCommand, OrgOutboxCompleteOutcome,
    OrgOutboxFailCommand, OrgOutboxFailOutcome, OrgOutboxLease, OrgOutboxRenewCommand,
    OrgPublishCommand, OrgPublishOutcome, OrgSubtreePropagateCommand, OrgSubtreePropagateOutcome,
};

/// org outbox `event_kind` 的 DB 内封闭分类（10 个一等事件字面量，逐一冻结）。
///
/// - 仅接受**精确大写**取值：`FromStr` 不做大小写折叠、不容忍首尾空白；
///   小写/混合/未知/空输入一律解析失败（[`OrgOutboxEventKindParseError`]）。
/// - 公开常量 `ORG_EVENT_*` 由 [`OrgOutboxEventKind::as_str`]（const fn）派生，
///   常量与分类不可能漂移；[`OrgOutboxEventKind::ALL`] 与单测再冻结全部 10 个
///   字符串作第二道防线。
/// - DB-internal 派发合同：category-1 的 7 类（publication 驱动）只能经
///   `complete_publish` 消费；[`OrgOutboxEventKind::MembershipChanged`]、
///   [`OrgOutboxEventKind::SubtreePropagate`] 与
///   [`OrgOutboxEventKind::DependencyPropagate`] 允许租约内无发布完成。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OrgOutboxEventKind {
    NodeCreated,
    NodeTopologyChanged,
    NodeMutated,
    GrantIssued,
    GrantRevoked,
    MaskApplied,
    MaskRemoved,
    MembershipChanged,
    SubtreePropagate,
    DependencyPropagate,
}

/// [`OrgOutboxEventKind`] 解析失败（精确大写匹配之外的一切输入）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrgOutboxEventKindParseError;

impl OrgOutboxEventKind {
    /// 全部 10 个一等事件种类（顺序即声明顺序）。
    pub const ALL: [OrgOutboxEventKind; 10] = [
        OrgOutboxEventKind::NodeCreated,
        OrgOutboxEventKind::NodeTopologyChanged,
        OrgOutboxEventKind::NodeMutated,
        OrgOutboxEventKind::GrantIssued,
        OrgOutboxEventKind::GrantRevoked,
        OrgOutboxEventKind::MaskApplied,
        OrgOutboxEventKind::MaskRemoved,
        OrgOutboxEventKind::MembershipChanged,
        OrgOutboxEventKind::SubtreePropagate,
        OrgOutboxEventKind::DependencyPropagate,
    ];

    /// 稳定 wire 字面量（`org_scope_outbox.event_kind` 列；const 供公开常量派生）。
    pub const fn as_str(self) -> &'static str {
        match self {
            OrgOutboxEventKind::NodeCreated => "NODE_CREATED",
            OrgOutboxEventKind::NodeTopologyChanged => "NODE_TOPOLOGY_CHANGED",
            OrgOutboxEventKind::NodeMutated => "NODE_MUTATED",
            OrgOutboxEventKind::GrantIssued => "GRANT_ISSUED",
            OrgOutboxEventKind::GrantRevoked => "GRANT_REVOKED",
            OrgOutboxEventKind::MaskApplied => "MASK_APPLIED",
            OrgOutboxEventKind::MaskRemoved => "MASK_REMOVED",
            OrgOutboxEventKind::MembershipChanged => "MEMBERSHIP_CHANGED",
            OrgOutboxEventKind::SubtreePropagate => "SUBTREE_PROPAGATE",
            OrgOutboxEventKind::DependencyPropagate => "DEPENDENCY_PROPAGATE",
        }
    }

    /// "无发布完成"白名单：MEMBERSHIP_CHANGED 与两类有界传播 intent。
    /// category-1 其余 7 类必须经 publication 驱动的 `complete_publish`，绝不
    /// 由此路径消费。
    pub const fn allows_publication_free_completion(self) -> bool {
        matches!(
            self,
            OrgOutboxEventKind::MembershipChanged
                | OrgOutboxEventKind::SubtreePropagate
                | OrgOutboxEventKind::DependencyPropagate
        )
    }
}

impl core::str::FromStr for OrgOutboxEventKind {
    type Err = OrgOutboxEventKindParseError;

    /// 仅精确大写匹配（无大小写折叠、无 trim）；其余输入一律解析失败。
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .iter()
            .copied()
            .find(|kind| kind.as_str() == value)
            .ok_or(OrgOutboxEventKindParseError)
    }
}

/// 事件类型常量（org outbox `event_kind`）——由 [`OrgOutboxEventKind`] 派生，
/// 与分类同源，不可能漂移。
pub const ORG_EVENT_NODE_CREATED: &str = OrgOutboxEventKind::NodeCreated.as_str();
pub const ORG_EVENT_NODE_TOPOLOGY_CHANGED: &str = OrgOutboxEventKind::NodeTopologyChanged.as_str();
pub const ORG_EVENT_NODE_MUTATED: &str = OrgOutboxEventKind::NodeMutated.as_str();
pub const ORG_EVENT_GRANT_ISSUED: &str = OrgOutboxEventKind::GrantIssued.as_str();
pub const ORG_EVENT_GRANT_REVOKED: &str = OrgOutboxEventKind::GrantRevoked.as_str();
pub const ORG_EVENT_MASK_APPLIED: &str = OrgOutboxEventKind::MaskApplied.as_str();
pub const ORG_EVENT_MASK_REMOVED: &str = OrgOutboxEventKind::MaskRemoved.as_str();
pub const ORG_EVENT_MEMBERSHIP_CHANGED: &str = OrgOutboxEventKind::MembershipChanged.as_str();
pub const ORG_EVENT_SUBTREE_PROPAGATE: &str = OrgOutboxEventKind::SubtreePropagate.as_str();
pub const ORG_EVENT_DEPENDENCY_PROPAGATE: &str = OrgOutboxEventKind::DependencyPropagate.as_str();

/// 行政树深度上限（治理写路径环检查；决策读路径绝不遍历）。
pub const ORG_MAX_TREE_DEPTH: usize = 64;
/// MOVE/DETACH 事务内一次性撤销旧链 received grant 上限；超出保守失败。
pub const ORG_MAX_GRANTS_REVOKE_PER_TX: usize = 1000;
/// 子树传播单批上限。
pub const ORG_MAX_PROPAGATE_BATCH: i64 = 1000;
/// 传播前沿集合宽度上限（历史 API 兼容保留：仓库侧 frontier 现在必须**恰为**
/// `[载荷锚点]`（宽度 1）；service 侧批大小推导仍引用本常量，值不变）。
pub const ORG_MAX_PROPAGATE_FRONTIER: usize = 256;
/// compile input 载入时单单元 grant 上限（对齐类型合同）。
pub const ORG_MAX_COMPILE_GRANTS: usize = astral_types::org_scope::MAX_ORG_GRANTS_PER_INPUT;
/// compile input 载入时单单元 mask 上限。
pub const ORG_MAX_COMPILE_MASKS: usize = astral_types::org_scope::MAX_ORG_MASKS_PER_INPUT;

// ─────────────────────────────────────────────────────────────────────────────
// Gate（schema presence / tenant management 探测）
// ─────────────────────────────────────────────────────────────────────────────

/// org-scope 治理门状态（main 与旗标组合成最终 admit/deny/legacy 决策）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrgScopeGateState {
    /// 确知 `org_scope_node` 表不存在：特性从未激活，全部租户走 legacy。
    SchemaUnmanaged,
    /// 任何除"确知表不存在"以外的 DB 失败：fail-closed，PENDING。
    Pending,
    /// 表存在但该租户没有 node 行：该租户未被纳入行政治理，走 legacy。
    TenantUnmanaged,
    /// 该租户存在 node 行：受 org 治理。旗标 off 时 main 必须 deny（Disabled）。
    TenantManaged { node: OrgNode },
}

const GATE_TABLE_PROBE_SQL: &str = "SELECT COUNT(*) FROM information_schema.TABLES \
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'org_scope_node'";

/// 13 张 ORG_SCOPE source/projection 表；仅在显式启用 ORG_SCOPE 的启动门内校验，
/// 不把 default-off 的可选 schema 误提升为全局数据库启动前置。
const ORG_SCOPE_REQUIRED_TABLES: [&str; 13] = [
    "org_scope_node",
    "org_scope_request",
    "org_scope_grant",
    "org_scope_revision",
    "org_scope_mask",
    "org_scope_membership",
    "org_scope_publication",
    "org_scope_segment",
    "org_scope_current",
    "org_scope_outbox",
    "org_scope_dependency",
    "org_scope_operation",
    "org_scope_audit",
];

const ORG_SCOPE_SCHEMA_TABLES_SQL: &str = "SELECT CAST(TABLE_NAME AS CHAR) AS table_name \
     FROM information_schema.TABLES \
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME IN (?,?,?,?,?,?,?,?,?,?,?,?,?)";
const ORG_SCOPE_SCHEMA_INDEX_SQL: &str = "SELECT CAST(COLUMN_NAME AS CHAR) AS column_name, \
     CAST(NON_UNIQUE AS SIGNED) AS non_unique \
     FROM information_schema.STATISTICS \
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND INDEX_NAME = ? \
     ORDER BY SEQ_IN_INDEX";
const ORG_SCOPE_REQUIRED_INDEXES: &[(&str, &str, &[&str], bool)] = &[
    (
        "org_scope_membership",
        "idx_osmem_user_active",
        &["user_id", "active"],
        false,
    ),
    (
        "org_scope_membership",
        "idx_osmem_card",
        &["card_id", "active"],
        false,
    ),
    ("identity_card", "uk_ic_user", &["user_id"], true),
];

/// Enabled-only startup prerequisite for the ORG_SCOPE source and membership-cap
/// contracts. This is read-only and intentionally separate from the unconditional
/// legacy schema validator: disabled/unmigrated deployments must keep their legacy
/// startup behavior, while enabled deployments must fail before workers/routes can
/// consume a schema that cannot uphold the membership lock contract.
pub async fn validate_org_scope_schema_prerequisites(pool: &MySqlPool) -> Result<(), AstralError> {
    let mut table_query = sqlx::query(ORG_SCOPE_SCHEMA_TABLES_SQL);
    for table in ORG_SCOPE_REQUIRED_TABLES {
        table_query = table_query.bind(table);
    }
    let rows = table_query.fetch_all(pool).await.map_err(db_err)?;
    let present: std::collections::HashSet<String> = rows
        .iter()
        .filter_map(|row| row.try_get::<String, _>("table_name").ok())
        .map(|name| name.to_ascii_lowercase())
        .collect();
    if present.len() != ORG_SCOPE_REQUIRED_TABLES.len()
        || ORG_SCOPE_REQUIRED_TABLES
            .iter()
            .any(|table| !present.contains(*table))
    {
        return Err(AstralError::Database(
            "code=org_scope.schema_prerequisites_missing_tables".into(),
        ));
    }

    for (table, index, columns, unique) in ORG_SCOPE_REQUIRED_INDEXES.iter().copied() {
        let rows = sqlx::query(ORG_SCOPE_SCHEMA_INDEX_SQL)
            .bind(table)
            .bind(index)
            .fetch_all(pool)
            .await
            .map_err(db_err)?;
        if rows.len() != columns.len()
            || rows.iter().enumerate().any(|(position, row)| {
                let column = row.try_get::<String, _>("column_name").ok();
                let non_unique = row.try_get::<i64, _>("non_unique").ok();
                column.as_deref() != Some(columns[position])
                    || non_unique != Some(i64::from(!unique))
            })
        {
            return Err(AstralError::Database(format!(
                "code=org_scope.schema_prerequisite_index_mismatch;table={table};index={index}"
            )));
        }
    }
    Ok(())
}

/// 读取全部当前受治理租户。调用方只能在 schema gate 已确认存在之后使用：任一
/// 数据库错误保持 `Err`，不得把未知覆盖范围当作空集而启动有限 allowlist worker。
///
/// 这里故意不按 `active` 过滤。inactive node 仍是 durable 管理态，可能带有待
/// 消费的撤销/拓扑 outbox；把它从 worker allowlist 漏掉会令可恢复状态永久停滞。
const MANAGED_TENANT_IDS_SQL: &str = "SELECT tenant_id FROM org_scope_node ORDER BY tenant_id ASC";

/// 从显式 projector allowlist 中找出尚未覆盖的 durable 管理态租户。
///
/// 这是纯函数，供启动门与测试共用；caller 必须在读取完整 node 表后调用。空
/// 返回才代表 frozen allowlist 覆盖了所有当前管理态，不能用单个 tenant probe
/// 或 outbox 空闲状态替代该证明。
pub fn missing_org_scope_tenant_allowlist_entries(
    configured_tenants: &[i64],
    managed_tenants: &[i64],
) -> Vec<i64> {
    managed_tenants
        .iter()
        .copied()
        .filter(|tenant_id| !configured_tenants.contains(tenant_id))
        .collect()
}

/// 读取当前 `org_scope_node` 中的全部受治理租户，供启动期 allowlist coverage
/// gate 使用。节点 id 必须是正数；畸形 durable 行也拒绝启动而不是静默跳过。
pub async fn list_org_scope_managed_tenant_ids(pool: &MySqlPool) -> Result<Vec<i64>, AstralError> {
    let tenant_ids = sqlx::query_scalar::<_, i64>(MANAGED_TENANT_IDS_SQL)
        .fetch_all(pool)
        .await
        .map_err(db_err)?;
    if let Some(tenant_id) = tenant_ids.iter().copied().find(|tenant_id| *tenant_id <= 0) {
        return Err(AstralError::Database(format!(
            "code=org_scope.managed_tenant_id_invalid;tenant_id={tenant_id}"
        )));
    }
    Ok(tenant_ids)
}

/// 探测 org-scope 门状态。**不返回 Err**：DB 失败映射为
/// [`OrgScopeGateState::Pending`]，调用方无法把基础设施故障误当 Unmanaged。
pub async fn probe_org_scope_gate(pool: &MySqlPool, tenant_id: i64) -> OrgScopeGateState {
    if tenant_id <= 0 {
        return OrgScopeGateState::Pending;
    }
    let table_present = match sqlx::query_scalar::<_, i64>(GATE_TABLE_PROBE_SQL)
        .fetch_one(pool)
        .await
    {
        Ok(count) => count > 0,
        Err(_) => return OrgScopeGateState::Pending,
    };
    if !table_present {
        return OrgScopeGateState::SchemaUnmanaged;
    }
    let node = match load_node_in_pool(pool, tenant_id).await {
        Ok(Some(node)) => node,
        Ok(None) => return OrgScopeGateState::TenantUnmanaged,
        Err(_) => return OrgScopeGateState::Pending,
    };
    OrgScopeGateState::TenantManaged { node }
}

// ─────────────────────────────────────────────────────────────────────────────
// node 行/类型转换/读取内核（跨子模块共享）
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) const NODE_SELECT_COLUMNS: &str = "tenant_id, root_tenant_id, parent_tenant_id, \
     generation, revoke_fence, relationship_revision, active, created_request_id, \
     created_operation_id, last_operation_id, activation_operator_user_id, \
     activation_approval_operation_id";

/// node 行视图。
#[derive(Debug, Clone)]
pub(crate) struct OrgNodeRow {
    pub tenant_id: i64,
    pub root_tenant_id: i64,
    pub parent_tenant_id: Option<i64>,
    pub generation: i64,
    pub revoke_fence: i64,
    pub relationship_revision: i64,
    pub active: bool,
    pub last_operation_id: String,
    pub activation_operator_user_id: Option<i64>,
    pub activation_approval_operation_id: Option<String>,
}

pub(crate) fn row_generation(value: i64, field: &str) -> Result<u64, AstralError> {
    if value < 0 {
        return Err(AstralError::Database(format!(
            "code=org_scope.negative_generation;field={field};value={value}"
        )));
    }
    Ok(value as u64)
}

pub(crate) fn gen_to_i64(value: u64, field: &str) -> Result<i64, AstralError> {
    i64::try_from(value).map_err(|_| {
        AstralError::Validation(format!("code=org_scope.generation_overflow;field={field}"))
    })
}

/// 行 → 类型化 `OrgNode`。行政根缺 activation 证明 → Err（调用方转 Pending，
/// 绝不放宽为有效节点）。
pub(crate) fn typed_node(row: &OrgNodeRow) -> Result<OrgNode, AstralError> {
    let root_activation = if row.parent_tenant_id.is_none() {
        match (
            row.activation_operator_user_id,
            &row.activation_approval_operation_id,
        ) {
            (Some(operator_user_id), Some(approval_operation_id)) => Some(OrgRootActivation {
                operator_user_id,
                approval_operation_id: approval_operation_id.clone(),
            }),
            _ => {
                return Err(AstralError::Database(
                    "code=org_scope.root_activation_missing".into(),
                ))
            }
        }
    } else {
        None
    };
    Ok(OrgNode {
        tenant_id: row.tenant_id,
        root_tenant_id: row.root_tenant_id,
        parent_tenant_id: row.parent_tenant_id,
        generation: row_generation(row.generation, "node.generation")?,
        revoke_fence: row_generation(row.revoke_fence, "node.revoke_fence")?,
        relationship_revision: row_generation(
            row.relationship_revision,
            "node.relationship_revision",
        )?,
        active: row.active,
        operation_id: row.last_operation_id.clone(),
        root_activation,
    })
}

pub(crate) fn node_row_from_row(row: &sqlx::mysql::MySqlRow) -> Result<OrgNodeRow, AstralError> {
    Ok(OrgNodeRow {
        tenant_id: row.try_get("tenant_id").map_err(db_err)?,
        root_tenant_id: row.try_get("root_tenant_id").map_err(db_err)?,
        parent_tenant_id: row.try_get("parent_tenant_id").map_err(db_err)?,
        generation: row.try_get("generation").map_err(db_err)?,
        revoke_fence: row.try_get("revoke_fence").map_err(db_err)?,
        relationship_revision: row.try_get("relationship_revision").map_err(db_err)?,
        active: row.try_get::<i8, _>("active").map_err(db_err)? != 0,
        last_operation_id: row.try_get("last_operation_id").map_err(db_err)?,
        activation_operator_user_id: row.try_get("activation_operator_user_id").map_err(db_err)?,
        activation_approval_operation_id: row
            .try_get("activation_approval_operation_id")
            .map_err(db_err)?,
    })
}

pub(crate) async fn load_node_in_pool(
    pool: &MySqlPool,
    tenant_id: i64,
) -> Result<Option<OrgNode>, AstralError> {
    let sql = format!("SELECT {NODE_SELECT_COLUMNS} FROM org_scope_node WHERE tenant_id = ?");
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
        .map_err(db_err)?;
    row.map(|row| node_row_from_row(&row))
        .transpose()?
        .map(|row| typed_node(&row))
        .transpose()
}

pub(crate) async fn load_node_in_tx(
    tx: &mut Transaction<'static, MySql>,
    tenant_id: i64,
) -> Result<Option<OrgNodeRow>, AstralError> {
    let sql = format!("SELECT {NODE_SELECT_COLUMNS} FROM org_scope_node WHERE tenant_id = ?");
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_err)?;
    row.map(|row| node_row_from_row(&row)).transpose()
}

pub(crate) async fn load_node_required_in_tx(
    tx: &mut Transaction<'static, MySql>,
    tenant_id: i64,
) -> Result<OrgNodeRow, AstralError> {
    load_node_in_tx(tx, tenant_id).await?.ok_or_else(|| {
        AstralError::NotFound(format!("code=org_scope.node_missing;tenant_id={tenant_id}"))
    })
}

pub(crate) async fn lock_node_in_tx(
    tx: &mut Transaction<'static, MySql>,
    tenant_id: i64,
) -> Result<Option<OrgNodeRow>, AstralError> {
    let sql =
        format!("SELECT {NODE_SELECT_COLUMNS} FROM org_scope_node WHERE tenant_id = ? FOR UPDATE");
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_err)?;
    row.map(|row| node_row_from_row(&row)).transpose()
}

/// 统一按 tenant_id 升序锁一组 node 行（避免并发 move 死锁）。
pub(crate) async fn lock_nodes_in_tx(
    tx: &mut Transaction<'static, MySql>,
    tenant_ids: &[i64],
) -> Result<Vec<OrgNodeRow>, AstralError> {
    if tenant_ids.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = vec!["?"; tenant_ids.len()].join(", ");
    let sql = format!(
        "SELECT {NODE_SELECT_COLUMNS} FROM org_scope_node WHERE tenant_id IN ({placeholders}) \
         ORDER BY tenant_id FOR UPDATE"
    );
    let mut query = sqlx::query(&sql);
    for tenant_id in tenant_ids {
        query = query.bind(*tenant_id);
    }
    let rows = query.fetch_all(&mut **tx).await.map_err(db_err)?;
    rows.iter().map(node_row_from_row).collect()
}

/// 沿 parent_tenant_id 上溯行政祖先（治理写/编译装载路径专用，深度有界；
/// 准入决策读路径绝不调用）。
pub(crate) async fn walk_ancestors_in_tx(
    tx: &mut Transaction<'static, MySql>,
    start_tenant_id: i64,
) -> Result<Vec<OrgNodeRow>, AstralError> {
    let mut chain = Vec::new();
    let mut cursor = Some(start_tenant_id);
    while let Some(tenant_id) = cursor {
        if chain.len() > ORG_MAX_TREE_DEPTH {
            return Err(AstralError::Validation(
                "code=org_scope.tree_depth_exceeded".into(),
            ));
        }
        let node = load_node_required_in_tx(tx, tenant_id).await?;
        cursor = node.parent_tenant_id;
        chain.push(node);
    }
    Ok(chain)
}

const NODE_ADVANCE_SQL: &str = "UPDATE org_scope_node SET generation = generation + 1, \
     revoke_fence = revoke_fence + IF(?, 1, 0), \
     relationship_revision = relationship_revision + IF(?, 1, 0), \
     last_operation_id = ? \
     WHERE tenant_id = ?";

/// 推进已锁定 node 行（generation 必进；可选 fence/relationship），回读新行。
/// `revoke_fence ≤ generation` 不变式由此保持（同步推进）。
pub(crate) async fn advance_node_in_tx(
    tx: &mut Transaction<'static, MySql>,
    tenant_id: i64,
    bump_fence: bool,
    bump_relationship: bool,
    operation_id: &str,
) -> Result<OrgNodeRow, AstralError> {
    let result = sqlx::query(NODE_ADVANCE_SQL)
        .bind(bump_fence)
        .bind(bump_relationship)
        .bind(operation_id)
        .bind(tenant_id)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    require_affected_one(&result, "node_advance_missing")?;
    load_node_in_tx(tx, tenant_id)
        .await?
        .ok_or_else(|| AstralError::Database("code=org_scope.node_vanished_after_advance".into()))
}

// ─────────────────────────────────────────────────────────────────────────────
// 命令/结果结构
// ─────────────────────────────────────────────────────────────────────────────

/// 一次 durable 变更记录（操作账/审批 outcome 的构成项）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrgMutationRecord {
    pub record_kind: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub tenant_id: i64,
}

/// 直接变更结果（revoke/mask/membership）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrgMutationOutcome {
    pub operation_id: String,
    pub replayed: bool,
    pub records: Vec<OrgMutationRecord>,
}

/// 审批结果（approve_request）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrgApproveOutcome {
    pub request_id: i64,
    pub operation_id: String,
    pub replayed: bool,
    pub records: Vec<OrgMutationRecord>,
}

/// DB reader 准入查询（main 的 `load_org_authorization(ctx)` 组合本查询与 gate）。
///
/// membership 绑定物理卡对：`card_id` 必填并严格相等；`identity_card_id` 可选，
/// 提供时同样严格相等（防换卡重放）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgAdmissionQuery {
    pub tenant_id: i64,
    pub user_id: i64,
    pub card_id: i64,
    pub identity_card_id: Option<i64>,
    pub now_unix_seconds: i64,
}

// ─────────────────────────────────────────────────────────────────────────────
// 仓储 trait
// ─────────────────────────────────────────────────────────────────────────────

/// ORG_SCOPE 权威存储入口。
///
/// 错误语义：[`OrgScopeRepository::load_admission_evidence`] 把**业务缺失**折叠为
/// `Ok(OrgAdmissionResult::Pending)`；`Err` 仅用于参数级错误与基础设施失败，
/// main 的 hook 必须把 `Err` 映射为 `Unavailable` 并 fail-closed，同时保留依赖
/// 故障与确定性业务 Pending 的可观测区分。其余方法的 `Err` 表示命令被拒绝或
/// 失败，绝不产生部分提交（单事务）。
#[async_trait::async_trait]
pub trait OrgScopeRepository: Send + Sync {
    /// 创建审批请求（ROOT_INIT/ROOT_GRANT/ATTACH/MOVE/DETACH/GRANT）。
    async fn create_request(
        &self,
        cmd: &OrgCreateRequestCommand,
    ) -> Result<OrgRequestOutcome, AstralError>;
    /// 审批并**同事务**执行对应 mutation；ROOT_INIT/ROOT_GRANT 必须携带治理证明。
    async fn approve_request(
        &self,
        cmd: &OrgApproveCommand,
    ) -> Result<OrgApproveOutcome, AstralError>;
    /// 驳回请求（PENDING → REJECTED）。
    async fn reject_request(&self, cmd: &OrgRejectCommand) -> Result<bool, AstralError>;
    /// 请求人撤销请求（PENDING → CANCELLED）。
    async fn cancel_request(&self, cmd: &OrgCancelCommand) -> Result<bool, AstralError>;
    /// 读取请求视图。
    async fn get_request(&self, request_id: i64) -> Result<Option<OrgRequestView>, AstralError>;
    /// 撤销 grant（narrowing；receiving 侧 generation 立即推进）。
    async fn revoke_grant(
        &self,
        cmd: &OrgGrantRevokeCommand,
    ) -> Result<OrgMutationOutcome, AstralError>;
    /// 本级精确来源屏蔽（不动 source grant 生命周期）。
    async fn apply_mask(
        &self,
        cmd: &OrgMaskApplyCommand,
    ) -> Result<OrgMutationOutcome, AstralError>;
    /// 撤除屏蔽。
    async fn remove_mask(
        &self,
        cmd: &OrgMaskRemoveCommand,
    ) -> Result<OrgMutationOutcome, AstralError>;
    /// 创建成员资格（独立版本化事实；不推进 node generation）。
    async fn create_membership(
        &self,
        cmd: &OrgMembershipCreateCommand,
    ) -> Result<OrgMutationOutcome, AstralError>;
    /// 撤销成员资格（立即影响该主体准入，不需重编译）。
    async fn revoke_membership(
        &self,
        cmd: &OrgMembershipRevokeCommand,
    ) -> Result<OrgMutationOutcome, AstralError>;
    /// 新 org worker：认领一条到期 outbox 事件（租约 CAS）。
    async fn claim_outbox_event(
        &self,
        cmd: &OrgOutboxClaimCommand,
    ) -> Result<Option<OrgOutboxLease>, AstralError>;
    /// 新 org worker：续租。
    async fn renew_outbox_lease(&self, cmd: &OrgOutboxRenewCommand) -> Result<bool, AstralError>;
    /// 新 org worker：失败登记（有限重试退避或终态 FAILED）。
    async fn fail_outbox_event(
        &self,
        cmd: &OrgOutboxFailCommand,
    ) -> Result<OrgOutboxFailOutcome, AstralError>;
    /// 新 org worker：在租约内装载已批准事实编译输入（flatten 祖先依赖 +
    /// 父 publication 头）。
    async fn load_compile_input(
        &self,
        cmd: &OrgCompileInputCommand,
    ) -> Result<astral_types::org_scope::OrgCompileInput, AstralError>;
    /// 新 org worker：原子发布（sealed publication/segments/dependency pins +
    /// current generation CAS + 事件终态 + 审计，单事务）。载荷校验失败或
    /// source/dependency 陈旧时返回 Err，worker 保持 PENDING 重试。
    async fn complete_publish(
        &self,
        cmd: &OrgPublishCommand,
    ) -> Result<OrgPublishOutcome, AstralError>;
    /// 新 org worker：按批推进 MOVE/DETACH 后代的 root 传播（**扇出**语义：
    /// 每批只推进锚点——载荷 child——的直接 active 子节点中尚未以本操作 id
    /// 落过 NODE revision 账的至多 `batch_limit` 个（同 root 后代同样选中
    /// 失效），并为每个被推进子节点原子派生新的 typed `SUBTREE_PROPAGATE`
    /// child intent；后代由各自 child event 继续推进，宽兄弟分支不可能丢失）。
    /// 事件在事务内先经租约校验（status/owner/token 摘要/未过期 + 精确
    /// SUBTREE_PROPAGATE kind）与意图绑定（tenant/operation/root/frontier/
    /// revision 栅栏），任一不一致绝不写节点。重试凭账存在性跳过已推进子节点，
    /// 崩溃/重试安全。
    async fn propagate_subtree_root(
        &self,
        cmd: &OrgSubtreePropagateCommand,
    ) -> Result<OrgSubtreePropagateOutcome, AstralError>;
    /// 新 org worker：按批推进 source-head 变更的直接依赖者。依赖传播只推进
    /// generation，不触碰 topology relationship/revoke_fence；用 outbox intent
    /// marker 幂等，等待锚点 publication 后再推进其子节点，防止后代在父节点发布
    /// 前递归作废。每个子节点只写 NODE_MUTATED 触发事件 + typed dependency child
    /// intent；publication 仍只经 complete_publish。
    async fn propagate_dependency_change(
        &self,
        cmd: &OrgDependencyPropagateCommand,
    ) -> Result<OrgDependencyPropagateOutcome, AstralError>;
    /// 新 org worker：租约内**无发布完成**（原子要求 LEASED owner + token
    /// 摘要 + 未过期租约 + 精确 expected kind；清租约 + CAS 单调 + DONE）。
    ///
    /// - 仅 [`OrgOutboxEventKind::MembershipChanged`] /
    ///   [`OrgOutboxEventKind::SubtreePropagate`] /
    ///   [`OrgOutboxEventKind::DependencyPropagate`] 可用；category-1 其余 7 类与
    ///   未知种类在任何 DB 写之前拒绝（稳定机码
    ///   `code=org_scope.outbox_complete_kind_forbidden`）；行内 event_kind 与
    ///   `expected_kind` 不一致同样拒绝（`code=org_scope.outbox_complete_kind_mismatch`），
    ///   绝不静默消费错种类的事件。
    /// - 不产生 publication、source mutation 或新审计写——消费完成本身以
    ///   outbox 行的 status/cas_version/attempts 为可追溯证据。
    /// - 租约丢失/已终态时返回 `code=org_scope.outbox_lease_lost`，绝不静默
    ///   成功；重复完成同事件亦如此（DONE 行不再满足 LEASED 谓词）。
    /// - 默认实现 fail-closed（`code=org_scope.outbox_complete_impl_unavailable`）：
    ///   SQL 生产实现（`SqlxOrgScopeRepository`）须在自身 impl 中覆盖并委托
    ///   worker 原语；未覆盖的实现一律拒绝，绝不假装完成。
    async fn complete_outbox_event(
        &self,
        cmd: &OrgOutboxCompleteCommand,
    ) -> Result<OrgOutboxCompleteOutcome, AstralError> {
        let _ = cmd;
        Err(AstralError::Internal(
            "code=org_scope.outbox_complete_impl_unavailable".into(),
        ))
    }
    /// 准入证据读取：current 已封存 publication + fresh 绑定 id 校验（含祖先
    /// active/root/generation/fence/relationship）+ fresh membership；不运行时
    /// 遍历祖先做授权推导。业务缺失 → `Ok(Pending)`。
    async fn load_admission_evidence(
        &self,
        query: &OrgAdmissionQuery,
    ) -> Result<OrgAdmissionResult, AstralError>;
}

/// sqlx 生产实现。
pub struct SqlxOrgScopeRepository {
    db: MySqlPool,
}

impl SqlxOrgScopeRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }

    pub(crate) fn pool(&self) -> &MySqlPool {
        &self.db
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 共享内部工具
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) fn db_err(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("org_scope repository query failed: {error}"))
}

/// 类型合同错误 → AstralError（保留稳定机器码）。
pub(crate) fn org_err(error: OrgError) -> AstralError {
    AstralError::Validation(format!(
        "code={};detail={}",
        error.code.as_str(),
        error.message
    ))
}

pub(crate) fn positive_i64(value: i64, field: &str) -> Result<(), AstralError> {
    if value <= 0 {
        return Err(AstralError::Validation(format!(
            "code=org_scope.non_positive_id;field={field}"
        )));
    }
    Ok(())
}

/// 稳定 operation_id 校验：1..=[`MAX_ORG_ID_TEXT_LEN`]（64）字节，与类型合同
/// `org_validate_operation_id` 同界；ASCII 字母数字与 `-_.:/`。
pub(crate) fn validated_operation_id(value: &str) -> Result<(), AstralError> {
    if value.is_empty() || value.len() > MAX_ORG_ID_TEXT_LEN {
        return Err(AstralError::Validation(
            "code=org_scope.invalid_operation_id;reason=length".into(),
        ));
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
    }) {
        return Err(AstralError::Validation(
            "code=org_scope.invalid_operation_id;reason=charset".into(),
        ));
    }
    Ok(())
}

pub(crate) fn validated_stable_uuid(value: &str, field: &str) -> Result<(), AstralError> {
    if value.len() != 36 {
        return Err(AstralError::Validation(format!(
            "code=org_scope.invalid_uuid;field={field};reason=length"
        )));
    }
    let parsed = Uuid::parse_str(value).map_err(|_| {
        AstralError::Validation(format!(
            "code=org_scope.invalid_uuid;field={field};reason=parse"
        ))
    })?;
    if parsed.is_nil() {
        return Err(AstralError::Validation(format!(
            "code=org_scope.invalid_uuid;field={field};reason=nil"
        )));
    }
    if parsed.to_string() != value {
        return Err(AstralError::Validation(format!(
            "code=org_scope.invalid_uuid;field={field};reason=non_canonical"
        )));
    }
    Ok(())
}

/// lease owner 校验（worker 身份，允许 128 字节）。
pub(crate) fn validated_lease_owner(value: &str) -> Result<(), AstralError> {
    if value.is_empty() || value.len() > 128 {
        return Err(AstralError::Validation(
            "code=org_scope.invalid_lease_owner;reason=length".into(),
        ));
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
    }) {
        return Err(AstralError::Validation(
            "code=org_scope.invalid_lease_owner;reason=charset".into(),
        ));
    }
    Ok(())
}

/// 64 位十六进制 lease token → 32 字节。
pub(crate) fn decode_worker_token(token_hex: &str) -> Result<Vec<u8>, AstralError> {
    let bytes = hex::decode(token_hex).map_err(|_| {
        AstralError::Validation("code=org_scope.invalid_worker_token;reason=hex".into())
    })?;
    if bytes.len() != 32 {
        return Err(AstralError::Validation(
            "code=org_scope.invalid_worker_token;reason=length".into(),
        ));
    }
    Ok(bytes)
}

/// DB lease rows retain only the SHA-256 of their opaque bearer token. The
/// caller retains the raw 32-byte token and proves lease ownership by hashing
/// it again at every guarded mutation.
pub(crate) fn worker_token_hash(token: &[u8]) -> Vec<u8> {
    Sha256::digest(token).to_vec()
}

pub(crate) fn uuid_v4_string() -> String {
    Uuid::new_v4().to_string()
}

/// 规范输入 digest：kind 域分隔 + serde 规范序列化字节的 SHA-256。
pub(crate) fn canonical_input_digest(kind: &str, canonical_json: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"astral:org-scope:op:v1:");
    hasher.update(kind.as_bytes());
    hasher.update(b":");
    hasher.update(canonical_json.as_bytes());
    hasher.finalize().to_vec()
}

/// 64 位十六进制摘要 → 32 字节（DB BINARY(32) 列）。
pub(crate) fn digest32_from_hex(value: &str, field: &str) -> Result<Vec<u8>, AstralError> {
    let bytes = hex::decode(value).map_err(|_| {
        AstralError::Validation(format!("code=org_scope.invalid_digest;field={field}"))
    })?;
    if bytes.len() != 32 {
        return Err(AstralError::Validation(format!(
            "code=org_scope.invalid_digest;field={field};reason=length"
        )));
    }
    Ok(bytes)
}

/// 截断到 MySQL 列宽的 last_error 文本。
pub(crate) fn truncate_error(text: &str) -> String {
    if text.len() <= 512 {
        text.to_owned()
    } else {
        let mut cut = 512;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        text[..cut].to_owned()
    }
}

/// 作用域入口校验（类型域校验 + 正向 id/文本界）。
pub(crate) fn validated_scope(scope: &OrgScope) -> Result<(), AstralError> {
    positive_i64(scope.resource_tenant_id, "scope.resource_tenant_id")?;
    if scope.resource.trim().is_empty() || scope.resource.len() > 191 {
        return Err(AstralError::Validation(
            "code=org_scope.invalid_scope;field=resource".into(),
        ));
    }
    if scope.action.trim().is_empty() || scope.action.len() > 191 {
        return Err(AstralError::Validation(
            "code=org_scope.invalid_scope;field=action".into(),
        ));
    }
    scope.validate().map_err(org_err)
}

pub(crate) fn validity_bounds(window: &ValidityWindow) -> (Option<i64>, Option<i64>) {
    (window.not_before, window.expires_at)
}

/// 请求级 subject 校验：PERSONAL 需正 id；UNIT 不携带 subject。具体的
/// membership/card/root 关系在 GRANT 审批事务内以锁定读复验，不能由该结构校验替代。
pub(crate) fn validated_subject(subject: Option<&OrgSubject>) -> Result<(), AstralError> {
    if let Some(subject) = subject {
        subject.validate().map_err(org_err)?;
    }
    Ok(())
}

pub(crate) async fn begin_tx(pool: &MySqlPool) -> Result<Transaction<'static, MySql>, AstralError> {
    pool.begin().await.map_err(db_err)
}

/// 事务内确认受影响行数恰为 1，否则失败（CAS 语义兜底）。
pub(crate) fn require_affected_one(
    result: &sqlx::mysql::MySqlQueryResult,
    code: &str,
) -> Result<(), AstralError> {
    if result.rows_affected() != 1 {
        return Err(AstralError::Validation(format!("code=org_scope.{code}")));
    }
    Ok(())
}

/// Pending 快捷构造。
pub(crate) fn pending(code: OrgPendingCode, detail: impl Into<String>) -> OrgAdmissionResult {
    OrgAdmissionResult::Pending {
        code,
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_id_is_capped_to_type_contract_length() {
        assert!(validated_operation_id("op-20260922_1:2/3.4").is_ok());
        assert!(validated_operation_id("").is_err());
        assert!(validated_operation_id(&"a".repeat(MAX_ORG_ID_TEXT_LEN + 1)).is_err());
        assert!(validated_operation_id("bad id with space").is_err());
        assert!(validated_operation_id("中文").is_err());
    }

    #[test]
    fn worker_token_must_be_32_bytes_hex() {
        assert!(decode_worker_token(&"ab".repeat(32)).is_ok());
        assert!(decode_worker_token(&"ab".repeat(31)).is_err());
        assert!(decode_worker_token("zz").is_err());
    }

    #[test]
    fn canonical_digest_is_domain_separated_and_stable() {
        let first = canonical_input_digest("GRANT", r#"{"a":1}"#);
        let second = canonical_input_digest("GRANT", r#"{"a":1}"#);
        let other_kind = canonical_input_digest("MOVE", r#"{"a":1}"#);
        assert_eq!(first, second);
        assert_ne!(first, other_kind);
        assert_eq!(first.len(), 32);
    }

    #[test]
    fn generation_boundary_conversion_is_checked() {
        assert_eq!(gen_to_i64(1, "generation").unwrap(), 1i64);
        assert_eq!(row_generation(7, "generation").unwrap(), 7u64);
        assert!(gen_to_i64((i64::MAX as u64) + 1, "generation").is_err());
        assert!(row_generation(-1, "generation").is_err());
    }

    #[test]
    fn error_truncation_respects_char_boundaries() {
        let ascii = "a".repeat(600);
        assert_eq!(truncate_error(&ascii).len(), 512);
        let multibyte = "组".repeat(300);
        assert!(truncate_error(&multibyte).is_char_boundary(0));
        assert!(truncate_error(&multibyte).len() <= 512);
    }

    #[test]
    fn org_scope_enabled_schema_prerequisites_are_frozen() {
        assert_eq!(ORG_SCOPE_REQUIRED_TABLES.len(), 13);
        assert!(ORG_SCOPE_REQUIRED_TABLES.contains(&"org_scope_membership"));
        assert!(ORG_SCOPE_REQUIRED_TABLES.contains(&"org_scope_outbox"));
        assert_eq!(ORG_SCOPE_SCHEMA_TABLES_SQL.matches('?').count(), 13);
        assert!(ORG_SCOPE_SCHEMA_TABLES_SQL.contains("information_schema.TABLES"));
        assert!(ORG_SCOPE_SCHEMA_INDEX_SQL.contains("information_schema.STATISTICS"));
        assert!(ORG_SCOPE_SCHEMA_INDEX_SQL.contains("ORDER BY SEQ_IN_INDEX"));
        assert_eq!(
            ORG_SCOPE_REQUIRED_INDEXES,
            [
                (
                    "org_scope_membership",
                    "idx_osmem_user_active",
                    &["user_id", "active"][..],
                    false,
                ),
                (
                    "org_scope_membership",
                    "idx_osmem_card",
                    &["card_id", "active"][..],
                    false,
                ),
                ("identity_card", "uk_ic_user", &["user_id"][..], true),
            ]
        );
    }

    #[test]
    fn frozen_allowlist_must_cover_every_durable_managed_tenant() {
        assert!(missing_org_scope_tenant_allowlist_entries(&[7, 9], &[]).is_empty());
        assert!(missing_org_scope_tenant_allowlist_entries(&[7, 9], &[7, 9]).is_empty());
        assert_eq!(
            missing_org_scope_tenant_allowlist_entries(&[7, 9], &[7, 11, 13, 9]),
            vec![11, 13]
        );
        // The helper receives every node row; it deliberately has no active-state
        // filter, so an inactive durable node remains a required worker owner.
        assert_eq!(
            missing_org_scope_tenant_allowlist_entries(&[7], &[7, 42]),
            vec![42]
        );
    }

    #[test]
    fn org_outbox_event_kind_freezes_all_ten_wire_literals() {
        let expected = [
            (OrgOutboxEventKind::NodeCreated, "NODE_CREATED"),
            (
                OrgOutboxEventKind::NodeTopologyChanged,
                "NODE_TOPOLOGY_CHANGED",
            ),
            (OrgOutboxEventKind::NodeMutated, "NODE_MUTATED"),
            (OrgOutboxEventKind::GrantIssued, "GRANT_ISSUED"),
            (OrgOutboxEventKind::GrantRevoked, "GRANT_REVOKED"),
            (OrgOutboxEventKind::MaskApplied, "MASK_APPLIED"),
            (OrgOutboxEventKind::MaskRemoved, "MASK_REMOVED"),
            (OrgOutboxEventKind::MembershipChanged, "MEMBERSHIP_CHANGED"),
            (OrgOutboxEventKind::SubtreePropagate, "SUBTREE_PROPAGATE"),
            (
                OrgOutboxEventKind::DependencyPropagate,
                "DEPENDENCY_PROPAGATE",
            ),
        ];
        assert_eq!(OrgOutboxEventKind::ALL.len(), 10);
        for (kind, literal) in expected {
            assert_eq!(kind.as_str(), literal);
            // 公开常量与分类同源（const 派生），运行期再逐一冻结。
            let constant = match kind {
                OrgOutboxEventKind::NodeCreated => ORG_EVENT_NODE_CREATED,
                OrgOutboxEventKind::NodeTopologyChanged => ORG_EVENT_NODE_TOPOLOGY_CHANGED,
                OrgOutboxEventKind::NodeMutated => ORG_EVENT_NODE_MUTATED,
                OrgOutboxEventKind::GrantIssued => ORG_EVENT_GRANT_ISSUED,
                OrgOutboxEventKind::GrantRevoked => ORG_EVENT_GRANT_REVOKED,
                OrgOutboxEventKind::MaskApplied => ORG_EVENT_MASK_APPLIED,
                OrgOutboxEventKind::MaskRemoved => ORG_EVENT_MASK_REMOVED,
                OrgOutboxEventKind::MembershipChanged => ORG_EVENT_MEMBERSHIP_CHANGED,
                OrgOutboxEventKind::SubtreePropagate => ORG_EVENT_SUBTREE_PROPAGATE,
                OrgOutboxEventKind::DependencyPropagate => ORG_EVENT_DEPENDENCY_PROPAGATE,
            };
            assert_eq!(constant, literal);
            // 解析回环：仅精确大写取值可解析。
            assert_eq!(literal.parse::<OrgOutboxEventKind>().unwrap(), kind);
        }
    }

    #[test]
    fn org_outbox_event_kind_parse_rejects_lowercase_unknown_and_padding() {
        for bad in [
            "node_created",
            "Node_Created",
            "NODE_CREATED ",
            " NODE_CREATED",
            "node topology changed",
            "NODE_REMOVED",
            "SUBTREE_PROPAGATION",
            "",
        ] {
            assert!(
                bad.parse::<OrgOutboxEventKind>().is_err(),
                "kind literal {bad:?} must not parse"
            );
        }
    }

    #[test]
    fn publication_free_completion_allowlist_matches_exactly_three_kinds() {
        for kind in OrgOutboxEventKind::ALL {
            let expected_allowed = matches!(
                kind,
                OrgOutboxEventKind::MembershipChanged
                    | OrgOutboxEventKind::SubtreePropagate
                    | OrgOutboxEventKind::DependencyPropagate
            );
            assert_eq!(kind.allows_publication_free_completion(), expected_allowed);
            let classified = worker::validated_completion_kind(kind);
            assert_eq!(classified.is_ok(), expected_allowed);
            if let Err(error) = classified {
                assert!(error
                    .to_string()
                    .contains("org_scope.outbox_complete_kind_forbidden"));
            }
        }
    }
}
