//! ORG_SCOPE 新 worker 原语：outbox 租约（claim/renew/fail）、编译输入装载
//! （`load_compile_input`，flatten 全部祖先 source head）、原子发布
//! （`complete_publish`）、kind 限定"无发布完成"（`complete_outbox_event`）
//! 与子树 root 传播（`propagate_subtree_root`，扇出语义）。
//!
//! 纪律：
//! - 与旧 `authorization_delta_event` 完全隔离：独立表、独立租约、独立载荷合同
//!   （typed org facts，无 CanonicalGrant/user_id 伪造）。
//! - 租约语义与 delta 事件租约同型：owner + token-hash 按值匹配、到期可夺、
//!   CAS 版本单调；`load_compile_input`/`complete_publish`/`complete_outbox_event`
//!   都在事务内复验 status=LEASED + owner + token + **未过期**（expiry fence
//!   全检）。
//! - **kind 封闭派发**（10 个字面量的 [`OrgOutboxEventKind`] 分类，mod.rs）：
//!   category-1 的 7 个投影必需种类只能 `load_compile_input` + `complete_publish`
//!   消费；`MEMBERSHIP_CHANGED` / `SUBTREE_PROPAGATE` /
//!   `DEPENDENCY_PROPAGATE` 只能 kind 限定的 `complete_outbox_event` 消费
//!   publication/source mutation/新审计写）。两条路径在仓库边界互斥：跨路径
//!   或未知种类一律确定性拒绝，绝不静默消费。无发布完成另有**载荷门**（行内
//!   载荷必须与 kind 同构、过类型合同校验、租户与事件一致；MEMBERSHIP 用
//!   typed `OrgMembership` 并把载荷 operation_id 绑定到事件行 operation_id
//!   ——两者由同一 source mutation 写入，漂移即损坏；SUBTREE 用 typed
//!   `OrgSubtreePropagatePayload`，其类型刻意不含 operation_id，完成证明以
//!   锁定事件行 operation_id 查询标记）与
//!   SUBTREE 的 **durable 传播收敛证明**（Current 关系下锚点必须已无"未以本
//!   操作 id 标记"的直接 active 子节点，Superseded 免证明）——畸形/跨租户/
//!   未收敛意图在仓库边界拒绝 DONE。
//! - claim 侧预算收敛：`OrgOutboxClaimCommand::max_attempts` 与 fail 侧同一
//!   部署预算。候选事件 attempts 已达预算时**不再认领**，而是在同一 claim
//!   事务内落终态 FAILED（稳定机码 `code=org_scope.outbox_claim_budget_exhausted`，
//!   租约字段清空、CAS 单调推进），否则 crash-after-claim 的过期租约回收会
//!   无限累加 attempts。判定（`candidate_attempts >= max_attempts`）与
//!   `fail_outbox_event` 的重试判定（`attempts < max_attempts`）严格互补：
//!   同一预算下认领侧绝不把 fail 侧仍会重试的事件提前终态化，事件也最多被
//!   认领 `max_attempts` 次。终态化对调用方表现为 `Ok(None)`（本事件永久
//!   退出队列），可观测性落库（status/last_error/cas_version），每租户每轮
//!   至多收敛一条，不改变轮询/租约/CAS 语义。
//! - `complete_publish` 单事务原子：sealed publication/segments/dependency pins
//!   插入 + current generation 单调 CAS + outbox 事件终态 + 审计；载荷合同校验
//!   （`OrgPublication::validate`）与 source/dependency 新鲜度任一失败即整体
//!   回滚，worker 保持 PENDING 重试，绝不部分发布。
//! - `propagate_subtree_root` 为**扇出**语义（防宽兄弟分支丢失）：单个 leased
//!   `SUBTREE_PROPAGATE` 事件只负责其**锚点**（载荷 `child_tenant_id`）的
//!   **直接** active 子节点中尚未以本操作 id 落过 NODE revision 账的
//!   （`org_scope_revision` 存在性 = durable 幂等标记；**不依赖 root 不等**——
//!   同 root MOVE 同样推进锚点关系代次、后代依赖钉同样陈旧，root 已等于目标
//!   的后代也必须被选中失效一次），至多 `batch_limit` 个；推进为 root 置目标
//!   （即使已相同）+ generation/relationship_revision/revoke_fence **同步 +1**
//!   （与 source 级 NODE_ATTACH/MOVE/DETACH 同一合同），并为每个被推进子节点
//!   原子追加新的 typed child intent（同 operation_id、目标 root、子节点推进后
//!   relationship_revision）；后代由各自 child event 继续推进，深度与宽度均由
//!   真实节点数有界。选中数 == batch_limit 时必为 `done=false,
//!   next_frontier=[锚点]`（同一事件重入排空剩余兄弟），选中数 < batch_limit
//!   才 done——绝不因本批更新完毕而宣称完成。每次调用先在事务内锁定并校验
//!   leased 事件（status/owner/token 摘要/未过期 + 精确 SUBTREE_PROPAGATE
//!   kind），再绑定意图（载荷 tenant/operation/root/frontier 必须与命令逐项
//!   一致、锚点 relationship_revision 必须等于载荷 revision；锚点 revision
//!   **更大** ⇒ 意图已被更新的拓扑 source 变更取代，无写安全放行
//!   `superseded=true`，更小 ⇒ fail-closed）；锁序 outbox 事件 → 锚点 → 直接
//!   子节点（升序）。重试凭账存在性跳过已推进子节点 ⇒ 崩溃/重试幂等；被
//!   rehome 的分支（父边已离开锚点）天然不可选，归更新的拓扑意图所有。每个
//!   被推进节点在同一事务内按 NODE 载荷合同追加 revision 账行（即幂等标记）
//!   与 `NODE_TOPOLOGY_CHANGED` outbox 事件。
//! - 编译本体（HAMT/OrgCompiledState）外置 policy-engine；本模块只装载数据。

use sqlx::Row;

use super::mutations::{
    append_audit_in_tx, append_outbox_event_in_tx, append_revision_in_tx, grant_from_row,
    is_unique_violation, typed_grant, OrgAuditWrite, GRANT_SELECT_COLUMNS,
};
use super::requests::append_subtree_propagate_intent_in_tx;
use super::*;
use astral_types::org_scope::{
    org_dependency_matches_publication, OrgCompileInput, OrgDependency,
    OrgDependencyPropagatePayload, OrgGrantRef, OrgMask, OrgMembership, OrgPublication, OrgSegment,
    OrgSubtreePropagatePayload,
};

// ─────────────────────────────────────────────────────────────────────────────
// 命令 / 结果
// ─────────────────────────────────────────────────────────────────────────────

/// 认领命令（worker 身份 + 租约时长 + claim 侧 attempt 预算）。
#[derive(Debug, Clone)]
pub struct OrgOutboxClaimCommand {
    pub tenant_id: i64,
    pub worker_owner: String,
    /// 64 位十六进制（32 字节熵）；DB 只存 SHA-256 摘要。
    pub worker_token_hex: String,
    pub lease_seconds: i64,
    /// claim 侧 attempt 预算（与 fail 侧 `OrgOutboxFailCommand::max_attempts`
    /// 携带同一部署配置）：候选事件 attempts 已达该值时不认领，改为同一 claim
    /// 事务内落终态 FAILED，使 crash-after-claim 的过期租约回收有界收敛。
    /// 必须 ≥ 1；事件最多被认领 `max_attempts` 次。
    pub max_attempts: i64,
}

/// 已认领事件租约。
#[derive(Debug, Clone)]
pub struct OrgOutboxLease {
    pub org_event_id: i64,
    pub event_id: String,
    pub tenant_id: i64,
    pub event_kind: String,
    pub operation_id: String,
    pub payload_json: String,
    pub attempts: i64,
    pub cas_version: u64,
    pub lease_expires_at_unix: i64,
}

/// 续租命令。
#[derive(Debug, Clone)]
pub struct OrgOutboxRenewCommand {
    pub org_event_id: i64,
    pub worker_owner: String,
    pub worker_token_hex: String,
    pub lease_seconds: i64,
}

/// 失败登记命令（有限重试退避或终态 FAILED）。
#[derive(Debug, Clone)]
pub struct OrgOutboxFailCommand {
    pub org_event_id: i64,
    pub worker_owner: String,
    pub worker_token_hex: String,
    pub error: String,
    pub retryable: bool,
    pub backoff_seconds: i64,
    /// attempts 达到该值后 retryable 失败转终态 FAILED。
    pub max_attempts: i64,
}

/// 失败登记结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgOutboxFailOutcome {
    /// "PENDING"（退避重试）或 "FAILED"（终态，operator 介入）。
    pub status: String,
    pub attempts: i64,
}

/// 编译输入装载命令（租约内）。
#[derive(Debug, Clone)]
pub struct OrgCompileInputCommand {
    pub org_event_id: i64,
    pub worker_owner: String,
    pub worker_token_hex: String,
}

/// 原子发布命令。
#[derive(Debug, Clone)]
pub struct OrgPublishCommand {
    pub org_event_id: i64,
    pub worker_owner: String,
    pub worker_token_hex: String,
    pub publication: OrgPublication,
}

/// 发布结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgPublishOutcome {
    pub publication_id: i64,
    pub generation: u64,
    pub cas_version: u64,
}

/// 子树传播命令（MOVE/DETACH 后代 root 推进，单批扇出）。
///
/// 事件驱动合同：一次调用只推进**锚点**（载荷 `child_tenant_id`）的**直接**
/// active 子节点中尚未以本操作 id 落过 NODE revision 账的至多 `batch_limit`
/// 个（durable 幂等标记；同 root 后代同样选中失效），并为每个被推进子节点
/// 原子追加新的 typed `SUBTREE_PROPAGATE` child intent（同 operation_id、目标
/// root、子节点推进后 relationship_revision）；后代由各自 child event 继续
/// 推进。
#[derive(Debug, Clone)]
pub struct OrgSubtreePropagateCommand {
    /// 租约内的 org outbox 事件 id（SUBTREE_PROPAGATE intent 行）。
    pub org_event_id: i64,
    pub worker_owner: String,
    /// 64 位十六进制（32 字节熵）；DB 只存 SHA-256 摘要。
    pub worker_token_hex: String,
    /// 必须精确等于 [`OrgOutboxEventKind::SubtreePropagate`]（入口预检拒绝其余
    /// 取值；锁定 SQL 亦带 kind 条件双保险）。
    pub expected_kind: OrgOutboxEventKind,
    /// 审计关联操作 id（传播以两级状态谓词幂等：锚点 root 栅栏 + 子节点
    /// root != 目标 root 谓词）；必须与事件行 operation_id 精确一致（意图绑定）。
    pub operation_id: String,
    /// 目标 root；必须与载荷 `new_root_tenant_id` 精确一致（意图绑定）。
    pub new_root_tenant_id: i64,
    /// 遍历前沿：必须**恰为** `[载荷 child_tenant_id]`（锚点重入）。锚点的
    /// 权威来源是 durable 载荷；本字段把调用方重入表达与 durable 锚点绑定，
    /// 空/多元素/异值在节点写入前一律拒绝（防止持有效租约的调用方把传播
    /// 重定向到无关租户）。
    pub frontier: Vec<i64>,
    /// 本批直接子节点推进上限（1..=[`ORG_MAX_PROPAGATE_BATCH`]）。
    pub batch_limit: i64,
}

/// 传播结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgSubtreePropagateOutcome {
    /// 本批实际推进 root 的直接子节点（升序）。
    pub updated_tenant_ids: Vec<i64>,
    /// 下一批前沿：`done=false` 时恒为 `[锚点]`（同一事件重入排空剩余兄弟）；
    /// `done=true` 时为空。
    pub next_frontier: Vec<i64>,
    /// 锚点直接子节点中未以本操作 id 标记者已在本批全部排空（选中数 <
    /// batch_limit）或意图已被取代。选中数 == batch_limit 时必为 false：必须
    /// 以同一事件重入，绝不因本批更新完毕而宣称完成（宽兄弟完整性）。
    pub done: bool,
    /// 意图已被更新的拓扑 source 变更取代。
    pub superseded: bool,
}

#[derive(Debug, Clone)]
pub struct OrgDependencyPropagateCommand {
    pub org_event_id: i64,
    pub worker_owner: String,
    pub worker_token_hex: String,
    pub expected_kind: OrgOutboxEventKind,
    pub operation_id: String,
    pub anchor_tenant_id: i64,
    pub batch_limit: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgDependencyPropagateOutcome {
    pub updated_tenant_ids: Vec<i64>,
    pub done: bool,
    pub superseded: bool,
}

/// kind 限定"无发布完成"命令（`MEMBERSHIP_CHANGED` / `SUBTREE_PROPAGATE`
/// 专用；category-1 投影种类只能经 `complete_publish`）。
#[derive(Debug, Clone)]
pub struct OrgOutboxCompleteCommand {
    pub org_event_id: i64,
    pub worker_owner: String,
    /// 64 位十六进制（32 字节熵）；DB 只存 SHA-256 摘要。
    pub worker_token_hex: String,
    /// 期望事件种类：白名单之外（category-1）在任何 DB 写之前拒绝；行内
    /// event_kind 与本值不一致同样拒绝，绝不静默消费错种类的事件。
    pub expected_kind: OrgOutboxEventKind,
}

/// 无发布完成结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgOutboxCompleteOutcome {
    /// 终态化时事件的已认领次数（claim 计数；完成本身不递增 attempts）。
    pub attempts: i64,
    /// 事件行完成后的 CAS 版本（单调 +1 证据）。
    pub cas_version: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// SQL
// ─────────────────────────────────────────────────────────────────────────────

/// claim 侧预算耗尽的稳定机器码（落库 `last_error`，operator 对账检索入口）。
/// 与 fail 侧终态、租约丢失机码同层级，不得漂移。
const ORG_OUTBOX_CLAIM_BUDGET_EXHAUSTED_CODE: &str = "code=org_scope.outbox_claim_budget_exhausted";

const OUTBOX_CLAIM_CANDIDATE_SQL: &str = "SELECT org_event_id, event_id, tenant_id, event_kind, \
     operation_id, payload_json, attempts, cas_version, lease_owner, \
     CAST(UNIX_TIMESTAMP(lease_expires_at) AS SIGNED) as lease_expires_at_unix \
     FROM org_scope_outbox WHERE tenant_id = ? \
       AND ((status = 'PENDING' \
             AND (next_attempt_at IS NULL OR next_attempt_at <= UTC_TIMESTAMP(6))) \
            OR (status = 'LEASED' \
                AND lease_expires_at IS NOT NULL \
                AND lease_expires_at <= UTC_TIMESTAMP(6))) \
     ORDER BY COALESCE(next_attempt_at, created_at), org_event_id LIMIT 1 FOR UPDATE";
const OUTBOX_CLAIM_INSTALL_SQL: &str = "UPDATE org_scope_outbox SET status = 'LEASED', \
     lease_owner = ?, lease_token_hash = ?, \
     lease_expires_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP(6)), \
     cas_version = cas_version + 1, attempts = attempts + 1 \
     WHERE org_event_id = ? \
       AND ((status = 'PENDING' \
             AND (next_attempt_at IS NULL OR next_attempt_at <= UTC_TIMESTAMP(6))) \
            OR (status = 'LEASED' \
                AND lease_expires_at IS NOT NULL \
                AND lease_expires_at <= UTC_TIMESTAMP(6)))";
/// claim 侧预算耗尽：候选行在 `FOR UPDATE` 锁内被本事务选中，更新谓词镜像
/// 候选谓词（due PENDING / 过期 LEASED）作双重防线；终态语义与
/// `OUTBOX_FAIL_TERMINAL_SQL` 同型（清租约、next_attempt_at=NULL、CAS 单调），
/// 但**不递增 attempts**——本次认领并未发生，attempts 保持真实认领次数。
const OUTBOX_CLAIM_EXHAUST_SQL: &str = "UPDATE org_scope_outbox SET status = 'FAILED', \
     next_attempt_at = NULL, lease_owner = NULL, lease_token_hash = NULL, lease_expires_at = NULL, \
     cas_version = cas_version + 1, last_error = ? \
     WHERE org_event_id = ? \
       AND ((status = 'PENDING' \
             AND (next_attempt_at IS NULL OR next_attempt_at <= UTC_TIMESTAMP(6))) \
            OR (status = 'LEASED' \
                AND lease_expires_at IS NOT NULL \
                AND lease_expires_at <= UTC_TIMESTAMP(6)))";
const OUTBOX_RENEW_SQL: &str = "UPDATE org_scope_outbox \
     SET lease_expires_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP(6)), \
         cas_version = cas_version + 1 \
     WHERE org_event_id = ? AND lease_owner = ? AND lease_token_hash = ? AND status = 'LEASED' \
       AND lease_expires_at > UTC_TIMESTAMP(6)";
const OUTBOX_LOCK_LEASED_SQL: &str = "SELECT org_event_id, event_id, tenant_id, event_kind, \
     operation_id, payload_json, status, attempts FROM org_scope_outbox \
     WHERE org_event_id = ? AND status = 'LEASED' AND lease_owner = ? \
       AND lease_token_hash = ? AND lease_expires_at > UTC_TIMESTAMP(6) FOR UPDATE";
const OUTBOX_FAIL_RETRY_SQL: &str = "UPDATE org_scope_outbox SET status = 'PENDING', \
     next_attempt_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP(6)), \
     lease_owner = NULL, lease_token_hash = NULL, lease_expires_at = NULL, \
     cas_version = cas_version + 1, last_error = ? \
     WHERE org_event_id = ? AND status = 'LEASED' AND lease_owner = ? \
       AND lease_token_hash = ? AND lease_expires_at > UTC_TIMESTAMP(6)";
const OUTBOX_FAIL_TERMINAL_SQL: &str = "UPDATE org_scope_outbox SET status = 'FAILED', \
     next_attempt_at = NULL, lease_owner = NULL, lease_token_hash = NULL, lease_expires_at = NULL, \
     cas_version = cas_version + 1, last_error = ? \
     WHERE org_event_id = ? AND status = 'LEASED' AND lease_owner = ? \
       AND lease_token_hash = ? AND lease_expires_at > UTC_TIMESTAMP(6)";
/// publication 驱动路径的事件终态：租约谓词（owner + token 摘要 + 未过期）+
/// 精确 event_kind 条件在单条 UPDATE 内原子生效（kind 由锁定行分类后回绑，
/// 防御性复断言，与 `OUTBOX_COMPLETE_KIND_SCOPED_SQL` 同型）。
const OUTBOX_COMPLETE_SQL: &str = "UPDATE org_scope_outbox SET status = 'DONE', \
     lease_owner = NULL, lease_token_hash = NULL, lease_expires_at = NULL, \
     cas_version = cas_version + 1 WHERE org_event_id = ? AND status = 'LEASED' \
       AND lease_owner = ? AND lease_token_hash = ? \
       AND lease_expires_at > UTC_TIMESTAMP(6) AND event_kind = ?";

/// 传播租约锁：在锚点/子节点锁定**之前**先锁定并校验 leased 事件行
/// （status/owner/token 摘要/未过期 + 精确 SUBTREE_PROPAGATE kind）。
const OUTBOX_LOCK_LEASED_FOR_PROPAGATE_SQL: &str = "SELECT org_event_id, event_id, tenant_id, \
     event_kind, operation_id, payload_json, status, attempts FROM org_scope_outbox \
     WHERE org_event_id = ? AND status = 'LEASED' AND lease_owner = ? \
       AND lease_token_hash = ? AND lease_expires_at > UTC_TIMESTAMP(6) \
       AND event_kind = ? FOR UPDATE";
const OUTBOX_LOCK_LEASED_FOR_DEPENDENCY_SQL: &str = "SELECT org_event_id, event_id, tenant_id, \
     event_kind, operation_id, payload_json, status, attempts FROM org_scope_outbox \
     WHERE org_event_id = ? AND status = 'LEASED' AND lease_owner = ? \
       AND lease_token_hash = ? AND lease_expires_at > UTC_TIMESTAMP(6) \
       AND event_kind = ? FOR UPDATE";

/// kind 限定无发布完成：租约谓词与精确 event_kind 在单条 UPDATE 内原子生效
/// （清租约 + CAS 单调 + DONE）。category-1/未知种类在任何 DB 写之前已被
/// 纯校验拒绝。
const OUTBOX_COMPLETE_KIND_SCOPED_SQL: &str = "UPDATE org_scope_outbox SET status = 'DONE', \
     lease_owner = NULL, lease_token_hash = NULL, lease_expires_at = NULL, \
     cas_version = cas_version + 1 WHERE org_event_id = ? AND status = 'LEASED' \
       AND lease_owner = ? AND lease_token_hash = ? \
       AND lease_expires_at > UTC_TIMESTAMP(6) AND event_kind = ?";

const CURRENT_SELECT_SQL: &str = "SELECT publication_id, generation, manifest_digest, \
     revoke_fence, cas_version FROM org_scope_current WHERE tenant_id = ?";
const PUBLICATION_SELECT_SQL: &str = "SELECT publication_id, tenant_id, root_tenant_id, \
     generation, relationship_revision, revoke_fence, dependencies_json, manifest_digest, \
     compiler_version, segment_count, status, operation_id FROM org_scope_publication \
     WHERE publication_id = ?";
const SEGMENT_SELECT_SQL: &str = "SELECT segment_index, segment_digest, content_json \
     FROM org_scope_segment WHERE publication_id = ? ORDER BY segment_index";
const MASKS_SELECT_SQL: &str = "SELECT mask_id, tenant_id, target_tenant_id, target_grant_id, \
     target_grant_revision, revision, active, operation_id FROM org_scope_mask \
     WHERE tenant_id = ? ORDER BY mask_id LIMIT ?";

/// 编译输入授权装载谓词：仅**当前 root 下活跃**的授权才是编译输入事实源
/// （`org_scope_grant` 是 current-row 状态，durable 历史在 `org_scope_revision`）。
/// - `root_tenant_id = 当前 node root`：跨 root MOVE/DETACH 在旧链**原地**撤销
///   后遗留的旧 root 行（`root_tenant_id` 行内不可变，见
///   `org_grant_revision_compatible`）绝不能进入新 root 编译输入——否则
///   `OrgCompileInput::validate` 的 root 绑定永久失败，后代永久 PENDING/FAILED
///   （可用性阻断）；同时防御任何残留的**active** 旧 root 行借编译输入回流。
/// - `active = 1`：inactive 墓碑不是授权事实——编译器 `resolve_unit` 跳过
///   inactive grant、`derive_ledgers` 对缺席 grant 移除账本并标 affected keys，
///   mask 与实际 contribution 的 provenance 链对账（目标缺席 = 无操作），
///   均不依赖墓碑行；墓碑只会耗尽 compile 容量预算。
///   谓词与单测 `compile_grant_loader_model_excludes_historical_rows` 的纯模型
///   过滤器逐字对应，漂移必须显式失败。
const GRANT_COMPILE_INPUT_PREDICATE_SQL: &str =
    "receiving_tenant_id = ? AND active = 1 AND root_tenant_id = ?";

const PUBLICATION_INSERT_SQL: &str = "INSERT INTO org_scope_publication \
     (tenant_id, root_tenant_id, generation, relationship_revision, revoke_fence, \
      dependencies_json, dependency_digest, manifest_digest, compiler_version, segment_count, \
      status, operation_id) \
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'SEALED', ?)";
const SEGMENT_INSERT_SQL: &str = "INSERT INTO org_scope_segment \
     (publication_id, segment_index, segment_digest, content_json) VALUES (?, ?, ?, ?)";
const DEPENDENCY_INSERT_SQL: &str = "INSERT INTO org_scope_dependency \
     (dependent_tenant_id, depends_on_tenant_id, publication_id, pinned_generation, \
      pinned_revoke_fence, pinned_relationship_revision) VALUES (?, ?, ?, ?, ?, ?)";
const CURRENT_CAS_SQL: &str = "UPDATE org_scope_current SET publication_id = ?, generation = ?, \
     manifest_digest = ?, revoke_fence = ?, cas_version = cas_version + 1, updated_at = UTC_TIMESTAMP(6) \
     WHERE tenant_id = ? AND generation < ?";
const CURRENT_INSERT_SQL: &str = "INSERT INTO org_scope_current \
     (tenant_id, publication_id, generation, manifest_digest, revoke_fence, cas_version) \
     VALUES (?, ?, ?, ?, ?, 1)";

/// 扇出批选择：锚点的**直接** active 子节点中，尚未以本操作 id 落过 NODE
/// revision 账的（`org_scope_revision` 存在性 = durable 幂等标记）。**不依赖**
/// root 不等或 `last_operation_id`：同 root MOVE 一样推进锚点关系代次，其后代
/// 的 flatten 依赖钉同样陈旧，必须被失效/重编译——root 已等于目标的后代也
/// 必须被选中一次；重试时凭账存在性跳过，绝不重复扇出。升序、锁内、至多
/// batch_limit 行（锚点行已先行锁定并做 revision/root 栅栏）。
const SUBTREE_SELECT_PROPAGATION_CHILDREN_SQL: &str = "SELECT n.tenant_id, n.parent_tenant_id, \
     n.root_tenant_id FROM org_scope_node n WHERE n.parent_tenant_id = ? AND n.active = 1 \
       AND NOT EXISTS (SELECT 1 FROM org_scope_revision r WHERE r.subject_kind = 'NODE' \
         AND r.subject_id = CAST(n.tenant_id AS CHAR) AND r.operation_id = ?) \
     ORDER BY n.tenant_id LIMIT ? FOR UPDATE";
/// 扇出批推进：root 置为目标（**即使已相同**——同 root MOVE 同样推进关系
/// 代次，使后代的 flatten 依赖钉陈旧、必须重编译），generation /
/// relationship_revision / revoke_fence **三者同步 +1**——与 source 级
/// NODE_ATTACH/MOVE/DETACH 同一合同（任何关系失效都同步推进三计数；与
/// `advance_node_in_tx` 的"同步推进保持 `revoke_fence ≤ generation` 不变式"
/// 一致）。传播式失效绝不拆散该耦合：决策见 `propagate_subtree_root` 文档
/// 与单测 `propagated_topology_update_advances_all_three_counters`。
/// 子节点行已在选择语句中 FOR UPDATE 锁定；affected != 1 只可能是异常状态。
const SUBTREE_UPDATE_SQL: &str = "UPDATE org_scope_node SET root_tenant_id = ?, \
     relationship_revision = relationship_revision + 1, revoke_fence = revoke_fence + 1, \
     generation = generation + 1, last_operation_id = ? WHERE tenant_id = ?";

/// The current publication pin and direct parent edge jointly identify the
/// dependent that must be invalidated. Historical dependency rows are excluded.
const DEPENDENCY_PROPAGATION_CANDIDATE_SQL: &str = "SELECT n.tenant_id FROM org_scope_node n \
     JOIN org_scope_current c ON c.tenant_id = n.tenant_id \
     JOIN org_scope_dependency d ON d.dependent_tenant_id = n.tenant_id \
       AND d.publication_id = c.publication_id AND d.depends_on_tenant_id = ? \
     WHERE n.parent_tenant_id = ? AND n.active = 1 \
       AND (d.pinned_generation <> ? OR d.pinned_revoke_fence <> ? \
            OR d.pinned_relationship_revision <> ?) \
       AND NOT EXISTS (SELECT 1 FROM org_scope_outbox o WHERE o.tenant_id = n.tenant_id \
         AND o.operation_id = ? AND o.event_kind IN ('DEPENDENCY_PROPAGATE', 'SUBTREE_PROPAGATE')) \
     ORDER BY n.tenant_id LIMIT ?";
const DEPENDENCY_PROPAGATION_CHILD_SQL: &str = "SELECT n.tenant_id FROM org_scope_node n \
     JOIN org_scope_current c ON c.tenant_id = n.tenant_id \
     JOIN org_scope_dependency d ON d.dependent_tenant_id = n.tenant_id \
       AND d.publication_id = c.publication_id AND d.depends_on_tenant_id = ? \
     WHERE n.parent_tenant_id = ? AND n.active = 1 \
       AND (d.pinned_generation <> ? OR d.pinned_revoke_fence <> ? \
            OR d.pinned_relationship_revision <> ?) \
       AND NOT EXISTS (SELECT 1 FROM org_scope_outbox o WHERE o.tenant_id = n.tenant_id \
         AND o.operation_id = ? AND o.event_kind IN ('DEPENDENCY_PROPAGATE', 'SUBTREE_PROPAGATE')) \
     ORDER BY n.tenant_id LIMIT ? FOR UPDATE";
const DEPENDENCY_PROPAGATION_DRAIN_SQL: &str = "SELECT n.tenant_id FROM org_scope_node n \
     JOIN org_scope_current c ON c.tenant_id = n.tenant_id \
     JOIN org_scope_dependency d ON d.dependent_tenant_id = n.tenant_id \
       AND d.publication_id = c.publication_id AND d.depends_on_tenant_id = ? \
     WHERE n.parent_tenant_id = ? AND n.active = 1 \
       AND (d.pinned_generation <> ? OR d.pinned_revoke_fence <> ? \
            OR d.pinned_relationship_revision <> ?) \
       AND NOT EXISTS (SELECT 1 FROM org_scope_outbox o WHERE o.tenant_id = n.tenant_id \
         AND o.operation_id = ? AND o.event_kind IN ('DEPENDENCY_PROPAGATE', 'SUBTREE_PROPAGATE')) \
     ORDER BY n.tenant_id LIMIT 1";
const DEPENDENCY_ADVANCE_SQL: &str = "UPDATE org_scope_node SET generation = generation + 1, \
     last_operation_id = ? WHERE tenant_id = ?";
const DEPENDENCY_SUPERSEDED_INTENT_SQL: &str = "SELECT org_event_id FROM org_scope_outbox \
     WHERE tenant_id = ? AND org_event_id > ? AND status <> 'FAILED' \
       AND ((event_kind = 'DEPENDENCY_PROPAGATE' \
             AND CAST(JSON_UNQUOTE(JSON_EXTRACT(payload_json, '$.generation')) AS UNSIGNED) >= ? \
             AND CAST(JSON_UNQUOTE(JSON_EXTRACT(payload_json, '$.root_tenant_id')) AS UNSIGNED) = ?) \
            OR (event_kind = 'SUBTREE_PROPAGATE' \
             AND CAST(JSON_UNQUOTE(JSON_EXTRACT(payload_json, '$.relationship_revision')) AS UNSIGNED) >= ? \
             AND CAST(JSON_UNQUOTE(JSON_EXTRACT(payload_json, '$.new_root_tenant_id')) AS UNSIGNED) = ?)) \
     ORDER BY org_event_id DESC LIMIT 1";
const SUBTREE_SUPERSEDED_INTENT_SQL: &str = "SELECT org_event_id FROM org_scope_outbox \
     WHERE tenant_id = ? AND org_event_id > ? AND status <> 'FAILED' \
       AND event_kind = 'SUBTREE_PROPAGATE' \
       AND CAST(JSON_UNQUOTE(JSON_EXTRACT(payload_json, '$.relationship_revision')) AS UNSIGNED) >= ? \
       AND CAST(JSON_UNQUOTE(JSON_EXTRACT(payload_json, '$.new_root_tenant_id')) AS UNSIGNED) = ? \
     ORDER BY org_event_id DESC LIMIT 1";

// ─────────────────────────────────────────────────────────────────────────────
// kind 封闭派发与意图绑定（纯函数；DB 写入之前生效）
// ─────────────────────────────────────────────────────────────────────────────

/// kind 限定无发布完成的稳定机码（category-1/未知种类在任何 DB 写前拒绝）。
const ORG_OUTBOX_COMPLETE_KIND_FORBIDDEN_CODE: &str =
    "code=org_scope.outbox_complete_kind_forbidden";
/// 行内 event_kind 与 expected_kind 不一致的稳定机码（绝不静默消费错种类）。
const ORG_OUTBOX_COMPLETE_KIND_MISMATCH_CODE: &str = "code=org_scope.outbox_complete_kind_mismatch";
/// publication 驱动路径遭遇非投影种类的稳定机码（membership/subtree 意图
/// 试图 publish）。
const ORG_PUBLISH_KIND_FORBIDDEN_CODE: &str = "code=org_scope.publish_kind_forbidden";
/// 行内 event_kind 不属于 10 类一等种类（未知/损坏）的稳定机码。
const ORG_OUTBOX_EVENT_KIND_UNKNOWN_CODE: &str = "code=org_scope.outbox_event_kind_unknown";
/// 传播入口 kind 预检失败（expected_kind != SUBTREE_PROPAGATE）。
const ORG_PROPAGATE_EVENT_KIND_INVALID_CODE: &str = "code=org_scope.propagate_event_kind_invalid";
/// 意图绑定：载荷 child 与事件租户不一致。
const ORG_PROPAGATE_INTENT_TENANT_MISMATCH_CODE: &str =
    "code=org_scope.propagate_intent_tenant_mismatch";
/// 意图绑定：命令 operation_id 与事件行不一致。
const ORG_PROPAGATE_INTENT_OPERATION_MISMATCH_CODE: &str =
    "code=org_scope.propagate_intent_operation_mismatch";
/// 意图绑定：命令目标 root 与载荷不一致。
const ORG_PROPAGATE_INTENT_ROOT_MISMATCH_CODE: &str =
    "code=org_scope.propagate_intent_root_mismatch";
/// 意图 revision 栅栏：锚点 revision 小于载荷 revision（损坏/乱序，fail-closed）。
const ORG_PROPAGATE_INTENT_REVISION_REGRESSION_CODE: &str =
    "code=org_scope.propagate_intent_revision_regression";
/// frontier 绑定失败（必须恰为 `[载荷 child_tenant_id]`）。
const ORG_PROPAGATE_FRONTIER_INVALID_CODE: &str = "code=org_scope.propagate_frontier_invalid";
/// 锚点 inactive（损坏/冻结态，fail-closed）。
const ORG_PROPAGATE_ANCHOR_INACTIVE_CODE: &str = "code=org_scope.propagate_anchor_inactive";
/// Current 关系下锚点 root 与目标 root 不一致（equal revision 下不可能；防御性
/// fail-closed）。
const ORG_PROPAGATE_ANCHOR_ROOT_MISMATCH_CODE: &str =
    "code=org_scope.propagate_anchor_root_mismatch";
/// SUBTREE 无发布完成的传播收敛证明失败：锚点仍存在"未以本操作 id 标记"的
/// 直接 active 子节点（DONE 前必须由传播批排空，或意图已被取代）。
const ORG_COMPLETE_PROPAGATION_INCOMPLETE_CODE: &str =
    "code=org_scope.complete_propagation_incomplete";
/// SUBTREE 无发布完成的目标 root 绑定失败：Current 关系下锚点 root 与载荷
/// 目标 root 不一致（畸形/陈旧目标意图，绝不因"无未标记子节点"而放行）。
const ORG_COMPLETE_PROPAGATION_ROOT_MISMATCH_CODE: &str =
    "code=org_scope.complete_propagation_root_mismatch";
/// 无发布完成的载荷 operation 绑定失败：MEMBERSHIP_CHANGED 载荷 operation_id
/// 与事件行 operation_id 不一致（载荷与事件行由同一 source mutation 写入，
/// 漂移即损坏/伪造，fail-closed）。
const ORG_COMPLETE_PAYLOAD_OPERATION_MISMATCH_CODE: &str =
    "code=org_scope.complete_payload_operation_mismatch";
const ORG_DEPENDENCY_PROPAGATE_KIND_INVALID_CODE: &str =
    "code=org_scope.dependency_propagate_kind_invalid";
const ORG_DEPENDENCY_PROPAGATE_INTENT_INVALID_CODE: &str =
    "code=org_scope.dependency_propagate_intent_invalid";
const ORG_DEPENDENCY_PROPAGATE_INTENT_TENANT_MISMATCH_CODE: &str =
    "code=org_scope.dependency_propagate_intent_tenant_mismatch";
const ORG_DEPENDENCY_PROPAGATE_INTENT_OPERATION_MISMATCH_CODE: &str =
    "code=org_scope.dependency_propagate_intent_operation_mismatch";
const ORG_DEPENDENCY_PROPAGATE_INTENT_HEAD_MISMATCH_CODE: &str =
    "code=org_scope.dependency_propagate_intent_head_mismatch";
const ORG_DEPENDENCY_PROPAGATE_ANCHOR_INACTIVE_CODE: &str =
    "code=org_scope.dependency_propagate_anchor_inactive";
const ORG_DEPENDENCY_PROPAGATE_SUPERSESSION_UNPROVEN_CODE: &str =
    "code=org_scope.dependency_propagate_supersession_unproven";
const ORG_PROPAGATE_SUPERSESSION_UNPROVEN_CODE: &str =
    "code=org_scope.propagate_supersession_unproven";
const ORG_DEPENDENCY_PROPAGATE_ANCHOR_PUBLICATION_STALE_CODE: &str =
    "code=org_scope.dependency_propagate_anchor_publication_stale";
const ORG_DEPENDENCY_PROPAGATE_INCOMPLETE_CODE: &str =
    "code=org_scope.dependency_propagate_incomplete";

pub(crate) fn validated_completion_kind(kind: OrgOutboxEventKind) -> Result<(), AstralError> {
    if kind.allows_publication_free_completion() {
        Ok(())
    } else {
        Err(AstralError::Validation(format!(
            "{ORG_OUTBOX_COMPLETE_KIND_FORBIDDEN_CODE};event_kind={}",
            kind.as_str()
        )))
    }
}

/// 传播入口 kind 预检（纯函数）：本原语只消费 SUBTREE_PROPAGATE intent。
fn validated_propagation_kind(kind: OrgOutboxEventKind) -> Result<(), AstralError> {
    if kind == OrgOutboxEventKind::SubtreePropagate {
        Ok(())
    } else {
        Err(AstralError::Validation(format!(
            "{ORG_PROPAGATE_EVENT_KIND_INVALID_CODE};expected_kind={}",
            kind.as_str()
        )))
    }
}

/// 行内 event_kind 的 **publication 驱动**分类器（纯函数）：仅 7 个 category-1
/// 投影必需种类可装载编译输入并经 `complete_publish` 消费；
/// MEMBERSHIP_CHANGED / SUBTREE_PROPAGATE 属"无发布完成"路径（拒绝），未知
/// 种类确定性拒绝（projector 随后有限次 fail，绝不 publish）。与
/// `allows_publication_free_completion` 严格互补：10 类二元划分，无重叠无遗漏。
fn publication_required_kind(row_event_kind: &str) -> Result<OrgOutboxEventKind, AstralError> {
    let kind: OrgOutboxEventKind = row_event_kind.parse().map_err(|_| {
        AstralError::Validation(format!(
            "{ORG_OUTBOX_EVENT_KIND_UNKNOWN_CODE};event_kind={row_event_kind}"
        ))
    })?;
    if kind.allows_publication_free_completion() {
        return Err(AstralError::Validation(format!(
            "{ORG_PUBLISH_KIND_FORBIDDEN_CODE};event_kind={}",
            kind.as_str()
        )));
    }
    Ok(kind)
}

fn validated_dependency_propagation_kind(kind: OrgOutboxEventKind) -> Result<(), AstralError> {
    if kind == OrgOutboxEventKind::DependencyPropagate {
        Ok(())
    } else {
        Err(AstralError::Validation(format!(
            "{ORG_DEPENDENCY_PROPAGATE_KIND_INVALID_CODE};expected_kind={}",
            OrgOutboxEventKind::DependencyPropagate.as_str()
        )))
    }
}

fn validated_dependency_payload(
    event_tenant_id: i64,
    payload_json: &str,
) -> Result<OrgDependencyPropagatePayload, AstralError> {
    let payload: OrgDependencyPropagatePayload =
        serde_json::from_str(payload_json).map_err(|error| {
            AstralError::Database(format!(
                "{ORG_DEPENDENCY_PROPAGATE_INTENT_INVALID_CODE};detail={error}"
            ))
        })?;
    payload.validate().map_err(org_err)?;
    if payload.anchor_tenant_id != event_tenant_id {
        return Err(AstralError::Validation(format!(
            "{ORG_DEPENDENCY_PROPAGATE_INTENT_TENANT_MISMATCH_CODE};payload_anchor={};event_tenant={event_tenant_id}",
            payload.anchor_tenant_id
        )));
    }
    Ok(payload)
}

fn validated_dependency_intent(
    event_tenant_id: i64,
    event_operation_id: &str,
    payload_json: &str,
    cmd_operation_id: &str,
    cmd_anchor_tenant_id: i64,
) -> Result<OrgDependencyPropagatePayload, AstralError> {
    let payload = validated_dependency_payload(event_tenant_id, payload_json)?;
    if event_operation_id != cmd_operation_id {
        return Err(AstralError::Validation(format!(
            "{ORG_DEPENDENCY_PROPAGATE_INTENT_OPERATION_MISMATCH_CODE};cmd={cmd_operation_id};event={event_operation_id}"
        )));
    }
    if payload.anchor_tenant_id != cmd_anchor_tenant_id {
        return Err(AstralError::Validation(format!(
            "{ORG_DEPENDENCY_PROPAGATE_INTENT_TENANT_MISMATCH_CODE};cmd_anchor={cmd_anchor_tenant_id};payload_anchor={}",
            payload.anchor_tenant_id
        )));
    }
    Ok(payload)
}

/// SUBTREE 载荷门（纯函数；传播绑定与无发布完成共用）：租约行内存储载荷必须
/// 是 typed `OrgSubtreePropagatePayload`、通过类型合同校验，且
/// `child_tenant_id == 事件租户`（跨租户意图一律拒绝）。
fn validated_propagation_payload(
    event_tenant_id: i64,
    payload_json: &str,
) -> Result<OrgSubtreePropagatePayload, AstralError> {
    let payload: OrgSubtreePropagatePayload =
        serde_json::from_str(payload_json).map_err(|error| {
            AstralError::Database(format!(
                "code=org_scope.propagate_payload_unreadable;detail={error}"
            ))
        })?;
    payload.validate().map_err(org_err)?;
    if payload.child_tenant_id != event_tenant_id {
        return Err(AstralError::Validation(format!(
            "{ORG_PROPAGATE_INTENT_TENANT_MISMATCH_CODE};payload_child={};event_tenant={event_tenant_id}",
            payload.child_tenant_id
        )));
    }
    Ok(payload)
}

/// 意图绑定（纯函数）：把租约内事件行的 durable 事实与命令语义逐项绑定。
/// 任一不一致即 Err（fail-closed，事务回滚、事件保持 LEASED 交由 worker 登记），
/// 绝不以漂移的命令语义写后代。
fn validated_propagation_intent(
    event_tenant_id: i64,
    event_operation_id: &str,
    payload_json: &str,
    cmd_operation_id: &str,
    cmd_new_root_tenant_id: i64,
) -> Result<OrgSubtreePropagatePayload, AstralError> {
    let payload = validated_propagation_payload(event_tenant_id, payload_json)?;
    if cmd_operation_id != event_operation_id {
        return Err(AstralError::Validation(format!(
            "{ORG_PROPAGATE_INTENT_OPERATION_MISMATCH_CODE};cmd={cmd_operation_id};event={event_operation_id}"
        )));
    }
    if cmd_new_root_tenant_id != payload.new_root_tenant_id {
        return Err(AstralError::Validation(format!(
            "{ORG_PROPAGATE_INTENT_ROOT_MISMATCH_CODE};cmd_root={cmd_new_root_tenant_id};payload_root={}",
            payload.new_root_tenant_id
        )));
    }
    Ok(payload)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompletionPropagationPayload {
    Subtree(OrgSubtreePropagatePayload),
    Dependency(OrgDependencyPropagatePayload),
}

/// 无发布完成的载荷门（DONE 之前的最后防线）：租约行内存储载荷必须
/// 与 event_kind 同构、通过类型合同校验，且租户/操作绑定一致。
fn validated_completion_payload(
    kind: OrgOutboxEventKind,
    event_tenant_id: i64,
    event_operation_id: &str,
    payload_json: &str,
) -> Result<Option<CompletionPropagationPayload>, AstralError> {
    match kind {
        OrgOutboxEventKind::MembershipChanged => {
            let membership: OrgMembership =
                serde_json::from_str(payload_json).map_err(|error| {
                    AstralError::Database(format!(
                        "code=org_scope.complete_payload_unreadable;event_kind={};detail={error}",
                        kind.as_str()
                    ))
                })?;
            membership.validate().map_err(org_err)?;
            if membership.tenant_id != event_tenant_id {
                return Err(AstralError::Validation(format!(
                    "code=org_scope.complete_payload_tenant_mismatch;payload_tenant={};event_tenant={event_tenant_id}",
                    membership.tenant_id
                )));
            }
            if membership.operation_id != event_operation_id {
                return Err(AstralError::Validation(format!(
                    "{ORG_COMPLETE_PAYLOAD_OPERATION_MISMATCH_CODE};payload_op={};event_op={event_operation_id}",
                    membership.operation_id
                )));
            }
            Ok(None)
        }
        OrgOutboxEventKind::SubtreePropagate => Ok(Some(CompletionPropagationPayload::Subtree(
            validated_propagation_payload(event_tenant_id, payload_json)?,
        ))),
        OrgOutboxEventKind::DependencyPropagate => {
            Ok(Some(CompletionPropagationPayload::Dependency(
                validated_dependency_payload(event_tenant_id, payload_json)?,
            )))
        }
        // 白名单校验（任何 DB 访问之前）保证只会是上述三种；此臂仅兜底。
        _ => Err(AstralError::Validation(
            ORG_OUTBOX_COMPLETE_KIND_FORBIDDEN_CODE.to_owned(),
        )),
    }
}

/// frontier 绑定（纯函数）：命令 frontier 必须**恰为** `[载荷 child_tenant_id]`
/// （durable 锚点重入）。空/多元素/异值一律拒绝——防止持有效租约的调用方把
/// 传播重定向到无关租户。
fn validated_propagation_frontier(
    frontier: &[i64],
    anchor_tenant_id: i64,
) -> Result<(), AstralError> {
    if frontier.len() == 1 && frontier[0] == anchor_tenant_id {
        Ok(())
    } else {
        Err(AstralError::Validation(format!(
            "{ORG_PROPAGATE_FRONTIER_INVALID_CODE};expected=[{anchor_tenant_id}];len={}",
            frontier.len()
        )))
    }
}

/// 意图 revision 栅栏（纯函数）：
/// - 锚点 revision == 载荷 revision → `false`（Current：锚点仍是意图所写状态，
///   允许按批推进）；
/// - 锚点 revision **>** 载荷 revision → `true`（Superseded：更新的拓扑 source
///   变更已推进锚点并必然已入队自己的 intent——source 变更事务结构性保证；
///   本意图无写安全放行，绝不以旧意图写后代，也绝不无限重试）；
/// - 锚点 revision **<** 载荷 revision → Err（损坏/乱序，fail-closed）。
fn propagation_intent_revision_fence(
    intent_revision: u64,
    anchor_revision: u64,
) -> Result<bool, AstralError> {
    if anchor_revision == intent_revision {
        Ok(false)
    } else if anchor_revision > intent_revision {
        Ok(true)
    } else {
        Err(AstralError::Validation(format!(
            "{ORG_PROPAGATE_INTENT_REVISION_REGRESSION_CODE};intent={intent_revision};anchor={anchor_revision}"
        )))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 租约原语
// ─────────────────────────────────────────────────────────────────────────────

/// claim 侧预算收敛判定（纯函数）：候选事件 attempts 已达预算 → 终态化而非
/// 认领。与 `fail_outbox_event` 的重试判定（`retryable && attempts <
/// max_attempts` 才退避重试）严格互补：同一预算值下，认领侧不会把 fail 侧
/// 仍会重试的事件提前终态化，预算耗尽后 crash-reclaim 也不再累加 attempts。
fn claim_attempts_budget_exhausted(candidate_attempts: i64, max_attempts: i64) -> bool {
    candidate_attempts >= max_attempts
}

/// fail 侧退避预检（纯函数）：负值 `backoff_seconds` 会把 durable
/// `next_attempt_at` 调度到过去（TIMESTAMPADD 负偏移），把退避语义退化为
/// 立即回收热循环；在任何 durable 调度写之前 fail-closed。
fn validated_fail_backoff_seconds(backoff_seconds: i64) -> Result<(), AstralError> {
    if backoff_seconds < 0 {
        return Err(AstralError::Validation(
            "code=org_scope.invalid_backoff_seconds".into(),
        ));
    }
    Ok(())
}

pub(crate) async fn claim_outbox_event(
    store: &SqlxOrgScopeRepository,
    cmd: &OrgOutboxClaimCommand,
) -> Result<Option<OrgOutboxLease>, AstralError> {
    positive_i64(cmd.tenant_id, "tenant_id")?;
    validated_lease_owner(&cmd.worker_owner)?;
    let token_hash = worker_token_hash(&decode_worker_token(&cmd.worker_token_hex)?);
    if cmd.lease_seconds <= 0 || cmd.lease_seconds > 3600 {
        return Err(AstralError::Validation(
            "code=org_scope.invalid_lease_seconds".into(),
        ));
    }
    positive_i64(cmd.max_attempts, "max_attempts")?;
    let mut tx = begin_tx(store.pool()).await?;
    let candidate = sqlx::query(OUTBOX_CLAIM_CANDIDATE_SQL)
        .bind(cmd.tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?;
    let Some(candidate) = candidate else {
        tx.commit().await.map_err(db_err)?;
        return Ok(None);
    };
    let org_event_id: i64 = candidate.try_get("org_event_id").map_err(db_err)?;
    // claim 侧预算收敛：候选事件 attempts 已达预算（典型成因是 worker 在
    // claim 之后、fail_outbox_event 之前崩溃，过期租约被反复回收）时不再
    // 认领，而是在本事务内直接落终态 FAILED 并返回 Ok(None)。事件由此永久
    // 退出队列，认领次数有界，绝不静默丢弃（durable FAILED + 机码可对账）。
    let candidate_attempts: i64 = candidate.try_get("attempts").map_err(db_err)?;
    if claim_attempts_budget_exhausted(candidate_attempts, cmd.max_attempts) {
        let event_id: String = candidate.try_get("event_id").map_err(db_err)?;
        let operation_id: String = candidate.try_get("operation_id").map_err(db_err)?;
        let previous_owner: Option<String> = candidate.try_get("lease_owner").map_err(db_err)?;
        let last_error = truncate_error(&format!(
            "{ORG_OUTBOX_CLAIM_BUDGET_EXHAUSTED_CODE};event_id={event_id};\
             operation_id={operation_id};attempts={candidate_attempts};max_attempts={}",
            cmd.max_attempts
        ));
        let exhaust = sqlx::query(OUTBOX_CLAIM_EXHAUST_SQL)
            .bind(&last_error)
            .bind(org_event_id)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        require_affected_one(&exhaust, "outbox_claim_exhaust_lost_race")?;
        tx.commit().await.map_err(db_err)?;
        tracing::warn!(
            tenant_id = cmd.tenant_id,
            org_event_id,
            event_id = %event_id,
            operation_id = %operation_id,
            attempts = candidate_attempts,
            max_attempts = cmd.max_attempts,
            previous_lease_owner = previous_owner.as_deref().unwrap_or(""),
            "org scope outbox event exhausted its claim attempt budget without a \
             worker failure record (crash after claim); terminalized to FAILED in \
             the claim transaction so reclaim cycles cannot grow attempts forever"
        );
        return Ok(None);
    }
    let install = sqlx::query(OUTBOX_CLAIM_INSTALL_SQL)
        .bind(&cmd.worker_owner)
        .bind(&token_hash)
        .bind(cmd.lease_seconds)
        .bind(org_event_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    require_affected_one(&install, "outbox_claim_lost_race")?;
    // 权威回读：租约到期时间与 attempt 计数来自本事务持久值。
    let readback = sqlx::query(
        "SELECT event_id, tenant_id, event_kind, operation_id, payload_json, attempts, \
         cas_version, CAST(UNIX_TIMESTAMP(lease_expires_at) AS SIGNED) as lease_expires_at_unix \
         FROM org_scope_outbox WHERE org_event_id = ?",
    )
    .bind(org_event_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;
    Ok(Some(OrgOutboxLease {
        org_event_id,
        event_id: readback.try_get("event_id").map_err(db_err)?,
        tenant_id: readback.try_get("tenant_id").map_err(db_err)?,
        event_kind: readback.try_get("event_kind").map_err(db_err)?,
        operation_id: readback.try_get("operation_id").map_err(db_err)?,
        payload_json: readback.try_get("payload_json").map_err(db_err)?,
        attempts: readback.try_get("attempts").map_err(db_err)?,
        cas_version: row_generation(
            readback.try_get("cas_version").map_err(db_err)?,
            "cas_version",
        )?,
        lease_expires_at_unix: readback
            .try_get::<Option<i64>, _>("lease_expires_at_unix")
            .map_err(db_err)?
            .unwrap_or(0),
    }))
}

pub(crate) async fn renew_outbox_lease(
    store: &SqlxOrgScopeRepository,
    cmd: &OrgOutboxRenewCommand,
) -> Result<bool, AstralError> {
    positive_i64(cmd.org_event_id, "org_event_id")?;
    validated_lease_owner(&cmd.worker_owner)?;
    let token_hash = worker_token_hash(&decode_worker_token(&cmd.worker_token_hex)?);
    if cmd.lease_seconds <= 0 || cmd.lease_seconds > 3600 {
        return Err(AstralError::Validation(
            "code=org_scope.invalid_lease_seconds".into(),
        ));
    }
    let result = sqlx::query(OUTBOX_RENEW_SQL)
        .bind(cmd.lease_seconds)
        .bind(cmd.org_event_id)
        .bind(&cmd.worker_owner)
        .bind(&token_hash)
        .execute(store.pool())
        .await
        .map_err(db_err)?;
    Ok(result.rows_affected() == 1)
}

pub(crate) async fn fail_outbox_event(
    store: &SqlxOrgScopeRepository,
    cmd: &OrgOutboxFailCommand,
) -> Result<OrgOutboxFailOutcome, AstralError> {
    positive_i64(cmd.org_event_id, "org_event_id")?;
    validated_lease_owner(&cmd.worker_owner)?;
    let token_hash = worker_token_hash(&decode_worker_token(&cmd.worker_token_hex)?);
    // 退避预检先于任何 durable 调度写（负值会让 next_attempt_at 落在过去）。
    validated_fail_backoff_seconds(cmd.backoff_seconds)?;
    let last_error = truncate_error(&cmd.error);
    let mut tx = begin_tx(store.pool()).await?;
    let leased = sqlx::query(OUTBOX_LOCK_LEASED_SQL)
        .bind(cmd.org_event_id)
        .bind(&cmd.worker_owner)
        .bind(&token_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?;
    let Some(leased) = leased else {
        return Err(AstralError::Validation(
            "code=org_scope.outbox_lease_lost".into(),
        ));
    };
    let attempts: i64 = leased.try_get("attempts").map_err(db_err)?;
    let outcome = if cmd.retryable && attempts < cmd.max_attempts {
        let result = sqlx::query(OUTBOX_FAIL_RETRY_SQL)
            .bind(cmd.backoff_seconds)
            .bind(&last_error)
            .bind(cmd.org_event_id)
            .bind(&cmd.worker_owner)
            .bind(&token_hash)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        require_affected_one(&result, "outbox_fail_lease_lost")?;
        OrgOutboxFailOutcome {
            status: "PENDING".into(),
            attempts,
        }
    } else {
        let result = sqlx::query(OUTBOX_FAIL_TERMINAL_SQL)
            .bind(&last_error)
            .bind(cmd.org_event_id)
            .bind(&cmd.worker_owner)
            .bind(&token_hash)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        require_affected_one(&result, "outbox_fail_lease_lost")?;
        OrgOutboxFailOutcome {
            status: "FAILED".into(),
            attempts,
        }
    };
    tx.commit().await.map_err(db_err)?;
    Ok(outcome)
}

// ─────────────────────────────────────────────────────────────────────────────
// kind 限定"无发布完成"（MEMBERSHIP_CHANGED / SUBTREE_PROPAGATE 专用）
// ─────────────────────────────────────────────────────────────────────────────

/// 租约内**无发布完成**：原子要求 LEASED owner + token 摘要 + 未过期租约 +
/// 精确 expected event kind；清租约字段、CAS 单调 +1、置 DONE。不产生
/// publication、source mutation 或新审计写——消费完成本身以 outbox 行的
/// status/cas_version/attempts 为可追溯证据。category-1/未知种类在任何 DB
/// 访问之前被 [`validated_completion_kind`] 拒绝；行内 event_kind 与
/// expected_kind 不一致同样拒绝；租约丢失（含对已 DONE 事件的重复完成）
/// 一律 `code=org_scope.outbox_lease_lost`，绝不静默成功。
///
/// 载荷与意图防线（DONE 之前）：行内存储载荷必须与 event_kind 同构、通过
/// 类型合同校验且租户/操作绑定一致（MEMBERSHIP_CHANGED → typed
/// `OrgMembership` + `membership.tenant_id == 事件租户` + 载荷 operation_id
/// 绑定事件行 operation_id；SUBTREE_PROPAGATE → typed
/// `OrgSubtreePropagatePayload` + `child_tenant_id == 事件租户`）。SUBTREE 另
/// 要求 **durable 传播收敛证明**：锁锚点并复用意图 revision 栅栏——Current
/// 关系下锚点 root 必须精确等于载荷目标 root（畸形/陈旧目标意图绝不因
/// "无未标记子节点"而放行），且锚点必须已无"未以本操作 id 标记"的直接
/// active 子节点（与传播批 done 语义同一谓词），否则
/// `code=org_scope.complete_propagation_incomplete` /
/// `code=org_scope.complete_propagation_root_mismatch`；
/// Superseded（锚点 revision 前进，更新 intent 必然入队）免证明安全完成；
/// revision 回退 fail-closed。任何防线失败即回滚、事件保持 LEASED，绝不
/// 静默完成畸形/跨租户/未收敛意图。
pub(crate) async fn complete_outbox_event(
    store: &SqlxOrgScopeRepository,
    cmd: &OrgOutboxCompleteCommand,
) -> Result<OrgOutboxCompleteOutcome, AstralError> {
    positive_i64(cmd.org_event_id, "org_event_id")?;
    validated_lease_owner(&cmd.worker_owner)?;
    let token_hash = worker_token_hash(&decode_worker_token(&cmd.worker_token_hex)?);
    // kind 白名单先于任何 DB 访问。
    validated_completion_kind(cmd.expected_kind)?;
    let mut tx = begin_tx(store.pool()).await?;
    // 租约锁（本步不带 kind 条件）：区分租约丢失与种类错配的诊断。
    let leased = sqlx::query(OUTBOX_LOCK_LEASED_SQL)
        .bind(cmd.org_event_id)
        .bind(&cmd.worker_owner)
        .bind(&token_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?
        .ok_or_else(|| AstralError::Validation("code=org_scope.outbox_lease_lost".into()))?;
    let row_kind: String = leased.try_get("event_kind").map_err(db_err)?;
    if row_kind != cmd.expected_kind.as_str() {
        return Err(AstralError::Validation(format!(
            "{ORG_OUTBOX_COMPLETE_KIND_MISMATCH_CODE};expected={};actual={row_kind}",
            cmd.expected_kind.as_str()
        )));
    }
    let event_tenant_id: i64 = leased.try_get("tenant_id").map_err(db_err)?;
    let event_operation_id: String = leased.try_get("operation_id").map_err(db_err)?;
    let payload_json: String = leased.try_get("payload_json").map_err(db_err)?;
    let attempts: i64 = leased.try_get("attempts").map_err(db_err)?;
    // 载荷门（DONE 之前的最后防线）：行内存储载荷必须与 event_kind 同构、通过
    // 类型合同校验且租户/操作绑定一致（MEMBERSHIP_CHANGED → typed OrgMembership
    // 且 membership.tenant_id == 事件租户、载荷 operation_id == 事件行
    // operation_id；SUBTREE_PROPAGATE → typed OrgSubtreePropagatePayload 且
    // child_tenant_id == 事件租户）。失败即回滚，事件保持 LEASED 交由 worker
    // 登记，绝不静默完成畸形/跨租户意图。
    let propagation_payload = validated_completion_payload(
        cmd.expected_kind,
        event_tenant_id,
        &event_operation_id,
        &payload_json,
    )?;
    if let Some(CompletionPropagationPayload::Subtree(payload)) = propagation_payload {
        // SUBTREE 完成的 durable 收敛证明：锁锚点并复用意图 revision 栅栏——
        // 锚点 revision == 载荷 revision 时（Current），锚点 root 必须精确等于
        // 载荷目标 root（与传播批同一 `ORG_PROPAGATE_ANCHOR_ROOT_MISMATCH` 语义
        // 的完成侧等价机码），且必须已无"未以本操作 id 标记"的直接 active 子
        // 节点（与传播批 done 语义同一谓词，LIMIT 1 存在性证明），否则拒绝完成
        // （`org_scope.complete_propagation_root_mismatch` /
        // `org_scope.complete_propagation_incomplete`），调用方必须先以传播批
        // 排空锚点；锚点 revision > 载荷 revision ⇒ 意图已被更新的拓扑 source
        // 变更取代（其 intent 必然已入队），免证明安全完成；更小 ⇒ fail-closed。
        // 锁序 outbox 事件 → 锚点，与传播批一致。
        let anchor = lock_node_in_tx(&mut tx, event_tenant_id)
            .await?
            .ok_or_else(|| {
                AstralError::NotFound(format!(
                    "code=org_scope.node_missing;tenant_id={event_tenant_id}"
                ))
            })?;
        if !anchor.active {
            return Err(AstralError::Validation(
                ORG_PROPAGATE_ANCHOR_INACTIVE_CODE.to_owned(),
            ));
        }
        let anchor_revision =
            row_generation(anchor.relationship_revision, "anchor.relationship_revision")?;
        let superseded =
            propagation_intent_revision_fence(payload.relationship_revision, anchor_revision)?;
        if !superseded {
            if anchor.root_tenant_id != payload.new_root_tenant_id {
                return Err(AstralError::Validation(format!(
                    "{ORG_COMPLETE_PROPAGATION_ROOT_MISMATCH_CODE};anchor_root={};payload_root={}",
                    anchor.root_tenant_id, payload.new_root_tenant_id
                )));
            }
            let unmarked = sqlx::query(SUBTREE_SELECT_PROPAGATION_CHILDREN_SQL)
                .bind(event_tenant_id)
                .bind(&event_operation_id)
                .bind(1_i64)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_err)?;
            if unmarked.is_some() {
                return Err(AstralError::Validation(
                    ORG_COMPLETE_PROPAGATION_INCOMPLETE_CODE.to_owned(),
                ));
            }
        }
    } else if let Some(CompletionPropagationPayload::Dependency(payload)) = propagation_payload {
        let anchor = lock_node_in_tx(&mut tx, event_tenant_id)
            .await?
            .ok_or_else(|| {
                AstralError::NotFound(format!(
                    "code=org_scope.node_missing;tenant_id={event_tenant_id}"
                ))
            })?;
        if !anchor.active {
            return Err(AstralError::Validation(
                ORG_DEPENDENCY_PROPAGATE_ANCHOR_INACTIVE_CODE.into(),
            ));
        }
        let anchor_generation = row_generation(anchor.generation, "anchor.generation")?;
        if anchor_generation > payload.generation {
            let anchor_relationship_revision =
                row_generation(anchor.relationship_revision, "anchor.relationship_revision")?;
            let replacement = sqlx::query(DEPENDENCY_SUPERSEDED_INTENT_SQL)
                .bind(event_tenant_id)
                .bind(cmd.org_event_id)
                .bind(anchor_generation)
                .bind(anchor.root_tenant_id)
                .bind(anchor_relationship_revision)
                .bind(anchor.root_tenant_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_err)?;
            if replacement.is_none() {
                return Err(AstralError::Validation(
                    ORG_DEPENDENCY_PROPAGATE_SUPERSESSION_UNPROVEN_CODE.into(),
                ));
            }
        } else {
            let anchor_revoke_fence = row_generation(anchor.revoke_fence, "anchor.revoke_fence")?;
            let anchor_relationship_revision =
                row_generation(anchor.relationship_revision, "anchor.relationship_revision")?;
            if anchor_generation < payload.generation
                || anchor.root_tenant_id != payload.root_tenant_id
                || anchor_revoke_fence != payload.revoke_fence
                || anchor_relationship_revision != payload.relationship_revision
            {
                return Err(AstralError::Validation(
                    ORG_DEPENDENCY_PROPAGATE_INTENT_HEAD_MISMATCH_CODE.into(),
                ));
            }
            let (dependency, publication) =
                load_ancestor_head_in_tx(&mut tx, event_tenant_id).await?;
            if !org_dependency_matches_publication(&dependency, &publication)
                || publication.generation != payload.generation
                || publication.root_tenant_id != payload.root_tenant_id
                || publication.revoke_fence != payload.revoke_fence
                || publication.relationship_revision != payload.relationship_revision
            {
                return Err(AstralError::Validation(
                    ORG_DEPENDENCY_PROPAGATE_ANCHOR_PUBLICATION_STALE_CODE.into(),
                ));
            }
            let outstanding = sqlx::query(DEPENDENCY_PROPAGATION_DRAIN_SQL)
                .bind(event_tenant_id)
                .bind(event_tenant_id)
                .bind(payload.generation)
                .bind(payload.revoke_fence)
                .bind(payload.relationship_revision)
                .bind(&event_operation_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_err)?;
            if outstanding.is_some() {
                return Err(AstralError::Validation(
                    ORG_DEPENDENCY_PROPAGATE_INCOMPLETE_CODE.into(),
                ));
            }
        }
    }
    // 终态 UPDATE 自身携带租约谓词 + 精确 kind 条件（单语句原子；行已在本
    // 事务锁定，affected != 1 只可能是异常状态，保守拒绝）。
    let complete = sqlx::query(OUTBOX_COMPLETE_KIND_SCOPED_SQL)
        .bind(cmd.org_event_id)
        .bind(&cmd.worker_owner)
        .bind(&token_hash)
        .bind(cmd.expected_kind.as_str())
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    require_affected_one(&complete, "outbox_complete_lease_lost")?;
    let cas_version: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT cas_version FROM org_scope_outbox WHERE org_event_id = ?",
    )
    .bind(cmd.org_event_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;
    Ok(OrgOutboxCompleteOutcome {
        attempts,
        cas_version: row_generation(cas_version, "outbox.cas_version")?,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// 编译输入装载（flatten 全部祖先 source head）
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) async fn load_compile_input(
    store: &SqlxOrgScopeRepository,
    cmd: &OrgCompileInputCommand,
) -> Result<OrgCompileInput, AstralError> {
    positive_i64(cmd.org_event_id, "org_event_id")?;
    validated_lease_owner(&cmd.worker_owner)?;
    let token_hash = worker_token_hash(&decode_worker_token(&cmd.worker_token_hex)?);
    let mut tx = begin_tx(store.pool()).await?;
    let event = sqlx::query(OUTBOX_LOCK_LEASED_SQL)
        .bind(cmd.org_event_id)
        .bind(&cmd.worker_owner)
        .bind(&token_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?
        .ok_or_else(|| AstralError::Validation("code=org_scope.outbox_lease_lost".into()))?;
    let row_event_kind: String = event.try_get("event_kind").map_err(db_err)?;
    // kind 封闭派发：只有 category-1 投影必需种类可装载编译输入；
    // MEMBERSHIP_CHANGED / SUBTREE_PROPAGATE / 未知种类在此确定性拒绝——
    // 内部调用方不能借编译路径消费非发布事件。
    publication_required_kind(&row_event_kind)?;
    let tenant_id: i64 = event.try_get("tenant_id").map_err(db_err)?;
    let operation_id: String = event.try_get("operation_id").map_err(db_err)?;

    let node_row = load_node_required_in_tx(&mut tx, tenant_id).await?;
    let node = typed_node(&node_row)?;
    if !node.active {
        return Err(AstralError::Validation(
            "code=org_scope.node_inactive".into(),
        ));
    }
    // `walk_ancestors_in_tx` returns [self, direct parent, ..., root]. Every
    // actual ancestor is a dependency pin; only the direct parent publication
    // is an input to contribution resolution.
    let chain = walk_ancestors_in_tx(&mut tx, tenant_id).await?;
    let direct_parent_tenant_id = node.parent_tenant_id;
    let mut heads: Vec<(OrgDependency, OrgPublication)> = Vec::new();
    for ancestor in chain.iter().skip(1) {
        let (dependency, publication) =
            load_ancestor_head_in_tx(&mut tx, ancestor.tenant_id).await?;
        if publication.root_tenant_id != node.root_tenant_id {
            return Err(AstralError::Validation(
                "code=org_scope.ancestor_publication_root_mismatch".into(),
            ));
        }
        heads.push((dependency, publication));
    }
    heads.sort_by_key(|(dependency, _)| dependency.tenant_id);
    let dependencies: Vec<OrgDependency> =
        heads.iter().map(|(dependency, _)| *dependency).collect();
    let parent_publications = match direct_parent_tenant_id {
        None => Vec::new(),
        Some(parent_tenant_id) => vec![heads
            .iter()
            .find(|(dependency, _)| dependency.tenant_id == parent_tenant_id)
            .map(|(_, publication)| publication.clone())
            .ok_or_else(|| {
                AstralError::Database("code=org_scope.direct_parent_publication_missing".into())
            })?],
    };

    // 授权装载（P1 可用性修复）：仅**当前 root 下活跃**的授权进入编译输入
    // （谓词见 `GRANT_COMPILE_INPUT_PREDICATE_SQL`）。跨 root MOVE/DETACH 在旧
    // 链原地撤销后遗留的旧 root 行（root 行内不可变）与 inactive 墓碑一律
    // 排除——否则 `OrgCompileInput::validate` 的 root 绑定永久失败（后代永久
    // PENDING/FAILED），且墓碑耗尽 compile 容量。编译器语义（policy-engine
    // `org_compiler.rs`）：`resolve_unit` 跳过 inactive grant；`derive_ledgers`
    // 对缺席 grant 移除账本并标 affected keys（本轮重算即收敛）；mask 与实际
    // contribution 的 provenance 链对账（目标缺席 = 无操作）——均不依赖墓碑
    // 行，过滤不损失任何当前 root 授权事实。
    let grant_rows = sqlx::query(&format!(
        "SELECT {GRANT_SELECT_COLUMNS} FROM org_scope_grant \
         WHERE {GRANT_COMPILE_INPUT_PREDICATE_SQL} ORDER BY grant_id LIMIT ?"
    ))
    .bind(tenant_id)
    .bind(node.root_tenant_id)
    .bind(ORG_MAX_COMPILE_GRANTS as i64 + 1)
    .fetch_all(&mut *tx)
    .await
    .map_err(db_err)?;
    if grant_rows.len() > ORG_MAX_COMPILE_GRANTS {
        return Err(AstralError::Validation(
            "code=org_scope.compile_grants_exceeded".into(),
        ));
    }
    let mut grants = Vec::with_capacity(grant_rows.len());
    for row in &grant_rows {
        grants.push(typed_grant(&grant_from_row(row)?).map_err(|error| {
            AstralError::Database(format!("code=org_scope.grant_row_invalid;detail={error}"))
        })?);
    }

    let mask_rows = sqlx::query(MASKS_SELECT_SQL)
        .bind(tenant_id)
        .bind(ORG_MAX_COMPILE_MASKS as i64 + 1)
        .fetch_all(&mut *tx)
        .await
        .map_err(db_err)?;
    if mask_rows.len() > ORG_MAX_COMPILE_MASKS {
        return Err(AstralError::Validation(
            "code=org_scope.compile_masks_exceeded".into(),
        ));
    }
    let mut masks = Vec::with_capacity(mask_rows.len());
    for row in &mask_rows {
        masks.push(OrgMask {
            mask_id: row.try_get("mask_id").map_err(db_err)?,
            tenant_id: row.try_get("tenant_id").map_err(db_err)?,
            target: OrgGrantRef {
                tenant_id: row.try_get("target_tenant_id").map_err(db_err)?,
                grant_id: row.try_get("target_grant_id").map_err(db_err)?,
                revision: row_generation(
                    row.try_get::<i64, _>("target_grant_revision")
                        .map_err(db_err)?,
                    "mask.target_revision",
                )?,
            },
            active: row.try_get::<i8, _>("active").map_err(db_err)? != 0,
            revision: row_generation(row.try_get("revision").map_err(db_err)?, "mask.revision")?,
            operation_id: row.try_get("operation_id").map_err(db_err)?,
        });
    }
    tx.commit().await.map_err(db_err)?;

    let input = OrgCompileInput {
        node,
        dependencies,
        parent_publications,
        grants,
        masks,
        operation_id,
    };
    // 结构性校验（fail-closed）：父授权解析/PENDING 分类在编译器完成。
    input.validate().map_err(org_err)?;
    Ok(input)
}

/// current 指针 ↔ publication 行身份绑定（纯函数）：generation / revoke_fence /
/// manifest digest 必须逐项一致，任一漂移即 fail-closed（稳定机码
/// `code=org_scope.current_pointer_inconsistent`，与 status/代次漂移同一失效
/// 类）。父 publication 输入与依赖钉装载共用该绑定，防止以漂移的 current 行
/// 冒充已封存事实源。
fn current_pointer_matches_publication(
    pointer_generation: i64,
    pointer_revoke_fence: i64,
    pointer_manifest_digest: &[u8],
    publication_generation: i64,
    publication_revoke_fence: i64,
    publication_manifest_digest: &[u8],
) -> Result<(), AstralError> {
    if pointer_generation != publication_generation
        || pointer_revoke_fence != publication_revoke_fence
        || pointer_manifest_digest != publication_manifest_digest
    {
        return Err(AstralError::Database(
            "code=org_scope.current_pointer_inconsistent".into(),
        ));
    }
    Ok(())
}

/// 装载一个祖先单元的当前 sealed publication 头及其依赖钉。
async fn load_ancestor_head_in_tx(
    tx: &mut Transaction<'static, MySql>,
    ancestor_tenant_id: i64,
) -> Result<(OrgDependency, OrgPublication), AstralError> {
    let current = sqlx::query(CURRENT_SELECT_SQL)
        .bind(ancestor_tenant_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_err)?
        .ok_or_else(|| {
            AstralError::NotFound(format!(
                "code=org_scope.parent_publication_missing;tenant_id={ancestor_tenant_id}"
            ))
        })?;
    let publication_id: i64 = current.try_get("publication_id").map_err(db_err)?;
    let current_generation: i64 = current.try_get("generation").map_err(db_err)?;
    let current_revoke_fence: i64 = current.try_get("revoke_fence").map_err(db_err)?;
    let current_manifest: Vec<u8> = current.try_get("manifest_digest").map_err(db_err)?;
    let row = sqlx::query(PUBLICATION_SELECT_SQL)
        .bind(publication_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_err)?
        .ok_or_else(|| AstralError::Database("code=org_scope.current_pointer_dangling".into()))?;
    let tenant_id: i64 = row.try_get("tenant_id").map_err(db_err)?;
    let root_tenant_id: i64 = row.try_get("root_tenant_id").map_err(db_err)?;
    let generation: i64 = row.try_get("generation").map_err(db_err)?;
    let relationship_revision: i64 = row.try_get("relationship_revision").map_err(db_err)?;
    let revoke_fence: i64 = row.try_get("revoke_fence").map_err(db_err)?;
    let dependencies_json: String = row.try_get("dependencies_json").map_err(db_err)?;
    let manifest_digest: Vec<u8> = row.try_get("manifest_digest").map_err(db_err)?;
    let compiler_version: String = row.try_get("compiler_version").map_err(db_err)?;
    let operation_id: String = row.try_get("operation_id").map_err(db_err)?;
    let status: String = row.try_get("status").map_err(db_err)?;
    if status != "SEALED" {
        return Err(AstralError::Database(
            "code=org_scope.current_pointer_inconsistent".into(),
        ));
    }
    // 指针身份绑定：current 行必须与所指 publication 行在 generation /
    // revoke_fence / manifest digest 上逐项恒等——父 publication 输入绝不接受
    // 漂移指针（即使 node head 未变，也不能以漂移 current 为编译输入事实源）。
    current_pointer_matches_publication(
        current_generation,
        current_revoke_fence,
        &current_manifest,
        generation,
        revoke_fence,
        &manifest_digest,
    )?;
    let segment_rows = sqlx::query(SEGMENT_SELECT_SQL)
        .bind(publication_id)
        .fetch_all(&mut **tx)
        .await
        .map_err(db_err)?;
    let mut segments = Vec::with_capacity(segment_rows.len());
    for segment_row in &segment_rows {
        segments.push(OrgSegment {
            index: u32::try_from(
                segment_row
                    .try_get::<i64, _>("segment_index")
                    .map_err(db_err)?,
            )
            .map_err(|_| AstralError::Database("code=org_scope.segment_index_invalid".into()))?,
            digest_hex: hex::encode(
                segment_row
                    .try_get::<Vec<u8>, _>("segment_digest")
                    .map_err(db_err)?,
            ),
            content: serde_json::from_str(
                &segment_row
                    .try_get::<String, _>("content_json")
                    .map_err(db_err)?,
            )
            .map_err(|error| {
                AstralError::Database(format!(
                    "code=org_scope.segment_content_unreadable;detail={error}"
                ))
            })?,
        });
    }
    let publication = OrgPublication {
        tenant_id,
        root_tenant_id,
        generation: row_generation(generation, "publication.generation")?,
        relationship_revision: row_generation(
            relationship_revision,
            "publication.relationship_revision",
        )?,
        revoke_fence: row_generation(revoke_fence, "publication.revoke_fence")?,
        dependencies: serde_json::from_str(&dependencies_json).map_err(|error| {
            AstralError::Database(format!(
                "code=org_scope.dependencies_unreadable;detail={error}"
            ))
        })?,
        manifest_digest_hex: hex::encode(manifest_digest),
        compiler_version,
        segments,
        operation_id,
    };
    let dependency = OrgDependency {
        tenant_id: ancestor_tenant_id,
        generation: publication.generation,
        revoke_fence: publication.revoke_fence,
        relationship_revision: publication.relationship_revision,
    };
    if tenant_id != ancestor_tenant_id
        || !org_dependency_matches_publication(&dependency, &publication)
    {
        return Err(AstralError::Database(
            "code=org_scope.ancestor_head_mismatch".into(),
        ));
    }
    Ok((dependency, publication))
}

// ─────────────────────────────────────────────────────────────────────────────
// 原子发布
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) async fn complete_publish(
    store: &SqlxOrgScopeRepository,
    cmd: &OrgPublishCommand,
) -> Result<OrgPublishOutcome, AstralError> {
    positive_i64(cmd.org_event_id, "org_event_id")?;
    validated_lease_owner(&cmd.worker_owner)?;
    let token_hash = worker_token_hash(&decode_worker_token(&cmd.worker_token_hex)?);
    // 载荷合同全量校验（manifest/segment digest、依赖排序、贡献归属）：
    // 失败发生在任何 durable 写之前。
    cmd.publication.validate().map_err(org_err)?;

    let (mut tx, authority_guard) = begin_authority_tx(store.pool()).await?;
    let event = sqlx::query(OUTBOX_LOCK_LEASED_SQL)
        .bind(cmd.org_event_id)
        .bind(&cmd.worker_owner)
        .bind(&token_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?
        .ok_or_else(|| AstralError::Validation("code=org_scope.outbox_lease_lost".into()))?;
    let row_event_kind: String = event.try_get("event_kind").map_err(db_err)?;
    // kind 封闭派发：只有 category-1 投影必需种类可发布（发生在任何 durable
    // 写之前）；MEMBERSHIP_CHANGED / SUBTREE_PROPAGATE 属"无发布完成"路径，
    // 未知种类确定性拒绝——绝不以 publish 消费错种类的事件。
    publication_required_kind(&row_event_kind)?;
    let event_tenant: i64 = event.try_get("tenant_id").map_err(db_err)?;
    if event_tenant != cmd.publication.tenant_id {
        return Err(AstralError::Validation(
            "code=org_scope.publish_tenant_mismatch".into(),
        ));
    }
    // durable 溯源绑定（先于任何 publication/审计写）：封存 publication 与
    // 审计事件携带的 operation 必须精确等于驱动本事件的 source mutation
    // operation（锁定事件行 operation_id）；漂移即伪造/损坏，fail-closed。
    let event_operation_id: String = event.try_get("operation_id").map_err(db_err)?;
    if event_operation_id != cmd.publication.operation_id {
        return Err(AstralError::Validation(format!(
            "code=org_scope.publish_operation_mismatch;event_op={event_operation_id};publication_op={}",
            cmd.publication.operation_id
        )));
    }

    // 本单元 source 新鲜度：node 头栅栏必须与 publication 逐项相等。
    let node_row = load_node_required_in_tx(&mut tx, cmd.publication.tenant_id).await?;
    let node = typed_node(&node_row)?;
    let stale = |detail: &str| {
        AstralError::Validation(format!(
            "code=org_scope.publish_stale_source;detail={detail}"
        ))
    };
    if !node.active {
        return Err(stale("node_inactive"));
    }
    if node.root_tenant_id != cmd.publication.root_tenant_id
        || node.generation != cmd.publication.generation
        || node.revoke_fence != cmd.publication.revoke_fence
        || node.relationship_revision != cmd.publication.relationship_revision
    {
        return Err(stale("node_head_advanced"));
    }
    // 依赖新鲜度：每个钉住的祖先 source head 必须 active 且逐项相等
    // （祖先撤销/移树即时令旧发布不可发布，亦令旧发布不可读）。
    for dependency in &cmd.publication.dependencies {
        let ancestor_row = load_node_required_in_tx(&mut tx, dependency.tenant_id).await?;
        let ancestor = typed_node(&ancestor_row)?;
        if !ancestor.active
            || ancestor.root_tenant_id != cmd.publication.root_tenant_id
            || ancestor.generation != dependency.generation
            || ancestor.revoke_fence != dependency.revoke_fence
            || ancestor.relationship_revision != dependency.relationship_revision
        {
            return Err(stale("dependency_head_advanced"));
        }
    }

    let dependency_digest_hex =
        astral_types::org_scope::org_dependency_digest_hex(&cmd.publication.dependencies)
            .map_err(org_err)?;
    let manifest_digest =
        digest32_from_hex(&cmd.publication.manifest_digest_hex, "manifest_digest")?;
    let publication_result = sqlx::query(PUBLICATION_INSERT_SQL)
        .bind(cmd.publication.tenant_id)
        .bind(cmd.publication.root_tenant_id)
        .bind(gen_to_i64(
            cmd.publication.generation,
            "publication.generation",
        )?)
        .bind(gen_to_i64(
            cmd.publication.relationship_revision,
            "publication.relationship_revision",
        )?)
        .bind(gen_to_i64(
            cmd.publication.revoke_fence,
            "publication.revoke_fence",
        )?)
        .bind(
            serde_json::to_string(&cmd.publication.dependencies).map_err(|error| {
                AstralError::Internal(format!("org_scope dependencies serialize: {error}"))
            })?,
        )
        .bind(digest32_from_hex(
            &dependency_digest_hex,
            "dependency_digest",
        )?)
        .bind(&manifest_digest)
        .bind(&cmd.publication.compiler_version)
        .bind(cmd.publication.segments.len() as i64)
        .bind(&cmd.publication.operation_id)
        .execute(&mut *tx)
        .await;
    // 同 (tenant, generation) 重复发布：幂等成功（返回既有指针状态），绝不覆盖。
    let publication_id = match publication_result {
        Ok(result) => result.last_insert_id(),
        Err(error) if is_unique_violation(&error) => {
            let existing = sqlx::query(CURRENT_SELECT_SQL)
                .bind(cmd.publication.tenant_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_err)?
                .ok_or_else(|| {
                    AstralError::Database(
                        "code=org_scope.duplicate_publication_without_pointer".into(),
                    )
                })?;
            let existing_generation: i64 = existing.try_get("generation").map_err(db_err)?;
            if row_generation(existing_generation, "current.generation")?
                != cmd.publication.generation
            {
                return Err(AstralError::Validation(
                    "code=org_scope.publish_generation_conflict".into(),
                ));
            }
            let existing_manifest: Vec<u8> = existing.try_get("manifest_digest").map_err(db_err)?;
            if existing_manifest != manifest_digest {
                return Err(AstralError::Validation(
                    "code=org_scope.publish_manifest_conflict".into(),
                ));
            }
            // An idempotent replay may only complete the event when it proves the
            // already sealed evidence is byte-identical at this generation.
            complete_event_terminal(&mut tx, cmd, &token_hash, &row_event_kind).await?;
            let cas_version: i64 = existing.try_get("cas_version").map_err(db_err)?;
            commit_authority_tx(tx, authority_guard)
                .await
                .map_err(db_err)?;
            return Ok(OrgPublishOutcome {
                publication_id: existing.try_get("publication_id").map_err(db_err)?,
                generation: cmd.publication.generation,
                cas_version: row_generation(cas_version, "current.cas_version")?,
            });
        }
        Err(error) => return Err(db_err(error)),
    };
    let publication_id = i64::try_from(publication_id)
        .ok()
        .filter(|id| *id > 0)
        .ok_or_else(|| {
            AstralError::Internal("org_scope publication insert returned an unusable id".into())
        })?;
    for segment in &cmd.publication.segments {
        let content_json = serde_json::to_string(&segment.content).map_err(|error| {
            AstralError::Internal(format!("org_scope segment serialize: {error}"))
        })?;
        sqlx::query(SEGMENT_INSERT_SQL)
            .bind(publication_id)
            .bind(segment.index)
            .bind(digest32_from_hex(&segment.digest_hex, "segment_digest")?)
            .bind(content_json)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
    }
    for dependency in &cmd.publication.dependencies {
        sqlx::query(DEPENDENCY_INSERT_SQL)
            .bind(cmd.publication.tenant_id)
            .bind(dependency.tenant_id)
            .bind(publication_id)
            .bind(gen_to_i64(dependency.generation, "dependency.generation")?)
            .bind(gen_to_i64(
                dependency.revoke_fence,
                "dependency.revoke_fence",
            )?)
            .bind(gen_to_i64(
                dependency.relationship_revision,
                "dependency.relationship_revision",
            )?)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
    }
    // current generation 单调 CAS（affected-rows-exactly-one）。
    advance_current_pointer(&mut tx, &cmd.publication, publication_id).await?;
    // 事件终态（租约内原子完成，含未过期栅栏与精确 kind 条件；失败整体回滚
    // 含 publication）。
    complete_event_terminal(&mut tx, cmd, &token_hash, &row_event_kind).await?;
    let publish_detail = serde_json::json!({
        "generation": cmd.publication.generation,
        "manifestDigestHex": cmd.publication.manifest_digest_hex,
        "compilerVersion": cmd.publication.compiler_version,
    })
    .to_string();
    append_audit_in_tx(
        &mut tx,
        OrgAuditWrite {
            tenant_id: cmd.publication.tenant_id,
            actor_user_id: 0,
            actor_tenant_id: None,
            action: "PUBLICATION_SEALED",
            subject_kind: "PUBLICATION",
            subject_id: &publication_id.to_string(),
            request_id: None,
            operation_id: &cmd.publication.operation_id,
            detail_json: Some(publish_detail.as_str()),
        },
    )
    .await?;
    let pointer = sqlx::query(CURRENT_SELECT_SQL)
        .bind(cmd.publication.tenant_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;
    let cas_version: i64 = pointer.try_get("cas_version").map_err(db_err)?;
    commit_authority_tx(tx, authority_guard)
        .await
        .map_err(db_err)?;
    Ok(OrgPublishOutcome {
        publication_id,
        generation: cmd.publication.generation,
        cas_version: row_generation(cas_version, "current.cas_version")?,
    })
}

async fn complete_event_terminal(
    tx: &mut Transaction<'static, MySql>,
    cmd: &OrgPublishCommand,
    token_hash: &[u8],
    event_kind: &str,
) -> Result<(), AstralError> {
    // 终态 UPDATE 自身携带完整租约谓词（含**未过期**栅栏——租约过期后绝不
    // ACK）+ 精确 event_kind 条件；行已在本事务锁定，affected != 1 只可能是
    // 异常状态，保守拒绝。
    let result = sqlx::query(OUTBOX_COMPLETE_SQL)
        .bind(cmd.org_event_id)
        .bind(&cmd.worker_owner)
        .bind(token_hash)
        .bind(event_kind)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    require_affected_one(&result, "publish_event_lease_lost")
}

async fn advance_current_pointer(
    tx: &mut Transaction<'static, MySql>,
    publication: &OrgPublication,
    publication_id: i64,
) -> Result<(), AstralError> {
    let target_generation = gen_to_i64(publication.generation, "publication.generation")?;
    let manifest = digest32_from_hex(&publication.manifest_digest_hex, "manifest_digest")?;
    let revoke_fence = gen_to_i64(publication.revoke_fence, "publication.revoke_fence")?;
    let advance = sqlx::query(CURRENT_CAS_SQL)
        .bind(publication_id)
        .bind(target_generation)
        .bind(&manifest)
        .bind(revoke_fence)
        .bind(publication.tenant_id)
        .bind(target_generation)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    if advance.rows_affected() == 1 {
        return Ok(());
    }
    // 首次发布：直接插入；并发首插冲突则说明指针代次已 ≥ 目标，保守拒绝。
    let insert = sqlx::query(CURRENT_INSERT_SQL)
        .bind(publication.tenant_id)
        .bind(publication_id)
        .bind(target_generation)
        .bind(&manifest)
        .bind(revoke_fence)
        .execute(&mut **tx)
        .await;
    match insert {
        Ok(_) => Ok(()),
        Err(error) if is_unique_violation(&error) => Err(AstralError::Validation(
            "code=org_scope.publish_generation_conflict".into(),
        )),
        Err(error) => Err(db_err(error)),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 子树 root 传播（扇出语义：锚点直接子节点 drain + child intent 派生 +
// durable 幂等标记 + NODE revision 账）
// ─────────────────────────────────────────────────────────────────────────────

/// 传播节点变更的 NODE revision 账 + outbox 事件（与 requests.rs 的
/// `append_node_revision_and_event` 同一写序与载荷合同：typed node 载荷、
/// revision = 变更后 relationship_revision、subject_id = tenant_id 十进制
/// 文本；该账行同时是本操作的 durable 幂等标记，重试凭其存在性跳过）。
async fn append_node_revision_and_event_in_tx(
    tx: &mut Transaction<'static, MySql>,
    node: &OrgNodeRow,
    operation_id: &str,
) -> Result<(), AstralError> {
    let payload = serde_json::to_string(&typed_node(node)?)
        .map_err(|error| AstralError::Internal(format!("org_scope node payload: {error}")))?;
    append_revision_in_tx(
        tx,
        "NODE",
        node.tenant_id,
        &node.tenant_id.to_string(),
        row_generation(node.relationship_revision, "node.relationship_revision")?,
        &payload,
        operation_id,
    )
    .await?;
    append_outbox_event_in_tx(
        tx,
        node.tenant_id,
        ORG_EVENT_NODE_TOPOLOGY_CHANGED,
        operation_id,
        &payload,
    )
    .await?;
    Ok(())
}

/// 子树 root 传播（扇出，单批）：语义与锁序见模块文档与
/// `OrgSubtreePropagateCommand`/`OrgSubtreePropagateOutcome` 合同。
///
/// 单事务流程：锁定 leased 事件（kind 限定）→ 意图绑定（typed 载荷 +
/// tenant/operation/root/frontier 逐项一致）→ 锚点锁定 + revision 栅栏 →
/// 选择"未以本操作 id 落过 NODE 账"的直接 active 子节点（升序、锁内、至多
/// batch_limit）→ 逐个推进（root 置目标 + 三计数同步 +1）+ NODE 账/事件 +
/// 新 child intent → 审计（有推进时）→ 提交。选中数 == batch_limit 必返回
/// `done=false, next_frontier=[锚点]`（重入排空剩余兄弟），选中数 < batch_limit
/// 才 done；额外一次空轮兜底精确满批。撤销栅栏决策（deliberate）：传播式
/// 关系失效与 source 级 NODE_ATTACH/MOVE/DETACH 同一合同——generation/
/// relationship_revision/revoke_fence 同步 +1（`SUBTREE_UPDATE_SQL` 与单测
/// `propagated_topology_update_advances_all_three_counters` 冻结该耦合）；
/// 失效信号因此不依赖单一计数，读侧对三计数逐项相等校验保持 fail-closed。
pub(crate) async fn propagate_subtree_root(
    store: &SqlxOrgScopeRepository,
    cmd: &OrgSubtreePropagateCommand,
) -> Result<OrgSubtreePropagateOutcome, AstralError> {
    positive_i64(cmd.org_event_id, "org_event_id")?;
    validated_lease_owner(&cmd.worker_owner)?;
    let token_hash = worker_token_hash(&decode_worker_token(&cmd.worker_token_hex)?);
    // 入口 kind 预检：本原语只消费 SUBTREE_PROPAGATE intent（先于任何 DB 访问）。
    validated_propagation_kind(cmd.expected_kind)?;
    validated_operation_id(&cmd.operation_id)?;
    positive_i64(cmd.new_root_tenant_id, "new_root_tenant_id")?;
    // frontier 形状预检：只可能是单元素（durable 锚点）；空/多元素在绑定阶段
    // 精确拒绝（此处只挡明显畸形，权威校验在载荷绑定之后）。
    if cmd.frontier.len() > 1 {
        return Err(AstralError::Validation(format!(
            "{ORG_PROPAGATE_FRONTIER_INVALID_CODE};reason=length;len={}",
            cmd.frontier.len()
        )));
    }
    if cmd.batch_limit <= 0 || cmd.batch_limit > ORG_MAX_PROPAGATE_BATCH {
        return Err(AstralError::Validation(
            "code=org_scope.propagate_batch_invalid".into(),
        ));
    }
    let (mut tx, authority_guard) = begin_authority_tx(store.pool()).await?;
    // 1) 先锁并校验 leased 事件（status/owner/token 摘要/未过期 + 精确 kind），
    //    先于锚点/子节点任何锁定与写入。
    let event = sqlx::query(OUTBOX_LOCK_LEASED_FOR_PROPAGATE_SQL)
        .bind(cmd.org_event_id)
        .bind(&cmd.worker_owner)
        .bind(&token_hash)
        .bind(OrgOutboxEventKind::SubtreePropagate.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?
        .ok_or_else(|| AstralError::Validation("code=org_scope.outbox_lease_lost".into()))?;
    let event_tenant_id: i64 = event.try_get("tenant_id").map_err(db_err)?;
    let event_operation_id: String = event.try_get("operation_id").map_err(db_err)?;
    let payload_json: String = event.try_get("payload_json").map_err(db_err)?;
    // 2) 意图绑定：typed 载荷 + tenant/operation/root 逐项一致（先于任何节点
    //    写入；不一致 fail-closed 回滚，事件保持 LEASED 交由 worker 登记）。
    let payload = validated_propagation_intent(
        event_tenant_id,
        &event_operation_id,
        &payload_json,
        &cmd.operation_id,
        cmd.new_root_tenant_id,
    )?;
    // 3) frontier 绑定：必须恰为 `[durable 锚点]`。
    validated_propagation_frontier(&cmd.frontier, payload.child_tenant_id)?;
    // 4) 锚点锁定 + revision 栅栏（同一事件租约事务内）。
    let anchor = lock_node_in_tx(&mut tx, payload.child_tenant_id)
        .await?
        .ok_or_else(|| {
            AstralError::NotFound(format!(
                "code=org_scope.node_missing;tenant_id={}",
                payload.child_tenant_id
            ))
        })?;
    if !anchor.active {
        return Err(AstralError::Validation(
            ORG_PROPAGATE_ANCHOR_INACTIVE_CODE.to_owned(),
        ));
    }
    let anchor_revision =
        row_generation(anchor.relationship_revision, "anchor.relationship_revision")?;
    let superseded =
        propagation_intent_revision_fence(payload.relationship_revision, anchor_revision)?;
    if superseded {
        // The newer topology mutation must leave a later durable intent before this
        // event can be retired; otherwise a forgotten enqueue would hide a lost wave.
        let replacement = sqlx::query(SUBTREE_SUPERSEDED_INTENT_SQL)
            .bind(event_tenant_id)
            .bind(cmd.org_event_id)
            .bind(anchor_revision)
            .bind(anchor.root_tenant_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
        if replacement.is_none() {
            return Err(AstralError::Validation(
                ORG_PROPAGATE_SUPERSESSION_UNPROVEN_CODE.into(),
            ));
        }
        commit_authority_tx(tx, authority_guard)
            .await
            .map_err(db_err)?;
        return Ok(OrgSubtreePropagateOutcome {
            updated_tenant_ids: Vec::new(),
            next_frontier: Vec::new(),
            done: true,
            superseded: true,
        });
    }
    // Current 关系：root 必须精确等于目标（equal revision 下结构性成立；防御
    // 性 fail-closed，绝不以漂移的锚点状态推进后代）。
    if anchor.root_tenant_id != cmd.new_root_tenant_id {
        return Err(AstralError::Validation(
            ORG_PROPAGATE_ANCHOR_ROOT_MISMATCH_CODE.to_owned(),
        ));
    }
    // 5) 选择锚点的直接 active 子节点中尚未以本操作 id 落过 NODE 账的（durable
    //    幂等标记；同 root 后代同样选中失效），升序、锁内、至多 batch_limit。
    let stale_rows = sqlx::query(SUBTREE_SELECT_PROPAGATION_CHILDREN_SQL)
        .bind(payload.child_tenant_id)
        .bind(&cmd.operation_id)
        .bind(cmd.batch_limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(db_err)?;
    let selected: Vec<i64> = stale_rows
        .iter()
        .map(|row| row.try_get("tenant_id").map_err(db_err))
        .collect::<Result<Vec<_>, _>>()?;
    let mut updated_tenant_ids = Vec::with_capacity(selected.len());
    for tenant_id in &selected {
        // root 置目标（即使已相同）+ generation/relationship/revoke_fence 同步 +1。
        let result = sqlx::query(SUBTREE_UPDATE_SQL)
            .bind(cmd.new_root_tenant_id)
            .bind(&cmd.operation_id)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        require_affected_one(&result, "propagate_update_race")?;
        // 回读推进后行：NODE revision 账（即幂等标记）+ NODE_TOPOLOGY_CHANGED
        // 事件 + 新的 typed child intent（child=被推进子节点、目标 root、推进后
        // relationship_revision）与节点变更同事务原子。
        let node_after = load_node_required_in_tx(&mut tx, *tenant_id).await?;
        append_node_revision_and_event_in_tx(&mut tx, &node_after, &cmd.operation_id).await?;
        append_subtree_propagate_intent_in_tx(
            &mut tx,
            node_after.tenant_id,
            cmd.new_root_tenant_id,
            row_generation(
                node_after.relationship_revision,
                "node.relationship_revision",
            )?,
            &cmd.operation_id,
        )
        .await?;
        updated_tenant_ids.push(*tenant_id);
    }
    if !updated_tenant_ids.is_empty() {
        let propagation_detail = serde_json::json!({ "updated": updated_tenant_ids }).to_string();
        let root_subject_id = cmd.new_root_tenant_id.to_string();
        append_audit_in_tx(
            &mut tx,
            OrgAuditWrite {
                tenant_id: cmd.new_root_tenant_id,
                actor_user_id: 0,
                actor_tenant_id: None,
                action: "SUBTREE_PROPAGATED",
                subject_kind: "NODE",
                subject_id: &root_subject_id,
                request_id: None,
                operation_id: &cmd.operation_id,
                detail_json: Some(propagation_detail.as_str()),
            },
        )
        .await?;
    }
    commit_authority_tx(tx, authority_guard)
        .await
        .map_err(db_err)?;
    // 选中数 == batch_limit 时绝不定 done：同锚点可能仍有未 drain 的兄弟，必须
    // 以同一事件重入；空轮（0 < limit）或部分轮给出完成证明。
    let done = (selected.len() as i64) < cmd.batch_limit;
    Ok(OrgSubtreePropagateOutcome {
        next_frontier: if done {
            Vec::new()
        } else {
            vec![payload.child_tenant_id]
        },
        done,
        updated_tenant_ids,
        superseded: false,
    })
}

pub(crate) async fn propagate_dependency_change(
    store: &SqlxOrgScopeRepository,
    cmd: &OrgDependencyPropagateCommand,
) -> Result<OrgDependencyPropagateOutcome, AstralError> {
    positive_i64(cmd.org_event_id, "org_event_id")?;
    positive_i64(cmd.anchor_tenant_id, "anchor_tenant_id")?;
    validated_lease_owner(&cmd.worker_owner)?;
    validated_operation_id(&cmd.operation_id)?;
    validated_dependency_propagation_kind(cmd.expected_kind)?;
    if cmd.batch_limit <= 0 || cmd.batch_limit > ORG_MAX_PROPAGATE_BATCH {
        return Err(AstralError::Validation(
            "code=org_scope.propagate_batch_invalid".into(),
        ));
    }
    let token_hash = worker_token_hash(&decode_worker_token(&cmd.worker_token_hex)?);
    let (mut tx, authority_guard) = begin_authority_tx(store.pool()).await?;
    let event = sqlx::query(OUTBOX_LOCK_LEASED_FOR_DEPENDENCY_SQL)
        .bind(cmd.org_event_id)
        .bind(&cmd.worker_owner)
        .bind(&token_hash)
        .bind(OrgOutboxEventKind::DependencyPropagate.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?
        .ok_or_else(|| AstralError::Validation("code=org_scope.outbox_lease_lost".into()))?;
    let event_tenant_id: i64 = event.try_get("tenant_id").map_err(db_err)?;
    let event_operation_id: String = event.try_get("operation_id").map_err(db_err)?;
    let payload_json: String = event.try_get("payload_json").map_err(db_err)?;
    let payload = validated_dependency_intent(
        event_tenant_id,
        &event_operation_id,
        &payload_json,
        &cmd.operation_id,
        cmd.anchor_tenant_id,
    )?;
    let candidates = sqlx::query(DEPENDENCY_PROPAGATION_CANDIDATE_SQL)
        .bind(payload.anchor_tenant_id)
        .bind(payload.anchor_tenant_id)
        .bind(payload.generation)
        .bind(payload.revoke_fence)
        .bind(payload.relationship_revision)
        .bind(&cmd.operation_id)
        .bind(cmd.batch_limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(db_err)?;
    let mut lock_ids = Vec::with_capacity(candidates.len() + 1);
    lock_ids.push(payload.anchor_tenant_id);
    for row in &candidates {
        lock_ids.push(row.try_get("tenant_id").map_err(db_err)?);
    }
    lock_ids.sort_unstable();
    lock_ids.dedup();
    let locked_nodes = lock_nodes_in_tx(&mut tx, &lock_ids).await?;
    let anchor = locked_nodes
        .iter()
        .find(|node| node.tenant_id == payload.anchor_tenant_id)
        .cloned()
        .ok_or_else(|| {
            AstralError::NotFound(format!(
                "code=org_scope.node_missing;tenant_id={}",
                payload.anchor_tenant_id
            ))
        })?;
    if !anchor.active {
        return Err(AstralError::Validation(
            ORG_DEPENDENCY_PROPAGATE_ANCHOR_INACTIVE_CODE.into(),
        ));
    }
    let anchor_generation = row_generation(anchor.generation, "anchor.generation")?;
    if anchor_generation > payload.generation {
        let replacement = sqlx::query(DEPENDENCY_SUPERSEDED_INTENT_SQL)
            .bind(event_tenant_id)
            .bind(cmd.org_event_id)
            .bind(anchor_generation)
            .bind(anchor.root_tenant_id)
            .bind(row_generation(
                anchor.relationship_revision,
                "anchor.relationship_revision",
            )?)
            .bind(anchor.root_tenant_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
        if replacement.is_none() {
            return Err(AstralError::Validation(
                ORG_DEPENDENCY_PROPAGATE_SUPERSESSION_UNPROVEN_CODE.into(),
            ));
        }
        commit_authority_tx(tx, authority_guard)
            .await
            .map_err(db_err)?;
        return Ok(OrgDependencyPropagateOutcome {
            updated_tenant_ids: Vec::new(),
            done: true,
            superseded: true,
        });
    }
    if anchor_generation < payload.generation
        || anchor.root_tenant_id != payload.root_tenant_id
        || row_generation(anchor.revoke_fence, "anchor.revoke_fence")? != payload.revoke_fence
        || row_generation(anchor.relationship_revision, "anchor.relationship_revision")?
            != payload.relationship_revision
    {
        return Err(AstralError::Validation(
            ORG_DEPENDENCY_PROPAGATE_INTENT_HEAD_MISMATCH_CODE.into(),
        ));
    }
    let (anchor_dependency, anchor_publication) =
        load_ancestor_head_in_tx(&mut tx, payload.anchor_tenant_id).await?;
    if !org_dependency_matches_publication(&anchor_dependency, &anchor_publication)
        || anchor_publication.generation != payload.generation
        || anchor_publication.root_tenant_id != payload.root_tenant_id
        || anchor_publication.revoke_fence != payload.revoke_fence
        || anchor_publication.relationship_revision != payload.relationship_revision
    {
        return Err(AstralError::Validation(
            ORG_DEPENDENCY_PROPAGATE_ANCHOR_PUBLICATION_STALE_CODE.into(),
        ));
    }
    let stale = sqlx::query(DEPENDENCY_PROPAGATION_CHILD_SQL)
        .bind(payload.anchor_tenant_id)
        .bind(payload.anchor_tenant_id)
        .bind(payload.generation)
        .bind(payload.revoke_fence)
        .bind(payload.relationship_revision)
        .bind(&cmd.operation_id)
        .bind(cmd.batch_limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(db_err)?;
    let candidate_ids = candidates
        .iter()
        .map(|row| row.try_get::<i64, _>("tenant_id").map_err(db_err))
        .collect::<Result<Vec<_>, _>>()?;
    let stale_ids = stale
        .iter()
        .map(|row| row.try_get::<i64, _>("tenant_id").map_err(db_err))
        .collect::<Result<Vec<_>, _>>()?;
    if candidate_ids != stale_ids {
        return Err(AstralError::Validation(
            "code=org_scope.dependency_propagate_candidate_drift".into(),
        ));
    }
    let mut updated_tenant_ids = Vec::with_capacity(stale.len());
    for row in stale {
        let tenant_id: i64 = row.try_get("tenant_id").map_err(db_err)?;
        let result = sqlx::query(DEPENDENCY_ADVANCE_SQL)
            .bind(&cmd.operation_id)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        require_affected_one(&result, "dependency_propagate_update_race")?;
        let node_after = load_node_required_in_tx(&mut tx, tenant_id).await?;
        let payload_node = serde_json::to_string(&typed_node(&node_after)?)
            .map_err(|error| AstralError::Internal(format!("org_scope node payload: {error}")))?;
        append_outbox_event_in_tx(
            &mut tx,
            tenant_id,
            ORG_EVENT_NODE_MUTATED,
            &cmd.operation_id,
            &payload_node,
        )
        .await?;
        crate::org_scope_repository::requests::append_dependency_propagate_intent_in_tx(
            &mut tx,
            &node_after,
            &cmd.operation_id,
        )
        .await?;
        updated_tenant_ids.push(tenant_id);
    }
    if !updated_tenant_ids.is_empty() {
        let detail = serde_json::json!({"updated": updated_tenant_ids}).to_string();
        append_audit_in_tx(
            &mut tx,
            OrgAuditWrite {
                tenant_id: payload.anchor_tenant_id,
                actor_user_id: 0,
                actor_tenant_id: None,
                action: "DEPENDENCY_PROPAGATED",
                subject_kind: "NODE",
                subject_id: &payload.anchor_tenant_id.to_string(),
                request_id: None,
                operation_id: &cmd.operation_id,
                detail_json: Some(detail.as_str()),
            },
        )
        .await?;
    }
    commit_authority_tx(tx, authority_guard)
        .await
        .map_err(db_err)?;
    Ok(OrgDependencyPropagateOutcome {
        done: (updated_tenant_ids.len() as i64) < cmd.batch_limit,
        updated_tenant_ids,
        superseded: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::org_scope::{OrgGrant, OrgNode, OrgRootActivation, OrgScope};
    use astral_types::ValidityWindow;
    use policy_engine::{OrgCompileOutcome, OrgCompiler};
    use std::collections::{BTreeMap, BTreeSet, VecDeque};

    fn intent_payload_json(child: i64, root: i64, revision: u64) -> String {
        serde_json::to_string(&OrgSubtreePropagatePayload {
            child_tenant_id: child,
            new_root_tenant_id: root,
            relationship_revision: revision,
        })
        .unwrap()
    }

    #[test]
    fn dependency_propagation_sql_pins_current_publication_and_generation_only_update() {
        assert!(DEPENDENCY_PROPAGATION_CHILD_SQL.contains("d.publication_id = c.publication_id"));
        assert!(DEPENDENCY_PROPAGATION_CANDIDATE_SQL.contains("ORDER BY n.tenant_id LIMIT ?"));
        assert!(DEPENDENCY_PROPAGATION_CANDIDATE_SQL.contains("NOT EXISTS"));
        assert!(
            DEPENDENCY_PROPAGATION_CHILD_SQL.contains("n.parent_tenant_id = ? AND n.active = 1")
        );
        assert!(DEPENDENCY_PROPAGATION_CHILD_SQL.contains("d.pinned_generation <> ?"));
        assert!(DEPENDENCY_PROPAGATION_CHILD_SQL.contains("d.pinned_revoke_fence <> ?"));
        assert!(DEPENDENCY_PROPAGATION_CHILD_SQL.contains("d.pinned_relationship_revision <> ?"));
        assert!(DEPENDENCY_PROPAGATION_CHILD_SQL
            .contains("'DEPENDENCY_PROPAGATE', 'SUBTREE_PROPAGATE'"));
        assert!(
            DEPENDENCY_PROPAGATION_CHILD_SQL.contains("ORDER BY n.tenant_id LIMIT ? FOR UPDATE")
        );
        assert!(DEPENDENCY_PROPAGATION_DRAIN_SQL.contains("d.publication_id = c.publication_id"));
        assert!(DEPENDENCY_PROPAGATION_DRAIN_SQL.contains("LIMIT 1"));
        assert!(DEPENDENCY_ADVANCE_SQL.contains("SET generation = generation + 1"));
        assert!(!DEPENDENCY_ADVANCE_SQL.contains("revoke_fence"));
        assert!(!DEPENDENCY_ADVANCE_SQL.contains("relationship_revision"));
    }

    #[test]
    fn dependency_supersession_requires_a_later_durable_intent_bound_to_the_advanced_head() {
        assert!(DEPENDENCY_SUPERSEDED_INTENT_SQL.contains("org_event_id > ?"));
        assert!(DEPENDENCY_SUPERSEDED_INTENT_SQL.contains("status <> 'FAILED'"));
        assert!(DEPENDENCY_SUPERSEDED_INTENT_SQL.contains("$.generation"));
        assert!(DEPENDENCY_SUPERSEDED_INTENT_SQL.contains("$.root_tenant_id"));
        assert!(DEPENDENCY_SUPERSEDED_INTENT_SQL.contains("$.relationship_revision"));
        assert!(DEPENDENCY_SUPERSEDED_INTENT_SQL.contains("$.new_root_tenant_id"));
        assert!(DEPENDENCY_SUPERSEDED_INTENT_SQL.contains("event_kind = 'DEPENDENCY_PROPAGATE'"));
        // `SUBTREE_SUPERSEDED_INTENT_SQL` is topology-only; a later topology intent must
        // prove this event was replaced before it can be retired without a wave.
        assert!(SUBTREE_SUPERSEDED_INTENT_SQL.contains("event_kind = 'SUBTREE_PROPAGATE'"));
        assert!(!SUBTREE_SUPERSEDED_INTENT_SQL.contains("event_kind = 'DEPENDENCY_PROPAGATE'"));
    }

    #[test]
    fn dependency_intent_payload_binds_anchor_head_and_operation() {
        let payload = OrgDependencyPropagatePayload {
            anchor_tenant_id: 20,
            root_tenant_id: 10,
            generation: 7,
            revoke_fence: 0,
            relationship_revision: 4,
        };
        let encoded = serde_json::to_string(&payload).unwrap();
        assert!(validated_dependency_intent(20, "op-1", &encoded, "op-1", 20).is_ok());
        assert!(
            validated_dependency_intent(21, "op-1", &encoded, "op-1", 20)
                .unwrap_err()
                .to_string()
                .contains("dependency_propagate_intent_tenant_mismatch")
        );
        assert!(
            validated_dependency_intent(20, "op-2", &encoded, "op-1", 20)
                .unwrap_err()
                .to_string()
                .contains("dependency_propagate_intent_operation_mismatch")
        );
    }

    #[test]
    fn propagation_intent_binds_command_to_durable_payload() {
        // 合法绑定：载荷与事件租户/命令 operation/命令目标 root 逐项一致。
        let payload =
            validated_propagation_intent(20, "op-1", &intent_payload_json(20, 30, 7), "op-1", 30)
                .unwrap();
        assert_eq!(
            payload,
            OrgSubtreePropagatePayload {
                child_tenant_id: 20,
                new_root_tenant_id: 30,
                relationship_revision: 7
            }
        );
        // 历史 wire 字节兼容：旧 ad hoc producer 的 JSON 仍可解析绑定。
        assert!(validated_propagation_intent(
            20,
            "op-1",
            r#"{"child_tenant_id":20,"new_root_tenant_id":30,"relationship_revision":7}"#,
            "op-1",
            30
        )
        .is_ok());
        // 载荷 child != 事件租户。
        let error =
            validated_propagation_intent(21, "op-1", &intent_payload_json(20, 30, 7), "op-1", 30)
                .unwrap_err();
        assert!(error
            .to_string()
            .contains("org_scope.propagate_intent_tenant_mismatch"));
        // 命令 operation_id 与事件行不一致。
        let error =
            validated_propagation_intent(20, "op-2", &intent_payload_json(20, 30, 7), "op-1", 30)
                .unwrap_err();
        assert!(error
            .to_string()
            .contains("org_scope.propagate_intent_operation_mismatch"));
        // 命令目标 root 与载荷不一致。
        let error =
            validated_propagation_intent(20, "op-1", &intent_payload_json(20, 30, 7), "op-1", 31)
                .unwrap_err();
        assert!(error
            .to_string()
            .contains("org_scope.propagate_intent_root_mismatch"));
        // 未知字段（deny_unknown_fields）→ 载荷不可读，fail-closed。
        let error = validated_propagation_intent(
            20,
            "op-1",
            r#"{"child_tenant_id":20,"new_root_tenant_id":30,"relationship_revision":7,"extra":1}"#,
            "op-1",
            30,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("org_scope.propagate_payload_unreadable"));
        // 非法载荷（零 revision）→ 类型合同校验拒绝。
        let error =
            validated_propagation_intent(20, "op-1", &intent_payload_json(20, 30, 0), "op-1", 30)
                .unwrap_err();
        assert!(error.to_string().contains("org_scope.invalid_field"));
    }

    #[test]
    fn propagation_frontier_must_be_exactly_the_durable_anchor() {
        assert!(validated_propagation_frontier(&[20], 20).is_ok());
        for bad in [
            vec![],
            vec![20, 21],
            vec![21],
            vec![0],
            vec![-20],
            vec![20, 20],
        ] {
            let error = validated_propagation_frontier(&bad, 20).unwrap_err();
            assert!(error
                .to_string()
                .contains("org_scope.propagate_frontier_invalid"));
        }
    }

    #[test]
    fn propagation_revision_fence_classifies_current_superseded_and_regression() {
        // 相等 → Current（继续按批推进）。
        assert!(!propagation_intent_revision_fence(7, 7).unwrap());
        // 锚点 revision 更大 → Superseded（更新的拓扑变更已接管，安全放行）。
        assert!(propagation_intent_revision_fence(7, 8).unwrap());
        assert!(propagation_intent_revision_fence(7, 100).unwrap());
        // 锚点 revision 更小 → 损坏/乱序，fail-closed。
        let error = propagation_intent_revision_fence(7, 6).unwrap_err();
        assert!(error
            .to_string()
            .contains("org_scope.propagate_intent_revision_regression"));
    }

    #[test]
    fn ancestor_pointer_identity_binds_generation_fence_and_manifest() {
        let manifest = [7u8; 32];
        assert!(current_pointer_matches_publication(5, 2, &manifest, 5, 2, &manifest).is_ok());
        // generation 漂移 → fail-closed。
        let error =
            current_pointer_matches_publication(6, 2, &manifest, 5, 2, &manifest).unwrap_err();
        assert!(error
            .to_string()
            .contains("org_scope.current_pointer_inconsistent"));
        // revoke_fence 漂移 → fail-closed。
        let error =
            current_pointer_matches_publication(5, 3, &manifest, 5, 2, &manifest).unwrap_err();
        assert!(error
            .to_string()
            .contains("org_scope.current_pointer_inconsistent"));
        // manifest digest 漂移 → fail-closed。
        let error =
            current_pointer_matches_publication(5, 2, &manifest, 5, 2, &[8u8; 32]).unwrap_err();
        assert!(error
            .to_string()
            .contains("org_scope.current_pointer_inconsistent"));
    }

    // ───────────────────────────────────────────────────────────────────────
    // 无发布完成的载荷门（DONE 之前的最后防线）
    // ───────────────────────────────────────────────────────────────────────

    fn membership_payload_json(tenant_id: i64) -> String {
        serde_json::to_string(&OrgMembership {
            membership_id: "00000000-0000-0000-0000-00000000000a".into(),
            tenant_id,
            root_tenant_id: tenant_id,
            user_id: 42,
            identity_card_id: 4242,
            card_id: 424242,
            revision: 1,
            active: true,
            validity: astral_types::ValidityWindow::perpetual(),
            operation_id: "op-m-1".into(),
        })
        .unwrap()
    }

    #[test]
    fn completion_payload_gate_binds_membership_intent_to_event_tenant() {
        // 合法：typed OrgMembership + 同租户 + 同操作 → 通过。
        assert!(validated_completion_payload(
            OrgOutboxEventKind::MembershipChanged,
            20,
            "op-m-1",
            &membership_payload_json(20)
        )
        .unwrap()
        .is_none());
        // 跨租户 membership intent → 拒绝（绝不静默完成）。
        let error = validated_completion_payload(
            OrgOutboxEventKind::MembershipChanged,
            21,
            "op-m-1",
            &membership_payload_json(20),
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("org_scope.complete_payload_tenant_mismatch"));
        // 畸形 JSON → 确定性不可读错误。
        let error = validated_completion_payload(
            OrgOutboxEventKind::MembershipChanged,
            20,
            "op-m-1",
            "{\"tenant_id\":20}",
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("org_scope.complete_payload_unreadable"));
        // 类型合同失败（revision = 0）→ org_scope.invalid_field。
        let mut invalid: OrgMembership =
            serde_json::from_str(&membership_payload_json(20)).unwrap();
        invalid.revision = 0;
        let error = validated_completion_payload(
            OrgOutboxEventKind::MembershipChanged,
            20,
            "op-m-1",
            &serde_json::to_string(&invalid).unwrap(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("org_scope.invalid_field"));
        // category-1 kind 到达载荷门（防御兜底）→ 白名单拒绝。
        let error = validated_completion_payload(
            OrgOutboxEventKind::GrantIssued,
            20,
            "op-m-1",
            &membership_payload_json(20),
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("org_scope.outbox_complete_kind_forbidden"));
    }

    #[test]
    fn completion_payload_gate_binds_subtree_payload_and_flags_drain_proof() {
        // 合法 SUBTREE 载荷 → 返回 Some(payload)（需要 durable 收敛证明）。
        let payload = validated_completion_payload(
            OrgOutboxEventKind::SubtreePropagate,
            20,
            "op-1",
            &intent_payload_json(20, 30, 7),
        )
        .unwrap()
        .expect("subtree completion requires the drain proof");
        assert!(matches!(
            payload,
            CompletionPropagationPayload::Subtree(subtree) if subtree.relationship_revision == 7
        ));
        // 跨租户 subtree intent → 拒绝。
        let error = validated_completion_payload(
            OrgOutboxEventKind::SubtreePropagate,
            21,
            "op-1",
            &intent_payload_json(20, 30, 7),
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("org_scope.propagate_intent_tenant_mismatch"));
        // 非法载荷（零 revision）→ 类型合同校验拒绝。
        let error = validated_completion_payload(
            OrgOutboxEventKind::SubtreePropagate,
            20,
            "op-1",
            &intent_payload_json(20, 30, 0),
        )
        .unwrap_err();
        assert!(error.to_string().contains("org_scope.invalid_field"));
    }

    #[test]
    fn completion_payload_gate_binds_dependency_payload_and_flags_drain_proof() {
        let payload = OrgDependencyPropagatePayload {
            anchor_tenant_id: 20,
            root_tenant_id: 10,
            generation: 7,
            revoke_fence: 0,
            relationship_revision: 4,
        };
        let encoded = serde_json::to_string(&payload).unwrap();
        assert!(matches!(
            validated_completion_payload(
                OrgOutboxEventKind::DependencyPropagate,
                20,
                "ignored-operation-binding",
                &encoded,
            )
            .unwrap(),
            Some(CompletionPropagationPayload::Dependency(value)) if value == payload
        ));
        let error = validated_completion_payload(
            OrgOutboxEventKind::DependencyPropagate,
            21,
            "op-1",
            &encoded,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("dependency_propagate_intent_tenant_mismatch"));
    }

    #[test]
    fn completion_payload_gate_binds_membership_operation_to_event() {
        // 合法：载荷 operation_id 与事件行一致（两者由同一 source mutation
        // 写入，mutations.rs 两个入队点同值）→ durable 溯源绑定成立。
        assert!(validated_completion_payload(
            OrgOutboxEventKind::MembershipChanged,
            20,
            "op-m-1",
            &membership_payload_json(20)
        )
        .unwrap()
        .is_none());
        // 载荷 operation_id 与事件行不一致 → 溯源绑定失败，fail-closed
        // （绝不静默完成伪造/漂移载荷）。
        let error = validated_completion_payload(
            OrgOutboxEventKind::MembershipChanged,
            20,
            "op-other",
            &membership_payload_json(20),
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("org_scope.complete_payload_operation_mismatch"));
        // 机码稳定：operator 对账检索入口，漂移必须在此显式失败。
        assert_eq!(
            ORG_COMPLETE_PAYLOAD_OPERATION_MISMATCH_CODE,
            "code=org_scope.complete_payload_operation_mismatch"
        );
        // SUBTREE 载荷类型刻意不含 operation_id：operation 参数不参与其绑定，
        // 完成证明以锁定事件行 operation_id 查询标记。
        assert!(validated_completion_payload(
            OrgOutboxEventKind::SubtreePropagate,
            20,
            "op-any-value",
            &intent_payload_json(20, 30, 7)
        )
        .is_ok());
    }

    #[test]
    fn outbox_lock_sql_exposes_payload_and_completion_sql_keeps_lease_fences() {
        // 完成路径的租约锁 SELECT 必须暴露 payload_json（complete_outbox_event
        // 在 DONE 前要装载行内载荷做类型/租户/操作绑定，列漂移会在运行期
        // ColumnNotFound）；同一条 SQL 也服务 fail/编译装载路径，多列无副作用。
        assert!(OUTBOX_LOCK_LEASED_SQL.contains("payload_json"));
        // publication 驱动路径的终态 UPDATE 必须自带**未过期**租约栅栏
        // （租约过期后绝不 ACK）+ 精确 event_kind 条件（种类漂移绝不终态化）；
        // kind 限定完成路径同型。
        assert!(OUTBOX_COMPLETE_SQL.contains("lease_expires_at > UTC_TIMESTAMP(6)"));
        assert!(OUTBOX_COMPLETE_SQL.contains("AND event_kind = ?"));
        assert!(OUTBOX_COMPLETE_KIND_SCOPED_SQL.contains("lease_expires_at > UTC_TIMESTAMP(6)"));
        assert!(OUTBOX_COMPLETE_KIND_SCOPED_SQL.contains("AND event_kind = ?"));
    }

    #[test]
    fn fail_backoff_must_be_non_negative() {
        // 负值会把 durable next_attempt_at 调度到过去（TIMESTAMPADD 负偏移），
        // 把退避语义退化为立即回收热循环；必须在任何 durable 调度写之前
        // fail-closed。
        assert!(validated_fail_backoff_seconds(0).is_ok());
        assert!(validated_fail_backoff_seconds(30).is_ok());
        assert!(validated_fail_backoff_seconds(i64::MAX).is_ok());
        let error = validated_fail_backoff_seconds(-1).unwrap_err();
        assert!(error
            .to_string()
            .contains("code=org_scope.invalid_backoff_seconds"));
    }

    #[test]
    fn propagation_kind_gate_accepts_only_subtree_propagate() {
        assert!(validated_propagation_kind(OrgOutboxEventKind::SubtreePropagate).is_ok());
        for kind in OrgOutboxEventKind::ALL {
            if kind == OrgOutboxEventKind::SubtreePropagate {
                continue;
            }
            let error = validated_propagation_kind(kind).unwrap_err();
            assert!(error
                .to_string()
                .contains("org_scope.propagate_event_kind_invalid"));
        }
    }

    #[test]
    fn completion_kind_gate_and_publication_classifier_are_exact_complements() {
        for kind in OrgOutboxEventKind::ALL {
            let completion = validated_completion_kind(kind);
            let publish = publication_required_kind(kind.as_str());
            assert_ne!(
                completion.is_ok(),
                publish.is_ok(),
                "kind {} must take exactly one consumption path",
                kind.as_str()
            );
            if let Err(error) = completion {
                assert!(error
                    .to_string()
                    .contains("org_scope.outbox_complete_kind_forbidden"));
                assert_eq!(publish.unwrap(), kind);
            } else {
                assert!(publish
                    .unwrap_err()
                    .to_string()
                    .contains("org_scope.publish_kind_forbidden"));
            }
        }
        // 未知/小写/带空白种类：两条路径都确定性拒绝（projector 有限 fail）。
        for unknown in ["MEMBERSHIP_UPDATED", "node_created", "NODE_CREATED ", ""] {
            let error = publication_required_kind(unknown).unwrap_err();
            assert!(error
                .to_string()
                .contains("org_scope.outbox_event_kind_unknown"));
        }
    }

    #[test]
    fn propagated_topology_update_advances_all_three_counters() {
        // 决策冻结：传播式关系失效与 source 级 NODE_ATTACH/MOVE/DETACH 同一
        // 合同——generation、relationship_revision、revoke_fence 同步 +1。
        // 任何拆散该耦合的改动必须在此显式失败，并重新审查读侧失效信号。
        assert!(SUBTREE_UPDATE_SQL.contains("generation = generation + 1"));
        assert!(SUBTREE_UPDATE_SQL.contains("relationship_revision = relationship_revision + 1"));
        assert!(SUBTREE_UPDATE_SQL.contains("revoke_fence = revoke_fence + 1"));
    }

    // ───────────────────────────────────────────────────────────────────────
    // 扇出批引用模型（SUBTREE_SELECT_PROPAGATION_CHILDREN_SQL +
    // SUBTREE_UPDATE_SQL + child-intent 追加的纯快照模型）：锁定宽兄弟/同 root
    // 收敛语义与 durable 标记幂等，防止回归到“updated 子节点前沿”语义。
    // ───────────────────────────────────────────────────────────────────────

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct ModelNode {
        parent: Option<i64>,
        root: i64,
        active: bool,
    }

    /// 选中 = 锚点直接 active 子节点 ∩ 未以本操作 id 标记者，升序、至多
    /// batch_limit（不依赖 root 不等：同 root 后代同样被选中失效）。
    fn propagation_batch_model(
        nodes: &BTreeMap<i64, ModelNode>,
        marked: &BTreeSet<i64>,
        anchor: i64,
        batch_limit: usize,
    ) -> Vec<i64> {
        let mut selected: Vec<i64> = nodes
            .iter()
            .filter(|(tenant_id, node)| {
                node.parent == Some(anchor) && node.active && !marked.contains(tenant_id)
            })
            .map(|(tenant_id, _)| *tenant_id)
            .collect();
        selected.sort_unstable();
        selected.truncate(batch_limit);
        selected
    }

    /// 推进一步（UPDATE + durable 标记 + child intent 派生）：root 置目标
    /// （即使已相同）。
    fn apply_propagation(
        nodes: &mut BTreeMap<i64, ModelNode>,
        marked: &mut BTreeSet<i64>,
        updated: &[i64],
        new_root: i64,
    ) -> Vec<i64> {
        for tenant_id in updated {
            let node = nodes.get_mut(tenant_id).expect("selected node exists");
            node.root = new_root;
            marked.insert(*tenant_id);
        }
        updated.to_vec()
    }

    #[test]
    fn wide_sibling_fanout_converges_with_markers_and_same_root_children() {
        let new_root = 30i64;
        let batch_limit = 2usize;
        let mut nodes: BTreeMap<i64, ModelNode> = BTreeMap::new();
        // 同 root MOVE 场景：锚点与其全部后代 root **已经**等于目标（旧 root
        // 不等谓词会永远跳过它们、后代依赖钉永久陈旧）；标记模型必须照样选中。
        nodes.insert(
            10,
            ModelNode {
                parent: None,
                root: new_root,
                active: true,
            },
        );
        let mut all_descendants = BTreeSet::new();
        for child in [20i64, 21, 22] {
            nodes.insert(
                child,
                ModelNode {
                    parent: Some(10),
                    root: new_root,
                    active: true,
                },
            );
            all_descendants.insert(child);
            for grandchild in [child * 10, child * 10 + 1] {
                nodes.insert(
                    grandchild,
                    ModelNode {
                        parent: Some(child),
                        root: new_root,
                        active: true,
                    },
                );
                all_descendants.insert(grandchild);
            }
        }
        let mut marked = BTreeSet::new();
        let mut child_intents = BTreeSet::new();
        let mut queue: VecDeque<i64> = VecDeque::new();
        queue.push_back(10);
        let mut root_event_updated_lens: Vec<usize> = Vec::new();
        while let Some(anchor) = queue.pop_front() {
            loop {
                let selected = propagation_batch_model(&nodes, &marked, anchor, batch_limit);
                let intents_now = apply_propagation(&mut nodes, &mut marked, &selected, new_root);
                for intent in &intents_now {
                    if child_intents.insert(*intent) {
                        queue.push_back(*intent);
                    }
                }
                if anchor == 10 {
                    root_event_updated_lens.push(selected.len());
                }
                if selected.len() < batch_limit {
                    break;
                }
            }
        }
        // 宽兄弟完整性：3 个直接子节点 + 6 个孙节点全部失效一次，无遗漏分支。
        assert_eq!(marked, all_descendants);
        // 根事件第 1 批推进 2 个（done=false，next_frontier=[锚点]），第 2 批
        // 推进剩余 1 个并 done（batch=2 的精确满批排空语义）。
        assert_eq!(root_event_updated_lens, vec![2, 1]);
        // 每个被推进子节点恰好派生一个 child intent。
        assert_eq!(child_intents, all_descendants);
        // 重试幂等：durable 标记下再次 drain 不选中、不重复扇出。
        assert!(propagation_batch_model(&nodes, &marked, 10, batch_limit).is_empty());
    }

    #[test]
    fn cross_root_fanout_converges_and_rehomed_or_inactive_children_are_excluded() {
        let new_root = 30i64;
        let mut nodes: BTreeMap<i64, ModelNode> = BTreeMap::new();
        nodes.insert(
            10,
            ModelNode {
                parent: None,
                root: new_root,
                active: true,
            },
        );
        // 20：陈旧（root=99）→ 选中；21：已被更新的 MOVE rehome 到 77 名下
        // （父边离开锚点，归更新意图所有）→ 不可选；22：inactive → 永不选中。
        nodes.insert(
            20,
            ModelNode {
                parent: Some(10),
                root: 99,
                active: true,
            },
        );
        nodes.insert(
            21,
            ModelNode {
                parent: Some(77),
                root: 77,
                active: true,
            },
        );
        nodes.insert(
            22,
            ModelNode {
                parent: Some(10),
                root: 99,
                active: false,
            },
        );
        nodes.insert(
            77,
            ModelNode {
                parent: None,
                root: 77,
                active: true,
            },
        );
        let mut marked = BTreeSet::new();
        let selected = propagation_batch_model(&nodes, &marked, 10, 10);
        assert_eq!(selected, vec![20]);
        apply_propagation(&mut nodes, &mut marked, &selected, new_root);
        // 重试凭 durable 标记跳过已推进子节点。
        assert!(propagation_batch_model(&nodes, &marked, 10, 10).is_empty());
    }

    #[test]
    fn claim_budget_exhaustion_complements_the_fail_side_retry_predicate() {
        // fail_outbox_event 的重试判定是 `attempts < max_attempts`；claim 侧
        // 终态判定必须恰好是其补集：同一预算下，认领侧绝不把 fail 侧仍会
        // 重试的事件提前终态化，预算耗尽后也不再产生新的认领。
        for max_attempts in [1i64, 2, 5, 64] {
            for attempts in 0..=(max_attempts + 2) {
                let exhausted = claim_attempts_budget_exhausted(attempts, max_attempts);
                assert_eq!(exhausted, attempts >= max_attempts);
            }
        }
        // 边界：预算 = 1 意味着事件只允许一次认领（attempts=0 可认领；
        // attempts=1 的到期/过期候选直接终态化，绝不二次回收）。
        assert!(!claim_attempts_budget_exhausted(0, 1));
        assert!(claim_attempts_budget_exhausted(1, 1));
    }

    #[test]
    fn claim_budget_machine_code_is_stable() {
        // 机码是 operator 对账检索入口（last_error 落库），与租约丢失机码
        // 同层级，任何漂移都必须在此显式失败。
        assert_eq!(
            ORG_OUTBOX_CLAIM_BUDGET_EXHAUSTED_CODE,
            "code=org_scope.outbox_claim_budget_exhausted"
        );
    }

    #[test]
    fn claim_budget_must_be_positive() {
        // 预算 ≤ 0 会让每条到期候选在首次 claim 时就被终态化（attempts >= 0
        // 恒真），入口必须以 positive_i64 fail-closed 拒绝。
        assert!(positive_i64(1, "max_attempts").is_ok());
        assert!(positive_i64(i64::MAX, "max_attempts").is_ok());
        assert!(positive_i64(0, "max_attempts").is_err());
        assert!(positive_i64(-5, "max_attempts").is_err());
    }

    // ───────────────────────────────────────────────────────────────────────
    // P1：编译输入授权装载（GRANT_COMPILE_INPUT_PREDICATE_SQL）纯模型回归。
    // `org_scope_grant` 是 current-row 状态（durable 历史在
    // `org_scope_revision`）：跨 root MOVE/DETACH 原地撤销后遗留的旧 root 行
    // 与 inactive 墓碑不得进入编译输入——否则 `OrgCompileInput::validate` 的
    // root 绑定永久失败（后代永久 PENDING/FAILED 的可用性阻断），墓碑还会
    // 耗尽容量。编译器合同（policy-engine `org_compiler.rs`）：`resolve_unit`
    // 只消费输入内 grant 且跳过 inactive；`derive_ledgers` 对缺席 grant 移除
    // 账本并标 affected keys；mask 与实际 contribution provenance 对账、目标
    // 缺席 = 无操作——墓碑不是输入必需品，过滤不损失当前 root 授权事实。
    // ───────────────────────────────────────────────────────────────────────

    /// 与 [`GRANT_COMPILE_INPUT_PREDICATE_SQL`] 逐字对应的纯模型过滤器
    /// （`receiving_tenant_id` 绑定由查询参数承担；模型只裁 active+root）。
    fn compile_grant_loader_model(grants: &[OrgGrant], node_root_tenant_id: i64) -> Vec<OrgGrant> {
        grants
            .iter()
            .filter(|grant| grant.active && grant.root_tenant_id == node_root_tenant_id)
            .cloned()
            .collect()
    }

    fn p1_uuid(last: char) -> String {
        format!("00000000-0000-0000-0000-00000000000{last}")
    }

    fn p1_root_node(tenant_id: i64) -> OrgNode {
        OrgNode {
            tenant_id,
            root_tenant_id: tenant_id,
            parent_tenant_id: None,
            generation: 1,
            revoke_fence: 0,
            relationship_revision: 1,
            active: true,
            operation_id: "op-p1-root".into(),
            root_activation: Some(OrgRootActivation {
                operator_user_id: 7,
                approval_operation_id: "op-approve-root".into(),
            }),
        }
    }

    fn p1_child_node(parent_tenant_id: i64, root_tenant_id: i64) -> OrgNode {
        OrgNode {
            tenant_id: 20,
            root_tenant_id,
            parent_tenant_id: Some(parent_tenant_id),
            generation: 1,
            revoke_fence: 0,
            relationship_revision: 1,
            active: true,
            operation_id: "op-p1-child".into(),
            root_activation: None,
        }
    }

    fn p1_scope(resource_tenant_id: i64) -> OrgScope {
        OrgScope {
            resource_tenant_id,
            domain_id: None,
            resource: "doc:42".into(),
            action: "read".into(),
            validity: ValidityWindow::perpetual(),
        }
    }

    fn p1_grant(
        last: char,
        receiving_tenant_id: i64,
        origin_tenant_id: i64,
        root_tenant_id: i64,
        parent: Option<OrgGrantRef>,
        active: bool,
        revision: u64,
    ) -> OrgGrant {
        // 资源租户 V1 恒等授予方租户（与 policy-engine child_scope 同语义）。
        let scope = p1_scope(origin_tenant_id);
        OrgGrant {
            grant_id: p1_uuid(last),
            revision,
            receiving_tenant_id,
            origin_tenant_id,
            root_tenant_id,
            scope,
            delegable: parent.is_none(),
            parent,
            subject: None,
            active,
            operation_id: format!("op-grant-{last}"),
        }
    }

    fn p1_parent_contribution_ref() -> OrgGrantRef {
        OrgGrantRef {
            tenant_id: 10,
            grant_id: p1_uuid('a'),
            revision: 1,
        }
    }

    fn p1_parent_publication() -> OrgPublication {
        // 父单元（10，root 10）持可授予贡献 P1：编译出 pinned 父 publication。
        let p1 = p1_grant('a', 10, 10, 10, None, true, 1);
        let input = OrgCompileInput {
            node: p1_root_node(10),
            dependencies: Vec::new(),
            parent_publications: Vec::new(),
            grants: vec![p1],
            masks: Vec::new(),
            operation_id: "op-p1-compile-parent".into(),
        };
        match OrgCompiler::new().compile_full(&input).unwrap() {
            OrgCompileOutcome::Applied(state) => state.to_publication().unwrap(),
            OrgCompileOutcome::Pending { report, .. } => {
                panic!("parent unit must compile applied: {report:?}")
            }
        }
    }

    fn p1_child_input(
        root_tenant_id: i64,
        parent_publication: &OrgPublication,
        grants: Vec<OrgGrant>,
    ) -> OrgCompileInput {
        let dependency = OrgDependency {
            tenant_id: parent_publication.tenant_id,
            generation: parent_publication.generation,
            revoke_fence: parent_publication.revoke_fence,
            relationship_revision: parent_publication.relationship_revision,
        };
        OrgCompileInput {
            node: p1_child_node(parent_publication.tenant_id, root_tenant_id),
            dependencies: vec![dependency],
            parent_publications: vec![parent_publication.clone()],
            grants,
            masks: Vec::new(),
            operation_id: "op-p1-compile-child".into(),
        }
    }

    fn p1_applied(outcome: OrgCompileOutcome) -> policy_engine::OrgCompiledState {
        match outcome {
            OrgCompileOutcome::Applied(state) => state,
            OrgCompileOutcome::Pending { report, .. } => {
                panic!("expected Applied, got pending: {report:?}")
            }
        }
    }

    #[test]
    fn compile_grant_loader_model_excludes_historical_rows() {
        // 当前 root（10）下的活跃授权：唯一合法输入行。
        let current = p1_grant('b', 20, 10, 10, Some(p1_parent_contribution_ref()), true, 1);
        // 旧 root（99）时代遗留：原地撤销后的墓碑 + 防御性的 active 残留
        // （source 路径不可达——MOVE 是单事务原子撤销+重挂；谓词必须照样排除）。
        let old_ref = OrgGrantRef {
            tenant_id: 50,
            grant_id: p1_uuid('f'),
            revision: 1,
        };
        let old_root_tombstone = p1_grant('c', 20, 50, 99, Some(old_ref.clone()), false, 2);
        let old_root_active = p1_grant('d', 20, 50, 99, Some(old_ref), true, 2);
        // 当前 root 下的 inactive 墓碑（本 root 内正常撤销产物）。
        let current_root_tombstone = p1_grant(
            'e',
            20,
            10,
            10,
            Some(p1_parent_contribution_ref()),
            false,
            2,
        );
        // 修复前装载（无谓词）：旧 root 行触发 root 绑定 → validate 永久失败。
        let unfiltered = vec![
            old_root_active.clone(),
            old_root_tombstone,
            current_root_tombstone,
            current.clone(),
        ];
        let parent_publication = p1_parent_publication();
        let error = p1_child_input(10, &parent_publication, unfiltered.clone())
            .validate()
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("must carry the node authority root"),
            "unexpected validate error: {error}"
        );

        // 修复后装载：谓词只放行当前 root 下活跃行。
        let filtered = compile_grant_loader_model(&unfiltered, 10);
        assert_eq!(filtered, vec![current]);
        p1_child_input(10, &parent_publication, filtered)
            .validate()
            .expect("active current-root grants are the only legitimate compile input");

        // 旧 root 行"复活"的唯一途径：node.root 回到该 root **且**行经已批准
        // source 授权生命周期重新 active（root_tenant_id 行内不可变，见
        // `org_grant_revision_compatible`）——那是当前状态的合法输入，而非陈旧
        // 残留；node.root 在其它 root 时谓词永远排除这些行。
        assert!(compile_grant_loader_model(&[old_root_active], 10).is_empty());
        // 谓词 SQL 与模型过滤器逐字对应，漂移必须显式失败。
        assert_eq!(
            GRANT_COMPILE_INPUT_PREDICATE_SQL,
            "receiving_tenant_id = ? AND active = 1 AND root_tenant_id = ?"
        );
    }

    #[test]
    fn return_to_old_root_never_restores_old_grant_contributions() {
        // 分支 20 往返：根 A=10 → 根 B=99 → 回到根 A=10。行状态按 source 生命
        // 周期迁移（每次 revoke/issue 都有已批准 source mutation + revision 账；
        // 本测试验证装载谓词与编译器输出，不重复 source 语义）：A 时代 G_A 被
        // A→B MOVE 原地撤销（active=0、revision 前进、root 行内不变）；B 时代
        // 新发 G_B（root 99）；B→A MOVE 撤销 G_B，node.root 回到 10。
        let parent_publication = p1_parent_publication();
        let g_a_revoked = p1_grant(
            'b',
            20,
            10,
            10,
            Some(p1_parent_contribution_ref()),
            false,
            2,
        );
        let b_ref = OrgGrantRef {
            tenant_id: 50,
            grant_id: p1_uuid('f'),
            revision: 1,
        };
        let g_b_revoked = p1_grant('c', 20, 50, 99, Some(b_ref.clone()), false, 2);
        let rows = vec![g_a_revoked.clone(), g_b_revoked];

        // 修复前装载（无谓词）：旧行进入输入 → root 绑定永久失败（P1 阻断）。
        let error = p1_child_input(10, &parent_publication, rows.clone())
            .validate()
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("must carry the node authority root"),
            "unexpected validate error: {error}"
        );

        // 修复后装载：谓词排除全部 inactive/旧 root 行 → 输入无任何授权 →
        // 编译 Applied 且生效贡献为空：旧 G_A 绝不复活为 ALLOW（无授权即无
        // 准入放行，绝不静默恢复）。
        let filtered = compile_grant_loader_model(&rows, 10);
        assert!(filtered.is_empty());
        let state = p1_applied(
            OrgCompiler::new()
                .compile_full(&p1_child_input(10, &parent_publication, filtered))
                .unwrap(),
        );
        assert!(state.effective.is_empty());
        assert!(state.grant_ledger.is_empty());
        let publication = state.to_publication().unwrap();
        assert!(!publication.contains_grant(&OrgGrantRef {
            tenant_id: 20,
            grant_id: p1_uuid('b'),
            revision: 2
        }));

        // 防御纵深：即使 B 时代行异常残留为 active（source 路径不可达），
        // root 谓词也绝不把它装进 root 10 的输入。
        let stale_b_active = p1_grant('c', 20, 50, 99, Some(b_ref), true, 2);
        assert!(compile_grant_loader_model(&[g_a_revoked.clone(), stale_b_active], 10).is_empty());

        // 恢复授权只能走新的已批准 source grant：在 A 下重新签发（新行，
        // parent ref 仍精确 P1 rev 1）→ 谓词放行 → 编译出恰好一条生效贡献；
        // 被撤销的旧行永不自动回流。
        let g_a2 = p1_grant('d', 20, 10, 10, Some(p1_parent_contribution_ref()), true, 1);
        let filtered2 = compile_grant_loader_model(&[g_a_revoked, g_a2.clone()], 10);
        assert_eq!(filtered2, vec![g_a2.clone()]);
        let state2 = p1_applied(
            OrgCompiler::new()
                .compile_full(&p1_child_input(10, &parent_publication, filtered2))
                .unwrap(),
        );
        assert_eq!(state2.effective.len(), 1);
        let publication2 = state2.to_publication().unwrap();
        assert!(publication2.contains_grant(&OrgGrantRef {
            tenant_id: 20,
            grant_id: p1_uuid('d'),
            revision: 1
        }));
    }
}
