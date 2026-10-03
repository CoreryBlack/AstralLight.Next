//! ORG_SCOPE 审批请求生命周期与审批调度。
//!
//! 合同要点：
//! - 行政关系（root/attach/move/detach）与跨租户 grant 的 source of truth 是
//!   **经批准的治理 mutation**；终端请求或单方目录修改不能自行宣布独立。
//! - approve 在**同一 source 短事务**内：锁定请求行 → CAS PENDING→APPROVED →
//!   按种类执行变更内核（锁定读复验上级持权/delegable/精确 revision/同 root/
//!   作用域包含/环检查）→ revision + outbox + 审计 → outcome 落账。
//! - **治理准入证明**（`OrgGovernanceProof`）：ROOT_INIT / ROOT_GRANT 的审批
//!   **与驳回**必须携带显式证明——root-init 专用 registered meta-permission 对 +
//!   PolicyEngine/服务授权上下文的稳定 admission operation id + 精确批准能力范
//!   围。无证明、元权限不匹配（非注册对）或能力范围不能覆盖待发 scope 时
//!   fail-closed，不落任何 durable 写（驳回权与审批权同界，杜绝任意签名用户
//!   驳回根请求的拒绝服务面）。
//!   DB 层校验存在性/结构/范围绑定并 durable 落审计；证明真实性由
//!   API/PolicyEngine 边界保证（main 接线）。
//! - 新租户 bootstrap 不经普通 create 获得初始 grants：ROOT_INIT 的
//!   initial_grants 逐项绑定审批证明的 approved_capability，且根 node 持久化
//!   `OrgRootActivation`（operator + approval operation）。
//! - 并发锁序：先无锁规划（走链收集 id），再按 tenant_id 升序一次锁定，锁后
//!   复走校验；链在规划与锁定之间漂移时返回可重试错误（请求保持 PENDING）。
//! - **actor/决策租户结构绑定**：create 复核提交方租户与 payload requester
//!   一致（服务层一律以签名 actor tenant 派生 requester）；approve/reject 复核
//!   决策人租户——ATTACH/MOVE 为载荷对侧父租户，GRANT/DETACH 为锁定态下
//!   请求方当前直接行政父（禁止同根兄弟/祖父跳级），ROOT_INIT/ROOT_GRANT
//!   凭治理元能力、服务层无租户归属保证，DB 层不虚构租户约束。

use serde::{Deserialize, Serialize};
use sqlx::Row;

use super::mutations::{
    append_audit_in_tx, append_outbox_event_in_tx, append_revision_in_tx, claim_operation_in_tx,
    grant_scope, lock_grant_in_tx, record_operation_outcome_in_tx,
    revoke_received_grants_from_old_root_in_tx, typed_grant, OperationClaim, OrgAuditWrite,
    NODE_ATTACH_SQL, NODE_DETACH_SQL, NODE_INSERT_SQL, NODE_MOVE_SQL, NODE_ROOT_ACTIVATION_SQL,
};
use super::*;
use astral_types::org_scope::{
    OrgDependencyPropagatePayload, OrgGrantSeed, OrgRequestPayload, OrgSubtreePropagatePayload,
    MAX_ORG_ROOT_INIT_GRANTS,
};

// ─────────────────────────────────────────────────────────────────────────────
// 命令 / 结果
// ─────────────────────────────────────────────────────────────────────────────

/// 治理准入证明（ROOT_INIT/ROOT_GRANT 审批必备）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgGovernanceProof {
    /// 注册的 root-init 专用 meta-permission 资源；必须精确等于
    /// `org_authority_edge`（DB 层精确复核，非注册取值 fail-closed）。
    pub permission_resource: String,
    /// 注册的 meta-permission 动作；必须精确等于 `bootstrap`。
    pub permission_action: String,
    /// PolicyEngine ALLOW / 服务授权上下文的稳定 admission operation id。
    pub admission_operation_id: String,
    /// 经本次 PolicyEngine 检查的能力范围；每项待发 scope 必须至少由其中一项覆盖。
    /// ROOT_INIT 可以发放多个不相交的资源范围，因此不能伪造为一个更宽泛的 scope。
    pub approved_capabilities: Vec<OrgScope>,
}

/// 创建审批请求命令。
#[derive(Debug, Clone, Serialize)]
pub struct OrgCreateRequestCommand {
    pub operation_id: String,
    pub actor_user_id: i64,
    pub actor_tenant_id: Option<i64>,
    pub payload: OrgRequestPayload,
}

/// 审批命令。
#[derive(Debug, Clone, Serialize)]
pub struct OrgApproveCommand {
    pub request_id: i64,
    pub expected_revision: u64,
    pub approver_user_id: i64,
    pub approver_tenant_id: Option<i64>,
    pub operation_id: String,
    pub note: Option<String>,
    /// ROOT_INIT/ROOT_GRANT 必填；其他种类忽略（结构资格由内核复验）。
    pub governance_proof: Option<OrgGovernanceProof>,
}

/// 驳回命令。
#[derive(Debug, Clone, Serialize)]
pub struct OrgRejectCommand {
    pub request_id: i64,
    pub expected_revision: u64,
    pub approver_user_id: i64,
    pub approver_tenant_id: Option<i64>,
    pub operation_id: String,
    pub note: Option<String>,
    /// ROOT_INIT/ROOT_GRANT 必填（驳回权与审批权同界）；其他种类忽略。
    pub governance_proof: Option<OrgGovernanceProof>,
}

/// 请求人撤销命令。
#[derive(Debug, Clone, Serialize)]
pub struct OrgCancelCommand {
    pub request_id: i64,
    pub expected_revision: u64,
    pub actor_user_id: i64,
    pub actor_tenant_id: Option<i64>,
    pub operation_id: String,
    pub note: Option<String>,
}

/// 创建请求结果。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrgRequestOutcome {
    pub request_id: i64,
    pub operation_id: String,
    pub replayed: bool,
}

/// 请求视图。
#[derive(Debug, Clone)]
pub struct OrgRequestView {
    pub request_id: i64,
    pub request_kind: String,
    pub requester_tenant_id: i64,
    pub requester_user_id: i64,
    pub target_tenant_id: i64,
    pub parent_tenant_id: Option<i64>,
    pub status: String,
    pub revision: u64,
    pub payload: OrgRequestPayload,
    pub decided_by: Option<i64>,
    pub decision_note: Option<String>,
    pub created_at_unix: Option<i64>,
    pub decided_at_unix: Option<i64>,
}

// ─────────────────────────────────────────────────────────────────────────────
// SQL
// ─────────────────────────────────────────────────────────────────────────────

const REQUEST_INSERT_SQL: &str = "INSERT INTO org_scope_request \
     (request_kind, requester_tenant_id, requester_user_id, target_tenant_id, parent_tenant_id, \
      payload_json, status, operation_id, operation_digest) \
     VALUES (?, ?, ?, ?, ?, ?, 'PENDING', ?, ?)";
const REQUEST_LOCK_SQL: &str = "SELECT request_id, request_kind, requester_tenant_id, \
     requester_user_id, target_tenant_id, parent_tenant_id, payload_json, status, revision, decided_by, \
     decision_note, CAST(UNIX_TIMESTAMP(created_at) AS SIGNED) as created_at_unix, \
     CAST(UNIX_TIMESTAMP(decided_at) AS SIGNED) as decided_at_unix \
     FROM org_scope_request WHERE request_id = ? FOR UPDATE";
const REQUEST_SELECT_SQL: &str = "SELECT request_id, request_kind, requester_tenant_id, \
     requester_user_id, target_tenant_id, parent_tenant_id, payload_json, status, revision, decided_by, \
     decision_note, CAST(UNIX_TIMESTAMP(created_at) AS SIGNED) as created_at_unix, \
     CAST(UNIX_TIMESTAMP(decided_at) AS SIGNED) as decided_at_unix \
     FROM org_scope_request WHERE request_id = ?";
const REQUEST_DECIDE_SQL: &str =
    "UPDATE org_scope_request SET status = ?, revision = revision + 1, \
     decided_by = ?, decided_at = UTC_TIMESTAMP(6), decision_note = ? \
     WHERE request_id = ? AND status = 'PENDING' AND revision = ?";

const GRANT_INSERT_SQL: &str = "INSERT INTO org_scope_grant \
     (grant_id, revision, receiving_tenant_id, origin_tenant_id, root_tenant_id, \
      resource_tenant_id, domain_id, resource, action, valid_from, valid_until, delegable, \
      parent_tenant_id, parent_grant_id, parent_grant_revision, subject_kind, subject_user_id, \
      subject_card_id, active, operation_id) \
     VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)";

// ─────────────────────────────────────────────────────────────────────────────
// payload 派生
// ─────────────────────────────────────────────────────────────────────────────

fn target_of(payload: &OrgRequestPayload) -> i64 {
    match payload {
        OrgRequestPayload::RootInit { root_tenant_id, .. }
        | OrgRequestPayload::RootGrant { root_tenant_id, .. } => *root_tenant_id,
        OrgRequestPayload::Attach {
            child_tenant_id, ..
        }
        | OrgRequestPayload::Move {
            child_tenant_id, ..
        }
        | OrgRequestPayload::Detach { child_tenant_id } => *child_tenant_id,
        OrgRequestPayload::Grant {
            receiving_tenant_id,
            ..
        } => *receiving_tenant_id,
    }
}

fn parent_of(payload: &OrgRequestPayload) -> Option<i64> {
    match payload {
        OrgRequestPayload::Attach {
            parent_tenant_id, ..
        }
        | OrgRequestPayload::Move {
            new_parent_tenant_id: parent_tenant_id,
            ..
        } => Some(*parent_tenant_id),
        OrgRequestPayload::Grant { parent_grant, .. } => Some(parent_grant.tenant_id),
        _ => None,
    }
}

fn requester_of(payload: &OrgRequestPayload) -> i64 {
    match payload {
        OrgRequestPayload::RootInit { root_tenant_id, .. }
        | OrgRequestPayload::RootGrant { root_tenant_id, .. } => *root_tenant_id,
        OrgRequestPayload::Attach {
            child_tenant_id, ..
        }
        | OrgRequestPayload::Move {
            child_tenant_id, ..
        }
        | OrgRequestPayload::Detach { child_tenant_id } => *child_tenant_id,
        OrgRequestPayload::Grant {
            receiving_tenant_id,
            ..
        } => *receiving_tenant_id,
    }
}

fn payload_json_of(payload: &OrgRequestPayload) -> Result<String, AstralError> {
    serde_json::to_string(payload)
        .map_err(|error| AstralError::Internal(format!("org_scope payload serialize: {error}")))
}

/// Root genesis and root-origin grant issuance have no parent provenance that could prove a
/// foreign resource owner. Recheck this inside the approval transaction as well as at request
/// creation: a malformed/tampered durable request must roll back before its status CAS, source
/// grant, outbox, revision, or audit record can be committed.
fn require_root_source_scope(root_tenant_id: i64, scope: &OrgScope) -> Result<(), AstralError> {
    if scope.resource_tenant_id == root_tenant_id {
        Ok(())
    } else {
        Err(AstralError::Validation(
            "code=org_scope.root_source_resource_tenant_mismatch".into(),
        ))
    }
}

/// 入口载荷校验：类型合同校验 + DB 侧补充边界（先于任何 durable 写）。
fn validate_payload(payload: &OrgRequestPayload) -> Result<(), AstralError> {
    payload.validate().map_err(org_err)?;
    match payload {
        OrgRequestPayload::RootInit {
            root_tenant_id,
            initial_grants,
        } => {
            if initial_grants.len() > MAX_ORG_ROOT_INIT_GRANTS {
                return Err(AstralError::Validation(
                    "code=org_scope.root_init_grants_exceeded".into(),
                ));
            }
            // Root genesis is a permanent self-source contract: without parent
            // provenance, the signed root tenant must also own the root scope.
            // A separately verified resource-owner fact is not inferred from
            // the request body, directory topology, or financial relationships.
            for seed in initial_grants {
                require_root_source_scope(*root_tenant_id, &seed.scope)?;
            }
        }
        OrgRequestPayload::RootGrant {
            root_tenant_id,
            scope,
            ..
        } => {
            require_root_source_scope(*root_tenant_id, scope)?;
        }
        OrgRequestPayload::Grant { subject, .. } => {
            validated_subject(subject.as_ref())?;
        }
        _ => {}
    }
    Ok(())
}

/// ROOT_INIT/ROOT_GRANT 治理证明的**精确** meta-permission 对（root-init 专用
/// 注册对，冻结字面量）。与 service 层 `META_RESOURCE`/`META_ACTION_BOOTSTRAP`
/// （astral-trustgraph org_authorities）及 `ResourceRegistry` 登记的
/// `org_authority_edge` + `bootstrap` 保持一致；任何其他取值 fail-closed。
const GOVERNANCE_META_RESOURCE: &str = "org_authority_edge";
const GOVERNANCE_META_ACTION: &str = "bootstrap";

/// 决策备注 durable 上限（字节）：对齐 service 层 `bounded_note` 的 512 字节界
/// 与 `org_scope_request.decision_note VARCHAR(512)` 列宽。DB 侧在任何 durable
/// 写之前独立复核，不信任上游裁剪。
const DECISION_NOTE_MAX_BYTES: usize = 512;

/// 决策备注边界校验：超界拒绝（先于 digest/claim/任何 durable 写）。
fn validated_decision_note(note: Option<&str>) -> Result<(), AstralError> {
    match note {
        None => Ok(()),
        Some(note) => {
            if note.len() > DECISION_NOTE_MAX_BYTES {
                return Err(AstralError::Validation(
                    "code=org_scope.decision_note_too_long".into(),
                ));
            }
            Ok(())
        }
    }
}

/// 审批/驳回治理证明校验：ROOT_INIT/ROOT_GRANT 必须携带；meta-permission 必须
/// 精确等于注册对；能力范围必须覆盖待发 scope。返回证明引用供 durable 审计。
fn require_governance_proof<'a>(
    governance_proof: Option<&'a OrgGovernanceProof>,
    issued_scopes: &[&OrgScope],
) -> Result<&'a OrgGovernanceProof, AstralError> {
    let proof = governance_proof.ok_or_else(|| {
        AstralError::Permission(
            "code=org_scope.governance_proof_required;kind=root_authority".into(),
        )
    })?;
    if proof.permission_resource.trim() != GOVERNANCE_META_RESOURCE
        || proof.permission_action.trim() != GOVERNANCE_META_ACTION
    {
        return Err(AstralError::Permission(
            "code=org_scope.governance_proof_meta_permission_mismatch".into(),
        ));
    }
    validated_operation_id(&proof.admission_operation_id)?;
    let capabilities = &proof.approved_capabilities;
    if capabilities.is_empty() {
        return Err(AstralError::Permission(
            "code=org_scope.governance_proof_capability_required".into(),
        ));
    }
    for capability in capabilities {
        validated_scope(capability)?;
    }
    for scope in issued_scopes {
        // Each issued scope must be independently covered. A ROOT_INIT with
        // unrelated resources must not be represented by a fabricated broad
        // capability solely to satisfy a scalar proof field.
        if !capabilities
            .iter()
            .any(|capability| capability.covers(scope).is_ok())
        {
            return Err(AstralError::Permission(
                "code=org_scope.governance_proof_capability_exceeded".into(),
            ));
        }
    }
    Ok(proof)
}

/// 审批与驳回共用的载荷级证明要求（纯函数）：ROOT_INIT/ROOT_GRANT 必须携带
/// 结构合法且能力覆盖待发 scope 的治理证明（驳回权与审批权同界——DB 层独立
/// 复核，直接仓储调用不能凭上游 generic 路由权限驳回根请求）；其余 kind 无
/// 证明要求（`Ok(None)`，既有非根驳回行为保持不变）。
fn required_governance_proof<'a>(
    governance_proof: Option<&'a OrgGovernanceProof>,
    payload: &OrgRequestPayload,
) -> Result<Option<&'a OrgGovernanceProof>, AstralError> {
    match payload {
        OrgRequestPayload::RootInit { initial_grants, .. } => {
            let scopes: Vec<&OrgScope> = initial_grants.iter().map(|seed| &seed.scope).collect();
            require_governance_proof(governance_proof, &scopes).map(Some)
        }
        OrgRequestPayload::RootGrant { scope, .. } => {
            let scopes: [&OrgScope; 1] = [scope];
            require_governance_proof(governance_proof, &scopes).map(Some)
        }
        _ => Ok(None),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// actor / 决策租户结构绑定（纯函数；DB 侧独立复核，不信任上游授权推导）
// ─────────────────────────────────────────────────────────────────────────────

/// create 边界：提交方租户必须存在且等于 payload requester。服务层一律以签名
/// actor tenant 派生 requester（ROOT_* = root_tenant_id；ATTACH/MOVE/DETACH =
/// child_tenant_id；GRANT = receiving_tenant_id），本检查把该约束固化为 durable
/// 边界：直接仓储调用不能替其他租户提交请求。
fn validated_actor_tenant(
    actor_tenant_id: Option<i64>,
    requester_tenant_id: i64,
) -> Result<(), AstralError> {
    if actor_tenant_id != Some(requester_tenant_id) {
        return Err(AstralError::Permission(
            "code=org_scope.request_actor_tenant_mismatch".into(),
        ));
    }
    Ok(())
}

/// approve/reject 边界（载荷显式对侧）：ATTACH/MOVE 的决策权属于载荷对侧父
/// 租户。其余 kind 在此放行——GRANT/DETACH 归锁定态下的当前直接行政父
/// （变更内核 / reject 复核），ROOT_INIT/ROOT_GRANT 归治理元能力（服务层
/// `KindAuthority::RootMeta` 无租户归属约束，DB 层不虚构）。
fn require_counterparty_decider(
    approver_tenant_id: Option<i64>,
    payload: &OrgRequestPayload,
) -> Result<(), AstralError> {
    let counterparty = match payload {
        OrgRequestPayload::Attach {
            parent_tenant_id, ..
        } => *parent_tenant_id,
        OrgRequestPayload::Move {
            new_parent_tenant_id,
            ..
        } => *new_parent_tenant_id,
        _ => return Ok(()),
    };
    if approver_tenant_id != Some(counterparty) {
        return Err(AstralError::Permission(
            "code=org_scope.decide_not_counterparty_parent".into(),
        ));
    }
    Ok(())
}

/// approve/reject 边界（锁定态当前直接父）：GRANT/DETACH 的决策权属于请求方
/// **当前**直接行政父，在事务锁定读下重建；同根兄弟/祖父跳级、缺租户或
/// 无父态一律 fail-closed。
fn require_requesting_parent_decider(
    approver_tenant_id: Option<i64>,
    current_parent_tenant_id: Option<i64>,
) -> Result<(), AstralError> {
    match (approver_tenant_id, current_parent_tenant_id) {
        (Some(approver), Some(parent)) if approver == parent => Ok(()),
        _ => Err(AstralError::Permission(
            "code=org_scope.decide_not_requesting_parent".into(),
        )),
    }
}

/// ATTACH 既有 node 的旧根退休判定（纯函数；锁定态真值）。既有 node 已由前置
/// 检查保证 parentless ⟹ 必为独立行政根（root = 自身）：其自源 active grants
/// （`receiving = child AND root = former root`）必须在改挂拓扑**之前**整体
/// 撤销——否则该节点再次 detach（root 复原为自身）后，这些未经新批准的旧
/// grants 会凭编译输入的 root 过滤重新匹配而复活。返回值即撤销内核
/// `revoke_received_grants_from_old_root_in_tx` 的 `old_root_tenant_id` 实参。
/// brand-new 子分支（node 行尚不存在）不存在任何 grant 行——grant 创建路径
/// （ROOT_INIT/ROOT_GRANT/GRANT）全部要求 node 行已存在，故无需撤销。
/// 同根 reparent（MOVE）不经过本判定：MOVE/DETACH 的旧链撤销语义保持不变。
fn former_root_to_retire_on_attach(existing: &OrgNodeRow) -> Result<i64, AstralError> {
    if existing.parent_tenant_id.is_some() {
        return Err(AstralError::Validation(
            "code=org_scope.attach_requires_parentless_child".into(),
        ));
    }
    Ok(existing.root_tenant_id)
}

// ─────────────────────────────────────────────────────────────────────────────
// 请求行读取
// ─────────────────────────────────────────────────────────────────────────────
struct RequestLockedRow {
    request_id: i64,
    request_kind: String,
    requester_tenant_id: i64,
    requester_user_id: i64,
    target_tenant_id: i64,
    parent_tenant_id: Option<i64>,
    payload_json: String,
    status: String,
    revision: i64,
    decided_by: Option<i64>,
    decision_note: Option<String>,
    created_at_unix: Option<i64>,
    decided_at_unix: Option<i64>,
}

fn request_from_row(row: &sqlx::mysql::MySqlRow) -> Result<RequestLockedRow, AstralError> {
    Ok(RequestLockedRow {
        request_id: row.try_get("request_id").map_err(db_err)?,
        request_kind: row.try_get("request_kind").map_err(db_err)?,
        requester_tenant_id: row.try_get("requester_tenant_id").map_err(db_err)?,
        requester_user_id: row.try_get("requester_user_id").map_err(db_err)?,
        target_tenant_id: row.try_get("target_tenant_id").map_err(db_err)?,
        parent_tenant_id: row.try_get("parent_tenant_id").map_err(db_err)?,
        payload_json: row.try_get("payload_json").map_err(db_err)?,
        status: row.try_get("status").map_err(db_err)?,
        revision: row.try_get("revision").map_err(db_err)?,
        decided_by: row.try_get("decided_by").map_err(db_err)?,
        decision_note: row.try_get("decision_note").map_err(db_err)?,
        created_at_unix: row.try_get("created_at_unix").map_err(db_err)?,
        decided_at_unix: row.try_get("decided_at_unix").map_err(db_err)?,
    })
}

fn parse_payload(json: &str) -> Result<OrgRequestPayload, AstralError> {
    serde_json::from_str(json).map_err(|error| {
        AstralError::Database(format!(
            "code=org_scope.request_payload_unreadable;detail={error}"
        ))
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// 请求生命周期入口
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) async fn create_request(
    store: &SqlxOrgScopeRepository,
    cmd: &OrgCreateRequestCommand,
) -> Result<OrgRequestOutcome, AstralError> {
    validated_operation_id(&cmd.operation_id)?;
    positive_i64(cmd.actor_user_id, "actor_user_id")?;
    validate_payload(&cmd.payload)?;
    // actor-tenant 结构绑定：提交方租户必须与 payload requester 一致（服务层
    // 一律以签名 actor tenant 派生 requester；缺失或不一致 fail-closed，直接
    // 调用方不能替其他租户提交请求）。
    validated_actor_tenant(cmd.actor_tenant_id, requester_of(&cmd.payload))?;
    let payload_json = payload_json_of(&cmd.payload)?;
    let kind = cmd.payload.kind().as_str();
    let target = target_of(&cmd.payload);
    let parent = parent_of(&cmd.payload);
    let requester_tenant = requester_of(&cmd.payload);
    let canonical = serde_json::to_string(cmd)
        .map_err(|error| AstralError::Internal(format!("org_scope cmd serialize: {error}")))?;
    let digest = canonical_input_digest("REQUEST_CREATE", &canonical);

    let mut tx = begin_tx(store.pool()).await?;
    match claim_operation_in_tx(
        &mut tx,
        &cmd.operation_id,
        "REQUEST_CREATE",
        target,
        &digest,
    )
    .await?
    {
        OperationClaim::Replayed(mut value) => {
            tx.commit().await.map_err(db_err)?;
            // 幂等合同：回放返回首次 outcome，但必须向调用方标明 replayed=true。
            value["replayed"] = serde_json::Value::Bool(true);
            serde_json::from_value(value).map_err(|error| {
                AstralError::Database(format!(
                    "code=org_scope.replay_outcome_unreadable;detail={error}"
                ))
            })
        }
        OperationClaim::Fresh => {
            // 结构性预检（plain 读快速失败；审批内核在锁定读下复验）。
            structural_precheck_in_tx(&mut tx, &cmd.payload).await?;
            let result = sqlx::query(REQUEST_INSERT_SQL)
                .bind(kind)
                .bind(requester_tenant)
                .bind(cmd.actor_user_id)
                .bind(target)
                .bind(parent)
                .bind(&payload_json)
                .bind(&cmd.operation_id)
                .bind(&digest)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;
            if result.last_insert_id() == 0 {
                return Err(AstralError::Internal(
                    "org_scope request insert returned an unusable id".into(),
                ));
            }
            let request_id = result.last_insert_id() as i64;
            append_audit_in_tx(
                &mut tx,
                OrgAuditWrite {
                    tenant_id: target,
                    actor_user_id: cmd.actor_user_id,
                    actor_tenant_id: cmd.actor_tenant_id,
                    action: "REQUEST_CREATED",
                    subject_kind: "REQUEST",
                    subject_id: &request_id.to_string(),
                    request_id: Some(request_id),
                    operation_id: &cmd.operation_id,
                    detail_json: Some(payload_json.as_str()),
                },
            )
            .await?;
            let outcome = OrgRequestOutcome {
                request_id,
                operation_id: cmd.operation_id.clone(),
                replayed: false,
            };
            record_operation_outcome_in_tx(&mut tx, &cmd.operation_id, &outcome).await?;
            tx.commit().await.map_err(db_err)?;
            Ok(outcome)
        }
    }
}

/// 创建时快速失败的结构预检（不做任何 durable 写）。
async fn structural_precheck_in_tx(
    tx: &mut Transaction<'static, MySql>,
    payload: &OrgRequestPayload,
) -> Result<(), AstralError> {
    match payload {
        OrgRequestPayload::RootInit { root_tenant_id, .. } => {
            if load_node_in_tx(tx, *root_tenant_id).await?.is_some() {
                return Err(AstralError::Validation(
                    "code=org_scope.node_already_initialized".into(),
                ));
            }
        }
        OrgRequestPayload::RootGrant { root_tenant_id, .. } => {
            let node = load_node_required_in_tx(tx, *root_tenant_id).await?;
            if node.parent_tenant_id.is_some() {
                return Err(AstralError::Validation(
                    "code=org_scope.root_grant_requires_root_node".into(),
                ));
            }
        }
        OrgRequestPayload::Attach {
            child_tenant_id,
            parent_tenant_id,
        } => {
            load_node_required_in_tx(tx, *parent_tenant_id).await?;
            if let Some(child) = load_node_in_tx(tx, *child_tenant_id).await? {
                if child.parent_tenant_id.is_some() {
                    return Err(AstralError::Validation(
                        "code=org_scope.attach_requires_parentless_child".into(),
                    ));
                }
            }
        }
        OrgRequestPayload::Move {
            child_tenant_id,
            new_parent_tenant_id,
        } => {
            let child = load_node_required_in_tx(tx, *child_tenant_id).await?;
            if child.parent_tenant_id.is_none() {
                return Err(AstralError::Validation(
                    "code=org_scope.move_requires_parent".into(),
                ));
            }
            load_node_required_in_tx(tx, *new_parent_tenant_id).await?;
        }
        OrgRequestPayload::Detach { child_tenant_id } => {
            let child = load_node_required_in_tx(tx, *child_tenant_id).await?;
            if child.parent_tenant_id.is_none() {
                return Err(AstralError::Validation(
                    "code=org_scope.detach_requires_parent".into(),
                ));
            }
        }
        OrgRequestPayload::Grant {
            receiving_tenant_id,
            parent_grant,
            ..
        } => {
            let node = load_node_required_in_tx(tx, *receiving_tenant_id).await?;
            // 立即行政上级约束：grant 只能来自当前直接父；禁止同根兄弟互授。
            if node.parent_tenant_id != Some(parent_grant.tenant_id) {
                return Err(AstralError::Validation(
                    "code=org_scope.grant_origin_not_immediate_parent".into(),
                ));
            }
            if lock_grant_in_tx(tx, &parent_grant.grant_id)
                .await?
                .is_none()
            {
                return Err(AstralError::NotFound(format!(
                    "code=org_scope.parent_grant_missing;grant_id={}",
                    parent_grant.grant_id
                )));
            }
        }
    }
    Ok(())
}

pub(crate) async fn approve_request(
    store: &SqlxOrgScopeRepository,
    cmd: &OrgApproveCommand,
) -> Result<OrgApproveOutcome, AstralError> {
    validated_operation_id(&cmd.operation_id)?;
    positive_i64(cmd.request_id, "request_id")?;
    positive_i64(cmd.approver_user_id, "approver_user_id")?;
    if cmd.expected_revision == 0 {
        return Err(AstralError::Validation(
            "code=org_scope.invalid_expected_revision;field=request".into(),
        ));
    }
    let expected_revision = gen_to_i64(cmd.expected_revision, "expected_revision")?;
    validated_decision_note(cmd.note.as_deref())?;
    let canonical = serde_json::to_string(cmd)
        .map_err(|error| AstralError::Internal(format!("org_scope cmd serialize: {error}")))?;
    let digest = canonical_input_digest("REQUEST_APPROVE", &canonical);

    let (mut tx, authority_guard) = begin_authority_tx(store.pool()).await?;
    let locked = sqlx::query(REQUEST_LOCK_SQL)
        .bind(cmd.request_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?
        .ok_or_else(|| {
            AstralError::NotFound(format!(
                "code=org_scope.request_missing;request_id={}",
                cmd.request_id
            ))
        })?;
    let request = request_from_row(&locked)?;
    match claim_operation_in_tx(
        &mut tx,
        &cmd.operation_id,
        "REQUEST_APPROVE",
        request.target_tenant_id,
        &digest,
    )
    .await?
    {
        OperationClaim::Replayed(mut value) => {
            commit_authority_tx(tx, authority_guard)
                .await
                .map_err(db_err)?;
            // 幂等合同：回放返回首次 outcome，但必须向调用方标明 replayed=true。
            value["replayed"] = serde_json::Value::Bool(true);
            serde_json::from_value(value).map_err(|error| {
                AstralError::Database(format!(
                    "code=org_scope.replay_outcome_unreadable;detail={error}"
                ))
            })
        }
        OperationClaim::Fresh => {
            if request.status != "PENDING" {
                return Err(AstralError::Validation(
                    "code=org_scope.request_not_pending".into(),
                ));
            }
            if request.revision != expected_revision {
                return Err(AstralError::Validation(
                    "code=org_scope.request_revision_conflict".into(),
                ));
            }
            let payload = parse_payload(&request.payload_json)?;
            if payload.kind().as_str() != request.request_kind.as_str() {
                return Err(AstralError::Database(
                    "code=org_scope.request_kind_payload_mismatch".into(),
                ));
            }
            // Revalidate the durable payload under the approval transaction before
            // its status CAS. In particular ROOT_* resource ownership cannot rely
            // only on the earlier submit boundary.
            validate_payload(&payload)?;
            // 决策租户结构绑定：ATTACH/MOVE 的批准权属于载荷显式对侧父租户；
            // GRANT/DETACH 由变更内核在锁定态下对照当前直接行政父复验；
            // ROOT_INIT/ROOT_GRANT 凭治理元能力（服务层无租户归属保证）。
            require_counterparty_decider(cmd.approver_tenant_id, &payload)?;
            // 治理准入证明：ROOT_INIT/ROOT_GRANT 无证明/能力越界 fail-closed，
            // 且发生在任何 durable 写之前。
            let proof_detail = required_governance_proof(cmd.governance_proof.as_ref(), &payload)?
                .and_then(|proof| serde_json::to_string(proof).ok());
            // CAS：PENDING → APPROVED（请求 revision 必须与调用方的已读值相等）。
            let decided = sqlx::query(REQUEST_DECIDE_SQL)
                .bind("APPROVED")
                .bind(cmd.approver_user_id)
                .bind(cmd.note.as_deref())
                .bind(cmd.request_id)
                .bind(expected_revision)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;
            require_affected_one(&decided, "request_revision_conflict")?;
            // 同事务执行变更内核（复用审批 operation_id）。
            let records =
                dispatch_approved_mutation(&mut tx, &payload, cmd, request.request_id).await?;
            append_audit_in_tx(
                &mut tx,
                OrgAuditWrite {
                    tenant_id: request.target_tenant_id,
                    actor_user_id: cmd.approver_user_id,
                    actor_tenant_id: cmd.approver_tenant_id,
                    action: "REQUEST_APPROVED",
                    subject_kind: "REQUEST",
                    subject_id: &request.request_id.to_string(),
                    request_id: Some(request.request_id),
                    operation_id: &cmd.operation_id,
                    detail_json: proof_detail.as_deref(),
                },
            )
            .await?;
            let outcome = OrgApproveOutcome {
                request_id: request.request_id,
                operation_id: cmd.operation_id.clone(),
                replayed: false,
                records,
            };
            record_operation_outcome_in_tx(&mut tx, &cmd.operation_id, &outcome).await?;
            commit_authority_tx(tx, authority_guard)
                .await
                .map_err(db_err)?;
            Ok(outcome)
        }
    }
}

pub(crate) async fn reject_request(
    store: &SqlxOrgScopeRepository,
    cmd: &OrgRejectCommand,
) -> Result<bool, AstralError> {
    positive_i64(cmd.request_id, "request_id")?;
    positive_i64(cmd.approver_user_id, "approver_user_id")?;
    validated_operation_id(&cmd.operation_id)?;
    if cmd.expected_revision == 0 {
        return Err(AstralError::Validation(
            "code=org_scope.invalid_expected_revision;field=request".into(),
        ));
    }
    let expected_revision = gen_to_i64(cmd.expected_revision, "expected_revision")?;
    validated_decision_note(cmd.note.as_deref())?;
    let canonical = serde_json::to_string(cmd)
        .map_err(|error| AstralError::Internal(format!("org_scope cmd serialize: {error}")))?;
    let digest = canonical_input_digest("REQUEST_REJECT", &canonical);
    let mut tx = begin_tx(store.pool()).await?;
    let locked = sqlx::query(REQUEST_LOCK_SQL)
        .bind(cmd.request_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?
        .ok_or_else(|| {
            AstralError::NotFound(format!(
                "code=org_scope.request_missing;request_id={}",
                cmd.request_id
            ))
        })?;
    let request = request_from_row(&locked)?;
    match claim_operation_in_tx(
        &mut tx,
        &cmd.operation_id,
        "REQUEST_REJECT",
        request.target_tenant_id,
        &digest,
    )
    .await?
    {
        OperationClaim::Replayed(mut value) => {
            tx.commit().await.map_err(db_err)?;
            // 幂等合同：回放返回首次 outcome，但必须向调用方标明 replayed=true。
            value["replayed"] = serde_json::Value::Bool(true);
            serde_json::from_value(value).map_err(|error| {
                AstralError::Database(format!(
                    "code=org_scope.replay_outcome_unreadable;detail={error}"
                ))
            })
        }
        OperationClaim::Fresh => {
            if request.status != "PENDING" {
                return Err(AstralError::Validation(
                    "code=org_scope.request_not_pending".into(),
                ));
            }
            if request.revision != expected_revision {
                return Err(AstralError::Validation(
                    "code=org_scope.request_revision_conflict".into(),
                ));
            }
            let payload = parse_payload(&request.payload_json)?;
            if payload.kind().as_str() != request.request_kind.as_str() {
                return Err(AstralError::Database(
                    "code=org_scope.request_kind_payload_mismatch".into(),
                ));
            }
            // 决策租户结构绑定（与服务层 kind 授权同界）：ATTACH/MOVE 归载荷
            // 对侧父租户；GRANT/DETACH 归请求方当前直接行政父（下方锁定态
            // 复核，拓扑并发漂移时 fail-closed，请求保持 PENDING）；
            // ROOT_* 凭治理元能力，无租户归属约束。
            require_counterparty_decider(cmd.approver_tenant_id, &payload)?;
            // 治理驳回证明：ROOT_INIT/ROOT_GRANT 的驳回权与审批权同界——必须
            // 携带与审批同构的治理证明（注册 meta 对精确匹配 + 稳定 admission
            // operation id + 能力绑定请求自身待发 scope），缺证/结构不合法一律
            // fail-closed 且先于任何 durable 写；直接仓储调用不能凭上游 generic
            // 路由权限驳回根请求。其余 kind 忽略该字段（行为不变）。证明
            // 真实性由 API/PolicyEngine 边界保证，DB 复核结构并 durable 落审计
            // （note 仍落 decision_note 列）。
            let proof_detail = required_governance_proof(cmd.governance_proof.as_ref(), &payload)?
                .and_then(|proof| serde_json::to_string(proof).ok());
            match &payload {
                OrgRequestPayload::Grant {
                    receiving_tenant_id,
                    ..
                } => {
                    reject_parent_decider_in_tx(
                        &mut tx,
                        cmd.approver_tenant_id,
                        *receiving_tenant_id,
                    )
                    .await?;
                }
                OrgRequestPayload::Detach { child_tenant_id } => {
                    reject_parent_decider_in_tx(&mut tx, cmd.approver_tenant_id, *child_tenant_id)
                        .await?;
                }
                _ => {}
            }
            let decided = sqlx::query(REQUEST_DECIDE_SQL)
                .bind("REJECTED")
                .bind(cmd.approver_user_id)
                .bind(cmd.note.as_deref())
                .bind(cmd.request_id)
                .bind(expected_revision)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;
            require_affected_one(&decided, "request_revision_conflict")?;
            append_audit_in_tx(
                &mut tx,
                OrgAuditWrite {
        tenant_id: request.target_tenant_id,
        actor_user_id: cmd.approver_user_id,
        actor_tenant_id: cmd.approver_tenant_id,
        action: "REQUEST_REJECTED",
        subject_kind: "REQUEST",
        subject_id: &cmd.request_id.to_string(),
        request_id: Some(cmd.request_id),
        operation_id: &cmd.operation_id,
        detail_json: // ROOT_* 驳回的 durable 审计明细 = 治理证明（与审批同构，可按
                // admission operation id 关联）；其余 kind 保持原样（note；note
                // 本身仍恒落 decision_note 列）。
                proof_detail.as_deref().or(cmd.note.as_deref()),
    },
            )
            .await?;
            record_operation_outcome_in_tx(&mut tx, &cmd.operation_id, &true).await?;
            tx.commit().await.map_err(db_err)?;
            Ok(true)
        }
    }
}

pub(crate) async fn cancel_request(
    store: &SqlxOrgScopeRepository,
    cmd: &OrgCancelCommand,
) -> Result<bool, AstralError> {
    positive_i64(cmd.request_id, "request_id")?;
    positive_i64(cmd.actor_user_id, "actor_user_id")?;
    validated_operation_id(&cmd.operation_id)?;
    if cmd.expected_revision == 0 {
        return Err(AstralError::Validation(
            "code=org_scope.invalid_expected_revision;field=request".into(),
        ));
    }
    let expected_revision = gen_to_i64(cmd.expected_revision, "expected_revision")?;
    validated_decision_note(cmd.note.as_deref())?;
    let canonical = serde_json::to_string(cmd)
        .map_err(|error| AstralError::Internal(format!("org_scope cmd serialize: {error}")))?;
    let digest = canonical_input_digest("REQUEST_CANCEL", &canonical);
    let mut tx = begin_tx(store.pool()).await?;
    let locked = sqlx::query(REQUEST_LOCK_SQL)
        .bind(cmd.request_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?
        .ok_or_else(|| {
            AstralError::NotFound(format!(
                "code=org_scope.request_missing;request_id={}",
                cmd.request_id
            ))
        })?;
    let request = request_from_row(&locked)?;
    match claim_operation_in_tx(
        &mut tx,
        &cmd.operation_id,
        "REQUEST_CANCEL",
        request.target_tenant_id,
        &digest,
    )
    .await?
    {
        OperationClaim::Replayed(mut value) => {
            tx.commit().await.map_err(db_err)?;
            // 幂等合同：回放返回首次 outcome，但必须向调用方标明 replayed=true。
            value["replayed"] = serde_json::Value::Bool(true);
            serde_json::from_value(value).map_err(|error| {
                AstralError::Database(format!(
                    "code=org_scope.replay_outcome_unreadable;detail={error}"
                ))
            })
        }
        OperationClaim::Fresh => {
            if request.status != "PENDING" {
                return Err(AstralError::Validation(
                    "code=org_scope.request_not_pending".into(),
                ));
            }
            if request.revision != expected_revision {
                return Err(AstralError::Validation(
                    "code=org_scope.request_revision_conflict".into(),
                ));
            }
            if request.requester_user_id != cmd.actor_user_id
                || cmd.actor_tenant_id != Some(request.requester_tenant_id)
            {
                return Err(AstralError::Permission(
                    "code=org_scope.cancel_not_requester".into(),
                ));
            }
            let decided = sqlx::query(REQUEST_DECIDE_SQL)
                .bind("CANCELLED")
                .bind(cmd.actor_user_id)
                .bind(cmd.note.as_deref())
                .bind(cmd.request_id)
                .bind(expected_revision)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;
            require_affected_one(&decided, "request_revision_conflict")?;
            append_audit_in_tx(
                &mut tx,
                OrgAuditWrite {
                    tenant_id: request.target_tenant_id,
                    actor_user_id: cmd.actor_user_id,
                    actor_tenant_id: cmd.actor_tenant_id,
                    action: "REQUEST_CANCELLED",
                    subject_kind: "REQUEST",
                    subject_id: &cmd.request_id.to_string(),
                    request_id: Some(cmd.request_id),
                    operation_id: &cmd.operation_id,
                    detail_json: cmd.note.as_deref(),
                },
            )
            .await?;
            record_operation_outcome_in_tx(&mut tx, &cmd.operation_id, &true).await?;
            tx.commit().await.map_err(db_err)?;
            Ok(true)
        }
    }
}

pub(crate) async fn get_request(
    store: &SqlxOrgScopeRepository,
    request_id: i64,
) -> Result<Option<OrgRequestView>, AstralError> {
    positive_i64(request_id, "request_id")?;
    let row = sqlx::query(REQUEST_SELECT_SQL)
        .bind(request_id)
        .fetch_optional(store.pool())
        .await
        .map_err(db_err)?;
    row.map(|row| {
        let locked = request_from_row(&row)?;
        let payload = parse_payload(&locked.payload_json)?;
        Ok(OrgRequestView {
            request_id: locked.request_id,
            request_kind: locked.request_kind,
            requester_tenant_id: locked.requester_tenant_id,
            requester_user_id: locked.requester_user_id,
            target_tenant_id: locked.target_tenant_id,
            parent_tenant_id: locked.parent_tenant_id,
            status: locked.status,
            revision: row_generation(locked.revision, "request.revision")?,
            payload,
            decided_by: locked.decided_by,
            decision_note: locked.decision_note,
            created_at_unix: locked.created_at_unix,
            decided_at_unix: locked.decided_at_unix,
        })
    })
    .transpose()
}

// ─────────────────────────────────────────────────────────────────────────────
// 审批调度 → 变更内核（同一事务）
// ─────────────────────────────────────────────────────────────────────────────

async fn dispatch_approved_mutation(
    tx: &mut Transaction<'static, MySql>,
    payload: &OrgRequestPayload,
    cmd: &OrgApproveCommand,
    request_id: i64,
) -> Result<Vec<OrgMutationRecord>, AstralError> {
    match payload {
        OrgRequestPayload::RootInit {
            root_tenant_id,
            initial_grants,
        } => {
            for seed in initial_grants {
                require_root_source_scope(*root_tenant_id, &seed.scope)?;
            }
            create_root_in_tx(tx, *root_tenant_id, initial_grants, request_id, cmd).await
        }
        OrgRequestPayload::RootGrant {
            root_tenant_id,
            scope,
            delegable,
        } => {
            require_root_source_scope(*root_tenant_id, scope)?;
            issue_root_grant_in_tx(tx, *root_tenant_id, scope, *delegable, request_id, cmd).await
        }
        OrgRequestPayload::Attach {
            child_tenant_id,
            parent_tenant_id,
        } => attach_node_in_tx(tx, *child_tenant_id, *parent_tenant_id, request_id, cmd).await,
        OrgRequestPayload::Move {
            child_tenant_id,
            new_parent_tenant_id,
        } => move_node_in_tx(tx, *child_tenant_id, *new_parent_tenant_id, request_id, cmd).await,
        OrgRequestPayload::Detach { child_tenant_id } => {
            detach_node_in_tx(tx, *child_tenant_id, request_id, cmd).await
        }
        OrgRequestPayload::Grant {
            receiving_tenant_id,
            parent_grant,
            scope,
            delegable,
            subject,
        } => {
            issue_grant_in_tx(
                tx,
                *receiving_tenant_id,
                parent_grant,
                scope,
                *delegable,
                subject.as_ref(),
                request_id,
                cmd,
            )
            .await
        }
    }
}

/// ROOT_INIT：创建根 node（含 `OrgRootActivation` 持久化）并按审批证明能力
/// 范围内的种子发初始 grants。
async fn create_root_in_tx(
    tx: &mut Transaction<'static, MySql>,
    root_tenant_id: i64,
    initial_grants: &[OrgGrantSeed],
    request_id: i64,
    cmd: &OrgApproveCommand,
) -> Result<Vec<OrgMutationRecord>, AstralError> {
    if load_node_in_tx(tx, root_tenant_id).await?.is_some() {
        return Err(AstralError::Validation(
            "code=org_scope.node_already_initialized".into(),
        ));
    }
    sqlx::query(NODE_INSERT_SQL)
        .bind(root_tenant_id)
        .bind(root_tenant_id)
        .bind(Option::<i64>::None)
        .bind(request_id)
        .bind(&cmd.operation_id)
        .bind(&cmd.operation_id)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    // 持久化根激活证明（OrgRootActivation：operator + approval operation）。
    // typed_node/OrgNode::validate 要求 parentless node 携带显式证明。
    let activated = sqlx::query(NODE_ROOT_ACTIVATION_SQL)
        .bind(cmd.approver_user_id)
        .bind(&cmd.operation_id)
        .bind(root_tenant_id)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    require_affected_one(&activated, "root_activation_missing")?;
    let mut records = vec![OrgMutationRecord {
        record_kind: "NODE_CREATED".into(),
        subject_kind: "NODE".into(),
        subject_id: root_tenant_id.to_string(),
        tenant_id: root_tenant_id,
    }];
    let node = load_node_required_in_tx(tx, root_tenant_id).await?;
    append_node_revision_and_event(tx, &node, request_id, cmd, ORG_EVENT_NODE_CREATED).await?;
    for seed in initial_grants {
        records.push(
            insert_root_origin_grant_in_tx(
                tx,
                root_tenant_id,
                &seed.scope,
                seed.delegable,
                request_id,
                cmd,
            )
            .await?,
        );
    }
    append_audit_in_tx(
        tx,
        OrgAuditWrite {
            tenant_id: root_tenant_id,
            actor_user_id: cmd.approver_user_id,
            actor_tenant_id: cmd.approver_tenant_id,
            action: "NODE_ROOT_INIT",
            subject_kind: "NODE",
            subject_id: &root_tenant_id.to_string(),
            request_id: Some(request_id),
            operation_id: &cmd.operation_id,
            detail_json: None,
        },
    )
    .await?;
    Ok(records)
}

/// ROOT_GRANT：为根租户追加 origin=root 的自身持有 grant。
async fn issue_root_grant_in_tx(
    tx: &mut Transaction<'static, MySql>,
    root_tenant_id: i64,
    scope: &OrgScope,
    delegable: bool,
    request_id: i64,
    cmd: &OrgApproveCommand,
) -> Result<Vec<OrgMutationRecord>, AstralError> {
    let node = lock_node_in_tx(tx, root_tenant_id).await?.ok_or_else(|| {
        AstralError::NotFound(format!(
            "code=org_scope.node_missing;tenant_id={root_tenant_id}"
        ))
    })?;
    if !node.active {
        return Err(AstralError::Validation(
            "code=org_scope.node_inactive".into(),
        ));
    }
    if node.parent_tenant_id.is_some() {
        return Err(AstralError::Validation(
            "code=org_scope.root_grant_requires_root_node".into(),
        ));
    }
    let record =
        insert_root_origin_grant_in_tx(tx, root_tenant_id, scope, delegable, request_id, cmd)
            .await?;
    Ok(vec![record])
}

/// 发 origin=receiving=root、parent=None 的根级 grant（ROOT_INIT/ROOT_GRANT 共用）。
async fn insert_root_origin_grant_in_tx(
    tx: &mut Transaction<'static, MySql>,
    root_tenant_id: i64,
    scope: &OrgScope,
    delegable: bool,
    request_id: i64,
    cmd: &OrgApproveCommand,
) -> Result<OrgMutationRecord, AstralError> {
    let node = load_node_required_in_tx(tx, root_tenant_id).await?;
    let grant_id = uuid_v4_string();
    let (valid_from, valid_until) = validity_bounds(&scope.validity);
    sqlx::query(GRANT_INSERT_SQL)
        .bind(&grant_id)
        .bind(root_tenant_id)
        .bind(root_tenant_id)
        .bind(node.root_tenant_id)
        .bind(scope.resource_tenant_id)
        .bind(scope.domain_id)
        .bind(scope.resource.trim())
        .bind(scope.action.trim())
        .bind(valid_from)
        .bind(valid_until)
        .bind(delegable)
        .bind(Option::<i64>::None)
        .bind(Option::<String>::None)
        .bind(Option::<i64>::None)
        .bind("UNIT")
        .bind(Option::<i64>::None)
        .bind(Option::<i64>::None)
        .bind(&cmd.operation_id)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    let grant_row = lock_grant_in_tx(tx, &grant_id).await?.ok_or_else(|| {
        AstralError::Database("code=org_scope.grant_vanished_after_insert".into())
    })?;
    let payload = serde_json::to_string(&typed_grant(&grant_row)?)
        .map_err(|error| AstralError::Internal(format!("org_scope grant payload: {error}")))?;
    append_revision_in_tx(
        tx,
        "GRANT",
        root_tenant_id,
        &grant_id,
        1,
        &payload,
        &cmd.operation_id,
    )
    .await?;
    append_outbox_event_in_tx(
        tx,
        root_tenant_id,
        ORG_EVENT_GRANT_ISSUED,
        &cmd.operation_id,
        &payload,
    )
    .await?;
    // Root-origin grants are source facts just like delegated grants. Advancing
    // the root head makes any prior publication inadmissible until the org
    // projector seals a manifest at the new generation.
    let node_after =
        advance_node_in_tx(tx, root_tenant_id, false, false, &cmd.operation_id).await?;
    append_dependency_propagate_intent_in_tx(tx, &node_after, &cmd.operation_id).await?;
    append_audit_in_tx(
        tx,
        OrgAuditWrite {
            tenant_id: root_tenant_id,
            actor_user_id: cmd.approver_user_id,
            actor_tenant_id: cmd.approver_tenant_id,
            action: "GRANT_ISSUED",
            subject_kind: "GRANT",
            subject_id: &grant_id,
            request_id: Some(request_id),
            operation_id: &cmd.operation_id,
            detail_json: Some(payload.as_str()),
        },
    )
    .await?;
    Ok(OrgMutationRecord {
        record_kind: "GRANT_ISSUED".into(),
        subject_kind: "GRANT".into(),
        subject_id: grant_id,
        tenant_id: root_tenant_id,
    })
}

/// ATTACH：把无父单元挂到目标父（或首建子 node）；环检查 + 父代推进。
async fn attach_node_in_tx(
    tx: &mut Transaction<'static, MySql>,
    child_tenant_id: i64,
    parent_tenant_id: i64,
    request_id: i64,
    cmd: &OrgApproveCommand,
) -> Result<Vec<OrgMutationRecord>, AstralError> {
    // 无锁规划：收集父链 id → 统一升序锁定 → 锁后复走（防并发移树环）。
    let planned_chain = walk_ancestors_in_tx(tx, parent_tenant_id).await?;
    let mut ids: Vec<i64> = planned_chain.iter().map(|node| node.tenant_id).collect();
    ids.push(child_tenant_id);
    ids.sort_unstable();
    ids.dedup();
    lock_nodes_in_tx(tx, &ids).await?;
    let locked_chain = verified_locked_chain(tx, parent_tenant_id, &ids).await?;
    if locked_chain
        .iter()
        .any(|node| node.tenant_id == child_tenant_id)
    {
        return Err(AstralError::Validation(
            "code=org_scope.attach_cycle".into(),
        ));
    }
    let parent = locked_chain
        .first()
        .cloned()
        .ok_or_else(|| AstralError::Validation("code=org_scope.parent_missing".into()))?;
    if !parent.active {
        return Err(AstralError::Validation(
            "code=org_scope.node_inactive".into(),
        ));
    }
    let mut records = Vec::new();
    match lock_node_in_tx(tx, child_tenant_id).await? {
        None => {
            sqlx::query(NODE_INSERT_SQL)
                .bind(child_tenant_id)
                .bind(parent.root_tenant_id)
                .bind(Option::<i64>::None)
                .bind(request_id)
                .bind(&cmd.operation_id)
                .bind(&cmd.operation_id)
                .execute(&mut **tx)
                .await
                .map_err(db_err)?;
            // 首建子 node 按 ATTACH 语义推进到目标父（INSERT 默认 root=self，
            // 这里原子改挂到父并推进 relationship_revision）。
            let created = load_node_required_in_tx(tx, child_tenant_id).await?;
            sqlx::query(NODE_ATTACH_SQL)
                .bind(parent_tenant_id)
                .bind(parent.root_tenant_id)
                .bind(&cmd.operation_id)
                .bind(child_tenant_id)
                .bind(created.relationship_revision)
                .execute(&mut **tx)
                .await
                .map_err(db_err)?;
            records.push(OrgMutationRecord {
                record_kind: "NODE_CREATED".into(),
                subject_kind: "NODE".into(),
                subject_id: child_tenant_id.to_string(),
                tenant_id: child_tenant_id,
            });
        }
        Some(existing) => {
            if !existing.active {
                return Err(AstralError::Validation(
                    "code=org_scope.node_inactive".into(),
                ));
            }
            if existing.parent_tenant_id.is_some() {
                return Err(AstralError::Validation(
                    "code=org_scope.attach_requires_parentless_child".into(),
                ));
            }
            // 既有独立根并入（跨根 attach）：先撤销其作为独立根期间自源发放的
            // 全部 active grants（former root = 自身），**再**改挂拓扑——与
            // MOVE/DETACH 同一失效序（撤销先于 CAS 改挂），复用同一撤销内核
            // （含 ORG_MAX_GRANTS_REVOKE_PER_TX 预算、revision 账、outbox、
            // GRANT_REVOKED 记录）。否则该节点再次 detach 后（root 复原为自身），
            // 这些未退休的旧 grants 会凭编译输入 root 过滤（`active = 1 AND
            // root_tenant_id = 当前 root`）重新匹配而复活。
            // 后代链不在本 source 事务内遍历：其 grants 的 parent 精确引用
            // `(tenant, grant_id, revision)` 在此撤销后失效（父 grant inactive
            // 且 revision 前进，永不错位复位），后代编译输入按当前 root 过滤
            // 排除旧行；即便日后 root 复原使旧行重新命中过滤，父引用也已从
            // 父单元 active ledger 消失 → 编译器 `ParentMissing` PENDING，
            // 直到存在新的已批准委托链（见 policy-engine org_compiler
            // `resolve_grant_contribution`）。
            let former_root = former_root_to_retire_on_attach(&existing)?;
            records.extend(
                revoke_received_grants_from_old_root_in_tx(
                    tx,
                    child_tenant_id,
                    former_root,
                    &cmd.operation_id,
                )
                .await?,
            );
            sqlx::query(NODE_ATTACH_SQL)
                .bind(parent_tenant_id)
                .bind(parent.root_tenant_id)
                .bind(&cmd.operation_id)
                .bind(child_tenant_id)
                .bind(existing.relationship_revision)
                .execute(&mut **tx)
                .await
                .map_err(db_err)?;
            records.push(OrgMutationRecord {
                record_kind: "NODE_ATTACHED".into(),
                subject_kind: "NODE".into(),
                subject_id: child_tenant_id.to_string(),
                tenant_id: child_tenant_id,
            });
        }
    }
    let child_after = load_node_required_in_tx(tx, child_tenant_id).await?;
    append_node_revision_and_event(
        tx,
        &child_after,
        request_id,
        cmd,
        ORG_EVENT_NODE_TOPOLOGY_CHANGED,
    )
    .await?;
    append_subtree_propagate_intent_in_tx(
        tx,
        child_tenant_id,
        child_after.root_tenant_id,
        row_generation(
            child_after.relationship_revision,
            "node.relationship_revision",
        )?,
        &cmd.operation_id,
    )
    .await?;
    let parent_after =
        advance_node_in_tx(tx, parent_tenant_id, false, false, &cmd.operation_id).await?;
    // Queue the generation-triggering projection before its dependency fan-out
    // intent so the anchor publication is available when the wave is claimed.
    let parent_payload = serde_json::to_string(&typed_node(&parent_after)?)
        .map_err(|error| AstralError::Internal(format!("org_scope node payload: {error}")))?;
    append_outbox_event_in_tx(
        tx,
        parent_tenant_id,
        ORG_EVENT_NODE_MUTATED,
        &cmd.operation_id,
        &parent_payload,
    )
    .await?;
    append_dependency_propagate_intent_in_tx(tx, &parent_after, &cmd.operation_id).await?;
    append_audit_in_tx(
        tx,
        OrgAuditWrite {
            tenant_id: child_tenant_id,
            actor_user_id: cmd.approver_user_id,
            actor_tenant_id: cmd.approver_tenant_id,
            action: "NODE_ATTACH",
            subject_kind: "NODE",
            subject_id: &child_tenant_id.to_string(),
            request_id: Some(request_id),
            operation_id: &cmd.operation_id,
            detail_json: None,
        },
    )
    .await?;
    Ok(records)
}

/// MOVE（invalidating move）：先撤销旧链 received grants，再 CAS 改挂新父并
/// 推进 fence/relationship/generation；后代 root 传播由 worker 按批完成。
async fn move_node_in_tx(
    tx: &mut Transaction<'static, MySql>,
    child_tenant_id: i64,
    new_parent_tenant_id: i64,
    request_id: i64,
    cmd: &OrgApproveCommand,
) -> Result<Vec<OrgMutationRecord>, AstralError> {
    // 无锁规划（只用于确定锁定集合；一切判定以锁定后数据为准）。
    let planned_chain = walk_ancestors_in_tx(tx, new_parent_tenant_id).await?;
    let mut ids: Vec<i64> = planned_chain.iter().map(|node| node.tenant_id).collect();
    ids.push(child_tenant_id);
    ids.sort_unstable();
    ids.dedup();
    lock_nodes_in_tx(tx, &ids).await?;
    let locked_chain = verified_locked_chain(tx, new_parent_tenant_id, &ids).await?;
    if locked_chain
        .iter()
        .any(|node| node.tenant_id == child_tenant_id)
    {
        return Err(AstralError::Validation("code=org_scope.move_cycle".into()));
    }
    let new_parent = locked_chain
        .first()
        .cloned()
        .ok_or_else(|| AstralError::Validation("code=org_scope.parent_missing".into()))?;
    if !new_parent.active {
        return Err(AstralError::Validation(
            "code=org_scope.node_inactive".into(),
        ));
    }
    // 锁定后的 child 真值（规划窗口内可能被并发 mutation 改动）。
    let child = load_node_required_in_tx(tx, child_tenant_id).await?;
    if !child.active {
        return Err(AstralError::Validation(
            "code=org_scope.node_inactive".into(),
        ));
    }
    let old_parent_tenant_id = child
        .parent_tenant_id
        .ok_or_else(|| AstralError::Validation("code=org_scope.move_requires_parent".into()))?;
    let old_root_tenant_id = child.root_tenant_id;
    if old_parent_tenant_id == new_parent_tenant_id {
        return Err(AstralError::Validation("code=org_scope.move_noop".into()));
    }
    let mut records = revoke_received_grants_from_old_root_in_tx(
        tx,
        child_tenant_id,
        old_root_tenant_id,
        &cmd.operation_id,
    )
    .await?;
    let result = sqlx::query(NODE_MOVE_SQL)
        .bind(new_parent_tenant_id)
        .bind(new_parent.root_tenant_id)
        .bind(&cmd.operation_id)
        .bind(child_tenant_id)
        .bind(child.relationship_revision)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    require_affected_one(&result, "move_relationship_cas_conflict")?;
    let child_after = load_node_required_in_tx(tx, child_tenant_id).await?;
    append_node_revision_and_event(
        tx,
        &child_after,
        request_id,
        cmd,
        ORG_EVENT_NODE_TOPOLOGY_CHANGED,
    )
    .await?;
    for tenant_id in [old_parent_tenant_id, new_parent_tenant_id] {
        append_outbox_event_in_tx(
            tx,
            tenant_id,
            ORG_EVENT_NODE_TOPOLOGY_CHANGED,
            &cmd.operation_id,
            &serde_json::json!({ "tenant_id": tenant_id }).to_string(),
        )
        .await?;
    }
    append_subtree_propagate_intent_in_tx(
        tx,
        child_tenant_id,
        child_after.root_tenant_id,
        row_generation(
            child_after.relationship_revision,
            "node.relationship_revision",
        )?,
        &cmd.operation_id,
    )
    .await?;
    for tenant_id in [old_parent_tenant_id, new_parent_tenant_id] {
        let parent_after =
            advance_node_in_tx(tx, tenant_id, false, false, &cmd.operation_id).await?;
        append_dependency_propagate_intent_in_tx(tx, &parent_after, &cmd.operation_id).await?;
    }
    records.push(OrgMutationRecord {
        record_kind: "NODE_MOVED".into(),
        subject_kind: "NODE".into(),
        subject_id: child_tenant_id.to_string(),
        tenant_id: child_tenant_id,
    });
    append_audit_in_tx(
        tx,
        OrgAuditWrite {
            tenant_id: child_tenant_id,
            actor_user_id: cmd.approver_user_id,
            actor_tenant_id: cmd.approver_tenant_id,
            action: "NODE_MOVE",
            subject_kind: "NODE",
            subject_id: &child_tenant_id.to_string(),
            request_id: Some(request_id),
            operation_id: &cmd.operation_id,
            detail_json: None,
        },
    )
    .await?;
    Ok(records)
}

/// DETACH：独立。撤销旧链 grants → CAS 置 parent=NULL/root=self → 旧父推进 →
/// 后代 root 传播 intent。
async fn detach_node_in_tx(
    tx: &mut Transaction<'static, MySql>,
    child_tenant_id: i64,
    request_id: i64,
    cmd: &OrgApproveCommand,
) -> Result<Vec<OrgMutationRecord>, AstralError> {
    let child = lock_node_in_tx(tx, child_tenant_id).await?.ok_or_else(|| {
        AstralError::NotFound(format!(
            "code=org_scope.node_missing;tenant_id={child_tenant_id}"
        ))
    })?;
    if !child.active {
        return Err(AstralError::Validation(
            "code=org_scope.node_inactive".into(),
        ));
    }
    let old_parent_tenant_id = child
        .parent_tenant_id
        .ok_or_else(|| AstralError::Validation("code=org_scope.detach_requires_parent".into()))?;
    // 决策租户结构绑定（锁定态）：DETACH 批准权属于子单元当前直接行政父；
    // 先于旧链撤销等任何 durable 写。
    require_requesting_parent_decider(cmd.approver_tenant_id, Some(old_parent_tenant_id))?;
    let old_root_tenant_id = child.root_tenant_id;
    let mut records = revoke_received_grants_from_old_root_in_tx(
        tx,
        child_tenant_id,
        old_root_tenant_id,
        &cmd.operation_id,
    )
    .await?;
    let result = sqlx::query(NODE_DETACH_SQL)
        .bind(&cmd.operation_id)
        .bind(child_tenant_id)
        .bind(child.relationship_revision)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    require_affected_one(&result, "detach_relationship_cas_conflict")?;
    // 独立行政根激活证明：detach 后节点成为行政根，`typed_node` /
    // `OrgNode::validate` 要求 parentless node 携带显式 proof，且类型化 revision
    // 落账（下方 `append_node_revision_and_event` → `typed_node`）会立即复核。
    // 证明使用**本次** detach 的批准人 + 审批 operation id（与 ROOT_INIT 同一
    // 合同），绝不沿用历史值；先于任何引用新状态的 durable 写。重挂路径在
    // NODE_ATTACH_SQL 中清空激活列，因此每次独立期都拿到自己的新证明。
    let activated = sqlx::query(NODE_ROOT_ACTIVATION_SQL)
        .bind(cmd.approver_user_id)
        .bind(&cmd.operation_id)
        .bind(child_tenant_id)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    require_affected_one(&activated, "root_activation_missing")?;
    let child_after = load_node_required_in_tx(tx, child_tenant_id).await?;
    append_node_revision_and_event(
        tx,
        &child_after,
        request_id,
        cmd,
        ORG_EVENT_NODE_TOPOLOGY_CHANGED,
    )
    .await?;
    append_outbox_event_in_tx(
        tx,
        old_parent_tenant_id,
        ORG_EVENT_NODE_TOPOLOGY_CHANGED,
        &cmd.operation_id,
        &serde_json::json!({ "tenant_id": old_parent_tenant_id }).to_string(),
    )
    .await?;
    append_subtree_propagate_intent_in_tx(
        tx,
        child_tenant_id,
        child_tenant_id,
        row_generation(
            child_after.relationship_revision,
            "node.relationship_revision",
        )?,
        &cmd.operation_id,
    )
    .await?;
    let parent_after =
        advance_node_in_tx(tx, old_parent_tenant_id, false, false, &cmd.operation_id).await?;
    append_dependency_propagate_intent_in_tx(tx, &parent_after, &cmd.operation_id).await?;
    records.push(OrgMutationRecord {
        record_kind: "NODE_DETACHED".into(),
        subject_kind: "NODE".into(),
        subject_id: child_tenant_id.to_string(),
        tenant_id: child_tenant_id,
    });
    append_audit_in_tx(
        tx,
        OrgAuditWrite {
            tenant_id: child_tenant_id,
            actor_user_id: cmd.approver_user_id,
            actor_tenant_id: cmd.approver_tenant_id,
            action: "NODE_DETACH",
            subject_kind: "NODE",
            subject_id: &child_tenant_id.to_string(),
            request_id: Some(request_id),
            operation_id: &cmd.operation_id,
            detail_json: None,
        },
    )
    .await?;
    Ok(records)
}

/// GRANT：锁 receiving node → 验 origin=直接行政父（禁止同根兄弟互授）→ 锁
/// parent grant 精确 revision 验 active+delegable+同 root+covers+有效期包含 →
/// 发 grant。
#[allow(clippy::too_many_arguments)]
async fn issue_grant_in_tx(
    tx: &mut Transaction<'static, MySql>,
    receiving_tenant_id: i64,
    parent_grant: &OrgGrantRef,
    scope: &OrgScope,
    delegable: bool,
    subject: Option<&OrgSubject>,
    request_id: i64,
    cmd: &OrgApproveCommand,
) -> Result<Vec<OrgMutationRecord>, AstralError> {
    let node = lock_node_in_tx(tx, receiving_tenant_id)
        .await?
        .ok_or_else(|| {
            AstralError::NotFound(format!(
                "code=org_scope.node_missing;tenant_id={receiving_tenant_id}"
            ))
        })?;
    if !node.active {
        return Err(AstralError::Validation(
            "code=org_scope.node_inactive".into(),
        ));
    }
    if node.parent_tenant_id != Some(parent_grant.tenant_id) {
        // 授权只能来自当前直接行政上级；兄弟/祖先直授一律拒绝。
        return Err(AstralError::Permission(
            "code=org_scope.grant_origin_not_immediate_parent".into(),
        ));
    }
    // 决策租户结构绑定（锁定态）：批准人必须是请求方当前直接行政父；同根
    // 兄弟/祖父跳级或无租户决策一律拒绝。
    require_requesting_parent_decider(cmd.approver_tenant_id, node.parent_tenant_id)?;
    let parent = lock_grant_in_tx(tx, &parent_grant.grant_id)
        .await?
        .ok_or_else(|| {
            AstralError::NotFound(format!(
                "code=org_scope.parent_grant_missing;grant_id={}",
                parent_grant.grant_id
            ))
        })?;
    if parent.receiving_tenant_id != parent_grant.tenant_id {
        return Err(AstralError::Validation(
            "code=org_scope.parent_grant_tenant_mismatch".into(),
        ));
    }
    if parent.revision != gen_to_i64(parent_grant.revision, "parent_grant.revision")? {
        // 精确 revision 绑定：上级 grant 变更后必须显式重批，绝不静默续用。
        return Err(AstralError::Validation(
            "code=org_scope.parent_grant_revision_changed".into(),
        ));
    }
    if !parent.active {
        return Err(AstralError::Validation(
            "code=org_scope.parent_grant_not_active".into(),
        ));
    }
    if !parent.delegable {
        return Err(AstralError::Permission(
            "code=org_scope.parent_grant_not_delegable".into(),
        ));
    }
    if parent.root_tenant_id != node.root_tenant_id {
        return Err(AstralError::Permission(
            "code=org_scope.parent_grant_root_mismatch".into(),
        ));
    }
    if parent.subject_kind == "PERSONAL" {
        return Err(AstralError::Permission(
            "code=org_scope.personal_grant_parent_must_be_unit".into(),
        ));
    }
    if let Some(subject) = subject {
        let membership = super::mutations::lock_personal_grant_membership_in_tx(
            tx,
            receiving_tenant_id,
            subject,
        )
        .await?;
        if membership.root_tenant_id != node.root_tenant_id {
            return Err(AstralError::Permission(
                "code=org_scope.personal_grant_membership_root_mismatch".into(),
            ));
        }
    }
    let parent_scope = grant_scope(&parent);
    parent_scope.covers(scope).map_err(org_err)?;
    // 有效期包含（类型 covers 已含窗口校验，这里保留显式机器码便于审计）。
    if !astral_types::org_scope::org_window_covers(&parent_scope.validity, &scope.validity) {
        return Err(AstralError::Validation(
            "code=org_scope.grant_validity_not_contained".into(),
        ));
    }
    let grant_id = uuid_v4_string();
    let (valid_from, valid_until) = validity_bounds(&scope.validity);
    let subject_kind = if subject.is_some() {
        "PERSONAL"
    } else {
        "UNIT"
    };
    sqlx::query(GRANT_INSERT_SQL)
        .bind(&grant_id)
        .bind(receiving_tenant_id)
        .bind(parent_grant.tenant_id)
        .bind(node.root_tenant_id)
        .bind(scope.resource_tenant_id)
        .bind(scope.domain_id)
        .bind(scope.resource.trim())
        .bind(scope.action.trim())
        .bind(valid_from)
        .bind(valid_until)
        .bind(delegable)
        .bind(parent_grant.tenant_id)
        .bind(&parent_grant.grant_id)
        .bind(gen_to_i64(parent_grant.revision, "parent_grant.revision")?)
        .bind(subject_kind)
        .bind(subject.map(|s| s.user_id))
        .bind(subject.map(|s| s.card_id))
        .bind(&cmd.operation_id)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    let grant_row = lock_grant_in_tx(tx, &grant_id).await?.ok_or_else(|| {
        AstralError::Database("code=org_scope.grant_vanished_after_insert".into())
    })?;
    let payload = serde_json::to_string(&typed_grant(&grant_row)?)
        .map_err(|error| AstralError::Internal(format!("org_scope grant payload: {error}")))?;
    append_revision_in_tx(
        tx,
        "GRANT",
        receiving_tenant_id,
        &grant_id,
        1,
        &payload,
        &cmd.operation_id,
    )
    .await?;
    append_outbox_event_in_tx(
        tx,
        receiving_tenant_id,
        ORG_EVENT_GRANT_ISSUED,
        &cmd.operation_id,
        &payload,
    )
    .await?;
    // 新授权进入本级作用域：generation 推进使当前 publication 立即过期，
    // 由 worker 重编译发布（fail-closed 窗口内 PENDING）。
    let node_after =
        advance_node_in_tx(tx, receiving_tenant_id, false, false, &cmd.operation_id).await?;
    append_dependency_propagate_intent_in_tx(tx, &node_after, &cmd.operation_id).await?;
    append_audit_in_tx(
        tx,
        OrgAuditWrite {
            tenant_id: receiving_tenant_id,
            actor_user_id: cmd.approver_user_id,
            actor_tenant_id: cmd.approver_tenant_id,
            action: "GRANT_ISSUED",
            subject_kind: "GRANT",
            subject_id: &grant_id,
            request_id: Some(request_id),
            operation_id: &cmd.operation_id,
            detail_json: Some(payload.as_str()),
        },
    )
    .await?;
    Ok(vec![OrgMutationRecord {
        record_kind: "GRANT_ISSUED".into(),
        subject_kind: "GRANT".into(),
        subject_id: grant_id,
        tenant_id: receiving_tenant_id,
    }])
}

// ─────────────────────────────────────────────────────────────────────────────
// 小工具
// ─────────────────────────────────────────────────────────────────────────────

/// 锁定后复走父链：链上任何节点不在锁定集合内 = 规划窗口内拓扑漂移 →
/// 可重试失败（请求保持 PENDING，绝不基于不完整链做环判定）。
async fn verified_locked_chain(
    tx: &mut Transaction<'static, MySql>,
    start_tenant_id: i64,
    locked_ids: &[i64],
) -> Result<Vec<OrgNodeRow>, AstralError> {
    let chain = walk_ancestors_in_tx(tx, start_tenant_id).await?;
    for node in &chain {
        if !locked_ids.contains(&node.tenant_id) {
            return Err(AstralError::Validation(
                "code=org_scope.chain_moved_retry".into(),
            ));
        }
    }
    Ok(chain)
}

/// reject 的 GRANT/DETACH 决策权复核：锁定请求方 node 后对照其当前直接行政
/// 父（与审批内核同界；node 缺失或无父态同样 fail-closed，事务回滚，请求
/// 保持 PENDING）。
async fn reject_parent_decider_in_tx(
    tx: &mut Transaction<'static, MySql>,
    approver_tenant_id: Option<i64>,
    tenant_id: i64,
) -> Result<(), AstralError> {
    let node = lock_node_in_tx(tx, tenant_id).await?.ok_or_else(|| {
        AstralError::NotFound(format!("code=org_scope.node_missing;tenant_id={tenant_id}"))
    })?;
    require_requesting_parent_decider(approver_tenant_id, node.parent_tenant_id)
}

/// node revision 账 + outbox 事件（共享写序）。
async fn append_node_revision_and_event(
    tx: &mut Transaction<'static, MySql>,
    node: &OrgNodeRow,
    request_id: i64,
    cmd: &OrgApproveCommand,
    event_kind: &str,
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
        &cmd.operation_id,
    )
    .await?;
    append_outbox_event_in_tx(tx, node.tenant_id, event_kind, &cmd.operation_id, &payload).await?;
    let _ = request_id;
    Ok(())
}

pub(crate) async fn append_dependency_propagate_intent_in_tx(
    tx: &mut Transaction<'static, MySql>,
    node: &OrgNodeRow,
    operation_id: &str,
) -> Result<(), AstralError> {
    let payload = OrgDependencyPropagatePayload {
        anchor_tenant_id: node.tenant_id,
        root_tenant_id: node.root_tenant_id,
        generation: row_generation(node.generation, "node.generation")?,
        revoke_fence: row_generation(node.revoke_fence, "node.revoke_fence")?,
        relationship_revision: row_generation(
            node.relationship_revision,
            "node.relationship_revision",
        )?,
    };
    payload.validate().map_err(org_err)?;
    let payload_json = serde_json::to_string(&payload).map_err(|error| {
        AstralError::Internal(format!("org_scope dependency propagate payload: {error}"))
    })?;
    append_outbox_event_in_tx(
        tx,
        node.tenant_id,
        ORG_EVENT_DEPENDENCY_PROPAGATE,
        operation_id,
        &payload_json,
    )
    .await
}

/// SUBTREE_PROPAGATE intent 载荷（worker 读取后按批推进后代 root；扇出语义下
/// 传播内核也会为每个被推进子节点派生新的 child intent，故 pub(crate)）。
/// typed 序列化：wire 键与历史 ad hoc JSON 完全一致（`OrgSubtreePropagatePayload`
/// snake_case），既有已入队行保持可解析；生产侧先 validate 再落库（fail-closed，
/// 先于任何 durable 写）。审批请求载荷合同（`OrgRequestPayload`）不受影响。
pub(crate) async fn append_subtree_propagate_intent_in_tx(
    tx: &mut Transaction<'static, MySql>,
    child_tenant_id: i64,
    new_root_tenant_id: i64,
    relationship_revision: u64,
    operation_id: &str,
) -> Result<(), AstralError> {
    let payload = OrgSubtreePropagatePayload {
        child_tenant_id,
        new_root_tenant_id,
        relationship_revision,
    };
    payload.validate().map_err(org_err)?;
    let payload_json = serde_json::to_string(&payload).map_err(|error| {
        AstralError::Internal(format!("org_scope subtree propagate payload: {error}"))
    })?;
    append_outbox_event_in_tx(
        tx,
        child_tenant_id,
        ORG_EVENT_SUBTREE_PROPAGATE,
        operation_id,
        &payload_json,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::ValidityWindow;

    fn grant_payload() -> OrgRequestPayload {
        OrgRequestPayload::Grant {
            receiving_tenant_id: 20,
            parent_grant: OrgGrantRef {
                tenant_id: 10,
                grant_id: "00000000-0000-0000-0000-00000000000a".into(),
                revision: 3,
            },
            scope: OrgScope {
                resource_tenant_id: 20,
                domain_id: None,
                resource: "learn_subject".into(),
                action: "read".into(),
                validity: ValidityWindow::perpetual(),
            },
            delegable: false,
            subject: None,
        }
    }

    #[test]
    fn kind_target_parent_derivation_is_consistent() {
        let payload = grant_payload();
        assert_eq!(payload.kind().as_str(), "GRANT");
        assert_eq!(target_of(&payload), 20);
        assert_eq!(parent_of(&payload), Some(10));
        assert_eq!(requester_of(&payload), 20);
    }

    #[test]
    fn payload_validation_rejects_bad_ids_and_self_parent() {
        let mut payload = grant_payload();
        if let OrgRequestPayload::Grant {
            receiving_tenant_id,
            ..
        } = &mut payload
        {
            *receiving_tenant_id = 0;
        }
        assert!(validate_payload(&payload).is_err());

        let payload = OrgRequestPayload::Attach {
            child_tenant_id: 7,
            parent_tenant_id: 7,
        };
        assert!(validate_payload(&payload).is_err());
    }

    #[test]
    fn root_source_scope_is_always_self_owned() {
        let foreign_scope = OrgScope {
            resource_tenant_id: 21,
            domain_id: None,
            resource: "learn_subject".into(),
            action: "read".into(),
            validity: ValidityWindow::perpetual(),
        };
        let root_init = OrgRequestPayload::RootInit {
            root_tenant_id: 20,
            initial_grants: vec![OrgGrantSeed {
                scope: foreign_scope.clone(),
                delegable: false,
            }],
        };
        let root_grant = OrgRequestPayload::RootGrant {
            root_tenant_id: 20,
            scope: foreign_scope,
            delegable: false,
        };
        for payload in [root_init, root_grant] {
            let error = validate_payload(&payload)
                .expect_err("root source scope with a foreign resource tenant must fail closed");
            assert!(error
                .to_string()
                .contains("org_scope.root_source_resource_tenant_mismatch"));
        }
    }

    #[test]
    fn approval_revalidates_durable_payload_before_status_cas_and_dispatch_rechecks_roots() {
        let source = include_str!("requests.rs");
        let approval = source
            .find("pub(crate) async fn approve_request(")
            .expect("approval mutation must remain");
        let approval_body = &source[approval..];
        let parse = approval_body
            .find("let payload = parse_payload(&request.payload_json)?;")
            .expect("approval must parse the locked durable payload");
        let validate = approval_body
            .find("validate_payload(&payload)?;")
            .expect("approval must validate the locked durable payload");
        let status_cas = approval_body
            .find("let decided = sqlx::query(REQUEST_DECIDE_SQL)")
            .expect("approval status CAS must remain");
        assert!(parse < validate && validate < status_cas);

        let dispatch = source
            .find("async fn dispatch_approved_mutation(")
            .expect("approval dispatch must remain");
        let dispatch_end = source[dispatch..]
            .find("async fn create_root_in_tx(")
            .map(|offset| dispatch + offset)
            .expect("root creation must follow approval dispatch");
        let dispatch_body = &source[dispatch..dispatch_end];
        assert!(dispatch_body.contains("require_root_source_scope(*root_tenant_id, &seed.scope)?;"));
        assert!(dispatch_body.contains("require_root_source_scope(*root_tenant_id, scope)?;"));
    }

    #[test]
    fn personal_grant_requires_unit_parent_and_membership_proof_in_transaction() {
        let source = include_str!("requests.rs");
        let issue = source
            .find("async fn issue_grant_in_tx(")
            .expect("grant approval kernel must remain");
        let body = &source[issue..];
        let parent_guard = body
            .find("if parent.subject_kind == \"PERSONAL\"")
            .expect("PERSONAL grants must reject PERSONAL parents");
        let membership_guard = body
            .find("lock_personal_grant_membership_in_tx")
            .expect("PERSONAL grants must lock current membership");
        let insert = body
            .find("sqlx::query(GRANT_INSERT_SQL)")
            .expect("grant insert must remain");
        assert!(parent_guard < membership_guard && membership_guard < insert);
        assert!(source.contains("personal_grant_membership_root_mismatch"));
    }
    #[test]
    fn governance_proof_is_required_and_binds_capability() {
        let cmd = OrgApproveCommand {
            request_id: 1,
            expected_revision: 1,
            approver_user_id: 1,
            approver_tenant_id: None,
            operation_id: "op".into(),
            note: None,
            governance_proof: None,
        };
        let scope = OrgScope {
            resource_tenant_id: 20,
            domain_id: None,
            resource: "learn_subject".into(),
            action: "read".into(),
            validity: ValidityWindow::perpetual(),
        };
        let scopes: [&OrgScope; 1] = [&scope];
        assert!(require_governance_proof(cmd.governance_proof.as_ref(), &scopes).is_err());

        let proving_cmd = OrgApproveCommand {
            request_id: 1,
            expected_revision: 1,
            approver_user_id: 1,
            approver_tenant_id: None,
            operation_id: "op".into(),
            note: None,
            governance_proof: Some(OrgGovernanceProof {
                permission_resource: GOVERNANCE_META_RESOURCE.into(),
                permission_action: GOVERNANCE_META_ACTION.into(),
                admission_operation_id: "adm-1".into(),
                approved_capabilities: vec![OrgScope {
                    resource_tenant_id: 20,
                    domain_id: None,
                    resource: "learn_subject:*".into(),
                    action: "*".into(),
                    validity: ValidityWindow::perpetual(),
                }],
            }),
        };
        assert!(require_governance_proof(proving_cmd.governance_proof.as_ref(), &scopes).is_ok());

        // 能力范围绑定：待发 scope 超出证明范围必须拒绝。
        let outside = OrgScope {
            resource_tenant_id: 30,
            domain_id: None,
            resource: "learn_subject".into(),
            action: "read".into(),
            validity: ValidityWindow::perpetual(),
        };
        let outside_scopes: [&OrgScope; 1] = [&outside];
        assert!(
            require_governance_proof(proving_cmd.governance_proof.as_ref(), &outside_scopes)
                .is_err()
        );
    }

    #[test]
    fn governance_proof_meta_permission_must_match_registered_pair() {
        let scope = OrgScope {
            resource_tenant_id: 20,
            domain_id: None,
            resource: "learn_subject".into(),
            action: "read".into(),
            validity: ValidityWindow::perpetual(),
        };
        let scopes: [&OrgScope; 1] = [&scope];
        let cmd_with = |resource: &str, action: &str| OrgApproveCommand {
            request_id: 1,
            expected_revision: 1,
            approver_user_id: 1,
            approver_tenant_id: None,
            operation_id: "op".into(),
            note: None,
            governance_proof: Some(OrgGovernanceProof {
                permission_resource: resource.into(),
                permission_action: action.into(),
                admission_operation_id: "adm-1".into(),
                approved_capabilities: vec![OrgScope {
                    resource_tenant_id: 20,
                    domain_id: None,
                    resource: "learn_subject:*".into(),
                    action: "*".into(),
                    validity: ValidityWindow::perpetual(),
                }],
            }),
        };
        assert!(require_governance_proof(
            cmd_with("org_authority_edge", "bootstrap")
                .governance_proof
                .as_ref(),
            &scopes
        )
        .is_ok());
        // 精确匹配：非空但未注册的取值（含历史遗留别名）一律 fail-closed。
        assert!(require_governance_proof(
            cmd_with("org_scope_root", "bootstrap")
                .governance_proof
                .as_ref(),
            &scopes
        )
        .is_err());
        assert!(require_governance_proof(
            cmd_with("org_authority_edge", "approve")
                .governance_proof
                .as_ref(),
            &scopes
        )
        .is_err());
        assert!(require_governance_proof(
            cmd_with("", "bootstrap").governance_proof.as_ref(),
            &scopes
        )
        .is_err());
        assert!(require_governance_proof(
            cmd_with("org_authority_edge", "").governance_proof.as_ref(),
            &scopes
        )
        .is_err());
    }

    #[test]
    fn decision_note_length_is_bounded_at_boundary() {
        assert!(validated_decision_note(None).is_ok());
        assert!(validated_decision_note(Some("ok")).is_ok());
        assert!(
            validated_decision_note(Some(&"n".repeat(DECISION_NOTE_MAX_BYTES))).is_ok(),
            "exactly the durable column/service bound must be accepted"
        );
        assert!(validated_decision_note(Some(&"n".repeat(DECISION_NOTE_MAX_BYTES + 1))).is_err());
    }

    fn self_owned_scope(tenant_id: i64) -> OrgScope {
        OrgScope {
            resource_tenant_id: tenant_id,
            domain_id: None,
            resource: "learn_subject".into(),
            action: "read".into(),
            validity: ValidityWindow::perpetual(),
        }
    }

    fn one_payload_per_kind() -> Vec<OrgRequestPayload> {
        vec![
            grant_payload(),
            OrgRequestPayload::Attach {
                child_tenant_id: 20,
                parent_tenant_id: 10,
            },
            OrgRequestPayload::Move {
                child_tenant_id: 20,
                new_parent_tenant_id: 30,
            },
            OrgRequestPayload::Detach {
                child_tenant_id: 20,
            },
            OrgRequestPayload::RootInit {
                root_tenant_id: 20,
                initial_grants: vec![OrgGrantSeed {
                    scope: self_owned_scope(20),
                    delegable: false,
                }],
            },
            OrgRequestPayload::RootGrant {
                root_tenant_id: 20,
                scope: self_owned_scope(20),
                delegable: false,
            },
        ]
    }

    #[test]
    fn create_actor_tenant_must_match_payload_requester() {
        // 服务层以签名 actor tenant 派生 requester；DB 边界要求 Some(requester)
        // 精确一致：None 或任何其他租户（含 0）一律拒绝。
        for payload in one_payload_per_kind() {
            let requester = requester_of(&payload);
            assert!(
                validated_actor_tenant(Some(requester), requester).is_ok(),
                "kind {} must accept its own requester tenant",
                payload.kind().as_str()
            );
            assert!(validated_actor_tenant(None, requester).is_err());
            assert!(validated_actor_tenant(Some(requester + 1), requester).is_err());
            assert!(validated_actor_tenant(Some(0), requester).is_err());
        }
    }

    #[test]
    fn counterparty_decider_binding_covers_attach_and_move() {
        // ATTACH/MOVE：决策人必须是载荷对侧父租户。
        let attach = OrgRequestPayload::Attach {
            child_tenant_id: 20,
            parent_tenant_id: 10,
        };
        assert!(require_counterparty_decider(Some(10), &attach).is_ok());
        assert!(require_counterparty_decider(None, &attach).is_err());
        assert!(require_counterparty_decider(Some(11), &attach).is_err());
        assert!(require_counterparty_decider(Some(20), &attach).is_err());

        let move_payload = OrgRequestPayload::Move {
            child_tenant_id: 20,
            new_parent_tenant_id: 30,
        };
        assert!(require_counterparty_decider(Some(30), &move_payload).is_ok());
        assert!(require_counterparty_decider(Some(10), &move_payload).is_err());

        // 其余 kind 不绑定载荷对侧：GRANT/DETACH 由锁定态当前直接父复核，
        // ROOT_* 凭治理元能力（本检查放行，不构成旁路）。
        for payload in [
            grant_payload(),
            OrgRequestPayload::Detach {
                child_tenant_id: 20,
            },
        ] {
            assert!(require_counterparty_decider(None, &payload).is_ok());
        }
        for payload in one_payload_per_kind() {
            if matches!(
                payload,
                OrgRequestPayload::RootInit { .. } | OrgRequestPayload::RootGrant { .. }
            ) {
                assert!(require_counterparty_decider(None, &payload).is_ok());
            }
        }
    }

    #[test]
    fn requesting_parent_decider_binding_rejects_sibling_grandparent_and_absent() {
        // 锁定态当前直接父 = 10：父本人放行；同根兄弟（11）/祖父（5）/
        // 子单元自身/缺租户/无父态一律 fail-closed。
        assert!(require_requesting_parent_decider(Some(10), Some(10)).is_ok());
        assert!(require_requesting_parent_decider(Some(11), Some(10)).is_err());
        assert!(require_requesting_parent_decider(Some(5), Some(10)).is_err());
        assert!(require_requesting_parent_decider(Some(20), Some(10)).is_err());
        assert!(require_requesting_parent_decider(None, Some(10)).is_err());
        assert!(require_requesting_parent_decider(Some(10), None).is_err());
        assert!(require_requesting_parent_decider(None, None).is_err());
    }

    fn root_grant_payload() -> OrgRequestPayload {
        OrgRequestPayload::RootGrant {
            root_tenant_id: 20,
            scope: self_owned_scope(20),
            delegable: false,
        }
    }

    fn proving_governance_proof() -> OrgGovernanceProof {
        OrgGovernanceProof {
            permission_resource: GOVERNANCE_META_RESOURCE.into(),
            permission_action: GOVERNANCE_META_ACTION.into(),
            admission_operation_id: "adm-1".into(),
            approved_capabilities: vec![OrgScope {
                resource_tenant_id: 20,
                domain_id: None,
                resource: "learn_subject:*".into(),
                action: "*".into(),
                validity: ValidityWindow::perpetual(),
            }],
        }
    }

    /// 驳回权与审批权同界（纯函数冻结）：ROOT_INIT/ROOT_GRANT 驳回必须携带与
    /// 审批同构的治理证明（缺证/非注册 meta 对 fail-closed）；非根 kind 无证明
    /// 要求（非根驳回行为保持不变）。
    #[test]
    fn root_reject_requires_same_governance_proof_as_approve() {
        // ROOT_*：缺证拒绝（直接仓储调用不能凭上游 generic 路由权限驳回根请求）。
        assert!(matches!(
            required_governance_proof(None, &root_grant_payload()),
            Err(AstralError::Permission(message))
                if message.contains("org_scope.governance_proof_required")
        ));
        // 合法证明放行，且返回的引用就是命令携带的证明（供 durable 审计）。
        let proof = proving_governance_proof();
        assert_eq!(
            required_governance_proof(Some(&proof), &root_grant_payload()).unwrap(),
            Some(&proof)
        );
        // 非注册 meta 对（驳回伪造审批权）拒绝。
        let mut forged = proof.clone();
        forged.permission_action = "approve".into();
        assert!(required_governance_proof(Some(&forged), &root_grant_payload()).is_err());
        // 能力越界的证明对 ROOT_* 同样拒绝（能力绑定请求自身待发 scope）。
        let mut overreaching = proof.clone();
        overreaching.approved_capabilities = vec![self_owned_scope(30)];
        assert!(required_governance_proof(Some(&overreaching), &root_grant_payload()).is_err());

        // 非根 kind：无证明要求（None 与携带证明均放行，字段被忽略）。
        assert!(required_governance_proof(None, &grant_payload()).is_ok());
        assert!(required_governance_proof(Some(&proof), &grant_payload()).is_ok());
    }

    fn parentless_node(tenant_id: i64, root_tenant_id: i64) -> OrgNodeRow {
        OrgNodeRow {
            tenant_id,
            root_tenant_id,
            parent_tenant_id: None,
            generation: 3,
            revoke_fence: 1,
            relationship_revision: 2,
            active: true,
            last_operation_id: "op-test".into(),
            activation_operator_user_id: Some(1),
            activation_approval_operation_id: Some("op-test".into()),
        }
    }

    /// ATTACH 既有独立根的旧根退休判定（纯函数冻结）：parentless ⟹ former root
    /// = 自身 root；带父态拒绝（同根 reparent 归 MOVE，不经本判定）。
    #[test]
    fn attach_former_root_retirement_decision_is_frozen() {
        assert_eq!(
            former_root_to_retire_on_attach(&parentless_node(20, 20)).unwrap(),
            20
        );
        let mut parented = parentless_node(20, 10);
        parented.parent_tenant_id = Some(10);
        parented.root_tenant_id = 10;
        assert!(matches!(
            former_root_to_retire_on_attach(&parented),
            Err(AstralError::Validation(message))
                if message.contains("org_scope.attach_requires_parentless_child")
        ));
    }

    // ───────────────────────────────────────────────────────────────────────
    // 复活不可能性纯模型（协调准则冻结）
    //
    // C 完成 A→B→A 移动/独立根 detach→attach→再 detach 后，后代 D 的旧
    // active 旧-root grant 不得仅因编译输入 root 过滤重新匹配而回到生效集合。
    // 模型逐字对应三个真实站点（漂移必须显式失败）：
    // 1. 撤销 = `GRANT_REVOKE_SQL`：active 1→0、revision +1、grant_id 不变；
    //    不存在任何把 inactive 行复位为 active 的路径——新授权只会由
    //    `GRANT_INSERT_SQL` 以全新 grant_id + active=1 插入。
    // 2. 编译输入装载 = `GRANT_COMPILE_INPUT_PREDICATE_SQL`（worker.rs）：
    //    `receiving_tenant_id = ? AND active = 1 AND root_tenant_id = 当前 root`。
    // 3. 父解析 = policy-engine org_compiler `resolve_grant_contribution`：
    //    父引用按精确 `(tenant, grant_id, revision)` 在钉住父 publication（由
    //    父单元当前 active grants 派生）内解析；缺失 → `ParentMissing` PENDING
    //    → 该贡献被排除出生效集合（admission_ready=false → 决策 PENDING），
    //    直到存在新的已批准委托链。
    // ───────────────────────────────────────────────────────────────────────

    #[derive(Clone)]
    struct ModelGrant {
        grant_id: &'static str,
        receiving: i64,
        root: i64,
        active: bool,
        revision: u64,
        // (parent_tenant, parent_grant_id, parent_revision) —— 精确父引用。
        parent: Option<(i64, &'static str, u64)>,
    }

    /// 模型：`revoke_received_grants_from_old_root_in_tx`（旧 root 收到侧整体撤销）。
    fn model_revoke_received_from_root(grants: &mut [ModelGrant], receiving: i64, old_root: i64) {
        for grant in grants.iter_mut() {
            if grant.receiving == receiving && grant.root == old_root && grant.active {
                grant.active = false;
                grant.revision += 1;
            }
        }
    }

    /// 模型：编译输入谓词 + 编译器父解析合并为“进入生效集合”判定。
    /// 父 ledger = 父单元在**当前 root** 下的 active grants（父 publication 由
    /// 同一谓词装载派生），与 D 自身的谓词命中无关。
    fn model_effective(grants: &[ModelGrant], receiving: i64, current_root: i64) -> Vec<&str> {
        let ledger_of = |tenant: i64| -> Vec<(&str, u64)> {
            grants
                .iter()
                .filter(|g| g.receiving == tenant && g.root == current_root && g.active)
                .map(|g| (g.grant_id, g.revision))
                .collect()
        };
        grants
            .iter()
            .filter(|g| g.receiving == receiving && g.root == current_root && g.active)
            .filter(|g| match g.parent {
                None => true,
                Some((parent_tenant, parent_id, parent_revision)) => {
                    ledger_of(parent_tenant).contains(&(parent_id, parent_revision))
                }
            })
            .map(|g| g.grant_id)
            .collect()
    }

    /// MOVE A→B→A：C 从 A 收到的 grant 在第一次移动时被撤销（既有 MOVE 失效
    /// 阶段），其精确 `(grant_id, revision)` 从此从 C 的 active ledger 消失。
    /// 第二次移动使 D 的 node root 复原为 A——D 的旧 grant 重新命中 root 过滤，
    /// 但父引用缺失 → ParentMissing → 不得进入生效集合（未经新批准的授权
    /// 复活被阻断）。
    #[test]
    fn moved_descendant_grant_stays_pending_after_root_filter_rematches() {
        const A: i64 = 10;
        const C: i64 = 20;
        const D: i64 = 30;
        let mut grants = vec![
            ModelGrant {
                grant_id: "g_ca",
                receiving: C,
                root: A,
                active: true,
                revision: 2,
                parent: Some((A, "g_a", 1)),
            },
            ModelGrant {
                grant_id: "g_d",
                receiving: D,
                root: A,
                active: true,
                revision: 1,
                parent: Some((C, "g_ca", 2)),
            },
        ];
        assert_eq!(model_effective(&grants, D, A), vec!["g_d"]);
        // C: A→B（撤销 C 从旧 root A 收到的 grants；propagate 随后把 D 的 node
        // root 推到 B，此处以 current_root=B 表达传播后的状态）。
        model_revoke_received_from_root(&mut grants, C, A);
        assert!(!grants.iter().any(|g| g.grant_id == "g_ca" && g.active));
        assert!(model_effective(&grants, D, 40).is_empty());
        // C: B→A（root 复原为 A；D 的旧 g_d 重新命中 root 过滤）。
        assert!(model_effective(&grants, D, A).is_empty());
        // 旧行仍 active 且 root=A——排除它的是父引用失效（ParentMissing），
        // 而不是行被删除/改写（root_tenant_id 行内不可变）。
        assert!(grants
            .iter()
            .any(|g| g.grant_id == "g_d" && g.active && g.root == A));
    }

    /// 既有独立根 detach→attach→再 detach：attach 时对自源 grants 的整体退休
    /// （`former_root_to_retire_on_attach` → 撤销内核）使后代旧 grant 的父引用
    /// 在 root 复原后无法解析；反事实（不撤销）则复活成立——证明退休是
    /// load-bearing，而非依赖表面行为。
    #[test]
    fn attached_independent_root_self_grants_cannot_resurrect_after_redetach() {
        const C: i64 = 20;
        const D: i64 = 30;
        // C 为独立根（root=C），持自源 g_cs；D 挂在 C 下，g_d 继承自 g_cs。
        let mut grants = vec![
            ModelGrant {
                grant_id: "g_cs",
                receiving: C,
                root: C,
                active: true,
                revision: 1,
                parent: None,
            },
            ModelGrant {
                grant_id: "g_d",
                receiving: D,
                root: C,
                active: true,
                revision: 1,
                parent: Some((C, "g_cs", 1)),
            },
        ];
        // attach 到 B：真实实现先经 `former_root_to_retire_on_attach` 决定
        // former root，再整体撤销（撤销先于拓扑改挂）。
        let former_root = former_root_to_retire_on_attach(&parentless_node(C, C)).unwrap();
        model_revoke_received_from_root(&mut grants, C, former_root);
        // 再次 detach（root 复原为 C）：g_d（active、root=C）重新命中过滤，
        // 但父引用 (g_cs, 1) 已从 C 的 active ledger 消失 → 不进生效集合。
        assert!(model_effective(&grants, D, C).is_empty());
        // C 自身 ledger 亦无复活行（g_cs 已撤销且 revision 前进、永不错位复位）。
        assert!(model_effective(&grants, C, C).is_empty());

        // 反事实（修复前）：attach 只改挂拓扑、不退休自源 grants → root 复原
        // 后 g_cs 仍 active，D 的父引用精确命中 → g_d 复活（未经任何新批准）。
        let resurrected = vec![
            ModelGrant {
                grant_id: "g_cs",
                receiving: C,
                root: C,
                active: true,
                revision: 1,
                parent: None,
            },
            ModelGrant {
                grant_id: "g_d",
                receiving: D,
                root: C,
                active: true,
                revision: 1,
                parent: Some((C, "g_cs", 1)),
            },
        ];
        assert_eq!(model_effective(&resurrected, D, C), vec!["g_d"]);
    }
}
