//! ORG_SCOPE 直接变更原语：grant 撤销、mask、membership（供审批调度的 node
//! 变更 SQL 常量亦在此），以及操作幂等账/审计/outbox/revision 事务内原语。
//!
//! 纪律（合同 DB boundaries）：
//! - 每个 pub 方法 = 一个 source 短事务：操作幂等账认领 → 锁定读结构校验 →
//!   变更 + generation CAS 推进 → revision 账 + outbox 事件 + 审计 → outcome
//!   落账 → 提交。
//! - 审批路径（requests.rs）在同一事务内调用 `_in_tx` 内核，复用审批操作的
//!   operation_id，不再二次认领。
//! - 所有写路径拒绝把 org 载荷写入旧 delta 链。
//! - membership create 以单表 `identity_card.uk_ic_user` 锁作为每用户串行锚点；
//!   物理双卡 join 仍是唯一绑定/健康证明，卡级与用户级 membership 锁只负责
//!   相应的唯一性与容量边界。
//! - 并发锁序冲突（如 grant→node 与 node→grant 交叉）由 InnoDB 死锁检测中止
//!   单事务，映射为可重试 Database 错误（worker/请求保持 PENDING），绝不部分
//!   提交。

use super::requests::append_dependency_propagate_intent_in_tx;
use super::*;
use serde::Serialize;

/// Direct local mutations are scoped to the signed actor's user-card tenant.
/// PolicyEngine proves the actor's permission before this repository boundary;
/// this structural check prevents an internal caller from retargeting that
/// approved local action at another tenant.
fn require_local_actor_tenant(
    actor_tenant_id: Option<i64>,
    tenant_id: i64,
) -> Result<(), AstralError> {
    if actor_tenant_id == Some(tenant_id) {
        return Ok(());
    }
    Err(AstralError::Permission(
        "code=org_scope.local_actor_tenant_mismatch".into(),
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// 直接命令 pre-flight（纯校验；事务/幂等认领/durable 写入之前）
// ─────────────────────────────────────────────────────────────────────────────

/// 直接本地命令的事务前 pre-flight 全部为纯校验：形状/id/租户检查 + actor
/// 租户边界门。每个 `OrgScopeRepository` 直接变更方法在 `begin_tx` /
/// `claim_operation_in_tx` 之前无条件调用对应校验器，因此重放路径（同
/// operation_id 命中已落账 outcome）也必须先通过当前 actor 边界，已记录的
/// outcome 不能绕过该门。审批路径（requests.rs）在同一事务内直接调用
/// `_in_tx` 内核，不经过这些直接命令 pre-flight，其 actor 校验归属审批流。
///
/// 校验顺序保持既有顺序不变，仅在租户正性检查之后插入 actor 边界门；
/// 不削弱、不放宽任何既有检查。
fn validate_grant_revoke_command(cmd: &OrgGrantRevokeCommand) -> Result<(), AstralError> {
    validated_operation_id(&cmd.operation_id)?;
    positive_i64(cmd.actor_user_id, "actor_user_id")?;
    positive_i64(cmd.receiving_tenant_id, "receiving_tenant_id")?;
    require_local_actor_tenant(cmd.actor_tenant_id, cmd.receiving_tenant_id)?;
    validated_stable_uuid(&cmd.grant_id, "grant_id")?;
    if cmd.expected_revision == 0 {
        return Err(AstralError::Validation(
            "code=org_scope.invalid_expected_revision;field=grant".into(),
        ));
    }
    if cmd
        .reason
        .as_deref()
        .is_some_and(|reason| reason.len() > 512)
    {
        return Err(AstralError::Validation(
            "code=org_scope.grant_revoke_reason_too_long".into(),
        ));
    }
    Ok(())
}

fn validate_mask_apply_command(cmd: &OrgMaskApplyCommand) -> Result<(), AstralError> {
    validated_operation_id(&cmd.operation_id)?;
    positive_i64(cmd.actor_user_id, "actor_user_id")?;
    positive_i64(cmd.tenant_id, "tenant_id")?;
    require_local_actor_tenant(cmd.actor_tenant_id, cmd.tenant_id)?;
    cmd.target.validate().map_err(org_err)?;
    validated_stable_uuid(&cmd.target.grant_id, "target.grant_id")?;
    if cmd.target.tenant_id == cmd.tenant_id {
        return Err(AstralError::Validation(
            "code=org_scope.mask_target_self".into(),
        ));
    }
    if cmd.expected_unit_generation == 0 {
        return Err(AstralError::Validation(
            "code=org_scope.invalid_expected_generation;field=unit".into(),
        ));
    }
    Ok(())
}

fn validate_mask_remove_command(cmd: &OrgMaskRemoveCommand) -> Result<(), AstralError> {
    validated_operation_id(&cmd.operation_id)?;
    positive_i64(cmd.actor_user_id, "actor_user_id")?;
    positive_i64(cmd.tenant_id, "tenant_id")?;
    require_local_actor_tenant(cmd.actor_tenant_id, cmd.tenant_id)?;
    validated_stable_uuid(&cmd.mask_id, "mask_id")?;
    if cmd.expected_revision == 0 {
        return Err(AstralError::Validation(
            "code=org_scope.invalid_expected_revision;field=mask".into(),
        ));
    }
    Ok(())
}

fn validate_membership_create_command(cmd: &OrgMembershipCreateCommand) -> Result<(), AstralError> {
    validated_operation_id(&cmd.operation_id)?;
    positive_i64(cmd.actor_user_id, "actor_user_id")?;
    positive_i64(cmd.tenant_id, "tenant_id")?;
    require_local_actor_tenant(cmd.actor_tenant_id, cmd.tenant_id)?;
    positive_i64(cmd.user_id, "user_id")?;
    positive_i64(cmd.identity_card_id, "identity_card_id")?;
    positive_i64(cmd.card_id, "card_id")?;
    cmd.validity.validate().map_err(|error| {
        AstralError::Validation(format!(
            "code=org_scope.invalid_membership_validity;detail={error}"
        ))
    })
}

fn validate_membership_revoke_command(cmd: &OrgMembershipRevokeCommand) -> Result<(), AstralError> {
    validated_operation_id(&cmd.operation_id)?;
    positive_i64(cmd.actor_user_id, "actor_user_id")?;
    positive_i64(cmd.tenant_id, "tenant_id")?;
    require_local_actor_tenant(cmd.actor_tenant_id, cmd.tenant_id)?;
    validated_stable_uuid(&cmd.membership_id, "membership_id")?;
    if cmd.expected_revision == 0 {
        return Err(AstralError::Validation(
            "code=org_scope.invalid_expected_revision;field=membership".into(),
        ));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// node 变更 SQL 常量（requests.rs 审批内核复用）
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) const NODE_INSERT_SQL: &str = "INSERT INTO org_scope_node \
     (tenant_id, root_tenant_id, parent_tenant_id, generation, revoke_fence, \
      relationship_revision, active, created_request_id, created_operation_id, \
      last_operation_id) \
     VALUES (?, ?, ?, 1, 0, 1, 1, ?, ?, ?)";
pub(crate) const NODE_MOVE_SQL: &str = "UPDATE org_scope_node SET parent_tenant_id = ?, \
     root_tenant_id = ?, relationship_revision = relationship_revision + 1, \
     revoke_fence = revoke_fence + 1, generation = generation + 1, last_operation_id = ? \
     WHERE tenant_id = ? AND relationship_revision = ?";
/// 改挂时同步清空 root activation 证明列：`root_activation` 是行政根专属证据
/// （`OrgNode::validate`："reserved for administrative roots"）。独立根并入后
/// 节点不再是根，保留旧证明会让后续状态引用一段已不存在的独立治理期；下次
/// DETACH 会以当次批准人 + 审批 operation id 重新落一份新证明，绝不复用旧值
/// （重挂不削弱/不透传既有证明）。brand-new 子分支（NODE_INSERT）的激活列
/// 本就是 NULL，此处清空对其为无操作。
pub(crate) const NODE_ATTACH_SQL: &str = "UPDATE org_scope_node SET parent_tenant_id = ?, \
     root_tenant_id = ?, relationship_revision = relationship_revision + 1, \
     revoke_fence = revoke_fence + 1, generation = generation + 1, \
     activation_operator_user_id = NULL, activation_approval_operation_id = NULL, \
     last_operation_id = ? \
     WHERE tenant_id = ? AND relationship_revision = ? AND parent_tenant_id IS NULL";
pub(crate) const NODE_DETACH_SQL: &str = "UPDATE org_scope_node SET parent_tenant_id = NULL, \
     root_tenant_id = tenant_id, relationship_revision = relationship_revision + 1, \
     revoke_fence = revoke_fence + 1, generation = generation + 1, last_operation_id = ? \
     WHERE tenant_id = ? AND relationship_revision = ? AND parent_tenant_id IS NOT NULL";
/// 独立行政根激活证明写入（ROOT_INIT 与 DETACH 共用同一合同）：parentless
/// node 必须携带显式 activation 证明（`typed_node` / `OrgNode::validate`），
/// 证明人 = 当次批准的 approver + 审批 operation id，绝不沿用历史值。
pub(crate) const NODE_ROOT_ACTIVATION_SQL: &str = "UPDATE org_scope_node \
     SET activation_operator_user_id = ?, activation_approval_operation_id = ? \
     WHERE tenant_id = ?";

// ─────────────────────────────────────────────────────────────────────────────
// grant/membership 行视图与类型转换（以 astral-types::org_scope 实际字段为准）
// ─────────────────────────────────────────────────────────────────────────────

/// grant 行视图（当前状态）。
#[derive(Debug, Clone)]
pub(crate) struct OrgGrantRow {
    pub grant_id: String,
    pub revision: i64,
    pub receiving_tenant_id: i64,
    pub origin_tenant_id: i64,
    pub root_tenant_id: i64,
    pub resource_tenant_id: i64,
    pub domain_id: Option<i64>,
    pub resource: String,
    pub action: String,
    pub valid_from: Option<i64>,
    pub valid_until: Option<i64>,
    pub delegable: bool,
    pub parent_tenant_id: Option<i64>,
    pub parent_grant_id: Option<String>,
    pub parent_grant_revision: Option<i64>,
    pub subject_kind: String,
    pub subject_user_id: Option<i64>,
    pub subject_card_id: Option<i64>,
    pub active: bool,
    pub operation_id: String,
}

pub(crate) const GRANT_SELECT_COLUMNS: &str = "grant_id, revision, receiving_tenant_id, \
     origin_tenant_id, root_tenant_id, resource_tenant_id, domain_id, resource, action, \
     valid_from, valid_until, delegable, parent_tenant_id, parent_grant_id, \
     parent_grant_revision, subject_kind, subject_user_id, subject_card_id, active, operation_id";

pub(crate) fn grant_from_row(row: &sqlx::mysql::MySqlRow) -> Result<OrgGrantRow, AstralError> {
    Ok(OrgGrantRow {
        grant_id: row.try_get("grant_id").map_err(db_err)?,
        revision: row.try_get("revision").map_err(db_err)?,
        receiving_tenant_id: row.try_get("receiving_tenant_id").map_err(db_err)?,
        origin_tenant_id: row.try_get("origin_tenant_id").map_err(db_err)?,
        root_tenant_id: row.try_get("root_tenant_id").map_err(db_err)?,
        resource_tenant_id: row.try_get("resource_tenant_id").map_err(db_err)?,
        domain_id: row.try_get("domain_id").map_err(db_err)?,
        resource: row.try_get("resource").map_err(db_err)?,
        action: row.try_get("action").map_err(db_err)?,
        valid_from: row.try_get("valid_from").map_err(db_err)?,
        valid_until: row.try_get("valid_until").map_err(db_err)?,
        delegable: row.try_get::<i8, _>("delegable").map_err(db_err)? != 0,
        parent_tenant_id: row.try_get("parent_tenant_id").map_err(db_err)?,
        parent_grant_id: row.try_get("parent_grant_id").map_err(db_err)?,
        parent_grant_revision: row.try_get("parent_grant_revision").map_err(db_err)?,
        subject_kind: row.try_get("subject_kind").map_err(db_err)?,
        subject_user_id: row.try_get("subject_user_id").map_err(db_err)?,
        subject_card_id: row.try_get("subject_card_id").map_err(db_err)?,
        active: row.try_get::<i8, _>("active").map_err(db_err)? != 0,
        operation_id: row.try_get("operation_id").map_err(db_err)?,
    })
}

pub(crate) fn grant_scope(row: &OrgGrantRow) -> OrgScope {
    OrgScope {
        resource_tenant_id: row.resource_tenant_id,
        domain_id: row.domain_id,
        resource: row.resource.clone(),
        action: row.action.clone(),
        validity: ValidityWindow {
            not_before: row.valid_from,
            expires_at: row.valid_until,
        },
    }
}

/// 类型化 `astral_types::org_scope::OrgGrant` 视图（编译/审计载荷）。
pub(crate) fn typed_grant(
    row: &OrgGrantRow,
) -> Result<astral_types::org_scope::OrgGrant, AstralError> {
    let subject = match row.subject_kind.as_str() {
        "PERSONAL" => Some(astral_types::org_scope::OrgSubject {
            user_id: row.subject_user_id.ok_or_else(|| {
                AstralError::Database("code=org_scope.personal_grant_user_missing".into())
            })?,
            card_id: row.subject_card_id.ok_or_else(|| {
                AstralError::Database("code=org_scope.personal_grant_card_missing".into())
            })?,
        }),
        "UNIT" => {
            if row.subject_user_id.is_some() || row.subject_card_id.is_some() {
                return Err(AstralError::Database(
                    "code=org_scope.unit_grant_subject_present".into(),
                ));
            }
            None
        }
        _ => {
            return Err(AstralError::Database(
                "code=org_scope.grant_subject_kind_invalid".into(),
            ))
        }
    };
    Ok(astral_types::org_scope::OrgGrant {
        grant_id: row.grant_id.clone(),
        revision: row_generation(row.revision, "grant.revision")?,
        receiving_tenant_id: row.receiving_tenant_id,
        origin_tenant_id: row.origin_tenant_id,
        root_tenant_id: row.root_tenant_id,
        scope: grant_scope(row),
        delegable: row.delegable,
        parent: match (
            &row.parent_grant_id,
            &row.parent_tenant_id,
            row.parent_grant_revision,
        ) {
            (Some(grant_id), Some(tenant_id), Some(revision)) => Some(OrgGrantRef {
                tenant_id: *tenant_id,
                grant_id: grant_id.clone(),
                revision: row_generation(revision, "grant.parent_revision")?,
            }),
            _ => None,
        },
        subject,
        active: row.active,
        operation_id: row.operation_id.clone(),
    })
}

/// membership 行视图。
#[derive(Debug, Clone)]
pub(crate) struct OrgMembershipRow {
    pub membership_id: String,
    pub tenant_id: i64,
    pub root_tenant_id: i64,
    pub user_id: i64,
    pub identity_card_id: i64,
    pub card_id: i64,
    pub revision: i64,
    pub active: bool,
    pub valid_from: Option<i64>,
    pub valid_until: Option<i64>,
    pub operation_id: String,
}

pub(crate) const MEMBERSHIP_SELECT_COLUMNS: &str = "membership_id, tenant_id, root_tenant_id, \
     user_id, identity_card_id, card_id, revision, active, valid_from, valid_until, operation_id";

pub(crate) fn membership_from_row(
    row: &sqlx::mysql::MySqlRow,
) -> Result<OrgMembershipRow, AstralError> {
    Ok(OrgMembershipRow {
        membership_id: row.try_get("membership_id").map_err(db_err)?,
        tenant_id: row.try_get("tenant_id").map_err(db_err)?,
        root_tenant_id: row.try_get("root_tenant_id").map_err(db_err)?,
        user_id: row.try_get("user_id").map_err(db_err)?,
        identity_card_id: row.try_get("identity_card_id").map_err(db_err)?,
        card_id: row.try_get("card_id").map_err(db_err)?,
        revision: row.try_get("revision").map_err(db_err)?,
        active: row.try_get::<i8, _>("active").map_err(db_err)? != 0,
        valid_from: row.try_get("valid_from").map_err(db_err)?,
        valid_until: row.try_get("valid_until").map_err(db_err)?,
        operation_id: row.try_get("operation_id").map_err(db_err)?,
    })
}

pub(crate) fn typed_membership(
    row: &OrgMembershipRow,
) -> Result<astral_types::org_scope::OrgMembership, AstralError> {
    Ok(astral_types::org_scope::OrgMembership {
        membership_id: row.membership_id.clone(),
        tenant_id: row.tenant_id,
        root_tenant_id: row.root_tenant_id,
        user_id: row.user_id,
        identity_card_id: row.identity_card_id,
        card_id: row.card_id,
        revision: row_generation(row.revision, "membership.revision")?,
        active: row.active,
        validity: ValidityWindow {
            not_before: row.valid_from,
            expires_at: row.valid_until,
        },
        operation_id: row.operation_id.clone(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// 操作幂等账 / 审计 / outbox / revision（事务内原语）
// ─────────────────────────────────────────────────────────────────────────────

const OPERATION_INSERT_SQL: &str = "INSERT INTO org_scope_operation \
     (operation_id, operation_kind, tenant_id, input_digest) VALUES (?, ?, ?, ?)";
const OPERATION_SELECT_SQL: &str = "SELECT input_digest, outcome_json FROM org_scope_operation \
     WHERE operation_id = ? FOR UPDATE";
const OPERATION_OUTCOME_SQL: &str = "UPDATE org_scope_operation SET outcome_json = ? \
     WHERE operation_id = ? AND outcome_json IS NULL";

const AUDIT_INSERT_SQL: &str = "INSERT INTO org_scope_audit \
     (tenant_id, actor_user_id, actor_tenant_id, action, subject_kind, subject_id, request_id, \
      operation_id, detail_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";

const OUTBOX_INSERT_SQL: &str = "INSERT INTO org_scope_outbox \
     (event_id, tenant_id, event_kind, operation_id, payload_json, status) \
     VALUES (?, ?, ?, ?, ?, 'PENDING')";

const REVISION_INSERT_SQL: &str = "INSERT INTO org_scope_revision \
     (subject_kind, tenant_id, subject_id, revision, payload_json, payload_digest, operation_id) \
     VALUES (?, ?, ?, ?, ?, ?, ?)";

const GRANT_REVOKE_SQL: &str = "UPDATE org_scope_grant SET active = 0, revision = revision + 1, \
     operation_id = ? WHERE grant_id = ? AND revision = ? AND active = 1";
const RECEIVED_GRANTS_LOCK_SQL: &str = "SELECT grant_id FROM org_scope_grant \
     WHERE receiving_tenant_id = ? AND root_tenant_id = ? AND active = 1 \
     ORDER BY grant_id LIMIT ? FOR UPDATE";

const MASK_INSERT_SQL: &str = "INSERT INTO org_scope_mask \
     (mask_id, tenant_id, target_tenant_id, target_grant_id, target_grant_revision, revision, \
      active, operation_id) VALUES (?, ?, ?, ?, ?, 1, 1, ?)";
const MASK_LOCK_SQL: &str = "SELECT mask_id, tenant_id, target_tenant_id, target_grant_id, \
     target_grant_revision, revision, active, operation_id FROM org_scope_mask \
     WHERE mask_id = ? FOR UPDATE";
const MASK_REMOVE_SQL: &str = "UPDATE org_scope_mask SET active = 0, revision = revision + 1, \
     operation_id = ? WHERE mask_id = ? AND revision = ? AND active = 1";

const MEMBERSHIP_INSERT_SQL: &str = "INSERT INTO org_scope_membership \
     (membership_id, tenant_id, root_tenant_id, user_id, identity_card_id, card_id, revision, \
      active, valid_from, valid_until, operation_id) VALUES (?, ?, ?, ?, ?, ?, 1, 1, ?, ?, ?)";
/// Per-user serialization anchor for membership creation. This intentionally
/// has no health predicates: a matching row is locked first, then the physical
/// binding join below remains the sole proof that the requested card pair is usable.
const MEMBERSHIP_USER_SERIALIZATION_LOCK_SQL: &str = "SELECT card_id FROM identity_card \
     FORCE INDEX (uk_ic_user) WHERE user_id = ? FOR UPDATE";
/// Shared physical card-pair proof SQL. Mutation callers request `FOR UPDATE`;
/// reader callers use the same join as a fresh read-only proof.
pub(crate) fn membership_physical_binding_sql(for_update: bool) -> String {
    let suffix = if for_update { " FOR UPDATE" } else { "" };
    format!(
        "SELECT uc.card_id \
         FROM user_card uc \
         INNER JOIN identity_card ic ON ic.user_id = uc.user_id \
         INNER JOIN platform_user pu ON pu.user_id = uc.user_id \
                                    AND pu.status = 'ACTIVE' AND pu.deleted_at IS NULL \
         INNER JOIN tenant t ON t.tenant_id = uc.tenant_id AND t.status = 'ACTIVE' \
         INNER JOIN tenant_domain_map tdm ON tdm.tenant_id = uc.tenant_id \
                                         AND tdm.domain_id = uc.domain_id AND tdm.status = 'ACTIVE' \
         WHERE uc.card_id = ? AND uc.user_id = ? AND uc.tenant_id = ? \
           AND uc.card_status = 'ACTIVE' AND uc.card_type != 'LEVEL_TEMPLATE_CARD' \
           AND (uc.valid_from IS NULL OR uc.valid_from <= UTC_TIMESTAMP()) \
           AND (uc.valid_until IS NULL OR uc.valid_until >= UTC_TIMESTAMP()) \
           AND ic.card_id = ? AND ic.user_id = ? AND ic.status = 'ACTIVE' \
           AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()){suffix}"
    )
}
const ACTIVE_MEMBERSHIP_BY_CARD_LOCK_SQL: &str = "SELECT membership_id FROM org_scope_membership \
     FORCE INDEX (idx_osmem_card) WHERE card_id = ? AND active = 1 ORDER BY membership_id FOR UPDATE";
const ACTIVE_MEMBERSHIPS_BY_USER_LOCK_SQL: &str = "SELECT membership_id FROM org_scope_membership \
     FORCE INDEX (idx_osmem_user_active) WHERE user_id = ? AND active = 1 LIMIT ? FOR UPDATE";
const MEMBERSHIP_REVOKE_SQL: &str = "UPDATE org_scope_membership SET active = 0, \
     revision = revision + 1, operation_id = ? \
     WHERE membership_id = ? AND revision = ? AND active = 1";

pub(crate) enum OperationClaim {
    Fresh,
    Replayed(serde_json::Value),
}

pub(crate) fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .map(|database| database.is_unique_violation())
        .unwrap_or(false)
}

/// 认领操作幂等槽：同 id 同 digest 且已落 outcome → 重放；同 id 异 digest →
/// Validation 冲突；outcome 缺失（防御）→ 保守冲突。
pub(crate) async fn claim_operation_in_tx(
    tx: &mut Transaction<'static, MySql>,
    operation_id: &str,
    operation_kind: &str,
    tenant_id: i64,
    input_digest: &[u8],
) -> Result<OperationClaim, AstralError> {
    if let Some(row) = sqlx::query(OPERATION_SELECT_SQL)
        .bind(operation_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_err)?
    {
        return match_operation_row(operation_id, &row, input_digest);
    }
    let insert = sqlx::query(OPERATION_INSERT_SQL)
        .bind(operation_id)
        .bind(operation_kind)
        .bind(tenant_id)
        .bind(input_digest)
        .execute(&mut **tx)
        .await;
    match insert {
        Ok(_) => Ok(OperationClaim::Fresh),
        Err(error) if is_unique_violation(&error) => {
            let row = sqlx::query(OPERATION_SELECT_SQL)
                .bind(operation_id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(db_err)?
                .ok_or_else(|| {
                    AstralError::Database(
                        "code=org_scope.operation_claim_lost;reason=duplicate_without_row".into(),
                    )
                })?;
            match_operation_row(operation_id, &row, input_digest)
        }
        Err(error) => Err(db_err(error)),
    }
}

fn match_operation_row(
    operation_id: &str,
    row: &sqlx::mysql::MySqlRow,
    input_digest: &[u8],
) -> Result<OperationClaim, AstralError> {
    let stored_digest: Vec<u8> = row.try_get("input_digest").map_err(db_err)?;
    if stored_digest != input_digest {
        return Err(AstralError::Validation(format!(
            "code=org_scope.operation_digest_conflict;operation_id={operation_id}"
        )));
    }
    let outcome: Option<serde_json::Value> = row.try_get("outcome_json").map_err(db_err)?;
    match outcome {
        Some(value) => Ok(OperationClaim::Replayed(value)),
        None => Err(AstralError::Validation(format!(
            "code=org_scope.operation_inflight;operation_id={operation_id}"
        ))),
    }
}

/// 落操作 outcome（幂等账终态）。
pub(crate) async fn record_operation_outcome_in_tx(
    tx: &mut Transaction<'static, MySql>,
    operation_id: &str,
    outcome: &impl Serialize,
) -> Result<(), AstralError> {
    let outcome_json = serde_json::to_string(outcome)
        .map_err(|error| AstralError::Internal(format!("org_scope outcome serialize: {error}")))?;
    let result = sqlx::query(OPERATION_OUTCOME_SQL)
        .bind(outcome_json)
        .bind(operation_id)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    require_affected_one(&result, "operation_outcome_missing")
}

/// Typed audit record written in the same transaction as its source mutation.
/// Keeping this as one value prevents producer call sites from silently swapping
/// tenant, subject, request, and operation correlations.
pub(crate) struct OrgAuditWrite<'a> {
    pub tenant_id: i64,
    pub actor_user_id: i64,
    pub actor_tenant_id: Option<i64>,
    pub action: &'a str,
    pub subject_kind: &'a str,
    pub subject_id: &'a str,
    pub request_id: Option<i64>,
    pub operation_id: &'a str,
    pub detail_json: Option<&'a str>,
}

/// 审计行（与 source 变更同一事务，可按 operation_id/request_id 关联）。
pub(crate) async fn append_audit_in_tx(
    tx: &mut Transaction<'static, MySql>,
    audit: OrgAuditWrite<'_>,
) -> Result<(), AstralError> {
    let detail_json = audit
        .detail_json
        .map(|detail| {
            if serde_json::from_str::<serde_json::Value>(detail).is_ok() {
                Ok(detail.to_owned())
            } else {
                serde_json::to_string(detail).map_err(|error| {
                    AstralError::Internal(format!("org_scope audit detail serialize: {error}"))
                })
            }
        })
        .transpose()?;
    sqlx::query(AUDIT_INSERT_SQL)
        .bind(audit.tenant_id)
        .bind(audit.actor_user_id)
        .bind(audit.actor_tenant_id)
        .bind(audit.action)
        .bind(audit.subject_kind)
        .bind(audit.subject_id)
        .bind(audit.request_id)
        .bind(audit.operation_id)
        .bind(detail_json)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    Ok(())
}

/// org 专属 outbox 事件（绝不写旧 authorization_delta_event）。
pub(crate) async fn append_outbox_event_in_tx(
    tx: &mut Transaction<'static, MySql>,
    tenant_id: i64,
    event_kind: &str,
    operation_id: &str,
    payload_json: &str,
) -> Result<(), AstralError> {
    let event_id = format!(
        "org:{}:{}",
        event_kind.to_ascii_lowercase(),
        uuid_v4_string()
    );
    sqlx::query(OUTBOX_INSERT_SQL)
        .bind(&event_id)
        .bind(tenant_id)
        .bind(event_kind)
        .bind(operation_id)
        .bind(payload_json)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    Ok(())
}

/// 追加 append-only revision 账行（digest 绑定载荷字节）。
pub(crate) async fn append_revision_in_tx(
    tx: &mut Transaction<'static, MySql>,
    subject_kind: &str,
    tenant_id: i64,
    subject_id: &str,
    revision: u64,
    payload_json: &str,
    operation_id: &str,
) -> Result<(), AstralError> {
    let digest: Vec<u8> = Sha256::digest(payload_json.as_bytes()).to_vec();
    sqlx::query(REVISION_INSERT_SQL)
        .bind(subject_kind)
        .bind(tenant_id)
        .bind(subject_id)
        .bind(gen_to_i64(revision, "revision")?)
        .bind(payload_json)
        .bind(digest)
        .bind(operation_id)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// grant/membership 读取内核
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) async fn lock_grant_in_tx(
    tx: &mut Transaction<'_, MySql>,
    grant_id: &str,
) -> Result<Option<OrgGrantRow>, AstralError> {
    let sql =
        format!("SELECT {GRANT_SELECT_COLUMNS} FROM org_scope_grant WHERE grant_id = ? FOR UPDATE");
    let row = sqlx::query(&sql)
        .bind(grant_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_err)?;
    row.map(|row| grant_from_row(&row)).transpose()
}

pub(crate) async fn lock_membership_in_tx(
    tx: &mut Transaction<'static, MySql>,
    membership_id: &str,
) -> Result<Option<OrgMembershipRow>, AstralError> {
    let sql = format!(
        "SELECT {MEMBERSHIP_SELECT_COLUMNS} FROM org_scope_membership \
         WHERE membership_id = ? FOR UPDATE"
    );
    let row = sqlx::query(&sql)
        .bind(membership_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_err)?;
    row.map(|row| membership_from_row(&row)).transpose()
}

/// Lock and prove the physical identity/card binding for a PERSONAL grant target.
/// The approval transaction follows the membership-create lock order: identify a
/// candidate without locking it, lock the per-user identity anchor, lock the
/// physical binding, then lock and revalidate the membership row. This prevents
/// a create/revoke deadlock while keeping the final proof current at the durable
/// write boundary.
pub(crate) async fn lock_personal_grant_membership_in_tx(
    tx: &mut Transaction<'static, MySql>,
    receiving_tenant_id: i64,
    subject: &astral_types::org_scope::OrgSubject,
) -> Result<OrgMembershipRow, AstralError> {
    let candidate_sql = "SELECT membership_id, identity_card_id FROM org_scope_membership \
         WHERE tenant_id = ? AND user_id = ? AND card_id = ? AND active = 1 \
           AND (valid_from IS NULL OR valid_from <= UNIX_TIMESTAMP()) \
           AND (valid_until IS NULL OR valid_until >= UNIX_TIMESTAMP()) \
         ORDER BY membership_id LIMIT 1";
    let candidate = sqlx::query(candidate_sql)
        .bind(receiving_tenant_id)
        .bind(subject.user_id)
        .bind(subject.card_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_err)?
        .ok_or_else(|| {
            AstralError::Permission(
                "code=org_scope.personal_grant_membership_missing_or_invalid".into(),
            )
        })?;
    let membership_id: String = candidate.try_get("membership_id").map_err(db_err)?;
    let identity_card_id: i64 = candidate.try_get("identity_card_id").map_err(db_err)?;

    let user_anchor = sqlx::query(MEMBERSHIP_USER_SERIALIZATION_LOCK_SQL)
        .bind(subject.user_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_err)?;
    if user_anchor.is_none() {
        return Err(AstralError::Permission(
            "code=org_scope.personal_grant_physical_binding_invalid".into(),
        ));
    }

    let physical = sqlx::query(&membership_physical_binding_sql(true))
        .bind(subject.card_id)
        .bind(subject.user_id)
        .bind(receiving_tenant_id)
        .bind(identity_card_id)
        .bind(subject.user_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_err)?;
    if physical.is_none() {
        return Err(AstralError::Permission(
            "code=org_scope.personal_grant_physical_binding_invalid".into(),
        ));
    }

    let current_sql = format!(
        "SELECT {MEMBERSHIP_SELECT_COLUMNS} FROM org_scope_membership m \
         WHERE m.membership_id = ? AND m.tenant_id = ? AND m.user_id = ? \
           AND m.card_id = ? AND m.active = 1 \
           AND (m.valid_from IS NULL OR m.valid_from <= UNIX_TIMESTAMP()) \
           AND (m.valid_until IS NULL OR m.valid_until >= UNIX_TIMESTAMP()) \
         FOR UPDATE"
    );
    let row = sqlx::query(&current_sql)
        .bind(&membership_id)
        .bind(receiving_tenant_id)
        .bind(subject.user_id)
        .bind(subject.card_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_err)?
        .ok_or_else(|| {
            AstralError::Permission(
                "code=org_scope.personal_grant_membership_missing_or_invalid".into(),
            )
        })?;
    membership_from_row(&row)
}
/// 撤销该租户从旧 root 链收到的全部 active grant（MOVE/DETACH 失效阶段，以及
/// ATTACH 把既有独立根并入新父时对其自源 grants（former root = 自身）的整体
/// 退休）。超出 [`ORG_MAX_GRANTS_REVOKE_PER_TX`] 保守失败（请求保持 PENDING）。
pub(crate) async fn revoke_received_grants_from_old_root_in_tx(
    tx: &mut Transaction<'static, MySql>,
    receiving_tenant_id: i64,
    old_root_tenant_id: i64,
    operation_id: &str,
) -> Result<Vec<OrgMutationRecord>, AstralError> {
    let rows = sqlx::query(RECEIVED_GRANTS_LOCK_SQL)
        .bind(receiving_tenant_id)
        .bind(old_root_tenant_id)
        .bind(ORG_MAX_GRANTS_REVOKE_PER_TX as i64 + 1)
        .fetch_all(&mut **tx)
        .await
        .map_err(db_err)?;
    if rows.len() > ORG_MAX_GRANTS_REVOKE_PER_TX {
        return Err(AstralError::Validation(
            "code=org_scope.move_revoke_budget_exceeded".into(),
        ));
    }
    let mut records = Vec::new();
    for row in rows {
        let grant_id: String = row.try_get("grant_id").map_err(db_err)?;
        let grant = lock_grant_in_tx(tx, &grant_id).await?.ok_or_else(|| {
            AstralError::Database("code=org_scope.grant_vanished_in_revoke".into())
        })?;
        let expected = grant.revision;
        let result = sqlx::query(GRANT_REVOKE_SQL)
            .bind(operation_id)
            .bind(&grant_id)
            .bind(expected)
            .execute(&mut **tx)
            .await
            .map_err(db_err)?;
        require_affected_one(&result, "grant_revoke_race")?;
        let mut revoked = grant.clone();
        revoked.active = false;
        revoked.revision = expected + 1;
        revoked.operation_id = operation_id.to_owned();
        let payload = serde_json::to_string(&typed_grant(&revoked)?)
            .map_err(|error| AstralError::Internal(format!("org_scope grant payload: {error}")))?;
        append_revision_in_tx(
            tx,
            "GRANT",
            revoked.receiving_tenant_id,
            &grant_id,
            row_generation(revoked.revision, "grant.revision")?,
            &payload,
            operation_id,
        )
        .await?;
        append_outbox_event_in_tx(
            tx,
            revoked.receiving_tenant_id,
            ORG_EVENT_GRANT_REVOKED,
            operation_id,
            &payload,
        )
        .await?;
        records.push(OrgMutationRecord {
            record_kind: "GRANT_REVOKED".into(),
            subject_kind: "GRANT".into(),
            subject_id: grant_id,
            tenant_id: revoked.receiving_tenant_id,
        });
    }
    Ok(records)
}

// ─────────────────────────────────────────────────────────────────────────────
// 直接命令结构（API owner 消费面；Serialize 供幂等 digest）
// ─────────────────────────────────────────────────────────────────────────────

/// 撤销 grant（narrowing）。`expected_revision` 为显式乐观栅栏。
#[derive(Debug, Clone, Serialize)]
pub struct OrgGrantRevokeCommand {
    pub operation_id: String,
    pub actor_user_id: i64,
    pub actor_tenant_id: Option<i64>,
    pub receiving_tenant_id: i64,
    pub grant_id: String,
    pub expected_revision: u64,
    pub reason: Option<String>,
}

/// 本级精确来源屏蔽。`target` 必须是本单元某条已接收贡献
/// provenance 链上的祖先 exact ref；`expected_unit_generation` 防止基于过期
/// 单元视图叠加 overlay。
#[derive(Debug, Clone, Serialize)]
pub struct OrgMaskApplyCommand {
    pub operation_id: String,
    pub actor_user_id: i64,
    pub actor_tenant_id: Option<i64>,
    pub tenant_id: i64,
    pub target: OrgGrantRef,
    pub expected_unit_generation: u64,
    pub reason: Option<String>,
}

/// 撤除屏蔽。
#[derive(Debug, Clone, Serialize)]
pub struct OrgMaskRemoveCommand {
    pub operation_id: String,
    pub actor_user_id: i64,
    pub actor_tenant_id: Option<i64>,
    pub tenant_id: i64,
    pub mask_id: String,
    pub expected_revision: u64,
}

/// 创建成员资格。
#[derive(Debug, Clone, Serialize)]
pub struct OrgMembershipCreateCommand {
    pub operation_id: String,
    pub actor_user_id: i64,
    pub actor_tenant_id: Option<i64>,
    pub tenant_id: i64,
    pub user_id: i64,
    pub identity_card_id: i64,
    pub card_id: i64,
    pub validity: ValidityWindow,
}

/// 撤销成员资格。
#[derive(Debug, Clone, Serialize)]
pub struct OrgMembershipRevokeCommand {
    pub operation_id: String,
    pub actor_user_id: i64,
    pub actor_tenant_id: Option<i64>,
    pub tenant_id: i64,
    pub membership_id: String,
    pub expected_revision: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// `_in_tx` 变更内核（直接命令用）
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) async fn revoke_grant_in_tx(
    tx: &mut Transaction<'static, MySql>,
    cmd: &OrgGrantRevokeCommand,
    expected_revision: i64,
) -> Result<Vec<OrgMutationRecord>, AstralError> {
    let grant = lock_grant_in_tx(tx, &cmd.grant_id).await?.ok_or_else(|| {
        AstralError::NotFound(format!(
            "code=org_scope.grant_missing;grant_id={}",
            cmd.grant_id
        ))
    })?;
    if grant.receiving_tenant_id != cmd.receiving_tenant_id {
        return Err(AstralError::Permission(
            "code=org_scope.grant_receiving_tenant_mismatch".into(),
        ));
    }
    if !grant.active {
        return Err(AstralError::Validation(
            "code=org_scope.grant_not_active".into(),
        ));
    }
    let result = sqlx::query(GRANT_REVOKE_SQL)
        .bind(&cmd.operation_id)
        .bind(&cmd.grant_id)
        .bind(expected_revision)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    require_affected_one(&result, "grant_revoke_revision_conflict")?;
    let mut revoked = grant.clone();
    revoked.active = false;
    revoked.revision = expected_revision + 1;
    revoked.operation_id = cmd.operation_id.clone();
    let payload = serde_json::to_string(&typed_grant(&revoked)?)
        .map_err(|error| AstralError::Internal(format!("org_scope grant payload: {error}")))?;
    append_revision_in_tx(
        tx,
        "GRANT",
        revoked.receiving_tenant_id,
        &cmd.grant_id,
        row_generation(revoked.revision, "grant.revision")?,
        &payload,
        &cmd.operation_id,
    )
    .await?;
    append_outbox_event_in_tx(
        tx,
        revoked.receiving_tenant_id,
        ORG_EVENT_GRANT_REVOKED,
        &cmd.operation_id,
        &payload,
    )
    .await?;
    // 撤销是 narrowing：receiving 侧 generation 立即推进，依赖它的下级
    // publication 的绑定 id 随即失配 → PENDING（祖先失效即时可见）。
    let node_after = advance_node_in_tx(
        tx,
        revoked.receiving_tenant_id,
        false,
        false,
        &cmd.operation_id,
    )
    .await?;
    append_dependency_propagate_intent_in_tx(tx, &node_after, &cmd.operation_id).await?;
    append_audit_in_tx(
        tx,
        OrgAuditWrite {
            tenant_id: revoked.receiving_tenant_id,
            actor_user_id: cmd.actor_user_id,
            actor_tenant_id: cmd.actor_tenant_id,
            action: "GRANT_REVOKE",
            subject_kind: "GRANT",
            subject_id: &cmd.grant_id,
            request_id: None,
            operation_id: &cmd.operation_id,
            detail_json: cmd.reason.as_deref(),
        },
    )
    .await?;
    Ok(vec![OrgMutationRecord {
        record_kind: "GRANT_REVOKED".into(),
        subject_kind: "GRANT".into(),
        subject_id: cmd.grant_id.clone(),
        tenant_id: revoked.receiving_tenant_id,
    }])
}

pub(crate) async fn apply_mask_in_tx(
    tx: &mut Transaction<'static, MySql>,
    cmd: &OrgMaskApplyCommand,
) -> Result<Vec<OrgMutationRecord>, AstralError> {
    cmd.target.validate().map_err(org_err)?;
    if cmd.target.tenant_id == cmd.tenant_id {
        return Err(AstralError::Validation(
            "code=org_scope.mask_target_self".into(),
        ));
    }
    if cmd.expected_unit_generation == 0 {
        return Err(AstralError::Validation(
            "code=org_scope.invalid_expected_generation;field=unit".into(),
        ));
    }
    if cmd
        .reason
        .as_deref()
        .is_some_and(|reason| reason.len() > 512)
    {
        return Err(AstralError::Validation(
            "code=org_scope.mask_reason_too_long".into(),
        ));
    }
    let node = lock_node_in_tx(tx, cmd.tenant_id).await?.ok_or_else(|| {
        AstralError::NotFound(format!(
            "code=org_scope.node_missing;tenant_id={}",
            cmd.tenant_id
        ))
    })?;
    if !node.active {
        return Err(AstralError::Validation(
            "code=org_scope.node_inactive".into(),
        ));
    }
    if row_generation(node.generation, "node.generation")? != cmd.expected_unit_generation {
        return Err(AstralError::Validation(
            "code=org_scope.mask_unit_generation_conflict".into(),
        ));
    }
    if !local_grant_chain_contains_target_in_tx(tx, cmd.tenant_id, node.root_tenant_id, &cmd.target)
        .await?
    {
        return Err(AstralError::Permission(
            "code=org_scope.mask_target_not_ancestor_contribution".into(),
        ));
    }

    let mask_id = uuid_v4_string();
    let insert = sqlx::query(MASK_INSERT_SQL)
        .bind(&mask_id)
        .bind(cmd.tenant_id)
        .bind(cmd.target.tenant_id)
        .bind(&cmd.target.grant_id)
        .bind(gen_to_i64(cmd.target.revision, "mask.target_revision")?)
        .bind(&cmd.operation_id)
        .execute(&mut **tx)
        .await;
    match insert {
        Ok(_) => {}
        Err(error) if is_unique_violation(&error) => {
            return Err(AstralError::Validation(
                "code=org_scope.mask_already_active".into(),
            ));
        }
        Err(error) => return Err(db_err(error)),
    }
    let mask = astral_types::org_scope::OrgMask {
        mask_id: mask_id.clone(),
        tenant_id: cmd.tenant_id,
        target: cmd.target.clone(),
        active: true,
        revision: 1,
        operation_id: cmd.operation_id.clone(),
    };
    let mask_payload = serde_json::to_string(&mask)
        .map_err(|error| AstralError::Internal(format!("org_scope mask payload: {error}")))?;
    append_revision_in_tx(
        tx,
        "MASK",
        cmd.tenant_id,
        &mask_id,
        1,
        &mask_payload,
        &cmd.operation_id,
    )
    .await?;
    append_outbox_event_in_tx(
        tx,
        cmd.tenant_id,
        ORG_EVENT_MASK_APPLIED,
        &cmd.operation_id,
        &mask_payload,
    )
    .await?;
    let node_after = advance_node_in_tx(tx, cmd.tenant_id, false, false, &cmd.operation_id).await?;
    append_dependency_propagate_intent_in_tx(tx, &node_after, &cmd.operation_id).await?;
    let audit_detail = serde_json::json!({
        "mask": mask,
        "reason": cmd.reason,
    })
    .to_string();
    append_audit_in_tx(
        tx,
        OrgAuditWrite {
            tenant_id: cmd.tenant_id,
            actor_user_id: cmd.actor_user_id,
            actor_tenant_id: cmd.actor_tenant_id,
            action: "MASK_APPLY",
            subject_kind: "MASK",
            subject_id: &mask_id,
            request_id: None,
            operation_id: &cmd.operation_id,
            detail_json: Some(audit_detail.as_str()),
        },
    )
    .await?;
    Ok(vec![OrgMutationRecord {
        record_kind: "MASK_APPLIED".into(),
        subject_kind: "MASK".into(),
        subject_id: mask_id,
        tenant_id: cmd.tenant_id,
    }])
}

/// Proves that a requested mask target is one of this unit's inherited exact
/// source references. A local grant is never a legal target; callers must
/// revoke it through the grant ledger. Each parent edge is re-locked and
/// revision-checked, so a source revision change cannot be hidden behind an
/// old request payload.
async fn local_grant_chain_contains_target_in_tx(
    tx: &mut Transaction<'_, MySql>,
    tenant_id: i64,
    expected_root_tenant_id: i64,
    target: &OrgGrantRef,
) -> Result<bool, AstralError> {
    let sql = format!(
        "SELECT {GRANT_SELECT_COLUMNS} FROM org_scope_grant \
         WHERE receiving_tenant_id = ? AND active = 1 AND parent_grant_id IS NOT NULL \
         ORDER BY grant_id LIMIT ?"
    );
    let rows = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(ORG_MAX_COMPILE_GRANTS as i64 + 1)
        .fetch_all(&mut **tx)
        .await
        .map_err(db_err)?;
    if rows.len() > ORG_MAX_COMPILE_GRANTS {
        return Err(AstralError::Validation(
            "code=org_scope.mask_chain_grants_exceeded".into(),
        ));
    }
    for row in rows {
        let mut cursor = grant_from_row(&row)?;
        if cursor.root_tenant_id != expected_root_tenant_id {
            return Err(AstralError::Validation(
                "code=org_scope.mask_local_grant_root_mismatch".into(),
            ));
        }
        let mut visited = std::collections::BTreeSet::new();
        let mut exhausted_depth_budget = true;
        for _ in 0..=ORG_MAX_TREE_DEPTH {
            let (Some(parent_tenant_id), Some(parent_grant_id), Some(parent_revision)) = (
                cursor.parent_tenant_id,
                cursor.parent_grant_id.clone(),
                cursor.parent_grant_revision,
            ) else {
                exhausted_depth_budget = false;
                break;
            };
            if cursor.origin_tenant_id != parent_tenant_id {
                return Err(AstralError::Validation(
                    "code=org_scope.mask_parent_origin_mismatch".into(),
                ));
            }
            let parent_ref = OrgGrantRef {
                tenant_id: parent_tenant_id,
                grant_id: parent_grant_id.clone(),
                revision: row_generation(parent_revision, "grant.parent_revision")?,
            };
            if !visited.insert((parent_ref.tenant_id, parent_ref.grant_id.clone())) {
                return Err(AstralError::Validation(
                    "code=org_scope.mask_parent_grant_cycle".into(),
                ));
            }
            let parent = lock_grant_in_tx(tx, &parent_ref.grant_id)
                .await?
                .ok_or_else(|| {
                    AstralError::Validation("code=org_scope.mask_parent_grant_missing".into())
                })?;
            if parent.receiving_tenant_id != parent_ref.tenant_id
                || parent.revision != gen_to_i64(parent_ref.revision, "mask.parent_revision")?
                || !parent.active
            {
                return Err(AstralError::Validation(
                    "code=org_scope.mask_parent_grant_revision_changed".into(),
                ));
            }
            if parent.root_tenant_id != expected_root_tenant_id {
                return Err(AstralError::Validation(
                    "code=org_scope.mask_parent_grant_root_mismatch".into(),
                ));
            }
            if &parent_ref == target {
                return Ok(true);
            }
            cursor = parent;
        }
        if exhausted_depth_budget {
            return Err(AstralError::Validation(
                "code=org_scope.mask_parent_chain_depth_exceeded".into(),
            ));
        }
    }
    Ok(false)
}

pub(crate) async fn remove_mask_in_tx(
    tx: &mut Transaction<'static, MySql>,
    cmd: &OrgMaskRemoveCommand,
) -> Result<Vec<OrgMutationRecord>, AstralError> {
    let mask_row = sqlx::query(MASK_LOCK_SQL)
        .bind(&cmd.mask_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_err)?;
    let mask = mask_row.ok_or_else(|| {
        AstralError::NotFound(format!(
            "code=org_scope.mask_missing;mask_id={}",
            cmd.mask_id
        ))
    })?;
    let tenant_id: i64 = mask.try_get("tenant_id").map_err(db_err)?;
    let revision: i64 = mask.try_get("revision").map_err(db_err)?;
    let active: bool = mask.try_get::<i8, _>("active").map_err(db_err)? != 0;
    let target_tenant_id: i64 = mask.try_get("target_tenant_id").map_err(db_err)?;
    let target_grant_id: String = mask.try_get("target_grant_id").map_err(db_err)?;
    let target_grant_revision: i64 = mask.try_get("target_grant_revision").map_err(db_err)?;
    if tenant_id != cmd.tenant_id {
        return Err(AstralError::Permission(
            "code=org_scope.mask_tenant_mismatch".into(),
        ));
    }
    let expected_revision = gen_to_i64(cmd.expected_revision, "expected_revision")?;
    if revision != expected_revision {
        return Err(AstralError::Validation(
            "code=org_scope.mask_revision_conflict".into(),
        ));
    }
    if !active {
        return Err(AstralError::Validation(
            "code=org_scope.mask_not_active".into(),
        ));
    }
    let result = sqlx::query(MASK_REMOVE_SQL)
        .bind(&cmd.operation_id)
        .bind(&cmd.mask_id)
        .bind(expected_revision)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    require_affected_one(&result, "mask_remove_race")?;
    let next_revision = row_generation(revision, "mask.revision")? + 1;
    let mask_payload = serde_json::to_string(&astral_types::org_scope::OrgMask {
        mask_id: cmd.mask_id.clone(),
        tenant_id,
        target: OrgGrantRef {
            tenant_id: target_tenant_id,
            grant_id: target_grant_id,
            revision: row_generation(target_grant_revision, "mask.target_revision")?,
        },
        active: false,
        revision: next_revision,
        operation_id: cmd.operation_id.clone(),
    })
    .map_err(|error| AstralError::Internal(format!("org_scope mask payload: {error}")))?;
    append_revision_in_tx(
        tx,
        "MASK",
        tenant_id,
        &cmd.mask_id,
        next_revision,
        &mask_payload,
        &cmd.operation_id,
    )
    .await?;
    append_outbox_event_in_tx(
        tx,
        tenant_id,
        ORG_EVENT_MASK_REMOVED,
        &cmd.operation_id,
        &mask_payload,
    )
    .await?;
    let node_after = advance_node_in_tx(tx, tenant_id, false, false, &cmd.operation_id).await?;
    append_dependency_propagate_intent_in_tx(tx, &node_after, &cmd.operation_id).await?;
    append_audit_in_tx(
        tx,
        OrgAuditWrite {
            tenant_id,
            actor_user_id: cmd.actor_user_id,
            actor_tenant_id: cmd.actor_tenant_id,
            action: "MASK_REMOVE",
            subject_kind: "MASK",
            subject_id: &cmd.mask_id,
            request_id: None,
            operation_id: &cmd.operation_id,
            detail_json: Some(mask_payload.as_str()),
        },
    )
    .await?;
    Ok(vec![OrgMutationRecord {
        record_kind: "MASK_REMOVED".into(),
        subject_kind: "MASK".into(),
        subject_id: cmd.mask_id.clone(),
        tenant_id,
    }])
}

async fn ensure_membership_user_serialization_in_tx(
    tx: &mut Transaction<'_, MySql>,
    user_id: i64,
) -> Result<(), AstralError> {
    let row = sqlx::query(MEMBERSHIP_USER_SERIALIZATION_LOCK_SQL)
        .bind(user_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_err)?;
    if row.is_some() {
        return Ok(());
    }
    Err(AstralError::Permission(
        "code=org_scope.membership_physical_card_binding_invalid".into(),
    ))
}

async fn ensure_membership_card_binding_in_tx(
    tx: &mut Transaction<'_, MySql>,
    cmd: &OrgMembershipCreateCommand,
) -> Result<(), AstralError> {
    let row = sqlx::query(&membership_physical_binding_sql(true))
        .bind(cmd.card_id)
        .bind(cmd.user_id)
        .bind(cmd.tenant_id)
        .bind(cmd.identity_card_id)
        .bind(cmd.user_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_err)?;
    if row.is_none() {
        return Err(AstralError::Permission(
            "code=org_scope.membership_physical_card_binding_invalid".into(),
        ));
    }
    Ok(())
}

async fn ensure_card_is_not_actively_assigned_in_tx(
    tx: &mut Transaction<'_, MySql>,
    card_id: i64,
) -> Result<(), AstralError> {
    let rows = sqlx::query(ACTIVE_MEMBERSHIP_BY_CARD_LOCK_SQL)
        .bind(card_id)
        .fetch_all(&mut **tx)
        .await
        .map_err(db_err)?;
    if rows.is_empty() {
        return Ok(());
    }
    Err(AstralError::Validation(
        "code=org_scope.membership_already_active_for_unit".into(),
    ))
}

/// Enforce the globally bounded multi-membership contract after a successful
/// single-row `identity_card.uk_ic_user` serialization anchor. The bounded
/// membership range remains a separate create-versus-revoke boundary; neither
/// its gap-lock behavior nor the multi-table binding join proves the cap alone.
async fn ensure_user_membership_cap_in_tx(
    tx: &mut Transaction<'_, MySql>,
    user_id: i64,
) -> Result<(), AstralError> {
    let cap = i64::try_from(ORG_MAX_ACTIVE_MEMBERSHIPS_PER_USER).map_err(|_| {
        AstralError::Internal("org_scope membership cap exceeds SQL LIMIT range".into())
    })?;
    let lock_limit = cap.checked_add(1).ok_or_else(|| {
        AstralError::Internal("org_scope membership cap lock limit overflows SQL range".into())
    })?;
    let rows = sqlx::query(ACTIVE_MEMBERSHIPS_BY_USER_LOCK_SQL)
        .bind(user_id)
        .bind(lock_limit)
        .fetch_all(&mut **tx)
        .await
        .map_err(db_err)?;
    if rows.len() < ORG_MAX_ACTIVE_MEMBERSHIPS_PER_USER {
        return Ok(());
    }
    Err(AstralError::Validation(format!(
        "code=org_scope.membership_user_cap_exceeded;cap={ORG_MAX_ACTIVE_MEMBERSHIPS_PER_USER}"
    )))
}

pub(crate) async fn create_membership_in_tx(
    tx: &mut Transaction<'static, MySql>,
    cmd: &OrgMembershipCreateCommand,
    valid_from: Option<i64>,
    valid_until: Option<i64>,
) -> Result<Vec<OrgMutationRecord>, AstralError> {
    let node = lock_node_in_tx(tx, cmd.tenant_id).await?.ok_or_else(|| {
        AstralError::NotFound(format!(
            "code=org_scope.node_missing;tenant_id={}",
            cmd.tenant_id
        ))
    })?;
    if !node.active {
        return Err(AstralError::Validation(
            "code=org_scope.node_inactive".into(),
        ));
    }
    ensure_membership_user_serialization_in_tx(tx, cmd.user_id).await?;
    ensure_membership_card_binding_in_tx(tx, cmd).await?;
    ensure_card_is_not_actively_assigned_in_tx(tx, cmd.card_id).await?;
    ensure_user_membership_cap_in_tx(tx, cmd.user_id).await?;
    let membership_id = uuid_v4_string();
    sqlx::query(MEMBERSHIP_INSERT_SQL)
        .bind(&membership_id)
        .bind(cmd.tenant_id)
        .bind(node.root_tenant_id)
        .bind(cmd.user_id)
        .bind(cmd.identity_card_id)
        .bind(cmd.card_id)
        .bind(valid_from)
        .bind(valid_until)
        .bind(&cmd.operation_id)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    // 成员资格是独立证据对象：不推进 node generation，无需重编译；
    // 读侧逐请求 fresh 校验 membership，撤销即时生效。
    let membership_row = OrgMembershipRow {
        membership_id: membership_id.clone(),
        tenant_id: cmd.tenant_id,
        root_tenant_id: node.root_tenant_id,
        user_id: cmd.user_id,
        identity_card_id: cmd.identity_card_id,
        card_id: cmd.card_id,
        revision: 1,
        active: true,
        valid_from,
        valid_until,
        operation_id: cmd.operation_id.clone(),
    };
    let membership_payload = serde_json::to_string(&typed_membership(&membership_row)?)
        .map_err(|error| AstralError::Internal(format!("org_scope membership payload: {error}")))?;
    append_revision_in_tx(
        tx,
        "MEMBERSHIP",
        cmd.tenant_id,
        &membership_id,
        1,
        &membership_payload,
        &cmd.operation_id,
    )
    .await?;
    append_outbox_event_in_tx(
        tx,
        cmd.tenant_id,
        ORG_EVENT_MEMBERSHIP_CHANGED,
        &cmd.operation_id,
        &membership_payload,
    )
    .await?;
    append_audit_in_tx(
        tx,
        OrgAuditWrite {
            tenant_id: cmd.tenant_id,
            actor_user_id: cmd.actor_user_id,
            actor_tenant_id: cmd.actor_tenant_id,
            action: "MEMBERSHIP_CREATE",
            subject_kind: "MEMBERSHIP",
            subject_id: &membership_id,
            request_id: None,
            operation_id: &cmd.operation_id,
            detail_json: Some(membership_payload.as_str()),
        },
    )
    .await?;
    Ok(vec![OrgMutationRecord {
        record_kind: "MEMBERSHIP_CREATED".into(),
        subject_kind: "MEMBERSHIP".into(),
        subject_id: membership_id,
        tenant_id: cmd.tenant_id,
    }])
}

pub(crate) async fn revoke_membership_in_tx(
    tx: &mut Transaction<'static, MySql>,
    cmd: &OrgMembershipRevokeCommand,
) -> Result<Vec<OrgMutationRecord>, AstralError> {
    let membership = lock_membership_in_tx(tx, &cmd.membership_id)
        .await?
        .ok_or_else(|| {
            AstralError::NotFound(format!(
                "code=org_scope.membership_missing;membership_id={}",
                cmd.membership_id
            ))
        })?;
    if membership.tenant_id != cmd.tenant_id {
        return Err(AstralError::Permission(
            "code=org_scope.membership_tenant_mismatch".into(),
        ));
    }
    let expected_revision = gen_to_i64(cmd.expected_revision, "expected_revision")?;
    if membership.revision != expected_revision {
        return Err(AstralError::Validation(
            "code=org_scope.membership_revision_conflict".into(),
        ));
    }
    if !membership.active {
        return Err(AstralError::Validation(
            "code=org_scope.membership_not_active".into(),
        ));
    }
    let result = sqlx::query(MEMBERSHIP_REVOKE_SQL)
        .bind(&cmd.operation_id)
        .bind(&cmd.membership_id)
        .bind(expected_revision)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    require_affected_one(&result, "membership_revoke_race")?;
    let next_revision = row_generation(expected_revision, "membership.revision")? + 1;
    let payload = serde_json::to_string(&typed_membership(&OrgMembershipRow {
        membership_id: cmd.membership_id.clone(),
        tenant_id: membership.tenant_id,
        root_tenant_id: membership.root_tenant_id,
        user_id: membership.user_id,
        identity_card_id: membership.identity_card_id,
        card_id: membership.card_id,
        revision: expected_revision + 1,
        active: false,
        valid_from: membership.valid_from,
        valid_until: membership.valid_until,
        operation_id: cmd.operation_id.clone(),
    })?)
    .map_err(|error| AstralError::Internal(format!("org_scope membership payload: {error}")))?;
    append_revision_in_tx(
        tx,
        "MEMBERSHIP",
        membership.tenant_id,
        &cmd.membership_id,
        next_revision,
        &payload,
        &cmd.operation_id,
    )
    .await?;
    append_outbox_event_in_tx(
        tx,
        membership.tenant_id,
        ORG_EVENT_MEMBERSHIP_CHANGED,
        &cmd.operation_id,
        &payload,
    )
    .await?;
    append_audit_in_tx(
        tx,
        OrgAuditWrite {
            tenant_id: membership.tenant_id,
            actor_user_id: cmd.actor_user_id,
            actor_tenant_id: cmd.actor_tenant_id,
            action: "MEMBERSHIP_REVOKE",
            subject_kind: "MEMBERSHIP",
            subject_id: &cmd.membership_id,
            request_id: None,
            operation_id: &cmd.operation_id,
            detail_json: Some(payload.as_str()),
        },
    )
    .await?;
    Ok(vec![OrgMutationRecord {
        record_kind: "MEMBERSHIP_REVOKED".into(),
        subject_kind: "MEMBERSHIP".into(),
        subject_id: cmd.membership_id.clone(),
        tenant_id: membership.tenant_id,
    }])
}

// ─────────────────────────────────────────────────────────────────────────────
// trait 实现：直接命令在本文件落地；请求/worker/reader 委派到对应子模块
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl OrgScopeRepository for SqlxOrgScopeRepository {
    async fn revoke_grant(
        &self,
        cmd: &OrgGrantRevokeCommand,
    ) -> Result<OrgMutationOutcome, AstralError> {
        validate_grant_revoke_command(cmd)?;
        let expected_revision = gen_to_i64(cmd.expected_revision, "expected_revision")?;
        let cmd_json = serde_json::to_string(cmd)
            .map_err(|error| AstralError::Internal(format!("org_scope cmd serialize: {error}")))?;
        let digest = canonical_input_digest("GRANT_REVOKE", &cmd_json);
        let (mut tx, authority_guard) = begin_authority_tx(self.pool()).await?;
        match claim_operation_in_tx(
            &mut tx,
            &cmd.operation_id,
            "GRANT_REVOKE",
            cmd.receiving_tenant_id,
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
                let records = revoke_grant_in_tx(&mut tx, cmd, expected_revision).await?;
                let outcome = OrgMutationOutcome {
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

    async fn apply_mask(
        &self,
        cmd: &OrgMaskApplyCommand,
    ) -> Result<OrgMutationOutcome, AstralError> {
        validate_mask_apply_command(cmd)?;
        let cmd_json = serde_json::to_string(cmd)
            .map_err(|error| AstralError::Internal(format!("org_scope cmd serialize: {error}")))?;
        let digest = canonical_input_digest("MASK_APPLY", &cmd_json);
        let (mut tx, authority_guard) = begin_authority_tx(self.pool()).await?;
        match claim_operation_in_tx(
            &mut tx,
            &cmd.operation_id,
            "MASK_APPLY",
            cmd.tenant_id,
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
                let records = apply_mask_in_tx(&mut tx, cmd).await?;
                let outcome = OrgMutationOutcome {
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

    async fn remove_mask(
        &self,
        cmd: &OrgMaskRemoveCommand,
    ) -> Result<OrgMutationOutcome, AstralError> {
        validate_mask_remove_command(cmd)?;
        let cmd_json = serde_json::to_string(cmd)
            .map_err(|error| AstralError::Internal(format!("org_scope cmd serialize: {error}")))?;
        let digest = canonical_input_digest("MASK_REMOVE", &cmd_json);
        let (mut tx, authority_guard) = begin_authority_tx(self.pool()).await?;
        match claim_operation_in_tx(
            &mut tx,
            &cmd.operation_id,
            "MASK_REMOVE",
            cmd.tenant_id,
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
                let records = remove_mask_in_tx(&mut tx, cmd).await?;
                let outcome = OrgMutationOutcome {
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

    async fn create_membership(
        &self,
        cmd: &OrgMembershipCreateCommand,
    ) -> Result<OrgMutationOutcome, AstralError> {
        validate_membership_create_command(cmd)?;
        let (valid_from, valid_until) = validity_bounds(&cmd.validity);
        let cmd_json = serde_json::to_string(cmd)
            .map_err(|error| AstralError::Internal(format!("org_scope cmd serialize: {error}")))?;
        let digest = canonical_input_digest("MEMBERSHIP_CREATE", &cmd_json);
        let (mut tx, authority_guard) = begin_authority_tx(self.pool()).await?;
        match claim_operation_in_tx(
            &mut tx,
            &cmd.operation_id,
            "MEMBERSHIP_CREATE",
            cmd.tenant_id,
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
                let records =
                    create_membership_in_tx(&mut tx, cmd, valid_from, valid_until).await?;
                let outcome = OrgMutationOutcome {
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

    async fn revoke_membership(
        &self,
        cmd: &OrgMembershipRevokeCommand,
    ) -> Result<OrgMutationOutcome, AstralError> {
        validate_membership_revoke_command(cmd)?;
        let cmd_json = serde_json::to_string(cmd)
            .map_err(|error| AstralError::Internal(format!("org_scope cmd serialize: {error}")))?;
        let digest = canonical_input_digest("MEMBERSHIP_REVOKE", &cmd_json);
        let (mut tx, authority_guard) = begin_authority_tx(self.pool()).await?;
        match claim_operation_in_tx(
            &mut tx,
            &cmd.operation_id,
            "MEMBERSHIP_REVOKE",
            cmd.tenant_id,
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
                let records = revoke_membership_in_tx(&mut tx, cmd).await?;
                let outcome = OrgMutationOutcome {
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

    async fn create_request(
        &self,
        cmd: &OrgCreateRequestCommand,
    ) -> Result<OrgRequestOutcome, AstralError> {
        requests::create_request(self, cmd).await
    }

    async fn approve_request(
        &self,
        cmd: &OrgApproveCommand,
    ) -> Result<OrgApproveOutcome, AstralError> {
        requests::approve_request(self, cmd).await
    }

    async fn reject_request(&self, cmd: &OrgRejectCommand) -> Result<bool, AstralError> {
        requests::reject_request(self, cmd).await
    }

    async fn cancel_request(&self, cmd: &OrgCancelCommand) -> Result<bool, AstralError> {
        requests::cancel_request(self, cmd).await
    }

    async fn get_request(&self, request_id: i64) -> Result<Option<OrgRequestView>, AstralError> {
        requests::get_request(self, request_id).await
    }

    async fn claim_outbox_event(
        &self,
        cmd: &OrgOutboxClaimCommand,
    ) -> Result<Option<OrgOutboxLease>, AstralError> {
        worker::claim_outbox_event(self, cmd).await
    }

    async fn renew_outbox_lease(&self, cmd: &OrgOutboxRenewCommand) -> Result<bool, AstralError> {
        worker::renew_outbox_lease(self, cmd).await
    }

    async fn fail_outbox_event(
        &self,
        cmd: &OrgOutboxFailCommand,
    ) -> Result<OrgOutboxFailOutcome, AstralError> {
        worker::fail_outbox_event(self, cmd).await
    }

    async fn load_compile_input(
        &self,
        cmd: &OrgCompileInputCommand,
    ) -> Result<astral_types::org_scope::OrgCompileInput, AstralError> {
        worker::load_compile_input(self, cmd).await
    }

    async fn complete_publish(
        &self,
        cmd: &OrgPublishCommand,
    ) -> Result<OrgPublishOutcome, AstralError> {
        worker::complete_publish(self, cmd).await
    }

    async fn propagate_subtree_root(
        &self,
        cmd: &OrgSubtreePropagateCommand,
    ) -> Result<OrgSubtreePropagateOutcome, AstralError> {
        worker::propagate_subtree_root(self, cmd).await
    }

    async fn propagate_dependency_change(
        &self,
        cmd: &OrgDependencyPropagateCommand,
    ) -> Result<OrgDependencyPropagateOutcome, AstralError> {
        worker::propagate_dependency_change(self, cmd).await
    }

    async fn complete_outbox_event(
        &self,
        cmd: &OrgOutboxCompleteCommand,
    ) -> Result<OrgOutboxCompleteOutcome, AstralError> {
        worker::complete_outbox_event(self, cmd).await
    }

    async fn load_admission_evidence(
        &self,
        query: &OrgAdmissionQuery,
    ) -> Result<OrgAdmissionResult, AstralError> {
        reader::load_admission_evidence_in_pool(self.pool(), query).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 直接命令 pre-flight 纯测试（无 DB）：actor 租户边界门 + 既有校验不削弱
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const ACTOR_TENANT_ID: i64 = 4210;
    const OTHER_TENANT_ID: i64 = 4211;
    const GRANT_UUID: &str = "1f0e3a2b-4c5d-4e6f-8a9b-0c1d2e3f4a5b";
    const MASK_UUID: &str = "2a1b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
    const MEMBERSHIP_UUID: &str = "3b2c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e";
    const ORG_SCOPE_AUTHORITY_MIGRATION_SQL: &str =
        include_str!("../../migrations/20260922000001_org_scope_authority.sql");

    fn assert_local_actor_tenant_mismatch(error: AstralError) {
        match error {
            AstralError::Permission(message) => assert_eq!(
                message, "code=org_scope.local_actor_tenant_mismatch",
                "unexpected Permission payload"
            ),
            other => panic!("expected Permission(local_actor_tenant_mismatch), got {other:?}"),
        }
    }

    fn grant_revoke_command(actor_tenant_id: Option<i64>) -> OrgGrantRevokeCommand {
        OrgGrantRevokeCommand {
            operation_id: "op-grant-revoke-1".into(),
            actor_user_id: 7,
            actor_tenant_id,
            receiving_tenant_id: ACTOR_TENANT_ID,
            grant_id: GRANT_UUID.into(),
            expected_revision: 3,
            reason: Some("test".into()),
        }
    }

    fn mask_apply_command(actor_tenant_id: Option<i64>) -> OrgMaskApplyCommand {
        OrgMaskApplyCommand {
            operation_id: "op-mask-apply-1".into(),
            actor_user_id: 7,
            actor_tenant_id,
            tenant_id: ACTOR_TENANT_ID,
            target: OrgGrantRef {
                tenant_id: OTHER_TENANT_ID,
                grant_id: GRANT_UUID.into(),
                revision: 2,
            },
            expected_unit_generation: 5,
            reason: None,
        }
    }

    fn mask_remove_command(actor_tenant_id: Option<i64>) -> OrgMaskRemoveCommand {
        OrgMaskRemoveCommand {
            operation_id: "op-mask-remove-1".into(),
            actor_user_id: 7,
            actor_tenant_id,
            tenant_id: ACTOR_TENANT_ID,
            mask_id: MASK_UUID.into(),
            expected_revision: 1,
        }
    }

    fn membership_create_command(actor_tenant_id: Option<i64>) -> OrgMembershipCreateCommand {
        OrgMembershipCreateCommand {
            operation_id: "op-membership-create-1".into(),
            actor_user_id: 7,
            actor_tenant_id,
            tenant_id: ACTOR_TENANT_ID,
            user_id: 42,
            identity_card_id: 4242,
            card_id: 424242,
            validity: ValidityWindow::perpetual(),
        }
    }

    fn membership_revoke_command(actor_tenant_id: Option<i64>) -> OrgMembershipRevokeCommand {
        OrgMembershipRevokeCommand {
            operation_id: "op-membership-revoke-1".into(),
            actor_user_id: 7,
            actor_tenant_id,
            tenant_id: ACTOR_TENANT_ID,
            membership_id: MEMBERSHIP_UUID.into(),
            expected_revision: 1,
        }
    }

    #[test]
    fn helper_requires_exact_actor_tenant_match() {
        assert!(require_local_actor_tenant(Some(ACTOR_TENANT_ID), ACTOR_TENANT_ID).is_ok());
        // 缺席（None）与不一致（含非正 actor 值）都以同一稳定码拒绝。
        assert_local_actor_tenant_mismatch(
            require_local_actor_tenant(None, ACTOR_TENANT_ID).unwrap_err(),
        );
        assert_local_actor_tenant_mismatch(
            require_local_actor_tenant(Some(OTHER_TENANT_ID), ACTOR_TENANT_ID).unwrap_err(),
        );
        assert_local_actor_tenant_mismatch(
            require_local_actor_tenant(Some(0), ACTOR_TENANT_ID).unwrap_err(),
        );
    }

    #[test]
    fn personal_grant_membership_lock_reuses_physical_binding_contract() {
        let source = include_str!("mutations.rs");
        let start = source
            .find("pub(crate) async fn lock_personal_grant_membership_in_tx")
            .expect("PERSONAL membership lock helper must remain");
        let body = &source[start..];
        assert!(body.contains("m.tenant_id = ? AND m.user_id = ? AND m.card_id = ?"));
        assert!(body.contains("m.active = 1"));
        assert!(body.contains("valid_from"));
        assert!(body.contains("valid_until"));
        assert!(body.contains("MEMBERSHIP_USER_SERIALIZATION_LOCK_SQL"));
        assert!(body.contains("membership_physical_binding_sql(true)"));
        assert!(body.contains("personal_grant_membership_missing_or_invalid"));
    }

    #[test]
    fn physical_binding_sql_has_locked_and_fresh_variants() {
        let locked = membership_physical_binding_sql(true);
        let fresh = membership_physical_binding_sql(false);
        for sql in [&locked, &fresh] {
            assert!(sql.contains("user_card uc"));
            assert!(sql.contains("identity_card ic"));
            assert!(sql.contains("platform_user pu"));
            assert!(sql.contains("tenant_domain_map tdm"));
            assert!(sql.contains("uc.card_status = 'ACTIVE'"));
            assert!(sql.contains("ic.status = 'ACTIVE'"));
        }
        assert!(locked.ends_with(" FOR UPDATE"));
        assert!(!fresh.ends_with(" FOR UPDATE"));
    }

    #[test]
    fn grant_revoke_preflight_gates_actor_tenant() {
        assert!(
            validate_grant_revoke_command(&grant_revoke_command(Some(ACTOR_TENANT_ID))).is_ok()
        );
        assert_local_actor_tenant_mismatch(
            validate_grant_revoke_command(&grant_revoke_command(None)).unwrap_err(),
        );
        assert_local_actor_tenant_mismatch(
            validate_grant_revoke_command(&grant_revoke_command(Some(OTHER_TENANT_ID)))
                .unwrap_err(),
        );
        // 既有校验不削弱：grant_id 形状仍按原稳定码拒绝。
        let mut bad = grant_revoke_command(Some(ACTOR_TENANT_ID));
        bad.grant_id = "not-a-uuid".into();
        assert!(matches!(
            validate_grant_revoke_command(&bad),
            Err(AstralError::Validation(message))
                if message.contains("code=org_scope.invalid_uuid")
        ));
    }

    #[test]
    fn mask_apply_preflight_gates_actor_tenant() {
        assert!(validate_mask_apply_command(&mask_apply_command(Some(ACTOR_TENANT_ID))).is_ok());
        assert_local_actor_tenant_mismatch(
            validate_mask_apply_command(&mask_apply_command(None)).unwrap_err(),
        );
        assert_local_actor_tenant_mismatch(
            validate_mask_apply_command(&mask_apply_command(Some(OTHER_TENANT_ID))).unwrap_err(),
        );
        // 既有校验不削弱：self-target 与 generation=0 仍按原稳定码拒绝。
        let mut self_target = mask_apply_command(Some(ACTOR_TENANT_ID));
        self_target.target.tenant_id = ACTOR_TENANT_ID;
        assert!(matches!(
            validate_mask_apply_command(&self_target),
            Err(AstralError::Validation(message))
                if message.contains("code=org_scope.mask_target_self")
        ));
        let mut zero_generation = mask_apply_command(Some(ACTOR_TENANT_ID));
        zero_generation.expected_unit_generation = 0;
        assert!(matches!(
            validate_mask_apply_command(&zero_generation),
            Err(AstralError::Validation(message))
                if message.contains("code=org_scope.invalid_expected_generation")
        ));
    }

    #[test]
    fn mask_remove_preflight_gates_actor_tenant() {
        assert!(validate_mask_remove_command(&mask_remove_command(Some(ACTOR_TENANT_ID))).is_ok());
        assert_local_actor_tenant_mismatch(
            validate_mask_remove_command(&mask_remove_command(None)).unwrap_err(),
        );
        assert_local_actor_tenant_mismatch(
            validate_mask_remove_command(&mask_remove_command(Some(OTHER_TENANT_ID))).unwrap_err(),
        );
        // 既有校验不削弱：expected_revision=0 仍按原稳定码拒绝。
        let mut zero_revision = mask_remove_command(Some(ACTOR_TENANT_ID));
        zero_revision.expected_revision = 0;
        assert!(matches!(
            validate_mask_remove_command(&zero_revision),
            Err(AstralError::Validation(message))
                if message.contains("code=org_scope.invalid_expected_revision;field=mask")
        ));
    }

    #[test]
    fn membership_create_preflight_gates_actor_tenant() {
        assert!(
            validate_membership_create_command(&membership_create_command(Some(ACTOR_TENANT_ID)))
                .is_ok()
        );
        assert_local_actor_tenant_mismatch(
            validate_membership_create_command(&membership_create_command(None)).unwrap_err(),
        );
        assert_local_actor_tenant_mismatch(
            validate_membership_create_command(&membership_create_command(Some(OTHER_TENANT_ID)))
                .unwrap_err(),
        );
        // 既有校验不削弱：非正 card_id 仍按原稳定码拒绝。
        let mut bad_card = membership_create_command(Some(ACTOR_TENANT_ID));
        bad_card.card_id = 0;
        assert!(matches!(
            validate_membership_create_command(&bad_card),
            Err(AstralError::Validation(message))
                if message.contains("code=org_scope.non_positive_id;field=card_id")
        ));
    }

    #[test]
    fn membership_revoke_preflight_gates_actor_tenant() {
        assert!(
            validate_membership_revoke_command(&membership_revoke_command(Some(ACTOR_TENANT_ID)))
                .is_ok()
        );
        assert_local_actor_tenant_mismatch(
            validate_membership_revoke_command(&membership_revoke_command(None)).unwrap_err(),
        );
        assert_local_actor_tenant_mismatch(
            validate_membership_revoke_command(&membership_revoke_command(Some(OTHER_TENANT_ID)))
                .unwrap_err(),
        );
        // 既有校验不削弱：expected_revision=0 仍按原稳定码拒绝。
        let mut zero_revision = membership_revoke_command(Some(ACTOR_TENANT_ID));
        zero_revision.expected_revision = 0;
        assert!(matches!(
            validate_membership_revoke_command(&zero_revision),
            Err(AstralError::Validation(message))
                if message.contains("code=org_scope.invalid_expected_revision;field=membership")
        ));
    }

    #[test]
    fn actor_tenant_participates_in_idempotent_digest() {
        // actor_tenant_id 参与规范输入 digest：换 actor 租户的重放不可能命中
        // 同 operation_id 的已落账 outcome（digest 冲突），重放绕不过边界门。
        let first = serde_json::to_string(&grant_revoke_command(Some(ACTOR_TENANT_ID))).unwrap();
        let second = serde_json::to_string(&grant_revoke_command(Some(OTHER_TENANT_ID))).unwrap();
        let absent = serde_json::to_string(&grant_revoke_command(None)).unwrap();
        assert_ne!(
            canonical_input_digest("GRANT_REVOKE", &first),
            canonical_input_digest("GRANT_REVOKE", &second)
        );
        assert_ne!(
            canonical_input_digest("GRANT_REVOKE", &first),
            canonical_input_digest("GRANT_REVOKE", &absent)
        );
    }

    /// Membership-cap SQL and lock-order contract:
    /// - user scope is global across roots/tenants and uses its dedicated index;
    /// - a single-table `identity_card.uk_ic_user` lock serializes every same-user
    ///   create before the multi-table binding proof and protects the cap under
    ///   either MySQL REPEATABLE READ or READ COMMITTED;
    /// - the query reads `cap + 1` candidates, so a below-cap range reaches its
    ///   insertion gap before an insert may proceed;
    /// - the identity anchor, physical binding, card range and user range locks
    ///   precede the membership insert.
    #[test]
    fn membership_cap_sql_contract_is_frozen() {
        const {
            assert!(ORG_MAX_ACTIVE_MEMBERSHIPS_PER_USER > 0);
        }
        assert!(
            ORG_SCOPE_AUTHORITY_MIGRATION_SQL
                .contains("KEY idx_osmem_user_active (user_id, active)"),
            "membership cap needs a user-leading active-row index"
        );
        assert!(
            MEMBERSHIP_USER_SERIALIZATION_LOCK_SQL.contains("FROM identity_card")
                && MEMBERSHIP_USER_SERIALIZATION_LOCK_SQL.contains("FORCE INDEX (uk_ic_user)")
                && MEMBERSHIP_USER_SERIALIZATION_LOCK_SQL.contains("WHERE user_id = ? FOR UPDATE")
                && !MEMBERSHIP_USER_SERIALIZATION_LOCK_SQL.contains("status")
                && !MEMBERSHIP_USER_SERIALIZATION_LOCK_SQL.contains("expires_at"),
            "membership cap needs an unconditional, single-table per-user anchor; \
             sql={MEMBERSHIP_USER_SERIALIZATION_LOCK_SQL}"
        );
        assert!(
            ACTIVE_MEMBERSHIP_BY_CARD_LOCK_SQL.contains("FORCE INDEX (idx_osmem_card)")
                && ACTIVE_MEMBERSHIP_BY_CARD_LOCK_SQL.contains("WHERE card_id = ? AND active = 1")
                && ACTIVE_MEMBERSHIP_BY_CARD_LOCK_SQL.contains("FOR UPDATE"),
            "card-assignment query must pin its card-leading active-row index; \
             sql={ACTIVE_MEMBERSHIP_BY_CARD_LOCK_SQL}"
        );
        assert!(
            ACTIVE_MEMBERSHIPS_BY_USER_LOCK_SQL.contains("FORCE INDEX (idx_osmem_user_active)")
                && ACTIVE_MEMBERSHIPS_BY_USER_LOCK_SQL.contains("WHERE user_id = ? AND active = 1")
                && ACTIVE_MEMBERSHIPS_BY_USER_LOCK_SQL.contains("LIMIT ? FOR UPDATE"),
            "membership-cap query must lock the bounded active-user range; \
             sql={ACTIVE_MEMBERSHIPS_BY_USER_LOCK_SQL}"
        );

        let source = include_str!("mutations.rs");
        let cap_check = source
            .split("async fn ensure_user_membership_cap_in_tx")
            .nth(1)
            .and_then(|rest| {
                rest.split("pub(crate) async fn create_membership_in_tx")
                    .next()
            })
            .expect("membership cap helper must exist");
        assert!(
            cap_check.contains("let lock_limit = cap.checked_add(1)")
                && cap_check.contains(".bind(lock_limit)"),
            "membership cap must lock through the cap + 1 boundary"
        );

        let body = source
            .split("pub(crate) async fn create_membership_in_tx")
            .nth(1)
            .expect("membership create kernel must exist");
        let anchor = body
            .find("ensure_membership_user_serialization_in_tx(tx, cmd.user_id)")
            .expect("per-user identity-card anchor must precede membership cap");
        let binding = body
            .find("ensure_membership_card_binding_in_tx(tx, cmd)")
            .expect("physical binding proof must remain");
        let card = body
            .find("ensure_card_is_not_actively_assigned_in_tx(tx, cmd.card_id)")
            .expect("card assignment lock must remain");
        let cap = body
            .find("ensure_user_membership_cap_in_tx(tx, cmd.user_id)")
            .expect("user membership cap must be checked");
        let insert = body
            .find("sqlx::query(MEMBERSHIP_INSERT_SQL)")
            .expect("membership insert must remain");
        assert!(
            anchor < binding && binding < card && card < cap && cap < insert,
            "membership locks must be ordered anchor -> binding -> card -> user cap -> insert"
        );
    }

    /// root activation 证明列的 SQL 漂移绊线（`typed_node`/`OrgNode::validate`
    /// 合同）：
    /// - ATTACH 改挂必须清空激活列——`root_activation` 仅行政根可持有，重挂
    ///   后保留旧证明会让节点引用一段已不存在的独立治理期；下次 detach 以
    ///   当次批准人 + 审批 operation id 重落新证明（重挂不透传旧证明）。
    /// - ROOT activation 写入必须同时设置 operator 与 approval operation 两列
    ///   （ROOT_INIT 与 DETACH 共用同一合同，证明永不缺半边）。
    #[test]
    fn root_activation_sql_contract_is_frozen() {
        assert!(
            NODE_ATTACH_SQL.contains("activation_operator_user_id = NULL")
                && NODE_ATTACH_SQL.contains("activation_approval_operation_id = NULL"),
            "attach must clear stale root activation proofs; sql={NODE_ATTACH_SQL}"
        );
        assert!(
            !NODE_DETACH_SQL.contains("activation_operator_user_id"),
            "detach must not clear/keep the proof via the topology statement; the \
             dedicated activation write follows it"
        );
        for column in [
            "SET activation_operator_user_id = ?",
            "activation_approval_operation_id = ?",
        ] {
            assert!(
                NODE_ROOT_ACTIVATION_SQL.contains(column),
                "root activation write must bind {column}; sql={NODE_ROOT_ACTIVATION_SQL}"
            );
        }
    }
}
